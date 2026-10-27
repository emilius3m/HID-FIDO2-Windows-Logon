#include "hidfido/support_report.hpp"
#include "../src/credential_provider/diagnostic.hpp"
#include "../src/manager/platform.hpp"
#include <TraceLoggingProvider.h>
#include <chrono>
#include <iostream>
#include <stdexcept>
#include <thread>

TRACELOGGING_DEFINE_PROVIDER(g_support_test, "HIDFIDO2.SupportSyntheticTest",
    (0x6c0e3d67, 0x8b83, 0x48b5, 0x95, 0xc7, 0x59, 0x12, 0xf7, 0x85, 0x9d, 0x04));

namespace {
using namespace hidfido::management;
namespace cp = hidfido::credential_diagnostic;
void check(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
template<class F> void rejects(F work, const char* message) { try { work(); } catch (const std::exception&) { return; } throw std::runtime_error(message); }
void walkthrough() {
    Status s; SetupChecks c;
    check(setup_step(s, c) == SetupStep::unavailable, "Unknown status started setup");
    s.observed = s.compatible = true;
    check(setup_step(s, c) == SetupStep::recovery, "Recovery confirmation skipped");
    c.recovery = true; check(setup_step(s, c) == SetupStep::primary, "New account did not request enrollment");
    s.enrolled = true; check(setup_step(s, c) == SetupStep::password, "Suspension ignored");
    s.active = true; s.keys = {{L"Primary", "verified_distinct", 123}};
    check(setup_step(s, c) == SetupStep::spare, "Single key allowed activation");
    s.keys.push_back({L"Spare", "unknown", 0});
    c.primary_unlock = c.spare_unlock = c.restart = true;
    check(setup_step(s, c) == SetupStep::protection, "User confirmations became hardware proofs");
    s.keys[1].proof = "verified_denied";
    check(setup_step(s, c) == SetupStep::activation, "Hardware proofs incorrectly meant provider installed");
    s.registered = true; c.spare_unlock = false;
    check(setup_step(s, c) == SetupStep::trial, "Actual spare-key trial skipped");
    c.spare_unlock = true; check(setup_step(s, c) == SetupStep::complete, "Complete walkthrough not recognized");
    s.active = false; check(setup_step(s, c) == SetupStep::password, "New password suspension ignored after completion");
    s.compatible = false; check(setup_step(s, c) == SetupStep::unavailable, "Incompatible reader passed setup");
}
void rename_command() {
    const auto args = vault_arguments(VaultAction::rename_key, L"Primary", L"S-1-5-21-1-2-3-1001", L"Office key");
    check(args[0] == L"--rename-key" && args[1] == L"Primary" && args[2] == L"--new-label" && args[3] == L"Office key" && args[args.size()-2] == L"--expected-sid", "Rename command/SID binding changed");
    rejects([] { vault_arguments(VaultAction::rename_key, L"Primary", L"sid"); }, "Empty replacement accepted");
    rejects([] { vault_arguments(VaultAction::rename_key, L"Primary", L"sid", L"bad\nname"); }, "Control characters accepted");
    rejects([] { vault_arguments(VaultAction::verify, L"Primary", L"sid", L"extra"); }, "Replacement label accepted for an unrelated action");
    Status s; s.observed = s.compatible = s.enrolled = true; s.keys = {{L"Primary", "unknown", 0}};
    check(can_run(s, VaultAction::rename_key, false, false), "Suspended account cannot rename metadata");
    check(!can_run(s, VaultAction::rename_key, false, true), "Demo can rename a real key");
}
void diagnostic_privacy() {
    const std::string helper = "{\"schema\":1,\"tick_ms\":123456,\"stage\":\"pin_input\",\"event\":\"started\"}\n{\"schema\":1,\"tick_ms\":123457,\"stage\":\"ctap_client_pin\",\"event\":\"error\",\"error_kind\":\"ctap\",\"ctap_status\":49}\n";
    const auto sanitized = sanitize_helper_report(helper);
    check(sanitized.find("123456") == sanitized.npos && parse_json(sanitized).array.size() == 2, "Uptime leaked or helper events lost");
    for (const auto data : {
        R"({"schema":1,"tick_ms":1,"stage":"startup","event":"error","password":"secret"})",
        R"({"schema":1,"tick_ms":1,"stage":"secret","event":"started"})",
        R"({"schema":1,"tick_ms":1,"stage":"startup","event":"secret"})",
        R"({"schema":1,"tick_ms":1,"stage":"startup","event":"error","ctap_status":256})",
        R"({"schema":1,"tick_ms":1,"stage":"startup","event":"error","win32_error":"secret"})"}) rejects([&] { sanitize_helper_report(data); }, "Untrusted helper text exported");
    SupportEvents events;
    events.add(UINT32_MAX, 0, 0, 0);
    events.add(static_cast<unsigned>(cp::Stage::set_string_nonempty), 1234, 0, 1);
    events.add(static_cast<unsigned>(cp::Stage::field_update), 1234, 0, 2);
    check(events.snapshot().empty(), "Keystroke diagnostics retained");
    std::thread producer([&] { for (unsigned i = 0; i < support_event_limit; ++i) events.add(static_cast<unsigned>(cp::Stage::worker_error), 1, 49, i); });
    for (unsigned i = 0; i < 20; ++i) (void)events.snapshot(); producer.join();
    events.add(static_cast<unsigned>(cp::Stage::worker_ready), 0, 0, support_duration_ms + 1);
    events.add(static_cast<unsigned>(cp::Stage::worker_ready), 0, 0, 1);
    check(events.snapshot().size() == support_event_limit && events.discarded() == 2, "Diagnostic limits not enforced");
    Status s; s.observed = s.active = s.enrolled = true; s.schema = 2;
    s.provider_path = L"C:\\Users\\PRIVATE_ACCOUNT\\secret"; s.provider_version = L"PRIVATE_VERSION";
    s.keys = {{L"PRIVATE_KEY_LABEL", "verified_distinct", 0}}; s.backups = {{"PRIVATE_BACKUP_ID", 0, 0}};
    const auto report = make_support_report(s, SupportAudit::failed, events.snapshot(), events.discarded(), 5, 2, helper, false, 1);
    check(report.find("PRIVATE") == report.npos && report.find("123456") == report.npos, "Private status metadata leaked");
    const auto parsed = parse_json(report);
    check(parsed.at("logon_events").array.size() == support_event_limit && parsed.at("installation_check").text() == "failed" && parsed.at("provider_version").kind == Json::Kind::null, "Support report misrepresented checks");
    events.clear(); check(events.snapshot().empty() && !events.discarded(), "New collection retained previous events");
}
void etw_synthetic_check() {
    SupportTrace capture;
    check(TraceLoggingRegister(g_support_test) == ERROR_SUCCESS, "Cannot register synthetic provider");
    struct Unregister { ~Unregister() { TraceLoggingUnregister(g_support_test); } } unregister;
    for (int run = 0; run < 2; ++run) {
        capture.start();
        for (unsigned attempt = 0; attempt < 40 && capture.events().snapshot().empty(); ++attempt) {
            TraceLoggingWrite(g_support_test, "Lifecycle", TraceLoggingLevel(cp::level), TraceLoggingKeyword(cp::keyword),
                TraceLoggingUInt32(static_cast<unsigned>(cp::Stage::worker_error), "Stage"),
                TraceLoggingWideString(L"DO_NOT_EXPORT", "StageName"), TraceLoggingUInt64(1, "A"), TraceLoggingUInt64(49, "B"),
                TraceLoggingWideString(L"DO_NOT_EXPORT", "UnexpectedText"));
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        capture.stop();
        const auto events = capture.events().snapshot();
        check(!capture.running() && !capture.consumer_error() && !events.empty(), "ETW did not capture and stop cleanly");
        bool synthetic{};
        for (const auto& event : events) if (event.stage == static_cast<unsigned>(cp::Stage::worker_error) && event.a == 1 && event.b == 49) synthetic = true;
        check(synthetic, "TDH did not decode synthetic numeric properties");
        const auto report = make_support_report({}, SupportAudit::not_run, events, 0, 0, 0, {}, false, {}, true);
        check(report.find("DO_NOT_EXPORT") == report.npos, "Raw ETW strings leaked");
    }
}
void etw_deadline_check() {
    SupportTrace capture; capture.start();
    const auto started = std::chrono::steady_clock::now();
    while (capture.running() && std::chrono::steady_clock::now() - started < std::chrono::seconds(315)) std::this_thread::sleep_for(std::chrono::milliseconds(100));
    const auto stopped_itself = !capture.running(); const auto elapsed = capture.elapsed_ms(); capture.stop();
    check(stopped_itself && elapsed >= support_duration_ms && elapsed < support_duration_ms + 10000 && !capture.consumer_error(), "ETW deadline failed to stop independently of the UI");
}
}
int main(int argc, char** argv) {
    if (argc == 3 && (std::string_view(argv[1]) == "--etw-self-test" || std::string_view(argv[1]) == "--etw-deadline-test")) {
        unsigned code = 1;
        try { if (std::string_view(argv[1]) == "--etw-self-test") etw_synthetic_check(); else etw_deadline_check(); code = 0; } catch (const std::system_error& error) { code = static_cast<unsigned>(error.code().value()); } catch (...) {}
        try { write_new_text(std::filesystem::path(argv[2]), "{\"SyntheticEtwTest\":true,\"Success\":" + std::string(code == 0 ? "true" : "false") + ",\"Code\":" + std::to_string(code) + ",\"AuthenticationAttempted\":false}", false); } catch (...) { return 2; }
        return code ? 1 : 0;
    }
    try { walkthrough(); rename_command(); diagnostic_privacy(); std::cout << "Setup gates, metadata rename and bounded private support reports passed. No host changes.\n"; return 0; }
    catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
