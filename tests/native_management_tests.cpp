#include "hidfido/native_management.hpp"
#include <algorithm>
#include <iostream>
#include <stdexcept>
#include <vector>

namespace {
using namespace hidfido::management;
void check(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
template<class F> void rejects(F work, const char* message) { try { work(); } catch (const std::exception&) { return; } throw std::runtime_error(message); }
std::string status_text() {
    return R"({"schema":1,"vault_schema":2,"current_account_enrolled":true,"current_account_active":true,"current_account_key_count":2,"provider_schema_compatible":true,"password_generation":3,"keys":[{"label":"Principale","protection_state":"unknown","checked_at_unix":0},{"label":"Riserva","protection_state":"verified_distinct","checked_at_unix":123}],"backups":[{"id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","created_at_unix":123,"password_generation":3}]})";
}
void metadata_and_actions() {
    auto s = parse_status(status_text()); check(s.schema == 2 && s.keys.size() == 2 && s.keys[0].proof == "unknown", "Legacy metadata must remain unknown");
    check(can_run(s, VaultAction::verify, false, false), "Enrolled active key unavailable");
    check(!can_run(s, VaultAction::verify, true, false) && !can_run(s, VaultAction::verify, false, true), "Busy/demo actions enabled");
    s.active = false; check(!can_run(s, VaultAction::verify, false, false) && can_run(s, VaultAction::update_password, false, false), "Suspension must guide password repair");
    s.keys.resize(1); check(!can_run(s, VaultAction::remove_key, false, false), "Last key removal enabled");
    s.compatible = false; check(!can_run(s, VaultAction::backup, false, false), "Incompatible provider may mutate vault");
    for (const auto action : {VaultAction::enroll, VaultAction::verify, VaultAction::verify_protection, VaultAction::add_key, VaultAction::remove_key, VaultAction::update_password, VaultAction::backup, VaultAction::restore}) {
        const auto selection = action == VaultAction::restore ? L"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" : L"Riserva 2";
        const auto args = vault_arguments(action, selection, L"S-1-5-21-1-2-3-1001");
        check(args[0].starts_with(L"--") && args[args.size() - 2] == L"--expected-sid", "Native action vocabulary or SID binding lost");
    }
    rejects([] { vault_arguments(VaultAction::restore, L"..\\arbitrary", L"S-1-5-21-1-2-3-1001"); }, "Arbitrary restore path accepted");
    rejects([] { vault_arguments(VaultAction::verify, std::wstring(L"key\0hidden", 10), L"sid"); }, "Command NUL accepted");
    auto bad = status_text(); const auto at = bad.find("Riserva"); bad.replace(at, 7, "Principale"); rejects([&] { parse_status(bad); }, "Duplicate key metadata accepted");
    bad = status_text(); bad.replace(bad.find("verified_distinct"), 17, "pretend_verified"); rejects([&] { parse_status(bad); }, "Unknown proof state accepted");
}
void json_boundaries() {
    check(parse_json(R"({"label":"Chiave \u00e8 \ud83d\udd11"})").at("label").text() == "Chiave è 🔑", "Unicode escape decoding failed");
    for (const auto text : {R"({"x":1,"x":2})", R"({"x":18446744073709551616})", R"({"x":01})", R"({"x":"\u0000"})", R"({"x":"\ud800"})", R"([] true)", R"({"x":1.2})"}) rejects([&] { parse_json(text); }, "Malformed JSON accepted");
    rejects([] { parse_json(std::string(1024 * 1024 + 1, ' ')); }, "Oversized JSON accepted");
    const std::string value = "x\"\\\n"; check(parse_json(json_string(value)).text() == value, "JSON serialization did not preserve data");
}
struct FakeBackend : TransactionBackend {
    std::vector<std::string> trace; std::string fail;
    void step(const char* name) { trace.emplace_back(name); if (fail == name) throw std::runtime_error(name); }
    void preflight() override { step("preflight"); }
    void prepare() override { step("prepare"); }
    void remove_previous() override { step("remove-old"); }
    void activate_new() override { step("activate-new"); }
    void verify_new() override { step("verify-new"); }
    void cleanup_new() override { step("cleanup-new"); }
    void restore_previous() override { step("restore-old"); }
};
void transactions() {
    FakeBackend good; check(transact(good, true).success, "Native update failed");
    check(good.trace == std::vector<std::string>{"preflight", "prepare", "remove-old", "activate-new", "verify-new"}, "Old provider removed before staged checks/state");
    for (const auto failure : {"preflight", "prepare"}) { FakeBackend b; b.fail = failure; rejects([&] { transact(b, true); }, "Preflight failure hidden"); check(std::find(b.trace.begin(), b.trace.end(), "remove-old") == b.trace.end(), "Preflight failure touched activation"); }
    for (const auto failure : {"activate-new", "verify-new"}) { FakeBackend b; b.fail = failure; const auto result = transact(b, true); check(!result.success && result.restored && !result.recovery_required && b.trace.back() == "restore-old", "Partial install did not restore previous registration"); }
    struct BadRollback : FakeBackend { void restore_previous() override { step("restore-old"); throw std::runtime_error("incompatible archive"); } } b;
    b.fail = "activate-new"; const auto result = transact(b, true); check(!result.success && !result.restored && result.recovery_required, "Failed/incompatible rollback falsely reported restored");
    FakeBackend first; first.fail = "activate-new"; const auto initial = transact(first, false); check(!initial.restored && !initial.recovery_required && first.trace.back() == "cleanup-new", "First-install cleanup attempted an old activation");
}
void native_manifest_profile() {
    const auto paths = hidfido::installer::native_payload_paths(); check(paths.size() == 4, "Native runtime unexpectedly contains additional payload");
    for (const auto path : paths) check(path.ends_with(".exe") || path.ends_with(".dll"), "Native package contains scripts");
    const std::string hash(64, 'a'); std::string identity = "HID-FIDO2-WinLogon/release/1\n0.6.0\n8664", files;
    for (const auto path : paths) { identity += "\n" + std::string(path) + "=" + hash; if (!files.empty()) files += ','; files += "{\"Path\":" + json_string(path) + ",\"Length\":1,\"Sha256\":" + json_string(hash) + '}'; }
    const auto id = hidfido::installer::sha256_hex({reinterpret_cast<const std::uint8_t*>(identity.data()), identity.size()});
    const auto data = "{\"Schema\":1,\"ProjectId\":\"HID-FIDO2-WinLogon\",\"ProviderClsid\":" + json_string(narrow(provider_clsid)) + ",\"Architecture\":\"8664\",\"VaultSchema\":2,\"Version\":\"0.6.0\",\"ReleaseId\":" + json_string(id) + ",\"Files\":[" + files + "]}";
    const auto manifest = hidfido::installer::parse_manifest({reinterpret_cast<const std::uint8_t*>(data.data()), data.size()}); check(manifest.native_management && manifest.files.size() == 4, "Native manifest rejected");
    auto altered = data; const auto pos = altered.find("Gestione-HID-FIDO2.exe"); altered.replace(pos, 21, "scripts/evil.ps1"); rejects([&] { hidfido::installer::parse_manifest({reinterpret_cast<const std::uint8_t*>(altered.data()), altered.size()}); }, "Native script substitution accepted");
}
}
int main() {
    try { json_boundaries(); metadata_and_actions(); transactions(); native_manifest_profile(); std::cout << "Native manager: bounded metadata, Unicode, fixed actions, last-key policy, staged update, rollback and four-binary profile passed. No host registry/vault accessed.\n"; return 0; }
    catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}
