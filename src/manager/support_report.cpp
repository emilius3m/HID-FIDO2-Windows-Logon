#include "hidfido/support_report.hpp"
#include "hidfido/localization.hpp"
#include "../credential_provider/diagnostic.hpp"
#include "../vault/public_report.hpp"
#include <algorithm>
#include <array>

namespace hidfido::management {
namespace {
namespace cp = credential_diagnostic;
namespace helper = vault::diagnostic;
std::string ascii(std::wstring_view text) { return narrow(text); }
std::string boolean(bool value) { return value ? "true" : "false"; }
bool numeric_version(std::wstring_view version) {
    return !version.empty() && version.size() <= 32 && std::all_of(version.begin(), version.end(), [](wchar_t c) { return (c >= L'0' && c <= L'9') || c == L'.'; });
}
bool helper_stage(std::string_view text) {
    for (int i = 0; i <= static_cast<int>(helper::Stage::rename_key); ++i) if (helper::name(static_cast<helper::Stage>(i)) == text) return true;
    return false;
}
bool helper_error(std::string_view text) {
    for (int i = 0; i <= static_cast<int>(helper::Error::other); ++i) if (helper::name(static_cast<helper::Error>(i)) == text) return true;
    return false;
}
}
void SupportEvents::clear() { std::lock_guard lock(mutex_); events_.clear(); discarded_ = 0; }
void SupportEvents::add(std::uint32_t stage, std::uint64_t a, std::uint64_t b, std::uint64_t elapsed_ms) noexcept {
    try {
        std::lock_guard lock(mutex_);
        // Discard keystroke-related stages entirely, including event timing.
        if (stage > static_cast<unsigned>(cp::Stage::field_update) ||
            stage == static_cast<unsigned>(cp::Stage::set_string_empty) ||
            stage == static_cast<unsigned>(cp::Stage::set_string_nonempty) ||
            stage == static_cast<unsigned>(cp::Stage::field_update)) return;
        if (elapsed_ms > support_duration_ms || events_.size() >= support_event_limit) { ++discarded_; return; }
        events_.push_back({elapsed_ms, a, b, stage});
    } catch (...) { /* Diagnostic loss must never affect authentication. */ }
}
std::vector<SupportEvent> SupportEvents::snapshot() const { std::lock_guard lock(mutex_); return events_; }
std::uint64_t SupportEvents::discarded() const { std::lock_guard lock(mutex_); return discarded_; }

std::string sanitize_helper_report(std::string_view jsonl) {
    if (jsonl.size() > 256 * 1024) throw std::runtime_error("Helper diagnostic limit exceeded");
    std::string output = "["; std::uint64_t origin{}; bool first = true; unsigned count{};
    while (!jsonl.empty()) {
        const auto end = jsonl.find('\n');
        auto line = jsonl.substr(0, end);
        jsonl = end == jsonl.npos ? std::string_view{} : jsonl.substr(end + 1);
        if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
        if (line.empty()) continue;
        if (++count > support_event_limit) throw std::runtime_error("Too many helper events");
        const auto record = parse_json(line);
        if (record.kind != Json::Kind::object || record.at("schema").integer() != 1) throw std::runtime_error("Invalid helper report");
        constexpr std::array allowed{"schema", "tick_ms", "stage", "event", "error_kind", "ctap_status", "win32_error", "exit_code"};
        for (const auto& [key, value] : record.object) {
            (void)value;
            if (std::find(allowed.begin(), allowed.end(), key) == allowed.end()) throw std::runtime_error("Unexpected helper field");
        }
        const auto stage = record.at("stage").text(), event = record.at("event").text();
        if (!helper_stage(stage) || (event != "started" && event != "completed" && event != "failed" && event != "error" && event != "finished")) throw std::runtime_error("Invalid helper stage");
        const auto tick = record.at("tick_ms").integer();
        if (first) origin = tick;
        if (tick < origin) throw std::runtime_error("Invalid helper time");
        if (!first) output += ',';
        output += "{\"elapsed_ms\":" + std::to_string(tick - origin) + ",\"stage\":" + json_string(stage) + ",\"event\":" + json_string(event);
        if (const auto it = record.object.find("error_kind"); it != record.object.end()) {
            const auto kind = it->second.text(); if (!helper_error(kind)) throw std::runtime_error("Invalid helper error");
            output += ",\"error_kind\":" + json_string(kind);
        }
        for (const auto field : {"ctap_status", "win32_error", "exit_code"}) {
            if (const auto it = record.object.find(field); it != record.object.end()) {
                const auto value = it->second.integer();
                const std::uint64_t maximum = std::string_view(field) == "ctap_status" ? 255 : UINT32_MAX;
                if (value > maximum) throw std::runtime_error("Invalid helper code");
                output += "," + json_string(field) + ':' + std::to_string(value);
            }
        }
        output += '}'; first = false;
    }
    return output + ']';
}
std::string make_support_report(const Status& s, SupportAudit audit, const std::vector<SupportEvent>& events,
    std::uint64_t discarded, std::uint32_t consumer_error, std::uint32_t events_lost,
    std::string_view helper_report, bool helper_incomplete, std::optional<unsigned> last_exit_code, bool demo) {
    // No generic serialization of Status/audit/ETW. Every exported field is
    // constructed here from a fixed allowlist, excluding labels, SIDs, paths,
    // credential IDs, salts, ciphertext and arbitrary exception messages.
    const auto verified = std::count_if(s.keys.begin(), s.keys.end(), [](const auto& key) { return key.proof == "verified_denied" || key.proof == "verified_distinct"; });
    SYSTEMTIME now{}; GetSystemTime(&now); std::array<char, 32> time{};
    sprintf_s(time.data(), time.size(), "%04u-%02u-%02uT%02u:%02u:%02uZ", now.wYear, now.wMonth, now.wDay, now.wHour, now.wMinute, now.wSecond);
    std::string output = "{\n  \"schema\": 1,\n  \"application_version\": \"0.9.0\",\n  \"created_utc\": " + json_string(time.data()) +
        ",\n  \"data_source\": " + json_string(demo ? "demo" : "local") +
        ",\n  \"language\": " + json_string(ascii(ui::language_code(ui::language()))) +
        ",\n  \"status_available\": " + boolean(s.observed) + ",\n  \"account_enrolled\": " + boolean(s.enrolled) +
        ",\n  \"account_active\": " + boolean(s.active) + ",\n  \"provider_registered\": " + boolean(s.registered) +
        ",\n  \"provider_version\": " + (numeric_version(s.provider_version) ? json_string(ascii(s.provider_version)) : "null") +
        ",\n  \"vault_schema\": " + std::to_string(s.schema) + ",\n  \"key_count\": " + std::to_string(s.keys.size()) +
        ",\n  \"verified_key_count\": " + std::to_string(verified) + ",\n  \"backup_count\": " + std::to_string(s.backups.size()) +
        ",\n  \"installation_check\": " + json_string(audit == SupportAudit::passed ? "passed" : audit == SupportAudit::failed ? "failed" : "not_run") +
        ",\n  \"last_operation_exit_code\": " + (last_exit_code ? std::to_string(*last_exit_code) : "null") +
        ",\n  \"trace_discarded\": " + std::to_string(discarded) + ",\n  \"trace_consumer_error\": " + std::to_string(consumer_error) +
        ",\n  \"trace_events_lost\": " + std::to_string(events_lost) + ",\n  \"helper_report_incomplete\": " + boolean(helper_incomplete) + ",\n  \"logon_events\": [";
    SupportEvents bounded;
    for (const auto& event : events) bounded.add(event.stage, event.a, event.b, event.elapsed_ms);
    bool first = true;
    for (const auto& event : bounded.snapshot()) {
        if (!first) output += ',';
        output += "\n    {\"elapsed_ms\":" + std::to_string(event.elapsed_ms) + ",\"stage\":" + json_string(ascii(cp::name(static_cast<cp::Stage>(event.stage)))) + ",\"a\":" + std::to_string(event.a) + ",\"b\":" + std::to_string(event.b) + '}'; first = false;
    }
    output += "\n  ],\n  \"helper_events\": " + sanitize_helper_report(helper_report) + "\n}\n";
    return output;
}
}
