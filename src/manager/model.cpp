#include "hidfido/native_management.hpp"
#include "hidfido/localization.hpp"
#include <windows.h>
#include <algorithm>
#include <limits>

namespace hidfido::management {
std::wstring widen(std::string_view text) {
    if (text.empty()) return {};
    const auto count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), nullptr, 0);
    if (!count) throw std::runtime_error("Invalid UTF-8");
    std::wstring result(count, L'\0'); MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), result.data(), count);
    if (result.find(L'\0') != std::wstring::npos) throw std::runtime_error("Embedded NUL"); return result;
}
std::string narrow(std::wstring_view text) {
    if (text.empty()) return {};
    const auto count = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
    if (!count) throw std::runtime_error("Invalid UTF-16");
    std::string result(count, '\0'); WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), result.data(), count, nullptr, nullptr);
    if (result.find('\0') != std::string::npos) throw std::runtime_error("Embedded NUL"); return result;
}
bool valid_id(std::string_view value, std::size_t length) noexcept {
    return value.size() == length && std::all_of(value.begin(), value.end(), [](char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); });
}
Status parse_status(std::string_view data) {
    const auto root = parse_json(data); Status s;
    if (root.at("schema").integer() != 1) throw std::runtime_error("Unsupported public status");
    const auto schema = root.at("vault_schema").integer();
    if (schema != 1 && schema != 2) throw std::runtime_error("Unsupported vault schema");
    s.schema = static_cast<unsigned>(schema); s.observed = true;
    s.enrolled = root.at("current_account_enrolled").flag(); s.active = root.at("current_account_active").flag();
    s.compatible = root.at("provider_schema_compatible").flag();
    const auto count = root.at("current_account_key_count").integer();
    if (count > 8 || root.at("keys").kind != Json::Kind::array || root.at("keys").array.size() != count) throw std::runtime_error("Invalid key metadata");
    for (const auto& key : root.at("keys").array) {
        const auto label = widen(key.at("label").text()); const auto proof = key.at("protection_state").text();
        if (label.empty() || label.size() > 64 || (proof != "unknown" && proof != "verified_denied" && proof != "verified_distinct")) throw std::runtime_error("Invalid key metadata");
        if (std::any_of(s.keys.begin(), s.keys.end(), [&](const auto& old) { return old.label == label; })) throw std::runtime_error("Duplicate key label");
        s.keys.push_back({label, proof, key.at("checked_at_unix").integer()});
    }
    const auto generation = root.at("password_generation").integer(); if (generation > UINT32_MAX) throw std::runtime_error("Invalid password generation");
    s.password_generation = static_cast<unsigned>(generation);
    if (root.at("backups").kind != Json::Kind::array || root.at("backups").array.size() > 512) throw std::runtime_error("Invalid backup metadata");
    for (const auto& backup : root.at("backups").array) {
        const auto id = backup.at("id").text(); if (!valid_id(id, 32)) throw std::runtime_error("Invalid backup id");
        s.backups.push_back({id, backup.at("created_at_unix").integer(), backup.at("password_generation").integer()});
    }
    return s;
}
bool can_run(const Status& s, VaultAction action, bool busy, bool demo) noexcept {
    if (busy || demo || !s.observed || !s.compatible) return false;
    switch (action) {
    case VaultAction::enroll: return !s.enrolled;
    case VaultAction::verify: case VaultAction::verify_protection: return s.enrolled && s.active && !s.keys.empty();
    case VaultAction::add_key: return s.enrolled && s.active && s.keys.size() < 8;
    case VaultAction::remove_key: return s.enrolled && s.keys.size() > 1;
    case VaultAction::update_password: case VaultAction::backup: return s.enrolled;
    case VaultAction::restore: return s.enrolled && !s.backups.empty();
    } return false;
}
std::vector<std::wstring> vault_arguments(VaultAction action, std::wstring_view selection, std::wstring_view sid) {
    // Fixed command vocabulary; no executable/script/command text from UI.
    const wchar_t* command{}; bool argument{};
    switch (action) {
    case VaultAction::enroll: command = L"--enroll"; argument = true; break;
    case VaultAction::verify: command = L"--verify"; argument = true; break;
    case VaultAction::verify_protection: command = L"--verify-protection"; argument = true; break;
    case VaultAction::add_key: command = L"--add-key"; argument = true; break;
    case VaultAction::remove_key: command = L"--remove-key"; argument = true; break;
    case VaultAction::restore: command = L"--restore-backup"; argument = true; break;
    case VaultAction::update_password: command = L"--update-password"; break;
    case VaultAction::backup: command = L"--backup"; break;
    }
    if (!command || sid.empty() || sid.find(L'\0') != sid.npos) throw std::runtime_error("Invalid action");
    std::vector<std::wstring> result{command};
    if (argument) {
        if (selection.empty() || selection.size() > 64 || selection.find(L'\0') != selection.npos) throw std::runtime_error("Invalid selection");
        if (action == VaultAction::restore && !valid_id(narrow(selection), 32)) throw std::runtime_error("Invalid backup selection");
        result.emplace_back(selection);
    }
    result.emplace_back(L"--language"); result.emplace_back(ui::language_code(ui::language()));
    result.emplace_back(L"--expected-sid"); result.emplace_back(sid); return result;
}
TransactionResult transact(TransactionBackend& backend, bool previous) {
    backend.preflight(); backend.prepare();
    try { if (previous) backend.remove_previous(); backend.activate_new(); backend.verify_new(); return {true, false, false}; }
    catch (...) {
        try { backend.cleanup_new(); if (previous) backend.restore_previous(); return {false, previous, false}; }
        catch (...) { return {false, false, true}; }
    }
}
}
