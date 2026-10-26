#include "hidfido/localization.hpp"
#include "hidfido/user_messages.hpp"
#include "hidfido/logon_serialization.hpp"
#include <windows.h>
#include <iostream>
#include <set>
#include <stdexcept>
#include <string>

namespace {
void check(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
void catalog_and_messages() {
    using namespace hidfido::ui;
    std::set<std::wstring_view> keys;
    for (const auto& entry : translations()) {
        check(!entry.key.empty() && *entry.italian && *entry.english, "Empty translation");
        check(keys.insert(entry.key).second, "Duplicate translation key");
        set_language(Language::italian); check(tr(entry.key.data()) == std::wstring_view(entry.italian), "Italian lookup failed");
        set_language(Language::english); check(tr(entry.key.data()) == std::wstring_view(entry.english), "English lookup failed");
    }
    check(parse_language(L"it") == Language::italian && parse_language(L"en") == Language::english, "Supported language rejected");
    for (const auto value : {L"", L"fr", L"en --install", L"EN"}) check(!parse_language(value), "Invalid language accepted");
    set_language(Language::english);
    check(std::wstring_view(tr(L"Aggiorna copia cifrata")) == L"Update saved password", "User-facing password action unclear");
    check(describe_logon_error(ERROR_LOGON_FAILURE).find(L"Windows password") != std::wstring::npos, "English password error missing");
    const auto wrong = static_cast<std::int32_t>(0xC000006A);
    const auto english = hidfido::logon::advise_logon_result(wrong, 0);
    check(english.suspend_record && english.message.find(L"Update saved password") != std::wstring::npos, "English recovery guidance or suspension lost");
    check(english.message.find(L"--update-password") == std::wstring::npos, "CLI command exposed in sign-in guidance");
    set_language(Language::italian);
    const auto italian = hidfido::logon::advise_logon_result(wrong, 0);
    check(italian.suspend_record && italian.message.find(L"Aggiorna password salvata") != std::wstring::npos, "Italian recovery guidance or suspension lost");
}
void isolated_preference() {
    using namespace hidfido::ui;
    const auto root = L"Software\\HidFidoLocalizationTests\\" + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64());
    HKEY fixture{};
    check(RegCreateKeyExW(HKEY_CURRENT_USER, root.c_str(), 0, nullptr, 0, KEY_ALL_ACCESS, nullptr, &fixture, nullptr) == ERROR_SUCCESS, "Preference fixture failed");
    bool overridden{};
    const auto cleanup = [&] { if (overridden) RegOverridePredefKey(HKEY_LOCAL_MACHINE, nullptr); RegCloseKey(fixture); RegDeleteTreeW(HKEY_CURRENT_USER, root.c_str()); };
    try {
        check(RegOverridePredefKey(HKEY_LOCAL_MACHINE, fixture) == ERROR_SUCCESS, "Registry isolation failed"); overridden = true;
        const auto fallback = preferred_language();
        check(save_preferred_language(Language::english) && preferred_language() == Language::english, "English preference not persisted");
        check(save_preferred_language(Language::italian) && preferred_language() == Language::italian, "Italian preference not persisted");
        const wchar_t invalid[] = L"fr";
        check(RegSetKeyValueW(fixture, L"SOFTWARE\\HID-FIDO2-WinLogon\\Preferences", L"Language", REG_SZ, invalid, sizeof(invalid)) == ERROR_SUCCESS, "Invalid fixture write failed");
        check(preferred_language() == fallback, "Unknown saved language did not fall back safely");
        const DWORD invalid_type = 1;
        check(RegSetKeyValueW(fixture, L"SOFTWARE\\HID-FIDO2-WinLogon\\Preferences", L"Language", REG_DWORD, &invalid_type, sizeof(invalid_type)) == ERROR_SUCCESS, "Type fixture failed");
        check(preferred_language() == fallback, "Invalid preference type did not fall back safely");
    } catch (...) { cleanup(); throw; }
    cleanup();
}
}
int main() {
    try { catalog_and_messages(); isolated_preference(); std::cout << "Italian/English catalog, recovery behavior, strict language parsing and isolated preference persistence passed.\n"; return 0; }
    catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
