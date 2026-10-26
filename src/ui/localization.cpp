#include "hidfido/localization.hpp"
#include <windows.h>
#include <atomic>

namespace hidfido::ui {
namespace {
std::atomic<Language> selected{Language::english};
constexpr wchar_t preference_key[] = L"SOFTWARE\\HID-FIDO2-WinLogon\\Preferences";
constexpr Translation catalog[]{
#define HIDFIDO_STRING(key, italian, english) {key, italian, english},
#include "hidfido/strings.inc"
#undef HIDFIDO_STRING
};
}
Language language() noexcept { return selected.load(std::memory_order_relaxed); }
void set_language(Language value) noexcept { selected.store(value, std::memory_order_relaxed); }
std::optional<Language> parse_language(std::wstring_view value) noexcept {
    if (value == L"it") return Language::italian;
    if (value == L"en") return Language::english;
    return std::nullopt;
}
const wchar_t* language_code(Language value) noexcept { return value == Language::italian ? L"it" : L"en"; }
Language preferred_language() noexcept {
    const auto fallback = PRIMARYLANGID(GetUserDefaultUILanguage()) == LANG_ITALIAN ? Language::italian : Language::english;
    wchar_t value[3]{}; DWORD bytes = sizeof(value);
    if (RegGetValueW(HKEY_LOCAL_MACHINE, preference_key, L"Language", RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY,
                     nullptr, value, &bytes) != ERROR_SUCCESS || bytes != sizeof(value) || value[2] != L'\0') return fallback;
    return parse_language(std::wstring_view(value, 2)).value_or(fallback);
}
bool save_preferred_language(Language value) noexcept {
    HKEY key{};
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, preference_key, 0, nullptr, REG_OPTION_NON_VOLATILE,
                       KEY_SET_VALUE | KEY_WOW64_64KEY, nullptr, &key, nullptr) != ERROR_SUCCESS) return false;
    const auto result = RegSetValueExW(key, L"Language", 0, REG_SZ,
        reinterpret_cast<const BYTE*>(language_code(value)), 3 * sizeof(wchar_t));
    RegCloseKey(key);
    return result == ERROR_SUCCESS;
}
const wchar_t* tr(const wchar_t* key) noexcept {
    if (!key) return L"";
    for (const auto& entry : catalog) if (entry.key == key) return language() == Language::italian ? entry.italian : entry.english;
    // Keys at call sites are static, null-terminated literals. The completeness
    // check rejects an untranslated call site before a release is packaged.
    return key;
}
std::span<const Translation> translations() noexcept { return catalog; }
}
