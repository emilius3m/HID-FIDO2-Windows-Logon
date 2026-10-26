#pragma once

#include <optional>
#include <span>
#include <string_view>

namespace hidfido::ui {
enum class Language { italian, english };
struct Translation { std::wstring_view key; const wchar_t* italian; const wchar_t* english; };

Language language() noexcept;
void set_language(Language value) noexcept;
Language preferred_language() noexcept;
// A presentation preference only. Writing requires the manager's existing
// elevation; it never changes a vault, key, credential or sign-in policy.
bool save_preferred_language(Language value) noexcept;
std::optional<Language> parse_language(std::wstring_view value) noexcept;
const wchar_t* language_code(Language value) noexcept;
const wchar_t* tr(const wchar_t* key) noexcept;
std::span<const Translation> translations() noexcept;
}
