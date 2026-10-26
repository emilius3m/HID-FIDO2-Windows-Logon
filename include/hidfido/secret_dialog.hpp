#pragma once

#include "hidfido/password_envelope.hpp"

#include <optional>

// Local, project-owned input windows. Secrets never pass through the console,
// command-line arguments, files or logs; edit controls are cleared on exit.
namespace hidfido::ui {
// Masked single-line input. Returns the typed UTF-16 code units (no
// terminator) or nullopt when cancelled or empty.
std::optional<password::SecureBytes> prompt_secret(const wchar_t* title, const wchar_t* instructions,
                                                   unsigned max_units);
// FIDO2 PIN: NFC UTF-8, validated locally; format errors are shown and the
// window stays open, without any authenticator attempt.
std::optional<password::SecureBytes> request_fido_pin(const wchar_t* title, const wchar_t* instructions);
// Disables console QuickEdit selection: a click in the console would otherwise
// freeze this process's output, and with it the ceremony, until Esc is pressed.
void disable_console_selection() noexcept;
}
