#pragma once

#include "hidfido/password_envelope.hpp"

#include <cstdint>
#include <span>
#include <string>
#include <string_view>

// Credential material handed by the credential provider to LogonUI, which
// passes it to the standard Negotiate package. Windows alone authenticates the
// account and creates the session.
namespace hidfido::logon {
enum class Kind { interactive, unlock };

// Packed KERB_INTERACTIVE_UNLOCK_LOGON: the structure followed by domain, user
// name and a CredProtectW-protected password (UTF-16, no terminators). The
// input password is protected for the current calling context before packing;
// no plaintext password is exported to the caller. Each UNICODE_STRING Buffer holds
// the offset of its text from the start of the result. The returned buffer is
// erased on destruction; callers copy it into CoTaskMem for LogonUI.
password::SecureBytes pack_interactive_logon(Kind kind, std::wstring_view domain, std::wstring_view user,
                                             std::span<const std::uint8_t> password_utf16);

// What the provider does after Windows reports the logon result.
struct ResultAdvice {
    bool success{};
    // The stored password must not be replayed again (changed, expired, ...):
    // the vault record is suspended until updated with hid-fido2-vault.
    bool suspend_record{};
    std::wstring message;   // Italian, shown in the tile; empty on success
};
ResultAdvice advise_logon_result(std::int32_t status, std::int32_t substatus);
}
