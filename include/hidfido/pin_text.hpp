#pragma once

#include "hidfido/password_envelope.hpp"

#include <span>

namespace hidfido::pin {
// Converts a FIDO2 PIN typed as UTF-16 (no terminator) to NFC-normalized UTF-8
// and validates it locally with pin_hash16 before any authenticator attempt is
// consumed. Throws std::runtime_error on malformed input; no PIN text in errors.
password::SecureBytes utf8_from_typed(std::span<const wchar_t> typed);
}
