#pragma once

// Tool-only diagnostic. Never link this module into the Credential Provider or
// use it to obtain application secrets. Production HmacClient still requires UV.
#include "hidfido/ctap_client.hpp"

#include <optional>

namespace hidfido::ctap::diagnostic {
enum class Outcome { denied, distinct_secret, same_secret };
struct ProbeResult {
    Outcome outcome;
    std::optional<std::uint8_t> ctap_status;
};

// Checks a dedicated test credential against its previously verified UV secret.
// Sends only clientPIN/getKeyAgreement, never getPINToken or a PIN/hash. The
// assertion explicitly requires UP and omits pinAuth/pinProtocol/uv. A signed
// UV=0 result is independently verified; raw secrets never escape this module.
// Only CTAP PIN_REQUIRED is classified denied. All unexpected/malformed/ambiguous
// results throw an inconclusive error, including an unexpected signed UV=1.
ProbeResult probe_without_pin(Transport& transport, const Credential& credential,
                              const Hash& salt,
                              std::span<const std::uint8_t> expected_uv_secret);
}
