#pragma once

#include "hidfido/core.hpp"

namespace hidfido {
// Parses a CTAP registration containing exactly the canonical hmac-secret:true
// extension output and an ES256 public key. Derives the ID from attested data.
// A subsequent assertion with a fresh challenge must succeed before persistence.
Credential parse_hmac_registration(
    std::span<const std::uint8_t> authenticator_data);

struct VerifiedHmacAssertion {
    Hash ciphertext{};
    std::uint32_t sign_count{};
};

// PIN/UV protocol 1, one salt only. Returns encrypted extension output only
// after independent ES256 verification of the complete authenticator data.
// Requires UP+UV, exactly hmac-secret:bytes32, no AT, no unknown extensions,
// no trailing data, the local RP/client-data policy and monotonic counters.
VerifiedHmacAssertion verify_hmac_assertion(
    const Credential& credential,
    std::span<const std::uint8_t> authenticator_data,
    std::span<const std::uint8_t> signature,
    std::string_view expected_client_data);
}
