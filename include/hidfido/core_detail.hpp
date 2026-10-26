#pragma once

#include "hidfido/core.hpp"

// Internal entry points shared by the strict core and CTAP extension verifier.
// Do not use these without validating the extension output with core_hmac.hpp.
namespace hidfido::detail {
struct ExtensionRegistration {
    Credential credential;
    std::size_t extension_offset{};
};

ExtensionRegistration parse_extension_registration(
    std::span<const std::uint8_t> authenticator_data);

// Requires ED, verifies every signed byte including the extension map, and
// applies the existing RP, UP/UV, flag, DER, public key and counter policy.
// Extension CBOR semantics are deliberately checked by the strict wrapper.
std::uint32_t verify_extension_assertion_signature(
    const Credential& credential,
    std::span<const std::uint8_t> authenticator_data,
    std::span<const std::uint8_t> signature,
    std::string_view expected_client_data);
}
