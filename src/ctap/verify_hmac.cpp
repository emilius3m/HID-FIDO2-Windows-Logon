#include "hidfido/core_hmac.hpp"
#include "hidfido/core_detail.hpp"

#include <algorithm>
#include <array>
#include <stdexcept>
#include <utility>

namespace hidfido {
namespace {
// Exactly one canonical, definite-length map entry. This fixed profile rejects
// duplicate/unknown keys, nonminimal lengths, indefinite CBOR and trailing data
// without traversing attacker-selected nested CBOR. CTAP2.1 section 12.5.
constexpr std::array<std::uint8_t, 13> extension_prefix{
    0xa1, 0x6b, 'h', 'm', 'a', 'c', '-', 's', 'e', 'c', 'r', 'e', 't'};

void validate_prefix(std::span<const std::uint8_t> extension) {
    if (extension.size() < extension_prefix.size() ||
        !std::equal(extension_prefix.begin(), extension_prefix.end(), extension.begin())) {
        throw std::runtime_error("Expected exactly one canonical hmac-secret extension");
    }
}
}

Credential parse_hmac_registration(
    std::span<const std::uint8_t> authenticator_data) {
    auto parsed = detail::parse_extension_registration(authenticator_data);
    const auto extension = authenticator_data.subspan(parsed.extension_offset);
    validate_prefix(extension);
    if (extension.size() != extension_prefix.size() + 1 || extension.back() != 0xf5) {
        throw std::runtime_error("Registration requires exactly hmac-secret:true");
    }
    return std::move(parsed.credential);
}

VerifiedHmacAssertion verify_hmac_assertion(
    const Credential& credential,
    std::span<const std::uint8_t> authenticator_data,
    std::span<const std::uint8_t> signature,
    std::string_view expected_client_data) {
    // Verification includes ED and the original complete extension bytes. Never
    // clear ED or truncate authData to pass it through the extension-free API.
    const auto count = detail::verify_extension_assertion_signature(
        credential, authenticator_data, signature, expected_client_data);
    const auto extension = authenticator_data.subspan(37);
    validate_prefix(extension);
    constexpr auto output_offset = extension_prefix.size() + 2;
    if (extension.size() != output_offset + Hash{}.size() ||
        extension[extension_prefix.size()] != 0x58 ||
        extension[extension_prefix.size() + 1] != 0x20) {
        throw std::runtime_error("Assertion requires exactly hmac-secret:bytes32 (PIN protocol 1)");
    }
    VerifiedHmacAssertion result;
    std::copy_n(extension.begin() + output_offset, result.ciphertext.size(),
                result.ciphertext.begin());
    result.sign_count = count;
    return result;
}
}
