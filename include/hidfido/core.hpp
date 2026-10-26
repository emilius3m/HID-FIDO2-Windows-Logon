#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace hidfido {
using Bytes = std::vector<std::uint8_t>;
using Hash = std::array<std::uint8_t, 32>;
inline constexpr char rp_id[] = "hid-fido2-winlogon.localhost";
inline constexpr wchar_t rp_id_w[] = L"hid-fido2-winlogon.localhost";
inline constexpr char origin[] = "https://hid-fido2-winlogon.localhost";

struct Credential {
    Bytes id;
    Hash x{};
    Hash y{};
    std::array<std::uint8_t, 16> aaguid{};
    Hash user_handle{};
    std::uint32_t sign_count{};
    std::wstring label;
    std::wstring owner_sid;
};

Bytes random_bytes(std::size_t count);
Hash sha256(std::span<const std::uint8_t> bytes);
std::string base64url(std::span<const std::uint8_t> bytes);
// JSON is constructed locally, held for one synchronous ceremony, and signed verbatim.
std::string make_client_data(std::string_view type, std::span<const std::uint8_t> challenge);
// Enrollment uses attestation=none; this parses a bounded ES256 COSE public key.
// A subsequent fresh verified assertion is mandatory before persistence.
Credential parse_registration(std::span<const std::uint8_t> authenticator_data,
                              std::span<const std::uint8_t> returned_id);
// Rejects RP mismatch, absent UP/UV, extensions/AT, invalid flags, malformed DER,
// bad ES256 signature, and counter rollback. Returns the new counter.
std::uint32_t verify_assertion(const Credential& credential,
                               std::span<const std::uint8_t> authenticator_data,
                               std::span<const std::uint8_t> signature,
                               std::string_view expected_client_data);
}
