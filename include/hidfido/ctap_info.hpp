#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace hidfido::ctap {

struct AuthenticatorInfo {
    std::vector<std::string> versions;
    std::vector<std::string> extensions;
    std::array<std::uint8_t, 16> aaguid{};
    std::vector<std::uint32_t> pin_protocols;
    std::optional<bool> client_pin;
    std::optional<bool> uv;
    std::optional<bool> rk;
    std::optional<std::uint32_t> max_msg_size;
    bool hmac_secret{};
};

// Parse the CTAP status byte followed by the authenticatorGetInfo CBOR map.
// This pure function issues no authenticator commands. Unknown members are
// skipped, but must contain bounded, well-formed CBOR. Throws runtime_error.
// Definite lengths and shortest integer/length encodings are required; map
// order is tolerated for interoperability, while duplicate keys are rejected.
AuthenticatorInfo parse_get_info(std::span<const std::uint8_t> response);

}
