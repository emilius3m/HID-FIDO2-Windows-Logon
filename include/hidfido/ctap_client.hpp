#pragma once

#include "hidfido/core.hpp"
#include "hidfido/ctap_info.hpp"
#include "hidfido/password_envelope.hpp"

#include <cstdint>
#include <span>
#include <stdexcept>
#include <string_view>

namespace hidfido::ctap {

// Exchanges exactly one CTAP command (command byte followed by CBOR). Returns
// the status byte and response CBOR; transports must never retry PIN commands.
class Transport {
public:
    virtual ~Transport() = default;
    virtual Bytes transact(std::span<const std::uint8_t> command) = 0;
};

class StatusError : public std::runtime_error {
public:
    explicit StatusError(std::uint8_t status);
    std::uint8_t status() const noexcept { return status_; }
private:
    std::uint8_t status_{};
};

// One synchronous ceremony per call. PIN inputs are UTF-8, owned and erased by
// the caller. This client does not cache PIN tokens and never retries a failure.
// It supports one hmac-secret salt, CTAP PIN protocol 1, and ES256 credentials.
class HmacClient {
public:
    explicit HmacClient(Transport& transport) noexcept : transport_(transport) {}
    AuthenticatorInfo info();
    // Returns a provisional, dedicated nonresident credential. A successful
    // get_secret with a fresh challenge is required before trusting/persisting it.
    // user_name/display_name are UTF-8 labels stored with the credential.
    // exclude_ids (at most 8) makes a key that already holds one of them refuse
    // with CTAP2_ERR_CREDENTIAL_EXCLUDED (0x19).
    Credential make_credential(std::span<const std::uint8_t> utf8_pin,
                               const Hash& user_handle,
                               std::string_view user_name = "hmac-test",
                               std::string_view display_name = "HMAC secret test",
                               std::span<const Bytes> exclude_ids = {});
    // Requires independently verified signed UP+UV and the signed 32-byte
    // hmac-secret extension before decrypting. Updates counter only on success.
    password::SecureBytes get_secret(std::span<const std::uint8_t> utf8_pin,
                                     Credential& credential, const Hash& salt);
private:
    Transport& transport_;
};
}
