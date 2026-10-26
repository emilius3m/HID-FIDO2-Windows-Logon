#pragma once

#include "hidfido/password_envelope.hpp"

#include <array>
#include <cstdint>
#include <memory>
#include <span>

namespace hidfido::pin {
using SecureBytes = password::SecureBytes;
using Hash = std::array<std::uint8_t, 32>;

// Coordinates use the 32-byte big-endian representation required by COSE EC2.
struct P256PublicKey { Hash x{}, y{}; };

// CTAP PIN/UV protocol 1 only. A default-constructed object owns a fresh CNG
// ECDH P-256 ephemeral key; neither its scalar nor raw ECDH secret is exported.
// Obtain a fresh instance for each clientPIN or hmac-secret transaction.
class KeyAgreement {
public:
    KeyAgreement();
    ~KeyAgreement();
    KeyAgreement(const KeyAgreement&) = delete;
    KeyAgreement& operator=(const KeyAgreement&) = delete;
    KeyAgreement(KeyAgreement&&) noexcept;
    KeyAgreement& operator=(KeyAgreement&&) noexcept;
    P256PublicKey public_key() const;
    SecureBytes shared_secret(const P256PublicKey& peer) const;

    // Import only public, synthetic standard test vectors. Normal callers must
    // use the default constructor: production key agreement must be fresh.
    static KeyAgreement from_private_for_testing(
        std::span<const std::uint8_t> private_scalar, const P256PublicKey& public_key);
private:
    struct Impl;
    explicit KeyAgreement(std::unique_ptr<Impl> impl) noexcept;
    std::unique_ptr<Impl> impl_;
};

SecureBytes sha256(std::span<const std::uint8_t> message);
SecureBytes hmac_sha256(std::span<const std::uint8_t> key,
                        std::span<const std::uint8_t> message);

// Protocol 1 CBC with an all-zero IV and no padding. Accepts positive block
// multiples from 16 through 512 bytes, permitting authenticator-selected
// CTAP 2.0 PIN-token sizes; 512 is an application allocation cap. These
// primitives do not authenticate ciphertext; the CTAP client must verify its
// protocol and assertion bindings separately.
SecureBytes aes256_cbc_encrypt(std::span<const std::uint8_t> key,
                              std::span<const std::uint8_t> plaintext);
SecureBytes aes256_cbc_decrypt(std::span<const std::uint8_t> key,
                              std::span<const std::uint8_t> ciphertext);

// LEFT(SHA256(PIN),16). Rejects malformed UTF-8, NUL, fewer than four Unicode
// scalar values, and more than 63 UTF-8 bytes. Does not normalize Unicode;
// any normalization policy belongs to the input UI, before this boundary.
// The caller owns and must erase the original PIN after the synchronous call.
SecureBytes pin_hash16(std::span<const std::uint8_t> utf8_pin);
}
