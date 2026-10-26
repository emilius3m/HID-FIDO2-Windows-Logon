#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

namespace hidfido::password {
using Bytes = std::vector<std::uint8_t>;
using Salt = std::array<std::uint8_t, 32>;
using Nonce = std::array<std::uint8_t, 12>;
using Tag = std::array<std::uint8_t, 16>;
inline constexpr std::uint32_t envelope_version = 1;
inline constexpr std::size_t max_plaintext_bytes = 4096;
enum class Purpose : std::uint32_t { wrapped_data_key = 1, secret_payload = 2 };

// Owns a noncopyable allocation that is zeroed before release, including on
// exceptions. VirtualLock is best effort; locked() reports its actual result.
// This cannot defend against SYSTEM, debuggers, kernel access or a live process
// compromise. Callers must also clear their original sensitive input buffers.
class SecureBytes {
public:
    SecureBytes() noexcept = default;
    explicit SecureBytes(std::size_t size);
    ~SecureBytes();
    SecureBytes(const SecureBytes&) = delete;
    SecureBytes& operator=(const SecureBytes&) = delete;
    SecureBytes(SecureBytes&& other) noexcept;
    SecureBytes& operator=(SecureBytes&& other) noexcept;
    std::span<std::uint8_t> bytes() noexcept { return {data_, size_}; }
    std::span<const std::uint8_t> bytes() const noexcept { return {data_, size_}; }
    std::size_t size() const noexcept { return size_; }
    bool locked() const noexcept { return locked_; }
    void clear() noexcept;
private:
    void release() noexcept;
    std::uint8_t* data_{};
    std::size_t size_{};
    bool locked_{};
};

// Metadata is public but integrity critical. Every field is bound by exact bytes
// (without Unicode, case or SID normalization) to both HKDF and AES-GCM AAD.
// The caller validates the local account and canonical SID before constructing
// this context. hmac_salt is the public 32-byte salt sent to the authenticator.
struct Context {
    std::string_view account_sid;
    std::string_view account_name;
    std::string_view rp_id;
    std::span<const std::uint8_t> credential_id;
    Salt hmac_salt{};
    std::uint32_t version{envelope_version};
    Purpose purpose{Purpose::wrapped_data_key};
};

struct Envelope {
    std::uint32_t version{envelope_version};
    Nonce nonce{};
    Bytes ciphertext;
    Tag tag{};
};

// uv_hmac_secret must be exactly the authenticated, UV-protected 32-byte
// hmac-secret output for context.credential_id and context.hmac_salt. This
// module does NOT perform or establish FIDO user verification. In particular,
// a non-UV hmac-secret output is not an acceptable input. Erase the source
// secret after this synchronous call. No password, PIN or secret is logged.
// A vault should generate a common random data-encryption key (DEK), then seal
// that 32-byte DEK under each credential with purpose=wrapped_data_key. Password
// rotation can then replace one common DEK-protected payload while preserving
// the other keys' wrappers. This module does not implement that machine vault.
// Purpose is cryptographically bound; secret_payload permits bounded arbitrary
// bytes for isolated use/tests. Adding/revoking wrappers is caller-managed.
Envelope seal(std::span<const std::uint8_t> uv_hmac_secret,
              const Context& context, std::span<const std::uint8_t> plaintext);
SecureBytes open(std::span<const std::uint8_t> uv_hmac_secret,
                 const Context& context, const Envelope& envelope);

namespace crypto {
// Narrow primitives are public for standard known-answer tests. HKDF bounds
// each input to 4096 bytes and output to 255 * 32 bytes (RFC 5869 SHA-256).
SecureBytes hkdf_sha256(std::span<const std::uint8_t> input_key_material,
                       std::span<const std::uint8_t> salt,
                       std::span<const std::uint8_t> info,
                       std::size_t output_size);
// Only 256-bit keys, 96-bit nonces and full 128-bit tags are supported. A caller
// of the raw encrypt primitive must NEVER reuse a nonce with the same key;
// seal() instead generates its nonce with the system CNG RNG.
Envelope aes256_gcm_encrypt(std::span<const std::uint8_t> key,
                            const Nonce& nonce,
                            std::span<const std::uint8_t> aad,
                            std::span<const std::uint8_t> plaintext);
// Authentication must succeed before any plaintext is returned. On all
// failures, temporary plaintext and key buffers are erased by RAII.
SecureBytes aes256_gcm_decrypt(std::span<const std::uint8_t> key,
                              const Nonce& nonce,
                              std::span<const std::uint8_t> aad,
                              std::span<const std::uint8_t> ciphertext,
                              const Tag& tag);
}
}
