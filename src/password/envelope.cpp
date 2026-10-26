#include "hidfido/password_envelope.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <cstring>
#include <stdexcept>
#include <utility>

namespace hidfido::password {
namespace {
constexpr std::size_t max_context_bytes = 4096;
constexpr std::size_t max_secure_allocation = 64 * 1024;

void check(NTSTATUS status, const char* operation) {
    // Errors deliberately contain no inputs, metadata or secret bytes.
    if (status < 0) throw std::runtime_error(operation);
}

void bounded(std::size_t value, std::size_t maximum, const char* error) {
    if (value > maximum) throw std::invalid_argument(error);
}

PUCHAR input(std::span<const std::uint8_t> bytes) noexcept {
    return const_cast<PUCHAR>(bytes.data());
}

class Algorithm {
public:
    explicit Algorithm(LPCWSTR name, ULONG flags = 0) {
        check(BCryptOpenAlgorithmProvider(&handle_, name, MS_PRIMITIVE_PROVIDER, flags),
              "CNG algorithm initialization failed");
    }
    ~Algorithm() { if (handle_) BCryptCloseAlgorithmProvider(handle_, 0); }
    Algorithm(const Algorithm&) = delete;
    Algorithm& operator=(const Algorithm&) = delete;
    BCRYPT_ALG_HANDLE get() const noexcept { return handle_; }
    ULONG object_size() const {
        ULONG size{}, written{};
        check(BCryptGetProperty(handle_, BCRYPT_OBJECT_LENGTH,
              reinterpret_cast<PUCHAR>(&size), sizeof(size), &written, 0),
              "CNG object size query failed");
        if (written != sizeof(size) || size == 0 || size > max_secure_allocation) {
            throw std::runtime_error("Invalid CNG object size");
        }
        return size;
    }
private:
    BCRYPT_ALG_HANDLE handle_{};
};

class Hmac {
public:
    explicit Hmac(std::span<const std::uint8_t> key)
        : algorithm_(BCRYPT_SHA256_ALGORITHM, BCRYPT_ALG_HANDLE_HMAC_FLAG),
          object_(algorithm_.object_size()) {
        check(BCryptCreateHash(algorithm_.get(), &handle_, object_.bytes().data(),
              static_cast<ULONG>(object_.size()), input(key),
              static_cast<ULONG>(key.size()), 0), "CNG HMAC initialization failed");
    }
    ~Hmac() { if (handle_) BCryptDestroyHash(handle_); }
    Hmac(const Hmac&) = delete;
    Hmac& operator=(const Hmac&) = delete;
    void update(std::span<const std::uint8_t> bytes) {
        if (bytes.empty()) return;
        check(BCryptHashData(handle_, input(bytes), static_cast<ULONG>(bytes.size()), 0),
              "CNG HMAC update failed");
    }
    SecureBytes finish() {
        SecureBytes result(32);
        check(BCryptFinishHash(handle_, result.bytes().data(), 32, 0),
              "CNG HMAC finalization failed");
        return result;
    }
private:
    Algorithm algorithm_;
    SecureBytes object_;
    BCRYPT_HASH_HANDLE handle_{};
};

class AesKey {
public:
    explicit AesKey(std::span<const std::uint8_t> key)
        : algorithm_(BCRYPT_AES_ALGORITHM), object_(algorithm_.object_size()) {
        if (key.size() != 32) throw std::invalid_argument("AES-256 key must be 32 bytes");
        check(BCryptSetProperty(algorithm_.get(), BCRYPT_CHAINING_MODE,
              reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)),
              sizeof(BCRYPT_CHAIN_MODE_GCM), 0), "CNG GCM initialization failed");
        check(BCryptGenerateSymmetricKey(algorithm_.get(), &handle_,
              object_.bytes().data(), static_cast<ULONG>(object_.size()),
              input(key), static_cast<ULONG>(key.size()), 0),
              "CNG AES key initialization failed");
    }
    ~AesKey() { if (handle_) BCryptDestroyKey(handle_); }
    AesKey(const AesKey&) = delete;
    AesKey& operator=(const AesKey&) = delete;
    BCRYPT_KEY_HANDLE get() const noexcept { return handle_; }
private:
    Algorithm algorithm_;
    SecureBytes object_;
    BCRYPT_KEY_HANDLE handle_{};
};

std::span<const std::uint8_t> bytes(std::string_view text) noexcept {
    return {reinterpret_cast<const std::uint8_t*>(text.data()), text.size()};
}

void append_u32(Bytes& output, std::uint32_t value) {
    output.push_back(static_cast<std::uint8_t>(value >> 24));
    output.push_back(static_cast<std::uint8_t>(value >> 16));
    output.push_back(static_cast<std::uint8_t>(value >> 8));
    output.push_back(static_cast<std::uint8_t>(value));
}

void append_field(Bytes& output, std::span<const std::uint8_t> field) {
    append_u32(output, static_cast<std::uint32_t>(field.size()));
    output.insert(output.end(), field.begin(), field.end());
}

void validate(const Context& context) {
    if (context.version != envelope_version) {
        throw std::invalid_argument("Unsupported password envelope version");
    }
    if (context.purpose != Purpose::wrapped_data_key &&
        context.purpose != Purpose::secret_payload) {
        throw std::invalid_argument("Unsupported password envelope purpose");
    }
    if (context.account_sid.empty() || context.account_sid.size() > 184 ||
        context.account_name.empty() || context.account_name.size() > 1024 ||
        context.rp_id.empty() || context.rp_id.size() > 253 ||
        context.credential_id.empty() || context.credential_id.size() > 1023) {
        throw std::invalid_argument("Invalid password envelope binding");
    }
    if (context.account_sid.find('\0') != std::string_view::npos ||
        context.account_name.find('\0') != std::string_view::npos ||
        context.rp_id.find('\0') != std::string_view::npos) {
        throw std::invalid_argument("Embedded NUL in password envelope binding");
    }
}

Bytes binding(const Context& context, std::string_view domain) {
    Bytes result;
    result.reserve(64 + context.account_sid.size() + context.account_name.size() +
                   context.rp_id.size() + context.credential_id.size());
    append_field(result, bytes(domain));
    append_u32(result, context.version);
    append_u32(result, static_cast<std::uint32_t>(context.purpose));
    append_field(result, bytes(context.account_sid));
    append_field(result, bytes(context.account_name));
    append_field(result, bytes(context.rp_id));
    append_field(result, context.credential_id);
    append_field(result, context.hmac_salt);
    bounded(result.size(), max_context_bytes, "Password envelope binding exceeds limit");
    return result;
}

SecureBytes derive(std::span<const std::uint8_t> secret, const Context& context) {
    if (secret.size() != 32) {
        throw std::invalid_argument("UV hmac-secret output must be 32 bytes");
    }
    const auto info = binding(context, "HIDFIDO/WINDOWS-PASSWORD/KEK/HKDF-SHA256/v1");
    return crypto::hkdf_sha256(secret, context.hmac_salt, info, 32);
}
}

SecureBytes::SecureBytes(std::size_t size) : size_(size) {
    bounded(size, max_secure_allocation, "Secure allocation exceeds limit");
    if (size == 0) return;
    data_ = static_cast<std::uint8_t*>(VirtualAlloc(nullptr, size,
                                                   MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!data_) throw std::runtime_error("Secure allocation failed");
    locked_ = VirtualLock(data_, size_) != FALSE;
}

SecureBytes::~SecureBytes() { release(); }

SecureBytes::SecureBytes(SecureBytes&& other) noexcept
    : data_(std::exchange(other.data_, nullptr)), size_(std::exchange(other.size_, 0)),
      locked_(std::exchange(other.locked_, false)) {}

SecureBytes& SecureBytes::operator=(SecureBytes&& other) noexcept {
    if (this != &other) {
        release();
        data_ = std::exchange(other.data_, nullptr);
        size_ = std::exchange(other.size_, 0);
        locked_ = std::exchange(other.locked_, false);
    }
    return *this;
}

void SecureBytes::clear() noexcept {
    if (data_ && size_) SecureZeroMemory(data_, size_);
}

void SecureBytes::release() noexcept {
    if (data_) {
        clear();
        if (locked_) VirtualUnlock(data_, size_);
        VirtualFree(data_, 0, MEM_RELEASE);
    }
    data_ = nullptr;
    size_ = 0;
    locked_ = false;
}

namespace crypto {
SecureBytes hkdf_sha256(std::span<const std::uint8_t> input_key_material,
                       std::span<const std::uint8_t> salt,
                       std::span<const std::uint8_t> info,
                       std::size_t output_size) {
    bounded(input_key_material.size(), max_context_bytes, "HKDF input exceeds limit");
    bounded(salt.size(), max_context_bytes, "HKDF salt exceeds limit");
    bounded(info.size(), max_context_bytes, "HKDF info exceeds limit");
    if (output_size == 0 || output_size > 255 * 32) {
        throw std::invalid_argument("Invalid HKDF output length");
    }
    const std::array<std::uint8_t, 32> zero_salt{};
    Hmac extract(salt.empty() ? std::span<const std::uint8_t>(zero_salt) : salt);
    extract.update(input_key_material);
    auto prk = extract.finish();
    SecureBytes output(output_size);
    SecureBytes previous;
    std::size_t position{};
    for (std::uint16_t i = 1; position < output_size; ++i) {
        Hmac expand(prk.bytes());
        expand.update(previous.bytes());
        expand.update(info);
        const std::array<std::uint8_t, 1> counter{static_cast<std::uint8_t>(i)};
        expand.update(counter);
        previous = expand.finish();
        const auto count = (std::min)(previous.size(), output_size - position);
        std::copy_n(previous.bytes().begin(), count, output.bytes().begin() + position);
        position += count;
    }
    return output;
}

Envelope aes256_gcm_encrypt(std::span<const std::uint8_t> key, const Nonce& nonce,
                            std::span<const std::uint8_t> aad,
                            std::span<const std::uint8_t> plaintext) {
    bounded(plaintext.size(), max_plaintext_bytes, "Password plaintext exceeds limit");
    bounded(aad.size(), max_context_bytes, "GCM authenticated data exceeds limit");
    AesKey aes(key);
    Envelope result;
    result.nonce = nonce;
    result.ciphertext.resize(plaintext.size());
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth;
    BCRYPT_INIT_AUTH_MODE_INFO(auth);
    auth.pbNonce = input(nonce);
    auth.cbNonce = static_cast<ULONG>(nonce.size());
    auth.pbAuthData = input(aad);
    auth.cbAuthData = static_cast<ULONG>(aad.size());
    auth.pbTag = result.tag.data();
    auth.cbTag = static_cast<ULONG>(result.tag.size());
    // A non-null output for empty messages ensures this is an actual AEAD call,
    // not CNG's output-size query (which would not calculate/verify a tag).
    std::uint8_t empty_output{};
    ULONG written{};
    check(BCryptEncrypt(aes.get(), input(plaintext), static_cast<ULONG>(plaintext.size()),
          &auth, nullptr, 0, result.ciphertext.empty() ? &empty_output : result.ciphertext.data(),
          static_cast<ULONG>(result.ciphertext.size()), &written, 0),
          "CNG authenticated encryption failed");
    if (written != plaintext.size()) throw std::runtime_error("Invalid GCM output size");
    return result;
}

SecureBytes aes256_gcm_decrypt(std::span<const std::uint8_t> key, const Nonce& nonce,
                              std::span<const std::uint8_t> aad,
                              std::span<const std::uint8_t> ciphertext, const Tag& tag) {
    bounded(ciphertext.size(), max_plaintext_bytes, "Password ciphertext exceeds limit");
    bounded(aad.size(), max_context_bytes, "GCM authenticated data exceeds limit");
    AesKey aes(key);
    SecureBytes result(ciphertext.size());
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth;
    BCRYPT_INIT_AUTH_MODE_INFO(auth);
    auth.pbNonce = input(nonce);
    auth.cbNonce = static_cast<ULONG>(nonce.size());
    auth.pbAuthData = input(aad);
    auth.cbAuthData = static_cast<ULONG>(aad.size());
    auth.pbTag = input(tag);
    auth.cbTag = static_cast<ULONG>(tag.size());
    std::uint8_t empty_output{};
    ULONG written{};
    check(BCryptDecrypt(aes.get(), input(ciphertext), static_cast<ULONG>(ciphertext.size()),
          &auth, nullptr, 0, result.size() == 0 ? &empty_output : result.bytes().data(),
          static_cast<ULONG>(result.size()), &written, 0),
          "Password envelope authentication failed");
    if (written != ciphertext.size()) throw std::runtime_error("Invalid GCM output size");
    return result;
}
}

Envelope seal(std::span<const std::uint8_t> uv_hmac_secret, const Context& context,
              std::span<const std::uint8_t> plaintext) {
    validate(context);
    bounded(plaintext.size(), max_plaintext_bytes, "Password plaintext exceeds limit");
    if (context.purpose == Purpose::wrapped_data_key && plaintext.size() != 32) {
        throw std::invalid_argument("Wrapped data-encryption key must be 32 bytes");
    }
    auto key = derive(uv_hmac_secret, context);
    const auto aad = binding(context, "HIDFIDO/WINDOWS-PASSWORD/AAD/AES256-GCM/v1");
    Nonce nonce{};
    check(BCryptGenRandom(nullptr, nonce.data(), static_cast<ULONG>(nonce.size()),
                          BCRYPT_USE_SYSTEM_PREFERRED_RNG), "CNG nonce generation failed");
    return crypto::aes256_gcm_encrypt(key.bytes(), nonce, aad, plaintext);
}

SecureBytes open(std::span<const std::uint8_t> uv_hmac_secret, const Context& context,
                 const Envelope& envelope) {
    validate(context);
    if (envelope.version != context.version) {
        throw std::invalid_argument("Password envelope version mismatch");
    }
    if (context.purpose == Purpose::wrapped_data_key && envelope.ciphertext.size() != 32) {
        throw std::invalid_argument("Wrapped data-encryption key must be 32 bytes");
    }
    auto key = derive(uv_hmac_secret, context);
    const auto aad = binding(context, "HIDFIDO/WINDOWS-PASSWORD/AAD/AES256-GCM/v1");
    return crypto::aes256_gcm_decrypt(key.bytes(), envelope.nonce, aad,
                                     envelope.ciphertext, envelope.tag);
}
}
