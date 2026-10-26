#include "hidfido/pin_protocol.hpp"

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

namespace hidfido::pin {
namespace {
constexpr std::size_t max_input_size = 64 * 1024;

void check(NTSTATUS status, const char* operation) {
    if (status < 0) throw std::runtime_error(operation);
}

PUCHAR input(std::span<const std::uint8_t> bytes) noexcept {
    return const_cast<PUCHAR>(bytes.data());
}

void bound(std::span<const std::uint8_t> bytes) {
    if (bytes.size() > max_input_size) throw std::invalid_argument("PIN protocol input exceeds limit");
}

class Algorithm {
public:
    explicit Algorithm(LPCWSTR name, ULONG flags = 0) {
        check(BCryptOpenAlgorithmProvider(&handle_, name, MS_PRIMITIVE_PROVIDER, flags),
              "PIN protocol CNG algorithm initialization failed");
    }
    ~Algorithm() { if (handle_) BCryptCloseAlgorithmProvider(handle_, 0); }
    Algorithm(const Algorithm&) = delete;
    Algorithm& operator=(const Algorithm&) = delete;
    BCRYPT_ALG_HANDLE get() const noexcept { return handle_; }
    ULONG object_size() const {
        ULONG size{}, written{};
        check(BCryptGetProperty(handle_, BCRYPT_OBJECT_LENGTH,
              reinterpret_cast<PUCHAR>(&size), sizeof(size), &written, 0),
              "PIN protocol CNG object query failed");
        if (written != sizeof(size) || size == 0 || size > max_input_size) {
            throw std::runtime_error("PIN protocol CNG object size invalid");
        }
        return size;
    }
private:
    BCRYPT_ALG_HANDLE handle_{};
};

struct Key {
    BCRYPT_KEY_HANDLE handle{};
    Key() = default;
    ~Key() { if (handle) BCryptDestroyKey(handle); }
    Key(const Key&) = delete;
    Key& operator=(const Key&) = delete;
};

struct Secret {
    BCRYPT_SECRET_HANDLE handle{};
    Secret() = default;
    ~Secret() { if (handle) BCryptDestroySecret(handle); }
    Secret(const Secret&) = delete;
    Secret& operator=(const Secret&) = delete;
};

struct HashHandle {
    BCRYPT_HASH_HANDLE handle{};
    HashHandle() = default;
    ~HashHandle() { if (handle) BCryptDestroyHash(handle); }
    HashHandle(const HashHandle&) = delete;
    HashHandle& operator=(const HashHandle&) = delete;
};

SecureBytes digest(std::span<const std::uint8_t> message,
                   std::span<const std::uint8_t> key, bool hmac) {
    bound(message);
    bound(key);
    Algorithm algorithm(BCRYPT_SHA256_ALGORITHM, hmac ? BCRYPT_ALG_HANDLE_HMAC_FLAG : 0);
    SecureBytes object(algorithm.object_size());
    HashHandle hash;
    check(BCryptCreateHash(algorithm.get(), &hash.handle, object.bytes().data(),
          static_cast<ULONG>(object.size()), input(key), static_cast<ULONG>(key.size()), 0),
          "PIN protocol hash initialization failed");
    if (!message.empty()) {
        check(BCryptHashData(hash.handle, input(message), static_cast<ULONG>(message.size()), 0),
              "PIN protocol hash update failed");
    }
    SecureBytes result(32);
    check(BCryptFinishHash(hash.handle, result.bytes().data(), 32, 0),
          "PIN protocol hash finalization failed");
    return result;
}

SecureBytes cbc(std::span<const std::uint8_t> key,
                std::span<const std::uint8_t> message, bool encrypt) {
    if (key.size() != 32) throw std::invalid_argument("PIN protocol AES key must be 32 bytes");
    if (message.empty() || message.size() > 512 || message.size() % 16 != 0) {
        throw std::invalid_argument("PIN protocol AES payload must be a 16-byte multiple from 16 to 512 bytes");
    }
    Algorithm algorithm(BCRYPT_AES_ALGORITHM);
    check(BCryptSetProperty(algorithm.get(), BCRYPT_CHAINING_MODE,
          reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_CBC)),
          sizeof(BCRYPT_CHAIN_MODE_CBC), 0), "PIN protocol CBC initialization failed");
    SecureBytes object(algorithm.object_size());
    Key aes;
    check(BCryptGenerateSymmetricKey(algorithm.get(), &aes.handle, object.bytes().data(),
          static_cast<ULONG>(object.size()), input(key), static_cast<ULONG>(key.size()), 0),
          "PIN protocol AES key initialization failed");
    // CNG mutates the IV. A fresh zero IV is required on every operation.
    SecureBytes iv(16);
    SecureBytes result(message.size());
    ULONG written{};
    const auto length = static_cast<ULONG>(message.size());
    if (encrypt) {
        check(BCryptEncrypt(aes.handle, input(message), length, nullptr,
              iv.bytes().data(), 16, result.bytes().data(), length, &written, 0),
              "PIN protocol CBC encryption failed");
    } else {
        check(BCryptDecrypt(aes.handle, input(message), length, nullptr,
              iv.bytes().data(), 16, result.bytes().data(), length, &written, 0),
              "PIN protocol CBC decryption failed");
    }
    if (written != length) throw std::runtime_error("PIN protocol CBC output size invalid");
    return result;
}

struct PublicBlob {
    BCRYPT_ECCKEY_BLOB header{BCRYPT_ECDH_PUBLIC_P256_MAGIC, 32};
    Hash x{}, y{};
};
static_assert(sizeof(PublicBlob) == sizeof(BCRYPT_ECCKEY_BLOB) + 64);

void validate_pin(std::span<const std::uint8_t> pin) {
    if (pin.size() < 4 || pin.size() > 63) throw std::invalid_argument("PIN length is outside CTAP2 limits");
    std::size_t characters{};
    for (std::size_t i = 0; i < pin.size();) {
        std::size_t width{};
        if (pin[i] >= 1 && pin[i] <= 0x7f) width = 1;
        else if (pin[i] >= 0xc2 && pin[i] <= 0xdf) width = 2;
        else if (pin[i] >= 0xe0 && pin[i] <= 0xef) width = 3;
        else if (pin[i] >= 0xf0 && pin[i] <= 0xf4) width = 4;
        else throw std::invalid_argument("PIN is not valid non-NUL UTF-8");
        if (width > pin.size() - i) throw std::invalid_argument("PIN contains truncated UTF-8");
        for (std::size_t j = 1; j < width; ++j) {
            if ((pin[i + j] & 0xc0) != 0x80) throw std::invalid_argument("PIN contains invalid UTF-8 continuation");
        }
        if ((width == 3 && ((pin[i] == 0xe0 && pin[i + 1] < 0xa0) ||
                           (pin[i] == 0xed && pin[i + 1] >= 0xa0))) ||
            (width == 4 && ((pin[i] == 0xf0 && pin[i + 1] < 0x90) ||
                           (pin[i] == 0xf4 && pin[i + 1] >= 0x90)))) {
            throw std::invalid_argument("PIN contains non-scalar or overlong UTF-8");
        }
        i += width;
        ++characters;
    }
    if (characters < 4) throw std::invalid_argument("PIN needs at least four Unicode characters");
}
}

struct KeyAgreement::Impl {
    Algorithm algorithm{BCRYPT_ECDH_P256_ALGORITHM};
    Key key;
    Impl() {
        check(BCryptGenerateKeyPair(algorithm.get(), &key.handle, 256, 0),
              "PIN protocol ECDH key generation failed");
        check(BCryptFinalizeKeyPair(key.handle, 0), "PIN protocol ECDH key finalization failed");
    }
    Impl(std::span<const std::uint8_t> scalar, const P256PublicKey& point) {
        if (scalar.size() != 32) throw std::invalid_argument("P-256 test scalar must be 32 bytes");
        SecureBytes blob(sizeof(BCRYPT_ECCKEY_BLOB) + 96);
        const BCRYPT_ECCKEY_BLOB header{BCRYPT_ECDH_PRIVATE_P256_MAGIC, 32};
        std::memcpy(blob.bytes().data(), &header, sizeof(header));
        auto position = blob.bytes().begin() + sizeof(header);
        position = std::copy(point.x.begin(), point.x.end(), position);
        position = std::copy(point.y.begin(), point.y.end(), position);
        std::copy(scalar.begin(), scalar.end(), position);
        check(BCryptImportKeyPair(algorithm.get(), nullptr, BCRYPT_ECCPRIVATE_BLOB,
              &key.handle, blob.bytes().data(), static_cast<ULONG>(blob.size()), 0),
              "PIN protocol ECDH test key import failed");
    }
};

KeyAgreement::KeyAgreement() : impl_(std::make_unique<Impl>()) {}
KeyAgreement::KeyAgreement(std::unique_ptr<Impl> impl) noexcept : impl_(std::move(impl)) {}
KeyAgreement::~KeyAgreement() = default;
KeyAgreement::KeyAgreement(KeyAgreement&&) noexcept = default;
KeyAgreement& KeyAgreement::operator=(KeyAgreement&&) noexcept = default;

KeyAgreement KeyAgreement::from_private_for_testing(
    std::span<const std::uint8_t> scalar, const P256PublicKey& public_key) {
    return KeyAgreement(std::make_unique<Impl>(scalar, public_key));
}

P256PublicKey KeyAgreement::public_key() const {
    if (!impl_) throw std::logic_error("PIN protocol key agreement was moved");
    PublicBlob blob;
    ULONG written{};
    check(BCryptExportKey(impl_->key.handle, nullptr, BCRYPT_ECCPUBLIC_BLOB,
          reinterpret_cast<PUCHAR>(&blob), sizeof(blob), &written, 0),
          "PIN protocol ECDH public key export failed");
    if (written != sizeof(blob) || blob.header.dwMagic != BCRYPT_ECDH_PUBLIC_P256_MAGIC ||
        blob.header.cbKey != 32) throw std::runtime_error("PIN protocol ECDH public key format invalid");
    return {blob.x, blob.y};
}

SecureBytes KeyAgreement::shared_secret(const P256PublicKey& peer) const {
    if (!impl_) throw std::logic_error("PIN protocol key agreement was moved");
    PublicBlob blob;
    blob.x = peer.x;
    blob.y = peer.y;
    Key peer_key;
    // No BCRYPT_NO_KEY_VALIDATION: CNG must validate the P-256 point.
    check(BCryptImportKeyPair(impl_->algorithm.get(), nullptr, BCRYPT_ECCPUBLIC_BLOB,
          &peer_key.handle, reinterpret_cast<PUCHAR>(&blob), sizeof(blob), 0),
          "PIN protocol authenticator ECDH point is invalid");
    Secret secret;
    check(BCryptSecretAgreement(impl_->key.handle, peer_key.handle, &secret.handle, 0),
          "PIN protocol ECDH agreement failed");
    SecureBytes raw(32);
    ULONG written{};
    check(BCryptDeriveKey(secret.handle, BCRYPT_KDF_RAW_SECRET, nullptr,
          raw.bytes().data(), 32, &written, 0), "PIN protocol raw ECDH derivation failed");
    if (written != 32) throw std::runtime_error("PIN protocol raw ECDH size invalid");
    // BCryptDeriveKey RAW_SECRET returns little-endian; CTAP hashes the fixed
    // 32-byte big-endian x coordinate, retaining leading zeros.
    std::reverse(raw.bytes().begin(), raw.bytes().end());
    return sha256(raw.bytes());
}

SecureBytes sha256(std::span<const std::uint8_t> message) {
    return digest(message, {}, false);
}

SecureBytes hmac_sha256(std::span<const std::uint8_t> key,
                        std::span<const std::uint8_t> message) {
    return digest(message, key, true);
}

SecureBytes aes256_cbc_encrypt(std::span<const std::uint8_t> key,
                              std::span<const std::uint8_t> plaintext) {
    return cbc(key, plaintext, true);
}

SecureBytes aes256_cbc_decrypt(std::span<const std::uint8_t> key,
                              std::span<const std::uint8_t> ciphertext) {
    return cbc(key, ciphertext, false);
}

SecureBytes pin_hash16(std::span<const std::uint8_t> utf8_pin) {
    validate_pin(utf8_pin);
    auto hash = sha256(utf8_pin);
    SecureBytes result(16);
    std::copy_n(hash.bytes().begin(), result.size(), result.bytes().begin());
    return result;
}
}
