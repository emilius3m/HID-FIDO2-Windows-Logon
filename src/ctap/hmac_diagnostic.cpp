#include "hmac_diagnostic.hpp"
#include "hidfido/pin_protocol.hpp"

#include <windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <string>
#include <string_view>
#include <utility>

namespace hidfido::ctap::diagnostic {
namespace {
constexpr std::size_t max_message = 8192;
constexpr std::uint8_t pin_required = 0x36;

[[noreturn]] void invalid(const char* message) {
    throw std::runtime_error(std::string("UV diagnostic inconclusive: ") + message);
}
void check_cng(NTSTATUS status, const char* message) { if (status < 0) invalid(message); }
std::span<const std::uint8_t> as_bytes(std::string_view value) {
    return {reinterpret_cast<const std::uint8_t*>(value.data()), value.size()};
}
void append(Bytes& out, std::span<const std::uint8_t> value) { out.insert(out.end(), value.begin(), value.end()); }
void head(Bytes& out, std::uint8_t major, std::uint64_t value) {
    const auto initial = static_cast<std::uint8_t>(major << 5);
    if (value < 24) out.push_back(static_cast<std::uint8_t>(initial | value));
    else {
        unsigned size = value <= 255 ? 1 : value <= 65535 ? 2 : value <= 0xffffffffULL ? 4 : 8;
        out.push_back(static_cast<std::uint8_t>(initial | (size == 1 ? 24 : size == 2 ? 25 : size == 4 ? 26 : 27)));
        while (size) { --size; out.push_back(static_cast<std::uint8_t>(value >> (8 * size))); }
    }
}
void integer(Bytes& out, std::int64_t value) {
    head(out, value < 0 ? 1 : 0, value < 0 ? static_cast<std::uint64_t>(-(value + 1)) : static_cast<std::uint64_t>(value));
}
void text(Bytes& out, std::string_view value) { head(out, 3, value.size()); append(out, as_bytes(value)); }
void blob(Bytes& out, std::span<const std::uint8_t> value) { head(out, 2, value.size()); append(out, value); }
void map(Bytes& out, std::uint64_t size) { head(out, 5, size); }

void utf8(std::span<const std::uint8_t> data) {
    std::size_t position{};
    while (position < data.size()) {
        const auto first = data[position++];
        if (first < 128) continue;
        unsigned count{}; std::uint32_t scalar{}, minimum{};
        if (first >= 0xc2 && first <= 0xdf) { count = 1; scalar = first & 31U; minimum = 128; }
        else if (first >= 0xe0 && first <= 0xef) { count = 2; scalar = first & 15U; minimum = 2048; }
        else if (first >= 0xf0 && first <= 0xf4) { count = 3; scalar = first & 7U; minimum = 65536; }
        else invalid("invalid UTF-8");
        if (count > data.size() - position) invalid("truncated UTF-8");
        while (count--) {
            const auto next = data[position++];
            if ((next & 0xc0U) != 0x80U) invalid("invalid UTF-8 continuation");
            scalar = (scalar << 6) | (next & 63U);
        }
        if (scalar < minimum || scalar > 0x10ffff || (scalar >= 0xd800 && scalar <= 0xdfff)) invalid("invalid UTF-8 scalar");
    }
}
struct Node {
    std::uint8_t major{}, additional{};
    std::uint64_t value{};
    Bytes bytes;
    std::vector<Node> children;
    bool is_int(std::int64_t number) const noexcept {
        return major == (number < 0 ? 1 : 0) && value == (number < 0 ? static_cast<std::uint64_t>(-(number + 1)) : static_cast<std::uint64_t>(number));
    }
    bool is_text(std::string_view value_text) const noexcept { return major == 3 && std::ranges::equal(bytes, as_bytes(value_text)); }
};
class Reader {
public:
    explicit Reader(std::span<const std::uint8_t> data) : data_(data) {}
    Node read(unsigned depth = 0) {
        if (depth > 8 || ++items_ > 4096) invalid("CBOR limits exceeded");
        const auto first = take(1)[0];
        Node node; node.major = static_cast<std::uint8_t>(first >> 5); node.additional = static_cast<std::uint8_t>(first & 31U);
        if (node.additional < 24) node.value = node.additional;
        else {
            if (node.additional > 27) invalid("indefinite/reserved CBOR");
            const unsigned size = 1U << (node.additional - 24U);
            for (const auto byte : take(size)) node.value = (node.value << 8) | byte;
            if (node.major != 7 && ((size == 1 && node.value < 24) || (size == 2 && node.value <= 255) || (size == 4 && node.value <= 65535) || (size == 8 && node.value <= 0xffffffffULL))) invalid("nonminimal CBOR");
            if (node.major == 7 && node.additional == 24 && node.value < 32) invalid("invalid simple CBOR");
        }
        switch (node.major) {
        case 0: case 1: case 7: break;
        case 2: case 3: {
            const auto value = take(node.value); if (node.major == 3) utf8(value);
            node.bytes.assign(value.begin(), value.end()); break;
        }
        case 4:
            if (node.value > 512) invalid("CBOR array exceeds limit");
            for (std::uint64_t i = 0; i < node.value; ++i) node.children.push_back(read(depth + 1));
            break;
        case 5: {
            if (node.value > 128) invalid("CBOR map exceeds limit");
            std::vector<std::span<const std::uint8_t>> keys;
            for (std::uint64_t i = 0; i < node.value; ++i) {
                const auto start = position_; auto key = read(depth + 1);
                if (key.major > 3) invalid("unsupported CBOR map key");
                const auto encoded = data_.subspan(start, position_ - start);
                for (const auto previous : keys) if (std::ranges::equal(previous, encoded)) invalid("duplicate CBOR key");
                keys.push_back(encoded); node.children.push_back(std::move(key)); node.children.push_back(read(depth + 1));
            }
            break;
        }
        default: invalid("CBOR tag not permitted");
        }
        return node;
    }
    bool finished() const noexcept { return position_ == data_.size(); }
private:
    std::span<const std::uint8_t> take(std::uint64_t count) {
        if (count > data_.size() - position_) invalid("truncated CBOR");
        const auto result = data_.subspan(position_, static_cast<std::size_t>(count)); position_ += static_cast<std::size_t>(count); return result;
    }
    std::span<const std::uint8_t> data_;
    std::size_t position_{}, items_{};
};
const Node* member(const Node& node, std::int64_t key) {
    if (node.major != 5) invalid("expected map");
    for (std::size_t i = 0; i < node.children.size(); i += 2) if (node.children[i].is_int(key)) return &node.children[i + 1];
    return nullptr;
}
const Node* member(const Node& node, std::string_view key) {
    if (node.major != 5) invalid("expected map");
    for (std::size_t i = 0; i < node.children.size(); i += 2) if (node.children[i].is_text(key)) return &node.children[i + 1];
    return nullptr;
}
const Node& required(const Node& node, std::int64_t key) {
    const auto* result = member(node, key); if (!result) invalid("missing member"); return *result;
}
const Bytes& byte_string(const Node& node) { if (node.major != 2) invalid("expected byte string"); return node.bytes; }
Node response_map(std::span<const std::uint8_t> response) {
    if (response.empty() || response.size() > max_message) invalid("response size invalid");
    if (response[0]) throw StatusError(response[0]);
    Reader reader(response.subspan(1)); auto result = reader.read();
    if (!reader.finished() || result.major != 5) invalid("response map/trailing bytes invalid");
    return result;
}
void public_key(Bytes& out, const pin::P256PublicKey& key) {
    map(out, 5); integer(out, 1); integer(out, 2); integer(out, 3); integer(out, -25);
    integer(out, -1); integer(out, 1); integer(out, -2); blob(out, key.x); integer(out, -3); blob(out, key.y);
}
pin::P256PublicKey get_key_agreement(Transport& transport) {
    Bytes request{0x06}; map(request, 2); integer(request, 1); integer(request, 1); integer(request, 2); integer(request, 2);
    const auto response = transport.transact(request);
    const auto node = response_map(response); const auto& key = required(node, 1);
    if (!required(key, 1).is_int(2) || !required(key, 3).is_int(-25) || !required(key, -1).is_int(1)) invalid("invalid agreement COSE parameters");
    const auto& x = byte_string(required(key, -2)); const auto& y = byte_string(required(key, -3));
    if (x.size() != 32 || y.size() != 32) invalid("invalid agreement point length");
    pin::P256PublicKey result; std::ranges::copy(x, result.x.begin()); std::ranges::copy(y, result.y.begin()); return result;
}

std::array<std::uint8_t, 64> signature_raw(std::span<const std::uint8_t> der) {
    if (der.size() < 8 || der.size() > 72 || der[0] != 0x30 || der[1] != der.size() - 2) invalid("invalid DER sequence");
    std::array<std::uint8_t, 64> result{}; std::size_t position = 2;
    for (unsigned scalar = 0; scalar < 2; ++scalar) {
        if (der.size() - position < 2 || der[position++] != 2) invalid("invalid DER integer");
        const auto size = der[position++];
        if (size == 0 || size > 33 || size > der.size() - position) invalid("invalid DER integer length");
        auto value = der.subspan(position, size); position += size;
        if ((value[0] & 0x80) != 0) invalid("negative DER integer");
        if (value.size() > 1 && value[0] == 0) {
            if ((value[1] & 0x80) == 0) invalid("nonminimal DER integer");
            value = value.subspan(1);
        }
        if (value.size() > 32 || std::ranges::all_of(value, [](auto byte) { return byte == 0; })) invalid("invalid ECDSA scalar");
        std::ranges::copy(value, result.begin() + scalar * 32 + (32 - value.size()));
    }
    if (position != der.size()) invalid("trailing DER bytes");
    return result;
}
class Algorithm {
public:
    Algorithm() { check_cng(BCryptOpenAlgorithmProvider(&handle_, BCRYPT_ECDSA_P256_ALGORITHM, MS_PRIMITIVE_PROVIDER, 0), "ECDSA provider unavailable"); }
    ~Algorithm() { if (handle_) BCryptCloseAlgorithmProvider(handle_, 0); }
    Algorithm(const Algorithm&) = delete; Algorithm& operator=(const Algorithm&) = delete;
    BCRYPT_ALG_HANDLE get() const noexcept { return handle_; }
private: BCRYPT_ALG_HANDLE handle_{};
};
class Key {
public:
    Key(BCRYPT_ALG_HANDLE algorithm, const Credential& credential) {
        std::array<std::uint8_t, sizeof(BCRYPT_ECCKEY_BLOB) + 64> data{};
        const BCRYPT_ECCKEY_BLOB header{BCRYPT_ECDSA_PUBLIC_P256_MAGIC, 32}; std::memcpy(data.data(), &header, sizeof(header));
        std::copy(credential.x.begin(), credential.x.end(), data.begin() + sizeof(header));
        std::copy(credential.y.begin(), credential.y.end(), data.begin() + sizeof(header) + 32);
        check_cng(BCryptImportKeyPair(algorithm, nullptr, BCRYPT_ECCPUBLIC_BLOB, &handle_, data.data(), static_cast<ULONG>(data.size()), 0), "invalid ECDSA public point");
    }
    ~Key() { if (handle_) BCryptDestroyKey(handle_); }
    Key(const Key&) = delete; Key& operator=(const Key&) = delete;
    BCRYPT_KEY_HANDLE get() const noexcept { return handle_; }
private: BCRYPT_KEY_HANDLE handle_{};
};

Hash verify_non_uv(const Credential& credential, std::span<const std::uint8_t> auth,
                    std::span<const std::uint8_t> signature, const Hash& client_hash) {
    if (auth.size() < 37 || auth.size() > 4096) invalid("authenticator data length invalid");
    const auto rp_hash = sha256(as_bytes(rp_id));
    if (!std::equal(rp_hash.begin(), rp_hash.end(), auth.begin())) invalid("RP hash mismatch");
    if (auth[32] != 0x81) invalid("expected UP=1, UV=0, ED=1 with no other flags");
    const auto count = (static_cast<std::uint32_t>(auth[33]) << 24) | (static_cast<std::uint32_t>(auth[34]) << 16) | (static_cast<std::uint32_t>(auth[35]) << 8) | auth[36];
    if ((credential.sign_count || count) && count <= credential.sign_count) invalid("signature counter did not increase");
    const auto raw = signature_raw(signature);
    Bytes signed_data(auth.begin(), auth.end()); append(signed_data, client_hash); const auto digest = sha256(signed_data);
    Algorithm algorithm; Key key(algorithm.get(), credential);
    check_cng(BCryptVerifySignature(key.get(), nullptr, const_cast<PUCHAR>(digest.data()), static_cast<ULONG>(digest.size()), const_cast<PUCHAR>(raw.data()), static_cast<ULONG>(raw.size()), 0), "ES256 signature verification failed");
    Reader reader(auth.subspan(37)); const auto extension = reader.read();
    if (!reader.finished() || extension.major != 5 || extension.children.size() != 2 || !extension.children[0].is_text("hmac-secret")) invalid("unexpected signed extension");
    const auto& ciphertext = byte_string(extension.children[1]);
    if (ciphertext.size() != 32) invalid("hmac-secret ciphertext length invalid");
    Hash result; std::ranges::copy(ciphertext, result.begin()); return result;
}
void verify_descriptor(const Node& descriptor, const Credential& credential) {
    const auto* id = member(descriptor, "id"); const auto* type = member(descriptor, "type");
    if (!id || !type || !type->is_text("public-key") || !std::ranges::equal(byte_string(*id), credential.id)) invalid("credential descriptor mismatch");
}
bool equal_secret(std::span<const std::uint8_t> left, std::span<const std::uint8_t> right) noexcept {
    volatile unsigned difference = 0;
    for (std::size_t i = 0; i < 32; ++i) difference = difference | (left[i] ^ right[i]);
    return difference == 0;
}
}

ProbeResult probe_without_pin(Transport& transport, const Credential& credential,
                              const Hash& salt, std::span<const std::uint8_t> expected_uv_secret) {
    if (expected_uv_secret.size() != 32) invalid("expected UV secret must contain 32 bytes");
    if (credential.id.empty() || credential.id.size() > 1023) invalid("invalid credential ID length");
    pin::KeyAgreement agreement;
    password::SecureBytes shared;
    try { shared = agreement.shared_secret(get_key_agreement(transport)); }
    catch (const StatusError&) { invalid("key agreement failed before assertion"); }
    auto encrypted_salt = pin::aes256_cbc_encrypt(shared.bytes(), salt);
    auto salt_auth = pin::hmac_sha256(shared.bytes(), encrypted_salt.bytes());
    const auto challenge = random_bytes(32);
    const auto client = make_client_data("webauthn.get", challenge);
    const auto client_hash = sha256(as_bytes(client));
    Bytes request{0x02}; map(request, 5);
    integer(request, 1); text(request, rp_id); integer(request, 2); blob(request, client_hash);
    integer(request, 3); head(request, 4, 1); map(request, 2); text(request, "id"); blob(request, credential.id); text(request, "type"); text(request, "public-key");
    integer(request, 4); map(request, 1); text(request, "hmac-secret"); map(request, 3);
    integer(request, 1); public_key(request, agreement.public_key()); integer(request, 2); blob(request, encrypted_salt.bytes()); integer(request, 3); blob(request, salt_auth.bytes().first(16));
    integer(request, 5); map(request, 1); text(request, "up"); request.push_back(0xf5);
    const auto response = transport.transact(request);
    if (response.empty() || response.size() > max_message) invalid("assertion response size invalid");
    // A status-only refusal is meaningful here; never reinterpret unrelated
    // failures, trailing data, malformed output or unexpected UV as protection.
    if (response[0] == pin_required) {
        if (response.size() != 1) invalid("PIN_REQUIRED response has trailing data");
        return {Outcome::denied, pin_required};
    }
    Node result;
    try { result = response_map(response); }
    catch (const StatusError& error) {
        throw std::runtime_error("UV diagnostic inconclusive: CTAP status " + std::to_string(error.status()));
    }
    if (const auto* descriptor = member(result, 1)) verify_descriptor(*descriptor, credential);
    if (const auto* number = member(result, 5); number && !number->is_int(1)) invalid("unexpected credential count");
    const auto ciphertext = verify_non_uv(credential, byte_string(required(result, 2)), byte_string(required(result, 3)), client_hash);
    auto secret = pin::aes256_cbc_decrypt(shared.bytes(), ciphertext);
    if (secret.size() != 32) invalid("decrypted secret size invalid");
    const auto outcome = equal_secret(secret.bytes(), expected_uv_secret) ? Outcome::same_secret : Outcome::distinct_secret;
    secret.clear();
    return {outcome, std::nullopt};
}
}
