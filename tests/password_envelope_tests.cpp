#include "hidfido/password_envelope.hpp"

#include <algorithm>
#include <iostream>
#include <stdexcept>
#include <string>
#include <type_traits>

namespace {
using namespace hidfido::password;

static_assert(!std::is_copy_constructible_v<SecureBytes>);
static_assert(!std::is_copy_assignable_v<SecureBytes>);
static_assert(std::is_nothrow_move_constructible_v<SecureBytes>);
static_assert(std::is_nothrow_move_assignable_v<SecureBytes>);

void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

template<class Action>
void rejects(Action&& action) {
    try { action(); }
    catch (const std::exception&) { return; }
    throw std::runtime_error("Malformed or unauthenticated data was accepted");
}

Bytes hex(std::string_view text) {
    if (text.size() % 2) throw std::runtime_error("Invalid test vector");
    auto nibble = [](char c) -> std::uint8_t {
        if (c >= '0' && c <= '9') return static_cast<std::uint8_t>(c - '0');
        if (c >= 'a' && c <= 'f') return static_cast<std::uint8_t>(c - 'a' + 10);
        throw std::runtime_error("Invalid test vector digit");
    };
    Bytes result;
    for (std::size_t i = 0; i < text.size(); i += 2) {
        result.push_back(static_cast<std::uint8_t>((nibble(text[i]) << 4) | nibble(text[i + 1])));
    }
    return result;
}

bool equal(std::span<const std::uint8_t> left, std::span<const std::uint8_t> right) {
    return std::equal(left.begin(), left.end(), right.begin(), right.end());
}

void hkdf_vectors() {
    // RFC 5869 Appendix A.1 and A.3, SHA-256, including empty salt/info.
    const Bytes ikm(22, 0x0b);
    const auto salt = hex("000102030405060708090a0b0c");
    const auto info = hex("f0f1f2f3f4f5f6f7f8f9");
    const auto expected = hex("3cb25f25faacd57a90434f64d0362f2a"
                              "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                              "34007208d5b887185865");
    auto actual = crypto::hkdf_sha256(ikm, salt, info, 42);
    require(equal(actual.bytes(), expected), "RFC 5869 case 1 failed");
    actual = crypto::hkdf_sha256(ikm, {}, {}, 42);
    require(equal(actual.bytes(), hex("8da4e775a563c18f715f802a063c5a31"
                                      "b8a11f5c5ee1879ec3454e5f3c738d2d"
                                      "9d201395faa4b61a96c8")), "RFC 5869 case 3 failed");
    rejects([&] { crypto::hkdf_sha256(ikm, salt, info, 0); });
    rejects([&] { crypto::hkdf_sha256(ikm, salt, info, 255 * 32 + 1); });
    const Bytes excessive(4097, 0);
    rejects([&] { crypto::hkdf_sha256(excessive, salt, info, 32); });
    rejects([&] { crypto::hkdf_sha256(ikm, excessive, info, 32); });
    rejects([&] { crypto::hkdf_sha256(ikm, salt, excessive, 32); });
}

void gcm_vectors() {
    // NIST SP 800-38D / GCM test vectors: AES-256, zero key and 96-bit IV.
    const Bytes key(32, 0);
    const Nonce nonce{};
    const Bytes block(16, 0);
    auto encrypted = crypto::aes256_gcm_encrypt(key, nonce, {}, block);
    require(equal(encrypted.ciphertext, hex("cea7403d4d606b6e074ec5d3baf39d18")),
            "AES-256-GCM known ciphertext mismatch");
    require(equal(encrypted.tag, hex("d0d1c8a799996bf0265b98b5d48ab919")),
            "AES-256-GCM known tag mismatch");
    auto decrypted = crypto::aes256_gcm_decrypt(key, nonce, {}, encrypted.ciphertext, encrypted.tag);
    require(equal(decrypted.bytes(), block), "AES-256-GCM vector decryption failed");

    encrypted = crypto::aes256_gcm_encrypt(key, nonce, {}, {});
    require(encrypted.ciphertext.empty(), "Empty plaintext produced ciphertext");
    require(equal(encrypted.tag, hex("530f8afbc74536b9a963b4f1c4cb738b")),
            "AES-256-GCM empty-message tag mismatch");
    decrypted = crypto::aes256_gcm_decrypt(key, nonce, {}, {}, encrypted.tag);
    require(decrypted.size() == 0, "Empty message decryption failed");
    encrypted.tag[0] ^= 1;
    rejects([&] { crypto::aes256_gcm_decrypt(key, nonce, {}, {}, encrypted.tag); });
    rejects([&] { crypto::aes256_gcm_encrypt(Bytes(31), nonce, {}, block); });

    // Keep the AES key fixed while altering AAD, independently of HKDF context
    // changes: this detects accidental omission of GCM authenticated data.
    Bytes aad{0x01, 0x02, 0x03};
    encrypted = crypto::aes256_gcm_encrypt(key, nonce, aad, block);
    require(equal(crypto::aes256_gcm_decrypt(key, nonce, aad,
                  encrypted.ciphertext, encrypted.tag).bytes(), block),
            "AES-GCM authenticated-data round trip failed");
    aad[0] ^= 1;
    rejects([&] { crypto::aes256_gcm_decrypt(key, nonce, aad,
                       encrypted.ciphertext, encrypted.tag); });
}

void envelope_security() {
    const Bytes credential{0x01, 0, 0x02, 0x9a};
    Context context{"S-1-5-21-123-456-789-1001", "MACHINE\\Synthetic", "example.localhost", credential};
    context.purpose = Purpose::secret_payload;
    for (std::size_t i = 0; i < context.hmac_salt.size(); ++i) {
        context.hmac_salt[i] = static_cast<std::uint8_t>(i);
    }
    const Bytes secret(32, 0x42);
    // Synthetic arbitrary bytes, including NUL and non-UTF-8; never a user password.
    const Bytes plaintext{0xff, 0, 0x50, 0x00, 0x61, 0x00, 0x01, 0xfe};
    const auto envelope = seal(secret, context, plaintext);
    auto actual = open(secret, context, envelope);
    require(equal(actual.bytes(), plaintext), "Synthetic envelope round trip failed");
    const auto another = seal(secret, context, plaintext);
    require(another.nonce != envelope.nonce, "System RNG repeated an envelope nonce");

    auto wrong_secret = secret;
    wrong_secret[0] ^= 1;
    rejects([&] { open(wrong_secret, context, envelope); });
    auto changed = envelope;
    changed.tag[0] ^= 1;
    rejects([&] { open(secret, context, changed); });
    changed = envelope;
    changed.nonce[0] ^= 1;
    rejects([&] { open(secret, context, changed); });
    changed = envelope;
    changed.ciphertext[0] ^= 1;
    rejects([&] { open(secret, context, changed); });
    changed = envelope;
    changed.ciphertext.pop_back();
    rejects([&] { open(secret, context, changed); });
    changed = envelope;
    changed.version = 2;
    rejects([&] { open(secret, context, changed); });

    auto other = context;
    other.account_sid = "S-1-5-21-123-456-789-1002";
    rejects([&] { open(secret, other, envelope); });
    other = context;
    other.account_name = "MACHINE\\Another";
    rejects([&] { open(secret, other, envelope); });
    other = context;
    other.rp_id = "another.localhost";
    rejects([&] { open(secret, other, envelope); });
    auto other_credential = credential;
    other_credential[0] ^= 1;
    other = context;
    other.credential_id = other_credential;
    rejects([&] { open(secret, other, envelope); });
    other = context;
    other.hmac_salt[0] ^= 1;
    rejects([&] { open(secret, other, envelope); });
    other = context;
    other.version = 2;
    rejects([&] { seal(secret, other, plaintext); });
    other = context;
    other.purpose = Purpose::wrapped_data_key;
    rejects([&] { open(secret, other, envelope); });
    rejects([&] { seal(secret, other, plaintext); });
    const Bytes synthetic_dek(32, 0x71);
    const auto wrapper = seal(secret, other, synthetic_dek);
    require(equal(open(secret, other, wrapper).bytes(), synthetic_dek),
            "Per-credential DEK wrapping failed");
    rejects([&] { open(secret, context, wrapper); });

    const auto empty = seal(secret, context, {});
    require(open(secret, context, empty).size() == 0, "Empty envelope round trip failed");
    const Bytes largest(max_plaintext_bytes, 0x5a);
    require(equal(open(secret, context, seal(secret, context, largest)).bytes(), largest),
            "Maximum envelope round trip failed");
    rejects([&] { seal(secret, context, Bytes(max_plaintext_bytes + 1)); });
    rejects([&] { seal(Bytes(31), context, plaintext); });
    changed = envelope;
    changed.ciphertext.resize(max_plaintext_bytes + 1);
    rejects([&] { open(secret, context, changed); });
    other = context;
    other.account_sid = {};
    rejects([&] { seal(secret, other, plaintext); });
    other = context;
    other.account_name = std::string_view("A\0B", 3);
    rejects([&] { seal(secret, other, plaintext); });
}

void secure_buffer() {
    SecureBytes original(32);
    std::fill(original.bytes().begin(), original.bytes().end(), std::uint8_t{0x5a});
    SecureBytes moved(std::move(original));
    require(original.size() == 0 && original.bytes().data() == nullptr,
            "Moved-from secure buffer retains ownership");
    require(moved.size() == 32 && moved.bytes()[0] == 0x5a, "Secure move lost data");
    moved.clear();
    require(std::all_of(moved.bytes().begin(), moved.bytes().end(), [](auto b) { return b == 0; }),
            "Explicit secret clearing failed");
    SecureBytes destination(8);
    destination = std::move(moved);
    require(moved.size() == 0 && destination.size() == 32, "Secure move assignment failed");
    rejects([] { SecureBytes excessive(65537); });
}
}

int main() {
    try {
        hkdf_vectors();
        gcm_vectors();
        envelope_security();
        secure_buffer();
        std::cout << "Password envelope: HKDF/AES-GCM vectors, bindings, tampering, bounds and secure buffers passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Password envelope test failed: " << error.what() << '\n';
        return 1;
    }
}
