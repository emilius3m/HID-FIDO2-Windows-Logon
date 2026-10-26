#include "hidfido/pin_protocol.hpp"

#include <algorithm>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace {
using namespace hidfido::pin;
using Bytes = std::vector<std::uint8_t>;

static_assert(!std::is_copy_constructible_v<KeyAgreement>);
static_assert(!std::is_copy_assignable_v<KeyAgreement>);
static_assert(std::is_nothrow_move_constructible_v<KeyAgreement>);
static_assert(std::is_nothrow_move_assignable_v<KeyAgreement>);

void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

template<class Action>
void rejects(Action&& action) {
    try { action(); }
    catch (const std::exception&) { return; }
    throw std::runtime_error("PIN protocol accepted invalid input");
}

Bytes hex(std::string_view text) {
    if (text.size() % 2) throw std::runtime_error("Invalid public test vector");
    auto nibble = [](char c) -> std::uint8_t {
        if (c >= '0' && c <= '9') return static_cast<std::uint8_t>(c - '0');
        if (c >= 'a' && c <= 'f') return static_cast<std::uint8_t>(c - 'a' + 10);
        throw std::runtime_error("Invalid public test vector digit");
    };
    Bytes result;
    for (std::size_t i = 0; i < text.size(); i += 2) {
        result.push_back(static_cast<std::uint8_t>((nibble(text[i]) << 4) | nibble(text[i + 1])));
    }
    return result;
}

Hash coordinate(std::string_view text) {
    const auto value = hex(text);
    if (value.size() != 32) throw std::runtime_error("Invalid test coordinate");
    Hash result{};
    std::copy(value.begin(), value.end(), result.begin());
    return result;
}

std::span<const std::uint8_t> bytes(std::string_view text) {
    return {reinterpret_cast<const std::uint8_t*>(text.data()), text.size()};
}

bool equal(std::span<const std::uint8_t> left, std::span<const std::uint8_t> right) {
    return std::equal(left.begin(), left.end(), right.begin(), right.end());
}

void hash_vectors() {
    require(equal(sha256(bytes("abc")).bytes(),
                  hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")),
            "SHA-256 abc known-answer mismatch");
    require(equal(sha256({}).bytes(),
                  hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")),
            "SHA-256 empty known-answer mismatch");
    // RFC 4231 section 4.2, test case 1 (public synthetic key).
    const Bytes key(20, 0x0b);
    require(equal(hmac_sha256(key, bytes("Hi There")).bytes(),
                  hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")),
            "RFC 4231 HMAC-SHA256 mismatch");
    const Bytes excessive(65537);
    rejects([&] { sha256(excessive); });
    rejects([&] { hmac_sha256(excessive, {}); });
    rejects([&] { hmac_sha256(key, excessive); });
}

void cbc_vectors() {
    // NIST SP 800-38A F.2.5 AES-256 CBC. XOR the published nonzero IV
    // into block 1: CBC under IV=0 must then produce the published ciphertext.
    // This retains the remaining three published plaintext blocks unchanged.
    const auto key = hex("603deb1015ca71be2b73aef0857d7781"
                         "1f352c073b6108d72d9810a30914dff4");
    const auto plaintext = hex("6bc0bce12a459991e134741a7f9e1925"
                               "ae2d8a571e03ac9c9eb76fac45af8e51"
                               "30c81c46a35ce411e5fbc1191a0a52ef"
                               "f69f2445df4f9b17ad2b417be66c3710");
    const auto expected = hex("f58c4c04d6e5f1ba779eabfb5f7bfbd6"
                              "9cfc4e967edb808d679f777bc6702c7d"
                              "39f23369a9d9bacfa530e26304231461"
                              "b2eb05e2c39be9fcda6c19078c6a9d1b");
    for (const std::size_t count : {std::size_t{16}, std::size_t{32}, std::size_t{48}, std::size_t{64}}) {
        const auto plain = std::span<const std::uint8_t>(plaintext).first(count);
        const auto cipher = std::span<const std::uint8_t>(expected).first(count);
        require(equal(aes256_cbc_encrypt(key, plain).bytes(), cipher), "AES-256-CBC NIST encrypt mismatch");
        require(equal(aes256_cbc_decrypt(key, cipher).bytes(), plain), "AES-256-CBC NIST decrypt mismatch");
        require(equal(aes256_cbc_encrypt(key, plain).bytes(), cipher), "AES CBC did not reset its zero IV");
    }
    // Independent longer CBC fixtures: plaintext byte i is i modulo 256.
    // Expected ciphertext SHA256 digests were produced with Python cryptography
    // AES-256-CBC(IV=0), separately from the CNG implementation under test.
    for (const auto& [count, expected_digest] : {
             std::pair<std::size_t, std::string_view>{80, "ee0aabba9396f9824a22af0c4e3864cd1b47570cd3763e8dc88c0def71bfbb32"},
             std::pair<std::size_t, std::string_view>{512, "732812f5917471d70c98a8b081ba143765ed52b88ed9359d025c0b357ad0a56b"}}) {
        Bytes plain(count);
        for (std::size_t i = 0; i < count; ++i) plain[i] = static_cast<std::uint8_t>(i % 256);
        auto encrypted = aes256_cbc_encrypt(key, plain);
        require(equal(sha256(encrypted.bytes()).bytes(), hex(expected_digest)), "Long AES CBC known-answer mismatch");
        require(equal(aes256_cbc_decrypt(key, encrypted.bytes()).bytes(), plain), "Long AES CBC decryption mismatch");
    }
    const Bytes bad_key(31);
    rejects([&] { aes256_cbc_encrypt(bad_key, plaintext); });
    rejects([&] { aes256_cbc_decrypt(bad_key, expected); });
    for (const std::size_t count : {std::size_t{0}, std::size_t{15}, std::size_t{17},
                                  std::size_t{65}, std::size_t{511}, std::size_t{513}, std::size_t{528}}) {
        const Bytes invalid(count);
        rejects([&] { aes256_cbc_encrypt(key, invalid); });
        rejects([&] { aes256_cbc_decrypt(key, invalid); });
    }
}

void agreement_vectors() {
    // RFC 5903 section 8.1 P-256 ECDH vector. The CTAP protocol-1 KDF is
    // SHA256 of its fixed-width, big-endian shared x (d6840f6b...4b9442de).
    // Expected digest calculated independently with Python hashlib SHA256.
    const auto scalar = hex("c88f01f510d9ac3f70a292daa2316de544e9aab8afe84049c62a9c57862d1433");
    const P256PublicKey ours{
        coordinate("dad0b65394221cf9b051e1feca5787d098dfe637fc90b9ef945d0c3772581180"),
        coordinate("5271a0461cdb8252d61f1c456fa3e59ab1f45b33accf5f58389e0577b8990bb3")};
    const P256PublicKey peer{
        coordinate("d12dfb5289c8d4f81208b70270398c342296970a0bccb74c736fc7554494bf63"),
        coordinate("56fbf3ca366cc23e8157854c13c58d6aac23f046ada30f8353e74f33039872ab")};
    auto agreement = KeyAgreement::from_private_for_testing(scalar, ours);
    const auto exported = agreement.public_key();
    require(exported.x == ours.x && exported.y == ours.y, "P-256 public coordinate export mismatch");
    require(equal(agreement.shared_secret(peer).bytes(),
                  hex("0519dc09b36efad1d00aef1d5b53b100202eb910b5de0dede75f190a357a367d")),
            "RFC 5903 CTAP ECDH KDF mismatch (check raw secret endian order)");
    rejects([&] { agreement.shared_secret(P256PublicKey{}); });
    auto off_curve = peer;
    off_curve.y.back() ^= 1;
    rejects([&] { agreement.shared_secret(off_curve); });
    P256PublicKey outside_field;
    outside_field.x.fill(0xff);
    outside_field.y.fill(0xff);
    rejects([&] { agreement.shared_secret(outside_field); });
    rejects([&] { KeyAgreement::from_private_for_testing(Bytes(31), ours); });

    // Independent leading-zero fixture: scalar 1 times public point 379G.
    // Coordinates generated with Python cryptography SECP256R1, expected
    // digest with hashlib. Prevents loss of fixed-width leading zeros.
    Bytes one(32);
    one.back() = 1;
    const P256PublicKey generator{
        coordinate("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"),
        coordinate("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")};
    const P256PublicKey leading_zero{
        coordinate("005543894af3d00ed7d740abdbd75c96b06877b787db5f70eea78b90a8d7c00a"),
        coordinate("bb4c85a3d8ea29efaafa24406912dd84d5b14dc32bf656ef6c6bd58a5d943f92")};
    auto fixed = KeyAgreement::from_private_for_testing(one, generator);
    require(equal(fixed.shared_secret(leading_zero).bytes(),
                  hex("de871827cee742c5599e753fb4ce366b5a7737cec60a046ed730ebf5a162483c")),
            "Leading-zero ECDH coordinate was truncated");

    KeyAgreement alice, bob;
    const auto alice_public = alice.public_key();
    const auto bob_public = bob.public_key();
    require(alice_public.x != bob_public.x || alice_public.y != bob_public.y,
            "Fresh ECDH instances repeated an ephemeral public key");
    require(equal(alice.shared_secret(bob_public).bytes(), bob.shared_secret(alice_public).bytes()),
            "Fresh ECDH peers disagreed");
    KeyAgreement moved(std::move(alice));
    require(moved.public_key().x == alice_public.x, "ECDH move lost its key");
    rejects([&] { alice.public_key(); });
    rejects([&] { alice.shared_secret(bob_public); });
}

void pin_validation() {
    // This public test PIN is synthetic. No user's PIN is read or printed.
    require(equal(pin_hash16(bytes("1234")).bytes(), hex("03ac674216f3e15c761ee1a5e255f067")),
            "PIN SHA-256 truncation mismatch");
    require(pin_hash16(bytes(std::string(63, 'a'))).size() == 16, "63-byte PIN rejected");
    require(pin_hash16(hex("c3a9c3a9c3a9c3a9")).size() == 16, "Four multibyte Unicode scalars rejected");
    require(pin_hash16(hex("f09f9880f09f9880f09f9880f09f9880")).size() == 16,
            "Four supplementary Unicode scalars rejected");
    rejects([&] { pin_hash16({}); });
    rejects([&] { pin_hash16(bytes("123")); });
    rejects([&] { pin_hash16(bytes(std::string(64, 'a'))); });
    rejects([&] { pin_hash16(hex("f09f9880f09f9880f09f9880")); });
    for (const auto malformed : {
             "31323300", "3132333480", "31323334c080", "31323334c1bf", "31323334c2",
             "31323334c241", "31323334e09fbf", "31323334eda080", "31323334edbfbf",
             "31323334efbf", "31323334f08fbfbf", "31323334f4908080", "31323334f5808080",
             "31323334ff", "31323334fe", "31323334f09f98"}) {
        rejects([&] { pin_hash16(hex(malformed)); });
    }
}
}

int main() {
    try {
        hash_vectors();
        cbc_vectors();
        agreement_vectors();
        pin_validation();
        std::cout << "PIN protocol 1: SHA/HMAC/AES vectors, ECDH endian/leading-zero/point checks and UTF-8 bounds passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "PIN protocol 1 test failed: " << error.what() << '\n';
        return 1;
    }
}
