#include "hidfido/core.hpp"

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
#include <functional>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <utility>

namespace {
using hidfido::Bytes;
using hidfido::Credential;
using hidfido::Hash;

void require(bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error(message);
}

void check_cng(NTSTATUS status, const char* operation) {
    if (status < 0) throw std::runtime_error(std::string("Test setup failed: ") + operation);
}

template<typename Action>
void rejects(Action&& action, std::string_view expected = {}) {
    bool rejected = false;
    try {
        action();
    } catch (const std::exception& error) {
        rejected = true;
        if (!expected.empty()) {
            require(std::string_view(error.what()).find(expected) != std::string_view::npos,
                    std::string("Wrong rejection: ") + error.what() +
                    "; expected a message containing " + std::string(expected));
        }
    }
    require(rejected, "Invalid input was accepted");
}

std::span<const std::uint8_t> bytes(std::string_view text) {
    return {reinterpret_cast<const std::uint8_t*>(text.data()), text.size()};
}

void set_counter(Bytes& auth, std::uint32_t value) {
    auth[33] = static_cast<std::uint8_t>(value >> 24);
    auth[34] = static_cast<std::uint8_t>(value >> 16);
    auth[35] = static_cast<std::uint8_t>(value >> 8);
    auth[36] = static_cast<std::uint8_t>(value);
}

Bytes assertion_auth(std::uint32_t count, std::uint8_t flags = 0x05) {
    Bytes auth(37);
    const auto rp_hash = hidfido::sha256(bytes(hidfido::rp_id));
    std::copy(rp_hash.begin(), rp_hash.end(), auth.begin());
    auth[32] = flags;
    set_counter(auth, count);
    return auth;
}

Bytes integer_der(std::span<const std::uint8_t> scalar) {
    while (scalar.size() > 1 && scalar[0] == 0) scalar = scalar.subspan(1);
    const bool sign_padding = (scalar[0] & 0x80) != 0;
    Bytes result{0x02, static_cast<std::uint8_t>(scalar.size() + (sign_padding ? 1 : 0))};
    if (sign_padding) result.push_back(0);
    result.insert(result.end(), scalar.begin(), scalar.end());
    return result;
}

Bytes p1363_der(std::span<const std::uint8_t> raw) {
    require(raw.size() == 64, "Test key produced wrong P-256 signature size");
    const auto r = integer_der(raw.first(32));
    const auto s = integer_der(raw.subspan(32));
    Bytes result{0x30, static_cast<std::uint8_t>(r.size() + s.size())};
    result.insert(result.end(), r.begin(), r.end());
    result.insert(result.end(), s.begin(), s.end());
    return result;
}

class Fixture {
public:
    Fixture() {
        try {
            check_cng(BCryptOpenAlgorithmProvider(&algorithm_, BCRYPT_ECDSA_P256_ALGORITHM,
                                                   MS_PRIMITIVE_PROVIDER, 0), "open ECDSA");
            check_cng(BCryptGenerateKeyPair(algorithm_, &key_, 256, 0), "generate P-256 key");
            check_cng(BCryptFinalizeKeyPair(key_, 0), "finalize P-256 key");
            std::array<std::uint8_t, sizeof(BCRYPT_ECCKEY_BLOB) + 64> exported{};
            ULONG size{};
            check_cng(BCryptExportKey(key_, nullptr, BCRYPT_ECCPUBLIC_BLOB,
                                       exported.data(), static_cast<ULONG>(exported.size()),
                                       &size, 0), "export public key");
            require(size == exported.size(), "Unexpected exported public key length");
            std::copy_n(exported.begin() + sizeof(BCRYPT_ECCKEY_BLOB), 32, credential.x.begin());
            std::copy_n(exported.begin() + sizeof(BCRYPT_ECCKEY_BLOB) + 32, 32, credential.y.begin());
            credential.id = {0x11, 0x00, 0xff, 0x82, 0x5a};
            for (std::size_t i = 0; i < credential.aaguid.size(); ++i) {
                credential.aaguid[i] = static_cast<std::uint8_t>(i + 1);
            }
            const Hash challenge{};
            client_data = hidfido::make_client_data("webauthn.get", challenge);
        } catch (...) {
            cleanup();
            throw;
        }
    }
    ~Fixture() { cleanup(); }
    Fixture(const Fixture&) = delete;
    Fixture& operator=(const Fixture&) = delete;

    Bytes sign(std::span<const std::uint8_t> auth, std::string_view client) const {
        const auto client_hash = hidfido::sha256(bytes(client));
        Bytes message(auth.begin(), auth.end());
        message.insert(message.end(), client_hash.begin(), client_hash.end());
        const auto digest = hidfido::sha256(message);
        std::array<std::uint8_t, 64> raw{};
        ULONG written{};
        check_cng(BCryptSignHash(key_, nullptr, const_cast<PUCHAR>(digest.data()),
                                  static_cast<ULONG>(digest.size()), raw.data(),
                                  static_cast<ULONG>(raw.size()), &written, 0), "sign assertion");
        require(written == raw.size(), "Unexpected P-256 signature length");
        return p1363_der(raw);
    }

    Bytes cose() const {
        Bytes result{0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20};
        result.insert(result.end(), credential.x.begin(), credential.x.end());
        result.insert(result.end(), {0x22, 0x58, 0x20});
        result.insert(result.end(), credential.y.begin(), credential.y.end());
        return result;
    }

    Bytes registration(std::uint32_t count = 5) const {
        auto auth = assertion_auth(count, 0x45);
        auth.insert(auth.end(), credential.aaguid.begin(), credential.aaguid.end());
        auth.push_back(static_cast<std::uint8_t>(credential.id.size() >> 8));
        auth.push_back(static_cast<std::uint8_t>(credential.id.size()));
        auth.insert(auth.end(), credential.id.begin(), credential.id.end());
        const auto public_key = cose();
        auth.insert(auth.end(), public_key.begin(), public_key.end());
        return auth;
    }

    Credential credential;
    std::string client_data;
private:
    void cleanup() noexcept {
        if (key_) { BCryptDestroyKey(key_); key_ = nullptr; }
        if (algorithm_) { BCryptCloseAlgorithmProvider(algorithm_, 0); algorithm_ = nullptr; }
    }
    BCRYPT_ALG_HANDLE algorithm_{};
    BCRYPT_KEY_HANDLE key_{};
};

class Runner {
public:
    template<typename Action>
    void run(const char* name, Action&& action) {
        ++total_;
        try {
            action();
            std::cout << "[PASS] " << name << '\n';
        } catch (const std::exception& error) {
            ++failures_;
            std::cerr << "[FAIL] " << name << ": " << error.what() << '\n';
        }
    }
    int finish() const {
        std::cout << total_ - failures_ << '/' << total_ << " tests passed\n";
        return failures_ == 0 ? 0 : 1;
    }
private:
    int total_{};
    int failures_{};
};
} // namespace

int main() {
    try {
        Fixture fixture;
        Runner runner;

        runner.run("SHA-256 known-answer vectors", [] {
            constexpr Hash abc{
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
                0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
                0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
                0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad};
            constexpr Hash empty{
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
                0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
                0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
                0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55};
            require(hidfido::sha256(bytes("abc")) == abc, "SHA-256 abc mismatch");
            require(hidfido::sha256({}) == empty, "SHA-256 empty mismatch");
        });

        runner.run("Unpadded base64url boundary vectors", [] {
            require(hidfido::base64url({}).empty(), "Empty base64url mismatch");
            require(hidfido::base64url(bytes("f")) == "Zg", "One-byte base64url mismatch");
            require(hidfido::base64url(bytes("fo")) == "Zm8", "Two-byte base64url mismatch");
            require(hidfido::base64url(bytes("foo")) == "Zm9v", "Three-byte base64url mismatch");
            require(hidfido::base64url(bytes("foobar")) == "Zm9vYmFy", "Base64url mismatch");
            require(hidfido::base64url(Bytes{0xfb, 0xff, 0xff}) == "-___", "URL alphabet mismatch");
        });

        runner.run("RNG and bounded local client data", [] {
            const auto first = hidfido::random_bytes(32);
            const auto second = hidfido::random_bytes(32);
            require(first.size() == 32 && first != second, "RNG smoke check failed");
            require(hidfido::random_bytes(0).empty(), "Zero-length RNG mismatch");
            const Hash zero{};
            const auto get = hidfido::make_client_data("webauthn.get", zero);
            require(get == std::string("{\"type\":\"webauthn.get\",\"challenge\":\"") +
                           std::string(43, 'A') + "\",\"origin\":\"" + hidfido::origin +
                           "\",\"crossOrigin\":false}", "Client JSON mismatch");
            require(hidfido::make_client_data("webauthn.create", first).find("webauthn.create") !=
                    std::string::npos, "Creation ceremony type mismatch");
            rejects([&] { hidfido::make_client_data("get\"", first); }, "ceremony type");
            rejects([] { hidfido::make_client_data("webauthn.get", Bytes(31)); }, "32-byte");
            rejects([] { hidfido::random_bytes(1024 * 1024 + 1); }, "limit");
            rejects([] { hidfido::base64url(Bytes(1024 * 1024 + 1)); }, "limit");
        });

        runner.run("Generated CNG key verifies valid ES256 assertion", [&] {
            auto credential = fixture.credential;
            credential.sign_count = 5;
            const auto auth = assertion_auth(6);
            const auto signature = fixture.sign(auth, fixture.client_data);
            require(hidfido::verify_assertion(credential, auth, signature, fixture.client_data) == 6,
                    "Valid assertion returned wrong counter");
        });

        runner.run("Signature binds challenge, counter and credential public key", [&] {
            const auto auth = assertion_auth(2);
            const auto signature = fixture.sign(auth, fixture.client_data);
            auto different_challenge = Hash{};
            different_challenge[0] = 1;
            const auto different_client = hidfido::make_client_data("webauthn.get", different_challenge);
            rejects([&] { hidfido::verify_assertion(fixture.credential, auth, signature, different_client); },
                    "signature verification");
            auto changed_auth = auth;
            set_counter(changed_auth, 3);
            rejects([&] { hidfido::verify_assertion(fixture.credential, changed_auth, signature,
                                                   fixture.client_data); }, "signature verification");
            auto changed_signature = signature;
            changed_signature.back() ^= 1;
            rejects([&] { hidfido::verify_assertion(fixture.credential, auth, changed_signature,
                                                   fixture.client_data); });
            Fixture other;
            rejects([&] { hidfido::verify_assertion(other.credential, auth, signature,
                                                   fixture.client_data); }, "signature verification");
        });

        runner.run("RP mismatch is rejected even with a valid signature", [&] {
            auto auth = assertion_auth(1);
            auth[0] ^= 1;
            const auto signature = fixture.sign(auth, fixture.client_data);
            rejects([&] { hidfido::verify_assertion(fixture.credential, auth, signature,
                                                   fixture.client_data); }, "RP ID hash");
        });

        runner.run("UP UV reserved backup AT and ED assertion policy", [&] {
            const std::pair<std::uint8_t, const char*> cases[]{
                {std::uint8_t{0x04}, "presence"}, {std::uint8_t{0x01}, "verification"},
                {std::uint8_t{0x07}, "reserved"}, {std::uint8_t{0x25}, "reserved"},
                {std::uint8_t{0x0d}, "Backup"}, {std::uint8_t{0x15}, "Backup"}, {std::uint8_t{0x1d}, "Backup"},
                {std::uint8_t{0x45}, "attested"}, {std::uint8_t{0x85}, "extensions"}};
            for (const auto& [flags, message] : cases) {
                const auto auth = assertion_auth(1, flags);
                const auto signature = fixture.sign(auth, fixture.client_data);
                rejects([&] { hidfido::verify_assertion(fixture.credential, auth, signature,
                                                       fixture.client_data); }, message);
            }
        });

        runner.run("Assertion authData and enrolled ID are bounded", [&] {
            auto auth = assertion_auth(1);
            const auto signature = fixture.sign(auth, fixture.client_data);
            for (std::size_t size = 0; size < auth.size(); ++size) {
                rejects([&] { hidfido::verify_assertion(fixture.credential,
                    std::span<const std::uint8_t>(auth).first(size), signature, fixture.client_data); });
            }
            auth.push_back(0);
            rejects([&] { hidfido::verify_assertion(fixture.credential, auth, signature,
                                                   fixture.client_data); }, "trailing");
            auth.resize(4097);
            rejects([&] { hidfido::verify_assertion(fixture.credential, auth, signature,
                                                   fixture.client_data); }, "length");
            auto credential = fixture.credential;
            credential.id.clear();
            rejects([&] { hidfido::verify_assertion(credential, assertion_auth(1), signature,
                                                   fixture.client_data); }, "credential ID");
            credential.id.resize(1024);
            rejects([&] { hidfido::verify_assertion(credential, assertion_auth(1), signature,
                                                   fixture.client_data); }, "credential ID");
        });

        runner.run("Client data ceremony origin and canonical encoding policy", [&] {
            const auto auth = assertion_auth(1);
            const auto signature = fixture.sign(auth, fixture.client_data);
            const auto creation = hidfido::make_client_data("webauthn.create", Hash{});
            rejects([&] { hidfido::verify_assertion(fixture.credential, auth, signature, creation); },
                    "locally constructed");
            auto bad_origin = fixture.client_data;
            bad_origin.replace(bad_origin.find(hidfido::origin), std::strlen(hidfido::origin),
                               "https://attacker.example");
            rejects([&] { hidfido::verify_assertion(fixture.credential, auth, signature, bad_origin); },
                    "locally constructed");
            auto bad_challenge = fixture.client_data;
            const auto offset = bad_challenge.find("challenge\":\"") + std::strlen("challenge\":\"");
            bad_challenge[offset] = '=';
            rejects([&] { hidfido::verify_assertion(fixture.credential, auth, signature, bad_challenge); },
                    "challenge encoding");
            bad_challenge = fixture.client_data;
            bad_challenge[offset + 42] = 'B';
            rejects([&] { hidfido::verify_assertion(fixture.credential, auth, signature, bad_challenge); },
                    "Non-canonical");
            auto trailing = fixture.client_data + " ";
            rejects([&] { hidfido::verify_assertion(fixture.credential, auth, signature, trailing); },
                    "locally constructed");
        });

        runner.run("Counter zero-zero valid and nonzero counters strictly increase", [&] {
            const std::pair<std::uint32_t, std::uint32_t> valid[]{
                {0, 0}, {0, 1}, {5, 6}, {0x12345677, 0x12345678},
                {0xfffffffe, 0xffffffff}};
            for (const auto& [stored, observed] : valid) {
                auto credential = fixture.credential;
                credential.sign_count = stored;
                const auto auth = assertion_auth(observed);
                const auto signature = fixture.sign(auth, fixture.client_data);
                require(hidfido::verify_assertion(credential, auth, signature, fixture.client_data) == observed,
                        "Valid counter rejected");
            }
            const std::pair<std::uint32_t, std::uint32_t> invalid[]{
                {5, 0}, {5, 4}, {5, 5}, {0xffffffff, 0}, {0xffffffff, 0xffffffff}};
            for (const auto& [stored, observed] : invalid) {
                auto credential = fixture.credential;
                credential.sign_count = stored;
                const auto auth = assertion_auth(observed);
                const auto signature = fixture.sign(auth, fixture.client_data);
                rejects([&] { hidfido::verify_assertion(credential, auth, signature,
                                                       fixture.client_data); }, "counter");
            }
        });

        runner.run("Strict DER rejects truncation negative nonminimal and out-of-range scalars", [&] {
            const auto auth = assertion_auth(1);
            const auto good = fixture.sign(auth, fixture.client_data);
            for (std::size_t size = 0; size < good.size(); ++size) {
                rejects([&] { hidfido::verify_assertion(fixture.credential, auth,
                    std::span<const std::uint8_t>(good).first(size), fixture.client_data); }, "DER");
            }
            const Bytes bad_signatures[]{
                {0x30, 0x06, 0x02, 0x01, 0x80, 0x02, 0x01, 0x01}, // negative r
                {0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01}, // needless zero
                {0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01}, // zero r
                {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00}, // zero s
                {0x30, 0x06, 0x02, 0x00, 0x02, 0x02, 0x01, 0x01}, // empty r
                {0x30, 0x80, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01}, // indefinite
                {0x30, 0x81, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01}, // long length
                {0x30, 0x06, 0x03, 0x01, 0x01, 0x02, 0x01, 0x01}}; // wrong tag
            for (const auto& signature : bad_signatures) {
                rejects([&] { hidfido::verify_assertion(fixture.credential, auth, signature,
                                                       fixture.client_data); }, "DER");
            }
            auto trailing = good;
            trailing.push_back(0);
            rejects([&] { hidfido::verify_assertion(fixture.credential, auth, trailing,
                                                   fixture.client_data); }, "DER");
            trailing = {0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x00};
            rejects([&] { hidfido::verify_assertion(fixture.credential, auth, trailing,
                                                   fixture.client_data); }, "Trailing DER");
            const Bytes order{
                0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
                0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51};
            auto raw = Bytes(64);
            std::copy(order.begin(), order.end(), raw.begin());
            raw.back() = 1;
            const auto out_of_range = p1363_der(raw);
            rejects([&] { hidfido::verify_assertion(fixture.credential, auth, out_of_range,
                                                   fixture.client_data); }, "outside P-256 range");
        });

        runner.run("Registration extracts ES256 key ID AAGUID and big-endian counter", [&] {
            const auto auth = fixture.registration(0x12345678);
            const auto parsed = hidfido::parse_registration(auth, fixture.credential.id);
            require(parsed.id == fixture.credential.id, "Credential ID mismatch");
            require(parsed.x == fixture.credential.x && parsed.y == fixture.credential.y,
                    "COSE public key mismatch");
            require(parsed.aaguid == fixture.credential.aaguid, "AAGUID mismatch");
            require(parsed.sign_count == 0x12345678, "Big-endian counter mismatch");
            const auto assertion = assertion_auth(0x12345679);
            const auto signature = fixture.sign(assertion, fixture.client_data);
            require(hidfido::verify_assertion(parsed, assertion, signature, fixture.client_data) == 0x12345679,
                    "Parsed public key could not verify signature");
        });

        runner.run("Registration rejects all truncated prefixes and ID mismatch", [&] {
            const auto auth = fixture.registration();
            for (std::size_t size = 0; size < auth.size(); ++size) {
                rejects([&] { hidfido::parse_registration(
                    std::span<const std::uint8_t>(auth).first(size), fixture.credential.id); });
            }
            auto other_id = fixture.credential.id;
            other_id.back() ^= 1;
            rejects([&] { hidfido::parse_registration(auth, other_id); }, "ID mismatch");
            rejects([&] { hidfido::parse_registration(auth, {}); }, "ID length");
            auto bad = auth;
            bad[53] = 0x04;
            bad[54] = 0x00; // > 1023
            rejects([&] { hidfido::parse_registration(bad, fixture.credential.id); }, "ID length");
            bad[53] = bad[54] = 0;
            rejects([&] { hidfido::parse_registration(bad, fixture.credential.id); }, "ID length");
        });

        runner.run("Registration RP UP UV AT ED backup and reserved flags", [&] {
            auto bad = fixture.registration();
            bad[0] ^= 1;
            rejects([&] { hidfido::parse_registration(bad, fixture.credential.id); }, "RP ID hash");
            const std::pair<std::uint8_t, const char*> cases[]{
                {std::uint8_t{0x44}, "presence"}, {std::uint8_t{0x41}, "verification"}, {std::uint8_t{0x05}, "requires"},
                {std::uint8_t{0xc5}, "extensions"}, {std::uint8_t{0x4d}, "Backup"}, {std::uint8_t{0x55}, "Backup"},
                {std::uint8_t{0x47}, "reserved"}, {std::uint8_t{0x65}, "reserved"}};
            for (const auto& [flags, message] : cases) {
                bad = fixture.registration();
                bad[32] = flags;
                rejects([&] { hidfido::parse_registration(bad, fixture.credential.id); }, message);
            }
        });

        runner.run("COSE algorithm curve type duplicate private unknown and trailing data", [&] {
            const auto offset = 55 + fixture.credential.id.size();
            const std::pair<std::size_t, std::uint8_t> edits[]{
                {std::size_t{1}, std::uint8_t{0x04}}, // unknown label
                {std::size_t{2}, std::uint8_t{0x03}}, // kty RSA
                {std::size_t{3}, std::uint8_t{0x01}}, // duplicate label 1
                {std::size_t{4}, std::uint8_t{0x27}}, // algorithm -8
                {std::size_t{6}, std::uint8_t{0x02}}, // curve P-384
                {std::size_t{7}, std::uint8_t{0x23}}, // private-key field -4
                {std::size_t{9}, std::uint8_t{0x1f}}, // X coordinate 31 bytes
                {std::size_t{0}, std::uint8_t{0xa6}}, // extra map entry
                {std::size_t{0}, std::uint8_t{0xbf}}}; // indefinite map
            for (const auto& [index, value] : edits) {
                auto bad = fixture.registration();
                bad[offset + index] = value;
                rejects([&] { hidfido::parse_registration(bad, fixture.credential.id); });
            }
            auto bad = fixture.registration();
            bad.push_back(0);
            rejects([&] { hidfido::parse_registration(bad, fixture.credential.id); }, "trailing");
            bad = fixture.registration();
            bad[offset + 1] = 0x18;
            bad.insert(bad.begin() + static_cast<std::ptrdiff_t>(offset + 2), 0x01);
            rejects([&] { hidfido::parse_registration(bad, fixture.credential.id); }, "Non-minimal CBOR");
        });

        runner.run("Noncanonical COSE map order and malformed public points fail", [&] {
            auto reordered = fixture.registration();
            const auto offset = 55 + fixture.credential.id.size();
            const auto canonical = fixture.cose();
            // y, alg, x, crv, kty: all five fields, but not CTAP2 canonical order.
            Bytes cose{0xa5};
            cose.insert(cose.end(), canonical.begin() + 42, canonical.end());
            cose.insert(cose.end(), canonical.begin() + 3, canonical.begin() + 5);
            cose.insert(cose.end(), canonical.begin() + 7, canonical.begin() + 42);
            cose.insert(cose.end(), canonical.begin() + 5, canonical.begin() + 7);
            cose.insert(cose.end(), canonical.begin() + 1, canonical.begin() + 3);
            reordered.resize(offset);
            reordered.insert(reordered.end(), cose.begin(), cose.end());
            rejects([&] { hidfido::parse_registration(reordered, fixture.credential.id); },
                    "Non-canonical COSE key map order");
            auto bad = fixture.registration();
            std::fill_n(bad.begin() + static_cast<std::ptrdiff_t>(offset + 10), std::size_t{32}, std::uint8_t{0});
            std::fill_n(bad.begin() + static_cast<std::ptrdiff_t>(offset + 45), std::size_t{32}, std::uint8_t{0});
            rejects([&] { hidfido::parse_registration(bad, fixture.credential.id); }, "BCryptImportKeyPair");
        });

        return runner.finish();
    } catch (const std::exception& error) {
        std::cerr << "Fatal test setup failure: " << error.what() << '\n';
        return 1;
    }
}
