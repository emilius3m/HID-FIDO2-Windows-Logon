#include "hidfido/core_hmac.hpp"

#include <windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <iostream>
#include <stdexcept>
#include <string>
#include <utility>

namespace {
using hidfido::Bytes;
using hidfido::Credential;
using hidfido::Hash;

void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}
void check(NTSTATUS status) {
    require(status >= 0, "CNG fixture operation failed");
}
template<typename Action>
void rejects(Action&& action, std::string_view expected = {}) {
    try {
        action();
    } catch (const std::exception& error) {
        if (!expected.empty() && std::string_view(error.what()).find(expected) == std::string_view::npos) {
            throw std::runtime_error(std::string("Wrong rejection: ") + error.what());
        }
        return;
    }
    throw std::runtime_error("Malformed hmac-secret input accepted");
}
std::span<const std::uint8_t> bytes(std::string_view value) {
    return {reinterpret_cast<const std::uint8_t*>(value.data()), value.size()};
}
void append(Bytes& destination, std::span<const std::uint8_t> value) {
    destination.insert(destination.end(), value.begin(), value.end());
}
Bytes extension_prefix() {
    Bytes result{0xa1, 0x6b};
    append(result, bytes("hmac-secret"));
    return result;
}
Bytes registration_extension() {
    auto result = extension_prefix();
    result.push_back(0xf5);
    return result;
}
Bytes assertion_extension(std::uint8_t fill = 0x6b) {
    auto result = extension_prefix();
    result.insert(result.end(), {0x58, 0x20});
    result.insert(result.end(), 32, fill);
    return result;
}
Bytes auth_header(std::uint32_t count, std::uint8_t flags) {
    Bytes result(37);
    const auto rp = hidfido::sha256(bytes(hidfido::rp_id));
    std::copy(rp.begin(), rp.end(), result.begin());
    result[32] = flags;
    result[33] = static_cast<std::uint8_t>(count >> 24);
    result[34] = static_cast<std::uint8_t>(count >> 16);
    result[35] = static_cast<std::uint8_t>(count >> 8);
    result[36] = static_cast<std::uint8_t>(count);
    return result;
}
Bytes assertion(std::uint32_t count = 6, std::uint8_t flags = 0x85,
                const Bytes& extension = assertion_extension()) {
    auto result = auth_header(count, flags);
    append(result, extension);
    return result;
}
Bytes integer_der(std::span<const std::uint8_t> scalar) {
    while (scalar.size() > 1 && scalar[0] == 0) scalar = scalar.subspan(1);
    const bool pad = (scalar[0] & 0x80) != 0;
    Bytes result{0x02, static_cast<std::uint8_t>(scalar.size() + (pad ? 1 : 0))};
    if (pad) result.push_back(0);
    append(result, scalar);
    return result;
}

class Fixture {
public:
    Fixture() {
        try {
            check(BCryptOpenAlgorithmProvider(&algorithm_, BCRYPT_ECDSA_P256_ALGORITHM,
                                               MS_PRIMITIVE_PROVIDER, 0));
            check(BCryptGenerateKeyPair(algorithm_, &key_, 256, 0));
            check(BCryptFinalizeKeyPair(key_, 0));
            std::array<std::uint8_t, sizeof(BCRYPT_ECCKEY_BLOB) + 64> exported{};
            ULONG size{};
            check(BCryptExportKey(key_, nullptr, BCRYPT_ECCPUBLIC_BLOB, exported.data(),
                                   static_cast<ULONG>(exported.size()), &size, 0));
            require(size == exported.size(), "Wrong CNG public key length");
            std::copy_n(exported.begin() + sizeof(BCRYPT_ECCKEY_BLOB), 32, credential.x.begin());
            std::copy_n(exported.begin() + sizeof(BCRYPT_ECCKEY_BLOB) + 32, 32, credential.y.begin());
            credential.id = {0x01, 0x00, 0xff, 0x42};
            credential.sign_count = 5;
            credential.aaguid.fill(0x31);
            client = hidfido::make_client_data("webauthn.get", Hash{});
        } catch (...) {
            cleanup();
            throw;
        }
    }
    ~Fixture() { cleanup(); }
    Fixture(const Fixture&) = delete;
    Fixture& operator=(const Fixture&) = delete;

    Bytes sign(const Bytes& auth, std::string_view json) const {
        auto message = auth;
        append(message, hidfido::sha256(bytes(json)));
        const auto digest = hidfido::sha256(message);
        std::array<std::uint8_t, 64> raw{};
        ULONG written{};
        check(BCryptSignHash(key_, nullptr, const_cast<PUCHAR>(digest.data()),
                             static_cast<ULONG>(digest.size()), raw.data(),
                             static_cast<ULONG>(raw.size()), &written, 0));
        require(written == raw.size(), "Wrong CNG signature length");
        const auto r = integer_der(std::span<const std::uint8_t>(raw).first(32));
        const auto s = integer_der(std::span<const std::uint8_t>(raw).subspan(32));
        Bytes result{0x30, static_cast<std::uint8_t>(r.size() + s.size())};
        append(result, r);
        append(result, s);
        return result;
    }
    Bytes cose() const {
        Bytes result{0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20};
        append(result, credential.x);
        result.insert(result.end(), {0x22, 0x58, 0x20});
        append(result, credential.y);
        return result;
    }
    Bytes registration(const Bytes& extension = registration_extension()) const {
        auto result = auth_header(credential.sign_count, 0xc5);
        append(result, credential.aaguid);
        result.push_back(0);
        result.push_back(static_cast<std::uint8_t>(credential.id.size()));
        append(result, credential.id);
        append(result, cose());
        append(result, extension);
        return result;
    }
    hidfido::VerifiedHmacAssertion verify(const Bytes& auth) const {
        return hidfido::verify_hmac_assertion(credential, auth, sign(auth, client), client);
    }
    Credential credential;
    std::string client;
private:
    void cleanup() noexcept {
        if (key_) BCryptDestroyKey(key_);
        if (algorithm_) BCryptCloseAlgorithmProvider(algorithm_, 0);
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
        std::cout << total_ - failures_ << '/' << total_ << " hmac verifier tests passed\n";
        return failures_ == 0 ? 0 : 1;
    }
private:
    unsigned total_{};
    unsigned failures_{};
};
}

int main() {
    try {
        Fixture fixture;
        Runner runner;
        runner.run("Registration parses ES256 key, AT ID and exact hmac-secret:true", [&] {
            const auto parsed = hidfido::parse_hmac_registration(fixture.registration());
            require(parsed.id == fixture.credential.id, "Attested ID mismatch");
            require(parsed.x == fixture.credential.x && parsed.y == fixture.credential.y,
                    "ES256 public key mismatch");
            require(parsed.aaguid == fixture.credential.aaguid, "AAGUID mismatch");
            require(parsed.sign_count == 5, "Registration counter mismatch");
            const auto auth = assertion();
            const auto verified = hidfido::verify_hmac_assertion(
                parsed, auth, fixture.sign(auth, fixture.client), fixture.client);
            require(verified.sign_count == 6, "Verified counter mismatch");
            require(std::all_of(verified.ciphertext.begin(), verified.ciphertext.end(),
                               [](auto value) { return value == 0x6b; }), "Ciphertext mismatch");
        });
        runner.run("Existing extension-free APIs keep rejecting ED", [&] {
            const auto registration = fixture.registration();
            rejects([&] { hidfido::parse_registration(registration, fixture.credential.id); }, "extensions");
            const auto auth = assertion();
            const auto signature = fixture.sign(auth, fixture.client);
            rejects([&] { hidfido::verify_assertion(fixture.credential, auth, signature, fixture.client); },
                    "extensions");
        });
        runner.run("ES256 covers ED bytes, extension ciphertext and exact challenge", [&] {
            auto auth = assertion();
            const auto signature = fixture.sign(auth, fixture.client);
            auth.back() ^= 1;
            rejects([&] { hidfido::verify_hmac_assertion(fixture.credential, auth, signature, fixture.client); },
                    "signature verification");
            auth = assertion();
            auto stripped = auth_header(6, 0x05);
            const auto stripped_signature = fixture.sign(stripped, fixture.client);
            rejects([&] { hidfido::verify_hmac_assertion(fixture.credential, auth, stripped_signature,
                                                         fixture.client); }, "signature verification");
            auto challenge = Hash{};
            challenge[0] = 0x51;
            const auto changed_client = hidfido::make_client_data("webauthn.get", challenge);
            rejects([&] { hidfido::verify_hmac_assertion(fixture.credential, auth, signature, changed_client); },
                    "signature verification");
            Fixture other;
            rejects([&] { hidfido::verify_hmac_assertion(other.credential, auth, signature, fixture.client); },
                    "signature verification");
        });
        runner.run("Signed assertions enforce RP, UP, UV, backup, reserved and AT flags", [&] {
            auto bad = assertion();
            bad[0] ^= 1;
            rejects([&] { fixture.verify(bad); }, "RP ID hash");
            const std::pair<std::uint8_t, const char*> cases[]{
                {std::uint8_t{0x84}, "presence"}, {std::uint8_t{0x81}, "verification"},
                {std::uint8_t{0x87}, "reserved"}, {std::uint8_t{0xa5}, "reserved"},
                {std::uint8_t{0x8d}, "Backup"}, {std::uint8_t{0x95}, "Backup"},
                {std::uint8_t{0x9d}, "Backup"}, {std::uint8_t{0xc5}, "attested"},
                {std::uint8_t{0x05}, "required"}};
            for (const auto& [flags, expected] : cases) {
                rejects([&] { fixture.verify(assertion(6, flags)); }, expected);
            }
        });
        runner.run("Counter handling matches core, including zero counters and rollback", [&] {
            const std::pair<std::uint32_t, std::uint32_t> valid[]{
                {0, 0}, {0, 1}, {5, 6}, {0x12345677, 0x12345678}, {0xfffffffe, 0xffffffff}};
            for (const auto& [stored, count] : valid) {
                auto credential = fixture.credential;
                credential.sign_count = stored;
                const auto auth = assertion(count);
                const auto verified = hidfido::verify_hmac_assertion(
                    credential, auth, fixture.sign(auth, fixture.client), fixture.client);
                require(verified.sign_count == count, "Valid counter rejected");
            }
            const std::pair<std::uint32_t, std::uint32_t> invalid[]{
                {5, 0}, {5, 4}, {5, 5}, {0xffffffff, 0}, {0xffffffff, 0xffffffff}};
            for (const auto& [stored, count] : invalid) {
                auto credential = fixture.credential;
                credential.sign_count = stored;
                const auto auth = assertion(count);
                rejects([&] { hidfido::verify_hmac_assertion(credential, auth,
                    fixture.sign(auth, fixture.client), fixture.client); }, "counter");
            }
        });
        runner.run("Signed assertion extension CBOR is exact, bounded and unambiguous", [&] {
            std::vector<Bytes> bad;
            auto extension = assertion_extension();
            extension[0] = 0xa2; // claims a second entry
            bad.push_back(extension);
            auto duplicate = assertion_extension();
            extension = assertion_extension(); extension[0] = 0xa2;
            append(extension, std::span<const std::uint8_t>(duplicate).subspan(1));
            bad.push_back(extension); // two complete entries with the same name
            extension = assertion_extension(); extension[0] = 0xa2;
            extension.insert(extension.end(), {0x61, 'x', 0xf5});
            bad.push_back(extension); // one complete unknown extension
            extension = assertion_extension(); extension[0] = 0xbf; bad.push_back(extension);
            extension = assertion_extension(); extension[0] = 0xa0; bad.push_back(extension);
            extension = assertion_extension(); extension[12] = 'x'; bad.push_back(extension);
            extension = assertion_extension(); extension.push_back(0); bad.push_back(extension);
            extension = assertion_extension(); extension[14] = 0x1f; bad.push_back(extension);
            extension = assertion_extension(); extension[14] = 0x40;
            extension.insert(extension.end(), 32, 0x6b); bad.push_back(extension); // two salts
            extension = assertion_extension(); extension[13] = 0x5f; bad.push_back(extension);
            extension = assertion_extension(); extension[1] = 0x78;
            extension.insert(extension.begin() + 2, 0x0b); bad.push_back(extension); // nonminimal text
            extension = assertion_extension(); extension[13] = 0x59;
            extension.insert(extension.begin() + 14, 0); bad.push_back(extension); // nonminimal bytes
            extension = registration_extension(); bad.push_back(extension);
            bad.push_back({0xa0});
            for (const auto& malformed : bad) {
                rejects([&] { fixture.verify(assertion(6, 0x85, malformed)); });
            }
        });
        runner.run("Every truncated assertion and oversized data are rejected", [&] {
            const auto good = assertion();
            for (std::size_t length = 0; length < good.size(); ++length) {
                const Bytes truncated(good.begin(), good.begin() + length);
                rejects([&] { fixture.verify(truncated); });
            }
            auto bad = good;
            bad.resize(4097);
            rejects([&] { fixture.verify(bad); }, "length");
        });
        runner.run("Registration requires UP UV AT ED and forbids backup/reserved flags", [&] {
            const std::pair<std::uint8_t, const char*> cases[]{
                {std::uint8_t{0xc4}, "presence"}, {std::uint8_t{0xc1}, "verification"},
                {std::uint8_t{0xc7}, "reserved"}, {std::uint8_t{0xe5}, "reserved"},
                {std::uint8_t{0xcd}, "Backup"}, {std::uint8_t{0xd5}, "Backup"},
                {std::uint8_t{0x85}, "requires"}, {std::uint8_t{0x45}, "required"}};
            for (const auto& [flags, expected] : cases) {
                auto bad = fixture.registration();
                bad[32] = flags;
                rejects([&] { hidfido::parse_hmac_registration(bad); }, expected);
            }
            auto bad = fixture.registration(); bad[0] ^= 1;
            rejects([&] { hidfido::parse_hmac_registration(bad); }, "RP ID hash");
        });
        runner.run("Registration rejects false, absent, unknown and trailing extension data", [&] {
            std::vector<Bytes> bad;
            auto extension = registration_extension(); extension.back() = 0xf4; bad.push_back(extension);
            extension = registration_extension(); extension.push_back(0); bad.push_back(extension);
            extension = registration_extension(); extension[12] = 'x'; bad.push_back(extension);
            extension = registration_extension(); extension[0] = 0xa2; bad.push_back(extension);
            auto duplicate = registration_extension();
            extension = registration_extension(); extension[0] = 0xa2;
            append(extension, std::span<const std::uint8_t>(duplicate).subspan(1));
            bad.push_back(extension);
            extension = registration_extension(); extension[0] = 0xa2;
            extension.insert(extension.end(), {0x61, 'x', 0xf5}); bad.push_back(extension);
            extension = registration_extension(); extension[0] = 0xbf; bad.push_back(extension);
            extension = registration_extension(); extension[1] = 0x78;
            extension.insert(extension.begin() + 2, 0x0b); bad.push_back(extension);
            bad.push_back(assertion_extension());
            bad.push_back({0xa0});
            bad.push_back({});
            for (const auto& malformed : bad) {
                rejects([&] { hidfido::parse_hmac_registration(fixture.registration(malformed)); });
            }
        });
        runner.run("Registration retains strict COSE public key policy and CNG point validation", [&] {
            const auto offset = 55 + fixture.credential.id.size();
            const std::pair<std::size_t, std::uint8_t> edits[]{
                {std::size_t{0}, std::uint8_t{0xa6}}, {std::size_t{0}, std::uint8_t{0xbf}},
                {std::size_t{1}, std::uint8_t{0x04}}, {std::size_t{2}, std::uint8_t{0x03}},
                {std::size_t{3}, std::uint8_t{0x01}}, {std::size_t{4}, std::uint8_t{0x27}},
                {std::size_t{6}, std::uint8_t{0x02}}, {std::size_t{7}, std::uint8_t{0x23}},
                {std::size_t{9}, std::uint8_t{0x1f}}};
            for (const auto& [index, value] : edits) {
                auto bad = fixture.registration(); bad[offset + index] = value;
                rejects([&] { hidfido::parse_hmac_registration(bad); });
            }
            auto bad = fixture.registration();
            std::fill_n(bad.begin() + offset + 10, 32, std::uint8_t{0});
            std::fill_n(bad.begin() + offset + 45, 32, std::uint8_t{0});
            rejects([&] { hidfido::parse_hmac_registration(bad); }, "BCryptImportKeyPair");
            bad = fixture.registration(); bad[53] = 4; bad[54] = 0;
            rejects([&] { hidfido::parse_hmac_registration(bad); }, "ID length");
            bad = fixture.registration(); bad[53] = bad[54] = 0;
            rejects([&] { hidfido::parse_hmac_registration(bad); }, "ID length");
        });
        runner.run("Every truncated registration and oversize input is rejected", [&] {
            const auto good = fixture.registration();
            for (std::size_t length = 0; length < good.size(); ++length) {
                rejects([&] { hidfido::parse_hmac_registration(
                    std::span<const std::uint8_t>(good).first(length)); });
            }
            auto bad = good; bad.resize(4097);
            rejects([&] { hidfido::parse_hmac_registration(bad); }, "length");
        });
        runner.run("DER, enrolled ID and local client-data policy remain strict", [&] {
            const auto auth = assertion();
            const auto signature = fixture.sign(auth, fixture.client);
            for (std::size_t length = 0; length < signature.size(); ++length) {
                rejects([&] { hidfido::verify_hmac_assertion(fixture.credential, auth,
                    std::span<const std::uint8_t>(signature).first(length), fixture.client); }, "DER");
            }
            auto credential = fixture.credential; credential.id.clear();
            rejects([&] { hidfido::verify_hmac_assertion(credential, auth, signature, fixture.client); }, "ID length");
            credential.id.resize(1024);
            rejects([&] { hidfido::verify_hmac_assertion(credential, auth, signature, fixture.client); }, "ID length");
            const auto creation = hidfido::make_client_data("webauthn.create", Hash{});
            rejects([&] { hidfido::verify_hmac_assertion(fixture.credential, auth, signature, creation); },
                    "locally constructed");
            const auto trailing_json = fixture.client + " ";
            rejects([&] { hidfido::verify_hmac_assertion(fixture.credential, auth, signature, trailing_json); },
                    "locally constructed");
        });
        return runner.finish();
    } catch (const std::exception& error) {
        std::cerr << "Fatal hmac verifier fixture failure: " << error.what() << '\n';
        return 1;
    }
}
