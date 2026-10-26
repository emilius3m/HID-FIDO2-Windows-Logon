#include "hidfido/ctap_client.hpp"
#include "hidfido/pin_protocol.hpp"

#include <windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace {
using hidfido::Bytes;
using hidfido::Hash;
using hidfido::Credential;
namespace pin = hidfido::pin;

void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}
void cng(NTSTATUS status) { require(status >= 0, "test CNG operation failed"); }
template<class Action> void rejects(Action&& action) {
    bool caught{}; try { action(); } catch (const std::exception&) { caught = true; }
    require(caught, "invalid response was accepted");
}
std::span<const std::uint8_t> bytes(std::string_view value) {
    return {reinterpret_cast<const std::uint8_t*>(value.data()), value.size()};
}
void append(Bytes& out, std::span<const std::uint8_t> value) { out.insert(out.end(), value.begin(), value.end()); }
void head(Bytes& out, unsigned major, std::size_t value) {
    if (value < 24) out.push_back(static_cast<std::uint8_t>((major << 5) | value));
    else if (value <= 255) { out.push_back(static_cast<std::uint8_t>((major << 5) | 24)); out.push_back(static_cast<std::uint8_t>(value)); }
    else { out.push_back(static_cast<std::uint8_t>((major << 5) | 25)); out.push_back(static_cast<std::uint8_t>(value >> 8)); out.push_back(static_cast<std::uint8_t>(value)); }
}
void integer(Bytes& out, int value) { head(out, value < 0 ? 1U : 0U, static_cast<std::size_t>(value < 0 ? -1 - value : value)); }
void text(Bytes& out, std::string_view value) { head(out, 3, value.size()); append(out, bytes(value)); }
void blob(Bytes& out, std::span<const std::uint8_t> value) { head(out, 2, value.size()); append(out, value); }
void map(Bytes& out, std::size_t count) { head(out, 5, count); }
void cose(Bytes& out, const Hash& x, const Hash& y, int algorithm) {
    map(out, 5); integer(out, 1); integer(out, 2); integer(out, 3); integer(out, algorithm);
    integer(out, -1); integer(out, 1); integer(out, -2); blob(out, x); integer(out, -3); blob(out, y);
}

struct Node {
    unsigned major{};
    std::size_t value{};
    Bytes data;
    std::vector<Node> children;
    bool is_int(int number) const { return major == (number < 0 ? 1U : 0U) && value == static_cast<std::size_t>(number < 0 ? -1 - number : number); }
    bool is_text(std::string_view label) const { return major == 3 && std::ranges::equal(data, bytes(label)); }
    const Node& at(int key) const {
        require(major == 5, "test expected map");
        for (std::size_t i = 0; i < children.size(); i += 2) if (children[i].is_int(key)) return children[i + 1];
        throw std::runtime_error("test missing integer member");
    }
    const Node& at(std::string_view key) const {
        require(major == 5, "test expected map");
        for (std::size_t i = 0; i < children.size(); i += 2) if (children[i].is_text(key)) return children[i + 1];
        throw std::runtime_error("test missing text member");
    }
};
Node decode(std::span<const std::uint8_t> input, std::size_t& position, unsigned depth = 0) {
    require(depth <= 8 && position < input.size(), "test invalid request CBOR");
    const auto initial = input[position++];
    Node result; result.major = initial >> 5; result.value = initial & 31U;
    if (result.value >= 24) {
        require(result.value <= 26, "test unexpected request length");
        const auto length = std::size_t{1} << (result.value - 24); result.value = 0;
        require(length <= input.size() - position, "test truncated request length");
        for (std::size_t i = 0; i < length; ++i) result.value = (result.value << 8) | input[position++];
    }
    if (result.major == 2 || result.major == 3) {
        require(result.value <= input.size() - position, "test truncated request data");
        result.data.assign(input.begin() + position, input.begin() + position + result.value); position += result.value;
    } else if (result.major == 4 || result.major == 5) {
        const auto count = result.value * (result.major == 5 ? 2 : 1);
        for (std::size_t i = 0; i < count; ++i) result.children.push_back(decode(input, position, depth + 1));
    }
    return result;
}
Node request_map(std::span<const std::uint8_t> request) {
    std::size_t position = 1; auto result = decode(request, position);
    require(position == request.size(), "test trailing request bytes"); return result;
}
Hash hash32(const Node& node) {
    require(node.major == 2 && node.data.size() == 32, "test expected hash32");
    Hash result; std::ranges::copy(node.data, result.begin()); return result;
}
pin::P256PublicKey peer(const Node& node) {
    require(node.children.size() == 10 && node.at(1).is_int(2) && node.at(3).is_int(-25) && node.at(-1).is_int(1), "invalid client agreement COSE");
    return {hash32(node.at(-2)), hash32(node.at(-3))};
}
Bytes integer_der(std::span<const std::uint8_t> scalar) {
    while (scalar.size() > 1 && scalar[0] == 0) scalar = scalar.subspan(1);
    const bool pad = (scalar[0] & 0x80) != 0;
    Bytes out{0x02, static_cast<std::uint8_t>(scalar.size() + (pad ? 1 : 0))};
    if (pad) out.push_back(0); append(out, scalar); return out;
}

enum class Fault { none, no_uv, no_extension, altered_extension, wrong_id, duplicate, trailing,
                   truncated, bad_status, bad_point, short_token, replay, extra_extension, bad_token_length };

class Authenticator final : public hidfido::ctap::Transport {
public:
    explicit Authenticator(std::size_t token_size = 64) : token_(token_size) {
        cng(BCryptOpenAlgorithmProvider(&algorithm_, BCRYPT_ECDSA_P256_ALGORITHM, nullptr, 0));
        cng(BCryptGenerateKeyPair(algorithm_, &signing_, 256, 0)); cng(BCryptFinalizeKeyPair(signing_, 0));
        std::array<std::uint8_t, sizeof(BCRYPT_ECCKEY_BLOB) + 64> exported{}; ULONG size{};
        cng(BCryptExportKey(signing_, nullptr, BCRYPT_ECCPUBLIC_BLOB, exported.data(), static_cast<ULONG>(exported.size()), &size, 0));
        require(size == exported.size(), "test public key length");
        std::copy_n(exported.begin() + sizeof(BCRYPT_ECCKEY_BLOB), 32, credential.x.begin());
        std::copy_n(exported.begin() + sizeof(BCRYPT_ECCKEY_BLOB) + 32, 32, credential.y.begin());
        credential.id = {0x01, 0x82, 0x00, 0xff};
        secret.fill(0x5a); salt.fill(0x6b);
        // Public synthetic fixture, deliberately 64 bytes by default to catch
        // the former assumption that all protocol-1 tokens were 16/32 bytes.
        for (std::size_t i = 0; i < token_.size(); ++i) token_.bytes()[i] = static_cast<std::uint8_t>(i % 256);
    }
    ~Authenticator() override { if (signing_) BCryptDestroyKey(signing_); if (algorithm_) BCryptCloseAlgorithmProvider(algorithm_, 0); }
    Authenticator(const Authenticator&) = delete;
    Authenticator& operator=(const Authenticator&) = delete;

    Bytes transact(std::span<const std::uint8_t> request) override {
        require(!request.empty(), "test empty request"); ++commands;
        if (request[0] == 4) {
            require(request.size() == 1, "GetInfo must have no CBOR");
            Bytes result{0}; map(result, 5);
            integer(result, 1); result.push_back(0x81); text(result, "FIDO_2_0");
            integer(result, 2); result.push_back(0x81); text(result, "hmac-secret");
            integer(result, 3); blob(result, credential.aaguid);
            integer(result, 4); map(result, 1); text(result, "clientPin"); result.push_back(0xf5);
            integer(result, 6); result.insert(result.end(), {0x81, 0x01}); return result;
        }
        const auto node = request_map(request);
        if (request[0] == 6 && node.at(2).is_int(2)) {
            require(node.children.size() == 4 && node.at(1).is_int(1), "getKeyAgreement request fields");
            auto key = agreement_.public_key();
            if (fault == Fault::bad_point) { key.x.fill(0); key.y.fill(0); }
            Bytes result{0}; map(result, 1); integer(result, 1); cose(result, key.x, key.y, -25); return result;
        }
        if (request[0] == 6 && node.at(2).is_int(5)) {
            ++pin_attempts;
            require(node.children.size() == 8 && node.at(1).is_int(1), "getPINToken request fields");
            shared_ = agreement_.shared_secret(peer(node.at(3)));
            auto pin_hash = pin::aes256_cbc_decrypt(shared_.bytes(), node.at(6).data);
            const std::array<std::uint8_t, 16> known_pin_hash{0x03,0xac,0x67,0x42,0x16,0xf3,0xe1,0x5c,0x76,0x1e,0xe1,0xa5,0xe2,0x55,0xf0,0x67};
            require(std::ranges::equal(pin_hash.bytes(), known_pin_hash), "PIN request does not match SHA256(1234)[0:16]");
            if (fault == Fault::bad_status) return {0x31};
            if (fault == Fault::short_token) return {0, 0xa1, 2, 0x41, 0};
            if (fault == Fault::bad_token_length) {
                Bytes result{0}; map(result, 1); integer(result, 2);
                blob(result, Bytes(token_response_size, 0)); return result;
            }
            auto encrypted = pin::aes256_cbc_encrypt(shared_.bytes(), token_.bytes());
            Bytes result{0}; map(result, 1); integer(result, 2); blob(result, encrypted.bytes()); return result;
        }
        if (request[0] == 1) {
            const bool has_exclude = node.children.size() == 16;
            require(node.children.size() == 14 || has_exclude, "makeCredential exact seven members (eight with excludeList); omit options for nonresident default");
            last_user_name = node.at(3).at("name").data;
            excluded_ids_seen = 0;
            if (has_exclude) {
                for (const auto& excluded : node.at(5).children) {
                    require(excluded.at("type").is_text("public-key"), "makeCredential excludeList descriptor");
                    ++excluded_ids_seen;
                    if (excluded.at("id").data == credential.id) return {0x19};
                }
            }
            require(node.at(2).at("id").is_text(hidfido::rp_id), "makeCredential RP");
            require(node.at(3).at("id").data.size() == 32, "makeCredential user ID");
            require(node.at(4).children.size() == 1 && node.at(4).children[0].at("alg").is_int(-7) && node.at(4).children[0].at("type").is_text("public-key"), "makeCredential ES256");
            require(node.at(6).at("hmac-secret").major == 7 && node.at(6).at("hmac-secret").value == 21, "makeCredential hmac-secret true");
            check_pin_auth(node.at(1), node.at(8), node.at(9));
            auto auth = auth_data(0xc5);
            append(auth, credential.aaguid); auth.push_back(0); auth.push_back(static_cast<std::uint8_t>(credential.id.size())); append(auth, credential.id);
            cose(auth, credential.x, credential.y, -7); map(auth, 1); text(auth, "hmac-secret"); auth.push_back(0xf5);
            Bytes result{0}; map(result, 3); integer(result, 1); text(result, "none"); integer(result, 2); blob(result, auth); integer(result, 3); map(result, 0); return result;
        }
        require(request[0] == 2, "unexpected CTAP command");
        require(node.children.size() == 14, "getAssertion request fields");
        require(node.at(1).is_text(hidfido::rp_id), "getAssertion RP");
        require(node.at(3).children.size() == 1 && node.at(3).children[0].at("type").is_text("public-key") && node.at(3).children[0].at("id").data == credential.id, "getAssertion single allow-list");
        require(node.at(5).children.size() == 2 && node.at(5).at("up").major == 7 && node.at(5).at("up").value == 21, "getAssertion UP only; uv must be omitted with PIN authentication");
        check_pin_auth(node.at(2), node.at(6), node.at(7));
        const auto& extension = node.at(4).at("hmac-secret");
        require(extension.children.size() == 6, "PIN1 hmac input exact members");
        auto extension_shared = agreement_.shared_secret(peer(extension.at(1)));
        auto expected_auth = pin::hmac_sha256(extension_shared.bytes(), extension.at(2).data);
        require(std::ranges::equal(extension.at(3).data, expected_auth.bytes().first(16)), "saltAuth mismatch");
        auto decrypted_salt = pin::aes256_cbc_decrypt(extension_shared.bytes(), extension.at(2).data);
        require(std::ranges::equal(decrypted_salt.bytes(), salt), "saltEnc mismatch");
        if (fault == Fault::replay && !cached_response_.empty()) return cached_response_;
        auto encrypted = pin::aes256_cbc_encrypt(extension_shared.bytes(), secret);
        auto auth = auth_data(fault == Fault::no_uv ? 0x81 : fault == Fault::no_extension ? 0x05 : 0x85);
        if (fault != Fault::no_extension) {
            map(auth, fault == Fault::extra_extension ? 2 : 1); text(auth, "hmac-secret"); blob(auth, encrypted.bytes());
            if (fault == Fault::extra_extension) { text(auth, "unexpected"); auth.push_back(0xf5); }
        }
        const auto signature = sign(auth, hash32(node.at(2)));
        if (fault == Fault::altered_extension) auth.back() ^= 1;
        Bytes result{0}; map(result, fault == Fault::duplicate ? 4 : 3);
        integer(result, 1); map(result, 2); text(result, "id"); auto id = credential.id;
        if (fault == Fault::wrong_id) id[0] ^= 1;
        blob(result, id); text(result, "type"); text(result, "public-key");
        integer(result, 2); blob(result, auth); integer(result, 3); blob(result, signature);
        if (fault == Fault::duplicate) { integer(result, 3); blob(result, signature); }
        if (fault == Fault::trailing) result.push_back(0);
        if (fault == Fault::truncated) result.pop_back();
        cached_response_ = result; return result;
    }
    Credential credential;
    Hash secret{}, salt{};
    Fault fault{};
    std::size_t token_response_size{};
    unsigned commands{}, pin_attempts{}, excluded_ids_seen{};
    Bytes last_user_name;
private:
    void check_pin_auth(const Node& hash, const Node& auth, const Node& protocol) {
        require(protocol.is_int(1), "PIN protocol must be 1");
        const auto digest = hash32(hash);
        auto expected = pin::hmac_sha256(token_.bytes(), digest);
        require(std::ranges::equal(auth.data, expected.bytes().first(16)), "pinUvAuthParam mismatch");
    }
    Bytes auth_data(std::uint8_t flags) {
        Bytes auth(37); const auto rp_hash = hidfido::sha256(bytes(hidfido::rp_id));
        std::copy(rp_hash.begin(), rp_hash.end(), auth.begin()); auth[32] = flags; auth[36] = static_cast<std::uint8_t>(++counter_); return auth;
    }
    Bytes sign(std::span<const std::uint8_t> auth, const Hash& client_hash) {
        Bytes joined(auth.begin(), auth.end()); append(joined, client_hash); const auto digest = hidfido::sha256(joined);
        std::array<std::uint8_t, 64> signature{}; ULONG size{};
        cng(BCryptSignHash(signing_, nullptr, const_cast<PUCHAR>(digest.data()), static_cast<ULONG>(digest.size()), signature.data(), static_cast<ULONG>(signature.size()), &size, 0));
        require(size == 64, "test signature size");
        const auto r = integer_der(std::span(signature).first(32)); const auto s = integer_der(std::span(signature).subspan(32));
        Bytes result{0x30, static_cast<std::uint8_t>(r.size() + s.size())}; append(result, r); append(result, s); return result;
    }
    pin::KeyAgreement agreement_;
    hidfido::password::SecureBytes shared_;
    hidfido::password::SecureBytes token_;
    unsigned counter_{};
    Bytes cached_response_;
    BCRYPT_ALG_HANDLE algorithm_{};
    BCRYPT_KEY_HANDLE signing_{};
};
}

int main() {
    try {
        constexpr std::string_view pin_value = "1234";
        {
            Authenticator authenticator;
            hidfido::ctap::HmacClient client(authenticator);
            Hash user{}; user.fill(0x42);
            auto credential = client.make_credential(bytes(pin_value), user);
            require(credential.id == authenticator.credential.id && credential.user_handle == user, "enrollment credential mismatch");
            auto first = client.get_secret(bytes(pin_value), credential, authenticator.salt);
            require(std::ranges::equal(first.bytes(), authenticator.secret), "first hmac-secret output mismatch");
            auto second = client.get_secret(bytes(pin_value), credential, authenticator.salt);
            require(std::ranges::equal(first.bytes(), second.bytes()), "hmac-secret not reproducible with new ephemeral agreement/challenge");
            require(credential.sign_count == 3, "verified counter not updated");
            require(authenticator.pin_attempts == 3, "unexpected PIN retries");
            authenticator.fault = Fault::replay;
            rejects([&] { client.get_secret(bytes(pin_value), credential, authenticator.salt); });
        }
        for (const auto fault : {Fault::no_uv, Fault::no_extension, Fault::altered_extension, Fault::wrong_id, Fault::duplicate, Fault::trailing, Fault::truncated, Fault::bad_status, Fault::bad_point, Fault::short_token, Fault::extra_extension}) {
            Authenticator authenticator; authenticator.fault = fault;
            hidfido::ctap::HmacClient client(authenticator);
            auto credential = authenticator.credential;
            rejects([&] { client.get_secret(bytes(pin_value), credential, authenticator.salt); });
            require(credential.sign_count == 0, "failed ceremony changed persisted counter");
            require(authenticator.pin_attempts <= 1, "failed ceremony retried PIN");
        }
        {
            Authenticator authenticator; authenticator.fault = Fault::bad_status;
            hidfido::ctap::HmacClient client(authenticator);
            bool correct{};
            try { client.get_secret(bytes(pin_value), authenticator.credential, authenticator.salt); }
            catch (const hidfido::ctap::StatusError& error) { correct = error.status() == 0x31 && std::string_view(error.what()) == "CTAP status 49"; }
            require(correct && authenticator.pin_attempts == 1, "numeric PIN error/no-retry contract");
        }
        {
            Authenticator authenticator; hidfido::ctap::HmacClient client(authenticator);
            rejects([&] { client.get_secret(bytes("123"), authenticator.credential, authenticator.salt); });
            require(authenticator.pin_attempts == 0, "invalid PIN reached authenticator");
        }
        {
            Authenticator authenticator; hidfido::ctap::HmacClient client(authenticator);
            Hash user{}; user.fill(0x42);
            const std::vector<Bytes> other_key{Bytes{0x09, 0x09}};
            auto credential = client.make_credential(bytes(pin_value), user, "utente", "Accesso Windows utente", other_key);
            require(credential.id == authenticator.credential.id && authenticator.excluded_ids_seen == 1 &&
                    std::ranges::equal(authenticator.last_user_name, bytes("utente")), "excludeList or user name not sent");
            const std::vector<Bytes> same_key{authenticator.credential.id};
            bool excluded{};
            try { client.make_credential(bytes(pin_value), user, "utente", "Accesso Windows utente", same_key); }
            catch (const hidfido::ctap::StatusError& error) { excluded = error.status() == 0x19; }
            require(excluded, "Key holding an excluded credential was enrolled again");
            const auto attempts = authenticator.pin_attempts;
            rejects([&] { client.make_credential(bytes(pin_value), user, "", "Accesso"); });
            rejects([&] { client.make_credential(bytes(pin_value), user, "utente", "Accesso", std::vector<Bytes>(9, Bytes{1})); });
            require(authenticator.pin_attempts == attempts, "Invalid enrollment parameters reached the authenticator");
        }
        for (const std::size_t length : {std::size_t{16}, std::size_t{32}, std::size_t{48},
                                        std::size_t{64}, std::size_t{80}, std::size_t{512}}) {
            Authenticator authenticator(length);
            hidfido::ctap::HmacClient client(authenticator);
            Hash user{}; user.fill(0x42);
            auto credential = client.make_credential(bytes(pin_value), user);
            auto secret = client.get_secret(bytes(pin_value), credential, authenticator.salt);
            require(std::ranges::equal(secret.bytes(), authenticator.secret), "Variable-length PIN token ceremony failed");
            require(authenticator.pin_attempts == 2 && credential.sign_count == 2,
                    "Variable-length token ceremony retried or lost its counter");
        }
        for (const std::size_t length : {std::size_t{0}, std::size_t{1}, std::size_t{15}, std::size_t{17},
                                        std::size_t{31}, std::size_t{33}, std::size_t{63}, std::size_t{65},
                                        std::size_t{511}, std::size_t{513}, std::size_t{528}}) {
            Authenticator authenticator;
            authenticator.fault = Fault::bad_token_length;
            authenticator.token_response_size = length;
            hidfido::ctap::HmacClient client(authenticator);
            bool correct{};
            try { client.get_secret(bytes(pin_value), authenticator.credential, authenticator.salt); }
            catch (const std::runtime_error& error) {
                correct = error.what() == std::string("CTAP client: invalid encrypted PIN token length ") + std::to_string(length);
            }
            require(correct, "Malformed token error must disclose only its numeric length");
            require(authenticator.commands == 3 && authenticator.pin_attempts == 1 && authenticator.credential.sign_count == 0,
                    "Malformed token reached assertion, retried PIN or changed the counter");
        }
        std::cout << "CTAP hmac-secret client: enrollment, fresh signed UV assertions, PIN1 maps, secrets, malformed responses and no-retry tests passed.\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "CTAP client test failed: " << error.what() << '\n'; return 1;
    }
}
