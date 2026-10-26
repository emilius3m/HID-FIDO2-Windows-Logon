#include "../src/ctap/hmac_diagnostic.hpp"
#include "hidfido/pin_protocol.hpp"

#include <windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {
using hidfido::Bytes;
using hidfido::Hash;
namespace pin = hidfido::pin;
namespace diagnostic = hidfido::ctap::diagnostic;
void require(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
void cng(NTSTATUS value) { require(value >= 0, "test CNG failure"); }
std::span<const std::uint8_t> bytes(std::string_view value) { return {reinterpret_cast<const std::uint8_t*>(value.data()), value.size()}; }
void append(Bytes& out, std::span<const std::uint8_t> value) { out.insert(out.end(), value.begin(), value.end()); }
void head(Bytes& out, unsigned major, std::size_t value) {
    if (value < 24) out.push_back(static_cast<std::uint8_t>((major << 5) | value));
    else if (value < 256) { out.push_back(static_cast<std::uint8_t>((major << 5) | 24)); out.push_back(static_cast<std::uint8_t>(value)); }
    else { out.push_back(static_cast<std::uint8_t>((major << 5) | 25)); out.push_back(static_cast<std::uint8_t>(value >> 8)); out.push_back(static_cast<std::uint8_t>(value)); }
}
void integer(Bytes& out, int value) { head(out, value < 0 ? 1 : 0, static_cast<std::size_t>(value < 0 ? -1 - value : value)); }
void text(Bytes& out, std::string_view value) { head(out, 3, value.size()); append(out, bytes(value)); }
void blob(Bytes& out, std::span<const std::uint8_t> value) { head(out, 2, value.size()); append(out, value); }
void map(Bytes& out, std::size_t count) { head(out, 5, count); }
void cose(Bytes& out, const pin::P256PublicKey& key) {
    map(out, 5); integer(out, 1); integer(out, 2); integer(out, 3); integer(out, -25);
    integer(out, -1); integer(out, 1); integer(out, -2); blob(out, key.x); integer(out, -3); blob(out, key.y);
}
struct Node {
    unsigned major{}; std::size_t value{}; Bytes data; std::vector<Node> children;
    bool is_int(int i) const { return major == (i < 0 ? 1U : 0U) && value == static_cast<std::size_t>(i < 0 ? -1 - i : i); }
    bool is_text(std::string_view name) const { return major == 3 && std::ranges::equal(data, bytes(name)); }
    const Node& at(int key) const {
        require(major == 5, "request expected map");
        for (std::size_t i = 0; i < children.size(); i += 2) if (children[i].is_int(key)) return children[i + 1];
        throw std::runtime_error("missing integer request key");
    }
    const Node& at(std::string_view key) const {
        require(major == 5, "request expected map");
        for (std::size_t i = 0; i < children.size(); i += 2) if (children[i].is_text(key)) return children[i + 1];
        throw std::runtime_error("missing text request key");
    }
};
Node decode(std::span<const std::uint8_t> input, std::size_t& position, unsigned depth = 0) {
    require(depth <= 8 && position < input.size(), "bad request CBOR");
    const auto first = input[position++]; Node node; node.major = first >> 5; node.value = first & 31U;
    if (node.value >= 24) {
        require(node.value <= 26, "unexpected request CBOR length");
        const auto count = std::size_t{1} << (node.value - 24); node.value = 0;
        require(count <= input.size() - position, "truncated request CBOR length");
        for (std::size_t i = 0; i < count; ++i) node.value = (node.value << 8) | input[position++];
    }
    if (node.major == 2 || node.major == 3) {
        require(node.value <= input.size() - position, "truncated request CBOR bytes");
        node.data.assign(input.begin() + position, input.begin() + position + node.value); position += node.value;
    } else if (node.major == 4 || node.major == 5) {
        const auto count = node.value * (node.major == 5 ? 2 : 1);
        for (std::size_t i = 0; i < count; ++i) node.children.push_back(decode(input, position, depth + 1));
    }
    return node;
}
Hash hash32(const Node& node) {
    require(node.major == 2 && node.data.size() == 32, "expected request byte32");
    Hash result; std::ranges::copy(node.data, result.begin()); return result;
}
Bytes der_integer(std::span<const std::uint8_t> value) {
    while (value.size() > 1 && value[0] == 0) value = value.subspan(1);
    const bool pad = (value[0] & 128) != 0;
    Bytes out{2, static_cast<std::uint8_t>(value.size() + (pad ? 1 : 0))};
    if (pad) out.push_back(0); append(out, value); return out;
}
enum class Fault { none, same, denied, malformed_signature, bad_signature, wrong_challenge,
                   uv, no_up, no_ed, wrong_rp, rollback, no_extension, duplicate,
                   truncated, denied_with_data, unrelated_status, agreement_denied,
                   bad_point, wrong_id, multiple_credentials };
class Authenticator final : public hidfido::ctap::Transport {
public:
    explicit Authenticator(Fault fault = Fault::none) : fault_(fault) {
        cng(BCryptOpenAlgorithmProvider(&algorithm_, BCRYPT_ECDSA_P256_ALGORITHM, nullptr, 0));
        cng(BCryptGenerateKeyPair(algorithm_, &key_, 256, 0)); cng(BCryptFinalizeKeyPair(key_, 0));
        std::array<std::uint8_t, sizeof(BCRYPT_ECCKEY_BLOB) + 64> data{}; ULONG count{};
        cng(BCryptExportKey(key_, nullptr, BCRYPT_ECCPUBLIC_BLOB, data.data(), static_cast<ULONG>(data.size()), &count, 0));
        require(count == data.size(), "test public key size");
        std::copy_n(data.begin() + sizeof(BCRYPT_ECCKEY_BLOB), 32, credential.x.begin());
        std::copy_n(data.begin() + sizeof(BCRYPT_ECCKEY_BLOB) + 32, 32, credential.y.begin());
        credential.id = {1, 0, 0xff, 0x82}; credential.sign_count = 10;
        expected.fill(0x55); salt.fill(0x77);
    }
    ~Authenticator() override { if (key_) BCryptDestroyKey(key_); if (algorithm_) BCryptCloseAlgorithmProvider(algorithm_, 0); }
    Authenticator(const Authenticator&) = delete; Authenticator& operator=(const Authenticator&) = delete;
    Bytes transact(std::span<const std::uint8_t> request) override {
        ++commands; require(!request.empty(), "empty diagnostic request");
        std::size_t position = 1; const auto node = decode(request, position);
        require(position == request.size(), "diagnostic request trailing bytes");
        if (request[0] == 6) {
            // This rejects getPINToken, get retries, PIN hashes, set/reset PIN.
            require(commands == 1 && node.children.size() == 4 && node.at(1).is_int(1) && node.at(2).is_int(2), "diagnostic transmitted a PIN/token command");
            if (fault_ == Fault::agreement_denied) return {0x36};
            auto key = agreement_.public_key();
            if (fault_ == Fault::bad_point) { key.x.fill(0); key.y.fill(0); }
            Bytes result{0}; map(result, 1); integer(result, 1); cose(result, key); return result;
        }
        require(commands == 2 && request[0] == 2 && node.children.size() == 10, "diagnostic must send a single five-member getAssertion without PIN fields");
        require(node.at(1).is_text(hidfido::rp_id), "diagnostic wrong RP");
        auto hash = hash32(node.at(2));
        const auto& allow = node.at(3);
        require(allow.major == 4 && allow.children.size() == 1 && allow.children[0].at("id").data == credential.id && allow.children[0].at("type").is_text("public-key"), "diagnostic wrong allow-list");
        const auto& options = node.at(5);
        require(options.children.size() == 2 && options.at("up").major == 7 && options.at("up").value == 21, "diagnostic must require UP and omit UV");
        const auto& extension = node.at(4).at("hmac-secret");
        require(extension.children.size() == 6, "diagnostic hmac map must contain only PIN1 fields");
        const auto& key_node = extension.at(1);
        require(key_node.children.size() == 10 && key_node.at(1).is_int(2) && key_node.at(3).is_int(-25) && key_node.at(-1).is_int(1), "diagnostic invalid COSE point");
        auto shared = agreement_.shared_secret({hash32(key_node.at(-2)), hash32(key_node.at(-3))});
        auto salt_auth = pin::hmac_sha256(shared.bytes(), extension.at(2).data);
        require(std::ranges::equal(extension.at(3).data, salt_auth.bytes().first(16)), "diagnostic saltAuth mismatch");
        auto decrypted = pin::aes256_cbc_decrypt(shared.bytes(), extension.at(2).data);
        require(std::ranges::equal(decrypted.bytes(), salt), "diagnostic salt mismatch");
        if (fault_ == Fault::denied) return {0x36};
        if (fault_ == Fault::denied_with_data) return {0x36, 0xa0};
        if (fault_ == Fault::unrelated_status) return {0x3f};
        auto output = expected; if (fault_ != Fault::same) output[0] ^= 1;
        auto ciphertext = pin::aes256_cbc_encrypt(shared.bytes(), output);
        Bytes auth(37); const auto rp_hash = hidfido::sha256(bytes(hidfido::rp_id));
        std::copy(rp_hash.begin(), rp_hash.end(), auth.begin());
        auth[32] = fault_ == Fault::uv ? 0x85 : fault_ == Fault::no_up ? 0x80 : fault_ == Fault::no_ed ? 0x01 : 0x81;
        auth[36] = fault_ == Fault::rollback ? 10 : 11;
        if (fault_ == Fault::wrong_rp) auth[0] ^= 1;
        if (fault_ != Fault::no_extension) { map(auth, 1); text(auth, "hmac-secret"); blob(auth, ciphertext.bytes()); }
        if (fault_ == Fault::wrong_challenge) hash[0] ^= 1;
        auto signature = sign(auth, hash);
        if (fault_ == Fault::bad_signature) signature.back() ^= 1;
        if (fault_ == Fault::malformed_signature) signature = {0x30, 3, 2, 1, 1};
        Bytes result{0}; map(result, fault_ == Fault::duplicate || fault_ == Fault::multiple_credentials ? 4 : 3);
        integer(result, 1); map(result, 2); text(result, "id"); auto id = credential.id;
        if (fault_ == Fault::wrong_id) id[0] ^= 1;
        blob(result, id); text(result, "type"); text(result, "public-key");
        integer(result, 2); blob(result, auth); integer(result, 3); blob(result, signature);
        if (fault_ == Fault::duplicate) { integer(result, 3); blob(result, signature); }
        if (fault_ == Fault::multiple_credentials) { integer(result, 5); integer(result, 2); }
        if (fault_ == Fault::truncated) result.pop_back();
        return result;
    }
    hidfido::Credential credential;
    Hash expected{}, salt{};
    unsigned commands{};
private:
    Bytes sign(std::span<const std::uint8_t> auth, const Hash& client_hash) {
        Bytes joined(auth.begin(), auth.end()); append(joined, client_hash); const auto digest = hidfido::sha256(joined);
        std::array<std::uint8_t, 64> raw{}; ULONG size{};
        cng(BCryptSignHash(key_, nullptr, const_cast<PUCHAR>(digest.data()), static_cast<ULONG>(digest.size()), raw.data(), static_cast<ULONG>(raw.size()), &size, 0));
        require(size == 64, "test signature size");
        const auto r = der_integer(std::span(raw).first(32)); const auto s = der_integer(std::span(raw).subspan(32));
        Bytes result{0x30, static_cast<std::uint8_t>(r.size() + s.size())}; append(result, r); append(result, s); return result;
    }
    Fault fault_{};
    pin::KeyAgreement agreement_;
    BCRYPT_ALG_HANDLE algorithm_{};
    BCRYPT_KEY_HANDLE key_{};
};
template<class Action> void inconclusive(Action&& action) {
    bool rejected{}; try { action(); } catch (const std::exception&) { rejected = true; }
    require(rejected, "ambiguous diagnostic response was classified as protection");
}
}

int main() {
    try {
        for (const auto fault : {Fault::none, Fault::same, Fault::denied}) {
            Authenticator authenticator(fault);
            const auto result = diagnostic::probe_without_pin(authenticator, authenticator.credential, authenticator.salt, authenticator.expected);
            const auto expected = fault == Fault::none ? diagnostic::Outcome::distinct_secret : fault == Fault::same ? diagnostic::Outcome::same_secret : diagnostic::Outcome::denied;
            require(result.outcome == expected, "wrong diagnostic classification");
            require(result.ctap_status == (fault == Fault::denied ? std::optional<std::uint8_t>{std::uint8_t{0x36}} : std::nullopt), "wrong diagnostic status");
            require(authenticator.commands == 2, "diagnostic issued unexpected commands");
            require(authenticator.credential.sign_count == 10, "diagnostic changed production credential metadata");
        }
        for (const auto fault : {Fault::malformed_signature, Fault::bad_signature, Fault::wrong_challenge, Fault::uv, Fault::no_up, Fault::no_ed, Fault::wrong_rp, Fault::rollback, Fault::no_extension, Fault::duplicate, Fault::truncated, Fault::denied_with_data, Fault::unrelated_status, Fault::agreement_denied, Fault::bad_point, Fault::wrong_id, Fault::multiple_credentials}) {
            Authenticator authenticator(fault);
            inconclusive([&] { diagnostic::probe_without_pin(authenticator, authenticator.credential, authenticator.salt, authenticator.expected); });
            require(authenticator.commands <= 2, "diagnostic retried a failed command");
        }
        {
            Authenticator authenticator;
            inconclusive([&] { diagnostic::probe_without_pin(authenticator, authenticator.credential, authenticator.salt, std::span(authenticator.expected).first(16)); });
            require(authenticator.commands == 0, "invalid input reached authenticator");
        }
        std::cout << "Tool-only UV boundary diagnostic: same/distinct/denied, signatures/challenge/flags, malformed data and no PIN/token commands passed.\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "UV diagnostic test failed: " << error.what() << '\n'; return 1;
    }
}
