#include "hidfido/ctap_client.hpp"
#include "hidfido/core_hmac.hpp"
#include "hidfido/pin_protocol.hpp"

#include <algorithm>
#include <array>
#include <limits>
#include <string>
#include <string_view>
#include <utility>

namespace hidfido::ctap {
namespace {
constexpr std::size_t max_message = 8192;
// CTAP 2.0 section 5.5.2 allows authenticator-selected PIN-token lengths that
// are multiples of 16. 512 bytes is this client's defensive allocation cap,
// not a size required or imposed by that specification.
constexpr std::size_t max_pin_token_bytes = 512;
constexpr std::size_t max_items = 4096;
constexpr unsigned max_depth = 8;

[[noreturn]] void invalid(const char* message) {
    throw std::runtime_error(std::string("CTAP client: ") + message);
}
std::span<const std::uint8_t> as_bytes(std::string_view value) {
    return {reinterpret_cast<const std::uint8_t*>(value.data()), value.size()};
}
void append(Bytes& target, std::span<const std::uint8_t> value) {
    target.insert(target.end(), value.begin(), value.end());
}
void head(Bytes& target, std::uint8_t major, std::uint64_t value) {
    const auto initial = static_cast<std::uint8_t>(major << 5);
    if (value < 24) target.push_back(static_cast<std::uint8_t>(initial | value));
    else {
        unsigned length = value <= 0xff ? 1 : value <= 0xffff ? 2 : value <= 0xffffffffULL ? 4 : 8;
        target.push_back(static_cast<std::uint8_t>(initial | (length == 1 ? 24 : length == 2 ? 25 : length == 4 ? 26 : 27)));
        while (length) { --length; target.push_back(static_cast<std::uint8_t>(value >> (8 * length))); }
    }
}
void integer(Bytes& target, std::int64_t value) {
    head(target, value < 0 ? 1 : 0, value < 0 ? static_cast<std::uint64_t>(-(value + 1)) : static_cast<std::uint64_t>(value));
}
void blob(Bytes& target, std::span<const std::uint8_t> value) {
    head(target, 2, value.size()); append(target, value);
}
void text(Bytes& target, std::string_view value) {
    head(target, 3, value.size()); append(target, as_bytes(value));
}
void boolean(Bytes& target, bool value) { target.push_back(value ? 0xf5 : 0xf4); }
void map(Bytes& target, std::uint64_t count) { head(target, 5, count); }
void array(Bytes& target, std::uint64_t count) { head(target, 4, count); }

void utf8(std::span<const std::uint8_t> value) {
    std::size_t index{};
    while (index < value.size()) {
        const auto first = value[index++];
        if (first < 0x80) continue;
        unsigned trailing{}; std::uint32_t scalar{}, minimum{};
        if (first >= 0xc2 && first <= 0xdf) { trailing = 1; scalar = first & 31U; minimum = 0x80; }
        else if (first >= 0xe0 && first <= 0xef) { trailing = 2; scalar = first & 15U; minimum = 0x800; }
        else if (first >= 0xf0 && first <= 0xf4) { trailing = 3; scalar = first & 7U; minimum = 0x10000; }
        else invalid("invalid UTF-8 response");
        if (trailing > value.size() - index) invalid("truncated UTF-8 response");
        while (trailing--) {
            const auto next = value[index++];
            if ((next & 0xc0U) != 0x80U) invalid("invalid UTF-8 continuation");
            scalar = (scalar << 6) | (next & 63U);
        }
        if (scalar < minimum || scalar > 0x10ffff || (scalar >= 0xd800 && scalar <= 0xdfff)) invalid("invalid UTF-8 scalar");
    }
}

// No application secret is decoded by this CBOR reader. ClientPIN token and
// hmac-secret fields remain ciphertext until copied to locked SecureBytes.
struct Node {
    std::uint8_t major{};
    std::uint8_t additional{};
    std::uint64_t value{};
    Bytes bytes;
    std::vector<Node> children;
    bool is_int(std::int64_t number) const noexcept {
        return major == (number < 0 ? 1 : 0) && value == (number < 0 ? static_cast<std::uint64_t>(-(number + 1)) : static_cast<std::uint64_t>(number));
    }
    bool is_text(std::string_view name) const noexcept {
        return major == 3 && std::ranges::equal(bytes, as_bytes(name));
    }
};

class Reader {
public:
    explicit Reader(std::span<const std::uint8_t> data) : data_(data) {}
    Node read(unsigned depth = 0) {
        if (depth > max_depth || ++items_ > max_items) invalid("CBOR limits exceeded");
        const auto initial = take(1)[0];
        Node node; node.major = static_cast<std::uint8_t>(initial >> 5); node.additional = static_cast<std::uint8_t>(initial & 31U);
        if (node.additional < 24) node.value = node.additional;
        else {
            if (node.additional > 27) invalid("indefinite or reserved CBOR");
            const unsigned length = 1U << (node.additional - 24U);
            for (const auto byte : take(length)) node.value = (node.value << 8) | byte;
            if (node.major != 7 && ((length == 1 && node.value < 24) || (length == 2 && node.value <= 0xff) || (length == 4 && node.value <= 0xffff) || (length == 8 && node.value <= 0xffffffffULL))) invalid("nonminimal CBOR");
            if (node.major == 7 && node.additional == 24 && node.value < 32) invalid("invalid simple CBOR");
        }
        switch (node.major) {
        case 0: case 1: case 7: break;
        case 2: case 3: {
            const auto data = take(node.value);
            if (node.major == 3) utf8(data);
            node.bytes.assign(data.begin(), data.end()); break;
        }
        case 4:
            if (node.value > 512) invalid("CBOR array exceeds limit");
            for (std::uint64_t i = 0; i < node.value; ++i) node.children.push_back(read(depth + 1));
            break;
        case 5: {
            if (node.value > 128) invalid("CBOR map exceeds limit");
            std::vector<std::span<const std::uint8_t>> keys;
            for (std::uint64_t i = 0; i < node.value; ++i) {
                const auto start = position_;
                auto key = read(depth + 1);
                if (key.major > 3) invalid("unsupported CBOR map key");
                const auto encoded = data_.subspan(start, position_ - start);
                for (const auto previous : keys) if (std::ranges::equal(previous, encoded)) invalid("duplicate CBOR map key");
                keys.push_back(encoded); node.children.push_back(std::move(key));
                node.children.push_back(read(depth + 1));
            }
            break;
        }
        default: invalid("CBOR tags not permitted");
        }
        return node;
    }
    bool finished() const noexcept { return position_ == data_.size(); }
private:
    std::span<const std::uint8_t> take(std::uint64_t count) {
        if (count > data_.size() - position_) invalid("truncated CBOR response");
        const auto size = static_cast<std::size_t>(count);
        const auto result = data_.subspan(position_, size); position_ += size; return result;
    }
    std::span<const std::uint8_t> data_;
    std::size_t position_{}, items_{};
};

const Node* member(const Node& node, std::int64_t label) {
    if (node.major != 5) invalid("expected response map");
    for (std::size_t i = 0; i < node.children.size(); i += 2) if (node.children[i].is_int(label)) return &node.children[i + 1];
    return nullptr;
}
const Node* member(const Node& node, std::string_view label) {
    if (node.major != 5) invalid("expected response map");
    for (std::size_t i = 0; i < node.children.size(); i += 2) if (node.children[i].is_text(label)) return &node.children[i + 1];
    return nullptr;
}
const Node& required(const Node& node, std::int64_t label) {
    const auto* result = member(node, label);
    if (!result) invalid("missing response member");
    return *result;
}
const Bytes& byte_string(const Node& node) {
    if (node.major != 2) invalid("expected response byte string");
    return node.bytes;
}
Node exchange(Transport& transport, const Bytes& request) {
    if (request.empty() || request.size() > max_message) invalid("command size exceeds limit");
    const auto response = transport.transact(request);
    if (response.empty()) invalid("missing response status");
    if (response.size() > max_message) invalid("response size exceeds limit");
    if (response[0]) throw StatusError(response[0]);
    Reader reader(std::span(response).subspan(1));
    auto result = reader.read();
    if (!reader.finished() || result.major != 5) invalid("invalid response map or trailing CBOR");
    return result;
}

void capabilities(const AuthenticatorInfo& info) {
    if (!info.hmac_secret) invalid("authenticator lacks hmac-secret");
    if (!info.client_pin.value_or(false)) invalid("authenticator requires an already configured PIN");
    if (std::ranges::find(info.pin_protocols, 1U) == info.pin_protocols.end()) invalid("authenticator lacks PIN protocol 1");
}
void public_key(Bytes& request, const pin::P256PublicKey& key) {
    map(request, 5);
    integer(request, 1); integer(request, 2);
    integer(request, 3); integer(request, -25);
    integer(request, -1); integer(request, 1);
    integer(request, -2); blob(request, key.x);
    integer(request, -3); blob(request, key.y);
}
pin::P256PublicKey peer_key(Transport& transport) {
    Bytes request{0x06}; map(request, 2);
    integer(request, 1); integer(request, 1);
    integer(request, 2); integer(request, 2);
    const auto result = exchange(transport, request);
    const auto& key = required(result, 1);
    if (!required(key, 1).is_int(2) || !required(key, 3).is_int(-25) || !required(key, -1).is_int(1)) invalid("invalid key-agreement COSE parameters");
    const auto& x = byte_string(required(key, -2)); const auto& y = byte_string(required(key, -3));
    if (x.size() != 32 || y.size() != 32) invalid("invalid key-agreement point length");
    pin::P256PublicKey peer;
    std::ranges::copy(x, peer.x.begin()); std::ranges::copy(y, peer.y.begin()); return peer;
}
struct Session {
    pin::KeyAgreement agreement;
    password::SecureBytes shared;
    password::SecureBytes token;
};
Session pin_session(Transport& transport, std::span<const std::uint8_t> utf8_pin) {
    // Validate locally before any authenticator PIN command. Never retry.
    auto pin_hash = pin::pin_hash16(utf8_pin);
    Session session;
    session.shared = session.agreement.shared_secret(peer_key(transport));
    auto encrypted_hash = pin::aes256_cbc_encrypt(session.shared.bytes(), pin_hash.bytes());
    pin_hash.clear();
    Bytes request{0x06}; map(request, 4);
    integer(request, 1); integer(request, 1);
    integer(request, 2); integer(request, 5);
    integer(request, 3); public_key(request, session.agreement.public_key());
    integer(request, 6); blob(request, encrypted_hash.bytes());
    const auto result = exchange(transport, request);
    const auto& token_enc = byte_string(required(result, 2));
    if (token_enc.empty() || token_enc.size() > max_pin_token_bytes || token_enc.size() % 16 != 0) {
        // Length only: never include token bytes or decrypted material.
        throw std::runtime_error("CTAP client: invalid encrypted PIN token length " + std::to_string(token_enc.size()));
    }
    session.token = pin::aes256_cbc_decrypt(session.shared.bytes(), token_enc);
    return session;
}
std::string client_data(std::string_view type) {
    const auto challenge = random_bytes(32);
    return make_client_data(type, challenge);
}
void descriptor(Bytes& request, std::span<const std::uint8_t> credential_id) {
    map(request, 2); text(request, "id"); blob(request, credential_id);
    text(request, "type"); text(request, "public-key");
}
void verify_descriptor(const Node& node, const Credential& credential) {
    const auto* id = member(node, "id"); const auto* type = member(node, "type");
    if (!id || !type || !type->is_text("public-key") || !std::ranges::equal(byte_string(*id), credential.id)) invalid("assertion credential does not match allow list");
}
}

StatusError::StatusError(std::uint8_t status)
    : std::runtime_error("CTAP status " + std::to_string(status)), status_(status) {}

AuthenticatorInfo HmacClient::info() {
    const std::array<std::uint8_t, 1> request{0x04};
    const auto response = transport_.transact(request);
    if (!response.empty() && response[0]) throw StatusError(response[0]);
    return parse_get_info(response);
}

Credential HmacClient::make_credential(std::span<const std::uint8_t> utf8_pin, const Hash& user_handle,
                                       std::string_view user_name, std::string_view display_name,
                                       std::span<const Bytes> exclude_ids) {
    if (exclude_ids.size() > 8) invalid("exclude list exceeds limit");
    for (const auto& id : exclude_ids) if (id.empty() || id.size() > 1023) invalid("invalid exclude-list credential ID length");
    if (user_name.empty() || user_name.size() > 64 || display_name.empty() || display_name.size() > 64) {
        invalid("user names must be 1 to 64 bytes");
    }
    utf8(as_bytes(user_name)); utf8(as_bytes(display_name));
    capabilities(info());
    auto session = pin_session(transport_, utf8_pin);
    const auto client = client_data("webauthn.create");
    const auto client_hash = sha256(as_bytes(client));
    auto pin_auth = pin::hmac_sha256(session.token.bytes(), client_hash);
    session.token.clear();
    session.shared.clear();
    Bytes request{0x01}; map(request, exclude_ids.empty() ? 7 : 8);
    integer(request, 1); blob(request, client_hash);
    integer(request, 2); map(request, 2); text(request, "id"); text(request, rp_id); text(request, "name"); text(request, "HID FIDO2 HMAC test");
    integer(request, 3); map(request, 3); text(request, "id"); blob(request, user_handle); text(request, "name"); text(request, user_name); text(request, "displayName"); text(request, display_name);
    integer(request, 4); array(request, 1); map(request, 2); text(request, "alg"); integer(request, -7); text(request, "type"); text(request, "public-key");
    if (!exclude_ids.empty()) {
        // An authenticator already holding one of these credentials refuses
        // with CTAP2_ERR_CREDENTIAL_EXCLUDED, so the same key is not enrolled twice.
        integer(request, 5); array(request, exclude_ids.size());
        for (const auto& id : exclude_ids) descriptor(request, id);
    }
    integer(request, 6); map(request, 1); text(request, "hmac-secret"); boolean(request, true);
    // The default is nonresident. Omit rk entirely: devices that do not expose
    // the rk capability can reject even an explicitly false rk option.
    integer(request, 8); blob(request, pin_auth.bytes().first(16));
    integer(request, 9); integer(request, 1);
    const auto result = exchange(transport_, request);
    const auto& format = required(result, 1);
    if (!format.is_text("packed") && !format.is_text("none")) invalid("unsupported attestation format");
    if (required(result, 3).major != 5) invalid("invalid attestation statement");
    auto credential = parse_hmac_registration(byte_string(required(result, 2)));
    credential.user_handle = user_handle;
    return credential;
}

password::SecureBytes HmacClient::get_secret(std::span<const std::uint8_t> utf8_pin,
                                            Credential& credential, const Hash& salt) {
    if (credential.id.empty() || credential.id.size() > 1023) invalid("invalid allow-list credential ID length");
    capabilities(info());
    auto session = pin_session(transport_, utf8_pin);
    auto salt_enc = pin::aes256_cbc_encrypt(session.shared.bytes(), salt);
    auto salt_auth = pin::hmac_sha256(session.shared.bytes(), salt_enc.bytes());
    const auto client = client_data("webauthn.get");
    const auto client_hash = sha256(as_bytes(client));
    auto pin_auth = pin::hmac_sha256(session.token.bytes(), client_hash);
    session.token.clear();
    Bytes request{0x02}; map(request, 7);
    integer(request, 1); text(request, rp_id);
    integer(request, 2); blob(request, client_hash);
    integer(request, 3); array(request, 1); descriptor(request, credential.id);
    integer(request, 4); map(request, 1); text(request, "hmac-secret"); map(request, 3);
    integer(request, 1); public_key(request, session.agreement.public_key());
    integer(request, 2); blob(request, salt_enc.bytes());
    integer(request, 3); blob(request, salt_auth.bytes().first(16));
    integer(request, 5); map(request, 1); text(request, "up"); boolean(request, true);
    integer(request, 6); blob(request, pin_auth.bytes().first(16));
    integer(request, 7); integer(request, 1);
    const auto result = exchange(transport_, request);
    if (const auto* returned = member(result, 1)) verify_descriptor(*returned, credential);
    // A single explicit allow-list entry permits an omitted credential member.
    if (const auto* number = member(result, 5); number && !number->is_int(1)) invalid("unexpected assertion credential count");
    const auto& auth = byte_string(required(result, 2));
    const auto& signature = byte_string(required(result, 3));
    const auto verified = verify_hmac_assertion(credential, auth, signature, client);
    auto secret = pin::aes256_cbc_decrypt(session.shared.bytes(), verified.ciphertext);
    if (secret.size() != 32) invalid("invalid decrypted hmac-secret length");
    credential.sign_count = verified.sign_count;
    return secret;
}
}
