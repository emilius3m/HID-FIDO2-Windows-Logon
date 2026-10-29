// age v1 header, payload STREAM and the X25519 / fido2prf recipients.
// Parsing follows the strict rules of the C2SP age specification: canonical
// unpadded base64, 64-column stanza bodies, an exact MAC line and no data after
// the final payload chunk.
#include "hidfido/age.hpp"

#include <algorithm>
#include <istream>
#include <ostream>
#include <sstream>
#include <utility>

namespace hidfido::age {
namespace {
constexpr std::string_view intro = "age-encryption.org/v1";
constexpr std::string_view x25519_type = "X25519";
constexpr std::string_view x25519_label = "age-encryption.org/v1/X25519";
constexpr std::size_t max_header_bytes = 1 << 20;
constexpr std::size_t max_stanzas = 1024;
constexpr std::size_t encrypted_chunk = chunk_size + 16;

std::span<const std::uint8_t> bytes_of(std::string_view text) noexcept {
    return {reinterpret_cast<const std::uint8_t*>(text.data()), text.size()};
}

const std::array<std::uint8_t, 12> zero_nonce{};

std::array<std::uint8_t, 32> derive32(std::span<const std::uint8_t> ikm, std::span<const std::uint8_t> salt,
                                      std::string_view info) {
    auto derived = crypto::hkdf_sha256(ikm, salt, bytes_of(info), 32);
    std::array<std::uint8_t, 32> key{};
    std::copy(derived.begin(), derived.end(), key.begin());
    wipe(derived);
    return key;
}

Bytes wrap_file_key(const std::array<std::uint8_t, 32>& key, const FileKey& file_key) {
    return crypto::chacha20poly1305_seal(key, zero_nonce, file_key);
}

std::optional<FileKey> unwrap_file_key(const std::array<std::uint8_t, 32>& key, std::span<const std::uint8_t> body) {
    if (body.size() != 32) return std::nullopt;
    auto opened = crypto::chacha20poly1305_open(key, zero_nonce, body);
    if (!opened) return std::nullopt;
    FileKey file_key{};
    std::copy(opened->begin(), opened->end(), file_key.begin());
    wipe(*opened);
    return file_key;
}

bool valid_arg(std::string_view arg) noexcept {
    return !arg.empty() && std::ranges::all_of(arg, [](char c) { return c >= 0x21 && c <= 0x7e; });
}

std::array<std::uint8_t, 12> stream_nonce(std::uint64_t counter, bool last) noexcept {
    std::array<std::uint8_t, 12> nonce{};
    for (int i = 0; i < 8; ++i) nonce[10 - i] = static_cast<std::uint8_t>(counter >> (8 * i));
    nonce[11] = last ? 1 : 0;
    return nonce;
}

// ---- Minimal canonical CBOR for the fido2prf identity payload ----
void cbor_head(Bytes& out, std::uint8_t major, std::uint64_t value) {
    const auto type = static_cast<std::uint8_t>(major << 5);
    if (value < 24) out.push_back(static_cast<std::uint8_t>(type | value));
    else if (value <= 0xff) { out.push_back(type | 24); out.push_back(static_cast<std::uint8_t>(value)); }
    else if (value <= 0xffff) {
        out.push_back(type | 25);
        out.push_back(static_cast<std::uint8_t>(value >> 8));
        out.push_back(static_cast<std::uint8_t>(value));
    } else throw std::invalid_argument("CBOR value too large for a fido2prf identity");
}

class CborReader {
public:
    explicit CborReader(std::span<const std::uint8_t> data) : data_(data) {}
    std::uint64_t head(std::uint8_t major) {
        const auto first = take(1)[0];
        if ((first >> 5) != major) throw FormatError("Unexpected CBOR type in fido2prf identity");
        const auto info = first & 0x1f;
        if (info < 24) return info;
        if (info == 24) {
            const auto value = take(1)[0];
            if (value < 24) throw FormatError("Non-canonical CBOR in fido2prf identity");
            return value;
        }
        if (info == 25) {
            const auto bytes = take(2);
            const auto value = (std::uint64_t{bytes[0]} << 8) | bytes[1];
            if (value <= 0xff) throw FormatError("Non-canonical CBOR in fido2prf identity");
            return value;
        }
        throw FormatError("Unsupported CBOR length in fido2prf identity");
    }
    std::span<const std::uint8_t> take(std::size_t count) {
        if (count > data_.size() - position_) throw FormatError("Truncated fido2prf identity");
        const auto result = data_.subspan(position_, count);
        position_ += count;
        return result;
    }
    std::string text(std::size_t maximum) {
        const auto length = head(3);
        if (length > maximum) throw FormatError("Oversized text in fido2prf identity");
        const auto bytes = take(static_cast<std::size_t>(length));
        return {bytes.begin(), bytes.end()};
    }
    bool empty() const noexcept { return position_ == data_.size(); }
private:
    std::span<const std::uint8_t> data_;
    std::size_t position_{};
};

// ---- Bech32 ----
constexpr std::string_view bech32_charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

std::uint32_t polymod(std::span<const std::uint8_t> values) noexcept {
    constexpr std::array<std::uint32_t, 5> generator{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3};
    std::uint32_t checksum = 1;
    for (const auto value : values) {
        const auto top = checksum >> 25;
        checksum = ((checksum & 0x1ffffff) << 5) ^ value;
        for (int i = 0; i < 5; ++i) if ((top >> i) & 1) checksum ^= generator[i];
    }
    return checksum;
}

Bytes hrp_expand(std::string_view hrp) {
    Bytes result;
    for (const char c : hrp) result.push_back(static_cast<std::uint8_t>(static_cast<unsigned char>(c) >> 5));
    result.push_back(0);
    for (const char c : hrp) result.push_back(static_cast<std::uint8_t>(static_cast<unsigned char>(c) & 31));
    return result;
}

Bytes convert_bits(std::span<const std::uint8_t> data, int from, int to, bool pad) {
    Bytes result;
    std::uint32_t accumulator = 0;
    int bits = 0;
    const std::uint32_t mask = (1u << to) - 1;
    for (const auto value : data) {
        if ((value >> from) != 0) throw FormatError("Invalid Bech32 data");
        accumulator = (accumulator << from) | value;
        bits += from;
        while (bits >= to) {
            bits -= to;
            result.push_back(static_cast<std::uint8_t>((accumulator >> bits) & mask));
        }
    }
    if (pad) {
        if (bits) result.push_back(static_cast<std::uint8_t>((accumulator << (to - bits)) & mask));
    } else if (bits >= from || ((accumulator << (to - bits)) & mask)) {
        throw FormatError("Invalid Bech32 padding");
    }
    return result;
}

std::string lower(std::string_view text) {
    std::string result(text);
    for (auto& c : result) if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    return result;
}
std::string upper(std::string_view text) {
    std::string result(text);
    for (auto& c : result) if (c >= 'a' && c <= 'z') c = static_cast<char>(c - 'a' + 'A');
    return result;
}
}

// ---- Encodings ----
namespace encoding {
std::string base64_encode(std::span<const std::uint8_t> data) {
    static constexpr char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    std::size_t i = 0;
    for (; i + 3 <= data.size(); i += 3) {
        const std::uint32_t v = (std::uint32_t{data[i]} << 16) | (std::uint32_t{data[i + 1]} << 8) | data[i + 2];
        out += alphabet[v >> 18]; out += alphabet[(v >> 12) & 63]; out += alphabet[(v >> 6) & 63]; out += alphabet[v & 63];
    }
    if (data.size() - i == 1) {
        const std::uint32_t v = std::uint32_t{data[i]} << 16;
        out += alphabet[v >> 18]; out += alphabet[(v >> 12) & 63];
    } else if (data.size() - i == 2) {
        const std::uint32_t v = (std::uint32_t{data[i]} << 16) | (std::uint32_t{data[i + 1]} << 8);
        out += alphabet[v >> 18]; out += alphabet[(v >> 12) & 63]; out += alphabet[(v >> 6) & 63];
    }
    return out;
}

Bytes base64_decode(std::string_view text) {
    auto value = [](char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        return -1;
    };
    if (text.size() % 4 == 1) throw FormatError("Invalid base64 length");
    Bytes out;
    std::uint32_t accumulator = 0;
    int bits = 0;
    for (const char c : text) {
        const int v = value(c);
        if (v < 0) throw FormatError("Invalid base64 character");
        accumulator = (accumulator << 6) | static_cast<std::uint32_t>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<std::uint8_t>(accumulator >> bits));
        }
    }
    if (accumulator & ((1u << bits) - 1)) throw FormatError("Non-canonical base64");
    return out;
}

std::string bech32_encode(std::string_view hrp, std::span<const std::uint8_t> data, bool upper_case) {
    const auto low_hrp = lower(hrp);
    if (low_hrp.empty() || !std::ranges::all_of(low_hrp, [](char c) { return c >= 33 && c <= 126; })) {
        throw std::invalid_argument("Invalid Bech32 human-readable part");
    }
    const auto words = convert_bits(data, 8, 5, true);
    auto values = hrp_expand(low_hrp);
    values.insert(values.end(), words.begin(), words.end());
    values.insert(values.end(), 6, 0);
    const auto checksum = polymod(values) ^ 1;
    std::string result = low_hrp + "1";
    for (const auto word : words) result += bech32_charset[word];
    for (int i = 0; i < 6; ++i) result += bech32_charset[(checksum >> (5 * (5 - i))) & 31];
    return upper_case ? upper(result) : result;
}

Bech32 bech32_decode(std::string_view text) {
    bool has_lower = false, has_upper = false;
    for (const char c : text) {
        if (c < 33 || c > 126) throw FormatError("Invalid Bech32 character");
        has_lower |= c >= 'a' && c <= 'z';
        has_upper |= c >= 'A' && c <= 'Z';
    }
    if (has_lower && has_upper) throw FormatError("Mixed-case Bech32 string");
    const auto normalized = lower(text);
    const auto separator = normalized.rfind('1');
    if (separator == std::string::npos || separator == 0 || separator + 7 > normalized.size()) {
        throw FormatError("Malformed Bech32 string");
    }
    const auto hrp = normalized.substr(0, separator);
    Bytes words;
    for (const char c : std::string_view(normalized).substr(separator + 1)) {
        const auto position = bech32_charset.find(c);
        if (position == std::string_view::npos) throw FormatError("Invalid Bech32 data character");
        words.push_back(static_cast<std::uint8_t>(position));
    }
    auto values = hrp_expand(hrp);
    values.insert(values.end(), words.begin(), words.end());
    if (polymod(values) != 1) throw FormatError("Invalid Bech32 checksum");
    words.resize(words.size() - 6);
    return {hrp, convert_bits(words, 5, 8, false)};
}
}

// ---- X25519 ----
X25519Recipient::X25519Recipient(std::span<const std::uint8_t, 32> public_key) {
    std::copy(public_key.begin(), public_key.end(), public_key_.begin());
}

X25519Recipient X25519Recipient::parse(std::string_view text) {
    const auto decoded = encoding::bech32_decode(text);
    if (decoded.hrp != "age" || decoded.data.size() != 32 || text.substr(0, 4) != "age1") {
        throw FormatError("Not an age X25519 recipient");
    }
    return X25519Recipient(std::span<const std::uint8_t, 32>(decoded.data.data(), 32));
}

std::string X25519Recipient::encode() const { return encoding::bech32_encode("age", public_key_, false); }

std::vector<Stanza> X25519Recipient::wrap(const FileKey& file_key) {
    std::array<std::uint8_t, 32> ephemeral{};
    random_bytes(ephemeral);
    const auto share = crypto::x25519_base(ephemeral);
    auto shared = crypto::x25519(ephemeral, public_key_);
    wipe(ephemeral);
    if (crypto::equal_constant_time(shared, std::array<std::uint8_t, 32>{})) {
        throw FormatError("Invalid X25519 recipient (low-order point)");
    }
    Bytes salt(share.begin(), share.end());
    salt.insert(salt.end(), public_key_.begin(), public_key_.end());
    auto key = derive32(shared, salt, x25519_label);
    wipe(shared);
    Stanza stanza{std::string(x25519_type), {encoding::base64_encode(share)}, wrap_file_key(key, file_key)};
    wipe(key);
    return {std::move(stanza)};
}

X25519Identity::X25519Identity(std::span<const std::uint8_t, 32> secret_key) {
    std::copy(secret_key.begin(), secret_key.end(), secret_key_.begin());
    public_key_ = crypto::x25519_base(secret_key_);
}

X25519Identity::X25519Identity(X25519Identity&& other) noexcept
    : secret_key_(other.secret_key_), public_key_(other.public_key_) {
    wipe(other.secret_key_);
}

X25519Identity::~X25519Identity() { wipe(secret_key_); }

X25519Identity X25519Identity::generate() {
    std::array<std::uint8_t, 32> secret{};
    random_bytes(secret);
    X25519Identity identity(secret);
    wipe(secret);
    return identity;
}

X25519Identity X25519Identity::parse(std::string_view text) {
    auto decoded = encoding::bech32_decode(text);
    if (decoded.hrp != "age-secret-key-" || decoded.data.size() != 32 || text.substr(0, 16) != "AGE-SECRET-KEY-1") {
        wipe(decoded.data);
        throw FormatError("Not an age X25519 secret key");
    }
    X25519Identity identity(std::span<const std::uint8_t, 32>(decoded.data.data(), 32));
    wipe(decoded.data);
    return identity;
}

std::string X25519Identity::encode() const { return encoding::bech32_encode("AGE-SECRET-KEY-", secret_key_, true); }

X25519Recipient X25519Identity::recipient() const { return X25519Recipient(public_key_); }

std::optional<FileKey> X25519Identity::unwrap(std::span<const Stanza> stanzas) {
    for (const auto& stanza : stanzas) {
        if (stanza.type != x25519_type) continue;
        if (stanza.args.size() != 1) throw FormatError("Invalid X25519 stanza");
        const auto share = encoding::base64_decode(stanza.args[0]);
        if (share.size() != 32 || stanza.body.size() != 32) throw FormatError("Invalid X25519 stanza");
        auto shared = crypto::x25519(secret_key_, std::span<const std::uint8_t, 32>(share.data(), 32));
        if (crypto::equal_constant_time(shared, std::array<std::uint8_t, 32>{})) {
            throw FormatError("Invalid X25519 stanza (low-order point)");
        }
        Bytes salt(share);
        salt.insert(salt.end(), public_key_.begin(), public_key_.end());
        auto key = derive32(shared, salt, x25519_label);
        wipe(shared);
        auto file_key = unwrap_file_key(key, stanza.body);
        wipe(key);
        if (file_key) return file_key;
    }
    return std::nullopt;
}

// ---- fido2prf ----
std::string Fido2PrfCredential::encode() const {
    if (credential_id.empty() || credential_id.size() > 1023 || rp_id.empty() || rp_id.size() > 253 ||
        transports.size() > 8) {
        throw std::invalid_argument("Invalid fido2prf credential");
    }
    Bytes data;
    cbor_head(data, 0, 1);
    cbor_head(data, 2, credential_id.size());
    data.insert(data.end(), credential_id.begin(), credential_id.end());
    cbor_head(data, 3, rp_id.size());
    data.insert(data.end(), rp_id.begin(), rp_id.end());
    cbor_head(data, 4, transports.size());
    for (const auto& transport : transports) {
        cbor_head(data, 3, transport.size());
        data.insert(data.end(), transport.begin(), transport.end());
    }
    return encoding::bech32_encode("AGE-PLUGIN-FIDO2PRF-", data, true);
}

Fido2PrfCredential Fido2PrfCredential::parse(std::string_view text) {
    const auto decoded = encoding::bech32_decode(text);
    if (decoded.hrp != "age-plugin-fido2prf-") throw FormatError("Not a fido2prf identity");
    CborReader reader(decoded.data);
    if (reader.head(0) != 1) throw FormatError("Unsupported fido2prf identity version");
    Fido2PrfCredential result;
    const auto id_length = reader.head(2);
    if (id_length == 0 || id_length > 1023) throw FormatError("Invalid fido2prf credential ID");
    const auto id = reader.take(static_cast<std::size_t>(id_length));
    result.credential_id.assign(id.begin(), id.end());
    result.rp_id = reader.text(253);
    if (result.rp_id.empty()) throw FormatError("Invalid fido2prf relying party");
    const auto count = reader.head(4);
    if (count > 8) throw FormatError("Too many fido2prf transports");
    for (std::uint64_t i = 0; i < count; ++i) result.transports.push_back(reader.text(32));
    if (!reader.empty()) throw FormatError("Trailing data in fido2prf identity");
    return result;
}

Bytes fido2prf_input(std::span<const std::uint8_t, 16> nonce, std::uint8_t which) {
    Bytes input(fido2prf_label.begin(), fido2prf_label.end());
    input.push_back(which);
    input.insert(input.end(), nonce.begin(), nonce.end());
    return input;
}

crypto::Hash webauthn_prf_salt(std::span<const std::uint8_t> input) {
    Bytes message{'W', 'e', 'b', 'A', 'u', 't', 'h', 'n', ' ', 'P', 'R', 'F', 0};
    message.insert(message.end(), input.begin(), input.end());
    return crypto::sha256(message);
}

namespace {
std::array<std::uint8_t, 32> fido2prf_key(std::array<std::uint8_t, 64>& output) {
    auto key = crypto::hkdf_extract(bytes_of(fido2prf_label), output);
    wipe(output);
    return key;
}

PrfResult evaluate(const PrfFunction& prf, std::span<const Fido2PrfCredential> allowed,
                   std::span<const std::uint8_t, 16> nonce) {
    const auto first = fido2prf_input(nonce, 1);
    const auto second = fido2prf_input(nonce, 2);
    auto result = prf(PrfRequest{allowed, first, second});
    if (result.used >= allowed.size()) {
        wipe(result.output);
        throw std::runtime_error("The authenticator used a credential that was not requested");
    }
    return result;
}
}

Fido2PrfRecipient::Fido2PrfRecipient(Fido2PrfCredential credential, PrfFunction prf)
    : credential_(std::move(credential)), prf_(std::move(prf)) {
    if (!prf_) throw std::invalid_argument("Missing PRF function");
}

std::vector<Stanza> Fido2PrfRecipient::wrap(const FileKey& file_key) {
    std::array<std::uint8_t, 16> nonce{};
    random_bytes(nonce);
    auto result = evaluate(prf_, std::span(&credential_, 1), nonce);
    auto key = fido2prf_key(result.output);
    Stanza stanza{std::string(fido2prf_label), {encoding::base64_encode(nonce)}, wrap_file_key(key, file_key)};
    wipe(key);
    return {std::move(stanza)};
}

Fido2PrfIdentity::Fido2PrfIdentity(std::vector<Fido2PrfCredential> credentials, PrfFunction prf)
    : credentials_(std::move(credentials)), prf_(std::move(prf)) {
    if (credentials_.empty() || !prf_) throw std::invalid_argument("Missing fido2prf credentials");
    for (const auto& credential : credentials_) {
        if (credential.rp_id != credentials_.front().rp_id) {
            throw std::invalid_argument("fido2prf credentials of one identity must share a relying party");
        }
    }
}

std::optional<FileKey> Fido2PrfIdentity::unwrap(std::span<const Stanza> stanzas) {
    for (const auto& stanza : stanzas) {
        if (stanza.type != fido2prf_label) continue;
        if (stanza.args.size() != 1) throw FormatError("Invalid fido2prf stanza");
        const auto nonce = encoding::base64_decode(stanza.args[0]);
        if (nonce.size() != 16) throw FormatError("Invalid fido2prf stanza nonce");
        // A body of the wrong size can never be ours: skip it without a touch.
        if (stanza.body.size() != 32) continue;
        auto result = evaluate(prf_, credentials_, std::span<const std::uint8_t, 16>(nonce.data(), 16));
        auto key = fido2prf_key(result.output);
        auto file_key = unwrap_file_key(key, stanza.body);
        wipe(key);
        if (file_key) return file_key;
    }
    return std::nullopt;
}

// ---- Header ----
std::string serialize_header(std::span<const Stanza> stanzas, const FileKey& file_key) {
    if (stanzas.empty()) throw std::invalid_argument("An age file needs at least one recipient");
    std::string header(intro);
    header += '\n';
    for (const auto& stanza : stanzas) {
        if (!valid_arg(stanza.type)) throw std::invalid_argument("Invalid stanza type");
        header += "-> " + stanza.type;
        for (const auto& arg : stanza.args) {
            if (!valid_arg(arg)) throw std::invalid_argument("Invalid stanza argument");
            header += ' ' + arg;
        }
        header += '\n';
        const auto body = encoding::base64_encode(stanza.body);
        std::size_t offset = 0;
        for (; body.size() - offset >= 64; offset += 64) header += body.substr(offset, 64) + '\n';
        header += body.substr(offset) + '\n';
    }
    header += "---";
    auto mac_key = derive32(file_key, {}, "header");
    const auto mac = crypto::hmac_sha256(mac_key, bytes_of(header));
    wipe(mac_key);
    header += ' ' + encoding::base64_encode(mac) + '\n';
    return header;
}

std::vector<Stanza> parse_header(std::istream& input, std::string& mac_input, crypto::Hash& mac) {
    mac_input.clear();
    auto read_line = [&]() {
        std::string line;
        for (;;) {
            const auto c = input.get();
            if (c == std::char_traits<char>::eof()) throw FormatError("Truncated age header");
            if (mac_input.size() + line.size() >= max_header_bytes) throw FormatError("Oversized age header");
            if (c == '\n') return line;
            line.push_back(static_cast<char>(c));
        }
    };
    auto line = read_line();
    if (line != intro) throw FormatError("Not an age v1 file (or an unsupported armored file)");
    mac_input = line + '\n';
    std::vector<Stanza> stanzas;
    for (line = read_line();; line = read_line()) {
        if (line.starts_with("---")) {
            if (line.size() != 3 + 1 + 43 || line[3] != ' ') throw FormatError("Malformed age header MAC line");
            const auto decoded = encoding::base64_decode(std::string_view(line).substr(4));
            if (decoded.size() != mac.size()) throw FormatError("Malformed age header MAC");
            std::copy(decoded.begin(), decoded.end(), mac.begin());
            mac_input += "---";
            if (stanzas.empty()) throw FormatError("age header has no recipients");
            return stanzas;
        }
        if (!line.starts_with("-> ")) throw FormatError("Malformed age stanza");
        if (stanzas.size() == max_stanzas) throw FormatError("Too many age stanzas");
        mac_input += line + '\n';
        Stanza stanza;
        std::size_t start = 3;
        std::vector<std::string> fields;
        for (;;) {
            const auto end = line.find(' ', start);
            fields.push_back(line.substr(start, end == std::string::npos ? std::string::npos : end - start));
            if (!valid_arg(fields.back())) throw FormatError("Malformed age stanza argument");
            if (end == std::string::npos) break;
            start = end + 1;
        }
        stanza.type = fields.front();
        stanza.args.assign(fields.begin() + 1, fields.end());
        std::string body;
        for (;;) {
            const auto body_line = read_line();
            if (body_line.size() > 64) throw FormatError("Malformed age stanza body");
            mac_input += body_line + '\n';
            body += body_line;
            if (body_line.size() < 64) break;
        }
        stanza.body = encoding::base64_decode(body);
        stanzas.push_back(std::move(stanza));
    }
}

// ---- Payload ----
Encryptor::Encryptor(std::ostream& output, std::span<Recipient* const> recipients) : output_(output) {
    if (recipients.empty()) throw std::invalid_argument("An age file needs at least one recipient");
    FileKey file_key{};
    random_bytes(file_key);
    try {
        std::vector<Stanza> stanzas;
        for (auto* recipient : recipients) {
            auto wrapped = recipient->wrap(file_key);
            for (auto& stanza : wrapped) stanzas.push_back(std::move(stanza));
        }
        const auto header = serialize_header(stanzas, file_key);
        std::array<std::uint8_t, 16> nonce{};
        random_bytes(nonce);
        key_ = derive32(file_key, nonce, "payload");
        wipe(file_key);
        output_.write(header.data(), static_cast<std::streamsize>(header.size()));
        output_.write(reinterpret_cast<const char*>(nonce.data()), static_cast<std::streamsize>(nonce.size()));
        if (!output_) throw std::runtime_error("Cannot write the encrypted file");
    } catch (...) {
        wipe(file_key);
        throw;
    }
    buffer_.reserve(chunk_size);
}

Encryptor::~Encryptor() {
    wipe(key_);
    wipe(buffer_);
}

void Encryptor::write(std::span<const std::uint8_t> data) {
    if (finished_) throw std::logic_error("Encryptor already finished");
    while (!data.empty()) {
        // Only a chunk followed by more data may be written as non-final.
        if (buffer_.size() == chunk_size) flush_chunk(false);
        const auto count = (std::min)(data.size(), chunk_size - buffer_.size());
        buffer_.insert(buffer_.end(), data.begin(), data.begin() + static_cast<std::ptrdiff_t>(count));
        data = data.subspan(count);
    }
}

void Encryptor::finish() {
    if (finished_) return;
    flush_chunk(true);
    finished_ = true;
    output_.flush();
    if (!output_) throw std::runtime_error("Cannot write the encrypted file");
    wipe(key_);
}

void Encryptor::flush_chunk(bool last) {
    const auto nonce = stream_nonce(counter_++, last);
    const auto sealed = crypto::chacha20poly1305_seal(key_, nonce, buffer_);
    output_.write(reinterpret_cast<const char*>(sealed.data()), static_cast<std::streamsize>(sealed.size()));
    if (!output_) throw std::runtime_error("Cannot write the encrypted file");
    wipe(buffer_);
    buffer_.clear();
}

Decryptor::Decryptor(std::istream& input, std::span<Identity* const> identities) : input_(input) {
    std::string mac_input;
    crypto::Hash mac{};
    stanzas_ = parse_header(input_, mac_input, mac);
    std::optional<FileKey> file_key;
    for (auto* identity : identities) {
        file_key = identity->unwrap(stanzas_);
        if (file_key) break;
    }
    if (!file_key) throw NoIdentityMatched();
    auto mac_key = derive32(*file_key, {}, "header");
    const auto expected = crypto::hmac_sha256(mac_key, bytes_of(mac_input));
    wipe(mac_key);
    if (!crypto::equal_constant_time(expected, mac)) {
        wipe(*file_key);
        throw FormatError("age header authentication failed");
    }
    std::array<std::uint8_t, 16> nonce{};
    input_.read(reinterpret_cast<char*>(nonce.data()), nonce.size());
    if (input_.gcount() != static_cast<std::streamsize>(nonce.size())) {
        wipe(*file_key);
        throw FormatError("Truncated age payload");
    }
    key_ = derive32(*file_key, nonce, "payload");
    wipe(*file_key);
}

Decryptor::~Decryptor() {
    wipe(key_);
    wipe(plain_);
    wipe(chunk_);
}

bool Decryptor::next_chunk() {
    if (finished_) return false;
    if (last_seen_) {
        // The final chunk was released; the file must end right after it.
        char extra{};
        input_.read(&extra, 1);
        if (input_.gcount() != 0) throw FormatError("Unexpected data after the final age chunk");
        if (input_.bad()) throw std::runtime_error("Cannot read the encrypted file");
        finished_ = true;
        return false;
    }
    chunk_.resize(encrypted_chunk);
    input_.read(reinterpret_cast<char*>(chunk_.data()), static_cast<std::streamsize>(chunk_.size()));
    const auto length = static_cast<std::size_t>(input_.gcount());
    if (input_.bad()) throw std::runtime_error("Cannot read the encrypted file");
    if (length < 16) throw FormatError("Truncated age payload (missing final chunk)");
    bool last = length < encrypted_chunk;
    if (last && length == 16 && counter_ != 0) throw FormatError("Invalid empty final age chunk");
    const auto chunk = std::span(chunk_).first(length);
    auto opened = crypto::chacha20poly1305_open(key_, stream_nonce(counter_, last), chunk);
    if (!opened && !last) {
        // A full-size chunk may also be the final one (reference behaviour).
        opened = crypto::chacha20poly1305_open(key_, stream_nonce(counter_, true), chunk);
        last = opened.has_value();
    }
    if (!opened) throw FormatError("age payload authentication failed (damaged or truncated file)");
    ++counter_;
    wipe(plain_);
    plain_ = std::move(*opened);
    position_ = 0;
    last_seen_ = last;
    return true;
}

std::size_t Decryptor::read(std::span<std::uint8_t> output) {
    std::size_t written = 0;
    while (written < output.size()) {
        if (position_ == plain_.size()) {
            if (!next_chunk()) break;
            continue;
        }
        const auto count = (std::min)(output.size() - written, plain_.size() - position_);
        std::copy_n(plain_.begin() + static_cast<std::ptrdiff_t>(position_), count, output.begin() + static_cast<std::ptrdiff_t>(written));
        position_ += count;
        written += count;
    }
    return written;
}

void encrypt(std::istream& input, std::ostream& output, std::span<Recipient* const> recipients) {
    Encryptor encryptor(output, recipients);
    std::vector<std::uint8_t> buffer(chunk_size);
    for (;;) {
        input.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(buffer.size()));
        const auto count = static_cast<std::size_t>(input.gcount());
        if (input.bad()) throw std::runtime_error("Cannot read the input file");
        if (count) encryptor.write(std::span(buffer).first(count));
        if (count < buffer.size()) break;
    }
    wipe(buffer);
    encryptor.finish();
}

void decrypt(std::istream& input, std::ostream& output, std::span<Identity* const> identities) {
    Decryptor decryptor(input, identities);
    std::vector<std::uint8_t> buffer(chunk_size);
    for (;;) {
        const auto count = decryptor.read(buffer);
        if (!count) break;
        output.write(reinterpret_cast<const char*>(buffer.data()), static_cast<std::streamsize>(count));
        if (!output) throw std::runtime_error("Cannot write the decrypted file");
    }
    wipe(buffer);
    if (!decryptor.finished()) throw FormatError("Truncated age payload");
}
}
