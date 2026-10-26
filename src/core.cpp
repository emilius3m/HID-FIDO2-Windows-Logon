#include "hidfido/core.hpp"
#include "hidfido/core_detail.hpp"

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
#include <limits>
#include <sstream>
#include <stdexcept>

namespace hidfido {
namespace {
constexpr std::size_t max_random_size = 1024 * 1024;
constexpr std::size_t max_credential_id_size = 1023;
constexpr std::size_t max_authenticator_data_size = 4096;
constexpr std::size_t fixed_authenticator_data_size = 37;
constexpr std::uint8_t flag_up = 0x01;
constexpr std::uint8_t flag_uv = 0x04;
constexpr std::uint8_t flag_be = 0x08;
constexpr std::uint8_t flag_bs = 0x10;
constexpr std::uint8_t flag_at = 0x40;
constexpr std::uint8_t flag_ed = 0x80;
constexpr std::uint8_t flag_reserved = 0x22;
constexpr std::string_view base64_alphabet =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

[[noreturn]] void invalid(std::string_view message) {
    throw std::runtime_error(std::string(message));
}

void check_cng(NTSTATUS status, const char* operation) {
    if (status < 0) {
        std::ostringstream message;
        message << operation << " failed (NTSTATUS 0x" << std::hex
                << static_cast<unsigned long>(status) << ')';
        throw std::runtime_error(message.str());
    }
}

class Algorithm {
public:
    explicit Algorithm(LPCWSTR name) {
        check_cng(BCryptOpenAlgorithmProvider(&value_, name,
                                               MS_PRIMITIVE_PROVIDER, 0),
                  "BCryptOpenAlgorithmProvider");
    }
    ~Algorithm() { if (value_) BCryptCloseAlgorithmProvider(value_, 0); }
    Algorithm(const Algorithm&) = delete;
    Algorithm& operator=(const Algorithm&) = delete;
    BCRYPT_ALG_HANDLE get() const noexcept { return value_; }
private:
    BCRYPT_ALG_HANDLE value_{};
};

class Key {
public:
    Key(BCRYPT_ALG_HANDLE algorithm, const Credential& credential) {
        // CNG's header has native ULONG fields; the coordinates are big-endian.
        std::array<std::uint8_t, sizeof(BCRYPT_ECCKEY_BLOB) + 64> blob{};
        const BCRYPT_ECCKEY_BLOB header{BCRYPT_ECDSA_PUBLIC_P256_MAGIC, 32};
        std::memcpy(blob.data(), &header, sizeof(header));
        std::copy(credential.x.begin(), credential.x.end(),
                  blob.begin() + sizeof(header));
        std::copy(credential.y.begin(), credential.y.end(),
                  blob.begin() + sizeof(header) + 32);
        // Never set BCRYPT_NO_KEY_VALIDATION: enrollment must reject bad points.
        check_cng(BCryptImportKeyPair(algorithm, nullptr, BCRYPT_ECCPUBLIC_BLOB,
                                      &value_, blob.data(),
                                      static_cast<ULONG>(blob.size()), 0),
                  "BCryptImportKeyPair");
    }
    ~Key() { if (value_) BCryptDestroyKey(value_); }
    Key(const Key&) = delete;
    Key& operator=(const Key&) = delete;
    BCRYPT_KEY_HANDLE get() const noexcept { return value_; }
private:
    BCRYPT_KEY_HANDLE value_{};
};

std::span<const std::uint8_t> as_bytes(std::string_view value) {
    return {reinterpret_cast<const std::uint8_t*>(value.data()), value.size()};
}

std::uint32_t counter(std::span<const std::uint8_t> data) {
    return (static_cast<std::uint32_t>(data[33]) << 24) |
           (static_cast<std::uint32_t>(data[34]) << 16) |
           (static_cast<std::uint32_t>(data[35]) << 8) |
           static_cast<std::uint32_t>(data[36]);
}

void validate_authenticator_data(std::span<const std::uint8_t> data,
                                 bool registration, bool extensions = false) {
    if (data.size() < fixed_authenticator_data_size ||
        data.size() > max_authenticator_data_size) {
        invalid("Invalid authenticator data length");
    }
    const auto expected_rp_hash = sha256(as_bytes(rp_id));
    if (!std::equal(expected_rp_hash.begin(), expected_rp_hash.end(), data.begin())) {
        invalid("RP ID hash mismatch");
    }
    const auto flags = data[32];
    if ((flags & flag_up) == 0) invalid("User presence (UP) is required");
    if ((flags & flag_uv) == 0) invalid("User verification (UV) is required");
    if (flags & flag_reserved) invalid("Invalid reserved authenticator flags");
    if (flags & (flag_be | flag_bs)) {
        invalid("Backup eligible or backed up credentials are outside prototype policy");
    }
    if (extensions) {
        if ((flags & flag_ed) == 0) invalid("Authenticator extensions (ED) are required");
    } else if (flags & flag_ed) {
        invalid("Authenticator extensions (ED) are not supported");
    }
    if (registration) {
        if ((flags & flag_at) == 0) invalid("Registration requires attested credential data (AT)");
    } else {
        if (flags & flag_at) invalid("Assertion must not contain attested credential data (AT)");
        if (!extensions && data.size() != fixed_authenticator_data_size) {
            invalid("Unexpected trailing assertion authenticator data");
        }
        if (extensions && data.size() == fixed_authenticator_data_size) {
            invalid("Missing assertion authenticator extension data");
        }
    }
}

// Deliberately small CBOR reader: definite lengths, canonical integer/length
// encodings, integer map labels and byte strings are the only accepted subset.
class CborReader {
public:
    explicit CborReader(std::span<const std::uint8_t> data) : data_(data) {}

    std::uint64_t map_length() {
        const auto head = read_head();
        if (head.major != 5) invalid("COSE key must be a CBOR map");
        return head.value;
    }

    std::int64_t integer() {
        const auto head = read_head();
        if ((head.major != 0 && head.major != 1) ||
            head.value > static_cast<std::uint64_t>((std::numeric_limits<std::int64_t>::max)())) {
            invalid("Invalid CBOR integer in COSE key");
        }
        const auto value = static_cast<std::int64_t>(head.value);
        return head.major == 0 ? value : -1 - value;
    }

    Hash coordinate() {
        const auto head = read_head();
        if (head.major != 2 || head.value != 32) {
            invalid("COSE coordinates must be 32-byte byte strings");
        }
        const auto value = take(32);
        Hash result{};
        std::copy(value.begin(), value.end(), result.begin());
        return result;
    }

    bool finished() const noexcept { return position_ == data_.size(); }
    std::size_t position() const noexcept { return position_; }

private:
    struct Head { std::uint8_t major; std::uint64_t value; };
    std::span<const std::uint8_t> take(std::size_t count) {
        if (count > data_.size() - position_) invalid("Truncated CBOR in COSE key");
        const auto result = data_.subspan(position_, count);
        position_ += count;
        return result;
    }

    Head read_head() {
        const auto initial = take(1)[0];
        const auto major = static_cast<std::uint8_t>(initial >> 5);
        const auto additional = static_cast<std::uint8_t>(initial & 0x1f);
        if (additional < 24) return {major, additional};
        if (additional > 27) invalid("Indefinite or reserved CBOR encoding is not supported");
        const std::size_t size = std::size_t{1} << (additional - 24);
        const auto encoded = take(size);
        std::uint64_t value{};
        for (const auto byte : encoded) value = (value << 8) | byte;
        const std::uint64_t minimum = size == 1 ? 24 :
            size == 2 ? 256 : size == 4 ? 65536 : std::uint64_t{1} << 32;
        if (value < minimum) invalid("Non-minimal CBOR encoding in COSE key");
        return {major, value};
    }

    std::span<const std::uint8_t> data_;
    std::size_t position_{};
};

std::array<std::uint8_t, 64> der_to_p1363(std::span<const std::uint8_t> der) {
    // A P-256 signature needs only short-form lengths and is at most 72 bytes.
    if (der.size() < 8 || der.size() > 72 || der[0] != 0x30 ||
        static_cast<std::size_t>(der[1]) != der.size() - 2) {
        invalid("Malformed DER ES256 signature sequence");
    }
    constexpr Hash order{
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
        0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51};
    std::array<std::uint8_t, 64> result{};
    std::size_t position = 2;
    for (std::size_t part = 0; part < 2; ++part) {
        if (der.size() - position < 2 || der[position++] != 0x02) {
            invalid("Malformed DER ES256 signature integer");
        }
        const auto length = static_cast<std::size_t>(der[position++]);
        if (length == 0 || length > 33 || length > der.size() - position) {
            invalid("Invalid DER ES256 integer length");
        }
        auto value = der.subspan(position, length);
        position += length;
        if (value[0] & 0x80) invalid("Negative DER ES256 integer");
        if (value[0] == 0 && value.size() > 1) {
            if ((value[1] & 0x80) == 0) invalid("Non-minimal DER ES256 integer");
            value = value.subspan(1);
        }
        if (value.size() > 32) invalid("DER ES256 integer exceeds P-256 size");
        auto scalar = std::span<std::uint8_t>(result).subspan(part * 32, 32);
        std::copy(value.begin(), value.end(), scalar.end() - value.size());
        if (std::all_of(scalar.begin(), scalar.end(), [](auto byte) { return byte == 0; }) ||
            !std::lexicographical_compare(scalar.begin(), scalar.end(),
                                          order.begin(), order.end())) {
            invalid("DER ES256 scalar is outside P-256 range");
        }
    }
    if (position != der.size()) invalid("Trailing DER ES256 signature data");
    return result;
}

void validate_local_assertion_client_data(std::string_view data) {
    // No untrusted JSON is accepted: the public verifier consumes precisely the
    // canonical JSON our builder creates for the current synchronous ceremony.
    constexpr std::string_view prefix = "{\"type\":\"webauthn.get\",\"challenge\":\"";
    const std::string suffix = std::string("\",\"origin\":\"") + origin + "\",\"crossOrigin\":false}";
    constexpr std::size_t challenge_characters = 43; // 32 bytes, unpadded base64url.
    if (data.size() != prefix.size() + challenge_characters + suffix.size() ||
        !data.starts_with(prefix) || !data.ends_with(suffix)) {
        invalid("Assertion client data must be locally constructed webauthn.get JSON");
    }
    const auto challenge = data.substr(prefix.size(), challenge_characters);
    for (const char character : challenge) {
        if (base64_alphabet.find(character) == std::string_view::npos) {
            invalid("Invalid challenge encoding in local client data");
        }
    }
    if ((base64_alphabet.find(challenge.back()) & 0x03) != 0) {
        invalid("Non-canonical challenge encoding in local client data");
    }
}
} // namespace

Bytes random_bytes(std::size_t count) {
    if (count > max_random_size) invalid("Random byte request exceeds prototype limit");
    Bytes result(count);
    if (!result.empty()) {
        check_cng(BCryptGenRandom(nullptr, result.data(), static_cast<ULONG>(result.size()),
                                  BCRYPT_USE_SYSTEM_PREFERRED_RNG), "BCryptGenRandom");
    }
    return result;
}

Hash sha256(std::span<const std::uint8_t> bytes) {
    if (bytes.size() > (std::numeric_limits<ULONG>::max)()) {
        invalid("SHA-256 input exceeds Windows API limit");
    }
    Algorithm algorithm(BCRYPT_SHA256_ALGORITHM);
    Hash result{};
    check_cng(BCryptHash(algorithm.get(), nullptr, 0,
                         const_cast<PUCHAR>(bytes.data()), static_cast<ULONG>(bytes.size()),
                         result.data(), static_cast<ULONG>(result.size())), "BCryptHash");
    return result;
}

std::string base64url(std::span<const std::uint8_t> bytes) {
    if (bytes.size() > max_random_size) invalid("Base64url input exceeds prototype limit");
    std::string result;
    result.reserve((bytes.size() * 4 + 2) / 3);
    std::size_t position{};
    while (bytes.size() - position >= 3) {
        const auto value = (static_cast<std::uint32_t>(bytes[position]) << 16) |
                           (static_cast<std::uint32_t>(bytes[position + 1]) << 8) |
                           static_cast<std::uint32_t>(bytes[position + 2]);
        result.push_back(base64_alphabet[(value >> 18) & 63]);
        result.push_back(base64_alphabet[(value >> 12) & 63]);
        result.push_back(base64_alphabet[(value >> 6) & 63]);
        result.push_back(base64_alphabet[value & 63]);
        position += 3;
    }
    if (position != bytes.size()) {
        const auto first = bytes[position++];
        result.push_back(base64_alphabet[first >> 2]);
        if (position == bytes.size()) {
            result.push_back(base64_alphabet[(first & 3) << 4]);
        } else {
            const auto second = bytes[position];
            result.push_back(base64_alphabet[((first & 3) << 4) | (second >> 4)]);
            result.push_back(base64_alphabet[(second & 15) << 2]);
        }
    }
    return result;
}

std::string make_client_data(std::string_view type, std::span<const std::uint8_t> challenge) {
    if (type != "webauthn.create" && type != "webauthn.get") {
        invalid("Unsupported client data ceremony type");
    }
    if (challenge.size() != 32) invalid("Client data requires a 32-byte challenge");
    return std::string("{\"type\":\"") + std::string(type) + "\",\"challenge\":\"" +
           base64url(challenge) + "\",\"origin\":\"" + origin + "\",\"crossOrigin\":false}";
}

namespace {
Credential parse_registration_impl(std::span<const std::uint8_t> authenticator_data,
                              std::span<const std::uint8_t> returned_id,
                              bool extensions, std::size_t* extension_offset) {
    validate_authenticator_data(authenticator_data, true, extensions);
    if (!extensions && (returned_id.empty() || returned_id.size() > max_credential_id_size)) {
        invalid("Invalid returned credential ID length");
    }
    if (authenticator_data.size() < 55) invalid("Truncated attested credential data");
    const auto id_size = (static_cast<std::size_t>(authenticator_data[53]) << 8) |
                         static_cast<std::size_t>(authenticator_data[54]);
    if (id_size == 0 || id_size > max_credential_id_size ||
        id_size > authenticator_data.size() - 55) {
        invalid("Invalid attested credential ID length");
    }
    const auto id = authenticator_data.subspan(55, id_size);
    if (!extensions && (id.size() != returned_id.size() ||
        !std::equal(id.begin(), id.end(), returned_id.begin()))) {
        invalid("Returned credential ID mismatch");
    }

    Credential credential;
    credential.id.assign(id.begin(), id.end());
    std::copy_n(authenticator_data.begin() + 37, credential.aaguid.size(), credential.aaguid.begin());
    credential.sign_count = counter(authenticator_data);
    CborReader reader(authenticator_data.subspan(55 + id_size));
    if (reader.map_length() != 5) invalid("COSE key must contain exactly five public ES256 fields");
    constexpr std::array<std::int64_t, 5> canonical_labels{1, 3, -1, -2, -3};
    unsigned seen{};
    for (unsigned field = 0; field < 5; ++field) {
        const auto label = reader.integer();
        unsigned bit{};
        switch (label) {
        case 1: bit = 1; break;
        case 3: bit = 2; break;
        case -1: bit = 4; break;
        case -2: bit = 8; break;
        case -3: bit = 16; break;
        default: invalid("Unknown or private COSE key field");
        }
        if (seen & bit) invalid("Duplicate COSE key field");
        if (label != canonical_labels[field]) invalid("Non-canonical COSE key map order");
        seen |= bit;
        switch (label) {
        case 1: if (reader.integer() != 2) invalid("COSE key type must be EC2"); break;
        case 3: if (reader.integer() != -7) invalid("COSE algorithm must be ES256"); break;
        case -1: if (reader.integer() != 1) invalid("COSE curve must be P-256"); break;
        case -2: credential.x = reader.coordinate(); break;
        case -3: credential.y = reader.coordinate(); break;
        default: invalid("Unsupported COSE key field");
        }
    }
    if (seen != 31 || (!extensions && !reader.finished())) {
        invalid("Unexpected trailing COSE key data");
    }
    if (extension_offset) *extension_offset = 55 + id_size + reader.position();
    Algorithm algorithm(BCRYPT_ECDSA_P256_ALGORITHM);
    const Key key(algorithm.get(), credential); // Validate the public point before enrollment.
    return credential;
}

std::uint32_t verify_assertion_impl(const Credential& credential,
                               std::span<const std::uint8_t> authenticator_data,
                               std::span<const std::uint8_t> signature,
                               std::string_view expected_client_data, bool extensions) {
    if (credential.id.empty() || credential.id.size() > max_credential_id_size) {
        invalid("Invalid enrolled credential ID length");
    }
    validate_local_assertion_client_data(expected_client_data);
    validate_authenticator_data(authenticator_data, false, extensions);
    const auto raw_signature = der_to_p1363(signature);
    const auto client_hash = sha256(as_bytes(expected_client_data));
    Bytes signed_data(authenticator_data.begin(), authenticator_data.end());
    signed_data.insert(signed_data.end(), client_hash.begin(), client_hash.end());
    const auto digest = sha256(signed_data);
    Algorithm algorithm(BCRYPT_ECDSA_P256_ALGORITHM);
    const Key key(algorithm.get(), credential);
    const auto status = BCryptVerifySignature(key.get(), nullptr,
                                               const_cast<PUCHAR>(digest.data()),
                                               static_cast<ULONG>(digest.size()),
                                               const_cast<PUCHAR>(raw_signature.data()),
                                               static_cast<ULONG>(raw_signature.size()), 0);
    if (status < 0) invalid("ES256 assertion signature verification failed");
    const auto new_counter = counter(authenticator_data);
    // All-zero counters are explicitly supported by WebAuthn; any established
    // nonzero counter must move strictly forward in this serialized prototype.
    if ((credential.sign_count != 0 || new_counter != 0) &&
        new_counter <= credential.sign_count) {
        invalid("Signature counter did not increase; possible rollback or clone");
    }
    return new_counter;
}
} // namespace

Credential parse_registration(std::span<const std::uint8_t> authenticator_data,
                              std::span<const std::uint8_t> returned_id) {
    return parse_registration_impl(authenticator_data, returned_id, false, nullptr);
}

std::uint32_t verify_assertion(const Credential& credential,
                               std::span<const std::uint8_t> authenticator_data,
                               std::span<const std::uint8_t> signature,
                               std::string_view expected_client_data) {
    return verify_assertion_impl(credential, authenticator_data, signature,
                                 expected_client_data, false);
}

namespace detail {
ExtensionRegistration parse_extension_registration(
    std::span<const std::uint8_t> authenticator_data) {
    ExtensionRegistration result;
    result.credential = parse_registration_impl(authenticator_data, {}, true,
                                                 &result.extension_offset);
    return result;
}

std::uint32_t verify_extension_assertion_signature(
    const Credential& credential,
    std::span<const std::uint8_t> authenticator_data,
    std::span<const std::uint8_t> signature,
    std::string_view expected_client_data) {
    return verify_assertion_impl(credential, authenticator_data, signature,
                                 expected_client_data, true);
}
} // namespace detail
} // namespace hidfido
