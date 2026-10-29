#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <iosfwd>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

// Portable implementation of the age v1 file format
// (https://age-encryption.org/v1, C2SP age) with two recipient types:
//
//  - X25519 ("age1..." / "AGE-SECRET-KEY-1..."): an asymmetric recovery key
//    that can be printed on paper and used with any standard age client.
//  - age-encryption.org/fido2prf ("AGE-PLUGIN-FIDO2PRF-1..."): the symmetric
//    FIDO2 PRF/hmac-secret recipient of typage and age-plugin-fido2prf. Both
//    wrapping and unwrapping require the security key, its PIN and a touch.
//
// This module has no Windows dependency and performs no device I/O: the PRF
// evaluation is injected by the caller (WebAuthn on Windows, a fake in tests).
// Scrypt passphrase stanzas, ASCII armor and plugin protocols are not supported.
namespace hidfido::age {
using Bytes = std::vector<std::uint8_t>;
using FileKey = std::array<std::uint8_t, 16>;

class FormatError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};
// No identity unwrapped the file key. Distinct from malformed/tampered input.
class NoIdentityMatched : public std::runtime_error {
public:
    NoIdentityMatched() : std::runtime_error("No identity matched any recipient stanza") {}
};

// Overwrites memory in a way the optimizer must keep.
void wipe(std::span<std::uint8_t> bytes) noexcept;
template<std::size_t N> void wipe(std::array<std::uint8_t, N>& value) noexcept { wipe(std::span<std::uint8_t>(value)); }
inline void wipe(Bytes& value) noexcept { wipe(std::span<std::uint8_t>(value)); }
// Cryptographically secure random bytes from the operating system.
void random_bytes(std::span<std::uint8_t> output);

namespace crypto {
using Hash = std::array<std::uint8_t, 32>;
Hash sha256(std::span<const std::uint8_t> data);
Hash hmac_sha256(std::span<const std::uint8_t> key, std::span<const std::uint8_t> data);
Hash hkdf_extract(std::span<const std::uint8_t> salt, std::span<const std::uint8_t> ikm);
Bytes hkdf_sha256(std::span<const std::uint8_t> ikm, std::span<const std::uint8_t> salt,
                  std::span<const std::uint8_t> info, std::size_t length);
// RFC 8439 AEAD. open() returns nullopt on authentication failure.
Bytes chacha20poly1305_seal(std::span<const std::uint8_t, 32> key, std::span<const std::uint8_t, 12> nonce,
                            std::span<const std::uint8_t> plaintext, std::span<const std::uint8_t> aad = {});
std::optional<Bytes> chacha20poly1305_open(std::span<const std::uint8_t, 32> key,
                                           std::span<const std::uint8_t, 12> nonce,
                                           std::span<const std::uint8_t> ciphertext,
                                           std::span<const std::uint8_t> aad = {});
// RFC 7748 X25519 (clamps the scalar). Constant time.
std::array<std::uint8_t, 32> x25519(std::span<const std::uint8_t, 32> scalar, std::span<const std::uint8_t, 32> point);
std::array<std::uint8_t, 32> x25519_base(std::span<const std::uint8_t, 32> scalar);
bool equal_constant_time(std::span<const std::uint8_t> left, std::span<const std::uint8_t> right) noexcept;
}

namespace encoding {
// Canonical unpadded standard base64 used by age stanzas.
std::string base64_encode(std::span<const std::uint8_t> data);
Bytes base64_decode(std::string_view text);
// BIP 173 Bech32 without the 90-character limit, as used by age. Encodes in
// lower case unless upper_case; decoding rejects mixed case.
std::string bech32_encode(std::string_view hrp, std::span<const std::uint8_t> data, bool upper_case);
struct Bech32 { std::string hrp; Bytes data; };
Bech32 bech32_decode(std::string_view text);
}

struct Stanza {
    std::string type;
    std::vector<std::string> args;
    Bytes body;
};

class Recipient {
public:
    virtual ~Recipient() = default;
    virtual std::vector<Stanza> wrap(const FileKey& file_key) = 0;
};

class Identity {
public:
    virtual ~Identity() = default;
    // Returns nullopt when no stanza belongs to this identity. Throws for a
    // malformed stanza of this identity's type.
    virtual std::optional<FileKey> unwrap(std::span<const Stanza> stanzas) = 0;
};

// ---- X25519 -----------------------------------------------------------------
class X25519Recipient final : public Recipient {
public:
    explicit X25519Recipient(std::span<const std::uint8_t, 32> public_key);
    static X25519Recipient parse(std::string_view text);  // "age1..."
    std::string encode() const;
    std::vector<Stanza> wrap(const FileKey& file_key) override;
    const std::array<std::uint8_t, 32>& public_key() const noexcept { return public_key_; }
private:
    std::array<std::uint8_t, 32> public_key_{};
};

class X25519Identity final : public Identity {
public:
    explicit X25519Identity(std::span<const std::uint8_t, 32> secret_key);
    ~X25519Identity() override;
    X25519Identity(const X25519Identity&) = delete;
    X25519Identity& operator=(const X25519Identity&) = delete;
    X25519Identity(X25519Identity&& other) noexcept;
    X25519Identity& operator=(X25519Identity&&) = delete;
    static X25519Identity generate();
    static X25519Identity parse(std::string_view text);  // "AGE-SECRET-KEY-1..."
    std::string encode() const;
    X25519Recipient recipient() const;
    std::optional<FileKey> unwrap(std::span<const Stanza> stanzas) override;
private:
    std::array<std::uint8_t, 32> secret_key_{};
    std::array<std::uint8_t, 32> public_key_{};
};

// ---- FIDO2 PRF (age-encryption.org/fido2prf) ----------------------------------
inline constexpr std::string_view fido2prf_label = "age-encryption.org/fido2prf";

// Public, non-secret data encoded in "AGE-PLUGIN-FIDO2PRF-1...": it names a
// credential, but using it still requires the key, the PIN and a touch.
struct Fido2PrfCredential {
    Bytes credential_id;
    std::string rp_id;
    std::vector<std::string> transports;
    std::string encode() const;
    static Fido2PrfCredential parse(std::string_view text);
    bool operator==(const Fido2PrfCredential&) const = default;
};

// The two 32-byte WebAuthn PRF results (first || second) for the given PRF
// inputs. `allowed` lists acceptable credentials (same RP ID); `used` returns
// the index of the credential the authenticator actually used.
struct PrfRequest {
    std::span<const Fido2PrfCredential> allowed;
    std::span<const std::uint8_t> first_input;
    std::span<const std::uint8_t> second_input;
};
struct PrfResult {
    std::array<std::uint8_t, 64> output{};
    std::size_t used{};
};
using PrfFunction = std::function<PrfResult(const PrfRequest&)>;

// WebAuthn PRF inputs of the fido2prf stanza for a 16-byte nonce.
Bytes fido2prf_input(std::span<const std::uint8_t, 16> nonce, std::uint8_t which);
// The hmac-secret salt an authenticator receives for a PRF input:
// SHA-256("WebAuthn PRF" || 0x00 || input). Exposed for tests and fakes.
crypto::Hash webauthn_prf_salt(std::span<const std::uint8_t> input);

class Fido2PrfRecipient final : public Recipient {
public:
    Fido2PrfRecipient(Fido2PrfCredential credential, PrfFunction prf);
    std::vector<Stanza> wrap(const FileKey& file_key) override;
private:
    Fido2PrfCredential credential_;
    PrfFunction prf_;
};

// One identity for a set of credentials sharing an RP ID: every fido2prf
// stanza costs one assertion in which any of the credentials may answer.
class Fido2PrfIdentity final : public Identity {
public:
    Fido2PrfIdentity(std::vector<Fido2PrfCredential> credentials, PrfFunction prf);
    std::optional<FileKey> unwrap(std::span<const Stanza> stanzas) override;
private:
    std::vector<Fido2PrfCredential> credentials_;
    PrfFunction prf_;
};

// ---- File format --------------------------------------------------------------
inline constexpr std::size_t chunk_size = 64 * 1024;

// Writes the header and streams the payload. finish() must be called; an
// unfinished encryptor leaves an invalid (truncated) file behind.
class Encryptor {
public:
    Encryptor(std::ostream& output, std::span<Recipient* const> recipients);
    ~Encryptor();
    Encryptor(const Encryptor&) = delete;
    Encryptor& operator=(const Encryptor&) = delete;
    void write(std::span<const std::uint8_t> data);
    void finish();
private:
    void flush_chunk(bool last);
    std::ostream& output_;
    std::array<std::uint8_t, 32> key_{};
    std::uint64_t counter_{};
    Bytes buffer_;
    bool finished_{};
};

// Parses and authenticates the header, then returns plaintext only from
// authenticated chunks. finished() is true once the authenticated final chunk
// has been read and the input ends right after it; only then is the plaintext
// complete. Truncation, reordering or trailing data throw FormatError, possibly
// after earlier authenticated chunks were returned.
class Decryptor {
public:
    Decryptor(std::istream& input, std::span<Identity* const> identities);
    ~Decryptor();
    Decryptor(const Decryptor&) = delete;
    Decryptor& operator=(const Decryptor&) = delete;
    // Returns 0 only at the authenticated end of the payload.
    std::size_t read(std::span<std::uint8_t> output);
    bool finished() const noexcept { return finished_; }
    const std::vector<Stanza>& stanzas() const noexcept { return stanzas_; }
private:
    bool next_chunk();
    std::istream& input_;
    std::vector<Stanza> stanzas_;
    std::array<std::uint8_t, 32> key_{};
    std::uint64_t counter_{};
    Bytes plain_;
    std::size_t position_{};
    Bytes chunk_;
    bool last_seen_{};
    bool finished_{};
};

// Header serialization, exposed for tests. The MAC covers everything up to
// and including "---".
std::string serialize_header(std::span<const Stanza> stanzas, const FileKey& file_key);
std::vector<Stanza> parse_header(std::istream& input, std::string& mac_input, crypto::Hash& mac);

// Convenience wrappers for whole streams.
void encrypt(std::istream& input, std::ostream& output, std::span<Recipient* const> recipients);
void decrypt(std::istream& input, std::ostream& output, std::span<Identity* const> identities);

// ---- Folder archives ----------------------------------------------------------
// Folders are stored as a POSIX pax/ustar archive inside one age file, so the
// whole folder costs one touch per security key and stays readable with
// `age -d file.tar.age | tar -x`. Only directories and regular files are
// written or accepted; links, devices and unsafe paths are rejected.
using Sink = std::function<void(std::span<const std::uint8_t>)>;
using Source = std::function<std::size_t(std::span<std::uint8_t>)>;  // 0 = end

struct ArchiveStats { std::uint64_t files{}; std::uint64_t directories{}; std::uint64_t bytes{}; };
// Archives the contents of `folder` under its own name as top-level entry.
ArchiveStats write_tar(const std::filesystem::path& folder, const Sink& sink);
// Extracts into `destination`, which must already exist and be empty. Every
// entry path is validated before anything is created. The caller must still
// confirm the authenticated end of the decrypted stream before trusting it.
ArchiveStats extract_tar(const Source& source, const std::filesystem::path& destination);
// Validates and normalizes an archive member path to safe relative segments.
std::vector<std::string> safe_archive_path(std::string_view path);
}
