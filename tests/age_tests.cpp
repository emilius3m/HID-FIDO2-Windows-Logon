// Portable tests for the age implementation. No security key, WebAuthn or
// Windows API is used: FIDO2 PRF evaluation is replaced by a software
// authenticator computing HMAC-SHA-256(credRandom, hmac-secret salt).
// Optional argument: a directory of C2SP age testkit vectors (tests/age-testkit).
#include "hidfido/age.hpp"
#include "hidfido/age_files.hpp"

#include <algorithm>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <string>

namespace {
using namespace hidfido::age;
namespace fs = std::filesystem;

void require(bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error(message);
}

template<class Action>
void rejects(Action&& action, const std::string& message) {
    try { action(); }
    catch (const std::exception&) { return; }
    throw std::runtime_error("Accepted invalid input: " + message);
}

Bytes hex(std::string_view text) {
    auto nibble = [](char c) -> std::uint8_t {
        if (c >= '0' && c <= '9') return static_cast<std::uint8_t>(c - '0');
        if (c >= 'a' && c <= 'f') return static_cast<std::uint8_t>(c - 'a' + 10);
        throw std::runtime_error("Invalid hex digit in test vector");
    };
    Bytes result;
    for (std::size_t i = 0; i + 1 < text.size(); i += 2) {
        result.push_back(static_cast<std::uint8_t>((nibble(text[i]) << 4) | nibble(text[i + 1])));
    }
    return result;
}

std::string to_hex(std::span<const std::uint8_t> data) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string result;
    for (const auto byte : data) { result += digits[byte >> 4]; result += digits[byte & 15]; }
    return result;
}

std::span<const std::uint8_t> bytes(std::string_view text) {
    return {reinterpret_cast<const std::uint8_t*>(text.data()), text.size()};
}

std::string text(std::span<const std::uint8_t> data) { return {data.begin(), data.end()}; }

// ---- Primitives -------------------------------------------------------------
void primitive_vectors() {
    require(to_hex(crypto::sha256({})) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "SHA-256 empty");
    require(to_hex(crypto::sha256(bytes("abc"))) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "SHA-256 abc");
    require(to_hex(crypto::sha256(bytes("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))) ==
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1", "SHA-256 two blocks");
    // RFC 4231 test cases 1 and 6 (key longer than the block).
    require(to_hex(crypto::hmac_sha256(Bytes(20, 0x0b), bytes("Hi There"))) ==
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7", "HMAC case 1");
    require(to_hex(crypto::hmac_sha256(Bytes(131, 0xaa), bytes("Test Using Larger Than Block-Size Key - Hash Key First"))) ==
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54", "HMAC case 6");
    // RFC 5869 A.1 and A.3.
    require(to_hex(crypto::hkdf_sha256(Bytes(22, 0x0b), hex("000102030405060708090a0b0c"), hex("f0f1f2f3f4f5f6f7f8f9"), 42)) ==
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865", "HKDF A.1");
    require(to_hex(crypto::hkdf_sha256(Bytes(22, 0x0b), {}, {}, 42)) ==
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8", "HKDF A.3");

    // RFC 8439 2.8.2 AEAD vector.
    const auto key = hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    const auto nonce = hex("070000004041424344454647");
    const auto aad = hex("50515253c0c1c2c3c4c5c6c7");
    const std::string plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    const auto sealed = crypto::chacha20poly1305_seal(std::span<const std::uint8_t, 32>(key.data(), 32),
                                                     std::span<const std::uint8_t, 12>(nonce.data(), 12), bytes(plaintext), aad);
    require(to_hex(sealed) ==
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116"
        "1ae10b594f09e26a7e902ecbd0600691", "ChaCha20-Poly1305 RFC 8439");
    const auto opened = crypto::chacha20poly1305_open(std::span<const std::uint8_t, 32>(key.data(), 32),
                                                     std::span<const std::uint8_t, 12>(nonce.data(), 12), sealed, aad);
    require(opened && text(*opened) == plaintext, "ChaCha20-Poly1305 open");
    for (std::size_t i = 0; i < sealed.size(); i += 17) {
        auto damaged = sealed;
        damaged[i] ^= 1;
        require(!crypto::chacha20poly1305_open(std::span<const std::uint8_t, 32>(key.data(), 32),
                                               std::span<const std::uint8_t, 12>(nonce.data(), 12), damaged, aad), "AEAD tamper");
    }

    // RFC 7748 5.2 and 6.1.
    auto scalar = hex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
    auto point = hex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
    require(to_hex(crypto::x25519(std::span<const std::uint8_t, 32>(scalar.data(), 32), std::span<const std::uint8_t, 32>(point.data(), 32))) ==
            "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552", "X25519 5.2 #1");
    scalar = hex("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d");
    point = hex("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493");
    require(to_hex(crypto::x25519(std::span<const std::uint8_t, 32>(scalar.data(), 32), std::span<const std::uint8_t, 32>(point.data(), 32))) ==
            "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957", "X25519 5.2 #2");
    std::array<std::uint8_t, 32> k{9}, u{9};
    for (int i = 0; i < 1000; ++i) {
        const auto next = crypto::x25519(k, u);
        u = k;
        k = next;
        if (i == 0) require(to_hex(k) == "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079", "X25519 iterated 1");
    }
    require(to_hex(k) == "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51", "X25519 iterated 1000");
    const auto alice = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    const auto bob = hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    const auto alice_public = crypto::x25519_base(std::span<const std::uint8_t, 32>(alice.data(), 32));
    const auto bob_public = crypto::x25519_base(std::span<const std::uint8_t, 32>(bob.data(), 32));
    require(to_hex(alice_public) == "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a", "X25519 Alice public");
    require(to_hex(crypto::x25519(std::span<const std::uint8_t, 32>(alice.data(), 32), bob_public)) ==
            "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742", "X25519 shared secret");
}

void encoding_vectors() {
    using namespace encoding;
    require(base64_encode(bytes("f")) == "Zg" && base64_encode(bytes("fo")) == "Zm8" && base64_encode(bytes("foo")) == "Zm9v", "base64");
    require(text(base64_decode("Zm9vYg")) == "foob", "base64 decode");
    rejects([] { base64_decode("Zh"); }, "non-canonical base64");
    rejects([] { base64_decode("Zg=="); }, "padded base64");
    rejects([] { base64_decode("Z"); }, "base64 length");
    // BIP 173 valid strings, and the age identity printed by age-keygen.
    require(bech32_decode("A12UEL5L").hrp == "a", "bech32 minimal");
    require(bech32_decode("abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw").data.size() == 20, "bech32 long data");
    rejects([] { bech32_decode("A12UEl5L"); }, "mixed-case bech32");
    rejects([] { bech32_decode("a12uel5m"); }, "bad bech32 checksum");
    const auto identity = X25519Identity::parse("AGE-SECRET-KEY-1YMTJJ5RSY39UAG7UC0F26W806NC5R333GS4JL8EULY0YFHUATMMQXNVL7L");
    require(identity.encode() == "AGE-SECRET-KEY-1YMTJJ5RSY39UAG7UC0F26W806NC5R333GS4JL8EULY0YFHUATMMQXNVL7L", "identity round trip");
    require(identity.recipient().encode() == "age1nhhhsudgcg0e6jhajg6sahylf2kvmtf0awskjczjpwp0n4f64fyqmhxhh8", "age-keygen public key");
    rejects([] { X25519Recipient::parse("AGE1NHHHSUDGCG0E6JHAJG6SAHYLF2KVMTF0AWSKJCZJPWP0N4F64FYQMHXHH8"); }, "upper-case recipient");
    rejects([] { X25519Identity::parse("age-secret-key-1ymtjj5rsy39uag7uc0f26w806nc5r333gs4jl8euly0yfhuatmmqxnvl7l"); }, "lower-case identity");
    rejects([] { X25519Identity::parse("age1nhhhsudgcg0e6jhajg6sahylf2kvmtf0awskjczjpwp0n4f64fyqmhxhh8"); }, "recipient as identity");
}

// ---- Interoperability with the reference age implementation -------------------
void decrypts_reference_age_file() {
    // `printf 'Ciao dal file cifrato con age!\n' | age -r <key> -r <other>` (age 1.1.1).
    const auto file = hex(
        "6167652d656e6372797074696f6e2e6f72672f76310a2d3e20583235353139204e64316533446446686f7864575a7830546b447154367453"
        "46543663414d3942645079316b5a4f506944510a49574b584d595044544f636c322f5577634d6958396c6c4a567575594138436361755777"
        "5766344144726b0a2d3e2058323535313920754564434530704a306d4676424e6e7939352b34517534796a47734353366c334c78386c5038"
        "553535316b0a4e47585739307137795352487a435231364768684a7059434762514a6957654f5831473367326c794975550a2d2d2d205161"
        "41442f783051586745334f6944667335344742746a61476233574d325a397a524758435441315046670a179bf1eeaadcadd59686551e8eaf"
        "9f18a5b57fbdd50f8faf533afb621de168e59c1d52ef29fc6b9deb4cd127e2011f30c8b76e4751366d7b039c7113372f73");
    auto identity = X25519Identity::parse("AGE-SECRET-KEY-1YMTJJ5RSY39UAG7UC0F26W806NC5R333GS4JL8EULY0YFHUATMMQXNVL7L");
    Identity* identities[] = {&identity};
    std::istringstream input(text(file));
    std::ostringstream output;
    decrypt(input, output, identities);
    require(output.str() == "Ciao dal file cifrato con age!\n", "reference age file");

    auto stranger = X25519Identity::generate();
    Identity* wrong[] = {&stranger};
    std::istringstream again(text(file));
    std::ostringstream ignored;
    bool no_match = false;
    try { decrypt(again, ignored, wrong); } catch (const NoIdentityMatched&) { no_match = true; }
    require(no_match && ignored.str().empty(), "wrong identity");
}

// ---- Software FIDO2 authenticator ------------------------------------------------
struct FakeAuthenticator {
    std::map<Bytes, Bytes> cred_random;  // credential ID -> CredRandomWithUV
    std::optional<Bytes> present;         // credential of the attached key
    unsigned touches{};
    PrfFunction prf() {
        return [this](const PrfRequest& request) {
            ++touches;
            for (std::size_t i = 0; i < request.allowed.size(); ++i) {
                if (!present || request.allowed[i].credential_id != *present) continue;
                const auto& secret = cred_random.at(*present);
                PrfResult result;
                const auto first = crypto::hmac_sha256(secret, webauthn_prf_salt(request.first_input));
                const auto second = crypto::hmac_sha256(secret, webauthn_prf_salt(request.second_input));
                std::copy(first.begin(), first.end(), result.output.begin());
                std::copy(second.begin(), second.end(), result.output.begin() + 32);
                result.used = i;
                return result;
            }
            throw std::runtime_error("Security key not registered for this file");
        };
    }
};

void fido2prf_vectors() {
    // Independently computed with Python (hashlib/hmac/cryptography) from the
    // typage fido2prf construction: credRandom = 00..1f, nonce = 64..73.
    const std::string identity = "AGE-PLUGIN-FIDO2PRF-1Q9VRPJXFET9UENWWELGDR5KN6N2AD47CM8DDHHXAMM07PC0ZU0JWTEH8AR5746LVAHHWLU837TELFA0K7AKKS6TY94NXJER0XGKKZEM9S93H2UMZ65VT8Q";
    const auto credential = Fido2PrfCredential::parse(identity);
    Bytes expected_id;
    for (int i = 200; i < 248; ++i) expected_id.push_back(static_cast<std::uint8_t>(i));
    require(credential.credential_id == expected_id && credential.rp_id == "hid-fido2-age" &&
            credential.transports == std::vector<std::string>{"usb"}, "fido2prf identity parse");
    require(credential.encode() == identity, "fido2prf identity encode");
    rejects([&] { Fido2PrfCredential::parse("AGE-PLUGIN-OTHER-1QQQQQQQQ"); }, "foreign plugin identity");

    FakeAuthenticator key;
    Bytes secret;
    for (int i = 0; i < 32; ++i) secret.push_back(static_cast<std::uint8_t>(i));
    key.cred_random[credential.credential_id] = secret;
    key.present = credential.credential_id;
    Fido2PrfIdentity fido({credential}, key.prf());
    const Stanza stanza{std::string(fido2prf_label), {"ZGVmZ2hpamtsbW5vcHFycw"},
                        hex("10e31255643737febcd23d6ccfea86f5e3473675cf209efd3b470cefcdac2d00")};
    const auto file_key = fido.unwrap(std::span(&stanza, 1));
    require(file_key && text(*file_key) == "YELLOW SUBMARINE", "fido2prf stanza unwrap");
    require(key.touches == 1, "one touch per stanza");

    auto bad_args = stanza;
    bad_args.args.push_back("extra");
    rejects([&] { fido.unwrap(std::span(&bad_args, 1)); }, "fido2prf extra argument");
    auto bad_nonce = stanza;
    bad_nonce.args = {"ZGVm"};
    rejects([&] { fido.unwrap(std::span(&bad_nonce, 1)); }, "fido2prf short nonce");
}

Bytes pattern(std::size_t size) {
    Bytes data(size);
    for (std::size_t i = 0; i < size; ++i) data[i] = static_cast<std::uint8_t>((i * 131 + i / 251) & 0xff);
    return data;
}

std::string encrypt_to(std::span<const std::uint8_t> plaintext, std::span<Recipient* const> recipients) {
    std::istringstream input(text(plaintext));
    std::ostringstream output;
    encrypt(input, output, recipients);
    return output.str();
}

std::string decrypt_with(const std::string& file, std::span<Identity* const> identities) {
    std::istringstream input(file);
    std::ostringstream output;
    decrypt(input, output, identities);
    return output.str();
}

void multiple_recipients() {
    // Principale and Riserva security keys plus a paper recovery key.
    FakeAuthenticator principale, riserva;
    const Fido2PrfCredential p{{1, 2, 3, 4}, "hid-fido2-age", {"usb"}};
    const Fido2PrfCredential r{{5, 6, 7, 8, 9}, "hid-fido2-age", {"usb"}};
    principale.cred_random[p.credential_id] = Bytes(32, 0x11);
    principale.present = p.credential_id;
    riserva.cred_random[r.credential_id] = Bytes(32, 0x22);
    riserva.present = r.credential_id;
    auto paper = X25519Identity::generate();
    auto paper_recipient = paper.recipient();
    Fido2PrfRecipient to_principale(p, principale.prf()), to_riserva(r, riserva.prf());
    Recipient* recipients[] = {&to_principale, &to_riserva, &paper_recipient};

    for (const std::size_t size : {std::size_t{0}, std::size_t{1}, chunk_size - 1, chunk_size, chunk_size + 1,
                                   2 * chunk_size, 3 * chunk_size + 17}) {
        const auto plaintext = pattern(size);
        const auto file = encrypt_to(plaintext, recipients);
        require(file.size() > size && file.find("-> age-encryption.org/fido2prf ") != std::string::npos &&
                file.find("-> X25519 ") != std::string::npos, "file has three recipients");
        Identity* by_paper[] = {&paper};
        require(decrypt_with(file, by_paper) == text(plaintext), "paper key decrypts size " + std::to_string(size));

        // Either key alone opens the file; the profile lists both credentials.
        Fido2PrfIdentity with_principale({p, r}, principale.prf());
        Identity* by_principale[] = {&with_principale};
        principale.touches = 0;
        require(decrypt_with(file, by_principale) == text(plaintext), "Principale decrypts");
        require(principale.touches == 1, "Principale needs one touch");
        Fido2PrfIdentity with_riserva({p, r}, riserva.prf());
        Identity* by_riserva[] = {&with_riserva};
        riserva.touches = 0;
        require(decrypt_with(file, by_riserva) == text(plaintext), "Riserva decrypts");
        require(riserva.touches == 2, "Riserva tries the first stanza, then its own");
    }

    // Unknown key: no file key, no plaintext.
    FakeAuthenticator other;
    const Fido2PrfCredential o{{42}, "hid-fido2-age", {"usb"}};
    other.cred_random[o.credential_id] = Bytes(32, 0x33);
    other.present = o.credential_id;
    const auto file = encrypt_to(bytes("segreto"), recipients);
    Fido2PrfIdentity with_other({o}, other.prf());
    Identity* by_other[] = {&with_other};
    bool refused = false;
    try { decrypt_with(file, by_other); } catch (const std::runtime_error&) { refused = true; }
    require(refused, "unregistered key refused");
}

void tamper_detection() {
    auto identity = X25519Identity::generate();
    auto recipient = identity.recipient();
    Recipient* recipients[] = {&recipient};
    Identity* identities[] = {&identity};
    const auto plaintext = pattern(2 * chunk_size + 100);
    const auto file = encrypt_to(plaintext, recipients);
    const auto header_end = file.find("\n---") + 4 + 44 + 1;
    rejects([&] { decrypt_with(file.substr(0, file.size() - 1), identities); }, "truncated last chunk");
    rejects([&] { decrypt_with(file.substr(0, header_end + 16 + chunk_size + 16), identities); }, "dropped final chunks");
    rejects([&] { decrypt_with(file + '\0', identities); }, "trailing data");
    for (const auto offset : {std::size_t{30}, header_end - 3, header_end + 3, header_end + 16 + 5, file.size() - 3}) {
        auto damaged = file;
        damaged[offset] = static_cast<char>(damaged[offset] ^ 0x20);
        rejects([&] { decrypt_with(damaged, identities); }, "bit flip at " + std::to_string(offset));
    }
    // Swapping two full chunks breaks the STREAM counter.
    auto swapped = file;
    const auto first = header_end + 16;
    const auto encrypted = chunk_size + 16;
    std::swap_ranges(swapped.begin() + static_cast<std::ptrdiff_t>(first), swapped.begin() + static_cast<std::ptrdiff_t>(first + encrypted),
                     swapped.begin() + static_cast<std::ptrdiff_t>(first + encrypted));
    rejects([&] { decrypt_with(swapped, identities); }, "reordered chunks");
}

// ---- C2SP age testkit -------------------------------------------------------------
std::string testkit_result(const std::string& file, std::vector<std::unique_ptr<X25519Identity>>& keys,
                           std::string& released) {
    std::vector<Identity*> identities;
    for (auto& key : keys) identities.push_back(key.get());
    std::istringstream input(file);
    bool constructed = false;
    crypto::Hash hash{};
    Bytes payload;
    try {
        Decryptor decryptor(input, identities);
        constructed = true;
        std::vector<std::uint8_t> buffer(4096);
        for (std::size_t count; (count = decryptor.read(buffer)) != 0;) payload.insert(payload.end(), buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(count));
        released = to_hex(crypto::sha256(payload));
        return decryptor.finished() ? "success" : "payload failure";
    } catch (const NoIdentityMatched&) {
        return "no match";
    } catch (const FormatError& error) {
        released = to_hex(crypto::sha256(payload));
        if (constructed) return "payload failure";
        return std::string(error.what()).find("header authentication") != std::string::npos ? "HMAC failure" : "header failure";
    }
    (void)hash;
}

void testkit(const fs::path& directory) {
    unsigned checked = 0, skipped = 0;
    for (const auto& entry : fs::directory_iterator(directory)) {
        if (!entry.is_regular_file() || entry.path().filename() == "README.md") continue;
        std::ifstream stream(entry.path(), std::ios::binary);
        const std::string content((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());
        const auto split = content.find("\n\n");
        require(split != std::string::npos, "malformed testkit vector " + entry.path().filename().string());
        std::multimap<std::string, std::string> fields;
        std::istringstream lines(content.substr(0, split));
        for (std::string line; std::getline(lines, line);) {
            const auto colon = line.find(": ");
            if (colon != std::string::npos) fields.emplace(line.substr(0, colon), line.substr(colon + 2));
        }
        bool supported = !fields.count("compressed") && !fields.count("armored") && !fields.count("passphrase");
        std::vector<std::unique_ptr<X25519Identity>> keys;
        for (auto [it, end] = fields.equal_range("identity"); it != end && supported; ++it) {
            try { keys.push_back(std::make_unique<X25519Identity>(X25519Identity::parse(it->second))); }
            catch (const FormatError&) { supported = false; }
        }
        if (!supported) { ++skipped; continue; }
        std::string released;
        const auto expected = fields.find("expect")->second;
        const auto actual = testkit_result(content.substr(split + 2), keys, released);
        require(actual == expected, entry.path().filename().string() + ": expected " + expected + ", got " + actual);
        if (const auto payload = fields.find("payload"); payload != fields.end() && (actual == "success" || actual == "payload failure")) {
            require(released == payload->second, entry.path().filename().string() + ": released plaintext mismatch");
        }
        ++checked;
    }
    require(checked >= 40, "testkit directory is incomplete");
    std::cout << "age testkit: " << checked << " vectors checked, " << skipped << " unsupported skipped\n";
}

// ---- Folder archives ---------------------------------------------------------------
struct TempDir {
    fs::path path;
    TempDir() {
        std::array<std::uint8_t, 8> random{};
        random_bytes(random);
        path = fs::temp_directory_path() / ("hidfido-age-test-" + to_hex(random));
        fs::create_directories(path);
    }
    ~TempDir() { std::error_code ignored; fs::remove_all(path, ignored); }
};

fs::path u8path(std::string_view text) {
    return fs::path(std::u8string(reinterpret_cast<const char8_t*>(text.data()), text.size()));
}

void write_file(const fs::path& path, std::span<const std::uint8_t> data) {
    fs::create_directories(path.parent_path());
    std::ofstream output(path, std::ios::binary);
    output.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
}

Bytes read_file(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

Source source_of(const std::string& data, std::size_t& position) {
    return [&data, &position](std::span<std::uint8_t> output) {
        const auto count = (std::min)(output.size(), data.size() - position);
        std::copy_n(data.begin() + static_cast<std::ptrdiff_t>(position), count, output.begin());
        position += count;
        return count;
    };
}

// Builds one ustar header (plus data) for hostile-archive tests.
std::string tar_entry(const std::string& name, char type, const std::string& data = {}) {
    std::array<char, 512> header{};
    std::copy(name.begin(), name.begin() + static_cast<std::ptrdiff_t>((std::min)(name.size(), std::size_t{100})), header.begin());
    auto octal = [&](std::size_t offset, std::size_t length, std::uint64_t value) {
        std::string digits(length - 1, '0');
        for (std::size_t i = digits.size(); i-- > 0; value >>= 3) digits[i] = static_cast<char>('0' + (value & 7));
        std::copy(digits.begin(), digits.end(), header.begin() + static_cast<std::ptrdiff_t>(offset));
    };
    octal(100, 8, 0644); octal(108, 8, 0); octal(116, 8, 0); octal(124, 12, data.size()); octal(136, 12, 0);
    header[156] = type;
    std::copy_n("ustar", 6, header.begin() + 257);
    header[263] = '0'; header[264] = '0';
    std::uint32_t sum = 0;
    for (std::size_t i = 0; i < 512; ++i) sum += (i >= 148 && i < 156) ? ' ' : static_cast<std::uint8_t>(header[i]);
    octal(148, 7, sum);
    header[155] = ' ';
    std::string result(header.begin(), header.end());
    result += data;
    result.append((512 - data.size() % 512) % 512, '\0');
    return result;
}

std::string tar_end() { return std::string(1024, '\0'); }

void folder_archives() {
    TempDir temp;
    const auto source = temp.path / "Documenti";
    write_file(source / "lettera.txt", bytes("Caro amico,\n"));
    write_file(source / u8path("città") / u8path("perché è così.txt"), pattern(70000));
    write_file(source / "vuoto.bin", {});
    write_file(source / "esatto.bin", pattern(512));
    const auto long_name = std::string(120, 'n') + ".txt";
    write_file(source / "annidata" / "a" / "b" / long_name, bytes("percorso lungo"));
    fs::create_directories(source / "cartella vuota");

    std::string archive;
    const auto written = write_tar(source, [&](std::span<const std::uint8_t> data) { archive.append(data.begin(), data.end()); });
    require(written.files == 5 && archive.size() % (20 * 512) == 0, "archive written");

    // Encrypt the archive, decrypt it again and extract.
    auto identity = X25519Identity::generate();
    auto recipient = identity.recipient();
    Recipient* recipients[] = {&recipient};
    Identity* identities[] = {&identity};
    const auto encrypted = encrypt_to(bytes(archive), recipients);
    std::istringstream input(encrypted);
    Decryptor decryptor(input, identities);
    const auto target = temp.path / "estratto";
    fs::create_directories(target);
    const auto extracted = extract_tar([&](std::span<std::uint8_t> output) { return decryptor.read(output); }, target);
    require(decryptor.finished(), "archive stream authenticated to the end");
    require(extracted.files == written.files && extracted.bytes == written.bytes, "extracted counts");
    require(read_file(target / "Documenti" / "lettera.txt") == Bytes(bytes("Caro amico,\n").begin(), bytes("Caro amico,\n").end()), "small file");
    require(read_file(target / "Documenti" / u8path("città") / u8path("perché è così.txt")) == pattern(70000), "unicode path");
    require(read_file(target / "Documenti" / "esatto.bin") == pattern(512), "block-sized file");
    require(fs::is_empty(target / "Documenti" / "vuoto.bin"), "empty file");
    require(fs::is_directory(target / "Documenti" / "cartella vuota"), "empty folder");
    require(fs::exists(target / "Documenti" / "annidata" / "a" / "b" / long_name), "pax long name");

    // Destination must be empty.
    std::size_t position = 0;
    rejects([&] { extract_tar(source_of(archive, position), target); }, "non-empty destination");

    // Hostile archives never write outside the destination.
    const std::vector<std::pair<std::string, std::string>> hostile{
        {tar_entry("../evaso.txt", '0', "x") + tar_end(), "parent traversal"},
        {tar_entry("a/../../evaso.txt", '0', "x") + tar_end(), "nested traversal"},
        {tar_entry("/etc/evaso", '0', "x") + tar_end(), "absolute path"},
        {tar_entry("C:/evaso", '0', "x") + tar_end(), "drive letter"},
        {tar_entry("a\\..\\evaso", '0', "x") + tar_end(), "backslash"},
        {tar_entry("cartella/CON.txt", '0', "x") + tar_end(), "reserved device name"},
        {tar_entry("file.txt:stream", '0', "x") + tar_end(), "alternate data stream"},
        {tar_entry("collegamento", '2') + tar_end(), "symbolic link"},
        {tar_entry("rigido", '1') + tar_end(), "hard link"},
        {tar_entry("dispositivo", '3') + tar_end(), "device"},
        {tar_entry("doppio.txt", '0', "a") + tar_entry("doppio.txt", '0', "b") + tar_end(), "duplicate entry"},
        {tar_entry("dati.txt", '0', "abc") + tar_end() + "garbage", "trailing garbage"},
        {tar_entry("dati.txt", '0', "abc"), "missing end marker"},
        {tar_entry("dati.txt", '0', std::string(600, 'z')).substr(0, 900), "truncated data"},
    };
    for (const auto& [data, description] : hostile) {
        TempDir sandbox;
        const auto inside = sandbox.path / "dentro";
        fs::create_directories(inside);
        std::size_t offset = 0;
        rejects([&] { extract_tar(source_of(data, offset), inside); }, description);
        require(!fs::exists(sandbox.path / "evaso.txt") && !fs::exists(sandbox.path / "evaso"), "escaped: " + description);
    }
    auto corrupted = tar_entry("dati.txt", '0', "abc") + tar_end();
    corrupted[10] = 'X';
    TempDir sandbox;
    std::size_t offset = 0;
    rejects([&] { extract_tar(source_of(corrupted, offset), sandbox.path); }, "bad header checksum");
}

// ---- Shared file operations (command line, helper and manager) --------------------
template<class Action>
void fails_with(files::Problem expected, Action&& action, const std::string& message) {
    try { action(); }
    catch (const files::Error& error) {
        require(error.problem() == expected, message + ": wrong problem");
        return;
    }
    throw std::runtime_error("Accepted invalid input: " + message);
}

bool no_leftovers(const fs::path& folder) {
    for (const auto& entry : fs::recursive_directory_iterator(folder)) {
        const auto name = entry.path().filename().string();
        if (name.find(".partial") != std::string::npos) return false;
    }
    return true;
}

void file_operations() {
    // Profiles: labels come from the comment right before each recipient.
    auto paper = X25519Identity::generate();
    const Fido2PrfCredential key{{1, 2, 3}, "hid-fido2-age", {"usb"}};
    const auto text = "\xEF\xBB\xBF# hid-fido2-age 2026-10-29\r\n# Principale\r\n" + key.encode() +
                      "\n\n# Recupero su carta\n" + paper.recipient().encode() + "\n";
    const auto profile = files::parse_profile(text);
    require(profile.keys.size() == 1 && profile.keys[0].label == "Principale" && profile.keys[0].credential == key, "profile key");
    require(profile.recovery.size() == 1 && profile.recovery[0].label == "Recupero su carta", "profile recovery");
    fails_with(files::Problem::profile_secret, [&] { files::parse_profile("# x\n" + paper.encode() + "\n"); }, "secret in profile");
    fails_with(files::Problem::profile_line, [] { files::parse_profile("age1\nqualcosa\n"); }, "unknown line");
    fails_with(files::Problem::profile_empty, [] { files::parse_profile("# solo commenti\n"); }, "empty profile");
    require(files::group_recovery_key("AGE-SECRET-KEY-1ABCDEFGH") == "AGE-SECRET-KEY-1 ABCD EFGH", "grouping");
    require(files::strip_whitespace(" AGE-SECRET-KEY-1 ABCD\tEFGH\r\n") == "AGE-SECRET-KEY-1ABCDEFGH", "ungrouping");

    TempDir temp;
    const auto profile_path = temp.path / "profilo" / "destinatari.txt";
    fails_with(files::Problem::profile_missing, [&] { files::read_profile(profile_path); }, "missing profile");
    files::append_profile(profile_path, "Principale", key.encode(), "2026-10-29");
    files::append_profile(profile_path, "Recupero su carta", paper.recipient().encode(), "2026-10-29");
    const auto stored = files::read_profile(profile_path);
    require(stored.keys.size() == 1 && stored.recovery.size() == 1 && stored.keys[0].label == "Principale", "profile round trip");
    fails_with(files::Problem::profile_label, [&] { files::append_profile(profile_path, "", key.encode(), "x"); }, "empty label");
    fails_with(files::Problem::profile_label, [&] { files::append_profile(profile_path, "a\nb", key.encode(), "x"); }, "multi-line label");
    fails_with(files::Problem::profile_secret, [&] { files::append_profile(profile_path, "Carta", paper.encode(), "x"); }, "secret appended");
    write_file(temp.path / "rotto.txt", bytes("non un profilo\n"));
    fails_with(files::Problem::profile_line, [&] { files::append_profile(temp.path / "rotto.txt", "X", key.encode(), "x"); }, "append to invalid profile");

    // Names.
    require(files::decrypted_name(temp.path / "Contratto.pdf.age").filename() == "Contratto.pdf", "decrypted file name");
    require(files::decrypted_name(temp.path / "Documenti.TAR.AGE").filename() == "Documenti", "decrypted folder name");
    fails_with(files::Problem::not_age_name, [&] { files::decrypted_name(temp.path / "nota.txt"); }, "not an age name");
    require(files::encrypted_name(temp.path / "Documenti", true).filename() == "Documenti.tar.age", "folder archive name");
    write_file(temp.path / "Contratto.pdf.age", bytes("x"));
    write_file(temp.path / "Contratto (2).pdf.age", bytes("x"));
    require(files::available_name(temp.path / "Contratto.pdf.age").filename() == "Contratto (3).pdf.age", "numbered encrypted name");
    fs::create_directories(temp.path / "Archivio");
    require(files::available_name(temp.path / "Archivio").filename() == "Archivio (2)", "numbered folder name");
    require(files::available_name(temp.path / "libero.txt").filename() == "libero.txt", "free name unchanged");

    // File round trip, refusal and renaming.
    auto recipient = paper.recipient();
    Recipient* recipients[] = {&recipient};
    Identity* identities[] = {&paper};
    const auto work = temp.path / "lavoro";
    write_file(work / "relazione.pdf", pattern(3 * chunk_size + 5));
    std::uint64_t last_done = 0, last_total = 0;
    files::Observer observer{[&](std::uint64_t done, std::uint64_t total) { last_done = done; last_total = total; }, {}};
    const auto encrypted = files::encrypt(work / "relazione.pdf", recipients, std::nullopt, false, observer);
    require(encrypted.output == fs::absolute(work / "relazione.pdf.age") && !encrypted.folder, "encrypted next to the input");
    require(last_total == 3 * chunk_size + 5 && last_done == last_total, "encryption progress");
    fails_with(files::Problem::output_exists, [&] { files::encrypt(work / "relazione.pdf", recipients, std::nullopt, false); }, "overwrite refused");
    const auto again = files::encrypt(work / "relazione.pdf", recipients, std::nullopt, true);
    require(again.output.filename() == "relazione (2).pdf.age", "renamed encryption");
    fails_with(files::Problem::output_exists, [&] { files::decrypt(encrypted.output, identities, std::nullopt, false); }, "decrypt overwrite refused");
    const auto decrypted = files::decrypt(encrypted.output, identities, std::nullopt, true);
    require(decrypted.output.filename() == "relazione (2).pdf" && read_file(decrypted.output) == pattern(3 * chunk_size + 5), "renamed decryption");

    // Folder round trip next to the archive, with a name conflict.
    const auto folder = work / "Documenti";
    write_file(folder / "a.txt", bytes("uno"));
    write_file(folder / u8path("sotto") / u8path("è.bin"), pattern(1000));
    fails_with(files::Problem::output_inside_input, [&] { files::encrypt(folder, recipients, folder / "x.tar.age", false); }, "archive inside itself");
    const auto archive = files::encrypt(folder, recipients, std::nullopt, false);
    require(archive.folder && archive.output.filename() == "Documenti.tar.age" && archive.stats.files == 2, "folder archive");
    fails_with(files::Problem::output_exists, [&] { files::decrypt(archive.output, identities, std::nullopt, false); }, "folder conflict refused");
    require(no_leftovers(temp.path), "staging folder left after refusal");
    const auto restored = files::decrypt(archive.output, identities, std::nullopt, true);
    require(restored.output.filename() == "Documenti (2)" && read_file(restored.output / u8path("sotto") / u8path("è.bin")) == pattern(1000), "renamed folder extraction");
    const auto chosen = files::decrypt(archive.output, identities, work / "Ripristino", false);
    require(fs::exists(chosen.output / "Documenti" / "a.txt"), "extraction into a new folder");

    // Cancellation, tampering and a wrong key leave nothing behind.
    files::Observer stop{{}, [] { return false; }};
    fails_with(files::Problem::cancelled, [&] { files::encrypt(folder, recipients, work / "annullato.tar.age", false, stop); }, "cancelled encryption");
    fails_with(files::Problem::cancelled, [&] { files::decrypt(archive.output, identities, work / "annullata", false, stop); }, "cancelled extraction");
    auto damaged = read_file(archive.output);
    damaged[damaged.size() - 40] ^= 1;
    write_file(work / "danneggiato.tar.age", damaged);
    rejects([&] { files::decrypt(work / "danneggiato.tar.age", identities, std::nullopt, true); }, "damaged folder archive");
    require(!fs::exists(work / "annullato.tar.age") && !fs::exists(work / "annullata") && no_leftovers(temp.path), "no partial results");
    auto stranger = X25519Identity::generate();
    Identity* wrong[] = {&stranger};
    bool refused = false;
    try { files::decrypt(encrypted.output, wrong, work / "mai.pdf", false); } catch (const NoIdentityMatched&) { refused = true; }
    require(refused && !fs::exists(work / "mai.pdf"), "wrong key");
    require(files::has_stanza(files::read_stanzas(encrypted.output), "X25519"), "header inspection");
}
}

int main(int argc, char** argv) {
    try {
        primitive_vectors();
        encoding_vectors();
        decrypts_reference_age_file();
        fido2prf_vectors();
        multiple_recipients();
        tamper_detection();
        folder_archives();
        file_operations();
        if (argc > 1) testkit(argv[1]);
        std::cout << "age file encryption tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAILED: " << error.what() << "\n";
        return 1;
    }
}
