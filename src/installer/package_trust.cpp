#include "hidfido/package_trust.hpp"

#include <windows.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <softpub.h>

#include <algorithm>
#include <array>
#include <map>
#include <stdexcept>
#include <utility>

namespace hidfido::installer {
namespace {
constexpr std::array<std::string_view, 4> native_paths{
    "bin/HidFido2CredentialProvider.dll", "bin/hid-fido2-vault.exe",
    "bin/provider-smoke.exe", "Gestione-HID-FIDO2.exe"};
[[noreturn]] void invalid() { throw std::runtime_error("Package trust validation failed"); }
bool lower_hex(std::string_view text, std::size_t size) noexcept {
    return text.size() == size && std::all_of(text.begin(), text.end(), [](char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); });
}
std::string lower(std::string_view text) {
    std::string result(text);
    for (auto& c : result) if (c >= 'A' && c <= 'F') c = static_cast<char>(c + ('a' - 'A'));
    return result;
}
struct Json {
    enum class Kind { null_value, boolean, number, string, array, object } kind{};
    std::uint64_t number{};
    std::string string;
    std::vector<Json> array;
    std::map<std::string, Json> object;
};
class Reader {
public:
    explicit Reader(std::span<const std::uint8_t> bytes) : bytes_(bytes) {}
    Json read(unsigned depth = 0) {
        if (depth > 12 || ++items_ > 20000) invalid();
        whitespace();
        Json result;
        const char c = peek();
        if (c == '"') { result.kind = Json::Kind::string; result.string = string(); }
        else if (c == '{') {
            result.kind = Json::Kind::object; ++at_; whitespace();
            if (peek() == '}') { ++at_; return result; }
            for (;;) {
                whitespace(); const auto key = string(); whitespace(); require(':');
                if (!result.object.emplace(key, read(depth + 1)).second) invalid();
                whitespace(); const auto end = take();
                if (end == '}') break;
                if (end != ',') invalid();
            }
        } else if (c == '[') {
            result.kind = Json::Kind::array; ++at_; whitespace();
            if (peek() == ']') { ++at_; return result; }
            for (;;) {
                result.array.push_back(read(depth + 1)); whitespace(); const auto end = take();
                if (end == ']') break;
                if (end != ',') invalid();
            }
        } else if (c >= '0' && c <= '9') {
            result.kind = Json::Kind::number;
            const bool zero = c == '0';
            do {
                const auto digit = static_cast<unsigned>(take() - '0');
                if (result.number > (UINT64_MAX - digit) / 10) invalid();
                result.number = result.number * 10 + digit;
                if (zero) break;
            } while (at_ < bytes_.size() && peek() >= '0' && peek() <= '9');
        } else if (c == 'n') { literal("null"); result.kind = Json::Kind::null_value; }
        else if (c == 't') { literal("true"); result.kind = Json::Kind::boolean; result.number = 1; }
        else if (c == 'f') { literal("false"); result.kind = Json::Kind::boolean; }
        else invalid();
        return result;
    }
    bool finished() { whitespace(); return at_ == bytes_.size(); }
private:
    char peek() const { if (at_ == bytes_.size()) invalid(); return static_cast<char>(bytes_[at_]); }
    char take() { const auto c = peek(); ++at_; return c; }
    void require(char c) { if (take() != c) invalid(); }
    void whitespace() { while (at_ < bytes_.size() && (peek() == ' ' || peek() == '\t' || peek() == '\r' || peek() == '\n')) ++at_; }
    void literal(std::string_view word) { for (char c : word) require(c); }
    std::string string() {
        require('"'); std::string value;
        for (;;) {
            const auto c = static_cast<unsigned char>(take());
            if (c == '"') return value;
            if (c < 0x20 || value.size() >= 65536) invalid();
            if (c != '\\') { value.push_back(static_cast<char>(c)); continue; }
            switch (take()) {
            case '"': value.push_back('"'); break; case '\\': value.push_back('\\'); break;
            case '/': value.push_back('/'); break; case 'b': value.push_back('\b'); break;
            case 'f': value.push_back('\f'); break; case 'n': value.push_back('\n'); break;
            case 'r': value.push_back('\r'); break; case 't': value.push_back('\t'); break;
            case 'u': {
                // Metadata names/paths are ASCII. Accept ASCII escapes only;
                // literal UTF-8 in unrelated signer descriptions remains data.
                unsigned scalar{};
                for (unsigned i = 0; i < 4; ++i) {
                    const auto h = take();
                    const unsigned digit = h >= '0' && h <= '9' ? h - '0' : h >= 'a' && h <= 'f' ? h - 'a' + 10 : h >= 'A' && h <= 'F' ? h - 'A' + 10 : 99;
                    if (digit > 15) invalid(); scalar = scalar * 16 + digit;
                }
                if (scalar > 0x7f || scalar == 0) invalid();
                value.push_back(static_cast<char>(scalar)); break;
            }
            default: invalid();
            }
        }
    }
    std::span<const std::uint8_t> bytes_;
    std::size_t at_{}, items_{};
};
const Json& member(const Json& value, const char* name) {
    if (value.kind != Json::Kind::object) invalid();
    const auto found = value.object.find(name); if (found == value.object.end()) invalid();
    return found->second;
}
std::string text(const Json& value) { if (value.kind != Json::Kind::string) invalid(); return value.string; }
std::uint64_t number(const Json& value) { if (value.kind != Json::Kind::number) invalid(); return value.number; }
class Handle {
public:
    explicit Handle(HANDLE h = INVALID_HANDLE_VALUE) noexcept : h_(h) {}
    ~Handle() { if (h_ != INVALID_HANDLE_VALUE) CloseHandle(h_); }
    Handle(Handle&& other) noexcept : h_(std::exchange(other.h_, INVALID_HANDLE_VALUE)) {}
    Handle& operator=(Handle&& other) noexcept { if (this != &other) { if (h_ != INVALID_HANDLE_VALUE) CloseHandle(h_); h_ = std::exchange(other.h_, INVALID_HANDLE_VALUE); } return *this; }
    Handle(const Handle&) = delete; Handle& operator=(const Handle&) = delete;
    HANDLE get() const noexcept { return h_; }
private: HANDLE h_;
};
Handle open_pinned(const std::filesystem::path& path, bool directory) {
    const auto access = directory ? FILE_READ_ATTRIBUTES : GENERIC_READ;
    Handle handle(CreateFileW(path.c_str(), access, FILE_SHARE_READ | (directory ? FILE_SHARE_WRITE : 0), nullptr, OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT | (directory ? FILE_FLAG_BACKUP_SEMANTICS : 0), nullptr));
    if (handle.get() == INVALID_HANDLE_VALUE) invalid();
    FILE_ATTRIBUTE_TAG_INFO attributes{};
    if (!GetFileInformationByHandleEx(handle.get(), FileAttributeTagInfo, &attributes, sizeof(attributes)) ||
        (attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) ||
        static_cast<bool>(attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != directory) invalid();
    return handle;
}
std::vector<std::uint8_t> bytes(HANDLE file, std::uint64_t maximum) {
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file, &size) || size.QuadPart <= 0 || static_cast<std::uint64_t>(size.QuadPart) > maximum) invalid();
    LARGE_INTEGER zero{}; if (!SetFilePointerEx(file, zero, nullptr, FILE_BEGIN)) invalid();
    std::vector<std::uint8_t> value(static_cast<std::size_t>(size.QuadPart));
    std::size_t at{};
    while (at < value.size()) {
        DWORD read{};
        if (!ReadFile(file, value.data() + at, static_cast<DWORD>(value.size() - at), &read, nullptr) || !read) invalid();
        at += read;
    }
    return value;
}
std::string certificate_pin(PCCERT_CONTEXT certificate) {
    if (!certificate) invalid();
    return sha256_hex({certificate->pbCertEncoded, certificate->cbCertEncoded});
}
void verify_authenticode(const std::filesystem::path& path, HANDLE file, std::string_view pin, bool prototype) {
    WINTRUST_FILE_INFO info{}; info.cbStruct = sizeof(info); info.pcwszFilePath = path.c_str(); info.hFile = file;
    WINTRUST_DATA data{}; data.cbStruct = sizeof(data); data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN; data.dwUnionChoice = WTD_CHOICE_FILE;
    data.pFile = &info; data.dwStateAction = WTD_STATEACTION_VERIFY;
    data.dwProvFlags = WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT;
    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    const auto status = WinVerifyTrust(nullptr, &action, &data);
    bool valid = false;
    if (prototype) valid = status == TRUST_E_NOSIGNATURE;
    else if (status == ERROR_SUCCESS) {
        const auto* provider = WTHelperProvDataFromStateData(data.hWVTStateData);
        const auto* signer = provider ? WTHelperGetProvSignerFromChain(const_cast<CRYPT_PROVIDER_DATA*>(provider), 0, FALSE, 0) : nullptr;
        const auto* certificate = signer ? WTHelperGetProvCertFromChain(const_cast<CRYPT_PROVIDER_SGNR*>(signer), 0) : nullptr;
        if (certificate && certificate->pCert) valid = certificate_pin(certificate->pCert) == pin;
    }
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &action, &data);
    if (!valid) invalid();
}
void verify_manifest_signature(std::span<const std::uint8_t> manifest, std::span<const std::uint8_t> signature, std::string_view pin) {
    CRYPT_VERIFY_MESSAGE_PARA parameters{}; parameters.cbSize = sizeof(parameters);
    parameters.dwMsgAndCertEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
    const BYTE* content = manifest.data(); DWORD length = static_cast<DWORD>(manifest.size());
    PCCERT_CONTEXT signer{};
    if (!CryptVerifyDetachedMessageSignature(&parameters, 0, signature.data(), static_cast<DWORD>(signature.size()),
                                             1, &content, &length, &signer)) invalid();
    bool match = false;
    try { match = certificate_pin(signer) == pin; } catch (...) { CertFreeCertificateContext(signer); throw; }
    CertFreeCertificateContext(signer);
    // The exact pinned certificate's chain and code-signing policy have
    // already been validated on every Authenticode payload, including self.
    if (!match) invalid();
}
}

std::span<const std::string_view> native_payload_paths() noexcept { return native_paths; }
bool valid_signer_pin(std::string_view text) noexcept {
    return text.size() == 64 && std::all_of(text.begin(), text.end(), [](char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'); });
}
std::string sha256_hex(std::span<const std::uint8_t> value) {
    BCRYPT_ALG_HANDLE algorithm{}; BCRYPT_HASH_HANDLE hash{};
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, MS_PRIMITIVE_PROVIDER, 0) < 0) invalid();
    std::array<std::uint8_t, 32> digest{};
    const auto created = BCryptCreateHash(algorithm, &hash, nullptr, 0, nullptr, 0, 0);
    const auto updated = created < 0 ? created : BCryptHashData(hash, const_cast<PUCHAR>(value.data()), static_cast<ULONG>(value.size()), 0);
    const auto finished = updated < 0 ? updated : BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0);
    if (hash) BCryptDestroyHash(hash); BCryptCloseAlgorithmProvider(algorithm, 0);
    if (finished < 0) invalid();
    constexpr char alphabet[] = "0123456789abcdef";
    std::string result; result.reserve(64);
    for (auto byte : digest) { result.push_back(alphabet[byte >> 4]); result.push_back(alphabet[byte & 15]); }
    return result;
}
Manifest parse_manifest(std::span<const std::uint8_t> data) {
    if (data.empty() || data.size() > 1024 * 1024) invalid();
    Reader reader(data); const auto root = reader.read(); if (!reader.finished()) invalid();
    if (number(member(root, "Schema")) != 1 || text(member(root, "ProjectId")) != "HID-FIDO2-WinLogon" ||
        text(member(root, "ProviderClsid")) != "{8B5D856B-C940-4AFB-A050-167F5D4F75E2}" ||
        text(member(root, "Architecture")) != "8664" || number(member(root, "VaultSchema")) != 2) invalid();
    Manifest manifest; manifest.version = text(member(root, "Version")); manifest.release_id = text(member(root, "ReleaseId"));
    if (manifest.version.empty() || manifest.version.size() > 64 || !lower_hex(manifest.release_id, 64)) invalid();
    for (char c : manifest.version) if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '.' || c == '-')) invalid();
    const auto& files = member(root, "Files");
    if (files.kind != Json::Kind::array) invalid();
    const auto expected_paths = native_payload_paths();
    if (files.array.size() != expected_paths.size()) invalid();
    manifest.native_management = true;
    for (const auto expected : expected_paths) {
        const Json* selected{};
        for (const auto& file : files.array) if (text(member(file, "Path")) == expected) { if (selected) invalid(); selected = &file; }
        if (!selected) invalid();
        ManifestFile file{text(member(*selected, "Path")), number(member(*selected, "Length")), text(member(*selected, "Sha256"))};
        if (!file.length || file.length > 64 * 1024 * 1024 || !lower_hex(file.sha256, 64)) invalid();
        manifest.files.push_back(std::move(file));
    }
    std::string identity = "HID-FIDO2-WinLogon/release/1\n" + manifest.version + "\n8664";
    for (const auto& file : manifest.files) identity += "\n" + file.path + "=" + file.sha256;
    if (sha256_hex({reinterpret_cast<const std::uint8_t*>(identity.data()), identity.size()}) != manifest.release_id) invalid();
    return manifest;
}
std::wstring quote_argument(std::wstring_view value) {
    std::wstring result = L"\""; unsigned slashes{};
    for (auto c : value) {
        if (c == L'\\') { ++slashes; continue; }
        if (c == L'"') { result.append(slashes * 2 + 1, L'\\'); result.push_back(c); }
        else { result.append(slashes, L'\\'); result.push_back(c); }
        slashes = 0;
    }
    result.append(slashes * 2, L'\\'); result.push_back(L'"'); return result;
}
struct PinnedPackage::State { Manifest manifest; std::vector<Handle> handles; };
PinnedPackage::PinnedPackage(const std::filesystem::path& requested, std::string_view signer_pin, bool prototype)
    : state_(std::make_unique<State>()) {
    if (prototype ? !signer_pin.empty() : !valid_signer_pin(signer_pin)) invalid();
    const auto pin = lower(signer_pin);
    const auto directory = std::filesystem::absolute(requested).lexically_normal();
    const auto native = directory.native();
    if (native.size() < 3 || native[1] != L':' || native[2] != L'\\' || native.find(L':', 2) != std::wstring::npos) invalid();
    auto cursor = directory.root_path(); state_->handles.push_back(open_pinned(cursor, true));
    for (const auto& part : directory.relative_path()) { cursor /= part; state_->handles.push_back(open_pinned(cursor, true)); }
    state_->handles.push_back(open_pinned(directory / L"bin", true));
    auto manifest = open_pinned(directory / L"release.json", false);
    const auto manifest_bytes = bytes(manifest.get(), 1024 * 1024);
    state_->manifest = parse_manifest(manifest_bytes);
    state_->handles.push_back(std::move(manifest));
    std::vector<std::string> actual;
    for (const auto& item : std::filesystem::directory_iterator(directory)) {
        const auto name = item.path().filename().string();
        if (name == "bin") {
            for (const auto& child : std::filesystem::directory_iterator(item.path())) actual.push_back(name + "/" + child.path().filename().string());
        } else actual.push_back(name);
    }
    std::vector<std::string> expected{"release.json"};
    for (const auto& file : state_->manifest.files) {
        expected.push_back(file.path);
        const auto path = directory / std::filesystem::path(file.path);
        auto source = open_pinned(path, false);
        const auto content = bytes(source.get(), 64 * 1024 * 1024);
        if (content.size() != file.length || sha256_hex(content) != file.sha256) invalid();
        verify_authenticode(path, source.get(), pin, prototype);
        state_->handles.push_back(std::move(source));
    }
    if (!prototype) {
        expected.push_back("release.p7s");
        auto signature = open_pinned(directory / L"release.p7s", false);
        verify_manifest_signature(manifest_bytes, bytes(signature.get(), 1024 * 1024), pin);
        state_->handles.push_back(std::move(signature));
    }
    std::sort(actual.begin(), actual.end()); std::sort(expected.begin(), expected.end());
    if (actual != expected) invalid();
}
PinnedPackage::~PinnedPackage() = default;
const Manifest& PinnedPackage::manifest() const noexcept { return state_->manifest; }
}
