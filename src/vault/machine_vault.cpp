#include "hidfido/machine_vault.hpp"
#include "hidfido/provider_ids.hpp"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <aclapi.h>
#include <bcrypt.h>
#include <knownfolders.h>
#include <sddl.h>
#include <shlobj.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <optional>
#include <thread>
#include <utility>

namespace hidfido::vault {
namespace {
constexpr std::array<std::uint8_t, 8> magic{'H', 'F', 'M', 'V', 'A', 'U', 'L', 'T'};
constexpr std::uint32_t schema_version = current_schema;
constexpr std::uint32_t flag_stale = 1;
constexpr std::size_t max_file = 256 * 1024;
constexpr std::size_t max_sid = 184;
constexpr std::size_t max_account_name = 256;
constexpr std::size_t max_label_units = 64;
constexpr std::size_t max_credential_id = 1023;

[[noreturn]] void win_error(const char* operation, DWORD code = GetLastError()) {
    throw std::runtime_error(std::string(operation) + " failed (Windows error " +
                             std::to_string(code) + ")");
}

[[noreturn]] void invalid_vault(const char* reason) {
    throw std::runtime_error(std::string("Invalid machine vault: ") + reason);
}

class Handle {
public:
    explicit Handle(HANDLE value = INVALID_HANDLE_VALUE) noexcept : value_(value) {}
    ~Handle() { if (valid()) CloseHandle(value_); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    Handle(Handle&& other) noexcept : value_(std::exchange(other.value_, INVALID_HANDLE_VALUE)) {}
    Handle& operator=(Handle&& other) noexcept {
        if (this != &other) {
            if (valid()) CloseHandle(value_);
            value_ = std::exchange(other.value_, INVALID_HANDLE_VALUE);
        }
        return *this;
    }
    bool valid() const noexcept { return value_ != INVALID_HANDLE_VALUE && value_ != nullptr; }
    HANDLE get() const noexcept { return value_; }
    HANDLE release() noexcept { return std::exchange(value_, INVALID_HANDLE_VALUE); }
private:
    HANDLE value_;
};

class LocalMemory {
public:
    explicit LocalMemory(void* pointer = nullptr) noexcept : pointer_(pointer) {}
    ~LocalMemory() { if (pointer_) LocalFree(pointer_); }
    LocalMemory(const LocalMemory&) = delete;
    LocalMemory& operator=(const LocalMemory&) = delete;
private:
    void* pointer_;
};

class Security {
public:
    explicit Security(std::wstring_view sddl) {
        const std::wstring text(sddl);
        PSECURITY_DESCRIPTOR descriptor = nullptr;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text.c_str(), SDDL_REVISION_1, &descriptor, nullptr)) {
            win_error("Create vault security descriptor");
        }
        descriptor_ = descriptor;
        attributes_.nLength = sizeof(attributes_);
        attributes_.lpSecurityDescriptor = descriptor_;
        attributes_.bInheritHandle = FALSE;
    }
    ~Security() { if (descriptor_) LocalFree(descriptor_); }
    Security(const Security&) = delete;
    Security& operator=(const Security&) = delete;
    SECURITY_ATTRIBUTES* attributes() noexcept { return &attributes_; }
private:
    PSECURITY_DESCRIPTOR descriptor_{};
    SECURITY_ATTRIBUTES attributes_{};
};

bool machine_mode(std::wstring_view sddl) noexcept { return sddl == machine_sddl; }

bool default_machine_path(const std::filesystem::path& path) {
    return CompareStringOrdinal(path.c_str(), -1, default_path().c_str(), -1, TRUE) == CSTR_EQUAL;
}

void reject_reparse(HANDLE handle) {
    FILE_ATTRIBUTE_TAG_INFO attributes{};
    if (!GetFileInformationByHandleEx(handle, FileAttributeTagInfo, &attributes, sizeof(attributes))) {
        win_error("Inspect vault object");
    }
    if (attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) invalid_vault("reparse points are not allowed");
}

bool trusted_sid(PSID sid) {
    return sid && IsValidSid(sid) &&
        (IsWellKnownSid(sid, WinLocalSystemSid) || IsWellKnownSid(sid, WinBuiltinAdministratorsSid));
}

DWORD file_rights(DWORD mask) {
    GENERIC_MAPPING mapping{FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_GENERIC_EXECUTE, FILE_ALL_ACCESS};
    MapGenericMask(&mask, &mapping);
    return mask;
}

PACL checked_dacl(PSECURITY_DESCRIPTOR descriptor) {
    if (!descriptor || !IsValidSecurityDescriptor(descriptor)) invalid_vault("invalid security descriptor");
    PACL dacl = nullptr; BOOL present = FALSE, defaulted = FALSE;
    if (!GetSecurityDescriptorDacl(descriptor, &present, &dacl, &defaulted) ||
        !present || !dacl || !IsValidAcl(dacl)) invalid_vault("missing or null DACL");
    return dacl;
}

void validate_machine_descriptor(PSECURITY_DESCRIPTOR descriptor) {
    const auto dacl = checked_dacl(descriptor);
    PSID owner = nullptr; BOOL defaulted = FALSE;
    if (!GetSecurityDescriptorOwner(descriptor, &owner, &defaulted) || !trusted_sid(owner)) {
        invalid_vault("vault object is not owned by SYSTEM or Administrators");
    }
    SECURITY_DESCRIPTOR_CONTROL control{}; DWORD revision{};
    if (!GetSecurityDescriptorControl(descriptor, &control, &revision) || !(control & SE_DACL_PROTECTED)) {
        invalid_vault("vault DACL must be protected");
    }
    DWORD system = 0, administrators = 0;
    for (DWORD i = 0; i < dacl->AceCount; ++i) {
        void* raw = nullptr;
        if (!GetAce(dacl, i, &raw)) win_error("Read vault ACE");
        const auto* header = static_cast<const ACE_HEADER*>(raw);
        if (header->AceType != ACCESS_ALLOWED_ACE_TYPE || header->AceFlags != 0 ||
            header->AceSize < sizeof(ACCESS_ALLOWED_ACE)) invalid_vault("unsupported or inherited vault ACE");
        const auto* ace = static_cast<const ACCESS_ALLOWED_ACE*>(raw);
        auto* sid = const_cast<DWORD*>(&ace->SidStart);
        if (!trusted_sid(sid) || GetLengthSid(sid) > header->AceSize - offsetof(ACCESS_ALLOWED_ACE, SidStart)) {
            invalid_vault("vault DACL permits an untrusted identity");
        }
        if (IsWellKnownSid(sid, WinLocalSystemSid)) system |= file_rights(ace->Mask);
        else administrators |= file_rights(ace->Mask);
    }
    if ((system & FILE_ALL_ACCESS) != FILE_ALL_ACCESS ||
        (administrators & FILE_ALL_ACCESS) != FILE_ALL_ACCESS) {
        invalid_vault("SYSTEM and Administrators require full vault access");
    }
}

void verify_machine_security(HANDLE handle) {
    PSECURITY_DESCRIPTOR raw = nullptr;
    const DWORD result = GetSecurityInfo(handle, SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, nullptr, nullptr, nullptr, nullptr, &raw);
    if (result != ERROR_SUCCESS) win_error("Read vault security", result);
    LocalMemory storage(raw);
    validate_machine_descriptor(raw);
}

bool trusted_installer(PSID sid) {
    // Resolve the local service SID instead of accepting arbitrary service SIDs.
    std::array<std::uint8_t, SECURITY_MAX_SID_SIZE> expected{};
    wchar_t domain[256]{}; DWORD sid_size = static_cast<DWORD>(expected.size()), domain_size = 256;
    SID_NAME_USE use{};
    return LookupAccountNameW(nullptr, L"NT SERVICE\\TrustedInstaller", expected.data(), &sid_size,
                              domain, &domain_size, &use) && EqualSid(sid, expected.data());
}

void verify_machine_ancestor(HANDLE handle) {
    PSECURITY_DESCRIPTOR raw = nullptr;
    const DWORD result = GetSecurityInfo(handle, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                                         nullptr, nullptr, nullptr, nullptr, &raw);
    if (result != ERROR_SUCCESS) win_error("Read vault ancestor security", result);
    LocalMemory storage(raw);
    PSID owner = nullptr; BOOL defaulted = FALSE;
    if (!GetSecurityDescriptorOwner(raw, &owner, &defaulted) || !owner || !IsValidSid(owner) ||
        (!trusted_sid(owner) && !trusted_installer(owner))) {
        invalid_vault("untrusted vault ancestor owner");
    }
    const auto dacl = checked_dacl(raw);
    for (DWORD i = 0; i < dacl->AceCount; ++i) {
        void* raw_ace = nullptr;
        if (!GetAce(dacl, i, &raw_ace)) win_error("Read ancestor ACE");
        const auto* header = static_cast<const ACE_HEADER*>(raw_ace);
        if (header->AceFlags & INHERIT_ONLY_ACE) continue;
        if (header->AceType == ACCESS_DENIED_ACE_TYPE) continue;
        if (header->AceType != ACCESS_ALLOWED_ACE_TYPE || header->AceSize < sizeof(ACCESS_ALLOWED_ACE)) {
            invalid_vault("unsupported ancestor ACE");
        }
        const auto* ace = static_cast<const ACCESS_ALLOWED_ACE*>(raw_ace);
        auto* sid = const_cast<DWORD*>(&ace->SidStart);
        if (!IsValidSid(sid) || GetLengthSid(sid) > header->AceSize - offsetof(ACCESS_ALLOWED_ACE, SidStart)) {
            invalid_vault("invalid ancestor SID");
        }
        // ProgramData legitimately permits creating children. Those permissions
        // cannot replace this protected child; DELETE_CHILD/owner/DACL can.
        constexpr DWORD dangerous = WRITE_DAC | WRITE_OWNER | DELETE | FILE_DELETE_CHILD;
        if ((file_rights(ace->Mask) & dangerous) && !trusted_sid(sid) && !trusted_installer(sid)) {
            invalid_vault("untrusted ancestor replacement permissions");
        }
    }
}

std::optional<std::vector<Handle>> pin_directories(const std::filesystem::path& directory,
                                                 Security* create_security, bool machine) {
    std::vector<std::filesystem::path> paths{directory.root_path()};
    auto cursor = directory.root_path();
    for (const auto& part : directory.relative_path()) { cursor /= part; paths.push_back(cursor); }
    std::vector<Handle> handles;
    handles.reserve(paths.size());
    for (std::size_t i = 0; i < paths.size(); ++i) {
        if (create_security && i != 0 && !CreateDirectoryW(paths[i].c_str(), create_security->attributes())) {
            const DWORD code = GetLastError();
            if (code != ERROR_ALREADY_EXISTS) win_error("Create vault directory", code);
        }
        // No delete sharing: the directory chain cannot be renamed/replaced
        // between descriptor verification and the subsequent path operation.
        Handle handle(CreateFileW(paths[i].c_str(), READ_CONTROL | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
        if (!handle.valid()) {
            const DWORD code = GetLastError();
            if (!create_security && (code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND)) return std::nullopt;
            win_error("Open vault directory", code);
        }
        reject_reparse(handle.get());
        FILE_ATTRIBUTE_TAG_INFO attributes{};
        if (!GetFileInformationByHandleEx(handle.get(), FileAttributeTagInfo, &attributes, sizeof(attributes)) ||
            !(attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY)) invalid_vault("vault ancestor is not a directory");
        if (machine) {
            if (i + 1 == paths.size()) verify_machine_security(handle.get());
            else verify_machine_ancestor(handle.get());
        }
        handles.push_back(std::move(handle));
    }
    return handles;
}

std::filesystem::path checked_path(const std::filesystem::path& requested) {
    if (requested.empty() || requested.filename().empty()) throw std::runtime_error("A vault filename is required");
    auto path = std::filesystem::absolute(requested).lexically_normal();
    if (path.filename().wstring().find(L':') != std::wstring::npos ||
        path.native().rfind(L"\\\\?\\", 0) == 0 || path.native().rfind(L"\\\\.\\", 0) == 0) {
        throw std::runtime_error("Unsupported vault path");
    }
    return path;
}

std::filesystem::path lock_path(const std::filesystem::path& path) {
    auto result = path;
    result.replace_extension(L".lock");
    if (result == path) result += L".lock";
    return result;
}

// --- Binary encoding ---------------------------------------------------------

void append_u32(Bytes& output, std::uint32_t value) {
    for (unsigned shift = 0; shift < 32; shift += 8) output.push_back(static_cast<std::uint8_t>(value >> shift));
}
void append_u64(Bytes& output, std::uint64_t value) {
    for (unsigned shift = 0; shift < 64; shift += 8) output.push_back(static_cast<std::uint8_t>(value >> shift));
}
void append_raw(Bytes& output, std::span<const std::uint8_t> value) {
    output.insert(output.end(), value.begin(), value.end());
}
void append_blob(Bytes& output, std::span<const std::uint8_t> value) {
    append_u32(output, static_cast<std::uint32_t>(value.size()));
    append_raw(output, value);
}
std::span<const std::uint8_t> bytes_of(std::string_view value) {
    return {reinterpret_cast<const std::uint8_t*>(value.data()), value.size()};
}
std::span<const std::uint8_t> bytes_of(std::wstring_view value) {
    return {reinterpret_cast<const std::uint8_t*>(value.data()), value.size() * sizeof(wchar_t)};
}
void append_envelope(Bytes& output, const password::Envelope& envelope) {
    append_u32(output, envelope.version);
    append_raw(output, envelope.nonce);
    append_blob(output, envelope.ciphertext);
    append_raw(output, envelope.tag);
}

class Reader {
public:
    explicit Reader(std::span<const std::uint8_t> data) : data_(data) {}
    std::span<const std::uint8_t> take(std::size_t count) {
        if (count > data_.size() - position_) invalid_vault("truncated data");
        const auto result = data_.subspan(position_, count);
        position_ += count;
        return result;
    }
    std::uint32_t u32() {
        const auto raw = take(4);
        return std::uint32_t{raw[0]} | (std::uint32_t{raw[1]} << 8) |
               (std::uint32_t{raw[2]} << 16) | (std::uint32_t{raw[3]} << 24);
    }
    std::uint64_t u64() {
        const auto raw = take(8);
        std::uint64_t result{};
        for (unsigned index = 0; index < 8; ++index) result |= std::uint64_t{raw[index]} << (8 * index);
        return result;
    }
    std::span<const std::uint8_t> blob(std::size_t maximum) {
        const auto size = u32();
        if (size > maximum) invalid_vault("field exceeds its limit");
        return take(size);
    }
    template<std::size_t N> void raw(std::array<std::uint8_t, N>& output) {
        const auto value = take(N);
        std::copy(value.begin(), value.end(), output.begin());
    }
    bool finished() const noexcept { return position_ == data_.size(); }
private:
    std::span<const std::uint8_t> data_;
    std::size_t position_{};
};

password::Envelope read_envelope(Reader& reader, std::size_t max_ciphertext) {
    password::Envelope envelope;
    envelope.version = reader.u32();
    reader.raw(envelope.nonce);
    const auto ciphertext = reader.blob(max_ciphertext);
    envelope.ciphertext.assign(ciphertext.begin(), ciphertext.end());
    reader.raw(envelope.tag);
    return envelope;
}

// --- Validation ----------------------------------------------------------------

bool valid_sid(std::string_view sid) {
    if (sid.size() < 6 || sid.size() > max_sid || sid.rfind("S-1-", 0) != 0) return false;
    return std::all_of(sid.begin(), sid.end(), [](char c) { return c == 'S' || c == '-' || (c >= '0' && c <= '9'); });
}

bool valid_label(std::wstring_view label) {
    if (label.empty() || label.size() > max_label_units) return false;
    return std::all_of(label.begin(), label.end(), [](wchar_t c) { return c >= 0x20 && c != 0x7f && !(c >= 0xd800 && c <= 0xdfff); });
}

void validate_password(std::span<const std::uint8_t> password_utf16) {
    if (password_utf16.empty() || password_utf16.size() % sizeof(wchar_t) != 0 ||
        password_utf16.size() > max_password_units * sizeof(wchar_t)) {
        throw std::invalid_argument("Windows password must be 1 to 256 UTF-16 code units");
    }
    for (std::size_t i = 0; i < password_utf16.size(); i += 2) {
        if (password_utf16[i] == 0 && password_utf16[i + 1] == 0) {
            throw std::invalid_argument("Windows password must not contain NUL");
        }
    }
}

void validate_envelope(const password::Envelope& envelope, std::size_t minimum, std::size_t maximum) {
    if (envelope.version != password::envelope_version) invalid_vault("unsupported envelope version");
    if (envelope.ciphertext.size() < minimum || envelope.ciphertext.size() > maximum) {
        invalid_vault("envelope size is outside the allowed range");
    }
}

void validate_record(const AccountRecord& record) {
    if (!valid_sid(record.sid)) invalid_vault("invalid account SID");
    if (record.account_name.empty() || record.account_name.size() > max_account_name ||
        record.account_name.find('\0') != std::string::npos) {
        invalid_vault("invalid account name");
    }
    validate_envelope(record.password, 2, max_password_units * sizeof(wchar_t));
    if (record.password.ciphertext.size() % 2 != 0) invalid_vault("password payload is not UTF-16");
    if (record.wrappers.empty() || record.wrappers.size() > max_wrappers) invalid_vault("invalid key wrapper count");
    for (std::size_t i = 0; i < record.wrappers.size(); ++i) {
        const auto& wrapper = record.wrappers[i];
        if (!valid_label(wrapper.label)) invalid_vault("invalid key label");
        if (wrapper.credential.id.empty() || wrapper.credential.id.size() > max_credential_id) {
            invalid_vault("invalid credential ID");
        }
        validate_envelope(wrapper.wrapped_key, 32, 32);
        switch (wrapper.protection_state) {
        case ProtectionState::unknown:
            if (wrapper.protection_checked_at_unix || wrapper.protection_verification_version) invalid_vault("unknown protection has proof metadata");
            break;
        case ProtectionState::verified_denied:
        case ProtectionState::verified_distinct:
            if (!wrapper.protection_checked_at_unix || wrapper.protection_checked_at_unix > 253402300799ULL ||
                wrapper.protection_verification_version != protection_verification_version) invalid_vault("invalid key-protection provenance");
            break;
        default: invalid_vault("unknown key-protection state");
        }
        for (std::size_t j = 0; j < i; ++j) {
            if (record.wrappers[j].label == wrapper.label) invalid_vault("duplicate key label");
            if (record.wrappers[j].credential.id == wrapper.credential.id) invalid_vault("duplicate credential ID");
        }
    }
}

void validate_vault(const Vault& vault) {
    if (vault.accounts.size() > max_accounts) invalid_vault("too many accounts");
    for (std::size_t i = 0; i < vault.accounts.size(); ++i) {
        validate_record(vault.accounts[i]);
        for (std::size_t j = 0; j < i; ++j) {
            if (vault.accounts[j].sid == vault.accounts[i].sid) invalid_vault("duplicate account SID");
        }
    }
}

// --- Cryptographic contexts ------------------------------------------------------

password::Context wrapper_context(const AccountRecord& record, const KeyWrapper& wrapper) {
    password::Context context;
    context.account_sid = record.sid;
    context.account_name = record.account_name;
    context.rp_id = rp_id;
    context.credential_id = wrapper.credential.id;
    context.hmac_salt = wrapper.salt;
    context.purpose = password::Purpose::wrapped_data_key;
    return context;
}

// The payload is sealed with the DEK as input key material. The record ID takes
// the credential slot and the payload salt the HKDF salt, so the password is
// bound to account SID/name, RP and this record.
password::Context payload_context(const AccountRecord& record) {
    password::Context context;
    context.account_sid = record.sid;
    context.account_name = record.account_name;
    context.rp_id = rp_id;
    context.credential_id = record.record_id;
    context.hmac_salt = record.payload_salt;
    context.purpose = password::Purpose::secret_payload;
    return context;
}

template<std::size_t N> std::array<std::uint8_t, N> random_array() {
    std::array<std::uint8_t, N> result{};
    if (BCryptGenRandom(nullptr, result.data(), static_cast<ULONG>(N), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) {
        throw std::runtime_error("CNG random generation failed");
    }
    return result;
}

void require_data_key(std::span<const std::uint8_t> data_key) {
    if (data_key.size() != 32) throw std::invalid_argument("Data-encryption key must be 32 bytes");
}
}

AccountRecord* Vault::find(std::string_view sid) noexcept {
    for (auto& account : accounts) if (account.sid == sid) return &account;
    return nullptr;
}

const AccountRecord* Vault::find(std::string_view sid) const noexcept {
    for (const auto& account : accounts) if (account.sid == sid) return &account;
    return nullptr;
}

std::string_view protection_state_name(ProtectionState state) noexcept {
    switch (state) {
    case ProtectionState::verified_denied: return "verified_denied";
    case ProtectionState::verified_distinct: return "verified_distinct";
    default: return "unknown";
    }
}

Bytes serialize(const Vault& vault, std::uint32_t format_version) {
    validate_vault(vault);
    if (format_version != 1 && format_version != schema_version) invalid_vault("unsupported serialization version");
    Bytes output;
    append_raw(output, magic);
    append_u32(output, format_version);
    append_u32(output, static_cast<std::uint32_t>(vault.accounts.size()));
    for (const auto& record : vault.accounts) {
        append_blob(output, bytes_of(record.sid));
        append_blob(output, bytes_of(record.account_name));
        append_raw(output, record.record_id);
        append_u32(output, record.password_generation);
        append_u32(output, record.stale ? flag_stale : 0);
        append_raw(output, record.payload_salt);
        append_envelope(output, record.password);
        append_u32(output, static_cast<std::uint32_t>(record.wrappers.size()));
        for (const auto& wrapper : record.wrappers) {
            append_blob(output, bytes_of(wrapper.label));
            append_blob(output, wrapper.credential.id);
            append_raw(output, wrapper.credential.x);
            append_raw(output, wrapper.credential.y);
            append_raw(output, wrapper.credential.user_handle);
            append_u32(output, wrapper.credential.sign_count);
            append_raw(output, wrapper.salt);
            append_envelope(output, wrapper.wrapped_key);
            if (format_version >= 2) {
                append_u32(output, static_cast<std::uint32_t>(wrapper.protection_state));
                append_u64(output, wrapper.protection_checked_at_unix);
                append_u32(output, wrapper.protection_verification_version);
            } else if (wrapper.protection_state != ProtectionState::unknown) {
                invalid_vault("cannot discard verified protection metadata in schema 1");
            }
        }
    }
    const auto checksum = sha256(output);
    append_raw(output, checksum);
    if (output.size() > max_file) invalid_vault("vault exceeds size limit");
    return output;
}

Vault parse(std::span<const std::uint8_t> bytes) {
    if (bytes.size() < magic.size() + 8 + 32 || bytes.size() > max_file) invalid_vault("file size is outside the allowed range");
    const auto body = bytes.first(bytes.size() - 32);
    const auto checksum = sha256(body);
    if (!std::equal(checksum.begin(), checksum.end(), bytes.end() - 32)) invalid_vault("checksum mismatch");
    Reader reader(body);
    const auto header = reader.take(magic.size());
    if (!std::equal(magic.begin(), magic.end(), header.begin())) invalid_vault("unrecognized file");
    const auto source_schema = reader.u32();
    if (source_schema != 1 && source_schema != schema_version) invalid_vault("unsupported schema version");
    const auto count = reader.u32();
    if (count > max_accounts) invalid_vault("too many accounts");
    Vault vault;
    vault.source_schema = source_schema;
    for (std::uint32_t a = 0; a < count; ++a) {
        AccountRecord record;
        const auto sid = reader.blob(max_sid);
        record.sid.assign(sid.begin(), sid.end());
        const auto name = reader.blob(max_account_name);
        record.account_name.assign(name.begin(), name.end());
        reader.raw(record.record_id);
        record.password_generation = reader.u32();
        const auto flags = reader.u32();
        if (flags & ~flag_stale) invalid_vault("unknown record flags");
        record.stale = (flags & flag_stale) != 0;
        reader.raw(record.payload_salt);
        record.password = read_envelope(reader, max_password_units * sizeof(wchar_t));
        const auto wrappers = reader.u32();
        if (wrappers == 0 || wrappers > max_wrappers) invalid_vault("invalid key wrapper count");
        for (std::uint32_t w = 0; w < wrappers; ++w) {
            KeyWrapper wrapper;
            const auto label = reader.blob(max_label_units * sizeof(wchar_t));
            if (label.size() % sizeof(wchar_t) != 0) invalid_vault("key label is not UTF-16");
            wrapper.label.resize(label.size() / sizeof(wchar_t));
            std::memcpy(wrapper.label.data(), label.data(), label.size());
            const auto id = reader.blob(max_credential_id);
            wrapper.credential.id.assign(id.begin(), id.end());
            reader.raw(wrapper.credential.x);
            reader.raw(wrapper.credential.y);
            reader.raw(wrapper.credential.user_handle);
            wrapper.credential.sign_count = reader.u32();
            reader.raw(wrapper.salt);
            wrapper.wrapped_key = read_envelope(reader, 32);
            if (source_schema >= 2) {
                wrapper.protection_state = static_cast<ProtectionState>(reader.u32());
                wrapper.protection_checked_at_unix = reader.u64();
                wrapper.protection_verification_version = reader.u32();
            }
            record.wrappers.push_back(std::move(wrapper));
        }
        vault.accounts.push_back(std::move(record));
    }
    if (!reader.finished()) invalid_vault("trailing data");
    validate_vault(vault);
    return vault;
}

std::filesystem::path default_path() {
    PWSTR raw = nullptr;
    const HRESULT result = SHGetKnownFolderPath(FOLDERID_ProgramData, KF_FLAG_DEFAULT, nullptr, &raw);
    if (FAILED(result) || !raw) {
        CoTaskMemFree(raw);
        throw std::runtime_error("Cannot resolve ProgramData");
    }
    std::filesystem::path base(raw);
    CoTaskMemFree(raw);
    return base / L"HID-FIDO2-WinLogon" / L"vault.bin";
}

bool provider_version_supports_schema2(std::uint32_t major, std::uint32_t minor) noexcept {
    return major > 0 || minor >= 5;
}

bool installed_provider_supports_schema2() {
    const auto cp_path = std::wstring(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\") + credential_provider_clsid_text;
    HKEY key{};
    const auto found = RegOpenKeyExW(HKEY_LOCAL_MACHINE, cp_path.c_str(), 0, KEY_READ | KEY_WOW64_64KEY, &key);
    if (found == ERROR_FILE_NOT_FOUND || found == ERROR_PATH_NOT_FOUND) return true;
    if (found != ERROR_SUCCESS) win_error("Inspect active provider", found);
    RegCloseKey(key);
    const auto com_path = std::wstring(L"SOFTWARE\\Classes\\CLSID\\") + credential_provider_clsid_text + L"\\InprocServer32";
    std::array<wchar_t, 32768> path{};
    DWORD bytes = static_cast<DWORD>(path.size() * sizeof(wchar_t));
    const auto read = RegGetValueW(HKEY_LOCAL_MACHINE, com_path.c_str(), nullptr,
        RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY, nullptr, path.data(), &bytes);
    if (read != ERROR_SUCCESS || bytes < 2 * sizeof(wchar_t)) return false;
    const auto size = GetFileVersionInfoSizeW(path.data(), nullptr);
    if (!size || size > 1024 * 1024) return false;
    Bytes version(size);
    if (!GetFileVersionInfoW(path.data(), 0, size, version.data())) return false;
    VS_FIXEDFILEINFO* info{}; UINT length{};
    if (!VerQueryValueW(version.data(), L"\\", reinterpret_cast<void**>(&info), &length) ||
        length < sizeof(VS_FIXEDFILEINFO) || info->dwSignature != 0xfeef04bd) return false;
    return provider_version_supports_schema2(HIWORD(info->dwFileVersionMS), LOWORD(info->dwFileVersionMS));
}

void validate_machine_security_sddl(std::wstring_view sddl) {
    Security descriptor(sddl);
    validate_machine_descriptor(descriptor.attributes()->lpSecurityDescriptor);
}

Lock::Lock(const std::filesystem::path& vault_path, std::wstring_view sddl,
            std::chrono::milliseconds timeout) {
    if (timeout < std::chrono::milliseconds::zero() || timeout > std::chrono::seconds(3)) {
        throw std::invalid_argument("Vault lock timeout must be between zero and three seconds");
    }
    const auto path = checked_path(vault_path);
    Security security(sddl);
    const bool machine = machine_mode(sddl) || default_machine_path(path);
    if (machine) validate_machine_descriptor(security.attributes()->lpSecurityDescriptor);
    auto directories = pin_directories(path.parent_path(), &security, machine);
    Handle lock(CreateFileW(lock_path(path).c_str(), GENERIC_READ | GENERIC_WRITE | READ_CONTROL,
                            FILE_SHARE_READ | FILE_SHARE_WRITE, security.attributes(), OPEN_ALWAYS,
                            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    if (!lock.valid()) win_error("Open vault lock");
    reject_reparse(lock.get());
    if (machine) verify_machine_security(lock.get());
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    for (;;) {
        OVERLAPPED operation{};
        if (LockFileEx(lock.get(), LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &operation)) break;
        const DWORD code = GetLastError();
        if (code != ERROR_LOCK_VIOLATION) win_error("Lock vault", code);
        if (std::chrono::steady_clock::now() >= deadline) {
            throw ConcurrencyConflict("Machine vault is busy; retry manually");
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    directory_handles_.reserve(directories->size());
    for (auto& directory : *directories) directory_handles_.push_back(directory.release());
    handle_ = lock.release();
}

Lock::~Lock() {
    if (!handle_) return;
    OVERLAPPED operation{};
    UnlockFileEx(handle_, 0, 1, 0, &operation);
    CloseHandle(handle_);
    for (const auto directory : directory_handles_) CloseHandle(directory);
}

Vault load(const std::filesystem::path& requested, bool require_machine_security) {
    const auto path = checked_path(requested);
    const bool machine = require_machine_security || default_machine_path(path);
    auto directories = pin_directories(path.parent_path(), nullptr, machine);
    if (!directories) return {};
    // Readers keep a coherent handle to the previous file while a writer
    // atomically replaces the path. They must not block that replacement.
    Handle file(CreateFileW(path.c_str(), GENERIC_READ | READ_CONTROL, FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    if (!file.valid()) {
        const DWORD code = GetLastError();
        if (code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND) return {};
        win_error("Open machine vault", code);
    }
    reject_reparse(file.get());
    if (machine) verify_machine_security(file.get());
    LARGE_INTEGER length{};
    if (!GetFileSizeEx(file.get(), &length)) win_error("Read vault size");
    if (length.QuadPart <= 0 || length.QuadPart > static_cast<LONGLONG>(max_file)) {
        invalid_vault("file size is outside the allowed range");
    }
    Bytes data(static_cast<std::size_t>(length.QuadPart));
    std::size_t offset = 0;
    while (offset < data.size()) {
        DWORD read = 0;
        if (!ReadFile(file.get(), data.data() + offset, static_cast<DWORD>(data.size() - offset), &read, nullptr)) {
            win_error("Read machine vault");
        }
        if (!read) invalid_vault("truncated file");
        offset += read;
    }
    return parse(data);
}

void save(const std::filesystem::path& requested, const Vault& vault, std::wstring_view sddl) {
    const auto path = checked_path(requested);
    if (default_machine_path(path) && !installed_provider_supports_schema2()) {
        throw std::runtime_error("Aggiorna prima il Credential Provider a una versione compatibile: l'archivio corrente non e stato modificato");
    }
    const auto data = serialize(vault);
    Security security(sddl);
    const bool machine = machine_mode(sddl) || default_machine_path(path);
    if (machine) validate_machine_descriptor(security.attributes()->lpSecurityDescriptor);
    auto directories = pin_directories(path.parent_path(), &security, machine);
    {
        Handle existing(CreateFileW(path.c_str(), READ_CONTROL | FILE_READ_ATTRIBUTES, FILE_SHARE_READ,
                                    nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
        if (existing.valid()) {
            reject_reparse(existing.get());
            if (machine) verify_machine_security(existing.get());
        } else if (GetLastError() != ERROR_FILE_NOT_FOUND) {
            win_error("Inspect previous machine vault");
        }
    }
    static std::atomic<unsigned long long> sequence{0};
    std::filesystem::path temporary;
    Handle output;
    for (unsigned attempt = 0; attempt < 32; ++attempt) {
        temporary = path;
        temporary += L".tmp-" + std::to_wstring(GetCurrentProcessId()) + L"-" +
                     std::to_wstring(GetTickCount64()) + L"-" + std::to_wstring(sequence.fetch_add(1));
        output = Handle(CreateFileW(temporary.c_str(), GENERIC_WRITE, 0, security.attributes(), CREATE_NEW,
                                    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, nullptr));
        if (output.valid()) break;
        const DWORD code = GetLastError();
        if (code != ERROR_FILE_EXISTS && code != ERROR_ALREADY_EXISTS) win_error("Create temporary vault", code);
    }
    if (!output.valid()) throw std::runtime_error("Could not allocate a temporary vault");
    try {
        std::size_t offset = 0;
        while (offset < data.size()) {
            DWORD written = 0;
            if (!WriteFile(output.get(), data.data() + offset, static_cast<DWORD>(data.size() - offset), &written, nullptr)) {
                win_error("Write machine vault");
            }
            if (!written) throw std::runtime_error("Writing machine vault made no progress");
            offset += written;
        }
        if (!FlushFileBuffers(output.get())) win_error("Flush machine vault");
        output = Handle{};
        if (!MoveFileExW(temporary.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
            win_error("Atomically replace machine vault");
        }
    } catch (...) {
        output = Handle{};
        DeleteFileW(temporary.c_str());
        throw;
    }
}

namespace {
bool valid_backup_id(std::string_view id) {
    return id.size() == 32 && std::ranges::all_of(id, [](char value) {
        return (value >= '0' && value <= '9') || (value >= 'a' && value <= 'f');
    });
}
std::filesystem::path backup_file(const std::filesystem::path& vault_path, std::string_view id) {
    if (!valid_backup_id(id)) throw std::invalid_argument("Invalid backup identifier");
    return checked_path(vault_path).parent_path() / L"backups" / (std::wstring(id.begin(), id.end()) + L".bin");
}
std::uint64_t created_at(HANDLE file) {
    FILETIME time{};
    if (!GetFileTime(file, &time, nullptr, nullptr)) win_error("Read backup creation time");
    const auto ticks = (std::uint64_t{time.dwHighDateTime} << 32) | time.dwLowDateTime;
    constexpr std::uint64_t epoch = 116444736000000000ULL;
    return ticks >= epoch ? (ticks - epoch) / 10000000 : 0;
}
}

BackupInfo create_backup(const std::filesystem::path& requested, const AccountRecord& record, std::wstring_view sddl) {
    validate_record(record);
    const auto path = checked_path(requested);
    Security security(sddl);
    const bool machine = machine_mode(sddl) || default_machine_path(path);
    if (machine) validate_machine_descriptor(security.attributes()->lpSecurityDescriptor);
    auto directories = pin_directories(path.parent_path() / L"backups", &security, machine);
    const auto bytes = serialize(Vault{{record}});
    std::string id;
    Handle output;
    for (unsigned attempt = 0; attempt < 32; ++attempt) {
        constexpr char hex[] = "0123456789abcdef";
        id.clear();
        for (const auto byte : random_array<16>()) { id += hex[byte >> 4]; id += hex[byte & 15]; }
        output = Handle(CreateFileW(backup_file(path, id).c_str(), GENERIC_WRITE | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ, security.attributes(), CREATE_NEW, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, nullptr));
        if (output.valid()) break;
        const auto code = GetLastError();
        if (code != ERROR_FILE_EXISTS && code != ERROR_ALREADY_EXISTS) win_error("Create protected backup", code);
    }
    if (!output.valid()) throw std::runtime_error("Could not allocate a new backup");
    try {
        DWORD written{};
        if (!WriteFile(output.get(), bytes.data(), static_cast<DWORD>(bytes.size()), &written, nullptr) ||
            written != bytes.size() || !FlushFileBuffers(output.get())) win_error("Write protected backup");
        return {id, created_at(output.get()), record.password_generation, record.wrappers.size()};
    } catch (...) {
        output = Handle{};
        DeleteFileW(backup_file(path, id).c_str());
        throw;
    }
}

AccountRecord load_backup(const std::filesystem::path& requested, std::string_view id, std::string_view account_sid) {
    const auto path = checked_path(requested);
    const auto backup = load(backup_file(path, id), default_machine_path(path));
    if (backup.accounts.size() != 1 || !backup.find(account_sid)) {
        throw std::runtime_error("Backup is missing or belongs to another account");
    }
    return *backup.find(account_sid);
}

std::vector<BackupInfo> list_backups(const std::filesystem::path& requested, std::string_view account_sid) {
    const auto path = checked_path(requested);
    const auto directory = path.parent_path() / L"backups";
    const auto pinned = pin_directories(directory, nullptr, default_machine_path(path));
    if (!pinned) return {};
    std::vector<BackupInfo> result;
    unsigned entries{};
    for (const auto& entry : std::filesystem::directory_iterator(directory)) {
        if (++entries > 512) throw std::runtime_error("Too many backup directory entries");
        const auto name = entry.path().filename().wstring();
        if (name.size() != 36 || name.substr(32) != L".bin") continue;
        std::string id;
        for (const auto c : std::wstring_view(name).substr(0, 32)) {
            if (c > 0x7f) { id.clear(); break; }
            id.push_back(static_cast<char>(c));
        }
        if (!valid_backup_id(id)) continue;
        try {
            const auto record = load_backup(path, id, account_sid);
            Handle file(CreateFileW(entry.path().c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ, nullptr,
                OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
            if (!file.valid()) win_error("Inspect protected backup");
            reject_reparse(file.get());
            result.push_back({id, created_at(file.get()), record.password_generation, record.wrappers.size()});
        } catch (const std::exception&) {
            // A damaged/unrelated backup never makes the active vault unusable.
            // Explicit recovery of that ID still fails closed in load_backup.
        }
    }
    std::ranges::sort(result, [](const auto& left, const auto& right) { return left.created_at_unix > right.created_at_unix; });
    return result;
}

SecureBytes new_data_key() {
    SecureBytes key(32);
    if (BCryptGenRandom(nullptr, key.bytes().data(), 32, BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) {
        throw std::runtime_error("CNG data-key generation failed");
    }
    return key;
}

AccountRecord create_record(std::string sid, std::string account_name,
                            std::span<const std::uint8_t> password_utf16,
                            std::span<const std::uint8_t> data_key) {
    require_data_key(data_key);
    validate_password(password_utf16);
    AccountRecord record;
    record.sid = std::move(sid);
    record.account_name = std::move(account_name);
    if (!valid_sid(record.sid)) throw std::invalid_argument("Invalid account SID");
    if (record.account_name.empty() || record.account_name.size() > max_account_name ||
        record.account_name.find('\0') != std::string::npos) {
        throw std::invalid_argument("Invalid account name");
    }
    record.record_id = random_array<16>();
    record.payload_salt = random_array<32>();
    record.password = password::seal(data_key, payload_context(record), password_utf16);
    return record;
}

void add_wrapper(AccountRecord& record, std::wstring label, Credential credential,
                 const password::Salt& salt, std::span<const std::uint8_t> uv_secret,
                 std::span<const std::uint8_t> data_key) {
    require_data_key(data_key);
    if (!valid_label(label)) throw std::invalid_argument("Invalid key label");
    if (credential.id.empty() || credential.id.size() > max_credential_id) {
        throw std::invalid_argument("Invalid credential ID");
    }
    if (record.wrappers.size() >= max_wrappers) throw std::invalid_argument("Too many keys for this account");
    for (const auto& existing : record.wrappers) {
        if (existing.label == label) throw std::invalid_argument("Key label already enrolled");
        if (existing.credential.id == credential.id) throw std::invalid_argument("Credential already enrolled");
    }
    // Authenticate the DEK against the payload first: wrapping a wrong key would
    // silently create an unusable wrapper.
    (void)open_password(record, data_key);
    KeyWrapper wrapper;
    wrapper.label = std::move(label);
    wrapper.credential = std::move(credential);
    wrapper.credential.label.clear();
    wrapper.credential.owner_sid.clear();
    wrapper.salt = salt;
    wrapper.wrapped_key = password::seal(uv_secret, wrapper_context(record, wrapper), data_key);
    record.wrappers.push_back(std::move(wrapper));
}

SecureBytes unwrap_data_key(const AccountRecord& record, const KeyWrapper& wrapper,
                            std::span<const std::uint8_t> uv_secret) {
    auto key = password::open(uv_secret, wrapper_context(record, wrapper), wrapper.wrapped_key);
    if (key.size() != 32) throw std::runtime_error("Invalid unwrapped data-key size");
    return key;
}

SecureBytes open_password(const AccountRecord& record, std::span<const std::uint8_t> data_key) {
    require_data_key(data_key);
    auto password = password::open(data_key, payload_context(record), record.password);
    validate_password(password.bytes());
    return password;
}

void replace_password(AccountRecord& record, std::span<const std::uint8_t> data_key,
                      std::span<const std::uint8_t> password_utf16) {
    validate_password(password_utf16);
    (void)open_password(record, data_key);
    if (record.password_generation == UINT32_MAX) throw std::runtime_error("Password generation exhausted");
    AccountRecord updated = record;
    updated.payload_salt = random_array<32>();
    updated.password = password::seal(data_key, payload_context(updated), password_utf16);
    updated.password_generation = record.password_generation + 1;
    updated.stale = false;
    record = std::move(updated);
}

void rename_wrapper(AccountRecord& record, std::wstring_view label, std::wstring new_label) {
    if (!valid_label(new_label)) throw std::invalid_argument("Invalid key label");
    const auto found = std::find_if(record.wrappers.begin(), record.wrappers.end(),
        [&](const KeyWrapper& wrapper) { return wrapper.label == label; });
    if (found == record.wrappers.end()) throw std::invalid_argument("No key with that label");
    for (const auto& wrapper : record.wrappers) {
        if (&wrapper != &*found && wrapper.label == new_label) throw std::invalid_argument("Key label already enrolled");
    }
    found->label = std::move(new_label);
}

void remove_wrapper(AccountRecord& record, std::wstring_view label) {
    const auto found = std::find_if(record.wrappers.begin(), record.wrappers.end(),
                                    [&](const KeyWrapper& wrapper) { return wrapper.label == label; });
    if (found == record.wrappers.end()) throw std::invalid_argument("No key with that label");
    if (record.wrappers.size() == 1) throw std::invalid_argument("Cannot remove the last key of an account");
    record.wrappers.erase(found);
}

namespace {
bool same_envelope(const password::Envelope& left, const password::Envelope& right) {
    return left.version == right.version && left.nonce == right.nonce &&
           left.ciphertext == right.ciphertext && left.tag == right.tag;
}

void validate_account_authority(const AccountRecord& current, const AccountRecord& before) {
    if (current.sid != before.sid || current.account_name != before.account_name ||
        current.record_id != before.record_id || current.password_generation != before.password_generation ||
        current.payload_salt != before.payload_salt || current.stale != before.stale ||
        !same_envelope(current.password, before.password)) throw ConcurrencyConflict();
}

const KeyWrapper& authority_wrapper(const AccountRecord& record, std::span<const std::uint8_t> id) {
    for (const auto& wrapper : record.wrappers) {
        if (std::ranges::equal(wrapper.credential.id, id)) return wrapper;
    }
    throw ConcurrencyConflict("The authorizing key was revoked or replaced");
}

bool same_key_authority(const KeyWrapper& left, const KeyWrapper& right) {
    return left.credential.id == right.credential.id && left.credential.x == right.credential.x &&
        left.credential.y == right.credential.y && left.salt == right.salt &&
        same_envelope(left.wrapped_key, right.wrapped_key) &&
        left.protection_state == right.protection_state &&
        left.protection_checked_at_unix == right.protection_checked_at_unix &&
        left.protection_verification_version == right.protection_verification_version;
}
}

void validate_backup_restore(const AccountRecord& current, const AccountRecord& backup) {
    validate_record(current);
    validate_record(backup);
    if (current.sid != backup.sid || current.account_name != backup.account_name ||
        current.record_id != backup.record_id || current.password_generation != backup.password_generation ||
        current.payload_salt != backup.payload_salt) {
        throw std::runtime_error("Backup obsolete or from another record: use the Windows password and enroll again");
    }
    for (const auto& key : current.wrappers) {
        const auto& old_key = authority_wrapper(backup, key.credential.id);
        if (key.credential.x != old_key.credential.x || key.credential.y != old_key.credential.y ||
            key.salt != old_key.salt || !same_envelope(key.wrapped_key, old_key.wrapped_key) ||
            old_key.credential.sign_count > key.credential.sign_count) {
            throw std::runtime_error("Backup key authority does not match the current record");
        }
    }
}

void restore_password_payload(AccountRecord& current, const AccountRecord& backup,
                              std::span<const std::uint8_t> data_key,
                              std::span<const std::uint8_t> verified_windows_password) {
    validate_backup_restore(current, backup);
    auto recovered = open_password(backup, data_key);
    if (recovered.size() != verified_windows_password.size()) throw std::runtime_error("Verified password differs from the backup");
    volatile unsigned difference{};
    for (std::size_t index = 0; index < recovered.size(); ++index) {
        difference = difference | (recovered.bytes()[index] ^ verified_windows_password[index]);
    }
    if (difference) throw std::runtime_error("Verified password differs from the backup");
    auto restored = current;
    // Authenticate the compatible backup, rather than a possibly damaged
    // current payload. Key authority remains the current record's authority.
    restored.password = backup.password;
    replace_password(restored, data_key, recovered.bytes());
    current = std::move(restored);
}

void validate_key_authority(const AccountRecord& current, const AccountRecord& authorized_snapshot,
                            std::span<const std::uint8_t> credential_id) {
    if (credential_id.empty() || credential_id.size() > max_credential_id) throw ConcurrencyConflict();
    validate_account_authority(current, authorized_snapshot);
    const auto& current_key = authority_wrapper(current, credential_id);
    const auto& before_key = authority_wrapper(authorized_snapshot, credential_id);
    if (!same_key_authority(current_key, before_key) ||
        current_key.credential.sign_count != before_key.credential.sign_count) throw ConcurrencyConflict();
}

void apply_verified_key_use(AccountRecord& current, const AccountRecord& before,
                            const AccountRecord& verified, std::size_t wrapper_index) {
    if (wrapper_index >= before.wrappers.size() || wrapper_index >= verified.wrappers.size()) {
        throw ConcurrencyConflict("Invalid authorizing wrapper index");
    }
    const auto& old_key = before.wrappers[wrapper_index];
    const auto& used_key = verified.wrappers[wrapper_index];
    validate_key_authority(current, before, old_key.credential.id);
    validate_account_authority(verified, before);
    if (!same_key_authority(used_key, old_key)) throw ConcurrencyConflict("Verified key authority changed");
    const auto old_count = old_key.credential.sign_count;
    const auto new_count = used_key.credential.sign_count;
    if ((old_count != 0 || new_count != 0) && new_count <= old_count) {
        throw ConcurrencyConflict("Verified signature counter did not increase");
    }
    for (auto& wrapper : current.wrappers) {
        if (wrapper.credential.id == old_key.credential.id) {
            wrapper.credential.sign_count = new_count;
            return;
        }
    }
    throw ConcurrencyConflict();
}

bool suspend_password_generation(AccountRecord& current, const AccountRecord& attempted) noexcept {
    if (current.sid != attempted.sid || current.record_id != attempted.record_id ||
        current.password_generation != attempted.password_generation) return false;
    current.stale = true;
    return true;
}

Unlocked unlock_data_key(AccountRecord& record, const SecretSource& source) {
    for (std::size_t index = 0; index < record.wrappers.size(); ++index) {
        auto& wrapper = record.wrappers[index];
        SecureBytes secret;
        try {
            secret = source(wrapper);
        } catch (const CredentialNotOnKey&) {
            continue;
        }
        Unlocked result;
        result.data_key = unwrap_data_key(record, wrapper, secret.bytes());
        result.wrapper_index = index;
        return result;
    }
    throw CredentialNotOnKey();
}
}
