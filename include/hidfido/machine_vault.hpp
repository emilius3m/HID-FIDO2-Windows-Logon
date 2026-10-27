#pragma once

#include "hidfido/core.hpp"
#include "hidfido/password_envelope.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

// Machine vault for the password-backed logon path. One record per local
// account holds the Windows password sealed with a random data-encryption key
// (DEK); each enrolled FIDO2 key (e.g. Principale and Riserva) separately wraps
// that same DEK under its own UV hmac-secret output. A password change therefore
// re-seals only the payload and leaves every key wrapper valid.
namespace hidfido::vault {
using password::SecureBytes;

inline constexpr std::size_t max_accounts = 16;
inline constexpr std::size_t max_wrappers = 8;
inline constexpr std::uint32_t current_schema = 2;
inline constexpr std::uint32_t protection_verification_version = 1;
// UTF-16 code units of a Windows password accepted by this vault (LSA limit 256).
inline constexpr std::size_t max_password_units = 256;
// Owner Administrators and a protected DACL: SYSTEM (LogonUI/credential
// provider) and Administrators (the elevated enrollment tool) only. No
// inherited ACEs. The explicit owner keeps objects created by an elevated
// administrator from being owned by that user account.
inline constexpr wchar_t machine_sddl[] = L"O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)";

enum class ProtectionState : std::uint32_t { unknown = 0, verified_denied = 1, verified_distinct = 2 };
std::string_view protection_state_name(ProtectionState state) noexcept;

struct KeyWrapper {
    std::wstring label;                       // "Principale", "Riserva", ...
    Credential credential;                    // id, public key, user handle, counter
    password::Salt salt{};                    // public hmac-secret salt for this key
    password::Envelope wrapped_key;           // DEK sealed under this key's secret
    // Recorded only after an independent post-power-cycle UV/non-UV proof.
    // Schema-1 keys remain unknown; successful logon never upgrades this claim.
    ProtectionState protection_state{ProtectionState::unknown};
    std::uint64_t protection_checked_at_unix{};
    std::uint32_t protection_verification_version{};
};

struct AccountRecord {
    std::string sid;                          // canonical string SID, ASCII
    std::string account_name;                 // UTF-8 name bound at enrollment
    std::array<std::uint8_t, 16> record_id{}; // random, binds the payload envelope
    std::uint32_t password_generation{};      // incremented by every password update
    // Set after Windows rejected the stored password (changed, expired, ...).
    // A stale record is never replayed until the password is updated locally.
    bool stale{};
    password::Salt payload_salt{};
    password::Envelope password;              // UTF-16LE password sealed with the DEK
    std::vector<KeyWrapper> wrappers;
};

struct Vault {
    std::vector<AccountRecord> accounts;
    std::uint32_t source_schema{current_schema};
    AccountRecord* find(std::string_view sid) noexcept;
    const AccountRecord* find(std::string_view sid) const noexcept;
};

// Strict, bounded binary format with a trailing SHA-256 checksum (corruption
// detection only; confidentiality and integrity come from AES-GCM envelopes).
// Version 1 is writable only when all protection metadata is unknown, for
// explicit compatibility snapshots. Normal writes use the current schema.
Bytes serialize(const Vault& vault, std::uint32_t format_version = current_schema);
Vault parse(std::span<const std::uint8_t> bytes);

// %ProgramData%\HID-FIDO2-WinLogon\vault.bin
std::filesystem::path default_path();
// Schema-2 writes must not strand a provider with an incompatible reader. Checks
// inspect metadata only and never load the provider DLL.
bool provider_version_supports_schema2(std::uint32_t major, std::uint32_t minor) noexcept;
bool installed_provider_supports_schema2();

// Only the password payload may be recovered from a same-epoch backup. All
// current key authorities, revocations, counters and proof metadata are kept.
void validate_backup_restore(const AccountRecord& current, const AccountRecord& backup);
void restore_password_payload(AccountRecord& current, const AccountRecord& backup,
                              std::span<const std::uint8_t> data_key,
                              std::span<const std::uint8_t> verified_windows_password);

class ConcurrencyConflict : public std::runtime_error {
public:
    explicit ConcurrencyConflict(const char* message = "Machine vault changed during the operation")
        : std::runtime_error(message) {}
};

// Pure security-policy check, also used by descriptor tests without touching
// machine files. Requires protected, explicit SYSTEM/Administrators full access,
// trusted owner, and no other allow ACEs. Null/absent DACLs are rejected.
void validate_machine_security_sddl(std::wstring_view sddl);

// Optimistic authority/CAS checks. The caller holds Lock and reloads `current`.
// Changes to unrelated wrappers/counters are permitted; the authorizing wrapper
// and account/password epoch must match the snapshot exactly.
void validate_key_authority(const AccountRecord& current, const AccountRecord& authorized_snapshot,
                            std::span<const std::uint8_t> credential_id);
void apply_verified_key_use(AccountRecord& current, const AccountRecord& before,
                            const AccountRecord& verified, std::size_t wrapper_index);
// Suspend only the password generation actually rejected by Windows. A newer
// password or a replacement record must not inherit an older failure.
bool suspend_password_generation(AccountRecord& current, const AccountRecord& attempted) noexcept;

// Exclusive inter-process lock (vault.lock beside the vault) held across a
// load-modify-save sequence by the credential provider and the tool.
class Lock {
public:
    explicit Lock(const std::filesystem::path& vault_path, std::wstring_view sddl = machine_sddl,
                  std::chrono::milliseconds timeout = std::chrono::seconds(3));
    ~Lock();
    Lock(const Lock&) = delete;
    Lock& operator=(const Lock&) = delete;
private:
    void* handle_{};
    std::vector<void*> directory_handles_;
};

// A missing file yields an empty vault. Reparse points are rejected; the
// default path must also be owned by SYSTEM or Administrators.
Vault load(const std::filesystem::path& path, bool require_machine_security = false);
// Creates the directory and a temporary file with the given protected DACL,
// flushes it and atomically replaces the vault. Tests pass a current-user DACL.
void save(const std::filesystem::path& path, const Vault& vault,
          std::wstring_view sddl = machine_sddl);

struct BackupInfo {
    std::string id;
    std::uint64_t created_at_unix{};
    std::uint32_t password_generation{};
    std::size_t key_count{};
};
// Backups are immutable account-scoped snapshots next to the vault, in
// `backups/<32 lowercase hexadecimal characters>.bin`. No arbitrary import
// path is accepted. Production uses the same protected machine descriptor.
BackupInfo create_backup(const std::filesystem::path& vault_path, const AccountRecord& record,
                         std::wstring_view sddl = machine_sddl);
std::vector<BackupInfo> list_backups(const std::filesystem::path& vault_path, std::string_view account_sid);
AccountRecord load_backup(const std::filesystem::path& vault_path, std::string_view id, std::string_view account_sid);

SecureBytes new_data_key();
// Seals the UTF-16LE password (no terminator) with the DEK into a new record.
AccountRecord create_record(std::string sid, std::string account_name,
                            std::span<const std::uint8_t> password_utf16,
                            std::span<const std::uint8_t> data_key);
// Adds a wrapper for a verified credential. uv_secret must be the 32-byte UV
// hmac-secret output of `credential` for `salt`. Labels and IDs must be unique.
void add_wrapper(AccountRecord& record, std::wstring label, Credential credential,
                 const password::Salt& salt, std::span<const std::uint8_t> uv_secret,
                 std::span<const std::uint8_t> data_key);
SecureBytes unwrap_data_key(const AccountRecord& record, const KeyWrapper& wrapper,
                            std::span<const std::uint8_t> uv_secret);
SecureBytes open_password(const AccountRecord& record, std::span<const std::uint8_t> data_key);
// Re-seals a new password with the same DEK, increments the generation and
// clears the stale flag. Existing wrappers stay valid.
void replace_password(AccountRecord& record, std::span<const std::uint8_t> data_key,
                      std::span<const std::uint8_t> password_utf16);
// Refuses to remove the last wrapper.
void remove_wrapper(AccountRecord& record, std::wstring_view label);
// Metadata only: does not change credential IDs, counters, proof or envelopes.
// The caller holds Lock and rechecks the selected key's current authority.
void rename_wrapper(AccountRecord& record, std::wstring_view label, std::wstring new_label);

// Thrown by a SecretSource when the attached authenticator does not hold the
// wrapper's credential (CTAP2_ERR_NO_CREDENTIALS); unlock() tries the next one.
class CredentialNotOnKey : public std::runtime_error {
public:
    CredentialNotOnKey() : std::runtime_error("Credential not present on the attached key") {}
};
// Returns the verified UV hmac-secret for the wrapper; may update the wrapper's
// credential counter. Any exception other than CredentialNotOnKey aborts.
using SecretSource = std::function<SecureBytes(KeyWrapper& wrapper)>;
struct Unlocked {
    SecureBytes data_key;
    std::size_t wrapper_index{};
};
// Tries each wrapper in order; never retries a wrapper after a failure.
Unlocked unlock_data_key(AccountRecord& record, const SecretSource& source);
}
