#pragma once
#include "hidfido/manager_json.hpp"
#include "hidfido/package_trust.hpp"
#include <filesystem>
#include <optional>

namespace hidfido::management {
inline constexpr wchar_t provider_clsid[] = L"{8B5D856B-C940-4AFB-A050-167F5D4F75E2}";
struct Key { std::wstring label; std::string proof; std::uint64_t checked{}; };
struct Backup { std::string id; std::uint64_t created{}, generation{}; };
struct Status {
    bool observed{}, enrolled{}, active{}, registered{}, compatible{}, has_deployment{};
    unsigned schema{}, password_generation{};
    std::wstring provider_version, provider_path;
    std::vector<Key> keys; std::vector<Backup> backups;
};
enum class VaultAction { enroll, verify, verify_protection, add_key, remove_key, update_password, backup, restore, rename_key };
Status parse_status(std::string_view data);
std::vector<std::wstring> vault_arguments(VaultAction action, std::wstring_view selection, std::wstring_view sid, std::wstring_view new_label = {});
bool can_run(const Status& status, VaultAction action, bool busy, bool demo) noexcept;
bool valid_key_label(std::wstring_view label) noexcept;
enum class SetupStep { unavailable, recovery, primary, password, spare, protection, activation, trial, complete };
// User confirmations are session-local guidance, never hardware/authentication proofs.
struct SetupChecks { bool recovery{}, primary_unlock{}, spare_unlock{}, restart{}; };
SetupStep setup_step(const Status& status, const SetupChecks& checks) noexcept;
enum class HomeAction { setup, installation, password, keys, verify };
struct HomePresentation { const wchar_t* heading; const wchar_t* detail; const wchar_t* action; HomeAction next; bool ready{}; };
HomePresentation home_presentation(const Status& status) noexcept;
// Presentation preferences only. Acknowledgements never authorize enrollment,
// activate the provider or create hardware proofs. Recovery is never persisted.
std::string setup_trials_binding(const Status& status);
SetupChecks load_setup_trials(const Status& status) noexcept;
bool save_setup_trials(const Status& status, const SetupChecks& checks) noexcept;
bool valid_id(std::string_view value, std::size_t length) noexcept;
std::wstring widen(std::string_view text);
std::string narrow(std::wstring_view text);
std::wstring current_sid();
bool elevated();
std::filesystem::path install_root();
std::string read_text(const std::filesystem::path& path, std::size_t maximum = 1024 * 1024);
void check_protected(const std::filesystem::path& path, bool directory);
struct Deployment {
    std::string id, release_id, manifest_hash;
    std::filesystem::path directory, provider, manifest;
    std::string version;
    bool prototype{}, native{};
};
class TransactionBackend {
public:
    virtual ~TransactionBackend() = default;
    virtual void preflight() = 0;
    virtual void prepare() = 0;
    virtual void remove_previous() = 0;
    virtual void activate_new() = 0;
    virtual void verify_new() = 0;
    virtual void cleanup_new() = 0;
    virtual void restore_previous() = 0;
};
struct TransactionResult { bool success{}, restored{}, recovery_required{}; };
TransactionResult transact(TransactionBackend& backend, bool has_previous);
std::optional<Deployment> active_deployment();
Status observe(const std::filesystem::path& protected_package, std::wstring_view sid);
std::string audit_current(std::wstring_view sid);
std::filesystem::path stage_package(const std::filesystem::path& source, std::string_view pin);
TransactionResult install_or_update(const std::filesystem::path& source, std::string_view pin, std::wstring_view sid, bool allow_legacy);
void uninstall_provider();
void create_shortcuts(const std::filesystem::path& protected_package);
std::string package_release(const std::filesystem::path& build, const std::filesystem::path& output, std::string_view version, std::string_view pin);
// Only metadata is captured. Interactive operations use separate native tools
// without redirecting PIN/password dialogs or returning their buffers to UI.
std::string capture_status(const std::filesystem::path& executable, std::wstring_view sid);
}
