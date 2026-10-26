#pragma once

// The diagnostic API accepts only enum labels and numeric codes. It has no
// parameter for exception messages, account/device identifiers or secret data.
#include <windows.h>
#include <exception>
#include <filesystem>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>

namespace hidfido::vault::diagnostic {
enum class Stage {
    startup, elevation, account_resolution, expected_account, enrollment, add_key,
    verify_key, update_password, remove_key, remove_account, status, vault_snapshot,
    vault_commit, vault_suspension, vault_recheck, pin_input, password_input,
    windows_password_validation, token_identity, confirmation, hid_inventory,
    hid_open, key_enrollment, key_unlock, key_assertion, key_gate, key_remove,
    key_reinsert, non_uv_probe, secret_comparison, password_decryption,
    ctap_info, ctap_make_credential, ctap_get_assertion, ctap_client_pin, ctap_other
};
enum class Error { none, cancelled, user, ctap, hid, windows_password, vault, conflict, other };

inline std::string_view name(Stage stage) noexcept {
    switch (stage) {
#define HIDFIDO_STAGE(value) case Stage::value: return #value
        HIDFIDO_STAGE(startup); HIDFIDO_STAGE(elevation); HIDFIDO_STAGE(account_resolution);
        HIDFIDO_STAGE(expected_account); HIDFIDO_STAGE(enrollment); HIDFIDO_STAGE(add_key);
        HIDFIDO_STAGE(verify_key); HIDFIDO_STAGE(update_password); HIDFIDO_STAGE(remove_key);
        HIDFIDO_STAGE(remove_account); HIDFIDO_STAGE(status); HIDFIDO_STAGE(vault_snapshot);
        HIDFIDO_STAGE(vault_commit); HIDFIDO_STAGE(vault_suspension); HIDFIDO_STAGE(vault_recheck);
        HIDFIDO_STAGE(pin_input); HIDFIDO_STAGE(password_input); HIDFIDO_STAGE(windows_password_validation);
        HIDFIDO_STAGE(token_identity); HIDFIDO_STAGE(confirmation); HIDFIDO_STAGE(hid_inventory);
        HIDFIDO_STAGE(hid_open); HIDFIDO_STAGE(key_enrollment); HIDFIDO_STAGE(key_unlock);
        HIDFIDO_STAGE(key_assertion); HIDFIDO_STAGE(key_gate); HIDFIDO_STAGE(key_remove);
        HIDFIDO_STAGE(key_reinsert); HIDFIDO_STAGE(non_uv_probe); HIDFIDO_STAGE(secret_comparison);
        HIDFIDO_STAGE(password_decryption); HIDFIDO_STAGE(ctap_info); HIDFIDO_STAGE(ctap_make_credential);
        HIDFIDO_STAGE(ctap_get_assertion); HIDFIDO_STAGE(ctap_client_pin); HIDFIDO_STAGE(ctap_other);
#undef HIDFIDO_STAGE
    }
    return "startup";
}
inline std::string_view name(Error error) noexcept {
    switch (error) {
#define HIDFIDO_ERROR(value) case Error::value: return #value
        HIDFIDO_ERROR(none); HIDFIDO_ERROR(cancelled); HIDFIDO_ERROR(user); HIDFIDO_ERROR(ctap);
        HIDFIDO_ERROR(hid); HIDFIDO_ERROR(windows_password); HIDFIDO_ERROR(vault);
        HIDFIDO_ERROR(conflict); HIDFIDO_ERROR(other);
#undef HIDFIDO_ERROR
    }
    return "other";
}

class Report {
public:
    explicit Report(const std::filesystem::path& path) {
        file_ = CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_NEW,
                            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        if (file_ == INVALID_HANDLE_VALUE) throw std::runtime_error("Cannot create a new public diagnostic report");
        try { record(Stage::startup, "started"); }
        catch (...) { CloseHandle(file_); file_ = INVALID_HANDLE_VALUE; throw; }
    }
    ~Report() { if (file_ != INVALID_HANDLE_VALUE) CloseHandle(file_); }
    Report(const Report&) = delete;
    Report& operator=(const Report&) = delete;

    void error(Error kind, std::optional<unsigned> ctap = {}, std::optional<unsigned long> win32 = {}) noexcept {
        try { record(failed_stage_.value_or(current_), "error", kind, ctap, win32); } catch (...) {}
        failed_stage_.reset();
    }
    void finished(int exit_code) noexcept {
        try { record(current_, "finished", {}, {}, {}, exit_code); } catch (...) {}
    }
private:
    friend class Scope;
    void record(Stage stage, std::string_view event, std::optional<Error> error = {},
                std::optional<unsigned> ctap = {}, std::optional<unsigned long> win32 = {},
                std::optional<int> exit_code = {}) {
        std::string line = "{\"schema\":1,\"tick_ms\":" + std::to_string(GetTickCount64()) +
            ",\"stage\":\"" + std::string(name(stage)) + "\",\"event\":\"" + std::string(event) + "\"";
        if (error) line += ",\"error_kind\":\"" + std::string(name(*error)) + "\"";
        if (ctap) line += ",\"ctap_status\":" + std::to_string(*ctap);
        if (win32) line += ",\"win32_error\":" + std::to_string(*win32);
        if (exit_code) line += ",\"exit_code\":" + std::to_string(*exit_code);
        line += "}\n";
        DWORD written{};
        if (!WriteFile(file_, line.data(), static_cast<DWORD>(line.size()), &written, nullptr) ||
            written != line.size() || !FlushFileBuffers(file_)) {
            throw std::runtime_error("Cannot flush public diagnostic report");
        }
    }
    HANDLE file_{INVALID_HANDLE_VALUE};
    Stage current_{Stage::startup};
    std::optional<Stage> failed_stage_;
};

class Scope {
public:
    Scope(Report* report, Stage stage) : report_(report), stage_(stage), exceptions_(std::uncaught_exceptions()) {
        if (!report_) return;
        previous_ = report_->current_;
        report_->current_ = stage_;
        report_->record(stage_, "started");
    }
    ~Scope() noexcept {
        if (!report_) return;
        const bool failed = std::uncaught_exceptions() > exceptions_;
        if (failed && !report_->failed_stage_) report_->failed_stage_ = stage_;
        try { report_->record(stage_, failed ? "failed" : "completed"); } catch (...) {}
        report_->current_ = previous_;
    }
    Scope(const Scope&) = delete;
    Scope& operator=(const Scope&) = delete;
private:
    Report* report_{};
    Stage stage_, previous_{Stage::startup};
    int exceptions_{};
};
}
