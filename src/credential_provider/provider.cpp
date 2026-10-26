// SPDX-License-Identifier: MIT
// Original implementation using the documented Windows Credential Provider V2 ABI.
// A tile is offered only for local accounts enrolled in the machine vault. On
// submit, the FIDO2 PIN typed in the tile drives a direct CTAP2 hmac-secret
// assertion; the verified secret unwraps the vault key, the Windows password is
// decrypted in erased buffers only for the packed KERB_INTERACTIVE_UNLOCK_LOGON
// handed to LogonUI, and the standard Negotiate package authenticates it.
// The DLL has no registry-writing or self-registration path.
#include "hidfido/provider_ids.hpp"
#include "hidfido/ctap_client.hpp"
#include "hidfido/hid_transport.hpp"
#include "hidfido/logon_serialization.hpp"
#include "hidfido/machine_vault.hpp"
#include "hidfido/pin_text.hpp"
#include "hidfido/user_messages.hpp"
#include "diagnostic.hpp"

#include <windows.h>
#include <initguid.h>
#include <credentialprovider.h>
#include <ntsecapi.h>
#include <sddl.h>
#include <shlguid.h>
#include <wrl/client.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstring>
#include <cwchar>
#include <filesystem>
#include <memory>
#include <mutex>
#include <new>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace {
using Microsoft::WRL::ComPtr;
using hidfido::password::SecureBytes;
namespace vault = hidfido::vault;
namespace diagnostic = hidfido::credential_diagnostic;
using DiagnosticStage = diagnostic::Stage;
enum class CacheDiscard : std::uint64_t {
    unspecified, edited, deselected, credential_unadvised, provider_teardown,
    user_array, scenario, expired, allocation_failure, consumed, rejected_password
};
std::atomic<long> live_objects{};
std::atomic<long> server_locks{};

class ModuleObject {
public:
    ModuleObject() noexcept { ++live_objects; }
    ~ModuleObject() { --live_objects; }
    ModuleObject(const ModuleObject&) = delete;
    ModuleObject& operator=(const ModuleObject&) = delete;
};

constexpr wchar_t ready_text[] = L"Pronto: inserisci il PIN e premi Accedi.";
constexpr wchar_t suspended_text[] =
    L"Accesso con la chiave sospeso: la password Windows va aggiornata con hid-fido2-vault --update-password.";
constexpr wchar_t pin_format_text[] =
    L"Formato PIN non valido (almeno 4 caratteri). Nessun tentativo è stato inviato alla chiave.";

enum Field : DWORD { logo, label, title, instructions, pin, submit, status, field_count };
struct FieldDefinition {
    CREDENTIAL_PROVIDER_FIELD_TYPE type;
    PCWSTR text;
    GUID purpose;
};
const std::array<FieldDefinition, field_count> fields{{
    {CPFT_TILE_IMAGE, L"Chiave HID FIDO2", CPFG_CREDENTIAL_PROVIDER_LOGO},
    {CPFT_SMALL_TEXT, L"HID FIDO2", CPFG_CREDENTIAL_PROVIDER_LABEL},
    {CPFT_LARGE_TEXT, L"Chiave FIDO2", GUID{}},
    {CPFT_SMALL_TEXT, L"Collega Principale o Riserva, inserisci il PIN della chiave e toccala quando lampeggia.", GUID{}},
    {CPFT_PASSWORD_TEXT, L"PIN FIDO2", GUID{}},
    {CPFT_SUBMIT_BUTTON, L"Accedi", GUID{}},
    {CPFT_SMALL_TEXT, ready_text, GUID{}},
}};

// Key glyph in a unit square: ring head, shaft and two teeth. Mirrors
// inside_key in scripts/make-icon.py (the application icon); keep in sync.
bool inside_key(double u, double v) noexcept {
    const double dx = u - 0.32, dy = v - 0.50;
    const double d2 = dx * dx + dy * dy;
    return (d2 >= 0.09 * 0.09 && d2 <= 0.215 * 0.215) ||
           (u >= 0.50 && u <= 0.87 && v >= 0.452 && v <= 0.548) ||
           (u >= 0.69 && u <= 0.755 && v >= 0.548 && v <= 0.665) ||
           (u >= 0.80 && u <= 0.87 && v >= 0.548 && v <= 0.625);
}

// A refusal already phrased for the user; no Windows credential is produced.
struct Refusal {
    std::wstring message;
};

HRESULT copy_string(PCWSTR source, PWSTR* output) noexcept {
    if (!output) return E_POINTER;
    *output = nullptr;
    if (!source) return E_INVALIDARG;
    const auto bytes = (std::wcslen(source) + 1) * sizeof(wchar_t);
    auto* result = static_cast<PWSTR>(CoTaskMemAlloc(bytes));
    if (!result) return E_OUTOFMEMORY;
    std::memcpy(result, source, bytes);
    *output = result;
    return S_OK;
}

struct VaultLocation {
    std::filesystem::path path;
    std::wstring sddl;
};

// The production DLL always uses the fixed machine vault. Only the separately
// built test DLL (never registered) reads a test location from its environment.
std::optional<VaultLocation> vault_location() {
#ifdef HIDFIDO_CP_TESTING
    wchar_t path[MAX_PATH + 1]{}, sddl[512]{};
    if (!GetEnvironmentVariableW(L"HIDFIDO_TEST_VAULT_PATH", path, MAX_PATH) ||
        !GetEnvironmentVariableW(L"HIDFIDO_TEST_VAULT_SDDL", sddl, 511)) {
        return std::nullopt;
    }
    return VaultLocation{path, sddl};
#else
    return VaultLocation{vault::default_path(), vault::machine_sddl};
#endif
}

// Reads without the lock: the vault is only ever replaced atomically.
vault::Vault read_vault() {
    const auto location = vault_location();
    if (!location) return {};
    return vault::load(location->path);
}

std::string narrow_sid(PCWSTR sid) {
    std::string result;
    for (; *sid; ++sid) {
        if (*sid > 0x7f) throw std::invalid_argument("Non-ASCII SID");
        result.push_back(static_cast<char>(*sid));
    }
    return result;
}

struct LocalAccount {
    std::wstring domain;
    std::wstring user;
};

struct AttemptIdentity {
    std::string sid;
    std::array<std::uint8_t, 16> record_id{};
    std::uint32_t password_generation{};
};
#ifdef HIDFIDO_CP_TESTING
constexpr ULONGLONG cache_lifetime_ms = 500;
std::wstring test_mode() {
    wchar_t mode[64]{};
    const auto size = GetEnvironmentVariableW(L"HIDFIDO_TEST_BACKEND", mode, 64);
    return size && size < 64 ? std::wstring(mode) : std::wstring{};
}
#else
constexpr ULONGLONG cache_lifetime_ms = 15000;
#endif

LocalAccount local_account(PCWSTR sid) {
    PSID binary = nullptr;
    if (!ConvertStringSidToSidW(sid, &binary)) throw Refusal{L"Identità dell'account non valida."};
    wchar_t name[257]{}, domain[257]{}, computer[MAX_COMPUTERNAME_LENGTH + 1]{};
    DWORD name_size = 257, domain_size = 257, computer_size = MAX_COMPUTERNAME_LENGTH + 1;
    SID_NAME_USE use{};
    const BOOL found = LookupAccountSidW(nullptr, binary, name, &name_size, domain, &domain_size, &use);
    LocalFree(binary);
    if (!found || use != SidTypeUser) throw Refusal{L"Account Windows non trovato."};
    if (!GetComputerNameW(computer, &computer_size) ||
        CompareStringOrdinal(domain, -1, computer, -1, TRUE) != CSTR_EQUAL) {
        throw Refusal{L"Solo gli account locali di questo computer sono supportati."};
    }
    return {computer, name};
}

ULONG negotiate_package() {
    HANDLE lsa = nullptr;
    if (LsaConnectUntrusted(&lsa) < 0) throw Refusal{L"Servizio di autenticazione di Windows non disponibile."};
    char name_text[] = "Negotiate";
    LSA_STRING name{};
    name.Buffer = name_text;
    name.Length = static_cast<USHORT>(sizeof(name_text) - 1);
    name.MaximumLength = static_cast<USHORT>(sizeof(name_text));
    ULONG package = 0;
    const NTSTATUS status = LsaLookupAuthenticationPackage(lsa, &name, &package);
    LsaDeregisterLogonProcess(lsa);
    if (status < 0) throw Refusal{L"Pacchetto di autenticazione Windows non disponibile."};
    return package;
}

// Workers only post a non-sensitive wake-up. COM event interfaces are touched
// exclusively by the window's owning (Advise) apartment. No provider/credential
// pointer is carried in a queued message.
struct Notifications {
    static constexpr UINT message = WM_APP + 0x37;
    std::mutex mutex;
    HWND window{};
    UINT_PTR cookie{};
    bool available() {
        std::lock_guard lock(mutex);
        return window != nullptr;
    }
    void notify() noexcept {
        std::lock_guard lock(mutex);
        if (window) {
            const BOOL posted = PostMessageW(window, message, cookie, 0);
            diagnostic::write(DiagnosticStage::notification, posted != FALSE, posted ? 0 : GetLastError());
        }
    }
};

class Credential final : public ICredentialProviderCredential2, private ModuleObject {
public:
    Credential(PWSTR owned_sid, CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario, bool suspended,
               std::shared_ptr<Notifications> notifications)
        : sid_(owned_sid), scenario_(scenario), suspended_(suspended),
          status_text_(suspended ? suspended_text : ready_text), notifications_(std::move(notifications)) {}
    ~Credential() { CoTaskMemFree(sid_); }

    IFACEMETHODIMP QueryInterface(REFIID iid, void** output) override {
        if (!output) return E_POINTER;
        *output = nullptr;
        if (iid == IID_IUnknown || iid == __uuidof(ICredentialProviderCredential) ||
            iid == __uuidof(ICredentialProviderCredential2)) {
            *output = static_cast<ICredentialProviderCredential2*>(this);
        } else {
            return E_NOINTERFACE;
        }
            AddRef();
            return S_OK;
    }
    IFACEMETHODIMP_(ULONG) AddRef() override { return ++references_; }
    IFACEMETHODIMP_(ULONG) Release() override {
        const ULONG left = --references_;
        if (!left) delete this;
        return left;
    }
    IFACEMETHODIMP Advise(ICredentialProviderCredentialEvents* events) override {
        diagnostic::write(DiagnosticStage::credential_advise);
        if (!events) return E_POINTER;
        ComPtr<ICredentialProviderCredentialEvents> incoming(events), previous;
        {
            std::lock_guard lock(state_mutex_);
            previous.Swap(events_);
            incoming.Swap(events_);
            advise_thread_ = GetCurrentThreadId();
            ++events_generation_;
        }
        return S_OK;
    }
    IFACEMETHODIMP UnAdvise() override {
        diagnostic::write(DiagnosticStage::credential_unadvise);
        ComPtr<ICredentialProviderCredentialEvents> previous;
        {
            std::lock_guard lock(state_mutex_);
            expire_cache_locked();
            // LogonUI detaches this UI sink while re-enumerating after our
            // CredentialsChanged request. Preserve only the protected result
            // explicitly offered for that one handoff, never an in-flight PIN
            // operation or an unsolicited/unbounded cached credential.
            if (!ui_handoff_ || !cache_ready_locked()) {
                cancel_locked(CacheDiscard::credential_unadvised);
            }
            advise_thread_ = 0;
            ++events_generation_;
            previous.Swap(events_);
        }
        // Release outside the mutex: even IUnknown::Release may re-enter.
        return S_OK;
    }
    IFACEMETHODIMP SetSelected(BOOL* auto_logon) override {
        if (!auto_logon) return E_POINTER;
        *auto_logon = auto_logon_ready() ? TRUE : FALSE;
        diagnostic::write(DiagnosticStage::selected, *auto_logon);
        return S_OK;
    }
    IFACEMETHODIMP SetDeselected() override {
        diagnostic::write(DiagnosticStage::deselected);
        return Disconnect(CacheDiscard::deselected);
    }
    IFACEMETHODIMP GetUserSid(PWSTR* output) override { return copy_string(sid_, output); }
    IFACEMETHODIMP GetFieldState(DWORD id, CREDENTIAL_PROVIDER_FIELD_STATE* state,
                                 CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* interactive) override {
        if (state) *state = CPFS_HIDDEN;
        if (interactive) *interactive = CPFIS_NONE;
        if (!state || !interactive) return E_POINTER;
        if (id >= field_count) return E_INVALIDARG;
        *state = id == logo || id == title ? CPFS_DISPLAY_IN_BOTH : CPFS_DISPLAY_IN_SELECTED_TILE;
        if (id == pin) *interactive = CPFIS_FOCUSED;
        return S_OK;
    }
    IFACEMETHODIMP GetStringValue(DWORD id, PWSTR* output) override {
        if (!output) return E_POINTER;
        *output = nullptr;
        if (id >= field_count || id == logo) return E_INVALIDARG;
        // The PIN is never echoed back to LogonUI.
        if (id == pin) return copy_string(L"", output);
        if (id == status) {
            std::lock_guard lock(state_mutex_);
            return copy_string(status_text_.c_str(), output);
        }
        return copy_string(fields[id].text, output);
    }
    IFACEMETHODIMP GetBitmapValue(DWORD id, HBITMAP* output) override {
        if (!output) return E_POINTER;
        *output = nullptr;
        if (id != logo) return E_INVALIDARG;
        // Sign-in option logo: anti-aliased white key on a transparent
        // background (premultiplied alpha), the glyph of resources/hid-fido2.ico.
        // Drawn here so LogonUI loads no image decoder, resource or file.
        constexpr LONG side = 128;
        constexpr int samples = 4;
        BITMAPINFO info{};
        info.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
        info.bmiHeader.biWidth = side;
        info.bmiHeader.biHeight = -side;
        info.bmiHeader.biPlanes = 1;
        info.bmiHeader.biBitCount = 32;
        info.bmiHeader.biCompression = BI_RGB;
        void* raw = nullptr;
        HBITMAP bitmap = CreateDIBSection(nullptr, &info, DIB_RGB_COLORS, &raw, nullptr, 0);
        if (!bitmap || !raw) {
            if (bitmap) DeleteObject(bitmap);
            return E_OUTOFMEMORY;
        }
        auto* pixels = static_cast<DWORD*>(raw);
        for (LONG y = 0; y < side; ++y) {
            for (LONG x = 0; x < side; ++x) {
                int covered = 0;
                for (int sy = 0; sy < samples; ++sy) {
                    for (int sx = 0; sx < samples; ++sx) {
                        const double u = (x + (sx + 0.5) / samples) / side;
                        const double v = (y + (sy + 0.5) / samples) / side;
                        if (inside_key(u, v)) ++covered;
                    }
                }
                const DWORD alpha = static_cast<DWORD>(covered * 255 / (samples * samples));
                pixels[y * side + x] = (alpha << 24) | (alpha << 16) | (alpha << 8) | alpha;
            }
        }
        *output = bitmap;
        return S_OK;
    }
    IFACEMETHODIMP GetSubmitButtonValue(DWORD id, DWORD* adjacent) override {
        if (!adjacent) return E_POINTER;
        *adjacent = 0;
        if (id != submit) return E_INVALIDARG;
        *adjacent = pin;
        return S_OK;
    }
    IFACEMETHODIMP GetCheckboxValue(DWORD, BOOL* checked, PWSTR* text) override {
        if (checked) *checked = FALSE;
        if (text) *text = nullptr;
        return !checked || !text ? E_POINTER : E_INVALIDARG;
    }
    IFACEMETHODIMP GetComboBoxValueCount(DWORD, DWORD* count, DWORD* selected) override {
        if (count) *count = 0;
        if (selected) *selected = 0;
        return !count || !selected ? E_POINTER : E_INVALIDARG;
    }
    IFACEMETHODIMP GetComboBoxValueAt(DWORD, DWORD, PWSTR* output) override {
        if (!output) return E_POINTER;
        *output = nullptr;
        return E_INVALIDARG;
    }
    IFACEMETHODIMP SetStringValue(DWORD id, PCWSTR value) override {
        if (id != pin) return E_INVALIDARG;
        if (!value) return E_POINTER;
        const auto units = wcsnlen_s(value, 257);
        try {
            SecureBytes typed(units * sizeof(wchar_t));
            std::memcpy(typed.bytes().data(), value, typed.size());
            std::lock_guard lock(state_mutex_);
            // Input tracing must not emit once per keystroke: that would
            // disclose PIN length through event counts. Record only an
            // accepted empty-to-nonempty transition, plus UI clear events.
            if (!units || (!connecting_ && pin_.size() == 0)) {
                diagnostic::write(units ? DiagnosticStage::set_string_nonempty : DiagnosticStage::set_string_empty,
                                  state_flags_locked());
            }
            if (connecting_) return HRESULT_FROM_WIN32(ERROR_BUSY);
            pin_ = std::move(typed);
            discard_cache_locked(CacheDiscard::edited);
            cached_ = SecureBytes{};
            cached_identity_.reset();
            return S_OK;
        } catch (...) {
            clear_pin();
            return E_OUTOFMEMORY;
        }
    }
    IFACEMETHODIMP SetCheckboxValue(DWORD, BOOL) override { return E_INVALIDARG; }
    IFACEMETHODIMP SetComboBoxSelectedValue(DWORD, DWORD) override { return E_INVALIDARG; }
    IFACEMETHODIMP CommandLinkClicked(DWORD) override { return E_INVALIDARG; }

    // PLAP Connect is not exposed. LOGON/UNLOCK begin with GetSerialization.
    HRESULT Disconnect(CacheDiscard reason = CacheDiscard::unspecified) {
        {
            std::lock_guard lock(state_mutex_);
            diagnostic::write(DiagnosticStage::cancel, static_cast<std::uint64_t>(reason), state_flags_locked());
            cancel_locked(reason);
        }
        refresh_fields();
        return S_OK;
    }
    // Provider teardown/scenario changes must never call a LogonUI event while
    // iterating the provider's credential collection. Keep the COM reference
    // until normal UnAdvise/destruction, but disarm it without calling out.
    void cancel_silently(CacheDiscard reason = CacheDiscard::provider_teardown) {
        std::lock_guard lock(state_mutex_);
        diagnostic::write(DiagnosticStage::cancel_silent, static_cast<std::uint64_t>(reason), state_flags_locked());
        cancel_locked(reason);
        advise_thread_ = 0;
        ++events_generation_;
    }

    IFACEMETHODIMP GetSerialization(CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* response,
        CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* serialization, PWSTR* text,
        CREDENTIAL_PROVIDER_STATUS_ICON* icon) override {
        // Keep all outputs fail-closed even on malformed calls or allocation failure.
        if (response) *response = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
        if (serialization) *serialization = {};
        if (text) *text = nullptr;
        if (icon) *icon = CPSI_ERROR;
        if (!response || !serialization || !text || !icon) {
            Disconnect();
            return E_POINTER;
        }
        try {
            std::unique_lock lock(state_mutex_);
            diagnostic::write(DiagnosticStage::get_serialization, state_flags_locked());
            // This callback performs no FIDO, file, registry or LSA operation.
            // First submit launches a worker; a later auto-logon submit consumes
            // only the short-lived CredProtect-protected result once.
            if (cached_.size() && GetTickCount64() >= cache_deadline_) {
                discard_cache_locked(CacheDiscard::expired);
                cached_ = SecureBytes{};
                cached_identity_.reset();
                status_text_ = L"Verifica scaduta: inserisci nuovamente il PIN e premi Accedi.";
            }
            if (!cached_.size() || !cached_identity_ || cancelled_) {
                if (connecting_ || pending_identity_) {
                    diagnostic::write(DiagnosticStage::serialization_wait, state_flags_locked());
                    *icon = CPSI_NONE;
                    return copy_string(status_text_.c_str(), text);
                }
                if (suspended_) status_text_ = suspended_text;
                else if (pin_.size() == 0) status_text_ = L"Inserisci il PIN FIDO2 della chiave.";
                else {
                    // Format is checked locally before scheduling any key I/O.
                    try {
                        const std::span<const wchar_t> units(reinterpret_cast<const wchar_t*>(pin_.bytes().data()),
                                                             pin_.size() / sizeof(wchar_t));
                        auto checked = hidfido::pin::utf8_from_typed(units);
                    } catch (...) {
                        pin_ = SecureBytes{};
                        status_text_ = pin_format_text;
                        return copy_string(status_text_.c_str(), text);
                    }
                    if (!notifications_->available()) {
                        pin_ = SecureBytes{};
                        status_text_ = L"Interfaccia di accesso non pronta. Seleziona nuovamente l'opzione chiave.";
                    } else {
                        auto typed = std::move(pin_);
                        connecting_ = true;
                        cancelled_ = false;
                        status_text_ = L"Verifica della chiave in corso. Tocca la chiave quando lampeggia.";
                        diagnostic::write(DiagnosticStage::serialization_start, state_flags_locked());
                        try {
                            start_worker(std::move(typed));
                        } catch (...) {
                            connecting_ = false;
                            throw;
                        }
                        lock.unlock();
                        refresh_fields();
                        *icon = CPSI_NONE;
                        return S_OK;
                    }
                }
                pin_ = SecureBytes{};
                diagnostic::write(DiagnosticStage::serialization_empty, state_flags_locked());
                return copy_string(status_text_.c_str(), text);
            }
            auto* buffer = static_cast<BYTE*>(CoTaskMemAlloc(cached_.size()));
            if (!buffer) {
                discard_cache_locked(CacheDiscard::allocation_failure);
                cached_ = SecureBytes{};
                cached_identity_.reset();
                return E_OUTOFMEMORY;
            }
            std::memcpy(buffer, cached_.bytes().data(), cached_.size());
            serialization->ulAuthenticationPackage = cached_package_;
            serialization->clsidCredentialProvider = hidfido::credential_provider_clsid;
            serialization->rgbSerialization = buffer;
            serialization->cbSerialization = static_cast<ULONG>(cached_.size());
            pending_identity_ = std::move(cached_identity_);
            cached_identity_.reset();
            diagnostic::write(DiagnosticStage::serialization_return, cached_package_, state_flags_locked());
            discard_cache_locked(CacheDiscard::consumed);
            cached_ = SecureBytes{};
            *response = CPGSR_RETURN_CREDENTIAL_FINISHED;
            *icon = CPSI_NONE;
            return S_OK;
        } catch (...) { return E_UNEXPECTED; }
    }

    bool auto_logon_ready() {
        std::lock_guard lock(state_mutex_);
        expire_cache_locked();
        return cache_ready_locked();
    }
    bool begin_ui_handoff() {
        std::lock_guard lock(state_mutex_);
        expire_cache_locked();
        if (!cache_ready_locked()) return false;
        // Set before calling out: LogonUI may detach/rebind synchronously or
        // after CredentialsChanged returns. Consumption/cancellation/TTL ends
        // this single handoff; attaching a new UI sink does not extend its TTL.
        ui_handoff_ = true;
        return true;
    }
    void abort_ui_handoff() {
        std::lock_guard lock(state_mutex_);
        if (ui_handoff_) cancel_locked(CacheDiscard::unspecified);
    }
    bool expire_cache() {
        std::lock_guard lock(state_mutex_);
        return expire_cache_locked();
    }
    void refresh_fields() noexcept {
        try {
            ComPtr<ICredentialProviderCredentialEvents> events;
            std::wstring text;
            ULONGLONG generation{};
            {
                std::lock_guard lock(state_mutex_);
                if (advise_thread_ != GetCurrentThreadId()) return;
                events = events_;
                text = status_text_;
                generation = events_generation_;
            }
            if (events) {
                const auto pin_result = events->SetFieldString(static_cast<ICredentialProviderCredential2*>(this), pin, L"");
                diagnostic::write(DiagnosticStage::field_update, pin, static_cast<std::uint32_t>(pin_result));
                {
                    std::lock_guard lock(state_mutex_);
                    if (generation != events_generation_ || advise_thread_ != GetCurrentThreadId()) return;
                }
                const auto status_result = events->SetFieldString(static_cast<ICredentialProviderCredential2*>(this), status, text.c_str());
                diagnostic::write(DiagnosticStage::field_update, status, static_cast<std::uint32_t>(status_result));
            }
        } catch (...) {}
    }
    IFACEMETHODIMP ReportResult(NTSTATUS result, NTSTATUS substatus, PWSTR* text,
                                CREDENTIAL_PROVIDER_STATUS_ICON* icon) override {
        diagnostic::write(DiagnosticStage::report_result, static_cast<std::uint32_t>(result),
                          static_cast<std::uint32_t>(substatus));
        if (text) *text = nullptr;
        if (icon) *icon = CPSI_NONE;
        if (!text || !icon) return E_POINTER;
        try {
            std::optional<AttemptIdentity> sent;
            hidfido::logon::ResultAdvice advice;
            {
                std::lock_guard lock(state_mutex_);
                if (!pending_identity_) return S_OK;
                advice = hidfido::logon::advise_logon_result(result, substatus);
                sent = std::move(pending_identity_);
                pending_identity_.reset();
                if (advice.suspend_record) {
                    // Remains suspended even if the following disk operation
                    // fails. Repeated clicks cannot replay a rejected password.
                    suspended_ = true;
                    discard_cache_locked(CacheDiscard::rejected_password);
                    cached_ = SecureBytes{};
                    cached_identity_.reset();
                }
            }
            if (advice.success) {
                set_status(ready_text);
                return S_OK;
            }
            auto message = advice.message;
            if (advice.suspend_record) {
                try {
                    suspend_record(*sent);
                } catch (...) {
                    message += L" Impossibile sospendere l'archivio: non riprovare con la chiave.";
                }
            }
            *icon = CPSI_ERROR;
            set_status(message);
            return copy_string(message.c_str(), text);
        } catch (...) {
            return E_UNEXPECTED;
        }
    }
private:
    bool cache_ready_locked() const noexcept {
        return !connecting_ && !cancelled_ && cached_.size() != 0 &&
               cached_identity_.has_value() && !pending_identity_;
    }
    std::uint64_t state_flags_locked() const noexcept {
        return (pin_.size() ? 1ull : 0ull) | (cached_.size() ? 2ull : 0ull) |
               (cached_identity_ ? 4ull : 0ull) | (cancelled_ ? 8ull : 0ull) |
               (connecting_ ? 16ull : 0ull) | (pending_identity_ ? 32ull : 0ull) |
               (suspended_ ? 64ull : 0ull);
    }
    void discard_cache_locked(CacheDiscard reason) noexcept {
        ui_handoff_ = false;
        if (cached_.size() || cached_identity_) {
            diagnostic::write(DiagnosticStage::cache_discarded,
                              static_cast<std::uint64_t>(reason), state_flags_locked());
        }
    }
    void cancel_locked(CacheDiscard reason) {
        discard_cache_locked(reason);
        cancelled_ = true;
        cached_ = SecureBytes{};
        cached_identity_.reset();
        pin_ = SecureBytes{};
    }
    bool expire_cache_locked() {
        if (!cached_.size() || GetTickCount64() < cache_deadline_) return false;
        diagnostic::write(DiagnosticStage::cache_expired, state_flags_locked());
        discard_cache_locked(CacheDiscard::expired);
        cached_ = SecureBytes{};
        cached_identity_.reset();
        status_text_ = L"Verifica scaduta: inserisci nuovamente il PIN e premi Accedi.";
        return true;
    }
    struct Worker {
        Credential* credential;
        SecureBytes typed;
        HMODULE module{};
    };
    static void CALLBACK worker_callback(PTP_CALLBACK_INSTANCE instance, void* raw, PTP_WORK work) noexcept {
        auto* context = static_cast<Worker*>(raw);
        auto* self = context->credential;
        // Keep the DLL mapped through the callback's return, including after
        // the final credential Release. A detached std::thread cannot guarantee
        // that its return address survives DllCanUnloadNow becoming S_OK.
        FreeLibraryWhenCallbackReturns(instance, context->module);
        CallbackMayRunLong(instance);
        auto typed = std::move(context->typed);
        delete context;
        self->run_worker(std::move(typed));
        self->Release();
        CloseThreadpoolWork(work);
    }
    void start_worker(SecureBytes typed) {
        auto context = std::make_unique<Worker>(Worker{this, std::move(typed), nullptr});
        if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                                reinterpret_cast<LPCWSTR>(&worker_callback), &context->module)) {
            throw std::runtime_error("Cannot retain authentication module");
        }
        const auto work = CreateThreadpoolWork(worker_callback, context.get(), nullptr);
        if (!work) {
            FreeLibrary(context->module);
            throw std::runtime_error("Cannot create authentication worker");
        }
        AddRef();
        context.release();
        SubmitThreadpoolWork(work);
    }
    void run_worker(SecureBytes typed) noexcept {
        diagnostic::write(DiagnosticStage::worker_start);
        const HRESULT initialized = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        try {
            if (FAILED(initialized)) throw std::runtime_error("Cannot initialize authentication worker");
            const hidfido::ctap::ContinueCheck keep_going = [this] { return !cancelled_.load(); };
            ULONG package{};
            AttemptIdentity identity;
            auto packed = authenticate(package, identity, keep_going, std::move(typed));
            require_continue(keep_going);
            std::lock_guard lock(state_mutex_);
            if (cancelled_) throw Refusal{L"Operazione annullata."};
            cached_ = std::move(packed);
            ui_handoff_ = false;
            cached_package_ = package;
            cached_identity_ = std::move(identity);
            cache_deadline_ = GetTickCount64() + cache_lifetime_ms;
            status_text_ = L"Verifica chiave completata; invio a Windows.";
            diagnostic::write(DiagnosticStage::cache_ready, state_flags_locked());
            diagnostic::write(DiagnosticStage::worker_ready, package);
        } catch (const Refusal& refusal) {
            diagnostic::write(DiagnosticStage::worker_refusal);
            set_status(refusal.message);
        } catch (const std::exception& error) {
            if (const auto* status = dynamic_cast<const hidfido::ctap::StatusError*>(&error)) {
                diagnostic::write(DiagnosticStage::worker_error, 1, status->status());
            } else if (const auto* transport = dynamic_cast<const hidfido::ctap::HidTransportError*>(&error)) {
                diagnostic::write(DiagnosticStage::worker_error, 2, transport->code());
            } else diagnostic::write(DiagnosticStage::worker_error, 3);
            try { set_status(hidfido::ui::describe_failure(error)); } catch (...) {}
        } catch (...) {
            diagnostic::write(DiagnosticStage::worker_error, 4);
            set_status(L"Verifica della chiave non riuscita.");
        }
        typed.clear();
        // No later operation in the old worker may cancel a new attempt.
        connecting_ = false;
        diagnostic::write(DiagnosticStage::worker_finished, cancelled_ ? 1 : 0);
        notifications_->notify();
        if (SUCCEEDED(initialized)) CoUninitialize();
    }
    static void require_continue(const hidfido::ctap::ContinueCheck& keep_going) {
        if (keep_going && !keep_going()) {
            throw hidfido::ctap::HidTransportError("FIDO operation cancelled", ERROR_CANCELLED);
        }
    }
    SecureBytes authenticate(ULONG& package, AttemptIdentity& identity,
                              const hidfido::ctap::ContinueCheck& keep_going, SecureBytes typed) {
        require_continue(keep_going);
        {
            std::lock_guard lock(state_mutex_);
            if (suspended_) throw Refusal{suspended_text};
        }
        if (typed.size() == 0) throw Refusal{L"Inserisci il PIN FIDO2 della chiave."};
        SecureBytes pin_utf8;
        try {
            const std::span<const wchar_t> units(reinterpret_cast<const wchar_t*>(typed.bytes().data()),
                                                 typed.size() / sizeof(wchar_t));
            pin_utf8 = hidfido::pin::utf8_from_typed(units);
        } catch (const std::exception&) {
            throw Refusal{pin_format_text};
        }
        typed = SecureBytes{};

        // Everything that can fail without the key is checked before the PIN
        // reaches the authenticator.
        const auto sid = narrow_sid(sid_);
        diagnostic::write(DiagnosticStage::vault_snapshot);
        auto snapshot = read_vault();
        auto* found = snapshot.find(sid);
        if (!found) throw Refusal{L"Nessuna chiave registrata per questo account."};
        auto record = *found;
        if (record.stale) {
            { std::lock_guard lock(state_mutex_); suspended_ = true; }
            throw Refusal{suspended_text};
        }
        const auto before = record;
        identity = {record.sid, record.record_id, record.password_generation};
#ifdef HIDFIDO_CP_TESTING
        const auto mode = test_mode();
        if (!mode.empty()) return authenticate_synthetic(package, record, before, mode, keep_going);
#endif
        const auto account = local_account(sid_);
        package = negotiate_package();
        const auto devices = hidfido::ctap::enumerate_fido_hid();
        if (devices.empty()) throw Refusal{L"Collega la chiave FIDO2 (Principale o Riserva)."};
        if (devices.size() != 1) throw Refusal{L"Collega una sola chiave FIDO2."};

        set_status(L"Tocca la chiave quando lampeggia.");
        require_continue(keep_going);
        auto transport = hidfido::ctap::open_hid_transport(devices.front(), std::chrono::seconds(60), 3, keep_going);
        hidfido::ctap::HmacClient client(*transport);
        diagnostic::write(DiagnosticStage::hmac_start);
        auto unlocked = vault::unlock_data_key(record, [&](vault::KeyWrapper& wrapper) {
            try {
                return client.get_secret(pin_utf8.bytes(), wrapper.credential, wrapper.salt);
            } catch (const hidfido::ctap::StatusError& error) {
                if (error.status() == 0x2e) throw vault::CredentialNotOnKey();
                throw;
            }
        });
        pin_utf8.clear();
        diagnostic::write(DiagnosticStage::hmac_complete);
        require_continue(keep_going);
        persist_counters(before, record, unlocked.wrapper_index);
        diagnostic::write(DiagnosticStage::vault_commit);
        require_continue(keep_going);
        auto password = vault::open_password(record, unlocked.data_key.bytes());
        diagnostic::write(DiagnosticStage::password_opened);
        unlocked.data_key.clear();
        const auto kind = scenario_ == CPUS_UNLOCK_WORKSTATION ? hidfido::logon::Kind::unlock
                                                               : hidfido::logon::Kind::interactive;
        auto packed = hidfido::logon::pack_interactive_logon(kind, account.domain, account.user, password.bytes());
        diagnostic::write(DiagnosticStage::serialization_packed, package, static_cast<std::uint64_t>(kind));
        return packed;
    }
#ifdef HIDFIDO_CP_TESTING
    // Synthetic backend compiled only into the unregistered test DLL. It
    // exercises worker/cache/CAS/ReportResult without a key or Windows logon.
    SecureBytes authenticate_synthetic(ULONG& package, vault::AccountRecord& verified,
                                        const vault::AccountRecord& before,
                                        const std::wstring& mode,
                                        const hidfido::ctap::ContinueCheck& keep_going) {
        if (mode == L"wait") {
            for (unsigned i = 0; i < 100; ++i) { require_continue(keep_going); Sleep(10); }
        }
        require_continue(keep_going);
        if (verified.wrappers.empty()) throw std::runtime_error("Synthetic key missing");
        ++verified.wrappers[0].credential.sign_count;
        if (mode == L"counter_conflict" || mode == L"password_conflict" || mode == L"revocation_conflict") {
            const auto location = vault_location();
            if (!location) throw std::runtime_error("Synthetic vault missing");
            vault::Lock lock(location->path, location->sddl);
            auto current = vault::load(location->path);
            auto* record = current.find(before.sid);
            if (!record) throw std::runtime_error("Synthetic account missing");
            if (mode == L"counter_conflict") ++record->wrappers[0].credential.sign_count;
            if (mode == L"password_conflict") ++record->password_generation;
            if (mode == L"revocation_conflict") record->wrappers[0].credential.id[0] ^= 0x80;
            vault::save(location->path, current, location->sddl);
        }
        persist_counters(before, verified, 0);
        require_continue(keep_going);
        SecureBytes data_key(32);
        std::fill(data_key.bytes().begin(), data_key.bytes().end(), std::uint8_t{0x44});
        auto password = vault::open_password(before, data_key.bytes());
        package = 0x4242;
        const auto kind = scenario_ == CPUS_UNLOCK_WORKSTATION ? hidfido::logon::Kind::unlock
                                                               : hidfido::logon::Kind::interactive;
        return hidfido::logon::pack_interactive_logon(kind, L"SYNTHETIC-PC", L"synthetic-user", password.bytes());
    }
#endif
    // The verified counters must be stored before the password is released, so
    // a later replay or clone with a lower counter is still refused.
    void persist_counters(const vault::AccountRecord& before, const vault::AccountRecord& verified,
                           std::size_t wrapper_index) {
        const auto location = vault_location();
        if (!location) throw Refusal{L"Archivio macchina non disponibile."};
        vault::Lock lock(location->path, location->sddl);
        auto current = vault::load(location->path);
        auto* record = current.find(before.sid);
        if (!record) {
            throw Refusal{L"L'archivio è cambiato durante l'accesso. Riprova."};
        }
        vault::apply_verified_key_use(*record, before, verified, wrapper_index);
        vault::save(location->path, current, location->sddl);
    }
    void suspend_record(const AttemptIdentity& sent) {
#ifdef HIDFIDO_CP_TESTING
        wchar_t failure[2]{};
        if (GetEnvironmentVariableW(L"HIDFIDO_TEST_SUSPEND_FAIL", failure, 2)) {
            throw std::runtime_error("Synthetic test vault write failure");
        }
#endif
        const auto location = vault_location();
        if (!location) throw std::runtime_error("vault unavailable");
        vault::Lock lock(location->path, location->sddl);
        auto current = vault::load(location->path);
        auto* record = current.find(sent.sid);
        if (!record || record->record_id != sent.record_id ||
            record->password_generation != sent.password_generation) return;
        record->stale = true;
        vault::save(location->path, current, location->sddl);
    }
    void clear_pin() noexcept {
        {
            std::lock_guard lock(state_mutex_);
            pin_ = SecureBytes{};
        }
        refresh_fields();
    }
    void set_status(std::wstring_view text) noexcept {
        try {
            const std::wstring stable(text);
            {
                std::lock_guard lock(state_mutex_);
                status_text_ = stable;
            }
            notifications_->notify();
        } catch (...) {}
    }

    std::atomic<ULONG> references_{1};
    PWSTR sid_{};
    CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario_;
    bool suspended_{};
    std::mutex state_mutex_;
    std::atomic_bool cancelled_{false};
    std::atomic_bool connecting_{false};
    bool ui_handoff_{};
    SecureBytes cached_;
    ULONG cached_package_{};
    ULONGLONG cache_deadline_{};
    std::optional<AttemptIdentity> cached_identity_;
    std::optional<AttemptIdentity> pending_identity_;
    std::wstring status_text_;
    SecureBytes pin_;
    ComPtr<ICredentialProviderCredentialEvents> events_;
    DWORD advise_thread_{};
    ULONGLONG events_generation_{};
    std::shared_ptr<Notifications> notifications_;
};

class Provider final : public ICredentialProvider, public ICredentialProviderSetUserArray,
                       private ModuleObject {
public:
    ~Provider() { stop_notifications(); }
    IFACEMETHODIMP QueryInterface(REFIID iid, void** output) override {
        if (!output) return E_POINTER;
        *output = nullptr;
        if (iid == IID_IUnknown || iid == __uuidof(ICredentialProvider)) {
            *output = static_cast<ICredentialProvider*>(this);
        } else if (iid == __uuidof(ICredentialProviderSetUserArray)) {
            *output = static_cast<ICredentialProviderSetUserArray*>(this);
        } else {
            return E_NOINTERFACE;
        }
        AddRef();
        return S_OK;
    }
    IFACEMETHODIMP_(ULONG) AddRef() override { return ++references_; }
    IFACEMETHODIMP_(ULONG) Release() override {
        const ULONG left = --references_;
        if (!left) delete this;
        return left;
    }
    IFACEMETHODIMP SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario, DWORD) override {
        diagnostic::write(DiagnosticStage::usage_scenario, static_cast<std::uint64_t>(scenario));
        if (stopping_ || changing_credentials_) return HRESULT_FROM_WIN32(ERROR_BUSY);
        struct Reset { bool& flag; ~Reset() { flag = false; } } reset{changing_credentials_};
        changing_credentials_ = true;
        cancel_credentials(CacheDiscard::scenario);
        credentials_.clear();
        scenario_ = CPUS_INVALID;
        dirty_ = true;
        if (scenario == CPUS_LOGON || scenario == CPUS_UNLOCK_WORKSTATION) {
            scenario_ = scenario;
            return S_OK;
        }
        return scenario == CPUS_CREDUI || scenario == CPUS_CHANGE_PASSWORD || scenario == CPUS_PLAP
            ? E_NOTIMPL : E_INVALIDARG;
    }
    IFACEMETHODIMP SetSerialization(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* input) override {
        return input ? E_NOTIMPL : E_POINTER;
    }
    IFACEMETHODIMP Advise(ICredentialProviderEvents* events, UINT_PTR context) override {
        diagnostic::write(DiagnosticStage::provider_advise);
        if (!events) return E_POINTER;
        if (stopping_ || changing_credentials_) return HRESULT_FROM_WIN32(ERROR_BUSY);
        stop_notifications();
        try {
            static std::atomic<ULONG> sequence{};
            cookie_ = ++sequence;
            class_name_ = L"HidFido2CredentialEvents-" + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(cookie_);
            HMODULE module{};
            if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                    reinterpret_cast<LPCWSTR>(&window_proc), &module)) return HRESULT_FROM_WIN32(GetLastError());
            WNDCLASSW klass{};
            klass.lpfnWndProc = window_proc;
            klass.hInstance = module;
            klass.lpszClassName = class_name_.c_str();
            if (!RegisterClassW(&klass)) return HRESULT_FROM_WIN32(GetLastError());
            window_module_ = module;
            const auto window = CreateWindowExW(0, class_name_.c_str(), L"", 0, 0, 0, 0, 0, HWND_MESSAGE,
                                                 nullptr, module, this);
            if (!window) { const auto error = GetLastError(); stop_notifications(); return HRESULT_FROM_WIN32(error); }
            events_ = events;
            advise_context_ = context;
            {
                std::lock_guard lock(notifications_->mutex);
                notifications_->cookie = cookie_;
                notifications_->window = window;
            }
            if (!SetTimer(window, 1, 100, nullptr)) {
                const auto error = GetLastError(); stop_notifications(); return HRESULT_FROM_WIN32(error);
            }
            return S_OK;
        } catch (...) { stop_notifications(); return E_OUTOFMEMORY; }
    }
    IFACEMETHODIMP UnAdvise() override {
        diagnostic::write(DiagnosticStage::provider_unadvise);
        stop_notifications(); return S_OK;
    }
    IFACEMETHODIMP SetUserArray(ICredentialProviderUserArray* users) override {
        diagnostic::write(DiagnosticStage::user_array);
        if (!users) return E_POINTER;
        if (stopping_ || changing_credentials_) return HRESULT_FROM_WIN32(ERROR_BUSY);
        struct Reset { bool& flag; ~Reset() { flag = false; } } reset{changing_credentials_};
        changing_credentials_ = true;
        cancel_credentials(CacheDiscard::user_array);
        credentials_.clear();
        users_ = users;
        dirty_ = true;
        return S_OK;
    }
    IFACEMETHODIMP GetFieldDescriptorCount(DWORD* count) override {
        if (!count) return E_POINTER;
        *count = field_count;
        return S_OK;
    }
    IFACEMETHODIMP GetFieldDescriptorAt(DWORD index,
                                       CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** output) override {
        if (!output) return E_POINTER;
        *output = nullptr;
        if (index >= field_count) return E_INVALIDARG;
        auto* descriptor = static_cast<CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR*>(
            CoTaskMemAlloc(sizeof(CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR)));
        if (!descriptor) return E_OUTOFMEMORY;
        *descriptor = {};
        descriptor->dwFieldID = index;
        descriptor->cpft = fields[index].type;
        descriptor->guidFieldType = fields[index].purpose;
        const HRESULT result = copy_string(fields[index].text, &descriptor->pszLabel);
        if (FAILED(result)) {
            CoTaskMemFree(descriptor);
            return result;
        }
        *output = descriptor;
        return S_OK;
    }
    IFACEMETHODIMP GetCredentialCount(DWORD* count, DWORD* default_index, BOOL* auto_logon) override {
        if (count) *count = 0;
        if (default_index) *default_index = CREDENTIAL_PROVIDER_NO_DEFAULT;
        if (auto_logon) *auto_logon = FALSE;
        if (!count || !default_index || !auto_logon) return E_POINTER;
        const HRESULT result = enumerate();
        if (FAILED(result)) {
            diagnostic::write(DiagnosticStage::credential_count, UINT64_MAX, static_cast<std::uint32_t>(result));
            return result;
        }
        *count = static_cast<DWORD>(credentials_.size());
        for (DWORD i = 0; i < *count; ++i) {
            if (credentials_[i]->auto_logon_ready()) {
                *default_index = i;
                *auto_logon = TRUE;
                break;
            }
        }
        diagnostic::write(DiagnosticStage::credential_count, *count,
                          (*auto_logon ? (1ull << 32) : 0ull) | *default_index);
        return S_OK;
    }
    IFACEMETHODIMP GetCredentialAt(DWORD index, ICredentialProviderCredential** output) override {
        diagnostic::write(DiagnosticStage::credential_at, index);
        if (!output) return E_POINTER;
        *output = nullptr;
        const HRESULT result = enumerate();
        if (FAILED(result)) return result;
        if (index >= credentials_.size()) return E_INVALIDARG;
        return credentials_[index].CopyTo(output);
    }
private:
    static LRESULT CALLBACK window_proc(HWND window, UINT message, WPARAM wparam, LPARAM lparam) noexcept {
        if (message == WM_NCCREATE) {
            const auto* creation = reinterpret_cast<const CREATESTRUCTW*>(lparam);
            SetWindowLongPtrW(window, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(creation->lpCreateParams));
        }
        auto* self = reinterpret_cast<Provider*>(GetWindowLongPtrW(window, GWLP_USERDATA));
        if (self && !self->stopping_ && message == WM_TIMER && wparam == 1) {
            self->AddRef();
            self->on_expiry();
            self->Release();
            return 0;
        }
        if (self && !self->stopping_ && message == Notifications::message && wparam == self->cookie_) {
            // A callback may re-enter UnAdvise or release the external provider.
            self->AddRef();
            self->on_worker_notification();
            self->Release();
            return 0;
        }
        if (message == WM_NCDESTROY) SetWindowLongPtrW(window, GWLP_USERDATA, 0);
        return DefWindowProcW(window, message, wparam, lparam);
    }
    void on_worker_notification() noexcept {
        try {
            const auto credentials = credentials_;
            bool ready = false;
            for (const auto& credential : credentials) {
                credential->refresh_fields();
                ready = credential->auto_logon_ready() || ready;
            }
            auto events = events_;
            const auto context = advise_context_;
            diagnostic::write(DiagnosticStage::notification_ready, ready, events ? 1 : 0);
            if (ready && events) {
                ComPtr<Credential> handoff;
                for (const auto& credential : credentials) {
                    if (credential->begin_ui_handoff()) { handoff = credential; break; }
                }
                if (handoff) {
                    const auto result = events->CredentialsChanged(context);
                    diagnostic::write(DiagnosticStage::credentials_changed, static_cast<std::uint32_t>(result));
                    if (FAILED(result)) handoff->abort_ui_handoff();
                }
            }
        } catch (...) {}
    }
    void on_expiry() noexcept {
        try {
            const auto credentials = credentials_;
            for (const auto& credential : credentials) {
                if (credential->expire_cache()) credential->refresh_fields();
            }
        } catch (...) {}
    }
    void cancel_credentials(CacheDiscard reason = CacheDiscard::provider_teardown) noexcept {
        // cancel_silently performs no COM call, so re-entrancy cannot invalidate
        // this iteration or recursively re-enter provider teardown.
        for (const auto& credential : credentials_) credential->cancel_silently(reason);
    }
    void stop_notifications() noexcept {
        if (stopping_) return;
        stopping_ = true;
        HWND window{};
        {
            std::lock_guard lock(notifications_->mutex);
            window = std::exchange(notifications_->window, nullptr);
            notifications_->cookie = 0;
        }
        cancel_credentials();
        if (window) DestroyWindow(window);
        if (window_module_ && !class_name_.empty()) UnregisterClassW(class_name_.c_str(), window_module_);
        window_module_ = nullptr;
        class_name_.clear();
        events_.Reset();
        stopping_ = false;
    }
    HRESULT enumerate() noexcept {
        if (!dirty_) return S_OK;
        credentials_.clear();
        if (scenario_ == CPUS_INVALID) return E_UNEXPECTED;
        if (!users_) return S_OK;
        DWORD count = 0;
        HRESULT result = users_->GetCount(&count);
        if (FAILED(result)) return result;
        if (count > 1024) return HRESULT_FROM_WIN32(ERROR_TOO_MANY_NAMES);
        try {
            // An unreadable or invalid vault offers no tiles; the standard
            // password provider stays available.
            vault::Vault enrolled;
            try { enrolled = read_vault(); } catch (const std::exception&) {}
            std::vector<ComPtr<Credential>> next;
            next.reserve(count);
            for (DWORD index = 0; index < count; ++index) {
                ComPtr<ICredentialProviderUser> user;
                result = users_->GetAt(index, &user);
                if (FAILED(result)) return result;
                if (!user) return E_UNEXPECTED;
                GUID identity{};
                result = user->GetProviderID(&identity);
                if (FAILED(result)) return result;
                if (identity != Identity_LocalUserProvider) continue;
                PWSTR sid = nullptr;
                result = user->GetSid(&sid);
                if (FAILED(result) || !sid) {
                    CoTaskMemFree(sid);
                    return FAILED(result) ? result : E_UNEXPECTED;
                }
                PSID parsed_sid = nullptr;
                const BOOL valid = ConvertStringSidToSidW(sid, &parsed_sid);
                if (!valid || !IsValidSid(parsed_sid)) {
                    LocalFree(parsed_sid);
                    CoTaskMemFree(sid);
                    return E_INVALIDARG;
                }
                LocalFree(parsed_sid);
                const auto* record = enrolled.find(narrow_sid(sid));
                if (!record) {
                    CoTaskMemFree(sid);
                    continue;
                }
                ComPtr<Credential> credential;
                Credential* created{};
                try { created = new(std::nothrow) Credential(sid, scenario_, record->stale, notifications_); }
                catch (...) { CoTaskMemFree(sid); throw; }
                if (!created) {
                    CoTaskMemFree(sid);
                    return E_OUTOFMEMORY;
                }
                credential.Attach(created);
                next.push_back(std::move(credential));
            }
            credentials_.swap(next);
            dirty_ = false;
            return S_OK;
        } catch (const std::bad_alloc&) {
            return E_OUTOFMEMORY;
        } catch (...) {
            // No C++ exception crosses the in-process COM ABI.
            return E_UNEXPECTED;
        }
    }
    std::atomic<ULONG> references_{1};
    CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario_{CPUS_INVALID};
    bool dirty_{true};
    ComPtr<ICredentialProviderUserArray> users_;
    std::vector<ComPtr<Credential>> credentials_;
    std::shared_ptr<Notifications> notifications_{std::make_shared<Notifications>()};
    ComPtr<ICredentialProviderEvents> events_;
    UINT_PTR advise_context_{};
    UINT_PTR cookie_{};
    std::wstring class_name_;
    HMODULE window_module_{};
    bool stopping_{};
    bool changing_credentials_{};
};

class ClassFactory final : public IClassFactory, private ModuleObject {
public:
    IFACEMETHODIMP QueryInterface(REFIID iid, void** output) override {
        if (!output) return E_POINTER;
        *output = nullptr;
        if (iid != IID_IUnknown && iid != IID_IClassFactory) return E_NOINTERFACE;
        *output = static_cast<IClassFactory*>(this);
        AddRef();
        return S_OK;
    }
    IFACEMETHODIMP_(ULONG) AddRef() override { return ++references_; }
    IFACEMETHODIMP_(ULONG) Release() override {
        const ULONG left = --references_;
        if (!left) delete this;
        return left;
    }
    IFACEMETHODIMP CreateInstance(IUnknown* outer, REFIID iid, void** output) override {
        if (!output) return E_POINTER;
        *output = nullptr;
        if (outer) return CLASS_E_NOAGGREGATION;
        try {
            auto* provider = new(std::nothrow) Provider;
            if (!provider) return E_OUTOFMEMORY;
            const HRESULT result = provider->QueryInterface(iid, output);
            provider->Release();
            return result;
        } catch (...) { return E_OUTOFMEMORY; }
    }
    IFACEMETHODIMP LockServer(BOOL lock) override {
        if (lock) {
            ++server_locks;
            return S_OK;
        }
        long current = server_locks.load();
        while (current > 0) {
            if (server_locks.compare_exchange_weak(current, current - 1)) return S_OK;
        }
        return E_UNEXPECTED;
    }
private:
    std::atomic<ULONG> references_{1};
};
}

extern "C" HRESULT STDAPICALLTYPE DllGetClassObject(REFCLSID clsid, REFIID iid, void** output) {
    if (!output) return E_POINTER;
    *output = nullptr;
    if (clsid != hidfido::credential_provider_clsid) return CLASS_E_CLASSNOTAVAILABLE;
    auto* factory = new(std::nothrow) ClassFactory;
    if (!factory) return E_OUTOFMEMORY;
    const HRESULT result = factory->QueryInterface(iid, output);
    factory->Release();
    return result;
}

extern "C" HRESULT STDAPICALLTYPE DllCanUnloadNow() {
    return live_objects.load() == 0 && server_locks.load() == 0 ? S_OK : S_FALSE;
}
