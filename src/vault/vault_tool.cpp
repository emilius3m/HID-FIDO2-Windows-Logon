#include "hidfido/localization.hpp"
// Local, elevated administration of the machine vault. The Windows password and
// FIDO2 PINs are typed only in this program's own windows (secret_dialog), held
// in erased buffers and never printed, logged or passed on the command line.
#include "hidfido/ctap_client.hpp"
#include "hidfido/hid_transport.hpp"
#include "hidfido/machine_vault.hpp"
#include "hidfido/secret_dialog.hpp"
#include "hidfido/guided_ceremony.hpp"
#include "hidfido/account.hpp"
#include "hidfido/user_messages.hpp"
#include "../ctap/hmac_diagnostic.hpp"
#include "public_report.hpp"

#include <windows.h>
#include <bcrypt.h>
#include <fcntl.h>
#include <io.h>
#include <sddl.h>

#include <chrono>
#include <algorithm>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <system_error>
#include <thread>
#include <vector>

namespace {
using hidfido::ui::tr;
using namespace hidfido;
using password::SecureBytes;
namespace diagnostic = vault::diagnostic;
using Stage = diagnostic::Stage;
diagnostic::Report* active_report{};
ui::GuidedCeremony* active_ceremony{};

diagnostic::Scope phase(Stage stage) { return {active_report, stage}; }

class Cancelled : public std::runtime_error {
public:
    Cancelled() : std::runtime_error("Operation cancelled") {}
};
void check_cancelled() { if (active_ceremony && active_ceremony->cancelled()) throw Cancelled(); }
void show_step(ui::GuideStep step, std::wstring_view label = {}) {
    check_cancelled(); if (active_ceremony) active_ceremony->show(step, std::wstring(label));
}
ctap::ContinueCheck continue_ceremony() { return [] { return !active_ceremony || !active_ceremony->cancelled(); }; }
void release_sensor() {
    if (active_ceremony && !active_ceremony->acknowledge(ui::GuideStep::release)) throw Cancelled();
}
std::unique_ptr<ctap::HidTransport> open_ceremony_transport(const ctap::HidDeviceInfo& device, std::chrono::milliseconds timeout = std::chrono::seconds(90)) {
    check_cancelled(); return ctap::open_hid_transport(device, timeout, 3, continue_ceremony());
}
// Failure already explained to the user in Italian.
class UserError : public std::runtime_error {
public:
    explicit UserError(std::wstring message) : std::runtime_error("user error"), message_(std::move(message)) {}
    const std::wstring& message() const noexcept { return message_; }
private:
    std::wstring message_;
};

class PasswordRejected : public UserError {
public:
    explicit PasswordRejected(DWORD code) : UserError(ui::describe_logon_error(code)), code_(code) {}
    DWORD code() const noexcept { return code_; }
private:
    DWORD code_;
};

void report_error(const std::exception& error) noexcept {
    if (!active_report) return;
    // Never pass what(), UI text, request bytes or account/key metadata here.
    if (const auto* ctap_error = dynamic_cast<const ctap::StatusError*>(&error)) {
        active_report->error(diagnostic::Error::ctap, ctap_error->status());
    } else if (const auto* hid_error = dynamic_cast<const ctap::HidTransportError*>(&error)) {
        active_report->error(diagnostic::Error::hid, {}, hid_error->code());
    } else if (const auto* rejected = dynamic_cast<const PasswordRejected*>(&error)) {
        active_report->error(diagnostic::Error::windows_password, {}, rejected->code());
    } else if (dynamic_cast<const vault::ConcurrencyConflict*>(&error)) {
        active_report->error(diagnostic::Error::conflict);
    } else if (dynamic_cast<const vault::CredentialNotOnKey*>(&error)) {
        active_report->error(diagnostic::Error::ctap, 0x2e);
    } else if (dynamic_cast<const Cancelled*>(&error)) {
        active_report->error(diagnostic::Error::cancelled);
    } else if (dynamic_cast<const UserError*>(&error)) {
        active_report->error(diagnostic::Error::user);
    } else if (const auto* system = dynamic_cast<const std::system_error*>(&error);
               system && system->code().category() == std::system_category()) {
        active_report->error(diagnostic::Error::other, {}, static_cast<unsigned long>(system->code().value()));
    } else {
        active_report->error(diagnostic::Error::other);
    }
}

class ObservedTransport final : public ctap::Transport {
public:
    explicit ObservedTransport(ctap::Transport& transport) : transport_(transport) {}
    Bytes transact(std::span<const std::uint8_t> command) override {
        Stage stage = Stage::ctap_other;
        if (!command.empty()) {
            switch (command[0]) {
            case 0x01: stage = Stage::ctap_make_credential; break;
            case 0x02: stage = Stage::ctap_get_assertion; break;
            case 0x04: stage = Stage::ctap_info; break;
            case 0x06: stage = Stage::ctap_client_pin; break;
            }
        }
        const auto operation = phase(stage);
        return transport_.transact(command);
    }
private:
    ctap::Transport& transport_;
};

std::string utf8(std::wstring_view text) {
    if (text.empty()) return {};
    const int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()),
                                         nullptr, 0, nullptr, nullptr);
    if (size <= 0) throw std::runtime_error("Invalid account name encoding");
    std::string result(static_cast<std::size_t>(size), '\0');
    WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()),
                        result.data(), size, nullptr, nullptr);
    return result;
}

std::wstring widen_ascii(std::string_view text) { return {text.begin(), text.end()}; }

bool elevated() {
    HANDLE token{};
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
    TOKEN_ELEVATION elevation{};
    DWORD size{};
    const BOOL ok = GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size);
    CloseHandle(token);
    return ok && elevation.TokenIsElevated;
}

struct Account {
    std::string sid;
    std::wstring name;
    std::string name_utf8;
};

bool token_has_sid(HANDLE token, std::wstring_view expected_sid) {
    DWORD size = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &size);
    if (size == 0 || size > 4096) throw std::runtime_error("Cannot inspect account token");
    Bytes data(size);
    if (!GetTokenInformation(token, TokenUser, data.data(), size, &size)) {
        throw std::runtime_error("Cannot inspect account token");
    }
    PSID expected = nullptr;
    const std::wstring text(expected_sid);
    if (!ConvertStringSidToSidW(text.c_str(), &expected)) throw std::runtime_error("Invalid expected account SID");
    const bool matches = EqualSid(reinterpret_cast<const TOKEN_USER*>(data.data())->User.Sid, expected) != FALSE;
    LocalFree(expected);
    return matches;
}

void require_expected_account(const Account& account, std::wstring_view expected_sid) {
    if (expected_sid.empty()) return;
    PSID actual = nullptr, expected = nullptr;
    const auto actual_text = widen_ascii(account.sid);
    const std::wstring expected_text(expected_sid);
    if (!ConvertStringSidToSidW(actual_text.c_str(), &actual)) throw std::runtime_error("Cannot inspect account SID");
    const BOOL valid = ConvertStringSidToSidW(expected_text.c_str(), &expected);
    const bool same = valid && EqualSid(actual, expected);
    LocalFree(actual);
    if (expected) LocalFree(expected);
    if (!same) throw UserError(tr(L"L'account del processo elevato è diverso da quello richiesto. Nessuna credenziale acquisita."));
}

// The account is the user of this elevated process. Only local accounts are
// supported: the credential provider serializes them against this computer.
Account current_account() {
    const auto operation = phase(Stage::account_resolution);
    Account account;
    const auto sid = current_user_sid();
    account.sid = utf8(sid);
    PSID binary = nullptr;
    if (!ConvertStringSidToSidW(sid.c_str(), &binary)) throw std::runtime_error("Cannot parse current SID");
    wchar_t name[257]{}, domain[257]{}, computer[MAX_COMPUTERNAME_LENGTH + 1]{};
    DWORD name_size = 257, domain_size = 257, computer_size = MAX_COMPUTERNAME_LENGTH + 1;
    SID_NAME_USE use{};
    const BOOL found = LookupAccountSidW(nullptr, binary, name, &name_size, domain, &domain_size, &use);
    LocalFree(binary);
    if (!found || use != SidTypeUser) throw std::runtime_error("Cannot resolve the current account");
    if (!GetComputerNameW(computer, &computer_size) || CompareStringOrdinal(domain, -1, computer, -1, TRUE) != CSTR_EQUAL) {
        throw UserError(tr(L"Sono supportati solo account locali di questo computer."));
    }
    account.name = name;
    account.name_utf8 = utf8(account.name);
    return account;
}

void validate_windows_password(const Account& account, std::span<const std::uint8_t> password) {
    const auto operation = phase(Stage::windows_password_validation);
    // LogonUserW needs a terminator; keep it in an erased buffer.
    SecureBytes terminated(password.size() + sizeof(wchar_t));
    std::copy(password.begin(), password.end(), terminated.bytes().begin());
    HANDLE token{};
    if (!LogonUserW(account.name.c_str(), L".", reinterpret_cast<const wchar_t*>(terminated.bytes().data()),
                    LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &token)) {
        throw PasswordRejected(GetLastError());
    }
    bool matches = false;
    try { const auto identity_check = phase(Stage::token_identity); matches = token_has_sid(token, widen_ascii(account.sid)); }
    catch (...) { CloseHandle(token); throw; }
    CloseHandle(token);
    if (!matches) throw UserError(tr(L"Windows ha verificato un account diverso da quello selezionato. Operazione interrotta."));
}

SecureBytes request_password(const Account& account, const wchar_t* purpose) {
    const auto operation = phase(Stage::password_input);
    const auto instructions = std::wstring(purpose) + tr(L"\nAccount: ") + account.name +
        tr(L". La password viene verificata con Windows e salvata solo cifrata.");
    auto typed = active_ceremony ? active_ceremony->secret(ui::GuideStep::password, account.name) :
        ui::prompt_secret(tr(L"HID FIDO2 - password Windows"), instructions.c_str(), static_cast<unsigned>(vault::max_password_units));
    if (!typed) throw Cancelled();
    if (active_ceremony) active_ceremony->show(ui::GuideStep::checking, {}, tr(L"Attendi la risposta di Windows."), tr(L"Verifica della password"));
    validate_windows_password(account, typed->bytes());
    return std::move(*typed);
}

SecureBytes request_pin(std::wstring_view key) {
    const auto operation = phase(Stage::pin_input);
    if (active_ceremony) {
        show_step(ui::GuideStep::connect, key);
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(90);
        while (ctap::enumerate_fido_hid().size() != 1) {
            check_cancelled(); if (std::chrono::steady_clock::now() >= deadline) throw UserError(tr(L"Tempo scaduto in attesa della chiave."));
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
        auto pin = active_ceremony->secret(ui::GuideStep::pin, std::wstring(key));
        if (!pin) throw Cancelled(); return std::move(*pin);
    }
    const auto devices = ctap::enumerate_fido_hid();
    if (devices.empty()) throw UserError(tr(L"Nessuna chiave FIDO2 collegata: collegala prima di inserire il PIN."));
    if (devices.size() != 1) throw UserError(tr(L"Collega una sola chiave FIDO2 alla volta, prima di inserire il PIN."));
    const auto instructions = tr(L"PIN FIDO2 della chiave ") + std::wstring(key) +
        tr(L" (non la password Windows).\nNessun tentativo automatico: un PIN errato conta sulla chiave.");
    auto pin = ui::request_fido_pin(tr(L"HID FIDO2 - PIN della chiave"), instructions.c_str());
    if (!pin) throw Cancelled();
    return std::move(*pin);
}

void confirm(const std::wstring& text) {
    const auto operation = phase(Stage::confirmation);
    if (active_ceremony) { if (!active_ceremony->acknowledge(ui::GuideStep::confirm, {}, text)) throw Cancelled(); return; }
    if (MessageBoxW(nullptr, text.c_str(), tr(L"HID FIDO2 - archivio macchina"),
                    MB_OKCANCEL | MB_ICONINFORMATION | MB_SETFOREGROUND) != IDOK) {
        throw Cancelled();
    }
}

Hash random_hash() {
    Hash value{};
    if (BCryptGenRandom(nullptr, value.data(), static_cast<ULONG>(value.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) {
        throw std::runtime_error("CNG random generation failed");
    }
    return value;
}

std::unique_ptr<ctap::HidTransport> open_single_key() {
    const auto devices = [&] { const auto inventory = phase(Stage::hid_inventory); return ctap::enumerate_fido_hid(); }();
    if (devices.empty()) throw UserError(tr(L"Nessuna chiave FIDO2 collegata."));
    if (devices.size() != 1) throw UserError(tr(L"Collega una sola chiave FIDO2 alla volta."));
    const auto opening = phase(Stage::hid_open);
    return open_ceremony_transport(devices.front());
}

void wait_for_key_count(std::size_t desired) {
    const auto operation = phase(desired == 0 ? Stage::key_remove : Stage::key_reinsert);
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(90);
    std::optional<std::chrono::steady_clock::time_point> stable_since;
    while (std::chrono::steady_clock::now() < deadline) {
        check_cancelled();
        const auto now = std::chrono::steady_clock::now();
        if (ctap::enumerate_fido_hid().size() == desired) {
            if (!stable_since) stable_since = now;
            if (now - *stable_since >= std::chrono::seconds(1)) return;
        } else stable_since.reset();
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
    throw UserError(tr(L"Tempo scaduto in attesa della chiave."));
}

struct NewKey {
    Credential credential;
    password::Salt salt{};
    SecureBytes secret;
    vault::ProtectionState protection{vault::ProtectionState::unknown};
};

std::uint64_t unix_now() {
    const auto value = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    if (value <= 0) throw std::runtime_error("Cannot record key verification time");
    return static_cast<std::uint64_t>(value);
}

void mark_protected(vault::KeyWrapper& wrapper, vault::ProtectionState state) {
    if (state == vault::ProtectionState::unknown) throw std::runtime_error("Missing key protection proof");
    wrapper.protection_state = state;
    wrapper.protection_checked_at_unix = unix_now();
    wrapper.protection_verification_version = vault::protection_verification_version;
}

std::string utf8_prefix(std::string_view value, std::size_t maximum) {
    auto size = (std::min)(value.size(), maximum);
    while (size < value.size() && size > 0 && (static_cast<unsigned char>(value[size]) & 0xc0) == 0x80) --size;
    return std::string(value.substr(0, size));
}

void wait_for_original_key(const ctap::HidDeviceInfo& device) {
    const auto operation = phase(Stage::key_reinsert);
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(90);
    std::optional<std::chrono::steady_clock::time_point> stable;
    while (std::chrono::steady_clock::now() < deadline) {
        check_cancelled();
        const auto devices = ctap::enumerate_fido_hid();
        const auto now = std::chrono::steady_clock::now();
        if (devices.size() == 1 && devices.front().path == device.path) {
            if (!stable) stable = now;
            if (now - *stable >= std::chrono::seconds(1)) return;
        } else stable.reset();
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
    throw UserError(tr(L"Tempo scaduto: reinserisci la stessa chiave nella stessa porta USB."));
}

bool equal_secret(std::span<const std::uint8_t> left, std::span<const std::uint8_t> right) {
    if (left.size() != 32 || right.size() != 32) return false;
    volatile unsigned difference = 0;
    for (std::size_t i = 0; i < 32; ++i) difference = difference | (left[i] ^ right[i]);
    return difference == 0;
}

// This exact credential/salt is checked independently. No Windows password is
// collected and no existing wrapper is changed until both probes conclude.
void verify_protection_after_reconnect(NewKey& key, const ctap::HidDeviceInfo& original,
                                      std::span<const std::uint8_t> pin) {
    if (!active_ceremony) confirm(tr(L"Verifica obbligatoria di questa chiave prima di registrarla.\nPremi OK, poi scollega la chiave. Quando la console lo indica, reinseriscila nella STESSA porta USB.\nVerrà provato l'accesso al segreto senza PIN; nessuna password Windows viene richiesta ora."));
    show_step(ui::GuideStep::remove);
    std::wcout << tr(L"Scollega ora la chiave.\n") << std::flush;
    wait_for_key_count(0);
    show_step(ui::GuideStep::reconnect);
    std::wcout << tr(L"Rimozione rilevata. Reinserisci la stessa chiave nella stessa porta USB.\n") << std::flush;
    wait_for_original_key(original);
    // The Crescendo key may not answer this request; 30 s bounds the wait.
    auto transport = [&] { const auto opening = phase(Stage::hid_open); return open_ceremony_transport(original, std::chrono::seconds(30)); }();
    show_step(ui::GuideStep::touch);
    std::wcout << tr(L"Verifica separata senza PIN: tocca la chiave quando lampeggia (il tocco serve anche senza PIN).\n") << std::flush;
    std::optional<ctap::diagnostic::ProbeResult> probe;
    try {
        const auto probe_phase = phase(Stage::non_uv_probe);
        ObservedTransport observed(*transport);
        probe = ctap::diagnostic::probe_without_pin(observed, key.credential, key.salt, key.secret.bytes());
    } catch (const std::exception& error) { report_error(error); }
    if (probe && probe->outcome == ctap::diagnostic::Outcome::same_secret) {
        throw UserError(tr(L"Questa chiave restituisce lo stesso segreto anche senza PIN: non è adatta a questo archivio. Nessun accesso Windows modificato."));
    }
    if (!probe) throw UserError(tr(L"Verifica senza PIN inconcludente: protezione non dimostrata. Nessuna modifica all'archivio. Scollega e ricollega la chiave prima di una nuova prova esplicita."));
    ObservedTransport observed(*transport);
    ctap::HmacClient client(observed);
    if (active_ceremony) release_sensor(); else confirm(tr(L"Stacca il dito, premi OK e tocca di nuovo brevemente quando lampeggia per l'ultima verifica con PIN."));
    show_step(ui::GuideStep::touch);
    std::wcout << tr(L"Verifica finale con PIN: tocca la chiave ora, quando lampeggia.\n") << std::flush;
    auto after = client.get_secret(pin, key.credential, key.salt);
    if (!equal_secret(after.bytes(), key.secret.bytes())) {
        throw UserError(tr(L"Il segreto della chiave è cambiato dopo reinserimento. Registrazione interrotta."));
    }
    key.secret = std::move(after);
    key.protection = probe->outcome == ctap::diagnostic::Outcome::denied
        ? vault::ProtectionState::verified_denied : vault::ProtectionState::verified_distinct;
    std::wcout << tr(L"Chiave verificata: il segreto senza PIN è negato o distinto e quello con PIN è stabile.\n");
}

NewKey enroll_key(const Account& account, std::wstring_view label, std::span<const std::uint8_t> pin,
                  std::span<const Bytes> exclude_ids = {}) {
    const auto operation = phase(Stage::key_enrollment);
    const auto devices = ctap::enumerate_fido_hid();
    if (devices.size() != 1) throw UserError(tr(L"Collega una sola chiave FIDO2."));
    const auto original = devices.front();
    NewKey key;
    key.salt = random_hash();
    {
        auto transport = [&] { const auto opening = phase(Stage::hid_open); return open_ceremony_transport(original); }();
        ObservedTransport observed(*transport);
        ctap::HmacClient client(observed);
        std::wcout << tr(L"Registrazione della chiave ") << label << tr(L": tocca la chiave quando lampeggia.\n") << std::flush;
        show_step(ui::GuideStep::touch, label);
        key.credential = client.make_credential(pin, random_hash(), utf8_prefix(account.name_utf8, 64),
            "Accesso Windows " + utf8_prefix(account.name_utf8, 40), exclude_ids);
        for (unsigned attempt = 1;; ++attempt) {
            if (active_ceremony) release_sensor(); else confirm(tr(L"Credenziale creata sulla chiave ") + std::wstring(label) + tr(L".\nStacca il dito, premi OK e tocca di nuovo brevemente quando lampeggia."));
            show_step(ui::GuideStep::touch, label);
            try { key.secret = client.get_secret(pin, key.credential, key.salt); break; }
            catch (const ctap::StatusError& error) {
                report_error(error);
                // Only an explicitly confirmed new touch. PIN failures never retry.
                if ((error.status() != 0x27 && error.status() != 0x2f) || attempt == 3) throw;
                std::wcout << ui::describe_failure(error) << tr(L" Puoi ripetere la sola verifica.\n") << std::flush;
            }
        }
    }
    verify_protection_after_reconnect(key, original, pin);
    return key;
}

// Unlocks the DEK with whichever enrolled key is attached. Wrapper counters in
// `record` are advanced by the verified assertion.
vault::Unlocked unlock_existing(vault::AccountRecord& record, std::span<const std::uint8_t> pin,
                               std::wstring_view expected_label = {}) {
    const auto operation = phase(Stage::key_unlock);
    auto transport = open_single_key();
    ObservedTransport observed(*transport);
    ctap::HmacClient client(observed);
    show_step(ui::GuideStep::touch, expected_label);
    std::wcout << tr(L"Tocca la chiave ora, quando lampeggia.\n") << std::flush;
    auto unlocked = vault::unlock_data_key(record, [&](vault::KeyWrapper& wrapper) {
        if (!expected_label.empty() && wrapper.label != expected_label) throw vault::CredentialNotOnKey();
        const auto assertion = phase(Stage::key_assertion);
        try {
            return client.get_secret(pin, wrapper.credential, wrapper.salt);
        } catch (const ctap::StatusError& error) {
            if (error.status() == 0x2e) { report_error(error); throw vault::CredentialNotOnKey(); }
            throw;
        }
    });
    std::wcout << tr(L"Archivio sbloccato con la chiave ") << record.wrappers[unlocked.wrapper_index].label << L".\n";
    return unlocked;
}

const std::filesystem::path& vault_path() {
    static const auto path = vault::default_path();
    return path;
}

vault::AccountRecord snapshot(const Account& account) {
    const auto operation = phase(Stage::vault_snapshot);
    vault::Lock lock(vault_path());
    const auto loaded = vault::load(vault_path());
    const auto* record = loaded.find(account.sid);
    if (!record) throw UserError(tr(L"Nessun record per questo account: usa prima --enroll Principale."));
    return *record;
}

// The authorizing proof is committed atomically with the change. An unrelated
// wrapper may have advanced meanwhile; used-key revocation/epoch changes abort.
template<class Change> void commit_key_use(const Account& account, const vault::AccountRecord& before,
                                          const vault::AccountRecord& verified, std::size_t index,
                                          Change&& change) {
    const auto operation = phase(Stage::vault_commit);
    check_cancelled();
    vault::Lock lock(vault_path());
    auto current = vault::load(vault_path());
    auto* record = current.find(account.sid);
    if (!record) throw vault::ConcurrencyConflict();
    vault::apply_verified_key_use(*record, before, verified, index);
    change(*record);
    vault::save(vault_path(), current);
}

void verify_protection(const Account& account, const std::wstring& label) {
    const auto operation = phase(Stage::key_gate);
    const auto before = snapshot(account);
    const auto found = std::find_if(before.wrappers.begin(), before.wrappers.end(), [&](const auto& value) { return value.label == label; });
    if (found == before.wrappers.end()) throw UserError(tr(L"Nessuna chiave con questa etichetta."));
    const auto index = static_cast<std::size_t>(found - before.wrappers.begin());
    if (!active_ceremony) confirm(tr(L"Collega soltanto la chiave ") + label + tr(L".\nLa prova verifica questa credenziale dopo reinserimento, senza PIN e poi con PIN. Password Windows e dati cifrati restano invariati."));
    auto pin = request_pin(label);
    const auto devices = ctap::enumerate_fido_hid();
    if (devices.size() != 1) throw UserError(tr(L"Collega una sola chiave FIDO2."));
    auto verified = before;
    NewKey key;
    key.credential = found->credential;
    key.salt = found->salt;
    {
        auto transport = [&] { const auto opening = phase(Stage::hid_open); return open_ceremony_transport(devices.front()); }();
        ObservedTransport observed(*transport);
        ctap::HmacClient client(observed);
        std::wcout << tr(L"Tocca la chiave quando lampeggia.\n") << std::flush;
        show_step(ui::GuideStep::touch, label);
        key.secret = client.get_secret(pin.bytes(), key.credential, key.salt);
        // Confirm this UV secret is precisely the one protecting this wrapper.
        auto opened = vault::unwrap_data_key(before, *found, key.secret.bytes());
        opened.clear();
    }
    verify_protection_after_reconnect(key, devices.front(), pin.bytes());
    pin.clear();
    verified.wrappers[index].credential.sign_count = key.credential.sign_count;
    commit_key_use(account, before, verified, index, [&](vault::AccountRecord& current) {
        for (auto& wrapper : current.wrappers) if (wrapper.credential.id == found->credential.id) {
            mark_protected(wrapper, key.protection);
            return;
        }
        throw vault::ConcurrencyConflict();
    });
    if (!active_ceremony) MessageBoxW(nullptr, tr(L"Protezione hardware verificata per questa chiave. Password cifrata e altre chiavi restano invariate."),
        tr(L"HID FIDO2 - verifica completata"), MB_OK | MB_ICONINFORMATION | MB_SETFOREGROUND);
}

void backup_account(const Account& account) {
    confirm(tr(L"Creare una copia cifrata dell'archivio di questo account nell'area protetta dei backup?\nNon contiene password in chiaro e non sostituisce la password Windows di recupero."));
    vault::Lock lock(vault_path());
    const auto current = vault::load(vault_path());
    const auto* record = current.find(account.sid);
    if (!record) throw UserError(tr(L"Nessun account registrato da salvare."));
    const auto backup = vault::create_backup(vault_path(), *record);
    const auto message = tr(L"Backup cifrato creato nell'area protetta.\nID: ") + widen_ascii(backup.id) +
        tr(L"\nIl ripristino mantiene chiavi autorizzate e contatori correnti. Per chiave persa o archivio illeggibile usa la password Windows e una nuova registrazione.");
    std::wcout << message << L"\n";
    MessageBoxW(nullptr, message.c_str(), tr(L"HID FIDO2 - backup"), MB_OK | MB_ICONINFORMATION | MB_SETFOREGROUND);
}

bool suspending_password_error(DWORD code) noexcept;

void restore_backup(const Account& account, const std::wstring& id) {
    const auto before = snapshot(account);
    if (before.stale) throw UserError(tr(L"Password memorizzata sospesa: accedi con la password Windows corrente e aggiornala prima di un ripristino."));
    const auto backup = vault::load_backup(vault_path(), utf8(id), account.sid);
    vault::validate_backup_restore(before, backup);
    if (active_ceremony) confirm(tr(L"Ripristinare la copia selezionata? La password sarà verificata una volta con Windows."));
    else confirm(tr(L"Ripristinare la password cifrata da questa copia compatibile?\nServono una chiave attualmente autorizzata e un contatto. Windows verificherà la password UNA volta.\nLe chiavi revocate non vengono aggiunte e i contatori non vengono ridotti."));
    auto pin = request_pin(tr(L"attualmente registrata"));
    auto verified = before;
    auto unlocked = unlock_existing(verified, pin.bytes());
    pin.clear();
    auto password = vault::open_password(backup, unlocked.data_key.bytes());
    try { validate_windows_password(account, password.bytes()); }
    catch (const PasswordRejected& error) {
        password.clear();
        if (suspending_password_error(error.code())) {
            try {
                commit_key_use(account, before, verified, unlocked.wrapper_index, [](vault::AccountRecord& current) { current.stale = true; });
            } catch (...) {
                throw UserError(error.message() + tr(L"\nImpossibile salvare la sospensione: non riprovare. Accedi con la password Windows e aggiorna l'archivio."));
            }
        }
        throw UserError(error.message() + tr(L"\nBackup non ripristinato. Accedi con la password Windows corrente e usa Aggiorna password memorizzata."));
    }
    commit_key_use(account, before, verified, unlocked.wrapper_index, [&](vault::AccountRecord& current) {
        vault::validate_backup_restore(current, backup);
        vault::restore_password_payload(current, backup, unlocked.data_key.bytes(), password.bytes());
    });
    password.clear();
    if (!active_ceremony) MessageBoxW(nullptr, tr(L"Password cifrata ripristinata e verificata. Generazione incrementata, chiavi e contatori correnti preservati."),
        tr(L"HID FIDO2 - ripristino completato"), MB_OK | MB_ICONINFORMATION | MB_SETFOREGROUND);
}

void enroll(const Account& account, const std::wstring& label) {
    const auto operation = phase(Stage::enrollment);
    {
        vault::Lock lock(vault_path());
        if (vault::load(vault_path()).find(account.sid)) {
            throw UserError(tr(L"L'account è già registrato: usa --add-key per un'altra chiave o --update-password."));
        }
    }
    auto pin = request_pin(label);
    auto key = enroll_key(account, label, pin.bytes());
    pin.clear();
    // Collect the Windows password only after conclusive post-power-cycle checks.
    auto password = request_password(account, tr(L"Chiave verificata. Password Windows attuale da cifrare nell'archivio macchina."));
    auto data_key = vault::new_data_key();
    auto record = vault::create_record(account.sid, account.name_utf8, password.bytes(), data_key.bytes());
    password.clear();
    vault::add_wrapper(record, label, std::move(key.credential), key.salt, key.secret.bytes(), data_key.bytes());
    mark_protected(record.wrappers.back(), key.protection);
    vault::Lock lock(vault_path());
    auto current = vault::load(vault_path());
    if (current.find(account.sid)) throw UserError(tr(L"L'account è stato registrato da un'altra operazione."));
    check_cancelled();
    current.accounts.push_back(std::move(record));
    vault::save(vault_path(), current);
    std::wcout << tr(L"Account registrato con la chiave ") << label << L".\n"
               << tr(L"Aggiungi subito la chiave di riserva: hid-fido2-vault --add-key Riserva\n");
}

void add_key(const Account& account, const std::wstring& label) {
    const auto operation = phase(Stage::add_key);
    const auto before = snapshot(account);
    auto verified = before;
    for (const auto& wrapper : before.wrappers) {
        if (wrapper.label == label) throw UserError(tr(L"Esiste già una chiave con questa etichetta."));
    }
    if (!active_ceremony) confirm(tr(L"Collega una chiave GIÀ registrata per l'account (per esempio Principale).\nServirà il suo PIN e un tocco per sbloccare l'archivio."));
    auto pin = request_pin(tr(L"già registrata"));
    auto unlocked = unlock_existing(verified, pin.bytes());
    pin.clear();
    if (active_ceremony) show_step(ui::GuideStep::remove); else confirm(tr(L"Ora scollega la chiave usata e premi OK."));
    wait_for_key_count(0);
    std::wcout << tr(L"Collega la nuova chiave ") << label << L".\n" << std::flush;
    show_step(ui::GuideStep::connect, label);
    wait_for_key_count(1);
    auto new_pin = request_pin(label);
    std::vector<Bytes> enrolled;
    for (const auto& wrapper : before.wrappers) enrolled.push_back(wrapper.credential.id);
    auto key = enroll_key(account, label, new_pin.bytes(), enrolled);
    new_pin.clear();
    commit_key_use(account, before, verified, unlocked.wrapper_index, [&](vault::AccountRecord& current) {
        vault::add_wrapper(current, label, std::move(key.credential), key.salt, key.secret.bytes(), unlocked.data_key.bytes());
        mark_protected(current.wrappers.back(), key.protection);
    });
    std::wcout << tr(L"Chiave ") << label << tr(L" aggiunta: ognuna delle chiavi registrate sblocca l'archivio.\n");
}

void update_password(const Account& account) {
    const auto operation = phase(Stage::update_password);
    const auto before = snapshot(account);
    auto verified = before;
    if (!active_ceremony) confirm(tr(L"Collega una chiave registrata per l'account (Principale o Riserva)."));
    auto pin = request_pin(tr(L"registrata"));
    auto unlocked = unlock_existing(verified, pin.bytes());
    pin.clear();
    auto password = request_password(account, tr(L"NUOVA password Windows, già impostata in Windows."));
    commit_key_use(account, before, verified, unlocked.wrapper_index, [&](vault::AccountRecord& current) {
        vault::replace_password(current, unlocked.data_key.bytes(), password.bytes());
    });
    std::wcout << tr(L"Password aggiornata; l'accesso con la chiave è di nuovo attivo. Tutte le chiavi restano valide.\n");
}

bool suspending_password_error(DWORD code) noexcept {
    return code == ERROR_LOGON_FAILURE || code == ERROR_INVALID_PASSWORD || code == ERROR_WRONG_PASSWORD ||
        code == ERROR_PASSWORD_EXPIRED || code == ERROR_PASSWORD_MUST_CHANGE || code == ERROR_ACCOUNT_LOCKED_OUT;
}

// Verifies the selected key and the stored Windows password without opening a
// desktop session or submitting anything to LogonUI. Exactly one LogonUserW
// call is allowed; the resulting identity token is checked and closed.
void verify_key(const Account& account, const std::wstring& label) {
    const auto operation = phase(Stage::verify_key);
    const auto before = snapshot(account);
    if (before.stale) throw UserError(tr(L"Accesso con chiave sospeso: aggiorna prima la password con --update-password."));
    if (std::ranges::none_of(before.wrappers, [&](const auto& wrapper) { return wrapper.label == label; })) {
        throw UserError(tr(L"Nessuna chiave registrata con questa etichetta."));
    }
    if (active_ceremony) confirm(tr(L"La password salvata verrà verificata una volta con Windows. Questa prova non sblocca il PC."));
    else confirm(tr(L"Collega soltanto la chiave ") + label + tr(L".\nIl PIN e un contatto apriranno l'archivio. La password cifrata sarà verificata UNA volta con Windows.\nNessuna sessione Windows viene aperta o sbloccata. Un rifiuto della password sospende il record."));
    auto pin = request_pin(label);
    auto verified = before;
    auto unlocked = unlock_existing(verified, pin.bytes(), label);
    pin.clear();
    commit_key_use(account, before, verified, unlocked.wrapper_index, [](vault::AccountRecord&) {});
    auto password = [&] { const auto opening = phase(Stage::password_decryption); return vault::open_password(verified, unlocked.data_key.bytes()); }();
    unlocked.data_key.clear();
    try {
        validate_windows_password(account, password.bytes());
    } catch (const PasswordRejected& error) {
        report_error(error);
        password.clear();
        if (suspending_password_error(error.code())) {
            try {
                const auto suspension = phase(Stage::vault_suspension);
                vault::Lock lock(vault_path());
                auto current = vault::load(vault_path());
                auto* record = current.find(account.sid);
                if (record && vault::suspend_password_generation(*record, verified)) vault::save(vault_path(), current);
            } catch (...) {
                throw UserError(error.message() + tr(L"\nImpossibile salvare la sospensione: non riprovare con la chiave. Accedi con la password Windows e usa --update-password."));
            }
            throw UserError(error.message() + tr(L"\nLa generazione rifiutata è sospesa se ancora presente. Accedi con la password Windows e usa --update-password."));
        }
        throw;
    }
    password.clear();
    {
        const auto recheck = phase(Stage::vault_recheck);
        vault::Lock lock(vault_path());
        const auto current = vault::load(vault_path());
        const auto* record = current.find(account.sid);
        if (!record) throw vault::ConcurrencyConflict();
        vault::validate_key_authority(*record, verified, verified.wrappers[unlocked.wrapper_index].credential.id);
    }
    const auto message = tr(L"Chiave ") + label + tr(L" verificata: archivio decifrato e password confermata da Windows per questo account.\nIl token di verifica è stato chiuso. Questa prova non accede e non sblocca Windows.");
    std::wcout << message << L"\n";
    if (!active_ceremony) MessageBoxW(nullptr, message.c_str(), tr(L"HID FIDO2 - verifica completata"), MB_OK | MB_ICONINFORMATION | MB_SETFOREGROUND);
}

void remove_key(const Account& account, const std::wstring& label) {
    const auto operation = phase(Stage::remove_key);
    const auto before = snapshot(account);
    const auto found = std::find_if(before.wrappers.begin(), before.wrappers.end(), [&](const auto& wrapper) { return wrapper.label == label; });
    if (found == before.wrappers.end()) throw UserError(tr(L"Nessuna chiave con questa etichetta."));
    confirm(tr(L"Rimuovere la chiave ") + label + tr(L" dall'archivio? Non potrà più sbloccare l'accesso.\nLa credenziale sulla chiave fisica non viene cancellata."));
    vault::Lock lock(vault_path());
    auto current = vault::load(vault_path());
    auto* record = current.find(account.sid);
    if (!record) throw vault::ConcurrencyConflict();
    vault::validate_key_authority(*record, before, found->credential.id);
    vault::remove_wrapper(*record, label);
    vault::save(vault_path(), current);
    std::wcout << tr(L"Chiave ") << label << tr(L" rimossa.\n");
}

void rename_key(const Account& account, const std::wstring& label, const std::wstring& replacement) {
    const auto operation = phase(Stage::rename_key);
    const auto before = snapshot(account);
    const auto found = std::find_if(before.wrappers.begin(), before.wrappers.end(), [&](const auto& key) { return key.label == label; });
    if (found == before.wrappers.end()) throw UserError(tr(L"Nessuna chiave con questa etichetta."));
    for (const auto& key : before.wrappers) {
        if (key.label == replacement && key.credential.id != found->credential.id) throw UserError(tr(L"Esiste già una chiave con questa etichetta."));
    }
    vault::Lock lock(vault_path());
    auto current = vault::load(vault_path());
    auto* record = current.find(account.sid);
    if (!record) throw vault::ConcurrencyConflict();
    vault::validate_key_authority(*record, before, found->credential.id);
    const auto selected = std::find_if(record->wrappers.begin(), record->wrappers.end(), [&](const auto& key) { return key.credential.id == found->credential.id; });
    if (selected == record->wrappers.end() || selected->label != label) throw vault::ConcurrencyConflict();
    vault::rename_wrapper(*record, label, replacement);
    vault::save(vault_path(), current);
    MessageBoxW(nullptr, tr(L"Nome della chiave aggiornato. Non occorre registrarla di nuovo."), tr(L"Gestione HID FIDO2"), MB_OK | MB_ICONINFORMATION | MB_SETFOREGROUND);
}

void remove_account(const Account& account) {
    const auto operation = phase(Stage::remove_account);
    const auto before = snapshot(account);
    confirm(tr(L"Eliminare dall'archivio la password cifrata e tutte le chiavi di questo account?\nL'accesso con password Windows resta invariato."));
    vault::Lock lock(vault_path());
    auto current = vault::load(vault_path());
    const auto* record = current.find(account.sid);
    if (!record) throw vault::ConcurrencyConflict();
    vault::validate_key_authority(*record, before, before.wrappers.front().credential.id);
    std::erase_if(current.accounts, [&](const vault::AccountRecord& record) { return record.sid == account.sid; });
    vault::save(vault_path(), current);
    std::wcout << tr(L"Record dell'account eliminato.\n");
}

void status() {
    const auto operation = phase(Stage::status);
    vault::Lock lock(vault_path());
    const auto current = vault::load(vault_path());
    std::wcout << tr(L"Archivio: ") << vault_path().wstring() << L"\n";
    if (current.accounts.empty()) { std::wcout << tr(L"Nessun account registrato.\n"); return; }
    for (const auto& record : current.accounts) {
        std::wcout << tr(L"\nAccount: ") << widen_ascii(record.sid) << L"\n"
                   << tr(L"  Stato: ") << (record.stale ? tr(L"SOSPESO (password da aggiornare)") : tr(L"attivo")) << L"\n"
                   << tr(L"  Aggiornamenti password: ") << record.password_generation << L"\n";
        for (const auto& wrapper : record.wrappers) {
            std::wcout << tr(L"  Chiave: ") << wrapper.label << tr(L" (contatore ") << wrapper.credential.sign_count << L")\n";
        }
    }
}

void write_json_text(std::wstring_view value) {
    constexpr char hex[] = "0123456789abcdef";
    std::cout << '"';
    for (const auto unit : value) {
        if (unit == L'"' || unit == L'\\') std::cout << '\\' << static_cast<char>(unit);
        else if (unit >= 0x20 && unit < 0x7f) std::cout << static_cast<char>(unit);
        else {
            const auto scalar = static_cast<unsigned>(unit);
            std::cout << "\\u" << hex[(scalar >> 12) & 15] << hex[(scalar >> 8) & 15] << hex[(scalar >> 4) & 15] << hex[scalar & 15];
        }
    }
    std::cout << '"';
}

void status_json(const Account& account) {
    const auto operation = phase(Stage::status);
    // Read-only preflight: load() does not create a directory, lock or file.
    const auto current = vault::load(vault_path());
    const auto* record = current.find(account.sid);
    std::vector<vault::BackupInfo> backups;
    bool backups_available = true;
    try { backups = vault::list_backups(vault_path(), account.sid); } catch (...) { backups_available = false; }
    const auto verified_count = record ? std::ranges::count_if(record->wrappers, [](const auto& wrapper) {
        return wrapper.protection_state != vault::ProtectionState::unknown;
    }) : 0;
    std::cout << "{\"schema\":1,\"account_count\":" << current.accounts.size()
        << ",\"vault_schema\":" << current.source_schema
        << ",\"current_account_enrolled\":" << (record ? "true" : "false")
        << ",\"current_account_active\":" << (record && !record->stale ? "true" : "false")
        << ",\"current_account_key_count\":" << (record ? record->wrappers.size() : 0)
        << ",\"verified_key_count\":" << verified_count
        << ",\"password_generation\":" << (record ? record->password_generation : 0)
        << ",\"provider_schema_compatible\":" << (vault::installed_provider_supports_schema2() ? "true" : "false")
        << ",\"keys\":[";
    if (record) for (std::size_t index = 0; index < record->wrappers.size(); ++index) {
        const auto& wrapper = record->wrappers[index];
        if (index) std::cout << ',';
        std::cout << "{\"label\":";
        write_json_text(wrapper.label);
        std::cout << ",\"protection_state\":\"" << vault::protection_state_name(wrapper.protection_state)
            << "\",\"checked_at_unix\":" << wrapper.protection_checked_at_unix
            << ",\"verification_version\":" << wrapper.protection_verification_version << '}';
    }
    std::cout << "],\"backups_available\":" << (backups_available ? "true" : "false")
        << ",\"backup_count\":" << backups.size() << ",\"backups\":[";
    for (std::size_t index = 0; index < backups.size(); ++index) {
        const auto& backup = backups[index];
        if (index) std::cout << ',';
        std::cout << "{\"id\":\"" << backup.id << "\",\"created_at_unix\":" << backup.created_at_unix
            << ",\"password_generation\":" << backup.password_generation << ",\"key_count\":" << backup.key_count << '}';
    }
    std::cout << "]}\n";
}

void usage() {
    std::wcout << tr(L"Rinomina: hid-fido2-vault --rename-key \"Nome attuale\" --new-label \"Nome nuovo\"\n");
    std::wcout <<
        tr(L"hid-fido2-vault: archivio macchina per l'accesso Windows con chiave FIDO2 (richiede amministratore).\n  hid-fido2-vault --status\n  hid-fido2-vault --status-json [--expected-sid SID]\n  hid-fido2-vault --enroll Principale\n  hid-fido2-vault --add-key Riserva\n  hid-fido2-vault --verify Principale (o Riserva; non apre una sessione Windows)\n  hid-fido2-vault --verify-protection Principale (o Riserva; prova hardware rigorosa)\n  hid-fido2-vault --update-password\n  hid-fido2-vault --backup\n  hid-fido2-vault --restore-backup ID (solo copia compatibile, senza ripristinare chiavi revocate)\n  hid-fido2-vault --remove-key Riserva\n  hid-fido2-vault --remove-account\nOgni comando accetta --expected-sid SID per verificare l'account dopo UAC.\nDiagnostica pubblica: --report <file-nuovo.jsonl> (solo fasi e codici numerici, senza segreti o identificatori).\nPassword e PIN solo nelle finestre locali del programma, mai sulla riga di comando.\n");
}
}

int wmain(int argc, wchar_t** argv) {
    ui::set_language(ui::preferred_language());
    const bool json = argc > 1 && std::wstring_view(argv[1]) == L"--status-json";
    _setmode(_fileno(stdout), json ? _O_TEXT : _O_U16TEXT);
    _setmode(_fileno(stderr), _O_U16TEXT);
    ui::disable_console_selection();
    if (argc < 2 || argc > 13) { if (!json) usage(); return 1; }
    const std::wstring command = argv[1];
    const bool needs_label = command == L"--enroll" || command == L"--add-key" || command == L"--remove-key" ||
        command == L"--verify" || command == L"--verify-protection" || command == L"--restore-backup" || command == L"--rename-key";
    std::wstring argument, expected_sid, report_path, new_label;
    bool language_set{}, guided{};
    for (int index = 2; index < argc; ++index) {
        // A label is always the first argument, even if its literal text is
        // identical to an option. Manager arguments are quoted, never commands.
        if (index == 2 && needs_label) { argument = argv[index]; }
        else if (std::wstring_view(argv[index]) == L"--guided") {
            if (guided) { if (!json) usage(); return 1; } guided = true;
        } else if (std::wstring_view(argv[index]) == L"--expected-sid") {
            if (!expected_sid.empty() || ++index == argc) { if (!json) usage(); return 1; }
            expected_sid = argv[index];
            if (expected_sid.empty()) { if (!json) usage(); return 1; }
        } else if (std::wstring_view(argv[index]) == L"--language") {
            if (language_set || ++index == argc) { if (!json) usage(); return 1; }
            const auto selected = ui::parse_language(argv[index]);
            if (!selected) { if (!json) usage(); return 1; }
            ui::set_language(*selected); language_set = true;
        } else if (std::wstring_view(argv[index]) == L"--new-label") {
            if (!new_label.empty() || ++index == argc || !*argv[index]) { if (!json) usage(); return 1; }
            new_label = argv[index];
        } else if (std::wstring_view(argv[index]) == L"--report") {
            if (!report_path.empty() || ++index == argc) { if (!json) usage(); return 1; }
            report_path = argv[index];
            if (report_path.empty()) { if (!json) usage(); return 1; }
        } else { if (!json) usage(); return 1; }
    }
    if (needs_label != !argument.empty()) { if (!json) usage(); return 1; }
    if ((command == L"--rename-key") != !new_label.empty()) { if (!json) usage(); return 1; }
    const bool interactive = command == L"--enroll" || command == L"--add-key" || command == L"--verify" || command == L"--verify-protection" || command == L"--update-password" || command == L"--restore-backup";
    if (guided && !interactive) { if (!json) usage(); return 1; }
    std::unique_ptr<diagnostic::Report> report;
    std::unique_ptr<ui::GuidedCeremony> ceremony;
    const auto finish = [&](int code) {
        if (report) {
            report->finished(code);
            std::wcerr << tr(L"Report diagnostico pubblico: ") << report_path << L"\n";
        }
        if (ceremony && code == 0 && !ceremony->cancelled()) {
            const auto heading = command == L"--enroll" || command == L"--add-key" ? tr(L"Chiave registrata") : command == L"--verify-protection" ? tr(L"Controllo di sicurezza superato") : command == L"--update-password" ? tr(L"Password aggiornata") : tr(L"Operazione completata");
            const auto detail = command == L"--verify" ? tr(L"La prova locale è riuscita. Prova lo sblocco separatamente in Windows.") : tr(L"Puoi tornare al gestore.");
            (void)ceremony->acknowledge(ui::GuideStep::success, argument, detail, heading);
        }
        active_report = nullptr; active_ceremony = nullptr;
        return code;
    };
    try {
        if (!report_path.empty()) {
            report = std::make_unique<diagnostic::Report>(std::filesystem::path(report_path));
            active_report = report.get();
        }
        {
            const auto check = phase(Stage::elevation);
            if (!elevated()) throw UserError(tr(L"Esegui da un terminale amministratore: archivio e chiave sono accessibili solo così."));
        }
        const auto account = current_account();
        { const auto check = phase(Stage::expected_account); require_expected_account(account, expected_sid); }
        if (command == L"--status-json") { status_json(account); return finish(0); }
        if (command == L"--status") { status(); return finish(0); }
        if (command == L"--backup") { backup_account(account); return finish(0); }
        if (!vault::installed_provider_supports_schema2()) {
            throw UserError(tr(L"Aggiorna prima il Credential Provider a una versione compatibile con l archivio. Nessuna modifica all'archivio e nessun PIN acquisito."));
        }
        if (guided) { ceremony = std::make_unique<ui::GuidedCeremony>(command == L"--add-key" ? 2 : 1, command == L"--enroll" || command == L"--add-key"); active_ceremony = ceremony.get(); }
        if (command == L"--enroll") enroll(account, argument);
        else if (command == L"--add-key") add_key(account, argument);
        else if (command == L"--verify") verify_key(account, argument);
        else if (command == L"--verify-protection") verify_protection(account, argument);
        else if (command == L"--update-password") update_password(account);
        else if (command == L"--restore-backup") restore_backup(account, argument);
        else if (command == L"--remove-key") remove_key(account, argument);
        else if (command == L"--rename-key") rename_key(account, argument, new_label);
        else if (command == L"--remove-account") remove_account(account);
        else { usage(); return finish(1); }
        return finish(0);
    } catch (const Cancelled& error) {
        report_error(error);
        std::wcerr << tr(L"Operazione annullata. Nessuna modifica all'archivio.\n");
        return finish(2);
    } catch (const UserError& error) {
        report_error(error);
        if (ceremony) { if (ceremony->cancelled()) return finish(2); (void)ceremony->acknowledge(ui::GuideStep::error, {}, error.message()); return finish(1); }
        std::wcerr << tr(L"Errore: ") << error.message() << L"\n";
        if (!json) MessageBoxW(nullptr, error.message().c_str(), tr(L"HID FIDO2 - operazione interrotta"),
                              MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
        return finish(1);
    } catch (const std::exception& error) {
        report_error(error);
        if (ceremony && ceremony->cancelled()) return finish(2);
        const auto message = ui::describe_failure(error);
        if (ceremony) { (void)ceremony->acknowledge(ui::GuideStep::error, {}, message); return finish(1); }
        std::wcerr << tr(L"Errore: ") << message << L"\n";
        if (!json) MessageBoxW(nullptr, message.c_str(), tr(L"HID FIDO2 - operazione interrotta"),
                              MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
        return finish(1);
    }
}
