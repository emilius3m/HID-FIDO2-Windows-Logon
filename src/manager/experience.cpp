#include "hidfido/native_management.hpp"
#include <windows.h>
#include <algorithm>
#include <array>

namespace hidfido::management {
HomePresentation home_presentation(const Status& s) noexcept {
    if (!s.observed) return {L"Stato non disponibile", L"Usa la password Windows per il recupero.", L"Controlla installazione", HomeAction::installation};
    if (!s.compatible) return {L"Aggiorna il componente di accesso", L"Apri Installazione per proseguire.", L"Apri Installazione", HomeAction::installation};
    if (!s.enrolled) return {L"Configura l'accesso a Windows", L"Inizia con la tua chiave principale.", L"Inizia", HomeAction::setup};
    if (!s.active) return {L"Password da aggiornare", L"La copia salvata richiede un aggiornamento.", L"Aggiorna password", HomeAction::password};
    if (s.keys.size() < 2) return {L"Aggiungi una chiave di riserva", L"Completa la configurazione con una seconda chiave.", L"Aggiungi la Riserva", HomeAction::setup};
    if (std::count_if(s.keys.begin(), s.keys.end(), [](const auto& key) { return key.proof == "verified_denied" || key.proof == "verified_distinct"; }) < 2)
        return {L"Completa la verifica delle chiavi", L"Le verifiche mancanti sono indicate in Chiavi.", L"Controlla chiavi", HomeAction::keys};
    if (!s.registered) return {L"Attiva l'accesso con chiave", L"Le chiavi sono registrate e verificate.", L"Apri Installazione", HomeAction::installation};
    return {L"Accesso con chiave attivo", L"Puoi usare le chiavi registrate su questo PC.", L"Prova una chiave", HomeAction::verify, true};
}
std::string setup_trials_binding(const Status& s) {
    std::string value = "HIDFIDO/UI/trials/1\n" + std::to_string(s.schema) + '\n' + std::to_string(s.password_generation) + '\n' + std::to_string(s.enrolled) + std::to_string(s.active) + std::to_string(s.registered) + '\n' + json_string(narrow(s.provider_path)) + '\n' + json_string(narrow(s.provider_version));
    for (const auto& key : s.keys) value += '\n' + json_string(narrow(key.label)) + ':' + json_string(key.proof) + ':' + std::to_string(key.checked);
    return installer::sha256_hex({reinterpret_cast<const std::uint8_t*>(value.data()), value.size()});
}
namespace {
constexpr wchar_t path[] = L"SOFTWARE\\HID-FIDO2-WinLogon\\UserInterface";
unsigned flags(const SetupChecks& c) { return static_cast<unsigned>(c.primary_unlock) | (static_cast<unsigned>(c.spare_unlock) << 1) | (static_cast<unsigned>(c.restart) << 2); }
bool valid_flags(unsigned value) { return value == 0 || value == 1 || value == 3 || value == 7; }
}
SetupChecks load_setup_trials(const Status& status) noexcept {
    try {
        std::array<wchar_t, 80> text{}; DWORD bytes = sizeof(text);
        if (RegGetValueW(HKEY_CURRENT_USER, path, L"WindowsTrials", RRF_RT_REG_SZ, nullptr, text.data(), &bytes) != ERROR_SUCCESS || bytes != 68 * sizeof(wchar_t) || text[67]) return {};
        if (text[0] != L'1' || text[1] != L':' || text[66] != L':') return {};
        const std::wstring binding(text.data() + 2, 64); if (narrow(binding) != setup_trials_binding(status)) return {};
        // The flags follow the binding, so use a separate bounded value.
        DWORD value{}, size = sizeof(value);
        if (RegGetValueW(HKEY_CURRENT_USER, path, L"WindowsTrialFlags", RRF_RT_REG_DWORD, nullptr, &value, &size) != ERROR_SUCCESS || !valid_flags(value)) return {};
        return {false, (value & 1) != 0, (value & 2) != 0, (value & 4) != 0};
    } catch (...) { return {}; }
}
bool save_setup_trials(const Status& status, const SetupChecks& checks) noexcept {
    try {
        if (!status.observed || !status.enrolled || !status.active || !status.registered || !valid_flags(flags(checks))) return false;
        const auto binding = L"1:" + widen(setup_trials_binding(status)) + L":";
        HKEY key{}; if (RegCreateKeyExW(HKEY_CURRENT_USER, path, 0, nullptr, 0, KEY_SET_VALUE, nullptr, &key, nullptr) != ERROR_SUCCESS) return false;
        struct Close { HKEY value; ~Close() { RegCloseKey(value); } } close{key};
        const DWORD value = flags(checks);
        // Invalidate before changing the binding, so interruption cannot apply
        // old trial flags to a new account/password/key/provider state.
        const DWORD empty{}; if (RegSetValueExW(key, L"WindowsTrialFlags", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&empty), sizeof(empty)) != ERROR_SUCCESS) return false;
        if (RegSetValueExW(key, L"WindowsTrials", 0, REG_SZ, reinterpret_cast<const BYTE*>(binding.c_str()), static_cast<DWORD>((binding.size() + 1) * sizeof(wchar_t))) != ERROR_SUCCESS) return false;
        return RegSetValueExW(key, L"WindowsTrialFlags", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&value), sizeof(value)) == ERROR_SUCCESS;
    } catch (...) { return false; }
}
}
