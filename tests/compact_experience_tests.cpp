#include "hidfido/native_management.hpp"
#include "hidfido/guidance_view.hpp"
#include <windows.h>
#include <iostream>
#include <stdexcept>

namespace {
using namespace hidfido::management;
void check(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
Status ready_status() {
    Status s; s.observed = s.compatible = s.enrolled = s.active = s.registered = true; s.schema = 2;
    s.provider_version = L"0.9.0"; s.provider_path = L"C:\\Example\\release\\provider.dll";
    s.keys = {{L"Primary", "verified_distinct", 123}, {L"Spare", "verified_denied", 124}}; return s;
}
void honest_states() {
    auto s = ready_status(); check(home_presentation(s).ready && home_presentation(s).next == HomeAction::verify, "Complete configuration is not ready");
    s.keys[1].proof = "unknown"; check(!home_presentation(s).ready && home_presentation(s).next == HomeAction::keys, "Unknown proof shown as ready");
    SetupChecks claimed{true, true, true, true}; check(setup_step(s, claimed) == SetupStep::protection, "User trial checkbox became a hardware proof");
    s.active = false; check(home_presentation(s).next == HomeAction::password, "Suspended password did not get the next action");
    s.enrolled = false; check(home_presentation(s).next == HomeAction::setup, "Empty account did not start setup");
    s.observed = false; check(home_presentation(s).next == HomeAction::installation && !home_presentation(s).ready, "Unavailable state was treated as healthy");
    for (const auto step : {hidfido::ui::GuideStep::connect, hidfido::ui::GuideStep::touch, hidfido::ui::GuideStep::remove, hidfido::ui::GuideStep::reconnect, hidfido::ui::GuideStep::checking})
        check(!hidfido::ui::guide_acknowledgement(step), "Waiting step offers manual success");
    check(hidfido::ui::guide_input(hidfido::ui::GuideStep::pin) && hidfido::ui::guide_input(hidfido::ui::GuideStep::password), "Secret fields mixed with ordinary instructions");
}
struct PrivateRegistry {
    HKEY key{}; std::wstring path = L"SOFTWARE\\HIDFIDO2.Tests.Compact." + std::to_wstring(GetCurrentProcessId()) + L"." + std::to_wstring(GetTickCount64()); bool overridden{};
    PrivateRegistry() {
        check(RegCreateKeyExW(HKEY_CURRENT_USER, path.c_str(), 0, nullptr, 0, KEY_ALL_ACCESS, nullptr, &key, nullptr) == ERROR_SUCCESS, "Cannot create private test fixture");
        if (RegOverridePredefKey(HKEY_CURRENT_USER, key) != ERROR_SUCCESS) { RegCloseKey(key); key = nullptr; RegDeleteTreeW(HKEY_CURRENT_USER, path.c_str()); throw std::runtime_error("Cannot override test HKCU"); }
        overridden = true;
    }
    ~PrivateRegistry() { if (overridden) RegOverridePredefKey(HKEY_CURRENT_USER, nullptr); if (key) RegCloseKey(key); if (path.starts_with(L"SOFTWARE\\HIDFIDO2.Tests.Compact.")) RegDeleteTreeW(HKEY_CURRENT_USER, path.c_str()); }
};
void trial_preferences() {
    PrivateRegistry registry; auto s = ready_status();
    check(!load_setup_trials(s).primary_unlock, "New fixture inherited confirmations");
    SetupChecks c{true, true, false, false}; check(save_setup_trials(s, c), "Cannot save user confirmation");
    auto loaded = load_setup_trials(s); check(!loaded.recovery && loaded.primary_unlock && !loaded.spare_unlock && !loaded.restart, "Recovery was persisted or untested steps were granted");
    c.spare_unlock = c.restart = true; check(save_setup_trials(s, c), "Cannot save complete confirmations");
    loaded = load_setup_trials(s); check(loaded.restart && !loaded.recovery, "Restart confirmation did not persist");
    auto changed = s; ++changed.password_generation; check(!load_setup_trials(changed).restart, "Old password generation inherited tests");
    changed = s; changed.keys.erase(changed.keys.begin()); check(!load_setup_trials(changed).restart, "Changed key set inherited tests");
    changed = s; changed.provider_path += L"new"; check(!load_setup_trials(changed).restart, "Changed provider inherited tests");
    c = {false, false, true, false}; check(!save_setup_trials(s, c), "Out-of-order confirmation accepted");
    HKEY preferences{}; check(RegOpenKeyExW(HKEY_CURRENT_USER, L"SOFTWARE\\HID-FIDO2-WinLogon\\UserInterface", 0, KEY_SET_VALUE, &preferences) == ERROR_SUCCESS, "Cannot inspect private UI fixture");
    const DWORD invalid = 6; RegSetValueExW(preferences, L"WindowsTrialFlags", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&invalid), sizeof(invalid)); RegCloseKey(preferences);
    check(!load_setup_trials(s).restart, "Malformed preference accepted");
}
}
int main() {
    try { honest_states(); trial_preferences(); std::cout << "Compact UI state and isolated user-confirmation preferences passed. No production registry or hardware used.\n"; return 0; }
    catch (const std::exception& failure) { std::cerr << failure.what() << '\n'; return 1; }
}
