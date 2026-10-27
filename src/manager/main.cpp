#include "hidfido/localization.hpp"
#include "hidfido/support_report.hpp"
#include "window.hpp"
#include <commctrl.h>
#include <shellapi.h>
#include <objidl.h>
#include <propidl.h>
#include <shobjidl.h>
#include <gdiplus.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <cwctype>
#include <memory>
#include <thread>

#ifndef HIDFIDO_TRUSTED_SIGNER_SHA256
#define HIDFIDO_TRUSTED_SIGNER_SHA256 ""
#endif
namespace {
using hidfido::ui::tr;
using namespace hidfido::management;
using hidfido::installer::quote_argument;
constexpr char signer_policy[] = "HIDFIDO_SIGNER_SHA256=" HIDFIDO_TRUSTED_SIGNER_SHA256;
std::string_view signer_pin() { return std::string_view(signer_policy).substr(sizeof("HIDFIDO_SIGNER_SHA256=") - 1); }
constexpr UINT complete_message = WM_APP + 20, capture_message = WM_APP + 21;
constexpr wchar_t title[] = L"Gestione HID FIDO2";
struct Options { bool demo{}, child{}, approved{}, package{}, audit{}, apply{}, remove{}, legacy{}, compact_preview{}; std::optional<hidfido::ui::Language> language; std::wstring expected_sid, demo_state; std::optional<hidfido::ui::GuideStep> preview_step; std::filesystem::path snapshot, build, output, result; };
Options parse_options() {
    int count{}; auto** args = CommandLineToArgvW(GetCommandLineW(), &count); if (!args) throw std::runtime_error("Arguments unavailable"); Options out;
    try {
        for (int i = 1; i < count; ++i) {
            const std::wstring_view arg(args[i]);
            const auto next = [&]() -> std::wstring { if (++i == count) throw std::runtime_error("Missing argument"); return args[i]; };
            if (arg == L"--manage") {}
            else if (arg == L"--demo") out.demo = true;
            else if (arg == L"--demo-compact") out.compact_preview = true;
            else if (arg == L"--demo-state") { if (!out.demo_state.empty()) throw std::runtime_error("Duplicate demo state"); out.demo_state = next(); if (out.demo_state != L"empty" && out.demo_state != L"ready") throw std::runtime_error("Invalid demo state"); }
            else if (arg == L"--wizard-step") {
                if (out.preview_step) throw std::runtime_error("Duplicate preview step");
                const auto value = next();
                const std::pair<std::wstring_view, hidfido::ui::GuideStep> steps[]{
                    {L"connect", hidfido::ui::GuideStep::connect}, {L"pin", hidfido::ui::GuideStep::pin},
                    {L"touch", hidfido::ui::GuideStep::touch}, {L"release", hidfido::ui::GuideStep::release},
                    {L"remove", hidfido::ui::GuideStep::remove}, {L"reconnect", hidfido::ui::GuideStep::reconnect},
                    {L"password", hidfido::ui::GuideStep::password}, {L"success", hidfido::ui::GuideStep::success}};
                for (const auto& [name, step] : steps) if (value == name) out.preview_step = step;
                if (!out.preview_step) throw std::runtime_error("Invalid wizard preview");
            }
            else if (arg == L"--audit") out.audit = true;
            else if (arg == L"--install") out.apply = true;
            else if (arg == L"--uninstall") out.remove = true;
            else if (arg == L"--allow-legacy-key-proof") out.legacy = true;
            else if (arg == L"--elevated") out.child = true;
            else if (arg == L"--prototype-approved") out.approved = true;
            else if (arg == L"--expected-sid") out.expected_sid = next();
            else if (arg == L"--snapshot") out.snapshot = next();
            else if (arg == L"--language") { if (out.language) throw std::runtime_error("Duplicate language"); out.language = hidfido::ui::parse_language(next()); if (!out.language) throw std::runtime_error("Language must be it or en"); }
            else if (arg == L"--package") { out.package = true; out.build = next(); out.output = next(); }
            else if (arg == L"--result") out.result = next();
            else throw std::runtime_error("Unknown argument");
        }
    } catch (...) { LocalFree(args); throw; } LocalFree(args);
    const auto modes = static_cast<unsigned>(out.demo) + out.package + out.audit + out.apply + out.remove;
    if (modes > 1 || ((!out.snapshot.empty() || !out.demo_state.empty() || out.preview_step || out.compact_preview) && !out.demo) || (out.package && out.child) || ((out.audit || out.apply || out.remove) && out.result.empty()) || (out.legacy && !out.apply) || (!out.result.empty() && !out.package && !out.audit && !out.apply && !out.remove)) throw std::runtime_error("Invalid mode"); return out;
}
std::filesystem::path module_directory() { std::wstring path(32768, L'\0'); const auto size = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size())); if (!size || size >= path.size()) throw std::runtime_error("Module path unavailable"); path.resize(size); return std::filesystem::path(path).parent_path(); }
}
int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int show) {
    try {
        if (!SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)) throw std::runtime_error("System DLL search policy unavailable");
        hidfido::ui::set_language(hidfido::ui::preferred_language());
        const auto options = parse_options(); if (options.language) hidfido::ui::set_language(*options.language); const auto source = module_directory();
        if (options.package) { const auto directory = package_release(options.build, options.output, "0.9.0", signer_pin()); if (!options.result.empty()) write_new_text(options.result, "{\"ReleaseDirectory\":" + json_string(directory) + "}", false); return 0; }
        const auto com = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED); if (FAILED(com)) throw std::runtime_error("COM initialization failed"); struct Co { ~Co() { CoUninitialize(); } } co;
        SetCurrentProcessExplicitAppUserModelID(L"HIDFIDO.WindowsLogon.Manager"); INITCOMMONCONTROLSEX controls{sizeof(controls), ICC_LISTVIEW_CLASSES | ICC_PROGRESS_CLASS | ICC_STANDARD_CLASSES}; InitCommonControlsEx(&controls);
        auto package = source; std::wstring sid;
        std::unique_ptr<hidfido::installer::PinnedPackage> pin;
        if (!options.demo) {
            sid = current_sid(); if (options.child && options.expected_sid != sid) throw std::runtime_error("UAC selected another Windows account");
            pin = std::make_unique<hidfido::installer::PinnedPackage>(source, signer_pin(), signer_pin().empty()); if (!pin->manifest().native_management) throw std::runtime_error("Native package required");
            bool stored_consent{};
            try { const auto installed = active_deployment(); stored_consent = installed && installed->prototype && installed->release_id == pin->manifest().release_id && _wcsicmp(installed->directory.c_str(), source.c_str()) == 0; } catch (...) {}
            if (signer_pin().empty() && !stored_consent && !(elevated() && options.child && options.approved) && !confirm(nullptr, tr(L"Questo prototipo locale non è firmato. Apri solo una copia compilata o ricevuta da una fonte attendibile.\r\n\r\nAprire Gestione HID FIDO2?"))) return 2;
            if (!elevated()) {
                std::wstring module(32768, L'\0'); const auto size = GetModuleFileNameW(nullptr, module.data(), static_cast<DWORD>(module.size())); module.resize(size); auto args = L"--manage --elevated --language " + quote_argument(hidfido::ui::language_code(hidfido::ui::language())) + L" --expected-sid " + quote_argument(sid) + (signer_pin().empty() ? L" --prototype-approved" : L"");
                if (options.audit) args += L" --audit --result " + quote_argument(options.result.wstring());
                if (options.apply || options.remove) { args += options.apply ? L" --install" : L" --uninstall"; args += L" --result " + quote_argument(options.result.wstring()); if (options.legacy) args += L" --allow-legacy-key-proof"; }
                SHELLEXECUTEINFOW request{sizeof(request)}; request.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC; request.lpVerb = L"runas"; request.lpFile = module.c_str(); request.lpParameters = args.c_str(); request.nShow = SW_SHOWNORMAL;
                if (!ShellExecuteExW(&request)) { if (GetLastError() == ERROR_CANCELLED) return 2; win_error("Start UAC"); } Handle child(request.hProcess); WaitForSingleObject(child.get(), INFINITE); DWORD code{}; GetExitCodeProcess(child.get(), &code); return static_cast<int>(code);
            }
            if (options.audit) { const auto report = audit_current(sid); const auto output_pins = pin_directories(std::filesystem::absolute(options.result).parent_path()); write_new_text(options.result, report, false); return 0; }
            if (options.apply || options.remove) {
                // Reserve a new, pinned result before changing registration.
                // Results contain public deployment metadata, never secrets,
                // and are not input to any privileged action.
                reject_reparse(options.result);
                const auto output_pins = pin_directories(std::filesystem::absolute(options.result).parent_path());
                Handle result_file(CreateFileW(options.result.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_NEW, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH, nullptr));
                if (!result_file.valid()) win_error("Reserve installation result");
                if (GetFileType(result_file.get()) != FILE_TYPE_DISK) throw std::runtime_error("Installation result must be a disk file");
                bool success{}; std::string result;
                try {
                    TransactionResult outcome;
                    if (options.remove) { uninstall_provider(); outcome.success = true; }
                    else outcome = install_or_update(source, signer_pin(), sid, options.legacy);
                    success = outcome.success;
                    result = std::string("{\"Success\":") + (outcome.success ? "true" : "false") + ",\"PreviousRestored\":" + (outcome.restored ? "true" : "false") + ",\"RecoveryRequired\":" + (outcome.recovery_required ? "true" : "false");
                    if (success && options.apply) {
                        const auto installed = active_deployment(); if (!installed) throw std::runtime_error("Installed registration unavailable");
                        result += ",\"DeploymentManifest\":" + json_string(narrow(installed->manifest.wstring())) + ",\"ReleaseId\":" + json_string(installed->release_id);
                        bool shortcuts{}; try { create_shortcuts(installed->directory); shortcuts = true; } catch (...) {}
                        result += std::string(",\"ShortcutsCreated\":") + (shortcuts ? "true" : "false");
                        const bool language_saved = hidfido::ui::save_preferred_language(hidfido::ui::language());
                        result += std::string(",\"LanguageSaved\":") + (language_saved ? "true" : "false");
                    }
                    result += '}';
                } catch (const std::exception& e) { success = false; result = "{\"Success\":false,\"Error\":" + json_string(e.what()) + "}"; }
                DWORD written{}; if (!WriteFile(result_file.get(), result.data(), static_cast<DWORD>(result.size()), &written, nullptr) || written != result.size() || !FlushFileBuffers(result_file.get())) win_error("Write installation result");
                return success ? 0 : 1;
            }
            package = stage_package(source, signer_pin());
            if (!hidfido::ui::save_preferred_language(hidfido::ui::language())) {
                error(nullptr, tr(L"Impossibile salvare la lingua. Riapri il gestore come amministratore e riprova.")); return 1;
            }
        }
        return show_manager({options.demo, options.demo_state, options.snapshot, options.preview_step, std::string(signer_pin()), options.compact_preview}, package, sid, instance, show);
    } catch (const std::exception& e) { technical_error(nullptr, widen(e.what()).c_str()); return 1; }
}
