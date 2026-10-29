#include "platform.hpp"
#include "hidfido/age_desktop.hpp"
#include "hidfido/localization.hpp"
#include <shellapi.h>
#include <shlobj.h>
#include <shldisp.h>
#include <oleauto.h>
#include <exdisp.h>
#include <servprov.h>
#include <algorithm>

// Files page: the manager shows public profile data and starts the
// hid-fido2-files helper. Keys, PINs and recovery secrets never reach it.
namespace hidfido::management {
namespace {
namespace files = age::files;
using ui::tr;
constexpr wchar_t classes[] = L"Software\\Classes\\";
constexpr wchar_t encrypt_verb[] = L"HIDFIDO.Encrypt", decrypt_verb[] = L"HIDFIDO.Decrypt", prog_id[] = L"HIDFIDO.AgeFile";

template<class T> struct Com {
    T* p{};
    ~Com() { if (p) p->Release(); }
    T** put() { return &p; }
    T* operator->() const { return p; }
};

class RegistryKey {
public:
    RegistryKey(const std::wstring& path, bool create) {
        const auto result = create ? RegCreateKeyExW(HKEY_CURRENT_USER, path.c_str(), 0, nullptr, 0, KEY_READ | KEY_WRITE, nullptr, &key_, nullptr)
                                   : RegOpenKeyExW(HKEY_CURRENT_USER, path.c_str(), 0, KEY_READ, &key_);
        if (result != ERROR_SUCCESS) key_ = nullptr;
        if (create && !key_) throw std::runtime_error("Cannot write Explorer integration");
    }
    ~RegistryKey() { if (key_) RegCloseKey(key_); }
    RegistryKey(const RegistryKey&) = delete;
    RegistryKey& operator=(const RegistryKey&) = delete;
    explicit operator bool() const noexcept { return key_ != nullptr; }
    std::wstring text(const wchar_t* name) const {
        if (!key_) return {};
        wchar_t value[2048]{}; DWORD bytes = sizeof(value) - sizeof(wchar_t), type{};
        if (RegQueryValueExW(key_, name, nullptr, &type, reinterpret_cast<BYTE*>(value), &bytes) != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ)) return {};
        return value;
    }
    void set(const wchar_t* name, const std::wstring& value) {
        if (RegSetValueExW(key_, name, 0, REG_SZ, reinterpret_cast<const BYTE*>(value.c_str()), static_cast<DWORD>((value.size() + 1) * sizeof(wchar_t))) != ERROR_SUCCESS) {
            throw std::runtime_error("Cannot write Explorer integration");
        }
    }
    void remove(const wchar_t* name) { if (key_) RegDeleteValueW(key_, name); }
private:
    HKEY key_{};
};

std::wstring command(const std::filesystem::path& helper, const wchar_t* option) {
    return installer::quote_argument(helper.wstring()) + L" " + option + L" \"%1\"";
}

void write_verb(const std::wstring& path, const wchar_t* label, const std::filesystem::path& helper, const wchar_t* option) {
    RegistryKey verb(path, true);
    verb.set(L"MUIVerb", tr(label));
    verb.set(L"Icon", installer::quote_argument(helper.wstring()) + L",0");
    RegistryKey(path + L"\\command", true).set(nullptr, command(helper, option));
}

// `base` is HKCU\Software\Classes\ in production and a private tree in tests.
std::wstring encrypt_key(const std::wstring& base, const wchar_t* type) { return base + type + L"\\shell\\" + encrypt_verb; }
std::wstring decrypt_key(const std::wstring& base) { return base + L"SystemFileAssociations\\.age\\shell\\" + decrypt_verb; }

bool shell_enabled(const std::wstring& base) { return static_cast<bool>(RegistryKey(encrypt_key(base, L"*") + L"\\command", false)); }

bool shell_current(const std::wstring& base, const std::filesystem::path& helper) {
    return RegistryKey(encrypt_key(base, L"*") + L"\\command", false).text(nullptr) == command(helper, L"--encrypt") &&
           RegistryKey(encrypt_key(base, L"*"), false).text(L"MUIVerb") == tr(L"Cifra con chiave FIDO2");
}

void write_shell(const std::wstring& base, const std::filesystem::path& helper) {
    write_verb(encrypt_key(base, L"*"), L"Cifra con chiave FIDO2", helper, L"--encrypt");
    write_verb(encrypt_key(base, L"Directory"), L"Cifra con chiave FIDO2", helper, L"--encrypt");
    write_verb(decrypt_key(base), L"Decifra con chiave FIDO2", helper, L"--decrypt");
    // Double-click opens .age files only where no other program owns them.
    RegistryKey type(base + prog_id, true);
    type.set(nullptr, tr(L"File cifrato (age)"));
    RegistryKey(base + prog_id + L"\\DefaultIcon", true).set(nullptr, installer::quote_argument(helper.wstring()) + L",0");
    write_verb(base + prog_id + L"\\shell\\open", L"Decifra con chiave FIDO2", helper, L"--decrypt");
    RegistryKey(base + L".age\\OpenWithProgids", true).set(prog_id, L"");
    RegistryKey extension(base + L".age", true);
    if (extension.text(nullptr).empty()) extension.set(nullptr, prog_id);
}

void remove_shell(const std::wstring& base) {
    for (const auto& path : {encrypt_key(base, L"*"), encrypt_key(base, L"Directory"), decrypt_key(base), base + prog_id}) {
        RegDeleteTreeW(HKEY_CURRENT_USER, path.c_str());
    }
    if (RegistryKey types(base + L".age\\OpenWithProgids", false); types) RegistryKey(base + L".age\\OpenWithProgids", true).remove(prog_id);
    if (RegistryKey extension(base + L".age", false); extension && extension.text(nullptr) == prog_id) RegistryKey(base + L".age", true).remove(nullptr);
}

void notify_shell() { SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, nullptr, nullptr); }

// Starts a program through the desktop's Explorer, so it runs with the signed-in
// user's normal (non-elevated) rights, sees their network drives and creates
// files they own. Throws when no suitable shell is available.
void shell_execute_unelevated(const std::filesystem::path& program, const std::wstring& parameters) {
    Com<IShellWindows> windows;
    if (FAILED(CoCreateInstance(CLSID_ShellWindows, nullptr, CLSCTX_LOCAL_SERVER, IID_PPV_ARGS(windows.put())))) throw std::runtime_error("Shell windows unavailable");
    VARIANT location{}; location.vt = VT_I4; location.lVal = CSIDL_DESKTOP;
    VARIANT empty{};
    long handle{};
    Com<IDispatch> desktop;
    if (windows->FindWindowSW(&location, &empty, SWC_DESKTOP, &handle, SWFO_NEEDDISPATCH, desktop.put()) != S_OK || !desktop.p) throw std::runtime_error("Desktop shell unavailable");
    Com<IServiceProvider> services;
    if (FAILED(desktop->QueryInterface(IID_PPV_ARGS(services.put())))) throw std::runtime_error("Desktop services unavailable");
    Com<IShellBrowser> browser;
    if (FAILED(services->QueryService(SID_STopLevelBrowser, IID_PPV_ARGS(browser.put())))) throw std::runtime_error("Desktop browser unavailable");
    Com<IShellView> view;
    if (FAILED(browser->QueryActiveShellView(view.put()))) throw std::runtime_error("Desktop view unavailable");
    Com<IDispatch> background;
    if (FAILED(view->GetItemObject(SVGIO_BACKGROUND, IID_PPV_ARGS(background.put())))) throw std::runtime_error("Desktop folder unavailable");
    Com<IShellFolderViewDual> folder;
    if (FAILED(background->QueryInterface(IID_PPV_ARGS(folder.put())))) throw std::runtime_error("Desktop folder view unavailable");
    Com<IDispatch> application;
    if (FAILED(folder->get_Application(application.put()))) throw std::runtime_error("Shell application unavailable");
    // Shell.Application.ShellExecute(file, arguments, directory, operation, show),
    // called by name: the C++ method name is renamed by the ShellExecute macro.
    DISPID method{};
    LPOLESTR name = const_cast<LPOLESTR>(L"ShellExecute");
    if (FAILED(application->GetIDsOfNames(IID_NULL, &name, 1, LOCALE_USER_DEFAULT, &method))) throw std::runtime_error("Shell execute unavailable");
    VARIANT arguments[5]{};  // Reverse order, as IDispatch expects.
    arguments[0].vt = VT_I4; arguments[0].lVal = SW_SHOWNORMAL;
    arguments[1].vt = VT_BSTR; arguments[1].bstrVal = SysAllocString(L"open");
    arguments[2].vt = VT_BSTR; arguments[2].bstrVal = SysAllocString(program.parent_path().c_str());
    arguments[3].vt = VT_BSTR; arguments[3].bstrVal = SysAllocString(parameters.c_str());
    arguments[4].vt = VT_BSTR; arguments[4].bstrVal = SysAllocString(program.c_str());
    DISPPARAMS call{arguments, nullptr, 5, 0};
    const bool allocated = arguments[1].bstrVal && arguments[2].bstrVal && arguments[3].bstrVal && arguments[4].bstrVal;
    const auto result = allocated ? application->Invoke(method, IID_NULL, LOCALE_USER_DEFAULT, DISPATCH_METHOD, &call, nullptr, nullptr, nullptr) : E_OUTOFMEMORY;
    for (auto& argument : arguments) VariantClear(&argument);
    if (FAILED(result)) throw std::runtime_error("Shell execute failed");
}
}

std::filesystem::path files_profile_path() { return age::desktop::default_profile_path(); }

FilesStatus observe_files() {
    FilesStatus status;
    try {
        const auto profile = files::read_profile(files_profile_path());
        status.profile = true;
        for (const auto& key : profile.keys) status.keys.push_back(widen(key.label));
        for (const auto& entry : profile.recovery) status.recovery.push_back(widen(entry.label));
    } catch (const files::Error& error) {
        status.readable = error.problem() == files::Problem::profile_missing;
    } catch (const std::exception&) {
        status.readable = false;
    }
    return status;
}

std::vector<std::wstring> files_arguments(FilesAction action, std::wstring_view label) {
    std::vector<std::wstring> arguments;
    switch (action) {
    case FilesAction::encrypt_file: arguments = {L"--pick-encrypt-file"}; break;
    case FilesAction::encrypt_folder: arguments = {L"--pick-encrypt-folder"}; break;
    case FilesAction::decrypt: arguments = {L"--pick-decrypt"}; break;
    case FilesAction::add_key:
        if (!valid_key_label(label)) throw std::invalid_argument("Invalid key label");
        arguments = {L"--new-key", std::wstring(label)};
        break;
    case FilesAction::add_recovery: arguments = {L"--new-recovery"}; break;
    }
    arguments.insert(arguments.end(), {L"--language", ui::language_code(ui::language())});
    return arguments;
}

void start_files_helper(const std::filesystem::path& helper, const std::vector<std::wstring>& arguments) {
    check_protected(helper, false);
    std::wstring parameters;
    for (const auto& argument : arguments) {
        if (argument.find(L'\0') != std::wstring::npos) throw std::runtime_error("Embedded command NUL");
        if (!parameters.empty()) parameters += L' ';
        parameters += installer::quote_argument(argument);
    }
    if (elevated()) {
        try { shell_execute_unelevated(helper, parameters); return; } catch (const std::exception&) {}
    }
    (void)start_native(helper, arguments);
}

bool files_shell_enabled() { return shell_enabled(classes); }

void set_files_shell(const std::filesystem::path& helper, bool enabled) {
    if (enabled) {
        check_protected(helper, false);
        write_shell(classes, helper);
    } else {
        remove_shell(classes);
    }
    notify_shell();
}

void refresh_files_shell(const std::filesystem::path& helper) noexcept {
    try {
        if (files_shell_enabled() && !shell_current(classes, helper)) set_files_shell(helper, true);
    } catch (...) {}
}
}
