// Compile the actual Files page implementation into this test translation unit
// so its private Explorer registration can be exercised in an isolated HKCU
// tree. Production always writes HKCU\Software\Classes for the signed-in user;
// no override ships in the app.
#include "../src/manager/files.cpp"
#include <iostream>

namespace {
using namespace hidfido::management;
namespace ui = hidfido::ui;
void check(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
template<class F> void rejects(F work, const char* message) { try { work(); } catch (const std::exception&) { return; } throw std::runtime_error(message); }

void helper_arguments() {
    ui::set_language(ui::Language::english);
    check(files_arguments(FilesAction::encrypt_file) == std::vector<std::wstring>{L"--pick-encrypt-file", L"--language", L"en"}, "Encrypt-file arguments");
    check(files_arguments(FilesAction::encrypt_folder).front() == L"--pick-encrypt-folder", "Encrypt-folder arguments");
    check(files_arguments(FilesAction::decrypt).front() == L"--pick-decrypt", "Decrypt arguments");
    check(files_arguments(FilesAction::add_recovery).front() == L"--new-recovery", "Recovery arguments");
    check(files_arguments(FilesAction::add_key, L"Riserva 2") == std::vector<std::wstring>{L"--new-key", L"Riserva 2", L"--language", L"en"}, "Key label passed as one argument");
    rejects([] { files_arguments(FilesAction::add_key, L""); }, "Empty key label accepted");
    rejects([] { files_arguments(FilesAction::add_key, L"a\nb"); }, "Control character in key label accepted");
    rejects([] { files_arguments(FilesAction::add_key, std::wstring(L"x\0--uninstall", 14)); }, "Embedded NUL in key label accepted");
}

void explorer_registration() {
    const auto root = L"Software\\HidFidoNativeTests\\" + widen(random_id());
    const auto base = root + L"\\Classes\\";
    const std::filesystem::path helper = L"C:\\Program Files\\HID-FIDO2-WinLogon\\releases\\abc\\bin\\hid-fido2-files.exe";
    const auto cleanup = [&] { RegDeleteTreeW(HKEY_CURRENT_USER, root.c_str()); };
    try {
        ui::set_language(ui::Language::italian);
        // Another program owns .age files: it keeps the double-click.
        RegistryKey(base + L".age", true).set(nullptr, L"Other.AgeFile");
        check(!shell_enabled(base), "Registration detected before writing");
        write_shell(base, helper);
        check(shell_enabled(base) && shell_current(base, helper), "Registration incomplete");
        const auto encrypt = RegistryKey(base + L"*\\shell\\HIDFIDO.Encrypt\\command", false).text(nullptr);
        check(encrypt == L"\"C:\\Program Files\\HID-FIDO2-WinLogon\\releases\\abc\\bin\\hid-fido2-files.exe\" --encrypt \"%1\"", "Encrypt command not quoted");
        check(RegistryKey(base + L"Directory\\shell\\HIDFIDO.Encrypt\\command", false).text(nullptr) == encrypt, "Folder verb missing");
        check(RegistryKey(base + L"SystemFileAssociations\\.age\\shell\\HIDFIDO.Decrypt\\command", false).text(nullptr).ends_with(L"--decrypt \"%1\""), "Decrypt verb missing");
        check(RegistryKey(base + L"*\\shell\\HIDFIDO.Encrypt", false).text(L"MUIVerb") == L"Cifra con chiave FIDO2", "Verb not localized");
        check(RegistryKey(base + L".age", false).text(nullptr) == L"Other.AgeFile", "Foreign .age default replaced");
        // A language change or a new release makes the registration stale.
        ui::set_language(ui::Language::english);
        check(!shell_current(base, helper), "Language change not detected");
        ui::set_language(ui::Language::italian);
        check(!shell_current(base, L"C:\\Program Files\\HID-FIDO2-WinLogon\\releases\\def\\bin\\hid-fido2-files.exe"), "Release change not detected");
        remove_shell(base);
        check(!shell_enabled(base) && !RegistryKey(base + L"HIDFIDO.AgeFile", false), "Removal incomplete");
        check(RegistryKey(base + L".age", false).text(nullptr) == L"Other.AgeFile", "Foreign .age default removed");
        // Without another owner, double-click opens the helper until removal.
        RegistryKey(base + L".age", true).remove(nullptr);
        write_shell(base, helper);
        check(RegistryKey(base + L".age", false).text(nullptr) == L"HIDFIDO.AgeFile", "Default program not offered");
        remove_shell(base);
        check(RegistryKey(base + L".age", false).text(nullptr).empty(), "Own default program left behind");
        remove_shell(base);  // Idempotent.
        cleanup();
    } catch (...) { cleanup(); throw; }
}
}

int main() {
    try {
        helper_arguments();
        explorer_registration();
        std::cout << "Files page: helper arguments, quoted per-user Explorer verbs, stale-registration detection and foreign .age owner preservation passed in private HKCU only.\n";
        return 0;
    } catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}
