// hid-fido2-age: command-line access to file and folder encryption in the age
// format, for several recipients at once - security keys (FIDO2 PRF through
// Windows WebAuthn, no administrator rights) and a paper recovery key. The
// graphical helper hid-fido2-files.exe uses the same profile and operations.
// Profiles hold only public data; the recovery secret is shown once and never
// written to disk by this tool.
#include "hidfido/age_desktop.hpp"
#include "hidfido/age_webauthn.hpp"
#include "hidfido/localization.hpp"

#include <fcntl.h>
#include <io.h>

#include <algorithm>
#include <cwctype>
#include <fstream>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace {
namespace fs = std::filesystem;
namespace age = hidfido::age;
namespace files = hidfido::age::files;
using age::desktop::narrow;
using age::desktop::widen;
namespace ui = hidfido::ui;
using ui::tr;

class UserError : public std::runtime_error {
public:
    explicit UserError(std::wstring message) : std::runtime_error("user error"), message_(std::move(message)) {}
    const std::wstring& message() const noexcept { return message_; }
private:
    std::wstring message_;
};

void say(const std::wstring& text) { std::wcout << text << std::flush; }

void wipe(std::string& text) noexcept { age::wipe(std::span(reinterpret_cast<std::uint8_t*>(text.data()), text.size())); }

std::wstring read_hidden_line() {
    const HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode{};
    const bool console = GetConsoleMode(input, &mode) != FALSE;
    if (console) SetConsoleMode(input, (mode & ~ENABLE_ECHO_INPUT) | ENABLE_LINE_INPUT);
    std::wstring line;
    wchar_t buffer[512]{};
    DWORD read{};
    const BOOL ok = console ? ReadConsoleW(input, buffer, 511, &read, nullptr) : FALSE;
    if (ok) line.assign(buffer, read);
    SecureZeroMemory(buffer, sizeof(buffer));
    if (console) SetConsoleMode(input, mode);
    say(L"\n");
    if (!ok) throw UserError(tr(L"Inserimento della chiave di recupero non disponibile: usa --identity <file>."));
    return line;
}

void require_webauthn() {
    if (!age::webauthn::prf_available()) {
        throw UserError(tr(L"Questa versione di Windows non permette di usare le chiavi di sicurezza per cifrare file (serve Windows 11 22H2 o successivo). La chiave di recupero funziona comunque."));
    }
}

age::PrfFunction prompted_prf(const files::Profile& profile) {
    return age::webauthn::prf([&profile](const age::PrfRequest& request) {
        std::wstring names;
        for (const auto& credential : request.allowed) {
            for (const auto& key : profile.keys) {
                if (key.credential == credential) names += (names.empty() ? L"" : L", ") + widen(key.label);
            }
        }
        say(tr(L"Collega la chiave di sicurezza (") + names + tr(L"). Windows chiederà il PIN e un tocco sulla chiave.\n"));
    });
}

// ---- Commands -------------------------------------------------------------------
void new_key(const std::wstring& label, const fs::path& profile_path, const std::string& rp_id) {
    const auto label_text = narrow(label);
    if (!files::valid_label(label_text) || label.size() > 64) throw UserError(tr(L"Etichetta della chiave non valida."));
    std::vector<age::Fido2PrfCredential> existing;
    try {
        for (const auto& key : files::read_profile(profile_path).keys) {
            if (key.label == label_text) throw UserError(tr(L"Il profilo ha già una chiave con questa etichetta: ") + label);
            existing.push_back(key.credential);
        }
    } catch (const files::Error& error) {
        if (error.problem() != files::Problem::profile_missing) throw;
    }
    require_webauthn();
    say(tr(L"Collega la chiave «") + label + tr(L"». Windows chiederà il PIN della chiave e un tocco per creare una credenziale dedicata ai file.\n"));
    const auto credential = age::webauthn::create_credential(label, rp_id, existing);
    files::append_profile(profile_path, label_text, credential.encode(), age::desktop::today());
    say(tr(L"Chiave «") + label + tr(L"» aggiunta al profilo ") + profile_path.wstring() +
        tr(L".\nIl profilo contiene solo dati pubblici: copialo insieme ai file cifrati.\n"));
}

void new_recovery(const fs::path& profile_path) {
    auto identity = age::X25519Identity::generate();
    files::append_profile(profile_path, narrow(tr(L"Recupero su carta")), identity.recipient().encode(), age::desktop::today());
    auto secret = identity.encode();
    auto grouped = files::group_recovery_key(secret);
    say(tr(L"\nCHIAVE DI RECUPERO - scrivila o stampala ORA e conservala in un luogo sicuro.\n"
           L"Non viene salvata su questo computer e non potrà essere mostrata di nuovo.\n"
           L"Chi la possiede può aprire tutti i file cifrati con questo profilo.\n\n"));
    say(L"    " + widen(secret) + L"\n\n");
    say(tr(L"Versione a gruppi, più facile da ricopiare (gli spazi vengono ignorati):\n\n"));
    say(L"    " + widen(grouped) + L"\n\n");
    wipe(secret);
    wipe(grouped);
    say(tr(L"La parte pubblica è stata aggiunta al profilo ") + profile_path.wstring() + L".\n");
    say(tr(L"Per aprire un file senza chiavi FIDO2: hid-fido2-age --decrypt FILE --recovery\n"
           L"oppure, su qualsiasi sistema: age -d -i chiave-recupero.txt FILE\n"));
}

void encrypt(const fs::path& input, const fs::path& profile_path, std::optional<fs::path> output) {
    const auto profile = files::read_profile(profile_path);
    if (!profile.keys.empty()) require_webauthn();
    if (profile.recovery.empty()) {
        say(tr(L"Attenzione: il profilo non ha una chiave di recupero. Se perdi tutte le chiavi di sicurezza, i file non saranno recuperabili.\n"));
    }
    const auto prf = prompted_prf(profile);
    std::vector<std::unique_ptr<age::Recipient>> owned;
    for (const auto& key : profile.keys) owned.push_back(std::make_unique<age::Fido2PrfRecipient>(key.credential, prf));
    for (const auto& entry : profile.recovery) owned.push_back(std::make_unique<age::X25519Recipient>(entry.recipient));
    std::vector<age::Recipient*> recipients;
    for (auto& recipient : owned) recipients.push_back(recipient.get());
    if (!profile.keys.empty()) say(tr(L"Servirà un tocco per ciascuna chiave del profilo (") + std::to_wstring(profile.keys.size()) + L").\n");
    const auto result = files::encrypt(input, recipients, output, false);
    if (result.folder) say(tr(L"Cartella cifrata: ") + std::to_wstring(result.stats.files) + tr(L" file in ") + result.output.wstring() + L"\n");
    else say(tr(L"File cifrato: ") + result.output.wstring() + L"\n");
    say(tr(L"L'originale non è stato modificato né cancellato.\n"));
}

void decrypt(const fs::path& input, const std::optional<fs::path>& profile_path, const std::vector<fs::path>& identity_files,
             bool recovery, std::optional<fs::path> output) {
    std::vector<std::unique_ptr<age::Identity>> owned;
    // Recovery keys first: they need no touch.
    for (const auto& file : identity_files) {
        std::ifstream stream(file, std::ios::binary);
        if (!stream) throw UserError(tr(L"File della chiave di recupero non trovato: ") + file.wstring());
        bool found = false;
        for (std::string line; std::getline(stream, line);) {
            auto text = files::strip_whitespace(line);
            wipe(line);
            if (text.starts_with("AGE-SECRET-KEY-1")) {
                owned.push_back(std::make_unique<age::X25519Identity>(age::X25519Identity::parse(text)));
                found = true;
            }
            wipe(text);
        }
        if (!found) throw UserError(tr(L"Nessuna chiave di recupero (AGE-SECRET-KEY-1...) nel file: ") + file.wstring());
    }
    if (recovery) {
        say(tr(L"Digita la chiave di recupero (AGE-SECRET-KEY-1...). Il testo non viene mostrato.\n> "));
        auto typed = read_hidden_line();
        std::string text;
        for (const wchar_t c : typed) text.push_back(static_cast<char>(c < 0x80 ? std::towupper(c) : L'?'));
        SecureZeroMemory(typed.data(), typed.size() * sizeof(wchar_t));
        auto key = files::strip_whitespace(text);
        wipe(text);
        try {
            owned.push_back(std::make_unique<age::X25519Identity>(age::X25519Identity::parse(key)));
        } catch (const age::FormatError&) {
            wipe(key);
            throw UserError(tr(L"Chiave di recupero non valida: controlla di averla ricopiata senza errori."));
        }
        wipe(key);
    }
    files::Profile profile;
    if (profile_path) profile = files::read_profile(*profile_path);
    // Without a recovery identity, the keys are the only way in.
    if (!profile.keys.empty() && owned.empty()) require_webauthn();
    const auto prf = prompted_prf(profile);
    // One identity per relying party: any registered key can answer.
    std::vector<std::string> parties;
    for (const auto& key : profile.keys) {
        if (std::ranges::find(parties, key.credential.rp_id) == parties.end()) parties.push_back(key.credential.rp_id);
    }
    for (const auto& party : parties) {
        std::vector<age::Fido2PrfCredential> credentials;
        for (const auto& key : profile.keys) if (key.credential.rp_id == party) credentials.push_back(key.credential);
        owned.push_back(std::make_unique<age::Fido2PrfIdentity>(std::move(credentials), prf));
    }
    if (owned.empty()) throw UserError(tr(L"Indica un profilo con --profile oppure usa --recovery."));
    std::vector<age::Identity*> identities;
    for (auto& identity : owned) identities.push_back(identity.get());
    const auto result = files::decrypt(input, identities, output, false);
    if (result.folder) say(tr(L"Cartella decifrata: ") + std::to_wstring(result.stats.files) + tr(L" file in ") + result.output.wstring() + L"\n");
    else say(tr(L"File decifrato: ") + result.output.wstring() + L"\n");
}

void usage() {
    std::wcerr << tr(
        L"hid-fido2-age: cifra file e cartelle per più destinatari (formato age).\n"
        L"  hid-fido2-age --new-key Principale [--profile destinatari.txt]\n"
        L"  hid-fido2-age --new-key Riserva [--profile destinatari.txt]\n"
        L"  hid-fido2-age --new-recovery [--profile destinatari.txt]\n"
        L"  hid-fido2-age --encrypt FILE-O-CARTELLA [--profile destinatari.txt] [--output FILE.age]\n"
        L"  hid-fido2-age --decrypt FILE.age [--profile destinatari.txt] [--output DESTINAZIONE]\n"
        L"  hid-fido2-age --decrypt FILE.age --recovery | --identity chiave-recupero.txt\n"
        L"Senza --profile si usa il profilo del gestore (%APPDATA%\\HID-FIDO2-WinLogon\\Files).\n"
        L"Le cartelle diventano NOME.tar.age (un solo tocco per chiave). Il PIN si digita solo nella finestra di Windows.\n"
        L"Opzioni: --rp-id ID (solo con --new-key), --language it|en.\n");
}
}

int wmain(int argc, wchar_t** argv) {
    SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32);
    ui::set_language(ui::preferred_language());
    _setmode(_fileno(stdout), _O_U16TEXT);
    _setmode(_fileno(stderr), _O_U16TEXT);
    if (argc < 2) { usage(); return 2; }
    const std::wstring command = argv[1];
    std::wstring argument;
    std::optional<fs::path> profile, output;
    std::vector<fs::path> identities;
    std::string rp_id(age::webauthn::default_rp_id);
    bool recovery = false, language_set = false, rp_set = false;
    int index = 2;
    const bool needs_argument = command == L"--new-key" || command == L"--encrypt" || command == L"--decrypt";
    if (needs_argument) {
        if (argc < 3 || !*argv[2]) { usage(); return 2; }
        argument = argv[index++];
    }
    for (; index < argc; ++index) {
        const std::wstring_view option = argv[index];
        const bool has_value = index + 1 < argc && *argv[index + 1];
        if (option == L"--profile" && has_value && !profile) profile = fs::path(argv[++index]);
        else if (option == L"--identity" && has_value) identities.emplace_back(argv[++index]);
        else if (option == L"--output" && has_value && !output) output = fs::path(argv[++index]);
        else if (option == L"--recovery" && !recovery) recovery = true;
        else if (option == L"--rp-id" && has_value && !rp_set) {
            rp_id = narrow(argv[++index]);
            rp_set = true;
        } else if (option == L"--language" && has_value && !language_set) {
            const auto selected = ui::parse_language(argv[++index]);
            if (!selected) { usage(); return 2; }
            ui::set_language(*selected);
            language_set = true;
        } else { usage(); return 2; }
    }
    try {
        const bool decrypting = command == L"--decrypt";
        // Decryption with only a recovery key needs no profile at all.
        if (!profile && (!decrypting || (!recovery && identities.empty()))) profile = age::desktop::default_profile_path();
        if (command == L"--new-key" && !output && !recovery && identities.empty()) new_key(argument, *profile, rp_id);
        else if (command == L"--new-recovery" && !output && !recovery && identities.empty() && !rp_set) new_recovery(*profile);
        else if (command == L"--encrypt" && !recovery && identities.empty() && !rp_set) encrypt(argument, *profile, output);
        else if (decrypting && !rp_set) decrypt(argument, profile, identities, recovery, output);
        else { usage(); return 2; }
        return 0;
    } catch (const UserError& error) {
        std::wcerr << tr(L"Errore: ") << error.message() << L"\n";
    } catch (const std::exception& error) {
        std::wcerr << tr(L"Errore: ") << age::desktop::describe(error) << L"\n";
    }
    return 1;
}
