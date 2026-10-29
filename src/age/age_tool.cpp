// hid-fido2-age: encrypts files and folders in the age format for several
// recipients at once - security keys (FIDO2 PRF through Windows WebAuthn, no
// administrator rights) and a paper recovery key (standard age X25519).
// Profiles hold only public data; the recovery secret is shown once and never
// written to disk by this tool.
#include "hidfido/age.hpp"
#include "hidfido/age_webauthn.hpp"
#include "hidfido/localization.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <fcntl.h>
#include <io.h>

#include <algorithm>
#include <cwchar>
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
namespace ui = hidfido::ui;
using ui::tr;

class UserError : public std::runtime_error {
public:
    explicit UserError(std::wstring message) : std::runtime_error("user error"), message_(std::move(message)) {}
    const std::wstring& message() const noexcept { return message_; }
private:
    std::wstring message_;
};

std::wstring widen(std::string_view text) {
    if (text.empty()) return {};
    const int size = MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
    std::wstring result(static_cast<std::size_t>((std::max)(size, 0)), L'\0');
    if (size > 0) MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), result.data(), size);
    return result;
}

std::string narrow(std::wstring_view text) {
    if (text.empty()) return {};
    const int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
    if (size <= 0) throw UserError(tr(L"Testo non valido."));
    std::string result(static_cast<std::size_t>(size), '\0');
    WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), result.data(), size, nullptr, nullptr);
    return result;
}

std::string trim(std::string_view text) {
    const auto begin = text.find_first_not_of(" \t\r\n");
    if (begin == std::string_view::npos) return {};
    return std::string(text.substr(begin, text.find_last_not_of(" \t\r\n") - begin + 1));
}

std::string today() {
    SYSTEMTIME now{};
    GetLocalTime(&now);
    char text[16]{};
    std::snprintf(text, sizeof(text), "%04u-%02u-%02u", now.wYear, now.wMonth, now.wDay);
    return text;
}

std::string random_suffix() {
    std::array<std::uint8_t, 6> random{};
    age::random_bytes(random);
    static constexpr char digits[] = "0123456789abcdef";
    std::string result;
    for (const auto byte : random) { result += digits[byte >> 4]; result += digits[byte & 15]; }
    return result;
}

// ---- Profiles: public recipients, one per line, '#' comments name the next one.
struct SecurityKey {
    std::wstring label;
    age::Fido2PrfCredential credential;
};
struct Profile {
    std::vector<SecurityKey> keys;
    std::vector<std::pair<std::wstring, age::X25519Recipient>> recovery;
};

Profile read_profile(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) throw UserError(tr(L"Profilo dei destinatari non trovato: ") + path.wstring());
    Profile profile;
    std::wstring label;
    std::size_t number = 0;
    for (std::string raw; std::getline(input, raw);) {
        ++number;
        if (number == 1 && raw.starts_with("\xEF\xBB\xBF")) raw.erase(0, 3);
        const auto line = trim(raw);
        if (line.empty()) continue;
        if (line.front() == '#') { label = widen(trim(std::string_view(line).substr(1))); continue; }
        try {
            if (line.starts_with("AGE-PLUGIN-FIDO2PRF-1")) {
                profile.keys.push_back({label.empty() ? tr(L"chiave di sicurezza") : label, age::Fido2PrfCredential::parse(line)});
            } else if (line.starts_with("age1")) {
                profile.recovery.emplace_back(label.empty() ? tr(L"chiave di recupero") : label, age::X25519Recipient::parse(line));
            } else if (line.starts_with("AGE-SECRET-KEY-")) {
                throw UserError(tr(L"Il profilo contiene una chiave SEGRETA di recupero alla riga ") + std::to_wstring(number) +
                                tr(L". Toglila dal file: il profilo deve contenere solo dati pubblici."));
            } else {
                throw age::FormatError("unknown line");
            }
        } catch (const age::FormatError&) {
            throw UserError(tr(L"Riga non riconosciuta nel profilo, riga ") + std::to_wstring(number) + L": " + path.wstring());
        }
        label.clear();
    }
    if (profile.keys.empty() && profile.recovery.empty()) throw UserError(tr(L"Il profilo non contiene destinatari: ") + path.wstring());
    return profile;
}

// The comment right before a recipient is its label; the date line is informative.
void append_profile(const fs::path& path, const std::wstring& label, const std::string& line) {
    if (fs::exists(path)) (void)read_profile(path);  // Never append to a file we would not accept.
    std::ofstream output(path, std::ios::binary | std::ios::app);
    if (!output) throw UserError(tr(L"Impossibile scrivere il profilo: ") + path.wstring());
    output << "# hid-fido2-age " << today() << "\n# " << narrow(label) << "\n" << line << "\n";
    if (!output) throw UserError(tr(L"Impossibile scrivere il profilo: ") + path.wstring());
}

// ---- Console -------------------------------------------------------------------
void say(const std::wstring& text) { std::wcout << text << std::flush; }

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

age::PrfFunction prompted_prf(const Profile& profile) {
    return age::webauthn::prf([&profile](const age::PrfRequest& request) {
        std::wstring names;
        for (const auto& credential : request.allowed) {
            for (const auto& key : profile.keys) {
                if (key.credential == credential) names += (names.empty() ? L"" : L", ") + key.label;
            }
        }
        say(tr(L"Collega la chiave di sicurezza (") + names +
            tr(L"). Windows chiederà il PIN e un tocco sulla chiave.\n"));
    });
}

// ---- Output handling: write next to the target, rename only after success.
class PendingFile {
public:
    explicit PendingFile(fs::path target) : target_(std::move(target)) {
        if (fs::exists(fs::symlink_status(target_))) throw UserError(tr(L"Esiste già: ") + target_.wstring() + tr(L". Nessun file è stato sovrascritto."));
        temporary_ = target_;
        temporary_ += L".partial-" + widen(random_suffix());
        stream_.open(temporary_, std::ios::binary | std::ios::trunc);
        if (!stream_) throw UserError(tr(L"Impossibile creare: ") + temporary_.wstring());
    }
    ~PendingFile() {
        if (committed_) return;
        stream_.close();
        std::error_code ignored;
        fs::remove(temporary_, ignored);
    }
    std::ofstream& stream() noexcept { return stream_; }
    void commit() {
        stream_.close();
        if (!stream_) throw UserError(tr(L"Errore di scrittura: ") + temporary_.wstring());
        if (fs::exists(fs::symlink_status(target_))) throw UserError(tr(L"Esiste già: ") + target_.wstring() + tr(L". Nessun file è stato sovrascritto."));
        fs::rename(temporary_, target_);
        committed_ = true;
    }
private:
    fs::path target_, temporary_;
    std::ofstream stream_;
    bool committed_{};
};

bool is_folder_archive(const fs::path& input) {
    auto name = input.filename().wstring();
    std::ranges::transform(name, name.begin(), [](wchar_t c) { return static_cast<wchar_t>(towlower(c)); });
    return name.size() > 8 && name.ends_with(L".tar.age");
}

void require_webauthn() {
    if (!age::webauthn::prf_available()) {
        throw UserError(tr(L"Questa versione di Windows non permette di usare le chiavi di sicurezza per cifrare file (serve Windows 11 22H2 o successivo). La chiave di recupero funziona comunque."));
    }
}

// ---- Commands -------------------------------------------------------------------
void new_key(const std::wstring& label, const fs::path& profile_path, const std::string& rp_id) {
    if (label.empty() || label.size() > 64 || label.find_first_of(L"\r\n#") != std::wstring::npos) {
        throw UserError(tr(L"Etichetta della chiave non valida."));
    }
    std::vector<age::Fido2PrfCredential> existing;
    if (fs::exists(profile_path)) {
        for (const auto& key : read_profile(profile_path).keys) {
            if (key.label == label) throw UserError(tr(L"Il profilo ha già una chiave con questa etichetta: ") + label);
            existing.push_back(key.credential);
        }
    }
    require_webauthn();
    say(tr(L"Collega la chiave «") + label + tr(L"». Windows chiederà il PIN della chiave e un tocco per creare una credenziale dedicata ai file.\n"));
    std::optional<age::Fido2PrfCredential> created;
    try {
        created = age::webauthn::create_credential(label, rp_id, existing);
    } catch (const age::webauthn::Error& error) {
        if (error.already_registered()) {
            throw UserError(tr(L"Questa chiave è già nel profilo con un'altra etichetta: collega una chiave fisica diversa."));
        }
        throw;
    }
    const auto& credential = *created;
    append_profile(profile_path, label, credential.encode());
    say(tr(L"Chiave «") + label + tr(L"» aggiunta al profilo ") + profile_path.wstring() +
        tr(L".\nIl profilo contiene solo dati pubblici: copialo insieme ai file cifrati.\n"));
}

void new_recovery(const fs::path& profile_path) {
    auto identity = age::X25519Identity::generate();
    auto secret = identity.encode();
    append_profile(profile_path, tr(L"Recupero su carta"), identity.recipient().encode());
    std::string grouped = secret.substr(0, 16);
    for (std::size_t i = 16; i < secret.size(); i += 4) grouped += " " + secret.substr(i, 4);
    say(tr(L"\nCHIAVE DI RECUPERO - scrivila o stampala ORA e conservala in un luogo sicuro.\n"
           L"Non viene salvata su questo computer e non potrà essere mostrata di nuovo.\n"
           L"Chi la possiede può aprire tutti i file cifrati con questo profilo.\n\n"));
    say(L"    " + widen(secret) + L"\n\n");
    say(tr(L"Versione a gruppi, più facile da ricopiare (gli spazi vengono ignorati):\n\n"));
    say(L"    " + widen(grouped) + L"\n\n");
    age::wipe(std::span(reinterpret_cast<std::uint8_t*>(secret.data()), secret.size()));
    age::wipe(std::span(reinterpret_cast<std::uint8_t*>(grouped.data()), grouped.size()));
    say(tr(L"La parte pubblica è stata aggiunta al profilo ") + profile_path.wstring() + L".\n");
    say(tr(L"Per aprire un file senza chiavi FIDO2: hid-fido2-age --decrypt FILE --recovery\n"
           L"oppure, su qualsiasi sistema: age -d -i chiave-recupero.txt FILE\n"));
}

void encrypt(const fs::path& input, const fs::path& profile_path, std::optional<fs::path> output) {
    const auto profile = read_profile(profile_path);
    const auto status = fs::symlink_status(input);
    const bool folder = fs::is_directory(status);
    if (!folder && !fs::is_regular_file(status)) throw UserError(tr(L"File o cartella non trovati: ") + input.wstring());
    auto absolute = fs::absolute(input);
    if (absolute.filename().empty()) absolute = absolute.parent_path();
    if (!output) output = fs::path(absolute.wstring() + (folder ? L".tar.age" : L".age"));
    if (folder) {
        // The archive must not contain its own partial output.
        const auto inside = fs::weakly_canonical(fs::absolute(*output)).lexically_relative(fs::weakly_canonical(absolute));
        if (!inside.empty() && *inside.begin() != L"..") {
            throw UserError(tr(L"Il file cifrato non può stare dentro la cartella da cifrare: scegli un altro --output."));
        }
    }
    if (!profile.keys.empty()) require_webauthn();
    if (profile.recovery.empty()) {
        say(tr(L"Attenzione: il profilo non ha una chiave di recupero. Se perdi tutte le chiavi di sicurezza, i file non saranno recuperabili.\n"));
    }
    auto prf = prompted_prf(profile);
    std::vector<std::unique_ptr<age::Recipient>> owned;
    for (const auto& key : profile.keys) owned.push_back(std::make_unique<age::Fido2PrfRecipient>(key.credential, prf));
    for (const auto& [label, recipient] : profile.recovery) owned.push_back(std::make_unique<age::X25519Recipient>(recipient));
    std::vector<age::Recipient*> recipients;
    for (auto& recipient : owned) recipients.push_back(recipient.get());
    if (!profile.keys.empty()) {
        say(tr(L"Servirà un tocco per ciascuna chiave del profilo (") + std::to_wstring(profile.keys.size()) + L").\n");
    }
    PendingFile pending(*output);
    age::Encryptor encryptor(pending.stream(), recipients);
    if (folder) {
        const auto stats = age::write_tar(absolute, [&](std::span<const std::uint8_t> data) { encryptor.write(data); });
        encryptor.finish();
        pending.commit();
        say(tr(L"Cartella cifrata: ") + std::to_wstring(stats.files) + tr(L" file in ") + output->wstring() + L"\n");
    } else {
        std::ifstream source(absolute, std::ios::binary);
        if (!source) throw UserError(tr(L"Impossibile leggere: ") + absolute.wstring());
        std::vector<std::uint8_t> buffer(age::chunk_size);
        for (;;) {
            source.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(buffer.size()));
            const auto count = static_cast<std::size_t>(source.gcount());
            if (source.bad()) throw UserError(tr(L"Impossibile leggere: ") + absolute.wstring());
            if (count) encryptor.write(std::span(buffer).first(count));
            if (count < buffer.size()) break;
        }
        age::wipe(buffer);
        encryptor.finish();
        pending.commit();
        say(tr(L"File cifrato: ") + output->wstring() + L"\n");
    }
    say(tr(L"L'originale non è stato modificato né cancellato.\n"));
}

void decrypt(const fs::path& input, const std::vector<fs::path>& profiles, const std::vector<fs::path>& identity_files,
             bool recovery, std::optional<fs::path> output) {
    std::vector<std::unique_ptr<age::Identity>> owned;
    // Recovery keys first: they need no touch.
    for (const auto& file : identity_files) {
        std::ifstream stream(file, std::ios::binary);
        if (!stream) throw UserError(tr(L"File della chiave di recupero non trovato: ") + file.wstring());
        bool found = false;
        for (std::string line; std::getline(stream, line);) {
            auto text = trim(line);
            if (!text.starts_with("AGE-SECRET-KEY-1")) { age::wipe(std::span(reinterpret_cast<std::uint8_t*>(line.data()), line.size())); continue; }
            owned.push_back(std::make_unique<age::X25519Identity>(age::X25519Identity::parse(text)));
            age::wipe(std::span(reinterpret_cast<std::uint8_t*>(text.data()), text.size()));
            age::wipe(std::span(reinterpret_cast<std::uint8_t*>(line.data()), line.size()));
            found = true;
        }
        if (!found) throw UserError(tr(L"Nessuna chiave di recupero (AGE-SECRET-KEY-1...) nel file: ") + file.wstring());
    }
    if (recovery) {
        say(tr(L"Digita la chiave di recupero (AGE-SECRET-KEY-1...). Il testo non viene mostrato.\n> "));
        auto typed = read_hidden_line();
        std::string text;
        for (const wchar_t c : typed) {
            if (c == L' ' || c == L'\t' || c == L'\r' || c == L'\n') continue;
            text.push_back(static_cast<char>(c < 0x80 ? std::towupper(c) : L'?'));
        }
        SecureZeroMemory(typed.data(), typed.size() * sizeof(wchar_t));
        try {
            owned.push_back(std::make_unique<age::X25519Identity>(age::X25519Identity::parse(text)));
        } catch (const age::FormatError&) {
            age::wipe(std::span(reinterpret_cast<std::uint8_t*>(text.data()), text.size()));
            throw UserError(tr(L"Chiave di recupero non valida: controlla di averla ricopiata senza errori."));
        }
        age::wipe(std::span(reinterpret_cast<std::uint8_t*>(text.data()), text.size()));
    }
    Profile merged;
    for (const auto& path : profiles) {
        auto profile = read_profile(path);
        for (auto& key : profile.keys) merged.keys.push_back(std::move(key));
    }
    // One identity per relying party: any registered key can answer.
    std::vector<std::string> parties;
    for (const auto& key : merged.keys) {
        if (std::ranges::find(parties, key.credential.rp_id) == parties.end()) parties.push_back(key.credential.rp_id);
    }
    // Without a recovery identity, the keys are the only way in.
    if (!merged.keys.empty() && owned.empty()) require_webauthn();
    const auto prf = prompted_prf(merged);
    for (const auto& party : parties) {
        std::vector<age::Fido2PrfCredential> credentials;
        for (const auto& key : merged.keys) if (key.credential.rp_id == party) credentials.push_back(key.credential);
        owned.push_back(std::make_unique<age::Fido2PrfIdentity>(std::move(credentials), prf));
    }
    if (owned.empty()) throw UserError(tr(L"Indica un profilo con --profile oppure usa --recovery."));
    std::vector<age::Identity*> identities;
    for (auto& identity : owned) identities.push_back(identity.get());

    std::ifstream source(input, std::ios::binary);
    if (!source) throw UserError(tr(L"File cifrato non trovato: ") + input.wstring());
    age::Decryptor decryptor(source, identities);
    const auto absolute = fs::absolute(input);
    if (is_folder_archive(input)) {
        // Extract into a private staging folder; move into place only after
        // the whole archive has been authenticated.
        const auto parent = output ? fs::absolute(*output).parent_path() : absolute.parent_path();
        if (output && fs::exists(fs::symlink_status(*output))) throw UserError(tr(L"Esiste già: ") + output->wstring() + tr(L". Nessun file è stato sovrascritto."));
        const auto staging = parent / (L".hid-fido2-age-" + widen(random_suffix()) + L".partial");
        fs::create_directory(staging);
        struct Cleanup { fs::path path; bool active{true}; ~Cleanup() { if (active) { std::error_code e; fs::remove_all(path, e); } } } cleanup{staging};
        const auto stats = age::extract_tar([&](std::span<std::uint8_t> data) { return decryptor.read(data); }, staging);
        if (!decryptor.finished()) throw age::FormatError("Truncated age payload");
        if (output) {
            fs::rename(staging, *output);
            cleanup.active = false;
            say(tr(L"Cartella decifrata: ") + std::to_wstring(stats.files) + tr(L" file in ") + output->wstring() + L"\n");
            return;
        }
        std::vector<fs::path> entries;
        for (const auto& entry : fs::directory_iterator(staging)) entries.push_back(entry.path().filename());
        for (const auto& name : entries) {
            if (fs::exists(fs::symlink_status(parent / name))) {
                throw UserError(tr(L"Esiste già: ") + (parent / name).wstring() + tr(L". Usa --output con una cartella nuova."));
            }
        }
        for (const auto& name : entries) fs::rename(staging / name, parent / name);
        say(tr(L"Cartella decifrata: ") + std::to_wstring(stats.files) + tr(L" file in ") + parent.wstring() + L"\n");
        return;
    }
    if (!output) {
        auto name = absolute.wstring();
        if (name.size() <= 4 || _wcsicmp(name.c_str() + name.size() - 4, L".age") != 0) {
            throw UserError(tr(L"Il file non termina con .age: indica il nome del risultato con --output."));
        }
        output = fs::path(name.substr(0, name.size() - 4));
    }
    PendingFile pending(*output);
    std::vector<std::uint8_t> buffer(age::chunk_size);
    for (std::size_t count; (count = decryptor.read(buffer)) != 0;) {
        pending.stream().write(reinterpret_cast<const char*>(buffer.data()), static_cast<std::streamsize>(count));
        if (!pending.stream()) throw UserError(tr(L"Errore di scrittura: ") + output->wstring());
    }
    age::wipe(buffer);
    if (!decryptor.finished()) throw age::FormatError("Truncated age payload");
    pending.commit();
    say(tr(L"File decifrato: ") + output->wstring() + L"\n");
}

void usage() {
    std::wcerr << tr(
        L"hid-fido2-age: cifra file e cartelle per più destinatari (formato age).\n"
        L"  hid-fido2-age --new-key Principale --profile destinatari.txt\n"
        L"  hid-fido2-age --new-key Riserva --profile destinatari.txt\n"
        L"  hid-fido2-age --new-recovery --profile destinatari.txt\n"
        L"  hid-fido2-age --encrypt FILE-O-CARTELLA --profile destinatari.txt [--output FILE.age]\n"
        L"  hid-fido2-age --decrypt FILE.age --profile destinatari.txt [--output DESTINAZIONE]\n"
        L"  hid-fido2-age --decrypt FILE.age --recovery | --identity chiave-recupero.txt\n"
        L"Le cartelle diventano NOME.tar.age (un solo tocco per chiave). Il PIN si digita solo nella finestra di Windows.\n"
        L"Opzioni: --rp-id ID (solo con --new-key), --language it|en.\n");
}
}

int wmain(int argc, wchar_t** argv) {
    ui::set_language(ui::preferred_language());
    _setmode(_fileno(stdout), _O_U16TEXT);
    _setmode(_fileno(stderr), _O_U16TEXT);
    if (argc < 2) { usage(); return 2; }
    const std::wstring command = argv[1];
    std::wstring argument;
    std::vector<fs::path> profiles, identities;
    std::optional<fs::path> output;
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
        if (option == L"--profile" && has_value) profiles.emplace_back(argv[++index]);
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
        if (command == L"--new-key" && profiles.size() == 1 && !output && !recovery && identities.empty()) {
            new_key(argument, profiles.front(), rp_id);
        } else if (command == L"--new-recovery" && profiles.size() == 1 && !output && !recovery && identities.empty() && !rp_set) {
            new_recovery(profiles.front());
        } else if (command == L"--encrypt" && profiles.size() == 1 && !recovery && identities.empty() && !rp_set) {
            encrypt(argument, profiles.front(), output);
        } else if (command == L"--decrypt" && !rp_set && (!profiles.empty() || recovery || !identities.empty())) {
            decrypt(argument, profiles, identities, recovery, output);
        } else {
            usage();
            return 2;
        }
        return 0;
    } catch (const UserError& error) {
        std::wcerr << tr(L"Errore: ") << error.message() << L"\n";
    } catch (const age::NoIdentityMatched&) {
        std::wcerr << tr(L"Errore: nessuna delle chiavi indicate può aprire questo file.\n");
    } catch (const age::webauthn::Error& error) {
        std::wcerr << (error.cancelled() ? tr(L"Operazione annullata o chiave non registrata per questo file.\n")
                                         : tr(L"Errore della chiave di sicurezza: ") + widen(error.what()) + L"\n");
    } catch (const age::FormatError& error) {
        std::wcerr << tr(L"Errore: file danneggiato, manomesso o non valido (") << widen(error.what())
                   << tr(L"). Nessun risultato parziale è stato conservato.\n");
    } catch (const std::exception& error) {
        std::wcerr << tr(L"Errore: ") << widen(error.what()) << L"\n";
    }
    return 1;
}
