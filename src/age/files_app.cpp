// hid-fido2-files: graphical helper for file and folder encryption, started by
// the manager's Files page and by Explorer's context menu. Runs as the signed-in
// user (no elevation). Windows owns the security-key dialog and the PIN; this
// process reads only the recovery key typed or shown in its own window.
#include "hidfido/age_desktop.hpp"
#include "hidfido/age_webauthn.hpp"
#include "hidfido/guidance_view.hpp"
#include "hidfido/localization.hpp"

#include <commctrl.h>
#include <commdlg.h>
#include <shellapi.h>
#include <shobjidl.h>
#include <gdiplus.h>

#include <atomic>
#include <cwctype>
#include <memory>
#include <optional>
#include <thread>
#include <vector>

namespace {
namespace fs = std::filesystem;
namespace age = hidfido::age;
namespace files = hidfido::age::files;
namespace ui = hidfido::ui;
using age::desktop::narrow;
using age::desktop::widen;
using ui::tr;

constexpr UINT status_message = WM_APP + 1, progress_message = WM_APP + 2, done_message = WM_APP + 3, start_message = WM_APP + 4;
constexpr int primary_id = 100, secondary_id = 101, link_id = 102, edit_id = 103, show_id = 104, confirm_id = 105;
constexpr wchar_t window_title[] = L"HID FIDO2 · File cifrati";

enum class Mode { encrypt, decrypt, new_key, new_recovery, preview };
enum class State { working, success, failure, choose, recovery_input, recovery_show };

struct Options {
    Mode mode{Mode::preview};
    fs::path path;
    std::wstring label;
    std::optional<fs::path> profile;
    std::wstring preview;
    fs::path snapshot;
};

struct Outcome {
    bool success{};
    files::Result result;
    std::wstring message;
    bool no_match{};
    bool cancelled{};
};

void wipe(std::string& text) noexcept { age::wipe(std::span(reinterpret_cast<std::uint8_t*>(text.data()), text.size())); }
void wipe(std::wstring& text) noexcept { SecureZeroMemory(text.data(), text.size() * sizeof(wchar_t)); }

std::optional<fs::path> pick(bool folder, bool encrypted) {
    IFileOpenDialog* dialog{};
    if (FAILED(CoCreateInstance(CLSID_FileOpenDialog, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&dialog)))) throw std::runtime_error("Open dialog unavailable");
    struct Release { IFileOpenDialog* value; ~Release() { value->Release(); } } release{dialog};
    DWORD options{};
    dialog->GetOptions(&options);
    dialog->SetOptions(options | FOS_FORCEFILESYSTEM | FOS_PATHMUSTEXIST | FOS_FILEMUSTEXIST | FOS_NOCHANGEDIR | (folder ? static_cast<DWORD>(FOS_PICKFOLDERS) : 0u));
    dialog->SetTitle(folder ? tr(L"Scegli la cartella da cifrare") : encrypted ? tr(L"Scegli il file da decifrare") : tr(L"Scegli il file da cifrare"));
    if (encrypted) {
        const COMDLG_FILTERSPEC types[]{{tr(L"File cifrati (*.age)"), L"*.age"}, {tr(L"Tutti i file"), L"*.*"}};
        dialog->SetFileTypes(2, types);
    }
    const auto shown = dialog->Show(nullptr);
    if (shown == HRESULT_FROM_WIN32(ERROR_CANCELLED)) return std::nullopt;
    if (FAILED(shown)) throw std::runtime_error("Open dialog failed");
    IShellItem* item{};
    if (FAILED(dialog->GetResult(&item))) throw std::runtime_error("Selection unavailable");
    struct Item { IShellItem* value; ~Item() { value->Release(); } } selected{item};
    wchar_t* path{};
    if (FAILED(item->GetDisplayName(SIGDN_FILESYSPATH, &path))) throw std::runtime_error("Selection is not a file system path");
    fs::path result(path);
    CoTaskMemFree(path);
    return result;
}

class FilesWindow {
public:
    explicit FilesWindow(Options options) : options_(std::move(options)) {}
    ~FilesWindow() {
        if (worker_.joinable()) worker_.join();
        if (recovery_) recovery_.reset();
        for (const auto font : {font_, large_, mono_}) if (font) DeleteObject(font);
        DeleteObject(white_);
    }

    int run(HINSTANCE instance, int show) {
        WNDCLASSEXW type{sizeof(type)};
        type.lpfnWndProc = window_proc; type.hInstance = instance; type.lpszClassName = L"HidFido2Files";
        type.hCursor = LoadCursorW(nullptr, IDC_ARROW); type.hIcon = LoadIconW(instance, MAKEINTRESOURCEW(1)); type.hIconSm = type.hIcon;
        type.hbrBackground = white_;
        if (!RegisterClassExW(&type)) throw std::runtime_error("Cannot register window");
        const auto dpi = GetDpiForSystem();
        RECT bounds{0, 0, MulDiv(640, dpi, 96), MulDiv(470, dpi, 96)}, work{};
        const DWORD style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_CLIPCHILDREN;
        AdjustWindowRectExForDpi(&bounds, style, FALSE, 0, dpi);
        SystemParametersInfoW(SPI_GETWORKAREA, 0, &work, 0);
        const int width = bounds.right - bounds.left, height = bounds.bottom - bounds.top;
        window_ = CreateWindowExW(0, type.lpszClassName, tr(window_title), style, work.left + (work.right - work.left - width) / 2,
                                  work.top + (work.bottom - work.top - height) / 2, width, height, nullptr, nullptr, instance, this);
        if (!window_) throw std::runtime_error("Cannot create window");
        age::webauthn::set_owner_window(window_);
        ShowWindow(window_, show);
        UpdateWindow(window_);
        PostMessageW(window_, start_message, 0, 0);
        MSG message{};
        while (GetMessageW(&message, nullptr, 0, 0) > 0) {
            if (keyboard(message)) continue;
            if (!IsDialogMessageW(window_, &message)) { TranslateMessage(&message); DispatchMessageW(&message); }
        }
        return exit_code_;
    }

private:
    int scale(int value) const { return MulDiv(value, static_cast<int>(dpi_), 96); }

    // Owner-drawn buttons are never dialog default buttons: Enter presses the
    // focused button, or the main action from the recovery-key field; Esc closes.
    bool keyboard(const MSG& message) {
        if (message.message != WM_KEYDOWN || (message.wParam != VK_RETURN && message.wParam != VK_ESCAPE)) return false;
        if (message.hwnd != window_ && GetParent(message.hwnd) != window_) return false;
        if (message.wParam == VK_ESCAPE) { PostMessageW(window_, WM_CLOSE, 0, 0); return true; }
        const auto focus = GetFocus();
        for (const auto [control, id] : {std::pair{primary_, primary_id}, std::pair{secondary_, secondary_id}, std::pair{link_, link_id}}) {
            if (focus == control && IsWindowEnabled(control)) { command(id); return true; }
        }
        if (focus == edit_ && IsWindowVisible(primary_) && IsWindowEnabled(primary_)) { command(primary_id); return true; }
        return false;
    }

    HWND make(const wchar_t* kind, DWORD style, int id = 0) {
        const auto control = CreateWindowExW(kind == std::wstring_view(L"EDIT") ? WS_EX_CLIENTEDGE : 0, kind, L"", WS_CHILD | style, 0, 0, 1, 1,
                                             window_, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), GetModuleHandleW(nullptr), nullptr);
        if (!control) throw std::runtime_error("Cannot create control");
        return control;
    }

    void create() {
        dpi_ = GetDpiForWindow(window_);
        heading_ = make(L"STATIC", WS_VISIBLE | SS_LEFT);
        detail_ = make(L"STATIC", WS_VISIBLE | SS_LEFT | SS_NOPREFIX);
        status_ = make(L"STATIC", WS_VISIBLE | SS_LEFT | SS_NOPREFIX);
        progress_ = make(PROGRESS_CLASSW, 0);
        edit_ = make(L"EDIT", ES_PASSWORD | ES_AUTOHSCROLL | ES_UPPERCASE | WS_TABSTOP, edit_id);
        show_ = make(L"BUTTON", BS_AUTOCHECKBOX | WS_TABSTOP, show_id);
        key_text_ = make(L"STATIC", SS_CENTER | SS_NOPREFIX);
        confirm_ = make(L"BUTTON", BS_AUTOCHECKBOX | BS_MULTILINE | WS_TABSTOP, confirm_id);
        primary_ = make(L"BUTTON", WS_VISIBLE | BS_OWNERDRAW | WS_TABSTOP, primary_id);
        secondary_ = make(L"BUTTON", WS_VISIBLE | BS_OWNERDRAW | WS_TABSTOP, secondary_id);
        link_ = make(L"BUTTON", BS_OWNERDRAW | WS_TABSTOP, link_id);
        SendMessageW(edit_, EM_SETLIMITTEXT, 200, 0);
        SendMessageW(progress_, PBM_SETRANGE32, 0, 1000);
        fonts();
    }

    void fonts() {
        for (const auto font : {font_, large_, mono_}) if (font) DeleteObject(font);
        const auto make_font = [&](int size, int weight, const wchar_t* face) {
            return CreateFontW(-scale(size), 0, 0, 0, weight, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, face);
        };
        font_ = make_font(15, FW_NORMAL, L"Segoe UI"); large_ = make_font(26, FW_SEMIBOLD, L"Segoe UI"); mono_ = make_font(18, FW_SEMIBOLD, L"Consolas");
        for (const auto control : {heading_, detail_, status_, edit_, show_, key_text_, confirm_, primary_, secondary_, link_}) {
            SendMessageW(control, WM_SETFONT, reinterpret_cast<WPARAM>(control == heading_ ? large_ : control == key_text_ || control == edit_ ? mono_ : font_), TRUE);
        }
    }

    void layout() {
        RECT area{}; GetClientRect(window_, &area);
        const int width = MulDiv(area.right, 96, static_cast<int>(dpi_)), height = MulDiv(area.bottom, 96, static_cast<int>(dpi_));
        const int left = 40, content = width - 80;
        const auto box = [&](HWND control, int x, int y, int w, int h) { MoveWindow(control, scale(x), scale(y), scale(std::max(1, w)), scale(std::max(1, h)), TRUE); };
        box(heading_, left, 28, content, 40);
        box(detail_, left, 76, content, state_ == State::recovery_show ? 62 : 70);
        box(key_text_, left, 146, content, 84);
        box(edit_, left, 170, content, 38);
        box(show_, left, 216, content, 26);
        box(confirm_, left, 244, content, 46);
        box(status_, left, height - 146, content, 40);
        box(progress_, left, height - 98, content, 6);
        // The secondary button moves to the right edge when it is the only one.
        const bool primary = IsWindowVisible(primary_) != FALSE;
        box(primary_, width - 40 - 160, height - 64, 160, 40);
        box(secondary_, primary ? width - 40 - 160 - 12 - 150 : width - 40 - 150, height - 64, 150, 40);
        box(link_, left - 6, height - 62, 236, 36);
        InvalidateRect(window_, nullptr, TRUE);
    }

    void visible(HWND control, bool value) { ShowWindow(control, value ? SW_SHOW : SW_HIDE); }

    // Shows one state. Empty button texts hide the button.
    void show_state(State state, const std::wstring& heading, const std::wstring& detail, const std::wstring& primary,
                    const std::wstring& secondary, const std::wstring& link = {}, ui::GuideArt art = ui::GuideArt::check) {
        state_ = state; art_ = art;
        SetWindowTextW(heading_, heading.c_str()); SetWindowTextW(detail_, detail.c_str()); SetWindowTextW(status_, L"");
        SetWindowTextW(primary_, primary.c_str()); SetWindowTextW(secondary_, secondary.c_str()); SetWindowTextW(link_, link.c_str());
        visible(primary_, !primary.empty()); visible(secondary_, !secondary.empty()); visible(link_, !link.empty());
        visible(progress_, state == State::working);
        visible(edit_, state == State::recovery_input); visible(show_, state == State::recovery_input);
        visible(key_text_, state == State::recovery_show); visible(confirm_, state == State::recovery_show);
        EnableWindow(primary_, state != State::recovery_show || checked(confirm_));
        EnableWindow(secondary_, TRUE);
        if (state == State::working) {
            SetWindowLongPtrW(progress_, GWL_STYLE, GetWindowLongPtrW(progress_, GWL_STYLE) | PBS_MARQUEE);
            SendMessageW(progress_, PBM_SETMARQUEE, TRUE, 30);
        }
        SetWindowTextW(show_, tr(L"Mostra i caratteri"));
        SetWindowTextW(confirm_, tr(L"Ho scritto o stampato la chiave e la conservo in un luogo sicuro, lontano dalle chiavette."));
        layout();
        SetFocus(state == State::recovery_input ? edit_ : !primary.empty() ? primary_ : secondary_);
    }

    bool options_preview() const noexcept { return options_.mode == Mode::preview; }
    static bool checked(HWND control) { return SendMessageW(control, BM_GETCHECK, 0, 0) == BST_CHECKED; }
    fs::path profile_path() const { return options_.profile ? *options_.profile : age::desktop::default_profile_path(); }

    void status(const std::wstring& text) { SetWindowTextW(status_, text.c_str()); }

    // ---- Starting operations ------------------------------------------------------
    void start() {
        try {
            switch (options_.mode) {
            case Mode::encrypt: start_encrypt(); break;
            case Mode::decrypt: start_decrypt(); break;
            case Mode::new_key: start_new_key(); break;
            case Mode::new_recovery: start_new_recovery(); break;
            case Mode::preview: preview(); break;
            }
        } catch (const std::exception& error) {
            failure(age::desktop::describe(error));
        }
    }

    void working(const std::wstring& heading, const std::wstring& detail) {
        show_state(State::working, heading, detail, L"", tr(L"Annulla"), L"", ui::GuideArt::insert);
        SendMessageW(progress_, PBM_SETPOS, 0, 0);
    }

    void failure(const std::wstring& message, bool offer_recovery = false, bool offer_retry = false) {
        exit_code_ = 1;
        show_state(State::failure, tr(L"Operazione non riuscita"), message, offer_retry ? tr(L"Riprova") : tr(L"Chiudi"),
                   offer_retry ? tr(L"Chiudi") : L"", offer_recovery ? tr(L"Usa la chiave di recupero") : L"", ui::GuideArt::wait);
        retry_ = offer_retry;
    }

    std::wstring key_names(const age::PrfRequest& request) const {
        std::wstring names;
        for (const auto& credential : request.allowed) {
            for (const auto& key : profile_.keys) {
                if (key.credential == credential) names += (names.empty() ? L"«" : L"» o «") + widen(key.label);
            }
        }
        return names.empty() ? std::wstring(tr(L"la chiave")) : names + L"»";
    }

    age::PrfFunction prf() {
        auto touches = std::make_shared<unsigned>(0);
        return age::webauthn::prf([this, touches](const age::PrfRequest& request) {
            ++*touches;
            auto text = std::make_unique<std::wstring>(tr(L"Collega ") + key_names(request) + tr(L" e toccala quando lampeggia. Windows chiederà il PIN della chiave."));
            if (total_touches_ > 1) *text += L" (" + std::to_wstring(*touches) + tr(L" di ") + std::to_wstring(total_touches_) + L")";
            PostMessageW(window_, status_message, 1, reinterpret_cast<LPARAM>(text.release()));
        });
    }

    files::Observer observer() {
        return {[this](std::uint64_t done, std::uint64_t total) {
                    if (total) PostMessageW(window_, progress_message, static_cast<WPARAM>(done * 1000 / total), 0);
                },
                [this] { return !cancel_.load(); }};
    }

    template<class Work> void run_worker(Work work) {
        if (worker_.joinable()) worker_.join();
        cancel_ = false;
        worker_ = std::thread([this, work = std::move(work)]() mutable {
            const auto com = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
            auto outcome = std::make_unique<Outcome>();
            try {
                outcome->result = work();
                outcome->success = true;
            } catch (const age::NoIdentityMatched& error) {
                outcome->no_match = true; outcome->message = age::desktop::describe(error);
            } catch (const age::webauthn::Error& error) {
                outcome->cancelled = error.cancelled(); outcome->message = age::desktop::describe(error);
            } catch (const files::Error& error) {
                outcome->cancelled = error.problem() == files::Problem::cancelled; outcome->message = age::desktop::describe(error);
            } catch (const std::exception& error) {
                outcome->message = age::desktop::describe(error);
            }
            if (SUCCEEDED(com)) CoUninitialize();
            PostMessageW(window_, done_message, 0, reinterpret_cast<LPARAM>(outcome.release()));
        });
    }

    void start_encrypt() {
        try { profile_ = files::read_profile(profile_path()); }
        catch (const files::Error& error) {
            if (error.problem() == files::Problem::profile_missing) {
                failure(tr(L"Non ci sono ancora chiavi per cifrare i file. Apri Gestione HID FIDO2, scheda File, e aggiungi le chiavi e la chiave di recupero."));
                return;
            }
            throw;
        }
        if (!profile_.keys.empty() && !age::webauthn::prf_available()) throw age::webauthn::Error("unavailable", E_NOTIMPL);
        const bool folder = fs::is_directory(fs::symlink_status(options_.path));
        total_touches_ = static_cast<unsigned>(profile_.keys.size());
        working(folder ? tr(L"Cifratura della cartella") : tr(L"Cifratura del file"), options_.path.filename().wstring());
        if (!profile_.keys.empty()) status(tr(L"Servirà un tocco per ciascuna chiave del profilo (") + std::to_wstring(profile_.keys.size()) + L").");
        else status(tr(L"Cifratura con la chiave di recupero."));
        auto prf_function = prf();
        run_worker([this, prf_function, observer = observer()] {
            std::vector<std::unique_ptr<age::Recipient>> owned;
            for (const auto& key : profile_.keys) owned.push_back(std::make_unique<age::Fido2PrfRecipient>(key.credential, prf_function));
            for (const auto& entry : profile_.recovery) owned.push_back(std::make_unique<age::X25519Recipient>(entry.recipient));
            std::vector<age::Recipient*> recipients;
            for (auto& recipient : owned) recipients.push_back(recipient.get());
            return files::encrypt(options_.path, recipients, std::nullopt, true, observer);
        });
    }

    void start_decrypt() {
        const auto stanzas = files::read_stanzas(options_.path);
        has_keys_stanza_ = files::has_stanza(stanzas, age::fido2prf_label);
        has_recovery_stanza_ = files::has_stanza(stanzas, "X25519");
        try { profile_ = files::read_profile(profile_path()); } catch (const files::Error&) { profile_ = {}; }
        const bool keys = has_keys_stanza_ && !profile_.keys.empty() && age::webauthn::prf_available();
        if (keys && has_recovery_stanza_) {
            show_state(State::choose, tr(L"Come vuoi aprire il file?"), options_.path.filename().wstring() + L"\n" +
                       tr(L"Usa una chiave di sicurezza registrata oppure la chiave di recupero scritta su carta."),
                       tr(L"Chiave di sicurezza"), tr(L"Chiave di recupero"), L"", ui::GuideArt::insert);
            return;
        }
        if (keys) { decrypt_with_keys(); return; }
        if (has_recovery_stanza_) { ask_recovery(); return; }
        failure(has_keys_stanza_ && profile_.keys.empty()
            ? tr(L"Questo file si apre con una chiave di sicurezza, ma il profilo di questo computer non ne contiene. Copia qui il profilo dei destinatari oppure usa un computer dove le chiavi sono configurate.")
            : has_keys_stanza_ ? tr(L"Questa versione di Windows non permette di usare le chiavi di sicurezza per cifrare file (serve Windows 11 22H2 o successivo). La chiave di recupero funziona comunque.")
            : tr(L"Questo file non è destinato alle chiavi di questo programma."));
    }

    void decrypt_with_keys() {
        total_touches_ = 1;
        working(is_folder() ? tr(L"Apertura della cartella cifrata") : tr(L"Apertura del file cifrato"), options_.path.filename().wstring());
        status(tr(L"Collega una delle chiavi registrate e toccala quando lampeggia."));
        auto prf_function = prf();
        run_worker([this, prf_function, observer = observer()] {
            std::vector<std::string> parties;
            for (const auto& key : profile_.keys) if (std::ranges::find(parties, key.credential.rp_id) == parties.end()) parties.push_back(key.credential.rp_id);
            std::vector<std::unique_ptr<age::Identity>> owned;
            for (const auto& party : parties) {
                std::vector<age::Fido2PrfCredential> credentials;
                for (const auto& key : profile_.keys) if (key.credential.rp_id == party) credentials.push_back(key.credential);
                owned.push_back(std::make_unique<age::Fido2PrfIdentity>(std::move(credentials), prf_function));
            }
            std::vector<age::Identity*> identities;
            for (auto& identity : owned) identities.push_back(identity.get());
            return files::decrypt(options_.path, identities, std::nullopt, true, observer);
        });
        using_recovery_ = false;
    }

    bool is_folder() const { return files::is_folder_archive(options_.path); }

    void ask_recovery(const std::wstring& problem = {}) {
        show_state(State::recovery_input, tr(L"Chiave di recupero"),
                   tr(L"Digita la chiave scritta sul foglio, che inizia con AGE-SECRET-KEY-1. Spazi e maiuscole non contano."),
                   tr(L"Apri il file"), tr(L"Annulla"), L"", ui::GuideArt::password);
        SetWindowTextW(edit_, L"");
        status(problem);
    }

    void decrypt_with_recovery() {
        const auto length = GetWindowTextLengthW(edit_);
        std::wstring typed(static_cast<std::size_t>(std::max(length, 0)) + 1, L'\0');
        GetWindowTextW(edit_, typed.data(), static_cast<int>(typed.size()));
        SetWindowTextW(edit_, L""); SendMessageW(edit_, EM_EMPTYUNDOBUFFER, 0, 0);
        std::string text;
        for (const wchar_t c : typed) if (c) text.push_back(static_cast<char>(c < 0x80 ? std::towupper(c) : L'?'));
        wipe(typed);
        auto key = files::strip_whitespace(text);
        wipe(text);
        std::shared_ptr<age::X25519Identity> identity;
        try { identity = std::make_shared<age::X25519Identity>(age::X25519Identity::parse(key)); }
        catch (const age::FormatError&) {
            wipe(key);
            status(tr(L"Chiave non valida: controlla di averla ricopiata senza errori."));
            SetFocus(edit_);
            return;
        }
        wipe(key);
        using_recovery_ = true;
        working(is_folder() ? tr(L"Apertura della cartella cifrata") : tr(L"Apertura del file cifrato"), options_.path.filename().wstring());
        status(tr(L"Apertura con la chiave di recupero."));
        run_worker([this, identity, observer = observer()] {
            age::Identity* identities[] = {identity.get()};
            return files::decrypt(options_.path, identities, std::nullopt, true, observer);
        });
    }

    void start_new_key() {
        if (!age::webauthn::prf_available()) throw age::webauthn::Error("unavailable", E_NOTIMPL);
        const auto label = narrow(options_.label);
        if (!files::valid_label(label) || options_.label.size() > 64) { failure(tr(L"Etichetta della chiave non valida.")); return; }
        std::vector<age::Fido2PrfCredential> existing;
        try {
            for (const auto& key : files::read_profile(profile_path()).keys) {
                if (key.label == label) { failure(tr(L"Il profilo ha già una chiave con questa etichetta: ") + options_.label); return; }
                existing.push_back(key.credential);
            }
        } catch (const files::Error& error) {
            if (error.problem() != files::Problem::profile_missing) throw;
        }
        working(tr(L"Aggiungi la chiave «") + options_.label + L"»",
                tr(L"Collega la chiave «") + options_.label + tr(L"». Windows chiederà il PIN della chiave e un tocco per creare una credenziale dedicata ai file.\n"));
        status(tr(L"Usa una chiave diversa da quelle già registrate."));
        const auto path = profile_path();
        run_worker([this, existing, label, path] {
            const auto credential = age::webauthn::create_credential(options_.label, age::webauthn::default_rp_id, existing);
            files::append_profile(path, label, credential.encode(), age::desktop::today());
            return files::Result{path, false, {}};
        });
    }

    void start_new_recovery() {
        recovery_ = std::make_unique<age::X25519Identity>(age::X25519Identity::generate());
        auto secret = recovery_->encode();
        auto grouped = files::group_recovery_key(secret);
        show_recovery(widen(grouped));
        wipe(secret); wipe(grouped);
    }

    void show_recovery(std::wstring grouped) {
        // Two lines: the prefix and groups 1-7, then groups 8-15.
        const auto split = grouped.find(L' ', grouped.find(L' ') + 1 + 7 * 5 - 1);
        if (split != std::wstring::npos) grouped[split] = L'\n';
        show_state(State::recovery_show, tr(L"La tua chiave di recupero"),
                   tr(L"Scrivila o stampala ora: non verrà salvata né mostrata di nuovo. Con questa chiave chiunque può aprire tutti i file cifrati con il tuo profilo."),
                   tr(L"Fatto"), tr(L"Stampa…"), L"", ui::GuideArt::password);
        SetWindowTextW(key_text_, grouped.c_str());
        wipe(grouped);
        SendMessageW(confirm_, BM_SETCHECK, BST_UNCHECKED, 0);
        EnableWindow(primary_, FALSE);
    }

    void finish_recovery() {
        if (!recovery_) return;
        files::append_profile(profile_path(), narrow(tr(L"Recupero su carta")), recovery_->recipient().encode(), age::desktop::today());
        recovery_.reset();
        SetWindowTextW(key_text_, L"");
        exit_code_ = 0;
        show_state(State::success, tr(L"Chiave di recupero aggiunta"),
                   tr(L"I prossimi file cifrati si potranno aprire anche con questa chiave. I file cifrati prima restano invariati."),
                   tr(L"Chiudi"), L"", L"", ui::GuideArt::check);
    }

    void print_recovery() {
        if (!recovery_) return;
        PRINTDLGW dialog{sizeof(dialog)};
        dialog.hwndOwner = window_; dialog.Flags = PD_RETURNDC | PD_NOPAGENUMS | PD_NOSELECTION | PD_HIDEPRINTTOFILE;
        if (!PrintDlgW(&dialog)) return;
        struct Cleanup { PRINTDLGW& d; ~Cleanup() { if (d.hDC) DeleteDC(d.hDC); if (d.hDevMode) GlobalFree(d.hDevMode); if (d.hDevNames) GlobalFree(d.hDevNames); } } cleanup{dialog};
        const auto dc = dialog.hDC;
        const int dpi = GetDeviceCaps(dc, LOGPIXELSY), page = GetDeviceCaps(dc, HORZRES), margin = dpi;
        const auto font = [&](int points, int weight, const wchar_t* face) { return CreateFontW(-MulDiv(points, dpi, 72), 0, 0, 0, weight, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH, face); };
        const auto title = font(18, FW_SEMIBOLD, L"Segoe UI"), body = font(11, FW_NORMAL, L"Segoe UI"), key = font(14, FW_SEMIBOLD, L"Consolas");
        DOCINFOW document{sizeof(document)}; document.lpszDocName = L"HID FIDO2";
        auto secret = recovery_->encode();
        auto grouped = widen(files::group_recovery_key(secret));
        wipe(secret);
        if (StartDocW(dc, &document) > 0 && StartPage(dc) > 0) {
            int y = margin;
            const auto write = [&](HFONT selected, const std::wstring& text, int gap) {
                SelectObject(dc, selected);
                RECT box{margin, y, page - margin, y + dpi * 4};
                const int used = DrawTextW(dc, text.c_str(), -1, &box, DT_LEFT | DT_WORDBREAK | DT_NOPREFIX);
                y += used + gap;
            };
            write(title, tr(L"Chiave di recupero per i file cifrati"), dpi / 4);
            write(body, tr(L"HID FIDO2 · creata il ") + widen(age::desktop::today()), dpi / 3);
            write(key, grouped, dpi / 3);
            write(body, tr(L"Conserva questo foglio in un luogo sicuro, separato dalle chiavette. Chi lo possiede può aprire tutti i file cifrati con il tuo profilo.\n\nPer aprire un file: Gestione HID FIDO2 o tasto destro sul file > Decifra, poi «Chiave di recupero». Su qualsiasi sistema: age -d -i chiave.txt FILE.age (il file chiave.txt contiene la riga AGE-SECRET-KEY-1...)."), 0);
            EndPage(dc);
            EndDoc(dc);
        } else {
            AbortDoc(dc);
        }
        wipe(grouped);
        for (const auto f : {title, body, key}) DeleteObject(f);
    }

    // ---- Results -------------------------------------------------------------
    void completed(std::unique_ptr<Outcome> outcome) {
        if (worker_.joinable()) worker_.join();
        SendMessageW(progress_, PBM_SETMARQUEE, FALSE, 0);
        if (outcome->success) {
            exit_code_ = 0;
            last_output_ = outcome->result.output;
            if (options_.mode == Mode::new_key) {
                show_state(State::success, tr(L"Chiave aggiunta"),
                           tr(L"La chiave «") + options_.label + tr(L"» potrà aprire i prossimi file cifrati. I file cifrati prima restano invariati."),
                           tr(L"Chiudi"), L"", L"", ui::GuideArt::check);
                return;
            }
            const bool encrypting = options_.mode == Mode::encrypt;
            const auto heading = encrypting ? (outcome->result.folder ? tr(L"Cartella cifrata") : tr(L"File cifrato"))
                                            : (outcome->result.folder ? tr(L"Cartella decifrata") : tr(L"File decifrato"));
            auto detail = tr(L"Salvato come: ") + outcome->result.output.wstring();
            if (outcome->result.folder) detail += L"\n" + std::to_wstring(outcome->result.stats.files) + tr(L" file");
            if (encrypting) detail += L"\n" + std::wstring(tr(L"L'originale non è stato modificato né cancellato.\n"));
            show_state(State::success, heading, detail, tr(L"Apri cartella"), tr(L"Chiudi"), L"", ui::GuideArt::check);
            return;
        }
        if (options_.mode == Mode::decrypt && using_recovery_ && outcome->no_match) {
            ask_recovery(tr(L"Questa chiave di recupero non apre il file."));
            return;
        }
        const bool keys = options_.mode == Mode::decrypt && !using_recovery_;
        failure(outcome->message, keys && has_recovery_stanza_, keys || options_.mode == Mode::new_key || options_.mode == Mode::encrypt);
    }

    void open_output() {
        if (last_output_.empty()) return;
        const auto args = L"/select,\"" + last_output_.wstring() + L"\"";
        ShellExecuteW(window_, L"open", L"explorer.exe", args.c_str(), nullptr, SW_SHOWNORMAL);
    }

    void command(int id) {
        if (options_preview()) { if (id == secondary_id || (id == primary_id && state_ == State::success)) DestroyWindow(window_); return; }
        if (id == show_id) { SendMessageW(edit_, EM_SETPASSWORDCHAR, checked(show_) ? 0 : L'●', 0); InvalidateRect(edit_, nullptr, TRUE); return; }
        if (id == confirm_id) { EnableWindow(primary_, checked(confirm_)); return; }
        switch (state_) {
        case State::working: if (id == secondary_id) { cancel_ = true; status(tr(L"Annullamento… Se Windows mostra la finestra della chiave, chiudila con Annulla.")); } break;
        case State::choose: if (id == primary_id) decrypt_with_keys(); else if (id == secondary_id) ask_recovery(); break;
        case State::recovery_input: if (id == primary_id) decrypt_with_recovery(); else if (id == secondary_id) close(); break;
        case State::recovery_show:
            if (id == primary_id) finish_recovery();
            else if (id == secondary_id) print_recovery();
            break;
        case State::success: if (id == primary_id && !last_output_.empty() && options_.mode != Mode::new_key) { open_output(); close(); } else close(); break;
        case State::failure:
            if (id == link_id) ask_recovery();
            else if (id == primary_id && retry_) { exit_code_ = 0; start(); }
            else close();
            break;
        }
    }

    void close() { DestroyWindow(window_); }

    bool may_close() {
        if (options_preview()) return true;
        if (state_ == State::working) {
            MessageBoxW(window_, tr(L"Attendi la fine dell'operazione o premi Annulla."), tr(window_title), MB_OK | MB_ICONINFORMATION);
            return false;
        }
        if (state_ == State::recovery_show &&
            MessageBoxW(window_, tr(L"Chiudere senza aggiungere la chiave di recupero? Questa chiave non verrà mostrata di nuovo e non potrà aprire nessun file."),
                        tr(window_title), MB_YESNO | MB_DEFBUTTON2 | MB_ICONWARNING) != IDYES) return false;
        return true;
    }

    // ---- Preview and snapshots (synthetic data, actions disabled) ----------------
    void preview_state(const std::wstring& name) {
        const std::wstring sample = L"AGE-SECRET-KEY-1 QPZR Y9X8 GF2T VDW0 S3JN 54KH CE6M UA7L QPZR Y9X8 GF2T VDW0 S3JN 54KH C";
        if (name == L"touch") {
            total_touches_ = 2; working(tr(L"Cifratura della cartella"), L"Documenti");
            status(std::wstring(tr(L"Collega ")) + L"«Principale»" + tr(L" e toccala quando lampeggia. Windows chiederà il PIN della chiave.") + L" (1" + tr(L" di ") + L"2)");
            art_ = ui::GuideArt::touch; SendMessageW(progress_, PBM_SETMARQUEE, FALSE, 0);
        } else if (name == L"choose") {
            show_state(State::choose, tr(L"Come vuoi aprire il file?"), L"Contratto.pdf.age\n" + std::wstring(tr(L"Usa una chiave di sicurezza registrata oppure la chiave di recupero scritta su carta.")),
                       tr(L"Chiave di sicurezza"), tr(L"Chiave di recupero"), L"", ui::GuideArt::insert);
        } else if (name == L"recovery") {
            show_state(State::recovery_input, tr(L"Chiave di recupero"), tr(L"Digita la chiave scritta sul foglio, che inizia con AGE-SECRET-KEY-1. Spazi e maiuscole non contano."),
                       tr(L"Apri il file"), tr(L"Annulla"), L"", ui::GuideArt::password);
            SetWindowTextW(edit_, L"AGE-SECRET-KEY-1QPZRY9X8");
        } else if (name == L"show") {
            show_recovery(sample);
        } else if (name == L"failure") {
            failure(tr(L"Operazione annullata o chiave non registrata per questo file."), true, true);
        } else {
            show_state(State::success, tr(L"Cartella cifrata"), tr(L"Salvato come: ") + std::wstring(L"C:\\Users\\Anna\\Documenti.tar.age\n12") + tr(L" file") +
                       L"\n" + tr(L"L'originale non è stato modificato né cancellato.\n"), tr(L"Apri cartella"), tr(L"Chiudi"), L"", ui::GuideArt::check);
        }
        EnableWindow(edit_, FALSE); EnableWindow(show_, FALSE); EnableWindow(confirm_, FALSE);
        InvalidateRect(window_, nullptr, TRUE);
    }

    void preview() {
        if (options_.snapshot.empty()) { preview_state(options_.preview); return; }
        Gdiplus::GdiplusStartupInput input; ULONG_PTR token{};
        if (Gdiplus::GdiplusStartup(&token, &input, nullptr) != Gdiplus::Ok) throw std::runtime_error("PNG renderer unavailable");
        const CLSID png{0x557cf406, 0x1a04, 0x11d3, {0x9a, 0x73, 0x00, 0x00, 0xf8, 0x1e, 0xf3, 0x2e}};
        fs::create_directories(options_.snapshot);
        for (const auto* name : {L"touch", L"choose", L"recovery", L"show", L"success", L"failure"}) {
            preview_state(name);
            RedrawWindow(window_, nullptr, nullptr, RDW_INVALIDATE | RDW_ALLCHILDREN | RDW_UPDATENOW);
            RECT area{}; GetWindowRect(window_, &area);
            const auto dc = GetDC(window_), memory = CreateCompatibleDC(dc);
            const auto bitmap = CreateCompatibleBitmap(dc, area.right - area.left, area.bottom - area.top);
            const auto old = SelectObject(memory, bitmap);
            SendMessageW(window_, WM_PRINT, reinterpret_cast<WPARAM>(memory), PRF_CLIENT | PRF_CHILDREN | PRF_ERASEBKGND | PRF_NONCLIENT);
            { Gdiplus::Bitmap image(bitmap, nullptr); const auto path = options_.snapshot / (std::wstring(L"files-") + name + L".png"); image.Save(path.c_str(), &png, nullptr); }
            SelectObject(memory, old); DeleteObject(bitmap); DeleteDC(memory); ReleaseDC(window_, dc);
        }
        Gdiplus::GdiplusShutdown(token);
        DestroyWindow(window_);
    }

    void paint(HDC dc) {
        RECT area{}; GetClientRect(window_, &area); FillRect(dc, &area, white_);
        if (state_ == State::recovery_input || state_ == State::recovery_show) {
            if (state_ == State::recovery_show) {
                RECT frame{scale(36), scale(140), area.right - scale(36), scale(236)};
                const auto pen = CreatePen(PS_SOLID, scale(1), RGB(220, 223, 227)); const auto old = SelectObject(dc, pen);
                SelectObject(dc, GetStockObject(NULL_BRUSH)); RoundRect(dc, frame.left, frame.top, frame.right, frame.bottom, scale(10), scale(10));
                SelectObject(dc, old); DeleteObject(pen);
            }
            return;
        }
        const int height = MulDiv(area.bottom, 96, static_cast<int>(dpi_));
        RECT art{scale(110), scale(150), area.right - scale(110), scale(height - 156)};
        if (art.bottom > art.top) ui::draw_guide_art(dc, art, art_);
    }

    static LRESULT CALLBACK window_proc(HWND window, UINT message, WPARAM w, LPARAM l) {
        auto* self = reinterpret_cast<FilesWindow*>(GetWindowLongPtrW(window, GWLP_USERDATA));
        if (message == WM_NCCREATE) {
            self = static_cast<FilesWindow*>(reinterpret_cast<CREATESTRUCTW*>(l)->lpCreateParams);
            self->window_ = window;
            SetWindowLongPtrW(window, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
        }
        if (!self) return DefWindowProcW(window, message, w, l);
        try {
            switch (message) {
            case WM_CREATE: self->create(); return 0;
            case WM_DPICHANGED: { const auto* r = reinterpret_cast<RECT*>(l); self->dpi_ = HIWORD(w); SetWindowPos(window, nullptr, r->left, r->top, r->right - r->left, r->bottom - r->top, SWP_NOZORDER); self->fonts(); self->layout(); return 0; }
            case start_message: self->start(); return 0;
            case status_message: {
                std::unique_ptr<std::wstring> text(reinterpret_cast<std::wstring*>(l));
                self->status(*text);
                if (w == 1) { self->art_ = ui::GuideArt::touch; InvalidateRect(window, nullptr, TRUE); }
                return 0;
            }
            case progress_message:
                if (GetWindowLongPtrW(self->progress_, GWL_STYLE) & PBS_MARQUEE) {
                    SendMessageW(self->progress_, PBM_SETMARQUEE, FALSE, 0);
                    SetWindowLongPtrW(self->progress_, GWL_STYLE, GetWindowLongPtrW(self->progress_, GWL_STYLE) & ~PBS_MARQUEE);
                }
                if (self->art_ != ui::GuideArt::wait) { self->art_ = ui::GuideArt::wait; InvalidateRect(window, nullptr, TRUE); }
                SendMessageW(self->progress_, PBM_SETPOS, w, 0);
                return 0;
            case done_message: self->completed(std::unique_ptr<Outcome>(reinterpret_cast<Outcome*>(l))); return 0;
            case WM_COMMAND: if (HIWORD(w) == BN_CLICKED) self->command(LOWORD(w)); return 0;
            case WM_DRAWITEM: {
                const auto& item = *reinterpret_cast<DRAWITEMSTRUCT*>(l);
                ui::draw_guide_button(item, item.CtlID == primary_id, item.CtlID == link_id);
                return TRUE;
            }
            case WM_CTLCOLORSTATIC: {
                const auto dc = reinterpret_cast<HDC>(w);
                SetBkMode(dc, TRANSPARENT);
                const auto control = reinterpret_cast<HWND>(l);
                SetTextColor(dc, control == self->status_ && self->state_ != State::working ? RGB(170, 50, 40) : control == self->status_ ? RGB(25, 90, 155) : RGB(35, 43, 55));
                return reinterpret_cast<LRESULT>(self->white_);
            }
            case WM_PAINT: { PAINTSTRUCT paint{}; const auto dc = BeginPaint(window, &paint); self->paint(dc); EndPaint(window, &paint); return 0; }
            case WM_PRINTCLIENT: self->paint(reinterpret_cast<HDC>(w)); return 0;
            case WM_CLOSE: if (self->may_close()) DestroyWindow(window); return 0;
            case WM_DESTROY:
                self->recovery_.reset();
                SetWindowTextW(self->key_text_, L"");
                age::webauthn::set_owner_window(nullptr);
                PostQuitMessage(0);
                return 0;
            }
        } catch (const std::exception& error) {
            self->failure(age::desktop::describe(error));
            return 0;
        }
        return DefWindowProcW(window, message, w, l);
    }

    Options options_;
    HWND window_{}, heading_{}, detail_{}, status_{}, progress_{}, edit_{}, show_{}, key_text_{}, confirm_{}, primary_{}, secondary_{}, link_{};
    HFONT font_{}, large_{}, mono_{};
    HBRUSH white_{CreateSolidBrush(RGB(255, 255, 255))};
    UINT dpi_{96};
    State state_{State::working};
    ui::GuideArt art_{ui::GuideArt::insert};
    files::Profile profile_;
    std::unique_ptr<age::X25519Identity> recovery_;
    std::thread worker_;
    std::atomic_bool cancel_{false};
    unsigned total_touches_{};
    bool has_keys_stanza_{}, has_recovery_stanza_{}, using_recovery_{}, retry_{};
    fs::path last_output_;
    int exit_code_{2};
};

std::optional<Options> parse_options() {
    int count{};
    auto** args = CommandLineToArgvW(GetCommandLineW(), &count);
    if (!args) throw std::runtime_error("Arguments unavailable");
    struct Free { LPWSTR* value; ~Free() { LocalFree(value); } } free{args};
    Options options;
    bool mode_set = false;
    const auto set_mode = [&](Mode mode) { if (mode_set) throw std::invalid_argument("Only one action"); options.mode = mode; mode_set = true; };
    for (int i = 1; i < count; ++i) {
        const std::wstring_view arg(args[i]);
        const auto next = [&]() -> std::wstring { if (++i == count || !*args[i]) throw std::invalid_argument("Missing value"); return args[i]; };
        if (arg == L"--encrypt") { set_mode(Mode::encrypt); options.path = next(); }
        else if (arg == L"--decrypt") { set_mode(Mode::decrypt); options.path = next(); }
        else if (arg == L"--pick-encrypt-file" || arg == L"--pick-encrypt-folder" || arg == L"--pick-decrypt") {
            const bool decrypting = arg == L"--pick-decrypt";
            set_mode(decrypting ? Mode::decrypt : Mode::encrypt);
            const auto selected = pick(arg == L"--pick-encrypt-folder", decrypting);
            if (!selected) return std::nullopt;
            options.path = *selected;
        }
        else if (arg == L"--new-key") { set_mode(Mode::new_key); options.label = next(); }
        else if (arg == L"--new-recovery") set_mode(Mode::new_recovery);
        else if (arg == L"--preview") { set_mode(Mode::preview); options.preview = next(); }
        else if (arg == L"--snapshot") options.snapshot = next();
        else if (arg == L"--profile") options.profile = fs::path(next());
        else if (arg == L"--language") {
            const auto language = ui::parse_language(next());
            if (!language) throw std::invalid_argument("Language must be it or en");
            ui::set_language(*language);
        } else throw std::invalid_argument("Unknown argument");
    }
    if (!mode_set || (!options.snapshot.empty() && options.mode != Mode::preview)) throw std::invalid_argument("Invalid arguments");
    return options;
}
}

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int show) {
    SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32);
    ui::set_language(ui::preferred_language());
    const auto com = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    struct Co { HRESULT value; ~Co() { if (SUCCEEDED(value)) CoUninitialize(); } } co{com};
    INITCOMMONCONTROLSEX controls{sizeof(controls), ICC_STANDARD_CLASSES | ICC_PROGRESS_CLASS};
    InitCommonControlsEx(&controls);
    try {
        const auto options = parse_options();
        if (!options) return 2;
        FilesWindow window(*options);
        return window.run(instance, show);
    } catch (const std::invalid_argument&) {
        MessageBoxW(nullptr, tr(L"Avvia questa funzione da Gestione HID FIDO2 (scheda File) o dal menu del tasto destro di Esplora file."), tr(window_title), MB_OK | MB_ICONINFORMATION);
        return 2;
    } catch (const std::exception& error) {
        MessageBoxW(nullptr, hidfido::age::desktop::describe(error).c_str(), tr(window_title), MB_OK | MB_ICONERROR);
        return 1;
    }
}
