#include "hidfido/localization.hpp"
#include "platform.hpp"
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
enum { nav_overview = 100, nav_keys, nav_password, nav_install, refresh_id = 200, close_id, primary_id, verify_id, proof_id, add_id, remove_id, windows_password_id, password_id, backup_id, restore_id, install_id, uninstall_id, recovery_id, legacy_id, language_id };
struct Options { bool demo{}, child{}, approved{}, package{}, audit{}, apply{}, remove{}, legacy{}; std::optional<hidfido::ui::Language> language; std::wstring expected_sid; std::filesystem::path snapshot, build, output, result; };
Options parse_options() {
    int count{}; auto** args = CommandLineToArgvW(GetCommandLineW(), &count); if (!args) throw std::runtime_error("Arguments unavailable"); Options out;
    try {
        for (int i = 1; i < count; ++i) {
            const std::wstring_view arg(args[i]);
            const auto next = [&]() -> std::wstring { if (++i == count) throw std::runtime_error("Missing argument"); return args[i]; };
            if (arg == L"--manage") {}
            else if (arg == L"--demo") out.demo = true;
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
    if (modes > 1 || (!out.snapshot.empty() && !out.demo) || (out.package && out.child) || ((out.audit || out.apply || out.remove) && out.result.empty()) || (out.legacy && !out.apply) || (!out.result.empty() && !out.package && !out.audit && !out.apply && !out.remove)) throw std::runtime_error("Invalid mode"); return out;
}
std::filesystem::path module_directory() { std::wstring path(32768, L'\0'); const auto size = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size())); if (!size || size >= path.size()) throw std::runtime_error("Module path unavailable"); path.resize(size); return std::filesystem::path(path).parent_path(); }
bool confirm(HWND parent, const wchar_t* text) { return MessageBoxW(parent, text, tr(title), MB_YESNO | MB_DEFBUTTON2 | MB_ICONQUESTION | MB_SETFOREGROUND) == IDYES; }
void error(HWND parent, const wchar_t* text) { MessageBoxW(parent, text, tr(title), MB_OK | MB_ICONERROR | MB_SETFOREGROUND); }
void technical_error(HWND parent, const wchar_t* details) {
    TASKDIALOGCONFIG dialog{sizeof(dialog)}; dialog.hwndParent = parent;
    dialog.dwCommonButtons = TDCBF_OK_BUTTON; dialog.pszWindowTitle = tr(title);
    dialog.pszMainIcon = TD_ERROR_ICON;
    dialog.pszContent = tr(L"Impossibile completare l'operazione. Verifica di aver estratto tutto il pacchetto e riprova. Per il recupero usa la password Windows.");
    dialog.pszExpandedInformation = details; dialog.pszExpandedControlText = tr(L"Dettagli tecnici"); dialog.pszCollapsedControlText = tr(L"Nascondi dettagli");
    if (FAILED(TaskDialogIndirect(&dialog, nullptr, nullptr, nullptr))) error(parent, dialog.pszContent);
}
std::wstring date(std::uint64_t unix_time) {
    if (!unix_time || unix_time > 30000000000ULL) return tr(L"Da eseguire"); ULARGE_INTEGER time{}; time.QuadPart = (unix_time + 11644473600ULL) * 10000000ULL;
    FILETIME ft{time.LowPart, time.HighPart}, local{}; SYSTEMTIME st{};
    if (!FileTimeToLocalFileTime(&ft, &local) || !FileTimeToSystemTime(&local, &st)) return tr(L"Data non disponibile");
    std::array<wchar_t, 48> buffer{}; swprintf_s(buffer.data(), buffer.size(), L"%02u/%02u/%04u %02u:%02u", st.wDay, st.wMonth, st.wYear, st.wHour, st.wMinute); return buffer.data();
}
std::wstring protection(const std::string& proof) {
    if (proof == "verified_denied") return tr(L"Verificata: senza PIN negato");
    if (proof == "verified_distinct") return tr(L"Verificata: segreto distinto");
    return tr(L"Da verificare");
}
std::wstring ask_label(HWND parent) {
    std::wstring result = hidfido::ui::language() == hidfido::ui::Language::english ? L"Backup 2" : L"Riserva 2";
    const auto procedure = [](HWND dialog, UINT message, WPARAM w, LPARAM l) -> INT_PTR {
        if (message == WM_INITDIALOG) { SetWindowTextW(dialog, tr(L"Nome della chiave")); SetDlgItemTextW(dialog, 1002, tr(L"Scegli un nome riconoscibile, per esempio Riserva 2.")); SetDlgItemTextW(dialog, IDOK, tr(L"Continua")); SetDlgItemTextW(dialog, IDCANCEL, tr(L"Annulla")); SetWindowLongPtrW(dialog, DWLP_USER, l); auto* text = reinterpret_cast<std::wstring*>(l); SetDlgItemTextW(dialog, 1001, text->c_str()); SendDlgItemMessageW(dialog, 1001, EM_SETLIMITTEXT, 64, 0); return TRUE; }
        if (message == WM_COMMAND && LOWORD(w) == IDOK) { std::array<wchar_t, 65> text{}; GetDlgItemTextW(dialog, 1001, text.data(), static_cast<int>(text.size())); std::wstring label(text.data()); if (label.empty() || !std::all_of(label.begin(), label.end(), [](wchar_t c) { return iswalnum(c) || c == L' ' || c == L'_' || c == L'-' || c == L'.'; })) { MessageBoxW(dialog, tr(L"Usa lettere, numeri, spazi, punto o trattino."), tr(title), MB_OK | MB_ICONWARNING); return TRUE; } *reinterpret_cast<std::wstring*>(GetWindowLongPtrW(dialog, DWLP_USER)) = label; EndDialog(dialog, IDOK); return TRUE; }
        if (message == WM_COMMAND && LOWORD(w) == IDCANCEL) { EndDialog(dialog, IDCANCEL); return TRUE; } return FALSE;
    };
    return DialogBoxParamW(GetModuleHandleW(nullptr), MAKEINTRESOURCEW(101), parent, procedure, reinterpret_cast<LPARAM>(&result)) == IDOK ? result : L"";
}
struct JobResult { TransactionResult transaction; bool uninstall{}, shortcut_warning{}; std::wstring failure; };
class Manager {
public:
    Manager(Options options, std::filesystem::path package, std::wstring sid) : options_(std::move(options)), package_(std::move(package)), sid_(std::move(sid)) {}
    ~Manager() { if (worker_.joinable()) worker_.join(); clear_fonts(); DeleteObject(white_); DeleteObject(sidebar_); }
    int run(HINSTANCE instance, int show) {
        WNDCLASSEXW cls{sizeof(cls)}; cls.lpfnWndProc = window_proc; cls.hInstance = instance; cls.lpszClassName = L"HidFido2NativeManager"; cls.hCursor = LoadCursorW(nullptr, IDC_ARROW); cls.hIcon = LoadIconW(instance, MAKEINTRESOURCEW(1)); cls.hIconSm = cls.hIcon; cls.hbrBackground = white_;
        if (!RegisterClassExW(&cls)) win_error("Register manager"); const auto dpi = GetDpiForSystem(); RECT bounds{0, 0, MulDiv(1000, dpi, 96), MulDiv(740, dpi, 96)}; AdjustWindowRectExForDpi(&bounds, WS_OVERLAPPEDWINDOW, FALSE, 0, dpi);
        RECT work{}; SystemParametersInfoW(SPI_GETWORKAREA, 0, &work, 0); const auto width = std::min<LONG>(bounds.right - bounds.left, work.right - work.left), height = std::min<LONG>(bounds.bottom - bounds.top, work.bottom - work.top);
        window_ = CreateWindowExW(0, cls.lpszClassName, options_.demo ? tr(L"Gestione HID FIDO2 - Anteprima") : tr(title), WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN, work.left + (work.right - work.left - width) / 2, work.top + (work.bottom - work.top - height) / 2, width, height, nullptr, nullptr, instance, this);
        if (!window_) win_error("Create manager"); ShowWindow(window_, show); UpdateWindow(window_); if (!options_.snapshot.empty()) PostMessageW(window_, capture_message, 0, 0);
        MSG message{}; while (GetMessageW(&message, nullptr, 0, 0) > 0) { if (!IsDialogMessageW(window_, &message)) { TranslateMessage(&message); DispatchMessageW(&message); } } return static_cast<int>(message.wParam);
    }
private:
    int scale(int value) const { return MulDiv(value, static_cast<int>(dpi_), 96); }
    HWND make(const wchar_t* kind, const wchar_t* text, DWORD style = 0, int id = 0, int page = -1) {
        const auto h = CreateWindowExW(kind == std::wstring_view(WC_LISTVIEWW) || kind == std::wstring_view(WC_COMBOBOXW) ? WS_EX_CLIENTEDGE : 0, kind, tr(text), WS_CHILD | WS_VISIBLE | style, 0, 0, 1, 1, window_, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), GetModuleHandleW(nullptr), nullptr);
        if (!h) win_error("Create manager control"); controls_.push_back(h); if (*text) labels_.emplace_back(h, text); if (page >= 0) pages_[static_cast<std::size_t>(page)].push_back(h); SendMessageW(h, WM_SETFONT, reinterpret_cast<WPARAM>(font_), TRUE); return h;
    }
    HWND text(const wchar_t* value, int page = -1) { return make(L"STATIC", value, SS_LEFT, 0, page); }
    HWND button(const wchar_t* value, int id, int page) { return make(L"BUTTON", value, BS_PUSHBUTTON | WS_TABSTOP, id, page); }
    void box(HWND control, int x, int y, int width, int height) { MoveWindow(control, scale(x), scale(y), scale(std::max(width, 1)), scale(std::max(height, 1)), TRUE); }
    void clear_fonts() { if (font_) DeleteObject(font_); if (large_) DeleteObject(large_); if (bold_) DeleteObject(bold_); font_ = large_ = bold_ = nullptr; }
    void fonts() {
        clear_fonts(); dpi_ = GetDpiForWindow(window_); font_ = CreateFontW(-scale(15), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
        large_ = CreateFontW(-scale(27), 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
        bold_ = CreateFontW(-scale(18), 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
        for (auto h : controls_) SendMessageW(h, WM_SETFONT, reinterpret_cast<WPARAM>(font_), TRUE);
        for (auto h : {heading_, brand_, summary_, password_heading_, backups_heading_, installed_heading_}) if (h) SendMessageW(h, WM_SETFONT, reinterpret_cast<WPARAM>(h == heading_ ? large_ : bold_), TRUE);
    }
    void create() {
        fonts(); brand_ = text(L"HID FIDO2"); brand_note_ = text(L"Accesso a Windows");
        const wchar_t* names[]{L"Panoramica", L"Chiavi", L"Password e recupero", L"Installazione"};
        for (int i = 0; i < 4; ++i) nav_[i] = make(L"BUTTON", names[i], BS_OWNERDRAW | WS_TABSTOP, nav_overview + i);
        version_ = text(options_.demo ? L"Versione 0.7 · Anteprima" : L"Versione 0.7 · App nativa"); heading_ = text(L"Panoramica"); subtitle_ = text(L"Gestisci l'accesso a Windows e le tue chiavi di sicurezza.");
        summary_ = text(L"Lettura dello stato…", 0); overview_detail_ = text(L"", 0); proof_note_ = text(L"", 0);
        primary_ = button(L"Verifica una chiave", primary_id, 0);
        instructions_ = text(L"Per entrare in Windows\r\n\r\nCollega una sola chiave, premi Win+L e scegli Opzioni di accesso > HID FIDO2. Inserisci il PIN della chiave e toccala quando richiesto.", 0);
        recovery_note_ = text(L"La password Windows resta il tuo accesso di recupero. Conserva una seconda chiave in un luogo sicuro.", 0);
        key_list_ = make(WC_LISTVIEWW, L"", LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS | WS_TABSTOP, 0, 1); ListView_SetExtendedListViewStyle(key_list_, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);
        const wchar_t* columns[]{L"Chiave", L"Protezione tramite PIN", L"Ultimo controllo"}; for (int i = 0; i < 3; ++i) { LVCOLUMNW column{}; column.mask = LVCF_TEXT | LVCF_WIDTH; column.pszText = const_cast<wchar_t*>(tr(columns[i])); column.cx = scale(i == 1 ? 280 : 180); ListView_InsertColumn(key_list_, i, &column); }
        verify_ = button(L"Prova chiave", verify_id, 1); proof_ = button(L"Verifica protezione", proof_id, 1); add_ = button(L"Aggiungi chiave", add_id, 1); remove_ = button(L"Rimuovi…", remove_id, 1);
        key_help_ = text(L"Prova chiave verifica l'archivio e la password con Windows. Verifica protezione richiede rimozione e reinserimento: un risultato inconcludente interrompe la prova.", 1);
        password_heading_ = text(L"Quando cambi la password Windows", 2); password_help_ = text(L"Cambia prima la password in Windows. Poi aggiorna la copia cifrata con una chiave registrata; anche l'altra chiave continuerà a funzionare.", 2);
        settings_ = button(L"Password Windows…", windows_password_id, 2); password_ = button(L"Aggiorna copia cifrata", password_id, 2);
        backups_heading_ = text(L"Copie protette dell'archivio", 2); backup_help_ = text(L"Il ripristino conserva chiavi revocate e contatori correnti. Una copia di una vecchia password non viene riattivata.", 2);
        backups_ = make(WC_COMBOBOXW, L"", CBS_DROPDOWNLIST | WS_TABSTOP | WS_VSCROLL, 0, 2); backup_ = button(L"Crea copia protetta", backup_id, 2); restore_ = button(L"Ripristina selezionata…", restore_id, 2);
        lost_help_ = text(L"Chiave persa: entra con la password Windows e revoca la chiave. Se una vecchia copia potrebbe essere stata sottratta, cambia anche la password Windows.", 2);
        installed_heading_ = text(L"", 3); installed_detail_ = text(L"", 3); trust_ = text(L"Prototipo locale non firmato. La distribuzione richiede la firma verificata dell'editore.", 3);
        legacy_ = make(L"BUTTON", L"Conserva le chiavi già registrate nel prototipo locale. Le prove hardware mancanti rimarranno da eseguire.", BS_AUTOCHECKBOX | BS_MULTILINE | WS_TABSTOP, legacy_id, 3);
        install_ = button(L"Installa / aggiorna", install_id, 3); uninstall_ = button(L"Rimuovi provider…", uninstall_id, 3); guide_ = button(L"Guida di recupero", recovery_id, 3);
        install_help_ = text(L"Il nuovo pacchetto viene verificato prima di cambiare la registrazione. Le copie precedenti restano disponibili; in caso di errore viene tentato il ripristino compatibile.", 3);
        native_note_ = text(L"Interfaccia, installazione, aggiornamento e rimozione sono C++ nativi. Il pacchetto utente contiene solo eseguibili e manifest.", 3);
        footer_ = text(L"Pronto"); progress_ = make(PROGRESS_CLASSW, L"", PBS_MARQUEE); close_ = button(L"Chiudi", close_id, -1); refresh_ = button(L"Aggiorna stato", refresh_id, -1);
        language_label_ = text(L"Lingua / Language");
        language_select_ = make(WC_COMBOBOXW, L"", CBS_DROPDOWNLIST | WS_TABSTOP, language_id);
        SendMessageW(language_select_, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"Italiano"));
        SendMessageW(language_select_, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"English"));
        SendMessageW(language_select_, CB_SETCURSEL, hidfido::ui::language() == hidfido::ui::Language::italian ? 0 : 1, 0);
        fonts(); change_page(0); refresh(); SetTimer(window_, 1, 250, nullptr);
    }
    void layout() {
        RECT rectangle{}; GetClientRect(window_, &rectangle); const int width = MulDiv(rectangle.right, 96, static_cast<int>(dpi_)), height = MulDiv(rectangle.bottom, 96, static_cast<int>(dpi_)); const int x = 244, content = width - x - 28;
        box(brand_, 22, 28, 185, 28); box(brand_note_, 22, 64, 185, 28); for (int i = 0; i < 4; ++i) box(nav_[i], 10, 130 + i * 54, 202, 44); box(version_, 22, height - 95, 185, 45);
        box(language_label_, 22, height - 192, 185, 24); box(language_select_, 22, height - 160, 178, 140);
        box(heading_, x, 26, content, 42); box(subtitle_, x, 76, content, 42);
        box(summary_, x, 145, content, 34); box(overview_detail_, x, 194, content, 54); box(proof_note_, x, 258, content, 64); box(primary_, x, 338, 250, 38); box(instructions_, x, 408, content, 126); box(recovery_note_, x, 551, content, 64);
        const int list_height = std::max(150, height - 350); box(key_list_, x, 139, content, list_height);
        box(verify_, x, 157 + list_height, 135, 38); box(proof_, x + 145, 157 + list_height, 175, 38); box(add_, x + 330, 157 + list_height, 150, 38); box(remove_, x + 490, 157 + list_height, 130, 38); box(key_help_, x, 215 + list_height, content, 94);
        ListView_SetColumnWidth(key_list_, 0, scale(145)); ListView_SetColumnWidth(key_list_, 1, scale(std::max(230, content - 345))); ListView_SetColumnWidth(key_list_, 2, scale(182));
        box(password_heading_, x, 140, content, 30); box(password_help_, x, 181, content, 65); box(settings_, x, 259, 210, 38); box(password_, x + 225, 259, 225, 38);
        box(backups_heading_, x, 328, content, 30); box(backup_help_, x, 371, content, 54); box(backups_, x, 440, content, 200); box(backup_, x, 488, 215, 38); box(restore_, x + 230, 488, 235, 38); box(lost_help_, x, std::min(550, height - 135), content, 76);
        box(installed_heading_, x, 141, content, 32); box(installed_detail_, x, 187, content, 44); box(trust_, x, 241, content, 62); box(legacy_, x, 318, content, 70);
        box(install_, x, 411, 210, 38); box(uninstall_, x + 225, 411, 210, 38); box(guide_, x, 465, 210, 38); box(install_help_, x, 526, content, 70); box(native_note_, x, 603, content, 50);
        ShowWindow(native_note_, page_ == 3 && height >= 720 ? SW_SHOW : SW_HIDE);
        box(footer_, x, height - 51, content - 280, 42); box(progress_, x, height - 15, content - 280, 5); box(refresh_, width - 290, height - 52, 150, 35); box(close_, width - 128, height - 52, 100, 35);
    }
    void change_page(int page) {
        page_ = page; const wchar_t* titles[]{tr(L"Panoramica"), tr(L"Le tue chiavi"), tr(L"Password e recupero"), tr(L"Installazione")}; SetWindowTextW(heading_, titles[page]);
        for (int i = 0; i < 4; ++i) { for (auto h : pages_[i]) ShowWindow(h, i == page ? SW_SHOW : SW_HIDE); InvalidateRect(nav_[i], nullptr, TRUE); } layout(); states();
    }
    void change_language() {
        if (busy_) return;
        const auto selected = SendMessageW(language_select_, CB_GETCURSEL, 0, 0);
        if (selected != 0 && selected != 1) return;
        const auto next = selected == 0 ? hidfido::ui::Language::italian : hidfido::ui::Language::english;
        if (!options_.demo && !hidfido::ui::save_preferred_language(next)) {
            SendMessageW(language_select_, CB_SETCURSEL, hidfido::ui::language() == hidfido::ui::Language::italian ? 0 : 1, 0);
            error(window_, tr(L"Impossibile salvare la lingua. Riapri il gestore come amministratore e riprova.")); return;
        }
        if (next == hidfido::ui::language()) return;
        hidfido::ui::set_language(next);
        SetWindowTextW(window_, options_.demo ? tr(L"Gestione HID FIDO2 - Anteprima") : tr(title));
        for (const auto& [control, key] : labels_) SetWindowTextW(control, tr(key));
        const wchar_t* columns[]{L"Chiave", L"Protezione tramite PIN", L"Ultimo controllo"};
        for (int i = 0; i < 3; ++i) { LVCOLUMNW column{}; column.mask = LVCF_TEXT; column.pszText = const_cast<wchar_t*>(tr(columns[i])); ListView_SetColumn(key_list_, i, &column); }
        refresh(); change_page(page_);
    }
    std::wstring selected_key() const { const auto index = ListView_GetNextItem(key_list_, -1, LVNI_SELECTED); return index >= 0 && static_cast<std::size_t>(index) < status_.keys.size() ? status_.keys[static_cast<std::size_t>(index)].label : L""; }
    void states() {
        const bool selected = !selected_key().empty(); const auto allow = [&](VaultAction a) { return can_run(status_, a, busy_, options_.demo); };
        EnableWindow(verify_, allow(VaultAction::verify) && selected); EnableWindow(proof_, allow(VaultAction::verify_protection) && selected); EnableWindow(add_, allow(VaultAction::add_key)); EnableWindow(remove_, allow(VaultAction::remove_key) && selected);
        EnableWindow(settings_, !options_.demo && !busy_); EnableWindow(password_, allow(VaultAction::update_password)); EnableWindow(backup_, allow(VaultAction::backup)); EnableWindow(restore_, allow(VaultAction::restore));
        const auto verified = std::count_if(status_.keys.begin(), status_.keys.end(), [](const auto& key) { return key.proof != "unknown"; }); const bool legacy = SendMessageW(legacy_, BM_GETCHECK, 0, 0) == BST_CHECKED;
        const bool here = !status_.provider_path.empty() && _wcsicmp(status_.provider_path.c_str(), (package_ / L"bin" / L"HidFido2CredentialProvider.dll").c_str()) == 0;
        EnableWindow(install_, !options_.demo && !busy_ && !here && status_.enrolled && status_.active && status_.keys.size() >= 2 && (verified >= 2 || (signer_pin().empty() && status_.registered && legacy)));
        EnableWindow(uninstall_, !options_.demo && !busy_ && status_.has_deployment); EnableWindow(guide_, !options_.demo && !busy_); EnableWindow(legacy_, !options_.demo && !busy_ && signer_pin().empty() && status_.registered && verified < 2);
        EnableWindow(refresh_, !busy_); EnableWindow(close_, !busy_); EnableWindow(primary_, !options_.demo && !busy_ && status_.observed); EnableWindow(language_select_, !busy_);
        SendMessageW(progress_, PBM_SETMARQUEE, busy_, 35); ShowWindow(progress_, busy_ ? SW_SHOW : SW_HIDE);
    }
    void refresh() {
        try {
            if (options_.demo) { status_ = {}; status_.observed = status_.enrolled = status_.active = status_.registered = status_.compatible = status_.has_deployment = true; status_.schema = 2; status_.provider_version = L"0.7.0"; status_.keys = {{L"Principale", "verified_distinct", 1792997471}, {L"Riserva", "unknown", 0}}; status_.backups = {{std::string(32, '1'), 1792997471, 0}}; }
            else status_ = observe(package_, sid_);
            const auto verified = std::count_if(status_.keys.begin(), status_.keys.end(), [](const auto& key) { return key.proof != "unknown"; });
            SetWindowTextW(summary_, !status_.enrolled ? tr(L"Configura l'accesso con la chiave") : !status_.active ? tr(L"Password memorizzata da aggiornare") : status_.registered ? tr(L"Accesso con chiave attivo") : tr(L"Chiavi registrate: attiva il provider"));
            const auto detail = tr(L"Chiavi registrate: ") + std::to_wstring(status_.keys.size()) + tr(L"\r\nProvider installato: ") + (status_.provider_version.empty() ? tr(L"non presente") : status_.provider_version); SetWindowTextW(overview_detail_, detail.c_str());
            const auto note = tr(L"Chiavi con protezione hardware verificata: ") + std::to_wstring(verified) + tr(L". Le registrazioni precedenti restano da verificare: il solo login riuscito non dimostra questa protezione."); SetWindowTextW(proof_note_, note.c_str());
            SetWindowTextW(primary_, !status_.compatible ? tr(L"Aggiorna il provider") : !status_.enrolled ? tr(L"Registra la Principale") : !status_.active ? tr(L"Aggiorna copia cifrata") : status_.keys.size() < 2 ? tr(L"Aggiungi la Riserva") : !status_.registered ? tr(L"Attiva accesso a Windows") : tr(L"Verifica una chiave"));
            const auto old_selection = selected_key(); ListView_DeleteAllItems(key_list_);
            for (std::size_t i = 0; i < status_.keys.size(); ++i) { const auto& key = status_.keys[i]; LVITEMW item{}; item.mask = LVIF_TEXT; item.iItem = static_cast<int>(i); item.pszText = const_cast<wchar_t*>(key.label.c_str()); ListView_InsertItem(key_list_, &item); auto proof = protection(key.proof), when = date(key.checked); ListView_SetItemText(key_list_, item.iItem, 1, proof.data()); ListView_SetItemText(key_list_, item.iItem, 2, when.data()); if (key.label == old_selection) ListView_SetItemState(key_list_, item.iItem, LVIS_SELECTED, LVIS_SELECTED); }
            SendMessageW(backups_, CB_RESETCONTENT, 0, 0); for (const auto& backup : status_.backups) { const auto label = date(backup.created); SendMessageW(backups_, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(label.c_str())); }
            if (status_.backups.empty()) SendMessageW(backups_, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(tr(L"Nessuna copia di sicurezza disponibile")));
            SendMessageW(backups_, CB_SETCURSEL, 0, 0);
            SetWindowTextW(installed_heading_, status_.registered ? tr(L"Provider di accesso installato") : status_.has_deployment ? tr(L"Registrazione parziale: rimozione disponibile") : tr(L"Provider non installato")); const auto installed = tr(L"Versione installata: ") + status_.provider_version + tr(L"\r\nL'accesso Windows con password viene conservato."); SetWindowTextW(installed_detail_, installed.c_str());
            SetWindowTextW(footer_, options_.demo ? tr(L"Anteprima: dati fittizi, operazioni disabilitate") : tr(L"Stato aggiornato"));
        } catch (const std::exception& e) { status_.observed = false; SetWindowTextW(footer_, tr(L"Stato non disponibile. Usa la password Windows.")); technical_error(window_, widen(e.what()).c_str()); } states();
    }
    void vault(VaultAction action, std::wstring selection = {}) {
        if (!can_run(status_, action, busy_, options_.demo)) return;
        if (action == VaultAction::remove_key && !confirm(window_, tr(L"Revocare questa chiave? Se una copia precedente può essere stata sottratta, cambia anche la password Windows."))) return;
        if (action == VaultAction::update_password && !confirm(window_, tr(L"Hai già cambiato la password in Windows? Ora verrà aggiornata la copia cifrata con una chiave registrata."))) return;
        if (action == VaultAction::restore && !confirm(window_, tr(L"Ripristinare la copia compatibile selezionata, conservando revoche e contatori correnti?"))) return;
        pending_ = start_native(package_ / L"bin" / L"hid-fido2-vault.exe", vault_arguments(action, selection, sid_)); busy_ = true; SetWindowTextW(footer_, tr(L"Segui le finestre locali della chiave. Nessun tentativo automatico.")); states();
    }
    void deploy(bool uninstall) {
        if (options_.demo || busy_) return;
        if (!confirm(window_, uninstall ? tr(L"Rimuovere il provider HID FIDO2? L'archivio e la password Windows saranno conservati.") : tr(L"Attivare questa versione nativa del provider? La password Windows resta disponibile e viene preparato il ripristino compatibile."))) return;
        const bool legacy = SendMessageW(legacy_, BM_GETCHECK, 0, 0) == BST_CHECKED; busy_ = true; states(); SetWindowTextW(footer_, uninstall ? tr(L"Rimozione del provider in corso…") : tr(L"Verifica e aggiornamento in corso…"));
        worker_ = std::thread([this, uninstall, legacy] {
            auto result = std::make_unique<JobResult>(); result->uninstall = uninstall;
            try { if (uninstall) { uninstall_provider(); result->transaction.success = true; } else { result->transaction = install_or_update(package_, signer_pin(), sid_, legacy); if (result->transaction.success) { try { create_shortcuts(package_); } catch (...) { result->shortcut_warning = true; } } } }
            catch (const std::exception& e) { result->failure = widen(e.what()); } PostMessageW(window_, complete_message, 0, reinterpret_cast<LPARAM>(result.release()));
        });
    }
    void guide() {
        MessageBoxW(window_, tr(L"Se la chiave non funziona, scegli Opzioni di accesso > Password nella schermata Windows e inserisci la password Windows attuale.\r\n\r\nPoi apri Gestione HID FIDO2. Da Chiavi puoi provare o rimuovere una chiave persa; da Password e recupero puoi aggiornare la password salvata.\r\n\r\nDa Installazione puoi rimuovere l'accesso HID FIDO2 conservando i dati salvati e l'accesso con password.\r\n\r\nLe copie di sicurezza richiedono dati ancora leggibili e una chiave registrata: non sostituiscono la password Windows o un backup del computer.\r\n\r\nSe non riesci ad accedere nemmeno con la password Windows, consulta docs/recovery.md nel progetto o chiedi assistenza. Per un disco protetto da BitLocker serve la sua chiave di recupero."), tr(L"Recupero dell'accesso"), MB_OK | MB_ICONINFORMATION);
    }
    void command(int id) {
        if (id == language_id) { change_language(); return; }
        if (id >= nav_overview && id <= nav_install) { change_page(id - nav_overview); return; }
        if (id == close_id) { SendMessageW(window_, WM_CLOSE, 0, 0); return; }
        if (options_.demo) return;
        switch (id) {
        case refresh_id: refresh(); break;
        case primary_id: if (!status_.compatible) change_page(3); else if (!status_.enrolled) vault(VaultAction::enroll, L"Principale"); else if (!status_.active) vault(VaultAction::update_password); else if (status_.keys.size() < 2) vault(VaultAction::add_key, status_.keys.front().label == L"Riserva" ? L"Principale" : L"Riserva"); else if (!status_.registered) change_page(3); else change_page(1); break;
        case verify_id: vault(VaultAction::verify, selected_key()); break;
        case proof_id: vault(VaultAction::verify_protection, selected_key()); break;
        case add_id: { const auto label = ask_label(window_); if (!label.empty()) vault(VaultAction::add_key, label); break; }
        case remove_id: vault(VaultAction::remove_key, selected_key()); break;
        case password_id: vault(VaultAction::update_password); break;
        case backup_id: vault(VaultAction::backup); break;
        case restore_id: { const auto selected = SendMessageW(backups_, CB_GETCURSEL, 0, 0); if (selected >= 0 && static_cast<std::size_t>(selected) < status_.backups.size()) vault(VaultAction::restore, widen(status_.backups[static_cast<std::size_t>(selected)].id)); break; }
        case windows_password_id: ShellExecuteW(window_, L"open", L"ms-settings:signinoptions", nullptr, nullptr, SW_SHOWNORMAL); break;
        case install_id: deploy(false); break; case uninstall_id: deploy(true); break;
        case recovery_id: guide(); break; case legacy_id: states(); break;
        }
    }
    void tick() {
        if (!pending_.valid() || WaitForSingleObject(pending_.get(), 0) != WAIT_OBJECT_0) return;
        DWORD code{}; if (!GetExitCodeProcess(pending_.get(), &code)) win_error("Read tool completion"); pending_ = Handle{}; busy_ = false; refresh();
        SetWindowTextW(footer_, code == 0 ? tr(L"Operazione completata.") : code == 2 ? tr(L"Operazione annullata. Nessun altro tentativo.") : tr(L"Operazione interrotta: consulta il messaggio dello strumento."));
    }
    void completed(JobResult* raw) {
        std::unique_ptr<JobResult> result(raw); if (worker_.joinable()) worker_.join(); busy_ = false; refresh();
        const auto& r = result->transaction;
        if (!result->failure.empty()) technical_error(window_, result->failure.c_str());
        else if (r.success) MessageBoxW(window_, result->uninstall ? tr(L"Provider rimosso. Archivio e accesso con password conservati.") : result->shortcut_warning ? tr(L"Provider nativo installato. I collegamenti non sono stati creati: apri Gestione-HID-FIDO2.exe dalla release protetta.") : tr(L"Versione nativa installata. I collegamenti Start e Desktop sono pronti. Prova separatamente sblocco e login dopo riavvio."), tr(title), MB_OK | MB_ICONINFORMATION);
        else error(window_, r.restored ? tr(L"Aggiornamento non riuscito. La registrazione precedente è stata ripristinata.") : tr(L"Aggiornamento non riuscito. Usa la password Windows e la guida di recupero."));
    }
    void snapshot() {
        if (!options_.demo || options_.snapshot.empty()) return; reject_reparse(options_.snapshot); std::filesystem::create_directories(options_.snapshot);
        Gdiplus::GdiplusStartupInput input; ULONG_PTR token{}; if (Gdiplus::GdiplusStartup(&token, &input, nullptr) != Gdiplus::Ok) throw std::runtime_error("PNG renderer unavailable");
        const CLSID png{0x557cf406, 0x1a04, 0x11d3, {0x9a, 0x73, 0x00, 0x00, 0xf8, 0x1e, 0xf3, 0x2e}};
        for (int page = 0; page < 4; ++page) {
            change_page(page); RedrawWindow(window_, nullptr, nullptr, RDW_INVALIDATE | RDW_ALLCHILDREN | RDW_UPDATENOW);
            RECT rect{}; GetWindowRect(window_, &rect);
            const auto dc = GetDC(window_), memory = CreateCompatibleDC(dc);
            const auto bitmap = CreateCompatibleBitmap(dc, rect.right - rect.left, rect.bottom - rect.top);
            const auto old = SelectObject(memory, bitmap);
            SendMessageW(window_, WM_PRINT, reinterpret_cast<WPARAM>(memory), PRF_CLIENT | PRF_CHILDREN | PRF_ERASEBKGND | PRF_NONCLIENT);
            // Hidden-window WM_PRINT omits the selected text of a native
            // dropdown. Render its actual selection so demo exports match UI.
            for (const auto combo : {language_select_, page == 2 ? backups_ : nullptr}) {
                if (!combo) continue;
                const auto selection = SendMessageW(combo, CB_GETCURSEL, 0, 0);
                if (selection == CB_ERR) continue;
                const auto length = SendMessageW(combo, CB_GETLBTEXTLEN, selection, 0);
                if (length < 0 || length > 512) continue;
                std::wstring label(static_cast<std::size_t>(length) + 1, L'\0');
                SendMessageW(combo, CB_GETLBTEXT, selection, reinterpret_cast<LPARAM>(label.data()));
                RECT item{}; GetWindowRect(combo, &item); OffsetRect(&item, -rect.left, -rect.top);
                item.left += scale(4); item.right -= scale(23); item.top += scale(1); item.bottom -= scale(1);
                FillRect(memory, &item, white_); const auto previous_font = SelectObject(memory, font_);
                SetBkMode(memory, TRANSPARENT); SetTextColor(memory, GetSysColor(IsWindowEnabled(combo) ? COLOR_WINDOWTEXT : COLOR_GRAYTEXT));
                DrawTextW(memory, label.c_str(), static_cast<int>(length), &item, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
                SelectObject(memory, previous_font);
            }
            { Gdiplus::Bitmap image(bitmap, nullptr); const auto path = options_.snapshot / (L"native-manager-" + std::to_wstring(page) + L".png"); image.Save(path.c_str(), &png, nullptr); }
            SelectObject(memory, old); DeleteObject(bitmap); DeleteDC(memory); ReleaseDC(window_, dc);
        }
        Gdiplus::GdiplusShutdown(token); SendMessageW(window_, WM_CLOSE, 0, 0);
    }
    static LRESULT CALLBACK window_proc(HWND window, UINT message, WPARAM w, LPARAM l) {
        auto* self = reinterpret_cast<Manager*>(GetWindowLongPtrW(window, GWLP_USERDATA));
        if (message == WM_NCCREATE) { self = static_cast<Manager*>(reinterpret_cast<CREATESTRUCTW*>(l)->lpCreateParams); self->window_ = window; SetWindowLongPtrW(window, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self)); }
        if (!self) return DefWindowProcW(window, message, w, l);
        try {
            switch (message) {
            case WM_CREATE: self->create(); return 0;
            case WM_SIZE: self->layout(); return 0;
            case WM_DPICHANGED: { const auto* rect = reinterpret_cast<RECT*>(l); SetWindowPos(window, nullptr, rect->left, rect->top, rect->right - rect->left, rect->bottom - rect->top, SWP_NOZORDER | SWP_NOACTIVATE); self->fonts(); self->layout(); return 0; }
            case WM_GETMINMAXINFO: { auto* info = reinterpret_cast<MINMAXINFO*>(l); info->ptMinTrackSize = {self->scale(900), self->scale(690)}; return 0; }
            case WM_COMMAND: self->command(LOWORD(w)); return 0;
            case WM_NOTIFY: if (reinterpret_cast<NMHDR*>(l)->hwndFrom == self->key_list_) self->states(); return 0;
            case WM_TIMER: self->tick(); return 0;
            case complete_message: self->completed(reinterpret_cast<JobResult*>(l)); return 0;
            case capture_message: self->snapshot(); return 0;
            case WM_CTLCOLORSTATIC: { const auto dc = reinterpret_cast<HDC>(w); const auto control = reinterpret_cast<HWND>(l); SetBkMode(dc, TRANSPARENT); SetTextColor(dc, control == self->summary_ && self->status_.active ? RGB(25, 111, 66) : RGB(35, 46, 58)); return reinterpret_cast<LRESULT>(control == self->brand_ || control == self->brand_note_ || control == self->version_ || control == self->language_label_ ? self->sidebar_ : self->white_); }
            case WM_DRAWITEM: { const auto* item = reinterpret_cast<DRAWITEMSTRUCT*>(l); if (item->CtlID < nav_overview || item->CtlID > nav_install) break; const bool selected = static_cast<int>(item->CtlID) - nav_overview == self->page_; const auto brush = CreateSolidBrush(selected ? RGB(221, 235, 247) : RGB(245, 247, 250)); FillRect(item->hDC, &item->rcItem, brush); DeleteObject(brush); SetBkMode(item->hDC, TRANSPARENT); SetTextColor(item->hDC, selected ? RGB(13, 83, 139) : RGB(51, 65, 80)); SelectObject(item->hDC, self->font_); auto rect = item->rcItem; rect.left += self->scale(14); std::array<wchar_t, 64> text{}; GetWindowTextW(item->hwndItem, text.data(), static_cast<int>(text.size())); DrawTextW(item->hDC, text.data(), -1, &rect, DT_LEFT | DT_VCENTER | DT_SINGLELINE); if (item->itemState & ODS_FOCUS) DrawFocusRect(item->hDC, &item->rcItem); return TRUE; }
            case WM_PAINT: { PAINTSTRUCT paint{}; const auto dc = BeginPaint(window, &paint); RECT rect{}; GetClientRect(window, &rect); rect.right = self->scale(222); FillRect(dc, &rect, self->sidebar_); EndPaint(window, &paint); return 0; }
            case WM_PRINTCLIENT: { RECT rect{}; GetClientRect(window, &rect); FillRect(reinterpret_cast<HDC>(w), &rect, self->white_); rect.right = self->scale(222); FillRect(reinterpret_cast<HDC>(w), &rect, self->sidebar_); return 0; }
            case WM_CLOSE: if (self->busy_) { MessageBoxW(window, tr(L"Attendi la conclusione dell'operazione nelle finestre locali."), tr(title), MB_OK | MB_ICONINFORMATION); return 0; } DestroyWindow(window); return 0;
            case WM_DESTROY: KillTimer(window, 1); PostQuitMessage(0); return 0;
            }
        } catch (const std::exception& e) { technical_error(window, widen(e.what()).c_str()); }
        return DefWindowProcW(window, message, w, l);
    }
    Options options_; std::filesystem::path package_; std::wstring sid_; Status status_; HWND window_{}; UINT dpi_{96}; bool busy_{}; int page_{};
    HBRUSH white_{CreateSolidBrush(RGB(255, 255, 255))}, sidebar_{CreateSolidBrush(RGB(245, 247, 250))}; HFONT font_{}, large_{}, bold_{};
    std::vector<HWND> controls_; std::vector<std::pair<HWND, const wchar_t*>> labels_; std::array<std::vector<HWND>, 4> pages_; std::array<HWND, 4> nav_{}; Handle pending_; std::thread worker_;
    HWND language_label_{}, language_select_{};
    HWND brand_{}, brand_note_{}, version_{}, heading_{}, subtitle_{}, summary_{}, overview_detail_{}, proof_note_{}, primary_{}, instructions_{}, recovery_note_{}, key_list_{}, verify_{}, proof_{}, add_{}, remove_{}, key_help_{}, password_heading_{}, password_help_{}, settings_{}, password_{}, backups_heading_{}, backup_help_{}, backups_{}, backup_{}, restore_{}, lost_help_{}, installed_heading_{}, installed_detail_{}, trust_{}, legacy_{}, install_{}, uninstall_{}, guide_{}, install_help_{}, native_note_{}, footer_{}, progress_{}, close_{}, refresh_{};
};
}
int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int show) {
    try {
        if (!SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)) throw std::runtime_error("System DLL search policy unavailable");
        hidfido::ui::set_language(hidfido::ui::preferred_language());
        const auto options = parse_options(); if (options.language) hidfido::ui::set_language(*options.language); const auto source = module_directory();
        if (options.package) { const auto directory = package_release(options.build, options.output, "0.7.0", signer_pin()); if (!options.result.empty()) write_new_text(options.result, "{\"ReleaseDirectory\":" + json_string(directory) + "}", false); return 0; }
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
        Manager app(options, package, sid); return app.run(instance, show);
    } catch (const std::exception& e) { technical_error(nullptr, widen(e.what()).c_str()); return 1; }
}
