#include "window.hpp"
#include "hidfido/support_report.hpp"
#include <commctrl.h>
#include <shellapi.h>
#include <shobjidl.h>
#include <gdiplus.h>
#include <algorithm>
#include <array>
#include <memory>
#include <thread>

namespace hidfido::management {
using ui::tr;

constexpr UINT complete_message = WM_APP + 20, capture_message = WM_APP + 21;
constexpr wchar_t title[] = L"Gestione HID FIDO2";
enum { nav_overview = 100, nav_keys, nav_settings, refresh_id = 200, close_id, primary_id, verify_id, proof_id, add_id, remove_id, windows_password_id, password_id, backup_id, restore_id, install_id, uninstall_id, recovery_id, legacy_id, language_id, rename_id, setup_id, setup_action_id, recovery_check_id, trial_primary_id, trial_spare_id, trial_restart_id, trace_start_id, trace_stop_id, support_report_id,
back_id = 300, instructions_id, support_info_id, password_section_id, install_section_id, support_section_id, setup_cancel_id, setup_help_id, key_list_id, key_details_id };
bool confirm(HWND parent, const wchar_t* text) { return MessageBoxW(parent, text, tr(title), MB_YESNO | MB_DEFBUTTON2 | MB_ICONQUESTION | MB_SETFOREGROUND) == IDYES; }
void error(HWND parent, const wchar_t* text) { MessageBoxW(parent, text, tr(title), MB_OK | MB_ICONERROR | MB_SETFOREGROUND); }
void technical_error(HWND parent, const wchar_t* details) {
    TASKDIALOGCONFIG dialog{sizeof(dialog)}; dialog.hwndParent = parent;
    dialog.dwCommonButtons = TDCBF_OK_BUTTON; dialog.pszWindowTitle = tr(title);
    dialog.pszMainIcon = TD_ERROR_ICON;
    dialog.pszContent = tr(L"Impossibile completare l'operazione. Verifica di aver estratto tutto il pacchetto e riprova. Per il recupero usa la password Windows.");
    dialog.pszExpandedInformation = details; dialog.pszExpandedControlText = tr(L"Nascondi dettagli"); dialog.pszCollapsedControlText = tr(L"Dettagli tecnici");
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
std::wstring ask_label(HWND parent, std::wstring initial = {}) {
    std::wstring result = initial.empty() ? (hidfido::ui::language() == hidfido::ui::Language::english ? L"Backup 2" : L"Riserva 2") : std::move(initial);
    const auto procedure = [](HWND dialog, UINT message, WPARAM w, LPARAM l) -> INT_PTR {
        if (message == WM_INITDIALOG) { SetWindowTextW(dialog, tr(L"Nome della chiave")); SetDlgItemTextW(dialog, 1002, tr(L"Scegli un nome riconoscibile, per esempio Riserva 2.")); SetDlgItemTextW(dialog, IDOK, tr(L"Continua")); SetDlgItemTextW(dialog, IDCANCEL, tr(L"Annulla")); SetWindowLongPtrW(dialog, DWLP_USER, l); auto* text = reinterpret_cast<std::wstring*>(l); SetDlgItemTextW(dialog, 1001, text->c_str()); SendDlgItemMessageW(dialog, 1001, EM_SETLIMITTEXT, 64, 0); return TRUE; }
        if (message == WM_COMMAND && LOWORD(w) == IDOK) { std::array<wchar_t, 65> text{}; GetDlgItemTextW(dialog, 1001, text.data(), static_cast<int>(text.size())); std::wstring label(text.data()); if (!valid_key_label(label) || label.find_first_not_of(L' ') == label.npos) { MessageBoxW(dialog, tr(L"Inserisci un nome da 1 a 64 caratteri, senza caratteri di controllo."), tr(title), MB_OK | MB_ICONWARNING); return TRUE; } *reinterpret_cast<std::wstring*>(GetWindowLongPtrW(dialog, DWLP_USER)) = label; EndDialog(dialog, IDOK); return TRUE; }
        if (message == WM_COMMAND && LOWORD(w) == IDCANCEL) { EndDialog(dialog, IDCANCEL); return TRUE; } return FALSE;
    };
    return DialogBoxParamW(GetModuleHandleW(nullptr), MAKEINTRESOURCEW(101), parent, procedure, reinterpret_cast<LPARAM>(&result)) == IDOK ? result : L"";
}
bool preview_report(HWND parent, const std::wstring& report) {
    const auto data = parse_json(narrow(report));
    const auto check = data.at("installation_check").text();
    const auto body = tr(L"Versione: ") + widen(data.at("application_version").text()) +
        tr(L"\nInstallazione: ") + (check == "passed" ? tr(L"controllo superato") : check == "failed" ? tr(L"da controllare") : tr(L"non verificata")) +
        tr(L"\nEventi raccolti: ") + std::to_wstring(data.at("logon_events").array.size() + data.at("helper_events").array.size()) +
        tr(L"\n\nIl report non viene inviato automaticamente.");
    auto details = report.substr(0, 16000);
    if (details.size() < report.size()) details += tr(L"\nAnteprima abbreviata. Il file salvato contiene tutti gli eventi.");
    const TASKDIALOG_BUTTON buttons[]{{IDOK, tr(L"Salva report…")}, {IDCANCEL, tr(L"Chiudi")}};
    TASKDIALOGCONFIG dialog{sizeof(dialog)}; dialog.hwndParent = parent; dialog.pszWindowTitle = L"HID FIDO2";
    dialog.dwFlags = TDF_ALLOW_DIALOG_CANCELLATION | TDF_SIZE_TO_CONTENT;
    dialog.pszMainInstruction = tr(L"Report pronto"); dialog.pszContent = body.c_str(); dialog.pszExpandedInformation = details.c_str();
    dialog.pszExpandedControlText = tr(L"Nascondi dettagli"); dialog.pszCollapsedControlText = tr(L"Mostra dettagli");
    dialog.pButtons = buttons; dialog.cButtons = 2; dialog.nDefaultButton = IDCANCEL; int selected{};
    if (FAILED(TaskDialogIndirect(&dialog, &selected, nullptr, nullptr))) throw std::runtime_error("Report preview unavailable");
    return selected == IDOK;
}
void save_support_report(HWND parent, std::string_view report) {
    IFileSaveDialog* dialog{};
    if (FAILED(CoCreateInstance(CLSID_FileSaveDialog, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&dialog)))) throw std::runtime_error("Save dialog unavailable");
    struct Release { IFileSaveDialog* value; ~Release() { value->Release(); } } release{dialog};
    const COMDLG_FILTERSPEC types[]{{L"JSON", L"*.json"}};
    dialog->SetFileTypes(1, types); dialog->SetDefaultExtension(L"json"); dialog->SetFileName(L"HID-FIDO2-support.json");
    dialog->SetTitle(tr(L"Salva report di assistenza"));
    dialog->SetOptions(FOS_FORCEFILESYSTEM | FOS_PATHMUSTEXIST | FOS_NOCHANGEDIR | FOS_NOREADONLYRETURN);
    const auto shown = dialog->Show(parent); if (shown == HRESULT_FROM_WIN32(ERROR_CANCELLED)) return;
    if (FAILED(shown)) throw std::runtime_error("Save dialog failed");
    IShellItem* item{}; if (FAILED(dialog->GetResult(&item))) throw std::runtime_error("Save destination unavailable");
    struct Item { IShellItem* value; ~Item() { value->Release(); } } selected{item};
    wchar_t* path{}; if (FAILED(item->GetDisplayName(SIGDN_FILESYSPATH, &path))) throw std::runtime_error("Save path unavailable");
    const std::filesystem::path destination(path); CoTaskMemFree(path);
    const auto pins = pin_directories(destination.parent_path());
    if (std::filesystem::exists(destination)) { error(parent, tr(L"Esiste già un file con questo nome. Scegli un nome nuovo per salvare il report.")); return; }
    write_new_text(destination, report, false);
    MessageBoxW(parent, tr(L"Report salvato. Puoi condividerlo dopo averlo controllato."), tr(title), MB_OK | MB_ICONINFORMATION);
}
struct JobResult { TransactionResult transaction; bool uninstall{}, shortcut_warning{}, support{}; SupportAudit audit{SupportAudit::not_run}; std::wstring failure; };
class Manager {
public:
    Manager(WindowOptions options, std::filesystem::path package, std::wstring sid) : options_(std::move(options)), package_(std::move(package)), sid_(std::move(sid)) {}
    ~Manager() { if (worker_.joinable()) worker_.join(); clear_fonts(); if (rows_) ImageList_Destroy(rows_); DeleteObject(white_); }
    int run(HINSTANCE instance, int show) {
        WNDCLASSEXW type{sizeof(type)}; type.lpfnWndProc = window_proc; type.hInstance = instance; type.lpszClassName = L"HidFido2CompactManager"; type.hCursor = LoadCursorW(nullptr, IDC_ARROW); type.hIcon = LoadIconW(instance, MAKEINTRESOURCEW(1)); type.hIconSm = type.hIcon; type.hbrBackground = white_;
        if (!RegisterClassExW(&type)) win_error("Register manager");
        const auto dpi = GetDpiForSystem(); RECT bounds{0, 0, MulDiv(options_.compact_preview ? 760 : 900, dpi, 96), MulDiv(options_.compact_preview ? 560 : 640, dpi, 96)}, work{};
        AdjustWindowRectExForDpi(&bounds, WS_OVERLAPPEDWINDOW, FALSE, 0, dpi); SystemParametersInfoW(SPI_GETWORKAREA, 0, &work, 0);
        const int width = std::min(bounds.right - bounds.left, work.right - work.left), height = std::min(bounds.bottom - bounds.top, work.bottom - work.top);
        window_ = CreateWindowExW(0, type.lpszClassName, options_.demo ? tr(L"HID FIDO2 · Anteprima") : L"HID FIDO2", WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN, work.left + (work.right - work.left - width) / 2, work.top + (work.bottom - work.top - height) / 2, width, height, nullptr, nullptr, instance, this);
        if (!window_) win_error("Create manager"); ShowWindow(window_, show); UpdateWindow(window_);
        if (!options_.snapshot.empty()) PostMessageW(window_, capture_message, 0, 0);
        MSG message{}; while (GetMessageW(&message, nullptr, 0, 0) > 0) if (!IsDialogMessageW(window_, &message)) { TranslateMessage(&message); DispatchMessageW(&message); }
        return static_cast<int>(message.wParam);
    }
private:
    std::string_view signer_pin() const { return options_.signer_pin; }
    int scale(int value) const { return MulDiv(value, static_cast<int>(dpi_), 96); }
    HWND make(const wchar_t* kind, const wchar_t* key, DWORD style = 0, int id = 0, int page = -1) {
        const auto h = CreateWindowExW(kind == std::wstring_view(WC_COMBOBOXW) ? WS_EX_CLIENTEDGE : 0, kind, tr(key), WS_CHILD | WS_VISIBLE | style, 0, 0, 1, 1, window_, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), GetModuleHandleW(nullptr), nullptr);
        if (!h) win_error("Create manager control"); controls_.push_back(h); if (*key) labels_.emplace_back(h, key); if (page >= 0) pages_[page].push_back(h); return h;
    }
    HWND text(const wchar_t* key, int page = -1) { return make(L"STATIC", key, SS_LEFT, 0, page); }
    HWND button(const wchar_t* key, int id, int page, bool primary = false, bool link = false) {
        const auto h = make(L"BUTTON", key, BS_OWNERDRAW | WS_TABSTOP, id, page); if (primary) primary_buttons_.push_back(h); if (link) link_buttons_.push_back(h); return h;
    }
    void box(HWND control, int x, int y, int width, int height) { MoveWindow(control, scale(x), scale(y), scale(std::max(1, width)), scale(std::max(1, height)), TRUE); }
    void clear_fonts() { for (const auto font : {font_, large_, bold_}) if (font) DeleteObject(font); font_ = large_ = bold_ = nullptr; }
    void fonts() {
        clear_fonts(); dpi_ = GetDpiForWindow(window_);
        const auto font = [&](int size, int weight) { return CreateFontW(-scale(size), 0, 0, 0, weight, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI"); };
        font_ = font(15, FW_NORMAL); large_ = font(28, FW_SEMIBOLD); bold_ = font(18, FW_SEMIBOLD);
        for (const auto h : controls_) SendMessageW(h, WM_SETFONT, reinterpret_cast<WPARAM>(h == heading_ || h == summary_ || h == setup_stage_ ? large_ : font_), TRUE);
        // List-view row height follows the small image list, including after a DPI change.
        const auto previous = rows_;
        rows_ = ImageList_Create(1, scale(58), ILC_COLOR32, 1, 1);
        if (!rows_) win_error("Create key row metrics");
        const auto dc = GetDC(window_); const auto bitmap = CreateCompatibleBitmap(dc, 1, scale(58));
        const auto added = bitmap ? ImageList_Add(rows_, bitmap, nullptr) : -1;
        if (bitmap) DeleteObject(bitmap); ReleaseDC(window_, dc);
        if (added < 0) win_error("Set key row metrics");
        ListView_SetImageList(key_list_, rows_, LVSIL_SMALL);
        if (previous) ImageList_Destroy(previous);
    }
    void create() {
        const wchar_t* names[]{L"Accesso", L"Chiavi", L"Impostazioni"};
        for (int i = 0; i < 3; ++i) nav_[i] = button(names[i], nav_overview + i, -1);
        heading_ = text(L""); back_ = button(L"‹ Impostazioni", back_id, -1, false, true);
        summary_ = text(L"Lettura dello stato…", 0); overview_detail_ = text(L"", 0);
        primary_ = button(L"Prova una chiave", primary_id, 0, true);
        instructions_toggle_ = button(L"Come accedere a Windows  ›", instructions_id, 0, false, true);
        instructions_ = text(L"1. Collega una sola chiave.\r\n2. Blocca Windows con Win+L.\r\n3. Scegli HID FIDO2 e usa il PIN della chiave.", 0);
        recovery_link_ = button(L"Problemi di accesso?", recovery_id, 0, false, true);
        key_list_ = make(WC_LISTVIEWW, L"Le tue chiavi", LVS_REPORT | LVS_NOCOLUMNHEADER | LVS_SINGLESEL | LVS_SHOWSELALWAYS | WS_TABSTOP, key_list_id, 1);
        ListView_SetExtendedListViewStyle(key_list_, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);
        const wchar_t* columns[]{L"Chiave", L"Stato", L"Opzioni"}; for (int i = 0; i < 3; ++i) { LVCOLUMNW column{}; column.mask = LVCF_TEXT | LVCF_WIDTH; column.pszText = const_cast<wchar_t*>(tr(columns[i])); column.cx = 200; ListView_InsertColumn(key_list_, i, &column); }
        add_ = button(L"Aggiungi chiave", add_id, 1, true);
        key_note_ = text(L"", 1);
        password_heading_ = text(L"Hai cambiato la password in Windows?", 2);
        password_ = button(L"Aggiorna password salvata", password_id, 2, true);
        settings_ = button(L"Cambia password in Windows", windows_password_id, 2, false, true);
        backups_heading_ = text(L"Copie di sicurezza", 2); backups_ = make(WC_COMBOBOXW, L"", CBS_DROPDOWNLIST | WS_TABSTOP | WS_VSCROLL, 0, 2);
        backup_ = button(L"Crea copia", backup_id, 2); restore_ = button(L"Ripristina…", restore_id, 2);
        lost_ = button(L"Ho perso una chiave", recovery_id, 2, false, true);
        installed_heading_ = text(L"", 3); installed_detail_ = text(L"", 3);
        trust_ = text(signer_pin().empty() ? L"Pacchetto locale non firmato" : L"Pacchetto con firma verificata", 3);
        legacy_ = make(L"BUTTON", L"Conserva le registrazioni esistenti", BS_AUTOCHECKBOX | WS_TABSTOP, legacy_id, 3);
        legacy_note_ = text(L"Le verifiche mancanti resteranno da completare.", 3);
        install_ = button(L"Installa / aggiorna", install_id, 3, true); uninstall_ = button(L"Rimuovi accesso con chiave…", uninstall_id, 3);
        setup_link_ = button(L"Configurazione guidata", setup_id, 3, false, true);
        setup_stage_ = text(L"", 4); setup_detail_ = text(L"", 4); setup_steps_ = text(L"", 4);
        setup_action_ = button(L"Continua", setup_action_id, 4, true); setup_cancel_ = button(L"Più tardi", setup_cancel_id, 4, false, true);
        recovery_check_ = make(L"BUTTON", L"Ho provato l'accesso con la password Windows.", BS_AUTOCHECKBOX | BS_MULTILINE | WS_TABSTOP, recovery_check_id, 4);
        setup_help_ = button(L"Come fare?", setup_help_id, 4, false, true);
        trace_state_ = text(L"", 5); support_heading_ = text(L"Riproduci il problema, poi crea un report.", 5);
        trace_start_ = button(L"Avvia raccolta", trace_start_id, 5, true);
        support_report_ = button(L"Crea report…", support_report_id, 5);
        support_toggle_ = button(L"Cosa contiene il report?  ›", support_info_id, 5, false, true);
        support_privacy_ = text(L"Solo versioni, stato e codici tecnici. Nessun PIN, password o identificatore dell'account. La raccolta si ferma dopo 5 minuti; il report resta sul PC finché scegli di condividerlo.", 5);
        password_section_ = button(L"Password e recupero  ›", password_section_id, 6);
        install_section_ = button(L"Installazione  ›", install_section_id, 6);
        support_section_ = button(L"Assistenza  ›", support_section_id, 6);
        language_label_ = text(L"Lingua / Language", 6); language_select_ = make(WC_COMBOBOXW, L"", CBS_DROPDOWNLIST | WS_TABSTOP, language_id, 6);
        SendMessageW(language_select_, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"Italiano")); SendMessageW(language_select_, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"English"));
        SendMessageW(language_select_, CB_SETCURSEL, ui::language() == ui::Language::italian ? 0 : 1, 0);
        version_ = text(L"HID FIDO2 · 0.9.0", 6);
        footer_ = text(L""); refresh_ = button(L"Aggiorna stato", refresh_id, -1, false, true); progress_ = make(PROGRESS_CLASSW, L"", PBS_MARQUEE);
        demo_guide_.create(window_); demo_guide_.visible(false);
        fonts(); SendMessageW(window_, WM_CHANGEUISTATE, MAKEWPARAM(UIS_SET, UISF_HIDEFOCUS), 0); refresh(); change_page(options_.preview_step ? 7 : 0); SetTimer(window_, 1, 250, nullptr);
    }
    void layout() {
        RECT area{}; GetClientRect(window_, &area); const int width = MulDiv(area.right, 96, static_cast<int>(dpi_)), height = MulDiv(area.bottom, 96, static_cast<int>(dpi_));
        const int left = 48, content = width - 96, centre = std::max(left, (width - 600) / 2);
        for (int i = 0; i < 3; ++i) { box(nav_[i], 36 + i * 150, 8, i == 2 ? 170 : 136, 46); ShowWindow(nav_[i], page_ == 4 || page_ == 7 ? SW_HIDE : SW_SHOW); }
        box(heading_, left, 91, content - 235, 44); box(back_, left - 8, 69, 180, 30);
        ShowWindow(back_, page_ == 2 || page_ == 3 || page_ == 5 ? SW_SHOW : SW_HIDE);
        ShowWindow(heading_, page_ == 0 || page_ == 4 || page_ == 7 ? SW_HIDE : SW_SHOW);
        if (page_ == 2 || page_ == 3 || page_ == 5) box(heading_, left, 116, content, 44);
        const int home_lift = std::max(0, (640 - height) / 2);
        box(summary_, centre + 56, 149 - home_lift, width - centre - 98, 76); box(overview_detail_, centre + 56, 227 - home_lift, content - 56, 36);
        box(primary_, centre + 56, 286 - home_lift, 250, 42); box(instructions_toggle_, centre - 6, 365 - home_lift, 600, 43);
        box(instructions_, centre + 10, 414 - home_lift, 580, 94); box(recovery_link_, centre - 6, (instructions_open_ ? 519 : 443) - home_lift, 220, 38);
        ShowWindow(instructions_, page_ == 0 && instructions_open_ ? SW_SHOW : SW_HIDE);
        box(add_, width - 246, 91, 198, 40); box(key_list_, left, 167, content, height - 260); box(key_note_, left, height - 77, content - 170, 28);
        ListView_SetColumnWidth(key_list_, 0, scale(std::max(240, content - 260))); ListView_SetColumnWidth(key_list_, 1, scale(185)); ListView_SetColumnWidth(key_list_, 2, scale(64));
        box(password_heading_, left, 191, content, 29); box(password_, left, 237, 270, 40); box(settings_, left + 285, 237, 285, 40);
        box(backups_heading_, left, 316, content, 29); box(backups_, left, 361, content, 180); box(backup_, left, 412, 170, 38); box(restore_, left + 184, 412, 170, 38); box(lost_, left - 6, 486, 230, 38);
        box(installed_heading_, left, 193, content, 30); box(installed_detail_, left, 232, content, 36); box(trust_, left, 286, content, 29);
        box(legacy_, left, 330, content, 30); box(legacy_note_, left + 22, 363, content - 22, 28);
        box(install_, left, 416, 218, 40); box(uninstall_, left + 232, 416, 300, 40); box(setup_link_, left - 6, 487, 260, 38);
        ShowWindow(legacy_note_, page_ == 3 && IsWindowEnabled(legacy_) ? SW_SHOW : SW_HIDE);
        box(setup_steps_, left, 29, content, 29); box(setup_stage_, left, 100, content, 78); box(setup_detail_, left, 187, content, 58);
        box(recovery_check_, left, std::min(403, height - 197), content, 52); box(setup_action_, width - 310, height - 67, 262, 40); box(setup_cancel_, left - 7, height - 67, 155, 40); box(setup_help_, width - 213, height - 119, 165, 34);
        box(support_heading_, left, 193, content, 32); box(trace_state_, left, 249, content, 48); box(trace_start_, left, 325, 225, 40); box(support_report_, left + 240, 325, 225, 40);
        box(support_toggle_, left - 7, 404, 310, 38); box(support_privacy_, left, 452, content, std::min(96, height - 494)); ShowWindow(support_privacy_, page_ == 5 && support_open_ ? SW_SHOW : SW_HIDE);
        box(password_section_, left, 170, content, 56); box(install_section_, left, 237, content, 56); box(support_section_, left, 304, content, 56);
        box(language_label_, left + 8, 396, 250, 30); box(language_select_, width - 252, 388, 204, 140); box(version_, left + 8, 470, content, 28);
        box(footer_, left, height - 32, content - 170, 24); box(refresh_, width - 211, height - 40, 163, 31); box(progress_, left, height - 5, content, 4);
        ShowWindow(refresh_, !busy_ && page_ != 4 && page_ != 7 ? SW_SHOW : SW_HIDE); ShowWindow(footer_, page_ == 4 || page_ == 7 ? SW_HIDE : SW_SHOW);
        if (page_ == 7) demo_guide_.layout();
        InvalidateRect(window_, nullptr, TRUE);
    }
    void change_page(int page) {
        page_ = page; const wchar_t* titles[]{L"Accesso", L"Le tue chiavi", L"Password e recupero", L"Installazione", L"Configurazione guidata", L"Assistenza", L"Impostazioni", L"Configurazione guidata"};
        SetWindowTextW(heading_, tr(titles[page]));
        for (int i = 0; i < 7; ++i) for (const auto h : pages_[i]) ShowWindow(h, i == page ? SW_SHOW : SW_HIDE);
        demo_guide_.visible(page == 7);
        for (const auto nav : nav_) InvalidateRect(nav, nullptr, TRUE);
        if (page == 7) { demo_guide_.show(options_.preview_step.value_or(ui::GuideStep::touch), L"Principale"); EnableWindow(demo_guide_.edit(), FALSE); EnableWindow(demo_guide_.accept(), FALSE); }
        layout(); states();
        if (page != 7) SetFocus(page == 4 ? setup_action_ : nav_[page == 0 ? 0 : page == 1 ? 1 : 2]);
    }
    void change_language() {
        if (busy_) return; const auto selection = SendMessageW(language_select_, CB_GETCURSEL, 0, 0); if (selection != 0 && selection != 1) return;
        const auto next = selection == 0 ? ui::Language::italian : ui::Language::english;
        if (!options_.demo && !ui::save_preferred_language(next)) { error(window_, tr(L"Impossibile salvare la lingua. Riapri il gestore come amministratore e riprova.")); return; }
        ui::set_language(next); for (const auto& [control, key] : labels_) SetWindowTextW(control, tr(key));
        SetWindowTextW(window_, options_.demo ? tr(L"HID FIDO2 · Anteprima") : L"HID FIDO2"); refresh(); change_page(page_);
    }
    std::wstring selected_key() const { const auto index = ListView_GetNextItem(key_list_, -1, LVNI_SELECTED); return index >= 0 && static_cast<std::size_t>(index) < status_.keys.size() ? status_.keys[index].label : L""; }
    void key_menu(int index = -1) {
        if (busy_) return; if (index < 0) index = ListView_GetNextItem(key_list_, -1, LVNI_SELECTED);
        if (index < 0 || static_cast<std::size_t>(index) >= status_.keys.size()) return;
        ListView_SetItemState(key_list_, index, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
        const auto menu = CreatePopupMenu(); if (!menu) win_error("Key menu");
        const auto add = [&](UINT id, const wchar_t* name, VaultAction action) { AppendMenuW(menu, MF_STRING | (can_run(status_, action, busy_, options_.demo) ? MF_ENABLED : MF_GRAYED), id, tr(name)); };
        if (status_.keys[index].proof == "unknown") add(proof_id, L"Completa verifica", VaultAction::verify_protection);
        add(verify_id, L"Prova chiave", VaultAction::verify); add(rename_id, L"Rinomina", VaultAction::rename_key);
        AppendMenuW(menu, MF_STRING, key_details_id, tr(L"Dettagli…"));
        AppendMenuW(menu, MF_SEPARATOR, 0, nullptr); add(remove_id, L"Rimuovi", VaultAction::remove_key);
        RECT row{}; ListView_GetItemRect(key_list_, index, &row, LVIR_BOUNDS); POINT point{row.right, row.bottom}; ClientToScreen(key_list_, &point);
        const auto chosen = TrackPopupMenu(menu, TPM_RETURNCMD | TPM_RIGHTALIGN | TPM_RIGHTBUTTON, point.x, point.y, 0, window_, nullptr); DestroyMenu(menu); if (chosen) command(static_cast<int>(chosen));
    }
    void key_details() {
        const auto index = ListView_GetNextItem(key_list_, -1, LVNI_SELECTED);
        if (index < 0 || static_cast<std::size_t>(index) >= status_.keys.size()) return;
        const auto& key = status_.keys[index];
        const auto body = tr(L"Controllo sicurezza: ") + protection(key.proof) + tr(L"\nUltimo controllo: ") + date(key.checked);
        const TASKDIALOG_BUTTON buttons[]{{IDOK, tr(L"Controlla sicurezza")}, {IDCANCEL, tr(L"Chiudi")}};
        TASKDIALOGCONFIG dialog{sizeof(dialog)}; dialog.hwndParent = window_; dialog.pszWindowTitle = L"HID FIDO2"; dialog.pszMainInstruction = key.label.c_str(); dialog.pszContent = body.c_str(); dialog.dwFlags = TDF_ALLOW_DIALOG_CANCELLATION;
        const bool available = can_run(status_, VaultAction::verify_protection, busy_, options_.demo);
        dialog.pButtons = available ? buttons : buttons + 1; dialog.cButtons = available ? 2 : 1; dialog.nDefaultButton = IDCANCEL; int selected{};
        if (SUCCEEDED(TaskDialogIndirect(&dialog, &selected, nullptr, nullptr)) && selected == IDOK) vault(VaultAction::verify_protection, key.label);
    }
    void setup_state() {
        const auto step = setup_step(status_, setup_checks_); const wchar_t *headline{}, *detail{}, *action{};
        switch (step) {
        case SetupStep::unavailable: headline = L"Controlla l'installazione"; detail = L"Apri Installazione per proseguire."; action = L"Apri Installazione"; setup_art_ = ui::GuideArt::wait; break;
        case SetupStep::recovery: headline = L"Prima di iniziare"; detail = L"Prepara due chiavi e verifica la password Windows."; action = L"Inizia"; setup_art_ = ui::GuideArt::insert; break;
        case SetupStep::primary: headline = L"Registra la Principale"; detail = L"Scegli la chiave che userai più spesso."; action = L"Registra la chiave"; setup_art_ = ui::GuideArt::insert; break;
        case SetupStep::password: headline = L"Aggiorna la password salvata"; detail = L"Usa una chiave registrata e la password Windows attuale."; action = L"Aggiorna password"; setup_art_ = ui::GuideArt::password; break;
        case SetupStep::spare: headline = L"Aggiungi la Riserva"; detail = L"Tieni pronte la chiave registrata e quella nuova."; action = L"Aggiungi la Riserva"; setup_art_ = ui::GuideArt::insert; break;
        case SetupStep::protection: headline = L"Completa la verifica"; detail = L"La procedura ti dirà quale chiave collegare."; action = L"Controlla la chiave"; setup_art_ = ui::GuideArt::touch; break;
        case SetupStep::activation: headline = L"Attiva l'accesso con chiave"; detail = L"La password Windows resterà disponibile per il recupero."; action = L"Attiva accesso"; setup_art_ = ui::GuideArt::check; break;
        case SetupStep::trial:
            headline = !setup_checks_.primary_unlock ? L"Prova la Principale" : !setup_checks_.spare_unlock ? L"Prova la Riserva" : L"Prova dopo un riavvio";
            detail = !setup_checks_.restart && setup_checks_.primary_unlock && setup_checks_.spare_unlock ? L"Salva il lavoro e prova l'accesso dopo un riavvio." : L"Collega solo questa chiave e sblocca Windows con HID FIDO2.";
            action = setup_checks_.primary_unlock && setup_checks_.spare_unlock ? L"Ho effettuato l'accesso" : L"Lo sblocco è riuscito"; setup_art_ = ui::GuideArt::check; break;
        case SetupStep::complete: headline = L"Configurazione completata"; detail = L"Hai confermato le prove in Windows. Conserva la Riserva."; action = L"Fine"; setup_art_ = ui::GuideArt::check; break;
        }
        SetWindowTextW(setup_stage_, tr(headline)); SetWindowTextW(setup_detail_, tr(detail)); SetWindowTextW(setup_action_, tr(action));
        const int macro = step == SetupStep::spare ? 2 : step == SetupStep::activation || step == SetupStep::trial || step == SetupStep::complete ? 3 : 1;
        SetWindowTextW(setup_steps_, macro == 1 ? tr(L"1 Principale     —     2 Riserva     —     3 Prova Windows") : macro == 2 ? tr(L"1 Principale ✓     —     2 Riserva     —     3 Prova Windows") : tr(L"1 Principale ✓     —     2 Riserva ✓     —     3 Prova Windows"));
        ShowWindow(recovery_check_, page_ == 4 && step == SetupStep::recovery ? SW_SHOW : SW_HIDE);
        EnableWindow(setup_action_, !busy_ && (step == SetupStep::recovery || step == SetupStep::trial || step == SetupStep::complete || !options_.demo));
        EnableWindow(recovery_check_, !busy_); EnableWindow(setup_cancel_, !busy_); EnableWindow(setup_help_, !busy_);
    }
    void setup_action() {
        if (busy_) return;
        const auto step = setup_step(status_, setup_checks_);
        if (step == SetupStep::recovery) {
            if (SendMessageW(recovery_check_, BM_GETCHECK, 0, 0) != BST_CHECKED) { SetFocus(recovery_check_); return; }
            setup_checks_.recovery = true; states(); setup_action(); return;
        }
        if (step == SetupStep::trial) {
            if (!setup_checks_.primary_unlock) setup_checks_.primary_unlock = true; else if (!setup_checks_.spare_unlock) setup_checks_.spare_unlock = true; else setup_checks_.restart = true;
            save_trials(); states(); InvalidateRect(window_, nullptr, TRUE); return;
        }
        if (step == SetupStep::complete) { change_page(0); return; }
        if (options_.demo) return;
        switch (step) {
        case SetupStep::unavailable: change_page(3); break;
        case SetupStep::primary: vault(VaultAction::enroll, L"Principale"); break;
        case SetupStep::password: vault(VaultAction::update_password); break;
        case SetupStep::spare: vault(VaultAction::add_key, status_.keys.front().label == L"Riserva" ? L"Principale" : L"Riserva"); break;
        case SetupStep::protection: for (const auto& key : status_.keys) if (key.proof == "unknown") { vault(VaultAction::verify_protection, key.label); break; } break;
        case SetupStep::activation: deploy(false); break;
        default: break;
        }
    }
    void save_trials() { if (!options_.demo) (void)save_setup_trials(status_, setup_checks_); }
    void support_state() {
        const auto count = support_trace_.events().snapshot().size();
        const auto line = support_trace_.running() ? tr(L"Raccolta in corso · secondi trascorsi: ") + std::to_wstring(support_trace_.elapsed_ms() / 1000) : std::wstring(tr(L"Raccolta ferma"));
        const auto text = line + tr(L"\r\nEventi di accesso raccolti: ") + std::to_wstring(count); SetWindowTextW(trace_state_, text.c_str());
        SetWindowTextW(trace_start_, support_trace_.running() ? tr(L"Ferma raccolta") : tr(L"Avvia raccolta")); EnableWindow(trace_start_, !options_.demo && !busy_); EnableWindow(support_report_, !busy_);
    }
    void collect_support_report() {
        if (busy_) return;
        support_trace_.stop();
        if (options_.demo) { show_support_report(SupportAudit::not_run); return; }
        busy_ = true; states(); SetWindowTextW(footer_, tr(L"Controllo dell'installazione per il report…"));
        worker_ = std::thread([this] {
            auto result = std::make_unique<JobResult>(); result->support = true;
            try { (void)audit_current(sid_); result->audit = SupportAudit::passed; } catch (...) { result->audit = SupportAudit::failed; }
            PostMessageW(window_, complete_message, 0, reinterpret_cast<LPARAM>(result.release()));
        });
    }
    void show_support_report(SupportAudit audit) {
        const auto report = make_support_report(status_, audit, support_trace_.events().snapshot(), support_trace_.events().discarded(), support_trace_.consumer_error(), support_trace_.events_lost(), helper_report_, helper_incomplete_, last_exit_code_, options_.demo);
        if (preview_report(window_, widen(report))) save_support_report(window_, report);
    }

    void states() {
        const auto allow = [&](VaultAction action) { return can_run(status_, action, busy_, options_.demo); };
        EnableWindow(add_, allow(VaultAction::add_key)); EnableWindow(settings_, !busy_ && !options_.demo); EnableWindow(password_, allow(VaultAction::update_password)); EnableWindow(backup_, allow(VaultAction::backup)); EnableWindow(restore_, allow(VaultAction::restore));
        const auto verified = std::count_if(status_.keys.begin(), status_.keys.end(), [](const auto& key) { return key.proof != "unknown"; }); const bool legacy = SendMessageW(legacy_, BM_GETCHECK, 0, 0) == BST_CHECKED;
        const bool here = !status_.provider_path.empty() && _wcsicmp(status_.provider_path.c_str(), (package_ / L"bin" / L"HidFido2CredentialProvider.dll").c_str()) == 0;
        EnableWindow(install_, !options_.demo && !busy_ && !here && status_.enrolled && status_.active && status_.keys.size() >= 2 && (verified >= 2 || (signer_pin().empty() && status_.registered && legacy)));
        EnableWindow(uninstall_, !options_.demo && !busy_ && status_.has_deployment); EnableWindow(legacy_, !options_.demo && !busy_ && signer_pin().empty() && status_.registered && verified < 2);
        EnableWindow(primary_, !busy_); EnableWindow(language_select_, !busy_); EnableWindow(refresh_, !busy_);
        for (const auto nav : nav_) EnableWindow(nav, !busy_); EnableWindow(back_, !busy_);
        SendMessageW(progress_, PBM_SETMARQUEE, busy_, 35); ShowWindow(progress_, busy_ ? SW_SHOW : SW_HIDE);
        setup_state(); support_state();
    }
    void refresh() {
        try {
            if (options_.demo) { status_ = {}; status_.observed = status_.enrolled = status_.active = status_.registered = status_.compatible = status_.has_deployment = true; status_.schema = 2; status_.provider_version = L"0.9.0"; status_.keys = {{L"Principale", "verified_distinct", 1792997471}, {L"Riserva", "unknown", 0}}; status_.backups = {{std::string(32, '1'), 1792997471, 0}}; }
            else status_ = observe(package_, sid_);
            if (options_.demo && options_.demo_state == L"empty") { status_ = {}; status_.observed = status_.compatible = true; status_.schema = 2; }
            if (options_.demo && options_.demo_state == L"ready") { status_.keys[1].proof = "verified_denied"; status_.keys[1].checked = 1792997471; }
            const auto binding = setup_trials_binding(status_);
            if (binding != trials_binding_) { setup_checks_.primary_unlock = setup_checks_.spare_unlock = setup_checks_.restart = false; if (!options_.demo) { const auto restored = load_setup_trials(status_); setup_checks_.primary_unlock = restored.primary_unlock; setup_checks_.spare_unlock = restored.spare_unlock; setup_checks_.restart = restored.restart; } trials_binding_ = binding; }
            const auto presentation = home_presentation(status_); home_ready_ = presentation.ready;
            SetWindowTextW(summary_, tr(presentation.heading)); SetWindowTextW(overview_detail_, tr(presentation.detail)); SetWindowTextW(primary_, tr(presentation.action));
            const auto selected = selected_key(); ListView_DeleteAllItems(key_list_);
            for (std::size_t i = 0; i < status_.keys.size(); ++i) {
                const auto& key = status_.keys[i]; LVITEMW item{}; item.mask = LVIF_TEXT; item.iItem = static_cast<int>(i); item.pszText = const_cast<wchar_t*>(key.label.c_str()); ListView_InsertItem(key_list_, &item);
                auto state = std::wstring(!status_.active ? tr(L"Password da aggiornare") : key.proof == "unknown" ? tr(L"Da verificare") : tr(L"Pronta"));
                ListView_SetItemText(key_list_, item.iItem, 1, state.data()); ListView_SetItemText(key_list_, item.iItem, 2, const_cast<wchar_t*>(L"•••")); if (selected == key.label) ListView_SetItemState(key_list_, item.iItem, LVIS_SELECTED, LVIS_SELECTED);
            }
            SendMessageW(backups_, CB_RESETCONTENT, 0, 0); for (const auto& backup : status_.backups) { const auto label = date(backup.created); SendMessageW(backups_, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(label.c_str())); }
            if (status_.backups.empty()) SendMessageW(backups_, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(tr(L"Nessuna copia di sicurezza disponibile"))); SendMessageW(backups_, CB_SETCURSEL, 0, 0);
            SetWindowTextW(installed_heading_, status_.registered ? tr(L"Accesso con chiave attivo") : tr(L"Accesso con chiave non installato"));
            const auto installed = tr(L"Versione installata: ") + (status_.provider_version.empty() ? tr(L"non presente") : status_.provider_version); SetWindowTextW(installed_detail_, installed.c_str());
            SetWindowTextW(footer_, options_.demo ? tr(L"Anteprima · dati di esempio") : L"");
        } catch (const std::exception& failure) { status_.observed = false; SetWindowTextW(summary_, tr(L"Stato non disponibile")); SetWindowTextW(overview_detail_, tr(L"Usa la password Windows per il recupero.")); technical_error(window_, widen(failure.what()).c_str()); }
        states();
    }
    void vault(VaultAction action, std::wstring selection = {}, std::wstring replacement = {}) {
        if (!can_run(status_, action, busy_, options_.demo)) return;
        if (action == VaultAction::remove_key && !confirm(window_, tr(L"Revocare questa chiave? Se una copia precedente può essere stata sottratta, cambia anche la password Windows."))) return;
        if (action == VaultAction::update_password && !confirm(window_, tr(L"Hai già cambiato la password in Windows? Ora verrà aggiornata la copia cifrata con una chiave registrata."))) return;
        if (action == VaultAction::restore && !confirm(window_, tr(L"Ripristinare la copia compatibile selezionata, conservando revoche e contatori correnti?"))) return;
        auto args = vault_arguments(action, selection, sid_, replacement);
        helper_report_.clear(); helper_incomplete_ = false;
        if (support_trace_.running()) {
            const auto directory = install_root() / L"support"; new_directory(directory); report_pins_ = pin_directories(directory);
            helper_report_path_ = directory / (widen(random_id()) + L".jsonl");
            args.emplace_back(L"--report"); args.emplace_back(helper_report_path_.wstring());
            helper_report_.clear(); helper_incomplete_ = true;
        }
        try { pending_ = start_native(package_ / L"bin" / L"hid-fido2-vault.exe", args); }
        catch (...) { helper_report_path_.clear(); report_pins_.clear(); throw; }
        busy_ = true; SetWindowTextW(footer_, tr(L"Segui le finestre locali della chiave. Nessun tentativo automatico.")); states();
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
        const wchar_t* content{};
        if (page_ == 4) {
            const auto step = setup_step(status_, setup_checks_);
            if (step == SetupStep::recovery) content = tr(L"Prima di attivare la chiave, verifica un accesso con la password Windows attuale e prepara due chiavi FIDO2. Il PIN di Windows Hello non è la password Windows.");
            else if (step == SetupStep::trial || step == SetupStep::complete) content = tr(L"1. Collega una sola chiave e premi Win+L.\n2. Scegli HID FIDO2 in Opzioni di accesso.\n3. Usa il PIN della chiave e toccala quando richiesto.\n\nConferma nel gestore solo le prove riuscite. Dopo il riavvio riaprilo per continuare.");
            else content = tr(L"Segui un passaggio alla volta. Usa il PIN della chiave e tocca il sensore solo quando richiesto. Puoi annullare e usare la password Windows.");
        } else content = tr(L"Nella schermata Windows scegli Opzioni di accesso > Password e usa la password attuale.\n\nDal gestore puoi aggiornare la password salvata o rimuovere una chiave persa. La rimozione di HID FIDO2 conserva l'accesso con password.");
        MessageBoxW(window_, content, tr(L"Recupero e prove di accesso"), MB_OK | MB_ICONINFORMATION);
    }

    void command(int id) {
        if (page_ == 7 && id == ui::GuidanceView::cancel_id) { change_page(0); return; }
        if (page_ == 7 && id == ui::GuidanceView::help_id) { MessageBoxW(window_, tr(L"Segui un passaggio alla volta. Usa il PIN della chiave e tocca il sensore solo quando richiesto. Puoi annullare e usare la password Windows."), L"HID FIDO2", MB_OK | MB_ICONINFORMATION); return; }
        if (id >= nav_overview && id <= nav_settings) { if (!busy_) change_page(id == nav_settings ? 6 : id - nav_overview); return; }
        if (id == language_id) { change_language(); return; }
        if (id == instructions_id) { instructions_open_ = !instructions_open_; layout(); return; }
        if (id == support_info_id) { support_open_ = !support_open_; layout(); return; }
        if (id == back_id) { if (!busy_) change_page(6); return; }
        if (id == setup_cancel_id) { if (!busy_) change_page(0); return; }
        if (id == password_section_id) { change_page(2); return; } if (id == install_section_id) { change_page(3); return; } if (id == support_section_id) { change_page(5); return; }
        if (id == setup_id) { change_page(4); return; }
        if (id == setup_action_id) { setup_action(); return; }
        if (id == setup_help_id || id == recovery_id) { guide(); return; }
        if (id == support_report_id) { collect_support_report(); return; }
        if (id == refresh_id) { if (!busy_) refresh(); return; }
        if (id == key_details_id) { key_details(); return; }
        if (id == primary_id) {
            if (busy_) return; const auto p = home_presentation(status_);
            if (p.next == HomeAction::setup) change_page(4); else if (p.next == HomeAction::installation) change_page(3); else if (p.next == HomeAction::password) { if (!options_.demo) vault(VaultAction::update_password); } else if (p.next == HomeAction::keys || options_.demo) change_page(1);
            else { const auto menu = CreatePopupMenu(); for (std::size_t i = 0; i < status_.keys.size(); ++i) AppendMenuW(menu, MF_STRING, 500 + i, status_.keys[i].label.c_str()); RECT button{}; GetWindowRect(primary_, &button); const auto chosen = TrackPopupMenu(menu, TPM_RETURNCMD, button.left, button.bottom, 0, window_, nullptr); DestroyMenu(menu); if (chosen >= 500 && chosen < 500 + status_.keys.size()) vault(VaultAction::verify, status_.keys[chosen - 500].label); } return;
        }
        if (options_.demo || busy_) return;
        switch (id) {
        case verify_id: vault(VaultAction::verify, selected_key()); break;
        case proof_id: vault(VaultAction::verify_protection, selected_key()); break;
        case add_id: { const auto label = ask_label(window_); if (!label.empty()) vault(VaultAction::add_key, label); break; }
        case remove_id: vault(VaultAction::remove_key, selected_key()); break;
        case rename_id: { const auto old = selected_key(); if (old.empty()) break; const auto label = ask_label(window_, old); if (!label.empty() && label != old) { if (std::any_of(status_.keys.begin(), status_.keys.end(), [&](const auto& key) { return key.label == label; })) error(window_, tr(L"Esiste già una chiave con questa etichetta.")); else vault(VaultAction::rename_key, old, label); } break; }
        case password_id: vault(VaultAction::update_password); break; case backup_id: vault(VaultAction::backup); break;
        case restore_id: { const auto selected = SendMessageW(backups_, CB_GETCURSEL, 0, 0); if (selected >= 0 && static_cast<std::size_t>(selected) < status_.backups.size()) vault(VaultAction::restore, widen(status_.backups[selected].id)); break; }
        case windows_password_id: ShellExecuteW(window_, L"open", L"ms-settings:signinoptions", nullptr, nullptr, SW_SHOWNORMAL); break;
        case install_id: deploy(false); break; case uninstall_id: deploy(true); break; case legacy_id: states(); layout(); break;
        case trace_start_id: if (support_trace_.running()) support_trace_.stop(); else { support_trace_.start(); helper_report_.clear(); helper_incomplete_ = false; last_exit_code_.reset(); } states(); break;
        }
    }
    void tick() {
        if (page_ == 5) support_state();
        if (!pending_.valid() || WaitForSingleObject(pending_.get(), 0) != WAIT_OBJECT_0) return;
        DWORD code{}; if (!GetExitCodeProcess(pending_.get(), &code)) win_error("Read tool completion"); pending_ = Handle{}; last_exit_code_ = code;
        if (!helper_report_path_.empty()) {
            try { auto report = read_text(helper_report_path_, 256 * 1024); (void)sanitize_helper_report(report); helper_report_ = std::move(report); helper_incomplete_ = false; } catch (...) { helper_report_.clear(); helper_incomplete_ = true; }
            DeleteFileW(helper_report_path_.c_str()); helper_report_path_.clear(); report_pins_.clear();
        }
        busy_ = false; refresh();
        SetWindowTextW(footer_, code == 0 ? tr(L"Operazione completata.") : code == 2 ? tr(L"Operazione annullata. Nessun altro tentativo.") : tr(L"Operazione interrotta: consulta il messaggio dello strumento."));
    }
    void completed(JobResult* raw) {
        std::unique_ptr<JobResult> result(raw); if (worker_.joinable()) worker_.join(); busy_ = false; refresh();
        if (result->support) { show_support_report(result->audit); return; }
        const auto& r = result->transaction;
        if (!result->failure.empty()) technical_error(window_, result->failure.c_str());
        else if (r.success) MessageBoxW(window_, result->uninstall ? tr(L"Provider rimosso. Archivio e accesso con password conservati.") : result->shortcut_warning ? tr(L"Provider nativo installato. I collegamenti non sono stati creati: apri Gestione-HID-FIDO2.exe dalla release protetta.") : tr(L"Versione nativa installata. I collegamenti Start e Desktop sono pronti. Prova separatamente sblocco e login dopo riavvio."), tr(title), MB_OK | MB_ICONINFORMATION);
        else error(window_, r.restored ? tr(L"Aggiornamento non riuscito. La registrazione precedente è stata ripristinata.") : tr(L"Aggiornamento non riuscito. Usa la password Windows e la guida di recupero."));
    }

    void snapshot() {
        if (!options_.demo || options_.snapshot.empty()) return; reject_reparse(options_.snapshot); std::filesystem::create_directories(options_.snapshot);
        Gdiplus::GdiplusStartupInput input; ULONG_PTR token{}; if (Gdiplus::GdiplusStartup(&token, &input, nullptr) != Gdiplus::Ok) throw std::runtime_error("PNG renderer unavailable");
        const CLSID png{0x557cf406, 0x1a04, 0x11d3, {0x9a, 0x73, 0x00, 0x00, 0xf8, 0x1e, 0xf3, 0x2e}};
        for (int page = options_.preview_step ? 7 : 0; page < 8; ++page) {
            if (page == 7 && !options_.preview_step) break; change_page(page); RedrawWindow(window_, nullptr, nullptr, RDW_INVALIDATE | RDW_ALLCHILDREN | RDW_UPDATENOW);
            RECT area{}; GetWindowRect(window_, &area); const auto dc = GetDC(window_), memory = CreateCompatibleDC(dc); const auto bitmap = CreateCompatibleBitmap(dc, area.right - area.left, area.bottom - area.top); const auto old = SelectObject(memory, bitmap);
            SendMessageW(window_, WM_PRINT, reinterpret_cast<WPARAM>(memory), PRF_CLIENT | PRF_CHILDREN | PRF_ERASEBKGND | PRF_NONCLIENT);
            // Native dropdowns omit selected text from hidden-window WM_PRINT.
            for (const auto combo : {page == 6 ? language_select_ : nullptr, page == 2 ? backups_ : nullptr}) {
                if (!combo) continue; const auto selection = SendMessageW(combo, CB_GETCURSEL, 0, 0); if (selection == CB_ERR) continue;
                const auto length = SendMessageW(combo, CB_GETLBTEXTLEN, selection, 0); if (length < 0 || length > 512) continue;
                std::wstring label(static_cast<std::size_t>(length) + 1, L'\0'); SendMessageW(combo, CB_GETLBTEXT, selection, reinterpret_cast<LPARAM>(label.data())); RECT r{}; GetWindowRect(combo, &r); OffsetRect(&r, -area.left, -area.top); r.left += scale(4); r.right -= scale(23); r.top += scale(1); r.bottom -= scale(1); FillRect(memory, &r, white_); SelectObject(memory, font_); SetBkMode(memory, TRANSPARENT); SetTextColor(memory, RGB(35, 43, 55)); DrawTextW(memory, label.c_str(), static_cast<int>(length), &r, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
            }
            { Gdiplus::Bitmap image(bitmap, nullptr); const auto path = options_.snapshot / (options_.preview_step ? L"native-wizard.png" : L"native-manager-" + std::to_wstring(page) + L".png"); if (image.Save(path.c_str(), &png, nullptr) != Gdiplus::Ok) throw std::runtime_error("Cannot save UI snapshot"); }
            SelectObject(memory, old); DeleteObject(bitmap); DeleteDC(memory); ReleaseDC(window_, dc);
        }
        Gdiplus::GdiplusShutdown(token); SendMessageW(window_, WM_CLOSE, 0, 0);
    }
    void paint(HDC dc) {
        RECT area{}; GetClientRect(window_, &area); FillRect(dc, &area, white_);
        if (page_ == 7) { demo_guide_.paint(dc); return; }
        if (page_ != 4) { const auto pen = CreatePen(PS_SOLID, 1, RGB(232, 234, 237)); const auto old = SelectObject(dc, pen); MoveToEx(dc, 0, scale(63), nullptr); LineTo(dc, area.right, scale(63)); SelectObject(dc, old); DeleteObject(pen); }
        if (page_ == 0) { const int width = MulDiv(area.right, 96, static_cast<int>(dpi_)), centre = std::max(48, (width - 600) / 2), lift = std::max(0, (640 - MulDiv(area.bottom, 96, static_cast<int>(dpi_))) / 2); const auto saved = SaveDC(dc); SetViewportOrgEx(dc, 0, -scale(lift), nullptr); RECT icon{scale(centre), scale(151), scale(centre + 38), scale(189)}; const auto pen = CreatePen(PS_SOLID, scale(2), home_ready_ ? RGB(30, 125, 75) : RGB(147, 111, 20)); const auto old = SelectObject(dc, pen), brush = SelectObject(dc, GetStockObject(NULL_BRUSH)); Ellipse(dc, icon.left, icon.top, icon.right, icon.bottom); if (home_ready_) { MoveToEx(dc, scale(centre + 9), scale(170), nullptr); LineTo(dc, scale(centre + 16), scale(177)); LineTo(dc, scale(centre + 29), scale(162)); } else { MoveToEx(dc, scale(centre + 19), scale(160), nullptr); LineTo(dc, scale(centre + 19), scale(173)); Ellipse(dc, scale(centre + 18), scale(179), scale(centre + 20), scale(181)); } SelectObject(dc, brush); SelectObject(dc, old); DeleteObject(pen); RestoreDC(dc, saved); }
        if (page_ == 4) { const int height = MulDiv(area.bottom, 96, static_cast<int>(dpi_)); RECT art{scale(130), scale(257), area.right - scale(130), scale(setup_step(status_, setup_checks_) == SetupStep::recovery ? std::min(390, height - 210) : std::min(465, height - 175))}; ui::draw_guide_art(dc, art, setup_art_); }
    }
    LRESULT draw_key_row(NMLVCUSTOMDRAW& drawing) {
        if (drawing.nmcd.dwDrawStage == CDDS_PREPAINT) return CDRF_NOTIFYITEMDRAW;
        if (drawing.nmcd.dwDrawStage != CDDS_ITEMPREPAINT) return CDRF_DODEFAULT;
        const auto index = static_cast<std::size_t>(drawing.nmcd.dwItemSpec); if (index >= status_.keys.size()) return CDRF_DODEFAULT;
        const auto& key = status_.keys[index]; const auto dc = drawing.nmcd.hdc; const auto saved = SaveDC(dc);
        RECT row{}; ListView_GetItemRect(key_list_, static_cast<int>(index), &row, LVIR_BOUNDS);
        const bool selected = (ListView_GetItemState(key_list_, static_cast<int>(index), LVIS_SELECTED) & LVIS_SELECTED) != 0;
        const auto background = CreateSolidBrush(selected ? RGB(244, 246, 248) : RGB(255, 255, 255)); FillRect(dc, &row, background); DeleteObject(background);
        const int centre = (row.top + row.bottom) / 2, icon_left = row.left + scale(13);
        const auto pen = CreatePen(PS_SOLID, scale(1), RGB(65, 75, 88)); SelectObject(dc, pen); SelectObject(dc, GetStockObject(NULL_BRUSH));
        RoundRect(dc, icon_left, centre - scale(13), icon_left + scale(21), centre + scale(15), scale(6), scale(6)); Rectangle(dc, icon_left + scale(5), centre - scale(21), icon_left + scale(16), centre - scale(13)); Ellipse(dc, icon_left + scale(7), centre - scale(5), icon_left + scale(15), centre + scale(3));
        SelectObject(dc, font_); SetBkMode(dc, TRANSPARENT); SetTextColor(dc, RGB(32, 33, 36));
        const int first_width = ListView_GetColumnWidth(key_list_, 0), second_width = ListView_GetColumnWidth(key_list_, 1);
        RECT name{row.left + scale(53), row.top, row.left + first_width - scale(14), row.bottom}; DrawTextW(dc, key.label.c_str(), -1, &name, DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS);
        const bool verified = key.proof != "unknown" && status_.active; const auto colour = verified ? RGB(30, 125, 75) : RGB(141, 105, 20);
        const auto dot = CreateSolidBrush(colour); SelectObject(dc, dot); SelectObject(dc, GetStockObject(NULL_PEN));
        const int status_left = row.left + first_width; Ellipse(dc, status_left + scale(3), centre - scale(3), status_left + scale(9), centre + scale(3));
        SetTextColor(dc, colour); RECT state{status_left + scale(18), row.top, status_left + second_width - scale(8), row.bottom};
        const auto state_text = !status_.active ? tr(L"Password da aggiornare") : key.proof == "unknown" ? tr(L"Da verificare  ›") : tr(L"Pronta");
        DrawTextW(dc, state_text, -1, &state, DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS);
        SetTextColor(dc, RGB(32, 33, 36)); RECT menu{status_left + second_width, row.top, row.right, row.bottom}; DrawTextW(dc, L"•••", -1, &menu, DT_SINGLELINE | DT_VCENTER | DT_CENTER);
        const auto rule = CreatePen(PS_SOLID, 1, RGB(234, 236, 239)); SelectObject(dc, rule); MoveToEx(dc, row.left, row.bottom - 1, nullptr); LineTo(dc, row.right, row.bottom - 1);
        if (selected && GetFocus() == key_list_ && !(SendMessageW(key_list_, WM_QUERYUISTATE, 0, 0) & UISF_HIDEFOCUS)) { auto focus = row; InflateRect(&focus, -2, -2); DrawFocusRect(dc, &focus); }
        RestoreDC(dc, saved); DeleteObject(dot); DeleteObject(pen); DeleteObject(rule); return CDRF_SKIPDEFAULT;
    }
    static LRESULT CALLBACK window_proc(HWND window, UINT message, WPARAM w, LPARAM l) {
        auto* self = reinterpret_cast<Manager*>(GetWindowLongPtrW(window, GWLP_USERDATA));
        if (message == WM_NCCREATE) { self = static_cast<Manager*>(reinterpret_cast<CREATESTRUCTW*>(l)->lpCreateParams); self->window_ = window; SetWindowLongPtrW(window, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self)); }
        if (!self) return DefWindowProcW(window, message, w, l);
        try {
            switch (message) {
            case WM_CREATE: self->create(); return 0; case WM_SIZE: self->layout(); return 0;
            case WM_GETMINMAXINFO: { const auto dpi = GetDpiForWindow(window); RECT bounds{0, 0, MulDiv(760, dpi, 96), MulDiv(560, dpi, 96)}; AdjustWindowRectExForDpi(&bounds, WS_OVERLAPPEDWINDOW, FALSE, 0, dpi); reinterpret_cast<MINMAXINFO*>(l)->ptMinTrackSize = {bounds.right - bounds.left, bounds.bottom - bounds.top}; return 0; }
            case WM_DPICHANGED: { const auto* bounds = reinterpret_cast<RECT*>(l); SetWindowPos(window, nullptr, bounds->left, bounds->top, bounds->right - bounds->left, bounds->bottom - bounds->top, SWP_NOZORDER); self->fonts(); self->demo_guide_.fonts(); self->layout(); return 0; }
            case WM_COMMAND:
                // Focus/dropdown notifications must not rebuild the page and
                // close the language selector before a choice is made.
                if (LOWORD(w) == language_id && HIWORD(w) != CBN_SELCHANGE) return 0;
                self->command(LOWORD(w)); return 0;
            case WM_NOTIFY: { const auto* header = reinterpret_cast<NMHDR*>(l); if (header->hwndFrom != self->key_list_) break;
                if (header->code == NM_CUSTOMDRAW) return self->draw_key_row(*reinterpret_cast<NMLVCUSTOMDRAW*>(l));
                if (header->code == NM_CLICK || header->code == NM_RCLICK || header->code == NM_DBLCLK) { const auto* item = reinterpret_cast<NMITEMACTIVATE*>(l); if (item->iItem >= 0 and static_cast<std::size_t>(item->iItem) < self->status_.keys.size()) { if (header->code == NM_CLICK && item->iSubItem == 1 && self->status_.keys[item->iItem].proof == "unknown" && !self->options_.demo) self->vault(VaultAction::verify_protection, self->status_.keys[item->iItem].label); else if (header->code != NM_CLICK || item->iSubItem == 2) self->key_menu(item->iItem); } }
                else if (header->code == LVN_KEYDOWN) { const auto key = reinterpret_cast<NMLVKEYDOWN*>(l)->wVKey; if (key == VK_RETURN || key == VK_SPACE || key == VK_APPS || (key == VK_F10 && GetKeyState(VK_SHIFT) < 0)) self->key_menu(); } return 0; }
            case WM_CONTEXTMENU: if (reinterpret_cast<HWND>(w) == self->key_list_) { self->key_menu(); return 0; } break;
            case WM_TIMER: self->tick(); return 0; case complete_message: self->completed(reinterpret_cast<JobResult*>(l)); return 0; case capture_message: self->snapshot(); return 0;
            case WM_DRAWITEM: {
                const auto& item = *reinterpret_cast<DRAWITEMSTRUCT*>(l);
                if (item.CtlID >= nav_overview && item.CtlID <= nav_settings) {
                    ui::draw_guide_button(item, false, true, true); const int selected = self->page_ == 0 ? 0 : self->page_ == 1 ? 1 : 2;
                    if (item.CtlID == static_cast<unsigned>(nav_overview + selected)) { const auto pen = CreatePen(PS_SOLID, self->scale(2), RGB(32, 33, 36)); const auto old = SelectObject(item.hDC, pen); MoveToEx(item.hDC, item.rcItem.left + self->scale(12), item.rcItem.bottom - self->scale(2), nullptr); LineTo(item.hDC, item.rcItem.right - self->scale(12), item.rcItem.bottom - self->scale(2)); SelectObject(item.hDC, old); DeleteObject(pen); } return TRUE;
                }
                if (item.CtlID >= password_section_id && item.CtlID <= support_section_id) {
                    FillRect(item.hDC, &item.rcItem, self->white_); SelectObject(item.hDC, self->font_); SetBkMode(item.hDC, TRANSPARENT); SetTextColor(item.hDC, RGB(32, 33, 36));
                    auto label = item.rcItem; label.left += self->scale(8); label.right -= self->scale(32);
                    const wchar_t* names[]{tr(L"Password e recupero"), tr(L"Installazione"), tr(L"Assistenza")}; DrawTextW(item.hDC, names[item.CtlID - password_section_id], -1, &label, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
                    auto arrow = item.rcItem; arrow.left = arrow.right - self->scale(32); DrawTextW(item.hDC, L"›", -1, &arrow, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
                    const auto pen = CreatePen(PS_SOLID, 1, RGB(232, 234, 237)); const auto old = SelectObject(item.hDC, pen); MoveToEx(item.hDC, item.rcItem.left, item.rcItem.bottom - 1, nullptr); LineTo(item.hDC, item.rcItem.right, item.rcItem.bottom - 1); SelectObject(item.hDC, old); DeleteObject(pen);
                    if ((item.itemState & ODS_FOCUS) && !(item.itemState & ODS_NOFOCUSRECT)) DrawFocusRect(item.hDC, &item.rcItem); return TRUE;
                }
                if (item.CtlID == ui::GuidanceView::accept_id || item.CtlID == ui::GuidanceView::help_id) { ui::draw_guide_button(item, item.CtlID == ui::GuidanceView::accept_id, item.CtlID == ui::GuidanceView::help_id); return TRUE; }
                ui::draw_guide_button(item, std::find(self->primary_buttons_.begin(), self->primary_buttons_.end(), item.hwndItem) != self->primary_buttons_.end(), std::find(self->link_buttons_.begin(), self->link_buttons_.end(), item.hwndItem) != self->link_buttons_.end()); return TRUE;
            }
            case WM_CTLCOLORSTATIC: SetBkMode(reinterpret_cast<HDC>(w), TRANSPARENT); SetTextColor(reinterpret_cast<HDC>(w), RGB(35, 43, 55)); return reinterpret_cast<LRESULT>(self->white_);
            case WM_PAINT: { PAINTSTRUCT paint{}; const auto dc = BeginPaint(window, &paint); self->paint(dc); EndPaint(window, &paint); return 0; }
            case WM_PRINTCLIENT: self->paint(reinterpret_cast<HDC>(w)); return 0;
            case WM_CLOSE: if (self->busy_) { MessageBoxW(window, tr(L"Termina o annulla l'operazione nella finestra della chiave."), L"HID FIDO2", MB_OK | MB_ICONINFORMATION); return 0; } self->support_trace_.stop(); DestroyWindow(window); return 0;
            case WM_DESTROY: KillTimer(window, 1); PostQuitMessage(0); return 0;
            }
        } catch (const std::exception& failure) { technical_error(window, widen(failure.what()).c_str()); }
        return DefWindowProcW(window, message, w, l);
    }
    WindowOptions options_; std::filesystem::path package_; std::wstring sid_; Status status_; HWND window_{}; UINT dpi_{96}; bool busy_{}, instructions_open_{}, support_open_{}, home_ready_{}; int page_{};
    HBRUSH white_{CreateSolidBrush(RGB(255, 255, 255))}; HFONT font_{}, large_{}, bold_{}; HIMAGELIST rows_{};
    std::vector<HWND> controls_, primary_buttons_, link_buttons_; std::vector<std::pair<HWND, const wchar_t*>> labels_; std::array<std::vector<HWND>, 7> pages_; std::array<HWND, 3> nav_{};
    Handle pending_; std::thread worker_; SetupChecks setup_checks_; std::string trials_binding_; ui::GuideArt setup_art_{ui::GuideArt::insert}; ui::GuidanceView demo_guide_;
    SupportTrace support_trace_; std::optional<unsigned> last_exit_code_; std::filesystem::path helper_report_path_; std::vector<Handle> report_pins_; std::string helper_report_; bool helper_incomplete_{};
    HWND heading_{}, back_{}, summary_{}, overview_detail_{}, primary_{}, instructions_toggle_{}, instructions_{}, recovery_link_{}, key_list_{}, add_{}, key_note_{};
    HWND password_heading_{}, password_{}, settings_{}, backups_heading_{}, backups_{}, backup_{}, restore_{}, lost_{}, installed_heading_{}, installed_detail_{}, trust_{}, legacy_{}, legacy_note_{}, install_{}, uninstall_{}, setup_link_{};
    HWND setup_stage_{}, setup_detail_{}, setup_steps_{}, setup_action_{}, setup_cancel_{}, recovery_check_{}, setup_help_{}, trace_state_{}, support_heading_{}, trace_start_{}, support_report_{}, support_toggle_{}, support_privacy_{};
    HWND password_section_{}, install_section_{}, support_section_{}, language_label_{}, language_select_{}, version_{}, footer_{}, refresh_{}, progress_{};
};

int show_manager(WindowOptions options, std::filesystem::path package, std::wstring sid, HINSTANCE instance, int show) { Manager app(std::move(options), std::move(package), std::move(sid)); return app.run(instance, show); }
}
