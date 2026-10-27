#pragma once
#include "hidfido/localization.hpp"
#include "hidfido/guidance_assets.hpp"
#include <windows.h>
#include <algorithm>
#include <array>
#include <string>
#include <stdexcept>

// Presentation only. No device access, credential validation, secret reads,
// storage or logging. The manager uses this same view for disabled previews;
// only the vault helper reads the masked edit control in a real ceremony.
namespace hidfido::ui {
enum class GuideStep { connect, pin, touch, release, remove, reconnect, checking, password, confirm, success, error };
enum class GuideArt { insert, touch, lift, remove, password, check, wait };
struct GuideCopy { const wchar_t* heading; const wchar_t* detail; GuideArt art; };
inline GuideCopy guide_copy(GuideStep step) noexcept {
    switch (step) {
    case GuideStep::connect: return {L"Collega la chiave", L"Collega una sola chiave USB.", GuideArt::insert};
    case GuideStep::pin: return {L"PIN della chiave", L"Il PIN della chiave, non quello del PC.", GuideArt::password};
    case GuideStep::touch: return {L"Tocca e rilascia la chiave", L"Tocca il sensore quando lampeggia, poi togli il dito.", GuideArt::touch};
    case GuideStep::release: return {L"Togli il dito dal sensore", L"Premi Continua quando il sensore è libero.", GuideArt::lift};
    case GuideStep::remove: return {L"Scollega la chiave", L"Attendi che la rimozione venga rilevata.", GuideArt::remove};
    case GuideStep::reconnect: return {L"Ricollega la stessa chiave", L"Usa la stessa porta USB.", GuideArt::insert};
    case GuideStep::checking: return {L"Verifica in corso", L"Attendi la risposta della chiave.", GuideArt::wait};
    case GuideStep::password: return {L"Password di Windows", L"Verrà verificata e salvata cifrata su questo PC.", GuideArt::password};
    case GuideStep::confirm: return {L"Prima di continuare", L"", GuideArt::wait};
    case GuideStep::success: return {L"Operazione completata", L"", GuideArt::check};
    case GuideStep::error: return {L"Operazione interrotta", L"", GuideArt::wait};
    }
    return {L"Operazione interrotta", L"", GuideArt::wait};
}
inline bool guide_input(GuideStep step) noexcept { return step == GuideStep::pin || step == GuideStep::password; }
inline bool guide_acknowledgement(GuideStep step) noexcept {
    return guide_input(step) || step == GuideStep::release || step == GuideStep::confirm || step == GuideStep::success || step == GuideStep::error;
}
inline void draw_guide_art(HDC dc, RECT bounds, GuideArt art) {
    if (art == GuideArt::insert || art == GuideArt::remove || art == GuideArt::touch || art == GuideArt::lift) {
        const unsigned quadrant = art == GuideArt::insert ? 0 : art == GuideArt::remove ? 1 : art == GuideArt::touch ? 2 : 3;
        if (detail::draw_guide_asset(dc, bounds, quadrant)) return;
    }
    const int saved = SaveDC(dc);
    const int width = bounds.right - bounds.left, height = bounds.bottom - bounds.top;
    const int unit = std::max(1, std::min(width / 420, height / 180));
    // Fixed 420 x 180 geometry, centred in its real available rectangle.
    SetMapMode(dc, MM_ANISOTROPIC); SetWindowExtEx(dc, 420, 180, nullptr);
    const int drawn_width = std::min(width, height * 420 / 180), drawn_height = drawn_width * 180 / 420;
    SetViewportExtEx(dc, drawn_width, drawn_height, nullptr);
    SetViewportOrgEx(dc, bounds.left + (width - drawn_width) / 2, bounds.top + (height - drawn_height) / 2, nullptr);
    const auto ink = CreatePen(PS_SOLID, 2, RGB(65, 75, 88)), accent = CreatePen(PS_SOLID, 3, RGB(34, 105, 185));
    SelectObject(dc, ink); SelectObject(dc, GetStockObject(WHITE_BRUSH));
    const auto line = [&](int x1, int y1, int x2, int y2) { MoveToEx(dc, x1, y1, nullptr); LineTo(dc, x2, y2); };
    if (art == GuideArt::password) {
        RoundRect(dc, 90, 45, 330, 135, 10, 10);
        for (int i = 0; i < 6; ++i) { SelectObject(dc, GetStockObject(DC_BRUSH)); SetDCBrushColor(dc, RGB(65, 75, 88)); Ellipse(dc, 126 + i * 31, 85, 134 + i * 31, 93); }
    } else if (art == GuideArt::check) {
        SelectObject(dc, accent); SelectObject(dc, GetStockObject(NULL_BRUSH)); Ellipse(dc, 164, 43, 256, 135);
        line(184, 89, 203, 107); line(203, 107, 239, 69);
    } else if (art == GuideArt::wait) {
        SelectObject(dc, GetStockObject(NULL_BRUSH)); RoundRect(dc, 165, 44, 255, 136, 14, 14);
        SelectObject(dc, accent); line(187, 90, 199, 90); line(207, 90, 219, 90); line(227, 90, 239, 90);
    } else {
        // Laptop edge and its USB port. The arrow changes direction on removal.
        SelectObject(dc, GetStockObject(WHITE_BRUSH)); RoundRect(dc, 25, 28, 146, 149, 10, 10);
        for (int row = 0; row < 3; ++row) for (int col = 0; col < 4; ++col) Rectangle(dc, 39 + col * 21, 45 + row * 20, 54 + col * 21, 57 + row * 20);
        Rectangle(dc, 129, 95, 146, 120);
        const int offset = art == GuideArt::touch || art == GuideArt::lift ? 0 : 43;
        Rectangle(dc, 145 + offset, 99, 178 + offset, 116);
        RoundRect(dc, 176 + offset, 82, 332 + offset, 133, 15, 15);
        Ellipse(dc, 307 + offset, 99, 321 + offset, 115);
        SelectObject(dc, accent); SelectObject(dc, GetStockObject(NULL_BRUSH)); Ellipse(dc, 228 + offset, 94, 254 + offset, 120);
        if (art == GuideArt::touch || art == GuideArt::lift) {
            SelectObject(dc, ink); SelectObject(dc, GetStockObject(WHITE_BRUSH));
            POINT finger[]{{391, 26}, {340, 28}, {269, 55}, {244, 81}, {236, 91}, {236, 101}, {249, 103}, {267, 89}, {289, 75}, {316, 74}, {340, 83}, {391, 92}};
            if (art == GuideArt::lift) for (auto& point : finger) point.y -= 30;
            PolyBezier(dc, finger, 10); line(391, art == GuideArt::lift ? 0 : 26, 391, art == GuideArt::lift ? 62 : 92);
            SelectObject(dc, accent); line(229, 77, 221, 67); line(249, 73, 251, 61);
        } else {
            SelectObject(dc, accent); const int left = 162, right = 201;
            line(left, 156, right, 156);
            const int tip = art == GuideArt::remove ? right : left, back = art == GuideArt::remove ? right - 10 : left + 10;
            line(tip, 156, back, 148); line(tip, 156, back, 164);
        }
    }
    RestoreDC(dc, saved); DeleteObject(ink); DeleteObject(accent); (void)unit;
}
inline void draw_guide_button(const DRAWITEMSTRUCT& item, bool primary, bool link = false, bool tab = false) {
    const auto saved = SaveDC(item.hDC); const bool disabled = (item.itemState & ODS_DISABLED) != 0;
    const COLORREF fill = primary ? (disabled ? RGB(220, 223, 227) : RGB(32, 33, 36)) : RGB(255, 255, 255);
    const auto brush = CreateSolidBrush(fill); const auto pen = CreatePen(PS_SOLID, 1, link ? RGB(255, 255, 255) : primary ? fill : RGB(220, 223, 227));
    SelectObject(item.hDC, brush); SelectObject(item.hDC, pen);
    RoundRect(item.hDC, item.rcItem.left, item.rcItem.top, item.rcItem.right, item.rcItem.bottom, 8, 8);
    SetBkMode(item.hDC, TRANSPARENT); SetTextColor(item.hDC, disabled ? RGB(96, 102, 112) : primary ? RGB(255, 255, 255) : link && !tab ? RGB(25, 90, 155) : RGB(32, 33, 36));
    auto font = reinterpret_cast<HFONT>(SendMessageW(item.hwndItem, WM_GETFONT, 0, 0)); if (font) SelectObject(item.hDC, font);
    std::array<wchar_t, 256> label{}; GetWindowTextW(item.hwndItem, label.data(), static_cast<int>(label.size()));
    auto rectangle = item.rcItem; DrawTextW(item.hDC, label.data(), -1, &rectangle, DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
    if ((item.itemState & ODS_FOCUS) && !(item.itemState & ODS_NOFOCUSRECT)) { InflateRect(&rectangle, -4, -4); DrawFocusRect(item.hDC, &rectangle); }
    RestoreDC(item.hDC, saved); DeleteObject(brush); DeleteObject(pen);
}

class GuidanceView {
public:
    static constexpr int accept_id = 4101, cancel_id = 4102, help_id = 4103;
    ~GuidanceView() { clear_fonts(); }
    void create(HWND parent, int macro = 1, bool enrollment = true) {
        parent_ = parent; macro_ = macro; enrollment_ = enrollment;
        const auto make = [&](const wchar_t* kind, DWORD style, int id) {
            return CreateWindowExW(kind == std::wstring_view(L"EDIT") ? WS_EX_CLIENTEDGE : 0, kind, L"", WS_CHILD | WS_VISIBLE | style, 0, 0, 1, 1, parent, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), GetModuleHandleW(nullptr), nullptr);
        };
        stage_ = make(L"STATIC", SS_LEFT, 0); heading_ = make(L"STATIC", SS_LEFT, 0); detail_ = make(L"STATIC", SS_LEFT, 0);
        label_ = make(L"STATIC", SS_LEFT, 0);
        edit_ = make(L"EDIT", ES_PASSWORD | ES_AUTOHSCROLL | WS_TABSTOP, 4104);
        status_ = make(L"STATIC", SS_LEFT, 0);
        accept_ = make(L"BUTTON", BS_OWNERDRAW | WS_TABSTOP, accept_id);
        cancel_ = make(L"BUTTON", BS_PUSHBUTTON | WS_TABSTOP, cancel_id);
        help_ = make(L"BUTTON", BS_OWNERDRAW | WS_TABSTOP, help_id);
        for (const auto control : controls()) if (!control) throw std::runtime_error("Cannot create guidance control");
        fonts(); show(GuideStep::connect, {});
    }
    void fonts() {
        const auto dpi = GetDpiForWindow(parent_); dpi_ = dpi; clear_fonts();
        font_ = CreateFontW(-px(15), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
        title_ = CreateFontW(-px(28), 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
        for (const auto control : controls()) SendMessageW(control, WM_SETFONT, reinterpret_cast<WPARAM>(control == heading_ ? title_ : font_), TRUE);
    }
    void show(GuideStep step, std::wstring label, std::wstring detail = {}, std::wstring heading = {}) {
        step_ = step; const auto copy = guide_copy(step); label_text_ = std::move(label);
        SetWindowTextW(stage_, enrollment_ ? (macro_ == 1 ? tr(L"1 Principale     —     2 Riserva     —     3 Prova Windows") : tr(L"1 Principale ✓     —     2 Riserva     —     3 Prova Windows")) : tr(L"Operazione sulla chiave"));
        SetWindowTextW(heading_, heading.empty() ? tr(copy.heading) : heading.c_str());
        SetWindowTextW(detail_, detail.empty() ? tr(copy.detail) : detail.c_str());
        SetWindowTextW(label_, guide_input(step) ? (step == GuideStep::pin ? tr(L"PIN") : tr(L"Password Windows")) : label_text_.c_str());
        SetWindowTextW(status_, guide_input(step) ? label_text_.c_str() : step == GuideStep::connect || step == GuideStep::reconnect ? tr(L"In attesa della chiave…") : step == GuideStep::remove ? tr(L"In attesa della rimozione…") : step == GuideStep::touch ? tr(L"In attesa del contatto…") : step == GuideStep::checking ? tr(L"Verifica in corso…") : L"");
        SendMessageW(edit_, EM_SETLIMITTEXT, step == GuideStep::pin ? 63 : 256, 0);
        SetWindowTextW(accept_, step == GuideStep::success || step == GuideStep::error ? tr(L"Chiudi") : tr(L"Continua"));
        SetWindowTextW(cancel_, tr(L"Annulla")); SetWindowTextW(help_, tr(L"Serve aiuto?"));
        layout();
    }
    void layout() {
        RECT area{}; GetClientRect(parent_, &area); width_ = MulDiv(area.right, 96, static_cast<int>(dpi_)); height_ = MulDiv(area.bottom, 96, static_cast<int>(dpi_));
        const int left = 48, content = width_ - 96;
        const auto box = [&](HWND control, int x, int y, int w, int h) { MoveWindow(control, px(x), px(y), px(std::max(w, 1)), px(std::max(h, 1)), TRUE); };
        box(stage_, left, 29, content, 28); box(heading_, left, 97, content, 43); box(detail_, left, 151, content, step_ == GuideStep::error || step_ == GuideStep::confirm ? 205 : 58);
        box(label_, left, guide_input(step_) ? 245 : 214, content, 26);
        box(edit_, left, 280, std::min(content, 520), 40);
        box(status_, left, height_ - 130, content, 34);
        box(cancel_, left, height_ - 64, 110, 36); box(accept_, width_ - 202, height_ - 64, 154, 36); box(help_, width_ - 192, height_ - 112, 144, 32);
        ShowWindow(edit_, guide_input(step_) ? SW_SHOW : SW_HIDE);
        ShowWindow(label_, step_ == GuideStep::error || step_ == GuideStep::confirm ? SW_HIDE : SW_SHOW);
        ShowWindow(accept_, guide_acknowledgement(step_) ? SW_SHOW : SW_HIDE);
        ShowWindow(cancel_, step_ == GuideStep::success || step_ == GuideStep::error ? SW_HIDE : SW_SHOW);
        InvalidateRect(parent_, nullptr, TRUE);
    }
    void paint(HDC dc) const {
        if (guide_input(step_) || step_ == GuideStep::confirm || step_ == GuideStep::error) return;
        RECT area{px(90), px(259), px(width_ - 90), px(height_ - 155)};
        if (area.bottom > area.top) draw_guide_art(dc, area, guide_copy(step_).art);
    }
    HWND edit() const noexcept { return edit_; }
    HWND accept() const noexcept { return accept_; }
    HWND cancel() const noexcept { return cancel_; }
    HWND help() const noexcept { return help_; }
    void visible(bool value) {
        for (const auto control : controls()) ShowWindow(control, value ? SW_SHOW : SW_HIDE);
        if (value) layout();
    }
    GuideStep step() const noexcept { return step_; }
    void inline_error(const wchar_t* message) { SetWindowTextW(status_, message); SetFocus(edit_); }
    void clear_edit() noexcept { SetWindowTextW(edit_, L""); SendMessageW(edit_, EM_EMPTYUNDOBUFFER, 0, 0); }
private:
    std::array<HWND, 9> controls() const { return {stage_, heading_, detail_, label_, status_, edit_, accept_, cancel_, help_}; }
    int px(int value) const { return MulDiv(value, static_cast<int>(dpi_), 96); }
    void clear_fonts() { if (font_) DeleteObject(font_); if (title_) DeleteObject(title_); font_ = title_ = nullptr; }
    HWND parent_{}, stage_{}, heading_{}, detail_{}, label_{}, status_{}, edit_{}, accept_{}, cancel_{}, help_{};
    HFONT font_{}, title_{}; UINT dpi_{96}; int macro_{1}, width_{900}, height_{620}; bool enrollment_{true}; GuideStep step_{GuideStep::connect}; std::wstring label_text_;
};
}
