#include "hidfido/localization.hpp"
#include "hidfido/secret_dialog.hpp"
#include "hidfido/pin_text.hpp"

#include <windows.h>

#include <algorithm>
#include <functional>
#include <stdexcept>

namespace hidfido::ui {
namespace {
using hidfido::ui::tr;
using password::SecureBytes;

struct Dialog {
    const wchar_t* instructions{};
    unsigned max_units{};
    // Converts the typed text; throwing keeps the window open after a message.
    std::function<SecureBytes(SecureBytes&)> accept;
    const wchar_t* format_error{};
    HWND text{};
    HWND edit{};
    HWND ok{};
    HWND cancel{};
    HFONT font{};
    HICON large_icon{};
    HICON small_icon{};
    UINT dpi{USER_DEFAULT_SCREEN_DPI};
    SecureBytes result;
    bool done{};
    bool accepted{};
};

// Layout in 96-DPI units; every position is scaled to the window's DPI.
constexpr int client_width = 520;
constexpr int margin = 16;
constexpr int gap = 12;
constexpr int text_height = 64;
constexpr int edit_height = 26;
constexpr int button_width = 100;
constexpr int button_height = 30;
constexpr int client_height = margin + text_height + gap + edit_height + gap + 4 + button_height + margin;
constexpr DWORD window_style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU;
constexpr DWORD window_ex_style = WS_EX_TOPMOST;

int scaled(int value, UINT dpi) { return MulDiv(value, static_cast<int>(dpi), USER_DEFAULT_SCREEN_DPI); }

// The message font (Segoe UI on Windows 10/11) at the window's DPI.
void apply_font(Dialog& state) {
    NONCLIENTMETRICSW metrics{};
    metrics.cbSize = sizeof(metrics);
    if (!SystemParametersInfoForDpi(SPI_GETNONCLIENTMETRICS, sizeof(metrics), &metrics, 0, state.dpi)) return;
    const HFONT font = CreateFontIndirectW(&metrics.lfMessageFont);
    if (!font) return;
    for (const HWND child : {state.text, state.edit, state.ok, state.cancel}) {
        SendMessageW(child, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
    }
    if (state.font) DeleteObject(state.font);
    state.font = font;
}

void layout(const Dialog& state) {
    const auto s = [&](int value) { return scaled(value, state.dpi); };
    int y = margin;
    MoveWindow(state.text, s(margin), s(y), s(client_width - 2 * margin), s(text_height), TRUE);
    y += text_height + gap;
    MoveWindow(state.edit, s(margin), s(y), s(client_width - 2 * margin), s(edit_height), TRUE);
    y += edit_height + gap + 4;
    MoveWindow(state.cancel, s(client_width - margin - button_width), s(y), s(button_width), s(button_height), TRUE);
    MoveWindow(state.ok, s(client_width - margin - 2 * button_width - 8), s(y), s(button_width), s(button_height), TRUE);
}

// The executable's icon (resource 1, resources/hid-fido2.ico) at this DPI.
void apply_icons(HWND window, Dialog& state) {
    const auto instance = GetModuleHandleW(nullptr);
    const auto load = [&](int metric) {
        const int size = GetSystemMetricsForDpi(metric, state.dpi);
        return static_cast<HICON>(LoadImageW(instance, MAKEINTRESOURCEW(1), IMAGE_ICON, size, size, LR_DEFAULTCOLOR));
    };
    const HICON large = load(SM_CXICON), small = load(SM_CXSMICON);
    if (large) SendMessageW(window, WM_SETICON, ICON_BIG, reinterpret_cast<LPARAM>(large));
    if (small) SendMessageW(window, WM_SETICON, ICON_SMALL, reinterpret_cast<LPARAM>(small));
    if (large) { if (state.large_icon) DestroyIcon(state.large_icon); state.large_icon = large; }
    if (small) { if (state.small_icon) DestroyIcon(state.small_icon); state.small_icon = small; }
}

SecureBytes read_edit(HWND edit, unsigned max_units) {
    const int units = GetWindowTextLengthW(edit);
    if (units < 1 || static_cast<unsigned>(units) > max_units) throw std::runtime_error("Invalid input length.");
    SecureBytes raw(static_cast<std::size_t>(units + 1) * sizeof(wchar_t));
    auto* text = reinterpret_cast<wchar_t*>(raw.bytes().data());
    if (GetWindowTextW(edit, text, units + 1) != units) throw std::runtime_error("Cannot read input field.");
    SecureBytes typed(static_cast<std::size_t>(units) * sizeof(wchar_t));
    std::copy_n(raw.bytes().begin(), typed.size(), typed.bytes().begin());
    return typed;
}

void clear_edit(HWND edit) {
    if (edit) { SetWindowTextW(edit, L""); SendMessageW(edit, EM_EMPTYUNDOBUFFER, 0, 0); }
}

LRESULT CALLBACK dialog_window(HWND window, UINT message, WPARAM wparam, LPARAM lparam) {
    auto* state = reinterpret_cast<Dialog*>(GetWindowLongPtrW(window, GWLP_USERDATA));
    if (message == WM_NCCREATE) {
        auto* create = reinterpret_cast<CREATESTRUCTW*>(lparam);
        state = static_cast<Dialog*>(create->lpCreateParams);
        SetWindowLongPtrW(window, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(state));
    }
    if (!state) return DefWindowProcW(window, message, wparam, lparam);
    if (message == WM_CREATE) {
        state->text = CreateWindowW(L"STATIC", state->instructions, WS_CHILD | WS_VISIBLE,
                                    0, 0, 0, 0, window, nullptr, nullptr, nullptr);
        state->edit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_PASSWORD | ES_AUTOHSCROLL,
            0, 0, 0, 0, window, reinterpret_cast<HMENU>(101), nullptr, nullptr);
        SendMessageW(state->edit, EM_SETLIMITTEXT, state->max_units, 0);
        state->ok = CreateWindowW(L"BUTTON", tr(L"Continua"), WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
            0, 0, 0, 0, window, reinterpret_cast<HMENU>(IDOK), nullptr, nullptr);
        state->cancel = CreateWindowW(L"BUTTON", tr(L"Annulla"), WS_CHILD | WS_VISIBLE | WS_TABSTOP,
            0, 0, 0, 0, window, reinterpret_cast<HMENU>(IDCANCEL), nullptr, nullptr);
        state->dpi = GetDpiForWindow(window);
        apply_font(*state);
        layout(*state);
        apply_icons(window, *state);
        SetFocus(state->edit);
        return 0;
    }
    if (message == WM_DPICHANGED) {
        // Moved to a monitor with another scale: adopt Windows' suggested rect.
        state->dpi = HIWORD(wparam);
        const auto* suggested = reinterpret_cast<const RECT*>(lparam);
        SetWindowPos(window, nullptr, suggested->left, suggested->top, suggested->right - suggested->left,
                     suggested->bottom - suggested->top, SWP_NOZORDER | SWP_NOACTIVATE);
        apply_font(*state);
        layout(*state);
        apply_icons(window, *state);
        return 0;
    }
    if (message == WM_CTLCOLORSTATIC) {
        // Text on the window background instead of a grey control box.
        SetBkMode(reinterpret_cast<HDC>(wparam), TRANSPARENT);
        return reinterpret_cast<LRESULT>(GetSysColorBrush(COLOR_WINDOW));
    }
    if (message == WM_COMMAND && LOWORD(wparam) == IDOK) {
        try {
            auto typed = read_edit(state->edit, state->max_units);
            state->result = state->accept ? state->accept(typed) : std::move(typed);
            state->accepted = true;
            clear_edit(state->edit);
            DestroyWindow(window);
        } catch (...) {
            clear_edit(state->edit);
            MessageBoxW(window, state->format_error, L"HID FIDO2", MB_OK | MB_ICONERROR);
            SetFocus(state->edit);
        }
        return 0;
    }
    if (message == WM_CLOSE || (message == WM_COMMAND && LOWORD(wparam) == IDCANCEL)) {
        clear_edit(state->edit);
        DestroyWindow(window);
        return 0;
    }
    if (message == WM_DESTROY) { state->done = true; return 0; }
    return DefWindowProcW(window, message, wparam, lparam);
}

// Sizes the hidden window for its DPI and centres it on its monitor's work area.
void place(HWND window, const Dialog& state) {
    RECT frame{0, 0, scaled(client_width, state.dpi), scaled(client_height, state.dpi)};
    AdjustWindowRectExForDpi(&frame, window_style, FALSE, window_ex_style, state.dpi);
    const int width = frame.right - frame.left, height = frame.bottom - frame.top;
    MONITORINFO monitor{};
    monitor.cbSize = sizeof(monitor);
    int x = CW_USEDEFAULT, y = CW_USEDEFAULT;
    if (GetMonitorInfoW(MonitorFromWindow(window, MONITOR_DEFAULTTOPRIMARY), &monitor)) {
        const auto& area = monitor.rcWork;
        x = area.left + ((area.right - area.left) - width) / 2;
        y = area.top + ((area.bottom - area.top) - height) / 2;
    }
    SetWindowPos(window, nullptr, x, y, width, height, SWP_NOZORDER | SWP_NOACTIVATE);
}

std::optional<SecureBytes> run(const wchar_t* title, Dialog& state) {
    const auto instance = GetModuleHandleW(nullptr);
    WNDCLASSW type{};
    type.lpfnWndProc = dialog_window;
    type.hInstance = instance;
    type.lpszClassName = L"HidfidoLocalSecret";
    type.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    type.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    if (!RegisterClassW(&type) && GetLastError() != ERROR_CLASS_ALREADY_EXISTS)
        throw std::runtime_error("Cannot register input window.");
    HWND window = CreateWindowExW(window_ex_style, type.lpszClassName, title, window_style,
        CW_USEDEFAULT, CW_USEDEFAULT, 0, 0, nullptr, nullptr, instance, &state);
    if (!window) throw std::runtime_error("Cannot create input window.");
    place(window, state);
    ShowWindow(window, SW_SHOW);
    SetForegroundWindow(window);
    MSG message{};
    while (!state.done) {
        const auto status = GetMessageW(&message, nullptr, 0, 0);
        if (status <= 0) { clear_edit(state.edit); DestroyWindow(window); break; }
        if (!IsDialogMessageW(window, &message)) { TranslateMessage(&message); DispatchMessageW(&message); }
    }
    if (state.font) DeleteObject(state.font);
    if (state.large_icon) DestroyIcon(state.large_icon);
    if (state.small_icon) DestroyIcon(state.small_icon);
    if (!state.accepted) return std::nullopt;
    return std::move(state.result);
}
}

std::optional<SecureBytes> prompt_secret(const wchar_t* title, const wchar_t* instructions, unsigned max_units) {
    Dialog state;
    state.instructions = instructions;
    state.max_units = max_units;
    state.format_error = tr(L"Inserimento non valido o troppo lungo.");
    return run(title, state);
}

void disable_console_selection() noexcept {
    const HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    if (input && input != INVALID_HANDLE_VALUE && GetConsoleMode(input, &mode)) {
        SetConsoleMode(input, (mode & ~static_cast<DWORD>(ENABLE_QUICK_EDIT_MODE)) | ENABLE_EXTENDED_FLAGS);
    }
}

std::optional<SecureBytes> request_fido_pin(const wchar_t* title, const wchar_t* instructions) {
    Dialog state;
    state.instructions = instructions;
    state.max_units = 63;
    state.accept = [](SecureBytes& typed) {
        const std::span<const wchar_t> text(reinterpret_cast<const wchar_t*>(typed.bytes().data()),
                                            typed.size() / sizeof(wchar_t));
        return pin::utf8_from_typed(text);
    };
    state.format_error = tr(L"Formato PIN non valido: usare almeno 4 caratteri e massimo 63 byte UTF-8.\nNessun tentativo è stato inviato alla chiave.");
    return run(title, state);
}
}
