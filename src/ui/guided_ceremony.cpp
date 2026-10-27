#include "hidfido/guided_ceremony.hpp"
#include "hidfido/pin_text.hpp"
#include <atomic>
#include <condition_variable>
#include <mutex>
#include <thread>

namespace hidfido::ui {
struct GuidedCeremony::Impl {
    struct Request { GuideStep step{GuideStep::connect}; std::wstring label, detail, heading; unsigned long long sequence{}; bool input{}, acknowledge{}; };
    static constexpr UINT update = WM_APP + 72, finish = WM_APP + 73;
    std::mutex mutex; std::condition_variable changed;
    std::atomic<HWND> window{}; std::atomic_bool cancelled{}, closing{};
    bool ready{}, failed{}, answered{}, hidden{}; unsigned long long shown{}; Request request;
    password::SecureBytes result;
    GuidanceView view; int macro; bool enrollment; std::thread thread;
    explicit Impl(int phase, bool enrolling) : macro(phase), enrollment(enrolling) {}
    void cancel() noexcept { cancelled.store(true); changed.notify_all(); }
    void accept() {
        std::unique_lock lock(mutex);
        if (shown != request.sequence || answered || cancelled.load()) return;
        if (request.input) {
            const auto units = GetWindowTextLengthW(view.edit());
            const auto maximum = request.step == GuideStep::pin ? 63 : 256;
            if (units < 1 || units > maximum) { view.inline_error(tr(L"Inserisci un valore valido.")); return; }
            password::SecureBytes text(static_cast<std::size_t>(units + 1) * sizeof(wchar_t));
            if (GetWindowTextW(view.edit(), reinterpret_cast<wchar_t*>(text.bytes().data()), units + 1) != units) throw std::runtime_error("Cannot read local secret");
            try {
                if (request.step == GuideStep::pin) result = pin::utf8_from_typed({reinterpret_cast<const wchar_t*>(text.bytes().data()), static_cast<std::size_t>(units)});
                else { result = password::SecureBytes(static_cast<std::size_t>(units) * sizeof(wchar_t)); std::copy_n(text.bytes().begin(), result.size(), result.bytes().begin()); }
            } catch (...) { view.clear_edit(); view.inline_error(tr(L"Formato PIN non valido. Nessun tentativo inviato.")); return; }
            text.clear(); view.clear_edit();
        } else if (!request.acknowledge) return;
        answered = true; EnableWindow(view.accept(), FALSE); changed.notify_all();
    }
    void refresh() {
        std::lock_guard lock(mutex); view.clear_edit();
        view.show(request.step, request.label, request.detail, request.heading); shown = request.sequence;
        EnableWindow(view.edit(), request.input && !cancelled.load()); EnableWindow(view.accept(), !cancelled.load());
        if (request.input) SetFocus(view.edit()); else if (request.acknowledge) SetFocus(view.accept()); else SetFocus(view.cancel());
    }
    static LRESULT CALLBACK procedure(HWND hwnd, UINT message, WPARAM w, LPARAM l) {
        auto* self = reinterpret_cast<Impl*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
        if (message == WM_NCCREATE) { self = static_cast<Impl*>(reinterpret_cast<CREATESTRUCTW*>(l)->lpCreateParams); SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self)); self->window.store(hwnd); }
        if (!self) return DefWindowProcW(hwnd, message, w, l);
        try {
            switch (message) {
            case WM_CREATE: self->view.create(hwnd, self->macro, self->enrollment); return 0;
            case update: self->refresh(); return 0;
            case finish: self->view.clear_edit(); DestroyWindow(hwnd); return 0;
#ifdef HIDFIDO_GUIDED_TESTING
            case WM_APP + 74: { std::lock_guard lock(self->mutex); return self->shown == self->request.sequence && !self->answered && !self->cancelled.load() ? static_cast<LRESULT>(self->view.step()) : -1; }
            case WM_APP + 75: SetWindowTextW(self->view.edit(), reinterpret_cast<const wchar_t*>(l)); self->accept(); return 0;
            case WM_APP + 76: return GetWindowTextLengthW(self->view.edit());
#endif
            case WM_SIZE: self->view.layout(); return 0;
            case WM_GETMINMAXINFO: { const auto dpi = GetDpiForWindow(hwnd); RECT bounds{0, 0, MulDiv(760, dpi, 96), MulDiv(550, dpi, 96)}; AdjustWindowRectExForDpi(&bounds, WS_OVERLAPPEDWINDOW, FALSE, 0, dpi); reinterpret_cast<MINMAXINFO*>(l)->ptMinTrackSize = {bounds.right - bounds.left, bounds.bottom - bounds.top}; return 0; }
            case WM_DPICHANGED: { const auto* bounds = reinterpret_cast<RECT*>(l); SetWindowPos(hwnd, nullptr, bounds->left, bounds->top, bounds->right - bounds->left, bounds->bottom - bounds->top, SWP_NOZORDER); self->view.fonts(); self->view.layout(); return 0; }
            case WM_COMMAND:
                if (LOWORD(w) == GuidanceView::accept_id) self->accept();
                else if (LOWORD(w) == GuidanceView::cancel_id) { self->view.clear_edit(); self->cancel(); EnableWindow(self->view.cancel(), FALSE); self->view.inline_error(tr(L"Annullamento in corso…")); }
                else if (LOWORD(w) == GuidanceView::help_id) MessageBoxW(hwnd, tr(L"Segui un passaggio alla volta. Usa il PIN della chiave e tocca il sensore solo quando richiesto. Puoi annullare e usare la password Windows."), L"HID FIDO2", MB_OK | MB_ICONINFORMATION);
                return 0;
            case WM_CLOSE: self->view.clear_edit(); self->cancel(); EnableWindow(self->view.cancel(), FALSE); return 0;
            case WM_DRAWITEM: draw_guide_button(*reinterpret_cast<DRAWITEMSTRUCT*>(l), w == GuidanceView::accept_id, w == GuidanceView::help_id); return TRUE;
            case WM_CTLCOLORSTATIC: SetBkMode(reinterpret_cast<HDC>(w), TRANSPARENT); SetTextColor(reinterpret_cast<HDC>(w), RGB(35, 43, 55)); return reinterpret_cast<LRESULT>(GetStockObject(WHITE_BRUSH));
            case WM_PAINT: { PAINTSTRUCT paint{}; const auto dc = BeginPaint(hwnd, &paint); self->view.paint(dc); EndPaint(hwnd, &paint); return 0; }
            case WM_DESTROY: self->cancel(); self->window.store(nullptr); PostQuitMessage(0); return 0;
            }
        } catch (...) { { std::lock_guard lock(self->mutex); self->failed = true; } self->cancel(); DestroyWindow(hwnd); }
        return DefWindowProcW(hwnd, message, w, l);
    }
    void run() noexcept {
        try {
            const auto instance = GetModuleHandleW(nullptr); WNDCLASSW type{};
            type.hInstance = instance; type.lpfnWndProc = procedure; type.lpszClassName = L"HidfidoGuidedCeremony"; type.hCursor = LoadCursorW(nullptr, IDC_ARROW); type.hIcon = LoadIconW(instance, MAKEINTRESOURCEW(1)); type.hbrBackground = reinterpret_cast<HBRUSH>(GetStockObject(WHITE_BRUSH));
            if (!RegisterClassW(&type) && GetLastError() != ERROR_CLASS_ALREADY_EXISTS) throw std::runtime_error("Cannot register ceremony window");
            const auto dpi = GetDpiForSystem(); RECT bounds{0, 0, MulDiv(900, dpi, 96), MulDiv(620, dpi, 96)}, work{};
            AdjustWindowRectExForDpi(&bounds, WS_OVERLAPPEDWINDOW, FALSE, 0, dpi); SystemParametersInfoW(SPI_GETWORKAREA, 0, &work, 0);
            const int width = std::min(bounds.right - bounds.left, work.right - work.left), height = std::min(bounds.bottom - bounds.top, work.bottom - work.top);
            const auto hwnd = CreateWindowExW(0, type.lpszClassName, L"HID FIDO2", WS_OVERLAPPEDWINDOW, work.left + (work.right - work.left - width) / 2, work.top + (work.bottom - work.top - height) / 2, width, height, nullptr, nullptr, instance, this);
            if (!hwnd) throw std::runtime_error("Cannot create ceremony window");
            if (!hidden) { ShowWindow(hwnd, SW_SHOW); SetForegroundWindow(hwnd); }
            { std::lock_guard lock(mutex); ready = true; } changed.notify_all();
            MSG message{};
            while (GetMessageW(&message, nullptr, 0, 0) > 0) {
                if (message.message == WM_KEYDOWN && message.wParam == VK_ESCAPE) { SendMessageW(hwnd, WM_COMMAND, GuidanceView::cancel_id, 0); continue; }
                if (message.message == WM_KEYDOWN && message.wParam == VK_RETURN) { SendMessageW(hwnd, WM_COMMAND, GuidanceView::accept_id, 0); continue; }
                if (!IsDialogMessageW(hwnd, &message)) { TranslateMessage(&message); DispatchMessageW(&message); }
            }
        } catch (...) { std::lock_guard lock(mutex); failed = true; }
        { std::lock_guard lock(mutex); ready = true; } cancel(); changed.notify_all();
    }
    void send(GuideStep step, std::wstring label, std::wstring detail, std::wstring heading, bool input, bool acknowledgement) {
        { std::lock_guard lock(mutex); if (cancelled.load()) return; request = {step, std::move(label), std::move(detail), std::move(heading), request.sequence + 1, input, acknowledgement}; answered = false; result.clear(); }
        if (!PostMessageW(window.load(), update, 0, 0)) cancel();
    }
    bool wait() { std::unique_lock lock(mutex); changed.wait(lock, [&] { return answered || cancelled.load() || failed; }); return answered && !cancelled.load() && !failed; }
};
GuidedCeremony::GuidedCeremony(int macro, bool enrollment) : impl_(std::make_unique<Impl>(macro, enrollment)) { start(); }
void GuidedCeremony::start() {
    impl_->thread = std::thread([this] { impl_->run(); });
    std::unique_lock lock(impl_->mutex); impl_->changed.wait(lock, [&] { return impl_->ready; }); const bool failed = impl_->failed; lock.unlock();
    if (failed) { if (impl_->thread.joinable()) impl_->thread.join(); throw std::runtime_error("Cannot start guided ceremony"); }
}
GuidedCeremony::~GuidedCeremony() {
    impl_->closing.store(true); if (const auto window = impl_->window.load()) PostMessageW(window, Impl::finish, 0, 0);
    impl_->cancel(); if (impl_->thread.joinable()) impl_->thread.join();
}
void GuidedCeremony::show(GuideStep step, std::wstring label, std::wstring detail, std::wstring heading) {
    if (guide_input(step)) throw std::invalid_argument("Secret input requires the local secret method");
    impl_->send(step, std::move(label), std::move(detail), std::move(heading), false, false);
}
bool GuidedCeremony::acknowledge(GuideStep step, std::wstring label, std::wstring detail, std::wstring heading) {
    if (!guide_acknowledgement(step) || guide_input(step)) throw std::invalid_argument("This step cannot be manually acknowledged");
    impl_->send(step, std::move(label), std::move(detail), std::move(heading), false, true); return impl_->wait();
}
std::optional<password::SecureBytes> GuidedCeremony::secret(GuideStep step, std::wstring label) {
    if (!guide_input(step)) throw std::invalid_argument("Not a secret-input step");
    impl_->send(step, std::move(label), {}, {}, true, true); if (!impl_->wait()) return {};
    std::lock_guard lock(impl_->mutex); return std::move(impl_->result);
}
bool GuidedCeremony::cancelled() const noexcept { return impl_->cancelled.load(); }
#ifdef HIDFIDO_GUIDED_TESTING
GuidedCeremony::GuidedCeremony(int macro, bool enrollment, bool hidden) : impl_(std::make_unique<Impl>(macro, enrollment)) { impl_->hidden = hidden; start(); }
std::optional<GuideStep> GuidedCeremony::test_ready_step() { const auto step = SendMessageW(impl_->window.load(), WM_APP + 74, 0, 0); if (step < 0) return {}; return static_cast<GuideStep>(step); }
void GuidedCeremony::test_submit(std::wstring_view value) { const std::wstring text(value); SendMessageW(impl_->window.load(), WM_APP + 75, 0, reinterpret_cast<LPARAM>(text.c_str())); }
void GuidedCeremony::test_cancel() { SendMessageW(impl_->window.load(), WM_CLOSE, 0, 0); }
unsigned GuidedCeremony::test_input_units() { return static_cast<unsigned>(SendMessageW(impl_->window.load(), WM_APP + 76, 0, 0)); }
#endif
}
