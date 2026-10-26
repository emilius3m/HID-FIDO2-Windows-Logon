#include "hidfido/hid_transport.hpp"

#include <windows.h>
#include <atomic>
#include <chrono>
#include <iostream>
#include <stdexcept>
#include <thread>

namespace {
void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}
class Event {
public:
    Event() : handle(CreateEventW(nullptr, TRUE, FALSE, nullptr)) {
        require(handle != nullptr, "Cannot create test event");
    }
    ~Event() { CloseHandle(handle); }
    Event(const Event&) = delete;
    Event& operator=(const Event&) = delete;
    HANDLE handle;
};
}
int main() {
    try {
        Event event;
        SetEvent(event.handle);
        hidfido::ctap::detail::wait_cancellable(event.handle, 1000, {});
        ResetEvent(event.handle);
        bool timeout{};
        try { hidfido::ctap::detail::wait_cancellable(event.handle, 30, {}); }
        catch (const hidfido::ctap::HidTransportError& error) { timeout = error.code() == ERROR_TIMEOUT; }
        require(timeout, "Unsignalled event must time out");
        std::atomic_bool cancelled{};
        std::jthread signal([&] { Sleep(25); cancelled = true; });
        bool stopped{};
        const auto start = GetTickCount64();
        try { hidfido::ctap::detail::wait_cancellable(event.handle, 5000, [&] { return !cancelled.load(); }); }
        catch (const hidfido::ctap::HidTransportError& error) { stopped = error.code() == ERROR_CANCELLED; }
        signal.join();
        require(stopped && GetTickCount64() - start < 400, "Cancellation was not polled promptly");
        require(GetTickCount64() - start >= 25, "Cancellation test did not actually wait");
        std::jthread complete([&] { Sleep(25); SetEvent(event.handle); });
        hidfido::ctap::detail::wait_cancellable(event.handle, 1000, [] { return true; });
        complete.join();
        // Cancellation wins even if the I/O event was already signalled, so a
        // cancelled operation cannot return credential material to its caller.
        stopped = false;
        try { hidfido::ctap::detail::wait_cancellable(event.handle, 1000, [] { return false; }); }
        catch (const hidfido::ctap::HidTransportError& error) { stopped = error.code() == ERROR_CANCELLED; }
        require(stopped, "Cancellation ignored for completed event");
        std::cout << "HID cancellation wait: success, timeout and prompt cancellation passed (no hardware).\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
