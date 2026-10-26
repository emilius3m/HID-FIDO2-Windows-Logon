#include "hidfido/hid_framing.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <setupapi.h>
#include <hidsdi.h>
#include <hidpi.h>
#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <cwctype>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <utility>

namespace hidfido::ctap {
namespace detail {
void wait_cancellable(void* event, std::uint32_t timeout_ms,
                      const ContinueCheck& keep_going) {
    const auto deadline = GetTickCount64() + timeout_ms;
    for (;;) {
        if (keep_going && !keep_going()) {
            throw HidTransportError("FIDO HID operation cancelled", ERROR_CANCELLED);
        }
        const auto now = GetTickCount64();
        if (now >= deadline) throw HidTransportError("FIDO HID I/O wait timed out", ERROR_TIMEOUT);
        const auto slice = static_cast<DWORD>((std::min)(ULONGLONG{100}, deadline - now));
        const auto result = WaitForSingleObject(event, slice);
        if (result == WAIT_OBJECT_0) return;
        if (result != WAIT_TIMEOUT) throw HidTransportError("FIDO HID I/O wait failed", GetLastError());
    }
}
}
namespace {
using namespace hid;
using HidError = HidTransportError;

class Handle {
public:
    explicit Handle(HANDLE value = INVALID_HANDLE_VALUE) noexcept : value_(value) {}
    ~Handle() { if (valid()) CloseHandle(value_); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    bool valid() const noexcept { return value_ && value_ != INVALID_HANDLE_VALUE; }
    HANDLE get() const noexcept { return value_; }
private:
    HANDLE value_;
};

class DeviceSet {
public:
    explicit DeviceSet(const GUID& guid)
        : value(SetupDiGetClassDevsW(&guid, nullptr, nullptr, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE)) {}
    ~DeviceSet() { if (value != INVALID_HANDLE_VALUE) SetupDiDestroyDeviceInfoList(value); }
    DeviceSet(const DeviceSet&) = delete;
    DeviceSet& operator=(const DeviceSet&) = delete;
    HDEVINFO value;
};

std::wstring hardware_ids(HDEVINFO set, SP_DEVINFO_DATA& device) {
    DWORD count{};
    SetupDiGetDeviceRegistryPropertyW(set, &device, SPDRP_HARDWAREID, nullptr, nullptr, 0, &count);
    if (count == 0 || count > 65536 || count % sizeof(wchar_t) != 0) return {};
    std::vector<wchar_t> value(count / sizeof(wchar_t) + 2, 0);
    if (!SetupDiGetDeviceRegistryPropertyW(set, &device, SPDRP_HARDWAREID, nullptr,
          reinterpret_cast<BYTE*>(value.data()), count, nullptr)) return {};
    return {value.data(), count / sizeof(wchar_t)};
}

bool valid_caps(HANDLE handle) {
    PHIDP_PREPARSED_DATA preparsed{};
    if (!HidD_GetPreparsedData(handle, &preparsed)) return false;
    HIDP_CAPS caps{};
    const auto status = HidP_GetCaps(preparsed, &caps);
    HidD_FreePreparsedData(preparsed);
    return status == HIDP_STATUS_SUCCESS && caps.UsagePage == 0xf1d0 && caps.Usage == 1 &&
           caps.InputReportByteLength == 65 && caps.OutputReportByteLength == 65;
}

DWORD remaining(ULONGLONG deadline) {
    const auto now = GetTickCount64();
    if (now >= deadline) throw HidError("FIDO HID operation timed out", ERROR_TIMEOUT);
    return static_cast<DWORD>(deadline - now);
}

void cancel_and_drain(HANDLE handle, OVERLAPPED& operation) noexcept {
    // OVERLAPPED, report and event storage must remain alive until the driver
    // acknowledges cancellation or completion, including exceptional paths.
    CancelIoEx(handle, &operation);
    DWORD transferred{};
    GetOverlappedResult(handle, &operation, &transferred, TRUE);
}

void check_continue(const ContinueCheck& keep_going) {
    if (keep_going && !keep_going()) throw HidError("FIDO HID operation cancelled", ERROR_CANCELLED);
}

void transfer(HANDLE handle, Report& report, bool write, ULONGLONG deadline,
              const ContinueCheck& keep_going = {}) {
    Handle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!event.valid()) throw HidError("Cannot allocate FIDO HID I/O event", GetLastError());
    (void)remaining(deadline);
    check_continue(keep_going);
    OVERLAPPED operation{};
    operation.hEvent = event.get();
    const auto size = static_cast<DWORD>(report.size());
    const BOOL complete = write ? WriteFile(handle, report.data(), size, nullptr, &operation)
                                : ReadFile(handle, report.data(), size, nullptr, &operation);
    if (!complete) {
        const auto error = GetLastError();
        if (error != ERROR_IO_PENDING) throw HidError("FIDO HID I/O submission failed", error);
        try { detail::wait_cancellable(event.get(), remaining(deadline), keep_going); }
        catch (...) {
            cancel_and_drain(handle, operation);
            throw;
        }
    }
    DWORD transferred{};
    if (!GetOverlappedResult(handle, &operation, &transferred, FALSE)) {
        const auto error = GetLastError();
        cancel_and_drain(handle, operation);
        throw HidError("FIDO HID I/O completion failed", error);
    }
    if (transferred != size) throw HidError("Unexpected FIDO HID report size");
}

void send(HANDLE handle, std::uint32_t channel, std::uint8_t command,
          std::span<const std::uint8_t> message, ULONGLONG deadline,
          const ContinueCheck& keep_going = {}) {
    for (auto& report : fragment(channel, command, message)) transfer(handle, report, true, deadline, keep_going);
}

Bytes receive(HANDLE handle, std::uint32_t channel, std::uint8_t expected, ULONGLONG deadline,
               const ContinueCheck& keep_going = {}) {
    Reassembler reassembler(channel, expected);
    for (;;) {
        Report report{};
        transfer(handle, report, false, deadline, keep_going);
        if (auto message = reassembler.feed(report)) return std::move(*message);
    }
}

std::uint32_t initialize_channel(HANDLE handle, std::chrono::milliseconds timeout,
                                 const ContinueCheck& keep_going) {
    std::array<std::uint8_t, 8> nonce{};
    if (BCryptGenRandom(nullptr, nonce.data(), static_cast<ULONG>(nonce.size()),
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) throw HidError("FIDO HID nonce generation failed");
    // INIT answers within milliseconds; a stalled one is retried by the caller
    // instead of waiting out the authenticator's touch window.
    const auto duration = (std::min)(timeout, std::chrono::milliseconds{3000});
    const auto deadline = GetTickCount64() + static_cast<ULONGLONG>(duration.count());
    send(handle, broadcast_channel, cmd_init, nonce, deadline, keep_going);
    for (;;) {
        const auto init = receive(handle, broadcast_channel, cmd_init, deadline, keep_going);
        if (init.size() < nonce.size()) throw HidError("Truncated CTAPHID INIT response");
        if (!std::equal(nonce.begin(), nonce.end(), init.begin())) continue;
        if (init.size() < 17) throw HidError("Invalid CTAPHID INIT response");
        const auto channel = (std::uint32_t{init[8]} << 24) | (std::uint32_t{init[9]} << 16) |
                             (std::uint32_t{init[10]} << 8) | init[11];
        if (channel == 0 || channel == broadcast_channel || (init[16] & 0x04) == 0) {
            throw HidError("Authenticator does not support a usable CTAPHID CBOR channel", ERROR_NOT_SUPPORTED);
        }
        return channel;
    }
}

// The Crescendo key was observed to occasionally drop the first exchange on a
// handle reopened shortly after a touch-confirmed operation. A read-only
// getInfo with a short deadline proves that the new channel answers CBOR
// before any PIN or credential command is sent on it.
void probe_channel(HANDLE handle, std::uint32_t channel, std::chrono::milliseconds timeout,
                    const ContinueCheck& keep_going) {
    constexpr std::array<std::uint8_t, 1> get_info{0x04};
    const auto duration = (std::min)(timeout, std::chrono::milliseconds{3000});
    const auto deadline = GetTickCount64() + static_cast<ULONGLONG>(duration.count());
    Bytes response;
    try {
        send(handle, channel, cmd_cbor, get_info, deadline, keep_going);
        response = receive(handle, channel, cmd_cbor, deadline, keep_going);
    } catch (const HidError& error) {
        throw HidError("FIDO HID channel probe failed", error.code());
    }
    if (response.empty() || response[0] != 0) throw HidError("FIDO HID channel probe was rejected");
}
}

std::vector<HidDeviceInfo> enumerate_fido_hid() {
    GUID guid{};
    HidD_GetHidGuid(&guid);
    DeviceSet set(guid);
    if (set.value == INVALID_HANDLE_VALUE) throw HidError("Cannot enumerate HID interfaces", GetLastError());
    std::vector<HidDeviceInfo> result;
    for (DWORD index = 0;; ++index) {
        SP_DEVICE_INTERFACE_DATA interface_data{sizeof(SP_DEVICE_INTERFACE_DATA)};
        if (!SetupDiEnumDeviceInterfaces(set.value, nullptr, &guid, index, &interface_data)) {
            if (GetLastError() != ERROR_NO_MORE_ITEMS) throw HidError("HID enumeration is incomplete", GetLastError());
            break;
        }
        DWORD size{};
        SetupDiGetDeviceInterfaceDetailW(set.value, &interface_data, nullptr, 0, &size, nullptr);
        if (size < sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W) || size > 65536) continue;
        Bytes buffer(size, 0);
        auto* detail = reinterpret_cast<SP_DEVICE_INTERFACE_DETAIL_DATA_W*>(buffer.data());
        detail->cbSize = sizeof(*detail);
        SP_DEVINFO_DATA device{sizeof(SP_DEVINFO_DATA)};
        if (!SetupDiGetDeviceInterfaceDetailW(set.value, &interface_data, detail, size, nullptr, &device)) continue;
        auto ids = hardware_ids(set.value, device);
        std::transform(ids.begin(), ids.end(), ids.begin(), [](wchar_t c) { return static_cast<wchar_t>(std::towupper(c)); });
        if (ids.find(L"UP:F1D0_U:0001") == std::wstring::npos) continue;
        Handle handle(CreateFileW(detail->DevicePath, 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                  nullptr, OPEN_EXISTING, 0, nullptr));
        if (!handle.valid() || !valid_caps(handle.get())) continue;
        HIDD_ATTRIBUTES attributes{sizeof(HIDD_ATTRIBUTES)};
        if (!HidD_GetAttributes(handle.get(), &attributes)) continue;
        result.push_back({detail->DevicePath, attributes.VendorID, attributes.ProductID});
    }
    return result;
}

struct HidTransport::Impl {
    Handle handle;
    std::chrono::milliseconds timeout;
    ContinueCheck keep_going;
    std::uint32_t channel{};
    bool poisoned{};
    std::mutex mutex;
    Impl(const HidDeviceInfo& device, std::chrono::milliseconds operation_timeout, ContinueCheck check)
        : handle(CreateFileW(device.path.c_str(), GENERIC_READ | GENERIC_WRITE,
                 FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr)),
          timeout(operation_timeout), keep_going(std::move(check)) {
        if (!handle.valid()) {
            throw HidError("Cannot open FIDO HID for direct CTAP access; administrator elevation may be required", GetLastError());
        }
        HIDD_ATTRIBUTES attributes{sizeof(HIDD_ATTRIBUTES)};
        if (!HidD_GetAttributes(handle.get(), &attributes) || !valid_caps(handle.get()) ||
            attributes.VendorID != device.vid || attributes.ProductID != device.pid) {
            throw HidError("Selected FIDO HID interface identity or report layout changed");
        }
        channel = initialize_channel(handle.get(), timeout, keep_going);
        try { probe_channel(handle.get(), channel, timeout, keep_going); }
        catch (...) { abort(); throw; }
    }
    void abort() noexcept {
        poisoned = true;
        try {
            const auto deadline = GetTickCount64() + 1000;
            send(handle.get(), channel, cmd_cancel, {}, deadline);
            // Discard the pending CBOR cancellation response. Any timeout still
            // cancels and drains the overlapped read before its storage dies.
            (void)receive(handle.get(), channel, cmd_cbor, deadline);
        } catch (...) {}
    }
};

HidTransport::HidTransport(const HidDeviceInfo& device, std::chrono::milliseconds timeout,
                             ContinueCheck keep_going) {
    if (timeout.count() <= 0 || timeout > std::chrono::minutes{5}) {
        throw std::invalid_argument("FIDO HID timeout must be positive and at most five minutes");
    }
    if (device.path.empty() || device.path.size() > 32767 || device.path.find(L'\0') != std::wstring::npos) {
        throw std::invalid_argument("Invalid FIDO HID interface target");
    }
    check_continue(keep_going);
    impl_ = std::make_unique<Impl>(device, timeout, std::move(keep_going));
}

HidTransport::~HidTransport() = default;

std::unique_ptr<HidTransport> open_hid_transport(const HidDeviceInfo& device,
                                                 std::chrono::milliseconds timeout, unsigned attempts,
                                                 ContinueCheck keep_going) {
    if (attempts == 0 || attempts > 5) throw std::invalid_argument("FIDO HID open attempts must be 1 to 5");
    for (unsigned attempt = 1;; ++attempt) {
        try {
            check_continue(keep_going);
            return std::make_unique<HidTransport>(device, timeout, keep_going);
        } catch (const HidError& error) {
            const auto code = error.code();
            if (attempt == attempts || (code != ERROR_TIMEOUT && code != ERROR_NOT_READY)) throw;
            for (unsigned slice = 0; slice < 5; ++slice) { check_continue(keep_going); Sleep(100); }
        }
    }
}

Bytes HidTransport::transact(std::span<const std::uint8_t> command) {
    if (command.empty() || command.size() > max_message ||
        (command[0] != 0x01 && command[0] != 0x02 && command[0] != 0x04 && command[0] != 0x06)) {
        throw std::invalid_argument("CTAP command is outside this transport's allowed operations");
    }
    std::scoped_lock lock(impl_->mutex);
    if (impl_->poisoned) throw std::runtime_error("FIDO HID transaction failed previously; explicitly reconnect the authenticator");
    const auto deadline = GetTickCount64() + static_cast<ULONGLONG>(impl_->timeout.count());
    try {
        send(impl_->handle.get(), impl_->channel, cmd_cbor, command, deadline, impl_->keep_going);
        return receive(impl_->handle.get(), impl_->channel, cmd_cbor, deadline, impl_->keep_going);
    } catch (...) {
        impl_->abort();
        throw;
    }
}
}
