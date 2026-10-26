#pragma once

#include "hidfido/ctap_client.hpp"

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace hidfido::ctap {
// Returning false cancels the current operation. Called at least every 100 ms
// during asynchronous HID waits; no callback means continue until the deadline.
using ContinueCheck = std::function<bool()>;
class HidTransportError : public std::runtime_error {
public:
    // 13 is Win32 ERROR_INVALID_DATA. The code is public metadata, not payload.
    explicit HidTransportError(const char* operation, std::uint32_t code = 13);
    std::uint32_t code() const noexcept { return code_; }
private:
    std::uint32_t code_;
};
// The device path is an opaque local handle target. Callers must not print or
// persist it: Windows paths can contain device-instance identifying material.
struct HidDeviceInfo {
    std::wstring path;
    std::uint16_t vid{}, pid{};
};

// Enumerates FIDO usage-page 0xF1D0 / usage 1 interfaces using metadata only.
// Opens no FIDO transaction and reads no serial number or product strings.
std::vector<HidDeviceInfo> enumerate_fido_hid();

// Synchronous, bounded CTAPHID transport. Opens and validates the selected
// interface, establishes a fresh random channel (INIT, 3 s limit), proves it
// answers with a read-only getInfo (3 s limit), and permits only CTAP
// makeCredential/getAssertion/getInfo/clientPIN commands (01/02/04/06).
// Construction sends no PIN or credential data: a caller may construct a new
// instance after an ERROR_TIMEOUT failure (1460) of INIT or the getInfo probe.
// The transport never retries any command. A transaction failure poisons this
// instance after best-effort CTAPHID_CANCEL; reconnect explicitly with a new
// instance rather than resubmitting a PIN request automatically.
class HidTransport final : public Transport {
public:
    explicit HidTransport(const HidDeviceInfo& device,
                          std::chrono::milliseconds timeout = std::chrono::milliseconds{90000},
                          ContinueCheck keep_going = {});
    ~HidTransport() override;
    HidTransport(const HidTransport&) = delete;
    HidTransport& operator=(const HidTransport&) = delete;
    Bytes transact(std::span<const std::uint8_t> command) override;
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// Constructs a transport, retrying construction up to `attempts` times only
// when INIT or the getInfo probe times out or the device is not yet ready.
// No PIN or credential data is involved in these attempts.
std::unique_ptr<HidTransport> open_hid_transport(
    const HidDeviceInfo& device,
    std::chrono::milliseconds timeout = std::chrono::milliseconds{90000},
    unsigned attempts = 3, ContinueCheck keep_going = {});

namespace detail {
// Internal Windows event wait, exposed for cancellation tests without a key.
// Throws HidTransportError(ERROR_CANCELLED/ERROR_TIMEOUT) as appropriate.
void wait_cancellable(void* event, std::uint32_t timeout_ms,
                      const ContinueCheck& keep_going);
}
}
