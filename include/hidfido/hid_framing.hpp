#pragma once

#include "hidfido/hid_transport.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

// Pure CTAPHID message framing, separated from overlapped device I/O so the
// packet rules can be tested without an authenticator. Reports include the
// leading zero report ID byte used by Windows HID (1 + 64 bytes).
namespace hidfido::ctap::hid {
using Report = std::array<std::uint8_t, 65>;
// 57 bytes in the initialization packet plus 128 continuations of 59 bytes.
constexpr std::size_t max_message = 7609;
constexpr std::uint32_t broadcast_channel = 0xffffffffu;
constexpr std::uint8_t cmd_init = 0x86, cmd_cbor = 0x90, cmd_cancel = 0x91;
constexpr std::uint8_t cmd_keepalive = 0xbb, cmd_error = 0xbf;

// Splits one request into its initialization and continuation reports.
// Throws HidTransportError for oversized messages or non-command bytes.
std::vector<Report> fragment(std::uint32_t channel, std::uint8_t command,
                             std::span<const std::uint8_t> message);

// Reassembles one response for a fixed channel and command. Reports for other
// channels are ignored; valid keepalives before the first packet are skipped.
// Throws HidTransportError on CTAPHID errors or malformed framing; the
// instance must then be discarded.
class Reassembler {
public:
    Reassembler(std::uint32_t channel, std::uint8_t expected) noexcept
        : channel_(channel), expected_(expected) {}
    // Returns the complete message once its final report has been fed.
    std::optional<Bytes> feed(const Report& report);
private:
    std::uint32_t channel_;
    std::uint8_t expected_;
    std::optional<std::size_t> length_;
    unsigned sequence_{};
    Bytes result_;
};
}
