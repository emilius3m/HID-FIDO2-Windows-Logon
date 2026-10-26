#include "hidfido/hid_framing.hpp"

#include <algorithm>
#include <string>
#include <utility>

namespace hidfido::ctap {
HidTransportError::HidTransportError(const char* operation, std::uint32_t code)
    : std::runtime_error(std::string(operation) + " (code " + std::to_string(code) + ")"), code_(code) {}
}

namespace hidfido::ctap::hid {
namespace {
using HidError = HidTransportError;

std::uint32_t be32(const std::uint8_t* data) noexcept {
    return (std::uint32_t{data[0]} << 24) | (std::uint32_t{data[1]} << 16) |
           (std::uint32_t{data[2]} << 8) | data[3];
}

void store_be32(std::uint8_t* data, std::uint32_t value) noexcept {
    for (unsigned i = 0; i < 4; ++i) data[i] = static_cast<std::uint8_t>(value >> (24 - 8 * i));
}
}

std::vector<Report> fragment(std::uint32_t channel, std::uint8_t command,
                             std::span<const std::uint8_t> message) {
    if (message.size() > max_message || (command & 0x80) == 0) throw HidError("Invalid CTAPHID request");
    std::vector<Report> reports(1);
    auto& report = reports.front();
    store_be32(report.data() + 1, channel);
    report[5] = command;
    report[6] = static_cast<std::uint8_t>(message.size() >> 8);
    report[7] = static_cast<std::uint8_t>(message.size());
    const auto first = (std::min)(message.size(), std::size_t{57});
    std::copy_n(message.begin(), first, report.begin() + 8);
    std::size_t position = first;
    unsigned sequence{};
    while (position < message.size()) {
        if (sequence > 127) throw HidError("CTAPHID request sequence exhausted");
        auto& next = reports.emplace_back();
        store_be32(next.data() + 1, channel);
        next[5] = static_cast<std::uint8_t>(sequence++);
        const auto count = (std::min)(message.size() - position, std::size_t{59});
        std::copy_n(message.begin() + position, count, next.begin() + 6);
        position += count;
    }
    return reports;
}

std::optional<Bytes> Reassembler::feed(const Report& report) {
    if (report[0] != 0) throw HidError("Unexpected FIDO HID report ID");
    if (be32(report.data() + 1) != channel_) return std::nullopt;
    if (report[5] == cmd_keepalive || report[5] == cmd_error) {
        if (report[6] != 0 || report[7] != 1) throw HidError("Invalid CTAPHID control length");
        if (report[5] == cmd_error) throw HidError("Authenticator returned a CTAPHID error", report[8]);
        if (length_ || (report[8] != 1 && report[8] != 2)) throw HidError("Invalid CTAPHID keepalive");
        return std::nullopt; // A keepalive never extends the fixed operation deadline.
    }
    if (!length_) {
        if (report[5] != expected_) throw HidError("Unexpected CTAPHID response command");
        length_ = (std::size_t{report[6]} << 8) | report[7];
        if (*length_ == 0 || *length_ > max_message) throw HidError("Invalid CTAPHID response length");
        result_.reserve(*length_);
        const auto count = (std::min)(*length_, std::size_t{57});
        result_.insert(result_.end(), report.begin() + 8, report.begin() + 8 + count);
    } else {
        if (sequence_ > 127 || report[5] != sequence_++) throw HidError("Invalid CTAPHID continuation sequence");
        const auto count = (std::min)(*length_ - result_.size(), std::size_t{59});
        result_.insert(result_.end(), report.begin() + 6, report.begin() + 6 + count);
    }
    if (result_.size() == *length_) return std::move(result_);
    return std::nullopt;
}
}
