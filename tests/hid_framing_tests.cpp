#include "hidfido/hid_framing.hpp"
#include "hidfido/hid_transport.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <exception>
#include <iostream>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace {
using hidfido::Bytes;
using hidfido::ctap::HidTransportError;
namespace hid = hidfido::ctap::hid;
using hid::Report;

constexpr std::uint32_t channel = 0x11223344u;

void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

template<class Action> void rejects(Action&& action, std::string_view reason, std::uint32_t code = 13) {
    bool rejected{};
    try { action(); }
    catch (const HidTransportError& error) {
        rejected = true;
        require(std::string_view(error.what()).find(reason) != std::string_view::npos,
                "Framing failure had an unexpected reason");
        require(error.code() == code, "Framing failure had an unexpected code");
    }
    require(rejected, "Malformed CTAPHID framing was accepted");
}

template<class Action> void invalid_argument(Action&& action) {
    bool rejected{};
    try { action(); } catch (const std::invalid_argument&) { rejected = true; }
    require(rejected, "Invalid transport argument was accepted");
}

Bytes pattern(std::size_t size) {
    Bytes data(size);
    for (std::size_t i = 0; i < size; ++i) data[i] = static_cast<std::uint8_t>(i * 7 + 3);
    return data;
}

bool has_channel(const Report& report, std::uint32_t value) {
    return report[1] == (value >> 24) && report[2] == ((value >> 16) & 0xff) &&
           report[3] == ((value >> 8) & 0xff) && report[4] == (value & 0xff);
}

Report header(std::uint32_t target, std::uint8_t command, std::size_t length) {
    Report report{};
    report[1] = static_cast<std::uint8_t>(target >> 24);
    report[2] = static_cast<std::uint8_t>(target >> 16);
    report[3] = static_cast<std::uint8_t>(target >> 8);
    report[4] = static_cast<std::uint8_t>(target);
    report[5] = command;
    report[6] = static_cast<std::uint8_t>(length >> 8);
    report[7] = static_cast<std::uint8_t>(length);
    return report;
}

Report control(std::uint8_t command, std::uint8_t value, std::uint32_t target = channel) {
    auto report = header(target, command, 1);
    report[8] = value;
    return report;
}

Bytes reassemble(const std::vector<Report>& reports, std::uint8_t expected = hid::cmd_cbor) {
    hid::Reassembler reassembler(channel, expected);
    for (std::size_t i = 0; i < reports.size(); ++i) {
        auto message = reassembler.feed(reports[i]);
        if (message) {
            require(i + 1 == reports.size(), "Message completed before its final report");
            return *message;
        }
    }
    throw std::runtime_error("Message did not complete");
}

void fragmentation() {
    const auto empty = hid::fragment(channel, hid::cmd_cancel, {});
    require(empty.size() == 1, "Empty request must use one report");
    require(empty[0][0] == 0 && has_channel(empty[0], channel) && empty[0][5] == hid::cmd_cancel &&
            empty[0][6] == 0 && empty[0][7] == 0, "Empty request header is wrong");
    require(std::all_of(empty[0].begin() + 8, empty[0].end(), [](auto b) { return b == 0; }),
            "Empty request must be zero padded");

    const auto single = pattern(57);
    const auto one = hid::fragment(channel, hid::cmd_cbor, single);
    require(one.size() == 1, "57 bytes must fit the initialization report");
    require(std::equal(single.begin(), single.end(), one[0].begin() + 8), "Initialization payload is wrong");

    const auto split = pattern(58);
    const auto two = hid::fragment(channel, hid::cmd_cbor, split);
    require(two.size() == 2, "58 bytes require one continuation");
    require(two[0][6] == 0 && two[0][7] == 58, "Big-endian length is wrong");
    require(two[1][0] == 0 && has_channel(two[1], channel) && two[1][5] == 0 && two[1][6] == split[57],
            "First continuation header is wrong");
    require(std::all_of(two[1].begin() + 7, two[1].end(), [](auto b) { return b == 0; }),
            "Continuation must be zero padded");

    const auto large = pattern(1000);
    const auto many = hid::fragment(channel, hid::cmd_cbor, large);
    require(many.size() == 1 + (1000 - 57 + 58) / 59, "Continuation count is wrong");
    require(many[0][6] == 0x03 && many[0][7] == 0xe8, "Length above 255 is wrong");
    for (std::size_t i = 1; i < many.size(); ++i) {
        require(many[i][5] == i - 1, "Continuation sequence is not consecutive");
    }

    const auto maximum = pattern(hid::max_message);
    const auto full = hid::fragment(channel, hid::cmd_cbor, maximum);
    require(full.size() == 129 && full.back()[5] == 127, "Maximum message must use sequence 0..127");

    const auto oversized = pattern(hid::max_message + 1);
    rejects([&] { (void)hid::fragment(channel, hid::cmd_cbor, oversized); }, "Invalid CTAPHID request");
    rejects([&] { (void)hid::fragment(channel, 0x10, single); }, "Invalid CTAPHID request");
}

void round_trips() {
    for (std::size_t size : {std::size_t{1}, std::size_t{56}, std::size_t{57}, std::size_t{58},
                             std::size_t{116}, std::size_t{117}, std::size_t{4096}, hid::max_message}) {
        const auto message = pattern(size);
        require(reassemble(hid::fragment(channel, hid::cmd_cbor, message)) == message,
                "Fragment/reassemble round trip changed the message");
    }
    const auto nonce = pattern(8);
    require(reassemble(hid::fragment(channel, hid::cmd_init, nonce), hid::cmd_init) == nonce,
            "INIT round trip changed the message");
}

void interleaving() {
    const auto message = pattern(200);
    auto reports = hid::fragment(channel, hid::cmd_cbor, message);
    hid::Reassembler reassembler(channel, hid::cmd_cbor);
    require(!reassembler.feed(control(hid::cmd_keepalive, 1)), "Keepalive must not complete");
    require(!reassembler.feed(control(hid::cmd_keepalive, 2)), "UP-needed keepalive must not complete");
    // Reports for another channel, including errors, belong to someone else.
    require(!reassembler.feed(control(hid::cmd_error, 0x06, 0x55667788u)), "Foreign error must be ignored");
    require(!reassembler.feed(hid::fragment(0x55667788u, hid::cmd_cbor, message)[0]),
            "Foreign response must be ignored");
    std::optional<Bytes> result;
    for (const auto& report : reports) {
        require(!result, "Message completed early");
        result = reassembler.feed(report);
    }
    require(result && *result == message, "Interleaved reassembly changed the message");
}

void malformed() {
    auto with_reassembler = [](auto&& fn) {
        return [fn] { hid::Reassembler reassembler(channel, hid::cmd_cbor); fn(reassembler); };
    };
    auto report_id = header(channel, hid::cmd_cbor, 1);
    report_id[0] = 1;
    rejects(with_reassembler([&](auto& r) { (void)r.feed(report_id); }), "report ID");

    rejects(with_reassembler([](auto& r) { (void)r.feed(control(hid::cmd_error, 0x0b)); }),
            "CTAPHID error", 0x0b);
    auto long_error = control(hid::cmd_error, 0x01);
    long_error[7] = 2;
    rejects(with_reassembler([&](auto& r) { (void)r.feed(long_error); }), "control length");
    rejects(with_reassembler([](auto& r) { (void)r.feed(control(hid::cmd_keepalive, 0)); }), "keepalive");
    rejects(with_reassembler([](auto& r) { (void)r.feed(control(hid::cmd_keepalive, 3)); }), "keepalive");

    rejects(with_reassembler([](auto& r) { (void)r.feed(header(channel, hid::cmd_init, 17)); }),
            "response command");
    rejects(with_reassembler([](auto& r) { (void)r.feed(header(channel, hid::cmd_cbor, 0)); }),
            "response length");
    rejects(with_reassembler([](auto& r) { (void)r.feed(header(channel, hid::cmd_cbor, hid::max_message + 1)); }),
            "response length");

    // Once a response has started, a keepalive and out-of-order packets are refused.
    const auto reports = hid::fragment(channel, hid::cmd_cbor, pattern(200));
    rejects(with_reassembler([&](auto& r) { (void)r.feed(reports[0]); (void)r.feed(control(hid::cmd_keepalive, 1)); }),
            "keepalive");
    rejects(with_reassembler([&](auto& r) { (void)r.feed(reports[0]); (void)r.feed(reports[2]); }),
            "continuation sequence");
    rejects(with_reassembler([&](auto& r) { (void)r.feed(reports[0]); (void)r.feed(reports[1]); (void)r.feed(reports[1]); }),
            "continuation sequence");
    rejects(with_reassembler([&](auto& r) { (void)r.feed(reports[0]); (void)r.feed(reports[0]); }),
            "continuation sequence");
}

void transport_arguments() {
    using namespace std::chrono_literals;
    const hidfido::ctap::HidDeviceInfo device{L"\\\\?\\hid#placeholder", 0x1234, 0x5678};
    invalid_argument([&] { hidfido::ctap::HidTransport transport(device, 0ms); });
    invalid_argument([&] { hidfido::ctap::HidTransport transport(device, -1ms); });
    invalid_argument([&] { hidfido::ctap::HidTransport transport(device, std::chrono::minutes{5} + 1ms); });
    invalid_argument([] { hidfido::ctap::HidTransport transport(hidfido::ctap::HidDeviceInfo{}); });
    const hidfido::ctap::HidDeviceInfo embedded_nul{std::wstring(L"abc\0def", 7), 1, 2};
    invalid_argument([&] { hidfido::ctap::HidTransport transport(embedded_nul); });
}
}

int main() {
    try {
        fragmentation();
        round_trips();
        interleaving();
        malformed();
        transport_arguments();
        std::cout << "CTAPHID framing tests passed.\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
