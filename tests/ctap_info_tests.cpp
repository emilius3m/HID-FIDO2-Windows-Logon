#include "hidfido/ctap_info.hpp"

#include <algorithm>
#include <cstdint>
#include <exception>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {
using Bytes = std::vector<std::uint8_t>;

void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

void rejects(const Bytes& data, std::string_view reason = {}) {
    bool rejected{};
    try {
        static_cast<void>(hidfido::ctap::parse_get_info(data));
    } catch (const std::runtime_error& error) {
        rejected = true;
        if (!reason.empty()) {
            require(std::string_view(error.what()).find(reason) != std::string_view::npos,
                    "Malformed fixture failed for an unexpected reason");
        }
    }
    require(rejected, "Malformed GetInfo response was accepted");
}

// Literal wire fixtures include the CTAP status octet, not CTAPHID headers.
Bytes minimal() {
    return {0x00, 0xa2,
            0x01, 0x81, 0x68, 'F','I','D','O','_','2','_','0',
            0x03, 0x50, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
}

Bytes full() {
    return {0x00, 0xa6,
            0x01, 0x82, 0x66, 'U','2','F','_','V','2',
                        0x68, 'F','I','D','O','_','2','_','0',
            0x02, 0x82, 0x6b, 'h','m','a','c','-','s','e','c','r','e','t',
                        0x6b, 'c','r','e','d','P','r','o','t','e','c','t',
            0x03, 0x50, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
            0x04, 0xa4, 0x62, 'r','k', 0xf5,
                        0x62, 'u','v', 0xf4,
                        0x69, 'c','l','i','e','n','t','P','i','n', 0xf5,
                        0x6a, 'f','u','t','u','r','e','F','l','a','g', 0xf5,
            0x05, 0x19, 0x04, 0x00,
            0x06, 0x82, 0x02, 0x01};
}

Bytes extra(std::initializer_list<std::uint8_t> member) {
    auto data = minimal();
    ++data[1];
    data.insert(data.end(), member.begin(), member.end());
    return data;
}

void positive_cases() {
    const auto complete = hidfido::ctap::parse_get_info(full());
    require(complete.versions == std::vector<std::string>{"U2F_V2", "FIDO_2_0"},
            "Version list changed");
    require(complete.extensions == std::vector<std::string>{"hmac-secret", "credProtect"},
            "Extension list changed");
    require(complete.hmac_secret, "hmac-secret was not detected");
    require(complete.client_pin && *complete.client_pin, "Configured client PIN not detected");
    require(complete.uv && !*complete.uv, "False UV differs from absent UV");
    require(complete.rk && *complete.rk, "Resident key option not detected");
    require(complete.pin_protocols == std::vector<std::uint32_t>{2, 1},
            "PIN protocol preference order changed");
    require(complete.max_msg_size == 1024U, "Maximum message size changed");
    require(complete.aaguid.front() == 0 && complete.aaguid.back() == 15,
            "AAGUID bytes changed");

    const auto basic = hidfido::ctap::parse_get_info(minimal());
    require(!basic.hmac_secret && basic.extensions.empty(), "Absent hmac-secret reported supported");
    require(!basic.client_pin && !basic.uv && !basic.rk && basic.pin_protocols.empty(),
            "Absent options reported configured");

    const auto unrelated = hidfido::ctap::parse_get_info(extra(
        {0x02, 0x81, 0x6c, 'h','m','a','c','-','s','e','c','r','e','t','2'}));
    require(!unrelated.hmac_secret, "hmac-secret prefix was accepted as the extension");

    // Unknown future member: map containing an array and an algorithm integer.
    static_cast<void>(hidfido::ctap::parse_get_info(extra(
        {0x18, 0x18, 0xa2, 0x01, 0x83, 0xf5, 0xf6, 0x42, 0xab, 0xcd, 0x02, 0x26})));
    static_cast<void>(hidfido::ctap::parse_get_info(extra({0x02, 0x80})));

    // Accept unsorted GetInfo members while still rejecting duplicate keys.
    auto unsorted = minimal();
    std::rotate(unsorted.begin() + 2, unsorted.begin() + 13, unsorted.end());
    const auto reordered = hidfido::ctap::parse_get_info(unsorted);
    require(reordered.versions == basic.versions && reordered.aaguid == basic.aaguid,
            "Unsorted valid map was not parsed consistently");
}

void malformed_cases() {
    const auto valid = full();
    for (std::size_t size = 0; size < valid.size(); ++size) {
        rejects(Bytes(valid.begin(), valid.begin() + size));
    }
    auto trailing = minimal();
    trailing.push_back(0);
    rejects(trailing, "trailing");
    auto status = minimal();
    status[0] = 0x12;
    rejects(status, "nonzero CTAP status");
    rejects(Bytes(8193, 0), "exceeds 8192");
    rejects({0, 0xa0}, "versions");
    rejects({0, 0xa1, 0x01, 0x81, 0x68, 'F','I','D','O','_','2','_','0'}, "AAGUID");
    rejects({0, 0xa2, 0x01, 0x80, 0x03, 0x40}, "empty");
    auto short_guid = minimal();
    short_guid[14] = 0x4f;
    short_guid.pop_back();
    rejects(short_guid, "16 bytes");
    auto wrong_type = minimal();
    wrong_type[3] = 0x61;
    rejects(wrong_type, "container type");
    auto indefinite = minimal();
    indefinite[1] = 0xbf;
    rejects(indefinite, "indefinite");
    auto nonminimal_map = minimal();
    nonminimal_map[1] = 0xb8;
    nonminimal_map.insert(nonminimal_map.begin() + 2, 0x02);
    rejects(nonminimal_map, "nonminimal");
    auto invalid_utf8 = minimal();
    invalid_utf8[5] = 0xc0;
    rejects(invalid_utf8, "UTF-8");

    rejects(extra({0x01, 0x81, 0x61, 'x'}), "duplicate GetInfo");
    rejects(extra({0x04, 0xa2, 0x62, 'u','v', 0xf4, 0x62, 'u','v', 0xf5}), "duplicate option");
    rejects(extra({0x04, 0xa1, 0x62, 'u','v', 0x01}), "boolean");
    rejects(extra({0x06, 0x80}), "must not be empty");
    rejects(extra({0x06, 0x82, 0x01, 0x01}), "duplicate PIN");
    rejects(extra({0x06, 0x81, 0x20}), "unsigned integer");
    rejects(extra({0x06, 0x81, 0x18, 0x01}), "nonminimal");
    rejects(extra({0x05, 0x00}), "positive");
    rejects(extra({0x05, 0x1b, 0,0,0,1,0,0,0,0}), "32 bits");
    rejects(extra({0x18, 0x18, 0xc0, 0x01}), "tags");
    rejects(extra({0x18, 0x18, 0xa2, 0x01, 0x00, 0x01, 0x01}), "duplicate CBOR");
    rejects(extra({0x18, 0x18, 0xa1, 0x81, 0x00, 0x00}), "complex");
    rejects(extra({0x18, 0x18, 0x9a, 0xff, 0xff, 0xff, 0xff}), "array exceeds");
    rejects(extra({0x18, 0x18, 0x5b, 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff}), "truncated");
    rejects(extra({0x18, 0x18, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x00}), "nesting");
}
}

int main() {
    try {
        positive_cases();
        malformed_cases();
        std::cout << "CTAP GetInfo parser tests passed.\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
