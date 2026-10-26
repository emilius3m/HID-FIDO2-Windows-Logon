// This executable sends ONLY CTAPHID_INIT and authenticatorGetInfo (0x04).
// No PIN commands, reset, makeCredential, assertions or credential management.
#include <windows.h>
#include <setupapi.h>
#include <hidsdi.h>
#include <hidpi.h>
#include <bcrypt.h>
#include "hidfido/ctap_info.hpp"
#include <algorithm>
#include <array>
#include <cstdint>
#include <cwctype>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
using Bytes = std::vector<std::uint8_t>;
class Handle {
public:
    explicit Handle(HANDLE value = INVALID_HANDLE_VALUE) : value_(value) {}
    ~Handle() { if (valid()) CloseHandle(value_); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    bool valid() const { return value_ && value_ != INVALID_HANDLE_VALUE; }
    HANDLE get() const { return value_; }
private:
    HANDLE value_;
};
class DeviceSet {
public:
    explicit DeviceSet(const GUID& guid) : value(SetupDiGetClassDevsW(&guid, nullptr, nullptr,
                                                     DIGCF_PRESENT | DIGCF_DEVICEINTERFACE)) {}
    ~DeviceSet() { if (value != INVALID_HANDLE_VALUE) SetupDiDestroyDeviceInfoList(value); }
    HDEVINFO value;
};
class ProbeError : public std::runtime_error {
public:
    explicit ProbeError(const char* message, DWORD code = 0) : std::runtime_error(message), code(code) {}
    DWORD code;
};
std::wstring hardware_ids(HDEVINFO set, SP_DEVINFO_DATA& device) {
    DWORD bytes = 0;
    SetupDiGetDeviceRegistryPropertyW(set, &device, SPDRP_HARDWAREID, nullptr, nullptr, 0, &bytes);
    if (!bytes || bytes > 65536) return {};
    std::vector<wchar_t> value(bytes / sizeof(wchar_t) + 2, 0);
    if (!SetupDiGetDeviceRegistryPropertyW(set, &device, SPDRP_HARDWAREID, nullptr,
            reinterpret_cast<BYTE*>(value.data()), bytes, nullptr)) return {};
    return {value.data(), bytes / sizeof(wchar_t)};
}
std::uint32_t be32(const std::uint8_t* data) {
    return (std::uint32_t{data[0]} << 24) | (std::uint32_t{data[1]} << 16) |
           (std::uint32_t{data[2]} << 8) | data[3];
}
void store_be32(std::uint8_t* data, std::uint32_t value) {
    for (unsigned index = 0; index < 4; ++index) data[index] = static_cast<std::uint8_t>(value >> (24 - 8 * index));
}
using Report = std::array<std::uint8_t, 65>;
DWORD remaining(ULONGLONG deadline) {
    const auto now = GetTickCount64();
    if (now >= deadline) throw ProbeError("HID response timed out.", ERROR_TIMEOUT);
    return static_cast<DWORD>(deadline - now);
}
void transfer(HANDLE device, Report& report, bool write, ULONGLONG deadline) {
    Handle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!event.valid()) throw ProbeError("Cannot allocate HID I/O event.", GetLastError());
    OVERLAPPED operation{};
    operation.hEvent = event.get();
    DWORD count = 0;
    const BOOL complete = write ? WriteFile(device, report.data(), static_cast<DWORD>(report.size()), nullptr, &operation)
                                : ReadFile(device, report.data(), static_cast<DWORD>(report.size()), nullptr, &operation);
    if (!complete) {
        const auto error = GetLastError();
        if (error != ERROR_IO_PENDING) throw ProbeError("HID I/O failed.", error);
        // Compute timeout before submitting further I/O. Drain cancelled I/O
        // before releasing OVERLAPPED/event/report storage.
        DWORD timeout = 0;
        try { timeout = remaining(deadline); }
        catch (...) {
            CancelIoEx(device, &operation);
            GetOverlappedResult(device, &operation, &count, TRUE);
            throw;
        }
        const auto wait = WaitForSingleObject(event.get(), timeout);
        if (wait != WAIT_OBJECT_0) {
            const auto code = wait == WAIT_TIMEOUT ? ERROR_TIMEOUT : GetLastError();
            CancelIoEx(device, &operation);
            GetOverlappedResult(device, &operation, &count, TRUE);
            throw ProbeError("HID response wait failed.", code);
        }
    }
    if (!GetOverlappedResult(device, &operation, &count, FALSE))
        throw ProbeError("HID completion failed.", GetLastError());
    if (count != report.size()) throw ProbeError("Unexpected HID report size.", ERROR_INVALID_DATA);
}
void send_single(HANDLE device, std::uint32_t channel, std::uint8_t command,
                  std::span<const std::uint8_t> payload, ULONGLONG deadline) {
    if (payload.size() > 57) throw ProbeError("Diagnostic request exceeds a single frame.");
    Report report{};
    store_be32(report.data() + 1, channel);
    report[5] = command;
    report[6] = static_cast<std::uint8_t>(payload.size() >> 8);
    report[7] = static_cast<std::uint8_t>(payload.size());
    std::copy(payload.begin(), payload.end(), report.begin() + 8);
    transfer(device, report, true, deadline);
}
Bytes receive(HANDLE device, std::uint32_t channel, std::uint8_t expected, ULONGLONG deadline) {
    Bytes result;
    std::optional<std::size_t> length;
    unsigned sequence = 0;
    while (true) {
        (void)remaining(deadline);
        Report report{};
        transfer(device, report, false, deadline);
        if (report[0] != 0 || be32(report.data() + 1) != channel) continue;
        if (report[5] == 0xbb || report[5] == 0xbf) {
            if (report[6] != 0 || report[7] != 1) throw ProbeError("Invalid CTAPHID control length.", ERROR_INVALID_DATA);
            if (report[5] == 0xbf) throw ProbeError("Authenticator returned a CTAPHID error.", report[8]);
            if (length) throw ProbeError("Unexpected keepalive during response assembly.", ERROR_INVALID_DATA);
            continue; // Keepalive never extends the fixed deadline.
        }
        if (!length) {
            if (report[5] != expected) throw ProbeError("Unexpected CTAPHID response command.", ERROR_INVALID_DATA);
            length = (std::size_t{report[6]} << 8) | report[7];
            if (*length == 0 || *length > 7609) throw ProbeError("Invalid CTAPHID response length.", ERROR_INVALID_DATA);
            result.reserve(*length);
            const auto count = (std::min)(*length, std::size_t{57});
            result.insert(result.end(), report.begin() + 8, report.begin() + 8 + count);
        } else {
            if (sequence > 127 || report[5] != sequence++)
                throw ProbeError("Invalid CTAPHID continuation sequence.", ERROR_INVALID_DATA);
            const auto count = (std::min)(*length - result.size(), std::size_t{59});
            result.insert(result.end(), report.begin() + 6, report.begin() + 6 + count);
        }
        if (result.size() == *length) return result;
    }
}
hidfido::ctap::AuthenticatorInfo get_info(HANDLE device) {
    std::array<std::uint8_t, 8> nonce{};
    if (BCryptGenRandom(nullptr, nonce.data(), static_cast<ULONG>(nonce.size()),
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) throw ProbeError("CNG random generation failed.");
    auto deadline = GetTickCount64() + 10000;
    send_single(device, 0xffffffffu, 0x86, nonce, deadline);
    Bytes init;
    do { init = receive(device, 0xffffffffu, 0x86, deadline); }
    while (init.size() >= nonce.size() && !std::equal(nonce.begin(), nonce.end(), init.begin()));
    if (init.size() < 17) throw ProbeError("Invalid CTAPHID INIT response.", ERROR_INVALID_DATA);
    const auto channel = be32(init.data() + 8);
    if (channel == 0 || channel == 0xffffffffu || (init[16] & 0x04) == 0)
        throw ProbeError("Authenticator does not advertise CTAPHID CBOR.", ERROR_NOT_SUPPORTED);
    constexpr std::array<std::uint8_t, 1> command{0x04};
    deadline = GetTickCount64() + 10000;
    send_single(device, channel, 0x90, command, deadline);
    return hidfido::ctap::parse_get_info(receive(device, channel, 0x90, deadline));
}
std::string json_string(std::string_view input) {
    std::ostringstream out;
    out << '"';
    for (const auto raw : input) {
        const auto c = static_cast<unsigned char>(raw);
        if (c == '"' || c == '\\') out << '\\' << static_cast<char>(c);
        else if (c < 32 || c > 126) out << "\\u00" << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned>(c) << std::dec;
        else out << static_cast<char>(c);
    }
    return out.str() + '"';
}
std::string string_array(const std::vector<std::string>& items) {
    std::string out = "[";
    for (std::size_t i = 0; i < items.size(); ++i) { if (i) out += ','; out += json_string(items[i]); }
    return out + ']';
}
const char* optional_bool(const std::optional<bool>& value) { return !value ? "null" : *value ? "true" : "false"; }
std::string info_json(const hidfido::ctap::AuthenticatorInfo& info) {
    std::ostringstream out;
    out << "{\"versions\":" << string_array(info.versions)
        << ",\"extensions\":" << string_array(info.extensions)
        << ",\"hmac_secret\":" << (info.hmac_secret ? "true" : "false")
        << ",\"client_pin\":" << optional_bool(info.client_pin)
        << ",\"uv\":" << optional_bool(info.uv)
        << ",\"rk\":" << optional_bool(info.rk) << ",\"pin_protocols\":[";
    for (std::size_t i = 0; i < info.pin_protocols.size(); ++i) { if (i) out << ','; out << info.pin_protocols[i]; }
    out << "]}";
    return out.str();
}
struct Result { unsigned vid{}, pid{}; std::string info, error; DWORD error_code{}; };
std::vector<Result> probe() {
    GUID hid{};
    HidD_GetHidGuid(&hid);
    DeviceSet set(hid);
    if (set.value == INVALID_HANDLE_VALUE) throw ProbeError("HID enumeration failed.", GetLastError());
    std::vector<Result> results;
    for (DWORD index = 0;; ++index) {
        SP_DEVICE_INTERFACE_DATA interface_data{sizeof(SP_DEVICE_INTERFACE_DATA)};
        if (!SetupDiEnumDeviceInterfaces(set.value, nullptr, &hid, index, &interface_data)) {
            if (GetLastError() != ERROR_NO_MORE_ITEMS) throw ProbeError("HID enumeration incomplete.", GetLastError());
            break;
        }
        DWORD size = 0;
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
        Result result;
        try {
            Handle handle(CreateFileW(detail->DevicePath, GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr));
            if (!handle.valid()) throw ProbeError("Cannot open FIDO HID; administrator elevation may be required.", GetLastError());
            HIDD_ATTRIBUTES attributes{sizeof(HIDD_ATTRIBUTES)};
            if (!HidD_GetAttributes(handle.get(), &attributes)) throw ProbeError("Cannot query HID attributes.", GetLastError());
            result.vid = attributes.VendorID;
            result.pid = attributes.ProductID;
            PHIDP_PREPARSED_DATA preparsed = nullptr;
            if (!HidD_GetPreparsedData(handle.get(), &preparsed)) throw ProbeError("Cannot query HID capabilities.", GetLastError());
            HIDP_CAPS caps{};
            const auto status = HidP_GetCaps(preparsed, &caps);
            HidD_FreePreparsedData(preparsed);
            if (status != HIDP_STATUS_SUCCESS || caps.UsagePage != 0xf1d0 || caps.Usage != 1 ||
                caps.InputReportByteLength != 65 || caps.OutputReportByteLength != 65)
                throw ProbeError("Unsupported FIDO HID report layout.", ERROR_NOT_SUPPORTED);
            result.info = info_json(get_info(handle.get()));
        } catch (const ProbeError& error) { result.error = error.what(); result.error_code = error.code; }
        catch (const std::exception&) { result.error = "Invalid authenticatorGetInfo response."; result.error_code = ERROR_INVALID_DATA; }
        results.push_back(std::move(result));
    }
    return results;
}
bool elevated() {
    SID_IDENTIFIER_AUTHORITY authority = SECURITY_NT_AUTHORITY;
    PSID sid = nullptr;
    if (!AllocateAndInitializeSid(&authority, 2, SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS, 0,0,0,0,0,0, &sid)) return false;
    BOOL member = FALSE;
    CheckTokenMembership(nullptr, sid, &member);
    FreeSid(sid);
    return member != FALSE;
}
}
int wmain(int argc, wchar_t** argv) {
    try {
        if (argc != 2 && argc != 4) throw ProbeError("Usage: ctap-probe --get-info [--report <file>]");
        if (std::wstring(argv[1]) != L"--get-info" || (argc == 4 && std::wstring(argv[2]) != L"--report"))
            throw ProbeError("Only read-only --get-info is available.");
        const auto results = probe();
        bool all_ok = !results.empty();
        std::ostringstream out;
        out << "{\"read_only\":true,\"elevated\":" << (elevated() ? "true" : "false") << ",\"devices\":[";
        for (std::size_t i = 0; i < results.size(); ++i) {
            const auto& result = results[i];
            if (i) out << ',';
            out << "{\"vid\":" << result.vid << ",\"pid\":" << result.pid << ",\"info\":"
                << (result.info.empty() ? "null" : result.info) << ",\"error\":"
                << (result.error.empty() ? "null" : json_string(result.error)) << ",\"error_code\":" << result.error_code << '}';
            if (!result.error.empty()) all_ok = false;
        }
        out << "]}\n";
        if (argc == 4) {
            std::ofstream file(std::filesystem::path(argv[3]), std::ios::binary | std::ios::trunc);
            file << out.str();
            if (!file) throw ProbeError("Cannot write diagnostic report.");
        }
        std::cout << out.str();
        return all_ok ? 0 : 2;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
