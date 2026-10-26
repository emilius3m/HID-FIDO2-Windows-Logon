// Read-only CTAPHID transport experiment. The only device commands issued are
// CTAPHID_INIT and authenticatorGetInfo. No PIN, assertion, credential creation,
// reset, credential-management operation, or Windows authentication is used.
#include <windows.h>

#include "hidfido/ctap_client.hpp"
#include "hidfido/hid_transport.hpp"

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>

namespace {
namespace ctap = hidfido::ctap;

class ReportError final : public std::runtime_error {
public:
    explicit ReportError(DWORD code) : std::runtime_error("report_io_failed"), code_(code) {}
    DWORD code() const noexcept { return code_; }
private:
    DWORD code_;
};

// Every string passed here is a fixed program label. No exception text, device
// path, attribute, serial number, identifier or CTAP response enters this log.
std::string json_line(std::string_view phase, std::string_view event,
                      std::string_view error = {}, std::optional<std::uint32_t> code = {}) {
    std::string result = "{\"test\":\"ctap-transport-read-only\",\"tick_ms\":" +
        std::to_string(GetTickCount64()) + ",\"phase\":\"" + std::string(phase) +
        "\",\"event\":\"" + std::string(event) + "\"";
    if (!error.empty()) result += ",\"error\":\"" + std::string(error) + "\"";
    if (code) result += ",\"code\":" + std::to_string(*code);
    result += "}\n";
    return result;
}

class EventLog {
public:
    explicit EventLog(const std::optional<std::filesystem::path>& path) {
        if (!path) return;
        // The single new file stays open throughout the experiment. Readers
        // may tail it, but no other writer/deleter can replace it while open.
        // CREATE_NEW also refuses an existing final reparse point or hardlink.
        file_ = CreateFileW(path->c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr,
            CREATE_NEW, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        if (file_ == INVALID_HANDLE_VALUE) throw ReportError(GetLastError());
    }
    ~EventLog() { if (file_ != INVALID_HANDLE_VALUE) CloseHandle(file_); }
    EventLog(const EventLog&) = delete;
    EventLog& operator=(const EventLog&) = delete;

    void write(std::string_view phase, std::string_view event,
               std::string_view error = {}, std::optional<std::uint32_t> code = {}) {
        const auto line = json_line(phase, event, error, code);
        std::cout << line << std::flush;
        if (file_ == INVALID_HANDLE_VALUE) return;
        DWORD written{};
        if (!WriteFile(file_, line.data(), static_cast<DWORD>(line.size()), &written, nullptr)) {
            throw ReportError(GetLastError());
        }
        if (written != line.size()) throw ReportError(ERROR_WRITE_FAULT);
        if (!FlushFileBuffers(file_)) throw ReportError(GetLastError());
    }
private:
    HANDLE file_{INVALID_HANDLE_VALUE};
};

void get_info(ctap::HidTransport& transport) {
    ctap::HmacClient client(transport);
    (void)client.info(); // Exactly authenticatorGetInfo: no PIN or UV operation.
}

bool experiment(EventLog& log, std::string_view& phase, bool gui_pause) {
    auto begin = [&](std::string_view next) {
        phase = next;
        log.write(phase, "begin");
    };
    auto pass = [&] { log.write(phase, "pass"); };

    begin("enumeration");
    const auto devices = ctap::enumerate_fido_hid();
    if (devices.size() != 1) {
        log.write(phase, "error", "exactly_one_fido_interface_required");
        throw std::invalid_argument("device_count_rejected");
    }
    pass();
    const auto& device = devices.front();
    constexpr auto timeout = std::chrono::milliseconds{5000};

    {
        begin("initial_handle_init");
        ctap::HidTransport transport(device, timeout);
        pass();
        begin("initial_handle_get_info_baseline");
        get_info(transport);
        pass();
        if (gui_pause) {
            begin("gui_pause_begin");
            const auto answer = MessageBoxW(nullptr,
                L"Pausa diagnostica del trasporto USB: non viene richiesto alcun PIN.\n"
                L"Lascia la chiave collegata, senza toccare il sensore.\n"
                L"Premi OK quando vuoi continuare, oppure Annulla per interrompere.",
                L"HID FIDO2 - sola diagnostica INIT/GetInfo",
                MB_OKCANCEL | MB_SETFOREGROUND | MB_ICONINFORMATION);
            if (answer == IDCANCEL) {
                log.write(phase, "error", "user_cancelled", ERROR_CANCELLED);
                return false;
            }
            if (answer != IDOK) {
                log.write(phase, "error", "gui_pause_failed", GetLastError());
                return false;
            }
            phase = "gui_pause_pass";
            pass();
        }
        begin("same_handle_get_info_immediate");
        get_info(transport);
        pass();
        begin("same_handle_idle_15_seconds");
        std::this_thread::sleep_for(std::chrono::seconds{15});
        pass();
        begin("same_handle_get_info_after_idle");
        get_info(transport);
        pass();
        begin("initial_handle_close");
    }
    pass();

    {
        begin("second_handle_init");
        ctap::HidTransport transport(device, timeout);
        pass();
        begin("second_handle_get_info");
        get_info(transport);
        pass();
        begin("second_handle_close");
    }
    pass();

    {
        begin("third_handle_init");
        ctap::HidTransport transport(device, timeout);
        pass();
        begin("third_handle_get_info");
        get_info(transport);
        pass();
        begin("third_handle_close");
    }
    pass();
    begin("complete");
    pass();
    return true;
}
}

int wmain(int argc, wchar_t** argv) {
    if ((argc != 2 && argc != 4) ||
        (std::wstring_view(argv[1]) != L"--run" && std::wstring_view(argv[1]) != L"--run-with-pause") ||
        (argc == 4 && std::wstring_view(argv[2]) != L"--report")) {
        std::cout << json_line("arguments", "error", "usage_run_or_run_with_pause_optional_report_new_file") << std::flush;
        return 1;
    }
    std::string_view phase = "report_open";
    try {
        std::optional<std::filesystem::path> report;
        if (argc == 4) report.emplace(argv[3]);
        EventLog log(report);
        try {
            return experiment(log, phase, std::wstring_view(argv[1]) == L"--run-with-pause") ? 0 : 2;
        } catch (const ctap::HidTransportError& error) {
            log.write(phase, "error", "hid_transport_failed", error.code());
        } catch (const ctap::StatusError& error) {
            log.write(phase, "error", "get_info_ctap_status", error.status());
        } catch (const ReportError&) {
            throw;
        } catch (const std::invalid_argument&) {
            // Enumeration already emitted its one specific, static error.
            // The transport constructor can also reject invalid local input.
            if (phase != "enumeration") log.write(phase, "error", "invalid_local_input");
        } catch (const std::exception&) {
            log.write(phase, "error", "get_info_or_operation_failed");
        }
    } catch (const ReportError& error) {
        // A failed log cannot reliably log its own failure. Stdout still gets
        // a fixed-label numeric error; never print the requested report path.
        std::cout << json_line(phase, "error", "report_io_failed", error.code()) << std::flush;
    } catch (const std::exception&) {
        std::cout << json_line(phase, "error", "setup_failed") << std::flush;
    }
    return 1;
}
