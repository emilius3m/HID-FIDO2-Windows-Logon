#include "../src/vault/public_report.hpp"

#include <fstream>
#include <iostream>
#include <iterator>

namespace {
using namespace hidfido::vault::diagnostic;
void require(bool condition, const char* message) { if (!condition) throw std::runtime_error(message); }
std::string read(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    require(input.good(), "Cannot read diagnostic test file");
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}
}

int main() {
    wchar_t temp[MAX_PATH + 1]{};
    const auto size = GetTempPathW(MAX_PATH, temp);
    if (!size || size >= MAX_PATH) return 1;
    const auto path = std::filesystem::path(temp) / (L"hidfido-public-report-test-" +
        std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64()) + L".jsonl");
    struct Cleanup { std::filesystem::path path; ~Cleanup() { DeleteFileW(path.c_str()); } } cleanup{path};
    try {
        { Scope disabled(nullptr, Stage::pin_input); }
        {
            Report report(path);
            try {
                Scope verification(&report, Stage::verify_key);
                Scope transport(&report, Stage::ctap_client_pin);
                throw std::runtime_error("SYNTHETIC-PIN-PASSWORD-SID-DEVICE-ID-SHOULD-NOT-BE-LOGGED");
            } catch (const std::exception&) { report.error(Error::ctap, 0x31); }
            {
                Scope validation(&report, Stage::windows_password_validation);
            }
            report.error(Error::windows_password, {}, ERROR_LOGON_FAILURE);
            report.finished(1);
        }
        const auto contents = read(path);
        require(contents.find("SYNTHETIC") == std::string::npos, "Exception text leaked into diagnostics");
        require(contents.find("\"stage\":\"ctap_client_pin\",\"event\":\"error\",\"error_kind\":\"ctap\",\"ctap_status\":49") != std::string::npos,
                "Inner failed phase or CTAP numeric code was lost");
        require(contents.find("\"win32_error\":1326") != std::string::npos, "Windows numeric code was lost");
        require(contents.find("\"exit_code\":1") != std::string::npos, "Completion code was lost");
        bool duplicate_rejected{};
        try { Report duplicate(path); } catch (const std::exception&) { duplicate_rejected = true; }
        require(duplicate_rejected && read(path) == contents, "Existing report was overwritten");
        std::cout << "Public vault report tests passed.\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
