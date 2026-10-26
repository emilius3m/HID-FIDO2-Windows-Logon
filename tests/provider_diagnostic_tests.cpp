#include "../src/credential_provider/diagnostic.hpp"

#include <iostream>
#include <limits>
#include <stdexcept>
#include <string_view>
#include <type_traits>

namespace {
using namespace hidfido::credential_diagnostic;
void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

static_assert(noexcept(format(Stage::get_serialization)));
static_assert(noexcept(write(Stage::get_serialization)));
static_assert(std::is_invocable_v<decltype(&write), Stage, std::uint64_t, std::uint64_t>);
static_assert(!std::is_invocable_v<decltype(&write), Stage, const wchar_t*, std::uint64_t>);
static_assert(!std::is_invocable_v<decltype(&write), Stage, std::wstring_view, std::uint64_t>);

void bounded_public_format() {
    const auto status = format(Stage::report_result, 0xc000006dU, 0xc000006aU);
    require(std::wstring_view(status.data()) == L"stage=report_result a=3221225581 b=3221225578",
            "Status event did not preserve only fixed labels and numeric codes");
    const auto maximum = format(Stage::credential_unadvise,
        (std::numeric_limits<std::uint64_t>::max)(), (std::numeric_limits<std::uint64_t>::max)());
    require(std::wstring_view(maximum.data()) ==
        L"stage=credential_unadvise a=18446744073709551615 b=18446744073709551615",
        "Maximum integer status was truncated");
    require(maximum.back() == L'\0', "Public diagnostic record exceeded its fixed storage");

    const auto unknown = format(static_cast<Stage>(-1), 7, 9);
    require(std::wstring_view(unknown.data()) == L"stage=unknown a=7 b=9",
            "Unknown stages were not mapped to a fixed label");
    for (unsigned i = 0; i <= static_cast<unsigned>(Stage::field_update); ++i) {
        const auto stage = static_cast<Stage>(i);
        const auto label = name(stage);
        require(!label.empty() && label != L"unknown" && label.size() < 48,
                "A public lifecycle stage is unmapped or unbounded");
        for (const auto character : label) {
            require((character >= L'a' && character <= L'z') || character == L'_',
                    "Stage label contains data outside the static label alphabet");
        }
        const auto record = format(stage, 1, 0);
        require(record[0] && record.back() == L'\0', "A public lifecycle record was not bounded");
    }
    require(provider_guid.Data1 != 0x8b5d856b, "Trace GUID accidentally reused the COM identity");
    require(level == 4 && keyword == 1, "Trace level or keyword changed unexpectedly");
}

void preserves_win32_error() {
    // No controller/session is started. The event contains synthetic numeric
    // values only, and EventRegister does not install a system manifest.
    SetLastError(ERROR_CANCELLED);
    write(Stage::worker_error, 0x80004005U, 0);
    require(GetLastError() == ERROR_CANCELLED, "Diagnostics changed caller GetLastError");
}
}

int main() {
    try {
        bounded_public_format();
        preserves_win32_error();
        std::cout << "Provider public ETW diagnostics: bounded labels, numeric statuses and Win32 error preservation passed.\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
