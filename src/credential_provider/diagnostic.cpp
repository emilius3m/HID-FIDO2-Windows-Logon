#include "diagnostic.hpp"

#include <TraceLoggingProvider.h>

namespace {
// A self-describing user-mode provider: no manifest, channel or system-wide
// registration is installed. Each DLL/EXE linked with this object owns its
// own handle and unregisters it before its code and metadata are unmapped.
TRACELOGGING_DEFINE_PROVIDER(
    g_hHidFido2LogonDiagnostic,
    "HIDFIDO2.WindowsLogon",
    (0x6c0e3d67, 0x8b83, 0x48b5, 0x95, 0xc7, 0x59, 0x12, 0xf7, 0x85, 0x9d, 0x04));

class LastError {
public:
    LastError() noexcept : code_(GetLastError()) {}
    ~LastError() { SetLastError(code_); }
    LastError(const LastError&) = delete;
    LastError& operator=(const LastError&) = delete;
private:
    DWORD code_;
};

class Registration {
public:
    Registration() noexcept { (void)TraceLoggingRegister(g_hHidFido2LogonDiagnostic); }
    ~Registration() { TraceLoggingUnregister(g_hHidFido2LogonDiagnostic); }
    Registration(const Registration&) = delete;
    Registration& operator=(const Registration&) = delete;
};
}

namespace hidfido::credential_diagnostic {
void write(Stage stage, std::uint64_t a, std::uint64_t b) noexcept {
    LastError restore_error;
    static Registration registration;
    const auto label = name(stage);
    const auto number = label == L"unknown" ? UINT32_MAX : static_cast<std::uint32_t>(stage);
    // StageName can only point to a fixed literal from name(). There is no
    // string argument through which a caller could supply a PIN or password.
    // The TraceLogging macro checks whether a controller enabled the provider.
    TraceLoggingWrite(g_hHidFido2LogonDiagnostic, "Lifecycle",
        TraceLoggingLevel(level),
        TraceLoggingKeyword(keyword),
        TraceLoggingUInt32(number, "Stage"),
        TraceLoggingWideString(label.data(), "StageName"),
        TraceLoggingUInt64(a, "A"),
        TraceLoggingUInt64(b, "B"));
}
}
