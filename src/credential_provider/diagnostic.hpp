#pragma once

// Prototype lifecycle diagnostics. The public API accepts only fixed stage
// labels and numeric status/flag values: never strings, secret buffers, account
// or credential identifiers. Capturing this provider needs an external ETW
// controller; this header never creates files, sessions or registry entries.
#include <windows.h>

#include <array>
#include <cstdint>
#include <cwchar>
#include <string_view>

namespace hidfido::credential_diagnostic {

inline constexpr GUID provider_guid{
    0x6c0e3d67, 0x8b83, 0x48b5, {0x95, 0xc7, 0x59, 0x12, 0xf7, 0x85, 0x9d, 0x04}};
inline constexpr wchar_t provider_guid_text[] = L"{6C0E3D67-8B83-48B5-95C7-5912F7859D04}";
inline constexpr UCHAR level = 4;
inline constexpr ULONGLONG keyword = 1;

enum class Stage {
    provider_advise, provider_unadvise, usage_scenario, user_array,
    credential_count, credential_at, credential_advise, credential_unadvise,
    selected, deselected, set_string_empty, set_string_nonempty,
    cancel, cancel_silent, cache_expired, cache_ready, cache_discarded,
    get_serialization, serialization_wait, serialization_start,
    serialization_empty, serialization_return, worker_start, worker_ready,
    worker_refusal, worker_error, worker_cancelled, worker_finished,
    notification, notification_ready, credentials_changed, report_result,
    vault_snapshot, vault_commit, password_opened, serialization_packed,
    hmac_start, hmac_complete, field_update
};

inline std::wstring_view name(Stage stage) noexcept {
    switch (stage) {
#define HIDFIDO_DIAGNOSTIC_WIDE_INNER(value) L##value
#define HIDFIDO_DIAGNOSTIC_WIDE(value) HIDFIDO_DIAGNOSTIC_WIDE_INNER(value)
#define HIDFIDO_DIAGNOSTIC_STAGE(value) case Stage::value: return HIDFIDO_DIAGNOSTIC_WIDE(#value)
        HIDFIDO_DIAGNOSTIC_STAGE(provider_advise);
        HIDFIDO_DIAGNOSTIC_STAGE(provider_unadvise);
        HIDFIDO_DIAGNOSTIC_STAGE(usage_scenario);
        HIDFIDO_DIAGNOSTIC_STAGE(user_array);
        HIDFIDO_DIAGNOSTIC_STAGE(credential_count);
        HIDFIDO_DIAGNOSTIC_STAGE(credential_at);
        HIDFIDO_DIAGNOSTIC_STAGE(credential_advise);
        HIDFIDO_DIAGNOSTIC_STAGE(credential_unadvise);
        HIDFIDO_DIAGNOSTIC_STAGE(selected);
        HIDFIDO_DIAGNOSTIC_STAGE(deselected);
        HIDFIDO_DIAGNOSTIC_STAGE(set_string_empty);
        HIDFIDO_DIAGNOSTIC_STAGE(set_string_nonempty);
        HIDFIDO_DIAGNOSTIC_STAGE(cancel);
        HIDFIDO_DIAGNOSTIC_STAGE(cancel_silent);
        HIDFIDO_DIAGNOSTIC_STAGE(cache_expired);
        HIDFIDO_DIAGNOSTIC_STAGE(cache_ready);
        HIDFIDO_DIAGNOSTIC_STAGE(cache_discarded);
        HIDFIDO_DIAGNOSTIC_STAGE(get_serialization);
        HIDFIDO_DIAGNOSTIC_STAGE(serialization_wait);
        HIDFIDO_DIAGNOSTIC_STAGE(serialization_start);
        HIDFIDO_DIAGNOSTIC_STAGE(serialization_empty);
        HIDFIDO_DIAGNOSTIC_STAGE(serialization_return);
        HIDFIDO_DIAGNOSTIC_STAGE(worker_start);
        HIDFIDO_DIAGNOSTIC_STAGE(worker_ready);
        HIDFIDO_DIAGNOSTIC_STAGE(worker_refusal);
        HIDFIDO_DIAGNOSTIC_STAGE(worker_error);
        HIDFIDO_DIAGNOSTIC_STAGE(worker_cancelled);
        HIDFIDO_DIAGNOSTIC_STAGE(worker_finished);
        HIDFIDO_DIAGNOSTIC_STAGE(notification);
        HIDFIDO_DIAGNOSTIC_STAGE(notification_ready);
        HIDFIDO_DIAGNOSTIC_STAGE(credentials_changed);
        HIDFIDO_DIAGNOSTIC_STAGE(report_result);
        HIDFIDO_DIAGNOSTIC_STAGE(vault_snapshot);
        HIDFIDO_DIAGNOSTIC_STAGE(vault_commit);
        HIDFIDO_DIAGNOSTIC_STAGE(password_opened);
        HIDFIDO_DIAGNOSTIC_STAGE(serialization_packed);
        HIDFIDO_DIAGNOSTIC_STAGE(hmac_start);
        HIDFIDO_DIAGNOSTIC_STAGE(hmac_complete);
        HIDFIDO_DIAGNOSTIC_STAGE(field_update);
#undef HIDFIDO_DIAGNOSTIC_STAGE
#undef HIDFIDO_DIAGNOSTIC_WIDE
#undef HIDFIDO_DIAGNOSTIC_WIDE_INNER
    }
    return L"unknown";
}

// Fixed size, no heap allocation and no arbitrary text input. The longest
// stage plus two maximum uint64 values fits comfortably in this buffer.
using Record = std::array<wchar_t, 160>;
inline Record format(Stage stage, std::uint64_t a = 0, std::uint64_t b = 0) noexcept {
    Record text{};
    const auto label = name(stage);
    const auto count = swprintf_s(text.data(), text.size(), L"stage=%.*ls a=%llu b=%llu",
        static_cast<int>(label.size()), label.data(),
        static_cast<unsigned long long>(a), static_cast<unsigned long long>(b));
    if (count < 0) text[0] = L'\0';
    return text;
}

// TraceLogging implementation is confined to one .cpp in the current module.
// Caller GetLastError is preserved, and diagnostics cannot fail authentication.
void write(Stage stage, std::uint64_t a = 0, std::uint64_t b = 0) noexcept;
}
