#pragma once
#include "hidfido/native_management.hpp"
#include <cstdint>
#include <memory>
#include <mutex>
#include <vector>

namespace hidfido::management {
inline constexpr std::size_t support_event_limit = 2048;
inline constexpr std::uint64_t support_duration_ms = 5 * 60 * 1000;
struct SupportEvent {
    std::uint64_t elapsed_ms{}, a{}, b{};
    std::uint32_t stage{};
};
// Only fixed provider stages and integer values. Raw ETW payloads, headers,
// process IDs, user names and arbitrary strings are never retained/exported.
class SupportEvents {
public:
    void clear();
    void add(std::uint32_t stage, std::uint64_t a, std::uint64_t b, std::uint64_t elapsed_ms) noexcept;
    std::vector<SupportEvent> snapshot() const;
    std::uint64_t discarded() const;
private:
    mutable std::mutex mutex_;
    std::vector<SupportEvent> events_;
    std::uint64_t discarded_{};
};
class SupportTrace {
public:
    SupportTrace();
    ~SupportTrace();
    SupportTrace(const SupportTrace&) = delete;
    SupportTrace& operator=(const SupportTrace&) = delete;
    void start(); // Explicit user action; real-time, memory only, no ETL file.
    void stop() noexcept;
    bool running() const noexcept;
    std::uint64_t elapsed_ms() const noexcept;
    SupportEvents& events() noexcept;
    std::uint32_t consumer_error() const noexcept;
    std::uint32_t events_lost() const noexcept;
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
enum class SupportAudit { not_run, passed, failed };
// Reconstruct validated helper JSONL. Unknown fields/text are rejected rather
// than copied. This is the only supported input path for helper diagnostics.
std::string sanitize_helper_report(std::string_view jsonl);
std::string make_support_report(const Status& status, SupportAudit audit,
    const std::vector<SupportEvent>& events, std::uint64_t discarded,
    std::uint32_t consumer_error, std::uint32_t events_lost,
    std::string_view helper_report, bool helper_incomplete,
    std::optional<unsigned> last_exit_code, bool demo = false);
}
