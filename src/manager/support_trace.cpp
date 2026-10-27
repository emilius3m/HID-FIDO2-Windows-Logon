#include "hidfido/support_report.hpp"
#include "../credential_provider/diagnostic.hpp"
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <objbase.h>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <system_error>
#include <thread>

namespace hidfido::management {
struct SupportTrace::Impl {
    SupportEvents records;
    std::atomic_bool active{};
    std::atomic<std::uint32_t> error{}, lost{};
    ULONGLONG started{};
    std::atomic<ULONGLONG> ended{};
    TRACEHANDLE session{}, consumer{INVALID_PROCESSTRACE_HANDLE};
    std::wstring name;
    std::vector<std::uint64_t> storage;
    std::mutex session_mutex, timer_mutex;
    std::condition_variable timer;
    bool cancelled{};
    std::thread worker, deadline;
    EVENT_TRACE_PROPERTIES* properties() { return reinterpret_cast<EVENT_TRACE_PROPERTIES*>(storage.data()); }

    template<class T> static bool property(EVENT_RECORD* event, const wchar_t* name, T& value) noexcept {
        PROPERTY_DATA_DESCRIPTOR descriptor{};
        descriptor.PropertyName = reinterpret_cast<ULONGLONG>(name); descriptor.ArrayIndex = ULONG_MAX;
        ULONG size{};
        return TdhGetPropertySize(event, 0, nullptr, 1, &descriptor, &size) == ERROR_SUCCESS && size == sizeof(T) &&
            TdhGetProperty(event, 0, nullptr, 1, &descriptor, sizeof(T), reinterpret_cast<BYTE*>(&value)) == ERROR_SUCCESS;
    }
    static void WINAPI event_record(EVENT_RECORD* event) noexcept {
        auto* self = static_cast<Impl*>(event->UserContext);
        if (!self || !IsEqualGUID(event->EventHeader.ProviderId, credential_diagnostic::provider_guid) || event->UserDataLength > 1024) return;
        std::uint32_t stage{}; std::uint64_t a{}, b{};
        if (!property(event, L"Stage", stage) || !property(event, L"A", a) || !property(event, L"B", b)) return;
        self->records.add(stage, a, b, GetTickCount64() - self->started);
    }
    static ULONG WINAPI buffer(EVENT_TRACE_LOGFILEW* log) noexcept {
        if (auto* self = static_cast<Impl*>(log->Context)) self->lost.store(log->EventsLost);
        return TRUE;
    }
    void finish() noexcept {
        std::lock_guard lock(session_mutex);
        if (session) {
            const auto result = ControlTraceW(session, nullptr, properties(), EVENT_TRACE_CONTROL_STOP);
            if (result != ERROR_SUCCESS && result != ERROR_WMI_INSTANCE_NOT_FOUND) error.store(result);
            lost.store(properties()->EventsLost);
            session = 0;
        }
        if (!ended.load() && started) ended.store(GetTickCount64());
        active.store(false);
    }
    void stop() noexcept {
        { std::lock_guard lock(timer_mutex); cancelled = true; }
        timer.notify_all(); finish();
        if (deadline.joinable()) deadline.join();
        if (consumer != INVALID_PROCESSTRACE_HANDLE) { CloseTrace(consumer); consumer = INVALID_PROCESSTRACE_HANDLE; }
        if (worker.joinable()) worker.join();
    }
};
SupportTrace::SupportTrace() : impl_(std::make_unique<Impl>()) {}
SupportTrace::~SupportTrace() { stop(); }
void SupportTrace::start() {
    stop(); auto& p = *impl_; p.records.clear(); p.error.store(0); p.lost.store(0); p.ended.store(0);
    GUID id{}; if (FAILED(CoCreateGuid(&id))) throw std::runtime_error("Cannot create support session");
    wchar_t guid[40]{}; StringFromGUID2(id, guid, 40); p.name = std::wstring(L"HIDFIDO2.Support.") + guid;
    const auto bytes = sizeof(EVENT_TRACE_PROPERTIES) + (p.name.size() + 1) * sizeof(wchar_t);
    p.storage.assign((bytes + 7) / 8, 0); auto* properties = p.properties();
    properties->Wnode.BufferSize = static_cast<ULONG>(bytes); properties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    properties->Wnode.Guid = id; properties->Wnode.ClientContext = 1;
    properties->BufferSize = 32; properties->MinimumBuffers = 2; properties->MaximumBuffers = 8;
    properties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE; properties->FlushTimer = 1;
    properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    p.started = GetTickCount64(); p.cancelled = false;
    auto result = StartTraceW(&p.session, p.name.c_str(), properties);
    if (result != ERROR_SUCCESS) { p.session = 0; throw std::system_error(static_cast<int>(result), std::system_category(), "Start support trace"); }
    try {
        ENABLE_TRACE_PARAMETERS parameters{}; parameters.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
        result = EnableTraceEx2(p.session, &credential_diagnostic::provider_guid, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
            credential_diagnostic::level, credential_diagnostic::keyword, 0, 0, &parameters);
        if (result != ERROR_SUCCESS) throw std::system_error(static_cast<int>(result), std::system_category(), "Enable support provider");
        EVENT_TRACE_LOGFILEW log{}; log.LoggerName = p.name.data();
        log.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        log.EventRecordCallback = Impl::event_record; log.BufferCallback = Impl::buffer; log.Context = &p;
        p.consumer = OpenTraceW(&log);
        if (p.consumer == INVALID_PROCESSTRACE_HANDLE) throw std::system_error(static_cast<int>(GetLastError()), std::system_category(), "Open support trace");
        p.active.store(true);
        const auto consumer = p.consumer;
        p.worker = std::thread([&p, consumer] {
            auto handle = consumer; const auto status = ProcessTrace(&handle, 1, nullptr, nullptr);
            if (status != ERROR_SUCCESS && status != ERROR_CANCELLED) p.error.store(status);
            p.finish();
        });
        p.deadline = std::thread([&p] {
            std::unique_lock lock(p.timer_mutex);
            if (!p.timer.wait_for(lock, std::chrono::milliseconds(support_duration_ms), [&p] { return p.cancelled; })) { lock.unlock(); p.finish(); }
        });
    } catch (...) { stop(); throw; }
}
void SupportTrace::stop() noexcept { impl_->stop(); }
bool SupportTrace::running() const noexcept { return impl_->active.load(); }
std::uint64_t SupportTrace::elapsed_ms() const noexcept {
    if (!impl_->started) return 0; const auto end = impl_->ended.load();
    return (end ? end : GetTickCount64()) - impl_->started;
}
SupportEvents& SupportTrace::events() noexcept { return impl_->records; }
std::uint32_t SupportTrace::consumer_error() const noexcept { return impl_->error.load(); }
std::uint32_t SupportTrace::events_lost() const noexcept { return impl_->lost.load(); }
}
