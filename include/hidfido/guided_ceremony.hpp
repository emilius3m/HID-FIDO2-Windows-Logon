#pragma once
#include "hidfido/guidance_view.hpp"
#include "hidfido/password_envelope.hpp"
#include <memory>
#include <optional>

namespace hidfido::ui {
// The helper owns this entire window, its masked input and erased results.
// Its worker may show a step or wait for local input; the UI thread stays live.
class GuidedCeremony {
public:
    GuidedCeremony(int macro, bool enrollment);
    ~GuidedCeremony();
    GuidedCeremony(const GuidedCeremony&) = delete;
    GuidedCeremony& operator=(const GuidedCeremony&) = delete;
    void show(GuideStep step, std::wstring label = {}, std::wstring detail = {}, std::wstring heading = {});
    bool acknowledge(GuideStep step, std::wstring label = {}, std::wstring detail = {}, std::wstring heading = {});
    std::optional<password::SecureBytes> secret(GuideStep step, std::wstring label);
    bool cancelled() const noexcept;
#ifdef HIDFIDO_GUIDED_TESTING
    GuidedCeremony(int macro, bool enrollment, bool hidden);
    std::optional<GuideStep> test_ready_step();
    void test_submit(std::wstring_view value);
    void test_cancel();
    unsigned test_input_units();
#endif
private:
    void start();
    struct Impl; std::unique_ptr<Impl> impl_;
};
}
