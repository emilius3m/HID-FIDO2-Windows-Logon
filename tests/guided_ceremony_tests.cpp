#include "hidfido/guided_ceremony.hpp"
#include <chrono>
#include <future>
#include <iostream>
#include <stdexcept>
#include <thread>

namespace {
using namespace hidfido::ui;
using namespace std::chrono_literals;
void check(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
struct CancelOnExit { GuidedCeremony& ceremony; ~CancelOnExit() { ceremony.test_cancel(); } };
void ready(GuidedCeremony& c, GuideStep step) {
    const auto end = std::chrono::steady_clock::now() + 3s;
    while (std::chrono::steady_clock::now() < end) { if (c.test_ready_step() == step) return; std::this_thread::sleep_for(10ms); }
    throw std::runtime_error("Hidden ceremony did not reach expected step");
}
void local_secret_input() {
    GuidedCeremony ceremony(1, true, true);
    auto pending = std::async(std::launch::async, [&] { return ceremony.secret(GuideStep::pin, L"Synthetic key"); });
    CancelOnExit cleanup{ceremony}; ready(ceremony, GuideStep::pin);
    ceremony.test_submit(L"1");
    check(pending.wait_for(100ms) == std::future_status::timeout && !ceremony.test_input_units(), "Invalid PIN format escaped or remained in control");
    ceremony.test_submit(L"cafe\u0301");
    check(pending.wait_for(2s) == std::future_status::ready, "Valid synthetic PIN did not finish");
    auto pin = pending.get(); check(pin && pin->size() == 5 && std::string(reinterpret_cast<const char*>(pin->bytes().data()), pin->size()) == "caf\xc3\xa9", "PIN normalization did not preserve UTF-8");
    pin->clear(); check(!ceremony.test_input_units(), "Accepted PIN remains in edit control");
    pending = std::async(std::launch::async, [&] { return ceremony.secret(GuideStep::password, L"Synthetic account"); });
    ready(ceremony, GuideStep::password); ceremony.test_submit(L"Dummy Windows password");
    check(pending.wait_for(2s) == std::future_status::ready, "Synthetic password input did not finish");
    auto password = pending.get(); check(password && password->size() == 22 * sizeof(wchar_t) && !ceremony.test_input_units(), "Password length or erasure failed"); password->clear();
    pending = std::async(std::launch::async, [&] { return ceremony.secret(GuideStep::pin, L"Synthetic key"); });
    ready(ceremony, GuideStep::pin); ceremony.test_cancel();
    check(pending.wait_for(2s) == std::future_status::ready && !pending.get(), "Cancellation returned an earlier secret or blocked");
}
void waiting_is_not_confirmation() {
    GuidedCeremony ceremony(1, true, true);
    bool rejected{}; try { (void)ceremony.acknowledge(GuideStep::touch); } catch (const std::invalid_argument&) { rejected = true; }
    check(rejected, "Hardware response can be manually acknowledged");
    auto pending = std::async(std::launch::async, [&] { return ceremony.acknowledge(GuideStep::release); });
    CancelOnExit cleanup{ceremony};
    ready(ceremony, GuideStep::release); ceremony.test_cancel();
    check(pending.wait_for(2s) == std::future_status::ready && !pending.get(), "Release cancellation blocked the worker");
}
}
int main() {
    try { local_secret_input(); waiting_is_not_confirmation(); std::cout << "Hidden guided UI: synthetic secret normalization, field erasure, cancellation and hardware-wait policy passed. No key, account password or authentication used.\n"; return 0; }
    catch (const std::exception& failure) { std::cerr << failure.what() << '\n'; return 1; }
}
