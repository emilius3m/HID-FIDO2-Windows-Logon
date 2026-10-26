#include "hidfido/pin_text.hpp"
#include "hidfido/pin_protocol.hpp"

#include <windows.h>

#include <stdexcept>

namespace hidfido::pin {
password::SecureBytes utf8_from_typed(std::span<const wchar_t> typed) {
    if (typed.empty() || typed.size() > 63) throw std::runtime_error("Invalid PIN length.");
    const auto units = static_cast<int>(typed.size());
    int capacity = NormalizeString(NormalizationC, typed.data(), units, nullptr, 0);
    if (capacity < 0) capacity = -capacity;
    if (capacity < 1 || capacity > 256) throw std::runtime_error("Cannot normalize PIN.");
    password::SecureBytes normalized(static_cast<std::size_t>(capacity) * sizeof(wchar_t));
    auto* normalized_text = reinterpret_cast<wchar_t*>(normalized.bytes().data());
    const int actual = NormalizeString(NormalizationC, typed.data(), units, normalized_text, capacity);
    if (actual < 1 || actual > capacity) throw std::runtime_error("Cannot normalize PIN.");
    const int count = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, normalized_text, actual,
                                          nullptr, 0, nullptr, nullptr);
    if (count < 1 || count > 63) throw std::runtime_error("PIN exceeds the protocol UTF-8 limit.");
    password::SecureBytes pin(static_cast<std::size_t>(count));
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, normalized_text, actual,
                            reinterpret_cast<char*>(pin.bytes().data()), count, nullptr, nullptr) != count) {
        throw std::runtime_error("Cannot encode PIN.");
    }
    (void)pin_hash16(pin.bytes()); // Validate locally, before consuming an authenticator attempt.
    return pin;
}
}
