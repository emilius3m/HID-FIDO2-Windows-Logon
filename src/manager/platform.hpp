#pragma once
#include "hidfido/native_management.hpp"
#include <windows.h>
#include <utility>

namespace hidfido::management {
class Handle {
public:
    explicit Handle(HANDLE h = INVALID_HANDLE_VALUE) : h_(h) {}
    ~Handle() { if (valid()) CloseHandle(h_); }
    Handle(Handle&& other) noexcept : h_(std::exchange(other.h_, INVALID_HANDLE_VALUE)) {}
    Handle& operator=(Handle&& other) noexcept { if (this != &other) { if (valid()) CloseHandle(h_); h_ = std::exchange(other.h_, INVALID_HANDLE_VALUE); } return *this; }
    Handle(const Handle&) = delete;
    bool valid() const { return h_ && h_ != INVALID_HANDLE_VALUE; }
    HANDLE get() const { return h_; }
    HANDLE release() { return std::exchange(h_, INVALID_HANDLE_VALUE); }
private: HANDLE h_;
};
inline constexpr wchar_t public_sddl[] = L"O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)";
inline constexpr wchar_t directory_sddl[] = L"O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)";
[[noreturn]] void win_error(const char* action);
void reject_reparse(const std::filesystem::path& path);
std::vector<Handle> pin_directories(const std::filesystem::path& path);
std::vector<std::uint8_t> read_bytes(const std::filesystem::path& path, std::size_t maximum = 64 * 1024 * 1024);
void new_directory(const std::filesystem::path& path);
void write_new(const std::filesystem::path& path, std::span<const std::uint8_t> bytes, bool protect = true);
void write_new_text(const std::filesystem::path& path, std::string_view text, bool protect = true);
std::string random_id();
std::wstring file_version(const std::filesystem::path& file);
Handle start_native(const std::filesystem::path& executable, const std::vector<std::wstring>& arguments);
unsigned run_native(const std::filesystem::path& executable, const std::vector<std::wstring>& arguments, unsigned timeout_ms = 30000);
void verify_install_ancestors();
}
