#include "hidfido/account.hpp"
#include <windows.h>
#include <sddl.h>
#include <cstdint>
#include <stdexcept>
#include <vector>

namespace hidfido {
std::wstring current_user_sid() {
    HANDLE token{};
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) throw std::runtime_error("Open process token failed");
    struct Close { HANDLE value; ~Close() { CloseHandle(value); } } close{token};
    DWORD required{};
    if (GetTokenInformation(token, TokenUser, nullptr, 0, &required) || GetLastError() != ERROR_INSUFFICIENT_BUFFER || !required) throw std::runtime_error("Read current SID size failed");
    std::vector<std::uint8_t> buffer(required);
    if (!GetTokenInformation(token, TokenUser, buffer.data(), required, &required)) throw std::runtime_error("Read current SID failed");
    wchar_t* sid{};
    if (!ConvertSidToStringSidW(reinterpret_cast<const TOKEN_USER*>(buffer.data())->User.Sid, &sid)) throw std::runtime_error("Format current SID failed");
    struct Free { void* value; ~Free() { LocalFree(value); } } memory{sid};
    return sid;
}
}
