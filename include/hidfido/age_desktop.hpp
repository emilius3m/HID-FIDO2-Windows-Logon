#pragma once

#include "hidfido/age_files.hpp"

#include <windows.h>
#include <shlobj.h>

#include <exception>
#include <filesystem>
#include <string>
#include <string_view>

// Windows desktop pieces shared by hid-fido2-age (command line),
// hid-fido2-files (graphical helper) and the manager's Files page.
namespace hidfido::age::desktop {
// %APPDATA%\HID-FIDO2-WinLogon\Files\destinatari.txt of the current user.
inline std::filesystem::path default_profile_path() {
    PWSTR folder{};
    if (FAILED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, KF_FLAG_DEFAULT, nullptr, &folder))) {
        CoTaskMemFree(folder);
        throw std::runtime_error("Application data folder unavailable");
    }
    std::filesystem::path path(folder);
    CoTaskMemFree(folder);
    return path / std::filesystem::path(files::profile_relative_path).make_preferred();
}

inline std::wstring widen(std::string_view text) {
    if (text.empty()) return {};
    const int size = MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
    std::wstring result(static_cast<std::size_t>(size > 0 ? size : 0), L'\0');
    if (size > 0) MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), result.data(), size);
    return result;
}

inline std::string narrow(std::wstring_view text) {
    if (text.empty()) return {};
    const int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
    if (size <= 0) throw std::invalid_argument("Invalid UTF-16 text");
    std::string result(static_cast<std::size_t>(size), '\0');
    WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), result.data(), size, nullptr, nullptr);
    return result;
}

inline std::string today() {
    SYSTEMTIME now{};
    GetLocalTime(&now);
    char text[16]{};
    wsprintfA(text, "%04u-%02u-%02u", now.wYear, now.wMonth, now.wDay);
    return text;
}

// User-facing, localized description of any failure of a file operation,
// without an "Error:" prefix. Never includes secret material.
std::wstring describe(const std::exception& error);
}
