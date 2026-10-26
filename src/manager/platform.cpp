#include "platform.hpp"
#include <aclapi.h>
#include <sddl.h>
#include <shlobj.h>
#include <bcrypt.h>
#include <algorithm>
#include <array>
#include <memory>

namespace hidfido::management {
namespace {
struct Local { void* p{}; ~Local() { if (p) LocalFree(p); } };
bool sid_is(PSID sid, WELL_KNOWN_SID_TYPE type) { return IsWellKnownSid(sid, type) != FALSE; }
void inspect_security(HANDLE handle, bool project, bool directory) {
    PSID owner{}; PACL dacl{}; PSECURITY_DESCRIPTOR descriptor{};
    const auto error = GetSecurityInfo(handle, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &owner, nullptr, &dacl, nullptr, &descriptor);
    Local memory{descriptor}; if (error || !owner || !dacl) throw std::runtime_error("Missing protected owner/DACL");
    Local ti; if (!ConvertStringSidToSidW(L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", &ti.p)) win_error("TrustedInstaller SID");
    const auto trusted = [&](PSID sid) { return sid_is(sid, WinLocalSystemSid) || sid_is(sid, WinBuiltinAdministratorsSid) || (!project && EqualSid(sid, ti.p)); };
    if (!trusted(owner)) throw std::runtime_error("Untrusted deployment owner");
    SECURITY_DESCRIPTOR_CONTROL control{}; DWORD revision{};
    if (!GetSecurityDescriptorControl(descriptor, &control, &revision) || (project && !(control & SE_DACL_PROTECTED))) throw std::runtime_error("Unprotected deployment DACL");
    bool system{}, administrators{}, users{};
    for (DWORD index = 0; index < dacl->AceCount; ++index) {
        void* raw{}; if (!GetAce(dacl, index, &raw)) win_error("Read ACL");
        const auto* header = static_cast<ACE_HEADER*>(raw);
        if (!project && (header->AceFlags & INHERIT_ONLY_ACE)) continue;
        if (header->AceType != ACCESS_ALLOWED_ACE_TYPE) { if (project || header->AceType != ACCESS_DENIED_ACE_TYPE) throw std::runtime_error("Unsupported deployment ACE"); continue; }
        const auto* ace = static_cast<ACCESS_ALLOWED_ACE*>(raw); auto* sid = const_cast<DWORD*>(&ace->SidStart);
        if (project) {
            if ((header->AceFlags & (INHERITED_ACE | INHERIT_ONLY_ACE)) || (!directory && header->AceFlags)) throw std::runtime_error("Unexpected inherited deployment ACE");
            if (sid_is(sid, WinBuiltinUsersSid)) { if (ace->Mask & ~(FILE_GENERIC_READ | FILE_GENERIC_EXECUTE)) throw std::runtime_error("Users can modify deployment"); users = (ace->Mask & FILE_GENERIC_READ) == FILE_GENERIC_READ; }
            else if (trusted(sid)) { if ((ace->Mask & FILE_ALL_ACCESS) == FILE_ALL_ACCESS) { if (sid_is(sid, WinLocalSystemSid)) system = true; else administrators = true; } }
            else throw std::runtime_error("Unexpected deployment principal");
        } else if (!trusted(sid) && (ace->Mask & (WRITE_DAC | WRITE_OWNER | DELETE | FILE_DELETE_CHILD | GENERIC_WRITE | GENERIC_ALL))) throw std::runtime_error("Deployment ancestor permits replacement");
    }
    if (project && (!system || !administrators || !users)) throw std::runtime_error("Required deployment access absent");
}
std::wstring command_line(const std::filesystem::path& executable, const std::vector<std::wstring>& args) {
    std::wstring result = installer::quote_argument(executable.wstring());
    for (const auto& arg : args) { if (arg.find(L'\0') != arg.npos) throw std::runtime_error("Embedded command NUL"); result += L" " + installer::quote_argument(arg); }
    return result;
}
std::filesystem::path system_directory() { std::wstring path(32768, L'\0'); const auto count = GetSystemDirectoryW(path.data(), static_cast<UINT>(path.size())); if (!count || count >= path.size()) win_error("System directory"); path.resize(count); return path; }
}
[[noreturn]] void win_error(const char* action) { throw std::runtime_error(std::string(action) + " (Windows " + std::to_string(GetLastError()) + ")"); }
bool elevated() {
    HANDLE token{}; if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) win_error("Process token"); Handle hold(token);
    TOKEN_ELEVATION value{}; DWORD count{}; if (!GetTokenInformation(token, TokenElevation, &value, sizeof(value), &count)) win_error("Elevation status"); return value.TokenIsElevated != 0;
}
std::wstring current_sid() {
    HANDLE token{}; if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) win_error("Process token"); Handle hold(token); DWORD length{};
    GetTokenInformation(token, TokenUser, nullptr, 0, &length); std::vector<std::uint8_t> data(length);
    if (!GetTokenInformation(token, TokenUser, data.data(), length, &length)) win_error("Token identity");
    wchar_t* text{}; if (!ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(data.data())->User.Sid, &text)) win_error("Token SID"); Local memory{text}; return text;
}
std::filesystem::path install_root() {
    wchar_t* path{}; if (FAILED(SHGetKnownFolderPath(FOLDERID_ProgramFiles, 0, nullptr, &path))) throw std::runtime_error("Program Files unavailable");
    const std::filesystem::path root(path); CoTaskMemFree(path); return root / L"HID-FIDO2-WinLogon";
}
void reject_reparse(const std::filesystem::path& path) {
    const auto absolute = std::filesystem::absolute(path).lexically_normal(); const auto text = absolute.native();
    if (text.size() < 3 || text[1] != L':' || text[2] != L'\\' || text.find(L':', 2) != text.npos) throw std::runtime_error("Nonlocal deployment path");
    auto cursor = absolute.root_path();
    for (const auto& part : absolute.relative_path()) {
        cursor /= part; const auto flags = GetFileAttributesW(cursor.c_str());
        if (flags == INVALID_FILE_ATTRIBUTES) { const auto error = GetLastError(); if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) continue; win_error("Inspect path"); }
        else if (flags & FILE_ATTRIBUTE_REPARSE_POINT) throw std::runtime_error("Reparse point refused");
    }
}
std::vector<Handle> pin_directories(const std::filesystem::path& path) {
    reject_reparse(path); const auto absolute = std::filesystem::absolute(path).lexically_normal(); std::vector<Handle> result;
    auto cursor = absolute.root_path();
    const auto pin = [&] { Handle h(CreateFileW(cursor.c_str(), FILE_READ_ATTRIBUTES | READ_CONTROL, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr)); if (!h.valid()) win_error("Pin directory"); result.push_back(std::move(h)); };
    pin(); for (const auto& part : absolute.relative_path()) { cursor /= part; pin(); } return result;
}
void check_protected(const std::filesystem::path& path, bool directory) {
    reject_reparse(path); Handle h(CreateFileW(path.c_str(), READ_CONTROL | FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | (directory ? FILE_FLAG_BACKUP_SEMANTICS : 0), nullptr));
    if (!h.valid()) win_error("Open protected item"); inspect_security(h.get(), true, directory);
}
void verify_install_ancestors() {
    auto cursor = install_root().parent_path(); const auto pins = pin_directories(cursor);
    for (;;) { Handle h(CreateFileW(cursor.c_str(), READ_CONTROL, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr)); if (!h.valid()) win_error("Open ancestor"); inspect_security(h.get(), false, true); const auto next = cursor.parent_path(); if (next == cursor) break; cursor = next; }
}
std::vector<std::uint8_t> read_bytes(const std::filesystem::path& path, std::size_t maximum) {
    reject_reparse(path); Handle h(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr)); if (!h.valid()) win_error("Read file");
    LARGE_INTEGER size{}; if (!GetFileSizeEx(h.get(), &size) || size.QuadPart < 1 || static_cast<std::uint64_t>(size.QuadPart) > maximum) throw std::runtime_error("File exceeds bound");
    std::vector<std::uint8_t> result(static_cast<std::size_t>(size.QuadPart)); std::size_t at{};
    while (at < result.size()) { DWORD got{}; if (!ReadFile(h.get(), result.data() + at, static_cast<DWORD>(result.size() - at), &got, nullptr) || !got) win_error("Read contents"); at += got; } return result;
}
std::string read_text(const std::filesystem::path& path, std::size_t maximum) { const auto bytes = read_bytes(path, maximum); std::string text(bytes.begin(), bytes.end()); if (text.starts_with("\xef\xbb\xbf")) text.erase(0, 3); return text; }
void new_directory(const std::filesystem::path& path) {
    reject_reparse(path); if (std::filesystem::exists(path)) { check_protected(path, true); return; }
    Local sd; if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(directory_sddl, SDDL_REVISION_1, &sd.p, nullptr)) win_error("Directory DACL");
    SECURITY_ATTRIBUTES attributes{sizeof(attributes), sd.p, FALSE}; if (!CreateDirectoryW(path.c_str(), &attributes)) win_error("Create protected directory"); check_protected(path, true);
}
void write_new(const std::filesystem::path& path, std::span<const std::uint8_t> data, bool protect) {
    reject_reparse(path); Local sd; SECURITY_ATTRIBUTES attributes{sizeof(attributes), nullptr, FALSE};
    if (protect) { if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(public_sddl, SDDL_REVISION_1, &sd.p, nullptr)) win_error("File DACL"); attributes.lpSecurityDescriptor = sd.p; }
    Handle h(CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, protect ? &attributes : nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, nullptr)); if (!h.valid()) win_error("Create immutable file");
    DWORD written{}; if (data.size() > MAXDWORD || !WriteFile(h.get(), data.data(), static_cast<DWORD>(data.size()), &written, nullptr) || written != data.size() || !FlushFileBuffers(h.get())) win_error("Write immutable file");
}
void write_new_text(const std::filesystem::path& path, std::string_view text, bool protect) { write_new(path, {reinterpret_cast<const std::uint8_t*>(text.data()), text.size()}, protect); }
std::string random_id() { std::array<std::uint8_t, 16> bytes{}; if (BCryptGenRandom(nullptr, bytes.data(), static_cast<ULONG>(bytes.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) throw std::runtime_error("Random identifier failed"); constexpr char hex[] = "0123456789abcdef"; std::string out; for (auto b : bytes) { out += hex[b >> 4]; out += hex[b & 15]; } return out; }
std::wstring file_version(const std::filesystem::path& file) {
    DWORD dummy{}; const auto size = GetFileVersionInfoSizeW(file.c_str(), &dummy); if (!size || size > 1024 * 1024) throw std::runtime_error("Version unavailable"); std::vector<std::uint8_t> data(size);
    if (!GetFileVersionInfoW(file.c_str(), 0, size, data.data())) win_error("Read version"); void* info{}; UINT length{};
    if (!VerQueryValueW(data.data(), L"\\", &info, &length) || length < sizeof(VS_FIXEDFILEINFO)) throw std::runtime_error("Invalid version resource");
    const auto* value = static_cast<const VS_FIXEDFILEINFO*>(info); return std::to_wstring(HIWORD(value->dwFileVersionMS)) + L"." + std::to_wstring(LOWORD(value->dwFileVersionMS)) + L"." + std::to_wstring(HIWORD(value->dwFileVersionLS));
}
Handle start_native(const std::filesystem::path& executable, const std::vector<std::wstring>& arguments) {
    check_protected(executable, false); auto command = command_line(executable, arguments); STARTUPINFOW startup{sizeof(startup)}; PROCESS_INFORMATION process{}; const auto cwd = system_directory();
    if (!CreateProcessW(executable.c_str(), command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, cwd.c_str(), &startup, &process)) win_error("Start native tool"); CloseHandle(process.hThread); return Handle(process.hProcess);
}
unsigned run_native(const std::filesystem::path& executable, const std::vector<std::wstring>& arguments, unsigned timeout_ms) {
    auto process = start_native(executable, arguments); if (WaitForSingleObject(process.get(), timeout_ms) != WAIT_OBJECT_0) { TerminateProcess(process.get(), 1); throw std::runtime_error("Native check timed out"); } DWORD code{}; if (!GetExitCodeProcess(process.get(), &code)) win_error("Native tool status"); return code;
}
std::string capture_status(const std::filesystem::path& executable, std::wstring_view sid) {
    check_protected(executable, false); SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE}; HANDLE rd{}, wr{};
    if (!CreatePipe(&rd, &wr, &sa, 0)) win_error("Status pipe"); Handle reader(rd), writer(wr); if (!SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0)) win_error("Status pipe inheritance");
    Handle null(CreateFileW(L"NUL", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING, 0, nullptr)); if (!null.valid()) win_error("Null status stream");
    SIZE_T size{}; InitializeProcThreadAttributeList(nullptr, 1, 0, &size); std::vector<std::uint8_t> storage(size);
    auto* attributes = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage.data()); if (!InitializeProcThreadAttributeList(attributes, 1, 0, &size)) win_error("Status handle allowlist");
    struct Cleanup { LPPROC_THREAD_ATTRIBUTE_LIST value; ~Cleanup() { DeleteProcThreadAttributeList(value); } } cleanup{attributes};
    HANDLE handles[]{wr, null.get()}; if (!UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, handles, sizeof(handles), nullptr, nullptr)) win_error("Status handle allowlist");
    STARTUPINFOEXW startup{}; startup.StartupInfo.cb = sizeof(startup); startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES; startup.StartupInfo.hStdOutput = wr; startup.StartupInfo.hStdError = null.get(); startup.StartupInfo.hStdInput = null.get(); startup.lpAttributeList = attributes;
    auto command = command_line(executable, {L"--status-json", L"--expected-sid", std::wstring(sid)}); PROCESS_INFORMATION process{}; const auto cwd = system_directory();
    if (!CreateProcessW(executable.c_str(), command.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT, nullptr, cwd.c_str(), &startup.StartupInfo, &process)) win_error("Read native status");
    Handle child(process.hProcess), thread(process.hThread); writer = Handle{}; std::string result; const auto start = GetTickCount64();
    for (;;) {
        DWORD available{}; if (!PeekNamedPipe(rd, nullptr, 0, nullptr, &available, nullptr)) { if (GetLastError() != ERROR_BROKEN_PIPE) win_error("Peek status"); available = 0; }
        if (available) { std::array<char, 4096> buffer{}; DWORD got{}; if (!ReadFile(rd, buffer.data(), std::min<DWORD>(available, static_cast<DWORD>(buffer.size())), &got, nullptr)) win_error("Read status"); result.append(buffer.data(), got); if (result.size() > 1024 * 1024) { TerminateProcess(child.get(), 1); throw std::runtime_error("Status exceeds bound"); } continue; }
        if (WaitForSingleObject(child.get(), 20) == WAIT_OBJECT_0) {
            DWORD remaining{};
            if (PeekNamedPipe(rd, nullptr, 0, nullptr, &remaining, nullptr) && remaining) continue;
            break;
        }
        if (GetTickCount64() - start > 15000) { TerminateProcess(child.get(), 1); throw std::runtime_error("Status timed out"); }
    }
    DWORD code{}; if (!GetExitCodeProcess(child.get(), &code) || code != 0) throw std::runtime_error("Native status unavailable"); return result;
}
}
