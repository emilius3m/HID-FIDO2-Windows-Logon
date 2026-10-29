#include "hidfido/package_trust.hpp"
#include <windows.h>
#include <shellapi.h>
#include <array>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
using namespace hidfido::installer;
void require(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
template<class Work> void rejects(Work&& work, const char* message) {
    try { work(); } catch (const std::exception&) { return; }
    throw std::runtime_error(message);
}
std::span<const std::uint8_t> bytes(std::string_view value) {
    return {reinterpret_cast<const std::uint8_t*>(value.data()), value.size()};
}
std::string manifest(std::string_view version = "0.6.0") {
    const std::string hash(64, 'a');
    std::string identity = "HID-FIDO2-WinLogon/release/1\n" + std::string(version) + "\n8664";
    std::string files;
    for (const auto path : native_payload_paths()) {
        identity += "\n" + std::string(path) + "=" + hash;
        if (!files.empty()) files += ',';
        files += "{\"Path\":\"" + std::string(path) + "\",\"Length\":7,\"Sha256\":\"" + hash + "\"}";
    }
    return "{\"Schema\":1,\"ProjectId\":\"HID-FIDO2-WinLogon\",\"ProviderClsid\":\"{8B5D856B-C940-4AFB-A050-167F5D4F75E2}\","
        "\"Architecture\":\"8664\",\"VaultSchema\":2,\"Version\":\"" + std::string(version) +
        "\",\"ReleaseId\":\"" + sha256_hex(bytes(identity)) + "\",\"Files\":[" + files + "]}";
}
void replace(std::string& value, std::string_view from, std::string_view to) {
    const auto at = value.find(from); require(at != std::string::npos, "Fixture field missing");
    value.replace(at, from.size(), to);
}
void parser() {
    const auto good = manifest();
    const auto parsed = parse_manifest(bytes(good));
    require(parsed.version == "0.6.0" && parsed.files.size() == native_payload_paths().size(), "Valid manifest not decoded");
    auto duplicate = good; duplicate.insert(1, "\"Schema\":1,");
    rejects([&] { parse_manifest(bytes(duplicate)); }, "Duplicate manifest member accepted");
    auto escaped_duplicate = good; escaped_duplicate.insert(1, "\"\\u0053chema\":1,");
    rejects([&] { parse_manifest(bytes(escaped_duplicate)); }, "Escaped duplicate member accepted");
    auto unknown = good; replace(unknown, "Gestione-HID-FIDO2.exe", "../other/manager.exe");
    rejects([&] { parse_manifest(bytes(unknown)); }, "Path traversal accepted");
    auto wrong_hash = good; replace(wrong_hash, "\"Length\":7", "\"Length\":0");
    rejects([&] { parse_manifest(bytes(wrong_hash)); }, "Zero length accepted");
    auto wrong_identity = good; replace(wrong_identity, "\"Version\":\"0.6.0\"", "\"Version\":\"0.6.1\"");
    rejects([&] { parse_manifest(bytes(wrong_identity)); }, "Manifest identity not authenticated by hashes");
    auto old_schema = good; replace(old_schema, "\"VaultSchema\":2", "\"VaultSchema\":1");
    rejects([&] { parse_manifest(bytes(old_schema)); }, "Legacy format accepted by new bootstrap");
    auto duplicate_path = good; replace(duplicate_path, "Gestione-HID-FIDO2.exe", "bin/provider-smoke.exe");
    rejects([&] { parse_manifest(bytes(duplicate_path)); }, "Duplicate payload accepted");
    auto overflow = good; replace(overflow, "\"Length\":7", "\"Length\":18446744073709551616");
    rejects([&] { parse_manifest(bytes(overflow)); }, "Integer overflow accepted");
    auto trailing = good + "false";
    rejects([&] { parse_manifest(bytes(trailing)); }, "Trailing data accepted");
    rejects([&] { parse_manifest(bytes(std::string(1024 * 1024 + 1, ' '))); }, "Oversize manifest accepted");
    std::string deep(20, '['); deep += "0"; deep += std::string(20, ']');
    rejects([&] { parse_manifest(bytes(deep)); }, "Excessive nesting accepted");
}
void quoting_and_pin() {
    for (const std::wstring value : {L"", L"C:\\Program Files\\HID FIDO2\\", L"a\\\"b", L"a b", L"plain"}) {
        const auto command = L"example.exe " + quote_argument(value);
        int count{}; auto** arguments = CommandLineToArgvW(command.c_str(), &count);
        require(arguments && count == 2, "Quoted command did not parse");
        const bool same = arguments[1] == value; LocalFree(arguments);
        require(same, "Windows argument roundtrip changed content");
    }
    require(valid_signer_pin(std::string(64, 'a')), "Lowercase signer pin rejected");
    require(valid_signer_pin(std::string(64, 'A')), "Uppercase signer pin rejected");
    require(!valid_signer_pin("") && !valid_signer_pin(std::string(63, 'a')) &&
            !valid_signer_pin(std::string(64, 'z')), "Invalid signer pin accepted");
    require(sha256_hex(bytes("abc")) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "Native SHA256 differs from known vector");
}
void missing_package() {
    const auto missing = std::filesystem::temp_directory_path() /
        (L"hidfido-bootstrap-missing-" + std::to_wstring(GetCurrentProcessId()));
    rejects([&] { PinnedPackage value(missing, {}, true); }, "Missing package accepted");
    rejects([&] { PinnedPackage value(missing, {}, false); }, "Signed profile accepted no pin");
    rejects([&] { PinnedPackage value(missing, std::string(64, 'a'), true); }, "Prototype accepted a signed-profile pin");
}
void pinned_source_fixture() {
    // A private, unprivileged fixture. The executable is copied as data only;
    // no fixture PE or package is ever launched or installed.
    const auto temporary = std::filesystem::canonical(std::filesystem::temp_directory_path());
    const auto directory = temporary / (L"hidfido-bootstrap-fixture-" + std::to_wstring(GetCurrentProcessId()) +
                                        L"-" + std::to_wstring(GetTickCount64()));
    require(std::filesystem::create_directory(directory), "Fixture directory already exists");
    const auto cleanup = [&] {
        if (!std::filesystem::exists(directory)) return;
        const auto actual = std::filesystem::canonical(directory);
        require(CompareStringOrdinal(actual.c_str(), -1, directory.c_str(), -1, TRUE) == CSTR_EQUAL,
                "Fixture cleanup path was replaced");
        std::filesystem::remove_all(directory);
    };
    try {
        std::filesystem::create_directory(directory / L"bin");
        std::wstring module(32768, L'\0');
        const auto length = GetModuleFileNameW(nullptr, module.data(), static_cast<DWORD>(module.size()));
        require(length && length < module.size(), "Test executable path unavailable"); module.resize(length);
        std::ifstream executable(std::filesystem::path(module), std::ios::binary);
        const std::vector<std::uint8_t> pe((std::istreambuf_iterator<char>(executable)), {});
        require(!pe.empty(), "Cannot read test executable as data");
        std::string entries, identity = "HID-FIDO2-WinLogon/release/1\n0.6.0\n8664";
        const auto write = [](const std::filesystem::path& path, std::span<const std::uint8_t> data) {
            std::ofstream file(path, std::ios::binary | std::ios::trunc);
            file.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
            require(file.good(), "Fixture write failed");
        };
        for (const auto path : native_payload_paths()) {
            const auto content = std::span<const std::uint8_t>(pe);
            write(directory / std::filesystem::path(path), content);
            const auto hash = sha256_hex(content); identity += "\n" + std::string(path) + "=" + hash;
            if (!entries.empty()) entries += ',';
            entries += "{\"Path\":\"" + std::string(path) + "\",\"Length\":" + std::to_string(content.size()) +
                       ",\"Sha256\":\"" + hash + "\"}";
        }
        const auto document = "{\"Schema\":1,\"ProjectId\":\"HID-FIDO2-WinLogon\",\"ProviderClsid\":\"{8B5D856B-C940-4AFB-A050-167F5D4F75E2}\","
            "\"Architecture\":\"8664\",\"VaultSchema\":2,\"Version\":\"0.6.0\",\"ReleaseId\":\"" +
            sha256_hex(bytes(identity)) + "\",\"Files\":[" + entries + "]}";
        write(directory / L"release.json", bytes(document));
        {
            PinnedPackage package(directory, {}, true);
            const auto protected_file = directory / L"Gestione-HID-FIDO2.exe";
            const auto writer = CreateFileW(protected_file.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                            nullptr, OPEN_EXISTING, 0, nullptr);
            require(writer == INVALID_HANDLE_VALUE && GetLastError() == ERROR_SHARING_VIOLATION,
                    "A verified source file remained writable during elevation");
            require(!MoveFileExW(protected_file.c_str(), (directory / L"changed.exe").c_str(), 0),
                    "A verified source file remained replaceable during elevation");
        }
        write(directory / L"unexpected.txt", bytes("inert fixture"));
        rejects([&] { PinnedPackage package(directory, {}, true); }, "Unexpected payload accepted");
        std::filesystem::remove(directory / L"unexpected.txt");
        write(directory / L"Gestione-HID-FIDO2.exe", bytes("tampered"));
        rejects([&] { PinnedPackage package(directory, {}, true); }, "Altered source file accepted");
    } catch (...) { cleanup(); throw; }
    cleanup();
}
}
int wmain(int count, wchar_t** arguments) {
    try {
        if (count == 3 && std::wstring_view(arguments[1]) == L"--verify-local-release") {
            PinnedPackage package(arguments[2], {}, true);
            std::cout << "Verified local release " << package.manifest().version << " " << package.manifest().release_id << '\n';
            return 0;
        }
        require(count == 1, "Unknown verification arguments");
        parser(); quoting_and_pin(); missing_package(); pinned_source_fixture();
        std::cout << "Installer bootstrap: bounded manifest, payload allowlist, identities, signer policy and quoting passed.\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
