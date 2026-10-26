#include "hidfido/logon_serialization.hpp"

#include <windows.h>
#include <ntsecapi.h>
#include <wincred.h>

#include <cstring>
#include <exception>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

namespace {
using namespace hidfido;

void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

template<class Action> void rejects(Action&& action, const char* message) {
    bool rejected{};
    try { action(); } catch (const std::exception&) { rejected = true; }
    require(rejected, message);
}

std::span<const std::uint8_t> utf16(std::wstring_view text) {
    return {reinterpret_cast<const std::uint8_t*>(text.data()), text.size() * sizeof(wchar_t)};
}

std::wstring_view text_at(std::span<const std::uint8_t> packed, const UNICODE_STRING& value) {
    const auto offset = reinterpret_cast<ULONG_PTR>(value.Buffer);
    require(value.Length == value.MaximumLength && value.Length % 2 == 0, "UNICODE_STRING lengths");
    require(offset >= sizeof(KERB_INTERACTIVE_UNLOCK_LOGON) && offset + value.Length <= packed.size(),
            "UNICODE_STRING offset outside the packed buffer");
    return {reinterpret_cast<const wchar_t*>(packed.data() + offset), value.Length / sizeof(wchar_t)};
}

void packing() {
    constexpr std::wstring_view domain = L"PC-UFFICIO", user = L"utente", password = L"Paèss w0rd!";
    for (const auto kind : {logon::Kind::interactive, logon::Kind::unlock}) {
        const auto packed = logon::pack_interactive_logon(kind, domain, user, utf16(password));
        require(packed.size() > sizeof(KERB_INTERACTIVE_UNLOCK_LOGON) + (domain.size() + user.size()) * 2,
                "Packed size");
        KERB_INTERACTIVE_UNLOCK_LOGON header{};
        std::memcpy(&header, packed.bytes().data(), sizeof(header));
        require(header.Logon.MessageType == (kind == logon::Kind::unlock ? KerbWorkstationUnlockLogon : KerbInteractiveLogon),
                "Message type");
        require(header.LogonId.LowPart == 0 && header.LogonId.HighPart == 0, "LogonId must be zero");
        require(text_at(packed.bytes(), header.Logon.LogonDomainName) == domain, "Domain");
        require(text_at(packed.bytes(), header.Logon.UserName) == user, "User");
        const auto protected_view = text_at(packed.bytes(), header.Logon.Password);
        require(protected_view != password, "Password exported in plaintext");
        std::wstring protected_text(protected_view);
        CRED_PROTECTION_TYPE protection{};
        require(CredIsProtectedW(protected_text.data(), &protection) && protection != CredUnprotected,
                "Serialized password is not CredProtect protected");
        DWORD required{};
        require(!CredUnprotectW(FALSE, protected_text.data(), static_cast<DWORD>(protected_text.size() + 1),
                               nullptr, &required) && GetLastError() == ERROR_INSUFFICIENT_BUFFER,
                "CredUnprotect size query");
        hidfido::password::SecureBytes plaintext(static_cast<std::size_t>(required) * sizeof(wchar_t));
        require(CredUnprotectW(FALSE, protected_text.data(), static_cast<DWORD>(protected_text.size() + 1),
                              reinterpret_cast<PWSTR>(plaintext.bytes().data()), &required),
                "CredUnprotect roundtrip");
        require(std::wstring_view(reinterpret_cast<PCWSTR>(plaintext.bytes().data())) == password,
                "Protected password roundtrip mismatch");
    }
    rejects([] { (void)logon::pack_interactive_logon(logon::Kind::interactive, L"", L"u", utf16(L"p")); }, "Empty domain");
    rejects([] { (void)logon::pack_interactive_logon(logon::Kind::interactive, L"d", L"", utf16(L"p")); }, "Empty user");
    rejects([] { (void)logon::pack_interactive_logon(logon::Kind::interactive, L"d", L"u", {}); }, "Empty password");
    const std::uint8_t odd[3]{1, 2, 3};
    rejects([&] { (void)logon::pack_interactive_logon(logon::Kind::interactive, L"d", L"u", odd); }, "Odd password");
    const std::wstring nul(L"u\0x", 3);
    rejects([&] { (void)logon::pack_interactive_logon(logon::Kind::interactive, L"d", nul, utf16(L"p")); }, "NUL user");
}

void results() {
    constexpr auto code = [](std::uint32_t value) { return static_cast<std::int32_t>(value); };
    const auto success = logon::advise_logon_result(0, 0);
    require(success.success && !success.suspend_record && success.message.empty(), "Success advice");

    for (const auto& [status, substatus] : {std::pair{code(0xC000006D), code(0xC000006A)},
                                            std::pair{code(0xC000006D), 0},
                                            std::pair{code(0xC000006A), 0},
                                            std::pair{code(0xC0000071), 0},
                                            std::pair{code(0xC0000224), 0},
                                            std::pair{code(0xC000006E), code(0xC0000071)}}) {
        const auto advice = logon::advise_logon_result(status, substatus);
        require(!advice.success && advice.suspend_record, "Password rejection must suspend the record");
        require(advice.message.find(L"password") != std::wstring::npos && advice.message.find(L"--update-password") == std::wstring::npos, "Missing user-facing password recovery instructions");
    }
    for (const auto& [status, substatus] : {std::pair{code(0xC0000234), 0},
                                            std::pair{code(0xC0000072), 0},
                                            std::pair{code(0xC0000193), 0},
                                            std::pair{code(0xC000015B), 0},
                                            std::pair{code(0xC000006E), code(0xC000006F)},
                                            std::pair{code(0xC000006D), code(0xC0000064)},
                                            std::pair{code(0xC0000001), 0}}) {
        const auto advice = logon::advise_logon_result(status, substatus);
        require(!advice.success && !advice.suspend_record && !advice.message.empty(),
                "Account-state rejection must not suspend the stored password");
    }
    require(logon::advise_logon_result(code(0xC0000001), 0).message.find(L"0xC0000001") != std::wstring::npos,
            "Unknown status code not reported");
}
}

int main() {
    try {
        packing();
        results();
        std::cout << "Logon serialization tests passed.\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
