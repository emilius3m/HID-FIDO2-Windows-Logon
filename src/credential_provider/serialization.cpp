#include "hidfido/localization.hpp"
#include "hidfido/logon_serialization.hpp"

#include <windows.h>
#include <ntsecapi.h>
#include <wincred.h>

#include <cstring>
#include <cwchar>
#include <stdexcept>

namespace hidfido::logon {
namespace {
using hidfido::ui::tr;
// NTSTATUS values reported to ICredentialProviderCredential::ReportResult.
constexpr std::int32_t status_no_such_user = static_cast<std::int32_t>(0xC0000064);
constexpr std::int32_t status_wrong_password = static_cast<std::int32_t>(0xC000006A);
constexpr std::int32_t status_logon_failure = static_cast<std::int32_t>(0xC000006D);
constexpr std::int32_t status_account_restriction = static_cast<std::int32_t>(0xC000006E);
constexpr std::int32_t status_invalid_logon_hours = static_cast<std::int32_t>(0xC000006F);
constexpr std::int32_t status_invalid_workstation = static_cast<std::int32_t>(0xC0000070);
constexpr std::int32_t status_password_expired = static_cast<std::int32_t>(0xC0000071);
constexpr std::int32_t status_account_disabled = static_cast<std::int32_t>(0xC0000072);
constexpr std::int32_t status_logon_type_not_granted = static_cast<std::int32_t>(0xC000015B);
constexpr std::int32_t status_account_expired = static_cast<std::int32_t>(0xC0000193);
constexpr std::int32_t status_password_must_change = static_cast<std::int32_t>(0xC0000224);
constexpr std::int32_t status_account_locked_out = static_cast<std::int32_t>(0xC0000234);

const wchar_t* update_hint() { return
    tr(L" L'accesso con la chiave è sospeso: entra con la password Windows ed esegui hid-fido2-vault --update-password da un terminale amministratore."); }

void set_string(UNICODE_STRING& target, std::size_t offset, std::size_t bytes) {
    target.Length = static_cast<USHORT>(bytes);
    target.MaximumLength = static_cast<USHORT>(bytes);
    target.Buffer = reinterpret_cast<PWSTR>(static_cast<ULONG_PTR>(offset));
}

std::wstring hex(std::int32_t value) {
    wchar_t text[16]{};
    swprintf_s(text, L"0x%08X", static_cast<unsigned>(value));
    return text;
}

password::SecureBytes protected_password(std::span<const std::uint8_t> password_utf16) {
    password::SecureBytes terminated(password_utf16.size() + sizeof(wchar_t));
    std::memcpy(terminated.bytes().data(), password_utf16.data(), password_utf16.size());
    auto* input = reinterpret_cast<PWSTR>(terminated.bytes().data());
    const auto characters = static_cast<DWORD>(password_utf16.size() / sizeof(wchar_t) + 1);
    DWORD capacity{};
    CRED_PROTECTION_TYPE protection{};
    if (CredProtectW(FALSE, input, characters, nullptr, &capacity, &protection) ||
        GetLastError() != ERROR_INSUFFICIENT_BUFFER || capacity < 2 || capacity > 32768) {
        throw std::runtime_error("Cannot determine protected Windows credential size");
    }
    password::SecureBytes output(static_cast<std::size_t>(capacity) * sizeof(wchar_t));
    auto* text = reinterpret_cast<PWSTR>(output.bytes().data());
    if (!CredProtectW(FALSE, input, characters, text, &capacity, &protection)) {
        throw std::runtime_error("Cannot protect Windows credential for LogonUI");
    }
    terminated.clear();
    const auto units = wcsnlen_s(text, output.size() / sizeof(wchar_t));
    if (units == 0 || units == output.size() / sizeof(wchar_t) || units * sizeof(wchar_t) > 0xfffe ||
        !CredIsProtectedW(text, &protection) || protection == CredUnprotected) {
        throw std::runtime_error("Windows returned an invalid protected credential");
    }
    password::SecureBytes result(units * sizeof(wchar_t));
    std::memcpy(result.bytes().data(), output.bytes().data(), result.size());
    return result;
}
}

password::SecureBytes pack_interactive_logon(Kind kind, std::wstring_view domain, std::wstring_view user,
                                             std::span<const std::uint8_t> password_utf16) {
    constexpr std::size_t limit = 0xfffe;
    const auto domain_bytes = domain.size() * sizeof(wchar_t);
    const auto user_bytes = user.size() * sizeof(wchar_t);
    if (domain.empty() || user.empty() || domain_bytes > limit || user_bytes > limit ||
        domain.find(L'\0') != std::wstring_view::npos || user.find(L'\0') != std::wstring_view::npos) {
        throw std::invalid_argument("Invalid logon domain or user name");
    }
    if (password_utf16.empty() || password_utf16.size() % sizeof(wchar_t) != 0 || password_utf16.size() > limit) {
        throw std::invalid_argument("Invalid logon password length");
    }
    for (std::size_t offset = 0; offset < password_utf16.size(); offset += sizeof(wchar_t)) {
        if (password_utf16[offset] == 0 && password_utf16[offset + 1] == 0) {
            throw std::invalid_argument("Windows password contains NUL");
        }
    }
    auto protected_utf16 = protected_password(password_utf16);
    KERB_INTERACTIVE_UNLOCK_LOGON header{};
    header.Logon.MessageType = kind == Kind::unlock ? KerbWorkstationUnlockLogon : KerbInteractiveLogon;
    std::size_t offset = sizeof(header);
    set_string(header.Logon.LogonDomainName, offset, domain_bytes);
    offset += domain_bytes;
    set_string(header.Logon.UserName, offset, user_bytes);
    offset += user_bytes;
    set_string(header.Logon.Password, offset, protected_utf16.size());
    offset += protected_utf16.size();

    password::SecureBytes packed(offset);
    auto* output = packed.bytes().data();
    std::memcpy(output, &header, sizeof(header));
    std::memcpy(output + sizeof(header), domain.data(), domain_bytes);
    std::memcpy(output + sizeof(header) + domain_bytes, user.data(), user_bytes);
    std::memcpy(output + sizeof(header) + domain_bytes + user_bytes,
                protected_utf16.bytes().data(), protected_utf16.size());
    return packed;
}

ResultAdvice advise_logon_result(std::int32_t status, std::int32_t substatus) {
    ResultAdvice advice;
    if (status >= 0) {
        advice.success = true;
        return advice;
    }
    // Password-related rejections suspend the record: replaying the same stored
    // password could only add failed attempts toward an account lockout.
    const auto password_problem = [&](std::int32_t code) {
        return code == status_wrong_password || code == status_password_expired || code == status_password_must_change;
    };
    if (status == status_password_expired || status == status_password_must_change ||
        (status == status_account_restriction && password_problem(substatus))) {
        advice.suspend_record = true;
        advice.message = std::wstring(tr(L"La password Windows è scaduta o deve essere cambiata: cambiala con l'opzione password standard.")) + update_hint();
        return advice;
    }
    if (status == status_wrong_password || (status == status_logon_failure && substatus != status_no_such_user)) {
        advice.suspend_record = true;
        advice.message = std::wstring(tr(L"Windows ha rifiutato la password memorizzata: probabilmente è stata cambiata.")) + update_hint();
        return advice;
    }
    if (status == status_account_locked_out) {
        advice.message = tr(L"Account Windows bloccato per troppi tentativi. Attendi o rivolgiti a un amministratore.");
    } else if (status == status_account_disabled) {
        advice.message = tr(L"Account Windows disabilitato.");
    } else if (status == status_account_expired) {
        advice.message = tr(L"Account Windows scaduto.");
    } else if (status == status_logon_type_not_granted) {
        advice.message = tr(L"L'account non ha il diritto di accesso locale a questo computer.");
    } else if (status == status_account_restriction &&
               (substatus == status_invalid_logon_hours || substatus == status_invalid_workstation)) {
        advice.message = tr(L"Accesso non consentito in questo orario o da questo computer.");
    } else if (status == status_logon_failure) {
        advice.message = tr(L"Account Windows non trovato.");
    } else {
        advice.message = tr(L"Accesso rifiutato da Windows (codice ") + hex(status) + L").";
    }
    return advice;
}
}
