#pragma once

#include <exception>
#include <string>

namespace hidfido::ui {
// Italian, user-facing explanation of a failed FIDO2 or vault operation.
// Project exception texts never contain secret material by design.
std::wstring describe_failure(const std::exception& error);
// Italian explanation of a Win32 LogonUser failure during password checks.
std::wstring describe_logon_error(unsigned long code);
}
