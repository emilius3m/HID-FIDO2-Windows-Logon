#pragma once
#include <string>

namespace hidfido {
// Canonical SID of the current Windows token. No account data is persisted.
std::wstring current_user_sid();
}
