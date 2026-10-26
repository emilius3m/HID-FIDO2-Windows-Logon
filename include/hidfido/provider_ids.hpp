#pragma once

#include <guiddef.h>

namespace hidfido {
// Stable COM identity for the experimental, fail-closed V2 provider.
inline constexpr GUID credential_provider_clsid{
    0x8b5d856b, 0xc940, 0x4afb, {0xa0, 0x50, 0x16, 0x7f, 0x5d, 0x4f, 0x75, 0xe2}};
inline constexpr wchar_t credential_provider_clsid_text[] =
    L"{8B5D856B-C940-4AFB-A050-167F5D4F75E2}";
}
