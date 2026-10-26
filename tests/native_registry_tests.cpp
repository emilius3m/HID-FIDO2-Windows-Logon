// Compile the actual Win32 implementation into this test translation unit so
// its private registry primitives can be exercised in an isolated HKCU tree.
// Production callers always use the default HKLM hive and fixed project paths;
// no runtime override, environment variable or test API ships in the app.
#include "../src/manager/deployment.cpp"
#include <iostream>

int main() {
    using namespace hidfido::management;
    const auto id = random_id(); const auto root = L"Software\\HidFidoNativeTests\\" + widen(id);
    const Expected entry{root + L"\\Provider", {{L"", L"Synthetic"}, {L"HidFidoDeploymentId", widen(id)}, {L"HidFidoReleaseId", std::wstring(64, L'a')}}, {}};
    const auto cleanup = [&] { RegDeleteTreeW(HKEY_CURRENT_USER, root.c_str()); };
    const auto rejects = [](auto&& work) { try { work(); } catch (const std::exception&) { return; } throw std::runtime_error("Registry ownership failure was not rejected"); };
    try {
        rejects([&] { assert_entry(entry, false, HKEY_CURRENT_USER); });
        assert_entry(entry, true, HKEY_CURRENT_USER);
        create_entry(entry, HKEY_CURRENT_USER); assert_entry(entry, false, HKEY_CURRENT_USER);
        rejects([&] { create_entry(entry, HKEY_CURRENT_USER); });
        const Expected foreign{entry.path, {{L"", L"Another provider"}}, {}};
        rejects([&] { delete_entry(foreign, HKEY_CURRENT_USER); });
        assert_entry(entry, false, HKEY_CURRENT_USER);
        {
            RegKey key; if (RegOpenKeyExW(HKEY_CURRENT_USER, entry.path.c_str(), 0, KEY_SET_VALUE | KEY_WOW64_64KEY, &key.h) != ERROR_SUCCESS) throw std::runtime_error("Fixture open failed");
            DWORD value = 1; RegSetValueExW(key.h, L"Unexpected", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&value), sizeof(value));
        }
        rejects([&] { delete_entry(entry, HKEY_CURRENT_USER); });
        {
            RegKey key; RegOpenKeyExW(HKEY_CURRENT_USER, entry.path.c_str(), 0, KEY_SET_VALUE | KEY_WOW64_64KEY, &key.h); RegDeleteValueW(key.h, L"Unexpected"); RegDeleteValueW(key.h, L"HidFidoReleaseId");
        }
        rejects([&] { assert_entry(entry, false, HKEY_CURRENT_USER); });
        assert_entry(entry, true, HKEY_CURRENT_USER); delete_entry(entry, HKEY_CURRENT_USER); delete_entry(entry, HKEY_CURRENT_USER);
        if (read_entry(entry.path, HKEY_CURRENT_USER).exists) throw std::runtime_error("Idempotent native deletion failed");
        cleanup(); std::cout << "Real Win32 registry primitives: exclusive creation, required fields, partial/idempotent removal and foreign-value preservation passed in private HKCU only.\n"; return 0;
    } catch (const std::exception& e) { cleanup(); std::cerr << e.what() << '\n'; return 1; }
}
