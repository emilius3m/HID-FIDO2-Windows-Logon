// Isolated, read-only COM check of the production DLL. Does not enumerate
// credentials, contact a key, request secrets, or register any component.
#include <windows.h>
#include <credentialprovider.h>
#include <wrl/client.h>
#include "hidfido/provider_ids.hpp"

#include <filesystem>
#include <iostream>
#include <stdexcept>

namespace {
using Microsoft::WRL::ComPtr;
void require(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
class Module {
public:
    explicit Module(const wchar_t* path) {
        require(std::filesystem::path(path).is_absolute(), "An absolute DLL path is required.");
        value = LoadLibraryExW(path, nullptr, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
        require(value != nullptr, "Production DLL or a trusted system dependency could not be loaded.");
    }
    ~Module() { if (value) FreeLibrary(value); }
    HMODULE value{};
};
void check(const wchar_t* path) {
    Module module(path);
    using GetClass = HRESULT (WINAPI*)(REFCLSID, REFIID, void**);
    using CanUnload = HRESULT (WINAPI*)();
    const auto get_class = reinterpret_cast<GetClass>(GetProcAddress(module.value, "DllGetClassObject"));
    const auto can_unload = reinterpret_cast<CanUnload>(GetProcAddress(module.value, "DllCanUnloadNow"));
    require(get_class && can_unload, "Required COM exports are missing.");
    require(!GetProcAddress(module.value, "DllRegisterServer"), "Unexpected self-registration export.");
    {
        ComPtr<IClassFactory> factory;
        require(SUCCEEDED(get_class(hidfido::credential_provider_clsid, IID_PPV_ARGS(&factory))), "COM class factory failed.");
        ComPtr<ICredentialProvider> provider;
        require(SUCCEEDED(factory->CreateInstance(nullptr, IID_PPV_ARGS(&provider))), "COM provider creation failed.");
        for (const auto scenario : {CPUS_LOGON, CPUS_UNLOCK_WORKSTATION}) {
            require(SUCCEEDED(provider->SetUsageScenario(scenario, 0)), "Required scenario was rejected.");
            DWORD count{};
            require(SUCCEEDED(provider->GetFieldDescriptorCount(&count)) && count > 0 && count <= 64,
                    "Invalid field descriptor count.");
            unsigned masked_fields{};
            for (DWORD i = 0; i < count; ++i) {
                CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* descriptor{};
                const auto hr = provider->GetFieldDescriptorAt(i, &descriptor);
                if (FAILED(hr) || !descriptor) {
                    if (descriptor) { CoTaskMemFree(descriptor->pszLabel); CoTaskMemFree(descriptor); }
                    throw std::runtime_error("Field descriptor query failed.");
                }
                if (descriptor->cpft == CPFT_PASSWORD_TEXT) ++masked_fields;
                CoTaskMemFree(descriptor->pszLabel);
                CoTaskMemFree(descriptor);
            }
            require(masked_fields == 1, "Expected exactly one masked PIN field.");
        }
    }
    require(can_unload() == S_OK, "COM references remained after the check.");
}
}
int wmain(int argc, wchar_t** argv) {
    if (argc != 2) { std::cerr << "Usage: provider-smoke <absolute production DLL path>\n"; return 1; }
    const auto hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) { std::cerr << "COM initialization failed.\n"; return 1; }
    int code = 1;
    try {
        check(argv[1]);
        std::cout << "Production COM check passed: LOGON/UNLOCK, fields and reference lifetime. No key, password or registration used.\n";
        code = 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; }
    CoUninitialize();
    return code;
}
