// SPDX-License-Identifier: MIT
// COM contract tests in this executable only. No COM/LogonUI registration is used.
#include "hidfido/machine_vault.hpp"
#include "hidfido/provider_ids.hpp"
#include "hidfido/account.hpp"

#include <windows.h>
#include <initguid.h>
#include <credentialprovider.h>
#include <ntsecapi.h>
#include <wincred.h>
#include <shlguid.h>
#include <wrl/client.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstring>
#include <cwchar>
#include <filesystem>
#include <functional>
#include <span>
#include <tuple>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>

namespace {
using Microsoft::WRL::ComPtr;

void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}
void succeeds(HRESULT result, const char* message) { require(result == S_OK, message); }

HRESULT duplicate(PCWSTR text, PWSTR* output) {
    if (!output) return E_POINTER;
    *output = nullptr;
    const auto bytes = (std::wcslen(text) + 1) * sizeof(wchar_t);
    *output = static_cast<PWSTR>(CoTaskMemAlloc(bytes));
    if (!*output) return E_OUTOFMEMORY;
    std::memcpy(*output, text, bytes);
    return S_OK;
}

class FakeUser final : public ICredentialProviderUser {
public:
    FakeUser(PCWSTR sid, GUID identity) noexcept : sid_(sid), identity_(identity) {}
    IFACEMETHODIMP QueryInterface(REFIID iid, void** output) override {
        if (!output) return E_POINTER;
        *output = nullptr;
        if (iid != IID_IUnknown && iid != __uuidof(ICredentialProviderUser)) return E_NOINTERFACE;
        *output = static_cast<ICredentialProviderUser*>(this);
        AddRef();
        return S_OK;
    }
    IFACEMETHODIMP_(ULONG) AddRef() override { return ++references_; }
    IFACEMETHODIMP_(ULONG) Release() override {
        const ULONG left = --references_;
        if (!left) delete this;
        return left;
    }
    IFACEMETHODIMP GetSid(PWSTR* output) override { return duplicate(sid_, output); }
    IFACEMETHODIMP GetProviderID(GUID* output) override {
        if (!output) return E_POINTER;
        *output = identity_;
        return S_OK;
    }
    IFACEMETHODIMP GetStringValue(REFPROPERTYKEY, PWSTR* output) override {
        if (!output) return E_POINTER;
        *output = nullptr;
        return E_NOTIMPL;
    }
    IFACEMETHODIMP GetValue(REFPROPERTYKEY, PROPVARIANT* output) override {
        if (!output) return E_POINTER;
        *output = {};
        return E_NOTIMPL;
    }
private:
    std::atomic<ULONG> references_{1};
    PCWSTR sid_;
    GUID identity_;
};

class FakeUsers final : public ICredentialProviderUserArray {
public:
    FakeUsers() {
        users_[0].Attach(new FakeUser(L"S-1-5-21-111-222-333-1001", Identity_LocalUserProvider));
        users_[1].Attach(new FakeUser(L"S-1-5-21-111-222-333-1002", Identity_LocalUserProvider));
        users_[2].Attach(new FakeUser(L"S-1-5-21-444-555-666-1003", GUID{}));
    }
    IFACEMETHODIMP QueryInterface(REFIID iid, void** output) override {
        if (!output) return E_POINTER;
        *output = nullptr;
        if (iid != IID_IUnknown && iid != __uuidof(ICredentialProviderUserArray)) return E_NOINTERFACE;
        *output = static_cast<ICredentialProviderUserArray*>(this);
        AddRef();
        return S_OK;
    }
    IFACEMETHODIMP_(ULONG) AddRef() override { return ++references_; }
    IFACEMETHODIMP_(ULONG) Release() override {
        const ULONG left = --references_;
        if (!left) delete this;
        return left;
    }
    IFACEMETHODIMP SetProviderFilter(REFGUID) override {
        ++filter_calls;
        return E_NOTIMPL;
    }
    IFACEMETHODIMP GetAccountOptions(CREDENTIAL_PROVIDER_ACCOUNT_OPTIONS* output) override {
        if (!output) return E_POINTER;
        *output = CPAO_NONE;
        return S_OK;
    }
    IFACEMETHODIMP GetCount(DWORD* output) override {
        if (!output) return E_POINTER;
        *output = advertised_count;
        return count_result;
    }
    IFACEMETHODIMP GetAt(DWORD index, ICredentialProviderUser** output) override {
        if (!output) return E_POINTER;
        *output = nullptr;
        if (index >= users_.size()) return E_INVALIDARG;
        if (index == failed_index) return E_ACCESSDENIED;
        return users_[index].CopyTo(output);
    }
    void replace_first_sid(PCWSTR sid) {
        users_[0].Attach(new FakeUser(sid, Identity_LocalUserProvider));
    }
    DWORD filter_calls{};
    DWORD advertised_count{3};
    DWORD failed_index{MAXDWORD};
    HRESULT count_result{S_OK};
private:
    std::atomic<ULONG> references_{1};
    std::array<ComPtr<ICredentialProviderUser>, 3> users_;
};

class FakeQuery final : public IQueryContinueWithStatus {
public:
    IFACEMETHODIMP QueryInterface(REFIID iid, void** output) override {
        if (!output) return E_POINTER;
        *output = nullptr;
        if (iid != IID_IUnknown && iid != __uuidof(IQueryContinue) &&
            iid != __uuidof(IQueryContinueWithStatus)) return E_NOINTERFACE;
        *output = static_cast<IQueryContinueWithStatus*>(this);
        AddRef();
        return S_OK;
    }
    IFACEMETHODIMP_(ULONG) AddRef() override { return ++references_; }
    IFACEMETHODIMP_(ULONG) Release() override {
        const auto left = --references_;
        if (!left) delete this;
        return left;
    }
    IFACEMETHODIMP QueryContinue() override { return ++calls > cancel_after ? S_FALSE : S_OK; }
    IFACEMETHODIMP SetStatusMessage(LPCWSTR) override { return S_OK; }
    std::atomic<unsigned> calls{};
    unsigned cancel_after{MAXDWORD};
private:
    std::atomic<ULONG> references_{1};
};

class FakeProviderEvents final : public ICredentialProviderEvents {
public:
    IFACEMETHODIMP QueryInterface(REFIID iid, void** output) override {
        if (!output) return E_POINTER;
        *output = nullptr;
        if (iid != IID_IUnknown && iid != __uuidof(ICredentialProviderEvents)) return E_NOINTERFACE;
        *output = static_cast<ICredentialProviderEvents*>(this); AddRef(); return S_OK;
    }
    IFACEMETHODIMP_(ULONG) AddRef() override { return ++references_; }
    IFACEMETHODIMP_(ULONG) Release() override {
        const auto left = --references_; if (!left) delete this; return left;
    }
    IFACEMETHODIMP CredentialsChanged(UINT_PTR context) override {
        wrong_thread = wrong_thread || GetCurrentThreadId() != apartment_thread;
        wrong_context = wrong_context || context != 0x5678;
        ++calls;
        return S_OK;
    }
    const DWORD apartment_thread{GetCurrentThreadId()};
    unsigned calls{};
    bool wrong_thread{}, wrong_context{};
private:
    std::atomic<ULONG> references_{1};
};

class FakeCredentialEvents final : public ICredentialProviderCredentialEvents {
public:
    IFACEMETHODIMP QueryInterface(REFIID iid, void** output) override {
        if (!output) return E_POINTER;
        *output = nullptr;
        if (iid != IID_IUnknown && iid != __uuidof(ICredentialProviderCredentialEvents)) return E_NOINTERFACE;
        *output = static_cast<ICredentialProviderCredentialEvents*>(this); AddRef(); return S_OK;
    }
    IFACEMETHODIMP_(ULONG) AddRef() override { return ++references_; }
    IFACEMETHODIMP_(ULONG) Release() override {
        const auto left = --references_; if (!left) delete this; return left;
    }
    IFACEMETHODIMP SetFieldString(ICredentialProviderCredential*, DWORD, LPCWSTR) override {
        ++calls;
        wrong_thread = wrong_thread || GetCurrentThreadId() != apartment_thread;
        auto callback = std::move(on_set); // One re-entrant callback, including nested field updates.
        if (callback) callback();
        return S_OK;
    }
    IFACEMETHODIMP SetFieldState(ICredentialProviderCredential*, DWORD, CREDENTIAL_PROVIDER_FIELD_STATE) override { return S_OK; }
    IFACEMETHODIMP SetFieldInteractiveState(ICredentialProviderCredential*, DWORD, CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE) override { return S_OK; }
    IFACEMETHODIMP SetFieldCheckbox(ICredentialProviderCredential*, DWORD, BOOL, LPCWSTR) override { return S_OK; }
    IFACEMETHODIMP SetFieldBitmap(ICredentialProviderCredential*, DWORD, HBITMAP) override { return S_OK; }
    IFACEMETHODIMP SetFieldComboBoxSelectedItem(ICredentialProviderCredential*, DWORD, DWORD) override { return S_OK; }
    IFACEMETHODIMP DeleteFieldComboBoxItem(ICredentialProviderCredential*, DWORD, DWORD) override { return S_OK; }
    IFACEMETHODIMP AppendFieldComboBoxItem(ICredentialProviderCredential*, DWORD, LPCWSTR) override { return S_OK; }
    IFACEMETHODIMP SetFieldSubmitButton(ICredentialProviderCredential*, DWORD, DWORD) override { return S_OK; }
    IFACEMETHODIMP OnCreatingWindow(HWND* output) override {
        if (!output) return E_POINTER; *output = nullptr; return S_OK;
    }
    const DWORD apartment_thread{GetCurrentThreadId()};
    unsigned calls{};
    bool wrong_thread{};
    std::function<void()> on_set;
private:
    std::atomic<ULONG> references_{1};
};

void pump_until(const std::function<bool()>& done) {
    const auto deadline = GetTickCount64() + 4000;
    while (!done()) {
        MSG message{};
        while (PeekMessageW(&message, nullptr, 0, 0, PM_REMOVE)) {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
        require(GetTickCount64() < deadline, "Asynchronous credential operation did not finish");
        Sleep(1);
    }
}

constexpr DWORD pin_field = 4;
constexpr DWORD status_field = 6;

std::wstring string_value(ICredentialProviderCredential* credential, DWORD field) {
    PWSTR text = nullptr;
    succeeds(credential->GetStringValue(field, &text), "Field text unavailable");
    std::wstring result = text ? text : L"";
    CoTaskMemFree(text);
    return result;
}

// Every call here must be refused locally, before any authenticator access:
// never pass a well-formed PIN for an active (non-suspended) tile.
void check_refusal(ICredentialProviderCredential* credential, PCWSTR typed_pin, PCWSTR expected) {
    if (typed_pin) succeeds(credential->SetStringValue(pin_field, typed_pin), "PIN field rejected");
    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE response = CPGSR_RETURN_CREDENTIAL_FINISHED;
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION serialization;
    std::memset(&serialization, 0xff, sizeof(serialization));
    PWSTR text = nullptr;
    CREDENTIAL_PROVIDER_STATUS_ICON icon = CPSI_SUCCESS;
    succeeds(credential->GetSerialization(&response, &serialization, &text, &icon),
             "GetSerialization failed");
    require(response == CPGSR_NO_CREDENTIAL_NOT_FINISHED, "Provider submitted a credential");
    require(serialization.ulAuthenticationPackage == 0 && serialization.cbSerialization == 0 &&
            serialization.rgbSerialization == nullptr && serialization.clsidCredentialProvider == GUID{},
            "Refusal contains credentials or an authentication package");
    const bool explained = text && std::wstring(text).find(expected) != std::wstring::npos;
    CoTaskMemFree(text);
    require(explained && icon == CPSI_ERROR, "Missing or unexpected refusal explanation");
    require(string_value(credential, pin_field).empty(), "PIN echoed back to LogonUI");

    std::memset(&serialization, 0xff, sizeof(serialization));
    icon = CPSI_SUCCESS;
    require(credential->GetSerialization(nullptr, &serialization, &text, &icon) == E_POINTER,
            "Null response accepted");
    require(text == nullptr && serialization.cbSerialization == 0 &&
            serialization.rgbSerialization == nullptr && icon == CPSI_ERROR,
            "Malformed call retained credential data");

    // Without a submitted credential, a logon result changes nothing.
    text = reinterpret_cast<PWSTR>(1);
    icon = CPSI_ERROR;
    succeeds(credential->ReportResult(static_cast<NTSTATUS>(0xC000006D), static_cast<NTSTATUS>(0xC000006A), &text, &icon),
             "ReportResult failed");
    require(text == nullptr && icon == CPSI_NONE, "Result reported without a submitted credential");
}

void check_tile(ICredentialProvider* provider, DWORD index, PCWSTR expected_sid, bool suspended) {
    ComPtr<ICredentialProviderCredential> credential;
    succeeds(provider->GetCredentialAt(index, &credential), "Tile unavailable");
    ComPtr<ICredentialProviderCredential2> credential2;
    succeeds(credential.As(&credential2), "Not a V2 credential");
    ComPtr<IConnectableCredentialProviderCredential> plap;
    require(credential.As(&plap) == E_NOINTERFACE, "LOGON credential exposes the PLAP Connect contract");
    PWSTR sid = nullptr;
    succeeds(credential2->GetUserSid(&sid), "GetUserSid failed");
    const bool matches = sid && std::wcscmp(sid, expected_sid) == 0;
    CoTaskMemFree(sid);
    require(matches, "Tile associated with the wrong SID");
    require(credential2->GetUserSid(nullptr) == E_POINTER, "Null SID output accepted");

    BOOL auto_logon = TRUE;
    succeeds(credential->SetSelected(&auto_logon), "Selection failed");
    require(auto_logon == FALSE, "Selection requests automatic logon");
    require(credential->SetSelected(nullptr) == E_POINTER, "Null selection output accepted");
    succeeds(credential->SetDeselected(), "Deselection failed");

    DWORD count = 0;
    succeeds(provider->GetFieldDescriptorCount(&count), "Field count failed");
    require(count >= 5 && count <= 10, "Unexpected field count");
    DWORD submit_id = MAXDWORD, password_fields = 0;
    for (DWORD field = 0; field < count; ++field) {
        CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* descriptor = nullptr;
        succeeds(provider->GetFieldDescriptorAt(field, &descriptor), "Descriptor failed");
        require(descriptor && descriptor->dwFieldID == field && descriptor->pszLabel,
                "Invalid descriptor identity");
        const auto type = descriptor->cpft;
        const auto purpose = descriptor->guidFieldType;
        CoTaskMemFree(descriptor->pszLabel);
        CoTaskMemFree(descriptor);
        require(type != CPFT_EDIT_TEXT, "Provider collects a visible text input");
        if (type == CPFT_PASSWORD_TEXT) {
            ++password_fields;
            require(field == pin_field, "Unexpected masked field");
        }
        CREDENTIAL_PROVIDER_FIELD_STATE state{};
        CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE interactive{};
        succeeds(credential->GetFieldState(field, &state, &interactive), "Field state failed");
        require(state != CPFS_HIDDEN, "Unexpected hidden field");
        require(interactive == (field == pin_field ? CPFIS_FOCUSED : CPFIS_NONE), "Unexpected focus");
        if (type == CPFT_TILE_IMAGE) {
            require(purpose == CPFG_CREDENTIAL_PROVIDER_LOGO, "Missing V2 logo purpose");
            HBITMAP bitmap = nullptr;
            succeeds(credential->GetBitmapValue(field, &bitmap), "Logo unavailable");
            BITMAP details{};
            const bool correct_size = GetObjectW(bitmap, static_cast<int>(sizeof(details)), &details) ==
                                      static_cast<int>(sizeof(details)) &&
                                      details.bmWidth == 128 && details.bmHeight == 128 &&
                                      details.bmBitsPixel == 32 && details.bmBits;
            bool transparent_corner{}, opaque_glyph{}, premultiplied{true};
            if (correct_size) {
                const auto* pixels = static_cast<const DWORD*>(details.bmBits);
                transparent_corner = (pixels[0] >> 24) == 0;
                for (int i = 0; i < 128 * 128; ++i) {
                    const DWORD alpha = pixels[i] >> 24;
                    opaque_glyph = opaque_glyph || alpha == 255;
                    // White glyph: every premultiplied channel equals alpha.
                    premultiplied = premultiplied && (pixels[i] & 0xff) == alpha &&
                                    ((pixels[i] >> 8) & 0xff) == alpha && ((pixels[i] >> 16) & 0xff) == alpha;
                }
            }
            DeleteObject(bitmap);
            require(correct_size, "Unexpected logo size or format");
            require(transparent_corner && opaque_glyph && premultiplied, "Logo is not a premultiplied glyph on transparency");
        } else if (type != CPFT_PASSWORD_TEXT) {
            require(!string_value(credential.Get(), field).empty(), "Empty field text");
        }
        if (type == CPFT_SUBMIT_BUTTON) submit_id = field;
    }
    require(password_fields == 1, "The tile must collect exactly the FIDO2 PIN");
    require(submit_id != MAXDWORD, "No submit button");
    DWORD adjacent = MAXDWORD;
    succeeds(credential->GetSubmitButtonValue(submit_id, &adjacent), "Submit placement failed");
    require(adjacent == pin_field, "Submit button not next to the PIN");
    require(credential->SetStringValue(0, L"secret") == E_INVALIDARG, "Text accepted by a non-input field");
    require(credential->SetStringValue(pin_field, nullptr) == E_POINTER, "Null PIN accepted");
    require(credential->SetCheckboxValue(0, TRUE) == E_INVALIDARG, "Unexpected checkbox");
    require(credential->CommandLinkClicked(0) == E_INVALIDARG, "Unexpected command link");
    PWSTR output = nullptr;
    require(credential->GetStringValue(count, &output) == E_INVALIDARG && !output,
            "Invalid field accepted");
    require(credential->GetBitmapValue(0, nullptr) == E_POINTER, "Null bitmap output accepted");
    require(credential->GetFieldState(0, nullptr, nullptr) == E_POINTER, "Null state output accepted");
    if (suspended) {
        require(string_value(credential.Get(), status_field).find(L"sospeso") != std::wstring::npos,
                "Suspension not shown");
        // A suspended record is refused before the PIN can reach any key.
        check_refusal(credential.Get(), L"1234", L"sospeso");
    } else {
        check_refusal(credential.Get(), nullptr, L"Inserisci il PIN");
        check_refusal(credential.Get(), L"12", L"Formato PIN non valido");
        succeeds(credential->SetStringValue(pin_field, L"9876"), "PIN field rejected");
        succeeds(credential->SetDeselected(), "Deselection failed");
        check_refusal(credential.Get(), nullptr, L"Inserisci il PIN");
    }
}

// Test vault: 1001 enrolled and active, 1002 enrolled but suspended. The keys'
// secrets are random and no authenticator is ever contacted.
struct TestVault {
    std::filesystem::path directory;
    std::filesystem::path path;
    std::wstring sddl;
    TestVault() {
        wchar_t temp[MAX_PATH + 1]{};
        require(GetTempPathW(MAX_PATH, temp) > 0, "temp path unavailable");
        directory = std::filesystem::path(temp) /
            (L"hidfido-cp-test-" + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64()));
        path = directory / L"vault.bin";
        sddl = L"D:P(A;;FA;;;SY)(A;;FA;;;" + hidfido::current_user_sid() + L")";
        namespace vault = hidfido::vault;
        vault::Vault data;
        const std::wstring password = L"password di prova";
        const std::span<const std::uint8_t> password_bytes(
            reinterpret_cast<const std::uint8_t*>(password.data()), password.size() * sizeof(wchar_t));
        for (const auto& [sid, suspended, tag] : {std::tuple{"S-1-5-21-111-222-333-1001", false, std::uint8_t{1}},
                                                  std::tuple{"S-1-5-21-111-222-333-1002", true, std::uint8_t{2}}}) {
            auto data_key = vault::new_data_key();
            // Fixed synthetic DEK used only by the separately built test DLL's
            // explicit fake backend. No real account or authenticator is used.
            std::fill(data_key.bytes().begin(), data_key.bytes().end(), std::uint8_t{0x44});
            auto secret = vault::new_data_key();
            auto record = vault::create_record(sid, "utente", password_bytes, data_key.bytes());
            hidfido::Credential credential;
            credential.id = hidfido::Bytes(32, tag);
            vault::add_wrapper(record, L"Principale", credential, hidfido::password::Salt{}, secret.bytes(), data_key.bytes());
            record.stale = suspended;
            data.accounts.push_back(std::move(record));
        }
        vault::save(path, data, sddl);
        use(path);
        SetEnvironmentVariableW(L"HIDFIDO_TEST_VAULT_SDDL", sddl.c_str());
    }
    ~TestVault() {
        std::error_code ignored;
        std::filesystem::remove_all(directory, ignored);
    }
    TestVault(const TestVault&) = delete;
    TestVault& operator=(const TestVault&) = delete;
    static void use(const std::filesystem::path& location) {
        SetEnvironmentVariableW(L"HIDFIDO_TEST_VAULT_PATH", location.c_str());
    }
};

using GetClass = HRESULT(STDAPICALLTYPE*)(REFCLSID, REFIID, void**);
using CanUnload = HRESULT(STDAPICALLTYPE*)();

void run(GetClass get_class, CanUnload can_unload, const TestVault& vault_files) {
    succeeds(can_unload(), "Fresh DLL cannot unload");
    void* wrong = reinterpret_cast<void*>(1);
    require(get_class(GUID{}, IID_IClassFactory, &wrong) == CLASS_E_CLASSNOTAVAILABLE && !wrong,
            "Unknown class accepted");
    require(get_class(hidfido::credential_provider_clsid, IID_IClassFactory, nullptr) == E_POINTER,
            "Null class output accepted");
    ComPtr<IClassFactory> factory;
    succeeds(get_class(hidfido::credential_provider_clsid, IID_PPV_ARGS(&factory)), "Class factory failed");
    require(can_unload() == S_FALSE, "Factory not counted in DLL lifetime");
    succeeds(factory->LockServer(TRUE), "Server lock failed");
    factory.Reset();
    require(can_unload() == S_FALSE, "Server lock not counted in DLL lifetime");
    succeeds(get_class(hidfido::credential_provider_clsid, IID_PPV_ARGS(&factory)), "Factory reload failed");
    succeeds(factory->LockServer(FALSE), "Server unlock failed");
    require(factory->LockServer(FALSE) == E_UNEXPECTED, "Server lock underflow accepted");
    require(factory->CreateInstance(factory.Get(), IID_IUnknown, &wrong) == CLASS_E_NOAGGREGATION && !wrong,
            "Aggregation accepted");
    require(factory->CreateInstance(nullptr, IID_IUnknown, nullptr) == E_POINTER, "Null instance output accepted");
    ComPtr<ICredentialProvider> provider;
    succeeds(factory->CreateInstance(nullptr, IID_PPV_ARGS(&provider)), "Provider creation failed");
    factory.Reset();
    require(can_unload() == S_FALSE, "Provider not counted in DLL lifetime");
    ComPtr<ICredentialProviderSetUserArray> set_users;
    succeeds(provider.As(&set_users), "SetUserArray interface unavailable");
    ComPtr<ICredentialProviderFilter> filter;
    require(provider.As(&filter) == E_NOINTERFACE && !filter, "Provider exposes a system-provider filter");
    ComPtr<IUnknown> identity1, identity2;
    succeeds(provider.As(&identity1), "Provider identity unavailable");
    succeeds(set_users.As(&identity2), "SetUserArray identity unavailable");
    require(identity1.Get() == identity2.Get(), "COM identity differs across interfaces");
    identity1.Reset();
    identity2.Reset();

    DWORD count = 99, default_index = 0;
    BOOL auto_logon = TRUE;
    require(provider->GetCredentialCount(&count, &default_index, &auto_logon) == E_UNEXPECTED && count == 0,
            "Provider enumerates without a supported scenario");
    require(default_index == CREDENTIAL_PROVIDER_NO_DEFAULT && auto_logon == FALSE,
            "Unsafe default tile values");
    for (auto scenario : {CPUS_CREDUI, CPUS_CHANGE_PASSWORD, CPUS_PLAP}) {
        require(provider->SetUsageScenario(scenario, 0) == E_NOTIMPL, "Unsupported scenario accepted");
    }
    require(provider->SetUsageScenario(CPUS_INVALID, 0) == E_INVALIDARG, "Invalid scenario accepted");
    require(set_users->SetUserArray(nullptr) == E_POINTER, "Null user array accepted");
    succeeds(provider->SetUsageScenario(CPUS_LOGON, 0), "Logon scenario rejected");
    succeeds(provider->GetCredentialCount(&count, &default_index, &auto_logon), "Empty enumeration failed");
    require(count == 0, "Provider invents a user without the LogonUI user array");
    ComPtr<FakeUsers> users;
    users.Attach(new FakeUsers);
    succeeds(set_users->SetUserArray(users.Get()), "User array rejected");

    // Without an enrolled vault record no tile is offered at all.
    TestVault::use(vault_files.directory / L"assente.bin");
    succeeds(provider->SetUsageScenario(CPUS_LOGON, 0), "Logon scenario rejected");
    succeeds(provider->GetCredentialCount(&count, &default_index, &auto_logon), "Vault-less enumeration failed");
    require(count == 0, "Tile offered without an enrolled vault record");
    TestVault::use(vault_files.path);

    for (auto scenario : {CPUS_LOGON, CPUS_UNLOCK_WORKSTATION}) {
        succeeds(provider->SetUsageScenario(scenario, 0), "Supported scenario rejected");
        succeeds(provider->GetCredentialCount(&count, &default_index, &auto_logon), "Enumeration failed");
        require(count == 2 && default_index == CREDENTIAL_PROVIDER_NO_DEFAULT && !auto_logon,
                "Local-user enumeration or defaults incorrect");
        check_tile(provider.Get(), 0, L"S-1-5-21-111-222-333-1001", false);
        check_tile(provider.Get(), 1, L"S-1-5-21-111-222-333-1002", true);
        ComPtr<ICredentialProviderCredential> missing;
        require(provider->GetCredentialAt(count, &missing) == E_INVALIDARG && !missing,
                "Out-of-range credential accepted");
    }
    require(users->filter_calls == 0, "Provider modifies the LogonUI user filter");
    require(provider->GetFieldDescriptorCount(nullptr) == E_POINTER, "Null field count accepted");
    require(provider->GetFieldDescriptorAt(0, nullptr) == E_POINTER, "Null descriptor output accepted");
    require(provider->GetCredentialCount(nullptr, &default_index, &auto_logon) == E_POINTER,
            "Null credential count accepted");
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION incoming{};
    require(provider->SetSerialization(&incoming) == E_NOTIMPL, "Incoming serialization accepted");

    // User-array failures must expose no partial tile set.
    users->failed_index = 1;
    succeeds(set_users->SetUserArray(users.Get()), "Array update failed");
    require(provider->GetCredentialCount(&count, &default_index, &auto_logon) == E_ACCESSDENIED && count == 0,
            "Partial enumeration survived a user-array failure");
    users->failed_index = MAXDWORD;
    users->advertised_count = 1025;
    succeeds(set_users->SetUserArray(users.Get()), "Array update failed");
    require(FAILED(provider->GetCredentialCount(&count, &default_index, &auto_logon)) && count == 0,
            "Unbounded user count accepted");
    users->advertised_count = 3;
    users->replace_first_sid(L"invalid SID");
    succeeds(set_users->SetUserArray(users.Get()), "Array update failed");
    require(provider->GetCredentialCount(&count, &default_index, &auto_logon) == E_INVALIDARG && count == 0,
            "Invalid SID accepted");

    users->replace_first_sid(L"S-1-5-21-111-222-333-1001");
    succeeds(set_users->SetUserArray(users.Get()), "Array restore failed");
    ComPtr<ICredentialProviderCredential> retained;
    succeeds(provider->GetCredentialAt(0, &retained), "Retained credential unavailable");
    set_users.Reset();
    provider.Reset();
    users.Reset();
    require(can_unload() == S_FALSE, "Outstanding credential not counted in DLL lifetime");
    check_refusal(retained.Get(), nullptr, L"Inserisci il PIN");
    retained.Reset();
    succeeds(can_unload(), "DLL references leaked");
    const auto final_vault = hidfido::vault::load(vault_files.path);
    const auto* active = final_vault.find("S-1-5-21-111-222-333-1001");
    const auto* suspended = final_vault.find("S-1-5-21-111-222-333-1002");
    require(active && !active->stale && suspended && suspended->stale,
            "Refused attempts or unsolicited results changed the vault");
}

void run_connected(GetClass get_class, CanUnload can_unload, const TestVault& vault_files) {
    namespace vault = hidfido::vault;
    const auto baseline = vault::load(vault_files.path);
    ComPtr<ICredentialProvider> advised_provider;
    ComPtr<FakeProviderEvents> events;
    const auto reset = [&] {
        if (advised_provider) succeeds(advised_provider->UnAdvise(), "Provider UnAdvise");
        advised_provider.Reset(); events.Reset();
        pump_until([&] { return can_unload() == S_OK; });
        vault::save(vault_files.path, baseline, vault_files.sddl);
        SetEnvironmentVariableW(L"HIDFIDO_TEST_SUSPEND_FAIL", nullptr);
        SetEnvironmentVariableW(L"HIDFIDO_TEST_BACKEND", L"success");
    };
    const auto tile = [&] {
        ComPtr<IClassFactory> factory;
        succeeds(get_class(hidfido::credential_provider_clsid, IID_PPV_ARGS(&factory)), "Test factory");
        succeeds(factory->CreateInstance(nullptr, IID_PPV_ARGS(&advised_provider)), "Test provider");
        succeeds(advised_provider->SetUsageScenario(CPUS_LOGON, 0), "Test scenario");
        events.Attach(new FakeProviderEvents);
        succeeds(advised_provider->Advise(events.Get(), 0x5678), "Provider Advise");
        ComPtr<ICredentialProviderSetUserArray> set_users;
        succeeds(advised_provider.As(&set_users), "Test user interface");
        ComPtr<FakeUsers> users; users.Attach(new FakeUsers);
        succeeds(set_users->SetUserArray(users.Get()), "Test users");
        ComPtr<ICredentialProviderCredential> result;
        succeeds(advised_provider->GetCredentialAt(0, &result), "Test tile");
        return result;
    };
    const auto ready = [&] {
        DWORD count{}, index{}; BOOL automatic{};
        succeeds(advised_provider->GetCredentialCount(&count, &index, &automatic), "Auto logon readiness");
        if (automatic) require(index == 0 && count == 2, "Auto logon selected the wrong tile");
        return automatic != FALSE;
    };
    const auto selected = [](ICredentialProviderCredential* credential, bool expected) {
        BOOL automatic = expected ? FALSE : TRUE;
        succeeds(credential->SetSelected(&automatic), "Ready credential selection");
        require((automatic != FALSE) == expected, "Selection and cache readiness disagree");
    };
    const auto serialization = [&](ICredentialProviderCredential* credential, bool expected) {
        CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE response{};
        CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION packed{};
        PWSTR message{}; CREDENTIAL_PROVIDER_STATUS_ICON icon{};
        const auto start = GetTickCount64();
        succeeds(credential->GetSerialization(&response, &packed, &message, &icon), "Async serialization");
        require(GetTickCount64() - start < 200, "GetSerialization blocked on authentication");
        CoTaskMemFree(message);
        require((response == CPGSR_RETURN_CREDENTIAL_FINISHED) == expected, "Wrong serialization readiness");
        if (expected) {
            require(packed.ulAuthenticationPackage == 0x4242 && packed.cbSerialization > sizeof(KERB_INTERACTIVE_UNLOCK_LOGON),
                    "Synthetic backend did not produce packed credentials");
            KERB_INTERACTIVE_UNLOCK_LOGON header{};
            std::memcpy(&header, packed.rgbSerialization, sizeof(header));
            const auto offset = reinterpret_cast<ULONG_PTR>(header.Logon.Password.Buffer);
            require(offset + header.Logon.Password.Length <= packed.cbSerialization, "Password offset bounds");
            std::wstring protected_text(reinterpret_cast<PCWSTR>(packed.rgbSerialization + offset),
                                        header.Logon.Password.Length / sizeof(wchar_t));
            CRED_PROTECTION_TYPE type{};
            require(CredIsProtectedW(protected_text.data(), &type) && type != CredUnprotected,
                    "Provider exported plaintext password");
        } else require(packed.rgbSerialization == nullptr && packed.cbSerialization == 0, "Refusal exported a buffer");
        if (packed.rgbSerialization) SecureZeroMemory(packed.rgbSerialization, packed.cbSerialization);
        CoTaskMemFree(packed.rgbSerialization);
    };
    const auto start = [&](ICredentialProviderCredential* credential) {
        succeeds(credential->SetStringValue(pin_field, L"1234"), "Synthetic PIN");
        serialization(credential, false); // LOGON does not call Connect.
        require(!ready() || events->calls == 0, "Worker completion was signalled before message dispatch");
    };
    const auto complete = [&](ICredentialProviderCredential* credential, bool expected) {
        pump_until([&] {
            const auto text = string_value(credential, status_field);
            return text.find(L"in corso") == std::wstring::npos && text.find(L"Tocca") == std::wstring::npos;
        });
        // Dispatch the completion message as well as any preceding status update.
        MSG message{};
        while (PeekMessageW(&message, nullptr, 0, 0, PM_REMOVE)) DispatchMessageW(&message);
        require(ready() == expected, "Worker exposed incorrect automatic logon state");
        require(!events->wrong_thread && !events->wrong_context, "Event escaped Advise apartment/context");
        if (expected) require(events->calls != 0, "Completed worker did not request automatic logon");
    };
    const auto result = [](ICredentialProviderCredential* credential) {
        PWSTR message{}; CREDENTIAL_PROVIDER_STATUS_ICON icon{};
        succeeds(credential->ReportResult(static_cast<NTSTATUS>(0xC000006D),
                                           static_cast<NTSTATUS>(0xC000006A), &message, &icon), "Pending logon result");
        require(message && icon == CPSI_ERROR, "Password rejection lacked advice");
        CoTaskMemFree(message);
    };
    {
        reset(); auto credential = tile();
        serialization(credential.Get(), false);
        start(credential.Get()); complete(credential.Get(), true);
        selected(credential.Get(), true);
        require(string_value(credential.Get(), pin_field).empty(), "Async tile retained PIN text");
        serialization(credential.Get(), true);
        selected(credential.Get(), false);
        require(!ready(), "Consumed cache still requested automatic logon");
        serialization(credential.Get(), false);
        result(credential.Get());
        require(vault::load(vault_files.path).find("S-1-5-21-111-222-333-1001")->stale, "Password rejection not persisted");
        check_refusal(credential.Get(), L"1234", L"sospeso");
    }
    {
        reset(); auto credential = tile();
        start(credential.Get()); complete(credential.Get(), true);
        serialization(credential.Get(), true);
        SetEnvironmentVariableW(L"HIDFIDO_TEST_SUSPEND_FAIL", L"1");
        result(credential.Get());
        require(!vault::load(vault_files.path).find("S-1-5-21-111-222-333-1001")->stale, "Synthetic write failure changed vault");
        check_refusal(credential.Get(), L"1234", L"sospeso");
    }
    {
        reset(); auto credential = tile();
        start(credential.Get()); complete(credential.Get(), true);
        serialization(credential.Get(), true);
        auto current = vault::load(vault_files.path);
        ++current.find("S-1-5-21-111-222-333-1001")->password_generation;
        vault::save(vault_files.path, current, vault_files.sddl);
        result(credential.Get());
        require(!vault::load(vault_files.path).find("S-1-5-21-111-222-333-1001")->stale,
                "Old Windows result suspended a newly updated password generation");
    }
    for (const auto* mode : {L"counter_conflict", L"password_conflict", L"revocation_conflict"}) {
        reset(); auto credential = tile();
        SetEnvironmentVariableW(L"HIDFIDO_TEST_BACKEND", mode);
        start(credential.Get()); complete(credential.Get(), false);
        serialization(credential.Get(), false);
    }
    {
        reset(); auto credential = tile();
        start(credential.Get()); complete(credential.Get(), true);
        Sleep(650); // Test DLL only: production cache lasts 15 seconds.
        require(!ready(), "Expired cache still requested auto logon");
        selected(credential.Get(), false);
        serialization(credential.Get(), false);
    }
    {
        // Characterize a possible framework echo without assuming Windows
        // actually performs it. The lifecycle trace distinguishes this from
        // UnAdvise/deselection on the real host. Do not silently change the
        // cancellation contract before that evidence is available.
        reset(); auto credential = tile();
        start(credential.Get()); complete(credential.Get(), true);
        selected(credential.Get(), true);
        ComPtr<FakeCredentialEvents> fields; fields.Attach(new FakeCredentialEvents);
        fields->on_set = [&] {
            succeeds(credential->SetStringValue(pin_field, L""), "Framework PIN clear echo");
        };
        succeeds(credential->Advise(fields.Get()), "Echo events Advise");
        // Echo the static empty UI update through the same callback surface,
        // with no deselection or Windows result that could clear the cache.
        succeeds(fields->SetFieldString(credential.Get(), pin_field, L""), "Echo field update");
        require(fields->calls == 1 && !ready(), "Empty field echo cache-loss characterization changed");
        selected(credential.Get(), false);
        serialization(credential.Get(), false);
        succeeds(credential->UnAdvise(), "Echo events UnAdvise");
    }
    {
        // Sequence traced in LogonUI on 25/10: after our CredentialsChanged,
        // LogonUI detaches the tile's event sink, re-enumerates, attaches a new
        // sink and only then asks for the serialization. The ready result must
        // cross that rebind exactly once.
        reset(); auto credential = tile();
        start(credential.Get()); complete(credential.Get(), true);
        succeeds(credential->UnAdvise(), "Re-enumeration UnAdvise");
        require(ready(), "Re-enumeration UnAdvise discarded the ready result");
        ComPtr<FakeCredentialEvents> fields; fields.Attach(new FakeCredentialEvents);
        succeeds(credential->Advise(fields.Get()), "Re-enumeration Advise");
        require(ready(), "New event sink discarded the ready result");
        selected(credential.Get(), true);
        serialization(credential.Get(), true);
        require(!ready(), "Handoff survived consumption");
        serialization(credential.Get(), false);
        succeeds(credential->UnAdvise(), "Post-submit UnAdvise");
    }
    {
        // The handoff is not a general exemption: deselection after the rebind
        // still clears it.
        reset(); auto credential = tile();
        start(credential.Get()); complete(credential.Get(), true);
        succeeds(credential->UnAdvise(), "Re-enumeration UnAdvise");
        succeeds(credential->SetDeselected(), "Deselection after rebind");
        require(!ready(), "Deselection after rebind kept the ready result");
        serialization(credential.Get(), false);
    }
    {
        // Without a completed handoff, detaching the tile cancels in-flight work.
        reset(); auto credential = tile();
        SetEnvironmentVariableW(L"HIDFIDO_TEST_BACKEND", L"wait");
        start(credential.Get());
        succeeds(credential->UnAdvise(), "In-flight credential UnAdvise");
        complete(credential.Get(), false);
        require(vault::load(vault_files.path).find("S-1-5-21-111-222-333-1001")->wrappers[0].credential.sign_count == 0,
                "Credential UnAdvise did not cancel the worker");
        serialization(credential.Get(), false);
    }
    {
        reset(); auto credential = tile();
        start(credential.Get()); complete(credential.Get(), true);
        succeeds(credential->SetDeselected(), "Ready tile deselection");
        require(!ready(), "Deselected cache requested auto logon");
        serialization(credential.Get(), false);
    }
    {
        reset(); auto credential = tile();
        SetEnvironmentVariableW(L"HIDFIDO_TEST_BACKEND", L"wait");
        start(credential.Get());
        succeeds(credential->SetDeselected(), "In-flight deselection");
        complete(credential.Get(), false);
        require(vault::load(vault_files.path).find("S-1-5-21-111-222-333-1001")->wrappers[0].credential.sign_count == 0,
                "Cancelled worker committed an assertion");
        serialization(credential.Get(), false);
    }
    {
        reset(); auto credential = tile();
        SetEnvironmentVariableW(L"HIDFIDO_TEST_BACKEND", L"wait");
        start(credential.Get());
        const auto before = events->calls;
        succeeds(advised_provider->UnAdvise(), "In-flight provider UnAdvise");
        complete(credential.Get(), false);
        require(events->calls == before, "Unadvised provider received a worker event");
        serialization(credential.Get(), false);
    }
    // Realistic COM re-entrancy: the first field callback can invalidate the
    // provider's collection or tear down its notification sink immediately.
    for (const bool replace_users : {false, true}) {
        reset(); auto credential = tile();
        SetEnvironmentVariableW(L"HIDFIDO_TEST_BACKEND", L"wait");
        ComPtr<FakeCredentialEvents> fields; fields.Attach(new FakeCredentialEvents);
        succeeds(credential->Advise(fields.Get()), "Credential event Advise");
        fields->on_set = [&] {
            if (replace_users) {
                ComPtr<ICredentialProviderSetUserArray> setter;
                succeeds(advised_provider.As(&setter), "Re-entrant user setter");
                ComPtr<FakeUsers> users; users.Attach(new FakeUsers);
                succeeds(setter->SetUserArray(users.Get()), "Re-entrant SetUserArray");
            } else succeeds(advised_provider->UnAdvise(), "Re-entrant provider UnAdvise");
        };
        start(credential.Get());
        require(fields->calls == 1 && !fields->wrong_thread,
                "Field update continued after re-entrant provider teardown/replacement");
        complete(credential.Get(), false);
        require(fields->calls == 1, "Retired credential received a late field callback");
        succeeds(credential->UnAdvise(), "Retired credential UnAdvise");
        require(fields->calls == 1, "Credential UnAdvise called a disarmed event sink");
    }
    for (const unsigned operation : {0U, 1U, 2U}) {
        reset(); auto credential = tile();
        ComPtr<FakeCredentialEvents> fields; fields.Attach(new FakeCredentialEvents);
        succeeds(credential->Advise(fields.Get()), "Teardown credential Advise");
        fields->on_set = [&] { succeeds(advised_provider->UnAdvise(), "Nested teardown callback"); };
        if (operation == 0) succeeds(advised_provider->UnAdvise(), "Silent provider teardown");
        if (operation == 1) {
            ComPtr<ICredentialProviderSetUserArray> setter;
            succeeds(advised_provider.As(&setter), "Silent replacement interface");
            ComPtr<FakeUsers> users; users.Attach(new FakeUsers);
            succeeds(setter->SetUserArray(users.Get()), "Silent user replacement");
        }
        if (operation == 2) succeeds(credential->UnAdvise(), "Silent credential teardown");
        require(fields->calls == 0, "Teardown invoked external field callbacks");
    }
    reset();
    SetEnvironmentVariableW(L"HIDFIDO_TEST_BACKEND", nullptr);
    succeeds(can_unload(), "Async tests leaked credential, window or factory references");
}
}

int wmain(int argc, wchar_t** argv) {
    if (argc != 2) {
        std::cerr << "Usage: provider_tests <absolute-provider-dll-path>\n";
        return 2;
    }
    const HRESULT initialized = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(initialized)) return 2;
    HMODULE module = LoadLibraryExW(argv[1], nullptr, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!module) {
        std::cerr << "LoadLibraryEx failed: " << GetLastError() << '\n';
        CoUninitialize();
        return 1;
    }
    int result = 0;
    try {
        auto get_class = reinterpret_cast<GetClass>(GetProcAddress(module, "DllGetClassObject"));
        auto can_unload = reinterpret_cast<CanUnload>(GetProcAddress(module, "DllCanUnloadNow"));
        require(get_class && can_unload, "Required COM exports missing");
        require(!GetProcAddress(module, "DllRegisterServer") && !GetProcAddress(module, "DllUnregisterServer"),
                "DLL exposes self-registration");
        const TestVault vault_files;
        run(get_class, can_unload, vault_files);
        run_connected(get_class, can_unload, vault_files);
        std::cout << "Credential Provider isolated COM and refusal tests passed; no key contacted, "
                     "no Windows authentication settings changed.\n";
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        result = 1;
    }
    FreeLibrary(module);
    CoUninitialize();
    return result;
}
