// fido2prf credentials and PRF evaluation through the Windows WebAuthn API.
// webauthn.dll owns the authenticator dialog, the PIN and the CTAP transport;
// this module only supplies PRF inputs and copies out the two 32-byte results.
#include "hidfido/age_webauthn.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <webauthn.h>

#include <algorithm>
#include <cstdio>
#include <memory>
#include <vector>

#if !defined(WEBAUTHN_API_VERSION_4) || !defined(WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_6)
#error "webauthn.h from Windows SDK 10.0.22621 or newer is required (WebAuthn API version 4 PRF salts)"
#endif

namespace hidfido::age::webauthn {
namespace {
constexpr DWORD timeout_ms = 120000;

// webauthn.dll is loaded on demand from System32 only, so the recovery-key
// path works on systems without it and no DLL can be planted beside the tool.
struct Api {
    decltype(&WebAuthNGetApiVersionNumber) version{};
    decltype(&WebAuthNAuthenticatorMakeCredential) make_credential{};
    decltype(&WebAuthNAuthenticatorGetAssertion) get_assertion{};
    decltype(&WebAuthNFreeCredentialAttestation) free_attestation{};
    decltype(&WebAuthNFreeAssertion) free_assertion{};
    decltype(&WebAuthNGetErrorName) error_name{};
    bool complete() const noexcept {
        return version && make_credential && get_assertion && free_attestation && free_assertion && error_name;
    }
};

template<class Function> void bind(HMODULE module, const char* name, Function& target) noexcept {
    target = reinterpret_cast<Function>(reinterpret_cast<void*>(GetProcAddress(module, name)));
}

const Api& api() noexcept {
    static const Api loaded = [] {
        Api result;
        const HMODULE module = LoadLibraryExW(L"webauthn.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (!module) return result;
        bind(module, "WebAuthNGetApiVersionNumber", result.version);
        bind(module, "WebAuthNAuthenticatorMakeCredential", result.make_credential);
        bind(module, "WebAuthNAuthenticatorGetAssertion", result.get_assertion);
        bind(module, "WebAuthNFreeCredentialAttestation", result.free_attestation);
        bind(module, "WebAuthNFreeAssertion", result.free_assertion);
        bind(module, "WebAuthNGetErrorName", result.error_name);
        if (!result.complete()) result = Api{};
        return result;
    }();
    return loaded;
}

std::wstring widen(std::string_view text) {
    if (text.empty()) return {};
    const int size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), nullptr, 0);
    if (size <= 0) throw std::invalid_argument("Invalid UTF-8 relying party");
    std::wstring result(static_cast<std::size_t>(size), L'\0');
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), result.data(), size);
    return result;
}

std::string error_name(HRESULT result) {
    std::string name;
    if (const auto* text = api().error_name ? api().error_name(result) : nullptr) {
        for (const wchar_t* c = text; *c; ++c) name.push_back(*c < 0x80 ? static_cast<char>(*c) : '?');
    }
    char code[16]{};
    std::snprintf(code, sizeof(code), "0x%08lX", static_cast<unsigned long>(result));
    return name.empty() ? std::string(code) : name + " (" + code + ")";
}

[[noreturn]] void fail(const char* operation, HRESULT result) {
    throw Error(std::string(operation) + ": " + error_name(result), result);
}

DWORD transport_flags(const std::vector<std::string>& transports) noexcept {
    DWORD flags = 0;
    for (const auto& transport : transports) {
        if (transport == "usb") flags |= WEBAUTHN_CTAP_TRANSPORT_USB;
        else if (transport == "nfc") flags |= WEBAUTHN_CTAP_TRANSPORT_NFC;
        else if (transport == "ble") flags |= WEBAUTHN_CTAP_TRANSPORT_BLE;
#ifdef WEBAUTHN_CTAP_TRANSPORT_HYBRID
        else if (transport == "hybrid") flags |= WEBAUTHN_CTAP_TRANSPORT_HYBRID;
#endif
        else if (transport == "internal") flags |= WEBAUTHN_CTAP_TRANSPORT_INTERNAL;
    }
    return flags;
}

std::string client_data(std::string_view type) {
    std::array<std::uint8_t, 32> challenge{};
    random_bytes(challenge);
    auto encoded = encoding::base64_encode(challenge);
    std::ranges::replace(encoded, '+', '-');
    std::ranges::replace(encoded, '/', '_');
    return std::string(R"({"type":")") + std::string(type) + R"(","challenge":")" + encoded +
           R"(","origin":"hid-fido2-age:","crossOrigin":false})";
}

HWND owner() noexcept {
    const auto window = GetForegroundWindow();
    return window ? window : GetConsoleWindow();
}

struct AttestationDeleter { void operator()(WEBAUTHN_CREDENTIAL_ATTESTATION* value) const noexcept { api().free_attestation(value); } };
struct AssertionDeleter { void operator()(WEBAUTHN_ASSERTION* value) const noexcept { api().free_assertion(value); } };

void require_api() {
    if (!prf_available()) {
        throw Error(api_version() == 0 ? std::string("Windows WebAuthn (webauthn.dll) is not available")
                                       : "Windows WebAuthn API version " + std::to_string(api_version()) +
                                         " has no PRF support; Windows 11 22H2 or later is required", E_NOTIMPL);
    }
}

// Sanity checks on Windows' own result: right RP, user present and verified.
void check_authenticator_data(std::span<const std::uint8_t> data, std::string_view rp_id) {
    if (data.size() < 37) throw Error("Invalid authenticator data", E_UNEXPECTED);
    const auto expected = crypto::sha256({reinterpret_cast<const std::uint8_t*>(rp_id.data()), rp_id.size()});
    if (!std::equal(expected.begin(), expected.end(), data.begin())) throw Error("Authenticator answered for another relying party", E_UNEXPECTED);
    if ((data[32] & 0x05) != 0x05) throw Error("Authenticator did not confirm user presence and verification", E_UNEXPECTED);
}
}

bool Error::already_registered() const noexcept { return result_ == NTE_EXISTS; }

bool Error::cancelled() const noexcept {
    return result_ == NTE_USER_CANCELLED || result_ == HRESULT_FROM_WIN32(ERROR_CANCELLED) ||
           result_ == HRESULT_FROM_WIN32(ERROR_TIMEOUT) || result_ == NTE_NOT_FOUND;
}

std::uint32_t api_version() noexcept { return api().complete() ? api().version() : 0; }

bool prf_available() noexcept { return api_version() >= minimum_api_version; }

Fido2PrfCredential create_credential(std::wstring_view label, std::string_view rp_id,
                                     std::span<const Fido2PrfCredential> exclude) {
    require_api();
    if (label.empty() || label.size() > 64 || rp_id.empty() || rp_id.size() > 253) {
        throw std::invalid_argument("Invalid key label or relying party");
    }
    const auto rp = widen(rp_id);
    const std::wstring name(label);
    WEBAUTHN_RP_ENTITY_INFORMATION rp_info{WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION, rp.c_str(), L"HID FIDO2 age", nullptr};
    std::array<std::uint8_t, 8> user_id{};
    random_bytes(user_id);  // A new handle never overwrites another credential.
    WEBAUTHN_USER_ENTITY_INFORMATION user{WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION,
                                          static_cast<DWORD>(user_id.size()), user_id.data(), name.c_str(), nullptr, name.c_str()};
    WEBAUTHN_COSE_CREDENTIAL_PARAMETER algorithms[] = {
        {WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION, WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY, WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256},
        {WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION, WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY, -8 /* EdDSA */},
    };
    WEBAUTHN_COSE_CREDENTIAL_PARAMETERS parameters{static_cast<DWORD>(std::size(algorithms)), algorithms};
    const auto json = client_data("webauthn.create");
    WEBAUTHN_CLIENT_DATA data{WEBAUTHN_CLIENT_DATA_CURRENT_VERSION, static_cast<DWORD>(json.size()),
                              reinterpret_cast<PBYTE>(const_cast<char*>(json.data())), WEBAUTHN_HASH_ALGORITHM_SHA_256};
    BOOL hmac_secret = TRUE;
    WEBAUTHN_EXTENSION extension{WEBAUTHN_EXTENSIONS_IDENTIFIER_HMAC_SECRET, sizeof(hmac_secret), &hmac_secret};
    std::vector<WEBAUTHN_CREDENTIAL_EX> excluded;
    for (const auto& credential : exclude) {
        if (credential.rp_id != rp_id) continue;
        excluded.push_back({WEBAUTHN_CREDENTIAL_EX_CURRENT_VERSION, static_cast<DWORD>(credential.credential_id.size()),
                            const_cast<PBYTE>(credential.credential_id.data()), WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
                            transport_flags(credential.transports)});
    }
    std::vector<WEBAUTHN_CREDENTIAL_EX*> excluded_pointers;
    for (auto& credential : excluded) excluded_pointers.push_back(&credential);
    WEBAUTHN_CREDENTIAL_LIST exclude_list{static_cast<DWORD>(excluded_pointers.size()), excluded_pointers.data()};
    WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS options{};
    options.dwVersion = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_5;
    if (!excluded.empty()) options.pExcludeCredentialList = &exclude_list;
    options.dwTimeoutMilliseconds = timeout_ms;
    options.Extensions = {1, &extension};
    options.dwAuthenticatorAttachment = WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM;
    options.bRequireResidentKey = FALSE;
    options.dwUserVerificationRequirement = WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED;
    options.dwAttestationConveyancePreference = WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE;
    WEBAUTHN_CREDENTIAL_ATTESTATION* raw = nullptr;
    const HRESULT result = api().make_credential(owner(), &rp_info, &user, &parameters, &data, &options, &raw);
    std::unique_ptr<WEBAUTHN_CREDENTIAL_ATTESTATION, AttestationDeleter> attestation(raw);
    if (FAILED(result)) fail("Security key registration failed", result);
    if (!attestation || !attestation->pbCredentialId || attestation->cbCredentialId == 0 || attestation->cbCredentialId > 1023) {
        throw Error("Windows returned no credential", E_UNEXPECTED);
    }
    bool prf_enabled = false;
    if (attestation->dwVersion >= WEBAUTHN_CREDENTIAL_ATTESTATION_VERSION_2) {
        for (DWORD i = 0; i < attestation->Extensions.cExtensions; ++i) {
            const auto& output = attestation->Extensions.pExtensions[i];
            if (output.pwszExtensionIdentifier && std::wstring_view(output.pwszExtensionIdentifier) == WEBAUTHN_EXTENSIONS_IDENTIFIER_HMAC_SECRET &&
                output.cbExtension == sizeof(BOOL) && *static_cast<const BOOL*>(output.pvExtension)) {
                prf_enabled = true;
            }
        }
    }
    if (!prf_enabled) throw Error("This security key does not support the hmac-secret (PRF) extension", NTE_NOT_SUPPORTED);
    check_authenticator_data({attestation->pbAuthenticatorData, attestation->cbAuthenticatorData}, rp_id);
    Fido2PrfCredential credential;
    credential.credential_id.assign(attestation->pbCredentialId, attestation->pbCredentialId + attestation->cbCredentialId);
    credential.rp_id = std::string(rp_id);
    const DWORD used = attestation->dwVersion >= WEBAUTHN_CREDENTIAL_ATTESTATION_VERSION_3 ? attestation->dwUsedTransport : 0;
    if (used & WEBAUTHN_CTAP_TRANSPORT_NFC) credential.transports = {"nfc"};
    else if (used & WEBAUTHN_CTAP_TRANSPORT_BLE) credential.transports = {"ble"};
    else credential.transports = {"usb"};
    return credential;
}

PrfFunction prf(std::function<void(const PrfRequest&)> prompt) {
    return [prompt = std::move(prompt)](const PrfRequest& request) -> PrfResult {
        require_api();
        if (request.allowed.empty()) throw std::invalid_argument("No credential to ask for");
        const auto& rp_id = request.allowed.front().rp_id;
        const auto rp = widen(rp_id);
        std::vector<WEBAUTHN_CREDENTIAL_EX> credentials;
        for (const auto& credential : request.allowed) {
            if (credential.rp_id != rp_id) throw std::invalid_argument("Mixed relying parties in one request");
            credentials.push_back({WEBAUTHN_CREDENTIAL_EX_CURRENT_VERSION, static_cast<DWORD>(credential.credential_id.size()),
                                   const_cast<PBYTE>(credential.credential_id.data()), WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
                                   transport_flags(credential.transports)});
        }
        std::vector<WEBAUTHN_CREDENTIAL_EX*> pointers;
        for (auto& credential : credentials) pointers.push_back(&credential);
        WEBAUTHN_CREDENTIAL_LIST allow{static_cast<DWORD>(pointers.size()), pointers.data()};
        // Windows turns PRF inputs into hmac-secret salts:
        // SHA-256("WebAuthn PRF" || 0x00 || input), exactly as browsers do.
        Bytes first(request.first_input.begin(), request.first_input.end());
        Bytes second(request.second_input.begin(), request.second_input.end());
        WEBAUTHN_HMAC_SECRET_SALT salt{static_cast<DWORD>(first.size()), first.data(), static_cast<DWORD>(second.size()), second.data()};
        WEBAUTHN_HMAC_SECRET_SALT_VALUES salts{&salt, 0, nullptr};
        const auto json = client_data("webauthn.get");
        WEBAUTHN_CLIENT_DATA data{WEBAUTHN_CLIENT_DATA_CURRENT_VERSION, static_cast<DWORD>(json.size()),
                                  reinterpret_cast<PBYTE>(const_cast<char*>(json.data())), WEBAUTHN_HASH_ALGORITHM_SHA_256};
        WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS options{};
        options.dwVersion = WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_6;
        options.dwTimeoutMilliseconds = timeout_ms;
        options.dwAuthenticatorAttachment = WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM;
        options.dwUserVerificationRequirement = WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED;
        options.pAllowCredentialList = &allow;
        options.pHmacSecretSaltValues = &salts;
        if (prompt) prompt(request);
        WEBAUTHN_ASSERTION* raw = nullptr;
        const HRESULT result = api().get_assertion(owner(), rp.c_str(), &data, &options, &raw);
        std::unique_ptr<WEBAUTHN_ASSERTION, AssertionDeleter> assertion(raw);
        if (FAILED(result)) fail("Security key verification failed", result);
        if (!assertion || assertion->dwVersion < WEBAUTHN_ASSERTION_VERSION_3 || !assertion->pHmacSecret ||
            assertion->pHmacSecret->cbFirst != 32 || assertion->pHmacSecret->cbSecond != 32 ||
            !assertion->pHmacSecret->pbFirst || !assertion->pHmacSecret->pbSecond) {
            throw Error("The security key returned no PRF result (hmac-secret unsupported?)", NTE_NOT_SUPPORTED);
        }
        check_authenticator_data({assertion->pbAuthenticatorData, assertion->cbAuthenticatorData}, rp_id);
        const std::span<const std::uint8_t> used(assertion->Credential.pbId, assertion->Credential.cbId);
        PrfResult output;
        output.used = request.allowed.size();
        for (std::size_t i = 0; i < request.allowed.size(); ++i) {
            if (std::ranges::equal(request.allowed[i].credential_id, used)) output.used = i;
        }
        if (output.used == request.allowed.size()) throw Error("Windows used a credential that was not requested", E_UNEXPECTED);
        std::copy_n(assertion->pHmacSecret->pbFirst, 32, output.output.begin());
        std::copy_n(assertion->pHmacSecret->pbSecond, 32, output.output.begin() + 32);
        wipe(std::span<std::uint8_t>(assertion->pHmacSecret->pbFirst, 32));
        wipe(std::span<std::uint8_t>(assertion->pHmacSecret->pbSecond, 32));
        return output;
    };
}
}
