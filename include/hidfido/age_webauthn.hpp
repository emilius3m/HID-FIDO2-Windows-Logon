#pragma once

#include "hidfido/age.hpp"

#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>

// Windows WebAuthn (webauthn.dll) backend for the age fido2prf recipient.
// Windows shows its own security-key dialog, collects the PIN and asks for the
// touch; this process never sees the PIN and needs no administrator rights.
// The hmac-secret salts follow the WebAuthn PRF rules, so a credential works
// with typage and age-plugin-fido2prf on other systems.
namespace hidfido::age::webauthn {
// Not a DNS name: a fixed relying-party label for file-encryption credentials,
// separate from the Windows sign-in credentials of this project.
inline constexpr std::string_view default_rp_id = "hid-fido2-age";
// WebAuthn API version 4 (Windows 11 22H2 or later) adds PRF salts to assertions.
inline constexpr std::uint32_t minimum_api_version = 4;

class Error : public std::runtime_error {
public:
    Error(const std::string& message, long result) : std::runtime_error(message), result_(result) {}
    long result() const noexcept { return result_; }
    bool cancelled() const noexcept;
    bool already_registered() const noexcept;
private:
    long result_;
};

std::uint32_t api_version() noexcept;
bool prf_available() noexcept;

// Creates a non-discoverable credential with hmac-secret and user verification.
// `label` (for example "Principale") is shown by Windows and stored on the key
// only as user name metadata; it is not a secret. A key that already holds one
// of `exclude` is refused (already_registered()), so a backup key cannot
// silently end up on the same hardware as the primary one.
Fido2PrfCredential create_credential(std::wstring_view label, std::string_view rp_id = default_rp_id,
                                     std::span<const Fido2PrfCredential> exclude = {});

// PRF evaluation through WebAuthNAuthenticatorGetAssertion with user
// verification required. `prompt` is called before Windows opens its dialog.
PrfFunction prf(std::function<void(const PrfRequest&)> prompt = {});
}
