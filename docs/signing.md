# Release signing

An unsigned local build is a prototype, not an authenticated distribution.
The native bootstrap accepts only unsigned payloads in that profile and asks
for explicit consent. It never imports a root certificate, exports private
keys or changes code-integrity or Secure Boot settings.

## Configure the expected publisher

Use a real code-signing certificate with an accessible private key. Compute
SHA-256 over the public DER certificate. This is distinct from the SHA-1
certificate thumbprint used to select a certificate with SignTool.

```cmd
certutil -hashfile publisher.cer SHA256
cmake --preset windows-x64 -DHIDFIDO_TRUSTED_SIGNER_SHA256=<64-hex-SHA256>
cmake --build --preset release
```

Replace placeholders before running commands. The pin is compiled into the
manager; a runtime flag cannot select another publisher. All five payloads
must have a valid Authenticode signature from that certificate.

## Sign binaries, then package

Use the Windows SDK [SignTool](https://learn.microsoft.com/en-us/windows/win32/seccrypto/signtool)
to sign and timestamp the five build outputs. Example with a certificate in
the current user's My store:

```cmd
signtool sign /sha1 <certificate-thumbprint> /fd SHA256 /tr <timestamp-service-URL> /td SHA256 build\Release\Gestione-HID-FIDO2.exe build\Release\HidFido2CredentialProvider.dll build\Release\hid-fido2-files.exe build\Release\hid-fido2-vault.exe build\Release\provider-smoke.exe
```

Use the appropriate store/provider options for the certificate. Do not keep
private key exports in this repository. Signing changes binary hashes, so
always generate the release manifest after signing:

```cmd
start /wait "" build\Release\Gestione-HID-FIDO2.exe --package "%CD%\build\Release" "%CD%\out\releases" --result "%CD%\out\signed-package.json"
```

The native producer finds the matching certificate in the user or machine My
store, signs `release.json` with a detached CMS signature and writes
`release.p7s`. Final validation checks payload Authenticode, certificate
identity, the detached signature and the manifest's exact file hashes.

## Lifetime and operational checks

The CMS manifest signature is not automatically given an Authenticode
timestamp. Its certificate must be valid at verification time. Plan new
releases and certificate-pin rotation before expiry. Do not promise indefinite
validity based only on PE timestamps.

Validate the real signing chain, timestamping, revocation behavior and target
App Control policy before distribution. A certificate does not guarantee a
provider will be accepted in every LogonUI configuration. Real signing and
the full device compatibility/recovery matrix require separate validation.

For local-only development, leave the pin empty and keep every payload
unsigned. Mixed signed/unsigned packages and invalid signatures are rejected;
the prototype profile is not a bypass for damaged or untrusted signatures.
