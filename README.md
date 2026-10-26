# HID FIDO2 Windows Logon

[English](README.md) · [Italiano](README.it.md)

Native C++ Windows application and Credential Provider for signing in to and unlocking a local Windows account with a USB FIDO2 security key.

**Experimental software.** The Windows password is stored encrypted, recovered after a verified FIDO2 assertion, and submitted to standard Windows authentication. This is a password-backed credential provider, not a replacement for the Windows authentication authority. Keep a working Windows password recovery option.

## Features

- Native Win32 manager for enrollment, key verification, revocation and status.
- CTAP2 / USB HID with FIDO2 PIN and user-presence verification.
- Per-key `hmac-secret` protection and recorded hardware protection checks.
- Encrypted machine vault, password updates and protected compatible backups.
- Native installation, update, rollback and provider removal.
- Package hashes, publisher pinning, Authenticode and detached manifest signing.
- Application and installer require no PowerShell, .NET, browser, custom USB driver or network service.

Current version: **0.6.0**. The UI is currently in Italian.

## Requirements and scope

| Component | Supported scope |
| --- | --- |
| Operating system | Windows 11 x64 |
| Account | Local account; management must elevate as that same account |
| Security key | USB FIDO2, ES256, PIN protocol 1 and `hmac-secret` |
| Recovery | Current Windows password and a second enrolled key |
| Runtime | Windows APIs and the MSVC x64 runtime used by provider/helpers |

HID Crescendo has been used during development. Other authenticators, Windows builds, Microsoft accounts, domain/Entra accounts and RDP are not validated. Automated checks do not establish end-to-end logon compatibility on a device. This version is not certified or ready for general production deployment.

## Install from a prepared package

Extract the complete distribution ZIP, then open
`app/Gestione-HID-FIDO2.exe`. This executable contains both the native manager
and the installer. Keep `release.json` and the `bin` directory beside it;
copying only the executable is not sufficient.

Locally prepared distributions are kept in `dist/`, excluded from source
control. Publish the distribution ZIP as a GitHub Release asset.

## Build and test

Install Visual Studio 2022 or Build Tools with Desktop development with C++, Windows SDK **10.0.22621.0**, and CMake **3.24 or newer**. From a Developer Command Prompt in the repository root:

```cmd
cmake --preset windows-x64
cmake --build --preset release
ctest --preset release
```

Tests cover cryptography, CTAP framing and cancellation, vault integrity and concurrency, logon serialization, isolated COM loading, package verification and native deployment. Registry tests use a private temporary HKCU tree, without registering a provider in HKLM.

Preview the UI with synthetic data and real actions disabled:

```cmd
build\Release\Gestione-HID-FIDO2.exe --demo
```

See [building and packaging](docs/building.md) for diagnostics and signed-release configuration.

## Create a package

```cmd
start /wait "" build\Release\Gestione-HID-FIDO2.exe --package "%CD%\build\Release" "%CD%\out\releases" --result "%CD%\out\package.json"
```

Use a new result filename each time. Packaging does not install or register anything. The release directory contains:

```text
Gestione-HID-FIDO2.exe
bin/HidFido2CredentialProvider.dll
bin/hid-fido2-vault.exe
bin/provider-smoke.exe
release.json
```

Signed releases also contain `release.p7s`. Keep the complete directory together: missing, altered or unexpected payloads are rejected.

## Use

1. Open `Gestione-HID-FIDO2.exe` from a trusted complete package. Approve UAC as the same Windows account; unsigned local builds require explicit prototype consent.
2. Enroll a primary key and a backup key using the native dialogs. Enter Windows passwords and key PINs only in those dialogs.
3. Install the provider from **Installazione**, after checking Windows password recovery works.
4. Lock Windows, select **Opzioni di accesso → HID FIDO2**, enter the key PIN and touch the key when requested.

The installed manager is **Gestione HID FIDO2** in Start and on the Desktop. After changing the Windows password, update its encrypted copy in **Password e recupero**. See the [user guide](docs/usage.md).

## Security and recovery

The vault uses AES-256-GCM and separate per-key wrapping of its data key. Access is restricted to SYSTEM and Administrators. PINs are not persisted; decrypted secrets are cleared after use.

Successful sign-in alone does not prove hardware protection against requests without a PIN. New enrollment requires explicit denial or a distinct secret in the independent hardware test; inconclusive results fail closed.

The Windows password provider remains available. Provider removal preserves vault data. Compatible backups preserve current revocations and counters and do not restore obsolete password generations. They are not complete disaster recovery.

Read the [security model](SECURITY.md) and [recovery instructions](docs/recovery.md) before enabling the provider. Distribution requires a real certificate and a validated [signing procedure](docs/signing.md).

## Project structure

| Directory | Contents |
| --- | --- |
| `src/manager` | Native desktop manager, packaging and deployment |
| `src/credential_provider` | COM provider, serialization and public diagnostics |
| `src/ctap` | CTAP2, PIN protocol, USB HID and protection checks |
| `src/vault`, `src/password` | Machine vault and authenticated encryption |
| `src/ui`, `resources` | Native dialogs, icon and version resources |
| `include/hidfido` | Shared interfaces |
| `tests` | Automated isolated tests |
| `docs` | Current architecture, usage, build, signing and recovery |

[Architecture](docs/architecture.md) · [MIT license](LICENSE)
