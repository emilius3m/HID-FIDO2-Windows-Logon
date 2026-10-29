# Building and packaging

## Toolchain

- Windows x64.
- Visual Studio 2022 or Build Tools, Desktop development with C++.
- Windows SDK 10.0.22621.0.
- CMake 3.24 or newer.

The checked-in [CMake presets](../CMakePresets.json) configure the x64 Visual
Studio generator. No third-party library or package manager is required.
Python is optional for regenerating documentation diagrams or the icon, and
for the source-level localization check:

```cmd
python scripts\check-ui-localization.py
```

Translations are built into the binaries from `include/hidfido/strings.inc`;
the installed app requires no Python or external language files.

From a Developer Command Prompt:

```cmd
cmake --preset windows-x64
cmake --build --preset release
ctest --preset release
```

This compiles the five product binaries, the optional `hid-fido2-age.exe`
command line and the isolated tests in `build\Release`. Compilation and tests do not install or register a provider.
The product uses Windows APIs; provider/helpers use the MSVC x64 runtime,
while the manager bootstrap links its CRT statically.

The package includes the file-encryption helper `hid-fido2-files.exe`;
`hid-fido2-age.exe` is not packaged. The `AgeFileEncryption` test also reads the
C2SP vectors in `tests/age-testkit`; the portable age core (`src/age/crypto.cpp`,
`age.cpp`, `tar.cpp`, `files.cpp`) and `tests/age_tests.cpp` build with any C++20
compiler, without Windows. `FilesPageIsolation` checks the Files page's Explorer
registration in a private HKCU tree. `hid-fido2-files.exe --preview <state>`
(`touch`, `choose`, `recovery`, `show`, `success`, `failure`; add
`--snapshot <folder>` for PNG files) shows the helper with synthetic data.

## Optional hardware diagnostics

```cmd
cmake --preset windows-x64 -DHIDFIDO_BUILD_DIAGNOSTICS=ON
cmake --build --preset release
```

This additionally builds `ctap-probe.exe` and `ctap-transport-check.exe`.
These inspect capabilities/transport without enrollment or PIN attempts.
Raw HID access may require elevation. They are developer diagnostics and are
not included in the five-binary product package.

## Package creation

```cmd
start /wait "" build\Release\Gestione-HID-FIDO2.exe --package "%CD%\build\Release" "%CD%\out\releases" --result "%CD%\out\package.json"
```

The native producer validates AMD64 PE inputs, rejects the test provider,
computes hashes and creates `out\releases\0.9.0\<release-id>`. It verifies
the completed package and writes its directory to the requested JSON result.
Existing result files are not overwritten: choose a new filename each time.

Do not add README files, logs or other payloads inside the immutable release
directory. Ship documentation beside the package or link to repository docs.
No secrets, certificates with private keys, vaults or enrollment databases
belong in the source tree or release package.

## Preview and package verification

```cmd
build\Release\Gestione-HID-FIDO2.exe --demo
build\Release\installer_trust_tests.exe --verify-local-release "<release-directory>"
```

Demo mode uses synthetic data, disables real actions, does not elevate and
does not read the machine vault. The verification command checks a local
unsigned package without launching any payload or changing Windows settings.

`--demo-compact` uses the minimum window size. `--wizard-step touch` (or
`connect`, `pin`, `release`, `remove`, `reconnect`, `password`, `success`)
previews the shared guided view with real actions and secret input disabled.
Both options require `--demo`. See [screenshot reproduction](images/README.md).

`CompactUserExperience` checks honest status selection and isolated setup
preferences. `GuidedCeremonyIsolation` uses a hidden test-only UI build to
check synthetic PIN normalization, secret-field clearing, cancellation and
the distinction between hardware waits and user acknowledgements. Its input
hooks are not compiled into the shipped vault helper. No key or Windows
authentication is used by that test.

For a signed distribution, configure the publisher pin and follow
[signing](signing.md). A passing build is not authorization to install an
experimental provider on another computer.

## Optional live ETW checks (development only)

`GuidedSetupAndSupport` normally tests the pure setup model, rename arguments
and report privacy/size boundaries without creating an ETW session. To also
test the actual Windows controller and TDH decoder, use an elevated Developer
Command Prompt and new result filenames:

```cmd
build\Release\management_experience_tests.exe --etw-self-test "%CD%\out\etw-synthetic.json"
build\Release\management_experience_tests.exe --etw-deadline-test "%CD%\out\etw-deadline.json"
```

The first check starts/stops collection twice and publishes synthetic numeric
events plus deliberately excluded text. The second takes five minutes and
checks automatic shutdown without a UI message loop. Neither uses a key,
reads a password, changes provider registration or attempts authentication.
They control a temporary session for this project's diagnostic provider only.
The test executable is not a distribution payload.
