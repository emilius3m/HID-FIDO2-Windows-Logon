# Building and packaging

## Toolchain

- Windows x64.
- Visual Studio 2022 or Build Tools, Desktop development with C++.
- Windows SDK 10.0.22621.0.
- CMake 3.24 or newer.

The checked-in [CMake presets](../CMakePresets.json) configure the x64 Visual
Studio generator. No third-party library or package manager is required.
Python is optional and used only to regenerate the checked-in icon.

From a Developer Command Prompt:

```cmd
cmake --preset windows-x64
cmake --build --preset release
ctest --preset release
```

This compiles the four product binaries and the isolated tests in
`build\Release`. Compilation and tests do not install or register a provider.
The product uses Windows APIs; provider/helpers use the MSVC x64 runtime,
while the manager bootstrap links its CRT statically.

## Optional hardware diagnostics

```cmd
cmake --preset windows-x64 -DHIDFIDO_BUILD_DIAGNOSTICS=ON
cmake --build --preset release
```

This additionally builds `ctap-probe.exe` and `ctap-transport-check.exe`.
These inspect capabilities/transport without enrollment or PIN attempts.
Raw HID access may require elevation. They are developer diagnostics and are
not included in the four-binary product package.

## Package creation

```cmd
start /wait "" build\Release\Gestione-HID-FIDO2.exe --package "%CD%\build\Release" "%CD%\out\releases" --result "%CD%\out\package.json"
```

The native producer validates AMD64 PE inputs, rejects the test provider,
computes hashes and creates `out\releases\0.6.0\<release-id>`. It verifies
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

For a signed distribution, configure the publisher pin and follow
[signing](signing.md). A passing build is not authorization to install an
experimental provider on another computer.
