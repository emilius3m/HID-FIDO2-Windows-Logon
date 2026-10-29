# Security model

HID FIDO2 Windows Logon is experimental security-sensitive software. It is
not certified, independently audited, or supported for general production
deployment. Test recovery before enabling it on a device.

## Authentication boundary

The Credential Provider collects a security-key PIN, verifies a FIDO2
assertion, decrypts the stored Windows password and serializes it for the
standard Windows authentication package. Windows decides whether to grant
access. The project does not install an authentication package, modify LSASS,
replace Windows Hello, change Secure Boot or disable code-integrity policies.

The native Windows password provider remains available. Therefore the
security key is an additional sign-in method, not an enforcement mechanism
requiring the key for every Windows sign-in. Microsoft recommends keeping a
[system credential provider available](https://learn.microsoft.com/en-us/windows/win32/secauthn/credential-providers-in-windows).

## Stored secrets and hardware assumptions

- A random data-encryption key protects the Windows password with AES-256-GCM.
- Each enrolled key independently wraps that data key using a verified
  `hmac-secret` result and HKDF-derived encryption material.
- Metadata is bound to authenticated envelopes; a file checksum alone is
  not an authenticity guarantee.
- The machine vault and backups allow SYSTEM and Administrators only.
- PINs are not persisted or passed as command-line arguments. Native dialogs
  collect PINs/passwords. Sensitive buffers are cleared; memory locking is
  best effort and does not defend against a compromised trusted process.
- Assertions are checked for signature, RP, challenge, user presence,
  verification, counters and signed extension contents.

A verified assertion with UV does not prove another client cannot obtain the
same key secret without a PIN. New enrollment performs a separate test after
physical reconnection: access without a PIN must be explicitly denied or
yield a different secret, followed by a stable result with PIN verification.
Identical or inconclusive results are rejected. Existing records with unknown
proof are shown as such; successful authentication never upgrades that claim.
An explicit unsigned local-prototype compatibility exception can preserve
existing registrations during an update; it does not certify their hardware.

## Trusted components and package integrity

The manager, vault helper, provider DLL, Windows kernel, SYSTEM and local
administrators form part of the trust boundary. The design does not protect
against compromise of those components, privileged debugging, malicious
firmware, physical key extraction or a captured usable Windows password.

The launcher validates the fixed five-binary package, hashes and trust
profile before UAC, repeats validation after elevation and pins source files
against replacement. Operations use a protected immutable copy. The manager
uses a static CRT and restricted system-DLL loading. Signature enforcement
uses a publisher certificate SHA-256 pin and a detached CMS manifest signature.

Unsigned mode is only for explicitly trusted local prototypes. A hash
manifest cannot establish the origin of an unsigned package. A valid
certificate does not guarantee admission under every Windows App Control
policy. No trust root or policy is installed or weakened by the product.

## Password changes, revocation and backups

Change the password in Windows first, then update the encrypted copy using
an enrolled key. A Windows rejection of a stored password suspends that
record to avoid repeated stale-password attempts.

Revocation affects the current vault. If someone possesses both an old vault
copy and a key authorized by that copy, revocation or data-key rotation in
the current vault does not make the old password ciphertext unusable. Change
the Windows password when that exposure is possible.

Backup restore requires the current record, an authorized key, a compatible
password generation and a successful Windows password validation. It keeps
current authorities, revocations and counters. It cannot recreate an absent
or wholly unreadable vault and is not a full machine backup.

See [recovery](docs/recovery.md) and [release signing](docs/signing.md).

## Reporting issues

For a vulnerability, use the hosting repository's private vulnerability
reporting channel when available. Do not publish an exploit or sensitive
artifacts in a public issue before coordinated disclosure. Never attach
passwords, PINs, private keys, vault files, recovery keys or personal account
identifiers. For ordinary bugs, provide a minimal reproduction, Windows
version, key model and sanitized public error codes.

## File encryption

The File tab and the File Explorer menu start `hid-fido2-files.exe` from the
protected release copy, with the user's normal rights. It encrypts in the age
format for every key in the user's profile and an optional paper recovery key.
Windows WebAuthn collects the key PIN; the recovery secret exists only in the
helper window that shows or receives it. The profile contains public data only
and is never trusted for anything but choosing recipients. Files encrypted for
a lost or stolen key stay readable with that key and its PIN until they are
re-encrypted. Details: [file and folder encryption](docs/file-encryption.md).
