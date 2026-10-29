# File and folder encryption

`hid-fido2-age.exe` encrypts files and folders in the standard
[age](https://age-encryption.org/v1) format for several recipients at once:

- the **Principale** security key,
- the **Riserva** security key,
- a **paper recovery key** that works without any security key.

Any one of them opens the file. The security keys use the FIDO2 `hmac-secret`
extension through the WebAuthn PRF interface of Windows, in the
`age-encryption.org/fido2prf` format of [typage](https://jsr.io/@age/age-encryption)
and `age-plugin-fido2prf`. The recovery key is a standard age X25519 key, so a
file can always be opened with the official `age` tool on any system.

The tool is separate from Windows sign-in: it does not use the machine vault,
does not need administrator rights and is not part of the sign-in release
package. Its credentials use their own relying party (`hid-fido2-age`), so they
are unrelated to the sign-in credentials on the same key.

## Requirements

- Windows 11 22H2 or later (WebAuthn API version 4) to use security keys. The
  recovery key works on any supported Windows version.
- A FIDO2 security key with a PIN and the `hmac-secret` extension.

Windows shows its own security-key dialog, asks for the PIN and for the touch.
The tool never receives the PIN.

## Set up once

Create a *profile*: a small text file with the public data of every recipient.

```cmd
hid-fido2-age --new-key Principale --profile destinatari.txt
hid-fido2-age --new-key Riserva --profile destinatari.txt
hid-fido2-age --new-recovery --profile destinatari.txt
```

`--new-key` creates a dedicated credential on the connected key (PIN and one
touch). `--new-recovery` shows the recovery key **once**: write it down or print
it, and store it somewhere safe and separate from the keys. It is never saved on
the computer. Anyone holding it can open every file encrypted with the profile.

The profile contains only public data (credential IDs and the public half of the
recovery key). Keep a copy with your encrypted files. A secret recovery key is
refused if someone pastes it into a profile.

## Encrypt

```cmd
hid-fido2-age --encrypt Contratto.pdf --profile destinatari.txt
hid-fido2-age --encrypt "C:\Users\me\Documenti" --profile destinatari.txt
```

- A file becomes `Contratto.pdf.age`; a folder becomes `Documenti.tar.age`.
- **Each security key in the profile must be connected and touched once**,
  one after the other, because fido2prf is a symmetric recipient: wrapping the
  file key for a security key needs that key. The recovery key needs nothing.
- A folder is stored as one archive, so it costs one touch per key regardless
  of how many files it contains. File names are encrypted with the contents.
- The original is not changed or deleted. Delete it yourself once you have
  checked that the encrypted copy opens. Normal deletion does not securely erase
  data; use full-disk encryption (BitLocker) for that guarantee.
- Existing files are never overwritten. Output is written to a temporary name
  and renamed only when complete.

## Decrypt

```cmd
hid-fido2-age --decrypt Contratto.pdf.age --profile destinatari.txt
hid-fido2-age --decrypt Documenti.tar.age --profile destinatari.txt --output Ripristino
```

Connect either key when asked. Each key stanza in the file costs one touch:
with Principale, one touch is enough; with only Riserva connected, Windows asks
twice (the first stanza belongs to Principale). With `--output`, a folder is
extracted inside a new destination folder; without it, next to the encrypted
file, refusing any name that already exists.

Without security keys, type the paper key (input is hidden; spaces are ignored):

```cmd
hid-fido2-age --decrypt Contratto.pdf.age --recovery
```

or use `--identity key.txt` with a file containing the `AGE-SECRET-KEY-1...` line.

Decryption authenticates every 64 KiB chunk and the end of the file. A damaged,
truncated, reordered or extended file is rejected and no partial result is kept.
Folder archives are extracted into a private temporary folder and moved into
place only after the whole archive has been authenticated. The archive reader
accepts only regular files and folders and rejects absolute paths, `..`,
links, devices, duplicate entries and names that are invalid on Windows.

## Other systems

Files are standard age files:

```sh
age -d -i recovery-key.txt Contratto.pdf.age > Contratto.pdf
age -d -i recovery-key.txt Documenti.tar.age | tar -x
```

With [`age-plugin-fido2prf`](https://github.com/FiloSottile/typage/tree/main/fido2prf)
installed, a file containing a key's `AGE-PLUGIN-FIDO2PRF-1...` line from the
profile also works as an age identity: `age -d -i principale.txt FILE.age`.
Browser-based typage cannot use these credentials, because a web page can only
use credentials of its own domain.

## Security notes

- Protection relies on the PIN-protected `hmac-secret` of each key (user
  verification is required), on the secrecy of the paper key, and on the
  integrity of this Windows session while a file is open.
- The file size and the number of recipients are visible without decryption.
- Losing every security key **and** the paper key makes the files unrecoverable.
- Removing a key from the profile affects only new files. Files encrypted before
  still open with that key; re-encrypt them if a key is lost or stolen.
- If the process is killed during decryption, a temporary `*.partial*` file or
  `.hid-fido2-age-*.partial` folder may remain next to the output. It holds
  decrypted data: delete it.
- Not supported: passphrase (scrypt) recipients, ASCII armor, other age plugins,
  and tar archives with GNU-specific long-name records.

## Implementation and tests

`src/age` contains a portable implementation of the age v1 format (SHA-256,
HMAC, HKDF, ChaCha20-Poly1305, X25519, Bech32), fido2prf, and the folder
archive, plus the Windows WebAuthn backend and the command-line tool.
`AgeFileEncryption` runs RFC known-answer tests, a file produced by the reference
`age` tool, the [C2SP age test vectors](../tests/age-testkit/README.md),
an independently computed fido2prf vector, multi-recipient round trips with a
software authenticator, tamper detection and hostile archives. It does not use
a security key; WebAuthn dialogs require manual testing with real hardware.
