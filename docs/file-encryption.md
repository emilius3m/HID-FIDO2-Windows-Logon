# File and folder encryption

HID FIDO2 can encrypt files and folders in the standard
[age](https://age-encryption.org/v1) format for several recipients at once:

- the **Principale** security key,
- the **Riserva** security key,
- a **paper recovery key** that works without any security key.

Any one of them opens the file. The security keys use the FIDO2 `hmac-secret`
extension through the WebAuthn PRF interface of Windows, in the
`age-encryption.org/fido2prf` format of [typage](https://jsr.io/@age/age-encryption)
and `age-plugin-fido2prf`. The recovery key is a standard age X25519 key, so a
file can always be opened with the official `age` tool on any system.

File encryption is separate from Windows sign-in: it does not use the machine
vault, and its credentials use their own relying party (`hid-fido2-age`), so
they are unrelated to the sign-in credentials on the same key.

## Requirements

- Windows 11 22H2 or later (WebAuthn API version 4) to use security keys. The
  recovery key works on any supported Windows version.
- A FIDO2 security key with a PIN and the `hmac-secret` extension.

Windows shows its own security-key dialog, asks for the PIN and for the touch.
No HID FIDO2 program receives the PIN.

## Set up once: the Files tab

Open **Gestione HID FIDO2** and choose the **File** tab.

1. **Add key…** → *Principale*: connect the key; Windows asks for its PIN and a
   touch, and a credential used only for files is created on it.
2. **Add key…** → *Riserva*: the same with the backup key. A key that is already
   in the profile is refused, so the backup cannot end up on the same hardware.
3. **Create recovery key…**: the key is shown **once**. Write it down or use
   **Print…**, store the sheet away from the keys, tick the confirmation and
   choose **Done**. It is never saved on the computer; anyone holding it can
   open every file encrypted with the profile. Closing the window without
   confirming adds nothing.
4. Optionally tick **Show "Encrypt" and "Decrypt" in the File Explorer
   right-click menu**.

The tab shows the keys and whether a recovery key exists. These choices are
stored in a *profile*, `%APPDATA%\HID-FIDO2-WinLogon\Files\destinatari.txt`,
which contains only public data (credential IDs and the public half of the
recovery key). **Open the profile folder** lets you keep a copy of it with your
encrypted files: a computer needs the profile to use the security keys.

## Encrypt and decrypt

From the Files tab choose **Encrypt file…**, **Encrypt folder…** or
**Decrypt…**; with the Explorer menu enabled, right-click a file or folder and
choose **Encrypt with FIDO2 key**, or right-click a `.age` file and choose
**Decrypt with FIDO2 key** (double-click also works unless another program
already owns `.age` files). In Windows 11 these entries are under **Show more
options**. Each operation opens a small **Encrypted files** window that shows
which key to connect and the progress.

- A file becomes `Contratto.pdf.age`; a folder becomes `Documenti.tar.age`.
  An existing name is never overwritten: the result is called, for example,
  `Contratto (2).pdf.age`.
- **Encrypting needs each security key in the profile, one after the other**
  (PIN and touch), because fido2prf is a symmetric recipient: wrapping the file
  key for a security key needs that key. The recovery key needs nothing.
- A folder is stored as one archive, so it costs one touch per key regardless
  of how many files it contains. File names are encrypted with the contents.
- Decrypting needs **one** key. When the file can also be opened with the
  recovery key, the window asks which one to use. Each key stanza costs one
  touch: with Principale one touch is enough; with only Riserva connected,
  Windows asks twice (the first stanza belongs to Principale).
- With the recovery key, type it as written on the sheet; spaces and letter
  case do not matter, and a mistyped key is detected before anything is read.
- The original is not changed or deleted. Delete it yourself once you have
  checked that the encrypted copy opens. Normal deletion does not securely erase
  data; use full-disk encryption (BitLocker) for that guarantee.

The manager starts these windows with your normal (non-elevated) rights, so
they see your network drives and the files you create belong to you. They run
the protected copy installed under `%ProgramFiles%\HID-FIDO2-WinLogon`, which
standard users can run but not modify; the Explorer entries point to the same
copy and are updated when the manager starts after an update.

## Command line

`hid-fido2-age.exe` (built with the project, not part of the release package)
offers the same operations for scripts and advanced users. Without `--profile`
it uses the same profile as the Files tab.

```cmd
hid-fido2-age --new-key Principale
hid-fido2-age --new-key Riserva
hid-fido2-age --new-recovery
hid-fido2-age --encrypt "C:\Users\me\Documenti"
hid-fido2-age --decrypt Documenti.tar.age --output Ripristino
hid-fido2-age --decrypt Contratto.pdf.age --recovery
```

`--identity key.txt` reads the recovery key from a file containing the
`AGE-SECRET-KEY-1...` line. The command line refuses existing output names
instead of renaming.

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
- The manager never handles keys, PINs or the recovery secret: it reads the
  public profile and starts the helper. The recovery key exists only in the
  helper window that shows or receives it, and is cleared after use. Printing
  passes it through the Windows print spooler.
- The file size and the number of recipients are visible without decryption.
- Losing every security key **and** the paper key makes the files unrecoverable.
- Adding or removing a key affects only new files. Files encrypted before keep
  their recipients; re-encrypt them if a key is lost or stolen.
- Decryption authenticates every 64 KiB chunk and the end of the file. A
  damaged, truncated, reordered or extended file is rejected and no partial
  result is kept. Folder archives are extracted into a private temporary folder
  and moved into place only after the whole archive has been authenticated; the
  reader accepts only regular files and folders and rejects absolute paths,
  `..`, links, devices, duplicate entries and names invalid on Windows.
- If the process is killed during an operation, a temporary `*.partial*` file
  or `.hid-fido2-age-*.partial` folder may remain next to the output. It may
  hold decrypted data: delete it.
- Not supported: passphrase (scrypt) recipients, ASCII armor, other age plugins,
  and tar archives with GNU-specific long-name records.

## Implementation and tests

`src/age` contains a portable implementation of the age v1 format (SHA-256,
HMAC, HKDF, ChaCha20-Poly1305, X25519, Bech32), fido2prf, the folder archive and
the shared file operations (`files.cpp`), plus the Windows WebAuthn backend, the
graphical helper `hid-fido2-files.exe` and the command line. The manager's Files
page is `src/manager/files.cpp`.

- `AgeFileEncryption` runs RFC known-answer tests, a file produced by the
  reference `age` tool, the [C2SP age test vectors](../tests/age-testkit/README.md),
  an independently computed fido2prf vector, multi-recipient round trips with a
  software authenticator, tamper detection, hostile archives and the file
  operations (profiles, naming, cancellation, no leftovers).
- `FilesPageIsolation` checks the helper arguments and the Explorer
  registration in a private HKCU tree, including preservation of another
  program's `.age` association.

They do not use a security key; WebAuthn dialogs require manual testing with
real hardware. `hid-fido2-files.exe --preview touch|choose|recovery|show|success|failure`
shows each window state with synthetic data and actions disabled.
