# User guide

The manager supports **Italian and English**. Choose **Settings → Lingua / Language**;
the current page updates immediately. The
choice is saved for this computer and also used by newly opened key dialogs
and the sign-in component when it is next loaded. The first run follows the
Windows display language for Italian, otherwise English. Windows-managed
dialogs such as UAC and Settings keep the Windows display language.

Key names are your saved data: switching language does not rename existing
keys. Demo mode changes only the preview language and does not save it.

The installed shortcut is **Gestione HID FIDO2**. The application window is **HID FIDO2**.
Management requires UAC elevation as the same Windows account being enrolled;
using another administrator's credentials is rejected.

## Enrollment and activation

The three tabs are **Accesso / Sign-in**, **Chiavi / Security keys** and
**Impostazioni / Settings**. Sign-in shows one status and the next action.
Password recovery, installation, support and language are under Settings.

**Configurazione guidata / Guided setup** starts from Sign-in when setup is
incomplete, or from **Settings → Installation**. It selects the next incomplete step from the current vault
and installation status: password recovery, primary key, spare key, two
hardware protection checks, provider activation and real Windows trials.
It reuses the native enrollment and deployment operations described below.
You can close the manager and resume from the saved keys later. The recovery
confirmation is requested again each time. Confirmations of successful
Windows trials are saved for this user and configuration, so you can resume
after restarting. Changes to the password generation, key metadata or installed
provider invalidate them. These are your own confirmations, never hardware
protection proofs. Confirm only trials you actually completed.

1. Confirm the current Windows password works and prepare a second key.
2. Open the native manager from a trusted complete package.
3. Register the primary key (**Principale**). Enter the security-key PIN in the native dialog,
   touch and release the sensor as requested, and follow the disconnect and
   reconnect instructions for the independent hardware check.
4. Enter the Windows password only in its native dialog. The tool verifies
   it with Windows for the expected account before saving the encrypted record.
5. Add the spare key (**Riserva**), first unlocking with an enrolled key, then switching to
   the new key when prompted. Only connect one key at a time.
6. In **Settings → Installation**, activate key sign-in after both registrations are
   ready. Normal installation requires two recorded hardware protection proofs.

Identical secrets without PIN or inconclusive hardware results abort new
enrollment. No automatic PIN retry is made. Cancel when uncertain rather
than repeatedly guessing a PIN.

The key window shows one physical action at a time: connect, enter the key
PIN, touch, lift your finger, unplug and reconnect. Connection and removal
advance only when detected; a Continue button cannot substitute for a key
response. The lift-finger step asks you to select Continue because the
program cannot detect that gesture. Cancel stops the pending operation;
already completed writes or credentials created on the key are not undone.
Enter passwords and PINs only in these local windows, never in chat or on
the command line. The password screen states that it will be stored encrypted.

## Sign-in and unlock

Connect one enrolled key. On the Windows sign-in screen select
**Opzioni di accesso → HID FIDO2**, enter the key's PIN and touch the key when
requested. This is the FIDO2 key PIN, not the Windows Hello device PIN.

Test unlock with each key separately, then sign-in after restart. Also test
absence, cancellation, removal during an operation and suspend/resume.
The manager's local **Prova chiave / Test key** validates the assertion, decrypts the
vault and verifies the stored password with Windows; it does not unlock or
open a Windows session and does not replace the LogonUI test.

If the key fails, return to the native Windows password option.

## Key management

**Chiavi / Security keys** lists each enrolled key and its recorded security check.
Use the **•••** menu on a row for Test key, Rename, Details and Remove.
Keyboard users can select a row and press Enter, Space or Shift+F10.
An amber **Da verificare / Not checked** status offers the missing check;
Details also shows its result and date. **Controlla sicurezza / Check security** performs the per-credential hardware check,
including physical reconnection. **Prova chiave / Test key** tests local usability.
These are different checks: successful sign-in does not set a missing proof.

**Aggiungi chiave / Add key** authorizes enrollment using a current key. **Rimuovi / Remove**
revokes a key from the current vault without deleting its physical credential.
The last enrolled key cannot be removed through that action.

**Rinomina / Rename** changes the selected key's display name. It needs the
same-account elevated manager, but no PIN or key connection: it only edits
metadata and does not decrypt the Windows password. Credential IDs, key
material, counters, proof dates and password generation stay unchanged.
Names must be unique within the account. An operation concurrent with a
conflicting vault change stops instead of replacing the newer state.

If a key is lost, sign in with the Windows password, revoke it and add a new
backup. If both the lost key and an older vault copy could be accessible to
someone else, also change the Windows password.

## Password changes

Change the password through Windows first. Then open **Settings** and choose **Password e recupero →
Aggiorna password salvata** / **Password and recovery → Update saved password**
and authorize with an enrolled key. Updating the same
data key's password payload preserves the other key wrappers.

A Windows rejection of an outdated stored password suspends the record.
Use the Windows password and update the encrypted copy before trying key
sign-in again. Do not attempt repeated sign-ins with a known stale password.

## Backups and removal

Create an encrypted backup from **Settings → Password and recovery**. Restore accepts only
the current account's compatible record/password generation and validates
the password with Windows. Current revocations, counters and key authorities
are retained. A copy cannot recreate a missing or completely unreadable vault.

**Settings → Installation → Remove key sign-in** removes the additional provider's
registration. Vault, backups, deployment records and immutable binaries are
preserved. No automatic lock, sign-out or restart is performed.

See [recovery](recovery.md) for normal and offline recovery paths.

## Support reports

Open **Settings → Support** and choose **Avvia raccolta / Start collection**
before reproducing an unlock problem. Return using the Windows password if
needed, then stop collection. The sign-in trace stays in memory, is bounded
to 2,048 events and stops after five minutes independently of the UI timer.
Closing the manager normally also stops it. It does not survive a restart
and cannot collect a boot-time sign-in before the manager has started.
If the manager crashes or is forcibly terminated, its shutdown/deadline code
cannot run and the temporary ETW session can remain until Windows restarts.
It still has bounded real-time buffers and no ETL file; a restart clears it.

While collection is running, a native key-management operation also records
its fixed stages and numeric CTAP/Windows error codes. Only its latest
operation is included. The helper temporarily writes this public diagnostic
data in the protected installation's `support` directory; the manager reads
and removes that file when the operation ends. A process crash can leave a
diagnostic file there; it contains no secrets or account/key identifiers.

**Crea report… / Create report…** stops collection, runs
a read-only installation check and opens a short summary. Expand **Show details**
to inspect the JSON; a long preview is abbreviated, while the saved file
retains all collected events. You can cancel, or save
a new UTF-8 JSON file with the native file dialog. Existing files are not
overwritten and nothing is uploaded automatically. Demo reports explicitly
identify their data source as `demo` and never audit the real installation.

Reports exclude PINs, passwords, key labels, account names/SIDs, device
paths, credential IDs, salts, ciphertext and raw memory. PIN-field update
events are discarded. An installation-check failure is included as a failed
check without copying arbitrary exception text. Missing, truncated or
invalid helper diagnostics are marked incomplete rather than exported raw.
