# User guide

The manager supports **Italian and English**. Choose **Lingua / Language**
at the bottom of the sidebar; the current page updates immediately. The
choice is saved for this computer and also used by newly opened key dialogs
and the sign-in component when it is next loaded. The first run follows the
Windows display language for Italian, otherwise English. Windows-managed
dialogs such as UAC and Settings keep the Windows display language.

Key names are your saved data: switching language does not rename existing
keys. Demo mode changes only the preview language and does not save it.

The manager is named **Gestione HID FIDO2** / **HID FIDO2 Manager**.
Management requires UAC elevation as the same Windows account being enrolled;
using another administrator's credentials is rejected.

## Enrollment and activation

1. Confirm the current Windows password works and prepare a second key.
2. Open the native manager from a trusted complete package.
3. Register **Principale**. Enter the security-key PIN in the native dialog,
   touch and release the sensor as requested, and follow the disconnect and
   reconnect instructions for the independent hardware check.
4. Enter the Windows password only in its native dialog. The tool verifies
   it with Windows for the expected account before saving the encrypted record.
5. Add **Riserva**, first unlocking with an enrolled key, then switching to
   the new key when prompted. Only connect one key at a time.
6. In **Installazione / Installation**, activate key sign-in after both registrations are
   ready. Normal installation requires two recorded hardware protection proofs.

Identical secrets without PIN or inconclusive hardware results abort new
enrollment. No automatic PIN retry is made. Cancel when uncertain rather
than repeatedly guessing a PIN.

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
**Controlla sicurezza / Check security** performs the per-credential hardware check,
including physical reconnection. **Prova chiave / Test key** tests local usability.
These are different checks: successful sign-in does not set a missing proof.

**Aggiungi chiave / Add key** authorizes enrollment using a current key. **Rimuovi / Remove**
revokes a key from the current vault without deleting its physical credential.
The last enrolled key cannot be removed through that action.

If a key is lost, sign in with the Windows password, revoke it and add a new
backup. If both the lost key and an older vault copy could be accessible to
someone else, also change the Windows password.

## Password changes

Change the password through Windows first. Then choose **Password e recupero →
Aggiorna password salvata** / **Password and recovery → Update saved password**
and authorize with an enrolled key. Updating the same
data key's password payload preserves the other key wrappers.

A Windows rejection of an outdated stored password suspends the record.
Use the Windows password and update the encrypted copy before trying key
sign-in again. Do not attempt repeated sign-ins with a known stale password.

## Backups and removal

Create an encrypted backup from **Password e recupero / Password and recovery**. Restore accepts only
the current account's compatible record/password generation and validates
the password with Windows. Current revocations, counters and key authorities
are retained. A copy cannot recreate a missing or completely unreadable vault.

**Installazione → Rimuovi accesso con chiave** / **Installation → Remove key sign-in** removes the additional provider's
registration. Vault, backups, deployment records and immutable binaries are
preserved. No automatic lock, sign-out or restart is performed.

See [recovery](recovery.md) for normal and offline recovery paths.
