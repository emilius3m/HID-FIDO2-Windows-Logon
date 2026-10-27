# Recovery

Keep a working native Windows sign-in method before enabling a third-party
provider. Know the current Windows password and prepare a recovery account
or recovery media. If BitLocker is enabled, keep its recovery key outside the
computer. A FIDO2 sign-in key does not unlock BitLocker.

## Windows is accessible

Use **Opzioni di accesso → Password** to sign in. Open **Gestione HID FIDO2 →
Impostazioni → Installazione → Rimuovi accesso con chiave…** (English:
**Settings → Installation → Remove key sign-in…**) to remove the project's registration.
This preserves vault data and other credential providers.

The native update controller stages and checks the new package before
changing registration. After failure it attempts compatible rollback.
If rollback is incomplete, use Windows password recovery and inspect the
protected deployment/recovery information before retrying.

Installation files are under:

```text
%ProgramFiles%\HID-FIDO2-WinLogon\releases\<release-id>
%ProgramFiles%\HID-FIDO2-WinLogon\deployments\<deployment-id>.json
%ProgramFiles%\HID-FIDO2-WinLogon\deployments\<deployment-id>.disable-provider.reg
```

The `.reg` file disables only this provider on the running Windows instance.
It is not a vault restore and must not be directly imported in Windows RE.
Do not delete immutable binaries while a process might still have them loaded.

## Password or vault problems

- Password changed: use the current Windows password, then update the
  encrypted copy from the manager using an enrolled key.
- Key lost: revoke it and provision another backup. Change the Windows
  password if an older vault copy and the lost key could be combined.
- Compatible encrypted payload damaged: a protected same-generation copy
  may repair it while retaining current authorities and counters.
- Vault missing or unreadable: use Windows recovery credentials. The current
  backup mechanism requires an existing compatible record and is not a full
  vault or disk recovery mechanism.

Never restore an older password generation or arbitrary historical vault
over the current file. That can undo revocation or reintroduce obsolete data.

## Offline recovery with Windows RE

Identify and unlock the correct Windows volume first. Drive letters can
change in recovery. The example below assumes the intended installation is
on `D:`. Verify `D:\Windows\System32\Config\SOFTWARE` before continuing.

```cmd
reg load HKLM\HidFidoRecovery D:\Windows\System32\Config\SOFTWARE
reg query "HKLM\HidFidoRecovery\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{8B5D856B-C940-4AFB-A050-167F5D4F75E2}"
reg delete "HKLM\HidFidoRecovery\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{8B5D856B-C940-4AFB-A050-167F5D4F75E2}" /f
reg unload HKLM\HidFidoRecovery
```

Check each result. After a successful `reg load`, always run `reg unload` at
the end. Remove only this project's provider activation. Leave SAM, SYSTEM,
authentication-package lists, other providers and filters unchanged. COM
registration can be cleaned up later from an accessible Windows session.

These commands target the mounted offline SOFTWARE hive, unlike the generated
`.reg` file, which refers to the running system's HKLM. Recovery procedures
must be tested for the actual device and Windows build.
