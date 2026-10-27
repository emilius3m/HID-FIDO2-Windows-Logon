# Manager screenshots

These PNGs were captured from the actual native Windows manager in version
0.9.0 using its built-in demo snapshot mode. All displayed account state,
key labels, hardware verification results and backup metadata are synthetic.
Real actions are disabled. This directory holds the Italian captures;
`en/` holds the English captures of the same seven pages and physical guidance.
The key labels are sample saved data and remain unchanged in English. The Medium article
retains its separate version 0.7 captures in `../medium-article/images/`.

To reproduce the captures from the complete distribution package:

```cmd
start /wait "" app\Gestione-HID-FIDO2.exe --demo --demo-state ready --language it --snapshot "C:\path\to\captures"
start /wait "" app\Gestione-HID-FIDO2.exe --demo --demo-state ready --language en --snapshot "C:\path\to\english-captures"
start /wait "" app\Gestione-HID-FIDO2.exe --demo --language en --wizard-step touch --snapshot "C:\path\to\touch"
```

The application writes seven PNGs and exits, or one `native-wizard.png`
when `--wizard-step` is supplied. Rename them as follows when
updating this directory:

| Generated file | Documentation file |
| --- | --- |
| `native-manager-0.png` | `manager-overview.png` |
| `native-manager-1.png` | `manager-keys.png` |
| `native-manager-2.png` | `manager-recovery.png` |
| `native-manager-3.png` | `manager-installation.png` |
| `native-manager-4.png` | `manager-setup.png` |
| `native-manager-5.png` | `manager-support.png` |
| `native-manager-6.png` | `manager-settings.png` |
| `native-wizard.png` with `--wizard-step touch` | `wizard-touch.png` |

Optional `--demo-state empty` previews an unenrolled account;
`--demo-state ready` previews two checked keys. These switches require
`--demo` and never read or change the real installation or vault.
Without a state override, the spare key has an unknown hardware check.
`--demo-compact` previews the minimum 760 × 560 client area.

Wizard preview steps are `connect`, `pin`, `touch`, `release`, `remove`,
`reconnect`, `password` and `success`. Input and Continue are disabled in
these previews. The physical illustrations use the embedded
[instructional atlas](../../resources/guidance-art.md), also used by the real
vault helper; they depict a generic key rather than a particular model.

The screenshots illustrate the management application. They are not captures
of the Windows secure sign-in desktop or evidence of successful authentication.
