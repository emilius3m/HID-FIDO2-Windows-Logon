# Manager screenshots

These PNGs were captured from the actual native Windows manager in version
0.7.0 using its built-in demo snapshot mode. All displayed account state,
key labels, hardware verification results and backup metadata are synthetic.
Real actions are disabled. This directory holds the Italian captures;
`en/` holds the English captures of the same four pages.

To reproduce the captures from the complete distribution package:

```cmd
start /wait "" app\Gestione-HID-FIDO2.exe --demo --language it --snapshot "C:\path\to\captures"
start /wait "" app\Gestione-HID-FIDO2.exe --demo --language en --snapshot "C:\path\to\english-captures"
```

The application writes four PNGs and exits. Rename them as follows when
updating this directory:

| Generated file | Documentation file |
| --- | --- |
| `native-manager-0.png` | `manager-overview.png` |
| `native-manager-1.png` | `manager-keys.png` |
| `native-manager-2.png` | `manager-recovery.png` |
| `native-manager-3.png` | `manager-installation.png` |

The screenshots illustrate the management application. They are not captures
of the Windows secure sign-in desktop or evidence of successful authentication.
