# HID FIDO2 Windows Logon

[English](README.md) · [Italiano](README.it.md)

Applicazione Windows e Credential Provider nativi in C++ per accedere a un
account locale e sbloccare il computer con una chiave di sicurezza USB FIDO2.

**Software sperimentale.** La password Windows viene conservata cifrata,
recuperata dopo una verifica FIDO2 e consegnata all'autenticazione standard di
Windows. Il provider usa la password e non sostituisce l'autorità di
autenticazione Windows. Mantieni una password Windows funzionante per il recupero.

## Funzionalità

- Gestore Win32 nativo per registrazione, verifica, revoca e stato delle chiavi.
- CTAP2 / USB HID con verifica del PIN FIDO2 e della presenza dell'utente.
- Protezione `hmac-secret` separata per chiave e prove hardware memorizzate.
- Archivio macchina cifrato, aggiornamento password e copie protette compatibili.
- Installazione, aggiornamento, rollback e rimozione nativi.
- Hash del pacchetto, pin dell'editore, Authenticode e firma del manifest.
- Applicazione e installer senza PowerShell, .NET, browser, driver USB
  personalizzati o servizi di rete.

Versione attuale: **0.6.0**. L'interfaccia è in italiano.

## Requisiti e ambito

| Componente | Ambito supportato |
| --- | --- |
| Sistema | Windows 11 x64 |
| Account | Locale; la gestione deve elevarsi con lo stesso account |
| Chiave | USB FIDO2, ES256, PIN protocol 1 e `hmac-secret` |
| Recupero | Password Windows corrente e seconda chiave registrata |
| Runtime | API Windows e runtime MSVC x64 usato da provider e strumenti |

Durante lo sviluppo è stata utilizzata HID Crescendo. Altre chiavi, build
Windows, account Microsoft, dominio/Entra e RDP non sono convalidati. I test
automatici non dimostrano la compatibilità del login reale su un dispositivo.
La versione non è certificata o pronta per una distribuzione generale in produzione.

## Installazione da un pacchetto pronto

Estrai l'intero ZIP di distribuzione e apri
`app/Gestione-HID-FIDO2.exe`. L'eseguibile comprende gestore e installer
nativi. Mantieni accanto `release.json` e la directory `bin`: il solo
eseguibile non è sufficiente.

Le distribuzioni locali sono conservate in `dist/`, esclusa dal controllo
versione. Lo ZIP va pubblicato come allegato di una GitHub Release.

## Compilazione e test

Servono Visual Studio 2022 o Build Tools con sviluppo desktop C++, Windows
SDK **10.0.22621.0** e CMake **3.24 o successivo**. Da Developer Command Prompt,
nella radice del repository:

```cmd
cmake --preset windows-x64
cmake --build --preset release
ctest --preset release
```

Le suite verificano crittografia, framing e annullamento CTAP, integrità e
concorrenza dell'archivio, serializzazione del login, caricamento COM isolato,
pacchetti e deployment nativo. I test di registro usano una chiave HKCU
temporanea privata, senza registrare il provider in HKLM.

Per vedere l'interfaccia con dati fittizi e operazioni reali disabilitate:

```cmd
build\Release\Gestione-HID-FIDO2.exe --demo
```

La [guida di compilazione](docs/building.md) descrive diagnostica opzionale e
configurazione delle release firmate.

## Creazione del pacchetto

```cmd
start /wait "" build\Release\Gestione-HID-FIDO2.exe --package "%CD%\build\Release" "%CD%\out\releases" --result "%CD%\out\package.json"
```

Usa ogni volta un nome nuovo per il risultato. La creazione del pacchetto non
installa o registra componenti. La directory generata contiene:

```text
Gestione-HID-FIDO2.exe
bin/HidFido2CredentialProvider.dll
bin/hid-fido2-vault.exe
bin/provider-smoke.exe
release.json
```

Una release firmata aggiunge `release.p7s`. Conserva la directory completa:
payload mancanti, alterati o inattesi vengono rifiutati.

## Utilizzo

1. Apri `Gestione-HID-FIDO2.exe` da un pacchetto completo attendibile. Conferma
   UAC con lo stesso account Windows; le build locali non firmate richiedono
   il consenso esplicito al prototipo.
2. Registra una chiave principale e una di riserva nei dialoghi nativi.
   Inserisci password Windows e PIN della chiave soltanto in quelle finestre.
3. Installa il provider da **Installazione**, dopo aver verificato che
   l'accesso di recupero con password Windows funzioni.
4. Blocca Windows, scegli **Opzioni di accesso → HID FIDO2**, inserisci il PIN
   della chiavetta e toccala quando richiesto.

Il gestore installato è **Gestione HID FIDO2** in Start e sul Desktop. Dopo
aver cambiato la password Windows, aggiorna la copia cifrata in **Password e
recupero**. Consulta la [guida d'uso](docs/usage.md).

## Sicurezza e recupero

L'archivio usa AES-256-GCM e protegge la chiave dei dati separatamente con ogni
chiavetta. L'accesso è limitato a SYSTEM e Administrators. I PIN non sono
persistiti e i segreti decifrati vengono cancellati dopo l'uso.

Un login riuscito non dimostra da solo la protezione hardware dalle richieste
senza PIN. Una nuova registrazione richiede un rifiuto esplicito o un segreto
distinto nella prova indipendente; un esito inconcludente interrompe la procedura.

Il provider password di Windows resta disponibile. La rimozione del provider
conserva l'archivio. Le copie compatibili preservano revoche e contatori
correnti e non ripristinano vecchie generazioni della password. Non sostituiscono
un recupero completo del computer.

Prima dell'attivazione leggi [modello di sicurezza](SECURITY.md) e
[istruzioni di recupero](docs/recovery.md). Per distribuire il software servono
un certificato reale e una [procedura di firma](docs/signing.md) convalidata.

## Struttura del progetto

| Directory | Contenuto |
| --- | --- |
| `src/manager` | Gestore desktop, packaging e deployment nativi |
| `src/credential_provider` | Provider COM, serializzazione e diagnostica pubblica |
| `src/ctap` | CTAP2, PIN protocol, USB HID e prove di protezione |
| `src/vault`, `src/password` | Archivio macchina e cifratura autenticata |
| `src/ui`, `resources` | Dialoghi nativi, icona e risorse di versione |
| `include/hidfido` | Interfacce condivise |
| `tests` | Test automatici isolati |
| `docs` | Architettura, uso, build, firma e recupero attuali |

[Architettura](docs/architecture.md) · [Licenza MIT](LICENSE)
