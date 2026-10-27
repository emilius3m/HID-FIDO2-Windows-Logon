# Version 0.8.0 — development package

The native manager adds guided setup, key renaming and local support reports.
The interface and dialogs remain available in Italian and English.

- Guided setup resumes from observed account/key/provider state. It requires
  two stored hardware protection proofs before its activation step. Recovery
  and real Windows trial confirmations remain manual, session-local guidance.
- Key renaming changes only display metadata, under the vault lock with
  current-authority checks. It does not decrypt the password, reset a counter,
  change a proof or require re-enrollment. No vault schema migration is needed.
- Support collection is explicit, limited to five minutes and 2,048 in-memory
  sign-in events, with fixed numeric fields only. The report previews selected
  status and audit results before a local JSON save. It excludes credentials
  and account/key identifiers and never uploads automatically.

Vault schema remains **2**, with the same four runtime payloads. The
credential collection, CTAP2 PIN and encryption design is unchanged.

## Validation

The twenty automated suites pass, including metadata-only rename/crypto
continuity, in-flight counter preservation, guided setup prerequisites and
report field/size/privacy boundaries. Synthetic ETW capture verifies the
actual Windows controller, TDH decoding, stop/restart and rejection of raw
string fields without authenticating a user. A separate five-minute live
test confirms automatic session shutdown without a UI message loop.
Native demo screens and the
report preview are checked separately in both languages.

Real key enrollment, LogonUI unlock, restart sign-in and recovery still
require a separate device-specific trial of this version. This development
package remains unsigned and experimental; a test result is not certification
or an independent security audit.
