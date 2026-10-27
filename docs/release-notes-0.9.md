# Version 0.9.0 — experimental preview

The native interface now has three tabs: **Sign-in**, **Security keys** and
**Settings**, in Italian and English.

- Sign-in shows the current state and one next action. Windows instructions
  expand on demand; recovery remains easy to find.
- Security keys uses a compact list and a per-key menu for local testing,
  renaming, details and removal. Missing hardware checks remain visible.
- Settings groups password recovery, installation, support and language.
  Reports start with a short summary; technical JSON is expandable.
- Setup and key operations show one action at a time, with illustrations
  for connecting, touching, releasing, unplugging and reconnecting. Hardware
  events advance waiting steps. Releasing the sensor is acknowledged by the
  user because the program cannot detect that gesture.
- PIN/password input stays inside the local vault helper. The manager does
  not receive those buffers. Cancellation is available during input, USB
  waiting and CTAP requests; it does not roll back completed writes or remove
  credentials already created on an authenticator.
- Manual Windows-trial confirmations survive a manager restart, bound to
  the public configuration state. They never create hardware proof or bypass
  enrollment/deployment prerequisites. Recovery acknowledgement is requested
  again on each opening.

Vault schema remains **2**. The package still contains the same four runtime
payloads; illustrations and translations are embedded. Existing key data and
password recovery use the existing storage and authentication design.

## Validation and limits

The final x64 build passes **22 automated suites**. The two added suites
cover status honesty, isolated preference persistence and a hidden native
guided window with synthetic input, field clearing and cancellation. The
source check covers **472 bilingual entries** and **285 UI lookups**.

Native demo screenshots cover Italian/English screens, physical guidance
and the minimum window size. These use synthetic data and disabled actions;
they are not hardware or sign-in evidence. Real enrollment, unlock, sign-in
after restart and recovery require a separate trial on the target computer.

The published package remains unsigned and experimental. It is not a certified
release or an independent security audit. Installation requires explicit
consent and preserves the existing Windows password recovery option.
