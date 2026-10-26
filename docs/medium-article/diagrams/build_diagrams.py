"""Builds the article's technical diagrams as SVG (light theme, for Medium).

    python docs/medium-article/diagrams/build_diagrams.py [--png]

--png also renders each SVG to ../images/<name>.png at 2x with headless
Microsoft Edge (Medium does not accept SVG uploads). Standard library only.
"""
import os
import re
import subprocess
import sys
import tempfile
from xml.sax.saxutils import escape

HERE = os.path.dirname(os.path.abspath(__file__))
IMAGES = os.path.join(os.path.dirname(HERE), 'images')
NAMES = ('cover', 'architecture', 'unlock-sequence', 'vault-keys', 'knowledge-map')
INK, MUTED, LINE, GRID = '#1f2328', '#57606a', '#8c959f', '#d0d7de'
ACCENT, ACCENT_FILL, BAND = '#2f6fb5', '#e8f0fa', '#f6f8fa'
FONT = "'Segoe UI', 'Helvetica Neue', Arial, sans-serif"


def text(x, y, value, size=15, weight=400, fill=INK, anchor='start', halo=False):
    # A white halo lets labels sit on top of lines without being struck through.
    outline = ' stroke="#ffffff" stroke-width="7" stroke-linejoin="round" paint-order="stroke"' if halo else ''
    return (f'<text x="{x}" y="{y}" font-size="{size}" font-weight="{weight}" fill="{fill}" '
            f'text-anchor="{anchor}"{outline}>{escape(value)}</text>')


def box(x, y, w, h, title, lines=(), accent=False, fill=None, size=17):
    stroke = ACCENT if accent else LINE
    background = fill or (ACCENT_FILL if accent else '#ffffff')
    out = [f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="10" fill="{background}" '
           f'stroke="{stroke}" stroke-width="{2 if accent else 1.4}"/>']
    # Title and detail lines centred vertically as one block.
    base = y + h / 2 - 12 * len(lines) + 6
    out.append(text(x + w / 2, base, title, size, 600, INK, 'middle'))
    for i, line in enumerate(lines):
        out.append(text(x + w / 2, base + 24 + 21 * i, line, 14.5, 400, MUTED, 'middle'))
    return ''.join(out)


def arrow(points, color=LINE, width=1.6, dashed=False, both=False, marker='a'):
    path = 'M' + ' L'.join(f'{x} {y}' for x, y in points)
    dash = ' stroke-dasharray="6 5"' if dashed else ''
    start = f' marker-start="url(#{marker})"' if both else ''
    return (f'<path d="{path}" fill="none" stroke="{color}" stroke-width="{width}"{dash}{start} '
            f'marker-end="url(#{marker})"/>')


def svg(width, height, body):
    defs = (f'<defs><marker id="a" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" '
            f'orient="auto-start-reverse"><path d="M0 0L10 5L0 10z" fill="{LINE}"/></marker>'
            f'<marker id="b" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" '
            f'orient="auto-start-reverse"><path d="M0 0L10 5L0 10z" fill="{ACCENT}"/></marker></defs>')
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" '
            f'font-family="{FONT}"><rect width="{width}" height="{height}" fill="#ffffff"/>{defs}{body}</svg>')


def write(name, content):
    with open(os.path.join(HERE, name), 'w', encoding='utf-8') as output:
        output.write(content)
    print('written', name)


# 1. Architecture --------------------------------------------------------------
def architecture():
    b = [text(40, 48, 'Two programs, one key, one vault: Windows still decides', 24, 600)]
    b.append(text(40, 80, 'Setup runs in the native manager; sign-in runs inside the Windows logon screen.', 16, 400, MUTED))
    b.append(box(40, 296, 140, 80, 'You'))
    b.append(box(240, 120, 280, 96, 'Native manager', ['enrollment · status · install']))
    b.append(box(600, 120, 520, 96, 'Vault helper', ['PIN and password dialogs · FIDO2 enrollment (elevated)']))
    b.append(box(600, 290, 245, 96, 'USB FIDO2 security key', ['PIN · touch · hmac-secret']))
    b.append(box(875, 290, 245, 96, 'Encrypted vault', ['AES-256-GCM', 'SYSTEM and Admins only']))
    b.append(box(600, 460, 520, 96, 'Credential Provider', ['DLL loaded by LogonUI · PIN field · unlock hand-off']))
    b.append(box(600, 640, 520, 96, 'Windows authentication', ['Negotiate / LSA · grants or refuses access'], accent=True))
    b.append(arrow([(110, 296), (110, 168), (240, 168)]))
    b.append(arrow([(110, 376), (110, 508), (600, 508)], ACCENT, 2, marker='b'))
    b.append(arrow([(520, 168), (600, 168)]))
    b.append(arrow([(722, 216), (722, 290)], both=True))
    b.append(arrow([(997, 216), (997, 290)], both=True))
    b.append(arrow([(722, 460), (722, 386)], ACCENT, 2, both=True, marker='b'))
    b.append(arrow([(997, 460), (997, 386)], ACCENT, 2, both=True, marker='b'))
    b.append(arrow([(860, 556), (860, 640)], ACCENT, 2, marker='b'))
    b.append(text(122, 240, 'manage', 14, 400, MUTED))
    b.append(text(122, 450, 'sign in', 14, 600, ACCENT))
    b.append(text(560, 158, 'runs', 14, 400, MUTED, 'middle'))
    b.append(text(874, 604, 'CredProtect-protected password', 14, 600, ACCENT))
    for i, line in enumerate(['Once, as administrator: enroll two', 'keys, store the password, install.']):
        b.append(text(240, 262 + 22 * i, line, 14.5, 400, MUTED))
    for i, line in enumerate(['Every sign-in: key PIN and a touch;', 'the Windows password is never typed.']):
        b.append(text(240, 544 + 22 * i, line, 14.5, 400, MUTED))
    b.append(f'<line x1="40" y1="776" x2="70" y2="776" stroke="{LINE}" stroke-width="1.6"/>')
    b.append(text(80, 781, 'setup and management', 14, 400, MUTED))
    b.append(f'<line x1="270" y1="776" x2="300" y2="776" stroke="{ACCENT}" stroke-width="2"/>')
    b.append(text(310, 781, 'sign-in and unlock', 14, 400, MUTED))
    write('architecture.svg', svg(1160, 806, ''.join(b)))


# 2. Unlock sequence -----------------------------------------------------------
def sequence():
    lanes = [('You', None), ('Sign-in screen', '(LogonUI)'), ('HID FIDO2', 'provider'),
             ('FIDO2', 'security key'), ('Encrypted', 'vault'), ('Windows', 'authentication')]
    xs = [110, 300, 500, 700, 900, 1090]
    top, step, first = 110, 52, 196
    rows = 16
    bottom = first + step * (rows - 1) + 40
    b = [text(40, 48, 'Sixteen steps from key verification to Windows authentication', 24, 600)]
    b.append(text(40, 80, 'Solid arrows are requests, dashed arrows are answers. Timing varies with the device and touch.', 16, 400, MUTED))
    for x, (name, sub) in zip(xs, lanes):
        b.append(f'<line x1="{x}" y1="{top + 56}" x2="{x}" y2="{bottom}" stroke="{GRID}" stroke-width="1.4" stroke-dasharray="5 5"/>')
        b.append(f'<rect x="{x - 80}" y="{top}" width="160" height="56" rx="10" fill="#ffffff" stroke="{LINE}" stroke-width="1.4"/>')
        if sub:
            b.append(text(x, top + 24, name, 16, 600, INK, 'middle'))
            b.append(text(x, top + 44, sub, 14, 400, MUTED, 'middle'))
        else:
            b.append(text(x, top + 34, name, 16, 600, INK, 'middle'))
    You, Screen, Prov, Key, Vault, Win = xs
    # (from, to, label, answer, highlight) ; from == to draws a note box on that lane
    steps = [
        (You, Screen, '1  Enter key PIN, Sign in', False, False),
        (Screen, Prov, '2  Ask for a credential', False, False),
        (Prov, Prov, '3  Local checks first', False, False),
        (Prov, Key, '4  Fresh ECDH shared secret', False, False),
        (Prov, Key, '5  Encrypted PIN hash', False, False),
        (Key, Prov, '6  Encrypted PIN token', True, False),
        (Prov, Key, '7  Challenge + encrypted salt', False, False),
        (You, Key, '8  Touch the key', False, True),
        (Key, Prov, '9  Signed answer + encrypted output', True, False),
        (Prov, Prov, '10  Verify signature, PIN, touch, counter', False, False),
        (Prov, Vault, '11  Derived output unwraps data key', False, False),
        (Prov, Vault, '12  Persist verified counter', False, False),
        (Vault, Prov, '13  Password, memory only', True, False),
        (Prov, Screen, '14  Protected password serialization', True, False),
        (Screen, Win, '15  Standard password check', False, False),
        (Win, Screen, '16  Access granted or refused', True, True),
    ]
    for i, (a, c, label, answer, hot) in enumerate(steps):
        y = first + step * i
        color, width, marker = (ACCENT, 2.2, 'b') if hot else (LINE, 1.6, 'a')
        if a == c:
            w = 330 if len(label) > 26 else 220
            b.append(f'<rect x="{a - w / 2}" y="{y - 18}" width="{w}" height="34" rx="8" fill="{BAND}" stroke="{LINE}" stroke-width="1.2"/>')
            b.append(text(a, y + 5, label, 15, 400, INK, 'middle'))
            continue
        direction = 1 if c > a else -1
        b.append(arrow([(a + 4 * direction, y + 6), (c - 4 * direction, y + 6)], color, width, answer, marker=marker))
        # Label centred above the arrow; its halo interrupts any lifeline underneath.
        span_mid = (a + c) / 2
        if hot and a == You:
            span_mid = (Screen + Prov) / 2
        b.append(text(span_mid, y - 2, label, 15, 600 if hot else 400, INK if (hot or not answer) else MUTED,
                      'middle', halo=True))
    write('unlock-sequence.svg', svg(1200, bottom + 30, ''.join(b)))


# 3. Vault key wrapping -------------------------------------------------------
def vault():
    b = [text(40, 48, 'Either key opens the vault; neither key ever sees the password', 24, 600)]
    b.append(text(40, 80, 'One random data key encrypts the password; each security key wraps that same data key.', 16, 400, MUTED))
    b.append(f'<rect x="385" y="105" width="815" height="330" rx="14" fill="{BAND}" stroke="{LINE}" stroke-width="1.2" stroke-dasharray="7 6"/>')
    b.append(text(405, 134, 'Machine vault (vault.bin) - SYSTEM and Administrators only', 15, 600, MUTED))
    b.append(box(40, 150, 260, 100, 'Primary security key', ['internal root stays inside', 'returns derived output']))
    b.append(box(40, 300, 260, 100, 'Backup security key', ['internal root stays inside', 'returns derived output']))
    b.append(box(415, 160, 240, 80, 'Wrapped data key #1', ['HKDF + AES-256-GCM']))
    b.append(box(415, 310, 240, 80, 'Wrapped data key #2', ['HKDF + AES-256-GCM']))
    b.append(box(720, 230, 200, 90, 'Data key', ['256-bit, random'], accent=True))
    b.append(box(970, 215, 210, 120, 'Windows password', ['AES-256-GCM', 'bound to account', 'and record']))
    b.append(arrow([(300, 200), (415, 200)]))
    b.append(arrow([(300, 350), (415, 350)]))
    b.append(arrow([(655, 200), (690, 200), (690, 260), (720, 260)], ACCENT, 2, marker='b'))
    b.append(arrow([(655, 350), (690, 350), (690, 290), (720, 290)], ACCENT, 2, marker='b'))
    b.append(arrow([(920, 275), (970, 275)], ACCENT, 2, marker='b'))
    b.append(text(342, 190, 'unwraps', 14, 400, MUTED, 'middle'))
    b.append(text(342, 340, 'unwraps', 14, 400, MUTED, 'middle'))
    b.append(text(945, 262, 'opens', 14, 600, ACCENT, 'middle'))
    b.append(text(40, 472, 'A password change re-encrypts only the password: both key wrappers stay valid,', 16, 400, INK))
    b.append(text(40, 498, 'so updating it needs just one of the two keys.', 16, 400, INK))
    write('vault-keys.svg', svg(1230, 520, ''.join(b)))


# 4. Knowledge map ------------------------------------------------------------
def knowledge():
    bands = [
        ('USB and FIDO2', ['CTAPHID framing and channels', 'CTAP 2.0 commands', 'canonical CBOR', 'PIN protocol 1',
                           'hmac-secret extension', 'COSE keys', 'ES256 and DER signatures', 'WebAuthn client data',
                           'authenticator quirks']),
        ('Cryptography and storage', ['ECDH P-256', 'AES-256-GCM', 'AES-CBC and HMAC-SHA256', 'HKDF-SHA256',
                                      'per-key key wrapping', 'Windows CNG', 'ACLs and SDDL', 'atomic writes and locks',
                                      'secure memory wiping']),
        ('Windows sign-in internals', ['Credential Provider V2 (COM)', 'LogonUI lifecycle', 'CredentialsChanged and auto-logon',
                                       'KERB_INTERACTIVE_UNLOCK_LOGON', 'Negotiate / LSA results', 'CredProtectW',
                                       'UAC and SID continuity', 'ETW TraceLogging']),
        ('Shipping it', ['Win32 UI and per-monitor DPI', 'manifests and visual styles', 'icons and version resources',
                         'package hashing and pinning', 'Authenticode and CMS signing', 'install, update, rollback',
                         '19 automated test suites', 'recovery documentation']),
    ]
    width, label_w, x0 = 1240, 230, 40
    y = 110
    b = [text(40, 48, 'What a "simple" key-based sign-in actually required', 24, 600)]
    b.append(text(40, 80, 'Each chip is a specification, API or technique the project had to get exactly right.', 16, 400, MUTED))
    for name, chips in bands:
        cx, cy, rows = x0 + label_w, y + 22, 1
        positions = []
        for chip in chips:
            w = int(len(chip) * 7.9) + 30
            if cx + w > width - 40:
                cx, cy, rows = x0 + label_w, cy + 46, rows + 1
            positions.append((cx, cy, w, chip))
            cx += w + 12
        h = 22 + rows * 46 + 6
        b.append(f'<rect x="{x0}" y="{y}" width="{width - 2 * x0}" height="{h}" rx="12" fill="{BAND}" stroke="{GRID}" stroke-width="1.2"/>')
        b.append(text(x0 + 20, y + h / 2 + 6, name, 16, 600, INK))
        for cx, cy, w, chip in positions:
            b.append(f'<rect x="{cx}" y="{cy}" width="{w}" height="34" rx="17" fill="#ffffff" stroke="{ACCENT}" stroke-width="1.3"/>')
            b.append(text(cx + w / 2, cy + 22, chip, 14, 400, INK, 'middle'))
        y += h + 18
    write('knowledge-map.svg', svg(width, y + 10, ''.join(b)))


# 0. Cover --------------------------------------------------------------------
def cover():
    # Same key glyph as the application icon, drawn as vectors.
    ox, oy, s = 120, 234, 320
    b = [f'<defs><linearGradient id="g" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#3a7cc4"/>'
         f'<stop offset="1" stop-color="#1f4f8a"/></linearGradient></defs>',
         f'<rect x="0" y="0" width="1400" height="788" fill="{BAND}"/>',
         f'<rect x="{ox}" y="{oy}" width="{s}" height="{s}" rx="64" fill="url(#g)"/>',
         f'<circle cx="{ox + 100}" cy="{oy + 160}" r="46" fill="none" stroke="#ffffff" stroke-width="34"/>',
         f'<rect x="{ox + 140}" y="{oy + 143}" width="140" height="34" fill="#ffffff"/>',
         f'<rect x="{ox + 236}" y="{oy + 177}" width="20" height="38" fill="#ffffff"/>',
         f'<rect x="{ox + 262}" y="{oy + 177}" width="18" height="26" fill="#ffffff"/>']
    b.append(text(540, 282, 'A STORY ABOUT CODING AGENTS', 22, 600, ACCENT))
    b.append(text(540, 356, 'One key, one PIN, one touch,', 50, 700))
    b.append(text(540, 420, 'and 13,000 lines of C++', 50, 700))
    b.append(text(540, 486, 'FIDO2 sign-in for Windows that I could never', 25, 400, MUTED))
    b.append(text(540, 520, 'have built on my own.', 25, 400, MUTED))
    return svg(1400, 788, ''.join(b))


def render_png():
    roots = [os.environ.get('ProgramFiles(x86)', ''), os.environ.get('ProgramFiles', '')]
    edge = next((p for p in (os.path.join(r, 'Microsoft', 'Edge', 'Application', 'msedge.exe') for r in roots)
                 if os.path.isfile(p)), None)
    if not edge:
        sys.exit('Microsoft Edge not found: open each SVG in a browser and export it instead.')
    os.makedirs(IMAGES, exist_ok=True)
    with tempfile.TemporaryDirectory() as profile:
        for name in NAMES:
            source = os.path.join(HERE, name + '.svg')
            with open(source, encoding='utf-8') as handle:
                width, height = re.search(r'width="(\d+)" height="(\d+)"', handle.read()).groups()
            target = os.path.join(IMAGES, name + '.png')
            subprocess.run([edge, '--headless', '--disable-gpu', '--hide-scrollbars', f'--user-data-dir={profile}',
                            '--force-device-scale-factor=2', f'--window-size={width},{height}',
                            f'--screenshot={target}', 'file:///' + source.replace('\\', '/')],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print('rendered', os.path.relpath(target, os.path.dirname(HERE)))


if __name__ == '__main__':
    write('cover.svg', cover())
    architecture()
    sequence()
    vault()
    knowledge()
    if '--png' in sys.argv[1:]:
        render_png()
