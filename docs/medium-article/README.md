# Medium article

An English article for Medium about building HID FIDO2 Windows Logon with
coding agents. Its message: a project of this complexity would not exist
without them, because the barrier was the knowledge each component required,
not the typing.

The story and copied manager screenshots describe version 0.6. Version 0.7
adds the bilingual interface; see the repository READMEs for the current UI.

| Path | Content |
| --- | --- |
| [`article.md`](article.md) | Title, subtitle and text (about 2,100 words, 8 minutes) |
| `images/cover.png` | Cover; Medium uses the first image as the story preview |
| `images/knowledge-map.png` | The specifications and techniques the project required |
| `images/architecture.png` | Components and the setup and sign-in paths |
| `images/vault-keys.png` | Data key wrapped separately by the primary and backup keys |
| `images/unlock-sequence.png` | The 16 unlock steps, same order as [security-overview.md](../security-overview.md) |
| `images/screenshot-*.png` | Native manager in demo mode (synthetic data) and the PIN dialog |
| `diagrams/` | SVG sources and the script that generates cover and diagrams |

The screenshots show the Italian interface. The manager captures come from
[`docs/images`](../images/README.md); the PIN dialog is the one shown by
`hid-fido2-vault.exe` during enrollment.

The diagrams distinguish the internal key secret from its encrypted derived
output. The protected password remains reusable: the provider consumes its
pending cache once, with a 15-second cache lifetime. It does not issue a
one-time Windows password. See the overview for counter and USB protection
limits.

## Publishing

1. In Medium, create a new story. Paste the `#` line as the title and the
   `##` line below it as the subtitle.
2. Open `article.md` in a rendered Markdown preview (VS Code or GitHub) and
   copy the text one section at a time. Medium keeps headings, bold, italics,
   lists, links and inline code; it does not render Markdown tables or Mermaid,
   and the article uses neither.
3. Medium does not import local images. At each image, upload the matching PNG
   from `images/`, type the italic line under it as the caption and copy the
   bracketed text of the Markdown image as alt text.
4. Use the wide ("outset") layout for `knowledge-map`, `architecture`,
   `vault-keys` and `unlock-sequence`, so their labels stay readable. The PNGs
   are rendered at twice their nominal size for high-density screens.
5. Suggested tags: Artificial Intelligence, Software Development,
   Cybersecurity, Windows, Programming.

Before publishing, check that:

- the personal statements are yours: Italian as your language, the two agents
  used (Claude Code and Codex), the PIN and password never typed into a chat;
- the closing link points to the published repository and, if you add a direct
  link to `docs/security-overview.md`, that the page is on the default branch;
- figures still match the code: about 8,500 non-blank lines of C++ in `src` and
  `include`, 3,900 in `tests`, 18 test suites registered in `CMakeLists.txt`.

## Regenerating the images

```cmd
python docs\medium-article\diagrams\build_diagrams.py --png
```

The script uses only the Python standard library. It rewrites the SVGs and,
with `--png`, renders each one to `images/` at 2x with headless Microsoft Edge.
Medium does not accept SVG uploads. Screenshots are copied, not generated.
