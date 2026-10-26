# Medium article

An English article for Medium about building HID FIDO2 Windows Logon with
coding agents. Its message: a project of this complexity would not exist
without them, because the barrier was the knowledge each component required,
not the typing.

The story includes the native rewrite in version 0.6 and the bilingual
interface added in version 0.7. All four manager screenshots show version
0.7 in English with synthetic demo data and real operations disabled.

| Path | Content |
| --- | --- |
| [`article.md`](article.md) | Title, subtitle and text (about 2,600 words, 10 minutes) |
| `images/cover.png` | Cover; Medium uses the first image as the story preview |
| `images/knowledge-map.png` | The specifications and techniques the project required |
| `images/architecture.png` | Components and the setup and sign-in paths |
| `images/vault-keys.png` | Data key wrapped separately by the primary and backup keys |
| `images/unlock-sequence.png` | The 16 unlock steps, same order as [security-overview.md](../security-overview.md) |
| `images/screenshot-*.png` | Overview, Security keys, Password and recovery, Installation; all in English |
| `diagrams/` | SVG sources and the script that generates cover and diagrams |

The manager captures are copied from [`docs/images/en`](../images/en/).
The old Italian PIN-dialog image has been replaced by the English Password
and recovery page. Saved key labels such as `Principale` and `Riserva` are
sample data and are not translated when changing the interface language.

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

- the personal statements are yours: the two agents used (Claude Code and
  Codex), approval of privileged changes, the PIN and password never typed into a chat;
- the closing link points to the published repository and, if you add a direct
  link to `docs/security-overview.md`, that the page is on the default branch;
- figures still match the code: about 8,900 non-blank lines of C++ in `src` and
  `include` (including the `.inc` translation catalog), 3,900 in `tests`, and
  19 test suites registered in `CMakeLists.txt`. The rounded headline is 13,000.
- the unlock timing refers to an earlier development build; it is not a
  performance or end-to-end validation claim for version 0.7.

## Regenerating the images

```cmd
python docs\medium-article\diagrams\build_diagrams.py --png
```

The script uses only the Python standard library. It rewrites the SVGs and,
with `--png`, renders each one to `images/` at 2x with headless Microsoft Edge.
Medium does not accept SVG uploads. Screenshots are copied, not generated.
When refreshing them, copy all four English manager captures from
`docs/images/en/` to the matching `images/screenshot-manager-*.png` files.
