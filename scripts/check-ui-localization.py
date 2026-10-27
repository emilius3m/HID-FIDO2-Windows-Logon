"""Check built-in UI translations without building or changing the app."""
from pathlib import Path
import json
import re

ROOT = Path(__file__).resolve().parents[1]
LITERAL = r'(?<![A-Za-z0-9_])L"(?:\\.|[^"\\])*"'
GROUP = LITERAL + r'(?:\s*' + LITERAL + r')*'


def decode(value):
    return ''.join(json.loads(part[1:]) for part in re.findall(LITERAL, value))


def main():
    catalog = {}
    for line in (ROOT / 'include/hidfido/strings.inc').read_text(encoding='utf-8').splitlines():
        if not line.startswith('HIDFIDO_STRING('):
            continue
        values = [decode(value) for value in re.findall(LITERAL, line)]
        assert len(values) == 3 and all(values), 'Malformed or empty catalog entry'
        key, italian, english = values
        assert key not in catalog, f'Duplicate UI key: {key}'
        catalog[key] = italian, english
    neutral = {'', 'HID FIDO2', 'HID FIDO2 · 0.9.0'}
    sources = [ROOT / name for name in (
        'src/manager/main.cpp', 'src/manager/window.cpp', 'src/manager/experience.cpp',
        'src/ui/guided_ceremony.cpp', 'include/hidfido/guidance_view.hpp',
        'src/ui/secret_dialog.cpp', 'src/ui/user_messages.cpp',
        'src/vault/vault_tool.cpp', 'src/credential_provider/provider.cpp',
        'src/credential_provider/serialization.cpp')]
    checked = 0
    for source in sources:
        text = source.read_text(encoding='utf-8')
        for match in re.finditer(r'\btr\(\s*(' + GROUP + r')\s*\)', text):
            key = decode(match.group(1))
            assert key in catalog or key in neutral, f'{source.name}: untranslated lookup {key}'
            checked += 1
        # These two blocks retain source keys for translation at display time.
        if source.name == 'window.cpp':
            block = text[text.index('    void create() {'):text.index('    void layout() {')]
            neutral_here = neutral | {'BUTTON', 'Italiano', 'English'}
            block += text[text.index('    void setup_state() {'):text.index('    void setup_action() {')]
            block += text[text.index('const wchar_t* titles[]'):text.index('SetWindowTextW(heading_', text.index('const wchar_t* titles[]'))]
        elif source.name == 'experience.cpp':
            block = text[text.index('HomePresentation home_presentation'):text.index('std::string setup_trials_binding')]
            neutral_here = neutral
        elif source.name == 'guidance_view.hpp':
            block = text[text.index('inline GuideCopy guide_copy'):text.index('inline bool guide_input')]
            neutral_here = neutral
        elif source.name == 'provider.cpp':
            block = text[text.index('constexpr wchar_t ready_text'):text.index('// Key glyph')]
            neutral_here = neutral
        else:
            continue
        for literal in re.findall(GROUP, block):
            key = decode(literal)
            assert key in catalog or key in neutral_here, f'{source.name}: untranslated control {key}'
    print(f'{len(catalog)} bilingual entries and {checked} UI lookups checked; all manager and sign-in labels covered.')


if __name__ == '__main__':
    main()
