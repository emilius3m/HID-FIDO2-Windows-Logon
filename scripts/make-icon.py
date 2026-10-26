"""Generates resources/hid-fido2.ico (and an optional preview PNG).

The key glyph geometry below is mirrored by `key_coverage` in
src/credential_provider/provider.cpp, which draws the LogonUI tile logo at
run time. Keep both in sync. Standard library only; not part of the build:

    python scripts/make-icon.py [--preview out\\icon-preview.png]
"""
import argparse
import os
import struct
import zlib

SIZES = (16, 20, 24, 32, 40, 48, 64, 256)
SAMPLES = 6  # supersampling per axis for anti-aliasing


def inside_key(u, v, bold=False):
    """Key glyph in a unit square: ring head, shaft and two teeth.

    The bold variant thickens every stroke for 16-24 px icons."""
    dx, dy = u - 0.32, v - 0.50
    d2 = dx * dx + dy * dy
    if bold:
        return ((0.095 ** 2 <= d2 <= 0.235 ** 2) or
                (0.50 <= u <= 0.90 and 0.44 <= v <= 0.56) or
                (0.66 <= u <= 0.76 and 0.56 <= v <= 0.70) or
                (0.81 <= u <= 0.90 and 0.56 <= v <= 0.66))
    if 0.09 ** 2 <= d2 <= 0.215 ** 2:
        return True
    if 0.50 <= u <= 0.87 and 0.452 <= v <= 0.548:
        return True
    if 0.69 <= u <= 0.755 and 0.548 <= v <= 0.665:
        return True
    return 0.80 <= u <= 0.87 and 0.548 <= v <= 0.625


def inside_rounded_square(u, v, inset=0.03, radius=0.2):
    lo, hi = inset, 1.0 - inset
    if not (lo <= u <= hi and lo <= v <= hi):
        return False
    cx = min(max(u, lo + radius), hi - radius)
    cy = min(max(v, lo + radius), hi - radius)
    return (u - cx) ** 2 + (v - cy) ** 2 <= radius ** 2


def lerp(a, b, t):
    return tuple(round(x + (y - x) * t) for x, y in zip(a, b))


def render_icon(size):
    """RGBA: white key on a blue rounded square with a vertical gradient."""
    top, bottom = (0x2F, 0x6F, 0xB5), (0x1B, 0x48, 0x78)
    # Small icons: no margin, larger and bolder glyph so it stays legible.
    small = size <= 24
    inset, radius, scale = (0.0, 0.18, 0.98) if small else (0.03, 0.2, 0.85)
    pixels = bytearray()
    for y in range(size):
        background = lerp(top, bottom, y / max(size - 1, 1))
        for x in range(size):
            square = glyph = 0
            for sy in range(SAMPLES):
                for sx in range(SAMPLES):
                    u = (x + (sx + 0.5) / SAMPLES) / size
                    v = (y + (sy + 0.5) / SAMPLES) / size
                    if inside_rounded_square(u, v, inset, radius):
                        square += 1
                        if inside_key(0.5 + (u - 0.5) / scale, 0.5 + (v - 0.5) / scale, small):
                            glyph += 1
            total = SAMPLES * SAMPLES
            alpha = square / total
            mix = glyph / square if square else 0.0
            color = lerp(background, (0xFF, 0xFF, 0xFF), mix)
            pixels += bytes(color) + bytes([round(alpha * 255)])
    return bytes(pixels)


def png(size, rgba):
    def chunk(kind, data):
        return struct.pack('>I', len(data)) + kind + data + struct.pack('>I', zlib.crc32(kind + data) & 0xFFFFFFFF)
    stride = size * 4
    raw = b''.join(b'\x00' + rgba[y * stride:(y + 1) * stride] for y in range(size))
    return (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', size, size, 8, 6, 0, 0, 0)) +
            chunk(b'IDAT', zlib.compress(raw, 9)) + chunk(b'IEND', b''))


def ico(images):
    header = struct.pack('<HHH', 0, 1, len(images))
    offset = 6 + 16 * len(images)
    entries, data = b'', b''
    for size, blob in images:
        dim = 0 if size >= 256 else size
        entries += struct.pack('<BBBBHHII', dim, dim, 0, 0, 1, 32, len(blob), offset + len(data))
        data += blob
    return header + entries + data


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--preview', help='also write a 256 px PNG preview to this path')
    args = parser.parse_args()
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    images = [(size, png(size, render_icon(size))) for size in SIZES]
    target = os.path.join(root, 'resources', 'hid-fido2.ico')
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, 'wb') as output:
        output.write(ico(images))
    print('written', target, 'sizes', ', '.join(map(str, SIZES)))
    if args.preview:
        with open(args.preview, 'wb') as output:
            output.write(images[-1][1])
        print('preview', args.preview)


if __name__ == '__main__':
    main()
