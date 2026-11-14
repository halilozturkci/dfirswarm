#!/usr/bin/env python3
"""A QR symbol with a known payload, as a PNG, with no library: the known-answer input of the qr-decode capability
probe (swarm.sh tool-supply --provides qr-decode) and of the QR tests.

Version 1 to 4, error correction L, byte mode, mask 0 by default. Only what a probe needs: the payload is at most 78
bytes. The symbol follows ISO/IEC 18004: finder, separator, timing and alignment patterns, the dark module, the format
bits (BCH 15,5) and the codewords in the zigzag order, one Reed-Solomon block (versions 1 to 4 at level L have one).

  qrgen.py <payload> <out.png> [--scale N] [--mask 0..7]
  qrgen.py --matrix <payload>        the modules as lines of 0 and 1 (no quiet zone)
"""
import struct
import sys
import zlib

# version: (data codewords, error-correction codewords, alignment centre or None)
VERSIONS = {1: (19, 7, None), 2: (34, 10, 18), 3: (55, 15, 22), 4: (80, 20, 26)}

EXP = [0] * 512
LOG = [0] * 256
_x = 1
for _i in range(255):
    EXP[_i] = _x
    LOG[_x] = _i
    _x <<= 1
    if _x & 0x100:
        _x ^= 0x11D
for _i in range(255, 512):
    EXP[_i] = EXP[_i - 255]


def gf_mul(a, b):
    return 0 if a == 0 or b == 0 else EXP[LOG[a] + LOG[b]]


def rs_remainder(data, degree):
    gen = [1]
    for i in range(degree):
        nxt = [0] * (len(gen) + 1)
        for j, g in enumerate(gen):
            nxt[j] ^= g
            nxt[j + 1] ^= gf_mul(g, EXP[i])
        gen = nxt
    rem = [0] * degree
    for byte in data:
        factor = byte ^ rem[0]
        rem = rem[1:] + [0]
        for j in range(degree):
            rem[j] ^= gf_mul(gen[j + 1], factor)
    return rem


def syndromes(codewords, degree):
    """The Reed-Solomon syndromes of a whole block: all zero for a block that is right."""
    out = []
    for i in range(degree):
        s = 0
        for c in codewords:
            s = gf_mul(s, EXP[i]) ^ c
        out.append(s)
    return out


def format_bits(mask):
    data = (1 << 3) | mask                      # level L is 01
    rem = data
    for _ in range(10):
        rem = (rem << 1) ^ ((rem >> 9) * 0x537)
    return ((data << 10) | rem) ^ 0x5412


MASKS = [
    lambda x, y: (x + y) % 2 == 0, lambda x, y: y % 2 == 0, lambda x, y: x % 3 == 0, lambda x, y: (x + y) % 3 == 0,
    lambda x, y: (x // 3 + y // 2) % 2 == 0, lambda x, y: x * y % 2 + x * y % 3 == 0,
    lambda x, y: (x * y % 2 + x * y % 3) % 2 == 0, lambda x, y: ((x + y) % 2 + x * y % 3) % 2 == 0,
]


def codewords_for(payload, version):
    data_n, ec_n, _ = VERSIONS[version]
    bits = [0, 1, 0, 0] + [(len(payload) >> i) & 1 for i in range(7, -1, -1)]
    for b in payload:
        bits += [(b >> i) & 1 for i in range(7, -1, -1)]
    bits += [0] * min(4, data_n * 8 - len(bits))
    bits += [0] * (-len(bits) % 8)
    data = [int("".join(map(str, bits[i:i + 8])), 2) for i in range(0, len(bits), 8)]
    pad = 0xEC
    while len(data) < data_n:
        data.append(pad)
        pad ^= 0xEC ^ 0x11
    return data + rs_remainder(data, ec_n)


def matrix(payload, mask=0):
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    version = next((v for v in sorted(VERSIONS) if len(payload) + 2 <= VERSIONS[v][0]), None)
    if version is None:
        raise ValueError("the payload is longer than this generator's 78 bytes")
    size = 17 + 4 * version
    mod = [[0] * size for _ in range(size)]
    func = [[False] * size for _ in range(size)]

    def put(x, y, dark):
        mod[y][x] = 1 if dark else 0
        func[y][x] = True

    for i in range(size):                          # timing
        put(6, i, i % 2 == 0)
        put(i, 6, i % 2 == 0)
    for cx, cy in ((3, 3), (size - 4, 3), (3, size - 4)):   # finders with their separators
        for dy in range(-4, 5):
            for dx in range(-4, 5):
                x, y = cx + dx, cy + dy
                if 0 <= x < size and 0 <= y < size:
                    d = max(abs(dx), abs(dy))
                    put(x, y, d not in (2, 4))
    centre = VERSIONS[version][2]
    if centre is not None:                         # one alignment pattern
        for dy in range(-2, 3):
            for dx in range(-2, 3):
                put(centre + dx, centre + dy, max(abs(dx), abs(dy)) != 1)
    fmt = format_bits(mask)
    bit = lambda i: (fmt >> i) & 1
    for i in range(6):
        put(8, i, bit(i))
    put(8, 7, bit(6))
    put(8, 8, bit(7))
    put(7, 8, bit(8))
    for i in range(9, 15):
        put(14 - i, 8, bit(i))
    for i in range(8):
        put(size - 1 - i, 8, bit(i))
    for i in range(8, 15):
        put(8, size - 15 + i, bit(i))
    put(8, size - 8, True)                         # the dark module
    cw = codewords_for(payload, version)
    i = 0
    right = size - 1
    while right >= 1:
        if right == 6:
            right = 5
        for vert in range(size):
            for j in range(2):
                x = right - j
                upward = ((right + 1) & 2) == 0
                y = size - 1 - vert if upward else vert
                if not func[y][x] and i < len(cw) * 8:
                    mod[y][x] = (cw[i >> 3] >> (7 - (i & 7))) & 1
                    i += 1
        right -= 2
    assert i == len(cw) * 8, "every codeword bit was placed"
    for y in range(size):
        for x in range(size):
            if not func[y][x] and MASKS[mask](x, y):
                mod[y][x] ^= 1
    return mod


def png(mod, scale=8, quiet=4):
    size = (len(mod) + 2 * quiet) * scale
    rows = []
    for py in range(size):
        y = py // scale - quiet
        row = bytearray([0])
        for px in range(size):
            x = px // scale - quiet
            dark = 0 <= y < len(mod) and 0 <= x < len(mod) and mod[y][x]
            row.append(0 if dark else 255)
        rows.append(bytes(row))
    def chunk(tag, body):
        return struct.pack(">I", len(body)) + tag + body + struct.pack(">I", zlib.crc32(tag + body) & 0xFFFFFFFF)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 0, 0, 0, 0)) + chunk(b"IDAT", zlib.compress(b"".join(rows), 9)) + chunk(b"IEND", b"")


def main(argv):
    if len(argv) >= 2 and argv[0] == "--matrix":
        for row in matrix(argv[1]):
            print("".join(map(str, row)))
        return 0
    if len(argv) < 2:
        sys.stderr.write(__doc__)
        return 2
    scale = int(argv[argv.index("--scale") + 1]) if "--scale" in argv else 8
    mask = int(argv[argv.index("--mask") + 1]) if "--mask" in argv else 0
    with open(argv[1], "wb") as fh:
        fh.write(png(matrix(argv[0], mask), scale))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
