/**
 * computer-forensics-base: qr_read, the QR symbol reader with no dependency beyond the standard library.
 *
 * The symbols are made by scripts/lib/qrgen.py, a generator that shares no line with the tool (versions 1 to 4, level L, byte mode), and
 * the numeric and alphanumeric streams are built here from the standard's bit layout and placed by that generator. The fixtures of the
 * capability: a clean symbol, the same symbol with a finder pattern erased (and one overdrawn), four pieces of one symbol each on a canvas
 * of its own with its own margins, and a picture that holds no symbol. They give three payloads and one "not a symbol", each row saying
 * where the payload was written and never the payload. The call is made as a job makes it: the working directory is the run's root and
 * the pictures are named by relative paths with spaces.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { lstat, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { PYTHON3 } from "./host-gates.ts";
import { call, CFB, greyPng, py, ROOT, withRun, type Doc } from "./pack-base-media-fixture.ts";

const QRGEN = join(ROOT, "scripts", "lib");
const PAYLOAD = "fixture payload 0042 / not from any case";

/** The fixture pictures, drawn by the independent generator: clean, a finder erased, a finder overdrawn, four pieces with margins. */
const BUILD = String.raw`
import sys, struct, zlib, random
sys.path.insert(0, sys.argv[1])
import qrgen
out, payload = sys.argv[2], sys.argv[3]
mod = qrgen.matrix(payload, 3)
n = len(mod)
def png(rows):
    w = len(rows[0])
    raw = b"".join(b"\x00" + bytes(r) for r in rows)
    ch = lambda k, b: struct.pack(">I", len(b)) + k + b + struct.pack(">I", zlib.crc32(k + b) & 0xFFFFFFFF)
    return b"\x89PNG\r\n\x1a\n" + ch(b"IHDR", struct.pack(">IIBBBBB", w, len(rows), 8, 0, 0, 0, 0)) + ch(b"IDAT", zlib.compress(raw)) + ch(b"IEND", b"")
def draw(grid, scale, left, top, right, bottom):
    w, h = left + len(grid[0]) * scale + right, top + len(grid) * scale + bottom
    rows = [bytearray(b"\xff" * w) for _ in range(h)]
    for r, line in enumerate(grid):
        for c, m in enumerate(line):
            if m:
                for y in range(scale):
                    rows[top + r * scale + y][left + c * scale:left + (c + 1) * scale] = b"\x00" * scale
    return rows
open(out + "/clean symbol.png", "wb").write(qrgen.png(mod, 6, 4))
for name, fill in (("finder erased.png", 255), ("finder overdrawn.png", 0)):
    rows = draw(mod, 6, 24, 24, 24, 24)
    for y in range(24 - 3, 24 + 8 * 6):
        for x in range(24 - 3, 24 + 8 * 6):
            rows[y][x] = fill
    open(out + "/" + name, "wb").write(png(rows))
half = n // 2 + 1
parts = [[r[:half] for r in mod[:half]], [r[half:] for r in mod[:half]], [r[:half] for r in mod[half:]], [r[half:] for r in mod[half:]]]
margins = [(9, 31, 14, 5), (40, 7, 3, 22), (5, 5, 37, 11), (23, 18, 8, 29)]
for k, (part, m) in enumerate(zip(parts, margins)):
    open(out + "/piece %d of four.png" % (k + 1), "wb").write(png(draw(part, 5, *m)))
print(len(mod))
`;

/** A symbol whose data stream is given as bits (a numeric and an alphanumeric segment, from the standard's layout), placed by qrgen. */
const BUILD_MODES = String.raw`
import sys
sys.path.insert(0, sys.argv[1])
import qrgen
ALNUM = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
def bits_of(value, width):
    return [(value >> i) & 1 for i in range(width - 1, -1, -1)]
digits, text = sys.argv[3], sys.argv[4]
bits = [0, 0, 0, 1] + bits_of(len(digits), 10)
for i in range(0, len(digits), 3):
    group = digits[i:i + 3]
    bits += bits_of(int(group), {3: 10, 2: 7, 1: 4}[len(group)])
bits += [0, 0, 1, 0] + bits_of(len(text), 9)
for i in range(0, len(text) - 1, 2):
    bits += bits_of(ALNUM.index(text[i]) * 45 + ALNUM.index(text[i + 1]), 11)
if len(text) % 2:
    bits += bits_of(ALNUM.index(text[-1]), 6)
def codewords_for(_payload, version):
    data_n, ec_n, _ = qrgen.VERSIONS[version]
    b = bits + [0] * min(4, data_n * 8 - len(bits))
    b += [0] * (-len(b) % 8)
    data = [int("".join(map(str, b[i:i + 8])), 2) for i in range(0, len(b), 8)]
    pad = 0xEC
    while len(data) < data_n:
        data.append(pad)
        pad ^= 0xEC ^ 0x11
    return data + qrgen.rs_remainder(data, ec_n)
qrgen.codewords_for = codewords_for
mod = qrgen.matrix(b"x" * 30, 5)          # 30 bytes: version 2, whose 34 data codewords hold the two segments
open(sys.argv[2], "wb").write(qrgen.png(mod, 4, 4))
`;

const rowOf = (doc: Doc, input: string): Doc => (doc.rows as Doc[]).find((r) => r.input === input)!;

test("a clean symbol, one with a finder erased, four shifted pieces of one symbol and a picture with none give three payloads and one \"not a symbol\"", async () => {
  await withRun(async (run, out) => {
    const dir = "inputs/case files";
    py(BUILD, [QRGEN, join(run, dir), PAYLOAD], run);
    // The picture with no symbol: stripes and a filled square, drawn here.
    await writeFile(join(run, dir, "no symbol.png"), greyPng(Array.from({ length: 120 }, (_, y) => Array.from({ length: 160 }, (_, x) => (y > 30 && y < 80 && x > 40 && x < 90 ? 0 : (x >> 3) % 2 ? 255 : 200)))));

    const single = await call("qr_read", run, { images: [`${dir}/clean symbol.png`, `${dir}/finder erased.png`, `${dir}/no symbol.png`] }, { out });
    assert.equal(single.code, 0, single.stdout + single.stderr);
    assert.equal(single.stderr, "");
    const a = single.doc;
    assert.equal(a.status, "complete", a.status_basis);
    assert.deepEqual(a.counts, { inputs: 3, decoded: 2, not_a_symbol: 1, not_read: 0, not_finished: 0 });
    assert.ok(a.control.passed && a.control.checks.length >= 3, "the planted control was read before the pictures");

    const clean = rowOf(a, `${dir}/clean symbol.png`);
    assert.deepEqual([clean.result, clean.version, clean.level, clean.mask, clean.errors_corrected, clean.payload_bytes], ["decoded", 3, "L", 3, 0, PAYLOAD.length]);
    assert.equal(clean.picture_reader, "the built-in PNG reader");
    assert.match(clean.located_by, /^three finder patterns/);
    assert.deepEqual(clean.segments, [{ mode: "byte", characters: PAYLOAD.length }]);
    assert.equal(clean.payload_file, "store/jobs/j000001/out/qr_read/qr-01.payload.bin");
    assert.equal(await readFile(join(out, "qr_read", "qr-01.payload.bin"), "utf8"), PAYLOAD);
    assert.equal((await lstat(join(out, "qr_read", "qr-01.payload.bin"))).mode & 0o777, 0o600);

    const erased = rowOf(a, `${dir}/finder erased.png`);
    assert.deepEqual([erased.result, erased.version, erased.level, erased.mask, erased.payload_bytes], ["decoded", 3, "L", 3, PAYLOAD.length]);
    assert.match(erased.located_by, /two finder patterns|the box/);
    assert.match(erased.function_patterns, /repainted/);
    assert.equal(await readFile(join(out, "qr_read", "qr-02.payload.bin"), "utf8"), PAYLOAD);
    assert.ok(erased.fixed_modules_repainted > 20, "the erased finder's modules were set to the standard's");
    // The repainted copy is a symbol the standard reading reads (the tool's own output read again, as a job would).
    const again = await call("qr_read", run, { image: "store/jobs/j000001/out/qr_read/qr-02.repainted.png", mode: "finders" }, { out });
    assert.equal(again.doc.rows[0].result, "decoded");
    assert.match(again.doc.rows[0].located_by, /^three finder patterns/);

    const none = rowOf(a, `${dir}/no symbol.png`);
    assert.equal(none.result, "not a symbol");
    assert.ok(none.looked_for.methods.length >= 3 && none.looked_for.polarities.length === 2 && typeof none.looked_for.finder_patterns_found === "number");
    assert.equal(none.payload_file, undefined);

    const pieces = await call("qr_read", run, { mode: "fragments", images: [3, 1, 4, 2].map((k) => `${dir}/piece ${k} of four.png`) }, { out });
    assert.equal(pieces.code, 0, pieces.stdout + pieces.stderr);
    const set = pieces.doc.rows[0] as Doc;
    assert.equal(pieces.doc.status, "complete");
    assert.deepEqual([set.result, set.version, set.level, set.mask, set.payload_bytes, set.modules_not_covered], ["decoded", 3, "L", 3, PAYLOAD.length, 0]);
    assert.equal(set.placements.length, 4);
    // Piece 0 of the call is the bottom-left quarter (piece 3 of four): it lies at row 15, column 0 of the 29 x 29 grid.
    assert.deepEqual(set.placements.map((p: Doc) => [p.row, p.column]), [[15, 0], [0, 0], [15, 15], [0, 15]]);
    assert.equal(await readFile(join(out, set.payload_file.replace("store/jobs/j000001/out/", "")), "utf8"), PAYLOAD);

    // The payload is in no answer: not as text, not as a digest.
    for (const r of [single, again, pieces]) {
      assert.ok(!r.stdout.includes(PAYLOAD) && !r.stdout.includes("fixture payload"), "the payload is not printed");
      assert.doesNotMatch(JSON.stringify((r.doc.rows as Doc[]).map((row) => ({ ...row, sha256: undefined, pieces: undefined }))), /[0-9a-f]{64}/, "no digest of a payload");
    }
  });
});

test("an overdrawn finder, a turned picture, a light-on-dark picture, and numeric and alphanumeric segments", async () => {
  await withRun(async (run, out) => {
    const dir = "inputs/case files";
    py(BUILD, [QRGEN, join(run, dir), PAYLOAD], run);
    py(BUILD_MODES, [QRGEN, join(run, dir, "two modes.png"), "0123456789012", "HELLO WORLD $%*+-./:"], run);
    // The clean symbol turned a quarter turn and inverted, by rewriting its pixels (the generator's PNG is 8-bit grey, filter 0).
    py(String.raw`
import sys, struct, zlib
data = open(sys.argv[1], "rb").read()
w, h = struct.unpack(">II", data[16:24])
at, idat = 8, b""
while at < len(data):
    n = struct.unpack(">I", data[at:at + 4])[0]
    if data[at + 4:at + 8] == b"IDAT":
        idat += data[at + 8:at + 8 + n]
    at += 12 + n
raw = zlib.decompress(idat)
rows = [raw[y * (w + 1) + 1:(y + 1) * (w + 1)] for y in range(h)]
turned = [bytes(255 - rows[h - 1 - x][y] for x in range(h)) for y in range(w)]
ch = lambda k, b: struct.pack(">I", len(b)) + k + b + struct.pack(">I", zlib.crc32(k + b) & 0xFFFFFFFF)
open(sys.argv[2], "wb").write(b"\x89PNG\r\n\x1a\n" + ch(b"IHDR", struct.pack(">IIBBBBB", h, w, 8, 0, 0, 0, 0)) + ch(b"IDAT", zlib.compress(b"".join(b"\x00" + r for r in turned))) + ch(b"IEND", b""))
`, [join(run, dir, "clean symbol.png"), join(run, dir, "turned and inverted.png")], run);
    const r = await call("qr_read", run, { images: [`${dir}/finder overdrawn.png`, `${dir}/turned and inverted.png`, `${dir}/two modes.png`], reader: "builtin" }, { out });
    assert.equal(r.doc.status, "complete", r.stdout);
    const [overdrawn, turned, modes] = r.doc.rows as Doc[];
    assert.deepEqual([overdrawn.result, overdrawn.payload_bytes], ["decoded", PAYLOAD.length]);
    assert.deepEqual([turned.result, turned.polarity, turned.payload_bytes], ["decoded", "light on dark", PAYLOAD.length]);
    assert.deepEqual(modes.segments, [{ mode: "numeric", characters: 13 }, { mode: "alphanumeric", characters: 20 }]);
    assert.equal(await readFile(join(out, "qr_read", "qr-03.payload.bin"), "utf8"), "0123456789012HELLO WORLD $%*+-./:");
    for (const k of [1, 2]) assert.equal(await readFile(join(out, "qr_read", `qr-0${k}.payload.bin`), "utf8"), PAYLOAD);
  });
});

test("damaged modules are corrected and counted, a symbol past correction is not a symbol, and a file that is no picture is not read", async () => {
  await withRun(async (run, out) => {
    const dir = "inputs/case files";
    py(BUILD, [QRGEN, join(run, dir), PAYLOAD], run);
    // Flip data modules of the clean symbol in its pixels: 3 modules (corrected), then a 9 x 9 block of them (past level L's correction).
    const DAMAGE = String.raw`
import sys, struct, zlib
data = open(sys.argv[1], "rb").read()
w, h = struct.unpack(">II", data[16:24])
at, idat = 8, b""
while at < len(data):
    n = struct.unpack(">I", data[at:at + 4])[0]
    if data[at + 4:at + 8] == b"IDAT":
        idat += data[at + 8:at + 8 + n]
    at += 12 + n
raw = bytearray(zlib.decompress(idat))
cells = [tuple(map(int, c.split(","))) for c in sys.argv[3].split(";")]
for r, c in cells:
    for y in range(6):
        for x in range(6):
            i = ((r + 4) * 6 + y) * (w + 1) + 1 + (c + 4) * 6 + x
            raw[i] = 255 - raw[i]
ch = lambda k, b: struct.pack(">I", len(b)) + k + b + struct.pack(">I", zlib.crc32(k + b) & 0xFFFFFFFF)
open(sys.argv[2], "wb").write(b"\x89PNG\r\n\x1a\n" + ch(b"IHDR", data[16:29]) + ch(b"IDAT", zlib.compress(bytes(raw))) + ch(b"IEND", b""))
`;
    py(DAMAGE, [join(run, dir, "clean symbol.png"), join(run, dir, "three flipped.png"), "10,12;14,20;20,15"], run);
    const block = Array.from({ length: 81 }, (_, i) => `${9 + Math.floor(i / 9)},${9 + (i % 9)}`).join(";");
    py(DAMAGE, [join(run, dir, "clean symbol.png"), join(run, dir, "block flipped.png"), block], run);
    await writeFile(join(run, dir, "not a picture.png"), "these bytes are text, whatever the name says\n");
    const r = await call("qr_read", run, { images: [`${dir}/three flipped.png`, `${dir}/block flipped.png`, `${dir}/not a picture.png`, `${dir}/absent.png`] }, { out });
    const [three, blockRow, text, absent] = r.doc.rows as Doc[];
    assert.equal(three.result, "decoded");
    assert.ok(three.errors_corrected >= 1 && three.errors_corrected <= 3, `errors corrected: ${three.errors_corrected}`);
    assert.equal(await readFile(join(out, "qr_read", "qr-01.payload.bin"), "utf8"), PAYLOAD);
    assert.equal(blockRow.result, "not a symbol", "more errors than Reed-Solomon corrects is no payload, never a wrong one");
    assert.deepEqual([text.result, absent.result], ["not read", "not read"]);
    // A picture that could not be read is not a negative: the answer is partial and says which.
    assert.equal(r.doc.status, "partial");
    assert.equal(r.doc.complete, false);
    assert.match(r.doc.status_basis, /was not read as a picture/);
    assert.deepEqual(r.doc.counts, { inputs: 4, decoded: 1, not_a_symbol: 1, not_read: 2, not_finished: 0 });
  });
});

test("the control alone, the rules in every refusal, and the manifest's word on the payload", async () => {
  await withRun(async (run, out) => {
    const self = await call("qr_read", run, { self_test: true }, { out });
    assert.equal(self.doc.status, "complete");
    assert.equal(self.doc.control.checks.length, 4);
    assert.ok(self.doc.control.checks.every((c: Doc) => c.passed));
    const manifest = JSON.parse(await readFile(join(CFB, "tools", "qr_read", "manifest.json"), "utf8")) as Doc;
    const rules = self.doc.rules as string[];
    assert.ok(rules.length >= 3 && rules.length <= 5);
    for (const rule of rules) assert.ok(manifest.description.includes(rule), `the manifest carries the rule: ${rule.slice(0, 60)}`);
    assert.match(manifest.description, /THE PAYLOAD IS NOT IN THE ANSWER/);
    assert.equal(manifest.secret_output, undefined, "the manifest says the agent decides on secret output, and declares none");
    for (const args of [{}, { mode: "fragments", image: "inputs/x.png" }, { image: "inputs/x.png", box: [0, 0, 5, 5] }, { image: 7 }]) {
      const r = await call("qr_read", run, args, { out });
      assert.equal(r.code, 1);
      assert.equal(r.doc.status, "failed");
      assert.deepEqual(r.doc.rules, rules, "a refusal carries the rules");
    }
    const missing = await call("qr_read", run, {}, { out });
    assert.match(missing.doc.error, /mode fragments together/, "the refusal of a call with no picture says the argument forms");
  });
});

// ---- the fixes of the second verification (version 2) --------------------------------------------------------------------------
// An encoder for versions 1 to 10 at every level, written here from ISO/IEC 18004's tables (the block table, the alignment centres,
// the BCH format and version words, the zigzag placement); it shares no line with the tool. Its symbols are drawn pixel by pixel.
const ENC = String.raw`
import sys, os, struct, zlib, random, json
BLOCKS = {
 1: {'L':[(1,26,19)],'M':[(1,26,16)],'Q':[(1,26,13)],'H':[(1,26,9)]},
 2: {'L':[(1,44,34)],'M':[(1,44,28)],'Q':[(1,44,22)],'H':[(1,44,16)]},
 3: {'L':[(1,70,55)],'M':[(1,70,44)],'Q':[(2,35,17)],'H':[(2,35,13)]},
 4: {'L':[(1,100,80)],'M':[(2,50,32)],'Q':[(2,50,24)],'H':[(4,25,9)]},
 5: {'L':[(1,134,108)],'M':[(2,67,43)],'Q':[(2,33,15),(2,34,16)],'H':[(2,33,11),(2,34,12)]},
 6: {'L':[(2,86,68)],'M':[(4,43,27)],'Q':[(4,43,19)],'H':[(4,43,15)]},
 7: {'L':[(2,98,78)],'M':[(4,49,31)],'Q':[(2,32,14),(4,33,15)],'H':[(4,39,13),(1,40,14)]},
 8: {'L':[(2,121,97)],'M':[(2,60,38),(2,61,39)],'Q':[(4,40,18),(2,41,19)],'H':[(4,40,14),(2,41,15)]},
 9: {'L':[(2,146,116)],'M':[(3,58,36),(2,59,37)],'Q':[(4,36,16),(4,37,17)],'H':[(4,36,12),(4,37,13)]},
 10:{'L':[(2,86,68),(2,87,69)],'M':[(4,69,43),(1,70,44)],'Q':[(6,43,19),(2,44,20)],'H':[(6,43,15),(2,44,16)]},
}
ALIGN = {1:[],2:[6,18],3:[6,22],4:[6,26],5:[6,30],6:[6,34],7:[6,22,38],8:[6,24,42],9:[6,26,46],10:[6,28,50]}
EXP = [0] * 512; LOG = [0] * 256; x = 1
for i in range(255):
    EXP[i] = x; LOG[x] = i; x <<= 1
    if x & 0x100: x ^= 0x11D
for i in range(255, 512): EXP[i] = EXP[i - 255]
def mul(a, b): return 0 if not a or not b else EXP[LOG[a] + LOG[b]]
def ecc(data, n):
    g = [1]
    for i in range(n):
        g2 = [0] * (len(g) + 1)
        for j, c in enumerate(g):
            g2[j] ^= c; g2[j + 1] ^= mul(c, EXP[i])
        g = g2
    msg = list(data) + [0] * n
    for i in range(len(data)):
        c = msg[i]
        if c:
            for j in range(1, len(g)): msg[i + j] ^= mul(g[j], c)
    return msg[len(data):]
def put(b, v, n):
    for i in range(n - 1, -1, -1): b.append((v >> i) & 1)
def byte_bits(payload, version):
    b = []; put(b, 4, 4); put(b, len(payload), 8 if version < 10 else 16)
    for c in payload: put(b, c, 8)
    return b
def blocks_of(bits, version, level):
    groups = BLOCKS[version][level]; ndata = sum(c * d for c, t, d in groups); cap = ndata * 8
    b = list(bits); assert len(b) <= cap
    b += [0] * min(4, cap - len(b)); b += [0] * (-len(b) % 8)
    cw = [int("".join(map(str, b[i:i + 8])), 2) for i in range(0, len(b), 8)]
    k = 0
    while len(cw) < ndata: cw.append((0xEC, 0x11)[k % 2]); k += 1
    blocks, lengths, at = [], [], 0
    for c, t, d in groups:
        for _ in range(c):
            blocks.append(cw[at:at + d] + ecc(cw[at:at + d], t - d)); lengths.append(d); at += d
    return blocks, lengths
def interleave(blocks, lengths):
    out = []
    for i in range(max(lengths)):
        for b, d in zip(blocks, lengths):
            if i < d: out.append(b[i])
    for i in range(len(blocks[0]) - lengths[0]):
        for b, d in zip(blocks, lengths): out.append(b[d + i])
    return out
def fmt_bits(level, mask):
    d = ({'L': 1, 'M': 0, 'Q': 3, 'H': 2}[level] << 3) | mask; v = d << 10
    for i in range(14, 9, -1):
        if v & (1 << i): v ^= 0x537 << (i - 10)
    return ((d << 10) | v) ^ 0x5412
def ver_bits(version):
    v = version << 12
    for i in range(17, 11, -1):
        if v & (1 << i): v ^= 0x1F25 << (i - 12)
    return (version << 12) | v
MASK = [lambda r, c: (r + c) % 2 == 0, lambda r, c: r % 2 == 0, lambda r, c: c % 3 == 0, lambda r, c: (r + c) % 3 == 0,
        lambda r, c: (r // 2 + c // 3) % 2 == 0, lambda r, c: (r * c) % 2 + (r * c) % 3 == 0, lambda r, c: ((r * c) % 2 + (r * c) % 3) % 2 == 0,
        lambda r, c: ((r * c) % 3 + (r + c) % 2) % 2 == 0]
def matrix(cw, version, level, mask):
    n = 17 + 4 * version
    M = [[None] * n for _ in range(n)]
    for r0, c0 in ((0, 0), (0, n - 7), (n - 7, 0)):
        for r in range(-1, 8):
            for c in range(-1, 8):
                if 0 <= r0 + r < n and 0 <= c0 + c < n:
                    M[r0 + r][c0 + c] = 1 if (0 <= r <= 6 and 0 <= c <= 6 and (r in (0, 6) or c in (0, 6) or (2 <= r <= 4 and 2 <= c <= 4))) else 0
    for i in range(8, n - 8): M[6][i] = M[i][6] = 1 - i % 2
    for r in ALIGN[version]:
        for c in ALIGN[version]:
            if (r < 9 and c < 9) or (r < 9 and c > n - 9) or (r > n - 9 and c < 9): continue
            for dr in range(-2, 3):
                for dc in range(-2, 3): M[r + dr][c + dc] = 1 if max(abs(dr), abs(dc)) != 1 else 0
    M[4 * version + 9][8] = 1
    f = fmt_bits(level, mask)
    first = [(0, 8), (1, 8), (2, 8), (3, 8), (4, 8), (5, 8), (7, 8), (8, 8), (8, 7), (8, 5), (8, 4), (8, 3), (8, 2), (8, 1), (8, 0)]
    for i in range(15):
        bit = (f >> i) & 1; r, c = first[i]; M[r][c] = bit
        if i < 8: M[8][n - 1 - i] = bit
        else: M[n - 7 + (i - 8)][8] = bit
    if version >= 7:
        vb = ver_bits(version)
        for k in range(18):
            bit = (vb >> k) & 1; M[n - 11 + k % 3][k // 3] = bit; M[k // 3][n - 11 + k % 3] = bit
    bits = []
    for w in cw: put(bits, w, 8)
    bi, d, xx, y = 0, -1, n - 1, n - 1
    while xx > 0:
        if xx == 6: xx -= 1
        while 0 <= y < n:
            for i in range(2):
                col = xx - i
                if M[y][col] is not None: continue
                bit = bits[bi] if bi < len(bits) else 0; bi += 1
                if MASK[mask](y, col): bit ^= 1
                M[y][col] = bit
            y += d
        d = -d; y += d; xx -= 2
    return M
def symbol(payload, version, level, mask, bits=None):
    blocks, lengths = blocks_of(bits if bits is not None else byte_bits(payload, version), version, level)
    return matrix(interleave(blocks, lengths), version, level, mask)
def draw(M, scale=6, quiet=4, rows=None, cols=None):
    rows = rows or (0, len(M)); cols = cols or (0, len(M[0]))
    h, w = rows[1] - rows[0], cols[1] - cols[0]
    out = []
    for yy in range((h + 2 * quiet) * scale):
        r = yy // scale - quiet + rows[0]; line = bytearray()
        for xp in range((w + 2 * quiet) * scale):
            c = xp // scale - quiet + cols[0]
            line.append(0 if rows[0] <= r < rows[1] and cols[0] <= c < cols[1] and M[r][c] else 255)
        out.append(bytes(line))
    return out
def chunk(k, b): return struct.pack(">I", len(b)) + k + b + struct.pack(">I", zlib.crc32(k + b) & 0xFFFFFFFF)
def png(rows, path, depth=8, cut=None):
    w, h = len(rows[0]), len(rows)
    if depth == 16: raw = b"".join(b"\x00" + b"".join(bytes((0, v)) for v in r) for r in rows)
    else: raw = b"".join(b"\x00" + r for r in rows)
    if cut: raw = raw[:len(raw) // cut]
    open(path, "wb").write(b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, depth, 0, 0, 0, 0)) + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b""))
`;

const encode = (script: string, args: string[], cwd: string): string => py(ENC + "\n" + script, args, cwd);

test("a clean symbol of every version from 2 to 10 reads with no correction (the alignment pattern's centre is not half a module off)", async () => {
  await withRun(async (run, out) => {
    encode(String.raw`
d = sys.argv[1]
for v in range(2, 11):
    level, mask = "LMQH"[v % 4], v % 8
    rnd = random.Random(v)
    payload = bytes(rnd.randrange(256) for _ in range((sum(c * dd for c, t, dd in BLOCKS[v][level]) - 3) // 2 + 1))
    png(draw(symbol(payload, v, level, mask), 6, 4), "%s/v%d.png" % (d, v))
    open("%s/v%d.expect" % (d, v), "wb").write(payload)
`, [join(run, "work/s1")], run);
    const r = await call("qr_read", run, { images: Array.from({ length: 9 }, (_, i) => `work/s1/v${i + 2}.png`) }, { out });
    assert.equal(r.doc.status, "complete", r.stdout.slice(0, 600));
    for (const [i, row] of (r.doc.rows as Doc[]).entries()) {
      const v = i + 2;
      assert.deepEqual([row.result, row.version, row.level, row.mask], ["decoded", v, "LMQH"[v % 4], v % 8], `version ${v}`);
      assert.equal(row.errors_corrected, 0, `a clean version ${v} symbol needed ${row.errors_corrected} corrections (${row.located_by})`);
      assert.deepEqual(await readFile(join(out, row.payload_file.replace("store/jobs/j000001/out/", ""))), await readFile(join(run, `work/s1/v${v}.expect`)));
    }
  });
});

test("the last-resort format search runs Reed-Solomon on a symbol of several blocks whose every block holds errors, and takes the strongest level that decodes", async () => {
  await withRun(async (run, out) => {
    // Both format copies overwritten, and in every Reed-Solomon block a quarter of its check codewords' worth of bytes changed.
    encode(String.raw`
d = sys.argv[1]
for v, level, mask in ((4, "H", 2), (5, "H", 6), (6, "M", 3)):
    rnd = random.Random(v)
    payload = bytes(rnd.randrange(256) for _ in range(30))
    blocks, lengths = blocks_of(byte_bits(payload, v), v, level)
    for b in blocks:
        for at in rnd.sample(range(len(b)), (len(b) - lengths[0]) // 4):
            b[at] ^= rnd.randrange(1, 256)
    M = matrix(interleave(blocks, lengths), v, level, mask)
    n = len(M)
    for i in range(9):
        if i != 6: M[8][i] ^= 1; M[i][8] ^= 1
    for i in range(8): M[8][n - 1 - i] ^= 1; M[n - 1 - i][8] ^= 1
    png(draw(M, 6, 4), "%s/v%d.png" % (d, v))
    open("%s/v%d.expect" % (d, v), "wb").write(payload)
`, [join(run, "work/s1")], run);
    const r = await call("qr_read", run, { images: [4, 5, 6].map((v) => `work/s1/v${v}.png`) }, { out });
    assert.equal(r.doc.status, "complete", r.stdout.slice(0, 600));
    for (const [i, row] of (r.doc.rows as Doc[]).entries()) {
      const v = [4, 5, 6][i];
      assert.equal(row.result, "decoded", `version ${v}: ${JSON.stringify(row.looked_for ?? row).slice(0, 300)}`);
      assert.ok(row.blocks > 1 && row.blocks_without_error === 0, "every block needed correcting");
      assert.match(row.format.by, /each of the 32 format words tried/);
      assert.deepEqual(await readFile(join(out, row.payload_file.replace("store/jobs/j000001/out/", ""))), await readFile(join(run, `work/s1/v${v}.expect`)));
    }
    // With no error in the data, a codeword of a stronger level is one of a weaker level whose blocks have the same lengths (version 1 at
    // every level, version 6 at M, Q and H): the weaker one decodes too, with the wrong split of data and check codewords. The strongest wins.
    encode(String.raw`
d = sys.argv[1]
for v, level, mask in ((1, "Q", 4), (6, "Q", 3), (6, "H", 1)):
    rnd = random.Random(100 * v + mask)
    payload = bytes(rnd.randrange(256) for _ in range(sum(c * dd for c, t, dd in BLOCKS[v][level]) - 2))
    M = symbol(payload, v, level, mask)
    n = len(M)
    for i in range(9):
        if i != 6: M[8][i] ^= 1; M[i][8] ^= 1
    for i in range(8): M[8][n - 1 - i] ^= 1; M[n - 1 - i][8] ^= 1
    png(draw(M, 6, 4), "%s/same-%d%s.png" % (d, v, level))
    open("%s/same-%d%s.expect" % (d, v, level), "wb").write(payload)
`, [join(run, "work/s1")], run);
    const same = await call("qr_read", run, { images: ["1Q", "6Q", "6H"].map((k) => `work/s1/same-${k}.png`) }, { out });
    for (const [i, row] of (same.doc.rows as Doc[]).entries()) {
      const k = ["1Q", "6Q", "6H"][i];
      assert.deepEqual([row.result, row.version, row.level], ["decoded", Number(k[0]), k[1]], `${k}: the level whose check codewords all hold`);
      assert.deepEqual(await readFile(join(out, row.payload_file.replace("store/jobs/j000001/out/", ""))), await readFile(join(run, `work/s1/same-${k}.expect`)));
    }
  });
});

test("fragments: a quarter of another symbol among three of one is named and makes the answer partial; the set's own four pieces contradict nothing", async () => {
  await withRun(async (run, out) => {
    encode(String.raw`
d = sys.argv[1]
rnd = random.Random(7)
A, B = bytes(rnd.randrange(256) for _ in range(5)), bytes(rnd.randrange(256) for _ in range(5))
X, Y = symbol(A, 2, "H", 5), symbol(B, 2, "H", 5)
n = len(X); h = n // 2 + 1
quarters = [((0, h), (0, h)), ((0, h), (h, n)), ((h, n), (0, h)), ((h, n), (h, n))]
for k, (rows, cols) in enumerate(quarters):
    png(draw(X, 6, 2, rows, cols), "%s/x%d.png" % (d, k))
    png(draw(Y, 6, 2, rows, cols), "%s/y%d.png" % (d, k))
open(d + "/x.expect", "wb").write(A)
`, [join(run, "work/s1")], run);
    const mixed = await call("qr_read", run, { mode: "fragments", images: ["work/s1/x0.png", "work/s1/x1.png", "work/s1/x2.png", "work/s1/y3.png"] }, { out });
    const row = mixed.doc.rows[0] as Doc;
    assert.equal(row.result, "decoded");
    assert.equal(mixed.doc.status, "partial", "a set with a piece that contradicts the symbol read is not a complete reading");
    assert.deepEqual(await readFile(join(out, row.payload_file.replace("store/jobs/j000001/out/", ""))), await readFile(join(run, "work/s1/x.expect")));
    assert.deepEqual(row.pieces_contradicting_the_symbol, [3], "the piece of the other symbol is named");
    assert.ok((row.placements as Doc[])[3].modules_contradicting_the_decoded_symbol > 0);
    assert.match(mixed.doc.partial_reasons.join(" "), /piece\(s\) 3 contradict the decoded symbol/);
    const own = await call("qr_read", run, { mode: "fragments", images: [0, 1, 2, 3].map((k) => `work/s1/x${k}.png`) }, { out });
    assert.equal(own.doc.status, "complete", own.stdout.slice(0, 600));
    assert.deepEqual((own.doc.rows[0].placements as Doc[]).map((p) => p.modules_contradicting_the_decoded_symbol), [0, 0, 0, 0]);
  });
});

test("fragments: sixteen pieces that place nowhere end with one JSON answer by the tool's clock, never past it", async () => {
  await withRun(async (run, out) => {
    encode(String.raw`
d = sys.argv[1]
rnd = random.Random(11)
for k in range(16):
    M = [[rnd.randrange(2) for _ in range(15)] for _ in range(15)]
    png(draw(M, 6, 2), "%s/n%d.png" % (d, k))
`, [join(run, "work/s1")], run);
    const r = await call("qr_read", run, { mode: "fragments", images: Array.from({ length: 16 }, (_, k) => `work/s1/n${k}.png`), max_seconds: 5 }, { out, limitMs: 40_000 });
    assert.equal(r.killed, false, "the search reads its clock at every step");
    assert.ok(r.ms < 20_000, `answered after ${r.ms} ms with max_seconds 5`);
    assert.equal(r.doc.status, "failed", r.stdout.slice(0, 400));
    assert.equal(r.doc.rows[0].result, "not finished", "a search that was stopped is not a negative");
    assert.match(r.doc.rows[0].why, /clock ran out|bound of/);
  });
});

test("a PNG cut short is said and partial, and a picture of several frames is searched frame by frame or says which frames it did not read", async () => {
  await withRun(async (run, out) => {
    // Pillow as the tool sees it (the tool runs without -I, so a user site counts); the GIF and TIFF fixtures are drawn by it the same way.
    const hasPillow = spawnSync(PYTHON3, ["-c", "import PIL.Image"], { cwd: run }).status === 0;
    encode(String.raw`
d = sys.argv[1]
payload = b"fixture: frames and cuts 0042"
M = symbol(payload, 3, "M", 4)
sym = draw(M, 6, 4)
side = len(sym)
white = [b"\xff" * side for _ in range(side)]
# The symbol in the second half of the rows, and the image data cut after the first half.
png(white + sym, d + "/cut.png", cut=2)
# An animated PNG: the default image (frame 1, fcTL before IDAT) is white, frame 2 (fdAT) holds the symbol.
def idat_of(rows): return zlib.compress(b"".join(b"\x00" + r for r in rows))
def fctl(seq): return struct.pack(">IIIIIHHBB", seq, side, side, 0, 0, 1, 10, 0, 0)
apng = (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", side, side, 8, 0, 0, 0, 0)) + chunk(b"acTL", struct.pack(">II", 2, 0))
        + chunk(b"fcTL", fctl(0)) + chunk(b"IDAT", idat_of(white)) + chunk(b"fcTL", fctl(1)) + chunk(b"fdAT", struct.pack(">I", 2) + idat_of(sym)) + chunk(b"IEND", b""))
open(d + "/animated.png", "wb").write(apng)
open(d + "/frames.expect", "wb").write(payload)
open(d + "/white.raw", "wb").write(b"".join(white))
open(d + "/symbol.raw", "wb").write(b"".join(sym))
`, [join(run, "work/s1"), String(hasPillow)], run);
    if (hasPillow) {
      const made = spawnSync(PYTHON3, ["-c", String.raw`
import sys
from PIL import Image
d, side = sys.argv[1], int(sys.argv[2])
frames = [Image.frombytes("L", (side, side), open(d + name, "rb").read()) for name in ("/white.raw", "/symbol.raw")]
frames[0].save(d + "/two.gif", save_all=True, append_images=frames[1:], duration=100)
frames[0].save(d + "/two.tif", save_all=True, append_images=frames[1:])
`, join(run, "work/s1"), String(Math.round(Math.sqrt((await readFile(join(run, "work/s1/white.raw"))).length)))], { cwd: run, encoding: "utf8" });
      assert.equal(made.status, 0, made.stderr);
    }
    const cut = await call("qr_read", run, { image: "work/s1/cut.png" }, { out });
    assert.equal(cut.doc.status, hasPillow ? "partial" : "failed", cut.stdout.slice(0, 600));
    const cutRow = cut.doc.rows[0] as Doc;
    if (hasPillow) {
      assert.match(cutRow.picture_damaged, /image data ends after/);
      assert.match(cut.doc.partial_reasons.join(" "), /damaged picture/);
    } else {
      assert.equal(cutRow.result, "not read");
    }

    const builtin = await call("qr_read", run, { image: "work/s1/animated.png", reader: "builtin" }, { out });
    assert.equal(builtin.doc.status, "partial", builtin.stdout.slice(0, 600));
    assert.deepEqual([builtin.doc.rows[0].frames, builtin.doc.rows[0].frames_searched], [2, 1]);
    assert.match(builtin.doc.rows[0].frames_not_read, /^frames 2 to 2: an animated PNG/);
    if (!hasPillow) return;
    const r = await call("qr_read", run, { images: ["work/s1/animated.png", "work/s1/two.gif", "work/s1/two.tif"] }, { out });
    assert.equal(r.doc.status, "complete", r.stdout.slice(0, 600));
    for (const row of r.doc.rows as Doc[]) {
      assert.deepEqual([row.result, row.frames, row.frames_searched, row.frame], ["decoded", 2, 2, 2], row.input);
      assert.deepEqual(await readFile(join(out, row.payload_file.replace("store/jobs/j000001/out/", ""))), await readFile(join(run, "work/s1/frames.expect")));
    }
  });
});

test("a structured-append header is noted without its parity byte; a box past the picture, a repainted copy's mode and a 16-bit PNG of low samples", async () => {
  await withRun(async (run, out) => {
    encode(String.raw`
d = sys.argv[1]
payload = b"fixture: part one 0042"
bits = []
put(bits, 3, 4); put(bits, 0x01, 8); put(bits, 0xA7, 8)          # structured append: symbol 1 of 2, parity 167
bits += byte_bits(payload, 2)
png(draw(symbol(None, 2, "L", 1, bits=bits), 6, 4), d + "/appended.png")
M = symbol(b"fixture: sixteen bits 0042", 2, "L", 0)
png(draw(M, 6, 4), d + "/sixteen.png", depth=16)                  # samples 0 and 255 in 16 bits: every high byte is zero
`, [join(run, "work/s1")], run);
    py(BUILD, [QRGEN, join(run, "inputs/case files"), PAYLOAD], run);
    const r = await call("qr_read", run, { images: ["work/s1/appended.png", "work/s1/sixteen.png"] }, { out });
    assert.equal(r.doc.status, "complete", r.stdout.slice(0, 600));
    const [appended, sixteen] = r.doc.rows as Doc[];
    assert.match(appended.notes.join(" "), /structured append: symbol 1 of 2/);
    assert.doesNotMatch(r.stdout, /parity \d|167/, "the parity byte, a digest of the whole message, is not printed");
    assert.equal(sixteen.result, "decoded");
    assert.match(sixteen.picture_notes.join(" "), /16-bit samples/);

    const boxed = await call("qr_read", run, { image: "work/s1/appended.png", box: [0, 0, 5000, 5000] }, { out });
    assert.equal(boxed.doc.rows[0].result, "not read");
    assert.match(boxed.doc.rows[0].why, /reaches past the picture/);
    assert.doesNotMatch(boxed.stdout, /IndexError/);

    const repaint = await call("qr_read", run, { image: "inputs/case files/finder erased.png", mode: "repaint" }, { out });
    const file = repaint.doc.rows[0].repainted_file as string;
    assert.equal((await lstat(join(out, file.replace("store/jobs/j000001/out/", "")))).mode & 0o777, 0o600);
  });
});
