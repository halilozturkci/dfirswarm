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
import { call, CFB, greyPng, py, ROOT, tool, withRun, type Doc } from "./pack-base-media-fixture.ts";

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

// ---- the second verification of 1.17.1: every decode, frame walk and row loop reads the clock and is bounded in memory -------------------

/** Pillow as the tool sees it (the tool runs without -I, so a user site counts). */
const pillowHere = (cwd: string): boolean => spawnSync(PYTHON3, ["-c", "import PIL.Image"], { cwd }).status === 0;

/** A fixture script that needs Pillow (run without -I, as the tool is): its stdout, or a failed assertion. */
function withPillow(code: string, args: string[], cwd: string): string {
  const r = spawnSync(PYTHON3, ["-c", code, ...args], { cwd, encoding: "utf8", maxBuffer: 64 << 20 });
  assert.equal(r.status, 0, `the fixture builder failed: ${r.stderr.slice(-600)}`);
  return r.stdout;
}

/**
 * A progressive JPEG with `n` more AC scans of its one component, each coding every block in end-of-band runs (EOB14: one code of one bit
 * in the scan's own table, then 14 bits of run length, so 32767 blocks in 15 bits; ISO/IEC 10918-1 G.1.2.2). A decoder works through
 * every block of every scan, so the scans cost time far beyond their bytes. 3000 x 2000 pixels: 93,750 blocks, three runs a scan.
 */
const JPEG_SCANS = String.raw`
import io, struct, sys
from PIL import Image, ImageDraw
out, n, w, h = sys.argv[1], int(sys.argv[2]), 3000, 2000
im = Image.new("L", (w, h), 255)
d = ImageDraw.Draw(im)
for i in range(0, w - 20, 40): d.rectangle([i + 5, 20, i + 20, h - 20], fill=0)
buf = io.BytesIO(); im.save(buf, "JPEG", progressive=True, quality=90); data = buf.getvalue()
assert data[-2:] == b"\xff\xd9"
left, bits = ((w + 7) // 8) * ((h + 7) // 8), ""
while left > 0:
    run = min(left, 32767); assert run >= 16384; bits += "0" + format(run - 16384, "014b"); left -= run
bits += "1" * (-len(bits) % 8)
entropy = bytearray()
for i in range(0, len(bits), 8):
    entropy.append(int(bits[i:i + 8], 2))
    if entropy[-1] == 0xFF: entropy.append(0)
table = bytes([0x10]) + bytes([1] + [0] * 15) + bytes([0xE0])
dht = b"\xff\xc4" + struct.pack(">H", 2 + len(table)) + table
scan = b"\xff\xda" + struct.pack(">H", 8) + bytes([1, 1, 0x00, 1, 63, 0x00]) + bytes(entropy)
open(out, "wb").write(data[:-2] + dht + scan * n + b"\xff\xd9")
`;

/** One call run under a parent that reports the peak resident memory of the tool and of every process it started (ru_maxrss of the children). */
function measured(run: string, out: string, args: unknown, limitS: number): { code: number | null; ms: number; rssMb: number; killed: boolean; doc: Doc; stdout: string } {
  const script = String.raw`
import json, os, resource, subprocess, sys, time
tool, args, out, limit = sys.argv[1], sys.argv[2], sys.argv[3], float(sys.argv[4])
env = {k: v for k, v in os.environ.items() if k not in ("SECRET_OUTPUT",)}
env.update(AGENT_ID="s1", JOB_ID="j000001", OUT=out)
started = time.monotonic()
p = subprocess.Popen([sys.executable, tool], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
try:
    so, _se = p.communicate(args.encode(), timeout=limit); killed = False
except subprocess.TimeoutExpired:
    p.kill(); so, _se = p.communicate(); killed = True
peak = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
peak = peak / (1 << 20) if sys.platform == "darwin" else peak / 1024
print(json.dumps({"code": p.returncode, "ms": round((time.monotonic() - started) * 1000), "rss_mb": round(peak), "killed": killed, "stdout": so.decode("utf-8", "replace")}))
`;
  const r = spawnSync(PYTHON3, ["-c", script, tool("qr_read"), JSON.stringify(args), out, String(limitS)], { cwd: run, encoding: "utf8", maxBuffer: 64 << 20 });
  assert.equal(r.status, 0, r.stderr.slice(-600));
  const m = JSON.parse(r.stdout) as { code: number | null; ms: number; rss_mb: number; killed: boolean; stdout: string };
  let doc: Doc = {};
  try {
    doc = JSON.parse(m.stdout) as Doc;
  } catch {
    doc = { not_json: m.stdout.slice(0, 300) };
  }
  return { code: m.code, ms: m.ms, rssMb: m.rss_mb, killed: m.killed, doc, stdout: m.stdout };
}

test("a TIFF of 250,000 pages is searched to the bound of 64 frames and never counted whole; Pillow's decode ends at the clock; an icon is not read", async () => {
  await withRun(async (run, out) => {
    // 250,000 page directories that share one 8 x 8 strip, written from the TIFF 6.0 layout: Pillow's count of the pages walks every one of them.
    py(String.raw`
import struct, sys
strip = b"\xff" * 64
data = bytearray(b"II*\x00" + struct.pack("<I", 8 + len(strip)) + strip)
tags = [(256, 3, 8), (257, 3, 8), (258, 3, 8), (259, 3, 1), (262, 3, 1), (273, 4, 8), (278, 3, 8), (279, 4, 64)]
size, base, n = 2 + 12 * len(tags) + 4, len(data), 250000
for i in range(n):
    data += struct.pack("<H", len(tags))
    for tag, kind, value in tags:
        data += struct.pack("<HHI", tag, kind, 1) + (struct.pack("<HH", value, 0) if kind == 3 else struct.pack("<I", value))
    data += struct.pack("<I", base + (i + 1) * size if i < n - 1 else 0)
open(sys.argv[1], "wb").write(bytes(data))
`, [join(run, "work/s1/pages.tif")], run);
    if (!pillowHere(run)) return;
    const pages = await call("qr_read", run, { image: "work/s1/pages.tif", max_seconds: 5 }, { out, limitMs: 40_000 });
    assert.equal(pages.killed, false, "the call ended by itself");
    assert.ok(pages.ms < 20_000, `answered in ${pages.ms} ms on a 5 second clock`);
    const row = pages.doc.rows[0] as Doc;
    assert.equal(pages.doc.status, "partial", pages.stdout.slice(0, 600));
    assert.deepEqual([row.result, row.frames_searched, row.frames_at_least, row.frames], ["not a symbol", 64, 65, undefined]);
    assert.match(row.frames_not_read, /^frames past the 64th: the picture has more than 64 frames, and they were neither counted nor searched/);

    // A JPEG of 250,000 scans: refused by its count of scans before Pillow sees it; and, with the bound of scans lifted (an environment
    // variable for the tests), Pillow's decode, which reads no clock of its own, is ended at the tool's clock.
    withPillow(JPEG_SCANS, [join(run, "work/s1/scans.jpg"), "250000"], run);
    const refused = await call("qr_read", run, { image: "work/s1/scans.jpg", max_seconds: 5 }, { out, limitMs: 40_000 });
    assert.ok(refused.ms < 10_000, `${refused.ms} ms`);
    assert.match(refused.doc.rows[0].why, /a JPEG of 25000\d scans \(start-of-scan markers\): this tool hands Pillow a JPEG of up to 256/);
    const lifted = await call("qr_read", run, { image: "work/s1/scans.jpg", max_seconds: 5 }, { out, limitMs: 40_000, env: { TOOL_MAX_JPEG_SCANS: "100000000" } });
    assert.equal(lifted.killed, false, "the call ended by itself");
    assert.ok(lifted.ms < 15_000, `answered in ${lifted.ms} ms on a 5 second clock`);
    assert.deepEqual([lifted.doc.status, lifted.doc.rows[0].result], ["failed", "not finished"], lifted.stdout.slice(0, 600));
    assert.match(lifted.doc.partial_reasons.join(" "), /the clock ran out while picture 1 of 1 was being read/);

    // An icon is not one of the formats the tool hands Pillow: it is not read, and the answer names the formats.
    withPillow(`from PIL import Image; import sys; Image.new("L", (64, 64), 255).save(sys.argv[1], sizes=[(16, 16), (64, 64)])`, [join(run, "work/s1/icon.ico")], run);
    const icon = await call("qr_read", run, { image: "work/s1/icon.ico" }, { out });
    assert.equal(icon.doc.rows[0].result, "not read");
    assert.match(icon.doc.rows[0].why, /the formats this tool hands it \(PNG, JPEG, BMP, GIF, WebP and TIFF/);
  });
});

test("a 40 KB PNG of 36,000,000 x 1 alternating pixels is bounded in memory; a PNG of 22 million chunks ends at the clock", async () => {
  await withRun(async (run, out) => {
    py(String.raw`
import struct, sys, zlib
def chunk(k, b): return struct.pack(">I", len(b)) + k + b + struct.pack(">I", zlib.crc32(k + b))
w = 36_000_000
raw = b"\x00" + (b"\x00\xff" * (w // 2))
open(sys.argv[1], "wb").write(b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, 1, 8, 0, 0, 0, 0)) + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))
small = b"".join(b"\x00" + b"\xff" * 8 for _ in range(8))
head = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 8, 8, 8, 0, 0, 0, 0)) + chunk(b"IDAT", zlib.compress(small))
with open(sys.argv[2], "wb") as f:
    f.write(head)
    one = chunk(b"zzZz", b"") * 65536
    for _ in range((250 << 20) // len(one)): f.write(one)
    f.write(chunk(b"IEND", b""))
`, [join(run, "work/s1/wide.png"), join(run, "work/s1/chunks.png")], run);
    // Every run of the row used to be held in a list (3.9 GB at its peak); the runs are now walked five at a time and counted as they come.
    const wide = measured(run, out, { image: "work/s1/wide.png", max_seconds: 10 }, 60);
    assert.equal(wide.killed, false);
    assert.ok(wide.rssMb < 1024, `the peak resident memory was ${wide.rssMb} MB`);
    assert.ok(wide.ms < 25_000, `answered in ${wide.ms} ms on a 10 second clock`);
    assert.ok(["not a symbol", "not finished"].includes(wide.doc.rows?.[0]?.result), wide.stdout.slice(0, 600));
    // The built-in reader's walk of the chunks reads the clock.
    const chunks = await call("qr_read", run, { image: "work/s1/chunks.png", max_seconds: 5, reader: "builtin" }, { out, limitMs: 40_000 });
    assert.equal(chunks.killed, false);
    assert.ok(chunks.ms < 12_000, `answered in ${chunks.ms} ms on a 5 second clock`);
    assert.equal(chunks.doc.rows[0].result, "not finished", chunks.stdout.slice(0, 600));
  });
});

test("frames that hold three different payloads are each written and listed; box goes with auto and repaint only", async () => {
  await withRun(async (run, out) => {
    encode(String.raw`
d = sys.argv[1]
for name, payload in (("a", b"fixture frame one 0042"), ("b", b"fixture frame two 0042"), ("c", b"fixture frame three 0042")):
    rows = draw(symbol(payload, 2, "M", 2), 4, 4)
    open(d + "/" + name + ".raw", "wb").write(b"".join(rows))
    open(d + "/" + name + ".expect", "wb").write(payload)
    side = len(rows)
open(d + "/side", "w").write(str(side))
png(draw(symbol(b"fixture plain symbol 0042", 2, "M", 3), 4, 4), d + "/plain.png")
`, [join(run, "work/s1")], run);
    if (pillowHere(run)) {
      withPillow(String.raw`
import sys
from PIL import Image
d = sys.argv[1]; side = int(open(d + "/side").read())
f = {k: Image.frombytes("L", (side, side), open(d + "/" + k + ".raw", "rb").read()) for k in "abc"}
for name, keys, kind in (("abc.gif", "abc", "GIF"), ("abab.gif", "abab", "GIF"), ("abc.tif", "abc", "TIFF")):
    frames = [f[k] for k in keys]
    frames[0].save(d + "/" + name, kind, save_all=True, append_images=frames[1:], **({"duration": 100} if kind == "GIF" else {}))
`, [join(run, "work/s1")], run);
      const r = await call("qr_read", run, { images: ["work/s1/plain.png", "work/s1/abc.gif", "work/s1/abab.gif", "work/s1/abc.tif"] }, { out });
      assert.equal(r.doc.status, "complete", r.stdout.slice(0, 800));
      const expect = async (name: string): Promise<Buffer> => readFile(join(run, "work/s1", name + ".expect"));
      const file = (cited: string): string => join(out, cited.replace("store/jobs/j000001/out/", ""));
      for (const [index, keys] of [[1, "abc"], [2, "abab"], [3, "abc"]] as Array<[number, string]>) {
        const at = r.doc.rows[index] as Doc;
        assert.deepEqual([at.result, at.frames, at.frames_searched, at.frame], ["decoded", keys.length, keys.length, 1], at.input);
        assert.deepEqual(await readFile(file(at.payload_file)), await expect("a"));
        const others = at.other_frames_decoded as Doc[];
        if (keys === "abc") {
          assert.deepEqual(others.map((o) => [o.frame, o.same_payload_as_frame ?? null]), [[2, null], [3, null]], at.input);
          assert.deepEqual(await readFile(file(others[0]!.payload_file)), await expect("b"));
          assert.deepEqual(await readFile(file(others[1]!.payload_file)), await expect("c"));
        } else {
          assert.deepEqual(at.frames_with_the_same_payload, [3]);
          assert.deepEqual(others.map((o) => [o.frame, o.same_payload_as_frame ?? null]), [[2, null], [4, 2]], at.input);
          assert.equal(others[1]!.payload_file, undefined, "a payload already written is not written twice");
        }
      }
      assert.doesNotMatch(r.stdout, /fixture frame/, "no payload in the answer");
    }
    // The box: refused with mode finders, and with it in auto only the box is read (looked_for says so).
    const finders = await call("qr_read", run, { image: "work/s1/plain.png", mode: "finders", box: [16, 16, 116, 116] }, { out });
    assert.equal(finders.doc.status, "failed");
    assert.match(finders.doc.error, /box goes with mode auto or repaint/);
    const exact = await call("qr_read", run, { image: "work/s1/plain.png", box: [16, 16, 116, 116] }, { out });
    assert.deepEqual([exact.doc.rows[0].result, exact.doc.rows[0].located_by], ["decoded", "the box given cut into 25 x 25 modules"], exact.stdout.slice(0, 600));
    const wrong = await call("qr_read", run, { image: "work/s1/plain.png", box: [0, 0, 132, 132] }, { out });
    const row = wrong.doc.rows[0] as Doc;
    assert.equal(row.result, "not a symbol", wrong.stdout.slice(0, 600));
    assert.match(row.looked_for.methods[0], /^the box given/);
    assert.doesNotMatch(JSON.stringify(row.looked_for), /three of them at the corners|two finder patterns/, "the readings that take no box are not claimed");
  });
});

// ---- the third verification of 1.17.2: a JPEG cut and given its end back, and every symbol of a frame -------------------------------------

test("a JPEG cut short and given its end marker back is damaged and partial (baseline, progressive, with restart markers); the whole files are complete", { skip: pillowHere(ROOT) ? false : "Pillow does not import here: the tool reads no JPEG without it" }, async () => {
  await withRun(async (run, out) => {
    // The symbol is in the top third; the rest of the picture is light grey, so that the cut part is not where the symbol is.
    encode(String.raw`
d = sys.argv[1]
rows = draw(symbol(b"fixture jpeg top 0042", 2, "M", 3), 4, 4)
w = len(rows[0])
open(d + "/top.raw", "wb").write(b"".join(rows) + b"\xe0" * (w * len(rows) * 2))
open(d + "/size", "w").write("%d %d" % (w, len(rows) * 3))
`, [join(run, "work/s1")], run);
    withPillow(String.raw`
import io, sys
from PIL import Image
d = sys.argv[1]; w, h = map(int, open(d + "/size").read().split())
im = Image.frombytes("L", (w, h), open(d + "/top.raw", "rb").read())
for name, kw in (("base", {}), ("prog", {"progressive": True}), ("rst", {"restart_marker_rows": 1})):
    b = io.BytesIO(); im.save(b, "JPEG", quality=95, **kw); data = b.getvalue()
    assert data[-2:] == b"\xff\xd9"
    open(d + "/" + name + ".jpg", "wb").write(data)
    open(d + "/" + name + " cut.jpg", "wb").write(data[:int(len(data) * 0.6)] + b"\xff\xd9")
    Image.open(d + "/" + name + " cut.jpg").load()     # libjpeg takes the cut file without an error: that is the case
`, [join(run, "work/s1")], run);
    const whole = await call("qr_read", run, { images: ["work/s1/base.jpg", "work/s1/prog.jpg", "work/s1/rst.jpg"] }, { out });
    assert.equal(whole.doc.status, "complete", whole.stdout.slice(0, 900));
    assert.deepEqual((whole.doc.rows as Doc[]).map((r) => [r.result, r.picture_damaged ?? null]), [["decoded", null], ["decoded", null], ["decoded", null]]);
    assert.equal(whole.doc.not_read_or_judged.pictures_damaged, 0);
    for (const name of ["base", "prog", "rst"]) {
      const r = await call("qr_read", run, { image: `work/s1/${name} cut.jpg` }, { out });
      assert.equal(r.doc.status, "partial", `${name}: ${r.stdout.slice(0, 900)}`);
      const row = r.doc.rows[0] as Doc;
      assert.match(row.picture_damaged, /the tool's own walk of the JPEG's coded data found it cut or corrupt \(scan \d+: the coded data ends/, name);
      assert.equal(r.doc.not_read_or_judged.pictures_damaged, 1, name);
      assert.doesNotMatch(r.doc.status_basis, /read whole/, name);
      assert.ok((r.doc.partial_reasons as string[]).some((s) => /damaged picture/.test(s)), name);
    }
  });
});

test("a TIFF coded with CCITT (compression 2 or 4), whose decoder fills a damaged strip and only warns, is counted as not walked; LZW is read whole and Deflate is counted as not walked", { skip: pillowHere(ROOT) ? false : "Pillow does not import here: the tool reads no TIFF without it" }, async () => {
  await withRun(async (run, out) => {
    encode(String.raw`
d = sys.argv[1]
rows = draw(symbol(b"fixture ccitt 0042", 2, "M", 3), 4, 4)
open(d + "/sym.raw", "wb").write(b"".join(rows))
open(d + "/size", "w").write("%d %d" % (len(rows[0]), len(rows)))
`, [join(run, "work/s1")], run);
    const made = withPillow(String.raw`
import io, sys
from PIL import Image, features
d = sys.argv[1]; w, h = map(int, open(d + "/size").read().split())
im = Image.frombytes("L", (w, h), open(d + "/sym.raw", "rb").read())
if not features.check_codec("libtiff"):
    print("no libtiff"); sys.exit(0)
for comp in ("group4", "tiff_ccitt", "tiff_lzw", "tiff_adobe_deflate"):
    b = io.BytesIO(); (im.convert("1") if comp in ("group4", "tiff_ccitt") else im).save(b, "TIFF", compression=comp)
    open(d + "/" + comp + ".tif", "wb").write(b.getvalue())
    if comp == "group4":
        data = bytearray(b.getvalue()); t = Image.open(io.BytesIO(bytes(data)))
        o, c = t.tag_v2[273][0], t.tag_v2[279][0]
        data[o + c // 3:o + c] = bytes(c - c // 3)          # sectors not recovered, given back as zeros
        open(d + "/group4 zeroed.tif", "wb").write(data)
        Image.open(d + "/group4 zeroed.tif").load()          # libtiff fills it and only warns: that is the case
print("made")
`, [join(run, "work/s1")], run);
    if (made.includes("no libtiff")) return;
    for (const name of ["group4", "tiff_ccitt", "group4 zeroed"]) {
      const r = await call("qr_read", run, { image: `work/s1/${name}.tif` }, { out });
      assert.equal(r.doc.status, "partial", `${name}: ${r.stdout.slice(0, 900)}`);
      assert.match((r.doc.rows[0] as Doc).jpeg_data_not_walked, /TIFF compression [24], whose decoder may fill a cut strip and only warn/, name);
      assert.equal(r.doc.not_read_or_judged.jpeg_data_not_walked, 1, name);
      assert.doesNotMatch(r.doc.status_basis, /read whole/, name);
    }
    for (const name of ["tiff_lzw"]) {
      const r = await call("qr_read", run, { image: `work/s1/${name}.tif` }, { out });
      assert.equal(r.doc.status, "complete", `${name}: ${r.stdout.slice(0, 900)}`);
      assert.equal((r.doc.rows[0] as Doc).result, "decoded", name);
    }
    {
      // Deflate: libtiff decodes the zero bits of a zeroed tail as symbols and says nothing, so the page is counted as not walked.
      const r = await call("qr_read", run, { image: `work/s1/tiff_adobe_deflate.tif` }, { out });
      assert.equal(r.doc.status, "partial", r.stdout.slice(0, 900));
      assert.match((r.doc.rows[0] as Doc).jpeg_data_not_walked, /TIFF compression 8/);
    }
  });
});

test("every symbol of a frame is read: two side by side, one of them light on dark; a ninth past the bound and finder patterns no reading explains are partial", async () => {
  await withRun(async (run, out) => {
    encode(String.raw`
d = sys.argv[1]
def side_by_side(a, b):
    h = max(len(a), len(b))
    pad = lambda rows, w: rows + [b"\xff" * w] * (h - len(rows))
    return [x + y for x, y in zip(pad(a, len(a[0])), pad(b, len(b[0])))]
A = draw(symbol(b"fixture first symbol 0042", 2, "M", 3), 4, 4)
B = draw(symbol(b"fixture second symbol 0042", 3, "L", 5), 4, 4)
open(d + "/first.expect", "wb").write(b"fixture first symbol 0042"); open(d + "/second.expect", "wb").write(b"fixture second symbol 0042")
png(side_by_side(A, B), d + "/two.png")
inverse = bytes(255 - v for v in range(256))
png(side_by_side(A, [r.translate(inverse) for r in B]), d + "/two inverted.png")
# A symbol whose data is overwritten past correction: its three finder patterns are there, and no reading makes a symbol of it.
M = symbol(b"fixture spoiled 0042", 2, "M", 3)
rnd = random.Random(7)
for r in range(9, 25):
    for c in range(9, 25):
        if not (16 <= r <= 20 and 16 <= c <= 20):
            M[r][c] = rnd.randrange(2)
for r in range(0, 9):
    for c in range(9, 17):
        M[r][c] = rnd.randrange(2)
png(side_by_side(A, draw(M, 4, 4)), d + "/one and a spoiled one.png")
# Nine symbols in one frame, three by three.
grid = [draw(symbol(("grid %d 0042" % k).encode(), 1, "L", k % 8), 3, 4) for k in range(9)]
rows = []
for i in range(3):
    line = grid[3 * i]
    for j in (1, 2):
        line = side_by_side(line, grid[3 * i + j])
    rows += line
png(rows, d + "/nine.png")
`, [join(run, "work/s1")], run);
    const file = (cited: string): string => join(out, cited.replace("store/jobs/j000001/out/", ""));
    for (const name of ["two.png", "two inverted.png"]) {
      const r = await call("qr_read", run, { image: `work/s1/${name}` }, { out });
      assert.equal(r.doc.status, "complete", `${name}: ${JSON.stringify(r.doc.partial_reasons)} ${JSON.stringify(r.doc.rows[0]).slice(0, 1500)}`);
      const row = r.doc.rows[0] as Doc;
      assert.equal(row.symbols_decoded, 2, name);
      assert.deepEqual(await readFile(file(row.payload_file)), await readFile(join(run, "work/s1/first.expect")));
      const second = (row.other_symbols_decoded as Doc[])[0]!;
      assert.deepEqual([second.frame, second.symbol, second.polarity], [1, 2, name === "two.png" ? "dark on light" : "light on dark"], name);
      assert.deepEqual(await readFile(file(second.payload_file)), await readFile(join(run, "work/s1/second.expect")), name);
      assert.ok(second.region_pixels[0] >= row.region_pixels[2] - 4, `the second symbol lies right of the first: ${second.region_pixels} ${row.region_pixels}`);
      assert.doesNotMatch(r.stdout, /fixture (first|second)/, "no payload in the answer");
    }
    const spoiled = await call("qr_read", run, { image: "work/s1/one and a spoiled one.png" }, { out });
    assert.equal(spoiled.doc.status, "partial", spoiled.stdout.slice(0, 900));
    const srow = spoiled.doc.rows[0] as Doc;
    assert.deepEqual([srow.result, srow.symbols_decoded], ["decoded", 1]);
    assert.ok(srow.finder_patterns_not_read.count >= 2, JSON.stringify(srow.finder_patterns_not_read));
    assert.equal(spoiled.doc.not_read_or_judged.finder_patterns_not_read, srow.finder_patterns_not_read.count);
    const nine = await call("qr_read", run, { image: "work/s1/nine.png" }, { out, limitMs: 90_000 });
    assert.equal(nine.doc.status, "partial", nine.stdout.slice(0, 900));
    const nrow = nine.doc.rows[0] as Doc;
    assert.equal(nrow.symbols_decoded, 8);
    assert.deepEqual(nrow.symbols_past_the_bound.frames, [1]);
    assert.equal(nine.doc.not_read_or_judged.frames_past_the_symbol_bound, 1);
    assert.equal(new Set([nrow.payload_file, ...(nrow.other_symbols_decoded as Doc[]).map((o) => o.payload_file)]).size, 8, "eight payloads, each in its own file");
  });
});

// ---- the fourth verification of 1.17.4: the pictures Pillow fills without a word, by paths the JPEG walk did not reach -------------------

/**
 * A TIFF of one 8-bit grey page (classic or BigTIFF), written field by field: `pieces` are its strips, or its tiles when `tiled` is
 * given; the pieces whose indexes are in `zero` are not in the file (offset 0, byte count 0); `extra` adds tags (tag, type, values).
 */
const TIFF = String.raw`
import struct
def tiff(width, height, comp, pieces, tiled=None, rps=None, extra=(), big=False, zero=()):
    tags = {256: (4, [width]), 257: (4, [height]), 258: (3, [8]), 259: (3, [comp]), 262: (3, [1]), 277: (3, [1])}
    if tiled: tags[322], tags[323] = (4, [tiled[0]]), (4, [tiled[1]])
    else: tags[278] = (4, [rps or height])
    for tag, kind, values in extra: tags[tag] = (kind, values)
    off_tag, cnt_tag = (324, 325) if tiled else (273, 279)
    wide = 16 if big else 4
    tags[cnt_tag] = (wide, [0 if i in zero else len(p) for i, p in enumerate(pieces)])
    tags[off_tag] = (wide, [0] * len(pieces))
    word, entry, head, start = (8, 20, 8, 16) if big else (4, 12, 2, 8)
    size, fmt = {3: 2, 4: 4, 16: 8}, {3: "H", 4: "I", 16: "Q"}
    at = start + head + entry * len(tags) + word
    where = {}
    for tag in sorted(tags):
        kind, values = tags[tag]
        if len(values) * size[kind] > word: where[tag] = at; at += len(values) * size[kind]
    offsets = []
    for i, p in enumerate(pieces):
        offsets.append(0 if i in zero else at); at += 0 if i in zero else len(p)
    tags[off_tag] = (wide, offsets)
    out = (b"II+\x00" + struct.pack("<HHQ", 8, 0, start)) if big else (b"II*\x00" + struct.pack("<I", start))
    out += struct.pack("<Q" if big else "<H", len(tags))
    arrays = b""
    for tag in sorted(tags):
        kind, values = tags[tag]
        body = struct.pack("<" + fmt[kind] * len(values), *values)
        out += struct.pack("<HHQ" if big else "<HHI", tag, kind, len(values))
        if tag in where: out += struct.pack("<Q" if big else "<I", where[tag]); arrays += body
        else: out += body.ljust(word, b"\x00")
    return out + b"\x00" * word + arrays + b"".join(p for i, p in enumerate(pieces) if i not in zero)
def jpeg(image):
    import io
    b = io.BytesIO(); image.save(b, "JPEG", quality=95); return b.getvalue()
def cut(data, keep=0.45):
    sos = data.index(b"\xff\xda")
    return data[:sos + int((len(data) - sos) * keep)] + b"\xff\xd9"
`;

test("a PNG past the built-in reader's bound of rows, or a frame of an animated PNG, whose zlib stream ends early is damaged and partial; the whole ones are complete", { skip: pillowHere(ROOT) ? false : "Pillow does not import here: the tool reads neither picture without it" }, async () => {
  await withRun(async (run, out) => {
    encode(String.raw`
d = sys.argv[1]
# 6000 x 6000 RGBA at 16 bits: 288,006,000 bytes of rows, past the built-in reader's 256 MiB. The symbol is at row 4000; the cut file's
# zlib stream ends whole after row 3000, so Pillow fills the rest and says nothing.
W = H = 6000
rows = draw(symbol(b"fixture past the bound 0042", 3, "M", 1), 12, 0)
white = b"\xff\xff" * 4
def line(y):
    if 4000 <= y < 4000 + len(rows):
        return b"\x00" + white * 1000 + b"".join(white if v else b"\x00" * 6 + b"\xff\xff" for v in rows[y - 4000]) + white * (W - 1000 - len(rows))
    return b"\x00" + white * W
for name, upto in (("big", H), ("big cut", 3000)):
    z = zlib.compressobj(6)
    idat = b"".join(z.compress(line(y)) for y in range(upto)) + z.flush()
    open(d + "/" + name + ".png", "wb").write(b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", W, H, 16, 6, 0, 0, 0)) + chunk(b"IDAT", idat) + chunk(b"IEND", b""))
open(d + "/frame.raw", "wb").write(b"".join(draw(symbol(b"fixture second frame 0042", 2, "M", 3), 4, 4)))
`, [join(run, "work/s1")], run);
    withPillow(String.raw`
import io, math, struct, sys, zlib
from PIL import Image
d = sys.argv[1]
raw = open(d + "/frame.raw", "rb").read(); side = math.isqrt(len(raw))
frames = [Image.new("L", (side, side), 255), Image.frombytes("L", (side, side), raw), Image.new("L", (side, side), 128)]
# The first picture is the default image only, not a frame of the animation: the two after it are the fdAT frames.
b = io.BytesIO(); frames[0].save(b, "PNG", save_all=True, append_images=frames[1:], duration=100, default_image=True); data = b.getvalue()
open(d + "/animated.png", "wb").write(data)
# The second frame's fdAT data ends whole after a third of its rows: Pillow keeps the frame before under the rest, and says nothing.
out, at, seen = bytearray(data[:8]), 8, 0
while at < len(data):
    n = int.from_bytes(data[at:at + 4], "big"); kind = data[at + 4:at + 8]; body = data[at + 8:at + 8 + n]; at += 12 + n
    if kind == b"fdAT":
        seen += 1
        if seen == 1:
            rows = zlib.decompress(body[4:])
            body = body[:4] + zlib.compress(rows[:len(rows) // side * (side // 3)])
    out += struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body))
open(d + "/animated cut.png", "wb").write(bytes(out))
im = Image.open(d + "/animated cut.png")
for k in range(im.n_frames): im.seek(k); im.load()          # Pillow takes every frame without an error: that is the case
Image.open(d + "/big cut.png").load()
`, [join(run, "work/s1")], run);
    const whole = await call("qr_read", run, { images: ["work/s1/big.png", "work/s1/animated.png"] }, { out, limitMs: 120_000 });
    assert.equal(whole.doc.status, "complete", whole.stdout.slice(0, 900));
    assert.deepEqual((whole.doc.rows as Doc[]).map((r) => [r.result, r.picture_damaged ?? null]), [["decoded", null], ["decoded", null]]);
    for (const [name, said] of [["big cut", /a PNG whose image data ends after 144003000 of 288006000 bytes/], ["animated cut", /an animated PNG whose frame 1 after the image data \(fdAT\) ends after/]] as const) {
      const r = await call("qr_read", run, { image: `work/s1/${name}.png` }, { out, limitMs: 120_000 });
      assert.equal(r.doc.status, "partial", `${name}: ${r.stdout.slice(0, 900)}`);
      const row = r.doc.rows[0] as Doc;
      assert.equal(row.result, "not a symbol", name);
      assert.match(row.picture_damaged, said, name);
      assert.equal(r.doc.not_read_or_judged.pictures_damaged, 1, name);
      assert.doesNotMatch(r.doc.status_basis, /read whole/, name);
    }
  });
});

test("a TIFF strip or tile of JPEG data cut short and given its end marker back, and an uncompressed strip the file does not hold, are damaged and partial; old-style JPEG is not walked", { skip: pillowHere(ROOT) ? false : "Pillow does not import here: the tool reads no TIFF without it" }, async () => {
  await withRun(async (run, out) => {
    // The symbol is in the bottom half: the cut part of the strip is where the symbol is.
    encode(String.raw`
d = sys.argv[1]
rows = draw(symbol(b"fixture tiff bottom 0042", 2, "M", 3), 4, 4)
w = len(rows[0])
open(d + "/bottom.raw", "wb").write(b"\xff" * (w * len(rows)) + b"".join(rows))
open(d + "/size", "w").write("%d %d" % (w, 2 * len(rows)))
`, [join(run, "work/s1")], run);
    withPillow(TIFF + String.raw`
import sys
from PIL import Image
d = sys.argv[1]; w, h = map(int, open(d + "/size").read().split())
im = Image.frombytes("L", (w, h), open(d + "/bottom.raw", "rb").read())
whole = jpeg(im)
for name, data in (("strip", tiff(w, h, 7, [whole])), ("strip cut", tiff(w, h, 7, [cut(whole)])),
                   ("big", tiff(w, h, 7, [whole], big=True)), ("big cut", tiff(w, h, 7, [cut(whole)], big=True)),
                   ("old style", tiff(w, h, 6, [whole]))):
    open(d + "/" + name + ".tif", "wb").write(data)
# Tiles of 64 x 64, each a JPEG of its own; the last tile (in the symbol) cut.
tw = 64
tiles = [jpeg(im.crop((x, y, x + tw, y + tw))) for y in range(0, h, tw) for x in range(0, w, tw)]
open(d + "/tiles.tif", "wb").write(tiff(w, h, 7, tiles, tiled=(tw, tw)))
open(d + "/tiles cut.tif", "wb").write(tiff(w, h, 7, tiles[:-1] + [cut(tiles[-1], 0.3)], tiled=(tw, tw)))
# Uncompressed strips of 16 rows; one of them is not in the file (offset 0, byte count 0): Pillow reads its rows from the file's start.
data = im.tobytes(); strips = [data[i:i + 16 * w] for i in range(0, len(data), 16 * w)]
open(d + "/raw.tif", "wb").write(tiff(w, h, 1, strips, rps=16))
open(d + "/raw sparse.tif", "wb").write(tiff(w, h, 1, strips, rps=16, zero={len(strips) - 3}))
# Pillow's own writer: several strips of JPEG data with their tables in JPEGTables, two pages; the second page's strip ended early.
im.save(d + "/pillow.tif", compression="jpeg", strip_size=4096)
Image.new("L", (w, h), 255).save(d + "/pages.tif", compression="jpeg", save_all=True, append_images=[im])
pages = bytearray(open(d + "/pages.tif", "rb").read())
two = Image.open(d + "/pages.tif"); two.seek(1)
at = two.tag_v2[273][0]; strip = bytes(pages[at:at + two.tag_v2[279][0]]); sos = strip.index(b"\xff\xda")
pages[at + sos + (len(strip) - sos) // 3:at + sos + (len(strip) - sos) // 3 + 2] = b"\xff\xd9"
open(d + "/pages cut.tif", "wb").write(bytes(pages))
for name in ("strip cut", "big cut", "tiles cut", "raw sparse", "pages cut"):
    t = Image.open(d + "/" + name + ".tif")
    for k in range(getattr(t, "n_frames", 1)): t.seek(k); t.load()     # Pillow takes every page without an error: that is the case
`, [join(run, "work/s1")], run);
    const names = ["strip", "big", "tiles", "raw", "pillow", "pages"];
    const whole = await call("qr_read", run, { images: names.map((n) => `work/s1/${n}.tif`) }, { out, limitMs: 120_000 });
    assert.equal(whole.doc.status, "complete", whole.stdout.slice(0, 1500));
    assert.deepEqual((whole.doc.rows as Doc[]).map((r) => [r.result, r.picture_damaged ?? null, r.jpeg_data_not_walked ?? null]), names.map(() => ["decoded", null, null]));
    for (const [name, said] of [["strip cut", /page 1, strip 1 of JPEG data: scan 1: the coded data ends/], ["big cut", /page 1, strip 1 of JPEG data: scan 1: the coded data ends/],
      ["tiles cut", /page 1, tile \d+ of JPEG data: scan 1: the coded data ends/], ["raw sparse", /page 1, strip \d+ of uncompressed data: its byte count is 0 and its rows need \d+/],
      ["pages cut", /page 2, strip 1 of JPEG data: scan 1: the coded data ends/]] as const) {
      const r = await call("qr_read", run, { image: `work/s1/${name}.tif` }, { out, limitMs: 120_000 });
      assert.equal(r.doc.status, "partial", `${name}: ${r.stdout.slice(0, 900)}`);
      const row = r.doc.rows[0] as Doc;
      assert.match(row.picture_damaged, /^the tool's own walk of the TIFF's strips and tiles found it cut or corrupt/, name);
      assert.match(row.picture_damaged, said, name);
      assert.equal(r.doc.not_read_or_judged.pictures_damaged, 1, name);
    }
    const old = await call("qr_read", run, { image: "work/s1/old style.tif" }, { out });
    if (old.doc.rows?.[0]?.result !== "not read") {
      // libtiff reads old-style JPEG where it was built with it; the tool does not walk it, and says so.
      assert.equal(old.doc.status, "partial", old.stdout.slice(0, 900));
      assert.match(old.doc.rows[0].jpeg_data_not_walked, /^page 1 is coded as old-style JPEG \(TIFF compression 6\)/);
      assert.equal(old.doc.not_read_or_judged.jpeg_data_not_walked, 1);
    }
  });
});
