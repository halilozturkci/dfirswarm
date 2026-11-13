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
import { lstat, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
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
