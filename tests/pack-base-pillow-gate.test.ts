/**
 * computer-forensics-base: the Pillow gate that qr_read and glyph_strip carry (the same code in both), held to its shape.
 *
 * Pillow, and libtiff, libjpeg and zlib under it, fill a picture whose data is cut or zeroed and say nothing to Pillow's caller, so a
 * picture Pillow decoded is complete only when the tool itself saw its data whole. The gate's TIFF rule is an allowlist: a page passes
 * only when its shape is one the tool's walk sees as libtiff and Pillow do; every other shape is counted as not walked. Each case here
 * is one shape that a verification found passed as whole before (a Compression tag named twice, YCbCr through libtiff's RGBA
 * interface, a JPEG strip whose frame is smaller than the strip, strip and tile tags in one directory, a PNG header chunk longer than
 * 13 bytes), each with its whole control, and each run through both tools. The fixtures are drawn here: the symbol by
 * scripts/lib/qrgen.py, the codings by Pillow's own writer, the directories and chunks by this file. The safety net under the walk
 * (the decoding child's standard error read as damage) is held directly: a stand-in for Pillow prints a decoder's line there.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { test } from "node:test";
import { PYTHON3 } from "./host-gates.ts";
import { call, CFB, ROOT, withRun, type Doc } from "./pack-base-media-fixture.ts";

/** Pillow as the tool sees it (the tool runs without -I, so a user site counts). */
const pillowHere = spawnSync(PYTHON3, ["-c", "import PIL.Image"], { cwd: ROOT }).status === 0;
const libtiffHere = spawnSync(PYTHON3, ["-c", "from PIL import features; import sys; sys.exit(0 if features.check_codec('libtiff') else 1)"], { cwd: ROOT }).status === 0;
const SKIP = pillowHere && libtiffHere ? false : "Pillow with libtiff does not import here: the tools read no TIFF without it";

/** A fixture script that needs Pillow (run without -I, as the tool is): its stdout, or a failed assertion. */
function withPillow(code: string, args: string[], cwd: string): string {
  const r = spawnSync(PYTHON3, ["-c", code, ...args], { cwd, encoding: "utf8", maxBuffer: 64 << 20 });
  assert.equal(r.status, 0, `the fixture builder failed: ${r.stderr.slice(-800)}`);
  return r.stdout;
}

/**
 * The fixtures, each written to the directory given, and a JSON report of how Pillow takes each one in a child whose standard error is
 * a pipe: whether it loads, and whether libtiff printed anything while it did.
 */
const BUILD = String.raw`
import io, json, os, struct, sys, zlib
sys.path.insert(0, sys.argv[1])
import qrgen
from PIL import Image
d = sys.argv[2]
mod = qrgen.matrix("fixture pillow gate 0042 / not from any case", 3)
n = len(mod); W = (n + 8) * 8
im = Image.new("L", (W, W), 255); px = im.load()
for r, line in enumerate(mod):
    for c, m in enumerate(line):
        if m:
            for y in range(8):
                for x in range(8):
                    px[(c + 4) * 8 + x, (r + 4) * 8 + y] = 0

def saved(image, **kw):
    b = io.BytesIO(); image.save(b, "TIFF", **kw); return b.getvalue()

def entries(data):
    """The 12-byte entries of a little-endian classic TIFF's first directory."""
    at = struct.unpack("<I", data[4:8])[0]
    count = struct.unpack("<H", data[at:at + 2])[0]
    return [data[at + 2 + 12 * i:at + 14 + 12 * i] for i in range(count)]

def entry(tag, kind, value):
    return struct.pack("<HHIHH", tag, kind, 1, value, 0) if kind == 3 else struct.pack("<HHII", tag, kind, 1, value)

def rewritten(data, ents):
    """The file with a new first directory of these entries appended, the header pointed at it (the old one left as dead bytes)."""
    out = bytearray(data) + (b"\x00" if len(data) % 2 else b"")
    at = len(out)
    out += struct.pack("<H", len(ents)) + b"".join(ents) + b"\x00\x00\x00\x00"
    struct.pack_into("<I", out, 4, at)
    return bytes(out)

def with_twice(data, tag, kind, value):
    """The file with a second entry of the tag, of another value, right after the first (the order of tags is kept)."""
    ents = []
    for e in entries(data):
        ents.append(e)
        if struct.unpack("<H", e[:2])[0] == tag:
            ents.append(entry(tag, kind, value))
    return rewritten(data, ents)

def zeroed(data, keep=3):
    """The file with the last two thirds of its strips' data given back as zeros (sectors not recovered)."""
    t = Image.open(io.BytesIO(data)); offs, cnts = list(t.tag_v2[273]), list(t.tag_v2[279])
    start, end = offs[0], offs[-1] + cnts[-1]
    out = bytearray(data); out[start + (end - start) // keep:end] = bytes(end - start - (end - start) // keep)
    return bytes(out)

def one_strip(strip, height, tags_more=()):
    """An 8-bit grey page of one strip, built by hand: the strip, then its directory."""
    out = bytearray(b"II*\x00\x00\x00\x00\x00"); off = len(out); out += strip
    if len(out) % 2: out += b"\x00"
    tags = [(256, 3, W), (257, 3, height), (258, 3, 8), (259, 3, 7), (262, 3, 1), (273, 4, off), (277, 3, 1), (278, 3, height), (279, 4, len(strip))]
    for tag, kind, value in tags_more:
        tags = [t for t in tags if t[0] != tag] + [(tag, kind, value)]
    tags.sort(key=lambda t: t[0])
    at = len(out); struct.pack_into("<I", out, 4, at)
    out += struct.pack("<H", len(tags)) + b"".join(entry(*t) for t in tags) + b"\x00\x00\x00\x00"
    return bytes(out)

def jpeg(image):
    b = io.BytesIO(); image.save(b, "JPEG", quality=95); return b.getvalue()

def png(header, raw):
    chunk = lambda k, b: struct.pack(">I", len(b)) + k + b + struct.pack(">I", zlib.crc32(k + b) & 0xFFFFFFFF)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header) + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b"")

files = {}
g4 = saved(im.convert("1"), compression="group4")
files["g4 twice whole"] = with_twice(g4, 259, 3, 5)                 # Group 4 by libtiff (the first copy), LZW by Pillow (the last)
files["g4 twice zeroed"] = with_twice(zeroed(g4), 259, 3, 5)
raw = saved(im, compression="raw")
files["raw offsets twice"] = with_twice(raw, 273, 4, 8)            # a second StripOffsets, pointing at the header
for comp, short in (("tiff_lzw", "lzw"), ("tiff_adobe_deflate", "deflate"), ("packbits", "packbits")):
    ycc = saved(im.convert("RGB").convert("YCbCr"), compression=comp)
    files["ycc %s whole" % short] = ycc
    files["ycc %s zeroed" % short] = zeroed(ycc)
rgb = saved(im.convert("RGB"), compression="tiff_lzw")
files["rgb lzw whole"] = rgb
files["rgb lzw zeroed"] = zeroed(rgb)
files["jpeg strip whole"] = one_strip(jpeg(im), W)
files["jpeg strip short"] = one_strip(jpeg(im.crop((0, 0, W, W // 3 // 8 * 8))), W)    # a frame a third of the strip's rows
pix = im.tobytes(); keep = len(pix) // 3
def raw_page(tiles):
    out = bytearray(b"II*\x00\x00\x00\x00\x00"); off = len(out); out += (pix[:keep] + bytes(len(pix) - keep)) if tiles else pix
    tags = [(256, 3, W), (257, 3, W), (258, 3, 8), (259, 3, 1), (262, 3, 1), (273, 4, off), (277, 3, 1), (278, 3, W), (279, 4, keep if tiles else len(pix))]
    if tiles:
        tags += [(322, 3, W), (323, 3, W), (324, 4, off), (325, 4, len(pix))]   # the tiles say the whole page is there; the strip a third
    at = len(out); struct.pack_into("<I", out, 4, at)
    out += struct.pack("<H", len(tags)) + b"".join(entry(*t) for t in tags) + b"\x00\x00\x00\x00"
    return bytes(out)
def strips_page(named):
    """An 8-bit grey page of strips of 8 rows, whose directory names only the first N of them (the rest of the rows are in no strip)."""
    R = 8; pieces = [pix[y * W:(y + R) * W] for y in range(0, W, R)]
    out = bytearray(b"II*\x00\x00\x00\x00\x00"); offs = []
    for piece in pieces[:named]:
        offs.append(len(out)); out += piece
    if len(out) % 2: out += b"\x00"
    where_offs = len(out); out += b"".join(struct.pack("<I", o) for o in offs)
    where_counts = len(out); out += b"".join(struct.pack("<I", len(piece)) for piece in pieces[:named])
    tags = [(256, 3, W), (257, 3, W), (258, 3, 8), (259, 3, 1), (262, 3, 1), (277, 3, 1), (278, 3, R)]
    ents = [entry(*t) for t in tags] + [struct.pack("<HHII", 273, 4, named, where_offs), struct.pack("<HHII", 279, 4, named, where_counts)]
    ents.sort(key=lambda e: struct.unpack("<H", e[:2])[0])
    at = len(out); struct.pack_into("<I", out, 4, at)
    out += struct.pack("<H", len(ents)) + b"".join(ents) + b"\x00\x00\x00\x00"
    return bytes(out)
def planar_page(bits, kind284=3):
    """An RGB page of three planes (one strip each), PlanarConfiguration 2 (of the TIFF type kind284), bits a sample."""
    unit = bits // 8; plane = pix * unit if unit == 1 else b"".join(bytes([p, p]) for p in pix)
    out = bytearray(b"II*\x00\x00\x00\x00\x00"); offs = []
    for _ in range(3):
        offs.append(len(out)); out += plane
    if len(out) % 2: out += b"\x00"
    arrays = {}
    def array(fmt, values):
        at = len(out); out.extend(struct.pack("<" + fmt * len(values), *values)); return at
    depth_at = array("H", [bits] * 3); offs_at = array("I", offs); counts_at = array("I", [len(plane)] * 3)
    ents = [entry(256, 3, W), entry(257, 3, W), struct.pack("<HHII", 258, 3, 3, depth_at), entry(259, 3, 1), entry(262, 3, 2),
            struct.pack("<HHII", 273, 4, 3, offs_at), entry(277, 3, 3), entry(278, 3, W), struct.pack("<HHII", 279, 4, 3, counts_at),
            struct.pack("<HHIHH", 284, kind284, 1, 2, 0)]
    ents.sort(key=lambda e: struct.unpack("<H", e[:2])[0])
    at = len(out); struct.pack_into("<I", out, 4, at)
    out += struct.pack("<H", len(ents)) + b"".join(ents) + b"\x00\x00\x00\x00"
    return bytes(out)
files["planar 8"] = planar_page(8)
files["planar 16"] = planar_page(16)
files["planar tag of type byte"] = planar_page(8, 1) + bytes(3 * W * W)
files["grey 16 bit"] = saved(im.convert("I;16"), compression="raw")      # Pillow clips a 16-bit sample above 255 to 255 when it makes an 8-bit picture
rgba = saved(im.convert("RGBA"), compression="raw")
files["rgb 4 samples no extrasamples"] = rewritten(rgba, [e for e in entries(rgba) if struct.unpack("<H", e[:2])[0] != 338])
dfl = saved(im.convert("RGB"), compression="tiff_adobe_deflate")
files["deflate whole"] = dfl
files["deflate zeroed"] = zeroed(dfl)                                        # libtiff decodes the zero bits of a Huffman block as symbols, in silence
pal = saved(im.convert("P"), compression="raw")
files["palette whole"] = pal
def short_map(data, values):
    """The page with its ColorMap entry claiming that many values: Pillow paints the indices a short map lacks black, libtiff drops the map."""
    ents = []
    for e in entries(data):
        if struct.unpack("<H", e[:2])[0] == 320: e = e[:4] + struct.pack("<I", values) + e[8:]
        ents.append(e)
    return rewritten(data, ents)
files["palette short map"] = short_map(pal, 510)
lzw_pages = saved(im.convert("RGB"), compression="tiff_lzw")
def damaged_middle(data):
    t = Image.open(io.BytesIO(data)); o, c = t.tag_v2[273][0], t.tag_v2[279][0]; out = bytearray(data); mid = o + c // 2
    out[mid:mid + 4] = bytes(4); return bytes(out)
files["lzw damaged in the middle"] = damaged_middle(lzw_pages)
def with_tables(data, tables):
    """The page with a JPEGTables entry (tag 347) pointing at the tables bytes, appended to the file."""
    body = bytes(data) + (b"\x00" if len(data) % 2 else b"")
    at = len(body)
    ents = sorted(entries(data) + [struct.pack("<HHII", 347, 7, len(tables), at)], key=lambda e: struct.unpack("<H", e[:2])[0])
    return rewritten(body + tables, ents)
files["jpeg tables with a restart interval"] = with_tables(files["jpeg strip whole"], b"\xff\xd8\xff\xdd\x00\x04\x00\x01\xff\xd9")
files["strips whole"] = strips_page(W // 8)
files["strips two of many"] = strips_page(2)
files["strips half of many"] = strips_page(W // 16)
files["raw strip whole"] = raw_page(False)
def signed_samples(data):
    """The uncompressed page with SampleFormat 2 (signed) added: Pillow's mode table reads the bytes as unsigned."""
    ents = sorted(entries(data) + [entry(339, 3, 2)], key=lambda e: struct.unpack("<H", e[:2])[0])
    return rewritten(data, ents)
files["sample format signed"] = signed_samples(files["raw strip whole"])
files["raw strip and tiles"] = raw_page(True)
rows = b"".join(b"\x00" + pix[y * W:(y + 1) * W] for y in range(W))
long_header = struct.pack(">IIBBBBB", W, W, 8, 0, 0, 0, 0) + b"\x00"      # 14 bytes: Pillow reads the first 13
files["header 14 whole.png"] = png(long_header, rows)
files["header 14 half.png"] = png(long_header, rows[:len(rows) // 2])  # a zlib stream that ends after half the rows

def taken(data):
    r, w = os.pipe(); pid = os.fork()
    if pid == 0:
        os.dup2(w, 2); os.close(r)
        try:
            i = Image.open(io.BytesIO(data)); i.load(); os.write(1, b"")
            os._exit(0)
        except Exception:
            os._exit(3)
    os.close(w); said = b""
    while True:
        block = os.read(r, 65536)
        if not block: break
        said += block
    os.close(r); _pid, status = os.waitpid(pid, 0)
    return {"loads": os.WEXITSTATUS(status) == 0, "printed": bool(said.strip())}

report = {}
for name, data in files.items():
    path = os.path.join(d, name if name.endswith(".png") else name + ".tif")
    open(path, "wb").write(data)
    report[name] = taken(data)
print(json.dumps(report))
`;

type Seen = { status: string; row: Doc };

/** One picture through qr_read and through glyph_strip: each tool's status and the fields of its answer on the picture. */
async function both(run: string, out: string, file: string): Promise<{ qr: Seen; glyph: Seen }> {
  const q = await call("qr_read", run, { image: `work/s1/${file}` }, { out, limitMs: 60_000 });
  assert.ok(q.doc.status, `qr_read on ${file}: ${q.stdout.slice(0, 600)}${q.stderr.slice(0, 600)}`);
  const g = await call("glyph_strip", run, { image: `work/s1/${file}`, ocr: "none" }, { out, limitMs: 60_000 });
  assert.ok(g.doc.status, `glyph_strip on ${file}: ${g.stdout.slice(0, 600)}${g.stderr.slice(0, 600)}`);
  return { qr: { status: q.doc.status, row: (q.doc.rows?.[0] ?? {}) as Doc }, glyph: { status: g.doc.status, row: g.doc } };
}

test("the Pillow gate passes a TIFF page only in a shape its walk takes: a tag named twice, YCbCr, a short JPEG frame, strip and tile tags together and a long PNG header are never complete; the whole controls are", { skip: SKIP }, async () => {
  await withRun(async (run, out) => {
    const report = JSON.parse(withPillow(BUILD, [join(ROOT, "scripts", "lib"), join(run, "work/s1")], run)) as Record<string, { loads: boolean; printed: boolean }>;
    // Each damaged case is one Pillow takes without an error: that is the case.
    for (const name of ["g4 twice zeroed", "ycc lzw zeroed", "ycc deflate zeroed", "ycc packbits zeroed", "jpeg strip short", "raw strip and tiles", "header 14 half.png", "strips two of many", "strips half of many", "palette short map"]) {
      assert.ok(report[name]!.loads, `Pillow does not load ${name} here, so it is not the case this test holds`);
    }
    const file = (name: string): string => (name.endsWith(".png") ? name : name + ".tif");

    // The whole controls: the shapes the walk takes (LZW in RGB, one JPEG strip of the page's size, an uncompressed strip, a PNG
    // whose header chunk is 14 bytes) are complete in both tools, and Pillow's decoder printed nothing on them.
    for (const name of ["palette whole", "jpeg strip whole", "raw strip whole", "strips whole", "header 14 whole.png"]) {
      assert.equal(report[name]!.printed, false, `${name}: libtiff printed on a whole file`);
      const { qr, glyph } = await both(run, out, file(name));
      assert.equal(qr.status, "complete", `qr_read, ${name}: ${JSON.stringify(qr.row).slice(0, 600)}`);
      assert.equal(qr.row.result, "decoded", name);
      assert.equal(glyph.status, "complete", `glyph_strip, ${name}: ${JSON.stringify(glyph.row).slice(0, 600)}`);
    }

    // A tag named twice (Pillow reads the last copy, libtiff the first): never walked, whole or not.
    for (const [name, tag] of [["g4 twice whole", 259], ["g4 twice zeroed", 259], ["raw offsets twice", 273]] as const) {
      const { qr, glyph } = await both(run, out, file(name));
      for (const [who, seen] of [["qr_read", qr], ["glyph_strip", glyph]] as const) {
        assert.equal(seen.status, "partial", `${who}, ${name}: ${JSON.stringify(seen.row).slice(0, 600)}`);
        if (!seen.row.picture_damaged) assert.match(seen.row.jpeg_data_not_walked, new RegExp(`^page 1 names tag ${tag} more than once in its directory`), `${who}, ${name}`);
      }
    }

    // YCbCr coded with LZW, Deflate or PackBits: Pillow reads it through libtiff's RGBA interface, which fills and only prints. The
    // whole file is not walked; the zeroed one is damaged by what libtiff printed, or (where it printed nothing) not walked either.
    for (const short of ["lzw", "deflate", "packbits"]) {
      for (const state of ["whole", "zeroed"]) {
        const name = `ycc ${short} ${state}`;
        const { qr, glyph } = await both(run, out, file(name));
        for (const [who, seen] of [["qr_read", qr], ["glyph_strip", glyph]] as const) {
          assert.equal(seen.status, "partial", `${who}, ${name}: ${JSON.stringify(seen.row).slice(0, 600)}`);
          if (state === "zeroed" && report[name]!.printed) {
            assert.match(seen.row.picture_damaged, /it printed \d+ line\(s\) on its standard error while it decoded, the first: /, `${who}, ${name}`);
          } else {
            assert.match(seen.row.jpeg_data_not_walked, /is coded with TIFF compression (5|8|32773|32946), whose decoder may fill a cut or damaged strip/, `${who}, ${name}`);
          }
        }
      }
    }

    // LZW and PackBits are not walked: libtiff raises on a cut or zeroed tail, not on a strip damaged in its middle (decoded out of step, in silence).
    {
      // This fixture's damage is one Pillow refuses (the verifier's, a few zeroed bytes in an LZW palette page, decodes silently): never complete.
      const { qr, glyph } = await both(run, out, file("lzw damaged in the middle"));
      assert.notEqual(qr.status, "complete", JSON.stringify(qr.row).slice(0, 600));
      assert.notEqual(glyph.status, "complete", JSON.stringify(glyph.row).slice(0, 600));
    }
    for (const name of ["rgb lzw whole"]) {
      const { qr, glyph } = await both(run, out, file(name));
      for (const [who, seen] of [["qr_read", qr], ["glyph_strip", glyph]] as const) {
        assert.equal(seen.status, "partial", `${who}, ${name}: ${JSON.stringify(seen.row).slice(0, 600)}`);
        assert.match(seen.row.jpeg_data_not_walked, /is coded with TIFF compression 5/, `${who}, ${name}`);
      }
    }

    // A palette page whose ColorMap is short (Pillow paints the indices it lacks black; libtiff drops the map): never complete.
    {
      const { qr, glyph } = await both(run, out, file("palette short map"));
      for (const [who, seen] of [["qr_read", qr], ["glyph_strip", glyph]] as const) {
        assert.equal(seen.status, "partial", `${who}: ${JSON.stringify(seen.row).slice(0, 600)}`);
        assert.match(seen.row.jpeg_data_not_walked, /palette page whose ColorMap holds 510 values where 8-bit samples need 768/, who);
      }
    }

    // LZW in RGB, zeroed: Pillow reads it strip by strip and libtiff fails the read; never complete.
    {
      const { qr, glyph } = await both(run, out, file("rgb lzw zeroed"));
      assert.notEqual(qr.status, "complete", JSON.stringify(qr.row).slice(0, 600));
      assert.notEqual(glyph.status, "complete", JSON.stringify(glyph.row).slice(0, 600));
    }

    // A JPEG strip whose frame is a third of the strip's rows: libtiff leaves the rest unwritten.
    {
      const { qr, glyph } = await both(run, out, file("jpeg strip short"));
      for (const [who, seen] of [["qr_read", qr], ["glyph_strip", glyph]] as const) {
        assert.equal(seen.status, "partial", `${who}: ${JSON.stringify(seen.row).slice(0, 600)}`);
        assert.match(seen.row.picture_damaged, /page 1, strip 1 of JPEG data: its frame is \d+ rows high where the strip is \d+/, who);
      }
    }

    // Strip and tile tags in one directory: Pillow's own decoder reads the strip (a third of the rows), the tiles say the page is whole.
    {
      const { qr, glyph } = await both(run, out, file("raw strip and tiles"));
      for (const [who, seen] of [["qr_read", qr], ["glyph_strip", glyph]] as const) {
        assert.equal(seen.status, "partial", `${who}: ${JSON.stringify(seen.row).slice(0, 600)}`);
        assert.match(seen.row.jpeg_data_not_walked, /^page 1 holds both strip and tile tags/, who);
      }
    }

    // An uncompressed page whose directory names fewer strips than its size needs: Pillow's decoder sets up one tile for each strip named
    // and leaves the rows no strip holds black, with no error and nothing printed.
    for (const name of ["strips two of many", "strips half of many"]) {
      const { qr, glyph } = await both(run, out, file(name));
      for (const [who, seen] of [["qr_read", qr], ["glyph_strip", glyph]] as const) {
        assert.equal(seen.status, "partial", `${who}, ${name}: ${JSON.stringify(seen.row).slice(0, 600)}`);
        assert.match(seen.row.jpeg_data_not_walked, /^an uncompressed page holds \d+ strips where its size needs \d+; the walk does not take it/, `${who}, ${name}`);
      }
    }

    // Separate planes (Pillow takes each plane's mode from one character of the page's, so a plane loses its width, its inversion or its bit
    // order, in silence), signed samples (read as unsigned), and a PlanarConfiguration of the type BYTE (Pillow keeps it as bytes and reads
    // the page as contiguous; the walk reads it as 2): none is walked.
    for (const [name, why] of [["planar 16", /is in separate planes \(PlanarConfiguration 2\)/], ["planar 8", /is in separate planes \(PlanarConfiguration 2\)/], ["sample format signed", /has a SampleFormat other than unsigned integer/],
      ["planar tag of type byte", /tag 284 of page 1 is of the type 1; the walk takes the tags it reads only as SHORT, LONG or LONG8/]] as const) {
      const { qr, glyph } = await both(run, out, file(name));
      for (const [who, seen] of [["qr_read", qr], ["glyph_strip", glyph]] as const) {
        assert.equal(seen.status, "partial", `${who}, ${name}: ${JSON.stringify(seen.row).slice(0, 600)}`);
        assert.match(seen.row.jpeg_data_not_walked, why, `${who}, ${name}`);
      }
    }

    // A 16-bit grey page (clipped to white), four samples of RGB with no ExtraSamples (taken for alpha by Pillow), and Deflate (a zeroed tail
    // decodes as noise): none is walked.
    for (const [name, why] of [["grey 16 bit", /has 1 sample\(s\) of depths 16; the walk takes pages whose samples are all 1, 2, 4 or 8 bits/],
      ["rgb 4 samples no extrasamples", /has 4 sample\(s\) in photometric interpretation 2, which needs 3/],
      ["deflate whole", /is coded with TIFF compression 8/]] as const) {
      const { qr, glyph } = await both(run, out, file(name));
      for (const [who, seen] of [["qr_read", qr], ["glyph_strip", glyph]] as const) {
        assert.equal(seen.status, "partial", `${who}, ${name}: ${JSON.stringify(seen.row).slice(0, 600)}`);
        assert.match(seen.row.jpeg_data_not_walked, why, `${who}, ${name}`);
      }
    }

    // The zeroed Deflate page of this fixture is one Pillow refuses (the verifier's, with a tail that decodes as noise, it does not): never complete.
    {
      const { qr, glyph } = await both(run, out, file("deflate zeroed"));
      assert.notEqual(qr.status, "complete", JSON.stringify(qr.row).slice(0, 600));
      assert.notEqual(glyph.status, "complete", JSON.stringify(glyph.row).slice(0, 600));
    }

    // JPEGTables that hold a restart interval (DRI): the tables are put before each strip's data by the walk, libjpeg resets the interval at the
    // strip's own start of image, so the two read different pictures.
    {
      const { qr, glyph } = await both(run, out, file("jpeg tables with a restart interval"));
      for (const [who, seen] of [["qr_read", qr], ["glyph_strip", glyph]] as const) {
        assert.equal(seen.status, "partial", `${who}: ${JSON.stringify(seen.row).slice(0, 600)}`);
        assert.match(seen.row.jpeg_data_not_walked, /its JPEGTables hold a segment \(marker 0xDD\) other than quantization or Huffman tables/, who);
      }
    }

    // A PNG whose header chunk is 14 bytes (the built-in reader refuses it; Pillow takes it) and whose zlib stream ends after half
    // the rows: its image data is measured all the same.
    {
      const { qr, glyph } = await both(run, out, file("header 14 half.png"));
      for (const [who, seen] of [["qr_read", qr], ["glyph_strip", glyph]] as const) {
        assert.equal(seen.status, "partial", `${who}: ${JSON.stringify(seen.row).slice(0, 600)}`);
        assert.match(seen.row.picture_damaged, /its image data \(IDAT\) inflates to \d+ of the \d+ bytes its rows need/, who);
      }
      assert.equal(qr.row.result, "not a symbol");
    }
  });
});

/**
 * The safety net under the walk, held without libtiff: each tool's file is loaded as a module (it then holds no stop signal and prints
 * nothing), and its PillowFrames is given a stand-in for Pillow whose open() prints a line on standard error, as libtiff does, and
 * then opens the picture with Pillow. A decoder's line makes the frame damaged; libtiff's note on a tag it does not know does not;
 * nothing printed is nothing said.
 */
const NET = String.raw`
import importlib.util, io, json, os, sys, zlib, struct
path, said = sys.argv[1], sys.argv[2].encode()
spec = importlib.util.spec_from_file_location("gate_under_test", path)
tool = importlib.util.module_from_spec(spec); spec.loader.exec_module(tool)
Image = tool.pillow()
class StandIn:
    def __init__(self, line): self.line = line
    def open(self, fp, formats=None):
        if self.line: os.write(2, self.line)
        return Image.open(fp, formats=formats)
    def new(self, *a, **k): return Image.new(*a, **k)
rows = b"".join(b"\x00" + bytes(255 if (x // 4 + y // 4) % 2 else 0 for x in range(32)) for y in range(16))
chunk = lambda k, b: struct.pack(">I", len(b)) + k + b + struct.pack(">I", zlib.crc32(k + b) & 0xFFFFFFFF)
data = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 32, 16, 8, 0, 0, 0, 0)) + chunk(b"IDAT", zlib.compress(rows)) + chunk(b"IEND", b"")
stream = tool.PillowFrames(data, StandIn(said), 1)
try:
    frame = stream.next_frame()
finally:
    stream.close()
print(json.dumps({"damage": frame.damage, "by": frame.damage_by, "size": [frame.width, frame.height]}))
`;

/**
 * The size the decoding child sends is the size after load(): Pillow 12.3 reads an orientation from a TIFF's XMP (tag 700) when there is no
 * Orientation tag and load() then transposes the picture, which swaps its size. Rows cut at the size from before the load were scrambled.
 * Held without Pillow 12.3: a stand-in picture whose size swaps in load().
 */
const SWAP = String.raw`
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("gate_under_test", sys.argv[1])
tool = importlib.util.module_from_spec(spec); spec.loader.exec_module(tool)
class Pic:
    mode, info = "L", {}
    def __init__(self): self.size = (4, 2)
    def load(self): self.size = (2, 4)                      # the transposition made in load()
    def convert(self, mode): return self
    def seek(self, k): raise EOFError
    def tobytes(self): return bytes(range(8))
class StandIn:
    def open(self, fp, formats=None): return Pic()
    def new(self, *a, **k): raise AssertionError("not used")
stream = tool.PillowFrames(b"not read by the stand-in", StandIn(), 1)
try:
    frame = stream.next_frame()
finally:
    stream.close()
print(json.dumps({"size": [frame.width, frame.height], "first_row": list(frame.gray[0])}))
`;

test("the size the decoding child sends is the size after load(), so a picture the load transposes is cut into rows at its new width", { skip: pillowHere ? false : "Pillow does not import here" }, () => {
  for (const tool of ["qr_read", "glyph_strip"]) {
    const r = spawnSync(PYTHON3, ["-c", SWAP, join(ROOT, "packs", "computer-forensics-base", "tools", tool, "run.py")], { encoding: "utf8" });
    assert.equal(r.status, 0, `${tool}: ${r.stderr.slice(-600)}`);
    assert.deepEqual(JSON.parse(r.stdout), { size: [2, 4], first_row: [0, 1] }, tool);
  }
});

test("the safety net: a line a decoder prints on the decoding child's standard error makes the frame damaged; a note on an unknown tag and silence do not", { skip: pillowHere ? false : "Pillow does not import here" }, () => {
  for (const name of ["qr_read", "glyph_strip"]) {
    const run = (line: string): Doc => JSON.parse(withPillow(NET, [join(CFB, "tools", name, "run.py"), line], ROOT)) as Doc;
    const damaged = run("TIFFFillStrip: Read error on strip 3; got 0 bytes, expected 4096.\nZIPDecode: Decoding error at scanline 9.\n");
    assert.deepEqual(damaged.size, [32, 16], name);
    assert.equal(damaged.by, "Pillow's decoder (libtiff, or libjpeg or zlib under it)", name);
    assert.equal(damaged.damage, "frame 1: it printed 2 line(s) on its standard error while it decoded, the first: TIFFFillStrip: Read error on strip 3; got 0 bytes, expected 4096.", name);
    assert.equal(run("TIFFReadDirectory: Warning, Unknown field with tag 50001 (0xc351) encountered.\n").damage, null, name);
    assert.equal(run("").damage, null, name);
  }
});
