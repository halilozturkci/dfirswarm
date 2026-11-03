/**
 * heic_inspect (mobile-forensics): a preview of a HEIC or HEIF original, tied back to the original, with a bounded box walk.
 *
 * The HEIF containers are built here from the box layouts of ISO/IEC 14496-12 (ftyp, meta, hdlr, pitm, iinf/infe, iloc, iref) and ISO/IEC
 * 23008-12 (iprp/ipco/ispe/irot, ipma, the ImageGrid item). They carry no codec data: the walk needs none, and the conversion is a stub
 * `heif-convert` (and a stub `exiftool`) on PATH that records its argv. No real HEIC sample exists on the author's machine; one real
 * run is gated on `heif-convert` being on PATH and records its version.
 *
 * The tool is new in this change: on the base every test fails because the script does not exist.
 */
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { chmod, mkdir, readFile, readdir, stat, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { ROOT, runPy, withCwd } from "./tool-library-harness.ts";

const TOOL = process.env.HEIC_INSPECT ?? join(ROOT, "packs", "mobile-forensics", "tools", "heic_inspect", "run.py");
const AGENT = { AGENT_ID: "s1" };

type Run = { code: number | null; stdout: string; stderr: string };
type Answer = {
  status: string; status_basis: string; error?: string; interrupted?: string; observations: string[];
  original: { bytes: number; sha256: string | null; brands: { major: string; minor_version: number; compatible: string[] } | null; brand_read: boolean; walk: Walk };
  metadata: { status: string; tags?: number; groups?: Record<string, number>; has_gps_tags?: boolean; has_exif?: boolean; values?: string; reason?: string };
  preview: { status: string; path?: string; bytes?: number; sha256?: string; width?: number; height?: number; backend: string; reason?: string; earlier_file_kept?: string; format?: string } | null;
  conversion: { backend: string; exit_code: number | null; ended: string | null; files_produced: number; errors: string; quality: unknown } | null;
  values_file: { requested: boolean; written: number; file: string | null };
  boxes: { box?: string; problem?: string; offset: number; size?: number; depth?: number }[]; box_rows: number;
  problems: { problem: string; offset: number; note: string }[]; problem_count: number;
  pages: { boxes: { rows: number; all_results: string; truncated: boolean } }; truncated: boolean;
};
type Walk = {
  brands: { major: string } | null; handler: string | null; top_level_boxes: string[]; top_level_box_count: number;
  primary: { item_id: number; type: string | null; width: number | null; height: number | null; rotation_degrees: number; grid?: { rows: number; columns: number; output_width: number; output_height: number; tiles_referenced: number }; position_among_visible_images: number | null } | null;
  items_declared: number | null; items_listed: number; image_items: number; visible_image_items: number; hidden_image_items: number;
  item_types: Record<string, number>; properties: number; references: Record<string, number>; extents_beyond_file: number; extents_overlapping: number;
  boxes_walked: number; boxes_not_entered: number; walk_truncated_at_max_boxes: boolean; problems: number;
};

// --- ISO base media file boxes, from the specification's layouts ---------------------------------------------------------------

const u16 = (n: number): Buffer => { const b = Buffer.alloc(2); b.writeUInt16BE(n); return b; };
const u32 = (n: number): Buffer => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; };
const cc = (s: string): Buffer => Buffer.from(s, "latin1");
function box(type: string, ...parts: Buffer[]): Buffer {
  const payload = Buffer.concat(parts);
  return Buffer.concat([u32(8 + payload.length), cc(type), payload]);
}
function full(type: string, version: number, flags: number, ...parts: Buffer[]): Buffer {
  return box(type, Buffer.from([version, (flags >> 16) & 255, (flags >> 8) & 255, flags & 255]), ...parts);
}
const ftyp = (major = "heic", compat = ["mif1", "heic"]): Buffer => box("ftyp", cc(major), u32(0), ...compat.map(cc));
const hdlr = (type = "pict"): Buffer => full("hdlr", 0, 0, u32(0), cc(type), Buffer.alloc(12), Buffer.from([0]));
const pitm = (id: number): Buffer => full("pitm", 0, 0, u16(id));
const infe = (id: number, type: string, hidden = false): Buffer => full("infe", 2, hidden ? 1 : 0, u16(id), u16(0), cc(type), Buffer.from([0]));
const iinf = (...entries: Buffer[]): Buffer => full("iinf", 0, 0, u16(entries.length), ...entries);
/** iloc v0: offset_size 4, length_size 4, base_offset_size 0; each item has one extent. */
function iloc(items: { id: number; offset: number; length: number }[]): Buffer {
  return full("iloc", 0, 0, Buffer.from([0x44, 0x00]), u16(items.length),
    ...items.map((i) => Buffer.concat([u16(i.id), u16(0), u16(1), u32(i.offset), u32(i.length)])));
}
const ispe = (w: number, h: number): Buffer => full("ispe", 0, 0, u32(w), u32(h));
const irot = (angle: number): Buffer => box("irot", Buffer.from([angle]));
/** ipma v0 (flags 0): item_ID u16, association_count u8, one byte per association (essential bit 7, index 1..127). */
function ipma(assoc: { id: number; props: number[] }[]): Buffer {
  return full("ipma", 0, 0, u32(assoc.length), ...assoc.map((a) => Buffer.concat([u16(a.id), Buffer.from([a.props.length]), Buffer.from(a.props)])));
}
const iprp = (props: Buffer[], assoc: Buffer): Buffer => box("iprp", box("ipco", ...props), assoc);
const iref = (type: string, from: number, to: number[]): Buffer => full("iref", 0, 0, box(type, u16(from), u16(to.length), ...to.map(u16)));

/** A one-image HEIC: item 1 (hvc1), 4032 x 3024, rotated 90 degrees, its data in mdat. */
function simpleHeic(opts: { width?: number; height?: number; rotate?: number; noIspe?: boolean; extra?: Buffer[] } = {}): Buffer {
  const data = Buffer.from("not codec data, the walk does not read it");
  const build = (dataOffset: number): Buffer => Buffer.concat([
    ftyp(),
    full("meta", 0, 0, hdlr(), pitm(1), iinf(infe(1, "hvc1")), iloc([{ id: 1, offset: dataOffset, length: data.length }]),
      iprp(opts.noIspe ? [irot(opts.rotate ?? 0)] : [ispe(opts.width ?? 4032, opts.height ?? 3024), irot(opts.rotate ?? 1)], ipma([{ id: 1, props: opts.noIspe ? [0x81] : [0x81, 0x82] }])),
      ...(opts.extra ?? [])),
    box("mdat", data),
  ]);
  const first = build(0);
  const at = first.length - data.length;       // mdat's payload starts where the data does
  return build(at);
}

/** A grid HEIC: item 1 is a 2 x 2 grid of 512-pixel tiles (items 2 to 5, hidden), 1024 x 1024 in all; item 6 is a thumbnail. */
function gridHeic(): Buffer {
  const grid = Buffer.from([0, 0, 1, 1, 0x04, 0x00, 0x04, 0x00]);     // version 0, flags 0, rows-1, columns-1, output 1024 x 1024 (16-bit fields)
  const tile = Buffer.alloc(16, 1);
  const build = (gridAt: number): Buffer => Buffer.concat([
    ftyp("heic", ["mif1", "heic", "msf1"]),
    full("meta", 0, 0, hdlr(), pitm(1),
      iinf(infe(1, "grid"), infe(2, "hvc1", true), infe(3, "hvc1", true), infe(4, "hvc1", true), infe(5, "hvc1", true), infe(6, "hvc1", false)),
      iloc([{ id: 1, offset: gridAt, length: grid.length }, ...[2, 3, 4, 5, 6].map((id, i) => ({ id, offset: gridAt + 8 + i * 16, length: 16 }))]),
      iprp([ispe(1024, 1024), ispe(512, 512), ispe(160, 160)], ipma([{ id: 1, props: [1] }, { id: 2, props: [2] }, { id: 3, props: [2] }, { id: 4, props: [2] }, { id: 5, props: [2] }, { id: 6, props: [3] }])),
      iref("dimg", 1, [2, 3, 4, 5]), iref("thmb", 6, [1])).subarray(0),
    box("mdat", grid, tile, tile, tile, tile, tile),
  ]);
  const first = build(0);
  return build(first.length - (grid.length + 5 * 16));
}

// --- running the tool -------------------------------------------------------------------------------------------------------------

function run(cwd: string, args: unknown, env: Record<string, string> = {}, bin?: string): Promise<Run> {
  return runPy(TOOL, cwd, args, bin, { ...AGENT, ...env });
}
async function asJob(cwd: string, args: unknown, name = "out", job = "j-1", secret = true, bin?: string): Promise<Run> {
  await mkdir(join(cwd, name), { recursive: true });
  return run(cwd, args, { JOB_ID: job, OUT: join(cwd, name), ...(secret ? { SECRET_OUTPUT: "1" } : {}) }, bin);
}
function body(out: Run): Answer {
  assert.doesNotMatch(out.stderr, /Traceback/);
  assert.ok(out.code === 0, out.stderr + out.stdout);
  return JSON.parse(out.stdout) as Answer;
}
function failed(out: Run): Answer {
  assert.notEqual(out.code, 0, out.stdout);
  assert.doesNotMatch(out.stderr, /Traceback/);
  return JSON.parse(out.stdout) as Answer;
}
async function walkDir(dir: string): Promise<string[]> {
  const out: string[] = [];
  for (const e of await readdir(dir, { withFileTypes: true }).catch(() => [])) {
    const p = join(dir, e.name);
    if (e.isDirectory()) out.push(...(await walkDir(p)));
    else out.push(p);
  }
  return out.sort();
}
async function file(cwd: string, name: string, data: Buffer): Promise<string> {
  const p = join(cwd, "work", name);
  await mkdir(join(cwd, "work"), { recursive: true });
  await writeFile(p, data);
  return p;
}

/** A JPEG with a SOF0 header of the given size, the way a decoder writes one (SOI, APP0, SOF0, EOI): enough for the tool to read the size. */
function jpeg(w: number, h: number, pad = 0): Buffer {
  const sof = Buffer.concat([Buffer.from([0xff, 0xc0, 0x00, 0x0b, 0x08]), u16(h), u16(w), Buffer.from([0x01, 0x01, 0x11, 0x00])]);
  return Buffer.concat([Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x04, 0x00, 0x00]), sof, Buffer.alloc(pad, 7), Buffer.from([0xff, 0xd9])]);
}

/** A stub `heif-convert` that records its argv (one per line, NUL-free) and the working directory, and writes a JPEG of the given size where it is told. */
async function stubConvert(bin: string, w: number, h: number, extra = "", count = 1): Promise<void> {
  const jpg = join(bin, "stub.jpg");
  await writeFile(jpg, jpeg(w, h, 50));
  const script = `#!/bin/sh
printf '%s\\n' "$@" > "${bin}/convert-argv.txt"
pwd > "${bin}/convert-cwd.txt"
echo "$$" > "${bin}/convert-pid.txt"
n=$(cat "${bin}/convert-count.txt" 2>/dev/null || echo 0); n=$((n+1)); echo $n > "${bin}/convert-count.txt"
${extra}
for a in "$@"; do out="$a"; done
if [ ${count} -le 1 ]; then cp "${jpg}" "$out"; else base="\${out%.*}"; ext="\${out##*.}"; i=1; while [ $i -le ${count} ]; do cp "${jpg}" "\${base}-$i.$ext"; i=$((i+1)); done; fi
`;
  await writeFile(join(bin, "heif-convert"), script);
  await chmod(join(bin, "heif-convert"), 0o755);
}

/** A stub `exiftool` that records its argv and prints JSON for the file it is given: one set of tags for a path that ends in .heic, another for a preview. */
async function stubExiftool(bin: string, canaries: Record<string, string>): Promise<void> {
  const original = JSON.stringify([{ SourceFile: "x", "EXIF:Make": canaries.make, "EXIF:SerialNumber": canaries.serial, "GPS:GPSLatitude": canaries.lat, "GPS:GPSLongitude": canaries.lon, "XMP-dc:Creator": canaries.who, "File:FileType": "HEIC" }]);
  const preview = JSON.stringify([{ SourceFile: "x", "EXIF:Make": "PREVIEW-MAKE-DIFFERENT", "EXIF:SerialNumber": "PREVIEW-SERIAL-DIFFERENT" }]);
  await writeFile(join(bin, "exiftool"), `#!/bin/sh
printf '%s\\n' "$@" >> "${bin}/exiftool-argv.txt"
for a in "$@"; do last="$a"; done
case "$last" in
  *.heic) cat <<'JSON'
${original}
JSON
  ;;
  *) cat <<'JSON'
${preview}
JSON
  ;;
esac
`);
  await chmod(join(bin, "exiftool"), 0o755);
}

const CANARIES = { make: "CanaryMakeQ7f3", serial: "SN-CANARY-81hD2", lat: "41.0123456 N canary", lon: "29.9876543 E canary", who: "Canary Person Zk9" };

// --- the box walk -------------------------------------------------------------------------------------------------------------------

test("it walks a HEIC's boxes without a decoder: brands, handler, primary item, size, rotation, items, locations", async () => {
  await withCwd(async (cwd) => {
    const original = await file(cwd, "photo.heic", simpleHeic());
    const answer = body(await run(cwd, { path: original, convert: false }));
    const w = answer.original.walk;
    assert.equal(answer.original.brands!.major, "heic");
    assert.deepEqual(answer.original.brands!.compatible, ["mif1", "heic"]);
    assert.equal(answer.original.brand_read, true);
    assert.equal(w.handler, "pict");
    assert.deepEqual(w.top_level_boxes, ["ftyp", "meta", "mdat"]);
    assert.equal(w.primary!.item_id, 1);
    assert.equal(w.primary!.type, "hvc1");
    assert.equal(w.primary!.width, 4032);
    assert.equal(w.primary!.height, 3024);
    assert.equal(w.primary!.rotation_degrees, 90);
    assert.equal(w.image_items, 1);
    assert.equal(w.visible_image_items, 1);
    assert.equal(w.items_declared, 1);
    assert.equal(w.extents_beyond_file, 0);
    assert.equal(w.problems, 0);
    // The identity of the original is its size and SHA-256, computed from the bytes.
    const bytes = await readFile(original);
    assert.equal(answer.original.bytes, bytes.length);
    const { createHash } = await import("node:crypto");
    assert.equal(answer.original.sha256, createHash("sha256").update(bytes).digest("hex"));
    // Every box is a line of the result file the answer names.
    const lines = (await readFile(join(cwd, answer.pages.boxes.all_results), "utf8")).split("\n").filter(Boolean);
    assert.equal(lines.length, answer.box_rows);
    assert.ok(lines.map((l) => JSON.parse(l) as { box?: string }).some((r) => r.box === "ispe"), "ispe is among the boxes");
  });
});

test("a grid image: rows, columns and output size from the item's own data, the tiles from dimg, hidden tiles apart from the visible image", async () => {
  await withCwd(async (cwd) => {
    const answer = body(await run(cwd, { path: await file(cwd, "grid.heic", gridHeic()), convert: false }));
    const w = answer.original.walk;
    assert.equal(w.primary!.type, "grid");
    assert.deepEqual(w.primary!.grid, { rows: 2, columns: 2, output_width: 1024, output_height: 1024, tiles_referenced: 4, version: 0 });
    assert.equal(w.image_items, 6);
    assert.equal(w.visible_image_items, 2);
    assert.equal(w.hidden_image_items, 4);
    assert.equal(w.references.dimg, 4);
    assert.equal(w.references.thmb, 1);
    assert.deepEqual(w.item_types, { grid: 1, hvc1: 5 });
    assert.equal(w.primary!.position_among_visible_images, 1);
    assert.deepEqual(answer.original.brands!.major, "heic");
  });
});

test("hostile boxes are bounded and reported with their offsets: size 0, past the file, below the header, huge counts, overlapping and outside extents", async () => {
  await withCwd(async (cwd) => {
    const simple = simpleHeic();
    // A last box of size 0 runs to the end of the file, and is said.
    const zero = Buffer.concat([simple, Buffer.concat([u32(0), cc("zzzz"), Buffer.from("tail")])]);
    const z = body(await run(cwd, { path: await file(cwd, "zero.heic", zero), convert: false }));
    assert.ok(z.boxes.some((b) => b.box === "zzzz"), "the box of size 0 is walked");
    assert.equal(z.problem_count, 0);
    // A box that declares more than the file holds is clipped and reported.
    const past = Buffer.concat([simple, u32(0x7fffffff), cc("big!"), Buffer.alloc(10)]);
    const p = body(await run(cwd, { path: await file(cwd, "past.heic", past), convert: false }));
    assert.ok(p.problems.some((x) => x.problem === "size_past_parent" && x.offset === simple.length), JSON.stringify(p.problems));
    assert.equal(p.status, "partial");
    // A box smaller than its header: the walk of the level stops, and says so.
    const small = Buffer.concat([simple, u32(4), cc("tiny"), Buffer.alloc(8)]);
    const s = body(await run(cwd, { path: await file(cwd, "small.heic", small), convert: false }));
    assert.ok(s.problems.some((x) => x.problem === "size_below_header"), JSON.stringify(s.problems));
    // A 64-bit size that is not possible.
    const huge = Buffer.concat([simple, u32(1), cc("huge"), Buffer.from([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff])]);
    const h = body(await run(cwd, { path: await file(cwd, "huge.heic", huge), convert: false }));
    assert.ok(h.problems.some((x) => x.problem === "size_past_parent"));
    // iinf declares 60,000 entries in a box of a few bytes; iloc declares 4 billion items; ipma 4 billion entries.
    const lies = Buffer.concat([
      ftyp(),
      full("meta", 0, 0, hdlr(), pitm(1), full("iinf", 0, 0, u16(60000), infe(1, "hvc1")),
        full("iloc", 2, 0, Buffer.from([0x44, 0x00]), u32(0xffffffff), u32(1), u16(0), u16(1), u32(0), u32(4)),
        iprp([ispe(10, 10)], full("ipma", 1, 0, u32(0xffffffff), u32(1), Buffer.from([1, 1])))),
    ]);
    const l = body(await run(cwd, { path: await file(cwd, "lies.heic", lies), convert: false }));
    assert.ok(l.problems.filter((x) => x.problem === "count_beyond_box").length >= 3, JSON.stringify(l.problems.map((x) => x.problem)));
    // Extents outside the file and extents of two items that overlap.
    const data = Buffer.alloc(64, 5);
    const bad = Buffer.concat([
      ftyp(),
      full("meta", 0, 0, hdlr(), pitm(1), iinf(infe(1, "hvc1"), infe(2, "hvc1")),
        iloc([{ id: 1, offset: 1000000, length: 100 }, { id: 2, offset: 0, length: 100000 }]),
        iprp([ispe(10, 10)], ipma([{ id: 1, props: [1] }]))),
      box("mdat", data),
    ]);
    const b = body(await run(cwd, { path: await file(cwd, "extents.heic", bad), convert: false }));
    assert.equal(b.original.walk.extents_beyond_file, 2, JSON.stringify(b.problems));
    const ov = Buffer.concat([ftyp(), full("meta", 0, 0, hdlr(), pitm(1), iinf(infe(1, "hvc1"), infe(2, "hvc1")),
      iloc([{ id: 1, offset: 20, length: 30 }, { id: 2, offset: 40, length: 30 }]), iprp([ispe(10, 10)], ipma([{ id: 1, props: [1] }]))), box("mdat", data)]);
    const o = body(await run(cwd, { path: await file(cwd, "overlap.heic", ov), convert: false }));
    assert.equal(o.original.walk.extents_overlapping, 1, JSON.stringify(o.problems));
  });
});

test("deep nesting and a very long box list are bounded: the walk enters only the boxes a HEIF reader needs, and stops at 20,000 boxes saying so", async () => {
  await withCwd(async (cwd) => {
    let nested = box("meta", Buffer.alloc(4), box("meta", Buffer.alloc(4)));
    for (let i = 0; i < 2000; i++) nested = box("moov", nested);          // 2,000 levels of containers
    const deep = body(await run(cwd, { path: await file(cwd, "deep.heic", Buffer.concat([ftyp(), nested])), convert: false }));
    assert.ok(deep.original.walk.top_level_box_count <= 3);
    assert.ok(deep.box_rows < 50, `${deep.box_rows} rows for a nest the walk does not enter`);
    const many = Buffer.concat([ftyp(), ...Array.from({ length: 30000 }, () => box("free"))]);
    const m = body(await run(cwd, { path: await file(cwd, "many.heic", many), convert: false }));
    assert.equal(m.original.walk.walk_truncated_at_max_boxes, true);
    assert.equal(m.original.walk.boxes_walked, 20000);
    assert.equal(m.status, "partial");
    assert.match(m.status_basis, /stopped at 20000 boxes/);
    assert.equal(m.box_rows, 20001, "the 20,000 boxes and the problem that says the walk stopped are all in the result file");
  });
});

test("a fuzz of 400 mutated containers always ends with JSON, a bounded walk and no traceback", async () => {
  // At most 1,000 cases on the box walk: seeded byte flips, truncations and length rewrites of a valid file.
  await withCwd(async (cwd) => {
    const seeds = [simpleHeic(), gridHeic()];
    let x = 99;
    const next = (n: number): number => { x = (Math.imul(x, 1103515245) + 12345) >>> 0; return x % n; };
    for (let i = 0; i < 400; i++) {
      const b = Buffer.from(seeds[i % 2]);
      const kind = next(4);
      if (kind === 0) for (let k = 0; k < 1 + next(6); k++) b[next(b.length)] = next(256);
      else if (kind === 1) b.writeUInt32BE(next(2) ? 0 : next(0xffffffff), 4 * next(Math.floor(b.length / 4)));
      else if (kind === 2) { const t = Math.max(12, next(b.length)); b.fill(0, t); }
      else for (let k = 0; k < 3; k++) b.writeUInt16BE(next(65536), 2 * next(Math.floor(b.length / 2)));
      b.write("ftyp", 4, "latin1");
      const r = await run(cwd, { path: await file(cwd, `fuzz${i}.heic`, b), convert: false, max_seconds: 20 });
      assert.doesNotMatch(r.stderr, /Traceback/, `case ${i}`);
      const a = JSON.parse(r.stdout) as Answer;
      assert.ok(["complete", "partial", "failed"].includes(a.status), `case ${i}: ${r.stdout.slice(0, 200)}`);
      if (a.status !== "failed") assert.ok(a.original.walk.boxes_walked <= 20000);
    }
  });
});

test("a file that is not a HEIF container, a FIFO, a link, a directory and a missing path are refused as JSON", async () => {
  await withCwd(async (cwd) => {
    const png = await file(cwd, "pic.png", Buffer.concat([Buffer.from([0x89]), cc("PNG\r\n\x1a\n"), Buffer.alloc(64)]));
    assert.match(failed(await run(cwd, { path: png })).error!, /no 'ftyp' box at offset 4/);
    const fifo = join(cwd, "work", "pipe.heic");
    assert.equal(spawnSync("mkfifo", [fifo]).status, 0);
    const began = Date.now();
    assert.match(failed(await run(cwd, { path: fifo })).error!, /not a regular file/);
    assert.ok(Date.now() - began < 10000, "a FIFO does not hold the tool");
    const real = await file(cwd, "real.heic", simpleHeic());
    await symlink(real, join(cwd, "work", "link.heic"));
    assert.match(failed(await run(cwd, { path: join(cwd, "work", "link.heic") })).error!, /symbolic link/);
    assert.match(failed(await run(cwd, { path: join(cwd, "work") })).error!, /not a regular file/);
    assert.match(failed(await run(cwd, { path: join(cwd, "nothing.heic") })).error!, /no such file/);
    assert.match(failed(await run(cwd, { path: real, password: "x" })).error!, /no such argument/);
    assert.match(failed(await run(cwd, { path: real, format: "gif" })).error!, /format must be/);
    assert.match(failed(await run(cwd, { path: real, backend: "imagemagick" })).error!, /backend must be/);
  });
});

// --- the conversion ---------------------------------------------------------------------------------------------------------------

test("a preview from heif-convert: the identity of the original and the derivative, the backend and its settings recorded, one program with no shell", async () => {
  await withCwd(async (cwd, bin) => {
    await stubConvert(bin, 4032, 3024);
    await stubExiftool(bin, CANARIES);
    const original = await file(cwd, "photo.heic", simpleHeic());
    const answer = body(await asJob(cwd, { path: original, quality: 80 }, "out", "j-1", false, bin));
    assert.equal(answer.status, "complete", answer.status_basis);
    assert.equal(answer.preview!.status, "written");
    assert.equal(answer.preview!.backend, "heif-convert");
    assert.equal(answer.preview!.format, "jpeg");
    assert.equal(answer.preview!.width, 4032);
    assert.equal(answer.preview!.height, 3024);
    const previewPath = join(cwd, "out", answer.preview!.path!.split("/out/")[1]);
    const bytes = await readFile(previewPath);
    assert.equal(answer.preview!.bytes, bytes.length);
    const { createHash } = await import("node:crypto");
    assert.equal(answer.preview!.sha256, createHash("sha256").update(bytes).digest("hex"));
    assert.notEqual(answer.preview!.sha256, answer.original.sha256);
    assert.equal(answer.conversion!.exit_code, 0);
    assert.equal(answer.conversion!.quality, 80);
    const argv = (await readFile(join(bin, "convert-argv.txt"), "utf8")).trim().split("\n");
    assert.deepEqual(argv.slice(0, 2), ["-q", "80"]);
    assert.equal(argv[2], original, "the original is named by its absolute path");
    assert.match(argv[3], /\/\.work-[^/]+\/out\.jpg$/);
    assert.equal(argv.length, 4);
    // Nothing is left in the work directory, and the original is untouched.
    assert.deepEqual((await walkDir(join(cwd, "out"))).filter((p) => p.includes("/.work-")), []);
    assert.deepEqual(await readFile(original), simpleHeic());
  });
});

test("there is no silent fallback: with the chosen backend missing the walk and the metadata are still given, and the answer is partial", async () => {
  await withCwd(async (cwd, bin) => {
    await stubExiftool(bin, CANARIES);
    const answer = body(await run(cwd, { path: await file(cwd, "photo.heic", simpleHeic()) }, {}, bin));
    assert.equal(answer.status, "partial");
    assert.equal(answer.preview!.status, "refused");
    assert.match(answer.preview!.reason!, /heif-convert is not on PATH.*no other backend is tried/);
    assert.equal(answer.original.walk.primary!.width, 4032);
    assert.equal(answer.metadata.status, "ok");
  });
});

test("the decompression-bomb guard refuses before any backend is started: pixels, size, and an original that declares no size", async () => {
  await withCwd(async (cwd, bin) => {
    await stubConvert(bin, 10, 10);
    await stubExiftool(bin, CANARIES);
    const big = await file(cwd, "bomb.heic", simpleHeic({ width: 60000, height: 60000 }));
    const a = body(await run(cwd, { path: big }, {}, bin));
    assert.equal(a.preview!.status, "refused");
    assert.match(a.preview!.reason!, /over max_pixels/);
    const smallLimit = body(await run(cwd, { path: await file(cwd, "ok.heic", simpleHeic()), max_pixels: 1000 }, {}, bin));
    assert.match(smallLimit.preview!.reason!, /declares 4032 x 3024 pixels.*over max_pixels \(1000\)/);
    const bytesLimit = body(await run(cwd, { path: await file(cwd, "ok2.heic", simpleHeic()), max_bytes: 10 }, {}, bin));
    assert.match(bytesLimit.preview!.reason!, /over max_bytes \(10\)/);
    const noSize = body(await run(cwd, { path: await file(cwd, "nosize.heic", simpleHeic({ noIspe: true })) }, {}, bin));
    assert.match(noSize.preview!.reason!, /does not declare the primary image's size/);
    const wrapped = body(await run(cwd, { path: await file(cwd, "wrap.heic", simpleHeic({ width: 0xffffffff, height: 0xffffffff })) }, {}, bin));
    assert.match(wrapped.preview!.reason!, /over max_pixels/, "the product is not computed in 32 bits");
    assert.equal(await stat(join(bin, "convert-argv.txt")).then(() => true, () => false), false, "the backend was never started");
  });
});

test("the metadata is the original's, from exiftool, and the answer carries presence and counts but no value; the preview's metadata is never read", async () => {
  await withCwd(async (cwd, bin) => {
    await stubConvert(bin, 4032, 3024);
    await stubExiftool(bin, CANARIES);
    const original = await file(cwd, "photo.heic", simpleHeic());
    const r = await asJob(cwd, { path: original }, "out", "j-1", false, bin);
    const answer = body(r);
    assert.equal(answer.metadata.status, "ok");
    assert.equal(answer.metadata.tags, 6);
    assert.equal(answer.metadata.has_gps_tags, true);
    assert.equal(answer.metadata.has_exif, true);
    const all = [r.stdout, r.stderr, ...(await Promise.all((await walkDir(join(cwd, "out"))).filter((p) => !p.endsWith(".jpg")).map((p) => readFile(p, "utf8"))))].join("\n");
    for (const v of Object.values(CANARIES)) assert.ok(!all.includes(v), `a value reached a channel: ${v.slice(0, 6)}`);
    assert.ok(!all.includes("PREVIEW-MAKE-DIFFERENT"), "the preview's metadata did not stand in");
    // exiftool was run once, on the original, and never on the preview.
    const calls = (await readFile(join(bin, "exiftool-argv.txt"), "utf8")).trim().split("\n");
    assert.equal(calls[calls.length - 1], original);
    assert.equal(calls.filter((c) => c.endsWith(".jpg")).length, 0);
    // The groups are families exiftool defines; the file's own namespace text is not echoed.
    assert.deepEqual(Object.keys(answer.metadata.groups!).sort(), ["EXIF", "File", "GPS", "XMP"]);
  });
});

test("write_values: the values are written only in a secret-output job, to a 0600 file, and the request is refused as JSON before anything is made otherwise", async () => {
  await withCwd(async (cwd, bin) => {
    await stubExiftool(bin, CANARIES);
    const original = await file(cwd, "photo.heic", simpleHeic());
    const outside = failed(await run(cwd, { path: original, write_values: true, convert: false }, {}, bin));
    assert.match(outside.error!, /write_values is refused outside a job/);
    assert.deepEqual(await readdir(join(cwd, "work")), ["photo.heic"]);
    const notSecret = failed(await asJob(cwd, { path: original, write_values: true, convert: false }, "out", "j-2", false, bin));
    assert.match(notSecret.error!, /SECRET_OUTPUT is not 1/);
    assert.deepEqual(await readdir(join(cwd, "out")), []);
    const r = await asJob(cwd, { path: original, write_values: true, convert: false }, "out3", "j-3", true, bin);
    const answer = body(r);
    assert.equal(answer.values_file.written, 6);
    const values = join(cwd, "out3", "heic-inspect-values.jsonl");
    assert.equal((await stat(values)).mode & 0o777, 0o600);
    const text = await readFile(values, "utf8");
    for (const v of Object.values(CANARIES)) assert.ok(text.includes(v), `${v} is in the values file`);
    assert.ok(!r.stdout.includes(CANARIES.serial) && !r.stderr.includes(CANARIES.serial));
    // A second run in the same OUT takes the next name and replaces nothing.
    await asJob(cwd, { path: original, write_values: true, convert: false }, "out3", "j-3", true, bin);
    assert.ok((await readdir(join(cwd, "out3"))).includes("heic-inspect-values-2.jsonl"));
  });
});

test("a derivative never overwrites: the same preview is named again, a different one takes -2 and the earlier is kept", async () => {
  await withCwd(async (cwd, bin) => {
    await stubExiftool(bin, CANARIES);
    const original = await file(cwd, "photo.heic", simpleHeic());
    await stubConvert(bin, 4032, 3024);
    const first = body(await asJob(cwd, { path: original }, "out", "j-1", false, bin));
    const again = body(await asJob(cwd, { path: original }, "out", "j-1", false, bin));
    assert.equal(again.preview!.path, first.preview!.path, "an identical preview is named again");
    const before = await readFile(join(cwd, "out", first.preview!.path!.split("/out/")[1]));
    // The stub now writes a different, smaller picture.
    await writeFile(join(bin, "stub.jpg"), jpeg(4032, 3024, 0));
    const third = body(await asJob(cwd, { path: original }, "out", "j-1", false, bin));
    assert.notEqual(third.preview!.path, first.preview!.path);
    assert.match(third.preview!.path!, /-2\.jpg$/);
    assert.equal(third.preview!.earlier_file_kept, first.preview!.path);
    assert.deepEqual(await readFile(join(cwd, "out", first.preview!.path!.split("/out/")[1])), before);
  });
});

test("several images in the file: the one asked for is kept, the primary by default, and a primary that cannot be matched is said", async () => {
  await withCwd(async (cwd, bin) => {
    await stubExiftool(bin, CANARIES);
    await stubConvert(bin, 1024, 1024, "", 2);
    const grid = await file(cwd, "grid.heic", gridHeic());
    const second = body(await asJob(cwd, { path: grid, image: 2 }, "out", "j-1", false, bin));
    assert.equal(second.preview!.status, "written", JSON.stringify([second.preview, second.conversion]));
    assert.match(second.preview!.path!, /-img2\.jpg$/);
    assert.equal(second.conversion!.files_produced, 2);
    const primary = body(await asJob(cwd, { path: grid }, "out2", "j-1", false, bin));
    assert.equal(primary.preview!.status, "written", JSON.stringify(primary.preview));
    // Three images written for a file with two visible ones: the primary cannot be matched.
    await stubConvert(bin, 1024, 1024, "", 3);
    const lost = body(await asJob(cwd, { path: grid }, "out3", "j-1", false, bin));
    assert.equal(lost.preview!.status, "failed");
    assert.match(lost.preview!.reason!, /could not be matched/);
    assert.equal(lost.status, "partial");
  });
});

test("a backend that hangs is ended at the deadline with everything it started; a backend that floods is ended at the output cap", async () => {
  await withCwd(async (cwd, bin) => {
    await stubExiftool(bin, CANARIES);
    await stubConvert(bin, 10, 10, `sleep 300 &\necho $! > "${bin}/convert-child.txt"\nsleep 300`);
    const original = await file(cwd, "photo.heic", simpleHeic());
    const began = Date.now();
    const hung = body(await asJob(cwd, { path: original, max_seconds: 12 }, "out", "j-1", false, bin));
    assert.ok(Date.now() - began < 25000, `${Date.now() - began} ms`);
    assert.equal(hung.conversion!.ended, "the time given to it ran out");
    assert.equal(hung.preview!.status, "failed");
    for (const f of ["convert-pid.txt", "convert-child.txt"]) {
      const pid = Number((await readFile(join(bin, f), "utf8")).trim());
      assert.throws(() => process.kill(pid, 0), (e: NodeJS.ErrnoException) => e.code === "ESRCH", `${f}: the process is gone`);
    }
    assert.deepEqual((await walkDir(join(cwd, "out"))).filter((p) => p.includes("/.work-")), []);
    // A flood: the stub writes without end beside its output; the cap stops it.
    await stubConvert(bin, 10, 10, `dd if=/dev/zero of="$(dirname "$out")/flood.bin" bs=1M 2>/dev/null`);
    await writeFile(join(bin, "heif-convert"), `#!/bin/sh\necho "$$" > "${bin}/convert-pid.txt"\nfor a in "$@"; do out="$a"; done\ndd if=/dev/zero of="$(dirname "$out")/flood.bin" bs=1M 2>/dev/null\n`);
    const flood = body(await asJob(cwd, { path: original, max_output_bytes: 5 << 20, max_seconds: 60 }, "out2", "j-1", false, bin));
    assert.match(flood.conversion!.ended!, /passed 5242880 bytes/);
    const pid = Number((await readFile(join(bin, "convert-pid.txt"), "utf8")).trim());
    assert.throws(() => process.kill(pid, 0), (e: NodeJS.ErrnoException) => e.code === "ESRCH");
    assert.deepEqual((await walkDir(join(cwd, "out2"))).filter((p) => p.includes("flood.bin")), []);
  });
});

test("SIGTERM during the conversion: JSON, exit 143, the backend and what it started are gone, no work directory is left", async () => {
  await withCwd(async (cwd, bin) => {
    await stubExiftool(bin, CANARIES);
    await stubConvert(bin, 10, 10, `sleep 300 &\necho $! > "${bin}/convert-child.txt"\nsleep 300`);
    const original = await file(cwd, "photo.heic", simpleHeic());
    await mkdir(join(cwd, "out"), { recursive: true });
    const child = spawn("python3", [TOOL], { cwd, env: { ...process.env, ...AGENT, PATH: `${bin}:${process.env.PATH}`, JOB_ID: "j-1", OUT: join(cwd, "out") } });
    const out: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => out.push(c));
    child.stdin.end(JSON.stringify({ path: original, max_seconds: 100 }));
    const done = new Promise<number | null>((resolve) => child.on("close", (code) => resolve(code)));
    for (let i = 0; i < 400 && !(await stat(join(bin, "convert-child.txt")).then(() => true, () => false)); i++) await new Promise((r) => setTimeout(r, 25));
    child.kill("SIGTERM");
    assert.equal(await done, 143);
    const a = JSON.parse(Buffer.concat(out).toString("utf8")) as Answer;
    assert.equal(a.interrupted, "SIGTERM");
    for (const f of ["convert-pid.txt", "convert-child.txt"]) {
      const pid = Number((await readFile(join(bin, f), "utf8")).trim());
      assert.throws(() => process.kill(pid, 0), (e: NodeJS.ErrnoException) => e.code === "ESRCH", `${f}: the process is gone`);
    }
    assert.deepEqual((await walkDir(join(cwd, "out"))).filter((p) => /\/\.work-|\/\.heic_inspect-/.test(p)), []);
  });
});

test("pillow-heif is the other backend, run in a child process of its own, chosen explicitly and recorded", async () => {
  await withCwd(async (cwd, bin) => {
    await stubExiftool(bin, CANARIES);
    // A stand-in for the library, from its documented interface: register_heif_opener() and PIL's Image.open / n_frames / seek / load / save.
    const libs = join(cwd, "libs");
    await mkdir(join(libs, "PIL"), { recursive: true });
    await mkdir(join(libs, "pillow_heif"), { recursive: true });
    await writeFile(join(libs, "pillow_heif", "__init__.py"), "def register_heif_opener():\n    pass\n");
    await writeFile(join(libs, "PIL", "__init__.py"), "");
    await writeFile(join(libs, "PIL", "Image.py"), `import os, builtins
MAX_IMAGE_PIXELS = None
class _Im:
    size = (4032, 3024)
    mode = "RGB"
    n_frames = 1
    def seek(self, n): pass
    def load(self): pass
    def convert(self, m): return self
    def save(self, out, format=None, **kw):
        builtins.open(out, "wb").write(bytes.fromhex("ffd8ffe000040000ffc0000b08") + (3024).to_bytes(2, "big") + (4032).to_bytes(2, "big") + bytes.fromhex("0101110 0ffd9".replace(" ", "")))
        builtins.open(out + ".argv", "w").write(repr((format, kw, os.getpid())))
def open(path):
    return _Im()
`);
    const original = await file(cwd, "photo.heic", simpleHeic());
    const answer = body(await asPillow(cwd, original, libs, bin));
    assert.equal(answer.preview!.backend, "pillow-heif");
    assert.equal(answer.preview!.status, "written", JSON.stringify([answer.preview, answer.conversion]));
    assert.equal(answer.conversion!.backend, "pillow-heif");
    assert.equal(answer.preview!.width, 4032);
  });
});

async function asPillow(cwd: string, original: string, libs: string, bin: string): Promise<Run> {
  await mkdir(join(cwd, "outp"), { recursive: true });
  return run(cwd, { path: original, backend: "pillow-heif", quality: 70 }, { JOB_ID: "j-p", OUT: join(cwd, "outp"), PYTHONPATH: libs }, bin);
}

const hasHeifConvert = spawnSync("sh", ["-c", "command -v heif-convert"]).status === 0;
test("one real run, gated on heif-convert being on PATH (its version is recorded)", { skip: hasHeifConvert ? false : "heif-convert is not on PATH on this machine" }, async () => {
  // No real HEIC sample exists in the repository: the file is a container without codec data, which heif-convert is expected to refuse,
  // and the answer must then be partial with the backend's own error recorded. What this proves is the call and the supervision, not a decode.
  await withCwd(async (cwd) => {
    const version = spawnSync("heif-convert", ["--version"], { encoding: "utf8" });
    const answer = body(await run(cwd, { path: await file(cwd, "photo.heic", simpleHeic()), max_seconds: 60 }));
    assert.equal(answer.conversion!.backend, "heif-convert");
    assert.notEqual(answer.status, "complete", `heif-convert ${(version.stdout + version.stderr).trim()} decoded a file without codec data`);
  });
});
