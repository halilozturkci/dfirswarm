/**
 * thumbcache_read: the entries of a Windows thumbnail or icon cache, and the images they store.
 *
 * The fixtures are written here from the layout (the 24- or 28-byte file header that begins 'CMMM', and an entry header of 48 bytes on
 * Windows 7 and 56 on Vista and on Windows 8 and later, then the identifier, the padding and the stored image), never from the tool's
 * output. What is held: every image comes out byte for byte under a name the tool made, with its hash; the header's type and the file's
 * name are both said; a cut file, an entry whose lengths do not fit, and bytes that are no entry each make the answer partial and say
 * where; a version without a layout and a file of another format are refused; every bound is said when it is reached; wrong arguments and
 * a stop signal get one JSON document.
 *
 * The Windows 10 layout was also run by hand against the caches of a real profile (in the manifest); these cases need no such file.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { withCwd } from "./tool-library-harness.ts";
import { WIN } from "./windows-pack-harness.ts";
import { assertJsonAnswer, assertStopped, fuzzTool, jobEnv, manifestOf, runTool, stopAt, typeConfused, withDeadline, type StopSignal } from "./windows-tool-contract.ts";

const TOOL = "thumbcache_read";
type Row = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any
type Answer = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any
type Entry = { hash: bigint; data: Buffer; id?: string; width?: number; height?: number; padding?: number; ext?: string };

// --- images: the smallest files of each kind that carry what the tool reads from them ---------------------------------------------------

function bmp(width: number, height: number, fill: number): Buffer {
  const pixels = Buffer.alloc(width * height * 4, fill);
  const b = Buffer.alloc(54);
  b.write("BM", 0, "latin1");
  b.writeUInt32LE(54 + pixels.length, 2);
  b.writeUInt32LE(54, 10);
  b.writeUInt32LE(40, 14);
  b.writeInt32LE(width, 18);
  b.writeInt32LE(-height, 22); // a top-down bitmap: the height is stored negative
  b.writeUInt16LE(1, 26);
  b.writeUInt16LE(32, 28);
  return Buffer.concat([b, pixels]);
}

function png(width: number, height: number): Buffer {
  const ihdr = Buffer.alloc(25);
  ihdr.writeUInt32BE(13, 0);
  ihdr.write("IHDR", 4, "latin1");
  ihdr.writeUInt32BE(width, 8);
  ihdr.writeUInt32BE(height, 12);
  return Buffer.concat([Buffer.from("89504e470d0a1a0a", "hex"), ihdr, Buffer.from("0000000049454e44ae426082", "hex")]);
}

const jpeg = (n: number): Buffer => Buffer.concat([Buffer.from("ffd8ffe000104a46494600010100000100010000", "hex"), Buffer.alloc(n, 0x5a), Buffer.from("ffd9", "hex")]);

// --- the cache file ---------------------------------------------------------------------------------------------------------------------

const HEADER_BYTES: Record<number, number> = { 0x14: 24, 0x15: 24, 0x1a: 24, 0x1c: 28, 0x1e: 24, 0x1f: 24, 0x20: 24 };

function entry(version: number, e: Entry): Buffer {
  const id = Buffer.from(e.id ?? e.hash.toString(16).padStart(16, "0"), "utf16le");
  const pad = Buffer.alloc(e.padding ?? 0);
  const head = Buffer.alloc(version === 0x15 ? 48 : 56);
  head.write("CMMM", 0, "latin1");
  head.writeUInt32LE(head.length + id.length + pad.length + e.data.length, 4);
  head.writeBigUInt64LE(e.hash, 8);
  let at = 16;
  if (version === 0x14) {
    Buffer.from((e.ext ?? "jpg").padEnd(4, "\0"), "utf16le").copy(head, 16);
    at = 24;
  }
  head.writeUInt32LE(id.length, at);
  head.writeUInt32LE(pad.length, at + 4);
  head.writeUInt32LE(e.data.length, at + 8);
  at += 12;
  if (version !== 0x14 && version !== 0x15) {
    head.writeUInt32LE(e.width ?? 0, at);
    head.writeUInt32LE(e.height ?? 0, at + 4);
    at += 8;
  }
  head.writeBigUInt64LE(0x1122334455667788n, at + 4); // the data checksum, which the tool copies and does not verify
  head.writeBigUInt64LE(0x99aabbccddeeff00n, at + 12);
  return Buffer.concat([head, id, pad, e.data]);
}

/** A cache: the header, the entries, and (with `freeBytes`) the empty entry Windows keeps over the unused rest of the file. */
function cache(version: number, type: number, entries: Entry[], o: { freeBytes?: number; first?: number } = {}): Buffer {
  const size = HEADER_BYTES[version] ?? 24;
  const body = Buffer.concat(entries.map((e) => entry(version, e)));
  const head = Buffer.alloc(size);
  head.write("CMMM", 0, "latin1");
  head.writeUInt32LE(version, 4);
  head.writeUInt32LE(type, 8);
  const at = version === 0x14 || version === 0x15 || version === 0x1a ? 12 : 16;
  head.writeUInt32LE(o.first ?? size, at);
  head.writeUInt32LE(size + body.length, at + 4);
  if (at + 8 < size) head.writeUInt32LE(entries.length, at + 8);
  const parts = [head, body];
  if (o.freeBytes) {
    const filler = Buffer.alloc(o.freeBytes);
    entry(version, { hash: 0n, id: "", data: Buffer.alloc(0) }).copy(filler, 0);
    filler.writeUInt32LE(o.freeBytes, 4);
    parts.push(filler);
  }
  return Buffer.concat(parts);
}

const sha = (b: Buffer): string => createHash("sha256").update(b).digest("hex");

function put(cwd: string, rel: string, bytes: Buffer): string {
  mkdirSync(join(cwd, rel, ".."), { recursive: true });
  writeFileSync(join(cwd, rel), bytes);
  return rel;
}

async function read(cwd: string, args: Record<string, unknown>, env: Record<string, string> = {}): Promise<Answer> {
  const run = await runTool(TOOL, cwd, args, env);
  return { ...assertJsonAnswer(run, JSON.stringify(args).slice(0, 120)), exit: run.code };
}

const A = bmp(4, 3, 0x11);
const B = jpeg(900);
const C = png(1280, 720);
const THREE: Entry[] = [
  { hash: 0x7da835189c8552can, data: A, width: 4, height: 3 },
  { hash: 0x0123456789abcdefn, data: B, width: 1280, height: 720, padding: 2 },
  { hash: 0xfedcba9876543210n, data: C, width: 1280, height: 720 },
];

// --- the read ---------------------------------------------------------------------------------------------------------------------------

test("a Windows 10 cache: every entry is a row, every stored image is written byte for byte under a name the tool made, with its hash", async () => {
  await withCwd(async (cwd) => {
    const file = put(cwd, "work/Explorer/thumbcache_1280.db", cache(0x20, 6, THREE, { freeBytes: 4096 }));
    const out = await read(cwd, { path: file });
    assert.equal(out.status, "complete", out.status_basis);
    assert.equal(out.exit, 0);
    assert.match(out.status_basis, /every cache file found \(1\) was read from its first entry to its end; 4 entr\(ies\), 3 with an image, every image written/);
    assert.equal(out.parser, "thumbcache_read/1");
    const [said] = out.files;
    assert.deepEqual([said.format_version, said.windows, said.cache_type, said.size_class_from_header, said.size_class_from_name, said.cache_family_from_name],
      ["0x20", "Windows 10 and later", 6, "1280", "1280", "thumbcache"]);
    assert.deepEqual([said.first_entry_offset, said.first_entry_offset_from, said.entries, said.entries_with_image, said.images_written], [24, "header", 4, 3, 3]);
    assert.deepEqual(said.bytes_not_in_an_entry, { zero_bytes: 0, other_bytes: 0, other: 0 });
    const rows = out.entries as Row[];
    assert.equal(rows.length, 4);
    for (const [i, image] of [A, B, C].entries()) {
      const row = rows[i];
      assert.equal(row.entry, i + 1);
      assert.equal(row.entry_hash, THREE[i].hash.toString(16).padStart(16, "0"));
      assert.equal(row.identifier, row.entry_hash, "Windows writes the hash as the entry's name");
      assert.equal(row.data_size, image.length);
      assert.equal(row.sha256, sha(image));
      assert.equal(row.in_free_space, false);
      assert.equal(row.checksums_verified, false, "the checksums are copied, not verified");
      assert.equal(row.data_checksum, "1122334455667788");
      assert.ok(readFileSync(join(cwd, row.written)).equals(image), "the image written is the image stored");
      assert.match(row.written, new RegExp(`^work/s1/thumbcache_read-[0-9a-f]{12}/thumbcache_1280\\.db-00000${i + 1}-${row.entry_hash}\\.(bmp|jpg|png)$`));
    }
    assert.deepEqual(rows.map((r) => r.image_type), ["bmp", "jpeg", "png", null]);
    assert.deepEqual([rows[0].image_width, rows[0].image_height], [4, 3], "a BMP's own header, its height stored negative");
    assert.deepEqual([rows[2].image_width, rows[2].image_height, rows[2].declared_width, rows[2].declared_height], [1280, 720, 1280, 720]);
    assert.equal(rows[1].padding_bytes, 2);
    assert.equal(rows[1].data_offset, rows[1].offset + 56 + 32 + 2, "the image starts after the entry header, the identifier and the padding");
    // The entry Windows keeps over the unused rest of the file: no image, and past the header's first free byte.
    assert.deepEqual([rows[3].in_free_space, rows[3].data_size, rows[3].entry_size, rows[3].written], [true, 0, 4096, undefined]);
    assert.equal(out.images_written, 3);
    assert.equal(out.image_bytes_written, A.length + B.length + C.length);
    assert.match(out.note, /does not hold the item's path/);
  });
});

test("the layouts of Vista (an extension in the entry), Windows 7 (48-byte entry header) and Windows 8 (a 28-byte file header) are read, each by its own table", async () => {
  await withCwd(async (cwd) => {
    const cases: Array<[number, number, string, string, string]> = [
      [0x14, 2, "thumbcache_256.db", "256", "Windows Vista"],
      [0x15, 3, "thumbcache_1024.db", "1024", "Windows 7"],
      [0x1c, 4, "iconcache_256.db", "256", "Windows 8 (v2)"],
      [0x1f, 6, "thumbcache_1600.db", "1600", "Windows 8.1"],
    ];
    for (const [version, type, name, size, label] of cases) {
      const out = await read(cwd, { path: put(cwd, `work/v${version}/${name}`, cache(version, type, THREE.slice(0, 2))) });
      assert.equal(out.status, "complete", `${label}: ${out.status_basis}`);
      const [said] = out.files;
      assert.deepEqual([said.windows, said.size_class_from_header, said.size_class_from_name, said.entries, said.images_written], [label, size, size, 2, 2], label);
      const rows = out.entries as Row[];
      assert.deepEqual(rows.map((r) => r.sha256), [sha(A), sha(B)], label);
      assert.ok(readFileSync(join(cwd, rows[1].written)).equals(B), label);
      assert.equal("declared_width" in rows[0], version >= 0x1a, `${label}: a width and a height are in the entry from Windows 8 on`);
      if (version === 0x14) assert.equal(rows[0].extension, "jpg");
    }
    assert.equal((await read(cwd, { path: "work/v28/iconcache_256.db" })).files[0].cache_family_from_name, "iconcache");
  });
});

test("the header's type and the file's name are both said, and a disagreement is a problem line", async () => {
  await withCwd(async (cwd) => {
    const out = await read(cwd, { path: put(cwd, "work/thumbcache_96.db", cache(0x20, 6, THREE.slice(0, 1))) });
    assert.deepEqual([out.files[0].size_class_from_header, out.files[0].size_class_from_name], ["1280", "96"]);
    assert.match(out.files[0].problems[0], /the file's name says '96' and its header says '1280'/);
    const odd = await read(cwd, { path: put(cwd, "work/thumbcache_sr.db", cache(0x20, 99, [])) });
    assert.equal(odd.files[0].size_class_from_header, null);
    assert.match(odd.files[0].problems[0], /cache type 99 has no meaning in the table for version 0x20/);
  });
});

// --- what is cut, damaged or not a cache --------------------------------------------------------------------------------------------------

test("a file that ends inside an entry gives a truncated row, writes the whole images before it and not the cut one, and is partial", async () => {
  await withCwd(async (cwd) => {
    const whole = cache(0x20, 6, THREE);
    const cut = whole.subarray(0, 24 + entry(0x20, THREE[0]).length + 56 + 32 + 2 + 100); // 100 bytes into the second image
    const out = await read(cwd, { path: put(cwd, "work/thumbcache_1280.db", cut) });
    assert.equal(out.status, "partial");
    assert.equal(out.exit, 0);
    const rows = out.entries as Row[];
    assert.equal(rows.length, 2, "the entry after the cut one does not exist in the file");
    assert.ok(readFileSync(join(cwd, rows[0].written)).equals(A));
    assert.deepEqual([rows[1].truncated, rows[1].data_bytes_present, rows[1].written, rows[1].sha256], [true, 100, undefined, null]);
    assert.match(rows[1].not_written, /the file ends inside the image \(100 of 922 bytes\): a cut image is not written/);
    assert.match(out.files[0].status_basis, /the file ends inside the entry at offset \d+ \(\d+ of its \d+ bytes are there\)/);
    assert.match(out.files[0].status_basis, /ends before the offset its header gives for its first free byte/);
    // Cut inside an entry's header: a row that says so, and no field of the entry is believed.
    const short = await read(cwd, { path: put(cwd, "work/short/thumbcache_32.db", whole.subarray(0, 24 + 30)) });
    assert.equal(short.status, "partial");
    assert.match(short.entries[0].error, /the file ends 30 bytes into this entry's header of 56/);
    // Cut inside the file header.
    const head = await read(cwd, { path: put(cwd, "work/head/thumbcache_32.db", whole.subarray(0, 10)) });
    assert.equal(head.files[0].status, "partial");
    assert.match(head.files[0].status_basis, /shorter than the 24 bytes of a cache header: no entry was read/);
  });
});

test("an entry whose lengths do not fit it is a row with an error, the next entry is found again, and bytes that are no entry are counted", async () => {
  await withCwd(async (cwd) => {
    const bad = entry(0x20, THREE[0]);
    bad.writeUInt32LE(0x7fffffff, 24); // the data size: far more than the entry holds
    const junk = Buffer.alloc(300, 0xee);
    const zeros = Buffer.alloc(512);
    const bytes = Buffer.concat([cache(0x20, 6, []), bad, junk, entry(0x20, THREE[1]), zeros, entry(0x20, THREE[2])]);
    bytes.writeUInt32LE(bytes.length, 20);
    const out = await read(cwd, { path: put(cwd, "work/thumbcache_1280.db", bytes) });
    assert.equal(out.status, "partial");
    const rows = out.entries as Row[];
    assert.match(rows[0].error, /the entry declares \d+ bytes and its parts need \d+ .*: its image was not read/);
    assert.equal(rows[0].written, undefined);
    const good = rows.filter((r) => r.written);
    assert.deepEqual(good.map((r) => r.sha256), [sha(B), sha(C)], "the entries after the damage are read");
    const said = out.files[0];
    assert.equal(said.entries_malformed, 1);
    assert.equal(said.bytes_not_in_an_entry.zero_bytes, 512, "a run of zeros between entries is not a problem");
    assert.ok(said.bytes_not_in_an_entry.other_bytes >= 300, "the bytes that are neither an entry nor zero are counted");
    assert.match(said.status_basis, /stretch\(es\) of the file \(\d+ bytes\) are neither an entry nor zero; 1 entr\(ies\) have lengths that do not fit them/);
  });
});

test("a version without a layout, the cache's index, IconCache.db and a file that is no cache are refused by name, never guessed at", async () => {
  await withCwd(async (cwd) => {
    const unknown = await read(cwd, { path: put(cwd, "work/thumbcache_48.db", cache(0x21, 2, THREE)) });
    assert.equal(unknown.status, "failed");
    assert.notEqual(unknown.exit, 0);
    assert.equal(unknown.entry_count, 0);
    assert.match(unknown.files[0].status_basis, /version is 0x21, which is not one this tool has a layout for .* the layout is not guessed/);
    const index = await read(cwd, { path: put(cwd, "work/thumbcache_idx.db", Buffer.concat([Buffer.from("IMMM"), Buffer.alloc(200)])) });
    assert.match(index.files[0].status_basis, /this is the cache's index \(it begins 'IMMM'\): it holds no image/);
    const other = await read(cwd, { path: put(cwd, "work/IconCache.db", Buffer.alloc(4096, 7)) });
    assert.equal(other.status, "failed");
    assert.match(other.files[0].status_basis, /does not begin with 'CMMM'/);
    assert.match(String(other.error), /no thumbnail cache was read/);
    assert.equal(existsSync(join(cwd, "work", "s1")), false, "nothing was written for a file that was not read");
  });
});

// --- a directory, the page, a rerun ---------------------------------------------------------------------------------------------------------

test("a directory is read file by file; the inline page is `limit` rows and the whole list is a file; a rerun replaces nothing and names the same images", async () => {
  await withCwd(async (cwd) => {
    put(cwd, "work/Explorer/thumbcache_1280.db", cache(0x20, 6, THREE));
    put(cwd, "work/Explorer/iconcache_16.db", cache(0x20, 0, THREE.slice(0, 1)));
    put(cwd, "work/Explorer/thumbcache_idx.db", Buffer.concat([Buffer.from("IMMM"), Buffer.alloc(64)]));
    put(cwd, "work/Explorer/notes.txt", Buffer.from("not a cache"));
    const env = jobEnv(cwd);
    const first = await read(cwd, { path: "work/Explorer", limit: 1 }, env);
    assert.equal(first.status, "partial", "the index beside the caches is named and not read");
    assert.match(first.status_basis, /1 of the 3 cache file\(s\) read are partial or failed/);
    assert.deepEqual(first.files.map((f: Row) => [f.file.split("/").pop(), f.status]), [["iconcache_16.db", "complete"], ["thumbcache_1280.db", "complete"], ["thumbcache_idx.db", "failed"]]);
    assert.equal(first.entries.length, 1);
    assert.deepEqual([first.entry_count, first.returned, first.truncated, first.images_written], [4, 1, true, 4]);
    assert.match(first.all_results, /^store\/jobs\/j000001\/out\/tool-output\/thumbcache_read-[0-9a-f]{16}\.jsonl$/);
    const all = readFileSync(join(env.OUT, "tool-output", first.all_results.split("/").pop()), "utf8").trim().split("\n").map((l) => JSON.parse(l) as Row);
    assert.equal(all.length, 4);
    assert.match(first.images_directory, /^store\/jobs\/j000001\/out\/thumbcache_read-[0-9a-f]{12}$/);
    const dir = join(env.OUT, first.images_directory.split("/").pop());
    const before = readdirSync(dir).sort();
    assert.equal(before.length, 4);
    const again = await read(cwd, { path: "work/Explorer", limit: 1 }, env);
    assert.deepEqual(readdirSync(dir).sort(), before, "the same images are named again: none is replaced and none is written twice");
    assert.equal(again.all_results, first.all_results);
    assert.deepEqual(again.entries[0].written, first.entries[0].written);
    assert.equal(readdirSync(dir).some((n) => n.startsWith(".")), false, "no temporary file is left beside the images");
  });
});

test("each bound is said when it is reached: max_entries, max_image_bytes, max_output_bytes, extract false, include_free false", async () => {
  await withCwd(async (cwd) => {
    const file = put(cwd, "work/thumbcache_1280.db", cache(0x20, 6, THREE, { freeBytes: 1024 }));
    const few = await read(cwd, { path: file, max_entries: 2 });
    assert.equal(few.status, "partial");
    assert.equal(few.entry_count, 2);
    assert.match(few.files[0].status_basis, /max_entries was reached at offset \d+ of \d+: the entries from there on were not read/);
    const small = await read(cwd, { path: file, max_image_bytes: 200 });
    assert.equal(small.status, "partial");
    assert.deepEqual(small.entries.map((r: Row) => Boolean(r.written)), [true, false, true, false]);
    assert.equal(small.entries[1].sha256, sha(B), "an image that is not written is still hashed");
    assert.match(small.entries[1].not_written, /over max_image_bytes \(200\)/);
    const none = await read(cwd, { path: file, max_output_bytes: 0 });
    assert.equal(none.status, "partial");
    assert.equal(none.images_written, 0);
    assert.match(none.files[0].status_basis, /3 image\(s\) were hashed and not written because max_output_bytes was reached/);
    const listed = await read(cwd, { path: file, extract: false });
    assert.equal(listed.status, "complete");
    assert.deepEqual([listed.images_written, listed.images_directory, listed.entries[0].sha256, listed.entries[0].not_written], [0, null, sha(A), "extract is false"]);
    assert.match(listed.status_basis, /none written \(extract is false\)/);
    const allocated = await read(cwd, { path: file, include_free: false });
    assert.equal(allocated.entry_count, 3, "the entry past the header's first free byte is not read");
    assert.match(allocated.files[0].status_basis, /include_free is false: what lies past it was not read/);
  });
});

// --- the contract ---------------------------------------------------------------------------------------------------------------------------

test("wrong arguments, a link and a missing file are answered as JSON, and a link is never followed", async () => {
  await withCwd(async (cwd) => {
    const file = put(cwd, "work/thumbcache_32.db", cache(0x20, 1, THREE));
    const seed = 20261113;
    const statuses = await fuzzTool(TOOL, typeConfused(manifestOf(TOOL), 200, seed, { path: file }), seed, { cwd });
    assert.ok((statuses.failed ?? 0) > 100, `the wrong types were refused: ${JSON.stringify(statuses)}`);
    for (const args of [{}, { path: "" }, { path: "work/none.db" }, { path: file, limit: 0 }, { path: file, limit: 1001 }, { path: file, surprise: 1 }, { path: file, max_entries: 0 }]) {
      const out = await read(cwd, args);
      assert.equal(out.status, "failed", JSON.stringify(args));
      assert.notEqual(out.exit, 0);
    }
    symlinkSync(join(cwd, file), join(cwd, "work", "link.db"));
    assert.match(String((await read(cwd, { path: "work/link.db" })).error), /symbolic link: it is not followed/);
    // A directory that holds a link named like a cache: the link is named as not opened, the file beside it is read.
    mkdirSync(join(cwd, "work", "dir"));
    writeFileSync(join(cwd, "work", "dir", "thumbcache_96.db"), cache(0x20, 3, THREE.slice(0, 1)));
    symlinkSync(join(cwd, file), join(cwd, "work", "dir", "thumbcache_256.db"));
    const mixed = await read(cwd, { path: "work/dir" });
    assert.equal(mixed.status, "partial");
    assert.match(mixed.files.find((f: Row) => f.file.endsWith("thumbcache_256.db")).status_basis, /a link, not followed/);
    assert.equal(mixed.images_written, 1);
  });
});

test("at its own time limit the tool answers partial and names the clock", async () => {
  await withCwd(async (cwd) => {
    const file = put(cwd, "work/thumbcache_1280.db", cache(0x20, 6, THREE));
    const answer = assertJsonAnswer(await runTool(withDeadline(TOOL, 0), cwd, { path: file }), "deadline 0") as Answer;
    assert.equal(answer.status, "partial");
    assert.equal(answer.stopped_by_time_limit, true);
    assert.match(JSON.stringify(answer), /the tool's own clock \(0 s\) ran out/);
  });
});

for (const signal of ["SIGTERM", "SIGINT", "SIGHUP"] as StopSignal[]) {
  test(`stopped by ${signal} the tool answers one JSON document, exits 128 plus the signal and leaves no temporary file`, async () => {
    await withCwd(async (cwd) => {
      const many: Entry[] = Array.from({ length: 6000 }, (_, i) => ({ hash: BigInt(i + 1), data: bmp(2, 2, i & 0xff), width: 2, height: 2 }));
      const file = put(cwd, "work/thumbcache_16.db", cache(0x20, 0, many));
      const early = assertStopped(await stopAt(TOOL, { path: file }, {}, "early", signal, { cwd }), signal);
      assert.equal(early.answered, true);
      const env = jobEnv(cwd);
      const run = await stopAt(TOOL, { path: file, limit: 1 }, env, "temp", signal, { cwd });
      const got = assertStopped(run, signal);
      if (got.answered) {
        assert.equal(got.answer.interrupted, true);
        assert.equal(typeof got.answer.entries_read, "number");
      }
      for (const name of readdirSync(env.OUT)) {
        if (!name.startsWith("thumbcache_read-")) continue;
        assert.equal(readdirSync(join(env.OUT, name)).some((n) => n.startsWith(".")), false, "no hidden temporary image is left");
        for (const image of readdirSync(join(env.OUT, name)).slice(0, 50)) assert.equal(statSync(join(env.OUT, name, image)).size, 70, "an image placed before the stop is a whole file");
      }
      // In the middle of printing a large answer: the answer stands, whole.
      const printed = await stopAt(TOOL, { path: file, limit: 1000, extract: false }, {}, "print", signal, { cwd });
      const whole = assertStopped(printed, signal);
      if (!whole.answered) assert.equal((whole.answer.entries as unknown[]).length, 1000);
    });
  });
}

test("the tool is registered: the manifest's digest is the script's, it names the caches by name and by magic, and it starts no program", async () => {
  const manifest = JSON.parse(readFileSync(join(WIN, TOOL, "manifest.json"), "utf8"));
  const script = readFileSync(join(WIN, TOOL, "run.py"));
  assert.equal(manifest.sha256, sha(script));
  assert.deepEqual(manifest.use, { names: ["thumbcache_*.db", "iconcache_*.db"], magic: [{ offset: 0, hex: "434d4d4d" }] });
  assert.deepEqual(manifest.requires, []);
  assert.equal("secret_output" in manifest, false);
  assert.doesNotMatch(script.toString("utf8"), /subprocess|os\.system|socket|urllib/);
  assert.match(manifest.description, /checksums_verified is false/);
  assert.match(manifest.description, /renderings\s+made before/);
});
