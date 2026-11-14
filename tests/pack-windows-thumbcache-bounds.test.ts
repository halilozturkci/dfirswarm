/**
 * thumbcache_read's bounds on what it prints and on how it walks a directory.
 *
 * - A file that ends inside many entries: one reason per entry made a file's status_basis grow with the file (2,000,000 entries that each declare
 *   a size past the end gave 192 MB of answer). The reason now counts them and names the first three by offset.
 * - A deep directory: os.walk recursed in Python 3.11 and earlier, so a tree deeper than the recursion limit ended the whole answer with an
 *   error. The tool walks with a stack of its own; the test runs it under a recursion limit far below the tree's depth (on Python 3.12 and later
 *   os.walk no longer recurses, so the source is also held to not calling it).
 *
 * The cache files are built here from the published layout of the Windows 10 format (0x20), not from the tool's reading.
 */
import assert from "node:assert/strict";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { withCwd } from "./tool-library-harness.ts";
import { WIN } from "./windows-pack-harness.ts";
import { assertJsonAnswer, runTool } from "./windows-tool-contract.ts";

const TOOL = "thumbcache_read";
type Answer = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

/** A Windows 10 (0x20) cache header of 24 bytes: 'CMMM', the version, the cache type, the first entry's offset and the first free byte's. */
function header(type: number, first: number, free: number): Buffer {
  const h = Buffer.alloc(24);
  h.write("CMMM", 0, "latin1");
  h.writeUInt32LE(0x20, 4);
  h.writeUInt32LE(type, 8);
  h.writeUInt32LE(first, 16);
  h.writeUInt32LE(free, 20);
  return h;
}

/** A Windows 10 entry of 56 header bytes with no identifier and no image, declaring `size` bytes. */
function emptyEntry(hash: number, size: number): Buffer {
  const e = Buffer.alloc(56);
  e.write("CMMM", 0, "latin1");
  e.writeUInt32LE(size >>> 0, 4);
  e.writeBigUInt64LE(BigInt(hash), 8);
  return e; // identifier, padding and data sizes, width, height and the checksums are all zero
}

/** A Windows 10 entry holding a small BMP under an identifier of 16 characters. */
function imageEntry(hash: number): Buffer {
  const pixels = Buffer.alloc(16, 0x42);
  const bmp = Buffer.alloc(54);
  bmp.write("BM", 0, "latin1");
  bmp.writeUInt32LE(54 + pixels.length, 2);
  bmp.writeUInt32LE(54, 10);
  bmp.writeUInt32LE(40, 14);
  bmp.writeInt32LE(2, 18);
  bmp.writeInt32LE(2, 22);
  bmp.writeUInt16LE(1, 26);
  bmp.writeUInt16LE(32, 28);
  const data = Buffer.concat([bmp, pixels]);
  const id = Buffer.from(hash.toString(16).padStart(16, "0"), "utf16le");
  const e = Buffer.alloc(56);
  e.write("CMMM", 0, "latin1");
  e.writeUInt32LE(56 + id.length + data.length, 4);
  e.writeBigUInt64LE(BigInt(hash), 8);
  e.writeUInt32LE(id.length, 16);
  e.writeUInt32LE(0, 20);
  e.writeUInt32LE(data.length, 24);
  e.writeUInt32LE(2, 28);
  e.writeUInt32LE(2, 32);
  return Buffer.concat([e, id, data]);
}

test("a file that ends inside 20,000 entries says so in one bounded reason: the count and the first three offsets", async () => {
  await withCwd(async (cwd) => {
    const n = 20_000;
    const one = emptyEntry(1, 0xffffffff); // each declares a size past the end of the file, while its parts are whole in it
    const body = Buffer.concat(Array.from({ length: n }, () => one));
    mkdirSync(join(cwd, "work", "cut"), { recursive: true });
    writeFileSync(join(cwd, "work", "cut", "thumbcache_32.db"), Buffer.concat([header(0, 24, 24 + body.length), body]));
    const run = await runTool(TOOL, cwd, { path: "work/cut/thumbcache_32.db" }, { AGENT_ID: "s1" });
    const out = assertJsonAnswer(run, "many cut entries") as Answer;
    assert.equal(out.status, "partial");
    const file = out.files[0] as Answer;
    assert.equal(file.entries, n);
    assert.equal(file.entries_truncated, n);
    assert.match(file.status_basis, new RegExp(`^the file ends inside ${n} entr\\(ies\\) \\(rows\\[\\]\\.truncated; entries_truncated counts them\\): at offset 24 \\(\\d+ of its 4294967295 bytes are there\\); at offset 80 \\(.*\\); at offset 136 \\(.*\\); and ${n - 3} more`));
    assert.ok(file.status_basis.length < 1000, `the reason is ${file.status_basis.length} characters for ${n} entries`);
    assert.ok(run.stdout.length < 400_000, `the answer is ${run.stdout.length} bytes for ${n} entries (the page holds 100 rows)`);
    // A file cut inside one entry names it alone, with no "more".
    const two = Buffer.concat([imageEntry(7), emptyEntry(8, 4096)]);
    writeFileSync(join(cwd, "work", "cut", "thumbcache_96.db"), Buffer.concat([header(1, 24, 24 + two.length), two]));
    const single = assertJsonAnswer(await runTool(TOOL, cwd, { path: "work/cut/thumbcache_96.db" }, { AGENT_ID: "s1" }), "one cut entry") as Answer;
    assert.match(single.files[0].status_basis, /^the file ends inside 1 entr\(ies\) \(rows\[\]\.truncated; entries_truncated counts them\): at offset \d+ \(56 of its 4096 bytes are there\)(;|$)/);
    assert.doesNotMatch(single.files[0].status_basis, /more/);
  });
});

test("a directory 300 levels deep is walked under a recursion limit of 100: the cache at the bottom is read, and the walk does not call os.walk", async () => {
  assert.doesNotMatch(readFileSync(join(WIN, TOOL, "run.py"), "utf8"), /\bos\.walk\(/, "the walk keeps its own stack");
  await withCwd(async (cwd) => {
    const levels = Array.from({ length: 300 }, () => "d");
    const deep = join(cwd, "work", "deep", ...levels);
    mkdirSync(deep, { recursive: true });
    const cache = Buffer.concat([imageEntry(0x1234)]);
    writeFileSync(join(deep, "thumbcache_32.db"), Buffer.concat([header(0, 24, 24 + cache.length), cache]));
    // A cache beside the top too, and a sibling tree after the deep one: the order is a directory's files, then its subdirectories by name.
    writeFileSync(join(cwd, "work", "deep", "thumbcache_96.db"), Buffer.concat([header(1, 24, 24 + cache.length), cache]));
    mkdirSync(join(cwd, "work", "deep", "e"), { recursive: true });
    writeFileSync(join(cwd, "work", "deep", "e", "thumbcache_256.db"), Buffer.concat([header(2, 24, 24 + cache.length), cache]));
    const wrapper = join(cwd, "low-recursion.py");
    writeFileSync(wrapper, `import runpy, sys\nsys.setrecursionlimit(100)\nrunpy.run_path(${JSON.stringify(join(WIN, TOOL, "run.py"))}, run_name="__main__")\n`);
    const run = await runTool(wrapper, cwd, { path: "work/deep", extract: false }, { AGENT_ID: "s1" });
    const out = assertJsonAnswer(run, "a deep directory") as Answer;
    assert.equal(out.status, "complete", out.status_basis);
    assert.deepEqual((out.files as Answer[]).map((f) => String(f.file).replace(/^.*?work\/deep\//, "")), [
      "thumbcache_96.db",
      `${levels.join("/")}/thumbcache_32.db`,
      "e/thumbcache_256.db",
    ]);
    assert.equal(out.entry_count, 3);
  });
});
