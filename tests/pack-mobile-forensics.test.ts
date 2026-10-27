/**
 * The mobile pack's three tools and its recipes, against fixtures the test builds from the formats' own
 * layouts and never from a tool's output.
 *
 * SQLite (sqlite_freespace): the file format's own layout. Page 1 starts with a 100-byte header (the page
 * size is the big-endian u16 at 16, 1 meaning 65536; the freelist's first trunk page is the u32 at 32 and
 * its length the u32 at 36; the text encoding the u32 at 56). A b-tree page's header sits at byte 0 of the
 * page (byte 100 of page 1): type at +0 (2, 5, 10, 13), the first freeblock at +1 (u16), the cell count at
 * +3, the start of the cell content at +5. A freeblock is a u16 next offset and a u16 size, then the freed
 * bytes; the offsets are from the start of the page. A freelist trunk page holds a u32 next trunk, a u32 leaf
 * count and that many u32 leaf page numbers. The databases themselves are made by Python's sqlite3, the
 * reference writer of the format here, and every expected position is found by walking the file with the
 * rules above or by searching the bytes, never by asking the tool.
 *
 * Backups (manifest_db): Manifest.db's Files table, with the keyed archive Apple's NSKeyedArchiver writes in
 * `file` ($archiver, $version, $top with a root UID, and $objects: "$null", the root dictionary, its class).
 * plistlib builds them.
 *
 * Protobuf (protobuf_peek): the wire format by hand: key = (field << 3) | type, base-128 varints, type 2
 * followed by a length.
 *
 * To see that a test fails on the code it was written against, point MOBILE_PACK at a copy of the pack as it
 * was before the fixes:
 *
 *   git archive edcfe913 packs/mobile-forensics | tar -x -C /tmp/old   # the pack as it was before these fixes (1.2.0)
 *   MOBILE_PACK=/tmp/old/packs/mobile-forensics node --experimental-strip-types --test tests/pack-mobile-forensics.test.ts
 *
 * The tools follow the secret-safe output pattern of recovery_key_scan (docs/packs.md, "Secrets and
 * sensitive output"): what they print and write is checked for a value, a fragment and a digest, in the
 * answer and in every file the answer names.
 */
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, readFile, readdir, rm, stat, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { ROOT, childGone, runPy, runPySnippet, withCwd } from "./tool-library-harness.ts";

const PACK = process.env.MOBILE_PACK ?? join(ROOT, "packs", "mobile-forensics");
const TOOLS = join(PACK, "tools");
const FREESPACE = join(TOOLS, "sqlite_freespace", "run.py");
const MANIFEST = join(TOOLS, "manifest_db", "run.py");
const PROTOBUF = join(TOOLS, "protobuf_peek", "run.py");
const AGENT = { AGENT_ID: "s1" };
const FRAGMENT_STEPS = 1000;      // what sqlite_freespace charges the work budget for every fragment its expression is called on
const RECOVERY_NAME = "123456-654321-111111-222222-333333-444444-555555-666666";

type Run = { code: number | null; stdout: string; stderr: string };

async function tool(script: string, cwd: string, args: unknown, env: Record<string, string> = {}, bin?: string): Promise<Run> {
  return runPy(script, cwd, args, bin, { ...AGENT, ...env });
}

/**
 * The tool as a job runs it: JOB_ID and OUT set, OUT inside the run directory, and SECRET_OUTPUT=1 as the job service sets it
 * for a job run with secret_output (or one whose manifest declares write_values). `name` keeps two runs apart.
 */
async function asJob(script: string, cwd: string, args: unknown, name = "out", job = "j-1", secret = true): Promise<Run> {
  await mkdir(join(cwd, name), { recursive: true });
  return tool(script, cwd, args, { JOB_ID: job, OUT: join(cwd, name), ...(secret ? { SECRET_OUTPUT: "1" } : {}) });
}

function body<T>(out: Run): T {
  assert.equal(out.code, 0, out.stderr + out.stdout);
  assert.doesNotMatch(out.stderr, /Traceback/);
  return JSON.parse(out.stdout) as T;
}

function refused(out: Run): { error: string; [key: string]: unknown } {
  assert.notEqual(out.code, 0, out.stdout);
  assert.doesNotMatch(out.stderr, /Traceback/);
  return JSON.parse(out.stdout) as { error: string };
}

const sha256 = (data: Buffer | string): string => createHash("sha256").update(data).digest("hex");

async function exists(path: string): Promise<boolean> {
  return stat(path).then(() => true, () => false);
}

/** Run a Python fixture builder; its argv follows the code. */
async function build(code: string, ...args: string[]): Promise<void> {
  const out = await runPySnippet(code, args, null);
  assert.equal(out.code, 0, out.stderr);
}

/**
 * The tool run under a wrapper that reports, after the answer on stderr, the process's peak resident memory (bytes) and the peak
 * of what Python allocated (tracemalloc). The resident peak depends on the machine: a runner's interpreter, its allocator and, on
 * Linux, a peak a child can inherit from a large parent are in it, so a test compares it with a run of the same wrapper on a tiny
 * input (`baseline()`). The Python allocation peak does not depend on any of that: it is what the tool's own buffers need.
 */
const MEASURE = String.raw`
import resource, runpy, sys, tracemalloc
tracemalloc.start()
sys.argv = [sys.argv[1]]
try:
    runpy.run_path(sys.argv[0], run_name="__main__")
except SystemExit:
    pass
traced = tracemalloc.get_traced_memory()[1]
usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
sys.stderr.write("MAXRSS %d\nTRACED %d\n" % (usage if sys.platform == "darwin" else usage * 1024, traced))
`;

type Measured = { run: Run; maxrss: number; traced: number };

async function measured(script: string, cwd: string, args: unknown, env: Record<string, string> = {}): Promise<Measured> {
  return new Promise((resolve, reject) => {
    const child = spawn("python3", ["-c", MEASURE, script], { cwd, env: { ...process.env, ...AGENT, ...env } });
    const out: Buffer[] = [], err: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => out.push(c));
    child.stderr.on("data", (c: Buffer) => err.push(c));
    child.on("error", reject);
    child.on("close", (code) => {
      const stderr = Buffer.concat(err).toString("utf8");
      const m = /MAXRSS (\d+)\nTRACED (\d+)\n/.exec(stderr);
      assert.ok(m, stderr);
      resolve({ run: { code, stdout: Buffer.concat(out).toString("utf8"), stderr: stderr.replace(m[0], "") }, maxrss: Number(m[1]), traced: Number(m[2]) });
    });
    child.stdin.end(JSON.stringify(args));
  });
}

/** The same wrapper on a message of a few bytes: what the interpreter and this machine cost before the tool has anything to hold. */
async function baseline(script: string, cwd: string): Promise<Measured> {
  const tiny = await measured(script, cwd, { hex: "0801" });
  assert.equal(tiny.run.code, 0, tiny.run.stderr);
  return tiny;
}

/** The tool with the text of its standard input as given (JSON.stringify cannot write NaN or Infinity). */
async function rawTool(script: string, cwd: string, stdin: string, env: Record<string, string> = {}): Promise<Run> {
  return new Promise((resolve, reject) => {
    const child = spawn("python3", [script], { cwd, env: { ...process.env, ...AGENT, ...env } });
    const out: Buffer[] = [], err: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => out.push(c));
    child.stderr.on("data", (c: Buffer) => err.push(c));
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stdout: Buffer.concat(out).toString("utf8"), stderr: Buffer.concat(err).toString("utf8") }));
    child.stdin.end(stdin);
  });
}

/** Every regular file under a directory (not following links), with its bytes. */
async function filesUnder(dir: string): Promise<{ path: string; data: Buffer }[]> {
  const found: { path: string; data: Buffer }[] = [];
  const walk = async (d: string): Promise<void> => {
    for (const entry of await readdir(d, { withFileTypes: true })) {
      const p = join(d, entry.name);
      if (entry.isDirectory()) await walk(p);
      else if (entry.isFile()) found.push({ path: p, data: await readFile(p) });
    }
  };
  await walk(dir);
  return found;
}

/** A needle as every encoding a tool could print it in. */
function forms(text: string): Buffer[] {
  const utf8 = Buffer.from(text, "utf8");
  return [utf8, Buffer.from(text, "utf16le"), Buffer.from(utf8.toString("base64"), "ascii"), Buffer.from(utf8.toString("hex"), "ascii"),
    Buffer.from(sha256(utf8), "ascii")];
}

/** Everything a tool wrote or printed, except the one file that is allowed to hold the values. */
async function assertNowhere(text: string, stdout: string, dir: string, allowed: string[]): Promise<void> {
  for (const form of forms(text)) {
    assert.equal(Buffer.from(stdout, "utf8").indexOf(form), -1, "the answer holds " + JSON.stringify(text) + " (or an encoding or digest of it)");
    for (const file of await filesUnder(dir)) {
      if (allowed.some((a) => file.path.endsWith(a))) continue;
      assert.equal(file.data.indexOf(form), -1, file.path + " holds " + JSON.stringify(text) + " (or an encoding or digest of it)");
    }
  }
}

async function jsonl<T>(path: string): Promise<T[]> {
  const text = await readFile(path, "utf8");
  return text.split("\n").filter(Boolean).map((l) => JSON.parse(l) as T);
}

// --- SQLite fixtures ---------------------------------------------------------------

/** A database with 16 rows in one table, the ninth and the fifteenth deleted: their cells are on page 2's freeblock chain. */
const FREEBLOCK_DB = String.raw`
import sqlite3, sys
path, marker, encoding = sys.argv[1:4]
db = sqlite3.connect(path)
if encoding != "utf-8":
    db.execute("PRAGMA encoding = '%s'" % encoding)
db.execute("PRAGMA secure_delete = OFF")
db.execute("CREATE TABLE message (id INTEGER PRIMARY KEY, body TEXT)")
rows = [(i, "keep-%02d-" % i + "k" * 30) for i in range(1, 9)]
rows.append((9, marker + "-" + "x" * 30))
rows += [(i, "tail-%02d-" % i + "t" * 30) for i in range(10, 14)]
rows.append((14, "keep-14-" + "k" * 30))
rows.append((15, "SECOND-DELETED-ROW-" + "y" * 30))
rows.append((16, "keep-16-" + "k" * 30))
db.executemany("INSERT INTO message VALUES (?, ?)", rows)
db.commit()
db.execute("DELETE FROM message WHERE id IN (9, 15)")
db.commit()
db.close()
`;

/** A database whose deleted rows free whole pages: the freelist has a trunk and leaves. */
const FREELIST_DB = String.raw`
import sqlite3, sys
path, marker = sys.argv[1:3]
db = sqlite3.connect(path)
db.execute("PRAGMA secure_delete = OFF")
db.execute("CREATE TABLE message (id INTEGER PRIMARY KEY, body TEXT)")
db.executemany("INSERT INTO message VALUES (?, ?)", [(i, marker + "-%03d-" % i + "w" * 900) for i in range(1, 41)])
db.commit()
db.execute("DELETE FROM message")
db.commit()
db.close()
`;

type Fragment = {
  finding_id: string; page: number; where: string; encoding: string; offset: number; offset_verified: boolean;
  bytes: number; characters: number; block_offset?: number; text?: string; value?: string;
};
type Paged = { matched: number; returned: number; truncated: boolean; all_results?: string };
type Free = {
  db: string; parser: string; status: string; status_basis?: string; fragments: Fragment[]; fragment_count: number; filter: string | null; filter_marks: string | null;
  problems: { kind: string; detail: string }[]; problem_kinds: Record<string, number>; stopped_before_page: number | null;
  database: { page_size: number; text_encoding: string; bytes: number; pages_in_file: number; journal_mode_on_disk: string };
  freelist: { declared: number; walked: number; trunk_pages: number };
  scanned: Record<string, number>; encodings_scanned: string[];
  companions: Record<string, { bytes: number; examined: boolean }>;
  secret_values: { requested: boolean; written: number | null; values_file: string | null; contains_secret_values: boolean | null; rows_are_all_fragments?: string };
  pages: { fragments: Paged; problems: Paged }; paths_withheld: number; truncated: boolean;
};
type Value = { finding_id: string; file: string; page: number; where: string; encoding: string; offset: number; bytes: number; characters: number; value: string; match?: number; run?: string };

/** The freeblocks of every b-tree page, by walking the file with the format's own rules. */
function freeblocks(file: Buffer): { page: number; block: number; size: number; base: number }[] {
  let pageSize = file.readUInt16BE(16);
  if (pageSize === 1) pageSize = 65536;
  const out: { page: number; block: number; size: number; base: number }[] = [];
  for (let p = 1; p <= file.length / pageSize; p++) {
    const base = (p - 1) * pageSize;
    const at = base + (p === 1 ? 100 : 0);
    if (![2, 5, 10, 13].includes(file[at])) continue;
    let block = file.readUInt16BE(at + 1);
    for (let guard = 0; block && guard < 100; guard++) {
      const size = file.readUInt16BE(base + block + 2);
      out.push({ page: p, block, size, base });
      block = file.readUInt16BE(base + block);
    }
  }
  return out;
}

/**
 * The tool as a job runs it. `rows` is every row of the values file (one for every fragment found: `contains` marks them with match 1, 0 or
 * 2 and never drops one); `values` is the rows an expression matched or could not decide, which is what a reader of the file filters on.
 */
async function freespace(cwd: string, db: string, args: Record<string, unknown> = {}, name = "out"): Promise<{ answer: Free; values: Value[]; rows: Value[]; out: string; run: Run }> {
  const run = await asJob(FREESPACE, cwd, { db, write_values: true, ...args }, name);
  const answer = body<Free>(run);
  const valuesFile = join(cwd, name, "sqlite-freespace-values.jsonl");
  const rows = (await exists(valuesFile)) ? await jsonl<Value>(valuesFile) : [];
  let values = rows.filter((v) => v.match !== 0);
  if (!values.length && answer.fragments.some((f) => f.text !== undefined)) {
    // The tool as it was before the fix printed each fragment's text in the answer: read it from there, so that a
    // test run against that code fails on the assertion that names the defect.
    values = answer.fragments.map((f, i) => ({ finding_id: `old${i}`, file: db, page: f.page, where: f.where, encoding: f.encoding, offset: f.offset,
      bytes: Buffer.byteLength(f.text ?? ""), characters: [...(f.text ?? "")].length, value: f.text ?? "" }));
  }
  return { answer, values, rows, out: join(cwd, name), run };
}

// --- sqlite_freespace ----------------------------------------------------------------

test("sqlite_freespace reports a freeblock fragment at the byte position of its text, 4 bytes past the freeblock's own header", async () => {
  // It sliced the region from block + 4 and recorded block as its base, so every "freeblock in page" offset was 4 too early.
  await withCwd(async (cwd) => {
    const marker = "FREEBLOCK-MARKER-ALPHA";
    const db = join(cwd, "work", "sms.db");
    await build(FREEBLOCK_DB, db, marker, "utf-8");
    const file = await readFile(db);
    const { answer, values } = await freespace(cwd, db);
    // Where the format puts the deleted cell: on a freeblock of page 2.
    const spec = freeblocks(file);
    assert.ok(spec.length >= 1, "the fixture has a freeblock");
    const hit = values.find((v) => v.value.includes(marker));
    assert.ok(hit, "the deleted row's text is recovered");
    assert.equal(hit.where, "freeblock in page");
    const block = spec.find((b) => hit.offset >= b.base + b.block + 4 && hit.offset < b.base + b.block + b.size);
    assert.ok(block, "the fragment lies after a freeblock's 4-byte header and inside its size, by the format's own walk");
    assert.equal(hit.page, block.page);
    // The offset is where the bytes are: the file's bytes at it are the text.
    assert.equal(file.subarray(hit.offset, hit.offset + hit.bytes).toString("utf8"), hit.value);
    assert.ok(file.indexOf(Buffer.from(marker)) >= hit.offset && file.indexOf(Buffer.from(marker)) < hit.offset + hit.bytes);
    assert.equal(answer.status, "complete", JSON.stringify(answer.problems));
    const row = answer.fragments.find((f) => f.finding_id === hit.finding_id);
    assert.ok(row);
    assert.equal(row.offset_verified, true);
    assert.equal(row.block_offset, block.block);
    assert.equal(row.bytes, Buffer.byteLength(hit.value));
    assert.equal(row.characters, [...hit.value].length);
    assert.equal(row.text, undefined, "the answer carries no text");
  });
});

test("sqlite_freespace reads UTF-8 text in any language, and UTF-16LE text, and says which", async () => {
  // The pattern was printable ASCII and ASCII-range UTF-16: Turkish and Chinese text in a deleted row was a hole.
  await withCwd(async (cwd) => {
    const turkish = "Merhaba çok güzel şğı İstanbul";
    const chinese = "你好，世界。这是一个测试消息";
    for (const [name, text] of [["tr", turkish], ["zh", chinese]]) {
      const db = join(cwd, "work", `${name}.db`);
      await build(FREEBLOCK_DB, db, text, "utf-8");
      const { answer, values } = await freespace(cwd, db, {}, `out-${name}`);
      const found = values.find((v) => v.value.includes(text));
      assert.ok(found, `${name}: the text is recovered whole`);
      assert.equal(found.encoding, "utf-8");
      assert.equal((await readFile(db)).subarray(found.offset, found.offset + found.bytes).toString("utf8"), found.value);
      assert.deepEqual(answer.encodings_scanned.slice(0, 2), ["utf-8", "utf-16le"]);
    }
    // A database that stores its text as UTF-16LE (header field at 56 is 2).
    const wide = "你好，世界。这是一个测试消息 and ASCII";
    const db = join(cwd, "work", "wide.db");
    await build(FREEBLOCK_DB, db, wide, "UTF-16le");
    const file = await readFile(db);
    assert.equal(file.readUInt32BE(56), 2);
    const { answer, values } = await freespace(cwd, db, {}, "out-wide");
    assert.equal(answer.database.text_encoding, "UTF-16LE");
    const found = values.find((v) => v.value.includes("你好，世界。这是一个测试消息"));
    assert.ok(found, "UTF-16LE text with CJK characters is recovered");
    assert.equal(found.encoding, "utf-16le");
    assert.equal(file.subarray(found.offset, found.offset + found.bytes).toString("utf16le"), found.value);
  });
});

test("sqlite_freespace keeps a freeblock chain that loops from being read again and again, and says corrupt", async () => {
  // A guard of 4096 steps ended a loop in silence: the same block was read 4096 times and listed as 4096 fragments.
  await withCwd(async (cwd) => {
    const marker = "LOOPING-FREEBLOCK";
    const db = join(cwd, "work", "loop.db");
    await build(FREEBLOCK_DB, db, marker, "utf-8");
    const file = await readFile(db);
    const spec = freeblocks(file).find((b) => file.indexOf(Buffer.from(marker)) >= b.base + b.block && file.indexOf(Buffer.from(marker)) < b.base + b.block + b.size);
    assert.ok(spec);
    // The freeblock's next pointer is its own offset: the chain never ends.
    file.writeUInt16BE(spec.block, spec.base + spec.block);
    await writeFile(db, file);
    const { answer, values } = await freespace(cwd, db);
    assert.equal(answer.status, "corrupt");
    assert.ok(answer.problem_kinds["freeblock chain corrupt"] >= 1, JSON.stringify(answer.problem_kinds));
    assert.equal(values.filter((v) => v.value.includes(marker)).length, 1, "the looping block is read once");
    assert.ok(answer.problems.some((p) => /points back|loop/.test(p.detail)));
  });
});

test("sqlite_freespace walks the freelist once, compares it with the header and names a cycle", async () => {
  await withCwd(async (cwd) => {
    const marker = "FREELIST-PAGE-MARKER";
    const db = join(cwd, "work", "freelist.db");
    await build(FREELIST_DB, db, marker);
    const file = await readFile(db);
    const pageSize = file.readUInt16BE(16) === 1 ? 65536 : file.readUInt16BE(16);
    const trunk = file.readUInt32BE(32);
    const declared = file.readUInt32BE(36);
    assert.ok(trunk >= 2 && declared >= 3, "the fixture has a freelist");
    const clean = await freespace(cwd, db, { min_length: 20 }, "out-clean");
    assert.equal(clean.answer.status, "complete", JSON.stringify(clean.answer.problems));
    assert.equal(clean.answer.freelist.declared, declared);
    assert.equal(clean.answer.freelist.walked, declared);
    const inPages = clean.values.filter((v) => v.value.includes(marker));
    const onFreelist = inPages.filter((v) => v.where.startsWith("freelist"));
    assert.ok(onFreelist.length >= 10, "the deleted rows are read out of freelist pages, got " + onFreelist.length);
    // Every fragment, wherever it was found, is at the byte position it reports.
    for (const v of clean.values) assert.equal(file.subarray(v.offset, v.offset + v.bytes).toString("utf8"), v.value);
    // The trunk page lists itself as the next trunk: a cycle.
    const cyclic = Buffer.from(file);
    cyclic.writeUInt32BE(trunk, (trunk - 1) * pageSize);
    const bad = join(cwd, "work", "cycle.db");
    await writeFile(bad, cyclic);
    const cycle = await freespace(cwd, bad, { min_length: 20 }, "out-cycle");
    assert.equal(cycle.answer.status, "corrupt");
    assert.ok(cycle.answer.problem_kinds["freelist cycle"] >= 1, JSON.stringify(cycle.answer.problem_kinds));
    // The header says one more free page than the chain holds.
    const counted = Buffer.from(file);
    counted.writeUInt32BE(declared + 5, 36);
    const wrong = join(cwd, "work", "count.db");
    await writeFile(wrong, counted);
    const count = await freespace(cwd, wrong, { min_length: 20 }, "out-count");
    assert.equal(count.answer.status, "corrupt");
    assert.ok(count.answer.problem_kinds["freelist count differs from the header"] >= 1);
  });
});

test("sqlite_freespace validates the header: a short file, a bad page size and a truncated last page are named, never a traceback", async () => {
  await withCwd(async (cwd) => {
    const magic = Buffer.from("SQLite format 3\0", "latin1");
    const short = join(cwd, "work", "short.db");
    await writeFile(short, Buffer.concat([magic, Buffer.alloc(30)]));
    assert.match(refused(await tool(FREESPACE, cwd, { db: short })).error, /not a SQLite database/);
    const odd = Buffer.alloc(8192);
    magic.copy(odd);
    odd.writeUInt16BE(3000, 16);
    odd[18] = 1; odd[19] = 1;
    const oddPath = join(cwd, "work", "odd.db");
    await writeFile(oddPath, odd);
    assert.match(refused(await tool(FREESPACE, cwd, { db: oddPath })).error, /page size/);
    const future = Buffer.from(odd);
    future.writeUInt16BE(4096, 16);
    future[19] = 9;
    const futurePath = join(cwd, "work", "future.db");
    await writeFile(futurePath, future);
    assert.match(refused(await tool(FREESPACE, cwd, { db: futurePath })).error, /read format version is 9/);
    // A real database cut 100 bytes short: the last page is partial, and the answer says it was not examined.
    const db = join(cwd, "work", "cut.db");
    await build(FREEBLOCK_DB, db, "CUT-FILE-MARKER", "utf-8");
    const file = await readFile(db);
    await writeFile(db, file.subarray(0, file.length - 100));
    const { answer } = await freespace(cwd, db);
    assert.equal(answer.status, "corrupt");
    assert.ok(answer.problem_kinds["partial last page"] >= 1, JSON.stringify(answer.problem_kinds));
    assert.ok(answer.scanned.pages_partial >= 1);
  });
});

test("sqlite_freespace stops at its time limit and says which pages it did not reach", async () => {
  await withCwd(async (cwd) => {
    const db = join(cwd, "work", "slow.db");
    await build(FREELIST_DB, db, "TIME-LIMIT-MARKER");
    const { answer } = await freespace(cwd, db, { max_seconds: 1e-9 });
    assert.equal(answer.status, "partial");
    assert.equal(answer.stopped_before_page, 1);
    assert.ok(answer.scanned.pages_not_reached >= 3);
    assert.ok(answer.problem_kinds["time limit"] === 1);
  });
});

test("sqlite_freespace prints no fragment text and writes it only to a 0600 file of a job, created before the scan", async () => {
  await withCwd(async (cwd) => {
    const marker = "PRIVATE-DELETED-MESSAGE-TEXT";
    const db = join(cwd, "work", "private.db");
    await build(FREELIST_DB, db, marker);
    // One fragment is inline at limit 1, so the whole list is in a paging file too.
    const { answer, values, out, run } = await freespace(cwd, db, { limit: 1, min_length: 20 });
    assert.ok(answer.fragment_count >= 2, "the fixture has more than one fragment: " + answer.fragment_count);
    assert.equal(answer.pages.fragments.truncated, true);
    assert.match(answer.pages.fragments.all_results ?? "", /^store\/jobs\/j-1\/out\/tool-output\/sqlite_freespace-[0-9a-f]{16}\.jsonl$/);
    assert.equal(answer.secret_values.values_file, "store/jobs/j-1/out/sqlite-freespace-values.jsonl");
    assert.equal(answer.secret_values.contains_secret_values, true);
    assert.equal(answer.secret_values.written, answer.fragment_count);
    assert.equal((await stat(join(out, "sqlite-freespace-values.jsonl"))).mode & 0o777, 0o600);
    // Every text is in the values file, and nowhere else: not the answer, not the paging file.
    for (const v of values) await assertNowhere(v.value, run.stdout, out, ["sqlite-freespace-values.jsonl"]);
    assert.ok(values.some((v) => v.value.includes(marker)));
    // The paging file names the same fragments by id, offset and length, with no text field.
    const rows = await jsonl<Fragment>(join(out, "tool-output", answer.pages.fragments.all_results!.split("/").pop()!));
    assert.equal(rows.length, answer.fragment_count);
    assert.ok(rows.every((r) => r.text === undefined && r.value === undefined));
    assert.deepEqual(rows.map((r) => r.finding_id).sort(), values.map((v) => v.finding_id).sort());
    // Nothing was written outside $OUT: no work/ directory in the run directory.
    assert.equal(await exists(join(cwd, "work", "s1")), false);
  });
});

test("sqlite_freespace refuses write_values outside a job, and a second run in the same job, as JSON", async () => {
  await withCwd(async (cwd) => {
    const db = join(cwd, "work", "once.db");
    await build(FREEBLOCK_DB, db, "ONCE-MARKER", "utf-8");
    const outside = refused(await tool(FREESPACE, cwd, { db, write_values: true }));
    assert.match(outside.error, /refused outside a job/);
    assert.equal(await exists(join(cwd, "sqlite-freespace-values.jsonl")), false);
    const first = await freespace(cwd, db, {}, "job-out");
    assert.ok(first.values.length >= 1);
    const again = refused(await asJob(FREESPACE, cwd, { db, write_values: true }, "job-out"));
    assert.match(again.error, /values file already exists/);
    // The first run's values are untouched.
    assert.deepEqual(await jsonl<Value>(join(cwd, "job-out", "sqlite-freespace-values.jsonl")), first.values);
    // A link at the name is refused too, dangling or not, and not written through.
    await mkdir(join(cwd, "linked"), { recursive: true });
    await symlink(join(cwd, "elsewhere.jsonl"), join(cwd, "linked", "sqlite-freespace-values.jsonl"));
    refused(await asJob(FREESPACE, cwd, { db, write_values: true }, "linked"));
    assert.equal(await exists(join(cwd, "elsewhere.jsonl")), false);
    // Nothing to find: the file is made, empty, 0600, and the answer says written 0.
    const clean = join(cwd, "work", "clean.db");
    await build(`import sqlite3, sys\ndb = sqlite3.connect(sys.argv[1])\ndb.execute("CREATE TABLE t (a TEXT)")\ndb.execute("INSERT INTO t VALUES ('live row text')")\ndb.commit()\n`, clean);
    const none = await freespace(cwd, clean, {}, "none");
    assert.equal(none.answer.secret_values.written, 0);
    assert.equal(none.answer.secret_values.contains_secret_values, false);
    assert.equal((await stat(join(none.out, "sqlite-freespace-values.jsonl"))).size, 0);
  });
});

test("sqlite_freespace withholds a path component shaped like a recovery password on every channel, and survives a name that is not UTF-8", async () => {
  await withCwd(async (cwd) => {
    const dir = join(cwd, "work", RECOVERY_NAME);
    await mkdir(dir, { recursive: true });
    const db = join(dir, "keyed.db");
    await build(FREEBLOCK_DB, db, "NAMED-DIR-MARKER", "utf-8");
    const { answer, run } = await freespace(cwd, db, { limit: 1, min_length: 4 });
    assert.equal(answer.db.includes(RECOVERY_NAME), false);
    assert.ok(answer.paths_withheld >= 1);
    assert.equal(run.stdout.includes(RECOVERY_NAME), false);
    for (const f of await filesUnder(join(cwd, "out"))) if (!f.path.endsWith("-values.jsonl")) assert.equal(f.data.includes(Buffer.from(RECOVERY_NAME)), false, f.path);
    // A missing file in that directory: the error does not print the name either.
    const missing = refused(await tool(FREESPACE, cwd, { db: join(dir, "nothing.db") }));
    assert.equal(JSON.stringify(missing).includes(RECOVERY_NAME), false);
    // A file name that is not UTF-8 reaches Python as a lone surrogate; nothing raises, and the output is plain ASCII.
    const odd = join(cwd, "work", "b\udcff.db");
    // A name that does not exist: the error prints the name as an escape, and the answer is plain ASCII JSON.
    const gone = await tool(FREESPACE, cwd, { db: odd });
    assert.equal(refused(gone).error, "no such file");
    assert.ok(/^[\x00-\x7f]*$/.test(gone.stdout), "a lone surrogate is escaped, not raised");
    // A name that does exist, where the filesystem takes such a name (macOS refuses it).
    const raw = Buffer.concat([Buffer.from(join(cwd, "work") + "/"), Buffer.from([0x62, 0xff, 0x2e, 0x64, 0x62])]);
    const made = await writeFile(raw, await readFile(db)).then(() => true, (e: NodeJS.ErrnoException) => { assert.equal(e.code, "EILSEQ"); return false; });
    if (made) {
      const out = await asJob(FREESPACE, cwd, { db: odd, write_values: true, limit: 1, min_length: 4 }, "out-odd");
      const oddAnswer = body<Free>(out);
      // Parsed, the escape \udcff is the lone surrogate itself; the text of the answer holds the escape.
      assert.ok(oddAnswer.db.endsWith("/b\udcff.db"), oddAnswer.db);
      assert.match(out.stdout, /b\\udcff\.db/);
      assert.ok(oddAnswer.fragment_count >= 1);
      assert.ok(/^[\x00-\x7f]*$/.test(out.stdout), "the answer is ASCII: a lone surrogate is escaped");
    }
  });
});

test("sqlite_freespace reads UTF-16 text at either byte parity in LE and BE, and does not report ASCII text as CJK", async () => {
  // Pairs were read from the start of the region only: a text that began on an odd byte was read as CJK units, and the
  // genuine word was in no fragment. Greek, Hebrew and Arabic were not found in a UTF-16BE database at all.
  await withCwd(async (cwd) => {
    const greek = "Καλημέρα κόσμε αυτό είναι δοκιμή";
    for (let pad = 0; pad < 4; pad++) {
      const text = greek + "x".repeat(pad);
      const db = join(cwd, "work", `le${pad}.db`);
      await build(FREEBLOCK_DB, db, text, "UTF-16le");
      const file = await readFile(db);
      const { values } = await freespace(cwd, db, {}, `out-le${pad}`);
      const found = values.find((v) => v.value.includes(text));
      assert.ok(found, `pad ${pad}: the Greek text is recovered whole, got ${JSON.stringify(values.map((v) => v.value))}`);
      assert.equal(found.encoding, "utf-16le");
      assert.equal(file.subarray(found.offset, found.offset + found.bytes).toString("utf16le"), found.value);
    }
    for (const [name, text] of [["greek", greek], ["hebrew", "שלום עולם זה מבחן של הטקסט"], ["arabic", "مرحبا بالعالم هذا اختبار للنص"], ["cyrillic", "Привет мир это проверка текста"]]) {
      const db = join(cwd, "work", `be-${name}.db`);
      await build(FREEBLOCK_DB, db, text, "UTF-16be");
      const file = await readFile(db);
      assert.equal(file.readUInt32BE(56), 3);
      const { answer, values } = await freespace(cwd, db, {}, `out-be-${name}`);
      assert.deepEqual(answer.encodings_scanned, ["utf-8", "utf-16be"]);
      const found = values.find((v) => v.value.includes(text));
      assert.ok(found, `${name}: recovered whole, got ${JSON.stringify(values.map((v) => v.value))}`);
      assert.equal(found.encoding, "utf-16be");
      assert.equal(Buffer.from(file.subarray(found.offset, found.offset + found.bytes)).swap16().toString("utf16le"), found.value);
    }
    // ASCII text in a UTF-16 database: found as ASCII, and no fragment of it is read as CJK or Hangul.
    const ascii = "plain ascii message text in a utf sixteen database";
    const db = join(cwd, "work", "ascii16.db");
    await build(FREEBLOCK_DB, db, ascii, "UTF-16le");
    const { values } = await freespace(cwd, db, { min_length: 4 }, "out-ascii16");
    assert.ok(values.some((v) => v.value.includes(ascii)));
    for (const v of values) {
      // A header byte beside the text may decode as one stray character; a fragment that is mostly CJK is a misreading.
      const cjk = [...v.value].filter((c) => /[\u3000-\u9fff\uac00-\ud7af]/.test(c)).length;
      assert.ok(cjk <= 2 && cjk < [...v.value].length / 4, `a CJK reading of ASCII bytes: ${v.value}`);
    }
  });
});

test("sqlite_freespace reads Armenian, Georgian, Devanagari, Thai and Vietnamese UTF-16 text too", async () => {
  await withCwd(async (cwd) => {
    const texts: [string, string][] = [
      ["armenian", "Բարեւ աշխարհ սա փորձնական տեքստ է"], ["georgian", "გამარჯობა მსოფლიო ეს სატესტო ტექსტია"],
      ["devanagari", "नमस्ते दुनिया यह एक परीक्षण संदेश है"], ["thai", "สวัสดีชาวโลก นี่คือข้อความทดสอบ"],
      ["vietnamese", "Xin chào thế giới đây là một thông điệp thử nghiệm ề ệ ố"],
    ];
    for (const [name, text] of texts) {
      const db = join(cwd, "work", `${name}.db`);
      await build(FREEBLOCK_DB, db, text, "UTF-16le");
      const { values } = await freespace(cwd, db, {}, `out-${name}`);
      assert.ok(values.some((v) => v.value.includes(text)), `${name} is recovered whole`);
    }
  });
});

test("sqlite_freespace says partial while a -wal or a -journal that holds bytes is not read", async () => {
  await withCwd(async (cwd) => {
    const db = join(cwd, "work", "wal.db");
    await build(FREEBLOCK_DB, db, "COMPANION-MARKER", "utf-8");
    assert.equal((await freespace(cwd, db, {}, "plain")).answer.status, "complete");
    await writeFile(db + "-wal", Buffer.alloc(64));
    const { answer } = await freespace(cwd, db, {}, "with-wal");
    assert.equal(answer.status, "partial");
    assert.ok(answer.problem_kinds["companion not examined"] >= 1);
    assert.deepEqual(answer.companions, { "-wal": { bytes: 64, examined: false } });
    // A companion with no bytes holds nothing to examine.
    await writeFile(db + "-wal", Buffer.alloc(0));
    assert.equal((await freespace(cwd, db, {}, "empty-wal")).answer.status, "complete");
  });
});

test("sqlite_freespace prints none of a file that is not SQLite, only its size and the entropy of its start", async () => {
  await withCwd(async (cwd) => {
    const file = join(cwd, "work", "notes.txt");
    await writeFile(file, "password=Tr0ub4dor&3 and the rest of a text file that is long enough to be a sample\n".repeat(40));
    const err = refused(await tool(FREESPACE, cwd, { db: file }));
    assert.match(err.error, /not a SQLite database/);
    const text = JSON.stringify(err);
    for (const form of ["password", Buffer.from("password").toString("hex"), "Tr0ub4"]) assert.equal(text.includes(form), false, form);
    assert.equal(err.head_hex, undefined);
    assert.equal(typeof err.entropy_bits_per_byte_of_first_4096, "number");
    // A file too short for the figure to be more than a statistic of its content gets none.
    const tiny = join(cwd, "work", "tiny.txt");
    await writeFile(tiny, "aaaaaaaaaaab");
    assert.equal(refused(await tool(FREESPACE, cwd, { db: tiny })).entropy_bits_per_byte_of_first_4096, null);
    assert.equal(err.bytes, 80 * 40 + 0 === 0 ? 0 : (await stat(file)).size);
  });
});

test("sqlite_freespace refuses a filter that backtracks or can cost much per start, so it cannot run for seconds on a fragment and never on another", async () => {
  // A filter that backtracks only when a lookahead holds ran 2 seconds on a fragment that held a guess and microseconds on one that did
  // not, and the answer counted the slow ones (scanned.contains_timeouts, problem_kinds): one bit about text nobody could see, per call.
  // Run against the code before the fix, the first expression is accepted and the run is slow. The bound is 256 steps: at 16,384 an
  // expression such as `\d(?:.?){10}Y` cost 1.75 s on a hidden region of digits and 0.05 s on one of letters.
  await withCwd(async (cwd) => {
    const db = join(cwd, "work", "regex.db");
    await build(FREELIST_DB, db, "REGEX-MARKER");
    const refusals: [string, RegExp][] = [
      ["^(?=.*token=Zq7K)(?:.*)*Y$", /lookahead and lookbehind/],
      ["(w+)+z", /unbounded repeat/],
      ["(w{1,8})+z", /unbounded repeat/],
      ["(w{1,8}){1,9}z", /nested repeat or an alternation/],
      ["(a|aa){1,30}$", /nested repeat or an alternation/],
      ["(a)\\1", /back references/],
      ["(?<=a)b", /lookahead and lookbehind/],
      ["x*", /unbounded repeat/],
      ["a.+b", /unbounded repeat/],
      ["a{5000}", /repeat count above 4096/],
      ["(?:ab|cd){12}c", /too many steps/],
      [".{0,63}.{0,63}z", /too many steps/],
      ["w".repeat(257), /at most 256 characters/],
      // What cost the most time on text the first element matches, now over the bound.
      ["\\d(?:.?){10}Y", /too many steps/],
      ["(?:a?){10}Z", /too many steps/],
      ["(?:\\d?){10}Y", /too many steps/],
      ["(?:[a-z]|\\d){4000}Q", /too many steps/],
      [["Zq7K", "(?:.?){10}Y"].join(""), /too many steps/],
      ["w{257}", /too many steps/],
    ];
    for (const [pattern, why] of refusals) {
      const err = refused(await asJob(FREESPACE, cwd, { db, write_values: true, contains: pattern, min_length: 20 }, "refused-" + sha256(pattern).slice(0, 8)));
      assert.match(err.error, why, pattern);
      assert.equal(err.contains_refused, true, pattern);
      assert.equal(err.fragments, undefined, "nothing was scanned: " + pattern);
    }
    // What people write for a token or a number is accepted, and marks the file.
    const free = await freespace(cwd, db, { min_length: 20 }, "all-regex");
    for (const pattern of ["REGEX-MARKER-0[0-9]{2}", "marker|nothing", "^REGEX", "[A-Z]{5}-[A-Z]{6}-[0-9]{3}", "w{200}", "(?:REGEX|XEGER)-MARKER", "colou?r|REGEX",
      "[A-Za-z0-9]{32}", "\\d{6}(?:-\\d{6}){7}", "[0-9a-f]{64}"]) {
      const run = await freespace(cwd, db, { contains: pattern, min_length: 20 }, "ok-" + sha256(pattern).slice(0, 8));
      assert.equal(run.answer.fragment_count, free.answer.fragment_count, pattern);
      assert.equal(run.rows.length, free.rows.length, pattern);
      assert.ok(run.values.length <= free.values.length, pattern);
    }
    assert.ok((await freespace(cwd, db, { contains: "REGEX-MARKER-0[0-9]{2}", min_length: 20 }, "n1")).values.length >= 1);
  });
});

test("sqlite_freespace writes a row for every fragment whatever contains asks, so the sealed file's size and digest answer nothing about the text", async () => {
  // contains used to decide which fragments were written, and the harness shows the requester a job output's byte count and sha256:
  // 299 bytes for a right prefix of a hidden token and 0 for a wrong one, 62 calls a character. The file is now one row per fragment,
  // `match` marks what the expression matched, and a random `run` makes every run's digest different.
  await withCwd(async (cwd) => {
    const secret = ["token", "=", "Zq7K", "p2mR9xT4"].join("");
    const db = join(cwd, "work", "oracle.db");
    await build(FREEBLOCK_DB, db, secret, "utf-8");
    const guesses: (string | undefined)[] = [undefined, "Zq7K", "Zq7J", "Zq7Kp2", "Zq7Kp3", "token=Zq7Kp2mR9xT4", "^$", ".", "[0-9]{4}", "(?:Zq7K|Zq7J)[a-z0-9]{2}"];
    const sizes = new Set<number>();
    const digests = new Set<string>();
    const runs = new Set<string>();
    const marks: Record<string, number> = {};
    let fragments = -1;
    for (const [i, contains] of guesses.entries()) {
      const r = await freespace(cwd, db, { min_length: 4, ...(contains ? { contains } : {}) }, `size-${i}`);
      const data = await readFile(join(r.out, "sqlite-freespace-values.jsonl"));
      sizes.add(data.length);
      digests.add(sha256(data));
      if (fragments < 0) fragments = r.answer.fragment_count;
      assert.equal(r.answer.fragment_count, fragments);
      assert.equal(r.rows.length, fragments, "a row for every fragment found");
      assert.equal(r.answer.secret_values.written, fragments, "the count is the fragments', never the matches'");
      assert.ok(r.rows.every((v) => [0, 1, 2].includes(v.match ?? -1)), "match is 0, 1 or 2 in every row");
      if (!contains) assert.ok(r.rows.every((v) => v.match === 1), "without an expression every row is 1");
      assert.equal(new Set(r.rows.map((v) => v.run)).size, 1, "one run id in the file");
      assert.match(r.rows[0].run ?? "", /^[0-9a-f]{16}$/);
      runs.add(r.rows[0].run ?? "");
      marks[contains ?? "(none)"] = r.rows.filter((v) => v.match === 1).length;
    }
    assert.equal(sizes.size, 1, `the file's size depends on the expression: ${[...sizes].join(", ")}`);
    assert.equal(digests.size, guesses.length, "a different digest in every run");
    assert.equal(runs.size, guesses.length);
    // The marks are the answer a reader of the file filters on: the right prefix marks the fragment, a wrong one marks none.
    assert.ok(marks["Zq7K"] >= 1 && marks["Zq7Kp2"] >= 1);
    assert.equal(marks["Zq7J"], 0);
    assert.equal(marks["Zq7Kp3"], 0);
    assert.equal(marks["(none)"], fragments);
    // Nothing of that is in the answer: the same answer, whatever the expression matched.
    const a = await freespace(cwd, db, { min_length: 4, contains: "Zq7K" }, "ans-a");
    const b = await freespace(cwd, db, { min_length: 4, contains: "Zq7J" }, "ans-b");
    const strip = (x: Free) => JSON.stringify({ ...x, filter: "-", pages: "-" });
    assert.equal(strip(a.answer), strip(b.answer));
  });
});

test("sqlite_freespace's size does not follow the expression for a UTF-16 fragment or one with characters JSON escapes either", async () => {
  await withCwd(async (cwd) => {
    const secret = ["pw", "=", "Ünï", "\"q7\\K", "p2\n", "你好"].join("");
    const db = join(cwd, "work", "escapes.db");
    await build(FREEBLOCK_DB, db, secret, "UTF-16le");
    const sizes = new Set<number>();
    for (const [i, contains] of [undefined, "q7", "nothing-like-it", "你好"].entries()) {
      const r = await freespace(cwd, db, { min_length: 4, ...(contains ? { contains } : {}) }, `esc-${i}`);
      sizes.add((await readFile(join(r.out, "sqlite-freespace-values.jsonl"))).length);
      assert.equal(r.rows.length, r.answer.fragment_count);
    }
    assert.equal(sizes.size, 1);
  });
});

/**
 * The tool with `linear_pattern` replaced by a plain re.compile (as if a pattern that backtracks had got past the check) and a short clock
 * for one fragment: what the second line of defence does. The args are on stdin; env and paths are on argv.
 */
const FREESPACE_UNCHECKED = String.raw`
import importlib.util, os, re, sys
sys.dont_write_bytecode = True      # the pack is sealed: no __pycache__ beside its tools
spec = importlib.util.spec_from_file_location("fs", sys.argv[1]); fs = importlib.util.module_from_spec(spec); spec.loader.exec_module(fs)
if hasattr(fs, "linear_pattern"):
    arity = len(fs.linear_pattern("a"))      # (pattern, reason) before the work budget, (pattern, reason, cost) after it
    fs.linear_pattern = lambda source: (re.compile(source, re.I), None) + ((1,) if arity == 3 else ())
fs.REGEX_SECONDS = 0.25
os.chdir(sys.argv[2])
os.environ.update(JOB_ID="j-1", OUT=sys.argv[3], SECRET_OUTPUT="1", AGENT_ID="s1")
os.makedirs(sys.argv[3], exist_ok=True)
fs.run_main(fs.main)
`;

test("sqlite_freespace marks a fragment its expression could not be decided on in the file, and the answer says partial", async () => {
  // Past the cost check, a pattern can still be slow. A fragment on which it ran out of time was written as if it had matched, with no
  // mark and no word in the answer, which said `complete`: a reader of the sealed file could not tell a match from an undecided row.
  await withCwd(async (cwd) => {
    const guess = ["token", "=", "Zq7K"].join("");
    const present = join(cwd, "work", "present.db");
    await build(FREEBLOCK_DB, present, guess + "p2mR9xT4", "utf-8");
    const slow = "^(?=.*" + guess + ")(?:.*)*Y$";
    const out = join(cwd, "unchecked-present");
    const run = await runPySnippet(FREESPACE_UNCHECKED, [FREESPACE, cwd, out], { db: present, write_values: true, contains: slow, min_length: 20 });
    const answer = body<Free>(run);
    const rows = await jsonl<Value>(join(out, "sqlite-freespace-values.jsonl"));
    assert.equal(rows.length, answer.fragment_count, "every fragment is a row");
    const undecided = rows.filter((v) => v.match === 2);
    assert.ok(undecided.length >= 1, "the fragment the expression ran out of time on is marked 2");
    assert.ok(undecided.some((v) => v.value.includes(guess)));
    assert.equal(answer.status, "partial", "the answer says it did not decide");
    assert.equal(answer.problem_kinds["contains not decided"], 1);
    assert.equal(answer.scanned.contains_not_decided, undecided.length);
    assert.match(answer.problems.find((p) => p.kind === "contains not decided")?.detail ?? "", /marked match 2/);
    assert.match(answer.status_basis ?? "", /not examined|partial/);
    // And the same file size as a run that decided everything.
    const quick = join(cwd, "unchecked-quick");
    const other = await runPySnippet(FREESPACE_UNCHECKED, [FREESPACE, cwd, quick], { db: present, write_values: true, contains: "no-such-text", min_length: 20 });
    assert.equal(body<Free>(other).status, "complete");
    assert.equal((await readFile(join(quick, "sqlite-freespace-values.jsonl"))).length, (await readFile(join(out, "sqlite-freespace-values.jsonl"))).length);
  });
});

/**
 * The real tool, with `timed_search` (the one call that runs the caller's expression) slowed by `argv[4]` seconds for every fragment,
 * and with the work budget replaced by `argv[5]` steps and the most the clock skips by `argv[6]` seconds when those are given: an
 * expression that takes time on text of one class and none on text of another, without depending on how fast the machine is.
 */
const FREESPACE_SLOW_EXPRESSION = String.raw`
import importlib.util, os, sys, time
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("fs", sys.argv[1]); fs = importlib.util.module_from_spec(spec); spec.loader.exec_module(fs)
delay = float(sys.argv[4])
inner = fs.timed_search
def slow(pattern, text, seconds):
    time.sleep(delay)
    return inner(pattern, text, seconds)
fs.timed_search = slow
if len(sys.argv) > 5 and hasattr(fs, "STEP_BUDGET"):
    fs.STEP_BUDGET = int(sys.argv[5])
if len(sys.argv) > 6 and hasattr(fs, "EXPRESSION_ALLOWANCE"):
    fs.EXPRESSION_ALLOWANCE = float(sys.argv[6])
os.chdir(sys.argv[2])
os.environ.update(JOB_ID="j-1", OUT=sys.argv[3], SECRET_OUTPUT="1", AGENT_ID="s1")
os.makedirs(sys.argv[3], exist_ok=True)
fs.run_main(fs.main)
`;

test("sqlite_freespace's status, its pages and its count of undecided fragments do not follow how long contains takes", async () => {
  // The time an expression took counted toward max_seconds, so the answer said `partial` with a count of pages not reached when the hidden text
  // was mostly of a class the expression is slow on, and `complete` when it was not: `\d{250}x` on 22 fragments of 60,000 characters, max_seconds
  // 0.5, was partial (1 undecided, 13 pages not reached) on digits and complete on letters, three runs in three, with no noise.
  await withCwd(async (cwd) => {
    const db = join(cwd, "work", "timing.db");
    await build(FREELIST_DB, db, "TIMING-MARKER");
    const answers: Free[] = [];
    for (const [i, delay] of [0, 0.08].entries()) {
      const out = join(cwd, `slow-${i}`);
      // 40 rows of 900 characters, one fragment each at least: with 0.08 s a fragment the expression runs 3 s or more, six times max_seconds.
      const run = await runPySnippet(FREESPACE_SLOW_EXPRESSION, [FREESPACE, cwd, out, String(delay)], { db, write_values: true, contains: "TIMING-MARKER-0[0-9]{2}", min_length: 20, max_seconds: 0.5 });
      answers.push(body<Free>(run));
    }
    const [quick, slow] = answers;
    assert.ok(quick.fragment_count >= 20, "enough fragments for the delay to add up");
    for (const answer of answers) {
      assert.equal(answer.status, "complete", answer.status_basis);
      assert.equal(answer.stopped_before_page, null);
      assert.equal(answer.scanned.pages_not_reached, 0);
      assert.equal(answer.scanned.contains_not_decided ?? 0, 0);
      assert.equal(answer.problem_kinds["time limit"], undefined);
    }
    const shape = (x: Free) => JSON.stringify({ status: x.status, scanned: x.scanned, problem_kinds: x.problem_kinds, stopped: x.stopped_before_page, n: x.fragment_count });
    assert.equal(shape(quick), shape(slow));
  });
});

test("sqlite_freespace gives contains a work budget in the sizes the answer shows, so what it cannot decide is the same on any text of those sizes", async () => {
  // Digits and letters of the same lengths in the same layout: an expression that is slow on one class and fast on the other leaves the same
  // undecided fragments, the same status and the same pages, because the budget is characters times the expression's cost bound, and the
  // pattern and the lengths are what the caller already has.
  await withCwd(async (cwd) => {
    const TEXTS = String.raw`
import random, sqlite3, sys
path, kind = sys.argv[1:3]
rng = random.Random(5)
alphabet = "0123456789" if kind == "digits" else "abcdefghijklmnopqrstuvwxyz"
db = sqlite3.connect(path)
db.execute("PRAGMA secure_delete = OFF")
db.execute("CREATE TABLE message (id INTEGER PRIMARY KEY, body TEXT)")
db.executemany("INSERT INTO message VALUES (?, ?)", [(i, "".join(rng.choice(alphabet) for _ in range(300 + 20 * i))) for i in range(1, 41)])
db.commit()
db.execute("DELETE FROM message")
db.commit()
db.close()
`;
    const pattern = "\\d{40}";      // cost bound 40 steps a character
    const results: { answer: Free; rows: Value[] }[] = [];
    let budget = 0;
    for (const kind of ["digits", "letters"]) {
      const db = join(cwd, "work", `${kind}.db`);
      await build(TEXTS, db, kind);
      if (!budget) {
        const probe = await freespace(cwd, db, { min_length: 20 }, "probe");
        const total = probe.answer.fragments.reduce((n, f) => n + f.characters * 40 + FRAGMENT_STEPS, 0);
        budget = Math.floor(total / 2);      // about half of the fragments fit
      }
      const out = join(cwd, `budget-${kind}`);
      const run = await runPySnippet(FREESPACE_SLOW_EXPRESSION, [FREESPACE, cwd, out, "0", String(budget)], { db, write_values: true, contains: pattern, min_length: 20 });
      const answer = body<Free>(run);
      results.push({ answer, rows: await jsonl<Value>(join(out, "sqlite-freespace-values.jsonl")) });
    }
    // What the visible sizes say: fragments in order, a running total of FRAGMENT_STEPS and characters times 40, and everything past the budget is undecided.
    let running = 0;
    const expected = results[0].answer.fragments.map((f) => { running += FRAGMENT_STEPS + f.characters * 40; return running > budget; });
    const overBudget = expected.filter(Boolean).length;
    assert.ok(overBudget > 3 && overBudget < expected.length - 3, `the budget splits the fragments (${overBudget} of ${expected.length})`);
    for (const { answer, rows } of results) {
      assert.deepEqual(rows.map((v) => v.match === 2), expected);
      assert.equal(answer.scanned.contains_not_decided, overBudget);
      assert.equal(answer.status, "partial");
      assert.equal(answer.problem_kinds["contains not decided"], 1);
      assert.match(answer.problems.find((p) => p.kind === "contains not decided")?.detail ?? "", /work its expression may do/);
      assert.equal(answer.stopped_before_page, null);
    }
    const [digits, letters] = results;
    const shape = (x: Free) => JSON.stringify({ status: x.status, status_basis: x.status_basis, undecided: x.scanned.contains_not_decided, not_reached: x.scanned.pages_not_reached,
      problem_kinds: x.problem_kinds, stopped: x.stopped_before_page, fragments: x.fragments.map((f) => [f.page, f.offset, f.bytes, f.characters, f.encoding]) });
    assert.equal(shape(digits.answer), shape(letters.answer));
    // And the expression ran where it was in budget: digits matched there, letters did not.
    assert.ok(digits.rows.filter((v) => v.match === 1).length >= 3);
    assert.equal(letters.rows.filter((v) => v.match === 1).length, 0);
  });
});

test("sqlite_freespace's contains marks the sealed values file, and nothing in the answer says which fragments matched", async () => {
  // The answer listed the fragments that matched and the total before the filter: with text you cannot see, one call was one bit of every
  // fragment, and an alternation of guesses confirmed a short PIN in a few calls. The expression now only marks the rows of the file.
  await withCwd(async (cwd) => {
    const db = join(cwd, "work", "wal.db");
    await build(FREEBLOCK_DB, db, "FILTER-MARKER-ONE", "utf-8");
    await writeFile(db + "-wal", Buffer.alloc(32));
    const all = await freespace(cwd, db, { min_length: 4 }, "all");
    const some = await freespace(cwd, db, { contains: "FILTER-MARKER", min_length: 4 }, "some");
    const none = await freespace(cwd, db, { contains: "no-such-text-anywhere", min_length: 4 }, "none");
    const everything = await freespace(cwd, db, { contains: ".", min_length: 4 }, "everything");
    assert.ok(all.answer.fragment_count > 1);
    // The same fragments, the same counts, whatever the expression matched.
    for (const other of [some, none, everything]) {
      assert.deepEqual(other.answer.fragments.map((f) => [f.finding_id, f.offset, f.bytes]), all.answer.fragments.map((f) => [f.finding_id, f.offset, f.bytes]));
      assert.equal(other.answer.fragment_count, all.answer.fragment_count);
      assert.deepEqual(other.answer.scanned, all.answer.scanned);
      assert.equal(other.answer.secret_values.written, all.answer.fragment_count, "the rows are every fragment, so the count says nothing");
      assert.match(other.answer.secret_values.rows_are_all_fragments ?? "", /how many matched is not shown/);
      assert.equal(other.rows.length, all.rows.length);
    }
    assert.equal(some.answer.filter, "FILTER-MARKER");
    assert.match(some.answer.filter_marks ?? "", /rows of the values file only/);
    // What the file marks is what matched.
    assert.ok(some.values.length >= 1 && some.values.length < all.values.length);
    assert.ok(some.values.every((v) => /FILTER-MARKER/i.test(v.value)));
    assert.deepEqual(some.rows.filter((v) => v.match === 1).map((v) => v.finding_id), some.values.map((v) => v.finding_id));
    assert.ok(some.rows.filter((v) => v.match === 0).every((v) => !/FILTER-MARKER/i.test(v.value)));
    assert.equal(none.values.length, 0);
    assert.equal(none.rows.every((v) => v.match === 0), true);
    assert.equal(everything.values.length, all.values.length);
    assert.deepEqual(some.answer.companions, { "-wal": { bytes: 32, examined: false } });
    assert.match(refused(await tool(FREESPACE, cwd, { db, contains: "(" })).error, /not a valid regex/);
    // contains with no values file to mark is refused before anything is scanned, outside a job and in one.
    const bare = refused(await tool(FREESPACE, cwd, { db, contains: "FILTER-MARKER" }));
    assert.match(bare.error, /contains narrows the sealed values file: it needs write_values: true/);
    assert.equal(bare.contains_refused, true);
    assert.equal(bare.fragments, undefined);
    const noValues = refused(await asJob(FREESPACE, cwd, { db, contains: ".", write_values: false }, "novalues"));
    assert.equal(noValues.contains_refused, true);
    assert.equal(noValues.fragment_count, undefined);
  });
});

test("sqlite_freespace and manifest_db print no FutureWarning for an expression that is a set inside a set", async () => {
  // re.compile warns (to stderr, with a position) about `[[:alpha:]]`; the warning is not an answer.
  await withCwd(async (cwd) => {
    const db = join(cwd, "work", "warn.db");
    await build(FREEBLOCK_DB, db, "WARN-MARKER", "utf-8");
    const free = await asJob(FREESPACE, cwd, { db, write_values: true, contains: "[[:alpha:]]{3}", min_length: 4 }, "warn-fs");
    assert.equal(free.code, 0, free.stdout);
    assert.equal(free.stderr, "");
    const dir = await backup(cwd, "warn-bk", { entries: [{ id: ID_A, path: "Library/a.db", blob: "none" }] });
    const m = await tool(MANIFEST, cwd, { path: dir, contains: "[[:alpha:]]{3}" });
    assert.equal(m.code, 0, m.stdout);
    assert.equal(m.stderr, "");
  });
});

test("sqlite_freespace's time limit is finite and below the tool's own, and says so as JSON", async () => {
  // NaN and Infinity switched the clock off, and a limit above the harness's 300 seconds ended the tool with no answer.
  await withCwd(async (cwd) => {
    const db = join(cwd, "work", "limit.db");
    await build(FREELIST_DB, db, "LIMIT-MARKER");
    for (const bad of ["NaN", "Infinity", "-Infinity", "1e308", "100000", "256", "0", "-1", "\"5\"", "true"]) {
      const r = await rawTool(FREESPACE, cwd, `{"db":${JSON.stringify(db)},"max_seconds":${bad}}`);
      assert.match(refused(r).error, /max_seconds/, bad);
    }
    const edge = await rawTool(FREESPACE, cwd, `{"db":${JSON.stringify(db)},"max_seconds":255}`);
    assert.equal(edge.code, 0, edge.stdout + edge.stderr);
  });
});

// --- manifest_db ----------------------------------------------------------------------

/**
 * A backup directory from a JSON spec. The Files table is Apple's (fileID, domain, relativePath, flags, file);
 * `file` is an NSKeyedArchiver archive: $archiver, $version, $top.root, and $objects ("$null", the root
 * dictionary with the metadata and a class UID, the class dictionary).
 */
const BACKUP = String.raw`
import datetime, json, os, plistlib, shutil, sqlite3, sys
UID = plistlib.UID
dest, spec = sys.argv[1], json.load(sys.stdin)

def conv(v):
    return float(v["float"]) if isinstance(v, dict) and "float" in v else v

def archive(e):
    objects = ["$null"]
    root = {"$class": UID(2), "Size": e.get("size", 10), "Mode": 33188, "UserID": 501, "GroupID": 501,
            "ProtectionClass": 4, "InodeNumber": 7}
    if e.get("pad"):
        root["Padding"] = b"\0" * e["pad"]      # a keyed archive of the given size: a hostile cell, not a real MBFile
    for key, name in (("birth", "Birth"), ("modified", "LastModified"), ("changed", "LastStatusChange")):
        if key in e:
            root[name] = e[key]
    if e.get("wrapped_key") or e.get("null_key"):
        root["EncryptionKey"] = UID(3)
    objects.append(root)
    objects.append({"$classname": "MBFile", "$classes": ["MBFile", "NSObject"]})
    if e.get("wrapped_key"):
        objects.append({"NS.data": bytes.fromhex(e["wrapped_key"])})
    elif e.get("null_key"):
        objects.append("$null")
    if e.get("decoy"):
        # An object with a Size that comes before the root: the first object holding Size is not the root.
        objects.insert(1, {"Size": 1, "Mode": 1})
        objects[2]["$class"] = UID(3)
        if e.get("wrapped_key"):
            objects[2]["EncryptionKey"] = UID(4)
        top = UID(2)
    else:
        top = UID(1)
    return plistlib.dumps({"$archiver": "NSKeyedArchiver", "$version": 100000, "$top": {"root": top}, "$objects": objects},
                          fmt=plistlib.FMT_BINARY)

os.makedirs(dest, exist_ok=True)
manifest = {"Version": "10.0", "Date": datetime.datetime(2025, 3, 1, 12, 0, 0), "WasPasscodeSet": True,
            "Lockdown": {"ProductVersion": "17.4", "SerialNumber": "SERIAL-FIXTURE", "DeviceName": "Fixture Phone"}}
if spec.get("encrypted") != "absent":
    manifest["IsEncrypted"] = spec.get("encrypted", False)
for k, v in spec.get("manifest_extra", {}).items():
    manifest[k] = conv(v)
if spec.get("keybag"):
    manifest["BackupKeyBag"] = bytes.fromhex(spec["keybag"])
    manifest["ManifestKey"] = bytes.fromhex(spec["manifest_key"])
if spec.get("manifest_plist", True):
    with open(os.path.join(dest, "Manifest.plist"), "wb") as fh:
        plistlib.dump(manifest, fh)
if spec.get("info", True):
    with open(os.path.join(dest, "Info.plist"), "wb") as fh:
        info = {"Device Name": "Fixture Phone", "Product Version": "17.4", "Serial Number": "SERIAL-FIXTURE", "Installed Applications": ["com.example.a"]}
        info.update({k: conv(v) for k, v in spec.get("info_extra", {}).items()})
        plistlib.dump(info, fh)
if spec.get("status_plist", True):
    with open(os.path.join(dest, "Status.plist"), "wb") as fh:
        plistlib.dump({"BackupState": "new", "IsFullBackup": True, "SnapshotState": spec.get("snapshot", "finished"), "UUID": "FIXTURE-UUID"}, fh)

db_path = os.path.join(dest, "Manifest.db")
if spec.get("manifest_db") == "notsqlite":
    # Deterministic bytes that are not a SQLite header: a counter pattern, not random bytes.
    with open(db_path, "wb") as fh:
        fh.write(bytes((i * 131 + 7) % 256 for i in range(8192)))
else:
    con = sqlite3.connect(db_path)
    if spec.get("wal"):
        con.execute("PRAGMA journal_mode = WAL")
        con.execute("PRAGMA wal_autocheckpoint = 0")
    con.execute("CREATE TABLE Files (fileID TEXT PRIMARY KEY, domain TEXT, relativePath TEXT, flags INTEGER, file BLOB)")
    con.execute("CREATE TABLE Properties (key TEXT PRIMARY KEY, value BLOB)")
    def add(e):
        blob = None if e.get("nometa") else archive(e)
        if e.get("rawpath_hex"):
            # TEXT whose bytes are not UTF-8 (CAST keeps the bytes as they are)
            con.execute("INSERT INTO Files VALUES (?,?,CAST(? AS TEXT),?,?)", (e["id"], e.get("domain", "HomeDomain"), bytes.fromhex(e["rawpath_hex"]), e.get("flags", 1), blob))
        else:
            con.execute("INSERT INTO Files VALUES (?,?,?,?,?)", (e["id"], e.get("domain", "HomeDomain"), e["path"], e.get("flags", 1), blob))
    for e in spec["entries"]:
        add(e)
        layout = e.get("blob", "sharded")
        if layout == "sharded":
            os.makedirs(os.path.join(dest, e["id"][:2]), exist_ok=True)
            with open(os.path.join(dest, e["id"][:2], e["id"]), "wb") as fh:
                fh.write(b"x" * e.get("size", 10))
        elif layout == "flat":
            with open(os.path.join(dest, e["id"]), "wb") as fh:
                fh.write(b"x" * e.get("size", 10))
        elif layout == "dir":
            os.makedirs(os.path.join(dest, e["id"][:2], e["id"]), exist_ok=True)
        elif layout.startswith("symlink:"):
            os.makedirs(os.path.join(dest, e["id"][:2]), exist_ok=True)
            os.symlink(layout[8:], os.path.join(dest, e["id"][:2], e["id"]))
    con.commit()
    if spec.get("wal"):
        # The rest is committed only in the WAL: copy the main file and the WAL while the connection is open.
        con.execute("PRAGMA wal_checkpoint(FULL)")
        for e in spec["wal"]:
            add(e)
        con.commit()
        shutil.copy(db_path, db_path + ".main")
        shutil.copy(db_path + "-wal", db_path + ".walcopy")
        con.close()
        for suffix in ("", "-wal", "-shm"):
            if os.path.exists(db_path + suffix):
                os.remove(db_path + suffix)
        os.rename(db_path + ".main", db_path)
        os.rename(db_path + ".walcopy", db_path + "-wal")
    else:
        con.close()
`;

type Entry = {
  file_id: string; file_id_valid: boolean; domain: string; relative_path: string; flags: number; kind: string; blob: string;
  blob_layout?: string; blob_bytes?: number; on_disk?: string; metadata_status: string; metadata_reason?: string;
  size?: number; created?: string | null; created_raw?: number; modified?: string | null; modified_raw?: number;
  changed?: string | null; has_wrapped_file_key?: boolean; payload_encrypted: boolean | null; manifest_rowid?: number;
};
type Manifest = {
  path: string; parser: string; status: string; status_basis?: string; encrypted: boolean | null;
  encryption: { state: string; basis: string; payload_encrypted: boolean | null; key_material_in_manifest_plist: Record<string, { present: boolean; bytes: number | null; printed: boolean }>; decryption: string };
  manifest_plist: Record<string, unknown>; info_plist: Record<string, unknown>; status_plist: Record<string, unknown>; device: Record<string, unknown>;
  manifest_db_file: { bytes: number; format: string; entropy_bits_per_byte_of_first_4096?: number; companions: Record<string, number>; snapshot?: string; working_copy?: string };
  listing: { available: boolean; reason: string | null }; observations: string[]; read_error: string | null;
  epoch: { applied: string; range_of_values_read: Record<string, { earliest: string | null; latest: string | null; values: number; zero_values_left_out: number }> };
  counts: { files_in_manifest: number | null; rows_read: number; rows_matching: number; invalid_file_ids: number; metadata: Record<string, number>; blobs: Record<string, number>; layouts: Record<string, number> };
  stopped_at_row: number | null; entries: Entry[]; entry_count: number; files_in_manifest: number | null; domains: { domain: string; entries: number }[];
  pages: { entries: Paged; domains: Paged }; truncated: boolean; paths_withheld: number;
};

const ID_A = "3d0d7e5fb2ce288813306e4d4636395e047a3d28";
const ID_B = "aa" + "0".repeat(38);
const ID_C = "bb" + "1".repeat(38);

async function backup(cwd: string, name: string, spec: Record<string, unknown>): Promise<string> {
  const dir = join(cwd, "work", name);
  // The spec goes in on stdin: one argv string is capped at 128 KiB on Linux, and 1,500 entries are 149 KB.
  const out = await runPySnippet(BACKUP, [dir], spec);
  assert.equal(out.code, 0, out.stderr);
  return dir;
}

async function manifest(cwd: string, path: string, args: Record<string, unknown> = {}): Promise<{ answer: Manifest; run: Run }> {
  const run = await tool(MANIFEST, cwd, { path, ...args });
  return { answer: body<Manifest>(run), run };
}

test("manifest_db converts times by the epoch it is told, never by a window that moves with the calendar", async () => {
  // It tried the Unix epoch and then the Apple one and kept the first whose year was in 2005..now+2: a Unix time
  // from 2004 read as null, and the same value read differently as the years passed.
  await withCwd(async (cwd) => {
    const dir = await backup(cwd, "times", { entries: [
      { id: ID_A, path: "Library/a.db", birth: 1100000000, modified: 700000000, changed: 1700000000 },
    ] });
    const unix = (await manifest(cwd, dir)).answer;
    const a = unix.entries[0];
    assert.equal(a.created, "2004-11-09T11:33:20Z", "a Unix time before 2005 is still a Unix time");
    assert.equal(a.created_raw, 1100000000);
    assert.equal(a.modified, "1992-03-07T20:26:40Z");
    assert.equal(a.changed, "2023-11-14T22:13:20Z");
    assert.equal(unix.epoch.applied, "unix");
    assert.equal(unix.epoch.range_of_values_read.modified.earliest, "1992-03-07T20:26:40Z");
    // Told the Apple epoch, it counts from 2001-01-01: 700000000 s is 2023-03-08T20:26:40Z.
    const apple = (await manifest(cwd, dir, { epoch: "apple" })).answer.entries[0];
    assert.equal(apple.modified, "2023-03-08T20:26:40Z");
    assert.equal(apple.modified_raw, 700000000);
    assert.match(refused(await tool(MANIFEST, cwd, { path: dir, epoch: "windows" })).error, /epoch must be/);
  });
});

/** Damage a Manifest.db the way a cut or a bad sector does: zero the page that holds a b-tree, or cut bytes off its end. */
const DAMAGE = String.raw`
import os, sqlite3, sys
path, what = sys.argv[1], sys.argv[2]
if what.startswith("zero:"):
    name = what[5:]
    con = sqlite3.connect(path)
    root = con.execute("SELECT rootpage FROM sqlite_master WHERE name = ?", (name,)).fetchone()[0]
    page_size = con.execute("PRAGMA page_size").fetchone()[0]
    con.close()
    with open(path, "r+b") as fh:
        fh.seek((root - 1) * page_size)
        fh.write(b"\0" * page_size)
elif what.startswith("cut:"):
    size = os.path.getsize(path)
    with open(path, "r+b") as fh:
        fh.truncate(size - int(what[4:]))
`;

function many(count: number, make: (i: number) => Record<string, unknown> = () => ({})): Record<string, unknown>[] {
  return Array.from({ length: count }, (_, i) => ({ id: i.toString(16).padStart(40, "0"), path: `Library/file-${String(i).padStart(4, "0")}.db`, ...make(i) }));
}

test("manifest_db lists every row when the index on the file id is damaged, and says partial when the file is cut short", async () => {
  // count(*) and the ordered scan went through the file-id index: one bad page of it lost the whole listing, which the table itself still held.
  // A file cut inside its last page was read with zeros for the rest of the page, and a row there came back as nothing, under `complete`.
  await withCwd(async (cwd) => {
    const dir = await backup(cwd, "badindex", { entries: many(60) });
    const db = join(dir, "Manifest.db");
    assert.equal((await runPySnippet(DAMAGE, [db, "zero:sqlite_autoindex_Files_1"], null)).code, 0);
    const damaged = (await manifest(cwd, dir)).answer;
    assert.equal(damaged.listing.available, true, JSON.stringify(damaged.listing));
    assert.equal(damaged.read_error, null);
    assert.equal(damaged.files_in_manifest, 60);
    assert.equal(damaged.entry_count, 60);
    assert.equal(damaged.status, "complete");
    // Cut inside the last page, and by a whole page: both say so.
    const bigger = await backup(cwd, "cutpage", { entries: many(400, (i) => ({ path: `Library/Deep/${"x".repeat(60)}/file-${i}.db` })) });
    const size = (await stat(join(bigger, "Manifest.db"))).size;
    assert.ok(size > 3 * 4096, `${size}`);
    assert.equal((await runPySnippet(DAMAGE, [join(bigger, "Manifest.db"), "cut:100"], null)).code, 0);
    const cut = (await manifest(cwd, bigger)).answer;
    assert.equal(cut.status, "partial", JSON.stringify(cut.observations));
    assert.ok(cut.observations.some((o) => /ends \d+ bytes into a page of 4096: the last page is cut short/.test(o)), cut.observations.join("\n"));
    const whole = await backup(cwd, "cutwhole", { entries: many(400, (i) => ({ path: `Library/Deep/${"x".repeat(60)}/file-${i}.db` })) });
    assert.equal((await runPySnippet(DAMAGE, [join(whole, "Manifest.db"), "cut:4096"], null)).code, 0);
    // SQLite itself refuses a file with fewer pages than its header declares: nothing is listed, and it is not an empty backup.
    const missing = refused(await tool(MANIFEST, cwd, { path: whole }));
    assert.match(missing.error, /Manifest\.db would not open as SQLite/);
    assert.match(String(missing.note), /not an empty backup/);
  });
});

test("manifest_db stops at max_seconds even when contains backtracks on every path, and says which rows it could not match", async () => {
  // The expression was bounded neither per row nor by the clock that max_seconds sets: a few paths of a runaway expression ran for minutes.
  await withCwd(async (cwd) => {
    const dir = await backup(cwd, "slowrx", { entries: many(60, () => ({ path: `Library/${"a".repeat(31)}b` })) });
    const started = Date.now();
    const { answer } = await manifest(cwd, dir, { contains: "(a|aa)+$", max_seconds: 3 });
    assert.ok(Date.now() - started < 20000, `took ${Date.now() - started} ms`);
    assert.equal(answer.status, "partial");
    // The stop is in the observations whether the deadline fell inside a row's expression or between two rows (it was only said in the first
    // case, and the test failed on CI whenever the three seconds ended between rows).
    assert.notEqual(answer.stopped_at_row, null);
    assert.ok(answer.observations.some((o) => /max_seconds \(3\) passed after \d+ rows: the rest of the Files table is not listed/.test(o)), answer.observations.join("\n"));
    for (const bad of ["NaN", "Infinity", "1e308", "100000", "0", "-1"]) {
      const r = await rawTool(MANIFEST, cwd, `{"path":${JSON.stringify(dir)},"max_seconds":${bad}}`);
      assert.match(refused(r).error, /max_seconds/, bad);
    }
  });
});

test("manifest_db judges whether the backup finished from Status.plist, and says unknown when it cannot", async () => {
  // Status.plist was read and never judged: a backup that stopped partway was listed under `complete`, and the pack's README said it was reported.
  await withCwd(async (cwd) => {
    const entries = many(3);
    const done = (await manifest(cwd, await backup(cwd, "snap-finished", { entries, snapshot: "finished" }))).answer;
    assert.deepEqual((done as unknown as { completion: { state: string } }).completion.state, "finished");
    assert.equal(done.status, "complete");
    const partway = (await manifest(cwd, await backup(cwd, "snap-new", { entries, snapshot: "uploadingFiles" }))).answer;
    const completion = (partway as unknown as { completion: { state: string; basis: string } }).completion;
    assert.equal(completion.state, "not_finished");
    assert.match(completion.basis, /SnapshotState is "uploadingFiles"/);
    assert.equal(partway.status, "partial");
    assert.ok(partway.observations.some((o) => /completion state is not finished .*do not read the listing as a finished backup/.test(o)), partway.observations.join("\n"));
    // No Status.plist at all (an iTunes backup has none): unknown, noted, and not by itself a failure.
    const none = await backup(cwd, "snap-none", { entries, snapshot: "finished" });
    await rm(join(none, "Status.plist"));
    const unknown = (await manifest(cwd, none)).answer;
    assert.equal((unknown as unknown as { completion: { state: string } }).completion.state, "unknown");
    assert.equal(unknown.status, "complete");
    assert.ok(unknown.observations.some((o) => /completion state is unknown/.test(o)));
  });
});

test("manifest_db says when times under the epoch applied fall after the backup's date or before 2007, without choosing an epoch", async () => {
  await withCwd(async (cwd) => {
    const dir = await backup(cwd, "consistency", { entries: [
      { id: ID_A, path: "Library/future.db", modified: 1900000000 },        // 2030-03-17: after the backup's date, 2025-03-01
      { id: ID_B, path: "Library/old.db", modified: 1100000000 },           // 2004
      { id: ID_C, path: "Library/fine.db", modified: 1700000000 },
    ] });
    const { answer } = await manifest(cwd, dir);
    const epoch = answer.epoch as unknown as { applied: string; consistency: { backup_date: string | null; after_backup_date: Record<string, number>; before_2007_01_01: Record<string, number>; note: string } };
    assert.equal(epoch.applied, "unix");
    assert.equal(epoch.consistency.backup_date, "2025-03-01T12:00:00Z");
    assert.deepEqual(epoch.consistency.after_backup_date, { modified: 1 });
    assert.deepEqual(epoch.consistency.before_2007_01_01, { modified: 1 });
    assert.match(epoch.consistency.note, /31-year shift/);
    assert.ok(answer.observations.some((o) => /some times fall after the backup's own date or before 2007: see epoch\.consistency/.test(o)), answer.observations.join("\n"));
    // Told the Apple epoch, the same numbers fall elsewhere (a 31-year shift); the tool does not pick between them.
    const apple = (await manifest(cwd, dir, { epoch: "apple" })).answer.epoch as unknown as { applied: string; consistency: { after_backup_date: Record<string, number> } };
    assert.equal(apple.applied, "apple");
    assert.deepEqual(apple.consistency.after_backup_date, { modified: 3 }, "as seconds from 2001 all three fall in 2035..2061");
  });
});

test("manifest_db reads the keyed archive's root, not the first object that has a Size", async () => {
  await withCwd(async (cwd) => {
    const dir = await backup(cwd, "root", { entries: [
      { id: ID_A, path: "Library/sms.db", size: 1234, modified: 1710000000, decoy: true },
    ] });
    const { answer } = await manifest(cwd, dir);
    const e = answer.entries[0];
    assert.equal(e.size, 1234, "the root's Size, not the decoy's 1");
    assert.equal(e.metadata_status, "ok");
    assert.equal(e.modified, "2024-03-09T16:00:00Z");
  });
});

test("manifest_db says unknown when Manifest.plist has no IsEncrypted, and never reads it as unencrypted", async () => {
  await withCwd(async (cwd) => {
    const entries = [{ id: ID_A, path: "Library/sms.db" }];
    const noFlag = (await manifest(cwd, await backup(cwd, "noflag", { encrypted: "absent", entries }))).answer;
    assert.equal(noFlag.encrypted, null, "a missing flag is not false");
    assert.equal(noFlag.encryption.state, "unknown");
    assert.match(noFlag.encryption.basis, /no IsEncrypted/);
    assert.equal(noFlag.entries[0].payload_encrypted, null);
    const noPlist = (await manifest(cwd, await backup(cwd, "noplist", { manifest_plist: false, entries }))).answer;
    assert.equal(noPlist.encryption.state, "unknown");
    assert.match(noPlist.encryption.basis, /missing/);
    assert.equal(noPlist.manifest_plist.status, "missing");
    const clear = (await manifest(cwd, await backup(cwd, "clear", { encrypted: false, entries }))).answer;
    assert.equal(clear.encryption.state, "not_encrypted");
    assert.equal(clear.encrypted, false);
  });
});

test("manifest_db lists an encrypted backup's manifest instead of reporting it empty, and says what is encrypted", async () => {
  await withCwd(async (cwd) => {
    const dir = await backup(cwd, "enc", { encrypted: true, entries: [
      { id: ID_A, path: "Library/SMS/sms.db", size: 4096, wrapped_key: "00112233445566778899aabbccddeeff" },
      { id: ID_B, path: "Library/Notes/notes.sqlite", size: 77 },
    ] });
    const { answer } = await manifest(cwd, dir);
    assert.equal(answer.entry_count, 2, "an encrypted backup's manifest is listed, not reported empty");
    assert.equal(answer.encrypted, true);
    assert.equal(answer.encryption.state, "encrypted");
    assert.equal(answer.encryption.payload_encrypted, true);
    assert.match(answer.encryption.decryption, /not provided/);
    assert.equal(answer.listing.available, true);
    assert.ok(answer.entries.every((e) => e.payload_encrypted === true));
    assert.equal(answer.entries.find((e) => e.file_id === ID_A)?.has_wrapped_file_key, true);
    assert.equal(answer.status, "complete");
  });
});

test("manifest_db says so when an encrypted backup's Manifest.db is not SQLite: nothing listed, and not an empty phone", async () => {
  await withCwd(async (cwd) => {
    const dir = await backup(cwd, "encdb", { encrypted: true, manifest_db: "notsqlite", entries: [] });
    const { answer } = await manifest(cwd, dir);
    assert.equal(answer.status, "partial");
    assert.equal(answer.encrypted, true);
    assert.equal(answer.listing.available, false);
    assert.match(answer.listing.reason ?? "", /not a plaintext SQLite database/);
    assert.equal(answer.files_in_manifest, null, "not 0: the count is unknown");
    assert.equal(answer.manifest_db_file.format, "not a plaintext SQLite database");
    assert.ok(answer.observations.some((o) => /consistent with an encrypted backup/.test(o)));
    // The flag says unencrypted and the file is not SQLite: the two disagree, and it is said.
    const odd = (await manifest(cwd, await backup(cwd, "disagree", { encrypted: false, manifest_db: "notsqlite", entries: [] }))).answer;
    assert.ok(odd.observations.some((o) => /disagree/.test(o)));
    assert.equal(odd.status, "partial");
  });
});

test("manifest_db never joins a file id that is not 40 hex digits to a path, and reports the blob states without following a link", async () => {
  // fileID "../x" became <root>/../../x, and a file there was reported as the entry's on_disk.
  await withCwd(async (cwd) => {
    const outside = join(cwd, "work", "outside-secret-file");
    await writeFile(outside, "outside the backup");
    const dir = await backup(cwd, "ids", { entries: [
      { id: ID_A, path: "Library/present.db", blob: "sharded" },
      { id: ID_B, path: "Library/flat.db", blob: "flat" },
      { id: ID_C, path: "Library/missing.db", blob: "none" },
      { id: "cc" + "2".repeat(38), path: "Library/dir.db", blob: "dir" },
      { id: "dd" + "3".repeat(38), path: "Library/link.db", blob: "symlink:" + outside },
      { id: "../x", path: "Library/evil.db", blob: "none" },
      { id: "ee" + "4".repeat(38), path: "Library", flags: 2, blob: "none" },
    ] });
    // The id "../x" joined as <root>/../../x is <run dir>/x: a file there is where the old code said the blob was.
    await writeFile(join(cwd, "x"), "decoy");
    const { answer } = await manifest(cwd, dir);
    const by = Object.fromEntries(answer.entries.map((e) => [e.relative_path, e]));
    assert.equal(by["Library/evil.db"].on_disk, undefined, "an id of ../x is never joined to a path");
    assert.equal(by["Library/evil.db"].blob, "refused");
    assert.equal(by["Library/present.db"].blob, "present");
    assert.equal(by["Library/present.db"].blob_layout, "sharded");
    assert.equal(by["Library/present.db"].on_disk, `${ID_A.slice(0, 2)}/${ID_A}`);
    assert.equal(by["Library/flat.db"].blob, "present");
    assert.equal(by["Library/flat.db"].blob_layout, "flat");
    assert.equal(by["Library/flat.db"].on_disk, ID_B);
    assert.equal(by["Library/missing.db"].blob, "missing");
    assert.equal(by["Library/dir.db"].blob, "directory");
    assert.equal(by["Library/link.db"].blob, "symlink");
    assert.equal(by["Library/evil.db"].blob, "refused");
    assert.equal(by["Library/evil.db"].file_id_valid, false);
    assert.equal(by["Library/evil.db"].on_disk, undefined);
    assert.equal(by["Library"].blob, "not_applicable");
    assert.equal(answer.counts.invalid_file_ids, 1);
    assert.equal(answer.counts.layouts.sharded, 1);
    assert.equal(answer.counts.layouts.flat, 1);
  });
});

test("manifest_db opens a Manifest.db with a -wal in a working copy, so a row only the WAL holds is listed, and leaves the original alone", async () => {
  await withCwd(async (cwd) => {
    const dir = await backup(cwd, "wal", {
      entries: [{ id: ID_A, path: "Library/in-main.db" }],
      wal: [{ id: ID_B, path: "Library/only-in-wal.db" }],
    });
    const before = [sha256(await readFile(join(dir, "Manifest.db"))), sha256(await readFile(join(dir, "Manifest.db-wal")))];
    const { answer } = await manifest(cwd, dir);
    const paths = answer.entries.map((e) => e.relative_path).sort();
    assert.deepEqual(paths, ["Library/in-main.db", "Library/only-in-wal.db"]);
    assert.match(answer.manifest_db_file.snapshot ?? "", /working directory/);
    assert.ok(answer.manifest_db_file.working_copy);
    assert.deepEqual([sha256(await readFile(join(dir, "Manifest.db"))), sha256(await readFile(join(dir, "Manifest.db-wal")))], before);
    assert.equal(await exists(join(dir, "Manifest.db-shm")), false, "the original has no -shm made beside it");
    // As a job the working copy is under $OUT, the only place a job writes.
    const before2 = await readdir(join(cwd, "work", "s1", "tool-output"));
    const run = await asJob(MANIFEST, cwd, { path: dir }, "job-wal");
    const inJob = body<Manifest>(run);
    assert.deepEqual(await readdir(join(cwd, "work", "s1", "tool-output")), before2, "a job writes nothing outside $OUT");
    assert.ok((inJob.manifest_db_file.working_copy ?? "").startsWith(join(cwd, "job-wal", "tool-output")), "the working copy is under $OUT");
    assert.equal(inJob.entry_count, 2);
  });
});

test("manifest_db prints no key material: the key bag and the manifest key are presence and a length", async () => {
  await withCwd(async (cwd) => {
    const keybag = Buffer.from(Array.from({ length: 96 }, (_, i) => (i * 41 + 3) % 251));
    const manifestKey = Buffer.from(Array.from({ length: 44 }, (_, i) => (i * 17 + 9) % 253));
    const wrapped = Buffer.from(Array.from({ length: 40 }, (_, i) => (i * 29 + 5) % 247));
    const dir = await backup(cwd, "keys", { encrypted: true, keybag: keybag.toString("hex"), manifest_key: manifestKey.toString("hex"),
      entries: [{ id: ID_A, path: "Library/a.db", wrapped_key: wrapped.toString("hex") }, { id: ID_B, path: "Library/b.db", wrapped_key: wrapped.toString("hex") }] });
    const { answer, run } = await manifest(cwd, dir, { limit: 1 });
    assert.deepEqual(answer.encryption.key_material_in_manifest_plist, {
      BackupKeyBag: { present: true, bytes: 96, printed: false },
      ManifestKey: { present: true, bytes: 44, printed: false },
    });
    for (const secret of [keybag, manifestKey, wrapped]) {
      for (const form of [secret.toString("hex"), secret.toString("base64"), sha256(secret)]) {
        assert.equal(run.stdout.includes(form), false, "key material (or an encoding or digest of it) is in the answer");
        assert.equal(run.stdout.includes(form.slice(0, 16)), false, "a head of key material is in the answer");
      }
    }
    assert.doesNotMatch(run.stdout, /[0-9a-f]{64}/i, "no digest");
    // And in the file that holds the whole listing: the answer names it, and it holds every entry.
    for (const secret of [keybag, manifestKey, wrapped]) {
      for (const text of [secret.toString("hex"), secret.toString("base64")]) await assertNowhere(text, run.stdout, join(cwd, "work", "s1"), []);
    }
    assert.equal((await jsonl<Entry>(join(cwd, answer.pages.entries.all_results!))).length, 2);
    // The device identity that Manifest.plist and Info.plist carry in the clear is there.
    assert.equal(answer.device.SerialNumber, "SERIAL-FIXTURE");
    assert.equal(answer.info_plist["Device Name"], "Fixture Phone");
    assert.equal(answer.status_plist.SnapshotState, "finished");
    assert.equal(answer.manifest_plist.WasPasscodeSet, true);
  });
});

test("manifest_db prints strict JSON whatever the plists hold, and one row it cannot decode does not stop the listing", async () => {
  // NaN and Infinity in a plist reached the answer as NaN and Infinity, which JSON does not have; a TEXT cell that is
  // not UTF-8 stopped the whole listing with an error that quoted the path.
  await withCwd(async (cwd) => {
    const dir = await backup(cwd, "strict", {
      manifest_extra: { Version: { float: "nan" } },
      info_extra: { "Phone Number": { float: "nan" }, "Serial Number": { float: "inf" } },
      entries: [
        { id: ID_A, path: "Library/ok.db", blob: "none", birth: 0, modified: 1700000000 },
        { id: ID_B, path: "unused", rawpath_hex: Buffer.from("Library/caf\xff/notes.txt", "latin1").toString("hex"), blob: "none", flags: 1 },
        { id: ID_C, path: "Library/odd.db", blob: "none" },
      ],
    });
    const { answer, run } = await manifest(cwd, dir);
    assert.doesNotThrow(() => JSON.parse(run.stdout));
    assert.doesNotMatch(run.stdout, /\bNaN\b|Infinity/);
    assert.deepEqual(answer.manifest_plist.Version, { _float: "nan" });
    assert.deepEqual(answer.info_plist["Serial Number"], { _float: "inf" });
    assert.equal(answer.entry_count, 3, "every row is listed");
    assert.ok(answer.entries.some((e) => e.relative_path === "Library/caf\udcff/notes.txt"), JSON.stringify(answer.entries.map((e) => e.relative_path)));
    assert.equal(answer.status, "complete");
    // A zero time is converted and returned, and left out of the range that shows a wrong epoch.
    assert.equal(answer.epoch.range_of_values_read.created.zero_values_left_out, 1);
    assert.equal(answer.epoch.range_of_values_read.created.values, 0);
    assert.equal(answer.epoch.range_of_values_read.modified.earliest, "2023-11-14T22:13:20Z");
  });
});

test("manifest_db says partial, with what it read, when a page of Manifest.db is damaged", async () => {
  await withCwd(async (cwd) => {
    const entries = Array.from({ length: 1500 }, (_, i) => ({ id: i.toString(16).padStart(40, "0"), path: `Library/p${String(i).padStart(5, "0")}`, blob: "none", size: i }));
    const dir = await backup(cwd, "damaged", { entries });
    const file = await readFile(join(dir, "Manifest.db"));
    const pageSize = file.readUInt16BE(16) === 1 ? 65536 : file.readUInt16BE(16);
    // The third leaf page of the table (type 13) is overwritten with a byte that is no page type.
    let leaves = 0;
    for (let p = 2; p <= file.length / pageSize; p++) {
      if (file[(p - 1) * pageSize] === 13 && ++leaves === 3) file.fill(0xff, (p - 1) * pageSize, (p - 1) * pageSize + 64);
    }
    assert.ok(leaves >= 3, "the fixture has several leaf pages");
    await writeFile(join(dir, "Manifest.db"), file);
    const run = await tool(MANIFEST, cwd, { path: dir });
    const answer = body<Manifest>(run);
    assert.equal(answer.status, "partial");
    assert.match(answer.read_error ?? "", /DatabaseError|OperationalError/);
    assert.ok(answer.counts.rows_read < 1500 && answer.counts.rows_read > 0, `rows_read ${answer.counts.rows_read}`);
    assert.equal(answer.entries.length + 0 > 0, true);
    assert.doesNotMatch(run.stdout, /Library\/p\d+.*malformed/s, "the error does not quote a row");
    // No hidden temporary file is left in the tool-output directory: every file is named in the answer.
    const kept = join(cwd, "work", "s1", "tool-output");
    const names = (await exists(kept)) ? await readdir(kept) : [];
    assert.ok(names.every((n) => !n.startsWith(".")), names.join());
  });
});

test("manifest_db does not follow a Manifest.db that is a link, or a -wal that is one", async () => {
  await withCwd(async (cwd) => {
    const outside = join(cwd, "work", "outside.txt");
    await writeFile(outside, "root:x:0:0:secret text that is not a database\n".repeat(30));
    const dir = await backup(cwd, "links", { entries: [{ id: ID_A, path: "Library/a.db", blob: "none" }] });
    await symlink(outside, join(dir, "Manifest.db-wal"));
    const { answer } = await manifest(cwd, dir);
    assert.ok(answer.observations.some((o) => /Manifest\.db-wal is a symbolic link: not followed/.test(o)));
    assert.equal(answer.status, "partial", "a companion that was not applied makes the listing partial");
    assert.equal(answer.manifest_db_file.snapshot?.startsWith("the main file only"), true);
    assert.equal(answer.entry_count, 1);
    // A Manifest.db that is a link: refused, and nothing of the target is printed.
    const linked = await backup(cwd, "links2", { entries: [] });
    await (await import("node:fs/promises")).rm(join(linked, "Manifest.db"));
    await symlink(outside, join(linked, "Manifest.db"));
    const err = refused(await tool(MANIFEST, cwd, { path: linked }));
    assert.match(err.error, /symbolic link/);
    assert.equal(JSON.stringify(err).includes("root:x"), false);
    assert.equal(JSON.stringify(err).includes(Buffer.from("root:x").toString("hex")), false);
  });
});

test("manifest_db prints no byte of a Manifest.db that is not SQLite, and a key id shaped like a recovery password is withheld", async () => {
  await withCwd(async (cwd) => {
    const dir = await backup(cwd, "notsql", { encrypted: true, manifest_db: "notsqlite", entries: [] });
    const { answer, run } = await manifest(cwd, dir);
    assert.equal(answer.manifest_db_file.format, "not a plaintext SQLite database");
    assert.equal(typeof answer.manifest_db_file.entropy_bits_per_byte_of_first_4096, "number");
    assert.doesNotMatch(run.stdout, /head_hex/);
    const named = await backup(cwd, "shaped", { entries: [{ id: RECOVERY_NAME, path: "Library/x.db", blob: "none" }, { id: ID_A, path: "Library/y.db", blob: "none", null_key: true }] });
    const got = await manifest(cwd, named, { limit: 1 });
    assert.equal(got.run.stdout.includes(RECOVERY_NAME), false);
    for (const f of await filesUnder(join(cwd, "work", "s1"))) assert.equal(f.data.includes(Buffer.from(RECOVERY_NAME)), false, f.path);
    // A key that is a reference to $null is no key.
    const rows = await jsonl<Entry>(join(cwd, got.answer.pages.entries.all_results!));
    assert.equal(rows.find((r) => r.relative_path === "Library/y.db")?.has_wrapped_file_key, false);
  });
});

test("manifest_db keeps the whole listing: a page inline, every entry in the file the answer names, in a stable order", async () => {
  await withCwd(async (cwd) => {
    const entries = Array.from({ length: 450 }, (_, i) => ({ id: i.toString(16).padStart(40, "0"), path: `Library/p${String(i).padStart(4, "0")}`, domain: `Domain-${String(i % 9).padStart(2, "0")}`, blob: "none" }));
    const dir = await backup(cwd, "many", { entries });
    const { answer } = await manifest(cwd, dir, { limit: 100 });
    assert.equal(answer.entry_count, 450);
    assert.equal(answer.entries.length, 100);
    assert.equal(answer.truncated, true);
    assert.equal(answer.pages.entries.truncated, true);
    const rows = await jsonl<Entry>(join(cwd, answer.pages.entries.all_results!));
    assert.equal(rows.length, 450);
    assert.deepEqual(rows.map((r) => r.file_id), [...rows.map((r) => r.file_id)].sort());
    assert.equal(answer.domains.length, 9);
    assert.equal(answer.counts.blobs.missing, 450);
    // A filter reports its own matches, and the manifest's total beside them.
    const some = (await manifest(cwd, dir, { contains: "p000[0-4]$", limit: 100 })).answer;
    assert.equal(some.entry_count, 5);
    assert.equal(some.files_in_manifest, 450);
    assert.equal((await manifest(cwd, dir, { domain: "Domain-03", limit: 1000 })).answer.entry_count, 50);
  });
});

test("manifest_db withholds a path shaped like a recovery password, and a time limit says partial", async () => {
  await withCwd(async (cwd) => {
    const dir = await backup(cwd, "named", { entries: [{ id: ID_A, path: `Documents/${RECOVERY_NAME}/key.txt`, blob: "none" }] });
    const { answer, run } = await manifest(cwd, dir);
    assert.equal(run.stdout.includes(RECOVERY_NAME), false);
    assert.equal(answer.entries[0].relative_path.includes(RECOVERY_NAME), false);
    assert.ok(answer.paths_withheld >= 1);
    const slow = (await manifest(cwd, dir, { max_seconds: 1e-9 })).answer;
    assert.equal(slow.status, "partial");
    assert.equal(slow.stopped_at_row, 0);
    assert.ok(slow.observations.some((o) => /^max_seconds \(1e-09\) passed after 0 rows: the rest of the Files table is not listed/.test(o)), slow.observations.join("\n"));
    // A file that is not a backup is refused in JSON, and no traceback.
    assert.match(refused(await tool(MANIFEST, cwd, { path: join(cwd, "work") })).error, /no Manifest.db/);
  });
});

// --- protobuf_peek ---------------------------------------------------------------------

function varint(n: bigint | number): Buffer {
  let v = BigInt(n);
  const out: number[] = [];
  do {
    let byte = Number(v & 0x7fn);
    v >>= 7n;
    if (v) byte |= 0x80;
    out.push(byte);
  } while (v);
  return Buffer.from(out);
}
const key = (field: number, wire: number): Buffer => varint((field << 3) | wire);
const lenDelimited = (field: number, data: Buffer | string): Buffer => {
  const d = typeof data === "string" ? Buffer.from(data, "utf8") : data;
  return Buffer.concat([key(field, 2), varint(d.length), d]);
};
const varintField = (field: number, v: bigint | number): Buffer => Buffer.concat([key(field, 0), varint(v)]);

type PbField = {
  field_path: string; field: number; wire_type: string; depth: number; offset: number; value?: number; as_bool?: boolean;
  zigzag_reading?: number; twos_complement_reading?: number; hex?: string; payload_offset?: number; payload_bytes?: number;
  read_as?: string; also_reads_as?: string[] | string; children?: number; characters?: number; finding_id?: string; as_signed?: unknown; text?: unknown; value_withheld?: string;
};
type Pb = {
  source: string; parser: string;
  window: { offset: number; bytes: number; file_bytes: number | null; bytes_after_window: number; next_offset?: number };
  structure: { status: string; reason: string; problem_offset?: number; bytes_in_window: number; consistent_with_protobuf_wire_format: boolean };
  fields: PbField[]; field_count: number; top_level_fields: number; counts: Record<string, number>;
  secret_values: { requested: boolean; written: number; values_file: string | null; contains_secret_values: boolean };
  pages: { fields: Paged }; truncated: boolean; looks_like_protobuf?: unknown; strings?: unknown; paths_withheld: number;
};
type PbValue = { finding_id: string; source: string; field_path: string | null; offset: number; payload_offset: number; kind: string; bytes: number | null; value: string | Record<string, unknown> };

/** The parser's finding for a window that was not accepted, from its one row in the values file (written in a fixed width). */
function parseFinding(values: PbValue[]): { state: string; reason: string; offset: number; rule_failed: string } {
  const row = values.find((v) => v.kind === "window");
  assert.ok(row, "one row of kind window");
  assert.equal(values.length, 1);
  const parse = (row as unknown as { parse: { state: string; reason: string; offset: string; rule_failed: string } }).parse;
  return { state: parse.state.trim(), reason: parse.reason.trim(), offset: /^\d+$/.test(parse.offset) ? Number(parse.offset) : -1, rule_failed: parse.rule_failed.trim() };
}

async function peek(cwd: string, args: Record<string, unknown>, name?: string): Promise<{ answer: Pb; run: Run; values: PbValue[] }> {
  const run = name ? await asJob(PROTOBUF, cwd, { write_values: true, ...args }, name) : await tool(PROTOBUF, cwd, args);
  const answer = body<Pb>(run);
  const file = name ? join(cwd, name, "protobuf-values.jsonl") : "";
  return { answer, run, values: file && (await exists(file)) ? await jsonl<PbValue>(file) : [] };
}

test("protobuf_peek reads a nested message with absolute offsets and full field paths", async () => {
  // Nested offsets were relative to the nested buffer, and `offset` shifted nothing in the answer.
  await withCwd(async (cwd) => {
    const inner = Buffer.concat([lenDelimited(1, "abc"), varintField(2, 5)]);
    const message = Buffer.concat([varintField(1, 150), lenDelimited(2, "testing"), lenDelimited(3, inner), key(4, 5), Buffer.from("0000803f", "hex")]);
    const prefix = Buffer.alloc(100, 0xaa);
    await writeFile(join(cwd, "work", "blob.bin"), Buffer.concat([prefix, message]));
    const { answer } = await peek(cwd, { path: "work/blob.bin", offset: 100 });
    assert.equal(answer.structure.status, "valid");
    assert.equal(answer.structure.consistent_with_protobuf_wire_format, true);
    const paths = answer.fields.map((f) => f.field_path);
    assert.deepEqual(paths, ["1", "2", "3", "3.1", "3.2", "4"]);
    const file = Buffer.concat([prefix, message]);
    const innerStart = 100 + varintField(1, 150).length + lenDelimited(2, "testing").length;
    const byPath = Object.fromEntries(answer.fields.map((f) => [f.field_path, f]));
    assert.equal(byPath["1"].offset, 100);
    assert.equal(byPath["3"].offset, innerStart);
    assert.equal(byPath["3"].payload_offset, innerStart + 2);
    assert.equal(byPath["3"].read_as, "nested message");
    assert.equal(byPath["3.1"].offset, innerStart + 2, "a nested field's offset is in the file, not in its parent's buffer");
    assert.equal(byPath["3.2"].offset, innerStart + 2 + lenDelimited(1, "abc").length);
    // The key of every field is where it says: the byte at its offset is (field << 3) | wire type.
    for (const f of answer.fields) assert.equal(file[f.offset] >> 3, f.field, `field ${f.field_path} at ${f.offset}`);
    // A top-level varint is printed, with its zigzag reading named as one. A fixed-width value and anything under a
    // length-delimited field is not printed: it may be the content of a string or of bytes.
    assert.equal(byPath["1"].value, 150);
    assert.equal(byPath["1"].zigzag_reading, 75);
    assert.equal(byPath["1"].as_signed, undefined, "the zigzag reading is named as one");
    assert.equal(byPath["4"].value, undefined);
    assert.equal(byPath["4"].hex, undefined);
    assert.match(byPath["4"].value_withheld ?? "", /raw bytes/);
    assert.equal(byPath["3.2"].value, undefined);
    assert.match(byPath["3.2"].value_withheld ?? "", /inside a length-delimited field/);
    const job = await peek(cwd, { path: "work/blob.bin", offset: 100 }, "pb-numbers");
    const held = Object.fromEntries(job.values.map((v) => [v.field_path, v]));
    const { pad, ...readings } = held["4"].value as Record<string, unknown>;
    assert.deepEqual(readings, { value: 0x3f800000, hex: "0000803f", float_reading: 1 });
    assert.match(String(pad), /^-+$/, "the readings are padded to one width");
    assert.equal(held["4"].kind, "number");
    assert.equal((held["3.2"].value as unknown as { value: number }).value, 5);
  });
});

test("protobuf_peek reads a bounded window of a large file, and says what lies after it, in a bounded amount of memory", async () => {
  // It read the whole file and then sliced from the offset. The test measures the process: a tool that reads the file
  // whole takes more than 200 MB for the file below, and this one stays under 64 MB.
  await withCwd(async (cwd) => {
    const big = join(cwd, "work", "big.bin");
    // Aimed with an offset and a length, so the window must be a message of at least 16 bytes and 4 fields to be shown.
    const message = Buffer.concat([varintField(1, 7), lenDelimited(2, "hello"), varintField(3, 300), lenDelimited(4, "world!")]);
    await writeFile(big, Buffer.concat([Buffer.alloc(100), message]));
    // 200 MiB, sparse: only the message and the end of the file hold bytes.
    const fd = await import("node:fs/promises").then((m) => m.open(big, "r+"));
    await fd.truncate(200 * 1024 * 1024);
    await fd.close();
    const one = await measured(PROTOBUF, cwd, { path: "work/big.bin", offset: 100, length: message.length });
    const answer = body<Pb>(one.run);
    assert.equal(answer.structure.status, "valid");
    assert.equal(answer.window.bytes, message.length);
    assert.equal(answer.window.file_bytes, 200 * 1024 * 1024);
    assert.equal(answer.window.bytes_after_window, 200 * 1024 * 1024 - 100 - message.length);
    assert.equal(answer.window.next_offset, 100 + message.length);
    // Compared with the same wrapper on a few bytes, so that the interpreter and the machine are not counted; a tool that reads the
    // file whole takes 200 MiB more.
    const base = await baseline(PROTOBUF, cwd);
    assert.ok(one.traced - base.traced < 8 * 1024 * 1024, `the tool allocated ${one.traced - base.traced} bytes more than a few bytes cost, to read ${message.length} bytes of a 200 MiB file`);
    assert.ok(one.maxrss - base.maxrss < 96 * 1024 * 1024, `the tool's resident peak grew by ${one.maxrss - base.maxrss} bytes to read ${message.length} bytes of a 200 MiB file`);
    // Without a length the window is bounded too (8 MiB), never the whole file.
    const two = await measured(PROTOBUF, cwd, { path: "work/big.bin", offset: 100 });
    const dflt = body<Pb>(two.run);
    assert.equal(dflt.window.bytes, 8 * 1024 * 1024);
    assert.ok(dflt.window.next_offset);
    assert.ok(two.traced - base.traced < 3 * 8 * 1024 * 1024, `the default window took ${two.traced - base.traced} allocated bytes`);
    assert.ok(two.maxrss - base.maxrss < 128 * 1024 * 1024, `the default window grew the resident peak by ${two.maxrss - base.maxrss} bytes`);
    assert.match(refused(await tool(PROTOBUF, cwd, { path: "work/big.bin", length: 65 * 1024 * 1024 })).error, /at most/);
    assert.match(refused(await tool(PROTOBUF, cwd, { path: "work/big.bin", offset: 300 * 1024 * 1024 })).error, /past the end/);
  });
});

test("protobuf_peek takes memory that follows the window, not the window times the depth", async () => {
  // Every length-delimited payload was copied into the frame that parsed it and stayed alive while the nested parse recursed:
  // 32 levels around 60 MiB took 2.3 GB.
  await withCwd(async (cwd) => {
    let inner: Buffer = Buffer.alloc(12 * 1024 * 1024, 0xff);
    for (let i = 0; i < 32; i++) inner = lenDelimited(1, inner);
    await writeFile(join(cwd, "work", "chain.bin"), inner);
    const run = await measured(PROTOBUF, cwd, { path: "work/chain.bin", length: inner.length, max_depth: 32 });
    const answer = body<Pb>(run.run);
    assert.equal(answer.window.bytes, inner.length);
    const base = await baseline(PROTOBUF, cwd);
    // What the tool itself allocates for the window and its nested readings (about 4 times the window here), and the resident peak over
    // the baseline run: a margin of 2 and 5 over what is measured, where a copy of the payload per level is 30 times the window.
    const bounded = (m: Measured): boolean => m.traced - base.traced < 8 * inner.length && m.maxrss - base.maxrss < 24 * inner.length;
    assert.ok(bounded(run), `32 levels around ${inner.length} bytes: ${run.traced - base.traced} bytes allocated, resident peak ${run.maxrss - base.maxrss} over the baseline ${base.maxrss}`);
    // The same test fails on a tool that copies the payload of every level and keeps the copy while it parses the next.
    const source = await readFile(PROTOBUF, "utf8");
    const copy = "payload = ctx.view[at:at + length]";
    assert.equal(source.split(copy).length, 2, "the line the mutant changes is in the tool");
    const mutant = join(cwd, "work", "protobuf_peek_mutant.py");
    await writeFile(mutant, source.replace(copy, "payload = bytes(ctx.view[at:at + length])"));
    const copied = await measured(mutant, cwd, { path: "work/chain.bin", length: inner.length, max_depth: 32 });
    assert.equal(copied.run.code, 0, copied.run.stderr);
    assert.equal(bounded(copied), false, `a tool that copies each level took ${copied.traced - base.traced} allocated bytes, ${copied.maxrss - base.maxrss} resident over the baseline`);
  });
});

test("protobuf_peek withholds its rows from a window that is not a message, and names every structural error only in the job's values file", async () => {
  // Groups were noted and the parse went on; and rows were printed for a prefix that failed, in reasons that carried numbers
  // derived from the bytes.
  await withCwd(async (cwd) => {
    const group = Buffer.concat([varintField(1, 1), key(5, 3), varintField(1, 2), key(5, 4), varintField(2, 3)]);
    const { answer, run, values } = await peek(cwd, { hex: group.toString("hex") }, "group");
    assert.equal(answer.structure.status, "not_accepted", "a group is not told apart from any other window the rules do not show");
    assert.equal(answer.structure.consistent_with_protobuf_wire_format, false);
    assert.doesNotMatch(answer.structure.reason, /group/);
    assert.deepEqual(answer.fields, []);
    assert.equal(answer.structure.problem_offset, undefined, "no position derived from the bytes");
    assert.equal(answer.looks_like_protobuf, undefined);
    assert.equal(parseFinding(values).state, "unsupported", "what the parser found is in the values file");
    assert.equal(parseFinding(values).offset, 2, "the diagnosis is in the values file");
    assert.doesNotMatch(run.stdout, /"offset": 2\b/);
    const cases: [string, Buffer, RegExp, number][] = [
      ["field number 0", Buffer.from([0x00, 0x01]), /field number of 0/, 0],
      ["wire type 7", Buffer.concat([varintField(1, 1), Buffer.from([(2 << 3) | 7])]), /wire type that is not defined/, 2],
      ["a varint of eleven bytes", Buffer.concat([key(1, 0), Buffer.from([0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01])]), /ten bytes|64-bit/, 0],
      ["a tenth byte above 1", Buffer.concat([key(1, 0), Buffer.from([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02])]), /64-bit/, 0],
      ["a length past the message", Buffer.concat([key(1, 2), varint(50), Buffer.from("short")]), /runs past/, 0],
      ["a truncated fixed32", Buffer.concat([key(1, 5), Buffer.from([1, 2])]), /fixed-width field runs past/, 0],
      ["a field number above 2^29-1", varint(((1n << 29n) << 3n) | 0n), /field number of 0, or above/, 0],
    ];
    for (const [name, message, why, at] of cases) {
      const r = await peek(cwd, { hex: message.toString("hex") }, `err-${name.replace(/\W+/g, "-")}`);
      assert.equal(r.answer.structure.status, "not_accepted", name);
      assert.equal(r.answer.structure.consistent_with_protobuf_wire_format, false, name);
      assert.deepEqual(r.answer.fields, [], name);
      const diagnosis = parseFinding(r.values);
      assert.match(diagnosis.reason, why, name);
      assert.equal(diagnosis.offset, at, name);
      assert.doesNotMatch(JSON.stringify(r.answer), /\d{4,}/.source === "" ? /x/ : /problem_offset/, name);
    }
    // A ten-byte varint of all ones is -1 as a two's-complement 64-bit integer, in a window that is a message.
    const minusOne = Buffer.concat([varintField(1, 3), key(2, 0), Buffer.from([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01])]);
    const m = (await peek(cwd, { hex: minusOne.toString("hex") })).answer;
    assert.equal(m.structure.status, "valid");
    assert.equal(m.fields[1].twos_complement_reading, -1);
  });
});

test("protobuf_peek does not give a withheld payload back through the offset and length its own answer names", async () => {
  // The answer named payload_offset and payload_bytes of a withheld field; run again at them, the payload was the top level of the
  // window and its field numbers, wire types and varints gave the characters back: one call, or a window slid over the payload.
  await withCwd(async (cwd) => {
    const sentence = "meet me at the north gate at nine, bring the key";
    const token = Buffer.from("b0c26ebab7479043b7a79f83a3693f30", "hex");
    const message = Buffer.concat([varintField(1, 150), lenDelimited(2, sentence), lenDelimited(3, token)]);
    await writeFile(join(cwd, "work", "m.bin"), message);
    const first = (await peek(cwd, { path: "work/m.bin" })).answer;
    const text = first.fields.find((f) => f.field_path === "2")!;
    const bytes = first.fields.find((f) => f.field_path === "3")!;
    assert.equal(text.read_as, "text");
    assert.equal(bytes.read_as, "bytes");
    for (const [name, payload] of [["text", text], ["bytes", bytes]] as const) {
      const from = payload.payload_offset!, size = payload.payload_bytes!;
      let printed = 0, windows = 0;
      const leaked = new Set<string>();
      for (let offset = from; offset < from + size; offset++) {
        for (const length of [size - (offset - from), Math.min(4, size - (offset - from)), Math.min(9, size - (offset - from))]) {
          windows++;
          const r = await tool(PROTOBUF, cwd, { path: "work/m.bin", offset, length });
          const a = body<Pb>(r);
          if (a.fields.length) { printed++; leaked.add(JSON.stringify(a.fields)); }
          // Whatever the window, the answer holds no number derived from the bytes in a reason, and no row of a rejected window.
          assert.doesNotMatch(r.stdout, /"problem_offset"/, `${name} ${offset}`);
        }
      }
      // A window is a message under the acceptance rule about once in a few thousand for bytes like these: none of the windows over this
      // sentence or this token is one, and every other window printed nothing.
      assert.equal(printed, 0, `${name}: ${printed} of ${windows} windows printed rows: ${[...leaked].join(" ")}`);
    }
    // The window over the sentence as a whole: a status and counts, no row.
    const whole = await tool(PROTOBUF, cwd, { path: "work/m.bin", offset: text.payload_offset, length: text.payload_bytes });
    const wholeAnswer = body<Pb>(whole);
    assert.equal(wholeAnswer.structure.status, "not_accepted");
    assert.deepEqual(wholeAnswer.fields, []);
    for (const word of ["meet", "gate", "bring"]) assert.equal(whole.stdout.includes(word), false);
  });
});

test("protobuf_peek prints no text and no bytes of a string or bytes field, and writes them only to a sealed job file", async () => {
  await withCwd(async (cwd) => {
    const text = "SECRET-TOKEN-value-9f3a";
    const blob = Buffer.from(Array.from({ length: 30 }, (_, i) => 0x80 + ((i * 7) % 100)));
    const message = Buffer.concat([lenDelimited(1, text), lenDelimited(2, blob), varintField(3, 1710000000),
      lenDelimited(4, Buffer.concat([lenDelimited(1, "nested-private-text"), varintField(2, 7)]))]);
    await writeFile(join(cwd, "work", "m.bin"), message);
    const plain = await peek(cwd, { path: "work/m.bin" });
    for (const needle of [text, "nested-private-text", blob.toString("hex")]) {
      for (const form of forms(needle)) assert.equal(Buffer.from(plain.run.stdout).indexOf(form), -1, needle);
    }
    assert.equal(plain.answer.secret_values.requested, false);
    const num = plain.answer.fields.find((f) => f.field_path === "3");
    assert.equal(num?.value, 1710000000, "a number is printed");
    const asText = plain.answer.fields.find((f) => f.field_path === "1");
    assert.equal(asText?.read_as, "text");
    assert.equal(asText?.characters, text.length);
    assert.equal(asText?.payload_bytes, text.length);
    // As a job with write_values: the values are in the 0600 file, once each, with the offsets the answer gives.
    const job = await peek(cwd, { path: "work/m.bin", limit: 2 }, "pb-job");
    assert.equal(job.answer.secret_values.values_file, "store/jobs/j-1/out/protobuf-values.jsonl");
    assert.equal((await stat(join(cwd, "pb-job", "protobuf-values.jsonl"))).mode & 0o777, 0o600);
    const byPath = Object.fromEntries(job.values.filter((v) => v.kind !== "nested_payload").map((v) => [v.field_path, v]));
    assert.equal(byPath["1"].value, text);
    assert.equal(byPath["1"].kind, "text");
    assert.equal(byPath["2"].kind, "bytes");
    assert.equal(byPath["2"].value, blob.toString("hex"));
    assert.equal(byPath["4.1"].value, "nested-private-text");
    // The payload of a nested message is in the values file whole, so that nobody needs to aim a window at it.
    assert.equal(job.values.find((v) => v.field_path === "4" && v.kind === "nested_payload")?.value, message.subarray(job.values.find((v) => v.field_path === "4")!.payload_offset).toString("hex"));
    for (const v of job.values) if (v.bytes !== null) assert.equal(message.subarray(v.payload_offset, v.payload_offset + v.bytes).length, v.bytes);
    await assertNowhere(text, job.run.stdout, join(cwd, "pb-job"), ["protobuf-values.jsonl"]);
    await assertNowhere(blob.toString("hex"), job.run.stdout, join(cwd, "pb-job"), ["protobuf-values.jsonl"]);
    // The whole field list is in the paging file, with no text in it either.
    assert.equal(job.answer.truncated, true);
    // Refused outside a job, and a second run in the same job.
    assert.match(refused(await tool(PROTOBUF, cwd, { path: "work/m.bin", write_values: true })).error, /refused outside a job/);
    assert.match(refused(await asJob(PROTOBUF, cwd, { path: "work/m.bin", write_values: true }, "pb-job")).error, /already exists/);
  });
});

test("protobuf_peek reads printable text as text, so a string's characters are never field numbers, wire types or lengths", async () => {
  // A 72-character token parsed as a nested message (a printable tag byte is a field number 4 to 15), and its first
  // characters were the keys and the length of the rows printed for it.
  await withCwd(async (cwd) => {
    const token = "5useUj3kKVJjBUD9Px9KiNx3t31cJIyXX4uDl45U6pMpIAymiDaRf7mQpBM4aT6q3dF7z4rJ";
    const english = "The quick brown fox jumps over the lazy dog while the committee reads the long minutes of the meeting aloud";
    for (const value of [token, english]) {
      const { answer, run } = await peek(cwd, { hex: Buffer.concat([varintField(1, 5), lenDelimited(2, value)]).toString("hex") });
      assert.equal(answer.fields.length, 2, "no row is printed for the characters of a string");
      assert.equal(answer.fields[1].read_as, "text");
      assert.equal(answer.fields[1].characters, value.length);
      for (const form of forms(value.slice(0, 12))) assert.equal(Buffer.from(run.stdout).indexOf(form), -1);
    }
    // The value is in the values file whole, as the text, in a job.
    const job = await peek(cwd, { hex: Buffer.concat([varintField(1, 5), lenDelimited(2, token)]).toString("hex") }, "token");
    assert.equal(job.values.find((v) => v.field_path === "2")?.value, token);
    // Binary bytes that parse as a message with a field number above 300 are bytes, and the answer says what else they could be.
    const big = Buffer.concat([key(1000, 0), varint(5), key(1001, 0), varint(6)]);
    const rejected = (await peek(cwd, { hex: Buffer.concat([varintField(1, 5), lenDelimited(2, big)]).toString("hex") })).answer.fields[1];
    assert.equal(rejected.read_as, "bytes");
    assert.match(String(rejected.also_reads_as), /does not meet the acceptance rule/);
  });
});

test("protobuf_peek does not print a token's bytes as the numbers of a nested message", async () => {
  // A 16-byte key that happened to parse as fields printed 12 of its bytes as 32- and 64-bit values.
  await withCwd(async (cwd) => {
    const keyBytes = Buffer.from("a577f43bbb49a9711d5ce74ae04c88d6", "hex");
    const message = Buffer.concat([varintField(1, 1), lenDelimited(2, keyBytes)]);
    const { answer, run } = await peek(cwd, { hex: message.toString("hex") });
    for (const form of ["f43bbb49", "1d5ce74ae04c88d6", "a577f43b", "49a9711d"]) assert.equal(run.stdout.includes(form), false, form);
    assert.notEqual(answer.fields[1].read_as, "nested message", "a single field is not a message");
    // Bytes that do read as a small nested message: the structure is shown, the numbers in it are not.
    const inner = Buffer.concat([varintField(1, 7), key_fixed(2, 0x11223344)]);
    const nested = (await peek(cwd, { hex: Buffer.concat([varintField(1, 1), lenDelimited(2, inner)]).toString("hex") }, "nested-key")).answer;
    const child = nested.fields.find((f) => f.field_path === "2.1");
    assert.equal(child?.value, undefined);
    assert.equal(nested.counts.number_values_withheld, 2);
    assert.equal(nested.counts.nested_payloads_withheld, 1);
    for (const form of ["44332211", "0x11223344", String(0x11223344)]) assert.equal(JSON.stringify(nested).includes(form), false, form);
  });
});

function key_fixed(field: number, v: number): Buffer {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(v);
  return Buffer.concat([key(field, 5), b]);
}

test("protobuf_peek holds to its depth, field and time budgets and says so, and refuses a depth it will not honour", async () => {
  await withCwd(async (cwd) => {
    const many = Buffer.concat(Array.from({ length: 500 }, (_, i) => varintField(1, i)));
    const cut = (await peek(cwd, { hex: many.toString("hex"), max_fields: 20 })).answer;
    assert.equal(cut.structure.status, "partial");
    assert.match(cut.structure.reason, /max_fields/);
    assert.equal(cut.field_count, 20);
    assert.equal(cut.structure.consistent_with_protobuf_wire_format, false);
    assert.equal((cut.structure as unknown as { resume_offset: number }).resume_offset, varintField(1, 0).length * 0 + Buffer.concat(Array.from({ length: 20 }, (_, i) => varintField(1, i))).length,
      "a window the budget stopped says where to resume, which is not next_offset");
    // Nesting: a message nested 10 deep is unwrapped to max_depth and read as bytes below it, and the answer counts what it did not try.
    let nested: Buffer = Buffer.concat([varintField(1, 1), lenDelimited(2, "qq")]);
    for (let i = 0; i < 9; i++) nested = Buffer.concat([varintField(1, 1), lenDelimited(2, nested)]);
    const shallow = (await peek(cwd, { hex: nested.toString("hex"), max_depth: 3 })).answer;
    assert.equal(shallow.counts.deepest, 3);
    assert.ok((shallow.structure as unknown as { fields_not_tried_as_nested_at_max_depth: number }).fields_not_tried_as_nested_at_max_depth >= 1);
    const deep = (await peek(cwd, { hex: nested.toString("hex"), max_depth: 20 })).answer;
    assert.equal(deep.counts.deepest, 9);
    assert.equal((deep.structure as unknown as { fields_not_tried_as_nested_at_max_depth?: number }).fields_not_tried_as_nested_at_max_depth, undefined);
    assert.match(refused(await tool(PROTOBUF, cwd, { hex: "0801", max_depth: 1000 })).error, /max_depth/);
    assert.match(refused(await tool(PROTOBUF, cwd, { hex: "0801", max_fields: 99999999 })).error, /at most/);
    assert.match(refused(await tool(PROTOBUF, cwd, { hex: "00".repeat(70000) })).error, /limited to/);
    assert.match(refused(await tool(PROTOBUF, cwd, { hex: "zz" })).error, /hex/);
    assert.match(refused(await tool(PROTOBUF, cwd, {})).error, /path or hex/);
    assert.match(refused(await tool(PROTOBUF, cwd, { path: "work/nothing.bin" })).error, /cannot read/);
    // Both a message in the call and a file: the call would win silently.
    assert.match(refused(await tool(PROTOBUF, cwd, { hex: "0801", path: "work/nothing.bin" })).error, /path or hex, not both/);
    // A time limit is finite and below the tool's own: NaN and Infinity switched the clock off.
    for (const bad of ["NaN", "Infinity", "1e308", "0", "-1", "\"5\""]) {
      const r = await rawTool(PROTOBUF, cwd, `{"hex":"0801","max_seconds":${bad}}`);
      assert.match(refused(r).error, /max_seconds/, bad);
    }
  });
});

test("protobuf_peek refuses a named pipe instead of waiting on it", async () => {
  await withCwd(async (cwd) => {
    const fifo = join(cwd, "work", "pipe");
    const made = spawnSync("mkfifo", [fifo]);
    assert.equal(made.status, 0);
    const started = Date.now();
    const r = await tool(PROTOBUF, cwd, { path: "work/pipe" });
    assert.ok(Date.now() - started < 10000, "the tool did not wait for a writer");
    assert.match(refused(r).error, /not a regular file/);
  });
});

test("protobuf_peek withholds a path shaped like a recovery password on every channel, and survives a name that is not UTF-8", async () => {
  await withCwd(async (cwd) => {
    const dir = join(cwd, "work", RECOVERY_NAME);
    await mkdir(dir, { recursive: true });
    await writeFile(join(dir, "m.bin"), Buffer.concat([varintField(1, 5), lenDelimited(2, "text-in-a-named-dir")]));
    const { answer, run } = await peek(cwd, { path: join("work", RECOVERY_NAME, "m.bin"), limit: 1 }, "named");
    assert.equal(answer.source.includes(RECOVERY_NAME), false);
    assert.ok(answer.paths_withheld >= 1);
    assert.equal(run.stdout.includes(RECOVERY_NAME), false);
    for (const f of await filesUnder(join(cwd, "named"))) if (!f.path.endsWith("-values.jsonl")) assert.equal(f.data.includes(Buffer.from(RECOVERY_NAME)), false, f.path);
    const missing = refused(await tool(PROTOBUF, cwd, { path: join("work", RECOVERY_NAME, "nothing.bin") }));
    assert.equal(JSON.stringify(missing).includes(RECOVERY_NAME), false);
    const gone = await tool(PROTOBUF, cwd, { path: "work/b\udcff.bin" });
    refused(gone);
    assert.ok(/^[\x00-\x7f]*$/.test(gone.stdout), "a lone surrogate is escaped, not raised");
  });
});

test("protobuf_peek and the other tools give each call its own paging file, so a later call never replaces an earlier answer's rows", async () => {
  // Two calls with `hex` shared one file name, and the second call's rows were in the first call's named file.
  await withCwd(async (cwd) => {
    const a = Buffer.concat(Array.from({ length: 5 }, (_, i) => varintField(1, i)));
    const b = Buffer.concat(Array.from({ length: 6 }, (_, i) => varintField(2, 100 + i)));
    const first = (await peek(cwd, { hex: a.toString("hex"), limit: 2 })).answer;
    const second = (await peek(cwd, { hex: b.toString("hex"), limit: 2 })).answer;
    assert.notEqual(first.pages.fields.all_results, second.pages.fields.all_results);
    assert.deepEqual((await jsonl<PbField>(join(cwd, first.pages.fields.all_results!))).map((r) => r.value), [0, 1, 2, 3, 4]);
    assert.deepEqual((await jsonl<PbField>(join(cwd, second.pages.fields.all_results!))).map((r) => r.value), [100, 101, 102, 103, 104, 105]);
    // Two databases whose directories print alike (both withheld) do not share a file either.
    const dirs = ["123456-654321-111111-222222-333333-444444-555555-666666", "123456-654321-111111-222222-333333-444444-555555-777777"];
    const answers: Free[] = [];
    for (const [i, name] of dirs.entries()) {
      await mkdir(join(cwd, "work", name), { recursive: true });
      const db = join(cwd, "work", name, "a.db");
      await build(FREEBLOCK_DB, db, `MARKER-IN-DIRECTORY-${i}`, "utf-8");
      answers.push((await freespace(cwd, db, { limit: 1, min_length: 4 }, `out-dir${i}`)).answer);
    }
    assert.notEqual(answers[0].pages.fragments.all_results, answers[1].pages.fragments.all_results);
  });
});

test("protobuf_peek reads a nested message under the acceptance rule and keeps every field of a long message", async () => {
  await withCwd(async (cwd) => {
    // Two fields, shortest-form varints, ascending, small: a message. One field, an unordered pair and a padded varint are not.
    const message = Buffer.concat([varintField(1, 1), lenDelimited(2, Buffer.concat([lenDelimited(1, "xyz"), varintField(2, 4)]))]);
    const { answer } = await peek(cwd, { hex: message.toString("hex") });
    assert.equal(answer.fields.find((f) => f.field_path === "2")?.read_as, "nested message");
    const rejected: [string, Buffer][] = [
      ["one field", lenDelimited(1, "xyz")],
      ["unordered", Buffer.concat([varintField(2, 4), lenDelimited(1, "xyz")])],
      ["a padded varint", Buffer.concat([varintField(1, 4), Buffer.from([0x10, 0x84, 0x00])])],
    ];
    for (const [name, inner] of rejected) {
      const r = (await peek(cwd, { hex: Buffer.concat([varintField(1, 1), lenDelimited(2, inner)]).toString("hex") })).answer;
      assert.equal(r.fields.find((f) => f.field_path === "2")?.read_as, "bytes", name);
      // And as a window of its own, the same bytes get no row.
      const alone = (await peek(cwd, { hex: inner.toString("hex") })).answer;
      assert.deepEqual(alone.fields, [], name);
      assert.equal(alone.structure.status, "not_accepted", name);
    }
    const long = Buffer.concat(Array.from({ length: 700 }, (_, i) => varintField(2, i)));
    const all = (await peek(cwd, { hex: long.toString("hex"), limit: 50 })).answer;
    assert.equal(all.field_count, 700);
    assert.equal(all.fields.length, 50);
    assert.equal(all.truncated, true);
    const rows = await jsonl<PbField>(join(cwd, all.pages.fields.all_results!));
    assert.equal(rows.length, 700);
    assert.deepEqual(rows.map((r) => r.value).slice(0, 5), [0, 1, 2, 3, 4]);
  });
});

test("the shared helper block of the three tools is byte for byte one", async () => {
  const blocks = await Promise.all(["sqlite_freespace", "manifest_db", "protobuf_peek"].map(async (t) => {
    const text = await readFile(join(TOOLS, t, "run.py"), "utf8");
    const a = text.indexOf("# --- shared with the pack's other tools: begin");
    const b = text.indexOf("# --- shared with the pack's other tools: end");
    assert.ok(a >= 0 && b > a, `${t} has the shared block`);
    return text.slice(a, b);
  }));
  assert.equal(blocks[0], blocks[1]);
  assert.equal(blocks[0], blocks[2]);
});

// --- review fixes: filters on the text that is printed, bounded cells, secret output, signals, windows ---------

const WITHHELD = "<recovery-password-shaped name withheld>";
/** A recovery password shaped name from pieces: eight groups of six digits, from a seeded generator, never a fixed literal. */
function recoveryName(seed: number): string {
  let x = seed >>> 0;
  const next = (): number => { x = (Math.imul(x, 1664525) + 1013904223) >>> 0; return x; };
  return Array.from({ length: 8 }, () => String(next() % 1000000).padStart(6, "0")).join("-");
}

test("manifest_db applies contains and domain to the path it prints, so a withheld component cannot be guessed digit by digit", async () => {
  // contains and domain ran on the real relative path: `Documents/<prefix>` matched while the printed path said the component was withheld, and
  // entry_count told, call by call, whether the guessed prefix was right (10 calls a digit, 480 for a 48-digit key).
  await withCwd(async (cwd) => {
    const keys = [recoveryName(11), recoveryName(12)];
    const dir = await backup(cwd, "oracle", { entries: [
      { id: ID_A, path: `Documents/${keys[0]}/note.txt`, blob: "none" },
      { id: ID_B, path: `Documents/${keys[1]}/note.txt`, blob: "none", domain: `AppDomain-${keys[1]}` },
      { id: ID_C, path: "Documents/other/note.txt", blob: "none" },
    ] });
    const base = (await manifest(cwd, dir)).answer;
    assert.equal(base.entry_count, 3);
    const counts: Record<string, number> = {};
    for (const [name, rx] of [["right prefix", `Documents/${keys[0].slice(0, 6)}`], ["wrong prefix", `Documents/${keys[0].slice(0, 5)}x`], ["whole key", keys[0]], ["its second group", keys[0].slice(7, 13)], ["a digit class", `Documents/[0-9]{6}-`]] as const) {
      const r = await manifest(cwd, dir, { contains: rx });
      counts[name] = r.answer.entry_count;
      assert.equal(r.run.stdout.includes(keys[0]), false);
      assert.equal(r.run.stdout.includes(keys[1]), false);
    }
    // Every guess about the withheld text gets the same answer: no row.
    assert.deepEqual(counts, { "right prefix": 0, "wrong prefix": 0, "whole key": 0, "its second group": 0, "a digit class": 0 });
    // What is printed can be filtered on, the placeholder included.
    assert.equal((await manifest(cwd, dir, { contains: "withheld>/note" })).answer.entry_count, 2);
    assert.equal((await manifest(cwd, dir, { contains: "other/note" })).answer.entry_count, 1);
    // domain: the printed domain is the placeholder; the real one matches nothing.
    const real = await manifest(cwd, dir, { domain: `AppDomain-${keys[1]}` });
    assert.equal(real.answer.entry_count, 0);
    assert.equal(real.run.stdout.includes(keys[1]), false);
    assert.equal((await manifest(cwd, dir, { domain: WITHHELD })).answer.entry_count, 1);
    assert.equal((await manifest(cwd, dir, { domain: "HomeDomain" })).answer.entry_count, 2);
    // The filter text is the caller's own and may be echoed, but the answer never carries a key.
    // The expression is echoed with anything shaped like a recovery password withheld.
    const echoed = JSON.stringify((await manifest(cwd, dir, { contains: keys[0] })).answer);
    assert.equal(echoed.includes(keys[0]), false);
    assert.equal(echoed.includes(keys[0].slice(0, 6)), false);
  });
});

test("manifest_db does not run a path or domain it cannot bound through the recovery-password patterns, and prints a placeholder for it", async () => {
  // The recovery-shape pattern cost 0.46 s per MB of a path or domain cell ("41 digits and a letter", repeated): three rows of 8 MB took 11.3 s of CPU,
  // max_seconds was only looked at between rows, and a cell of the 1 GB SQLite allows would have run past the tool's own timeout.
  await withCwd(async (cwd) => {
    const hostile = ("1".repeat(41) + "a").repeat(500);      // 21,000 characters
    const ordinary = "Documents/note.txt";
    const dir = await backup(cwd, "hostile", { entries: [
      { id: ID_A, path: `Library/${hostile}`, blob: "none", domain: `AppDomain-${hostile}` },
      { id: ID_B, path: ordinary, blob: "none" },
      { id: ID_C, path: hostile, blob: "none" },
    ] });
    const { answer, run } = await manifest(cwd, dir);
    assert.equal(answer.entry_count, 3);
    assert.equal(answer.entries[0].relative_path, "<name too long to judge withheld>");
    assert.equal(answer.entries[0].domain, "<name too long to judge withheld>");
    assert.equal(answer.entries[1].relative_path, ordinary);
    assert.equal(answer.entries[2].relative_path, "<name too long to judge withheld>");
    assert.equal(run.stdout.includes("1".repeat(41)), false, "none of the cell is printed");
    assert.ok(answer.paths_withheld >= 3);
    // What is printed can be filtered on, and the cell behind the placeholder matches nothing.
    assert.equal((await manifest(cwd, dir, { contains: "1111111111" })).answer.entry_count, 0);
    assert.equal((await manifest(cwd, dir, { contains: "too long to judge" })).answer.entry_count, 2);
    assert.equal((await manifest(cwd, dir, { domain: "<name too long to judge withheld>" })).answer.entry_count, 1);
    // The listing stays bounded in time whatever the cell holds: the same three rows with the cell 40 times larger take seconds, not minutes.
    const big = await backup(cwd, "hostile-big", { entries: [
      { id: ID_A, path: ("1".repeat(41) + "a").repeat(40000), blob: "none" }, { id: ID_B, path: ordinary, blob: "none" },
      { id: ID_C, path: ("1".repeat(41) + "a").repeat(40000), blob: "none" },
    ] });
    const began = Date.now();
    const large = await manifest(cwd, big);
    assert.equal(large.answer.entry_count, 3);
    assert.equal(large.answer.entries[0].relative_path, "<name too long to judge withheld>");
    assert.ok((Date.now() - began) / 1000 < 20, "3 rows of 1.7 MB took " + (Date.now() - began) / 1000 + " s");
  });
});

test("manifest_db does not read a keyed-archive cell above 1 MiB, and says so for that row", async () => {
  // The whole cell was read and parsed: a 76 MB archive took 1.05 GB, and a larger cell has no limit but the machine's.
  await withCwd(async (cwd) => {
    const pad = 40 * 1024 * 1024;
    const dir = await backup(cwd, "bigcell", { entries: [{ id: ID_A, path: "Library/a.db" }, { id: ID_B, path: "Library/big.db", pad }, { id: ID_C, path: "Library/c.db" }] });
    const run = await measured(MANIFEST, cwd, { path: dir });
    const answer = body<Manifest>(run.run);
    const rows = Object.fromEntries(answer.entries.map((e) => [e.relative_path, e]));
    assert.equal(rows["Library/big.db"].metadata_status, "too_large");
    assert.match(rows["Library/big.db"].metadata_reason ?? "", /^the file column is \d+ bytes, over the 1048576 this tool reads: the cell was not read$/);
    assert.equal(rows["Library/a.db"].metadata_status, "ok");
    assert.equal(rows["Library/c.db"].metadata_status, "ok");
    assert.equal(answer.counts.metadata.too_large, 1);
    assert.equal(answer.status, "partial", "a cell the tool did not read is metadata left out of the answer");
    assert.match(answer.status_basis ?? "", /the metadata of 1 listed row\(s\) is not in the answer/);
    assert.ok(answer.observations.some((o) => /^1 listed row\(s\) have no readable metadata/.test(o)), answer.observations.join("\n"));
    const base = await baseline(MANIFEST, cwd).catch(() => null);
    const tiny = await measured(MANIFEST, cwd, { path: await backup(cwd, "tinycell", { entries: [{ id: ID_A, path: "Library/a.db" }] }) });
    assert.ok(run.maxrss - tiny.maxrss < 80 * 1024 * 1024, `a 40 MiB cell cost ${run.maxrss - tiny.maxrss} bytes of resident memory more than a small one (${base ? "baseline measured" : "no baseline"})`);
  });
});

test("manifest_db says what a cell that is not a blob is, without reading it", async () => {
  await withCwd(async (cwd) => {
    const dir = await backup(cwd, "kinds", { entries: [{ id: ID_A, path: "Library/a.db" }, { id: ID_B, path: "Library/b.db", nometa: true }] });
    const make = String.raw`
import sqlite3, sys
con = sqlite3.connect(sys.argv[1])
con.execute("UPDATE Files SET file = 'text instead of a blob' WHERE fileID = ?", (sys.argv[2],))
con.commit()
`;
    assert.equal((await runPySnippet(make, [join(dir, "Manifest.db"), ID_A], null)).code, 0);
    const answer = (await manifest(cwd, dir)).answer;
    const rows = Object.fromEntries(answer.entries.map((e) => [e.relative_path, e]));
    assert.equal(rows["Library/a.db"].metadata_status, "malformed");
    assert.equal(rows["Library/a.db"].metadata_reason, "the file column is a str, not a blob");
    assert.equal(answer.status, "partial", "a cell the tool could not use is metadata left out of the answer");
    assert.match(answer.status_basis ?? "", /the metadata of 2 listed row\(s\) is not in the answer/, "a NULL cell is metadata left out too");
    assert.equal(rows["Library/b.db"].metadata_status, "absent");
  });
});

test("manifest_db, sqlite_freespace and protobuf_peek write their values only in a job run as secret output", async () => {
  // The tools checked JOB_ID and OUT only: write_values in a plain job wrote the values file as an ordinary output.
  await withCwd(async (cwd) => {
    const db = join(cwd, "work", "secret.db");
    await build(FREEBLOCK_DB, db, "SECRET-OUTPUT-MARKER", "utf-8");
    const refusal = refused(await asJob(FREESPACE, cwd, { db, write_values: true }, "plain", "j-1", false));
    assert.match(refusal.error, /not run as secret output \(SECRET_OUTPUT is not 1\)/);
    assert.equal(refusal.write_values, "refused");
    assert.equal(await exists(join(cwd, "plain", "sqlite-freespace-values.jsonl")), false, "nothing was written");
    assert.equal(refused(await asJob(FREESPACE, cwd, { db, write_values: true, contains: "SECRET" }, "plain2", "j-2", false)).write_values, "refused");
    // Without the flag nothing is asked of the job: the same tool answers.
    assert.equal(body<Free>(await asJob(FREESPACE, cwd, { db }, "plain3", "j-3", false)).secret_values.requested, false);
    const pb = join(cwd, "work", "pb.bin");
    await writeFile(pb, Buffer.concat([varintField(1, 7), lenDelimited(2, "hello world"), varintField(3, 300), lenDelimited(4, "more text")]));
    assert.match(refused(await asJob(PROTOBUF, cwd, { path: pb, write_values: true }, "plain4", "j-4", false)).error, /SECRET_OUTPUT is not 1/);
    assert.equal(await exists(join(cwd, "plain4", "protobuf-values.jsonl")), false);
    assert.equal(body<Pb>(await asJob(PROTOBUF, cwd, { path: pb, write_values: true }, "secret4", "j-5", true)).secret_values.written, 2);
    // The manifests say so, for the harness: the job is secret output whenever write_values is asked for.
    for (const name of ["sqlite_freespace", "protobuf_peek"]) {
      const manifestJson = JSON.parse(await readFile(join(TOOLS, name, "manifest.json"), "utf8")) as { secret_output?: unknown };
      assert.deepEqual(manifestJson.secret_output, { when_args: ["write_values"] }, name);
    }
  });
});

test("the three tools answer a stop signal with one JSON, exit 128 plus the signal, and leave nothing they made", async () => {
  // A signal ended the tool with no output and left the working copy of Manifest.db and a hidden temporary page file behind.
  await withCwd(async (cwd) => {
    const prelude = String.raw`
import importlib.util, os, sys, time
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("tool", sys.argv[1]); tool = importlib.util.module_from_spec(spec); spec.loader.exec_module(tool)
os.chdir(sys.argv[2])
os.environ.update(JOB_ID="j-1", OUT=sys.argv[3], SECRET_OUTPUT="1", AGENT_ID="s1")
os.makedirs(sys.argv[3], exist_ok=True)
def hang():
    sys.stderr.write("READY\n"); sys.stderr.flush(); time.sleep(60)
`;
    const stop = async (name: string, patch: string, args: Record<string, unknown>, tool: string, sig: NodeJS.Signals) => {
      const out = join(cwd, "stop-" + name + "-" + sig);
      const result = await stoppedBy(prelude + patch + "\ntool.run_main(tool.main)\n", [tool, cwd, out], args, sig);
      return { out, ...result };
    };
    const check = (r: Awaited<ReturnType<typeof stop>>, sig: NodeJS.Signals, number: number) => {
      assert.equal(r.code, 128 + number, r.stderr + r.stdout);
      assert.doesNotMatch(r.stderr, /Traceback/);
      const answer = JSON.parse(r.stdout) as Record<string, unknown>;
      assert.equal(answer.interrupted, sig);
      assert.equal(answer.status, "failed");
      assert.match(String(answer.status_basis), new RegExp(sig));
      return answer;
    };
    const hidden = async (dir: string): Promise<string[]> => (await exists(dir)) ? (await readdir(dir)).filter((n) => n.startsWith(".")) : [];

    // sqlite_freespace: the third fragment's text is being decoded; the first rows are in a page file, which is named, and the values file is closed.
    const db = join(cwd, "work", "stop.db");
    await build(FREEBLOCK_DB, db, "STOP-MARKER", "utf-8");
    for (const [sig, number] of [["SIGTERM", 15], ["SIGINT", 2], ["SIGHUP", 1]] as const) {
      const r = await stop("freespace", "real = tool.decode\ncount = [0]\ndef slow(raw, encoding):\n    count[0] += 1\n    if count[0] == 3: hang()\n    return real(raw, encoding)\ntool.decode = slow",
        { db, write_values: true, limit: 1, min_length: 4 }, FREESPACE, sig);
      const answer = check(r, sig, number);
      const kept = (answer.rows_read_before_the_failure_kept_in as string[])[0];
      assert.ok(kept, JSON.stringify(answer));
      assert.ok((await readFile(join(r.out, "tool-output", kept.split("/").pop()!), "utf8")).split("\n").filter(Boolean).length >= 2);
      assert.deepEqual(await hidden(join(r.out, "tool-output")), [], "no hidden temporary page file");
      assert.equal((answer.values_written_before_the_failure as { rows: number }).rows, 2);
      assert.equal(await exists(join(r.out, "sqlite-freespace-values.jsonl")), true);
    }

    // manifest_db: a WAL beside Manifest.db makes a working copy; the signal arrives while the third row's archive is read.
    const dir = await backup(cwd, "stopbk", { entries: many(4), wal: many(2, (i) => ({ id: (i + 100).toString(16).padStart(40, "0") })) });
    const m = await stop("manifest", "real = tool.metadata\ncount = [0]\ndef slow(*a):\n    count[0] += 1\n    if count[0] == 3: hang()\n    return real(*a)\ntool.metadata = slow",
      { path: dir, limit: 1 }, MANIFEST, "SIGTERM");
    const answer = check(m, "SIGTERM", 15);
    assert.ok((answer.rows_read_before_the_failure_kept_in as string[])[0]);
    assert.deepEqual((await exists(join(m.out, "tool-output")) ? await readdir(join(m.out, "tool-output")) : []).filter((n) => n.startsWith("manifest_db-working-copy-")), [], "the working copy was removed");
    assert.deepEqual(await hidden(join(m.out, "tool-output")), []);

    // protobuf_peek
    const pb = join(cwd, "work", "stop.bin");
    await writeFile(pb, Buffer.concat([varintField(1, 7), lenDelimited(2, "hello world"), varintField(3, 300), lenDelimited(4, "more text"), lenDelimited(5, "last text")]));
    const p = await stop("protobuf", "real = tool.SecretValues.add\ncount = [0]\ndef slow(self, *a):\n    count[0] += 1\n    if count[0] == 3: hang()\n    return real(self, *a)\ntool.SecretValues.add = slow",
      { path: pb, write_values: true, limit: 1 }, PROTOBUF, "SIGTERM");
    const pa = check(p, "SIGTERM", 15);
    assert.equal((pa.values_written_before_the_failure as { rows: number }).rows, 2);
    assert.deepEqual(await hidden(join(p.out, "tool-output")), []);
  });
});

/** A Python snippet run as a child: its stderr says READY when it is waiting, then it gets the signal. Args on stdin (JSON). */
async function stoppedBy(code: string, argv: string[], stdin: unknown, sig: NodeJS.Signals): Promise<Run> {
  return new Promise((resolve, reject) => {
    const child = spawn("python3", ["-c", code, ...argv], { env: { ...process.env, ...AGENT } });
    const out: Buffer[] = [], err: Buffer[] = [];
    let sent = false;
    const guard = setTimeout(() => { child.kill("SIGKILL"); }, 60000);
    child.stdout.on("data", (c: Buffer) => out.push(c));
    child.stderr.on("data", (c: Buffer) => {
      err.push(c);
      if (!sent && Buffer.concat(err).toString("utf8").includes("READY")) { sent = true; child.kill(sig); }
    });
    child.on("error", reject);
    child.on("close", (exit, signal) => {
      clearTimeout(guard);
      resolve({ code: exit ?? (signal ? 128 + 99 : null), stdout: Buffer.concat(out).toString("utf8"), stderr: Buffer.concat(err).toString("utf8") });
    });
    child.stdin.on("error", () => {});
    child.stdin.end(JSON.stringify(stdin));
  });
}

test("protobuf_peek shows a window aimed at a token only when it is a message of 16 bytes and 4 fields, and no window inside text at all", async () => {
  // The rule held for the whole payload and not for sub-windows: the first answer names where a withheld payload is, and a window slid across
  // a token was shown whenever its characters parsed as a message (the rows printed are the token's own bytes read as keys, lengths and varints).
  const slide = String.raw`
import importlib.util, json, random, string, sys, time
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("pb", sys.argv[1]); pb = importlib.util.module_from_spec(spec); spec.loader.exec_module(pb)
rule = getattr(pb, "window_accepted_by", None)
rng = random.Random(8)
def varint(n):
    out = bytearray()
    while True:
        b = n & 0x7F; n >>= 7
        if n: out.append(b | 0x80)
        else: out.append(b); return bytes(out)
WIRE = {"varint": 0, "64-bit": 1, "length-delimited": 2, "32-bit": 5}
def exposed(rows, mask):
    # the bytes of the window that the printed rows give away: keys, lengths, and the value of a top-level varint
    for r in rows:
        at = r["offset"]; key = len(varint((r["field"] << 3) | WIRE[r["wire_type"]]))
        for i in range(at, at + key): mask[i] = True
        if r["wire_type"] == "varint" and r["depth"] == 0:
            for i in range(at + key, at + key + len(varint(r["value"]))): mask[i] = True
        elif r["wire_type"] == "length-delimited":
            for i in range(at + key, r["payload_offset"]): mask[i] = True
            if "_children" in r: exposed(r["_children"], mask)
def derivable(blob, aimed):
    ctx = pb.Context(blob, 0, 6, 100000, time.monotonic() + 60)
    rows, state, problem, shape = pb.parse(ctx, 0, len(blob), 0, [])
    ok = rule(blob, state, shape, aimed) if rule else (len(blob) >= pb.MIN_WINDOW_BYTES and pb.accepted(state, shape))
    mask = [False] * len(blob)
    if ok: exposed(rows, mask)
    return mask
kinds = {"base62-20": (string.ascii_letters + string.digits, 20), "hex-32": ("0123456789abcdef", 32), "hex-64": ("0123456789abcdef", 64)}
result = {}
for label, (alphabet, length) in kinds.items():
    tokens = 0
    for _ in range(int(sys.argv[2])):
        token = "".join(rng.choice(alphabet) for _ in range(length)).encode()
        prefix = b"\x08\x01\x12" + varint(length)
        message = prefix + token + b"\x18\x02"
        start, end = len(prefix), len(prefix) + length
        hit = False
        for offset in range(0, len(message) - 7):
            for size in range(8, len(message) - offset + 1):
                mask = derivable(message[offset:offset + size], offset > 0 or size != len(message))
                if any(mask[i] for i in range(size) if start <= offset + i < end):
                    hit = True
        tokens += hit
    result[label] = tokens
print(json.dumps(result))
`;
  const count = 200;
  const run = await runPySnippet(slide, [PROTOBUF, String(count)], null);
  assert.equal(run.code, 0, run.stderr);
  const hits = JSON.parse(run.stdout) as Record<string, number>;
  // Before: about 46, 87 and 99 percent of these tokens had a shown window that gave bytes of the token away. After: at most 3 percent of them.
  for (const [label, n] of Object.entries(hits)) assert.ok(n <= 0.03 * count, `${label}: ${n} of ${count} tokens had a window that was shown`);
});

test("protobuf_peek does not show an aimed window that the field budget stopped, so max_fields cannot raise the rate of shown windows over a token", async () => {
  // A window the budget stopped was accepted on the fields it had read: with max_fields 4 acceptance was judged on the first four fields of any
  // window, and a window slid over a token was shown for 19 to 21 percent of 64-character hexadecimal tokens instead of 1 percent.
  await withCwd(async (cwd) => {
    // Eight small varint fields, 16 bytes: a message, aimed by its length.
    const hex = "08011002180320042805300638074008";
    const whole = body<{ structure: { status: string }; field_count: number }>(await tool(PROTOBUF, cwd, { hex, length: 16 }));
    assert.equal(whole.structure.status, "valid");
    assert.equal(whole.field_count, 8);
    type Peek = { structure: { status: string; reason: string; rows_withheld?: boolean }; field_count: number; top_level_fields: number };
    const budgeted = body<Peek>(await tool(PROTOBUF, cwd, { hex, length: 16, max_fields: 4 }));
    assert.equal(budgeted.structure.status, "not_accepted", "the budget stopped an aimed window: it is not shown");
    assert.equal(budgeted.field_count, 0);
    assert.equal(budgeted.top_level_fields, 0);
    // The same words and the same counts as any other window that is not shown.
    const text = body<Peek>(await tool(PROTOBUF, cwd, { hex: "68656c6c6f20776f726c64206162636465", length: 16 }));
    assert.equal(text.structure.status, "not_accepted");
    assert.equal(budgeted.structure.reason, text.structure.reason);
    // A window nobody aimed (the start of the file) is still read as far as the budget goes, and said to be partial.
    const unaimed = body<Peek>(await tool(PROTOBUF, cwd, { hex, max_fields: 4 }));
    assert.equal(unaimed.structure.status, "partial");
    assert.equal(unaimed.field_count, 4);

    // And over tokens: every window a budget of four fields shows is a window the default budget shows too.
    const probe = String.raw`
import importlib.util, json, random, sys, time
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("pb", sys.argv[1]); pb = importlib.util.module_from_spec(spec); spec.loader.exec_module(pb)
rng = random.Random(21)
def varint(n):
    out = bytearray()
    while True:
        b = n & 0x7F; n >>= 7
        if n: out.append(b | 0x80)
        else: out.append(b); return bytes(out)
def shown(win, max_fields):
    ctx = pb.Context(win, 0, 6, max_fields, time.monotonic() + 60)
    rows, state, problem, shape = pb.parse(ctx, 0, len(win), 0, [])
    return pb.window_accepted_by(win, state, shape, True)
extra, windows, default_shown, four_shown = 0, 0, 0, 0
for _ in range(int(sys.argv[2])):
    token = "".join(rng.choice("0123456789abcdef") for _ in range(64)).encode()
    prefix = b"\x08\x01\x12" + varint(len(token))
    message = prefix + token + b"\x18\x02"
    for offset in range(len(prefix), len(prefix) + len(token)):
        for size in range(1, min(len(message) - offset, 100) + 1):
            win = message[offset:offset + size]
            a, b = shown(win, 100000), shown(win, 4)
            windows += 1; default_shown += a; four_shown += b
            extra += (b and not a)
print(json.dumps({"windows": windows, "default_shown": default_shown, "four_shown": four_shown, "shown_only_with_four": extra}))
`;
    const run = await runPySnippet(probe, [PROTOBUF, "150"], null);
    assert.equal(run.code, 0, run.stderr);
    const counts = JSON.parse(run.stdout) as { windows: number; default_shown: number; four_shown: number; shown_only_with_four: number };
    assert.equal(counts.shown_only_with_four, 0, `${counts.shown_only_with_four} of ${counts.windows} windows were shown only because the budget was four fields`);
    assert.ok(counts.four_shown <= counts.default_shown);
  });
});

test("protobuf_peek holds a window it was aimed at to 16 bytes and 4 fields, and shows no window of printable text", async () => {
  await withCwd(async (cwd) => {
    const small = Buffer.concat([varintField(1, 7), lenDelimited(2, "hello"), varintField(3, 9)]);       // 3 fields, 12 bytes
    const four = Buffer.concat([varintField(1, 7), lenDelimited(2, "hello"), varintField(3, 300), lenDelimited(4, "world!")]);
    await writeFile(join(cwd, "work", "small.bin"), Buffer.concat([Buffer.alloc(4), small]));
    await writeFile(join(cwd, "work", "four.bin"), Buffer.concat([Buffer.alloc(4), four]));
    // Not aimed (offset 0, no length): the plain rule, 8 bytes and 2 fields.
    await writeFile(join(cwd, "work", "plain-small.bin"), small);
    assert.equal((await peek(cwd, { path: "work/plain-small.bin" })).answer.structure.status, "valid");
    // Aimed with an offset: the same bytes are not shown, and the reason carries no number from them.
    const aimedSmall = (await peek(cwd, { path: "work/small.bin", offset: 4 })).answer;
    assert.equal(aimedSmall.structure.status, "not_accepted");
    assert.equal(aimedSmall.fields.length, 0);
    assert.match(aimedSmall.structure.reason, /at least 8 bytes \(16 when offset or length was given\) with at least two fields \(4 when offset or length was given\)/);
    assert.equal((await peek(cwd, { path: "work/plain-small.bin", length: small.length })).answer.structure.status, "not_accepted", "a length is aiming too");
    assert.equal((await peek(cwd, { path: "work/four.bin", offset: 4 })).answer.structure.status, "valid");
    assert.equal((await peek(cwd, { hex: four.toString("hex"), length: four.length })).answer.structure.status, "valid");
    // A window of printable text is never a message, aimed or not: these are well-formed messages (printable tag bytes, one-byte varints) and the old rule
    // showed them, field numbers and values included.
    for (const printable of ["(A0B8C@D", "(A0B8C@DHEPF", " a(b0c8d@e"]) {
      const answer = (await peek(cwd, { hex: Buffer.from(printable).toString("hex") })).answer;
      assert.equal(answer.fields.length, 0, JSON.stringify(printable));
      assert.equal(answer.structure.consistent_with_protobuf_wire_format, false);
    }
  });
});

test("the three tools say status_basis, and protobuf_peek says status", async () => {
  await withCwd(async (cwd) => {
    const db = join(cwd, "work", "basis.db");
    await build(FREEBLOCK_DB, db, "BASIS-MARKER", "utf-8");
    const free = (await freespace(cwd, db, { min_length: 4 }, "basis")).answer as unknown as { status: string; status_basis: string };
    assert.equal(free.status, "complete");
    assert.match(free.status_basis, /every page was accounted for/);
    const stopped = (await freespace(cwd, db, { min_length: 4, max_seconds: 1e-9 }, "basis2")).answer as unknown as { status: string; status_basis: string };
    assert.equal(stopped.status, "partial");
    assert.match(stopped.status_basis, /the time limit stopped the scan before page 1/);
    const four = Buffer.concat([varintField(1, 7), lenDelimited(2, "hello"), varintField(3, 300), lenDelimited(4, "world!")]);
    const ok = (await peek(cwd, { hex: four.toString("hex") })).answer as unknown as { status: string; status_basis: string };
    assert.equal(ok.status, "complete");
    assert.match(ok.status_basis, /whole window parsed/);
    const no = (await peek(cwd, { hex: "ff" })).answer as unknown as { status: string; status_basis: string };
    assert.equal(no.status, "partial");
    assert.match(no.status_basis, /no row is printed/);
    const dir = await backup(cwd, "basis", { entries: many(2), snapshot: "uploadingFiles" });
    const m = (await manifest(cwd, dir)).answer as unknown as { status: string; status_basis: string };
    assert.equal(m.status, "partial");
    assert.match(m.status_basis, /the backup did not finish/);
    const done = (await manifest(cwd, await backup(cwd, "basis2", { entries: many(2) }))).answer as unknown as { status: string; status_basis: string };
    assert.equal(done.status, "complete");
    assert.match(done.status_basis, /read to its end/);
  });
});

test("the helper's stdin: a child that never reads it is not an error, and null means no stdin at all", async () => {
  // runPySnippet wrote its JSON to a child that had already exited (a fixture builder never reads stdin): the Writable emitted EPIPE with no
  // listener, which became an uncaught exception that ended the whole test file on a loaded runner.
  const big = "x".repeat(8 * 1024 * 1024);
  const done = await runPySnippet("pass", [], { padding: big });
  assert.equal(done.code, 0);
  const nothing = await runPySnippet("import sys; print(repr(sys.stdin.read()))", [], null);
  assert.equal(nothing.stdout.trim(), "''");
});

test("the helper's stdin ignores a child that is gone and no other error of the write", () => {
  for (const code of ["EPIPE", "ERR_STREAM_DESTROYED"]) assert.equal(childGone({ code }), true, code);
  for (const code of ["EIO", "ENOSPC", "ECONNRESET", "EBADF", undefined]) assert.equal(childGone({ code }), false, String(code));
});

// --- what a requester can see of a sealed output, the counts of a window, one document, recovery-password shapes -----------

test("protobuf_peek prints no count and one status for a window it does not show, so a window slid over a token cannot read the token through them", async () => {
  // The answer for a window that was not a message still printed field_count, top_level_fields, counts.{varint,64-bit,32-bit,length-delimited,
  // nested_messages,deepest} and, for a wire type 3 or 4, the status `unsupported`. The parse stops at the first error, so those numbers came from the
  // token's bytes (leave-one-out, a base62 character kept 18 of 62 candidates, a digit 3.4 of 10; a 6-digit PIN lost about 8 of 20 bits).
  await withCwd(async (cwd) => {
    const alphabets: [string, string][] = [["digits", "0123456789"], ["base62", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"], ["hex", "0123456789abcdef"]];
    let seed = 12345;
    const next = (): number => { seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0; return seed; };
    const byLength = new Map<number, Set<string>>();
    let windows = 0, rejected = 0, shown = 0;
    for (const [name, alphabet] of alphabets) {
      const token = Array.from({ length: 20 }, () => alphabet[next() % alphabet.length]).join("");
      const message = Buffer.concat([varintField(1, 150), lenDelimited(2, token), varintField(3, 7)]);
      await writeFile(join(cwd, "work", `${name}.bin`), message);
      const start = 5;
      for (let at = start; at < start + 20; at += 2) {
        for (const length of [2, 3, 5, 8, 12, 16, 20]) {
          if (at + length > message.length) continue;
          windows++;
          const r = await tool(PROTOBUF, cwd, { path: `work/${name}.bin`, offset: at, length });
          const a = body<Pb>(r);
          if (a.structure.status !== "not_accepted") { shown++; continue; }
          rejected++;
          assert.equal(a.field_count, 0, `${name} ${at}+${length}`);
          assert.equal(a.top_level_fields, 0);
          assert.deepEqual(Object.values(a.counts).filter((n) => n !== 0), [], "every count is zero");
          assert.deepEqual(a.fields, []);
          assert.equal((a.structure as Record<string, unknown>).fields_not_tried_as_nested_at_max_depth, undefined);
          // Everything that is not about where the window is, is the same for every window of that length that was not shown.
          const { window: _w, source: _s, ...rest } = a as unknown as Record<string, unknown>;
          const set = byLength.get(a.structure.bytes_in_window) ?? new Set<string>();
          set.add(JSON.stringify(rest));
          byLength.set(a.structure.bytes_in_window, set);
        }
      }
    }
    assert.ok(rejected >= windows * 0.9, `${rejected} of ${windows} windows were not shown`);
    for (const [length, answers] of byLength) assert.equal(answers.size, 1, `${answers.size} different answers for rejected windows of ${length} bytes`);
    assert.ok(shown <= windows * 0.1);
    // A group is not told apart either.
    const group = Buffer.concat([varintField(1, 1), key(5, 3), varintField(1, 2), key(5, 4), varintField(2, 3)]);
    const g = body<Pb>(await tool(PROTOBUF, cwd, { hex: group.toString("hex") }));
    const plain = body<Pb>(await tool(PROTOBUF, cwd, { hex: Buffer.alloc(group.length, 0xff).toString("hex") }));
    assert.equal(g.structure.status, "not_accepted");
    assert.equal(JSON.stringify(g.structure), JSON.stringify(plain.structure));
  });
});

test("protobuf_peek's values file for a window that is not shown has the size of the window, whatever the window parses as", async () => {
  // The file held one row for every field the parse found, with its varints and its content: its size, which the harness shows the requester,
  // was a function of the window's bytes (how many fields, how many digits), and a sliding window read a token through it.
  await withCwd(async (cwd) => {
    const n = 24;
    const unordered = Buffer.concat(Array.from({ length: 12 }, (_, i) => varintField(12 - i, i + 1)));
    const group = Buffer.concat([key(1, 3), Buffer.alloc(n - 1, 0x01)]);
    const windows: [string, Buffer][] = [
      ["unordered", unordered], ["bad varint", Buffer.alloc(n, 0xff)], ["text", Buffer.from("abcdefghijklmnopqrstuvwx")], ["group", group],
      ["big numbers", Buffer.concat([varintField(3, 1n << 62n), varintField(2, 1), varintField(1, 1n << 40n), key_fixed(1, 7)])],
      ["one long field", Buffer.concat([key(1, 2), varint(n - 2), Buffer.alloc(n - 2, 0x80)])],
    ];
    assert.deepEqual(windows.map(([, b]) => b.length).filter((l) => l !== n), [], "the fixtures are one length");
    const sizes = new Set<number>();
    const digests = new Set<string>();
    for (const [name, window] of windows) {
      const r = await peek(cwd, { hex: window.toString("hex") }, "win-" + name.replace(/\W+/g, "-"));
      assert.equal(r.answer.structure.status, "not_accepted", name);
      assert.equal(r.values.length, 1, name);
      assert.equal(r.values[0].kind, "window");
      assert.equal(r.values[0].value, window.toString("hex"), "the whole window, as hexadecimal");
      const data = await readFile(join(cwd, "win-" + name.replace(/\W+/g, "-"), "protobuf-values.jsonl"));
      sizes.add(data.length);
      digests.add(sha256(data));
    }
    assert.equal(sizes.size, 1, `the values file's size follows the window's parse: ${[...sizes].join(", ")}`);
    assert.equal(digests.size, windows.length);
    // The padded readings of a number under a nested message are one width, whatever the number is.
    const lines: number[] = [];
    for (const v of [5, 100]) {
      const message = Buffer.concat([varintField(1, 150), lenDelimited(2, Buffer.concat([varintField(1, v), varintField(2, 3)]))]);
      const r = await peek(cwd, { hex: message.toString("hex") }, "num-" + v);
      assert.equal(r.answer.structure.status, "valid");
      const text = await readFile(join(cwd, "num-" + v, "protobuf-values.jsonl"), "utf8");
      const line = text.split("\n").find((l) => l.includes('"field_path": "2.1"') || l.includes('"field_path":"2.1"'));
      assert.ok(line, "the row of the nested number");
      lines.push(line.length);
    }
    assert.equal(new Set(lines).size, 1, `a withheld number's row differs in width: ${lines.join(", ")}`);
  });
});

test("manifest_db's sealed outputs and answer have the same size whatever a withheld name says", async () => {
  // The names are the hidden text of this tool. Two backups that differ only in the digits of a recovery-password-shaped component give the
  // same answer (the file ids, which are SHA-1 digests, differ in value and not in width) and files of the same size.
  await withCwd(async (cwd) => {
    const sizes = new Set<number>();
    const files = new Set<number>();
    for (const seed of [21, 22, 23]) {
      const key1 = recoveryName(seed), key2 = recoveryName(seed + 100);
      const entries = [{ id: ID_A, path: `Documents/${key1}/a.txt`, blob: "none" }, { id: ID_B, path: `Documents/${key2}.key`, blob: "none" }, ...many(260)];
      const dir = await backup(cwd, "same-" + seed, { entries });
      const r = await tool(MANIFEST, cwd, { path: dir, limit: 5 });
      const answer = body<Manifest>(r);
      sizes.add(r.stdout.replaceAll(dir, "").length);
      const kept = answer.pages.entries.all_results;
      assert.ok(kept, "the whole listing is in a file");
      files.add((await readFile(join(cwd, kept))).length);
      for (const secret of [key1, key2]) assert.equal(r.stdout.includes(secret), false);
    }
    assert.equal(sizes.size, 1, `the answer's size follows the hidden names: ${[...sizes].join(", ")}`);
    assert.equal(files.size, 1, `the listing file's size follows the hidden names: ${[...files].join(", ")}`);
  });
});

test("manifest_db orders domains by the text it prints, so a withheld domain does not stand where its hidden name sorts", async () => {
  // domains were sorted by (count, real name) and printed as the placeholder: among domains with the same count, where the placeholder stood
  // followed the hidden text.
  await withCwd(async (cwd) => {
    const orders: string[] = [];
    for (const [name, hidden] of [["low", recoveryName(5)], ["high", "zz-" + recoveryName(6)]] as const) {
      const dir = await backup(cwd, "dom-" + name, { entries: [
        { id: ID_A, path: "Library/a", domain: "HomeDomain", blob: "none" }, { id: ID_B, path: "Library/b", domain: "HomeDomain", blob: "none" },
        { id: ID_C, path: "Library/c", domain: hidden, blob: "none" }, { id: "cc" + "2".repeat(38), path: "Library/d", domain: hidden, blob: "none" },
      ] });
      const { answer } = await manifest(cwd, dir);
      orders.push(answer.domains.map((d) => d.domain).join("|"));
      assert.match((answer as unknown as { note: string }).note, /file_id is the SHA-1 of the domain and the real path/);
      assert.equal(answer.domains.some((d) => d.domain.includes(hidden)), false);
    }
    assert.equal(orders[0], orders[1], orders.join(" vs "));
  });
});

test("the three tools withhold a recovery password in the forms a name is saved in, and print a number that is not one", async () => {
  // Only the dashed eight-by-six form was withheld: spaces, underscores, dots, 48 contiguous digits, an en dash, full-width and Arabic-Indic digits,
  // a zero-width character inside and a name that carried seven of the eight groups were printed. Counts only, from a seeded generator; the key is
  // never a fixed literal.
  const probe = String.raw`
import importlib.util, json, random, sys
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("t", sys.argv[1]); t = importlib.util.module_from_spec(spec); spec.loader.exec_module(t)
rng = random.Random(77)
def group(): return "%06d" % rng.randrange(10 ** 6)
def key(n=8): return [group() for _ in range(n)]
fw = {ord(str(i)): 0xFF10 + i for i in range(10)}
ar = {ord(str(i)): 0x0660 + i for i in range(10)}
sup = {ord(str(i)): ord("⁰¹²³⁴⁵⁶⁷⁸⁹"[i]) for i in range(10)}
def hexs(n): return "".join(rng.choice("0123456789abcdef") for _ in range(n))
shapes = {
    "dashed": lambda: "-".join(key()),
    "dashed with a prefix and a suffix": lambda: "recovery-" + "-".join(key()) + ".txt",
    "spaces": lambda: " ".join(key()),
    "underscores": lambda: "_".join(key()),
    "dots": lambda: ".".join(key()),
    "contiguous": lambda: "".join(key()),
    "en dash": lambda: "–".join(key()),
    "minus sign": lambda: "−".join(key()),
    "mixed separators": lambda: "".join(g + rng.choice(["-", " ", "_", ".", " - "]) for g in key()[:-1]) + group(),
    "full-width digits": lambda: "-".join(key()).translate(fw),
    "Arabic-Indic digits": lambda: "-".join(key()).translate(ar),
    "zero-width inside": lambda: "-".join(key())[:rng.randrange(1, 40)] + "​" + "-".join(key())[0:0] + "".join(key())[0:0],
    "seven groups": lambda: "-".join(key(7)),
    "superscript digits": lambda: "".join(key()).translate(sup),
    "commas": lambda: ",".join(key()),
    "colons": lambda: ":".join(key()),
    "semicolons": lambda: ";".join(key()),
    "plus signs": lambda: "+".join(key()),
    "parentheses": lambda: "".join("(%s)" % g for g in key()),
    "hash signs": lambda: "#".join(key()),
    "tildes": lambda: "~".join(key()),
    "quote marks": lambda: "".join(rng.choice(['"%s"', "'%s'", "“%s”", "‘%s’"]) % g for g in key()),
    "accents": lambda: "".join(g + "\u0301" for g in key()),
    "symbols": lambda: rng.choice(["§", "©", "•", "→"]).join(key()),
    "four or more spaces": lambda: (" " * rng.randrange(4, 12)).join(key()),
    "tabs": lambda: "\t\t\t\t".join(key()),
    "two path components": lambda: "".join(key(4)) + "/" + "".join(key(4)),
    "eight path components": lambda: "/".join(key()),
    "components and separators": lambda: "-".join(key(3)) + "/" + ", ".join(key(5)),
}
benign = {
    "uuid": lambda: "-".join([hexs(8), hexs(4), hexs(4), hexs(4), hexs(12)]),
    "sha256": lambda: hexs(64),
    "sha1": lambda: hexs(40),
    "millisecond timestamp": lambda: str(1700000000000 + rng.randrange(10 ** 9)),
    "phone number": lambda: "+90 %d %03d %02d %02d" % (rng.randrange(500, 600), rng.randrange(1000), rng.randrange(100), rng.randrange(100)),
    "date and time": lambda: "2026-10-20 12:%02d:%02d" % (rng.randrange(60), rng.randrange(60)),
    "six groups": lambda: "-".join(key(6)),
    "ipv4": lambda: ".".join(str(rng.randrange(256)) for _ in range(4)),
    "photo name": lambda: "IMG_%04d.HEIC" % rng.randrange(10000),
    "photo path": lambda: "Media/DCIM/%dAPPLE/IMG_%04d.JPG" % (rng.randrange(100, 999), rng.randrange(10000)),
    "dated directories": lambda: "%04d/%02d/%02d/%02d/%02d/%02d" % (rng.randrange(2000, 2030), rng.randrange(1, 13), rng.randrange(1, 29), rng.randrange(24), rng.randrange(60), rng.randrange(60)),
    "two timestamps": lambda: "%014d_%014d" % (rng.randrange(10 ** 14), rng.randrange(10 ** 14)),
    "digits and letters": lambda: "".join(rng.choice("0123456789") if i % 7 else "k" for i in range(60)),
}
out = {"withheld": {}, "printed": {}}
N = 40
for name, make in shapes.items():
    n = 0
    for _ in range(N):
        v = make()
        if name == "zero-width inside":
            k = "-".join(key()); cut = rng.randrange(1, len(k) - 1); v = k[:cut] + "​" + k[cut:]
        n += t.WITHHELD in t.shown("Documents/" + v + "/note.txt", False) and v not in t.shown("Documents/" + v, False)
    out["withheld"][name] = n
for name, make in benign.items():
    out["printed"][name] = sum(1 for _ in range(N) if (lambda v: t.shown("Documents/" + v, False) == "Documents/" + v and t.scrub("opening " + v) == "opening " + v)(make()))
out["scrub_withheld"] = sum(1 for _ in range(N) if t.WITHHELD in t.scrub("cannot read " + "-".join(key()) + " (denied)"))
# A text longer than the tool judges is withheld whole and never run through the digit patterns; one inside the bound is judged once.
calls = []
judge = t.key_spans
t.key_spans = lambda text: (calls.append(len(text)), judge(text))[1]
hostile = ("1" * 41 + "a") * 400
out["long"] = {"printed": t.shown("Documents/" + hostile, False), "calls": len(calls), "limit": t.JUDGE_CHARS}
inside = ("1" * 41 + "a") * 150
t.shown("Documents/" + inside, False)
out["inside"] = {"calls": len(calls), "longest": max(calls)}
t.key_spans = judge
print(json.dumps(out))
`;
  for (const script of [FREESPACE, MANIFEST, PROTOBUF]) {
    const r = await runPySnippet(probe, [script], null);
    assert.equal(r.code, 0, r.stderr);
    const out = JSON.parse(r.stdout) as { withheld: Record<string, number>; printed: Record<string, number>; scrub_withheld: number;
      long: { printed: string; calls: number; limit: number }; inside: { calls: number; longest: number } };
    for (const [shape, n] of Object.entries(out.withheld)) assert.equal(n, 40, `${script}: ${n} of 40 names in the shape "${shape}" were withheld`);
    for (const [shape, n] of Object.entries(out.printed)) assert.equal(n, 40, `${script}: ${n} of 40 names in the shape "${shape}" were printed`);
    assert.equal(out.scrub_withheld, 40);
    assert.equal(out.long.printed, "<name too long to judge withheld>", script);
    assert.equal(out.long.calls, 0, "a path over the bound is not run through the digit patterns");
    assert.equal(out.inside.calls, 1, "a path inside it is judged once");
    assert.ok(out.inside.longest <= out.long.limit);
  }
});

test("the three tools write one whole document when a stop signal arrives while a large answer is being written to a reader that has not read yet", async () => {
  // The answer was print()ed: a signal during a write to a full pipe raised in the middle of it, and the stop handler wrote its failure document
  // after the truncated answer. The reader got two documents, the first cut short.
  await withCwd(async (cwd) => {
    const code = String.raw`
import importlib.util, sys, threading
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("t", sys.argv[1]); t = importlib.util.module_from_spec(spec); spec.loader.exec_module(t)
def ready():
    sys.stderr.write("READY\n"); sys.stderr.flush()
threading.Timer(1.0, ready).start()
def main():
    t.send({"rows": ["row %d" % i for i in range(120000)], "tail": "the end"})
t.run_main(main)
`;
    for (const script of [FREESPACE, MANIFEST, PROTOBUF]) {
      for (const sig of ["SIGTERM", "SIGINT", "SIGHUP"] as const) {
        const r = await new Promise<Run>((resolve, reject) => {
          const child = spawn("python3", ["-c", code, script], { cwd, env: { ...process.env, ...AGENT } });
          const out: Buffer[] = [], err: Buffer[] = [];
          let sent = false;
          const guard = setTimeout(() => child.kill("SIGKILL"), 60000);
          child.stderr.on("data", (c: Buffer) => {
            err.push(c);
            if (sent || !Buffer.concat(err).toString("utf8").includes("READY")) return;
            sent = true;
            // The child is blocked writing to a pipe nobody has read from: signal it, wait, then read.
            child.kill(sig);
            setTimeout(() => child.stdout.on("data", (b: Buffer) => out.push(b)), 400);
          });
          child.on("error", reject);
          child.on("close", (code2, signal) => {
            clearTimeout(guard);
            resolve({ code: code2 ?? (signal ? 128 + 99 : null), stdout: Buffer.concat(out).toString("utf8"), stderr: Buffer.concat(err).toString("utf8").replace("READY\n", "") });
          });
        });
        const label = `${script} ${sig}`;
        assert.doesNotMatch(r.stderr, /Traceback/, label);
        let parsed: Record<string, unknown> | undefined;
        try { parsed = JSON.parse(r.stdout) as Record<string, unknown>; } catch { /* reported below */ }
        assert.ok(parsed, `${label}: stdout is not one JSON document (exit ${r.code}, ${r.stdout.length} bytes)`);
        // The answer was being written, so it is the answer; or the signal came first and the one document is the failure.
        if (parsed.interrupted !== undefined) assert.ok(r.code !== 0, label);
        else { assert.equal(r.code, 0, label); assert.equal(parsed.tail, "the end"); assert.equal((parsed.rows as string[]).length, 120000); }
      }
    }
  });
});

test("the three tools give up on a reader that takes nothing for the write deadline, instead of waiting until they are killed", async () => {
  // From the moment an answer was being written every stop signal was ignored, so a pipe nobody read could be ended only by SIGKILL.
  await withCwd(async (cwd) => {
    const code = String.raw`
import importlib.util, sys, threading
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("t", sys.argv[1]); t = importlib.util.module_from_spec(spec); spec.loader.exec_module(t)
t.WRITE_STALL_SECONDS = 1
def ready():
    sys.stderr.write("READY\n"); sys.stderr.flush()
threading.Timer(0.5, ready).start()
def main():
    t.send({"rows": ["row %d" % i for i in range(120000)], "tail": "the end"})
t.run_main(main)
`;
    for (const script of [FREESPACE, MANIFEST, PROTOBUF]) {
      const r = await new Promise<{ code: number | null; killed: boolean; seconds: number; stderr: string }>((resolve, reject) => {
        const child = spawn("python3", ["-c", code, script], { cwd, env: { ...process.env, ...AGENT } });
        const err: Buffer[] = [];
        const began = Date.now();
        let killed = false;
        const guard = setTimeout(() => { killed = true; child.kill("SIGKILL"); }, 30000);
        child.stderr.on("data", (c: Buffer) => {
          err.push(c);
          // Signalled while blocked, and nothing is ever read from standard output.
          if (Buffer.concat(err).toString("utf8").includes("READY") && !err.some((x) => x.includes("SENT"))) { child.kill("SIGTERM"); err.push(Buffer.from("SENT")); }
        });
        child.on("error", reject);
        child.on("close", (code2) => { clearTimeout(guard); resolve({ code: code2, killed, seconds: (Date.now() - began) / 1000, stderr: Buffer.concat(err).toString("utf8") }); });
      });
      assert.equal(r.killed, false, `${script}: the tool had to be killed`);
      assert.equal(r.code, 141, `${script}: ${r.stderr}`);
      assert.doesNotMatch(r.stderr, /Traceback/);
      assert.match(r.stderr, /the reader took nothing for 1 seconds/);
    }
  });
});


// --- the second review round: a clock that includes the tool's overhead, a statement SQLite does not end, wrong `complete`s ---

/**
 * A database whose freed pages are overwritten with `abc\x80` repeated: a fragment of three characters every four bytes, 1,024 to a page.
 * Argv: path, the number of freelist leaf pages to fill (0: all of them).
 */
const SHORT_FRAGMENTS_DB = String.raw`
import sqlite3, struct, sys
path, fill = sys.argv[1], int(sys.argv[2])
db = sqlite3.connect(path)
db.execute("PRAGMA page_size = 4096")
db.execute("PRAGMA secure_delete = OFF")
db.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, b BLOB)")
db.execute("INSERT INTO t VALUES (1, zeroblob(110000))")
db.commit()
db.execute("DELETE FROM t")
db.commit()
db.close()
raw = bytearray(open(path, "rb").read())
size = struct.unpack_from(">H", raw, 16)[0]
leaves, trunk = [], struct.unpack_from(">I", raw, 32)[0]
while trunk:
    base = (trunk - 1) * size
    following, count = struct.unpack_from(">II", raw, base)
    leaves += [struct.unpack_from(">I", raw, base + 8 + 4 * i)[0] for i in range(count)]
    trunk = following
for leaf in leaves[:fill or len(leaves)]:
    raw[(leaf - 1) * size:leaf * size] = b"abc\x80" * (size // 4)
open(path, "wb").write(raw)
`;

test("sqlite_freespace charges every fragment its expression is called on, so fragments of three characters cannot run past the work budget", async () => {
  // A fragment of three characters under a cost bound of 1 was 3 steps of a budget of 10^9, which never bound: the calls (2.85 us each against
  // 0.12 us for the search) ran for as long as there were fragments, with the clock of max_seconds skipping all of it: a run with max_seconds 270
  // took 327 s against a tool timeout of 300.
  await withCwd(async (cwd) => {
    const db = join(cwd, "work", "short.db");
    await build(SHORT_FRAGMENTS_DB, db, "0");
    const budget = 3_000_000;
    const out = join(cwd, "short");
    const run = await runPySnippet(FREESPACE_SLOW_EXPRESSION, [FREESPACE, cwd, out, "0", String(budget)], { db, write_values: true, contains: "a", min_length: 3, limit: 1 });
    const answer = body<Free>(run);
    const rows = await jsonl<Value>(join(out, "sqlite-freespace-values.jsonl"));
    assert.equal(rows.length, answer.fragment_count);
    assert.ok(answer.fragment_count > 20000, `${answer.fragment_count} fragments`);
    assert.ok(rows.every((r) => r.characters === 3));
    let running = 0;
    const expected = rows.map((r) => { running += FRAGMENT_STEPS + r.characters; return running > budget; });
    const decided = expected.filter((late) => !late).length;
    assert.equal(decided, Math.floor(budget / (FRAGMENT_STEPS + 3)), "the budget is spent at FRAGMENT_STEPS and the characters a fragment");
    assert.deepEqual(rows.map((r) => r.match === 2), expected);
    assert.equal(answer.scanned.contains_not_decided, answer.fragment_count - decided);
    assert.equal(answer.status, "partial");
  });
});

test("sqlite_freespace's clock skips at most EXPRESSION_ALLOWANCE for the time its expression takes, whatever the work budget says", async () => {
  // The whole call of the expression was taken off the clock with no bound but the work budget, which a run of short fragments never reached:
  // a starved machine, or a slow call, ran for as long as it liked past max_seconds and the manifest's timeout.
  await withCwd(async (cwd) => {
    const db = join(cwd, "work", "slow.db");
    await build(SHORT_FRAGMENTS_DB, db, "2");          // 2,048 fragments; at 5 ms a call, 10 s of expression
    const out = join(cwd, "slow");
    const started = Date.now();
    const run = await runPySnippet(FREESPACE_SLOW_EXPRESSION, [FREESPACE, cwd, out, "0.005", "1000000000000", "0.3"],
      { db, write_values: true, contains: "a", min_length: 3, max_seconds: 0.5, limit: 1 });
    const answer = body<Free>(run);
    assert.equal(answer.status, "partial", answer.status_basis);
    assert.notEqual(answer.stopped_before_page, null, "the time limit stopped the scan");
    assert.equal(answer.problem_kinds["time limit"], 1);
    assert.ok(Date.now() - started < 8000, `took ${Date.now() - started} ms`);
  });
});

test("sqlite_freespace finds the runs of a region of thousands of fragments in linear time", async () => {
  // covered_by summed over every run accepted so far for each candidate: a 64 KiB page of 8,191 fragments took 7.4 s, and the deadline is not read inside.
  await withCwd(async (cwd) => {
    const code = String.raw`
import importlib.util, json, sys, time
spec = importlib.util.spec_from_file_location("fs", sys.argv[1]); fs = importlib.util.module_from_spec(spec); spec.loader.exec_module(fs)
region = b"a\0b\0c\0\0\0" * 8191
patterns = fs.compile_runs(3)
began = time.perf_counter()
found, dropped = fs.runs_in(region, patterns, ["utf-16le"], 8)
print(json.dumps({"found": len(found), "dropped": dropped, "seconds": time.perf_counter() - began}))
`;
    const r = await runPySnippet(code, [FREESPACE], null);
    assert.equal(r.code, 0, r.stderr);
    const result = JSON.parse(r.stdout) as { found: number; dropped: number; seconds: number };
    assert.equal(result.found, 8191);
    assert.ok(result.seconds < 2, `${result.seconds} s for one region`);
  });
});

/** Deleted rows whose text is on overflow pages: 40 messages of 14 KB in 4 KiB pages (the freed pages are a freelist trunk and leaves). */
const BIG_ROWS_DB = String.raw`
import sqlite3, sys
path, marker = sys.argv[1:3]
db = sqlite3.connect(path)
db.execute("PRAGMA page_size = 4096")
db.execute("PRAGMA secure_delete = OFF")
db.execute("CREATE TABLE m (id INTEGER PRIMARY KEY, body TEXT)")
db.executemany("INSERT INTO m VALUES (?, ?)", [(i, (marker + "-%03d " % i) * 800) for i in range(1, 41)])
db.commit()
db.execute("DELETE FROM m")
db.commit()
db.close()
`;

test("sqlite_freespace is not complete when the header's freelist fields are zeroed, and reads the pages it no longer leads to", async () => {
  // Zeroing bytes 32 to 39 of the header (the freelist's first trunk page and its length) made 120 freed pages `pages_not_btree`, and the answer was
  // `complete`, "every page was examined", with 12 fragments of 167: eight bytes edited hid the deleted text.
  await withCwd(async (cwd) => {
    for (const [name, builder, count] of [["rows", BIG_ROWS_DB, 40], ["leaves", FREELIST_DB, 40]] as const) {
      const db = join(cwd, "work", `${name}.db`);
      await build(builder, db, "ZEROED-MARKER");
      const intact = await freespace(cwd, db, { min_length: 12 }, `${name}-intact`);
      assert.equal(intact.answer.status, "complete", intact.answer.status_basis);
      const marked = (rows: Value[]): number => rows.filter((v) => v.value.includes("ZEROED-MARKER")).length;
      assert.ok(marked(intact.rows) >= count / 2, `${marked(intact.rows)} fragments with the marker`);
      const bytes = await readFile(db);
      bytes.fill(0, 32, 40);
      const zeroed = join(cwd, "work", `${name}-zeroed.db`);
      await writeFile(zeroed, bytes);
      const hidden = await freespace(cwd, zeroed, { min_length: 12 }, `${name}-zeroed`);
      assert.notEqual(hidden.answer.status, "complete", `${name}: ${hidden.answer.status_basis}`);
      assert.equal(hidden.answer.status, "corrupt");
      assert.ok((hidden.answer.problem_kinds["pages in no structure"] ?? 0) >= 1, JSON.stringify(hidden.answer.problem_kinds));
      assert.ok(hidden.answer.scanned.pages_in_no_structure > 0);
      assert.doesNotMatch(hidden.answer.status_basis ?? "", /every page was/);
      assert.equal(marked(hidden.rows), marked(intact.rows), `${name}: the deleted text is found without the freelist`);
      // Only the count zeroed was already corrupt, and stays so.
      const countOnly = await readFile(db);
      countOnly.fill(0, 36, 40);
      await writeFile(join(cwd, "work", `${name}-count.db`), countOnly);
      assert.equal((await freespace(cwd, join(cwd, "work", `${name}-count.db`), { min_length: 12 }, `${name}-count`)).answer.status, "corrupt");
    }
  });
});

/** A live database whose rows spill onto overflow pages, in tables, indexes and a WITHOUT ROWID table. Argv: path, page size, auto_vacuum. */
const OVERFLOW_DB = String.raw`
import sqlite3, sys
path, page_size, auto_vacuum = sys.argv[1:4]
db = sqlite3.connect(path)
db.execute("PRAGMA page_size = " + page_size)
db.execute("PRAGMA auto_vacuum = " + auto_vacuum)
db.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, a TEXT, b BLOB)")
db.execute("CREATE INDEX ta ON t (a)")
db.execute("CREATE TABLE w (k TEXT PRIMARY KEY, v BLOB) WITHOUT ROWID")
for i in range(60):
    db.execute("INSERT INTO t (a, b) VALUES (?, ?)", ("row-%d-" % i + "q" * (200 + 700 * i), bytes([i]) * (3000 * (i % 7))))
    db.execute("INSERT INTO w VALUES (?, ?)", ("key-%d-" % i + "z" * (50 * i), bytes([i]) * (500 * i)))
db.commit()
db.close()
`;

test("sqlite_freespace accounts for the overflow pages of live rows and is complete, in every page size and with auto-vacuum", async () => {
  await withCwd(async (cwd) => {
    for (const [pageSize, vacuum] of [["512", "0"], ["1024", "1"], ["4096", "0"], ["4096", "2"], ["16384", "0"], ["65536", "0"]]) {
      const db = join(cwd, "work", `live-${pageSize}-${vacuum}.db`);
      await build(OVERFLOW_DB, db, pageSize, vacuum);
      const { answer } = await freespace(cwd, db, {}, `live-${pageSize}-${vacuum}`);
      assert.equal(answer.status, "complete", `${pageSize}/${vacuum}: ${answer.status_basis} ${JSON.stringify(answer.problem_kinds)}`);
      assert.ok(answer.scanned.overflow_pages > 0, `${pageSize}/${vacuum}: ${JSON.stringify(answer.scanned)}`);
      assert.equal(answer.scanned.pages_in_no_structure, 0);
    }
    // And a table that was dropped without its pages being freed (as a damaged file leaves it) is pages no structure owns.
    const db = join(cwd, "work", "orphan.db");
    await build(OVERFLOW_DB, db, "4096", "0");
    const bytes = await readFile(db);
    const master = bytes.subarray(100);        // sqlite_master is page 1 after the 100-byte header; make it list no table: zero its cell count
    master.writeUInt16BE(0, 3);
    master.writeUInt16BE(4096 - 100, 5);       // the cell content area is empty, as in a database without tables
    await writeFile(join(cwd, "work", "orphan-schema.db"), bytes);
    const answer = (await freespace(cwd, join(cwd, "work", "orphan-schema.db"), {}, "orphan")).answer;
    assert.notEqual(answer.status, "complete");
    assert.ok(answer.scanned.pages_in_no_structure > 10, JSON.stringify(answer.scanned));
  });
});

/** A Manifest.db whose table b-tree is a graph: 19 interior pages of 4 cells that all point at the next page, ending in one leaf (4^18 leaf visits). */
const DAG_DB = String.raw`
import os, sqlite3, struct, sys
dest, fan, levels, ps = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), 512
def varint(n):
    out = [n & 0x7f]
    n >>= 7
    while n:
        out.append((n & 0x7f) | 0x80)
        n >>= 7
    return bytes(reversed(out))
os.makedirs(dest, exist_ok=True)
path = os.path.join(dest, "Manifest.db")
con = sqlite3.connect(path)
con.execute("PRAGMA page_size = %d" % ps)
con.execute("CREATE TABLE Files (fileID TEXT, domain TEXT, relativePath TEXT, flags INTEGER, file BLOB)")
con.execute("INSERT INTO Files VALUES ('0123456789abcdef0123456789abcdef01234567', 'HomeDomain', 'Library/x', 1, NULL)")
con.commit()
con.close()
data = bytearray(open(path, "rb").read())
leaf = bytearray(data[ps:2 * ps])
leaf_no = levels + 2
pages = []
for i in range(levels):
    child = 2 + i + 1 if i < levels - 1 else leaf_no
    page = bytearray(ps)
    page[0] = 5
    content, pointers = ps, []
    for j in range(fan):
        cell = struct.pack(">I", child) + varint(j + 1)
        content -= len(cell)
        page[content:content + len(cell)] = cell
        pointers.append(content)
    struct.pack_into(">H", page, 3, fan)
    struct.pack_into(">H", page, 5, content)
    struct.pack_into(">I", page, 8, child)
    for j, pointer in enumerate(pointers):
        struct.pack_into(">H", page, 12 + 2 * j, pointer)
    pages.append(page)
out = bytearray(data[:ps])
for page in pages:
    out += page
out += leaf
struct.pack_into(">I", out, 28, leaf_no)
struct.pack_into(">I", out, 24, struct.unpack_from(">I", out, 92)[0])
open(path, "wb").write(out)
`;

/** The tool run for at most `killMs`, with a signal sent after `after` ms when one is given. `killed` says the harness had to end it. */
async function guarded(script: string, cwd: string, args: unknown, killMs: number, signal?: { name: NodeJS.Signals; after: number }): Promise<Run & { killed: boolean; ms: number }> {
  return new Promise((resolve, reject) => {
    const began = Date.now();
    const child = spawn("python3", [script], { cwd, env: { ...process.env, ...AGENT } });
    const out: Buffer[] = [], err: Buffer[] = [];
    let killed = false;
    const guard = setTimeout(() => { killed = true; child.kill("SIGKILL"); }, killMs);
    if (signal) setTimeout(() => child.kill(signal.name), signal.after);
    child.stdout.on("data", (c: Buffer) => out.push(c));
    child.stderr.on("data", (c: Buffer) => err.push(c));
    child.on("error", reject);
    child.on("close", (code) => {
      clearTimeout(guard);
      resolve({ code, killed, ms: Date.now() - began, stdout: Buffer.concat(out).toString("utf8"), stderr: Buffer.concat(err).toString("utf8") });
    });
    child.stdin.on("error", () => {});
    child.stdin.end(JSON.stringify(args));
  });
}

test("manifest_db ends a statement SQLite will not end: a table b-tree that points at itself, at max_seconds and on a stop signal", async () => {
  // `SELECT count(*) FROM Files` ran before the deadline loop with no limit: a 10 KB Manifest.db hung the tool for ever, and SIGTERM did nothing
  // (Python runs its handler only when the C call returns).
  await withCwd(async (cwd) => {
    const dir = join(cwd, "work", "dag");
    await build(DAG_DB, dir, "4", "19");
    const r = await guarded(MANIFEST, cwd, { path: dir, max_seconds: 2 }, 40000);
    assert.equal(r.killed, false, "the tool had to be killed after 40 s");
    assert.equal(r.code, 0, r.stderr + r.stdout);
    const answer = JSON.parse(r.stdout) as Manifest;
    assert.equal(answer.status, "partial");
    assert.notEqual(answer.stopped_at_row, null);
    assert.equal(answer.files_in_manifest, null, "the count was not finished and is not made up");
    assert.ok(answer.observations.some((o) => /were not all counted in the time given to the count/.test(o)), answer.observations.join("\n"));
    assert.ok(answer.observations.some((o) => /max_seconds \(2\) passed after \d+ rows/.test(o)), answer.observations.join("\n"));
    assert.ok(r.ms < 20000, `${r.ms} ms`);
    // A stop signal while SQLite runs: one JSON, exit 128 + 15.
    const s = await guarded(MANIFEST, cwd, { path: dir, max_seconds: 120 }, 40000, { name: "SIGTERM", after: 1500 });
    assert.equal(s.killed, false, "SIGTERM was not answered");
    assert.equal(s.code, 143, s.stderr + s.stdout);
    const stopped = JSON.parse(s.stdout) as Record<string, unknown>;
    assert.equal(stopped.interrupted, "SIGTERM");
    assert.equal(stopped.status, "failed");
    assert.doesNotMatch(s.stderr, /Traceback/);
  });
});

test("manifest_db reads a name column to its first 8,193 characters, so a cell of tens of megabytes does not become a string of that size", async () => {
  // The whole TEXT cell was read into Python, decoded, and kept (the domain as a key): a 50 MB path was 187 MB resident, a 200 MB one 659 MB.
  await withCwd(async (cwd) => {
    const dir = await backup(cwd, "hugenames", { entries: [{ id: ID_A, path: "Library/a.db" }, { id: ID_B, path: "x" }, { id: ID_C, path: "Library/c.db", domain: "AppDomain-x" }] });
    const make = String.raw`
import sqlite3, sys
con = sqlite3.connect(sys.argv[1])
con.execute("UPDATE Files SET relativePath = ? WHERE fileID = ?", ("a" * 24000000, sys.argv[2]))
con.execute("UPDATE Files SET domain = ? WHERE fileID = ?", ("d" * 24000000, sys.argv[2]))
con.execute("UPDATE Files SET domain = ? WHERE fileID = ?", ("d" * 24000001, sys.argv[3]))
con.commit()
`;
    assert.equal((await runPySnippet(make, [join(dir, "Manifest.db"), ID_B, ID_C], null)).code, 0);
    const run = await measured(MANIFEST, cwd, { path: dir });
    const answer = body<Manifest>(run.run);
    const tiny = await measured(MANIFEST, cwd, { path: await backup(cwd, "tinynames", { entries: [{ id: ID_A, path: "Library/a.db" }] }) });
    assert.ok(run.traced - tiny.traced < 2 * 1024 * 1024, `${run.traced - tiny.traced} bytes more allocated by Python than for a small backup, for two cells of 24 MB`);
    const rows = Object.fromEntries(answer.entries.map((e) => [e.file_id, e]));
    assert.equal(rows[ID_B].relative_path, "<name too long to judge withheld>");
    assert.equal(rows[ID_B].domain, "<name too long to judge withheld>");
    assert.equal(rows[ID_C].domain, "<name too long to judge withheld>");
    assert.equal(rows[ID_A].relative_path, "Library/a.db");
    // Two domains of different lengths are two, as they were when they were read whole.
    assert.equal((answer as unknown as { domain_count: number }).domain_count, 3);
  });
});

test("manifest_db does not read a plain plist of more than 4 MiB, and says so", async () => {
  // Three nested-array plists of 28 MB were 1.1 GB resident and 8 s: the plain plists of a backup are a few dozen kilobytes.
  await withCwd(async (cwd) => {
    const dir = await backup(cwd, "bigplist", { entries: many(2), info_extra: { "Padding": "p".repeat(5 << 20) } });
    const answer = (await manifest(cwd, dir)).answer;
    assert.equal(answer.info_plist.status, "too_large");
    assert.match(String(answer.info_plist.reason), /over 4194304/);
    assert.equal(answer.manifest_plist.status, "ok");
    assert.equal(answer.entry_count, 2);
  });
});

test("manifest_db says the working copy holds every name, because it does", async () => {
  // paths_note said a recovery-password-shaped component was withheld "from every path in this answer and in the files it names", and the working copy
  // it names beside a -wal is a byte copy of Manifest.db.
  await withCwd(async (cwd) => {
    const withWal = await backup(cwd, "notecopy", { entries: [{ id: ID_A, path: `Library/${RECOVERY_NAME}/a.db` }], wal: many(2, (i) => ({ id: (i + 100).toString(16).padStart(40, "0") })) });
    const answer = (await manifest(cwd, withWal)).answer as unknown as { paths_withheld: number; paths_note: string; manifest_db_file: { working_copy?: string } };
    assert.equal(answer.paths_withheld, 1);
    assert.ok(answer.manifest_db_file.working_copy);
    assert.match(answer.paths_note, /except the working copy named under manifest_db_file\.working_copy, a byte copy of Manifest\.db that holds every name as the database has it|the one exception is the working copy named under manifest_db_file\.working_copy, a byte copy of Manifest\.db/);
    const plain = await backup(cwd, "notenocopy", { entries: [{ id: ID_A, path: `Library/${RECOVERY_NAME}/a.db` }] });
    const without = (await manifest(cwd, plain)).answer as unknown as { paths_note: string };
    assert.doesNotMatch(without.paths_note, /working copy/);
  });
});

test("manifest_db is partial for every row whose metadata is not in the answer, not only the two states it listed", async () => {
  // not_keyed_archive and absent rows were listed with their path and blob state only, and the status stayed complete.
  await withCwd(async (cwd) => {
    const dir = await backup(cwd, "nokeyed", { entries: many(3) });
    const make = String.raw`
import plistlib, sqlite3, sys
con = sqlite3.connect(sys.argv[1])
con.execute("UPDATE Files SET file = ? WHERE fileID = ?", (plistlib.dumps({"just": "a plist"}), sys.argv[2]))
con.commit()
`;
    assert.equal((await runPySnippet(make, [join(dir, "Manifest.db"), many(3)[0].id as string], null)).code, 0);
    const answer = (await manifest(cwd, dir)).answer;
    assert.equal(answer.counts.metadata.not_keyed_archive, 1);
    assert.equal(answer.status, "partial");
    assert.match(answer.status_basis ?? "", /the metadata of 1 listed row\(s\) is not in the answer/);
    const absent = await backup(cwd, "absentmeta", { entries: many(3, (i) => (i === 1 ? { nometa: true } : {})) });
    const a = (await manifest(cwd, absent)).answer;
    assert.equal(a.counts.metadata.absent, 1);
    assert.equal(a.status, "partial");
  });
});

test("protobuf_peek is partial when bytes lie after the window it parsed whole, however the window ended", async () => {
  // A window that ended on a field boundary was `complete` with 12,582,912 bytes after it undecoded (the note and next_offset were right, the headline was not).
  await withCwd(async (cwd) => {
    const record = Buffer.concat([Buffer.from([0x0a, 0xfd, 0x01]), Buffer.alloc(253)]);        // 256 bytes: field 1, 253 zero bytes
    const file = join(cwd, "work", "records.pb");
    await writeFile(file, Buffer.concat(Array.from({ length: (9 << 20) / 256 }, () => record)));    // 9 MiB; the default window is 8 MiB, which ends on a record
    const whole = (await peek(cwd, { path: "work/records.pb", limit: 3 })).answer as unknown as { status: string; status_basis: string } & Pb;
    assert.equal(whole.structure.status, "valid");
    assert.equal(whole.structure.consistent_with_protobuf_wire_format, true, "the window itself is consistent");
    assert.equal(whole.window.bytes_after_window, 1 << 20);
    assert.equal(whole.status, "partial", whole.status_basis);
    assert.match(whole.status_basis, /not the whole input/);
    assert.match(whole.status_basis, /Bytes after the window are not decoded/);
    // An aimed window that ends on a record, and one that reaches the end of the file (complete: nothing after it).
    const aimed = (await peek(cwd, { path: "work/records.pb", offset: 256, length: 4096, limit: 3 })).answer as unknown as { status: string } & Pb;
    assert.equal(aimed.structure.status, "valid");
    assert.equal(aimed.status, "partial");
    const small = join(cwd, "work", "small.pb");
    await writeFile(small, Buffer.concat([record, record]));
    const all = (await peek(cwd, { path: "work/small.pb", limit: 3 })).answer as unknown as { status: string } & Pb;
    assert.equal(all.window.bytes_after_window, 0);
    assert.equal(all.status, "complete");
    const tail = (await peek(cwd, { path: "work/small.pb", offset: 256, limit: 3 })).answer as unknown as { status: string } & Pb;
    assert.equal(tail.window.bytes_after_window, 0);
    assert.equal(tail.structure.status === "valid" ? tail.status : "complete", "complete");
  });
});


// --- the third pass: a walk that held a pointer for every child, a freelist walk with no clock, a forged pointer-map flag, a ceiling that left no room ---

/** The tool with `time.monotonic` replaced by a clock that moves `argv[4]` seconds at every call, so that a deadline falls after a number of looks at the clock, not of seconds. */
const FREESPACE_FAKE_CLOCK = String.raw`
import importlib.util, os, sys, time
sys.dont_write_bytecode = True
step = float(sys.argv[4])
real = time.monotonic
calls = [0]
def fake():
    calls[0] += 1
    return real() + calls[0] * step
time.monotonic = fake
spec = importlib.util.spec_from_file_location("fs", sys.argv[1]); fs = importlib.util.module_from_spec(spec); spec.loader.exec_module(fs)
os.chdir(sys.argv[2])
os.environ.update(JOB_ID="j-1", OUT=sys.argv[3], SECRET_OUTPUT="1", AGENT_ID="s1")
os.makedirs(sys.argv[3], exist_ok=True)
fs.run_main(fs.main)
`;

/** A database whose page 1 is valid and whose pages 2..n are interior b-tree pages: `cells` cells each (a child pointer per cell, to a random page), or a chain (cells 0, the right-most child the next page). Argv: path, n, cells, page size. */
const INTERIOR_DB = String.raw`
import random, sqlite3, struct, sys
path, n, cells, ps = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
db = sqlite3.connect(path)
db.execute("PRAGMA page_size = %d" % ps)
db.execute("CREATE TABLE t (a)")
db.execute("INSERT INTO t VALUES (1)")
db.commit()
db.close()
data = bytearray(open(path, "rb").read())
rnd = random.Random(1)
out = bytearray(data[:ps])
for number in range(2, n + 1):
    page = bytearray(ps)
    page[0] = 5 if number < n or cells == 0 and number < n else 13
    if number < n:
        page[0] = 5
        struct.pack_into(">H", page, 3, cells)
        struct.pack_into(">H", page, 5, ps - 4 * max(cells, 1) if cells else ps)
        struct.pack_into(">I", page, 8, number + 1 if not cells else rnd.randint(2, n))
        for j in range(cells):
            struct.pack_into(">H", page, 12 + 2 * j, ps - 4 * (j + 1))
            struct.pack_into(">I", page, ps - 4 * (j + 1), rnd.randint(2, n))
    else:
        struct.pack_into(">H", page, 5, ps)
    out += page
struct.pack_into(">I", out, 28, n)
struct.pack_into(">I", out, 24, struct.unpack_from(">I", out, 92)[0])
open(path, "wb").write(out)
`;

test("sqlite_freespace keeps no pointer per child of an interior page, and stops at once on more child pointers than the file has pages", async () => {
  // survey() kept every child of every interior page (an array a page, then a stack of Python ints): 196 MB of interior pages took 44 s and
  // 3.08 GB, and an OOM kill under 2 GB left no JSON, where the previous code answered in 0.3 s.
  await withCwd(async (cwd) => {
    const tiny = join(cwd, "work", "tiny.db");
    await build(INTERIOR_DB, tiny, "3", "0", "4096");
    const base = await measured(FREESPACE, cwd, { db: tiny, limit: 1 });
    const big = join(cwd, "work", "fan.db");
    await build(INTERIOR_DB, big, "400", "600", "4096");
    const run = await measured(FREESPACE, cwd, { db: big, limit: 1 });
    const answer = body<Free>(run.run);
    assert.equal(answer.status, "corrupt");
    assert.ok(answer.problems.some((p) => p.kind === "b-tree links inconsistent" && /more child pointers than the file has pages \(400\)/.test(p.detail)), JSON.stringify(answer.problems.map((p) => p.detail)));
    assert.ok(run.traced - base.traced < 2 * 1024 * 1024, `${run.traced - base.traced} bytes more allocated than for a tiny database, for 400 interior pages of 600 cells`);
  });
});

test("sqlite_freespace reads the clock inside both walks of the b-trees and ends partial at the deadline", async () => {
  // The two walks of survey() never read the clock: 3,000 interior pages with max_seconds 16 ran 17 s past it.
  await withCwd(async (cwd) => {
    const db = join(cwd, "work", "chain.db");
    await build(INTERIOR_DB, db, "30000", "0", "512");        // a valid chain of 29,998 interior pages ending in a leaf: no fan-out, a long walk
    const out = join(cwd, "chain");
    const run = await runPySnippet(FREESPACE_FAKE_CLOCK, [FREESPACE, cwd, out, "0.002"], { db, max_seconds: 2, limit: 1 });
    const answer = body<Free>(run);
    assert.equal(answer.status, "partial", answer.status_basis);
    assert.equal(answer.stopped_before_page, 1, "the walk of the trees was stopped, before any page was scanned");
    assert.equal(answer.scanned.pages_not_reached, answer.database.pages_in_file);
    assert.equal(answer.problem_kinds["time limit"], 1);
  });
});

/** A freelist of trunk pages 3..n, each naming `1022` leaves that are all page 0 (outside the file); sparse. Argv: path, n. */
const TRUNKS_DB = String.raw`
import sqlite3, struct, sys
path, n, ps = sys.argv[1], int(sys.argv[2]), 4096
db = sqlite3.connect(path)
db.execute("PRAGMA page_size = %d" % ps)
db.execute("CREATE TABLE t (a)")
db.execute("INSERT INTO t VALUES (1)")
db.commit()
db.close()
with open(path, "r+b") as f:
    f.seek(ps * n - 1)
    f.write(b"\0")
    for number in range(3, n + 1):
        f.seek((number - 1) * ps)
        f.write(struct.pack(">II", number + 1 if number < n else 0, ps // 4 - 2))
    f.seek(32)
    f.write(struct.pack(">II", 3, n - 2))
    f.seek(28)
    f.write(struct.pack(">I", n))
    f.seek(24)
    f.write(struct.pack(">I", 7))
    f.seek(92)
    f.write(struct.pack(">I", 7))
`;

test("sqlite_freespace writes the first problems of a kind and folds the rest with an exact count, and reads the clock in the freelist walk", async () => {
  // 3,000 trunk pages of 1,022 leaves outside the file wrote 3.06 million problem rows (465 MB) and ran 10 s at max_seconds 2; about 86,000 pages pass 300 s.
  await withCwd(async (cwd) => {
    const db = join(cwd, "work", "trunks.db");
    await build(TRUNKS_DB, db, "800");
    const answer = (await freespace(cwd, db, { limit: 1 }, "trunks")).answer;
    assert.equal(answer.problem_kinds["freelist page outside the file"], 798 * 1022, "the count is exact");
    assert.ok(answer.pages.problems.matched <= 400, `${answer.pages.problems.matched} problem rows`);
    const folded = answer.problems.find((p) => (p as { folded?: number }).folded);
    assert.ok(folded, "one folded row for the kind");
    assert.equal((folded as unknown as { folded: number }).folded, 798 * 1022 - 100);
    assert.match(folded.detail, /more problems of this kind are folded into this row/);
    // The clock: a deadline that falls inside the walk stops it.
    const bigger = join(cwd, "work", "trunks-more.db");
    await build(TRUNKS_DB, bigger, "1200");
    const out = join(cwd, "trunks-clock");
    const run = await runPySnippet(FREESPACE_FAKE_CLOCK, [FREESPACE, cwd, out, "0.05"], { db: bigger, max_seconds: 0.5, limit: 1 });
    const stopped = body<Free>(run);
    assert.notEqual(stopped.status, "complete", stopped.status_basis);
    assert.equal(stopped.stopped_before_page, 1);
    assert.ok((stopped.problem_kinds["freelist page outside the file"] ?? 0) < 1100 * 1022, "the walk did not run to the end of the chain");
  });
});

test("sqlite_freespace reads a page at a pointer-map position that holds no pointer map, and is corrupt", async () => {
  // Bytes 52-55 of the header (auto-vacuum) put pointer-map pages at 2, 2+span, ...; they were skipped without a look, and the answer was complete
  // with eight fewer fragments: a forged flag hid the page.
  await withCwd(async (cwd) => {
    const db = join(cwd, "work", "ptrmap.db");
    await build(FREELIST_DB, db, "PTRMAP-MARKER");
    const marked = (rows: Value[]): number => rows.filter((v) => v.value.includes("PTRMAP-MARKER")).length;
    const intact = await freespace(cwd, db, { min_length: 12 }, "pm-intact");
    assert.equal(intact.answer.status, "complete");
    const bytes = await readFile(db);
    bytes.writeUInt32BE(1, 52);
    await writeFile(join(cwd, "work", "ptrmap-forged.db"), bytes);
    const forged = await freespace(cwd, join(cwd, "work", "ptrmap-forged.db"), { min_length: 12 }, "pm-forged");
    assert.equal(forged.answer.status, "corrupt", forged.answer.status_basis);
    assert.ok((forged.answer.problem_kinds["pointer-map page not a pointer map"] ?? 0) >= 1, JSON.stringify(forged.answer.problem_kinds));
    assert.equal(marked(forged.rows), marked(intact.rows), "the page is read");
  });
});

test("sqlite_freespace and manifest_db keep max_seconds at 255, so the allowance and the tail stay inside the manifest's 300 seconds", async () => {
  await withCwd(async (cwd) => {
    const db = join(cwd, "work", "cap.db");
    await build(FREELIST_DB, db, "CAP-MARKER");
    assert.match(refused(await rawTool(FREESPACE, cwd, `{"db":${JSON.stringify(db)},"max_seconds":256}`)).error, /max_seconds is at most 255/);
    const dir = await backup(cwd, "capbk", { entries: many(2) });
    assert.match(refused(await rawTool(MANIFEST, cwd, `{"path":${JSON.stringify(dir)},"max_seconds":256}`)).error, /max_seconds is at most 255/);
    for (const name of ["sqlite_freespace", "manifest_db"]) {
      const m = JSON.parse(await readFile(join(TOOLS, name, "manifest.json"), "utf8")) as { params: { max_seconds: { description: string } } };
      assert.match(m.params.max_seconds.description, /at most 255/, name);
    }
  });
});

test("manifest_db is not complete when a plain plist was too large to read, and does not say the backup finished when it cannot tell", async () => {
  // A Manifest.plist over the limit gave encryption `unknown` and a `complete` status; and a missing Status.plist gave "the backup finished".
  await withCwd(async (cwd) => {
    const dir = await backup(cwd, "bigmanifest", { entries: many(2), manifest_extra: { Padding: "p".repeat(6 << 20) } });
    const answer = (await manifest(cwd, dir)).answer;
    assert.equal(answer.manifest_plist.status, "too_large");
    assert.equal(answer.encryption.state, "unknown");
    assert.equal(answer.status, "partial");
    assert.match(answer.status_basis ?? "", /Manifest\.plist is over 4194304 bytes and was not read/);
    const nostatus = (await manifest(cwd, await backup(cwd, "nostatus", { entries: many(2), status_plist: false }))).answer;
    assert.equal(nostatus.status, "complete");
    assert.doesNotMatch(nostatus.status_basis ?? "", /the backup finished/);
    assert.match(nostatus.status_basis ?? "", /completion is unknown \(Status\.plist is missing\)/);
    const done = (await manifest(cwd, await backup(cwd, "finished", { entries: many(2) }))).answer;
    assert.match(done.status_basis ?? "", /the backup finished/);
  });
});
