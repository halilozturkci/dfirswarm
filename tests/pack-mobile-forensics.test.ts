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
import { ROOT, runPy, runPySnippet, withCwd } from "./tool-library-harness.ts";

const PACK = process.env.MOBILE_PACK ?? join(ROOT, "packs", "mobile-forensics");
const TOOLS = join(PACK, "tools");
const FREESPACE = join(TOOLS, "sqlite_freespace", "run.py");
const MANIFEST = join(TOOLS, "manifest_db", "run.py");
const PROTOBUF = join(TOOLS, "protobuf_peek", "run.py");
const AGENT = { AGENT_ID: "s1" };
const RECOVERY_NAME = "123456-654321-111111-222222-333333-444444-555555-666666";

type Run = { code: number | null; stdout: string; stderr: string };

async function tool(script: string, cwd: string, args: unknown, env: Record<string, string> = {}, bin?: string): Promise<Run> {
  return runPy(script, cwd, args, bin, { ...AGENT, ...env });
}

/** The tool as a job runs it: JOB_ID and OUT set, OUT inside the run directory. `name` keeps two runs apart. */
async function asJob(script: string, cwd: string, args: unknown, name = "out", job = "j-1"): Promise<Run> {
  await mkdir(join(cwd, name), { recursive: true });
  return tool(script, cwd, args, { JOB_ID: job, OUT: join(cwd, name) });
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

/** The tool run under a wrapper that reports the process's peak resident memory (bytes), after the answer on stdout. */
const MEASURE = String.raw`
import resource, runpy, sys
sys.argv = [sys.argv[1]]
try:
    runpy.run_path(sys.argv[0], run_name="__main__")
except SystemExit:
    pass
usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
sys.stderr.write("MAXRSS %d\n" % (usage if sys.platform == "darwin" else usage * 1024))
`;

async function measured(script: string, cwd: string, args: unknown, env: Record<string, string> = {}): Promise<{ run: Run; maxrss: number }> {
  return new Promise((resolve, reject) => {
    const child = spawn("python3", ["-c", MEASURE, script], { cwd, env: { ...process.env, ...AGENT, ...env } });
    const out: Buffer[] = [], err: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => out.push(c));
    child.stderr.on("data", (c: Buffer) => err.push(c));
    child.on("error", reject);
    child.on("close", (code) => {
      const stderr = Buffer.concat(err).toString("utf8");
      const m = /MAXRSS (\d+)/.exec(stderr);
      assert.ok(m, stderr);
      resolve({ run: { code, stdout: Buffer.concat(out).toString("utf8"), stderr: stderr.replace(/MAXRSS \d+\n/, "") }, maxrss: Number(m[1]) });
    });
    child.stdin.end(JSON.stringify(args));
  });
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
  db: string; parser: string; status: string; fragments: Fragment[]; fragment_count: number; filter: string | null; filter_narrows: string | null;
  problems: { kind: string; detail: string }[]; problem_kinds: Record<string, number>; stopped_before_page: number | null;
  database: { page_size: number; text_encoding: string; bytes: number; pages_in_file: number; journal_mode_on_disk: string };
  freelist: { declared: number; walked: number; trunk_pages: number };
  scanned: Record<string, number>; encodings_scanned: string[];
  companions: Record<string, { bytes: number; examined: boolean }>;
  secret_values: { requested: boolean; written: number | null; values_file: string | null; contains_secret_values: boolean | null; count_withheld?: string };
  pages: { fragments: Paged; problems: Paged }; paths_withheld: number; truncated: boolean;
};
type Value = { finding_id: string; file: string; page: number; where: string; encoding: string; offset: number; bytes: number; characters: number; value: string };

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

async function freespace(cwd: string, db: string, args: Record<string, unknown> = {}, name = "out"): Promise<{ answer: Free; values: Value[]; out: string; run: Run }> {
  const run = await asJob(FREESPACE, cwd, { db, write_values: true, ...args }, name);
  const answer = body<Free>(run);
  const valuesFile = join(cwd, name, "sqlite-freespace-values.jsonl");
  let values = (await exists(valuesFile)) ? await jsonl<Value>(valuesFile) : [];
  if (!values.length && answer.fragments.some((f) => f.text !== undefined)) {
    // The tool as it was before the fix printed each fragment's text in the answer: read it from there, so that a
    // test run against that code fails on the assertion that names the defect.
    values = answer.fragments.map((f, i) => ({ finding_id: `old${i}`, file: db, page: f.page, where: f.where, encoding: f.encoding, offset: f.offset,
      bytes: Buffer.byteLength(f.text ?? ""), characters: [...(f.text ?? "")].length, value: f.text ?? "" }));
  }
  return { answer, values, out: join(cwd, name), run };
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

test("sqlite_freespace stops at max_seconds even when a filter that backtracks runs on every fragment", async () => {
  // The regular expression was bounded per fragment and the clock only between pages: 7 fragments of a runaway
  // expression took 35 seconds against a limit of 1.
  await withCwd(async (cwd) => {
    const db = join(cwd, "work", "regex.db");
    await build(FREELIST_DB, db, "REGEX-MARKER");
    const started = Date.now();
    const { answer } = await freespace(cwd, db, { contains: "(w+)+z", max_seconds: 1, min_length: 20 });
    assert.ok(Date.now() - started < 12000, `took ${Date.now() - started} ms`);
    assert.equal(answer.status, "partial");
    assert.ok(answer.stopped_before_page !== null || answer.scanned.contains_timeouts >= 1);
  });
});

test("sqlite_freespace's contains narrows the sealed values file, and nothing in the answer says which fragments matched", async () => {
  // The answer listed the fragments that matched and the total before the filter: with text you cannot see, one call was one bit of every
  // fragment, and an alternation of guesses confirmed a short PIN in a few calls. The expression now only decides what is written to the file.
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
      assert.equal(other.answer.secret_values.written, null, "how many matched is not shown");
      assert.equal(other.answer.secret_values.contains_secret_values, null);
      assert.match(other.answer.secret_values.count_withheld ?? "", /how many fragments matched is not shown/);
    }
    assert.equal(some.answer.filter, "FILTER-MARKER");
    assert.match(some.answer.filter_narrows ?? "", /values file only/);
    // What is written is what matched.
    assert.ok(some.values.length >= 1 && some.values.length < all.values.length);
    assert.ok(some.values.every((v) => /FILTER-MARKER/i.test(v.value)));
    assert.equal(none.values.length, 0);
    assert.equal(everything.values.length, all.values.length);
    assert.deepEqual(some.answer.companions, { "-wal": { bytes: 32, examined: false } });
    assert.match(refused(await tool(FREESPACE, cwd, { db, contains: "(" })).error, /not a valid regex/);
    // contains with no values file to narrow is refused before anything is scanned, outside a job and in one.
    const bare = refused(await tool(FREESPACE, cwd, { db, contains: "FILTER-MARKER" }));
    assert.match(bare.error, /contains narrows the sealed values file: it needs write_values: true/);
    assert.equal(bare.contains_refused, true);
    assert.equal(bare.fragments, undefined);
    const noValues = refused(await asJob(FREESPACE, cwd, { db, contains: ".", write_values: false }, "novalues"));
    assert.equal(noValues.contains_refused, true);
    assert.equal(noValues.fragment_count, undefined);
  });
});

test("sqlite_freespace's contains cannot be used to learn which fragment is slow: a time-out is counted, not placed", async () => {
  await withCwd(async (cwd) => {
    const db = join(cwd, "work", "slowrx.db");
    await build(FREELIST_DB, db, "REGEX-MARKER");
    const { answer } = await freespace(cwd, db, { contains: "(w+)+z", max_seconds: 8, min_length: 20 }, "slow");
    assert.ok(answer.scanned.contains_timeouts >= 0);
    for (const problem of answer.problems) if (/contains took too long/.test(problem.kind)) assert.equal((problem as unknown as { page?: number }).page, undefined);
  });
});

test("sqlite_freespace's time limit is finite and below the tool's own, and says so as JSON", async () => {
  // NaN and Infinity switched the clock off, and a limit above the harness's 300 seconds ended the tool with no answer.
  await withCwd(async (cwd) => {
    const db = join(cwd, "work", "limit.db");
    await build(FREELIST_DB, db, "LIMIT-MARKER");
    for (const bad of ["NaN", "Infinity", "-Infinity", "1e308", "100000", "271", "0", "-1", "\"5\"", "true"]) {
      const r = await rawTool(FREESPACE, cwd, `{"db":${JSON.stringify(db)},"max_seconds":${bad}}`);
      assert.match(refused(r).error, /max_seconds/, bad);
    }
    const edge = await rawTool(FREESPACE, cwd, `{"db":${JSON.stringify(db)},"max_seconds":270}`);
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
  path: string; parser: string; status: string; encrypted: boolean | null;
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
    assert.ok(answer.observations.some((o) => /contains ran past its time on \d+ path\(s\)|time limit/.test(o)), answer.observations.join("\n"));
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
    assert.deepEqual(held["4"].value, { value: 0x3f800000, hex: "0000803f", float_reading: 1 });
    assert.equal(held["4"].kind, "number");
    assert.equal((held["3.2"].value as unknown as { value: number }).value, 5);
  });
});

test("protobuf_peek reads a bounded window of a large file, and says what lies after it, in a bounded amount of memory", async () => {
  // It read the whole file and then sliced from the offset. The test measures the process: a tool that reads the file
  // whole takes more than 200 MB for the file below, and this one stays under 64 MB.
  await withCwd(async (cwd) => {
    const big = join(cwd, "work", "big.bin");
    const message = Buffer.concat([varintField(1, 7), lenDelimited(2, "hello")]);
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
    assert.ok(one.maxrss < 64 * 1024 * 1024, `the tool took ${one.maxrss} bytes to read ${message.length} bytes of a 200 MiB file`);
    // Without a length the window is bounded too (8 MiB), never the whole file.
    const two = await measured(PROTOBUF, cwd, { path: "work/big.bin", offset: 100 });
    const dflt = body<Pb>(two.run);
    assert.equal(dflt.window.bytes, 8 * 1024 * 1024);
    assert.ok(dflt.window.next_offset);
    assert.ok(two.maxrss < 64 * 1024 * 1024, `the default window took ${two.maxrss} bytes`);
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
    assert.ok(run.maxrss < 200 * 1024 * 1024, `32 levels around ${inner.length} bytes took ${run.maxrss} bytes`);
  });
});

test("protobuf_peek withholds its rows from a window that is not a message, and names every structural error only in the job's values file", async () => {
  // Groups were noted and the parse went on; and rows were printed for a prefix that failed, in reasons that carried numbers
  // derived from the bytes.
  await withCwd(async (cwd) => {
    const group = Buffer.concat([varintField(1, 1), key(5, 3), varintField(1, 2), key(5, 4), varintField(2, 3)]);
    const { answer, run, values } = await peek(cwd, { hex: group.toString("hex") }, "group");
    assert.equal(answer.structure.status, "unsupported");
    assert.equal(answer.structure.consistent_with_protobuf_wire_format, false);
    assert.match(answer.structure.reason, /group/);
    assert.deepEqual(answer.fields, []);
    assert.equal(answer.structure.problem_offset, undefined, "no position derived from the bytes");
    assert.equal(answer.looks_like_protobuf, undefined);
    assert.equal(values.find((v) => v.kind === "diagnosis")?.offset, 2, "the diagnosis is in the values file");
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
      const diagnosis = r.values.find((v) => v.kind === "diagnosis")?.value as { reason: string; offset: number };
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
