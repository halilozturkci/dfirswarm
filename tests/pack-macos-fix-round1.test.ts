/**
 * The first fix round of the macos-forensics bundle, each case failing on the tools before it:
 *
 *  - fsevents_parse keeps its clock over an uncompressed record file with a long tail that is not a page (skip, read), and counts the rest of a file after an
 *    unsupported page from its size instead of reading it;
 *  - a write the filesystem refused is said to be a write that failed, never a fact about the evidence (fsevents_parse out_file, knowledgec_query's private
 *    copy on a full disk);
 *  - the looks at the staging directories (knowledgec_query's copies, unified_log's tree, census and copies) are under a clock or a cap;
 *  - the last-resort handler removes the pager's temporary file and names a partial out_file;
 *  - unified_log reads a line of exactly the cap, and a line nested a million levels deep is a line that did not parse.
 */
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { chmod, mkdir, readFile, readdir, stat, truncate, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { runPySnippet, withCwd } from "./tool-library-harness.ts";
import { CREATED, FS, KC, PLIST, PYTHON, UL, body, fsDir, fsPage, fsRecord, kcDb, logarchive, measured, tool, ul, ulStandin } from "./macos-pack-harness.ts";
import type { Json } from "./macos-pack-harness.ts";

const exists = (path: string): Promise<boolean> => stat(path).then(() => true, () => false);

/** A tool run under `ulimit -f <blocks>` (512-byte blocks): a write past it is refused with EFBIG. */
function limited(script: string, cwd: string, args: unknown, blocks: number, env: Record<string, string> = {}): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn("/bin/sh", ["-c", `ulimit -f ${blocks}; exec "$1" "$2"`, "sh", PYTHON, script], { cwd, env: { ...process.env, AGENT_ID: "s1", ...env } });
    const so: Buffer[] = [];
    const se: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => so.push(c));
    child.stderr.on("data", (c: Buffer) => se.push(c));
    child.on("error", reject);
    child.on("close", (c) => resolve({ code: c, stdout: Buffer.concat(so).toString("utf8"), stderr: Buffer.concat(se).toString("utf8") }));
    child.stdin.end(JSON.stringify(args));
  });
}

/** Runs a tool as `python3 run.py` does, with `patch` (Python, over the dict g of the module) applied between the definitions and the __main__ block. */
function patched(script: string, cwd: string, args: unknown, patch: string, env: Record<string, string> = {}): Promise<{ code: number | null; stdout: string; stderr: string }> {
  const code = `
import os, signal, sys
src = open(sys.argv[1], encoding="utf-8").read()
head, tail = src.split(chr(10) + 'if __name__ == "__main__":', 1)
g = {"__name__": "__main__", "__file__": sys.argv[1]}
exec(compile(head, sys.argv[1], "exec"), g)
${patch}
exec(compile('if __name__ == "__main__":' + tail, sys.argv[1], "exec"), g)
`;
  return new Promise((resolve, reject) => {
    const child = spawn("python3", ["-c", code, script], { cwd, env: { ...process.env, AGENT_ID: "s1", ...env } });
    const so: Buffer[] = [];
    const se: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => so.push(c));
    child.stderr.on("data", (c: Buffer) => se.push(c));
    child.on("error", reject);
    child.on("close", (c) => resolve({ code: c, stdout: Buffer.concat(so).toString("utf8"), stderr: Buffer.concat(se).toString("utf8") }));
    child.stdin.end(JSON.stringify(args));
  });
}

// ---- fsevents_parse: the clock over a file that is not compressed ----------------------------------------------------------------------------------

test("fsevents_parse keeps max_seconds over an uncompressed record file with a long tail that is not a page: 32 GiB after a page, max_seconds 1, ends in seconds", async () => {
  // skip_to_magic read the tail to its end outside the clock: a 16 GiB tail with max_seconds 5 took 150 s.
  await withCwd(async (cwd) => {
    const page = fsPage("2SLD", [fsRecord("Users/a/x.txt", 1n, CREATED, 1n)]);
    const file = join(cwd, "work", "raw");
    await writeFile(file, page);
    await truncate(file, 32 * 1024 ** 3);
    const run = await measured(FS, cwd, { path: "work/raw", max_seconds: 1 });
    const answer = JSON.parse(run.stdout) as Json;
    assert.ok(run.wall < 15, `${run.wall.toFixed(1)} s wall for max_seconds 1`);
    assert.ok(answer.limits.seconds_used < 12, `${answer.limits.seconds_used} s used`);
    assert.notEqual(answer.status, "complete");
    assert.equal(answer.record_count, 1, "the record before the tail is kept");
    assert.match(JSON.stringify(answer.problems), /time limit|max_seconds/);
  });
});

test("fsevents_parse counts the rest of a file after an unsupported (3SLD) page from its size, and does not read it: 32 GiB after the page", async () => {
  await withCwd(async (cwd) => {
    const page = fsPage("3SLD", [fsRecord("Users/a/x.txt", 1n, CREATED, 1n)]);
    const file = join(cwd, "work", "raw3");
    await writeFile(file, page);
    const size = 32 * 1024 ** 3;
    await truncate(file, size);
    const run = await measured(FS, cwd, { path: "work/raw3", max_seconds: 1 });
    const answer = JSON.parse(run.stdout) as Json;
    assert.ok(run.cpu < 3, `${run.cpu.toFixed(2)} s of CPU: the tail was read`);
    assert.equal(answer.coverage.bytes_not_decoded, size);
    assert.equal(answer.coverage.pages.unsupported, 1);
  });
});

// ---- a refused write is a write that failed -----------------------------------------------------------------------------------------------------

test("fsevents_parse says the records could not be written when out_file is refused (File too large), not 'read failed'", async () => {
  await withCwd(async (cwd) => {
    const page = fsPage("2SLD", Array.from({ length: 400 }, (_, i) => fsRecord(`Users/alice/Library/app${i}/file-${i}.tmp`, BigInt(i + 1), CREATED, BigInt(i + 1))));
    await fsDir(cwd, "fse", { "0000000000000001": page });
    const run = await limited(FS, cwd, { path: "work/fse", out_file: "work/o.jsonl" }, 4);
    const answer = JSON.parse(run.stdout) as Json;
    assert.notEqual(answer.status, "complete");
    const text = JSON.stringify(answer);
    assert.doesNotMatch(text, /read failed/);
    assert.match(text, /could not write|could not be written/);
    const kept = (await readFile(join(cwd, "work", "o.jsonl"), "utf8")).split("\n").filter(Boolean).length;
    assert.ok(kept <= answer.record_count + 0, `${kept} rows in the file, ${answer.record_count} counted: the count claims no more than was written`);
  });
});

test("knowledgec_query on a full or limited disk never says a valid database is not a SQLite database (ulimit -f of 8 to 200 blocks)", async () => {
  await withCwd(async (cwd) => {
    const db = await kcDb(cwd, "wal.db", 10, 0, {}, "wal");
    const seen = new Set<string>();
    for (const blocks of [4, 8, 12, 16, 20, 24, 32, 48, 64, 96, 128, 200, 400, 800]) {
      const run = await limited(KC, cwd, { db }, blocks);
      const answer = JSON.parse(run.stdout) as Json;
      assert.doesNotMatch(JSON.stringify(answer), /not a SQLite database|not a knowledgeC database/, `ulimit -f ${blocks}: ${run.stdout.slice(0, 300)}`);
      seen.add(answer.status);
    }
    assert.ok(seen.has("complete") || seen.has("partial"), "the largest limits are enough to read it");
  });
});

test("knowledgec_query on a tmpfs too small for the private copy's index says the staging area could not be written (unshare -rm)", async (t) => {
  const probe = spawnSync("unshare", ["-rm", "true"]);
  if (probe.status !== 0) return t.skip("no user and mount namespaces here");
  await withCwd(async (cwd) => {
    const db = await kcDb(cwd, "wal.db", 10, 0, {}, "wal");
    const said = new Set<string>();
    for (const kb of [16, 24, 32, 40, 48, 64, 96, 160]) {
      const mount = `mkdir -p work/s1/.knowledgec-stage && mount -t tmpfs -o size=${kb}k tmpfs work/s1/.knowledgec-stage`;
      const run = spawnSync("unshare", ["-rm", "sh", "-c", `${mount} && exec "$1" "$2"`, "sh", PYTHON, KC], { cwd, input: JSON.stringify({ db }), encoding: "utf8", env: { ...process.env, AGENT_ID: "s1" } });
      if (run.status === 125 || run.stdout === "") return t.skip(`cannot mount here: ${run.stderr.slice(0, 120)}`);
      const answer = JSON.parse(run.stdout) as Json;
      assert.doesNotMatch(run.stdout, /not a SQLite database|not a knowledgeC database/, `tmpfs ${kb}k: ${run.stdout.slice(0, 300)}`);
      if (/SQLite could not read or write/.test(run.stdout)) said.add(String(kb));
      assert.notEqual(answer.status, undefined);
    }
    assert.ok(said.size > 0, "a size was found at which SQLite itself could not write the index of the private copy");
  });
});

// ---- looks at the staging directories ---------------------------------------------------------------------------------------------------------

test("knowledgec_query looks at a directory of private copies with more than 10,000 entries in part, says so, and finishes", async () => {
  await withCwd(async (cwd) => {
    const db = await kcDb(cwd, "wal.db", 10, 0, {}, "wal");
    ok1(await tool(KC, cwd, { db }));                                                   // makes work/s1/.knowledgec-stage with its marker
    const parent = join(cwd, "work", "s1", ".knowledgec-stage");
    const made = await runPySnippet(`
import os, sys
for i in range(12000):
    os.close(os.open(os.path.join(sys.argv[1], "other%05d" % i), os.O_WRONLY | os.O_CREAT, 0o600))
`, [parent], null);
    assert.equal(made.code, 0, made.stderr);
    const run = await measured(KC, cwd, { db });
    const answer = JSON.parse(run.stdout) as Json;
    assert.ok(run.wall < 30, `${run.wall} s`);
    assert.match(answer.source_used.sweep_cut, /more than 10000 entries/);
  });
});

function ok1(run: { code: number | null; stdout: string; stderr: string }): Json {
  assert.equal(run.code, 0, run.stderr + run.stdout.slice(0, 300));
  return JSON.parse(run.stdout) as Json;
}

test("knowledgec_query names the copies an earlier version left in work/<id>, and does not remove them", async () => {
  await withCwd(async (cwd) => {
    const db = await kcDb(cwd, "wal.db", 10, 0, {}, "wal");
    const done = spawnSync("python3", ["-c", "import os; print(os.getpid())"], { encoding: "utf8" });
    const old = join(cwd, "work", "s1", `knowledgec-${done.stdout.trim()}-oldplace1`);
    await mkdir(old, { recursive: true, mode: 0o700 });
    await chmod(old, 0o700);
    await writeFile(join(old, "k.db"), "x".repeat(777), { mode: 0o600 });
    const answer = ok1(await tool(KC, cwd, { db }));
    const named = answer.source_used.copies_in_work_dir_not_swept;
    assert.equal(named.count, 1);
    assert.equal(named.listed[0].bytes, 777);
    assert.equal(await exists(join(old, "k.db")), true);
  });
});

test("knowledgec_query's wal count is under the clock: a deadline in the past stops at frame 0 and says so", async () => {
  const code = `
import importlib.util, struct, sys, tempfile, os, time
spec = importlib.util.spec_from_file_location("tool", sys.argv[1])
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
path = os.path.join(tempfile.mkdtemp(prefix="kc-wal-"), "x-wal")
page = 512
with open(path, "wb") as f:
    f.write(struct.pack(">IIIIII", 0x377F0682, 3007000, page, 1, 11, 22) + bytes(8))
    for i in range(5000):
        f.write(struct.pack(">IIII", i + 1, 1, 11, 22) + bytes(8) + bytes(page))
print(m.wal_inventory(path, time.monotonic() - 1)["counting_stopped_at_frame"], m.wal_inventory(path, time.monotonic() + 60)["frames_valid"])
`;
  const run = await runPySnippet(code, [KC], null);
  assert.equal(run.code, 0, run.stderr);
  assert.equal(run.stdout.trim(), "0 5000");
});

// ---- unified_log -----------------------------------------------------------------------------------------------------------------------------------

test("unified_log reads a line of exactly the cap (8 MiB without its newline) and counts a line of one byte more as over it; a line nested a million levels deep is a line that did not parse", async () => {
  await withCwd(async (cwd) => {
    const bin = await ulStandin(cwd, `
cap = 8 << 20
head = '{"timestamp": "2026-01-01T00:00:00", "eventMessage": "'
tail = '"}'
def line(total):
    return head + "x" * (total - len(head) - len(tail)) + tail
with open(out, "w") as f:
    f.write(line(cap) + chr(10))
    f.write(line(cap + 1) + chr(10))
    f.write("[" * 1000000 + "]" * 1000000 + chr(10))
    f.write(json.dumps({"timestamp": "2026-01-01T00:00:01", "eventMessage": "after"}) + chr(10))
`);
    const out = await ul(cwd, bin, { path: await logarchive(cwd), out_dir: "work/o" });
    const answer = JSON.parse(out.stdout) as Json;
    assert.equal(answer.error, undefined, out.stdout.slice(0, 300));
    assert.equal(answer.decoded_coverage.lines_over_cap, 1, "only the line of cap + 1 bytes is over it");
    assert.equal(answer.decoded_coverage.unparsed_lines, 1, "the nested line did not parse");
    assert.equal(answer.entry_count, 2, "the line of exactly the cap and the last line are entries");
    assert.equal(answer.status, "partial");
  });
});

test("unified_log's staging is under the clock: 3 GiB in one file with timeout_seconds 2 ends in the refusal for time, not after the copy", async () => {
  await withCwd(async (cwd) => {
    const root = join(cwd, "work", "vardb");
    await mkdir(join(root, "diagnostics", "timesync"), { recursive: true });
    await mkdir(join(root, "uuidtext"), { recursive: true });
    await writeFile(join(root, "diagnostics", "timesync", "0000.timesync"), "");
    const big = join(root, "diagnostics", "big.tracev3");
    await writeFile(big, "x");
    await truncate(big, 3 * 1024 ** 3);
    const bin = await ulStandin(cwd, `open(out, "w").write("")`);
    const begun = Date.now();
    const out = await ul(cwd, bin, { path: "work/vardb", out_dir: "work/o", timeout_seconds: 2, max_stage_bytes: 8 * 1024 ** 3 });
    assert.ok(Date.now() - begun < 20_000, `${Date.now() - begun} ms`);
    assert.equal(out.code, 1);
    assert.match(JSON.parse(out.stdout).error, /staging used the whole time budget/);
    assert.equal(await exists(join(cwd, "work", "o", ".logarchive-input")), false, "the staged copy is removed");
  });
});

// ---- the last resort ---------------------------------------------------------------------------------------------------------------------------

test("an unexpected error removes the pager's temporary file and names the partial out_file (fsevents_parse, plist_read, knowledgec_query)", async () => {
  await withCwd(async (cwd) => {
    const records = Array.from({ length: 3000 }, (_, i) => fsRecord(`Users/alice/Library/Caches/app${i % 40}/file-${i}.tmp`, BigInt(i + 1), CREATED, BigInt(i + 1)));
    await fsDir(cwd, "fse", { "0000000000000001": fsPage("2SLD", records) });
    // the pager has spilled to its temporary file (limit 5), and finish() fails
    const run = await patched(FS, cwd, { path: "work/fse", limit: 5 }, `
real = g["SealedPage"].finish
def finish(self):
    raise RuntimeError("injected")
g["SealedPage"].finish = finish
`);
    assert.equal(run.code, 1);
    assert.equal((JSON.parse(run.stdout) as Json).error, "the tool stopped on an unexpected error");
    const left = (await readdir(join(cwd, "work", "s1", "tool-output")).catch(() => [])).filter((n) => n.startsWith("."));
    assert.deepEqual(left, [], "a temporary file of the pager is left");
    const withFile = await patched(FS, cwd, { path: "work/fse", out_file: "work/o.jsonl" }, `
g["SealedPage"].finish = lambda self: (_ for _ in ()).throw(RuntimeError("injected"))
real_fsync = os.fsync
def fsync(fd):
    raise RuntimeError("injected")
os.fsync = fsync
`);
    const answer = JSON.parse(withFile.stdout) as Json;
    assert.equal(answer.partial_out_file, "work/o.jsonl");
    assert.equal(await exists(join(cwd, "work", "o.jsonl")), true, "the partial file is kept, and named");
    await mkdir(join(cwd, "work", "pl"), { recursive: true });
    await writeFile(join(cwd, "work", "pl", "a.plist"), '<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>a</key><string>b</string></dict></plist>');
    const plist = await patched(PLIST, cwd, { path: "work/pl", out_file: "work/p.jsonl" }, `
def fsync(fd):
    raise RuntimeError("injected")
os.fsync = fsync
`);
    assert.equal((JSON.parse(plist.stdout) as Json).partial_out_file, "work/p.jsonl");
    const db = await kcDb(cwd, "k.db", 40);
    const kc = await patched(KC, cwd, { db, limit: 3 }, `
g["SealedPage"].finish = lambda self: (_ for _ in ()).throw(RuntimeError("injected"))
`);
    assert.equal(kc.code, 1);
    const kcLeft = (await readdir(join(cwd, "work", "s1", "tool-output")).catch(() => [])).filter((n) => n.startsWith(".knowledgec"));
    assert.deepEqual(kcLeft, [], "a temporary file of knowledgec_query's pager is left");
  });
});

test("the four run.py files are executable", async () => {
  for (const f of [PLIST, FS, KC, UL]) assert.equal(((await stat(f)).mode & 0o111) !== 0, true, f);
  assert.ok(body !== undefined);
});
