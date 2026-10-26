/**
 * Corrections to the macos-forensics tools from the second verification round, each tested on the tools as an agent or a job runs them and each
 * failing on the tools before them:
 *
 *  - knowledgec_query reads a schema of hundreds of thousands of rows under its clock and its stop signals (the progress handler stood after the first
 *    statement, which is where SQLite parses the whole schema);
 *  - fsevents_parse holds a bounded list of problems with exact counts (an 81 KB gzip of bad page headers was 10 GB of memory and 253 s), refuses a FIFO
 *    as `path`, reads a gzip member whose header the 1 MiB read splits, and keeps the clock over members that inflate to nothing;
 *  - plist_read is not `complete` over a directory it could not list or search;
 *  - unified_log and knowledgec_query finish removing their staged copy when a stop signal lands in the removal, and say so truthfully;
 *  - the smaller ones: an index past the digits a list can hold, a directory an agent made under a staged copy's name, the preview's byte bound,
 *    and the goal template's question about privacy authorization.
 */
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { chmod, mkdir, readFile, readdir, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { gzipSync } from "node:zlib";
import { ROOT, runPySnippet, withCwd } from "./tool-library-harness.ts";
import { CREATED, FS, KC, MAC, PLIST, UL, body, dbCopy, fsDir, fsPage, fsRecord, gz, kcDb, logarchive, measured, ok, runAndSignal, tool, ul, ulStandin } from "./macos-pack-harness.ts";
import type { Json } from "./macos-pack-harness.ts";

const isRoot = typeof process.getuid === "function" && process.getuid() === 0;
const exists = (path: string): Promise<boolean> => stat(path).then(() => true, () => false);

const LOAD = `
import importlib.util, sys
spec = importlib.util.spec_from_file_location("tool", sys.argv[1])
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
`;

/** A tool run under a wall-clock limit of its own (a hang is a failed test, not a hung suite). */
function limited(script: string, cwd: string, args: unknown, seconds: number, env: Record<string, string> = {}): Promise<{ code: number | null; stdout: string; stderr: string; wall: number; killed: boolean }> {
  return new Promise((resolve, reject) => {
    const begun = Date.now();
    const child = spawn("python3", [script], { cwd, env: { ...process.env, AGENT_ID: "s1", ...env } });
    const so: Buffer[] = [];
    const se: Buffer[] = [];
    let killed = false;
    const timer = setTimeout(() => { killed = true; child.kill("SIGKILL"); }, seconds * 1000);
    child.stdout.on("data", (c: Buffer) => so.push(c));
    child.stderr.on("data", (c: Buffer) => se.push(c));
    child.on("error", reject);
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ code, stdout: Buffer.concat(so).toString("utf8"), stderr: Buffer.concat(se).toString("utf8"), wall: (Date.now() - begun) / 1000, killed });
    });
    child.stdin.end(JSON.stringify(args));
  });
}

async function problemRows(cwd: string, answer: Json): Promise<Json[]> {
  const file = answer.problems_pages?.all_results as string | undefined;
  if (!file) return answer.problems as Json[];
  return (await readFile(join(cwd, file), "utf8")).split("\n").filter(Boolean).map((l) => JSON.parse(l) as Json);
}

// ---- knowledgec_query: P1-1, the schema is read under the clock -----------------------------------------------------------------------------------

const BIG_SCHEMA = `
import sqlite3, sys
con = sqlite3.connect(sys.argv[1])
con.execute("CREATE TABLE ZOBJECT (Z_PK INTEGER PRIMARY KEY, ZSTREAMNAME VARCHAR, ZSTARTDATE TIMESTAMP)")
con.execute("INSERT INTO ZOBJECT VALUES (1, '/a', 1.0)")
con.commit()
con.execute("PRAGMA writable_schema=ON")
n = int(sys.argv[2])
con.executemany("INSERT INTO sqlite_master (type, name, tbl_name, rootpage, sql) VALUES ('table', ?, ?, 2, ?)",
                ((("t%d_xxxxxxxxxxxxxxxxxxxxxxxxxxxx" % i),) * 2 + ('CREATE TABLE "t%d_xxxxxxxxxxxxxxxxxxxxxxxxxxxx" (a)' % i,) for i in range(n)))
con.commit()
con.close()
`;

async function bigSchema(cwd: string, rows: number): Promise<string> {
  const path = join(cwd, "work", "big.db");
  const built = await runPySnippet(BIG_SCHEMA, [path, String(rows)], null);
  assert.equal(built.code, 0, built.stderr);
  return "work/big.db";
}

test("knowledgec_query stops a schema of 200,000 tables at max_seconds: the clock stands before the first statement, where SQLite parses the schema", async () => {
  // The handler used to be installed after the first statement (the list of tables), so a crafted file with 200,000-300,000 schema rows took 142-150 s
  // against the manifest's 120 whatever max_seconds said.
  await withCwd(async (cwd) => {
    const db = await bigSchema(cwd, 200_000);
    const run = await limited(KC, cwd, { db, max_seconds: 2 }, 40);
    assert.equal(run.killed, false, "the tool answered before the test's own limit");
    assert.equal(run.code, 0, run.stderr + run.stdout.slice(0, 300));
    const answer = JSON.parse(run.stdout) as Json;
    assert.equal(answer.status, "partial");
    assert.equal(answer.entry_count, 0);
    assert.ok(run.wall < 15, `${run.wall} s for max_seconds 2`);
    assert.ok(answer.limits.seconds_used < 15, String(answer.limits.seconds_used));
    assert.ok(answer.problems.some((p: string) => /schema of the file/.test(p) && /time ran out/.test(p)), JSON.stringify(answer.problems).slice(0, 400));
    assert.match(answer.resume.to_go_on, /schema/);
  });
});

test("knowledgec_query ends a schema read on SIGTERM: one JSON answer and exit 143 in seconds, not when SQLite is done", async () => {
  await withCwd(async (cwd) => {
    const db = await bigSchema(cwd, 200_000);
    const started = Date.now();
    const run = await runAndSignal(KC, cwd, { db, max_seconds: 85 }, "SIGTERM", async () => Date.now() - started > 1500);
    assert.equal(run.signalled, true);
    assert.equal(run.code, 143, run.stderr + run.stdout.slice(0, 200));
    const answer = JSON.parse(run.stdout) as Json;
    assert.equal(answer.interrupted, "SIGTERM");
    assert.ok((Date.now() - started) / 1000 < 20, `${(Date.now() - started) / 1000} s`);
  });
});

// ---- fsevents_parse: P1-2, a bounded list of problems -------------------------------------------------------------------------------------------

function badHeaders(mebibytes: number): Buffer {
  // pages whose 12-byte header declares a length of 0: one problem each, and 1 MiB of them is 87,381
  const block = Buffer.alloc(12);
  block.write("1SLD", 0, "latin1");
  return gzipSync(Buffer.concat(Array.from({ length: (mebibytes << 20) / 12 / 1024 }, () => Buffer.concat(Array.from({ length: 1024 }, () => block)))), { level: 1 });
}

test("fsevents_parse: 12 MiB of bad page headers (a 20 KB gzip) is a bounded list with exact counts, in seconds and bounded memory", async () => {
  // Before: every bad page appended a dict that was then judged one by one outside every clock (1,000,000 problems: 54-84 s and 500-600 MB; 40 MiB of the
  // same, an 81 KB gzip: 253 s and 1.7 GB; at the default expansion cap 10 GB).
  await withCwd(async (cwd) => {
    const dir = await fsDir(cwd, "bad", { "0000000000000001": badHeaders(12) });
    const run = await measured(FS, cwd, { path: dir, max_expanded_bytes: 1 << 30 });
    const answer = JSON.parse(run.stdout) as Json;
    const pages = (12 << 20) / 12;
    assert.equal(answer.coverage.pages.invalid_length, pages, "the count is exact");
    assert.equal(answer.problem_occurrences, pages, "every problem is counted");
    assert.ok(answer.problems_total <= 110, `${answer.problems_total} problem rows, not one per page`);
    const folded = (await problemRows(cwd, answer)).filter((r) => r.folded === true);
    assert.equal(folded.length, 1);
    assert.equal(folded[0].kind, "invalid page length");
    assert.equal(folded[0].occurrences, pages - 100, "what is folded is counted: the first 100 are listed one by one");
    assert.equal(folded[0].first_offset, 100 * 12);
    assert.equal(folded[0].last_offset, (pages - 1) * 12);
    assert.ok(answer.problems_folded, "the answer says it folded");
    assert.notEqual(answer.status, "complete");
    assert.ok(run.cpu < 25, `${run.cpu} s of CPU`);
    assert.ok(run.mb < 300, `${run.mb} MB`);
  });
});

test("fsevents_parse: the problem rows of many files stay under PROBLEM_ROWS_TOTAL, the rest is counted by kind, and every problem is accounted for", async () => {
  await withCwd(async (cwd) => {
    const header = Buffer.alloc(12);
    header.write("1SLD", 0, "latin1");
    const files: Record<string, Buffer> = {};
    for (let i = 0; i < 60; i++) files[`${String(i + 1).padStart(16, "0")}`] = gz(Buffer.concat(Array.from({ length: 150 }, () => header)));
    const dir = await fsDir(cwd, "many", files);
    const answer = body(await tool(FS, cwd, { path: dir, limit: 10 }));
    assert.equal(answer.problem_occurrences, 60 * 150);
    const rows = await problemRows(cwd, answer);
    assert.ok(rows.length <= 5000 + 1, `${rows.length} rows`);
    assert.equal(rows.reduce((sum, r) => sum + (r.occurrences ?? 1), 0), 60 * 150, "listed one by one, or counted in a folded row: nothing is lost from the count");
    assert.ok(rows.some((r) => r.folded === true && r.files !== undefined), "the problems after the cap are folded by kind across the files");
    for (const f of answer.per_file) assert.equal(f.problems, 150, "per_file carries the exact count of the file");
  });
});

// ---- fsevents_parse: P1-3, a FIFO ----------------------------------------------------------------------------------------------------------------

test("fsevents_parse refuses a FIFO as path as JSON at once, and never blocks on one it finds opening a file", async () => {
  await withCwd(async (cwd) => {
    const fifo = join(cwd, "work", "rec");
    const made = spawnSync("mkfifo", [fifo]);
    assert.equal(made.status, 0, String(made.stderr));
    const run = await limited(FS, cwd, { path: "work/rec" }, 15);
    assert.equal(run.killed, false, "a FIFO as path blocked in open() until a writer came");
    assert.equal(run.code, 1);
    const answer = JSON.parse(run.stdout) as Json;
    assert.equal(answer.status, "failed");
    assert.match(answer.error, /FIFO/);
    // the file opened inside the scan (a name that changed between the listing and the read): a read-only open with no writer
    const inside = await runPySnippet(LOAD + `
scan = m.FileScan(sys.argv[2])
m.scan_file(scan, lambda r: None, 1 << 20, 1 << 20)
print(scan.state, scan.error)
`, [join(MAC, "fsevents_parse", "run.py"), fifo], null);
    assert.equal(inside.code, 0, inside.stderr);
    assert.match(inside.stdout, /^failed not a regular file/);
  });
});

// ---- fsevents_parse: P2-1, P2-2 ------------------------------------------------------------------------------------------------------------------

test("fsevents_parse reads a gzip member whose two-byte header is split by the end of a 1 MiB read", async () => {
  // The rest of the file was reported as 'not a gzip member' (partial, data lost): `unused` was one byte and the test of the header looked at it alone.
  await withCwd(async (cwd) => {
    const member = gz(fsPage("2SLD", [fsRecord("a/b", 1n, CREATED, 1n)]));
    const m = member.length;
    let pad: Buffer | null = null;
    for (let n = 1; n < 400 && !pad; n++) {
      const candidate = gzipSync(fsPage("2SLD", [fsRecord("p".repeat(n), 9n, CREATED, 9n)]), { level: 0 });
      if (candidate.length <= 1_048_575 && (1_048_575 - candidate.length) % m === 0) pad = candidate;
    }
    assert.ok(pad, "a padding member that puts the 1 MiB boundary one byte into a member");
    const k = (1_048_575 - pad.length) / m;
    const total = 1 + k + 50;
    const dir = await fsDir(cwd, "straddle", { "0000000000000001": Buffer.concat([pad, Buffer.concat(Array.from({ length: k + 50 }, () => member))]) });
    const answer = ok(await tool(FS, cwd, { path: dir }));
    assert.equal(answer.record_count, total);
    assert.equal(answer.status, "complete", JSON.stringify(answer.problems).slice(0, 300));
    assert.equal(answer.coverage.members.complete, total);
  });
});

test("fsevents_parse keeps its clock over gzip members that inflate to nothing", async () => {
  // 12,000,000 empty members (228 MB) took 213 s of a 200 s clock and ended complete, 1.3 GB: the loop never gave the page loop's clock a turn.
  await withCwd(async (cwd) => {
    const empty = gzipSync(Buffer.alloc(0));
    const dir = await fsDir(cwd, "empties", { "0000000000000001": Buffer.concat(Array.from({ length: 2_000_000 / 1000 }, () => Buffer.concat(Array.from({ length: 1000 }, () => empty)))) });
    const run = await limited(FS, cwd, { path: dir, max_seconds: 1 }, 60);
    assert.equal(run.killed, false);
    const answer = JSON.parse(run.stdout) as Json;
    assert.notEqual(answer.status, "complete", `2,000,000 empty members, max_seconds 1: ${answer.status} after ${run.wall} s`);
    assert.ok(run.wall < 12, `${run.wall} s`);
    assert.match(answer.status_basis, /max_seconds/);
    assert.ok(answer.coverage.members.complete < 2_000_000);
  });
});

test("fsevents_parse names the links it did not follow and the entries that are not record files in the basis of a complete answer", async () => {
  await withCwd(async (cwd) => {
    const dir = await fsDir(cwd, "withlinks", { "0000000000000001": gz(fsPage("2SLD", [fsRecord("a/b", 1n, CREATED, 1n)])) });
    const { symlink } = await import("node:fs/promises");
    await symlink(join(cwd, "work", "withlinks", "0000000000000001"), join(cwd, "work", "withlinks", "0000000000000002"));
    assert.equal(spawnSync("mkfifo", [join(cwd, "work", "withlinks", "0000000000000003")]).status, 0);
    const answer = ok(await tool(FS, cwd, { path: dir }));
    assert.equal(answer.status, "complete");
    assert.match(answer.status_basis, /1 link\(s\) in the directory were not followed and 1 entry that is not a regular file was not read/);
    assert.equal(answer.directory.links_not_followed, 1);
    assert.equal(answer.directory.not_regular_files, 1);
  });
});

// ---- plist_read: P1-4, P3 dig, links --------------------------------------------------------------------------------------------------------------

const plistXml = (value: number): string => `<?xml version="1.0" encoding="UTF-8"?>\n<plist version="1.0"><dict><key>n</key><integer>${value}</integer></dict></plist>\n`;

test("plist_read is partial, and names the place, when a subdirectory cannot be listed", { skip: isRoot && "root can list anything" }, async () => {
  await withCwd(async (cwd) => {
    const ev = join(cwd, "work", "ev");
    await mkdir(join(ev, "ok"), { recursive: true });
    await mkdir(join(ev, "locked"), { recursive: true });
    await writeFile(join(ev, "ok", "a.plist"), plistXml(1));
    await writeFile(join(ev, "locked", "b.plist"), plistXml(2));
    await chmod(join(ev, "locked"), 0o000);
    try {
      const run = await tool(PLIST, cwd, { path: "work/ev" });
      assert.equal(run.code, 0, run.stderr);
      const answer = body(run);
      assert.equal(answer.status, "partial", answer.status_basis);
      assert.doesNotMatch(answer.status_basis, /every one of/);
      assert.match(answer.status_basis, /locked/);
      assert.equal(answer.walk.directories_unreadable, 1);
      assert.equal(answer.counts.parsed, 1);
    } finally {
      await chmod(join(ev, "locked"), 0o755);
    }
  });
});

test("plist_read is partial when a directory can be listed but not searched (its files cannot be looked at), and failed when nothing else was read", { skip: isRoot && "root can search anything" }, async () => {
  await withCwd(async (cwd) => {
    const ev = join(cwd, "work", "ev");
    await mkdir(join(ev, "locked"), { recursive: true });
    await writeFile(join(ev, "locked", "b.plist"), plistXml(2));
    await chmod(join(ev, "locked"), 0o444);
    try {
      const alone = await tool(PLIST, cwd, { path: "work/ev" });
      const answer = body(alone);
      assert.equal(answer.status, "failed", answer.status_basis);
      assert.equal(alone.code, 1);
      assert.equal(answer.walk.entries_unreadable, 1);
      assert.equal(answer.walk.not_regular_files, 0, "an entry that could not be looked at is not a special file");
      assert.match(answer.status_basis, /b\.plist/);
      await writeFile(join(ev, "a.plist"), plistXml(1));
      const both = body(await tool(PLIST, cwd, { path: "work/ev" }));
      assert.equal(both.status, "partial");
      assert.equal(both.counts.parsed, 1);
    } finally {
      await chmod(join(ev, "locked"), 0o755);
    }
  });
});

test("plist_read says in its basis what it did not follow or read by design, and stays complete for the regular files", async () => {
  await withCwd(async (cwd) => {
    const ev = join(cwd, "work", "ev");
    await mkdir(ev, { recursive: true });
    await writeFile(join(ev, "a.plist"), plistXml(1));
    const { symlink } = await import("node:fs/promises");
    await symlink(join(ev, "a.plist"), join(ev, "link.plist"));
    spawnSync("mkfifo", [join(ev, "pipe.plist")]);
    const answer = ok(await tool(PLIST, cwd, { path: "work/ev" }));
    assert.equal(answer.status, "complete");
    assert.match(answer.status_basis, /every one of the 1 matched file\(s\) was read/);
    assert.match(answer.status_basis, /1 link\(s\) were not followed/);
    assert.match(answer.status_basis, /not a regular file/);
  });
});

test("plist_read answers a key path with a digit string no list can hold as 'no key', not as an unexpected error", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "l.plist"), `<?xml version="1.0" encoding="UTF-8"?>\n<plist version="1.0"><dict><key>x</key><array><integer>1</integer></array></dict></plist>\n`);
    for (const index of ["9".repeat(5000), "²", "٣", "99999999999999999999"]) {
      const run = await tool(PLIST, cwd, { path: "work/l.plist", key: `x.${index}` });
      assert.equal(run.code, 1, run.stdout.slice(0, 200));
      const answer = body(run);
      assert.doesNotMatch(run.stdout, /unexpected error/, `index ${index.slice(0, 12)}`);
      assert.equal(answer.files[0].status, "failed");
      assert.match(answer.files[0].error, /no key/);
    }
    const fine = ok(await tool(PLIST, cwd, { path: "work/l.plist", key: "x.0" }));
    assert.equal(fine.files[0].value, 1);
  });
});

// ---- knowledgec_query and unified_log: P2-3, a stop signal in the removal of the staged copy ----------------------------------------------------

test("unified_log: a SIGTERM that lands while the staged copy is removed ends in the whole removal and an answer that says the reader had finished", async () => {
  // The finally: rmtree ran outside the handler that turns a signal into an answer: the answer said the tool was stopped 'before the reader had run', had no
  // counts, and the staged copy stayed half removed under out_dir (the next run in that directory refused to start).
  await withCwd(async (cwd) => {
    const bin = await ulStandin(cwd, `
open(out, "w").write("\\n".join(json.dumps({"timestamp": "2026-01-01T00:00:0%d" % i, "eventMessage": "m%d" % i, "processImagePath": "/usr/bin/p"}) for i in range(5)) + "\\n")
`);
    const input = await dbCopy(cwd, 300, 1);
    const code = LOAD + `
import os, shutil, signal
real = shutil.rmtree
def rmtree(path, *a, **k):
    if os.path.basename(str(path)) == ".logarchive-input" and not os.environ.get("SENT"):
        os.environ["SENT"] = "1"
        os.kill(os.getpid(), signal.SIGTERM)       # lands inside the removal
    return real(path, *a, **k)
shutil.rmtree = rmtree
m.install_stop_handlers()
m.main()
`;
    const run = await new Promise<{ code: number | null; stdout: string; stderr: string }>((resolve, reject) => {
      const child = spawn("python3", ["-c", code, UL], { cwd, env: { ...process.env, AGENT_ID: "s1", PATH: bin } });
      const so: Buffer[] = [];
      const se: Buffer[] = [];
      child.stdout.on("data", (c: Buffer) => so.push(c));
      child.stderr.on("data", (c: Buffer) => se.push(c));
      child.on("error", reject);
      child.on("close", (c) => resolve({ code: c, stdout: Buffer.concat(so).toString("utf8"), stderr: Buffer.concat(se).toString("utf8") }));
      child.stdin.end(JSON.stringify({ path: input, out_dir: "work/out" }));
    });
    assert.equal(run.code, 143, run.stderr + run.stdout.slice(0, 300));
    const answer = JSON.parse(run.stdout) as Json;
    assert.doesNotMatch(run.stdout, /before it had read anything|before the reader had run/);
    assert.equal(answer.interrupted, "SIGTERM");
    assert.equal(answer.entry_count, 5, "the reader had finished: its output is counted");
    assert.equal(await exists(join(cwd, "work", "out", ".logarchive-input")), false, "the staged copy is removed whole");
    assert.match(answer.status_basis, /after the reader had already finished/);
  });
});

test("knowledgec_query: a SIGTERM that lands while the private copy is removed still gives the answer, with the copy gone", async () => {
  await withCwd(async (cwd) => {
    const db = await kcDb(cwd, "wal.db", 30, 0, {}, "wal");
    const code = LOAD + `
import os, shutil, signal
real = shutil.rmtree
def rmtree(path, *a, **k):
    if os.path.basename(str(path)).startswith("knowledgec-") and not os.environ.get("SENT"):
        os.environ["SENT"] = "1"
        os.kill(os.getpid(), signal.SIGTERM)
    return real(path, *a, **k)
shutil.rmtree = rmtree
m.install_stop_handlers()
m.main()
`;
    const run = await new Promise<{ code: number | null; stdout: string; stderr: string }>((resolve, reject) => {
      const child = spawn("python3", ["-c", code, KC], { cwd, env: { ...process.env, AGENT_ID: "s1" } });
      const so: Buffer[] = [];
      const se: Buffer[] = [];
      child.stdout.on("data", (c: Buffer) => so.push(c));
      child.stderr.on("data", (c: Buffer) => se.push(c));
      child.on("error", reject);
      child.on("close", (c) => resolve({ code: c, stdout: Buffer.concat(so).toString("utf8"), stderr: Buffer.concat(se).toString("utf8") }));
      child.stdin.end(JSON.stringify({ db }));
    });
    assert.equal(run.code, 143, run.stderr + run.stdout.slice(0, 300));
    const answer = JSON.parse(run.stdout) as Json;
    assert.doesNotMatch(run.stdout, /before it had read anything/);
    assert.equal(answer.interrupted, "SIGTERM");
    assert.equal(answer.entry_count, 31, "every row was read before the signal");
    assert.equal(answer.source_used.staged_copy, "removed");
    const left = spawnSync("find", [join(cwd, "work")], { encoding: "utf8" }).stdout;
    assert.doesNotMatch(left, /knowledgec-\d+-/, "no private copy is left, whole or half");
  });
});

// ---- knowledgec_query: P3, the dead-copy sweep never takes an agent's own directory ------------------------------------------------------------------

test("knowledgec_query's sweep of dead private copies leaves a directory an agent made under the same name pattern", async () => {
  const code = LOAD + `
import os, subprocess, tempfile
root = tempfile.mkdtemp(prefix="kc-sweep-")
parent = os.path.join(root, "stage")
os.mkdir(parent)
dead = subprocess.Popen([sys.executable, "-c", "pass"]); dead.wait()
# an agent's own directory: default mode, a file of its own, a subdirectory
mine = os.path.join(parent, "knowledgec-%d-abc" % dead.pid)
os.mkdir(mine)
open(os.path.join(mine, "notes.txt"), "w").write("x")
sub = os.path.join(parent, "knowledgec-%d-sub" % dead.pid)
os.mkdir(sub, 0o700); os.mkdir(os.path.join(sub, "inner"))
# a dead private copy as this tool makes it: mode 0700, files 0600
ours = os.path.join(parent, "knowledgec-%d-ours1234" % dead.pid)
os.mkdir(ours, 0o700)
fd = os.open(os.path.join(ours, "k.db"), os.O_WRONLY | os.O_CREAT, 0o600); os.write(fd, b"x"); os.close(fd)
m.remove_dead_stages(parent)
print("left", sorted(os.listdir(parent)))
`;
  const run = await runPySnippet(code, [join(MAC, "knowledgec_query", "run.py")], null);
  assert.equal(run.code, 0, run.stderr);
  const left = /left (\[.*\])/.exec(run.stdout)?.[1] ?? "";
  assert.ok(left.includes("-abc"), `an agent's directory with its own file stays: ${left}`);
  assert.ok(left.includes("-sub"), `a directory with a subdirectory stays: ${left}`);
  assert.ok(!left.includes("ours1234"), `the copy this tool made is removed: ${left}`);
});

// ---- unified_log: P3 ------------------------------------------------------------------------------------------------------------------------------

test("unified_log bounds the preview by bytes as well as by limit, and says so; every entry is still counted and in the output file", async () => {
  await withCwd(async (cwd) => {
    const bin = await ulStandin(cwd, `
big = "x" * 200000
open(out, "w").write("\\n".join(json.dumps({"timestamp": "2026-01-01T00:00:%02d" % i, "eventMessage": big, "processImagePath": "/usr/bin/p"}) for i in range(20)) + "\\n")
`);
    const archive = await logarchive(cwd);
    const out = await ul(cwd, bin, { path: archive, out_dir: "work/o", limit: 500, max_inline_bytes: 450_000 });
    const answer = ok(out);
    assert.equal(answer.entry_count, 20);
    assert.ok(answer.entries_inline <= 3, `${answer.entries_inline} entries in a 450,000-byte preview`);
    assert.equal(answer.entries_bounded_by_bytes, true);
    assert.equal(answer.inline_byte_limit, 450_000);
    const bad = await ul(cwd, bin, { path: archive, out_dir: "work/o2", max_inline_bytes: 0 });
    assert.equal(bad.code, 1);
  });
});

test("unified_log refuses a FIFO as path instead of handing it to a reader that waits on it", async () => {
  await withCwd(async (cwd) => {
    const bin = await ulStandin(cwd, `time.sleep(0)`);
    const fifo = join(cwd, "work", "pipe");
    assert.equal(spawnSync("mkfifo", [fifo]).status, 0);
    const out = await ul(cwd, bin, { path: "work/pipe", out_dir: "work/o" });
    assert.equal(out.code, 1);
    assert.match(JSON.parse(out.stdout).error, /FIFO/);
  });
});

// ---- the goal template: P1-5 ------------------------------------------------------------------------------------------------------------------------

test("the goal's question 4 does not promise TCC states that no tool or skill of the pack provides", async () => {
  const goal = await readFile(join(ROOT, "packs", "macos-forensics", "goals", "mac-compromise.md"), "utf8");
  const q4 = /\n4\. Privacy authorization[\s\S]*?\n5\. /.exec(goal)?.[0] ?? "";
  assert.ok(q4, "question 4 is there");
  assert.match(q4, /cannot answer\s+the question/, "it carries the clause question 7 carries");
  assert.match(q4, /no TCC parser or skill/);
  assert.ok((await readdir(join(ROOT, "packs", "macos-forensics", "tools"))).every((t) => !/tcc/i.test(t)), "and the pack has no TCC tool");
});
