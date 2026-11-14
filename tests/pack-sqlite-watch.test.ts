/**
 * The shared SQLITE WATCH block, through every tool that opens evidence with sqlite3 (docs/packs.md, section 8, "A tool that reads SQLite evidence").
 *
 * A step of SQLite runs in C: a progress handler is called only between the steps of SQLite's own program, and a Python signal handler runs only when the
 * main thread is back in Python. A b-tree whose interior pages all point at one child (a DAG, not a tree) makes a walk visit the one leaf hundreds of
 * billions of times. The fixture here is a database whose sqlite_master b-tree is such a DAG, built from the file format (an interior table page is type
 * 0x05, its cells a 4-byte child page and a row-id varint, its right pointer at byte 8 of the page header), never from a tool's own reading: the schema
 * load, which every first statement makes, does not end. Each tool is run from a copy whose progress handlers are taken out (`.set_progress_handler(`
 * becomes a call that does nothing), so that only the watch can end that walk:
 *
 *   clock    with a short clock the tool answers with one JSON document within the clock and a small margin, partial or failed, and says it was the clock;
 *   SIGTERM  a SIGTERM while SQLite is in the walk is answered at once with one JSON document and exit 143 (128 + 15), with no traceback.
 *
 * The carriers: sqlite_query and sqlite_snapshot (computer-forensics-base), browser_history and chromium_logins (windows-forensics; chromium_logins is
 * run by tests/pack-windows-chromium-sqlite-stall.test.ts on its own Login Data DAG), utmp_parse (linux-forensics, session database mode),
 * recovery_validate (ransomware-response), knowledgec_query, macos_tcc and safari_history (macos-forensics), manifest_db and backup_materialise
 * (mobile-forensics). backup_decrypt (mobile-forensics) carries the block in its child and in its own read of the decrypted map; it needs an encrypted
 * backup and a backend module (tests/pack-mobile-backup-decrypt.test.ts has a stand-in) and is held here by the census and the source check at the end.
 */
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { PYTHON3 } from "./host-gates.ts";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
type Answer = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

/** Python that makes a SQLite file with a table and rewrites its sqlite_master b-tree into a DAG; with a WAL when asked (one commit frame of the other table's page). */
const BUILD = String.raw`
import os, shutil, sqlite3, struct, sys
path, wal = sys.argv[1], sys.argv[2] == "wal"
for s in ("", "-wal", "-shm", "-journal"):
    os.path.exists(path + s) and os.remove(path + s)
PS = 4096
c = sqlite3.connect(path)
c.execute("PRAGMA page_size=%d" % PS)
if wal:
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA wal_autocheckpoint=0")
c.execute("CREATE TABLE t (a, b)")
c.execute("CREATE TABLE u (b)")
c.execute("INSERT INTO t VALUES (1, 'x')")
c.commit()
if wal:
    c.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    c.execute("INSERT INTO u VALUES (1)")            # one commit frame, of u's page (not page 1)
    c.commit()
    shutil.copy(path, path + ".main")
    shutil.copy(path + "-wal", path + ".wal")
c.close()
if wal:
    shutil.move(path + ".main", path)
    shutil.move(path + ".wal", path + "-wal")
    os.path.exists(path + "-shm") and os.remove(path + "-shm")

def dagify(path, depth=4):
    data = bytearray(open(path, "rb").read())
    n = len(data) // PS
    old = bytes(data[0:PS])
    assert old[100] == 0x0D, "the schema's root is a table leaf"
    leaf = bytearray(PS)
    cells = struct.unpack_from(">H", old, 103)[0]
    start = struct.unpack_from(">H", old, 105)[0]
    leaf[start:] = old[start:]
    leaf[0:8] = old[100:108]
    leaf[8:8 + 2 * cells] = old[108:108 + 2 * cells]
    chain = [1] + [n + i for i in range(1, depth)]
    leaf_page = n + depth
    data += bytes(PS * depth)
    for i, page_no in enumerate(chain):
        child = chain[i + 1] if i + 1 < len(chain) else leaf_page
        b = 100 if page_no == 1 else 0
        page = bytearray(PS)
        if page_no == 1:
            page[:100] = data[:100]
        fan = (PS - b - 12) // 7
        content = PS
        for k in range(fan):
            cell = struct.pack(">I", child) + bytes([1 + k % 100])
            content -= len(cell)
            page[content:content + len(cell)] = cell
            struct.pack_into(">H", page, b + 12 + 2 * k, content)
        page[b] = 0x05
        struct.pack_into(">HHHB", page, b + 1, 0, fan, content, 0)
        struct.pack_into(">I", page, b + 8, child)
        data[(page_no - 1) * PS: page_no * PS] = page
    data[(leaf_page - 1) * PS: leaf_page * PS] = leaf
    struct.pack_into(">I", data, 28, leaf_page)
    struct.pack_into(">I", data, 92, struct.unpack_from(">I", data, 24)[0])
    open(path, "wb").write(data)
    return leaf_page

pages = dagify(path)
if wal:
    # the commit frame says the database is as long as the file now is, with its checksums made again (the format's cumulative checksum)
    w = bytearray(open(path + "-wal", "rb").read())
    magic = struct.unpack_from(">I", w, 0)[0]
    fmt = ">" if magic & 1 else "<"
    def ck(data, s0, s1):
        for i in range(0, len(data), 8):
            x0, x1 = struct.unpack_from(fmt + "II", data, i)
            s0 = (s0 + x0 + s1) & 0xFFFFFFFF
            s1 = (s1 + x1 + s0) & 0xFFFFFFFF
        return s0, s1
    s0, s1 = struct.unpack_from(">II", w, 24)
    off = 32
    while off + 24 + PS <= len(w):
        if struct.unpack_from(">I", w, off + 4)[0]:
            struct.pack_into(">I", w, off + 4, pages)
        s0, s1 = ck(bytes(w[off:off + 8]) + bytes(w[off + 24:off + 24 + PS]), s0, s1)
        struct.pack_into(">II", w, off + 16, s0, s1)
        off += 24 + PS
    open(path + "-wal", "wb").write(w)
`;

function dagDb(path: string, wal = false): void {
  mkdirSync(dirname(path), { recursive: true });
  const r = spawnSync(PYTHON3, ["-I", "-c", BUILD, path, wal ? "wal" : "plain"], { encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
}

const NO_PROGRESS = "_sqlite_watch_test_no_progress";

/** A copy of the tool with its progress handlers taken out (and its DEADLINE_SECONDS set, for a tool whose clock is a constant). */
function copyOf(pack: string, tool: string, deadline?: number): string {
  let text = readFileSync(join(ROOT, "packs", pack, "tools", tool, "run.py"), "utf8");
  const handlers = text.split(".set_progress_handler(").length - 1;
  if (tool !== "sqlite_snapshot") assert.ok(handlers >= 1, `${tool} sets a progress handler`);
  text = text.replaceAll(".set_progress_handler(", ` and ${NO_PROGRESS}(`).replace(/^(\s*)(\w+) and _sqlite_watch_test_no_progress\(/gm, `$1${NO_PROGRESS}($2, `);
  const end = "# END SHARED SQLITE WATCH\n";
  assert.equal(text.split(end).length, 2, `${tool} carries the SQLITE WATCH block once`);
  text = text.replace(end, `${end}${NO_PROGRESS} = lambda *a, **k: None     # (the test: only the watch can end a walk in C)\n`);
  if (deadline !== undefined) {
    assert.match(text, /^DEADLINE_SECONDS = \d+/m);
    text = text.replace(/^DEADLINE_SECONDS = \d+/m, `DEADLINE_SECONDS = ${deadline}`);
  }
  const dir = mkdtempSync(join(tmpdir(), "sqlite-watch-tool-"));
  const copy = join(dir, "run.py");
  writeFileSync(copy, text);
  return copy;
}

type Run = { code: number | null; signal: string | null; stdout: string; stderr: string; ms: number };

function start(script: string, cwd: string, args: unknown, env: Record<string, string>): { child: ReturnType<typeof spawn>; closed: Promise<Run> } {
  const began = Date.now();
  const child = spawn(PYTHON3, [script], { cwd, env: { ...process.env, AGENT_ID: "s1", ...env }, detached: true });
  const out: Buffer[] = [];
  const err: Buffer[] = [];
  child.stdout!.on("data", (c: Buffer) => out.push(c));
  child.stderr!.on("data", (c: Buffer) => err.push(c));
  const timer = setTimeout(() => { try { process.kill(-(child.pid as number), "SIGKILL"); } catch { /* gone */ } }, 90_000);
  const closed = new Promise<Run>((resolve) => child.on("close", (code, signal) => {
    clearTimeout(timer);
    resolve({ code, signal, stdout: Buffer.concat(out).toString("utf8"), stderr: Buffer.concat(err).toString("utf8"), ms: Date.now() - began });
  }));
  child.stdin!.on("error", () => undefined);
  child.stdin!.end(JSON.stringify(args));
  return { child, closed };
}

function answerOf(run: Run, what: string): Answer {
  assert.doesNotMatch(run.stderr, /Traceback/, `${what}: ${run.stderr.slice(-1500)}`);
  try {
    return JSON.parse(run.stdout) as Answer;
  } catch {
    assert.fail(`${what}: not one JSON document (exit ${run.code}, signal ${run.signal}): ${run.stdout.slice(0, 400)} | ${run.stderr.slice(-800)}`);
  }
}

type Carrier = {
  pack: string;
  tool: string;
  /** The tool's clock: set by max_seconds (args) or by its DEADLINE_SECONDS constant. */
  constantClock?: boolean;
  /** Lay the fixture out in `cwd` and give the arguments for a clock of `seconds`. */
  setup: (cwd: string, seconds: number) => { args: Answer; env?: Record<string, string> };
  /** What the answer says when the clock ended the walk. */
  clock: RegExp;
};

const job = (cwd: string): Record<string, string> => {
  const out = join(cwd, "store", "jobs", "j000001", "out");
  mkdirSync(out, { recursive: true });
  return { JOB_ID: "j000001", OUT: out };
};

const CARRIERS: Carrier[] = [
  {
    pack: "computer-forensics-base", tool: "sqlite_query",
    setup: (cwd, seconds) => { dagDb(join(cwd, "inputs", "e.db")); return { args: { db_path: "inputs/e.db", sql: "SELECT name FROM sqlite_master", max_seconds: seconds } }; },
    clock: /stopped at the \d+-second time budget/,
  },
  {
    pack: "computer-forensics-base", tool: "sqlite_snapshot",
    setup: (cwd, seconds) => { dagDb(join(cwd, "inputs", "e.db"), true); return { args: { db_path: "inputs/e.db", out_dir: "work/snap", max_seconds: seconds } }; },
    clock: /the time budget \(max_seconds\) ran out while SQLite worked on the copy, and it was interrupted/,
  },
  {
    pack: "windows-forensics", tool: "browser_history", constantClock: true,
    setup: (cwd) => { dagDb(join(cwd, "inputs", "History")); return { args: { path: "inputs/History" }, env: { TMPDIR: join(cwd, "tmp") } }; },
    clock: /the tool's own clock \(\d+ s\) ran out/,
  },
  {
    pack: "linux-forensics", tool: "utmp_parse",
    setup: (cwd, seconds) => { dagDb(join(cwd, "inputs", "wtmp.db")); return { args: { path: "inputs/wtmp.db", max_seconds: seconds }, env: job(cwd) }; },
    clock: /the tool's own clock \(max_seconds, \d+ s\) ran out while SQLite read the database, and SQLite was interrupted there/,
  },
  {
    pack: "ransomware-response", tool: "recovery_validate",
    setup: (cwd, seconds) => { dagDb(join(cwd, "inputs", "r.db")); return { args: { items: [{ recovered: "inputs/r.db", format: "sqlite" }], max_seconds: seconds } }; },
    clock: /not_run_time_limit/,
  },
  {
    pack: "macos-forensics", tool: "knowledgec_query",
    setup: (cwd, seconds) => { dagDb(join(cwd, "inputs", "knowledgeC.db")); return { args: { db: "inputs/knowledgeC.db", max_seconds: seconds } }; },
    clock: /still being read when the time ran out/,
  },
  {
    pack: "macos-forensics", tool: "macos_tcc",
    setup: (cwd, seconds) => { dagDb(join(cwd, "inputs", "TCC.db")); return { args: { path: "inputs/TCC.db", max_seconds: seconds } }; },
    clock: /still being read when the time ran out/,
  },
  {
    pack: "macos-forensics", tool: "safari_history",
    setup: (cwd, seconds) => { dagDb(join(cwd, "inputs", "History.db")); return { args: { path: "inputs/History.db", max_seconds: seconds } }; },
    clock: /still being read when the time ran out/,
  },
  {
    pack: "mobile-forensics", tool: "manifest_db",
    setup: (cwd, seconds) => { dagDb(join(cwd, "inputs", "backup", "Manifest.db")); return { args: { path: "inputs/backup", max_seconds: seconds } }; },
    clock: /max_seconds passed while Manifest\.db was being opened/,
  },
  {
    pack: "mobile-forensics", tool: "backup_materialise",
    setup: (cwd, seconds) => { dagDb(join(cwd, "inputs", "backup", "Manifest.db")); return { args: { path: "inputs/backup", all: true, max_seconds: seconds * 3 } }; },
    clock: /max_seconds passed while Manifest\.db was being opened/,
  },
];

function withCwd(fn: (cwd: string) => Promise<void>): Promise<void> {
  const cwd = realpathSync(mkdtempSync(join(tmpdir(), "sqlite-watch-")));
  for (const d of ["inputs", "work/s1", "tmp"]) mkdirSync(join(cwd, d), { recursive: true });
  return fn(cwd).finally(() => rmSync(cwd, { recursive: true, force: true }));
}

const CLOCK = 3;

for (const c of CARRIERS) {
  test(`${c.tool}: a schema load that walks a DAG b-tree in C ends at the tool's clock (${CLOCK} s) with the progress handler taken out, and says it was the clock`, async () => {
    await withCwd(async (cwd) => {
      const { args, env } = c.setup(cwd, CLOCK);
      const run = await start(copyOf(c.pack, c.tool, c.constantClock ? CLOCK : undefined), cwd, args, env ?? {}).closed;
      const answer = answerOf(run, c.tool);
      assert.ok(run.ms < (CLOCK * (c.tool === "backup_materialise" ? 3 : 1) + 8) * 1000, `${c.tool} answered after ${run.ms} ms with a ${CLOCK} s clock`);
      assert.ok(["partial", "failed"].includes(answer.status), `${c.tool}: ${answer.status} ${answer.status_basis}`);
      assert.match(JSON.stringify(answer), c.clock, `${c.tool}: the clock is said: ${JSON.stringify(answer).slice(0, 1500)}`);
    });
  });

  test(`${c.tool}: a SIGTERM while SQLite walks the DAG b-tree in C is answered at once with one JSON document and exit 143`, async () => {
    await withCwd(async (cwd) => {
      const { args, env } = c.setup(cwd, 40);
      const s = start(copyOf(c.pack, c.tool, c.constantClock ? 40 : undefined), cwd, args, env ?? {});
      await new Promise((r) => setTimeout(r, 3500));     // the tool is in the walk by now (the clock is 40 seconds away)
      assert.equal(s.child.exitCode, null, `${c.tool} is still running, inside the walk`);
      const sent = Date.now();
      s.child.kill("SIGTERM");
      const run = await s.closed;
      const seconds = (Date.now() - sent) / 1000;
      assert.ok(seconds < 6, `${c.tool} answered ${seconds} s after the signal`);
      assert.equal(run.signal, null, `${c.tool}: ended by its own handler, not by the signal`);
      assert.equal(run.code, 143, `${c.tool}: ${run.stdout.slice(0, 300)} ${run.stderr.slice(-500)}`);
      const answer = answerOf(run, c.tool);
      assert.ok(["partial", "failed"].includes(answer.status), `${c.tool}: ${JSON.stringify(answer).slice(0, 600)}`);
    });
  });
}

test("every tool that carries the block makes a watch, watches its connections and closes the watch; the carriers are the census's", () => {
  const found = spawnSync("grep", ["-rl", "# BEGIN SHARED SQLITE WATCH", "packs", "tool-library"], { cwd: ROOT, encoding: "utf8" }).stdout.trim().split("\n").sort();
  const census = JSON.parse(readFileSync(join(ROOT, "tests", "shared-blocks.json"), "utf8")).families["SQLITE WATCH"].variants[0].carriers;
  assert.equal(found.length, census, found.join(" "));
  for (const file of found) {
    const text = readFileSync(join(ROOT, file), "utf8").replace(/# BEGIN SHARED SQLITE WATCH\n[\s\S]*?# END SHARED SQLITE WATCH\n/, "");
    assert.match(text, /SqliteWatch\(/, `${file} makes a watch`);
    assert.match(text, /\.watch\(/, `${file} watches a connection`);
    assert.match(text, /\.close\(\)/, `${file} closes the watch`);
    assert.match(text, /sqlite3\.connect\(/, `${file} opens a database`);
  }
  for (const tool of CARRIERS) assert.ok(found.includes(`packs/${tool.pack}/tools/${tool.tool}/run.py`), `${tool.tool} is a carrier`);
});
