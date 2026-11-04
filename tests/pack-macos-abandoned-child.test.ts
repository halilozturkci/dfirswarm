/**
 * PKG-MAC-18 fix round. Three families of cases, all with stand-ins (mac_apt and unifiedlog_iterator are not installed here and were never run):
 *  1. an abandoned child: the program writes a clean log, exits 0 and leaves a child that closed its descriptors and writes later; the tool must end it
 *     before it measures anything (macos_triage, the macos-artefacts recipe, unified_log), say partial, and say that a process in a session of its own
 *     (setsid) cannot be ended by the tool and is seen only when a file grew or is held open;
 *  2. the log reader (one text in macos_triage and the recipe): a review hint quoted in an error line, a line over 4000 bytes, a plugin or finish line
 *     that is only quoted or has no line shape, a deadline and a byte cap on the read, and stderr read for an error word when a log exists;
 *  3. the reader exercised through its own source text, so that the tool and the recipe are held to the same behaviour.
 */
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { chmod, mkdir, readFile, readdir, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { withCwd } from "./tool-library-harness.ts";
import { MAC, filesUnder } from "./macos-late-harness.ts";
import { PYTHON, UL, logarchive, ulStandin } from "./macos-pack-harness.ts";
import type { Json } from "./macos-pack-harness.ts";

const TRIAGE = join(MAC, "macos_triage", "run.py");
const RECIPE = join(MAC, "..", "recipes", "macos-artefacts", "run.py");
const PX = (level: string, msg: string): string => `2026-11-04 12:00:00,000|MAIN|${level}|${msg}`;

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));
const alive = (pid: number): boolean => {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
};

/** Run a program as the harness starts a tool: the leader of a group of its own. */
function lead(argv: string[], cwd: string, env: Record<string, string>, stdin?: string): Promise<{ code: number | null; stdout: string; stderr: string; ms: number }> {
  return new Promise((resolve, reject) => {
    const began = Date.now();
    const child = spawn(argv[0], argv.slice(1), { cwd, env: { ...process.env, AGENT_ID: "s1", ...env }, detached: true });
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => out.push(c));
    child.stderr.on("data", (c: Buffer) => err.push(c));
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stdout: Buffer.concat(out).toString("utf8"), stderr: Buffer.concat(err).toString("utf8"), ms: Date.now() - began }));
    child.stdin.on("error", () => undefined);
    child.stdin.end(stdin ?? "");
  });
}

const PRE = `
import os, signal, sys, time
argv = sys.argv[1:]
HERE = os.path.dirname(os.path.abspath(__file__))
if argv == ["-h"]:
    print("macOS Artifact Parsing Tool, version 1.33.2")
    sys.exit(0)
TYPES = ["AFF4", "AXIOMZIP", "DD", "DMG", "E01", "MOUNTED", "SPARSE", "UAC", "VMDK", "VR"]
out = argv[argv.index("-o") + 1]
os.makedirs(out, exist_ok=True)
LOG = os.path.join(out, "Log.20261104-120000.txt")
def log(line, level="INFO"):
    with open(LOG, "a") as f:
        f.write("2026-11-04 12:00:00,000|MAIN|%s|%s\\n" % (level, line))
def start():
    log("Started macOS Artifact Parsing Tool, version 1.33.2")
def plugin(name, lines=(), ran=True):
    log("-" * 50)
    log("Running plugin " + name)
    for l in lines:
        log(l)
    if ran:
        log(name + " plugin ran for 00:00:01")
def finish():
    log("Finished in time = 00:00:02")
    log("Review the Log file and report any ERRORs or EXCEPTIONS to the developers")
`;

async function stand(bin: string, script: string): Promise<void> {
  await mkdir(bin, { recursive: true });
  const file = join(bin, "mac_apt.py");
  await writeFile(file, `#!/usr/bin/env python3\n${PRE}\n${script}\n`);
  await chmod(file, 0o755);
}

async function e01(cwd: string): Promise<string> {
  await writeFile(join(cwd, "work", "mac.E01"), Buffer.concat([Buffer.from([0x45, 0x56, 0x46, 0x09, 0x0d, 0x0a, 0xff, 0x00]), Buffer.alloc(4096)]));
  return "work/mac.E01";
}

const OK_ONE = `start()\nplugin("TCC", ["Processed 3 rows"])\nfinish()\n`;

/** The program writes a clean log and a 100-byte database and exits 0; a child it leaves closes its descriptors, waits, then writes a traceback and 100 KB. */
const child = (delay: number, session: boolean, pidFile: string): string => `
${OK_ONE}
open(os.path.join(out, "mac_apt.db"), "wb").write(b"x" * 100)
if os.fork() == 0:
    ${session ? "os.setsid()" : "pass"}
    open(${JSON.stringify(pidFile)}, "a").write("%d\\n" % os.getpid())
    for fd in (0, 1, 2):
        os.close(fd)
    time.sleep(${delay})
    with open(LOG, "a") as f:
        f.write("2026-11-04 12:00:09,000|MAIN|INFO|Traceback (most recent call last):\\n")
    with open(os.path.join(out, "mac_apt.db"), "ab") as f:
        f.write(b"y" * 100000)
    os._exit(0)
`;

const triage = (cwd: string, bin: string, args: Json) =>
  lead([PYTHON, TRIAGE], cwd, { PATH: `${bin}:${process.env.PATH ?? ""}`, JOB_ID: "j-1", OUT: join(cwd, "out"), SECRET_OUTPUT: "1" }, JSON.stringify(args));
const real = (cwd: string, shown: string): string => join(cwd, "out", shown.replace(/^store\/jobs\/[^/]+\/out\//, ""));
const reap = async (pidFile: string): Promise<void> => {
  for (const pid of (await readFile(pidFile, "utf8").catch(() => "")).split(/\s+/).filter(Boolean).map(Number)) if (alive(pid)) process.kill(pid, "SIGKILL");
};

test("macos_triage: a child the program leaves (descriptors closed, writes 0.6 s after the exit) is ended before anything is measured: partial, and the files do not change afterwards", async () => {
  await withCwd(async (cwd, bin) => {
    await mkdir(join(cwd, "out"), { recursive: true });
    await stand(bin, child(0.6, false, join(cwd, "pids.txt")));
    const r = await triage(cwd, bin, { path: await e01(cwd), input_type: "E01", plugins: ["TCC"] });
    const a = JSON.parse(r.stdout) as Json;
    assert.equal(a.exit_code, 0);
    assert.equal(a.status, "partial", a.status_basis);
    assert.ok(a.program_group.left_behind >= 1, JSON.stringify(a.program_group));
    assert.match(a.status_basis, /left \d+ process\(es\) running in the tool's process group/);
    const db = join(real(cwd, a.output_directory), "mac_apt.db");
    const log = join(real(cwd, a.output_directory), "Log.20261104-120000.txt");
    assert.equal((await stat(db)).size, 100);
    assert.equal(a.files.find((f: Json) => f.file === "mac_apt.db").bytes, 100);
    await sleep(1500);
    assert.equal((await stat(db)).size, 100, "the child was ended: the database does not grow");
    assert.doesNotMatch(await readFile(log, "utf8"), /Traceback/);
  });
});

test("macos_triage: a child that started a session of its own (setsid) cannot be ended; a file that grew within the settle makes the answer partial and says so", async () => {
  await withCwd(async (cwd, bin) => {
    await mkdir(join(cwd, "out"), { recursive: true });
    const pids = join(cwd, "pids.txt");
    await stand(bin, child(0.5, true, pids));
    try {
      const a = JSON.parse((await triage(cwd, bin, { path: await e01(cwd), input_type: "E01", plugins: ["TCC"] })).stdout) as Json;
      assert.equal(a.status, "partial", a.status_basis);
      assert.ok(a.program_group.files_grown_after >= 1, JSON.stringify(a.program_group));
      assert.match(a.status_basis, /session of its own \(setsid\).*cannot end it/);
    } finally {
      await reap(pids);
    }
  });
});

test("macos_triage: a clean program that leaves nothing is complete, and nothing changes a second later", async () => {
  await withCwd(async (cwd, bin) => {
    await mkdir(join(cwd, "out"), { recursive: true });
    await stand(bin, `${OK_ONE}open(os.path.join(out, "mac_apt.db"), "wb").write(b"x" * 100)\n`);
    const a = JSON.parse((await triage(cwd, bin, { path: await e01(cwd), input_type: "E01", plugins: ["TCC"] })).stdout) as Json;
    assert.equal(a.status, "complete", a.status_basis + JSON.stringify(a.problems));
    assert.equal(a.program_group.left_behind, 0);
    assert.equal(a.program_group.files_grown_after, 0);
  });
});

test("macos_triage: a traceback on stderr with exit 0 and a clean log is partial, and stderr is read only at its end", async () => {
  await withCwd(async (cwd, bin) => {
    await mkdir(join(cwd, "out"), { recursive: true });
    await stand(bin, `${OK_ONE}sys.stderr.write("Traceback (most recent call last):\\n  File x\\nKeyError: 1\\n")\n`);
    const r = await triage(cwd, bin, { path: await e01(cwd), input_type: "E01", plugins: ["TCC"] });
    const a = JSON.parse(r.stdout) as Json;
    assert.equal(a.status, "partial");
    assert.match(a.problems.join("\n"), /end of stdout or stderr/);
    assert.doesNotMatch(r.stdout, /KeyError/);
  });
});

test("macos_triage: the finish hint on the console is not an error word", async () => {
  await withCwd(async (cwd, bin) => {
    await mkdir(join(cwd, "out"), { recursive: true });
    await stand(bin, `${OK_ONE}print("Review the Log file and report any ERRORs or EXCEPTIONS to the developers")\n`);
    const a = JSON.parse((await triage(cwd, bin, { path: await e01(cwd), input_type: "E01", plugins: ["TCC"] })).stdout) as Json;
    assert.equal(a.status, "complete", a.status_basis + JSON.stringify(a.problems));
  });
});

test("macos_triage: a log read is charged to the tool's clock: a 250 MB log with max_seconds 1 is cut, partial, and the call ends in about the floor, not in minutes", async () => {
  await withCwd(async (cwd, bin) => {
    await mkdir(join(cwd, "out"), { recursive: true });
    await stand(bin, `
start()
log("Running plugin TCC")
line = ("2026-11-04 12:00:00,000|MAIN|INFO|Processed some rows of the table number 12345\\n") * 1000
with open(LOG, "a") as f:
    for _ in range(3200):
        f.write(line)
log("TCC plugin ran for 00:00:01")
finish()
`);
    const r = await triage(cwd, bin, { path: await e01(cwd), input_type: "E01", plugins: ["TCC"], max_seconds: 1 });
    const a = JSON.parse(r.stdout) as Json;
    assert.equal(a.status, "partial", a.status_basis);
    assert.match(a.log.read_cut, /time given to reading the log ran out/);
    assert.match(a.status_basis, /log was not fully read/);
    assert.ok(r.ms < 60_000, `${r.ms} ms`);
  });
}, { timeout: 180_000 });

// ---- the abandoned child in the recipe --------------------------------------------------------------------------------------------------------

test("the recipe: a child the program leaves is ended before index.tsv records sizes: partial, and the recorded size is the final size", async () => {
  await withCwd(async (cwd, bin) => {
    await stand(bin, child(0.6, false, join(cwd, "pids.txt")));
    const path = await e01(cwd);
    const r = await lead(["python3", RECIPE, "run", "--target", JSON.stringify({ paths: [path], plugins: ["TCC"] }), "--out", "o"], cwd, { PATH: `${bin}:${process.env.PATH ?? ""}` });
    const c = JSON.parse(await readFile(join(cwd, "o", "coverage.json"), "utf8")) as Json;
    assert.equal(c.status, "partial", c.status_basis);
    assert.ok(c.plugins.program_group.left_behind >= 1, JSON.stringify(c.plugins.program_group));
    const index = await readFile(join(cwd, "o", "index.tsv"), "utf8");
    assert.match(index, /mac_apt\/mac_apt\.db\t100\t/);
    await sleep(1500);
    assert.equal((await stat(join(cwd, "o", "mac_apt", "mac_apt.db"))).size, 100);
    assert.ok(r.code !== null);
  });
});

test("the recipe: a setsid child that writes inside the settle makes the run partial", async () => {
  await withCwd(async (cwd, bin) => {
    const pids = join(cwd, "pids.txt");
    await stand(bin, child(0.5, true, pids));
    try {
      await lead(["python3", RECIPE, "run", "--target", JSON.stringify({ paths: [await e01(cwd)], plugins: ["TCC"] }), "--out", "o"], cwd, { PATH: `${bin}:${process.env.PATH ?? ""}` });
      const c = JSON.parse(await readFile(join(cwd, "o", "coverage.json"), "utf8")) as Json;
      assert.equal(c.status, "partial");
      assert.match(c.errors.join("\n"), /session of its own \(setsid\)/);
    } finally {
      await reap(pids);
    }
  });
});

// ---- unified_log -----------------------------------------------------------------------------------------------------------------------------

const ulChild = (delay: number, session: boolean, pidFile: string): string => `
open(out, "w").write(json.dumps({"timestamp": "2026-01-01T00:00:00", "eventMessage": "one", "processImagePath": "/usr/bin/p"}) + chr(10))
if os.fork() == 0:
    ${session ? "os.setsid()" : "pass"}
    open(${JSON.stringify(pidFile)}, "a").write("%d\\n" % os.getpid())
    for fd in (0, 1, 2):
        os.close(fd)
    time.sleep(${delay})
    open(out, "a").write(json.dumps({"timestamp": "2026-01-01T00:00:01", "eventMessage": "late", "processImagePath": "/usr/bin/p"}) + chr(10))
    os._exit(0)
`;

test("unified_log: a child the reader leaves is ended before the output is counted and hashed: partial, and the file stays one line", async () => {
  await withCwd(async (cwd) => {
    const bin = await ulStandin(cwd, ulChild(0.6, false, join(cwd, "pids.txt")));
    const r = await lead([PYTHON, UL], cwd, { PATH: bin }, JSON.stringify({ path: await logarchive(cwd), out_dir: "work/o" }));
    const a = JSON.parse(r.stdout) as Json;
    const file = join(cwd, "work", "o", "unifiedlogs.jsonl");
    assert.equal(a.status, "partial", a.status_basis);
    assert.equal(a.entry_count, 1);
    assert.ok(a.reader_group.left_behind >= 1, JSON.stringify(a.reader_group));
    assert.match(a.status_basis, /left \d+ process\(es\) running in the tool's process group/);
    await sleep(1500);
    assert.equal((await readFile(file, "utf8")).split("\n").filter(Boolean).length, 1, "the output is still one line");
    const { createHash } = await import("node:crypto");
    assert.equal(a.output_sha256, createHash("sha256").update(await readFile(file)).digest("hex"), "the sha256 is of the file as it is");
  });
});

test("unified_log: a setsid child that writes inside the settle makes the answer partial and says it cannot be ended", async () => {
  await withCwd(async (cwd) => {
    const pids = join(cwd, "pids.txt");
    const bin = await ulStandin(cwd, ulChild(0.5, true, pids));
    try {
      const a = JSON.parse((await lead([PYTHON, UL], cwd, { PATH: bin }, JSON.stringify({ path: await logarchive(cwd), out_dir: "work/o" }))).stdout) as Json;
      assert.equal(a.status, "partial", a.status_basis);
      assert.match(a.status_basis, /session of its own \(setsid\)/);
    } finally {
      await reap(pids);
    }
  });
});

test("unified_log: a clean reader that leaves nothing is complete and the group fields say so", async () => {
  await withCwd(async (cwd) => {
    const bin = await ulStandin(cwd, `open(out, "w").write(json.dumps({"timestamp": "2026-01-01T00:00:00", "eventMessage": "one", "processImagePath": "/usr/bin/p"}) + chr(10))`);
    const a = JSON.parse((await lead([PYTHON, UL], cwd, { PATH: bin }, JSON.stringify({ path: await logarchive(cwd), out_dir: "work/o" }))).stdout) as Json;
    assert.equal(a.status, "complete", a.status_basis);
    assert.equal(a.reader_group.left_behind, 0);
  });
});

// ---- the log reader, run from its own source text (the tool's and the recipe's copy) ---------------------------------------------------------

const SNIPPET = `
import json, os, sys, time
src = open(sys.argv[1], encoding="utf-8").read()
blk = src.split("# macapt-log-reader: start")[1].split("# macapt-log-reader: stop")[0]
ns = {"os": os, "time": time}
exec(blk, ns)
opts = json.loads(sys.argv[3])
deadline = time.monotonic() + opts["deadline_in"] if opts.get("deadline_in") is not None else None
read = ns["ma_read_log"]([sys.argv[2]], deadline, opts.get("max_bytes", ns["MA_READ_MAX"]))
rows = ns["ma_plugins"](read)
print(json.dumps({"read": {k: v for k, v in read.items() if k != "plugins"}, "rows": [{"plugin": r["plugin"], "status": r["status"]} for r in rows], "tail": ns["ma_tail_hits"]([sys.argv[2]])}))
`;

async function reader(file: string, cwd: string, lines: string[], opts: Json = {}): Promise<Json> {
  const log = join(cwd, "reader.log");
  await writeFile(log, lines.join("\n") + "\n");
  const r = spawnSync(PYTHON, ["-c", SNIPPET, file, log, JSON.stringify(opts)], { encoding: "utf8", maxBuffer: 1 << 26 });
  assert.equal(r.status, 0, r.stderr);
  return JSON.parse(r.stdout) as Json;
}

const GOOD = (middle: string[], name = "TCC"): string[] => [
  PX("INFO", "Started macOS Artifact Parsing Tool, version 1.33.2"),
  PX("INFO", "Running plugin " + name),
  ...middle,
  PX("INFO", name + " plugin ran for 00:00:01"),
  PX("INFO", "Finished in time = 00:00:02"),
  PX("INFO", "Review the Log file and report any ERRORs or EXCEPTIONS to the developers"),
];

for (const [label, file] of [["macos_triage", TRIAGE], ["the recipe", RECIPE]] as const) {
  test(`${label}: the finish hint is exempt only as the whole message of its own line; a path that holds its words does not hide an error`, async () => {
    await withCwd(async (cwd) => {
      const clean = await reader(file, cwd, GOOD(["Processed"]));
      assert.equal(clean.read.run_errors.length, 0);
      assert.deepEqual(clean.rows, [{ plugin: "TCC", status: "parsed" }]);
      const inside = await reader(file, cwd, GOOD([PX("ERROR", 'cannot open "/x/Review the Log file and report any y/db.sqlite"')]));
      assert.equal(inside.rows[0].status, "failed", "an error line that quotes the hint inside a path is an error");
      const after = await reader(file, cwd, [...GOOD(["x"]), PX("INFO", "database failed to open: Review the Log file and report any ERRORs or EXCEPTIONS to the developers")]);
      assert.equal(after.read.run_errors.length, 1, "the hint with other error text on its line is an error");
      const prefixed = await reader(file, cwd, [...GOOD(["x"]).slice(0, -1), "2026-11-04 12:00:00,000|MAIN|ERROR|Review the Log file and report any ERRORs or EXCEPTIONS to the developers"]);
      assert.equal(prefixed.read.run_errors.length, 1, "an ERROR level on the hint line is an error");
    });
  });

  test(`${label}: a line over 4000 bytes is scanned whole; one over the cap is counted and read to the cap`, async () => {
    await withCwd(async (cwd) => {
      const far = await reader(file, cwd, GOOD([PX("INFO", "x".repeat(4500) + " failed to parse record")]));
      assert.equal(far.rows[0].status, "failed", "a failure word at byte 4500 is found");
      const huge = await reader(file, cwd, GOOD([PX("INFO", "y".repeat((1 << 20) + 500))]));
      assert.equal(huge.read.long_lines, 1);
      assert.equal(huge.rows[0].status, "parsed");
      const small = await reader(file, cwd, GOOD(["ok"]));
      assert.equal(small.read.long_lines, 0);
    });
  });

  test(`${label}: quoted or shapeless plugin, finish and start text is not a recognised line: BASH never ran, no real finish, nothing parsed from bare lines`, async () => {
    await withCwd(async (cwd) => {
      const quoted = await reader(file, cwd, [
        PX("INFO", "Started macOS Artifact Parsing Tool, version 1.33.2"),
        PX("INFO", "note: Running plugin BASH"),
        PX("INFO", "see BASH plugin ran for 00:00:01"),
        PX("INFO", "note: Finished in time = 00:00:01"),
      ]);
      assert.deepEqual(quoted.rows, []);
      assert.equal(quoted.read.finished, false);
      const bare = await reader(file, cwd, [
        PX("INFO", "Started macOS Artifact Parsing Tool, version 1.33.2"),
        "Running plugin BASH",
        "BASH plugin ran for 00:00:01",
        "Finished in time = 00:00:01",
      ]);
      assert.deepEqual(bare.rows, []);
      assert.equal(bare.read.unanchored, 3);
      assert.equal(bare.read.finished, false);
      const none = await reader(file, cwd, GOOD(["x"]).map((l) => l.split("|").slice(3).join("|")));
      assert.deepEqual(none.rows, [], "a log without the line shape is not recognised");
      assert.equal(none.read.started, false);
      assert.ok(none.read.unanchored >= 4);
    });
  });

  test(`${label}: the read has a deadline and a byte cap, and says which one ended it`, async () => {
    await withCwd(async (cwd) => {
      const many = GOOD(Array.from({ length: 200000 }, () => PX("INFO", "Processed some rows of the table number 12345")));
      const timed = await reader(file, cwd, many, { deadline_in: 0 });
      assert.match(timed.read.cut, /time given to reading the log ran out/);
      assert.equal(timed.read.lines, 0);
      const capped = await reader(file, cwd, many, { max_bytes: 100000 });
      assert.match(capped.read.cut, /longer than the 100000 bytes/);
      assert.ok(capped.read.bytes < 200000);
      const whole = await reader(file, cwd, many);
      assert.equal(whole.read.cut, null);
      assert.equal(whole.read.finished, true);
    });
  });

  test(`${label}: the end of stdout and stderr is read for an error word, the finish hint taken out`, async () => {
    await withCwd(async (cwd) => {
      const hint = await reader(file, cwd, ["Review the Log file and report any ERRORs or EXCEPTIONS to the developers"]);
      assert.deepEqual(hint.tail, [0, 0]);
      const tb = await reader(file, cwd, ["fine", "Traceback (most recent call last):", "ValueError: no"]);
      assert.deepEqual(tb.tail, [1, 0]);
    });
  });
}

test("the tool and the recipe still carry one copy of the log reader, and neither starts a program in a session or a group of its own", async () => {
  const cut = (t: string): string => t.slice(t.indexOf("# macapt-log-reader: start"), t.indexOf("# macapt-log-reader: stop"));
  const [a, b] = [await readFile(TRIAGE, "utf8"), await readFile(RECIPE, "utf8")];
  assert.equal(cut(a), cut(b));
  for (const t of [a, b, await readFile(UL, "utf8")]) assert.doesNotMatch(t, /start_new_session\s*=\s*True|process_group\s*=|setpgid|setsid\(\)/);
  assert.equal((await stat(TRIAGE)).mode & 0o777, 0o755);
  assert.ok((await filesUnder(join(MAC, ".."))).length > 0);
  assert.ok((await readdir(MAC)).includes("macos_triage"));
});
