/**
 * PKG-MAC-18 fix round 2. A child that LEAVES the tool's process group (setsid, setpgid, a double fork and then setsid, a periodic writer that never exits) is
 * still found: the tool is a child subreaper (Linux), so every orphan of the program comes to it, and it kills and reaps them before it measures anything.
 * Also: a tool that does not lead its process group is no exception, a FIFO at the name of the log never blocks the read, and a stop signal ends the log read.
 * Stand-ins only (mac_apt and unifiedlog_iterator were never run here).
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { chmod, mkdir, readFile, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { withCwd } from "./tool-library-harness.ts";
import { MAC } from "./macos-late-harness.ts";
import { PYTHON, UL, logarchive, ulStandin } from "./macos-pack-harness.ts";
import type { Json } from "./macos-pack-harness.ts";

const TRIAGE = join(MAC, "macos_triage", "run.py");
const RECIPE = join(MAC, "..", "recipes", "macos-artefacts", "run.py");
const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));
const alive = (pid: number): boolean => {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
};

function run(argv: string[], cwd: string, env: Record<string, string>, stdin: string, detached: boolean): Promise<{ code: number | null; stdout: string; stderr: string; ms: number }> {
  return new Promise((resolve, reject) => {
    const began = Date.now();
    const child = spawn(argv[0], argv.slice(1), { cwd, env: { ...process.env, AGENT_ID: "s1", ...env }, detached });
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => out.push(c));
    child.stderr.on("data", (c: Buffer) => err.push(c));
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stdout: Buffer.concat(out).toString("utf8"), stderr: Buffer.concat(err).toString("utf8"), ms: Date.now() - began }));
    child.stdin.on("error", () => undefined);
    child.stdin.end(stdin);
  });
}

const PRE = `
import os, sys, time
argv = sys.argv[1:]
if argv == ["-h"]:
    print("macOS Artifact Parsing Tool, version 1.33.2")
    sys.exit(0)
out = argv[argv.index("-o") + 1]
os.makedirs(out, exist_ok=True)
LOG = os.path.join(out, "Log.20261104-120000.txt")
DB = os.path.join(out, "mac_apt.db")
def log(line, level="INFO"):
    with open(LOG, "a") as f:
        f.write("2026-11-04 12:00:00,000|MAIN|%s|%s\\n" % (level, line))
`;
const CLEAN = `
log("Started macOS Artifact Parsing Tool, version 1.33.2")
log("Running plugin TCC")
log("Processed 3 rows")
log("TCC plugin ran for 00:00:01")
log("Finished in time = 00:00:02")
log("Review the Log file and report any ERRORs or EXCEPTIONS to the developers")
open(DB, "wb").write(b"x" * 100)
`;

/** The python that leaves a child: `variant` is how it leaves, `fork` how long after the program starts it does it; `target` and `late` say what it writes. */
const ESCAPER = (variant: string, fork: number, pidFile: string, target: string, small: string, late: string): string => `
if os.fork() == 0:
    time.sleep(${fork})
    v = ${JSON.stringify(variant)}
    if v == "double":
        if os.fork() != 0:
            os._exit(0)
        os.setsid()
    elif v == "setpgid":
        os.setpgid(0, 0)
    else:
        os.setsid()
    open(${JSON.stringify(pidFile)}, "a").write("%d\\n" % os.getpid())
    for fd in (0, 1, 2):
        os.close(fd)
    TARGET = ${target}
    if v == "periodic":
        while True:
            time.sleep(0.2)
            open(TARGET, "ab").write(${small})
    time.sleep(3)
    ${late}
    os._exit(0)
`;

async function e01(cwd: string): Promise<string> {
  await writeFile(join(cwd, "work", "mac.E01"), Buffer.concat([Buffer.from([0x45, 0x56, 0x46, 0x09, 0x0d, 0x0a, 0xff, 0x00]), Buffer.alloc(4096)]));
  return "work/mac.E01";
}
async function stand(bin: string, script: string): Promise<void> {
  await mkdir(bin, { recursive: true });
  const file = join(bin, "mac_apt.py");
  await writeFile(file, `#!/usr/bin/env python3\n${PRE}\n${script}\n`);
  await chmod(file, 0o755);
}
const MAC_LATE = `open(TARGET, "ab").write(b"y" * 100000)\n    open(LOG, "a").write("2026-11-04 12:00:09,000|MAIN|INFO|Traceback (most recent call last):\\n")`;
const UL_LINE = `json.dumps({"timestamp": "2026-01-01T00:00:01", "eventMessage": "late", "processImagePath": "/usr/bin/p"}).encode() + b"\\n"`;

type Tool = "triage" | "recipe" | "ul";
const VARIANTS = ["setsid", "setpgid", "double", "periodic"];
const FORKS = [0, 0.6, 1.5];

/** One run of a tool over a stand-in that leaves a child; resolves with what was found, after the files were watched for 5 more seconds. */
async function scenario(tool: Tool, variant: string, fork: number, leader = true): Promise<void> {
  const label = `${tool} ${variant} fork ${fork}${leader ? "" : " non-leader"}`;
  await withCwd(async (cwd, bin) => {
    const pids = join(cwd, "pids.txt");
    let target = "";
    let sizeAfter: () => Promise<number> = async () => -1;
    let expectSize = 0;
    let digestOk: () => Promise<void> = async () => undefined;
    let status = "";
    let left = 0;
    let basis = "";
    if (tool === "ul") {
      const file = join(cwd, "work", "o", "unifiedlogs.jsonl");
      const ulbin = await ulStandin(cwd, `open(out, "w").write(json.dumps({"timestamp": "2026-01-01T00:00:00", "eventMessage": "one", "processImagePath": "/usr/bin/p"}) + chr(10))\n${ESCAPER(variant, fork, pids, "out", UL_LINE, `open(TARGET, "ab").write(${UL_LINE})`)}`);
      const r = await run([PYTHON, UL], cwd, { PATH: ulbin }, JSON.stringify({ path: await logarchive(cwd), out_dir: "work/o" }), leader);
      const a = JSON.parse(r.stdout) as Json;
      status = a.status;
      left = a.reader_group.left_behind;
      basis = a.status_basis;
      target = file;
      sizeAfter = async () => (await readFile(file, "utf8")).split("\n").filter(Boolean).length;
      expectSize = 1;
      digestOk = async () => {
        const { createHash } = await import("node:crypto");
        assert.equal(a.output_sha256, createHash("sha256").update(await readFile(file)).digest("hex"), `${label}: the sha256 is of the file as it ends up`);
      };
    } else {
      await stand(bin, `${CLEAN}\n${ESCAPER(variant, fork, pids, "DB", 'b"z" * 10', MAC_LATE)}`);
      const env = { PATH: `${bin}:${process.env.PATH ?? ""}`, JOB_ID: "j-1", OUT: join(cwd, "out"), SECRET_OUTPUT: "1" };
      await mkdir(join(cwd, "out"), { recursive: true });
      if (tool === "triage") {
        const r = await run([PYTHON, TRIAGE], cwd, env, JSON.stringify({ path: await e01(cwd), input_type: "E01", plugins: ["TCC"] }), leader);
        const a = JSON.parse(r.stdout) as Json;
        status = a.status;
        left = a.program_group.left_behind;
        basis = a.status_basis;
        target = join(cwd, "out", a.output_directory.replace(/^store\/jobs\/[^/]+\/out\//, ""), "mac_apt.db");
      } else {
        const r = await run(["python3", RECIPE, "run", "--target", JSON.stringify({ paths: [await e01(cwd)], plugins: ["TCC"] }), "--out", "o"], cwd, env, "", leader);
        const c = JSON.parse(await readFile(join(cwd, "o", "coverage.json"), "utf8")) as Json;
        status = c.status;
        left = c.plugins.program_group.left_behind;
        basis = c.status_basis;
        target = join(cwd, "o", "mac_apt", "mac_apt.db");
        assert.ok(r.code !== null);
      }
      sizeAfter = async () => (await stat(target)).size;
      expectSize = 100;
    }
    assert.equal(status, "partial", `${label}: ${basis}`);
    assert.ok(left >= 1, `${label}: left_behind ${left}`);
    assert.match(basis, /left \d+ process\(es\) running/, label);
    await sleep(5000);
    assert.equal(await sizeAfter(), expectSize, `${label}: the file is unchanged five seconds after the answer`);
    if (tool !== "ul") assert.doesNotMatch(await readFile(join(target, "..", "Log.20261104-120000.txt"), "utf8"), /Traceback/, label);
    for (const pid of (await readFile(pids, "utf8").catch(() => "")).split(/\s+/).filter(Boolean).map(Number)) assert.ok(!alive(pid), `${label}: pid ${pid} is gone`);
    await digestOk();
  });
}

for (const tool of ["triage", "recipe", "ul"] as const) {
  test(`${tool}: a child that leaves the tool's group (setsid, setpgid, double fork, periodic writer) at 0, 0.6 or 1.5 s is found, ended and reaped: partial, files unchanged afterwards`, { timeout: 170_000 }, async () => {
    await Promise.all(VARIANTS.flatMap((v) => FORKS.map((f) => scenario(tool, v, f))));
  });
}

test("a tool that does not lead its process group (plain child, double-fork child, 3 s) is partial and never complete: triage, recipe and unified_log", { timeout: 120_000 }, async () => {
  await Promise.all((["triage", "recipe", "ul"] as const).flatMap((tool) => ["setsid", "double"].map((v) => scenario(tool, v, 0, false))));
});

test("a clean program that leaves nothing is still complete in a tool that is the subreaper, and a clean run is not made partial by the scan", async () => {
  await withCwd(async (cwd, bin) => {
    await stand(bin, CLEAN);
    await mkdir(join(cwd, "out"), { recursive: true });
    const env = { PATH: `${bin}:${process.env.PATH ?? ""}`, JOB_ID: "j-1", OUT: join(cwd, "out"), SECRET_OUTPUT: "1" };
    const a = JSON.parse((await run([PYTHON, TRIAGE], cwd, env, JSON.stringify({ path: await e01(cwd), input_type: "E01", plugins: ["TCC"] }), true)).stdout) as Json;
    assert.equal(a.status, "complete", a.status_basis + JSON.stringify(a.problems));
    assert.equal(a.program_group.left_behind, 0);
    assert.match(a.status_basis, /No process was left running after mac_apt ended/);
  });
});

test("a FIFO at the name of the log never blocks the read: the answer comes inside the clock, the log is unreadable and the run is not complete (triage and recipe)", { timeout: 120_000 }, async () => {
  await withCwd(async (cwd, bin) => {
    await stand(bin, `os.mkfifo(LOG)\nopen(DB, "wb").write(b"x" * 100)\n`);
    await mkdir(join(cwd, "out"), { recursive: true });
    const env = { PATH: `${bin}:${process.env.PATH ?? ""}`, JOB_ID: "j-1", OUT: join(cwd, "out"), SECRET_OUTPUT: "1" };
    const t = await run([PYTHON, TRIAGE], cwd, env, JSON.stringify({ path: await e01(cwd), input_type: "E01", plugins: ["TCC"], max_seconds: 5 }), true);
    const a = JSON.parse(t.stdout) as Json;
    assert.ok(t.ms < 40_000, `${t.ms} ms`);
    assert.notEqual(a.status, "complete");
    assert.match(a.problems.join("\n"), /could not be read/);
    const r = await run(["python3", RECIPE, "run", "--target", JSON.stringify({ paths: [await e01(cwd)], plugins: ["TCC"] }), "--out", "o", "--max-seconds", "5"], cwd, env, "", true);
    assert.ok(r.ms < 40_000, `${r.ms} ms`);
    const c = JSON.parse(await readFile(join(cwd, "o", "coverage.json"), "utf8")) as Json;
    assert.notEqual(c.status, "complete");
  });
});

test("SIGTERM during the log read ends the read: exit 143 and one JSON answer long before the log would have been read", { timeout: 120_000 }, async () => {
  await withCwd(async (cwd, bin) => {
    await stand(bin, `
log("Started macOS Artifact Parsing Tool, version 1.33.2")
log("Running plugin TCC")
line = ("2026-11-04 12:00:00,000|MAIN|INFO|Processed some rows of the table number 12345\\n") * 1000
with open(LOG, "a") as f:
    for _ in range(3200):
        f.write(line)
log("TCC plugin ran for 00:00:01")
log("Finished in time = 00:00:02")
`);
    await mkdir(join(cwd, "out"), { recursive: true });
    const env = { ...process.env, AGENT_ID: "s1", PATH: `${bin}:${process.env.PATH ?? ""}`, JOB_ID: "j-1", OUT: join(cwd, "out"), SECRET_OUTPUT: "1" };
    const began = Date.now();
    const child = spawn(PYTHON, [TRIAGE], { cwd, env });
    const out: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => out.push(c));
    child.stdin.end(JSON.stringify({ path: await e01(cwd), input_type: "E01", plugins: ["TCC"], max_seconds: 300 }));
    // the stand-in has ended and the read has begun once the answer's run directory holds the 250 MB log: wait for it, then send the signal
    const watch = async (): Promise<void> => {
      for (let i = 0; i < 200; i++) {
        await sleep(100);
        const { readdir } = await import("node:fs/promises");
        const dirs = await readdir(join(cwd, "out", "tool-output")).catch(() => [] as string[]);
        for (const d of dirs) {
          const log = await stat(join(cwd, "out", "tool-output", d, "out", "Log.20261104-120000.txt")).catch(() => null);
          if (log && log.size > 200_000_000) return;
        }
      }
    };
    await watch();
    await sleep(2500);
    child.kill("SIGTERM");
    const code = await new Promise<number | null>((res) => child.on("close", (c) => res(c)));
    assert.equal(code, 143);
    assert.ok(Date.now() - began < 90_000, `${Date.now() - began} ms`);
    const a = JSON.parse(Buffer.concat(out).toString("utf8")) as Json;
    assert.equal(a.interrupted, "SIGTERM");
  });
});

test("a child the tool already had before the program started (a bystander) is not the program's and is left alone", { timeout: 60_000 }, async () => {
  await withCwd(async (cwd, bin) => {
    await stand(bin, CLEAN);
    await mkdir(join(cwd, "out"), { recursive: true });
    const bystanderFile = join(cwd, "bystander.pid");
    const child = spawn("/bin/sh", ["-c", '/bin/sleep 300 </dev/null >/dev/null 2>&1 & echo $! > "$1"; exec "$2" "$3"', "sh", bystanderFile, PYTHON, TRIAGE], {
      cwd, detached: true, env: { ...process.env, AGENT_ID: "s1", PATH: `${bin}:${process.env.PATH ?? ""}`, JOB_ID: "j-1", OUT: join(cwd, "out"), SECRET_OUTPUT: "1" },
    });
    const out: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => out.push(c));
    child.stdin.end(JSON.stringify({ path: await e01(cwd), input_type: "E01", plugins: ["TCC"] }));
    await new Promise((res) => child.on("close", res));
    const bystander = Number((await readFile(bystanderFile, "utf8")).trim());
    try {
      const a = JSON.parse(Buffer.concat(out).toString("utf8")) as Json;
      assert.equal(a.status, "complete", a.status_basis);
      assert.ok(alive(bystander), "a child that was there before the program started is not killed");
    } finally {
      if (alive(bystander)) process.kill(bystander, "SIGKILL");
    }
  });
});
