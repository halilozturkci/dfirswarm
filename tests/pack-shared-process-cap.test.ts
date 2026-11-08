/**
 * What the pipes of a program that has ended may deliver (the byte cap of communicate_bounded, both texts of the shared process block).
 *
 * A process a program leaves behind can go on holding the program's pipes and write into them at full speed. communicate_bounded used to keep
 * every byte it delivered (Popen.communicate), so a flooding holder made one call hold gigabytes and run for many seconds, and a caller
 * decoded and parsed all of it, while the block's text, the READMEs and the changelogs said a pipe holder is let go one second after the
 * program ended. Now, from the moment the program has ended (or was killed at its deadline), the pipes give at most PIPE_GRACE seconds and
 * POST_EXIT_BYTES bytes; at the byte cap the tool stops reading, ends the holder and lets the pipes go, and says so (PIPE_CUT, a note in
 * process_notes(), a partial answer through process_apply). The cases are the block's, run as text in a python of its own, one per lineage:
 * the flooding holder (time and peak memory), the silent and the slow holder (still let go after about a second), a large legitimate output
 * (still returned whole), the input written to a program, the deadline, and a program that closed its pipes and goes on running.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { ROOT } from "./tool-library-harness.ts";
import { NO_ADOPTION } from "./host-gates.ts";

const FAMILIES: { family: string; script: string }[] = [
  { family: "general", script: join(ROOT, "packs", "network-forensics", "tools", "zeek_run", "run.py") },
  { family: "windows", script: join(ROOT, "packs", "windows-forensics", "tools", "yara_scan", "run.py") },
];

const CASE = String.raw`
import json, os, re, resource, signal, subprocess, sys, time
src = open(sys.argv[1]).read()
block = re.search(r"^# BEGIN SHARED PROCESS\n.*?^# END SHARED PROCESS\n", src, re.S | re.M).group(0)
W = sys.argv[2]
case = sys.argv[3]
ns = {"os": os, "signal": signal, "subprocess": subprocess, "sys": sys, "describe": str}
exec(block, ns)
NL = chr(92) + "n"
PID = "open(%r, 'w').write(str(os.getpid()))" % (W + "/f.pid")
FLOOD = "import os; " + PID + "\nwhile True: os.write(1, b'junk line from a leftover" + NL + "' * 2000)"
SLOW = "import os, time; " + PID + "\nwhile True:\n    os.write(1, b'tick" + NL + "'); time.sleep(0.01)"
HOLD = "import os, time; " + PID + "; time.sleep(60)"
def holder(code):
    return "setsid python3 -c '%s' </dev/null &" % code.replace("'", "'\"'\"'")
PROGRAMS = {
    "flood": ["sh", "-c", holder(FLOOD) + " echo HEADER"],
    "silent": ["sh", "-c", holder(HOLD) + " echo HEADER; sleep 0.2"],
    "slow": ["sh", "-c", holder(SLOW) + " echo HEADER; sleep 0.2"],
    "big": ["python3", "-c", "import sys\nfor i in range(50): sys.stdout.buffer.write(bytes([65 + i % 26]) * (1 << 20))"],
    "echo": ["python3", "-c", "import sys; d = sys.stdin.buffer.read(); sys.stdout.write(str(len(d)) + ' ' + str(sum(d)))"],
    "hang": ["sh", "-c", "echo HEADER; sleep 60"],
    "closed": ["sh", "-c", "echo HEADER; exec 1>&- 2>&-; sleep 1.2"],
}
seconds = 1.5 if case == "hang" else 20
data = bytes((i * 7) % 256 for i in range(3000000)) if case == "echo" else None
proc = ns["spawn"](PROGRAMS[case], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
ns["ACTIVE"].append(proc)
t = time.monotonic()
out, err, timed_out = ns["communicate_bounded"](proc, seconds, data)
elapsed = time.monotonic() - t
ns["ACTIVE"].remove(proc)
applied = ns["process_apply"]({"status": "complete", "ok": True})
print(json.dumps({"elapsed": elapsed, "out_len": len(out), "head": out[:7].decode("latin-1"), "timed_out": timed_out,
    "cut": ns.get("PIPE_CUT", {"cut": 0})["cut"], "left": ns["LEFT"]["left_behind"], "rss_mb": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / (1048576 if sys.platform == "darwin" else 1024),
    "applied": applied, "text": out.decode("latin-1") if case == "echo" else None,
    "big_ok": out == b"".join(bytes([65 + i % 26]) * (1 << 20) for i in range(50)) if case == "big" else None,
    "returncode": proc.returncode}))
`;

type Result = {
  elapsed: number; out_len: number; head: string; timed_out: boolean; cut: number; left: number; rss_mb: number;
  applied: { status: string; ok: boolean; status_basis?: string; program_group: { notes: string[]; left_behind: number } };
  text: string | null; big_ok: boolean | null; returncode: number | null;
};

async function runCase(script: string, name: string): Promise<Result> {
  const dir = await mkdtemp(join(tmpdir(), "p0b-"));
  try {
    const child = spawn("python3", ["-c", CASE, script, dir, name], { detached: true, stdio: ["ignore", "pipe", "pipe"] });
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => out.push(c));
    child.stderr.on("data", (c: Buffer) => err.push(c));
    const code = await new Promise<number | null>((resolve) => child.on("exit", (c) => resolve(c)));
    try { process.kill(-(child.pid as number), "SIGKILL"); } catch { /* the group is empty */ }
    const text = Buffer.concat(out).toString("utf8");
    assert.equal(code, 0, `${name}: ${Buffer.concat(err).toString("utf8").slice(-600)} ${text.slice(-300)}`);
    return JSON.parse(text.trim().split("\n").pop() as string) as Result;
  } finally {
    for (const file of await readdir(dir).catch(() => [] as string[])) {
      if (!file.endsWith(".pid")) continue;
      const pid = Number((await readFile(join(dir, file), "utf8").catch(() => "")).trim());
      if (Number.isInteger(pid) && pid > 1) { try { process.kill(pid, "SIGKILL"); } catch { /* gone */ } }
    }
    await rm(dir, { recursive: true, force: true });
  }
}

for (const { family, script } of FAMILIES) {
  test(`${family}: a holder that floods the pipe at full speed is cut off at the byte cap: seconds and memory stay small, the cut is said`, async () => {
    const r = await runCase(script, "flood");
    assert.equal(r.head.startsWith("HEADER"), true, "the program's own output is kept");
    assert.ok(r.elapsed < 5, `the call took ${r.elapsed.toFixed(1)} s`);
    assert.ok(r.rss_mb < 200, `the tool held ${r.rss_mb.toFixed(0)} MiB at its peak`);
    assert.ok(r.out_len < 16 * 1024 * 1024, `the output held ${r.out_len} bytes`);
    assert.equal(r.cut, 1, "the call was cut at the cap and counted");
    assert.ok(r.left >= 1, "the holder was ended");
    assert.equal(r.applied.status, "partial");
    assert.equal(r.applied.ok, false);
    assert.ok(r.applied.program_group.notes.some((n) => /went on writing/.test(n)), JSON.stringify(r.applied.program_group.notes));
    assert.equal(r.returncode, 0);
  });

  test(`${family}: a silent holder and a slow writer are let go about a second after the program ended, with no cut`, async () => {
    for (const name of ["silent", "slow"]) {
      const r = await runCase(script, name);
      assert.equal(r.head.startsWith("HEADER"), true, name);
      assert.ok(r.elapsed >= 1.0 && r.elapsed < 3.5, `${name}: ${r.elapsed.toFixed(2)} s`);
      assert.equal(r.cut, 0, name);
      assert.ok(r.left >= 1, `${name}: the holder was ended`);
      assert.equal(r.applied.status, "partial", name);
      assert.ok(r.out_len < 1024 * 1024, `${name}: ${r.out_len} bytes`);
    }
  });

  test(`${family}: a large legitimate output of a program that exits cleanly is returned whole and the answer stays complete`, { skip: NO_ADOPTION }, async () => {
    const r = await runCase(script, "big");
    assert.equal(r.out_len, 50 * 1024 * 1024);
    assert.equal(r.big_ok, true);
    assert.equal(r.cut, 0);
    assert.equal(r.left, 0);
    assert.equal(r.applied.status, "complete");
    assert.ok(r.elapsed < 10, `${r.elapsed.toFixed(1)} s`);
  });

  test(`${family}: the input reaches the program whole, a program that never ends is killed at its deadline, a program that closed its pipes is waited for`, { skip: NO_ADOPTION }, async () => {
    const echo = await runCase(script, "echo");
    let sum = 0;
    for (let i = 0; i < 3000000; i += 1) sum += (i * 7) % 256;
    assert.equal(echo.text, `3000000 ${sum}`);
    const hang = await runCase(script, "hang");
    assert.equal(hang.timed_out, true);
    assert.equal(hang.head.startsWith("HEADER"), true);
    assert.ok(hang.elapsed >= 1.4 && hang.elapsed < 5, `${hang.elapsed.toFixed(1)} s`);
    const closed = await runCase(script, "closed");
    assert.equal(closed.head.startsWith("HEADER"), true);
    assert.equal(closed.timed_out, false);
    assert.equal(closed.returncode, 0);
    assert.ok(closed.elapsed >= 1.0 && closed.elapsed < 4, `${closed.elapsed.toFixed(1)} s`);
    assert.equal(closed.applied.status, "complete");
  });
}
