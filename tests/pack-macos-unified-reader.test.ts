/**
 * unified_log's reader: lines of its output are read with a bound (one line of 300 MB cost 1.2 GB of memory and was parsed whole), a reader that is stopped
 * or times out leaves no process behind in the tool's process group (a double-forked descendant was out of reach of a walk down the process tree, and a
 * bystander of the group is left alone), the reader dies with the tool (PR_SET_PDEATHSIG), and a staged copy that a killed run left is named with its
 * size when the same out_dir is used again.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { readFile, stat } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { withCwd } from "./tool-library-harness.ts";
import { PYTHON, UL, dbCopy, logarchive, measured, ul, ulStandin } from "./macos-pack-harness.ts";
import type { Json } from "./macos-pack-harness.ts";

const exists = (path: string): Promise<boolean> => stat(path).then(() => true, () => false);
const alive = (pid: number): boolean => {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
};
const gone = async (pid: number, ms = 5000): Promise<boolean> => {
  for (const end = Date.now() + ms; Date.now() < end; await new Promise((r) => setTimeout(r, 40))) if (!alive(pid)) return true;
  return !alive(pid);
};
const waitFor = async (path: string, ms = 20_000): Promise<string> => {
  for (const end = Date.now() + ms; Date.now() < end; await new Promise((r) => setTimeout(r, 25))) {
    const text = await readFile(path, "utf8").catch(() => "");
    if (text.trim()) return text.trim();
  }
  throw new Error(`${path} never appeared`);
};

test("unified_log reads a line of the reader's output with a bound: one line of 300 MB is counted with its length, not parsed, and the tool stays under 200 MB", async () => {
  await withCwd(async (cwd) => {
    const bin = await ulStandin(cwd, `
with open(out, "w") as f:
    f.write('{"timestamp": "2026-01-01T00:00:00", "eventMessage": "')
    for _ in range(300):
        f.write("x" * 1000000)
    f.write('"}' + chr(10))
    f.write(json.dumps({"timestamp": "2026-01-01T00:00:01", "eventMessage": "after", "processImagePath": "/usr/bin/p"}) + chr(10))
`);
    const run = await measured(UL, cwd, { path: await logarchive(cwd), out_dir: "work/o" }, { PATH: bin });
    const answer = JSON.parse(run.stdout) as Json;
    assert.ok(run.mb < 200, `${run.mb.toFixed(0)} MB of memory`);
    assert.equal(answer.entry_count, 1, "the line after it is counted");
    assert.equal(answer.decoded_coverage.lines_over_cap, 1);
    assert.ok(answer.decoded_coverage.longest_line_bytes > 300_000_000);
    assert.deepEqual(answer.decoded_coverage.first_lines_over_cap.map((l: Json) => l.line), [1]);
    assert.equal(answer.status, "partial");
    assert.match(answer.status_basis, /longer than 8388608 bytes and were not parsed/);
    assert.ok((await stat(join(cwd, "work", "o", "unifiedlogs.jsonl"))).size > 300_000_000, "the line is kept in the output file as the reader wrote it");
  });
});

/** The tool as the harness starts it: the leader of a group of its own, with a bystander of that group started before it (`sleep` in the group, its pid in a file). */
function leader(script: string, cwd: string, args: unknown, bin: string, bystanderFile: string): ReturnType<typeof spawn> {
  const child = spawn("/bin/sh", ["-c", '/bin/sleep 300 </dev/null >/dev/null 2>&1 & echo $! > "$1"; exec "$2" "$3"', "sh", bystanderFile, PYTHON, script], {
    cwd, detached: true, env: { ...process.env, AGENT_ID: "s1", PATH: bin },
  });
  child.stdin?.on("error", () => undefined);
  child.stdin?.end(JSON.stringify(args));
  return child;
}

test("unified_log ends what a reader double-forked when it is stopped, and leaves a bystander of the group alone", async () => {
  await withCwd(async (cwd) => {
    const orphanFile = join(cwd, "orphan.pid");
    const bystanderFile = join(cwd, "bystander.pid");
    const bin = await ulStandin(cwd, `
import os
if os.fork() == 0:
    if os.fork() == 0:
        open(${JSON.stringify(orphanFile)}, "w").write(str(os.getpid()))
        os.execv("/bin/sleep", ["sleep", "300"])
    os._exit(0)
time.sleep(300)
`);
    const child = leader(UL, cwd, { path: await logarchive(cwd), out_dir: "work/o" }, bin, bystanderFile);
    const out: Buffer[] = [];
    child.stdout?.on("data", (c: Buffer) => out.push(c));
    const closed = new Promise<number | null>((resolve) => child.on("exit", (code) => resolve(code)));
    let orphan = 0;
    let bystander = 0;
    try {
      orphan = Number(await waitFor(orphanFile));
      bystander = Number(await waitFor(bystanderFile));
      assert.ok(alive(orphan) && alive(bystander));
      process.kill(child.pid as number, "SIGTERM");
      assert.equal(await closed, 143);
      const answer = JSON.parse(Buffer.concat(out).toString("utf8")) as Json;
      assert.equal(answer.interrupted, "SIGTERM");
      assert.ok(answer.reader_processes_left.ended >= 1, JSON.stringify(answer.reader_processes_left));
      assert.equal(await gone(orphan), true, "the double-forked descendant of the reader is still running");
      assert.equal(alive(bystander), true, "a process that was in the group before the reader started was killed");
    } finally {
      for (const pid of [orphan, bystander]) if (pid > 0 && alive(pid)) process.kill(pid, "SIGKILL");
      if (child.exitCode === null) child.kill("SIGKILL");
    }
  });
});

test("unified_log ends a reader's double-forked descendant when its own time is up, too", async () => {
  await withCwd(async (cwd) => {
    const orphanFile = join(cwd, "orphan.pid");
    const bin = await ulStandin(cwd, `
import os
if os.fork() == 0:
    if os.fork() == 0:
        open(${JSON.stringify(orphanFile)}, "w").write(str(os.getpid()))
        os.execv("/bin/sleep", ["sleep", "300"])
    os._exit(0)
time.sleep(300)
`);
    const bystanderFile = join(cwd, "bystander.pid");
    const child = leader(UL, cwd, { path: await logarchive(cwd), out_dir: "work/o", timeout_seconds: 2 }, bin, bystanderFile);
    const out: Buffer[] = [];
    child.stdout?.on("data", (c: Buffer) => out.push(c));
    const closed = new Promise<number | null>((resolve) => child.on("exit", (code) => resolve(code)));
    let orphan = 0;
    let bystander = 0;
    try {
      orphan = Number(await waitFor(orphanFile));
      bystander = Number(await waitFor(bystanderFile));
      await closed;
      const answer = JSON.parse(Buffer.concat(out).toString("utf8")) as Json;
      assert.equal(answer.timed_out, true);
      assert.equal(await gone(orphan), true, "the double-forked descendant of the reader outlived the tool's time");
      assert.equal(alive(bystander), true);
    } finally {
      for (const pid of [orphan, bystander]) if (pid > 0 && alive(pid)) process.kill(pid, "SIGKILL");
      if (child.exitCode === null) child.kill("SIGKILL");
    }
  });
});

test("unified_log's reader dies with the tool when the tool is killed (PR_SET_PDEATHSIG on Linux)", async (t) => {
  if (process.platform !== "linux") return t.skip("PR_SET_PDEATHSIG is Linux");
  await withCwd(async (cwd) => {
    const readerFile = join(cwd, "reader.pid");
    const bystanderFile = join(cwd, "bystander.pid");
    const bin = await ulStandin(cwd, `
open(${JSON.stringify(readerFile)}, "w").write(str(os.getpid()))
time.sleep(300)
`);
    const child = leader(UL, cwd, { path: await logarchive(cwd), out_dir: "work/o" }, bin, bystanderFile);
    const closed = new Promise<number | null>((resolve) => child.on("exit", (code) => resolve(code)));
    let reader = 0;
    let bystander = 0;
    try {
      reader = Number(await waitFor(readerFile));
      bystander = Number(await waitFor(bystanderFile));
      process.kill(child.pid as number, "SIGKILL");
      await closed;
      assert.equal(await gone(reader), true, "the reader outlived the tool that was killed");
    } finally {
      for (const pid of [reader, bystander]) if (pid > 0 && alive(pid)) process.kill(pid, "SIGKILL");
    }
  });
});

test("unified_log names a staged copy that a killed run left, with its size, when the same out_dir is used again", async () => {
  await withCwd(async (cwd) => {
    const input = await dbCopy(cwd, 300, 1);
    const bin = await ulStandin(cwd, `open(out, "w").write("")`);
    const code = `
import importlib.util, os, shutil, signal, sys
spec = importlib.util.spec_from_file_location("tool", sys.argv[1])
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
real = m.copy_file
count = [0]
def copy_file(*a, **k):
    count[0] += 1
    if count[0] > 5:
        os.kill(os.getpid(), signal.SIGKILL)       # the harness's end of a tool at its timeout, in the middle of staging
    return real(*a, **k)
m.copy_file = copy_file
m.install_stop_handlers()
m.main()
`;
    const killed = await new Promise<number | null>((resolve, reject) => {
      const child = spawn("python3", ["-c", code, UL], { cwd, env: { ...process.env, AGENT_ID: "s1", PATH: bin } });
      child.on("error", reject);
      child.on("close", (c, sig) => resolve(c ?? (sig === "SIGKILL" ? -9 : null)));
      child.stdin.end(JSON.stringify({ path: input, out_dir: "work/out" }));
    });
    assert.equal(killed, -9);
    assert.equal(await exists(join(cwd, "work", "out", ".logarchive-input")), true, "the killed run left its staged copy");
    const again = await ul(cwd, bin, { path: input, out_dir: "work/out" });
    assert.equal(again.code, 1);
    const refusal = JSON.parse(again.stdout) as Json;
    assert.match(refusal.error, /\.logarchive-input is a copy of the evidence that an earlier run staged and was killed/);
    assert.equal(refusal.staged_copy.kind, "directory");
    assert.equal(refusal.staged_copy.files, 5);
    assert.ok(refusal.staged_copy.bytes > 0);
    assert.equal(refusal.staged_copy.walk_complete, true);
  });
});
