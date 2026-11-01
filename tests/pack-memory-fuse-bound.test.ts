/**
 * mem_fs and a FUSE mount whose server does not answer. A stat of such a mount blocks for as long as the server lives, so the call the
 * tool made on its main thread, outside any timer (the startup loop's stat of <mount>/sys, os.path.ismount in the clean-up), held the
 * tool past the 600 seconds of its manifest. The stand-in (tests/memory-fuse-stall.py) is a minimal FUSE server over /dev/fuse that
 * answers INIT and then stops answering; it needs /dev/fuse and a fusermount helper, and these cases skip with a reason where the host
 * has neither. Each case runs the tool as the harness does (the leader of a process group of its own) under a hard kill of this file's
 * own, so a tool that hangs fails the case instead of the suite; every stand-in is recorded by pid and ended, and its mount released, here.
 *
 *  - a mount that never answers its first stat ends the call as "not ready" at the deadline, with no check child left;
 *  - a SIGTERM during that blocked stat gives one JSON answer (interrupted, exit 143);
 *  - a server that stops answering once the engine is told to stop (the engine was a front for a detached server) makes the
 *    clean-up name the mount as still there and not answering, in seconds, with no check child left;
 *  - an unmount helper that cannot be reaped after its kill is named with its pid and left, and the wait for it is bounded.
 */
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { accessSync, constants, readdirSync, readFileSync } from "node:fs";
import { chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { ROOT, withCwd } from "./tool-library-harness.ts";
import { FS, fsStub } from "./memory-f1-support.ts";

const STALL = join(ROOT, "tests", "memory-fuse-stall.py");
const HELPER = ["fusermount3", "fusermount"].find((name) => spawnSync("sh", ["-c", `command -v ${name}`]).status === 0);

type Answer = { status: string; error?: string; phase?: string; cleanup_problems?: string[]; status_basis?: string };
type Ended = { code: number | null; stdout: string; ms: number; killedByTest: boolean };

function cannotMount(): string | null {
  if (process.platform !== "linux") return "FUSE stand-in needs Linux";
  try { accessSync("/dev/fuse", constants.R_OK | constants.W_OK); } catch { return "/dev/fuse cannot be opened by this user"; }
  if (!HELPER) return "neither fusermount3 nor fusermount is installed";
  return null;
}

const alive = (pid: number): boolean => { try { process.kill(pid, 0); return true; } catch { return false; } };
const end = (pid: number): void => { try { process.kill(pid, "SIGKILL"); } catch { /* gone */ } };
const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

/** Command lines (NULs shown as spaces) of the processes whose command line holds `needle`, this process excluded. */
function commandLines(needle: string): string[] {
  const found: string[] = [];
  for (const entry of readdirSync("/proc")) {
    if (!/^\d+$/.test(entry) || Number(entry) === process.pid) continue;
    try {
      const line = readFileSync(`/proc/${entry}/cmdline`, "utf8").replaceAll("\0", " ");
      if (line.includes(needle)) found.push(`${entry}: ${line}`);
    } catch { /* gone */ }
  }
  return found;
}

type Standin = { mount: string; env: Record<string, string>; ready: string; pidFile: string; flag: string; release: () => Promise<void> };

/** A `memprocfs` on PATH that is the stand-in, and the paths it reports through. */
async function standin(cwd: string, bin: string, mode: "stall-getattr" | "stall-after-term"): Promise<Standin> {
  const dir = join(cwd, "stall");
  await mkdir(dir, { recursive: true });
  await mkdir(join(cwd, "work", "s1"), { recursive: true });
  await writeFile(join(bin, "memprocfs"), `#!/bin/sh\nexec python3 "${STALL}" "$@"\n`);
  await chmod(join(bin, "memprocfs"), 0o755);
  const ready = join(dir, "ready"), pidFile = join(dir, "server.pid"), flag = join(dir, "flag");
  const mount = join(cwd, "work", "s1", "m");
  return {
    mount, ready, pidFile, flag,
    env: { STALL_MODE: mode, STALL_FLAG: flag, STALL_PIDFILE: pidFile, STALL_READY: ready },
    release: async () => {
      const pid = Number(await readFile(pidFile, "utf8").catch(() => "0"));
      if (pid) end(pid);
      await sleep(200);
      if (HELPER) spawnSync(HELPER, ["-u", "-z", mount], { timeout: 10_000 });
    },
  };
}

/** The tool, started as the harness starts one (leader of its own group). `hardMs`: the longest this file waits before it kills the group. */
function runFs(cwd: string, bin: string, args: unknown, env: Record<string, string>, hardMs: number, signalWhen?: { signal: NodeJS.Signals; ready: string }, unstick?: () => Promise<void>): Promise<Ended> {
  const began = Date.now();
  const e: NodeJS.ProcessEnv = { ...process.env, AGENT_ID: "s1", ...env, PATH: `${bin}:${process.env.PATH ?? ""}` };
  delete e.JOB_ID; delete e.OUT; delete e.SECRET_OUTPUT;
  const child = spawn("python3", [(env.TOOL_COPY as string | undefined) ?? FS], { cwd, env: e, detached: true, stdio: ["pipe", "pipe", "ignore"] });
  const chunks: Buffer[] = [];
  child.stdout.on("data", (c: Buffer) => chunks.push(c));
  child.stdin.end(JSON.stringify(args));
  let killedByTest = false;
  // A tool blocked on a request its FUSE server has read cannot be killed (D state) until the server is gone: `unstick` ends the server.
  const hard = setTimeout(() => { killedByTest = true; try { process.kill(-(child.pid as number), "SIGKILL"); } catch { /* gone */ } void unstick?.(); }, hardMs);
  if (signalWhen) {
    void (async () => {
      while (child.exitCode === null && !killedByTest) {
        try { readFileSync(signalWhen.ready); break; } catch { await sleep(20); }
      }
      await sleep(400);   // the tool is inside its blocked stat
      if (child.exitCode === null) try { child.kill(signalWhen.signal); } catch { /* gone */ }
    })();
  }
  return new Promise((resolve) => {
    child.on("exit", (code) => {
      clearTimeout(hard);
      setTimeout(() => resolve({ code, stdout: Buffer.concat(chunks).toString("utf8"), ms: Date.now() - began, killedByTest }), 100);
    });
  });
}

const whyNot = cannotMount();

test("mem_fs: a mount that never answers its first stat ends the call as not ready at the deadline, and leaves no check child", { skip: whyNot ?? false }, async () => {
  await withCwd(async (cwd, bin) => {
    const s = await standin(cwd, bin, "stall-getattr");
    await writeFile(join(cwd, "inputs", "memory.raw"), Buffer.alloc(4096));
    try {
      const ran = await runFs(cwd, bin, { path: "inputs/memory.raw", mount: s.mount, mode: "list", timeout_seconds: 3 }, s.env, 40_000, undefined, s.release);
      assert.equal(ran.killedByTest, false, "the tool was still blocked in its stat of the mount when this file killed it");
      const answer = JSON.parse(ran.stdout) as Answer;
      assert.equal(answer.status, "failed", ran.stdout);
      assert.equal(answer.phase, "startup");
      assert.match(answer.error ?? "", /not ready/);
      assert.ok(ran.ms < 20_000, `the call took ${ran.ms} ms against a 3 s deadline`);
      assert.deepEqual(commandLines(s.mount), [], "a process that names the mount is still running");
    } finally {
      await s.release();
    }
  });
});

test("mem_fs: a SIGTERM during the blocked stat gives one JSON answer", { skip: whyNot ?? false }, async () => {
  await withCwd(async (cwd, bin) => {
    const s = await standin(cwd, bin, "stall-getattr");
    await writeFile(join(cwd, "inputs", "memory.raw"), Buffer.alloc(4096));
    try {
      const ran = await runFs(cwd, bin, { path: "inputs/memory.raw", mount: s.mount, mode: "list", timeout_seconds: 120 }, s.env, 40_000, { signal: "SIGTERM", ready: s.ready }, s.release);
      assert.equal(ran.killedByTest, false, "the tool did not answer a SIGTERM that arrived during the blocked stat");
      const answer = JSON.parse(ran.stdout) as Answer;   // two documents would not parse
      assert.equal(answer.status, "interrupted", ran.stdout);
      assert.equal(ran.code, 143);
      assert.deepEqual(commandLines(s.mount), [], "a process that names the mount is still running");
    } finally {
      await s.release();
    }
  });
});

test("mem_fs: a server that stops answering once the engine is stopped makes the clean-up name the mount as still there, in seconds", { skip: whyNot ?? false }, async () => {
  await withCwd(async (cwd, bin) => {
    const s = await standin(cwd, bin, "stall-after-term");
    await writeFile(join(cwd, "inputs", "memory.raw"), Buffer.alloc(4096));
    try {
      const ran = await runFs(cwd, bin, { path: "inputs/memory.raw", mount: s.mount, mode: "list", list: "sys", timeout_seconds: 5 }, s.env, 60_000, undefined, s.release);
      assert.equal(ran.killedByTest, false, "the clean-up was still blocked on the mount when this file killed the tool");
      const answer = JSON.parse(ran.stdout) as Answer;
      assert.equal(answer.status, "failed", ran.stdout);
      assert.equal(answer.phase, "cleanup", ran.stdout);
      assert.match(answer.error ?? "", /still there and does not answer/);
      assert.ok((answer.cleanup_problems ?? []).some((p) => /does not answer/.test(p)), ran.stdout);
      assert.ok(ran.ms < 45_000, `the call took ${ran.ms} ms`);
      const server = Number(await readFile(s.pidFile, "utf8"));
      assert.ok(alive(server), "the server ended with the engine, so the mount was never stalled");
      // A request the server has read cannot be interrupted, not even by SIGKILL, so a check or a helper stuck on it outlives its kill:
      // the answer must name each one by pid, and each ends once the server is gone.
      const stuck = commandLines(s.mount).filter((line) => !line.includes("memory-fuse-stall.py")).map((line) => Number(line.split(":")[0]));
      for (const pid of stuck) assert.match(JSON.stringify(answer.cleanup_problems), new RegExp(`pid ${pid}\\b`), `process ${pid} is left and the answer does not name it`);
      await s.release();
      for (let i = 0; i < 50 && stuck.some(alive); i++) await sleep(100);
      assert.deepEqual(stuck.filter(alive), [], "a left process outlived the server");
    } finally {
      await s.release();
    }
  });
});

test("mem_fs: an unmount helper that cannot be reaped after its kill is named with its pid and left, and the wait for it is bounded", async () => {
  await withCwd(async (cwd, bin) => {
    const env = await fsStub(cwd, bin, { tree: { "proc/a.txt": "alpha\n", "sys/x": "" }, ignoreTerm: true });
    await writeFile(join(cwd, "inputs", "memory.raw"), Buffer.alloc(4096));
    // the waits are shortened in a copy of the tool, and its kill is made to do nothing (a process in uninterruptible sleep is not reaped
    // by SIGKILL), so that the case takes seconds and the reaping limit is the only thing that can end the wait
    const text = await readFile(FS, "utf8");
    assert.match(text, /^CLEANUP_WAIT = 20$/m);
    assert.match(text, /^UNMOUNT_WAIT = 12\b/m);
    assert.match(text, /^REAP_WAIT = 2\b/m);
    assert.equal(text.split("        child.kill()\n").length, 2, "end_child's kill is not where this case expects it");
    const copy = join(cwd, "mem_fs_unreapable.py");
    await writeFile(copy, text.replace(/^CLEANUP_WAIT = 20$/m, "CLEANUP_WAIT = 2").replace(/^UNMOUNT_WAIT = 12\b/m, "UNMOUNT_WAIT = 1")
      .replace(/^REAP_WAIT = 2\b/m, "REAP_WAIT = 1").replace("        child.kill()\n", "        pass\n"));
    await chmod(copy, 0o755);
    const helperPids = join(cwd, "helper.pids");
    await writeFile(join(bin, "fusermount3"), `#!/bin/sh\necho $$ >> "${helperPids}"\nexec sleep 30\n`);
    await chmod(join(bin, "fusermount3"), 0o755);
    await mkdir(join(cwd, "work", "s1"), { recursive: true });
    try {
      const ran = await runFs(cwd, bin, { path: "inputs/memory.raw", mount: join(cwd, "work", "s1", "m"), mode: "list", timeout_seconds: 30 },
        { ...env, TOOL_COPY: copy }, 60_000);
      assert.equal(ran.killedByTest, false, "the wait for the helper had no limit");
      const answer = JSON.parse(ran.stdout) as Answer;
      assert.equal(answer.status, "failed", ran.stdout);
      assert.equal(answer.phase, "cleanup");
      assert.ok((answer.cleanup_problems ?? []).some((p) => /unmount helper did not finish within 1s and could not be ended \(pid \d+, left running\)/.test(p)), ran.stdout);
      assert.ok(ran.ms < 30_000, `the call took ${ran.ms} ms`);
    } finally {
      for (const pid of (await readFile(helperPids, "utf8").catch(() => "")).split("\n").filter(Boolean)) end(Number(pid));
    }
  });
});
