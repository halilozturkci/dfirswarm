/**
 * mem_fs and what its engine leaves behind. The engine is a stand-in (tests/memory-f1-support.ts) that starts a `sleep` which inherits
 * its stdout and stderr, the pipes the tool's two drain threads read. The tool is started the way the harness starts one, as the leader
 * of a process group of its own; every stand-in and decoy is recorded by pid and ended by this file.
 *
 *  - an engine whose descendant holds the pipes after the engine is gone does not hold the tool (it closed a stream a thread was
 *    reading, which waits for the last holder: the call ran as long as the descendant lived, past the manifest's 600 seconds), and the
 *    descendant, which is in the tool's own group, is ended; a process outside the tool is not;
 *  - the program is ended whether the tool leads its group or not, and wherever it was put (a session of its own), because it was seen below
 *    the engine while the engine ran; a process beside the tool is never ended;
 *  - an unmount helper that does not answer is a named problem of the clean-up, and the clean-up goes on (it raised, and the answer was
 *    "unexpected failure: TimeoutExpired" with the drains, the files and the secret file still open).
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { withCwd } from "./tool-library-harness.ts";
import { FS, fsStub } from "./memory-f1-support.ts";
import { gone, pidFile } from "./pack-network-harness.ts";

type Ended = { code: number | null; stdout: string; ms: number; endGroup: () => void };

function start(script: string, cwd: string, args: unknown, env: Record<string, string>, bin: string, leader: boolean): Promise<Ended> {
  const began = Date.now();
  const e: NodeJS.ProcessEnv = { ...process.env, AGENT_ID: "s1", ...env, PATH: `${bin}:${process.env.PATH ?? ""}` };
  delete e.JOB_ID; delete e.OUT; delete e.SECRET_OUTPUT;
  const child = spawn("python3", [script], { cwd, env: e, detached: leader, stdio: ["pipe", "pipe", "ignore"] });
  const chunks: Buffer[] = [];
  child.stdout.on("data", (c: Buffer) => chunks.push(c));
  child.stdin.end(JSON.stringify(args));
  const endGroup = (): void => { try { process.kill(leader ? -(child.pid as number) : (child.pid as number), "SIGKILL"); } catch { /* gone */ } };
  return new Promise((resolve) => {
    // "exit": a program the tool left holds its pipes open, and the test must say so, not wait for it
    child.on("exit", (code) => setTimeout(() => resolve({ code, stdout: Buffer.concat(chunks).toString("utf8"), ms: Date.now() - began, endGroup }), 100));
  });
}

const end = (pid: number): void => { try { process.kill(pid, "SIGKILL"); } catch { /* gone */ } };

function bystander(): number {
  const child = spawn("sleep", ["300"], { detached: true, stdio: "ignore" });
  child.unref();
  return child.pid as number;
}

test("an engine that ended and left a program holding its pipes does not hold mem_fs: it returns in seconds, and the program is ended", async () => {
  await withCwd(async (cwd, bin) => {
    const holdPid = join(cwd, "hold.pid");
    const env = await fsStub(cwd, bin, { tree: { "proc/a.txt": "alpha\n", "sys/x": "" }, hold: { seconds: 40, pidFile: holdPid } });
    await writeFile(join(cwd, "inputs", "memory.raw"), Buffer.alloc(4096));
    const decoy = bystander();
    let holder = 0;
    let ran: Ended | undefined;
    try {
      ran = await start(FS, cwd, { path: "inputs/memory.raw", mount: join(cwd, "work", "s1", "m"), mode: "list", timeout_seconds: 30 }, env, bin, true);
      holder = await pidFile(holdPid, 5000);
      assert.ok(ran.ms < 25_000, `took ${ran.ms} ms: the call waited for the program the engine left`);
      const answer = JSON.parse(ran.stdout);
      assert.equal(answer.status, "complete", ran.stdout);
      assert.equal(await gone(holder, 10_000), true, "the program the engine left, in the tool's group, was not ended");
      assert.equal(await gone(decoy, 300), false, "a process outside the tool was signalled");
    } finally {
      ran?.endGroup();
      for (const pid of [holder, decoy]) if (pid) end(pid);
    }
  });
});

for (const [name, leader, ownSession] of [["a tool that does not lead its group", false, false], ["a holder in a session of its own", true, true]] as const) {
  test(`${name}: mem_fs returns, ends the program it saw below the engine, and leaves a process beside it alone`, async () => {
    await withCwd(async (cwd, bin) => {
      const holdPid = join(cwd, "hold.pid");
      const env = await fsStub(cwd, bin, { tree: { "proc/a.txt": "alpha\n", "sys/x": "" }, hold: { seconds: 40, pidFile: holdPid, ownSession } });
      await writeFile(join(cwd, "inputs", "memory.raw"), Buffer.alloc(4096));
      const decoy = spawn("sleep", ["300"], { stdio: "ignore" });
      let holder = 0;
      let ran: Ended | undefined;
      try {
        ran = await start(FS, cwd, { path: "inputs/memory.raw", mount: join(cwd, "work", "s1", "m"), mode: "list", timeout_seconds: 30 }, env, bin, leader);
        holder = await pidFile(holdPid, 5000);
        assert.ok(ran.ms < 25_000, `took ${ran.ms} ms`);
        assert.equal(JSON.parse(ran.stdout).status, "complete", ran.stdout);
        assert.equal(await gone(holder, 10_000), true, "the program the engine left was not ended");
        assert.equal(await gone(decoy.pid as number, 300), false, "a process beside the tool was signalled");
      } finally {
        ran?.endGroup();
        for (const pid of [holder, decoy.pid as number]) if (pid) end(pid);
      }
    });
  });
}

test("an unmount helper that does not answer is a named problem of the clean-up, and the clean-up goes on", async () => {
  await withCwd(async (cwd, bin) => {
    const env = await fsStub(cwd, bin, { tree: { "proc/a.txt": "alpha\n", "sys/x": "" }, ignoreTerm: true });
    await writeFile(join(cwd, "inputs", "memory.raw"), Buffer.alloc(4096));
    // the clean-up waits are shortened in a copy of the tool, so that the case takes seconds and not minutes
    const fast = join(cwd, "mem_fs_fast.py");
    const text = await readFile(FS, "utf8");
    assert.match(text, /^CLEANUP_WAIT = 20$/m);
    await writeFile(fast, text.replace(/^CLEANUP_WAIT = 20$/m, "CLEANUP_WAIT = 2"));
    await chmod(fast, 0o755);
    await writeFile(join(bin, "fusermount3"), "#!/bin/sh\nsleep 30\n");
    await chmod(join(bin, "fusermount3"), 0o755);
    await mkdir(join(cwd, "work", "s1"), { recursive: true });
    let ran: Ended | undefined;
    try {
      ran = await start(fast, cwd, { path: "inputs/memory.raw", mount: join(cwd, "work", "s1", "m"), mode: "list", timeout_seconds: 30 }, env, bin, true);
      assert.doesNotMatch(ran.stdout, /unexpected failure/, ran.stdout);
      const answer = JSON.parse(ran.stdout);
      assert.match(JSON.stringify(answer), /unmount helper/, ran.stdout);
    } finally {
      ran?.endGroup();
    }
  });
});

