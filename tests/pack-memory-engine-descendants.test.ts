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
 *  - the program is ended whoever adopts it: init, or a live subreaper that is not pid 1 (WSL's relay, a service manager), which the
 *    clean-up took for a parent of a pid reused since the listing and so left the program running;
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

// The tool started below a live subreaper that is not pid 1 (WSL's relay, a service manager, a container's init): what the engine
// leaves is adopted by it, not by init.
const SUBREAPER = "import ctypes, subprocess, sys\nctypes.CDLL(None).prctl(36, 1)\nsys.exit(subprocess.call([sys.executable, sys.argv[1]]))";

function start(script: string, cwd: string, args: unknown, env: Record<string, string>, bin: string, leader: boolean, subreaper = false): Promise<Ended> {
  const began = Date.now();
  const e: NodeJS.ProcessEnv = { ...process.env, AGENT_ID: "s1", ...env, PATH: `${bin}:${process.env.PATH ?? ""}` };
  delete e.JOB_ID; delete e.OUT; delete e.SECRET_OUTPUT;
  const child = spawn("python3", subreaper ? ["-c", SUBREAPER, script] : [script], { cwd, env: e, detached: leader, stdio: ["pipe", "pipe", "ignore"] });
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

test("adopted by a live subreaper that is not init: the program the engine left is still ended, and a process beside the tool is not", { skip: process.platform !== "linux" && "PR_SET_CHILD_SUBREAPER is Linux's" }, async () => {
  await withCwd(async (cwd, bin) => {
    const holdPid = join(cwd, "hold.pid");
    const env = await fsStub(cwd, bin, { tree: { "proc/a.txt": "alpha\n", "sys/x": "" }, hold: { seconds: 40, pidFile: holdPid } });
    await writeFile(join(cwd, "inputs", "memory.raw"), Buffer.alloc(4096));
    const decoy = bystander();
    let holder = 0;
    let ran: Ended | undefined;
    try {
      ran = await start(FS, cwd, { path: "inputs/memory.raw", mount: join(cwd, "work", "s1", "m"), mode: "list", timeout_seconds: 30 }, env, bin, true, true);
      holder = await pidFile(holdPid, 5000);
      assert.ok(ran.ms < 25_000, `took ${ran.ms} ms: the call waited for the program the engine left`);
      assert.equal(JSON.parse(ran.stdout).status, "complete", ran.stdout);
      assert.equal(await gone(holder, 10_000), true, "the program the engine left, adopted by the subreaper, was not ended");
      assert.equal(await gone(decoy, 300), false, "a process outside the tool was signalled");
    } finally {
      ran?.endGroup();
      for (const pid of [holder, decoy]) if (pid) end(pid);
    }
  });
});

test("an unmount helper that does not answer is a named problem of the clean-up, and the clean-up goes on", async () => {
  await withCwd(async (cwd, bin) => {
    const env = await fsStub(cwd, bin, { tree: { "proc/a.txt": "alpha\n", "sys/x": "" }, ignoreTerm: true });
    await writeFile(join(cwd, "inputs", "memory.raw"), Buffer.alloc(4096));
    // the clean-up waits are shortened in a copy of the tool, so that the case takes seconds and not minutes
    const fast = join(cwd, "mem_fs_fast.py");
    const text = await readFile(FS, "utf8");
    assert.match(text, /^CLEANUP_WAIT = 20$/m);
    assert.match(text, /^UNMOUNT_WAIT = 12\b/m);
    await writeFile(fast, text.replace(/^CLEANUP_WAIT = 20$/m, "CLEANUP_WAIT = 2").replace(/^UNMOUNT_WAIT = 12\b/m, "UNMOUNT_WAIT = 2"));
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

// The stub engine of tests/memory-f1-support.ts, changed to double-fork a program that keeps the engine's stdout and stderr: it is
// reparented to init (or a subreaper) at once, so it is never below the engine in the clean-up's listing.
const DAEMON = `if os.environ.get("STUB_DAEMON"):
    if os.fork() == 0:
        os.setsid()
        if os.fork() == 0:
            open(os.environ["STUB_DAEMON_PID"], "w").write(str(os.getpid()))
            os.execvp("sleep", ["sleep", os.environ["STUB_DAEMON"]])
        os._exit(0)
    os.wait()
`;

const linuxOnly = process.platform === "linux" ? false : "pipe holders are found through /proc, which is Linux's";

test("an engine that daemonises a program holding its pipes: mem_fs ends it, names it, and leaves a process holding a pipe of its own alone", { skip: linuxOnly }, async () => {
  await withCwd(async (cwd, bin) => {
    const env = await fsStub(cwd, bin, { tree: { "proc/a.txt": "alpha\n", "sys/x": "" } });
    const stub = await readFile(join(bin, "memprocfs"), "utf8");
    const marker = 'print("stub memprocfs: initialising")\n';
    assert.ok(stub.includes(marker));
    await writeFile(join(bin, "memprocfs"), stub.replace(marker, marker + DAEMON));
    await writeFile(join(cwd, "inputs", "memory.raw"), Buffer.alloc(4096));
    const daemonPid = join(cwd, "daemon.pid");
    const decoy = spawn("sleep", ["300"], { stdio: ["pipe", "pipe", "pipe"] });     // holds pipes, none of them the tool's
    let daemon = 0;
    let ran: Ended | undefined;
    try {
      ran = await start(FS, cwd, { path: "inputs/memory.raw", mount: join(cwd, "work", "s1", "m"), mode: "list", timeout_seconds: 30 },
        { ...env, STUB_DAEMON: "60", STUB_DAEMON_PID: daemonPid }, bin, true);
      daemon = await pidFile(daemonPid, 5000);
      const answer = JSON.parse(ran.stdout);
      assert.equal(answer.status, "complete", ran.stdout);
      assert.equal(await gone(daemon, 5000), true, "the program the engine daemonised, holding its pipes, was left running");
      const record = answer.clean_up?.pipe_holders;
      assert.deepEqual(record?.ended?.map((e: { pid: number }) => e.pid), [daemon], ran.stdout);
      assert.equal(record.search_complete, true);
      assert.deepEqual(record.left, []);
      assert.equal(await gone(decoy.pid as number, 300), false, "a process beside the tool, holding a pipe of its own, was signalled");
    } finally {
      ran?.endGroup();
      for (const pid of [daemon, decoy.pid as number]) if (pid) end(pid);
    }
  });
});

// The checks that keep the kill set no wider than the holders, on the functions themselves (the tool is loaded as a module; nothing runs).
const PROBE = `
import importlib.util, json, os, signal, subprocess, sys, time
spec = importlib.util.spec_from_file_location("memfs", sys.argv[1])
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
m.HOLDER_TERM = 0.4
m.HOLDER_KILL = 1.0
out = {}

# the tool's own pipe (stdout, which its parent holds too): neither this process nor an ancestor is ever a holder
mine = m.pipe_inodes(sys.stdout)
found, complete = m.find_pipe_holders(mine)
out["own"] = {"inodes": len(mine), "self": os.getpid() in found, "parent": os.getppid() in found, "pid1": 1 in found}

# a holder that is found, then signalled with the wrong start time (a pid reused since), the wrong pipe, and the right ones
kid = subprocess.Popen(["sleep", "60"], stdout=subprocess.PIPE)
inodes = m.pipe_inodes(kid.stdout)
wanted = {"pipe:[%d]" % i for i in inodes}
found, complete = m.find_pipe_holders(inodes)
start = found.get(kid.pid)
out["found"] = {"kid": kid.pid in found, "complete": complete, "only_kid": sorted(found) == [kid.pid]}
out["reused"] = m.signal_holder(kid.pid, (start or 0) + 1, wanted, signal.SIGTERM)
out["wrong_pipe"] = m.signal_holder(kid.pid, start, {"pipe:[1]"}, signal.SIGTERM)
time.sleep(0.3)
out["alive_after_refusals"] = kid.poll() is None
out["right"] = m.signal_holder(kid.pid, start, wanted, signal.SIGTERM)
kid.wait(timeout=5)

# end_pipe_holders: one holder that gives way to SIGTERM, one that ignores it and is killed, one that is gone already
polite = subprocess.Popen(["sleep", "60"], stdout=subprocess.PIPE)
stubborn = subprocess.Popen([sys.executable, "-c", "import signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)"], stdout=subprocess.PIPE)
time.sleep(0.6)
inodes = m.pipe_inodes(polite.stdout, stubborn.stdout)
record = m.end_pipe_holders(inodes)
polite.poll(); stubborn.poll()
out["record"] = {"found": record["found"], "how": sorted((e["how"] for e in record["ended"])), "left": record["left"], "complete": record["search_complete"],
                 "polite_ended": polite.returncode is not None, "stubborn_ended": stubborn.returncode is not None}
print(json.dumps(out))
`;

test("the pipe-holder step: this tool, its parent and pid 1 are never holders, a reused pid or another pipe is not signalled, a holder that ignores SIGTERM is killed", { skip: linuxOnly }, async () => {
  const ran = await new Promise<{ code: number | null; stdout: string; stderr: string }>((resolve) => {
    const child = spawn("python3", ["-c", PROBE, FS], { stdio: ["ignore", "pipe", "pipe"] });
    const out: Buffer[] = [], err: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => out.push(c));
    child.stderr.on("data", (c: Buffer) => err.push(c));
    const hard = setTimeout(() => child.kill("SIGKILL"), 60_000);
    child.on("close", (code) => { clearTimeout(hard); resolve({ code, stdout: Buffer.concat(out).toString("utf8"), stderr: Buffer.concat(err).toString("utf8") }); });
  });
  assert.equal(ran.code, 0, ran.stderr);
  const got = JSON.parse(ran.stdout);
  assert.deepEqual(got.own, { inodes: 1, self: false, parent: false, pid1: false });
  assert.deepEqual(got.found, { kid: true, complete: true, only_kid: true });
  assert.equal(got.reused, false, "a process with another start time was signalled");
  assert.equal(got.wrong_pipe, false, "a process that does not hold the pipe was signalled");
  assert.equal(got.alive_after_refusals, true);
  assert.equal(got.right, true);
  assert.deepEqual(got.record, { found: 2, how: ["killed", "terminated"], left: [], complete: true, polite_ended: true, stubborn_ended: true });
});

