/**
 * The process block (# BEGIN SHARED PROCESS) every tool and recipe that starts a program carries, in its two lineages: the general one
 * (network, linux, reverse-engineering, virtualization, base, encrypted-containers) and the windows one (wait_for instead of preflight
 * and run_to_files). Three things are held here, each with a case that fails on the text that came before:
 *
 *  - a signal that lands after the program is forked and before it is in ACTIVE ends the whole tree, not an empty list;
 *  - a program that has ended while something it started still holds its pipes does not hold the tool (it waited for the last holder
 *    to let go, up to the program's whole life), and that holder is ended when the tool leads its group, as the harness starts it;
 *  - nothing outside the tool's own tree is ever signalled: a process in another group, and one in the tool's group when the tool does
 *    not lead it, are untouched.
 *
 * The block is run as text in a process of its own (it must lead its group, the way the harness starts a tool), and the tools
 * are run end to end with a stand-in engine. Every stand-in and decoy is recorded by pid and ended by this file.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { ZEEK, gone, pidFile, put, stub, withCwd } from "./pack-network-harness.ts";
import { ROOT } from "./tool-library-harness.ts";

const BEGIN = "# BEGIN SHARED PROCESS";
const END = "# END SHARED PROCESS";
const sha = (text: string): string => createHash("sha256").update(text).digest("hex");

/** The two texts, as a copy carries them (from BEGIN to END, the way the other suites cut them). */
export const GENERAL_SHA = "6a346a556fd3aa04e663d17a505434db5195726251411f19809dd8c69e96e9f2";
export const WINDOWS_SHA = "d856905899410381ac49ee6157a8fd1c8c1db13c2c520dfac5ec2edfe12f324e";

async function carriers(): Promise<string[]> {
  const found: string[] = [];
  const walk = async (dir: string): Promise<void> => {
    for (const e of await readdir(dir, { withFileTypes: true })) {
      const full = join(dir, e.name);
      if (e.isDirectory()) {
        if (e.name !== "node_modules" && e.name !== "__pycache__") await walk(full);
      } else if (e.name === "run.py" && (await readFile(full, "utf8")).includes(BEGIN)) found.push(full);
    }
  };
  await walk(join(ROOT, "packs"));
  await walk(join(ROOT, "tool-library"));
  return found.sort();
}

function cut(text: string): string {
  const start = text.indexOf(BEGIN);
  const end = text.indexOf(END);
  assert.ok(start >= 0 && end > start);
  return text.slice(start, end + END.length);
}

test("every carrier of the process block holds one of its two texts, byte for byte", async () => {
  const files = await carriers();
  assert.ok(files.length >= 25, `${files.length} carriers`);
  for (const file of files) {
    const block = cut(await readFile(file, "utf8"));
    const windows = block.includes("def wait_for(");
    assert.equal(sha(block), windows ? WINDOWS_SHA : GENERAL_SHA, `${file} carries a ${windows ? "windows" : "general"} block that is not the pinned text`);
  }
});

type Ran = { code: number | null; stdout: string; stderr: string; endGroup: () => void };

/** Run a python program as the leader of a group of its own, like a tool the harness starts; ends the group afterwards. */
async function lead(code: string, args: string[], env: Record<string, string> = {}, leader = true): Promise<Ran> {
  const child = spawn("python3", ["-c", code, ...args], { env: { ...process.env, ...env }, detached: leader, stdio: ["ignore", "pipe", "pipe"] });
  const out: Buffer[] = [];
  const err: Buffer[] = [];
  child.stdout.on("data", (c: Buffer) => out.push(c));
  child.stderr.on("data", (c: Buffer) => err.push(c));
  const code2 = await new Promise<number | null>((resolve) => child.on("exit", (c) => resolve(c)));
  await new Promise((r) => setTimeout(r, 100));
  // the group is ended by the caller, after it has looked at what the tool left (the harness does the same, at its deadline)
  const endGroup = (): void => { if (leader) try { process.kill(-(child.pid as number), "SIGKILL"); } catch { /* the group is empty */ } };
  return { code: code2, stdout: Buffer.concat(out).toString("utf8"), stderr: Buffer.concat(err).toString("utf8"), endGroup };
}

const HEAD = String.raw`
import json, os, re, signal, subprocess, sys, time
src = open(sys.argv[1]).read()
block = re.search(r"^# BEGIN SHARED PROCESS\n.*?^# END SHARED PROCESS\n", src, re.S | re.M).group(0)
ns = {"os": os, "signal": signal, "subprocess": subprocess, "sys": sys, "describe": str}
exec(block, ns)
work = sys.argv[2]
def pid_of(name):
    for _ in range(200):
        try:
            text = open(work + "/" + name).read().strip()
            if text:
                return int(text)
        except OSError:
            pass
        time.sleep(0.05)
    raise SystemExit("no " + name)
`;

const BEFORE_ACTIVE = HEAD + String.raw`
ns["install_signal_handlers"]()
proc = ns["spawn"](["sh", "-c", "sleep 300 & echo $! > " + work + "/child.pid; echo $$ > " + work + "/engine.pid; wait"])
pid_of("child.pid")
os.kill(os.getpid(), signal.SIGTERM)       # the signal lands after the fork and before the program is in ACTIVE
ns["ACTIVE"].append(proc)
time.sleep(30)
`;

const HOLDER = HEAD + String.raw`
t = time.monotonic()
holder = work + "/holder.pid"
# "child": the program starts a holder of its pipes and stays a moment, so the holder is seen below it; "daemon": it starts the holder
# the way a daemon does (a child of a child that ends at once) and ends at once, so nothing was ever seen below it
daemon = os.environ.get("HOLD_MODE") == "daemon"
shell = ("(sleep 120 & echo $! > " + holder + "); " if daemon else "sleep 120 & echo $! > " + holder + "; sleep 0.8; ") + "echo '{\"ok\": true}'; exit 0"
proc = ns["spawn"](["sh", "-c", shell], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
ns["ACTIVE"].append(proc)
out, err, timed_out = ns["communicate_bounded"](proc, 30)
ns["ACTIVE"].remove(proc)
print(json.dumps({"out": out.decode(), "timed_out": timed_out, "code": proc.returncode, "took": time.monotonic() - t}), flush=True)
open(work + "/done", "w").write("1")
`;

const HUNG = HEAD + String.raw`
t = time.monotonic()
proc = ns["spawn"](["sh", "-c", "sleep 300 & echo $! > " + work + "/child.pid; echo $$ > " + work + "/engine.pid; wait"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
ns["ACTIVE"].append(proc)
out, err, timed_out = ns["communicate_bounded"](proc, 1)
ns["ACTIVE"].remove(proc)
print(json.dumps({"timed_out": timed_out, "took": time.monotonic() - t}))
`;

const FAMILIES: [string, string][] = [
  ["general", join(ROOT, "packs", "network-forensics", "tools", "zeek_run", "run.py")],
  ["windows", join(ROOT, "packs", "windows-forensics", "tools", "yara_scan", "run.py")],
];

/** A process of the test's own, in a group of its own: nothing the tool owns. Ended by pid by the caller. */
function bystander(): number {
  const child = spawn("sleep", ["300"], { detached: true, stdio: "ignore" });
  child.unref();
  return child.pid as number;
}
const end = (pid: number): void => { try { process.kill(pid, "SIGKILL"); } catch { /* gone */ } };

for (const [family, script] of FAMILIES) {
  test(`${family}: a signal after the fork and before ACTIVE ends the whole tree, and a process outside the tool is left alone`, async () => {
    await withCwd(async (cwd) => {
      const decoy = bystander();
      let engine = 0, child = 0;
      let ran: Ran | undefined;
      try {
        ran = await lead(BEFORE_ACTIVE, [script, cwd]);
        assert.equal(ran.code, 143, ran.stderr);
        engine = await pidFile(join(cwd, "engine.pid"), 5000);
        child = await pidFile(join(cwd, "child.pid"), 5000);
        assert.equal(await gone(engine, 10_000), true, "the program the tool had forked survived the signal");
        assert.equal(await gone(child, 10_000), true, "what that program had started survived the signal");
        assert.equal(await gone(decoy, 300), false, "a process that is not below the tool was signalled");
      } finally {
        ran?.endGroup();
        for (const pid of [engine, child, decoy]) if (pid) end(pid);
      }
    });
  });

  test(`${family}: a program that ended and left something holding its pipes does not hold the tool, and what it left is ended`, async () => {
    await withCwd(async (cwd) => {
      const decoy = bystander();
      let holder = 0;
      let ran: Ran | undefined;
      try {
        ran = await lead(HOLDER, [script, cwd]);
        holder = await pidFile(join(cwd, "holder.pid"), 5000);
        assert.equal(ran.code, 0, ran.stderr);
        const seen = JSON.parse(ran.stdout);
        assert.equal(seen.timed_out, false);
        assert.equal(seen.code, 0);
        assert.match(seen.out, /"ok": true/, "what the program wrote was kept");
        assert.ok(seen.took < 10, `took ${seen.took} s: the tool waited for the holder`);
        assert.equal(await gone(holder, 10_000), true, "the program's leftover, in the tool's own group, was not ended");
        assert.equal(await gone(decoy, 300), false, "a process outside the tool's group was signalled");
      } finally {
        ran?.endGroup();
        for (const pid of [holder, decoy]) if (pid) end(pid);
      }
    });
  });

  test(`${family}: a tool that does not lead its group ends nothing it did not start below itself (the holder is left, the tool is not held)`, async () => {
    await withCwd(async (cwd) => {
      // not detached: the tool is in this test's own group, which holds the decoy and the test runner
      const decoy = spawn("sleep", ["300"], { stdio: "ignore" });
      let holder = 0;
      let ran: Ran | undefined;
      try {
        ran = await lead(HOLDER, [script, cwd], {}, false);
        holder = await pidFile(join(cwd, "holder.pid"), 5000);
        assert.equal(ran.code, 0, ran.stderr);
        assert.ok(JSON.parse(ran.stdout).took < 10);
        assert.equal(await gone(decoy.pid as number, 300), false, "a process in the shared group was signalled");
        assert.equal(await gone(holder, 300), false, "the holder was ended although the tool does not lead its group");
      } finally {
        ran?.endGroup();
        for (const pid of [holder, decoy.pid as number]) if (pid) end(pid);
      }
    });
  });

  test(`${family}: a program that does not end is killed with what it started at the tool's own deadline`, async () => {
    await withCwd(async (cwd) => {
      let engine = 0, child = 0;
      let ran: Ran | undefined;
      try {
        ran = await lead(HUNG, [script, cwd]);
        assert.equal(ran.code, 0, ran.stderr);
        const seen = JSON.parse(ran.stdout);
        assert.equal(seen.timed_out, true);
        assert.ok(seen.took >= 1 && seen.took < 10, `took ${seen.took}`);
        engine = await pidFile(join(cwd, "engine.pid"), 5000);
        child = await pidFile(join(cwd, "child.pid"), 5000);
        assert.equal(await gone(engine, 10_000), true);
        assert.equal(await gone(child, 10_000), true);
      } finally {
        ran?.endGroup();
        for (const pid of [engine, child]) if (pid) end(pid);
      }
    });
  });
}

for (const [family, script] of FAMILIES) {
  test(`${family}: a program that ends at once and leaves a daemon holding its pipes does not hold the tool (the daemon is ended where /proc names the pipe's holders)`, async () => {
    await withCwd(async (cwd) => {
      let holder = 0;
      let ran: Ran | undefined;
      try {
        ran = await lead(HOLDER, [script, cwd], { HOLD_MODE: "daemon" });
        holder = await pidFile(join(cwd, "holder.pid"), 5000);
        assert.equal(ran.code, 0, ran.stderr);
        assert.ok(JSON.parse(ran.stdout).took < 10);
        // Linux names the holders of a pipe; elsewhere a holder that was never seen below the tool is not the tool's to end
        if (process.platform === "linux") assert.equal(await gone(holder, 10_000), true, "the holder of the pipes was not ended");
      } finally {
        ran?.endGroup();
        if (holder) end(holder);
      }
    });
  });
}

/** A tool that heads a pipeline in a job-control shell leads its group, and the next stage of the pipeline is in that group without being its child. */
async function inPipeline(code: string, script: string, cwd: string): Promise<{ code: number | null; stdout: string; endGroup: () => void }> {
  const shell = 'set -m; python3 -c "$1" "$2" "$3" | sh -c \'echo $$ > "$0/consumer.pid"; exec sleep 300\' "$3" & wait';
  const child = spawn("bash", ["-c", shell, "bash", code, script, cwd], { detached: true, stdio: ["ignore", "pipe", "pipe"] });
  child.stdout.resume();
  child.stderr.resume();
  child.unref();
  return { code: null, stdout: "", endGroup: () => { try { process.kill(-(child.pid as number), "SIGKILL"); } catch { /* gone */ } } };
}

for (const [family, script] of FAMILIES) {
  test(`${family}: the next stage of a pipeline the tool heads, in the tool's group, is not ended by a stop signal or by a held pipe`, async () => {
    for (const [name, code] of [["signal", BEFORE_ACTIVE], ["held pipe", HOLDER]] as const) {
      await withCwd(async (cwd) => {
        let consumer = 0, child = 0, holder = 0;
        let ran: { endGroup: () => void } | undefined;
        try {
          ran = await inPipeline(code, script, cwd);
          consumer = await pidFile(join(cwd, "consumer.pid"), 5000);
          if (name === "signal") {
            child = await pidFile(join(cwd, "child.pid"), 5000);
            assert.equal(await gone(child, 10_000), true, "the signal path did not end the program's tree");
          } else {
            holder = await pidFile(join(cwd, "holder.pid"), 5000);
            await pidFile(join(cwd, "done"), 30_000);     // the tool has gone through its grace and its reaping
          }
          assert.equal(await gone(consumer, 500), false, `${name}: the next stage of the pipeline, which the tool never started, was ended`);
        } finally {
          ran?.endGroup();
          for (const pid of [consumer, child, holder]) if (pid) end(pid);
        }
      });
    }
  });
}

// --- the tools, end to end ----------------------------------------------------------------------------------------------

type Started = { pid: number; exited: Promise<number | null>; stdout: () => string; killGroup: () => void };

function startTool(script: string, cwd: string, args: unknown, env: Record<string, string>, bin: string): Started {
  const child = spawn("python3", [script], { cwd, env: { ...process.env, PATH: `${bin}:${process.env.PATH ?? ""}`, AGENT_ID: "s1", ...env }, detached: true, stdio: ["pipe", "pipe", "pipe"] });
  const chunks: Buffer[] = [];
  child.stdout.on("data", (c: Buffer) => chunks.push(c));
  child.stderr.on("data", () => undefined);
  child.stdin.end(JSON.stringify(args));
  const exited = new Promise<number | null>((resolve) => child.on("exit", (c) => resolve(c)));
  return { pid: child.pid as number, exited, stdout: () => Buffer.concat(chunks).toString("utf8"), killGroup: () => { try { process.kill(-(child.pid as number), "SIGKILL"); } catch { /* gone */ } } };
}

/** Runs the tool's module with a Popen that sends the tool SIGTERM right after it has forked the engine (marker: the engine's child is up). */
const INJECT = String.raw`
import os, signal, subprocess, time
if os.environ.get("INJECT_MARKER"):
    _Popen = subprocess.Popen
    class Popen(_Popen):
        def __init__(self, args, *a, **k):
            super().__init__(args, *a, **k)
            if isinstance(args, (list, tuple)) and args and os.path.basename(str(args[0])) == "zeek" and "--version" not in args:
                for _ in range(400):
                    try:
                        if open(os.environ["INJECT_MARKER"]).read().strip():
                            break
                    except OSError:
                        pass
                    time.sleep(0.025)
                os.kill(os.getpid(), signal.SIGTERM)
    subprocess.Popen = Popen
`;

const ZEEK_ENGINE = `#!/bin/sh
for a in "$@"; do
  case "$a" in
    --version) printf 'zeek version 8.0.10-stand-in\\n'; exit 0;;
  esac
done
echo $$ > "$STUB_DIR/engine.pid"
sleep 300 &
echo $! > "$STUB_DIR/child.pid"
wait
`;

test("zeek_run: a signal that lands after the engine is forked and before it is registered ends the engine and what it started", async () => {
  await withCwd(async (cwd, bin) => {
    const dir = join(cwd, "stub");
    const shim = join(cwd, "shim");
    await mkdir(dir, { recursive: true });
    await mkdir(shim, { recursive: true });
    await writeFile(join(shim, "sitecustomize.py"), INJECT);
    await stub(bin, "zeek", ZEEK_ENGINE);
    await put(cwd, "work/c.pcap", Buffer.from("not read by the stand-in"));
    const decoy = bystander();
    let engine = 0, child = 0;
    const run = startTool(ZEEK, cwd, { path: "work/c.pcap", out_dir: "work/zeek-out" }, { STUB_DIR: dir, PYTHONPATH: shim, INJECT_MARKER: join(dir, "child.pid") }, bin);
    try {
      const code = await run.exited;
      engine = await pidFile(join(dir, "engine.pid"), 5000);
      child = await pidFile(join(dir, "child.pid"), 5000);
      assert.equal(code, 143, run.stdout());
      assert.notEqual(JSON.parse(run.stdout()).status, "complete");
      assert.equal(await gone(engine, 10_000), true, "the engine survived the signal");
      assert.equal(await gone(child, 10_000), true, "what the engine started survived the signal");
      assert.equal(await gone(decoy, 300), false, "a process outside the tool was signalled");
    } finally {
      run.killGroup();
      for (const pid of [engine, child, decoy]) if (pid) end(pid);
    }
  });
});

const ZEEK_HOLDING = `#!/bin/sh
for a in "$@"; do
  case "$a" in
    --version) sleep 120 & echo $! > "$STUB_DIR/holder.pid"; sleep 0.8; printf 'zeek version 8.0.10-stand-in\\n'; exit 0;;
  esac
done
exit 0
`;

test("zeek_run: an engine that ended and left a program holding its stdout and stderr does not hold the tool, and the program is ended", async () => {
  await withCwd(async (cwd, bin) => {
    const dir = join(cwd, "stub");
    await mkdir(dir, { recursive: true });
    await stub(bin, "zeek", ZEEK_HOLDING);
    await put(cwd, "work/c.pcap", Buffer.from("not read by the stand-in"));
    const decoy = bystander();
    let holder = 0;
    const began = Date.now();
    const run = startTool(ZEEK, cwd, { path: "work/c.pcap", out_dir: "work/zeek-out", timeout_seconds: 60 }, { STUB_DIR: dir }, bin);
    try {
      let timer: NodeJS.Timeout | undefined;
      const code = await Promise.race([run.exited, new Promise<string>((r) => { timer = setTimeout(() => r("held"), 60_000); })]).finally(() => clearTimeout(timer));
      assert.notEqual(code, "held", "the tool was still waiting for the program the engine left");
      holder = await pidFile(join(dir, "holder.pid"), 5000);
      assert.ok(Date.now() - began < 45_000, `took ${Date.now() - began} ms`);
      // the stand-in writes no logs, so the answer is a failure; what is held is that the run went on to the engine itself (exit_code 0)
      assert.equal(JSON.parse(run.stdout()).exit_code, 0, run.stdout());
      assert.equal(await gone(holder, 10_000), true, "the program the engine left was not ended");
      assert.equal(await gone(decoy, 300), false, "a process outside the tool was signalled");
    } finally {
      run.killGroup();
      for (const pid of [holder, decoy]) if (pid) end(pid);
    }
  });
});
