/**
 * What a program leaves behind (the settle part of the shared process block, both texts: the general one and the windows one).
 *
 * A program the tool runs can exit by itself and leave a process that goes on writing a file the answer then reports: one that started a
 * session of its own, or one that holds none of the tool's descriptors, which the walk below the program and the pipe holder scan never
 * reach. Four review rounds found that class tool by tool. The block now makes the tool a subreaper (PR_SET_CHILD_SUBREAPER) when it spawns
 * its first program and, when a program leaves ACTIVE (and at the end of communicate_bounded, and in kill_all), ends the children of the tool
 * that are no program's own. The cases here are the block's, run as text in a process of its own that leads its group the way the harness
 * starts a tool; then three tools end to end (the audit's repros): extract_stream (windows text), fuzzy_hash (general text, RE pack) and the
 * twin of the first. Every stand-in is recorded by pid or by a marker program and ended by this file.
 *
 * Not here: a carrier calling process_apply (the packages that wire a carrier test its answer); the cases of tests/pack-shared-process.test.ts.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile, readdir, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { gone, put, stub, withCwd } from "./pack-network-harness.ts";
import { ROOT, runPy } from "./tool-library-harness.ts";
import { NO_ADOPTION } from "./host-gates.ts";

const BEGIN = "# BEGIN SHARED PROCESS";
const END = "# END SHARED PROCESS";

const FAMILIES: { family: "general" | "windows"; script: string; wraps: string[] }[] = [
  { family: "general", script: join(ROOT, "packs", "network-forensics", "tools", "zeek_run", "run.py"), wraps: ["run_to_files", "preflight"] },
  { family: "windows", script: join(ROOT, "packs", "windows-forensics", "tools", "yara_scan", "run.py"), wraps: ["wait_for"] },
];

type Ran = { code: number | null; stdout: string; stderr: string; endGroup: () => void; pid: number };

/** Run a python program that execs the block, as the leader of a group of its own (the harness's way) or, with leader false, in this test's group. */
async function lead(code: string, args: string[], env: Record<string, string> = {}, leader = true): Promise<Ran> {
  const child = spawn("python3", ["-c", code, ...args], { env: { ...process.env, ...env }, detached: leader, stdio: ["ignore", "pipe", "pipe"] });
  const out: Buffer[] = [];
  const err: Buffer[] = [];
  child.stdout.on("data", (c: Buffer) => out.push(c));
  child.stderr.on("data", (c: Buffer) => err.push(c));
  const status = await new Promise<number | null>((resolve) => child.on("exit", (c) => resolve(c)));
  await new Promise((r) => setTimeout(r, 100));
  const endGroup = (): void => { if (leader) try { process.kill(-(child.pid as number), "SIGKILL"); } catch { /* the group is empty */ } };
  return { code: status, stdout: Buffer.concat(out).toString("utf8"), stderr: Buffer.concat(err).toString("utf8"), endGroup, pid: child.pid as number };
}

const end = (pid: number): void => { try { process.kill(pid, "SIGKILL"); } catch { /* gone */ } };

/** Every pid a stand-in recorded in `dir` (files named *.pid), for the cleanup of a case that failed. */
async function recorded(dir: string): Promise<number[]> {
  const found: number[] = [];
  for (const name of await readdir(dir).catch(() => [] as string[])) {
    if (!name.endsWith(".pid")) continue;
    const n = Number((await readFile(join(dir, name), "utf8").catch(() => "")).trim());
    if (Number.isInteger(n) && n > 1) found.push(n);
  }
  return found;
}

const HEAD = String.raw`
import json, os, re, signal, subprocess, sys, time, types
src = open(sys.argv[1]).read()
block = re.search(r"^# BEGIN SHARED PROCESS\n.*?^# END SHARED PROCESS\n", src, re.S | re.M).group(0)
W = sys.argv[2]
WRAP = os.environ.get("WRAP", "")
def load(over=None):
    ns = {"os": os, "signal": signal, "subprocess": subprocess, "sys": sys, "describe": str}
    ns.update(over or {})
    exec(block, ns)
    return ns
def stat_of(pid):
    try:
        data = open("/proc/%d/stat" % pid).read()
    except OSError:
        return None
    return data.rsplit(")", 1)[1].split()[0]
def alive(pid):
    s = stat_of(pid)
    return s is not None and s not in ("Z", "X")
def pid_of(name, wait=10):
    until = time.monotonic() + wait
    while time.monotonic() < until:
        try:
            text = open(W + "/" + name).read().strip()
            if text:
                return int(text)
        except OSError:
            pass
        time.sleep(0.02)
    raise SystemExit("no " + name)
def procs_with(marker):
    found = []
    for entry in os.listdir("/proc"):
        if entry.isdigit() and int(entry) != os.getpid():
            try:
                if marker.encode() in open("/proc/%s/cmdline" % entry, "rb").read() and alive(int(entry)):
                    found.append(int(entry))
            except OSError:
                pass
    return found
def children_of_me():
    me, found = os.getpid(), {}
    for entry in os.listdir("/proc"):
        if entry.isdigit():
            try:
                rest = open("/proc/%s/stat" % entry).read().rsplit(")", 1)[1].split()
            except OSError:
                continue
            if int(rest[1]) == me:
                found[int(entry)] = rest[0]
    return found
def run_prog(ns, argv, seconds=30):
    """One program the way the lineage's own wrapper runs it; its exit code."""
    if WRAP == "preflight":
        return ns["preflight"](argv, seconds)[0]
    if WRAP == "wait_for":
        out, err = open(W + "/o.txt", "wb"), open(W + "/e.txt", "wb")
        proc = ns["spawn"](argv, stdout=out, stderr=err)
        return ns["wait_for"](proc, seconds)[0]
    return ns["run_to_files"](argv, W + "/o.txt", W + "/e.txt", seconds)[0]
def settled_size(path):
    return os.path.getsize(path)
`;

const LATE = HEAD + String.raw`
ns = load()
f = W + "/f.txt"
prog = "echo first > %s; (setsid sh -c 'echo $$ > %s/late.pid; sleep 1; echo late >> %s' </dev/null >/dev/null 2>&1 &); sleep 0.3; exit 0" % (f, W, f)
code = run_prog(ns, ["sh", "-c", prog])
size_at = settled_size(f)
late = pid_of("late.pid")
alive_at = alive(late)
verdict = ns["process_verdict"]()
time.sleep(float(os.environ.get("AFTER", "2.5")))
print(json.dumps({"code": code, "size_at": size_at, "size_after": settled_size(f), "late_alive_at_return": alive_at, "late_alive_after": alive(late), "verdict": verdict, "kids": children_of_me()}))
`;

const DOUBLE = HEAD + String.raw`
ns = load()
code = run_prog(ns, ["sh", "-c", "(sleep 90.101 & echo $! > %s/d.pid); exit 0" % W])
print(json.dumps({"code": code, "left": procs_with("sleep\0" + "90.101"), "verdict": ns["process_verdict"](), "kids": children_of_me()}))
`;

const CHAIN = HEAD + String.raw`
ns = load()
script = W + "/chain.sh"
open(script, "w").write("echo $$ > %s/b.pid\nsh -c 'echo $$ > %s/c.pid; sh -c \"echo \\$\\$ > %s/d.pid; exec sleep 90.102\" & wait' &\nsleep 0.4\nexit 0\n" % (W, W, W))
code = run_prog(ns, ["sh", script])
print(json.dumps({"code": code, "left": procs_with("sleep\0" + "90.102"), "b": alive(pid_of("b.pid")), "c": alive(pid_of("c.pid")), "d": alive(pid_of("d.pid")), "verdict": ns["process_verdict"](), "kids": children_of_me()}))
`;

const ORPHAN_KIDS = HEAD + String.raw`
ns = load()
script = W + "/orphan.sh"
open(script, "w").write("setsid sh -c 'sleep 90.103 & sleep 90.103 & sleep 90.103 & echo $$ > %s/o.pid; wait' </dev/null >/dev/null 2>&1 &\nsleep 0.5\nexit 0\n" % W)
code = run_prog(ns, ["sh", script])
print(json.dumps({"code": code, "left": procs_with("sleep\0" + "90.103"), "orphan": alive(pid_of("o.pid")), "verdict": ns["process_verdict"](), "kids": children_of_me()}))
`;

const PRE_EXISTING = HEAD + String.raw`
pre = subprocess.Popen(["sleep", "90.104"])        # a child the tool had before its first program
ns = load()
code = run_prog(ns, ["sh", "-c", "(setsid sleep 90.105 & echo $! > %s/o.pid); sleep 0.3; exit 0" % W])
out = {"code": code, "pre_alive": pre.poll() is None, "orphan": alive(pid_of("o.pid")), "verdict": ns["process_verdict"](), "pre_kids": len(ns["PRE_KIDS"])}
pre.kill(); pre.wait()
out["kids"] = children_of_me()
print(json.dumps(out))
`;

const SECOND_PROGRAM = HEAD + String.raw`
ns = load()
other = ns["spawn"](["sleep", "90.106"])
ns["ACTIVE"].append(other)
code = run_prog(ns, ["sh", "-c", "(setsid sleep 90.107 & echo $! > %s/o.pid); sleep 0.3; exit 0" % W])
mid = {"orphan": alive(pid_of("o.pid")), "other": other.poll() is None, "verdict": ns["process_verdict"]()}
other.kill(); other.wait()
ns["ACTIVE"].remove(other)                 # the second program has ended: what is left is the first one's, and is ended now
end = {"orphan": alive(pid_of("o.pid")), "verdict": ns["process_verdict"](), "returncode": other.returncode}
print(json.dumps({"code": code, "mid": mid, "end": end}))
`;

const RETURNCODE = HEAD + String.raw`
ns = load()
out = {}
for name, shell in (("seven", "(setsid sleep 90.108 &); exit 7"), ("killed", "(setsid sleep 90.109 &); kill -9 $$"), ("zero", "(setsid sleep 90.110 &); exit 0")):
    p = ns["spawn"](["sh", "-c", shell])
    ns["ACTIVE"].append(p)
    p.wait()
    ns["ACTIVE"].remove(p)
    out[name] = {"returncode": p.returncode, "again": p.wait(), "poll": p.poll()}
time.sleep(0.2)
out["left"] = [procs_with("sleep\0" + m) for m in ("90.108", "90.109", "90.110")]
out["verdict"] = ns["process_verdict"]()
print(json.dumps(out))
`;

const ZOMBIE = HEAD + String.raw`
ns = load()
code = run_prog(ns, ["sh", "-c", "/bin/true & sleep 0.3; exit 0"])
kids = children_of_me()
print(json.dumps({"code": code, "kids": kids, "started": sorted(ns["SPAWNED"]), "verdict": ns["process_verdict"]()}))
`;

const LEAVES = HEAD + String.raw`
ns = load()
p = ns["spawn"](["sh", "-c", "sleep 90.111 & echo $! > %s/daemon.pid; exit 0" % W], leaves=True)
ns["ACTIVE"].append(p)
p.wait()
ns["ACTIVE"].remove(p)
daemon = pid_of("daemon.pid")
first = {"alive": alive(daemon), "verdict": ns["process_verdict"]()}
code = run_prog(ns, ["sh", "-c", "(setsid sleep 90.112 & echo $! > %s/o.pid); sleep 0.3; exit 0" % W])
second = {"daemon": alive(daemon), "orphan": alive(pid_of("o.pid")), "verdict": ns["process_verdict"]()}
# process_keep: a pid named before its program has ended
q = ns["spawn"](["sh", "-c", "sleep 90.113 & echo $! > %s/kept.pid; sleep 1.2; exit 0" % W])
ns["ACTIVE"].append(q)
ns["process_keep"](pid_of("kept.pid"))
q.wait()
ns["ACTIVE"].remove(q)
third = {"kept": alive(pid_of("kept.pid")), "verdict": ns["process_verdict"]()}
for name in ("daemon.pid", "kept.pid"):
    try:
        os.kill(pid_of(name), signal.SIGKILL)
    except OSError:
        pass
print(json.dumps({"first": first, "second": second, "third": third}))
`;

const STORM = HEAD + String.raw`
ns = load()
if os.environ.get("LEFTOVER_SECONDS"):
    ns["LEFTOVER_SECONDS"] = float(os.environ["LEFTOVER_SECONDS"])
prog = "import os, signal, sys\nfor i in range(1500):\n    if os.fork() == 0:\n        os.setsid(); signal.alarm(60); signal.pause()\nsys.stdout.write('forked')\n"
t0 = time.monotonic()
code = run_prog(ns, ["python3", "-c", prog])
took = time.monotonic() - t0
rest = {pid: s for pid, s in children_of_me().items() if pid not in ns["SPAWNED"]}
live = [pid for pid, s in rest.items() if s != "Z"]
verdict = ns["process_verdict"]()
for pid in live:
    try:
        os.kill(pid, signal.SIGKILL)
    except OSError:
        pass
print(json.dumps({"code": code, "took": took, "live": len(live), "verdict": verdict}))
`;

const REFUSED = HEAD + String.raw`
import ctypes
ctypes.CDLL = lambda *a, **k: types.SimpleNamespace(prctl=lambda *x: -1)       # the kernel refuses
ns = load()
out = {}
# a program that leaves an orphan the tool never saw below it: not found
code = run_prog(ns, ["sh", "-c", "(setsid sleep 90.114 & echo $! > %s/unseen.pid); sleep 0.3; exit 0" % W])
out["unseen_alive"] = alive(pid_of("unseen.pid"))
out["verdict_unseen"] = ns["process_verdict"]()
out["subreaper"] = ns["SUB"]["on"]
# a program whose child was seen below it while it ran: ended after the program, by the walk's own record
p = ns["spawn"](["sh", "-c", "sleep 90.115 >/dev/null 2>&1 & echo $! > %s/seen.pid; sleep 1.2; exit 0" % W], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
ns["ACTIVE"].append(p)
ns["communicate_bounded"](p, 20)
ns["ACTIVE"].remove(p)
out["seen_alive"] = alive(pid_of("seen.pid"))
out["verdict_seen"] = ns["process_verdict"]()
answer = ns["process_apply"]({"status": "complete", "ok": True, "complete": True, "status_basis": "all of it"})
out["answer"] = answer
os.kill(pid_of("unseen.pid"), signal.SIGKILL)
print(json.dumps(out))
`;

const NONLINUX = HEAD + String.raw`
fsys = types.ModuleType("sys")
fsys.__dict__.update({k: v for k, v in sys.__dict__.items() if not k.startswith("__")})
fsys.platform = "darwin"
ns = load({"sys": fsys})
if os.environ.get("DOWNGRADE") == "0":
    ns["NONLINUX_UNPROVEN_DOWNGRADE"] = False
code = run_prog(ns, ["sh", "-c", "(setsid sleep 90.116 & echo $! > %s/unseen.pid); sleep 0.3; exit 0" % W])
verdict = ns["process_verdict"]()
answer = ns["process_apply"]({"status": "complete", "ok": True, "complete": True, "status_basis": "all of it"})
out = {"verdict": verdict, "answer": answer, "unseen_alive": alive(pid_of("unseen.pid")), "kids": children_of_me(), "process_notes": ns["process_notes"]()}
os.kill(pid_of("unseen.pid"), signal.SIGKILL)
print(json.dumps(out))
`;

const SIGTERM_IN_SETTLE = HEAD + String.raw`
ns = load()
ns["STATE"]["last_word"] = lambda signum: open(W + "/last_word", "w").write(str(signum))
ns["install_signal_handlers"]()
orig = ns["_end_children"]
def hooked(victims, deadline):
    os.kill(os.getpid(), signal.SIGTERM)        # the stop lands while settle is ending what the program left
    return orig(victims, deadline)
ns["_end_children"] = hooked
run_prog(ns, ["sh", "-c", "for n in 1 2 3; do (setsid sh -c 'echo $$ > %s/k'$n'.pid; exec sleep 90.117' </dev/null >/dev/null 2>&1 &); done; sleep 0.5; exit 0" % W])
print("not reached")
`;

const CLEAN_COST = HEAD + String.raw`
ns = load()
t0 = time.monotonic()
for _ in range(40):
    ns["preflight"](["true"], 10) if "preflight" in ns else ns["wait_for"](ns["spawn"](["true"]), 10)
per = (time.monotonic() - t0) / 40
print(json.dumps({"per_program": per, "verdict": ns["process_verdict"](), "kids": children_of_me(), "started": len(ns["SPAWNED"])}))
`;

const SHORTCUT = HEAD + String.raw`
ns = load()
procs = [ns["spawn"](["sleep", "90.118"]) for _ in range(3)]
ns["become_subreaper"]()
a = ns["_children_of_me"]()
real = os.listdir
def refuse(path):
    if "/task" in str(path):
        raise OSError("no children files")
    return real(path)
os.listdir = refuse
try:
    b = ns["_children_of_me"]()
finally:
    os.listdir = real
for p in procs:
    p.kill(); p.wait()
print(json.dumps({"same": sorted(a) == sorted(b) and all(a[k][1] == b[k][1] for k in a), "n": len(a), "pids": sorted(p.pid for p in procs), "listed": sorted(a)}))
`;

const APPLY = HEAD + String.raw`
ns = load()
apply = ns["process_apply"]
clean = apply({"status": "complete", "ok": True, "status_basis": "x"})
ns["LEFT"]["left_behind"] = 2
left = apply({"status": "complete", "ok": True, "complete": True, "status_basis": "x"})
other = apply({"status": "failed", "ok": False})
bare = apply({"status": "complete"})
ns["LEFT"]["left_behind"] = 0
ns["LEFT"]["unproven"].append("nobody can say")
unproven = apply({"status": "complete", "complete": True})
print(json.dumps({"clean": clean, "left": left, "other": other, "bare": bare, "unproven": unproven}))
`;

type Json = any; // eslint-disable-line @typescript-eslint/no-explicit-any

async function runCase(code: string, family: { script: string }, cwd: string, env: Record<string, string> = {}, leader = true): Promise<{ ran: Ran; seen: Json }> {
  const ran = await lead(code, [family.script, cwd], env, leader);
  let seen: Json = null;
  try { seen = JSON.parse(ran.stdout); } catch { /* the case says so below */ }
  return { ran, seen };
}

/** A process of the test's own in a group of its own: nothing the tool owns. */
function bystander(): number {
  const child = spawn("sleep", ["300"], { detached: true, stdio: "ignore" });
  child.unref();
  return child.pid as number;
}

async function withCase(
  family: { script: string },
  code: string,
  env: Record<string, string>,
  check: (seen: Json, ran: Ran, cwd: string, decoy: number) => Promise<void>,
  leader = true,
): Promise<void> {
  await withCwd(async (cwd) => {
    const decoy = bystander();
    let ran: Ran | undefined;
    try {
      const done = await runCase(code, family, cwd, env, leader);
      ran = done.ran;
      assert.equal(ran.code === 0 || ran.code === 143, true, `exit ${ran.code}: ${ran.stderr}`);
      await check(done.seen, ran, cwd, decoy);
      assert.equal(await gone(decoy, 200), false, "a process outside the tool was signalled");
    } finally {
      ran?.endGroup();
      for (const pid of [...(await recorded(cwd)), decoy]) end(pid);
    }
  });
}

for (const fam of FAMILIES) {
  for (const wrap of fam.wraps) {
    test(`${fam.family}/${wrap}: a late writer in a session of its own that holds no descriptor is ended before the file is measured, and the file stays as it was`, { skip: NO_ADOPTION }, async () => {
      await withCase(fam, LATE, { WRAP: wrap }, async (seen) => {
        assert.equal(seen.code, 0);
        assert.equal(seen.size_at, 6, "what the program wrote");
        assert.equal(seen.size_after, seen.size_at, "the file grew after the tool had measured it");
        assert.equal(seen.late_alive_at_return, false, "the late writer was still running when the call returned");
        assert.equal(seen.late_alive_after, false);
        assert.ok(seen.verdict.left_behind >= 1, JSON.stringify(seen.verdict));
        assert.equal(seen.verdict.subreaper, true);
        assert.deepEqual(seen.verdict.unproven, []);
        assert.deepEqual(seen.kids, {}, "a child of the tool is left (a zombie or a process)");
      });
    });
  }

  const wrap = fam.wraps[0]!;
  const table: [string, string, (seen: Json) => void][] = [
    ["a double fork (the program's child ended at once, its own child goes on)", DOUBLE, (s) => { assert.deepEqual(s.left, []); assert.equal(s.verdict.left_behind, 1); }],
    ["a chain of three below a program that has ended", CHAIN, (s) => { assert.deepEqual(s.left, []); assert.equal(s.b, false); assert.equal(s.c, false); assert.equal(s.d, false); assert.ok(s.verdict.left_behind >= 2, JSON.stringify(s.verdict)); }],
    ["an orphan and the three children it has", ORPHAN_KIDS, (s) => { assert.deepEqual(s.left, []); assert.equal(s.orphan, false); assert.ok(s.verdict.left_behind >= 4, JSON.stringify(s.verdict)); }],
    ["a child the tool had before its first program is left alone, the program's leftover is not", PRE_EXISTING, (s) => { assert.equal(s.pre_alive, true); assert.equal(s.orphan, false); assert.equal(s.verdict.left_behind, 1); assert.equal(s.pre_kids, 1); }],
    ["a zombie the program's exit leaves is reaped and is not counted as a process left running", ZOMBIE, (s) => { assert.deepEqual(s.kids, {}); assert.equal(s.verdict.left_behind, 0); assert.deepEqual(s.verdict.unproven, []); }],
  ];
  for (const [name, code, assertSeen] of table) {
    test(`${fam.family}: ${name}`, { skip: NO_ADOPTION }, async () => {
      await withCase(fam, code, { WRAP: wrap }, async (seen, ran) => {
        assert.ok(seen, `no answer: ${ran.stderr}`);
        assert.equal(seen.code ?? 0, 0);
        assertSeen(seen);
        assert.deepEqual(seen.kids, {}, "a child of the tool is left");
        assert.deepEqual(seen.verdict.unproven, []);
      });
    });
  }

  test(`${fam.family}: while a second program is running nothing is ended and the answer is unproven; when it ends, its own leftovers go`, { skip: NO_ADOPTION }, async () => {
    await withCase(fam, SECOND_PROGRAM, { WRAP: wrap }, async (seen) => {
      assert.equal(seen.mid.orphan, true, "a leftover was ended while another program was running: it cannot be told from that program's child");
      assert.equal(seen.mid.other, true, "the second program was ended");
      assert.equal(seen.mid.verdict.left_behind, 0);
      assert.match(seen.mid.verdict.unproven.join(" "), /another one ended|still running/);
      assert.equal(seen.end.orphan, false);
      assert.equal(seen.end.verdict.left_behind, 1);
      assert.ok(seen.end.verdict.unproven.length >= 1, "the unproven reason stays: the first look could not rule it out");
      assert.equal(seen.end.returncode, -9);
    });
  });

  test(`${fam.family}: Popen.returncode is what the program exited with, whatever settle did around it`, { skip: NO_ADOPTION }, async () => {
    await withCase(fam, RETURNCODE, {}, async (seen) => {
      assert.deepEqual([seen.seven.returncode, seen.seven.again, seen.seven.poll], [7, 7, 7]);
      assert.deepEqual([seen.killed.returncode, seen.killed.again, seen.killed.poll], [-9, -9, -9]);
      assert.deepEqual([seen.zero.returncode, seen.zero.again, seen.zero.poll], [0, 0, 0]);
      assert.deepEqual(seen.left, [[], [], []]);
      assert.equal(seen.verdict.left_behind, 3);
    });
  });

  test(`${fam.family}: a program started with leaves=True (or a pid process_keep names) keeps what it leaves; a later program's leftovers are still ended`, { skip: NO_ADOPTION }, async () => {
    await withCase(fam, LEAVES, { WRAP: wrap }, async (seen) => {
      assert.equal(seen.first.alive, true, "the daemon the program left on purpose was ended");
      assert.equal(seen.first.verdict.left_behind, 0);
      assert.deepEqual(seen.first.verdict.unproven, []);
      assert.equal(seen.second.daemon, true, "the kept daemon was ended by a later program's settle");
      assert.equal(seen.second.orphan, false);
      assert.equal(seen.second.verdict.left_behind, 1);
      assert.equal(seen.third.kept, true, "process_keep did not keep the process");
      assert.equal(seen.third.verdict.left_behind, 1, "process_keep: the kept process was counted as left behind");
    });
  });

  test(`${fam.family}: a program that leaves 1500 processes in sessions of its own is cleared within the bound, with every one counted`, { skip: NO_ADOPTION }, async () => {
    await withCase(fam, STORM, { WRAP: wrap }, async (seen) => {
      assert.equal(seen.code, 0);
      assert.ok(seen.took < 3 + 4, `took ${seen.took} s`);
      assert.equal(seen.live, 0, "processes the program left are still running");
      assert.equal(seen.verdict.left_behind, 1500);
      assert.deepEqual(seen.verdict.unproven, []);
    });
  });

  test(`${fam.family}: the clock is read for every process: with a bound of 0.05 s a storm is cut at it and the answer says some are still running`, { skip: NO_ADOPTION }, async () => {
    await withCase(fam, STORM, { WRAP: wrap, LEFTOVER_SECONDS: "0.05" }, async (seen) => {
      assert.equal(seen.code, 0);
      assert.ok(seen.took < 3, `took ${seen.took} s: the bound did not hold`);
      assert.ok(seen.live > 0 || seen.verdict.left_behind === 1500, JSON.stringify(seen.verdict));
      if (seen.live > 0) assert.match(seen.verdict.unproven.join(" "), /still running|not all ended|more processes/);
    });
  });

  test(`${fam.family}: where the kernel refuses the subreaper nothing is adopted: what the tool saw below the program is ended, what it did not is left and unproven, and a complete answer becomes partial`, { skip: NO_ADOPTION }, async () => {
    await withCase(fam, REFUSED, { WRAP: wrap }, async (seen) => {
      assert.equal(seen.subreaper, false);
      assert.equal(seen.unseen_alive, true, "what the tool never saw cannot be found without the subreaper");
      assert.match(seen.verdict_unseen.unproven.join(" "), /refused PR_SET_CHILD_SUBREAPER/);
      assert.equal(seen.seen_alive, false, "a child seen below the program was left after the program ended");
      assert.equal(seen.verdict_seen.left_behind, 1);
      assert.equal(seen.answer.status, "partial");
      assert.deepEqual([seen.answer.ok, seen.answer.complete], [false, false]);
      assert.match(seen.answer.status_basis, /^all of it; a program left 1 process running/);
      assert.deepEqual(seen.answer.program_group.subreaper, false);
    });
  });

  test(`${fam.family}: on a host that is not Linux the same, and the one constant NONLINUX_UNPROVEN_DOWNGRADE decides whether that alone makes an answer partial`, { skip: NO_ADOPTION }, async () => {
    await withCase(fam, NONLINUX, { WRAP: wrap }, async (seen) => {
      assert.equal(seen.verdict.subreaper, false);
      assert.match(seen.verdict.unproven.join(" "), /cannot adopt orphaned processes/);
      assert.deepEqual(seen.process_notes, [], "the sentence is in the verdict only: a tool that reads process_notes() is not made partial by it");
      assert.equal(seen.answer.status, "partial");
      assert.equal(seen.unseen_alive, true);
    });
    await withCase(fam, NONLINUX, { WRAP: wrap, DOWNGRADE: "0" }, async (seen) => {
      assert.deepEqual(seen.verdict.unproven, []);
      assert.match(seen.verdict.notes.join(" "), /cannot adopt orphaned processes/);
      assert.equal(seen.answer.status, "complete");
      assert.equal(seen.answer.ok, true);
      assert.equal(seen.answer.program_group.subreaper, false);
    });
  });

  test(`${fam.family}: SIGTERM while settle is ending a program's leftovers ends them, gives the last word, and touches nothing else`, { skip: NO_ADOPTION }, async () => {
    await withCwd(async (cwd) => {
      const decoy = bystander();
      let ran: Ran | undefined;
      try {
        ran = await lead(SIGTERM_IN_SETTLE, [fam.script, cwd], { WRAP: wrap });
        assert.equal(ran.code, 143, ran.stderr + ran.stdout);
        assert.equal(await readFile(join(cwd, "last_word"), "utf8"), "15");
        for (const name of ["k1.pid", "k2.pid", "k3.pid"]) {
          const pid = Number((await readFile(join(cwd, name), "utf8")).trim());
          assert.equal(await gone(pid, 5000), true, `${name} survived the stop`);
        }
        assert.equal(await gone(decoy, 200), false, "a process beside the tool was ended");
      } finally {
        ran?.endGroup();
        for (const pid of [...(await recorded(cwd)), decoy]) end(pid);
      }
    });
  });

  test(`${fam.family}: the tool does not need to lead its group, and does not end the processes beside it`, { skip: NO_ADOPTION }, async () => {
    await withCwd(async (cwd) => {
      const sibling = spawn("sleep", ["300"], { stdio: "ignore" });      // in this test's group, which the tool shares
      let ran: Ran | undefined;
      try {
        const done = await runCase(LATE, fam, cwd, { WRAP: wrap, AFTER: "1.5" }, false);
        ran = done.ran;
        assert.equal(ran.code, 0, ran.stderr);
        assert.equal(done.seen.late_alive_at_return, false);
        assert.equal(done.seen.size_after, done.seen.size_at);
        assert.ok(done.seen.verdict.left_behind >= 1);
        assert.equal(await gone(sibling.pid as number, 200), false, "a process in the tool's group, not its own, was ended");
        assert.equal(await gone(process.pid, 0), false, "the test process was ended");
      } finally {
        for (const pid of [...(await recorded(cwd)), sibling.pid as number]) end(pid);
      }
    });
  });

  test(`${fam.family}: two tools running at once do not end each other's programs or leftovers`, { skip: NO_ADOPTION }, async () => {
    await withCwd(async (a) => {
      await withCwd(async (b) => {
        const slow = HEAD + String.raw`
ns = load()
code = run_prog(ns, ["sh", "-c", "(setsid sh -c 'echo $$ > %s/late.pid; exec sleep 90.119' </dev/null >/dev/null 2>&1 &); sleep 3; kill -0 $(cat %s/late.pid) && echo yes > %s/alive_at_end; echo done > %s/done; exit 0" % (W, W, W, W)])
print(json.dumps({"code": code, "done": os.path.exists(W + "/done"), "alive_at_end": os.path.exists(W + "/alive_at_end"), "late": alive(pid_of("late.pid")), "verdict": ns["process_verdict"]()}))
`;
        try {
          const [one, two] = await Promise.all([
            runCase(LATE, fam, a, { WRAP: wrap, AFTER: "0.2" }),
            runCase(slow, fam, b, { WRAP: wrap }),
          ]);
          assert.equal(one.ran.code, 0, one.ran.stderr);
          assert.equal(two.ran.code, 0, two.ran.stderr);
          assert.equal(one.seen.late_alive_after, false);
          assert.equal(two.seen.done, true, "the other tool's program was ended before it finished");
          assert.equal(two.seen.code, 0);
          assert.equal(two.seen.alive_at_end, true, "the other tool ended this tool's leftover while this tool's program was still running");
          assert.equal(two.seen.late, false, "this tool's own leftover was not ended when its program had");
          assert.equal(two.seen.verdict.left_behind, 1);
        } finally {
          for (const dir of [a, b]) for (const pid of await recorded(dir)) end(pid);
        }
      });
    });
  });

  test(`${fam.family}: a clean run is untouched: nothing left, nothing unproven, no child of the tool but the programs it started, and settle adds little to a program`, { skip: NO_ADOPTION }, async () => {
    await withCase(fam, CLEAN_COST, {}, async (seen) => {
      assert.equal(seen.verdict.left_behind, 0);
      assert.deepEqual(seen.verdict.unproven, []);
      assert.deepEqual(seen.verdict.notes, []);
      assert.equal(seen.verdict.subreaper, true);
      assert.ok(seen.per_program < 0.25, `${seen.per_program} s a program`);
    });
  });

  test(`${fam.family}: the children of the tool are the same from the kernel's own list as from a scan of /proc`, { skip: NO_ADOPTION }, async () => {
    await withCase(fam, SHORTCUT, {}, async (seen) => {
      assert.equal(seen.same, true, JSON.stringify(seen));
      assert.deepEqual(seen.listed, seen.pids);
    });
  });

  test(`${fam.family}: process_apply attaches program_group, and turns complete into partial only when something was left or cannot be ruled out`, { skip: NO_ADOPTION }, async () => {
    await withCase(fam, APPLY, {}, async (seen) => {
      assert.equal(seen.clean.status, "complete");
      assert.equal(seen.clean.status_basis, "x");
      assert.deepEqual(Object.keys(seen.clean.program_group).sort(), ["left_behind", "notes", "subreaper", "unproven"]);
      assert.equal(seen.left.status, "partial");
      assert.deepEqual([seen.left.ok, seen.left.complete], [false, false]);
      assert.match(seen.left.status_basis, /^x; a program left 2 processes running after it ended/);
      assert.equal(seen.other.status, "failed");
      assert.equal(seen.other.ok, false);
      assert.equal(seen.bare.status, "partial");
      assert.equal("ok" in seen.bare, false);
      assert.match(seen.bare.status_basis, /^a program left 2 processes/);
      assert.equal(seen.unproven.status, "partial");
      assert.equal(seen.unproven.complete, false);
      assert.match(seen.unproven.status_basis, /cannot prove that no program left a process behind/);
    });
  });
}

// --- the two texts -------------------------------------------------------------------------------------------------

async function blockOf(path: string): Promise<string> {
  const text = await readFile(path, "utf8");
  const start = text.indexOf(BEGIN);
  const stop = text.indexOf(END);
  assert.ok(start >= 0 && stop > start);
  return text.slice(start, stop + END.length);
}

test("both texts carry the same settle API, one definition of each, and the one policy constant is a line of its own", async () => {
  const names = ["become_subreaper", "process_keep", "settle", "process_verdict", "process_apply", "spawn", "communicate_bounded", "kill_all", "_stop_under", "_end_children"];
  const texts = await Promise.all(FAMILIES.map((f) => blockOf(f.script)));
  for (const text of texts) {
    for (const name of names) assert.equal(text.match(new RegExp(`^def ${name}\\(`, "gm"))?.length, 1, name);
    assert.equal(text.match(/^NONLINUX_UNPROVEN_DOWNGRADE = True$/gm)?.length, 1);
    assert.match(text, /^def spawn\(argv, leaves=False, \*\*kwargs\):$/m);
    assert.match(text, /^class _Active\(list\):$/m);
  }
  // everything the new part adds is one text in both: the section from the first helper to the pipe grace
  const section = (t: string): string => t.slice(t.indexOf("def _stat_row("), t.indexOf("PIPE_GRACE = 1.0"));
  assert.equal(section(texts[0]!), section(texts[1]!));
  assert.ok(section(texts[0]!).length > 8000);
});

test("the block text uses none of what a reverse-engineering file must not: no group or session of its own, no thread, no os.spawn/popen/system/exec", async () => {
  for (const fam of FAMILIES) {
    const text = (await blockOf(fam.script)).replace(/^\s*#.*$/gm, "").replace(/"""[\s\S]*?"""/g, "");
    assert.doesNotMatch(text, /start_new_session|setsid|setpgrp|setpgid|preexec_fn=os\.setsid|process_group|os\.killpg|os\.spawn|os\.popen|os\.system|os\.exec|pty\.|multiprocessing/);
    assert.doesNotMatch(text, /import threading/);
  }
  // the whole block, comments included, does not name them either
  for (const fam of FAMILIES) assert.doesNotMatch(await blockOf(fam.script), /setsid|setpgrp|setpgid|killpg|multiprocessing|import threading/);
});

// --- the audit's repros, end to end -------------------------------------------------------------------------------------

const sha256 = (buf: Buffer): string => createHash("sha256").update(buf).digest("hex");

for (const [label, script] of [
  ["the windows pack's tool", join(ROOT, "packs", "windows-forensics", "tools", "extract_stream", "run.py")],
  ["its tool-library twin", join(ROOT, "tool-library", "extract_stream", "run.py")],
] as const) {
  test(`repro 2 (${label}): extract_stream with an icat that leaves a late writer for its output file answers over a file that no longer changes`, { skip: NO_ADOPTION }, async () => {
    await withCwd(async (cwd, bin) => {
      const output = join(cwd, "work", "s1", "stream.bin");
      await put(cwd, "pids/.keep", "");
      await stub(bin, "icat", `echo $$ > "${cwd}/pids/icat.pid"
printf 'first-bytes\\n'
(setsid sh -c 'echo $$ > "${cwd}/pids/late.pid"; sleep 1.5; echo late-bytes >> "${output}"' </dev/null >/dev/null 2>&1 &)
sleep 0.3
exit 0`);
      await writeFile(join(cwd, "work", "input.bin"), "stand-in input\n");
      try {
        const run = await runPy(script, cwd, { image: "work/input.bin", inode: "5-128-1", offset: 0, output: "work/s1/stream.bin" }, bin, { AGENT_ID: "s1" });
        assert.equal(run.code, 0, run.stderr + run.stdout);
        const answer = JSON.parse(run.stdout);
        const at = await readFile(output);
        assert.equal(at.length, "first-bytes\n".length, "what icat wrote");
        assert.equal(answer.size, at.length);
        assert.equal(answer.sha256, sha256(at));
        const late = Number((await readFile(join(cwd, "pids", "late.pid"), "utf8")).trim());
        assert.equal(await gone(late, 3000), true, "the late writer was left running");
        await new Promise((r) => setTimeout(r, 2500));
        const later = await readFile(output);
        assert.equal(later.length, at.length, "the file the answer measured grew afterwards");
        assert.equal(sha256(later), answer.sha256);
      } finally {
        for (const pid of await recorded(join(cwd, "pids"))) end(pid);
      }
    });
  });
}

test("repro 3: fuzzy_hash with an ssdeep that leaves a late writer for its own log by name, holding no descriptor, answers over a log that no longer grows", { skip: NO_ADOPTION }, async () => {
  const FUZZY = join(ROOT, "packs", "reverse-engineering", "tools", "fuzzy_hash", "run.py");
  const TLSH = "T1" + "A1B2C3D4E5".repeat(7);
  const SSDEEP = "96:aBcDeF0123456789+/aBcDeF0123456789+/:XyZ0123456789+/";
  await withCwd(async (cwd, bin) => {
    await put(cwd, "pids/.keep", "");
    await stub(bin, "ssdeep", `if [ "$1" = "-V" ]; then echo "2.14.1"; exit 0; fi
LOG=$(readlink /proc/$$/fd/1 2>/dev/null || lsof -a -p $$ -d 1 -Fn 2>/dev/null | sed -n 's/^n//p')
echo 'ssdeep,1.1--blocksize:hash:hash,filename'
echo "${SSDEEP},\\"$(basename "$3")\\""
(setsid sh -c 'echo $$ > "${cwd}/pids/late.pid"; sleep 1.5; echo late >> "'"$LOG"'"' </dev/null >/dev/null 2>&1 &)
sleep 0.3
exit 0`);
    await stub(bin, "tlsh", `if [ "$1" = "-version" ]; then echo "tlsh 4.12.0"; exit 0; fi
printf '${TLSH}\\t%s\\n' "$2"`);
    await put(cwd, "work/s.bin", Buffer.from("x".repeat(5000)));
    try {
      const run = await runPy(FUZZY, cwd, { path: "work/s.bin" }, bin, { AGENT_ID: "s1" });
      assert.equal(run.code, 0, run.stderr + run.stdout);
      const answer = JSON.parse(run.stdout);
      const log = join(cwd, "work", "s1", "tool-output", answer.logs.stdout);
      const at = (await stat(log)).size;
      const late = Number((await readFile(join(cwd, "pids", "late.pid"), "utf8")).trim());
      assert.equal(await gone(late, 3000), true, "the late writer was left running");
      await new Promise((r) => setTimeout(r, 2500));
      assert.equal((await stat(log)).size, at, "the log the answer names grew after the answer");
    } finally {
      for (const pid of await recorded(join(cwd, "pids"))) end(pid);
    }
  });
});
