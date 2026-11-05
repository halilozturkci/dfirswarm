/**
 * PKG-P1 (the macOS pilot of the process sweep). The shared PROCESS block ends what a program leaves behind (settle()); the macOS carriers call process_apply, so
 * that a program that exits 0 and leaves a writer behind, or a host where the absence of one cannot be proven, never answers `complete` over a file the program
 * wrote. Stand-ins only, with real abandoned children (a plain child that holds the descriptor, setsid, a double fork, a child with no pipe descriptors, a periodic
 * writer, a late writer):
 *   - keychain_open: a child of the reader holds the items file's descriptor and writes to it after the reader exited 0 and the summary was read. The answer is
 *     `partial` (outcome opened), says what was ended, and the items file's size and sha256 in the answer are the file's now and 4.5 seconds later.
 *   - apfs_inventory: a child of fsapfsinfo holds the kept stdout file open (opened through the tool's own descriptor) and writes after the exit. Same.
 *   - a clean run is still `complete`, with program_group.left_behind 0 and no unproven reason.
 *   - where the absence cannot be proven (the host is not Linux, or the kernel refuses PR_SET_CHILD_SUBREAPER: the tool is run with sys.platform patched, or with
 *     ctypes.CDLL replaced by a library whose prctl fails), a clean run that writes a file is at most `partial` and says why, for keychain_open, apfs_inventory,
 *     macos_triage and the macos-artefacts recipe.
 * The cases that fail on the batch head (before the carriers called process_apply) are the abandoned-child ones: the answer was `complete` and the file's hash stale.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { chmod, mkdir, readFile, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { withCwd } from "./tool-library-harness.ts";
import { MAC, PYTHON } from "./macos-pack-harness.ts";
import type { Json } from "./macos-pack-harness.ts";
import { APFS, FSAPFS_OK, fsapfsStub } from "./macos-late-harness.ts";

const KEYCHAIN = join(MAC, "keychain_open", "run.py");
const TRIAGE = join(MAC, "macos_triage", "run.py");
const RECIPE = join(MAC, "..", "recipes", "macos-artefacts", "run.py");
const sha = (data: Buffer): string => createHash("sha256").update(data).digest("hex");
const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));
const alive = (pid: number): boolean => {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
};
const pidsOf = async (file: string): Promise<number[]> => (await readFile(file, "utf8").catch(() => "")).split(/\s+/).filter(Boolean).map(Number);
async function reap(file: string): Promise<void> {
  for (const pid of await pidsOf(file)) if (alive(pid)) process.kill(pid, "SIGKILL");
}

// The tool runs the way the harness starts one: as the leader of a process group of its own. `wrapper` is Python that runs before the tool, for the cases where the host is not Linux.
const DARWIN = `
import sys, os, subprocess, selectors, ctypes, json, re, time, hashlib, shutil, signal, stat, errno, functools, runpy
script = sys.argv[1]
sys.argv = sys.argv[1:]
sys.platform = "darwin"
runpy.run_path(script, run_name="__main__")
`;
const REFUSED = `
import sys, os, subprocess, selectors, ctypes, json, re, time, hashlib, shutil, signal, stat, errno, functools, runpy
script = sys.argv[1]
sys.argv = sys.argv[1:]
class Refusing(object):
    def prctl(self, *a):
        return -1
ctypes.CDLL = lambda *a, **k: Refusing()
runpy.run_path(script, run_name="__main__")
`;
type Run = { code: number | null; stdout: string; stderr: string };
function exec(argv: string[], cwd: string, env: Record<string, string>, stdin: string, wrapper?: string): Promise<Run> {
  return new Promise((resolve, reject) => {
    const args = wrapper ? ["-c", wrapper, ...argv.slice(1)] : argv.slice(1);
    const child = spawn(PYTHON, args, { cwd, env: { ...process.env, AGENT_ID: "s1", ...env }, detached: true });
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => out.push(c));
    child.stderr.on("data", (c: Buffer) => err.push(c));
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stdout: Buffer.concat(out).toString("utf8"), stderr: Buffer.concat(err).toString("utf8") }));
    child.stdin.on("error", () => undefined);
    child.stdin.end(stdin);
  });
}

type Host = "linux" | "darwin" | "refused";
const WRAPPERS: Record<Host, string | undefined> = { linux: undefined, darwin: DARWIN, refused: REFUSED };

// ---- the leftover: one Python function, used by both stand-ins ---------------------------------------------------------------------------------

/** Python that forks a child which holds `target` open (a path or a function that finds it) and writes to it `delay` seconds later, the way `variant` says. */
const LEAVE = String.raw`
def leave(variant, delay, pidfile, find):
    target_fd = find()
    if os.fork() != 0:
        return
    if variant == "double":
        if os.fork() != 0:
            os._exit(0)
    if variant in ("setsid", "double", "periodic"):
        os.setsid()
    open(pidfile, "a").write("%d\n" % os.getpid())
    if variant != "inherit":
        keep = (target_fd,)
        for fd in range(0, 256):
            if fd not in keep:
                try:
                    os.close(fd)
                except OSError:
                    pass
    if variant == "periodic":
        while True:
            time.sleep(0.2)
            os.write(target_fd, b'{"late": true}\n')
    time.sleep(delay)
    os.write(target_fd, b'{"late": true}\n')
    os._exit(0)
`;

const VARIANTS = ["inherit", "setsid", "double", "nopipes", "periodic"];

// ---- keychain_open ------------------------------------------------------------------------------------------------------------------------------

const READER = String.raw`
import json, os, sys, time
${LEAVE}
LOCKED = '[Invalid Password / Keychain Locked]'


class Rec(object):
    def __init__(self, spec):
        self.Created, self.LastModified = '20200101000000Z', '20200102000000Z'
        self.Account, self.Service, self.PrintName = spec.get('account'), spec.get('service'), spec.get('label')
        self.SSGP, self.DBKey, self.IV, self.Key = object(), b'k', b'iv', b'key'
        self.locked = False
        self.password = spec.get('password')
        self.password_b64_encoded = False


def items_fd():
    for fd in os.listdir('/proc/self/fd'):
        try:
            if 'keychain-items' in os.readlink('/proc/self/fd/' + fd):
                return int(fd)
        except OSError:
            pass
    raise SystemExit('no items file descriptor')


class Chainbreaker(object):
    KEYCHAIN_LOCKED_SIGNATURE = LOCKED

    def __init__(self, filepath, unlock_password=None, unlock_key=None, unlock_file=None):
        self.spec = json.loads(open(filepath, 'rb').read()[4:].decode('utf-8') or '{}')
        self.locked = unlock_password != self.spec.get('password')

    def dump_generic_passwords(self):
        leave_spec = self.spec.get('leave')
        if leave_spec:
            leave(leave_spec['variant'], leave_spec['delay'], leave_spec['pids'], items_fd)
        return [Rec(s) for s in self.spec.get('items', [])]

    def dump_internet_passwords(self):
        return []

    def dump_appleshare_passwords(self):
        return []

    def dump_x509_certificates(self):
        return []

    def dump_public_keys(self):
        return []

    def dump_private_keys(self):
        return []
`;

async function reader(cwd: string): Promise<string> {
  const dir = join(cwd, "reader");
  const mod = join(dir, "mod");
  await mkdir(join(mod, "chainbreaker"), { recursive: true });
  await mkdir(join(dir, "bin"), { recursive: true });
  await writeFile(join(mod, "chainbreaker", "__init__.py"), READER, "utf8");
  await writeFile(join(mod, "chainbreaker", "__main__.py"), "", "utf8");
  const launcher = join(dir, "bin", "chainbreaker");
  await writeFile(launcher, `#!/bin/sh\nexport PYTHONPATH="${mod}\${PYTHONPATH:+:$PYTHONPATH}"\nexec "${PYTHON}" "${join(mod, "chainbreaker", "__main__.py")}" "$@"\n`, "utf8");
  await chmod(launcher, 0o755);
  return `${join(dir, "bin")}:${process.env.PATH}`;
}

async function keychainRun(cwd: string, leave: { variant: string; delay: number } | null, host: Host = "linux"): Promise<{ answer: Json; pids: string }> {
  const pids = join(cwd, "pids.txt");
  const spec = { password: "pw", items: [{ account: "a1", service: "s1", label: "l1", password: "v1" }, { account: "a2", service: "s2", label: "l2", password: "v2" }], ...(leave ? { leave: { ...leave, pids } } : {}) };
  const kc = join(cwd, "work", "login.keychain-db");
  await writeFile(kc, Buffer.concat([Buffer.from("kych"), Buffer.from(JSON.stringify(spec).padEnd(256))]));
  const pw = join(cwd, "work", "pw.txt");
  await writeFile(pw, "pw\n");
  await chmod(pw, 0o600);
  await mkdir(join(cwd, "out"), { recursive: true });
  const env = { PATH: await reader(cwd), JOB_ID: "j-1", OUT: join(cwd, "out"), SECRET_OUTPUT: "1" };
  const r = await exec([PYTHON, KEYCHAIN], cwd, env, JSON.stringify({ path: kc, password_file: pw }), WRAPPERS[host]);
  assert.doesNotMatch(r.stderr, /Traceback/, r.stderr);
  return { answer: JSON.parse(r.stdout) as Json, pids };
}

for (const variant of VARIANTS) {
  test(`keychain_open: a child of the reader (${variant}) that holds the items file and writes after the reader exited 0 is ended: partial, and the file is the file the answer describes`, { skip: process.platform !== "linux" }, async () => {
    await withCwd(async (cwd) => {
      const { answer: a, pids } = await keychainRun(cwd, { variant, delay: variant === "periodic" ? 0 : 3 });
      try {
        assert.equal(a.outcome, "opened", JSON.stringify(a));
        assert.equal(a.status, "partial", a.status_basis);
        assert.ok(a.program_group.left_behind >= 1, JSON.stringify(a.program_group));
        assert.match(a.status_basis, /left a process running after it ended/);
        assert.match(a.problems.join(" "), /left \d+ process\(es\) running after it ended/);
        const file = join(cwd, "out", "keychain-items.jsonl");
        const now = await readFile(file);
        assert.equal(a.items_file.bytes, now.length);
        assert.equal(a.items_file.sha256, sha(now));
        await sleep(4500);
        const later = await readFile(file);
        assert.equal(later.length, now.length, "the file did not grow after the answer");
        assert.equal(sha(later), a.items_file.sha256);
        for (const pid of await pidsOf(pids)) assert.equal(alive(pid), false, `pid ${pid} was left running`);
      } finally {
        await reap(pids);
      }
    });
  });
}

test("keychain_open: a clean reader is complete, nothing was left behind, and the answer says so", { skip: process.platform !== "linux" }, async () => {
  await withCwd(async (cwd) => {
    const { answer: a } = await keychainRun(cwd, null);
    assert.equal(a.status, "complete", a.status_basis + JSON.stringify(a.problems));
    assert.equal(a.program_group.left_behind, 0);
    assert.deepEqual(a.program_group.unproven, []);
    assert.equal(a.program_group.subreaper, true);
  });
});

for (const host of ["darwin", "refused"] as Host[]) {
  test(`keychain_open: where nothing is adopted (${host}) a clean reader that wrote the items file is at most partial, and the answer says why`, { skip: process.platform !== "linux" }, async () => {
    await withCwd(async (cwd) => {
      const { answer: a } = await keychainRun(cwd, null, host);
      assert.equal(a.outcome, "opened");
      assert.equal(a.status, "partial", a.status_basis);
      assert.ok(a.program_group.unproven.length >= 1, JSON.stringify(a.program_group));
      assert.equal(a.program_group.subreaper, false);
      assert.match(a.problems.join(" "), /cannot be shown to be final/);
      assert.equal(a.items_file.bytes, (await stat(join(cwd, "out", "keychain-items.jsonl"))).size);
    });
  });
}

// ---- apfs_inventory -----------------------------------------------------------------------------------------------------------------------------

/** fsapfsinfo's stand-in: prints a good container and leaves a child that holds the tool's stdout capture file (opened through the tool's own descriptor). */
const apfsScript = (variant: string, delay: number, pids: string): string => `
${LEAVE}
def capture():
    ppid = os.getppid()
    for fd in os.listdir("/proc/%d/fd" % ppid):
        try:
            link = os.readlink("/proc/%d/fd/%s" % (ppid, fd))
        except OSError:
            continue
        if "/.apfs-" in link and "-stdout-" in link:
            return os.open("/proc/%d/fd/%s" % (ppid, fd), os.O_WRONLY | os.O_APPEND)
    raise SystemExit("no capture file")
leave(${JSON.stringify(variant)}, ${delay}, ${JSON.stringify(pids)}, capture)
${FSAPFS_OK}
`;

async function apfsRun(cwd: string, bin: string, leave: { variant: string; delay: number } | null, host: Host = "linux"): Promise<{ answer: Json; pids: string }> {
  const pids = join(cwd, "pids.txt");
  await fsapfsStub(bin, leave ? apfsScript(leave.variant, leave.delay, pids) : FSAPFS_OK);
  await writeFile(join(cwd, "work", "c.img"), Buffer.alloc(8192));
  const r = await exec([PYTHON, APFS], cwd, { PATH: `${bin}:${process.env.PATH ?? ""}`, JOB_ID: "j-1", OUT: join(cwd, "out") }, JSON.stringify({ path: "work/c.img" }), WRAPPERS[host]);
  assert.doesNotMatch(r.stderr, /Traceback/, r.stderr);
  return { answer: JSON.parse(r.stdout) as Json, pids };
}
const kept = (cwd: string, shown: string): string => join(cwd, "out", shown.replace(/^store\/jobs\/[^/]+\/out\//, ""));

for (const variant of VARIANTS) {
  test(`apfs_inventory: a child of fsapfsinfo (${variant}) that holds the kept stdout file and writes after the exit is ended: partial, and the file keeps the size the answer counted`, { skip: process.platform !== "linux" }, async () => {
    await withCwd(async (cwd, bin) => {
      await mkdir(join(cwd, "out"), { recursive: true });
      const { answer: a, pids } = await apfsRun(cwd, bin, { variant, delay: variant === "periodic" ? 0 : 3 });
      try {
        assert.equal(a.status, "partial", a.status_basis + JSON.stringify(a.problems));
        assert.ok(a.program_group.left_behind >= 1, JSON.stringify(a.program_group));
        assert.match(a.problems.join(" "), /left \d+ process\(es\) running after it ended/);
        const file = kept(cwd, a.stdout_file);
        const now = (await stat(file)).size;
        assert.equal(now, a.stdout_bytes, "the kept file is what was counted");
        await sleep(4500);
        assert.equal((await stat(file)).size, now, "the file did not grow after the answer");
        for (const pid of await pidsOf(pids)) assert.equal(alive(pid), false, `pid ${pid} was left running`);
      } finally {
        await reap(pids);
      }
    });
  });
}

test("apfs_inventory: a clean run is complete, nothing was left behind, and the answer says so", { skip: process.platform !== "linux" }, async () => {
  await withCwd(async (cwd, bin) => {
    await mkdir(join(cwd, "out"), { recursive: true });
    const { answer: a } = await apfsRun(cwd, bin, null);
    assert.equal(a.status, "complete", a.status_basis + JSON.stringify(a.problems));
    assert.equal(a.program_group.left_behind, 0);
    assert.deepEqual(a.program_group.unproven, []);
  });
});

for (const host of ["darwin", "refused"] as Host[]) {
  test(`apfs_inventory: where nothing is adopted (${host}) a clean run that kept its output is at most partial, and the answer says why`, { skip: process.platform !== "linux" }, async () => {
    await withCwd(async (cwd, bin) => {
      await mkdir(join(cwd, "out"), { recursive: true });
      const { answer: a } = await apfsRun(cwd, bin, null, host);
      assert.equal(a.status, "partial", a.status_basis);
      assert.ok(a.program_group.unproven.length >= 1, JSON.stringify(a.program_group));
      assert.match(a.problems.join(" "), /cannot be shown to be final/);
    });
  });
}

// ---- macos_triage and the recipe: the same rule where nothing is adopted ----------------------------------------------------------------

const MAC_APT = String.raw`
import os, sys, time
argv = sys.argv[1:]
if argv == ["-h"]:
    print("macOS Artifact Parsing Tool, version 1.33.2")
    sys.exit(0)
out = argv[argv.index("-o") + 1]
os.makedirs(out, exist_ok=True)
LOG = os.path.join(out, "Log.20261104-120000.txt")
def log(line, level="INFO"):
    with open(LOG, "a") as f:
        f.write("2026-11-04 12:00:00,000|MAIN|%s|%s\n" % (level, line))
log("Started macOS Artifact Parsing Tool, version 1.33.2")
log("Running plugin TCC")
log("TCC plugin ran for 00:00:01")
log("Finished in time = 00:00:02")
log("Review the Log file and report any ERRORs or EXCEPTIONS to the developers")
open(os.path.join(out, "mac_apt.db"), "wb").write(b"x" * 100)
`;
async function macApt(bin: string, cwd: string): Promise<string> {
  await mkdir(bin, { recursive: true });
  const file = join(bin, "mac_apt.py");
  await writeFile(file, `#!/usr/bin/env python3\n${MAC_APT}\n`);
  await chmod(file, 0o755);
  await writeFile(join(cwd, "work", "mac.E01"), Buffer.concat([Buffer.from([0x45, 0x56, 0x46, 0x09, 0x0d, 0x0a, 0xff, 0x00]), Buffer.alloc(4096)]));
  return "work/mac.E01";
}

test("macos_triage and the macos-artefacts recipe: a clean mac_apt is complete where orphans are adopted, and at most partial (with the reason) where they are not", { skip: process.platform !== "linux" }, async () => {
  await withCwd(async (cwd, bin) => {
    const path = await macApt(bin, cwd);
    const PATH = `${bin}:${process.env.PATH ?? ""}`;
    const results: Record<string, [string, string[], boolean]> = {};
    for (const host of ["linux", "darwin", "refused"] as Host[]) {
      await mkdir(join(cwd, `out-${host}`), { recursive: true });
      const t = await exec([PYTHON, TRIAGE], cwd, { PATH, JOB_ID: "j-1", OUT: join(cwd, `out-${host}`), SECRET_OUTPUT: "1" }, JSON.stringify({ path, input_type: "E01", plugins: ["TCC"] }), WRAPPERS[host]);
      const a = JSON.parse(t.stdout) as Json;
      results[`triage ${host}`] = [a.status, a.program_group.unproven, a.program_group.left_behind === 0];
      if (host === "linux") assert.match(a.status_basis, /settle\(\) found none/);
      else assert.match(a.status_basis, /cannot be shown to be final/, `triage ${host}: ${a.status_basis}`);
      await exec([PYTHON, RECIPE, "run", "--target", JSON.stringify({ paths: [path], plugins: ["TCC"] }), "--out", `rec-${host}`], cwd, { PATH }, "", WRAPPERS[host]);
      const c = JSON.parse(await readFile(join(cwd, `rec-${host}`, "coverage.json"), "utf8")) as Json;
      results[`recipe ${host}`] = [c.status, c.program_group.unproven, c.program_group.left_behind === 0];
      if (host !== "linux") assert.match(c.status_basis, /cannot be shown to be final/, `recipe ${host}: ${c.status_basis}`);
    }
    for (const tool of ["triage", "recipe"]) {
      assert.equal(results[`${tool} linux`][0], "complete", JSON.stringify(results));
      assert.deepEqual(results[`${tool} linux`][1], []);
      for (const host of ["darwin", "refused"]) {
        assert.equal(results[`${tool} ${host}`][0], "partial", JSON.stringify(results));
        assert.ok(results[`${tool} ${host}`][1].length >= 1, `${tool} ${host}`);
        assert.ok(results[`${tool} ${host}`][2]);
      }
    }
  });
});
