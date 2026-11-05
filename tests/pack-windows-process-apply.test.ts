/**
 * PKG-P2 (the windows-forensics tools and the tool-library twins of the process sweep). The shared PROCESS block ends what a program leaves behind (settle()); the
 * windows tools that run a program and report a file that program wrote call process_apply, so that a program that exits 0 and leaves a writer behind, or a host where
 * the absence of one cannot be proven, never answers `complete` over a file the program wrote. Stand-ins only, with real abandoned children (a child in the tool's group
 * that holds the descriptor, setsid, a double fork, a child with no descriptors that opens the file again by name, one that truncates and rewrites it, a periodic writer):
 *   - extract_stream (icat -> the output file), vss_stores (vshadowinfo -> stdout_file), esedb_query (esedbexport -> the export), sigma_hunt (the engine's result file),
 *     srum_reader (SrumECmd's CSV), lnk_jumplist (JLECmd's CSV), yara_scan (yara's standard error file) and the windows-artefacts recipe (target-query's files):
 *     the answer is `partial`, says what was ended (`program_group.left_behind`), and the files it describes are the files now and 2.4 seconds later;
 *   - a clean run is still `complete`, with left_behind 0 and no unproven reason;
 *   - where the absence cannot be proven (sys.platform patched to darwin, or ctypes.CDLL replaced by a library whose prctl fails) a clean run of those tools is `partial`
 *     and says why; the tools that report only what a program printed on a pipe (registry_recover's regfexport counts, vss_materialise's copies, lnkinfo) are not held to it;
 *   - the readers that wait for a pipe (yara_scan's reader thread, registry_recover's select loop, vss_materialise's copy loop) do not wait for what a program left holding it:
 *     it is ended and the answer says so; vss_materialise keeps nothing that came through such a pipe as a copy.
 * The cases that fail on the batch head (before the tools called process_apply) are the abandoned-child ones: the answer was `complete` over a file the program's child could
 * have changed; run with WINDOWS_PACK_TOOLS naming the head's tools to see it.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { chmod, mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { test } from "node:test";
import { withCwd } from "./tool-library-harness.ts";
import { WIN } from "./windows-pack-harness.ts";
import { FILETIME_A, cfb, destList, lnk } from "./windows-t1-fixtures.ts";

type Answer = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any
type Host = "linux" | "darwin" | "refused";
const LINUX = process.platform === "linux";
const sha = (data: Buffer | string): string => createHash("sha256").update(data).digest("hex");
const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));
const RECIPE = join(WIN, "..", "recipes", "windows-artefacts", "run.py");

const alive = (pid: number): boolean => {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
};
async function pidsOf(file: string): Promise<number[]> {
  return (await readFile(file, "utf8").catch(() => "")).split(/\s+/).filter(Boolean).map(Number);
}
async function reap(file: string): Promise<void> {
  for (const pid of await pidsOf(file)) if (alive(pid)) process.kill(pid, "SIGKILL");
}
async function allGone(file: string, waitMs = 3000): Promise<number[]> {
  const until = Date.now() + waitMs;
  for (;;) {
    const left = (await pidsOf(file)).filter(alive);
    if (!left.length || Date.now() > until) return left;
    await sleep(50);
  }
}

// ---- how a tool is run: the way the harness starts one (the leader of a process group of its own), on a patched host when asked --------------------------------------

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
const WRAPPERS: Record<Host, string | undefined> = { linux: undefined, darwin: DARWIN, refused: REFUSED };
type Run = { code: number | null; stdout: string; stderr: string; ms: number };

function exec(script: string, argv: string[], cwd: string, env: Record<string, string>, stdin: string, host: Host = "linux"): Promise<Run> {
  return new Promise((resolveRun, reject) => {
    const wrapper = WRAPPERS[host];
    const args = wrapper ? ["-c", wrapper, script, ...argv] : [script, ...argv];
    const began = Date.now();
    const child = spawn("python3", args, { cwd, env: { ...process.env, AGENT_ID: "s1", ...env }, detached: true });
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => out.push(c));
    child.stderr.on("data", (c: Buffer) => err.push(c));
    child.on("error", reject);
    child.on("close", (code) => resolveRun({ code, stdout: Buffer.concat(out).toString("utf8"), stderr: Buffer.concat(err).toString("utf8"), ms: Date.now() - began }));
    child.stdin.on("error", () => undefined);
    child.stdin.end(stdin);
  });
}

// ---- the leftover: one Python function, used by every stand-in ---------------------------------------------------------------------------------------------------------

/** Python that forks a child which writes to `paths` (by name) `LEAVE_DELAY` seconds after the program is gone, the way LEAVE_VARIANT says; hold and chatty keep standard output open. */
const LEAVE = String.raw`
import os, sys, time


def leave(*paths):
    variant = os.environ.get("LEAVE_VARIANT")
    if not variant:
        return
    delay = float(os.environ.get("LEAVE_DELAY", "1.2"))
    if os.fork() != 0:
        return
    if variant == "double":
        if os.fork() != 0:
            os._exit(0)
    if variant in ("setsid", "double", "rewrite", "periodic", "hold", "chatty", "flood"):
        os.setsid()
    open(os.environ["LEAVE_PIDS"], "a").write("%d\n" % os.getpid())
    if variant != "inherit":
        keep = (1,) if variant in ("hold", "chatty", "flood") else ()
        for fd in range(0, 256):
            if fd not in keep:
                try:
                    os.close(fd)
                except OSError:
                    pass
    if variant == "hold":
        time.sleep(40)
        os._exit(0)
    if variant == "flood":
        # PKG-P8c: at full speed, until the tool lets the pipe go (the write then fails). Started after the program printed its answer.
        while True:
            try:
                os.write(1, b"junk line from a flooder\n" * 4096)
            except OSError:
                os._exit(0)
    if variant == "chatty":
        for _ in range(2000):
            try:
                os.write(1, b"junk line from a leftover\n")
            except OSError:
                break
            time.sleep(0.02)
        os._exit(0)
    if variant == "periodic":
        while True:
            time.sleep(0.2)
            for p in paths:
                open(p, "a").write("late\n")
    time.sleep(delay)
    for p in paths:
        if variant == "rewrite":
            open(p, "w").write("REWRITTEN BY A LATE WRITER\n")
        else:
            open(p, "a").write("late\n")
    os._exit(0)
`;
const PY = "#!/usr/bin/env python3\n";
async function pystub(bin: string, name: string, code: string): Promise<void> {
  await mkdir(bin, { recursive: true });
  const path = join(bin, name);
  await writeFile(path, PY + LEAVE + code, "utf8");
  await chmod(path, 0o755);
}

// ---- the cases ---------------------------------------------------------------------------------------------------------------------------------------------------------

type Setup = { args: unknown; env?: Record<string, string>; stdin?: string; argv?: string[] };
type Case = {
  name: string;
  script: string;
  install: (cwd: string, bin: string) => Promise<Setup>;
  /** The files the answer describes (absolute), read when the answer is in and again later. */
  watched: (answer: Answer, cwd: string) => Promise<string[]>;
  /** What the answer says about those files, checked against them. */
  claims?: (answer: Answer, files: Buffer[]) => void;
  /** The program_group is at the top of the answer (default) or of this object. */
  group?: (answer: Answer) => Answer;
  /** Whether the answer for a clean run is `complete` (default) and the name of the status field. */
  held: boolean;
  /** The answer is read from a file (the recipe's coverage.json) instead of standard output. */
  answerOf?: (run: Run, cwd: string) => Promise<Answer>;
};

const stdoutAnswer = async (run: Run): Promise<Answer> => {
  assert.doesNotMatch(run.stderr, /Traceback/, run.stderr);
  return JSON.parse(run.stdout) as Answer;
};

const NOW = "work/input.bin";
async function input(cwd: string): Promise<void> {
  await writeFile(join(cwd, NOW), "stand-in input\n");
}

const extract: Case = {
  name: "extract_stream",
  script: join(WIN, "extract_stream", "run.py"),
  held: true,
  install: async (cwd, bin) => {
    await input(cwd);
    await pystub(bin, "icat", `
sys.stdout.buffer.write(b"0123456789ab")
sys.stdout.buffer.flush()
leave(os.readlink("/proc/self/fd/1"))
`);
    return { args: { image: NOW, inode: "5-128-1", offset: 0, output: "work/s1/stream.bin" } };
  },
  watched: async (a, cwd) => [join(cwd, a.output)],
  claims: (a, files) => {
    assert.equal(a.size, files[0].length, "the size in the answer is the file's");
    assert.equal(a.sha256, sha(files[0]), "the digest in the answer is the file's");
  },
};

const stores: Case = {
  name: "vss_stores",
  script: join(WIN, "vss_stores", "run.py"),
  held: true,
  install: async (cwd, bin) => {
    await input(cwd);
    await pystub(bin, "vshadowinfo", `
print("vshadowinfo 20240101\\n\\nVolume Shadow Snapshot information:")
print("\\tNumber of stores:\\t0\\n")
sys.stdout.flush()
leave(os.readlink("/proc/self/fd/1"))
`);
    return { args: { image: NOW } };
  },
  watched: async (a, cwd) => [join(cwd, a.stdout_file), join(cwd, a.stderr_file)],
  claims: (a, files) => {
    assert.equal(a.store_count, 0);
    assert.equal(files[0].toString().includes("late"), false);
  },
};

const ESEDB_EXPORT = `
a = sys.argv[1:]
if a[:1] == ["-V"]:
    print("esedbexport 20231020")
    sys.exit(0)
target = a[a.index("-t") + 1]
d = target + ".export"
os.makedirs(d)
p = os.path.join(d, "Containers.4")
open(p, "w").write("Id\\tName\\n1\\ta\\n")
leave(p)
`;
const esedb: Case = {
  name: "esedb_query",
  script: join(WIN, "esedb_query", "run.py"),
  held: true,
  install: async (cwd, bin) => {
    await input(cwd);
    await pystub(bin, "esedbexport", ESEDB_EXPORT);
    return { args: { path: NOW } };
  },
  watched: async (a, cwd) => {
    const dir = join(cwd, a.export_dir);
    return (await readdir(dir)).map((n) => join(dir, n));
  },
  claims: (a, files) => {
    assert.equal(files.length, 1);
    assert.deepEqual(Object.values(a.files), [files[0].length], "the size in the answer is the file's");
  },
};

const sigma: Case = {
  name: "sigma_hunt",
  script: join(WIN, "sigma_hunt", "run.py"),
  held: true,
  install: async (cwd, bin) => {
    await mkdir(join(cwd, "work", "logs"), { recursive: true });
    await writeFile(join(cwd, "work", "logs", "a.evtx"), "ElfFile\0stand-in");
    await pystub(bin, "hayabusa", `
if sys.argv[1] in ("--version", "-V"):
    print("hayabusa 2.0")
    sys.exit(0)
a = sys.argv[1:]
out = a[a.index("-o") + 1]
open(out, "w").write("[]\\n")
leave(out)
`);
    return { args: { path: "work/logs", out_dir: "work/s1/hunt" }, env: { JOB_ID: "", OUT: "" } };
  },
  watched: async (a, cwd) => [resolve(cwd, a.result_file)],
};

const NET_HEAD = "Id,Timestamp,ExeInfo,ExeInfoDescription,ExeTimestamp,SidType,Sid,UserName,UserId,AppId,BytesSent,BytesReceived,InterfaceLuid,InterfaceType,L2ProfileId,ProfileName";
const netRow = (id: number): string => [id, `2026-10-12 ${String(8 + id).padStart(2, "0")}:00:00`, "C:\\\\app.exe", "", "2026-01-01 00:00:00", "User", "S-1-5-18", "SYSTEM", 5, 7 + id, 100 * id, 200 * id, "1689399632855040", "Ethernet", 11, "HomeNet"].join(",");
const ese = (): Buffer => {
  const b = Buffer.alloc(4096);
  Buffer.from("efcdab89", "hex").copy(b, 4);
  b.writeUInt32LE(0x620, 8);
  b.writeUInt32LE(3, 52);
  return b;
};
const srum: Case = {
  name: "srum_reader",
  script: join(WIN, "srum_reader", "run.py"),
  held: true,
  install: async (cwd, bin) => {
    const sru = join(cwd, "work", "ev", "Windows", "System32", "sru");
    const cfg = join(cwd, "work", "ev", "Windows", "System32", "config");
    await mkdir(sru, { recursive: true });
    await mkdir(cfg, { recursive: true });
    await writeFile(join(sru, "SRUDB.dat"), ese());
    await writeFile(join(cfg, "SOFTWARE"), Buffer.from("regf" + "\0".repeat(100)));
    await pystub(bin, "SrumECmd", `
a = sys.argv[1:]
d = a[a.index("--csv") + 1]
p = os.path.join(d, "20261104000000_SrumECmd_NetworkUsages_Output.csv")
open(p, "w").write("${NET_HEAD}\\n${[1, 2, 3].map(netRow).join("\\n")}\\n")
print("Found SRUM database file 'x' (State: Clean Shutdown, Format Version: 1568, Engine Version: 6.2)")
sys.stdout.flush()
leave(p)
`);
    return { args: { path: join(sru, "SRUDB.dat"), software: join(cfg, "SOFTWARE") } };
  },
  watched: async (a, cwd) => [join(cwd, a.rows_file)],
  claims: (a) => assert.equal(a.rows_total, 3, "the rows are the rows the CSV held when SrumECmd ended"),
};

const APP = "1b4dd67f29cb1962";
const JUMPLIST = (): Buffer =>
  cfb([
    { name: "1", data: lnk({ local: { path: "C:\\case\\report.txt", serial: 0x1a2b3c4d, label: "SYSTEM" }, name: "Report" }) },
    { name: "DestList", data: destList(4, [{ number: 1, host: "WKS", filetime: FILETIME_A + 10_000_000n, pin: -1, path: "C:\\case\\f1.txt" }]) },
  ]);
const lnkJumplist: Case = {
  name: "lnk_jumplist",
  script: join(WIN, "lnk_jumplist", "run.py"),
  held: true,
  install: async (cwd, bin) => {
    await writeFile(join(cwd, "work", `${APP}.automaticDestinations-ms`), JUMPLIST());
    await pystub(bin, "JLECmd", `
a = sys.argv[1:]
d = a[a.index("--csv") + 1]
p = os.path.join(d, "20261103000000_AutomaticDestinations.csv")
open(p, "w").write("EntryNumber,Path,LastModified,PinStatus,AppId\\n1,C:\\\\case\\\\f1.txt,2023-11-13 00:53:21.1234567,Unpinned,${APP}\\n")
leave(p)
`);
    return { args: { path: `work/${APP}.automaticDestinations-ms` } };
  },
  watched: async (a, cwd) => [join(cwd, a.rows_file), join(cwd, a.receipt)],
};

const YARA = `
a = sys.argv[1:]
if a == ["--version"]:
    print("4.5.8")
    sys.exit(0)
if a == ["--help"]:
    print("  -s,  --print-strings   print matching strings")
    print("  -L,  --print-string-length   print length of matched strings")
    print("  -N,  --no-follow-symlinks   do not follow symlinks")
    sys.exit(0)
print("r " + a[-1])
sys.stdout.flush()
sys.stderr.write("warning: rule r is slow\\n")
sys.stderr.flush()
leave(os.readlink("/proc/self/fd/2"))
`;
const yara: Case = {
  name: "yara_scan",
  script: join(WIN, "yara_scan", "run.py"),
  held: true,
  install: async (cwd, bin) => {
    await input(cwd);
    await writeFile(join(cwd, "work", "rules.yar"), "rule r { condition: true }\n");
    await pystub(bin, "yara", YARA);
    return { args: { rules: "work/rules.yar", target: NOW } };
  },
  watched: async (a, cwd) => [join(cwd, a.stderr_file)],
  claims: (a, files) => {
    assert.equal(a.match_count, 1);
    assert.equal(a.stderr_line_count, files[0].toString().split("\n").filter(Boolean).length, "the line count in the answer is the file's");
  },
};

const DISSECT = `
a = sys.argv[1:]
if "--help" in a:
    print("usage: target-query [-f FUNCTIONS] [--json] target")
    print("  --json  output records as JSON")
    sys.exit(0)
if "--version" in a:
    print("target-query 3.20 (stand-in)")
    sys.exit(0)
fn = a[a.index("-f") + 1]
print('{"x":1}')
sys.stdout.flush()
if fn == "bam":
    leave(os.readlink("/proc/self/fd/1"))
`;
const recipe: Case = {
  name: "windows-artefacts recipe",
  script: RECIPE,
  held: true,
  install: async (cwd, bin) => {
    const recent = join(cwd, "c", "C", "Users", "x", "AppData", "Recent");
    await mkdir(recent, { recursive: true });
    await writeFile(join(recent, "report.lnk"), lnk({ local: { path: "C:\\case\\report.txt", serial: 0x1a2b3c4d, label: "SYSTEM" }, name: "Report" }));
    await pystub(bin, "target-query", DISSECT);
    return { args: {}, argv: ["run", "--target", JSON.stringify({ paths: ["c"] }), "--out", join(cwd, "out")], stdin: "" };
  },
  answerOf: async (_run, cwd) => JSON.parse(await readFile(join(cwd, "out", "coverage.json"), "utf8")) as Answer,
  watched: async (_a, cwd) => [join(cwd, "out", "dissect-target", "bam.out")],
};

const HELD = [extract, stores, esedb, sigma, srum, lnkJumplist, yara, recipe];

// ---- the runner ---------------------------------------------------------------------------------------------------------------------------------------------------------

type Outcome = { answer: Answer; run: Run; cwd: string; pids: string; files: Buffer[]; paths: string[] };

async function inCase(c: Case, variant: string | null, host: Host, check: (o: Outcome) => Promise<void>): Promise<void> {
  await withCwd(async (cwd, bin) => {
    const pids = join(cwd, "leftover.pids");
    try {
      const s = await c.install(cwd, bin);
      const env: Record<string, string> = { PATH: `${bin}:${process.env.PATH ?? ""}`, LEAVE_PIDS: pids, ...(variant ? { LEAVE_VARIANT: variant } : {}), ...(s.env ?? {}) };
      const run = await exec(c.script, s.argv ?? [], cwd, env, s.stdin ?? JSON.stringify(s.args), host);
      const answer = await (c.answerOf ?? stdoutAnswer)(run, cwd);
      const paths = await c.watched(answer, cwd).catch(() => [] as string[]);
      const files = await Promise.all(paths.map((p) => readFile(p).catch(() => Buffer.alloc(0))));
      await check({ answer, run, cwd, pids, files, paths });
    } finally {
      await reap(pids);
    }
  });
}

const groupOf = (c: Case, a: Answer): Answer => (c.group ? c.group(a) : a).program_group;

const VARIANTS = ["inherit", "setsid", "double", "rewrite", "periodic"];
for (const c of HELD) {
  for (const variant of VARIANTS) {
    test(`${c.name}: a child of the program (${variant}) that writes after the program exited 0 is ended: partial, and the files the answer describes do not change afterwards`, { skip: !LINUX }, async () => {
      await inCase(c, variant, "linux", async (o) => {
        assert.equal(o.answer.status, "partial", o.run.stdout.slice(0, 1500));
        const group = groupOf(c, o.answer);
        assert.ok(group, "the answer carries program_group");
        assert.ok(group.left_behind >= 1, `program_group.left_behind is ${group.left_behind}`);
        assert.equal(group.subreaper, true);
        assert.match(JSON.stringify(o.answer).replace(/\\"/g, '"'), /left \d+ process|left process|process\(es\)/, "the answer says a process was left and ended");
        assert.deepEqual(await allGone(o.pids), [], "the leftover is gone");
        c.claims?.(o.answer, o.files);
        await sleep(2400);
        const later = await Promise.all(o.paths.map((p) => readFile(p).catch(() => Buffer.alloc(0))));
        o.paths.forEach((p, i) => {
          assert.equal(sha(later[i]), sha(o.files[i]), `${p} is the file the answer describes, and does not change after it`);
          assert.doesNotMatch(later[i].toString("utf8"), /late|REWRITTEN/, `${p} holds nothing a leftover wrote`);
        });
      });
    });
  }

  test(`${c.name}: a clean run is complete, with nothing left behind and nothing unproven`, { skip: !LINUX }, async () => {
    await inCase(c, null, "linux", async (o) => {
      assert.equal(o.answer.status, "complete", JSON.stringify(o.answer.status_basis ?? o.run.stdout.slice(0, 800)));
      const group = groupOf(c, o.answer);
      assert.ok(group, "the answer carries program_group");
      assert.equal(group.left_behind, 0);
      assert.deepEqual(group.unproven, []);
      assert.equal(group.subreaper, true);
      c.claims?.(o.answer, o.files);
    });
  });

  for (const host of ["darwin", "refused"] as const) {
    test(`${c.name}: where the absence of a leftover cannot be proven (${host === "darwin" ? "the host is not Linux" : "the kernel refuses PR_SET_CHILD_SUBREAPER"}), a clean run is at most partial and says why`, { skip: !LINUX }, async () => {
      await inCase(c, null, host, async (o) => {
        assert.equal(o.answer.status, "partial", JSON.stringify(o.answer.status_basis ?? o.run.stdout.slice(0, 800)));
        const group = groupOf(c, o.answer);
        assert.equal(group.subreaper, false);
        assert.ok(group.unproven.length >= 1, "program_group.unproven names the reason");
        assert.match(JSON.stringify(o.answer), /cannot be shown to be final|cannot adopt|refused PR_SET_CHILD_SUBREAPER|cannot prove|no process behind|left no process/);
      });
    });
  }
}

// ---- esedb_query: a reused export keeps what its run recorded; a table read after a leftover is partial ----------------------------------------------------------------

test("esedb_query: an export made while esedbexport left a process behind is reused as partial, with the reason the first call recorded; a clean export is reused as complete", { skip: !LINUX }, async () => {
  await withCwd(async (cwd, bin) => {
    const pids = join(cwd, "leftover.pids");
    try {
      await esedb.install(cwd, bin);
      const env = { PATH: `${bin}:${process.env.PATH ?? ""}`, LEAVE_PIDS: pids };
      const dirty = JSON.parse((await exec(esedb.script, [], cwd, { ...env, LEAVE_VARIANT: "setsid" }, JSON.stringify({ path: NOW }))).stdout) as Answer;
      assert.equal(dirty.status, "partial");
      assert.equal(dirty.export_reused, false);
      const again = JSON.parse((await exec(esedb.script, [], cwd, env, JSON.stringify({ path: NOW }))).stdout) as Answer;
      assert.equal(again.export_reused, true, "the export is reused");
      assert.equal(again.status, "partial", "reused: still partial");
      assert.match(JSON.stringify(again.process_problems), /left \d+ process\(es\) running after it ended/);
      assert.match(JSON.stringify(again.process_problems), /recorded by the call that made this export/);
      assert.equal(again.program_group.left_behind, 0, "this call ended nothing");
      const table = JSON.parse((await exec(esedb.script, [], cwd, env, JSON.stringify({ path: NOW, table: "Containers" }))).stdout) as Answer;
      assert.equal(table.status, "partial");
      assert.match(table.status_basis, /left \d+ process/);
      assert.equal(table.row_count, 1, "the rows are still read");
    } finally {
      await reap(pids);
    }
    await rmExport(cwd);
    const clean = JSON.parse((await exec(esedb.script, [], cwd, { PATH: `${bin}:${process.env.PATH ?? ""}`, LEAVE_PIDS: pids }, JSON.stringify({ path: NOW }))).stdout) as Answer;
    assert.equal(clean.status, "complete", clean.status_basis);
    const reused = JSON.parse((await exec(esedb.script, [], cwd, { PATH: `${bin}:${process.env.PATH ?? ""}`, LEAVE_PIDS: pids }, JSON.stringify({ path: NOW }))).stdout) as Answer;
    assert.equal(reused.export_reused, true);
    assert.equal(reused.status, "complete", reused.status_basis);
  });
});

async function rmExport(cwd: string): Promise<void> {
  await rm(join(cwd, "work", "s1", "esedb-export"), { recursive: true, force: true });
}

// ---- lnk_jumplist: lnkinfo prints on a pipe and is not held to the rule; JLECmd's CSV is ------------------------------------------------------------------------------------

test("lnk_jumplist: a process lnkinfo leaves behind is ended and counted, and does not change a status that rests on what lnkinfo printed on a pipe; the same on a host that cannot adopt orphans", { skip: !LINUX }, async () => {
  for (const host of ["linux", "darwin", "refused"] as const) {
    await withCwd(async (cwd, bin) => {
      const pids = join(cwd, "leftover.pids");
      try {
        await writeFile(join(cwd, "work", "report.lnk"), lnk({ local: { path: "C:\\case\\report.txt", serial: 0x1a2b3c4d, label: "SYSTEM" }, name: "Report" }));
        await pystub(bin, "lnkinfo", `
print("lnkinfo 20240101")
sys.stdout.flush()
leave()
`);
        const env = { PATH: `${bin}:${process.env.PATH ?? ""}`, LEAVE_PIDS: pids, LEAVE_VARIANT: "setsid", LEAVE_DELAY: "20" };
        const out = JSON.parse((await exec(join(WIN, "lnk_jumplist", "run.py"), [], cwd, env, JSON.stringify({ path: "work/report.lnk" }), host)).stdout) as Answer;
        assert.equal(out.status, "complete", `${host}: ${out.status_basis}`);
        assert.equal(out.lnkinfo.checked, 1);
        if (host === "linux") {
          assert.ok(out.program_group.left_behind >= 1, "the leftover was ended and counted");
          assert.deepEqual(await allGone(pids), []);
        }
      } finally {
        await reap(pids);
      }
    });
  }
});

// ---- the readers that wait for a pipe ---------------------------------------------------------------------------------------------------------------------------------------

for (const variant of ["hold", "chatty"]) {
  test(`yara_scan: a process yara left holding its output pipe (${variant}) does not hold the reader thread: the tool answers at once, partial, and the process is ended`, { skip: !LINUX }, async () => {
    await inCase(yara, variant, "linux", async (o) => {
      assert.ok(o.run.ms < 15_000, `answered in ${o.run.ms} ms`);
      assert.equal(o.answer.status, "partial");
      assert.ok(o.answer.program_group.left_behind >= 1);
      assert.deepEqual(await allGone(o.pids), []);
    });
  });
}

/** regfexport_counts() of registry_recover, called on its own (the tool reaches it only through regipy, which not every host has), as the leader of a process group like a tool. */
const DRIVER = `
import importlib.util, json, sys, time
spec = importlib.util.spec_from_file_location("registry_recover_under_test", sys.argv[1])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
began = time.monotonic()
result = mod.regfexport_counts(sys.argv[2], 30)
result["took"] = round(time.monotonic() - began, 2)
result["group"] = mod.process_verdict()
print(json.dumps(result))
`;
for (const variant of [null, "hold", "chatty", "setsid"]) {
  test(`registry_recover: regfexport's counts when it ${variant ? `leaves a process behind (${variant})` : "leaves nothing"}: a process holding the output pipe does not hold the select loop, and the counts of a run that left one are not trusted`, { skip: !LINUX }, async () => {
    await withCwd(async (cwd, bin) => {
      const pids = join(cwd, "leftover.pids");
      try {
        await writeFile(join(cwd, "work", "h.dat"), Buffer.alloc(4096));
        await writeFile(join(cwd, "driver.py"), DRIVER);
        await pystub(bin, "regfexport", `
print("Key path: x")
print("Value: y")
sys.stdout.flush()
leave()
`);
        const env = { PATH: `${bin}:${process.env.PATH ?? ""}`, LEAVE_PIDS: pids, LEAVE_DELAY: "20", ...(variant ? { LEAVE_VARIANT: variant } : {}) };
        const run = await exec(join(cwd, "driver.py"), [join(WIN, "registry_recover", "run.py"), join(cwd, "work", "h.dat")], cwd, env, "");
        assert.doesNotMatch(run.stderr, /Traceback/, run.stderr);
        const out = JSON.parse(run.stdout) as Answer;
        assert.ok(out.took < 12, `answered in ${out.took} s`);
        assert.deepEqual(await allGone(pids), [], "the leftover is gone");
        if (!variant) {
          assert.equal(out.finished, true);
          assert.deepEqual([out.keys, out.values], [1, 1]);
          assert.equal(out.group.left_behind, 0);
        } else {
          assert.equal(out.finished, false, JSON.stringify(out));
          assert.match(out.why_not_finished, /left \d+ process\(es\) running after it ended/);
          assert.ok(out.group.left_behind >= 1);
        }
      } finally {
        await reap(pids);
      }
    });
  });
}

// ---- vss_materialise: the stand-ins of its own suite, with a leftover ---------------------------------------------------------------------------------------------------

const INFO = `
n = 2
print("vshadowinfo 20240101\\n\\nVolume Shadow Snapshot information:")
print("\\tNumber of stores:\\t%d\\n" % n)
for i in range(1, n + 1):
    print("Store: %d" % i)
    print("\\tIdentifier\\t\\t: %08d-aaaa-bbbb-cccc-%012d" % (i * 11111111 % 100000000, i))
    print("\\tCreation time\\t\\t: Oct 17, 2023 12:00:00.000000000 UTC")
sys.stdout.flush()
if os.environ.get("LEAVE_PROGRAM") == "vshadowinfo":
    leave()
`;
const MOUNT = `
import shutil
d = os.environ["FAKE_DIR"]
mount = sys.argv[-1]
for n in ("1", "2"):
    shutil.copy(os.path.join(d, "store-%s.json" % n), os.path.join(mount, "vss%s" % n))
sys.stdout.flush()
if os.environ.get("LEAVE_PROGRAM") == "vshadowmount":
    leave()
`;
const UMOUNT = `
import glob
mount = sys.argv[-1]
for f in glob.glob(os.path.join(mount, "vss*")):
    os.unlink(f)
`;
const FLS = `
import json
a = sys.argv[1:]
vol, rest = a[0], a[1:]
fs = json.load(open(vol))["fs"]
def enc(p): return str(int.from_bytes(p.encode(), "big")) + "-128-1"
def dec(i): n = int(i.split("-")[0]); return n.to_bytes((n.bit_length() + 7) // 8, "big").decode()
path = dec(rest[0]) if rest else ""
node = fs
for part in [p for p in path.split("/") if p]:
    node = node[part]
for name, val in node.items():
    kind = "d/d" if isinstance(val, dict) else "r/r"
    print("%s %s:\\t%s" % (kind, enc((path + "/" + name).lstrip("/")), name))
sys.stdout.flush()
if os.environ.get("LEAVE_PROGRAM") == "fls":
    leave()
`;
const ICAT = `
import json
a = sys.argv[1:]
vol, inode = a
def dec(i): n = int(i.split("-")[0]); return n.to_bytes((n.bit_length() + 7) // 8, "big").decode()
node = json.load(open(vol))["fs"]
for part in dec(inode).split("/"):
    node = node[part]
sys.stdout.write(node)
sys.stdout.flush()
if os.environ.get("LEAVE_PROGRAM") == "icat" and vol.endswith("vss1"):
    leave()
`;
const SYSTEM = "/Windows/System32/config/SYSTEM";
const volume = (text: string): string => JSON.stringify({ fs: { Windows: { System32: { config: { SYSTEM: text } } } } });

async function vssRun(program: string | null, variant: string | null, host: Host = "linux"): Promise<{ answer: Answer; cwd: string; pids: string; run: Run }> {
  let result: { answer: Answer; cwd: string; pids: string; run: Run } | null = null;
  await withCwd(async (cwd, bin) => {
    const pids = join(cwd, "leftover.pids");
    try {
      const fake = join(cwd, "fake");
      await mkdir(fake, { recursive: true });
      await writeFile(join(fake, "store-1.json"), volume("old system"));
      await writeFile(join(fake, "store-2.json"), volume("new system"));
      await writeFile(join(cwd, "work", "disk.raw"), volume("new system"));
      await writeFile(join(cwd, "fuse-device"), "");
      await pystub(bin, "vshadowinfo", INFO);
      await pystub(bin, "vshadowmount", MOUNT);
      await pystub(bin, "fusermount3", UMOUNT);
      await pystub(bin, "fls", FLS);
      await pystub(bin, "icat", ICAT);
      const env = {
        PATH: `${bin}:${process.env.PATH ?? ""}`, FAKE_DIR: fake, DFIRSWARM_FUSE_DEVICE: join(cwd, "fuse-device"), LEAVE_PIDS: pids,
        ...(variant ? { LEAVE_VARIANT: variant } : {}), ...(program ? { LEAVE_PROGRAM: program } : {}),
      };
      const run = await exec(join(WIN, "vss_materialise", "run.py"), [], cwd, env, JSON.stringify({ image: "work/disk.raw", offset: 1048576, stores: [1, 2], paths: [SYSTEM] }), host);
      assert.doesNotMatch(run.stderr, /Traceback/, run.stderr);
      result = { answer: JSON.parse(run.stdout) as Answer, cwd, pids, run };
      assert.deepEqual(await allGone(pids), [], "the leftover is gone");
    } finally {
      await reap(pids);
    }
  });
  return result as unknown as { answer: Answer; cwd: string; pids: string; run: Run };
}

test("vss_materialise: a clean run is complete with nothing left behind", { skip: !LINUX }, async () => {
  const { answer } = await vssRun(null, null);
  assert.equal(answer.status, "complete", answer.status_basis);
  assert.equal(answer.program_group.left_behind, 0);
  assert.equal(answer.copies, 2);
});

for (const variant of ["hold", "chatty"]) {
  test(`vss_materialise: a process icat left holding its output pipe (${variant}) is ended after the grace, the bytes that came through the pipe are not kept as a copy, and the answer is partial`, { skip: !LINUX }, async () => {
    const { answer, run } = await vssRun("icat", variant);
    assert.ok(run.ms < 30_000, `answered in ${run.ms} ms`);
    assert.equal(answer.status, "partial", answer.status_basis);
    assert.ok(answer.program_group.left_behind >= 1);
    const first = answer.rows.find((r: Answer) => r.store === 1 && r.path === SYSTEM);
    assert.equal(first.copy_status, "left_behind");
    assert.equal(first.copied_to, null);
    assert.equal(first.sha256, null);
    const second = answer.rows.find((r: Answer) => r.store === 2 && r.path === SYSTEM);
    assert.equal(second.copy_status, "copied", "a store whose icat left nothing is copied");
    assert.match(answer.status_basis, /left running were ended/);
  });
}

for (const program of ["vshadowinfo", "fls"]) {
  test(`vss_materialise: a process ${program} left behind with no descriptor of the tool's is ended at once and the final answer says so (partial), the copies being intact`, { skip: !LINUX }, async () => {
    const { answer } = await vssRun(program, "setsid");
    assert.equal(answer.status, "partial", answer.status_basis);
    assert.ok(answer.program_group.left_behind >= 1);
    assert.match(answer.status_basis, /left running were ended/);
  });
}

test("vss_materialise reports only what programs printed on pipes: a host that cannot adopt orphans does not make its copies less than complete, and says it in program_group", { skip: !LINUX }, async () => {
  for (const host of ["darwin", "refused"] as const) {
    const { answer } = await vssRun(null, null, host);
    assert.equal(answer.status, "complete", `${host}: ${answer.status_basis}`);
    assert.equal(answer.program_group.subreaper, false);
    assert.ok(answer.program_group.notes.length + answer.program_group.unproven.length >= 1);
  }
});

// ---- a pipe cut at the byte cap of the shared block (PKG-P8c) --------------------------------------------------------------------------------------------------------
// communicate_bounded reads at most 1 MiB more from the pipes of a program that has ended, then ends the holder and lets the pipes go (PIPE_CUT). A flooder in a session of its own, started after
// the program printed its answer, is cut that way. On Linux the tool also adopts and ends it (left_behind >= 1); where it cannot (darwin, prctl refused) nothing finds it and only the cut is left to
// say the pipe was mixed: that was `complete` on the batch head. The sentence is looked for in the status_basis, not in program_group.notes (where the head said it too).

for (const host of ["linux", "darwin", "refused"] as const) {
  test(`lnk_jumplist: lnkinfo's pipe cut at the byte cap (${host}) is partial for the run, and the link's own row says lnkinfo was not compared`, { skip: !LINUX, timeout: 120000 }, async () => {
    await withCwd(async (cwd, bin) => {
      const pids = join(cwd, "leftover.pids");
      try {
        await writeFile(join(cwd, "work", "report.lnk"), lnk({ local: { path: "C:\\case\\report.txt", serial: 0x1a2b3c4d, label: "SYSTEM" }, name: "Report" }));
        await pystub(bin, "lnkinfo", `
print("lnkinfo 20240101")
sys.stdout.flush()
leave()
`);
        const env = { PATH: `${bin}:${process.env.PATH ?? ""}`, LEAVE_PIDS: pids, LEAVE_VARIANT: "flood" };
        const out = JSON.parse((await exec(join(WIN, "lnk_jumplist", "run.py"), [], cwd, env, JSON.stringify({ path: "work/report.lnk" }), host)).stdout) as Answer;
        assert.equal(out.status, "partial", `${host}: ${out.status_basis}`);
        assert.match(out.status_basis, /1 lnkinfo call\(s\) were cut at 1048576 bytes because a process that held lnkinfo's pipe after it ended went on writing/);
        assert.match(out.status_basis, /the rows are lnk_parse's own reading/);
        assert.equal(out.lnkinfo.checked, 0, "what a flooder mixed into lnkinfo's output was not compared");
        assert.equal(out.lnkinfo.not_run, 1);
        const row = out.rows.find((r: Answer) => r.row === "link");
        assert.equal(row.integrity.lnkinfo.ran, false);
        assert.match(row.integrity.lnkinfo.why, /lnkinfo's pipe was cut at 1048576 bytes/);
        assert.equal(row.integrity.status, "ok", "lnk_parse's own reading of the link stands");
        if (host === "linux") assert.ok(out.program_group.left_behind >= 1);
        else assert.equal(out.program_group.left_behind, 0, "nothing was found: the cut alone makes it partial");
      } finally {
        await reap(pids);
      }
    });
  });
}

test("lnk_jumplist: a clean lnkinfo is still compared and complete on every host", { skip: !LINUX }, async () => {
  for (const host of ["linux", "darwin", "refused"] as const) {
    await withCwd(async (cwd, bin) => {
      await writeFile(join(cwd, "work", "report.lnk"), lnk({ local: { path: "C:\\case\\report.txt", serial: 0x1a2b3c4d, label: "SYSTEM" }, name: "Report" }));
      await pystub(bin, "lnkinfo", `
print("lnkinfo 20240101")
`);
      const env = { PATH: `${bin}:${process.env.PATH ?? ""}`, LEAVE_PIDS: join(cwd, "leftover.pids") };
      const out = JSON.parse((await exec(join(WIN, "lnk_jumplist", "run.py"), [], cwd, env, JSON.stringify({ path: "work/report.lnk" }), host)).stdout) as Answer;
      assert.equal(out.status, "complete", `${host}: ${out.status_basis}`);
      assert.equal(out.lnkinfo.checked, 1);
    });
  }
});

for (const host of ["linux", "darwin", "refused"] as const) {
  test(`vss_materialise: vshadowinfo's pipe cut at the byte cap (${host}) is partial and says so; the copies are intact`, { skip: !LINUX, timeout: 120000 }, async () => {
    const { answer, run } = await vssRun("vshadowinfo", "flood", host);
    assert.ok(run.ms < 30_000, `answered in ${run.ms} ms`);
    assert.equal(answer.status, "partial", `${host}: ${answer.status_basis}`);
    assert.match(answer.status_basis, /call\(s\) of vshadowinfo or fusermount were cut at 1048576 bytes because a process that held the program's pipe after it ended went on writing/);
    assert.equal(answer.copies, 2);
    if (host === "linux") assert.ok(answer.program_group.left_behind >= 1);
    else assert.equal(answer.program_group.left_behind, 0, "nothing was found: the cut alone makes it partial");
  });
}

test("vss_materialise: the vshadowmount daemon is left on purpose; a flood on its pipe is not a leftover and is not counted: the answer stays complete", { skip: !LINUX, timeout: 120000 }, async () => {
  const { answer } = await vssRun("vshadowmount", "flood");
  assert.equal(answer.status, "complete", answer.status_basis);
  assert.equal(answer.copies, 2);
  assert.doesNotMatch(String(answer.status_basis), /were cut at/);
});
