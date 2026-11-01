/**
 * The residuals of the shared blocks (PKG-XP-02), each held by a case that runs the block's own text from a carrier and fails on the
 * text that came before:
 *
 *  - part 1, PLACE and PAGE (the comparing of two result files): a FIFO, a link or a directory at the name a result is placed at
 *    never holds the tool, and the comparing of one call has a clock;
 *  - part 2, PLACE, STOP and PAGE: ...
 *  - part 3, PROCESS: ...
 *
 * Every program the cases start is run under a timeout and ended by this file; the cases write only under their own temporary directory.
 */
import assert from "node:assert/strict";
import { execFileSync, spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { ROOT } from "./tool-library-harness.ts";

const sha = (text: string): string => createHash("sha256").update(text).digest("hex");
const rel = (...parts: string[]): string => join(ROOT, ...parts);

async function runFiles(): Promise<string[]> {
  const found: string[] = [];
  const walk = async (dir: string): Promise<void> => {
    for (const e of await readdir(dir, { withFileTypes: true })) {
      const full = join(dir, e.name);
      if (e.isDirectory()) {
        if (e.name !== "node_modules" && e.name !== "__pycache__") await walk(full);
      } else if (e.name === "run.py") found.push(full);
    }
  };
  await walk(rel("packs"));
  await walk(rel("tool-library"));
  return found.sort();
}

async function scratch(fn: (dir: string) => Promise<void>): Promise<void> {
  const dir = await mkdtemp(join(tmpdir(), "xp02-"));
  try {
    await fn(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

/** Run python text as `python3 -I -c <code> args`, ended by SIGKILL at `ms`: a hang is a failed case, not a stuck suite. */
function py(code: string, args: string[], ms = 30_000): { status: number | null; signal: string | null; stdout: string; stderr: string } {
  const r = spawnSync("python3", ["-I", "-c", code, ...args], { encoding: "utf8", timeout: ms, killSignal: "SIGKILL" });
  return { status: r.status, signal: r.signal, stdout: r.stdout ?? "", stderr: r.stderr ?? "" };
}

// ---------------------------------------------------------------------------------------------------------------------
// Part 1: the comparing of a result file with the file already at its name
// ---------------------------------------------------------------------------------------------------------------------

/** The block's own text, run: the PLACE block of the windows lineage or the PAGE block of the memory lineage. */
const PLACE_CASES = String.raw`
import json, os, re, sys, time, errno, hashlib, signal
from pathlib import Path
src = open(sys.argv[1], encoding="utf8").read()
name = sys.argv[2]
begin, end = src.index("# BEGIN SHARED " + name), src.index("# END SHARED " + name)
GUARD = {"depth": 0, "pending": None, "stopping": False}
def checkpoint():
    pass
exec(src[begin:end], globals())
signal.alarm(8)   # a hang ends the program with SIGALRM: no answer, so the case fails
d = Path(sys.argv[3])
out = {}
def tmpfile(n, data):
    p = d / (".tmp-%s" % n)
    p.write_bytes(data)
    return p
# a FIFO at the final name, and a result with no hit (empty): the temporary file is 0 bytes and so is the FIFO
fifo = d / "hits.jsonl"
os.mkfifo(fifo)
got = place_without_replacing(tmpfile("a", b""), fifo)
out["fifo"] = {"name": got.name, "still_fifo": (os.lstat(fifo).st_mode & 0o170000) == 0o010000, "placed_size": got.stat().st_size}
# a link at the final name, to a file that is empty too
target = d / "elsewhere.txt"
target.write_bytes(b"")
os.symlink(target, d / "link.jsonl")
got = place_without_replacing(tmpfile("b", b""), d / "link.jsonl")
out["link"] = {"name": got.name, "target_size": target.stat().st_size, "still_link": os.path.islink(d / "link.jsonl")}
# a directory at the final name
os.mkdir(d / "dir.jsonl")
got = place_without_replacing(tmpfile("c", b"x" * 4096), d / "dir.jsonl")
out["directory"] = {"name": got.name, "still_directory": os.path.isdir(d / "dir.jsonl")}
# a rerun with identical content keeps its name, any other content takes the next one
first = place_without_replacing(tmpfile("d1", b"same bytes\n" * 100), d / "rerun.jsonl")
second_tmp = tmpfile("d2", b"same bytes\n" * 100)
second = place_without_replacing(second_tmp, d / "rerun.jsonl")
third = place_without_replacing(tmpfile("d3", b"other bytes\n" * 100), d / "rerun.jsonl")
fourth_tmp = tmpfile("d4", b"other bytes\n" * 100)
fourth = place_without_replacing(fourth_tmp, d / "rerun.jsonl")
out["rerun"] = {"first": first.name, "second": second.name, "second_tmp_gone": not second_tmp.exists(), "third": third.name, "fourth": fourth.name, "fourth_tmp_gone": not fourth_tmp.exists()}
# the clock of the comparing: with none left, an identical earlier result is taken as different and the next free name is used
PLACE_COMPARE_SECONDS = -1
late = place_without_replacing(tmpfile("e", b"same bytes\n" * 100), d / "rerun.jsonl")
out["clock"] = {"name": late.name}
print(json.dumps(out))
`;

type Placed = Record<string, Record<string, unknown>>;
function placeCases(file: string, block: string, dir: string): Placed {
  const r = py(PLACE_CASES, [file, block, dir]);
  assert.equal(r.status, 0, `${file}: ${r.signal ?? ""} ${r.stderr} (no answer: the placing hung or crashed)`);
  return JSON.parse(r.stdout) as Placed;
}

function checkPlace(got: Placed, file: string): void {
  assert.deepEqual(got.fifo, { name: "hits-2.jsonl", still_fifo: true, placed_size: 0 }, `${file}: a FIFO at the final name`);
  assert.deepEqual(got.link, { name: "link-2.jsonl", target_size: 0, still_link: true }, `${file}: a link at the final name`);
  assert.deepEqual(got.directory, { name: "dir-2.jsonl", still_directory: true }, `${file}: a directory at the final name`);
  assert.deepEqual(got.rerun, { first: "rerun.jsonl", second: "rerun.jsonl", second_tmp_gone: true, third: "rerun-2.jsonl", fourth: "rerun-2.jsonl", fourth_tmp_gone: true }, `${file}: a rerun with identical content`);
  assert.equal((got.clock as { name: string }).name, "rerun-3.jsonl", `${file}: past the comparing clock an earlier result is taken as different`);
}

const PLACE_CARRIERS: Array<[string, string]> = [
  ["packs/windows-forensics/tools/regkv/run.py", "PLACE"],
  ["packs/windows-forensics/tools/esedb_query/run.py", "PLACE"],
  ["packs/encrypted-containers/tools/archive_probe/run.py", "PLACE"],
  ["packs/ransomware-response/tools/ransom_note_scan/run.py", "PLACE"],
  ["packs/ransomware-response/tools/encryption_extent/run.py", "PLACE"],
  ["packs/ransomware-response/tools/recovery_validate/run.py", "PLACE"],
  ["packs/ransomware-response/tools/ransomware_scope_report/run.py", "PLACE"],
  ["tool-library/yara_scan/run.py", "PLACE"],
  ["packs/memory-forensics/tools/mem_carve/run.py", "PAGE"],
  ["packs/memory-forensics/tools/mem_fs/run.py", "PAGE"],
  ["packs/memory-forensics/tools/mem_profile/run.py", "PAGE"],
];

for (const [file, block] of PLACE_CARRIERS) {
  test(`${file}: a FIFO, a link or a directory at the final name does not hold the placing, and an identical rerun keeps its name`, async () => {
    await scratch(async (dir) => checkPlace(placeCases(rel(file), block, dir), file));
  });
}

/** An unmarked copy of the comparison (the publish() families): the function alone, run. */
const FUNC_CASES = String.raw`
import json, os, re, sys, time, signal
from pathlib import Path
src = open(sys.argv[1], encoding="utf8").read()
m = re.search(r"^def (_?same_bytes)\(.*?(?=^\S)", src, re.M | re.S)
CHUNK = 1 << 20
exec(m.group(0), globals())
fn = globals()[m.group(1)]
signal.alarm(8)
d = Path(sys.argv[2])
(d / "a").write_bytes(b"")
os.mkfifo(d / "fifo")
(d / "empty2").write_bytes(b"")
os.symlink(d / "empty2", d / "link")
os.mkdir(d / "dir")
(d / "x1").write_bytes(b"abc" * 1000)
(d / "x2").write_bytes(b"abc" * 1000)
(d / "y").write_bytes(b"abd" * 1000)
print(json.dumps({"fifo": fn(d / "a", d / "fifo"), "fifo_first": fn(d / "fifo", d / "a"), "link": fn(d / "a", d / "link"),
                  "directory": fn(d / "a", d / "dir"), "same": fn(d / "x1", d / "x2"), "different": fn(d / "x1", d / "y"),
                  "missing": fn(d / "x1", d / "nothing")}))
`;

const FUNC_CARRIERS = [
  "packs/cloud-forensics/tools/ual_parse/run.py",
  "packs/triage-collection/tools/collection_id/run.py",
  "packs/computer-forensics-base/tools/chunk_needles/run.py",
  "packs/computer-forensics-base/tools/sig_carve/run.py",
  "tool-library/sqlite_query/run.py",
];

for (const file of FUNC_CARRIERS) {
  test(`${file}: the comparison of two result files never reads a FIFO, a link or a directory`, async () => {
    await scratch(async (dir) => {
      const r = py(FUNC_CASES, [rel(file), dir]);
      assert.equal(r.status, 0, `${file}: ${r.signal ?? ""} ${r.stderr} (the comparison hung or crashed)`);
      assert.deepEqual(JSON.parse(r.stdout), { fifo: false, fifo_first: false, link: false, directory: false, same: true, different: false, missing: false }, file);
    });
  });
}

/** The two texts of the comparison, with the name and the block size taken out: every copy in the tree holds one of them. */
function functionText(src: string): { name: string; text: string } | null {
  const m = src.match(/^def (_?same_bytes)\(.*?(?=^\S)/ms);
  return m ? { name: m[1], text: m[0].replace(/\s+$/, "") } : null;
}

export const SAME_BYTES_SHA = "be5900ae7e40d28756b884eff38cf3787d69e0bf4487b838e49d868460f00375";

test("every copy of the comparison in the tree is the one fixed text (the macOS unified_log staging check is the one left, and it is not a placing)", async () => {
  const seen = new Map<string, string[]>();
  for (const file of await runFiles()) {
    const f = functionText(await readFile(file, "utf8"));
    if (!f) continue;
    const key = sha(f.text.replace(/^def _?same_bytes/, "def same_bytes").replaceAll("CHUNK", "1 << 20"));
    seen.set(key, [...(seen.get(key) ?? []), file.slice(ROOT.length + 1).replaceAll("\\", "/")]);
  }
  const groups = [...seen.entries()].sort((a, b) => b[1].length - a[1].length);
  assert.equal(groups.length, 2, JSON.stringify(groups.map(([k, v]) => [k.slice(0, 10), v.length])));
  assert.equal(groups[0][0], SAME_BYTES_SHA);
  assert.equal(groups[0][1].length, 59, "56 carriers before the three tools of ransomware-response added since (encryption_extent, recovery_validate, ransomware_scope_report)");
  assert.deepEqual(groups[1][1], ["packs/macos-forensics/tools/unified_log/run.py"]);
});

test("mem_carve with no hit and a FIFO planted at its own results_to names the result beside it and ends (it hung for ever, and only SIGKILL ended it)", async () => {
  await scratch(async (dir) => {
    await mkdir(join(dir, "inputs"), { recursive: true });
    await mkdir(join(dir, "work", "s1"), { recursive: true });
    await writeFile(join(dir, "inputs", "clean.raw"), Buffer.alloc(10_000, 0x41));
    execFileSync("mkfifo", [join(dir, "work", "s1", "hits.jsonl")]);
    const child = spawn("python3", [rel("packs/memory-forensics/tools/mem_carve/run.py")], { cwd: dir, env: { ...process.env, AGENT_ID: "s1" } });
    const out: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => out.push(c));
    child.stdin.end(JSON.stringify({ path: "inputs/clean.raw", results_to: "work/s1/hits.jsonl" }));
    const timer = setTimeout(() => child.kill("SIGKILL"), 30_000);
    const code = await new Promise<number | null>((resolve) => child.on("close", (c) => resolve(c)));
    clearTimeout(timer);
    assert.equal(code, 0, "the tool ended by itself");
    const answer = JSON.parse(Buffer.concat(out).toString("utf8")) as Record<string, unknown>;
    assert.ok(["complete", "partial"].includes(String(answer.status)), String(answer.status));
    const names = await readdir(join(dir, "work", "s1"));
    assert.ok(names.includes("hits-2.jsonl"), names.join(","));
  });
});

// ---------------------------------------------------------------------------------------------------------------------
// Part 2: PLACE (a stop between taking the name and the move), STOP (the word of the early answer), PAGE (the abort loop)
// ---------------------------------------------------------------------------------------------------------------------

/** The block's own text, run, with a stop injected at the first step after the final name is taken. */
const PLACE_STOP_CASES = String.raw`
import json, os, sys, signal, time, errno, re, hashlib
from pathlib import Path
src = open(sys.argv[1], encoding="utf8").read()
name, d, mode = sys.argv[2], Path(sys.argv[3]), sys.argv[4]
begin, end = src.index("# BEGIN SHARED " + name), src.index("# END SHARED " + name)
GUARD = {"depth": 0, "pending": None, "stopping": False}
def checkpoint():
    pass
exec(src[begin:end], globals())
signal.alarm(20)
tmp = d / ".tmp-result"
tmp.write_bytes(b"result bytes\n" * 50)
final = d / "hits.jsonl"
class Stop(BaseException):
    pass
if mode == "kill":
    # SIGKILL at the first step after the name is taken: the move of the old way, the removal of the hidden name of the new one
    def die(*a, **k):
        os.kill(os.getpid(), signal.SIGKILL)
    real_unlink = os.unlink
    def unlink(p, *a, **k):
        if str(p) == str(tmp):
            die()
        return real_unlink(p, *a, **k)
    os.replace = die
    os.unlink = unlink
    place_without_replacing(tmp, final)
elif mode == "unwind":
    # a file system with no hard links, and a stop that unwinds (the signal handler raises) right after the empty name is created
    def nolink(*a, **k):
        raise OSError(errno.EPERM, "no hard links here")
    os.link = nolink
    real_close = os.close
    def handler(signum, frame):
        raise Stop()
    signal.signal(signal.SIGTERM, handler)
    def close(fd):
        real_close(fd)
        os.kill(os.getpid(), signal.SIGTERM)
        time.sleep(0.05)
    os.close = close
    try:
        place_without_replacing(tmp, final)
        print(json.dumps({"stopped": False}))
    except Stop:
        os.close = real_close
        print(json.dumps({"stopped": True, "final_exists": os.path.lexists(final), "tmp_exists": tmp.exists()}))
elif mode == "nolink":
    # a file system with no hard links, nothing stopping: the older way still places the file, and keeps the rules
    def nolink(*a, **k):
        raise OSError(errno.EPERM, "no hard links here")
    os.link = nolink
    got = place_without_replacing(tmp, final)
    again = d / ".tmp-again"
    again.write_bytes(b"result bytes\n" * 50)
    same = place_without_replacing(again, final)
    print(json.dumps({"first": got.name, "size": got.stat().st_size, "again": same.name, "again_tmp_gone": not again.exists(), "tmp_gone": not tmp.exists()}))
`;

function runPlaceStop(file: string, block: string, dir: string, mode: string) {
  return py(PLACE_STOP_CASES, [rel(file), block, dir, mode]);
}

for (const [file, block] of PLACE_CARRIERS) {
  test(`${file}: a stop right after the final name is taken leaves no empty file at it`, async () => {
    await scratch(async (dir) => {
      const killed = runPlaceStop(file, block, dir, "kill");
      assert.equal(killed.signal, "SIGKILL", `${file}: ${killed.stderr}`);
      const final = join(dir, "hits.jsonl");
      const names = await readdir(dir);
      if (names.includes("hits.jsonl")) assert.equal((await readFile(final)).length, 650, `${file}: a file at the final name after SIGKILL is the whole result`);
      assert.ok(names.includes(".tmp-result") || names.includes("hits.jsonl"), "the result is somewhere");
    });
    await scratch(async (dir) => {
      const r = runPlaceStop(file, block, dir, "unwind");
      assert.equal(r.status, 0, `${file}: ${r.stderr}`);
      assert.deepEqual(JSON.parse(r.stdout), { stopped: true, final_exists: false, tmp_exists: true }, `${file}: no hard links, a stop that unwinds`);
    });
    await scratch(async (dir) => {
      const r = runPlaceStop(file, block, dir, "nolink");
      assert.equal(r.status, 0, `${file}: ${r.stderr}`);
      assert.deepEqual(JSON.parse(r.stdout), { first: "hits.jsonl", size: 650, again: "hits.jsonl", again_tmp_gone: true, tmp_gone: true }, `${file}: no hard links, no stop`);
    });
  });
}

const STOP_CARRIERS = {
  windows: [
    "packs/ransomware-response/tools/ransom_note_scan/run.py",
    "packs/ransomware-response/tools/encrypted_survey/run.py",
    "packs/ransomware-response/tools/encryption_extent/run.py",
    "packs/ransomware-response/tools/recovery_validate/run.py",
    "packs/ransomware-response/tools/ransomware_scope_report/run.py",
    "packs/windows-forensics/tools/regkv/run.py",
    "packs/windows-forensics/tools/lnk_parse/run.py",
    "packs/reverse-engineering/tools/pe_info/run.py",
    "tool-library/regkv/run.py",
  ],
  encrypted: [
    "packs/encrypted-containers/tools/crypto_id/run.py",
    "packs/encrypted-containers/tools/archive_probe/run.py",
    "packs/encrypted-containers/tools/recovery_key_scan/run.py",
    "packs/encrypted-containers/tools/password_recover/run.py",
    "packs/encrypted-containers/tools/tcrypt_header/run.py",
  ],
};

/** The STOP block's own text, run: SIGTERM at once, so the generic last word of the early window is what is answered. */
const STOP_CASE = String.raw`
import json, os, sys, signal, time
src = open(sys.argv[1], encoding="utf8").read()
begin, end = src.index("# BEGIN SHARED STOP"), src.index("# END SHARED STOP")
seal = lambda answer: answer
exec(src[begin:end], globals())
os.kill(os.getpid(), signal.SIGTERM)
time.sleep(10)
`;

for (const [lineage, files] of Object.entries(STOP_CARRIERS)) {
  for (const file of files) {
    test(`${file}: SIGTERM in the early window answers status failed with interrupted true, never status interrupted (${lineage} lineage)`, () => {
      const r = py(STOP_CASE, [rel(file)]);
      assert.equal(r.status, 143, `${file}: ${r.signal ?? ""} ${r.stderr}`);
      const answer = JSON.parse(r.stdout) as Record<string, unknown>;
      assert.equal(answer.status, "failed", file);
      assert.equal(answer.interrupted, true, file);
      assert.equal(answer.signal, 15, file);
      assert.match(String(answer.status_basis), /^[^.]*stopped by signal 15[^.]*$/, `${file}: one sentence`);
    });
  }
}

test("no carrier of the STOP block, in either lineage, can print a status of interrupted", async () => {
  let n = 0;
  for (const file of await runFiles()) {
    const text = await readFile(file, "utf8");
    const m = text.match(/^# BEGIN SHARED STOP$[\s\S]*?^# END SHARED STOP$/m);
    if (!m || file.includes("macos-forensics")) continue; // the macOS lineage is not changed by this sweep
    n += 1;
    assert.doesNotMatch(m[0], /"status": "interrupted"/, file);
  }
  assert.ok(n >= 35, `${n} carriers`);
});

/** A failure that ends a memory tool while a second signal lands in the loop that drops the pages' temporary files. */
const PAGE_CASE = String.raw`
import contextlib, importlib.util, io, json, os, signal, sys, tempfile
spec = importlib.util.spec_from_file_location("m", sys.argv[1])
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
d = tempfile.mkdtemp()
os.chdir(d)
os.environ.pop("JOB_ID", None)
os.environ.pop("OUT", None)
os.environ["AGENT_ID"] = "s1"
signal.signal(signal.SIGTERM, m._on_signal)
signal.alarm(20)
real = m.LosslessPage("t", ["k"], 1)
for i in range(3):
    real.add({"n": i})
class Boom:
    def abort(self):
        os.kill(os.getpid(), signal.SIGTERM)   # the signal lands in the middle of the loop
m.PAGES.insert(0, Boom())
buf = io.StringIO()
code = None
try:
    with contextlib.redirect_stdout(buf):
        m.fail("a refusal")
except SystemExit as exc:
    code = exc.code
except BaseException as exc:  # noqa: BLE001
    code = "raised " + type(exc).__name__
left = sorted(os.listdir(os.path.join(d, "work", "s1", "tool-output")))
print(json.dumps({"code": code, "out": buf.getvalue(), "left": left}))
`;

for (const tool of ["mem_carve", "mem_fs", "mem_profile"]) {
  test(`${tool}: a signal in the loop that drops the pages' temporary files gives one answer and leaves no hidden page file`, () => {
    const r = py(PAGE_CASE, [rel("packs", "memory-forensics", "tools", tool, "run.py")]);
    assert.equal(r.status, 0, `${tool}: ${r.signal ?? ""} ${r.stderr}`);
    const got = JSON.parse(r.stdout) as { code: unknown; out: string; left: string[] };
    assert.equal(got.code, 1, `${tool}: ${JSON.stringify(got.code)}`);
    const docs = got.out.trim().split("\n").filter((l) => l.trim() !== "");
    const whole = JSON.parse(got.out) as { status?: string };
    assert.equal(whole.status, "failed", `${tool}: one document, the failed answer (${docs.length} lines)`);
    assert.deepEqual(got.left, [], `${tool}: no hidden page file is left`);
  });
}

// ---------------------------------------------------------------------------------------------------------------------
// Part 3: PROCESS (both lineages): identity before a kill, a ps that cannot list, the deadline walk
// ---------------------------------------------------------------------------------------------------------------------

const PROCESS_CARRIERS = [
  "packs/reverse-engineering/tools/fuzzy_hash/run.py", // general lineage
  "packs/network-forensics/tools/zeek_run/run.py", // general lineage
  "packs/windows-forensics/tools/extract_stream/run.py", // windows lineage
  "tool-library/yara_scan/run.py", // windows lineage, the library's copy
];

/** What the cases share: the block's own text, run in a program of its own that leads its group (the way the harness starts a tool). */
const PROCESS_HEAD = String.raw`
import json, os, signal, subprocess, sys, time
src = open(sys.argv[1], encoding="utf8").read()
case, work = sys.argv[2], sys.argv[3]
begin, end = src.index("# BEGIN SHARED PROCESS"), src.index("# END SHARED PROCESS")
def describe(exc):
    return "%s: %s" % (type(exc).__name__, exc)
exec(src[begin:end], globals())
try:
    os.setpgrp()
except OSError:
    pass
signal.alarm(60)
def cmdlines(marker):
    found = []
    for entry in os.listdir("/proc"):
        if entry.isdigit():
            try:
                with open("/proc/%s/cmdline" % entry, "rb") as fh:
                    text = fh.read().replace(b"\0", b" ").decode("utf8", "replace")
                with open("/proc/%s/stat" % entry, "rb") as fh:
                    state = fh.read().rsplit(b")", 1)[1].split()[0]
            except OSError:
                continue
            if marker in text and state != b"Z" and int(entry) != os.getpid():
                found.append(int(entry))
    return found
def alive(pid):
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    with open("/proc/%d/stat" % pid, "rb") as fh:
        return fh.read().rsplit(b")", 1)[1].split()[0] != b"Z"
def wait_for_marker(marker, n=1):
    end_at = time.monotonic() + 10
    while time.monotonic() < end_at:
        if len(cmdlines(marker)) >= n:
            return cmdlines(marker)
        time.sleep(0.01)
    return cmdlines(marker)
def clean(marker):
    for pid in cmdlines(marker):
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass
out = {}
`;

const PROCESS_CASES: Record<string, string> = {
  // a listed pid whose identity changes before the kill is left alone; the same tree with the identity as listed is ended
  identity: String.raw`
for label, reuse in (("same", False), ("reused", True)):
    marker = "sleep 61.1%d" % (1 if reuse else 2)
    proc = spawn(["sh", "-c", marker + " & wait"], stdout=subprocess.DEVNULL)
    ACTIVE.append(proc)
    pids = wait_for_marker(marker, 2)
    if reuse and "_read_ident" in globals():
        real = _read_ident
        def fake(pid, kind, _real=real, _pids=set(pids)):
            got = _real(pid, kind)
            return ("proc", -1) if pid in _pids and got is not None else got   # as if the pid had been another process when it was listed
        globals()["_read_ident"] = fake
    kill_tree(proc)
    ACTIVE.remove(proc)
    time.sleep(0.3)
    out[label] = {"sleeper_alive": any(alive(p) for p in pids), "program_gone": proc.poll() is not None}
    clean(marker)
print(json.dumps(out))
`,
  // a pid that was seen below the tool and has been taken by another process is not ended by reap_orphans
  reap: String.raw`
for label, wrong in (("same", False), ("reused", True)):
    marker = "sleep 61.3%d" % (1 if wrong else 2)
    made = subprocess.run(["sh", "-c", marker + " >/dev/null 2>&1 & echo $!"], stdout=subprocess.PIPE, text=True)
    pid = int(made.stdout.strip())
    time.sleep(0.2)
    SEEN.add(pid)
    now = process_ident(pid) if "process_ident" in globals() else None
    SEEN_IDENT[pid] = ("proc", -5) if wrong else now
    reap_orphans()
    time.sleep(0.3)
    out[label] = {"alive": alive(pid)}
    clean(marker)
print(json.dumps(out))
`,
  // the process listing is made to fail (no /proc, no libproc), and ps is a stand-in that fails or sleeps past PS_WAIT
  unlisted: String.raw`
real_isdir = os.path.isdir
os.path.isdir = lambda p: False if p == "/proc/self" else real_isdir(p)
_children_libproc = lambda pid: None
PS_WAIT = 1
os.environ["PATH"] = work + ":" + os.environ["PATH"]
marker = "sleep 61.4%s" % sys.argv[4]
proc = spawn(["sh", "-c", marker + " & wait"], stdout=subprocess.DEVNULL)
ACTIVE.append(proc)
pids = wait_for_marker(marker, 2)
note = kill_tree(proc)
ACTIVE.remove(proc)
time.sleep(0.2)
out["kill_tree"] = {"note": note, "program_gone": proc.poll() is not None, "sleeper_alive": any(alive(p) for p in pids)}
clean(marker)
marker = "sleep 61.5%s" % sys.argv[4]
proc = spawn(["sh", "-c", marker + " & wait"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
ACTIVE.append(proc)
pids = wait_for_marker(marker, 2)
o, e, timed_out = communicate_bounded(proc, 1.0)
ACTIVE.remove(proc)
out["communicate"] = {"timed_out": timed_out, "stderr": e.decode("utf8", "replace"), "program_gone": proc.poll() is not None}
out["descendants_flag"] = bool(getattr(descendants(os.getpid()), "not_listed", False))
clean(marker)
print(json.dumps(out))
`,
  // a program that forks fast, below the one that is killed, on the deadline path: nothing it forked is left
  forker: String.raw`
script = os.path.join(work, "forker.py")
open(script, "w").write("import os, sys, time\nfor i in range(int(sys.argv[1])):\n    if os.fork() == 0:\n        os.execv('/bin/sleep', ['sleep', '61.6'])\ntime.sleep(61)\n")
left = []
for attempt in range(5):
    proc = spawn(["sh", "-c", "python3 %s 200 & wait" % script], stdout=subprocess.DEVNULL)
    ACTIVE.append(proc)
    wait_for_marker("sleep 61.6", 4)
    kill_tree(proc)
    ACTIVE.remove(proc)
    end_at = time.monotonic() + 5     # a killed process is gone a moment later, longer on a loaded host
    while time.monotonic() < end_at and len(cmdlines("sleep 61.6")) + len(cmdlines("forker.py")):
        time.sleep(0.05)
    left.append(len(cmdlines("sleep 61.6")) + len(cmdlines("forker.py")))
    clean("sleep 61.6")
    clean("forker.py")
print(json.dumps({"left": left}))
`,
};

function processCase(file: string, name: string, work: string, extra: string[] = []) {
  return py(PROCESS_HEAD + PROCESS_CASES[name], [rel(file), name, work, ...extra], 90_000);
}

for (const file of PROCESS_CARRIERS) {
  test(`${file}: a listed pid whose start time changed before the kill is not signalled; an unchanged one is`, async () => {
    await scratch(async (dir) => {
      const r = processCase(file, "identity", dir);
      assert.equal(r.status, 0, `${file}: ${r.signal ?? ""} ${r.stderr}`);
      assert.deepEqual(JSON.parse(r.stdout), { same: { sleeper_alive: false, program_gone: true }, reused: { sleeper_alive: true, program_gone: true } }, file);
    });
  });

  test(`${file}: a pid seen below the tool that another process has taken is not ended by reap_orphans`, async () => {
    await scratch(async (dir) => {
      const r = processCase(file, "reap", dir);
      assert.equal(r.status, 0, `${file}: ${r.signal ?? ""} ${r.stderr}`);
      assert.deepEqual(JSON.parse(r.stdout), { same: { alive: false }, reused: { alive: true } }, file);
    });
  });

  for (const [label, body] of [["fails", "#!/bin/sh\nexit 1\n"], ["sleeps past PS_WAIT", "#!/bin/sh\nexec sleep 30\n"]] as const) {
    test(`${file}: with no /proc and no libproc a ps that ${label} is not read as an empty tree: the answer says the tree could not be listed`, async () => {
      await scratch(async (dir) => {
        await writeFile(join(dir, "ps"), body, { mode: 0o755 });
        const r = processCase(file, "unlisted", dir, [label === "fails" ? "1" : "2"]);
        assert.equal(r.status, 0, `${file}: ${r.signal ?? ""} ${r.stderr}`);
        const got = JSON.parse(r.stdout) as Record<string, any>;
        assert.match(String(got.kill_tree.note), /could not be listed/, file);
        assert.equal(got.kill_tree.program_gone, true, "the program itself is still ended");
        assert.equal(got.communicate.timed_out, true);
        assert.match(got.communicate.stderr, /could not be listed/, file);
        assert.equal(got.communicate.program_gone, true);
        assert.equal(got.descendants_flag, true, "the list descendants() gives for a caller that cannot take an exception says it is not listed");
      });
    });
  }

  test(`${file}: a fast forker below the program on the deadline path leaves no descendant (5 tries)`, async () => {
    await scratch(async (dir) => {
      const r = processCase(file, "forker", dir);
      assert.equal(r.status, 0, `${file}: ${r.signal ?? ""} ${r.stderr}`);
      assert.deepEqual(JSON.parse(r.stdout), { left: [0, 0, 0, 0, 0] }, file);
    });
  });
}
