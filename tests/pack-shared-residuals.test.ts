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
  assert.equal(groups[0][1].length, 56);
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
