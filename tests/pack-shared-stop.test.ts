/**
 * The stop block (# BEGIN SHARED STOP) in its three lineages (windows and ransomware: 64 lines; macos-forensics; encrypted-containers),
 * and the memory pack's page block (# BEGIN SHARED PAGE, the 185-line text). What is held, each with a case that fails on the text
 * that came before:
 *
 *  - the handlers are in as soon as the module has run as far as the block, not when main() starts: a signal in that gap used to
 *    kill the process with no answer. The gap is made deterministic by running the source up to the end of the block and sending
 *    the signal there; the time before that (the start of the interpreter, the compiling of the file) cannot be closed from inside
 *    the file and is not claimed;
 *  - a stop signal that comes while the final answer is being written does not cut the answer: the tool is blocked in the write
 *    (its stdout is not read), the signal is sent, and the whole document must arrive;
 *  - a page that cannot flush its temporary file (disk full, a quota) still removes that file and raises nothing from abort().
 */
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { ROOT } from "./tool-library-harness.ts";

const sha = (text: string): string => createHash("sha256").update(text).digest("hex");
const PINS: Record<string, string> = {
  windows: "a14f0cf911ea78baeb78749e447ea802f2da101febe03e1f6faa8636bfe59019",
  macos: "c2e19b97dbdc3943294c42a9573427e487199059969d25cee3171a7d908a1675",
  encrypted: "1c2073b19c6881895643b72d190304b9386356c9e7f74a2e6625efeecc95ab11",
  page: "36e9ed0641414393ce86f2a4a0bcd2f97a0c925d3f04dcefdf6e5d4a0d0cd09a",
};

async function carriers(marker: string): Promise<string[]> {
  const found: string[] = [];
  const walk = async (dir: string): Promise<void> => {
    for (const e of await readdir(dir, { withFileTypes: true })) {
      const full = join(dir, e.name);
      if (e.isDirectory()) {
        if (e.name !== "node_modules" && e.name !== "__pycache__") await walk(full);
      } else if (e.name === "run.py" && (await readFile(full, "utf8")).includes(marker)) found.push(full);
    }
  };
  await walk(join(ROOT, "packs"));
  await walk(join(ROOT, "tool-library"));
  return found.sort();
}

function cut(text: string, name: string): string {
  const begin = `# BEGIN SHARED ${name}`;
  const end = `# END SHARED ${name}`;
  const start = text.indexOf(begin);
  const stop = text.indexOf(end);
  assert.ok(start >= 0 && stop > start);
  return text.slice(start, stop + end.length);
}

function lineage(path: string): "windows" | "macos" | "encrypted" {
  if (path.includes("/macos-forensics/")) return "macos";
  if (path.includes("/encrypted-containers/")) return "encrypted";
  return "windows";
}

test("every carrier of the stop block holds the text of its lineage, byte for byte; the memory tools hold one page block", async () => {
  const files = await carriers("# BEGIN SHARED STOP");
  assert.ok(files.length >= 14, `${files.length} carriers`);
  for (const file of files) assert.equal(sha(cut(await readFile(file, "utf8"), "STOP")), PINS[lineage(file)], `${file} (${lineage(file)})`);
  const memory = (await carriers("# BEGIN SHARED PAGE")).filter((f) => f.includes("/memory-forensics/"));
  assert.equal(memory.length, 3);
  for (const file of memory) assert.equal(sha(cut(await readFile(file, "utf8"), "PAGE")), PINS.page, file);
});

// --- a signal after the block and before main() ----------------------------------------------------------------------------

async function early(file: string, signal: "SIGTERM" | "SIGINT" | "SIGHUP"): Promise<{ code: number | null; stdout: string; stderr: string }> {
  const dir = await mkdtemp(join(tmpdir(), "stop-early-"));
  try {
    const text = await readFile(file, "utf8");
    const end = text.indexOf("# END SHARED STOP");
    const prefix = text.slice(0, text.indexOf("\n", end) + 1);
    const script = join(dir, "prefix.py");
    await writeFile(script, `${prefix}\nimport os as _os, signal as _signal, time as _time\n_os.kill(_os.getpid(), _signal.${signal})\n_time.sleep(30)\nprint("survived")\n`);
    const ran = spawnSync("python3", [script], { cwd: dir, encoding: "utf8", timeout: 60_000, env: { ...process.env, AGENT_ID: "s1" } });
    return { code: ran.status, stdout: ran.stdout, stderr: ran.stderr };
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

const NUMBER = { SIGTERM: 15, SIGINT: 2, SIGHUP: 1 } as const;

test("a stop signal after the block has run and before main() installs the tool's own handlers gives one JSON answer and exit 128 + the signal, in every carrier", async () => {
  for (const file of await carriers("# BEGIN SHARED STOP")) {
    const ran = await early(file, "SIGTERM");
    assert.equal(ran.code, 128 + NUMBER.SIGTERM, `${file}: ${ran.stderr}`);
    const lines = ran.stdout.trim().split("\n");
    assert.equal(lines.length >= 1, true);
    const answer = JSON.parse(ran.stdout);
    assert.ok(answer.status === "interrupted" || answer.status === "failed" || answer.status === "partial", `${file}: ${ran.stdout}`);
    assert.doesNotMatch(ran.stderr, /Traceback/, file);
  }
});

test("SIGINT and SIGHUP in that gap end each lineage the same way", async () => {
  for (const file of [
    join(ROOT, "packs", "ransomware-response", "tools", "ransom_note_scan", "run.py"),
    join(ROOT, "packs", "macos-forensics", "tools", "plist_read", "run.py"),
    join(ROOT, "packs", "encrypted-containers", "tools", "crypto_id", "run.py"),
  ]) {
    for (const signal of ["SIGINT", "SIGHUP"] as const) {
      const ran = await early(file, signal);
      assert.equal(ran.code, 128 + NUMBER[signal], `${file} ${signal}: ${ran.stderr}`);
      JSON.parse(ran.stdout);
      assert.doesNotMatch(ran.stderr, /Traceback/, `${file} ${signal}`);
    }
  }
});

// --- a signal while the final answer is being written -----------------------------------------------------------------------

/** Run a tool whose answer is a few megabytes with its stdout unread, send `signal` while it is blocked in the write, then read all of it. */
async function signalledDuringPrint(script: string, cwd: string, args: unknown): Promise<{ code: number | null; stdout: string }> {
  const child = spawn("python3", [script], { cwd, env: { ...process.env, AGENT_ID: "s1" }, stdio: ["pipe", "pipe", "ignore"] });
  const chunks: Buffer[] = [];
  child.stdin.end(JSON.stringify(args));
  const closed = new Promise<number | null>((resolve) => child.on("close", (code) => resolve(code)));
  await new Promise<void>((resolve) => {
    child.stdout.once("data", (c: Buffer) => {
      chunks.push(c);
      child.stdout.pause();
      resolve();
    });
  });
  await new Promise((r) => setTimeout(r, 500));
  assert.equal(child.exitCode, null, "the tool ended before it could be signalled: the answer was too small to fill the pipe");
  child.kill("SIGTERM");
  await new Promise((r) => setTimeout(r, 200));
  child.stdout.on("data", (c: Buffer) => chunks.push(c));
  child.stdout.resume();
  const code = await closed;
  return { code, stdout: Buffer.concat(chunks).toString("utf8") };
}

async function noteTree(cwd: string, dirs: number): Promise<void> {
  for (let i = 0; i < dirs; i++) {
    const d = join(cwd, "work", "ev", `d${String(i).padStart(4, "0")}`);
    await mkdir(d, { recursive: true });
    await writeFile(join(d, "README.txt"), `Your files are encrypted. Decrypt them: pay in bitcoin.\nyour personal id: ${"Z9".repeat(8)}${i}\n`);
    await writeFile(join(d, "a.docx.locked"), randomBytes(2000));
  }
}

for (const [name, tool] of [["ransom_note_scan", "ransom_note_scan"], ["encrypted_survey", "encrypted_survey"]] as const) {
  test(`${name}: a stop signal while the answer is being written leaves one complete JSON document`, async () => {
    const cwd = await mkdtemp(join(tmpdir(), "stop-print-"));
    try {
      await noteTree(cwd, 3000);
      const ran = await signalledDuringPrint(join(ROOT, "packs", "ransomware-response", "tools", tool, "run.py"), cwd, { root: "work/ev", limit: 1_000_000 });
      assert.ok(ran.stdout.length > 1_000_000, `${ran.stdout.length} bytes`);
      const answer = JSON.parse(ran.stdout);
      assert.notEqual(answer.status, "interrupted");
      assert.equal(ran.code, 0, "the answer was written whole and the tool ended by itself");
    } finally {
      await rm(cwd, { recursive: true, force: true });
    }
  });
}

// --- a page that cannot flush ----------------------------------------------------------------------------------------------

const PAGE_CASE = String.raw`
from __future__ import annotations
import errno, hashlib, json, os, re, resource, signal, sys, tempfile
from pathlib import Path
src = open(sys.argv[1]).read()
block = re.search(r"^# BEGIN SHARED PAGE\n.*?^# END SHARED PAGE\n", src, re.S | re.M).group(0)
ns = {"errno": errno, "hashlib": hashlib, "json": json, "os": os, "re": re, "Path": Path, "GUARD": {"depth": 0}, "checkpoint": lambda: None}
exec(compile(block, "page-block", "exec"), ns)
signal.signal(signal.SIGXFSZ, signal.SIG_IGN)       # a write past the limit is then EFBIG, the error a full disk gives as ENOSPC
os.chdir(tempfile.mkdtemp())
page = ns["LosslessPage"]("t", "k", 1)
for i in range(50):
    page.add({"i": i, "pad": "x" * 100})
tmp = str(page._tmp)
resource.setrlimit(resource.RLIMIT_FSIZE, (10, 10))
try:
    page.abort()
    page.abort()
    raised = None
except OSError as exc:
    raised = type(exc).__name__
print(json.dumps({"raised": raised, "left": os.path.exists(tmp), "tmp_cleared": page._tmp is None}))
`;

test("a page whose temporary file cannot be flushed (disk full, a quota) is still removed by abort(), and abort() raises nothing", async () => {
  for (const tool of ["mem_carve", "mem_fs", "mem_profile"]) {
    const ran = spawnSync("python3", ["-c", PAGE_CASE, join(ROOT, "packs", "memory-forensics", "tools", tool, "run.py")], { encoding: "utf8", timeout: 60_000 });
    assert.equal(ran.status, 0, ran.stderr);
    assert.deepEqual(JSON.parse(ran.stdout), { raised: null, left: false, tmp_cleared: true }, tool);
  }
});
