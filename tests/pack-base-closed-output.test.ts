/**
 * computer-forensics-base: a program that closes its standard output and goes on running does not hold a tool past its own clock.
 *
 * archive_extract (its zstd program reader), chunk_needles and icat_extract (icat, in the pack and in the tool library) and the
 * archive-members recipe (7z) read the program's pipe themselves to its end and then waited for the program with no bound, so a
 * program that closed the pipe and kept running held the tool until the harness killed it. The stand-ins here print a little, write
 * their pid, close standard output and sleep: the answer must come within the tool's clock and a small grace, be one JSON document,
 * be partial (never complete), and the stand-in must be gone. The stand-ins prove nothing about the real programs' output.
 */
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { chmod, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { PYTHON3 } from "./host-gates.ts";
import { LIB, ROOT } from "./tool-library-harness.ts";

const BASE = (kind: string, name: string): string => join(ROOT, "packs", "computer-forensics-base", kind, name, "run.py");

type Run = { code: number | null; stdout: string; stderr: string; ms: number };

// A program that prints `text`, writes its pid, closes its standard output and sleeps.
const closesAndSleeps = (text: string): string => `#!/usr/bin/env python3
import os, sys, time
sys.stdout.buffer.write(${JSON.stringify(text)}.encode()); sys.stdout.flush()
open(os.environ["STUB_PID"], "w").write(str(os.getpid()))
os.close(1)
time.sleep(300)
`;

async function place(fn: (cwd: string, bin: string, pidPath: string) => Promise<void>): Promise<void> {
  const cwd = await realpath(await mkdtemp(join(process.platform === "darwin" ? "/tmp" : tmpdir(), "closed-output-")));
  const bin = join(cwd, "bin");
  try {
    await mkdir(bin, { recursive: true });
    await mkdir(join(cwd, "inputs"), { recursive: true });
    await mkdir(join(cwd, "work"), { recursive: true });
    await fn(cwd, bin, join(cwd, "standin.pid"));
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
}

async function stub(bin: string, name: string, text: string): Promise<void> {
  await writeFile(join(bin, name), text);
  await chmod(join(bin, name), 0o755);
}

function run(script: string, cwd: string, bin: string, pidPath: string, stdin: unknown, argv: string[] = [], env: Record<string, string> = {}): Promise<Run> {
  const began = Date.now();
  return new Promise((resolve, reject) => {
    const child = spawn(PYTHON3, [script, ...argv], { cwd, env: { ...process.env, PATH: `${bin}:${process.env.PATH ?? ""}`, STUB_PID: pidPath, AGENT_ID: "s1", ...env } });
    const out: Buffer[] = [], err: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => out.push(c));
    child.stderr.on("data", (c: Buffer) => err.push(c));
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stdout: Buffer.concat(out).toString("utf8"), stderr: Buffer.concat(err).toString("utf8"), ms: Date.now() - began }));
    child.stdin.end(stdin === null ? "" : JSON.stringify(stdin));
  });
}

/** Whether the process is gone, giving it a moment. */
async function gone(pid: number, waitMs = 5_000): Promise<boolean> {
  const until = Date.now() + waitMs;
  for (;;) {
    try {
      process.kill(pid, 0);
    } catch {
      return true;
    }
    if (Date.now() > until) return false;
    await new Promise((r) => setTimeout(r, 50));
  }
}

const GRACE_MS = 4_000;   // the interpreter's start, the answer and a loaded host, above the tool's own clock

async function check(out: Run, clockSeconds: number, pidPath: string): Promise<Record<string, unknown>> {
  assert.ok(out.ms < clockSeconds * 1000 + GRACE_MS, `answered after ${out.ms} ms`);
  assert.doesNotMatch(out.stderr, /Traceback/);
  const answer = JSON.parse(out.stdout);      // one JSON document: a second one, or none, does not parse
  assert.equal(answer.status, "partial", JSON.stringify(answer).slice(0, 800));
  assert.notEqual(answer.complete, true);
  const pid = Number((await readFile(pidPath, "utf8")).trim());
  assert.ok(pid > 0, "the stand-in wrote its pid, so it was the program that closed its output");
  assert.equal(await gone(pid), true, "the stand-in was ended");
  return answer;
}

for (const [where, script] of [["pack", BASE("tools", "chunk_needles")], ["tool-library", join(LIB, "chunk_needles", "run.py")]] as const) {
  test(`chunk_needles (${where}): an icat that closes its output and goes on running is ended at the clock; the answer is partial from where its stream ended`, async () => {
    await place(async (cwd, bin, pidPath) => {
      await stub(bin, "icat", closesAndSleeps("a needle in the stream\n".repeat(4)));
      await writeFile(join(cwd, "inputs", "disk.img"), Buffer.alloc(4096));
      const out = await run(script, cwd, bin, pidPath, { image: "inputs/disk.img", inode: 5, offset: 0, needles: "needle", max_seconds: 5 });
      const answer = await check(out, 5, pidPath) as Record<string, any>;
      assert.equal(answer.hits.needle.ascii, 4, "what icat gave before it closed its output is scanned");
      assert.equal(answer.next_start, 4 * "a needle in the stream\n".length);
      assert.match(answer.status_basis, /icat closed its output but was still running when the scan's clock ran out/);
      assert.match(answer.stopped, /its exit status was not seen/);
    });
  });
}

for (const [where, script] of [["pack", BASE("tools", "icat_extract")], ["tool-library", join(LIB, "icat_extract", "run.py")]] as const) {
  test(`icat_extract (${where}): an icat that closes its output and goes on running is ended at the clock; the file keeps its partial name`, async () => {
    await place(async (cwd, bin, pidPath) => {
      await stub(bin, "icat", closesAndSleeps("stream bytes\n".repeat(8)));
      await writeFile(join(cwd, "inputs", "disk.img"), Buffer.alloc(4096));
      const out = await run(script, cwd, bin, pidPath, { image: "inputs/disk.img", inode: 5, offset: 0, output: "work/s1/out.bin", max_seconds: 5 });
      const answer = await check(out, 5, pidPath) as Record<string, any>;
      assert.equal(answer.path, "work/s1/out.bin.partial");
      assert.equal(answer.size, 8 * "stream bytes\n".length);
      assert.match(answer.problem, /icat closed its output but was still running when the time budget of 5 seconds was reached/);
    });
  });
}

test("archive_extract: a zstd program that closes its output and goes on running is ended at the clock; the run stops at max_seconds, partial", async (t) => {
  if (spawnSync(PYTHON3, ["-c", "import compression.zstd"]).status === 0) {
    t.skip("this Python has compression.zstd, which archive_extract uses before the zstd program: the program's pipe is not read here");
    return;
  }
  await place(async (cwd, bin, pidPath) => {
    await stub(bin, "zstd", closesAndSleeps(""));
    // A zstd frame's magic number (RFC 8878, 0xFD2FB528 little-endian) and bytes that are not a frame: only the signature is read before the program.
    await writeFile(join(cwd, "inputs", "a.tar.zst"), Buffer.concat([Buffer.from([0x28, 0xb5, 0x2f, 0xfd]), Buffer.from("not a frame body")]));
    const out = await run(BASE("tools", "archive_extract"), cwd, bin, pidPath, { path: "inputs/a.tar.zst", out_dir: "work/s1/a", max_seconds: 6 });
    const answer = await check(out, 6, pidPath) as Record<string, any>;
    assert.equal(answer.stopped_by, "max_seconds");
    assert.match(answer.stop, /the zstd program, which had closed its output, was still running/);
  });
});

test("archive-members recipe: a 7z that closes its output and goes on running is ended at the recipe's clock; the listing is partial", async () => {
  await place(async (cwd, bin, pidPath) => {
    const listing = "Path = a.txt\nSize = 3\nPacked Size = 3\nModified = 2020-01-01 00:00:00\nAttributes = A\n\n";
    for (const name of ["7z", "7zz", "7za", "7zr"]) await stub(bin, name, closesAndSleeps(listing));
    // The 7z signature (7z\xBC\xAF\x27\x1C) and a version; the stand-in does the listing.
    await writeFile(join(cwd, "inputs", "a.7z"), Buffer.concat([Buffer.from([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c, 0x00, 0x04]), Buffer.alloc(100)]));
    const target = JSON.stringify({ paths: ["inputs/a.7z"] });
    const out = await run(BASE("recipes", "archive-members"), cwd, bin, pidPath, null, ["run", "--target", target, "--out", "work/am"], { RECIPE_SECONDS: "6" });
    const answer = await check(out, 6, pidPath) as Record<string, any>;
    assert.equal(answer.members, 1);
    const coverage = JSON.parse(await readFile(join(cwd, "work", "am", "coverage.json"), "utf8"));
    assert.match(JSON.stringify(coverage.limits_hit), /7z closed its output after 1 members but was still running at the deadline/);
  });
});
