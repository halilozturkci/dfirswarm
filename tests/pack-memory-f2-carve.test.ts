/**
 * mem_carve, after the second review of the memory-forensics pack: the clock is looked at before every slice that is cut out, the slices
 * count toward max_results_bytes, max_extract has a cap, every call makes progress however little time it is given, the parents of
 * an extract directory are private, and an early end of file is counted for what was read. Every case here fails on the tool as it was
 * at the head of the first fix round. The clock and the file size are faked by a sitecustomize on PYTHONPATH (tests/memory-f1-support.ts).
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { readFile, readdir, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { withCwd } from "./tool-library-harness.ts";
import { CARVE, json, runTool, shimDir } from "./memory-f1-support.ts";

type Hit = { kind: string; signature_offset: number; extracted_to?: string; extract_status?: string };
type Carve = {
  status: string; status_basis: string; hit_count: number; hits: Hit[]; bytes_swept: number; error?: string; complete_results?: string;
  coverage: { start: number; end: number; ended: string; resume_start?: number; file_bytes: number; bytes_read: number };
  extraction?: { extracted: number; extracted_bytes?: number; not_extracted: number; max_extract: number };
};
const job = (cwd: string): Record<string, string> => ({ JOB_ID: "j000001", OUT: join(cwd, "work", "s1"), SECRET_OUTPUT: "1" });

/** A SQLite database header that passes the tool's check: 4096-byte pages, one page, change counter equal to version-valid-for. */
const sqliteHead = (): Buffer => {
  const b = Buffer.alloc(100);
  b.write("SQLite format 3\u0000", 0, "latin1");
  b.writeUInt16BE(4096, 16);
  b[18] = 1;
  b[19] = 1;
  b.writeUInt32BE(7, 24);
  b.writeUInt32BE(1, 28);
  b.writeUInt32BE(7, 92);
  return b;
};
const sqliteImage = (count: number, spacing: number, size: number): Buffer => {
  const blob = Buffer.alloc(size, 0x41);
  for (let i = 0; i < count; i++) sqliteHead().copy(blob, i * spacing);
  return blob;
};

test("mem_carve looks at the clock before every slice it cuts out, and stops there with a resume offset (P2-2)", async () => {
  await withCwd(async (cwd) => {
    const shim = await shimDir(cwd);
    await writeFile(join(cwd, "work", "db.raw"), sqliteImage(50, 8192, 50 * 8192));
    // The clock moves one second at every look: max_seconds 5 allows five looks. The tool's old clock was looked at once, for the first hit.
    const run = await runTool(CARVE, cwd, { path: "work/db.raw", extract_to: "work/s1/ex", write_values: true, max_extract: 1000, max_seconds: 5 },
      { ...job(cwd), PYTHONPATH: shim, FAKE_CLOCK_STEP: "1" });
    const out = json<Carve>(run);
    assert.equal(out.status, "partial", run.stdout.slice(0, 400));
    assert.match(out.status_basis, /time limit: max_seconds 5/);
    const cut = out.extraction?.extracted as number;
    assert.ok(cut >= 1 && cut < 50, `${cut} slices were cut before the clock ran out`);
    assert.equal(out.hit_count, cut, "no hit is reported past the one the sweep stopped at");
    assert.equal(out.coverage.resume_start, cut * 8192, "the resume offset is the first hit that was not reported");
    assert.equal((await readdir(join(cwd, "work", "s1", "ex"))).filter((n) => n.endsWith(".bin")).length, cut, "a file for every slice and no other");
    // the rest, from resume_start, joined to the first part, is all fifty
    const rest = json<Carve>(await runTool(CARVE, cwd, { path: "work/db.raw", start: out.coverage.resume_start, extract_to: "work/s1/ex2", write_values: true, max_extract: 1000 }, job(cwd)));
    assert.equal(rest.status, "complete");
    assert.equal(cut + rest.hit_count, 50);
  });
});

test("the slices cut out count toward max_results_bytes, so a large cut stops the sweep (P2-2)", async () => {
  await withCwd(async (cwd) => {
    // five databases, each cut 2 MiB (the kind's size) from an image of 3.5 MiB: the hit list is tiny, the slices are not
    await writeFile(join(cwd, "work", "db.raw"), sqliteImage(5, 700 * 1024, 3_670_016));
    const out = json<Carve>(await runTool(CARVE, cwd, { path: "work/db.raw", extract_to: "work/s1/ex", write_values: true, max_results_bytes: 1 << 20 }, job(cwd)));
    assert.equal(out.status, "partial");
    assert.match(out.status_basis, /result size limit: the hit list and the slices cut out reached max_results_bytes 1048576/);
    assert.equal(out.extraction?.extracted, 1);
    assert.ok((out.extraction?.extracted_bytes ?? 0) >= 1 << 20);
    assert.equal(out.coverage.resume_start, 700 * 1024, "the next hit is where to go on");
  });
});

test("max_extract has a cap of 1,000 and the refusal says why (P2-2)", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "db.raw"), sqliteImage(2, 8192, 16384));
    for (const max_extract of [1001, 100000, 1e9]) {
      const refused = json<Carve>(await runTool(CARVE, cwd, { path: "work/db.raw", extract_to: "work/s1/ex", write_values: true, max_extract }, job(cwd)));
      assert.equal(refused.status, "failed");
      assert.match(refused.error as string, /max_extract must be an integer from 0 to 1000: each slice is up to 64 MiB/);
    }
    const ok = json<Carve>(await runTool(CARVE, cwd, { path: "work/db.raw", extract_to: "work/s1/ex", write_values: true, max_extract: 1000 }, job(cwd)));
    assert.equal(ok.extraction?.extracted, 2);
    assert.equal(json<Carve>(await runTool(CARVE, cwd, { path: "work/db.raw", max_extract: -1 })).status, "failed");
  });
});

test("a call makes progress however little time it is given, so a resume loop ends (P3-8)", async () => {
  await withCwd(async (cwd) => {
    const shim = await shimDir(cwd);
    // 10 MiB, a hit every 64 KiB; the clock is past max_seconds at its very first look
    const blob = Buffer.alloc(10 << 20);
    const oracle: number[] = [];
    for (let at = 0; at < blob.length - 4; at += 64 * 1024) { blob.write("regf", at, "latin1"); oracle.push(at); }
    await writeFile(join(cwd, "work", "slow.raw"), blob);
    const all: number[] = [];
    let start = 0;
    let calls = 0;
    for (; calls < 20; calls++) {
      const out = json<Carve>(await runTool(CARVE, cwd, { path: "work/slow.raw", start, max_seconds: 1, results_to: `work/s1/part${calls}.jsonl` }, { PYTHONPATH: shim, FAKE_CLOCK_STEP: "1000" }));
      const rows = (await readFile(join(cwd, "work", "s1", `part${calls}.jsonl`), "utf8")).trimEnd().split("\n").filter(Boolean).map((l) => JSON.parse(l) as Hit);
      all.push(...rows.map((h) => h.signature_offset));
      assert.ok(out.hit_count >= 1, `call ${calls} reported a hit`);
      if (out.status === "complete") break;
      assert.equal(out.status, "partial");
      assert.ok((out.coverage.resume_start as number) > start, `call ${calls} moved resume_start from ${start} to ${out.coverage.resume_start}`);
      start = out.coverage.resume_start as number;
    }
    assert.ok(calls < 20, "the resume loop ended");
    assert.deepEqual(all, oracle, "the calls joined are the whole hit list, no gap and no duplicate");
  });
});

test("the parents of an extract directory are private too, and the answer counts the slices' bytes (P3-1)", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "db.raw"), sqliteImage(1, 8192, 16384));
    const out = json<Carve>(await runTool(CARVE, cwd, { path: "work/db.raw", extract_to: "work/s1/a/b/ex", write_values: true }, job(cwd)));
    assert.equal(out.extraction?.extracted, 1);
    for (const dir of ["a", "a/b", "a/b/ex"]) assert.equal((await stat(join(cwd, "work", "s1", dir))).mode & 0o777, 0o700, dir);
    assert.equal(out.extraction?.extracted_bytes, 16384);
  });
});

test("an early end of file counts what was read as swept, and reports a signature in its last bytes (P3-3)", async () => {
  await withCwd(async (cwd) => {
    const shim = await shimDir(cwd);
    const blob = Buffer.alloc(102400);
    blob.write("regf", 1000, "latin1");
    blob.write("regf", 102396, "latin1");           // the last four bytes of the file
    await writeFile(join(cwd, "work", "short.raw"), blob);
    // the file was measured 8,192 bytes longer than it is when read
    const out = json<Carve>(await runTool(CARVE, cwd, { path: "work/short.raw" }, { PYTHONPATH: shim, FAKE_GETSIZE_EXTRA: "8192", FAKE_GETSIZE_SUFFIX: "short.raw" }));
    assert.equal(out.status, "partial");
    assert.match(out.status_basis, /early end of file/);
    assert.equal(out.coverage.bytes_read, 102400);
    assert.equal(out.bytes_swept, 102400, "swept what was read, not the length the file was measured at");
    assert.deepEqual(out.hits.map((h) => h.signature_offset), [1000, 102396]);
  });
});

// The tool is loaded as a module (nothing runs until run_guarded), SYNC_EVERY is made small, and os.fsync is replaced by one that records
// when it was called and, the first time, takes longer than the whole clock: the periodic fsync of an explicit hit list, which sits inside
// the clocked loop, is then started after the deadline unless the loop stops starting them.
const FSYNC_PROBE = `
import importlib.util, json, os, sys, time
spec = importlib.util.spec_from_file_location("carve", sys.argv[1])
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
m.SYNC_EVERY = 2048
calls, real, t0 = [], os.fsync, time.monotonic()
def slow(fd):
    calls.append(time.monotonic() - t0)
    if len(calls) == 1:
        time.sleep(1.5)
    real(fd)
os.fsync = slow
try:
    m.run_guarded()
finally:
    sys.stderr.write(json.dumps(calls))
`;

test("with results_to, a periodic fsync is not started once the clock has run out (the final one is)", async () => {
  await withCwd(async (cwd) => {
    // 3,000 hits in one window (fewer than the 4,096 between two looks at the clock), so only the periodic fsyncs can be late
    const blob = Buffer.alloc(3000 * 16 + 4096);
    for (let i = 0; i < 3000; i++) blob.write("%PDF-", i * 16, "latin1");
    await writeFile(join(cwd, "work", "dense.raw"), blob);
    const run = await new Promise<{ code: number | null; stdout: string; stderr: string }>((resolve) => {
      const child = spawn("python3", ["-c", FSYNC_PROBE, CARVE], { cwd, env: { ...process.env, AGENT_ID: "s1" }, stdio: ["pipe", "pipe", "pipe"] });
      const out: Buffer[] = [], err: Buffer[] = [];
      child.stdout.on("data", (c: Buffer) => out.push(c));
      child.stderr.on("data", (c: Buffer) => err.push(c));
      child.stdin.end(JSON.stringify({ path: "work/dense.raw", kinds: ["PDF"], limit: 1, max_seconds: 1, results_to: "work/s1/hits.jsonl" }));
      const hard = setTimeout(() => child.kill("SIGKILL"), 60_000);
      child.on("close", (code) => { clearTimeout(hard); resolve({ code, stdout: Buffer.concat(out).toString("utf8"), stderr: Buffer.concat(err).toString("utf8") }); });
    });
    const out = JSON.parse(run.stdout) as Carve;
    assert.equal(out.hit_count, 3000, run.stdout);
    const calls = JSON.parse(run.stderr.trim().split("\n").pop() as string) as number[];
    assert.ok(calls.length >= 2, `the probe saw ${calls.length} fsync calls`);
    assert.ok(calls[0] < 1, "the first periodic fsync should start before the 1 s clock");
    const late = calls.slice(0, -1).filter((t) => t > 1.1);      // all but the last call, which is the final fsync at the end of the sweep
    assert.equal(late.length, 0, `${late.length} periodic fsync(s) were started after the deadline`);
  });
});

test("the manifest and the docstring give the measured end of the spill path at the 16 GiB cap, and the cap they measured is the one in the code", async () => {
  const dir = join(CARVE, "..");
  const manifest = JSON.parse(await readFile(join(dir, "manifest.json"), "utf8")) as { description: string; timeout_seconds: number };
  const code = (await readFile(CARVE, "utf8")).replace(/\s+/g, " ");
  assert.doesNotMatch(manifest.description, /was not measured/);
  assert.doesNotMatch(code, /was not measured/);
  assert.match(manifest.description, /fed 16 GiB took 4\.1 s .{0,120}51\.7 s/);
  assert.match(code, /took 4\.1 s .{0,400}51\.7 s/);
  assert.match(code, /MAX_RESULT_BYTES_DEFAULT, MAX_RESULT_BYTES_CAP, MAX_RESULT_BYTES_FLOOR = 1 << 30, 16 << 30, 1 << 20/, "the cap that was measured (16 GiB) changed");
  // the figures leave room: 780 s of clock + the measured end of a rerun (51.7 s) is inside the manifest's timeout
  assert.ok(780 + 52 <= manifest.timeout_seconds);
});
