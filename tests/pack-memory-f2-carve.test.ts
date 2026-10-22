/**
 * mem_carve, after the second review of the memory-forensics pack: the clock is looked at before every slice that is cut out, the slices
 * count toward max_results_bytes, max_extract has a cap, every call makes progress however little time it is given, the parents of
 * an extract directory are private, and an early end of file is counted for what was read. Every case here fails on the tool as it was
 * at the head of the first fix round. The clock and the file size are faked by a sitecustomize on PYTHONPATH (tests/memory-f1-support.ts).
 */
import assert from "node:assert/strict";
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
