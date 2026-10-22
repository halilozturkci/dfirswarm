/**
 * mem_carve, after the review of the memory-forensics pack: its own clock and result-size limit with a place to resume, the gate on cutting
 * slices out (write_values, a job, SECRET_OUTPUT), the meaning of `truncated`, signals, status, results that are never replaced, and the
 * bounds on `limit`. Every case here fails on the tool as it was on main.
 */
import assert from "node:assert/strict";
import { mkdir, readFile, readdir, stat, symlink, truncate, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { withCwd } from "./tool-library-harness.ts";
import { CARVE, json, runTool } from "./memory-f1-support.ts";

type Hit = { kind: string; signature_offset: number; object_offset: number | null; validation: string; validation_detail: string; declared_bytes?: number; requested_bytes: number; available_bytes: number; cut_complete: boolean | null; extract_status?: string; extracted_to?: string; extracted_bytes?: number };
type Carve = {
  status: string; status_basis: string; hit_count: number; hits: Hit[]; truncated: boolean; complete_results?: string; complete_results_note?: string;
  coverage: { start: number; end: number; ended: string; resume_start?: number; max_seconds: number }; bytes_swept: number;
  extraction?: { extracted: number; refused: number; not_exported?: number; not_extracted: number; manifest?: string };
  limit_clamped_to?: number; error?: string; signal?: number; partial_results?: string | null; resume_start?: number; hit_count_so_far?: number;
};
const job = (cwd: string): Record<string, string> => ({ JOB_ID: "j000001", OUT: join(cwd, "work", "s1"), SECRET_OUTPUT: "1" });
const lines = async (path: string): Promise<Hit[]> => (await readFile(path, "utf8")).trimEnd().split("\n").map((l) => JSON.parse(l) as Hit);
const hiveBlock = (minor: number): Buffer => {
  const b = Buffer.alloc(4096);
  b.write("regf", 0, "latin1");
  b.writeUInt32LE(1, 0x14);
  b.writeUInt32LE(minor, 0x18);
  return b;
};
/** `count` registry-hive signatures at 16-byte spacing: a hit every 16 bytes, from a few kilobytes. */
const dense = (count: number): Buffer => {
  const blob = Buffer.alloc(count * 16);
  for (let i = 0; i < count; i++) blob.write("regf", i * 16, "latin1");
  return blob;
};

test("mem_carve stops at max_results_bytes, says partial, and resumes without a gap or a duplicate (P1-1)", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "dense.raw"), dense(40_000));
    const first = json<Carve>(await runTool(CARVE, cwd, { path: "work/dense.raw", results_to: "work/s1/a.jsonl", max_results_bytes: 1 << 20 }));
    assert.equal(first.status, "partial");
    assert.match(first.status_basis, /result size limit/);
    const resume = first.coverage.resume_start as number;
    assert.ok(resume > 0 && resume < 40_000 * 16, `stopped inside the image (${resume})`);
    assert.equal(first.hit_count, resume / 16, "every hit before resume_start, and no other, is in the answer");
    assert.equal(first.bytes_swept, resume);
    const second = json<Carve>(await runTool(CARVE, cwd, { path: "work/dense.raw", results_to: "work/s1/b.jsonl", start: resume, max_results_bytes: 1 << 30 }));
    assert.equal(second.status, "complete");
    const all = [...(await lines(join(cwd, "work/s1/a.jsonl"))), ...(await lines(join(cwd, "work/s1/b.jsonl")))];
    assert.deepEqual(all.map((h) => h.signature_offset), Array.from({ length: 40_000 }, (_, i) => i * 16), "the two runs together are the oracle's hit list");
  });
});

test("mem_carve stops at max_seconds within a couple of seconds, with a resume offset, and refuses a bound past its cap (P1-1)", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "dense.raw"), dense(1_500_000)); // 24 MB, 1.5M hits: several seconds of work
    const run = await runTool(CARVE, cwd, { path: "work/dense.raw", results_to: "work/s1/t.jsonl", max_seconds: 1 });
    const out = json<Carve>(run);
    assert.equal(out.status, "partial");
    assert.match(out.status_basis, /time limit: max_seconds 1/);
    assert.ok(run.ms < 9000, `ended in ${run.ms} ms`);
    assert.ok((out.coverage.resume_start as number) > 0);
    assert.equal(out.coverage.max_seconds, 1);
    for (const bad of [0, 781, 1.5, "10", true]) {
      const refused = json<Carve>(await runTool(CARVE, cwd, { path: "work/dense.raw", max_seconds: bad }));
      assert.equal(refused.status, "failed");
      assert.match(refused.error as string, /max_seconds must be an integer from 1 to 780/);
    }
  });
});

test("mem_carve ends with one JSON answer on SIGTERM, exit 143, and names the partial hit list (P2-5)", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "dense.raw"), dense(2_500_000));
    const run = await runTool(CARVE, cwd, { path: "work/dense.raw", results_to: "work/s1/sig.jsonl" }, {}, undefined, "SIGTERM", 1500);
    assert.equal(run.code, 143, run.stderr);
    assert.doesNotMatch(run.stderr, /Traceback/);
    const out = json<Carve>(run);
    assert.equal(out.status, "interrupted");
    assert.equal(out.signal, 15);
    assert.match(out.partial_results as string, /sig\.jsonl\.partial$/);
    const rows = await lines(out.partial_results as string);
    assert.ok(rows.length > 0);
    assert.equal(rows.length, out.hit_count_so_far, "whole lines only, as many as were counted");
    assert.equal(out.resume_start, rows[rows.length - 1].signature_offset + 1);
    const names = await readdir(join(cwd, "work", "s1"));
    assert.deepEqual(names.filter((n) => n.endsWith(".partial")), ["sig.jsonl.partial"], "no hidden partial is left behind");
    const hup = await runTool(CARVE, cwd, { path: "work/dense.raw", limit: 5 }, {}, undefined, "SIGINT", 1000);
    assert.equal(hup.code, 130);
    assert.doesNotMatch(hup.stderr, /Traceback|KeyboardInterrupt/);
    assert.equal(json<Carve>(hup).status, "interrupted");
  });
});

test("mem_carve cuts slices out only with write_values in a job run as secret output, into a 0700 directory with 0600 files (P2-3)", async () => {
  await withCwd(async (cwd) => {
    const blob = Buffer.alloc(0x3000);
    hiveBlock(5).copy(blob, 0x1000);
    await writeFile(join(cwd, "work", "m.raw"), blob);
    const ask = { path: "work/m.raw", extract_to: "work/s1/carved" };
    // 1. no flag
    const noFlag = json<Carve>(await runTool(CARVE, cwd, ask, job(cwd)));
    assert.equal(noFlag.status, "failed");
    assert.match(noFlag.error as string, /write_values: true/);
    // 2. not a job
    const outside = json<Carve>(await runTool(CARVE, cwd, { ...ask, write_values: true }));
    assert.match(outside.error as string, /refused outside a job/);
    // 3. a job that is not secret output
    const plain = json<Carve>(await runTool(CARVE, cwd, { ...ask, write_values: true }, { JOB_ID: "j1", OUT: join(cwd, "work", "s1") }));
    assert.match(plain.error as string, /not run as secret output/);
    await assert.rejects(stat(join(cwd, "work", "s1", "carved")), "nothing was created by a refusal");
    // 4. the hit list needs none of it
    const listing = json<Carve>(await runTool(CARVE, cwd, { path: "work/m.raw" }));
    assert.equal(listing.hit_count, 1);
    // 5. all three
    const ok = json<Carve>(await runTool(CARVE, cwd, { ...ask, write_values: true }, job(cwd)));
    assert.equal(ok.extraction?.extracted, 1);
    assert.equal((await stat(join(cwd, "work", "s1", "carved"))).mode & 0o777, 0o700);
    assert.equal((await stat(ok.hits[0].extracted_to as string)).mode & 0o777, 0o600);
  });
});

test("mem_carve calls a structure truncated only when the file ends first, and cuts a Prefetch record to its declared length (P2-4)", async () => {
  await withCwd(async (cwd) => {
    // A SQLite header declaring 5000 pages of 4096 bytes (20,480,000), counter 7 valid for 7, with 30 MB behind it.
    const sqlite = Buffer.alloc(30_000_000);
    sqlite.write("SQLite format 3\0", 0, "latin1");
    sqlite.writeUInt16BE(4096, 16);
    sqlite[18] = 1; sqlite[19] = 1;
    sqlite.writeUInt32BE(7, 24); sqlite.writeUInt32BE(5000, 28); sqlite.writeUInt32BE(7, 92);
    // A plain version-30 Prefetch record declaring 300,000 bytes, present whole.
    const pf = Buffer.alloc(300_000);
    pf.writeUInt32LE(30, 0); pf.write("SCCA", 4, "latin1"); pf.writeUInt32LE(300_000, 0x0c);
    const blob = Buffer.concat([sqlite, Buffer.alloc(4096), pf]);
    await writeFile(join(cwd, "work", "m.raw"), blob);
    const out = json<Carve>(await runTool(CARVE, cwd, { path: "work/m.raw", kinds: ["SQLite database", "prefetch record"] }));
    const [db, rec] = out.hits;
    assert.equal(db.validation, "header plausible", "not truncated: the file holds the declared 20 MB");
    assert.equal(db.declared_bytes, 20_480_000);
    assert.equal(db.requested_bytes, 20_480_000);
    assert.equal(db.cut_complete, true);
    assert.equal(rec.validation, "header plausible");
    assert.equal(rec.object_offset, 30_000_000 + 4096);
    assert.equal(rec.requested_bytes, 300_000, "the cut grows to the declared length, up to the kind's cap");
    assert.equal(rec.cut_complete, true);
    // The file ends inside the declared length: that is truncated.
    await writeFile(join(cwd, "work", "short.raw"), sqlite.subarray(0, 9_000_000));
    const cut = json<Carve>(await runTool(CARVE, cwd, { path: "work/short.raw" }));
    assert.equal(cut.hits[0].validation, "truncated");
    assert.match(cut.hits[0].validation_detail, /the file ends 9000000 bytes after the structure's start, before the 20480000 bytes/);
    assert.equal(cut.hits[0].cut_complete, false);
    // Declared above the cap: plausible, and the cut says it is not the whole.
    const huge = Buffer.from(sqlite.subarray(0, 4096));
    huge.writeUInt32BE(25_000, 28); // 25,000 pages: 102,400,000 bytes, more than the kind's 64 MiB cap
    await writeFile(join(cwd, "work", "huge.raw"), huge);
    await truncate(join(cwd, "work", "huge.raw"), 110_000_000); // sparse
    const capped = json<Carve>(await runTool(CARVE, cwd, { path: "work/huge.raw", kinds: ["SQLite database"] }));
    assert.equal(capped.hits[0].validation, "header plausible");
    assert.equal(capped.hits[0].requested_bytes, 64 << 20);
    assert.equal(capped.hits[0].cut_complete, false);
  });
});

test("mem_carve never replaces a results file or writes through a link; the result takes the next free name (P2-10)", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "d.raw"), dense(2000));
    await mkdir(join(cwd, "work", "s1"), { recursive: true });
    const big = json<Carve>(await runTool(CARVE, cwd, { path: "work/d.raw", results_to: "work/s1/r.jsonl" }));
    const bigBytes = (await readFile(join(cwd, "work/s1/r.jsonl"))).length;
    const small = json<Carve>(await runTool(CARVE, cwd, { path: "work/d.raw", results_to: "work/s1/r.jsonl", max_bytes: 4000 }));
    assert.equal((await readFile(join(cwd, "work/s1/r.jsonl"))).length, bigBytes, "the larger earlier file was kept");
    assert.match(small.complete_results as string, /r-2\.jsonl$/);
    assert.match(small.complete_results_note as string, /next free name/);
    assert.equal(big.hit_count, 2000);
    // the same result again names the file that already holds it
    const again = json<Carve>(await runTool(CARVE, cwd, { path: "work/d.raw", results_to: "work/s1/r.jsonl" }));
    assert.match(again.complete_results as string, /r\.jsonl$/);
    // a link is refused, and its target untouched
    await writeFile(join(cwd, "work/s1/victim.txt"), "do not touch");
    await symlink(join(cwd, "work/s1/victim.txt"), join(cwd, "work/s1/l.jsonl"));
    const link = json<Carve>(await runTool(CARVE, cwd, { path: "work/d.raw", results_to: "work/s1/l.jsonl" }));
    assert.equal(link.status, "failed");
    assert.match(link.error as string, /symbolic link/);
    assert.equal(await readFile(join(cwd, "work/s1/victim.txt"), "utf8"), "do not touch");
  });
});

test("mem_carve carries status and status_basis in every answer and fails with JSON on a wrong type (P2-11, P3-12)", async () => {
  await withCwd(async (cwd) => {
    const blob = Buffer.alloc(0x2000);
    hiveBlock(5).copy(blob, 0x1000);
    await writeFile(join(cwd, "work", "m.raw"), blob);
    const ok = json<Carve>(await runTool(CARVE, cwd, { path: "work/m.raw" }));
    assert.equal(ok.status, "complete");
    assert.match(ok.status_basis, /every byte of the range 0 to 8192/);
    // a refused extract makes the sweep partial
    await mkdir(join(cwd, "work", "s1", "carved"), { recursive: true });
    await writeFile(join(cwd, "work", "s1", "carved", "000000001000-registry_hive.bin"), "x");
    const refused = json<Carve>(await runTool(CARVE, cwd, { path: "work/m.raw", extract_to: "work/s1/carved", write_values: true }, job(cwd)));
    assert.equal(refused.status, "partial");
    assert.match(refused.status_basis, /refused or failed/);
    for (const args of [{ path: "work/nothing.raw" }, { path: "work/m.raw", kinds: 5 }, { path: "work/m.raw", extract_to: 5 }, { path: "work/m.raw", write_values: "yes" }]) {
      const bad = json<Carve>(await runTool(CARVE, cwd, args));
      assert.equal(bad.status, "failed");
      assert.ok((bad.status_basis as string).length > 20);
      assert.doesNotMatch(bad.error as string, /unexpected failure/);
    }
  });
});

test("mem_carve clamps limit and says so, and counts a refused slice toward max_extract (P2-12, P3-8)", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "d.raw"), dense(20_000));
    const out = json<Carve>(await runTool(CARVE, cwd, { path: "work/d.raw", limit: 1_000_000_000 }));
    assert.equal(out.limit_clamped_to, 5000);
    assert.equal(out.hits.length, 5000);
    assert.equal(out.hit_count, 20_000);
    assert.equal(out.truncated, true);
    assert.ok(out.complete_results, "the rest is in the file the answer names");
    assert.equal((await lines(join(cwd, out.complete_results as string))).length, 20_000);
    // max_extract 1 with the first slice's name taken: the second hit is not cut in its place
    const blob = Buffer.alloc(0x3000);
    hiveBlock(5).copy(blob, 0x1000); hiveBlock(5).copy(blob, 0x2000);
    await writeFile(join(cwd, "work", "two.raw"), blob);
    await mkdir(join(cwd, "work", "s1", "c"), { recursive: true });
    await writeFile(join(cwd, "work", "s1", "c", "000000001000-registry_hive.bin"), "x");
    const two = json<Carve>(await runTool(CARVE, cwd, { path: "work/two.raw", extract_to: "work/s1/c", max_extract: 1, write_values: true }, job(cwd)));
    assert.equal(two.extraction?.refused, 1);
    assert.equal(two.extraction?.extracted, 0, "the earliest candidate was the one tried");
    assert.equal(two.extraction?.not_extracted, 1);
  });
});
