/**
 * A sweep's line is bounded (Batman III, the run s17fdfe: a sweep its budget
 * ended wrote one row an unsearched object into its line, 97,000 to 193,000
 * rows, 33 to 51 MB a line; the hub parsed the file whole at fourteen call
 * sites and rendered the list into ledger.md under the table lock for each
 * record: 621 MB of heap to parse, a 265 MB ledger.md, records that held
 * the lock for 7 to 97 s).
 *
 * What it did not search is a summary on the line and a file beside the
 * ledger; nothing made from a sweep in words is longer than a few KB; the
 * sweeps are read once and kept; a record renders ledger.md after the table
 * lock is let go. A line from before the change (the whole list in it) is
 * read bounded, and read again under the new rules it names its file.
 * Synthetic runs; the run s17fdfe's own file is read where it is, when it
 * is there, and never written.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { copyFile, mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import * as P from "../extensions/protocol.ts";
import * as SW from "../extensions/store-sweep.ts";
import { checkLedgerAnswers } from "../scripts/check-answers.ts";
import { A, coverage, F, ok, planned, rec, REVIEW, run } from "./negative-bar-fixture.ts";

const mine: string[] = [];
after(async () => {
  for (const d of mine) {
    spawnSync("chmod", ["-R", "u+w", d]);
    await rm(d, { recursive: true, force: true });
  }
});

const sha = (s: string | Buffer) => createHash("sha256").update(s).digest("hex");
const ROWS = 200_000;

/** A committed job whose manifest lists `n` files (ten bytes each, in 400 directories): a store too large to list by hand. Only the manifest is written: a sweep whose byte budget is under ten bytes opens none of them. */
async function hugeJob(S: string, id: string, n: number): Promise<void> {
  const dir = join(S, "store", "jobs", id);
  await mkdir(join(dir, "out"), { recursive: true });
  const files = Array.from({ length: n }, (_, i) => ({ path: `Users/dir${String(i % 400).padStart(3, "0")}/AppData/Local/Packages/file-${String(i).padStart(6, "0")}.dat`, sha256: sha(`f${i}`), bytes: 10 }));
  await writeFile(join(dir, "manifest.json"), JSON.stringify({ files }));
  await writeFile(join(dir, "job.json"), JSON.stringify({ id, state: "committed", requester: { agent: "a0" }, status: "ok", exit: 0, spec: { kind: "command", scope: "declared", inputs: ["input:disk.E01"], command: "extract" } }));
}

/** The longest the table lock was seen held while `during` ran: its directory looked for at every turn of the loop. */
async function lockHeld(S: string, during: () => Promise<unknown>): Promise<number> {
  const lock = join(S, "locks", ".table.lock");
  let since = 0;
  let longest = 0;
  let done = false;
  const p = during().finally(() => (done = true));
  while (!done) {
    const now = performance.now();
    if (existsSync(lock)) {
      since ||= now;
      longest = Math.max(longest, now - since);
    } else since = 0;
    await new Promise<void>((r) => setImmediate(r));
  }
  await p;
  return longest;
}

test("a sweep that left 200,000 objects writes a line under 64 KB and names the list in a file of 200,000 rows; its words, the gate's item and ledger.md stay small, and a record made beside it holds the table lock for milliseconds", async () => {
  const { S, a0, a1, a2 } = await run();
  await hugeJob(S, "j900000", ROWS);
  await planned(a0, "2");
  const abs = ok(await rec(a0, { kind: "absence", value: "a remote tool", source: "the disk", evidence: "a search", refs: ["job:j000001/hits.txt"], control: { ref: "job:j000001/hits.txt", found: "the same search finds a planted row" }, answers: ["2"] })).entry;
  // A byte budget no object fits in: every object of the store is named unsearched.
  process.env.SWARM_SWEEP_MAX_BYTES = "5";
  let cov: P.LedgerEntry;
  let before = 0;
  try {
    cov = ok(await rec(a0, coverage("2", ["input:disk.E01"], [`E-${abs.seq}`], { looked_for: ["mallory"] }))).entry;
    before = (await stat(join(S, P.LEDGER_MD))).size;
    await SW.awaitSweeps(S);
  } finally {
    delete process.env.SWARM_SWEEP_MAX_BYTES;
  }
  const text = await readFile(join(S, SW.LEDGER_SWEEPS), "utf8");
  const lines = text.split("\n").filter(Boolean);
  assert.equal(lines.length, 1);
  assert.ok(Buffer.byteLength(lines[0]!) < 64 * 1024, `the line is ${Buffer.byteLength(lines[0]!)} bytes`);
  assert.equal(SW.verifySweepChain(text).ok, true);
  const sw = SW.sweepOf(cov, await SW.readSweeps(S))!;
  assert.equal(sw.state, "partial");
  const all = sw.unsearched_all!;
  assert.ok(all, "the list is summarised");
  assert.ok(all.total >= ROWS && all.total < ROWS + 20, String(all.total));
  assert.equal(SW.unsearchedTotal(sw), all.total);
  assert.equal(all.left, 0, "an object larger than a pass's budget is no pass's to search");
  assert.deepEqual(all.by_reason.map((r) => [r.code, r.count]), [["too_large", all.total]]);
  assert.equal(all.by_prefix.reduce((n, p) => n + p.count, 0), all.total, "every object is counted under a directory");
  assert.ok(all.by_prefix.length <= SW.SWEEP_UNSEARCHED_PREFIXES + 1);
  assert.deepEqual(all.by_prefix[0], { prefix: "job:j900000/Users", count: ROWS });
  assert.ok(sw.unsearched.length > 0 && sw.unsearched.length <= SW.SWEEP_UNSEARCHED_SAMPLE, "a few are named on the line");
  assert.match(sw.unsearched[0]!.why, /would pass the sweep's byte budget \(5, SWARM_SWEEP_MAX_BYTES\) by themselves/);
  // The whole list, in its file: named by its sha256, a row an object, each with its reason's code.
  const file = all.file!;
  assert.match(file.path, /^ledger\/sweeps\/unsearched-[0-9a-f]{64}\.jsonl$/);
  const body = await readFile(join(S, file.path));
  assert.equal(sha(body), file.sha256);
  assert.ok(file.path.includes(file.sha256));
  const rows = body.toString("utf8").split("\n").filter(Boolean);
  assert.equal(rows.length, all.total);
  assert.equal(file.rows, all.total);
  assert.deepEqual(JSON.parse(rows.find((r) => r.includes("file-199999"))!), { ref: "job:j900000/Users/dir399/AppData/Local/Packages/file-199999.dat", why: "too_large" });
  let streamed = 0;
  for await (const row of SW.unsearchedRows(S, sw)) {
    assert.equal(row.code, "too_large");
    streamed += 1;
  }
  assert.equal(streamed, all.total, "and read back as a stream");
  // In words: the summary and the file, never the list.
  const words = SW.sweepWords(sw, cov);
  assert.ok(Buffer.byteLength(words) < 4096, `sweepWords is ${Buffer.byteLength(words)} bytes`);
  assert.match(words, new RegExp(`store sweep partial: 0 object\\(s\\), 0 bytes searched for "mallory"; not searched: ${all.total} object\\(s\\); by reason: ${all.total} too_large .*by directory: job:j900000/Users ${ROWS}.*the whole list: ${file.path} \\(${all.total} rows, sha256 ${file.sha256}\\)`));
  // ledger.md: what the sweep added to it.
  await P.renderLedger(S);
  const grown = (await stat(join(S, P.LEDGER_MD))).size - before;
  assert.ok(grown < 8 * 1024, `ledger.md grew by ${grown} bytes`);
  assert.match(await readFile(join(S, P.LEDGER_MD), "utf8"), /store sweep partial: .*the whole list: ledger\/sweeps\/unsearched-/);
  // The gate's item for an answer that rests on it.
  ok(await rec(a1, { kind: "answer", section: "question:2", value: "No evidence of a remote tool was found on the disk", reasoning: `E-${cov.seq}`, ...A, result: "bounded_negative" }));
  const attested = await P.attestEntry(a2, { seq: cov.seq, how: "ran the search again", review: REVIEW });
  assert.ok(attested.ok, JSON.stringify(attested));
  const r = await checkLedgerAnswers(S, ["2"], ["2"]);
  const d = r.defects.find((x) => x.code === "sweep_partial")!;
  assert.ok(d, r.lines.join("\n").slice(0, 2000));
  assert.ok(Buffer.byteLength(d.what) < 4096 && Buffer.byteLength(d.fix) < 4096, `the gate's item is ${Buffer.byteLength(d.what)} + ${Buffer.byteLength(d.fix)} bytes`);
  assert.match(d.what, new RegExp(`whose store sweep is partial: 0 object\\(s\\) searched, not searched: ${all.total} object\\(s\\); by reason: .*the whole list: ${file.path}`));
  assert.match(d.fix, /a partial sweep is not a clean one/);
  assert.ok(r.lines.join("\n").length < 64 * 1024, "the check's whole answer is small");
  // A record made while that sweep line stands: the table lock is held for the append, not for a render of the list.
  ok(await rec(a0, { kind: "finding", ...F, value: "a warm-up", source: "the disk", evidence: "row 1", refs: ["job:j000001/hits.txt"], answers: ["2"] }));
  const md = (await stat(join(S, P.LEDGER_MD))).size;
  const t0 = performance.now();
  const held = await lockHeld(S, async () => ok(await rec(a0, { kind: "finding", ...F, value: "the export's first row is a header", source: "the disk", evidence: "row 2", refs: ["job:j000001/hits.txt"], answers: ["2"] })));
  const took = performance.now() - t0;
  assert.ok(held < 200, `the table lock was held for ${held.toFixed(1)} ms`);
  assert.ok(took < 2000, `the record took ${took.toFixed(1)} ms`);
  assert.match(await readFile(join(S, P.LEDGER_MD), "utf8"), /the export's first row is a header/, "and ledger.md holds the record when the call returns");
  assert.ok((await stat(join(S, P.LEDGER_MD))).size - md < 2048);
  process.stdout.write(`# 200,000 unsearched: line ${Buffer.byteLength(lines[0]!)} B, list ${body.length} B in ${rows.length} rows, sweepWords ${Buffer.byteLength(words)} B, gate item ${Buffer.byteLength(d.what)} B, ledger.md +${grown} B, table lock held ${held.toFixed(1)} ms of a ${took.toFixed(1)} ms record\n`);
});

test("records made in a burst share a render of ledger.md, each returning after one that read what it wrote", async () => {
  const { S, a0, a1, a2, a3 } = await run();
  const made = await Promise.all([a0, a1, a2, a3, a0, a1, a2, a3].map((c, i) => rec(c, { kind: "finding", ...F, value: `burst finding ${i}`, source: "the disk", evidence: `row ${i}`, refs: ["job:j000001/hits.txt"] })));
  for (const m of made) ok(m);
  const md = await readFile(join(S, P.LEDGER_MD), "utf8");
  for (let i = 0; i < 8; i++) assert.match(md, new RegExp(`burst finding ${i}`));
  // Asked for together, renders that have not begun are one.
  const [x, y, z] = await Promise.all([P.renderLedger(S), P.renderLedger(S), P.renderLedger(S)]);
  assert.equal(x, y);
  assert.equal(y, z);
});

test("the sweeps are read once and kept: a second read parses nothing, an append is added in memory, and a file changed under the process is read again", async () => {
  const { S, a0 } = await run();
  await planned(a0, "2");
  const abs = ok(await rec(a0, { kind: "absence", value: "a remote tool", source: "the disk", evidence: "a search", refs: ["job:j000001/hits.txt"], control: { ref: "job:j000001/hits.txt", found: "the same search finds a planted row" }, answers: ["2"] })).entry;
  const c1 = ok(await rec(a0, coverage("2", ["input:disk.E01"], [`E-${abs.seq}`], { looked_for: ["mallory"] }))).entry;
  await SW.awaitSweeps(S);
  const one = await SW.readSweeps(S);
  assert.equal(one.length, 1);
  assert.equal((await SW.readSweeps(S))[0], one[0], "the same record, not parsed again");
  const c2 = ok(await rec(a0, coverage("2", ["input:disk.E01"], [`E-${abs.seq}`], { looked_for: ["trent"], supersedes: c1.seq }))).entry;
  await SW.awaitSweeps(S);
  const two = await SW.readSweeps(S);
  assert.deepEqual(two.map((s) => s.seq), [c1.seq, c2.seq]);
  assert.equal(two[0], one[0], "the line held is kept; the new one was added to it");
  assert.equal(two[1]!.prev, one[0]!.hash, "chained from the head in memory");
  const file = join(S, SW.LEDGER_SWEEPS);
  assert.equal(SW.verifySweepChain(await readFile(file, "utf8")).ok, true);
  // Another process appends: the lines after the last one read are read, the rest kept.
  const text = await readFile(file, "utf8");
  const extra: SW.SweepRecord = { ...two[1]!, at: new Date().toISOString(), prev: two[1]!.hash };
  extra.hash = SW.sweepHash(extra, two[1]!.hash!);
  await writeFile(file, `${text}${JSON.stringify(extra)}\n`);
  const three = await SW.readSweeps(S);
  assert.equal(three.length, 3);
  assert.equal(three[0], one[0]);
  assert.equal(three[2]!.hash, extra.hash);
  // Rewritten under it: read whole again.
  await writeFile(file, text.split("\n")[0] + "\n");
  const back = await SW.readSweeps(S);
  assert.equal(back.length, 1);
  assert.notEqual(back[0], one[0]);
  assert.deepEqual(back[0], one[0]);
  await writeFile(file, "");
  assert.deepEqual(await SW.readSweeps(S), []);
});

test("a line from before the change, its whole list in it, is read bounded and streamed from where it lies; read again under the new rules it names its file, and what its budget left is searched by the next pass", async () => {
  const { S, a0 } = await run();
  await planned(a0, "2");
  const abs = ok(await rec(a0, { kind: "absence", value: "a remote tool", source: "the disk", evidence: "a search", refs: ["job:j000001/hits.txt"], control: { ref: "job:j000001/hits.txt", found: "the same search finds a planted row" }, answers: ["2"] })).entry;
  const c1 = ok(await rec(a0, coverage("2", ["input:disk.E01"], [`E-${abs.seq}`], { looked_for: ["mallory"] }))).entry;
  const c2 = ok(await rec(a0, coverage("2", ["input:disk.E01", "input:logs/a.log"], [`E-${abs.seq}`], { looked_for: ["trent"] }))).entry;
  await SW.awaitSweeps(S);
  const real = await SW.readSweeps(S);
  // As the older harness wrote them: rules version 3, every unsearched object a row of the line. One line of 30,000 rows (several MB), one of 120.
  const old = (base: SW.SweepRecord, n: number, why: (i: number) => string, prev: string): SW.SweepRecord => {
    const { unsearched_all: _a, pass: _p, continues: _c, prev: _pv, hash: _h, ...rest } = base;
    const line: SW.SweepRecord = { ...rest, rules: 3, state: "partial", unsearched: Array.from({ length: n }, (_, i) => ({ ref: `job:j9${String(i % 7).padStart(5, "0")}/Windows/WinSxS/amd64_"quoted" \\ name ${i}/file-${i}.dll`, why: why(i) })), prev };
    line.hash = SW.sweepHash(line, prev);
    return line;
  };
  const big = old(real.find((s) => s.seq === c1.seq)!, 30_000, (i) => (i % 3 ? `its ${1000 + i} bytes would pass the sweep's byte budget (17179869184, SWARM_SWEEP_MAX_BYTES; 17179860000 searched)` : "the sweep's time budget (1800 s, SWARM_SWEEP_MAX_SEC) ran out before it"), "genesis");
  const small = old(real.find((s) => s.seq === c2.seq)!, 120, () => "it could not be read (EACCES: permission denied)", big.hash!);
  const file = join(S, SW.LEDGER_SWEEPS);
  const text = `${JSON.stringify(big)}\n${JSON.stringify(small)}\n`;
  assert.ok(Buffer.byteLength(JSON.stringify(big)) > 4 * 1024 * 1024);
  await writeFile(file, text);
  assert.equal(SW.verifySweepChain(text).ok, true);
  const held = await SW.readSweeps(S);
  assert.deepEqual(held.map((s) => [s.seq, s.rules, s.hash, s.unsearched.length, SW.unsearchedTotal(s), SW.unsearchedLeft(s), s.unsearched_all?.file]), [
    [c1.seq, 3, big.hash, SW.SWEEP_UNSEARCHED_SAMPLE, 30_000, 30_000, undefined],
    [c2.seq, 3, small.hash, SW.SWEEP_UNSEARCHED_SAMPLE, 120, 0, undefined],
  ]);
  assert.ok(Buffer.byteLength(JSON.stringify(held)) < 64 * 1024, "what is held of both is small");
  assert.deepEqual(held[0]!.unsearched_all!.by_reason.map((r) => [r.code, r.count]), [["bytes", 20_000], ["time", 10_000]]);
  assert.deepEqual(held[1]!.unsearched_all!.by_reason, [{ code: "unreadable", count: 120, why: "they could not be read" }]);
  assert.deepEqual(held[0]!.unsearched[0], big.unsearched[0]);
  // The whole list, from the line's own bytes.
  const rows: SW.UnsearchedRow[] = [];
  for await (const row of SW.unsearchedRows(S, held[0]!)) rows.push(row);
  assert.deepEqual(rows.map((r) => r.ref), big.unsearched.map((u) => u.ref));
  assert.deepEqual([rows[0]!.code, rows[1]!.code, rows[1]!.why], ["time", "bytes", big.unsearched[1]!.why]);
  assert.ok(Buffer.byteLength(SW.sweepWords(held[0]!, c1)) < 4096);
  assert.match(SW.sweepWords(held[0]!, c1), /not searched yet \(the next pass goes on with what was left\): 30000 object\(s\), all of them left to the next pass; by reason: 20000 bytes .*; 10000 time .*the whole list: in the sweep's own line of ledger\/sweeps\.jsonl/);
  // Read again under this harness's rules: a line each, the list in a file.
  const r = await SW.rereadSweeps(S);
  assert.deepEqual(r.records.map((x) => [x.seq, x.from_version, x.how]), [[c1.seq, 3, "read"], [c2.seq, 3, "read"]]);
  const now = await SW.readSweeps(S);
  assert.equal(now.length, 4);
  const again = SW.sweepOf(c1, now)!;
  assert.equal(again.rules, SW.SWEEP_RULES);
  assert.equal(again.unsearched_all!.file!.rows, 30_000);
  assert.equal(sha(await readFile(join(S, again.unsearched_all!.file!.path))), again.unsearched_all!.file!.sha256);
  const after4 = await readFile(file, "utf8");
  assert.equal(SW.verifySweepChain(after4).ok, true);
  assert.ok(after4.split("\n").filter(Boolean).slice(2).every((l) => Buffer.byteLength(l) < 64 * 1024));
  const kept: string[] = [];
  for await (const row of SW.unsearchedRows(S, SW.sweepOf(c2, now)!)) kept.push(`${row.code}: ${row.why}`);
  assert.deepEqual([kept.length, kept[0]], [120, "unreadable: it could not be read (EACCES: permission denied)"], "an object's own words are kept in the file");
  // What the old budget left is the next pass's: nobody asks. (These objects are no longer in the store: the pass says so, and nothing is left.)
  assert.equal(await SW.reconcileSweeps(S, { orphanMs: 0 }), 1);
  const done = SW.sweepOf(c1, await SW.readSweeps(S))!;
  assert.deepEqual([done.pass, done.continues, SW.unsearchedLeft(done), SW.unsearchedTotal(done)], [2, again.hash, 0, 30_000]);
  assert.deepEqual(done.unsearched_all!.by_reason.map((x) => [x.code, x.count]), [["unreadable", 30_000]]);
  assert.match(done.unsearched[0]!.why, /no longer in the store's listing/);
  assert.equal(await SW.reconcileSweeps(S, { orphanMs: 0 }), 0, "and no pass is started for what no pass can search");
});

const REAL = join(import.meta.dirname, "..", "runs", "s17fdfe", "ledger", "sweeps.jsonl");
test("the run s17fdfe's own sweeps (280 MB, seven lines of 33 to 51 MB) are read bounded, in a few MB of heap, and convert to lines that name their files", { skip: !existsSync(REAL) }, async () => {
  // Read where it is (never written), in a process of its own so that the heap is this read's.
  const script = `
    const SW = await import(${JSON.stringify(join(import.meta.dirname, "..", "extensions", "store-sweep.ts"))});
    const run = process.argv[1];
    gc();
    const h0 = process.memoryUsage().heapUsed;
    const t0 = Date.now();
    const sweeps = await SW.readSweeps(run);
    const ms = Date.now() - t0;
    gc();
    const h1 = process.memoryUsage().heapUsed;
    const words = sweeps.map((s) => SW.sweepWords(s, { looked_for: s.terms }));
    gc();
    const h2 = process.memoryUsage().heapUsed;
    console.log(JSON.stringify({ ms, h0, h1, h2, lines: sweeps.length, totals: sweeps.map((s) => SW.unsearchedTotal(s)), sample: sweeps.map((s) => s.unsearched.length), unsearched_bytes: sweeps.map((s) => JSON.stringify([s.unsearched, s.unsearched_all]).length), words: words.map((w) => Buffer.byteLength(w)) }));
  `;
  const out = spawnSync(process.execPath, ["--experimental-strip-types", "--no-warnings", "--expose-gc", "--input-type=module", "-e", script, join(import.meta.dirname, "..", "runs", "s17fdfe")], { encoding: "utf8", maxBuffer: 16 * 1024 * 1024 });
  assert.equal(out.status, 0, out.stderr);
  const m = JSON.parse(out.stdout) as { ms: number; h0: number; h1: number; h2: number; lines: number; totals: number[]; sample: number[]; unsearched_bytes: number[]; words: number[] };
  assert.equal(m.lines, 7);
  assert.deepEqual(m.totals, [97066, 97066, 173972, 185283, 192973, 97083, 97083]);
  assert.ok(m.sample.every((n) => n === SW.SWEEP_UNSEARCHED_SAMPLE));
  assert.ok(m.unsearched_bytes.every((n) => n < 16 * 1024), JSON.stringify(m.unsearched_bytes));
  assert.ok(m.words.every((n) => n < 4096), JSON.stringify(m.words));
  assert.ok(m.h1 - m.h0 < 32 * 1024 * 1024, `the read added ${((m.h1 - m.h0) / 1e6).toFixed(1)} MB of heap`);
  assert.ok(m.h2 - m.h1 < 8 * 1024 * 1024, `the words added ${((m.h2 - m.h1) / 1e6).toFixed(1)} MB of heap`);
  // Converted, in a copy: each line read again names its list in a file.
  const base = await mkdtemp(join(tmpdir(), "sweep-real-"));
  mine.push(base);
  await mkdir(join(base, "ledger"), { recursive: true });
  for (const f of ["sweeps.jsonl", "entries.jsonl", "attestations.jsonl"]) await copyFile(join(import.meta.dirname, "..", "runs", "s17fdfe", "ledger", f), join(base, "ledger", f));
  const r = await SW.rereadSweeps(base);
  assert.equal(r.records.length, 7);
  const text = await readFile(join(base, SW.LEDGER_SWEEPS), "utf8");
  assert.equal(SW.verifySweepChain(text).ok, true);
  const latest = (await SW.readSweeps(base)).slice(7);
  assert.deepEqual(latest.map((s) => s.unsearched_all!.file!.rows), m.totals);
  for (const s of latest) assert.equal((await stat(join(base, s.unsearched_all!.file!.path))).isFile(), true);
  process.stdout.write(`# s17fdfe: read in ${m.ms} ms, heap ${(m.h0 / 1e6).toFixed(1)} MB before, ${(m.h1 / 1e6).toFixed(1)} MB after the read, ${(m.h2 / 1e6).toFixed(1)} MB after every sweep's words; what is held of each list ${Math.max(...m.unsearched_bytes)} B at most; words ${Math.max(...m.words)} B at most\n`);
});
