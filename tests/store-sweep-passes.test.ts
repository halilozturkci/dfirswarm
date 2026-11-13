/**
 * The store sweep's passes (Batman III: each coverage record began a
 * whole-store search of its own in the hub's loop, up to twelve at once;
 * the run E1 read 86.6 GB in seven sweeps of one store and spent 9,307 s of
 * the hub's loop on them; a store larger than the byte budget stayed
 * partial for ever; the run D's sweeps lost with its hub ran 85 minutes
 * later, at the finish gate).
 *
 * One pass at a time, in a process of its own, for every record waiting
 * when it starts: each object read once for the union of their strings. What
 * each object holds of each string is kept, so a later record with the same
 * strings reads nothing and a pass that died is not paid for twice. A pass
 * its budget ended is continued by the next, by itself, until nothing is
 * left. A hub that starts takes up the sweeps nobody is running. Synthetic
 * runs only.
 */
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { mkdir, mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import * as P from "../extensions/protocol.ts";
import * as SW from "../extensions/store-sweep.ts";
import { coverage, ok, planned, rec, run } from "./negative-bar-fixture.ts";

const mine: string[] = [];
after(async () => {
  for (const d of mine) {
    spawnSync("chmod", ["-R", "u+w", d]);
    await rm(d, { recursive: true, force: true });
  }
});
const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));
const sha = (s: string | Buffer) => createHash("sha256").update(s).digest("hex");

/** A run whose store holds `jobs` committed jobs of `per` files each, every file its own bytes (`size` of them); `plant` puts a string into a file by its number. */
async function store(jobs: number, per: number, size: number, plant: Record<number, string> = {}): Promise<{ S: string; objects: number; bytes: number }> {
  const base = await mkdtemp(join(tmpdir(), "sweep-pass-"));
  mine.push(base);
  const S = join(base, "run");
  await P.initSandbox(S, { swarmId: "sp1", agentIds: ["a0"], capUsd: 1, wallClockMinutes: 30 });
  let n = 0;
  let bytes = 0;
  for (let j = 0; j < jobs; j++) {
    const id = `j${String(j + 1).padStart(6, "0")}`;
    const out = join(S, "store", "jobs", id, "out");
    const files: Array<{ path: string; sha256: string; bytes: number }> = [];
    for (let d = 0; d < per; d += 100) await mkdir(join(out, `d${d / 100}`), { recursive: true });
    for (let f = 0; f < per; f++, n++) {
      const head = Buffer.from(`object ${n} of the store\n${plant[n] ? `${plant[n]}\n` : ""}`);
      const body = Buffer.concat([head, Buffer.alloc(Math.max(0, size - head.length), 0x2e)]);
      const path = `d${Math.floor(f / 100)}/f${f}.txt`;
      await writeFile(join(out, path), body);
      files.push({ path, sha256: sha(body), bytes: body.length });
      bytes += body.length;
    }
    await writeFile(join(S, "store", "jobs", id, "manifest.json"), JSON.stringify({ files }));
    await writeFile(join(S, "store", "jobs", id, "job.json"), JSON.stringify({ id, state: "committed", status: "ok", exit: 0, spec: { kind: "command", scope: "all", inputs: ["all"], command: "extract" } }));
  }
  return { S, objects: n, bytes };
}
/** A coverage record as the sweep reads one. */
const cov = (seq: number, looked_for: string[], refs: string[] = ["input:disk.E01"]): P.LedgerEntry => ({ seq, hash: sha(`coverage ${seq} ${looked_for.join("|")}`), kind: "coverage", refs, result_refs: [], looked_for, at: new Date().toISOString() }) as unknown as P.LedgerEntry;
/** The ref of object `n` of a store of `per` files a job. */
const refOf = (n: number, per: number) => `job:j${String(Math.floor(n / per) + 1).padStart(6, "0")}/d${Math.floor((n % per) / 100)}/f${n % per}.txt`;

test("eight coverage records in a burst are one pass that reads each object once, off this process's loop; a later record with the same strings reads nothing, and one with a new string reads each object once for it", async () => {
  const PER = 400;
  const plant: Record<number, string> = { 5: "shared-string", 1203: "shared-string", 2399: "shared-string" };
  for (let i = 0; i < 8; i++) plant[100 + 300 * i] = `needle-${i}`;
  const { S, objects } = await store(6, PER, 4096, plant);
  assert.equal(objects, 2400);
  // A timer of this process, through the pass.
  let last = performance.now();
  let lag = 0;
  const tick = setInterval(() => {
    const now = performance.now();
    lag = Math.max(lag, now - last - 20);
    last = now;
  }, 20);
  const covs = Array.from({ length: 8 }, (_, i) => cov(i + 1, [`needle-${i}`, "shared-string"]));
  const lines = await Promise.all(covs.map((c) => SW.startSweep(S, c)));
  clearInterval(tick);
  const passes = SW.sweepPasses(S);
  assert.equal(passes.length, 1, "one pass for the eight");
  assert.deepEqual([passes[0]!.records, passes[0]!.objects, passes[0]!.reads, passes[0]!.from_results], [8, 2400, 2400, 0], "each object read once in total");
  assert.ok(lag < 500, `a 20 ms timer of this process was ${lag.toFixed(0)} ms late at most`);
  // What each object holds is attributed to each record by its own strings.
  lines.forEach((l, i) => {
    assert.ok(l, `record ${i + 1} has its line`);
    assert.deepEqual([l!.seq, l!.target, l!.state, l!.terms, l!.searched.objects, l!.unsearched], [i + 1, covs[i]!.hash, "hits", [`needle-${i}`, "shared-string"], 2400, []]);
    assert.deepEqual(
      l!.hits.map((h) => [h.ref, h.term]).sort(),
      [[refOf(100 + 300 * i, PER), `needle-${i}`], ...[5, 1203, 2399].map((n) => [refOf(n, PER), "shared-string"])].sort(),
    );
  });
  const text = await readFile(join(S, SW.LEDGER_SWEEPS), "utf8");
  assert.deepEqual([SW.verifySweepChain(text).ok, SW.verifySweepChain(text).total], [true, 8]);
  // The same strings again: nothing is read.
  const again = await SW.startSweep(S, cov(9, ["needle-3", "shared-string"]));
  assert.deepEqual(again!.hits.map((h) => [h.ref, h.term, h.count, h.first_offset]), lines[3]!.hits.map((h) => [h.ref, h.term, h.count, h.first_offset]));
  let p = SW.sweepPasses(S).at(-1)!;
  assert.deepEqual([p.records, p.reads, p.bytes_read, p.from_results], [1, 0, 0, 2400], "a second record with the same strings reads nothing");
  // A record that names an object: its hit there is said, not holding, from the same kept results.
  const named = await SW.startSweep(S, cov(10, ["needle-3"], ["input:disk.E01", refOf(1000, PER)]));
  assert.deepEqual([named!.state, named!.hits.length, named!.named_hits.map((h) => h.ref)], ["clean", 0, [refOf(1000, PER)]]);
  assert.equal(SW.sweepPasses(S).at(-1)!.reads, 0);
  // One new string among kept ones: each object is read once, for it alone.
  const fresh = await SW.startSweep(S, cov(11, ["shared-string", "object 77 of"]));
  p = SW.sweepPasses(S).at(-1)!;
  assert.deepEqual([p.reads, p.from_results], [2400, 0]);
  assert.deepEqual(fresh!.hits.map((h) => [h.ref, h.term]).sort(), [[refOf(77, PER), "object 77 of"], ...[5, 1203, 2399].map((n) => [refOf(n, PER), "shared-string"])].sort());
  // A record already swept is not swept again.
  assert.equal((await SW.startSweep(S, covs[0]!))!.hash, lines[0]!.hash);
  assert.equal(SW.sweepPasses(S).length, 4);
  process.stdout.write(`# 8 records in a burst over ${objects} objects: 1 pass, ${passes[0]!.reads} reads, ${passes[0]!.ms} ms in the child, timer lag ${lag.toFixed(0)} ms; the same strings again: ${0} reads\n`);
});

test("a store larger than a pass's byte budget is swept in several passes, each continuing the last from the list it left, and ends clean with nobody asking", async () => {
  const PER = 300;
  const { S, objects, bytes } = await store(4, PER, 8192, { 1100: "late-needle" });
  const budget = Math.ceil(bytes / 3.5);
  const c = cov(1, ["no-such-string-anywhere"]);
  const other = cov(2, ["late-needle"]);
  const [line, hit] = await Promise.all([SW.startSweep(S, c, { maxBytes: budget }), SW.startSweep(S, other)]);
  const passes = SW.sweepPasses(S);
  assert.equal(passes.length, 4, JSON.stringify(passes));
  assert.equal(passes.reduce((n, p) => n + p.reads, 0), objects, "every object read once over the passes");
  assert.ok(passes.every((p) => p.bytes_read <= budget), "no pass read more than its budget");
  assert.deepEqual([line!.state, line!.pass, line!.searched.objects, line!.searched.bytes, line!.unsearched, line!.unsearched_all], ["clean", 4, objects, bytes, [], undefined]);
  assert.deepEqual([hit!.state, hit!.pass, hit!.hits.map((h) => h.ref)], ["hits", 4, [refOf(1100, PER)]], "a hit found by a later pass is on the line that ends the sweep");
  // On the chain: each pass a line that continues the one before; what a pass left is a summary and a file the next reads.
  const all = (await SW.readSweeps(S)).filter((s) => s.target === c.hash);
  assert.deepEqual(all.map((s) => [s.pass, s.state, s.continues]), [[undefined, "partial", undefined], [2, "partial", all[0]!.hash], [3, "partial", all[1]!.hash], [4, "clean", all[2]!.hash]]);
  const left = all.map((s) => SW.unsearchedTotal(s));
  assert.ok(left[0]! > left[1]! && left[1]! > left[2]! && left[2]! > 0 && left[3] === 0, JSON.stringify(left));
  assert.equal(SW.unsearchedLeft(all[0]!), left[0], "all of it left to the next pass");
  const first = all[0]!.unsearched_all!;
  assert.deepEqual(first.by_reason.map((r) => r.code), ["bytes"]);
  assert.ok(existsSync(join(S, first.file!.path)));
  assert.equal(sha(await readFile(join(S, first.file!.path))), first.file!.sha256);
  assert.match(SW.sweepWords(all[0]!, c), /store sweep partial: .*not searched yet \(the next pass goes on with what was left\): \d+ object\(s\), all of them left to the next pass; by reason: \d+ bytes/);
  assert.match(SW.sweepWords(line, c), /^store sweep clean: 1200 object\(s\), \d+ bytes searched for "no-such-string-anywhere" in 4 passes$/);
  assert.equal(SW.verifySweepChain(await readFile(join(S, SW.LEDGER_SWEEPS), "utf8")).ok, true);
  process.stdout.write(`# ${objects} objects, ${bytes} bytes, a pass's budget ${budget}: ${passes.length} passes, reads ${passes.map((p) => p.reads).join(" + ")}, unsearched after each ${left.join(", ")}\n`);
});

test("a pass killed in the middle is not paid for twice: the next one reads only what the first did not get to, and completes", async () => {
  const { S, objects } = await store(3, 100, 1024 * 1024, { 3: "early-needle", 297: "late-needle" });
  const c = cov(1, ["early-needle", "late-needle"]);
  // A process of its own starts the sweep (as a hub does), its pass in a child of that; both are killed once some results are on disk.
  const driver = `const SW = await import(${JSON.stringify(join(import.meta.dirname, "..", "extensions", "store-sweep.ts"))}); await SW.startSweep(${JSON.stringify(S)}, ${JSON.stringify(c)}); process.exit(0);`;
  const child = spawn(process.execPath, ["--experimental-strip-types", "--no-warnings", "--input-type=module", "-e", driver], { detached: true, stdio: "ignore", env: { ...process.env, SWARM_SWEEP_CACHE_FLUSH_MS: "50", SWARM_SWEEP_SETTLE_MS: "0" } });
  // What is kept so far: an object counts once both strings' results for it are written (a string's bits are replaced whole, after its rows).
  const dir = join(S, SW.SWEEP_RESULTS_DIR);
  const kept = async (): Promise<number> => {
    const names = existsSync(dir) ? (await readdir(dir)).filter((n) => /^[0-9a-f]{32}\.bits$/.test(n)) : [];
    if (names.length < 2) return 0;
    const counts = await Promise.all(names.map(async (n) => [...(await readFile(join(dir, n)).catch(() => Buffer.alloc(0)))].reduce((sum, byte) => sum + byte.toString(2).replaceAll("0", "").length, 0)));
    return Math.min(...counts);
  };
  const until = Date.now() + 60_000;
  let seen = 0;
  while (Date.now() < until && child.exitCode === null) {
    seen = await kept();
    if (seen >= 10) break;
    await sleep(2);
  }
  // Between two writes of the results, as a rule: a writer killed in one leaves its lock for the next to wait out, which this does not test.
  await sleep(15);
  process.kill(-child.pid!, "SIGKILL");
  await new Promise<void>((r) => (child.exitCode !== null || child.signalCode ? r() : child.once("exit", () => r())));
  assert.ok(seen >= 10 && seen < objects, `killed with ${seen} of ${objects} objects' results kept`);
  assert.deepEqual(await SW.readSweeps(S), [], "it wrote no line");
  // Started again (a hub that restarts): it resumes and completes.
  const line = await SW.startSweep(S, c);
  const p = SW.sweepPasses(S).at(-1)!;
  assert.ok(p.from_results >= seen && p.reads < objects && p.reads + p.from_results === objects, JSON.stringify(p));
  assert.deepEqual([line!.state, line!.searched.objects, line!.unsearched, line!.hits.map((h) => [h.ref, h.term])], ["hits", objects, [], [[refOf(3, 100), "early-needle"], [refOf(297, 100), "late-needle"]]]);
  process.stdout.write(`# killed with ${seen} of ${objects} objects done; the next pass read ${p.reads} and took ${p.from_results} from the kept results\n`);
});

test("a coverage record whose sweep was lost with its process gets it when the hub starts, and from the hub's rounds once it is older than the orphan bound", async () => {
  const { S, a0 } = await run();
  await planned(a0, "2");
  const abs = ok(await rec(a0, { kind: "absence", value: "a remote tool", source: "the disk", evidence: "a search", refs: ["job:j000001/hits.txt"], answers: ["2"] })).entry;
  const c1 = ok(await rec(a0, coverage("2", ["input:disk.E01"], [`E-${abs.seq}`], { looked_for: ["mallory"] }))).entry;
  const c2 = ok(await rec(a0, coverage("2", ["input:disk.E01", "input:logs/a.log"], [`E-${abs.seq}`], { looked_for: ["trent"] }))).entry;
  await SW.awaitSweeps(S);
  assert.equal((await SW.readSweeps(S)).length, 2);
  // The hub died before either line was written.
  await writeFile(join(S, SW.LEDGER_SWEEPS), "");
  assert.equal(await SW.reconcileSweepsAtStart(S), 2, "both are started, though written a moment ago");
  await SW.awaitSweeps(S);
  let now = await SW.readSweeps(S);
  assert.deepEqual([SW.sweepOf(c1, now)?.state, SW.sweepOf(c2, now)?.state], ["clean", "clean"]);
  assert.equal(await SW.reconcileSweepsAtStart(S), 0, "a record with its line is left alone");
  // Lost again, and no start: the hub's round takes them up once they are older than the orphan bound.
  await writeFile(join(S, SW.LEDGER_SWEEPS), "");
  process.env.SWARM_SWEEP_ORPHAN_SEC = "0";
  try {
    await SW.reverseSweepInBackground(S);
    const until = Date.now() + 30_000;
    while (Date.now() < until && (await SW.readSweeps(S)).length < 2) {
      await sleep(50);
      await SW.awaitSweeps(S);
    }
  } finally {
    delete process.env.SWARM_SWEEP_ORPHAN_SEC;
  }
  now = await SW.readSweeps(S);
  assert.deepEqual([SW.sweepOf(c1, now)?.state, SW.sweepOf(c2, now)?.state], ["clean", "clean"]);
});
