/**
 * Preparing the finish, and late items resolved in one batch (docs/adr/0015,
 * "Preparing the finish"; the limits spec, item 3). `finish prepare` takes
 * the lease and the report's boundary as a done takes them, runs no check
 * and writes no sentinel, and lists readiness and every late item; a
 * prepare again, a republished report, a takeover and a resume keep what
 * was late until it is resolved. `finish resolve` with items records one
 * resolution per item, against the generation and the report's digest,
 * validated whole under the lock, with an idempotency key. The final
 * transaction is unchanged: a veto, an objection or an evidence addition
 * racing the done still holds the sentinel. And the metric: a run whose
 * only first-done refusal would have been late items has none when the
 * coordinator prepares and resolves in one batch.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { appendFile, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import * as F from "../extensions/finish.ts";
import * as L from "../extensions/leads.ts";
import * as P from "../extensions/protocol.ts";
import { checkLedgerAnswers } from "../scripts/check-answers.ts";
import { finishGate } from "../scripts/finish-gate.ts";
import { admitMaterial } from "../scripts/material.ts";
import { measureRun } from "../scripts/metrics.ts";
import { prepareResume } from "../scripts/resume.ts";
import { custodyAnchorPath } from "../scripts/custody.ts";
import { ALL_AREAS, coverage, job, sha } from "./negative-bar-fixture.ts";

const dirs: string[] = [];
after(async () => {
  for (const d of dirs) {
    // The store is sealed read-only.
    spawnSync("chmod", ["-R", "u+w", d]);
    await rm(d, { recursive: true, force: true });
  }
});

type Ctx = { sandboxRoot: string; agentId: string };
const GOAL = ["## Goal", "", "Examine the host.", "", "### Questions", "", "1. Who logged on, and when?", "", "## Definition of done", "", "d", "", "## Checks", "", '- `node x "$SWARM_HARNESS/scripts/check-answers.ts" --sections 1`', ""].join("\n");
const FINDING = { basis: "observed", confidence: "high", indicates: "What the observation shows, and the step to it.", confidence_why: "Read directly from the object it cites." } as const;
const ESTABLISHED = {
  strength: "established",
  answer_review: {
    reproduced: "re-derived the cited finding from its sealed ref",
    read: "nothing beyond the cited entries",
    parts: [{ part: "the question as asked", established: true, why: "the cited finding shows it" }],
    inference: "the finding is the answer",
    alternatives: [{ explanation: "a copy of the record left by another process", why: "the record's own metadata ties it to the event", evidence: ["E-1"] }],
    other_family: { checked: false, text: "no other source family holds it here" },
    // Source-first (docs/adr/0015): the strongest rival and its test, and how the value was derived.
    discriminator: { rival: "a copy of the record written later by a backup process", test: "read the record's write time against the backup's run times", favours_if: "the answer if it falls outside every backup run; the rival if inside one", outcome: "it falls outside every backup run", refs: ["job:j000001/hits.txt"] },
    derivation: { job: "j000001", inputs: ["input:logs/a.log"] },
  },
} as const;

async function run(id = "fp1") {
  const base = await mkdtemp(join(tmpdir(), "finish-prepare-"));
  dirs.push(base);
  const runs = join(base, "runs");
  const S = join(runs, id);
  await P.initSandbox(S, { swarmId: id, agentIds: ["a0", "a1", "a2"], capUsd: 5, wallClockMinutes: 30, goal: GOAL });
  // One log and a job over it, whose output a finding cites; the anchor a kickoff writes beside the run (a resume records itself there).
  await writeFile(join(S, "inputs.json"), JSON.stringify({ files: [{ path: "inputs/logs/a.log", sha256: sha("a"), bytes: 10 }] }));
  await job(S, "j000001", "hits.txt", { spec: { kind: "command", scope: "declared", inputs: ["input:logs/a.log"], command: "search" } });
  await writeFile(custodyAnchorPath(S), JSON.stringify({ run: id, started_at: new Date().toISOString() }));
  const ctx = (agentId: string): Ctx => ({ sandboxRoot: S, agentId });
  for (const a of ["a0", "a1", "a2"]) await traceRow(S, a, "bash");
  return { S, id, runs, a0: ctx("a0"), a1: ctx("a1"), a2: ctx("a2") };
}

/** A trace row, as the extension writes one (logEvent's shape). */
async function traceRow(S: string, agent: string, tool: string, args: Record<string, unknown> = {}, result: Record<string, unknown> = { ok: true }): Promise<void> {
  const at = new Date().toISOString();
  await appendFile(join(S, P.EVENTS_REL), `${JSON.stringify({ ts: at, recv_ts: at, agent, tool, args, result })}\n`);
}

async function publish(S: string, agent: string, text: string): Promise<void> {
  await mkdir(join(S, "work"), { recursive: true });
  await writeFile(join(S, "work", "report.md"), text);
  await P.recordFileVersion(S, "work/report.md", agent);
}

const tick = () => new Promise((r) => setTimeout(r, 25));
const REPORT = "work/report.md";

/** Question 1 established on a finding and attested established by another seat: the finish line passes on it. */
async function established(r: { S: string; a0: Ctx; a1: Ctx; a2: Ctx }): Promise<void> {
  const f = await P.recordEntry(r.a0, { kind: "finding", ...FINDING, value: "a logon at 09:14 by the first account", source: "the log", evidence: "line 12", refs: ["job:j000001/hits.txt"], answers: ["1"] } as unknown as P.LedgerInput);
  assert.ok(f.ok, JSON.stringify(f));
  const seq = (f as { entry: P.LedgerEntry }).entry.seq;
  const a = await P.recordEntry(r.a1, { kind: "answer", section: "question:1", value: "The first account, at 09:14", reasoning: `E-${seq}`, confidence: "high", confidence_why: "direct", alternatives_open: "none open", would_change: "a second source", result: "established" } as unknown as P.LedgerInput);
  // The rival-area check runs for every review (docs/adr/0013): the log the finding was read from is covered for question 1.
  const cov = await P.recordEntry(r.a0, coverage("1", ["input:logs/a.log"], ["job:j000001/hits.txt"], { areas: ALL_AREAS }) as unknown as P.LedgerInput);
  assert.ok(cov.ok, JSON.stringify(cov));
  assert.ok(a.ok, JSON.stringify(a));
  const at = await P.attestEntry(r.a2, { seq: (a as { entry: P.LedgerEntry }).entry.seq, how: "re-read line 12", ...ESTABLISHED } as unknown as P.LedgerActInput);
  assert.ok(at.ok, JSON.stringify(at));
}

const refused = (x: { ok: boolean }, re: RegExp) => {
  assert.equal(x.ok, false, `expected a refusal: ${JSON.stringify(x)}`);
  assert.match((x as unknown as { reason: string }).reason, re);
};
const events = async (S: string) => (await F.readFinish(S)).events.length;
const ids = (late: unknown) => (late as F.LateItem[]).map((x) => `${x.kind}:${x.id}`);
type Prepared = { ok: true; mine: boolean; generation: number; digest: string; late: F.LateItem[]; boundary: { since: string | null; segment?: number; carried?: number[] }; readiness: { ready: boolean }; seq: number; took_over?: string; not_yours?: boolean; coordinator: string };
const prepare = async (c: Ctx, report?: string) => (await F.prepareFinish(c, report ? { report } : {})) as unknown as Prepared & { ok: boolean; reason?: string };

test("prepare takes the finish as a done would, runs no check and writes no sentinel, and lists every late item; finish status lists them only once the finish is prepared", async () => {
  const r = await run();
  refused(await F.prepareFinish(r.a0, {}), /name the report you drafted/);
  refused(await F.prepareFinish(r.a0, { report: REPORT }), /work\/report\.md does not exist yet: write the report and publish it/);
  assert.equal(await events(r.S), 0, "a refused prepare records nothing");
  await publish(r.S, "a0", "# Report v1\n");
  await tick();
  const p1 = await P.postMessage(r.a1, { tag: "result", body: "the timeline misses the second logon" });
  const v1 = await P.postMessage(r.a2, { tag: "veto", body: "the first account is a service account" });
  // Before any prepare or done there is no boundary, and finish status lists nothing late.
  const before = await F.finishStatus(r.a2);
  assert.equal(before.coordinator, null);
  assert.deepEqual(before.late, []);
  // Another seat's prepare is not its own: answered quietly, and the lease goes to the report's publisher, as a done's would.
  const other = await prepare(r.a1, REPORT);
  assert.equal(other.ok, true);
  assert.deepEqual([other.not_yours, other.coordinator, other.generation], [true, "a0", 1]);
  const own = await prepare(r.a0, REPORT);
  assert.equal(own.ok, true, JSON.stringify(own));
  assert.deepEqual([own.mine, own.coordinator, own.generation], [true, "a0", 1]);
  assert.equal(own.digest, await F.reportDigest(r.S, REPORT));
  assert.deepEqual(ids(own.late), [`post:${p1.id}`, `post:${v1.id}`], "every late item, whole");
  assert.equal(typeof own.readiness.ready, "boolean");
  assert.equal(own.boundary.since, new Date(await P.outputWrittenAt(r.S, REPORT)).toISOString(), "the boundary is the report's write time, not the prepare's");
  const st = await F.readFinish(r.S);
  assert.deepEqual(st.events.map((e) => e.ev), ["lease", "prepare"], "no check, no readiness posted by it, one lease");
  assert.equal(await P.swarmDoneExists(r.S), false, "no sentinel");
  assert.deepEqual(st.prepares.map((x) => [x.by, x.generation, x.late.length]), [["a0", 1, 2]]);
  // Now every seat's finish status lists them.
  const after = await F.finishStatus(r.a2);
  assert.deepEqual(ids(after.late), [`post:${p1.id}`, `post:${v1.id}`]);
  assert.equal((after.prepared as { current: boolean; late: number }).current, true);
  // The header names the batch's generation and digest.
  assert.match((await F.finishHeader(r.S, "a0")) ?? "", new RegExp(`all in one call \\(finish resolve with items, generation 1, digest ${own.digest.slice(0, 12)}\\)`));
});

test("a batch resolves every late item in one act, one resolution event each, bound to the generation and digest; the done then goes on", async () => {
  const r = await run();
  await established(r);
  await publish(r.S, "a0", "# Report\n");
  await tick();
  const p1 = await P.postMessage(r.a1, { tag: "result", body: "the timeline misses the second logon" });
  const obj = await F.ackReport(r.a2, { verdict: "objection", why: "section 1 names the wrong logon", report: REPORT });
  assert.ok(obj.ok);
  const own = await prepare(r.a0, REPORT);
  assert.deepEqual(ids(own.late), [`post:${p1.id}`, `objection:${(obj as { seq: number }).seq}`]);
  const n = await events(r.S);
  const b = await F.resolveLate(r.a0, { items: [{ post: `#${p1.id}`, how: "not_material", why: "the second logon is the same session" }, { ack: (obj as { seq: number }).seq, how: "folded", where: "section 1 names the 09:14 logon" }], generation: own.generation, digest: own.digest, key: "finish-1" });
  assert.equal(b.ok, true, JSON.stringify(b));
  assert.equal(b.resolved, 2);
  assert.deepEqual(b.late, []);
  const st = await F.readFinish(r.S);
  assert.equal(st.events.length, n + 2, "one event per item");
  assert.deepEqual(st.resolutions.map((x) => [x.post ?? null, x.ack ?? null, x.how, x.batch, x.generation, x.digest]), [
    [p1.id, null, "not_material", "finish-1", 1, own.digest],
    [null, (obj as { seq: number }).seq, "folded", "finish-1", 1, own.digest],
  ]);
  assert.equal(st.resolutions[1]!.why, "section 1 names the 09:14 logon", "a folded item's where is its words");
  // The coordinator's done: nothing late, the sentinel written.
  const turn = await F.finishTurnFor(r.a0, { output_file: REPORT });
  assert.equal(F.lateRefusal(turn, REPORT), null);
  const done = await P.markDone(r.a0, { reason: "finished", outputFile: REPORT, finish: { holder: turn.holder, generation: turn.generation } });
  assert.equal("created_sentinel" in done && done.created_sentinel, true);
});

test("republish: prepare again keeps the earliest boundary, what was late stays late, and the batch carries the new digest (a stale one is refused with the exact field, nothing recorded)", async () => {
  const r = await run();
  await publish(r.S, "a0", "# Report v1\n");
  const first = await prepare(r.a0, REPORT);
  assert.deepEqual(first.late, []);
  await tick();
  const p1 = await P.postMessage(r.a1, { tag: "result", body: "the timeline misses the second logon" });
  await tick();
  // Folded into the report and published again: the post is older than the new version, and still late.
  await publish(r.S, "a0", "# Report v2\n\nThe second logon at 09:20.\n");
  const again = await prepare(r.a0, REPORT);
  assert.equal(again.boundary.since, first.boundary.since, "the earliest boundary is kept");
  assert.notEqual(again.digest, first.digest);
  assert.deepEqual(ids(again.late), [`post:${p1.id}`], "a republished report forgives nothing");
  assert.equal(again.generation, first.generation);
  const n = await events(r.S);
  const stale = await F.resolveLate(r.a0, { items: [{ post: p1.id, how: "folded", where: "the timeline's 09:20 row" }], generation: again.generation, digest: first.digest, key: "fold-1" });
  refused(stale, new RegExp(`work/report\\.md is at digest ${again.digest}, not ${first.digest}.*Nothing was recorded\\. Still late: post #${p1.id}\\.`));
  assert.deepEqual(stale.stale, { digest: { expected: first.digest, current: again.digest, report: REPORT } });
  assert.deepEqual(stale.unresolved, [{ kind: "post", id: p1.id }]);
  assert.equal(await events(r.S), n, "nothing recorded");
  // The same key, sent again with the digest read again: recorded once.
  const okb = await F.resolveLate(r.a0, { items: [{ post: p1.id, how: "folded", where: "the timeline's 09:20 row" }], generation: again.generation, digest: again.digest.slice(0, 12), key: "fold-1" });
  assert.equal(okb.ok, true, JSON.stringify(okb));
  assert.equal(await events(r.S), n + 1);
  assert.deepEqual(await F.lateItems(r.S, "a0", REPORT), []);
});

test("takeover: the next seat's prepare takes an unavailable coordinator's finish at the next generation and keeps its boundary; a batch at the old generation is stale, the old holder's is not its own", async () => {
  const r = await run();
  await publish(r.S, "a0", "# Report\n");
  const first = await prepare(r.a0, REPORT);
  await tick();
  const p1 = await P.postMessage(r.a2, { tag: "veto", body: "the first account is a service account" });
  // a0 compacts: unavailable for the whole compaction.
  await traceRow(r.S, "a0", "compact_start");
  const took = await prepare(r.a1, REPORT);
  assert.equal(took.ok, true, JSON.stringify(took));
  assert.deepEqual([took.mine, took.took_over, took.generation], [true, "a0", 2]);
  assert.equal(took.boundary.since, first.boundary.since, "a takeover keeps the earliest boundary");
  assert.deepEqual(ids(took.late), [`post:${p1.id}`]);
  const posts = (await P.readInbox(r.a2, { markSeen: false })).posts.map((p) => p.body);
  assert.ok(posts.some((b) => /^a1 coordinates the finish now \(generation 2\)/.test(b)), "the takeover is said on the board");
  const n = await events(r.S);
  refused(await F.resolveLate(r.a0, { items: [{ post: p1.id, how: "not_material", why: "x" }], generation: 1, digest: first.digest }), /resolutions are the coordinator's \(a1\)/);
  const stale = await F.resolveLate(r.a1, { items: [{ post: p1.id, how: "not_material", why: "the service account ran the scheduled task only" }], generation: 1, digest: took.digest, key: "t1" });
  refused(stale, /the lease is at generation 2 \(held by a1\), not 1/);
  assert.deepEqual(stale.stale, { generation: { expected: 1, current: 2, holder: "a1" } });
  assert.deepEqual(stale.unresolved, [{ kind: "post", id: p1.id }]);
  assert.equal(await events(r.S), n);
  assert.equal((await F.resolveLate(r.a1, { items: [{ post: p1.id, how: "not_material", why: "the service account ran the scheduled task only" }], generation: 2, digest: took.digest, key: "t1" })).ok, true);
  assert.deepEqual(await F.lateItems(r.S, "a1", REPORT), []);
});

test("resume: the first prepare after it opens the new segment, carries what was still late by name, forgives nothing, and the continuation's own posts before its report are not late", async () => {
  const r = await run("fpres");
  await publish(r.S, "a0", "# Report v1\n");
  const s1 = await prepare(r.a0, REPORT);
  assert.equal(s1.boundary.segment, undefined);
  await tick();
  const p1 = await P.postMessage(r.a1, { tag: "result", body: "the first logon was remote" });
  const p2 = await P.postMessage(r.a2, { tag: "result", body: "a second account logged on too" });
  const obj = await F.ackReport(r.a2, { verdict: "objection", why: "section 1 misses the second account" });
  assert.ok(obj.ok);
  assert.ok((await F.resolveLate(r.a0, { post: p2.id, how: "folded", why: "section 1 names both accounts" })).ok);
  // The run is stopped with a post and an objection unresolved, and resumed.
  await P.markStopped(r.S, "operator", "swarm.sh stop");
  const res = await prepareResume(r.S, { run: r.id, by: "operator", minutes: 30 });
  assert.equal(res.ok, true);
  await tick();
  for (const a of ["a0", "a1", "a2"]) await traceRow(r.S, a, "bash");
  // The continuation's own work, before the report it finishes on, and a new version of the report.
  const p3 = await P.postMessage(r.a1, { tag: "result", body: "the continuation found the third logon" });
  await tick();
  await publish(r.S, "a0", "# Report v2\n\nThree logons.\n");
  const s2 = await prepare(r.a0, REPORT);
  assert.equal(s2.ok, true, JSON.stringify(s2));
  assert.deepEqual([s2.mine, s2.generation, s2.boundary.segment, s2.boundary.carried], [true, 2, 1, [p1.id]]);
  assert.notEqual(s2.boundary.since, s1.boundary.since, "the new segment has its own boundary");
  assert.deepEqual(ids(s2.late).sort(), [`objection:${(obj as { seq: number }).seq}`, `post:${p1.id}`].sort(), "the unresolved post is carried, the objection stays; the resolved one and the continuation's own post are not late");
  assert.ok(!ids(s2.late).includes(`post:${p3.id}`));
  const lease = (await F.readFinish(r.S)).events.filter((e) => e.ev === "lease").at(-1)!;
  assert.deepEqual([lease.segment, lease.carried], [1, [{ id: p1.id, by: "a1", tag: "result" }]]);
  // A post after the new report is late; a prepare again changes neither the boundary nor what is carried.
  await tick();
  const p4 = await P.postMessage(r.a2, { tag: "veto", body: "the third logon is the backup job" });
  const s3 = await prepare(r.a0, REPORT);
  assert.deepEqual([s3.generation, s3.boundary.since, s3.boundary.segment, s3.boundary.carried], [2, s2.boundary.since, 1, [p1.id]]);
  assert.deepEqual(ids(s3.late).sort(), [`objection:${(obj as { seq: number }).seq}`, `post:${p1.id}`, `post:${p4.id}`].sort());
  // Resolved in one batch, and the sentinel is written.
  const b = await F.resolveLate(r.a0, { items: [{ post: p1.id, how: "folded", where: "section 1, the remote logon" }, { post: p4.id, how: "not_material", why: "the backup job is named in section 2 already" }, { ack: (obj as { seq: number }).seq, how: "folded", where: "section 1 names the second account" }], generation: 2, digest: s3.digest, key: "resume-1" });
  assert.equal(b.ok, true, JSON.stringify(b));
  assert.deepEqual(b.late, []);
  const turn = await F.finishTurnFor(r.a0, { output_file: REPORT });
  assert.equal(F.lateRefusal(turn, REPORT), null);
  const done = await P.markDone(r.a0, { reason: "finished", outputFile: REPORT, finish: { holder: turn.holder, generation: turn.generation } });
  assert.equal("created_sentinel" in done && done.created_sentinel, true);
  assert.equal((await F.readFinish(r.S)).chain.ok, true);
});

test("an interrupted batch retried: the same key records nothing twice and says what is still late; a new key finds each item resolved already, says so and records nothing; another batch under a used key is refused", async () => {
  const r = await run();
  await publish(r.S, "a0", "# Report\n");
  await tick();
  const p1 = await P.postMessage(r.a1, { tag: "result", body: "one" });
  const p2 = await P.postMessage(r.a2, { tag: "result", body: "two" });
  const own = await prepare(r.a0, REPORT);
  const batch = { items: [{ post: p1.id, how: "not_material", why: "already in section 1" }, { post: p2.id, how: "folded", where: "section 2" }], generation: own.generation, digest: own.digest };
  const first = await F.resolveLate(r.a0, { ...batch, key: "k1" });
  assert.equal(first.ok, true);
  const n = await events(r.S);
  // The reply was lost; meanwhile another post landed. The retry, in another order, with the same key:
  await tick();
  const p3 = await P.postMessage(r.a1, { tag: "veto", body: "three" });
  const retry = await F.resolveLate(r.a0, { ...batch, items: [...batch.items].reverse(), key: "k1" });
  assert.equal(retry.ok, true, JSON.stringify(retry));
  assert.equal(retry.replayed, true);
  assert.deepEqual(retry.seqs, first.seqs);
  assert.deepEqual(ids(retry.late), [`post:${p3.id}`], "nothing hidden: what is still late is said");
  assert.equal(await events(r.S), n, "nothing recorded twice");
  // The same items under a new key: each resolved already, named with its seq; nothing recorded, and nothing to send again (the Fable review of the limits branch, P3-8).
  const again = await F.resolveLate(r.a0, { ...batch, key: "k2" });
  assert.deepEqual([again.ok, again.resolved, again.seqs], [true, 0, []], JSON.stringify(again));
  assert.match(String(again.note), new RegExp(`^every item of this batch was resolved already \\(post #${p1.id}, seq \\d+; post #${p2.id}, seq \\d+\\): nothing was recorded\\. Still late: post #${p3.id}[^:]*: resolve those, then call done\\.$`));
  assert.deepEqual(ids(again.late), [`post:${p3.id}`]);
  // One item resolved already beside one that is not: the batch is refused, and says to leave it out.
  refused(await F.resolveLate(r.a0, { items: [batch.items[0]!, { post: p3.id, how: "not_material", why: "x" }], generation: own.generation, digest: own.digest, key: "k3" }), new RegExp(`post #${p1.id} \\(item 1\\) was resolved already \\(seq \\d+, not_material, batch k1\\).*Leave those items out and send the batch again`));
  // Another batch under k1: refused.
  refused(await F.resolveLate(r.a0, { items: [{ post: p3.id, how: "not_material", why: "x" }], generation: own.generation, digest: own.digest, key: "k1" }), /key k1 was recorded already for another batch/);
  assert.equal(await events(r.S), n);
  // No key: the batch's own content names it, so a resend is a retry too.
  const auto = { items: [{ post: p3.id, how: "not_material", why: "the veto restates section 3" }], generation: own.generation, digest: own.digest };
  const a1 = await F.resolveLate(r.a0, auto);
  assert.equal(a1.ok, true);
  assert.match(String(a1.key), /^auto-[0-9a-f]{24}$/);
  const a2 = await F.resolveLate(r.a0, auto);
  assert.deepEqual([a2.ok, a2.replayed, a2.key], [true, true, a1.key]);
  assert.equal(await events(r.S), n + 1);
  // The same item under a digest prefix of another length (another auto key): resolved already, and nothing is late now.
  const longer = await F.resolveLate(r.a0, { ...auto, digest: String(own.digest).slice(0, 20) });
  assert.equal(longer.ok, true, JSON.stringify(longer));
  assert.match(String(longer.note), /: nothing was recorded\. Nothing is late against the report: call done\.$/);
  assert.equal(await events(r.S), n + 1);
});

test("a batch with one stale item records nothing: that item is named, and every id still unresolved is returned; a malformed batch says how to fix each part", async () => {
  const r = await run();
  await publish(r.S, "a0", "# Report\n");
  await tick();
  const p1 = await P.postMessage(r.a1, { tag: "result", body: "one" });
  const p2 = await P.postMessage(r.a2, { tag: "result", body: "two" });
  const p3 = await P.postMessage(r.a1, { tag: "veto", body: "three" });
  const own = await prepare(r.a0, REPORT);
  assert.ok((await F.resolveLate(r.a0, { post: p2.id, how: "not_material", why: "the same session" })).ok, "one resolved on its own");
  const n = await events(r.S);
  const b = await F.resolveLate(r.a0, { items: [{ post: p1.id, how: "not_material", why: "a" }, { post: p2.id, how: "not_material", why: "b" }, { post: p3.id, how: "folded", where: "c" }], generation: own.generation, digest: own.digest, key: "s1" });
  refused(b, new RegExp(`post #${p2.id} \\(item 2\\) was resolved already .*Leave those items out and send the batch again\\. Nothing was recorded\\. Still late: post #${p1.id}, post #${p3.id}\\.`));
  assert.deepEqual((b.problems as Array<{ index: number }>).map((x) => x.index), [2]);
  assert.equal(b.stale, undefined, "the generation and digest hold");
  assert.deepEqual(b.unresolved, [{ kind: "post", id: p1.id }, { kind: "post", id: p3.id }]);
  assert.equal(await events(r.S), n, "nothing recorded");
  refused(await F.resolveLate(r.a0, { items: [{ post: 999, how: "not_material", why: "x" }], generation: own.generation, digest: own.digest }), /post #999 \(item 1\) is not late against the report/);
  const bad = await F.resolveLate(r.a0, { items: [{ post: p1.id, how: "folded" }, { post: p3.id, ack: 4, how: "not_material", why: "x" }, { post: p1.id, how: "ignored" }], key: "" });
  refused(bad, /a batch carries generation .*, and digest .*, and key: 1 to 200 characters.*folded needs where: where the report says it now.*names one: post .* or ack .*how is folded .* or not_material/);
  refused(await F.resolveLate(r.a0, { items: [{ post: p1.id, how: "not_material", why: "a" }, { post: p1.id, how: "not_material", why: "b" }], generation: own.generation, digest: own.digest }), /is named twice in this batch \(items 1 and 2\)/);
  refused(await F.resolveLate(r.a0, { items: [], generation: own.generation, digest: own.digest }), /items is a list of what you resolve, at least one/);
  refused(await F.resolveLate(r.a0, { items: [{ post: p1.id, how: "not_material", why: "x".repeat(L.LEAD_WHY_MAX + 1) }], generation: own.generation, digest: own.digest }), /nothing is cut, so a longer text is refused/);
  assert.equal(await events(r.S), n);
});

test("the final transaction is unchanged: a veto, an objection or an evidence addition racing the done still holds the sentinel after prepare and a batch", async () => {
  const r = await run("fprace");
  await established(r);
  await publish(r.S, "a0", "# Report\n");
  await tick();
  const p1 = await P.postMessage(r.a1, { tag: "result", body: "one" });
  const own = await prepare(r.a0, REPORT);
  assert.ok((await F.resolveLate(r.a0, { items: [{ post: p1.id, how: "not_material", why: "a" }], generation: own.generation, digest: own.digest })).ok);
  const turn = await F.finishTurnFor(r.a0, { output_file: REPORT });
  assert.equal(F.lateRefusal(turn, REPORT), null, "nothing late when the done began");
  const lease = { holder: turn.holder, generation: turn.generation };
  // A veto lands while the checks run.
  await tick();
  const veto = await P.postMessage(r.a2, { tag: "veto", body: "the first account is a service account" });
  await assert.rejects(P.markDone(r.a0, { reason: "finished", outputFile: REPORT, finish: lease }), new RegExp(`late against the report: post #${veto.id} \\(veto\\) by a2.*finish resolve, all in one call with items`));
  assert.ok((await F.resolveLate(r.a0, { items: [{ post: veto.id, how: "not_material", why: "the service account ran only the task" }], generation: 1, digest: own.digest })).ok);
  // An objection lands while the checks run.
  const obj = await F.ackReport(r.a2, { verdict: "objection", why: "the task is not in the report" });
  assert.ok(obj.ok);
  await assert.rejects(P.markDone(r.a0, { reason: "finished", outputFile: REPORT, finish: lease }), /late against the report: objection/);
  assert.ok((await F.resolveLate(r.a0, { items: [{ ack: (obj as { seq: number }).seq, how: "not_material", why: "the task is in section 2" }], generation: 1, digest: own.digest })).ok);
  // Evidence is added while the checks run: the revision the checks ran at no longer holds.
  const { revision } = await P.stateRevision(r.S);
  const src = join(r.S, "..", "late-export");
  await mkdir(src, { recursive: true });
  await writeFile(join(src, "proxy.csv"), "time,host\n09:58,ws\n");
  const added = await admitMaterial(r.S, { mode: "evidence", path: join(src, "proxy.csv"), why: "the proxy export", supplied_by: "operator", via: "cli" });
  assert.equal(added.ok, true, JSON.stringify(added));
  await assert.rejects(P.markDone(r.a0, { reason: "finished", outputFile: REPORT, finish: lease, revision }), new RegExp(P.FINISH_LINE_UNSETTLED.slice(0, 40).replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  assert.equal(await P.swarmDoneExists(r.S), false);
});

test("the metric: a run whose only first-done refusal would have been late items has none when the coordinator prepares and resolves in one batch", async () => {
  /** The coordinator's done as the done tool answers it (agent-swarm.ts): the late items first, then the sentinel; a trace row as it writes one. */
  const doneAs = async (S: string, c: Ctx) => {
    const turn = await F.finishTurnFor(c, { output_file: REPORT });
    const reason = F.lateRefusal(turn, REPORT);
    if (reason) {
      await traceRow(S, c.agentId, "done", { reason: "finished", output_file: REPORT }, { ok: false, reason, late: turn.late.length });
      return false;
    }
    const r = await P.markDone(c, { reason: "finished", outputFile: REPORT, finish: { holder: turn.holder, generation: turn.generation } });
    await traceRow(S, c.agentId, "done", { reason: "finished", output_file: REPORT }, { reason: "finished", output_file: REPORT, created_sentinel: "created_sentinel" in r && r.created_sentinel });
    return true;
  };
  const finishTool = async (S: string, c: Ctx, params: Record<string, unknown>) => {
    const out = await F.finishAct(c, params);
    await traceRow(S, c.agentId, "finish", params, { ok: out.ok, action: params.action });
    return out as Record<string, unknown> & { ok: boolean };
  };
  const shaped = async (id: string) => {
    const r = await run(id);
    await established(r);
    await publish(r.S, "a0", "# Report\n\n## 1. Who logged on, and when?\n\nThe first account, at 09:14.\n");
    await tick();
    await P.postMessage(r.a1, { tag: "result", body: "the second logon at 09:20 is the same session" });
    await P.postMessage(r.a2, { tag: "result", body: "the logon came over the VPN" });
    await F.syncReadiness(r.S, await F.readiness(r.S));
    // The finish line would pass: the only thing a done could be refused on is what is late.
    const c = await checkLedgerAnswers(r.S, ["1"]);
    const runRow = { total: 1, passed: c.ok ? 1 : 0, source: "registry", checks: [{ cmd: "check-answers --sections 1", ok: c.ok, answers: { outcomes: c.outcomes, results: c.results, dispositions: c.dispositions, best_candidate: c.best_candidate, named: [] } }] };
    const verdict = P.finishLineVerdict({ ...runRow, gate: await finishGate(r.S, runRow) }, false);
    assert.equal(verdict.proceed, true, JSON.stringify(verdict));
    return r;
  };
  // Without prepare: the coordinator's first done is refused on the late items alone, then each is resolved.
  const a = await shaped("fpma");
  assert.equal(await doneAs(a.S, a.a0), false);
  for (const x of await F.lateItems(a.S, "a0", REPORT)) await finishTool(a.S, a.a0, { action: "resolve", post: x.id, how: "not_material", why: "already in section 1" });
  assert.equal(await doneAs(a.S, a.a0), true);
  // With prepare and one batch: the first done goes on.
  const b = await shaped("fpmb");
  const p = await finishTool(b.S, b.a0, { action: "prepare", report: REPORT });
  const late = p.late as F.LateItem[];
  assert.equal(late.length, 2);
  await finishTool(b.S, b.a0, { action: "resolve", items: late.map((x) => ({ post: x.id, how: "not_material", why: "already in section 1" })), generation: p.generation, digest: p.digest, key: "tail-1" });
  assert.equal(await doneAs(b.S, b.a0), true);
  const ma = await measureRun(a.S);
  const mb = await measureRun(b.S);
  assert.deepEqual([ma.finish.first_done?.how, ma.finish.first_done_late, ma.finish.late_refusals], ["refused: late posts", true, 1]);
  assert.deepEqual([mb.finish.first_done?.how, mb.finish.first_done_late, mb.finish.late_refusals], ["accepted: wrote the sentinel", false, 0]);
  // The calls are counted, so a refusal renamed into more calls cannot pass for a gain.
  assert.deepEqual([ma.finish.calls.prepare, ma.finish.calls.resolve, ma.finish.calls.resolve_batches, ma.finish.resolutions, ma.finish.batches], [0, 2, 0, 2, 0]);
  assert.deepEqual([mb.finish.calls.prepare, mb.finish.calls.resolve, mb.finish.calls.resolve_batches, mb.finish.resolutions, mb.finish.batches], [1, 1, 1, 2, 1]);
  assert.equal(ma.done.refused_by["late posts"], 1);
  assert.equal(mb.done.refused_by["late posts"], undefined);
  assert.equal(typeof mb.finish.tail.minutes, "number", JSON.stringify(mb.finish.tail));
  assert.equal(mb.finish.tail.calls.done, 1);
  const text = (await import("../scripts/metrics.ts")).metricsText(mb);
  assert.match(text, /the first done accepted: wrote the sentinel \(a0\); 0 done\(s\) refused on late items; finish calls: 1 prepare, 1 resolve \(1 with items\)/);
  assert.match((await import("../scripts/metrics.ts")).metricsText(ma), /the first done refused: late posts \(a0\), on late items; 1 done\(s\) refused on late items/);
  // What the trace keeps of the finish acts is read back from the register too.
  assert.match(await readFile(join(b.S, "leads", "finish.jsonl"), "utf8"), /"ev":"prepare"/);
});

test("what holds the finish is given by code, and the trace keeps the codes and counts: an answer with no critic act holds it as no_critic_act", async () => {
  const r = await run("fp-held");
  const f = await P.recordEntry(r.a0, { kind: "finding", ...FINDING, value: "a logon at 09:14 by the first account", source: "the log", evidence: "line 12", refs: ["job:j000001/hits.txt"], answers: ["1"] } as unknown as P.LedgerInput);
  assert.ok(f.ok, JSON.stringify(f));
  const seq = (f as { entry: P.LedgerEntry }).entry.seq;
  const a = await P.recordEntry(r.a1, { kind: "answer", section: "question:1", value: "The first account, at 09:14", reasoning: `E-${seq}`, confidence: "high", confidence_why: "direct", alternatives_open: "none open", would_change: "a second source", result: "established" } as unknown as P.LedgerInput);
  assert.ok(a.ok, JSON.stringify(a));
  const st = (await F.finishStatus(r.a0)) as { ready: boolean; items: string[]; held?: Array<{ section: string; code: string }> };
  assert.equal(st.ready, false);
  assert.ok(st.held?.some((h) => h.section === "question:1" && h.code === "no_critic_act"), JSON.stringify(st.held));
  const counts = F.readinessCounts(st as unknown as Record<string, unknown>);
  assert.equal(counts.ready, false);
  assert.equal(counts.items, st.items.length);
  assert.ok((counts.held?.no_critic_act ?? 0) >= 1, JSON.stringify(counts));
  // No words of an item reach the counts.
  assert.ok(!JSON.stringify(counts).includes("question:1"), JSON.stringify(counts));
  await publish(r.S, "a0", "# Report\n\n## 1\n\nThe first account.\n");
  const p = await prepare(r.a0, REPORT);
  assert.ok(p.ok, JSON.stringify(p));
  assert.ok(((p.readiness as { held?: unknown[] }).held ?? []).length >= 1, JSON.stringify(p.readiness));
  assert.deepEqual(F.heldCodes([{ code: "sweep_hits" }, { code: "sweep_hits" }, { code: "no_critic_act" }, {}]), { sweep_hits: 2, no_critic_act: 1 });
});
