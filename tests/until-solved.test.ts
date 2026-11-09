/**
 * An until-solved run at the protocol level: every cap advisory and no wall
 * clock (each pressure the brakes read says nothing is over), no abandon (a
 * vote or not), and a finish line that takes every question in scope with a
 * disposition under the bar, the same as any run (the dispositions
 * themselves: tests/until-solved-dispositions.test.ts): a question with none,
 * a finish line that could not be run and an abandon are all refused, each
 * naming what is not disposed and what blocks it. The model gateway refuses no call for a cap. The regroup lists what is
 * open, blocked, waiting on the operator and uncited.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import * as P from "../extensions/protocol.ts";
import * as L from "../extensions/leads.ts";
import * as FIN from "../extensions/finish.ts";
import { finishGate } from "../scripts/finish-gate.ts";
import { refusalFor } from "../scripts/model-gateway.ts";
import * as NB from "./negative-bar-fixture.ts";

const dirs: string[] = [];
after(async () => {
  for (const d of dirs) await rm(d, { recursive: true, force: true });
});

const F = { basis: "observed", confidence: "high", indicates: "What the observation shows, and the step to it.", confidence_why: "Read directly from the object it cites." } as const;
const GOAL = ["## Goal", "", "g", "", "## Definition of done", "", "d", "", "## Checks", "", '- `node x "$SWARM_HARNESS/scripts/check-answers.ts" --sections 1,2,summary,narrative`', ""].join("\n");

async function run(o: { until?: boolean } = {}) {
  const base = await mkdtemp(join(tmpdir(), "until-"));
  dirs.push(base);
  const S = join(base, "run");
  await P.initSandbox(S, { swarmId: "u1", agentIds: ["a0", "a1", "a2"], capUsd: 5, wallClockMinutes: 30, goal: GOAL });
  if (o.until !== false) {
    const b = await P.readBudget(S);
    await P.writeBudget(S, { ...b, until_solved: true, stall_minutes: 15, wall_clock_minutes: 0 });
  }
  return { S, a0: { sandboxRoot: S, agentId: "a0" }, a1: { sandboxRoot: S, agentId: "a1" } };
}

test("every brake reads an until-solved run's caps as advisory and its clock as absent", () => {
  const over = P.normalizeBudget({ cap_usd: 1, spent_usd: 50, tokens: 9e9, cap_tokens: 1000, wall_clock_minutes: 1, started_at: new Date(Date.now() - 86_400_000).toISOString(), cap_per_agent_usd: 1, cap_per_agent_tokens: 10, cap_per_model_usd: { "m/x": 1 }, agents: { a0: { ...P.emptyAgentBudget(), spent_usd: 40, tokens: 9e9, model: "m/x" } } });
  assert.equal(P.overCap(over).over, true, "the same numbers stop an ordinary run");
  assert.equal(P.budgetPressure(over).reason, "cap");
  const until = P.normalizeBudget({ ...over, until_solved: true, wall_clock_minutes: 0 });
  assert.equal(until.wall_clock_minutes, 0, "an until-solved run's zero wall clock is kept, not read as unset");
  assert.equal(until.until_solved, true);
  assert.deepEqual(P.overCap(until), { over: false, by: null });
  const pressure = P.budgetPressure(until);
  assert.deepEqual([pressure.reason, pressure.over_budget, pressure.over_time], [null, false, false]);
  assert.equal(P.agentPressure(until, "a0").over, false);
  assert.equal(P.modelPressure(until, "m/x").over, false);
  // An ordinary run's zero wall clock still reads as the default.
  assert.equal(P.normalizeBudget({ ...over, wall_clock_minutes: 0 }).wall_clock_minutes, 15);
});

test("the model gateway refuses no call for a cap or a clock in an until-solved run, and still for the run's end", async () => {
  const { S } = await run();
  const b = await P.readBudget(S);
  await P.writeBudget(S, { ...b, cap_usd: 1, started_at: new Date(Date.now() - 86_400_000).toISOString() });
  const seat = { token: "t", model: "m/x", providers: [] } as never;
  const state = { spent_usd: 500, seats: { a0: { spent_usd: 500, input: 1e9, output: 0, cache_read: 0, cache_write: 0, model: "m/x" } } } as never;
  assert.equal(refusalFor(S, "a0", seat, state, Date.now(), 0), null);
  await writeFile(join(S, P.SENTINEL_REL), "---\nby: x\n---\n");
  assert.equal(refusalFor(S, "a0", seat, state, Date.now(), 0)?.code, "run_finished");
});

test("no abandon in an until-solved run: the verdict refuses it and markDone refuses it, a vote or not", async () => {
  const { a0 } = await run();
  const failing = { total: 1, passed: 0, checks: [{ cmd: "test -f work/report.md", ok: false }] };
  const v = P.finishLineVerdict(failing, true, { untilSolved: true });
  assert.equal(v.proceed, false);
  if (!v.proceed) assert.match(v.reason, /only the operator|operator stops it/);
  await assert.rejects(P.markDone(a0, { reason: `${P.ABANDON_PREFIX}the key is not in the image`, outputFile: "work/report.md" }), /until solved/);
  assert.equal(await P.swarmDoneExists(a0.sandboxRoot), false);
});

test("the until-solved gate refuses a question with no disposition under the bar (an answer resting on a limitation), and names what blocks it", async () => {
  const { S, a0, a1 } = await run();
  // Question 1 answered; question 2 rests on a limitation, its lead closed needs_operator.
  const f = await P.recordEntry(a0, { kind: "finding", ...F, value: "The volume holds the notes", source: "the volume", evidence: "listing", answers: ["1"] });
  assert.ok(f.ok);
  const lim = await P.recordEntry(a0, { kind: "limitation", value: "The third part's key is outside the image", source: "the plaintext", evidence: "the pointer", reason: "unavailable", answers: ["2"] });
  assert.ok(lim.ok);
  assert.equal((await L.openLead(a1, { title: "Follow the pointer outside the image", why: "question 2's key", answers: ["2"], take: true })).ok, true);
  assert.equal((await L.closeLead(a1, "L-1", { disposition: "needs_operator", ref: "Allow the host the pointer names" })).ok, true);
  // What the answers check said, as await-done hands it back.
  const checks = { total: 1, passed: 1, checks: [{ cmd: "check-answers", ok: true, answers: { outcomes: { "question:1": "answered", "question:2": "limited", summary: "answered", narrative: "answered" }, named: [] } }] };
  const gate = await finishGate(S, checks);
  assert.equal(gate.until_solved, true);
  assert.deepEqual(gate.defects, []);
  assert.ok(gate.limited.some((l) => /question:2 is examination-limited/.test(l)), JSON.stringify(gate.limited));
  assert.ok(gate.limited.some((l) => /L-1 was closed needs_operator/.test(l)));
  const q2 = gate.questions.find((q) => q.id === "2")!;
  assert.equal(q2.outcome, "limited");
  assert.ok(q2.blocks.some((b) => /L-1 "Follow the pointer outside the image" was closed needs_operator: Allow the host the pointer names/.test(b)), JSON.stringify(q2.blocks));
  const v = P.finishLineVerdict({ ...checks, gate }, false);
  // Refused: question 2 rests on a limitation, which is no disposition under
  // the bar (before 2026-09-28 this said "ends only when every question is
  // answered", and refused a reviewed not_determinable too).
  assert.equal(v.proceed, false, "a question with no disposition under the bar holds the run");
  if (!v.proceed) {
    assert.match(v.reason, /it ends when every question in scope has a disposition under the bar/);
    assert.match(v.reason, /- question:2 is limited, with no disposition under the bar: .*L-1/);
    assert.match(v.reason, /Only the operator can stop this run/);
  }
  // The same run under a cap policy is refused too: one rule under every
  // stop policy (before 2026-09-28 it ended examination-limited on a
  // question resting on a limitation). Only an abandon ends it there, which
  // an until-solved run refuses.
  const ordinary = P.finishLineVerdict({ ...checks, gate: { ...gate, until_solved: false } }, false);
  assert.equal(ordinary.proceed, false, JSON.stringify(ordinary));
  if (!ordinary.proceed) assert.match(ordinary.reason, /done finishes a run, whatever its stop policy, only when every question in scope has a disposition under the bar/);
  const abandoned = P.finishLineVerdict({ ...checks, gate: { ...gate, until_solved: false } }, true);
  assert.ok(abandoned.proceed && abandoned.outcome === "abandoned", JSON.stringify(abandoned));
  assert.equal(P.finishLineVerdict({ ...checks, gate }, true).proceed, false, "no abandon under the operator's stop");
  // A finish line that could not be run is a refusal too, never an end.
  const unavailable = P.finishLineVerdict(null, false, { untilSolved: true });
  assert.equal(unavailable.proceed, false);
  // Every question answered, nothing limited: it ends completed.
  const done = P.finishLineVerdict({ ...checks, gate: { defects: [], limited: [], questions: [{ id: "1", outcome: "answered", blocks: [] }, { id: "2", outcome: "answered", blocks: [] }], until_solved: true } }, false);
  assert.ok(done.proceed && done.outcome === "completed");
});

test("20,000 uncited input files give a regroup post under the bound that counts the rest and names the file holding all 20,000", async () => {
  const { S } = await run();
  const files = Array.from({ length: 20_000 }, (_, i) => ({ path: `inputs/case/dir${String(Math.floor(i / 100)).padStart(3, "0")}/file-${String(i).padStart(6, "0")}.bin`, bytes: 1000 + i, sha256: "c".repeat(64) }));
  await writeFile(join(S, "inputs.json"), JSON.stringify({ files }));
  const snap = await L.leadsSnapshot(S);
  const since = await L.lastProgress(S, snap, new Date(Date.now() - 3_600_000).toISOString());
  const text = await L.regroupMessage(S, snap, { minutes: 20, since, count: 1, nextMinutes: 30 });
  assert.ok(text.length <= P.inboxPageChars(), `the post is ${text.length} characters, over the bound of ${P.inboxPageChars()}`);
  const listed = (text.match(/^- inputs\/case\//gm) ?? []).length;
  assert.ok(listed > 0 && listed <= 50, `${listed} files listed`);
  assert.match(text, /Evidence no standing entry cites \(20000\):/);
  const rest = 20_000 - listed;
  assert.match(text, new RegExp(`- \\.\\.\\. and ${rest} more, not listed here \\(20000 in all\\): every list, whole, is in (tool-output/harness/\\S+) \\((\\d+) bytes, sha256 ([0-9a-f]{64})\\)`));
  const m = /every list, whole, is in (tool-output\/harness\/\S+) \((\d+) bytes, sha256 ([0-9a-f]{64})\)/.exec(text)!;
  const kept = await readFile(join(S, m[1]!));
  assert.equal(kept.length, Number(m[2]));
  assert.equal(createHash("sha256").update(kept).digest("hex"), m[3]);
  assert.equal((kept.toString("utf8").match(/^- inputs\/case\//gm) ?? []).length, 20_000, "all 20,000 are in the file");
  // A short regroup is unchanged: no file, no "more".
  await writeFile(join(S, "inputs.json"), JSON.stringify({ files: files.slice(0, 3) }));
  const small = await L.regroupMessage(S, await L.leadsSnapshot(S), { minutes: 20, since, count: 1, nextMinutes: 30 });
  assert.doesNotMatch(small, /more, not listed here/);
});

test("the regroup lists the questions not answered, the leads open and blocked, what waits on the operator and the evidence no entry cites", async () => {
  const { S, a0, a1 } = await run();
  await writeFile(join(S, "inputs.json"), JSON.stringify({ files: [{ path: "inputs/disk.E01", bytes: 10, sha256: "a".repeat(64) }, { path: "inputs/phone.tar", bytes: 20, sha256: "b".repeat(64) }] }));
  await mkdir(join(S, "catalog", "gen", "g0002"), { recursive: true });
  await writeFile(join(S, "catalog", "gen", "g0002", "generation.json"), JSON.stringify({ id: "g0002", target: { ref: "job:j000009/vault.img", name: "the decrypted vault" }, coverage: { covered: "its file list", members: 42 } }));
  const f = await P.recordEntry(a0, { kind: "finding", ...F, value: "The phone holds the notes", source: "phone", evidence: "listing", refs: ["unresolved:the archive was listed by hand"], answers: ["1"] });
  assert.ok(f.ok);
  assert.equal((await L.openLead(a0, { title: "Find the key", why: "the vault", take: true })).ok, true);
  assert.equal((await L.openLead(a1, { title: "Read the vault", why: "question 2", needs: ["L-1"], answers: ["2"], take: true })).ok, true);
  assert.equal((await L.openLead(a1, { title: "Walk the second profile", why: "nobody has" })).ok, true);
  assert.equal((await L.openLead(a1, { title: "The outside resource", why: "the pointer", take: true })).ok, true);
  assert.equal((await L.closeLead(a1, "L-4", { disposition: "needs_operator", ref: "Allow the host the plaintext names" })).ok, true);
  const snap = await L.leadsSnapshot(S);
  const since = await L.lastProgress(S, snap, new Date(Date.now() - 3_600_000).toISOString());
  assert.match(since.what, /L-4 closed needs_operator|E-1/);
  const text = await L.regroupMessage(S, snap, { minutes: 20, since, count: 1, nextMinutes: 30 });
  assert.match(text, /^REGROUP 1: nothing has moved for 20 minutes/);
  assert.match(text, /Questions not answered \(2\):\n- question:1: no answer; no lead names it\n- question:2: no answer; L-2 blocked \(a1\) on L-1:resolved/);
  assert.match(text, /Leads open, held by nobody \(1\):\n- L-3 "Walk the second profile"/);
  assert.match(text, /Leads blocked \(1\):\n- L-2 "Read the vault" \(a1\) waiting on L-1:resolved: L-1 is held by a0/);
  assert.match(text, /Waiting on the operator \(1\):\n- L-4 "The outside resource": Allow the host the plaintext names/);
  assert.match(text, /Evidence no standing entry cites \(3\):\n- inputs\/disk\.E01 \(10 bytes; case evidence\)\n- inputs\/phone\.tar \(20 bytes; case evidence\)\n- catalogue g0002: the decrypted vault \(its file list, 42 listed; lineage not recorded\)/);
  assert.match(text, /the next regroup comes in 30 minutes/);
});

/** Four questions the finish line holds for four different reasons. */
const FOUR = [
  "## Goal",
  "",
  "Examine the host.",
  "",
  "### Questions",
  "",
  "1. Who logged on?",
  "2. Was a remote tool installed?",
  "3. What was deleted?",
  "4. When did it start?",
  "",
  "## Must establish",
  "",
  "- 3",
  "",
  "## Definition of done",
  "",
  "d",
  "",
  "## Checks",
  "",
  '- `node x "$SWARM_HARNESS/scripts/check-answers.ts" --sections 1,2,3,4`',
  "",
].join("\n");

test("the regroup lists every required question the finish line holds, whatever the kind of gap: no answer, a best candidate, an unmet must-establish and a disputed answer", async () => {
  const c = await NB.run({ goal: FOUR });
  const { A, covers, ESTABLISHED, F, ok, partialParts, partsReview, planned, rec } = NB;
  // Question 2: an answer that claims established, every review of which holds it a best candidate only.
  await planned(c.a0, "2");
  const f2 = ok(await rec(c.a0, { kind: "finding", ...F, value: "a remote tool's service entry", source: "the disk", evidence: "a registry key", refs: ["job:j000001/hits.txt"], answers: ["2"] })).entry;
  const a2 = ok(await rec(c.a1, { kind: "answer", section: "question:2", value: "Yes: a remote tool was installed as a service", reasoning: `E-${f2.seq}`, ...A, result: "established" })).entry;
  assert.ok((await P.attestEntry(c.a2, { seq: a2.seq, how: "re-read the key", ...ESTABLISHED, strength: "best_candidate" })).ok);
  // Question 3 must be established: its answer is partial, which ends no run on it.
  await planned(c.a0, "3", [{ source: "input:logs/a.log", method: "read the log" }]);
  const f3 = ok(await rec(c.a0, { kind: "finding", ...F, value: "two files were deleted at 09:14", source: "the log", evidence: "line 12", refs: ["job:j000002/hits.txt"], answers: ["3"] })).entry;
  const lim3 = ok(await rec(c.a0, { kind: "limitation", value: "The log does not name the files", source: "the log", evidence: "its fields", reason: "unavailable", answers: ["3"] })).entry;
  const a3 = ok(await rec(c.a1, { kind: "answer", section: "question:3", value: "Two files, at 09:14; which ones is open", reasoning: `E-${f3.seq}; which is open (E-${lim3.seq})`, ...A, result: "partial", parts: partialParts(f3.seq, `E-${lim3.seq}`) })).entry;
  assert.ok((await P.attestEntry(c.a2, { seq: a3.seq, how: "re-read line 12", ...partsReview(ESTABLISHED) })).ok);
  // Question 4: established and attested, then disputed.
  await planned(c.a0, "4");
  const f4 = ok(await rec(c.a0, { kind: "finding", ...F, value: "it started at 08:00", source: "the disk", evidence: "a registry key", refs: ["job:j000001/hits.txt"], answers: ["4"] })).entry;
  const a4 = ok(await rec(c.a1, { kind: "answer", section: "question:4", value: "It started at 08:00", reasoning: `E-${f4.seq}`, ...A, confidence: "high", result: "established" })).entry;
  await covers(c.a0, "4");
  assert.ok((await P.attestEntry(c.a2, { seq: a4.seq, how: "re-read the key", ...ESTABLISHED })).ok);
  assert.ok((await P.disputeEntry(c.a3, { seq: a4.seq, why: "the registry key is the installer's, not the first run's" })).ok);
  // The finish line holds all four questions, for four reasons; the post says all four, in its words.
  const ready = await FIN.readiness(c.S);
  assert.deepEqual([...new Set((ready.held ?? []).map((h) => h.section))].sort(), ["question:1", "question:2", "question:3", "question:4"], JSON.stringify(ready.items));
  const snap = await L.leadsSnapshot(c.S);
  const since = await L.lastProgress(c.S, snap, new Date(Date.now() - 3_600_000).toISOString());
  const text = await L.regroupMessage(c.S, snap, { minutes: 20, since, count: 1, nextMinutes: 30 });
  assert.match(text, /Questions not answered \(4\):/);
  assert.match(text, /- question:1: no answer/);
  assert.match(text, /- question:2: answer E-\d+ claims established and every review holds it a best candidate only/);
  assert.match(text, /- question:3: must be established \(required by .*\): answer E-\d+ is partial/);
  assert.match(text, /- question:4: .*disputed/);
});

test("a validation control and a tool reference are listed apart with their lineage role, not as evidence no entry cites; case-derived objects stay in the evidence list", async () => {
  const c = await NB.run();
  await writeFile(join(c.S, "inputs.json"), JSON.stringify({ files: [{ path: "inputs/disk.E01", bytes: 10, sha256: "a".repeat(64) }] }));
  const made = (id: string, spec: Record<string, unknown>) => NB.job(c.S, id, "out.img", { spec });
  await made("j000020", { kind: "command", scope: "declared", inputs: [], command: "mkimg" });
  await made("j000021", { kind: "command", scope: "declared", inputs: ["input:disk.E01"], command: "carve" });
  await made("j000022", { kind: "tool", scope: "declared", inputs: [], tool: "reference_table" });
  for (const [g, job, name] of [["g0101", "j000020", "a control image"], ["g0102", "j000021", "a carved volume"], ["g0103", "j000022", "the tool's table"]] as const) {
    await mkdir(join(c.S, "catalog", "gen", g), { recursive: true });
    await writeFile(join(c.S, "catalog", "gen", g, "generation.json"), JSON.stringify({ id: g, target: { ref: `job:${job}/out.img`, name }, coverage: { covered: "its listing", members: 3 } }));
  }
  const snap = await L.leadsSnapshot(c.S);
  const since = await L.lastProgress(c.S, snap, new Date(Date.now() - 3_600_000).toISOString());
  const text = await L.regroupMessage(c.S, snap, { minutes: 20, since, count: 1, nextMinutes: 30 });
  assert.match(text, /Evidence no standing entry cites \(2\):\n- inputs\/disk\.E01 \(10 bytes; case evidence\)\n- catalogue g0102: a carved volume \(its listing, 3 listed; case-derived\)\n/);
  assert.match(text, /Controls and tool references, apart from the evidence \(2\):[^\n]*\n- catalogue g0101: a control image \(its listing, 3 listed; validation control\)\n- catalogue g0103: the tool's table \(its listing, 3 listed; tool reference\)/);
});
