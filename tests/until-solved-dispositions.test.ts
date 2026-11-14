/**
 * One rule for the end of a run, under every stop policy (docs/adr/0013,
 * joint-r3 Phase 1a): done finishes a run only when every question in scope
 * has a disposition under the bar. A not_determinable answer on a coverage
 * record another seat reviewed is one: the done proceeds, examination-
 * limited. An unreviewed one, one behind a quick negative nobody attested,
 * one whose coverage no longer stands, a best candidate (B2) and a defect a
 * limitation only names are none: the done is refused, with the way to a
 * disposition said. The stop policy decides only who else ends the run:
 * --stop operator (its alias --until-solved) takes the caps and the wall
 * clock away and adds no stricter answer requirement; under cap-pause and
 * cap-stop a cap pauses or stops the run whatever the questions' state, and
 * that end is paused or stopped, never completed.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import * as FIN from "../extensions/finish.ts";
import * as P from "../extensions/protocol.ts";
import * as L from "../extensions/leads.ts";
import { checkLedgerAnswers } from "../scripts/check-answers.ts";
import { finishGate } from "../scripts/finish-gate.ts";
import { A, coverage, coversDiskAndLog, ESTABLISHED, F, ok, planned, rec, REVIEW, run } from "./negative-bar-fixture.ts";

const GOAL = [
  "## Goal",
  "",
  "Examine the host.",
  "",
  "### Questions",
  "",
  "1. Who logged on?",
  "2. Was a remote tool installed?",
  "",
  "## Definition of done",
  "",
  "d",
  "",
  "## Checks",
  "",
  '- `node x "$SWARM_HARNESS/scripts/check-answers.ts" --sections 1,2 --existence 2`',
  "",
].join("\n");

/** A run of two questions, its stop the operator's unless said otherwise. */
async function operatorRun(o: { until?: boolean } = {}) {
  const r = await run({ goal: GOAL });
  if (o.until !== false) {
    const b = await P.readBudget(r.S);
    await P.writeBudget(r.S, { ...b, stop_policy: "operator", until_solved: true, wall_clock_minutes: 0 });
  }
  return r;
}

/** The finish line as the harness runs it: the goal's answers check, then the gate, then the verdict. */
async function finish(S: string) {
  const r = await checkLedgerAnswers(S, ["1", "2"], ["2"]);
  const named = r.defects.filter((d) => d.named_by.length).map((d) => `${d.what} (named by ${d.named_by.map((n) => `#${n}`).join(", ")})`);
  const checks = { total: 1, passed: r.ok ? 1 : 0, source: "registry", checks: [{ cmd: "check-answers --sections 1,2 --existence 2", ok: r.ok, out: r.lines.join("\n"), answers: { outcomes: r.outcomes, results: r.results, dispositions: r.dispositions, best_candidate: r.best_candidate, named } }] };
  const gate = await finishGate(S, checks);
  return { check: r, gate, verdict: P.finishLineVerdict({ ...checks, gate }, false) };
}

/** Question 1 answered on a finding, established by another seat, its lead closed. */
async function answerOne(r: Awaited<ReturnType<typeof operatorRun>>, strength: "established" | "best_candidate" = "established") {
  const lead = await planned(r.a0, "1", [{ source: "input:logs/a.log", method: "read the logons" }]);
  const f = ok(await rec(r.a0, { kind: "finding", ...F, value: "alice logged on at 09:14", source: "the log", evidence: "line 12", refs: ["job:j000002/hits.txt"], answers: ["1"] })).entry;
  ok(await rec(r.a1, { kind: "answer", section: "question:1", value: "alice", reasoning: `E-${f.seq} shows the logon`, ...A, confidence: "high", result: "established" }));
  const ans = (await P.readLedger(r.S)).find((e) => e.kind === "answer" && e.section === "question:1")!;
  await coversDiskAndLog(r.a0, "1");
  const att = await P.attestEntry(r.a2, { seq: ans.seq, how: "re-read the log line from job:j000002", ...ESTABLISHED, strength } as never);
  assert.ok(att.ok, (att as { reason?: string }).reason);
  assert.ok((await L.closeLead(r.a0, lead, { disposition: "resolved", ref: `E-${f.seq}` })).ok);
}

/** Question 2 answered not_determinable on a coverage record; the search's lead closed negative, quick when asked. */
async function notDeterminable(r: Awaited<ReturnType<typeof operatorRun>>, o: { quick?: boolean } = {}) {
  const lead = await planned(r.a0, "2");
  // A lead closed at once after one job over one object is a quick negative; one whose job read everything is not.
  await L.attachJob(r.S, "a0", o.quick ? "j000001" : "j000006", lead);

  const job = o.quick ? "j000001" : "j000006";
  const absence = ok(await rec(r.a0, { kind: "absence", value: "a remote tool", source: "inputs/disk.E01", evidence: "a search over the disk", completion: "complete", refs: [`job:${job}/hits.txt`], control: { ref: `job:${job}/hits.txt`, found: "the same search finds a planted row" }, answers: ["2"] })).entry;
  assert.ok((await L.recordInterpretations(r.S, "a0", absence.seq, [{ job }])).ok);
  const closed = await L.closeLead(r.a0, lead, { disposition: "negative", ref: `E-${absence.seq}` });
  assert.ok(closed.ok, (closed as { reason?: string }).reason);
  assert.equal(Boolean((closed as { lead: L.LeadView }).lead.quick_negative), Boolean(o.quick));
  const cov = ok(await rec(r.a0, coverage("2", ["input:disk.E01"], [`E-${absence.seq}`, `job:${job}/hits.txt`], { detection_opportunity: { trace_expected: "unknown", why: "the tool may leave nothing on disk" } }))).entry;
  const ans = ok(await rec(r.a1, { kind: "answer", section: "question:2", value: "It cannot be determined from the disk whether a remote tool was installed", reasoning: `E-${cov.seq} over E-${absence.seq}`, ...A, result: "not_determinable" })).entry;
  return { lead, absence, cov, ans };
}

test("under --stop operator, a not_determinable answer on a coverage record another seat reviewed is a disposition: the done proceeds, examination-limited", async () => {
  const r = await operatorRun();
  await answerOne(r);
  const q2 = await notDeterminable(r);
  let f = await finish(r.S);
  assert.equal(f.gate.until_solved, true);
  assert.equal(f.verdict.proceed, false, "unreviewed, it is no disposition yet: the answers check holds it");
  if (!f.verdict.proceed) assert.match(f.verdict.reason, /negative \(unreviewed\)/);
  assert.ok((await P.attestEntry(r.a2, { seq: q2.cov.seq, how: "ran the search again from job:j000001", review: REVIEW })).ok);
  f = await finish(r.S);
  assert.deepEqual(f.gate.questions.map((q) => [q.id, q.outcome, q.disposition]), [["1", "answered", "established"], ["2", "inconclusive", "not_determinable"]]);
  assert.ok(f.verdict.proceed, JSON.stringify(f.verdict));
  assert.equal(f.verdict.proceed && f.verdict.outcome, "examination_limited", "not determinable limits the run; it never holds it");
  // The same answers under a cap policy end the same way: the operator's policy adds nothing to the bar.
  const b = await P.readBudget(r.S);
  await P.writeBudget(r.S, { ...b, stop_policy: "cap-pause", until_solved: false });
  const capped = await finish(r.S);
  assert.equal(capped.verdict.proceed && capped.verdict.outcome, "examination_limited");
});

test("under --stop operator, readiness turns ready on the dispositions the done ends on: a reviewed not_determinable limits the run and holds nothing; a best candidate still holds it (the finished c10 pilot's readiness never turned ready)", async () => {
  const r = await operatorRun();
  await answerOne(r);
  const q2 = await notDeterminable(r);
  assert.ok((await P.attestEntry(r.a2, { seq: q2.cov.seq, how: "ran the search again from job:j000006", review: REVIEW })).ok);
  const f = await finish(r.S);
  assert.equal(f.verdict.proceed && f.verdict.outcome, "examination_limited", JSON.stringify(f.verdict));
  const ready = await FIN.readiness(r.S);
  assert.deepEqual([ready.ready, ready.items], [true, []], "the done passes here, so readiness is ready");
  assert.ok(ready.limited.some((l) => /question:2 is not determinable/.test(l)), JSON.stringify(ready.limited));
  // A best candidate is no disposition: it holds readiness under the operator's stop, as it holds the done.
  const best = await operatorRun();
  await answerOne(best, "best_candidate");
  const b2 = await notDeterminable(best);
  assert.ok((await P.attestEntry(best.a2, { seq: b2.cov.seq, how: "ran the search again from job:j000006", review: REVIEW })).ok);
  assert.equal((await finish(best.S)).verdict.proceed, false);
  const held = await FIN.readiness(best.S);
  assert.equal(held.ready, false);
  assert.ok(held.items.some((i) => /question:1 is a best candidate, not established/.test(i)), JSON.stringify(held.items));
  assert.ok(!held.items.some((i) => /question:2 is not determinable/.test(i)), "the disposition itself holds nothing");
});

test("under --stop operator, an unreviewed negative, a quick negative nobody attested, a coverage record that no longer stands and a best candidate each hold the done", async () => {
  // Unreviewed: the answers check itself holds a material negative.
  const unreviewed = await operatorRun();
  await answerOne(unreviewed);
  await notDeterminable(unreviewed);
  let f = await finish(unreviewed.S);
  assert.equal(f.check.ok, false);
  assert.ok(f.check.defects.some((d) => d.code === "negative_unreviewed"));
  assert.equal(f.verdict.proceed, false);
  // A quick negative nobody attested holds its question, though the negative was reviewed.
  const quick = await operatorRun();
  await answerOne(quick);
  const q = await notDeterminable(quick, { quick: true });
  assert.ok((await P.attestEntry(quick.a2, { seq: q.cov.seq, how: "ran the search again", review: REVIEW })).ok);
  f = await finish(quick.S);
  assert.equal(f.check.ok, true, f.check.lines.join("\n"));
  assert.equal(f.verdict.proceed, false);
  if (!f.verdict.proceed) {
    assert.match(f.verdict.reason, /- question:2 is inconclusive, with no disposition under the bar: L-\d+ "Work question 2" was closed a quick negative .* that nobody else has attested/);
    assert.equal(f.verdict.failing, "question:2");
  }
  assert.ok((await P.attestEntry(quick.a3, { seq: q.absence.seq, how: "ran the search again from job:j000001 over the whole disk" })).ok);
  f = await finish(quick.S);
  assert.equal(f.verdict.proceed && f.verdict.outcome, "examination_limited", JSON.stringify(f.verdict));
  // Its coverage no longer stands: the search it rests on corrected after the review.
  const stale = await operatorRun();
  await answerOne(stale);
  const s = await notDeterminable(stale);
  assert.ok((await P.attestEntry(stale.a2, { seq: s.cov.seq, how: "ran the search again", review: REVIEW })).ok);
  assert.equal((await finish(stale.S)).verdict.proceed, true);
  ok(await rec(stale.a0, { kind: "absence", value: "a remote tool", source: "inputs/disk.E01", evidence: "a search over one volume only", completion: "partial", refs: ["job:j000001/hits.txt"], control: { ref: "job:j000001/hits.txt", found: "the same search finds a planted row" }, answers: ["2"], supersedes: s.absence.seq, because: "the search stopped at the first volume" }));
  f = await finish(stale.S);
  assert.ok(f.check.defects.some((d) => d.code === "coverage_stale"));
  assert.equal(f.gate.questions.find((x) => x.id === "2")?.disposition, undefined);
  assert.equal(f.verdict.proceed, false);
  // A best candidate is never a disposition (B2): every review holds question 1 so.
  const best = await operatorRun();
  await answerOne(best, "best_candidate");
  const b = await notDeterminable(best);
  assert.ok((await P.attestEntry(best.a2, { seq: b.cov.seq, how: "ran the search again", review: REVIEW })).ok);
  f = await finish(best.S);
  assert.equal(f.gate.questions.find((x) => x.id === "1")?.disposition, undefined);
  assert.equal(f.verdict.proceed, false);
  if (!f.verdict.proceed) assert.match(f.verdict.reason, /- question:1 is limited, with no disposition under the bar: its answer is a best candidate, not established/);
});

test("a defect a limitation only names holds the done under every stop policy: --stop operator, cap-pause and cap-stop alike", async () => {
  const r = await operatorRun();
  await answerOne(r);
  const lead = await planned(r.a0, "2");
  // Question 2 unanswered, and a limitation that names it.
  const lim = ok(await rec(r.a0, { kind: "limitation", value: "The disk's second volume is encrypted and no key is in the case", source: "the disk", evidence: "the volume header", reason: "unavailable", answers: ["2"] })).entry;
  const closed = await L.closeLead(r.a0, lead, { disposition: "infeasible", ref: `E-${lim.seq}` });
  assert.ok(closed.ok, (closed as { reason?: string }).reason);
  let f = await finish(r.S);
  assert.equal(f.check.ok, true, "a named defect lets the check pass");
  assert.equal(f.verdict.proceed, false);
  if (!f.verdict.proceed) {
    assert.match(f.verdict.reason, /- question:2 is limited, with no disposition under the bar: L-\d+ "Work question 2" was closed infeasible: E-\d+; no standing answer entry/);
    assert.match(f.verdict.reason, /A defect is fixed, never only named:\n- a defect a limitation names: question:2 has no answer/);
    assert.match(f.verdict.reason, /When the evidence cannot answer a question, that is an answer too: plan its routes .* record a coverage record .* have another seat review it .* then answer not_determinable/);
  }
  // Cap-pause and cap-stop: the same refusal (before 2026-09-28 a cap policy ended examination-limited here).
  for (const policy of ["cap-pause", "cap-stop"] as const) {
    const b = await P.readBudget(r.S);
    await P.writeBudget(r.S, { ...b, stop_policy: policy, until_solved: false, wall_clock_minutes: 60 });
    f = await finish(r.S);
    assert.equal(f.gate.until_solved, false);
    assert.equal(f.verdict.proceed, false, `${policy}: a limitation that names the question is no disposition`);
    if (!f.verdict.proceed) {
      assert.equal(f.verdict.failing, "question:2");
      assert.match(f.verdict.reason, /done finishes a run, whatever its stop policy, only when every question in scope has a disposition under the bar/);
      assert.match(f.verdict.reason, /A cap pauses or stops the run whatever the questions' state/);
      assert.match(f.verdict.reason, /then answer not_determinable/);
    }
  }
});

test("cap-pause: a reviewed not_determinable lets done proceed, examination-limited; an unreviewed one does not", async () => {
  const r = await operatorRun({ until: false });
  await P.writeBudget(r.S, { ...(await P.readBudget(r.S)), stop_policy: "cap-pause" });
  await answerOne(r);
  const q2 = await notDeterminable(r);
  let f = await finish(r.S);
  assert.equal(f.gate.until_solved, false);
  assert.equal(f.verdict.proceed, false, "unreviewed: no disposition, under a cap policy too");
  assert.ok((await P.attestEntry(r.a2, { seq: q2.cov.seq, how: "ran the search again from job:j000006", review: REVIEW })).ok);
  f = await finish(r.S);
  assert.equal(f.verdict.proceed && f.verdict.outcome, "examination_limited", JSON.stringify(f.verdict));
});

test("a cap pauses or stops the run, and the operator stops it, whatever the questions' state: paused or stopped, never completed", async () => {
  // cap-pause: question 2 has no disposition, and the cap pauses the run all the same.
  const paused = await operatorRun({ until: false });
  await answerOne(paused);
  await planned(paused.a0, "2");
  const over = async (S: string, policy: "cap-pause" | "cap-stop") => {
    const b = await P.readBudget(S);
    await P.writeBudget(S, { ...b, stop_policy: policy, spent_usd: (b.cap_usd || 5) + 1, stop_steer_at: new Date(Date.now() - 5 * 60_000).toISOString(), stop_reason: "cap", cap_steer_sent: true });
  };
  await over(paused.S, "cap-pause");
  assert.equal((await finish(paused.S)).verdict.proceed, false, "the done waits for question 2");
  const p = await P.capAct(paused.S, "cap", "the cap passed and the grace period ended");
  assert.deepEqual([p.kind, p.created], ["paused", true]);
  assert.equal((await P.runOutcome(paused.S)).outcome, "paused");
  // cap-stop: the harness writes the sentinel itself, as stopped.
  const stopped = await operatorRun({ until: false });
  await answerOne(stopped);
  await planned(stopped.a0, "2");
  await over(stopped.S, "cap-stop");
  const s = await P.capAct(stopped.S, "cap", "the cap passed and the grace period ended");
  assert.deepEqual([s.kind, s.created], ["stopped", true]);
  assert.equal((await P.runOutcome(stopped.S)).outcome, "stopped", "a cap's end is stopped, never completed");
  // The operator's stop, whatever the policy and the questions.
  const operator = await operatorRun();
  await answerOne(operator);
  await planned(operator.a0, "2");
  await P.markStopped(operator.S, "operator", "swarm.sh stop");
  assert.equal((await P.runOutcome(operator.S)).outcome, "stopped");
});
