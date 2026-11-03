/**
 * Partial is a disposition, and "a best candidate" concerns only an answer
 * that claims established (docs/adr/0015, "After the run s9722fa"). On that
 * run (a CTF case, six goal questions, --stop operator) every question had a
 * partial answer with medium confidence; each review was capped to
 * best_candidate by the answer's confidence and by the parts the answer
 * itself declared open; readiness then held all six as "a best candidate,
 * not established", the answers check disposed them partial, and the seats
 * read the finish status as "not under the bar" and walked every answer down
 * to not determinable. Readiness, the answers check and the finish gate now
 * read one test (protocol.ts heldAsBestCandidate), under every stop policy,
 * and a partial answer's review attests its own claims. Synthetic runs only.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import * as FIN from "../extensions/finish.ts";
import * as P from "../extensions/protocol.ts";
import * as L from "../extensions/leads.ts";
import { checkLedgerAnswers } from "../scripts/check-answers.ts";
import { finishGate } from "../scripts/finish-gate.ts";
import { A, covers, ESTABLISHED, F, ok, planned, rec, refused, run } from "./negative-bar-fixture.ts";

const GOAL = [
  "## Goal",
  "",
  "Examine the host.",
  "",
  "### Questions",
  "",
  "1. Who logged on, and when?",
  "2. Was a remote tool installed?",
  "",
  "## Definition of done",
  "",
  "d",
  "",
  "## Checks",
  "",
  '- `node x "$SWARM_HARNESS/scripts/check-answers.ts" --sections 1,2`',
  "",
].join("\n");

const POLICIES = ["operator", "cap-pause", "cap-stop"] as const;

async function setPolicy(S: string, policy: (typeof POLICIES)[number]): Promise<void> {
  const b = await P.readBudget(S);
  await P.writeBudget(S, policy === "operator" ? { ...b, stop_policy: "operator", until_solved: true, wall_clock_minutes: 0 } : { ...b, stop_policy: policy, until_solved: false, wall_clock_minutes: 60 });
}

/** The finish line as the harness runs it: the goal's answers check, then the gate, then the verdict. */
async function finish(S: string) {
  const r = await checkLedgerAnswers(S, ["1", "2"]);
  const named = r.defects.filter((d) => d.named_by.length).map((d) => `${d.what} (named by ${d.named_by.map((n) => `#${n}`).join(", ")})`);
  const checks = { total: 1, passed: r.ok ? 1 : 0, source: "registry", checks: [{ cmd: "check-answers --sections 1,2", ok: r.ok, out: r.lines.join("\n"), answers: { outcomes: r.outcomes, results: r.results, dispositions: r.dispositions, best_candidate: r.best_candidate, named } }] };
  const gate = await finishGate(S, checks);
  return { check: r, gate, verdict: P.finishLineVerdict({ ...checks, gate }, false) };
}

/** A review part by part: `parts` as given, everything else as an established review words it. */
const review = (strength: "established" | "best_candidate", parts: P.AnswerReview["parts"]) => ({ strength, answer_review: { ...ESTABLISHED.answer_review, parts } });

/** Question 2 answered established on a finding, attested established, its lead closed. */
async function answerTwo(r: Awaited<ReturnType<typeof run>>) {
  const lead = await planned(r.a0, "2");
  const f = ok(await rec(r.a0, { kind: "finding", ...F, value: "a remote tool's service entry", source: "the disk", evidence: "a registry key", refs: ["job:j000001/hits.txt"], answers: ["2"] })).entry;
  const a = ok(await rec(r.a1, { kind: "answer", section: "question:2", value: "Yes: a remote tool was installed as a service", reasoning: `E-${f.seq}`, ...A, confidence: "high", result: "established" })).entry;
  await covers(r.a0, "2");
  const att = await P.attestEntry(r.a2, { seq: a.seq, how: "re-read the key from job:j000001", ...ESTABLISHED });
  assert.ok(att.ok, (att as { reason?: string }).reason);
  assert.ok((await L.closeLead(r.a0, lead, { disposition: "resolved", ref: `E-${f.seq}` })).ok);
}

/** Question 1 as s9722fa's were: partial, medium confidence, a limitation on the part it leaves open; its lead closed on the finding. */
async function partialOne(r: Awaited<ReturnType<typeof run>>, o: { would_change?: string } = {}) {
  const lead = await planned(r.a0, "1", [{ source: "input:logs/a.log", method: "read the logons" }]);
  const f = ok(await rec(r.a0, { kind: "finding", ...F, value: "a logon at 09:14 from the office network", source: "the log", evidence: "line 12", refs: ["job:j000002/hits.txt"], answers: ["1"] })).entry;
  const lim = ok(await rec(r.a0, { kind: "limitation", value: "The log keeps no account name for a network logon", source: "the log", evidence: "its field list", reason: "unavailable", answers: ["1"] })).entry;
  const a = ok(await rec(r.a1, { kind: "answer", section: "question:1", value: "A logon at 09:14 from the office network; the account is not established", reasoning: `E-${f.seq} shows the logon and its time; the account is open (E-${lim.seq})`, ...A, ...(o.would_change ? { would_change: o.would_change } : {}), limitations: [lim.seq], result: "partial", parts: [{ id: "when", part: "when and from where the logon came", status: "established", refs: [`E-${f.seq}`] }, { id: "who", part: "which account logged on", status: "open", open_by: `E-${lim.seq}` }] })).entry;
  assert.equal(a.confidence, "medium");
  assert.ok((await L.closeLead(r.a0, lead, { disposition: "resolved", ref: `E-${f.seq}` })).ok);
  return { f, lim, a };
}

test("the run s9722fa, reconstructed: a partial answer with medium confidence and a best_candidate review is disposed partial by readiness, the answers check and the finish gate alike, under all three stop policies", async () => {
  const r = await run({ goal: GOAL });
  await answerTwo(r);
  const q1 = await partialOne(r);
  // Reviewed as s9722fa's seats reviewed them: the open part held not established with no word that the answer declares it open, the attest best_candidate.
  const att = await P.attestEntry(r.a3, { seq: q1.a.seq, how: "re-read line 12 from job:j000002", ...review("best_candidate", [{ part: "when", established: true, why: "line 12" }, { part: "which account", established: false, why: "no account field" }]) });
  assert.ok(att.ok, (att as { reason?: string }).reason);
  const line = (att as { line: P.LedgerAttestation }).line;
  assert.equal(line.strength, "best_candidate");
  assert.deepEqual(line.capped, [`the review holds "which account" not established (no account field), and the answer does not declare it open`], "the answer's medium confidence caps nothing on a partial answer");
  assert.match((att as { note?: string }).note ?? "", new RegExp(`#${q1.a.seq} is partially established, a disposition held to its own bar, so a best candidate holds nothing on it \\("best candidate" concerns only an answer that claims established\\)`));
  // The shared test.
  assert.equal(P.claimsEstablished(q1.a), false);
  assert.equal(P.heldAsBestCandidate(q1.a, P.answerReviews(q1.a, await P.readAttestations(r.S))), false);
  for (const policy of POLICIES) {
    await setPolicy(r.S, policy);
    const f = await finish(r.S);
    assert.equal(f.gate.until_solved, policy === "operator");
    // The answers check: partial, limited, no best candidate.
    assert.equal(f.check.ok, true, `${policy}: ${f.check.lines.join("\n")}`);
    assert.deepEqual(f.check.best_candidate, [], policy);
    assert.equal(f.check.outcomes["question:1"], "limited", policy);
    assert.equal(f.check.dispositions["question:1"], "partial", policy);
    assert.doesNotMatch(f.check.lines.join("\n"), /best candidate, not established/, policy);
    // The finish gate: disposed partial, and the done proceeds, examination-limited.
    assert.deepEqual(f.gate.questions.map((q) => [q.id, q.disposition]), [["1", "partial"], ["2", "established"]], policy);
    assert.equal(f.verdict.proceed && f.verdict.outcome, "examination_limited", `${policy}: ${JSON.stringify(f.verdict)}`);
    // Readiness: ready, the partial answer limiting the run and holding nothing.
    const ready = await FIN.readiness(r.S);
    assert.deepEqual([ready.ready, ready.items], [true, []], `${policy}: ${JSON.stringify(ready)}`);
    assert.ok(ready.limited.includes("question:1 is partially established"), `${policy}: ${JSON.stringify(ready.limited)}`);
    assert.ok(!ready.limited.some((l) => /best candidate/.test(l)), policy);
  }
});

test("an answer that claims established, every review of which holds it a best candidate, still holds: readiness and the done agree under every stop policy", async () => {
  const r = await run({ goal: GOAL });
  await answerTwo(r);
  const lead = await planned(r.a0, "1", [{ source: "input:logs/a.log", method: "read the logons" }]);
  const f = ok(await rec(r.a0, { kind: "finding", ...F, value: "alice logged on at 09:14", source: "the log", evidence: "line 12", refs: ["job:j000002/hits.txt"], answers: ["1"] })).entry;
  const a = ok(await rec(r.a1, { kind: "answer", section: "question:1", value: "alice, at 09:14", reasoning: `E-${f.seq}`, ...A, result: "established" })).entry;
  assert.ok((await L.closeLead(r.a0, lead, { disposition: "resolved", ref: `E-${f.seq}` })).ok);
  // Its medium confidence caps the review, as before.
  refused(await P.attestEntry(r.a3, { seq: a.seq, how: "re-read line 12", ...ESTABLISHED }), /can be attested best_candidate only: its confidence is medium\. Attest it best_candidate \(it does not satisfy the finish line\)/);
  const att = await P.attestEntry(r.a3, { seq: a.seq, how: "re-read line 12", ...ESTABLISHED, strength: "best_candidate" });
  assert.ok(att.ok);
  assert.match((att as { note?: string }).note ?? "", /question:1 is not established by it, and the finish line says so/);
  assert.equal(P.heldAsBestCandidate(a, P.answerReviews(a, await P.readAttestations(r.S))), true);
  for (const policy of POLICIES) {
    await setPolicy(r.S, policy);
    const f = await finish(r.S);
    assert.deepEqual(f.check.best_candidate, ["question:1"], policy);
    assert.equal(f.check.dispositions["question:1"], undefined, policy);
    assert.equal(f.gate.questions.find((q) => q.id === "1")?.disposition, undefined, policy);
    assert.equal(f.verdict.proceed, false, policy);
    if (!f.verdict.proceed) assert.match(f.verdict.reason, /- question:1 is limited, with no disposition under the bar: its answer is a best candidate, not established/, policy);
    const held = await FIN.readiness(r.S);
    assert.equal(held.ready, false, `${policy}: readiness holds it, as the done does`);
    assert.ok(held.items.some((i) => new RegExp(`question:1 is a best candidate, not established \\(E-${a.seq} claims established`).test(i)), `${policy}: ${JSON.stringify(held.items)}`);
  }
});

test("a partial answer's review attests the answer's own claims: a part it declares open names the limitation or coverage record that declares it and does not cap, nor do its confidence and the routes its would_change names; a part it claims that the review does not hold does", async () => {
  const r = await run({ goal: GOAL });
  // Its would_change names a planned route no job examined: on an established claim that caps a review.
  const q1 = await partialOne(r, { would_change: "an account name from another source than input:logs/a.log" });
  const asEstablished = await P.strengthCaps(r.S, { ...q1.a, result: "established" }, null);
  assert.ok(asEstablished.includes("its confidence is medium") && asEstablished.some((c) => /^would_change names input:logs\/a\.log \(read the logons\), a planned route nothing examined/.test(c)), `the same answer claiming established is capped by its confidence and the route: ${JSON.stringify(asEstablished)}`);
  assert.deepEqual(await P.strengthCaps(r.S, q1.a, null), [], "the partial answer is capped by neither");
  const other = ok(await rec(r.a0, { kind: "limitation", value: "The disk's second volume is encrypted", source: "the disk", evidence: "its header", reason: "unavailable", answers: ["2"] })).entry;
  // A part it claims, held not established: a dispute or a best candidate, never an established review.
  refused(
    await P.attestEntry(r.a3, { seq: q1.a.seq, how: "re-read line 12", ...review("established", [{ part: "when", established: false, why: "the clock is unchecked" }]) }),
    new RegExp(`#${q1.a.seq} is partial: its review attests the answer's own claims, the parts it holds established and the parts it declares open, and the review holds "when" not established \\(the clock is unchecked\\), and the answer does not declare it open\\. .*a part it claims established that you do not hold so is a dispute`),
  );
  // declared_open names an entry the answer cites to declare a part open, and only on a partial answer.
  refused(
    await P.attestEntry(r.a3, { seq: q1.a.seq, how: "re-read line 12", ...review("established", [{ part: "which account", established: false, why: "no field", declared_open: `E-${other.seq}` }]) }),
    new RegExp(`declared_open names E-${other.seq} for "which account": #${q1.a.seq} declares a part open by a limitation it cites or a coverage record it rests on, and it cites E-${q1.lim.seq}`),
  );
  refused(await P.attestEntry(r.a3, { seq: q1.a.seq, how: "x", ...review("established", [{ part: "which account", established: false, why: "no field", declared_open: "L-3" }]) }), /declared_open names the entry by which the answer declares "which account" open, as E-<seq>/);
  // The part it declares open, held so: established, its medium confidence and its would_change notwithstanding.
  const att = await P.attestEntry(r.a3, { seq: q1.a.seq, how: "re-read line 12 from job:j000002; no account field in the log", ...review("established", [{ part: "when, and from where", established: true, why: "line 12" }, { part: "which account", established: false, why: "the log keeps none", declared_open: `#${q1.lim.seq}` }]) });
  assert.ok(att.ok, (att as { reason?: string }).reason);
  const line = (att as { line: P.LedgerAttestation }).line;
  assert.equal(line.strength, "established");
  assert.equal(line.capped, undefined);
  assert.equal(line.answer_review?.parts[1]?.declared_open, `E-${q1.lim.seq}`, "kept, as E-<seq>, in the chained attestation");
  assert.match(P.answerReviewWords(line.answer_review!), new RegExp(`which account open, as the answer declares it \\(E-${q1.lim.seq}\\)`));
  // An answer that claims established declares no part open.
  await answerTwo(r);
  const est = (await P.readLedger(r.S)).find((e) => e.kind === "answer" && e.section === "question:2")!;
  refused(await P.attestEntry(r.a3, { seq: est.seq, how: "x", ...review("established", [{ part: "installed", established: false, why: "w", declared_open: `E-${other.seq}` }]) }), new RegExp(`declared_open is for a partial answer's part the answer itself declares open; #${est.seq} is established: it claims every part established`));
});
