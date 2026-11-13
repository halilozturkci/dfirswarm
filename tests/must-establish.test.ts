/**
 * A question that must be established (docs/adr/0013, "A question that must
 * be established"). On the Breadcrumbs run (a flag-only challenge, --stop
 * operator) the one question's answer was partial on a reviewed finding,
 * which is a disposition under the bar, so the coordinator's done ended the
 * run examination-limited after 23 minutes without the flag; the operator
 * resumed it and asked the question again by hand. The goal (a `## Must
 * establish` section, or `must_establish:` in its metadata block) and the
 * operator (`question add --must-establish`, `amend --must-establish`) can
 * now say that a question must be established: for it, partial, not
 * determinable, a bounded negative short of the stronger bar and out of
 * scope are no disposition, under every stop policy. The ways out stay on
 * the record: the operator accepts its limits (question accept, for that
 * revision and the answer standing) or releases the requirement (amend
 * --no-must-establish, with why). A question that does not use it reads as
 * it always did. Synthetic runs only.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import * as FIN from "../extensions/finish.ts";
import * as P from "../extensions/protocol.ts";
import * as L from "../extensions/leads.ts";
import * as Q from "../extensions/questions.ts";
import { checkLedgerAnswers } from "../scripts/check-answers.ts";
import { finishGate } from "../scripts/finish-gate.ts";
import { A, coverage, covers, ESTABLISHED, F, ok, planned, rec, REVIEW, run } from "./negative-bar-fixture.ts";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { questionArgv } from "../scripts/ui/questions.ts";
import { mayRequireEstablished, mustEstablishPayload, mustEstablishWords } from "../ui/src/lib/question-forms.ts";
import type { QuestionView } from "../ui/src/lib/types.ts";

/** Two questions; `must` names the ones the goal says must be established, in its own section. */
const goal = (must: string[] = ["1"]) =>
  [
    "## Goal",
    "",
    "Examine the host.",
    "",
    "### Questions",
    "",
    "1. Who logged on, and when?",
    "2. Was a remote tool installed?",
    "",
    ...(must.length ? ["## Must establish", "", ...must.map((m) => `- ${m}`), ""] : []),
    "## Definition of done",
    "",
    "d",
    "",
    "## Checks",
    "",
    '- `node x "$SWARM_HARNESS/scripts/check-answers.ts" --sections 1,2 --existence 2`',
    "",
  ].join("\n");

const POLICIES = ["operator", "cap-pause", "cap-stop"] as const;
const OPERATOR: Q.Actor = { kind: "human", role: "operator", person: "ops@lab", enrolled: false, os_user: "ops", host: "lab", via: "cli", identity: "claimed" };
const ANALYST: Q.Actor = { kind: "human", role: "analyst", person: "ana", name: "Ana", enrolled: true, os_user: "ana", host: "lab", via: "cli", identity: "claimed" };

async function setPolicy(S: string, policy: (typeof POLICIES)[number]): Promise<void> {
  const b = await P.readBudget(S);
  await P.writeBudget(S, policy === "operator" ? { ...b, stop_policy: "operator", until_solved: true, wall_clock_minutes: 0 } : { ...b, stop_policy: policy, until_solved: false, wall_clock_minutes: 60 });
}

/** The finish line as the harness runs it: the goal's answers check, then the gate, then the verdict. */
async function finish(S: string) {
  const r = await checkLedgerAnswers(S, ["1", "2"], ["2"]);
  const named = r.defects.filter((d) => d.named_by.length).map((d) => `${d.what} (named by ${d.named_by.map((n) => `#${n}`).join(", ")})`);
  const checks = { total: 1, passed: r.ok ? 1 : 0, source: "registry", checks: [{ cmd: "check-answers --sections 1,2 --existence 2", ok: r.ok, out: r.lines.join("\n"), answers: { outcomes: r.outcomes, results: r.results, dispositions: r.dispositions, best_candidate: r.best_candidate, named } }] };
  const gate = await finishGate(S, checks);
  return { check: r, gate, verdict: P.finishLineVerdict({ ...checks, gate }, false) };
}

const act = async (S: string, actor: Q.Actor, ev: Q.ActKind, input: Q.ActInput) => Q.act(S, actor, ev, input);
const okAct = async (S: string, actor: Q.Actor, ev: Q.ActKind, input: Q.ActInput) => {
  const r = await act(S, actor, ev, input);
  assert.ok(r.ok, (r as { reason?: string }).reason);
  return r as Q.ActResult;
};
const refusedAct = async (S: string, actor: Q.Actor, ev: Q.ActKind, input: Q.ActInput, re: RegExp) => {
  const r = await act(S, actor, ev, input);
  assert.equal(r.ok, false, `expected a refusal: ${JSON.stringify(r)}`);
  assert.match((r as { reason: string }).reason, re);
};

/** `q` established on a finding, attested established by another seat, its lead closed. */
async function established(r: Awaited<ReturnType<typeof run>>, q: string) {
  const lead = await planned(r.a0, q);
  const f = ok(await rec(r.a0, { kind: "finding", ...F, value: `the record question ${q} asks for`, source: "the disk", evidence: "a registry key", refs: ["job:j000001/hits.txt"], answers: [q] })).entry;
  const a = ok(await rec(r.a1, { kind: "answer", section: `question:${q}`, value: `Established: the record question ${q} asks for`, reasoning: `E-${f.seq}`, ...A, confidence: "high", result: "established" })).entry;
  await covers(r.a0, q);
  const att = await P.attestEntry(r.a2, { seq: a.seq, how: "re-read the key from job:j000001", ...ESTABLISHED });
  assert.ok(att.ok, (att as { reason?: string }).reason);
  assert.ok((await L.closeLead(r.a0, lead, { disposition: "resolved", ref: `E-${f.seq}` })).ok);
  return a;
}

/** Question 1 partial on a finding, the part it leaves open bounded by a limitation, reviewed by another seat that holds the open part as the answer declares it: a disposition under the ordinary bar. */
async function partialOne(r: Awaited<ReturnType<typeof run>>) {
  const lead = await planned(r.a0, "1", [{ source: "input:logs/a.log", method: "read the logons" }]);
  const f = ok(await rec(r.a0, { kind: "finding", ...F, value: "a logon at 09:14 from the office network", source: "the log", evidence: "line 12", refs: ["job:j000002/hits.txt"], answers: ["1"] })).entry;
  const lim = ok(await rec(r.a0, { kind: "limitation", value: "The log keeps no account name for a network logon", source: "the log", evidence: "its field list", reason: "unavailable", answers: ["1"] })).entry;
  const a = ok(await rec(r.a1, { kind: "answer", section: "question:1", value: "A logon at 09:14; the account is not established", reasoning: `E-${f.seq} shows the logon; the account is open (E-${lim.seq})`, ...A, limitations: [lim.seq], result: "partial", parts: [{ id: "when", part: "when the logon happened", status: "established", refs: [`E-${f.seq}`] }, { id: "who", part: "which account logged on", status: "open", open_by: `E-${lim.seq}` }] })).entry;
  assert.ok((await L.closeLead(r.a0, lead, { disposition: "resolved", ref: `E-${f.seq}` })).ok);
  const att = await P.attestEntry(r.a3, { seq: a.seq, how: "re-read line 12 from job:j000002", ...ESTABLISHED, answer_review: { ...ESTABLISHED.answer_review, parts: [{ id: "when", part: "when", established: true, why: "line 12" }, { id: "who", part: "which account", established: false, why: "the log keeps none", declared_open: `E-${lim.seq}` }] } });
  assert.ok(att.ok, (att as { reason?: string }).reason);
  return { f, lim, a };
}

/** Question 1 not determinable on a coverage record another seat reviewed: a disposition under the ordinary bar. */
async function notDeterminableOne(r: Awaited<ReturnType<typeof run>>) {
  const lead = await planned(r.a0, "1", [{ source: "input:logs/a.log", method: "search the logons" }]);
  const abs = ok(await rec(r.a0, { kind: "absence", value: "an account name for the logon", source: "the log", evidence: "a search", completion: "complete", refs: ["job:j000002/hits.txt"], control: { ref: "job:j000002/hits.txt", found: "the same search finds a planted row" }, answers: ["1"] })).entry;
  const cov = ok(await rec(r.a0, coverage("1", ["input:logs/a.log"], [`E-${abs.seq}`, "job:j000002/hits.txt"], { acquisition_none_why: "no source outside the evidence records it" }))).entry;
  const a = ok(await rec(r.a1, { kind: "answer", section: "question:1", value: "Who logged on cannot be determined from the log", reasoning: `E-${cov.seq}`, ...A, result: "not_determinable" })).entry;
  assert.ok((await P.attestEntry(r.a2, { seq: cov.seq, how: "ran the search again from job:j000002", review: REVIEW })).ok);
  const closed = await L.closeLead(r.a0, lead, { disposition: "negative", ref: `E-${abs.seq}` });
  assert.ok(closed.ok, (closed as { reason?: string }).reason);
  return { cov, a };
}

test("the goal says which of its questions must be established: a Must establish section names them as the goal numbers them, and the register seeds the requirement on each, the goal's word", async () => {
  assert.deepEqual(
    Q.goalMustEstablish("## Must establish\n\n- 1\n- Q-3: the flag is the answer\n- question:bonus\n- 2.\n\n## Checks\n"),
    [
      { section: "1", why: null, item: 1 },
      { section: "3", why: "the flag is the answer", item: 2 },
      { section: "bonus", why: null, item: 3 },
      { section: "2", why: null, item: 4 },
    ],
  );
  assert.deepEqual(Q.goalMustEstablish("## Goal\n\nNothing required.\n"), []);
  const r = await run({ goal: goal(["1"]) });
  const seeded = await Q.seedRegister(r.S);
  assert.deepEqual(seeded.must_establish, ["Q-1"]);
  assert.equal(seeded.must_establish_unknown, undefined);
  const snap = await Q.questionsSnapshot(r.S);
  const q1 = snap.state.questions.get("Q-1")!;
  assert.equal(Q.mustEstablish(q1), true);
  assert.equal(q1.must_establish?.origin.kind, "goal");
  assert.equal(Q.mustEstablish(snap.state.questions.get("Q-2")!), false);
  // A goal that requires nothing seeds as it always did: no word on any act.
  const plain = await run({ goal: goal([]) });
  assert.deepEqual(Object.keys(await Q.seedRegister(plain.S)).sort(), ["objectives", "questions", "seeded"], "nothing more is said of a goal that requires nothing");
  const events = (await Q.readQuestionEvents(plain.S)).events.filter((e) => e.ev === "open");
  assert.ok(events.every((e) => !("must_establish" in (e.act ?? {}))), JSON.stringify(events.map((e) => e.act)));
  // A name the goal does not number requires nothing, and the seed says so.
  const typo = await run({ goal: goal(["7"]) });
  const t = await Q.seedRegister(typo.S);
  assert.deepEqual([t.must_establish, t.must_establish_unknown], [undefined, ["7"]]);
});

test("the operator requires a question to be established and releases it, on the record; an analyst, an agent and a background question cannot carry it", async () => {
  const r = await run({ goal: goal([]) });
  await Q.seedRegister(r.S);
  const added = await okAct(r.S, OPERATOR, "open", { text: "Which account installed the remote tool?", why: "the client asks", must_establish: true });
  let snap = await Q.questionsSnapshot(r.S);
  assert.equal(Q.mustEstablish(snap.state.questions.get(added.q!)!), true);
  await refusedAct(r.S, ANALYST, "open", { text: "Which host did it come from?", why: "w", must_establish: true }, /requiring a question to be established is the examiner's or the operator's/);
  await refusedAct(r.S, OPERATOR, "open", { text: "Is there anything else?", why: "w", materiality: "background", must_establish: true }, /a question that must be established is material/);
  const agent = await Q.questionOpen(r.a0, { text: "What did the tool connect to?", why: "w", objective: "O-1", materiality: "material", must_establish: true } as Q.ActInput);
  assert.equal(agent.ok, false);
  // On a question that exists: the goal's question 1, by amendment, which makes no new revision.
  const marked = await okAct(r.S, OPERATOR, "amend", { q: "Q-1", expected_rev: 1, must_establish: true, why: "the flag is the answer" });
  assert.equal(marked.rev, 1);
  snap = await Q.questionsSnapshot(r.S);
  assert.equal(Q.mustEstablish(snap.state.questions.get("Q-1")!), true);
  assert.equal(snap.state.questions.get("Q-1")!.must_establish?.why, "the flag is the answer");
  await refusedAct(r.S, OPERATOR, "amend", { q: "Q-1", expected_rev: 1, must_establish: true }, /Q-1 must be established already/);
  await refusedAct(r.S, OPERATOR, "amend", { q: "Q-1", expected_rev: 1, materiality: "background" }, /a question that must be established is material/);
  // A release says why, and the record keeps who released it and why.
  await refusedAct(r.S, OPERATOR, "amend", { q: "Q-1", expected_rev: 1, must_establish: false }, /a release of the requirement says why/);
  await okAct(r.S, OPERATOR, "amend", { q: "Q-1", expected_rev: 1, must_establish: false, why: "the client takes what the log holds" });
  snap = await Q.questionsSnapshot(r.S);
  const q1 = snap.state.questions.get("Q-1")!;
  assert.equal(Q.mustEstablish(q1), false);
  assert.deepEqual([q1.must_establish?.required, q1.must_establish?.why, q1.must_establish?.origin.person], [false, "the client takes what the log holds", "ops@lab"]);
  await refusedAct(r.S, OPERATOR, "amend", { q: "Q-1", expected_rev: 1, must_establish: false, why: "again" }, /Q-1 is not required to be established/);
  const md = Q.renderQuestionsMd(await Q.viewContext(r.S));
  assert.match(md, /The requirement that it be established was released by ops@lab, .*: the client takes what the log holds/);
  assert.match(md, new RegExp(`Must be established \\(required by ops@lab`));
});

test("a partial answer on a reviewed finding is no disposition for a question that must be established: the answers check, the gate, the verdict and readiness hold it under every stop policy", async () => {
  const r = await run({ goal: goal(["1"]) });
  await established(r, "2");
  const q1 = await partialOne(r);
  for (const policy of POLICIES) {
    await setPolicy(r.S, policy);
    const f = await finish(r.S);
    assert.equal(f.check.ok, true, `${policy}: the answers check itself fails nothing: ${f.check.lines.join("\n")}`);
    assert.equal(f.check.outcomes["question:1"], "limited", policy);
    assert.equal(f.check.dispositions["question:1"], undefined, `${policy}: partial is no disposition for it`);
    assert.equal(f.check.dispositions["question:2"], "established", policy);
    assert.match(f.check.lines.join("\n"), /question:1: .*it must be established, and this is no disposition for it/, policy);
    const g1 = f.gate.questions.find((q) => q.id === "1")!;
    assert.deepEqual([g1.outcome, g1.disposition, g1.must_establish], ["limited", undefined, true], policy);
    assert.match(g1.blocks[0]!, /^it must be established \(required by the goal\): it is examination-limited \(partially established, E-\d+\), which ends no run on it/, policy);
    assert.equal(f.verdict.proceed, false, `${policy}: ${JSON.stringify(f.verdict)}`);
    if (!f.verdict.proceed) {
      assert.equal(f.verdict.failing, "question:1");
      assert.match(f.verdict.reason, /- question:1 is limited, with no disposition under the bar: it must be established/);
      assert.match(f.verdict.reason, /only the operator accepts its limits \(question accept\) or releases the requirement \(question amend --no-must-establish\)/);
      assert.doesNotMatch(f.verdict.reason, /then answer not_determinable/, "the way to not determinable is not offered for a question that must be established");
      assert.match(f.verdict.reason, /answer bounded_negative with asserts_absence: true/, "the stronger bar's steps are, for a question that asks whether something exists");
    }
    const ready = await FIN.readiness(r.S);
    assert.equal(ready.ready, false, policy);
    assert.ok(ready.items.some((i) => new RegExp(`^question:1 must be established \\(required by the goal\\): its answer E-${q1.a.seq} is partially established`).test(i)), `${policy}: ${JSON.stringify(ready.items)}`);
  }
});

test("a reviewed not determinable is no disposition for it either; established is, and the run ends completed", async () => {
  const r = await run({ goal: goal(["1"]) });
  await established(r, "2");
  const nd = await notDeterminableOne(r);
  let f = await finish(r.S);
  assert.equal(f.check.outcomes["question:1"], "inconclusive");
  assert.equal(f.check.dispositions["question:1"], undefined);
  assert.equal(f.verdict.proceed, false);
  assert.equal((await FIN.readiness(r.S)).ready, false);
  // Established on a finding, attested established by another seat: the requirement is met.
  const f1 = ok(await rec(r.a0, { kind: "finding", ...F, value: "alice logged on at 09:14", source: "a second log", evidence: "line 3", refs: ["job:j000001/hits.txt"], answers: ["1"] })).entry;
  const a = ok(await rec(r.a1, { kind: "answer", section: "question:1", value: "alice, at 09:14", reasoning: `E-${f1.seq}`, ...A, confidence: "high", result: "established", supersedes: nd.a.seq })).entry;
  await covers(r.a0, "1");
  assert.ok((await P.attestEntry(r.a2, { seq: a.seq, how: "re-read the key from job:j000001", ...ESTABLISHED })).ok);
  f = await finish(r.S);
  assert.equal(f.check.dispositions["question:1"], "established");
  assert.equal(f.verdict.proceed && f.verdict.outcome, "completed", JSON.stringify(f.verdict));
  const ready = await FIN.readiness(r.S);
  assert.deepEqual([ready.ready, ready.items], [true, []]);
});

test("the operator's acceptance of its limits, or the requirement released, ends the run examination-limited on the same partial answer", async () => {
  // The acceptance: the existing act, for this revision and the answer standing.
  const r = await run({ goal: goal(["1"]) });
  await established(r, "2");
  await partialOne(r);
  await okAct(r.S, OPERATOR, "accept", { q: "Q-1", as: "bounded", why: "the log keeps no account names", expected_rev: 1 });
  for (const policy of POLICIES) {
    await setPolicy(r.S, policy);
    const f = await finish(r.S);
    assert.equal(f.gate.questions.find((q) => q.id === "1")!.outcome, "accepted", policy);
    assert.equal(f.verdict.proceed && f.verdict.outcome, "examination_limited", `${policy}: ${JSON.stringify(f.verdict)}`);
    assert.equal((await FIN.readiness(r.S)).ready, true, policy);
  }
  // The release: the requirement taken off, said why; partial is a disposition again.
  const s = await run({ goal: goal(["1"]) });
  await established(s, "2");
  await partialOne(s);
  assert.equal((await finish(s.S)).verdict.proceed, false);
  await okAct(s.S, OPERATOR, "amend", { q: "Q-1", expected_rev: 1, must_establish: false, why: "the client takes what the log holds" });
  const f = await finish(s.S);
  assert.equal(f.check.dispositions["question:1"], "partial");
  assert.equal(f.verdict.proceed && f.verdict.outcome, "examination_limited", JSON.stringify(f.verdict));
  assert.deepEqual((await FIN.readiness(s.S)).items, []);
});

test("a person's question the operator requires to be established holds the finish the same way, through the register's part of the gate", async () => {
  const r = await run({ goal: goal([]) });
  await established(r, "1");
  await established(r, "2");
  const asked = await okAct(r.S, OPERATOR, "open", { text: "Which account installed the remote tool?", why: "the client asks", must_establish: true });
  const section = asked.q!.slice(2);
  const opened = await L.openLead(r.a0, { title: `Work question ${section}`, why: "it is asked", answers: [section], take: true, routes: [{ source: "input:logs/a.log", method: "read the service installs" }], proposition: "an account the log names installed the tool", negation: "no account the log names installed it" });
  assert.ok(opened.ok, (opened as { reason?: string }).reason);
  const lead = (opened as { lead: { id: string } }).lead.id;
  const f = ok(await rec(r.a0, { kind: "finding", ...F, value: "the tool's service was made at 09:20", source: "the log", evidence: "line 40", refs: ["job:j000002/hits.txt"], answers: [section] })).entry;
  const lim = ok(await rec(r.a0, { kind: "limitation", value: "The log keeps no account name for a service install", source: "the log", evidence: "its field list", reason: "unavailable", answers: [section] })).entry;
  const a = ok(await rec(r.a1, { kind: "answer", section: `question:${section}`, value: "Installed at 09:20; the account is not established", reasoning: `E-${f.seq}; the account is open (E-${lim.seq})`, ...A, limitations: [lim.seq], result: "partial", contrary_none_why: "nothing in the log points elsewhere", parts: [{ id: "when", part: "when it was installed", status: "established", refs: [`E-${f.seq}`] }, { id: "who", part: "which account", status: "open", open_by: `E-${lim.seq}` }] })).entry;
  assert.ok((await L.closeLead(r.a0, lead, { disposition: "resolved", ref: `E-${f.seq}` })).ok);
  assert.ok((await P.attestEntry(r.a3, { seq: a.seq, how: "re-read line 40 from job:j000002", ...ESTABLISHED, answer_review: { ...ESTABLISHED.answer_review, parts: [{ id: "when", part: "when", established: true, why: "line 40" }, { id: "who", part: "which account", established: false, why: "the log keeps none", declared_open: `E-${lim.seq}` }] } })).ok);
  const fin = await finish(r.S);
  const q = fin.gate.questions.find((x) => x.id === section)!;
  assert.deepEqual([q.outcome, q.disposition, q.must_establish], ["limited", undefined, true], JSON.stringify(q));
  assert.match(q.blocks[0]!, /^it must be established \(required by ops@lab/);
  assert.equal(fin.verdict.proceed, false);
  assert.equal((await FIN.readiness(r.S)).ready, false);
});

test("an answered question that must be established is never told it must be, whatever else stands on it: a quick negative nobody attested beside its established answer, a goal's or a person's", async () => {
  const r = await run({ goal: goal(["1"]) });
  await established(r, "2");
  const asked = await okAct(r.S, OPERATOR, "open", { text: "Which account installed the remote tool?", why: "the client asks", must_establish: true });
  const section = asked.q!.slice(2);
  // On each required question: a quick negative (one job over one object, closed at once), nobody attesting it, then an established answer by another lead.
  for (const [q, frame] of [["1", false], [section, true]] as const) {
    const framing = frame ? { proposition: "an account the log names did it", negation: "no account the log names did it" } : {};
    const quick = await L.openLead(r.a0, { title: `A first look at ${q}`, why: "it is asked", answers: [q], take: true, routes: [{ source: "input:disk.E01", method: "search the disk" }], ...framing });
    assert.ok(quick.ok, (quick as { reason?: string }).reason);
    const qid = (quick as { lead: { id: string } }).lead.id;
    await L.attachJob(r.S, "a0", "j000001", qid);
    const abs = ok(await rec(r.a0, { kind: "absence", value: `nothing for ${q}`, source: "inputs/disk.E01", evidence: "a search", completion: "complete", refs: ["job:j000001/hits.txt"], control: { ref: "job:j000001/hits.txt", found: "the same search finds a planted row" }, answers: [q] })).entry;
    assert.ok((await L.recordInterpretations(r.S, "a0", abs.seq, [{ job: "j000001" }])).ok);
    const closed = await L.closeLead(r.a0, qid, { disposition: "negative", ref: `E-${abs.seq}` });
    assert.ok(closed.ok && (closed as { lead: L.LeadView }).lead.quick_negative, "a quick negative");
    const f = ok(await rec(r.a0, { kind: "finding", ...F, value: `the record for ${q}`, source: "the disk", evidence: "a registry key", refs: ["job:j000001/hits.txt"], answers: [q] })).entry;
    const a = ok(await rec(r.a1, { kind: "answer", section: `question:${q}`, value: `Established for ${q}`, reasoning: `E-${f.seq}`, ...A, confidence: "high", result: "established", ...(frame ? { contrary_none_why: "nothing points elsewhere" } : {}) })).entry;
    await covers(r.a0, q);
    // A person's question presumes its framing (docs/adr/0011): its established review tests that premise.
    const review = frame ? { ...ESTABLISHED, answer_review: { ...ESTABLISHED.answer_review, premise_tested: { outcome: "the record names the account that did it", refs: ["job:j000001/hits.txt"] } } } : ESTABLISHED;
    const att = await P.attestEntry(r.a2, { seq: a.seq, how: "re-read the key from job:j000001", ...review });
    assert.ok(att.ok && (att as { line: P.LedgerAttestation }).line.strength === "established", JSON.stringify(att));
  }
  const f = await finish(r.S);
  for (const id of ["1", section]) {
    const g = f.gate.questions.find((q) => q.id === id)!;
    assert.equal(g.outcome, "answered", `${id}: ${JSON.stringify(g)}`);
    assert.ok(!g.blocks.some((b) => /must be established/.test(b)), `${id}: an answered question is not told it must be established: ${JSON.stringify(g.blocks)}`);
  }
});

test("every seat's header names the questions that must be established while they are not, and says what ends the run on them", async () => {
  const r = await run({ goal: goal(["1"]) });
  const told = { seq: 0 };
  let d = Q.questionsDigest("a0", await Q.viewContext(r.S), told);
  const line = d.lines.find((l) => /^Must be established/.test(l));
  assert.ok(line, JSON.stringify(d.lines));
  assert.match(line, /Q-1 \(question:1, required by the goal\): no answer yet/);
  assert.match(line, /partial, not determinable, a bounded negative short of the stronger bar and out of scope do not end the run on it/);
  await established(r, "1");
  d = Q.questionsDigest("a0", await Q.viewContext(r.S), told);
  assert.ok(!d.lines.some((l) => /^Must be established/.test(l)), "an established answer meets it: the line goes");
  // A run that requires nothing has no such line.
  const plain = await run({ goal: goal([]) });
  assert.ok(!Q.questionsDigest("a0", await Q.viewContext(plain.S), told).lines.some((l) => /Must be established/.test(l)));
});

test("the console marks a question must be established, shows who required it, and releases it with why, through the same command line", async () => {
  const r = await run({ goal: goal([]) });
  await Q.seedRegister(r.S);
  const cli = (sub: string, argv: string[]) => {
    const p = spawnSync(process.execPath, ["--experimental-strip-types", "--no-warnings", join(import.meta.dirname, "..", "scripts", "questions-cli.ts"), sub, r.S, ...argv], { encoding: "utf8" });
    return { code: p.status, out: `${p.stdout}${p.stderr}` };
  };
  // The add form's field.
  const add = questionArgv({ action: "add", text: "Which account ran the installer?", why: "the client asks", must_establish: true });
  assert.ok(add.argv.includes("--must-establish"));
  assert.ok(!questionArgv({ action: "add", text: "t", why: "w" }).argv.includes("--must-establish"), "left out, nothing is required");
  const opened = cli(add.sub, add.argv);
  assert.equal(opened.code, 0, opened.out);
  let snap = await Q.questionsSnapshot(r.S);
  const asked = [...snap.state.questions.values()].find((q) => q.text === "Which account ran the installer?")!;
  assert.equal(Q.mustEstablish(asked), true);
  // A card's action on the goal's question 1: required (no new revision), then released with why.
  const q1 = () => snap.state.questions.get("Q-1")! as unknown as QuestionView;
  const require = questionArgv(mustEstablishPayload({ id: "Q-1", rev: 1 }, true, "the flag is the answer"));
  assert.deepEqual(require, { sub: "amend", argv: ["Q-1", "--expect-rev", "1", "--why", "the flag is the answer", "--must-establish"] });
  assert.equal(cli(require.sub, require.argv).code, 0);
  snap = await Q.questionsSnapshot(r.S);
  assert.equal(q1().rev, 1, "no new revision");
  const view = Q.viewQuestion(snap.state.questions.get("Q-1")!, await Q.viewContext(r.S)) as unknown as QuestionView;
  assert.match(mustEstablishWords(view.must_establish!), /^required by .+: the flag is the answer$/);
  // A release without why is refused by the register, and said.
  const bare = questionArgv(mustEstablishPayload({ id: "Q-1", rev: 1 }, false, " "));
  assert.deepEqual(bare.argv, ["Q-1", "--expect-rev", "1", "--no-must-establish"]);
  const refused = cli(bare.sub, bare.argv);
  assert.notEqual(refused.code, 0);
  assert.match(refused.out, /a release of the requirement says why/);
  const release = questionArgv(mustEstablishPayload({ id: "Q-1", rev: 1 }, false, "the client takes what the log holds"));
  assert.equal(cli(release.sub, release.argv).code, 0);
  snap = await Q.questionsSnapshot(r.S);
  const released = Q.viewQuestion(snap.state.questions.get("Q-1")!, await Q.viewContext(r.S)) as unknown as QuestionView;
  assert.equal(released.must_establish?.required, false);
  assert.match(mustEstablishWords(released.must_establish!), /^released by .+: the client takes what the log holds$/);
  assert.match(mustEstablishWords({ required: true, at: "t", by: "goal", origin: { kind: "goal" } as QuestionView["origin"], seq: 1, rev: 1, why: null }), /^required by the goal$/);
});

test("a question's asker neither requires nor releases it: the operator's requirement on an analyst's question stays until the operator or an examiner releases it, and the console offers the action only to them", async () => {
  const r = await run({ goal: goal([]) });
  await Q.seedRegister(r.S);
  const mine = await okAct(r.S, ANALYST, "open", { text: "Which share did the archive come from?", why: "the timeline" });
  await okAct(r.S, OPERATOR, "amend", { q: mine.q!, expected_rev: 1, must_establish: true, why: "the client's question" });
  await refusedAct(r.S, ANALYST, "amend", { q: mine.q!, expected_rev: 1, must_establish: false, why: "mine to release" }, /releasing the requirement that a question be established is the examiner's or the operator's, whoever asked the question/);
  let snap = await Q.questionsSnapshot(r.S);
  assert.equal(Q.mustEstablish(snap.state.questions.get(mine.q!)!), true, "still required");
  await okAct(r.S, OPERATOR, "amend", { q: mine.q!, expected_rev: 1, must_establish: false, why: "the client takes the partial answer" });
  snap = await Q.questionsSnapshot(r.S);
  assert.equal(Q.mustEstablish(snap.state.questions.get(mine.q!)!), false);
  const people = [
    { id: "ana", role: "analyst" },
    { id: "rev", role: "reviewer" },
    { id: "obs", role: "observer" },
    { id: "exa", role: "examiner" },
    { id: "ops", role: "operator" },
  ];
  assert.deepEqual(["", "ana", "rev", "obs", "exa", "ops", "nobody"].map((as) => mayRequireEstablished(as, people)), [true, false, false, false, true, true, false]);
});

test("start --check says what the seed says before the run exists: a question the goal requires and does not number requires nothing (questions-cli goal-check)", async () => {
  // The goal's questions from its text alone, as goalQuestions reads them from a run.
  const gq = L.goalQuestionsIn(goal(["1", "7"]), () => null);
  assert.deepEqual([gq.questions, gq.unread], [["1", "2"], []]);
  assert.deepEqual(Q.mustEstablishUnknownIn(goal(["1", "7"]), gq.questions), ["7"]);
  assert.deepEqual(Q.mustEstablishUnknownIn(goal(["Q-2"]), gq.questions), [], "Q-2 is question 2, as the goal numbers it");
  assert.deepEqual(Q.mustEstablishUnknownIn(goal([]), gq.questions), []);
  // A brief the check cannot read leaves its questions unknown: named as unread, and nothing called unknown wrongly.
  const briefGoal = goal(["4"]).replace("--sections 1,2 --existence 2", "--sections-in inputs/brief.md");
  const unread = L.goalQuestionsIn(briefGoal, () => null);
  assert.deepEqual(unread.unread, ["inputs/brief.md"]);
  const read = L.goalQuestionsIn(briefGoal, (p) => (p === "inputs/brief.md" ? "## Question 3\n\nWhat ran?\n\n## Question 4\n\nWho ran it?\n" : null));
  assert.deepEqual(read.unread, []);
  assert.ok(read.questions.includes("4"), JSON.stringify(read.questions));
  assert.deepEqual(Q.mustEstablishUnknownIn(briefGoal, read.questions), []);
  // The same reading the run's own seed makes.
  const typo = await run({ goal: goal(["7"]) });
  assert.deepEqual((await Q.seedRegister(typo.S)).must_establish_unknown, ["7"]);
});

test("the report says which questions were required to be established, by whom and why, and which requirement the operator released", async () => {
  const { renderReportBodyMarkdown } = await import("../scripts/report-body.ts");
  const r = await run({ goal: goal(["1: the flag is the answer"]) });
  await Q.seedRegister(r.S);
  const added = await okAct(r.S, OPERATOR, "open", { text: "Which account installed the remote tool?", why: "the client asks", must_establish: true });
  await okAct(r.S, OPERATOR, "amend", { q: added.q!, expected_rev: 1, must_establish: false, why: "the client takes what the log holds" });
  const md = await renderReportBodyMarkdown(r.S);
  const said = md.split("\n").find((l) => l.includes("Must be established."));
  assert.ok(said, md.slice(0, 4000));
  assert.match(said!, /Q-1 \(required by the goal: the flag is the answer\)/);
  assert.match(said!, new RegExp(`The requirement was released on one question: ${added.q}, by ops@lab, operator, claimed, not enrolled, via cli at [0-9T:.Z-]+ \\(the client takes what the log holds\\)`));
  assert.match(md, /must be established/);
  // A run that requires nothing says nothing of it.
  const plain = await run({ goal: goal([]) });
  await Q.seedRegister(plain.S);
  assert.doesNotMatch(await renderReportBodyMarkdown(plain.S), /Must be established\./);
});
