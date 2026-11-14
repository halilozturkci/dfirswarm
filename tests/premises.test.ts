/**
 * The premise register and an answer's claim and open-part rows
 * (docs/adr/0011 "Premises", docs/adr/0013 "Claim and open-part rows"):
 * premises as P-n events on the question chain, designated by the operator
 * (the goal, the register's premise add) or proposed by an agent under
 * test; answers citing them at a revision with a stance; the gate
 * premise_inconsistent and its ways out, none of which forces either side;
 * parts established or open, a partial answer with no open part refused, a
 * premise never an open part; a review's parts by id and a part it says the
 * answer leaves out; the warnings; the dispute a rebutting finding opens;
 * the report, the register's views and the CLI; and an answer without the
 * new fields hashing as it always did.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { test } from "node:test";
import * as FIN from "../extensions/finish.ts";
import * as L from "../extensions/leads.ts";
import * as PM from "../extensions/premises.ts";
import * as P from "../extensions/protocol.ts";
import * as Q from "../extensions/questions.ts";
import * as R from "../extensions/requests.ts";
import { checkLedgerAnswers } from "../scripts/check-answers.ts";
import { renderReportBodyMarkdown } from "../scripts/report-body.ts";
import { questionArgv } from "../scripts/ui/questions.ts";
import { A, covers, coversDiskAndLog, ESTABLISHED, F, GOAL, ok, planned, rec, refused, run } from "./negative-bar-fixture.ts";

const ROOT = resolve(import.meta.dirname, "..");
const HIGH = { ...A, confidence: "high" } as const;
const OPERATOR: Q.Actor = { kind: "human", role: "operator", person: "ops@lab", enrolled: false, os_user: "ops", host: "lab", via: "cli", identity: "claimed" };
const ANALYST: Q.Actor = { kind: "human", role: "analyst", person: "ana", name: "ANA", enrolled: true, os_user: "ana", host: "lab", via: "cli", identity: "claimed" };

/** The negative bar's goal with one premise: the laptop is the employee's for 2024, about the disk, applying to questions 1 and 2. */
const PREMISED = GOAL.replace("## Definition of done", "## Premises\n\n- The disk image disk.E01 is of the laptop issued to the employee, who alone used it [scope: questions 1, 2; entities disk.E01; times 2024-01-01..2024-12-31]\n\n## Definition of done");

const act = async (S: string, who: Q.Actor, ev: Q.ActKind, input: Q.ActInput) => {
  const r = await Q.act(S, who, ev, input);
  assert.ok(r.ok, (r as { reason?: string }).reason);
  return r as Q.ActResult;
};

/** A finding for question `q`, and an answer to it established on it, citing `premises`, by a1. */
async function answer(c: Awaited<ReturnType<typeof run>>, q: string, premises: unknown[], o: { supersedes?: number; finding?: number } = {}) {
  const f = o.finding ?? ok(await rec(c.a0, { kind: "finding", ...F, value: `what question ${q} asks, ${Math.random().toString(36).slice(2, 8)}`, source: "the disk", evidence: "a key", refs: ["job:j000001/hits.txt"], answers: [q] })).entry.seq;
  return ok(await rec(c.a1, { kind: "answer", section: `question:${q}`, value: `the answer to question ${q}`, reasoning: `E-${f}`, ...HIGH, result: "established", premises, ...(o.supersedes ? { supersedes: o.supersedes } : {}) }));
}

const codes = (r: Awaited<ReturnType<typeof checkLedgerAnswers>>, section: string) => r.defects.filter((d) => d.section === section).map((d) => d.code);

test("the goal's premises: a Premises section read verbatim with the scope its bracket says, seeded as givens; a goal without one seeds none, and a chain from before the register folds none", async () => {
  assert.deepEqual(Q.goalPremises(PREMISED), [{ text: "The disk image disk.E01 is of the laptop issued to the employee, who alone used it", item: 1, scope: { entities: ["disk.E01"], times: [{ from: "2024-01-01", to: "2024-12-31" }], questions: ["Q-1", "Q-2"] } }]);
  assert.deepEqual(Q.goalPremises('## Premises\n\n1. "The subject is the account alice"\n2. A second one\n   that runs on\n\n## Other'), [{ text: "The subject is the account alice", item: 1, scope: {} }, { text: "A second one that runs on", item: 2, scope: {} }]);
  const bad = Q.goalPremises("## Premises\n\n- One [scope: owners bob]\n");
  assert.equal(bad[0]!.text, "One");
  assert.match(bad[0]!.bad ?? "", /"owners bob" is not questions, entities or times/);
  // Seeded at the kickoff: P-1, a given of the goal, on the chain.
  const c = await run({ goal: PREMISED });
  await Q.seedRegister(c.S);
  const snap = await Q.questionsSnapshot(c.S);
  const p = snap.state.premises.get("P-1")!;
  assert.deepEqual([p.class, p.authority, p.rev, p.locator], ["given", "goal", 1, "the goal (SWARM.md), Premises, item 1"]);
  assert.deepEqual(p.scope.questions, ["Q-1", "Q-2"]);
  assert.equal(snap.state.events.find((e) => e.ev === "seed")?.premises?.[0], "P-1");
  // A goal without a Premises section: none, and its seed is as it always was.
  const plain = await run();
  await Q.seedRegister(plain.S);
  const ps = await Q.questionsSnapshot(plain.S);
  assert.equal(ps.state.premises.size, 0);
  assert.equal("premises" in (ps.state.events.find((e) => e.ev === "seed") ?? {}), false);
  // A chain from before the register (a contract fixture's) folds no premise and verifies as it did.
  const old = await readFile(join(ROOT, "tests", "fixtures", "contract", "partial-every-policy", "run", "questions", "questions.jsonl"), "utf8").catch(() => "");
  if (old) {
    assert.equal(Q.verifyQuestionChain(old).ok, true);
    assert.equal(PM.foldPremises(old.split("\n").filter(Boolean).map((l) => JSON.parse(l) as Q.QuestionEvent)).size, 0);
  }
});

test("only the operator designates: an agent proposes a premise under test, an analyst is refused, and the operator adds, revises against the revision it read, admits and withdraws, each on the question chain", async () => {
  const c = await run();
  await Q.seedRegister(c.S);
  // An agent proposes; it cannot add, admit or withdraw.
  const proposed = await Q.premisePropose(c.a0, { text: "The laptop's clock kept UTC", locator: "input:logs/a.log, line 1", why: "every time the answers give is read off it" });
  assert.ok(proposed.ok && proposed.p === "P-1" && proposed.class === "proposition_under_test", JSON.stringify(proposed));
  refused(await Q.premisePropose(c.a0, { text: "no locator", why: "w" }), /locator is required: where its words stand/);
  refused(await Q.act(c.S, { kind: "agent", agent: "a0" }, "premise_add", { text: "t" }), /an agent proposes a premise \(premise_propose\)/);
  refused(await Q.act(c.S, { kind: "agent", agent: "a0" }, "premise_admit", { p: "P-1", as: "given", why: "w" }), /adding, revising, admitting and withdrawing a premise are the operator's/);
  refused(await Q.premisePropose(c.a1, { text: "The laptop's clock kept UTC", locator: "x", why: "w" }), /P-1 says this already, word for word .*cite it in an answer/);
  // An analyst designates nothing.
  refused(await Q.act(c.S, ANALYST, "premise_add", { text: "t" }), /designating the case's premises .* is the examiner's or the operator's, not an analyst's/);
  // The operator: a given by default, a supplied assertion when said; scope checked, its questions in the register.
  const added = await act(c.S, OPERATOR, "premise_add", { text: "The account alice is the employee's", locator: "the brief, page 2", premise_scope: { entities: ["alice"], questions: ["Q-1"] } });
  assert.deepEqual([added.p, added.class, added.rev], ["P-2", "given", 1]);
  refused(await Q.act(c.S, OPERATOR, "premise_add", { text: "t2", premise_scope: { questions: ["Q-99"] } }), /scope\.questions names Q-99, not in the question register/);
  refused(await Q.act(c.S, OPERATOR, "premise_add", { text: "t3", premise_scope: { times: ["2024-05-01..2024-01-01"] } }), /2024-05-01 is after 2024-01-01/);
  const said = await act(c.S, OPERATOR, "premise_add", { text: "The client says the laptop was never lent", class: "supplied_assertion" });
  assert.equal(said.class, "supplied_assertion");
  // A revision names the revision it revises and changes something; a stale one is refused, not merged.
  refused(await Q.act(c.S, OPERATOR, "premise_revise", { p: "P-2", text: "x", why: "w" }), /a revision names the revision it revises/);
  refused(await Q.act(c.S, OPERATOR, "premise_revise", { p: "P-2", expected_rev: 1, why: "w", locator: "the brief, page 2" }), /revision 1 of P-2 says this already/);
  const revised = await act(c.S, OPERATOR, "premise_revise", { p: "P-2", expected_rev: 1, why: "the brief's second page says until June", premise_scope: { entities: ["alice"], times: ["2024-01-01..2024-06-30"], questions: ["Q-1"] } });
  assert.equal(revised.rev, 2);
  refused(await Q.act(c.S, OPERATOR, "premise_revise", { p: "P-2", expected_rev: 1, why: "w", text: "y" }), /P-2 is at revision 2 .*not 1: read it again/);
  // An admission changes the class, never the revision; a withdrawal needs its why.
  const admitted = await act(c.S, OPERATOR, "premise_admit", { p: "P-1", as: "given", why: "the intake notes say so" });
  assert.deepEqual([admitted.class, admitted.rev], ["given", 1]);
  refused(await Q.act(c.S, OPERATOR, "premise_admit", { p: "P-1", as: "given", why: "again" }), /P-1 is a given already/);
  refused(await Q.act(c.S, OPERATOR, "premise_withdraw", { p: "P-3" }), /why is required: why the premise is withdrawn/);
  await act(c.S, OPERATOR, "premise_withdraw", { p: "P-3", why: "the client withdrew the statement" });
  refused(await Q.act(c.S, OPERATOR, "premise_revise", { p: "P-3", expected_rev: 1, why: "w", text: "z" }), /P-3 was withdrawn .* it takes no further act/);
  // All of it on the chain, which verifies; the register folds it.
  const { text } = await Q.readQuestionEvents(c.S);
  assert.equal(Q.verifyQuestionChain(text).ok, true);
  const s = (await Q.questionsSnapshot(c.S)).state.premises;
  assert.deepEqual([...s.values()].map((p) => [p.id, p.class, p.rev, Boolean(p.withdrawn)]), [["P-1", "given", 1, false], ["P-2", "given", 2, false], ["P-3", "supplied_assertion", 1, true]]);
  assert.deepEqual(s.get("P-1")!.classes.map((x) => x.class), ["proposition_under_test", "given"]);
  // A signed act's statement names the premise it acts on.
  const st = JSON.parse(Q.statementOf({ ev: "premise_revise", act: { premise: { id: "P-2", text: "t" }, why: "w", expected_rev: 2 }, origin: Q.originOf(OPERATOR), by: "operator" }, "run1")) as { target: string };
  assert.equal(st.target, "P-2");
  // What each seat is told, once, and the header's list, whole.
  const ctx = await Q.viewContext(c.S);
  const digest = Q.questionsDigest("a2", ctx, { seq: 0 });
  assert.deepEqual(digest.notices.filter((n) => n.kind === "premise").map((n) => n.q), ["P-1", "P-2", "P-3", "P-2", "P-1", "P-3"]);
  assert.ok(digest.lines.some((l) => l.startsWith("Premises (2; an answer cites each it rests on or bears on") && l.includes('P-2 rev 2, a given') && !l.includes("P-3")), digest.lines.join("\n"));
  assert.equal(Q.questionsDigest("a2", ctx, { seq: ctx.questions.state.events.at(-1)!.seq }).notices.length, 0, "told once");
  // The views: the agents' tool, and questions.md.
  const view = (await Q.questionsView(c.a0, { view: "premises" })) as { premises: Q.PremiseView[] };
  assert.equal(view.premises.length, 3);
  const one = (await Q.questionsView(c.a0, { id: "P-2" })) as { premise: Q.PremiseView; history: unknown[] };
  assert.equal(one.premise.rev, 2);
  assert.equal(one.history.length, 2);
  const md = Q.renderQuestionsMd(ctx);
  assert.match(md, /## Premises \(3\)/);
  assert.match(md, /### P-1: revision 1, a given/);
  assert.match(md, /- Class: a proposition under test .* → a given/);
});

test("an answer cites premises at the revision it read: an unknown or withdrawn premise and an earlier revision are refused; a proposition under test is assumed only conditionally, a premise scoped to named questions only where it applies, and a narrowed scope stays inside the premise's", async () => {
  const c = await run({ goal: PREMISED });
  await Q.seedRegister(c.S);
  await Q.premisePropose(c.a0, { text: "The laptop's clock kept UTC", locator: "input:logs/a.log, line 1", why: "w" });
  refused(await answer(c, "1", [{ id: "P-9", rev: 1, stance: "assumed" }]).catch((e) => ({ ok: false, reason: String(e) })), /P-9, which is not in the premise register/);
  const f = ok(await rec(c.a0, { kind: "finding", ...F, value: "alice logged on", source: "a log", evidence: "line 1", refs: ["job:j000001/hits.txt"], answers: ["1"] })).entry.seq;
  const base = { kind: "answer", section: "question:1", value: "alice", reasoning: `E-${f}`, ...HIGH, result: "established" };
  refused(await rec(c.a1, { ...base, premises: [{ id: "P-1", rev: 2, stance: "assumed" }] }), /P-1 at revision 2, and it is at revision 1: read it again/);
  refused(await rec(c.a1, { ...base, premises: [{ id: "P-1", rev: 1, stance: "doubted" }] }), /stance is one of assumed, supported, contradicted, unresolved/);
  refused(await rec(c.a1, { ...base, premises: [{ id: "P-1", rev: 1, stance: "assumed" }, { id: "P-1", rev: 1, stance: "unresolved" }] }), /cites P-1 twice/);
  refused(await rec(c.a1, { ...base, premises: [{ id: "P-2", rev: 1, stance: "assumed" }] }), /P-2 is a proposition under test .* assumed conditionally \(conditional: true/);
  refused(await rec(c.a1, { ...base, premises: [{ id: "P-2", rev: 1, stance: "unresolved", conditional: true }] }), /conditional is for an assumption/);
  refused(await rec(c.a1, { ...base, premises: [{ id: "P-1", rev: 1, stance: "supported" }] }), /P-1 is supported: name in its refs the standing finding or event that shows it/);
  refused(await rec(c.a1, { ...base, premises: [{ id: "P-1", rev: 1, stance: "assumed", scope: { entities: ["other.E01"] } }] }), /entities other\.E01 are not among the premise's \(disk\.E01\)/);
  refused(await rec(c.a1, { ...base, premises: [{ id: "P-1", rev: 1, stance: "assumed", scope: { times: [{ from: "2023-06-01", to: "2024-02-01" }] } }] }), /times 2023-06-01 to 2024-02-01 are not inside the premise's/);
  refused(await rec(c.a1, { kind: "answer", section: "summary", value: "s", reasoning: `E-${f}`, premises: [{ id: "P-1", rev: 1, stance: "assumed" }] }), /parts and premises are a question's answer's/);
  // What stands: the given assumed, the proposition conditionally, one supported on its finding.
  const a = ok(await rec(c.a1, { ...base, premises: [{ id: "P-1", rev: 1, stance: "assumed", scope: { times: [{ from: "2024-02-01", to: "2024-02-28" }] } }, { id: "P-2", rev: 1, stance: "assumed", conditional: true }] })).entry;
  assert.deepEqual(a.premises, [{ id: "P-1", rev: 1, stance: "assumed", scope: { times: [{ from: "2024-02-01", to: "2024-02-28" }] } }, { id: "P-2", rev: 1, stance: "assumed", conditional: true }]);
  // P-1 applies to questions 1 and 2: question 3's answer assumes it only conditionally.
  const f3 = ok(await rec(c.a0, { kind: "finding", ...F, value: "a file was deleted", source: "the disk", evidence: "a key", refs: ["job:j000001/hits.txt"], answers: ["3"] })).entry.seq;
  refused(await rec(c.a1, { kind: "answer", section: "question:3", value: "a file", reasoning: `E-${f3}`, ...HIGH, result: "established", premises: [{ id: "P-1", rev: 1, stance: "assumed" }] }), /P-1 applies to Q-1, Q-2 \(its scope\), and this answers Q-3: assume it here only conditionally/);
  ok(await rec(c.a1, { kind: "answer", section: "question:3", value: "a file", reasoning: `E-${f3}`, ...HIGH, result: "established", premises: [{ id: "P-1", rev: 1, stance: "assumed", conditional: true }] }));
  // Withdrawn: refused from then on.
  await act(c.S, OPERATOR, "premise_withdraw", { p: "P-2", why: "the clock was not on UTC" });
  refused(await rec(c.a1, { ...base, supersedes: a.seq, value: "alice, again", premises: [{ id: "P-2", rev: 1, stance: "assumed", conditional: true }] }), /cites P-2, withdrawn at .*: the clock was not on UTC/);
});

test("a partial answer names what is open, or is refused; an established one has no open part; an open part is bounded by an acquisition ask, a route, a limitation or a coverage record, never by a premise", async () => {
  const c = await run({ goal: PREMISED });
  await Q.seedRegister(c.S);
  const lead = await planned(c.a0, "1");
  const f = ok(await rec(c.a0, { kind: "finding", ...F, value: "a logon at 09:14", source: "a log", evidence: "line 12", refs: ["job:j000002/hits.txt"], answers: ["1"] })).entry.seq;
  const lim = ok(await rec(c.a0, { kind: "limitation", value: "the log keeps no account name", source: "a log", evidence: "its fields", reason: "unavailable", answers: ["1"] })).entry.seq;
  const base = { kind: "answer", section: "question:1", value: "a logon at 09:14; the account is open", reasoning: `E-${f}`, ...A, result: "partial" };
  const when = { id: "when", part: "when", status: "established", refs: [`E-${f}`] };
  // The refusal's words, whole.
  const none = await rec(c.a1, base);
  refused(none, /^record it established or name what is open: a partial answer carries parts \[\{id, part, status, refs, open_by\?\}\]/);
  assert.equal((none as unknown as { reason: string }).reason, P.PARTIAL_NEEDS_OPEN_PART);
  refused(await rec(c.a1, { ...base, parts: [when] }), /^record it established or name what is open/);
  refused(await rec(c.a1, { ...base, result: "established", parts: [when, { id: "who", part: "which account", status: "open", open_by: `E-${lim}` }] }), /result established claims every part the question asks, and "who" is open: record it partial/);
  // What bounds an open part.
  refused(await rec(c.a1, { ...base, parts: [when, { id: "who", part: "which account", status: "open" }] }), /"who" is open: say what bounds it in open_by/);
  refused(await rec(c.a1, { ...base, parts: [when, { id: "who", part: "which account", status: "open", open_by: "P-1" }] }), /"who" is open by P-1, a premise, and a premise is never an open part: what the case takes as given is cited in premises/);
  refused(await rec(c.a1, { ...base, parts: [when, { id: "who", part: "which account", status: "open", open_by: `E-${f}` }] }), /"who" is open by E-\d+, a finding: an open part is bounded by a limitation .* or a coverage record/);
  refused(await rec(c.a1, { ...base, parts: [when, { id: "who", part: "which account", status: "open", open_by: "R-7" }] }), /"who" is open by R-7, which is not a request of this run/);
  refused(await rec(c.a1, { ...base, parts: [when, { id: "who", part: "which account", status: "open", open_by: "L-99" }] }), /"who" is open by L-99, which is not in the lead register/);
  refused(await rec(c.a1, { ...base, parts: [{ id: "when", part: "when", status: "established" }] }), /"when" is established: name the entries that establish it in refs/);
  refused(await rec(c.a1, { ...base, parts: [when, { ...when }] }), /parts names "when" twice/);
  refused(await rec(c.a1, { ...base, parts: [when, { id: "who", part: "which account", status: "established", refs: [`E-${f}`], open_by: `E-${lim}` }] }), /"who" is established: open_by is an open part's/);
  // Recorded: the limitation that bounds the open part joins the answer's limitations; a route bounds another.
  const a = ok(await rec(c.a1, { ...base, parts: [when, { id: "who", part: "which account", status: "open", open_by: `E-${lim}` }, { id: "how", part: "how", status: "open", open_by: lead }] })).entry;
  assert.deepEqual(a.limitations?.map((x) => x.seq), [lim]);
  assert.deepEqual(a.parts?.map((p) => [p.id, p.status, p.open_by ?? null]), [["when", "established", null], ["who", "open", `E-${lim}`], ["how", "open", lead]]);
  assert.ok(!(a.support ?? []).some((x) => x.seq === lim), "the bounding limitation is among the limitations, not the support");
});

test("premise_inconsistent: an assumption and a contradiction of one revision over scopes that overlap hold both questions; scopes that do not meet, uncertainty, a conditional assumption and a named rebutting finding hold nothing, and neither answer is forced", async () => {
  const c = await run({ goal: PREMISED });
  await Q.seedRegister(c.S);
  const a1 = ok(await answer(c, "1", [{ id: "P-1", rev: 1, stance: "assumed" }])).entry;
  // Uncertainty and support hold nothing.
  const a2 = await answer(c, "2", [{ id: "P-1", rev: 1, stance: "unresolved" }]);
  let r = await checkLedgerAnswers(c.S, ["1", "2"]);
  assert.deepEqual([codes(r, "question:1"), codes(r, "question:2")], [["no_critic_act"], ["no_critic_act"]]);
  // A contradiction with no rebutting finding, over the whole scope: both held, the reply says so and the ways out.
  const contra = await answer(c, "2", [{ id: "P-1", rev: 1, stance: "contradicted" }], { supersedes: a2.entry.seq });
  assert.match(contra.note ?? "", /this answer contradicts P-1 \(revision 1\), which E-\d+ \(question:1\) assumes, over scopes that overlap: the finish line holds both questions \(premise_inconsistent\) until they are reconciled, and neither side is forced: revise one answer/);
  r = await checkLedgerAnswers(c.S, ["1", "2"]);
  assert.ok(codes(r, "question:1").includes("premise_inconsistent") && codes(r, "question:2").includes("premise_inconsistent"), r.lines.join("\n"));
  const d = r.defects.find((x) => x.code === "premise_inconsistent" && x.section === "question:1")!;
  assert.match(d.what, new RegExp(`^answer #${a1.seq} \\(question:1\\) assumes P-1 \\(revision 1\\), which #${contra.entry.seq} \\(question:2\\) contradicts, over scopes that overlap$`));
  for (const way of ["revise one answer", "cite the finding that rebuts P-1 in the contradiction's refs", "narrow either citation's scope", "answer conditionally"]) assert.ok(d.fix.includes(way), `${way}: ${d.fix}`);
  assert.deepEqual(d.named_by, []);
  const ready = await FIN.readiness(c.S);
  assert.ok(ready.items.some((i) => i === d.what), JSON.stringify(ready.items));
  // Scopes that do not meet: question 2 contradicts it only for the second half of the year, question 1 assumes it for February.
  const narrow = await answer(c, "2", [{ id: "P-1", rev: 1, stance: "contradicted", scope: { times: [{ from: "2024-07-01", to: "2024-12-31" }] } }], { supersedes: contra.entry.seq });
  const a1b = ok(await answer(c, "1", [{ id: "P-1", rev: 1, stance: "assumed", scope: { times: [{ from: "2024-02-01", to: "2024-02-28" }] } }], { supersedes: a1.seq })).entry;
  r = await checkLedgerAnswers(c.S, ["1", "2"]);
  assert.ok(!r.defects.some((x) => x.code === "premise_inconsistent"), r.lines.join("\n"));
  // Overlapping again (question 2 for the whole year): a conditional assumption holds nothing.
  const whole = await answer(c, "2", [{ id: "P-1", rev: 1, stance: "contradicted" }], { supersedes: narrow.entry.seq });
  const cond = ok(await answer(c, "1", [{ id: "P-1", rev: 1, stance: "assumed", conditional: true }], { supersedes: a1b.seq })).entry;
  r = await checkLedgerAnswers(c.S, ["1", "2"]);
  assert.ok(!r.defects.some((x) => x.code === "premise_inconsistent"), r.lines.join("\n"));
  // Question 1 assumes it outright again; question 2 names the finding that rebuts it: the premise goes to the operator, question 1 is warned, and nothing holds.
  ok(await answer(c, "1", [{ id: "P-1", rev: 1, stance: "assumed" }], { supersedes: cond.seq }));
  const rebut = ok(await rec(c.a0, { kind: "finding", ...F, value: "a second user's profile on the laptop", source: "the disk", evidence: "the profile list", refs: ["job:j000001/hits.txt"], answers: ["2"] })).entry.seq;
  const rebutted = await answer(c, "2", [{ id: "P-1", rev: 1, stance: "contradicted", refs: [`E-${rebut}`] }], { supersedes: whole.entry.seq, finding: rebut });
  assert.match(rebutted.note ?? "", /the premise dispute R-1 \(P-1 revision 1\) is with the operator/);
  r = await checkLedgerAnswers(c.S, ["1", "2"]);
  assert.ok(!r.defects.some((x) => x.code === "premise_inconsistent"), r.lines.join("\n"));
  assert.ok(r.warnings.some((w) => /\(question:1\) assumes P-1 \(revision 1\), which #\d+ \(question:2\) contradicts on E-\d+: the premise is disputed before the operator/.test(w)), r.warnings.join("\n"));
  const req = (await R.requestsSnapshot(c.S)).requests.get("R-1")!;
  assert.deepEqual([req.kind, req.key, req.line.id, req.state === "answered"], ["premise", "premise:P-1@r1", "P-1", false]);
  assert.deepEqual(R.noticeOf(req, "nb1").id, "P-1");
  // A rebutting finding that is disputed rebuts nothing: the pair holds again.
  assert.ok((await P.disputeEntry(c.a3, { seq: rebut, why: "the profile is a default one", refs: ["job:j000001/hits.txt"] })).ok);
  r = await checkLedgerAnswers(c.S, ["1", "2"]);
  assert.ok(codes(r, "question:1").includes("premise_inconsistent"), r.lines.join("\n"));
});

test("a premise revised or withdrawn: the answers citing its earlier revision, or it, are warned, never rewritten; its dispute closes; the operator may also answer the dispute on the request", async () => {
  const c = await run({ goal: PREMISED });
  await Q.seedRegister(c.S);
  ok(await answer(c, "1", [{ id: "P-1", rev: 1, stance: "assumed" }]));
  const rebut = ok(await rec(c.a0, { kind: "finding", ...F, value: "the laptop was reissued in July", source: "the disk", evidence: "the asset tag", refs: ["job:j000001/hits.txt"], answers: ["2"] })).entry.seq;
  ok(await answer(c, "2", [{ id: "P-1", rev: 1, stance: "contradicted", refs: [`E-${rebut}`] }], { finding: rebut }));
  assert.equal((await R.requestsSnapshot(c.S)).requests.get("R-1")?.closed, null);
  await act(c.S, OPERATOR, "premise_revise", { p: "P-1", expected_rev: 1, why: "the laptop was the employee's only until June", premise_scope: { entities: ["disk.E01"], times: ["2024-01-01..2024-06-30"], questions: ["Q-1", "Q-2"] } });
  await R.reconcileRequests(c.S);
  const closed = (await R.requestsSnapshot(c.S)).requests.get("R-1")!;
  assert.deepEqual([closed.state, closed.closed?.text], ["answered", "P-1 was revised to revision 2: the laptop was the employee's only until June"]);
  let r = await checkLedgerAnswers(c.S, ["1", "2"]);
  assert.equal(r.warnings.filter((w) => /cites P-1 at revision 1, revised to 2 since/.test(w)).length, 2, r.warnings.join("\n"));
  await act(c.S, OPERATOR, "premise_withdraw", { p: "P-1", why: "the brief was wrong about the laptop" });
  r = await checkLedgerAnswers(c.S, ["1", "2"]);
  assert.equal(r.warnings.filter((w) => /cites P-1, withdrawn at .*the brief was wrong about the laptop/.test(w)).length, 2, r.warnings.join("\n"));
  assert.ok(!r.warnings.some((w) => /revised to 2 since/.test(w)), "a withdrawn premise is warned of as withdrawn, not as revised");
  // A dispute the operator answers on the request: "the premise stands, and why"; nothing is forced on the answers.
  const d = await run({ goal: PREMISED });
  await Q.seedRegister(d.S);
  const rb = ok(await rec(d.a0, { kind: "finding", ...F, value: "a second profile", source: "the disk", evidence: "the list", refs: ["job:j000001/hits.txt"], answers: ["2"] })).entry.seq;
  ok(await answer(d, "2", [{ id: "P-1", rev: 1, stance: "contradicted", refs: [`E-${rb}`] }], { finding: rb }));
  const answered = await R.requestAct(d.S, "R-1", { ev: "answered", by: "operator", text: "the premise stands: the profile is the IT department's" });
  assert.ok(answered.ok, JSON.stringify(answered));
  const cli = spawnSync(process.execPath, ["--experimental-strip-types", "--no-warnings", join(ROOT, "scripts", "requests-cli.ts"), "answer", d.S, "R-1", "again"], { encoding: "utf8" });
  assert.doesNotMatch(cli.stdout, /is a premise request: /, "a premise dispute is answered on the request, as a stop proposal is");
});

test("the operator's ruling releases an unreconciled conflict: a revision revised since, or a premise withdrawn, holds nothing, and the answers citing it are warned instead; on a question not material the conflict is a warning", async () => {
  const c = await run({ goal: PREMISED });
  await Q.seedRegister(c.S);
  ok(await answer(c, "1", [{ id: "P-1", rev: 1, stance: "assumed" }]));
  ok(await answer(c, "2", [{ id: "P-1", rev: 1, stance: "contradicted" }]));
  let r = await checkLedgerAnswers(c.S, ["1", "2"]);
  assert.deepEqual([codes(r, "question:1").includes("premise_inconsistent"), codes(r, "question:2").includes("premise_inconsistent")], [true, true], r.lines.join("\n"));
  // A question the operator marked not material: the conflict is warned there, and still holds the material one.
  const snap = await Q.questionsSnapshot(c.S);
  const g = P.ledgerGate({ entries: await P.readLedger(c.S), attestations: [], disputes: [], sections: ["question:1", "question:2"], bar: (id) => ({ material: id !== "2", existence: false }), premises: snap.state.premises });
  assert.deepEqual(g.defects.filter((d) => d.code === "premise_inconsistent").map((d) => d.section), ["question:1"]);
  const warned = g.warnings.filter((w) => w.code === "premise_inconsistent");
  assert.deepEqual(warned.map((w) => w.section), ["question:2"]);
  assert.match(warned[0]!.what, /contradicts P-1 \(revision 1\), which #\d+ \(question:1\) assumes, over scopes that overlap \(a question not material: warned, never held\)/);
  // The operator revises P-1: the conflict was over revision 1, which is retired; each answer is warned it cites it.
  await act(c.S, OPERATOR, "premise_revise", { p: "P-1", expected_rev: 1, why: "the brief named the wrong period", premise_scope: { entities: ["disk.E01"], times: ["2024-01-01..2024-12-31"], questions: ["Q-1", "Q-2"] }, text: "The disk image disk.E01 is of the laptop issued to the employee" });
  r = await checkLedgerAnswers(c.S, ["1", "2"]);
  assert.ok(!r.defects.some((d) => d.code === "premise_inconsistent"), r.lines.join("\n"));
  assert.equal(r.warnings.filter((w) => /cites P-1 at revision 1, revised to 2 since/.test(w)).length, 2, r.warnings.join("\n"));
  const ready = await FIN.readiness(c.S);
  assert.ok(!ready.items.some((i) => /over scopes that overlap/.test(i)), `readiness holds no premise conflict: ${ready.items.join("; ")}`);
  // The same pair, and the operator withdraws P-1: nothing holds, and each answer is warned it cites a withdrawn premise.
  const d = await run({ goal: PREMISED });
  await Q.seedRegister(d.S);
  ok(await answer(d, "1", [{ id: "P-1", rev: 1, stance: "assumed" }]));
  ok(await answer(d, "2", [{ id: "P-1", rev: 1, stance: "contradicted" }]));
  await act(d.S, OPERATOR, "premise_withdraw", { p: "P-1", why: "the brief was wrong about the laptop" });
  r = await checkLedgerAnswers(d.S, ["1", "2"]);
  assert.ok(!r.defects.some((x) => x.code === "premise_inconsistent"), r.lines.join("\n"));
  assert.equal(r.warnings.filter((w) => /cites P-1, withdrawn at .*the brief was wrong about the laptop/.test(w)).length, 2, r.warnings.join("\n"));
});

test("a review names the answer's parts by id and may add one the answer leaves out: an omitted part allows an established claim only best_candidate, and stays warned (part_omitted); a partial answer's open row needs no declared_open; review parts without ids read as they always did", async () => {
  const c = await run();
  const lead = await planned(c.a0, "1");
  const f = ok(await rec(c.a0, { kind: "finding", ...F, value: "alice logged on at 09:14", source: "a log", evidence: "line 12", refs: ["job:j000002/hits.txt"], answers: ["1"] })).entry.seq;
  const a = ok(await rec(c.a1, { kind: "answer", section: "question:1", value: "alice, at 09:14", reasoning: `E-${f}`, ...HIGH, result: "established", parts: [{ id: "who", part: "who", status: "established", refs: [`E-${f}`] }, { id: "when", part: "when", status: "established", refs: [`E-${f}`] }] })).entry;
  assert.ok((await L.closeLead(c.a0, lead, { disposition: "resolved", ref: `E-${f}` })).ok);
  const review = (parts: unknown[]) => ({ ...ESTABLISHED, answer_review: { ...ESTABLISHED.answer_review, parts } });
  refused(await P.attestEntry(c.a2, { seq: a.seq, how: "re-read line 12", ...review([{ id: "where", part: "where", established: true, why: "w" }]) }), /carries parts who, when: answer_review\.parts\[\]\.id names one of them \(got where/);
  refused(await P.attestEntry(c.a2, { seq: a.seq, how: "re-read line 12", ...review([{ id: "who", part: "who", established: true, why: "w" }, { id: "who", part: "who again", established: true, why: "w" }]) }), /weighs who twice/);
  refused(await P.attestEntry(c.a2, { seq: a.seq, how: "re-read line 12", ...review([{ part: "from where", established: true, why: "w", missing: true }]) }), /"from where" is missing from the answer, so the answer does not establish it: established false/);
  refused(await P.attestEntry(c.a2, { seq: a.seq, how: "re-read line 12", ...review([{ id: "who", part: "from where", established: false, why: "w", missing: true }]) }), /is missing from the answer: it has no id of the answer's/);
  const omitted = review([{ id: "who", part: "who", established: true, why: "line 12" }, { id: "when", part: "when", established: true, why: "line 12" }, { part: "from which host", established: false, why: "the question asks where from", missing: true }]);
  refused(await P.attestEntry(c.a2, { seq: a.seq, how: "re-read line 12", ...omitted }), /can be attested best_candidate only: the review names "from which host", a part of the question the answer leaves out \(the question asks where from\)/);
  const bc = await P.attestEntry(c.a2, { seq: a.seq, how: "re-read line 12", ...omitted, strength: "best_candidate" });
  assert.ok(bc.ok && bc.line, JSON.stringify(bc));
  let r = await checkLedgerAnswers(c.S, ["1"]);
  assert.deepEqual(r.best_candidate, ["question:1"]);
  const w = r.warnings.filter((x) => /leaves out a part of the question its review names: "from which host" \(a2: the question asks where from\)/.test(x));
  assert.equal(w.length, 1, r.warnings.join("\n"));
  assert.ok((await FIN.readiness(c.S)).warnings.some((x) => /leaves out a part of the question/.test(x)), "said in finish status");
  const view = Q.viewQuestion((await Q.questionsSnapshot(c.S)).state.questions.get("Q-1")!, await Q.viewContext(c.S));
  assert.deepEqual(view.answer?.omitted, [{ by: "a2", part: "from which host", why: "the question asks where from" }]);
  // Recorded again with the part: nothing is warned; the review, by ids, holds it established.
  const a2 = ok(await rec(c.a1, { kind: "answer", section: "question:1", value: "alice, at 09:14, from the office host", reasoning: `E-${f}`, ...HIGH, result: "established", supersedes: a.seq, parts: [{ id: "who", part: "who", status: "established", refs: [`E-${f}`] }, { id: "when", part: "when", status: "established", refs: [`E-${f}`] }, { id: "where", part: "from which host", status: "established", refs: [`E-${f}`] }] })).entry;
  await coversDiskAndLog(c.a0, "1");
  const est = await P.attestEntry(c.a2, { seq: a2.seq, how: "re-read line 12", ...review([{ id: "who", part: "who", established: true, why: "line 12" }, { id: "when", part: "when", established: true, why: "line 12" }, { id: "where", part: "from which host", established: true, why: "line 12's source address" }]) });
  assert.ok(est.ok && est.line?.strength === "established", JSON.stringify(est));
  r = await checkLedgerAnswers(c.S, ["1"]);
  assert.equal(r.dispositions["question:1"], "established", r.lines.join("\n"));
  assert.ok(!r.warnings.some((x) => /leaves out a part/.test(x)));
  // An answer without parts: an id names nothing; parts without ids are read as they always were.
  const f2 = ok(await rec(c.a0, { kind: "finding", ...F, value: "a tool", source: "the disk", evidence: "a key", refs: ["job:j000001/hits.txt"], answers: ["2"] })).entry.seq;
  const plain = ok(await rec(c.a1, { kind: "answer", section: "question:2", value: "a tool", reasoning: `E-${f2}`, ...HIGH, result: "established" })).entry;
  await covers(c.a0, "2");
  // The id is left out and said: the part is weighed as written (it was a refusal that asked only for the id to be left out).
  const idless = await P.attestEntry(c.a2, { seq: plain.seq, how: "re-read", ...review([{ id: "a", part: "the question", established: true, why: "w" }]) });
  assert.ok(idless.ok, (idless as { reason?: string }).reason);
  assert.match(String((idless as { note?: string }).note), /#\d+ carries no parts, so the ids in answer_review\.parts \(a\) name nothing: each part is weighed as you wrote it, without an id/);
  assert.equal((idless as { line: P.LedgerAttestation }).line.answer_review?.parts[0]?.id, undefined);
  assert.ok((await P.attestEntry(c.a3, { seq: plain.seq, how: "re-read", ...ESTABLISHED })).ok);
});

test("an open part the question does not ask: a review marks it not_asked, which caps nothing; the partial answer whose every other part is established is warned to be recorded established with it among its limitations, and never promoted", async () => {
  const c = await run();
  const lead = await planned(c.a0, "1");
  const f = ok(await rec(c.a0, { kind: "finding", ...F, value: "alice logged on at 09:14", source: "a log", evidence: "line 12", refs: ["job:j000002/hits.txt"], answers: ["1"] })).entry.seq;
  const lim = ok(await rec(c.a0, { kind: "limitation", value: "The log keeps no other session detail", source: "a log", evidence: "its fields", reason: "unavailable", answers: ["1"] })).entry.seq;
  // The question asks who logged on and when; the answer holds open the terminal the session used, which it does not ask.
  const a = ok(await rec(c.a1, { kind: "answer", section: "question:1", value: "alice, at 09:14; the terminal is not established", reasoning: `E-${f}; the terminal is open (E-${lim})`, ...A, limitations: [lim], result: "partial", parts: [{ id: "who", part: "who logged on", status: "established", refs: [`E-${f}`] }, { id: "when", part: "when", status: "established", refs: [`E-${f}`] }, { id: "tty", part: "which terminal the session used", status: "open", open_by: `E-${lim}` }] })).entry;
  assert.ok((await L.closeLead(c.a0, lead, { disposition: "resolved", ref: `E-${f}` })).ok);
  const review = (parts: unknown[]) => ({ ...ESTABLISHED, answer_review: { ...ESTABLISHED.answer_review, parts } });
  // Its shape: never with missing, never established.
  refused(await P.attestEntry(c.a2, { seq: a.seq, how: "re-read line 12", ...review([{ part: "which terminal", established: false, why: "w", not_asked: true, missing: true }]) }), /is either missing \(the question asks it and the answer leaves it out\) or not_asked \(the answer holds it and the question does not ask it\), not both/);
  refused(await P.attestEntry(c.a2, { seq: a.seq, how: "re-read line 12", ...review([{ id: "tty", part: "which terminal", established: true, why: "w", not_asked: true }]) }), /is not asked by the question, so the review does not weigh it: established false/);
  // A review that holds the open part open, as the answer declares it: nothing is warned, the answer is partial.
  const held = review([{ id: "who", part: "who logged on", established: true, why: "line 12" }, { id: "when", part: "when", established: true, why: "line 12" }, { id: "tty", part: "which terminal the session used", established: false, why: "the log keeps none" }]);
  await coversDiskAndLog(c.a0, "1");
  assert.equal((await P.attestEntry(c.a3, { seq: a.seq, how: "re-read line 12", ...held })).ok, true);
  let r = await checkLedgerAnswers(c.S, ["1"]);
  assert.equal(r.dispositions["question:1"], "partial");
  assert.ok(!r.warnings.some((x) => /partial/.test(x) && /question:1/.test(x)), r.warnings.join("\n"));
  // Another review marks it outside the question: recorded established, nothing capped; the warning says what to record, and the answer stays partial.
  const marked = review([{ id: "who", part: "who logged on", established: true, why: "line 12" }, { id: "when", part: "when", established: true, why: "line 12" }, { id: "tty", part: "which terminal the session used", established: false, why: "the question asks who and when, not the terminal", not_asked: true }]);
  const att = await P.attestEntry(c.a2, { seq: a.seq, how: "re-read line 12", ...marked });
  assert.ok(att.ok && att.line, JSON.stringify(att));
  assert.equal(att.line!.strength, "established");
  assert.equal(att.line!.capped, undefined);
  assert.deepEqual(att.line!.answer_review?.parts.map((p) => p.not_asked ?? false), [false, false, true], "kept in the chained attestation");
  assert.match(P.answerReviewWords(att.line!.answer_review!), /tty which terminal the session used NOT ASKED by the question \(a limitation, not an open part\)/);
  assert.deepEqual((att as { warned?: string[] }).warned, ["partial_all_parts_established"], "said in the attest's reply");
  r = await checkLedgerAnswers(c.S, ["1"]);
  assert.equal(r.dispositions["question:1"], "partial", "never promoted: the answer stands as recorded");
  assert.equal(r.results["question:1"], "partial");
  const w = r.warnings.filter((x) => /\(question:1\) is partial, and every part of the question its reviews weighed is established/.test(x));
  assert.equal(w.length, 1, r.warnings.join("\n"));
  assert.match(w[0]!, /what it holds open the question does not ask, as its reviews mark it: tty "which terminal the session used" \(a2: the question asks who and when, not the terminal\)/);
  assert.match(w[0]!, new RegExp(`record the answer again with supersedes=${a.seq} and result established, with what the question does not ask \\("which terminal the session used"\\) among its limitations, not its parts`));
  assert.match(w[0]!, /Nothing is changed for you: the answer stands as recorded until you record it again/);
  assert.ok(!(await FIN.readiness(c.S)).items.some((x) => /question:1/.test(x)), "a warning never holds");
  // The report says it beside the part it marks (docs/adr/0013, "What the report shows of an answer's parts").
  assert.match(await renderReportBodyMarkdown(c.S), /\| tty \| which terminal the session used \| open; not asked by the question, as a review marks it: a2 \(the question asks who and when, not the terminal\) \|/);
  // On an answer that claims established, a part marked not asked caps nothing either.
  const f2 = ok(await rec(c.a0, { kind: "finding", ...F, value: "a remote tool installed as a service", source: "the disk", evidence: "a key", refs: ["job:j000001/hits.txt"], answers: ["2"] })).entry.seq;
  const est = ok(await rec(c.a1, { kind: "answer", section: "question:2", value: "a remote tool, as a service", reasoning: `E-${f2}`, ...HIGH, result: "established" })).entry;
  await covers(c.a0, "2");
  const e2 = await P.attestEntry(c.a2, { seq: est.seq, how: "re-read the key", ...review([{ part: "the question as asked", established: true, why: "the key" }, { part: "every other tool the host ever ran", established: false, why: "the question asks whether one was installed, not every tool", not_asked: true }]) });
  assert.ok(e2.ok && e2.line?.strength === "established" && !e2.line.capped, JSON.stringify(e2));
});

test("an answer without parts or premises hashes as it always did: the fields are in the core only when present, and a ledger written before them verifies", async () => {
  const entry = { v: 4, seq: 7, kind: "answer", value: "alice", section: "question:1", reasoning: "E-1", result: "established", confidence: "high", by: "a1", authors: ["a1"], at: "2026-09-29T00:00:00Z" } as P.LedgerEntry;
  const h = P.ledgerHash(entry, "genesis");
  assert.equal(P.ledgerHash({ ...entry, parts: [], premises: [] }, "genesis"), h, "empty rows are none");
  assert.notEqual(P.ledgerHash({ ...entry, parts: [{ id: "a", part: "p", status: "established", refs: ["E-1"] }] }, "genesis"), h);
  assert.notEqual(P.ledgerHash({ ...entry, premises: [{ id: "P-1", rev: 1, stance: "assumed" }] }, "genesis"), h);
  assert.equal(P.answerFingerprint({ ...entry, parts: [], premises: [] }), P.answerFingerprint(entry), "the fingerprint a summary is bound to is unchanged");
  assert.equal(JSON.stringify(P.conclusionFields(entry)), JSON.stringify({ result: "established", question_rev: 1, inconclusive: false, asserts_absence: false }));
  for (const f of ["partial-every-policy", "c10-partial-cascade", "resume-prefix"]) {
    const text = await readFile(join(ROOT, "tests", "fixtures", "contract", f, "run", "ledger", "entries.jsonl"), "utf8");
    assert.equal(P.verifyLedgerChain(text).ok, true, `${f}: its ledger verifies`);
  }
});

test("the report renders the premises and each answer's parts and premises; a run with neither reads as before", async () => {
  const c = await run({ goal: PREMISED });
  await Q.seedRegister(c.S);
  const lead = await planned(c.a0, "1");
  const f = ok(await rec(c.a0, { kind: "finding", ...F, value: "a logon at 09:14", source: "a log", evidence: "line 12", refs: ["job:j000002/hits.txt"], answers: ["1"] })).entry.seq;
  const lim = ok(await rec(c.a0, { kind: "limitation", value: "no account name", source: "a log", evidence: "its fields", reason: "unavailable", answers: ["1"] })).entry.seq;
  ok(await rec(c.a1, { kind: "answer", section: "question:1", value: "a logon at 09:14", reasoning: `E-${f}`, ...A, result: "partial", parts: [{ id: "when", part: "when the logon happened", status: "established", refs: [`E-${f}`] }, { id: "who", part: "which account", status: "open", open_by: `E-${lim}` }], premises: [{ id: "P-1", rev: 1, stance: "assumed", conditional: true }] }));
  assert.ok((await L.closeLead(c.a0, lead, { disposition: "resolved", ref: `E-${f}` })).ok);
  const md = await renderReportBodyMarkdown(c.S);
  assert.match(md, /The premises the examination took/);
  assert.match(md, /P-1 \(revision 1\).*a given.*The disk image disk\.E01 is of the laptop issued to the employee, who alone used it/);
  assert.match(md, /Part by part, as the answer reads revision 1 of the question/);
  assert.match(md, /which account.*open/);
  assert.match(md, /assuming P-1: the answer holds only if it does/);
  const plain = await run();
  const pf = ok(await rec(plain.a0, { kind: "finding", ...F, value: "alice", source: "a log", evidence: "line 1", refs: ["job:j000002/hits.txt"], answers: ["1"] })).entry.seq;
  ok(await rec(plain.a1, { kind: "answer", section: "question:1", value: "alice", reasoning: `E-${pf}`, ...A, result: "established" }));
  const pmd = await renderReportBodyMarkdown(plain.S);
  assert.doesNotMatch(pmd, /The premises the examination took|Part by part|assuming P-/);
});

test("the operator's premise commands, from the CLI and the console: add, admit, revise and withdraw as swarm.sh question premise does them, list and show read them", async () => {
  const c = await run();
  await Q.seedRegister(c.S);
  const cli = (...args: string[]) => spawnSync(process.execPath, ["--experimental-strip-types", "--no-warnings", join(ROOT, "scripts", "questions-cli.ts"), "premise", c.S, ...args], { encoding: "utf8" });
  const add = cli("add", "--text", "The laptop is the employee's", "--locator", "the brief, page 1", "--entity", "disk.E01", "--time", "2024-01-01..2024-12-31", "--for-question", "Q-1", "--why", "the brief says so");
  assert.equal(add.status, 0, add.stdout + add.stderr);
  const added = JSON.parse(add.stdout.trim().split("\n").at(-1)!) as { ok: boolean; p: string; class: string; admitted_by: string };
  assert.deepEqual([added.ok, added.p, added.class, added.admitted_by], [true, "P-1", "given", "cli, no hub running"]);
  await Q.premisePropose(c.a0, { text: "The clock kept UTC", locator: "input:logs/a.log", why: "w" });
  const admit = cli("admit", "P-2", "--as", "supplied_assertion", "--why", "the client says so");
  assert.equal(admit.status, 0, admit.stdout + admit.stderr);
  assert.equal((JSON.parse(admit.stdout.trim()) as { class: string }).class, "supplied_assertion");
  const revise = cli("revise", "P-1", "--expect-rev", "1", "--why", "narrower", "--no-scope");
  assert.equal(revise.status, 0, revise.stdout + revise.stderr);
  const withdraw = cli("withdraw", "P-2", "--why", "the client withdrew it");
  assert.equal(withdraw.status, 0, withdraw.stdout + withdraw.stderr);
  const list = cli("list", "--json");
  const views = (JSON.parse(list.stdout) as { premises: Q.PremiseView[] }).premises;
  assert.deepEqual(views.map((p) => [p.id, p.class, p.rev, Boolean(p.withdrawn)]), [["P-1", "given", 2, false], ["P-2", "supplied_assertion", 1, true]]);
  assert.deepEqual(views[0]!.scope, {}, "--no-scope cleared it");
  const show = cli("show", "P-1");
  assert.match(show.stdout, /^P-1 rev 2, a given \(ops|^P-1 rev 2, a given \(/m);
  assert.match(show.stdout, /revision 1 .*The laptop is the employee's — at the brief, page 1; scope entities disk\.E01; times 2024-01-01 to 2024-12-31; questions Q-1/);
  // The console: each premise act as swarm.sh question <id> premise … arguments.
  assert.deepEqual(questionArgv({ action: "premise_add", text: "t", locator: "l", class: "given", entities: "a, b", times: ["2024-01-01..2024-02-01"], questions: "Q-1" }), { sub: "premise", argv: ["add", "--text", "t", "--locator", "l", "--class", "given", "--entity", "a", "--entity", "b", "--time", "2024-01-01..2024-02-01", "--for-question", "Q-1"] });
  assert.deepEqual(questionArgv({ action: "premise_admit", p: "p-2", admit_as: "given", why: "w", as: "ana" }), { sub: "premise", argv: ["admit", "P-2", "--as", "given", "--why", "w", "--as", "ana"] });
  assert.deepEqual(questionArgv({ action: "premise_revise", p: "P-1", expected_rev: 2, why: "w", text: "t2" }), { sub: "premise", argv: ["revise", "P-1", "--expect-rev", "2", "--why", "w", "--text", "t2"] });
  assert.deepEqual(questionArgv({ action: "premise_withdraw", p: "P-1", why: "w" }), { sub: "premise", argv: ["withdraw", "P-1", "--why", "w"] });
  assert.throws(() => questionArgv({ action: "premise_admit", p: "P-1", admit_as: "proposition_under_test", why: "w" }), /admit_as is given or supplied_assertion/);
});

test("scope overlap is structural: entities shared, time ranges that meet (a date reaching to its day's end), and what a scope leaves out is unbounded", () => {
  const overlap = PM.scopesOverlap;
  assert.equal(overlap({ entities: ["Alice"] }, { entities: ["alice ", "bob"] }), true, "entities compare folded");
  assert.equal(overlap({ entities: ["alice"] }, { entities: ["bob"] }), false);
  assert.equal(overlap({ times: [{ from: "2024-01-01", to: "2024-03-31" }] }, { times: [{ from: "2024-03-31", to: "2024-12-31" }] }), true, "a day shared");
  assert.equal(overlap({ times: [{ from: "2024-01-01", to: "2024-03-31" }] }, { times: [{ from: "2024-04-01" }] }), false);
  assert.equal(overlap({ entities: ["alice"], times: [{ to: "2024-01-01" }] }, { times: [{ from: "2023-01-01" }] }), true, "no entities on one side: unbounded");
  assert.equal(overlap(undefined, { entities: ["x"] }), true);
  assert.equal(PM.scopeOutside({ times: [{ from: "2024-02-01", to: "2024-02-28" }] }, { times: [{ from: "2024-01-01", to: "2024-12-31" }] }), null);
  assert.equal(PM.checkScope({ owners: ["x"] }).ok, false);
});

// The shipped goals designate what their briefs state as given (the limits
// spec, item 6 refinement: c10 run sd9645b held four givens of its brief open
// as parts to prove). Each premise is the goal's own sentence, closely
// restated, with its scope; the questions a scope names are questions the
// goal numbers. What a premise must never be (an answer, or what a question
// tests) is a reviewer's judgement, recorded beside each list.
test("the shipped goals with a brief designate its givens: each premise parses with its scope, and names only questions the goal has", async () => {
  const { readdir } = await import("node:fs/promises");
  const dir = join(ROOT, "prompts", "goals");
  const counts: Record<string, number> = {};
  for (const name of (await readdir(dir)).filter((f) => f.endsWith(".md")).sort()) {
    const text = await readFile(join(dir, name), "utf8");
    const front = /^---\n([\s\S]*?)\n---\n/.exec(text)?.[1] ?? null;
    const items = front ? [...(/^premises:\n((?:[ \t]+-[^\n]*\n?)*)/m.exec(`${front}\n`)?.[1] ?? "").matchAll(/^[ \t]+-[ \t]*(.*?)[ \t]*$/gm)].map((m) => m[1]) : [];
    const brief = /\b(case brief|published brief|the brief|intake note|scenario)\b|^#{2,3}[ \t]*.*\b(brief|scenario|background|situation)\b/im.test(text);
    if (!items.length) {
      assert.ok(!brief, `${name} has a brief and designates no premises`);
      continue;
    }
    counts[name] = items.length;
    assert.ok(items.length <= 3, `${name}: a short list`);
    const parsed = Q.goalPremises(`## Premises\n\n${items.map((x) => `- ${x}`).join("\n")}\n`);
    assert.equal(parsed.length, items.length, name);
    const numbered = new Set([...text.matchAll(/^(\d+)\. /gm)].map((m) => `Q-${m[1]}`));
    for (const p of parsed) {
      assert.equal(p.bad, undefined, `${name}: ${p.text}`);
      assert.ok(p.scope.entities?.length || p.scope.questions?.length, `${name}: a premise names its scope: ${p.text}`);
      for (const q of p.scope.questions ?? []) assert.ok(numbered.has(q), `${name}: ${q} is not a question of the goal`);
    }
  }
  // Every case goal with a brief, and none of the goals without a case (hello, pelican, analyse-inputs).
  assert.deepEqual(Object.keys(counts).length, 17);
  for (const plain of ["hello.md", "pelican.md", "analyse-inputs.md"]) assert.equal(counts[plain], undefined);
});
