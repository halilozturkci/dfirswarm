/**
 * A question's premise, tested first (docs/adr/0011, "What a question
 * presumes"): what a question takes as happened, on the register (the goal's
 * Presumptions section, the asker's --presumes on an open or an amendment,
 * an agent's with question_open or with a clarification while nobody has
 * said so), and a person's question's framing; the review's premise test,
 * answer_review.premise_tested {outcome, refs}, against the fixed rival "the
 * question's premise is not supported"; an established attest of an
 * established answer without it recorded best_candidate with how to fix it;
 * a partial answer without it warned (premise_untested) at the record, the
 * attest and finish status, never held; the answer's own premise_tested; the
 * views, the report, the CLI and the console; and an entry without the new
 * fields hashing as it always did.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import { test } from "node:test";
import * as FIN from "../extensions/finish.ts";
import * as L from "../extensions/leads.ts";
import * as P from "../extensions/protocol.ts";
import * as Q from "../extensions/questions.ts";
import { checkLedgerAnswers } from "../scripts/check-answers.ts";
import { renderReportBodyMarkdown } from "../scripts/report-body.ts";
import { questionArgv } from "../scripts/ui/questions.ts";
import { A, covers, coversDiskAndLog, ESTABLISHED, F, GOAL, ok, planned, rec, refused, run } from "./negative-bar-fixture.ts";

const ROOT = resolve(import.meta.dirname, "..");
const HIGH = { ...A, confidence: "high" } as const;
const OPERATOR: Q.Actor = { kind: "human", role: "operator", person: "ops@lab", enrolled: false, os_user: "ops", host: "lab", via: "cli", identity: "claimed" };
const ANALYST: Q.Actor = { kind: "human", role: "analyst", person: "ana", name: "ANA", enrolled: true, os_user: "ana", host: "lab", via: "cli", identity: "claimed" };

/** The negative bar's goal, its fifth question presuming a tool was run (docs/adr/0011, "What a question presumes"). */
const PRESUMED = GOAL.replace("## Definition of done", "## Presumptions\n\n- 5: A remote tool was run on the host by an account.\n- 9: a question the goal does not have\n- words that name no question\n\n## Definition of done");
/** A premise test resting on the disk's job output. */
const TESTED = { outcome: "the service log shows the tool's service started twice under one account", refs: ["job:j000001/hits.txt"] };

const act = async (S: string, who: Q.Actor, ev: Q.ActKind, input: Q.ActInput) => {
  const r = await Q.act(S, who, ev, input);
  assert.ok(r.ok, (r as { reason?: string }).reason);
  return r as Q.ActResult;
};
const review = (o: Record<string, unknown> = {}) => ({ ...ESTABLISHED, answer_review: { ...ESTABLISHED.answer_review, ...o } });

test("what a question presumes: the goal's Presumptions section, the asker's word on an open or an amendment, an agent's with question_open or once with a clarification, a person's question's framing; never over the asker's word", async () => {
  const c = await run({ goal: PRESUMED });
  await Q.seedRegister(c.S);
  // The goal's section: seeded on its question, verbatim; a line for a question the goal lacks, or naming none, seeds nothing.
  assert.deepEqual(Q.goalPresumes(PRESUMED).map((x) => [x.section, x.text, Boolean(x.bad)]), [["5", "A remote tool was run on the host by an account.", false], ["9", "a question the goal does not have", false], ["", "words that name no question", true]]);
  let snap = await Q.questionsSnapshot(c.S);
  assert.equal(snap.bySection.get("5")?.presumes?.text, "A remote tool was run on the host by an account.");
  assert.equal(snap.bySection.get("5")?.presumes?.via, "open");
  assert.equal(snap.bySection.get("1")?.presumes, null, "a question the section does not name presumes nothing");
  assert.equal(Q.questionPresumption(snap.bySection.get("1")!, null), null, "a goal's question without presumes is not framed by the register");
  // An agent records what a goal question presumes with its clarification, once; the asker's word stands over it.
  const clar = await Q.questionAsk(c.a0, "Q-3", "which deletions are meant: files, or records in a database?", "Something was deleted from the host.");
  assert.equal(clar.ok, true, JSON.stringify(clar));
  snap = await Q.questionsSnapshot(c.S);
  assert.deepEqual([snap.bySection.get("3")?.presumes?.text, snap.bySection.get("3")?.presumes?.via, snap.bySection.get("3")?.presumes?.by], ["Something was deleted from the host.", "clarify", "a0"]);
  refused(await Q.questionAsk(c.a1, "Q-5", "is it the service's account or the user's?", "A tool was installed."), /Q-5 presumes already, as the goal recorded it: "A remote tool was run on the host by an account\."\. The recorded word stands/);
  // The asker's word on an open, and on an amendment against the revision read.
  const opened = await act(c.S, OPERATOR, "open", { text: "When did the tool first connect out?", why: "the timeline", presumes: "The tool connected out." });
  const q7 = (await Q.questionsSnapshot(c.S)).state.questions.get(opened.q!)!;
  assert.equal(q7.presumes?.text, "The tool connected out.");
  await act(c.S, OPERATOR, "amend", { q: opened.q, expected_rev: 1, presumes: "The tool connected out at least once." });
  const q7b = (await Q.questionsSnapshot(c.S)).state.questions.get(opened.q!)!;
  assert.deepEqual([q7b.presumes?.text, q7b.presumes?.via, q7b.rev], ["The tool connected out at least once.", "amend", 1], "presumes alone makes no new revision");
  refused(await Q.act(c.S, OPERATOR, "priority", { q: opened.q, priority: "urgent", reason: "r", presumes: "x" }), /presumes is said when a question is opened, amended, or \(by an agent\) with a clarification/);
  refused(await Q.act(c.S, OPERATOR, "open", { text: "t?", why: "w", presumes: "x".repeat(Q.QUESTION_PRESUMES_MAX + 1) }), /presumes is over 2000 characters/);
  // An agent's question_open with presumes.
  const agentQ = await Q.questionOpen(c.a2, { text: "Which account created the service?", why: "attribution", materiality: "material", objective: undefined, parent: "Q-5", presumes: "An account created the service." });
  assert.equal(agentQ.ok, true, JSON.stringify(agentQ));
  // A person's question is framed by the register: the proposition its first lead states, with its negation; its own words until one does.
  const asked = await act(c.S, ANALYST, "open", { text: "Did the tool reach the file server?", why: "scope of the breach", parent: "Q-2" });
  let v = Q.questionViews(await Q.viewContext(c.S)).find((x) => x.id === asked.q)!;
  assert.deepEqual([v.presumption?.source, v.presumption?.text, v.presumption?.lead], ["framing", "Did the tool reach the file server?", undefined]);
  const framed = await L.openLead(c.a1, { title: "test the reach", why: "asked", answers: [asked.q!], take: true, proposition: "The tool reached the file server.", negation: "The tool never reached the file server.", routes: [{ source: "input:logs/a.log", method: "read the log" }] });
  assert.ok(framed.ok, (framed as { reason?: string }).reason);
  v = Q.questionViews(await Q.viewContext(c.S)).find((x) => x.id === asked.q)!;
  assert.deepEqual([v.presumption?.text, v.presumption?.negation, v.presumption?.lead], ["The tool reached the file server.", "The tool never reached the file server.", (framed as { lead: { id: string } }).lead.id]);
  // Where it shows: the agents' list, questions.md, the question's post.
  const list = (await Q.questionsView(c.a0, { view: "list" })).questions as Array<Record<string, unknown>>;
  assert.equal(list.find((x) => x.id === "Q-5")?.presumes, "A remote tool was run on the host by an account.");
  const md = Q.renderQuestionsMd(await Q.viewContext(c.S));
  assert.match(md, /- Presumes "A remote tool was run on the host by an account\." \(presumed by the goal\): its answer tests that premise first, against "the question's premise is not supported"/);
  const post = Q.questionPostBody(q7b, await Q.questionsSnapshot(c.S), { offerTo: null, first: false, hypotheses: [] });
  assert.match(post, /Presumes: "The tool connected out at least once\."\. Test whether it happened before answering/);
  // The clarification's operator request carries it.
  const R = await import("../extensions/requests.ts");
  const req = [...(await R.requestsSnapshot(c.S)).requests.values()].find((x) => x.kind === "clarification" && x.questions?.includes("Q-3"));
  assert.equal((req?.line as { presumes?: string } | undefined)?.presumes, "Something was deleted from the host.");
});

test("a chain from before presumes folds none, and an answer or a review without a premise test hashes as it always did", async () => {
  const c = await run();
  const snap = await Q.questionsSnapshot(c.S);
  assert.ok([...snap.state.questions.values()].every((q) => q.presumes === null));
  const entry = { v: 4, seq: 7, kind: "answer", value: "alice", section: "question:1", reasoning: "E-1", result: "established", confidence: "high", by: "a1", authors: ["a1"], at: "2026-09-30T00:00:00Z" } as P.LedgerEntry;
  const h = P.ledgerHash(entry, "genesis");
  assert.notEqual(P.ledgerHash({ ...entry, premise_tested: TESTED }, "genesis"), h, "in the core when present");
  assert.equal(P.ledgerHash({ ...entry, premise_tested: undefined }, "genesis"), h);
  const att = { v: 2, act: "attest", seq: 7, target: h, by: "a2", at: "2026-09-30T00:00:00Z", how: "re-derived", strength: "established", answer_review: ESTABLISHED.answer_review } as unknown as P.LedgerAttestation;
  assert.equal(P.attestationHash({ ...att, answer_review: { ...ESTABLISHED.answer_review } as unknown as P.AnswerReview }, "genesis"), P.attestationHash(att, "genesis"));
  assert.notEqual(P.attestationHash({ ...att, answer_review: { ...ESTABLISHED.answer_review, premise_tested: TESTED } as unknown as P.AnswerReview }, "genesis"), P.attestationHash(att, "genesis"));
});

test("the review tests the premise: on a question that presumes an event, an established attest of an established answer without it is recorded best_candidate with how to fix it; with it, established; on a question that presumes nothing, nothing changes", async () => {
  const c = await run({ goal: PRESUMED });
  await Q.seedRegister(c.S);
  const lead = await planned(c.a0, "5");
  const f = ok(await rec(c.a0, { kind: "finding", ...F, value: "the tool's service ran as svc-backup", source: "the disk", evidence: "a key", refs: ["job:j000001/hits.txt"], answers: ["5"] })).entry.seq;
  const a = ok(await rec(c.a1, { kind: "answer", section: "question:5", value: "svc-backup", reasoning: `E-${f}`, ...HIGH, result: "established" })).entry;
  assert.ok((await L.closeLead(c.a0, lead, { disposition: "resolved", ref: `E-${f}` })).ok);
  // Its shape: an outcome and at least one ref; never the answer under review, never an entry the ledger lacks.
  refused(await P.attestEntry(c.a2, { seq: a.seq, how: "re-read the key", ...review({ premise_tested: { outcome: "it ran" } }) }), /answer_review\.premise_tested\.refs names the observation or the job the outcome rests on/);
  refused(await P.attestEntry(c.a2, { seq: a.seq, how: "re-read the key", ...review({ premise_tested: { outcome: "it ran", refs: [`E-${a.seq}`] } }) }), /names E-\d+, the answer under review: a premise test rests on what the test read or showed/);
  refused(await P.attestEntry(c.a2, { seq: a.seq, how: "re-read the key", ...review({ premise_tested: { outcome: "it ran", refs: ["E-999"] } }) }), /premise_tested\.refs names E-999: there is no entry #999/);
  // Without it: recorded best_candidate, capped, the reply saying how to fix it.
  const capped = await P.attestEntry(c.a2, { seq: a.seq, how: "re-read the key", ...review() });
  assert.ok(capped.ok && capped.line, JSON.stringify(capped));
  assert.equal(capped.line!.strength, "best_candidate");
  assert.ok(capped.line!.capped?.some((x) => /question:5 presumes "A remote tool was run on the host by an account\." \(presumed by the goal\), and the review does not test that premise/.test(x)), JSON.stringify(capped.line!.capped));
  assert.match(capped.note ?? "", /premise_tested \{outcome \(what the test showed of whether it happened\), refs .*\}, which a review gives as answer_review\.premise_tested/);
  assert.match(capped.note ?? "", /If the evidence does not support it, the answer is premise_not_supported/);
  assert.match(capped.note ?? "", /A clue that fits the question's frame is a candidate to test against that rival, not an answer/);
  assert.ok((await FIN.readiness(c.S)).items.some((x) => /question:5 is a best candidate/.test(x)), "held as a best candidate, as any capped claim is");
  // A placeholder outcome caps it the same way.
  const placeholder = await P.attestEntry(c.a3, { seq: a.seq, how: "re-read the key", ...review({ premise_tested: { outcome: "n/a", refs: ["job:j000001/hits.txt"] } }) });
  assert.equal(placeholder.ok && placeholder.line?.strength, "best_candidate");
  assert.ok(placeholder.ok && placeholder.line?.capped?.some((x) => /premise test says nothing a reader can weigh/.test(x)));
  // With the test: established; the seat's later review is its review, and the question is established.
  await covers(c.a0, "5");
  const tested = await P.attestEntry(c.a2, { seq: a.seq, how: "re-read the key and the service log", ...review({ premise_tested: TESTED }) });
  assert.ok(tested.ok && tested.line?.strength === "established" && !tested.line.capped, JSON.stringify(tested));
  assert.match(P.answerReviewWords(tested.line!.answer_review!), /the premise tested against "the question's premise is not supported": the service log shows the tool's service started twice under one account \(job:j000001\/hits\.txt\)/);
  const r = await checkLedgerAnswers(c.S, ["5"]);
  assert.equal(r.dispositions["question:5"], "established");
  // A question that presumes nothing: an established review without the test is established.
  const lead1 = await planned(c.a0, "1");
  const f1 = ok(await rec(c.a0, { kind: "finding", ...F, value: "alice logged on", source: "a log", evidence: "line 1", refs: ["job:j000002/hits.txt"], answers: ["1"] })).entry.seq;
  const a1 = ok(await rec(c.a1, { kind: "answer", section: "question:1", value: "alice", reasoning: `E-${f1}`, ...HIGH, result: "established" })).entry;
  assert.ok((await L.closeLead(c.a0, lead1, { disposition: "resolved", ref: `E-${f1}` })).ok);
  await coversDiskAndLog(c.a0, "1");
  const plain = await P.attestEntry(c.a2, { seq: a1.seq, how: "re-read line 1", ...review() });
  assert.ok(plain.ok && plain.line?.strength === "established" && !plain.line.capped, JSON.stringify(plain));
});

test("a partial answer whose premise nothing tests is warned (premise_untested) at its record, the attest and finish status, never held; the answer's own premise test, or a review's, answers it", async () => {
  const c = await run({ goal: PRESUMED });
  await Q.seedRegister(c.S);
  const lead = await planned(c.a0, "5");
  const f = ok(await rec(c.a0, { kind: "finding", ...F, value: "a service entry names an account", source: "the disk", evidence: "a key", refs: ["job:j000001/hits.txt"], answers: ["5"] })).entry.seq;
  const lim = ok(await rec(c.a0, { kind: "limitation", value: "The service log was rotated away", source: "the disk", evidence: "its absence", reason: "unavailable", answers: ["5"] })).entry.seq;
  const parts = [{ id: "acct", part: "which account", status: "established", refs: [`E-${f}`] }, { id: "when", part: "when it ran", status: "open", open_by: `E-${lim}` }];
  const a = ok(await rec(c.a1, { kind: "answer", section: "question:5", value: "the service entry names svc-backup; when it ran is open", reasoning: `E-${f}; E-${lim}`, ...A, limitations: [lim], result: "partial", parts }));
  assert.deepEqual(a.warned, ["premise_untested"], "said in the record's reply");
  assert.match(a.warnings?.[0] ?? "", /answer #\d+ \(question:5\) is partial on a question that presumes "A remote tool was run on the host by an account\." \(presumed by the goal\), and neither it nor a review of it tests that premise/);
  assert.match(a.warnings?.[0] ?? "", /record it again with supersedes=\d+ and premise_tested \{outcome, refs\}/);
  assert.ok((await L.closeLead(c.a0, lead, { disposition: "resolved", ref: `E-${f}` })).ok);
  // A review without the test: recorded as given (partial is a disposition), and warned in its reply.
  const att = await P.attestEntry(c.a2, { seq: a.entry.seq, how: "re-read the key", ...review({ parts: [{ id: "acct", part: "which account", established: true, why: "the key" }, { id: "when", part: "when it ran", established: false, why: "no log" }] }) });
  assert.ok(att.ok && att.line, JSON.stringify(att));
  assert.equal(att.line!.capped, undefined, "nothing capped on a partial answer");
  assert.ok((att as P.WarningsDelivered).warned?.includes("premise_untested"), JSON.stringify(att));
  // Finish status says it; readiness is not held on it; the answers check disposes it partial.
  const ready = await FIN.readiness(c.S);
  assert.ok(ready.warned.some((w) => w.code === "premise_untested" && w.section === "question:5"));
  assert.ok(!ready.items.some((x) => /question:5/.test(x)), "a warning never holds");
  let r = await checkLedgerAnswers(c.S, ["5"]);
  assert.equal(r.dispositions["question:5"], "partial");
  assert.ok(r.warnings.some((x) => /premise_untested|neither it nor a review of it tests that premise/.test(x)));
  // The answer's own test answers it: recorded again with premise_tested, its entries citations.
  const again = ok(await rec(c.a1, { kind: "answer", section: "question:5", value: "the service entry names svc-backup; when it ran is open", reasoning: `E-${f}; E-${lim}`, ...A, limitations: [lim], result: "partial", parts, premise_tested: { outcome: "the service entry shows the tool installed and started", refs: [`E-${f}`, "job:j000001/hits.txt"] }, supersedes: a.entry.seq }));
  assert.equal(again.warned, undefined, JSON.stringify(again.warnings));
  assert.deepEqual(again.entry.premise_tested, { outcome: "the service entry shows the tool installed and started", refs: [`E-${f}`, "job:j000001/hits.txt"] });
  assert.ok(again.entry.support?.some((x) => x.seq === f));
  r = await checkLedgerAnswers(c.S, ["5"]);
  assert.ok(!r.warnings.some((x) => /tests that premise/.test(x)), r.warnings.join("\n"));
  // Its shape is held where it is recorded.
  refused(await rec(c.a1, { kind: "answer", section: "question:5", value: "v", reasoning: `E-${f}`, ...A, limitations: [lim], result: "partial", parts, premise_tested: { refs: [`E-${f}`] }, supersedes: again.entry.seq }), /premise_tested\.outcome is required/);
  refused(await rec(c.a1, { kind: "answer", section: "question:5", value: "v", reasoning: `E-${f}`, ...A, limitations: [lim], result: "partial", parts, premise_tested: { outcome: "o", refs: ["job:j999999/x"] }, supersedes: again.entry.seq }), /premise_tested\.refs:/);
  refused(await rec(c.a0, { kind: "finding", ...F, value: "x", source: "s", evidence: "e", refs: ["job:j000001/hits.txt"], answers: ["5"], premise_tested: TESTED }), /premise_tested/);
  // A review's test answers it too, on an answer without its own.
  const lead2 = await planned(c.a0, "3");
  const f2 = ok(await rec(c.a0, { kind: "finding", ...F, value: "notes.txt deleted", source: "the disk", evidence: "a record", refs: ["job:j000001/hits.txt"], answers: ["3"] })).entry.seq;
  const lim2 = ok(await rec(c.a0, { kind: "limitation", value: "no other volume", source: "the disk", evidence: "the table", reason: "unavailable", answers: ["3"] })).entry.seq;
  // Question 3 presumes nothing yet: no warning.
  const p3 = ok(await rec(c.a1, { kind: "answer", section: "question:3", value: "notes.txt; other volumes open", reasoning: `E-${f2}; E-${lim2}`, ...A, limitations: [lim2], result: "partial", parts: [{ id: "what", part: "what was deleted", status: "established", refs: [`E-${f2}`] }, { id: "rest", part: "on the other volumes", status: "open", open_by: `E-${lim2}` }] }));
  assert.equal(p3.warned, undefined);
  assert.ok((await L.closeLead(c.a0, lead2, { disposition: "resolved", ref: `E-${f2}` })).ok);
  // An agent records what it presumes (a clarification): the same answer is warned now, and a review's test answers it.
  assert.equal((await Q.questionAsk(c.a2, "Q-3", "files only, or records too?", "Something was deleted from the host.")).ok, true);
  r = await checkLedgerAnswers(c.S, ["3"]);
  assert.ok(r.warnings.some((x) => /\(question:3\) is partial on a question that presumes "Something was deleted from the host\." \(presumed by a2\)/.test(x)), r.warnings.join("\n"));
  const withTest = await P.attestEntry(c.a3, { seq: p3.entry.seq, how: "re-read the record", ...review({ parts: [{ id: "what", part: "what was deleted", established: true, why: "the record" }, { id: "rest", part: "on the other volumes", established: false, why: "no other volume" }], premise_tested: { outcome: "the record shows a deletion", refs: [`E-${f2}`] } }) });
  assert.ok(withTest.ok && withTest.line, JSON.stringify(withTest));
  assert.ok(!(withTest as P.WarningsDelivered).warned?.includes("premise_untested"));
  r = await checkLedgerAnswers(c.S, ["3"]);
  assert.ok(!r.warnings.some((x) => /\(question:3\).*tests that premise/.test(x)), r.warnings.join("\n"));
});

test("an answer that tests the premise and finds it unsupported records premise_not_supported, and it is disposed; the report and the console show the presumption and each test", async () => {
  const c = await run({ goal: PRESUMED });
  await Q.seedRegister(c.S);
  const lead = await planned(c.a0, "5");
  const f = ok(await rec(c.a0, { kind: "finding", ...F, value: "the service list holds no remote tool, and its installer was cancelled before it ran", source: "the disk", evidence: "the services key and the installer log", refs: ["job:j000001/hits.txt"], answers: ["5"] })).entry.seq;
  const a = ok(await rec(c.a1, { kind: "answer", section: "question:5", value: "The question's premise is not supported: no remote tool ran on the host", reasoning: `E-${f}`, ...HIGH, result: "premise_not_supported", premise_tested: { outcome: "no service of the tool exists, and the installer log shows the install cancelled", refs: [`E-${f}`] } }));
  assert.equal(a.warned, undefined);
  assert.ok((await L.closeLead(c.a0, lead, { disposition: "resolved", ref: `E-${f}` })).ok);
  const att = await P.attestEntry(c.a2, { seq: a.entry.seq, how: "re-read the services key and the installer log", ...review({ premise_tested: { outcome: "the services key holds no such service", refs: ["job:j000001/hits.txt"] } }) });
  assert.ok(att.ok && att.line, JSON.stringify(att));
  const r = await checkLedgerAnswers(c.S, ["5"]);
  assert.equal(r.dispositions["question:5"], "premise_not_supported");
  assert.deepEqual(r.defects.filter((d) => d.section === "question:5"), []);
  // The report: the presumption in the chain, each test on the answer.
  const md = await renderReportBodyMarkdown(c.S);
  assert.match(md, /\*\*Presumes:\*\* "A remote tool was run on the host by an account\." \(presumed by the goal\): its answer tests that premise first/);
  assert.match(md, /\*\*Premise tested\*\*: the question presumes "A remote tool was run on the host by an account\." \(presumed by the goal\)\. by the answer \(a1\), against "the question's premise is not supported": no service of the tool exists, and the installer log shows the install cancelled \(E-\d+\); by a2's review, against "the question's premise is not supported": the services key holds no such service \(`job:j000001\/hits\.txt`\)\./);
  // The console's view.
  const v = Q.questionViews(await Q.viewContext(c.S)).find((x) => x.section === "5")!;
  assert.deepEqual(v.answer?.premise_tests?.map((t) => [t.by, t.review]), [["a1", false], ["a2", true]]);
  assert.equal(v.presumption?.text, "A remote tool was run on the host by an account.");
  // A presumed question whose answer is established with no test says so in the report.
  const c2 = await run({ goal: PRESUMED });
  await Q.seedRegister(c2.S);
  const l2 = await planned(c2.a0, "5");
  const f2 = ok(await rec(c2.a0, { kind: "finding", ...F, value: "svc-backup ran it", source: "the disk", evidence: "a key", refs: ["job:j000001/hits.txt"], answers: ["5"] })).entry.seq;
  ok(await rec(c2.a1, { kind: "answer", section: "question:5", value: "svc-backup", reasoning: `E-${f2}`, ...HIGH, result: "established" }));
  assert.ok((await L.closeLead(c2.a0, l2, { disposition: "resolved", ref: `E-${f2}` })).ok);
  assert.match(await renderReportBodyMarkdown(c2.S), /No test of that premise is on the record: neither the answer nor a review of it tests whether it happened\./);
});

test("the operator's --presumes, from the CLI and the console: add and amend say it, show reads it", async () => {
  const c = await run();
  const cli = (...args: string[]) => spawnSync("node", ["--experimental-strip-types", "--no-warnings", resolve(ROOT, "scripts", "questions-cli.ts"), ...args], { encoding: "utf8", env: { ...process.env, SWARM_RUNS_DIR: resolve(c.S, "..") } });
  const add = cli("add", c.S, "--text", "Which account ran the backup job?", "--why", "attribution", "--presumes", "A backup job ran.");
  assert.equal(add.status, 0, add.stderr + add.stdout);
  const q = (JSON.parse(add.stdout.trim().split("\n")[0]!) as { q: string }).q;
  const show = cli("show", c.S, q);
  assert.match(show.stdout, /presumes "A backup job ran\." \(presumed by .*\): its answer tests that premise first/);
  const amend = cli("amend", c.S, q, "--expect-rev", "1", "--presumes", "A backup job ran at least once.");
  assert.equal(amend.status, 0, amend.stderr + amend.stdout);
  assert.equal((await Q.questionsSnapshot(c.S)).state.questions.get(q)?.presumes?.text, "A backup job ran at least once.");
  // The console's form sends it as the CLI takes it.
  assert.deepEqual(questionArgv({ action: "add", text: "t?", why: "w", presumes: "It happened." }).argv.slice(-2), ["--presumes", "It happened."]);
  assert.ok(questionArgv({ action: "amend", q: "Q-7", expected_rev: 1, presumes: "It happened." }).argv.join(" ").includes("--presumes It happened."));
});

test("replay --presumes asks a run from before presumptions what the premise rule would have said: each question named presumes its event in the copy, the run untouched", async () => {
  const { mkdtemp, rm } = await import("node:fs/promises");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const { replay, resolveRun } = await import("../scripts/replay.ts");
  const scratch = await mkdtemp(join(tmpdir(), "replay-presumes-"));
  try {
    const here = { label: "this checkout", harness: ROOT, how: "this checkout", commit: null };
    const dir = join(ROOT, "tests", "fixtures", "contract", "partial-every-policy", "run");
    const r = await replay({ run: await resolveRun(dir), targets: [here], presumes: ["1", "Q-2", "Q-9"], scratch });
    assert.equal(r.unchanged, true, "the run's registers are unchanged");
    assert.deepEqual(r.presumed?.questions, ["1", "Q-2", "Q-9"]);
    assert.deepEqual(r.presumed?.notes, ["Q-9 is not in the run's question register: not presumed"]);
    const p = r.evaluations[0]!.projection!;
    assert.ok(p, r.evaluations[0]!.error ?? "");
    // Question 1's partial answer: its review tests no premise, so it is warned; nothing holds on it.
    assert.ok(p.questions.find((q) => q.section === "question:1")?.warnings.includes("premise_untested"));
    assert.equal(p.readiness?.ready, true);
    // Question 2's established attest: the review rule would have capped it for the premise (and, the history predating the source-first review, for its discriminator); its recorded strength stays the run's.
    assert.deepEqual(p.review_caps?.capped.map((c) => `${c.section} ${c.codes.join(" ")}`), ["question:2 no_discriminator premise_untested"]);
    assert.equal(p.questions.find((q) => q.section === "question:2")?.gate?.disposition, "established");
  } finally {
    await rm(scratch, { recursive: true, force: true });
  }
});
