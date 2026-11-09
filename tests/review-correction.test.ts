/**
 * Review and correction (Plan 3, WP4; docs/adr/0015): the attest's strength
 * and its review part by part (B2), the route plan held to its routes and a
 * limiting route reviewed before it stops holding the finish line (B3, A4),
 * an agent's reopen (B4), an interpretation bound to its entry (B13), and a
 * dispute that stays open on the correction of the entry it named (B18).
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import * as P from "../extensions/protocol.ts";
import * as L from "../extensions/leads.ts";
import * as Q from "../extensions/questions.ts";
import { checkLedgerAnswers } from "../scripts/check-answers.ts";
import { finishGate } from "../scripts/finish-gate.ts";
import { A, coverage, covers, ESTABLISHED, F, job, ok, okq, planned, rec, refused, REVIEW, run } from "./negative-bar-fixture.ts";

const HIGH = { ...A, confidence: "high" } as const;
const review = (parts: Array<{ part: string; established: boolean; why: string }> = ESTABLISHED.answer_review.parts as never) => ({ ...ESTABLISHED.answer_review, parts });
const operator: Q.Actor = { kind: "human", role: "operator", person: "tester@lab", enrolled: false, os_user: "tester", host: "lab", via: "cli", identity: "claimed" };

/** A finding under question `q` and an established answer resting on it, recorded by a1 and a0. */
async function answered(c: Awaited<ReturnType<typeof run>>, q: string, answer: Record<string, unknown> = {}) {
  await planned(c.a0, q);
  const f = ok(await rec(c.a0, { kind: "finding", ...F, value: `What question ${q} asks`, source: "the disk", evidence: "a search", refs: ["job:j000001/hits.txt"], answers: [q] })).entry;
  const a = ok(await rec(c.a1, { kind: "answer", section: `question:${q}`, value: `The answer to ${q}`, reasoning: `E-${f.seq} shows it`, result: "established", ...HIGH, ...answer })).entry;
  return { f, a };
}

test("B2: an answer to a question is attested with a strength and its review; what caps it allows only a best candidate, which does not satisfy the finish line", async () => {
  const c = await run();
  const { f, a } = await answered(c, "1");
  refused(await P.attestEntry(c.a2, { seq: a.seq, how: "re-derived it" }), /its attest says how strongly you hold it, strength established or best_candidate/);
  refused(await P.attestEntry(c.a2, { seq: a.seq, how: "re-derived it", strength: "established" }), /give answer_review \{reproduced/);
  refused(await P.attestEntry(c.a2, { seq: a.seq, how: "x", strength: "certain", answer_review: review() }), /strength is established or best_candidate/);
  refused(await P.attestEntry(c.a2, { seq: a.seq, how: "x", strength: "established", answer_review: { ...review(), parts: [] } }), /answer_review\.parts names each part/);
  refused(await P.attestEntry(c.a2, { seq: a.seq, how: "x", strength: "established", answer_review: { ...review(), other_family: { checked: "no" } } }), /other_family is \{checked: true\|false, text\}/);
  // A part the review holds not established caps it.
  refused(await P.attestEntry(c.a2, { seq: a.seq, how: "x", strength: "established", answer_review: review([{ part: "who", established: true, why: "the log says" }, { part: "when", established: false, why: "no clock was checked" }]) }), /can be attested best_candidate only: the review holds "when" not established/);
  // Strength and answer_review belong to answers to questions.
  refused(await P.attestEntry(c.a2, { seq: f.seq, how: "re-derived it", strength: "established" }), /strength is for an answer to a question; #\d+ is a finding/);
  refused(await P.attestEntry(c.a2, { seq: f.seq, how: "re-derived it", answer_review: review() }), /answer_review is for an answer to a question/);
  // Held a best candidate: a critic act, and the question is limited, not answered.
  const bc = await P.attestEntry(c.a2, { seq: a.seq, how: "re-derived the finding; the time is not checked", strength: "best_candidate", answer_review: review([{ part: "who", established: true, why: "the log says" }, { part: "when", established: false, why: "no clock was checked" }]) });
  assert.ok(bc.ok, (bc as { reason?: string }).reason);
  assert.equal((bc as { line: P.LedgerAttestation }).line.strength, "best_candidate");
  assert.match((bc as { note?: string }).note ?? "", /recorded as a best candidate \(the review holds "when" not established/);
  assert.ok(P.verifyAttestationChain(await (await import("node:fs/promises")).readFile(`${c.S}/ledger/attestations.jsonl`, "utf8")).ok, "the strength and the review are inside the chained record");
  const r = await checkLedgerAnswers(c.S, ["1"]);
  assert.equal(r.outcomes["question:1"], "limited", r.lines.join("\n"));
  assert.deepEqual(r.best_candidate, ["question:1"]);
  assert.ok(r.lines.some((l) => /a best candidate, not established \(every review holds #\d+ a best candidate: a2/.test(l)), r.lines.join("\n"));
  assert.ok(!r.defects.some((d) => d.code === "no_critic_act"), "a best candidate is a critic act");
  // A second review that holds it established makes it answered.
  await covers(c.a0, "1");
  const est = await P.attestEntry(c.a3, { seq: a.seq, how: "re-derived both parts, the clock too", ...ESTABLISHED });
  assert.ok(est.ok, (est as { reason?: string }).reason);
  assert.equal((await checkLedgerAnswers(c.S, ["1"])).outcomes["question:1"], "answered");
});

test("B2: a medium confidence, or a route its would_change names that nothing took, caps the attest at best_candidate", async () => {
  const c = await run();
  const med = await answered(c, "3", { confidence: "medium" });
  refused(await P.attestEntry(c.a2, { seq: med.a.seq, how: "x", ...ESTABLISHED }), /can be attested best_candidate only: its confidence is medium/);
  // A planned route nothing examined, named in would_change.
  await planned(c.a0, "4", [{ source: "input:logs/b.log", method: "read the second log" }]);
  const f4 = ok(await rec(c.a0, { kind: "finding", ...F, value: "It started at ten", source: "the disk", evidence: "a search", refs: ["job:j000001/hits.txt"], answers: ["4"] })).entry;
  const a4 = ok(await rec(c.a1, { kind: "answer", section: "question:4", value: "At ten", reasoning: `E-${f4.seq}`, result: "established", ...HIGH, would_change: "input:logs/b.log may show an earlier start" })).entry;
  refused(await P.attestEntry(c.a2, { seq: a4.seq, how: "x", ...ESTABLISHED }), /would_change names input:logs\/b\.log \(read the second log\), a planned route nothing examined/);
  // A lead it names that is not closed resolved, negative or duplicate.
  const lid = okq(await L.openLead(c.a2, { title: "Read the memory image", why: "it may hold the start", answers: ["5"], routes: [{ source: "words: the memory image", method: "read it" }] })).lead.id;
  await planned(c.a0, "5");
  const f5 = ok(await rec(c.a0, { kind: "finding", ...F, value: "Account x", source: "the disk", evidence: "a search", refs: ["job:j000001/hits.txt"], answers: ["5"] })).entry;
  const a5 = ok(await rec(c.a1, { kind: "answer", section: "question:5", value: "x", reasoning: `E-${f5.seq}`, result: "established", ...HIGH, would_change: `what ${lid} finds in memory` })).entry;
  refused(await P.attestEntry(c.a3, { seq: a5.seq, how: "x", ...ESTABLISHED }), new RegExp(`would_change names ${lid}, a route not taken \\(open, unheld\\)`));
  const capped = await P.attestEntry(c.a3, { seq: a5.seq, how: "x", ...ESTABLISHED, strength: "best_candidate" });
  assert.ok(capped.ok);
  assert.deepEqual((capped as { line: P.LedgerAttestation }).line.capped, [`would_change names ${lid}, a route not taken (open, unheld)`], "why it was capped is written by the hub into the record");
});

test("B18: a correction of a disputed entry inherits the dispute until the disputer answers it; the disputer withdraws it on the correction", async () => {
  const c = await run();
  await planned(c.a0, "1");
  const f = ok(await rec(c.a0, { kind: "finding", ...F, value: "Bob logged on", source: "the log", evidence: "line 1", refs: ["job:j000002/hits.txt"], answers: ["1"] })).entry;
  assert.ok((await P.disputeEntry(c.a2, { seq: f.seq, why: "line 1 is another host's" })).ok);
  const fix = ok(await rec(c.a0, { kind: "finding", ...F, value: "Bob logged on at the console", source: "the log", evidence: "line 1 and the host field", refs: ["job:j000002/hits.txt"], answers: ["1"], supersedes: f.seq, because: "the host field says which host" })).entry;
  const inForce = P.disputesInForce(await P.readLedger(c.S), await P.readDisputes(c.S));
  const inherited = inForce.find((d) => d.inherited_from === f.seq);
  assert.ok(inherited, "the dispute stands on the correction");
  assert.equal(inherited!.target, fix.hash);
  // An answer resting on the correction is told the dispute is open.
  refused(await rec(c.a1, { kind: "answer", section: "question:1", value: "Bob", reasoning: `E-${fix.seq}`, result: "established", ...HIGH }), new RegExp(`E-${fix.seq} is disputed by a2: line 1 is another host's \\(raised on E-${f.seq}, which it corrects: the dispute is open until a2 withdraws it\\)`));
  // A lead closed on it does not stand either (the lead register's view).
  const snap = await L.leadsSnapshot(c.S);
  assert.equal(L.entryStands(snap.ledger, fix.seq).ok, false);
  // The disputer cannot attest it while the dispute stands, and a second dispute is the same one.
  refused(await P.attestEntry(c.a2, { seq: fix.seq, how: "re-derived it" }), new RegExp(`you disputed #${f.seq}, which #${fix.seq} corrects`));
  const again = await P.disputeEntry(c.a2, { seq: fix.seq, why: "still another host" });
  assert.ok(again.ok && !(again as { appended: boolean }).appended);
  assert.match((again as { note?: string }).note ?? "", new RegExp(`you disputed #${f.seq}, which #${fix.seq} corrects`));
  // Answered: withdrawn by naming the correction.
  const w = await P.disputeEntry(c.a2, { seq: fix.seq, why: "the host field settles it", withdraw: true });
  assert.ok(w.ok, (w as { reason?: string }).reason);
  assert.equal((w as { line: P.LedgerDispute }).line.seq, f.seq, "the withdrawal names the dispute it ends");
  assert.deepEqual(P.disputesInForce(await P.readLedger(c.S), await P.readDisputes(c.S)), []);
  ok(await rec(c.a1, { kind: "answer", section: "question:1", value: "Bob", reasoning: `E-${fix.seq}`, result: "established", ...HIGH }));
  // A disputed answer, corrected by its author: the dispute stays on the correction.
  const q = (await P.readLedger(c.S)).find((e) => e.kind === "answer" && e.section === "question:1")!;
  assert.ok((await P.disputeEntry(c.a3, { seq: q.seq, why: "the console is not named in the log" })).ok);
  const q2 = ok(await rec(c.a1, { kind: "answer", section: "question:1", value: "Bob, at the console", reasoning: `E-${fix.seq}`, result: "established", ...HIGH, supersedes: q.seq })).entry;
  const r = await checkLedgerAnswers(c.S, ["1"]);
  const d = r.defects.find((x) => x.code === "answer_disputed");
  assert.ok(d, r.lines.join("\n"));
  assert.match(d!.what, new RegExp(`answer #${q2.seq} \\(question:1\\) is disputed by a3: the console is not named in the log \\(raised on #${q.seq}, which it corrects: a correction does not answer a dispute\\)`));
  assert.match(d!.fix, /the disputer reads the correction and withdraws the dispute/);
});

test("B13: an interpretation is bound to its entry: superseded without re-interpreting, or disputed, the job needs re-interpretation", async () => {
  const c = await run();
  await job(c.S, "j000010", "rows.txt", { spec: { kind: "command", scope: "declared", inputs: ["input:disk.E01"], command: "list" }, requester: { agent: "a0" } });
  const lid = await planned(c.a0, "3");
  const attached = await L.attachJob(c.S, "a0", "j000010", lid);
  assert.ok(attached.ok);
  const e = ok(await rec(c.a0, { kind: "finding", ...F, value: "Three files were deleted", source: "the listing", evidence: "rows 1-3", refs: ["job:j000010/rows.txt"], answers: ["3"] })).entry;
  okq(await L.recordInterpretations(c.S, "a0", e.seq, ["j000010"]));
  const snap = async () => L.leadsSnapshot(c.S);
  const mine = async (s: L.LeadsSnapshot) => (await L.awaitingInterpretation(c.S, s.state, s.jobs, s.ledger)).filter((a) => a.job === "j000010");
  let s = await snap();
  assert.deepEqual(await mine(s), []);
  assert.equal(s.state.interpretations.get("j000010")![0].hash, e.hash, "bound to the entry's hash");
  // Corrected without interpreting it again: the interpretation no longer stands.
  const fix = ok(await rec(c.a0, { kind: "finding", ...F, value: "Four files were deleted", source: "the listing", evidence: "rows 1-4", refs: ["job:j000010/rows.txt"], answers: ["3"], supersedes: e.seq, because: "row 4 was missed" })).entry;
  s = await snap();
  const waiting = await mine(s);
  assert.equal(waiting.length, 1);
  assert.equal(waiting[0].reinterpret, true);
  assert.match(waiting[0].why, new RegExp(`its interpretation no longer stands \\(E-${e.seq}: E-${e.seq} was superseded by E-${fix.seq}, which does not interpret it\\)`));
  const gate = await L.leadDefects(c.S, s);
  assert.ok(gate.defects.some((d) => d.code === "uninterpreted_job" && d.job === "j000010"), "a material lead's job waits for it at the finish line");
  // The correction interprets it: it stands again.
  okq(await L.recordInterpretations(c.S, "a0", fix.seq, ["j000010"]));
  s = await snap();
  assert.deepEqual(await mine(s), []);
  // Disputed: needs re-interpretation again.
  assert.ok((await P.disputeEntry(c.a2, { seq: fix.seq, why: "row 4 is a directory" })).ok);
  s = await snap();
  const again = await mine(s);
  assert.equal(again.length, 1);
  assert.match(again[0].why, new RegExp(`E-${fix.seq} is disputed`));
});

test("B4: an agent reopens a closed lead with the revision it read and why; the operator's restrictions and an open duplicate refuse it; disputes stay", async () => {
  const c = await run();
  await planned(c.a0, "1");
  const f = ok(await rec(c.a0, { kind: "finding", ...F, value: "Bob", source: "the log", evidence: "line 1", refs: ["job:j000002/hits.txt"], answers: ["1"] })).entry;
  const lid = okq(await L.openLead(c.a1, { title: "Who logged on", why: "question 1", answers: ["1"], take: true, routes: [{ source: "input:logs/a.log", method: "read it" }], overlap: "verification", overlap_why: "the log, independently of a0's disk search" })).lead.id;
  const closed = okq(await L.closeLead(c.a1, lid, { disposition: "resolved", ref: `E-${f.seq}` })).lead;
  refused(await L.agentReopenLead(c.a2, lid, { why: "the log is another host's" }), /expected_revision is the lead's revision/);
  refused(await L.agentReopenLead(c.a2, lid, { expected_revision: closed.rev - 1, why: "x" }), new RegExp(`${lid} is at revision ${closed.rev}, not ${closed.rev - 1}`));
  refused(await L.agentReopenLead(c.a2, lid, { expected_revision: closed.rev, why: "" }), /why is required/);
  assert.ok((await P.disputeEntry(c.a3, { seq: f.seq, why: "another host's line" })).ok);
  // (The dispute reopened it already; closed again on what stands, then reopened by an agent.)
  await L.reopenOnLedger(c.S);
  const f2 = ok(await rec(c.a0, { kind: "finding", ...F, value: "Bob at the console", source: "the log", evidence: "line 1 host field", refs: ["job:j000002/hits.txt"], answers: ["1"] })).entry;
  okq(await L.claimLead(c.a1, lid, { overlap: "verification", overlap_why: "the log, independently of a0's disk search" }));
  const again = okq(await L.closeLead(c.a1, lid, { disposition: "resolved", ref: `E-${f2.seq}` })).lead;
  const r = await L.agentReopenLead(c.a2, lid, { expected_revision: again.rev, why: "the console login is a service account", take: true });
  const opened = okq(r);
  assert.deepEqual([opened.lead.status, opened.lead.holder, opened.lead.generation], ["active", "a2", again.generation + 1]);
  const snap = await L.leadsSnapshot(c.S);
  const reopen = snap.state.events.filter((e) => e.lead === lid && e.ev === "reopen").at(-1)!;
  assert.deepEqual([reopen.by, reopen.cause, reopen.expected_revision], ["a2", "agent", again.rev]);
  assert.ok(snap.state.leads.get(lid)!.reopened.some((x) => x.cause === "agent"), "history is kept");
  // The operator closed it: the operator's.
  const op = okq(await L.openLead({ sandboxRoot: c.S, agentId: "operator" }, { title: "Directive", why: "the operator's", answers: ["2"], product: "p", acceptance: "a" })).lead.id;
  await planned(c.a0, "2");
  const lim = ok(await rec(c.a0, { kind: "limitation", value: "The second disk is not in the case", source: "inputs", evidence: "inputs.json", reason: "unavailable", answers: ["2"] })).entry;
  okq(await L.closeLead({ sandboxRoot: c.S, agentId: "operator" }, op, { disposition: "deferred", ref: `E-${lim.seq}` }));
  const opView = (await L.leadsSnapshot(c.S)).state.leads.get(op)!;
  refused(await L.agentReopenLead(c.a2, op, { expected_revision: opView.rev, why: "x" }), /was closed by the operator: only the operator reopens it/);
  // needs_operator not yet answered: the operator's to answer.
  const no = okq(await L.openLead(c.a1, { title: "Reach the mail host", why: "question 6", answers: ["6"], take: true, routes: [{ source: "words: the mail host", method: "ask it" }] })).lead.id;
  const noClosed = okq(await L.closeLead(c.a1, no, { disposition: "needs_operator", ref: "allow the mail host so a job can read the account" })).lead;
  refused(await L.agentReopenLead(c.a2, no, { expected_revision: noClosed.rev, why: "x" }), /waits for the operator/);
  // A duplicate of a lead still open is worked there.
  const d1 = okq(await L.openLead(c.a1, { title: "Deleted files", why: "3", answers: ["3"], routes: [{ source: "input:disk.E01", method: "list" }] })).lead.id;
  const d2 = okq(await L.openLead(c.a2, { title: "Deleted files again", why: "3" })).lead.id;
  const dup = okq(await L.closeLead(c.a3, d2, { disposition: "duplicate", ref: d1 })).lead;
  refused(await L.agentReopenLead(c.a3, d2, { expected_revision: dup.rev, why: "x" }), new RegExp(`${d2} is a duplicate of ${d1}, which is still open`));
  // A withdrawn question's lead is not an agent's to bring back.
  const q = okq(await Q.act(c.S, operator, "open", { text: "Was a printer used?", why: "scope check" })).q!;
  const ql = okq(await L.openLead(c.a1, { title: "Printer", why: "q", answers: [q], take: true, proposition: "a printer was used", negation: "no printer was used", routes: [{ source: "input:disk.E01", method: "spool files" }] })).lead.id;
  okq(await Q.act(c.S, operator, "withdraw", { q, why: "not needed" }));
  await Q.reconcile(c.S);
  const wl = (await L.leadsSnapshot(c.S)).state.leads.get(ql)!;
  assert.equal(wl.closed?.disposition, "withdrawn");
  refused(await L.agentReopenLead(c.a2, ql, { expected_revision: wl.rev, why: "x" }), /closed withdrawn with the question it served/);
});

test("B4: a reopen names the disputes in force on what the lead cites and never answers them", async () => {
  const c = await run();
  const { f, a } = await answered(c, "1");
  const lid = okq(await L.openLead(c.a2, { title: "Confirm who", why: "q1", answers: ["1"], take: true })).lead.id;
  okq(await L.closeLead(c.a2, lid, { disposition: "resolved", ref: `E-${f.seq}` }));
  assert.ok((await P.disputeEntry(c.a3, { seq: a.seq, why: "who is not established" })).ok);
  const view = (await L.leadsSnapshot(c.S)).state.leads.get(lid)!;
  const r = okq(await L.agentReopenLead(c.a0, lid, { expected_revision: view.rev, why: "the answer is disputed" }));
  assert.ok((r.disputes ?? []).some((d) => new RegExp(`E-${a.seq} disputed by a3 \\(who is not established\\): a reopen does not answer it`).test(d)), JSON.stringify(r.disputes));
  assert.equal(P.disputesInForce(await P.readLedger(c.S), await P.readDisputes(c.S)).length, 1, "the dispute stands");
});

test("B3/A4: a limiting route stops holding the finish line only once its questions are disposed and another seat holds it no longer material; a reopen or an unreviewed lead with no question keeps it", async () => {
  const c = await run();
  const lid = await planned(c.a0, "3", [{ source: "input:disk.E01", method: "carve the unallocated space" }]);
  const lim = ok(await rec(c.a0, { kind: "limitation", value: "Carving was not possible: the image is encrypted", source: "the disk", evidence: "the header", reason: "failed", answers: ["3"] })).entry;
  okq(await L.closeLead(c.a0, lid, { disposition: "infeasible", ref: `E-${lim.seq}` }));
  const limitedLines = async () => (await finishGate(c.S, null)).limited.filter((l) => l.startsWith(`${lid} `));
  assert.match((await limitedLines())[0] ?? "", new RegExp(`${lid} was closed infeasible \\(E-${lim.seq}\\): its question question:3 is not disposed under the bar`));
  // Another route answers question 3.
  const f = ok(await rec(c.a1, { kind: "finding", ...F, value: "Two files were deleted", source: "the listing", evidence: "rows", refs: ["job:j000001/hits.txt"], answers: ["3"] })).entry;
  const a = ok(await rec(c.a1, { kind: "answer", section: "question:3", value: "Two files", reasoning: `E-${f.seq}`, result: "established", ...HIGH })).entry;
  assert.ok((await P.attestEntry(c.a2, { seq: a.seq, how: "re-derived the listing", ...ESTABLISHED })).ok);
  const run3 = { total: 1, passed: 1, checks: [{ cmd: "check-answers", ok: true, answers: { outcomes: { "question:3": "answered" } } }] };
  const gate = await finishGate(c.S, run3 as never);
  assert.match(gate.limited.find((l) => l.startsWith(`${lid} `)) ?? "", /no other seat has reviewed whether its limitation is still material/);
  // Its closer does not review it; another seat does.
  refused(await L.routeReview(c.a0, lid, { material: false, why: "x" }), /you closed .*: its route is reviewed by another seat/);
  refused(await L.routeReview(c.a2, lid, { why: "x" }), /material is true or false/);
  okq(await L.routeReview(c.a2, lid, { material: true, why: "carving could still find a third file" }));
  assert.match((await finishGate(c.S, run3 as never)).limited.find((l) => l.startsWith(`${lid} `)) ?? "", /a2 holds its limitation still material/);
  // Reviewed for these answers already (the c10 pilot's stampede): another seat's review is answered quietly, nothing recorded;
  // a second, independent review says why it adds something.
  const quiet = okq(await L.routeReview(c.a3, lid, { material: false, why: `E-${a.seq} settles question 3` }));
  assert.deepEqual(quiet.deferred?.by, ["a2"]);
  okq(await L.routeReview(c.a3, lid, { material: false, why: `E-${a.seq} settles question 3 from the file system; carving adds nothing it asks`, second_review_why: `a2 did not weigh E-${a.seq}, which answers question 3 without the carve` }));
  assert.equal((await finishGate(c.S, run3 as never)).limited.filter((l) => l.startsWith(`${lid} `)).length, 0, "no longer limiting");
  // Reopened and closed again: the review was of the earlier close.
  const view = (await L.leadsSnapshot(c.S)).state.leads.get(lid)!;
  okq(await L.agentReopenLead(c.a1, lid, { expected_revision: view.rev, why: "a key turned up", take: true }));
  okq(await L.closeLead(c.a1, lid, { disposition: "infeasible", ref: `E-${lim.seq}` }));
  assert.equal((await finishGate(c.S, run3 as never)).limited.filter((l) => l.startsWith(`${lid} `)).length, 1, "a new close needs a new review");
  // A lead that names no question is never vacuously disposed.
  const bare = okq(await L.openLead(c.a2, { title: "Check the backup tape", why: "background", take: true })).lead.id;
  okq(await L.closeLead(c.a2, bare, { disposition: "deferred", ref: `E-${lim.seq}` }));
  assert.match((await finishGate(c.S, run3 as never)).limited.find((l) => l.startsWith(`${bare} `)) ?? "", /it names no question, and no other seat has reviewed/);
  okq(await L.routeReview(c.a3, bare, { material: false, why: "nothing asked depends on the tape" }));
  assert.equal((await finishGate(c.S, run3 as never)).limited.filter((l) => l.startsWith(`${bare} `)).length, 0);
});

test("the negative's review is unchanged by strengths: a reviewed negative answers without a strength", async () => {
  const c = await run();
  await planned(c.a0, "2");
  const absence = ok(await rec(c.a0, { kind: "absence", value: "a remote tool", source: "inputs/disk.E01", evidence: "a search", refs: ["job:j000001/hits.txt"], answers: ["2"] })).entry;
  const cov = ok(await rec(c.a0, coverage("2", ["input:disk.E01"], [`E-${absence.seq}`]))).entry;
  const ans = ok(await rec(c.a1, { kind: "answer", section: "question:2", value: "No evidence of a remote tool was found on the disk", reasoning: `E-${cov.seq}`, ...A, result: "bounded_negative" })).entry;
  refused(await P.attestEntry(c.a2, { seq: ans.seq, how: "x", strength: "established", answer_review: review() }), /answer_review is for an answer to a question; #\d+ is a negative/);
  assert.ok((await P.attestEntry(c.a2, { seq: ans.seq, how: "ran it again", review: REVIEW })).ok);
});

test("A4/B18: a contrary entry corrected or disputed after an answer weighed it takes the answer down, and a summary citing its question with it, though the answer was never recorded again", async () => {
  const c = await run();
  await planned(c.a0, "1");
  const f = ok(await rec(c.a0, { kind: "finding", ...F, value: "Bob logged on", source: "the log", evidence: "line 1", refs: ["job:j000002/hits.txt"], answers: ["1"] })).entry;
  const x = ok(await rec(c.a2, { kind: "finding", ...F, value: "The session on line 1 was a service account", source: "the log", evidence: "line 1's logon type", refs: ["job:j000002/hits.txt"], answers: ["1"] })).entry;
  const a = ok(await rec(c.a1, { kind: "answer", section: "question:1", value: "Bob", reasoning: `E-${f.seq} shows it; E-${x.seq} says a service account, but the logon type is interactive`, contrary: [x.seq], result: "established", ...HIGH })).entry;
  const sum = ok(await rec(c.a3, { kind: "answer", section: "summary", value: "Bob logged on (Q-1).", reasoning: "Q-1 says who." })).entry;
  const problems = async () => P.answerProblems(await P.readLedger(c.S), await P.readDisputes(c.S));
  assert.equal((await problems()).size, 0);
  // The contrary entry is corrected materially: the weighing no longer stands.
  const x2 = ok(await rec(c.a2, { kind: "finding", ...F, value: "The session on line 1 was Bob's, by his own password, remotely", source: "the log", evidence: "line 1's logon type and source address", refs: ["job:j000002/hits.txt"], answers: ["1"], supersedes: x.seq, because: "the logon type was read from the wrong column" })).entry;
  let p = await problems();
  assert.ok(p.get(a.seq)?.some((m) => new RegExp(`weighs E-${x.seq} as contrary evidence, superseded by #${x2.seq}, and does not weigh the correction`).test(m)), JSON.stringify([...p]));
  assert.ok(p.get(sum.seq)?.some((m) => new RegExp(`it cites Q-1 \\(question:1\\), whose answer E-${a.seq} no longer stands on its own support`).test(m)), JSON.stringify([...p]));
  const gate = P.ledgerGate({ entries: await P.readLedger(c.S), attestations: await P.readAttestations(c.S), disputes: await P.readDisputes(c.S), sections: ["question:1", "summary"] });
  assert.ok(gate.open.some((d) => d.section === "question:1"), JSON.stringify(gate.open));
  // Re-weighed: the answer recorded again with the correction as its contrary evidence stands.
  const a2 = ok(await rec(c.a1, { kind: "answer", section: "question:1", value: "Bob, remotely", reasoning: `E-${f.seq} shows it; E-${x2.seq} places it remotely`, contrary: [x2.seq], result: "established", ...HIGH, supersedes: a.seq })).entry;
  p = await problems();
  assert.equal(p.has(a2.seq), false, JSON.stringify([...p]));
  // A dispute of the contrary entry is a change of it too, until the answer qualifies it.
  assert.ok((await P.disputeEntry(c.a0, { seq: x2.seq, why: "the source address is the jump host" })).ok);
  p = await problems();
  assert.ok(p.get(a2.seq)?.some((m) => new RegExp(`weighs E-${x2.seq} as contrary evidence, disputed by a0`).test(m)), JSON.stringify([...p]));
});
