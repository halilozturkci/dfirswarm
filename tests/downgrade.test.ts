/**
 * A downgrade needs counter-evidence (docs/adr/0013, "After the round-13
 * scoring" and "After the run s9722fa"): a revision that moves an answer
 * from established or partial to not determinable or a bounded negative
 * names what undermines the earlier chain, or it is refused and pointed to a
 * dispute and a lower strength; a dispute is still how a doubt is said. What
 * it names bears against the chain (a finding that contradicts it, a
 * refuted hypothesis tied to it, an entry it rests on under a dispute, a
 * correction of one): limitations and the downgrader's own coverage do not.
 * While a positive finding the earlier answer rested on still stands, the
 * revision is refused and pointed to a partial answer. Synthetic runs only.
 */
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import * as P from "../extensions/protocol.ts";
import { checkLedgerAnswers } from "../scripts/check-answers.ts";
import { renderReportBodyMarkdown } from "../scripts/report-body.ts";
import { A, coverage, ESTABLISHED, F, ok, planned, rec, refused, run } from "./negative-bar-fixture.ts";

const attested = async (c: { sandboxRoot: string; agentId: string }, input: P.LedgerActInput) => {
  const r = await P.attestEntry(c, input);
  assert.ok(r.ok && (r as { line: unknown }).line, JSON.stringify(r));
};
const codes = (r: Awaited<ReturnType<typeof checkLedgerAnswers>>, section: string) => r.defects.filter((d) => d.section === section).map((d) => d.code);

test("a downgrade names its counter-evidence: refused without it, admitted with it, in the chained core and the report; a dispute is still how a doubt is said", async () => {
  const { S, a0, a1, a2, a3 } = await run();
  const f = ok(await rec(a0, { kind: "finding", ...F, value: "alice logged on", source: "a log", evidence: "line 1", refs: ["job:j000001/hits.txt"], answers: ["1"] })).entry;
  const est = ok(await rec(a1, { kind: "answer", section: "question:1", value: "alice", reasoning: `E-${f.seq}`, ...A, confidence: "high", result: "established" })).entry;
  await attested(a2, { seq: est.seq, how: "read the line again", ...ESTABLISHED });
  // The dispute path is unchanged: a doubt is a dispute, and the answer stays.
  const disp = await P.disputeEntry(a3, { seq: est.seq, why: "the line may record the logon the other way round", refs: ["job:j000001/hits.txt"] });
  assert.ok(disp.ok, (disp as { reason?: string }).reason);
  let r = await checkLedgerAnswers(S, ["1"]);
  assert.deepEqual(codes(r, "question:1"), ["answer_disputed"]);
  // Walked down with no counter-evidence: refused, pointing to the dispute and a lower strength.
  await planned(a0, "1");
  const abs = ok(await rec(a0, { kind: "absence", value: "a logon", source: "the log", evidence: "a search", refs: ["job:j000002/hits.txt"], control: { ref: "job:j000002/hits.txt", found: "the same search finds a planted row" }, answers: ["1"] })).entry;
  const cov = ok(await rec(a0, coverage("1", ["input:logs/a.log"], [`E-${abs.seq}`]))).entry;
  const down = { kind: "answer", section: "question:1", value: "Who logged on cannot be determined from the log", reasoning: `E-${cov.seq}`, ...A, result: "not_determinable", supersedes: est.seq };
  refused(await rec(a1, down), new RegExp(`#${est.seq} answered question:1 established; recording it not determinable is a downgrade, and a downgrade names what undermines the earlier chain: downgrade \\{evidence: .*dispute #${est.seq} \\(why, refs\\), and if the doubt stands attest it best_candidate or record it again with confidence medium; the answer stays. A part the evidence cannot settle makes an answer partial, never not determinable while the findings it rests on stand`));
  refused(await rec(a1, { ...down, downgrade: { evidence: [`E-${est.seq}`], why: "w" } }), /names E-\d+, the answer being downgraded/);
  refused(await rec(a1, { ...down, downgrade: { evidence: ["E-999"], why: "w" } }), /no entry #999/);
  refused(await rec(a1, { ...down, downgrade: { evidence: ["job:j000009/none.txt"], why: "w" } }), /downgrade\.evidence: /);
  refused(await rec(a1, { ...down, downgrade: { evidence: [], why: "w" } }), /downgrade is \{evidence: \[E-<seq> or objects\], why\}/);
  refused(await rec(a1, { kind: "answer", section: "question:1", value: "alice, as the log says", reasoning: `E-${f.seq}`, ...A, result: "established", supersedes: est.seq, downgrade: { evidence: [`E-${f.seq}`], why: "w" } }), /downgrade is for a revision that moves an answer from established or partial to not_determinable or bounded_negative; #\d+ is established and this is established/);
  // The downgrader's own coverage record is no counter-evidence, and the finding the answer rests on still stands.
  refused(await rec(a1, { ...down, downgrade: { evidence: [`E-${cov.seq}`], why: "the search found nothing more" } }), new RegExp(`downgrade\\.evidence names nothing that bears against #${est.seq}'s chain \\(E-${est.seq}, E-${f.seq}\\): E-${cov.seq} is a coverage record: it says what a search covered, not that a finding is wrong.*#${est.seq} rests on E-${f.seq}, recorded for question:1, which still stands: not corrected, under no dispute, contradicted by nothing\\. Recording question:1 not determinable would discard it\\. Answer partial instead`));
  // With what undermines the chain, a finding that contradicts the one the answer rests on: admitted, and kept.
  const counter = ok(await rec(a3, { kind: "finding", ...F, value: "the line records a logon to alice's account from another user's session", source: "a log", evidence: "line 2", refs: ["job:j000002/hits.txt"], answers: ["1"], rel: [{ to: f.seq, kind: "contradicts" }] })).entry;
  const why = "the line the answer read names the session's owner, not the account logged on to";
  const nd = ok(await rec(a1, { ...down, reasoning: `E-${cov.seq}; E-${counter.seq} undermines E-${f.seq}`, downgrade: { evidence: [`E-${counter.seq}`, "job:j000002/hits.txt"], why } })).entry;
  assert.deepEqual(nd.downgrade, { evidence: [`E-${counter.seq}`, "job:j000002/hits.txt"], why });
  const text = await readFile(join(S, P.LEDGER_ENTRIES), "utf8");
  assert.equal(P.verifyLedgerChain(text).ok, true);
  assert.equal(P.verifyLedgerChain(text.replace(why, "a reason")).ok, false, "the downgrade is in the chained core");
  // The report's chain for the question: the earlier answer, its dispute, the counter-evidence.
  const md = await renderReportBodyMarkdown(S);
  assert.match(md, new RegExp(`\\*\\*Downgraded:\\*\\* E-${nd.seq} moved the answer from established \\(E-${est.seq}\\) to not determinable`));
  assert.match(md, new RegExp(`\\*\\*Counter-evidence:\\*\\* E-${counter.seq}, \`job:j000002/hits.txt\`: ${why}`));
  assert.match(md, /\*\*Disputes of the earlier answer:\*\* a3: the line may record the logon the other way round/);
});

test("a downgrade of a partial answer resting on standing findings, citing only limitations and coverage, is refused and pointed to a partial answer (the run s9722fa); a dispute and a correction of what it rests on then admit it", async () => {
  const { S, a0, a1, a2, a3 } = await run();
  await planned(a0, "1");
  // Two findings for the question, a limitation on the part still open, a finding for another question.
  const f1 = ok(await rec(a0, { kind: "finding", ...F, value: "a logon to the host at 09:14", source: "a log", evidence: "line 12", refs: ["job:j000002/hits.txt"], answers: ["1"] })).entry;
  const f2 = ok(await rec(a0, { kind: "finding", ...F, value: "the logon came from the office network", source: "a log", evidence: "line 13", refs: ["job:j000002/hits.txt"], answers: ["1"] })).entry;
  const other = ok(await rec(a0, { kind: "finding", ...F, value: "a remote tool's service entry", source: "the disk", evidence: "a registry key", refs: ["job:j000001/hits.txt"], answers: ["2"] })).entry;
  const lim = ok(await rec(a0, { kind: "limitation", value: "The account name is not in the log's retained fields", source: "the log", evidence: "the field list", reason: "unavailable", answers: ["1"] })).entry;
  const part = ok(await rec(a1, { kind: "answer", section: "question:1", value: "A logon from the office network at 09:14; the account is not established", reasoning: `E-${f1.seq} and E-${f2.seq}; the account is open (E-${lim.seq})`, ...A, limitations: [lim.seq], result: "partial", parts: [{ id: "when", part: "when and from where", status: "established", refs: [`E-${f1.seq}`, `E-${f2.seq}`] }, { id: "who", part: "which account", status: "open", open_by: `E-${lim.seq}` }] })).entry;
  await attested(a2, { seq: part.seq, how: "re-read lines 12 and 13", ...ESTABLISHED, answer_review: { ...ESTABLISHED.answer_review, parts: [{ id: "when", part: "when and from where", established: true, why: "lines 12 and 13" }, { id: "who", part: "which account", established: false, why: "not in the log", declared_open: `E-${lim.seq}` }] } });
  // The downgrader's own coverage record for the open part.
  const abs = ok(await rec(a3, { kind: "absence", value: "an account name for the logon", source: "the log", evidence: "a search", refs: ["job:j000002/hits.txt"], control: { ref: "job:j000002/hits.txt", found: "the same search finds a planted row" }, answers: ["1"] })).entry;
  const cov = ok(await rec(a3, coverage("1", ["input:logs/a.log"], [`E-${abs.seq}`]))).entry;
  const down = { kind: "answer", section: "question:1", value: "Who logged on cannot be determined from the log", reasoning: `E-${cov.seq}; E-${lim.seq}`, ...A, limitations: [lim.seq], result: "not_determinable", supersedes: part.seq };
  const r = await rec(a3, { ...down, downgrade: { evidence: [`E-${lim.seq}`, `E-${cov.seq}`, `E-${other.seq}`], why: "the account cannot be established" } });
  refused(r, new RegExp(`downgrade\\.evidence names nothing that bears against #${part.seq}'s chain`));
  const reason = (r as unknown as { reason: string }).reason;
  assert.match(reason, new RegExp(`E-${lim.seq} is a limitation: it says a route could not be examined, not that a finding is wrong`));
  assert.match(reason, new RegExp(`E-${cov.seq} is a coverage record: it says what a search covered, not that a finding is wrong`));
  assert.match(reason, new RegExp(`E-${other.seq} is a finding that contradicts nothing the earlier answer rests on`));
  assert.match(reason, new RegExp(`#${part.seq} rests on E-${f1.seq}, E-${f2.seq}, recorded for question:1, which still stand: not corrected, under no dispute, contradicted by nothing\\. Recording question:1 not determinable would discard them\\. Answer partial instead \\(record it with supersedes=${part.seq}, result partial\\)`));
  assert.match(reason, /name the parts still open, each with what bounds it \(parts \[\{id, part, status: "open", open_by: E-<seq> of its limitation or coverage record, R-<n> or L-<n>\}\]/);
  // A dispute on one finding bears against the chain; the other still stands.
  assert.ok((await P.disputeEntry(a3, { seq: f1.seq, why: "line 12 is a logoff, not a logon", refs: ["job:j000002/hits.txt"] })).ok);
  const r2 = await rec(a3, { ...down, downgrade: { evidence: [`E-${f1.seq}`, `E-${cov.seq}`], why: "line 12 is a logoff" } });
  refused(r2, new RegExp(`#${part.seq} rests on E-${f2.seq}, recorded for question:1, which still stands`));
  assert.doesNotMatch((r2 as unknown as { reason: string }).reason, /names nothing that bears against/);
  // Its author corrects the other: nothing positive it rested on stands, and the downgrade is admitted.
  ok(await rec(a0, { kind: "finding", ...F, value: "the connection came from the office network; no logon on that line", source: "a log", evidence: "line 13", refs: ["job:j000002/hits.txt"], answers: ["1"], supersedes: f2.seq, because: "line 13 records a connection, not a logon" }));
  const nd = ok(await rec(a3, { ...down, downgrade: { evidence: [`E-${f1.seq}`, `E-${cov.seq}`], why: "line 12 is a logoff and line 13 a connection" } })).entry;
  assert.equal(nd.result, "not_determinable");
  assert.deepEqual(nd.downgrade?.evidence, [`E-${f1.seq}`, `E-${cov.seq}`]);
});

test("what bears against a chain, by links alone: a finding that contradicts it, a refuted hypothesis tied to it, a correction of what it rests on; a limitation, a coverage record and an unrelated finding do not", async () => {
  const { a0, a1, a2, a3 } = await run();
  const f = ok(await rec(a0, { kind: "finding", ...F, value: "alice logged on", source: "a log", evidence: "line 1", refs: ["job:j000002/hits.txt"], answers: ["1"] })).entry;
  const est = ok(await rec(a1, { kind: "answer", section: "question:1", value: "alice", reasoning: `E-${f.seq}`, ...A, result: "established" })).entry;
  const against = ok(await rec(a2, { kind: "finding", ...F, value: "the session was bob's", source: "a log", evidence: "line 2", refs: ["job:j000002/hits.txt"], answers: ["1"], rel: [{ to: est.seq, kind: "contradicts" }] })).entry;
  const hyp = ok(await rec(a2, { kind: "hypothesis", value: "alice's logon was interactive", source: "a log", evidence: "line 1", status: "refuted", refs: ["job:j000002/hits.txt"], rel: [{ to: f.seq, kind: "derived_from" }] })).entry;
  const lim = ok(await rec(a3, { kind: "limitation", value: "The log keeps no session owner", source: "the log", evidence: "the fields", reason: "unavailable", answers: ["1"] })).entry;
  const unrelated = ok(await rec(a3, { kind: "finding", ...F, value: "a tool was installed", source: "the disk", evidence: "a key", refs: ["job:j000001/hits.txt"], answers: ["2"] })).entry;
  const entries = await P.readLedger(a0.sandboxRoot);
  const chk = P.downgradeCheck(est, [`E-${against.seq}`, `E-${hyp.seq}`, `E-${lim.seq}`, `E-${unrelated.seq}`], entries, []);
  assert.deepEqual(chk.bearing.map((x) => x.seq), [against.seq, hyp.seq]);
  assert.deepEqual(chk.not_bearing.map((x) => x.seq), [lim.seq, unrelated.seq]);
  assert.deepEqual(chk.standing.map((e) => e.seq), [f.seq], "the finding the answer rests on is contradicted by nothing: the answer's contradiction leaves it standing");
  // A correction of the finding it rests on bears against it, and leaves nothing standing.
  const corr = ok(await rec(a0, { kind: "finding", ...F, value: "a logon to alice's account from bob's session", source: "a log", evidence: "line 1", refs: ["job:j000002/hits.txt"], answers: ["1"], supersedes: f.seq, because: "the line names the session's owner" })).entry;
  const again = P.downgradeCheck(est, [`E-${corr.seq}`], await P.readLedger(a0.sandboxRoot), []);
  assert.deepEqual([again.bearing.map((x) => x.how), again.standing.length], [[`a correction of E-${f.seq}, which the earlier answer rests on`], 0]);
});
