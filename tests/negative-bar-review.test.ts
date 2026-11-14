/**
 * The negative bar under review (Astra's review of WP2): each case below
 * failed on the code before its fix.
 *
 * - A coverage record binds its results by hash: a result superseded,
 *   disputed or changed after the record takes the record, and the reviewed
 *   negative resting on it, out of standing.
 * - premise_not_supported rests on a finding; one resting on a search alone
 *   meets the negative bar, and "it did not happen" is checked whatever the
 *   result.
 * - An acceptance is bound to the answer it accepted: a replacement answer
 *   is held to the negative bar, and the acceptance no longer stands.
 * - The report states a negative in the bounded form the harness makes from
 *   the coverage record; the agents' own words follow, marked as theirs.
 * - The hub's object coverage names objects as the job scopes do: a digest
 *   of an input is that input, a store path is its job's output, a
 *   catalogue directory holds its members, and a coverage record takes a
 *   directory of the evidence as its object.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import * as P from "../extensions/protocol.ts";
import * as L from "../extensions/leads.ts";
import * as Q from "../extensions/questions.ts";
import { checkLedgerAnswers } from "../scripts/check-answers.ts";
import { finishGate } from "../scripts/finish-gate.ts";
import { renderReportBodyMarkdown } from "../scripts/report-body.ts";
import { A, coverage, ESTABLISHED, F, job, ok, okq, planned, rec, refused, REVIEW, run, sha } from "./negative-bar-fixture.ts";

const operator: Q.Actor = { kind: "human", role: "operator", person: "tester@lab", enrolled: false, os_user: "tester", host: "lab", via: "cli", identity: "claimed" };

test("a coverage record binds its results by hash: a result superseded or disputed after it takes the reviewed negative out of standing", async () => {
  const { S, a0, a1, a2, a3 } = await run();
  await planned(a0, "2");
  const absence = ok(await rec(a0, { kind: "absence", value: "a remote tool", source: "inputs/disk.E01", evidence: "a search over the whole disk", completion: "complete", refs: ["job:j000001/hits.txt"], control: { ref: "job:j000001/hits.txt", found: "the same search finds a planted row" }, answers: ["2"] })).entry;
  const cov = ok(await rec(a0, coverage("2", ["input:disk.E01"], [`E-${absence.seq}`, "job:j000001/hits.txt"]))).entry;
  assert.equal(cov.coverage, "complete");
  assert.deepEqual(cov.result_bound, [{ seq: absence.seq, hash: absence.hash }], "the record names its results by hash");
  const ans = ok(await rec(a1, { kind: "answer", section: "question:2", value: "No evidence of a remote tool was found on the disk", reasoning: `E-${cov.seq}`, ...A, result: "bounded_negative" })).entry;
  assert.ok((await P.attestEntry(a2, { seq: cov.seq, how: "ran the search again from job:j000001", review: REVIEW })).ok);
  let r = await checkLedgerAnswers(S, ["2"], ["2"]);
  // Reviewed on its coverage record: a disposition under the bar (examination-limited: the answer does not say the event did not happen).
  assert.deepEqual([r.ok, r.outcomes["question:2"], r.dispositions["question:2"]], [true, "limited", "bounded_negative"], r.lines.join("\n"));
  // The search it rests on is corrected: it did not cover the whole disk.
  ok(await rec(a0, { kind: "absence", value: "a remote tool", source: "inputs/disk.E01", evidence: "a search over one volume only", completion: "partial", refs: ["job:j000001/hits.txt"], control: { ref: "job:j000001/hits.txt", found: "the same search finds a planted row" }, answers: ["2"], supersedes: absence.seq, because: "the search stopped at the first volume" }));
  r = await checkLedgerAnswers(S, ["2"], ["2"]);
  assert.equal(r.ok, false, r.lines.join("\n"));
  const stale = r.defects.find((d) => d.code === "coverage_stale");
  assert.ok(stale, JSON.stringify(r.defects));
  assert.match(stale!.what, new RegExp(`E-${cov.seq}.*its result E-${absence.seq} is superseded by #\\d+`));
  assert.deepEqual(stale!.named_by, [], "a stale coverage record is corrected, never named away");
  assert.notEqual(r.outcomes["question:2"], "answered");
  assert.equal(r.dispositions["question:2"], undefined, "no disposition on a coverage record that no longer stands");
  const review = P.negativeReview(ans, await P.readLedger(S), await P.readAttestations(S), await P.readDisputes(S));
  assert.equal(review.reviewed, false, "the review was of a search that no longer stands");
  // A result disputed after the record: the same.
  await planned(a0, "6");
  const absence6 = ok(await rec(a0, { kind: "absence", value: "an upload", source: "inputs/disk.E01", evidence: "a search", refs: ["job:j000001/hits.txt"], control: { ref: "job:j000001/hits.txt", found: "the same search finds a planted row" }, answers: ["6"] })).entry;
  const cov6 = ok(await rec(a0, coverage("6", ["input:disk.E01"], [`E-${absence6.seq}`]))).entry;
  ok(await rec(a1, { kind: "answer", section: "question:6", value: "No evidence of an upload was found on the disk", reasoning: `E-${cov6.seq}`, ...A, result: "not_determinable" }));
  assert.ok((await P.attestEntry(a2, { seq: cov6.seq, how: "ran it again", review: REVIEW })).ok);
  assert.ok((await P.disputeEntry(a3, { seq: absence6.seq, why: "the search excluded compressed files" })).ok);
  r = await checkLedgerAnswers(S, ["6"], []);
  assert.ok(r.defects.some((d) => d.code === "coverage_stale" && /disputed by a3/.test(d.what)), JSON.stringify(r.defects));
});

test("premise_not_supported rests on a finding; on a search alone it meets the negative bar, and absolute wording is checked whatever the result", async () => {
  const { S, a0, a1, a2 } = await run();
  await planned(a0, "2");
  const absence = ok(await rec(a0, { kind: "absence", value: "an intrusion", source: "inputs/disk.E01", evidence: "a search", refs: ["job:j000001/hits.txt"], control: { ref: "job:j000001/hits.txt", found: "the same search finds a planted row" }, answers: ["2"] })).entry;
  const base = { kind: "answer", section: "question:2", reasoning: `E-${absence.seq}`, ...A, confidence: "high", result: "premise_not_supported" };
  refused(await rec(a1, { ...base, value: "The question's premise does not hold" }), /premise_not_supported rests on a standing finding/);
  refused(await rec(a1, { ...base, value: "The intrusion did not happen" }), /worded as the event's absence \("did not happen"\)/);
  // With a finding that shows the premise false, the answer stands; "did not happen" is still the bar's.
  const finding = ok(await rec(a0, { kind: "finding", ...F, value: "The alert came from another host's log", source: "a log", evidence: "line 9", refs: ["job:j000002/hits.txt"], answers: ["2"] })).entry;
  refused(await rec(a1, { ...base, reasoning: `E-${finding.seq}`, value: "The intrusion did not happen: the alert was another host's" }), /worded as the event's absence/);
  const ans = ok(await rec(a1, { ...base, reasoning: `E-${finding.seq}`, value: "The premise does not hold: the alert came from another host's log" })).entry;
  assert.ok((await P.attestEntry(a2, { seq: ans.seq, how: "read E-" + finding.seq + " again", ...ESTABLISHED })).ok);
  const r = await checkLedgerAnswers(S, ["2"], ["2"]);
  assert.equal(r.outcomes["question:2"], "answered", r.lines.join("\n"));
  // A ledger written without these checks (an older harness) is held to the bar by the gate.
  const entry = (seq: number, e: Record<string, unknown>) => ({ v: 4, seq, by: "a0", authors: ["a0"], at: "2026-01-01T00:00:00Z", hash: `h${seq}`, ...e }) as unknown as P.LedgerEntry;
  const entries = [
    entry(1, { kind: "absence", value: "an intrusion", source: "s", evidence: "e", answers: ["2"] }),
    entry(2, { kind: "answer", section: "question:2", value: "The intrusion did not happen", reasoning: "E-1", result: "premise_not_supported", support: [{ seq: 1, hash: "h1" }] }),
  ];
  const g = P.ledgerGate({ entries, attestations: [], disputes: [], sections: ["question:2"], bar: () => ({ material: true, existence: true }) });
  const codes = g.defects.map((d) => d.code);
  assert.ok(codes.includes("coverage_missing") && codes.includes("negative_unreviewed") && codes.includes("wording"), JSON.stringify(codes));
  const established = P.ledgerGate({ entries: [entries[0], entry(2, { ...entries[1], result: "established", value: "It never happened" })], attestations: [], disputes: [], sections: ["question:2"], bar: () => ({ material: true, existence: false }) });
  assert.ok(established.defects.some((d) => d.code === "wording"), "absolute wording is held whatever the result");
});

test("an acceptance is bound to the answer it accepted: a replacement negative is held to the bar, and the acceptance no longer stands", async () => {
  const { S, a0, a1, a2, a3 } = await run();
  const q = okq(await Q.act(S, operator, "open", { text: "Was a second remote tool staged?", why: "the client asks", materiality: "material" })).q!;
  const section = q.slice(2);
  const opened = await L.openLead(a0, { title: "Search for a second tool", why: "asked", answers: [q], take: true, proposition: "a second tool was staged", negation: "no second tool was staged", routes: [{ source: "input:disk.E01", method: "search the disk" }] });
  assert.ok(opened.ok, (opened as { reason?: string }).reason);
  const lead = (opened as { lead: { id: string } }).lead.id;
  const absence = ok(await rec(a0, { kind: "absence", value: "a second tool", source: "the disk", evidence: "a search", refs: ["job:j000001/hits.txt"], control: { ref: "job:j000001/hits.txt", found: "the same search finds a planted row" }, answers: [q] })).entry;
  assert.ok((await L.closeLead(a0, lead, { disposition: "negative", ref: `E-${absence.seq}` })).ok);
  const cov = ok(await rec(a0, coverage(q, ["input:disk.E01"], [`E-${absence.seq}`]))).entry;
  const ans = ok(await rec(a1, { kind: "answer", section: `question:${section}`, value: "No evidence of a second tool was found on the disk", reasoning: `E-${cov.seq}`, ...A, contrary_none_why: "nothing points to one", result: "bounded_negative" })).entry;
  assert.ok((await P.attestEntry(a2, { seq: cov.seq, how: "ran it again", review: REVIEW })).ok);
  const accepted = await Q.act(S, operator, "accept", { q, as: "bounded", why: "the disk is what the case holds", expected_rev: 1 });
  assert.ok(accepted.ok, (accepted as { reason?: string }).reason);
  let gate = await finishGate(S, null);
  assert.ok(!gate.defects.some((d) => "question" in d && d.question === q), JSON.stringify(gate.defects));
  // The coverage and the answer replaced, the question's revision unchanged: the new negative is nobody's review yet.
  const cov2 = ok(await rec(a3, { ...coverage(q, ["input:disk.E01"], [`E-${absence.seq}`], { settings: "a narrower search" }), supersedes: cov.seq })).entry;
  ok(await rec(a1, { kind: "answer", section: `question:${section}`, value: "No evidence of a second tool was found in the narrower search", reasoning: `E-${cov2.seq}`, ...A, contrary_none_why: "nothing points to one", result: "bounded_negative", supersedes: ans.seq }));
  const view = Q.questionViews(await Q.viewContext(S)).find((v) => v.id === q)!;
  assert.equal(view.accepted?.stands, false, "the acceptance was of another answer");
  gate = await finishGate(S, null);
  assert.ok(gate.defects.some((d) => "question" in d && d.question === q && /negative \(unreviewed\)/.test(d.what)), JSON.stringify(gate.defects));
  assert.ok(!(gate.accepted ?? []).some((l) => l.startsWith(q)), "an acceptance that no longer stands limits nothing");
});

test("the report states a negative in the bounded form made from its coverage record; the agents' words follow, marked as theirs", async () => {
  const { S, a0, a1 } = await run();
  await planned(a0, "2");
  const absence = ok(await rec(a0, { kind: "absence", value: "a remote tool", source: "one volume", evidence: "a search", refs: ["job:j000003/hits.txt"], control: { ref: "job:j000003/hits.txt", found: "the same search finds a planted row" }, answers: ["2"] })).entry;
  const cov = ok(await rec(a0, coverage("2", ["input:disk.E01"], [`E-${absence.seq}`, "job:j000003/hits.txt"], { proposition: "A remote administration tool was installed.", detection_opportunity: { trace_expected: "no", why: "the tool may leave nothing on disk" } }))).entry;
  assert.equal(cov.coverage, "partial");
  ok(await rec(a1, { kind: "answer", section: "question:2", value: "No remote tool was installed on this host", reasoning: `E-${cov.seq}`, ...A, result: "bounded_negative" }));
  const md = await renderReportBodyMarkdown(S);
  assert.match(md, /\*\*Answer\*\*[^\n]*\n\n> No evidence that a remote administration tool was installed was found in input:disk\.E01, the whole of each object, no time bound\./);
  assert.doesNotMatch(md, /\*\*Answer\*\*[^\n]*\n\n> No remote tool was installed/);
  assert.match(md, /As the agents worded it \(not the conclusion: the bar for saying more is not met\): No remote tool was installed on this host/);
});

test("the hub's object coverage names objects as the job scopes do: an input's digest, a store path, a catalogue directory, a directory of the evidence", async () => {
  const { S, a0 } = await run();
  await job(S, "j000007", "hits.txt", { spec: { kind: "command", scope: "declared", inputs: ["input:logs/"], command: "search" } });
  await job(S, "j000008", "hits.txt", { spec: { kind: "command", scope: "declared", inputs: ["catalog/gen/g0001/"], command: "search" } });
  await job(S, "j000009", "hits.txt", { spec: { kind: "command", scope: "declared", inputs: ["store/jobs/j000001/out/hits.txt"], command: "search" } });
  await planned(a0, "2");
  // A digest of an input is that input: a job over its directory read it.
  const byDigest = ok(await rec(a0, coverage("2", [`sha256:${sha("a")}`], ["job:j000007/hits.txt"]))).entry;
  assert.equal(byDigest.coverage, "complete", JSON.stringify(byDigest.coverage_detail));
  // A catalogue directory holds its members.
  const member = ok(await rec(a0, coverage("2", ["member:g0001#2"], ["job:j000008/hits.txt"], { settings: "the members" }))).entry;
  assert.equal(member.coverage, "complete", JSON.stringify(member.coverage_detail));
  // A store path is its job's output, by its manifest's digest: the same bytes named by their digest are covered.
  const stored = ok(await rec(a0, coverage("2", [`sha256:${sha("j000001\n")}`], ["job:j000009/hits.txt"], { settings: "the stored hits" }))).entry;
  assert.equal(stored.coverage, "complete", JSON.stringify(stored.coverage_detail));
  // A directory of the evidence is an object a coverage record may name, as its refusal says.
  const dir = ok(await rec(a0, coverage("2", ["input:logs/"], ["job:j000007/hits.txt"], { settings: "the log directory" }))).entry;
  assert.equal(dir.coverage, "complete", JSON.stringify(dir.coverage_detail));
});
