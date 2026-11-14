/**
 * The rules the first calibration run on the new flow asked for (docs/adr/
 * 0013, "After the first calibration run"): new evidence stales every
 * standing negative, not-determinable and partial answer whose coverage is
 * older, whatever question it was added for; a completeness claim rests on a
 * coverage record naming the areas searched; an established attest names an
 * alternative it weighed; the run records a high confidence only where an
 * established answer was attested so; a not-determinable answer's coverage
 * names the acquisition ask, or why none, and the gate warns when it does
 * neither. Synthetic runs only: no case, no tool, no truth value.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdir, readdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import * as P from "../extensions/protocol.ts";
import * as L from "../extensions/leads.ts";
import * as Q from "../extensions/questions.ts";
import { checkLedgerAnswers } from "../scripts/check-answers.ts";
import { finishGate, NEGATIVE_BAR_CODES } from "../scripts/finish-gate.ts";
import { admitMaterial } from "../scripts/material.ts";
import { measureRun } from "../scripts/metrics.ts";
import { renderReportBodyMarkdown } from "../scripts/report-body.ts";
import { A, coverage, covers, ESTABLISHED, F, ok, okq, partialParts, partsReview, planned, rec, refused, REVIEW, run } from "./negative-bar-fixture.ts";

const ROOT = join(fileURLToPath(import.meta.url), "..", "..");
/** An answer an established review may hold so: its author's confidence high (a medium caps a review at best_candidate). */
const HIGH = { ...A, confidence: "high" } as const;
const WITHOUT_ALTERNATIVE = { ...ESTABLISHED, answer_review: { ...ESTABLISHED.answer_review, alternatives: "none the evidence allows" } } as const;

async function lateFile(S: string, name: string, body: string): Promise<string> {
  const dir = join(S, "..", "late");
  await mkdir(dir, { recursive: true });
  await writeFile(join(dir, name), body);
  return join(dir, name);
}
const defectsOf = (r: Awaited<ReturnType<typeof checkLedgerAnswers>>, section: string, code: string) => r.defects.filter((d) => d.section === section && d.code === code);
const attested = async (c: { sandboxRoot: string; agentId: string }, input: P.LedgerActInput) => {
  const r = await P.attestEntry(c, input);
  assert.ok(r.ok, (r as { reason?: string }).reason);
  assert.ok((r as { line: unknown }).line, `recorded, not deferred: ${JSON.stringify(r)}`);
  return r as { ok: true; line: P.LedgerAttestation; appended: boolean; note?: string };
};

// --- 1. new evidence stales what rests on older coverage ------------------------------------------

test("new evidence stales every standing negative, not-determinable and partial answer whose coverage is older, named or not; an established answer is not; only the new evidence examined, reviewed by another seat, and weighed with a delta clears it: a coverage record naming it, or an entry resting on it, attested, citing an entry that interprets it with a delta", async () => {
  const { S, a0, a1, a2, a3 } = await run();
  await planned(a0, "2");
  await planned(a3, "4");
  // A bounded negative, reviewed.
  const abs2 = ok(await rec(a0, { kind: "absence", value: "a remote tool", source: "inputs/disk.E01", evidence: "a search", refs: ["job:j000001/hits.txt"], control: { ref: "job:j000001/hits.txt", found: "the same search finds a planted row" }, answers: ["2"] })).entry;
  const cov2 = ok(await rec(a0, coverage("2", ["input:disk.E01"], [`E-${abs2.seq}`, "job:j000001/hits.txt"]))).entry;
  const ans2 = ok(await rec(a1, { kind: "answer", section: "question:2", value: "No evidence of a remote tool was found on the disk", reasoning: `E-${cov2.seq}`, ...A, result: "bounded_negative" })).entry;
  await attested(a2, { seq: cov2.seq, how: "ran the search again from job:j000001", review: REVIEW });
  // A not determinable, reviewed, its coverage saying why no source was asked for.
  const abs4 = ok(await rec(a3, { kind: "absence", value: "a start time", source: "inputs/logs/a.log", evidence: "a search", refs: ["job:j000002/hits.txt"], control: { ref: "job:j000002/hits.txt", found: "the same search finds a planted row" }, answers: ["4"] })).entry;
  const cov4 = ok(await rec(a3, coverage("4", ["input:logs/a.log"], [`E-${abs4.seq}`, "job:j000002/hits.txt"], { acquisition_none_why: "no source outside the evidence records when it started" }))).entry;
  const ans4 = ok(await rec(a1, { kind: "answer", section: "question:4", value: "No evidence of when it started was found in the log", reasoning: `E-${cov4.seq}`, ...A, result: "not_determinable" })).entry;
  await attested(a2, { seq: cov4.seq, how: "ran the search again from job:j000002", review: REVIEW });
  // An established answer and a partial one, each attested established.
  const f1 = ok(await rec(a0, { kind: "finding", ...F, value: "alice logged on", source: "a log", evidence: "line 1", refs: ["job:j000001/hits.txt"], answers: ["1"] })).entry;
  const ans1 = ok(await rec(a1, { kind: "answer", section: "question:1", value: "alice", reasoning: `E-${f1.seq}`, ...HIGH, result: "established" })).entry;
  await covers(a0, "1");
  await attested(a2, { seq: ans1.seq, how: "read E-" + f1.seq + " again", ...ESTABLISHED });
  const f5 = ok(await rec(a0, { kind: "finding", ...F, value: "the tool ran as an administrator", source: "a log", evidence: "line 2", refs: ["job:j000001/hits.txt"], answers: ["5"] })).entry;
  const lim5 = ok(await rec(a0, { kind: "limitation", value: "The log does not name the administrator account", source: "a log", evidence: "its fields", reason: "unavailable", answers: ["5"] })).entry;
  const ans5 = ok(await rec(a1, { kind: "answer", section: "question:5", value: "an administrator, not named", reasoning: `E-${f5.seq}`, ...HIGH, result: "partial", parts: partialParts(f5.seq, `E-${lim5.seq}`) })).entry;
  await covers(a0, "5");
  await attested(a2, { seq: ans5.seq, how: "read E-" + f5.seq + " again", ...partsReview(ESTABLISHED) });
  const sections = ["1", "2", "4", "5"];
  const before = await checkLedgerAnswers(S, sections, ["2"]);
  assert.deepEqual(before.defects.filter((d) => d.code === "evidence_stale"), [], "no evidence was added yet");
  assert.deepEqual(before.dispositions, { "question:1": "established", "question:2": "bounded_negative", "question:4": "not_determinable", "question:5": "partial" }, before.lines.join("\n"));

  // The operator adds evidence and names no question.
  const added = await admitMaterial(S, { mode: "evidence", path: await lateFile(S, "proxy.csv", "time,host\n09:58,ws\n"), why: "the proxy export the network team kept", supplied_by: "t", via: "cli" });
  assert.equal(added.ok, true, String(added.reason ?? ""));
  const entry = added.entry as number;
  const stale = added.stale_answers as Array<{ section: string; answer: number; result: string; coverage: number[] }>;
  assert.deepEqual(stale.map((x) => x.section).sort(), ["question:2", "question:4", "question:5"], "every negative, not determinable and partial answer, named or not; never the established one");
  assert.deepEqual(stale.find((x) => x.section === "question:2")?.coverage, [cov2.seq]);
  const posts = await Promise.all((await readdir(join(S, "threads", "main"))).filter((n) => n.endsWith("-system.md")).map((n) => readFile(join(S, "threads", "main", n), "utf8")));
  const post = posts.find((p) => /EVIDENCE ADDED/.test(p))!;
  assert.match(post, new RegExp(`Now stale, whatever question the evidence was added for: .*question:2 \\(E-${ans2.seq}, bounded negative; coverage E-${cov2.seq}\\)`));
  assert.match(post, new RegExp(`question:4 \\(E-${ans4.seq}, not determinable; coverage E-${cov4.seq}\\)`));
  assert.doesNotMatch(post, /question:1 \(E-/, "an established answer is not staled");

  let r = await checkLedgerAnswers(S, sections, ["2"]);
  assert.equal(r.ok, false);
  for (const s of ["question:2", "question:4", "question:5"]) {
    const d = defectsOf(r, s, "evidence_stale");
    assert.equal(d.length, 1, `${s}: ${r.lines.join("\n")}`);
    assert.match(d[0].what, new RegExp(`new evidence since its coverage \\(ev-0001, E-${entry}, inventory revision 1\\); re-examine against it`));
    assert.deepEqual(d[0].named_by, [], "fixed, never named");
    assert.equal(r.dispositions[s], undefined, `${s} has no disposition while it is stale`);
  }
  assert.match(defectsOf(r, "question:2", "evidence_stale")[0].what, new RegExp(`Its coverage record E-${cov2.seq} was recorded before the addition's entry E-${entry}`));
  assert.deepEqual(defectsOf(r, "question:2", "evidence_stale")[0].additions, [entry]);
  assert.match(defectsOf(r, "question:2", "evidence_stale")[0].fix, /examine import:ev-0001 for question:2: record what it shows as an entry whose refs name the import's files, with a delta, rel \[\{to: \d+, kind: supports \| contradicts \| adds_part \| irrelevant \| inconclusive\}\].*record kind=coverage with answers=\["2"\]/);
  assert.deepEqual(defectsOf(r, "question:1", "evidence_stale"), []);
  assert.equal(r.dispositions["question:1"], "established");
  assert.ok(NEGATIVE_BAR_CODES.has("evidence_stale"), "an acceptance excuses it only when made after the evidence came (acceptanceExcuses; tested below)");

  // Recorded again without examining it: still stale.
  const ans5b = ok(await rec(a1, { kind: "answer", section: "question:5", value: "an administrator, still not named", reasoning: `E-${f5.seq}`, ...HIGH, result: "partial", parts: partialParts(f5.seq, `E-${lim5.seq}`), supersedes: ans5.seq })).entry;
  r = await checkLedgerAnswers(S, sections, ["2"]);
  assert.equal(defectsOf(r, "question:5", "evidence_stale").length, 1, `E-${ans5b.seq} does not cite the new evidence or coverage at the new revision`);

  // Question 2: a coverage record after the addition that does not name the new evidence among its objects clears nothing.
  const cov2n = ok(await rec(a0, coverage("2", ["input:disk.E01"], [`E-${abs2.seq}`], { coverage_actual: "every byte of the disk, searched again" }))).entry;
  const ans2n = ok(await rec(a1, { kind: "answer", section: "question:2", value: "No evidence of a remote tool was found on the disk", reasoning: `E-${cov2n.seq}`, ...A, result: "bounded_negative", supersedes: ans2.seq })).entry;
  await attested(a2, { seq: cov2n.seq, how: "ran the search again over the disk", review: REVIEW });
  r = await checkLedgerAnswers(S, sections, ["2"]);
  assert.match(defectsOf(r, "question:2", "evidence_stale")[0]?.what ?? "", new RegExp(`E-${cov2n.seq}, recorded after it, does not name import:ev-0001 among its objects`));
  // One naming it: stale until another seat reviews it.
  const cov2b = ok(await rec(a0, coverage("2", ["input:disk.E01", "import:ev-0001/proxy.csv"], [`E-${abs2.seq}`]))).entry;
  const ans2b = ok(await rec(a1, { kind: "answer", section: "question:2", value: "No evidence of a remote tool was found on the disk or in the proxy export", reasoning: `E-${cov2b.seq}`, ...A, result: "bounded_negative", supersedes: ans2n.seq })).entry;
  r = await checkLedgerAnswers(S, sections, ["2"]);
  assert.match(defectsOf(r, "question:2", "evidence_stale")[0]?.what ?? "", new RegExp(`E-${cov2b.seq} examines it and no other seat has reviewed it yet`));
  await attested(a2, { seq: cov2b.seq, how: "ran the search again over the disk and the export", review: REVIEW, second_review_why: "the export is new" });
  // Examined and reviewed, and nothing it cites says how the export bears on the answer: still stale (the delta rule, docs/adr/0013).
  r = await checkLedgerAnswers(S, sections, ["2"]);
  assert.match(defectsOf(r, "question:2", "evidence_stale")[0]?.what ?? "", /it was examined and reviewed, and nothing it cites says how the new evidence bears on the answer \(a delta\)/);
  // What the export shows for the question, with its delta, among the results of the coverage the answer cites.
  const d2 = ok(await rec(a0, { kind: "absence", value: "a remote tool in the proxy export", source: "the proxy export", evidence: "read whole: one line, a host at 09:58", refs: ["import:ev-0001/proxy.csv"], answers: ["2"], rel: [{ to: ans2b.seq, kind: "irrelevant" }] })).entry;
  const cov2c = ok(await rec(a0, coverage("2", ["input:disk.E01", "import:ev-0001/proxy.csv"], [`E-${abs2.seq}`, `E-${d2.seq}`], { supersedes: cov2b.seq }))).entry;
  const ans2c = ok(await rec(a1, { kind: "answer", section: "question:2", value: "No evidence of a remote tool was found on the disk or in the proxy export", reasoning: `E-${cov2c.seq}`, ...A, result: "bounded_negative", supersedes: ans2b.seq })).entry;
  await attested(a2, { seq: cov2c.seq, how: "ran the search again over the disk and the export", review: REVIEW, second_review_why: "the export's delta is new" });
  r = await checkLedgerAnswers(S, sections, ["2"]);
  assert.deepEqual(defectsOf(r, "question:2", "evidence_stale"), [], r.lines.join("\n"));
  assert.equal(r.dispositions["question:2"], "bounded_negative");
  assert.equal(P.evidenceStale(ans2c, await P.readLedger(S), await P.readAttestations(S)), null);

  // Question 4: the answer again, citing an entry that rests on the new evidence: a one-line finding nobody else looked at clears nothing (the Fable review).
  const f4 = ok(await rec(a3, { kind: "finding", ...F, value: "the export's first line is at 09:58", source: "the proxy export", evidence: "line 2", refs: ["import:ev-0001/proxy.csv"], answers: ["4"] })).entry;
  const ans4b = ok(await rec(a1, { kind: "answer", section: "question:4", value: "No evidence of when it started was found in the log; the export begins after it", reasoning: `E-${cov4.seq} and E-${f4.seq}`, ...A, result: "not_determinable", supersedes: ans4.seq })).entry;
  r = await checkLedgerAnswers(S, sections, ["2"]);
  assert.match(defectsOf(r, "question:4", "evidence_stale")[0]?.what ?? "", new RegExp(`E-${f4.seq} examines it and no other seat has reviewed it yet`));
  // Another seat attests the finding: the new evidence is examined and reviewed, and the finding says nothing of how it bears on the answer.
  await attested(a2, { seq: f4.seq, how: "read the export's second line again from import:ev-0001/proxy.csv", refs: ["import:ev-0001/proxy.csv"] });
  r = await checkLedgerAnswers(S, sections, ["2"]);
  assert.match(defectsOf(r, "question:4", "evidence_stale")[0]?.what ?? "", new RegExp(`E-${f4.seq} interprets it with no delta`));
  // Corrected with its delta (the export begins after the start: it cannot say), attested, and cited.
  const f4b = ok(await rec(a3, { kind: "finding", ...F, value: "the export's first line is at 09:58", source: "the proxy export", evidence: "line 2", refs: ["import:ev-0001/proxy.csv"], answers: ["4"], rel: [{ to: ans4b.seq, kind: "inconclusive" }], supersedes: f4.seq, because: "says how the export bears on the answer" })).entry;
  const ans4c = ok(await rec(a1, { kind: "answer", section: "question:4", value: "No evidence of when it started was found in the log; the export begins after it", reasoning: `E-${cov4.seq} and E-${f4b.seq}`, ...A, result: "not_determinable", supersedes: ans4b.seq })).entry;
  await attested(a2, { seq: f4b.seq, how: "read the export's second line again from import:ev-0001/proxy.csv", refs: ["import:ev-0001/proxy.csv"] });
  r = await checkLedgerAnswers(S, sections, ["2"]);
  assert.deepEqual(defectsOf(r, "question:4", "evidence_stale"), [], r.lines.join("\n"));
  // The review made before the evidence came counts for nothing on the answer recorded after it: reviewed again.
  assert.deepEqual(defectsOf(r, "question:4", "negative_unreviewed").length, 1, "the old review of E-cov4 predates the addition");
  await attested(a2, { seq: ans4c.seq, how: "read the log and the export again", review: REVIEW });
  r = await checkLedgerAnswers(S, sections, ["2"]);
  assert.equal(r.dispositions["question:4"], "not_determinable", r.lines.join("\n"));
  // Question 5 is still stale; nothing else is.
  assert.deepEqual(r.defects.filter((d) => d.code === "evidence_stale").map((d) => d.section), ["question:5"]);
  assert.equal(P.verifyLedgerChain(await readFile(join(S, P.LEDGER_ENTRIES), "utf8")).ok, true);
});

const OPERATOR: Q.Actor = { kind: "human", role: "operator", person: "ops@lab", enrolled: false, os_user: "ops", host: "lab", via: "cli", identity: "claimed" };

test("the operator's lever on stale evidence: an acceptance made after the evidence came excuses evidence_stale on its question, one made before does not, and the reply says what the finish line still holds (the Fable review, P2 3a)", async () => {
  const { S, a0, a1, a2 } = await run();
  const lead = await planned(a0, "2");
  const abs = ok(await rec(a0, { kind: "absence", value: "a remote tool", source: "the disk", evidence: "a search", refs: ["job:j000001/hits.txt"], control: { ref: "job:j000001/hits.txt", found: "the same search finds a planted row" }, answers: ["2"] })).entry;
  assert.ok((await L.closeLead(a0, lead, { disposition: "negative", ref: `E-${abs.seq}` })).ok);
  const cov = ok(await rec(a0, coverage("2", ["input:disk.E01"], [`E-${abs.seq}`]))).entry;
  ok(await rec(a1, { kind: "answer", section: "question:2", value: "No evidence of a remote tool was found on the disk", reasoning: `E-${cov.seq}`, ...A, result: "bounded_negative" }));
  await attested(a2, { seq: cov.seq, how: "ran it again", review: REVIEW });
  // An acceptance made before the evidence came: the evidence stales the answer, and the acceptance does not excuse it.
  const early = okq(await Q.act(S, OPERATOR, "accept", { q: "Q-2", as: "bounded", why: "the disk is what the case holds", expected_rev: 1 }));
  assert.deepEqual(early.still_held, [], "nothing else holds it");
  const first = await admitMaterial(S, { mode: "evidence", path: await lateFile(S, "proxy.csv", "time,host\n09:58,ws\n"), why: "the proxy export", supplied_by: "t", via: "cli" });
  assert.equal(first.ok, true, String(first.reason ?? ""));
  let r = await checkLedgerAnswers(S, ["2"], ["2"]);
  assert.equal(defectsOf(r, "question:2", "evidence_stale").length, 1, "an acceptance from before the evidence excuses nothing of it");
  // Accepted again after it: excused, and the reply says nothing else holds.
  const late = okq(await Q.act(S, OPERATOR, "accept", { q: "Q-2", as: "bounded", why: "the export does not bear on the disk's tools", expected_rev: 1 }));
  assert.deepEqual(late.still_held, []);
  r = await checkLedgerAnswers(S, ["2"], ["2"]);
  assert.deepEqual(defectsOf(r, "question:2", "evidence_stale"), [], r.lines.join("\n"));
  // Evidence added after the acceptance stales it again.
  const second = await admitMaterial(S, { mode: "evidence", path: await lateFile(S, "dns.log", "09:58 ws query\n"), why: "the DNS log", supplied_by: "t", via: "cli" });
  assert.equal(second.ok, true, String(second.reason ?? ""));
  r = await checkLedgerAnswers(S, ["2"], ["2"]);
  const d = defectsOf(r, "question:2", "evidence_stale");
  assert.equal(d.length, 1);
  assert.deepEqual(d[0].additions, [first.entry as number, second.entry as number]);
  assert.match(d[0].fix, /Or the operator accepts the question's limits after the evidence came \(question accept\)/);
});

// --- 2. a completeness claim rests on coverage of its areas -------------------------------------

const COMPLETENESS_GOAL = [
  "## Goal",
  "",
  "Examine the drive.",
  "",
  "### Questions",
  "",
  "1. Which files were copied to the drive? List every file.",
  "2. Was the drive connected at all?",
  "3. Who used the workstation?",
  "",
  "## Definition of done",
  "",
  "d",
  "",
  "## Checks",
  "",
  '- `node x "$SWARM_HARNESS/scripts/check-answers.ts" --sections 1,2,3 --existence 2`',
  "",
].join("\n");

test("a question asking for every one, all or a complete list is a completeness claim: its established or partial answer rests on a coverage record naming the areas searched, or the gate holds it", async () => {
  // The word rule, small on purpose.
  for (const t of ["List every file.", "all connections to the host", "each account that signed in", "a complete list of the transfers", "Give the complete inventory."]) assert.equal(Q.completenessWords(t), true, t);
  for (const t of ["Was the drive connected at all?", "Who used the workstation?", "Allocate the blame", "the overall picture", "Which file was the first?"]) assert.equal(Q.completenessWords(t), false, t);
  // Whitespace folded; "at each" and "each time" say when, not how many (the Fable review, P3 10).
  for (const t of ["Was the disk wiped at  all?", "Was the disk wiped at\nall?", "At each logon, which IP was used?", "Did it beacon each time the user logged on?"]) assert.equal(Q.completenessWords(t), false, JSON.stringify(t));
  for (const t of ["Which files were copied, each with its time?", "List  every\nfile."]) assert.equal(Q.completenessWords(t), true, JSON.stringify(t));
  const { S, a0, a1, a2, a3 } = await run({ goal: COMPLETENESS_GOAL });
  const snap = await Q.questionsSnapshot(S);
  assert.deepEqual(["Q-1", "Q-2", "Q-3"].map((id) => [snap.state.questions.get(id)!.completeness, snap.state.questions.get(id)!.completeness_by]), [[true, "words"], [false, null], [false, null]]);
  // The asker's word overrides the words, either way; the CLI's flag is that word.
  const off = okq(await Q.act(S, { kind: "agent", agent: "a0" }, "open", { text: "List every account on the drive", why: "the case needs them", parent: "Q-3", materiality: "material", source_entry: "E-1", completeness: false }));
  const on = okq(await Q.act(S, { kind: "agent", agent: "a0" }, "open", { text: "Which transfers left the drive?", why: "the case needs them", parent: "Q-1", materiality: "material", source_entry: "E-1", completeness: true }));
  refused(await Q.act(S, { kind: "agent", agent: "a0" }, "open", { text: "Which hosts?", why: "w", parent: "Q-1", materiality: "material", source_entry: "E-1", completeness: "maybe" }), /completeness is true or false/);
  const cli = spawnSync(process.execPath, ["--experimental-strip-types", "--no-warnings", join(ROOT, "scripts", "questions-cli.ts"), "add", S, "--text", "Which printers were used?", "--why", "the case needs them", "--completeness"], { encoding: "utf8" });
  assert.equal(cli.status, 0, cli.stdout + cli.stderr);
  const cliQ = String(JSON.parse(cli.stdout.trim().split("\n").at(-1)!).q);
  const snap2 = await Q.questionsSnapshot(S);
  assert.deepEqual([off.q, on.q, cliQ].map((id) => [snap2.state.questions.get(id!)!.completeness, snap2.state.questions.get(id!)!.completeness_by]), [[false, "asker"], [true, "asker"], [true, "asker"]]);
  const view = Q.viewQuestion(snap2.state.questions.get("Q-1")!, await Q.viewContext(S));
  assert.equal(view.completeness, true);

  // Established on a finding alone: the reply says so, and the gate holds it.
  await planned(a0, "1");
  const f1 = ok(await rec(a0, { kind: "finding", ...F, value: "two files were copied", source: "the drive's directory", evidence: "a listing", refs: ["job:j000001/hits.txt"], answers: ["1"] })).entry;
  const r1 = ok(await rec(a1, { kind: "answer", section: "question:1", value: "Two files were copied", reasoning: `E-${f1.seq}`, ...HIGH, result: "established" }));
  assert.match(r1.note ?? "", /Q-1 asks for a complete set .* It cites none, so the finish line holds it \(completeness_uncovered\)/);
  await attested(a2, { seq: r1.entry.seq, how: "read the listing again", ...ESTABLISHED });
  let r = await checkLedgerAnswers(S, ["1"]);
  let d = defectsOf(r, "question:1", "completeness_uncovered");
  assert.equal(d.length, 1, r.lines.join("\n"));
  assert.match(d[0].what, /asks for a complete set, and it rests on no standing coverage record that says what was searched/);
  assert.match(d[0].fix, /areas \{allocated, deleted, unallocated, slack, secondary\}/);
  assert.deepEqual(d[0].named_by, []);
  assert.equal(r.dispositions["question:1"], undefined);
  assert.ok(NEGATIVE_BAR_CODES.has("completeness_uncovered"));
  // The operator's acceptance is recorded, and its reply says what it does not excuse.
  const q1lead = [...(await L.leadsSnapshot(S)).state.leads.values()].find((l) => l.answers.includes("1") && !l.closed)!;
  assert.ok((await L.closeLead(a0, q1lead.id, { disposition: "resolved", ref: `E-${f1.seq}` })).ok);
  const acc = okq(await Q.act(S, OPERATOR, "accept", { q: "Q-1", as: "bounded", why: "the listing is what the case holds", expected_rev: 1 }));
  assert.equal(acc.still_held?.length, 1);
  assert.match(acc.still_held![0], /^completeness_uncovered: answer #\d+ \(question:1\) is established on a question that asks for a complete set/);

  // A coverage record that names no areas does not carry the claim, and says so.
  const cov = ok(await rec(a0, coverage("1", ["input:disk.E01"], [`E-${f1.seq}`])));
  assert.match(cov.note ?? "", /Q-1 asks for a complete set: .* this one names none/);
  const r2 = ok(await rec(a1, { kind: "answer", section: "question:1", value: "Two files were copied", reasoning: `E-${f1.seq}, searched as E-${cov.entry.seq}`, ...HIGH, result: "established", supersedes: r1.entry.seq })).entry;
  await attested(a2, { seq: r2.seq, how: "read the listing again", ...ESTABLISHED });
  r = await checkLedgerAnswers(S, ["1"]);
  d = defectsOf(r, "question:1", "completeness_uncovered");
  assert.match(d[0]?.what ?? "", new RegExp(`its coverage record E-${cov.entry.seq} does not say which areas the search reached`));

  // The areas, every one named.
  refused(await rec(a0, coverage("1", ["input:disk.E01"], [`E-${f1.seq}`], { areas: { allocated: "searched" } })), /areas\.deleted is searched, skipped, not_applicable \(every area is named\)/);
  refused(await rec(a0, coverage("1", ["input:disk.E01"], [`E-${f1.seq}`], { areas: { allocated: "searched", deleted: "searched", unallocated: "searched", slack: "searched", secondary: "searched", swap: "searched" } })), /areas names "swap", which is not an area/);
  refused(await rec(a0, coverage("1", ["input:disk.E01"], [`E-${f1.seq}`], { areas: { allocated: "searched", deleted: "searched", unallocated: "searched", slack: "skipped", secondary: "not_applicable" } })), /areas says slack skipped, and skipped says none/);
  const areas = { allocated: "searched", deleted: "searched", unallocated: "searched", slack: "skipped", secondary: "not applicable" };
  const cov2 = ok(await rec(a0, coverage("1", ["input:disk.E01"], [`E-${f1.seq}`], { areas, skipped: "slack: the listing reads no slack, so none was searched" })));
  assert.deepEqual(cov2.entry.areas, { allocated: "searched", deleted: "searched", unallocated: "searched", slack: "skipped", secondary: "not_applicable" });
  assert.match(cov2.note ?? "", /areas: allocated searched, deleted searched, unallocated searched, slack skipped, secondary not applicable/);
  const r3 = ok(await rec(a1, { kind: "answer", section: "question:1", value: "Two files were copied", reasoning: `E-${f1.seq}, searched as E-${cov2.entry.seq}`, ...HIGH, result: "established", supersedes: r2.seq })).entry;
  await covers(a0, "1");
  await attested(a3, { seq: r3.seq, how: "read the listing and the coverage again", ...ESTABLISHED });
  r = await checkLedgerAnswers(S, ["1"]);
  assert.deepEqual(defectsOf(r, "question:1", "completeness_uncovered"), [], r.lines.join("\n"));
  assert.equal(r.dispositions["question:1"], "established");
  // In the chained core: the areas cannot be changed after the record.
  const text = await readFile(join(S, P.LEDGER_ENTRIES), "utf8");
  assert.equal(P.verifyLedgerChain(text).ok, true);
  assert.equal(P.verifyLedgerChain(text.replace('"slack":"skipped"', '"slack":"searched"')).ok, false);
});

// --- 3. an established attest names an alternative -----------------------------------------------

test("an established attest names an alternative it weighed and why the evidence rules it out; without one it is recorded a best candidate and the reply says so, and the seat may attest again once it has", async () => {
  const { S, a0, a1, a2 } = await run();
  const f = ok(await rec(a0, { kind: "finding", ...F, value: "alice logged on", source: "a log", evidence: "line 1", refs: ["job:j000001/hits.txt"], answers: ["1"] })).entry;
  const ans = ok(await rec(a1, { kind: "answer", section: "question:1", value: "alice", reasoning: `E-${f.seq}`, ...HIGH, result: "established" })).entry;
  await covers(a0, "1");
  refused(await P.attestEntry(a2, { seq: ans.seq, how: "x", ...ESTABLISHED, answer_review: { ...ESTABLISHED.answer_review, alternatives: [] } }), /answer_review\.alternatives lists each alternative explanation you considered and why the evidence rules it out/);
  refused(await P.attestEntry(a2, { seq: ans.seq, how: "x", ...ESTABLISHED, answer_review: { ...ESTABLISHED.answer_review, alternatives: [{ explanation: "bob" }] } }), /answer_review\.alternatives\[\]\.why is required/);
  const first = await attested(a2, { seq: ans.seq, how: "read the log line again", ...WITHOUT_ALTERNATIVE });
  assert.equal(first.line.strength, "best_candidate", "recorded a best candidate, not refused");
  assert.deepEqual(first.line.capped, [P.NO_ALTERNATIVE_CAP]);
  assert.match(first.note ?? "", /you attested it established, and it is recorded as a best candidate: the review names no alternative explanation/);
  let r = await checkLedgerAnswers(S, ["1"]);
  assert.deepEqual(r.best_candidate, ["question:1"]);
  assert.equal(r.dispositions["question:1"], undefined);
  // The same seat again, naming one: its review now.
  const again = await attested(a2, { seq: ans.seq, how: "weighed another account against the log line", ...ESTABLISHED });
  assert.equal(again.appended, true);
  assert.equal(again.line.strength, "established");
  assert.match(P.answerReviewWords(again.line.answer_review!), /alternatives weighed: a copy of the record left by another process \(ruled out: /);
  const third = await P.attestEntry(a2, { seq: ans.seq, how: "once more", ...ESTABLISHED });
  assert.equal((third as { appended: boolean }).appended, false, "an established review is once per seat");
  r = await checkLedgerAnswers(S, ["1"]);
  assert.deepEqual(r.best_candidate, []);
  assert.equal(r.dispositions["question:1"], "established");
  assert.equal(P.verifyAttestationChain(await readFile(join(S, P.LEDGER_ATTESTATIONS), "utf8")).ok, true);
});

test("an alternative counts only when it names the entries that rule it out and says something: filler is recorded a best candidate, an entry not in the ledger is refused (the Fable review, P2 4)", async () => {
  const { S, a0, a1, a2, a3 } = await run();
  const f = ok(await rec(a0, { kind: "finding", ...F, value: "alice logged on", source: "a log", evidence: "line 1", refs: ["job:j000001/hits.txt"], answers: ["1"] })).entry;
  const g = ok(await rec(a0, { kind: "finding", ...F, value: "bob's session was closed at the time", source: "a log", evidence: "line 9", refs: ["job:j000001/hits.txt"], answers: ["1"] })).entry;
  const ans = ok(await rec(a1, { kind: "answer", section: "question:1", value: "alice", reasoning: `E-${f.seq}`, ...HIGH, result: "established" })).entry;
  await covers(a0, "1");
  const review = (alternatives: unknown) => ({ ...ESTABLISHED, answer_review: { ...ESTABLISHED.answer_review, alternatives } });
  // An entry that is not in the ledger: refused, as any ref that does not resolve.
  refused(await P.attestEntry(a2, { seq: ans.seq, how: "x", ...review([{ explanation: "another user at the same console", why: "the log shows bob logged off", evidence: ["E-999"] }]) }), /answer_review\.alternatives\[\]\.evidence names E-999: there is no entry #999 in the ledger/);
  refused(await P.attestEntry(a2, { seq: ans.seq, how: "x", ...review([{ explanation: "another user at the same console", why: "the log shows bob logged off", evidence: ["job:j000001/hits.txt"] }]) }), /evidence names entries as E-<seq>/);
  // Filler, or a real explanation with no entry: recorded a best candidate, with why.
  for (const [what, alts] of [
    ["the filler the review found", [{ explanation: "none", why: "n/a", evidence: [`E-${g.seq}`] }]],
    ["no entry named", [{ explanation: "another user at the same console", why: "the log shows bob's session was closed then" }]],
    ["the same words twice", [{ explanation: "another user at the console", why: "another user at the console", evidence: [`E-${g.seq}`] }]],
  ] as const) {
    assert.equal(P.reviewNamesAlternative({ ...ESTABLISHED.answer_review, alternatives: alts } as unknown as P.AnswerReview), false, what);
  }
  const filler = await attested(a2, { seq: ans.seq, how: "read the line again", ...review([{ explanation: "none", why: "n/a", evidence: [`E-${g.seq}`] }]) });
  assert.equal(filler.line.strength, "best_candidate");
  assert.deepEqual(filler.line.capped, [P.NO_ALTERNATIVE_CAP]);
  assert.equal(P.recordedConfidence(ans, await P.readAttestations(S)).recorded, "medium");
  // A real alternative, ruled out by an entry in the ledger: established, and the high kept.
  const real = await attested(a3, { seq: ans.seq, how: "weighed bob against the log", ...review([{ explanation: "bob, who shared the console that morning", why: "his session was closed before the logon", evidence: [`E-${g.seq}`] }]) });
  assert.equal(real.line.strength, "established");
  assert.deepEqual(real.line.answer_review?.alternatives, [{ explanation: "bob, who shared the console that morning", why: "his session was closed before the logon", evidence: [`E-${g.seq}`] }]);
  assert.equal(P.recordedConfidence(ans, await P.readAttestations(S)).recorded, "high");
});

// --- 4. the recorded confidence --------------------------------------------------------------------

test("the run records a high confidence only on an established answer another seat attested established naming its alternatives; any other high is recorded medium, said in the reply, the report and the metrics", async () => {
  const { S, a0, a1, a2, a3 } = await run();
  await planned(a3, "4");
  const f = ok(await rec(a0, { kind: "finding", ...F, value: "alice logged on", source: "a log", evidence: "line 1", refs: ["job:j000001/hits.txt"], answers: ["1"] })).entry;
  const est = ok(await rec(a1, { kind: "answer", section: "question:1", value: "alice", reasoning: `E-${f.seq}`, ...HIGH, result: "established" }));
  await covers(a0, "1");
  assert.match(est.note ?? "", /confidence high is recorded as medium until another seat attests this answer established, naming the alternatives it weighed/);
  const abs = ok(await rec(a3, { kind: "absence", value: "a start time", source: "inputs/logs/a.log", evidence: "a search", refs: ["job:j000002/hits.txt"], control: { ref: "job:j000002/hits.txt", found: "the same search finds a planted row" }, answers: ["4"] })).entry;
  const cov = ok(await rec(a3, coverage("4", ["input:logs/a.log"], [`E-${abs.seq}`], { acquisition_none_why: "no other source records it" }))).entry;
  const nd = ok(await rec(a1, { kind: "answer", section: "question:4", value: "No evidence of when it started was found in the log", reasoning: `E-${cov.seq}`, ...HIGH, result: "not_determinable" }));
  assert.match(nd.note ?? "", /confidence high is recorded as medium: high is kept only by an established answer, and this one is not determinable/);
  const f5 = ok(await rec(a0, { kind: "finding", ...F, value: "the tool ran as an administrator", source: "a log", evidence: "line 2", refs: ["job:j000001/hits.txt"], answers: ["5"] })).entry;
  const med = ok(await rec(a1, { kind: "answer", section: "question:5", value: "an administrator", reasoning: `E-${f5.seq}`, ...A, result: "established" }));
  assert.doesNotMatch(med.note ?? "", /confidence high/);
  const conf = async (e: P.LedgerEntry) => P.recordedConfidence(e, await P.readAttestations(S));
  assert.deepEqual(await conf(est.entry), { stated: "high", recorded: "medium", why: "high is kept only once another seat attests it established, naming the alternatives it weighed and why the evidence rules each out; none has" });
  assert.equal((await conf(med.entry)).recorded, "medium", "a medium stands as stated");
  // A best candidate does not keep it; an established review naming an alternative does.
  await attested(a2, { seq: est.entry.seq, how: "read the line again", ...ESTABLISHED, strength: "best_candidate" });
  assert.equal((await conf(est.entry)).recorded, "medium");
  await attested(a3, { seq: est.entry.seq, how: "weighed another account", ...ESTABLISHED });
  assert.deepEqual(await conf(est.entry), { stated: "high", recorded: "high", why: null });
  await attested(a2, { seq: cov.seq, how: "ran the search again", review: REVIEW });
  assert.equal((await conf(nd.entry)).recorded, "medium", "a not determinable never keeps a high");
  // The report and the metrics show the recorded confidence, the stated one beside it.
  const md = await renderReportBodyMarkdown(S);
  assert.match(md, /Confidence medium \(stated high; high is kept only by an established answer, and this one is not determinable\)/);
  // An answer recorded before the rule (no confidence_rule) keeps the high its author declared, whatever its attests (a text alternatives review, as every review was before the rule).
  const legacy = { ...est.entry, confidence_rule: undefined } as unknown as P.LedgerEntry;
  const textReview = [{ v: 2, act: "attest", seq: est.entry.seq, target: est.entry.hash!, by: "a3", at: new Date().toISOString(), how: "re-read it", strength: "established", answer_review: { ...ESTABLISHED.answer_review, alternatives: "none the evidence allows" } }] as unknown as P.LedgerAttestation[];
  assert.deepEqual(P.recordedConfidence(legacy, textReview), { stated: "high", recorded: "high", why: null, legacy: true });
  assert.equal(P.confidenceWords(P.recordedConfidence(legacy, textReview)), "high (as declared: recorded before the run recorded confidence)");
  assert.equal(P.recordedConfidence(est.entry, textReview).recorded, "medium", "the same attest on an answer recorded under the rule keeps nothing");
  assert.equal(est.entry.confidence_rule, 1, "the hub marks an answer recorded under the rule");
  const m = await measureRun(S);
  assert.equal(m.confidence.recorded, true);
  assert.equal(m.confidence.legacy, 0);
  assert.deepEqual([m.confidence.stated.high, m.confidence.recorded_levels.high, m.confidence.recorded_levels.medium], [2, 1, 2]);
  assert.deepEqual(m.confidence.lowered.map((x) => [x.section, x.answer]), [["4", `E-${nd.entry.seq}`]]);
});

// --- 5. a missing source is asked for -----------------------------------------------------------------

test("a not-determinable answer's coverage names the acquisition ask, or why none: the answers check warns of one that does neither and holds nothing; the finish line's note repeats it", async () => {
  const { S, a0, a1, a2 } = await run();
  await planned(a0, "4");
  const abs = ok(await rec(a0, { kind: "absence", value: "a start time", source: "inputs/logs/a.log", evidence: "a search", refs: ["job:j000002/hits.txt"], control: { ref: "job:j000002/hits.txt", found: "the same search finds a planted row" }, answers: ["4"] })).entry;
  const cov = ok(await rec(a0, coverage("4", ["input:logs/a.log"], [`E-${abs.seq}`]))).entry;
  const ans = ok(await rec(a1, { kind: "answer", section: "question:4", value: "No evidence of when it started was found in the log", reasoning: `E-${cov.seq}`, ...A, result: "not_determinable" }));
  assert.match(ans.note ?? "", /not determinable for want of a source the evidence does not hold\? Ask for it first: lead_close needs_operator with ask \{kind: acquisition/);
  await attested(a2, { seq: cov.seq, how: "ran the search again", review: REVIEW });
  let r = await checkLedgerAnswers(S, ["4"]);
  assert.equal(r.ok, true, r.lines.join("\n"));
  assert.equal(r.dispositions["question:4"], "not_determinable", "a warning holds nothing");
  assert.equal(r.warnings.length, 1);
  assert.match(r.warnings[0], new RegExp(`answer #${ans.entry.seq} \\(question:4\\) is not determinable, and its coverage record E-${cov.seq} names no acquisition ask and no reason for none`));
  assert.ok(r.lines.some((l) => l.startsWith("WARN: ")));
  // The ask's field is checked against the requests register.
  refused(await rec(a0, coverage("4", ["input:logs/a.log"], [`E-${abs.seq}`], { acquisition_ask: "the proxy logs" })), /acquisition_ask names an acquisition request, R-<n>/);
  refused(await rec(a0, coverage("4", ["input:logs/a.log"], [`E-${abs.seq}`], { acquisition_ask: "R-9" })), /acquisition_ask R-9 is not a request of this run/);
  refused(await rec(a0, coverage("4", ["input:logs/a.log"], [`E-${abs.seq}`], { acquisition_ask: "R-1", acquisition_none_why: "none" })), /give one/);
  okq(await L.openLead(a1, { title: "The proxy logs", why: "they would date it", answers: ["4"], take: true }));
  const asked = okq(await L.closeLead(a1, "L-2", { disposition: "needs_operator", ref: "The proxy logs are not in the evidence", ask: { kind: "acquisition", source: "the web proxy's logs", where: "the network team", expected_value: "when it started", urgency: "normal" } }));
  assert.equal(asked.request?.id, "R-1");
  const cov2 = ok(await rec(a0, coverage("4", ["input:logs/a.log"], [`E-${abs.seq}`], { acquisition_ask: "r-1" }))).entry;
  assert.equal(cov2.acquisition_ask, "R-1");
  ok(await rec(a1, { kind: "answer", section: "question:4", value: "No evidence of when it started was found in the log; the proxy logs are asked for", reasoning: `E-${cov2.seq}`, ...A, result: "not_determinable", supersedes: ans.entry.seq }));
  await attested(a2, { seq: cov2.seq, how: "ran the search again", review: REVIEW });
  r = await checkLedgerAnswers(S, ["4"]);
  assert.deepEqual(r.warnings, [], r.lines.join("\n"));
  // The finish gate carries the check's warnings, and the verdict's note says them without holding the done.
  const gate = await finishGate(S, { total: 1, passed: 1, checks: [{ cmd: "check-answers", ok: true, answers: { outcomes: { "question:4": "inconclusive" }, dispositions: { "question:4": "not_determinable" }, warnings: ["a warning"] } as never }] });
  assert.deepEqual(gate.warnings, ["a warning"]);
  const v = P.finishLineVerdict({ total: 1, passed: 1, checks: [], gate: { defects: [], limited: ["question:4 is inconclusive"], questions: [{ id: "4", outcome: "inconclusive", blocks: [], disposition: "not_determinable" }], holding: [], warnings: ["a warning"] } }, false);
  assert.equal(v.proceed, true);
  assert.equal((v as { outcome: string }).outcome, "examination_limited");
  assert.match((v as { note?: string }).note ?? "", /warnings \(not held on\): a warning/);
});

test("under the case policy's more_evidence: no, acquisition_none_why naming the policy satisfies the rule: the warning and the answer's reply suggest it, never an ask (the ctf preset's asks, each declined at once)", async () => {
  const { S, a0, a1, a2 } = await run();
  await mkdir(join(S, "network"), { recursive: true });
  await writeFile(join(S, "network", "policy.json"), JSON.stringify({ policy: "ctf", more_evidence: "no" }));
  await planned(a0, "4");
  const abs = ok(await rec(a0, { kind: "absence", value: "a start time", source: "inputs/logs/a.log", evidence: "a search", refs: ["job:j000002/hits.txt"], control: { ref: "job:j000002/hits.txt", found: "the same search finds a planted row" }, answers: ["4"] })).entry;
  const cov = ok(await rec(a0, coverage("4", ["input:logs/a.log"], [`E-${abs.seq}`]))).entry;
  const ans = ok(await rec(a1, { kind: "answer", section: "question:4", value: "No evidence of when it started was found in the log", reasoning: `E-${cov.seq}`, ...A, result: "not_determinable" }));
  assert.match(ans.note ?? "", new RegExp(`this case admits no further evidence \\(more_evidence: no\\), so open no acquisition ask: the coverage record behind this answer says so in acquisition_none_why \\("${P.NO_MORE_EVIDENCE_NONE_WHY.replace(/[()]/g, "\\$&")}"\\)`));
  assert.doesNotMatch(ans.note ?? "", /Ask for it first/);
  await attested(a2, { seq: cov.seq, how: "ran the search again", review: REVIEW });
  let r = await checkLedgerAnswers(S, ["4"]);
  assert.equal(r.warnings.length, 1);
  assert.match(r.warnings[0], new RegExp(`this case admits no further evidence \\(more_evidence: no\\), so open no acquisition ask: record the coverage again with supersedes=${cov.seq} with acquisition_none_why: "the case policy admits no further evidence`));
  assert.doesNotMatch(r.warnings[0], /lead_close needs_operator/);
  // Said so, the rule is met: no ask was opened.
  const cov2 = ok(await rec(a0, coverage("4", ["input:logs/a.log"], [`E-${abs.seq}`], { acquisition_none_why: P.NO_MORE_EVIDENCE_NONE_WHY, supersedes: cov.seq }))).entry;
  ok(await rec(a1, { kind: "answer", section: "question:4", value: "No evidence of when it started was found in the log", reasoning: `E-${cov2.seq}`, ...A, result: "not_determinable", supersedes: ans.entry.seq }));
  await attested(a2, { seq: cov2.seq, how: "ran the search again", review: REVIEW, second_review_why: "the record now says why no ask" });
  r = await checkLedgerAnswers(S, ["4"]);
  assert.deepEqual(r.warnings, [], r.lines.join("\n"));
  assert.equal(r.dispositions["question:4"], "not_determinable");
  const requests = existsSync(join(S, "requests", "requests.jsonl")) ? await readFile(join(S, "requests", "requests.jsonl"), "utf8") : "";
  assert.doesNotMatch(requests, /"acquisition"/, "no acquisition was asked");
});
