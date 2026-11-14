/**
 * A coverage record revised for the same questions and at the same coverage
 * carries the answer that rests on it (extensions/ledger-rules.ts
 * carriedCoverage): the answer is not written again with the same value. On
 * the run sf4406b each revision of question 7's coverage (to name what a store
 * sweep found) made its answer be recorded again, 18 versions in an hour, and
 * each new answer cut the report's acknowledgements, so the finish never
 * settled. The gates read the correction in place of the record cited: it is
 * still swept and still reviewed. A correction that changes the questions or
 * the coverage is not carried, and a finding's correction never is.
 */
import assert from "node:assert/strict";
import { after, test } from "node:test";
import * as P from "../extensions/protocol.ts";
import { checkLedgerAnswers } from "../scripts/check-answers.ts";
import { A, coverage, dirs, ok, planned, rec, run } from "./negative-bar-fixture.ts";
import { rm } from "node:fs/promises";

after(async () => {
  for (const d of dirs) await rm(d, { recursive: true, force: true });
});

test("an answer resting on a coverage record revised for the same question and coverage stands on the revision; one revised to other questions or another coverage does not", async () => {
  const { S, a0, a1 } = await run();
  await planned(a0, "2");
  const abs = ok(await rec(a0, { kind: "absence", value: "no remote tool on the disk", source: "the disk", evidence: "a search", refs: ["job:j000001/hits.txt"], control: { ref: "job:j000001/hits.txt", found: "the same search finds a planted row" }, answers: ["2"] })).entry;
  const cov = ok(await rec(a0, coverage("2", ["input:disk.E01"], [`E-${abs.seq}`, "job:j000001/hits.txt"]))).entry;
  const ans = ok(await rec(a1, { kind: "answer", section: "question:2", value: "No evidence of a remote tool was found on the disk", reasoning: `E-${cov.seq}`, ...A, result: "bounded_negative" })).entry;
  const problems = async () => P.answerProblems(await P.readLedger(S), await P.readDisputes(S));
  assert.equal((await problems()).size, 0);
  // Revised to name one more result (what a sweep found): same question, same coverage. The answer is not written again.
  const cov2 = ok(await rec(a0, coverage("2", ["input:disk.E01"], [`E-${abs.seq}`, "job:j000001/hits.txt", "job:j000006/hits.txt"], { supersedes: cov.seq }))).entry;
  assert.equal(cov2.coverage, cov.coverage);
  assert.equal((await problems()).get(ans.seq), undefined, "carried by the revision");
  const ledger = await P.readLedger(S);
  const bySeq = new Map(ledger.map((e) => [e.seq, e]));
  const replaced = new Map(ledger.filter((e) => typeof e.supersedes === "number").map((e) => [e.supersedes as number, e.seq]));
  assert.deepEqual(P.citedForQuestion(bySeq.get(ans.seq)!, bySeq, replaced, "2").map((e) => e.seq), [cov2.seq], "the gates read the revision");
  // The answers check holds no answer_support or coverage_missing for it; the revision still waits for its review like any record.
  const r = await checkLedgerAnswers(S, ["2"], ["2"]);
  const codes = r.defects.filter((d) => d.section === "question:2").map((d) => d.code);
  assert.ok(!codes.includes("answer_support") && !codes.includes("coverage_missing"), codes.join(", "));
  // Revised to another coverage (an object it names and does not cover): the answer is weighed again.
  const cov3 = ok(await rec(a0, coverage("2", ["input:disk.E01", "job:j000002/hits.txt"], [`E-${abs.seq}`, "job:j000001/hits.txt"], { supersedes: cov2.seq }))).entry;
  assert.notEqual(cov3.coverage, cov.coverage);
  assert.match((await problems()).get(ans.seq)?.[0] ?? "", new RegExp(`rests on E-${cov.seq}, superseded by #${cov3.seq}, and does not cite the correction`));
});

test("a revision to other questions is not carried", async () => {
  const { S, a0, a1 } = await run();
  await planned(a0, "2");
  const abs = ok(await rec(a0, { kind: "absence", value: "no remote tool on the disk", source: "the disk", evidence: "a search", refs: ["job:j000001/hits.txt"], control: { ref: "job:j000001/hits.txt", found: "the same search finds a planted row" }, answers: ["2"] })).entry;
  const cov = ok(await rec(a0, coverage("2", ["input:disk.E01"], [`E-${abs.seq}`, "job:j000001/hits.txt"]))).entry;
  const ans = ok(await rec(a1, { kind: "answer", section: "question:2", value: "No evidence of a remote tool was found on the disk", reasoning: `E-${cov.seq}`, ...A, result: "bounded_negative" })).entry;
  const moved = ok(await rec(a0, { ...coverage("3", ["input:disk.E01"], [`E-${abs.seq}`, "job:j000001/hits.txt"]), supersedes: cov.seq })).entry;
  assert.match((await P.answerProblems(await P.readLedger(S), await P.readDisputes(S))).get(ans.seq)?.[0] ?? "", new RegExp(`superseded by #${moved.seq}, and does not cite the correction`));
});
