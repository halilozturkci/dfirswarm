/**
 * One role-aware rule for an entry that rests on the kept output of a job that
 * did not succeed (docs/adr/0013; ledger-rules.ts failedJobIsDefect): an answer
 * that cites it as support stands on those bytes, so it is refused at the
 * append and flagged at the finish until the answer qualifies it; an answer
 * that cites it as a limitation is accepted at the append and passes the
 * answers check with no defect, the failed job being the limitation's subject.
 */
import assert from "node:assert/strict";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import * as P from "../extensions/protocol.ts";
import { checkLedgerAnswers } from "../scripts/check-answers.ts";
import { storePaths } from "../scripts/evidence-store.ts";
import { A, F, job, ok, partialParts, planned, rec, refused, run } from "./negative-bar-fixture.ts";

/** A job over the disk that ran to its end when it was read, and failed after: the status the answers check reads is the job's own. */
async function failLater(S: string, id: string): Promise<void> {
  const path = join(storePaths(S).jobs, id, "job.json");
  const record = JSON.parse(await readFile(path, "utf8")) as Record<string, unknown>;
  await writeFile(path, JSON.stringify({ ...record, status: "failed", exit: 1 }));
}

test("a limitation that rests on a failed job is the limitation's subject: accepted at the append, no defect at the finish; the same entry cited as support is refused and flagged", async () => {
  const c = await run();
  await job(c.S, "j000010", "hits.txt", { spec: { kind: "command", scope: "declared", inputs: ["input:disk.E01"], command: "search" } });
  await planned(c.a0, "1");
  const support = ok(await rec(c.a0, { kind: "finding", ...F, value: "alice logged on at 09:14", source: "the log", evidence: "line 12", refs: ["job:j000010/hits.txt"], answers: ["1"] })).entry;
  const limitation = ok(await rec(c.a0, { kind: "limitation", value: "The unallocated space was not carved", source: "the disk", evidence: "the carve", reason: "unavailable", refs: ["job:j000010/hits.txt"], answers: ["1"] })).entry;
  // The answer rests on the finding and is bounded by the limitation (an open part bounded by it joins the answer's limitations).
  const answer = ok(await rec(c.a1, { kind: "answer", section: "question:1", value: "alice, at 09:14; whether anything else ran is open", reasoning: `E-${support.seq} shows the logon; the rest is open (E-${limitation.seq})`, ...A, result: "partial", parts: partialParts(support.seq, `E-${limitation.seq}`) })).entry;
  assert.ok(answer.limitations?.some((l) => l.seq === limitation.seq), "the limitation is one of the answer's edges");
  // The job fails after both were recorded (a rerun, a reaped job): both entries now rest on a failed job's kept output.
  await failLater(c.S, "j000010");
  const entries = await P.readLedger(c.S);
  const failed = new Map<number, string[]>([[support.seq, ["job:j000010/hits.txt (failed)"]], [limitation.seq, ["job:j000010/hits.txt (failed)"]]]);
  const problems = P.answerProblems(entries, [], failed).get(answer.seq) ?? [];
  assert.ok(problems.some((p) => p.startsWith(`it rests on E-${support.seq}, which rests on the kept output of a job that did not succeed`)), `support is flagged: ${problems.join("; ")}`);
  assert.ok(!problems.some((p) => p.includes(`E-${limitation.seq}`)), `a limitation is not: ${problems.join("; ")}`);
  assert.equal(P.failedJobIsDefect("support"), true);
  assert.equal(P.failedJobIsDefect("limitation"), false);
  // The answers check reads the real job statuses: the one defect is the support edge's, and it names no limitation.
  const r = await checkLedgerAnswers(c.S, ["1"]);
  const defect = r.defects.filter((d) => d.code === "answer_support" && d.section === "question:1");
  assert.equal(defect.length, 1, r.lines.join("\n"));
  assert.match(defect[0]!.what, new RegExp(`rests on E-${support.seq}, which rests on the kept output of a job that did not succeed`));
  assert.doesNotMatch(defect[0]!.what, new RegExp(`is bounded by E-${limitation.seq}`));
  // Qualified, the support edge is no defect either; the limitation never needed it.
  const fixed = ok(await rec(c.a1, { kind: "answer", section: "question:1", value: "alice, at 09:14; whether anything else ran is open", reasoning: `E-${support.seq} shows the logon; the rest is open (E-${limitation.seq})`, ...A, result: "partial", parts: partialParts(support.seq, `E-${limitation.seq}`), qualifies: [{ ref: `E-${support.seq}`, why: "the lines before the failure are whole and the logon is among them" }], supersedes: answer.seq })).entry;
  const after = await checkLedgerAnswers(c.S, ["1"]);
  assert.deepEqual(after.defects.filter((d) => d.code === "answer_support"), [], after.lines.join("\n"));
  assert.ok(fixed.qualifies?.length === 1);
  // A qualifies on the limitation edge is still refused: the rule needs no new field.
  refused(await rec(c.a1, { kind: "answer", section: "question:1", value: "alice, at 09:14", reasoning: `E-${support.seq}`, ...A, result: "partial", parts: partialParts(support.seq, `E-${limitation.seq}`), qualifies: [{ ref: `E-${support.seq}`, why: "whole lines" }, { ref: `E-${limitation.seq}`, why: "the carve failed" }], supersedes: fixed.seq }), new RegExp(`qualifies names E-${limitation.seq}, which the answer does not cite as support`));
  // The same entry cited as support without qualifies is refused at the append.
  await planned(c.a0, "2");
  const other = ok(await rec(c.a0, { kind: "finding", ...F, value: "a second logon", source: "the log", evidence: "line 40", refs: ["job:j000001/hits.txt"], answers: ["2"] })).entry;
  refused(await rec(c.a1, { kind: "answer", section: "question:2", value: "a logon", reasoning: `E-${limitation.seq}; E-${other.seq}`, ...A, result: "established" }), new RegExp(`E-${limitation.seq} rests on the kept output of a job that did not succeed`));
});
