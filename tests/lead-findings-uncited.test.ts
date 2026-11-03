/**
 * An answer that leaves out what the record ties to its question (the run
 * s993d40, a CTF case of six questions: one answer left out two methods the
 * ledger held as findings, attested by another seat, under that question's
 * leads, and one of them named a second question whose answer never
 * reached it either). The answers check warns, never holds: a standing
 * finding or event, not disputed, which the answer does not reach,
 * directly or through the entries it cites, and which two seats hold
 * (another seat attested it, or two recorded it) and the lead register
 * recorded under a lead linked to the question, or which names the
 * question in its answers, or whose rel links it to an entry the answer
 * cites; or one seat's that names the question and that another question's
 * answer relies on. Registers and refs only. Synthetic runs only.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { join, resolve } from "node:path";
import { test } from "node:test";
import * as FIN from "../extensions/finish.ts";
import * as L from "../extensions/leads.ts";
import * as P from "../extensions/protocol.ts";
import { ANSWERS_MARK, checkLedgerAnswers } from "../scripts/check-answers.ts";
import { finishGate } from "../scripts/finish-gate.ts";
import { A, covers, ESTABLISHED, F, ok, planned, rec, run } from "./negative-bar-fixture.ts";

const ROOT = resolve(import.meta.dirname, "..");

const GOAL = [
  "## Goal",
  "",
  "Examine the host.",
  "",
  "### Questions",
  "",
  "1. How did the data leave the host?",
  "2. Which account was used?",
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

const WARN = /\(question:1\) leaves out what the record ties to Q-1:/;

type Ctx = { sandboxRoot: string; agentId: string };

/** The finish line as the harness runs it: the goal's answers check, then the gate, then the verdict. */
async function finish(S: string) {
  const r = await checkLedgerAnswers(S, ["1", "2"]);
  const checks = { total: 1, passed: r.ok ? 1 : 0, source: "registry", checks: [{ cmd: "check-answers --sections 1,2", ok: r.ok, out: r.lines.join("\n"), answers: { outcomes: r.outcomes, results: r.results, dispositions: r.dispositions, best_candidate: r.best_candidate, warnings: r.warnings, named: [] } }] };
  const gate = await finishGate(S, checks);
  return { check: r, gate, verdict: P.finishLineVerdict({ ...checks, gate }, false) };
}

const finding = (value: string, o: Record<string, unknown> = {}) => ({ kind: "finding", ...F, value, source: "the disk", evidence: "a record", refs: ["job:j000001/hits.txt"], answers: ["1"], ...o });

async function attest(c: Ctx, seq: number): Promise<void> {
  const r = await P.attestEntry(c, { seq, how: "re-read the record from job:j000001/hits.txt" });
  assert.ok(r.ok, (r as { reason?: string }).reason);
}

async function answer(c: Ctx, section: string, cites: number[], o: Record<string, unknown> = {}) {
  const a = ok(await rec(c, { kind: "answer", section, value: `the answer, on ${cites.map((n) => `E-${n}`).join(", ")}`, reasoning: cites.map((n) => `E-${n}`).join("; "), ...A, confidence: "high", result: "established", ...o })).entry;
  return a;
}

test("the register records an entry under a lead by the lead's acts: its jobs' interpretations and every close or confirmation that names it, for each question the lead serves", () => {
  const at = "2026-09-29T00:00:00Z";
  const ev = (seq: number, e: Partial<L.LeadEvent>): L.LeadEvent => ({ v: 1, seq, at, by: "a0", ev: "open", prev: "", hash: "", ...e }) as L.LeadEvent;
  const s = L.foldLeads([
    ev(1, { ev: "open", lead: "L-1", answers: ["1", "Q-3"], title: "t" }),
    ev(2, { ev: "job", lead: "L-1", job: "j000001" }),
    ev(3, { ev: "interpret", job: "j000001", entry: 5, kind: "finding" }),
    ev(4, { ev: "close", lead: "L-1", disposition: "resolved", ref: "E-7", result_refs: ["E-8", "job:j000001/hits.txt"] }),
    ev(5, { ev: "reopen", lead: "L-1", why: "new evidence", cause: "evidence_added" }),
    ev(6, { ev: "close", lead: "L-1", disposition: "resolved", ref: "E-9" }),
    ev(7, { ev: "confirm", lead: "L-1", ref: "E-10" }),
    ev(8, { ev: "open", lead: "L-2", answers: ["3"], title: "u" }),
    ev(9, { ev: "close", lead: "L-2", disposition: "duplicate", ref: "L-1" }),
    ev(10, { ev: "interpret", job: "j000009", entry: 11, kind: "finding" }),
  ]);
  const got = L.questionLeadEntries(s);
  const plain = (m: Map<number, string[]> | undefined) => [...(m ?? [])].sort((x, y) => x[0] - y[0]);
  assert.deepEqual(plain(got.get("1")), [5, 7, 8, 9, 10].map((n) => [n, ["L-1"]]));
  assert.deepEqual(plain(got.get("3")), [5, 7, 8, 9, 10].map((n) => [n, ["L-1"]]), "Q-3 is question 3; a duplicate's ref names a lead, not an entry");
  assert.equal(got.size, 2, "a job run under no lead records nothing under one");
});

test("an answer that leaves out findings the record ties to its question is warned of, each named with its lead or its own tie, never one seat's no other answer relies on, in the answers check, its machine line, the finish line's note and finish status; the done proceeds; citing them clears it", async () => {
  const r = await run({ goal: GOAL });
  const L1 = await planned(r.a0, "1");
  assert.ok((await L.attachJob(r.S, "a0", "j000001", L1)).ok);
  // Reached through an entry the answer cites (rel derived_from): not warned of.
  const through = ok(await rec(r.a0, finding("the archive was built from the export folder"))).entry;
  const cited = ok(await rec(r.a0, finding("the archive left over HTTPS to a file host", { rel: [{ to: through.seq, kind: "derived_from" }] }))).entry;
  // Under the lead: an interpretation another seat attested, an event two seats recorded, and what is never warned of.
  const attested = ok(await rec(r.a0, finding("a second copy went to a USB stick"))).entry;
  const event = { kind: "event", ts: "2024-01-01T09:14:00Z", value: "the USB stick was mounted", source: "the disk", evidence: "the USB history", refs: ["job:j000001/hits.txt"], answers: ["1"] };
  const twice = ok(await rec(r.a0, event)).entry;
  assert.equal(ok(await rec(r.a2, event)).merged, true, "the same event again from another seat is a second author");
  const alone = ok(await rec(r.a0, finding("a mail client was open"))).entry;
  // One seat's, under the lead, naming no question: its author tied it to none, so one seat is not enough.
  const unnamed = ok(await rec(r.a0, finding("the mail client's cache was 2 MB", { answers: undefined }))).entry;
  const disputed = ok(await rec(r.a0, finding("the archive was encrypted"))).entry;
  const replaced = ok(await rec(r.a0, finding("the archive was 4 MB"))).entry;
  const lim = ok(await rec(r.a0, { kind: "limitation", value: "The proxy log is not in the case", source: "the case", evidence: "the inventory", reason: "unavailable", answers: ["1"] })).entry;
  for (const seq of [through.seq, cited.seq, attested.seq, disputed.seq, replaced.seq]) await attest(r.a3, seq);
  assert.ok((await P.disputeEntry(r.a1, { seq: disputed.seq, why: "the header says it is not" })).ok);
  const correction = ok(await rec(r.a0, finding("the archive was 5 MB", { supersedes: replaced.seq }))).entry;
  await attest(r.a3, correction.seq);
  assert.ok((await L.recordInterpretations(r.S, "a0", attested.seq, ["j000001"])).ok);
  for (const seq of [alone.seq, unnamed.seq, disputed.seq, replaced.seq, lim.seq]) assert.ok((await L.recordInterpretations(r.S, "a0", seq, ["j000001"])).ok);
  assert.ok((await L.closeLead(r.a0, L1, { disposition: "resolved", ref: `E-${cited.seq}`, result_refs: [`E-${twice.seq}`, `E-${through.seq}`] })).ok);
  // Question 2's lead and answer: what they hold is not question 1's.
  const L2 = await planned(r.a1, "2");
  const g = ok(await rec(r.a1, finding("the account was svc_backup", { answers: ["2"] }))).entry;
  const other = ok(await rec(r.a1, finding("svc_backup's password was reset that morning", { answers: ["2"] }))).entry;
  await attest(r.a3, g.seq);
  await attest(r.a3, other.seq);
  assert.ok((await L.closeLead(r.a1, L2, { disposition: "resolved", ref: `E-${g.seq}`, result_refs: [`E-${other.seq}`] })).ok);
  const a1 = await answer(r.a1, "question:1", [cited.seq]);
  const a2 = await answer(r.a2, "question:2", [g.seq, other.seq]);
  await covers(r.a0, "1");
  await covers(r.a0, "2");
  for (const [c, a] of [[r.a2, a1], [r.a3, a2]] as const) {
    const att = await P.attestEntry(c, { seq: a.seq, how: "re-derived the cited findings", ...ESTABLISHED });
    assert.ok(att.ok, (att as { reason?: string }).reason);
  }

  // The correction names Q-1 and another seat attested it, though no act of the lead register names it: left out, by its own tie.
  // One seat's finding that names Q-1 counts only where another question's answer relies on it: none does here, so neither it nor one naming no question is listed.
  const want = `answer #${a1.seq} (question:1) leaves out what the record ties to Q-1: E-${attested.seq} (a finding under ${L1}), E-${twice.seq} (an event under ${L1}), E-${correction.seq} (a finding that names Q-1): cite them or say why they do not bear on it. record the answer again with supersedes=${a1.seq}, citing each as E-<seq> in its reasoning (or among its contrary or limitations), or saying there why each does not bear on Q-1; an entry the answer cites that names one (rel, a coverage record's result_refs) counts`;
  const f = await finish(r.S);
  assert.equal(f.check.ok, true, f.check.lines.join("\n"));
  assert.deepEqual(f.check.dispositions, { "question:1": "established", "question:2": "established" });
  assert.deepEqual(f.check.warnings, [want], "one warning, for question 1 alone, naming exactly the three entries");
  assert.ok(f.check.lines.includes(`WARN: ${want}`));
  // The finish line: completed, the warning in its note; readiness ready, the warning apart from its items; finish status shows it.
  assert.deepEqual(f.gate.warnings, [want]);
  assert.equal(f.verdict.proceed && f.verdict.outcome, "completed", JSON.stringify(f.verdict));
  assert.equal((f.verdict as { note?: string }).note, `warnings (not held on): ${want}`);
  const ready = await FIN.readiness(r.S);
  assert.deepEqual([ready.ready, ready.items, ready.warnings], [true, [], [want]], JSON.stringify(ready));
  const status = await FIN.finishStatus(r.a1);
  assert.equal(status.ready, true);
  assert.deepEqual(status.warnings, [want]);
  // The CLI prints it and carries it in its machine line, and exits 0.
  const cli = spawnSync("node", ["--experimental-strip-types", "--no-warnings", join(ROOT, "scripts", "check-answers.ts"), "--sections", "1,2"], { cwd: r.S, encoding: "utf8" });
  assert.equal(cli.status, 0, cli.stdout + cli.stderr);
  assert.ok(cli.stdout.includes(`WARN: ${want}\n`));
  const machine = JSON.parse(cli.stdout.split("\n").find((l) => l.startsWith(`${ANSWERS_MARK} `))!.slice(ANSWERS_MARK.length + 1)) as { warnings?: string[] };
  assert.deepEqual(machine.warnings, [want]);

  // Citing them clears it: one in the reasoning, the other through a finding the answer cites that names it.
  const bridge = ok(await rec(r.a0, finding("the USB copy and the upload were the same archive", { rel: [{ to: twice.seq, kind: "supports" }] }))).entry;
  const again = await answer(r.a1, "question:1", [cited.seq, attested.seq, bridge.seq, correction.seq], { supersedes: a1.seq });
  const att = await P.attestEntry(r.a2, { seq: again.seq, how: "re-derived the cited findings", ...ESTABLISHED });
  assert.ok(att.ok, (att as { reason?: string }).reason);
  const after = await finish(r.S);
  assert.deepEqual(after.check.warnings, [], after.check.warnings.join("\n"));
  assert.equal((after.verdict as { note?: string }).note, undefined, JSON.stringify(after.verdict));
  assert.deepEqual((await FIN.readiness(r.S)).warnings, []);
  assert.equal((await FIN.finishStatus(r.a1)).warnings, undefined);
});

test("every entry left out is listed, however many; a broken lead register says nothing of the leads, and the ledger's own tie still counts", async () => {
  const r = await run({ goal: GOAL });
  const L1 = await planned(r.a0, "1");
  assert.ok((await L.attachJob(r.S, "a0", "j000001", L1)).ok);
  const first = ok(await rec(r.a0, finding("method 0 of the exfiltration"))).entry;
  await attest(r.a3, first.seq);
  const left: number[] = [];
  for (let i = 1; i <= 25; i++) {
    const e = ok(await rec(r.a0, finding(`method ${i} of the exfiltration`))).entry;
    await attest(r.a3, e.seq);
    assert.ok((await L.recordInterpretations(r.S, "a0", e.seq, ["j000001"])).ok);
    left.push(e.seq);
  }
  assert.ok((await L.closeLead(r.a0, L1, { disposition: "resolved", ref: `E-${first.seq}` })).ok);
  const a = await answer(r.a1, "question:1", [first.seq]);
  const c = await checkLedgerAnswers(r.S, ["1"]);
  const w = c.warnings.filter((x) => WARN.test(x));
  assert.equal(w.length, 1);
  assert.equal(w[0].split(": cite them")[0], `answer #${a.seq} (question:1) leaves out what the record ties to Q-1: ${left.map((n) => `E-${n} (a finding under ${L1})`).join(", ")}`, "all 25, none cut");
  // A lead register whose chain is broken says nothing of the leads (the finish gate names it); each finding names Q-1 itself, and that tie is the ledger's.
  const { readFile, writeFile } = await import("node:fs/promises");
  const log = join(r.S, L.LEADS_LOG);
  const text = await readFile(log, "utf8");
  await writeFile(log, text.replace(/"title":"Work question 1"/, '"title":"Work question one"'));
  const broken = (await checkLedgerAnswers(r.S, ["1"])).warnings.filter((x) => WARN.test(x));
  assert.equal(broken.length, 1, broken.join("\n"));
  assert.equal(broken[0].split(": cite them")[0], `answer #${a.seq} (question:1) leaves out what the record ties to Q-1: ${left.map((n) => `E-${n} (a finding that names Q-1)`).join(", ")}`);
});

test("a rel ties an entry to the question only when it weighs what the answer cites (supports, contradicts, a delta): one that duplicates it, or is derived from it, ties nothing", async () => {
  const r = await run({ goal: GOAL });
  const L1 = await planned(r.a0, "1");
  await planned(r.a0, "2");
  const base = ok(await rec(r.a0, finding("the data left over the proxy"))).entry;
  const dup = ok(await rec(r.a0, finding("the data left over the proxy, as its log repeats it", { answers: ["2"], rel: [{ to: base.seq, kind: "duplicates" }] }))).entry;
  const derived = ok(await rec(r.a0, finding("the proxy's session, carved from its log", { answers: ["2"], rel: [{ to: base.seq, kind: "derived_from" }] }))).entry;
  const sup = ok(await rec(r.a0, finding("the firewall passed the proxy's upload", { answers: ["2"], rel: [{ to: base.seq, kind: "supports" }] }))).entry;
  for (const seq of [base.seq, dup.seq, derived.seq, sup.seq]) await attest(r.a3, seq);
  assert.ok((await L.closeLead(r.a0, L1, { disposition: "resolved", ref: `E-${base.seq}` })).ok);
  const a = await answer(r.a1, "question:1", [base.seq]);
  const w = (await checkLedgerAnswers(r.S, ["1"])).warnings.filter((x) => WARN.test(x));
  assert.equal(w.length, 1, w.join("\n"));
  assert.equal(w[0].split(": cite it")[0], `answer #${a.seq} (question:1) leaves out what the record ties to Q-1: E-${sup.seq} (a finding whose rel supports E-${base.seq}, which the answer cites)`);
});
