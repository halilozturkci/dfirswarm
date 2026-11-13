/**
 * The report's per-question chains (B14, docs/adr/0016): one screen of every
 * question at the top; in §2 each question from who asked it to what it cost
 * (an analyst's question with its revisions, its neutral wording, its
 * attachment's provenance and a clarification answered; the proposition its
 * first lead tested; its leads, the negative counted and the duplicate
 * footnoted; its result with why nothing speaks against it); the goal's,
 * the emergent, the proposed, the excluded and the withdrawn questions each
 * with why they matter; the unresolved ones; the cost per question and how
 * it is apportioned; and Appendix F with every register event.
 */
import assert from "node:assert/strict";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import * as P from "../extensions/protocol.ts";
import * as L from "../extensions/leads.ts";
import * as Q from "../extensions/questions.ts";
import { renderReportBody, renderReportBodyMarkdown } from "../scripts/report-body.ts";
import { recordAttachments } from "../scripts/questions-cli.ts";
import { apportion, conserveRound, holdingIntervals, questionCost } from "../scripts/question-cost.ts";
import { A, F, GOAL, job, ok, okq, rec, sha, dirs } from "./negative-bar-fixture.ts";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";

const GOAL_O = GOAL.replace("## Definition of done", "## Objectives\n\n- O-1: Establish who used the host and how.\n\n## Definition of done");
const ana: Q.Actor = { kind: "human", role: "analyst", person: "ana", name: "ANA", enrolled: true, os_user: "tester", host: "lab", via: "cli", identity: "claimed" };
const operator: Q.Actor = { kind: "human", role: "operator", person: "tester@lab", enrolled: false, os_user: "tester", host: "lab", via: "cli", identity: "claimed" };
const pause = () => new Promise((r) => setTimeout(r, 15));

/** The Markdown under one heading, to the next heading of the same level or above. */
function mdSlice(md: string, heading: string): string {
  const start = md.indexOf(`\n${heading}`);
  assert.ok(start >= 0, `no heading ${heading}`);
  const level = /^#+/.exec(heading)?.[0].length ?? 2;
  const rest = md.slice(start + 1);
  const next = rest.slice(1).search(new RegExp(`\\n#{1,${level}} `));
  return next >= 0 ? rest.slice(0, next + 1) : rest;
}

async function caseRun() {
  const base = await mkdtemp(join(tmpdir(), "report-questions-"));
  dirs.push(base);
  const S = join(base, "run");
  await P.initSandbox(S, { swarmId: "rq1", agentIds: ["a0", "a1", "a2"], capUsd: 5, wallClockMinutes: 30, goal: GOAL_O });
  await writeFile(join(S, "inputs.json"), JSON.stringify({ files: [{ path: "inputs/disk.E01", sha256: sha("disk"), bytes: 10 }] }));
  await job(S, "j000001", "hits.txt", { spec: { kind: "command", scope: "declared", inputs: ["input:disk.E01"], command: "search" } });
  await job(S, "j000002", "hits.txt", { spec: { kind: "command", scope: "declared", inputs: ["input:disk.E01"], command: "search" } });
  await Q.seedRegister(S);
  const ctx = (id: string) => ({ sandboxRoot: S, agentId: id });
  const [a0, a1, a2] = ["a0", "a1", "a2"].map(ctx);

  // An analyst's question, amended with a neutral wording, with a hint and an attachment, clarified.
  const q7 = okq(await Q.act(S, ana, "open", { text: "Did someone copy files to a USB stick?", why: "The client saw a stick on the desk", objective: "O-1", materiality: "material", hints: [{ ref: "input:disk.E01" }], attachments: ["job:j000002/hits.txt"] })).q as string;
  await recordAttachments(S, q7, ["job:j000002/hits.txt"], "ANA (ana), analyst, claimed");
  okq(await Q.act(S, ana, "amend", { q: q7, expected_rev: 1, text: "Were files copied to a removable drive?", why: "a stick is only one kind of drive", neutral: "Were files written to removable media?" }));
  const asked = okq(await Q.questionAsk(a1, q7, "Whose files: the owner's, or anyone's?"));
  okq(await Q.act(S, ana, "clarify_answer", { q: q7, clarify: asked.clarify as string, answer: "anyone's files" }));
  // A question the analyst withdrew.
  const q8 = okq(await Q.act(S, ana, "open", { text: "Was the printer used that day?", why: "a print job might show what was taken", objective: "O-1", materiality: "material" })).q as string;
  okq(await Q.act(S, ana, "withdraw", { q: q8, why: "the client found the printer's own log" }));

  // The goal's first question: a lead, a finding, an answer.
  const l1 = okq(await L.openLead(a0, { title: "Who logged on", why: "question 1", answers: ["1"], take: true, routes: [{ source: "input:disk.E01", method: "the logon records" }] })).lead.id;
  await pause();
  const f1 = ok(await rec(a0, { kind: "finding", ...F, value: "alice logged on at the console", source: "the security log", evidence: "record 12", refs: ["job:j000001/hits.txt"], answers: ["1"] })).entry;
  ok(await rec(a1, { kind: "answer", section: "question:1", value: "alice", reasoning: `E-${f1.seq}`, ...A, result: "established" }));
  okq(await L.closeLead(a0, l1, { disposition: "resolved", ref: `E-${f1.seq}` }));

  // An agent's question from what it found, and one outside every objective, proposed, and one excluded.
  const q9 = okq(await Q.questionOpen(a1, { text: "Was the drive attached before alice logged on?", why: "the order matters for who copied", objective: "O-1", materiality: "material", source_entry: `E-${f1.seq}` })).q as string;
  const q10 = okq(await Q.questionOpen(a2, { text: "What else ran that afternoon?", why: "worth knowing", materiality: "background", source_entry: `E-${f1.seq}` })).q as string;
  const q11 = okq(await Q.questionOpen(a2, { text: "Who installed the office suite?", why: "it came up", materiality: "background", source_entry: `E-${f1.seq}` })).q as string;
  okq(await Q.act(S, operator, "scope", { q: q11, scope: "excluded", why: "not the case's" }));

  // The analyst's question: its first lead states the proposition and its negation, and closes negative quickly.
  const l2 = okq(await L.openLead(a1, { title: "Removable media history", why: `${q7} asks it`, answers: [q7], take: true, proposition: "files were copied to a removable drive", negation: "no file was copied to a removable drive", routes: [{ source: "input:disk.E01", method: "device history and link files" }] })).lead.id;
  await L.attachJob(S, "a1", "j000001", l2);
  await pause();
  const absence = ok(await rec(a1, { kind: "absence", value: "a link file pointing at a removable drive", source: "inputs/disk.E01", evidence: "a search of the link files", refs: ["job:j000001/hits.txt"], control: { ref: "job:j000001/hits.txt", found: "the same search finds a planted row" }, answers: ["7"] })).entry;
  okq(await L.closeLead(a1, l2, { disposition: "negative", ref: `E-${absence.seq}` }));
  // A second seat opens the same work, and closes it as a duplicate.
  const l3 = okq(await L.openLead(a2, { title: "Removable media again", why: "the same", answers: [q7], take: true, overlap: "verification", overlap_why: "check it" } as never)).lead.id;
  await pause();
  okq(await L.closeLead(a2, l3, { disposition: "duplicate", ref: l2 }));
  // Then a finding after all, and the answer to the analyst's question, with why nothing speaks against it.
  const l4 = okq(await L.openLead(a1, { title: "Device registry keys", why: "a second route", answers: [q7], take: true, routes: [{ source: "input:disk.E01", method: "the device keys" }] })).lead.id;
  await pause();
  const f7 = ok(await rec(a1, { kind: "finding", ...F, value: "a removable drive was attached at 14:02", source: "the device keys", evidence: "key 3", refs: ["job:j000002/hits.txt"], answers: ["7"] })).entry;
  ok(await rec(a2, { kind: "answer", section: "question:7", question_rev: 2, value: "a removable drive was attached; nothing shows files were copied to it", reasoning: `E-${f7.seq}`, ...A, result: "established", contrary_none_why: "no entry says the drive was never attached" }));
  okq(await L.closeLead(a1, l4, { disposition: "resolved", ref: `E-${f7.seq}` }));
  // The operator accepts what is left of question 3.
  okq(await Q.act(S, operator, "accept", { q: "Q-3", expected_rev: 1, as: "not_determinable", why: "the disk keeps no record of deletions" }));

  // The tokens, as the gateway recorded each call: during a hold, and outside every hold.
  const events = (await L.readLeadEvents(S)).events;
  const at = (lead: string, ev: string) => Date.parse(events.find((e) => e.lead === lead && (e.ev === ev || (ev === "claim" && e.ev === "open" && e.holder)))!.at);
  const calls = [
    { at: new Date(at(l1, "claim") + 1).toISOString(), seat: "a0", input: 400, output: 100, cache_read: 0, cache_write: 0 },
    { at: new Date(at(l2, "claim") + 1).toISOString(), seat: "a1", input: 900, output: 100, cache_read: 0, cache_write: 0 },
    { at: new Date(at(l3, "claim") + 1).toISOString(), seat: "a2", input: 150, output: 50, cache_read: 0, cache_write: 0 },
    { at: new Date(Date.parse(events[0].at) - 60_000).toISOString(), seat: "a2", input: 250, output: 50, cache_read: 0, cache_write: 0 },
    { at: new Date(Date.parse(events[0].at) - 60_000).toISOString(), seat: "a2", refused: "no_token" },
  ];
  await mkdir(join(S, "traces"), { recursive: true });
  await writeFile(join(S, "traces", "model-gateway.jsonl"), calls.map((c) => JSON.stringify(c)).join("\n") + "\n");
  return { S, q7, q8, q9, q10, q11, l1, l2, l3, l4, f1, f7, absence };
}

test("the report's first layer: one screen of every question, then each question's chain from who asked it to what it cost", async () => {
  const r = await caseRun();
  const md = await renderReportBodyMarkdown(r.S);
  const html = (await renderReportBody(r.S)).html;

  // §1: one screen, every question, the ones not admitted said so.
  const s1 = mdSlice(md, "## 1. Summary for decision makers");
  assert.match(s1, /\| Question \| Status \| Asked by \| Answer \| Leads \| Accepted \| Tokens \|/);
  assert.match(s1, /\| Question 7 \| `answered` \| Q-7 · ANA \(ana\), analyst, claimed, via cli \| E-\d+ established \| 3: 1 negative, 1 duplicate, 1 resolved \| — \| 1,200 \|/);
  assert.match(s1, /\| Question 1 \| `answered` \| Q-1 · the goal \| E-\d+ established \| 1: 1 resolved \| — \| 500 \|/);
  assert.match(s1, /\| Question 3 \| `not answered` \| Q-3 · the goal \| none \| 0 \| not determinable \| 0 \|/);
  assert.match(s1, /\| Q-8 \| `withdrawn` \|/);
  assert.match(s1, /\| Q-10 \| `proposed, not admitted` \| Q-10 · agent a2, from E-\d+ \|/);
  assert.match(s1, /\| Q-11 \| `excluded` \|/);

  // §2: the analyst's question, whole.
  const s2 = mdSlice(md, "## 2. Request, scope and questions");
  const chain = mdSlice(s2, "#### Q-7 · Were files copied to a removable drive?");
  assert.match(chain, /Asked by:\*\* ANA \(ana\), analyst, claimed, via cli/);
  assert.match(chain, /Why:\*\* The client saw a stick on the desk/);
  assert.match(chain, /Under:\*\* objective O-1: Establish who used the host and how\./);
  assert.match(chain, /r1, \d{4}-.*by ANA \(ana\), analyst, claimed, via cli: \*\*Did someone copy files to a USB stick\?\*\*/, "the first revision, verbatim");
  assert.match(chain, /r2, \d{4}-.*\(a stick is only one kind of drive\): \*\*Were files copied to a removable drive\?\*\*/);
  assert.match(chain, /Neutral formulation:\*\* Were files written to removable media\? \(by ANA/);
  assert.match(chain, /Hints:\*\* `input:disk\.E01`/);
  assert.match(chain, /Attachments:\*\* `job:j000002\/hits\.txt`: recorded as external material \(E-\d+\), supplied by ANA \(ana\), analyst, claimed at .* from an attachment to Q-7/);
  assert.match(chain, /Clarifications:\*\* C-1: a1 asked .*Whose files: the owner's, or anyone's\?\. Answered by ANA \(ana\), analyst, claimed, via cli at .*: anyone's files/);
  assert.match(chain, /Proposition tested:\*\* files were copied to a removable drive; its negation: no file was copied to a removable drive \(L-\d+\)/);
  assert.match(chain, /\*\*Leads \(3\)\*\*/);
  assert.match(chain, new RegExp(`\\*\\*${r.l4}\\*\\* Device registry keys.*Ended resolved \\(a1\\): E-${r.f7.seq}`));
  assert.doesNotMatch(chain, /Removable media history: /, "the negative lead is counted here, not listed");
  assert.match(chain, new RegExp(`1 lead closed negative \\(1 quick, 1 not reviewed by another agent\\): ${r.l2}, each whole in Appendix F`));
  assert.match(chain, new RegExp(`> Duplicates: ${r.l3} \\(of ${r.l2}, closed by a2\\)`), "a duplicate is footnoted");
  assert.match(chain, /`answered` established: E-\d+ \(§5\)\. Nothing recorded against it, and why: no entry says the drive was never attached/);
  assert.match(chain, /\*\*Cost:\*\* 1,200 tokens \(60\.0% of the run's 2,000 tokens\); by lead: L-\d+ 1,000 tokens, L-\d+ 200 tokens, L-\d+ 0 tokens/);

  // The other kinds, each with why it matters.
  assert.match(s2, /### Original questions \(the goal's\) \(6\)\n\nWhat the goal asked\./);
  assert.match(s2, /### Asked during the run \(1\)\n\nQuestions a person put while the swarm worked/);
  assert.match(mdSlice(s2, `#### ${r.q9} · Was the drive attached before alice logged on?`), new RegExp(`Asked by:\\*\\* agent a1, from E-${r.f1.seq}`));
  assert.match(s2, /### Emergent questions \(found in the evidence\) \(1\)/);
  assert.match(s2, /### Proposed, not admitted \(1\)\n\nQuestions outside the declared objectives, waiting for the operator's triage/);
  assert.match(mdSlice(s2, `#### ${r.q11} · Who installed the office suite?`), /Scope:\*\* proposed at .*\n\s+- excluded at .*: excluded by tester@lab, operator, claimed, not enrolled, via cli: not the case's/);
  assert.match(mdSlice(s2, `#### ${r.q8} · Was the printer used that day?`), /Withdrawn:\*\* by ANA \(ana\), analyst, claimed, via cli at .*: the client found the printer's own log/);
  // The goal's third question, accepted: unresolved, and why.
  const q3 = mdSlice(s2, "#### Q-3 · What was deleted?");
  assert.match(q3, /\*\*Accepted\*\* as not determinable by tester@lab, operator, claimed, not enrolled, via cli at .* \(r1\): the disk keeps no record of deletions\. It stands/);
  const unresolved = mdSlice(s2, "### Unresolved");
  assert.match(unresolved, /Q-3: `not answered` Accepted by the operator as not determinable/);
  assert.doesNotMatch(unresolved, /Q-7:/, "a settled question is not unresolved");
  assert.doesNotMatch(unresolved, /Q-8:|Q-10:|Q-11:/, "only questions in scope are unresolved");

  // How the cost is counted, and it adds up.
  assert.match(s2, /\*\*How the cost is counted\.\*\* Each model call the gateway recorded .* Of the run's 2,000 tokens, 1,700 tokens went to questions \(0 tokens of it given to what a call made holding no lead named: a review, a record, an act on a lead\), 0 tokens to leads that name no question, 0 tokens to the finish and the report's writing, 300 tokens to calls made while the seat held no lead and named nothing \(other 300 tokens; by seat: a2 300 tokens\)/);

  // §4 counts the negative and footnotes the duplicate; Appendix F has every event, every lead whole.
  const s4 = mdSlice(md, "### How the investigation proceeded");
  assert.match(s4, new RegExp(`and 1 lead closed negative \\(1 quick\\): ${r.l2}, in Appendix F\\.`));
  assert.match(s4, new RegExp(`Duplicates: ${r.l3} \\(of ${r.l2}\\); in Appendix F\\.`));
  const f = mdSlice(md, "## Appendix F: The question and lead registers");
  const register = (await Q.questionsSnapshot(r.S)).state.events;
  for (const e of register) assert.match(f, new RegExp(`\\| ${e.seq} \\| ${e.at.replace(/[.]/g, "\\.")} \\|`), `question event ${e.seq}`);
  for (const id of [r.l1, r.l2, r.l3, r.l4]) assert.match(f, new RegExp(`#### ${id} · `));
  const leadEvents = (await L.readLeadEvents(r.S)).events;
  for (const e of leadEvents) assert.ok(f.includes(`${e.seq} · ${e.at} · ${e.by} · ${e.ev}`), `lead event ${e.seq}`);
  assert.match(mdSlice(f, "### Negative leads (1)"), new RegExp(`\\*\\*${r.l2}\\*\\* Removable media history.*Routes planned: input:disk\\.E01 \\(device history and link files\\)\\..*Quick negative:\\*\\* closed \\d+ s after it was taken.*Review: \\*\\*not reviewed\\*\\*`));
  assert.match(mdSlice(f, "### Duplicate leads (1)"), new RegExp(`\\*\\*${r.l3}\\*\\* Removable media again`));

  // Anchors resolve, and two renders are the same bytes.
  for (const m of html.matchAll(/href="#(qc-[^"]+|reg-[^"]+|chains)"/g)) assert.ok(html.includes(`id="${m[1]}"`), `#${m[1]}`);
  assert.equal((await renderReportBody(r.S)).html, html);
});

test("Appendix F renders every lead event losslessly: one with no lead (an interpretation) and a close's acquisition ask", async () => {
  const base = await mkdtemp(join(tmpdir(), "appendixf-"));
  dirs.push(base);
  const S = join(base, "run");
  await P.initSandbox(S, { swarmId: "sapp", agentIds: ["a1"] });
  await writeFile(join(S, "SWARM.md"), "# Goal\n\n### Questions\n\n1. What happened?\n");
  await mkdir(join(S, "leads"), { recursive: true });
  const raw = [
    { v: 1, seq: 1, at: "2026-01-01T00:00:00Z", by: "a1", ev: "open", lead: "L-1", title: "Look", why: "w", answers: ["1"], material: true, holder: "a1" },
    { v: 1, seq: 2, at: "2026-01-01T00:01:00Z", by: "a1", ev: "job", lead: "L-1", job: "j000001" },
    // An interpretation: it names a job, not a lead, and says how the rest of the output was treated.
    { v: 1, seq: 3, at: "2026-01-01T00:02:00Z", by: "a1", ev: "interpret", job: "j000001", entry: 4, kind: "finding", rest: "the remaining 900 rows were scanned and hold nothing of note" },
    // A close that asks for evidence the run does not have (an acquisition ask).
    { v: 1, seq: 4, at: "2026-01-01T00:03:00Z", by: "a1", ev: "close", lead: "L-1", disposition: "needs_operator", ref: "R-1", ask: { kind: "acquisition", source: "the firewall logs", where: "the SOC", expected_value: "the egress record", urgency: "high", questions: ["1"], owner: "the SOC", authority_needed: "a data request" } },
  ];
  let prev = "genesis";
  const lines = raw.map((e) => {
    const hash = L.leadEventHash(e as never, prev);
    const line = JSON.stringify({ ...e, prev, hash });
    prev = hash;
    return line;
  });
  await writeFile(join(S, "leads", "leads.jsonl"), lines.join("\n") + "\n");
  const md = await renderReportBodyMarkdown(S);
  const f = mdSlice(md, "## Appendix F: The question and lead registers");
  assert.match(f, /Events not tied to a lead \(1\)/, "an event with no lead has its own place");
  assert.match(f, /the remaining 900 rows were scanned and hold nothing of note/, "the interpretation's `rest` is rendered, not dropped");
  assert.match(f, /the firewall logs/, "a close's acquisition ask is rendered whole");
  assert.match(f, /a data request/);
});

test("the cost apportioning: a call to the leads its seat held then, split evenly, and to their questions; calls outside a hold go to no question", () => {
  const t = (s: number) => new Date(Date.UTC(2026, 0, 1, 0, 0, s)).toISOString();
  const ev = (seq: number, at: number, ev: string, lead: string, extra: Record<string, unknown> = {}) => ({ v: 1, seq, at: t(at), by: "a1", ev, lead, prev: "", hash: "", ...extra }) as unknown as L.LeadEvent;
  const events = [ev(1, 0, "open", "L-1", { holder: "a1" }), ev(2, 10, "open", "L-2"), ev(3, 20, "claim", "L-2", { holder: "a1" }), ev(4, 30, "close", "L-1"), ev(5, 40, "release", "L-2")];
  const iv = holdingIntervals(events);
  assert.deepEqual(iv.get("L-1"), [{ seat: "a1", from: Date.parse(t(0)), to: Date.parse(t(30)) }]);
  const calls = [5, 25, 35, 50].map((s) => ({ seat: "a1", at: Date.parse(t(s)), tokens: 100 }));
  const cost = apportion(calls, iv, (lead) => (lead === "L-1" ? ["Q-1"] : ["Q-1", "Q-2"]), "gateway");
  assert.equal(cost.total, 400);
  // 5 s: L-1 alone → Q-1 100; 25 s: L-1 and L-2 → Q-1 50 + (50 split) 25, Q-2 25; 35 s: L-2 → Q-1 50, Q-2 50; 50 s: nothing held.
  assert.deepEqual(Object.fromEntries(cost.byQuestion), { "Q-1": 225, "Q-2": 75 });
  assert.deepEqual(Object.fromEntries(cost.unheld), { a1: 100 });
  assert.equal([...cost.byQuestion.values()].reduce((a, b) => a + b, 0) + cost.noQuestion + [...cost.unheld.values()].reduce((a, b) => a + b, 0), cost.total, "the figures add up to the total");
});

test("the host fallback keeps a seat's budget even when the trace has no row for it, in an explicit bucket", async () => {
  const base = await mkdtemp(join(tmpdir(), "cost-host-"));
  dirs.push(base);
  const S = join(base, "run");
  await P.initSandbox(S, { swarmId: "shost", agentIds: ["a1", "a2"] });
  // No gateway log; budget for two seats, trace rows for only one.
  await mkdir(join(S, "traces"), { recursive: true });
  await writeFile(join(S, "budget.json"), JSON.stringify({ agents: { a1: { tokens: 1000 }, a2: { tokens: 900 } } }));
  await writeFile(join(S, "traces", "events.jsonl"), [{ ts: "2026-01-01T00:00:01Z", agent: "a1" }, { ts: "2026-01-01T00:00:02Z", agent: "a1" }].map((r) => JSON.stringify(r)).join("\n") + "\n");
  const cost = await questionCost(S, [], () => []);
  assert.equal(cost.source, "trace");
  assert.deepEqual(Object.fromEntries(cost.noTrace), { a2: 900 }, "a seat with a budget but no trace row is in the no-trace bucket, not dropped");
  assert.equal(cost.total, 1900, "the run's total is the whole budget, not only the placed part");
});

test("conserveRound: whole shares sum to the whole of the total, a 1001 split as 501 and 500", () => {
  assert.deepEqual(conserveRound([500.5, 500.5]), [501, 500]);
  assert.deepEqual(conserveRound([1 / 3, 1 / 3, 1 / 3].map((x) => x * 100)), [34, 33, 33]);
  const vals = [10.4, 10.4, 10.2];
  const whole = conserveRound(vals);
  assert.equal(whole.reduce((a, b) => a + b, 0), Math.round(vals.reduce((a, b) => a + b, 0)), "the shares conserve the rounded total");
});
