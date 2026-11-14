/**
 * The negative bar (extensions/negative-bar.ts, docs/adr/0013): every result
 * an answer may state and what each rests on; the coverage record, required
 * on a material negative and a "not determinable", every field of it; the
 * hub's object coverage (the jobs' declared inputs, by place and digest,
 * against the record's objects and the catalogue's generations inside
 * them); the route plan (warned at the first lead, required before a
 * negative closes, its unexamined sources named); the quick-negative flag;
 * the review of a material negative by another seat, which the finish line
 * waits for; the wording rule; and the operator's acceptance, refused while
 * a route is open or a negative is unreviewed, bound to its revision, and
 * limiting the run.
 */
import assert from "node:assert/strict";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import * as P from "../extensions/protocol.ts";
import * as L from "../extensions/leads.ts";
import * as Q from "../extensions/questions.ts";
import * as NB from "../extensions/negative-bar.ts";
import { checkLedgerAnswers } from "../scripts/check-answers.ts";
import { finishGate } from "../scripts/finish-gate.ts";
import { renderReportBodyMarkdown } from "../scripts/report-body.ts";
import { A, coverage, F, job, ok, okq, partialParts, planned, rec, refused, REVIEW, run, sha } from "./negative-bar-fixture.ts";

test("every result an answer may state, what each rests on, and how the answers check reads it", async () => {
  const { S, a0, a1 } = await run();
  const f1 = ok(await rec(a0, { kind: "finding", ...F, value: "alice logged on", source: "a log", evidence: "line 1", refs: ["job:j000001/hits.txt"], answers: ["1"] })).entry;
  const absence4 = ok(await rec(a0, { kind: "absence", value: "a start time", source: "inputs/disk.E01", evidence: "a search", refs: ["job:j000001/hits.txt"], control: { ref: "job:j000001/hits.txt", found: "the same search finds a planted row" }, answers: ["4"] })).entry;
  // The result is stated on every question's answer; the vocabulary is the whole of it.
  refused(await rec(a1, { kind: "answer", section: "question:1", value: "alice", reasoning: `E-${f1.seq}`, ...A }), /states its result: established .* premise_not_supported/);
  refused(await rec(a1, { kind: "answer", section: "question:1", value: "alice", reasoning: `E-${f1.seq}`, ...A, result: "confirmed" }), /result is one of established, partial, bounded_negative, not_determinable, out_of_scope, premise_not_supported/);
  assert.deepEqual([...NB.ANSWER_RESULTS], ["established", "partial", "bounded_negative", "not_determinable", "out_of_scope", "premise_not_supported"]);
  // established and partial rest on a finding.
  refused(await rec(a1, { kind: "answer", section: "question:4", value: "at ten", reasoning: `E-${absence4.seq}`, ...A, result: "established" }), /a result established rests on a standing finding/);
  const established = ok(await rec(a1, { kind: "answer", section: "question:1", value: "alice", reasoning: `E-${f1.seq}`, ...A, result: "established" })).entry;
  assert.equal(established.result, "established");
  const f5 = ok(await rec(a0, { kind: "finding", ...F, value: "the tool ran as some account", source: "a log", evidence: "line 2", refs: ["job:j000001/hits.txt"], answers: ["5"] })).entry;
  // A partial answer names what is open (docs/adr/0013, "Claim and open-part rows"): with no open part it is refused.
  refused(await rec(a1, { kind: "answer", section: "question:5", value: "an administrator, not named", reasoning: `E-${f5.seq}`, ...A, result: "partial" }), /^record it established or name what is open: /);
  const lim5 = ok(await rec(a0, { kind: "limitation", value: "the log does not name the account", source: "a log", evidence: "its fields", reason: "unavailable", answers: ["5"] })).entry;
  ok(await rec(a1, { kind: "answer", section: "question:5", value: "an administrator, not named", reasoning: `E-${f5.seq}`, ...A, result: "partial", parts: partialParts(f5.seq, `E-${lim5.seq}`) }));
  // out_of_scope rests on what it cites, a limitation included.
  const lim6 = ok(await rec(a0, { kind: "limitation", value: "no network capture in the case", source: "the case's evidence", evidence: "inputs.json lists none", reason: "unavailable", answers: ["6"] })).entry;
  ok(await rec(a1, { kind: "answer", section: "question:6", value: "the case holds no network evidence", reasoning: `E-${lim6.seq}`, ...A, result: "out_of_scope" }));
  // premise_not_supported answers.
  const f3 = ok(await rec(a0, { kind: "finding", ...F, value: "the file listing shows nothing deleted", source: "a listing", evidence: "row 9", refs: ["job:j000001/hits.txt"], answers: ["3"] })).entry;
  ok(await rec(a1, { kind: "answer", section: "question:3", value: "nothing shows anything was deleted", reasoning: `E-${f3.seq}`, ...A, result: "premise_not_supported" }));
  // not_determinable and bounded_negative: a coverage record and a route plan (below); inconclusive is the old word.
  refused(await rec(a1, { kind: "answer", section: "question:4", value: "not known", reasoning: `E-${absence4.seq}`, ...A, result: "established", inconclusive: true }), /inconclusive is the old word for result not_determinable/);
  await planned(a0, "4");
  const cov4 = ok(await rec(a0, coverage("4", ["input:disk.E01"], [`E-${absence4.seq}`]))).entry;
  const nd = ok(await rec(a1, { kind: "answer", section: "question:4", value: "when it started cannot be determined", reasoning: `E-${absence4.seq}; E-${cov4.seq}`, ...A, inconclusive: true })).entry;
  assert.deepEqual([nd.result, nd.inconclusive], ["not_determinable", true]);
  const r = await checkLedgerAnswers(S, ["1", "3", "4", "5", "6"]);
  assert.deepEqual(r.outcomes, { "question:1": "answered", "question:3": "answered", "question:4": "inconclusive", "question:5": "limited", "question:6": "limited" });
  assert.deepEqual(r.results, { "question:1": "established", "question:3": "premise_not_supported", "question:4": "not_determinable", "question:5": "partial", "question:6": "out_of_scope" });
  assert.ok(r.defects.some((d) => d.code === "negative_unreviewed" && d.section === "question:4"), "the not_determinable waits for its review");
  // An answer recorded before results (the committed fixture's) reads as it always did.
  assert.equal(NB.answerResult({ kind: "answer", inconclusive: true }), "not_determinable");
  assert.equal(NB.answerResult({ kind: "answer" }), null);
});

test("a coverage record says every field, is refused on another kind, and a material negative rests on one", async () => {
  const { a0, a1 } = await run();
  const absence = ok(await rec(a0, { kind: "absence", value: "a remote tool", source: "inputs/disk.E01", evidence: "a search", refs: ["job:j000001/hits.txt"], control: { ref: "job:j000001/hits.txt", found: "the same search finds a planted row" }, answers: ["2"] })).entry;
  const full = coverage("2", ["input:disk.E01"], [`E-${absence.seq}`, "job:j000001/hits.txt"]);
  for (const [field, re] of [
    ["time_range", /time_range is required/],
    ["search_method", /search_method is required/],
    ["settings", /settings is required/],
    ["coverage_actual", /coverage_actual is required/],
    ["skipped", /skipped is required on a coverage record \("none" when nothing was/],
    ["failures", /failures is required/],
    ["alternatives", /alternatives is required: the explanations or routes still open/],
    ["result_refs", /result_refs is required/],
    ["refs", /refs is required on a coverage record/],
    ["answers", /answers is required on a coverage record/],
    ["detection_opportunity", /detection_opportunity is \{trace_expected: yes \| no \| unknown, why\}/],
    ["looked_for_none_why", /looked_for is required on a coverage record: the literal strings a hit would contain/],
  ] as const) {
    const { [field]: _gone, ...rest } = full as Record<string, unknown>;
    refused(await rec(a0, rest), re);
  }
  refused(await rec(a0, { ...full, proposition: undefined, value: undefined }), /proposition \(or value\) is required/);
  refused(await rec(a0, { ...full, detection_opportunity: { trace_expected: "maybe", why: "x" } }), /trace_expected: yes \| no \| unknown/);
  refused(await rec(a0, { ...full, result_refs: ["E-99"] }), /result_refs names E-99: there is no entry #99/);
  refused(await rec(a0, { ...full, inventory_rev: "0".repeat(64) }), /is not the run's inventory now/);
  refused(await rec(a0, { kind: "absence", value: "x", source: "s", evidence: "e", time_range: "all" }), /time_range is a coverage record's/);
  refused(await rec(a0, { kind: "answer", section: "question:2", value: "v", reasoning: `E-${absence.seq}`, ...A, result: "bounded_negative", skipped: "none" }), /skipped is not an answer's/);
  // The route plan comes first, then the record.
  refused(await rec(a1, { kind: "answer", section: "question:2", value: "No evidence of a remote tool was found on the disk", reasoning: `E-${absence.seq}`, ...A, result: "bounded_negative" }), /question:2 is a material question with no route plan/);
  await planned(a0, "2");
  refused(await rec(a1, { kind: "answer", section: "question:2", value: "No evidence of a remote tool was found on the disk", reasoning: `E-${absence.seq}`, ...A, result: "bounded_negative" }), /a bounded negative on a material question rests on a coverage record/);
  const cov = ok(await rec(a0, full));
  assert.equal(cov.entry.kind, "coverage");
  assert.equal(cov.entry.value, "The event question 2 asks about happened", "the proposition is the entry's value");
  assert.equal(cov.entry.inventory_rev, await NB.inventoryRevision(a0.sandboxRoot), "the hub writes the inventory revision");
  assert.deepEqual(cov.entry.detection_opportunity, { trace_expected: "yes", why: "the event writes to the objects searched, and they keep it" });
  assert.equal(P.verifyLedgerChain(await readFile(join(a0.sandboxRoot, P.LEDGER_ENTRIES), "utf8")).ok, true);
  // Every field is in the chained core.
  const text = await readFile(join(a0.sandboxRoot, P.LEDGER_ENTRIES), "utf8");
  for (const [from, to] of [["every byte of the objects named", "most bytes"], ['"coverage":"complete"', '"coverage":"partial"'], ['"trace_expected":"yes"', '"trace_expected":"no"']]) {
    assert.equal(P.verifyLedgerChain(text.replace(from, to)).ok, false, `${from} is chained`);
  }
  const ans = ok(await rec(a1, { kind: "answer", section: "question:2", value: "No evidence of a remote tool was found on the disk", reasoning: `E-${cov.entry.seq}, over E-${absence.seq}`, ...A, result: "bounded_negative" })).entry;
  assert.deepEqual(ans.support?.map((x) => x.seq), [cov.entry.seq, absence.seq]);
  // A background question's negative needs neither.
  const q = okq(await Q.act(a0.sandboxRoot, { kind: "agent", agent: "a0" }, "open", { text: "Was a printer attached?", why: "context", parent: "Q-2", materiality: "background" }));
  const bg = ok(await rec(a0, { kind: "absence", value: "a printer", source: "the hives", evidence: "a search", refs: ["job:j000001/hits.txt"], control: { ref: "job:j000001/hits.txt", found: "the same search finds a planted row" }, answers: [q.q!] })).entry;
  ok(await rec(a1, { kind: "answer", section: `question:${q.q!.slice(2)}`, value: "No evidence of a printer was found", reasoning: `E-${bg.seq}`, ...A, result: "bounded_negative" }));
});

test("the hub's object coverage: the jobs' declared inputs against the record's objects and the catalogue inside them, by place and digest", async () => {
  const { S, a0 } = await run();
  const entries = await P.readLedger(S);
  const cov = (objects: string[], results: string[]) => NB.computeObjectCoverage(S, { objects, resultRefs: results, entries });
  // The disk declared whole: it and the volumes the catalogue lists in it.
  const whole = await cov(["input:disk.E01"], ["job:j000001/hits.txt"]);
  assert.equal(whole.coverage, "complete", whole.why.join("; "));
  assert.deepEqual(whole.jobs, ["j000001"]);
  assert.ok(whole.units.some((u) => /catalogue generation g0001 of input:disk\.E01/.test(u.what) && u.covered));
  // One volume declared: the disk is not, and neither is the rest of its generation.
  const member = await cov(["input:disk.E01"], ["job:j000003/hits.txt"]);
  assert.equal(member.coverage, "partial");
  assert.ok(member.units.some((u) => /catalogue generation g0001/.test(u.what) && !u.covered && /only member:g0001#2 of it were declared, not the whole/.test(u.how)));
  // A member the record names, covered by its container being declared.
  const byContainer = await cov(["member:g0001#3"], ["job:j000001/hits.txt"]);
  assert.equal(byContainer.coverage, "complete", byContainer.why.join("; "));
  // A directory of the evidence: each file in it.
  const dir = await cov(["input:logs/"], ["job:j000002/hits.txt"]);
  assert.equal(dir.coverage, "partial");
  assert.deepEqual(dir.units.map((u) => [u.what, u.covered]), [["input:logs/a.log", true], ["input:logs/b.log", false]]);
  // A job that did not succeed, a search that was partial, no job at all, an object the run cannot name.
  assert.match((await cov(["input:disk.E01"], ["job:j000004/hits.txt"])).why.join(";"), /job j000004 did not succeed \(failed\)/);
  const partialAbsence = ok(await P.recordEntry(a0, { kind: "absence", value: "x", source: "s", evidence: "e", completion: "partial", refs: ["job:j000001/hits.txt"], control: { ref: "job:j000001/hits.txt", found: "the same search finds a planted row" } } as P.LedgerInput)).entry;
  const withPartial = await NB.computeObjectCoverage(S, { objects: ["input:disk.E01"], resultRefs: [`E-${partialAbsence.seq}`], entries: await P.readLedger(S) });
  assert.equal(withPartial.coverage, "partial");
  assert.match(withPartial.why.join(";"), new RegExp(`E-${partialAbsence.seq}, a search it rests on, was partial`));
  assert.match((await cov(["input:disk.E01"], [])).why.join(";"), /no job is behind it/);
  assert.equal((await cov(["unresolved:held on a phone nobody imaged", "input:disk.E01"], ["job:j000001/hits.txt"])).coverage, "partial");
  // By digest: an object named by its content is the one declared by its place.
  const digest = await cov([`sha256:${sha("disk")}`], ["job:j000001/hits.txt"]);
  assert.equal(digest.coverage, "complete", digest.why.join("; "));
  // A job that read everything covers it, and says it was said, not measured.
  const all = await cov(["input:logs/"], ["job:j000006/hits.txt"]);
  assert.equal(all.coverage, "complete");
  assert.match(all.units[0].how, /read every object of the run \(scope all: said, not measured\)/);
  // The job behind an entry the record cites: through its refs, or the interpretation that names it.
  const interp = ok(await P.recordEntry(a0, { kind: "absence", value: "y", source: "s", evidence: "e" } as P.LedgerInput)).entry;
  const byInterpretation = await NB.computeObjectCoverage(S, { objects: ["input:disk.E01"], resultRefs: [`E-${interp.seq}`], entries: await P.readLedger(S), interpretations: new Map([["j000001", [{ entry: interp.seq }]]]) });
  assert.equal(byInterpretation.coverage, "complete", byInterpretation.why.join("; "));
  // The inventory revision moves with the inventory.
  const before = await NB.inventoryRevision(S);
  await writeFile(join(S, "catalog", "gen", "g0001", "generation.json"), JSON.stringify({ id: "g0001", job: "j000005", target: { ref: "input:disk.E01", name: "disk.E01 (again)" } }));
  assert.notEqual(await NB.inventoryRevision(S), before);
});

test("the route plan: warned at a question's first lead, required before a material negative closes, its unexamined sources named", async () => {
  const { S, a0, a1 } = await run();
  const first = await L.openLead(a0, { title: "Search for a remote tool", why: "question 2", answers: ["2"], take: true });
  assert.ok(first.ok);
  assert.match((first as { warning?: string }).warning ?? "", /no route plan under question:2: list the sources you will examine and how/);
  const lead = (first as { lead: { id: string } }).lead.id;
  const absence = ok(await rec(a0, { kind: "absence", value: "a remote tool", source: "inputs/disk.E01", evidence: "a search", refs: ["job:j000001/hits.txt"], control: { ref: "job:j000001/hits.txt", found: "the same search finds a planted row" }, answers: ["2"] })).entry;
  refused(await L.closeLead(a0, lead, { disposition: "negative", ref: `E-${absence.seq}` }), /serves question:2, a material question with no route plan/);
  refused(await L.linkLead(a0, lead, { routes: [{ source: "input:disk.E01" }] }), /a route's method is required/);
  assert.ok((await L.linkLead(a0, lead, { routes: [{ source: "input:disk.E01", method: "search the disk" }, { source: "input:logs/b.log", method: "read the other log" }, { source: "the firewall's own log", method: "ask for it" }] })).ok);
  // A job under the lead declared the disk: that route was examined; the other two were not.
  await L.attachJob(S, "a0", "j000001", lead);
  const closed = await L.closeLead(a0, lead, { disposition: "negative", ref: `E-${absence.seq}` });
  assert.ok(closed.ok, (closed as { reason?: string }).reason);
  const view = (closed as { lead: L.LeadView }).lead;
  assert.deepEqual(view.not_examined?.map((r) => r.source), ["input:logs/b.log", "the firewall's own log"]);
  assert.match(view.not_examined?.[1].why ?? "", /named in words, not as an object of the run/);
  assert.deepEqual(view.routes.map((r) => r.source), ["input:disk.E01", "input:logs/b.log", "the firewall's own log"]);
  // A coverage record for the question names the same routes, from the same plan.
  const cov = ok(await rec(a1, coverage("2", ["input:disk.E01"], [`E-${absence.seq}`]))).entry;
  assert.deepEqual(cov.not_examined?.map((r) => r.source), ["input:logs/b.log", "the firewall's own log"]);
  assert.match(await readFile(join(S, L.LEADS_MD), "utf8"), /Route plan: input:disk\.E01 \(search the disk\)[\s\S]*Planned routes not examined: input:logs\/b\.log/);
  // A person's question's first lead gives its plan with its proposition.
  const q = okq(await Q.act(S, { kind: "human", role: "examiner", person: "eve", name: "EVE", enrolled: true, os_user: "t", host: "h", via: "cli", identity: "claimed" }, "open", { text: "Was the tool run by bob?", why: "the client asks" })).q!;
  refused(await L.openLead(a1, { title: "t", why: "w", answers: [q], take: true, proposition: "bob ran it", negation: "bob did not run it" }), /give its route plan too/);
  assert.ok((await L.openLead(a1, { title: "t", why: "w", answers: [q], take: true, proposition: "bob ran it", negation: "bob did not run it", routes: [{ source: "input:logs/a.log", method: "the account on each run" }] })).ok);
});

test("the quick negative: held under two minutes, one job, one object; shown in the header until another seat attests its search", async () => {
  const { S, a0, a2 } = await run();
  const lead = await planned(a0, "2");
  await L.attachJob(S, "a0", "j000001", lead);
  const absence = ok(await rec(a0, { kind: "absence", value: "a remote tool", source: "inputs/disk.E01", evidence: "a search", refs: ["job:j000001/hits.txt"], control: { ref: "job:j000001/hits.txt", found: "the same search finds a planted row" }, answers: ["2"] })).entry;
  const closed = await L.closeLead(a0, lead, { disposition: "negative", ref: `E-${absence.seq}` });
  assert.ok(closed.ok);
  const q = (closed as { lead: L.LeadView }).lead.quick_negative;
  assert.ok(q && q.jobs === 1 && q.objects === 1 && q.held_ms < NB.QUICK_NEGATIVE_HELD_MS, JSON.stringify(q));
  let header = (await L.leadsDigest(a2)).text;
  assert.match(header, new RegExp(`Quick negatives, each a cue for review .*${lead} "Work question 2" \\(held \\d+ s, 1 job\\(s\\), 1 object\\(s\\); E-${absence.seq}\\)`));
  // The report says it beside the lead, with the plan it closed against.
  const md = await renderReportBodyMarkdown(S);
  assert.match(md, new RegExp(`${lead}\\*\\* .*Routes planned: input:disk\\.E01 \\(search the disk\\)\\..*Quick negative:\\*\\* closed \\d+ s after it was taken, on 1 job over 1 object; a cue for review, not a refusal\\.`));
  assert.ok((await P.attestEntry(a2, { seq: absence.seq, how: "ran the search again from job:j000001" })).ok);
  header = (await L.leadsDigest(a2)).text;
  assert.doesNotMatch(header, /Quick negatives/);
  // Two jobs is not quick, whatever the time.
  const other = await planned(a0, "3");
  await L.attachJob(S, "a0", "j000002", other);
  await L.attachJob(S, "a0", "j000003", other);
  const absence3 = ok(await rec(a0, { kind: "absence", value: "a deletion", source: "the disk", evidence: "a search", refs: ["job:j000001/hits.txt"], control: { ref: "job:j000001/hits.txt", found: "the same search finds a planted row" }, answers: ["3"] })).entry;
  const c3 = await L.closeLead(a0, other, { disposition: "negative", ref: `E-${absence3.seq}` });
  assert.equal((c3 as { lead: L.LeadView }).lead.quick_negative, undefined);
  // Reopened, the mark goes with the close it was on.
  await L.reopenLead(S, lead, "operator", "look again", "operator");
  const reopened = (await L.leadsSnapshot(S)).state.leads.get(lead)!;
  assert.equal(reopened.quick_negative, undefined);
});

test("a material negative nobody else reviewed holds the finish line; the review states what was challenged, reproduced or tried", async () => {
  const { S, a0, a1, a2, a3 } = await run();
  await planned(a0, "2");
  const absence = ok(await rec(a0, { kind: "absence", value: "a remote tool", source: "inputs/disk.E01", evidence: "a search", refs: ["job:j000001/hits.txt"], control: { ref: "job:j000001/hits.txt", found: "the same search finds a planted row" }, answers: ["2"] })).entry;
  const cov = ok(await rec(a0, coverage("2", ["input:disk.E01"], [`E-${absence.seq}`, "job:j000001/hits.txt"]))).entry;
  const ans = ok(await rec(a1, { kind: "answer", section: "question:2", value: "No evidence of a remote tool was found on the disk", reasoning: `E-${cov.seq}`, ...A, result: "bounded_negative" })).entry;
  assert.match(await readFile(join(S, P.LEDGER_MD), "utf8"), /question:2 \(bounded_negative\) \*\*\(negative, unreviewed\)\*\*/);
  const header = (await L.leadsDigest(a3)).text;
  // Its review is offered to one seat (the c10 pilot's stampede), and the header says to whom.
  assert.match(header, new RegExp(`Negatives awaiting review by another seat .*question:2 \\(E-${ans.seq} bounded negative, by a1; coverage E-${cov.seq} complete; its review is offered to a2\\)`));
  let r = await checkLedgerAnswers(S, ["2"], ["2"]);
  assert.equal(r.ok, false);
  const d = r.defects.find((x) => x.code === "negative_unreviewed")!;
  assert.deepEqual([d.section, d.named_by], ["question:2", []]);
  assert.match(d.fix, /review \{detection, reproduced, other_route\}/);
  // A limitation does not excuse it.
  ok(await rec(a2, { kind: "limitation", value: `E-${ans.seq} was not reviewed`, source: "the ledger", evidence: "no attest", reason: "not_examined", answers: ["2"] }));
  r = await checkLedgerAnswers(S, ["2"], ["2"]);
  assert.equal(r.ok, false, "a negative is reviewed, never named away");
  // The review: required on a negative, refused on anything else, never the author's or the coverage record's.
  refused(await P.attestEntry(a2, { seq: ans.seq, how: "read it" }), /its attest is a review/);
  refused(await P.attestEntry(a2, { seq: cov.seq, how: "read it", review: { ...REVIEW, other_route: { done: false, text: "" } } }), /review\.other_route\.text is required: why not/);
  refused(await P.attestEntry(a2, { seq: cov.seq, how: "read it", review: { detection: { done: "yes", text: "x" }, reproduced: REVIEW.reproduced, other_route: REVIEW.other_route } }), /review\.detection is \{done: true\|false, text\}/);
  refused(await P.attestEntry(a0, { seq: ans.seq, how: "mine", review: REVIEW }), /you recorded the coverage record/);
  refused(await P.attestEntry(a2, { seq: absence.seq, how: "ran it again", review: REVIEW }), /review is for a negative/);
  const att = await P.attestEntry(a2, { seq: cov.seq, how: "ran the search again from job:j000001", review: REVIEW });
  assert.ok(att.ok, (att as { reason?: string }).reason);
  assert.deepEqual((att as { line: P.LedgerAttestation }).line.review, REVIEW);
  const chain = await readFile(join(S, P.LEDGER_ATTESTATIONS), "utf8");
  assert.equal(P.verifyAttestationChain(chain).ok, true);
  assert.equal(P.verifyAttestationChain(chain.replace("nothing", "something")).ok, false, "the review is in the hashed record");
  r = await checkLedgerAnswers(S, ["2"], ["2"]);
  assert.equal(r.ok, true, r.lines.join("\n"));
  // An existence question, covered complete and reviewed: a disposition under
  // the bar, and examination-limited while the answer only says nothing was
  // found (the stronger words settle it: the wording test below).
  assert.deepEqual(r.outcomes, { "question:2": "limited" });
  assert.deepEqual(r.dispositions, { "question:2": "bounded_negative" });
  assert.match(r.lines[0], /the answer does not say the event did not happen.*reviewed by a2/);
  assert.match(await readFile(join(S, P.LEDGER_MD), "utf8"), /question:2 \(bounded_negative\) \(negative, reviewed by a2\)/);
  // The register's question for the section says the same, and keeps the disposition on its chain.
  await L.leadsDigest(a3);
  const snap = await Q.questionsSnapshot(S);
  const disp = snap.state.questions.get("Q-2")!.disposition as Record<string, unknown>;
  assert.equal(disp.answer, `E-${ans.seq}`);
  assert.equal(disp.result, "bounded_negative");
  assert.equal(disp.reviewed, true);
  assert.deepEqual(disp.reviewed_by, ["a2"]);
  assert.ok(snap.state.events.some((e) => e.ev === "dispose" && e.q === "Q-2"));
});

test("a register question's material negative holds the finish gate until reviewed", async () => {
  const { S, a0, a1, a2 } = await run();
  const q = okq(await Q.act(S, { kind: "agent", agent: "a0" }, "open", { text: "Was a second remote tool staged?", why: "the first one points to it", parent: "Q-2", materiality: "material", source_entry: "E-1" })).q!;
  const section = q.slice(2);
  await planned(a0, q);
  const absence = ok(await rec(a0, { kind: "absence", value: "a second tool", source: "the disk", evidence: "a search", refs: ["job:j000001/hits.txt"], control: { ref: "job:j000001/hits.txt", found: "the same search finds a planted row" }, answers: [q] })).entry;
  const cov = ok(await rec(a0, coverage(q, ["input:disk.E01"], [`E-${absence.seq}`]))).entry;
  ok(await rec(a1, { kind: "answer", section: `question:${section}`, value: "No evidence of a second tool was found on the disk", reasoning: `E-${cov.seq}`, ...A, result: "bounded_negative" }));
  const blocked = await finishGate(S, null);
  assert.ok(blocked.defects.some((d) => d.code === "question_answer" && /negative \(unreviewed\)/.test(d.what)), JSON.stringify(blocked.defects));
  assert.ok((await P.attestEntry(a2, { seq: cov.seq, how: "ran it again", review: REVIEW })).ok);
  const clear = await finishGate(S, null);
  assert.ok(!clear.defects.some((d) => d.code === "question_answer"), JSON.stringify(clear.defects));
  assert.ok(clear.limited.some((l) => l.startsWith(`${q} (question:${section}) is examination-limited`)), "a bounded negative on a question that does not ask whether something exists limits the run");
});

test("the wording: a negative says what was not found where; 'it did not happen' only on an existence question, complete, with the trace expected", async () => {
  const { S, a0, a1, a2 } = await run();
  await planned(a0, "2");
  await planned(a0, "3");
  const absence = ok(await rec(a0, { kind: "absence", value: "a remote tool", source: "one volume of the disk", evidence: "a search", refs: ["job:j000003/hits.txt"], control: { ref: "job:j000003/hits.txt", found: "the same search finds a planted row" }, answers: ["2"] })).entry;
  const partial = ok(await rec(a0, coverage("2", ["input:disk.E01"], [`E-${absence.seq}`, "job:j000003/hits.txt"]))).entry;
  assert.equal(partial.coverage, "partial");
  const worded = { kind: "answer", section: "question:2", reasoning: `E-${partial.seq}`, ...A, result: "bounded_negative" };
  refused(await rec(a1, { ...worded, value: "A remote tool was never installed; it did not happen" }), /worded as the event's absence \("did not happen"\)/);
  refused(await rec(a1, { ...worded, value: "No remote tool was installed", asserts_absence: true }), /rests on a coverage record the hub found complete and that says the event would have left a trace/);
  refused(await rec(a1, { ...worded, value: "x", asserts_absence: true, result: "not_determinable" }), /asserts_absence says the event did not happen: it comes with result bounded_negative/);
  // Question 3 does not ask whether something exists: never "it did not happen" there.
  const absence3 = ok(await rec(a0, { kind: "absence", value: "a deletion", source: "the disk", evidence: "a search", refs: ["job:j000001/hits.txt"], control: { ref: "job:j000001/hits.txt", found: "the same search finds a planted row" }, answers: ["3"] })).entry;
  const cov3 = ok(await rec(a0, coverage("3", ["input:disk.E01"], [`E-${absence3.seq}`, "job:j000001/hits.txt"]))).entry;
  refused(await rec(a1, { kind: "answer", section: "question:3", reasoning: `E-${cov3.seq}`, ...A, result: "bounded_negative", value: "Nothing was deleted", asserts_absence: true }), /only an answer to a question that asks whether something exists may say that/);
  // Complete, the trace expected, an existence question: said, and marked.
  const complete = ok(await rec(a0, coverage("2", ["input:disk.E01"], [`E-${absence.seq}`, "job:j000001/hits.txt"], { settings: "every encoding, the whole disk" }))).entry;
  assert.equal(complete.coverage, "complete");
  const said = ok(await rec(a1, { ...worded, reasoning: `E-${complete.seq}`, value: "No remote tool was installed on this host: it did not happen", asserts_absence: true })).entry;
  assert.equal(said.asserts_absence, true);
  assert.ok((await P.attestEntry(a2, { seq: said.seq, how: "ran it again", review: REVIEW })).ok);
  const strong = await checkLedgerAnswers(S, ["2"], ["2"]);
  assert.equal(strong.ok, true);
  assert.deepEqual([strong.outcomes["question:2"], strong.dispositions["question:2"]], ["answered", "bounded_negative"], "the stronger bar, said and reviewed, settles the question: the run may end completed on it");
  // The gate holds it again when what earned it no longer stands: the record corrected to one the hub finds partial.
  const corrected = ok(await rec(a0, { ...coverage("2", ["input:disk.E01"], [`E-${absence.seq}`, "job:j000003/hits.txt"], { settings: "one volume only" }), supersedes: complete.seq })).entry;
  assert.equal(corrected.coverage, "partial");
  const r = await checkLedgerAnswers(S, ["2"], ["2"]);
  assert.equal(r.ok, false);
  assert.ok(r.defects.some((d) => d.code === "answer_support"), "the answer no longer stands on what it cited");
  // A hand-written drift (an old answer worded absolutely) is the gate's wording defect.
  const g = P.ledgerGate({
    entries: [{ v: 4, seq: 1, kind: "answer", section: "question:9", value: "It never happened", reasoning: "E-2", result: "bounded_negative", support: [], by: "a0", authors: ["a0"], at: "2026-01-01T00:00:00Z" } as P.LedgerEntry],
    attestations: [],
    disputes: [],
    sections: ["question:9"],
    bar: () => ({ material: false, existence: true }),
  });
  assert.ok(g.defects.some((d) => d.code === "wording" && /"never happened"/.test(d.what)));
});

test("the operator's acceptance: refused while a route is open or a negative unreviewed, bound to its revision, and it limits the run", async () => {
  const { S, a0, a1, a2 } = await run();
  const operator: Q.Actor = { kind: "human", role: "operator", person: "tester@lab", enrolled: false, os_user: "tester", host: "lab", via: "cli", identity: "claimed" };
  const lead = await planned(a0, "2");
  refused(await Q.act(S, operator, "accept", { q: "Q-2", as: "bounded", why: "enough was searched", expected_rev: 1 }), new RegExp(`a route is still open on Q-2: ${lead}`));
  const absence = ok(await rec(a0, { kind: "absence", value: "a remote tool", source: "the disk", evidence: "a search", refs: ["job:j000001/hits.txt"], control: { ref: "job:j000001/hits.txt", found: "the same search finds a planted row" }, answers: ["2"] })).entry;
  assert.ok((await L.closeLead(a0, lead, { disposition: "negative", ref: `E-${absence.seq}` })).ok);
  const cov = ok(await rec(a0, coverage("2", ["input:disk.E01"], [`E-${absence.seq}`, "job:j000003/hits.txt"]))).entry;
  const ans = ok(await rec(a1, { kind: "answer", section: "question:2", value: "No evidence of a remote tool was found on the volume searched", reasoning: `E-${cov.seq}`, ...A, result: "bounded_negative" })).entry;
  refused(await Q.act(S, operator, "accept", { q: "Q-2", as: "bounded", why: "enough was searched", expected_rev: 1 }), new RegExp(`Q-2's answer E-${ans.seq} is a negative \\(unreviewed\\).*never stands in for one`));
  assert.ok((await P.attestEntry(a2, { seq: ans.seq, how: "read the coverage", review: REVIEW })).ok);
  refused(await Q.act(S, operator, "accept", { q: "Q-2", as: "bounded", why: "enough was searched", expected_rev: 2 }), /Q-2 is at revision 1/);
  refused(await Q.act(S, { kind: "agent", agent: "a0" }, "accept", { q: "Q-2", as: "bounded", why: "w", expected_rev: 1 }), /an agent does not accept a question/);
  const accepted = await Q.act(S, operator, "accept", { q: "Q-2", as: "bounded", why: "one volume is what the case could read", expected_rev: 1 });
  assert.ok(accepted.ok, (accepted as { reason?: string }).reason);
  const events = (await Q.questionsSnapshot(S)).state.events;
  assert.deepEqual((events.at(-1)!.decided as Record<string, unknown>).outcome, "examination_limited");
  // The acceptance limits the run: its finish is examination-limited, never completed.
  const gate = await finishGate(S, null);
  assert.ok(gate.limited.some((l) => /Q-2 was accepted as a bounded examination by tester@lab/.test(l)));
  assert.deepEqual(gate.questions.find((q) => q.id === "2")?.outcome, "accepted");
  // The fixture's other goal questions are unanswered, and under one rule for
  // every stop policy they would hold the done: the acceptance is weighed
  // alone here, as the only question in scope.
  const alone = { ...gate, questions: gate.questions.filter((q) => q.id === "2") };
  assert.ok(!P.finishLineVerdict({ total: 0, passed: 0, checks: [], source: "registry", gate }, false).proceed, "an unanswered question holds the done, under a cap policy too");
  const verdict = P.finishLineVerdict({ total: 0, passed: 0, checks: [], source: "registry", gate: alone }, false);
  assert.equal(verdict.proceed && verdict.outcome, "examination_limited");
  // Under the operator's stop policy an accepted question holds nothing; one left open does.
  const until = P.finishLineVerdict({ total: 0, passed: 0, checks: [], source: "registry", gate: { ...alone, until_solved: true, questions: [...alone.questions, { id: "5", outcome: "unanswered", blocks: ["no standing answer entry"] }] } }, false);
  assert.equal(until.proceed, false);
  assert.match((until as { reason: string }).reason, /question:5 is unanswered/);
  assert.doesNotMatch((until as { reason: string }).reason, /question:2 is/);
  // Its disposition is on the chain.
  await Q.syncDispositions(S);
  const disp = (await Q.questionsSnapshot(S)).state.questions.get("Q-2")!.disposition as Record<string, unknown>;
  assert.equal(disp.accepted, "bounded");
});

test("the report words a bounded negative as what was not found where, shows its coverage as the hub found it, and says an unreviewed one", async () => {
  const { S, a0, a1, a2 } = await run();
  await planned(a0, "2", [{ source: "input:disk.E01", method: "search the disk" }, { source: "input:logs/b.log", method: "read the other log" }]);
  const absence = ok(await rec(a0, { kind: "absence", value: "a remote tool", source: "the disk", evidence: "a search", refs: ["job:j000003/hits.txt"], control: { ref: "job:j000003/hits.txt", found: "the same search finds a planted row" }, answers: ["2"] })).entry;
  const cov = ok(await rec(a0, coverage("2", ["input:disk.E01"], [`E-${absence.seq}`, "job:j000003/hits.txt"], { proposition: "A remote administration tool was installed." }))).entry;
  ok(await rec(a1, { kind: "answer", section: "question:2", value: "No evidence of a remote tool was found on the volume searched", reasoning: `E-${cov.seq}`, ...A, result: "bounded_negative" }));
  let md = await renderReportBodyMarkdown(S);
  assert.match(md, /Result: no evidence that a remote administration tool was installed was found in input:disk\.E01, the whole of each object, no time bound\. This is a bounded negative: it says what was not found where, not that it did not happen\./);
  assert.match(md, /Computed by the hub.*coverage partial/);
  assert.match(md, /Planned, not examined.*input:logs\/b\.log \(read the other log\)/);
  assert.match(md, /Negative \(unreviewed\): no seat other than its authors has reviewed it/);
  assert.match(md, /negative \(unreviewed\)/);
  assert.ok((await P.attestEntry(a2, { seq: cov.seq, how: "read the coverage", review: REVIEW })).ok);
  md = await renderReportBodyMarkdown(S);
  assert.match(md, /Reviewed by a2: challenged the detection assumptions: a logon on this host/);
  assert.match(md, /no evidence found \(bounded negative\)/);
});
