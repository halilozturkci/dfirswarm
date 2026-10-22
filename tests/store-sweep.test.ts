/**
 * The store sweep (docs/adr/0013, "After the round-13 scoring"): a coverage record names what a hit would contain, and the hub
 * searches every output the run holds for it; a hit in an object the record
 * does not name holds the negative until the record is revised to name it;
 * a pending sweep holds like an unreviewed negative; a partial one names what
 * it did not search and holds until the operator accepts the question's
 * limits. Synthetic runs only.
 */
import assert from "node:assert/strict";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import * as P from "../extensions/protocol.ts";
import * as L from "../extensions/leads.ts";
import * as Q from "../extensions/questions.ts";
import * as SW from "../extensions/store-sweep.ts";
import { checkLedgerAnswers } from "../scripts/check-answers.ts";
import { sealTree, storePaths } from "../scripts/evidence-store.ts";
import { measureRun } from "../scripts/metrics.ts";
import { renderReportBodyMarkdown } from "../scripts/report-body.ts";
import { A, coverage, F, ok, planned, rec, refused, REVIEW, run } from "./negative-bar-fixture.ts";

/** A committed job whose one output holds `body`: an export or a listing the run made. */
async function jobWith(S: string, id: string, file: string, body: string | Buffer): Promise<void> {
  const staging = join(S, "..", `staging-${id}-${Math.random().toString(16).slice(2)}`);
  await mkdir(staging, { recursive: true });
  await writeFile(join(staging, file), body);
  await sealTree(S, staging, join(storePaths(S).jobs, id, "out"), id, 1);
  await writeFile(join(storePaths(S).jobs, id, "job.json"), JSON.stringify({ id, state: "committed", requester: { agent: "a0" }, status: "ok", exit: 0, spec: { kind: "command", scope: "declared", inputs: ["input:disk.E01"], command: "export" } }));
}
const attested = async (c: { sandboxRoot: string; agentId: string }, input: P.LedgerActInput) => {
  const r = await P.attestEntry(c, input);
  assert.ok(r.ok && (r as { line: unknown }).line, JSON.stringify(r));
};
const codes = (r: Awaited<ReturnType<typeof checkLedgerAnswers>>, section: string) => r.defects.filter((d) => d.section === section).map((d) => d.code);
const OPERATOR: Q.Actor = { kind: "human", role: "operator", person: "tester@lab", enrolled: false, os_user: "tester", host: "lab", via: "cli", identity: "claimed" };

test("a coverage record names what a hit would contain, or why nothing literal would: each string checked", async () => {
  const { a0 } = await run();
  const abs = ok(await rec(a0, { kind: "absence", value: "a remote tool", source: "the disk", evidence: "a search", refs: ["job:j000001/hits.txt"], answers: ["2"] })).entry;
  const base = coverage("2", ["input:disk.E01"], [`E-${abs.seq}`]);
  const { looked_for_none_why: _n, ...bare } = base as Record<string, unknown>;
  refused(await rec(a0, bare), /looked_for is required on a coverage record: the literal strings a hit would contain/);
  refused(await rec(a0, { ...bare, looked_for: ["ab"] }), /looked_for "ab" is shorter than 3 characters/);
  refused(await rec(a0, { ...bare, looked_for: ["alice"], looked_for_none_why: "none" }), /give one/);
  refused(await rec(a0, { ...bare, looked_for: Array.from({ length: 21 }, (_, i) => `term-${i}`) }), /looked_for names more than 20 strings/);
  refused(await rec(a0, { kind: "finding", ...F, value: "x", source: "s", evidence: "e", refs: ["job:j000001/hits.txt"], looked_for: ["alice"] }), /looked_for is a coverage record's/);
  const cov = ok(await rec(a0, { ...bare, looked_for: ["Alice", "alice", "  ws-11 "] }));
  assert.deepEqual(cov.entry.looked_for, ["Alice", "ws-11"], "trimmed, and the same string in another case once");
  await SW.awaitSweeps(a0.sandboxRoot);
  // In the chained core.
  const text = await readFile(join(a0.sandboxRoot, P.LEDGER_ENTRIES), "utf8");
  assert.equal(P.verifyLedgerChain(text).ok, true);
  assert.equal(P.verifyLedgerChain(text.replace('"ws-11"', '"ws-12"')).ok, false);
});

test("the store sweep: a hit outside the record's objects holds the negative, UTF-16LE included; pending holds; a revision naming the hits releases it; the review offer, ledger.md, the report and the metrics say it", async () => {
  const { S, a0, a1, a2, a3 } = await run();
  // Outputs the run made before the negative: an export holding the name, a listing holding the host in UTF-16LE.
  await jobWith(S, "j000007", "export.csv", "time,user,host\n09:58,ALICE,ws-11\n");
  await jobWith(S, "j000008", "strings.bin", Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from("header bob-laptop tail", "utf16le")]));
  await planned(a0, "2");
  const abs = ok(await rec(a0, { kind: "absence", value: "a remote tool", source: "the disk", evidence: "a search", refs: ["job:j000001/hits.txt"], answers: ["2"] })).entry;
  const covR = ok(await rec(a0, coverage("2", ["input:disk.E01"], [`E-${abs.seq}`, "job:j000001/hits.txt"], { looked_for: ["alice", "bob-laptop", "no-such-string-xyz"] })));
  assert.match(covR.note ?? "", /the hub now searches every output the run holds .* for "alice", "bob-laptop", "no-such-string-xyz", in UTF-8 and UTF-16LE/);
  const cov = covR.entry;
  const ans = ok(await rec(a1, { kind: "answer", section: "question:2", value: "No evidence of a remote tool was found on the disk", reasoning: `E-${cov.seq}`, ...A, result: "bounded_negative" })).entry;
  // Pending: the gate over no sweep line holds it as it holds an unreviewed negative.
  const pending = P.ledgerGate({ entries: await P.readLedger(S), attestations: [], disputes: [], sections: ["question:2"], sweeps: [] });
  assert.ok(pending.defects.some((d) => d.code === "sweep_pending" && d.section === "question:2" && new RegExp(`E-${cov.seq}, whose store sweep .* has not finished`).test(d.what)), JSON.stringify(pending.defects));
  await SW.awaitSweeps(S);
  const sw = SW.sweepOf(cov, await SW.readSweeps(S))!;
  assert.equal(sw.state, "hits");
  assert.deepEqual(sw.hits.map((h) => [h.ref, h.term, h.count, h.encodings]), [["job:j000007/export.csv", "alice", 1, ["utf-8"]], ["job:j000008/strings.bin", "bob-laptop", 1, ["utf-16le"]]]);
  assert.equal(sw.hits[0].first_offset, "time,user,host\n09:58,".length);
  assert.equal(sw.hits[1].first_offset, 2 + "header ".length * 2);
  assert.deepEqual(sw.named_hits, [], "nothing in the record's own objects holds the strings");
  assert.equal(sw.unsearched.length, 0);
  assert.ok(sw.searched.objects >= 8, "every job's output is searched");
  assert.equal(SW.verifySweepChain(await readFile(join(S, SW.LEDGER_SWEEPS), "utf8")).ok, true);
  // The sweep's own render of ledger.md can be overtaken by one that began before its line was written (two renders write the same file, the later write
  // wins); render once more from what is on disk, which is what this reads.
  await P.renderLedger(S);
  assert.match(await readFile(join(S, P.LEDGER_MD), "utf8"), /looked for: "alice", "bob-laptop", "no-such-string-xyz"; store sweep hits: .*found outside the record's objects: "alice" in job:j000007\/export\.csv/);
  // The review offer carries the sweep and asks for the whole store.
  await L.leadsDigest(a3);
  const snap = await L.leadsSnapshot(S);
  const offer = snap.state.reviewOffers.get(`E-${ans.seq}`)?.at(-1);
  assert.ok(offer, "the negative's review is offered");
  const words = L.reviewOfferText(`E-${ans.seq}`, offer!, snap);
  assert.match(words, /Check the answer against everything the run holds, not only its coverage's sources: .*"alice" in job:j000007\/export\.csv.*say in other_route what you did with the store sweep/);
  await attested({ sandboxRoot: S, agentId: offer!.to }, { seq: cov.seq, how: "ran the search again", review: REVIEW });
  // Reviewed, and still held: the hits are outside the record.
  let r = await checkLedgerAnswers(S, ["2"], ["2"]);
  assert.equal(r.ok, false);
  assert.deepEqual(codes(r, "question:2"), ["sweep_hits"]);
  const d = r.defects.find((x) => x.code === "sweep_hits")!;
  assert.match(d.what, /found what it looked for in objects the record does not name: "alice" in job:j000007\/export\.csv \(1 time, first at byte 21\); "bob-laptop" in job:j000008\/strings\.bin \(1 time, first at byte 16, utf-16le\)/);
  assert.match(d.fix, new RegExp(`record the coverage again with supersedes=${cov.seq} naming each in refs, with what it showed: those entries in result_refs`));
  assert.match(d.fix, /one entry per object \(a finding, an event or a limitation whose refs name the object itself\), or one absence whose refs list several/);
  assert.deepEqual(d.named_by, []);
  assert.equal(r.dispositions["question:2"], undefined);
  // What each hit object showed, recorded after the sweep: a finding on the export, a search of the listing that found no tool.
  const seenExport = ok(await rec(a0, { kind: "finding", ...F, value: "the export's row with alice is a user of another host", source: "the export", evidence: "row 2", refs: ["job:j000007/export.csv"], answers: ["2"] })).entry;
  const seenListing = ok(await rec(a0, { kind: "absence", value: "a remote tool in the listing", source: "the listing", evidence: "read whole: it names a host", refs: ["job:j000008/strings.bin"], answers: ["2"] })).entry;
  // The record revised to name what the sweep found, with what it showed; its own sweep then holds nothing.
  const cov2 = ok(await rec(a0, coverage("2", ["input:disk.E01", "job:j000007/export.csv", "job:j000008"], [`E-${abs.seq}`, "job:j000001/hits.txt", `E-${seenExport.seq}`, `E-${seenListing.seq}`], { looked_for: ["alice", "bob-laptop", "no-such-string-xyz"], supersedes: cov.seq, coverage_actual: "the disk, and the export and the listing the sweep named: the export's row is a user of another host, the listing names a host, not a tool" }))).entry;
  ok(await rec(a1, { kind: "answer", section: "question:2", value: "No evidence of a remote tool was found on the disk, the export or the listing", reasoning: `E-${cov2.seq}`, ...A, result: "bounded_negative", supersedes: ans.seq }));
  await SW.awaitSweeps(S);
  const sw2 = SW.sweepOf(cov2, await SW.readSweeps(S))!;
  assert.equal(sw2.state, "clean");
  assert.deepEqual(sw2.named_hits.map((h) => h.ref), ["job:j000007/export.csv", "job:j000008/strings.bin"], "a hit in an object the record names is said, never holding");
  await attested(a2, { seq: cov2.seq, how: "read the export and the listing", review: REVIEW, second_review_why: "the revised record names the objects the sweep found" });
  r = await checkLedgerAnswers(S, ["2"], ["2"]);
  assert.deepEqual(codes(r, "question:2"), [], r.lines.join("\n"));
  assert.equal(r.dispositions["question:2"], "bounded_negative");
  // The metrics and the report.
  const m = await measureRun(S);
  assert.deepEqual([m.sweeps.records, m.sweeps.with_hits, m.sweeps.clean, m.sweeps.hit_objects, m.sweeps.released, m.sweeps.held.length], [2, 1, 1, 2, 1, 0]);
  const md = await renderReportBodyMarkdown(S);
  assert.match(md, /### Store sweeps/);
  assert.match(md, /2 coverage records named what a hit would contain.*2 swept, 0 pending, 1 with hits in objects the record did not name, 0 partial; 1 of the records with hits were revised/);
  assert.match(md, /Store sweep \(by the hub\):\*\* store sweep clean/);
});

test("naming a hit object in a revised record is not examining it (the run sb1b3c8): the gate holds each until an entry written after the sweep that names the object itself says what it showed, one per object or one absence over several", async () => {
  const { S, a0, a1, a2, a3 } = await run();
  await jobWith(S, "j000007", "export.csv", "time,user\n09:58,alice\n");
  await jobWith(S, "j000008", "a.txt", "alice was here\n");
  await jobWith(S, "j000009", "b.txt", "and alice again\n");
  await planned(a0, "2");
  // Recorded before any sweep: it names the export, but it was not written in answer to the hit (it says nothing of what the hit is).
  const early = ok(await rec(a0, { kind: "finding", ...F, value: "the export lists logons", source: "the export", evidence: "its header", refs: ["job:j000007/export.csv"], answers: ["2"] })).entry;
  const abs = ok(await rec(a0, { kind: "absence", value: "a remote tool", source: "the disk", evidence: "a search", refs: ["job:j000001/hits.txt"], answers: ["2"] })).entry;
  const cov = ok(await rec(a0, coverage("2", ["input:disk.E01"], [`E-${abs.seq}`, "job:j000001/hits.txt"], { looked_for: ["alice"] }))).entry;
  let ans = ok(await rec(a1, { kind: "answer", section: "question:2", value: "No evidence of a remote tool was found on the disk", reasoning: `E-${cov.seq}`, ...A, result: "bounded_negative" })).entry;
  await SW.awaitSweeps(S);
  assert.deepEqual(SW.sweepOf(cov, await SW.readSweeps(S))!.hits.map((h) => h.ref), ["job:j000007/export.csv", "job:j000008/a.txt", "job:j000009/b.txt"]);
  // Revised to name them all, by their directories, with nothing said about any: the reply says so, and the gate still holds.
  const named = ok(await rec(a0, coverage("2", ["input:disk.E01", "job:j000007", "job:j000008", "job:j000009"], [`E-${abs.seq}`, "job:j000001/hits.txt", `E-${early.seq}`], { looked_for: ["alice"], supersedes: cov.seq })));
  assert.match(named.note ?? "", /it names 3 objects an earlier sweep found hits in, and no entry among its result_refs says what each showed: job:j000007\/export\.csv, job:j000008\/a\.txt, job:j000009\/b\.txt\. Naming a hit is not examining it/);
  ans = ok(await rec(a1, { kind: "answer", section: "question:2", value: "No evidence of a remote tool was found on the disk or the outputs", reasoning: `E-${named.entry.seq}`, ...A, result: "bounded_negative", supersedes: ans.seq })).entry;
  await SW.awaitSweeps(S);
  assert.equal(SW.sweepOf(named.entry, await SW.readSweeps(S))!.state, "clean", "its own sweep finds the hits named");
  await attested(a2, { seq: named.entry.seq, how: "ran the search again", review: REVIEW });
  let r = await checkLedgerAnswers(S, ["2"], ["2"]);
  assert.deepEqual(codes(r, "question:2"), ["sweep_hits"], r.lines.join("\n"));
  let d = r.defects.find((x) => x.code === "sweep_hits")!;
  assert.match(d.what, new RegExp(`coverage record E-${named.entry.seq} names 3 objects an earlier sweep found hits in with no entry among its results that says what each showed: job:j000007/export\\.csv \\("alice", found by the sweep of E-${cov.seq}\\); job:j000008/a\\.txt .*; job:j000009/b\\.txt .*Naming a hit is not examining it`));
  assert.match(d.fix, /one entry per object .* or one absence whose refs list several .* written after the sweep/);
  assert.equal(r.dispositions["question:2"], undefined);
  // What each showed: a finding on the export; one absence over the other two, but first one that names only a directory, which examines nothing in particular.
  const seen = ok(await rec(a3, { kind: "finding", ...F, value: "the export's alice is a user of another host", source: "the export", evidence: "row 2", refs: ["job:j000007/export.csv"], answers: ["2"] })).entry;
  const byDir = ok(await rec(a3, { kind: "absence", value: "a remote tool in the notes", source: "the notes", evidence: "read", refs: ["job:j000008", "job:j000009"], answers: ["2"] })).entry;
  const cov3 = ok(await rec(a0, coverage("2", ["input:disk.E01", "job:j000007", "job:j000008", "job:j000009"], [`E-${abs.seq}`, "job:j000001/hits.txt", `E-${seen.seq}`, `E-${byDir.seq}`], { looked_for: ["alice"], supersedes: named.entry.seq }))).entry;
  ans = ok(await rec(a1, { kind: "answer", section: "question:2", value: "No evidence of a remote tool was found on the disk or the outputs", reasoning: `E-${cov3.seq}`, ...A, result: "bounded_negative", supersedes: ans.seq })).entry;
  await SW.awaitSweeps(S);
  await attested(a2, { seq: cov3.seq, how: "ran the search again", review: REVIEW, second_review_why: "the record now cites what the objects showed" });
  r = await checkLedgerAnswers(S, ["2"], ["2"]);
  d = r.defects.find((x) => x.code === "sweep_hits")!;
  assert.ok(d, r.lines.join("\n"));
  assert.match(d.what, /names 2 objects an earlier sweep found hits in .*: job:j000008\/a\.txt .*; job:j000009\/b\.txt/);
  assert.doesNotMatch(d.what, /export\.csv/, "the export is examined: a finding written after the sweep names it");
  // One absence over both, naming each object: released.
  const both = ok(await rec(a3, { kind: "absence", value: "a remote tool in the notes", source: "the notes", evidence: "read whole: each names a person, no tool", refs: ["job:j000008/a.txt", "job:j000009/b.txt"], answers: ["2"] })).entry;
  const cov4 = ok(await rec(a0, coverage("2", ["input:disk.E01", "job:j000007", "job:j000008", "job:j000009"], [`E-${abs.seq}`, "job:j000001/hits.txt", `E-${seen.seq}`, `E-${both.seq}`], { looked_for: ["alice"], supersedes: cov3.seq })));
  assert.doesNotMatch(cov4.note ?? "", /Naming a hit is not examining it/);
  ok(await rec(a1, { kind: "answer", section: "question:2", value: "No evidence of a remote tool was found on the disk or the outputs", reasoning: `E-${cov4.entry.seq}`, ...A, result: "bounded_negative", supersedes: ans.seq }));
  await SW.awaitSweeps(S);
  await attested(a2, { seq: cov4.entry.seq, how: "ran the search again", review: REVIEW, second_review_why: "the record now cites what each object showed" });
  r = await checkLedgerAnswers(S, ["2"], ["2"]);
  assert.deepEqual(codes(r, "question:2"), [], r.lines.join("\n"));
  assert.equal(r.dispositions["question:2"], "bounded_negative");
});

test("a hit in an object the record names does not hold; a partial sweep names what it did not search and holds until the operator accepts the question's limits; a sweep lost with its process is run again", async () => {
  const { S, a0, a1, a2 } = await run();
  await jobWith(S, "j000007", "export.csv", "time,user\n09:58,alice\n");
  const lead = await planned(a0, "2");
  const abs = ok(await rec(a0, { kind: "absence", value: "a remote tool", source: "the disk", evidence: "a search", refs: ["job:j000001/hits.txt"], answers: ["2"] })).entry;
  assert.ok((await L.closeLead(a0, lead, { disposition: "negative", ref: `E-${abs.seq}` })).ok);
  // Named already: the export is among the record's objects.
  const named = ok(await rec(a0, coverage("2", ["input:disk.E01", "job:j000007"], [`E-${abs.seq}`], { looked_for: ["alice"] }))).entry;
  await SW.awaitSweeps(S);
  const swN = SW.sweepOf(named, await SW.readSweeps(S))!;
  assert.deepEqual([swN.state, swN.hits.length, swN.named_hits.map((h) => h.ref)], ["clean", 0, ["job:j000007/export.csv"]]);
  // Lost with its process: the line gone, the gate's reader runs it again.
  await writeFile(join(S, SW.LEDGER_SWEEPS), "");
  assert.equal(await SW.reconcileSweeps(S, { orphanMs: 0 }), 1);
  assert.equal(SW.sweepOf(named, await SW.readSweeps(S))?.state, "clean");
  // A budget the sweep cannot keep: partial, every object it did not reach named.
  process.env.SWARM_SWEEP_MAX_BYTES = "1";
  let partial: P.LedgerEntry;
  try {
    partial = ok(await rec(a0, coverage("2", ["input:disk.E01"], [`E-${abs.seq}`], { looked_for: ["alice"], supersedes: named.seq }))).entry;
    await SW.awaitSweeps(S);
  } finally {
    delete process.env.SWARM_SWEEP_MAX_BYTES;
  }
  const swP = SW.sweepOf(partial, await SW.readSweeps(S))!;
  assert.equal(swP.state, "partial");
  assert.ok(swP.unsearched.some((u) => u.ref === "job:j000007/export.csv" && /would pass the sweep's byte budget \(1, SWARM_SWEEP_MAX_BYTES/.test(u.why)), JSON.stringify(swP.unsearched));
  const ans = ok(await rec(a1, { kind: "answer", section: "question:2", value: "No evidence of a remote tool was found on the disk", reasoning: `E-${partial.seq}`, ...A, result: "bounded_negative" })).entry;
  await attested(a2, { seq: partial.seq, how: "ran the search again", review: REVIEW });
  let r = await checkLedgerAnswers(S, ["2"], ["2"]);
  assert.deepEqual(codes(r, "question:2"), ["sweep_partial"]);
  assert.match(r.defects[0].what, new RegExp(`E-${partial.seq}, whose store sweep is partial: 0 object\\(s\\) searched, not searched: .*job:j000007/export\\.csv`));
  // The operator accepts the question's limits: the partial sweep holds no more.
  const accepted = await Q.act(S, OPERATOR, "accept", { q: "Q-2", as: "bounded", why: "the store is too large to sweep in this run", expected_rev: 1 });
  assert.ok(accepted.ok, (accepted as { reason?: string }).reason);
  r = await checkLedgerAnswers(S, ["2"], ["2"]);
  assert.deepEqual(codes(r, "question:2"), [], r.lines.join("\n"));
  assert.equal(P.ledgerGate({ entries: await P.readLedger(S), attestations: await P.readAttestations(S), disputes: [], sections: ["question:2"], sweeps: await SW.readSweeps(S) }).defects.some((x) => x.code === "sweep_partial" && x.seqs.includes(ans.seq)), true, "the gate still says it; the check excuses it for the accepted question");
  // A sweeps chain that does not verify: the check cannot read the gate.
  const text = await readFile(join(S, SW.LEDGER_SWEEPS), "utf8");
  await writeFile(join(S, SW.LEDGER_SWEEPS), text.replace('"state":"partial"', '"state":"clean"'));
  r = await checkLedgerAnswers(S, ["2"], ["2"]);
  assert.equal(r.ok, false);
  assert.match(r.lines[0], /ledger\/sweeps\.jsonl's chain is broken at line \d+ \(the line was rewritten\): what the store sweeps found cannot be read/);
});
