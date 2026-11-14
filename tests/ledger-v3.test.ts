/**
 * The ledger's version 3 (Fable and Codex, after reading 1,040 entries of 14
 * runs): a hypothesis with its status and a limitation with its reason; the
 * question an entry answers, its links to other entries, a sensitive mark, the
 * clock and precision of a time, observed or inferred, how far a search got,
 * an attribution, locators and a correction's reason. A second author saying
 * the same thing is an attestation appended beside the entry, never written
 * into it; the same sentence with other fields is its own entry or a correction.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  initSandbox,
  ledgerCore,
  listLedger,
  readLedger,
  recordEntry,
  standingContradictions,
  verifyAttestationChain,
  verifyLedgerChain,
  LEDGER_ATTESTATIONS,
  LEDGER_ENTRIES,
  LEDGER_MD,
  type LedgerEntry,
} from "../extensions/protocol.ts";
import { sealTree, storePaths } from "../scripts/evidence-store.ts";

/** What a finding carries from version 4 on: how it was seen, how sure and why, what it indicates. */
const F = { basis: "observed", confidence: "medium", indicates: "What the observation shows, and the step to it.", confidence_why: "Read directly from the object it cites." } as const;

async function run() {
  const root = await mkdtemp(join(tmpdir(), "ledger-v3-"));
  await initSandbox(root, { reset: true, agentIds: ["a0", "a1"] });
  await writeFile(join(root, "inputs.json"), JSON.stringify({ files: [{ path: "inputs/disk.E01", sha256: "a".repeat(64), bytes: 10 }] }));
  for (const [id, status] of [["j000001", "ok"], ["j000002", "failed"]] as const) {
    const staging = join(root, "..", `staging-${id}-${Math.random().toString(16).slice(2)}`);
    await mkdir(staging, { recursive: true });
    await writeFile(join(staging, "rows.json"), `{"job":"${id}"}\n`);
    await sealTree(root, staging, join(storePaths(root).jobs, id, "out"), id, 1);
    await writeFile(join(storePaths(root).jobs, id, "job.json"), JSON.stringify({ id, state: "committed", status }));
  }
  return { root, a0: { sandboxRoot: root, agentId: "a0" }, a1: { sandboxRoot: root, agentId: "a1" } };
}

const ok = (r: Awaited<ReturnType<typeof recordEntry>>) => {
  assert.ok(r.ok, (r as { reason?: string }).reason);
  return r as { ok: true; entry: LedgerEntry; merged: boolean; total: number; note?: string };
};
const refused = (r: Awaited<ReturnType<typeof recordEntry>>, re: RegExp) => {
  assert.equal(r.ok, false);
  assert.match((r as { reason: string }).reason, re);
};

test("a hypothesis has a status, a limitation a reason, and each field is checked", async () => {
  const { a0 } = await run();
  const h = ok(await recordEntry(a0, { kind: "hypothesis", value: "The vault key was typed by hand", source: "notes app", evidence: "a 48-digit string", confidence: "low" }));
  assert.equal(h.entry.status, "open", "a hypothesis starts open");
  assert.equal(h.entry.v, 4, "written at the current version");
  refused(await recordEntry(a0, { kind: "finding", ...F, value: "x", source: "s", evidence: "e", status: "open" }), /status is a hypothesis's/);
  refused(await recordEntry(a0, { kind: "limitation", value: "The vault's second volume", source: "vault.vhdx p2", evidence: "no key" }), /a limitation needs a reason/);
  const l = ok(await recordEntry(a0, { kind: "limitation", value: "The vault's second volume was not opened", source: "vault.vhdx p2", evidence: "bitlocker: no recovery key found", reason: "unavailable" }));
  assert.equal(l.entry.reason, "unavailable");
  refused(await recordEntry(a0, { kind: "finding", ...F, value: "x", source: "s", evidence: "e", reason: "failed" }), /reason is a limitation's/);
  refused(await recordEntry(a0, { kind: "finding", ...F, value: "x", source: "s", evidence: "e", answers: ["two words!"] }), /section ids/);
  // A section id in a spelling the seats used is the id it names: taken, and said.
  const spelt = ok(await recordEntry(a0, { kind: "finding", ...F, value: "y", source: "s", evidence: "e", answers: ["question:3", "Q 4"] }));
  assert.deepEqual(spelt.entry.answers, ["3", "4"]);
  assert.match(spelt.note ?? "", /answers "question:3", "Q 4" taken as "3", "4": answers takes the id alone/);
  refused(await recordEntry(a0, { kind: "finding", ...F, value: "x", source: "s", evidence: "e", clock: "NTFS $SI" }), /give ts too/);
  refused(await recordEntry(a0, { kind: "finding", ...F, value: "x", source: "s", evidence: "e", completion: "partial" }), /completion is an absence's/);
  refused(await recordEntry(a0, { kind: "finding", ...F, value: "x", source: "s", evidence: "e", because: "wrong" }), /give supersedes too/);
  refused(await recordEntry(a0, { kind: "finding", ...F, value: "x", source: "s", evidence: "e", rel: [{ to: 40, kind: "supports" }] }), /no entry #40/);
  refused(await recordEntry(a0, { kind: "finding", ...F, value: "x", source: "s", evidence: "e", rel: [{ to: 1, kind: "agrees" }] }), /rel.kind must be one of/);
  refused(await recordEntry(a0, { kind: "finding", ...F, value: "x", source: "s", evidence: "e", refs: ["job:j000001/rows.json"], locators: [{ ref: "input:disk.E01", at: "row 3" }] }), /not one of the entry's refs/);
  refused(await recordEntry(a0, { kind: "finding", ...F, value: "x", source: "s", evidence: "e", attribution: { subject: "", subject_type: "account" } }), /attribution.subject is required/);
  refused(await recordEntry(a0, { kind: "finding", ...F, value: "x", source: "s", evidence: "e", attribution: { subject: "bob", subject_type: "account", basis_refs: ["job:j000009/x"] } }), /attribution.basis_refs/);
});

test("the typed fields are recorded, chained, rendered and listed", async () => {
  const { root, a0, a1 } = await run();
  const event = ok(await recordEntry(a0, { kind: "event", value: "Powder.exe created", ts: "2024-04-05", clock: "NTFS $SI created", source: "$MFT", evidence: "istat 1234", basis: "observed", answers: ["Q4"] }));
  assert.equal(event.entry.precision, "date", "a date alone is a day, said as one");
  const finding = ok(await recordEntry(a1, { kind: "finding", ...F, value: "The suspect ran Powder.exe", source: "prefetch", evidence: "POWDER.EXE-1234.pf", refs: ["job:j000001/rows.json"], locators: [{ ref: "job:j000001/rows.json", at: "row 1" }], answers: ["Q4"], rel: [{ to: 1, kind: "derived_from" }], basis: "inferred", alternatives: [{ explanation: "Powder.exe was copied by a sync client", status: "rejected", why: "the prefetch file records a run" }], attribution: { subject: "laptop\\\\bob", subject_type: "account", basis_refs: ["input:disk.E01"] }, sensitive: true }));
  const against = ok(await recordEntry(a0, { kind: "hypothesis", value: "Powder.exe was only copied, never run", source: "amcache", evidence: "no execution flag", rel: [{ to: finding.entry.seq, kind: "contradicts" }] }));
  const absence = ok(await recordEntry(a0, { kind: "absence", value: "No other Powder.exe", source: "C: allocated files", evidence: "fls -r | grep -i powder", completion: "partial" }));
  assert.match(absence.note ?? "", /record what was not reached as kind=limitation/);
  const text = await readFile(join(root, LEDGER_ENTRIES), "utf8");
  assert.equal(verifyLedgerChain(text).ok, true);
  assert.match(ledgerCore(finding.entry), /"answers":\["Q4"\].*"rel":\[\{"to":1,"kind":"derived_from"\}\].*"sensitive":true/);
  assert.equal(verifyLedgerChain(text.replace('"answers":["Q4"]', '"answers":["Q5"]')).ok, false, "a changed answer breaks the chain");
  assert.equal(verifyLedgerChain(text.replace('"kind":"contradicts"', '"kind":"supports"')).ok, false, "and so does a changed link");
  const all = await readLedger(root);
  assert.deepEqual(standingContradictions(all), [{ from: against.entry.seq, to: finding.entry.seq }]);
  const md = await readFile(join(root, LEDGER_MD), "utf8");
  assert.match(md, /\| 2024-04-05 · clock: NTFS \$SI created \| Powder\.exe created \[answers Q4; observed\]/);
  assert.match(md, /The suspect ran Powder\.exe \[answers Q4; derived from #1; inferred; attributed to laptop\\\\bob \(account\); sensitive\]/);
  assert.match(md, /## Hypotheses[\s\S]*Powder\.exe was only copied, never run \[contradicts #2\] \| open/);
  assert.match(md, /## Standing contradictions\n\n- #3 contradicts #2; both stand/);
  assert.match(md, /No other Powder\.exe \[search partial\]/);
  // The hypothesis is refuted by a correction; the contradiction stops standing.
  ok(await recordEntry(a1, { kind: "hypothesis", value: "Powder.exe was only copied, never run", source: "amcache", evidence: "prefetch shows a run", status: "refuted", supersedes: against.entry.seq, because: "the prefetch file records a run count of 3" }));
  assert.deepEqual(standingContradictions(await readLedger(root)), []);
  const hyps = await listLedger(root, { kind: "hypothesis" });
  assert.deepEqual(hyps.map((e) => e.status), ["open", "refuted"]);
});

test("a duplicate names the entry that stands; a second author is an attestation, chained, and never rewrites the entry", async () => {
  const { root, a0, a1 } = await run();
  ok(await recordEntry(a0, { kind: "ioc", value: "10.0.0.9", source: "netscan", evidence: "row 4" }));
  ok(await recordEntry(a0, { kind: "ioc", value: "10.0.0.9 (C2)", source: "netscan", evidence: "row 4, beaconing", supersedes: 1 }));
  refused(await recordEntry(a1, { kind: "finding", ...F, value: "same host", source: "s", evidence: "e", rel: [{ to: 1, kind: "duplicates" }] }), /#1 is superseded by #2: a duplicate names the entry that stands, #2/);
  const before = await readFile(join(root, LEDGER_ENTRIES), "utf8");
  const again = ok(await recordEntry(a1, { kind: "ioc", value: "10.0.0.9 (C2)", source: "netscan", evidence: "row 4, beaconing" }));
  assert.equal(again.merged, true);
  assert.deepEqual(again.entry.authors, ["a0", "a1"]);
  assert.equal(await readFile(join(root, LEDGER_ENTRIES), "utf8"), before, "entries.jsonl is append-only: the attestation is not written into it");
  const twice = ok(await recordEntry(a1, { kind: "ioc", value: "10.0.0.9 (C2)", source: "netscan", evidence: "row 4, beaconing" }));
  assert.match(twice.note ?? "", /already says this, recorded by you/);
  const att = await readFile(join(root, LEDGER_ATTESTATIONS), "utf8");
  assert.equal(att.trim().split("\n").length, 1, "one attestation per author");
  assert.equal(verifyAttestationChain(att).ok, true);
  assert.equal(verifyAttestationChain(att.replace('"by":"a1"', '"by":"a9"')).ok, false, "a rewritten attestation breaks its chain");
  assert.match(await readFile(join(root, LEDGER_MD), "utf8"), /10\.0\.0\.9 \(C2\) \(corrects #1\).*\| a0, a1 \|/);
});

test("an entry resting on the kept output of a job that failed says why it still holds: a finding in qualifies, another kind is told", async () => {
  const { a0 } = await run();
  refused(await recordEntry(a0, { kind: "finding", ...F, value: "The message names the buyer", source: "q10_messages.json", evidence: "jq", refs: ["job:j000002/rows.json", "job:j000001/rows.json"] }), /rests on the kept output of a job that did not succeed \(job:j000002\/rows\.json: failed\): say in qualifies/);
  refused(await recordEntry(a0, { kind: "finding", ...F, value: "The message names the buyer", source: "q10_messages.json", evidence: "jq", refs: ["job:j000002/rows.json", "job:j000001/rows.json"], qualifies: [{ ref: "job:j000001/rows.json", why: "x" }] }), /rests on the kept output of a job that did not succeed \(job:j000002\/rows\.json: failed\).*To keep it, add qualifies: \[\{ref: "job:j000002\/rows\.json", why: "<why its bytes are still usable>"\}\].*Taken as meant, nothing to change there: qualifies on job:j000001\/rows\.json is left out: its job succeeded/);
  const r = ok(await recordEntry(a0, { kind: "finding", ...F, value: "The message names the buyer", source: "q10_messages.json", evidence: "jq", refs: ["job:j000002/rows.json", "job:j000001/rows.json"], qualifies: [{ ref: "job:j000002/rows.json", why: "the job failed after writing every row" }] }));
  assert.deepEqual(r.entry.qualifies, [{ ref: "job:j000002/rows.json", why: "the job failed after writing every row" }]);
  assert.equal(r.note, undefined, "a qualified ref needs no note");
  const ioc = ok(await recordEntry(a0, { kind: "ioc", value: "buyer@example.org", source: "q10_messages.json", evidence: "jq", refs: ["job:j000002/rows.json"] }));
  assert.match(ioc.note ?? "", /rests on the kept output of a job that did not succeed: job:j000002\/rows\.json \(job j000002: failed\)/);
  refused(await recordEntry(a0, { kind: "absence", value: "No second buyer", source: "q10_messages.json", evidence: "jq", refs: ["job:j000002/rows.json"], control: { ref: "job:j000002/rows.json", found: "the same search finds a planted row" } }), /cannot show that something is absent/);
});

test("the report shows hypotheses, limitations, contradictions, the questions answered and what is sensitive", async () => {
  const { renderReport } = await import("../scripts/report.ts");
  const { root, a0, a1 } = await run();
  const f = ok(await recordEntry(a0, { kind: "finding", ...F, value: "The suspect ran Powder.exe", source: "prefetch", evidence: "POWDER.EXE-1234.pf", refs: ["job:j000002/rows.json"], answers: ["Q4"], confidence: "high", qualifies: [{ ref: "job:j000002/rows.json", why: "the prefetch rows were written before the job failed" }] }));
  ok(await recordEntry(a1, { kind: "hypothesis", value: "Powder.exe was only copied", source: "amcache", evidence: "no execution flag", rel: [{ to: f.entry.seq, kind: "contradicts" }] }));
  ok(await recordEntry(a0, { kind: "limitation", value: "The second volume was not opened", source: "vault p2", evidence: "no key", reason: "unavailable", answers: ["5"] }));
  ok(await recordEntry(a0, { kind: "ioc", value: "recovery key 111111-222222", source: "notes", evidence: "row 11", sensitive: true }));
  const html = await renderReport(root, { runsDir: join(root, "..") });
  assert.match(html, /<h3>Hypotheses \(1\)<\/h3>/);
  assert.match(html, /<h3>Limitations \(1\)<\/h3>/);
  assert.match(html, /1 standing contradiction: <a href="#e-2">E-2<\/a> contradicts <a href="#e-1">E-1<\/a>/);
  // Each question with where it stands: named by entries, answered by none (the body's §1).
  // The one-screen table (docs/adr/0016): its answer column names the entries a question with no answer has.
  assert.match(html, /Question 4<\/a><\/td><td><span class="chip chip-brick">not answered<\/span><\/td><td>[^<]*<\/td><td>none; 1 entry: <a href="#e-1">E-1<\/a>/);
  assert.match(html, /Question 5<\/a><\/td><td><span class="chip chip-brick">not answered<\/span><\/td><td>[^<]*<\/td><td>none; 1 entry: <a href="#e-3">E-3<\/a>/);
  assert.match(html, /<h3>Sensitive material<\/h3><p>1 standing entry is marked sensitive: <a href="#e-4">E-4<\/a>/);
  assert.match(html, /Failed job<\/dt><dd>job:j000002\/rows\.json: job j000002 ended failed/, "the exhibit says it rests on a failed job's kept output");
  assert.match(html, /id="e-1">[\s\S]*?chip-saffron">qualified \(failed job\)</, "and that its finder says why those bytes hold");
});
