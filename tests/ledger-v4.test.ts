/**
 * The ledger's version 4 (two rounds between Claude, Fable and GPT-6-Astra
 * on a report that interprets): a finding says what it indicates, how sure
 * and why, and what else could explain it; the hub writes how each cited
 * object was made; an answer rests on the entries it cites by hash, every
 * claimed support checked at record and marked when it falls later,
 * transitively; tokens an answer asserts that no cited entry holds are
 * marked, never refused; attest and dispute are chained acts beside the
 * ledger; and the goal's check refuses a done once, naming the fix, and lets
 * the next through when a limitation names each defect left. Old ledgers
 * verify as they always did.
 */
import test, { after } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  answerCitations,
  answerProblems,
  answerSection,
  answerTokens,
  attestEntry,
  disputeEntry,
  finishLineVerdict,
  initSandbox,
  ledgerContent,
  ledgerCore,
  ledgerGate,
  ledgerHash,
  listLedger,
  openContradictions,
  readAttestations,
  readDisputes,
  readLedger,
  recordEntry,
  unsupportedTokens,
  verifyAttestationChain,
  verifyDisputeChain,
  verifyLedgerChain,
  LEDGER_ATTESTATIONS,
  LEDGER_DISPUTES,
  LEDGER_ENTRIES,
  LEDGER_MD,
  type LedgerEntry,
  type LedgerInput,
} from "../extensions/protocol.ts";
import { sealTree, storePaths } from "../scripts/evidence-store.ts";
import { briefQuestions, checkLedgerAnswers } from "../scripts/check-answers.ts";
import { takeCustody } from "../scripts/custody.ts";
import { FIXTURE_SECTIONS } from "./fixtures/ledger-v4/generate.ts";
import { openLead } from "../extensions/leads.ts";

const ROOT = join(import.meta.dirname, "..");
const FIXTURE = join(ROOT, "tests", "fixtures", "ledger-v4");
const dirs: string[] = [];
after(async () => {
  // A sealed job's output is read-only, as the store leaves it.
  for (const d of dirs) {
    spawnSync("chmod", ["-R", "u+w", d]);
    await rm(d, { recursive: true, force: true });
  }
});

const sha = (s: string) => createHash("sha256").update(s).digest("hex");
/** How a critic attests an answer to a question since B2: established, with the review part by part. */
const EST = { strength: "established", answer_review: { reproduced: "re-derived the cited finding from its sealed ref", read: "nothing beyond the cited entries", link: "the cited record is the host's own log of the event the question asks about", parts: [{ part: "the question as asked", established: true, why: "the cited finding shows it" }], inference: "the finding is the answer", alternatives: [{ explanation: "a copy of the record left by another process", why: "the cited record's own metadata ties it to the event", evidence: ["E-1"] }], other_family: { checked: false, text: "no other source family holds it in this fixture" }, discriminator: { rival: "a copy of the record written later by a backup process", test: "read the record's write time against the backup's run times", favours_if: "the answer if it falls outside every backup run; the rival if inside one", outcome: "it falls outside every backup run", refs: ["job:j000001/rows.txt"] }, derivation: { job: "j000001", inputs: ["input:disk.E01"] } } } as const;
/** A finding's version 4 fields, observed. */
const F = { basis: "observed", confidence: "high", indicates: "What the observation shows, and the step to it.", confidence_why: "Read directly from the object it cites." } as const;
/** A question's answer's required fields: an established result (the negative bar says what a negative needs). */
const Q = { result: "established", confidence: "high", confidence_why: "The cited entries are direct.", alternatives_open: "none open", would_change: "a second source that disagrees" } as const;

async function job(root: string, id: string, file: string, text: string, record: Record<string, unknown>): Promise<void> {
  const staging = join(root, "..", `staging-${id}-${Math.random().toString(16).slice(2)}`);
  await mkdir(staging, { recursive: true });
  await writeFile(join(staging, file), text);
  await sealTree(root, staging, join(storePaths(root).jobs, id, "out"), id, 1);
  await writeFile(join(storePaths(root).jobs, id, "job.json"), JSON.stringify({ id, state: "committed", ...record }));
}

async function run() {
  const base = await mkdtemp(join(tmpdir(), "ledger-v4-"));
  dirs.push(base);
  const root = join(base, "run");
  await mkdir(root);
  await initSandbox(root, { reset: true, agentIds: ["a0", "a1", "a2", "a3"] });
  await writeFile(join(root, "inputs.json"), JSON.stringify({ files: [{ path: "inputs/disk.E01", sha256: sha("disk"), bytes: 10 }, { path: "inputs/access.log", sha256: sha("log"), bytes: 10 }] }));
  const image = { image: "dfirswarm-disk:dev", image_digest: `sha256:${sha("img")}` };
  await job(root, "j000001", "rows.txt", "row 1: 2024-04-05T10:15:00Z C:\\Users\\Bob\\Desktop\\Powder.exe 88493-128-4\n", { spec: { kind: "command", inputs: ["input:disk.E01"], network: "off", command: "fls -r inputs/disk.E01" }, requester: { agent: "a0" }, status: "ok", exit: 0, ...image });
  await job(root, "j000002", "partial.txt", "three whole lines\n", { spec: { kind: "tool", inputs: ["all"], network: "off", tool: "evtx_query", args: { z: 1, a: "x" } }, requester: { agent: "a1" }, status: "failed", exit: 1, tool_sha256: sha("tool") });
  await job(root, "j000003", "grep.txt", "no hit\n", { spec: { kind: "import", inputs: ["work/a1/grep.txt"], network: "off", source: "work/a1/grep.txt" }, requester: { agent: "a1" }, status: "ok", exit: 0, ...image });
  await job(root, "j000004", "listing.tsv", "1\tBob/notes.txt\n", { spec: { kind: "recipe", inputs: ["input:disk.E01"], network: "off", recipe: "base/disk-volumes", target: { paths: ["/abs/inputs/disk.E01"], ref: "input:disk.E01" } }, requester: { agent: "system" }, status: "ok", exit: 0, tool_sha256: sha("recipe"), ...image });
  await mkdir(join(root, "catalog", "gen", "g0001"), { recursive: true });
  await writeFile(join(root, "catalog", "gen", "g0001", "generation.json"), JSON.stringify({ id: "g0001", job: "j000004" }));
  await writeFile(join(root, "catalog", "gen", "g0001", "members.tsv"), "1\tBob/notes.txt\n");
  const ctx = (id: string) => ({ sandboxRoot: root, agentId: id });
  return { root, a0: ctx("a0"), a1: ctx("a1"), a2: ctx("a2"), a3: ctx("a3") };
}

type Ok = { ok: true; entry: LedgerEntry; merged: boolean; total: number; note?: string };
const ok = (r: Awaited<ReturnType<typeof recordEntry>>): Ok => {
  assert.ok(r.ok, (r as { reason?: string }).reason);
  return r as Ok;
};
const refused = (r: { ok: boolean }, re: RegExp) => {
  assert.equal(r.ok, false, "expected a refusal");
  assert.match((r as unknown as { reason: string }).reason, re);
};
const rec = (c: { sandboxRoot: string; agentId: string }, input: Record<string, unknown>) => recordEntry(c, input as unknown as LedgerInput);

test("a finding says what it indicates, how sure and why, and what else could explain it; each field is checked and chained", async () => {
  const { root, a0, a1 } = await run();
  const base = { kind: "finding", value: "Powder.exe ran", source: "prefetch", evidence: "POWDER.EXE-1234.pf", refs: ["job:j000001/rows.txt"] };
  refused(await rec(a0, { ...base, confidence: "high", indicates: "i", confidence_why: "c" }), /basis observed or inferred/);
  refused(await rec(a0, { ...base, basis: "observed", indicates: "i" }), /confidence high, medium or low/);
  refused(await rec(a0, { ...base, basis: "observed", indicates: "i", confidence_why: "c" }), /confidence_why says why that confidence: give confidence too/);
  refused(await rec(a0, { ...base, basis: "observed", confidence: "high", confidence_why: "c" }), /indicates is required/);
  refused(await rec(a0, { ...base, basis: "observed", confidence: "high", indicates: "i" }), /confidence_why is required/);
  refused(await rec(a0, { ...base, ...F, indicates: "x".repeat(1501) }), /indicates is over 1500 characters/);
  refused(await rec(a0, { ...base, ...F, basis: "inferred" }), /an inferred finding lists what else could explain it/);
  refused(await rec(a0, { ...base, ...F, basis: "inferred", alternatives: [{ explanation: "copied only", status: "maybe", why: "w" }] }), /status must be one of rejected, open/);
  refused(await rec(a0, { ...base, ...F, basis: "inferred", alternatives: [{ explanation: "copied only", status: "open" }] }), /an alternative is \{explanation, status/);
  refused(await rec(a0, { ...base, ...F, basis: "inferred", alternatives: [{ explanation: "e", status: "open", why: "w" }], alternatives_none_why: "none" }), /give it or the alternatives, not both/);
  refused(await rec(a0, { ...base, ...F, basis: "inferred", alternatives: [{ explanation: "e", status: "rejected", why: "w", test_refs: ["job:j000001/rowz.txt"] }] }), /test_refs: ref "job:j000001\/rowz\.txt" does not resolve.*nearest: job:j000001\/rows\.txt/);
  refused(await rec(a0, { kind: "ioc", value: "10.0.0.9", source: "s", evidence: "e", indicates: "C2" }), /indicates is a finding's/);
  refused(await rec(a0, { kind: "ioc", value: "10.0.0.9", source: "s", evidence: "e", confidence_why: "c" }), /give confidence too/);
  refused(await rec(a0, { ...base, ...F, section: "question:1" }), /section is an answer's/);
  const f = ok(await rec(a0, { ...base, ...F, basis: "inferred", alternatives: [{ explanation: "Powder.exe was only copied", status: "rejected", why: "the prefetch file counts 3 runs", test_refs: ["job:j000001/rows.txt"] }], significance: "It puts the tool on the suspect's machine." }));
  assert.equal(f.entry.v, 4);
  assert.deepEqual(f.entry.alternatives, [{ explanation: "Powder.exe was only copied", status: "rejected", why: "the prefetch file counts 3 runs", test_refs: ["job:j000001/rows.txt"] }]);
  const none = ok(await rec(a1, { ...base, ...F, value: "Powder.exe ran twice", basis: "inferred", alternatives_none_why: "the count is read, not reasoned" }));
  assert.equal(none.entry.alternatives_none_why, "the count is read, not reasoned");
  const core = ledgerCore(f.entry);
  assert.match(core, /"indicates":"What the observation shows.*"confidence_why":"Read directly.*"alternatives":\[\{"explanation":"Powder\.exe was only copied","status":"rejected".*"significance":"It puts the tool/);
  // What a finding indicates is part of what it says; why that confidence is not.
  assert.notEqual(ledgerContent(f.entry), ledgerContent({ ...f.entry, indicates: "another indication" }));
  assert.equal(ledgerContent(f.entry), ledgerContent({ ...f.entry, confidence_why: "another why" }));
  const text = await readFile(join(root, LEDGER_ENTRIES), "utf8");
  assert.equal(verifyLedgerChain(text).ok, true);
  for (const [from, to] of [['"indicates":"What', '"indicates":"Not what'], ['"status":"rejected"', '"status":"open"'], ['"confidence_why":"Read', '"confidence_why":"Guessed']]) {
    assert.equal(verifyLedgerChain(text.replace(from, to)).ok, false, `${from} is in the chained core`);
  }
  // The same finding again from a peer, word for word: a second author, as a version 2 line naming the entry's hash.
  const again = ok(await rec(a1, { ...base, ...F, basis: "inferred", alternatives: [{ explanation: "Powder.exe was only copied", status: "rejected", why: "the prefetch file counts 3 runs", test_refs: ["job:j000001/rows.txt"] }], significance: "It puts the tool on the suspect's machine." }));
  assert.equal(again.merged, true);
  const att = await readAttestations(root);
  assert.deepEqual(att.map((a) => [a.v, a.act, a.seq, a.target]), [[2, "same_content", f.entry.seq, f.entry.hash]]);
  assert.deepEqual((await readLedger(root)).find((e) => e.seq === f.entry.seq)?.authors, ["a0", "a1"]);
  const md = await readFile(join(root, LEDGER_MD), "utf8");
  assert.match(md, /Powder\.exe ran \[inferred\] _\(high\)_.* — indicates: What the observation shows, and the step to it\. — why that confidence: Read directly.* — alternatives: Powder\.exe was only copied \(rejected: the prefetch file counts 3 runs; tested with job:j000001\/rows\.txt\) — significance: .* — made by: job j000001: command `fls -r inputs\/disk\.E01` in dfirswarm-disk:dev/);
});

test("a finding on a failed job's output says why in qualifies; it can never show an absence", async () => {
  const { a0 } = await run();
  const base = { kind: "finding", ...F, value: "Three events were parsed", source: "Security.evtx", evidence: "evtx_query", refs: ["job:j000002/partial.txt"] };
  refused(await rec(a0, base), /job:j000002\/partial\.txt: failed\): say in qualifies/);
  // A why on a job none of the entry's failed refs is from qualifies nothing: left out and said, and the ref that does need one is still named. Something that is no job is told which ref to use.
  refused(await rec(a0, { ...base, qualifies: [{ ref: "job:j000001/rows.txt", why: "w" }] }), /this finding rests on the kept output of a job that did not succeed \(job:j000002\/partial\.txt: failed\).*qualifies on job:j000001\/rows\.txt is left out: no ref of the entry from a job that failed is from that job/);
  refused(await rec(a0, { ...base, qualifies: [{ ref: "the parser's output", why: "w" }] }), /qualifies names "the parser's output", which is not one of the entry's refs: use exactly job:j000002\/partial\.txt, as refs has it/);
  refused(await rec(a0, { ...base, qualifies: [{ ref: "job:j000002/partial.txt" }] }), /qualifies is \[\{ref, why\}\]/);
  const q = ok(await rec(a0, { ...base, qualifies: [{ ref: "job:j000002/partial.txt", why: "the parser wrote three whole records before it failed" }] }));
  assert.equal(q.note, undefined);
  refused(await rec(a0, { kind: "absence", value: "No 4624", source: "Security.evtx", evidence: "evtx_query", refs: ["job:j000002/partial.txt"], control: { ref: "job:j000001/rows.txt", found: "the same search finds a planted row" } }), /cannot show that something is absent/);
  refused(await rec(a0, { kind: "absence", value: "No 4624", source: "Security.evtx", evidence: "evtx_query", refs: ["job:j000002/partial.txt"], control: { ref: "job:j000001/rows.txt", found: "the same search finds a planted row" }, completion: "complete" }), /cannot show that something is absent/);
  const partial = ok(await rec(a0, { kind: "absence", value: "No 4624 in what was parsed", source: "Security.evtx", evidence: "evtx_query", refs: ["job:j000002/partial.txt"], control: { ref: "job:j000001/rows.txt", found: "the same search finds a planted row" }, completion: "partial" }));
  assert.match(partial.note ?? "", /job that did not succeed/);
  // qualifies on a limitation says nothing the limitation does not: left out, and said (it was a refusal with nothing else to fix).
  const lim = ok(await rec(a0, { kind: "limitation", value: "The log was not parsed", source: "Security.evtx", evidence: "the parser failed", reason: "failed", refs: ["job:j000002/partial.txt"], qualifies: [{ ref: "job:j000002/partial.txt", why: "w" }] }));
  assert.match(lim.note ?? "", /qualifies is left out of this limitation: it says why a failed job's bytes still support a claim, and a limitation rests on what could not be done/);
  assert.equal(lim.entry.qualifies, undefined);
});

test("the hub writes how each cited object was made, canonical and chained, and the line alone re-verifies", async () => {
  const { root, a0 } = await run();
  await mkdir(join(storePaths(root).imports, "i0001"), { recursive: true });
  await writeFile(join(storePaths(root).imports, "i0001", "manifest.json"), JSON.stringify({ v: 1, job: "i0001", files: [{ path: "x.txt", path_b64: Buffer.from("x.txt").toString("base64"), bytes: 1, sha256: sha("x") }], dirs: [], rejected: [], totals: { files: 1, bytes: 1 } }));
  const f = ok(await rec(a0, { kind: "finding", ...F, value: "The note names Bob", source: "the image", evidence: "several jobs", refs: ["job:j000001/rows.txt", "job:j000002/partial.txt", "job:j000003/grep.txt", "member:g0001#1", "import:i0001/x.txt", "input:disk.E01", "job:j000001/rows.txt"], qualifies: [{ ref: "job:j000002/partial.txt", why: "whole lines before the failure" }] }));
  const byJob = new Map((f.entry.method ?? []).map((m) => [String(m.job ?? m.import), m]));
  assert.deepEqual([...byJob.keys()], ["i0001", "j000001", "j000002", "j000003", "j000004"], "one record per job or import, the member through its generation's job, the input none");
  assert.deepEqual(byJob.get("j000001"), { command: "fls -r inputs/disk.E01", declared_scope: ["input:disk.E01"], exit: 0, image: "dfirswarm-disk:dev", image_digest: `sha256:${sha("img")}`, job: "j000001", job_kind: "command", kind: "job", network: "off", status: "ok" });
  const tool = byJob.get("j000002") as Record<string, unknown>;
  assert.deepEqual(Object.keys(tool), [...Object.keys(tool)].sort(), "keys sorted");
  assert.deepEqual(tool.args, { a: "x", z: 1 }, "nested keys sorted too");
  assert.equal(tool.image_digest, "unknown", "what the run did not record stays unknown");
  assert.equal(tool.tool_version, "unknown");
  assert.equal(tool.status, "failed");
  assert.equal(byJob.get("j000003")?.kind, "import");
  assert.match(String(byJob.get("j000003")?.produced_by), /^a1, in its own VM; how the file was made is not recorded/);
  assert.equal(byJob.get("j000004")?.recipe, "base/disk-volumes");
  assert.equal(byJob.get("j000004")?.target, "input:disk.E01", "a target by its ref, never a host path");
  assert.match(String(byJob.get("i0001")?.produced_by), /^unknown/);
  assert.match(ledgerCore(f.entry), /"method":\[\{"import":"i0001"/);
  const text = await readFile(join(root, LEDGER_ENTRIES), "utf8");
  assert.equal(verifyLedgerChain(text.replace('"status":"failed"', '"status":"ok"')).ok, false, "a method changed after the fact breaks the chain");
  // The same line with its method's keys written in another order is the same core.
  const line = JSON.parse(text.trim()) as LedgerEntry;
  const shuffled = { ...line, method: line.method?.map((m) => Object.fromEntries(Object.entries(m).reverse())) };
  assert.equal(ledgerHash(shuffled, line.prev as string), line.hash);
});

test("versions 2, 3 and 4 chain together; the old cores are the bytes they were; an older version after a newer, or an unknown one, breaks the chain", async () => {
  const e1: LedgerEntry = { seq: 1, kind: "ioc", ts: "", value: "v1", by: "a0", authors: ["a0"], at: "2024-01-01T00:00:00Z" };
  const e2: LedgerEntry = { v: 2, seq: 2, kind: "finding", value: "v2", source: "s", evidence: "e", confidence: "high", refs: ["input:disk.E01"], supersedes: 1, by: "a0", authors: ["a0"], at: "2024-01-01T00:00:01Z" };
  const e3: LedgerEntry = { v: 3, seq: 3, kind: "finding", value: "v3", source: "s", evidence: "e", confidence: "medium", answers: ["3"], basis: "inferred", because: "b", by: "a0", authors: ["a0"], at: "2024-01-01T00:00:02Z" };
  const e4: LedgerEntry = { v: 4, seq: 4, kind: "finding", value: "v4", source: "s", evidence: "e", confidence: "low", basis: "observed", indicates: "i", confidence_why: "c", qualifies: [{ ref: "job:j1/x", why: "w" }], method: [{ z: 1, a: { d: 2, c: 1 } }], by: "a0", authors: ["a0"], at: "2024-01-01T00:00:03Z" };
  // The bytes each version was chained with, written out: a change to them is a broken ledger.
  assert.equal(ledgerCore(e1), '{"seq":1,"kind":"ioc","ts":"","value":"v1","by":"a0","at":"2024-01-01T00:00:00Z"}');
  assert.equal(ledgerCore(e2), '{"v":2,"seq":2,"kind":"finding","ts":"","value":"v2","source":"s","evidence":"e","confidence":"high","supersedes":1,"refs":["input:disk.E01"],"by":"a0","at":"2024-01-01T00:00:01Z"}');
  assert.equal(ledgerCore(e3), '{"v":3,"seq":3,"kind":"finding","ts":"","value":"v3","source":"s","evidence":"e","confidence":"medium","answers":["3"],"basis":"inferred","because":"b","by":"a0","at":"2024-01-01T00:00:02Z"}');
  assert.equal(ledgerCore({ ...e3, indicates: "ignored by version 3" }), ledgerCore(e3), "a version 3 core takes no version 4 field");
  assert.equal(ledgerCore(e4), '{"v":4,"seq":4,"kind":"finding","ts":"","value":"v4","source":"s","evidence":"e","confidence":"low","basis":"observed","indicates":"i","confidence_why":"c","qualifies":[{"ref":"job:j1/x","why":"w"}],"method":[{"a":{"c":1,"d":2},"z":1}],"by":"a0","at":"2024-01-01T00:00:03Z"}');
  const chain = (entries: LedgerEntry[]) => {
    let prev = "genesis";
    return entries.map((e, i) => {
      if (i === 0 && e.v === undefined) return JSON.stringify(e);
      const x = { ...e, prev: i === 0 ? "genesis" : prev };
      if (i === 1 && entries[0].v === undefined) x.prev = ledgerHash(entries[0], "genesis");
      x.hash = ledgerHash(x, x.prev);
      prev = x.hash;
      return JSON.stringify(x);
    }).join("\n");
  };
  const good = verifyLedgerChain(chain([e1, e2, e3, e4]));
  assert.equal(good.ok, true, good.reason ?? "");
  assert.equal(good.chained, 3);
  assert.equal(verifyLedgerChain(chain([e2, e4, { ...e3, seq: 5 }])).reason, "a version 3 entry after version 4 ones");
  assert.equal(verifyLedgerChain(chain([e2, e3, e4, { ...e2, seq: 5 }])).reason, "a version 2 entry after version 4 ones");
  const unknown = verifyLedgerChain(chain([e2, { ...e4, v: 5 as never }]));
  assert.equal(unknown.ok, false);
  assert.match(unknown.reason ?? "", /version 5, which this harness does not know/);
  assert.match(ledgerCore({ ...e4, v: 5 as never }), /^\{"unknown_version":5,"line":/, "an unknown version's core is its whole line, never the nearest version's");
});

test("custody holds every chained entry to the trace whatever its version: one of version 3 or 4 off the trace is named (the reverse trace check)", async () => {
  const { root, a0, a1 } = await run();
  // A version 2 and a version 3 entry as older harnesses wrote them, then the harness's own version 4 ones.
  const e1: LedgerEntry = { v: 2, seq: 1, kind: "ioc", value: "10.0.0.9", source: "fw.log", evidence: "line 9", by: "a0", authors: ["a0"], at: "2024-01-01T00:00:00Z" };
  e1.prev = "genesis";
  e1.hash = ledgerHash(e1, "genesis");
  const e2: LedgerEntry = { v: 3, seq: 2, kind: "event", ts: "2024-01-01T00:00:00.000Z", value: "logon", source: "Security.evtx", evidence: "4624", basis: "observed", by: "a1", authors: ["a1"], at: "2024-01-01T00:00:01Z" };
  e2.prev = e1.hash;
  e2.hash = ledgerHash(e2, e1.hash);
  await mkdir(join(root, "ledger"), { recursive: true });
  await writeFile(join(root, LEDGER_ENTRIES), `${JSON.stringify(e1)}\n${JSON.stringify(e2)}\n`);
  const e3 = ok(await rec(a0, { kind: "finding", ...F, value: "the logon came from 10.0.0.9", source: "Security.evtx", evidence: "4624 IpAddress", refs: ["job:j000001/rows.txt"] })).entry;
  const e4 = ok(await rec(a1, { kind: "ioc", value: "bob", source: "Security.evtx", evidence: "TargetUserName" })).entry;
  const line = (e: LedgerEntry) => JSON.stringify({ ts: e.at, agent: e.by, tool: "record", args: {}, result: { ok: true, seq: e.seq, merged: false, hash: e.hash } });
  await writeFile(join(root, "traces", "events.jsonl"), [e1, e2, e3, e4].map(line).join("\n") + "\n");
  let c = await takeCustody(root);
  assert.deepEqual(c.ledger?.not_on_trace, [], JSON.stringify(c.ledger));
  assert.equal(c.ledger?.intact, true);
  // The version 4 entry never carried on the trace: written into the file without the tool.
  await writeFile(join(root, "traces", "events.jsonl"), [e1, e2, e4].map(line).join("\n") + "\n");
  c = await takeCustody(root);
  assert.deepEqual(c.ledger?.not_on_trace, [e3.seq]);
  assert.equal(c.ledger?.intact, false);
});

test("an answer rests on the entries it cites by hash; every claimed support is checked when it is recorded", async () => {
  const { root, a0, a1, a2, a3 } = await run();
  const f1 = ok(await rec(a0, { kind: "finding", ...F, value: "Powder.exe ran at 10:15Z", source: "prefetch", evidence: "row 1", refs: ["job:j000001/rows.txt"], answers: ["1"] })).entry;
  const f2 = ok(await rec(a1, { kind: "finding", ...F, value: "Powder.exe was on the desktop", source: "$MFT", evidence: "row 1", refs: ["job:j000001/rows.txt"] })).entry;
  const hyp = ok(await rec(a1, { kind: "hypothesis", value: "Bob ran it", source: "prefetch", evidence: "row 1", answers: ["1"] })).entry;
  const lim = ok(await rec(a1, { kind: "limitation", value: "The second volume was not opened", source: "p2", evidence: "no key", reason: "unavailable", answers: ["2"] })).entry;
  const ans = { kind: "answer", section: "question:1", value: "Powder.exe ran at 10:15Z", ...Q };
  refused(await rec(a3, { ...ans, section: "question:" }), /section is question:<id>/);
  refused(await rec(a3, { ...ans, reasoning: `E-${f1.seq}`, refs: ["input:disk.E01"] }), /refs is not an answer's/);
  refused(await rec(a3, { ...ans, reasoning: `E-${f1.seq}`, basis: "observed" }), /basis is not an answer's/);
  refused(await rec(a3, { ...ans }), /reasoning is required/);
  refused(await rec(a3, { ...ans, reasoning: `E-${f1.seq}`, confidence: undefined }), /confidence high, medium or low/);
  refused(await rec(a3, { ...ans, reasoning: `E-${f1.seq}`, would_change: "" }), /would_change is required/);
  refused(await rec(a3, { ...ans, reasoning: `E-${f1.seq}`, alternatives_open: "" }), /alternatives_open is required/);
  refused(await rec(a3, { ...ans, reasoning: "E-99" }), /E-99: there is no entry #99/);
  refused(await rec(a3, { ...ans, reasoning: `E-${f2.seq} and E-${hyp.seq}` }), new RegExp(`rests on at least one standing finding, search, limitation or coverage record recorded with answers=\\["1"\\].*none of E-${f2.seq}, E-${hyp.seq} names it`));
  refused(await rec(a3, { ...ans, reasoning: `E-${f1.seq}`, limitations: [f2.seq] }), /limitations names #\d+, a finding/);
  // A qualifies on an entry the answer does not cite is refused, with the entries that need one; one on a cited entry that needs none is left out and said (the answer below).
  refused(await rec(a3, { ...ans, reasoning: `E-${f1.seq}`, qualifies: [{ ref: `E-${f2.seq}`, why: "w" }] }), /qualifies names E-\d+, which the answer does not cite as support: it qualifies only a cited entry that needs it \(none of the entries it cites does: leave qualifies out\)/);
  const a = ok(await rec(a3, { ...ans, section: "Q1", reasoning: `Prefetch says so (E-${f1.seq}); it was on the desktop (E-${f2.seq}); a hypothesis (E-${hyp.seq}).`, contrary: [`E-${hyp.seq}`], limitations: [lim.seq], qualifies: [{ ref: `E-${f1.seq}`, why: "w" }] }));
  assert.match(a.note ?? "", new RegExp(`Taken as meant, nothing to change there: qualifies on E-${f1.seq} is left out: it is neither disputed nor resting on a failed job`));
  assert.equal(a.entry.qualifies, undefined);
  assert.equal(a.entry.section, "question:1", "Q1 is question:1");
  assert.deepEqual(a.entry.support, [{ seq: f1.seq, hash: f1.hash }, { seq: f2.seq, hash: f2.hash }], "contrary evidence is not support");
  assert.deepEqual(a.entry.contrary, [{ seq: hyp.seq, hash: hyp.hash }]);
  assert.deepEqual(a.entry.limitations, [{ seq: lim.seq, hash: lim.hash }]);
  assert.match(ledgerCore(a.entry), /"section":"question:1","reasoning":"Prefetch.*"support":\[\{"seq":1,"hash":"[0-9a-f]{64}"\}.*"contrary":.*"limitations":.*"alternatives_open":"none open","would_change":/);
  const text = await readFile(join(root, LEDGER_ENTRIES), "utf8");
  assert.equal(verifyLedgerChain(text.replace("Prefetch says so", "Prefetch proves it")).ok, false, "the reasoning is chained");
  assert.equal(verifyLedgerChain(text.replace(`"support":[{"seq":${f1.seq},"hash":"${f1.hash}"`, `"support":[{"seq":${f1.seq},"hash":"${"0".repeat(64)}"`)).ok, false, "and so is every edge's hash");
  // One answer stands for a section: a second is refused; a revision supersedes it.
  refused(await rec(a1, { ...ans, reasoning: `E-${f1.seq}, again` }), new RegExp(`question:1 is answered by #${a.entry.seq} already.*supersedes=${a.entry.seq}`));
  refused(await rec(a1, { ...ans, reasoning: `E-${f1.seq}`, supersedes: f1.seq }), /an answer corrects an answer/);
  refused(await rec(a1, { kind: "finding", ...F, value: "x", source: "s", evidence: "e", supersedes: a.entry.seq }), /is an answer: an answer is corrected by an answer/);
  refused(await rec(a3, { ...ans, section: "question:2", reasoning: `E-${lim.seq}`, supersedes: a.entry.seq }), /an answer corrects the answer to its own section/);
  refused(await rec(a3, { ...ans, reasoning: `E-${f1.seq} and E-${a.entry.seq}`, supersedes: a.entry.seq }), /does not rest on the answer it corrects/);
  const revised = ok(await rec(a3, { ...ans, reasoning: `Prefetch (E-${f1.seq}).`, supersedes: a.entry.seq, because: "the desktop copy is not needed" }));
  assert.equal(revised.entry.supersedes, a.entry.seq);
  // The same answer again from another agent: a second author, not a second answer.
  const same = ok(await rec(a2, { ...ans, reasoning: `Prefetch (E-${f1.seq}).` }));
  assert.equal(same.merged, true);
  // A summary and a narrative need one standing citation; they name no question.
  refused(await rec(a3, { kind: "answer", section: "summary", value: "s", reasoning: "no citation" }), /a summary cites at least one standing entry/);
  const s = ok(await rec(a3, { kind: "answer", section: "summary", value: "Powder.exe ran.", reasoning: `See E-${revised.entry.seq}.` }));
  // An answer a summary cites by its seq is bound to its question instead (the c10 pilot): not held by its seq.
  assert.deepEqual(s.entry.support ?? [], []);
  assert.deepEqual(s.entry.question_refs?.map((r) => [r.section, r.answer]), [["question:1", revised.entry.seq]]);
  ok(await rec(a3, { kind: "answer", section: "narrative", value: "At 10:15Z Powder.exe ran from the desktop.", reasoning: `E-${f2.seq} then E-${f1.seq}.` }));
  // An inconclusive answer (the old word for not_determinable) rests on a
  // coverage record of its material question, closed against its route plan.
  const inconclusive = { kind: "answer", section: "question:2", value: "Not established", ...Q, result: undefined, inconclusive: true };
  refused(await rec(a3, { ...inconclusive, reasoning: `The volume was not opened (E-${lim.seq}).` }), /question:2 is a material question with no route plan/);
  assert.ok((await openLead(a1, { title: "Open the second volume", why: "question 2 rests on it", answers: ["2"], take: true, routes: [{ source: "input:disk.E01", method: "open the second volume with the recovered key" }] })).ok);
  refused(await rec(a3, { ...inconclusive, reasoning: `The volume was not opened (E-${lim.seq}).` }), /a not determinable on a material question rests on a coverage record/);
  const cov = ok(await rec(a1, { kind: "coverage", looked_for_none_why: "no literal form a byte search could find", proposition: "The second volume holds the answer to question 2", refs: ["input:disk.E01"], answers: ["2"], time_range: "the whole image, no time bound", search_method: "open the volume", settings: "no key", coverage_actual: "the first volume only", skipped: "the second volume, which did not open", failures: "the volume would not decrypt", result_refs: [`E-${lim.seq}`], alternatives: "a key in memory, not examined", detection_opportunity: { trace_expected: "unknown", why: "what the volume holds was never read" } })).entry;
  const inc = ok(await rec(a3, { ...inconclusive, reasoning: `The volume was not opened (E-${lim.seq}); what was searched is E-${cov.seq}.` }));
  assert.equal(inc.entry.inconclusive, true);
  assert.equal(inc.entry.result, "not_determinable", "inconclusive is recorded as the result it is");
  const listed = await listLedger(root, { kind: "answer" });
  assert.equal(listed.length, 5);
  assert.match(await readFile(join(root, LEDGER_MD), "utf8"), /## Answers[\s\S]*question:2 \(inconclusive\) \(not_determinable\) \*\*\(negative, unreviewed\)\*\*: Not established/);
});

test("a superseded entry is cited only with its correction and supports nothing; a disputed one, or one on a failed job, only with qualifies", async () => {
  const { a0, a1, a2, a3 } = await run();
  const f1 = ok(await rec(a0, { kind: "finding", ...F, value: "The key is 1234", source: "notes", evidence: "row 1", refs: ["job:j000001/rows.txt"], answers: ["1"] })).entry;
  const fix = ok(await rec(a1, { kind: "finding", ...F, value: "The key is 1235", source: "notes", evidence: "row 1, read again", refs: ["job:j000001/rows.txt"], answers: ["1"], supersedes: f1.seq })).entry;
  const ans = { kind: "answer", section: "question:1", value: "The key", ...Q };
  refused(await rec(a3, { ...ans, reasoning: `E-${f1.seq}` }), new RegExp(`E-${f1.seq} is superseded by #${fix.seq}: cite E-${fix.seq}, the correction`));
  // A superseded entry beside its correction gains no authority: only the correction names the question.
  const other = ok(await rec(a0, { kind: "finding", ...F, value: "The notes app holds it", source: "notes", evidence: "db", refs: ["job:j000001/rows.txt"], answers: ["2"] })).entry;
  const old2 = ok(await rec(a0, { kind: "finding", ...F, value: "Question 2's old answer", source: "notes", evidence: "db", refs: ["job:j000001/rows.txt"], answers: ["2"] })).entry;
  ok(await rec(a1, { kind: "finding", ...F, value: "Question 2's new answer, which names another question", source: "notes", evidence: "db", refs: ["job:j000001/rows.txt"], answers: ["5"], supersedes: old2.seq }));
  refused(await rec(a3, { ...ans, section: "question:2", reasoning: `E-${old2.seq} and E-${old2.seq + 1}` }), /rests on at least one standing finding/);
  ok(await rec(a3, { ...ans, section: "question:2", reasoning: `E-${other.seq}` }));
  const a = ok(await rec(a3, { ...ans, reasoning: `E-${f1.seq} said 1234; E-${fix.seq} corrects it.` })).entry;
  assert.deepEqual(a.support?.map((x) => x.seq), [f1.seq, fix.seq]);
  // A disputed entry.
  const f3 = ok(await rec(a0, { kind: "finding", ...F, value: "The vault opened", source: "vault", evidence: "dislocker", refs: ["job:j000001/rows.txt"], answers: ["3"] })).entry;
  assert.ok((await disputeEntry(a2, { seq: f3.seq, why: "the key does not match the protector" })).ok);
  refused(await rec(a3, { ...ans, section: "question:3", reasoning: `E-${f3.seq}` }), new RegExp(`E-${f3.seq} is disputed by a2: the key does not match the protector.*qualifies \\[\\{ref: "E-${f3.seq}", why\\}\\]`));
  const q3 = ok(await rec(a3, { ...ans, section: "question:3", reasoning: `E-${f3.seq}`, qualifies: [{ ref: `E-${f3.seq}`, why: "the volume's files were read, so it opened whatever the protector" }] })).entry;
  assert.deepEqual(q3.qualifies, [{ ref: `E-${f3.seq}`, why: "the volume's files were read, so it opened whatever the protector" }]);
  // A version 3 finding on a failed job's output, which says nothing of it: the answer must.
  const { root } = { root: a0.sandboxRoot };
  const text = await readFile(join(root, LEDGER_ENTRIES), "utf8");
  const last = JSON.parse(text.trim().split("\n").at(-1) as string) as LedgerEntry;
  const legacy: LedgerEntry = { v: 3, seq: last.seq + 1, kind: "finding", value: "Three events", source: "evtx", evidence: "evtx_query", refs: ["job:j000002/partial.txt"], answers: ["4"], by: "a0", authors: ["a0"], at: "2024-01-01T00:00:00Z", prev: last.hash };
  legacy.hash = ledgerHash(legacy, last.hash as string);
  await writeFile(join(root, LEDGER_ENTRIES), `${text}${JSON.stringify(legacy)}\n`);
  refused(await rec(a3, { ...ans, section: "question:4", reasoning: `E-${legacy.seq}` }), new RegExp(`E-${legacy.seq} rests on the kept output of a job that did not succeed \\(job:j000002/partial\\.txt \\(failed\\)\\)`));
  ok(await rec(a3, { ...ans, section: "question:4", reasoning: `E-${legacy.seq}`, qualifies: [{ ref: `E-${legacy.seq}`, why: "whole records before the failure" }] }));
});

test("the token check normalises before it matches, marks what no cited entry holds, and never refuses", async () => {
  const toks = (t: string) => answerTokens(t).map((x) => `${x.kind}:${x.norm}`);
  assert.deepEqual(toks("sha256 ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"), ["hash:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"]);
  assert.deepEqual(toks("at 2024-03-20 14:05 and 2024-03-20T17:05:09+03:00 on 2024-03-21"), ["time:2024-03-20T14:05", "time:2024-03-20T14:05:09", "time:2024-03-21"]);
  assert.deepEqual(toks("C:\\Users\\Bob\\Desktop\\Powder.exe, /var/log/auth.log and work/a0/x.txt"), ["path:/users/bob/desktop/powder.exe", "path:/var/log/auth.log", "path:work/a0/x.txt"]);
  assert.deepEqual(toks("inode 88493-128-4 and inode 12"), ["inode:88493", "inode:12"]);
  assert.deepEqual(toks("from 10.0.0.9 and fe80::1:2"), ["ip:10.0.0.9", "ip:fe80::1:2"]);
  assert.deepEqual(toks("bob@example.org as CORP\\bob, S-1-5-21-1-2-3-1001"), ["account:bob@example.org", "account:corp/bob", "account:S-1-5-21-1-2-3-1001"]);
  assert.deepEqual(toks("and/or TCP/IP, E-12/E-13, 03/20/2024, https://example.org/a/b.html, 14:05:22"), [], "none of these is a token");
  const e = (seq: number, fields: Partial<LedgerEntry>): LedgerEntry => ({ v: 4, seq, kind: "finding", value: "", by: "a0", authors: ["a0"], at: "2099-01-01T00:00:00Z", ...fields });
  const cited = [e(1, { value: "C:/users/bob/desktop/POWDER.EXE ran", ts: "2024-03-20T14:05:09.000Z", evidence: "inode 88493", refs: ["job:j000001/rows.txt"] }), e(2, { value: "hash ABCDEF0123456789ABCDEF0123456789", source: "10.0.0.9 in fw.log" })];
  const bySeq = new Map(cited.map((x) => [x.seq, x]));
  assert.deepEqual(
    unsupportedTokens("C:\\Users\\Bob\\Desktop\\Powder.exe ran at 2024-03-20 14:05 (inode 88493-128-4) from 10.0.0.9; hash abcdef0123456789abcdef0123456789; job:j000001/rows.txt", cited, bySeq),
    [],
    "case, separators, drive letter, the minute of a time to the second, an inode's first number",
  );
  assert.deepEqual(unsupportedTokens("at 2024-03-20T14:06Z from 10.0.0.10 as bob@example.org; 2099-01-01", cited, bySeq), ["2024-03-20T14:06Z", "10.0.0.10", "bob@example.org", "2099-01-01"], "an entry's own write time supports nothing");
  // A token an answer asserted without support is not supported by being repeated: a cited answer lends its entries, not its words.
  const answer: LedgerEntry = { ...e(3, { kind: "answer", value: "the key is 1111-2222-3333", reasoning: "S-1-5-21-9-9-9-500", support: [{ seq: 1, hash: "h" }] }) };
  bySeq.set(3, answer);
  assert.deepEqual(unsupportedTokens("S-1-5-21-9-9-9-500 ran POWDER.EXE from C:\\users\\bob\\desktop\\powder.exe", [answer], bySeq), ["S-1-5-21-9-9-9-500"]);
  // At record: marked on the answer and in its note, never refused.
  const { a0, a3 } = await run();
  const f = ok(await rec(a0, { kind: "finding", ...F, value: "Powder.exe ran at 2024-04-05T10:15:00Z", source: "C:\\Users\\Bob\\Desktop\\Powder.exe", evidence: "row 1", refs: ["job:j000001/rows.txt"], answers: ["1"] })).entry;
  const a = ok(await rec(a3, { kind: "answer", section: "question:1", value: "It ran at 2024-04-05 10:15 from C:/Users/Bob/Desktop/Powder.exe", reasoning: `E-${f.seq}; its hash is ${"d".repeat(64)} and it wrote /tmp/out.bin`, ...Q }));
  assert.deepEqual(a.entry.unsupported_tokens, ["d".repeat(64), "/tmp/out.bin"]);
  assert.match(a.note ?? "", /in none of the cited entries: d{64}, \/tmp\/out\.bin/);
  assert.equal(answerCitations("E-3, E-5–E-7 and #9").join(","), "3,5,6,7");
  assert.deepEqual(answerSection("Q12"), { ok: true, section: "question:12", id: "12" });
  assert.equal(answerSection("question:summary").ok, false);
});

test("attest says how an entry was re-derived; dispute says why it does not hold; each is its own chain and neither is the author's", async () => {
  const { root, a0, a1, a2 } = await run();
  const f = ok(await rec(a0, { kind: "finding", ...F, value: "Powder.exe ran", source: "prefetch", evidence: "row 1", refs: ["job:j000001/rows.txt"] })).entry;
  const fix = ok(await rec(a1, { kind: "finding", ...F, value: "Powder.exe ran three times", source: "prefetch", evidence: "row 1, run count", refs: ["job:j000001/rows.txt"], supersedes: f.seq })).entry;
  refused(await attestEntry(a1, { seq: fix.seq, how: "x" }), /is yours/);
  refused(await attestEntry(a2, { seq: f.seq, how: "x" }), new RegExp(`superseded by #${fix.seq}: attest the entry that stands`));
  refused(await attestEntry(a2, { seq: fix.seq, how: "" }), /how is required/);
  refused(await attestEntry(a2, { seq: 99, how: "x" }), /no entry #99/);
  refused(await attestEntry(a2, { seq: fix.seq, how: "x", refs: ["job:j000001/rowz.txt"] }), /does not resolve/);
  const at = await attestEntry(a2, { seq: `E-${fix.seq}`, how: "re-derived the run count from job:j000001/rows.txt row 1; read the rest", refs: ["job:j000001/rows.txt"] });
  assert.ok(at.ok && at.appended);
  assert.deepEqual([at.line.v, at.line.act, at.line.target, at.line.how, at.line.refs], [2, "attest", fix.hash, "re-derived the run count from job:j000001/rows.txt row 1; read the rest", ["job:j000001/rows.txt"]]);
  const twice = await attestEntry(a2, { seq: fix.seq, how: "again" });
  assert.ok(twice.ok && !twice.appended && /already/.test(twice.note ?? ""));
  assert.deepEqual((await readLedger(root)).find((e) => e.seq === fix.seq)?.authors, ["a1"], "an attester is not an author");
  refused(await disputeEntry(a1, { seq: fix.seq, why: "x" }), /is yours: correct it with record\(supersedes=/);
  refused(await disputeEntry(a0, { seq: fix.seq, why: "" }), /why is required/);
  refused(await disputeEntry(a0, { seq: fix.seq, why: "x", withdraw: true }), /no standing dispute/);
  const d = await disputeEntry(a0, { seq: fix.seq, why: "the run count is of another Powder.exe" });
  assert.ok(d.ok && d.line.act === "dispute" && d.line.target === fix.hash);
  refused(await attestEntry(a0, { seq: fix.seq, how: "x" }), /you dispute #\d+: withdraw the dispute/);
  const w = await disputeEntry(a0, { seq: fix.seq, why: "the path matches after all", withdraw: true });
  assert.ok(w.ok && w.line.act === "withdraw");
  const listed = (await listLedger(root)).find((e) => e.seq === fix.seq) as LedgerEntry & { attested_by?: string[]; disputed_by?: unknown[] };
  assert.deepEqual(listed.attested_by, ["a2"]);
  assert.equal(listed.disputed_by, undefined, "a withdrawn dispute no longer stands");
  const attText = await readFile(join(root, LEDGER_ATTESTATIONS), "utf8");
  assert.equal(verifyAttestationChain(attText).ok, true);
  assert.equal(verifyAttestationChain(attText.replace("re-derived the run count", "glanced at the run count")).ok, false, "the how is inside the hashed record");
  assert.equal(verifyAttestationChain(`${attText}${JSON.stringify({ seq: 1, by: "a3", at: "t", prev: JSON.parse(attText.trim().split("\n").at(-1) as string).hash, hash: "x" })}\n`).reason, "a version 1 attestation after version 2 ones");
  assert.match(verifyAttestationChain(JSON.stringify({ v: 3, seq: 1 })).reason ?? "", /version 3, which this harness does not know/);
  const disText = await readFile(join(root, LEDGER_DISPUTES), "utf8");
  assert.equal(verifyDisputeChain(disText).ok, true);
  assert.equal(verifyDisputeChain(disText.replace("another Powder.exe", "a different file")).ok, false, "the why is inside the hashed record");
  assert.match(verifyDisputeChain(JSON.stringify({ v: 1, act: "retract" })).reason ?? "", /act is "retract"/);
  const md = await readFile(join(root, LEDGER_MD), "utf8");
  assert.match(md, /Powder\.exe ran three times \(corrects #1\) \[observed\] \[attested by a2\]/);
});

test("invalidation is transitive: a finding superseded or disputed after an answer rests on it marks the answer and every answer resting on that one", async () => {
  const { root, a0, a1, a2, a3 } = await run();
  const f = ok(await rec(a0, { kind: "finding", ...F, value: "Bob ran it", source: "prefetch", evidence: "row 1", refs: ["job:j000001/rows.txt"], answers: ["1"] })).entry;
  const q1 = ok(await rec(a3, { kind: "answer", section: "question:1", value: "Bob", reasoning: `E-${f.seq}`, ...Q })).entry;
  const sum = ok(await rec(a3, { kind: "answer", section: "summary", value: "Bob ran it.", reasoning: `E-${q1.seq}` })).entry;
  const nar = ok(await rec(a3, { kind: "answer", section: "narrative", value: "Bob ran it at 10:15.", reasoning: `E-${sum.seq}` })).entry;
  const problems = async () => answerProblems(await readLedger(root), await readDisputes(root));
  assert.equal((await problems()).size, 0);
  assert.ok((await disputeEntry(a2, { seq: f.seq, why: "the prefetch is of another user's profile" })).ok);
  let p = await problems();
  assert.match(p.get(q1.seq)?.[0] ?? "", new RegExp(`rests on E-${f.seq}, disputed by a2 \\(the prefetch is of another user's profile\\)`));
  // The summary cited E-q1 by its seq, which binds it to question:1 (the c10 pilot's fix): it falls with that question's answer.
  assert.match(p.get(sum.seq)?.[0] ?? "", new RegExp(`it cites question:1 \\(question:1\\), whose answer E-${q1.seq} no longer stands on its own support`));
  assert.match(p.get(nar.seq)?.[0] ?? "", new RegExp(`rests on E-${sum.seq}, an answer that no longer stands`), "and on through every answer above it");
  // Citing a fallen answer is refused at record.
  refused(await rec(a3, { kind: "answer", section: "narrative", value: "n", reasoning: `E-${q1.seq}`, supersedes: nar.seq }), new RegExp(`question:1's answer E-${q1.seq} no longer stands on its own support`));
  // The dispute withdrawn, the chain stands again; the finding superseded, it falls the other way.
  assert.ok((await disputeEntry(a2, { seq: f.seq, why: "same user after all", withdraw: true })).ok);
  assert.equal((await problems()).size, 0);
  const g = ok(await rec(a1, { kind: "finding", ...F, value: "Alice ran it", source: "prefetch", evidence: "row 1, user SID", refs: ["job:j000001/rows.txt"], answers: ["1"], supersedes: f.seq })).entry;
  p = await problems();
  assert.match(p.get(q1.seq)?.[0] ?? "", new RegExp(`rests on E-${f.seq}, superseded by #${g.seq}, and does not cite the correction`));
  assert.ok(p.has(sum.seq) && p.has(nar.seq));
  const md = await readFile(join(root, LEDGER_MD), "utf8");
  assert.match(md, /\*\*no longer stands on its support: it rests on E-\d+, superseded by #\d+/);
  // Revised on another support, the question's answer stands; the summary bound to its earlier conclusion is recorded again.
  const q1b = ok(await rec(a3, { kind: "answer", section: "question:1", value: "Alice", reasoning: `E-${g.seq}`, ...Q, supersedes: q1.seq })).entry;
  p = await problems();
  assert.equal(p.has(q1b.seq), false);
  assert.match(p.get(sum.seq)?.[0] ?? "", new RegExp(`whose answer changed its support, scope or contrary evidence since it was cited \\(E-${q1.seq} → E-${q1b.seq}\\)`));
});

test("an open contradiction is two standing entries that contradict, weighed by no answer and named by no limitation", async () => {
  const { root, a0, a1, a3 } = await run();
  const x = ok(await rec(a0, { kind: "finding", ...F, value: "It ran at 10:15", source: "prefetch", evidence: "row 1", refs: ["job:j000001/rows.txt"], answers: ["1"] })).entry;
  const y = ok(await rec(a1, { kind: "finding", ...F, value: "It never ran", source: "amcache", evidence: "no execution flag", refs: ["job:j000001/rows.txt"], rel: [{ to: x.seq, kind: "contradicts" }] })).entry;
  assert.deepEqual(openContradictions(await readLedger(root)), [{ from: y.seq, to: x.seq }]);
  const g1 = ledgerGate({ entries: await readLedger(root), attestations: [], disputes: [], sections: [] });
  assert.equal(g1.open[0]?.code, "open_contradiction");
  assert.match(g1.open[0]?.fix ?? "", new RegExp(`record a limitation citing E-${y.seq} and E-${x.seq}`));
  // An answer that holds both, one as its contrary evidence, weighs it.
  ok(await rec(a3, { kind: "answer", section: "question:1", value: "It ran", reasoning: `E-${x.seq}; the amcache flag (E-${y.seq}) is not written for every run`, contrary: [y.seq], ...Q }));
  assert.deepEqual(openContradictions(await readLedger(root)), []);
  // So does a limitation that names both, without an answer.
  const z = ok(await rec(a0, { kind: "finding", ...F, value: "It ran twice", source: "prefetch", evidence: "count", refs: ["job:j000001/rows.txt"], rel: [{ to: y.seq, kind: "contradicts" }] })).entry;
  assert.deepEqual(openContradictions(await readLedger(root)), [{ from: z.seq, to: y.seq }]);
  ok(await rec(a0, { kind: "limitation", value: `Whether it ran twice is not settled: E-${z.seq} and E-${y.seq} disagree`, source: "prefetch, amcache", evidence: "no third source", reason: "partial" }));
  assert.deepEqual(openContradictions(await readLedger(root)), []);
});

test("the gate at done: the first done is refused and told each defect and its fix; the second passes once a limitation names each defect left", async () => {
  const { root, a0, a1, a2, a3 } = await run();
  await writeFile(
    join(root, "SWARM.md"),
    ["# Goal", "", "## Definition of done", "", "Every question answered in the ledger, each answer attested or disputed.", "", "## Checks", "", '- `node --experimental-strip-types --no-warnings "$SWARM_HARNESS/scripts/check-answers.ts" --sections 1,2,summary,narrative`', ""].join("\n"),
  );
  const f = ok(await rec(a0, { kind: "finding", ...F, value: "Powder.exe ran", source: "prefetch", evidence: "row 1", refs: ["job:j000001/rows.txt"], answers: ["1"] })).entry;
  // The rival-area check runs for every review (docs/adr/0013): the disk the finding was read from is covered for question 1, by a search over it.
  await job(root, "j000009", "search.txt", "no other hits\n", { spec: { kind: "command", scope: "declared", inputs: ["input:disk.E01"], network: "off", command: "search" }, requester: { agent: "a0" }, status: "ok", exit: 0 });
  ok(await rec(a0, { kind: "coverage", proposition: "The event question 1 asks about happened", refs: ["input:disk.E01"], answers: ["1"], time_range: "the whole of each object, no time bound", search_method: "a keyword search", settings: "case-insensitive, every encoding the tool offers", coverage_actual: "every byte of the objects named", skipped: "none: the search ran to its end", failures: "none", result_refs: ["job:j000009/search.txt"], alternatives: "the event may have left its trace only in memory, which the case does not hold", detection_opportunity: { trace_expected: "yes", why: "the event writes to the objects searched, and they keep it" }, looked_for_none_why: "the fixture's event has no literal form a byte search could find", areas: { allocated: "searched", deleted: "searched", unallocated: "searched", slack: "searched", secondary: "not_applicable" } }));
  const q1 = ok(await rec(a3, { kind: "answer", section: "question:1", value: "It ran", reasoning: `E-${f.seq}`, ...Q })).entry;
  const sum = ok(await rec(a3, { kind: "answer", section: "summary", value: "It ran.", reasoning: `E-${q1.seq}` })).entry;
  const finishLine = () => {
    const r = spawnSync("bash", [join(ROOT, "scripts", "await-done.sh"), "--sandbox", root, "--checks-json"], { encoding: "utf8", env: { ...process.env, SWARM_RUNS_DIR: join(root, "..", "no-registry") } });
    return JSON.parse(r.stdout.trim().split("\n").at(-1) ?? "{}") as Parameters<typeof finishLineVerdict>[0] & object;
  };
  // The first done: refused, the check's own words in the refusal.
  const first = finishLine();
  assert.equal(first?.checks[0].ok, false, JSON.stringify(first));
  const verdict = finishLineVerdict(first, false);
  assert.equal(verdict.proceed, false);
  const reason = (verdict as { reason: string }).reason;
  assert.match(reason, /It says:\nquestion:1: answered by #\d+, resting on #\d+ \(a finding with refs\)/);
  assert.match(reason, /DEFECT: question:2 has no answer\. Fix: record kind=answer section=question:2 citing E-<seq>.*if the ledger cannot answer it, record kind=limitation with answers=\["2"\]/);
  assert.match(reason, new RegExp(`DEFECT: answer #${q1.seq} \\(question:1\\) has no critic act\\. Fix: an agent other than its author re-derives`));
  assert.match(reason, /DEFECT: narrative has no answer/);
  assert.match(reason, /0 named by a limitation, 4 open/);
  // The critic acts, the author writes the narrative; two defects stay, and a limitation names each.
  assert.ok((await attestEntry(a2, { seq: q1.seq, how: "re-derived row 1 of job:j000001/rows.txt", ...EST })).ok);
  const nar = ok(await rec(a3, { kind: "answer", section: "narrative", value: "It ran at 10:15.", reasoning: `E-${f.seq}` })).entry;
  assert.ok((await attestEntry(a2, { seq: nar.seq, how: "re-read E-1 against its ref" })).ok);
  ok(await rec(a1, { kind: "limitation", value: "Question 2 could not be answered: the second volume was not opened", source: "p2", evidence: "no key", reason: "unavailable", answers: ["2"] }));
  const still = finishLine();
  assert.equal(still?.checks[0].ok, false, "the summary has no critic act yet");
  assert.match(finishLineVerdict(still, false).proceed ? "" : (finishLineVerdict(still, false) as { reason: string }).reason, new RegExp(`answer #${sum.seq} \\(summary\\) has no critic act`));
  ok(await rec(a3, { kind: "limitation", value: `The summary E-${sum.seq} was not reviewed before the run's end`, source: "the ledger", evidence: "the critic ran out of time", reason: "partial" }));
  const second = finishLine();
  assert.equal(second?.checks[0].ok, true, JSON.stringify(second));
  assert.equal(second?.passed, second?.total, "every check passes (this sandbox has no registry, so its checks certify nothing: the verdict is the operator's)");
  // Named, the defects are still defects: the check says so, and the run may end.
  const r = await checkLedgerAnswers(root, ["1", "2", "summary", "narrative"]);
  assert.equal(r.ok, true);
  assert.deepEqual(r.outcomes, { "question:1": "answered", "question:2": "limited", summary: "answered", narrative: "answered" });
  assert.equal(r.defects.length, 2);
  assert.ok(r.lines.some((l) => /^defect, named by #\d+: question:2 has no answer/.test(l)));
  assert.ok(r.lines.some((l) => /^defect, named by #\d+: answer #\d+ \(summary\) has no critic act/.test(l)));
  // A dispute of the answer is a defect of its own until it is answered.
  assert.ok((await disputeEntry(a2, { seq: q1.seq, why: "row 1 is another binary" })).ok);
  const disputed = await checkLedgerAnswers(root, ["1"]);
  assert.equal(disputed.ok, false);
  assert.ok(disputed.lines.some((l) => /^DEFECT: answer #\d+ \(question:1\) is disputed by a2: row 1 is another binary/.test(l)));
  // A failing check that printed too much for the refusal says its size and how to read it.
  const big = finishLineVerdict({ total: 1, passed: 0, checks: [{ cmd: "c", ok: false, out_bytes: 70000 }] }, false) as { reason: string };
  assert.match(big.reason, /It printed 70000 bytes; run it from the run's directory to read them/);
});

test("the ledger gate finds nothing a done would refuse on a run whose answers stand: the committed fixture holds every kind and act", async () => {
  const text = await readFile(join(FIXTURE, "ledger", "entries.jsonl"), "utf8");
  const chain = verifyLedgerChain(text);
  assert.equal(chain.ok, true, chain.reason ?? "");
  const entries = await readLedger(FIXTURE);
  assert.deepEqual([...new Set(entries.map((e) => e.kind))].sort(), ["absence", "answer", "event", "finding", "hypothesis", "ioc", "limitation"]);
  assert.deepEqual(entries.filter((e) => e.v === 3).map((e) => e.seq), [1, 2, 3], "a legacy version 3 prefix");
  assert.ok(entries.slice(3).every((e) => e.v === 4));
  assert.deepEqual([...new Set(entries.filter((e) => e.kind === "answer").map((e) => e.section))].sort(), ["narrative", "question:1", "question:2", "question:3", "summary"]);
  assert.ok(entries.some((e) => e.qualifies?.length && e.method?.some((m) => m.status !== "ok")), "a finding on a failed job, qualified");
  assert.ok(entries.some((e) => e.kind === "finding" && e.supersedes !== undefined), "a superseded finding and its correction");
  assert.ok(entries.some((e) => e.unsupported_tokens?.length), "an answer with a token no cited entry holds");
  assert.equal(verifyAttestationChain(await readFile(join(FIXTURE, LEDGER_ATTESTATIONS), "utf8")).ok, true);
  assert.equal(verifyDisputeChain(await readFile(join(FIXTURE, LEDGER_DISPUTES), "utf8")).ok, true);
  const att = await readAttestations(FIXTURE);
  assert.equal(att[0].v, undefined, "a version 1 attestation first");
  assert.ok(att.slice(1).every((a) => a.v === 2 && a.act === "attest" && a.how));
  assert.deepEqual((await readDisputes(FIXTURE)).map((d) => d.act), ["dispute", "dispute", "withdraw"]);
  const gate = ledgerGate({ entries, attestations: att, disputes: await readDisputes(FIXTURE), sections: FIXTURE_SECTIONS });
  const expected = JSON.parse(await readFile(join(FIXTURE, "gate.json"), "utf8")) as { answers: Record<string, number | null>; defects: unknown[]; open: unknown[]; unsupported: unknown };
  assert.deepEqual(Object.fromEntries(Object.entries(gate.answers).map(([k, v]) => [k, v?.seq ?? null])), expected.answers);
  assert.deepEqual(gate.defects, expected.defects);
  assert.deepEqual(gate.open, []);
  assert.deepEqual(gate.unsupported, expected.unsupported);
  const r = await checkLedgerAnswers(FIXTURE, FIXTURE_SECTIONS);
  assert.equal(r.ok, true, r.lines.join("\n"));
});

test("the brief's questions are counted as the goals' awk counts them, and the check reads them from there", async () => {
  assert.deepEqual(briefQuestions(["# Brief", "1. Who?", "2) When?", "Q3 Where?", "**4.** How?", "### 5. Why?", "Question 6: what", "1. again", "  7. indented", "Rule 8. not a question"].join("\n")), ["1", "2", "3", "4", "5", "6"]);
  const { root, a0, a2, a3 } = await run();
  await mkdir(join(root, "inputs"), { recursive: true });
  await writeFile(join(root, "inputs", "CASE.md"), "1. What ran?\n");
  const cli = () => spawnSync("node", ["--experimental-strip-types", "--no-warnings", join(ROOT, "scripts", "check-answers.ts"), "--sections-in", "inputs/CASE.md", "--sections", "summary"], { cwd: root, encoding: "utf8" });
  let r = cli();
  assert.equal(r.status, 1);
  assert.match(r.stdout, /question:1: no answer[\s\S]*summary: no answer/);
  const f = ok(await rec(a0, { kind: "finding", ...F, value: "Powder.exe ran", source: "prefetch", evidence: "row 1", refs: ["job:j000001/rows.txt"], answers: ["1"] })).entry;
  const q = ok(await rec(a3, { kind: "answer", section: "question:1", value: "Powder.exe", reasoning: `E-${f.seq}`, ...Q })).entry;
  const s = ok(await rec(a3, { kind: "answer", section: "summary", value: "Powder.exe ran.", reasoning: `E-${q.seq}` })).entry;
  assert.ok((await attestEntry(a2, { seq: q.seq, how: "re-derived from job:j000001/rows.txt", ...EST })).ok);
  assert.ok((await attestEntry(a2, { seq: s.seq, how: "re-derived from job:j000001/rows.txt" })).ok);
  r = cli();
  assert.equal(r.status, 0, r.stdout);
  const usage = spawnSync("node", ["--experimental-strip-types", "--no-warnings", join(ROOT, "scripts", "check-answers.ts")], { cwd: root, encoding: "utf8" });
  assert.equal(usage.status, 2);
});

test("in ledger mode too, a bounded negative is examination-limited unless its question asks whether something exists and it says the event did not happen under the stronger bar, covered and reviewed; it is a disposition either way", async () => {
  const { a0, a1, a2, a3, root } = await run();
  assert.ok((await openLead(a0, { title: "Look for a second wallet", why: "question 1", answers: ["1"], take: true, routes: [{ source: "input:disk.E01", method: "list every file, allocated and deleted" }] })).ok);
  const none = ok(await rec(a0, { kind: "absence", value: "No second wallet file", source: "inputs/disk.E01", evidence: "fls over the whole image, allocated and deleted", refs: ["job:j000001/rows.txt"], control: { ref: "job:j000001/rows.txt", found: "the same search finds a planted row" }, answers: ["1"] })).entry;
  const cov = ok(await rec(a0, { kind: "coverage", looked_for_none_why: "no literal form a byte search could find", proposition: "A second wallet file exists on the disk", refs: ["input:disk.E01"], answers: ["1"], time_range: "no time bound", search_method: "a full file listing", settings: "fls -r, allocated and deleted", coverage_actual: "every file system entry of the image", skipped: "none: the listing ran to its end", failures: "none", result_refs: [`E-${none.seq}`, "job:j000001/rows.txt"], alternatives: "a wallet held only in memory", detection_opportunity: { trace_expected: "yes", why: "a wallet on this disk is a file the listing names" } })).entry;
  assert.equal(cov.coverage, "complete", "the job behind it read the disk (no declared scope: everything)");
  refused(await rec(a3, { kind: "answer", section: "question:1", value: "The second wallet did not happen", reasoning: `E-${cov.seq}`, ...Q, result: "bounded_negative" }), /worded as the event's absence/);
  const q = ok(await rec(a3, { kind: "answer", section: "question:1", value: "No evidence of a second wallet was found on the disk", reasoning: `E-${cov.seq}, over E-${none.seq}`, ...Q, result: "bounded_negative" })).entry;
  refused(await attestEntry(a2, { seq: q.seq, how: "re-ran the listing's search" }), /its attest is a review/);
  const unreviewed = await checkLedgerAnswers(root, ["1"], ["1"]);
  assert.equal(unreviewed.ok, false, "an unreviewed material negative holds the finish line");
  assert.ok(unreviewed.defects.some((d) => d.code === "negative_unreviewed" && d.named_by.length === 0));
  refused(await attestEntry(a0, { seq: q.seq, how: "mine", review: { detection: { done: true, text: "t" }, reproduced: { done: true, text: "t" }, other_route: { done: false, text: "none" } } }), /is yours|recorded the coverage record/);
  assert.ok((await attestEntry(a2, { seq: q.seq, how: "re-ran the listing's search", review: { detection: { done: true, text: "a wallet is a file on this disk; the listing names deleted entries too" }, reproduced: { done: true, text: "ran the listing again: no wallet" }, other_route: { done: false, text: "no memory image in the case" } } })).ok);
  void a1;
  const limited = await checkLedgerAnswers(root, ["1"]);
  assert.equal(limited.ok, true, "limited is said apart, not failed");
  assert.deepEqual(limited.outcomes, { "question:1": "limited" });
  assert.deepEqual(limited.results, { "question:1": "bounded_negative" });
  assert.match(limited.lines[0], /^question:1: examination-limited \(a bounded negative: no evidence found in its scope; the question asks for more than whether something exists\)/);
  assert.deepEqual(limited.dispositions, { "question:1": "bounded_negative" }, "a reviewed bounded negative on its coverage record is a disposition under the bar");
  // An existence question (said here only on the command line), covered
  // complete with the trace expected and reviewed: still examination-limited
  // while the answer only says nothing was found.
  const existence = await checkLedgerAnswers(root, ["1"], ["1"]);
  assert.deepEqual(existence.outcomes, { "question:1": "limited" });
  assert.match(existence.lines[0], /the answer does not say the event did not happen/);
  assert.deepEqual(existence.dispositions, { "question:1": "bounded_negative" });
  // (That the stronger bar settles it, with asserts_absence, is tests/negative-bar.test.ts's: this goal does not declare question 1 an existence question, so the record refuses asserts_absence.)
});
