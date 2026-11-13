/**
 * Preparation (docs/adr/0013, "A source's broad extraction before a negative
 * on it"; extensions/preparation.ts, scripts/preparation.ts): what a pack
 * declares a recipe prepares; the census's list of broad extractions; the
 * hub's receipts on the store journal (planned, attempted, produced, partial,
 * failed, declined), each naming the source snapshot, the recipe and its
 * version, the output manifest and the exclusions, and written once; the
 * offer of a non-auto one as a lead, deduplicated against queued and sealed
 * work; a declared one the images cannot run declined with its why; a
 * seat's decline; and the gate: an absence or complete-coverage negative on
 * a source whose extraction is planned or attempted held
 * (preparation_pending), released by produced, partial, failed, declined or
 * the operator's acceptance, every other material negative on such a source
 * warned (preparation_missing), and a negative's review offer leading with
 * the state of its sources.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import * as FIN from "../extensions/finish.ts";
import * as L from "../extensions/leads.ts";
import * as O from "../extensions/offers.ts";
import * as P from "../extensions/protocol.ts";
import * as PR from "../extensions/preparation.ts";
import * as Q from "../extensions/questions.ts";
import { checkLedgerAnswers } from "../scripts/check-answers.ts";
import { Journal, storePaths, verifyJournalText } from "../scripts/evidence-store.ts";
import { JobService, type JobRecord } from "../scripts/job-service.ts";
import { plannedPreparations, reconcilePreparation } from "../scripts/preparation.ts";
import { registerDigest, replay, resolveRun } from "../scripts/replay.ts";
import { localWorker } from "./job-service-worker.ts";
import { A, coverage, dirs, F, job, ok, okq, planned, rec, REVIEW, run, sha } from "./negative-bar-fixture.ts";

const ROOT = join(import.meta.dirname, "..");
const DISK = { sha256: sha("disk"), ref: "input:disk.E01", name: "inputs/disk.E01" };

/** A receipt on the store journal, as the hub writes one. */
async function receipt(S: string, state: PR.PreparationState, o: Partial<PR.PreparationReceipt> = {}): Promise<void> {
  const j = await Journal.open(S);
  await j.append({ type: "preparation", state, source: DISK, recipe: "tpack/whole", recipe_version: "1.0.0", recipe_sha256: "0".repeat(64), capability: "disk-records", manifest: null, exclusions: ["deleted files: nothing is carved"], by: "harness", ...(state === "planned" || state === "attempted" ? { job: "j000009" } : {}), ...o });
}

/** The answers check's open defect and warning codes on a question. */
async function codes(S: string, q: string, existence: string[] = []): Promise<{ defects: string[]; warnings: string[]; lines: string[] }> {
  const r = await checkLedgerAnswers(S, [q], existence);
  const words = r.warnings ?? [];
  return { defects: r.defects.filter((d) => d.section === `question:${q}` && !d.named_by.length).map((d) => d.code), warnings: words.filter((w) => /broad extraction/.test(w)).map(() => "preparation_missing"), lines: r.lines };
}

/** Question 2 (an existence question) answered: no remote tool, it did not happen, over the whole disk, reviewed by another seat. */
async function absence(o: { S: string; a0: P.SwarmContext; a1: P.SwarmContext; a2: P.SwarmContext }): Promise<P.LedgerEntry> {
  const lead = await planned(o.a0, "2");
  const found = ok(await rec(o.a0, { kind: "absence", value: "a remote tool", source: "the disk", evidence: "a search", refs: ["job:j000001/hits.txt"], control: { ref: "job:j000001/hits.txt", found: "the same search finds a planted row" }, answers: ["2"] })).entry;
  assert.ok((await L.closeLead(o.a0, lead, { disposition: "negative", ref: `E-${found.seq}` })).ok);
  const cov = ok(await rec(o.a0, coverage("2", ["input:disk.E01"], [`E-${found.seq}`, "job:j000001/hits.txt"], { acquisition_none_why: "the disk is the whole of the case" }))).entry;
  assert.equal(cov.coverage, "complete", "the job behind it declared the disk");
  const ans = ok(await rec(o.a1, { kind: "answer", section: "question:2", value: "No remote tool was installed on the disk: the installation did not happen", reasoning: `E-${cov.seq}`, ...A, result: "bounded_negative", asserts_absence: true })).entry;
  assert.ok((await P.attestEntry(o.a2, { seq: ans.seq, how: "read the coverage and ran the search again", review: REVIEW })).ok);
  return ans;
}

test("a receipt folds by source and capability: the newest state, released once any receipt reached produced, partial, failed or declined, and never held again by a later run", () => {
  const r = (seq: number, state: PR.PreparationState, capability = "c1", sha256 = "a".repeat(64)): PR.PreparationReceipt => ({ seq, at: "t", state, source: { sha256, ref: "input:x", name: "x" }, recipe: `p/${capability}`, recipe_version: "1.0.0", recipe_sha256: "s", capability, exclusions: [], by: "harness" });
  const f = PR.foldPreparation([r(1, "planned"), r(2, "attempted"), r(3, "planned", "c2"), r(4, "planned", "c1", "b".repeat(64))]);
  const a = f.get("a".repeat(64))!;
  assert.deepEqual(a.capabilities.map((c) => [c.capability, c.state, c.released]), [["c1", "attempted", false], ["c2", "planned", false]]);
  assert.equal(a.pending, true);
  assert.equal(a.produced, false);
  const g = PR.foldPreparation([r(1, "planned"), r(2, "attempted"), r(3, "failed"), r(4, "planned"), r(5, "attempted")]).get("a".repeat(64))!;
  assert.equal(g.capabilities[0]!.state, "attempted", "the newest state is a run again");
  assert.equal(g.capabilities[0]!.released, true, "a failed run released it");
  assert.equal(g.capabilities[0]!.outcome, "failed", "the negative is weighed against the outcome that released it");
  assert.equal(g.pending, false);
  const p = PR.foldPreparation([r(1, "planned"), r(2, "produced")]).get("a".repeat(64))!;
  assert.equal(p.produced, true);
  for (const s of PR.PREPARATION_STATES) assert.equal(PR.PREPARATION_PENDING.has(s), s === "planned" || s === "attempted", s);
  assert.equal(PR.receiptOf({ type: "preparation", state: "done", source: { sha256: "x" } }), null, "a state outside the six is no receipt");
});

test("an absence negative is held while its source's broad extraction is planned or attempted; produced, partial, failed or declined releases it, and anything but produced warns", async () => {
  for (const state of PR.PREPARATION_STATES) {
    const r = await run();
    const ans = await absence(r);
    const before = await codes(r.S, "2", ["2"]);
    assert.deepEqual(before.defects, [], `${state}: nothing holds before any receipt`);
    await receipt(r.S, "planned", { job: "j000009" });
    if (state !== "planned") await receipt(r.S, state, state === "attempted" ? { job: "j000009" } : state === "declined" ? { why: "the operator's policy runs no timeline", by: "a3" } : state === "failed" ? { job: "j000009", why: "log2timeline is not in the image" } : { job: "j000009", generation: "g0002", manifest: { sha256: "m".repeat(64), files: 3, bytes: 99 } });
    const c = await codes(r.S, "2", ["2"]);
    const held = state === "planned" || state === "attempted";
    assert.deepEqual(c.defects, held ? ["preparation_pending"] : [], `${state}: ${c.lines.join(" | ")}`);
    assert.deepEqual(c.warnings, held || state === "produced" ? [] : ["preparation_missing"], `${state}: a released source that has not produced is warned, a held one only held`);
    if (held) {
      const line = c.lines.find((l) => /DEFECT: answer #\d+ \(question:2\) is bounded negative and says the event did not happen over inputs\/disk\.E01/.test(l));
      assert.ok(line, c.lines.join("\n"));
      assert.match(line!, new RegExp(`answer #${ans.seq}`));
      assert.match(line!, /Fix: wait for job j000009 \(tpack\/whole over input:disk\.E01; job_status j000009\)/, "the fix says exactly what releases it");
      assert.match(line!, /or the operator accepts the question's limits/);
      assert.match(line!, /it does not hold: deleted files: nothing is carved/, "the exclusions are named");
    }
    if (state === "failed") assert.ok((await checkLedgerAnswers(r.S, ["2"], ["2"])).warnings?.some((w) => /failed \(job j000009: log2timeline is not in the image\)/.test(w)), "failed with why releases the hold, and the warning says why");
  }
});

test("a negative whose coverage is complete over the source is held; a plain negative, one reaching it through a member or a job's output, is warned and never held", async () => {
  const { S, a0, a1, a2 } = await run();
  await receipt(S, "attempted", { job: "j000009" });
  // Question 4: not determinable on a coverage record complete over the disk.
  await planned(a0, "4");
  const f4 = ok(await rec(a0, { kind: "absence", value: "a start time", source: "the disk", evidence: "a search", refs: ["job:j000001/hits.txt"], control: { ref: "job:j000001/hits.txt", found: "the same search finds a planted row" }, answers: ["4"] })).entry;
  const c4 = ok(await rec(a0, coverage("4", ["input:disk.E01"], [`E-${f4.seq}`, "job:j000001/hits.txt"], { acquisition_none_why: "none would settle it" }))).entry;
  assert.equal(c4.coverage, "complete");
  const a4 = ok(await rec(a1, { kind: "answer", section: "question:4", value: "When it started cannot be determined from the disk", reasoning: `E-${c4.seq}`, ...A, result: "not_determinable" }));
  assert.ok((await P.attestEntry(a2, { seq: a4.entry.seq, how: "ran it again", review: REVIEW })).ok);
  // Question 1: not determinable on a partial record naming the disk (its job read a log, not the disk).
  await planned(a0, "1");
  const f1 = ok(await rec(a0, { kind: "absence", value: "a logon", source: "the log", evidence: "a search", refs: ["job:j000002/hits.txt"], control: { ref: "job:j000002/hits.txt", found: "the same search finds a planted row" }, answers: ["1"] })).entry;
  const c1 = ok(await rec(a0, coverage("1", ["input:disk.E01", "input:logs/a.log"], [`E-${f1.seq}`, "job:j000002/hits.txt"], { acquisition_none_why: "none would settle it" }))).entry;
  assert.equal(c1.coverage, "partial");
  const a1rec = ok(await rec(a1, { kind: "answer", section: "question:1", value: "Who logged on cannot be determined", reasoning: `E-${c1.seq}`, ...A, result: "not_determinable" }));
  assert.ok(a1rec.warned?.includes("preparation_missing"), `the record's reply says the warning: ${JSON.stringify(a1rec.warnings)}`);
  assert.ok(a1rec.warnings?.some((w) => /weighed without a produced broad extraction of what it rests on: coverage record E-\d+ names inputs\/disk\.E01: broad extraction tpack\/whole 1\.0\.0 attempted \(job j000009\)/.test(w)), JSON.stringify(a1rec.warnings));
  // Question 5: complete, over a member of the disk's catalogue (a job declared it).
  await planned(a0, "5", [{ source: "member:g0001#2", method: "read the volume" }]);
  const f5 = ok(await rec(a0, { kind: "absence", value: "an account", source: "the volume", evidence: "a search", refs: ["job:j000003/hits.txt"], control: { ref: "job:j000003/hits.txt", found: "the same search finds a planted row" }, answers: ["5"] })).entry;
  const c5 = ok(await rec(a0, coverage("5", ["member:g0001#2"], [`E-${f5.seq}`, "job:j000003/hits.txt"], { acquisition_none_why: "none would settle it" }))).entry;
  assert.equal(c5.coverage, "complete");
  ok(await rec(a1, { kind: "answer", section: "question:5", value: "Which account ran it cannot be determined from the volume", reasoning: `E-${c5.seq}`, ...A, result: "not_determinable" }));
  // Question 6: complete, over an output made from the disk (a job that read everything stands behind it).
  await planned(a0, "6", [{ source: "job:j000001/hits.txt", method: "read the hits" }]);
  const f6 = ok(await rec(a0, { kind: "absence", value: "a transfer", source: "the hits", evidence: "a search", refs: ["job:j000006/hits.txt"], control: { ref: "job:j000006/hits.txt", found: "the same search finds a planted row" }, answers: ["6"] })).entry;
  const c6 = ok(await rec(a0, coverage("6", ["job:j000001/hits.txt"], [`E-${f6.seq}`, "job:j000006/hits.txt"], { acquisition_none_why: "none would settle it" }))).entry;
  assert.equal(c6.coverage, "complete");
  ok(await rec(a1, { kind: "answer", section: "question:6", value: "What left the network cannot be determined from the hits", reasoning: `E-${c6.seq}`, ...A, result: "not_determinable" }));

  const facts = await PR.preparationFacts(S, await P.readLedger(S));
  assert.deepEqual(facts.reach.get(c4.seq), [{ sha256: DISK.sha256, how: "named", via: "input:disk.E01" }]);
  assert.deepEqual(facts.reach.get(c5.seq), [{ sha256: DISK.sha256, how: "member", via: "member:g0001#2" }]);
  assert.deepEqual(facts.reach.get(c6.seq), [{ sha256: DISK.sha256, how: "derived", via: "job:j000001/hits.txt" }]);
  const r = await checkLedgerAnswers(S, ["1", "4", "5", "6"]);
  const held = (q: string) => r.defects.some((d) => d.code === "preparation_pending" && d.section === `question:${q}`);
  const warned = (q: string) => (r.warnings ?? []).some((w) => new RegExp(`\\(question:${q}\\).*weighed without a produced broad extraction`).test(w));
  assert.deepEqual(["1", "4", "5", "6"].map((q) => [q, held(q), warned(q)]), [["1", false, true], ["4", true, false], ["5", false, true], ["6", false, true]]);
  assert.ok((r.warnings ?? []).some((w) => /\(question:5\).*names members of the catalogue of inputs\/disk\.E01/.test(w)));
  assert.ok((r.warnings ?? []).some((w) => /\(question:6\).*rests on outputs made from inputs\/disk\.E01/.test(w)));
  // Readiness holds on the held one, lists the warnings, and never holds on a warning.
  const ready = await FIN.readiness(S);
  assert.ok(ready.items.some((i) => /question:4\) is not determinable and rests on coverage record E-\d+, complete over inputs\/disk\.E01/.test(i)), ready.items.join("\n"));
  assert.ok(!ready.items.some((i) => /question:(1|5|6)\).*broad extraction/.test(i)), "a warned negative is no item");
  assert.deepEqual(ready.warned.filter((w) => w.code === "preparation_missing").map((w) => w.section).sort(), ["question:1", "question:5", "question:6"]);
  // Produced: nothing held, nothing warned.
  await receipt(S, "produced", { job: "j000009", generation: "g0002", manifest: { sha256: "m".repeat(64), files: 3, bytes: 99 } });
  const after = await checkLedgerAnswers(S, ["1", "4", "5", "6"]);
  assert.ok(!after.defects.some((d) => d.code === "preparation_pending"));
  assert.ok(!(after.warnings ?? []).some((w) => /broad extraction/.test(w)));
});

test("the operator's acceptance of the question releases the hold, and a run with no receipt is read as before", async () => {
  const r = await run();
  const ans = await absence(r);
  const noReceipt = await checkLedgerAnswers(r.S, ["2"], ["2"]);
  const partsBefore = await FIN.finishParts(r.S);
  assert.equal("preparation" in partsBefore, false, "a run with no receipt keeps its revision's parts");
  await receipt(r.S, "planned", { job: "j000009" });
  assert.ok((await checkLedgerAnswers(r.S, ["2"], ["2"])).defects.some((d) => d.code === "preparation_pending"));
  assert.notEqual((await FIN.finishParts(r.S)).preparation, undefined, "a receipt moves the finish revision");
  assert.equal(P.ACCEPTANCE_NEVER_EXCUSES.has("preparation_pending"), false);
  assert.equal(P.acceptanceExcuses({ code: "preparation_pending" }, 1), true);
  const operator: Q.Actor = { kind: "human", role: "operator", person: "tester@lab", enrolled: false, os_user: "tester", host: "lab", via: "cli", identity: "claimed" };
  okq(await Q.act(r.S, operator, "accept", { q: "Q-2", as: "bounded", why: "the timeline is not worth its hours here", expected_rev: 1 }));
  const after = await checkLedgerAnswers(r.S, ["2"], ["2"]);
  assert.ok(!after.defects.some((d) => d.code === "preparation_pending"), "the acceptance excuses it in the answers check");
  const ready = await FIN.readiness(r.S);
  assert.ok(!ready.items.some((i) => /broad extraction/.test(i)), `readiness is released too: ${ready.items.join(" | ")}`);
  assert.equal(noReceipt.defects.filter((d) => d.code.startsWith("preparation")).length, 0);
  assert.ok(ans.seq > 0);
});

test("a negative's review offer leads with the state of each source it rests on", async () => {
  const { S, a0, a1 } = await run();
  await planned(a0, "4");
  const f4 = ok(await rec(a0, { kind: "absence", value: "a start time", source: "the disk", evidence: "a search", refs: ["job:j000001/hits.txt"], control: { ref: "job:j000001/hits.txt", found: "the same search finds a planted row" }, answers: ["4"] })).entry;
  const c4 = ok(await rec(a0, coverage("4", ["input:disk.E01"], [`E-${f4.seq}`, "job:j000001/hits.txt"], { acquisition_none_why: "none would settle it" }))).entry;
  const ans = ok(await rec(a1, { kind: "answer", section: "question:4", value: "When it started cannot be determined from the disk", reasoning: `E-${c4.seq}`, ...A, result: "not_determinable" })).entry;
  assert.equal(await L.negativePreparationWords(S, await L.leadsSnapshot(S), ans.seq), null, "no receipt, nothing to lead with");
  await receipt(S, "attempted", { job: "j000009" });
  const snap = await L.leadsSnapshot(S);
  const words = await L.negativePreparationWords(S, snap, ans.seq);
  assert.match(String(words), /^Preparation of the sources it rests on: inputs\/disk\.E01: broad extraction tpack\/whole 1\.0\.0 attempted \(job j000009\); it does not hold: deleted files: nothing is carved — this negative is held \(preparation_pending\)/);
  const offer: O.Offer = { seq: 1, at: new Date().toISOString(), to: "a2", rev: 1, reason: "negative_review", seen_at: null, declined: null, accepted: null, lapsed_at: null };
  const text = L.reviewOfferText(`E-${ans.seq}`, offer, snap, ["a warning"], words);
  assert.ok(text.startsWith(String(words)), "the preparation state comes first");
  assert.match(text, new RegExp(`E-${ans.seq} \\(question:4, not determinable\\) is offered to you for its review`));
  assert.ok(text.indexOf("a warning") > text.indexOf("offered to you"), "the warnings come last, as before");
});

// ---------------------------------------------------------------------------------------------
// The hub's side: a pack of four recipes, the census, the job service and the reconciliation
// ---------------------------------------------------------------------------------------------

/** A pack with one inventory and three broad extractions of a "thing": auto, offered, and declared unavailable. */
function thingPack(dir: string): string {
  const pack = join(dir, "tpack");
  const detect = `import json, os, sys
cmd = sys.argv[1]
t = json.loads(sys.argv[3]) if not os.path.isfile(sys.argv[3]) else json.load(open(sys.argv[3]))
p = t["paths"][0]
head = open(p, "rb").read(16)
if cmd == "detect":
    ok = head.startswith(b"THING")
    print(json.dumps({"applies": ok, "why": "a thing" if ok else "not a thing"}))
    sys.exit(0 if ok else 1)
out = sys.argv[sys.argv.index("--out") + 1]
os.makedirs(out, exist_ok=True)
status = "failed" if b"FAIL" in head else "partial" if b"PART" in head else "complete"
open(os.path.join(out, "records.tsv"), "w").write("a\\tb\\n")
open(os.path.join(out, "index.tsv"), "w").write("records.tsv\\tthe records\\n")
json.dump({"status": status, "covered": "the thing", "not_covered": "what it hides", "limits_hit": [], "errors": ["it stopped"] if status != "complete" else []}, open(os.path.join(out, "coverage.json"), "w"))
sys.exit(1 if status == "failed" else 0)
`;
  const recipe = (name: string, o: Record<string, unknown>) => {
    mkdirSync(join(pack, "recipes", name), { recursive: true });
    writeFileSync(join(pack, "recipes", name, "run.py"), detect);
    writeFileSync(join(pack, "recipes", name, "recipe.json"), JSON.stringify({ id: name, version: "1.0.0", description: `the ${name} recipe`, object: "thing", order: 10, min_bytes: 1, runtime: "python3", entry: "run.py", limits: { seconds: 60 }, outputs: ["records.tsv"], covers: "the thing", ...o }));
  };
  recipe("list", { purpose: "inventory", auto: ["kickoff"] });
  recipe("whole", { purpose: "broad_extraction", capability: "thing-records", exclusions: ["what it hides"], auto: ["kickoff"] });
  recipe("slow", { purpose: "broad_extraction", capability: "thing-timeline", exclusions: ["the thing's past"], auto: [] });
  recipe("cannot", { purpose: "broad_extraction", capability: "thing-other", exclusions: ["everything"], auto: [], unavailable: "no program in the images reads it" });
  writeFileSync(join(pack, "pack.json"), JSON.stringify({ id: "tpack", name: "tpack", version: "1.0.0" }));
  return pack;
}

async function thingRun(things: Record<string, string>) {
  const base = await mkdtemp(join(tmpdir(), "preparation-"));
  dirs.push(base);
  const S = join(base, "run");
  await P.initSandbox(S, { swarmId: "prep1", agentIds: ["a0", "a1"], capUsd: 5, wallClockMinutes: 30, goal: "## Goal\n\nExamine the thing.\n\n### Questions\n\n1. Is there a thing?\n" });
  for (const d of ["inputs", "tools", "catalog", "work/a1"]) mkdirSync(join(S, d), { recursive: true });
  const files: Array<{ path: string; sha256: string; bytes: number }> = [];
  for (const [name, body] of Object.entries(things)) {
    writeFileSync(join(S, "inputs", name), body);
    files.push({ path: `inputs/${name}`, sha256: sha(body), bytes: body.length });
  }
  writeFileSync(join(S, "inputs.json"), JSON.stringify({ files }));
  const pack = thingPack(base);
  const census = spawnSync("python3", [join(ROOT, "scripts", "evidence_catalog.py"), S, "--plan-only", "--recipes-from", pack], { encoding: "utf8" });
  assert.equal(census.status, 0, census.stderr);
  const posts: Array<[string, string]> = [];
  const svc = new JobService({ sandbox: S, run: "s000000", image: "img:test", workers: 2, workerCpus: 1, workerMemoryMib: 512, allowHosts: [], openNet: false, packDirs: [pack], forging: false, minFreeMb: 1, runWorker: localWorker(), destroyWorker: async () => ({ ok: true }), notify: async (to, body) => void posts.push([to, body]), identity: async (a) => ({ name: `${a}-name` }) });
  return { S, pack, svc, posts };
}

async function eventually(ok: () => boolean, what: string, ms = 30000): Promise<void> {
  const end = Date.now() + ms;
  while (!ok()) {
    if (Date.now() > end) throw new Error(`not within ${ms} ms: ${what}`);
    await new Promise((r) => setTimeout(r, 50));
  }
}
/** A job at its end; a recipe's once its generation is published (job-service afterCommit). */
const done = (j: JobRecord | undefined) => Boolean(j && ["committed", "failed", "cancelled"].includes(j.state) && (j.state !== "committed" || j.spec.kind !== "recipe" || j.generation || !["ok", "failed", "timed_out"].includes(j.status ?? "")));
const receipts = (S: string) => verifyJournalText(readFileSync(storePaths(S).journal, "utf8")).lines.map((l) => PR.receiptOf(l as unknown as Record<string, unknown>)).filter((r): r is PR.PreparationReceipt => Boolean(r));

test("the census lists every broad extraction that applies; the hub writes each state of an auto one's job once, offers the rest as one lead each, and declines what the images cannot run", async () => {
  const { S, svc } = await thingRun({ "a.thing": "THING one", "b.bin": "nothing here" });
  const plan = await plannedPreparations(S);
  // In the census's order: pack, then order, then name.
  assert.deepEqual(plan.map((p) => [p.input, p.recipe, p.auto, p.unavailable ?? null]), [
    ["inputs/a.thing", "tpack/cannot", false, "no program in the images reads it"],
    ["inputs/a.thing", "tpack/slow", false, null],
    ["inputs/a.thing", "tpack/whole", true, null],
  ]);
  const planJson = JSON.parse(readFileSync(join(S, "catalog", "plan.json"), "utf8")) as { recipes: Array<{ recipe: string }> };
  assert.deepEqual(planJson.recipes.map((r) => r.recipe), ["tpack/list", "tpack/whole"], "only the kickoff's recipes are planned to run");
  const coverageRow = readFileSync(join(S, "catalog", "coverage.tsv"), "utf8").split("\n").find((l) => l.startsWith("inputs/a.thing\t"))!;
  assert.match(coverageRow, /tpack\/cannot \(declared, and it cannot run in this run's job images: no program in the images reads it\); tpack\/slow \(a broad extraction, offered once the run is up\)/);
  assert.match(readFileSync(join(S, "catalog", "README.md"), "utf8"), /Broad extractions \(a pack's parse of a whole source/);
  await svc.start();
  const kickoff = [...svc.jobs.values()];
  assert.deepEqual(kickoff.map((j) => j.spec.recipe).sort(), ["tpack/list", "tpack/whole"]);
  await eventually(() => kickoff.every((j) => done(svc.jobs.get(j.id))), "the kickoff's jobs done");
  const round = await reconcilePreparation(svc, S);
  const whole = kickoff.find((j) => j.spec.recipe === "tpack/whole")!.id;
  const got = receipts(S);
  assert.deepEqual(got.map((r) => [r.capability, r.state, r.job ?? r.lead ?? null]), [
    ["thing-records", "planned", whole],
    ["thing-records", "attempted", whole],
    ["thing-records", "produced", whole],
    ["thing-other", "declined", null],
    ["thing-timeline", "planned", "L-1"],
  ]);
  const produced = got.find((r) => r.state === "produced")!;
  assert.deepEqual(produced.source, { sha256: sha("THING one"), ref: "input:a.thing", name: "inputs/a.thing", bytes: 9 }, "the source snapshot, by digest");
  assert.equal(produced.recipe, "tpack/whole");
  assert.equal(produced.recipe_version, "1.0.0");
  assert.match(produced.recipe_sha256, /^[0-9a-f]{64}$/);
  assert.equal(produced.generation, svc.jobs.get(whole)!.generation);
  assert.deepEqual(produced.manifest, { sha256: svc.jobs.get(whole)!.outputs!.manifest_sha256, files: svc.jobs.get(whole)!.outputs!.files, bytes: svc.jobs.get(whole)!.outputs!.bytes }, "the output manifest");
  assert.deepEqual(produced.exclusions, ["what it hides", "not covered in this run: what it hides"], "the declared exclusions, then this run's");
  const declined = got.find((r) => r.state === "declined")!;
  assert.equal(declined.why, "its pack declares it, and it cannot run in this run's job images: no program in the images reads it");
  assert.deepEqual(round.opened, ["L-1"]);
  // The lead: the harness's, unheld, serving no question, not material, the route and the source named.
  const lead = (await L.leadsSnapshot(S)).state.leads.get("L-1")!;
  assert.deepEqual([lead.opened_by, lead.holder, lead.answers, lead.material], ["system", null, [], false]);
  assert.deepEqual(lead.preparation, { sha256: sha("THING one"), ref: "input:a.thing", capability: "thing-timeline", recipe: "tpack/slow" });
  assert.deepEqual(lead.routes, [{ source: "input:a.thing", method: "recipe tpack/slow" }]);
  assert.match(lead.why, /is held \(preparation_pending\) until this extraction is produced, partial, failed or declined/);
  // A second round writes nothing, and offers nothing again.
  const again = await reconcilePreparation(svc, S);
  assert.deepEqual([again.receipts, again.opened.length], [0, 0]);
  assert.equal(receipts(S).length, got.length);
  // The unavailable recipe is refused if asked for by name, with the pack's why.
  const asked = await svc.submit("a1", { kind: "recipe", recipe: "tpack/cannot", target: { paths: [join(S, "inputs", "a.thing")], ref: "input:a.thing" }, inputs: ["input:a.thing"] });
  assert.equal(asked.ok, false);
  assert.match((asked as { reason: string }).reason, /tpack\/cannot is declared by its pack but cannot run in this run's job images: no program in the images reads it/);
  await svc.stop("over");
});

test("a seat's decline of an offered extraction is its receipt, with why; a run of it by another route closes the lead; a failed run says why; nothing is offered twice", async () => {
  const { S, svc, posts } = await thingRun({ "a.thing": "THING one", "b.thing": "THING-PART two", "c.thing": "THING-FAIL three" });
  await svc.start();
  await eventually(() => [...svc.jobs.values()].every((j) => done(j)), "the kickoff's jobs done");
  await reconcilePreparation(svc, S);
  const byInput = (name: string) => receipts(S).filter((r) => r.source.name === `inputs/${name}`);
  assert.deepEqual(byInput("b.thing").filter((r) => r.capability === "thing-records").map((r) => r.state), ["planned", "attempted", "partial"], "a partial run is partial");
  assert.match(String(byInput("b.thing").find((r) => r.state === "partial")!.why), /it stopped/);
  const failed = byInput("c.thing").find((r) => r.state === "failed")!;
  assert.match(String(failed.why), /status failed/, "a failed run says why");
  assert.ok(failed.exclusions.includes("an error: it stopped"), "and what this run of it did not cover");
  const snap = await L.leadsSnapshot(S);
  const leadOf = (name: string) => [...snap.state.leads.values()].find((l) => l.preparation?.ref === `input:${name}`)!.id;
  // a1 takes the offered timeline of a.thing and declines it, citing a limitation.
  const a1 = { sandboxRoot: S, agentId: "a1" };
  const la = leadOf("a.thing");
  assert.ok((await L.claimLead(a1, la)).ok);
  const lim = ok(await rec(a1, { kind: "limitation", value: "The timeline of the thing would take hours and the question does not need it", source: "the thing", evidence: "its size", reason: "not_examined", answers: ["1"] })).entry;
  assert.ok((await L.closeLead(a1, la, { disposition: "deferred", ref: `E-${lim.seq}`, why: "the question does not need it" })).ok);
  // a0 runs the timeline of b.thing without claiming its lead.
  const lb = leadOf("b.thing");
  const ran = await svc.catalogRequest("a0", "input:b.thing", "tpack/slow");
  assert.ok(ran.ok);
  await eventually(() => done(svc.jobs.get((ran as { job: JobRecord }).job.id)), "a0's run");
  const r = await reconcilePreparation(svc, S);
  const declined = receipts(S).find((x) => x.state === "declined" && x.lead === la)!;
  assert.equal(declined.by, "a1", "the seat that declined it");
  assert.match(String(declined.why), new RegExp(`${la} closed deferred on E-${lim.seq}: the question does not need it`));
  assert.deepEqual(byInput("b.thing").filter((x) => x.capability === "thing-timeline").map((x) => [x.state, x.job ?? x.lead]), [["planned", lb], ["planned", (ran as { job: JobRecord }).job.id], ["attempted", (ran as { job: JobRecord }).job.id], ["partial", (ran as { job: JobRecord }).job.id]]);
  assert.deepEqual(r.closed, [lb], "the lead whose extraction reached an outcome by another route is closed by the harness");
  const closed = (await L.leadsSnapshot(S)).state.leads.get(lb)!.closed!;
  assert.deepEqual([closed.by, closed.disposition], ["system", "withdrawn"]);
  assert.match(closed.ref, /^partial by job j\d+, generation g\d+ \(store journal line \d+\)$/);
  // The declined lead stays as the seat closed it; nothing is offered again for a source on the record.
  assert.equal((await L.leadsSnapshot(S)).state.leads.get(la)!.closed!.by, "a1");
  const again = await reconcilePreparation(svc, S);
  assert.deepEqual([again.receipts, again.opened.length, again.closed.length], [0, 0, 0]);
  assert.ok(!posts.some(([, b]) => /broad extraction applies/.test(b)), "a system pass tells no one");
  await svc.stop("over");
});

test("a seat's close of an offered extraction any other way, with nothing run, is its decline and says so; the hold's fix never points at a closed lead; the harness closes only a lead no seat holds", async () => {
  // The hold's fix: an open lead is to be run or declined; a closed one is never pointed at, its close being the decline the hub records.
  const r = (seq: number, state: PR.PreparationState, o: Partial<PR.PreparationReceipt> = {}): PR.PreparationReceipt => ({ seq, at: "t", state, source: DISK, recipe: "tpack/slow", recipe_version: "1.0.0", recipe_sha256: "s", capability: "thing-timeline", exclusions: [], by: "harness", ...o });
  const src = PR.foldPreparation([r(1, "planned", { lead: "L-3" })]).get(DISK.sha256)!;
  assert.match(PR.holdFix(src), /^run or decline L-3, the offered tpack\/slow over input:disk\.E01: lead_claim L-3/);
  const shut = PR.holdFix(src, new Map([["L-3", { disposition: "duplicate", ref: "L-4", by: "a1" }]]));
  assert.match(shut, /^L-3, the offered tpack\/slow over input:disk\.E01, was closed duplicate by a1 \(L-4\) and nothing ran it: the hub records that close as its decline at its next round, which releases the hold; or run it now: catalog_request target=input:disk\.E01 recipe=tpack\/slow$/);
  assert.doesNotMatch(shut, /lead_claim|close L-3/);
  // The hub: a1 closes the offered timeline of a.thing a duplicate of b.thing's, running nothing; a1 takes b.thing's, and a0 runs it by another route.
  const { S, svc } = await thingRun({ "a.thing": "THING one", "b.thing": "THING-PART two" });
  await svc.start();
  await eventually(() => [...svc.jobs.values()].every((j) => done(j)), "the kickoff's jobs done");
  await reconcilePreparation(svc, S);
  const snap = await L.leadsSnapshot(S);
  const leadOf = (name: string) => [...snap.state.leads.values()].find((l) => l.preparation?.ref === `input:${name}`)!.id;
  const la = leadOf("a.thing");
  const lb = leadOf("b.thing");
  const a1 = { sandboxRoot: S, agentId: "a1" };
  assert.ok((await L.claimLead(a1, la)).ok);
  const closedA = await L.closeLead(a1, la, { disposition: "duplicate", ref: lb, why: "one timeline run is enough" });
  assert.ok(closedA.ok, (closedA as { reason?: string }).reason);
  assert.ok((await L.claimLead(a1, lb)).ok);
  const ran = await svc.catalogRequest("a0", "input:b.thing", "tpack/slow");
  assert.ok(ran.ok);
  await eventually(() => done(svc.jobs.get((ran as { job: JobRecord }).job.id)), "a0's run");
  const round = await reconcilePreparation(svc, S);
  const declined = receipts(S).find((x) => x.state === "declined" && x.lead === la)!;
  assert.ok(declined, JSON.stringify(receipts(S).filter((x) => x.lead === la)));
  assert.equal(declined.by, "a1");
  assert.match(String(declined.why), new RegExp(`^${la} closed duplicate on ${lb}: one timeline run is enough, and nothing ran the extraction it offered: its close is its decline$`));
  // b.thing's extraction reached an outcome by another route; a1 holds its lead, so the harness leaves it to a1.
  assert.deepEqual(round.closed, []);
  const held = (await L.leadsSnapshot(S)).state.leads.get(lb)!;
  assert.deepEqual([held.closed, held.holder], [null, "a1"]);
  // a1's own close is taken, and writes no decline: the extraction ran.
  const lim = ok(await rec(a1, { kind: "limitation", value: "The timeline of b.thing was run by a0", source: "the thing", evidence: "its job", reason: "not_examined", answers: ["1"] })).entry;
  assert.ok((await L.closeLead(a1, lb, { disposition: "deferred", ref: `E-${lim.seq}`, why: "a0 ran it" })).ok);
  await reconcilePreparation(svc, S);
  assert.ok(!receipts(S).some((x) => x.state === "declined" && x.lead === lb), "a released extraction is not declined");
  await svc.stop("over");
});

test("evidence detected after the kickoff: the auto extraction runs, the rest is offered; an agent's detect pass is told what is not run unasked", async () => {
  const { S, svc, posts } = await thingRun({ "a.thing": "THING one" });
  await svc.start();
  await eventually(() => [...svc.jobs.values()].every((j) => done(j)), "the kickoff's jobs done");
  // A file a job made, detected by the system (as evidence added is), by its ref.
  const made = await svc.submit("a1", { kind: "command", command: `printf 'THING late' > "$OUT/late.thing"`, inputs: [] });
  assert.ok(made.ok);
  await eventually(() => done(svc.jobs.get((made as { job: JobRecord }).job.id)), "the job that makes it");
  const ref = `job:${(made as { job: JobRecord }).job.id}/late.thing`;
  const pass = await svc.catalogRequest("system", ref);
  assert.ok(pass.ok);
  const recipesOver = () => [...svc.jobs.values()].filter((j) => j.spec.kind === "recipe" && j.spec.target?.ref === ref);
  await eventually(() => done(svc.jobs.get((pass as { job: JobRecord }).job.id)) && recipesOver().length >= 2, "the pass, and the recipes it ran");
  await eventually(() => [...svc.jobs.values()].every((j) => done(j)), "every job done");
  // The pass is read once: a moment more, and nothing else is started.
  await new Promise((r) => setTimeout(r, 300));
  const ran = [...svc.jobs.values()].filter((j) => j.spec.kind === "recipe" && j.spec.target?.ref === ref).map((j) => j.spec.recipe).sort();
  assert.deepEqual(ran, ["tpack/list", "tpack/whole"], "the offered and the unavailable extraction are not run by the pass");
  const r = await reconcilePreparation(svc, S);
  const late = receipts(S).filter((x) => x.source.ref === ref);
  assert.deepEqual(late.map((x) => [x.capability, x.state]).sort(), [["thing-other", "declined"], ["thing-records", "attempted"], ["thing-records", "planned"], ["thing-records", "produced"], ["thing-timeline", "planned"]].sort());
  // Offered: the kickoff input's timeline and the late file's, one lead each, the late one naming its object.
  assert.equal(r.opened.length, 2);
  assert.ok([...(await L.leadsSnapshot(S)).state.leads.values()].some((l) => l.preparation?.ref === ref && l.preparation.capability === "thing-timeline" && r.opened.includes(l.id)));
  // An agent's own detect pass over it: told the broad extraction is not run unasked.
  const mine = await svc.catalogRequest("a1", ref);
  assert.ok(mine.ok);
  await eventually(() => posts.some(([to, b]) => to === "a1" && /A broad extraction applies and is not run unasked/.test(b)), `a1 told: ${JSON.stringify(posts)}`);
  assert.ok(posts.some(([to, b]) => to === "a1" && /tpack\/cannot over .* \(declared, and it cannot run in this run's images: no program in the images reads it\)/.test(b)));
  await svc.stop("over");
});

test("the kickoff's refusal of an auto extraction is its decline, with the refusal's words", async () => {
  const { S, svc } = await thingRun({ "a.thing": "THING one" });
  // The plan names a target outside the run: the service refuses it, and says so on the record.
  const plan = JSON.parse(readFileSync(join(S, "catalog", "plan.json"), "utf8")) as { recipes: Array<{ recipe: string; target: { paths: string[] } }> };
  for (const r of plan.recipes) if (r.recipe === "tpack/whole") r.target.paths = ["/nowhere/a.thing"];
  writeFileSync(join(S, "catalog", "plan.json"), JSON.stringify(plan));
  await svc.start();
  const k = verifyJournalText(readFileSync(storePaths(S).journal, "utf8")).lines.find((l) => l.type === "kickoff_queued") as unknown as { refused?: Array<{ recipe: string; reason: string }> };
  assert.deepEqual(k.refused?.map((x) => x.recipe), ["tpack/whole"]);
  await eventually(() => [...svc.jobs.values()].every((j) => done(j)), "the kickoff's jobs done");
  await reconcilePreparation(svc, S);
  const d = receipts(S).find((x) => x.capability === "thing-records")!;
  assert.equal(d.state, "declined");
  assert.match(String(d.why), /^the kickoff's queue refused it: \/nowhere\/a\.thing is not an object of this run/);
  await svc.stop("over");
  assert.ok(existsSync(join(S, "catalog", "plan.json")));
  assert.ok((await readFile(join(S, "catalog", "coverage.tsv"), "utf8")).length > 0);
  assert.ok(F && sha);
});

test("the seats are told: what a broad extraction is, what to do with its lead, the hold and the warning, and what the review offer opens with", async () => {
  const prompt = (await readFile(join(ROOT, "prompts", "worker-system.md"), "utf8")).replace(/\s+/g, " ");
  for (const must of [
    "A broad extraction is a pack's parse of a whole source into a searchable form",
    "take it and run it (catalog_request target=<ref> recipe=<recipe>), or close it deferred or infeasible citing a limitation that says why it should not run",
    "waits while that source's broad extraction is planned or attempted (`preparation_pending`): produced, partial, failed or declined releases it, and so does the operator's acceptance",
    "is warned (`preparation_missing`)",
    "The review offer opens with the state of each source's broad extraction",
  ]) assert.ok(prompt.includes(must), `prompts/worker-system.md does not say: ${must}`);
});

test("replay --prepare-as asks this checkout's packs about the run's own evidence, in place, and shows which negatives the hold would hold and which it would warn", async () => {
  const r = await run();
  // A phone's file-system tar, small: the mobile pack's broad extraction applies to it.
  mkdirSync(join(r.S, "inputs"), { recursive: true });
  const made = spawnSync("python3", ["-c", "import io,sys,tarfile\nwith tarfile.open(sys.argv[1],'w') as t:\n  i=tarfile.TarInfo('private/var/mobile/Library/SMS/sms.db'); i.size=3; t.addfile(i, io.BytesIO(b'sql'))", join(r.S, "inputs", "phone.tar")]);
  assert.equal(made.status, 0, String(made.stderr));
  const bytes = readFileSync(join(r.S, "inputs", "phone.tar"));
  const inputs = JSON.parse(readFileSync(join(r.S, "inputs.json"), "utf8")) as { files: Array<Record<string, unknown>> };
  inputs.files.push({ path: "inputs/phone.tar", sha256: (await import("node:crypto")).createHash("sha256").update(bytes).digest("hex"), bytes: bytes.length });
  writeFileSync(join(r.S, "inputs.json"), JSON.stringify(inputs));
  await job(r.S, "j000007", "hits.txt", { spec: { kind: "command", scope: "declared", inputs: ["input:phone.tar"], command: "search" } });
  // Question 4 not determinable on coverage complete over the phone; question 1 on coverage that names it and is partial.
  await planned(r.a0, "4", [{ source: "input:phone.tar", method: "search the phone" }]);
  const f4 = ok(await rec(r.a0, { kind: "absence", value: "a start time", source: "the phone", evidence: "a search", refs: ["job:j000007/hits.txt"], control: { ref: "job:j000007/hits.txt", found: "the same search finds a planted row" }, answers: ["4"] })).entry;
  const c4 = ok(await rec(r.a0, coverage("4", ["input:phone.tar"], [`E-${f4.seq}`, "job:j000007/hits.txt"], { acquisition_none_why: "none would settle it" }))).entry;
  assert.equal(c4.coverage, "complete");
  ok(await rec(r.a1, { kind: "answer", section: "question:4", value: "When it started cannot be determined from the phone", reasoning: `E-${c4.seq}`, ...A, result: "not_determinable" }));
  await planned(r.a0, "1", [{ source: "input:phone.tar", method: "search the phone" }]);
  const f1 = ok(await rec(r.a0, { kind: "absence", value: "a logon", source: "the log", evidence: "a search", refs: ["job:j000002/hits.txt"], control: { ref: "job:j000002/hits.txt", found: "the same search finds a planted row" }, answers: ["1"] })).entry;
  const c1 = ok(await rec(r.a0, coverage("1", ["input:phone.tar", "input:logs/a.log"], [`E-${f1.seq}`, "job:j000002/hits.txt"], { acquisition_none_why: "none would settle it" }))).entry;
  ok(await rec(r.a1, { kind: "answer", section: "question:1", value: "Who logged on cannot be determined", reasoning: `E-${c1.seq}`, ...A, result: "not_determinable" }));
  const before = await registerDigest(r.S);
  const scratch = await mkdtemp(join(tmpdir(), "prepare-as-"));
  dirs.push(scratch);
  const here = { label: "this checkout", harness: ROOT, how: "this checkout", commit: null };
  const got = await replay({ run: await resolveRun(r.S), targets: [here], prepareAs: "attempted", scratch });
  assert.equal(got.unchanged, true, "the run is not written");
  assert.equal(await registerDigest(r.S), before);
  assert.deepEqual(got.prepared_as?.items, [{ source: "input:phone.tar", recipe: "mobile-forensics/ios-ileapp", capability: "ios-artifacts", unavailable: false }]);
  const p = got.evaluations[0]!.projection!;
  assert.deepEqual(p.errors, []);
  assert.deepEqual(p.preparation?.sources, [{ source: "input:phone.tar", pending: true, produced: false, capabilities: [{ capability: "ios-artifacts", recipe: "mobile-forensics/ios-ileapp", state: "attempted", outcome: "attempted", released: false, by: "replay", synthetic: true }] }]);
  assert.deepEqual(p.preparation?.held, [{ section: "question:4", sources: ["input:phone.tar"] }]);
  assert.deepEqual(p.preparation?.warned, [{ section: "question:1", sources: ["input:phone.tar"] }]);
  assert.ok(p.questions.find((q) => q.section === "question:4")?.check?.defects.includes("preparation_pending"));
  assert.ok(p.questions.find((q) => q.section === "question:1")?.warnings.includes("preparation_missing"));
  // As produced: nothing held, nothing warned.
  const produced = await replay({ run: await resolveRun(r.S), targets: [here], prepareAs: "produced", scratch: await mkdtemp(join(tmpdir(), "prepare-as-")) });
  const q = produced.evaluations[0]!.projection!;
  assert.deepEqual([q.preparation?.held, q.preparation?.warned], [[], []]);
});
