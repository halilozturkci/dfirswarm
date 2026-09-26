/**
 * A ledger entry names the run's objects it rests on (refs): each checked when
 * it is written, a typo refused with the nearest names, the refs chained in
 * the entry's core (added, removed or changed later, the chain breaks), a
 * finding without refs taken with a note, and the same finding recorded again
 * with refs made a correction of the one without.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { initSandbox, ledgerCore, readLedger, recordEntry, verifyLedgerChain, type LedgerEntry } from "../extensions/protocol.ts";
import { sealTree, storePaths } from "../scripts/evidence-store.ts";

async function run() {
  const root = await mkdtemp(join(tmpdir(), "ledger-refs-"));
  await initSandbox(root, { reset: true, agentIds: ["a0", "a1"] });
  await writeFile(join(root, "inputs.json"), JSON.stringify({ files: [{ path: "inputs/disk.E01", sha256: "a".repeat(64), bytes: 10 }, { path: "inputs/mem.raw", sha256: "b".repeat(64), bytes: 10 }] }));
  const staging = join(root, "..", "staging-j000001");
  await mkdir(join(staging, "report"), { recursive: true });
  await writeFile(join(staging, "report", "out.txt"), "the key is 1234\n");
  await writeFile(join(staging, "report", "other.txt"), "x\n");
  await sealTree(root, staging, join(storePaths(root).jobs, "j000001", "out"), "j000001", 1);
  return { root, a0: { sandboxRoot: root, agentId: "a0" }, a1: { sandboxRoot: root, agentId: "a1" } };
}

test("refs are checked when written, and a typo is refused with the nearest names", async () => {
  const { root, a0 } = await run();
  const ok = await recordEntry(a0, { kind: "finding", value: "The key is 1234", source: "the job's report", evidence: "cat", refs: ["job:j000001/report/out.txt", "input:disk.E01"], confidence: "high" });
  assert.ok(ok.ok, (ok as { reason?: string }).reason);
  const entry = (ok as { entry: LedgerEntry }).entry;
  assert.deepEqual(entry.refs, ["job:j000001/report/out.txt", "input:disk.E01"]);
  assert.equal((ok as { note?: string }).note, undefined, "a finding with refs needs no note");
  assert.match(ledgerCore(entry), /"refs":\["job:j000001\/report\/out.txt","input:disk.E01"\]/, "the refs are in the chained core");
  const typo = await recordEntry(a0, { kind: "finding", value: "Another", source: "s", evidence: "e", refs: ["job:j000001/report/outt.txt"] });
  assert.equal(typo.ok, false);
  assert.match((typo as { reason: string }).reason, /is not in job j000001's manifest; nearest: job:j000001\/report\/out\.txt/);
  const input = await recordEntry(a0, { kind: "finding", value: "Another", source: "s", evidence: "e", refs: "input:dsk.E01" });
  assert.match((input as { reason: string }).reason, /not in inputs\.json; nearest: input:disk\.E01/);
  const job = await recordEntry(a0, { kind: "finding", value: "Another", source: "s", evidence: "e", refs: ["job:j000002/report/out.txt"] });
  assert.match((job as { reason: string }).reason, /has no sealed manifest; nearest: job:j000001/);
  assert.equal((await recordEntry(a0, { kind: "finding", value: "Another", source: "s", evidence: "e", refs: ["unresolved:"] })).ok, false, "unresolved: needs its why");
  assert.equal((await recordEntry(a0, { kind: "finding", value: "Another", source: "s", evidence: "e", refs: Array.from({ length: 21 }, (_, i) => `unresolved:${i}`) })).ok, false, "at most 20 refs");
  const why = await recordEntry(a0, { kind: "finding", value: "The page was only on screen", source: "s", evidence: "e", refs: ["unresolved:seen in a screenshot the agent could not seal"] });
  assert.ok(why.ok, "a ref may say why no object can be named");
  const md = await readFile(join(root, "ledger", "ledger.md"), "utf8");
  assert.match(md, /refs: `job:j000001\/report\/out\.txt`, `input:disk\.E01`/);
});

test("a finding without refs is taken with a note; recorded again with refs, it becomes the correction; the chain holds and tampering breaks it", async () => {
  const { root, a0, a1 } = await run();
  const bare = await recordEntry(a0, { kind: "finding", value: "The key is 1234", source: "a report", evidence: "cat" });
  assert.ok(bare.ok);
  assert.match((bare as { note?: string }).note ?? "", /no object of the run cited: add refs/);
  const scratch = await recordEntry(a0, { kind: "finding", value: "The runlist has 65 extents", source: "work/a0/vdi_runlist.tsv (SHA-256 44a0…)", evidence: "decoded from the $LogFile" });
  assert.match((scratch as { note?: string }).note ?? "", /work\/a0\/vdi_runlist\.tsv is a file in an agent's own work\/.*run the work that made it as a job \(job_run\)/, "a finding resting on a work/ file is told so, by name");
  const withRefs = await recordEntry(a1, { kind: "finding", value: "The key is 1234", source: "the job's report", evidence: "cat", refs: ["job:j000001/report/out.txt"] });
  assert.ok(withRefs.ok);
  const fix = (withRefs as { entry: LedgerEntry; merged: boolean }).entry;
  assert.equal((withRefs as { merged: boolean }).merged, false, "the refs cannot be merged into a core that has none");
  assert.equal(fix.supersedes, 1, "it corrects the entry without refs");
  const again = await recordEntry(a0, { kind: "finding", value: "The key is 1234", source: "x", evidence: "y", refs: ["job:j000001/report/out.txt"] });
  assert.equal((again as { merged: boolean }).merged, true, "the same refs again: merged into the one that stands");
  assert.equal((again as { entry: LedgerEntry }).entry.seq, fix.seq);
  const other = await recordEntry(a0, { kind: "finding", value: "The key is 1234", source: "x", evidence: "y", refs: ["job:j000001/report/other.txt"] });
  assert.match((other as { note?: string }).note ?? "", /whose refs stand .* record a correction with supersedes=3/, "other refs are not dropped in silence");
  const entries = await readLedger(root);
  assert.equal(entries.length, 3);
  assert.deepEqual(entries[2].authors.sort(), ["a0", "a1"]);
  const text = await readFile(join(root, "ledger", "entries.jsonl"), "utf8");
  assert.equal(verifyLedgerChain(text).ok, true);
  assert.equal(verifyLedgerChain(text.replace('"refs":["job:j000001/report/out.txt"]', '"refs":["job:j000001/report/other.txt"]')).ok, false, "a changed ref breaks the chain");
  const lines = text.trim().split("\n").map((l) => JSON.parse(l) as LedgerEntry);
  delete lines[2].refs;
  assert.equal(verifyLedgerChain(lines.map((l) => JSON.stringify(l)).join("\n")).ok, false, "a removed ref breaks it");
  lines[0].refs = ["input:disk.E01"];
  assert.equal(verifyLedgerChain(lines.map((l) => JSON.stringify(l)).join("\n")).ok, false, "and so does one added after the fact");
});
