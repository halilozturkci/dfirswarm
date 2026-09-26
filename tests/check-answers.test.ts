/**
 * scripts/check-answers.ts, the goal check that each named section of the
 * report rests on the ledger: a standing finding whose refs resolve, or a
 * search that found nothing. A section citing only a finding without refs,
 * a superseded one, a ref that no longer resolves, or nothing, fails and
 * says why; how sure the swarm was is not asked. await-done.sh hands the
 * check SWARM_HARNESS so a goal can call it.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { initSandbox, recordEntry } from "../extensions/protocol.ts";
import { sealTree, storePaths } from "../scripts/evidence-store.ts";
import { checkAnswers, citedSeqs } from "../scripts/check-answers.ts";

const ROOT = join(import.meta.dirname, "..");

async function run() {
  const S = await mkdtemp(join(tmpdir(), "answers-"));
  await initSandbox(S, { reset: true, agentIds: ["a0"] });
  await writeFile(join(S, "inputs.json"), JSON.stringify({ files: [{ path: "inputs/disk.E01", sha256: "a".repeat(64), bytes: 1 }] }));
  const staging = join(S, "..", `${Math.random()}`);
  await mkdir(staging, { recursive: true });
  await writeFile(join(staging, "key.txt"), "1234\n");
  await sealTree(S, staging, join(storePaths(S).jobs, "j000001", "out"), "j000001", 1);
  const a0 = { sandboxRoot: S, agentId: "a0" };
  await recordEntry(a0, { kind: "finding", value: "The key is 1234", source: "a job", evidence: "cat", refs: ["job:j000001/key.txt"] }); // #1
  await recordEntry(a0, { kind: "finding", value: "The volume is BitLocker", source: "the image", evidence: "fsstat" }); // #2 (no refs)
  await recordEntry(a0, { kind: "absence", value: "a PGP private key", source: "inputs/disk.E01", evidence: "grep -a 'BEGIN PGP PRIVATE' over the whole image" }); // #3
  await recordEntry(a0, { kind: "event", ts: "2024-01-01T00:00:00Z", value: "logon", source: "Security.evtx", evidence: "4624" }); // #4
  await recordEntry(a0, { kind: "finding", value: "The README was AES-encrypted", source: "a job", evidence: "header", refs: ["job:j000001/key.txt"] }); // #5
  await recordEntry(a0, { kind: "finding", value: "The README was AES Crypt v2", source: "a job", evidence: "header", refs: ["input:disk.E01"], supersedes: 5 }); // #6
  return S;
}

test("citations: #n, E-n and ranges", () => {
  assert.deepEqual(citedSeqs("see #4, E-7 and ledger #10–#12").sort((a, b) => a - b), [4, 7, 10, 11, 12]);
});

test("each section rests on a finding with refs or on an absence; one that does not says why", async () => {
  const S = await run();
  await writeFile(join(S, "work", "report.md"), [
    "# Report", "", "## 1. The key", "It is 1234 (#1).", "",
    "## 2. The volume", "BitLocker (#2); logon at #4.", "",
    "## 3. The PGP key", "Not found (E-3).", "",
    "## 4. The README", "AES (#5).", "",
    "## 5. Reflection", "Nothing cited.", "",
    "## 6. The README, again", "AES Crypt v2 (#5–#6).", "",
  ].join("\n"));
  const r = await checkAnswers(S, "work/report.md", ["1", "2", "3", "4", "5", "6", "7"]);
  assert.equal(r.ok, false);
  assert.deepEqual(r.lines, [
    "section 1: rests on #1 (a finding with refs)",
    "section 2: rests on no standing finding with refs and no search that found nothing (cites #2, #4: #2 names no refs)",
    "section 3: rests on #3 (a search that found nothing)",
    "section 4: rests on no standing finding with refs and no search that found nothing (cites #5: #5 is superseded)",
    "section 5: rests on no standing finding with refs and no search that found nothing (cites no ledger entry)",
    "section 6: rests on #6 (a finding with refs)",
    'section 7: no "## 7." heading in work/report.md',
  ]);
  assert.equal((await checkAnswers(S, "work/report.md", ["1", "3", "6"])).ok, true);
  // A ref that no longer resolves no longer counts.
  await rm(join(storePaths(S).jobs, "j000001", "manifest.json"));
  assert.match((await checkAnswers(S, "work/report.md", ["1"])).lines[0], /#1's refs job:j000001\/key\.txt do not resolve/);
});

test("await-done.sh runs a goal line that calls it through SWARM_HARNESS", async () => {
  const S = await run();
  await writeFile(join(S, "work", "report.md"), "## 1. The key\nIt is 1234 (#1).\n");
  // No registry here: the check comes from the sandbox's contract.
  await writeFile(join(S, "SWARM.md"), [
    "# Goal", "", "## Definition of done", "", "Answers rest on the ledger.", "", "## Checks", "",
    '- `node --experimental-strip-types --no-warnings "$SWARM_HARNESS/scripts/check-answers.ts" --report work/report.md --sections 1`',
    "",
  ].join("\n"));
  const r = spawnSync("bash", [join(ROOT, "scripts", "await-done.sh"), "--sandbox", S, "--checks-json"], { encoding: "utf8", env: { ...process.env, SWARM_RUNS_DIR: join(S, "..", "no-registry") } });
  const out = JSON.parse(r.stdout.trim().split("\n").at(-1) ?? "{}") as { checks?: Array<{ ok: boolean }> };
  assert.equal(out.checks?.length, 1, r.stdout + r.stderr);
  assert.equal(out.checks?.[0].ok, true, r.stdout + r.stderr);
  // And fails when the section rests on nothing that counts.
  await writeFile(join(S, "work", "report.md"), "## 1. The key\nBitLocker (#2).\n");
  const r2 = spawnSync("bash", [join(ROOT, "scripts", "await-done.sh"), "--sandbox", S, "--checks-json"], { encoding: "utf8", env: { ...process.env, SWARM_RUNS_DIR: join(S, "..", "no-registry") } });
  assert.equal((JSON.parse(r2.stdout.trim().split("\n").at(-1) ?? "{}") as { checks?: Array<{ ok: boolean }> }).checks?.[0].ok, false);
});
