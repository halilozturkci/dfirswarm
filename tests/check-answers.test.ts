/**
 * scripts/check-answers.ts, the goal check that each named section of the
 * report rests on the ledger: a standing finding whose refs resolve (one of
 * them an object of the run), a complete search that found nothing, or a
 * limitation (examination-limited, said apart). A section citing only a finding without refs,
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
    "section 2: rests on no standing finding with refs, no complete search that found nothing and no limitation (cites #2, #4: #2 names no refs)",
    "section 3: rests on #3 (a search that found nothing)",
    "section 4: rests on no standing finding with refs, no complete search that found nothing and no limitation (cites #5: #5 is superseded)",
    "section 5: rests on no standing finding with refs, no complete search that found nothing and no limitation (cites no ledger entry)",
    "section 6: rests on #6 (a finding with refs)",
    'section 7: no "## 7." heading in work/report.md',
    "sections: 3 answered, 0 examination-limited, 4 unanswered",
  ]);
  assert.equal((await checkAnswers(S, "work/report.md", ["1", "3", "6"])).ok, true);
  // A ref that no longer resolves no longer counts.
  await rm(join(storePaths(S).jobs, "j000001", "manifest.json"));
  assert.match((await checkAnswers(S, "work/report.md", ["1"])).lines[0], /#1's refs job:j000001\/key\.txt do not resolve/);
});

test("an entry tagged for a section answers it; unresolved-only refs, a hypothesis and a partial search do not; a limitation is examination-limited; a failed job is named", async () => {
  const S = await run();
  const a0 = { sandboxRoot: S, agentId: "a0" };
  const staging = join(S, "..", `${Math.random()}`);
  await mkdir(staging, { recursive: true });
  await writeFile(join(staging, "msgs.json"), "[]\n");
  await sealTree(S, staging, join(storePaths(S).jobs, "j000002", "out"), "j000002", 1);
  await writeFile(join(storePaths(S).jobs, "j000002", "job.json"), JSON.stringify({ id: "j000002", status: "failed" }));
  await recordEntry(a0, { kind: "finding", value: "The buyer is named in a message", source: "a job", evidence: "jq", refs: ["job:j000002/msgs.json"], answers: ["Q7"] }); // #7
  await recordEntry(a0, { kind: "finding", value: "The page was only on screen", source: "s", evidence: "e", refs: ["unresolved:seen in a screenshot"] }); // #8
  await recordEntry(a0, { kind: "hypothesis", value: "The key was typed by hand", source: "s", evidence: "e" }); // #9
  await recordEntry(a0, { kind: "absence", value: "no second wallet", source: "C:", evidence: "grep over allocated files", completion: "partial" }); // #10
  await recordEntry(a0, { kind: "limitation", value: "The second volume was not opened", source: "vault p2", evidence: "no key", reason: "unavailable", answers: ["11"] }); // #11
  await writeFile(join(S, "work", "report.md"), [
    "## 7. The buyer", "In a message.", "",
    "## 8. The page", "On screen (#8).", "",
    "## 9. The key", "Maybe typed (#9).", "",
    "## 10. A second wallet", "Not found (#10).", "",
    "## 11. The second volume", "Not opened.", "",
  ].join("\n"));
  const r = await checkAnswers(S, "work/report.md", ["7", "8", "9", "10", "11"]);
  assert.deepEqual(r.lines, [
    "section 7: rests on #7 (a finding with refs, tagged for this section; on the kept output of a job that did not succeed: job:j000002/msgs.json (job failed))",
    "section 8: rests on no standing finding with refs, no complete search that found nothing and no limitation (cites #8: #8 rests on unresolved: refs only, which name no object of the run)",
    "section 9: rests on no standing finding with refs, no complete search that found nothing and no limitation (cites #9: #9 is a hypothesis (open), not an answer)",
    "section 10: rests on no standing finding with refs, no complete search that found nothing and no limitation (cites #10: #10 is a search that was partial: it holds only for what was searched)",
    "section 11: examination-limited, rests on #11 (a limitation: unavailable, tagged for this section)",
    "sections: 1 answered, 1 examination-limited, 3 unanswered",
  ]);
  assert.deepEqual(r.outcomes, { "7": "answered", "8": "unanswered", "9": "unanswered", "10": "unanswered", "11": "limited" });
});

test("a ledger whose chain is broken answers nothing, and a job log changed after its seal no longer resolves", async () => {
  const S = await run();
  await writeFile(join(S, "work", "report.md"), "## 1. The key\nIt is 1234 (#1).\n");
  const { readFile: rf } = await import("node:fs/promises");
  const file = join(S, "ledger", "entries.jsonl");
  const text = await rf(file, "utf8");
  await writeFile(file, text.replace("The key is 1234", "The key is 9999"));
  const r = await checkAnswers(S, "work/report.md", ["1"]);
  assert.equal(r.ok, false);
  assert.match(r.lines[0], /the ledger's chain is broken at line 1 \(the entry's core was rewritten\)/);
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
