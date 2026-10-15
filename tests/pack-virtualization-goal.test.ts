/**
 * The virtualization pack's goal template: its definition of done and its acceptance check for answer 7 (the recovery
 * position). The check is read from the template and run on small reports, so it is the line the harness runs that is
 * tested: it has to bind the position to answer 7's section and to a stated phrase, which a pattern for the bare words
 * "unknown" or "restorable" anywhere in a report does not.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { VIRT } from "./pack-virtualization-harness.ts";

const GOAL = join(VIRT, "goals", "what-recovery-survives.md");

async function check(): Promise<string> {
  const text = await readFile(GOAL, "utf8");
  const line = text.split("\n").find((l) => l.startsWith("- `awk") && /recovery position/i.test(l));
  assert.ok(line, "the template has no acceptance check for the recovery position");
  return line.slice(3, -1);
}

async function passes(report: string): Promise<boolean> {
  const dir = await mkdtemp(join(tmpdir(), "goal-check-"));
  try {
    await mkdir(join(dir, "work"));
    await writeFile(join(dir, "work", "report.md"), report);
    return spawnSync("bash", ["-c", await check()], { cwd: dir }).status === 0;
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

const REPORT = (seven: string, rest = "") => `## 1.\nEvidence.\n## 6.\nStates.\n## 7.\n${seven}\n## 8.\nUnknowns.\n${rest}`;

test("the recovery-position check passes on a stated position in answer 7 and on none of these", async () => {
  for (const state of ["restorable and tested", "present with chain whole and untested", "present with chain incomplete", "absent in the listings examined", "unknown"]) {
    assert.equal(await passes(REPORT(`Recovery position: ${state} - vm100\nFive tests: listing yes; chain yes.`)), true, state);
  }
  assert.equal(await passes(REPORT("**Recovery position:** unknown - vm9")), true, "bold is still the phrase");
  // The words anywhere else, or in another answer, are not a position on answer 7.
  assert.equal(await passes(REPORT("Nothing is stated here.", "the copy is restorable and tested, position unknown")), false);
  assert.equal(await passes("## 7.\nnone\n## 8.\nRecovery position: unknown - vm1\n"), false, "the phrase is in answer 8");
  assert.equal(await passes(REPORT("Recovery position: probably fine - vm1")), false, "not one of the five states");
  assert.equal(await passes(REPORT("Recovery position: restorable - vm1")), false, "restorable without the test is not a state");
});

test("the check is one awk pass bound to answer 7: no pipe, no SIGPIPE under pipefail on a 300 KB report, and no event-count minimum in the template", async () => {
  const text = await readFile(GOAL, "utf8");
  assert.doesNotMatch(await check(), /\s\|\s|\|\s*(grep|tail|head|wc)/, "the check has no pipe to another command");
  assert.doesNotMatch(text.slice(text.indexOf("## Checks")), /wc -l|-ge [0-9]|events\.jsonl.*(count|wc)/, "no event-count minimum");
  const dir = await mkdtemp(join(tmpdir(), "goal-big-"));
  try {
    await mkdir(join(dir, "work"));
    const filler = "A line of evidence about a chain that is whole in the set.\n".repeat(5000);          // about 290 KB
    const report = `## 1.\n${filler}## 6.\nStates.\n## 7.\nRecovery position: unknown - vm100\n${filler}## 8.\nUnknowns.\n`;
    assert.ok(report.length > 300_000);
    await writeFile(join(dir, "work", "report.md"), report);
    assert.equal(spawnSync("bash", ["-c", `set -euo pipefail; ${await check()}`], { cwd: dir }).status, 0);
    await writeFile(join(dir, "work", "report.md"), `## 7.\n${filler}## 8.\nRecovery position: unknown - vm1\n`);
    assert.notEqual(spawnSync("bash", ["-c", `set -euo pipefail; ${await check()}`], { cwd: dir }).status, 0);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("the definition of done names the five states, forbids a credential or a hash of a secret in the report, and the checks do not weaken what the harness holds", async () => {
  const text = await readFile(GOAL, "utf8");
  const done = text.slice(text.indexOf("## Definition of done"), text.indexOf("## Checks"));
  assert.match(done, /Recovery position: <state> - <object>/);
  assert.match(done, /restorable and tested, present with chain whole and untested, present with chain\s+incomplete, absent in the listings examined, or unknown/);
  assert.match(done, /No credential, key,\s+token or hash of a secret appears in the report/);
  assert.match(done, /no credential found in the evidence was used/);
  assert.doesNotMatch(done, /appendix/i);
  const checks = text.slice(text.indexOf("## Checks"));
  for (const line of ["test -f work/report.md", "check-answers.ts", "inputs_check", '"tool":"skill"']) assert.ok(checks.includes(line), `the check list keeps ${line}`);
  assert.ok(checks.includes("1 2 3 4 5 6 7 8"), "every question has a heading check");
});
