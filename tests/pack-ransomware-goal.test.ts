/**
 * The ransomware goal template's definition of done and its acceptance check for answer 2.
 * The check is read from the template and run on small reports, so it is the line the harness
 * runs that is tested: it has to bind the position to answer 2's section and to a stated phrase,
 * which a pattern for the bare words "established" or "partial" anywhere in a report does not.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { ROOT } from "./tool-library-harness.ts";

const GOAL = join(ROOT, "packs", "ransomware-response", "goals", "ransomware-case.md");

async function check(): Promise<string> {
  const text = await readFile(GOAL, "utf8");
  const line = text.split("\n").find((l) => l.startsWith("- `") && /exfiltration conclusion/i.test(l));
  assert.ok(line, "the template has no acceptance check for the exfiltration conclusion");
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

const REPORT = (two: string, rest = "") => `## 1.\nScope.\n## 2.\n${two}\n## 3.\nEntry.\n${rest}`;

test("the exfiltration check passes on a stated outcome in answer 2 and on none of these", async () => {
  for (const outcome of ["established", "partial", "bounded negative", "bounded-negative", "not determinable", "not-determinable"]) {
    assert.equal(await passes(REPORT(`Exfiltration conclusion: ${outcome}\nCoverage: proxy logs 2026-04-01 to 2026-04-12.`)), true, outcome);
  }
  assert.equal(await passes(REPORT("**Exfiltration conclusion:** partial")), true, "bold is still the phrase");
  // The words anywhere else, or in another answer, are not a position on answer 2.
  assert.equal(await passes(REPORT("Nothing is stated here.", "the connection was established and the task partial")), false);
  assert.equal(await passes("## 1.\nthe connection was established\n## 2.\nnothing here\n## 3.\nx\n"), false);
  assert.equal(await passes("## 2.\nnone\n## 3.\nx\n## 4.\nExfiltration conclusion: partial\n"), false, "the phrase is in answer 4");
  assert.equal(await passes(REPORT("Exfiltration conclusion: probably nothing")), false, "not one of the four outcomes");
});

test("the definition of done names the four outcomes and the phrase, and keeps a value and a hash out of the report", async () => {
  const text = await readFile(GOAL, "utf8");
  const done = text.slice(text.indexOf("## Definition of done"), text.indexOf("## Checks"));
  assert.match(done, /Exfiltration conclusion: <outcome>/);
  assert.match(done, /established, partial,\s+bounded negative or not determinable/);
  assert.doesNotMatch(done, /three exfiltration positions/);
  assert.doesNotMatch(done, /appendix/i, "an appendix in work/report.md is not a sealed output");
  assert.match(done, /hash of a secret/);
  assert.match(done, /note id and offset/);
  assert.match(done, /sealed job output/);
});
