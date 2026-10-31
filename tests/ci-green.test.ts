/**
 * `CI green` no longer waits for the macOS parts through `needs`: scripts/ci-green.ts reads them from the run
 * attempt's own jobs. This is the decision table: every case of the rule, a run with no macOS part, a re-run
 * attempt, and the one-look command line.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { evaluate, GRACE_MINUTES, type Job, type Needs } from "../scripts/ci-green.ts";

const ROOT = resolve(fileURLToPath(new URL("..", import.meta.url)));
const NOW = new Date("2026-11-01T12:00:00Z");
const MIN = 60_000;
const PASS: Needs = { select: { result: "success" }, test: { result: "success" }, microvm: { result: "skipped" } };
const part = (name: string, status: string, conclusion: string | null = null, startedMinutesAgo?: number): Job => ({
  name: `macOS · ${name}`,
  status,
  conclusion,
  started_at: startedMinutesAgo === undefined ? null : new Date(NOW.getTime() - startedMinutesAgo * MIN).toISOString(),
});
const ALL_DONE: Job[] = [
  part("typecheck · node tests 1/2", "completed", "success"),
  part("node tests 2/2", "completed", "success"),
  part("shell suites 1/2", "completed", "skipped"),
  part("shell suites 2/2", "completed", "success"),
];

test("the needed jobs pass on success or skipped only", () => {
  assert.equal(evaluate(PASS, ALL_DONE, NOW, 0).verdict, "pass");
  for (const bad of ["failure", "cancelled", "timed_out"]) {
    assert.equal(evaluate({ ...PASS, test: { result: bad } }, ALL_DONE, NOW, 0).verdict, "fail", bad);
  }
  assert.equal(evaluate({ ...PASS, test: { result: undefined } }, ALL_DONE, NOW, 0).verdict, "fail", "a result that is missing is no pass");
});

test("a macOS part that failed or was cancelled fails green, even while another still runs", () => {
  for (const conclusion of ["failure", "cancelled", "timed_out"]) {
    const jobs = [...ALL_DONE.slice(1), part("typecheck · node tests 1/2", "completed", conclusion)];
    assert.equal(evaluate(PASS, jobs, NOW, 0).verdict, "fail", conclusion);
  }
  const mixed = [part("node tests 2/2", "in_progress", null, 10), part("shell suites 1/2", "completed", "failure")];
  assert.equal(evaluate(PASS, mixed, NOW, 0).verdict, "fail");
});

test("a part completed with success or skipped passes", () => {
  assert.equal(evaluate(PASS, ALL_DONE, NOW, 0).verdict, "pass");
});

test("a part in progress is waited for, up to its own limit: 90 minutes for a node part, 55 for a shell part", () => {
  assert.equal(evaluate(PASS, [part("node tests 2/2", "in_progress", null, 89)], NOW, 0).verdict, "wait");
  assert.equal(evaluate(PASS, [part("node tests 2/2", "in_progress", null, 91)], NOW, 0).verdict, "fail");
  assert.equal(evaluate(PASS, [part("shell suites 1/2", "in_progress", null, 54)], NOW, 0).verdict, "wait");
  assert.equal(evaluate(PASS, [part("shell suites 1/2", "in_progress", null, 56)], NOW, 0).verdict, "fail");
});

test("a part still queued is waited for up to the grace period, then passes with a notice naming it", () => {
  const queued = [...ALL_DONE.slice(1), part("typecheck · node tests 1/2", "queued")];
  assert.equal(evaluate(PASS, queued, NOW, 0).verdict, "wait");
  assert.equal(evaluate(PASS, queued, NOW, (GRACE_MINUTES - 1) * MIN).verdict, "wait");
  const v = evaluate(PASS, queued, NOW, GRACE_MINUTES * MIN);
  assert.equal(v.verdict, "pass");
  assert.equal(v.notices.length, 1);
  assert.match(v.notices[0]!, /macOS · typecheck · node tests 1\/2 had not started/);
  // The grace never excuses a failure.
  assert.equal(evaluate({ ...PASS, test: { result: "failure" } }, queued, NOW, GRACE_MINUTES * MIN).verdict, "fail");
});

test("a run with no macOS part (the job was skipped, or the list is empty) passes on the needed jobs", () => {
  const v = evaluate(PASS, [{ name: "CI green", status: "in_progress" }, { name: "test", status: "completed", conclusion: "success" }], NOW, 0);
  assert.equal(v.verdict, "pass");
  assert.match(v.lines.join("\n"), /no macOS part/);
  assert.equal(evaluate(PASS, [], NOW, 0).verdict, "pass");
});

test("a re-run attempt: only the attempt's own jobs are read, a name listed twice counts once, as its last entry", () => {
  const rerun = [part("node tests 2/2", "completed", "failure"), part("node tests 2/2", "completed", "success"), ...ALL_DONE.filter((j) => !j.name.includes("node tests 2/2"))];
  assert.equal(evaluate(PASS, rerun, NOW, 0).verdict, "pass");
});

test("a status or conclusion it does not know is never read as a pass", () => {
  assert.equal(evaluate(PASS, [part("node tests 2/2", "completed", "something-new")], NOW, 0).verdict, "fail");
  assert.equal(evaluate(PASS, [part("node tests 2/2", "mystery")], NOW, 0).verdict, "fail");
});

test("the command line, one look: exit 0 on pass, 1 on fail, 2 on wait, notices for a part that did not start", () => {
  const dir = mkdtempSync(join(tmpdir(), "ci-green-"));
  try {
    const run = (jobs: Job[], extra: string[] = []) => {
      writeFileSync(join(dir, "needs.json"), JSON.stringify(PASS));
      writeFileSync(join(dir, "jobs.json"), JSON.stringify(jobs));
      return spawnSync("node", ["--experimental-strip-types", "--no-warnings", join(ROOT, "scripts/ci-green.ts"), "--needs", join(dir, "needs.json"), "--jobs", join(dir, "jobs.json"), "--now", NOW.toISOString(), ...extra], { encoding: "utf8" });
    };
    assert.equal(run(ALL_DONE).status, 0);
    assert.equal(run([part("node tests 2/2", "completed", "failure")]).status, 1);
    assert.equal(run([part("node tests 2/2", "queued")]).status, 2);
    const late = run([part("node tests 2/2", "queued")], ["--waited-minutes", String(GRACE_MINUTES)]);
    assert.equal(late.status, 0);
    assert.match(late.stdout, /::notice::macOS · node tests 2\/2 had not started/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
