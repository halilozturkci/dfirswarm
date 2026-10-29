/**
 * scripts/test-node.ts's own options (the tier, a list of suites, timings,
 * retrying a failed file alone, the shard), the deep suites run apart under
 * their own timeout, and the timings reporter they use, which is run here on
 * two small suites so that a change in what node reports fails by name.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { chooseSuites, DEEP_TIMEOUT_MS, deepSuites, failedSuites, mergeTimings, nodeSuites, ownOptions, passes, TEST_TIMEOUT_MS, worse } from "../scripts/test-node.ts";

const ROOT = resolve(fileURLToPath(new URL("..", import.meta.url)));

test("its own options come out of argv; the rest is left for node in order", () => {
  const o = ownOptions(["--tier=fast", "--test-shard=1/2", "--files-from=/tmp/x", "--retry-alone", "--test-name-pattern=a", "--timings=/tmp/t.json", "--list", "--test-concurrency=3"]);
  assert.deepEqual(o, { tier: "fast", filesFrom: "/tmp/x", timings: "/tmp/t.json", retryAlone: true, shard: { index: 1, total: 2 }, list: true, rest: ["--test-name-pattern=a", "--test-concurrency=3"] });
  assert.deepEqual(ownOptions([]).rest, []);
  assert.equal(ownOptions([]).tier, "all");
  assert.equal(ownOptions([]).shard, null);
  assert.deepEqual(ownOptions(["--test-shard", "3/3", "--test-only"]), { ...ownOptions([]), shard: { index: 3, total: 3 }, rest: ["--test-only"] });
  assert.throws(() => ownOptions(["--tier=slow"]), /fast, deep or all/);
  for (const bad of [["--test-shard=0/2"], ["--test-shard=3/2"], ["--test-shard=1/0"], ["--test-shard=x"], ["--test-shard=1/2/3"], ["--test-shard="], ["--test-shard"]]) {
    assert.throws(() => ownOptions(bad), /--test-shard takes I\/N/, bad.join(" "));
  }
});

test("the deep suites run apart, after the others, under the longer timeout; a shard cuts each list round-robin", () => {
  const chosen = ["tests/a.test.ts", "tests/b.test.ts", "tests/c.test.ts", "tests/d.test.ts", "tests/e.test.ts"];
  const deep = ["tests/b.test.ts", "tests/d.test.ts", "tests/e.test.ts"];
  assert.deepEqual(passes(chosen, deep, null), [
    { name: "others", files: ["tests/a.test.ts", "tests/c.test.ts"], timeoutMs: TEST_TIMEOUT_MS },
    { name: "deep", files: ["tests/b.test.ts", "tests/d.test.ts", "tests/e.test.ts"], timeoutMs: DEEP_TIMEOUT_MS },
  ]);
  assert.deepEqual(passes(chosen, deep, { index: 1, total: 2 }).map((p) => p.files), [["tests/a.test.ts"], ["tests/b.test.ts", "tests/e.test.ts"]]);
  assert.deepEqual(passes(chosen, deep, { index: 2, total: 2 }).map((p) => p.files), [["tests/c.test.ts"], ["tests/d.test.ts"]]);
  // A run with no file is not started: no deep suite chosen, or none in this shard.
  assert.deepEqual(passes(["tests/a.test.ts"], deep, null).map((p) => p.name), ["others"]);
  assert.deepEqual(passes(["tests/b.test.ts"], deep, null).map((p) => p.name), ["deep"]);
  assert.deepEqual(passes(["tests/a.test.ts", "tests/b.test.ts"], deep, { index: 2, total: 2 }), []);
  assert.deepEqual(passes([], deep, null), []);
  // The order the list came in does not move a suite to another shard.
  assert.deepEqual(passes([...chosen].reverse(), deep, { index: 1, total: 3 }), passes(chosen, deep, { index: 1, total: 3 }));
  assert.ok(DEEP_TIMEOUT_MS >= 2 * TEST_TIMEOUT_MS && DEEP_TIMEOUT_MS <= 20 * 60_000, "longer than the others', and a hang still fails well inside a node job's limit");
});

test("the two runs' timings are one document, and their statuses one status", () => {
  const a = JSON.stringify({ files: [{ file: "/r/tests/a.test.ts", ms: 10 }, { file: "/r/tests/c.test.ts", ms: 5 }], failed: ["/r/tests/c.test.ts"] });
  const b = JSON.stringify({ files: [{ file: "/r/tests/b.test.ts", ms: 7 }], failed: [] });
  assert.deepEqual(JSON.parse(mergeTimings([a, b])), { files: [{ file: "/r/tests/a.test.ts", ms: 10 }, { file: "/r/tests/b.test.ts", ms: 7 }, { file: "/r/tests/c.test.ts", ms: 5 }], failed: ["/r/tests/c.test.ts"] });
  assert.deepEqual(JSON.parse(mergeTimings([b])), JSON.parse(b));
  // A failure is never hidden by a later run that passed, or passed only alone.
  for (const [x, y, want] of [[0, 0, 0], [0, 3, 3], [3, 0, 3], [1, 0, 1], [0, 1, 1], [3, 1, 1], [1, 3, 1], [3, 3, 3], [2, 1, 2]]) {
    assert.equal(worse(x, y), want, `${x} then ${y}`);
  }
});

test("a tier and a list cut the suites; a listed path that is no suite is refused", () => {
  const run = ["tests/a.test.ts", "tests/b.test.ts", "tests/c.test.ts"];
  const deep = ["tests/b.test.ts"];
  assert.deepEqual(chooseSuites(run, deep, "all", null), run);
  assert.deepEqual(chooseSuites(run, deep, "fast", null), ["tests/a.test.ts", "tests/c.test.ts"]);
  assert.deepEqual(chooseSuites(run, deep, "deep", null), ["tests/b.test.ts"]);
  assert.deepEqual(chooseSuites(run, deep, "all", ["tests/c.test.ts", "tests/b.test.ts"]), ["tests/b.test.ts", "tests/c.test.ts"]);
  assert.deepEqual(chooseSuites(run, deep, "fast", ["tests/b.test.ts"]), []);
  assert.deepEqual(chooseSuites(run, deep, "all", []), []);
  assert.throws(() => chooseSuites(run, deep, "all", ["tests/gone.test.ts"]), /no suite npm test runs/);
});

test("the deep list names only suites npm test runs, each once", () => {
  const deep = deepSuites(ROOT);
  const { run } = nodeSuites(ROOT);
  assert.ok(deep.every((p) => run.includes(p)));
  assert.equal(new Set(deep).size, deep.length, "a suite is listed twice");
});

test("the timings reporter writes each file's time and the files that failed", () => {
  const dir = mkdtempSync(join(tmpdir(), "test-timings-"));
  // A nested node --test reports to its parent unless the marker is taken out.
  const env = { ...process.env };
  delete env.NODE_TEST_CONTEXT;
  try {
    writeFileSync(join(dir, "pass.test.mjs"), 'import { test } from "node:test";\ntest("slow", async () => { await new Promise((r) => setTimeout(r, 120)); });\ntest("quick", () => {});\n');
    writeFileSync(join(dir, "fail.test.mjs"), 'import { test } from "node:test";\ntest("outer", async (t) => { await t.test("inner fails", () => { throw new Error("no"); }); });\n');
    const out = join(dir, "t.json");
    const r = spawnSync(process.execPath, ["--experimental-strip-types", "--test", `--test-reporter=${join(ROOT, "scripts", "test-timings-reporter.ts")}`, `--test-reporter-destination=${out}`, join(dir, "pass.test.mjs"), join(dir, "fail.test.mjs")], { env, encoding: "utf8" });
    assert.notEqual(r.status, 0, "a failing suite must fail the run");
    const doc = JSON.parse(readFileSync(out, "utf8")) as { files: { file: string; ms: number; tests: number; failed: number }[]; failed: string[] };
    const pass = doc.files.find((f) => f.file.endsWith("pass.test.mjs"));
    const fail = doc.files.find((f) => f.file.endsWith("fail.test.mjs"));
    assert.ok(pass && fail, JSON.stringify(doc));
    assert.equal(pass.tests, 2, "top-level tests only, each once");
    assert.ok(pass.ms >= 100, `the slow test's time is in its file's: ${pass.ms}`);
    assert.equal(pass.failed, 0);
    assert.ok(fail.failed >= 1, "a failing subtest counts its file as failed");
    assert.deepEqual(doc.failed.map((f) => f.split(/[\\/]/).pop()), ["fail.test.mjs"]);
    assert.deepEqual(failedSuites(JSON.stringify({ failed: [join(ROOT, "tests", "x.test.ts")] }), ROOT), ["tests/x.test.ts"]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
