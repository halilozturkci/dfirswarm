/**
 * scripts/test-node.ts's own options (the tier, a list of suites, timings,
 * retrying a failed file alone) and the timings reporter they use, which is run
 * here on two small suites so that a change in what node reports fails by name.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { chooseSuites, deepSuites, failedSuites, nodeSuites, ownOptions } from "../scripts/test-node.ts";

const ROOT = resolve(fileURLToPath(new URL("..", import.meta.url)));

test("its own options come out of argv; the rest is left for node in order", () => {
  const o = ownOptions(["--tier=fast", "--test-shard=1/2", "--files-from=/tmp/x", "--retry-alone", "--timings=/tmp/t.json", "--test-concurrency=3"]);
  assert.deepEqual(o, { tier: "fast", filesFrom: "/tmp/x", timings: "/tmp/t.json", retryAlone: true, rest: ["--test-shard=1/2", "--test-concurrency=3"] });
  assert.deepEqual(ownOptions([]).rest, []);
  assert.equal(ownOptions([]).tier, "all");
  assert.throws(() => ownOptions(["--tier=slow"]), /fast, deep or all/);
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
