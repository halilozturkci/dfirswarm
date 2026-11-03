/**
 * `npm test` finds its suites (scripts/test-node.ts): every tests/**\/*.test.ts
 * but the fixtures and the ones tests/node-tests.skip names, and a skip entry
 * that names no suite fails rather than going stale. Each test has a time
 * limit, so one that waits forever fails by name instead of hanging the run.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { nodeSuites, nodeTestOptions, readSkipList, TEST_TIMEOUT_MS } from "../scripts/test-node.ts";

test("the repository's suites: the VM ones are skipped, this one and the nested rule tests run", () => {
  const { run, skipped } = nodeSuites();
  assert.ok(run.includes("tests/test-node.test.ts"));
  assert.ok(run.some((p) => p.startsWith("tests/rules/")), "a suite one directory down runs too");
  for (const vm of ["tests/vm-integration.test.ts", "tests/vm-jobs.test.ts", "tests/vm-secret-rotation.test.ts"]) {
    assert.ok(skipped.includes(vm) && !run.includes(vm), vm);
  }
  assert.deepEqual(run, [...run].sort());
});

test("discovery skips fixtures, and a stale skip entry fails", () => {
  const root = mkdtempSync(join(tmpdir(), "test-node-"));
  try {
    mkdirSync(join(root, "tests", "fixtures", "x"), { recursive: true });
    mkdirSync(join(root, "tests", "deeper"), { recursive: true });
    for (const f of ["tests/a.test.ts", "tests/b.test.ts", "tests/deeper/c.test.ts", "tests/fixtures/x/d.test.ts", "tests/helper.ts"]) writeFileSync(join(root, f), "");
    writeFileSync(join(root, "tests", "node-tests.skip"), "# why\ntests/b.test.ts   # it boots something\n\n");
    assert.deepEqual(nodeSuites(root), { run: ["tests/a.test.ts", "tests/deeper/c.test.ts"], skipped: ["tests/b.test.ts"] });
    writeFileSync(join(root, "tests", "node-tests.skip"), "tests/gone.test.ts # removed long ago\n");
    assert.throws(() => nodeSuites(root), /names tests\/gone\.test\.ts, which no node suite is/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("the skip list reads paths and drops comments and blank lines", () => {
  assert.deepEqual(readSkipList("# head\n\ntests/x.test.ts  # why\n  tests/y.test.ts\n"), ["tests/x.test.ts", "tests/y.test.ts"]);
});

test("every test gets the per-test timeout unless the caller sets one", () => {
  assert.deepEqual(nodeTestOptions([]), [`--test-timeout=${TEST_TIMEOUT_MS}`]);
  assert.deepEqual(nodeTestOptions(["--test-name-pattern=hub"]), [`--test-timeout=${TEST_TIMEOUT_MS}`, "--test-name-pattern=hub"]);
  assert.deepEqual(nodeTestOptions(["--test-timeout=600000"]), ["--test-timeout=600000"], "the caller's own wins");
  assert.deepEqual(nodeTestOptions(["--test-timeout", "0"]), ["--test-timeout", "0"]);
  // Above the slowest suite file (Node 22 holds whole files to it), and a hang
  // still fails with time to spare inside the shortest CI job's 20 minutes.
  assert.ok(TEST_TIMEOUT_MS >= 180_000 && TEST_TIMEOUT_MS <= 600_000);
});

test("a test that waits forever fails by name at the timeout, and the run ends by itself", () => {
  const root = mkdtempSync(join(tmpdir(), "test-node-hang-"));
  try {
    // The shape of the vm-hub hang: a test awaits an event that already came,
    // while a server the file's after hook closes keeps the process alive.
    writeFileSync(
      join(root, "hang.test.mjs"),
      [
        'import { after, test } from "node:test";',
        'import { createServer } from "node:net";',
        `const server = createServer().listen(${JSON.stringify(join(root, "s.sock"))});`,
        'after(() => server.close());',
        'test("waits for an exit that already came", async () => { await new Promise(() => {}); });',
        'test("the next test still runs", () => {});',
      ].join("\n"),
    );
    const started = Date.now();
    // NODE_TEST_CONTEXT would make the inner run report to this one's runner instead of exiting with its own status.
    const { NODE_TEST_CONTEXT: _context, ...env } = process.env;
    const r = spawnSync(process.execPath, ["--test", "--test-reporter=spec", ...nodeTestOptions([], 500), join(root, "hang.test.mjs")], { encoding: "utf8", env, timeout: 60_000 });
    const out = `${r.stdout}${r.stderr}`;
    assert.equal(r.signal, null, `the run ended by itself:\n${out}`);
    assert.notEqual(r.status, 0, "a timed-out test fails the run");
    assert.match(out, /test timed out after 500ms/);
    // Node 22 also times the whole file, and may name the file instead.
    assert.match(out, /✖ (waits for an exit that already came|.*hang\.test\.mjs)/);
    if (Number(process.versions.node.split(".")[0]) >= 24) {
      // Node 24 times the test alone: it is the one named, and the file goes on.
      assert.match(out, /✖ waits for an exit that already came/);
      assert.match(out, /✔ the next test still runs/);
    }
    assert.ok(Date.now() - started < 30_000, `in seconds, not the job's limit (${Date.now() - started} ms)`);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
