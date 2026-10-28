/**
 * The macOS and the Linux CI jobs are split in parts that run side by side: some run the node
 * suites, `--test-shard I/N` each (node's own, handed through `npm test`; the
 * first of them also runs the typecheck), the others the shell suites,
 * `--shard I/N` each (scripts/test-bash.sh). Splitting must not lose a test, so
 * this suite reads the workflow and the shard assignment and fails if any shell
 * suite is in no shard or in two, or if the node parts are not shards 1..N of
 * one N that together leave no node suite out.
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { nodeSuites } from "../scripts/test-node.ts";

const ROOT = resolve(fileURLToPath(new URL("..", import.meta.url)));
const WORKFLOW = readFileSync(join(ROOT, ".github/workflows/ci.yml"), "utf8");

/** Every shell suite's stem, as `scripts/test-bash.sh` finds them. */
function allShellSuites(): string[] {
  return readdirSync(join(ROOT, "tests"))
    .filter((f) => f.endsWith(".test.sh"))
    .map((f) => f.slice(0, -".test.sh".length))
    .sort();
}

/** The stems shard `i/n` runs, from the script itself (`--list` runs nothing). */
function shardOf(i: number, n: number): string[] {
  const out = execFileSync("bash", [join(ROOT, "scripts/test-bash.sh"), "--shard", `${i}/${n}`, "--list"], { encoding: "utf8" });
  return out.split("\n").filter(Boolean);
}

/** The text of the `macos:` job in ci.yml, up to the next job. */
function macosJob(): string {
  const m = WORKFLOW.match(/^ {2}macos:\n([\s\S]*?)(?=^ {2}[a-z][\w-]*:\n|(?![\s\S]))/m);
  assert.ok(m, "ci.yml has no `macos:` job");
  return m[1];
}

test("any number of shards holds every shell suite exactly once", () => {
  const all = allShellSuites();
  assert.ok(all.length > 0);
  for (const n of [1, 2, 3, 4]) {
    const shards = Array.from({ length: n }, (_, k) => shardOf(k + 1, n));
    const seen = shards.flat();
    assert.deepEqual([...seen].sort(), all, `${n} shards: their union is not the full list, or a suite is in two`);
    if (all.length >= n) for (const [k, s] of shards.entries()) assert.ok(s.length > 0, `${n} shards: shard ${k + 1} is empty`);
  }
});

test("a shard is the same on every call and does not depend on what is named", () => {
  assert.deepEqual(shardOf(1, 2), shardOf(1, 2));
  assert.deepEqual(shardOf(2, 3), shardOf(2, 3));
});

test("a bad shard or a shard with named suites is refused", () => {
  for (const args of [["--shard", "0/2"], ["--shard", "3/2"], ["--shard", "x"], ["--shard", "1/2", "reap"], ["--shard", ""], ["--shard"], ["--shard="], ["--bogus"]]) {
    assert.throws(() => execFileSync("bash", [join(ROOT, "scripts/test-bash.sh"), ...args, "--list"], { stdio: "pipe" }), (e: { status?: number }) => e.status === 2, args.join(" "));
  }
});

test("--within keeps, of a shard, only the suites a file names, and a shard left with none passes", () => {
  const dir = mkdtempSync(join(tmpdir(), "ci-within-"));
  try {
    const [first] = shardOf(1, 2);
    const [other] = shardOf(2, 2);
    const list = join(dir, "shell.list");
    writeFileSync(list, `${first}\n${other}\nno-such-suite\n`);
    const run = (shard: string) => execFileSync("bash", [join(ROOT, "scripts/test-bash.sh"), "--shard", shard, "--within", list, "--list"], { encoding: "utf8" }).split("\n").filter(Boolean);
    assert.deepEqual(run("1/2"), [first]);
    assert.deepEqual(run("2/2"), [other]);
    writeFileSync(list, "no-such-suite\n");
    assert.deepEqual(run("1/2"), [], "a shard none of whose suites is listed runs nothing");
    assert.throws(() => execFileSync("bash", [join(ROOT, "scripts/test-bash.sh"), "--within", join(dir, "absent")], { stdio: "pipe" }), (e: { status?: number }) => e.status === 2);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the weights file names only suites that exist, once each", () => {
  const all = allShellSuites();
  const names = readFileSync(join(ROOT, "tests/shell-suites.weights"), "utf8")
    .split("\n")
    .map((l) => l.replace(/#.*$/, "").trim())
    .filter(Boolean)
    .map((l) => {
      const [stem, secs] = l.split(/\s+/);
      assert.match(secs ?? "", /^[1-9]\d*$/, `weights line '${l}'`);
      return stem;
    });
  assert.deepEqual(names.filter((n) => !all.includes(n)), [], "a weights line names a suite that no longer exists: remove it");
  assert.equal(new Set(names).size, names.length, "a suite is weighed twice");
});

/** The text of the `test:` job (the Linux parts) in ci.yml, up to the next job. */
function linuxJob(): string {
  const m = WORKFLOW.match(/^ {2}test:\n([\s\S]*?)(?=^ {2}[a-z][\w-]*:\n|(?![\s\S]))/m);
  assert.ok(m, "ci.yml has no `test:` job");
  return m[1];
}

test("the macOS job's parts together run every node suite and every shell suite", () => {
  // A self-hosted Mac may hold the concurrency down (a count, not a filter).
  coversEverySuite(macosJob(), "macOS", / \$\{\{ runner\.environment == 'self-hosted' && '--test-concurrency=\d+' \|\| '' \}\}/);
});

test("the Linux job's parts together run every node suite and every shell suite, and the UI build once", () => {
  const job = linuxJob();
  coversEverySuite(job, "Linux", null);
  assert.equal((job.match(/^\s+ui: true$/gm) ?? []).length, 1, "exactly one Linux part builds the UI");
  assert.match(job, /- name: UI build\n\s+if: matrix\.ui\n\s+run: npm run ui:build\n/, "the UI build step must run for the part that names it");
  assert.match(job, /- name: Nothing from a run is tracked\n\s+if: matrix\.ui\n/, "the tracked-files check must run in the UI part");
  assert.match(job, /run: npm test -- --test-shard=\$\{\{ matrix\.node \}\}[^\n]*\n\s+env:\n\s+SWARM_REQUIRE_BROWSER: "1"\n/, "the Linux node parts must require the browser they install");
});

// The one way a job may run fewer suites: the select job's lists, on a run it
// did not mark as everything. Each with the leading space the run lines use.
const NODE_TAIL = String.raw` --timings=\$\{\{ runner\.temp \}\}/timings\.json \$\{\{ needs\.select\.outputs\.all != 'true' && format\('--files-from=\{0\}/node\.list', runner\.temp\) \|\| '' \}\}`;
const SHELL_TAIL = String.raw` \$\{\{ needs\.select\.outputs\.all != 'true' && format\('--within=\{0\}/shell\.list', runner\.temp\) \|\| '' \}\}`;

test("a suite list narrows a run only through the select job, and never on a run it marks as everything", () => {
  const narrowing = [...WORKFLOW.matchAll(/--files-from|--within|--tier=/g)].length;
  const guarded = [...WORKFLOW.matchAll(/needs\.select\.outputs\.all != 'true' && format\('--(?:files-from|within)=\{0\}\/(?:node|shell)\.list', runner\.temp\)/g)].length;
  assert.ok(narrowing > 0, "no job reads the select job's lists");
  assert.equal(narrowing, guarded, "a --files-from, --within or --tier in ci.yml that is not the select job's guarded list");
  const select = WORKFLOW.match(/^ {2}select:\n([\s\S]*?)(?=^ {2}[a-z][\w-]*:\n)/m)?.[1] ?? "";
  assert.match(select, /if \[ "\$EVENT" != pull_request \] \|\| \[ "\$FULL_LABEL" = true \]; then[\s\S]*?echo "all=true"/, "a run that is not a pull request, or a pull request labelled full-ci, must run everything");
  assert.match(select, /scripts\/test-select\.ts --base "\$BASE" --json/, "a pull request's lists must come from scripts/test-select.ts against its base");
  for (const job of ["test", "node-floor", "node-24", "macos", "microvm"]) {
    const text = WORKFLOW.match(new RegExp(String.raw`^ {2}${job}:\n([\s\S]*?)(?=^ {2}[a-z][\w-]*:\n|(?![\s\S]))`, "m"))?.[1] ?? "";
    assert.match(text, /^ {4}needs: select$/m, `the ${job} job must wait for the select job`);
  }
});

/** The node parts are shards 1..N of one N, each once, narrowed only by the select job's list; one node part typechecks; the shell parts are shards 1..M, which together hold every shell suite. */
function coversEverySuite(job: string, where: string, nodeExtra: RegExp | null): void {
  // Node: the matrix names every shard 1..N of one N, each once, and the step
  // passes the part's own shard to node. The suites themselves are all found
  // by scripts/test-node.ts, with no filter, so a new one is in some shard.
  const nodeShards = [...job.matchAll(/^\s+node: "(\d+)\/(\d+)"$/gm)].map((m) => [Number(m[1]), Number(m[2])]);
  assert.ok(nodeShards.length >= 1, `no node part in the ${where} job`);
  const nn = nodeShards[0][1];
  assert.deepEqual(nodeShards.map(([i]) => i).sort(), Array.from({ length: nn }, (_, k) => k + 1), "the node parts must be shards 1..N, each once");
  assert.ok(nodeShards.every(([, m]) => m === nn), "the node parts name different shard counts");
  const extra = nodeExtra ? `(?:${nodeExtra.source})?` : "";
  assert.match(job, new RegExp(String.raw`- name: Node tests[^\n]*\n\s+if: matrix\.node\n\s+run: npm test -- --test-shard=\$\{\{ matrix\.node \}\}` + NODE_TAIL + extra + String.raw`\n`), "the node step must run `npm test` with the part's own --test-shard, and no filter but the select job's list");
  // The typecheck is done once: in exactly one part, which is a node part.
  assert.equal((job.match(/^\s+typecheck: true$/gm) ?? []).length, 1, "exactly one part runs the typecheck");
  assert.match(job, /- name: Typecheck\n\s+if: matrix\.typecheck\n\s+run: npm run typecheck\n/, "the typecheck step must run for the part that names it");
  assert.match(job, /node: "\d+\/\d+"\n\s+typecheck: true\n/, "the typecheck belongs to a node part");
  // Shell: the matrix names every shard 1..N of one N, and the step passes it on.
  const shards = [...job.matchAll(/^\s+shard: "(\d+)\/(\d+)"$/gm)].map((m) => [Number(m[1]), Number(m[2])]);
  assert.ok(shards.length >= 1, `no shell part in the ${where} job`);
  const n = shards[0][1];
  assert.deepEqual(shards.map(([i]) => i).sort(), Array.from({ length: n }, (_, k) => k + 1), "the shell parts must be shards 1..N, each once");
  assert.ok(shards.every(([, m]) => m === n), "the shell parts name different shard counts");
  assert.match(job, new RegExp(String.raw`if: matrix\.shard\n\s+run: npm run test:bash -- --shard \$\{\{ matrix\.shard \}\}` + SHELL_TAIL + String.raw`\n`), "the shell step must pass the part's own shard on, narrowed only by the select job's list");
  // And that shard count, applied by the script, covers all of them.
  const ran = Array.from({ length: n }, (_, k) => shardOf(k + 1, n)).flat();
  assert.deepEqual([...ran].sort(), allShellSuites());
}

test("node's --test-shard, as the node parts use it, runs every suite file exactly once", () => {
  // Measured on this Node, not assumed: five tiny suites, every shard of 1..4
  // run with `--test-shard` and the files that ran collected from the output.
  const dir = mkdtempSync(join(tmpdir(), "ci-node-shard-"));
  // Inside a test run, node reports a nested `node --test` to its parent
  // instead of printing: take the marker out so the child prints its own.
  const childEnv = { ...process.env };
  delete childEnv.NODE_TEST_CONTEXT;
  try {
    const files = ["a", "b", "c", "d", "e"].map((k) => {
      const f = join(dir, `${k}.test.mjs`);
      writeFileSync(f, `import { test } from "node:test";\ntest("t", () => { console.log("RAN-${k}"); });\n`);
      return f;
    });
    for (const n of [1, 2, 3, 4]) {
      const ran: string[] = [];
      for (let i = 1; i <= n; i++) {
        const out = execFileSync(process.execPath, ["--test", `--test-shard=${i}/${n}`, ...files], { encoding: "utf8", env: childEnv });
        ran.push(...[...out.matchAll(/RAN-([a-e])/g)].map((m) => m[1]));
      }
      assert.deepEqual([...ran].sort(), ["a", "b", "c", "d", "e"], `${n} node shards: their union is not every suite, or a suite ran twice`);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the node suites npm test runs are found by scripts/test-node.ts, none lost to a filter", () => {
  const { run, skipped } = nodeSuites(ROOT);
  assert.ok(run.includes("tests/ci-shards.test.ts"), "this suite must be one of them");
  // The only node suites left out are the ones tests/node-tests.skip names.
  const onDisk = (readdirSync(join(ROOT, "tests"), { recursive: true }) as string[]).filter((p) => p.endsWith(".test.ts") && !p.split("/").includes("fixtures")).length;
  assert.equal(run.length + skipped.length, onDisk);
});
