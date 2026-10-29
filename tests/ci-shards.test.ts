/**
 * The macOS and the Linux CI jobs are split in parts that run side by side: some run the node
 * suites, `--test-shard I/N` each (cut by scripts/test-node.ts, which runs the
 * deep suites apart after the others; the first part also runs the
 * typecheck), the others the shell suites,
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
import { deepSuites, nodeSuites } from "../scripts/test-node.ts";

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
  assert.match(select, /if \{ \[ "\$EVENT" != pull_request \] && \[ "\$narrow_push" != true \]; \} \|\| \[ "\$FULL_LABEL" = true \]; then[\s\S]*?echo "all=true"/, "a run that is neither a pull request nor a push with a range (the nightly run, a run by hand), and a pull request labelled full-ci, must run everything");
  assert.match(select, /narrow_push=false\n\s+if \[ "\$EVENT" = push \] && \[ -n "\$BASE" \] && git cat-file -e "\$BASE\^\{commit\}" 2>\/dev\/null; then narrow_push=true; fi/, "only a push whose before is a commit here may run narrow");
  assert.match(select, /BASE: \$\{\{ github\.event_name == 'pull_request' && github\.event\.pull_request\.base\.sha \|\| github\.event\.before \}\}/, "a pull request reads its base, a push what it brought");
  assert.match(select, /scripts\/test-select\.ts --base "\$BASE" --json/, "the lists must come from scripts/test-select.ts against that base");
  assert.match(WORKFLOW, /^ {2}schedule:\n {4}- cron: "[^"]+"$/m, "the nightly run, which runs everything, must stay");
  for (const job of ["test", "node-floor", "node-24", "macos", "microvm"]) {
    const text = WORKFLOW.match(new RegExp(String.raw`^ {2}${job}:\n([\s\S]*?)(?=^ {2}[a-z][\w-]*:\n|(?![\s\S]))`, "m"))?.[1] ?? "";
    assert.match(text, /^ {4}needs: select$/m, `the ${job} job must wait for the select job`);
  }
});

test("the Node 22.19 and Node 24 jobs' parts are node shards 1..N each, and Node 22.19's first typechecks", () => {
  for (const name of ["node-floor", "node-24"]) {
    const job = WORKFLOW.match(new RegExp(String.raw`^ {2}${name}:\n([\s\S]*?)(?=^ {2}[a-z][\w-]*:\n|(?![\s\S]))`, "m"))?.[1];
    assert.ok(job, `ci.yml has no ${name} job`);
    const listed = job.match(/^\s+node: \[([^\]]*)\]$/m)?.[1];
    assert.ok(listed, `${name}: no node: [..] matrix`);
    const parts = listed.split(",").map((s) => s.trim().replace(/^"|"$/g, "")).map((p) => p.split("/").map(Number));
    const n = parts[0][1];
    assert.ok(parts.every(([, m]) => m === n), `${name}: the parts name different shard counts`);
    assert.deepEqual(parts.map(([i]) => i).sort(), Array.from({ length: n }, (_, k) => k + 1), `${name}: the parts must be shards 1..N, each once`);
    assert.match(job, new RegExp(String.raw`- name: Node tests \$\{\{ matrix\.node \}\}\n\s+run: npm test -- --test-shard=\$\{\{ matrix\.node \}\}` + NODE_TAIL + String.raw`\n`), `${name}: the node step must pass the part's own shard, and no filter but the select job's list`);
  }
  const floor = WORKFLOW.match(/^ {2}node-floor:\n([\s\S]*?)(?=^ {2}[a-z][\w-]*:\n)/m)?.[1] ?? "";
  assert.match(floor, /- name: Typecheck\n\s+if: matrix\.node == '1\/\d+'\n\s+run: npm run typecheck\n/, "the floor's typecheck must run in its first part");
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

test("npm test's --test-shard, as the node parts use it, runs every suite file exactly once, the deep ones last", () => {
  // From the script itself (`--list` runs nothing), as a part would run it:
  // every shard of 1..4, and a list of suites the way the select job hands one.
  const { run } = nodeSuites(ROOT);
  const deep = deepSuites(ROOT);
  const dir = mkdtempSync(join(tmpdir(), "ci-node-shard-"));
  try {
    const list = join(dir, "node.list");
    const listed = [...new Set([run[0], run[run.length - 1], ...deep.slice(0, 3)])];
    writeFileSync(list, listed.join("\n") + "\n");
    for (const [want, extra] of [[run, []], [listed, [`--files-from=${list}`]]] as const) {
      for (const n of [1, 2, 3, 4]) {
        const shards = Array.from({ length: n }, (_, k) =>
          execFileSync(process.execPath, ["--experimental-strip-types", "--no-warnings", join(ROOT, "scripts/test-node.ts"), `--test-shard=${k + 1}/${n}`, ...extra, "--list"], { encoding: "utf8" }).split("\n").filter(Boolean));
        assert.deepEqual(shards.flat().sort(), [...want].sort(), `${n} node shards: their union is not every suite, or a suite is in two`);
        for (const [k, s] of shards.entries()) {
          const first = s.findIndex((f) => deep.includes(f));
          assert.ok(first === -1 || s.slice(first).every((f) => deep.includes(f)), `${n} shards: shard ${k + 1} runs a deep suite before another`);
        }
        const deepCounts = shards.map((s) => s.filter((f) => deep.includes(f)).length);
        assert.ok(Math.max(...deepCounts) - Math.min(...deepCounts) <= 1, `${n} shards: the deep suites are not spread evenly (${deepCounts.join(", ")})`);
      }
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

test("the CI green job, the check main requires, needs every other job, always runs, and passes on success or skipped only", () => {
  const jobs = WORKFLOW.slice(WORKFLOW.search(/^jobs:\n/m));
  const ids = [...jobs.matchAll(/^ {2}([a-z][\w-]*):\n/gm)].map((m) => m[1]);
  const green = jobs.match(/^ {2}green:\n([\s\S]*?)(?=^ {2}[a-z][\w-]*:\n|(?![\s\S]))/m)?.[1];
  assert.ok(green, "ci.yml has no green job");
  assert.match(green, /^ {4}name: CI green$/m, "its name is what main's ruleset requires: renaming it leaves the ruleset waiting for a check that never comes");
  // A required check that is skipped counts as passed: a green job skipped
  // because a job it needs failed would let the pull request merge.
  assert.match(green, /^ {4}if: always\(\)$/m, "it must run whatever the jobs it needs did");
  const needs = green.match(/^ {4}needs: \[([^\]\n]*)\]$/m)?.[1].split(",").map((s) => s.trim()) ?? [];
  assert.deepEqual([...needs].sort(), ids.filter((id) => id !== "green").sort(), "it must need every other job, or a job it leaves out could fail and the pull request still merge");
  assert.match(green, /NEEDS: \$\{\{ toJSON\(needs\) \}\}/, "it reads every result it needs");
  assert.match(green, /jq -e 'all\(\.\[\]; \.result == "success" or \.result == "skipped"\)'/, "anything but success or skipped (failure, cancelled) must fail it");
});
