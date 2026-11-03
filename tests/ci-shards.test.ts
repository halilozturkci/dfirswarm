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
import { repoLayout, select } from "../scripts/test-select.ts";

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
  // The Python 3.11 job builds its own list (the pack-tool suites among the select job's, or all of them) in a step that reads the
  // select job's outputs; the next test holds that step to it.
  const packList = [...WORKFLOW.matchAll(/--files-from="\$RUNNER_TEMP\/pack\.list"/g)].length;
  assert.ok(narrowing > 0, "no job reads the select job's lists");
  assert.equal(narrowing, guarded + packList, "a --files-from, --within or --tier in ci.yml that is not the select job's guarded list");
  assert.equal(packList, 1, "the Python 3.11 job's one list");
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

test("the CI green job, the check main requires, needs every other job but macos, always runs, and decides through scripts/ci-green.ts", () => {
  const jobs = WORKFLOW.slice(WORKFLOW.search(/^jobs:\n/m));
  const ids = [...jobs.matchAll(/^ {2}([a-z][\w-]*):\n/gm)].map((m) => m[1]);
  const green = jobs.match(/^ {2}green:\n([\s\S]*?)(?=^ {2}[a-z][\w-]*:\n|(?![\s\S]))/m)?.[1];
  assert.ok(green, "ci.yml has no green job");
  assert.match(green, /^ {4}name: CI green$/m, "its name is what main's ruleset requires: renaming it leaves the ruleset waiting for a check that never comes");
  // A required check that is skipped counts as passed: a green job skipped
  // because a job it needs failed would let the pull request merge.
  assert.match(green, /^ {4}if: always\(\)$/m, "it must run whatever the jobs it needs did");
  const needs = green.match(/^ {4}needs: \[([^\]\n]*)\]$/m)?.[1].split(",").map((s) => s.trim()) ?? [];
  assert.deepEqual([...needs].sort(), ids.filter((id) => id !== "green" && id !== "macos").sort(), "it must need every other job but macos, or a job it leaves out could fail and the pull request still merge (the macOS parts are read from the run's job list by scripts/ci-green.ts, so a queued Mac does not hold it)");
  assert.match(green, /NEEDS: \$\{\{ toJSON\(needs\) \}\}/, "it reads every result it needs");
  assert.match(green, /scripts\/ci-green\.ts[\s\S]*--needs-env NEEDS[\s\S]*--jobs-from-gh/,"it decides through scripts/ci-green.ts: the needed jobs pass on success or skipped only (tests/ci-green.test.ts), and the macOS parts are read from this run attempt's jobs");
  assert.match(green, /^ {6}actions: read$/m, "it reads the run's jobs");
  assert.doesNotMatch(green, /^ {4}needs:.*\bmacos\b/m, "it does not need the macOS job");
});

// --- the Python 3.11 job: the pack tools on the images' interpreter -----------------------------------------------------------------

/** The text of one job of ci.yml, up to the next job. */
function jobText(name: string): string {
  const m = WORKFLOW.match(new RegExp(String.raw`^ {2}${name}:\n([\s\S]*?)(?=^ {2}[a-z][\w-]*:\n|(?![\s\S]))`, "m"));
  assert.ok(m, `ci.yml has no \`${name}:\` job`);
  return m[1];
}

const BASE_DOCKERFILE = readFileSync(join(ROOT, "images/base.Dockerfile"), "utf8");

test("a job runs the pack-tool suites on the images' Python 3.11, in the images' own base image, from the images' apt snapshot", () => {
  const job = jobText("python-311");
  // The image is the one the base Dockerfile ends in, by the same digest: a digest moved there (scripts/apt-snapshot-bump.sh --digests) and not here fails this.
  const from = [...BASE_DOCKERFILE.matchAll(/^FROM (node:24-bookworm-slim@sha256:[0-9a-f]{64})$/gm)].map((m) => m[1]);
  assert.equal(from.length, 1, "images/base.Dockerfile has one node:24-bookworm-slim stage, pinned by digest");
  const image = from[0].replace(/[.*+?^${}()|[\]\\]/g, (c) => `\\${c}`);
  assert.match(job, new RegExp(String.raw`^ {4}container:\n {6}image: ${image}\n(?: {6}#[^\n]*\n)* {6}options: --init$`, "m"), "the job's container is the base image's node stage, by its digest, with an init that reaps what the suites kill (a zombie is still a pid to a stop-signal case)");
  assert.match(job, /^ {4}runs-on: ubuntu-24\.04$/m);
  // python3 comes from the images' own apt sources (the snapshot date in images/debian-snapshot, the sources text of the Dockerfile) and is checked to be 3.11.
  assert.match(job, /d="\$\(tr -d '\[:space:\]' < images\/debian-snapshot\)"/, "the snapshot date is read from images/debian-snapshot");
  const sources = BASE_DOCKERFILE.match(/printf ('Types: deb\\nURIs: http:\/\/snapshot\.debian\.org[^']*') "\$d" "\$d" > \/etc\/apt\/sources\.list\.d\/debian\.sources/)?.[1];
  assert.ok(sources, "the Dockerfile writes the snapshot sources");
  assert.ok(job.includes(`printf ${sources} "$d" "$d" > /etc/apt/sources.list.d/debian.sources`), "the job writes the same apt sources as the base image");
  assert.match(job, /apt-get install -y -q --no-install-recommends [^\n]*\bpython3\b/, "python3 is Debian's");
  assert.match(job, /assert sys\.version_info\[:2\] == \(3, 11\)/, "the job fails when the interpreter is not 3.11");
  // The suites: the pack-tool ones, by scripts/test-node.ts, in shards 1..N of one N, as an unprivileged user.
  const parts = [...job.matchAll(/^\s+part: \[([^\]]*)\]$/gm)][0]?.[1];
  assert.ok(parts, "no part: [..] matrix");
  const shards = parts.split(",").map((s) => s.trim().replace(/^"|"$/g, "").split("/").map(Number));
  const n = shards[0][1];
  assert.ok(shards.every(([, m]) => m === n), "the parts name different shard counts");
  assert.deepEqual(shards.map(([i]) => i).sort(), Array.from({ length: n }, (_, k) => k + 1), "the parts must be shards 1..N, each once");
  assert.match(job, /scripts\/test-node\.ts --test-shard=\$\{\{ matrix\.part \}\} --files-from="\$RUNNER_TEMP\/pack\.list" "--test-skip-pattern=a walk of the whole file system with max_seconds 1"'/, "each part runs its own shard of the pack list through scripts/test-node.ts, with the one case it names left out");
  // The one case left out exists, under that name, and says why it cannot run on a small root (it walks "/").
  const skipped = readFileSync(join(ROOT, "tests/pack-windows-forensics-links-contract.test.ts"), "utf8");
  assert.match(skipped, /test\("lnk_jumplist: a walk of the whole file system with max_seconds 1 ends by its clock/, "the skipped case is named as the job skips it");
  assert.match(skipped, /runTool\("lnk_jumplist", cwd, \{ path: "\/", max_seconds: 1 \}\)/, "and it walks the root, the file system whose size it relies on");
  assert.equal(job.match(/--test-skip-pattern/g)?.length, 1, "one case is left out, no more");
  // Two uids share the job: root in the container (the steps), the runner's own (the files it writes into $RUNNER_TEMP before every step).
  // A chown of $RUNNER_TEMP to the node user locks the runner out of its own step files, and the next step fails.
  const commands = job.split("\n").filter((l) => !/^\s*#/.test(l));
  assert.deepEqual(commands.filter((l) => /\bchown\b/.test(l)).map((l) => l.trim()), ['chown -R node:node "$GITHUB_WORKSPACE"'], "the only chown is of the workspace");
  assert.ok(!commands.some((l) => /\b(chown|chmod)\b[^\n]*RUNNER_TEMP/.test(l)), "$RUNNER_TEMP is not handed to the node user");
  assert.match(job, /if \[ "\$ALL" = true \] && \[ ! -s "\$RUNNER_TEMP\/pack\.list" \]; then[^\n]*exit 1; fi/, "a run that runs everything fails on an empty list");
  assert.match(job, /su node -s \/bin\/bash -c 'node --experimental-strip-types/, "the suites run as the image's unprivileged user");
  // The list is the pack-tool suites among the select job's (a narrow run), or all of them: nothing else narrows it.
  assert.match(job, /ALL: \$\{\{ needs\.select\.outputs\.all \}\}\n\s+NODE_LIST: \$\{\{ needs\.select\.outputs\.node \}\}/, "the list is built from the select job's outputs");
  assert.match(job, /if \[ "\$ALL" = true \]; then\n\s+su node -s \/bin\/bash -c 'node --experimental-strip-types --no-warnings scripts\/test-node\.ts --list'\n\s+else\n\s+printf '%s\\n' "\$NODE_LIST"\n\s+fi \| \{ grep -E '\^tests\/pack-\[\^\/\]\+\\.test\\.ts\$' \|\| true; \} > "\$RUNNER_TEMP\/pack\.list"/, "everything: every suite npm test runs, then only the tests/pack-*.test.ts ones; narrow: those among the select job's");
});

test("the select job decides the Python 3.11 job, and the green check needs it", () => {
  const select = jobText("select");
  assert.match(select, /py311: \$\{\{ steps\.s\.outputs\.py311 \}\}/, "select exports py311");
  assert.match(select, /\{ echo "all=true"; echo "vm=true"; echo "py311=true"; echo "node="; echo "shell="; \} >> "\$GITHUB_OUTPUT"/, "a run that runs everything runs the job (the nightly run, a run by hand, the full-ci label)");
  assert.match(select, /py311="\$\(q 's\.py311'\)"/, "a narrow run asks scripts/test-select.ts");
  assert.match(jobText("python-311"), /^ {4}needs: select\n {4}if: needs\.select\.outputs\.py311 == 'true'$/m, "the job runs when select says so");
  assert.match(jobText("green"), /^ {4}needs: \[[^\]\n]*\bpython-311\b[^\]\n]*\]$/m, "CI green needs the job");
});

test("scripts/test-select.ts asks for the Python 3.11 job for a pack, the tool library, an image file or a pack-tool suite, and for everything it does not narrow", () => {
  const layout = repoLayout();
  const packTool = layout.nodeRun.find((s) => /^tests\/pack-[^/]+\.test\.ts$/.test(s)) as string;
  assert.ok(packTool, "there are pack-tool suites");
  const yes = ["packs/cloud-forensics/tools/cloudtrail_parse/run.py", "packs/triage-collection/README.md", "tool-library/x/run.py", "images/base.Dockerfile", packTool, "scripts/vm.ts", ".github/workflows/ci.yml", "package.json"];
  for (const f of yes) assert.equal(select([f], layout).py311, true, `${f} needs the Python 3.11 job`);
  const no = ["docs/architecture.md", "changelog.d/x.md", "tests/ci-shards.test.ts", "tests/changelog.test.ts"];
  for (const f of no) {
    const s = select([f], layout);
    assert.equal(s.all, false, f);
    assert.equal(s.py311, false, `${f} does not need the Python 3.11 job (${s.reasons.join("; ")})`);
  }
  assert.equal(select([], layout).py311, false, "nothing changed");
});

test("the re-real-programs job reports and does not gate: continue-on-error is on the job, it runs only when the Python 3.11 job does, on Python 3.11, and CI green still needs it", () => {
  const job = jobText("re-real-programs");
  assert.match(job, /^ {4}continue-on-error: true$/m, "the job itself, not one step, does not fail the run");
  assert.match(job, /^ {4}if: needs\.select\.outputs\.py311 == 'true'$/m);
  assert.match(job, /actions\/setup-python@[0-9a-f]{40} # v[\d.]+\n {8}with:\n {10}python-version: "3\.11"/, "the FLOSS lock is resolved for 3.11");
  assert.match(jobText("green"), /^ {4}needs: \[[^\]\n]*\bre-real-programs\b[^\]\n]*\]$/m);
});

test("the real-libraries job runs the listed files, fails on any skipped test, and CI green needs it", () => {
  const job = jobText("real-libraries");
  assert.match(job, /^ {4}needs: select\n {4}if: needs\.select\.outputs\.all == 'true' \|\| needs\.select\.outputs\.py311 == 'true'$/m, "it runs for everything and for a change the Python 3.11 job is also asked for");
  assert.doesNotMatch(job, /continue-on-error/, "it gates: a failure fails CI green");
  assert.match(job, /apt-get install -y -q qemu-utils /, "it installs qemu-img");
  assert.match(job, /grep -hE '\^\(python-evtx\|regipy\|Pillow\|pytsk3\)[^\n]*packs\/\*\/requires\/python\.txt/, "it installs the libraries as the packs declare them, with no versions of its own");
  assert.match(job, /--test-reporter=tap \$\(grep -vE '\^\[\[:space:\]\]\*\(#\|\$\)' tests\/real-libraries\.list\)/, "it runs the files of tests/real-libraries.list");
  assert.match(jobText("green"), /^ {4}needs: \[[^\]\n]*\breal-libraries\b[^\]\n]*\]$/m, "CI green needs the job");
  // The files it runs are real test files, one a line.
  const listed = readFileSync(join(ROOT, "tests/real-libraries.list"), "utf8").split("\n").filter((l) => l.trim() && !l.startsWith("#"));
  assert.equal(listed.length, 6);
  for (const f of listed) assert.ok(readFileSync(join(ROOT, f), "utf8").length > 0, f + " is a test file");
  // The skip check is the step's own text, run here on a TAP sample with and without a skip.
  const step = job.match(/- name: Fail when any test was skipped\n {8}if: [^\n]*\n {8}run: \|\n((?: {10}[^\n]*\n)+)/);
  assert.ok(step, "the job has a step that fails on a skip");
  const script = step[1].replace(/^ {10}/gm, "");
  const dir = mkdtempSync(join(tmpdir(), "real-libraries-"));
  try {
    const run = (tap: string | null) => {
      const file = join(dir, "sample.tap");
      if (tap !== null) writeFileSync(file, tap);
      try {
        return { code: 0, out: execFileSync("bash", ["-c", script], { env: { PATH: process.env.PATH ?? "", TAP: file, RUNNER_TEMP: dir }, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }) };
      } catch (e) {
        const err = e as { status: number; stdout: string };
        return { code: err.status, out: err.stdout };
      }
    };
    const clean = "TAP version 13\n# Subtest: a\nok 1 - a\n  ---\n  duration_ms: 1\n  ...\n1..1\n# tests 1\n# skipped 0\n";
    assert.equal(run(clean).code, 0, "a run with no skip passes");
    const skipped = "TAP version 13\nok 1 - a\n  # Subtest: nested\n  ok 1 - nested b # SKIP python-evtx is not installed on this host\nok 2 - c # SKIP no lib\n1..2\n# skipped 2\n";
    const bad = run(skipped);
    assert.notEqual(bad.code, 0, "a run with a skip fails");
    assert.match(bad.out, /nested b # SKIP python-evtx is not installed/, "and names the skipped test");
    assert.match(bad.out, /ok 2 - c # SKIP/);
    assert.equal(run("TAP version 13\nok 1 - todo # TODO\n").code, 0, "a todo is not a skip");
    rmSync(join(dir, "sample.tap"));
    assert.notEqual(run(null).code, 0, "no TAP output at all fails");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
