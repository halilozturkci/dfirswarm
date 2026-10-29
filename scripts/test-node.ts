/**
 * `npm test`: every node suite under tests/ (`*.test.ts` at any depth, the
 * fixtures aside), found rather than listed. A new suite needs no edit
 * anywhere, and two branches that each add one no longer both rewrite the one
 * line of package.json that used to name them all.
 *
 * The suites `npm test` must not run are named in tests/node-tests.skip, one
 * path per line, each with its reason. A path there that no longer exists
 * fails the run, so the list cannot go stale.
 *
 *   node --experimental-strip-types scripts/test-node.ts [node --test options…]
 *
 * Options are handed to `node --test` before the files
 * (`npm test -- --test-name-pattern=…`).
 *
 * Every test and hook gets TEST_TIMEOUT_MS (`--test-timeout`) unless the
 * options set their own: a test that waits forever fails by name in
 * minutes, rather than holding the run until CI's job limit cancels it with
 * no word of which test it was.
 *
 * The deep suites (tests/node-tests.deep) run apart, in a second `node
 * --test` after the others, under DEEP_TIMEOUT_MS: Node 22 holds a whole
 * file to the timeout, and a deep file that takes two minutes alone can take
 * three times that on a loaded runner.
 *
 * Its own options, taken out before the rest go to node:
 *
 *   --tier=fast|deep|all  tests/node-tests.deep names the deep suites (the
 *                         long hardening ones: canaries, fuzz, worst-case
 *                         inputs); fast runs the others, deep only those,
 *                         all (the default) every suite.
 *   --files-from=FILE     only the suites FILE names, one path per line (as
 *                         scripts/test-select.ts prints them); a path that is
 *                         no suite is refused. An empty FILE runs nothing.
 *   --timings=FILE        how long each suite file took, and which failed,
 *                         as JSON (scripts/test-timings-reporter.ts), beside
 *                         the usual output.
 *   --retry-alone         each file that failed is run again alone (one file
 *                         at a time) and said to have passed or failed so.
 *                         Exit 3 when every failure passed alone: green under
 *                         no load only, which is named, never taken for 0.
 *   --test-shard=I/N      shard I of N, cut here rather than by node: the
 *                         others and the deep suites are each dealt out
 *                         round-robin in sorted order (node's own rule), so
 *                         every suite is in one shard and the deep ones are
 *                         spread evenly over the shards.
 *   --list                print the suites the run would run, one per line,
 *                         in the order it runs them, and run nothing.
 */
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(fileURLToPath(new URL("..", import.meta.url)));

/** The skip list: `<path relative to the repo>  # why`, blank lines and `#` lines ignored. */
export function readSkipList(text: string): string[] {
  return text.split("\n").map((line) => line.replace(/#.*$/, "").trim()).filter(Boolean);
}

/**
 * The `--test-timeout` `npm test` runs under. Node 24 reads it per test and
 * per hook: a test that waits on something that never comes fails by name
 * after it, instead of holding the run until the CI job's own limit cancels
 * it unnamed (tests/vm-hub.test.ts did, twice, on the 20-minute Node 24
 * job). Node 22 (the host's, and the engines floor) also holds each whole
 * suite file to it, and fails the file by name. So it sits well above the
 * slowest file, not only the slowest test: on a hosted runner the slowest
 * test takes about 30 s and the slowest files (ui-server, vm-hub) up to
 * about 75 s on macOS.
 */
export const TEST_TIMEOUT_MS = 300_000;

/**
 * The `--test-timeout` the deep suites run under, apart from the others. In
 * #233's run on the hosted macOS runner, pack-triage-slots and
 * pack-virtualization-boundary (112 s and 126 s in other runs) were cut off at
 * 300 s with no test failed, and on the owner's Mac mini at concurrency 3
 * four more were. Fifteen minutes is past the slowest of them slowed five
 * times over, and a hang still fails by name well inside the node jobs' limits.
 */
export const DEEP_TIMEOUT_MS = 900_000;

/** The options handed to `node --test`: the caller's, led by the per-test timeout unless they set one. */
export function nodeTestOptions(argv: string[], timeoutMs: number = TEST_TIMEOUT_MS): string[] {
  const own = argv.some((a) => a === "--test-timeout" || a.startsWith("--test-timeout="));
  return own ? [...argv] : [`--test-timeout=${timeoutMs}`, ...argv];
}

/** The node suites `npm test` runs, sorted, and the skip list's paths; throws on a skip entry that names no suite. */
export function nodeSuites(root: string = ROOT): { run: string[]; skipped: string[] } {
  const tests = join(root, "tests");
  const found = (readdirSync(tests, { recursive: true }) as string[])
    .filter((p) => p.endsWith(".test.ts") && !p.split(sep).includes("fixtures"))
    .map((p) => relative(root, join(tests, p)).split(sep).join("/"))
    .sort();
  const listFile = join(tests, "node-tests.skip");
  const skipped = existsSync(listFile) ? readSkipList(readFileSync(listFile, "utf8")) : [];
  const stale = skipped.filter((p) => !found.includes(p));
  if (stale.length) throw new Error(`tests/node-tests.skip names ${stale.join(", ")}, which no node suite is: remove the line`);
  return { run: found.filter((p) => !skipped.includes(p)), skipped };
}

/** The deep list (tests/node-tests.deep), same form as the skip list; throws on an entry that names no suite. */
export function deepSuites(root: string = ROOT): string[] {
  const listFile = join(root, "tests", "node-tests.deep");
  const deep = existsSync(listFile) ? readSkipList(readFileSync(listFile, "utf8")) : [];
  const { run } = nodeSuites(root);
  const stale = deep.filter((p) => !run.includes(p));
  if (stale.length) throw new Error(`tests/node-tests.deep names ${stale.join(", ")}, which no suite npm test runs is: remove the line`);
  return deep;
}

export type Shard = { index: number; total: number };

export type OwnOptions = {
  tier: "all" | "fast" | "deep";
  filesFrom: string | null;
  timings: string | null;
  retryAlone: boolean;
  shard: Shard | null;
  list: boolean;
  rest: string[];
};

/** `I/N` as node reads `--test-shard`: whole numbers, 1 <= I <= N. Throws on anything else. */
function parseShard(v: string | undefined): Shard {
  const m = /^(\d+)\/(\d+)$/.exec(v ?? "");
  const index = m ? Number(m[1]) : 0;
  const total = m ? Number(m[2]) : 0;
  if (!m || index < 1 || index > total) throw new Error(`--test-shard takes I/N with 1 <= I <= N, not '${v ?? ""}'`);
  return { index, total };
}

/** This script's own options, out of argv; the rest is for node. Throws on a bad value. */
export function ownOptions(argv: string[]): OwnOptions {
  const o: OwnOptions = { tier: "all", filesFrom: null, timings: null, retryAlone: false, shard: null, list: false, rest: [] };
  for (let k = 0; k < argv.length; k++) {
    const a = argv[k];
    if (a.startsWith("--tier=")) {
      const t = a.slice("--tier=".length);
      if (t !== "all" && t !== "fast" && t !== "deep") throw new Error(`--tier takes fast, deep or all, not '${t}'`);
      o.tier = t;
    } else if (a.startsWith("--files-from=")) o.filesFrom = a.slice("--files-from=".length);
    else if (a.startsWith("--timings=")) o.timings = a.slice("--timings=".length);
    else if (a === "--retry-alone") o.retryAlone = true;
    else if (a === "--list") o.list = true;
    else if (a.startsWith("--test-shard=")) o.shard = parseShard(a.slice("--test-shard=".length));
    else if (a === "--test-shard") o.shard = parseShard(argv[++k]);
    else o.rest.push(a);
  }
  return o;
}

/** The suites to run: npm test's, cut to a tier and to a list. Throws on a listed path that is no suite. */
export function chooseSuites(run: string[], deep: string[], tier: OwnOptions["tier"], listed: string[] | null): string[] {
  let chosen = run;
  if (tier === "fast") chosen = chosen.filter((p) => !deep.includes(p));
  if (tier === "deep") chosen = chosen.filter((p) => deep.includes(p));
  if (listed) {
    const unknown = listed.filter((p) => !run.includes(p));
    if (unknown.length) throw new Error(`--files-from names ${unknown.join(", ")}, which no suite npm test runs is`);
    chosen = chosen.filter((p) => listed.includes(p));
  }
  return chosen;
}

export type Pass = { name: "others" | "deep"; files: string[]; timeoutMs: number };

/**
 * The chosen suites as the runs they go in, in order: the others under
 * TEST_TIMEOUT_MS, then the deep ones under DEEP_TIMEOUT_MS, each cut to the
 * shard (round-robin over the sorted list, as node's --test-shard does). A
 * run left with no file is dropped.
 */
export function passes(chosen: string[], deep: string[], shard: Shard | null): Pass[] {
  const cut = (files: string[]) => (shard ? [...files].sort().filter((_, k) => k % shard.total === shard.index - 1) : files);
  const all: Pass[] = [
    { name: "others", files: cut(chosen.filter((p) => !deep.includes(p))), timeoutMs: TEST_TIMEOUT_MS },
    { name: "deep", files: cut(chosen.filter((p) => deep.includes(p))), timeoutMs: DEEP_TIMEOUT_MS },
  ];
  return all.filter((p) => p.files.length);
}

/** Timings documents of runs one after another as one: every file, slowest first, and every failed file. */
export function mergeTimings(docs: string[]): string {
  const parsed = docs.map((d) => JSON.parse(d) as { files?: { ms: number }[]; failed?: string[] });
  const files = parsed.flatMap((d) => d.files ?? []).sort((a, b) => b.ms - a.ms);
  return JSON.stringify({ files, failed: parsed.flatMap((d) => d.failed ?? []) }, null, 1) + "\n";
}

/** The status of runs one after another: any failure over passed-alone (3) over 0. */
export function worse(a: number, b: number): number {
  if (a === 0) return b;
  if (b === 0) return a;
  return a === 3 ? b : a;
}

/** The suites a timings document says failed, relative to the repository. */
export function failedSuites(timingsJson: string, root: string = ROOT): string[] {
  const doc = JSON.parse(timingsJson) as { failed?: string[] };
  return [...new Set((doc.failed ?? []).map((f) => (isAbsolute(f) ? relative(root, f) : f).split(sep).join("/")))].sort();
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  let own: OwnOptions;
  let chosen: string[];
  let runs: Pass[];
  try {
    own = ownOptions(process.argv.slice(2));
    const suites = nodeSuites();
    if (!suites.run.length) throw new Error("no node suites found under tests/");
    const listed = own.filesFrom === null ? null : readFileSync(own.filesFrom, "utf8").split("\n").map((l) => l.trim()).filter(Boolean);
    const deep = deepSuites();
    chosen = chooseSuites(suites.run, deep, own.tier, listed);
    runs = passes(chosen, deep, own.shard);
  } catch (err) {
    console.error(`test-node: ${(err as Error).message}`);
    process.exit(2);
  }
  // The process ends by itself, with this status, rather than by
  // process.exit(): to a pipe stdout is written asynchronously, and an exit
  // straight after a long write cuts it short (the --list of a loaded CI
  // runner was, at 184 of 353 lines).
  if (own.list) process.stdout.write(runs.flatMap((run) => run.files).map((f) => `${f}\n`).join(""));
  else process.exitCode = runAll(own, chosen, runs);
}

/** Each run in turn, with its retries; the status of them all. */
function runAll(own: OwnOptions, chosen: string[], runs: Pass[]): number {
  if (!runs.length) {
    const shard = own.shard ? `, shard ${own.shard.index}/${own.shard.total} of ${chosen.length}` : "";
    console.log(`test-node: no suite to run (tier ${own.tier}${own.filesFrom ? `, ${own.filesFrom}` : ""}${shard})`);
    return 0;
  }
  const scratch = own.retryAlone || own.timings ? mkdtempSync(join(tmpdir(), "test-node-")) : null;
  const docs: string[] = [];
  let status = 0;
  for (const run of runs) {
    const options = nodeTestOptions(own.rest, run.timeoutMs);
    if (run.name === "deep") {
      const limit = options.find((a) => a.startsWith("--test-timeout=")) ?? "the --test-timeout given";
      console.log(`\ntest-node: the ${run.files.length} deep suite(s) of tests/node-tests.deep, apart, under ${limit}`);
    }
    const timingsFile = scratch ? join(scratch, `${run.name}.json`) : null;
    // A reporter named replaces node's default, so the default is named too.
    const reporters = timingsFile
      ? [`--test-reporter=${process.stdout.isTTY ? "spec" : "tap"}`, "--test-reporter-destination=stdout",
         `--test-reporter=${join(ROOT, "scripts", "test-timings-reporter.ts")}`, `--test-reporter-destination=${timingsFile}`]
      : [];
    const r = spawnSync(process.execPath, ["--experimental-strip-types", "--test", ...reporters, ...options, ...run.files], { cwd: ROOT, stdio: "inherit" });
    if (r.error) {
      console.error(`test-node: ${r.error.message}`);
      if (scratch) rmSync(scratch, { recursive: true, force: true });
      return 2;
    }
    let runStatus = r.status ?? 1;
    const doc = timingsFile && existsSync(timingsFile) ? readFileSync(timingsFile, "utf8") : null;
    if (doc) docs.push(doc);
    if (own.retryAlone && runStatus !== 0 && doc) {
      const failed = failedSuites(doc);
      const alone: string[] = [];
      const still: string[] = [];
      for (const file of failed) {
        console.log(`\ntest-node: ${file} failed with others; running it alone`);
        const again = spawnSync(process.execPath, ["--experimental-strip-types", "--test", "--test-concurrency=1", ...nodeTestOptions(own.rest.filter((a) => !a.startsWith("--test-concurrency")), run.timeoutMs), file], { cwd: ROOT, stdio: "inherit" });
        (again.status === 0 ? alone : still).push(file);
      }
      console.log("\ntest-node: retried alone");
      for (const f of alone) console.log(`  passed alone (load-sensitive): ${f}`);
      for (const f of still) console.log(`  failed alone too: ${f}`);
      if (failed.length && !still.length) runStatus = 3;
    }
    status = worse(status, runStatus);
  }
  if (own.timings && docs.length) writeFileSync(own.timings, mergeTimings(docs));
  if (scratch) rmSync(scratch, { recursive: true, force: true });
  return status;
}
