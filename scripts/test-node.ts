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
 */
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
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

export type OwnOptions = { tier: "all" | "fast" | "deep"; filesFrom: string | null; timings: string | null; retryAlone: boolean; rest: string[] };

/** This script's own options, out of argv; the rest is for node. Throws on a bad value. */
export function ownOptions(argv: string[]): OwnOptions {
  const o: OwnOptions = { tier: "all", filesFrom: null, timings: null, retryAlone: false, rest: [] };
  for (const a of argv) {
    if (a.startsWith("--tier=")) {
      const t = a.slice("--tier=".length);
      if (t !== "all" && t !== "fast" && t !== "deep") throw new Error(`--tier takes fast, deep or all, not '${t}'`);
      o.tier = t;
    } else if (a.startsWith("--files-from=")) o.filesFrom = a.slice("--files-from=".length);
    else if (a.startsWith("--timings=")) o.timings = a.slice("--timings=".length);
    else if (a === "--retry-alone") o.retryAlone = true;
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

/** The suites a timings document says failed, relative to the repository. */
export function failedSuites(timingsJson: string, root: string = ROOT): string[] {
  const doc = JSON.parse(timingsJson) as { failed?: string[] };
  return [...new Set((doc.failed ?? []).map((f) => (isAbsolute(f) ? relative(root, f) : f).split(sep).join("/")))].sort();
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  let own: OwnOptions;
  let chosen: string[];
  try {
    own = ownOptions(process.argv.slice(2));
    const suites = nodeSuites();
    if (!suites.run.length) throw new Error("no node suites found under tests/");
    const listed = own.filesFrom === null ? null : readFileSync(own.filesFrom, "utf8").split("\n").map((l) => l.trim()).filter(Boolean);
    chosen = chooseSuites(suites.run, deepSuites(), own.tier, listed);
  } catch (err) {
    console.error(`test-node: ${(err as Error).message}`);
    process.exit(2);
  }
  if (!chosen.length) {
    console.log(`test-node: no suite to run (tier ${own.tier}${own.filesFrom ? `, ${own.filesFrom}` : ""})`);
    process.exit(0);
  }
  const scratch = own.retryAlone && !own.timings ? mkdtempSync(join(tmpdir(), "test-node-")) : null;
  const timingsFile = own.timings ?? (scratch ? join(scratch, "timings.json") : null);
  // A reporter named replaces node's default, so the default is named too.
  const reporters = timingsFile
    ? [`--test-reporter=${process.stdout.isTTY ? "spec" : "tap"}`, "--test-reporter-destination=stdout",
       `--test-reporter=${join(ROOT, "scripts", "test-timings-reporter.ts")}`, `--test-reporter-destination=${timingsFile}`]
    : [];
  const options = nodeTestOptions(own.rest);
  const r = spawnSync(process.execPath, ["--experimental-strip-types", "--test", ...reporters, ...options, ...chosen], { cwd: ROOT, stdio: "inherit" });
  if (r.error) {
    console.error(`test-node: ${r.error.message}`);
    process.exit(2);
  }
  let status = r.status ?? 1;
  if (own.retryAlone && status !== 0 && timingsFile && existsSync(timingsFile)) {
    const failed = failedSuites(readFileSync(timingsFile, "utf8"));
    const alone: string[] = [];
    const still: string[] = [];
    for (const file of failed) {
      console.log(`\ntest-node: ${file} failed with others; running it alone`);
      const again = spawnSync(process.execPath, ["--experimental-strip-types", "--test", "--test-concurrency=1", ...nodeTestOptions(own.rest.filter((a) => !a.startsWith("--test-shard") && !a.startsWith("--test-concurrency"))), file], { cwd: ROOT, stdio: "inherit" });
      (again.status === 0 ? alone : still).push(file);
    }
    console.log("\ntest-node: retried alone");
    for (const f of alone) console.log(`  passed alone (load-sensitive): ${f}`);
    for (const f of still) console.log(`  failed alone too: ${f}`);
    if (failed.length && !still.length) status = 3;
  }
  if (scratch) rmSync(scratch, { recursive: true, force: true });
  process.exit(status);
}
