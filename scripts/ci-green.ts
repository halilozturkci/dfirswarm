/**
 * The decision of the `CI green` job (the one check main's ruleset requires).
 *
 *   node --experimental-strip-types scripts/ci-green.ts --needs-env NEEDS --jobs-from-gh OWNER/REPO RUN_ID ATTEMPT
 *   node --experimental-strip-types scripts/ci-green.ts --needs FILE --jobs FILE [--now ISO]   (one look, no waiting)
 *
 * The jobs `green` needs pass on success or skipped only. The macOS parts are not needed
 * (a queued job on the owner's Mac would hold every pull request), so they are read from
 * this run attempt's own job list:
 *
 *   - a part completed with failure, cancelled, timed_out or action_required fails green;
 *   - a part completed with success, skipped or neutral passes;
 *   - a part in progress is waited for, up to its own time limit (node parts 90 minutes,
 *     shell parts 55, ci.yml): one past it fails, since GitHub would have cut it;
 *   - a part not started (queued, waiting, pending) is waited for up to the grace period,
 *     then passes with a notice naming it, so a Mac that is off does not block a merge.
 *
 * `evaluate` is pure (the tests run its table); `main` polls the jobs list.
 */
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

export const MACOS_PREFIX = "macOS · ";
export const GRACE_MINUTES = 15;
export const NODE_PART_MINUTES = 90;
export const SHELL_PART_MINUTES = 55;

export type Needs = Record<string, { result?: string }>;
export type Job = { name: string; status: string; conclusion?: string | null; started_at?: string | null; created_at?: string | null };
export type Verdict = {
  /** pass: green may succeed; fail: it must fail; wait: look again. */
  verdict: "pass" | "fail" | "wait";
  lines: string[];
  notices: string[];
};

const FAILED = new Set(["failure", "cancelled", "timed_out", "action_required", "startup_failure", "stale"]);
const PASSED = new Set(["success", "skipped", "neutral"]);
const NOT_STARTED = new Set(["queued", "waiting", "pending", "requested"]);

/** The limit of a macOS part in minutes: the node parts have 90, the shell parts 55 (ci.yml `timeout-minutes`). */
export function partLimitMinutes(name: string): number {
  return /node tests/.test(name) ? NODE_PART_MINUTES : SHELL_PART_MINUTES;
}

/**
 * @param waitedMs how long green has already waited for the parts, which is how a part that has not started is told
 *   from one that never will. `now` is the moment of the look.
 */
export function evaluate(needs: Needs, jobs: Job[], now: Date, waitedMs: number, graceMs: number = GRACE_MINUTES * 60_000): Verdict {
  const lines: string[] = [];
  const notices: string[] = [];
  let failed = false;
  let waiting = false;

  for (const [name, n] of Object.entries(needs).sort(([a], [b]) => a.localeCompare(b))) {
    const ok = n.result === "success" || n.result === "skipped";
    lines.push(`${n.result}\t${name}`);
    if (!ok) failed = true;
  }

  // A re-run attempt lists each job once; if a name still repeats, the last entry is the live one.
  const parts = new Map<string, Job>();
  for (const j of jobs) if (j.name.startsWith(MACOS_PREFIX)) parts.set(j.name, j);

  for (const [name, j] of [...parts].sort(([a], [b]) => a.localeCompare(b))) {
    const conclusion = j.conclusion ?? "";
    if (j.status === "completed") {
      lines.push(`${conclusion}\t${name}`);
      if (FAILED.has(conclusion)) failed = true;
      else if (!PASSED.has(conclusion)) {
        failed = true;
        lines.push(`  (unknown conclusion "${conclusion}" is not read as a pass)`);
      }
    } else if (j.status === "in_progress") {
      const started = Date.parse(j.started_at ?? "");
      const limitMs = partLimitMinutes(name) * 60_000;
      if (Number.isFinite(started) && now.getTime() - started > limitMs) {
        lines.push(`in_progress past its ${partLimitMinutes(name)} minutes\t${name}`);
        failed = true;
      } else {
        lines.push(`in_progress\t${name}`);
        waiting = true;
      }
    } else if (NOT_STARTED.has(j.status)) {
      if (waitedMs >= graceMs) {
        lines.push(`${j.status}, not started after ${Math.round(graceMs / 60_000)} minutes\t${name}`);
        notices.push(`${name} had not started after ${Math.round(graceMs / 60_000)} minutes (${j.status}); CI green does not wait for it`);
      } else {
        lines.push(`${j.status}\t${name}`);
        waiting = true;
      }
    } else {
      lines.push(`${j.status}\t${name}`);
      failed = true;
    }
  }
  if (parts.size === 0) lines.push("(no macOS part in this run attempt)");

  // A failure is final even while another part still runs.
  if (failed) return { verdict: "fail", lines, notices };
  if (waiting) return { verdict: "wait", lines, notices };
  return { verdict: "pass", lines, notices };
}

function listJobs(repo: string, runId: string, attempt: string): Job[] {
  const out = execFileSync("gh", ["api", `repos/${repo}/actions/runs/${runId}/attempts/${attempt}/jobs`, "--paginate", "--jq", ".jobs[]"], {
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
  });
  return out.split("\n").filter(Boolean).map((l) => JSON.parse(l) as Job);
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function main(argv: string[]): Promise<number> {
  const arg = (flag: string): string | undefined => {
    const i = argv.indexOf(flag);
    return i >= 0 ? argv[i + 1] : undefined;
  };
  const needsRaw = arg("--needs-env") ? (process.env[arg("--needs-env")!] ?? "") : readFileSync(arg("--needs")!, "utf8");
  const needs = JSON.parse(needsRaw) as Needs;
  const graceMs = Number(arg("--grace-minutes") ?? GRACE_MINUTES) * 60_000;
  const pollMs = Number(arg("--poll-seconds") ?? 30) * 1000;

  // One look from files: for the tests and for a hand check.
  if (arg("--jobs")) {
    const jobs = JSON.parse(readFileSync(arg("--jobs")!, "utf8")) as Job[];
    const now = arg("--now") ? new Date(arg("--now")!) : new Date();
    const waited = Number(arg("--waited-minutes") ?? 0) * 60_000;
    const v = evaluate(needs, jobs, now, waited, graceMs);
    console.log(v.lines.join("\n"));
    for (const n of v.notices) console.log(`::notice::${n}`);
    return v.verdict === "pass" ? 0 : v.verdict === "fail" ? 1 : 2;
  }

  const gh = argv.indexOf("--jobs-from-gh");
  if (gh < 0) {
    console.error("usage: ci-green.ts --needs-env NAME|--needs FILE (--jobs FILE | --jobs-from-gh OWNER/REPO RUN_ID ATTEMPT)");
    return 2;
  }
  const [repo, runId, attempt] = [argv[gh + 1]!, argv[gh + 2]!, argv[gh + 3]!];
  const begun = Date.now();
  // The longest a part may run, plus the grace: green's own timeout-minutes covers this.
  const capMs = (NODE_PART_MINUTES * 60_000) + graceMs + 5 * 60_000;
  for (;;) {
    let v: Verdict;
    try {
      v = evaluate(needs, listJobs(repo, runId, attempt), new Date(), Date.now() - begun, graceMs);
    } catch (e) {
      // A failed listing is no pass: look again, and fail when the cap is reached.
      console.log(`could not list the jobs: ${(e as Error).message.split("\n")[0]}`);
      if (Date.now() - begun > capMs) return 1;
      await sleep(pollMs);
      continue;
    }
    if (v.verdict !== "wait") {
      console.log(v.lines.join("\n"));
      for (const n of v.notices) console.log(`::notice::${n}`);
      return v.verdict === "pass" ? 0 : 1;
    }
    if (Date.now() - begun > capMs) {
      console.log(v.lines.join("\n"));
      console.log("a macOS part is still running past every limit it has");
      return 1;
    }
    await sleep(pollMs);
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main(process.argv.slice(2)).then((code) => process.exit(code), (e) => {
    console.error(e);
    process.exit(1);
  });
}
