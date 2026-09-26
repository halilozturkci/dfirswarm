import type { ChangeKind } from "./types.ts";

/**
 * Which changes can move the finish line.
 *
 * A goal's `## Checks` are shell commands the operator wrote, run in the
 * sandbox, so nearly anything under it can change their answer: a report
 * under `work/`, the sentinel under `done/`, the board a sign-off is posted
 * to, the trace an `inputs_check` line lands on, the ledger a timeline is
 * counted from, `team.json` the hello goal reads every id out of. The
 * shipped goals alone read five of those. So this is a list of what a check
 * cannot read rather than a guess at what it can: a lease landing and a
 * turn's spend fold, which are also the two most frequent changes in a
 * running swarm, and a VM run's hub status, which lives outside the sandbox
 * where no check runs. The server's own cache is what bounds how often the
 * checks can actually run; this only keeps the console from asking for nothing.
 */
export const CHECKS_IGNORED_KINDS: readonly ChangeKind[] = ["locks", "budget", "hub"];

/** Every kind a client is told about; mirrors `ChangeKind` in `types.ts`. */
export const ALL_CHANGE_KINDS: readonly ChangeKind[] = [
  "registry",
  "threads",
  "locks",
  "done",
  "budget",
  "events",
  "history",
  "work",
  "team",
  "tools",
  "ledger",
  "names",
  "inputs",
  "contract",
  "store",
  "hub",
  "other",
];

/** The kinds the finish line refetches on: everything a check could read. */
export const CHECKS_CHANGE_KINDS: readonly ChangeKind[] = ALL_CHANGE_KINDS.filter(
  (kind) => !CHECKS_IGNORED_KINDS.includes(kind),
);

/** Whether a burst carrying these kinds could have changed a check's answer. */
export function shouldReloadChecks(kinds: readonly string[]): boolean {
  return kinds.some((kind) => (CHECKS_CHANGE_KINDS as readonly string[]).includes(kind));
}
