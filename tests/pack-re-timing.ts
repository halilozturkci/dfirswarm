/**
 * Timing checks that hold on a noisy runner. A linearity test compares the time of a text with the time of one four times as long: linear code
 * takes four times as much (a runner has been seen at 5.8), a quadratic rule sixteen times. A single pair of measurements on a shared runner
 * misses by more than that, so the test (1) measures CPU time, (2) takes the least of up to three rounds, and stops at the first round that
 * passes, and (3) allows LINEAR_BOUND times the shorter time, which is never taken as less than LINEAR_FLOOR seconds (a base of a few
 * hundredths of a second is all noise). The absolute bound on the longer text is for a rule that is slow at every size.
 */
export const LINEAR_BOUND = 8;
export const LINEAR_FLOOR = 0.05;
export const LINEAR_ABSOLUTE = 5;

export const linearOk = (small: number, large: number): boolean => large <= LINEAR_BOUND * Math.max(small, LINEAR_FLOOR);

/** Python source for the same: `growth(f, texts)` returns the least CPU time of each text over up to three rounds, stopping when the last is linear in the first. */
export const GROWTH_PY = [
  `LINEAR_BOUND, LINEAR_FLOOR = ${LINEAR_BOUND}, ${LINEAR_FLOOR}`,
  "def growth(f, texts, tries=3):",
  "    best = [None] * len(texts)",
  "    for _ in range(tries):",
  "        for i, t in enumerate(texts):",
  "            start = time.process_time()",
  "            f(t)",
  "            took = time.process_time() - start",
  "            best[i] = took if best[i] is None else min(best[i], took)",
  "        if best[-1] <= LINEAR_BOUND * max(best[0], LINEAR_FLOOR):",
  "            break",
  "    return best",
].join("\n");

/**
 * The same for a ladder of sizes, each four times the one before: every step must be linear by `linearOk`. A size that was never measured (null: the
 * ladder stopped at the step before it, see LADDER_PY) fails.
 */
export const ladderOk = (times: (number | null)[]): boolean => times.every((t, i) => t !== null && (i === 0 || linearOk(times[i - 1] as number, t)));

/**
 * Python source for a ladder: `ladder(f, texts)` returns the least CPU time of each text over up to three rounds, stopping at the first round in which every
 * step to the next text is linear (`ladder_ok`). The texts are measured from the shortest; a round stops at the first step that is not linear, so the longer
 * texts of a rule that is quadratic are never run (their time is None) and a test fails in seconds, not in the minutes the longest text would take.
 * Needs `time` imported; `f` must reset whatever state it caches between calls.
 */
export const LADDER_PY = [
  `LINEAR_BOUND, LINEAR_FLOOR = ${LINEAR_BOUND}, ${LINEAR_FLOOR}`,
  "def ladder_ok(best):",
  "    return None not in best and all(best[i] <= LINEAR_BOUND * max(best[i - 1], LINEAR_FLOOR) for i in range(1, len(best)))",
  "def ladder(f, texts, tries=3):",
  "    best = [None] * len(texts)",
  "    for _ in range(tries):",
  "        for i, t in enumerate(texts):",
  "            start = time.process_time()",
  "            f(t)",
  "            took = time.process_time() - start",
  "            best[i] = took if best[i] is None else min(best[i], took)",
  "            if i and best[i] > LINEAR_BOUND * max(best[i - 1], LINEAR_FLOOR):",
  "                break",
  "        if ladder_ok(best):",
  "            break",
  "    return best",
].join("\n");
