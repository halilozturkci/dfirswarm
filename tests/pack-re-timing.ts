/**
 * Timing checks that hold on a noisy runner. A linearity test compares the time of a text with the time of one four times as long: linear code
 * takes four times as much (a runner has been seen at 5.8), a quadratic rule sixteen times. A single pair of measurements on a shared runner
 * misses by more than that, so the test (1) measures CPU time, (2) runs every one of its rounds (three by default) and takes, for each text, the
 * MEDIAN of its rounds, and (3) allows LINEAR_BOUND times the shorter time, which is never taken as less than LINEAR_FLOOR seconds (a base of a few
 * hundredths of a second is all noise). The absolute bound on the longer text is for a rule that is slow at every size.
 *
 * The median is what keeps a quadratic rule from passing on one lucky round: the helper used to stop at the first round that looked linear, so a
 * quadratic rule whose first round was fast by noise was judged on that round alone. With every round run, the lucky round is one of three and the
 * median is the typical one; a linear rule with one noisy round keeps a typical median too. A text that was not measured in at least half of the
 * rounds (a ladder stops a round at its first step that is not linear) has no time, and the ladder fails.
 */
export const LINEAR_BOUND = 8;
export const LINEAR_FLOOR = 0.05;
export const LINEAR_ABSOLUTE = 5;

export const linearOk = (small: number, large: number): boolean => large <= LINEAR_BOUND * Math.max(small, LINEAR_FLOOR);

/** The median of a text's rounds (the upper one when their number is even); a round that did not measure it (null) counts as infinitely slow, so a text measured in fewer than half of the rounds has none (null). */
export const medianTime = (samples: (number | null)[]): number | null => {
  const sorted = samples.map((s) => (s === null ? Infinity : s)).sort((a, b) => a - b);
  const v = sorted[Math.floor(sorted.length / 2)];
  return v === undefined || !Number.isFinite(v) ? null : v;
};

/** What `growth` and `ladder` return, from the rounds' times (one row per round, one column per text): the median of each text. The same rule as the Python below. */
export const growthOf = (rounds: (number | null)[][]): (number | null)[] => (rounds[0] ?? []).map((_, i) => medianTime(rounds.map((r) => r[i] ?? null)));

const MEDIAN_PY = [
  "def median_time(samples):",
  "    s = sorted(float('inf') if x is None else x for x in samples)",
  "    v = s[len(s) // 2] if s else float('inf')",
  "    return None if v == float('inf') else v",
].join("\n");

/**
 * Python source for the same: `growth(f, texts, tries=3, clock=None)` runs every round (it does not stop at one that looks linear) and returns the
 * median CPU time of each text. `clock` is for a test that injects the times. Needs `time` imported.
 */
export const GROWTH_PY = [
  `LINEAR_BOUND, LINEAR_FLOOR = ${LINEAR_BOUND}, ${LINEAR_FLOOR}`,
  MEDIAN_PY,
  "def growth(f, texts, tries=3, clock=None):",
  "    clock = clock or time.process_time",
  "    rounds = []",
  "    for _ in range(tries):",
  "        row = []",
  "        for t in texts:",
  "            start = clock()",
  "            f(t)",
  "            row.append(clock() - start)",
  "        rounds.append(row)",
  "    return [median_time([r[i] for r in rounds]) for i in range(len(texts))]",
].join("\n");

/**
 * The same for a ladder of sizes, each four times the one before: every step must be linear by `linearOk`. A size that was never measured (null: the
 * ladder stopped at the step before it, see LADDER_PY, in at least half of the rounds) fails.
 */
export const ladderOk = (times: (number | null)[]): boolean => times.every((t, i) => t !== null && (i === 0 || linearOk(times[i - 1] as number, t)));

/**
 * Python source for a ladder: `ladder(f, texts, tries=3, clock=None)` runs every round and returns the median CPU time of each text. The texts are
 * measured from the shortest; a round stops at the first step that is not linear, so the longer texts of a rule that is quadratic are never run (their
 * time is None) and a test fails in seconds, not in the minutes the longest text would take. Because every round is run, a quadratic rule is not
 * judged on its luckiest round: a text that only one round reached has no median.
 * Needs `time` imported; `f` must reset whatever state it caches between calls.
 */
export const LADDER_PY = [
  `LINEAR_BOUND, LINEAR_FLOOR = ${LINEAR_BOUND}, ${LINEAR_FLOOR}`,
  MEDIAN_PY,
  "def ladder_ok(best):",
  "    return None not in best and all(best[i] <= LINEAR_BOUND * max(best[i - 1], LINEAR_FLOOR) for i in range(1, len(best)))",
  "def ladder(f, texts, tries=3, clock=None):",
  "    clock = clock or time.process_time",
  "    rounds = []",
  "    for _ in range(tries):",
  "        row = [None] * len(texts)",
  "        for i, t in enumerate(texts):",
  "            start = clock()",
  "            f(t)",
  "            row[i] = clock() - start",
  "            if i and row[i] > LINEAR_BOUND * max(row[i - 1], LINEAR_FLOOR):",
  "                break",
  "        rounds.append(row)",
  "    return [median_time([r[i] for r in rounds]) for i in range(len(texts))]",
].join("\n");
