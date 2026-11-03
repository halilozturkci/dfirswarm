/**
 * The shared growth helper (tests/pack-re-timing.ts) judges over all its rounds. It used to stop at the first round that looked linear, so a
 * quadratic rule whose first round was fast by noise passed on that round alone. These cases inject the times (no clock is read), so they say what
 * the helper does with a lucky round, not how fast the machine is.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { test } from "node:test";
import { GROWTH_PY, LADDER_PY, growthOf, ladderOk, linearOk, medianTime } from "./pack-re-timing.ts";

/** Run `growth` or `ladder` in Python with a clock that yields the given durations in order (one per text per round), and say how many times f ran. */
function run(kind: "growth" | "ladder", rounds: number[][], tries = rounds.length): { times: (number | null)[]; calls: number } {
  const source = [
    "import json, time",
    kind === "growth" ? GROWTH_PY : LADDER_PY,
    `d = iter(${JSON.stringify(rounds.flat())})`,
    "state = {'t': 0.0, 'n': 0, 'calls': 0}",
    "def clock():",
    "    state['n'] += 1",
    "    if state['n'] % 2 == 0:",
    "        state['t'] += next(d)",
    "    return state['t']",
    "def f(text):",
    "    state['calls'] += 1",
    `times = ${kind}(f, ['a', 'b', 'c', 'd', 'e'][:${rounds[0]!.length}], ${tries}, clock)`,
    "print(json.dumps({'times': times, 'calls': state['calls']}))",
  ].join("\n");
  const r = spawnSync("python3", ["-c", source], { encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
  return JSON.parse(r.stdout) as { times: (number | null)[]; calls: number };
}

test("a quadratic rule whose first round looks linear by noise is not linear: the helper runs every round and judges the median", () => {
  // Round 1: 0.5 s and 2.0 s (a ratio of 4, as a linear rule shows). Rounds 2 and 3: 0.5 s and 8.0 s (a ratio of 16, a quadratic rule).
  const rounds = [[0.5, 2.0], [0.5, 8.0], [0.5, 8.0]];
  const g = run("growth", rounds);
  assert.equal(g.calls, 6, "every round runs, whether or not the first looked linear");
  assert.deepEqual(g.times, [0.5, 8.0]);
  assert.equal(linearOk(g.times[0]!, g.times[1]!), false, "reported not linear");
  assert.deepEqual(growthOf(rounds), g.times, "the TypeScript rule is the Python rule");
  // The old rule (stop at the first round that passes, keep each text's least time) said linear for the same times.
  const oldLeast = [Math.min(...rounds.map((r) => r[0]!)), Math.min(...rounds.map((r) => r[1]!))];
  assert.equal(linearOk(oldLeast[0]!, oldLeast[1]!), true, "the least of the rounds is the lucky one: that is what let it pass");
});

test("a linear rule with one noisy round is linear, whichever text the noise falls on", () => {
  const noisyLarge = [[0.5, 2.0], [0.5, 2.0], [0.5, 9.0]];
  const noisySmall = [[0.5, 2.0], [3.0, 2.0], [0.5, 2.0]];
  for (const rounds of [noisyLarge, noisySmall]) {
    const g = run("growth", rounds);
    assert.equal(linearOk(g.times[0]!, g.times[1]!), true, JSON.stringify(g.times));
    assert.deepEqual(growthOf(rounds), g.times);
  }
});

test("a ladder: a quadratic rule whose first round is fully linear is not, because its other rounds stop at the step that is not and the longest text has no median", () => {
  // Three sizes. Round 1 looks linear all the way; rounds 2 and 3 stop at the second size (1.6 s against 0.1 s) and never run the third.
  const rounds = [[0.1, 0.4, 1.6], [0.1, 1.6], [0.1, 1.6]];
  const l = run("ladder", rounds.map((r) => r.slice()), 3);
  assert.equal(l.calls, 3 + 2 + 2, "a round stops at its first step that is not linear");
  assert.deepEqual(l.times.map((t) => (t === null ? t : Math.round(t * 1e6) / 1e6)), [0.1, 1.6, null]);
  assert.equal(ladderOk(l.times), false);
  // A ladder that is linear in every round is linear, and with one noisy round still is.
  const linear = run("ladder", [[0.1, 0.4, 1.6], [0.1, 0.4, 1.6], [0.1, 0.4, 1.6]]);
  assert.equal(linear.calls, 9, "a linear ladder runs every round too");
  assert.equal(ladderOk(linear.times), true, JSON.stringify(linear.times));
  const noisy = run("ladder", [[0.1, 0.4, 1.6], [0.1, 0.4, 1.6], [0.1, 0.4, 9.0]]);
  assert.equal(ladderOk(noisy.times), true, JSON.stringify(noisy.times));
});

test("medianTime: the middle round, the upper middle for an even number, and none for a text most rounds did not measure", () => {
  assert.equal(medianTime([3, 1, 2]), 2);
  assert.equal(medianTime([1, 4]), 4);
  assert.equal(medianTime([1, null, null]), null);
  assert.equal(medianTime([1, 2, null]), 2);
});
