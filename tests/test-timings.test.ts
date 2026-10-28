/**
 * scripts/test-timings.ts: the slowest node suite files as a table, and the
 * shell weights rebuilt from test-bash.sh logs.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { summary, weights } from "../scripts/test-timings.ts";

test("the summary merges the shards' timings and lists the slowest files first, with their share", () => {
  const a = JSON.stringify({ files: [{ file: "/r/tests/a.test.ts", ms: 1000, tests: 2, failed: 0, slowest: [{ name: "x|y", ms: 900 }] }] });
  const b = JSON.stringify({ files: [{ file: "/r/tests/b.test.ts", ms: 3000, tests: 1, failed: 1 }] });
  const md = summary([a, b], 5, "/r");
  assert.match(md, /2 node suite files, 0\.1 min/);
  const rows = md.split("\n").filter((l) => l.startsWith("| ") && !l.startsWith("| seconds") && !l.startsWith("| ---"));
  assert.equal(rows.length, 2);
  assert.match(rows[0], /^\| 3\.0 \| 75\.0% \| 1 \| `tests\/b\.test\.ts` \(failed\) \|/);
  assert.match(rows[1], /`tests\/a\.test\.ts` \| x\\\|y \|$/, "a | in a test name is escaped");
  assert.equal(summary([a, b], 1, "/r").split("\n").filter((l) => l.startsWith("| 3.0")).length, 1);
});

test("the weights take each logged suite's mean, keep the others and the header, longest first", () => {
  const current = "# header line\n# One line per suite: <stem> <seconds>\nslow 300\nkept 40\nfast 5\n";
  const log1 = "2026-10-27T22:15:44Z === ok   slow (100s)\n=== ok   fast (7s)\n=== FAIL broken (9s)\n";
  const log2 = "=== ok   slow (201s)\n=== ok   new (12s)\n";
  assert.equal(weights(current, [log1, log2]), "# header line\n# One line per suite: <stem> <seconds>\nslow 151\nkept 40\nnew 12\nfast 7\n");
  assert.equal(weights(current, []), "# header line\n# One line per suite: <stem> <seconds>\nslow 300\nkept 40\nfast 5\n", "no log: nothing moves");
});
