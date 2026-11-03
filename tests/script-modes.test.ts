/**
 * The scripts that are tracked as executable stay executable. A commit once changed scripts/swarm.sh from mode 100755 to 100644, so
 * `./scripts/swarm.sh help` said "Permission denied" in a clone while every test (which runs it through bash) passed. The list is
 * tests/executable-scripts.list; each path in it must be tracked with mode 100755.
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";

const ROOT = join(import.meta.dirname, "..");

test("every script listed in tests/executable-scripts.list is tracked with the executable bit", () => {
  const listed = readFileSync(join(ROOT, "tests/executable-scripts.list"), "utf8").split("\n").filter((l) => l.trim() && !l.startsWith("#"));
  assert.ok(listed.includes("scripts/swarm.sh"), "the list names scripts/swarm.sh");
  const modes = new Map<string, string>();
  for (const line of execFileSync("git", ["ls-files", "-s", "-z", "--", ...listed], { cwd: ROOT, encoding: "utf8" }).split("\0").filter(Boolean)) {
    const [meta, path] = line.split("\t");
    modes.set(path!, meta!.split(" ")[0]!);
  }
  const bad = listed.filter((f) => modes.get(f) !== "100755").map((f) => `${f}: ${modes.get(f) ?? "not tracked"}`);
  assert.deepEqual(bad, [], `these lost their executable bit (git update-index --chmod=+x):\n${bad.join("\n")}`);
});
