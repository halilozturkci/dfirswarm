/**
 * A recipe's detect step has three answers (docs/packs.md, section 8): exit 0 applies, exit 1 does not, exit 2 cannot tell (`applies: "unknown"`), and
 * any other code is a failed detect. A detect that could not read its target must not claim "does not apply".
 *
 *  - the census (scripts/evidence_catalog.py detect_why) says "could not tell" for exit 2, "failed" for another code, and keeps the recipe's own why for 1;
 *  - the job service's detect_answered rows carry applies: true | false | "unknown" (detectApplies), and only true starts a recipe;
 *  - every shipped recipe whose detect reads the target answers exit 2 and `applies: "unknown"` for a target it cannot open, and still exit 1 for a
 *    target it opened and found not to be its kind.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { detectApplies } from "../scripts/job-service.ts";
import { ROOT } from "./tool-library-harness.ts";

test("the job service maps a detect exit code to applies: 0 true, 1 false, 2 unknown, anything else false", () => {
  assert.equal(detectApplies("0"), true);
  assert.equal(detectApplies("1"), false);
  assert.equal(detectApplies("2"), "unknown");
  for (const rc of ["3", "124", "127", "", "x"]) assert.equal(detectApplies(rc), false, rc);
});

test("the census says 'could not tell' for exit 2, 'failed' for another code, and keeps the recipe's why for exit 1", () => {
  const code = [
    "import json, sys",
    `sys.path.insert(0, ${JSON.stringify(join(ROOT, "scripts"))})`,
    "import evidence_catalog as e",
    "print(json.dumps([e.detect_why(1, 'not a zip'), e.detect_why(2, 'unreadable'), e.detect_why(2, ''), e.detect_why(3, 'x'), e.detect_why(124, '')]))",
  ].join("\n");
  const r = spawnSync("python3", ["-c", code], { encoding: "utf8", timeout: 30_000 });
  assert.equal(r.status, 0, r.stderr);
  assert.deepEqual(JSON.parse(r.stdout), [
    "not a zip",
    "its detect step could not tell (exit 2): unreadable",
    "its detect step could not tell (exit 2)",
    "its detect step failed (exit 3): x",
    "its detect step failed (exit 124)",
  ]);
});

const RECIPES: Array<[string, string]> = [
  ["computer-forensics-base", "ad1-items"], ["computer-forensics-base", "archive-members"], ["computer-forensics-base", "disk-timeline"],
  ["mobile-forensics", "android-aleapp"], ["mobile-forensics", "android-backup"], ["mobile-forensics", "android-backup-apps"],
  ["mobile-forensics", "ios-filesystem"], ["mobile-forensics", "ios-ileapp"], ["network-forensics", "network-capture"],
];

function detect(pack: string, recipe: string, target: string): { code: number | null; answer: { applies?: unknown; why?: string } } {
  const r = spawnSync("python3", [join(ROOT, "packs", pack, "recipes", recipe, "run.py"), "detect", "--target", JSON.stringify({ paths: [target], name: "inputs/x" })], { encoding: "utf8", timeout: 60_000, cwd: tmpdir() });
  const line = r.stdout.trim().split("\n").pop() ?? "";
  return { code: r.status, answer: line ? (JSON.parse(line) as { applies?: unknown; why?: string }) : {} };
}

test("a recipe whose detect cannot open its target answers exit 2 and applies: unknown, and one that opened a file of another kind still answers exit 1", async () => {
  const dir = await mkdtemp(join(tmpdir(), "detect3-"));
  try {
    const other = join(dir, "notes.txt");
    await writeFile(other, "plain text that is no archive, no image and no capture\n".repeat(20));
    for (const [pack, recipe] of RECIPES) {
      const gone = detect(pack, recipe, join(dir, "does-not-exist"));
      assert.equal(gone.code, 2, `${recipe}: a target that is not there: exit ${gone.code} ${JSON.stringify(gone.answer)}`);
      assert.equal(gone.answer.applies, "unknown", `${recipe}: ${JSON.stringify(gone.answer)}`);
      assert.ok(gone.answer.why, `${recipe} says why`);
      const no = detect(pack, recipe, other);
      assert.equal(no.code, 1, `${recipe}: a text file: exit ${no.code} ${JSON.stringify(no.answer)}`);
      assert.equal(no.answer.applies, false, recipe);
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
