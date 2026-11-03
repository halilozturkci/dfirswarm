/**
 * The counts the docs state about the tool library equal what the tree holds, as tests/pack-doc-counts.test.ts holds the packs' counts.
 * Three sentences carry them, found by pattern (not by line number): tool-library/README.md ("Forty-six tools. Forty were written by agents:
 * thirty-two during the forensic cases ... eight in later runs ...; six were written for gaps"), docs/forged-tools.md ("holds forty-six:
 * thirty-two written during the forensic cases, eight folded in from later runs, and six written for the gaps") and docs/roadmap.md ("the
 * thirty-two in the library were written mid-case").
 *
 * What each number is, read from the tree:
 *   all         the directories under tool-library/ (each holds a manifest.json);
 *   maintainer  those whose manifest says `by: "maintainer"` (written for gaps the cases left);
 *   folded      the tools the README's "Folded from later runs" section names at the head of a bullet (`name` or `a` and `b`, then a dash);
 *   forensic    all - maintainer - folded: written by agents during the forensic cases;
 *   agents      all - maintainer.
 */
import assert from "node:assert/strict";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

const ROOT = join(import.meta.dirname, "..");

const ONES = ["zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten", "eleven", "twelve", "thirteen", "fourteen", "fifteen", "sixteen", "seventeen", "eighteen", "nineteen"];
const TENS = ["", "", "twenty", "thirty", "forty", "fifty", "sixty", "seventy", "eighty", "ninety"];
/** 0..99 in words, lower case: 46 is "forty-six". */
export function words(n: number): string {
  if (n < 20) return ONES[n]!;
  return n % 10 ? `${TENS[Math.floor(n / 10)]}-${ONES[n % 10]}` : TENS[n / 10]!;
}
const cap = (s: string) => s[0]!.toUpperCase() + s.slice(1);

export type Counts = { all: number; maintainer: number; folded: number; forensic: number; agents: number };

/** The counts of the tool library under `root`, from its directories, manifests and README. */
export function libraryCounts(root: string): Counts {
  const dirs = readdirSync(join(root, "tool-library"), { withFileTypes: true }).filter((d) => d.isDirectory()).map((d) => d.name);
  let maintainer = 0;
  for (const d of dirs) {
    const manifest = JSON.parse(readFileSync(join(root, "tool-library", d, "manifest.json"), "utf8")) as { by?: unknown };
    if (manifest.by === "maintainer") maintainer += 1;
  }
  const readme = readFileSync(join(root, "tool-library", "README.md"), "utf8");
  const section = /^## Folded from later runs\n([\s\S]*?)(?=^## )/m.exec(readme);
  assert.ok(section, "tool-library/README.md lost its 'Folded from later runs' section: the test reads the folded tools from it");
  const folded = new Set<string>();
  for (const m of section[1]!.matchAll(/^- (`[a-z0-9_]+`(?: and `[a-z0-9_]+`)*) —/gm)) for (const n of m[1]!.matchAll(/`([a-z0-9_]+)`/g)) folded.add(n[1]!);
  for (const n of folded) assert.ok(dirs.includes(n), `the README folds in ${n}, which is not a directory of tool-library/`);
  return { all: dirs.length, maintainer, folded: folded.size, forensic: dirs.length - maintainer - folded.size, agents: dirs.length - maintainer };
}

const W = "([A-Za-z]+(?:-[a-z]+)?)";

/** Each count the three docs state that differs from the tree's, or a sentence the patterns no longer find: one line each. */
export function docProblems(root: string): string[] {
  const c = libraryCounts(root);
  const problems: string[] = [];
  const check = (doc: string, pattern: RegExp, expect: (m: RegExpExecArray) => Array<[string, string, string]>) => {
    const text = readFileSync(join(root, doc), "utf8");
    const m = pattern.exec(text);
    if (!m) {
      problems.push(`${doc}: the sentence the test reads by pattern is gone (${pattern}); update the pattern with the sentence`);
      return;
    }
    for (const [what, said, want] of expect(m)) if (said !== want) problems.push(`${doc}: says ${said} for ${what}, the tree has ${want}`);
  };
  check("tool-library/README.md", new RegExp(`${W} tools\\.\\s+${W} were written by agents:\\s+${W} during the\\s+forensic cases[^]*?and ${W} in\\s+later runs[^]*?;\\s+${W} were written for gaps`), (m) => [
    ["the tools", m[1]!, cap(words(c.all))],
    ["the agent-written tools", m[2]!, cap(words(c.agents))],
    ["the tools of the forensic cases", m[3]!, words(c.forensic)],
    ["the tools folded in from later runs", m[4]!, words(c.folded)],
    ["the tools written for gaps", m[5]!, words(c.maintainer)],
  ]);
  check("docs/forged-tools.md", new RegExp(`holds ${W}:\\s+${W} written during the forensic\\s+cases,\\s+${W} folded in from later runs,\\s+and ${W} written for the gaps`), (m) => [
    ["the tools", m[1]!, words(c.all)],
    ["the tools of the forensic cases", m[2]!, words(c.forensic)],
    ["the tools folded in from later runs", m[3]!, words(c.folded)],
    ["the tools written for gaps", m[4]!, words(c.maintainer)],
  ]);
  check("docs/roadmap.md", new RegExp(`since the\\s+${W}\\s+in the library\\s+were written mid-case`), (m) => [["the tools written mid-case", m[1]!, words(c.forensic)]]);
  return problems;
}

test("the three docs state the tool library's counts, as the tree holds them", () => {
  assert.deepEqual(docProblems(ROOT), []);
});

test("the counts come from the tree: directories, the maintainer's manifests, the README's folded section", () => {
  const c = libraryCounts(ROOT);
  assert.ok(c.all > 0 && c.maintainer > 0 && c.folded > 0 && c.forensic > 0);
  assert.equal(c.all, c.maintainer + c.folded + c.forensic);
  assert.equal(words(46), "forty-six");
  assert.equal(words(32), "thirty-two");
  assert.equal(words(8), "eight");
});

/** A copy of the library and the three docs, built here, to change. */
function copy(): string {
  const root = mkdtempSync(join(tmpdir(), "tool-library-counts-"));
  cpSync(join(ROOT, "tool-library"), join(root, "tool-library"), { recursive: true });
  mkdirSync(join(root, "docs"), { recursive: true });
  for (const f of ["docs/forged-tools.md", "docs/roadmap.md"]) writeFileSync(join(root, f), readFileSync(join(ROOT, f)));
  return root;
}

test("a tool added to a copy of the library, or one written by the maintainer, or a doc that says another number, is named", () => {
  const root = copy();
  try {
    assert.deepEqual(docProblems(root), [], "the copy starts equal to the tree");
    // One more directory written during a case: every doc that counts the tools is now behind.
    mkdirSync(join(root, "tool-library", "extra_tool"));
    writeFileSync(join(root, "tool-library", "extra_tool", "manifest.json"), JSON.stringify({ name: "extra_tool", by: "s123456" }));
    const added = docProblems(root);
    const all = libraryCounts(root).all;
    assert.ok(added.some((p) => p.startsWith("tool-library/README.md: says Forty-six for the tools")), added.join("\n"));
    assert.ok(added.some((p) => p.startsWith("docs/forged-tools.md: says forty-six for the tools")), added.join("\n"));
    assert.ok(added.some((p) => p.startsWith("docs/roadmap.md: says thirty-two")), added.join("\n"));
    assert.equal(all, libraryCounts(ROOT).all + 1);
    // A tool that turns out to be the maintainer's moves a count from the forensic cases to the gaps.
    rmSync(join(root, "tool-library", "extra_tool"), { recursive: true });
    const victim = join(root, "tool-library", "aescrypt_v2_decrypt", "manifest.json");
    writeFileSync(victim, JSON.stringify({ ...(JSON.parse(readFileSync(victim, "utf8")) as object), by: "maintainer" }));
    const moved = docProblems(root);
    assert.ok(moved.some((p) => p.includes("for the tools written for gaps")), moved.join("\n"));
    // A sentence that is gone is named, not passed.
    writeFileSync(join(root, "docs", "roadmap.md"), "nothing about the library here\n");
    assert.ok(docProblems(root).some((p) => p.startsWith("docs/roadmap.md: the sentence the test reads by pattern is gone")));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
