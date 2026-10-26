/**
 * The pack counts the docs state (README.md, docs/packs.md section 7) equal
 * the packs' (scripts/pack-counts.ts). A failure names each number that
 * differs; `node --experimental-strip-types scripts/pack-counts.ts --write`
 * brings the docs back in line.
 */
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { docCountProblems, numberWord, packCounts, totals, writeDocCounts } from "../scripts/pack-counts.ts";

test("the docs' per-pack tables and totals equal what the packs hold", () => {
  assert.deepEqual(docCountProblems(), []);
});

test("every pack directory is counted, and the totals are the sums", () => {
  const counts = packCounts();
  assert.ok(counts.length > 0);
  for (const c of counts) assert.ok(c.skills > 0 && c.tools > 0, `${c.id} has skills and tools`);
  const t = totals(counts);
  assert.equal(t.skills, counts.reduce((n, c) => n + c.skills, 0));
  assert.equal(numberWord(13), "Thirteen");
  assert.equal(numberWord(30), "30");
});

/** A repo of two packs and the two docs, with the numbers of `says`. */
function fixture(says: { a: string; b: string; sentence: string }): string {
  const root = mkdtempSync(join(tmpdir(), "pack-doc-counts-"));
  const pack = (id: string, entries: string[], tools: string[], goals: string[]) => {
    mkdirSync(join(root, "packs", id, "skills"), { recursive: true });
    writeFileSync(join(root, "packs", id, "pack.json"), "{}");
    writeFileSync(join(root, "packs", id, "skills", "INDEX.md"), `# Skills\n\nRouter: \`x/router\`\n\n${entries.map((e) => `- \`${e}\` Title: when.`).join("\n")}\n`);
    for (const t of tools) {
      mkdirSync(join(root, "packs", id, "tools", t), { recursive: true });
      writeFileSync(join(root, "packs", id, "tools", t, "manifest.json"), "{}");
    }
    mkdirSync(join(root, "packs", id, "tools", "not-a-tool"), { recursive: true });
    if (goals.length) mkdirSync(join(root, "packs", id, "goals"), { recursive: true });
    for (const g of goals) writeFileSync(join(root, "packs", id, "goals", g), "goal");
  };
  pack("alpha-pack", ["a/one", "a/two", "a/router"], ["t1", "t2"], []);
  pack("beta-pack", ["b/one"], ["t3"], ["g1.md", "g2.md"]);
  mkdirSync(join(root, "packs", "no-manifest"), { recursive: true });
  mkdirSync(join(root, "docs"), { recursive: true });
  writeFileSync(
    join(root, "README.md"),
    `| Pack | Skills | Tools | Goals |\n| --- | --- | --- | --- |\n| \`alpha-pack\` | ${says.a} |\n| \`beta-pack\` | ${says.b} |\n\n**${says.sentence}\nrepository** under the same licence: 4 skills,\n3 tools and 2\ngoal templates across.\n`,
  );
  writeFileSync(
    join(root, "docs", "packs.md"),
    `${says.sentence.split(" ")[0]}, all under the same licence, in \`packs/\`:\n4 skills, 3 tools and 2 goal templates. Sealed.\n\n| Pack | Skills | Tools | Goals | What |\n| --- | --- | --- | --- | --- |\n| \`alpha-pack\` | ${says.a} | the first |\n| \`beta-pack\` | ${says.b} | the second |\n`,
  );
  return root;
}

test("a stale number, a missing row and a wrong count word are each named, and --write fixes them", () => {
  const root = fixture({ a: "2 | 2 | —", b: "1 | 1 | 2", sentence: "Three ship in this" });
  try {
    const problems = docCountProblems(root);
    assert.ok(problems.some((p) => /README\.md: `alpha-pack` says 2 skills, the pack has 3/.test(p)), problems.join("\n"));
    assert.ok(problems.some((p) => /docs\/packs\.md: `alpha-pack` says 2 skills, the pack has 3/.test(p)), problems.join("\n"));
    assert.ok(problems.some((p) => /README\.md: the sentence says Three for the number of packs, the packs have Two/.test(p)), problems.join("\n"));
    assert.ok(problems.some((p) => /docs\/packs\.md: the sentence says Three/.test(p)), problems.join("\n"));
    assert.ok(!problems.some((p) => /beta-pack/.test(p)), "the right row is not named");
    assert.ok(!problems.some((p) => /no-manifest/.test(p)), "a directory without pack.json is not a pack");
    writeDocCounts(root);
    assert.deepEqual(docCountProblems(root), []);
    assert.match(readFileSync(join(root, "README.md"), "utf8"), /\*\*Two ship in this\nrepository\*\* under the same licence: 4 skills,\n3 tools and 2\ngoal templates across\./);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("a row for something that is not a pack, and a pack with no row, are named", () => {
  const root = fixture({ a: "3 | 2 | —", b: "1 | 1 | 2", sentence: "Two ship in this" });
  try {
    assert.deepEqual(docCountProblems(root), []);
    writeFileSync(join(root, "README.md"), readFileSync(join(root, "README.md"), "utf8").replace("| `beta-pack` | 1 | 1 | 2 |\n", "| `gamma-pack` | 1 | 1 | 2 |\n"));
    const problems = docCountProblems(root);
    assert.ok(problems.some((p) => /`gamma-pack`, which is not a pack/.test(p)), problems.join("\n"));
    assert.ok(problems.some((p) => /README\.md: the table has no row for `beta-pack`/.test(p)), problems.join("\n"));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
