/**
 * One drift test over every shared block. It scans packs/ and tool-library/ for every BEGIN/END pair, in both marker styles:
 *
 *   # BEGIN SHARED X ... # END SHARED X
 *   # ---- BEGIN X ----...   ...   # ---- END X ----...        (the dashes after the name differ in length from file to file)
 *
 * groups the copies by family (the name in the markers) and by the digest of the lines strictly between the markers (sha256, first ten hexadecimal digits,
 * the lines joined with LF), and holds the result to tests/shared-blocks.json, which declares each family's variants with their carrier counts and a
 * reason for every variant beyond the first. It fails on a family or a variant that is not declared, on a changed number of carriers, on a variant whose
 * example is not a carrier of it, and on a BEGIN without its END (or an END without its BEGIN).
 *
 * The file declares counts, not digests: a block that changes in every carrier at once (a sweep) needs no edit, while a copy that drifted, a sweep that
 * missed one, an adoption and a removal each change a count or add a variant. When that is meant, edit tests/shared-blocks.json in the same change.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, relative, sep } from "node:path";
import { test } from "node:test";
import { ROOT } from "./tool-library-harness.ts";

type Variant = { carriers: number; example: string; why?: string };
type Declared = { families: Record<string, { variants: Variant[] }> };
type Found = { family: string; digest: string; file: string };

const SOURCES = /\.(py|sh|ts|js|mjs)$/;
const BEGIN_HASH = /^\s*# BEGIN SHARED (.+?)\s*$/;
const END_HASH = /^\s*# END SHARED (.+?)\s*$/;
const BEGIN_DASH = /^\s*# -{3,} BEGIN (.+?) -{3,}\s*$/;
const END_DASH = /^\s*# -{3,} END (.+?) -{3,}\s*$/;

async function files(dir: string, out: string[] = []): Promise<string[]> {
  for (const e of await readdir(dir, { withFileTypes: true }).catch(() => [])) {
    if (e.name === "node_modules" || e.name === ".git" || e.name === "__pycache__") continue;
    const path = join(dir, e.name);
    if (e.isDirectory()) await files(path, out);
    else if (SOURCES.test(e.name)) out.push(path);
  }
  return out;
}

/** Every copy under `<root>/packs` and `<root>/tool-library`, and what is wrong with the markers. */
export async function scan(root: string): Promise<{ found: Found[]; problems: string[] }> {
  const found: Found[] = [];
  const problems: string[] = [];
  for (const top of ["packs", "tool-library"]) {
    for (const path of (await files(join(root, top))).sort()) {
      const rel = relative(root, path).split(sep).join("/");
      const lines = (await readFile(path, "utf8")).split("\n");
      const open: Map<string, number> = new Map();
      lines.forEach((line, i) => {
        const b = BEGIN_HASH.exec(line) ?? BEGIN_DASH.exec(line);
        const e = END_HASH.exec(line) ?? END_DASH.exec(line);
        if (b) {
          const name = b[1];
          if (open.has(name)) problems.push(`${rel}:${i + 1}: BEGIN ${name} again before its END (the one at line ${(open.get(name) as number) + 1})`);
          open.set(name, i);
        } else if (e) {
          const name = e[1];
          const from = open.get(name);
          if (from === undefined) {
            problems.push(`${rel}:${i + 1}: END ${name} without its BEGIN`);
            return;
          }
          open.delete(name);
          const digest = createHash("sha256").update(lines.slice(from + 1, i).join("\n")).digest("hex").slice(0, 10);
          found.push({ family: name, digest, file: rel });
        }
      });
      for (const [name, from] of open) problems.push(`${rel}:${from + 1}: BEGIN ${name} without its END`);
    }
  }
  return { found, problems };
}

const HOW = "To change what is declared, edit tests/shared-blocks.json in the same change: `carriers` when a sweep or an adoption adds or removes carriers, a new variant with its `why` when a second text is meant.";

/** What is wrong with these copies against the declaration, as sentences; empty when they are as declared. */
export function judge(found: Found[], declared: Declared): string[] {
  const problems: string[] = [];
  const families = new Map<string, Map<string, string[]>>();
  for (const f of found) {
    const variants = families.get(f.family) ?? new Map<string, string[]>();
    variants.set(f.digest, [...(variants.get(f.digest) ?? []), f.file]);
    families.set(f.family, variants);
  }
  for (const [name, variants] of [...families].sort()) {
    const decl = declared.families[name];
    const seen = [...variants].map(([digest, fs]) => `${digest} in ${fs.length} (e.g. ${fs[0]})`).join("; ");
    if (!decl) {
      problems.push(`the family "${name}" is not declared (${seen}). ${HOW}`);
      continue;
    }
    if (decl.variants.length !== variants.size) {
      problems.push(`${name}: ${variants.size} variants found, ${decl.variants.length} declared: ${seen}. ${HOW}`);
      continue;
    }
    decl.variants.forEach((v, i) => {
      if (i > 0 && !(typeof v.why === "string" && v.why.trim().length >= 10)) problems.push(`${name}: the variant of ${v.example} needs a reason (why) of at least a few words`);
    });
    const taken = new Set<string>();
    for (const v of decl.variants) {
      const match = [...variants].find(([, fs]) => fs.includes(v.example));
      if (!match) {
        problems.push(`${name}: the declared example ${v.example} is not a carrier of any variant found (${seen}). ${HOW}`);
        continue;
      }
      if (taken.has(match[0])) problems.push(`${name}: two declared variants have the same text (${match[0]})`);
      taken.add(match[0]);
      if (match[1].length !== v.carriers) problems.push(`${name}: ${match[1].length} carriers of the variant of ${v.example}, ${v.carriers} declared. ${HOW}`);
    }
  }
  for (const name of Object.keys(declared.families)) {
    if (!families.has(name)) problems.push(`${name}: declared, and no file carries it. ${HOW}`);
  }
  return problems;
}

async function declaration(): Promise<Declared> {
  return JSON.parse(await readFile(join(ROOT, "tests", "shared-blocks.json"), "utf8")) as Declared;
}

test("every shared block under packs/ and tool-library/ is a declared family, in declared variants, with the declared carriers", async () => {
  const { found, problems } = await scan(ROOT);
  assert.deepEqual(problems, [], "every BEGIN has its END");
  assert.ok(found.length >= 150, `${found.length} copies found`);
  assert.deepEqual(judge(found, await declaration()), []);
});

test("the declaration is well formed: a count of at least two for a block that is shared, a reason for every extra variant", async () => {
  const declared = await declaration();
  for (const [name, family] of Object.entries(declared.families)) {
    assert.ok(family.variants.length >= 1, name);
    for (const v of family.variants) assert.ok(Number.isInteger(v.carriers) && v.carriers >= 2 && v.example, `${name}: ${JSON.stringify(v)}`);
  }
});

// ---- the census can fail: planted trees ---------------------------------------------------------------------------------------------------------

async function plant(root: string, rel: string, blocks: { name: string; body: string; dashed?: boolean; drop?: "begin" | "end" }[]): Promise<void> {
  const lines: string[] = ["#!/usr/bin/env python3", "import os"];
  for (const b of blocks) {
    if (b.drop !== "begin") lines.push(b.dashed ? `# ---- BEGIN ${b.name} ${"-".repeat(10 + (rel.length % 7))}` : `# BEGIN SHARED ${b.name}`);
    lines.push(b.body);
    if (b.drop !== "end") lines.push(b.dashed ? `# ---- END ${b.name} ${"-".repeat(20 + (rel.length % 5))}` : `# END SHARED ${b.name}`);
  }
  await mkdir(dirname(join(root, rel)), { recursive: true });
  await writeFile(join(root, rel), lines.join("\n") + "\n");
}

test("the census fails on a planted extra variant, an extra family, a removed carrier, and a BEGIN without its END; it reads both marker styles", async () => {
  const root = await mkdtemp(join(tmpdir(), "census-"));
  try {
    const declared: Declared = { families: {
      ALPHA: { variants: [{ carriers: 3, example: "packs/p/tools/a/run.py" }] },
      DASHED: { variants: [{ carriers: 2, example: "packs/p/tools/a/run.py" }] },
    } };
    for (const t of ["a", "b", "c"]) await plant(root, `packs/p/tools/${t}/run.py`, [{ name: "ALPHA", body: "x = 1" }, ...(t !== "c" ? [{ name: "DASHED", body: "y = 2", dashed: true }] : [])]);
    const clean = await scan(root);
    assert.deepEqual(clean.problems, []);
    assert.equal(clean.found.length, 5, "three of one style, two of the other (the dashes differ in length per file)");
    assert.deepEqual(judge(clean.found, declared), [], "the planted tree is as declared");

    // a copy that drifted is a third variant
    await plant(root, "packs/p/tools/c/run.py", [{ name: "ALPHA", body: "x = 2" }]);
    assert.match(judge((await scan(root)).found, declared).join("\n"), /ALPHA: 2 variants found, 1 declared/);
    await plant(root, "packs/p/tools/c/run.py", [{ name: "ALPHA", body: "x = 1" }]);

    // an extra family
    await plant(root, "tool-library/z/run.py", [{ name: "OMEGA", body: "z = 3" }]);
    assert.match(judge((await scan(root)).found, declared).join("\n"), /the family "OMEGA" is not declared/);
    await rm(join(root, "tool-library"), { recursive: true });

    // a removed carrier
    await rm(join(root, "packs/p/tools/b"), { recursive: true });
    assert.match(judge((await scan(root)).found, declared).join("\n"), /ALPHA: 2 carriers of the variant of packs\/p\/tools\/a\/run.py, 3 declared/);
    await plant(root, "packs/p/tools/b/run.py", [{ name: "ALPHA", body: "x = 1" }, { name: "DASHED", body: "y = 2", dashed: true }]);

    // a BEGIN without its END, and an END without its BEGIN
    await plant(root, "packs/p/tools/c/run.py", [{ name: "ALPHA", body: "x = 1", drop: "end" }]);
    assert.match((await scan(root)).problems.join("\n"), /c\/run.py:3: BEGIN ALPHA without its END/);
    await plant(root, "packs/p/tools/c/run.py", [{ name: "ALPHA", body: "x = 1", drop: "begin" }]);
    assert.match((await scan(root)).problems.join("\n"), /c\/run.py:\d+: END ALPHA without its BEGIN/);

    // a declared family nobody carries, and an extra variant without a reason
    await plant(root, "packs/p/tools/c/run.py", [{ name: "ALPHA", body: "x = 1" }]);
    assert.match(judge((await scan(root)).found, { families: { ...declared.families, GONE: { variants: [{ carriers: 2, example: "packs/p/tools/a/run.py" }] } } }).join("\n"), /GONE: declared, and no file carries it/);
    await plant(root, "packs/p/tools/c/run.py", [{ name: "ALPHA", body: "x = 9" }]);
    const two: Declared = { families: { ...declared.families, ALPHA: { variants: [{ carriers: 2, example: "packs/p/tools/a/run.py" }, { carriers: 1, example: "packs/p/tools/c/run.py" }] } } };
    assert.match(judge((await scan(root)).found, two).join("\n"), /needs a reason/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
