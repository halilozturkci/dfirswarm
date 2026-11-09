/**
 * `_S_LINE` (the second check's "line N" pattern, `[ \t]*line[ \t]+[0-9]`) takes quadratic time under `.search` on a run of spaces or tabs
 * (2.6 s for 32 KiB). The one BOUNDARY text calls it only at one position, with `.match`, which is a linear step. This test keeps it that way:
 * every use of the name, in every run.py under packs/ and tool-library/ that defines it, has to be `.match(` or `.fullmatch(`. A `.search(`,
 * `.sub(`, `.findall(`, `.finditer(`, `.split(` or a bare use (the pattern handed to another function, or rebound) fails. The scan proves itself on a planted source.
 *
 * Pure source scan: nothing is run.
 */
import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import { join, relative, sep } from "node:path";
import { test } from "node:test";
import { ROOT } from "./tool-library-harness.ts";

const DEFINE = /^\s*_S_LINE\s*=\s*re\.compile\(/;
const USE = /\b_S_LINE\b(\s*\.\s*([A-Za-z_]+)\s*\()?/g;
const ALLOWED = new Set(["match", "fullmatch"]);

async function runFiles(dir: string, out: string[] = []): Promise<string[]> {
  for (const e of await readdir(dir, { withFileTypes: true })) {
    if (e.name === "node_modules" || e.name === ".git") continue;
    const p = join(dir, e.name);
    if (e.isDirectory()) await runFiles(p, out);
    else if (e.name === "run.py") out.push(p);
  }
  return out;
}

/** Every line of `source` that uses the name in a way other than `.match(` or `.fullmatch(`, as "line: text". The defining line is not a use. */
function badUses(source: string): { defines: boolean; bad: string[]; uses: number } {
  let defines = false;
  let uses = 0;
  const bad: string[] = [];
  source.split("\n").forEach((line, i) => {
    if (DEFINE.test(line)) {
      defines = true;
      return;
    }
    const code = line.replace(/#.*$/, "");
    for (const m of code.matchAll(USE)) {
      uses++;
      if (!m[2] || !ALLOWED.has(m[2])) bad.push(`${i + 1}: ${line.trim()}`);
    }
  });
  return { defines, bad, uses };
}

test("the scan catches a .search, a .sub, a bare use, and passes .match and .fullmatch (the planted source)", () => {
  const planted = [
    '_S_LINE = re.compile(r"[ \t]*line[ \t]+[0-9]")',
    "ok1 = _S_LINE.match(flat, i + 1)",
    "ok2 = _S_LINE.fullmatch(flat)",
    "ok3 = _S_LINE . match (flat, 3)",
    "# _S_LINE.search(flat) in a comment is not a use",
    "bad1 = _S_LINE.search(flat)",
    "bad2 = _S_LINE.sub('', flat)",
    "bad3 = scan(_S_LINE, flat)",
    "bad4 = _S_LINE.finditer(flat)",
    "pat = _S_LINE",
  ].join("\n");
  const r = badUses(planted);
  assert.equal(r.defines, true);
  assert.deepEqual(
    r.bad.map((b) => b.split(":")[0]),
    ["6", "7", "8", "9", "10"],
    `the planted bad uses: ${r.bad.join(" | ")}`,
  );
  assert.equal(r.uses, 8, "three allowed uses and five bad ones");
  assert.equal(badUses('x = re.compile(r"line")\ny = 1').defines, false);
});

test("every carrier that defines _S_LINE uses it with .match or .fullmatch only", async () => {
  const defining: string[] = [];
  const problems: string[] = [];
  for (const root of ["packs", "tool-library"]) {
    for (const file of (await runFiles(join(ROOT, root))).sort()) {
      const text = await readFile(file, "utf8");
      if (!text.includes("_S_LINE")) continue;
      const rel = relative(ROOT, file).split(sep).join("/");
      const r = badUses(text);
      if (r.defines) defining.push(rel);
      else problems.push(`${rel}: uses _S_LINE without defining it`);
      for (const b of r.bad) problems.push(`${rel}:${b}`);
    }
  }
  assert.ok(defining.length >= 16, `expected at least the 16 carriers of the one text, found ${defining.length}`);
  assert.deepEqual(problems, [], "an _S_LINE use that is not .match( or .fullmatch(");
  // the three virtualization tools are among them
  for (const t of ["backup_audit_normalise", "snapshot_chain_check", "virtualization_inventory"]) {
    assert.ok(defining.includes(`packs/virtualization-backup-forensics/tools/${t}/run.py`), `${t} carries _S_LINE`);
  }
});
