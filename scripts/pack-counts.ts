/**
 * The counts the docs state about the packs in this repository, computed from
 * the packs themselves.
 *
 * `README.md` and `docs/packs.md` (section 7) each carry a per-pack table
 * (skills, tools, goal templates) and a sentence with the number of packs and
 * the totals. A number typed by hand goes stale with the next pack or skill, so
 * `tests/pack-doc-counts.test.ts` compares them with what this script computes
 * and fails when they differ. To bring the docs back in line:
 *
 *   node --experimental-strip-types scripts/pack-counts.ts           # print the counts
 *   node --experimental-strip-types scripts/pack-counts.ts --check   # exit 1 when a doc differs
 *   node --experimental-strip-types scripts/pack-counts.ts --write   # rewrite the numbers in place
 *
 * What is counted, per directory under `packs/` that holds a `pack.json`:
 *
 * - skills: the entries of `skills/INDEX.md` (the lines `- \`<id>\` ...`), which is
 *   what the harness shows an agent, routers included;
 * - tools: the directories of `tools/` that hold a `manifest.json`;
 * - goal templates: the `*.md` files of `goals/`.
 *
 * Only the numbers are written: a row's other cells and the prose around the
 * totals are left as they are.
 */
import { existsSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(fileURLToPath(new URL("..", import.meta.url)));

export interface PackCount {
  id: string;
  skills: number;
  tools: number;
  goals: number;
}

export function packCounts(root: string = ROOT): PackCount[] {
  const packs = join(root, "packs");
  const out: PackCount[] = [];
  for (const id of readdirSync(packs).sort()) {
    const dir = join(packs, id);
    if (!existsSync(join(dir, "pack.json"))) continue;
    const index = join(dir, "skills", "INDEX.md");
    const skills = existsSync(index) ? readFileSync(index, "utf8").split("\n").filter((l) => /^- `[^`]+`/.test(l)).length : 0;
    const toolsDir = join(dir, "tools");
    const tools = existsSync(toolsDir)
      ? readdirSync(toolsDir, { withFileTypes: true }).filter((e) => e.isDirectory() && existsSync(join(toolsDir, e.name, "manifest.json"))).length
      : 0;
    const goalsDir = join(dir, "goals");
    const goals = existsSync(goalsDir) ? readdirSync(goalsDir).filter((f) => f.endsWith(".md")).length : 0;
    out.push({ id, skills, tools, goals });
  }
  return out;
}

export interface Totals {
  packs: number;
  skills: number;
  tools: number;
  goals: number;
}

export function totals(counts: PackCount[]): Totals {
  return {
    packs: counts.length,
    skills: counts.reduce((n, c) => n + c.skills, 0),
    tools: counts.reduce((n, c) => n + c.tools, 0),
    goals: counts.reduce((n, c) => n + c.goals, 0),
  };
}

const WORDS = ["Zero", "One", "Two", "Three", "Four", "Five", "Six", "Seven", "Eight", "Nine", "Ten", "Eleven", "Twelve", "Thirteen", "Fourteen", "Fifteen", "Sixteen", "Seventeen", "Eighteen", "Nineteen", "Twenty"];
/** "Thirteen" for 13; the digits as text past twenty. */
export function numberWord(n: number): string {
  return WORDS[n] ?? String(n);
}

/** The two docs and where each keeps its table and its totals sentence. */
interface Doc {
  file: string;
  /** Table columns after the pack id: the cells that are skills, tools, goals (0-based, within the row's cells). */
  cols: [number, number, number];
  /** The sentence: group 1 the count word, 2 skills, 3 tools, 4 goals. */
  sentence: RegExp;
}

const DOCS: Doc[] = [
  { file: "README.md", cols: [1, 2, 3], sentence: /\*\*([A-Za-z]+) ship in this\s+repository\*\*[^:]*:\s+(\d+) skills,\s+(\d+) tools\s+and\s+(\d+)\s+goal\s+templates/d },
  { file: "docs/packs.md", cols: [1, 2, 3], sentence: /^([A-Z][a-z-]+), all under the same[^\n]*\n(\d+) skills, (\d+) tools and (\d+) goal templates/md },
];

const ROW = /^\| `([a-z0-9-]+)` \|(.*)\|\s*$/;

/** What a cell of a count column says: a number, or the dash that means none. */
const cellValue = (n: number): string => (n === 0 ? "—" : String(n));

function problemsOrRewrite(root: string, write: boolean): string[] {
  const counts = packCounts(root);
  const byId = new Map(counts.map((c) => [c.id, c]));
  const t = totals(counts);
  const problems: string[] = [];
  for (const doc of DOCS) {
    const path = join(root, doc.file);
    let text = readFileSync(path, "utf8");
    const seen = new Set<string>();
    const lines = text.split("\n").map((line) => {
      const m = ROW.exec(line);
      if (!m) return line;
      const id = m[1]!;
      const count = byId.get(id);
      if (!count) {
        problems.push(`${doc.file}: the table has a row for \`${id}\`, which is not a pack in packs/`);
        return line;
      }
      seen.add(id);
      const cells = line.split("|").slice(1, -1); // the cells between the outer bars
      const want = [count.skills, count.tools, count.goals];
      doc.cols.forEach((col, i) => {
        const have = cells[col]!.trim();
        const wantText = cellValue(want[i]!);
        if (have !== wantText) {
          const name = ["skills", "tools", "goals"][i]!;
          problems.push(`${doc.file}: \`${id}\` says ${have} ${name}, the pack has ${wantText}`);
          cells[col] = ` ${wantText} `;
        }
      });
      return "|" + cells.join("|") + "|";
    });
    for (const c of counts) if (!seen.has(c.id)) problems.push(`${doc.file}: the table has no row for \`${c.id}\``);
    text = lines.join("\n");

    const s = doc.sentence.exec(text);
    if (!s) {
      problems.push(`${doc.file}: the sentence with the number of packs and the totals was not found`);
    } else {
      const want = [numberWord(t.packs), String(t.skills), String(t.tools), String(t.goals)];
      const have = s.slice(1, 5);
      const names = ["number of packs", "skills", "tools", "goal templates"];
      const spans = (s as RegExpExecArray & { indices: Array<[number, number]> }).indices;
      for (let i = have.length - 1; i >= 0; i--) {
        if (have[i] === want[i]) continue;
        problems.push(`${doc.file}: the sentence says ${have[i]} for the ${names[i]}, the packs have ${want[i]}`);
        const [from, to] = spans[i + 1]!;
        text = text.slice(0, from) + want[i] + text.slice(to);
      }
    }
    if (write) writeFileSync(path, text);
  }
  return problems;
}

/** Every place where a doc differs from the packs; empty when they agree. */
export function docCountProblems(root: string = ROOT): string[] {
  return problemsOrRewrite(root, false);
}

/** Rewrite the numbers in the docs; returns what it changed. */
export function writeDocCounts(root: string = ROOT): string[] {
  return problemsOrRewrite(root, true);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const arg = process.argv[2];
  if (arg === "--check") {
    const p = docCountProblems();
    if (p.length) {
      console.error(p.join("\n") + "\nrun: node --experimental-strip-types scripts/pack-counts.ts --write");
      process.exit(1);
    }
    console.log("the docs' pack counts equal the packs'");
  } else if (arg === "--write") {
    const p = writeDocCounts();
    console.log(p.length ? p.join("\n") : "nothing to change");
  } else {
    const counts = packCounts();
    const t = totals(counts);
    for (const c of counts) console.log(`${c.id}\t${c.skills} skills\t${c.tools} tools\t${c.goals} goals`);
    console.log(`${numberWord(t.packs)} packs: ${t.skills} skills, ${t.tools} tools and ${t.goals} goal templates`);
  }
}
