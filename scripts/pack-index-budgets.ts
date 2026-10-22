/**
 * What the packs' skill indexes cost a seat, measured with the harness's own code.
 *
 *   node --experimental-strip-types scripts/pack-index-budgets.ts [--json]
 *
 * It reads every pack under packs/ with `readPackIndex` and renders the Skills section of the prompt with
 * `renderSkillsSection` (extensions/skills.ts), the two functions a kickoff uses, and prints:
 *
 * - for every pack: entries, index tokens, the router it names and the router's own line in tokens;
 * - for every image profile of images/profiles.json (the base pack is always part of a run): the packs with their
 *   `depends` closure, the tokens of every entry (full mode), the tokens the prompt shows, and the mode;
 * - the same for the base pack beside every one, two and three other packs, with the count that fit in full mode,
 *   the count shown by routers, the largest shown figure, and the combinations that do not fit even then.
 *
 * tests/pack-index-budgets.test.ts holds the invariants; this module is what both read, so the table and the test
 * cannot disagree about how a run is rendered.
 */
import { readFile, readdir } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { readPackIndex, renderSkillsSection, SKILL_BUDGET, type PackIndex } from "../extensions/skills.ts";

export const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
export const BASE_PACK = "computer-forensics-base";

export type PackMeasure = {
  pack: string;
  entries: number;
  tokens: number;
  router: string | null;
  routerTokens: number | null;
};

export type SetMeasure = {
  label: string;
  packs: string[];
  /** Tokens of every entry of every pack: what the prompt would carry if nothing were shortened. */
  full: number;
  /** Tokens of the entries the prompt shows after the budget has been applied. */
  shown: number;
  mode: "full" | "routers";
  /** Packs that were over a budget and name no router, so they are shown whole. */
  noRouter: string[];
};

export type Corpus = {
  /** Pack directory names, sorted. */
  names: string[];
  indexes: Map<string, PackIndex>;
  depends: Map<string, string[]>;
  profiles: Map<string, string[]>;
};

export async function loadCorpus(root: string = ROOT): Promise<Corpus> {
  const names = (await readdir(join(root, "packs"), { withFileTypes: true })).filter((e) => e.isDirectory()).map((e) => e.name).sort();
  const indexes = new Map<string, PackIndex>();
  const depends = new Map<string, string[]>();
  for (const name of names) {
    indexes.set(name, await readPackIndex(join(root, "packs", name)));
    const manifest = JSON.parse(await readFile(join(root, "packs", name, "pack.json"), "utf8")) as { depends?: string[] };
    depends.set(name, (manifest.depends ?? []).map((d) => d.split(/[<>=!~ ]/)[0]!));
  }
  const raw = JSON.parse(await readFile(join(root, "images", "profiles.json"), "utf8")).profiles as Record<string, string[] | { packs: string[] }>;
  const profiles = new Map<string, string[]>();
  for (const [name, value] of Object.entries(raw)) profiles.set(name, Array.isArray(value) ? value : value.packs);
  return { names, indexes, depends, profiles };
}

/** The packs of a run: the base pack, the packs asked for and their `depends`, each once, a dependency before its dependant. */
export function closure(corpus: Corpus, ids: string[]): string[] {
  const order: string[] = [];
  const seen = new Set<string>();
  const visit = (id: string): void => {
    if (seen.has(id)) return;
    seen.add(id);
    if (!corpus.indexes.has(id)) throw new Error(`no pack ${id} under packs/`);
    for (const d of corpus.depends.get(id) ?? []) visit(d);
    order.push(id);
  };
  visit(BASE_PACK);
  for (const id of ids) visit(id);
  return order;
}

export function measurePack(corpus: Corpus, name: string): PackMeasure {
  const p = corpus.indexes.get(name)!;
  const router = p.router ? p.entries.find((e) => e.id === p.router) : undefined;
  return { pack: name, entries: p.entries.length, tokens: p.tokens, router: p.router, routerTokens: router ? router.tokens : null };
}

export function measureSet(corpus: Corpus, label: string, ids: string[]): SetMeasure {
  const packs = closure(corpus, ids);
  const { report } = renderSkillsSection(packs.map((id) => corpus.indexes.get(id)!), SKILL_BUDGET);
  return { label, packs, full: report.index_tokens, shown: report.shown_tokens, mode: report.mode, noRouter: report.no_router };
}

export function measureProfiles(corpus: Corpus): SetMeasure[] {
  return [...corpus.profiles].map(([name, ids]) => measureSet(corpus, `profile ${name}`, ids));
}

/** The base pack beside every combination of `k` other packs (k = 1, 2, 3 are the runs an operator starts by hand). */
export function measureCombinations(corpus: Corpus, k: 1 | 2 | 3): SetMeasure[] {
  const others = corpus.names.filter((n) => n !== BASE_PACK);
  const out: SetMeasure[] = [];
  const pick = (from: number, chosen: string[]): void => {
    if (chosen.length === k) {
      out.push(measureSet(corpus, `base + ${chosen.join(" + ")}`, chosen));
      return;
    }
    for (let i = from; i < others.length; i++) pick(i + 1, [...chosen, others[i]!]);
  };
  pick(0, []);
  return out;
}

const n = (x: number): string => x.toLocaleString("en-US");

export function renderTable(corpus: Corpus): string {
  const lines: string[] = [];
  const budget = `entry ${SKILL_BUDGET.entry}, pack ${n(SKILL_BUDGET.pack)}, run ${n(SKILL_BUDGET.run)} tokens`;
  lines.push(`Skill index budgets (${budget})`, "", "Packs", "| pack | entries | index tokens | router | router line tokens |", "|---|---:|---:|---|---:|");
  for (const name of corpus.names) {
    const m = measurePack(corpus, name);
    lines.push(`| ${name} | ${m.entries} | ${n(m.tokens)} | ${m.router ?? "none"} | ${m.routerTokens ?? "-"} |`);
  }
  lines.push("", "Profiles (the base pack and the dependencies of each pack are part of a run)", "| profile | packs | full mode | shown | mode |", "|---|---:|---:|---:|---|");
  for (const m of measureProfiles(corpus)) lines.push(`| ${m.label.replace("profile ", "")} | ${m.packs.length} | ${n(m.full)} | ${n(m.shown)} | ${m.mode}${m.noRouter.length ? ` (no router: ${m.noRouter.join(", ")})` : ""} |`);
  lines.push("", "Combinations", "| combination | runs | whole index fits | shown by routers | largest shown | over the run budget when shown |", "|---|---:|---:|---:|---|---:|");
  for (const k of [1, 2, 3] as const) {
    const all = measureCombinations(corpus, k);
    const biggest = all.reduce((a, b) => (b.shown > a.shown ? b : a));
    const over = all.filter((m) => m.shown > SKILL_BUDGET.run);
    lines.push(`| base + ${k} | ${all.length} | ${all.filter((m) => m.mode === "full").length} | ${all.filter((m) => m.mode === "routers").length} | ${n(biggest.shown)} (${biggest.label.replace("base + ", "")}) | ${over.length} |`);
  }
  return lines.join("\n");
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  const corpus = await loadCorpus();
  if (process.argv.includes("--json")) {
    const out = {
      budget: SKILL_BUDGET,
      packs: corpus.names.map((name) => measurePack(corpus, name)),
      profiles: measureProfiles(corpus),
      combinations: { 1: measureCombinations(corpus, 1), 2: measureCombinations(corpus, 2), 3: measureCombinations(corpus, 3) },
    };
    console.log(JSON.stringify(out, null, 2));
  } else {
    console.log(renderTable(corpus));
  }
}
