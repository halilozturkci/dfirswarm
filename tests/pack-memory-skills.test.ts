/**
 * memory-forensics: the split pass. Every skill is a leaf within the size budget (at most 800 tokens, estimated
 * as bytes / 4.245, and 300 lines; an index entry at most 40 tokens), `needs` is at most two deep and its chain
 * at most 1,900 tokens, every second-level leaf is pointed to by a leaf that says when to open it, every id the
 * pack had before the split (and every id another pack names) is still a skill, and no rule of the review was
 * lost in the move: tests/pack-split-rules/memory-forensics.json lists, per old skill, the sentences that carry a Shows / Does not
 * show / Record / Sensitive output / bounded-negative / corroboration rule, and each must still be in the pack.
 */
import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { estimateTokens, readPackIndex, readPackIndexes, renderSkillsSection, SKILL_BUDGET } from "../extensions/skills.ts";
import { ROOT } from "./tool-library-harness.ts";

const PACK = join(ROOT, "packs", "memory-forensics");
const SKILLS = join(PACK, "skills");
const BASE_SKILLS = join(ROOT, "packs", "computer-forensics-base", "skills");
const TOKENS = (text: string): number => Buffer.byteLength(text) / 4.245;
const flat = (s: string): string => s.replace(/\s+/g, " ");
const norm = (s: string): string => s.replace(/[`*]/g, "").replace(/\s+/g, " ").toLowerCase().trim();

type Skill = { id: string; meta: Record<string, string | string[]>; body: string; text: string };

async function load(root: string): Promise<Map<string, Skill>> {
  const out = new Map<string, Skill>();
  const walk = async (dir: string): Promise<void> => {
    for (const e of await readdir(dir, { withFileTypes: true })) {
      if (e.isDirectory()) await walk(join(dir, e.name));
      else if (e.name.endsWith(".md") && e.name !== "INDEX.md") {
        const text = await readFile(join(dir, e.name), "utf8");
        const m = /^---\n([\s\S]*?)\n---\n/.exec(text);
        assert.ok(m, `${e.name} has front matter`);
        const meta: Record<string, string | string[]> = {};
        for (const line of m[1].split("\n")) {
          const [k, ...rest] = line.split(":");
          const v = rest.join(":").trim();
          meta[k.trim()] = v.startsWith("[") ? v.slice(1, -1).split(",").map((x) => x.trim()).filter(Boolean) : v;
        }
        out.set(String(meta.id), { id: String(meta.id), meta, body: text.slice(m[0].length), text });
      }
    }
  };
  await walk(root);
  return out;
}

// The decision leaves (the nine ids the pack had before the split) and their second-level leaves.
const OLD_IDS = [
  "acquire/images", "credentials/material", "network/state", "patterns/yara", "processes/injection",
  "strings/discipline", "triage/no-framework", "triage/volatility", "triage/what-you-have",
];
const SECOND: Record<string, string> = {
  "triage/container-details": "triage/what-you-have",
  "triage/carve-signatures": "triage/no-framework",
  "triage/paging-files": "triage/no-framework",
  "triage/volatility-symbols": "triage/volatility",
  "triage/volatility-plugins": "triage/volatility",
  "triage/volatility-catalogue": "triage/volatility",
  "processes/preserve-regions": "processes/injection",
  "network/timestamps-dns": "network/state",
  "credentials/key-schedules": "credentials/material",
  "acquire/avml-and-preserve": "acquire/images",
};

test("every skill is a leaf within the budget, opens with Use when ... Not for ..., and has a short index entry", async () => {
  const skills = await load(SKILLS);
  assert.equal(skills.size, OLD_IDS.length + Object.keys(SECOND).length + 1, "the pack's leaves and its router");
  for (const s of skills.values()) {
    assert.ok(TOKENS(s.text) <= 800, `${s.id} is ${Math.round(TOKENS(s.text))} tokens`);
    assert.ok(s.text.split("\n").length <= 300, `${s.id} lines`);
    const first = s.body.trim().split("\n")[0];
    assert.match(first, /^Use (when|only if) /, `${s.id} opens with Use when`);
    assert.match(first, /\bNot for\b/, `${s.id} says what it is not for`);
    const entry = `- \`${s.id}\` ${s.meta.title}: ${s.meta.when}`;
    assert.ok(TOKENS(entry) <= 40, `${s.id} index entry is ${Math.round(TOKENS(entry))} tokens`);
    // The router reads no artefact: it names notes and holds no rule, so it shows nothing.
    if (s.id === ROUTER) continue;
    assert.match(flat(s.body), /Does not show/i, `${s.id} says what it does not show`);
    assert.ok(s.body.includes("Sensitive output") || s.body.includes("Record:"), `${s.id} has Sensitive output or Record`);
  }
  const index = await readFile(join(SKILLS, "INDEX.md"), "utf8");
  for (const id of skills.keys()) assert.ok(index.includes(`\`${id}\``), `${id} is in the index`);
});

test("needs is at most two deep and its chain at most 1,900 tokens, counting the base skills it reaches", async () => {
  const all = new Map([...(await load(BASE_SKILLS)), ...(await load(SKILLS))]);
  const walk = (id: string, seen: string[], members: Set<string>): number => {
    const s = all.get(id);
    assert.ok(s, `${id} resolves`);
    members.add(id);
    let depth = 0;
    for (const n of (s.meta.needs as string[]) ?? []) {
      assert.ok(!seen.includes(n), `no cycle at ${n}`);
      depth = Math.max(depth, 1 + walk(n, [...seen, id], members));
    }
    return depth;
  };
  for (const id of (await load(SKILLS)).keys()) {
    const members = new Set<string>();
    const depth = walk(id, [], members);
    assert.ok(depth <= 2, `${id} needs ${depth} deep`);
    const tokens = [...members].reduce((n, i) => n + TOKENS(all.get(i)!.text), 0);
    assert.ok(tokens <= 1900, `${id} chain is ${Math.round(tokens)} tokens`);
  }
  // A needs edge is for an assumption the skill cannot do without, not for a pointer: the second-level leaves need nothing.
  for (const child of Object.keys(SECOND)) assert.deepEqual((await load(SKILLS)).get(child)!.meta.needs, [], `${child} needs nothing`);
});

test("every second-level leaf is pointed to by a leaf that says when to open it", async () => {
  const skills = await load(SKILLS);
  for (const [child, parent] of Object.entries(SECOND)) {
    const p = skills.get(parent);
    assert.ok(p, parent);
    assert.match(p.body, new RegExp(`Only (if|for)[\\s\\S]{0,320}\`${child}\``), `${parent} says when to open ${child}`);
    assert.match(skills.get(child)!.body.trim().split("\n")[0], /^Use only if /, `${child} says it is a second-level leaf`);
  }
});

test("every id the pack had, and every id another pack names, is still a skill", async () => {
  const skills = await load(SKILLS);
  for (const id of OLD_IDS) assert.ok(skills.has(id), `${id} is still a skill`);
  // Other packs name this pack's ids in prose (windows-forensics' memory skill) and in tests; each must resolve.
  const windows = await readFile(join(ROOT, "packs", "windows-forensics", "skills", "memory", "windows.md"), "utf8");
  for (const id of ["triage/volatility", "processes/injection", "strings/discipline"]) {
    assert.ok(windows.includes(`\`${id}\``) && skills.has(id), `windows-forensics names ${id}`);
  }
});

test("no rule of the review was lost in the move: the register of sentences is still in the pack", async () => {
  const skills = await load(SKILLS);
  const corpus = norm([...skills.values()].map((s) => s.body).join("\n"));
  const rules = JSON.parse(await readFile(join(ROOT, "tests", "pack-split-rules", "memory-forensics.json"), "utf8")) as Array<[string, string]>;
  assert.ok(rules.length >= 100, "the register is the whole one");
  for (const [from, frag] of rules) assert.ok(corpus.includes(frag), `from ${from}, gone: "${frag}" (moved or reworded: update tests/pack-split-rules/memory-forensics.json in the same change)`);
});

test("the rules the pack is held to are in the skills that carry them", async () => {
  const skills = await load(SKILLS);
  const body = (id: string): string => skills.get(id)!.body;
  // The Volatility offline rule stays, with the symbol rule beside it and no fetch fallback.
  assert.match(body("triage/volatility"), /vol --offline -vv -f IMAGE windows\.info/);
  assert.match(body("triage/volatility"), /Do not switch off `--offline`, and fetch nothing/);
  assert.match(body("triage/volatility"), /Never copy a symbol\s+table into a job's output/);
  assert.match(body("triage/volatility-catalogue"), /you do not run a fallback that fetches/);
  // Version facts are dated and name the version they hold for.
  for (const id of ["triage/volatility-plugins", "triage/volatility-symbols", "patterns/yara", "processes/injection", "triage/container-details"]) {
    assert.match(body(id), /as of October\s+2026/, `${id} dates its version facts`);
    assert.match(body(id), /2\.28\.2/, `${id} names the version`);
  }
  // The secret rules: the home of the rule, and a Sensitive output line wherever a secret-reaching tool or plugin is named.
  const home = body("credentials/material");
  assert.match(home, /\*\*Sensitive output\.\*\*[\s\S]*secret_output: true/);
  assert.match(home, /never a hash, digest, fingerprint or masked "shape" of a secret/);
  assert.match(home, /at most the first 4 and\s+the last 4/);
  assert.match(home, /A secret found in\s+evidence is an indicator, never a credential/);
  for (const id of ["triage/volatility", "triage/volatility-plugins", "triage/no-framework", "triage/carve-signatures", "triage/paging-files", "strings/discipline", "network/state", "patterns/yara", "processes/injection", "processes/preserve-regions", "credentials/key-schedules"]) {
    assert.match(body(id), /Sensitive output/, `${id} has a Sensitive output line`);
    assert.match(body(id), /secret_output: true/, `${id} says the job runs with secret_output: true`);
  }
  assert.match(body("credentials/key-schedules"), /record the offset and the key file's name,\s+never the key or a hash of it/);
  assert.doesNotMatch(body("credentials/key-schedules"), /carries a digest/);
  assert.match(body("credentials/key-schedules"), /take the\s+offsets and the count, not the keys/);
  // Four questions stay four; a negative is bounded.
  assert.match(home, /Four questions, each with its own evidence/);
  assert.match(body("strings/discipline"), /A hit with no locator is not evidence/);
  assert.match(body("network/timestamps-dns"), /record the route as\s+unexamined/);
});

test("the claims the review removed are not back, and the front matter lists what the body names", async () => {
  const skills = await load(SKILLS);
  const all = [...skills.values()].map((s) => s.text).join("\n");
  const banned: RegExp[] = [
    /memory is where credentials are in the clear/i,
    /sha256 to record/i,
    /record (its|the|a secret's) hash/i,
    /instant of acquisition/i,
    /page-file structures/i,
    /a snapshot is (always )?the best/i,
    /every capture is a smear/i,
    /^\s+avml\s+-/m,
    /^\s+vol(\.py)? .*\bwindows\.malfind\b/m,
    /\b(is|are|was|were) (the )?injected code\b/i,
  ];
  for (const re of banned) {
    assert.doesNotMatch(all, re, `${re} is not in the pack's skills`);
  }
  for (const s of skills.values()) {
    for (const tool of (s.meta.tools as string[]) ?? []) assert.ok(s.body.includes(tool), `${s.id} lists ${tool} and names it`);
    for (const prog of (s.meta.requires_host as string[]) ?? []) assert.ok(s.body.includes(prog), `${s.id} lists ${prog} and names it`);
  }
});

// Fields and names a skill teaches, each of which a tool must write: file -> skill -> names.
const TAUGHT: Array<[string, string, string[]]> = [
  ["tools/mem_carve/run.py", "triage/carve-signatures", ["signature_offset", "object_offset", "validation"]],
  ["tools/mem_profile/run.py", "triage/container-details", ["physical_start", "file_offset"]],
  ["tools/mem_profile/run.py", "triage/what-you-have", ["file_pages_4k_estimate"]],
  ["tools/mem_fs/run.py", "processes/preserve-regions", ["write_values", "export-manifest.jsonl"]],
];

test("the tool fields a skill names are fields the tools write", async () => {
  const skills = await load(SKILLS);
  for (const [file, skillId, names] of TAUGHT) {
    const script = await readFile(join(PACK, file), "utf8");
    const body = skills.get(skillId)?.body ?? "";
    for (const name of names) {
      assert.ok(body.includes(name), `${skillId} names ${name}`);
      const written = /^[a-z_0-9]+$/.test(name) ? script.includes(`"${name}"`) : script.includes(name);
      assert.ok(written, `${file} writes ${name}, which ${skillId} teaches`);
    }
  }
});

// ---- The router: the one entry a run shows for this pack when its index is over the run's budget. ----

const ROUTER = "memory/router";
const FAMILY = ["windows-forensics", "linux-forensics", "memory-forensics", "macos-forensics", "ransomware-response"];
// The 19 ids the pack had before the router: other packs' `needs` and text name them, and every one still resolves.
const BEFORE = [
  "acquire/avml-and-preserve", "acquire/images", "credentials/key-schedules", "credentials/material", "network/state",
  "network/timestamps-dns", "patterns/yara", "processes/injection", "processes/preserve-regions", "strings/discipline",
  "triage/carve-signatures", "triage/container-details", "triage/no-framework", "triage/paging-files", "triage/volatility",
  "triage/volatility-catalogue", "triage/volatility-plugins", "triage/volatility-symbols", "triage/what-you-have",
];

test("memory/router is the pack's only router, within 500 tokens, holds no rule, and names every other skill exactly once; every old id is alive", async () => {
  const skills = await load(SKILLS);
  const routers = [...skills.values()].filter((s) => s.meta.router === "true");
  assert.deepEqual(routers.map((s) => s.id), [ROUTER], "one router, and it is memory/router");
  const router = skills.get(ROUTER)!;
  assert.ok(TOKENS(router.text) <= 500, `the router is ${Math.round(TOKENS(router.text))} tokens`);
  assert.match(router.body.trim().split("\n")[0], /^Use when .*\bNot for\b/);
  assert.deepEqual(router.meta.tools ?? [], [], "the router names no tool");
  // No rule content: after its first line the body is group headings and lines that start with a skill id and say when to read it.
  for (const line of router.body.trim().split("\n").slice(1)) {
    if (!line.trim()) continue;
    assert.match(line, /^(`[a-z0-9-]+\/[a-z0-9-]+`|[A-Z][A-Za-z, -]{0,30}$)/, `a router line is a heading or starts with an id: ${line}`);
    assert.doesNotMatch(line, /\b(must|never|always|do not|don't|only if)\b/i, `a router holds no rule: ${line}`);
  }
  // Every other skill is named exactly once, by its whole id; none is missing and the router names nothing that is not a skill.
  const named = [...router.body.matchAll(/`([a-z0-9-]+\/[a-z0-9-]+)`/g)].map((m) => m[1]);
  assert.equal(new Set(named).size, named.length, `a skill is named twice: ${named.filter((n, i) => named.indexOf(n) !== i).join(", ")}`);
  assert.deepEqual([...named].sort(), [...skills.keys()].filter((id) => id !== ROUTER).sort());
  assert.equal(BEFORE.length, 19);
  for (const id of BEFORE) assert.ok(skills.has(id), `${id} is still a skill`);
  assert.equal(skills.size, BEFORE.length + 1, "the router is the only skill added");
  // The generated index names it as the pack's router, which is the line the harness reads.
  assert.match(await readFile(join(SKILLS, "INDEX.md"), "utf8"), /^Router: `memory\/router`$/m);
});

test("the pack index lists the entry lines of INDEX.md as the harness counts them, each at most 40 tokens (the index may pass 1,000: the pack is then shown by its router alone)", async () => {
  // Past 1,000 the harness shows the pack by its router alone in every run, the pack alone included. The budget is on the entries
  // (extensions/skills.ts readPackIndex): the file's header lines are not in it. The harness's entries are exactly the file's
  // "- `id`" lines, each counted as bytes / 4.245 rounded up, and their sum is the pack's count.
  const text = await readFile(join(SKILLS, "INDEX.md"), "utf8");
  const lines = text.split("\n").map((l) => l.trim()).filter((l) => /^- `[^`]+`/.test(l));
  const parsed = await readPackIndex(PACK);
  assert.deepEqual(parsed.entries.map((e) => e.line), lines, "the harness reads every entry line of the file, and no other");
  assert.equal(parsed.entries.length, BEFORE.length + 1);
  assert.equal(parsed.router, ROUTER);
  assert.equal(lines.reduce((n, l) => n + estimateTokens(l), 0), parsed.tokens);
  assert.ok(parsed.entries.every((e) => e.tokens <= SKILL_BUDGET.entry), "every entry is within the entry budget");
});

test("a run that carries this pack with others is over the run's index budget, and the pack's router is what lets the harness shorten the pack", async () => {
  const section = async (ids: string[], strip: string[] = []) => {
    const packs = (await readPackIndexes(ids.map((p) => join(ROOT, "packs", p)))).map((p) => (strip.includes(p.id) ? { ...p, router: null } : p));
    return renderSkillsSection(packs).report;
  };
  const BASE_ID = "computer-forensics-base";
  const profiles = JSON.parse(await readFile(join(ROOT, "images", "profiles.json"), "utf8")).profiles as Record<string, string[] | { packs: string[] }>;
  const members = (v: string[] | { packs: string[] }): string[] => (Array.isArray(v) ? v : v.packs);
  // The combinations are this pack's family (the base pack with windows, linux, memory, macos and ransomware packs) and the profiles that
  // carry the pack and are over the budget whole. Whatever the other packs have (the base pack's router, other packs' routers), these
  // do not change: only the family's own indexes are counted for the run being over, and only this pack's router for this pack.
  const combos: Array<[string, string[]]> = [
    ["a family combination", [BASE_ID, "windows-forensics", "linux-forensics", "memory-forensics"]],
    ["the full profile", [...new Set([BASE_ID, ...members(profiles.full!)])]],
  ];
  for (const [label, ids] of combos) {
    assert.ok(ids.includes("memory-forensics"), `${label} carries the pack`);
    const whole = await section(ids);
    assert.ok(whole.index_tokens > SKILL_BUDGET.run, `${label}: the whole index is ${whole.index_tokens} tokens, over the run's ${SKILL_BUDGET.run}; that is what makes the router the entry shown`);
    const mine = whole.packs.find((p) => p.id === "memory-forensics")!;
    assert.equal(mine.shown, "router", `${label}: the pack is shown by its router`);
    assert.equal(mine.router, ROUTER);
    assert.ok(!whole.no_router.includes("memory-forensics"), `${label}: the pack can be shortened`);
    // Without the router the harness cannot shorten the pack: it is shown whole, and the report names it.
    const without = await section(ids, ["memory-forensics"]);
    const bare = without.packs.find((p) => p.id === "memory-forensics")!;
    assert.equal(bare.shown, "full", `${label}: without its router the pack is shown whole`);
    assert.ok(without.no_router.includes("memory-forensics"), `${label}: without its router the report names the pack as one that cannot be shortened`);
    const routerLine = (await readPackIndex(PACK)).entries.find((e) => e.id === ROUTER)!.tokens;
    assert.equal(without.shown_tokens - whole.shown_tokens, mine.tokens - routerLine, `${label}: the section grows by the pack's index minus its router line`);
  }
  // The family on its own: with the family's routers the section fits the run's budget, without them it does not (the base pack's router, if it has one, is no help:
  // the family's indexes alone are over the budget).
  const family = [BASE_ID, ...FAMILY.filter((p) => ["windows-forensics", "linux-forensics", "memory-forensics"].includes(p) || p === "memory-forensics")];
  const fits = await section(family);
  assert.ok(fits.shown_tokens <= SKILL_BUDGET.run, `with the routers the section is ${fits.shown_tokens} tokens`);
  const bare = await section(family, FAMILY);
  assert.ok(bare.shown_tokens > SKILL_BUDGET.run, `without the family's routers the section is ${bare.shown_tokens} tokens, over the run's ${SKILL_BUDGET.run}`);
});
