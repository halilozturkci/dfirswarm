/**
 * windows-forensics: the skills are held to the size and shape rules of a skill leaf (a leaf is at most 800 tokens,
 * estimated as bytes / 4.245, and 300 lines; it opens with "Use when ... Not for ..."; `needs` is at most two deep and its
 * chain at most 2,000 tokens; an index entry is at most 40 tokens), the tool fields they name are fields the tools really
 * write, every id they point to exists, and the claims the review took apart stay gone.
 */
import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { alwaysBlock, alwaysProblems } from "./pack-router-checks.ts";
import { estimateTokens, readPackIndex, readPackIndexes, renderSkillsSection, SKILL_BUDGET } from "../extensions/skills.ts";
import { ROOT } from "./tool-library-harness.ts";
import { TAUGHT as TAUGHT_A } from "./windows-skills-taught-registry.ts";
import { TAUGHT as TAUGHT_B } from "./windows-skills-taught-execution.ts";
import { TAUGHT as TAUGHT_C } from "./windows-skills-taught-filesystem.ts";
import { TAUGHT as TAUGHT_D } from "./windows-skills-taught-logs.ts";
import { TAUGHT as TAUGHT_E } from "./windows-skills-taught-artifacts.ts";

const PACK = join(ROOT, "packs", "windows-forensics");
const SKILLS = join(PACK, "skills");
const TOOLS = join(PACK, "tools");
const BASE = join(ROOT, "packs", "computer-forensics-base");
const TOKENS = (text: string): number => Buffer.byteLength(text) / 4.245;

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

const OLD_IDS = [
  "accounts/logons", "antiforensics/traces", "artifacts/shell", "browser/artefacts", "execution/amcache", "execution/overview", "execution/prefetch",
  "execution/srum", "execution/userassist", "filesystem/ads", "filesystem/deleted", "filesystem/journals", "filesystem/mft", "filesystem/shadowcopies",
  "logs/hunting", "logs/powershell", "logs/recovery", "logs/remote-access", "logs/security", "memory/windows", "persistence/mechanisms",
  "registry/devices", "registry/overview", "registry/system-profile",
];

test("every skill is a leaf within the budget, opens with Use when ... Not for ..., has Shows, Does not show and Record, and a short index entry", async () => {
  const skills = await load(SKILLS);
  for (const id of OLD_IDS) assert.ok(skills.has(id), `${id} is still a skill`);
  assert.ok(skills.size >= OLD_IDS.length);
  for (const s of skills.values()) {
    assert.ok(TOKENS(s.text) <= 800, `${s.id} is ${Math.round(TOKENS(s.text))} tokens`);
    assert.ok(s.text.split("\n").length <= 300, `${s.id} lines`);
    const first = s.body.trim().split("\n")[0];
    assert.match(first, /^Use when /, `${s.id} opens with Use when`);
    assert.match(first, /\bNot for\b/, `${s.id} says what it is not for`);
    const entry = `- \`${s.id}\` ${s.meta.title}: ${s.meta.when}`;
    assert.ok(TOKENS(entry) <= 40, `${s.id} index entry is ${Math.round(TOKENS(entry))} tokens`);
    // The router reads no artefact: it names notes and holds no rule, so it shows nothing.
    if (s.id !== ROUTER) for (const part of ["Shows", "Does not show", "Record"]) assert.match(s.body, new RegExp(`${part}:`), `${s.id} has ${part}`);
  }
  const index = await readFile(join(SKILLS, "INDEX.md"), "utf8");
  for (const id of skills.keys()) assert.ok(index.includes(`\`${id}\``), `${id} is in the index`);
});

test("needs is at most two deep, never reaches a base skill, and its chain is at most 2,000 tokens", async () => {
  const mine = await load(SKILLS);
  const all = new Map([...(await load(join(BASE, "skills"))), ...mine]);
  const chain = (id: string, seen: string[] = []): { depth: number; ids: string[] } => {
    const s = all.get(id);
    assert.ok(s, `${id} resolves`);
    let best = { depth: 0, ids: [id] };
    for (const n of (s.meta.needs as string[]) ?? []) {
      assert.ok(!seen.includes(n), `no cycle at ${n}`);
      const sub = chain(n, [...seen, id]);
      if (sub.depth + 1 > best.depth) best = { depth: sub.depth + 1, ids: [id, ...sub.ids] };
    }
    return best;
  };
  for (const s of mine.values()) {
    for (const n of (s.meta.needs as string[]) ?? []) assert.ok(mine.has(n), `${s.id} needs ${n}, which is not in this pack (a base skill is three deep: point to it in the body)`);
    const { depth, ids } = chain(s.id);
    assert.ok(depth <= 2, `${s.id} needs ${depth} deep: ${ids.join(" > ")}`);
    const reached = new Set<string>();
    const walk = (id: string): void => { if (reached.has(id)) return; reached.add(id); for (const n of (all.get(id)!.meta.needs as string[]) ?? []) walk(n); };
    walk(s.id);
    const tokens = [...reached].reduce((n, i) => n + TOKENS(all.get(i)!.text), 0);
    assert.ok(tokens <= 2000, `${s.id} chain is ${Math.round(tokens)} tokens`);
  }
});

test("every second-level leaf is pointed to by the leaf it needs, with words that say when to open it", async () => {
  const skills = await load(SKILLS);
  for (const s of skills.values()) {
    for (const parent of (s.meta.needs as string[]) ?? []) {
      const p = skills.get(parent)!;
      const windows = [...p.body.matchAll(new RegExp(`\`${s.id}\``, "g"))].map((m) => p.body.slice(Math.max(0, (m.index ?? 0) - 200), (m.index ?? 0) + 200));
      assert.ok(windows.length > 0, `${parent} points to ${s.id}`);
      assert.ok(windows.some((w) => /[Oo]nly if|read it before|before you quote|when you need|if you need/.test(w)), `${parent} says when to open ${s.id}`);
    }
  }
});

test("every skill id a body points to exists in this pack or the base pack, or is a conditional memory-pack id", async () => {
  const skills = await load(SKILLS);
  const base = await load(join(BASE, "skills"));
  const memory = new Set(["strings/discipline", "processes/injection", "triage/volatility"]);
  for (const s of skills.values()) {
    for (const m of s.body.matchAll(/`([a-z][a-z0-9-]*\/[a-z0-9][a-z0-9-]*)`/g)) {
      const id = m[1];
      if (/^(work|inputs|store|ledger|tool-output|traces|goals|skills)\//.test(id)) continue;
      assert.ok(skills.has(id) || base.has(id) || memory.has(id), `${s.id} points to \`${id}\`, which is no skill`);
    }
  }
});

async function toolSource(tool: string, dir = TOOLS): Promise<string> {
  return (await readFile(join(dir, tool, "run.py"), "utf8")) + (await readFile(join(dir, tool, "manifest.json"), "utf8"));
}

test("the tool fields and flags a skill names are ones its tool writes or reads", async () => {
  const skills = await load(SKILLS);
  for (const [tool, skillId, names] of [...TAUGHT_A, ...TAUGHT_B, ...TAUGHT_C, ...TAUGHT_D, ...TAUGHT_E]) {
    const script = await toolSource(tool);
    const body = skills.get(skillId)?.body ?? "";
    for (const name of names) {
      assert.ok(body.includes(name), `${skillId} names ${name}`);
      assert.ok(script.includes(name), `${tool} has ${name}, which ${skillId} teaches`);
    }
  }
});

test("every backticked snake_case name in a skill is a name a tool of the pack or the base pack has, or is on the short list of other things", async () => {
  const skills = await load(SKILLS);
  let source = "";
  for (const dir of [TOOLS, join(BASE, "tools"), join(ROOT, "tool-library")]) for (const t of await readdir(dir)) source += await toolSource(t, dir).catch(() => "");
  source += await readFile(join(ROOT, "prompts", "worker-system.md"), "utf8");
  // Names of things that are not fields of these tools: other packs' tools and fields, Windows and Volatility names, the harness's own.
  const OTHER = new Set(["mem_profile", "mem_fs", "tsk_recover", "visit_source", "downloads_url_chains", "secret_output", "job_run", "work_dir"]);
  for (const s of skills.values()) {
    for (const m of s.body.matchAll(/`([a-z][a-z0-9]*(?:_[a-z0-9]+)+)`/g)) {
      const name = m[1];
      assert.ok(OTHER.has(name) || source.includes(name), `${s.id} names \`${name}\`, which no tool of the pack has`);
    }
  }
});

test("the claims the review took apart are gone, no skill states a version fact or a credential recipe, and secret handling is stated where a tool can reach one", async () => {
  const skills = await load(SKILLS);
  const GONE: RegExp[] = [
    /adjacent RIDs? (?:are|is|mean)s? an? (?:attacker|malicious)/i, /the SID (?:in the Recycle Bin )?(?:says|shows|tells) who deleted/i,
    /\$LogFile (?:records|is) (?:an independent|the wall)/i, /number of missing events/i, /ranked? (?:strongest|weakest)/i,
    /from Windows 8 onwards/i, /31,457,280/, /never a value, a fragment or a hash/i, /\bimpacket\b|\bdpapick3\b|credential-stores/i,
    /Windows 10 and later layout/i,
  ];
  for (const s of skills.values()) {
    for (const re of GONE) assert.doesNotMatch(s.body, re, `${s.id} still carries ${re}`);
    assert.doesNotMatch(s.body, /\b(?:as of|since) (?:Windows )?(?:20|19)\d\d\b|\b[Ww]indows (?:10|11|8|7)\b.*\b(?:always|never|only)\b/, `${s.id} states a version fact`);
  }
  for (const s of skills.values()) {
    for (const t of (s.meta.tools as string[]) ?? []) {
      const manifest = await readFile(join(TOOLS, t, "manifest.json"), "utf8").catch(() => "");
      // A tool whose manifest asks for a job with secret_output returns content that can be one; extract_stream, which never prints, does not.
      if (/SENSITIVE:[^]*secret_output|SENSITIVE:[^]*withhold/.test(manifest)) assert.match(s.body, /secret_output: true|withhold|locators? only/, `${s.id} names ${t}, which can reach a secret, and says how it is handled`);
    }
  }
});

// ---- What the skills and the README say about withholding, and how a found secret is described. ----

// A tool "can reach a secret" when its manifest declares secret_output: the job that writes values must be a secret job.
async function secretTools(): Promise<Set<string>> {
  const out = new Set<string>();
  for (const e of await readdir(TOOLS, { withFileTypes: true })) {
    if (!e.isDirectory()) continue;
    const manifest = JSON.parse(await readFile(join(TOOLS, e.name, "manifest.json"), "utf8"));
    if ("secret_output" in manifest) out.add(e.name);
  }
  return out;
}
const namedTools = (skill: Skill, tools: Set<string>): string[] =>
  [...tools].filter((t) => ((skill.meta.tools as string[]) ?? []).includes(t) || skill.body.includes("`" + t + "`"));
const SENSITIVE_LINE = /^(?:- )?(?:\*\*)?Sensitive output/;

test("every leaf that names a tool able to reach a secret says how to describe a found secret: where it sits, kind, length, what it grants, never its value, a fragment or a digest", async () => {
  const skills = await load(SKILLS);
  const tools = await secretTools();
  assert.ok(tools.size >= 10, "the tools that declare secret_output were found");
  const FOUND = /\bdescribe a found secret by where it sits\b[^.]*\bkind\b[^.]*\blength\b[^.]*\bgrants\b[^.]*\bnever\b[^.]*\bvalue\b[^.]*\bfragment\b[^.]*\b(?:digest|hash)\b/i;
  let checked = 0;
  for (const s of skills.values()) {
    if (namedTools(s, tools).length === 0) continue;
    checked++;
    assert.match(s.body, FOUND, `${s.id} names a tool that can reach a secret and does not say how to describe a found secret`);
  }
  assert.ok(checked >= 40, `${checked} leaves were checked`);
});

test("a Sensitive-output line that names lnk_parse, lnk_jumplist, yara_scan, browser_history, utf16_urls or jumplist says what its withholding goes by and that what it does not cover is printed", async () => {
  const skills = await load(SKILLS);
  const SIX = /`(?:lnk_parse|lnk_jumplist|yara_scan|browser_history|utf16_urls|jumplist)`/;
  let lines = 0;
  for (const s of skills.values()) {
    for (const line of s.body.split("\n")) {
      if (!SENSITIVE_LINE.test(line) || !SIX.test(line)) continue;
      lines++;
      assert.match(line, /\bprinted\b/, `${s.id}: its Sensitive-output line names the tool and does not say what is printed`);
      assert.match(line, /\b(?:by shape|by name|name and shape|by parameter name|out of the answer)\b/i, `${s.id}: its Sensitive-output line does not say what the withholding goes by`);
    }
  }
  assert.ok(lines >= 6, `${lines} lines were checked`);
});

test("the README does not say a tool prints none of a secret, and says the withholding is by shape or by name", async () => {
  const readme = (await readFile(join(PACK, "README.md"), "utf8")).replace(/\s+/g, " ");
  assert.doesNotMatch(readme, /print none of it/i);
  assert.match(readme, /by shape or by name, not wholesale, so a secret of another shape is printed/);
});

test("the six leaves that read a file system or a Prefetch structure have a Sensitive-output line, and no skill calls the adversary an operator", async () => {
  const skills = await load(SKILLS);
  for (const id of ["filesystem/indx", "filesystem/journals", "filesystem/recycle-bin", "filesystem/shadowcopies", "execution/prefetch", "execution/prefetch-carved"]) {
    const s = skills.get(id)!;
    assert.ok(s.body.split("\n").some((l) => SENSITIVE_LINE.test(l)), `${id} has a Sensitive-output line`);
  }
  for (const s of skills.values()) assert.doesNotMatch(s.body, /\boperator\b/i, `${s.id} says "operator": write the attacker or the intruder`);
});

// ---- The router: the one entry a run shows for this pack when its index is over the run's budget. ----

const ROUTER = "windows/router";
const FAMILY = ["windows-forensics", "linux-forensics", "memory-forensics", "macos-forensics", "ransomware-response"];
// The 52 ids the pack had before the router: other packs' `needs` and text name them, and every one still resolves.
const BEFORE = [
  "accounts/logons", "accounts/sessions", "antiforensics/controls", "antiforensics/log-clearing", "antiforensics/timestamps-clock",
  "antiforensics/traces", "antiforensics/wiping", "artifacts/jumplists", "artifacts/links", "artifacts/shell", "artifacts/shellbags",
  "browser/artefacts", "browser/downloads", "browser/strings", "browser/webcache", "execution/amcache", "execution/esedb",
  "execution/overview", "execution/prefetch", "execution/prefetch-carved", "execution/shimcache", "execution/srum",
  "execution/userassist", "filesystem/ads", "filesystem/deleted", "filesystem/indx", "filesystem/journals", "filesystem/mft",
  "filesystem/recycle-bin", "filesystem/shadowcopies", "filesystem/shadowcopies-open", "filesystem/timestamps", "logs/carving",
  "logs/coverage", "logs/events", "logs/hunting", "logs/lateral", "logs/powershell", "logs/powershell-history", "logs/recovery",
  "logs/remote-access", "logs/security", "memory/hibernation-pagefile", "memory/windows", "persistence/mechanisms",
  "persistence/tasks-com-wmi", "registry/clock", "registry/devices", "registry/devices-dates", "registry/overview",
  "registry/readers", "registry/system-profile",
];

test("windows/router is the pack's only router, within its limit, holds no rule outside its Always block, and names every other skill exactly once; every old id is alive", async () => {
  const skills = await load(SKILLS);
  const routers = [...skills.values()].filter((s) => s.meta.router === "true");
  assert.deepEqual(routers.map((s) => s.id), [ROUTER], "one router, and it is windows/router");
  const router = skills.get(ROUTER)!;
  assert.ok(TOKENS(router.text) <= 500, `the router is ${Math.round(TOKENS(router.text))} tokens`);
  assert.match(router.body.trim().split("\n")[0], /^Use when .*\bNot for\b/);
  assert.deepEqual(router.meta.tools ?? [], [], "the router names no tool");
  // No rule content: after its first line the body is group headings and lines that start with a skill id and say when to read it.
  // The Always block (docs/packs.md "Routers") holds the rules every note holds; the routing lines hold none.
  const { routing, rules } = alwaysBlock(router.body.trim());
  assert.deepEqual(alwaysProblems(rules), []);
  for (const line of routing.trim().split("\n").slice(1)) {
    if (!line.trim()) continue;
    assert.match(line, /^(`[a-z0-9-]+\/[a-z0-9-]+`|[A-Z][A-Za-z, -]{0,30}$)/, `a router line is a heading or starts with an id: ${line}`);
    assert.doesNotMatch(line, /\b(must|never|always|do not|don't|only if)\b/i, `a router holds no rule: ${line}`);
  }
  // Every other skill is named exactly once, by its whole id; none is missing and the router names nothing that is not a skill.
  const named = [...router.body.matchAll(/`([a-z0-9-]+\/[a-z0-9-]+)`/g)].map((m) => m[1]);
  assert.equal(new Set(named).size, named.length, `a skill is named twice: ${named.filter((n, i) => named.indexOf(n) !== i).join(", ")}`);
  assert.deepEqual([...named].sort(), [...skills.keys()].filter((id) => id !== ROUTER).sort());
  assert.equal(BEFORE.length, 52);
  for (const id of BEFORE) assert.ok(skills.has(id), `${id} is still a skill`);
  assert.equal(skills.size, BEFORE.length + 1, "the router is the only skill added");
  // The generated index names it as the pack's router, which is the line the harness reads.
  assert.match(await readFile(join(SKILLS, "INDEX.md"), "utf8"), /^Router: `windows\/router`$/m);
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
    assert.ok(ids.includes("windows-forensics"), `${label} carries the pack`);
    const whole = await section(ids);
    assert.ok(whole.index_tokens > SKILL_BUDGET.run, `${label}: the whole index is ${whole.index_tokens} tokens, over the run's ${SKILL_BUDGET.run}; that is what makes the router the entry shown`);
    const mine = whole.packs.find((p) => p.id === "windows-forensics")!;
    assert.equal(mine.shown, "router", `${label}: the pack is shown by its router`);
    assert.equal(mine.router, ROUTER);
    assert.ok(!whole.no_router.includes("windows-forensics"), `${label}: the pack can be shortened`);
    // Without the router the harness cannot shorten the pack: it is shown whole, and the report names it.
    const without = await section(ids, ["windows-forensics"]);
    const bare = without.packs.find((p) => p.id === "windows-forensics")!;
    assert.equal(bare.shown, "full", `${label}: without its router the pack is shown whole`);
    assert.ok(without.no_router.includes("windows-forensics"), `${label}: without its router the report names the pack as one that cannot be shortened`);
    const routerLine = (await readPackIndex(PACK)).entries.find((e) => e.id === ROUTER)!.tokens;
    // Collapsed, the pack shows its router and the core notes the budget had room for (docs/packs.md "Routers"); whole, every line.
    const coreLines = (await readPackIndex(PACK)).entries.filter((e) => (mine.core_shown ?? []).includes(e.id)).reduce((n, e) => n + e.tokens, 0);
    assert.ok(without.shown_tokens > whole.shown_tokens, `${label}: shown whole the pack takes more of the section`);
    assert.ok(mine.tokens - routerLine - coreLines > 0, `${label}: collapsed, the pack leaves out what is not its router or core`);
  }
  // The family on its own: with the family's routers the section fits the run's budget, without them it does not (the base pack's router, if it has one, is no help:
  // the family's indexes alone are over the budget).
  const family = [BASE_ID, ...FAMILY.filter((p) => ["windows-forensics", "linux-forensics", "memory-forensics"].includes(p) || p === "windows-forensics")];
  const fits = await section(family);
  assert.ok(fits.shown_tokens <= SKILL_BUDGET.run, `with the routers the section is ${fits.shown_tokens} tokens`);
  const bare = await section(family, FAMILY);
  assert.ok(bare.shown_tokens > SKILL_BUDGET.run, `without the family's routers the section is ${bare.shown_tokens} tokens, over the run's ${SKILL_BUDGET.run}`);
});

test("the notes say what regkv answers today, and a secret browser store is read as secret output, as the base pack's note shows", async () => {
  const skills = await load(SKILLS);
  // regkv: a missing key is an answer, and a dirty hive is partial.
  const readers = skills.get("registry/readers")!.body;
  assert.match(readers, /A key not in the hive is an answer \(`found: false`, exit 0\)/);
  assert.doesNotMatch(readers, /absent is answered `ok: false`/);
  assert.match(skills.get("registry/overview")!.body, /a dirty hive answers `partial`/);
  const regkv = await toolSource("regkv");
  for (const name of ["found", "path_parts_matched", "transaction_logs_looked_for"]) assert.ok(regkv.includes(`"${name}"`), `regkv writes ${name}`);
  // sqlite_query on Login Data: the base note's own example is the table export as secret output, so this note cannot say "never".
  const strings = skills.get("browser/strings")!.body;
  assert.doesNotMatch(strings, /never on `Login Data`/);
  assert.match(strings, /`Login Data`, `Cookies`, `Web Data`, `cookies\.sqlite` and `key4\.db` are read as secret output: a job with `secret_output: true`, `table` and `write_values: true`/);
  assert.match(strings, /never an inline `sql` over the values \(the base pack's `data\/sqlite-secrets`\)/);
  const base = (await load(join(BASE, "skills"))).get("data/sqlite-secrets")!.body;
  assert.match(base, /secret_output: true/);
  assert.match(base, /"write_values": true/);
});
