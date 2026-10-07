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
    for (const part of ["Shows", "Does not show", "Record"]) assert.match(s.body, new RegExp(`${part}:`), `${s.id} has ${part}`);
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
