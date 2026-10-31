/**
 * linux-forensics: the skills are held to the size and shape rules for a skill leaf (a leaf is at most 800 tokens,
 * estimated as bytes / 4.245, and 300 lines; it opens with "Use when ... Not for ..." or, for a second-level leaf,
 * "Use only if ... Not for ..."; `needs` is at most two deep and its chain at most 1,900 tokens counting the base
 * skills it reaches; an index entry is at most 40 tokens), they say what an artefact shows, what it does not and what
 * to record, and the tool fields they name are fields those tools really write. The split of a long skill into a
 * decision-rule leaf and second-level leaves keeps every rule: the key rules are asserted here by their text.
 */
import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { estimateTokens, readPackIndex, readPackIndexes, renderSkillsSection, SKILL_BUDGET } from "../extensions/skills.ts";
import { ROOT } from "./tool-library-harness.ts";

const PACK = join(ROOT, "packs", "linux-forensics");
const SKILLS = join(PACK, "skills");
const BASE_SKILLS = join(ROOT, "packs", "computer-forensics-base", "skills");
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

// Every old skill id stays, as a decision-rule leaf; the second-level leaves are reached from a parent by "only if".
const OLD_IDS = [
  "accounts/users", "containers/docker", "filesystem/ext", "filesystem/storage", "logs/auth", "logs/journal",
  "packages/integrity", "persistence/mechanisms", "timeline/linux", "triage/system-profile",
];
const CHILDREN: Record<string, string> = {
  "triage/identity-files": "triage/system-profile",
  "triage/clocks-boots": "triage/system-profile",
  "accounts/sessions-histories": "accounts/users",
  "containers/layers-times": "containers/docker",
  "containers/removed-logs": "containers/docker",
  "filesystem/ext-deleted": "filesystem/ext",
  "filesystem/storage-lvm-luks": "filesystem/storage",
  "filesystem/storage-xfs-btrfs-virtual": "filesystem/storage",
  "logs/auth-lines": "logs/auth",
  "logs/auth-time": "logs/auth",
  "logs/journal-clocks-verify": "logs/journal",
  "packages/baseline": "packages/integrity",
  "persistence/cron-timers": "persistence/mechanisms",
  "persistence/quieter-routes": "persistence/mechanisms",
  "timeline/linux-normalise": "timeline/linux",
};

test("every skill is a leaf within the budget, opens with Use when/only if ... Not for ..., has a short index entry, and old ids stay", async () => {
  const skills = await load(SKILLS);
  assert.equal(skills.size, OLD_IDS.length + Object.keys(CHILDREN).length + 1, "the pack's leaves and its router");
  for (const id of OLD_IDS) assert.ok(skills.has(id), `old id ${id} is alive`);
  for (const s of skills.values()) {
    assert.ok(TOKENS(s.text) <= 800, `${s.id} is ${Math.round(TOKENS(s.text))} tokens`);
    assert.ok(s.text.split("\n").length <= 300, `${s.id} lines`);
    const first = s.body.trim().split("\n")[0];
    assert.match(first, s.id in CHILDREN ? /^Use only if / : /^Use when /, `${s.id} opens with the right Use line`);
    assert.match(first, /\bNot for\b/, `${s.id} says what it is not for`);
    const entry = `- \`${s.id}\` ${s.meta.title}: ${s.meta.when}`;
    assert.ok(TOKENS(entry) <= 40, `${s.id} index entry is ${Math.round(TOKENS(entry))} tokens`);
    // The router reads no artefact: it names notes and holds no rule, so it shows nothing.
    if (s.id !== ROUTER) for (const part of ["Shows", "Does not show", "Record", "Sensitive output"]) {
      assert.match(s.body, new RegExp(`(^|\\. )${part}:`, "m"), `${s.id} has ${part}`);
    }
  }
  const index = await readFile(join(SKILLS, "INDEX.md"), "utf8");
  for (const id of skills.keys()) assert.ok(index.includes(`\`${id}\``), `${id} is in the index`);
});

test("needs is at most two deep and its chain is at most 1,900 tokens, counting the base skills it reaches", async () => {
  const all = new Map([...(await load(BASE_SKILLS)), ...(await load(SKILLS))]);
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
  const closure = (id: string, acc: Set<string> = new Set()): Set<string> => {
    acc.add(id);
    for (const n of (all.get(id)?.meta.needs as string[]) ?? []) closure(n, acc);
    return acc;
  };
  for (const id of (await load(SKILLS)).keys()) {
    const { depth, ids } = chain(id);
    assert.ok(depth <= 2, `${id} needs ${depth} deep: ${ids.join(" > ")}`);
    const tokens = [...closure(id)].reduce((n, i) => n + TOKENS(all.get(i)?.text ?? ""), 0);
    assert.ok(tokens <= 1900, `${id} chain is ${Math.round(tokens)} tokens`);
  }
});

test("every second-level leaf is pointed to by its parent with an 'only if' that says when to open it", async () => {
  const skills = await load(SKILLS);
  for (const [child, parent] of Object.entries(CHILDREN)) {
    const p = skills.get(parent);
    assert.ok(p, parent);
    const at = p.body.indexOf(`\`${child}\``);
    assert.ok(at >= 0, `${parent} points to ${child}`);
    assert.match(p.body.slice(Math.max(0, at - 260), at + 120), /[Oo]nly (if|once)|read with/, `${parent} says when to open ${child}`);
  }
});

// Fields and names a skill teaches, each of which a tool must write or read: tool -> skill -> names.
const TAUGHT: Array<[string, string, string[]]> = [
  ["auth_log", "logs/auth", ["order_basis", "cross_file_order", "year_basis", "write_text", "preview_text"]],
  ["auth_log", "logs/auth-time", ["year_basis", "time_raw", "time_utc", "time_zone", "rollovers", "rollover_lines", "reordered", "unparsed", "read_errors", "all_lines_parsed", "max_seconds"]],
  ["auth_log", "logs/auth-lines", ["user_bytes", "user_withheld"]],
  ["journal_export", "logs/journal", ["boots", "realtime_us", "monotonic_us", "native_line", "oversized_lines", "write_text", "preview_text", "journal-native.jsonl"]],
  ["journal_export", "logs/journal-clocks-verify", ["verify"]],
  ["utmp_parse", "accounts/sessions-histories", ["layout", "byte_order"]],
  ["shell_history", "accounts/sessions-histories", ["write_commands"]],
  ["linux_triage", "triage/system-profile", ["execution_complete", "coverage", "parsed"]],
  ["cron_dump", "persistence/cron-timers", ["unsupported", "write_text"]],
];

test("the tool fields a skill names are fields the tools write", async () => {
  const skills = await load(SKILLS);
  for (const [tool, skillId, names] of TAUGHT) {
    const script = await readFile(join(PACK, "tools", tool, "run.py"), "utf8");
    const body = skills.get(skillId)?.body ?? "";
    for (const name of names) {
      assert.ok(body.includes(name), `${skillId} names ${name}`);
      assert.ok(script.includes(name), `${tool} writes ${name}, which ${skillId} teaches`);
    }
  }
});

test("the front matter lists the tools of the pack that the body names, and only those", async () => {
  const skills = await load(SKILLS);
  const tools = (await readdir(join(PACK, "tools"))).filter((n) => !n.startsWith("."));
  for (const s of skills.values()) {
    const listed = new Set(s.meta.tools as string[]);
    for (const name of tools) {
      const named = new RegExp("(^|[^A-Za-z0-9_-])" + name + "([^A-Za-z0-9_-]|$)").test(s.body);
      assert.equal(listed.has(name), named, `${s.id}: ${name} ${named ? "is named but not listed" : "is listed but not named"}`);
    }
  }
});

test("the rules the split keeps: observation against verdict, bounded negatives, how the tools' status field is described", async () => {
  const skills = await load(SKILLS);
  const has = (id: string, re: RegExp): void => assert.match(skills.get(id)!.body.replace(/\s+/g, " "), re, `${id}: ${re}`);
  has("triage/system-profile", /`execution_complete` says the processes exited 0, which is not coverage/);
  has("triage/system-profile", /Treat an `empty` result as a parser's result, not as an absence/);
  has("triage/identity-files", /say the installation date is not determinable/);
  has("triage/clocks-boots", /a reboot that left no record in one source is not shown not to have happened/);
  has("triage/clocks-boots", /not from `\/etc\/timezone` alone/);
  has("accounts/users", /not to every root command/);
  has("accounts/users", /who was at the keyboard, or that a command ran/);
  has("accounts/sessions-histories", /a session with no end record is not shown to be open/);
  has("containers/docker", /that a risky configuration was exploited/);
  has("containers/removed-logs", /do not let a missing Docker directory clear the other runtimes/);
  has("filesystem/ext", /a lead and not a timestomping diagnosis/);
  has("filesystem/ext-deleted", /Do not write that contents are unrecoverable on the strength of an inode and a journal search/);
  has("filesystem/storage", /Do not call an unreadable partition damaged until you have identified the layer at its offset/);
  has("filesystem/storage-lvm-luks", /Header inspection does not show who owns a key slot/);
  has("logs/auth", /report a disagreement as a question with the alternatives, not as a finding/);
  has("logs/auth-time", /`status` is `complete` only where `all_lines_parsed` is true, which says every line matched a syslog shape and every file was read through, nothing more/);
  has("logs/auth-lines", /a person; for `publickey`, only a key/);
  has("logs/journal", /It does not show the historical storage policy/);
  has("logs/journal-clocks-verify", /A clean result does not authenticate an unsealed journal/);
  has("packages/integrity", /Run no verification script from the evidence/);
  has("packages/baseline", /a clean report is not a clean machine/);
  has("persistence/mechanisms", /No candidate matching these mechanisms was identified in these sources over this period/);
  has("persistence/cron-timers", /so an empty result there is not a negative/);
  has("timeline/linux", /a clean run is no evidence of RPM, newer accounting or full container coverage/);
  has("timeline/linux-normalise", /An empty parser result supports an absence only when/);
});

test("a skill that can reach secrets says the job runs with secret_output and cites a locator, never a value, a fragment or a hash", async () => {
  const skills = await load(SKILLS);
  for (const id of ["accounts/users", "accounts/sessions-histories", "logs/auth", "logs/journal", "persistence/mechanisms", "persistence/cron-timers", "timeline/linux", "triage/system-profile"]) {
    const body = skills.get(id)!.body;
    assert.match(body, /secret_output/, `${id} names secret_output`);
    assert.match(body, /(never|no) [^.]*(hash|value)/i, `${id} forbids a value or hash`);
  }
});

test("no skill states a distribution default it cannot source", async () => {
  const all = [...(await load(SKILLS)).values()].map((s) => s.body).join("\n");
  assert.doesNotMatch(all, /\b(Ubuntu|Debian|Red Hat|RHEL|Fedora|CentOS)\b[^.\n]{0,40}\b(defaults? to|by default)\b/i);
});

// ---- The router: the one entry a run shows for this pack when its index is over the run's budget. ----

const ROUTER = "linux/router";
const FAMILY = ["windows-forensics", "linux-forensics", "memory-forensics", "macos-forensics", "ransomware-response"];
// The 25 ids the pack had before the router: other packs' `needs` and text name them, and every one still resolves.
const BEFORE = [
  "accounts/sessions-histories", "accounts/users", "containers/docker", "containers/layers-times", "containers/removed-logs",
  "filesystem/ext", "filesystem/ext-deleted", "filesystem/storage", "filesystem/storage-lvm-luks", "filesystem/storage-xfs-btrfs-virtual",
  "logs/auth", "logs/auth-lines", "logs/auth-time", "logs/journal", "logs/journal-clocks-verify", "packages/baseline",
  "packages/integrity", "persistence/cron-timers", "persistence/mechanisms", "persistence/quieter-routes", "timeline/linux",
  "timeline/linux-normalise", "triage/clocks-boots", "triage/identity-files", "triage/system-profile",
];

test("linux/router is the pack's only router, within 500 tokens, holds no rule, and names every other skill exactly once; every old id is alive", async () => {
  const skills = await load(SKILLS);
  const routers = [...skills.values()].filter((s) => s.meta.router === "true");
  assert.deepEqual(routers.map((s) => s.id), [ROUTER], "one router, and it is linux/router");
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
  assert.equal(BEFORE.length, 25);
  for (const id of BEFORE) assert.ok(skills.has(id), `${id} is still a skill`);
  assert.equal(skills.size, BEFORE.length + 1, "the router is the only skill added");
  // The generated index names it as the pack's router, which is the line the harness reads.
  assert.match(await readFile(join(SKILLS, "INDEX.md"), "utf8"), /^Router: `linux\/router`$/m);
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
    assert.ok(ids.includes("linux-forensics"), `${label} carries the pack`);
    const whole = await section(ids);
    assert.ok(whole.index_tokens > SKILL_BUDGET.run, `${label}: the whole index is ${whole.index_tokens} tokens, over the run's ${SKILL_BUDGET.run}; that is what makes the router the entry shown`);
    const mine = whole.packs.find((p) => p.id === "linux-forensics")!;
    assert.equal(mine.shown, "router", `${label}: the pack is shown by its router`);
    assert.equal(mine.router, ROUTER);
    assert.ok(!whole.no_router.includes("linux-forensics"), `${label}: the pack can be shortened`);
    // Without the router the harness cannot shorten the pack: it is shown whole, and the report names it.
    const without = await section(ids, ["linux-forensics"]);
    const bare = without.packs.find((p) => p.id === "linux-forensics")!;
    assert.equal(bare.shown, "full", `${label}: without its router the pack is shown whole`);
    assert.ok(without.no_router.includes("linux-forensics"), `${label}: without its router the report names the pack as one that cannot be shortened`);
    const routerLine = (await readPackIndex(PACK)).entries.find((e) => e.id === ROUTER)!.tokens;
    assert.equal(without.shown_tokens - whole.shown_tokens, mine.tokens - routerLine, `${label}: the section grows by the pack's index minus its router line`);
  }
  // The family on its own: with the family's routers the section fits the run's budget, without them it does not (the base pack's router, if it has one, is no help:
  // the family's indexes alone are over the budget).
  const family = [BASE_ID, ...FAMILY.filter((p) => ["windows-forensics", "linux-forensics", "memory-forensics"].includes(p) || p === "linux-forensics")];
  const fits = await section(family);
  assert.ok(fits.shown_tokens <= SKILL_BUDGET.run, `with the routers the section is ${fits.shown_tokens} tokens`);
  const bare = await section(family, FAMILY);
  assert.ok(bare.shown_tokens > SKILL_BUDGET.run, `without the family's routers the section is ${bare.shown_tokens} tokens, over the run's ${SKILL_BUDGET.run}`);
});
