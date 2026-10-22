/**
 * macos-forensics: the skills are held to the size and shape rules for a skill leaf (a leaf is at most 800 tokens,
 * estimated as bytes / 4.245, and 300 lines; it opens with "Use when ... Not for ..." or, for a second-level leaf,
 * "Use only if ... Not for ..."; `needs` is at most two deep and its chain at most 1,900 tokens counting the base
 * skills it reaches; an index entry is at most 40 tokens). They say what an artefact shows, what it does not and what
 * to record, and the tool fields they name are fields those tools really write. The split of a long skill into a
 * decision-rule leaf and second-level leaves keeps every rule: the key rules are asserted here by their text.
 */
import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { estimateTokens, readPackIndex, readPackIndexes, renderSkillsSection, SKILL_BUDGET } from "../extensions/skills.ts";
import { ROOT } from "./tool-library-harness.ts";

const PACK = join(ROOT, "packs", "macos-forensics");
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
  "accounts/users", "artifacts/fsevents", "artifacts/knowledgec", "artifacts/plists", "filesystem/apfs",
  "logs/unified", "persistence/mechanisms", "triage/system-profile",
];
const CHILDREN: Record<string, string> = {
  "triage/clocks-hardware": "triage/system-profile",
  "accounts/attribution-remote": "accounts/users",
  "artifacts/plists-archives-dates": "artifacts/plists",
  "artifacts/fsevents-dating": "artifacts/fsevents",
  "artifacts/knowledgec-fields-time": "artifacts/knowledgec",
  "filesystem/apfs-recovery": "filesystem/apfs",
  "filesystem/apfs-encryption": "filesystem/apfs",
  "logs/unified-readers": "logs/unified",
  "persistence/login-items-quieter": "persistence/mechanisms",
};
// The leaves that can reach secret material say so; the rest point to them.
const SECRET_LEAVES = ["accounts/users", "artifacts/plists", "artifacts/knowledgec", "artifacts/fsevents", "logs/unified", "persistence/mechanisms", "triage/system-profile"];

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
    if (s.id === ROUTER) continue;
    assert.match(s.body, /\b(Shows|Does not show)[.:]/, `${s.id} says what it shows or does not show`);
    assert.match(s.body, /Does not show[.:*]/, `${s.id} has Does not show`);
    if (SECRET_LEAVES.includes(s.id)) assert.match(s.body, /Sensitive output/, `${s.id} has Sensitive output`);
  }
  const index = await readFile(join(SKILLS, "INDEX.md"), "utf8");
  for (const id of skills.keys()) assert.ok(index.includes(`\`${id}\``), `${id} is in the index`);
});

test("needs is at most two deep and its chain is at most 1,900 tokens, counting the base skills it reaches", async () => {
  const all = new Map([...(await load(BASE_SKILLS)), ...(await load(SKILLS))]);
  const closure = (id: string, depth: number, acc: Map<string, number>): void => {
    const s = all.get(id);
    assert.ok(s, `${id} resolves`);
    assert.ok(depth <= 2, `${id} is reached ${depth} deep`);
    acc.set(id, depth);
    for (const n of (s.meta.needs as string[]) ?? []) {
      assert.ok(!acc.has(n) || acc.get(n)! < depth + 1, `no cycle at ${n}`);
      closure(n, depth + 1, acc);
    }
  };
  for (const id of (await load(SKILLS)).keys()) {
    const acc = new Map<string, number>();
    closure(id, 0, acc);
    const tokens = [...acc.keys()].reduce((n, i) => n + TOKENS(all.get(i)?.text ?? ""), 0);
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
    assert.match(p.body.slice(Math.max(0, at - 260), at + 160), /[Oo]nly if/, `${parent} says when to open ${child}`);
  }
});

// Fields and names a skill teaches, each of which a tool must write or read: tool -> skill -> names.
const TAUGHT: Array<[string, string, string[]]> = [
  ["plist_read", "artifacts/plists", ["extracted_file_mtime", "write_values"]],
  ["knowledgec_query", "artifacts/knowledgec", ["source_used", "problems", "filters_unapplied"]],
  ["knowledgec_query", "artifacts/knowledgec-fields-time", ["value_type_code", "utc_offset_seconds", "export_oversize", "_truncated", "_where", "_hex", "max_seconds", "resume", "resume_since"]],
  ["fsevents_parse", "artifacts/fsevents", ["files_by_state", "flags_undecoded", "coverage", "problems", "status_basis", "max_seconds", "not_attempted", "contains_blind_records", "write_values"]],
  ["unified_log", "logs/unified", ["decoded_coverage", "support_files", "problems", "warnings", "status_basis", "reader_outcome"]],
  ["unified_log", "logs/unified-readers", ["reader", "timeout_seconds", "budget"]],
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

test("the rules the split keeps: observation against verdict, bounded negatives, the secret boundary, APFS and TCC limits", async () => {
  const skills = await load(SKILLS);
  const has = (id: string, re: RegExp): void => assert.match(skills.get(id)!.body.replace(/\s+/g, " "), re, `${id}: ${re}`);
  has("triage/system-profile", /A set of files is not a volume/);
  has("triage/system-profile", /there is no `BuildVersion`/);
  has("triage/system-profile", /it is not a record of installation/);
  has("triage/system-profile", /a packaging limit that says nothing about the subject's hardware/);
  has("triage/clocks-hardware", /applying the zone to them shifts them twice/);
  has("triage/clocks-hardware", /Report a serial number only when its source identifies this Mac/);
  has("accounts/users", /Membership at acquisition does not show membership at an earlier event/);
  has("accounts/users", /It is not a password-change, account-creation, login or key-installation event/);
  has("accounts/users", /never its bytes, a preview or a hash/);
  has("accounts/attribution-remote", /they do not show keyboard input or physical presence, in a row or alone/);
  has("accounts/attribution-remote", /Naming a person needs case evidence the artefacts here do not supply/);
  has("accounts/attribution-remote", /it does not show that the host was reachable, that the key was accepted, or that anyone logged in/);
  has("artifacts/plists", /Neither the file's mtime nor a clean shutdown establishes that/);
  has("artifacts/plists", /never a value, a fragment or a hash of one/);
  has("artifacts/plists-archives-dates", /a plausible date is not proof that the epoch is the field's/);
  has("artifacts/fsevents", /A zero count, an empty `problems` list or an exit of 0 is not a finished examination/);
  has("artifacts/fsevents", /no matching record was decoded from these files, by this parser and filter/);
  has("artifacts/fsevents-dating", /Event ids \(printed by `fsevents_parse`\) order records; they do not date them/);
  has("artifacts/fsevents-dating", /One anchor bounds the interval on one side/);
  has("artifacts/knowledgec", /keep apart "not retained", "not acquired", "unsupported" and "searched, no match"/);
  has("artifacts/knowledgec", /Does not show: keyboard input, physical presence, attention, intent or who the human was/);
  has("artifacts/knowledgec-fields-time", /do not read creation \(ingestion\) time as the time of the activity/);
  has("filesystem/apfs", /write "snapshot coverage unavailable", not "no snapshots"/);
  has("filesystem/apfs-recovery", /there is no NTFS-style `\$MFT` does not mean there is no recoverable history/);
  has("filesystem/apfs-encryption", /`fvdeinfo` is for Core Storage; it is not assumed to read APFS/);
  has("logs/unified", /Complete is not a coverage claim/);
  has("logs/unified", /the reader's whole output named in `output` is not judged and holds every message as decoded/);
  has("artifacts/knowledgec", /That is by shape: a plain password, a passphrase, a UUID-shaped key, a BitLocker key or anything under 16 characters in a name is printed/);
  has("artifacts/fsevents", /a plain password, a BitLocker key or an ordinary-looking name is printed/);
  has("artifacts/plists", /A file that does not parse is a row with the kind of error and its place, never the file's text/);
  has("logs/unified", /not proof that everything between them was recorded/);
  has("logs/unified-readers", /It does not bring back an entry that was never persisted, was removed by retention or was redacted/);
  has("persistence/mechanisms", /an agent loaded at login has not shown its program ran then/);
  has("persistence/mechanisms", /which no key-name pattern in `plist_read` catches/);
  has("persistence/login-items-quieter", /A registration is not execution/);
  has("persistence/login-items-quieter", /do not read an Accessibility permission as root or SYSTEM, or a TCC row's modified time as the time of a grant/);
});

test("a skill that can reach secrets says the job runs with secret_output and cites a locator, never a value, a fragment or a hash", async () => {
  const skills = await load(SKILLS);
  for (const id of ["accounts/users", "artifacts/plists", "persistence/mechanisms", "triage/system-profile"]) {
    const body = skills.get(id)!.body;
    assert.match(body, /secret_output/, `${id} names secret_output`);
    assert.match(body, /(never|no) [^.]*(hash|value|bytes)/i, `${id} forbids a value or hash`);
  }
});

test("no skill states an Apple version fact it cannot source, and the APFS time fact stays a Unix epoch", async () => {
  const all = [...(await load(SKILLS)).values()].map((s) => s.body).join("\n");
  assert.doesNotMatch(all, /\b(macOS|OS X|Mac OS X) ?(1[0-9]|2[0-9]|[0-9])(\.\d+)?\b/);
  assert.doesNotMatch(all, /\b(Sonoma|Ventura|Sequoia|Monterey|Big Sur|Catalina|Mojave|Tahoe)\b/);
  assert.match(all, /nanoseconds since the Unix epoch, not the Apple epoch/);
});

// ---- The router: the one entry a run shows for this pack when its index is over the run's budget. ----

const ROUTER = "macos/router";
const FAMILY = ["windows-forensics", "linux-forensics", "memory-forensics", "macos-forensics", "ransomware-response"];
// The 17 ids the pack had before the router: other packs' `needs` and text name them, and every one still resolves.
const BEFORE = [
  "accounts/attribution-remote", "accounts/users", "artifacts/fsevents", "artifacts/fsevents-dating", "artifacts/knowledgec",
  "artifacts/knowledgec-fields-time", "artifacts/plists", "artifacts/plists-archives-dates", "filesystem/apfs", "filesystem/apfs-encryption",
  "filesystem/apfs-recovery", "logs/unified", "logs/unified-readers", "persistence/login-items-quieter", "persistence/mechanisms",
  "triage/clocks-hardware", "triage/system-profile",
];

test("macos/router is the pack's only router, within 400 tokens, holds no rule, and names every other skill exactly once; every old id is alive", async () => {
  const skills = await load(SKILLS);
  const routers = [...skills.values()].filter((s) => s.meta.router === "true");
  assert.deepEqual(routers.map((s) => s.id), [ROUTER], "one router, and it is macos/router");
  const router = skills.get(ROUTER)!;
  assert.ok(TOKENS(router.text) <= 400, `the router is ${Math.round(TOKENS(router.text))} tokens`);
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
  assert.equal(BEFORE.length, 17);
  for (const id of BEFORE) assert.ok(skills.has(id), `${id} is still a skill`);
  assert.equal(skills.size, BEFORE.length + 1, "the router is the only skill added");
  // The generated index names it as the pack's router, which is the line the harness reads.
  assert.match(await readFile(join(SKILLS, "INDEX.md"), "utf8"), /^Router: `macos\/router`$/m);
});

test("the pack index is at most 1,000 tokens counted as the harness counts it: the entry lines of INDEX.md, not the whole file", async () => {
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
  assert.ok(parsed.tokens <= SKILL_BUDGET.pack, `the pack index is ${parsed.tokens} tokens of entries, over ${SKILL_BUDGET.pack}`);
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
    ["a family combination", [BASE_ID, "windows-forensics", "linux-forensics", "memory-forensics", "macos-forensics"]],
    ["the full profile", [...new Set([BASE_ID, ...members(profiles.full!)])]],
  ];
  for (const [label, ids] of combos) {
    assert.ok(ids.includes("macos-forensics"), `${label} carries the pack`);
    const whole = await section(ids);
    assert.ok(whole.index_tokens > SKILL_BUDGET.run, `${label}: the whole index is ${whole.index_tokens} tokens, over the run's ${SKILL_BUDGET.run}; that is what makes the router the entry shown`);
    const mine = whole.packs.find((p) => p.id === "macos-forensics")!;
    assert.equal(mine.shown, "router", `${label}: the pack is shown by its router`);
    assert.equal(mine.router, ROUTER);
    assert.ok(!whole.no_router.includes("macos-forensics"), `${label}: the pack can be shortened`);
    // Without the router the harness cannot shorten the pack: it is shown whole, and the report names it.
    const without = await section(ids, ["macos-forensics"]);
    const bare = without.packs.find((p) => p.id === "macos-forensics")!;
    assert.equal(bare.shown, "full", `${label}: without its router the pack is shown whole`);
    assert.ok(without.no_router.includes("macos-forensics"), `${label}: without its router the report names the pack as one that cannot be shortened`);
    const routerLine = (await readPackIndex(PACK)).entries.find((e) => e.id === ROUTER)!.tokens;
    assert.equal(without.shown_tokens - whole.shown_tokens, mine.tokens - routerLine, `${label}: the section grows by the pack's index minus its router line`);
  }
  // The family on its own: with the family's routers the section fits the run's budget, without them it does not (the base pack's router, if it has one, is no help:
  // the family's indexes alone are over the budget).
  const family = [BASE_ID, ...FAMILY.filter((p) => ["windows-forensics", "linux-forensics", "memory-forensics"].includes(p) || p === "macos-forensics")];
  const fits = await section(family);
  assert.ok(fits.shown_tokens <= SKILL_BUDGET.run, `with the routers the section is ${fits.shown_tokens} tokens`);
  const bare = await section(family, FAMILY);
  assert.ok(bare.shown_tokens > SKILL_BUDGET.run, `without the family's routers the section is ${bare.shown_tokens} tokens, over the run's ${SKILL_BUDGET.run}`);
});
