/**
 * encrypted-containers: the split pass. Every skill is a leaf within the size budget (at most 800 tokens, estimated
 * as bytes / 4.245, and 300 lines; an index entry at most 40 tokens), `needs` is at most two deep and its chain
 * at most 1,900 tokens, every second-level leaf is pointed to by a leaf that says when to open it, every id the
 * pack had before the split (and every id another pack names) is still a skill, and no rule of the review was
 * lost in the move: tests/pack-split-rules/encrypted-containers.json lists, per old skill, the sentences that carry a Shows / Does not
 * show / Record / Sensitive output / bounded-negative / corroboration rule, and each must still be in the pack.
 */
import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { routerChecks } from "./pack-router-checks.ts";
import { ROOT } from "./tool-library-harness.ts";

const PACK = join(ROOT, "packs", "encrypted-containers");
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

// The decision leaves (the five ids the pack had before the split) and their second-level leaves.
const OLD_IDS = ["identify/headers", "volumes/bitlocker", "volumes/luks-filevault", "archives/protected", "keys/where-they-hide"];
const SECOND: Record<string, string> = {
  "identify/by-format": "identify/headers",
  "volumes/bitlocker-opening": "volumes/bitlocker",
  "volumes/filevault-apfs": "volumes/luks-filevault",
  "archives/formats": "archives/protected",
  "keys/recovery-key-scan": "keys/where-they-hide",
  "keys/other-sources": "keys/where-they-hide",
};

// The pack's one router: shown alone when a run's index is over budget, and names every other skill once (routerChecks below).
const ROUTER = "encrypted/router";

test("every skill is a leaf within the budget, opens with Use when ... Not for ..., and has a short index entry", async () => {
  const skills = await load(SKILLS);
  assert.equal(skills.size, OLD_IDS.length + Object.keys(SECOND).length + 1);
  for (const s of skills.values()) {
    assert.ok(TOKENS(s.text) <= (s.id === ROUTER ? 400 : 800), `${s.id} is ${Math.round(TOKENS(s.text))} tokens`);
    assert.ok(s.text.split("\n").length <= 300, `${s.id} lines`);
    const first = s.body.trim().split("\n")[0];
    assert.match(first, /^Use (when|only if) /, `${s.id} opens with Use when`);
    assert.match(first, /\bNot for\b/, `${s.id} says what it is not for`);
    const entry = `- \`${s.id}\` ${s.meta.title}: ${s.meta.when}`;
    assert.ok(TOKENS(entry) <= 40, `${s.id} index entry is ${Math.round(TOKENS(entry))} tokens`);
    // The router reads no artefact: it names notes and holds no rule, so it shows and does not show nothing.
    if (s.id !== ROUTER) assert.match(flat(s.body), /Does not show/i, `${s.id} says what it does not show`);
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
  const own = await load(SKILLS);
  for (const id of own.keys()) {
    const members = new Set<string>();
    const depth = walk(id, [], members);
    assert.ok(depth <= 2, `${id} needs ${depth} deep`);
    const tokens = [...members].reduce((n, i) => n + TOKENS(all.get(i)!.text), 0);
    assert.ok(tokens <= 1900, `${id} chain is ${Math.round(tokens)} tokens`);
  }
  // The pointers between the pack's own notes are text, not `needs`: a note reached by "only if" needs nothing.
  for (const [id, s] of own) {
    for (const n of (s.meta.needs as string[]) ?? []) assert.ok(!own.has(n), `${id} needs ${n}: point to it in the text instead`);
  }
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
  // The base pack's filesystem/encrypted names this pack's skills; they must resolve here.
  const base = await readFile(join(BASE_SKILLS, "filesystem", "encrypted.md"), "utf8");
  for (const id of ["identify/headers", "volumes/bitlocker", "volumes/luks-filevault"]) {
    if (base.includes(`\`${id}\``)) assert.ok(skills.has(id), `${id} named by the base pack`);
  }
  // Conditional pointer to the memory pack's capture skill.
  assert.match([...skills.values()].map((s) => s.body).join("\n"), /If the\s+memory-forensics pack is loaded, its `acquire\/images` skill covers capture/);
});

test("no rule of the review was lost in the move: the register of sentences is still in the pack", async () => {
  const skills = await load(SKILLS);
  const corpus = norm([...skills.values()].map((s) => s.body).join("\n"));
  const rules = JSON.parse(await readFile(join(ROOT, "tests", "pack-split-rules", "encrypted-containers.json"), "utf8")) as Array<[string, string]>;
  assert.ok(rules.length >= 60, "the register is the whole one");
  for (const [from, frag] of rules) assert.ok(corpus.includes(frag), `from ${from}, gone: "${frag}" (moved or reworded: update tests/pack-split-rules/encrypted-containers.json in the same change)`);
});

test("the secret rules: a Sensitive output line wherever a tool that reaches secret material is named, and no recovery by guessing", async () => {
  const skills = await load(SKILLS);
  const named = [...skills.values()].filter((s) => /recovery_key_scan|ioc_scan|crypto_id|archive_probe/.test(s.body));
  assert.ok(named.length >= 6);
  for (const s of named) assert.match(s.body, /Sensitive output/, `${s.id} has a Sensitive output line`);
  const keys = skills.get("keys/where-they-hide")!.body;
  assert.match(keys, /run them as jobs with `secret_output: true`/);
  assert.match(keys, /never a password, a PIN,\s+a recovery value, a fragment of one, or a hash of one/);
  assert.match(keys, /use it through a reader that takes it from a\s+sealed file, not from a command line/);
  assert.match(keys, /Holding a device, an account name or a candidate secret\s+is not authority over another account or service/);
  const scan = skills.get("keys/recovery-key-scan")!.body;
  assert.match(scan, /write_values: true/);
  assert.match(scan, /recovery-passwords\.jsonl/);
  assert.match(scan, /never write a recovery value, a fragment of one, or a hash of one/);
  assert.match(skills.get("volumes/bitlocker-opening")!.body, /Never write a\s+recovery password, a fragment of one, or a hash of one/);
  assert.match(skills.get("volumes/bitlocker-opening")!.body, /name the routes tried/);
  assert.match(flat(skills.get("volumes/luks-filevault")!.body), /Do not write that no usable key exists/);
  assert.match(skills.get("identify/headers")!.body, /`crypto_id` prints no raw bytes of the file/);
  assert.doesNotMatch([...skills.values()].map((s) => s.text).join("\n"), /include_head_hex/, "the parameter that printed key material is gone");
  assert.match(skills.get("archives/protected")!.body, /this skill does not authorise it\s+and gives no method/);
  assert.match(skills.get("archives/protected")!.body, /Never write a password, a fragment of one, or a hash of one/);
  const all = [...skills.values()].map((s) => s.text).join("\n");
  assert.doesNotMatch(all, /brute[- ]?force|dictionary attack|wordlist|hashcat|john the ripper|rainbow table|\bcrack(ing|ed)?\b/i, "no recovery-by-guessing recipe");
  assert.doesNotMatch(all, /^\s+(john|hashcat|7z [a-z] -p)/m, "no cracking command");
});

test("the claims the review removed are not back, and the front matter lists what the body names", async () => {
  const skills = await load(SKILLS);
  const all = [...skills.values()].map((s) => s.text).join("\n");
  const banned: RegExp[] = [
    /"?no scheme recognised"? (means|shows|is) not encrypted/i,
    /a slot is a (person|user)/i,
    /high entropy (identifies|means) VeraCrypt/i,
    /an apfs container signature shows that every volume is encrypted/i,
    /(a )?member list (shows|proves) (that )?(anything|data) (was )?(copied|exfiltrated)/i,
    /cannot be recovered/i,
  ];
  for (const re of banned) assert.doesNotMatch(flat(all), re, `${re} is not in the pack's skills`);
  for (const s of skills.values()) {
    for (const tool of (s.meta.tools as string[]) ?? []) assert.ok(s.body.includes(tool), `${s.id} lists ${tool} and names it`);
    for (const prog of (s.meta.requires_host as string[]) ?? []) assert.ok(s.body.includes(prog), `${s.id} lists ${prog} and names it`);
  }
});

// Fields and names a skill teaches, each of which a tool must write: file -> skill -> names.
const TAUGHT: Array<[string, string, string[]]> = [
  ["tools/crypto_id/run.py", "identify/headers", ["header_fields_withheld"]],
  ["tools/recovery_key_scan/run.py", "keys/recovery-key-scan", ["max_bytes_per_file", "write_values", "recovery-passwords.jsonl", "paths_withheld", "max_seconds"]],
  ["tools/archive_probe/run.py", "archives/protected", ["header_encrypted", "names_withheld"]],
  ["tools/archive_probe/run.py", "archives/formats", ["timezone_unknown", "modified_utc"]],
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

routerChecks({
  pack: "encrypted-containers",
  router: ROUTER,
  before: [
    "archives/formats", "archives/protected", "identify/by-format", "identify/headers", "keys/other-sources", "keys/recovery-key-scan",
    "keys/where-they-hide", "volumes/bitlocker", "volumes/bitlocker-opening", "volumes/filevault-apfs", "volumes/luks-filevault",
  ],
  profiles: ["disk", "full"],
});
