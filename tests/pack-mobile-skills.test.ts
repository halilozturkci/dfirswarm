/**
 * mobile-forensics: the skills are held to the size and shape rules for a skill leaf (a leaf is at most 800
 * tokens, estimated as bytes / 4.245, and 300 lines; it opens with "Use when ... Not for ..."; `needs` is at
 * most two deep; an index entry is at most 40 tokens), they say what an artefact shows, what it does not and
 * what to record, and the tool and recipe fields they name are fields those really write, so a skill cannot
 * keep teaching a field a tool no longer has. The overclaims the review found are not in them.
 */
import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { ROOT } from "./tool-library-harness.ts";

const PACK = join(ROOT, "packs", "mobile-forensics");
const SKILLS = join(PACK, "skills");
const BASE_SKILLS = join(ROOT, "packs", "computer-forensics-base", "skills");
const MACOS_SKILLS = join(ROOT, "packs", "macos-forensics", "skills");
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

test("every skill is a leaf within the budget, opens with Use when ... Not for ..., and has a short index entry", async () => {
  const skills = await load(SKILLS);
  assert.equal(skills.size, 10);
  for (const s of skills.values()) {
    assert.ok(TOKENS(s.text) <= 800, `${s.id} is ${Math.round(TOKENS(s.text))} tokens`);
    assert.ok(s.text.split("\n").length <= 300, `${s.id} lines`);
    const first = s.body.trim().split("\n")[0];
    assert.match(first, /^Use (when|only if) /, `${s.id} opens with Use when`);
    assert.match(first, /\bNot for\b/, `${s.id} says what it is not for`);
    const entry = `- \`${s.id}\` ${s.meta.title}: ${s.meta.when}`;
    assert.ok(TOKENS(entry) <= 40, `${s.id} index entry is ${Math.round(TOKENS(entry))} tokens`);
    for (const part of ["Shows", "Does not show", "Record", "Sensitive output"]) {
      if (part === "Sensitive output" && s.id === "apps/fragments") continue;
      assert.match(s.body, new RegExp(`^${part}:`, "m"), `${s.id} has ${part}`);
    }
  }
  const index = await readFile(join(SKILLS, "INDEX.md"), "utf8");
  for (const id of skills.keys()) assert.ok(index.includes(`\`${id}\``), `${id} is in the index`);
});

test("needs is at most two deep and its chain is at most 2,000 tokens, counting the base skills it reaches", async () => {
  const all = new Map([...(await load(BASE_SKILLS)), ...(await load(MACOS_SKILLS)), ...(await load(SKILLS))]);
  const chain = (id: string, seen: string[] = []): { depth: number; ids: string[] } => {
    const s = all.get(id);
    assert.ok(s, `${id} resolves`);
    const needs = (s.meta.needs as string[]) ?? [];
    let best = { depth: 0, ids: [id] };
    for (const n of needs) {
      assert.ok(!seen.includes(n), `no cycle at ${n}`);
      const sub = chain(n, [...seen, id]);
      if (sub.depth + 1 > best.depth) best = { depth: sub.depth + 1, ids: [id, ...sub.ids] };
    }
    return best;
  };
  for (const id of (await load(SKILLS)).keys()) {
    const { depth, ids } = chain(id);
    assert.ok(depth <= 2, `${id} needs ${depth} deep: ${ids.join(" > ")}`);
    const total = new Set(ids.flatMap((i) => [i, ...(((all.get(i)?.meta.needs as string[]) ?? []))]));
    const tokens = [...total].reduce((n, i) => n + TOKENS(all.get(i)?.text ?? ""), 0);
    assert.ok(tokens <= 2000, `${id} chain is ${Math.round(tokens)} tokens`);
  }
});

test("every second-level leaf is pointed to by a leaf that says when to open it", async () => {
  const skills = await load(SKILLS);
  const pointers: Record<string, string> = {
    "extractions/backup-detail": "extractions/what-you-have",
    "apps/fragments": "apps/databases",
    "ios/containers-and-time": "ios/artifacts",
  };
  for (const [child, parent] of Object.entries(pointers)) {
    const p = skills.get(parent);
    assert.ok(p, parent);
    const at = p.body.indexOf(`\`${child}\``);
    assert.ok(at >= 0, `${parent} points to ${child}`);
    assert.match(p.body.slice(Math.max(0, at - 220), at + 80), /[Oo]nly if|fetch|you must|for how to read/, `${parent} says when to open ${child}`);
    assert.match(skills.get(child)!.body.trim().split("\n")[0], /^Use only if /, `${child} says it is a second-level leaf`);
  }
});

// Fields and names a skill teaches, each of which a tool or a recipe must write or read: file -> skill -> names.
const TAUGHT: Array<[string, string, string[]]> = [
  ["tools/sqlite_freespace/run.py", "apps/fragments", ["write_values", "sqlite-freespace-values.jsonl", "offset_verified", "block_offset", "fragments_found_before_filter", "all_results", "corrupt", "partial", "problems", "scanned"]],
  ["tools/sqlite_freespace/run.py", "apps/databases", ["scanned"]],
  ["tools/manifest_db/run.py", "extractions/backup-detail", ["epoch", "IsEncrypted", "Status.plist", "Info.plist", "not_encrypted", "unknown"]],
  ["tools/protobuf_peek/run.py", "ios/biome-segb", ["write_values"]],
  ["recipes/ios-ileapp/run.py", "ios/artifacts", ["modules.tsv", "errors_logged", "no_record", "errored", "unknown"]],
  ["recipes/android-aleapp/run.py", "android/artifacts", ["modules.tsv", "errors_logged", "no_record", "errored", "unknown"]],
  ["recipes/android-backup/run.py", "extractions/backup-detail", ["payload_stream", "tar_end"]],
  ["recipes/ios-filesystem/run.py", "extractions/what-you-have", ["sqlite.tsv"]],
];

test("the tool and recipe fields a skill names are fields they write", async () => {
  const skills = await load(SKILLS);
  for (const [file, skillId, names] of TAUGHT) {
    const script = await readFile(join(PACK, file), "utf8");
    const body = skills.get(skillId)?.body ?? "";
    for (const name of names) {
      assert.ok(body.includes(name), `${skillId} names ${name}`);
      assert.ok(script.includes(name), `${file} has ${name}, which ${skillId} teaches`);
    }
  }
});

test("the claims the review found are not in the skills, and the front matter lists what the body names", async () => {
  const skills = await load(SKILLS);
  const all = [...skills.values()].map((s) => s.text).join("\n");
  const banned: RegExp[] = [
    /A logical extraction cannot answer a question about deletion/i,
    /the extraction is\s+inert: say so and stop/i,
    /newest messages are (the ones )?in the WAL/i,
    /Photo EXIF is the strongest/i,
    /received in a message carries the sender's coordinates, not the holder's/i,
    /a phone that joined a named network was within its range/i,
    /installer field usually decides/i,
    /`timestamp_decode`[^.]*settles a bare number/i,
    /`sms\.db` keeps deleted messages/i,
    /Permissions are the capability list/i,
    /iOS 19/i,
    /\bsay so and stop\b/i,
  ];
  for (const re of banned) assert.doesNotMatch(all, re);
  // The tools and programs a body names in code are in its front matter.
  for (const s of skills.values()) {
    const listed = new Set([...(s.meta.tools as string[]), ...(s.meta.requires_host as string[])]);
    for (const name of ["manifest_db", "sqlite_freespace", "sqlite_query", "protobuf_peek", "plist_read", "timestamp_decode", "unified_log", "file_type", "exiftool", "ileapp", "aleapp", "unifiedlog_iterator"]) {
      const named = new RegExp("`" + name + "[ `]").test(s.body);
      if (named) assert.ok(listed.has(name), `${s.id} names ${name} but does not list it`);
    }
  }
});
