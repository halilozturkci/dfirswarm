/**
 * mobile-forensics: the skills are held to the size and shape rules for a skill leaf (a leaf is at most 800
 * tokens, estimated as bytes / 4.245, and 300 lines; it opens with "Use when ... Not for ..."; `needs` is at
 * most two deep; an index entry is at most 40 tokens), they say what an artefact shows, what it does not and
 * what to record, and the tool and recipe fields they name are fields those really write, so a skill cannot
 * keep teaching a field a tool no longer has. The overclaims the review found are not in them.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { routerChecks } from "./pack-router-checks.ts";
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

// The pack's one router: shown alone when a run's index is over budget, and names every other skill once (routerChecks below).
const ROUTER = "mobile/router";

test("every skill is a leaf within the budget, opens with Use when ... Not for ..., and has a short index entry", async () => {
  const skills = await load(SKILLS);
  assert.equal(skills.size, 11);
  for (const s of skills.values()) {
    assert.ok(TOKENS(s.text) <= (s.id === ROUTER ? 400 : 800), `${s.id} is ${Math.round(TOKENS(s.text))} tokens`);
    assert.ok(s.text.split("\n").length <= 300, `${s.id} lines`);
    const first = s.body.trim().split("\n")[0];
    assert.match(first, /^Use (when|only if) /, `${s.id} opens with Use when`);
    assert.match(first, /\bNot for\b/, `${s.id} says what it is not for`);
    const entry = `- \`${s.id}\` ${s.meta.title}: ${s.meta.when}`;
    assert.ok(TOKENS(entry) <= 40, `${s.id} index entry is ${Math.round(TOKENS(entry))} tokens`);
    // The router reads no artefact: it names notes and holds no rule, so it has none of the four parts.
    if (s.id === ROUTER) continue;
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
  ["tools/sqlite_freespace/run.py", "apps/fragments", ["write_values", "sqlite-freespace-values.jsonl", "offset_verified", "block_offset", "all_results", "corrupt", "partial", "problems", "scanned"]],
  ["tools/sqlite_freespace/run.py", "apps/databases", ["scanned"]],
  ["tools/manifest_db/run.py", "extractions/backup-detail", ["epoch", "IsEncrypted", "Status.plist", "Info.plist", "not_encrypted", "unknown", "completion", "SnapshotState", "not_finished", "consistency"]],
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
      // A field is a key or a value in the code, quoted; a file or a program name is only in the text.
      const written = /^[a-z_]+$/.test(name) ? script.includes(`"${name}"`) : script.includes(name);
      assert.ok(written, `${file} writes ${name}, which ${skillId} teaches`);
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
    /What is encrypted is the content of the files/i,
    /Does not show:[^\n]*when the backup was made(?! \()/i,
    /fragments_found_before_filter/,
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

test("an example that runs a LEAPP program makes its output directory first, since the programs refuse one that does not exist", async () => {
  const skills = await load(SKILLS);
  assert.match(skills.get("ios/artifacts")!.body, /mkdir -p "\$OUT\/ileapp" && ileapp /);
  assert.match(skills.get("android/artifacts")!.body, /mkdir -p "\$OUT\/aleapp" && aleapp /);
});

test("the skills say what the backup date, the completion state, KnowledgeC and plist_read's output are", async () => {
  const skills = await load(SKILLS);
  const detail = skills.get("extractions/backup-detail")!.body;
  assert.match(detail, /^Shows:[^\n]*backup date its plists record/m, "the backup date is shown (Manifest.plist Date, Info.plist Last Backup Date)");
  assert.match(detail, /`completion` is `finished`, `not_finished` or `unknown`/);
  assert.match(detail, /31-year shift/);
  assert.match(detail, /depends on the build that made it/);
  const ios = skills.get("ios/artifacts")!.body;
  assert.match(ios, /\*\*KnowledgeC\*\*[^\n]*Do not carry a macOS stream's meaning or retention to iOS/);
  assert.match(ios, /prints a binary value as a size, a digest and a preview, and a string in clear: check what yours prints/);
  assert.match(skills.get("ios/biome-segb")!.body, /with `path`, `offset` and `length` at the payload \(never `hex`/);
  assert.match(skills.get("location/sources")!.body, /manifest_db/);
});

test("the goal's extraction-kind check is one awk, not a pipe: a long answer 1 cannot end a grep -q early and fail it", async () => {
  // The harness runs a check under `set -euo pipefail`; `awk ... | grep -q` fails with SIGPIPE (141) when awk still has output to write
  // after grep found its match, which happens for an answer 1 of some tens of kilobytes.
  const goal = await readFile(join(PACK, "goals", "phone-examination.md"), "utf8");
  const checks = /^## Checks\n([\s\S]*?)(?=^#{1,6} |(?![\s\S]))/m.exec(goal)![1];
  const line = checks.split("\n").filter((l) => /^- `awk /.test(l)).map((l) => /`([^`]+)`/.exec(l)![1]);
  assert.equal(line.length, 1);
  assert.doesNotMatch(line[0], /report\.md\s*\||\|\s*grep/, "nothing is piped");
  const dir = await mkdtemp(join(tmpdir(), "goal-"));
  try {
    await mkdir(join(dir, "work"));
    const run = (): Promise<number | null> => new Promise((resolve) => {
      const child = spawn("bash", ["-c", `set -euo pipefail; eval "$CHECK"`], { cwd: dir, env: { ...process.env, CHECK: line[0] }, stdio: "ignore" });
      child.on("close", resolve);
    });
    const filler = "A line of the answer that names no kind of extraction at all.\n".repeat(4000);
    // The kind is named on the first line of a 250 KB answer 1: found, however much follows.
    await writeFile(join(dir, "work", "report.md"), `## 1. The extraction\nA full file system extraction.\n${filler}## 2. Next\n`);
    for (let i = 0; i < 5; i++) assert.equal(await run(), 0, `try ${i}`);
    // The kind is named only in a later answer: not found, however the words match there.
    await writeFile(join(dir, "work", "report.md"), `## 1. The extraction\nUnknown.\n## 2. Next\nA backup, physical and logical.\n`);
    assert.notEqual(await run(), 0);
    // Case does not matter.
    await writeFile(join(dir, "work", "report.md"), `## 1. The extraction\nAn APP EXPORT only.\n## 2. Next\n`);
    assert.equal(await run(), 0);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("the split pass: apps/fragments is a second-level leaf reached by a pointer, not by needs, so no chain of the pack passes 1,900 tokens", async () => {
  const skills = await load(SKILLS);
  assert.deepEqual(skills.get("apps/fragments")!.meta.needs, []);
  const all = new Map([...(await load(BASE_SKILLS)), ...(await load(MACOS_SKILLS)), ...skills]);
  for (const id of skills.keys()) {
    const seen = new Set<string>();
    const walk = (x: string): void => { if (seen.has(x)) return; seen.add(x); for (const n of ((all.get(x)?.meta.needs as string[]) ?? [])) walk(n); };
    walk(id);
    const total = [...seen].reduce((n, i) => n + TOKENS(all.get(i)?.text ?? ""), 0);
    assert.ok(total <= 1900, `${id} chain is ${Math.round(total)} tokens`);
  }
});

// ---- The router: the one entry a run shows for this pack when its index is over the run's budget. ----

routerChecks({
  pack: "mobile-forensics",
  router: ROUTER,
  before: [
    "android/artifacts", "apps/databases", "apps/fragments", "extractions/backup-detail", "extractions/what-you-have", "ios/artifacts",
    "ios/biome-segb", "ios/containers-and-time", "ios/unified-logs", "location/sources",
  ],
  profiles: ["mobile", "full"],
});

// A leaf must not present decryption as something a job does while the pack has no tool that decrypts.

/** The clauses of a text that say a job, a tool or a recipe decrypts, and do not say that it does not. */
function decryptionClaims(text: string): string[] {
  const found: string[] = [];
  for (const clause of text.split(/[.;:\n]/)) {
    const actor = /\b(job|jobs|tool|tools|recipe|recipes|run|runs)\b[^.;]*\bdecrypt(s|ed|ing)?\b|\bdecrypt(s|ed|ing)?\b[^.;]*\b(job|jobs|tool|tools|recipe|recipes)\b/i.test(clause);
    const denied = /\b(no|not|never|cannot|can't|nor|without|neither|nothing|none)\b/i.test(clause);
    if (actor && !denied) found.push(clause.trim());
  }
  return found;
}

test("no leaf of the pack presents decryption as something a job does, unless a tool of the pack declares a decrypting mode", async () => {
  // backup-detail ended "A job that decrypts or reads keychain content runs with `secret_output: true`": the pack decrypts nothing (README: no decryption),
  // so read with the rest of the leaf the sentence could be taken as a route. The rule turns itself off when a tool declares a decrypting parameter.
  const decrypting: string[] = [];
  for (const entry of await readdir(join(PACK, "tools"), { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    const manifest = JSON.parse(await readFile(join(PACK, "tools", entry.name, "manifest.json"), "utf8")) as { params?: Record<string, unknown> };
    for (const param of Object.keys(manifest.params ?? {})) if (/decrypt|password|passcode|keybag|unlock/i.test(param)) decrypting.push(`${entry.name}.${param}`);
  }
  // The rule itself: it finds the old sentence, and it lets a denial and an unrelated mention through.
  assert.equal(decryptionClaims("A job that decrypts or reads keychain content runs with `secret_output: true`.").length, 1);
  assert.equal(decryptionClaims("The recipe decrypts the payload. A tool decrypted it.").length, 2);
  assert.equal(decryptionClaims("No job here decrypts; one that reads keychain content runs with `secret_output: true`.").length, 0);
  assert.equal(decryptionClaims("This tool does not decrypt anything. Decryption is for the operator.").length, 0);
  if (decrypting.length) return;      // a tool of the pack decrypts: what a leaf says about it is for that tool's own tests
  const skills = await load(SKILLS);
  for (const s of skills.values()) {
    assert.deepEqual(decryptionClaims(s.body), [], `${s.id} presents decryption as a job's action, and no tool of the pack decrypts`);
  }
});
