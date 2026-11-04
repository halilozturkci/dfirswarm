/**
 * computer-forensics-base: the skills are held to the size and shape rules for a skill leaf (a leaf is at most
 * 800 tokens, estimated as bytes / 4.245, and 300 lines; it opens with "Use when ... Not for ..."; `needs` is at
 * most two deep and its chain at most 1,900 tokens; an index entry is at most 40 tokens), they say what an
 * artefact shows, does not show and what to record, the tools and programs a body names are in its front matter,
 * and the field names they teach are fields the tools really write, so a skill cannot keep teaching a field a
 * tool no longer has. The overclaims the review found, and the ones the split pass could bring back, are not in
 * them, and every id another pack reaches through `needs` is still a skill of this pack.
 */
import assert from "node:assert/strict";
import { mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { estimateTokens, readPackIndex, readPackIndexes, renderSkillsSection, SKILL_BUDGET } from "../extensions/skills.ts";
import { ROOT, runPy, runPySnippet } from "./tool-library-harness.ts";

const PACK = join(ROOT, "packs", "computer-forensics-base");
const SKILLS = join(PACK, "skills");
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

// The second-level leaves: each is pointed to by the leaf that says when to open it, and opens with "Use only if".
const SECOND_LEVEL: Record<string, string> = {
  "filesystem/scanners": "filesystem/carving",
  "filesystem/encrypted-metadata": "filesystem/encrypted",
  "timeline/super-scope": "timeline/super",
  "filesystem/layers-mapping": "filesystem/layers",
  "timeline/clocks-drift": "timeline/clocks",
  "data/sqlite-secrets": "data/sqlite",
};

// The pack's one router: it is shown alone when a run's index is over budget, and names every other skill once.
const ROUTER = "base/router";

// Skills whose tools can put secrets, credentials or private text in front of the agent: each has a Sensitive output part.
const SENSITIVE = [
  "data/browser-storage", "data/documents-media", "data/sqlite", "data/sqlite-secrets", "filesystem/carving", "filesystem/encrypted", "filesystem/encrypted-metadata", "filesystem/extract",
  "filesystem/scanners", "filesystem/semantics", "timeline/super", "evidence/archives",
];

// The skills added by Phase 2b; each has the full set of parts.
const NEW = [
  "evidence/scope", "evidence/provenance", "evidence/coverage", "evidence/tool-validation", "timeline/clocks",
  "filesystem/semantics", "filesystem/layers", "data/documents-media",
];

// A leaf is at most 800 tokens (a warning above, a refusal above 1,000) and the router at most 400. The three leaves the review of
// #133 left above 800 (layers, sqlite, clocks) were split into second-level leaves, so no leaf has a ceiling of its own any more.
const LEAF_MAX = 800;
const ROUTER_MAX = 400;

test("every skill is a leaf within the budget, opens with Use when ... Not for ..., and has a short index entry", async () => {
  const skills = await load(SKILLS);
  assert.equal(skills.size, 30);
  for (const s of skills.values()) {
    assert.ok(TOKENS(s.text) <= (s.id === ROUTER ? ROUTER_MAX : LEAF_MAX), `${s.id} is ${Math.round(TOKENS(s.text))} tokens`);
    assert.ok(TOKENS(s.text) <= 1000, `${s.id} is over the 1,000 a skill may have`);
    assert.ok(s.text.split("\n").length <= 300, `${s.id} lines`);
    const first = s.body.trim().split("\n")[0];
    assert.match(first, /^Use (when|only if) /, `${s.id} opens with Use when`);
    assert.match(first, /\bNot for\b/, `${s.id} says what it is not for`);
    if (s.id in SECOND_LEVEL) assert.match(first, /^Use only if /, `${s.id} says it is a second-level leaf`);
    const entry = `- \`${s.id}\` ${s.meta.title}: ${s.meta.when}`;
    assert.ok(TOKENS(entry) <= 40, `${s.id} index entry is ${Math.round(TOKENS(entry))} tokens`);
    // The two reporting leaves are method leaves about the ledger's acts: they read no artefact, so they show nothing.
    // The router reads no artefact either: it names notes and holds no rule.
    if (!s.id.startsWith("reporting/") && s.id !== ROUTER) assert.match(s.body, /\*\*Does not show\.\*\*/, `${s.id} has a Does not show part`);
  }
  const index = await readFile(join(SKILLS, "INDEX.md"), "utf8");
  for (const id of skills.keys()) assert.ok(index.includes(`\`${id}\``), `${id} is in the index`);
  // The pack budget is the harness's own count of the index entries (extensions/skills.ts), not the file's size: past it a pack shows its router only.
  const parsed = await readPackIndex(PACK);
  assert.equal(parsed.entries.length, 30);
  assert.ok(parsed.tokens <= SKILL_BUDGET.pack, `the pack index is ${Math.round(parsed.tokens)} tokens of entries`);
});

test("the base pack index is at most 1,000 tokens counted as the harness counts it: the entry lines of INDEX.md, not the whole file", async () => {
  // Past 1,000 the harness shows the base pack by its router alone in every run, the base pack alone included. The budget is on the
  // entries (extensions/skills.ts readPackIndex): the file's header lines (the title, the fetch sentence, the Router: line) are not
  // in it, so the whole file is larger than the count and is not the measure. This test holds the two measures consistent: the
  // harness's entries are exactly the file's "- `id`" lines, each counted as bytes / 4.245 rounded up, and their sum is the pack's count.
  const text = await readFile(join(SKILLS, "INDEX.md"), "utf8");
  const lines = text.split("\n").map((l) => l.trim()).filter((l) => /^- `[^`]+`/.test(l));
  const parsed = await readPackIndex(PACK);
  assert.deepEqual(parsed.entries.map((e) => e.line), lines, "the harness reads every entry line of the file, and no other");
  const sum = lines.reduce((n, l) => n + estimateTokens(l), 0);
  assert.equal(sum, parsed.tokens, "the entries, counted line by line, are the harness's count");
  assert.ok(lines.every((l) => estimateTokens(l) === Math.ceil(TOKENS(l))), "each line is its bytes / 4.245, rounded up");
  assert.ok(parsed.tokens <= SKILL_BUDGET.pack, `the base pack index is ${parsed.tokens} tokens of entries, over ${SKILL_BUDGET.pack}`);
  assert.ok(TOKENS(text) > parsed.tokens, "the whole file, header included, is more than its entries");
});

test("the new skills say what to record, and the skills whose tools can surface secrets have a Sensitive output part", async () => {
  const skills = await load(SKILLS);
  for (const id of NEW) {
    const s = skills.get(id);
    assert.ok(s, id);
    assert.match(s.body, /\*\*Record\.\*\*/, `${id} says what to record`);
  }
  for (const id of SENSITIVE) assert.match(skills.get(id)!.body, /\*\*Sensitive output\.\*\*/, `${id} has Sensitive output`);
  // The phrase is the worker prompt's: a job that may read a secret runs with secret_output: true.
  const prompt = await readFile(join(ROOT, "prompts", "worker-system.md"), "utf8");
  assert.match(prompt, /runs with `secret_output: true`/);
  for (const id of ["data/sqlite", "data/sqlite-secrets", "data/documents-media", "filesystem/scanners", "filesystem/encrypted-metadata", "filesystem/extract", "filesystem/semantics"]) {
    assert.match(skills.get(id)!.body, /`secret_output: true`/, `${id} says secret_output: true`);
  }
  // The skill about hashes writes the secret-digest exception, and the SQLite one keeps a short BLOB's digest out of the ledger.
  assert.match(skills.get("evidence/provenance")!.body, /A digest of a secret is not/);
  assert.match(skills.get("data/sqlite-secrets")!.body, /never the value, a fragment of it, or the `sha256` and base64 of a short BLOB/);
  // The parent cites the row's locator, not `rowid`: on an INTEGER PRIMARY KEY table the rowid is the value (review of #144).
  assert.match(skills.get("data/sqlite")!.body, /run the query as a job with `secret_output: true` and cite table, row locator and column, never the value/);
  assert.doesNotMatch(skills.get("data/sqlite")!.body, /cite table, `rowid` and column/);
});

test("needs is at most two deep and its chain is at most 1,900 tokens; every id another pack needs is still here", async () => {
  const skills = await load(SKILLS);
  const chain = (id: string, seen: string[] = []): { depth: number; ids: string[] } => {
    const s = skills.get(id);
    assert.ok(s, `${id} resolves`);
    let best = { depth: 0, ids: [id] };
    for (const n of (s.meta.needs as string[]) ?? []) {
      assert.ok(!seen.includes(n), `no cycle at ${n}`);
      const sub = chain(n, [...seen, id]);
      if (sub.depth + 1 > best.depth) best = { depth: sub.depth + 1, ids: [id, ...sub.ids] };
    }
    return best;
  };
  for (const id of skills.keys()) {
    const { depth, ids } = chain(id);
    assert.ok(depth <= 2, `${id} needs ${depth} deep: ${ids.join(" > ")}`);
    const reached = new Set<string>();
    const add = (i: string): void => {
      if (reached.has(i)) return;
      reached.add(i);
      for (const n of (skills.get(i)!.meta.needs as string[]) ?? []) add(n);
    };
    add(id);
    const tokens = [...reached].reduce((n, i) => n + TOKENS(skills.get(i)!.text), 0);
    assert.ok(tokens <= 1900, `${id} chain is ${Math.round(tokens)} tokens`);
  }
  // The only edge left is a real assumption: a dispute is made against a citation.
  assert.deepEqual(
    [...skills.values()].filter((s) => ((s.meta.needs as string[]) ?? []).length).map((s) => `${s.id} > ${(s.meta.needs as string[]).join(",")}`),
    ["reporting/disagreement > reporting/citations"],
  );
  // Other packs reach these through `needs` (and name them in their text): an id removed or renamed here breaks them.
  const packs = join(ROOT, "packs");
  const reachedByOthers = new Set<string>();
  for (const p of await readdir(packs)) {
    if (p === "computer-forensics-base") continue;
    const dir = join(packs, p, "skills");
    const others = await load(dir).catch(() => new Map<string, Skill>());
    for (const s of others.values()) for (const n of (s.meta.needs as string[]) ?? []) if (!others.has(n)) reachedByOthers.add(n.replace(/^computer-forensics-base:/, ""));
  }
  assert.ok(reachedByOthers.size > 0);
  for (const id of reachedByOthers) assert.ok(skills.has(id), `another pack needs ${id}, which this pack no longer has`);
  for (const id of ["evidence/imaging", "evidence/verify", "filesystem/carving", "filesystem/encrypted", "reporting/citations", "timeline/build", "timeline/super"]) {
    assert.ok(skills.has(id), `${id} is still a skill (other packs name it)`);
  }
});

test("every second-level leaf is pointed to by a leaf that says when to open it, and the new method leaves are reachable from the leaves they specialise", async () => {
  const skills = await load(SKILLS);
  for (const [child, parent] of Object.entries(SECOND_LEVEL)) {
    const p = skills.get(parent)!;
    const at = p.body.indexOf(`\`${child}\``);
    assert.ok(at >= 0, `${parent} points to ${child}`);
    assert.match(p.body.slice(Math.max(0, at - 160), at + 40), /\bNot for\b|[Oo]nly if|\bsays when\b|\bBefore you\b/, `${parent} says when to open ${child}`);
  }
  // Pointers: who sends the agent to the new leaves.
  const pointers: Array<[string, string]> = [
    ["evidence/verify", "evidence/provenance"], ["evidence/catalog", "evidence/coverage"], ["filesystem/carving", "evidence/coverage"],
    ["timeline/build", "timeline/clocks"], ["timeline/super-scope", "timeline/clocks"], ["data/sqlite", "timeline/clocks"],
    ["evidence/imaging", "filesystem/layers"], ["evidence/imaging", "filesystem/layers-mapping"], ["timeline/build", "timeline/clocks-drift"],
    ["filesystem/carving", "filesystem/layers"], ["filesystem/extract", "filesystem/semantics"],
    ["filesystem/encrypted-metadata", "evidence/scope"], ["data/documents-media", "evidence/scope"], ["evidence/coverage", "evidence/tool-validation"],
    ["reporting/citations", "evidence/coverage"],
  ];
  for (const [from, to] of pointers) assert.ok(skills.get(from)!.body.includes(`\`${to}\``), `${from} points to ${to}`);
  // Every skill is named by another skill of the pack, besides being in the index: none is reachable only by luck.
  const everything = [...skills.values()];
  for (const s of everything.filter((x) => x.id !== ROUTER)) {
    assert.ok(everything.some((o) => o.id !== s.id && o.body.includes(`\`${s.id}\``)), `${s.id} is named by no other skill`);
  }
  // ... and the second-level leaves are named by their parent, not only by the router.
  for (const [child, parent] of Object.entries(SECOND_LEVEL)) assert.ok(skills.get(parent)!.body.includes(`\`${child}\``), `${parent} names ${child}`);
});

// Fields and names a skill teaches, each of which a tool must write or read: file -> skill -> names.
const TAUGHT: Array<[string, string, string[]]> = [
  ["tools/sqlite_snapshot/run.py", "data/sqlite", ["changed_during_copy", "frames_committed", "frames_uncommitted_valid", "first_invalid_frame", "counts_agree", "rollback_journal", "pages_of_the_main_file_changed_by_the_wal"]],
  ["tools/sqlite_query/run.py", "data/sqlite", ["snapshot_status", "rows_file", "blob_b64", "blob_b64_head", "head_bytes", "freelist_count", "application_id", "user_version"]],
  ["tools/catalog_search/run.py", "evidence/coverage", ["all_matches", "revision", "matched"]],
  ["tools/timestamp_decode/run.py", "timeline/clocks", ["remainder_s"]],
  ["tools/timeline_super/run.py", "timeline/super", ["status", "collect_exit", "export_exit", "invalid_lines", "resume"]],
  ["tools/timeline_super/run.py", "timeline/super-scope", ["timezone", "storage_file", "psort_filter", "mode"]],
  ["tools/image_layout/run.py", "evidence/imaging", ["partition_table", "raw_outputs", "sector_size"]],
  ["tools/check_inputs/run.py", "evidence/verify", ["not_checked"]],
  ["tools/file_carver/run.py", "filesystem/carving", ["boundary", "overlay_uncertain", "validated", "heuristic"]],
  ["tools/ioc_scan/run.py", "filesystem/scanners", ["write_values", "all_results"]],
  ["tools/feature_scan/run.py", "filesystem/scanners", ["out_dir_contains_secret_values", "report.xml"]],
  ["tools/archive_extract/run.py", "evidence/provenance", ["SHORT_MEMBER"]],
  ["tools/sqlite_query/run.py", "data/sqlite-secrets", ["write_values", "rowid_from", "rowid_to", "locators_file", "sqlite-query-values.jsonl", "table_kind",
    "rowid_is_a_value", "virtual_table_unsupported", "cells_not_exported", "value_too_large", "unreadable", "values_file_error", "locator",
    "n_ranks", "shadowed", "row_unreadable", "values_file_holds"]],
];

test("the tool fields a skill names are fields the tools write", async () => {
  const skills = await load(SKILLS);
  for (const [file, skillId, names] of TAUGHT) {
    const script = await readFile(join(PACK, file), "utf8");
    const body = skills.get(skillId)!.body;
    for (const name of names) {
      // SHORT_MEMBER is the constant behind the 128-byte rule the provenance leaf states.
      if (name === "SHORT_MEMBER") {
        assert.match(body, /under 128 bytes/);
        assert.match(script, /SHORT_MEMBER = 128/);
        continue;
      }
      assert.ok(body.includes(name), `${skillId} names ${name}`);
      const written = /^[a-z_]+$/.test(name) ? script.includes(`"${name}"`) || script.includes(`${name}=`) || script.includes(`${name}:`) : script.includes(name);
      assert.ok(written, `${file} writes ${name}, which ${skillId} teaches`);
    }
  }
});

test("the claims the review found are not in the skills, and the front matter lists what the body names", async () => {
  const skills = await load(SKILLS);
  const all = [...skills.values()].map((s) => s.text).join("\n");
  const banned: RegExp[] = [
    /Nothing you extract can execute/i,
    /decided more than one case/i,
    /dislocker[^\n]* -p<[^>]*>/i,
    /there is nothing to weigh/i,
    /\bprobably encrypted\b/i,
    /no disk, no partition, no inode/i,
    /cuts it down without running the collection again/i,
    /`timestamp_decode`[^.\n]*\bsettles\b/i,
    /\blossless\b[^.\n]*`file_carver`|`file_carver`[^.\n]*\blossless\b/i,
    /a clock change stops mattering/i,
    /newest messages are (the ones )?in the WAL/i,
    /\bcannot be recovered\b(?![^\n]*(only after|never))/i,
    /\bhash of (the|a) (secret|password|key)[^\n]*\b(quote|write it|record it)\b/i,
    /--password[= ]|passphrase on the command line is fine/i,
  ];
  for (const re of banned) assert.doesNotMatch(all, re);
  // A body that names a tool of the pack in code lists it; the list is exactly what the pack-links lint holds, and here for the new leaves.
  const tools = (await readdir(join(PACK, "tools"))).sort();
  for (const s of skills.values()) {
    const listed = new Set([...((s.meta.tools as string[]) ?? []), ...((s.meta.requires_host as string[]) ?? [])]);
    for (const t of tools) {
      const named = new RegExp("(?<![\\w.-])" + t + "(?![\\w-])").test(s.body);
      if (named) assert.ok(listed.has(t), `${s.id} names ${t} but does not list it`);
    }
    for (const t of listed) assert.ok(new RegExp("(?<![\\w.-])" + t.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "(?![\\w-])").test(s.body), `${s.id} lists ${t} but never names it`);
  }
  // No version fact is stated for a program the pack does not pin: a dated "as of" is the form for one.
  assert.doesNotMatch(all, /\b(Plaso|libewf|Sleuth Kit|SQLite|bulk_extractor|steghide|exiftool) (version )?\d+(\.\d+)+/);
  // The stand-in rules: the method leaves name no tool they do not use (scope is a method leaf), and a secret is never put on a command line.
  assert.deepEqual(skills.get("evidence/scope")!.meta.tools, []);
  assert.match(skills.get("filesystem/encrypted-metadata")!.body, /It never goes on a command line: argv is recorded in the trace/);
});

test("the sizes the split pass reached stay: the skills that were over a budget are not on the golden list any more", async () => {
  const golden = await readFile(join(ROOT, "tests", "skill-budgets.golden"), "utf8");
  assert.doesNotMatch(golden, /^computer-forensics-base /m, "the base pack has no known budget finding left");
});

// ---- The review of #133: each fixed item has a test that fails on the text it replaced. ----

const paragraph = (s: Skill, lead: string): string => {
  const at = s.body.indexOf(lead);
  assert.ok(at >= 0, `${s.id} has a paragraph that opens ${lead}`);
  const end = s.body.indexOf("\n\n", at);
  return s.body.slice(at, end < 0 ? undefined : end);
};

test("a full search never shows an event did not happen: coverage agrees with citations and the worker prompt", async () => {
  const skills = await load(SKILLS);
  const lead = paragraph(skills.get("evidence/coverage")!, "**Wording.**");
  // The old text allowed the phrase "on a search the harness found complete".
  assert.doesNotMatch(lead, /"X did not happen" is for a question/);
  assert.match(lead, /"X did not happen" is never written, even after a search the harness found complete/);
  assert.match(lead, /answers whether X is in those sources, not whether the event occurred/);
  // No skill quotes "did not happen" as a phrase to use: where a skill quotes it, it is the phrase to avoid.
  for (const s of skills.values()) {
    for (const line of s.body.split("\n")) {
      if (/"[^"\n]*did not happen"/.test(line)) assert.match(line, /never/, `${s.id} quotes "did not happen" without saying never`);
    }
  }
  const prompt = await readFile(join(ROOT, "prompts", "worker-system.md"), "utf8");
  assert.match(prompt, /never "<what> did not happen", whatever the result/);
});

test("archive_extract runs with secret_output only when members may hold credential material, as the worker prompt says", async () => {
  const skills = await load(SKILLS);
  const s = skills.get("evidence/archives")!;
  // The old text said "run it with `secret_output: true`: members are evidence content" for every archive, against its own example.
  assert.doesNotMatch(s.body, /run it with `secret_output: true`: members are evidence content/);
  assert.doesNotMatch(s.body, /Members are evidence content and may hold credentials: the job runs with/);
  const example = s.body.split("\n").find((l) => l.includes("job_run tool=archive_extract"))!;
  assert.doesNotMatch(example, /secret_output/, "the example is the ordinary run");
  // Every paragraph that names the flag makes it conditional on what the listing shows.
  const paras = s.body.split("\n\n").filter((p) => p.includes("secret_output"));
  assert.ok(paras.length >= 2);
  for (const p of paras) assert.match(p, /(listing shows members that may hold credential stores, keys, tokens or browser profiles)/, p);
  assert.match(paragraph(s, "**Sensitive output.**"), /an archive of ordinary documents or logs runs without it/);
  // What the prompt says the flag does is the reason for the condition: it makes every downstream output sensitive.
  const prompt = await readFile(join(ROOT, "prompts", "worker-system.md"), "utf8");
  assert.match(prompt, /every output it seals is sensitive, and so is the output of any job that reads it/);
});

test("data/sqlite: on a secret table select locators only, because the inline page always carries values; the BLOB fields are the tool's", async () => {
  const skills = await load(SKILLS);
  const s = skills.get("data/sqlite")!;
  // The workaround is the fallback in the second-level leaf the Sensitive output line points to; the mode is the way in a job.
  const secrets = skills.get("data/sqlite-secrets")!;
  const fallback = paragraph(secrets, "**Fallback, outside a job or without the mode.**");
  assert.match(fallback, /`limit` is 1 or more, so the inline page always carries at least one row of values/);
  assert.match(fallback, /select only locators \(`rowid`, `length\(col\)`, `typeof\(col\)`\) `FROM t NOT INDEXED ORDER BY rowid`/);
  // Through an index on the secret column the locators come ranked by its values (the final review of #144): the table itself, in
  // rowid order, and a WITHOUT ROWID table in its key's.
  assert.match(fallback, /WITHOUT ROWID: `ORDER BY` the key, which ranks it\./);
  // The pointer says when to read the leaf: before any query on such a table, since the inline page carries values (the review of
  // #144 found it inverted: "Only if you need the rows" sent the agent there only when it wanted values in its context).
  assert.match(paragraph(s, "**Sensitive output.**"), /Before you query one, read `data\/sqlite-secrets`: the inline page always holds values\./);
  assert.doesNotMatch(s.body, /Only if you need the rows/);
  // The example is a job with secret_output, written as the other packs write one (a job_run tool=... line has no place for the flag).
  const example = secrets.body.split("\n").find((l) => l.includes("job_run") && l.includes("sqlite_query"))!;
  assert.match(example, /^ {4}job_run\(tool: "sqlite_query", secret_output: true, args: \{.*"write_values": true\}\)$/);
  const memory = await readFile(join(ROOT, "packs", "memory-forensics", "skills", "processes", "preserve-regions.md"), "utf8");
  assert.match(memory, /job_run\(tool: "mem_fs", secret_output: true, args: \{/, "the form the memory pack uses");
  // What the tool guarantees about a row's locator, said as the tool says it.
  const locate = paragraph(secrets, "**What locates a row**");
  assert.match(locate, /declared `INTEGER`: that column is the rowid, so the rowid is a value: never printed, a range refused \(`rowid_is_a_value`\)/);
  assert.match(locate, /which ranks the key's values/);
  assert.match(locate, /WITHOUT ROWID: `n` in primary key order, which ranks those values too/);
  assert.match(paragraph(secrets, "**Lengths.**"), /a PIN stored as an integer has lost its leading zeros/);
  assert.match(paragraph(secrets, "**Fallback, outside a job or without the mode.**"), /Where a column is the `INTEGER PRIMARY KEY`, `rowid` is its value: leave it out/);
  assert.match(paragraph(secrets, "**Record.**"), /the locator \(`rowid`, or `n` where `locator` is `n`\)/);
  assert.match(s.body, /`blob_b64_head`, its first `head_bytes` \(long\)/);
  assert.doesNotMatch(s.body, /a BLOB is `blob_b64` \(its head inline when long\)/);
  assert.match(s.body, /found the same number of committed frames/);
  assert.doesNotMatch(s.body, /read the same frames/);

  // The claims are the tool's: locator columns carry no value, limit 0 is refused, a plain select does carry the value.
  const dir = await mkdtemp(join(tmpdir(), "base-sqlite-"));
  try {
    const db = join(dir, "t.db");
    const made = await runPySnippet(
      "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute('create table tok(host text, v blob)'); c.execute('create index ixv on tok(v)'); [c.execute('insert into tok(host, v) values(?, ?)',('host-%d' % i, v)) for i, v in enumerate((b'zz-planted-secret-value-0001', b'aa-planted-secret-value-0002'))]; c.commit()",
      [db],
      {},
    );
    assert.equal(made.code, 0, made.stderr);
    const script = join(PACK, "tools", "sqlite_query", "run.py");
    const b64 = Buffer.from("zz-planted-secret-value-0001").toString("base64");
    // The skill's query, with t and col filled in: rowid order, not the order of the index on v (which would put rowid 2 first).
    const loc = await runPy(script, dir, { db_path: db, sql: "SELECT rowid, length(v), typeof(v) FROM tok NOT INDEXED ORDER BY rowid", limit: 2 });
    assert.equal(loc.code, 0, loc.stdout + loc.stderr);
    const answer = JSON.parse(loc.stdout);
    assert.equal(answer.ok, true);
    assert.ok(!loc.stdout.includes("planted-secret") && !loc.stdout.includes(b64), "a locator select puts no value in the answer");
    assert.ok(loc.stdout.includes("blob"), "typeof(v) says it is a blob");
    assert.deepEqual(answer.rows.map((r: { values: unknown[] }) => r.values[0]), [1, 2]);
    const ranked = JSON.parse((await runPy(script, dir, { db_path: db, sql: "SELECT rowid, length(v), typeof(v) FROM tok", limit: 2 })).stdout);
    assert.deepEqual(ranked.rows.map((r: { values: unknown[] }) => r.values[0]), [2, 1], "without the clause SQLite reads the covering index, in the values' order");
    const plain = await runPy(script, dir, { db_path: db, sql: "SELECT v FROM tok WHERE rowid = 1", limit: 1 });
    assert.ok(plain.stdout.includes(b64), "a plain select puts the base64 of a short BLOB in the inline page");
    const zero = await runPy(script, dir, { db_path: db, sql: "SELECT v FROM tok", limit: 0 });
    assert.notEqual(zero.code, 0);
    assert.match(zero.stdout, /limit is a whole number from 1 to/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("provenance: a credential store as a file has a digest, a value read out of it does not; archive_extract writes sha256 per member", async () => {
  const skills = await load(SKILLS);
  const s = skills.get("evidence/provenance")!;
  assert.doesNotMatch(s.body, /a token file, a password store, a recovery key/);
  assert.match(paragraph(s, "**Secrets.**"), /A credential store as a file \(a password database, a browser profile file\) is an object whose digest is its identity; a value read out of it is a secret/);
  assert.match(s.body, /`archive_extract` size, CRC and sha256 per member/);
  const tool = await readFile(join(PACK, "tools", "archive_extract", "run.py"), "utf8");
  assert.match(tool, /sizes, sha256, times/);
  // The semantics and extract skills record the sha256 of an extracted credential store.
  assert.match(skills.get("filesystem/semantics")!.body, /the sha256 and your check of the content/);
});

test("filesystem/encrypted has a Sensitive output line for bdeinfo, which prints salts, digests and protector identifiers", async () => {
  const skills = await load(SKILLS);
  const s = skills.get("filesystem/encrypted")!;
  const sensitive = paragraph(s, "**Sensitive output.**");
  assert.match(sensitive, /`bdeinfo` prints salts, digests and protector identifiers: run it as a job/);
  assert.match(skills.get("filesystem/encrypted-metadata")!.body, /header source, key slots and tokens/);
  // The protector-list caveat stays in the leaf that reads protector lists.
  assert.match(skills.get("filesystem/encrypted-metadata")!.body, /A protector list is the state when the metadata was last written, not who holds a protector or that it works/);
});

test("semantics and the catalogue agree on a named stream; clocks do not give a skipped local time a reading", async () => {
  const skills = await load(SKILLS);
  const semantics = skills.get("filesystem/semantics")!.body;
  assert.doesNotMatch(semantics, /hidden in a path listing/);
  assert.match(semantics, /`name:stream` on NTFS/);
  assert.match(skills.get("evidence/catalog")!.body, /named `\$DATA` streams show in the path field of the listing as `name:stream`/);
  const clocks = skills.get("timeline/clocks")!.body;
  assert.doesNotMatch(clocks, /In a repeated or skipped local hour/);
  assert.match(clocks, /A repeated local hour \(a daylight-saving change\) is ambiguous: keep both readings/);
  assert.match(clocks, /A local time in the skipped hour does not exist: it points to a wrong zone, rule or clock/);
  assert.doesNotMatch(clocks, /skipped[^\n]*keep both readings/);
});

test("filesystem/layers: the backing chain needs --backing-chain; the lost container rows and rules are back (the mapping rules in the second-level leaf)", async () => {
  const skills = await load(SKILLS);
  const layers = skills.get("filesystem/layers")!.body + "\n" + skills.get("filesystem/layers-mapping")!.body;
  assert.match(layers, /`qemu-img info --backing-chain`/);
  assert.match(layers, /plain `info` only the immediate backing file/);
  assert.match(layers, /only a claim by whoever named the file/);
  assert.match(layers, /AFF4 is a zip-based container/);
  assert.match(layers, /a directory or a zip\s+a collection, not an image/);
  assert.match(layers, /the bound for any scan over all of it/);
  assert.match(layers, /Validate the geometry, the metadata's consistency and that files read/);
  assert.match(layers, /`target-query` \(dissect; it also opens E01, VMDK, QCOW and a collection behind one interface, with a plugin per artefact family\)/);
  assert.match(layers, /check the version the image carries/);
});

test("content the split pass of #133 dropped is back where the review named it", async () => {
  const skills = await load(SKILLS);
  const body = (id: string): string => skills.get(id)!.body;
  // L1 extract's wrong-header list; L3 the super timeline is not every timestamp; L8 the clock bullet's list; L5 the LUKS header source.
  assert.match(body("filesystem/semantics"), /A wrong header can mean overwritten, fragmented, compressed, encrypted, truncated or the wrong record; a matching header or size is one check, not all of them/);
  assert.match(body("timeline/super"), /not every timestamp on the volume/);
  assert.match(body("timeline/clocks-drift"), /copying, extraction, restoration and ordinary file system behaviour explain it/);
  assert.match(body("filesystem/encrypted-metadata"), /give the version, header source, key slots and tokens/);
});

test("documents-media writes a copy under {OUT} only in a job; tool-validation does not call a second parser two readings by default", async () => {
  const skills = await load(SKILLS);
  const media = skills.get("data/documents-media")!.body;
  assert.doesNotMatch(media, /write the copy under `\$OUT` and never over the original/);
  assert.match(media, /in a job write the copy under `\{OUT\}` \(in your shell, `work\/<you>\/`\), never over the original/);
  const tv = skills.get("evidence/tool-validation")!.body;
  assert.doesNotMatch(tv, /a measurement by a different method, is two\./);
  assert.match(tv, /is two only if it does not share the first's assumption or input copy/);
  assert.match(tv, /`counts_agree` says only that both found the same number of committed frames, not the same pages or rows/);
  const tool = await readFile(join(PACK, "tools", "sqlite_snapshot", "run.py"), "utf8");
  assert.match(tool, /agree = log_frames == wal_info\["frames_committed"\]/, "counts_agree compares frame counts");
});

test("scope routes a lookup the evidence suggests as the worker prompt does: net_request where the run has the dynamic network", async () => {
  const skills = await load(SKILLS);
  const scope = skills.get("evidence/scope")!;
  assert.doesNotMatch(scope.body, /is a request to the operator, not something you fetch/);
  assert.match(scope.body, /where SWARM\.md says the run has the dynamic network it is a `net_request`, otherwise a request to the operator/);
  const prompt = await readFile(join(ROOT, "prompts", "worker-system.md"), "utf8");
  assert.match(prompt, /Where SWARM\.md says the run has the dynamic network, that lookup is a `net_request`/);
  // net_request is the harness's, not a tool of this pack: the method leaf still lists no tool.
  assert.deepEqual(scope.meta.tools, []);
});

// ---- The router: the one entry a run shows for this pack when its index is over the run's budget. ----

test("the router is the pack's only router, within 400 tokens, and names every other skill exactly once; every old id is alive", async () => {
  const skills = await load(SKILLS);
  const routers = [...skills.values()].filter((s) => s.meta.router === "true");
  assert.deepEqual(routers.map((s) => s.id), [ROUTER], "one router, and it is base/router");
  const router = skills.get(ROUTER)!;
  assert.ok(TOKENS(router.text) <= ROUTER_MAX, `the router is ${Math.round(TOKENS(router.text))} tokens`);
  assert.match(router.body.trim().split("\n")[0], /^Use when .*\bNot for\b/);
  assert.deepEqual(router.meta.tools ?? [], [], "the router names no tool");
  // Every other skill is named once as a line of its own or in the line of the leaf it specialises; none twice, none missing.
  const named = [...router.body.matchAll(/`([a-z0-9-]+\/[a-z0-9-]+)`/g)].map((m) => m[1]);
  assert.equal(new Set(named).size, named.length, `a skill is named twice: ${named.filter((n, i) => named.indexOf(n) !== i).join(", ")}`);
  assert.deepEqual([...named].sort(), [...skills.keys()].filter((id) => id !== ROUTER).sort());
  // The ids of the pack as they were before the router (other packs' `needs` and text name them): all of them still resolve.
  const before = [
    "data/documents-media", "data/sqlite", "evidence/ad1", "evidence/archives", "evidence/catalog", "evidence/collections", "evidence/coverage",
    "evidence/imaging", "evidence/provenance", "evidence/scope", "evidence/tool-validation", "evidence/verify", "filesystem/carving",
    "filesystem/encrypted", "filesystem/encrypted-metadata", "filesystem/extract", "filesystem/layers", "filesystem/scanners",
    "filesystem/semantics", "reporting/citations", "reporting/disagreement", "timeline/build", "timeline/clocks", "timeline/super", "timeline/super-scope",
  ];
  assert.equal(before.length, 25);
  for (const id of before) assert.ok(skills.has(id), `${id} is still a skill`);
  // The generated index names it as the pack's router, which is the line the harness reads.
  assert.match(await readFile(join(SKILLS, "INDEX.md"), "utf8"), /^Router: `base\/router`$/m);
});

test("a run of the base pack with encrypted-containers, windows and macos fits the run's 2,500-token index budget only because the base pack has a router", async () => {
  // The disk profile (base, encrypted-containers, windows) used to need the router; windows-forensics' index was then cut to fit its own
  // budget and the profile fits whole. This set is over the budget whole, and the other packs' routers are left out of the count on purpose:
  // what this holds is the base pack's router, whatever the other packs have.
  // linux-forensics stood in this set while its index was small; its index now passes 1,000 (thirty-four leaves and the router) and the pack is shown by its router, so
  // the set that keeps this property is the one with a pack whose whole index still fits the run beside the base router.
  const dirs = ["computer-forensics-base", "encrypted-containers", "windows-forensics", "macos-forensics"].map((p) => join(ROOT, "packs", p));
  const packs = (await readPackIndexes(dirs)).map((p) => (p.id === "computer-forensics-base" ? p : { ...p, router: null }));
  const withRouter = renderSkillsSection(packs).report;
  const base = withRouter.packs.find((p) => p.id === "computer-forensics-base")!;
  assert.equal(base.shown, "router", "the base pack is shown by its router when the run is over budget");
  assert.ok(withRouter.shown_tokens <= SKILL_BUDGET.run, `the set shows ${Math.round(withRouter.shown_tokens)} tokens of entries, over the run's ${SKILL_BUDGET.run}`);
  assert.ok(withRouter.index_tokens > SKILL_BUDGET.run, "the whole index is over the budget; that is what makes the router the entry shown");
  // The same packs with no router (as the base pack was) cannot be shortened: the section is over budget and the report says which pack could not be.
  const without = renderSkillsSection(packs.map((p) => (p.id === "computer-forensics-base" ? { ...p, router: null } : p))).report;
  assert.ok(without.shown_tokens > SKILL_BUDGET.run, `without the router the set shows ${Math.round(without.shown_tokens)} tokens`);
  assert.ok(without.no_router.includes("computer-forensics-base"));
  // The router's own line is what the prompt carries for the pack, and it is within the entry budget.
  const entry = packs[0]!.entries.find((e) => e.id === ROUTER)!;
  assert.ok(entry.tokens <= SKILL_BUDGET.entry);
});

test("no rule was lost when layers, sqlite and clocks were split: the register of their sentences is still in the pack", async () => {
  const skills = await load(SKILLS);
  const norm = (s: string): string => s.replace(/[`*]/g, "").replace(/\s+/g, " ").toLowerCase().trim();
  const corpus = norm([...skills.values()].map((s) => s.body).join("\n"));
  const rules = JSON.parse(await readFile(join(ROOT, "tests", "pack-split-rules", "computer-forensics-base.json"), "utf8")) as Array<[string, string]>;
  assert.ok(rules.length >= 80, "the register is the whole one");
  for (const [from, frag] of rules) assert.ok(corpus.includes(frag), `from ${from}, gone: "${frag}" (moved or reworded: update tests/pack-split-rules/computer-forensics-base.json in the same change)`);
  // Where the three leaves went: each of the moved rules is in the second-level leaf, and the parent points to it.
  const where = (id: string): string => norm(skills.get(id)!.body);
  assert.ok(where("filesystem/layers-mapping").includes("rebuild it from that metadata and all the members with a reader that supports the layer"));
  assert.ok(where("timeline/clocks-drift").includes("a logged clock change is a finding"));
  assert.ok(where("data/sqlite-secrets").includes("on such a table select only locators"));
});
