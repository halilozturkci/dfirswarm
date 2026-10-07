/**
 * reverse-engineering: the skills are held to the size and shape rules for a skill leaf (a leaf is at most 800
 * tokens, estimated as bytes / 4.245, and 300 lines; it opens with "Use when ... Not for ..."; `needs` is at most
 * two deep; an index entry is at most 40 tokens), and the tool fields they name are fields the tools really write,
 * so a skill cannot keep teaching a field name a tool no longer has. The claims the review found overclaimed
 * (a no-exec mount "prevents" execution, entropy "is packed", a valid signature "means a stolen certificate",
 * an external relationship "fetches on open") are held out of every body.
 */
import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { RE, TOOLS } from "./pack-re-harness.ts";

const SKILLS = join(RE, "skills");
const BASE_SKILLS = join(RE, "..", "computer-forensics-base", "skills");
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
        for (const line of m[1]!.split("\n")) {
          const [k, ...rest] = line.split(":");
          const v = rest.join(":").trim();
          meta[k!.trim()] = v.startsWith("[") ? v.slice(1, -1).split(",").map((x) => x.trim()).filter(Boolean) : v;
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
  assert.equal(skills.size, 12);
  for (const s of skills.values()) {
    assert.ok(TOKENS(s.text) <= 800, `${s.id} is ${Math.round(TOKENS(s.text))} tokens`);
    assert.ok(s.text.split("\n").length <= 300, `${s.id} lines`);
    const first = s.body.trim().split("\n")[0]!;
    assert.match(first, /^Use when /, `${s.id} opens with Use when`);
    assert.match(first, /\bNot for\b/, `${s.id} says what it is not for`);
    const entry = `- \`${s.id}\` ${s.meta.title}: ${s.meta.when}`;
    assert.ok(TOKENS(entry) <= 40, `${s.id} index entry is ${Math.round(TOKENS(entry))} tokens`);
    for (const part of ["Shows", "Does not show", "Record"]) assert.match(s.body, new RegExp(`${part}:`), `${s.id} has ${part}`);
  }
  const index = await readFile(join(SKILLS, "INDEX.md"), "utf8");
  for (const id of skills.keys()) assert.ok(index.includes(`\`${id}\``), `${id} is in the index`);
});

test("needs is at most two deep and its chain is at most 2,000 tokens, counting the base skills it reaches", async () => {
  const all = new Map([...(await load(BASE_SKILLS)), ...(await load(SKILLS))]);
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
    const tokens = ids.reduce((n, i) => n + TOKENS(all.get(i)?.text ?? ""), 0);
    assert.ok(tokens <= 2000, `${id} chain is ${Math.round(tokens)} tokens`);
  }
});

test("every second-level leaf is pointed to by a leaf that says when to open it", async () => {
  const skills = await load(SKILLS);
  const pointers: Record<string, string> = {
    "pe/signature-and-resources": "pe/structure",
    "elf/packing-and-identity": "elf/structure",
    "strings/decoding-and-similarity": "strings/obfuscated",
    "documents/external-and-active-content": "documents/macros",
    "rules/authoring": "rules/yara",
  };
  for (const [child, parent] of Object.entries(pointers)) {
    const p = skills.get(parent);
    assert.ok(p, parent);
    assert.ok(p.body.includes(`\`${child}\``), `${parent} points to ${child}`);
    assert.match(p.body, /Only if /, `${parent} says when`);
    assert.deepEqual(skills.get(child)!.meta.needs, [], `${child} needs nothing: it is opened from ${parent}`);
  }
});

// Fields and names a skill teaches, each of which a tool must write: tool -> [skill, names].
const TAUGHT: Array<[string, string, string[]]> = [
  ["pe_info", "pe/structure", ["compile_timestamp_raw", "writable_and_executable", "overlay_offset", "declares_clr_runtime_header", "declares_tls", "declares_delay_imports", "declares_resources", "entropy_note", "status", "problems", "coverage"]],
  ["pe_info", "pe/signature-and-resources", ["export_name", "certificate_table_declared", "certificate_table", "within_file"]],
  ["pe_info", "elf/structure", ["section_headers_absent", "stripped", "needed_libraries", "soname", "rpath", "runpath", "interpreter", "entry_point", "segments", "PT_DYNAMIC"]],
  ["doc_probe", "documents/macros", ["extension_content_disagreement", "members", "extract_to", "status"]],
  ["doc_probe", "documents/external-and-active-content", ["external_targets", "finding_id", "write_values", "doc-probe-values.jsonl", "markers", "encrypt_marker_present", "objdata_markers", "classes"]],
  ["fuzzy_hash", "strings/decoding-and-similarity", ["insufficient_input"]],
];

test("the tool fields a skill names are fields its tool writes", async () => {
  const skills = await load(SKILLS);
  for (const [tool, skillId, names] of TAUGHT) {
    const script = await readFile(join(TOOLS, tool, "run.py"), "utf8");
    const body = skills.get(skillId)?.body ?? "";
    for (const name of names) {
      assert.ok(body.includes(name), `${skillId} names ${name}`);
      assert.ok(script.includes(name), `${tool} has ${name}, which ${skillId} teaches`);
    }
  }
});

test("the per-engine status fields fuzzy_hash writes are the ones the skill names", async () => {
  const body = (await load(SKILLS)).get("strings/decoding-and-similarity")!.body;
  const script = await readFile(join(TOOLS, "fuzzy_hash", "run.py"), "utf8");
  assert.ok(body.includes("tlsh_status"));
  assert.ok(script.includes('engine + "_status"') && script.includes('("ssdeep", ') && script.includes('"tlsh", '), "the script writes <engine>_status for ssdeep and tlsh");
});

test("no skill states a version fact, the old overclaims are gone, and secret handling is stated where a tool can reach a secret", async () => {
  const skills = await load(SKILLS);
  const overclaims = [
    /held no-exec by the kernel|a sample cannot run even if|the harness enforces that rather than trusting/i,
    /A section at 7\.9|is packed, and a disassembly|means? "packed"/i,
    /means a stolen certificate|certificate theft/i,
    /has been renamed|\.docx` cannot carry a macro/i,
    /run on open|run on their own|runs when the document opens|fetches when the document opens|fetch(es)? something when opened/i,
    /what it was built to do|what this is for|the sample hides|hide exactly this/i,
    /not from the strings|will keep matching|still be right next month|survives a rename and most repacking/i,
    /identifies a binary across rebuilds|what a dropped tool usually looks like|runs on any distribution/i,
    /tells whoever wrote it that they are being investigated|breaks the custody chain/i,
  ];
  for (const s of skills.values()) {
    assert.doesNotMatch(s.body, /\bas of (20|19)\d\d\b|since (version )?\d|\b(UPX|capa|radare2|r2|FLOSS) \d+\.\d/i, `${s.id} states no version fact`);
    for (const rx of overclaims) assert.doesNotMatch(s.body, rx, `${s.id} still carries an overclaim (${rx})`);
  }
  for (const id of ["triage/quarantine", "strings/obfuscated", "strings/decoding-and-similarity", "documents/macros", "documents/external-and-active-content", "rules/yara"]) {
    assert.match(skills.get(id)!.body, /secret_output: true/, `${id} says the job runs with secret_output: true`);
    assert.match(skills.get(id)!.body, /Sensitive output:/, `${id} has a Sensitive output line`);
  }
});

test("the quarantine leaf says no-exec does not stop an interpreter, as the worker prompt does", async () => {
  const skills = await load(SKILLS);
  assert.match(skills.get("triage/quarantine")!.body, /does not stop an interpreter/);
  const prompt = await readFile(join(RE, "..", "..", "prompts", "worker-system.md"), "utf8");
  assert.match(prompt, /No-exec does not stop\s+an interpreter reading a file/);
});

test("front matter lists what the body names: every tool and program is one the pack or its dependency carries", async () => {
  const skills = await load(SKILLS);
  const host = JSON.parse(await readFile(join(RE, "requires", "host.json"), "utf8")) as { binaries: { name: string }[] };
  const programs = new Set(host.binaries.map((b) => b.name));
  const own = new Set(await readdir(TOOLS));
  const base = new Set(await readdir(join(RE, "..", "computer-forensics-base", "tools")));
  for (const s of skills.values()) {
    for (const t of (s.meta.tools as string[]) ?? []) assert.ok(own.has(t) || base.has(t), `${s.id}: tool ${t} resolves`);
    for (const p of (s.meta.requires_host as string[]) ?? []) assert.ok(programs.has(p), `${s.id}: program ${p} is declared by the pack`);
  }
});
