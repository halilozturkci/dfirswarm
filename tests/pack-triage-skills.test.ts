/**
 * triage-collection: the skills are held to the size and shape rules for a skill leaf (a leaf is at most 800 tokens, estimated as
 * bytes / 4.245, and 300 lines; it opens with "Use when ... Not for ..."; `needs` is at most two deep; an index entry is at most 40
 * tokens), the fields they name are fields the tools really write, the claims the review found are gone, and no skill commands a
 * collector: the harness examines supplied evidence and never performs live collection.
 */
import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { ROOT } from "./tool-library-harness.ts";
import { TOOLS, TRIAGE } from "./pack-triage-harness.ts";

const SKILLS = join(TRIAGE, "skills");
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

const DECISION = ["identify/collector", "verify/manifests", "normalise/layout", "gaps/what-is-missing", "plan/what-to-collect"];
const SECOND_LEVEL: Record<string, string> = {
  "identify/collector-clues": "identify/collector", "identify/acquisition-mode": "identify/collector",
  "verify/target-outcomes": "verify/manifests", "verify/time-layers": "verify/manifests",
  "normalise/inventory": "normalise/layout", "normalise/parsers": "normalise/layout",
  "gaps/coverage-statement": "gaps/what-is-missing",
  "plan/sources-windows": "plan/what-to-collect", "plan/sources-linux": "plan/what-to-collect",
};

test("every skill is a leaf within the budget, opens with Use when ... Not for ..., has a short index entry and its Shows, Does not show and Record", async () => {
  const skills = await load(SKILLS);
  assert.equal(skills.size, 14);
  assert.deepEqual([...skills.keys()].sort(), [...DECISION, ...Object.keys(SECOND_LEVEL)].sort());
  for (const s of skills.values()) {
    assert.ok(TOKENS(s.text) <= 800, `${s.id} is ${Math.round(TOKENS(s.text))} tokens`);
    assert.ok(s.text.split("\n").length <= 300, `${s.id} lines`);
    const first = s.body.trim().split("\n")[0];
    assert.match(first, /^Use when /, `${s.id} opens with Use when`);
    assert.match(first, /\bNot for\b/, `${s.id} says what it is not for`);
    const entry = `- \`${s.id}\` ${s.meta.title}: ${s.meta.when}`;
    assert.ok(TOKENS(entry) <= 40, `${s.id} index entry is ${Math.round(TOKENS(entry))} tokens`);
    assert.match(s.body, /Record:/, `${s.id} has Record`);
    if (s.id !== "plan/what-to-collect") for (const part of ["Shows", "Does not show"]) assert.match(s.body, new RegExp(`${part}:`), `${s.id} has ${part}`);
    assert.deepEqual(s.meta.requires_host, [], `${s.id} commands no program: the harness never collects live`);
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
    const total = new Set(ids.flatMap((i) => [i, ...((all.get(i)?.meta.needs as string[]) ?? [])]));
    const tokens = [...total].reduce((n, i) => n + TOKENS(all.get(i)?.text ?? ""), 0);
    assert.ok(tokens <= 2000, `${id} chain is ${Math.round(tokens)} tokens`);
  }
});

test("every second-level leaf is pointed to by one decision leaf that says when to open it, and needs nothing", async () => {
  const skills = await load(SKILLS);
  for (const [child, parent] of Object.entries(SECOND_LEVEL)) {
    const p = skills.get(parent);
    assert.ok(p, parent);
    assert.match(p.body, new RegExp(`Only if [^\\n]*\`${child}\``), `${parent} says when to open ${child}`);
    assert.deepEqual(skills.get(child)!.meta.needs, [], `${child} needs nothing: a second-level leaf is read when its parent says so`);
  }
});

// Fields a skill names, each of which a tool must write: tool -> [skill, names].
const TAUGHT: Array<[string, string, string[]]> = [
  ["collection_id", "identify/collector", ["collector_candidates", "objects", "failed_target_count", "mixed", "partial", "unsupported"]],
  ["collection_id", "identify/collector-clues", ["layout_clues"]],
  ["collection_id", "gaps/what-is-missing", ["not_observed", "objects"]],
  ["collection_id", "gaps/coverage-statement", ["failed_targets"]],
  ["collection_id", "verify/target-outcomes", ["failed_targets", "skipped", "partial", "unsupported", "locator"]],
  ["collection_index", "normalise/layout", ["source_path_hypothesis", "source_path_observed", "unresolved_components", "alternatives", "confidence", "ambiguous", "possible_renamed_streams"]],
  ["collection_index", "normalise/inventory", ["complete_index", "matches_filter", "not_attempted", "may_hold_secrets", "object_class", "out_file", "contains", "census"]],
  ["collection_index", "verify/time-layers", ["mtime_distribution_anomaly", "modified_epoch_ns", "recorded_modified_utc_raw", "modified"]],
  ["collection_index", "verify/manifests", ["check_inputs"]],
];

test("the tool fields a skill names are fields its tool writes", async () => {
  const skills = await load(SKILLS);
  for (const [tool, skillId, names] of TAUGHT) {
    const script = await readFile(join(TOOLS, tool, "run.py"), "utf8");
    const body = skills.get(skillId)?.body ?? "";
    for (const name of names) {
      assert.ok(body.includes(name), `${skillId} names ${name}`);
      if (name !== "check_inputs") assert.ok(script.includes(name), `${tool} has ${name}, which ${skillId} teaches`);
    }
  }
});

test("the old claims are gone, no skill states a version fact or tells the agent to run a collector, and secret handling is stated where a tool can reach one", async () => {
  const skills = await load(SKILLS);
  const all = [...skills.values()].map((s) => s.body).join("\n");
  assert.doesNotMatch(all, /cannot be answered no matter|There is no unallocated space|There is no file slack|There is no volume|is irrelevant; cite by path|work unchanged|parses exactly as it would|recognises the shape each collector leaves|value per megabyte|memory first if|were in use at the time|all four were|probably dropped|every timestamp-based conclusion|CyLR or a plain copy/i);
  assert.doesNotMatch(all, /\b\d+\.\d+\.\d+(\.\d+)?\b|as of (20|19)\d\d|since (version )?\d/i, "no version fact");
  assert.doesNotMatch(all, /(?:run|launch|start|execute|invoke|use) (?:the )?(?:uac|velociraptor|KAPE|CyLR)\b(?! \w+ (?:never|does not|is not))/i);
  assert.match(skills.get("plan/what-to-collect")!.body, /never performs live collection/);
  assert.match(skills.get("plan/what-to-collect")!.body, /Do not launch a collector/);
  assert.match(skills.get("plan/what-to-collect")!.meta.title as string, /through the operator/);
  assert.equal(skills.get("plan/what-to-collect")!.meta.requires_host.length, 0);
  assert.match(skills.get("gaps/what-is-missing")!.meta.title as string, /can and cannot establish/);
  for (const id of ["identify/collector", "verify/manifests", "normalise/layout", "normalise/inventory"]) {
    assert.match(skills.get(id)!.body, /Sensitive output:[^\n]*secret_output: true/, `${id} says the job runs with secret_output: true`);
  }
  assert.match(skills.get("plan/what-to-collect")!.body, /secret_output: true/);
  assert.match(skills.get("plan/sources-linux")!.body, /secret_output: true/);
  assert.match(skills.get("verify/manifests")!.body, /does not open a container/);
});

test("the goal template asks the new questions, keeps its acceptance checks, and binds the unallocated check to the answer's own section", async () => {
  const goal = await readFile(join(TRIAGE, "goals", "collection-intake.md"), "utf8");
  assert.match(goal, /5\. The delivered-object inventory/);
  assert.match(goal, /6\. Integrity and time provenance/);
  assert.match(goal, /source-filesystem, embedded-record, archive-member and analysis-filesystem/);
  assert.doesNotMatch(goal, /whether\s+the timestamps are original|cannot\s+contain/);
  assert.match(goal, /sed -n '\/\^## 4\\\.\/,\/\^## 5\\\.\/p' work\/report\.md \| grep -qiE 'unallocated\|logical acquisition'/);
  // nothing else an agent had to satisfy was loosened
  for (const check of ["test -f work/report.md", "check-answers.ts", "inputs_check", '"tool":"skill"', '"kind":"event"']) assert.ok(goal.includes(check), check);
});
