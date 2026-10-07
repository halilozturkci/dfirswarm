/**
 * triage-collection: the skills are held to the size and shape rules for a skill leaf (a leaf is at most 800 tokens, estimated as
 * bytes / 4.245, and 300 lines; it opens with "Use when ... Not for ..."; `needs` is at most two deep; an index entry is at most 40
 * tokens), the fields they name are fields the tools really write, the claims the review found are gone, and no skill commands a
 * collector: the harness examines supplied evidence and never performs live collection.
 */
import assert from "node:assert/strict";
import { writeFileSync } from "node:fs";
import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { ROOT } from "./tool-library-harness.ts";
import { ID, INDEX, KAPE_COPY_HEADER, LIME_MAGIC, TRIAGE, asJob, kapeCopyRow, put, uac3, veloResultRow, veloUploadsRow, withCwd } from "./pack-triage-harness.ts";

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

// Fields a skill names, each of which a tool must write: skill -> names. They are looked for in the answers of both tools on a fixture
// that holds every collector, an image, a memory capture, a credential-store name, a copy log and a ready-made census (not in the tools' source).
const TAUGHT: Record<string, string[]> = {
  "identify/collector": ["collector_candidates", "objects", "failed_target_count", "failed_targets_seen", "mixed", "unsupported", "unlabelled_examples", "basis"],
  "identify/collector-clues": ["layout_clues"],
  "gaps/what-is-missing": ["not_observed", "not_observed_caveats", "objects"],
  "gaps/coverage-statement": ["failed_targets"],
  "verify/target-outcomes": ["failed_targets", "failed_targets_seen", "skipped", "locator", "not_found"],
  "normalise/layout": ["source_path_hypothesis", "source_path_observed", "unresolved_components", "alternatives", "confidence", "ambiguous", "possible_renamed_streams", "recorded_modified_utc_raw", "recorded_file_size_raw"],
  "normalise/inventory": ["complete_index", "matches_filter", "not_attempted", "may_hold_secrets", "object_class", "census", "modified_epoch_ns"],
  "verify/time-layers": ["mtime_distribution_anomaly", "modified_epoch_ns", "recorded_modified_utc_raw", "modified"],
};

function collect(value: unknown, keys: Set<string>, strings: string[]): void {
  if (typeof value === "string") strings.push(value);
  else if (Array.isArray(value)) for (const v of value) collect(v, keys, strings);
  else if (value && typeof value === "object") for (const [k, v] of Object.entries(value)) (keys.add(k), collect(v, keys, strings));
}

test("the tool fields a skill names are fields the tools write: the fixture is run, and the keys and values of its answers are read", async () => {
  const skills = await load(SKILLS);
  const keys = new Set<string>();
  const strings: string[] = [];
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/f/C/Users/a/NTUSER.DAT", "hive");
    await put(cwd, "inputs/f/C/Windows/System32/config/SAM", "hive");
    await put(cwd, "inputs/f/memory.raw", Buffer.concat([LIME_MAGIC, Buffer.alloc(64)]));
    await put(cwd, "inputs/f/doc.txt_Zone.Identifier", "z");
    await put(cwd, "inputs/f/r_CopyLog.csv", `${KAPE_COPY_HEADER}\n${kapeCopyRow("C:\\Users\\a\\NTUSER.DAT", "D:\\o\\C\\Users\\a\\NTUSER.DAT")}\n`);
    await put(cwd, "inputs/f/r_SkipLog.csv", "SourceFile,Reason\nC:\\x,locked\n");
    await put(cwd, "inputs/f/b/B_SkipLog.csv", Buffer.from([0x53, 0x6f, 0x00, 0x75, 0x00]));              // NUL bytes: a log that is not read as text
    await put(cwd, "inputs/f/uac.log", [uac3("INF", "Starting"), "cannot say what this is"].join("\n") + "\n");
    await put(cwd, "inputs/f/v/uploads.json", veloUploadsRow("/C:/a") + "\n");
    await put(cwd, "inputs/f/v/results/A.json", veloResultRow("/C:/a") + "\n");
    for (let i = 0; i < 22; i++) await put(cwd, `inputs/f/many/f${i}`, "x");
    for (const run of [await asJob(ID, cwd, { root: "inputs/f" }, {}, "out", "j000800"), await asJob(INDEX, cwd, { root: "inputs/f" }, {}, "out", "j000801")]) {
      assert.equal(run.code, 0, run.stderr);
      collect(JSON.parse(run.stdout), keys, strings);
    }
  });
  for (const [skillId, names] of Object.entries(TAUGHT)) {
    const body = skills.get(skillId)?.body ?? "";
    for (const name of names) {
      assert.ok(body.includes(name), `${skillId} names ${name}`);
      assert.ok(keys.has(name) || strings.some((s) => s.includes(name)), `the tools' answers carry ${name}, which ${skillId} teaches`);
    }
  }
});

const BASE_VERIFY_AT_103 = 3472;   // bytes of base evidence/verify once the base pack's review lands (818 tokens): the chain must still fit

test("the needs chain fits 2,000 tokens even when the base evidence/verify has grown to what the base review makes it", async () => {
  const all = new Map([...(await load(BASE_SKILLS)), ...(await load(SKILLS))]);
  const grown = all.get("evidence/verify")!;
  all.set("evidence/verify", { ...grown, text: grown.text + "x".repeat(Math.max(0, BASE_VERIFY_AT_103 - Buffer.byteLength(grown.text))) });
  for (const [id, s] of (await load(SKILLS)).entries()) {
    const ids = new Set<string>([id]);
    const walk = (x: string): void => { for (const n of ((all.get(x)?.meta.needs as string[]) ?? [])) { ids.add(n); walk(n); } };
    walk(id);
    const tokens = [...ids].reduce((n, i) => n + TOKENS(all.get(i)?.text ?? ""), 0);
    assert.ok(tokens <= 2000, `${s.id} chain is ${Math.round(tokens)} tokens`);
  }
});

test("the old claims are gone, whatever their wording; no skill states a version fact or tells the agent to run a collector; secret handling is stated wherever a tool is named", async () => {
  const skills = await load(SKILLS);
  const flat = (s: string) => s.replace(/\s+/g, " ");
  const all = flat([...skills.values()].map((s) => s.body).join("\n"));
  // the claims, not the sentences they were first written in
  const claims: Array<[RegExp, string]> = [
    [/\bcannot be answered\b/i, "a question outside the profile cannot be answered"],
    [/\bno (?:unallocated|slack|inode|volume)\b(?![^.]*\bunless\b)(?![^.]*\bdelivered\b)/i, "there is no unallocated space, slack, inode or volume"],
    [/\bnothing can be carved\b|\bno carving\b(?!\s+was possible only)/i, "nothing can be carved"],
    [/\b(?:offset|-o)\b[^.]{0,60}\b(?:irrelevant|do not apply|does not apply)\b/i, "offset commands are irrelevant"],
    [/\bmemory first\b/i, "memory first as an order"],
    [/\b(?:work|apply|run|parse)s? (?:unchanged|without change)\b|\bunchanged:/i, "the platform packs work unchanged"],
    [/\bparses exactly as it would\b/i, "a copied $MFT parses as from an image"],
    [/\b(?:every|all) timestamp[- ]based conclusion\b|\bis about the copy\b|\babout the copy rather than\b/i, "every timestamp conclusion is about the copy"],
    [/\brecognises the shape each collector leaves\b/i, "collection_id recognises the collector"],
    [/\bvalue per megabyte\b/i, "a fixed value-per-megabyte list"],
    [/\bin use at the time\b|\ball four were\b/i, "an invented cause of a failed copy"],
    [/\bCyLR or a plain copy\b/i, "CyLR or a plain copy"],
  ];
  for (const [rx, what] of claims) assert.doesNotMatch(all, rx, what);
  // the same claims, paraphrased, are what the patterns are for: they must fire on these
  for (const sample of [
    "A logical collection has no unallocated space, no slack and no inode, so the offset commands do not apply and nothing can be carved.",
    "Always capture memory first while the machine is running.", "The platform packs apply without change: a copied $MFT parses as it would from an image.",
    "When most files share the collection date, every timestamp conclusion is about the copy, not the machine.",
    "A question outside the profile cannot be answered from this delivery however carefully you look.",
  ]) assert.ok(claims.some(([rx]) => rx.test(flat(sample))), `the patterns catch: ${sample}`);
  assert.doesNotMatch(all, /\b\d+\.\d+\.\d+(\.\d+)?\b|as of (20|19)\d\d|since (version )?\d/i, "no version fact");
  assert.doesNotMatch(all, /(?:run|launch|start|execute|invoke|use) (?:the )?(?:uac|velociraptor|KAPE|CyLR)\b(?! \w+ (?:never|does not|is not))/i);
  assert.match(skills.get("plan/what-to-collect")!.body, /never performs live collection/);
  assert.match(skills.get("plan/what-to-collect")!.body, /Do not launch a collector/);
  assert.match(skills.get("plan/what-to-collect")!.meta.title as string, /through the operator/);
  assert.equal(skills.get("plan/what-to-collect")!.meta.requires_host.length, 0);
  assert.match(skills.get("gaps/what-is-missing")!.meta.title as string, /can and cannot establish/);
  // the rule of the request skill is not turned round: the census says what is held, the failed targets and the unseen kinds are the gaps
  assert.doesNotMatch(skills.get("plan/what-to-collect")!.body, /Ask only for what neither lists/);
  assert.match(skills.get("plan/what-to-collect")!.body, /do not ask for what it holds/);
  assert.doesNotMatch(skills.get("verify/target-outcomes")!.body, /no row anywhere is not delivered/i);
  assert.match(skills.get("verify/target-outcomes")!.body, /unknown outcome/);
  // every leaf that names a tool says how its output is held
  for (const s of skills.values()) {
    if (((s.meta.tools as string[]) ?? []).length === 0) continue;
    assert.match(s.body, /Sensitive output:[^\n]*secret_output: true/, `${s.id} names a tool and says the job runs with secret_output: true`);
  }
  assert.match(skills.get("verify/manifests")!.body, /does not open a container/);
  assert.doesNotMatch(all, /archive_extract/, "an extractor that no pack ships is not advertised");
  assert.match(skills.get("identify/collector")!.body, /\bnot determined, never zero\b/);
  assert.match(skills.get("identify/collector")!.body, /more than one kind of object/);
  assert.doesNotMatch(skills.get("identify/collector")!.body, /copied files sit beside an image/);
  assert.match(skills.get("gaps/coverage-statement")!.body, /looked_for or looked_for_none_why/);
  assert.match(skills.get("gaps/what-is-missing")!.body, /once, plainly and early/);
  assert.match(skills.get("plan/sources-linux")!.body, /\/root/);
  assert.match(skills.get("plan/sources-linux")!.body, /\/var\/log\/journal/);
  assert.match(skills.get("plan/sources-windows")!.body, /ConsoleHost_history\.txt/);
  assert.match(skills.get("normalise/layout")!.body, /drop named streams altogether/);
});

test("the goal template asks the new questions, keeps its acceptance checks, and binds the unallocated check to the answer's own section without a pipe that can fail", async () => {
  const goal = await readFile(join(TRIAGE, "goals", "collection-intake.md"), "utf8");
  assert.match(goal, /5\. The delivered-object inventory/);
  assert.match(goal, /6\. Integrity and time provenance/);
  assert.match(goal, /source-filesystem, embedded-record, archive-member and analysis-filesystem/);
  assert.doesNotMatch(goal, /whether\s+the timestamps are original|cannot\s+contain/);
  // nothing else an agent had to satisfy was loosened
  for (const check of ["test -f work/report.md", "check-answers.ts", "inputs_check", '"tool":"skill"', '"kind":"event"']) assert.ok(goal.includes(check), check);
  const checks = [...goal.matchAll(/^- `(.+)`$/gm)].map((m) => m[1]);
  const unallocated = checks.find((c) => c.includes("unallocated"));
  assert.ok(unallocated, "the unallocated check is there");
  assert.match(unallocated!, /^awk '\/\^## \[0-9\]\+\\\.\/\{s=\/\^## 4\\\.\/\} s && tolower\(\$0\) ~ \/unallocated\|logical acquisition\/\{f=1\} END\{exit !f\}' work\/report\.md$/);
  for (const c of checks.filter((x) => x.includes("work/report.md"))) assert.doesNotMatch(c, /\|\s*grep -q/, `${c.slice(0, 60)} ends a pipe in grep -q: grep exits at the first match, the writer of a large report gets SIGPIPE, and pipefail fails the check`);
  // run the check the way the harness does (set -euo pipefail, eval), on reports of three sizes and on the cases it must tell apart
  const { spawnSync } = await import("node:child_process");
  const { mkdtemp, writeFile, mkdir, rm } = await import("node:fs/promises");
  const { tmpdir } = await import("node:os");
  const dir = await mkdtemp(join(tmpdir(), "goal-check-"));
  try {
    await mkdir(join(dir, "work"), { recursive: true });
    const run = (report: string): number | null => {
      writeFileSync(join(dir, "work", "report.md"), report);
      return spawnSync("bash", ["-c", `set -euo pipefail; ${unallocated}`], { cwd: dir, stdio: ["ignore", "pipe", "pipe"] }).status;
    };
    const filler = "A line of the report that says nothing about the word.\n";
    const section4 = (size: number) => `## 1. a\nx\n## 4. What this delivery can establish\nNo unallocated space was delivered.\n${filler.repeat(size)}## 5. next\ny\n`;
    for (const lines of [10, 1000, 6000]) for (let i = 0; i < 5; i++) assert.equal(run(section4(lines)), 0, `a report with ${lines} filler lines in section 4 passes`);
    assert.equal(run(`## 4. x\n${filler}## 5. Unallocated inventory\n${filler}`), 1, "the word in the next section's heading is not the answer to question 4");
    assert.equal(run(`## 4. x\n${filler}## 5. y\nunallocated here only\n`), 1, "the word only in section 5 fails");
    assert.equal(run(`## 4. Unallocated space\n${filler}## 5. y\n`), 0, "the word in section 4's own heading passes");
    assert.equal(run(`## 4. x\nThe acquisition was a logical acquisition.\n## 5. y\n`), 0);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
