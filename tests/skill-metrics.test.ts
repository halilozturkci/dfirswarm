/**
 * What a run did with its skills, read from the trace alone
 * (ui/src/lib/skill-metrics.ts): the code the context audit and the console's
 * Packs tab share. A hand-made trace with every case the record can show: a
 * seat that never loaded one, a load a later row uses by name, one it uses by
 * a tool its front matter names, one nothing shows used, a body a compaction
 * took out and the seat loaded again, a miss, an answer that the body was
 * already held, and a seat whose prompt never carried the index.
 */
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { audit, readRows, renderMarkdown, skillFindings } from "../scripts/context-audit.ts";
import { carriedSkills, skillUse, type SkillTraceRow } from "../ui/src/lib/skill-metrics.ts";

let clock = 0;
const row = (agent: string, tool: string, args: Record<string, unknown>, result: Record<string, unknown> = {}): SkillTraceRow => ({
  ts: `2026-10-07T10:00:${String(clock++).padStart(2, "0")}.000Z`,
  agent,
  tool,
  args,
  result,
});

const load = (agent: string, id: string, extra: Record<string, unknown> = {}) =>
  row(agent, "skill", { id }, { ok: true, pack: "pack-a", bytes: 2_000, sha256: `sha-${id}`, tokens: 500, tools: [], needs: [], ...extra });

function trace(): SkillTraceRow[] {
  clock = 0;
  return [
    row("s0", "skills_index", {}, { ok: true, source: "prompt", matches_packs: true, section_tokens: 900, shown_tokens: 800 }),
    row("s1", "skills_index", {}, { ok: true, source: "prompt", matches_packs: true, section_tokens: 900, shown_tokens: 800 }),
    row("s2", "skills_index", {}, { ok: true, source: "prompt", matches_packs: true, section_tokens: 900, shown_tokens: 800 }),
    // s0: three loads. One is named later, one is used through a tool its front matter names, one nothing shows used.
    load("s0", "execution/prefetch", { tools: ["prefetch_mam"], turn: 2 }),
    load("s0", "registry/devices", { turn: 3 }),
    load("s0", "logs/security", { tokens: 700, turn: 4 }),
    row("s0", "bash", { command: "prefetch_mam /evidence/a.pf" }, { ok: true }),
    row("s0", "post", { body: "From registry/devices: the USB serial matches." }, { ok: true }),
    row("s0", "skill_done", { id: "registry/devices", note: "device serials" }, { ok: true, turn: 9 }),
    // A compaction: all three are summarised out. The seat loads one again, with the flag the harness writes.
    row("s0", "compact_done", { via: "self", reason: "threshold" }, { ok: true, cycle: 1, tokens_before: 160_000 }),
    row("s0", "skills_compacted", {}, { ok: true, kept: [], lost: [{ key: "pack-a:execution/prefetch", turn: 2 }, { key: "pack-a:registry/devices", turn: 3 }, { key: "pack-a:logs/security", turn: 4 }] }),
    load("s0", "registry/devices", { reload_after_compaction: true, turn: 20 }),
    // s1: a miss, an answer that it already holds the body, an index read, then one load nothing shows used.
    row("s1", "skill", { id: "windows/execution/prefetch" }, { ok: false, error: "no such skill" }),
    load("s1", "execution/prefetch", { tools: ["prefetch_mam"] }),
    row("s1", "skill", { id: "execution/prefetch" }, { ok: true, already_loaded: true, loaded_at_turn: 3, tokens_saved: 500 }),
    row("s1", "skill", { id: "INDEX" }, { ok: true, in_prompt: false }),
    row("s1", "thinking", {}, { text: "nothing to do with prefetch here, the registry is empty", chars: 50 }),
    // s2 never touches a skill. s3 is a seat with no index row and no load.
    row("s2", "bash", { command: "ls" }, { ok: true }),
    row("s3", "bash", { command: "ls" }, { ok: true }),
    row("system", "reap", {}, { ok: true }),
  ];
}

test("per seat: loads, tokens, used after load, no trace of use, done, lost at a compaction, loaded again, misses", () => {
  const use = skillUse(trace(), ["s0", "s1", "s2", "s3"]);
  const s0 = use.seats.find((s) => s.agent === "s0")!;
  assert.deepEqual([s0.index_in_prompt, s0.index_source, s0.index_tokens], [true, "prompt", 900]);
  assert.equal(s0.lost_basis, "skills_compacted");
  assert.equal(s0.loads, 4, "three, and the reload");
  assert.equal(s0.distinct, 3);
  assert.equal(s0.tokens_loaded, 500 + 500 + 700 + 500);
  // prefetch is used through its tool, devices by name; logs/security by nothing; the reload of devices has nothing after it.
  assert.deepEqual(s0.detail.map((d) => [d.id, d.referenced]), [["execution/prefetch", true], ["registry/devices", true], ["logs/security", false], ["registry/devices", false]]);
  assert.equal(s0.referenced, 2);
  assert.equal(s0.unused, 2);
  assert.equal(s0.done, 1);
  assert.equal(s0.compactions, 1);
  assert.equal(s0.lost_at_compaction, 3, "the three loaded before the compaction");
  assert.equal(s0.refetched, 1, "one load after it, of a note it held before");
  assert.deepEqual(s0.detail.filter((d) => d.lost_at_compaction).map((d) => [d.id, d.refetched]), [["execution/prefetch", false], ["registry/devices", true], ["logs/security", false]]);
  assert.deepEqual(s0.detail.filter((d) => d.done).map((d) => d.id), ["registry/devices"]);

  const s1 = use.seats.find((s) => s.agent === "s1")!;
  assert.deepEqual([s1.loads, s1.already_loaded, s1.failed, s1.index_reads], [1, 1, 1, 1]);
  assert.equal(s1.referenced, 0, "a reasoning row that says 'prefetch' is not the id, and the tool was never called");
  assert.equal(s1.unused, 1);

  const s2 = use.seats.find((s) => s.agent === "s2")!;
  assert.deepEqual([s2.index_in_prompt, s2.loads], [true, 0]);
  const s3 = use.seats.find((s) => s.agent === "s3")!;
  assert.deepEqual([s3.index_in_prompt, s3.loads], [false, 0], "a seat with no skills_index row did not get the index");

  assert.deepEqual(use.totals, {
    seats: 4,
    seats_with_index: 3,
    seats_that_loaded: 2,
    loads: 5,
    tokens_loaded: 2_700,
    done: 1,
    referenced: 2,
    unused: 3,
    lost_at_compaction: 3,
    refetched: 1,
    loads_without_tools: 0,
    already_loaded: 1,
    failed: 1,
    index_reads: 1,
  });
});

test("a use by a tool the skill names counts only as a whole word, and a later mention of the id by another seat is not this seat's", () => {
  clock = 0;
  const rows = [
    load("a", "n/one", { tools: ["mam"] }),
    row("a", "bash", { command: "mammoth --list" }, { ok: true }),
    load("b", "n/one", { tools: ["mam"] }),
    row("a", "post", { body: "n/one says so" }, { ok: true }),
    row("b", "bash", { command: "echo nothing" }, { ok: true }),
  ];
  const use = skillUse(rows);
  assert.deepEqual(use.seats.map((s) => [s.agent, s.referenced]), [["a", 1], ["b", 0]], "mammoth is not mam; seat a's post is not seat b's use");
});

test("the per-skill rollup counts loads, tokens and the seats over the whole trace, keyed by pack and id", () => {
  clock = 0;
  const rows = [
    load("a", "shared/dup", { pack: "p1", tokens: 100 }),
    load("b", "shared/dup", { pack: "p2", tokens: 200 }),
    load("c", "shared/dup", { pack: "p1", tokens: 100 }),
  ];
  const use = skillUse(rows);
  assert.deepEqual(use.by_skill.map((r) => [r.key, r.loads, r.tokens, r.agents]), [["p1:shared/dup", 2, 200, ["a", "c"]], ["p2:shared/dup", 1, 200, ["b"]]]);
  assert.equal(carriedSkills(rows), true);
  assert.equal(carriedSkills([row("a", "bash", {})]), false);
});

test("a row from before the harness wrote the pack, the hash and the tokens still counts, from its bytes", () => {
  clock = 0;
  const old = row("a", "skill", { id: "x/y" }, { ok: true, bytes: 4_245 });
  const use = skillUse([old]);
  assert.equal(use.seats[0]!.tokens_loaded, 1_000);
  assert.deepEqual(use.by_skill.map((r) => r.key), ["x/y"]);
});

test("the context audit carries the skills: a table, findings that name the seats the index missed, and the JSON", () => {
  const dir = mkdtempSync(join(tmpdir(), "skill-audit-"));
  const file = join(dir, "events.jsonl");
  const seat = (agent: string): SkillTraceRow[] => [
    row(agent, "compact_config", { defaults: true }, { ok: true, model: "x/m", window: 200_000, ceiling: 200_000, notice: 80_000, warning: 100_000, compact: 120_000 }),
    row(agent, "context", {}, { ok: true, tokens: 20_000, ceiling: 200_000 }),
  ];
  const rows = [...trace().filter((r) => ["s0", "s1"].includes(r.agent)), ...seat("s0"), ...seat("s1"), ...seat("s2"), ...seat("s3"), row("s2", "skills_index", {}, { ok: true, section_tokens: 900 })];
  writeFileSync(file, rows.map((r) => JSON.stringify(r)).join("\n"));
  const read = readRows(file);
  const run = audit(read.rows, file, read.bad);
  assert.deepEqual(run.agents.map((a) => a.agent), ["s0", "s1", "s2", "s3"]);
  assert.equal(run.skills.totals.loads, 5);
  assert.equal(run.agents.find((a) => a.agent === "s0")!.skills.loads, 4);
  const f = run.findings.join("\n");
  assert.match(f, /3 of 4 seats had the run's index in the prompt Pi keeps for every run/);
  assert.match(f, /s3: no `skills_index` row, so nothing says the packs' index reached that seat\./);
  assert.match(f, /Skills: 5 bodies loaded by 2 of 4 seats \(2,700 tokens\); 2 seats never loaded one\./);
  assert.match(f, /Of those loads, 2 show a later use .* and 3 show none \(a proxy.*1 was marked done with skill_done\./);
  assert.match(f, /3 loaded bodies were taken out of the seat's context by a compaction \(the newest part of the history a compaction keeps is not counted\); 1 was loaded again\./);
  assert.ok(!/upper bound/.test(f), "seat s0's compaction is on a skills_compacted row: exact");
  assert.match(f, /1 call asked for a body the seat already held and was told so/);
  assert.match(f, /1 skill call named no skill the packs carry\./);
  const md = renderMarkdown(run);
  assert.match(md, /## Skills\n\n\| Agent \| Index in prompt \| Loads \|/);
  assert.match(md, /\| s0 \| yes \(900 tokens\) \| 4 \| 3 \| 2,200 \| 2 \| 2 \| 1 \| 3 \| 1 \| 0 \|/);
  assert.match(md, /Taken out by a compaction/);
  assert.match(md, /\| s1 \| yes \(900 tokens\) \| 1 \| 1 \| 500 \| 0 \| 1 \| 0 \| 0 \| 0 \| 1 \|/);
  // A run with no skill row says nothing about skills.
  const quiet = audit(readRows(file).rows.filter((r) => !r.tool.startsWith("skill")), file);
  assert.deepEqual(skillFindings(quiet.skills), []);
  assert.ok(!renderMarkdown(quiet).includes("## Skills"));
});

test("a run with self-compaction off still gets its skill findings, from the seats the trace shows", () => {
  clock = 0;
  const rows = [
    row("a0", "agent_start", {}, { ok: true }),
    row("a1", "agent_start", {}, { ok: true }),
    row("system", "reap", {}, { ok: true }),
    row("a0", "skills_index", {}, { ok: true, source: "prompt", matches_packs: true, section_tokens: 600 }),
    load("a0", "execution/prefetch"),
  ];
  const use = skillUse(rows);
  assert.deepEqual(use.seats.map((s) => s.agent), ["a0", "a1"], "the watchdog is not a seat");
  const run = audit(rows.map((r) => ({ ts: r.ts, agent: r.agent, tool: r.tool, args: (r.args ?? {}) as Record<string, unknown>, result: (r.result ?? {}) as Record<string, unknown> })), "x");
  assert.deepEqual(run.skills.seats.map((s) => s.agent), ["a0", "a1"]);
  assert.match(run.findings.join("\n"), /No `context` rows/);
  assert.match(run.findings.join("\n"), /a1: no `skills_index` row/);
  assert.match(run.findings.join("\n"), /Skills: 1 body loaded by 1 of 2 seats/);
});

test("an index only counts when Pi's own prompt carried this run's, whole: an extension's, a stale file's and a pack-less run's do not", () => {
  clock = 0;
  const rows = [
    row("a", "skills_index", {}, { ok: true, source: "prompt", matches_packs: true, section_tokens: 700 }),
    row("b", "skills_index", {}, { ok: true, source: "extension", section_tokens: 700 }),
    row("c", "skills_index", {}, { ok: false, source: "stale", matches_packs: false, section_tokens: 700 }),
    row("d", "skills_index", {}, { ok: true, source: "none" }),
    row("e", "skills_index", {}, { ok: true, source: "prompt", matches_packs: false }),
  ];
  const use = skillUse(rows, ["a", "b", "c", "d", "e"]);
  assert.deepEqual(use.seats.map((x) => [x.agent, x.index_in_prompt, x.index_source]), [["a", true, "prompt"], ["b", false, "extension"], ["c", false, "stale"], ["d", false, "none"], ["e", false, "prompt"]]);
  assert.equal(use.totals.seats_with_index, 1);
  const lines = audit(rows.map((r) => ({ ts: r.ts, agent: r.agent, tool: r.tool, args: {}, result: (r.result ?? {}) as Record<string, unknown> })), "x").findings.join("\n");
  assert.match(lines, /1 of 5 seats had the run's index in the prompt Pi keeps for every run/);
  assert.match(lines, /b: the prompt had no index, the extension added it to the first run's prompt, and a run a hand-off starts does not keep that\./);
  assert.match(lines, /c: the prompt carried an index written for other packs\./);
  assert.match(lines, /d: the packs listed no skill\./);
});

test("a body a compaction kept is not counted as lost, and a seat with no skills_compacted row is counted the old way and says so", () => {
  clock = 0;
  const rows = [
    load("k", "n/old", { turn: 1 }),
    load("k", "n/new", { turn: 9 }),
    // The compaction took the old one out and kept the new one (the kept tail), then the old one came back.
    row("k", "skills_compacted", {}, { ok: true, kept: [{ key: "pack-a:n/new", turn: 9 }], lost: [{ key: "pack-a:n/old", turn: 1 }] }),
    load("k", "n/old", { turn: 12, reload_after_compaction: true }),
    // A neighbour with only compact_done rows (a trace from before skills_compacted): the approximation.
    load("m", "n/old", { turn: 1 }),
    load("m", "n/new", { turn: 9 }),
    row("m", "compact_done", { via: "pi", reason: "threshold" }, { ok: true, cycle: 1 }),
  ];
  const use = skillUse(rows, ["k", "m"]);
  const k = use.seats.find((x) => x.agent === "k")!;
  assert.deepEqual([k.lost_at_compaction, k.refetched, k.lost_basis], [1, 1, "skills_compacted"]);
  assert.deepEqual(k.detail.map((d) => [d.id, d.lost_at_compaction, d.refetched]), [["n/old", true, true], ["n/new", false, false], ["n/old", false, false]]);
  const m = use.seats.find((x) => x.agent === "m")!;
  assert.deepEqual([m.lost_at_compaction, m.lost_basis], [2, "compact_done"]);
  const text = audit(rows.map((r) => ({ ts: r.ts, agent: r.agent, tool: r.tool, args: (r.args ?? {}) as Record<string, unknown>, result: (r.result ?? {}) as Record<string, unknown> })), "x").findings.join("\n");
  assert.match(text, /no skills_compacted row, so every compaction is counted as taking every body loaded before it: an upper bound/);
});

test("loads from rows that carry no tools list are counted and said: the proxy cannot see their tools", () => {
  clock = 0;
  const old = (id: string) => row("o", "skill", { id }, { ok: true, bytes: 2_000 });
  const rows = [old("a/b"), load("o", "c/d", { tools: [] }), row("o", "bash", { command: "echo a/b" }, { ok: true })];
  const use = skillUse(rows, ["o"]);
  assert.equal(use.seats[0]!.loads_without_tools, 1, "an empty list is a list; a missing one is an old row");
  assert.equal(use.totals.loads_without_tools, 1);
  const findings = audit(rows.map((r) => ({ ts: r.ts, agent: r.agent, tool: r.tool, args: (r.args ?? {}) as Record<string, unknown>, result: (r.result ?? {}) as Record<string, unknown> })), "x").findings.join("\n");
  assert.match(findings, /1 of the loads come from rows that carry no tools list \(a trace from before the harness wrote it\)/);
});
