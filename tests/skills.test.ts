/**
 * How a seat meets a pack's method (extensions/skills.ts): the Skills section
 * of the forced prompt and its budgets, the `skill` tool's answers, the
 * `skill_done` event, what a compaction does to what a seat holds, and the
 * kickoff's `--no-skills`. No model and no key: the extension is loaded
 * through Pi's own loader and its tools and hooks are called the way Pi calls
 * them. The same section surviving a real compaction, through the real CLI
 * and a scripted provider, is tests/skills-e2e.test.ts.
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { access, mkdir, mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { test } from "node:test";
import { EVENTS_REL, initSandbox, TOOL_RESERVED_NAMES } from "../extensions/protocol.ts";
import {
  collidingIds,
  estimateTokens,
  parseIndex,
  parseWanted,
  readPackIndex,
  renderFullIndex,
  renderSkillsSection,
  SKILL_BUDGET,
  SKILLS_SECTION_TITLE,
  splitSkill,
  suggestIds,
  type PackIndex,
} from "../extensions/skills.ts";
import { handoffHeader } from "../extensions/self-compact.ts";
import { PREFETCH_BODY, twoPacks, writePack, type SkillSpec } from "./fixtures/skill-packs.ts";

const REPO = resolve(import.meta.dirname, "..");

// ---------------------------------------------------------------------------
// The budgets, the index and the section: pure
// ---------------------------------------------------------------------------

function fakePack(id: string, entries: Array<[string, string]>, router: string | null = null, version = "1.0.0"): PackIndex {
  const list = entries.map(([eid, text]) => {
    const line = `- \`${eid}\` ${text}`;
    return { id: eid, line, tokens: estimateTokens(line) };
  });
  return { id, version, dir: `/packs/${id}`, entries: list, router, tokens: list.reduce((n, e) => n + e.tokens, 0) };
}

test("the estimator is bytes over 4.245, rounded up, of the UTF-8 text", () => {
  assert.equal(estimateTokens(""), 0);
  assert.equal(estimateTokens("a".repeat(4245)), 1000);
  assert.equal(estimateTokens("a".repeat(4246)), 1001);
  assert.equal(estimateTokens("é".repeat(100)), estimateTokens("x".repeat(200)), "bytes, not characters");
});

test("an INDEX.md gives its entries as written and the router it names, when it lists it", () => {
  const text = "# Skills in this pack\n\nFetch a body.\n\nRouter: `windows/overview`\n\n- `windows/overview` Where to start: First.\n- `windows/mft` The MFT: A file's times.\n";
  const parsed = parseIndex(text);
  assert.deepEqual(parsed.entries.map((e) => e.id), ["windows/overview", "windows/mft"]);
  assert.equal(parsed.entries[1]!.line, "- `windows/mft` The MFT: A file's times.");
  assert.equal(parsed.router, "windows/overview");
  assert.equal(parseIndex(text.replace("Router: `windows/overview`", "Router: `nothing/there`")).router, null, "a router the index does not list is no router");
  assert.equal(parseIndex("- `a/b` T: w\n").router, null);
});

test("within budget every entry is shown whole, under its pack, and the section is the same text each time", () => {
  const packs = [fakePack("base", [["a/one", "One: first."], ["a/two", "Two: second."]], null, "1.0.3"), fakePack("win", [["w/mft", "MFT: times."]], null, "2.1.0")];
  const first = renderSkillsSection(packs);
  const again = renderSkillsSection(packs);
  assert.equal(first.text, again.text, "byte-stable: the prompt cache sees the same prefix");
  assert.ok(first.text.startsWith(SKILLS_SECTION_TITLE));
  assert.match(first.text, /base 1\.0\.3 \(2 skills\)\n- `a\/one` One: first\.\n- `a\/two` Two: second\./);
  assert.match(first.text, /win 2\.1\.0 \(1 skill\)\n- `w\/mft` MFT: times\./);
  assert.equal(first.report.mode, "full");
  assert.deepEqual(first.report.over_budget, []);
  assert.equal(first.report.shown_tokens, first.report.index_tokens);
  assert.deepEqual(first.report.budget, SKILL_BUDGET);
  assert.equal(first.report.sha256, createHash("sha256").update(first.text).digest("hex"));
});

test("a pack over its budget shows its router only; a pack within it is shown whole", () => {
  const big = fakePack("big", [["big/router", "Router: start here."], ["big/a", "A: " + "x".repeat(200)], ["big/b", "B: " + "y".repeat(200)]], "big/router");
  const small = fakePack("small", [["s/one", "One: ok."]], null);
  const { text, report } = renderSkillsSection([big, small], { entry: 40, pack: 100, run: 10_000 });
  assert.equal(report.mode, "routers");
  assert.deepEqual(report.packs.map((p) => [p.id, p.shown]), [["big", "router"], ["small", "full"]]);
  assert.match(text, /big 1\.0\.0 \(3 skills, router only\)\n- `big\/router` Router: start here\.\n\nsmall/);
  assert.ok(!text.includes("big/a") && !text.includes("big/b"), "the leaves of a collapsed pack are not in the prompt");
  assert.match(text, /skill\(\) with no id lists every skill of every pack/);
  assert.equal(report.over_budget.length, 1);
  assert.match(report.over_budget[0]!, /^pack big \d+ > 100$/);
  assert.ok(report.shown_tokens < report.index_tokens);
});

test("a run over its budget shows every pack's router only", () => {
  const mk = (id: string) => fakePack(id, [[`${id}/router`, "Router: go."], [`${id}/leaf`, "Leaf: " + "z".repeat(120)]], `${id}/router`);
  const packs = [mk("p1"), mk("p2"), mk("p3")];
  // Each pack is within its budget; together they pass the run's.
  const { text, report } = renderSkillsSection(packs, { entry: 100, pack: 100, run: 100 });
  assert.equal(report.mode, "routers");
  assert.ok(report.packs.every((p) => p.shown === "router"));
  assert.ok(report.over_budget.some((o) => /^run \d+ > 100$/.test(o)), report.over_budget.join(";"));
  for (const id of ["p1", "p2", "p3"]) assert.ok(text.includes(`- \`${id}/router\``) && !text.includes(`${id}/leaf`));
  // Within budget nothing collapses.
  assert.equal(renderSkillsSection(packs, { entry: 100, pack: 1000, run: 1000 }).report.mode, "full");
});

test("a pack with no router cannot be shortened: it is shown whole, and the report says so", () => {
  const plain = fakePack("plain", [["p/a", "A: " + "q".repeat(300)], ["p/b", "B: " + "r".repeat(300)]], null);
  const { text, report } = renderSkillsSection([plain], { entry: 40, pack: 50, run: 60 });
  assert.equal(report.mode, "full");
  assert.deepEqual(report.packs.map((p) => p.shown), ["full"]);
  assert.deepEqual(report.no_router, ["plain"]);
  assert.ok(text.includes("`p/a`") && text.includes("`p/b`"), "nothing is cut");
  assert.ok(report.over_budget.length >= 1);
});

test("an entry over the entry budget is shown whole and named; an id two packs carry is listed as pack:id", () => {
  const long = fakePack("p1", [["x/long", "Long: " + "w".repeat(300)], ["dup/id", "Dup: in both."]], null);
  const other = fakePack("p2", [["dup/id", "Dup: in both, from the other."], ["y/ok", "Ok: fine."]], null);
  const { text, report } = renderSkillsSection([long, other]);
  assert.deepEqual(report.long_entries.map((e) => [e.pack, e.id]), [["p1", "x/long"]]);
  assert.ok(text.includes("w".repeat(300)), "an over-long entry is never clipped");
  assert.deepEqual(report.collisions, ["dup/id"]);
  assert.ok(text.includes("- `p1:dup/id` Dup: in both.") && text.includes("- `p2:dup/id` Dup: in both, from the other."));
  assert.ok(text.includes("- `x/long`") && text.includes("- `y/ok`"), "an id only one pack carries stays bare");
  assert.deepEqual([...collidingIds([long, other])], ["dup/id"]);
  assert.match(renderFullIndex([long, other]), /p2 1\.0\.0 \(2 skills\)\n- `p2:dup\/id`/);
});

test("packs with no skills add nothing, and an unreadable index is reported", async () => {
  const root = await mkdtemp(join(tmpdir(), "skills-pure-"));
  try {
    const none = join(root, "tools-only");
    await mkdir(join(none, "tools"), { recursive: true });
    const noIndex = join(root, "no-index");
    await mkdir(join(noIndex, "skills"), { recursive: true });
    const a = await readPackIndex(none);
    const b = await readPackIndex(noIndex);
    assert.deepEqual([a.entries.length, a.error], [0, undefined], "a pack of tools alone is not a fault");
    assert.match(b.error ?? "", /has no INDEX\.md/);
    assert.equal(renderSkillsSection([a]).text, "");
    const withError = renderSkillsSection([b]);
    assert.deepEqual(withError.report.unreadable.map((u) => u.pack), ["no-index"]);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a skill file: front matter parsed, body without it, id and pack:id accepted, a wrong id suggested", () => {
  const { meta, body } = splitSkill("---\nid: a/b\ntitle: T\nneeds: [x/y, z/w]\ntools: []\n---\n\nThe body.\n");
  assert.equal(meta.title, "T");
  assert.deepEqual(meta.needs, ["x/y", "z/w"]);
  assert.deepEqual(meta.tools, []);
  assert.equal(body, "The body.");
  assert.deepEqual(parseWanted("execution/prefetch"), { pack: null, id: "execution/prefetch" });
  assert.deepEqual(parseWanted(" windows-forensics:execution/prefetch "), { pack: "windows-forensics", id: "execution/prefetch" });
  for (const bad of ["", "Execution/Prefetch", "../etc/passwd", "a/../b", "pack:", ":id", "a b"]) assert.equal(parseWanted(bad), null, bad);
  const packs = [fakePack("windows-forensics", [["execution/prefetch", "P: x"], ["execution/overview", "O: y"], ["registry/devices", "R: z"]])];
  assert.deepEqual(suggestIds(packs, "windows/execution/prefetch").slice(0, 1), ["execution/prefetch"], "the pack-prefixed shape 17 of 143 calls used");
  assert.deepEqual(suggestIds(packs, "prefetch"), ["execution/prefetch"]);
  assert.deepEqual(suggestIds(packs, "catalog_search"), []);
});

test("every shipped pack's index parses, and a whole run of them renders without cutting an entry", async () => {
  const dirs = (await readdir(join(REPO, "packs"), { withFileTypes: true })).filter((d) => d.isDirectory()).map((d) => join(REPO, "packs", d.name));
  assert.ok(dirs.length >= 12);
  const indexes: PackIndex[] = [];
  for (const dir of dirs) {
    const manifest = JSON.parse(await readFile(join(dir, "pack.json"), "utf8")) as { id: string; skills?: number };
    const index = await readPackIndex(dir);
    assert.equal(index.id, manifest.id);
    assert.equal(index.error, undefined, dir);
    assert.equal(index.entries.length, manifest.skills ?? 0, `${manifest.id}: the index lists every skill the manifest counts`);
    assert.equal(new Set(index.entries.map((e) => e.id)).size, index.entries.length, `${manifest.id}: ids are unique inside a pack`);
    indexes.push(index);
  }
  const { text, report } = renderSkillsSection(indexes);
  for (const index of indexes) for (const entry of index.entries) {
    const shown = text.includes(entry.line) || text.includes(entry.line.replace(/^- `[^`]+`/, `- \`${index.id}:${entry.id}\``));
    assert.ok(shown || report.packs.find((p) => p.id === index.id)?.shown === "router", `${index.id}/${entry.id} is in the section unless its pack shows its router only`);
  }
  assert.equal(report.index_tokens, indexes.reduce((n, p) => n + p.tokens, 0));
});

// ---------------------------------------------------------------------------
// The extension, loaded the way Pi loads it
// ---------------------------------------------------------------------------

let loaderLookup: Promise<string | null> | undefined;
/** Pi's extension loader, found once for the file: the pinned package first, then a global one. */
function findLoader(): Promise<string | null> {
  return (loaderLookup ??= locateLoader());
}

async function locateLoader(): Promise<string | null> {
  const candidates: string[] = [];
  if (process.env.PI_PACKAGE_DIR) candidates.push(process.env.PI_PACKAGE_DIR);
  candidates.push(join(REPO, "node_modules", "@earendil-works", "pi-coding-agent"));
  const tryAll = async (): Promise<string | null> => {
    for (const dir of candidates) {
      const loader = join(dir, "dist", "core", "extensions", "loader.js");
      try {
        await access(loader);
        return loader;
      } catch {
        // next
      }
    }
    return null;
  };
  const found = await tryAll();
  if (found) return found;
  try {
    candidates.push(join(execFileSync("npm", ["root", "-g"], { encoding: "utf8" }).trim(), "@earendil-works", "pi-coding-agent"));
  } catch {
    // npm missing
  }
  return tryAll();
}

type Tool = { definition: { execute: (...args: unknown[]) => Promise<{ content: Array<{ type: string; text: string }>; details: Record<string, unknown> }> } };
type Handler = (event: unknown, ctx: unknown) => Promise<unknown>;
type Loaded = { tools: Map<string, Tool>; handlers: Map<string, Handler[]> };

/** What the session says: the entries in the model's context (a compaction's kept tail included) and the whole branch. */
type FakeSession = { context: unknown[]; branch: unknown[] };

type Seat = {
  root: string;
  ctx: { cwd: string; hasUI: false; ui: Record<string, never>; sessionManager: { getEntries: () => unknown[]; buildContextEntries: () => unknown[]; getBranch: () => unknown[] } };
  loaded: Loaded;
  session: FakeSession;
  skill: (id?: string, callId?: string) => Promise<{ text: string; details: Record<string, unknown> }>;
  done: (id: string, note?: string, callId?: string) => Promise<{ text: string; details: Record<string, unknown> }>;
  trace: () => Promise<Array<{ tool: string; agent: string; args: Record<string, unknown>; result: Record<string, unknown> }>>;
  fire: (event: string, payload?: Record<string, unknown>) => Promise<unknown[]>;
  prompt: (base?: string) => Promise<string>;
};

/** One seat: an extension loaded through Pi's loader over a sandbox and the given pack directories. */
async function withSeat(t: { skip: (m: string) => void }, packDirs: string[], run: (seat: Seat) => Promise<void>): Promise<void> {
  const loaderFile = await findLoader();
  if (!loaderFile) {
    t.skip("Pi package not found (set PI_PACKAGE_DIR or npm ci)");
    return;
  }
  const { loadExtensions } = (await import(loaderFile)) as { loadExtensions: (paths: string[], cwd: string) => Promise<{ extensions: Loaded[]; errors: unknown[] }> };
  const root = await mkdtemp(join(tmpdir(), "skills-seat-"));
  const keep = { agent: process.env.AGENT_ID, packs: process.env.SWARM_PACK_DIRS, compact: process.env.SWARM_SELF_COMPACT };
  try {
    await initSandbox(root, { reset: true });
    process.env.AGENT_ID = "agent00";
    process.env.SWARM_PACK_DIRS = packDirs.join(":");
    delete process.env.SWARM_SELF_COMPACT;
    const result = await loadExtensions([join(REPO, "extensions", "agent-swarm.ts")], root);
    assert.deepEqual(result.errors, []);
    const loaded = result.extensions[0]!;
    const session: FakeSession = { context: [], branch: [] };
    const ctx = { cwd: root, hasUI: false as const, ui: {}, sessionManager: { getEntries: () => session.branch, buildContextEntries: () => session.context, getBranch: () => session.branch } };
    const call = async (name: string, params: Record<string, unknown>, callId?: string) => {
      const tool = loaded.tools.get(name);
      assert.ok(tool, `${name} is registered`);
      const out = await tool.definition.execute(callId ?? `call-${Math.random().toString(36).slice(2)}`, params, undefined, undefined, ctx);
      return { text: out.content.map((c) => c.text).join(""), details: out.details };
    };
    const fire = async (event: string, payload: Record<string, unknown> = {}) => {
      const outs: unknown[] = [];
      for (const handler of loaded.handlers.get(event) ?? []) outs.push(await handler({ type: event, ...payload }, ctx));
      return outs;
    };
    await run({
      root,
      ctx,
      loaded,
      session,
      skill: (id, callId) => call("skill", id === undefined ? {} : { id }, callId),
      done: (id, note, callId) => call("skill_done", note === undefined ? { id } : { id, note }, callId),
      trace: async () => (await readFile(join(root, EVENTS_REL), "utf8").catch(() => "")).trim().split("\n").filter(Boolean).map((l) => JSON.parse(l)),
      fire,
      prompt: async (base = "BASE PROMPT") => {
        const outs = await fire("before_agent_start", { prompt: "go", systemPrompt: base, systemPromptOptions: { cwd: root } });
        return String((outs.find((o) => o && typeof o === "object" && "systemPrompt" in (o as object)) as { systemPrompt: string } | undefined)?.systemPrompt ?? "");
      },
    });
  } finally {
    for (const [name, value] of [["AGENT_ID", keep.agent], ["SWARM_PACK_DIRS", keep.packs], ["SWARM_SELF_COMPACT", keep.compact]] as const) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
    execFileSync("chmod", ["-R", "u+w", root]);
    await rm(root, { recursive: true, force: true });
  }
}

const lastRow = async (seat: Seat, tool: string) => [...(await seat.trace())].reverse().find((r) => r.tool === tool)!;

test("a skill body comes back as plain Markdown: no front matter, no JSON, the pack and the cost in one line", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "skills-packs-"));
  try {
    const { a, b } = await twoPacks(root);
    await withSeat(t, [a, b], async (seat) => {
      const out = await seat.skill("evidence/one");
      assert.ok(!out.text.trimStart().startsWith("{"), "no JSON envelope");
      assert.ok(!/^---\n/m.test(out.text) && !out.text.includes("requires_host:") && !out.text.includes("\\n"), "no front matter, no escaped newlines");
      const [head, , ...rest] = out.text.split("\n");
      assert.match(head!, /^Skill `evidence\/one` \(pack pack-a 1\.2\.0, about \d+ tokens\): The first note$/);
      assert.ok(out.text.includes(PREFETCH_BODY), "the body whole");
      assert.ok(rest.join("\n").startsWith(PREFETCH_BODY), "the body follows the header");
      // The trace row: the file's own sha256 (the one pack.json's checksums carry) and the tokens of what was delivered.
      const raw = await readFile(join(a, "skills", "evidence", "one.md"));
      const row = await lastRow(seat, "skill");
      assert.equal(row.args.id, "evidence/one");
      assert.equal(row.result.ok, true);
      assert.equal(row.result.pack, "pack-a");
      assert.equal(row.result.sha256, createHash("sha256").update(raw).digest("hex"));
      assert.equal(row.result.bytes, raw.length);
      assert.equal(row.result.tokens, estimateTokens(PREFETCH_BODY));
      assert.deepEqual(row.result.tools, ["tool_alpha"]);
      assert.deepEqual(row.result.needs, ["evidence/two", "other/x"]);
      assert.equal(typeof row.result.duration_ms, "number");
      assert.equal(row.agent, "agent00");
      assert.equal(out.details.sha256, row.result.sha256, "the result's details carry it too");
    });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("needs are listed with their cost and never loaded", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "skills-packs-"));
  try {
    const { a, b } = await twoPacks(root);
    await withSeat(t, [a, b], async (seat) => {
      const out = await seat.skill("evidence/one");
      const twoTokens = estimateTokens("Second body, short.");
      assert.match(out.text, /Builds on, not loaded: `evidence\/two` \(about \d+ tokens\), `pack-b:other\/x` \(about \d+ tokens\)\. Load those you need\./);
      assert.ok(out.text.includes(`\`evidence/two\` (about ${twoTokens} tokens)`));
      assert.ok(!out.text.includes("Second body, short.") && !out.text.includes("X body."), "no need was loaded for the seat");
      const needs = out.details.needs as Array<{ ref: string; tokens: number | null }>;
      assert.deepEqual(needs.map((n) => n.ref), ["evidence/two", "pack-b:other/x"], "a need another pack carries is named pack:id");
      assert.ok(needs.every((n) => typeof n.tokens === "number"));
      // Nothing was sent, so loading the need is a load, not an "already in your context".
      const two = await seat.skill("evidence/two");
      assert.match(two.text, /^Skill `evidence\/two`/);
      assert.ok(two.text.includes("Second body, short."));
      // Asking for the first again now says the need is loaded.
      const rows = (await seat.trace()).filter((r) => r.tool === "skill");
      assert.equal(rows.length, 2);
    });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a need the seat already holds is said to be loaded, a need no pack carries is said so", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "skills-packs-"));
  try {
    const a = await writePack(root, "solo", "1.0.0", {
      "n/first": { title: "First", when: "Always.", needs: ["n/second", "n/ghost"], body: "First body." },
      "n/second": { title: "Second", when: "Next.", body: "Second body." },
    });
    await withSeat(t, [a], async (seat) => {
      await seat.skill("n/second");
      const out = await seat.skill("n/first");
      assert.match(out.text, /`n\/second` \(already loaded, turn 1\)/);
      assert.match(out.text, /`n\/ghost` \(not carried by this run's packs\)/);
    });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("pack:id names one pack's copy; a bare id two packs carry is served by the first and says who else has it", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "skills-packs-"));
  try {
    const { a, b } = await twoPacks(root);
    await withSeat(t, [a, b], async (seat) => {
      const bare = await seat.skill("shared/dup");
      assert.ok(bare.text.includes("The copy from pack A."));
      assert.match(bare.text, /^Skill `shared\/dup` \(pack pack-a 1\.2\.0/);
      assert.match(bare.text, /Also carried by pack-b: skill\("pack-b:shared\/dup"\) loads that one\./);
      const explicit = await seat.skill("pack-b:shared/dup");
      assert.ok(explicit.text.includes("The copy from pack B."), explicit.text);
      assert.match(explicit.text, /^Skill `shared\/dup` \(pack pack-b 0\.4\.1/);
      const rows = (await seat.trace()).filter((r) => r.tool === "skill");
      assert.deepEqual(rows.map((r) => [r.args.id, r.result.pack]), [["shared/dup", "pack-a"], ["shared/dup", "pack-b"]], "the trace names the pack that served each body");
      assert.deepEqual(rows[0]!.result.also_in, ["pack-b"]);
      assert.equal(rows[1]!.args.requested, "pack-b:shared/dup");
      // A pack-qualified id for a skill the pack does not have, and a pack the run does not carry.
      const wrongPack = await seat.skill("pack-b:evidence/one");
      assert.match(wrongPack.text, /No skill "pack-b:evidence\/one"/);
      const noPack = await seat.skill("nope:evidence/one");
      assert.match(noPack.text, /No pack "nope" in this run \(it carries: pack-a, pack-b\)/);
    });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a body the seat already holds is answered by the turn it arrived in, not sent again; a compaction takes it out", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "skills-packs-"));
  try {
    const { a, b } = await twoPacks(root);
    await withSeat(t, [a, b], async (seat) => {
      await seat.skill("evidence/one");
      const turnEnds = seat.loaded.handlers.get("turn_end") ?? [];
      assert.ok(turnEnds.length >= 1);
      // Two turns pass.
      for (let i = 0; i < 2; i++) await seat.fire("turn_end", { turnIndex: i, message: { role: "assistant", content: [] }, toolResults: [] }).catch(() => undefined);
      const again = await seat.skill("evidence/one");
      assert.match(again.text, /^`evidence\/one` \(pack-a\) is already in your context, loaded at turn 1; not sent again\.$/);
      assert.ok(!again.text.includes("A prefetch file proves"), "the body is not resent");
      assert.equal(again.details.already_loaded, true);
      const row = await lastRow(seat, "skill");
      assert.equal(row.result.already_loaded, true);
      assert.equal(row.result.loaded_at_turn, 1);
      assert.equal(row.result.turn, 3, "the turn the call was made in: two turns finished, this is the third");
      assert.equal(row.result.tokens_saved, estimateTokens(PREFETCH_BODY));
      // The same body by its pack:id is the same load.
      assert.match((await seat.skill("pack-a:evidence/one")).text, /already in your context/);

      // A compaction summarised it away: the same call delivers it again, and the row says so.
      await seat.fire("session_compact", { compactionEntry: { id: "c1" }, fromExtension: false });
      const back = await seat.skill("evidence/one");
      assert.ok(back.text.includes("A prefetch file proves a run"), "delivered again after a compaction");
      const reload = await lastRow(seat, "skill");
      assert.equal(reload.result.reload_after_compaction, true);
      assert.equal(reload.result.ok, true);
    });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a wrong id is told the shapes that exist, not the whole list; the index call points at the prompt", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "skills-packs-"));
  try {
    const { a, b } = await twoPacks(root);
    await withSeat(t, [a, b], async (seat) => {
      const prefixed = await seat.skill("pack-a/evidence/one");
      assert.match(prefixed.text, /^No skill "pack-a\/evidence\/one" in this run's packs\. Did you mean: evidence\/one/);
      assert.ok(!prefixed.text.includes("evidence/three"), "no id list");
      const row = await lastRow(seat, "skill");
      assert.deepEqual([row.result.ok, row.result.error], [false, "no such skill"]);
      assert.ok((row.result.suggested as string[]).includes("evidence/one"));
      const bad = await seat.skill("Evidence/One");
      assert.match(bad.text, /lower case and slash separated/);
      assert.equal((await lastRow(seat, "skill")).result.error, "bad id");
      // Before any prompt is built nothing says the index is in one: the call answers with the index.
      const early = await seat.skill();
      assert.ok(early.text.includes("- `evidence/one`") && early.text.includes("pack-b 0.4.1"), "the whole index");
      assert.equal((await lastRow(seat, "skill")).result.in_prompt, false);
    });
    await withSeat(t, [a, b], async (seat) => {
      // With the kickoff's section in Pi's own prompt the call points there and sends nothing.
      const section = renderSkillsSection(await Promise.all([a, b].map((d) => readPackIndex(d)))).text;
      await seat.prompt(`PREAMBLE\n\n<addendum>\n${section}\n</addendum>`);
      const index = await seat.skill();
      assert.match(index.text, new RegExp(`whole index of this run's packs is in your instructions, under "${SKILLS_SECTION_TITLE}"`));
      const irow = await lastRow(seat, "skill");
      assert.deepEqual([irow.args.id, irow.result.in_prompt], ["INDEX", true]);
    });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("skill_done records what the seat took, marks the body releasable, and says so when there is nothing to mark", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "skills-packs-"));
  try {
    const { a, b } = await twoPacks(root);
    await withSeat(t, [a, b], async (seat) => {
      const early = await seat.done("evidence/one", "never loaded");
      assert.match(early.text, /is not among the notes you have loaded/);
      assert.deepEqual([early.details.ok, early.details.error], [false, "not loaded"]);

      await seat.skill("evidence/one");
      const done = await seat.done("evidence/one", "run count and last eight times; not who ran it");
      assert.match(done.text, /^Recorded: `evidence\/one` is done\./);
      const row = await lastRow(seat, "skill_done");
      assert.equal(row.args.id, "evidence/one");
      assert.equal(row.args.note, "run count and last eight times; not who ran it", "the note whole");
      assert.deepEqual([row.result.ok, row.result.pack, row.result.releasable], [true, "pack-a", true]);
      assert.equal(row.result.sha256, createHash("sha256").update(await readFile(join(a, "skills", "evidence", "one.md"))).digest("hex"));
      assert.equal(row.result.loaded_turn, 1);
      assert.match((await seat.done("evidence/one")).text, /already marked done/);
      // Done is not unloaded: the body is still in the context, so the tool still says so.
      assert.match((await seat.skill("evidence/one")).text, /already in your context.*marked done/);

      await seat.fire("session_compact", {});
      assert.match((await seat.done("evidence/one")).text, /is not among the notes you have loaded/);

      // Two packs' copies loaded: the bare id is ambiguous, pack:id is not.
      await seat.skill("shared/dup");
      await seat.skill("pack-b:shared/dup");
      const ambiguous = await seat.done("shared/dup", "x");
      assert.match(ambiguous.text, /More than one pack's `shared\/dup` is loaded: name it as pack:id \(pack-a:shared\/dup, pack-b:shared\/dup\)/);
      assert.match((await seat.done("pack-b:shared/dup", "the other one")).text, /^Recorded/);
    });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a fourth body while three are held and not done carries the reminder, and the row says how many were held", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "skills-packs-"));
  try {
    const { a, b } = await twoPacks(root);
    await withSeat(t, [a, b], async (seat) => {
      for (const id of ["evidence/two", "evidence/three", "evidence/four"]) assert.ok(!/You hold \d+ notes/.test((await seat.skill(id)).text));
      const fourth = await seat.skill("evidence/one");
      assert.match(fourth.text, /You hold 3 notes you have not marked done \(evidence\/two, evidence\/three, evidence\/four\)\. Mark the ones you have finished with skill_done before you load more\./);
      assert.equal((await lastRow(seat, "skill")).result.holding, 3);
      // Finish one: the next load is clean.
      await seat.done("evidence/two", "done");
      await seat.done("evidence/three", "done");
      assert.ok(!/You hold \d+ notes/.test((await seat.skill("shared/dup")).text));
    });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("the forced prompt carries the Skills section once, before the seat's own lines, and the same text every time", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "skills-packs-"));
  try {
    const { a, b } = await twoPacks(root);
    await withSeat(t, [a, b], async (seat) => {
      const first = await seat.prompt("BASE PROMPT");
      assert.ok(first.startsWith("BASE PROMPT"), first.slice(0, 80));
      assert.equal(first.split(SKILLS_SECTION_TITLE).length - 1, 1, "once");
      assert.match(first, /pack-a 1\.2\.0 \(5 skills\)\n- `evidence\/four` A fourth note: Rarely too\./);
      assert.ok(first.includes("- `pack-a:shared/dup` In both packs: Whenever.") && first.includes("- `pack-b:shared/dup` In both packs: Whenever."), "collisions are pack:id");
      assert.ok(first.includes("- `other/x` Another pack's note: On the other side."));
      assert.ok(first.indexOf(SKILLS_SECTION_TITLE) < first.indexOf("Your assigned id is agent00"), "the stable section sits before the seat's own lines");
      const second = await seat.prompt("BASE PROMPT");
      assert.equal(second, first, "byte-stable across prompts, so the cached prefix is");
      // One trace row for the section, however many prompts are built.
      const rows = (await seat.trace()).filter((r) => r.tool === "skills_index");
      assert.equal(rows.length, 1);
      const r = rows[0]!.result;
      assert.deepEqual([r.ok, r.mode, r.collisions, r.source], [true, "full", ["shared/dup"], "extension"], "a prompt with no section was given one");
      assert.ok(typeof r.section_tokens === "number" && (r.section_tokens as number) > 0);
      assert.deepEqual((r.packs as Array<{ id: string; shown: string }>).map((p) => [p.id, p.shown]), [["pack-a", "full"], ["pack-b", "full"]]);
      const section = first.slice(first.indexOf(SKILLS_SECTION_TITLE)).split("\n\nYour assigned id")[0]!;
      assert.equal(r.sha256, createHash("sha256").update(section).digest("hex"), "the row's hash is the hash of the section the seat was given");
      assert.equal(r.chars, section.length);
    });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a prompt that already carries the section (the kickoff's APPEND_SYSTEM.md) is not given it twice, and the row says whether it matches the packs", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "skills-packs-"));
  try {
    const { a, b } = await twoPacks(root);
    const section = renderSkillsSection(await Promise.all([a, b].map((d) => readPackIndex(d)))).text;
    await withSeat(t, [a, b], async (seat) => {
      const out = await seat.prompt(`PREAMBLE\n\n<addendum>\n${section}\n</addendum>`);
      assert.equal(out.split(SKILLS_SECTION_TITLE).length - 1, 1, "once");
      assert.ok(out.startsWith("PREAMBLE"));
      const row = (await seat.trace()).find((r) => r.tool === "skills_index")!;
      assert.deepEqual([row.result.ok, row.result.source, row.result.matches_packs], [true, "prompt", true]);
    });
    await withSeat(t, [a, b], async (seat) => {
      // A heading with no index under it (a one-line heading in a custom prompt, no kickoff file): the title is not the index.
      const out = await seat.prompt(`PREAMBLE\n\n${SKILLS_SECTION_TITLE}\n\nsomething else entirely`);
      assert.ok(out.includes("- `evidence/one` The first note") && out.includes("- `other/x`"), "the run's index is added, whole");
      assert.ok(out.includes("does not list this run's packs"), "and the old heading is said to be wrong");
      const row = (await seat.trace()).find((r) => r.tool === "skills_index")!;
      assert.deepEqual([row.result.ok, row.result.source, row.result.matches_packs], [false, "stale", false]);
      const board = await readdir(join(seat.root, "threads", "main")).catch(() => [] as string[]);
      const posts = await Promise.all(board.map((f) => readFile(join(seat.root, "threads", "main", f), "utf8")));
      assert.ok(posts.some((p) => /HARNESS FAULT: agent00's prompt carries a Skills section that is not the index of this run's packs/.test(p)), posts.join("\n---\n"));
    });
    await withSeat(t, [a, b], async (seat) => {
      // A file written for pack-a alone, the run carries both: the index of one pack passes for the index of two.
      const one = renderSkillsSection([await readPackIndex(a)]).text;
      const out = await seat.prompt(`PREAMBLE\n\n<addendum>\n${one}\n</addendum>`);
      assert.ok(out.includes("pack-b 0.4.1 (2 skills)") && out.includes("- `other/x`"), "pack-b's entries are added");
      const row = (await seat.trace()).find((r) => r.tool === "skills_index")!;
      assert.deepEqual([row.result.ok, row.result.source], [false, "stale"]);
    });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a run with no pack has no skill tools and no section; a pack whose index cannot be read is a fault on the trace and the board", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "skills-packs-"));
  try {
    const broken = join(root, "broken");
    await mkdir(join(broken, "skills", "x"), { recursive: true });
    await writeFile(join(broken, "skills", "x", "y.md"), "---\nid: x/y\ntitle: T\nwhen: w\n---\n\nbody\n");
    const { a } = await twoPacks(root);
    await withSeat(t, [a, broken], async (seat) => {
      const prompt = await seat.prompt("BASE");
      assert.ok(prompt.includes("- `evidence/one`"), "the readable pack is still in the section");
      const row = (await seat.trace()).find((r) => r.tool === "skills_index")!;
      assert.equal(row.result.ok, false);
      assert.deepEqual(row.result.unreadable, [{ pack: "broken", reason: "skills/ has no INDEX.md" }]);
      const board = await readdir(join(seat.root, "threads", "main")).catch(() => [] as string[]);
      const posts = await Promise.all(board.map((f) => readFile(join(seat.root, "threads", "main", f), "utf8")));
      assert.ok(posts.some((p) => /HARNESS FAULT: the Skills section of agent00's prompt could not list broken/.test(p)), posts.join("\n---\n"));
    });
    // No pack: the tools are not there, the prompt is the base.
    const loaderPath = await findLoader();
    if (loaderPath) {
      const { loadExtensions } = (await import(loaderPath)) as { loadExtensions: (paths: string[], cwd: string) => Promise<{ extensions: Loaded[]; errors: unknown[] }> };
      const keep = process.env.SWARM_PACK_DIRS;
      delete process.env.SWARM_PACK_DIRS;
      try {
        const sandbox = await mkdtemp(join(tmpdir(), "skills-none-"));
        await initSandbox(sandbox, { reset: true });
        const none = (await loadExtensions([join(REPO, "extensions", "agent-swarm.ts")], sandbox)).extensions[0]!;
        assert.ok(!none.tools.has("skill") && !none.tools.has("skill_done"));
        await rm(sandbox, { recursive: true, force: true });
      } finally {
        if (keep !== undefined) process.env.SWARM_PACK_DIRS = keep;
      }
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a pack's router stands in for its entries in the prompt when the run's index is over budget", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "skills-packs-"));
  try {
    // 40 skills with long "when" lines: well over a 1,000-token pack index; one is the router.
    const skills: Record<string, SkillSpec> = {};
    for (let i = 0; i < 40; i++) skills[`area/leaf-${String(i).padStart(2, "0")}`] = { title: `Leaf number ${i}`, when: `Reach for this when a very particular artefact of kind ${i} turns up in the evidence and nothing simpler explains it, and say which.`, body: `leaf ${i}` };
    skills["area/router"] = { title: "Where to start in this pack", when: "First, whenever the artefact class is not obvious.", body: "Router body.", router: true };
    const big = await writePack(root, "big-pack", "3.0.0", skills);
    const small = await writePack(root, "small-pack", "1.0.0", { "s/one": { title: "One", when: "Always.", body: "One." } });
    await withSeat(t, [big, small], async (seat) => {
      const prompt = await seat.prompt("BASE");
      assert.match(prompt, /big-pack 3\.0\.0 \(41 skills, router only\)\n- `area\/router` Where to start in this pack/);
      assert.ok(!prompt.includes("leaf-07"), "the leaves of the pack over budget are not in the prompt");
      assert.ok(prompt.includes("- `s/one` One: Always."), "a pack within budget is whole");
      const row = (await seat.trace()).find((r) => r.tool === "skills_index")!;
      assert.equal(row.result.mode, "routers");
      assert.ok((row.result.over_budget as string[]).some((o) => /^pack big-pack [\d,]+ > 1,000$/.test(o)), JSON.stringify(row.result.over_budget));
      // skill() with no id is the way to the leaves, once; asking again says it was listed.
      const index = await seat.skill();
      assert.ok(index.text.includes("area/leaf-07") && index.text.includes("area/router") && index.text.includes("s/one"));
      assert.equal((await lastRow(seat, "skill")).result.in_prompt, false);
      assert.match((await seat.skill()).text, /already listed at turn 1/);
      // The leaf is reachable by its id.
      assert.match((await seat.skill("area/leaf-07")).text, /^Skill `area\/leaf-07`/);
    });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// What the harness tells a seat after a compaction, the reserved names, the kickoff
// ---------------------------------------------------------------------------

test("the hand-off header lists the skill bodies the seat held before its context was compacted", () => {
  const facts = { claims: [], unread: {}, ledgerTotal: 0, ledgerMine: 0, sentinel: false, spentUsd: 0 };
  const without = handoffHeader("agent00", 1, facts, true, "threshold");
  assert.ok(!without.includes("Skill bodies"));
  const withSkills = handoffHeader("agent00", 1, { ...facts, skills: "Skill bodies a compaction took out of your context: pack-a:evidence/one, pack-b:shared/dup. Load again (skill(id)) the ones you still need." }, true, "threshold");
  assert.match(withSkills, /Skill bodies a compaction took out of your context: pack-a:evidence\/one, pack-b:shared\/dup\./);
});

test("the seat's hand-off line names what a compaction took, until the seat loads it again", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "skills-packs-"));
  try {
    const { a, b } = await twoPacks(root);
    const { registerSkills } = await import("../extensions/skills.ts");
    const handlers = new Map<string, Array<(event: unknown, ctx: unknown) => Promise<void>>>();
    const tools = new Map<string, { execute: (...a: unknown[]) => Promise<{ content: Array<{ text: string }> }> }>();
    const fake = {
      on: (event: string, h: (event: unknown, ctx: unknown) => Promise<void>) => handlers.set(event, [...(handlers.get(event) ?? []), h]),
      registerTool: (def: { name: string; execute: (...a: unknown[]) => Promise<{ content: Array<{ text: string }> }> }) => tools.set(def.name, def),
    };
    const sandbox = await mkdtemp(join(tmpdir(), "skills-fake-"));
    await initSandbox(sandbox, { reset: true });
    const rows: string[] = [];
    const handle = registerSkills(fake as never, { packDirs: [a, b], agentId: () => "agent00", trace: async (_c, tool) => void rows.push(tool), turns: () => 0, fault: async () => undefined });
    assert.equal(handle.handoffLine(), "", "nothing loaded, nothing to list");
    await tools.get("skill")!.execute("c1", { id: "evidence/one" }, undefined, undefined, { cwd: sandbox });
    await tools.get("skill")!.execute("c2", { id: "pack-b:shared/dup" }, undefined, undefined, { cwd: sandbox });
    // The session says nothing of either body is left in the context.
    const emptyContext = { cwd: sandbox, sessionManager: { buildContextEntries: () => [], getBranch: () => [] } };
    for (const h of handlers.get("session_compact") ?? []) await h({ type: "session_compact" }, emptyContext);
    assert.match(handle.handoffLine(), /a compaction took out of your context: pack-a:evidence\/one, pack-b:shared\/dup\. Load again/);
    await tools.get("skill")!.execute("c3", { id: "evidence/one" }, undefined, undefined, { cwd: sandbox });
    assert.match(handle.handoffLine(), /pack-b:shared\/dup/);
    // The seam for an unloader: the done ones are releasable, and releasing one frees its slot.
    assert.deepEqual(handle.ledger.releasable(), []);
    await tools.get("skill_done")!.execute("c4", { id: "evidence/one", note: "n" }, undefined, undefined, { cwd: sandbox });
    assert.deepEqual(handle.ledger.releasable().map((l) => [l.key, l.toolCallId]), [["pack-a:evidence/one", "c3"]]);
    handle.ledger.release("pack-a:evidence/one");
    assert.match((await tools.get("skill")!.execute("c5", { id: "evidence/one" }, undefined, undefined, { cwd: sandbox })).content[0]!.text, /^Skill `evidence\/one`/, "a released body is delivered again");
    await rm(sandbox, { recursive: true, force: true });
    void t;
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

/** A session entry holding a tool result, as Pi writes one. */
const resultEntry = (callId: string, toolName: string, details: Record<string, unknown>) => ({ type: "message", id: `e-${callId}`, message: { role: "toolResult", toolName, toolCallId: callId, details } });
const assistantEntry = (n: number) => ({ type: "message", id: `a-${n}`, message: { role: "assistant", content: [] } });

test("two calls in one assistant message take turns: Pi runs them at the same time, and the second finds the first's body loaded", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "skills-packs-"));
  try {
    const { a, b } = await twoPacks(root);
    await withSeat(t, [a, b], async (seat) => {
      const [first, second] = await Promise.all([seat.skill("evidence/one"), seat.skill("evidence/one")]);
      assert.match(first.text, /^Skill `evidence\/one`/);
      assert.ok(first.text.includes("A prefetch file proves a run"));
      assert.match(second.text, /^`evidence\/one` \(pack-a\) is already in your context, loaded at turn 1; not sent again\.$/);
      const rows = (await seat.trace()).filter((r) => r.tool === "skill");
      assert.deepEqual(rows.map((r) => [r.result.ok, r.result.already_loaded ?? false]), [[true, false], [true, true]], "one load row, one answer that it is loaded");

    });
    await withSeat(t, [a, b], async (seat) => {
      // Four different notes in one message: the reminder is on the fourth, the one that makes four.
      const ids = ["evidence/two", "evidence/three", "evidence/four", "shared/dup"];
      const out = await Promise.all(ids.map((id) => seat.skill(id)));
      assert.deepEqual(out.map((o) => /You hold \d+ notes/.test(o.text)), [false, false, false, true], out.map((o) => o.text.slice(-120)).join("\n---\n"));
    });
    await withSeat(t, [a, b], async (seat) => {
      // A load and its skill_done in one message: the load comes first, so there is a note to mark.
      const [loaded, done] = await Promise.all([seat.skill("evidence/two"), seat.done("evidence/two", "taken")]);
      assert.match(loaded.text, /^Skill `evidence\/two`/);
      assert.match(done.text, /^Recorded: `evidence\/two` is done\./);
    });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a compaction keeps what the session says is still in the context: the newest bodies stay, the rest are taken out and said", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "skills-packs-"));
  try {
    const { a, b } = await twoPacks(root);
    await withSeat(t, [a, b], async (seat) => {
      const one = await seat.skill("evidence/one", "c1");
      const two = await seat.skill("evidence/two", "c2");
      const three = await seat.skill("evidence/three", "c3");
      await seat.done("evidence/three", "taken", "c4");
      const done = (await seat.trace()).find((r) => r.tool === "skill_done")!;
      assert.ok(one && two && done);
      // The compaction kept the newest part of the history: the third body and its done, not the first two.
      seat.session.context = [{ type: "compaction", id: "k", firstKeptEntryId: "e-c3" }, resultEntry("c3", "skill", three.details), resultEntry("c4", "skill_done", { ok: true, id: "evidence/three", pack: "pack-a", turn: 1, note: "taken" })];
      await seat.fire("session_compact", { compactionEntry: { id: "k", firstKeptEntryId: "e-c3" } });
      const kept = await seat.skill("evidence/three");
      assert.match(kept.text, /^`evidence\/three` \(pack-a\) is already in your context, loaded at turn 1 and marked done; not sent again\.$/, "still there, and still done");
      const again = await seat.skill("evidence/one");
      assert.match(again.text, /^Skill `evidence\/one`/, "a body the compaction took out is delivered again");
      assert.equal((await lastRow(seat, "skill")).result.reload_after_compaction, true);
      const row = await lastRow(seat, "skills_compacted");
      assert.deepEqual(row.result.kept, [{ key: "pack-a:evidence/three", turn: 1 }]);
      assert.deepEqual(row.result.lost, [{ key: "pack-a:evidence/one", turn: 1 }, { key: "pack-a:evidence/two", turn: 1 }]);
      // A second compaction that keeps nothing of it.
      seat.session.context = [{ type: "compaction", id: "k2", firstKeptEntryId: null }];
      await seat.fire("session_compact", {});
      assert.match((await seat.skill("evidence/three")).text, /^Skill `evidence\/three`/);
    });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a process that starts on a session that already holds a body knows it, and counts its turns on from the session's", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "skills-packs-"));
  try {
    const { a, b } = await twoPacks(root);
    // What the first process delivered, from its own tool result.
    let delivered: Record<string, unknown> = {};
    await withSeat(t, [a, b], async (first) => {
      delivered = (await first.skill("evidence/one", "c1")).details;
      await first.done("evidence/one", "taken", "c2");
    });
    await withSeat(t, [a, b], async (seat) => {
      seat.session.context = [resultEntry("c1", "skill", delivered), resultEntry("c2", "skill_done", { ok: true, id: "evidence/one", pack: "pack-a", turn: 1, note: "taken" })];
      seat.session.branch = [assistantEntry(1), assistantEntry(2), assistantEntry(3), ...seat.session.context];
      await seat.fire("session_start", { reason: "startup" });
      const again = await seat.skill("evidence/one");
      assert.match(again.text, /^`evidence\/one` \(pack-a\) is already in your context, loaded at turn 1 and marked done; not sent again\.$/);
      assert.equal((await lastRow(seat, "skill")).result.turn, 4, "three turns were had before this process: this is the fourth");
      assert.match((await seat.done("evidence/one", "again")).text, /^`evidence\/one` was already marked done/);
      await seat.skill("evidence/two");
      assert.equal((await lastRow(seat, "skill")).result.turn, 4);
    });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("the ids a seat guesses under a pack's name are not answered with a note about something else", async (t) => {
  // The failures of the runs: pack-prefixed ids, tool names, ids of method no pack carries.
  const packs = [
    fakePack("windows-forensics", [["execution/prefetch", "P: x"], ["registry/devices", "R: x"], ["registry/overview", "R: y"], ["antiforensics/traces", "A: x"], ["filesystem/mft", "F: x"], ["logs/security", "L: x"]]),
    fakePack("memory-forensics", [["memory/windows", "W: x"], ["triage/volatility", "V: x"]]),
    fakePack("computer-forensics-base", [["evidence/catalog", "C: x"]]),
  ];
  assert.deepEqual(suggestIds(packs, "windows/execution/prefetch"), ["execution/prefetch"]);
  assert.deepEqual(suggestIds(packs, "windows-forensics:execution/prefetch"), ["execution/prefetch"]);
  assert.deepEqual(suggestIds(packs, "windows/anti-forensics"), ["antiforensics/traces"], "dashes do not count, and a directory of that name is named");
  assert.deepEqual(suggestIds(packs, "windows/registry"), ["registry/devices", "registry/overview"]);
  for (const guess of ["windows/ntfs", "windows/ntfs/logfile", "windows/secrets/dpapi", "windows", "catalog_search", "computer-forensics-base", "mobile/ios/biome"]) assert.deepEqual(suggestIds(packs, guess), [], `${guess}: nothing close, so nothing named`);
  // The tool says so, and sends the seat to the index rather than to a wrong note.
  const root = await mkdtemp(join(tmpdir(), "skills-packs-"));
  try {
    const win = await writePack(root, "windows-forensics", "1.0.0", { "memory/windows": { title: "Windows memory", when: "A Windows image.", body: "m" }, "execution/prefetch": { title: "Prefetch", when: "Runs.", body: "p" } });
    await withSeat(t, [win], async (seat) => {
      const miss = await seat.skill("windows/ntfs");
      assert.match(miss.text, /^No skill "windows\/ntfs" in this run's packs\. No close match; read the index in your instructions \("Skills carried by this run"\)/);
      assert.ok(!miss.text.includes("memory/windows"));
      assert.deepEqual((await lastRow(seat, "skill")).result.suggested, undefined);
      assert.match((await seat.skill("windows/execution/prefetch")).text, /Did you mean: execution\/prefetch\?/);
    });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a prompt the extension had to give the index to loses it with the run a hand-off starts: the index and the skill() answer follow the source", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "skills-packs-"));
  try {
    const { a, b } = await twoPacks(root);
    await withSeat(t, [a, b], async (seat) => {
      await seat.prompt("BASE PROMPT");
      assert.equal((await seat.trace()).find((r) => r.tool === "skills_index")!.result.source, "extension");
      const index = await seat.skill();
      assert.ok(index.text.includes("- `evidence/one`"), "the call answers with the index, not with a pointer to a prompt that may not carry it");
      assert.equal((await lastRow(seat, "skill")).result.in_prompt, false);
    });
    // The hand-off header: the index comes back there.
    const { registerSkills } = await import("../extensions/skills.ts");
    const handlers = new Map<string, Array<(event: unknown, ctx: unknown) => Promise<void>>>();
    const fake = { on: (e: string, h: (event: unknown, ctx: unknown) => Promise<void>) => handlers.set(e, [...(handlers.get(e) ?? []), h]), registerTool: () => undefined };
    const rows: string[] = [];
    const handle = registerSkills(fake as never, { packDirs: [a, b], agentId: () => "agent00", trace: async (_c, tool) => void rows.push(tool), turns: () => 0, fault: async () => undefined });
    await handle.promptSection(root, "BASE PROMPT");
    assert.match(handle.handoffLine(), /^The index of this run's packs \(your prompt no longer carries it\):\nSkills carried by this run/);
    assert.ok(handle.handoffLine().includes("- `other/x`"));
    const withFile = registerSkills(fake as never, { packDirs: [a, b], agentId: () => "agent00", trace: async () => undefined, turns: () => 0, fault: async () => undefined });
    await withFile.promptSection(root, `x ${renderSkillsSection(await Promise.all([a, b].map((d) => readPackIndex(d)))).text} y`);
    assert.equal(withFile.handoffLine(), "", "a prompt that carries the index keeps it: the header does not repeat it");
    void t;
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("front matter with CRLF line ends is stripped; an index that lists nothing for a pack that counts skills is a fault; the tool's examples name no pack", async (t) => {
  const crlf = "---\r\nid: a/b\r\ntitle: T\r\nneeds: [x/y]\r\ntools: [t1]\r\n---\r\n\r\nThe body.\r\n";
  const parsed = splitSkill(crlf);
  assert.equal(parsed.body, "The body.");
  assert.deepEqual([parsed.meta.title, parsed.meta.needs, parsed.meta.tools], ["T", ["x/y"], ["t1"]]);
  const root = await mkdtemp(join(tmpdir(), "skills-packs-"));
  try {
    const broken = join(root, "broken-index");
    await mkdir(join(broken, "skills"), { recursive: true });
    await writeFile(join(broken, "pack.json"), JSON.stringify({ id: "broken-index", version: "1.0.0", skills: 3 }));
    await writeFile(join(broken, "skills", "INDEX.md"), "# Skills in this pack\n\nA list nobody can parse:\n\n* alpha/one: first\n");
    const index = await readPackIndex(broken);
    assert.match(index.error ?? "", /lists no skill although pack\.json counts 3/);
    const empty = join(root, "no-skills");
    await mkdir(join(empty, "skills"), { recursive: true });
    await writeFile(join(empty, "pack.json"), JSON.stringify({ id: "no-skills", version: "1.0.0", skills: 0 }));
    await writeFile(join(empty, "skills", "INDEX.md"), "# Skills in this pack\n");
    assert.equal((await readPackIndex(empty)).error, undefined, "a pack that counts none lists none");
    const { a } = await twoPacks(root);
    await withSeat(t, [a, broken], async (seat) => {
      await seat.prompt("BASE");
      const row = (await seat.trace()).find((r) => r.tool === "skills_index")!;
      assert.equal(row.result.ok, false);
      assert.deepEqual(row.result.unreadable, [{ pack: "broken-index", reason: "skills/INDEX.md lists no skill although pack.json counts 3" }]);
      for (const name of ["skill", "skill_done"]) {
        const def = seat.loaded.tools.get(name)!.definition as unknown as { description: string; parameters: unknown };
        assert.ok(!/windows|prefetch/i.test(def.description + JSON.stringify(def.parameters)), `${name}'s description names a pack's note`);
      }
      assert.match((await seat.skill("NOT AN ID")).text, /"evidence\/four"\), optionally with its pack in front \("pack-a:evidence\/four"\)|"evidence\/(one|two|three|four)"/);
    });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("the worker prompt's Skills section sends no method to the ledger, counts notes not marked done, and does not promise a listing it cannot give", async () => {
  const prompt = await readFile(join(REPO, "prompts", "worker-system.md"), "utf8");
  const section = prompt.slice(prompt.indexOf("Skills (only when `skill` is in your tool list)"), prompt.indexOf("Context (only when `self_compact`"));
  assert.ok(section.length > 500);
  const flat = section.replace(/\s+/g, " ");
  assert.match(flat, /Never put the method in the ledger/);
  assert.ok(!/in the post, record or note/.test(flat), "no recital in a ledger record");
  assert.match(flat, /Hold at most three notes you have not marked done/);
  assert.match(flat, /takes the bodies it summarises out of your context \(the newest part of the history stays\)/);
  assert.match(flat, /When the index shows routers only, `skill\(\)` with no id lists every skill/);
  assert.ok(!/takes every body out/.test(flat));
});

test("the harness's own skill events are reserved against forged tools", () => {
  for (const name of ["skill", "skill_done", "skills_index"]) assert.ok(TOOL_RESERVED_NAMES.has(name), `${name} is reserved`);
});

test("every place the kickoff starts Pi passes --no-skills and the seat's prompt files, in that order, and the allowlist names both skill tools", async () => {
  const sh = await readFile(join(REPO, "scripts", "swarm.sh"), "utf8");
  const lines = sh.split("\n");
  const launches = lines.map((l, i) => ({ l, i })).filter(({ l }) => /--session-dir "\$sandbox\/\.pi-sessions\//.test(l));
  assert.equal(launches.length, 3, "a seat's Pi is started in three places: the host panes, the probe, a VM's launch script");
  for (const { i } of launches) {
    const around = lines.slice(Math.max(0, i - 6), i + 1).join("\n");
    assert.ok(around.includes("--no-skills"), `the Pi launch at swarm.sh:${i + 1} does not pass --no-skills:\n${around}`);
    // The prompt files come from one function, called for this seat just before, and sit between --no-skills/--name and --session-dir.
    assert.match(around, /seat_prompt_args "\$sandbox" "[^"]+"/, `the Pi launch at swarm.sh:${i + 1} does not build the seat's prompt arguments:\n${around}`);
    assert.ok(around.indexOf("--no-skills") < around.indexOf('"${SEAT_PROMPT_ARGS[@]}"') && around.indexOf('"${SEAT_PROMPT_ARGS[@]}"') < around.indexOf("--session-dir"), `the Pi launch at swarm.sh:${i + 1} passes the prompt files in another place:\n${around}`);
  }
  assert.match(sh, /\[\[ -n "\$pack_dirs" \]\] && PI_TOOLS\+=",skill,skill_done"/);
});

test("seat_prompt_args: the run's file and then the seat's, as explicit sources; the run's file left out when it is empty; paths with spaces, quotes and $ kept whole", async () => {
  const sh = await readFile(join(REPO, "scripts", "swarm.sh"), "utf8");
  const fn = /^seat_prompt_args\(\) \{[\s\S]*?^\}/m.exec(sh)![0];
  const root = await mkdtemp(join(tmpdir(), "seat args "));
  try {
    const sandbox = join(root, "My Cases", "çase $HOME 'q' [x]");
    await mkdir(join(sandbox, ".pi"), { recursive: true });
    const args = (id: string) => execFileSync("bash", ["-c", `${fn}\nseat_prompt_args "$1" "$2"\nprintf '%s\\0' "\${SEAT_PROMPT_ARGS[@]}"`, "_", sandbox, id], { encoding: "utf8" }).split("\0").slice(0, -1);
    // Empty run file (nothing applies): only the seat's own file is given, and that alone replaces Pi's discovery of a global one.
    await writeFile(join(sandbox, ".pi", "APPEND_SYSTEM.md"), "");
    assert.deepEqual(args("s1234500"), ["--append-system-prompt", join(sandbox, ".pi", "seat-s1234500.md")]);
    await writeFile(join(sandbox, ".pi", "APPEND_SYSTEM.md"), "Self-compaction is on.\n");
    assert.deepEqual(args("s1234501"), ["--append-system-prompt", join(sandbox, ".pi", "APPEND_SYSTEM.md"), "--append-system-prompt", join(sandbox, ".pi", "seat-s1234501.md")]);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
