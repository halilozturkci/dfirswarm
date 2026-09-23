/**
 * Self-compaction, the parts that need no model: the ceiling table, the
 * three lines resolved against a window, the level, the recovery reducer,
 * the templates, the hand-off header, and the tool's registration through
 * Pi's real loader when the spawner turns the option on.
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { access, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { test } from "node:test";
import {
  DEFAULT_SPECS,
  effectiveCeiling,
  HEADROOM_TOKENS,
  KEEP_RECENT_TOKENS,
  levelFor,
  parseSpecList,
  parseTokenSpec,
  RESERVE_TOKENS,
  resolveThresholds,
  ROT_CEILING_TOKENS,
  SPEC_LIST_RE,
  specForModel,
  specsForModel,
  specsFromEnv,
  validateSpecs,
} from "../extensions/context-ceiling.ts";
import { handoffHeader, HANDOFF_TYPE, latestAssistantUsage, nowPrompt, recoverState, renderTemplate, STATE_TYPE } from "../extensions/self-compact.ts";
import { EVENTS_REL, initSandbox, TOOL_RESERVED_NAMES } from "../extensions/protocol.ts";

const REPO = resolve(import.meta.dirname, "..");

test("specs parse as tokens, k/m suffixes, or percentages, and refuse the rest", () => {
  assert.deepEqual(parseTokenSpec("150000", "x"), { kind: "tokens", value: 150_000, raw: "150000" });
  assert.deepEqual(parseTokenSpec("150k", "x"), { kind: "tokens", value: 150_000, raw: "150k" });
  assert.deepEqual(parseTokenSpec("0.5m", "x"), { kind: "tokens", value: 500_000, raw: "0.5m" });
  assert.deepEqual(parseTokenSpec(" 60% ", "x"), { kind: "percent", value: 60, raw: "60%" });
  for (const bad of ["", "abc", "150.5", "120%", "-1"]) assert.throws(() => parseTokenSpec(bad, "x"), `${JSON.stringify(bad)} is refused`);
  assert.throws(() => validateSpecs({ noticeAt: "70%", warnAt: "50%", compactAt: "60%" }), /notice threshold .* must not exceed/);
  assert.throws(() => validateSpecs({ noticeAt: "40%", warnAt: "70%", compactAt: "60%" }), /warning threshold .* must not exceed/);
  assert.throws(() => validateSpecs({ noticeAt: "70%", warnAt: "50%", compactAt: "60%" }, { noticeAt: true, compactAt: true }), /notice threshold \(70%\) must not exceed the compact threshold/);
  assert.doesNotThrow(() => validateSpecs({ noticeAt: "55%", warnAt: "50%", compactAt: "60%" }, { noticeAt: true }), "only lines the operator set are held to each other");
});

test("the ceiling table: what the run data taught, model by model", () => {
  assert.equal(effectiveCeiling("openai/gpt-5.4-mini", 400_000).ceiling, 272_000, "declared 400k, measured 272k");
  assert.equal(effectiveCeiling("openai/gpt-5.4", 272_000).ceiling, 272_000);
  assert.equal(effectiveCeiling("openai/gpt-5.5", 272_000).ceiling, 272_000);
  assert.equal(effectiveCeiling("azure-foundry/grok-4.6", 500_000).ceiling, 200_000, "price doubles above 200k");
  assert.equal(effectiveCeiling("xai/grok-4.6", 500_000).ceiling, 200_000, "the provider does not change the model");
  assert.equal(effectiveCeiling("deepseek/deepseek-v4-pro", 1_000_000).ceiling, ROT_CEILING_TOKENS);
  assert.equal(effectiveCeiling("azure-foundry/DeepSeek-V4-Pro", 1_000_000).ceiling, ROT_CEILING_TOKENS, "matched without regard to case");
  assert.equal(effectiveCeiling("anthropic/claude-sonnet-5", 1_000_000).ceiling, ROT_CEILING_TOKENS, "an unlisted 1M model is held at the rot ceiling");
  assert.equal(effectiveCeiling("lmstudio/qwen3.8-27b", 128_768).ceiling, 128_768, "a small window is its own ceiling");
  const unknown = effectiveCeiling("mock/scripted", undefined);
  assert.equal(unknown.declared, 128_000);
  assert.match(unknown.reason, /assumed/);
  assert.equal(effectiveCeiling("openai/gpt-5.4-mini", 100_000).ceiling, 100_000, "a declared window below the table wins");
});

test("defaults resolve to 40 / 50 / 60 percent of the ceiling with room to the wall", () => {
  const r = resolveThresholds(DEFAULT_SPECS, "openai/gpt-5.4", 272_000, { fromDefaults: true });
  assert.ok(r.ok, JSON.stringify(r));
  const t = r.thresholds;
  assert.equal(t.ceiling, 272_000);
  assert.equal(t.noticeTokens, 108_800);
  assert.equal(t.warnTokens, 136_000);
  assert.equal(t.compactTokens, 163_200);
  assert.equal(t.capTokens, 272_000 - RESERVE_TOKENS - HEADROOM_TOKENS);
  assert.ok(t.compactTokens <= t.capTokens, "the compact line stays below what the window can hold");
  assert.equal(t.clamped, false);
  const mini = resolveThresholds(DEFAULT_SPECS, "openai/gpt-5.4-mini", 400_000, { fromDefaults: true });
  assert.ok(mini.ok && mini.thresholds.compactTokens === 163_200, "gpt-5.4-mini is held to the same lines as gpt-5.4, not to 60% of 400k");
  const grok = resolveThresholds(DEFAULT_SPECS, "azure-foundry/grok-4.6", 500_000, { fromDefaults: true });
  assert.ok(grok.ok && grok.thresholds.compactTokens === 120_000, "every grok call stays in the cheap tier");
  const big = resolveThresholds(DEFAULT_SPECS, "deepseek/deepseek-v4-pro", 1_000_000, { fromDefaults: true });
  assert.ok(big.ok && big.thresholds.compactTokens === 180_000);
});

test("explicit specs that do not fit are refused; defaults that do not fit are clamped and say so", () => {
  const refused = resolveThresholds({ noticeAt: "40%", warnAt: "50%", compactAt: "95%" }, "openai/gpt-5.4", 272_000);
  assert.ok(!refused.ok && /above the .* this .*-token window can hold/.test(refused.error), refused.ok ? "" : refused.error);
  const tiny = resolveThresholds(DEFAULT_SPECS, "tiny/model", 60_000, { fromDefaults: true });
  assert.ok(tiny.ok, tiny.ok ? "" : tiny.error);
  assert.ok(tiny.thresholds.clamped && tiny.thresholds.notes.length >= 1, "a 60k window cannot hold 60% plus reserve and headroom; clamped with a note");
  assert.ok(tiny.thresholds.compactTokens > KEEP_RECENT_TOKENS);
  const tokens = resolveThresholds({ noticeAt: "100k", warnAt: "120k", compactAt: "150k" }, "openai/gpt-5.4", 272_000);
  assert.ok(tokens.ok && tokens.thresholds.compactTokens === 150_000 && tokens.thresholds.noticeTokens === 100_000);
  const tooLow = resolveThresholds({ noticeAt: "1k", warnAt: "2k", compactAt: "10k" }, "openai/gpt-5.4", 272_000);
  assert.ok(!tooLow.ok && /retained history/.test(tooLow.error), "a compact line inside keepRecentTokens has nothing to cut");
});

test("the level follows the three lines", () => {
  const r = resolveThresholds(DEFAULT_SPECS, "openai/gpt-5.4", 272_000, { fromDefaults: true });
  assert.ok(r.ok);
  const t = r.thresholds;
  assert.equal(levelFor(null, t), "unknown");
  assert.equal(levelFor(10_000, t), "idle");
  assert.equal(levelFor(108_800, t), "notice");
  assert.equal(levelFor(136_000, t), "warning");
  assert.equal(levelFor(163_200, t), "forced");
  assert.equal(levelFor(250_000, undefined), "unknown");
});

test("the specs come from the pane's environment as lists, and a seat resolves them against its model", () => {
  const none = specsFromEnv({});
  assert.equal(none.fromDefaults, true);
  assert.deepEqual(specsForModel(none.specs, "openai/gpt-5.4-mini"), { specs: DEFAULT_SPECS, fromDefaults: true, explicit: { noticeAt: false, warnAt: false, compactAt: false }, matched: {} });
  const some = specsFromEnv({ SWARM_COMPACT_AT: "150k" });
  assert.equal(some.fromDefaults, false);
  assert.deepEqual(specsForModel(some.specs, "openai/gpt-5.4-mini").specs, { noticeAt: "40%", warnAt: "50%", compactAt: "150k" });
  // Per-model overrides: a provider/id key matches that seat exactly, a bare id matches it under any provider, the last match wins.
  const mixed = specsFromEnv({ SWARM_COMPACT_AT: "60%,openai/gpt-5.4-mini=55%,grok-4.6=70%,GROK-4.6=72%", SWARM_COMPACT_WARN_AT: "gpt-5.4-mini=45%" });
  assert.equal(mixed.fromDefaults, false);
  const mini = specsForModel(mixed.specs, "openai/gpt-5.4-mini");
  assert.deepEqual(mini.specs, { noticeAt: "40%", warnAt: "45%", compactAt: "55%" });
  assert.deepEqual(mini.matched, { warnAt: "gpt-5.4-mini", compactAt: "openai/gpt-5.4-mini" });
  assert.equal(mini.fromDefaults, false);
  const grok = specsForModel(mixed.specs, "azure-foundry/grok-4.6");
  assert.deepEqual(grok.specs, { noticeAt: "40%", warnAt: "50%", compactAt: "72%" }, "a bare id matches under any provider; the later entry wins");
  const other = specsForModel(mixed.specs, "deepseek/deepseek-v4-pro");
  assert.deepEqual(other.specs, { noticeAt: "40%", warnAt: "50%", compactAt: "60%" }, "a seat no entry names gets the seat value");
  assert.deepEqual(other.matched, {});
  const onlyOverrides = specsFromEnv({ SWARM_COMPACT_AT: "openai/gpt-5.4-mini=55%" });
  assert.equal(specsForModel(onlyOverrides.specs, "deepseek/deepseek-v4-pro").fromDefaults, true, "a list with no seat value leaves the other seats on the defaults");
  assert.equal(specsForModel(onlyOverrides.specs, "openai/gpt-5.4-mini").fromDefaults, false);
  // The list parser refuses what the shell and the console refuse.
  assert.deepEqual(parseSpecList("60%", "x"), { value: "60%", byModel: [] });
  assert.deepEqual(parseSpecList(" 60% , openai/gpt-5.4-mini = 55% ", "x"), { value: "60%", byModel: [{ key: "openai/gpt-5.4-mini", value: "55%" }] });
  assert.throws(() => parseSpecList("60%,70%", "x"), /two values for every seat/);
  assert.throws(() => parseSpecList("openai/gpt-5.4-mini=lots", "x"), /not a token count or a percentage/);
  assert.throws(() => parseSpecList("bad key!=60%", "x"), /is not a model/);
  assert.throws(() => specsFromEnv({ SWARM_COMPACT_AT: "60%,70%" }), /two values/);
  for (const good of ["60%", "150k", "60%,openai/gpt-5.4-mini=55%", "openai/gpt-5.4-mini=55%,grok-4.6=70%", "60% , x/y=1"]) assert.ok(SPEC_LIST_RE.test(good), good);
  for (const bad of ["", "lots", "60%,", "=60%", "a b=60%", "60%,x/y=lots"]) assert.ok(!SPEC_LIST_RE.test(bad), bad);
  assert.deepEqual(specForModel({ value: "", byModel: [] }, "60%", undefined), { value: "60%", explicit: false });
});

test("one explicit line out of order with a default fits the default to it instead of turning compaction off", () => {
  // As the extension resolves a seat: the pane's lists, the seat's model, its window.
  const seatResolve = (env: Record<string, string>, model = "openai/gpt-5.4", window = 272_000) => {
    const seat = specsForModel(specsFromEnv(env).specs, model);
    return resolveThresholds(seat.specs, model, window, { fromDefaults: seat.fromDefaults, explicit: seat.explicit });
  };
  const lines = (r: ReturnType<typeof seatResolve>) => (r.ok ? [r.thresholds.noticeTokens, r.thresholds.warnTokens, r.thresholds.compactTokens] : r.error);
  // A compact line below the default warning: the defaults scale down with it, 40 : 50 : 60, so the three levels stay apart.
  const pct = seatResolve({ SWARM_COMPACT_AT: "45%" });
  assert.deepEqual(lines(pct), [81_600, 102_000, 122_400], "the operator's line is kept; the defaults keep their proportions below it");
  assert.ok(pct.ok && pct.thresholds.clamped && pct.thresholds.notes.some((n) => /default warning threshold .* lowered/.test(n)), JSON.stringify(pct.ok && pct.thresholds.notes));
  assert.deepEqual(lines(seatResolve({ SWARM_COMPACT_AT: "100k" })), [66_666, 83_333, 100_000]);
  // A notice line above the default warning: the default warning rises to it and stays under the compact line.
  const notice = seatResolve({ SWARM_COMPACT_NOTICE_AT: "55%" });
  assert.deepEqual(lines(notice), [149_600, 149_600, 163_200]);
  assert.ok(notice.ok && notice.thresholds.notes.some((n) => /default warning threshold .* below the notice threshold 55%; raised/.test(n)), JSON.stringify(notice.ok && notice.thresholds.notes));
  assert.deepEqual(lines(seatResolve({ SWARM_COMPACT_NOTICE_AT: "55%", SWARM_COMPACT_AT: "70%" })), [149_600, 149_600, 190_400], "two operator lines in order are kept, whatever default sits between them");
  // A warning line above the default compact line: the default compact line rises to it, within what the window holds.
  const warn = seatResolve({ SWARM_COMPACT_WARN_AT: "65%" });
  assert.deepEqual(lines(warn), [108_800, 176_800, 176_800]);
  assert.ok(warn.ok && warn.thresholds.notes.some((n) => /default compact threshold .* below the warning threshold 65%; raised/.test(n)), JSON.stringify(warn.ok && warn.thresholds.notes));
  const warnTooHigh = seatResolve({ SWARM_COMPACT_WARN_AT: "90%" });
  assert.ok(!warnTooHigh.ok && /^the warning threshold 90% \(244,800 tokens\) is above the 223,616 this 272,000-token window can hold/.test(warnTooHigh.error), lines(warnTooHigh).toString());
  // Two lines the operator wrote that conflict are still refused, and the message names only those two, with their own values.
  const both = seatResolve({ SWARM_COMPACT_AT: "45%", SWARM_COMPACT_WARN_AT: "50%" });
  assert.ok(!both.ok && /warning threshold \(50%\) must not exceed the compact threshold \(45%\)/.test(both.error), lines(both).toString());
  const noticeOver = seatResolve({ SWARM_COMPACT_AT: "45%", SWARM_COMPACT_NOTICE_AT: "48%" });
  assert.ok(!noticeOver.ok && /notice threshold \(48%\) must not exceed the compact threshold \(45%\)/.test(noticeOver.error), lines(noticeOver).toString());
  const mixed = seatResolve({ SWARM_COMPACT_NOTICE_AT: "150k", SWARM_COMPACT_AT: "45%" });
  assert.ok(!mixed.ok, lines(mixed).toString());
  assert.equal(mixed.error, "the notice threshold 150k (150,000 tokens) is above the compact threshold 45% (122,400 tokens).");
  // An explicit compact line the window cannot hold is still refused, not clamped.
  const tooHigh = seatResolve({ SWARM_COMPACT_AT: "95%" });
  assert.ok(!tooHigh.ok && /window can hold/.test(tooHigh.error));
});

test("templates render the live numbers and leave unknown keys alone", () => {
  assert.equal(renderTemplate("{{used_tokens}} of {{ceiling}} ({{used_percent}}) {{nope}}", { used_tokens: "1,000", ceiling: "272,000", used_percent: "0.4%" }), "1,000 of 272,000 (0.4%) {{nope}}");
  assert.match(nowPrompt(), /call self_compact as your only tool call/);
  assert.match(nowPrompt("KEEP ME"), /Saved note, verbatim:\n\nKEEP ME\n\n---/);
});

test("the hand-off header states what the harness knows, and the note follows verbatim", () => {
  const header = handoffHeader("s1", 2, { name: "disk-triage", doing: "disk triage", claims: ["work/report.md"], unread: { main: 3, memory: 1 }, ledgerTotal: 41, ledgerMine: 12, sentinel: false, spentUsd: 1.04, capUsd: 6 }, true, "manual compaction");
  assert.match(header, /^\[self-compact · handoff\] cycle 2 · you are s1 "disk-triage" \(disk triage\)\./);
  assert.match(header, /Live claims: work\/report\.md\./);
  assert.match(header, /Unread posts: 3 in main, 1 in memory\. Call inbox before acting\./);
  assert.match(header, /Ledger: 41 entries, 12 yours\. Sentinel: absent\. Spend: \$1\.04 of the \$6 cap\./);
  assert.match(header, /Your note follows verbatim/);
  assert.match(header, /the harness, not a person: do not answer it with a status/, "run 6: four agents answered the hand-off with a status and ended their turns");
  assert.ok(header.endsWith(":\n---"), "the note is what follows the header, byte for byte");
  const bare = handoffHeader("s2", 0, { claims: [], unread: {}, ledgerTotal: 0, ledgerMine: 0, sentinel: true, spentUsd: 0 }, false, "overflow compaction");
  assert.match(bare, /you have not named yourself yet/);
  assert.match(bare, /Sentinel: PRESENT/);
  assert.match(bare, /No note was saved before this compaction/);
});

test("the recovery reducer rebuilds a hand-off from the branch", () => {
  const state = (h: Record<string, unknown> | undefined, cycle = 0, locked = false) => ({ type: "custom", customType: STATE_TYPE, data: { version: 1, cycle, locked, handoff: h } });
  const pending = { id: "h1", note: "N", status: "pending", attempts: 0, savedAt: 1 };
  assert.deepEqual(recoverState([]).state, { version: 1, cycle: 0, locked: false });
  const compacting = recoverState([state({ ...pending, status: "compacting" }, 0, true)]);
  assert.equal(compacting.state.handoff?.status, "compacting", "the caller decides what an interrupted compaction becomes");
  const landed = recoverState([state({ ...pending, status: "compacting" }), { type: "compaction", details: { handoffId: "h1" } }]);
  assert.equal(landed.state.handoff?.status, "ready", "the compaction carrying the id landed: the note is due");
  const journaled = recoverState([state({ ...pending, status: "ready" }), { type: "custom_message", customType: HANDOFF_TYPE, details: { id: "h1" } }]);
  assert.equal(journaled.journaledUnanswered, true);
  const answered = recoverState([state({ ...pending, status: "ready" }), { type: "custom_message", customType: HANDOFF_TYPE, details: { id: "h1" } }, { type: "message", message: { role: "assistant" } }]);
  assert.equal(answered.answered, true);
  assert.equal(latestAssistantUsage([{ type: "message", message: { role: "assistant", usage: { input: 10, cacheRead: 90, output: 1 } } }, { type: "compaction" }, { type: "message", message: { role: "assistant", usage: { input: 5, cacheRead: 0, output: 1 } } }])?.input, 5, "only usage after the latest compaction counts");
});

test("the trace names self-compaction writes are reserved from forged tools", () => {
  for (const name of ["self_compact", "context", "compact_notice", "compact_warning", "compact_forced", "compact_hold", "compact_note", "compact_start", "compact_done", "compact_failed", "compact_config"]) {
    assert.ok(TOOL_RESERVED_NAMES.has(name), `${name} is reserved`);
  }
});

async function findLoader(): Promise<string | null> {
  const candidates: string[] = [];
  if (process.env.PI_PACKAGE_DIR) candidates.push(process.env.PI_PACKAGE_DIR);
  try {
    candidates.push(join(execFileSync("npm", ["root", "-g"], { encoding: "utf8" }).trim(), "@earendil-works", "pi-coding-agent"));
  } catch {
    // npm missing
  }
  candidates.push(join(REPO, "node_modules", "@earendil-works", "pi-coding-agent"));
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
}

type LoadedTool = { definition: { execute: (...args: unknown[]) => Promise<{ details: Record<string, unknown>; isError?: boolean }> } };
type LoadedExtension = { path: string; tools: Map<string, LoadedTool>; handlers: Map<string, unknown[]> };

test("Pi loader: self_compact exists only when the spawner turned self-compaction on", async (t) => {
  const loaderPath = await findLoader();
  if (!loaderPath) {
    t.skip("Pi package not found");
    return;
  }
  const { loadExtensions } = (await import(loaderPath)) as { loadExtensions: (paths: string[], cwd: string) => Promise<{ extensions: LoadedExtension[]; errors: unknown[] }> };
  const previous = { agent: process.env.AGENT_ID, on: process.env.SWARM_SELF_COMPACT };
  const root = await mkdtemp(join(tmpdir(), "pi-load-compact-"));
  try {
    await initSandbox(root, { reset: true });
    process.env.AGENT_ID = "agent00";
    delete process.env.SWARM_SELF_COMPACT;
    const off = await loadExtensions([join(REPO, "extensions", "agent-swarm.ts")], root);
    assert.deepEqual(off.errors, []);
    assert.ok(!off.extensions[0].tools.has("self_compact"), "off unless the kickoff says so");

    process.env.SWARM_SELF_COMPACT = "1";
    const on = await loadExtensions([join(REPO, "extensions", "agent-swarm.ts")], root);
    assert.deepEqual(on.errors, []);
    const [swarm] = on.extensions;
    assert.ok(swarm.tools.has("self_compact"), "the hand-off tool is registered");
    for (const hook of ["context", "session_before_compact", "session_compact", "session_compact_failed", "agent_settled", "agent_end"]) {
      assert.ok((swarm.handlers.get(hook)?.length ?? 0) >= 1, `the ${hook} hook is wired`);
    }
    // Through the tool definition with a bare context: no session, so the
    // refusal is the "nothing to compact" one, on the trace, and no lock.
    const ctx = { cwd: root, hasUI: false, ui: {} };
    const tool = swarm.tools.get("self_compact")!.definition;
    await assert.rejects(tool.execute("t1", { note_to_self: "" }, undefined, undefined, ctx), /must not be blank/);
    await assert.rejects(tool.execute("t2", { note_to_self: "x".repeat(24_001) }, undefined, undefined, ctx), /exceeds 24000 characters/);
    const events = (await readFile(join(root, EVENTS_REL), "utf8")).trim().split("\n").map((l) => JSON.parse(l));
    const refusals = events.filter((e) => e.tool === "compact_note" && e.result.ok === false);
    assert.equal(refusals.length, 2, "both refusals are on the trace");
    assert.equal(refusals[0].agent, "agent00");
  } finally {
    if (previous.agent === undefined) delete process.env.AGENT_ID;
    else process.env.AGENT_ID = previous.agent;
    if (previous.on === undefined) delete process.env.SWARM_SELF_COMPACT;
    else process.env.SWARM_SELF_COMPACT = previous.on;
    execFileSync("chmod", ["-R", "u+w", root]);
    await rm(root, { recursive: true, force: true });
  }
});
