/**
 * A seat's packs through the real CLI (`pi --mode rpc`), the real swarm
 * extension and a scripted provider that records every model request: the
 * Skills section is in the very first prompt and in every prompt after a
 * compaction, the `skill` tool answers through Pi the way it answers
 * in-process, a body the seat held before a compaction is delivered again
 * after it, and the hand-off message names what the compaction took. And the
 * other half of "the packs' skills are the only ones a seat has": a Pi skill
 * planted in an operator's agent directory reaches the seat's prompt without
 * `--no-skills` and does not with it. No key, no network, no money.
 *
 * Why the kickoff writes the index into `.pi/APPEND_SYSTEM.md` and the forced
 * prompt of `before_agent_start` is not left to carry it: the forced prompt
 * lasts for the run a user prompt starts. The run a hand-off starts is begun by
 * a custom message, has no `before_agent_start`, and goes back to Pi's own
 * prompt sections, so the harness's forced lines (the id, the stop rule, the
 * inputs) are gone from every request after the first compaction. The test
 * that runs without the file shows it (as a diagnostic: a Pi that keeps the
 * forced prompt across a hand-off would make the file redundant, not wrong).
 *
 * Needs `pi` on PATH (the fake provider speaks 0.85.1's and 0.87.x's provider
 * contract). Skips when it is not there, like tests/self-compact-e2e.test.ts.
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { copyFileSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { test } from "node:test";
import { EVENTS_REL, initSandbox } from "../extensions/protocol.ts";
import { SKILLS_SECTION_TITLE } from "../extensions/skills.ts";
import { twoPacks } from "./fixtures/skill-packs.ts";
import { eventsOfType, messageText, RpcClient, type RpcEvent } from "./harness/rpc-client.ts";

const REPO = resolve(import.meta.dirname, "..");
const EXTENSION = join(REPO, "extensions", "agent-swarm.ts");
const FAKE = join(REPO, "tests", "fixtures", "self-compact-fake-provider.ts");
const HANDOFF = "self-compact-handoff";
const TOOLS = "read,bash,edit,write,post,inbox,wait,claim_file,release_file,claims,list_team,budget,file_history,file_restore,file_diff,thread_open,thread_join,inputs,name,record,ledger,done,self_compact,skill,skill_done";

function haveCli(): boolean {
  try {
    execFileSync("pi", ["--version"], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });
    return true;
  } catch {
    return false;
  }
}

type Dir = { root: string; sessionDir: string; logFile: string; traceFile: string };

async function makeSandbox(name: string): Promise<Dir> {
  const root = await mkdtemp(join(tmpdir(), `skills-e2e-${name}-`));
  await initSandbox(root, { reset: true });
  mkdirSync(join(root, ".pi"), { recursive: true });
  writeFileSync(join(root, ".pi", "settings.json"), JSON.stringify({ compaction: { enabled: true, reserveTokens: 16384, keepRecentTokens: 1500 } }, null, 2));
  mkdirSync(join(root, "work", "agent00"), { recursive: true });
  const sessionDir = join(root, ".pi-sessions", "agent00");
  mkdirSync(sessionDir, { recursive: true });
  return { root, sessionDir, logFile: join(root, "rpc.log"), traceFile: join(root, "fake-trace.jsonl") };
}

/** The Pi arguments of a seat as the kickoff starts it: the run's file and the seat's own, when the kickoff wrote them. */
function args(d: Dir, { noSkills = true, extra = [] as string[], forging = false } = {}): string[] {
  // As seat_prompt_args does: the run's file when it has anything in it, then the seat's own.
  const run = join(d.root, ".pi", "APPEND_SYSTEM.md");
  const files = existsSync(join(d.root, ".pi", "seat-agent00.md")) ? [...(existsSync(run) && statSync(run).size > 0 ? ["--append-system-prompt", run] : []), "--append-system-prompt", join(d.root, ".pi", "seat-agent00.md")] : [];
  return ["--no-extensions", ...(noSkills ? ["--no-skills"] : []), "--no-prompt-templates", "--no-context-files", "-a", ...files, "-e", EXTENSION, "-e", FAKE, "--model", "fake/scripted", "--session-dir", d.sessionDir, ...(forging ? [] : ["--tools", TOOLS]), ...extra];
}

const ENV = {
  AGENT_ID: "agent00",
  SWARM_SELF_COMPACT: "1",
  SWARM_COMPACT_NOTICE_AT: "20%",
  SWARM_COMPACT_WARN_AT: "40%",
  SWARM_COMPACT_AT: "50%",
  SC_FAKE_WINDOW: "200000",
  SC_FAKE_BASE: "5000",
  SC_FAKE_STEP: "20000",
  SC_FAKE_PROMPTS: "1",
};

type FakeTurn = { kind: string; lastRole?: string; lastText?: string; messages?: number; systemPrompt?: string };

function fakeTurns(d: Dir): FakeTurn[] {
  if (!existsSync(d.traceFile)) return [];
  return readFileSync(d.traceFile, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l) as FakeTurn).filter((r) => r.kind === "turn");
}

function trace(d: Dir): Array<{ tool: string; args: Record<string, unknown>; result: Record<string, unknown> }> {
  return readFileSync(join(d.root, EVENTS_REL), "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l));
}

function skillResults(events: RpcEvent[]): string[] {
  return eventsOfType(events, "tool_execution_end").filter((e) => e.toolName === "skill").map((e) => messageText(e.result));
}

async function cleanup(d: Dir): Promise<void> {
  if (process.env.SC_KEEP === "1") {
    console.log(`kept ${d.root}`);
    return;
  }
  await rm(d.root, { recursive: true, force: true }).catch(() => undefined);
}

/**
 * The kickoff's own files, from the kickoff's own script: the worker prompt as .pi/SYSTEM.md, the run's lines (and the packs'
 * index) as .pi/APPEND_SYSTEM.md, the seat's id as .pi/seat-agent00.md, over an inputs manifest like a run with evidence has.
 */
function kickoffFiles(d: Dir, packDirs: string[], { files = true, forging = false, bare = false } = {}): string {
  copyFileSync(join(REPO, "prompts", "worker-system.md"), join(d.root, ".pi", "SYSTEM.md"));
  if (!files) return "";
  if (!bare) writeFileSync(join(d.root, "inputs.json"), JSON.stringify({ source: "/cases/evidence", copied_at: "2026-10-07T00:00:00.000Z", files: [{ path: "inputs/a.txt", bytes: 5, sha256: "0".repeat(64) }], bytes: 5, enforce: "auto", guard: "none" }));
  const out = execFileSync("node", ["--experimental-strip-types", "--no-warnings", join(REPO, "scripts", "seat-prompt.ts"), "--sandbox", d.root, ...(bare ? [] : ["--self-compact"]), ...(forging ? ["--forging"] : []), "--seat", "agent00", ...packDirs.flatMap((p) => ["--pack-dir", p])], { encoding: "utf8" });
  assert.equal(JSON.parse(out).written, packDirs.length > 0, out);
  return out;
}

type Cycle = { turns: FakeTurn[]; resumedAt: number; events: RpcEvent[]; handoff: RpcEvent; rows: ReturnType<typeof trace> };

/** One seat, scripted: three skill calls, the climb to the compact line, the hand-off, one more skill call, the result. */
async function runCycle(d: Dir, packDirs: string[], { env = {} as Record<string, string>, forging = false, forge = false } = {}): Promise<Cycle> {
  const pre = [
    ...(forge ? [{ name: "make_tool", arguments: { name: "count_lines", description: "Count lines", runtime: "python3", script: "print(1)\n", params: {} } }] : []),
    { name: "skill", arguments: { id: "evidence/one" } },
    { name: "skill", arguments: { id: "evidence/one" } },
    { name: "skill", arguments: { id: "pack-b:shared/dup" } },
  ];
  const after = [{ name: "skill", arguments: { id: "evidence/one" } }];
  const client = new RpcClient({
    args: args(d, { forging }),
    cwd: d.root,
    env: { ...ENV, ...(forging ? { SWARM_TOOL_FORGING: "1", SWARM_TOOLS: TOOLS } : {}), ...env, SWARM_PACK_DIRS: packDirs.join(":"), SC_FAKE_TRACE: d.traceFile, SC_FAKE_PRE_STEPS: JSON.stringify(pre), SC_FAKE_AFTER_STEPS: JSON.stringify(after) },
    logFile: d.logFile,
  });
  try {
    const accepted = await client.request({ type: "prompt", message: "Start the scripted work." });
    assert.equal(accepted.success, true, JSON.stringify(accepted));
    const handoff = await client.waitFor((e) => e.type === "message_end" && (e.message as { customType?: string })?.customType === HANDOFF, 90_000);
    await client.waitFor((e) => e.type === "tool_execution_end" && e.toolName === "write", 30_000, { since: client.events.indexOf(handoff) });
    await client.waitFor((e) => e.type === "agent_settled", 60_000, { since: client.events.indexOf(handoff) });
    const turns = fakeTurns(d);
    const resumedAt = turns.findIndex((tn) => tn.lastRole === "user" && /^\[self-compact · handoff\]/.test(tn.lastText ?? ""));
    return { turns, resumedAt, events: [...client.events], handoff, rows: trace(d) };
  } finally {
    await client.close();
  }
}

test("the kickoff's index is in the first prompt and in every prompt after a compaction; a body is delivered again after it", async (t) => {
  if (!haveCli()) {
    t.skip("pi is not on PATH");
    return;
  }
  const d = await makeSandbox("compaction");
  const packsRoot = await mkdtemp(join(tmpdir(), "skills-e2e-packs-"));
  const { a, b } = await twoPacks(packsRoot);
  try {
    kickoffFiles(d, [a, b]);
    mkdirSync(join(d.root, "operator-agent"), { recursive: true });
    writeFileSync(join(d.root, "operator-agent", "APPEND_SYSTEM.md"), "OPERATOR-GLOBAL-APPEND: be brief, call me Boss.\n");
    const { turns, resumedAt, events, handoff, rows } = await runCycle(d, [a, b], { env: { PI_CODING_AGENT_DIR: join(d.root, "operator-agent") } });

    // 1. Every request the seat made carried the section: the first prompt, and each one after the compaction.
    assert.ok(turns.length >= 8, `the scripted seat made ${turns.length} requests`);
    const first = turns[0]!;
    assert.ok(first.systemPrompt?.includes("You are one worker in a local swarm."), "the worker prompt is the seat's: the kickoff's SYSTEM.md was read");
    assert.ok(first.systemPrompt?.includes(SKILLS_SECTION_TITLE), "the first prompt carries the Skills section");
    assert.ok(first.systemPrompt?.includes("- `evidence/one` The first note: Before anything else."), "with the entry lines");
    assert.ok(first.systemPrompt?.includes("- `pack-a:shared/dup` In both packs: Whenever."), "an id two packs carry is listed as pack:id");
    assert.equal(first.systemPrompt!.split(SKILLS_SECTION_TITLE).length - 1, 1, "once: the extension did not add it to a prompt that already had it");
    const missing = turns.map((tn, i) => ({ tn, i })).filter(({ tn }) => !tn.systemPrompt?.includes(SKILLS_SECTION_TITLE) || !tn.systemPrompt.includes("- `evidence/one`"));
    assert.deepEqual(missing.map((m) => m.i), [], "no request went out without the section");
    assert.ok(resumedAt > 0, "a request after the hand-off is on the fake's trace");
    const biggest = Math.max(...turns.slice(0, resumedAt).map((tn) => tn.messages ?? 0));
    assert.ok((turns[resumedAt]!.messages ?? 0) < biggest, "the history really was compacted: the section did not survive by the messages surviving");
    assert.ok(turns[resumedAt]!.systemPrompt!.includes("You are one worker in a local swarm."));
    assert.equal(turns[resumedAt]!.systemPrompt!.split(SKILLS_SECTION_TITLE).length - 1, 1);
    // The run a hand-off starts is not the forced prompt's: what holds for the whole run is in Pi's own prompt, in every request, once.
    const SEAT = "Your assigned id is agent00. Use it on every post and claim. If done/SWARM_DONE exists on this turn, call done and stop.";
    const INPUTS = "Read-only inputs: 1 file(s), 1 KB under inputs/ (from /cases/evidence).";
    const COMPACT = "Self-compaction is on. Your context has a ceiling for this model";
    for (const [name, line] of [["the seat's id and the stop rule", SEAT], ["the read-only inputs rule", INPUTS], ["the self-compaction mechanics", COMPACT]] as const) {
      const counts = turns.map((tn) => tn.systemPrompt!.split(line).length - 1);
      assert.deepEqual(counts.filter((n) => n !== 1), [], `${name}: in every request exactly once (the forced prompt did not say it again, and the hand-off's run kept it): ${counts.join(",")}`);
    }
    // What changes stays in the forced prompt: this pane's measured guard is said to the first run, not to the hand-off's.
    assert.match(first.systemPrompt!, /This pane has no kernel guard on inputs\/ \(measured when it started\)/);
    assert.ok(!/measured when it started/.test(turns[resumedAt]!.systemPrompt!), "a measurement is a fact about the first run: it is not repeated into a run it may no longer hold for");
    // An operator's own global APPEND_SYSTEM.md is not what a seat gets: the kickoff's flags replace Pi's discovery.
    assert.ok(turns.every((tn) => !tn.systemPrompt!.includes("OPERATOR-GLOBAL-APPEND")), "the decoy in the operator's agent directory never reached a request");

    // 2. The tool through Pi: plain Markdown, then "already", then another pack's copy, then the body again after the compaction.
    const results = skillResults(events);
    assert.equal(results.length, 4, results.join("\n---\n"));
    assert.match(results[0]!, /^Skill `evidence\/one` \(pack pack-a 1\.2\.0, about \d+ tokens\): The first note\n\nRead the run count first/);
    assert.ok(!results[0]!.includes("requires_host") && !results[0]!.trimStart().startsWith("{"));
    assert.match(results[1]!, /^`evidence\/one` \(pack-a\) is already in your context, loaded at turn 1; not sent again\.$/);
    assert.match(results[2]!, /^Skill `shared\/dup` \(pack pack-b 0\.4\.1/);
    assert.match(results[3]!, /^Skill `evidence\/one` \(pack pack-a 1\.2\.0/, "after the compaction the same call delivers the body again");

    // 3. The hand-off message names what the compaction took out.
    assert.match(messageText(handoff.message), /Skill bodies a compaction took out of your context: pack-a:evidence\/one, pack-b:shared\/dup\. Load again \(skill\(id\)\) the ones you still need\./);

    // 4. The record: one index row that says where the section came from, the loads with their hashes, the re-load flagged.
    const index = rows.filter((r) => r.tool === "skills_index");
    assert.equal(index.length, 1, "one row for the section, however many prompts were built");
    assert.deepEqual([index[0]!.result.ok, index[0]!.result.source, index[0]!.result.matches_packs], [true, "prompt", true], JSON.stringify(index[0]!.result));
    const skillRows = rows.filter((r) => r.tool === "skill");
    assert.deepEqual(skillRows.map((r) => [r.result.ok, r.result.already_loaded ?? false, r.result.reload_after_compaction ?? false]), [[true, false, false], [true, true, false], [true, false, false], [true, false, true]]);
    assert.ok(skillRows.filter((r) => !r.result.already_loaded).every((r) => /^[0-9a-f]{64}$/.test(String(r.result.sha256)) && Number(r.result.tokens) > 0));
    assert.deepEqual(skillRows.map((r) => r.result.pack), ["pack-a", "pack-a", "pack-b", "pack-a"]);
    // The compaction says which bodies it took out and which it kept (here the kept tail is too short to hold either).
    const compacted = rows.filter((r) => r.tool === "skills_compacted");
    assert.equal(compacted.length, 1);
    assert.deepEqual(compacted[0]!.result.kept, []);
    assert.deepEqual((compacted[0]!.result.lost as Array<{ key: string }>).map((x) => x.key), ["pack-a:evidence/one", "pack-b:shared/dup"]);
  } finally {
    await cleanup(d);
    await rm(packsRoot, { recursive: true, force: true });
  }
});

/** Waits until the seat has made `n` `skill` results (or fails after `ms`). */
async function skillResultsAfter(client: RpcClient, n: number, ms = 60_000): Promise<string[]> {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    const got = skillResults(client.events);
    if (got.length >= n) return got;
    await new Promise((r) => setTimeout(r, 50));
  }
  return skillResults(client.events);
}

test("two skill calls in one assistant message: Pi runs them at the same time, and the second is told the body is already loaded", async (t) => {
  if (!haveCli()) {
    t.skip("pi is not on PATH");
    return;
  }
  const d = await makeSandbox("parallel");
  const packsRoot = await mkdtemp(join(tmpdir(), "skills-e2e-packs-"));
  const { a, b } = await twoPacks(packsRoot);
  const batch = [[{ name: "skill", arguments: { id: "evidence/one" } }, { name: "skill", arguments: { id: "evidence/one" } }, { name: "skill", arguments: { id: "evidence/two" } }]];
  kickoffFiles(d, [a, b]);
  const client = new RpcClient({ args: args(d), cwd: d.root, env: { ...ENV, SWARM_PACK_DIRS: `${a}:${b}`, SC_FAKE_TRACE: d.traceFile, SC_FAKE_PRE_STEPS: JSON.stringify(batch) }, logFile: d.logFile });
  try {
    await client.request({ type: "prompt", message: "Start the scripted work." });
    const results = await skillResultsAfter(client, 3);
    assert.equal(results.length, 3, results.join("\n---\n"));
    assert.match(results[0]!, /^Skill `evidence\/one`/);
    assert.match(results[1]!, /^`evidence\/one` \(pack-a\) is already in your context, loaded at turn 1; not sent again\.$/, "the second call of the same message found the first's body");
    assert.match(results[2]!, /^Skill `evidence\/two`/);
    const rows = trace(d).filter((r) => r.tool === "skill");
    assert.deepEqual(rows.map((r) => [r.args.id, r.result.already_loaded ?? false]), [["evidence/one", false], ["evidence/one", true], ["evidence/two", false]]);
  } finally {
    await client.close();
    await cleanup(d);
    await rm(packsRoot, { recursive: true, force: true });
  }
});

test("a restart on the same session knows the body the session holds, and counts its turns on", async (t) => {
  if (!haveCli()) {
    t.skip("pi is not on PATH");
    return;
  }
  const d = await makeSandbox("restart");
  const packsRoot = await mkdtemp(join(tmpdir(), "skills-e2e-packs-"));
  const { a, b } = await twoPacks(packsRoot);
  const steps = [{ name: "skill", arguments: { id: "evidence/one" } }];
  const env = { ...ENV, SWARM_PACK_DIRS: `${a}:${b}`, SC_FAKE_TRACE: d.traceFile, SC_FAKE_PRE_STEPS: JSON.stringify(steps) };
  kickoffFiles(d, [a, b]);
  try {
    const first = new RpcClient({ args: args(d), cwd: d.root, env, logFile: d.logFile });
    try {
      await first.request({ type: "prompt", message: "Start the scripted work." });
      const got = await skillResultsAfter(first, 1);
      assert.match(got[0]!, /^Skill `evidence\/one`/);
      // The next request is made: the call, its result and the assistant message after it are in the session file.
      await first.waitFor((e) => e.type === "turn_end" && eventsOfType(first.events, "turn_end").length >= 1, 30_000);
    } finally {
      await first.close();
    }
    // The turns the session already had: its assistant messages, as the file holds them when the first process is gone.
    const sessionFile = readdirSync(d.sessionDir).filter((f) => f.endsWith(".jsonl")).map((f) => join(d.sessionDir, f))[0]!;
    const had = readFileSync(sessionFile, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l) as { type?: string; message?: { role?: string } }).filter((e) => e.type === "message" && e.message?.role === "assistant").length;
    assert.ok(had >= 1, "the first process left at least one assistant message in the session");
    const second = new RpcClient({ args: args(d, { extra: ["--continue"] }), cwd: d.root, env, logFile: d.logFile });
    try {
      await second.request({ type: "prompt", message: "Go on." });
      const got = await skillResultsAfter(second, 1);
      assert.match(got[0]!, /^`evidence\/one` \(pack-a\) is already in your context, loaded at turn 1; not sent again\.$/, "the restarted process read the body off the session it resumed");
      const rows = trace(d).filter((r) => r.tool === "skill");
      assert.deepEqual(rows.map((r) => [r.result.already_loaded ?? false, r.result.turn]), [[false, 1], [true, had + 1]], "and counted its turn after the ones the session already had");
    } finally {
      await second.close();
    }
  } finally {
    await cleanup(d);
    await rm(packsRoot, { recursive: true, force: true });
  }
});

test("tool forging: the rule is in every request once, what has been forged so far is in the hand-off header", async (t) => {
  if (!haveCli()) {
    t.skip("pi is not on PATH");
    return;
  }
  const d = await makeSandbox("forging");
  const packsRoot = await mkdtemp(join(tmpdir(), "skills-e2e-packs-"));
  const { a, b } = await twoPacks(packsRoot);
  try {
    kickoffFiles(d, [a, b], { forging: true });
    const { turns, resumedAt, handoff } = await runCycle(d, [a, b], { forging: true, forge: true });
    const FORGE = "Tool forging is on for this swarm. If the goal needs a tool nobody has";
    assert.ok(resumedAt > 0);
    assert.deepEqual(turns.map((tn) => tn.systemPrompt!.split(FORGE).length - 1).filter((n) => n !== 1), [], "the forging rule is in every request exactly once, the hand-off's run included");
    assert.match(turns[0]!.systemPrompt!, /Nothing has been forged yet\./, "the first run is told what has been forged so far");
    // The inventory changes, so the prompt of the run a hand-off starts cannot carry it: the header does.
    assert.match(messageText(handoff.message), /Tool forging is on\. Forged so far: count_lines \(by agent00, v1\)\. Call `tools` to see them\./);
  } finally {
    await cleanup(d);
    await rm(packsRoot, { recursive: true, force: true });
  }
});

/** The run's budget with its cap already passed (a token cap: the scripted model reports tokens, not dollars), under a stop policy. */
function passCap(d: Dir, policy: "cap-pause" | "cap-stop"): void {
  const file = join(d.root, "budget.json");
  const budget = JSON.parse(readFileSync(file, "utf8")) as Record<string, unknown>;
  writeFileSync(file, JSON.stringify({ ...budget, stop_policy: policy, cap_usd: 0, cap_tokens: 1 }));
}

test("a cap that was hit reaches the run a hand-off starts in the words of the run's stop policy: under cap-pause the seat is not told to call done", async (t) => {
  if (!haveCli()) {
    t.skip("pi is not on PATH");
    return;
  }
  const d = await makeSandbox("cap-pause");
  const packsRoot = await mkdtemp(join(tmpdir(), "skills-e2e-packs-"));
  const { a, b } = await twoPacks(packsRoot);
  try {
    kickoffFiles(d, [a, b]);
    passCap(d, "cap-pause");
    const { events, handoff } = await runCycle(d, [a, b]);
    const header = messageText(handoff.message);
    // The steer the seat was given by the harness when the cap was reached, and the header: the same words.
    const steer = eventsOfType(events, "message_start").map((e) => messageText(e.message)).find((m) => /^The run's token cap \(.* of 1\) is reached: it pauses in 2 minutes/.test(m));
    assert.ok(steer, "the harness steered the seat for the cap it passed (cap-pause)");
    // The same words; the figure in the parentheses is the one when each was said.
    const words = (m: string) => m.replace(/\(.*? of 1\)/, "(N of 1)");
    const said = /The run's token cap \(.*? of 1\) is reached:[^\n]*/.exec(header)?.[0];
    assert.ok(said, `the hand-off header carries the cap rule:\n${header}`);
    assert.equal(words(said!), words(steer!), "the hand-off header says what the steer said");
    assert.match(header, /do not call done unless the finish line is met/);
    assert.ok(!header.includes("Call done with reason cannot_complete") && !header.includes("cannot_complete"), "no order to call done");
    assert.match(header, /do not end your turn\. Work on until SWARM\.md's definition of done is met/, "the seat works on while the run waits for its operator");
  } finally {
    await cleanup(d);
    await rm(packsRoot, { recursive: true, force: true });
  }
});

test("under cap-stop the header orders the stop and does not also say to work on", async (t) => {
  if (!haveCli()) {
    t.skip("pi is not on PATH");
    return;
  }
  const d = await makeSandbox("cap-stop");
  const packsRoot = await mkdtemp(join(tmpdir(), "skills-e2e-packs-"));
  const { a, b } = await twoPacks(packsRoot);
  try {
    kickoffFiles(d, [a, b]);
    passCap(d, "cap-stop");
    const { handoff } = await runCycle(d, [a, b]);
    const header = messageText(handoff.message);
    assert.ok(header.includes("Swarm token cap hit. Call done with reason cannot_complete and stop. Do not start new work."), header);
    assert.ok(!header.includes("spent_usd="), "no dollar figures for a token cap");
    assert.match(header, /The swarm is ending, as the lines above say: do what they say and start nothing new\./);
    assert.ok(!header.includes("Work on until") && !header.includes("do not end your turn"));
  } finally {
    await cleanup(d);
    await rm(packsRoot, { recursive: true, force: true });
  }
});

test("when nothing applies the run's file is empty and not passed: the prompt carries the seat's line and no blank lines before it", async (t) => {
  if (!haveCli()) {
    t.skip("pi is not on PATH");
    return;
  }
  const d = await makeSandbox("bare");
  const agentDir = await mkdtemp(join(tmpdir(), "skills-e2e-agentdir-"));
  writeFileSync(join(agentDir, "APPEND_SYSTEM.md"), "OPERATOR-GLOBAL-APPEND: be brief.\n");
  try {
    kickoffFiles(d, [], { bare: true });
    assert.equal(statSync(join(d.root, ".pi", "APPEND_SYSTEM.md")).size, 0, "the run's file is there and empty");
    const client = new RpcClient({ args: args(d), cwd: d.root, env: { ...ENV, SWARM_SELF_COMPACT: "", PI_CODING_AGENT_DIR: agentDir, SC_FAKE_TRACE: d.traceFile }, logFile: d.logFile });
    try {
      await client.request({ type: "prompt", message: "Start the scripted work." });
      for (let i = 0; i < 100 && fakeTurns(d).length === 0; i++) await new Promise((r) => setTimeout(r, 100));
      const prompt = fakeTurns(d)[0]?.systemPrompt ?? "";
      assert.ok(prompt.includes("<addendum>\nYour assigned id is agent00."), `the addendum opens with the seat's line:\n${prompt.slice(prompt.indexOf("<addendum>"), prompt.indexOf("<addendum>") + 200)}`);
      assert.ok(!prompt.includes("OPERATOR-GLOBAL-APPEND"), "and the operator's global file, which an explicit source replaces, is not in it");
    } finally {
      await client.close();
    }
  } finally {
    await cleanup(d);
    await rm(agentDir, { recursive: true, force: true });
  }
});

test("without the kickoff's file the extension gives the first run the index; the run a hand-off starts is Pi's own prompt", async (t) => {
  if (!haveCli()) {
    t.skip("pi is not on PATH");
    return;
  }
  const d = await makeSandbox("fallback");
  const packsRoot = await mkdtemp(join(tmpdir(), "skills-e2e-packs-"));
  const { a, b } = await twoPacks(packsRoot);
  try {
    kickoffFiles(d, [a, b], { files: false });
    const { turns, resumedAt, rows } = await runCycle(d, [a, b]);
    assert.ok(turns[0]!.systemPrompt!.includes(SKILLS_SECTION_TITLE), "the fallback put the index in the forced prompt of the first run");
    assert.equal(rows.find((r) => r.tool === "skills_index")!.result.source, "extension");
    assert.ok(resumedAt > 0);
    // The reason the kickoff writes the file: the forced prompt does not outlive the run a user prompt started.
    const kept = turns[resumedAt]!.systemPrompt!.includes(SKILLS_SECTION_TITLE);
    t.diagnostic(`the first request after the hand-off ${kept ? "still carries" : "no longer carries"} a section the extension alone added`);
  } finally {
    await cleanup(d);
    await rm(packsRoot, { recursive: true, force: true });
  }
});

test("--no-skills keeps an operator's own Pi skills out of a seat's prompt; without it they are in", async (t) => {
  if (!haveCli()) {
    t.skip("pi is not on PATH");
    return;
  }
  const agentDir = await mkdtemp(join(tmpdir(), "skills-e2e-agentdir-"));
  mkdirSync(join(agentDir, "skills", "operator-decoy"), { recursive: true });
  writeFileSync(join(agentDir, "skills", "operator-decoy", "SKILL.md"), "---\nname: operator-decoy\ndescription: A personal skill of the operator's, nothing to do with the case. Use when asked about decoys.\n---\n\nDecoy body.\n");
  const firstPrompt = async (name: string, noSkills: boolean): Promise<string> => {
    const d = await makeSandbox(name);
    // As the kickoff leaves the sandbox: the worker prompt is Pi's custom prompt, which does not stop Pi listing skills.
    copyFileSync(join(REPO, "prompts", "worker-system.md"), join(d.root, ".pi", "SYSTEM.md"));
    const client = new RpcClient({ args: args(d, { noSkills }), cwd: d.root, env: { ...ENV, PI_CODING_AGENT_DIR: agentDir, SC_FAKE_TRACE: d.traceFile }, logFile: d.logFile });
    try {
      const accepted = await client.request({ type: "prompt", message: "Start the scripted work." });
      assert.equal(accepted.success, true, JSON.stringify(accepted));
      for (let i = 0; i < 100 && fakeTurns(d).length === 0; i++) await new Promise((r) => setTimeout(r, 100));
      const turns = fakeTurns(d);
      assert.ok(turns.length > 0, `no model request was made: ${client.stderr.join("").slice(-500)}`);
      return turns[0]!.systemPrompt ?? "";
    } finally {
      await client.close();
      await cleanup(d);
    }
  };
  try {
    const without = await firstPrompt("decoy-visible", false);
    assert.ok(without.includes("You are one worker in a local swarm."), "the worker prompt is the custom prompt, as in a run");
    assert.ok(without.includes("operator-decoy"), "without --no-skills Pi lists the operator's skill in the prompt, under the worker prompt too (the exposure --no-skills closes)");
    assert.match(without, /<available_skills>/);
    const withFlag = await firstPrompt("decoy-hidden", true);
    assert.ok(!withFlag.includes("operator-decoy") && !withFlag.includes("<available_skills>"), "with --no-skills the seat's prompt has no Pi skills at all");
  } finally {
    await rm(agentDir, { recursive: true, force: true });
  }
});
