/**
 * The skill unloader through the real CLI (`pi --mode rpc` 0.87.x), the real
 * swarm extension and scripted providers (tests/fixtures/skill-unload-fake-provider.ts)
 * that record every request they are sent: a body the seat marked done is
 * replaced in what the model is sent by a one-line stub, the session still
 * holds the raw result, a compaction after a release is summarised without
 * the body, a body loaded again after a release is delivered whole, and which
 * of that happens depends on the model's catalogue entry and on
 * `--skill-release`. No key, no network, no money.
 *
 * Needs `pi` on PATH. Skips when it is not there, like tests/skills-e2e.test.ts.
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { copyFileSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { test } from "node:test";
import { EVENTS_REL, initSandbox } from "../extensions/protocol.ts";
import { sessionCalls } from "../scripts/question-cost.ts";
import { skillUse, type SkillTraceRow } from "../ui/src/lib/skill-metrics.ts";
import { twoPacks } from "./fixtures/skill-packs.ts";
import { messageText, RpcClient, type RpcEvent } from "./harness/rpc-client.ts";

const REPO = resolve(import.meta.dirname, "..");
const EXTENSION = join(REPO, "extensions", "agent-swarm.ts");
const FAKE = join(REPO, "tests", "fixtures", "skill-unload-fake-provider.ts");
const TOOLS = "read,bash,edit,write,post,inbox,wait,claim_file,release_file,claims,list_team,budget,file_history,file_restore,file_diff,thread_open,thread_join,inputs,name,record,ledger,done,self_compact,skill,skill_done";
const BODY_ONE = "Read the run count first";
const BODY_TWO = "Second body, short.";
const STUB_ONE = /^evidence\/one released \(\d+ tokens\)\. Re-load with skill\('evidence\/one'\)\.$/;

function haveCli(): boolean {
  try {
    execFileSync("pi", ["--version"], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });
    return true;
  } catch {
    return false;
  }
}

type Dir = { root: string; sessionDir: string; logFile: string; fakeTrace: string };

async function makeSandbox(name: string): Promise<Dir> {
  const root = await mkdtemp(join(tmpdir(), `skill-unload-${name}-`));
  await initSandbox(root, { reset: true });
  mkdirSync(join(root, ".pi"), { recursive: true });
  writeFileSync(join(root, ".pi", "settings.json"), JSON.stringify({ compaction: { enabled: true, reserveTokens: 16384, keepRecentTokens: 1500 } }, null, 2));
  copyFileSync(join(REPO, "prompts", "worker-system.md"), join(root, ".pi", "SYSTEM.md"));
  mkdirSync(join(root, "work", "agent00"), { recursive: true });
  const sessionDir = join(root, ".pi-sessions", "agent00");
  mkdirSync(sessionDir, { recursive: true });
  return { root, sessionDir, logFile: join(root, "rpc.log"), fakeTrace: join(root, "fake-trace.jsonl") };
}

type Call = { name: string; arguments: Record<string, unknown> };
type Step = { calls?: Call[]; text?: string };
const skill = (id: string): Call => ({ name: "skill", arguments: { id } });
const done = (id: string, note = "took what I needed"): Call => ({ name: "skill_done", arguments: { id, note } });
const filler = (n: number): Call => ({ name: "bash", arguments: { command: `printf 'filler ${n} '; yes filler | head -n 300 | tr '\\n' ' '; echo` } });
const calls = (...c: Call[]): Step => ({ calls: c });
const HANDOFF_NOTE = "NAME: scripted-worker\nDONE: read two notes.\nNEXT ACTION: write nothing, reply All done.";
const handoff = (): Call => ({ name: "self_compact", arguments: { note_to_self: HANDOFF_NOTE } });
const FINAL = "All done.";

type Msg = { role: string; toolName?: string; toolCallId?: string; isError?: boolean; text: string };
type Turn = { kind: "turn"; i: number; model: string; tools: string[]; messages: Msg[] };
type Summary = { kind: "summary"; model: string; input: string };
type Row = SkillTraceRow & { tool: string; args: Record<string, unknown>; result: Record<string, unknown> };
type SessionEntry = { type: string; id: string; targetId?: string; replacement?: { content: Array<{ type: string; text?: string }> } | null; message?: { role?: string; toolName?: string; content?: Array<{ type: string; text?: string; thinkingSignature?: string }> } };

type Run = { turns: Turn[]; summaries: Summary[]; rows: Row[]; session: SessionEntry[]; events: RpcEvent[]; calls: Awaited<ReturnType<typeof sessionCalls>> };

/** One scripted seat over the two test packs, to the end of its script. */
async function runSeat(name: string, options: { model: string; release?: string; script: Step[]; thinking?: string }): Promise<Run> {
  const d = await makeSandbox(name);
  const packsRoot = await mkdtemp(join(tmpdir(), "skill-unload-packs-"));
  const { a, b } = await twoPacks(packsRoot);
  const client = new RpcClient({
    args: ["--no-extensions", "--no-skills", "--no-prompt-templates", "--no-context-files", "-a", "-e", EXTENSION, "-e", FAKE, "--model", options.model, ...(options.thinking ? ["--thinking", options.thinking] : []), "--session-dir", d.sessionDir, "--tools", TOOLS],
    cwd: d.root,
    env: {
      AGENT_ID: "agent00",
      SWARM_SELF_COMPACT: "1",
      SWARM_COMPACT_NOTICE_AT: "20%",
      SWARM_COMPACT_WARN_AT: "40%",
      SWARM_COMPACT_AT: "50%",
      SWARM_PACK_DIRS: `${a}:${b}`,
      ...(options.release !== undefined ? { SWARM_SKILL_RELEASE: options.release } : {}),
      SU_SCRIPT: JSON.stringify([...options.script, { text: FINAL }]),
      SU_TRACE: d.fakeTrace,
    },
    logFile: d.logFile,
  });
  try {
    const accepted = await client.request({ type: "prompt", message: "Start the scripted work." });
    assert.equal(accepted.success, true, JSON.stringify(accepted));
    await client.waitFor((e) => e.type === "message_end" && (e.message as { role?: string })?.role === "assistant" && messageText(e.message).includes(FINAL), 90_000);
    await client.waitFor((e) => e.type === "agent_settled", 30_000, { since: client.events.length - 1 }).catch(() => undefined);
  } finally {
    await client.close();
  }
  const records = existsSync(d.fakeTrace) ? readFileSync(d.fakeTrace, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l) as Turn | Summary) : [];
  const sessionFile = readdirSync(d.sessionDir).filter((f) => f.endsWith(".jsonl")).map((f) => join(d.sessionDir, f))[0]!;
  const run: Run = {
    turns: records.filter((r): r is Turn => r.kind === "turn"),
    summaries: records.filter((r): r is Summary => r.kind === "summary"),
    rows: readFileSync(join(d.root, EVENTS_REL), "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l) as Row),
    session: readFileSync(sessionFile, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l) as SessionEntry),
    events: [...client.events],
    // What the replay and cost readers make of the seat's session files, read where they are.
    calls: await sessionCalls(d.root),
  };
  if (process.env.SC_KEEP === "1") console.log(`kept ${d.root}`);
  else {
    await rm(d.root, { recursive: true, force: true }).catch(() => undefined);
  }
  await rm(packsRoot, { recursive: true, force: true }).catch(() => undefined);
  return run;
}

const rowsOf = (run: Run, tool: string) => run.rows.filter((r) => r.tool === tool);
const skillResultsIn = (turn: Turn) => turn.messages.filter((m) => m.role === "toolResult" && m.toolName === "skill").map((m) => m.text);
const carries = (turn: Turn, needle: string) => turn.messages.some((m) => m.text.includes(needle));
const resultEntries = (run: Run, toolName: string) => run.session.filter((e) => e.type === "message" && e.message?.role === "toolResult" && e.message.toolName === toolName);

// A script that loads two notes, finishes with the first, works on, and hands off.
const TWO_NOTES_THEN_HANDOFF: Step[] = [
  calls(skill("evidence/one")), //                     0
  calls(skill("evidence/two")), //                     1
  calls(filler(1)), //                                 2
  calls(done("evidence/one")), //                      3: the first is finished
  calls(filler(2)), //                                 4
  calls(filler(3)), //                                 5
  calls(filler(4)), //                                 6
  calls(handoff()), //                                 7: the seat hands off; a compaction follows
  // 8: the request the hand-off message starts answers with the final text
];

test("a finished body is replaced by a one-line stub at the next turn boundary; the session keeps the raw result; a body loaded again is delivered whole and not released twice", async (t) => {
  if (!haveCli()) {
    t.skip("pi is not on PATH");
    return;
  }
  const run = await runSeat("boundary", {
    model: "fake/scripted",
    script: [
      calls(skill("evidence/one")), //          0
      calls(filler(1)), //                      1
      calls(done("evidence/one")), //           2: finished; its turn ends, the body is released
      calls(filler(2)), //                      3: the request after the release
      calls(skill("evidence/one")), //          4: the seat needs it again
      calls(done("evidence/one")), //           5: finished again
      calls(filler(3)), //                      6
    ],
  });

  // (a) What the model was sent. Before the seat said done it had the body; the request after the turn that said it has the stub, not the body.
  assert.ok(run.turns.length >= 8, `${run.turns.length} requests`);
  assert.ok(carries(run.turns[2]!, BODY_ONE), "the request that produced skill_done still carried the body");
  assert.equal(carries(run.turns[3]!, BODY_ONE), false, "the request after the release does not carry the body");
  const stubbed = skillResultsIn(run.turns[3]!);
  assert.equal(stubbed.length, 1);
  assert.match(stubbed[0]!, STUB_ONE);
  assert.equal(run.turns[3]!.messages.length, run.turns[2]!.messages.length + 2, "nothing else left the history: the assistant message and the tool result of the done turn are added to the same messages");
  assert.ok(!run.turns[3]!.tools.includes("context_edit"), "the model was given no tool for this");

  // (d) skill(id) after a release delivers the body again, whole; the ledger says so.
  assert.equal(carries(run.turns[5]!, BODY_ONE), true, "the body is in the request after the seat loaded it again");
  assert.match(skillResultsIn(run.turns[5]!)[0]!, STUB_ONE, "the first copy is still the stub");
  assert.match(skillResultsIn(run.turns[5]!)[1]!, /^Skill `evidence\/one` \(pack pack-a 1\.2\.0, about \d+ tokens\)/);
  // Never toggle: the second done does not release it again in this context.
  assert.equal(carries(run.turns[7]!, BODY_ONE), true, "the second copy stays: a body is released once between two compactions");

  // The trace: load, done, unload, load (flagged), done; one unload only.
  const sequence = run.rows.filter((r) => ["skill", "skill_done", "skill_unload"].includes(r.tool)).map((r) => (r.tool === "skill" ? (r.result.reload_after_release ? "load*" : "load") : r.tool));
  assert.deepEqual(sequence, ["load", "skill_done", "skill_unload", "load*", "skill_done"]);
  const unload = rowsOf(run, "skill_unload")[0]!;
  assert.equal(unload.result.ok, true);
  assert.equal(unload.result.reason, "done");
  assert.equal(unload.result.pack, "pack-a");
  assert.match(String(unload.result.sha256), /^[0-9a-f]{64}$/);
  assert.ok(Number(unload.result.tokens) > 0);
  const firstLoad = rowsOf(run, "skill")[0]!;
  assert.equal(unload.result.call, firstLoad.result.call, "the unload names the tool call whose result it replaced");
  assert.equal(unload.result.loaded_turn, 1);
  assert.equal(unload.result.turn, 3);
  assert.equal(rowsOf(run, "skill")[1]!.result.released_turn, 3);

  // (b) The session still holds the raw result, and one context_edit that says what the model is sent instead.
  const loads = resultEntries(run, "skill");
  assert.equal(loads.length, 2);
  const raw = loads[0]!.message!.content!.map((c) => c.text ?? "").join("");
  assert.ok(raw.includes(BODY_ONE) && !STUB_ONE.test(raw), "the first tool result is the body, untouched");
  const edits = run.session.filter((e) => e.type === "context_edit");
  assert.equal(edits.length, 1, "one edit: the second release was not made");
  assert.equal(edits[0]!.targetId, loads[0]!.id);
  assert.match(edits[0]!.replacement!.content[0]!.text!, STUB_ONE);
  assert.equal(String(unload.result.entry), loads[0]!.id);

  // The policy row says why this seat's bodies leave at a boundary.
  const policy = rowsOf(run, "skill_release_policy");
  assert.equal(policy.length, 1);
  assert.deepEqual([policy[0]!.result.mode, policy[0]!.result.effective, policy[0]!.result.class, policy[0]!.result.api], ["auto", "boundary", "open", "openai-completions"]);

  // What the edit costs a provider's cache is on the row: about what followed the body at the time.
  assert.ok(Number(unload.result.suffix_tokens) > 0, `suffix_tokens ${String(unload.result.suffix_tokens)}`);
  assert.equal(unload.result.stub_tokens, Math.ceil(Buffer.byteLength(edits[0]!.replacement!.content[0]!.text!) / 4.245));

  // The readers of the session files are not troubled by the edit: every assistant call is still counted, once.
  const assistantEntries = run.session.filter((e) => e.type === "message" && e.message?.role === "assistant").length;
  assert.equal(run.calls.length, assistantEntries);

  // The console's Packs tab and the context audit count it from the trace alone.
  const seat = skillUse(run.rows, ["agent00"]).seats[0]!;
  assert.deepEqual([seat.loads, seat.done, seat.released, seat.released_at_compaction, seat.tokens_released, seat.reloaded_after_release], [2, 2, 1, 0, Number(unload.result.tokens), 1]);
  assert.deepEqual(seat.release_policy && [seat.release_policy.effective, seat.release_policy.class], ["boundary", "open"]);
  assert.deepEqual(seat.detail.map((d) => [d.released, d.reloaded_after_release]), [[true, false], [false, true]]);
});

test("two bodies finished in one turn leave together, in one edit of the history", async (t) => {
  if (!haveCli()) {
    t.skip("pi is not on PATH");
    return;
  }
  const run = await runSeat("batch", {
    model: "fake/scripted",
    script: [
      calls(skill("evidence/one")), // 0
      calls(skill("evidence/two")), // 1
      calls(filler(1)), //             2
      calls(done("evidence/one"), done("evidence/two")), // 3: both finished in one message
      calls(filler(2)), //             4
    ],
  });
  assert.equal(carries(run.turns[3]!, BODY_ONE) && carries(run.turns[3]!, BODY_TWO), true);
  assert.equal(carries(run.turns[4]!, BODY_ONE) || carries(run.turns[4]!, BODY_TWO), false, "both bodies are gone from the next request");
  assert.deepEqual(skillResultsIn(run.turns[4]!).map((x) => x.split(" ")[0]), ["evidence/one", "evidence/two"]);
  const unloads = rowsOf(run, "skill_unload");
  assert.deepEqual(unloads.map((r) => [r.args.id, r.result.batch, r.result.turn]), [["evidence/one", 2, 4], ["evidence/two", 2, 4]]);
  const edits = run.session.filter((e) => e.type === "context_edit");
  assert.equal(edits.length, 2);
  assert.equal(edits[0]!.id === edits[1]!.id, false);
  // Appended together: no message entry between them.
  const at = (id: string) => run.session.findIndex((e) => e.id === id);
  assert.equal(at(edits[1]!.id) - at(edits[0]!.id), 1);
});

test("parallel skill calls and a skill_done for an id the seat never loaded: the second load is told so, the unknown id is refused, and a body finished in the turn it was loaded waits one turn", async (t) => {
  if (!haveCli()) {
    t.skip("pi is not on PATH");
    return;
  }
  const run = await runSeat("parallel", {
    model: "fake/scripted",
    script: [
      calls(skill("evidence/one"), skill("evidence/one"), done("evidence/one"), done("no/such/note")), // 0: all four in one message
      calls(filler(1)), //                                                                              1
      calls(filler(2)), //                                                                              2
    ],
  });
  const results = run.turns[1]!.messages.filter((m) => m.role === "toolResult").map((m) => m.text);
  assert.match(results[0]!, /^Skill `evidence\/one`/);
  assert.match(results[1]!, /^`evidence\/one` \(pack-a\) is already in your context, loaded at turn 1; not sent again\.$/);
  assert.match(results[2]!, /^Recorded: `evidence\/one` is done\./);
  assert.match(results[3]!, /^`no\/such\/note` is not among the notes you have loaded/);
  const doneRows = rowsOf(run, "skill_done");
  assert.deepEqual(doneRows.map((r) => [r.result.ok, r.result.error ?? null]), [[true, null], [false, "not loaded"]]);
  // The body had no turn of its own before the first boundary: that boundary lets it stay, the next one releases it.
  assert.equal(carries(run.turns[1]!, BODY_ONE), true);
  assert.equal(carries(run.turns[2]!, BODY_ONE), false, "released at the boundary after the first turn that read it");
  assert.deepEqual(rowsOf(run, "skill_unload").map((r) => [r.result.ok, r.result.turn, r.result.loaded_turn]), [[true, 2, 1]]);
});

test("with thinking on, a Claude-shaped catalogue entry keeps its bodies until the compaction: no edit before it, the finished body leaves with it, and the summary is written from a stub", async (t) => {
  if (!haveCli()) {
    t.skip("pi is not on PATH");
    return;
  }
  const run = await runSeat("claude", { model: "fakeclaude/claude-scripted", script: TWO_NOTES_THEN_HANDOFF });

  // (e) The policy: the catalogue says anthropic-messages and reasoning, thinking is on, so no draft before the compaction.
  const policy = rowsOf(run, "skill_release_policy");
  assert.equal(policy.length, 1);
  assert.deepEqual([policy[0]!.result.effective, policy[0]!.result.class, policy[0]!.result.api, policy[0]!.result.reasoning], ["compaction", "signed-thinking", "anthropic-messages", true]);
  assert.notEqual(policy[0]!.result.thinking_level, "off");
  for (const i of [4, 5, 6, 7]) assert.equal(carries(run.turns[i]!, BODY_ONE), true, `request ${i}: the finished body is still there`);
  const compactionAt = run.session.findIndex((e) => e.type === "compaction");
  assert.ok(compactionAt > 0, "the hand-off compacted the session");
  const editAts = run.session.map((e, i) => (e.type === "context_edit" ? i : -1)).filter((i) => i >= 0);
  assert.equal(editAts.length, 1, "one edit in the whole session");
  assert.ok(editAts[0]! < compactionAt, "and it came right before the compaction, not at the turn that said done");
  const doneAt = run.session.findIndex((e) => e.type === "message" && e.message?.role === "toolResult" && e.message.toolName === "skill_done");
  assert.ok(editAts[0]! > doneAt + 8, "well after the skill_done: the finished body waited");

  // The release at the compaction, on the record.
  const unload = rowsOf(run, "skill_unload");
  assert.deepEqual(unload.map((r) => [r.args.id, r.result.ok, r.result.reason]), [["evidence/one", true, "compaction"]]);

  // The signed thinking blocks of the assistant turns are in the session as the provider wrote them.
  const assistants = run.session.filter((e) => e.type === "message" && e.message?.role === "assistant");
  assert.ok(assistants.length >= 8);
  assert.ok(assistants.every((e) => e.message!.content!.some((c) => c.type === "thinking" && /^sig-\d+$/.test(c.thinkingSignature ?? ""))), "no assistant message lost its thinking block");

  // (c) The summary input: the finished body is a stub, the other note is a line that names it, neither is text; the block lists them.
  assert.equal(run.summaries.length, 1);
  const input = run.summaries[0]!.input;
  assert.equal(input.includes(BODY_ONE) || input.includes(BODY_TWO), false, "no note's text reached the summary call");
  assert.match(input, /evidence\/one released \(\d+ tokens\)\. Re-load with skill\('evidence\/one'\)\./);
  assert.match(input, /\[note pack-a:evidence\/two: \d+ tokens, read at turn 2; its text is not part of this summary input\]/);
  assert.match(input, /<skills-read>[\s\S]*pack-a:evidence\/one: \d+ tokens, read at turn 1, marked done and released from its context[\s\S]*pack-a:evidence\/two: \d+ tokens, read at turn 2, not marked done[\s\S]*Not marked done \(probably still needed after the compaction\): pack-a:evidence\/two\.[\s\S]*<\/skills-read>/);

  // The hand-off message the seat resumed on: what it read, with sizes, and what it probably still needs.
  const resumed = run.turns[8]!;
  const header = resumed.messages.filter((m) => m.role === "user").map((m) => m.text).find((x) => x.startsWith("[self-compact · handoff]"))!;
  assert.match(header, /Skill bodies a compaction took out of your context: pack-a:evidence\/two\. Load again/);
  assert.match(header, /Method notes you read since your last compaction, with their size in tokens \(never their text\): pack-a:evidence\/two \d+ \(not marked done\), pack-a:evidence\/one \d+ \(marked done, released\)\./);
  assert.match(header, /Not marked done, so probably still needed: pack-a:evidence\/two\./);
  assert.equal(carries(resumed, BODY_ONE) || carries(resumed, BODY_TWO), false, "after the hand-off no note text is in the request: the summary and the header carry ids and sizes");
});

test("a model that does not think releases the finished body at the turn boundary, and the compaction after it is summarised without that body", async (t) => {
  if (!haveCli()) {
    t.skip("pi is not on PATH");
    return;
  }
  const run = await runSeat("release-then-compact", { model: "fake/scripted", script: TWO_NOTES_THEN_HANDOFF });
  assert.equal(carries(run.turns[3]!, BODY_ONE), true);
  assert.equal(carries(run.turns[4]!, BODY_ONE), false, "released at the boundary of the turn that said done");
  assert.match(skillResultsIn(run.turns[4]!)[0]!, STUB_ONE);
  assert.equal(carries(run.turns[4]!, BODY_TWO), true, "the note the seat has not finished with stays");
  assert.deepEqual(rowsOf(run, "skill_unload").map((r) => [r.args.id, r.result.reason, r.result.turn]), [["evidence/one", "done", 4]], "one release, at the boundary; the compaction had nothing left to release");
  assert.equal(rowsOf(run, "skill_release_policy")[0]!.result.effective, "boundary");

  // (c) The compaction after a release: the summary call is given the stub, not the body, and not the other note's text either.
  assert.equal(run.summaries.length, 1);
  const input = run.summaries[0]!.input;
  assert.equal(input.includes(BODY_ONE) || input.includes(BODY_TWO), false);
  assert.match(input, /evidence\/one released \(\d+ tokens\)\. Re-load with skill\('evidence\/one'\)\./);
  assert.match(input, /pack-a:evidence\/two: \d+ tokens, read at turn 2, not marked done/);
  assert.ok(run.summaries[0]!.model === "scripted");
  // The session holds all of it: both raw results, the edit, the compaction.
  assert.ok(resultEntries(run, "skill").every((e) => e.message!.content!.some((c) => /Read the run count first|Second body, short\./.test(c.text ?? ""))));
  assert.equal(run.session.filter((e) => e.type === "context_edit").length, 1);
  assert.equal(run.session.filter((e) => e.type === "compaction").length, 1);
  // After the compaction the ledger is rebuilt from the session, and the released body is not counted as held: the stub is a stub.
  const compacted = rowsOf(run, "skills_compacted")[0]!;
  assert.deepEqual((compacted.result.lost as Array<{ key: string }>).map((x) => x.key), ["pack-a:evidence/two"]);
  assert.deepEqual((compacted.result.released as Array<{ key: string }> | undefined)?.map((x) => x.key), ["pack-a:evidence/one"]);
});

test("--skill-release compaction: a model that may be edited at a boundary still keeps the finished body until the compaction", async (t) => {
  if (!haveCli()) {
    t.skip("pi is not on PATH");
    return;
  }
  const run = await runSeat("mode-compaction", { model: "fake/scripted", release: "compaction", script: TWO_NOTES_THEN_HANDOFF });
  const policy = rowsOf(run, "skill_release_policy")[0]!;
  assert.deepEqual([policy.result.mode, policy.result.effective, policy.result.class], ["compaction", "compaction", "open"]);
  for (const i of [4, 5, 6, 7]) assert.equal(carries(run.turns[i]!, BODY_ONE), true, `request ${i}`);
  assert.deepEqual(rowsOf(run, "skill_unload").map((r) => [r.result.ok, r.result.reason]), [[true, "compaction"]]);
  assert.match(run.summaries[0]!.input, /evidence\/one released \(\d+ tokens\)/);
  assert.equal(run.summaries[0]!.input.includes(BODY_ONE), false);
});

test("--skill-release off: no stub, no edit, nothing shaped; the summary is written from what Pi serialises, as before the unloader", async (t) => {
  if (!haveCli()) {
    t.skip("pi is not on PATH");
    return;
  }
  const run = await runSeat("mode-off", { model: "fake/scripted", release: "off", script: TWO_NOTES_THEN_HANDOFF });
  const policy = rowsOf(run, "skill_release_policy")[0]!;
  assert.deepEqual([policy.result.mode, policy.result.effective], ["off", "off"]);
  for (const i of [4, 5, 6, 7]) assert.equal(carries(run.turns[i]!, BODY_ONE), true, `request ${i}`);
  assert.equal(rowsOf(run, "skill_unload").length, 0);
  assert.equal(run.session.filter((e) => e.type === "context_edit").length, 0);
  const input = run.summaries[0]!.input;
  assert.ok(input.includes(BODY_ONE) && input.includes(BODY_TWO), "Pi's serialisation of the bodies is what the summary is written from");
  assert.equal(input.includes("<skills-read>"), false);
  const header = run.turns[8]!.messages.filter((m) => m.role === "user").map((m) => m.text).find((x) => x.startsWith("[self-compact · handoff]"))!;
  assert.match(header, /Skill bodies a compaction took out of your context: pack-a:evidence\/one, pack-a:evidence\/two\. Load again/);
  assert.equal(header.includes("Method notes you read since your last compaction"), false);
});
