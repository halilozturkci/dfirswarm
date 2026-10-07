/**
 * The skill unloader, decision by decision (extensions/skills.ts): which model
 * may have a finished body replaced at a turn boundary and which only at a
 * compaction, which bodies the plan lets go, what the stub says, what the
 * draft Pi is handed looks like, what the ledger does with a body that was
 * released, and what a compaction's summary and the hand-off header are told of
 * the notes a seat read. No model, no key, no Pi loop: the unloader runs on a
 * fake `pi` beside a simulated session (tests/harness/skill-seat.ts). The same
 * decisions through the real CLI, a scripted provider and a real compaction are
 * tests/skill-unload-e2e.test.ts.
 */
import assert from "node:assert/strict";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { convertToLlm, SessionManager } from "@earendil-works/pi-coding-agent";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { test } from "node:test";
import { TOOL_RESERVED_NAMES } from "../extensions/protocol.ts";
import {
  countDroppedThinkingBlocks,
  DEFAULT_RELEASE_MODE,
  effectiveRelease,
  isStub,
  loadsFromEntries,
  parseReleaseMode,
  planRelease,
  releaseClassOf,
  renderHandoffReads,
  renderSkillsRead,
  shapeForSummary,
  signedThinkingAfter,
  SkillLedger,
  stubText,
  suffixTokens,
  type ModelFacts,
  type SkillLoad,
} from "../extensions/skills.ts";
import { skillUse } from "../ui/src/lib/skill-metrics.ts";
import { twoPacks } from "./fixtures/skill-packs.ts";
import { directSeat, disposeSeat, MODELS } from "./harness/skill-seat.ts";

const REPO = resolve(import.meta.dirname, "..");
const BODY_ONE = "Read the run count first";

async function withPacks(run: (a: string, b: string) => Promise<void>): Promise<void> {
  const root = await mkdtemp(join(tmpdir(), "skill-unload-packs-"));
  try {
    const { a, b } = await twoPacks(root);
    await run(a, b);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

// ---------------------------------------------------------------------------
// The class of a model, from the catalogue and nothing else
// ---------------------------------------------------------------------------

test("the release class is read off the catalogue entry's api and reasoning, never its name or the thinking level; an api not shown safe is compaction-only", () => {
  // The allow-list: the Responses family, and a model the catalogue does not mark as reasoning.
  assert.equal(releaseClassOf(MODELS.codex).cls, "open");
  assert.equal(releaseClassOf(MODELS.local).cls, "open");
  assert.equal(releaseClassOf(MODELS.claudeNoThink).cls, "open");
  // Claude with thinking, through the api that signs the blocks.
  assert.equal(releaseClassOf(MODELS.claude).cls, "signed-thinking");
  // Reasoning on any other api is not shown safe: OpenRouter's Claude entries replay Anthropic's signatures inside reasoning_details.
  assert.equal(releaseClassOf(MODELS.openrouterClaude).cls, "unproven");
  assert.equal(releaseClassOf(MODELS.localThinking).cls, "unproven");
  // The name decides nothing: the same fields under any id give the same class.
  assert.equal(releaseClassOf({ ...MODELS.claude, id: "gpt-6-sol" }).cls, "signed-thinking");
  assert.equal(releaseClassOf({ ...MODELS.codex, id: "claude-fable-5-1" }).cls, "open");
  assert.equal(releaseClassOf({ ...MODELS.openrouterClaude, id: "gpt-6-sol" }).cls, "unproven");
  // The thinking level decides nothing either: a signed block already in the history is sent back at any level (see signedThinkingAfter).
  // A session that names no model is not guessed at.
  assert.equal(releaseClassOf(undefined).cls, "unknown");
  // What each class comes to under each mode: only `open` is released at a boundary, and only under auto.
  for (const cls of ["open", "signed-thinking", "unproven", "unknown"] as const) {
    assert.equal(effectiveRelease("auto", cls), cls === "open" ? "boundary" : "compaction", `auto, ${cls}`);
    assert.equal(effectiveRelease("compaction", cls), "compaction", `compaction, ${cls}`);
    assert.equal(effectiveRelease("off", cls), "off", `off, ${cls}`);
  }
});

/**
 * Real entries of Pi 0.87.1's catalogue (the file, the api it files the entry under, the id) and the class each
 * must have. Written by hand, from what each transport does with a signature: nothing here is computed from the
 * sets the code uses, so dropping an api from them fails a line of this table.
 */
const CATALOGUE_CASES: Array<[file: string, api: string, id: string, want: string]> = [
  ["anthropic.json", "anthropic-messages", "claude-fable-5-1", "signed-thinking"],
  ["anthropic.json", "anthropic-messages", "claude-opus-5-5", "signed-thinking"],
  ["anthropic.json", "anthropic-messages", "claude-sonnet-5", "signed-thinking"],
  ["anthropic.json", "anthropic-messages", "claude-haiku-4-5", "signed-thinking"],
  ["amazon-bedrock.json", "bedrock-converse-stream", "anthropic.claude-opus-5-5", "signed-thinking"],
  ["amazon-bedrock.json", "bedrock-converse-stream", "amazon.nova-lite-v1:0", "open"],
  ["openrouter.json", "anthropic-messages", "anthropic/claude-fable-5.1", "signed-thinking"],
  ["openrouter.json", "openai-completions", "anthropic/claude-fable-5.1:batch", "unproven"],
  ["openrouter.json", "openai-completions", "~anthropic/claude-opus-latest", "unproven"],
  ["radius.json", "pi-messages", "claude-fable-5-1", "unproven"],
  ["google.json", "google-generative-ai", "gemini-3-flash-preview", "unproven"],
  ["openai.json", "openai-responses", "gpt-5.5", "open"],
  ["openai.json", "openai-responses", "gpt-6-sol", "open"],
  ["openai.json", "openai-responses", "gpt-4o", "open"],
  ["openai-codex.json", "openai-codex-responses", "gpt-6-sol", "open"],
  ["openai-codex.json", "openai-codex-responses", "gpt-6-luna", "open"],
  ["azure-openai-responses.json", "azure-openai-responses", "gpt-5", "open"],
  ["mistral.json", "mistral-conversations", "codestral-latest", "open"],
];

test("over Pi's catalogue: named entries across providers have the class written for them, and no reasoning entry outside the Responses family is ever released at a boundary", () => {
  const candidates = [
    join(REPO, "node_modules", "@earendil-works", "pi-coding-agent", "node_modules", "@earendil-works", "pi-ai", "dist", "providers", "data"),
    join(REPO, "node_modules", "@earendil-works", "pi-ai", "dist", "providers", "data"),
  ];
  const dir = candidates.find((d) => existsSync(d));
  if (!dir) {
    return; // Pi's catalogue is not installed here; the class tests above still hold
  }
  const file = (name: string) => JSON.parse(readFileSync(join(dir, name), "utf8")) as Record<string, Record<string, ModelFacts & { id: string }>>;
  for (const [name, api, id, want] of CATALOGUE_CASES) {
    const entry = file(name)[api]?.[id];
    assert.ok(entry, `${name}: ${api} ${id} is in Pi's catalogue`);
    assert.equal(releaseClassOf(entry!).cls, want, `${name}: ${id}`);
  }
  // The whole catalogue, with the expectation stated in the test's own terms (a literal list, not the code's set).
  const responsesApis = ["openai-responses", "openai-codex-responses", "azure-openai-responses"];
  let entries = 0;
  let reasoningOutside = 0;
  for (const name of readdirSync(dir).filter((f) => f.endsWith(".json"))) {
    for (const models of Object.values(file(name))) {
      for (const model of Object.values(models)) {
        entries += 1;
        const cls = releaseClassOf(model).cls;
        const releasable = effectiveRelease("auto", cls) === "boundary";
        if (responsesApis.includes(String(model.api)) || model.reasoning !== true) assert.equal(releasable, true, `${name}: ${model.id} may be released at a boundary`);
        else {
          reasoningOutside += 1;
          assert.equal(releasable, false, `${name}: ${model.id} (${model.api}, reasoning) is compaction-only`);
        }
      }
    }
  }
  assert.ok(entries > 1000 && reasoningOutside > 500, `${entries} entries, ${reasoningOutside} reasoning entries outside the Responses family`);
});

test("the release mode is compaction (the default), auto or off; anything else is not a mode and runs as the default", () => {
  assert.equal(DEFAULT_RELEASE_MODE, "compaction");
  assert.deepEqual(["auto", "compaction", "off", " OFF ", "Compaction"].map(parseReleaseMode), ["auto", "compaction", "off", "off", "compaction"]);
  assert.deepEqual(["", "never", "boundary", undefined, null].map(parseReleaseMode), [null, null, null, null, null]);
});

// ---------------------------------------------------------------------------
// The stub, the plan
// ---------------------------------------------------------------------------

test("the stub is one line that names the note, its size and the way back; the same text is recognised again", () => {
  const stub = stubText("execution/prefetch", 508);
  assert.equal(stub, "execution/prefetch released (508 tokens). Re-load with skill('execution/prefetch').");
  assert.ok(!stub.includes("\n"));
  assert.equal(isStub(stub), true);
  assert.equal(isStub(`${stub}\n`), true);
  assert.equal(isStub(stubText("pack-b:shared/dup", 5)), true, "a pack:id reference too");
  assert.equal(isStub("Skill `execution/prefetch` (pack windows 1.0.0, about 508 tokens)\n\nBody."), false);
  assert.equal(isStub("execution/prefetch released (508 tokens). Re-load with skill('other')."), true, "only the shape is checked");
});

const load = (key: string, turn: number, done: number | null = null): SkillLoad => {
  const [pack, id] = key.split(":") as [string, string];
  return { key, pack, id, turn, at: "", sha256: "a".repeat(64), tokens: 100, toolCallId: `call-${key}-${turn}`, ...(done !== null ? { done: { turn: done, note: "" } } : {}) };
};
const plan = (held: SkillLoad[], extra: Partial<Parameters<typeof planRelease>[0]> = {}) =>
  planRelease({ held, turn: 10, effective: "boundary", trigger: "turn_end", releasedAt: () => undefined, ...extra });
const keys = (loads: SkillLoad[]) => loads.map((l) => l.key);

test("only a body the seat marked done is released, however many it holds; the notes it is working from are never touched", () => {
  const working = [load("p:a", 1), load("p:b", 2), load("p:c", 3), load("p:d", 4), load("p:e", 5)];
  const result = plan([...working, load("p:f", 6, 7)]);
  assert.deepEqual(keys(result.release), ["p:f"]);
  assert.deepEqual(result.keep.map((k) => [k.load.key, k.why]), working.map((l) => [l.key, "not marked done"]));
  assert.deepEqual(keys(plan(working).release), [], "five bodies held and none finished: nothing leaves, whatever the count");
});

test("all the finished bodies go in one plan: the history is rewritten once, not once per body", () => {
  const result = plan([load("p:a", 1, 3), load("p:b", 2, 4), load("p:c", 3)]);
  assert.deepEqual(keys(result.release), ["p:a", "p:b"]);
});

test("a body no turn has read yet is kept, whatever was marked; the next boundary lets it go", () => {
  const result = plan([load("p:a", 10, 10)], { turn: 10 });
  assert.deepEqual(result.release, []);
  assert.equal(result.keep[0]!.why, "no turn has read it yet");
  assert.deepEqual(keys(plan([load("p:a", 10, 10)], { turn: 11 }).release), ["p:a"]);
});

test("the policy decides the trigger: off releases nothing, compaction-only waits for a compaction, and a boundary release needs a boundary policy", () => {
  const held = [load("p:a", 1, 2)];
  assert.deepEqual(plan(held, { effective: "off" }).release, []);
  assert.deepEqual(plan(held, { effective: "off", trigger: "compaction" }).release, []);
  assert.deepEqual(plan(held, { effective: "compaction", trigger: "turn_end" }).release, []);
  assert.equal(plan(held, { effective: "compaction", trigger: "turn_end" }).keep[0]!.why, "this model's bodies leave at a compaction only");
  assert.deepEqual(keys(plan(held, { effective: "compaction", trigger: "compaction" }).release), ["p:a"]);
  assert.deepEqual(keys(plan(held, { effective: "boundary", trigger: "compaction" }).release), ["p:a"]);
});

test("never toggle: a body released once in a context is not released again at a boundary; at a compaction the rewrite is free", () => {
  const held = [load("p:a", 5, 6)];
  const seen = (key: string) => (key === "p:a" ? 4 : undefined);
  const again = plan(held, { releasedAt: seen });
  assert.deepEqual(again.release, []);
  assert.equal(again.keep[0]!.why, "released once already in this context");
  assert.deepEqual(keys(plan(held, { releasedAt: seen, trigger: "compaction" }).release), ["p:a"]);
});

test("a signed thinking block after the body keeps it at a boundary, and not at a hand-off", () => {
  const held = [load("p:a", 1, 2)];
  const signed = () => true;
  assert.deepEqual(plan(held, { signedAfter: signed }).release, []);
  assert.equal(plan(held, { signedAfter: signed }).keep[0]!.why, "a signed thinking block comes after it in the context");
  assert.deepEqual(keys(plan(held, { signedAfter: signed, trigger: "compaction" }).release), ["p:a"], "the history is replaced anyway");
  assert.deepEqual(keys(plan(held, { signedAfter: () => false }).release), ["p:a"]);
});

test("signedThinkingAfter: a thinking block with a signature from any api but the Responses family, after the entry and not before it", () => {
  const msg = (id: string, api: string | undefined, signature: unknown) => ({ type: "message", id, message: { role: "assistant", ...(api ? { api } : {}), content: [{ type: "thinking", thinking: "t", thinkingSignature: signature }, { type: "text", text: "x" }] } });
  const body = { type: "message", id: "body", message: { role: "toolResult", toolName: "skill" } };
  assert.equal(signedThinkingAfter([msg("before", "anthropic-messages", "SIG"), body, msg("after", "openai-responses", "{}")], "body"), false, "before the body does not count, and a Responses reasoning item is not signed over the history");
  assert.equal(signedThinkingAfter([body, msg("after", "anthropic-messages", "SIG")], "body"), true);
  assert.equal(signedThinkingAfter([body, msg("after", "openai-completions", "reasoning_details")], "body"), true, "OpenRouter replays Anthropic's signature through this api");
  assert.equal(signedThinkingAfter([body, msg("after", undefined, "SIG")], "body"), true, "a message that names no api is not trusted");
  assert.equal(signedThinkingAfter([body, msg("after", "anthropic-messages", "")], "body"), false, "no signature, nothing bound");
  assert.equal(signedThinkingAfter([body, msg("after", "anthropic-messages", undefined)], "body"), false);
  assert.equal(signedThinkingAfter([body], "missing"), false);
  assert.equal(signedThinkingAfter([body, { type: "message", id: "u", message: { role: "user", content: "x" } }], "body"), false);
});

// ---------------------------------------------------------------------------
// What the session says
// ---------------------------------------------------------------------------

const resultEntry = (id: string, callId: string, details: Record<string, unknown>, toolName = "skill") => ({ type: "message", id, message: { role: "toolResult", toolName, toolCallId: callId, details } });
const loadDetails = (id: string, pack: string, turn: number) => ({ ok: true, id, pack, turn, sha256: "b".repeat(64), tokens: 40 });

test("a body whose result a context_edit replaced is not in the context: it is returned as released, not as held", () => {
  const entries = [
    resultEntry("e1", "c1", loadDetails("evidence/one", "pack-a", 1)),
    resultEntry("e2", "c2", loadDetails("evidence/two", "pack-a", 2)),
    resultEntry("e3", "c3", { ok: true, id: "evidence/one", pack: "pack-a", turn: 3, note: "n" }, "skill_done"),
    { type: "context_edit", id: "x1", targetId: "e1", replacement: { content: [{ type: "text", text: "stub" }] } },
  ];
  const read = loadsFromEntries(entries);
  assert.deepEqual(read.loads.map((l) => [l.key, l.entryId]), [["pack-a:evidence/two", "e2"]]);
  assert.deepEqual(read.released.map((l) => [l.key, l.entryId, l.toolCallId]), [["pack-a:evidence/one", "e1", "c1"]]);
  assert.equal(read.loads[0]!.done, undefined, "the done mark of the released body does not attach to anything held");
  // An omission (replacement null) is an edit too: the entry is not in the context either.
  assert.deepEqual(loadsFromEntries([...entries.slice(0, 2), { type: "context_edit", id: "x2", targetId: "e2", replacement: null }]).loads.map((l) => l.key), ["pack-a:evidence/one"]);
  // A body loaded again after a release is the held one; its older copy is the stub.
  const again = loadsFromEntries([...entries, resultEntry("e4", "c4", loadDetails("evidence/one", "pack-a", 5))]);
  assert.deepEqual(again.loads.map((l) => [l.key, l.toolCallId]).sort(), [["pack-a:evidence/one", "c4"], ["pack-a:evidence/two", "c2"]]);
  assert.deepEqual(again.released.map((l) => l.toolCallId), ["c1"]);
  // Given the branch as well, an edit says in which turn it was made: the assistant messages before it.
  const assistantAt = (id: string) => ({ type: "message", id, message: { role: "assistant", content: [] } });
  const branch = [assistantAt("a1"), entries[0]!, assistantAt("a2"), assistantAt("a3"), entries[3]!, assistantAt("a4")];
  assert.deepEqual(loadsFromEntries(entries, branch).released.map((l) => l.releasedTurn), [3]);
  assert.deepEqual(loadsFromEntries(entries).released.map((l) => l.releasedTurn), [null], "no branch: not known, not guessed");
  // An index answer that was edited out is not an index in the context.
  const index = [resultEntry("i1", "ci", { ok: true, index: true, in_prompt: false, turn: 4 })];
  assert.equal(loadsFromEntries(index).indexTurn, 4);
  assert.equal(loadsFromEntries([...index, { type: "context_edit", id: "xi", targetId: "i1", replacement: null }]).indexTurn, null);
});

test("what an edit makes the cache write again is the context after the edited entry: the estimate the row carries", () => {
  const projected = [
    { sourceEntry: { id: "a" }, messages: [{ role: "toolResult", content: [{ type: "text", text: "x".repeat(400) }] }] },
    { sourceEntry: { id: "b" }, messages: [{ role: "assistant", content: [{ type: "text", text: "y".repeat(80) }, { type: "toolCall", arguments: { command: "z".repeat(20) } }] }] },
    { sourceEntry: { id: "c" }, messages: [{ role: "toolResult", content: [{ type: "text", text: "w".repeat(120) }] }, { role: "user", content: "v".repeat(40) }] },
  ];
  assert.equal(suffixTokens(projected, "a"), Math.ceil((80 + `{"command":"${"z".repeat(20)}"}`.length + 120 + 40) / 4));
  assert.equal(suffixTokens(projected, "c"), 0);
  assert.equal(suffixTokens(projected, "missing"), null);
  assert.equal(suffixTokens([], "a"), null);
});

// ---------------------------------------------------------------------------
// The ledger
// ---------------------------------------------------------------------------

test("the ledger remembers a release: the key is no longer held, the turn is on record, and a load after it is the same epoch's second", () => {
  const ledger = new SkillLedger();
  const one = load("p:one", 1);
  ledger.record(one);
  ledger.markDone("p:one", 2, "n");
  assert.deepEqual(ledger.releasable().map((l) => l.key), ["p:one"]);
  assert.equal(ledger.releasedAt("p:one"), undefined);
  assert.equal(ledger.release("p:one", { turn: 3, reason: "done" })?.key, "p:one");
  assert.equal(ledger.get("p:one"), undefined);
  assert.deepEqual(ledger.releasable(), []);
  assert.equal(ledger.releasedAt("p:one"), 3);
  assert.equal(ledger.release("p:one"), null, "a body that is not held cannot be released");
  ledger.record(load("p:one", 5));
  assert.equal(ledger.releasedAt("p:one"), 3, "loading it again does not forget that it was released: that is what keeps it from being released twice");
  assert.deepEqual(ledger.releasedLoads().map((l) => l.key), ["p:one"]);
  ledger.drop("p:one");
  assert.equal(ledger.get("p:one"), undefined, "a body the session no longer shows is dropped without being called a release");
});

test("a compaction ends the epoch: released bodies that left with it are reported once, the ones still in the kept tail as stubs stay on the record", () => {
  const ledger = new SkillLedger();
  for (const l of [load("p:a", 1), load("p:b", 2), load("p:c", 3)]) ledger.record(l);
  ledger.markDone("p:a", 4, "");
  ledger.release("p:a", { turn: 4, reason: "done" });
  ledger.markDone("p:b", 5, "");
  const stillStub = { ...load("p:a", 1), entryId: "e1", releasedTurn: 4 };
  const { kept, lost } = ledger.reconcile([{ ...load("p:c", 3), entryId: "e3" }], null, [stillStub]);
  assert.deepEqual(keys(kept), ["p:c"]);
  assert.deepEqual(keys(lost), ["p:b"]);
  const account = ledger.compactionAccount();
  assert.deepEqual(keys(account.lost), ["p:b"]);
  assert.deepEqual(keys(account.kept), ["p:c"]);
  assert.deepEqual(keys(account.released), ["p:a"]);
  assert.equal(ledger.releasedAt("p:a"), 4, "the stub in the kept tail is still this epoch's release, in the turn it was made");
  assert.equal(new SkillLedger().releasedAt("p:a"), undefined);
  assert.deepEqual(ledger.handoffIds(), ["p:b"]);
  // A process that starts on a session does not report a compaction it did not see.
  const restarted = new SkillLedger();
  restarted.restore([{ ...load("p:c", 3), entryId: "e3" }], null, [stillStub]);
  assert.deepEqual(restarted.handoffIds(), []);
  assert.deepEqual(restarted.compactionAccount().released, []);
  assert.equal(restarted.releasedAt("p:a"), 4);
  // A stub whose release turn is not known (no branch to count in) is still a release: null, not the load's turn.
  const unknownTurn = new SkillLedger();
  unknownTurn.restore([], null, [{ ...load("p:a", 1), entryId: "e1" }]);
  assert.equal(unknownTurn.releasedAt("p:a"), null);
});

// ---------------------------------------------------------------------------
// The unloader on a turn boundary
// ---------------------------------------------------------------------------

test("a finished body is replaced by a context_edit draft at the next turn boundary: the draft names the result, carries the stub, and keeps what other drafts asked for", async () => {
  await withPacks(async (a, b) => {
    const seat = await directSeat([a, b], { release: "auto" });
    try {
      await seat.skill("evidence/one", "c1");
      await seat.endTurn();
      await seat.done("evidence/one", "took the run count", "c2");
      const earlier = { type: "custom", customType: "other-extension", data: { n: 1 } };
      const out = await seat.endTurn({ entries: [earlier] });
      assert.equal(out.entries!.length, 2);
      assert.deepEqual(out.entries![0], earlier, "a draft another handler returned is passed on, not dropped");
      const draft = out.entries![1]!;
      assert.equal(draft.type, "context_edit");
      assert.equal(draft.targetId, "e-c1", "the entry that holds the load's result");
      assert.equal(draft.replacement!.content.length, 1);
      assert.match(draft.replacement!.content[0]!.text, /^evidence\/one released \(\d+ tokens\)\. Re-load with skill\('evidence\/one'\)\.$/);
      const row = seat.rowsOf("skill_unload")[0]!;
      assert.deepEqual(
        { ok: row.result.ok, reason: row.result.reason, call: row.result.call, entry: row.result.entry, turn: row.result.turn, loaded_turn: row.result.loaded_turn, done_turn: row.result.done_turn, held_turns: row.result.held_turns, batch: row.result.batch, policy: row.result.policy, class: row.result.class },
        { ok: true, reason: "done", call: "c1", entry: "e-c1", turn: 2, loaded_turn: 1, done_turn: 2, held_turns: 1, batch: 1, policy: "auto", class: "open" },
      );
      assert.match(String(row.result.sha256), /^[0-9a-f]{64}$/);
      assert.equal(row.result.tokens, seat.handle.ledger.releasedLoads()[0]!.tokens);
      assert.equal(seat.handle.ledger.get("pack-a:evidence/one"), undefined);
      // The next boundary has nothing left to release.
      assert.equal((await seat.endTurn()).entries, undefined);
      assert.equal(seat.rowsOf("skill_unload").length, 1);
      // skill(id) after the release delivers the body again and says it is the second.
      const again = await seat.skill("evidence/one", "c3");
      assert.match(again.text, /^Skill `evidence\/one`/);
      const reload = seat.rowsOf("skill").at(-1)!;
      assert.deepEqual([reload.result.reload_after_release, reload.result.released_turn, reload.result.call], [true, 2, "c3"]);
    } finally {
      await disposeSeat(seat);
    }
  });
});

test("two bodies finished in one turn leave in one return, a note the seat still works from stays, and a body finished in the turn it was loaded waits for the next boundary", async () => {
  await withPacks(async (a, b) => {
    const seat = await directSeat([a, b], { release: "auto" });
    try {
      await seat.skill("evidence/one", "c1");
      await seat.skill("evidence/two", "c2");
      await seat.skill("evidence/three", "c3");
      await seat.endTurn();
      await seat.done("evidence/one", "", "c4");
      await seat.done("evidence/two", "", "c5");
      const out = await seat.endTurn();
      assert.deepEqual(out.entries!.map((d) => d.targetId), ["e-c1", "e-c2"]);
      assert.deepEqual(seat.rowsOf("skill_unload").map((r) => r.result.batch), [2, 2]);
      assert.deepEqual(seat.handle.ledger.working().map((l) => l.id), ["evidence/three"], "the third note was never marked done and is held");
      // Loaded and finished in one turn: the model has not read it, so it waits.
      await seat.skill("evidence/four", "c6");
      await seat.done("evidence/four", "", "c7");
      assert.equal((await seat.endTurn()).entries, undefined);
      const next = await seat.endTurn();
      assert.deepEqual(next.entries!.map((d) => d.targetId), ["e-c6"]);
    } finally {
      await disposeSeat(seat);
    }
  });
});

test("never toggle: a body loaded again after its release is held until the next compaction, however often it is marked done", async () => {
  await withPacks(async (a, b) => {
    const seat = await directSeat([a, b], { release: "auto" });
    try {
      await seat.skill("evidence/one", "c1");
      await seat.endTurn();
      await seat.done("evidence/one", "", "c2");
      assert.equal((await seat.endTurn()).entries!.length, 1);
      await seat.skill("evidence/one", "c3");
      await seat.endTurn();
      await seat.done("evidence/one", "", "c4");
      assert.equal((await seat.endTurn()).entries, undefined, "the second copy is not released");
      assert.equal(seat.rowsOf("skill_unload").length, 1);
      assert.deepEqual(seat.handle.ledger.releasable().map((l) => l.toolCallId), ["c3"], "still held, still marked done");
    } finally {
      await disposeSeat(seat);
    }
  });
});

test("a model with signed thinking blocks gets no draft at a turn boundary; the finished body leaves in the turn the seat hands off in", async () => {
  await withPacks(async (a, b) => {
    const seat = await directSeat([a, b], { release: "auto" });
    try {
      await seat.skill("evidence/one", "c1");
      await seat.endTurn({ model: MODELS.claude });
      await seat.done("evidence/one", "", "c2");
      for (let i = 0; i < 3; i++) assert.equal((await seat.endTurn({ model: MODELS.claude })).entries, undefined, "no draft before the hand-off");
      assert.equal(seat.rowsOf("skill_unload").length, 0);
      const policy = seat.rowsOf("skill_release_policy");
      assert.equal(policy.length, 1, "one row for as long as the policy does not change");
      assert.deepEqual([policy[0]!.result.effective, policy[0]!.result.class, policy[0]!.result.api, policy[0]!.result.reasoning, policy[0]!.result.thinking_level, policy[0]!.result.model], ["compaction", "signed-thinking", "anthropic-messages", true, "medium", "anthropic/claude-fable-5-1"]);
      // The seat's self_compact came back: the compaction rewrites the prefix anyway.
      const out = await seat.endTurn({ model: MODELS.claude, handoff: true });
      assert.deepEqual(out.entries!.map((d) => d.targetId), ["e-c1"]);
      const row = seat.rowsOf("skill_unload")[0]!;
      assert.deepEqual([row.result.ok, row.result.reason, row.result.class], [true, "compaction", "signed-thinking"]);
    } finally {
      await disposeSeat(seat);
    }
  });
});

test("a hand-off that was refused, or that failed and was given up, is not a compaction: no release, and a body is not released twice by it", async () => {
  await withPacks(async (a, b) => {
    // The seat's self_compact was refused ("nothing to compact yet"): that turn is an ordinary one.
    const refused = await directSeat([a, b], { release: "compaction" });
    try {
      await refused.skill("evidence/one", "c1");
      await refused.endTurn({ model: MODELS.claude });
      await refused.done("evidence/one", "", "c2");
      assert.equal((await refused.endTurn({ model: MODELS.claude, handoff: "refused" })).entries, undefined);
    } finally {
      await disposeSeat(refused);
    }
    // self-compact still says pending (the note is kept after the retries are spent) but no self_compact came back this turn:
    // a seat that goes on working releases nothing, however long ago it handed off, and nothing toggles.
    const stuck = await directSeat([a, b], { release: "compaction", compactionPending: () => true });
    try {
      await stuck.skill("evidence/two", "c3");
      await stuck.endTurn({ model: MODELS.claude });
      await stuck.done("evidence/two", "", "c4");
      assert.equal((await stuck.endTurn({ model: MODELS.claude, handoff: true })).entries!.length, 1, "the turn the hand-off came back in");
      await stuck.skill("evidence/two", "c5");
      await stuck.endTurn({ model: MODELS.claude });
      await stuck.done("evidence/two", "", "c6");
      for (let i = 0; i < 3; i++) assert.equal((await stuck.endTurn({ model: MODELS.claude })).entries, undefined, "the compaction failed and the seat works on: no more releases");
      assert.equal(stuck.rowsOf("skill_unload").length, 1);
    } finally {
      await disposeSeat(stuck);
    }
    // And a self_compact result with the extension saying no hand-off is pending is not trusted either.
    const none = await directSeat([a, b], { release: "compaction", compactionPending: () => false });
    try {
      await none.skill("evidence/one", "c7");
      await none.endTurn();
      await none.done("evidence/one", "", "c8");
      assert.equal((await none.endTurn({ handoff: true })).entries, undefined);
    } finally {
      await disposeSeat(none);
    }
  });
});

test("a signed thinking block after the body keeps it, whatever model or thinking level the seat has now: a switch mid-run does not leave the block behind an edit", async () => {
  await withPacks(async (a, b) => {
    const seat = await directSeat([a, b], { release: "auto" });
    try {
      // A Claude seat loads a note, writes a reply with a signed thinking block, and the operator switches the seat to an open model.
      await seat.skill("evidence/one", "c1");
      seat.assistant({ api: "anthropic-messages", signed: true });
      await seat.endTurn({ model: MODELS.codex });
      await seat.done("evidence/one", "", "c2");
      seat.assistant({ api: "openai-completions" });
      assert.equal((await seat.endTurn({ model: MODELS.codex })).entries, undefined, "the model is open now; the block that stands after the body decides");
      assert.equal(seat.rowsOf("skill_unload").length, 0);
      // The same reply with its thinking block from a Responses model is an item tied to its own call: not signed over the history.
      await seat.skill("evidence/two", "c3");
      seat.assistant({ api: "openai-codex-responses", signed: true });
      await seat.endTurn({ model: MODELS.codex });
      await seat.done("evidence/two", "", "c4");
      const out = await seat.endTurn({ model: MODELS.codex });
      assert.deepEqual(out.entries!.map((d) => d.targetId), ["e-c3"]);
      // At the hand-off the history is replaced anyway: the held-back body goes then.
      const handoff = await seat.endTurn({ model: MODELS.codex, handoff: true });
      assert.deepEqual(handoff.entries!.map((d) => d.targetId), ["e-c1"]);
      // A Claude with thinking turned off is not an open model: the class does not read the level.
      const claudeOff = await directSeat([a, b], { release: "auto" });
      try {
        await claudeOff.skill("evidence/one", "d1");
        await claudeOff.endTurn({ model: MODELS.claude, thinkingLevel: "off" });
        await claudeOff.done("evidence/one", "", "d2");
        assert.equal((await claudeOff.endTurn({ model: MODELS.claude, thinkingLevel: "off" })).entries, undefined);
        assert.equal(claudeOff.rowsOf("skill_release_policy")[0]!.result.effective, "compaction");
      } finally {
        await disposeSeat(claudeOff);
      }
    } finally {
      await disposeSeat(seat);
    }
  });
});

test("a model switch is picked up at the next boundary, a row each time; an OpenRouter Claude and a local reasoning model are compaction-only", async () => {
  await withPacks(async (a, b) => {
    const seat = await directSeat([a, b], { release: "auto" });
    try {
      await seat.skill("evidence/one", "c1");
      await seat.endTurn({ model: MODELS.claude });
      await seat.done("evidence/one", "", "c2");
      assert.equal((await seat.endTurn({ model: MODELS.openrouterClaude })).entries, undefined);
      assert.equal((await seat.endTurn({ model: MODELS.localThinking })).entries, undefined);
      assert.equal((await seat.endTurn({ model: MODELS.codex })).entries!.length, 1, "no signed block stands after the body, and the model is on the allow-list");
      assert.deepEqual(seat.rowsOf("skill_release_policy").map((r) => [r.result.class, r.result.effective]), [["signed-thinking", "compaction"], ["unproven", "compaction"], ["unproven", "compaction"], ["open", "boundary"]]);
    } finally {
      await disposeSeat(seat);
    }
  });
});

test("a session that names no model is not guessed at: bodies wait for the compaction", async () => {
  await withPacks(async (a, b) => {
    const seat = await directSeat([a, b], { release: "auto" });
    try {
      await seat.skill("evidence/one", "c1");
      await seat.endTurn({ model: undefined });
      await seat.done("evidence/one", "", "c2");
      assert.equal((await seat.endTurn({ model: undefined })).entries, undefined);
      assert.deepEqual([seat.rowsOf("skill_release_policy")[0]!.result.class, seat.rowsOf("skill_release_policy")[0]!.result.model], ["unknown", null]);
    } finally {
      await disposeSeat(seat);
    }
  });
});

test("--skill-release: compaction (the default) releases when the seat hands off, on every model; auto adds the turn boundary; off releases nothing and shapes nothing; an unknown value is compaction, and the row says so", async () => {
  await withPacks(async (a, b) => {
    const scripted = async (release: string | undefined) => {
      const seat = await directSeat([a, b], release === undefined ? {} : { release });
      await seat.skill("evidence/one", "c1");
      await seat.endTurn();
      await seat.done("evidence/one", "", "c2");
      const atBoundary = await seat.endTurn();
      const atHandoff = await seat.endTurn({ handoff: true });
      return { seat, atBoundary, atHandoff };
    };
    for (const release of ["compaction", undefined, "sometimes"]) {
      const run = await scripted(release);
      try {
        assert.equal(run.atBoundary.entries, undefined, `${release}: nothing at an ordinary boundary, an open model too`);
        assert.deepEqual(run.atHandoff.entries!.map((d) => d.targetId), ["e-c1"], `${release}: the body leaves in the hand-off turn`);
        const row = run.seat.rowsOf("skill_release_policy")[0]!;
        assert.deepEqual([row.result.mode, row.result.effective], ["compaction", "compaction"]);
        assert.deepEqual([row.result.ok, row.result.requested], release === "sometimes" ? [false, "sometimes"] : [true, undefined], "an unknown value is said on the row, and runs as the default");
      } finally {
        await disposeSeat(run.seat);
      }
    }
    const auto = await scripted("auto");
    try {
      assert.equal(auto.atBoundary.entries!.length, 1, "auto: the open model's body leaves at the boundary");
      assert.equal(auto.atHandoff.entries, undefined, "and the hand-off finds nothing left");
    } finally {
      await disposeSeat(auto.seat);
    }
    const off = await scripted("off");
    try {
      assert.equal(off.atBoundary.entries, undefined);
      assert.equal(off.atHandoff.entries, undefined);
      assert.equal(off.seat.rowsOf("skill_unload").length, 0);
      assert.equal(off.seat.rowsOf("skill_release_policy")[0]!.result.effective, "off");
      const input = off.seat.handle.summaryInput([{ role: "toolResult", toolName: "skill", details: loadDetails("evidence/one", "pack-a", 1), content: [{ type: "text", text: BODY_ONE }] }], []);
      assert.equal(input.block, "");
      assert.equal(JSON.stringify(input.history).includes(BODY_ONE), true, "off leaves the summary input as Pi serialises it");
      assert.equal(off.seat.handle.handoffLine(), "");
    } finally {
      await disposeSeat(off.seat);
    }
  });
});

test("an error or an abort ends a turn without a release; a release is aimed only at a result the session shows in the context", async () => {
  await withPacks(async (a, b) => {
    const seat = await directSeat([a, b], { release: "auto" });
    try {
      await seat.skill("evidence/one", "c1");
      await seat.endTurn();
      await seat.done("evidence/one", "", "c2");
      assert.equal((await seat.endTurn({ outcome: "error" })).entries, undefined);
      assert.equal((await seat.endTurn({ outcome: "aborted" })).entries, undefined);
      // The ledger holds a body the session no longer has (a compaction took it): no draft, a row that says so, and the ledger lets go.
      seat.session.context = seat.session.context.filter((e) => (e as { id?: string }).id !== "e-c1");
      assert.equal((await seat.endTurn()).entries, undefined);
      const row = seat.rowsOf("skill_unload")[0]!;
      assert.deepEqual([row.result.ok, row.result.error, row.result.call], [false, "not in the context", "c1"]);
      assert.equal(seat.handle.ledger.get("pack-a:evidence/one"), undefined);
      assert.equal(seat.handle.ledger.releasedAt("pack-a:evidence/one"), undefined, "it was not released by anyone");
    } finally {
      await disposeSeat(seat);
    }
  });
});

test("a release Pi did not commit is found at the next boundary: the body is held again, the trace says the edit did not land, and it is not tried again", async () => {
  await withPacks(async (a, b) => {
    const seat = await directSeat([a, b], { release: "auto" });
    try {
      await seat.skill("evidence/one", "c1");
      await seat.endTurn();
      await seat.done("evidence/one", "", "c2");
      const first = await seat.endTurn({ commit: false });
      assert.equal(first.entries!.length, 1, "the draft was returned");
      assert.equal(seat.handle.ledger.get("pack-a:evidence/one"), undefined, "and the ledger believes it for now");
      assert.equal((await seat.endTurn()).entries, undefined, "the next boundary looks, finds no edit, and does not try the same body again");
      const rows = seat.rowsOf("skill_unload");
      assert.deepEqual(rows.map((r) => [r.result.ok, r.result.error ?? null]), [[true, null], [false, "the edit was not committed; the body is still in the context"]]);
      assert.equal(seat.handle.ledger.get("pack-a:evidence/one")?.done !== undefined, true, "held again, still marked done");
      assert.equal(seat.handle.ledger.releasedAt("pack-a:evidence/one"), undefined);
      assert.equal((await seat.endTurn()).entries, undefined);
      assert.equal(seat.rowsOf("skill_unload").length, 2, "no third attempt");
    } finally {
      await disposeSeat(seat);
    }
  });
});

test("a note two packs carry is named pack:id in its stub, and the stub's way back reaches that one", async () => {
  await withPacks(async (a, b) => {
    const seat = await directSeat([a, b], { release: "auto" });
    try {
      await seat.skill("pack-b:shared/dup", "c1");
      await seat.endTurn();
      await seat.done("pack-b:shared/dup", "", "c2");
      const out = await seat.endTurn();
      assert.match(out.entries![0]!.replacement!.content[0]!.text, /^pack-b:shared\/dup released \(\d+ tokens\)\. Re-load with skill\('pack-b:shared\/dup'\)\.$/);
      const back = await seat.skill("pack-b:shared/dup", "c3");
      assert.match(back.text, /^Skill `shared\/dup` \(pack pack-b/);
    } finally {
      await disposeSeat(seat);
    }
  });
});

test("skill_done for a note never loaded is refused and says so; for one the harness already released it says that instead", async () => {
  await withPacks(async (a, b) => {
    const seat = await directSeat([a, b], { release: "auto" });
    try {
      const unknown = await seat.done("no/such/note");
      assert.match(unknown.text, /^`no\/such\/note` is not among the notes you have loaded/);
      assert.deepEqual([seat.rowsOf("skill_done")[0]!.result.ok, seat.rowsOf("skill_done")[0]!.result.error, seat.rowsOf("skill_done")[0]!.result.released], [false, "not loaded", undefined]);
      await seat.skill("evidence/one", "c1");
      await seat.endTurn();
      await seat.done("evidence/one", "", "c2");
      await seat.endTurn();
      const again = await seat.done("evidence/one");
      assert.match(again.text, /^`evidence\/one` was already marked done and has been released from your context \(a one-line stub stands in its place\); skill\("evidence\/one"\) loads it again\./);
      assert.deepEqual([seat.rowsOf("skill_done").at(-1)!.result.ok, seat.rowsOf("skill_done").at(-1)!.result.released], [false, true]);
    } finally {
      await disposeSeat(seat);
    }
  });
});

// ---------------------------------------------------------------------------
// The compaction
// ---------------------------------------------------------------------------

test("a compaction rebuilds the ledger from a session that holds stubs: the released body is not counted as held or as lost, and the row names the stubs", async () => {
  await withPacks(async (a, b) => {
    const seat = await directSeat([a, b], { release: "auto" });
    try {
      await seat.skill("evidence/one", "c1");
      await seat.skill("evidence/two", "c2");
      await seat.endTurn();
      await seat.done("evidence/one", "", "c3");
      await seat.endTurn();
      assert.equal(seat.session.context.some((e) => e.type === "context_edit"), true, "the release is in the simulated session");
      // The compaction kept the newest part: the second note's result and everything after it.
      seat.session.context = [{ type: "compaction", id: "k", firstKeptEntryId: "e-c1" }, ...seat.session.context];
      await seat.fire("session_compact", { compactionEntry: { id: "k" } });
      const row = seat.rowsOf("skills_compacted")[0]!;
      assert.deepEqual((row.result.kept as Array<{ key: string }>).map((x) => x.key), ["pack-a:evidence/two"]);
      assert.deepEqual(row.result.lost, []);
      assert.deepEqual((row.result.released as Array<{ key: string }>).map((x) => x.key), ["pack-a:evidence/one"]);
      // The released body is not held after the compaction either: the next call delivers it, and says it is the second.
      const again = await seat.skill("evidence/one");
      assert.match(again.text, /^Skill `evidence\/one`/);
      assert.equal(seat.rowsOf("skill").at(-1)!.result.reload_after_release, true, "its stub is still in the kept tail, so it is still this epoch's release");
      assert.match((await seat.skill("evidence/two")).text, /already in your context/);
    } finally {
      await disposeSeat(seat);
    }
  });
});

test("a process that starts on a session with a stub in it knows the body is not held, and in which turn it was released", async () => {
  await withPacks(async (a, b) => {
    const first = await directSeat([a, b], { release: "auto" });
    let session = { context: [] as Array<Record<string, unknown>>, branch: [] as Array<Record<string, unknown>> };
    let releasedIn: unknown;
    try {
      await first.skill("evidence/one", "c1");
      await first.endTurn();
      await first.done("evidence/one", "", "c2");
      await first.endTurn();
      await first.endTurn();
      session = first.session;
      releasedIn = first.rowsOf("skill_unload")[0]!.result.turn;
    } finally {
      await disposeSeat(first);
    }
    assert.equal(releasedIn, 2);
    const seat = await directSeat([a, b], { release: "auto" });
    try {
      seat.session.context = session.context;
      seat.session.branch = session.branch;
      await seat.fire("session_start", { reason: "startup" });
      assert.match((await seat.skill("evidence/one", "c9")).text, /^Skill `evidence\/one`/, "the stub is not the body: it is delivered");
      const row = seat.rowsOf("skill").at(-1)!;
      assert.equal(row.result.reload_after_release, true);
      assert.equal(row.result.released_turn, 2, "the turn of the release, counted on the branch, not the turn the note was loaded in");
    } finally {
      await disposeSeat(seat);
    }
  });
});

const messageOf = (callId: string, id: string, turn: number, text: string, tokens = 40) => ({
  role: "toolResult",
  toolName: "skill",
  toolCallId: callId,
  details: { ok: true, id, pack: "pack-a", turn, tokens, sha256: "c".repeat(64) },
  content: [{ type: "text", text }],
});
const doneMessage = (id: string, turn: number) => ({ role: "toolResult", toolName: "skill_done", toolCallId: `d-${id}`, details: { ok: true, id, pack: "pack-a", turn }, content: [{ type: "text", text: "Recorded" }] });

test("the summary is written from ids and sizes: a body is one line naming the note, a stub stays a stub, the block lists what was read and what is probably still needed", () => {
  const stub = stubText("evidence/one", 41);
  const original = [
    messageOf("c1", "evidence/one", 1, stub),
    messageOf("c2", "evidence/two", 2, "Second body, short."),
    { role: "toolResult", toolName: "skill", toolCallId: "ci", details: { ok: true, index: true, turn: 3 }, content: [{ type: "text", text: "pack-a 1.2.0 (5 skills)\n- `evidence/one` ..." }] },
    { role: "toolResult", toolName: "skill", toolCallId: "cf", details: { ok: false, error: "no such skill" }, content: [{ type: "text", text: "No skill x." }] },
    { role: "toolResult", toolName: "skill", toolCallId: "ca", details: { ok: true, already_loaded: true }, content: [{ type: "text", text: "already in your context" }] },
    doneMessage("evidence/one", 4),
    { role: "toolResult", toolName: "bash", content: [{ type: "text", text: "Second body, short. is a string a command printed" }] },
  ];
  const before = JSON.stringify(original);
  const shaped = shapeForSummary(original);
  assert.equal(JSON.stringify(original), before, "the messages are not changed in place: the session keeps the whole result");
  const text = (m: unknown) => ((m as { content: Array<{ text: string }> }).content[0]!.text);
  assert.equal(text(shaped.messages[0]), stub);
  assert.equal(text(shaped.messages[1]), "[note pack-a:evidence/two: 40 tokens, read at turn 2; its text is not part of this summary input]");
  assert.equal(text(shaped.messages[2]), "[the skill index was listed at turn 3; it is not part of this summary input]");
  assert.equal(text(shaped.messages[3]), "No skill x.", "a miss is left: it names the ids that did not exist");
  assert.equal(text(shaped.messages[4]), "already in your context");
  assert.match(text(shaped.messages[6]), /Second body, short\./, "a command's output is not a note");
  assert.deepEqual(shaped.reads.map((r) => [r.key, r.tokens, r.turn, r.done, r.released]), [["pack-a:evidence/one", 40, 1, true, true], ["pack-a:evidence/two", 40, 2, false, false]]);
  const block = renderSkillsRead(shaped.reads);
  assert.equal(
    block,
    [
      "<skills-read>",
      "Method notes this agent read in the conversation above. Only their ids and sizes are here, never their text:",
      "- pack-a:evidence/one: 40 tokens, read at turn 1, marked done and released from its context",
      "- pack-a:evidence/two: 40 tokens, read at turn 2, not marked done",
      "Not marked done (probably still needed after the compaction): pack-a:evidence/two.",
      "</skills-read>",
    ].join("\n"),
  );
  assert.equal(renderSkillsRead([]), "");
  // A done that follows an unreleased body marks it; the body is a line either way.
  const marked = shapeForSummary([messageOf("c5", "evidence/two", 2, "Second body, short."), doneMessage("evidence/two", 3)]);
  assert.deepEqual(marked.reads.map((r) => [r.done, r.released]), [[true, false]]);
});

test("the seat's summary input is shaped through its handle: the history and the turn prefix both, the done mark found across them", async () => {
  await withPacks(async (a, b) => {
    const seat = await directSeat([a, b], { release: "auto" });
    try {
      const history = [messageOf("c1", "evidence/one", 1, BODY_ONE)];
      const prefix = [doneMessage("evidence/one", 2), messageOf("c2", "evidence/two", 3, "Second body, short.")];
      const shaped = seat.handle.summaryInput(history, prefix);
      assert.equal(JSON.stringify(shaped).includes(BODY_ONE), false);
      assert.equal(JSON.stringify(shaped).includes("Second body, short."), false);
      assert.equal(shaped.history.length, 1);
      assert.equal(shaped.turnPrefix.length, 2);
      assert.match(shaped.block, /pack-a:evidence\/one: 40 tokens, read at turn 1, marked done\n/);
      assert.match(shaped.block, /pack-a:evidence\/two: 40 tokens, read at turn 3, not marked done/);
    } finally {
      await disposeSeat(seat);
    }
  });
});

test("the hand-off header lists what the seat read: sizes, which it marked done, which were released earlier, which are probably still needed; never a body", async () => {
  const account = {
    lost: [{ ...load("pack-a:evidence/two", 2), tokens: 480 }, { ...load("pack-a:evidence/three", 3, 4), tokens: 300 }],
    kept: [{ ...load("pack-b:other/x", 6, 7), tokens: 90 }],
    released: [{ ...load("pack-a:evidence/one", 1, 2), tokens: 520, releasedTurn: 2, reason: "done" }],
  };
  const line = renderHandoffReads(account);
  assert.equal(
    line,
    "Method notes you read since your last compaction, with their size in tokens (never their text): pack-a:evidence/two 480 (taken out of your context, not marked done), pack-a:evidence/three 300 (taken out of your context, marked done), pack-a:evidence/one 520 (marked done, released earlier), pack-b:other/x 90 (marked done; still in your context).\n" +
      "Load again (skill(id)) the ones you still need; not marked done, so probably still needed: pack-a:evidence/two.",
  );
  assert.equal(renderHandoffReads({ lost: [], kept: [load("p:a", 1)], released: [] }), "", "nothing was taken out or released: nothing to add");
  assert.equal(renderHandoffReads({ lost: [load("p:a", 1, 2)], kept: [], released: [] }).includes("probably still needed"), false);

  await withPacks(async (a, b) => {
    const seat = await directSeat([a, b], { release: "auto" });
    try {
      await seat.skill("evidence/one", "c1");
      await seat.skill("evidence/two", "c2");
      await seat.endTurn();
      await seat.done("evidence/one", "", "c3");
      await seat.endTurn();
      seat.session.context = [{ type: "compaction", id: "k", firstKeptEntryId: null }];
      await seat.fire("session_compact", {});
      const header = seat.handle.handoffLine();
      assert.equal(
        header.replace(/ \d+ \(/g, " N ("),
        "Method notes you read since your last compaction, with their size in tokens (never their text): pack-a:evidence/two N (taken out of your context, not marked done), pack-a:evidence/one N (marked done, released earlier).\n" +
          "Load again (skill(id)) the ones you still need; not marked done, so probably still needed: pack-a:evidence/two.",
      );
      assert.equal(header.split("pack-a:evidence/two").length - 1, 2, "a note is named in the account and once more as the one probably still needed, not in a third sentence");
      assert.equal(header.includes(BODY_ONE) || header.includes("Second body"), false, "ids and sizes only");
    } finally {
      await disposeSeat(seat);
    }
  });
});

test("the harness's own release events are reserved against forged tools", () => {
  for (const name of ["skill_unload", "skill_release_policy", "skill_release_effect"]) assert.ok(TOOL_RESERVED_NAMES.has(name), `${name} is reserved`);
});

test("a batch's cost is its largest suffix, not their sum; the suffix counts the reasoning that is sent again", async () => {
  await withPacks(async (a, b) => {
    const seat = await directSeat([a, b], { release: "auto" });
    try {
      await seat.skill("evidence/one", "c1");
      await seat.skill("evidence/two", "c2");
      await seat.endTurn();
      await seat.done("evidence/one", "", "c3");
      await seat.done("evidence/two", "", "c4");
      // The projected context as Pi hands it to the boundary: the first result, then the second, then a reply with an encrypted reasoning item.
      const projected = [
        { sourceEntry: { id: "e-c1" }, messages: [] },
        { sourceEntry: { id: "e-c2" }, messages: [{ role: "toolResult", content: [{ type: "text", text: "x".repeat(400) }] }] },
        { sourceEntry: { id: "r" }, messages: [{ role: "assistant", content: [{ type: "thinking", thinking: "", thinkingSignature: "E".repeat(800) }, { type: "text", text: "y".repeat(40) }] }] },
      ];
      await seat.endTurn({ contextEntries: projected });
      const rows = seat.rowsOf("skill_unload");
      assert.deepEqual(rows.map((r) => r.result.suffix_tokens), [Math.ceil((400 + 800 + 40) / 4), Math.ceil((800 + 40) / 4)], "the first body's suffix includes the second's result; the encrypted reasoning counts");
      assert.deepEqual(rows.map((r) => r.result.batch_suffix_tokens), [310, 310], "both rows carry the batch's cost once: the largest suffix");
    } finally {
      await disposeSeat(seat);
    }
  });
});

test("the first Anthropic reply after a release or a compaction is read for the thinking blocks the service dropped; other transports have nothing to report", async () => {
  await withPacks(async (a, b) => {
    const seat = await directSeat([a, b], { release: "auto" });
    try {
      const reply = (api: string, dropped: number) => ({
        message: {
          role: "assistant",
          api,
          model: "claude-fable-5-1",
          diagnostics: dropped ? [{ type: "anthropic_input_transformations", details: { transformations: Array.from({ length: dropped }, () => ({ type: "thinking_dropped" })).concat([{ type: "something_else" } as never]) } }] : [],
        },
      });
      // Nothing was released yet: a reply is not watched.
      await seat.fire("message_end", reply("anthropic-messages", 3));
      assert.equal(seat.rowsOf("skill_release_effect").length, 0);
      await seat.skill("evidence/one", "c1");
      await seat.endTurn();
      await seat.done("evidence/one", "", "c2");
      await seat.endTurn();
      await seat.fire("message_end", { message: { role: "user" } });
      await seat.fire("message_end", reply("anthropic-messages", 2));
      await seat.fire("message_end", reply("anthropic-messages", 5));
      const rows = seat.rowsOf("skill_release_effect");
      assert.equal(rows.length, 1, "the first reply only");
      assert.deepEqual([rows[0]!.result.after, rows[0]!.result.thinking_dropped, rows[0]!.result.turn, rows[0]!.result.model], ["release", 2, 2, "claude-fable-5-1"]);
      // After a compaction, the same.
      seat.session.context = [{ type: "compaction", id: "k", firstKeptEntryId: null }];
      await seat.fire("session_compact", {});
      await seat.fire("message_end", reply("anthropic-messages", 0));
      assert.deepEqual(seat.rowsOf("skill_release_effect").map((r) => [r.result.after, r.result.thinking_dropped]), [["release", 2], ["compaction", 0]]);
      // A reply on a transport that does not report it writes nothing.
      await seat.skill("evidence/two", "c3");
      await seat.endTurn();
      await seat.done("evidence/two", "", "c4");
      await seat.endTurn();
      await seat.fire("message_end", reply("openai-codex-responses", 0));
      assert.equal(seat.rowsOf("skill_release_effect").length, 2);
      assert.equal(countDroppedThinkingBlocks(reply("anthropic-messages", 4).message), 4);
      assert.equal(countDroppedThinkingBlocks({}), 0);
    } finally {
      await disposeSeat(seat);
    }
  });
});

test("a release Pi did not commit at the hand-off boundary is taken back too: the compaction does not clear the doubt", async () => {
  await withPacks(async (a, b) => {
    const seat = await directSeat([a, b]);
    try {
      await seat.skill("evidence/one", "c1");
      await seat.endTurn();
      await seat.done("evidence/one", "", "c2");
      const out = await seat.endTurn({ handoff: true, commit: false });
      assert.equal(out.entries!.length, 1, "the draft was returned");
      seat.session.context = [{ type: "compaction", id: "k", firstKeptEntryId: null }];
      await seat.fire("session_compact", {});
      const rows = seat.rowsOf("skill_unload");
      assert.deepEqual(rows.map((r) => [r.result.ok, r.result.call]), [[true, "c1"], [false, "c1"]], "the failed row names the call of the release it takes back");
      // The metrics read the pair as no release at all.
      const flat = rows.map((r, i) => ({ ts: `2026-10-07T10:00:0${i}.000Z`, agent: "agent00", tool: r.tool, args: r.args, result: r.result }));
      assert.equal(skillUse(flat, ["agent00"]).seats[0]!.released, 0);
    } finally {
      await disposeSeat(seat);
    }
  });
});

test("the summary input counts a note as done when the ledger knows it was marked in the kept tail", async () => {
  await withPacks(async (a, b) => {
    const seat = await directSeat([a, b]);
    try {
      await seat.skill("evidence/one", "c1");
      await seat.endTurn();
      await seat.done("evidence/one", "", "c2");
      // The compaction cuts after the load and before the done: the done is in the kept tail, outside the part being summarised.
      const summarised = [{ role: "toolResult", toolName: "skill", toolCallId: "c1", details: { ok: true, id: "evidence/one", pack: "pack-a", turn: 1, tokens: 41, sha256: "a".repeat(64) }, content: [{ type: "text", text: BODY_ONE }] }];
      const shaped = seat.handle.summaryInput(summarised, []);
      assert.match(shaped.block, /pack-a:evidence\/one: 41 tokens, read at turn 1, marked done\n/);
      assert.equal(shaped.block.includes("probably still needed"), false);
    } finally {
      await disposeSeat(seat);
    }
  });
});

// ---------------------------------------------------------------------------
// What Pi's own Anthropic transport sends after an edit (no network)
// ---------------------------------------------------------------------------

test("Pi's Anthropic request after a context_edit differs from the one before it in the edited tool result alone: every thinking block goes out as the provider signed it", async (t) => {
  // Pi's real conversion (pi-ai's anthropic-messages `stream`), stopped at `onPayload` before any request is made:
  // this is the half of "does an edit break the signed thinking blocks" that can be read without a provider.
  // Whether Anthropic's service accepts the history is the other half, and nobody has asked it (docs/packs.md).
  const piAi = join(REPO, "node_modules", "@earendil-works", "pi-coding-agent", "node_modules", "@earendil-works", "pi-ai", "dist");
  const transport = join(piAi, "api", "anthropic-messages.js");
  const catalogue = join(piAi, "providers", "data", "anthropic.json");
  if (!existsSync(transport) || !existsSync(catalogue)) {
    t.skip("Pi's Anthropic transport is not where the pinned package keeps it");
    return;
  }
  const { stream } = (await import(pathToFileURL(transport).href)) as { stream: (model: unknown, context: unknown, options: unknown) => AsyncIterable<unknown> & { result: () => Promise<unknown> } };
  const model = (JSON.parse(readFileSync(catalogue, "utf8")) as Record<string, Record<string, ModelFacts & { id: string }>>)["anthropic-messages"]!["claude-fable-5-1"]!;
  const sm = SessionManager.inMemory("/tmp/skill-unload-anthropic");
  const now = Date.now();
  const usage = { input: 1, output: 1, cacheRead: 0, cacheWrite: 0, totalTokens: 2, cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 } };
  const assistant = (blocks: unknown[]) => ({ role: "assistant", content: blocks, api: "anthropic-messages", provider: "anthropic", model: model.id, usage, stopReason: "toolUse", timestamp: now });
  const append = (m: unknown) => (sm as unknown as { appendMessage: (m: unknown) => string }).appendMessage(m);
  append({ role: "user", content: [{ type: "text", text: "go" }], timestamp: now });
  append(assistant([{ type: "thinking", thinking: "t0", thinkingSignature: "SIG0" }, { type: "toolCall", id: "toolu_1", name: "skill", arguments: { id: "a/b" } }]));
  const bodyId = append({ role: "toolResult", toolCallId: "toolu_1", toolName: "skill", content: [{ type: "text", text: "THE WHOLE SKILL BODY ".repeat(20) }], isError: false, timestamp: now });
  append(assistant([{ type: "thinking", thinking: "t1", thinkingSignature: "SIG1" }, { type: "toolCall", id: "toolu_2", name: "skill_done", arguments: { id: "a/b" } }]));
  append({ role: "toolResult", toolCallId: "toolu_2", toolName: "skill_done", content: [{ type: "text", text: "Recorded" }], isError: false, timestamp: now });
  append(assistant([{ type: "thinking", thinking: "t2", thinkingSignature: "SIG2" }, { type: "toolCall", id: "toolu_3", name: "bash", arguments: { command: "ls" } }]));
  append({ role: "toolResult", toolCallId: "toolu_3", toolName: "bash", content: [{ type: "text", text: "files" }], isError: false, timestamp: now });

  type Block = { type: string; signature?: string; thinking?: string; content?: unknown; cache_control?: unknown };
  type Payload = { messages: Array<{ role: string; content: Block[] | string }> };
  const payload = async (): Promise<Payload> => {
    let captured: Payload | undefined;
    const s = stream(model, { messages: convertToLlm(sm.buildSessionProjection().messages), tools: [] }, {
      apiKey: "not-a-real-key",
      onPayload: (p: unknown) => {
        captured = JSON.parse(JSON.stringify(p)) as Payload;
        throw new Error("stopped before the network");
      },
    });
    try {
      for await (const _ of s) void _;
    } catch {
      // the stop above
    }
    await s.result().catch(() => undefined);
    assert.ok(captured, "Pi built the request");
    return captured!;
  };
  const before = await payload();
  (sm as unknown as { appendContextEdit: (id: string, r: unknown) => string }).appendContextEdit(bodyId, { content: [{ type: "text", text: "a/b released (84 tokens). Re-load with skill('a/b')." }] });
  const after = await payload();

  assert.equal(after.messages.length, before.messages.length);
  const differing = before.messages.map((m, i) => (JSON.stringify(m) === JSON.stringify(after.messages[i]) ? -1 : i)).filter((i) => i >= 0);
  assert.deepEqual(differing, [2], "only the message that holds the edited tool result differs");
  const thinking = (p: Payload) => p.messages.flatMap((m) => (Array.isArray(m.content) ? m.content.filter((c) => c.type === "thinking") : []));
  assert.deepEqual(thinking(after).map((c) => [c.thinking, c.signature]), [["t0", "SIG0"], ["t1", "SIG1"], ["t2", "SIG2"]]);
  assert.deepEqual(thinking(after), thinking(before), "the signed blocks are byte-identical before and after");
  const edited = after.messages[2]!.content as Block[];
  assert.equal(edited[0]!.type, "tool_result");
  assert.match(JSON.stringify(edited[0]!.content), /a\/b released \(84 tokens\)\. Re-load with skill\('a\/b'\)\./);
  assert.equal(JSON.stringify(before.messages[2]).includes("THE WHOLE SKILL BODY"), true);
  assert.equal(JSON.stringify(after).includes("THE WHOLE SKILL BODY"), false, "the body is not in what the provider is sent");
});

test("Pi's OpenAI Responses request after a context_edit differs in the edited function_call_output alone: every reasoning item goes out as the provider wrote it", async (t) => {
  // The Responses conversion is shared with the Codex transport (openai-responses-shared.js), which the team's runs use.
  const piAi = join(REPO, "node_modules", "@earendil-works", "pi-coding-agent", "node_modules", "@earendil-works", "pi-ai", "dist");
  const transport = join(piAi, "api", "openai-responses.js");
  const catalogue = join(piAi, "providers", "data", "openai.json");
  if (!existsSync(transport) || !existsSync(catalogue)) {
    t.skip("Pi's OpenAI Responses transport is not where the pinned package keeps it");
    return;
  }
  const { stream } = (await import(pathToFileURL(transport).href)) as { stream: (model: unknown, context: unknown, options: unknown) => AsyncIterable<unknown> & { result: () => Promise<unknown> } };
  const model = (JSON.parse(readFileSync(catalogue, "utf8")) as Record<string, Record<string, ModelFacts & { id: string }>>)["openai-responses"]!["gpt-5.5"]!;
  const sm = SessionManager.inMemory("/tmp/skill-unload-responses");
  const now = Date.now();
  const usage = { input: 1, output: 1, cacheRead: 0, cacheWrite: 0, totalTokens: 2, cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 } };
  const assistant = (blocks: unknown[]) => ({ role: "assistant", content: blocks, api: model.api, provider: model.provider, model: model.id, usage, stopReason: "toolUse", timestamp: now });
  const reasoning = (n: number) => JSON.stringify({ type: "reasoning", id: `rs_${n}`, summary: [], encrypted_content: `ENC${n}` });
  const append = (m: unknown) => (sm as unknown as { appendMessage: (m: unknown) => string }).appendMessage(m);
  append({ role: "user", content: [{ type: "text", text: "go" }], timestamp: now });
  append(assistant([{ type: "thinking", thinking: "", thinkingSignature: reasoning(0) }, { type: "toolCall", id: "call_1|fc_1", name: "skill", arguments: { id: "a/b" } }]));
  const bodyId = append({ role: "toolResult", toolCallId: "call_1|fc_1", toolName: "skill", content: [{ type: "text", text: "THE WHOLE SKILL BODY ".repeat(20) }], isError: false, timestamp: now });
  append(assistant([{ type: "thinking", thinking: "", thinkingSignature: reasoning(1) }, { type: "toolCall", id: "call_2|fc_2", name: "skill_done", arguments: { id: "a/b" } }]));
  append({ role: "toolResult", toolCallId: "call_2|fc_2", toolName: "skill_done", content: [{ type: "text", text: "Recorded" }], isError: false, timestamp: now });

  type Item = { type?: string; role?: string; id?: string; encrypted_content?: string; call_id?: string; output?: unknown };
  const payload = async (): Promise<{ input: Item[] }> => {
    let captured: { input: Item[] } | undefined;
    const s = stream(model, { messages: convertToLlm(sm.buildSessionProjection().messages), tools: [] }, {
      apiKey: "not-a-real-key",
      onPayload: (p: unknown) => {
        captured = JSON.parse(JSON.stringify(p)) as { input: Item[] };
        throw new Error("stopped before the network");
      },
    });
    try {
      for await (const _ of s) void _;
    } catch {
      // the stop above
    }
    await s.result().catch(() => undefined);
    assert.ok(captured, "Pi built the request");
    return captured!;
  };
  const before = await payload();
  (sm as unknown as { appendContextEdit: (id: string, r: unknown) => string }).appendContextEdit(bodyId, { content: [{ type: "text", text: "a/b released (84 tokens). Re-load with skill('a/b')." }] });
  const after = await payload();
  assert.equal(after.input.length, before.input.length);
  const differing = before.input.map((x, i) => (JSON.stringify(x) === JSON.stringify(after.input[i]) ? -1 : i)).filter((i) => i >= 0);
  assert.equal(differing.length, 1);
  assert.equal(after.input[differing[0]!]!.type, "function_call_output");
  assert.equal(after.input[differing[0]!]!.call_id, "call_1");
  assert.match(JSON.stringify(after.input[differing[0]!]!.output), /a\/b released \(84 tokens\)/);
  assert.deepEqual(after.input.filter((x) => x.type === "reasoning").map((x) => [x.id, x.encrypted_content]), [["rs_0", "ENC0"], ["rs_1", "ENC1"]]);
  assert.equal(JSON.stringify(after).includes("THE WHOLE SKILL BODY"), false);
});
