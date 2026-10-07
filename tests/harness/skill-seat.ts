/**
 * A seat's skill tools and hooks, driven without Pi's loop: extensions/skills.ts
 * registered on a fake `pi` that keeps its handlers and tools, with the session
 * Pi would hold simulated beside it (a tool result becomes a session entry, the
 * drafts a turn boundary returns become `context_edit` entries), so the unloader
 * can be read decision by decision. What Pi then does with the drafts is the
 * end-to-end suite's (tests/skill-unload-e2e.test.ts, through the real CLI).
 */
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { initSandbox } from "../../extensions/protocol.ts";
import { registerSkills, type ModelFacts, type SkillsHandle } from "../../extensions/skills.ts";

type Handler = (event: unknown, ctx: unknown) => Promise<unknown>;
type ToolDef = { execute: (...args: unknown[]) => Promise<{ content: Array<{ text: string }>; details: Record<string, unknown> }> };
export type Row = { tool: string; args: Record<string, unknown>; result: Record<string, unknown> };
export type Draft = { type: string; targetId: string; replacement: { content: Array<{ type: string; text: string }> } | null };

/** The catalogue entries the policy tests use: what Pi 0.87.1's data says of three models, by the fields the policy reads. */
export const MODELS: Record<string, ModelFacts> = {
  claude: { api: "anthropic-messages", provider: "anthropic", id: "claude-fable-5-1", reasoning: true },
  claudeNoThink: { api: "anthropic-messages", provider: "anthropic", id: "claude-haiku-x", reasoning: false },
  codex: { api: "openai-codex-responses", provider: "openai-codex", id: "gpt-6-sol", reasoning: true },
  local: { api: "openai-completions", provider: "llama.cpp", id: "qwen", reasoning: false },
  localThinking: { api: "openai-completions", provider: "llama.cpp", id: "qwen-thinking", reasoning: true },
  openrouterClaude: { api: "openai-completions", provider: "openrouter", id: "anthropic/claude-fable-5.1:batch", reasoning: true },
};

export type DirectSeat = {
  root: string;
  handle: SkillsHandle;
  rows: Row[];
  /** The entries Pi would hold, in order: `branch` is the whole session (getBranch()), `context` what buildContextEntries() returns (a test that plays a compaction replaces it and leaves the branch). */
  session: { context: Array<Record<string, unknown>>; branch: Array<Record<string, unknown>> };
  turn: { n: number };
  /** What `compactionPending` answers, for a seat that wants it to say no (a hand-off that is over). */
  compacting: { on: boolean };
  /** An assistant message entry in the session: the api that wrote it and whether it carries a signed thinking block. */
  assistant: (options?: { api?: string; signed?: boolean }) => void;
  /** A skill call (its result becomes a session entry). */
  skill: (id?: string, callId?: string) => Promise<{ text: string; details: Record<string, unknown> }>;
  done: (id: string, note?: string, callId?: string) => Promise<{ text: string; details: Record<string, unknown> }>;
  /** A turn ends: the turn counter moves, the `turn_end` handlers run, and the drafts they return are committed to the session. */
  endTurn: (options?: {
    model?: ModelFacts | undefined;
    thinkingLevel?: string;
    entries?: unknown[];
    outcome?: string;
    contextEntries?: unknown[];
    /** The turn's tool results: `self_compact` among them is the turn the seat handed off in. */
    handoff?: boolean | "refused";
    /** False: Pi does not commit the drafts (an older Pi, or a boundary another extension's invalid draft cancelled). */
    commit?: boolean;
  }) => Promise<{ entries: Draft[] | undefined }>;
  fire: (event: string, payload?: Record<string, unknown>) => Promise<unknown[]>;
  rowsOf: (tool: string) => Row[];
};

export async function directSeat(packDirs: string[], options: { release?: string; compactionPending?: () => boolean } = {}): Promise<DirectSeat> {
  const root = await mkdtemp(join(tmpdir(), "skill-unload-seat-"));
  await initSandbox(root, { reset: true });
  const handlers = new Map<string, Handler[]>();
  const tools = new Map<string, ToolDef>();
  const fake = {
    on: (event: string, h: Handler) => handlers.set(event, [...(handlers.get(event) ?? []), h]),
    registerTool: (def: ToolDef & { name: string }) => tools.set(def.name, def),
  };
  const rows: Row[] = [];
  const turn = { n: 0 };
  const compacting = { on: true };
  const session = { context: [] as Array<Record<string, unknown>>, branch: [] as Array<Record<string, unknown>> };
  const append = (entry: Record<string, unknown>) => {
    session.context.push(entry);
    session.branch.push(entry);
  };
  let counter = 0;
  const handle = registerSkills(fake as never, {
    packDirs,
    agentId: () => "agent00",
    trace: async (_cwd, tool, args, result) => void rows.push({ tool, args, result: result as Record<string, unknown> }),
    turns: () => turn.n,
    fault: async () => undefined,
    ...(options.release !== undefined ? { release: options.release } : {}),
    compactionPending: options.compactionPending ?? (() => compacting.on),
  });
  const ctxFor = (model: ModelFacts | undefined, thinkingLevel: string | undefined) => ({
    cwd: root,
    model,
    thinkingLevel,
    sessionManager: { buildContextEntries: () => session.context, getBranch: () => session.branch, getEntries: () => session.branch },
  });
  const entry = (callId: string, toolName: string, out: { text: string; details: Record<string, unknown> }) => {
    append({ type: "message", id: `e-${callId}`, message: { role: "toolResult", toolName, toolCallId: callId, details: out.details, content: [{ type: "text", text: out.text }] } });
  };
  const call = async (name: string, params: Record<string, unknown>, callId: string) => {
    const out = await tools.get(name)!.execute(callId, params, undefined, undefined, ctxFor(undefined, undefined));
    const result = { text: out.content.map((c) => c.text).join(""), details: out.details };
    entry(callId, name, result);
    return result;
  };
  const fire = async (event: string, payload: Record<string, unknown> = {}, ctx = ctxFor(undefined, undefined)) => {
    const outs: unknown[] = [];
    for (const h of handlers.get(event) ?? []) outs.push(await h({ type: event, ...payload }, ctx));
    return outs;
  };
  return {
    root,
    handle,
    rows,
    session,
    turn,
    compacting,
    assistant: (opts = {}) => {
      append({
        type: "message",
        id: `a-${++counter}`,
        message: { role: "assistant", api: opts.api ?? "openai-completions", content: [...(opts.signed ? [{ type: "thinking", thinking: "t", thinkingSignature: "SIG" }] : []), { type: "text", text: "ok" }] },
      });
    },
    skill: (id, callId) => call("skill", id === undefined ? {} : { id }, callId ?? `c${++counter}`),
    done: (id, note, callId) => call("skill_done", note === undefined ? { id } : { id, note }, callId ?? `c${++counter}`),
    endTurn: async (opts = {}) => {
      turn.n += 1;
      const model = "model" in opts ? opts.model : MODELS.codex;
      // The turn's assistant message is in the session before its turn_end (unsigned: a test that wants a signed one adds it first).
      append({ type: "message", id: `a-${++counter}`, message: { role: "assistant", api: model?.api ?? "none", content: [{ type: "text", text: "ok" }] } });
      const ctx = ctxFor(model, opts.thinkingLevel ?? "medium");
      const toolResults = opts.handoff ? [{ role: "toolResult", toolName: "self_compact", isError: opts.handoff === "refused" }] : [];
      const event = { type: "turn_end", entries: opts.entries ?? [], outcome: opts.outcome ?? "completed", toolResults, ...(opts.contextEntries ? { context: { contextEntries: opts.contextEntries } } : {}) };
      let result: { entries?: Draft[] } | undefined;
      for (const h of handlers.get("turn_end") ?? []) {
        const out = (await h(event, ctx)) as { entries?: Draft[] } | undefined;
        if (out?.entries) {
          result = out;
          event.entries = out.entries;
        }
      }
      // Pi commits the drafts before it builds the next request.
      for (const draft of opts.commit === false ? [] : (result?.entries ?? [])) {
        if (draft.type === "context_edit") append({ type: "context_edit", id: `edit-${++counter}`, targetId: draft.targetId, replacement: draft.replacement });
      }
      return { entries: result?.entries };
    },
    fire,
    rowsOf: (tool) => rows.filter((r) => r.tool === tool),
  };
}

export async function disposeSeat(seat: DirectSeat): Promise<void> {
  await rm(seat.root, { recursive: true, force: true });
}
