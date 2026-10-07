/**
 * Test-only Pi extension: a scripted provider "fake" with one model,
 * "scripted", whose reported context usage grows by a fixed step per
 * assistant message. With it the self-compaction cycle can be driven through
 * the real CLI and the real swarm extension for nothing: the notice, the
 * warning, the lock, the hand-off, the compaction with our prompt, the note
 * coming back, and the work resuming.
 *
 * Adapted from the reference build's harness (disler/self-compact-pi-agent,
 * MIT). What changed is the script: it speaks the swarm's flow — the
 * hand-off arrives under a `[self-compact · handoff]` header, the result is
 * written into the agent's own scratch directory (no claim needed), and the
 * nudge the harness sends when a run ends at the line is answered.
 *
 * Environment:
 *   SC_FAKE_WINDOW       context window the model declares (default 200000)
 *   SC_FAKE_BASE         tokens reported on the first turn (default 5000)
 *   SC_FAKE_STEP         extra tokens per assistant message since the last hand-off (default 20000)
 *   SC_FAKE_SCENARIO     ignore-until-forced (default) | obey-warning | never-compact | wait-for-steer
 *                        (calls wait until a message saying STEER-TEST reaches it, then stops)
 *   SC_FAKE_BIG_STEP     1 makes the first scripted bash step print 140 KB (20,000 lines), past Pi's 50 KB bound
 *   SC_FAKE_NOTE         the note_to_self the script hands off with
 *   SC_FAKE_RESULT_PATH  the file the script writes after the hand-off (default work/agent00/result.txt)
 *   SC_FAKE_CYCLES       hand-offs to complete before writing the result (default 1)
 *   SC_FAKE_SUMMARY_FAIL summary calls that fail before one succeeds (default 0)
 *   SC_FAKE_SUMMARY_RUNAWAY summary calls, after the failing ones, that stream text without end
 *                        and ignore maxTokens until they are aborted, as the openai-codex API
 *                        let two summaries run on to 128,000 output tokens (default 0)
 *   SC_FAKE_SUMMARY_HANG summary calls, after those, that answer nothing until aborted (default 0)
 *   SC_FAKE_TRACE        JSONL file that records every model request
 *   SC_FAKE_PROMPTS      1 puts the whole system prompt of every model request on that trace
 *   SC_FAKE_PRE_STEPS    JSON array of {name, arguments}: tool calls made one per turn before the
 *                        filler steps and the hand-off (a seat meeting its packs' skills)
 *   SC_FAKE_AFTER_STEPS  the same, made after the hand-off, before the result is written
 */
import { appendFileSync } from "node:fs";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

const env = (key: string, fallback: string) => process.env[key] ?? fallback;
const WINDOW = Number(env("SC_FAKE_WINDOW", "200000"));
const BASE = Number(env("SC_FAKE_BASE", "5000"));
const STEP = Number(env("SC_FAKE_STEP", "20000"));
const SCENARIO = env("SC_FAKE_SCENARIO", "ignore-until-forced");
const RESULT_PATH = env("SC_FAKE_RESULT_PATH", "work/agent00/result.txt");
const CYCLES = Number(env("SC_FAKE_CYCLES", "1"));
const SUMMARY_FAIL = Number(env("SC_FAKE_SUMMARY_FAIL", "0"));
const SUMMARY_RUNAWAY = Number(env("SC_FAKE_SUMMARY_RUNAWAY", "0"));
const SUMMARY_HANG = Number(env("SC_FAKE_SUMMARY_HANG", "0"));
/** One chunk of a runaway summary; the harness's bound is 48,000 characters. */
const RUNAWAY_CHUNK = "- the same line again, as a looping summarizer writes it\n".repeat(80);
const TRACE = process.env.SC_FAKE_TRACE;
const PROMPTS = env("SC_FAKE_PROMPTS", "") === "1";
type ScriptedCall = { name: string; arguments: Record<string, unknown> };
/** A step is one tool call, or an array of them: one assistant message with several calls, which Pi runs at the same time. */
type ScriptedStep = ScriptedCall | ScriptedCall[];
const PRE_STEPS: ScriptedStep[] = JSON.parse(env("SC_FAKE_PRE_STEPS", "[]"));
const AFTER_STEPS: ScriptedStep[] = JSON.parse(env("SC_FAKE_AFTER_STEPS", "[]"));
const NOTE = env(
  "SC_FAKE_NOTE",
  [
    "NAME: scripted-worker · slice: prove the hand-off resumes real work.",
    "DONE: ran the scripted bash steps; nothing else is pending.",
    "LEDGER: none recorded.",
    "PEERS: none.",
    "DECISIONS: none.",
    `NEXT ACTION: write ${RESULT_PATH} containing exactly done, then reply "Task complete".`,
  ].join("\n"),
);

let summaryCalls = 0;
let stepCounter = 0;
let taskDone = false;
let handoffsSeen = 0;
let preIndex = 0;
let afterIndex = 0;

type Plan = {
  text?: string;
  toolCall?: { name: string; arguments: Record<string, unknown> };
  toolCalls?: Array<{ name: string; arguments: Record<string, unknown> }>;
  usageTotal: number;
  stopReason: "stop" | "toolUse";
};

function textOf(content: unknown): string {
  if (typeof content === "string") return content;
  if (Array.isArray(content)) {
    return content
      .map((block) => (block && typeof block === "object" && (block as { type?: string }).type === "text" ? String((block as { text?: string }).text ?? "") : ""))
      .join("\n");
  }
  return "";
}

function trace(record: Record<string, unknown>) {
  if (!TRACE) return;
  try {
    appendFileSync(TRACE, `${JSON.stringify({ at: Date.now(), ...record })}\n`);
  } catch {
    // a trace that cannot be written must not fail the run it records
  }
}

const BIG_STEP = env("SC_FAKE_BIG_STEP", "") === "1";

function fillerStep(usageTotal: number): Plan {
  stepCounter += 1;
  // One step past Pi's 50 KB bash bound, when asked: 20,000 lines of "filler",
  // 140,000 bytes, which Pi spills to the host's temp directory and the
  // harness moves into the sandbox's tool-output/.
  const command = BIG_STEP && stepCounter === 1 ? "yes filler | head -n 20000" : `printf 'step ${stepCounter} '; yes filler | head -n 400 | tr '\\n' ' '; echo`;
  return {
    toolCall: { name: "bash", arguments: { command } },
    usageTotal,
    stopReason: "toolUse",
  };
}

function scripted(list: ScriptedStep[], index: number, usageTotal: number): Plan {
  const step = list[index]!;
  return Array.isArray(step) ? { toolCalls: step, usageTotal, stopReason: "toolUse" } : { toolCall: step, usageTotal, stopReason: "toolUse" };
}

function handoffPlan(usageTotal: number): Plan {
  return { toolCall: { name: "self_compact", arguments: { note_to_self: NOTE } }, usageTotal, stopReason: "toolUse" };
}

type Msg = { role: string; content?: unknown; toolName?: string; isError?: boolean };

function decide(messages: Msg[]): Plan {
  // Context is fresh after each hand-off: count assistant messages since the last one.
  let lastHandoff = -1;
  messages.forEach((m, i) => {
    if (m.role === "user" && /^\[self-compact · handoff\]/.test(textOf(m.content).trim())) lastHandoff = i;
  });
  const assistantCount = messages.slice(lastHandoff + 1).filter((m) => m.role === "assistant").length;
  const usageTotal = BASE + STEP * assistantCount;

  // Transient guidance is a trailing user-role message; look past it for the real last message.
  let lastIndex = messages.length - 1;
  let guidance = "";
  if (lastIndex >= 0 && messages[lastIndex]!.role === "user" && /^\[self-compact · (notice|WARNING|FORCED)\]/.test(textOf(messages[lastIndex]!.content))) {
    guidance = textOf(messages[lastIndex]!.content);
    lastIndex -= 1;
  }
  const last = messages[lastIndex];
  const lastText = last ? textOf(last.content) : "";

  if (taskDone) return { text: "Task complete.", usageTotal: BASE, stopReason: "stop" };

  if (SCENARIO === "wait-for-steer") {
    if (last?.role === "user" && /STEER-TEST/.test(lastText)) return { text: "Task complete.", usageTotal, stopReason: "stop" };
    return { toolCall: { name: "wait", arguments: { seconds: 120 } }, usageTotal, stopReason: "toolUse" };
  }

  if (last?.role === "toolResult") {
    const trText = textOf(last.content);
    if (last.toolName === "self_compact") {
      if (last.isError) return handoffPlan(usageTotal);
      return { text: "Note saved; waiting for the compaction.", usageTotal, stopReason: "stop" };
    }
    if (last.isError && /blocked by self-compact/.test(trText)) {
      if (SCENARIO === "never-compact") return fillerStep(usageTotal);
      return handoffPlan(usageTotal);
    }
    if (last.toolName === "write") return { text: "Task complete.", usageTotal: BASE, stopReason: "stop" };
    // A scripted skill call came back: the next one, else on with the flow.
    if (last.toolName === "skill" || last.toolName === "skill_done") {
      if (handoffsSeen === 0 && preIndex < PRE_STEPS.length) return scripted(PRE_STEPS, preIndex++, usageTotal);
      if (handoffsSeen >= CYCLES && afterIndex < AFTER_STEPS.length) return scripted(AFTER_STEPS, afterIndex++, usageTotal);
      if (handoffsSeen >= CYCLES) {
        taskDone = true;
        return { toolCall: { name: "write", arguments: { path: RESULT_PATH, content: "done" } }, usageTotal, stopReason: "toolUse" };
      }
      return fillerStep(usageTotal);
    }
  }

  if (guidance && SCENARIO === "obey-warning" && /self-compact · WARNING/.test(guidance)) return handoffPlan(usageTotal);

  if (last?.role === "user") {
    if (/^\[self-compact · handoff\]/.test(lastText.trim())) {
      handoffsSeen += 1;
      if (handoffsSeen < CYCLES) return fillerStep(usageTotal);
      if (afterIndex < AFTER_STEPS.length) return scripted(AFTER_STEPS, afterIndex++, usageTotal);
      taskDone = true;
      return { toolCall: { name: "write", arguments: { path: RESULT_PATH, content: "done" } }, usageTotal, stopReason: "toolUse" };
    }
    if (/^Compact now:/.test(lastText)) return handoffPlan(usageTotal);
    if (handoffsSeen === 0 && preIndex < PRE_STEPS.length) return scripted(PRE_STEPS, preIndex++, usageTotal);
  }

  return fillerStep(usageTotal);
}

type Usage = { input: number; output: number; cacheRead: number; cacheWrite: number; totalTokens: number; cost: { input: number; output: number; cacheRead: number; cacheWrite: number; total: number } };

function usage(total: number, output = 20): Usage {
  const half = Math.floor(total / 2);
  return { input: Math.max(0, total - half - output), output, cacheRead: half, cacheWrite: 0, totalTokens: total, cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 } };
}

/**
 * The scripted stream. Pi's `registerProvider` accepts a `streamSimple` that
 * returns an assistant-message event stream; the stream type lives in
 * pi-ai, which this repository does not depend on, so the events are built
 * as plain objects on a tiny hand-rolled async stream with the same surface
 * Pi consumes: `push`, `end`, `result`, async iteration.
 */
function makeStream() {
  const queue: unknown[] = [];
  let resolveNext: ((v: IteratorResult<unknown>) => void) | null = null;
  let ended = false;
  let final: unknown = null;
  let resolveResult: ((v: unknown) => void) | null = null;
  const result = new Promise<unknown>((r) => {
    resolveResult = r;
  });
  return {
    push(event: unknown) {
      if (resolveNext) {
        const r = resolveNext;
        resolveNext = null;
        r({ value: event, done: false });
      } else queue.push(event);
    },
    end() {
      ended = true;
      if (resolveNext) {
        const r = resolveNext;
        resolveNext = null;
        r({ value: undefined, done: true });
      }
    },
    finish(message: unknown) {
      final = message;
      resolveResult?.(message);
    },
    result: () => result,
    get message() {
      return final;
    },
    [Symbol.asyncIterator]() {
      return {
        next: (): Promise<IteratorResult<unknown>> => {
          if (queue.length) return Promise.resolve({ value: queue.shift(), done: false });
          if (ended) return Promise.resolve({ value: undefined, done: true });
          return new Promise((r) => {
            resolveNext = r;
          });
        },
      };
    },
  };
}

/**
 * Pi 0.85.1 hands a provider `{ systemPrompt, messages, tools }`; 0.87.0 hands
 * a transcript whose leading system messages carry the prompt (`content`, and
 * `sections` patched by name) and the tool declarations (`toolsAdded`). Read
 * both, so the same fake proves the cycle on the pinned version and on
 * whatever a host has installed. A run a user prompt starts has the forced
 * prompt in `content`; a run a hand-off starts has Pi's own sections.
 */
function promptAndTools(context: { systemPrompt?: string; messages: Msg[]; tools?: unknown[] }): { systemPrompt: string; tools: unknown[]; messages: Msg[] } {
  const tools: unknown[] = [...(context.tools ?? [])];
  const messages: Msg[] = [];
  // Every system message replays into one prompt, the way Pi's own transcript
  // helpers do it: `content` is appended, `sections` are patched by name (null
  // removes one), and the prompt is the content and the sections, joined.
  const content: string[] = [];
  const sections = new Map<string, string>();
  for (const m of context.messages) {
    if (m.role !== "system") {
      messages.push(m);
      continue;
    }
    const sys = m as Msg & { toolsAdded?: unknown[]; sections?: Record<string, string | null> };
    const text = textOf(sys.content);
    if (text) content.push(text);
    for (const [name, value] of Object.entries(sys.sections ?? {})) {
      if (value === null) sections.delete(name);
      else sections.set(name, value);
    }
    for (const added of sys.toolsAdded ?? []) tools.push(added);
  }
  const replayed = [...content, ...sections.values()].filter((part) => part.length > 0).join("\n\n");
  return { systemPrompt: context.systemPrompt || replayed, tools, messages };
}

function streamScripted(model: { api: string; provider: string; id: string }, rawContext: { systemPrompt?: string; messages: Msg[]; tools?: unknown[] }, options?: { signal?: AbortSignal }) {
  const context = promptAndTools(rawContext);
  if (PROMPTS) {
    trace({
      kind: "raw",
      topSystemPrompt: typeof rawContext.systemPrompt === "string" ? rawContext.systemPrompt.length : null,
      shape: rawContext.messages.map((m) => ({ role: m.role, keys: Object.keys(m), chars: textOf(m.content).length, sections: Object.keys((m as { sections?: object }).sections ?? {}), toolsAdded: ((m as { toolsAdded?: unknown[] }).toolsAdded ?? []).length })),
    });
  }
  const stream = makeStream();
  const output: Record<string, unknown> & { content: Array<Record<string, unknown>>; usage: Usage; stopReason: string; errorMessage?: string } = {
    role: "assistant",
    content: [],
    api: model.api,
    provider: model.provider,
    model: model.id,
    usage: usage(0, 0),
    stopReason: "pending",
    timestamp: Date.now(),
  };
  const isSummary = !context.tools || context.tools.length === 0;
  /** A call that goes on until it is aborted: then it ends the way a provider's aborted stream does. */
  const untilAborted = (tick?: () => void) => {
    const signal = options?.signal;
    const end = () => {
      if (timer) clearInterval(timer);
      output.stopReason = "aborted";
      output.errorMessage = "Request was aborted";
      stream.push({ type: "error", reason: "aborted", error: output });
      stream.finish(output);
      stream.end();
    };
    const timer = tick ? setInterval(tick, 2) : undefined;
    if (signal?.aborted) end();
    else signal?.addEventListener("abort", end, { once: true });
  };
  setTimeout(() => {
    try {
      stream.push({ type: "start", partial: output });
      if (isSummary) {
        summaryCalls += 1;
        trace({ kind: "summary", call: summaryCalls, model: model.id, systemPrompt: (context.systemPrompt ?? "").slice(0, 160) });
        if (summaryCalls <= SUMMARY_FAIL) throw new Error(`fake summary failure #${summaryCalls}`);
        if (summaryCalls <= SUMMARY_FAIL + SUMMARY_RUNAWAY) {
          output.content.push({ type: "text", text: "" });
          stream.push({ type: "text_start", contentIndex: 0, partial: output });
          untilAborted(() => {
            (output.content[0] as { text: string }).text += RUNAWAY_CHUNK;
            stream.push({ type: "text_delta", contentIndex: 0, delta: RUNAWAY_CHUNK, partial: output });
          });
          return;
        }
        if (summaryCalls <= SUMMARY_FAIL + SUMMARY_RUNAWAY + SUMMARY_HANG) {
          untilAborted();
          return;
        }
        // The summary names the model that wrote it, so a test can prove the
        // call went where --compact-model pointed.
        const text = `FAKE-SUMMARY[${(context.systemPrompt ?? "").slice(0, 60)}]\n## Goal\nScripted goal.\n## Next Steps\n1. Follow the note.\nMODEL: ${model.id}`;
        output.content.push({ type: "text", text: "" });
        stream.push({ type: "text_start", contentIndex: 0, partial: output });
        (output.content[0] as { text: string }).text = text;
        stream.push({ type: "text_delta", contentIndex: 0, delta: text, partial: output });
        stream.push({ type: "text_end", contentIndex: 0, content: text, partial: output });
        output.usage = usage(1050, 50);
        output.stopReason = "stop";
      } else {
        const plan = decide(context.messages);
        const lastMessage = context.messages[context.messages.length - 1];
        trace({ kind: "turn", plan, lastRole: lastMessage?.role, lastText: lastMessage ? textOf(lastMessage.content).slice(0, 400) : "", messages: context.messages.length, ...(PROMPTS ? { systemPrompt: context.systemPrompt } : {}) });
        let index = 0;
        if (plan.text) {
          output.content.push({ type: "text", text: "" });
          stream.push({ type: "text_start", contentIndex: index, partial: output });
          (output.content[index] as { text: string }).text = plan.text;
          stream.push({ type: "text_delta", contentIndex: index, delta: plan.text, partial: output });
          stream.push({ type: "text_end", contentIndex: index, content: plan.text, partial: output });
          index += 1;
        }
        for (const call of plan.toolCalls ?? (plan.toolCall ? [plan.toolCall] : [])) {
          const id = `call_${Date.now()}_${Math.floor(Math.random() * 1e6)}`;
          const toolCall = { type: "toolCall", id, name: call.name, arguments: call.arguments };
          output.content.push(toolCall);
          stream.push({ type: "toolcall_start", contentIndex: index, partial: output });
          stream.push({ type: "toolcall_delta", contentIndex: index, delta: JSON.stringify(call.arguments), partial: output });
          stream.push({ type: "toolcall_end", contentIndex: index, toolCall, partial: output });
          index += 1;
        }
        output.usage = usage(plan.usageTotal);
        output.stopReason = plan.stopReason;
      }
      stream.push({ type: "done", reason: output.stopReason, message: output });
      stream.finish(output);
      stream.end();
    } catch (error) {
      output.stopReason = options?.signal?.aborted ? "aborted" : "error";
      output.errorMessage = error instanceof Error ? error.message : String(error);
      stream.push({ type: "error", reason: output.stopReason, error: output });
      stream.finish(output);
      stream.end();
    }
  }, 5);
  return stream;
}

export default function fakeProvider(pi: ExtensionAPI) {
  pi.registerProvider("fake", {
    name: "Fake scripted provider",
    baseUrl: "http://127.0.0.1:1/fake",
    apiKey: "fake-key",
    api: "openai-completions",
    models: [
      {
        id: "scripted",
        name: "Scripted fake model",
        reasoning: false,
        input: ["text"],
        cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
        contextWindow: WINDOW,
        maxTokens: 8192,
      },
      // A second model nobody sits on: what --compact-model points at.
      {
        id: "summarizer",
        name: "Scripted fake summarizer",
        reasoning: false,
        input: ["text"],
        cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
        contextWindow: WINDOW,
        maxTokens: 8192,
      },
    ],
    streamSimple: streamScripted as never,
  } as never);
}
