/**
 * Test-only Pi extension: two scripted providers for the skill unloader's
 * end-to-end tests (tests/skill-unload-e2e.test.ts), no key and no network.
 *
 * - `fake/scripted`: an OpenAI-completions model that does not think. The
 *   class the unloader may edit at a turn boundary.
 * - `fakeclaude/claude-scripted`: a model whose catalogue entry says what a
 *   Claude Fable 5.1 or Opus 5.5 entry says in Pi 0.87.1's data: the
 *   `anthropic-messages` api, `reasoning: true`, and a `thinkingLevelMap` that
 *   cannot turn thinking off. Every assistant message it writes carries a
 *   signed thinking block, as the real one's would. The class the unloader
 *   releases at a compaction only.
 *
 * The script is a list of steps (env SU_SCRIPT, JSON). Every model request of
 * the seat takes the next one; a request made after the last step is answered
 * with a line of text. A step is one assistant message:
 *   { "calls": [{ "name": "skill", "arguments": { "id": "evidence/one" } }, ...] }
 *     one assistant message with those tool calls (Pi runs them at the same time)
 *   { "text": "..." }   an assistant message with text and no call
 * A summary request (the compaction's, which carries no tools) is answered with
 * a fixed summary and does not take a step. The self_compact flow therefore
 * reads: a step that calls self_compact, then one step for the request the
 * hand-off message starts.
 *
 * Every request is recorded in SU_TRACE (JSONL): the messages the provider was
 * sent, with the text of each, so a test can say what the model was shown after
 * a release. A summary request records the whole of its input.
 *
 * Environment:
 *   SU_SCRIPT   the steps
 *   SU_TRACE    the file every request is appended to
 *   SU_WINDOW   the context window the models declare (default 200000)
 */
import { appendFileSync } from "node:fs";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

const WINDOW = Number(process.env.SU_WINDOW ?? "200000");
const TRACE = process.env.SU_TRACE;
type Call = { name: string; arguments: Record<string, unknown> };
type Step = { calls?: Call[]; text?: string };
const SCRIPT: Step[] = JSON.parse(process.env.SU_SCRIPT ?? "[]");

let request = 0;

type Msg = { role: string; content?: unknown; toolName?: string; toolCallId?: string; isError?: boolean };

function textOf(content: unknown): string {
  if (typeof content === "string") return content;
  if (Array.isArray(content)) {
    return content
      .map((block) => (block && typeof block === "object" && (block as { type?: string }).type === "text" ? String((block as { text?: string }).text ?? "") : ""))
      .join("\n");
  }
  return "";
}

function record(entry: Record<string, unknown>) {
  if (!TRACE) return;
  try {
    appendFileSync(TRACE, `${JSON.stringify({ at: Date.now(), ...entry })}\n`);
  } catch {
    // a trace that cannot be written must not fail the run it records
  }
}

type Usage = { input: number; output: number; cacheRead: number; cacheWrite: number; totalTokens: number; cost: { input: number; output: number; cacheRead: number; cacheWrite: number; total: number } };

function usage(total: number, output = 20): Usage {
  return { input: Math.max(0, total - output), output, cacheRead: 0, cacheWrite: 0, totalTokens: total, cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 } };
}

/** The tiny async stream Pi consumes: `push`, `end`, `result`, async iteration (see tests/fixtures/self-compact-fake-provider.ts). */
function makeStream() {
  const queue: unknown[] = [];
  let resolveNext: ((v: IteratorResult<unknown>) => void) | null = null;
  let ended = false;
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
      resolveResult?.(message);
    },
    result: () => result,
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

/** Pi 0.87 hands a provider a transcript whose leading system messages carry the prompt and the tool declarations. */
function toolNames(context: { messages: Msg[]; tools?: unknown[] }): string[] {
  const names: string[] = [];
  for (const tool of context.tools ?? []) names.push(String((tool as { name?: string }).name ?? ""));
  for (const m of context.messages) {
    if (m.role !== "system") continue;
    for (const added of (m as Msg & { toolsAdded?: Array<{ name?: string }> }).toolsAdded ?? []) names.push(String(added.name ?? ""));
  }
  return names.filter(Boolean);
}

function streamScripted(model: { api: string; provider: string; id: string; reasoning?: boolean }, rawContext: { messages: Msg[]; tools?: unknown[] }, options?: { signal?: AbortSignal }) {
  const stream = makeStream();
  const messages = rawContext.messages.filter((m) => m.role !== "system");
  const tools = toolNames(rawContext);
  const isSummary = tools.length === 0;
  const thinks = model.reasoning === true;
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
  setTimeout(() => {
    try {
      stream.push({ type: "start", partial: output });
      if (isSummary) {
        const input = messages.map((m) => textOf(m.content)).join("\n");
        record({ kind: "summary", model: model.id, input });
        const text = `FAKE-SUMMARY\n## Goal\nScripted goal.\n## Next Steps\n1. Follow the note.\nSKILLS-READ-BLOCK: ${input.includes("<skills-read>") ? "yes" : "no"}`;
        output.content.push({ type: "text", text: "" });
        stream.push({ type: "text_start", contentIndex: 0, partial: output });
        (output.content[0] as { text: string }).text = text;
        stream.push({ type: "text_delta", contentIndex: 0, delta: text, partial: output });
        stream.push({ type: "text_end", contentIndex: 0, content: text, partial: output });
        output.usage = usage(1050, 50);
        output.stopReason = "stop";
      } else {
        const index = request++;
        const step: Step = SCRIPT[index] ?? { text: "The script is finished." };
        record({
          kind: "turn",
          i: index,
          model: model.id,
          tools,
          messages: messages.map((m) => ({ role: m.role, toolName: m.toolName, toolCallId: m.toolCallId, isError: m.isError, text: textOf(m.content) })),
        });
        let at = 0;
        if (thinks) {
          // What a signed thinking block looks like on an assistant message the provider wrote.
          const thinking = `thinking about step ${index}`;
          output.content.push({ type: "thinking", thinking, thinkingSignature: `sig-${index}` });
          stream.push({ type: "thinking_start", contentIndex: at, partial: output });
          stream.push({ type: "thinking_delta", contentIndex: at, delta: thinking, partial: output });
          stream.push({ type: "thinking_end", contentIndex: at, content: thinking, partial: output });
          at += 1;
        }
        if (step.text) {
          output.content.push({ type: "text", text: step.text });
          stream.push({ type: "text_start", contentIndex: at, partial: output });
          stream.push({ type: "text_delta", contentIndex: at, delta: step.text, partial: output });
          stream.push({ type: "text_end", contentIndex: at, content: step.text, partial: output });
          at += 1;
        }
        for (const call of step.calls ?? []) {
          const id = `call_${index}_${at}_${Math.floor(Math.random() * 1e6)}`;
          const toolCall = { type: "toolCall", id, name: call.name, arguments: call.arguments };
          output.content.push(toolCall);
          stream.push({ type: "toolcall_start", contentIndex: at, partial: output });
          stream.push({ type: "toolcall_delta", contentIndex: at, delta: JSON.stringify(call.arguments), partial: output });
          stream.push({ type: "toolcall_end", contentIndex: at, toolCall, partial: output });
          at += 1;
        }
        output.usage = usage(3000 + 100 * index);
        output.stopReason = step.calls?.length ? "toolUse" : "stop";
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

export default function fakeProviders(pi: ExtensionAPI) {
  const cost = { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 };
  pi.registerProvider("fake", {
    name: "Fake scripted provider",
    baseUrl: "http://127.0.0.1:1/fake",
    apiKey: "fake-key",
    api: "openai-completions",
    models: [{ id: "scripted", name: "Scripted fake model", reasoning: false, input: ["text"], cost, contextWindow: WINDOW, maxTokens: 8192 }],
    streamSimple: streamScripted as never,
  } as never);
  pi.registerProvider("fakeclaude", {
    name: "Fake scripted provider with a Claude-shaped catalogue entry",
    baseUrl: "http://127.0.0.1:1/fakeclaude",
    apiKey: "fake-key",
    api: "anthropic-messages",
    models: [
      {
        id: "claude-scripted",
        name: "Scripted fake Claude",
        reasoning: true,
        thinkingLevelMap: { off: null },
        input: ["text"],
        cost,
        contextWindow: WINDOW,
        maxTokens: 8192,
      },
    ],
    streamSimple: streamScripted as never,
  } as never);
}
