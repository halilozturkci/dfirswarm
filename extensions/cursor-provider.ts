/**
 * Cursor's models through Pi. This extension registers a provider, `cursor`,
 * whose stream runs Cursor's own CLI, `cursor-agent`, in its headless mode as
 * the model and nothing more. Pi stays the agent: its loop, its tools, the
 * swarm's guards and its record are the same as with any other provider.
 *
 *   pi -e extensions/cursor-provider.ts --model cursor/grok-4.7-medium
 *
 * The CLI is logged in on this host (`cursor-agent login`) or reads
 * CURSOR_API_KEY. Its model ids are Cursor's (`cursor-agent models`): the
 * reasoning effort is part of the id (`grok-4.7-high`, `kimi-k3-low`).
 *
 * `cursor-agent` is an agent of its own, with file, shell, search, web and MCP
 * tools, and the account's MCP plugins (Gmail among them). Measured on
 * 2026.10.22: `--mode ask` alone still read /etc/hostname outside its
 * workspace. So every call runs in a workspace of its own whose
 * `.cursor/cli.json` denies shell, read, write, web fetch and every MCP tool
 * (the CLI refuses each such call, which was checked), in ask mode with the
 * sandbox on; the model is told that Pi runs the tools and asks for them in a
 * text block this module parses (`<pi_tool_call>`). Pi's tools never reach the
 * CLI, and a call of the CLI's own tools is counted and refused, not run.
 *
 * Each call is one `cursor-agent -p` process, its prompt on stdin (an argument
 * holds at most 128 KiB on Linux). A conversation is one Cursor chat, resumed
 * with `--resume` so that only what is new since the last call is sent; the
 * chat's history is kept per workspace (a resume from another workspace
 * forgets it), so a chat keeps its workspace. Anything that changes the part
 * already sent (a compaction, an edit, another model's reply) starts a new
 * chat with the whole transcript. The CLI leaves a child behind (a node
 * process and a TypeScript language server it starts through npx), so each
 * call runs in a process group of its own and the whole group is ended when
 * the call is.
 *
 * Token usage is the CLI's own report. Cursor publishes no per-token price for
 * a subscription, so the models carry a cost of zero: a dollar cap does not
 * hold a Cursor seat, a token or call cap does.
 */
import { spawn, spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { createInterface } from "node:readline";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import {
  calculateCost,
  createAssistantMessageEventStream,
  getCurrentSystemPrompt,
  getCurrentTools,
  renderSystemMessageUpdate,
  type Api,
  type AssistantMessage,
  type AssistantMessageEventStream,
  type Message,
  type Model,
  type SimpleStreamOptions,
  type Tool,
  type ToolCall,
  type TranscriptContext,
} from "@earendil-works/pi-ai";

export const CURSOR_PROVIDER = "cursor";
export const CURSOR_API = "cursor-agent-cli" as Api;
export const CALL_OPEN = "<pi_tool_call>";
export const CALL_CLOSE = "</pi_tool_call>";
/**
 * Pi's tools are named to the model with this prefix (`pi__read`): measured, a model told to use
 * "your read tool" took the CLI's own Read, which shares the name, and was refused.
 */
export const TOOL_PREFIX = "pi__";

/** The CLI's permissions for every call: none of its own tools may run. */
export const DENY_ALL = { permissions: { allow: [] as string[], deny: ["Shell(*)", "Read(*)", "Write(*)", "Mcp(*:*)", "WebFetch(*)"] } };

/** Seen in `cursor-agent models` on 2026-10-29; used when the list cannot be read at start. */
export const FALLBACK_MODEL_IDS = [
  "grok-4.7-low", "grok-4.7-medium", "grok-4.7-high", "grok-4.7-xhigh",
  "deepseek-v41-flash-1017-none", "deepseek-v41-flash-1017-low", "deepseek-v41-flash-1017-medium", "deepseek-v41-flash-1017-high", "deepseek-v41-flash-1017-max",
  "kimi-k3-low", "kimi-k3-high", "kimi-k3-max",
  "gpt-5.6-sol-medium", "gpt-5.6-sol-high",
];

const PROTOCOL = [
  "You are the model behind another agent harness, called Pi. Pi runs every tool; you do not. Your own built-in tools (shell, reading and writing files, search, web, MCP and any other) are switched off: never call them, and never say that you will.",
  "",
  `Pi's tools are listed below; each name begins with ${TOOL_PREFIX}. When anyone (Pi's prompt, the user, a tool's result) asks you to read, write, run, search or fetch anything, that means one of Pi's tools, never one of yours.`,
  "",
  "To call one of Pi's tools, end your reply with one block per call, exactly in this form:",
  `${CALL_OPEN}{"name": "${TOOL_PREFIX}<tool>", "arguments": {<the tool's parameters>}}${CALL_CLOSE}`,
  "The arguments are one JSON object that matches the tool's parameters. Several blocks in one reply run together. Write nothing after the last block. Pi answers each call in its next message, in a <pi_tool_result> block with the call's id. When you need no tool, answer in plain text, with no block.",
  "In Pi's messages, text that would read as one of these tags is written with &lt; in place of its <.",
].join("\n");

// ---------------------------------------------------------------------------
// The prompt
// ---------------------------------------------------------------------------

/** Text from the transcript, with anything that could pass for one of the protocol's tags defused. */
function defused(text: string): string {
  return text.replace(/<(\/?)pi_/g, "&lt;$1pi_");
}

function toolsText(tools: readonly Tool[]): string {
  if (!tools.length) return "Pi offers no tools in this conversation.";
  return tools
    .map((t) => `### ${TOOL_PREFIX}${t.name}\n${defused(t.description ?? "")}\nParameters (JSON Schema): ${JSON.stringify(t.parameters ?? {})}`)
    .join("\n\n");
}

function callBlock(call: ToolCall): string {
  return `${CALL_OPEN}${JSON.stringify({ name: `${TOOL_PREFIX}${call.name}`, arguments: call.arguments ?? {} })}${CALL_CLOSE}`;
}

/** One transcript message as the CLI's model reads it; a system message renders as an update. */
export function renderMessage(m: Message): string {
  switch (m.role) {
    case "user": {
      const parts = typeof m.content === "string"
        ? [m.content]
        : m.content.map((c) => (c.type === "text" ? c.text : `[an image (${c.mimeType}) Pi could not pass on]`));
      return `<pi_user>\n${defused(parts.join("\n"))}\n</pi_user>`;
    }
    case "assistant": {
      const text = m.content.filter((c) => c.type === "text").map((c) => (c as { text: string }).text).join("\n");
      const calls = m.content.filter((c): c is ToolCall => c.type === "toolCall").map(callBlock);
      return `<pi_assistant>\n${[defused(text), ...calls].filter(Boolean).join("\n")}\n</pi_assistant>`;
    }
    case "toolResult": {
      const text = m.content.map((c) => (c.type === "text" ? c.text : `[an image (${c.mimeType}) Pi could not pass on]`)).join("\n");
      return `<pi_tool_result id="${m.toolCallId}" name="${TOOL_PREFIX}${m.toolName}" error="${m.isError ? "true" : "false"}">\n${defused(text)}\n</pi_tool_result>`;
    }
    case "system": {
      const lines = [defused(renderSystemMessageUpdate(m))];
      if (m.toolsAdded?.length) lines.push(`Tools added:\n${toolsText(m.toolsAdded)}`);
      if (m.toolsRemoved?.length) lines.push(`Tools removed: ${m.toolsRemoved.map((r) => `${TOOL_PREFIX}${r.name}`).join(", ")}`);
      return `<pi_system_update>\n${lines.join("\n\n")}\n</pi_system_update>`;
    }
  }
}

/** The whole transcript, for a new chat: the protocol, Pi's current prompt and tools, then every message. */
export function fullPrompt(messages: readonly Message[]): string {
  const body = messages.filter((m) => m.role !== "system").map(renderMessage).join("\n\n");
  return [
    PROTOCOL,
    `<pi_system_prompt>\n${defused(getCurrentSystemPrompt(messages))}\n</pi_system_prompt>`,
    `<pi_tools>\n${toolsText(getCurrentTools(messages))}\n</pi_tools>`,
    body,
    "Answer the last message, as Pi's model.",
  ].join("\n\n");
}

/** What is new since the last call, for a chat that holds the rest. */
export function deltaPrompt(messages: readonly Message[]): string {
  return [...messages.map(renderMessage), "Continue, as Pi's model."].join("\n\n");
}

// ---------------------------------------------------------------------------
// The reply
// ---------------------------------------------------------------------------

/** How much of a reply under way can be shown: everything before a block, or before what may be the start of one. */
export function shownLength(text: string): number {
  const open = text.indexOf(CALL_OPEN);
  if (open >= 0) return open;
  const lt = text.lastIndexOf("<");
  if (lt >= 0 && CALL_OPEN.startsWith(text.slice(lt))) return lt;
  return text.length;
}

export type ParsedReply = { text: string; calls: ToolCall[] };

function callId(): string {
  return `cursor_${randomBytes(6).toString("hex")}`;
}

function parseCall(raw: string): ToolCall {
  const body = raw.trim();
  try {
    const parsed = JSON.parse(body) as unknown;
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      const { name: given, arguments: args } = parsed as { name?: unknown; arguments?: unknown };
      const name = typeof given === "string" ? given.replace(new RegExp(`^${TOOL_PREFIX}`), "") : given;
      if (typeof name === "string" && name) {
        if (args === undefined) return { type: "toolCall", id: callId(), name, arguments: {} };
        if (args && typeof args === "object" && !Array.isArray(args)) return { type: "toolCall", id: callId(), name, arguments: args as ToolCall["arguments"] };
        return { type: "toolCall", id: callId(), name, arguments: {}, argumentsError: `the arguments are not a JSON object: ${JSON.stringify(args).slice(0, 400)}` };
      }
    }
  } catch {
    // reported below, with the text the model sent
  }
  const named = /"name"\s*:\s*"([^"]{1,128})"/.exec(body)?.[1]?.replace(new RegExp(`^${TOOL_PREFIX}`), "");
  return { type: "toolCall", id: callId(), name: named ?? "unparsed_tool_call", arguments: {}, argumentsError: `the call is not the JSON object the protocol asks for: ${body.slice(0, 400)}` };
}

/** A finished reply: its text (before the first block) and its tool calls. An unclosed last block is a call the model was cut off in. */
export function parseReply(reply: string): ParsedReply {
  const first = reply.indexOf(CALL_OPEN);
  if (first < 0) return { text: reply, calls: [] };
  const calls: ToolCall[] = [];
  let at = first;
  while (at >= 0) {
    const start = at + CALL_OPEN.length;
    const end = reply.indexOf(CALL_CLOSE, start);
    calls.push(parseCall(end < 0 ? reply.slice(start) : reply.slice(start, end)));
    if (end < 0) break;
    at = reply.indexOf(CALL_OPEN, end + CALL_CLOSE.length);
  }
  return { text: reply.slice(0, first).replace(/\s+$/, ""), calls };
}

// ---------------------------------------------------------------------------
// The CLI
// ---------------------------------------------------------------------------

export function cursorBinary(env: NodeJS.ProcessEnv = process.env): string {
  if (env.CURSOR_AGENT_BIN) return env.CURSOR_AGENT_BIN;
  const local = join(homedir(), ".local", "bin", "cursor-agent");
  return existsSync(local) ? local : "cursor-agent";
}

export function cursorArgs(model: string, workspace: string, chatId?: string): string[] {
  return [
    "-p", "--output-format", "stream-json", "--stream-partial-output",
    "--mode", "ask", "--sandbox", "enabled", "--trust",
    "--workspace", workspace, "--model", model,
    ...(chatId ? ["--resume", chatId] : []),
  ];
}

/** The CLI's environment: what it needs to find its login and run, and no other key Pi's process holds. */
export function cursorEnv(env: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
  const keep = ["HOME", "PATH", "USER", "LOGNAME", "LANG", "LC_ALL", "TERM", "TMPDIR", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME", "CURSOR_API_KEY", "CURSOR_API_ENDPOINT", "NO_OPEN_BROWSER"];
  const out: NodeJS.ProcessEnv = {};
  for (const k of keep) if (env[k] !== undefined) out[k] = env[k];
  out.NO_OPEN_BROWSER = "1";
  return out;
}

const WORKSPACE_PREFIX = "pi-cursor-";

/**
 * Workspaces whose Pi process is gone. A workspace is named for the process that made it
 * (`pi-cursor-<pid>-…`) and removed when that process exits; one killed by a signal leaves it,
 * and the next start removes it. Another live process's workspaces (another seat on this host)
 * are left alone.
 */
export function sweepWorkspaces(root: string = tmpdir()): string[] {
  const removed: string[] = [];
  let names: string[] = [];
  try {
    names = readdirSync(root);
  } catch {
    return removed;
  }
  for (const name of names) {
    const m = new RegExp(`^${WORKSPACE_PREFIX}(\\d+)-`).exec(name);
    if (!m) continue;
    const pid = Number(m[1]);
    let alive = pid === process.pid;
    if (!alive) {
      try {
        process.kill(pid, 0);
        alive = true;
      } catch (err) {
        alive = (err as NodeJS.ErrnoException).code === "EPERM";
      }
    }
    if (alive) continue;
    rmSync(join(root, name), { recursive: true, force: true });
    removed.push(name);
  }
  return removed;
}

/** A workspace for one chat: empty but for the permissions that refuse every tool of the CLI's. */
export function makeWorkspace(): string {
  const dir = mkdtempSync(join(tmpdir(), `${WORKSPACE_PREFIX}${process.pid}-`));
  mkdirSync(join(dir, ".cursor"), { recursive: true });
  writeFileSync(join(dir, ".cursor", "cli.json"), `${JSON.stringify(DENY_ALL, null, 2)}\n`, { mode: 0o600 });
  return dir;
}

/** Cursor's model list, from `cursor-agent models` ("<id> - <name>" per line). */
export function parseModelList(text: string): { id: string; name: string }[] {
  const out: { id: string; name: string }[] = [];
  for (const line of text.split("\n")) {
    const m = /^([a-z0-9][a-z0-9._\-[\]=,]*) - (.+)$/i.exec(line.trim());
    if (m) out.push({ id: m[1], name: m[2].replace(/[​-‍﻿]/g, "").replace(/\s+/g, " ").trim() });
  }
  return out;
}

function endGroup(pid: number | undefined): void {
  if (!pid) return;
  try {
    process.kill(-pid, "SIGTERM");
  } catch {
    return; // the group is gone already
  }
  const timer = setTimeout(() => {
    try {
      process.kill(-pid, "SIGKILL");
    } catch {
      // gone
    }
  }, 2000);
  timer.unref();
}

function listModels(env: NodeJS.ProcessEnv = process.env): { id: string; name: string }[] {
  try {
    const r = spawnSync(cursorBinary(env), ["models"], { env: cursorEnv(env), encoding: "utf8", timeout: 20_000 });
    return r.status === 0 ? parseModelList(r.stdout ?? "") : [];
  } catch {
    return [];
  }
}

// ---------------------------------------------------------------------------
// Chats
// ---------------------------------------------------------------------------

type Chat = { chatId: string; workspace: string; model: string; sent: number; prefixHash: string; lastUsed: number };

const MAX_CHATS = 16;
const chats = new Map<string, Chat>();

function hashOf(messages: readonly Message[]): string {
  const h = createHash("sha256");
  for (const m of messages) h.update(renderMessage(m)).update("\u0000");
  return h.digest("hex");
}

/** The key of a conversation: Pi's session id, else its first user message. */
function conversationKey(messages: readonly Message[], sessionId?: string): string {
  if (sessionId) return `s:${sessionId}`;
  const first = messages.find((m) => m.role === "user");
  return `u:${createHash("sha256").update(first ? renderMessage(first) : "").digest("hex")}`;
}

function dropChat(key: string): void {
  const chat = chats.get(key);
  if (!chat) return;
  chats.delete(key);
  rmSync(chat.workspace, { recursive: true, force: true });
}

let cleanupArmed = false;
function armCleanup(): void {
  if (cleanupArmed) return;
  cleanupArmed = true;
  process.once("exit", () => {
    for (const key of [...chats.keys()]) dropChat(key);
  });
}

/**
 * Whether a chat can carry on with these messages, and what to send it: the chat holds the
 * first `sent` messages (their hash matches) and the reply that came after them; what follows
 * that reply is new. Anything else is a new chat with the whole transcript.
 */
export function planCall(chat: Chat | undefined, messages: readonly Message[], model: string): { resume: boolean; send: Message[] } {
  if (!chat || chat.model !== model || messages.length <= chat.sent) return { resume: false, send: [...messages] };
  if (hashOf(messages.slice(0, chat.sent)) !== chat.prefixHash) return { resume: false, send: [...messages] };
  const reply = messages[chat.sent];
  if (reply.role !== "assistant" || reply.provider !== CURSOR_PROVIDER || reply.model !== model) return { resume: false, send: [...messages] };
  const rest = messages.slice(chat.sent + 1);
  if (!rest.length || rest.some((m) => m.role === "assistant")) return { resume: false, send: [...messages] };
  return { resume: true, send: rest };
}

// ---------------------------------------------------------------------------
// The stream
// ---------------------------------------------------------------------------

type CliEvent = { type?: string; subtype?: string; cwd?: string; session_id?: string; timestamp_ms?: number; is_error?: boolean; result?: unknown; message?: { content?: { text?: string }[] }; usage?: { inputTokens?: number; outputTokens?: number; cacheReadTokens?: number; cacheWriteTokens?: number } };

/** Counted for each call: the CLI's own tool calls the model made (refused by the workspace's permissions). */
export const ownToolCalls = { total: 0 };

/** Sent, once, to a chat whose model reached for the CLI's own tools and asked Pi for nothing. */
export const CORRECTION = [
  "Pi: your own built-in tools are switched off, and the call you just made was refused: it read and ran nothing.",
  `Pi's tools are the ${TOOL_PREFIX}… tools of the first message. Call them with ${CALL_OPEN} blocks, exactly as the first message says, and answer again.`,
].join(" ");

type CliRun = { reply: string; finalText?: string; result?: CliEvent; own: number; refused?: string; timedOut: boolean; spawnError?: Error; code: number | null; stderr: string };

/** One `cursor-agent -p` run in the chat's workspace: its events read, its process group ended with it. */
async function runCli(
  model: Model<Api>,
  workspace: string,
  chatId: string | undefined,
  prompt: string,
  options: SimpleStreamOptions | undefined,
  onStart: () => void,
  onReply: (replySoFar: string) => void,
): Promise<CliRun> {
  const run: CliRun = { reply: "", own: 0, timedOut: false, code: null, stderr: "" };
  const child = spawn(cursorBinary(), cursorArgs(model.id, workspace, chatId), { cwd: workspace, env: cursorEnv(), detached: true, stdio: ["pipe", "pipe", "pipe"] });
  const closed = new Promise<number | null>((resolve) => {
    child.once("close", (c) => resolve(c));
    child.once("error", (err) => {
      run.spawnError = err;
      resolve(null);
    });
  });
  const onAbort = () => endGroup(child.pid);
  options?.signal?.addEventListener("abort", onAbort, { once: true });
  const timeoutMs = options?.timeoutMs ?? 15 * 60_000;
  const timer = setTimeout(() => {
    run.timedOut = true;
    endGroup(child.pid);
  }, timeoutMs);
  child.stderr.on("data", (b: Buffer) => {
    if (run.stderr.length < 8192) run.stderr += b.toString("utf8");
  });
  child.stdin.on("error", () => undefined);
  child.stdin.end(prompt);

  const lines = createInterface({ input: child.stdout, crlfDelay: Infinity });
  for await (const line of lines) {
    if (!line.trim()) continue;
    let ev: CliEvent;
    try {
      ev = JSON.parse(line) as CliEvent;
    } catch {
      continue;
    }
    await options?.onProviderStreamEvent?.(ev, model);
    if (ev.type === "system" && ev.subtype === "init") {
      if (ev.cwd !== workspace) {
        run.refused = `cursor-agent started in ${String(ev.cwd)}, not in the call's own workspace: the call was stopped`;
        endGroup(child.pid);
        break;
      }
      await options?.onResponse?.({ status: 200, headers: {} }, model);
      onStart();
    } else if (ev.type === "assistant") {
      const text = (ev.message?.content ?? []).map((c) => c.text ?? "").join("");
      if (ev.timestamp_ms === undefined) {
        run.finalText = text;
      } else {
        run.reply += text;
        // After a call of the CLI's own tools the rest is held back: it may be answered again.
        if (!run.own) onReply(run.reply);
      }
    } else if (ev.type === "tool_call" && ev.subtype === "started") {
      run.own += 1;
      ownToolCalls.total += 1;
    } else if (ev.type === "result") {
      run.result = ev;
      // The answer is in: a CLI that does not exit after it is not waited for.
      setTimeout(() => endGroup(child.pid), 3000).unref();
    }
  }
  run.code = await closed;
  clearTimeout(timer);
  options?.signal?.removeEventListener("abort", onAbort);
  endGroup(child.pid);
  return run;
}

/** Why a run gave no answer, or nothing when it gave one. */
function runFailure(run: CliRun, timeoutMs: number): string | undefined {
  if (run.refused) return run.refused;
  if (run.timedOut) return `cursor-agent did not finish within ${Math.round(timeoutMs / 1000)} s`;
  if (run.spawnError) return `cursor-agent could not be started (${cursorBinary()}): ${run.spawnError.message}`;
  if (!run.result || run.result.is_error || run.code !== 0) {
    const said = run.stderr.trim().split("\n").slice(-3).join(" ").slice(0, 600);
    return /not logged in|unauthori[sz]ed|authentication/i.test(said)
      ? "cursor-agent is not logged in: run `cursor-agent login` on this host, or set CURSOR_API_KEY"
      : `cursor-agent ended without an answer (exit ${run.code ?? "signal"}${said ? `: ${said}` : ""})`;
  }
  return undefined;
}

export function streamCursor(model: Model<Api>, context: TranscriptContext, options?: SimpleStreamOptions): AssistantMessageEventStream {
  const stream = createAssistantMessageEventStream();
  const output: AssistantMessage = {
    role: "assistant",
    content: [],
    api: model.api,
    provider: model.provider,
    model: model.id,
    usage: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, totalTokens: 0, cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 } },
    stopReason: "pending",
    timestamp: Date.now(),
  };
  const fail = (reason: "error" | "aborted", message: string) => {
    output.stopReason = reason;
    output.errorMessage = message;
    stream.push({ type: "error", reason, error: output });
    stream.end();
  };

  void (async () => {
    armCleanup();
    const messages = context.messages;
    const key = conversationKey(messages, options?.sessionId);
    const existing = chats.get(key);
    const plan = planCall(existing, messages, model.id);
    if (existing && !plan.resume) dropChat(key);
    const chat = plan.resume ? existing : undefined;
    const workspace = chat?.workspace ?? makeWorkspace();
    let prompt = plan.resume ? deltaPrompt(plan.send) : fullPrompt(plan.send);
    const replaced = await options?.onPayload?.({ model: model.id, resume: chat?.chatId ?? null, prompt }, model);
    if (replaced && typeof replaced === "object" && typeof (replaced as { prompt?: unknown }).prompt === "string") prompt = (replaced as { prompt: string }).prompt;

    if (options?.signal?.aborted) {
      if (!chat) rmSync(workspace, { recursive: true, force: true });
      fail("aborted", "aborted before the call");
      return;
    }
    const forget = () => {
      if (chat) dropChat(key);
      else rmSync(workspace, { recursive: true, force: true });
    };

    // What the screen holds: one text block, only ever added to. A run's prose is shown as it
    // comes (up to what may begin a block); a second run's follows the first's.
    let shownText = "";
    let textIndex = -1;
    let started = false;
    const start = () => {
      if (started) return;
      started = true;
      stream.push({ type: "start", partial: output });
    };
    const show = (candidate: string) => {
      if (candidate.length <= shownText.length || !candidate.startsWith(shownText)) return;
      if (textIndex < 0) {
        output.content.push({ type: "text", text: "" });
        textIndex = output.content.length - 1;
        stream.push({ type: "text_start", contentIndex: textIndex, partial: output });
      }
      const delta = candidate.slice(shownText.length);
      shownText = candidate;
      (output.content[textIndex] as { text: string }).text = shownText;
      stream.push({ type: "text_delta", contentIndex: textIndex, delta, partial: output });
    };
    const timeoutMs = options?.timeoutMs ?? 15 * 60_000;
    const runs: CliRun[] = [];
    let chatId = chat?.chatId;
    let parsed: ParsedReply = { text: "", calls: [] };
    let before = "";
    for (let attempt = 0; attempt < 2; attempt++) {
      const lead = before ? `${before}\n\n` : "";
      const run = await runCli(model, workspace, chatId, attempt === 0 ? prompt : CORRECTION, options, start, (r) => {
        start();
        show(lead + r.slice(0, shownLength(r)));
      });
      runs.push(run);
      if (options?.signal?.aborted) {
        forget();
        fail("aborted", "aborted");
        return;
      }
      const failure = runFailure(run, timeoutMs);
      if (failure) {
        forget();
        fail("error", failure);
        return;
      }
      chatId = run.result?.session_id ?? chatId;
      parsed = parseReply(run.finalText ?? run.reply);
      parsed = { ...parsed, text: lead + parsed.text };
      // The model reached for the CLI's own tools (refused) and asked Pi for nothing: tell it once.
      if (!(run.own > 0 && parsed.calls.length === 0 && chatId)) break;
      before = shownText.replace(/\s+$/, "");
    }

    start();
    // What was shown is a prefix of the final prose: show the rest before the calls. What was shown
    // past the prose (the blank line before a block) is taken back from the message, not the screen.
    if (parsed.text.startsWith(shownText)) show(parsed.text);
    else if (textIndex >= 0 && shownText.replace(/\s+$/, "") === parsed.text) (output.content[textIndex] as { text: string }).text = parsed.text;
    if (textIndex >= 0) stream.push({ type: "text_end", contentIndex: textIndex, content: (output.content[textIndex] as { text: string }).text, partial: output });
    for (const call of parsed.calls) {
      output.content.push(call);
      const index = output.content.length - 1;
      stream.push({ type: "toolcall_start", contentIndex: index, partial: output });
      stream.push({ type: "toolcall_end", contentIndex: index, toolCall: call, partial: output });
    }
    for (const run of runs) {
      const u = run.result?.usage ?? {};
      output.usage.input += u.inputTokens ?? 0;
      output.usage.output += u.outputTokens ?? 0;
      output.usage.cacheRead += u.cacheReadTokens ?? 0;
      output.usage.cacheWrite += u.cacheWriteTokens ?? 0;
    }
    output.usage.totalTokens = output.usage.input + output.usage.output + output.usage.cacheRead + output.usage.cacheWrite;
    output.usage.cost = calculateCost(model, output.usage);
    output.stopReason = parsed.calls.length ? "toolUse" : "stop";
    if (chatId) output.responseId = chatId;

    if (chatId) {
      chats.set(key, { chatId, workspace, model: model.id, sent: messages.length, prefixHash: hashOf(messages), lastUsed: Date.now() });
      if (chats.size > MAX_CHATS) {
        const oldest = [...chats.entries()].sort((a, b) => a[1].lastUsed - b[1].lastUsed)[0]?.[0];
        if (oldest && oldest !== key) dropChat(oldest);
      }
    } else {
      forget();
    }
    stream.push({ type: "done", reason: output.stopReason, message: output });
    stream.end();
  })().catch((err: unknown) => fail(options?.signal?.aborted ? "aborted" : "error", err instanceof Error ? err.message : String(err)));

  return stream;
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

export function modelConfigs(list: { id: string; name: string }[]) {
  const seen = list.length ? list : FALLBACK_MODEL_IDS.map((id) => ({ id, name: id }));
  return seen
    .filter((m) => m.id !== "auto")
    .map((m) => ({
      id: m.id,
      name: `${m.name} (Cursor)`,
      reasoning: false,
      input: ["text" as const],
      cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
      contextWindow: 200_000,
      maxTokens: 32_000,
    }));
}

export default function (pi: ExtensionAPI) {
  sweepWorkspaces();
  const list = process.env.PI_CURSOR_NO_DISCOVERY === "1" ? [] : listModels();
  pi.registerProvider(CURSOR_PROVIDER, {
    name: "Cursor (cursor-agent)",
    baseUrl: "https://api2.cursor.sh",
    // The CLI holds its own login (or reads CURSOR_API_KEY); Pi needs a value to register models.
    apiKey: "cursor-agent-login",
    api: CURSOR_API,
    models: modelConfigs(list),
    streamSimple: streamCursor,
  });
}

export function _resetChatsForTests(): void {
  for (const key of [...chats.keys()]) dropChat(key);
  ownToolCalls.total = 0;
}
