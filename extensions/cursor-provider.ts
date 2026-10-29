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
 * workspace. So every chat has a workspace of its own whose
 * `.cursor/cli.json` denies shell, read, write, web fetch and every MCP tool,
 * in ask mode with the sandbox on (off only under a guard that holds Pi
 * itself: `cursorSandbox`); the model is told that Pi runs the tools
 * and asks for them in text blocks at the end of its reply (`<pi_tool_call>`),
 * which this module parses. A call of the CLI's own tools that the CLI
 * refused is counted; one that ran (anything but an empty search of the empty
 * workspace, or a list of tool names) stops the turn as an error. A tool the
 * permissions do not name (the CLI's web search) is not refused by them: its
 * request has left before the turn can be stopped.
 *
 * Each call is one `cursor-agent -p` process, its prompt on stdin (an argument
 * holds at most 128 KiB on Linux), in a process group of its own: the CLI
 * leaves a node process and a TypeScript language server behind, so the group
 * is killed when the call ends, and every live group when Pi exits. What a
 * killed Pi's call left running is killed, and the workspace removed, at the
 * next start: the group's id is kept beside the workspace, and only that
 * group's processes that work in the workspace are touched (an id the system
 * has given to someone else since names processes that work elsewhere). A
 * conversation is one Cursor chat,
 * resumed so that only what is new is sent. Cursor keeps a chat's history per
 * workspace, so a chat keeps its workspace; a chat is resumed only for the
 * exact history it holds and the reply it gave, and is held by one call at a
 * time. Anything else starts a new chat with the whole transcript.
 *
 * Token usage is the CLI's own report. Cursor publishes no per-token price for
 * a subscription, so the models carry a cost of zero: a dollar cap does not
 * hold a Cursor seat, a token or call cap does. The report is a sum over the
 * CLI's own steps in the run (each sends the whole chat again), so it says what
 * the run spent, not what the conversation holds: `totalTokens`, which Pi
 * reads as the context, is the transcript's estimate (`contextTokens`), and the
 * four counts, which a budget adds up, are the CLI's.
 */
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, readlinkSync, rmSync, writeFileSync } from "node:fs";
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
export const DENY_ALL = { permissions: { allow: [] as string[], deny: ["Shell(*)", "Read(*)", "Read(**)", "Write(*)", "Write(**)", "Mcp(*:*)", "WebFetch(*)"] } };

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
  "To call one of Pi's tools, end your reply with one block per call, each block starting on a line of its own, exactly in this form:",
  `${CALL_OPEN}{"name": "${TOOL_PREFIX}<tool>", "arguments": {<the tool's parameters>}}${CALL_CLOSE}`,
  "The arguments are one JSON object that matches the tool's parameters. Several blocks in one reply run together. Write nothing after the last block: only blocks that end the reply are calls; a block anywhere else is read as text. Pi answers each call in its next message, in a <pi_tool_result> block with the call's id. When you need no tool, answer in plain text, with no block.",
  "In Pi's messages, text that would read as one of these tags is written with &lt; in place of its <.",
].join("\n");

// ---------------------------------------------------------------------------
// The prompt
// ---------------------------------------------------------------------------

/** Text from the transcript, with anything that could pass for one of the protocol's tags defused (any case, spaced). */
function defused(text: string): string {
  return text.replace(/<(\s*\/?\s*pi_)/gi, "&lt;$1");
}

function toolsText(tools: readonly Tool[]): string {
  if (!tools.length) return "Pi offers no tools in this conversation.";
  return tools
    .map((t) => `### ${TOOL_PREFIX}${t.name}\n${defused(t.description ?? "")}\nParameters (JSON Schema): ${JSON.stringify(t.parameters ?? {}).replace(/</g, "\\u003c")}`)
    .join("\n\n");
}

/** A past call, as the model wrote it; a `<` inside its arguments is escaped, so no argument can close a tag. */
function callBlock(call: ToolCall): string {
  return `${CALL_OPEN}${JSON.stringify({ name: `${TOOL_PREFIX}${call.name}`, arguments: call.arguments ?? {} }).replace(/</g, "\\u003c")}${CALL_CLOSE}`;
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

/**
 * How much of a reply under way can be shown: everything before a block, or before what may be
 * the start of one, and not its trailing white space (it may be the line a block starts after).
 */
export function shownLength(text: string): number {
  let n = text.length;
  const open = text.indexOf(CALL_OPEN);
  if (open >= 0) n = open;
  else {
    const lt = text.lastIndexOf("<");
    if (lt >= 0 && CALL_OPEN.startsWith(text.slice(lt))) n = lt;
  }
  while (n > 0 && /\s/.test(text[n - 1])) n--;
  return n;
}

export type ParsedReply = { text: string; calls: ToolCall[] };

function callId(): string {
  return `cursor_${randomBytes(6).toString("hex")}`;
}

const unprefixed = (name: string) => name.replace(new RegExp(`^${TOOL_PREFIX}`), "");

function namedIn(body: string): string | undefined {
  const named = /"name"\s*:\s*"([^"]{1,128})"/.exec(body)?.[1];
  return named === undefined ? undefined : unprefixed(named);
}

function parseCall(raw: string): ToolCall {
  const body = raw.trim();
  try {
    const parsed = JSON.parse(body) as unknown;
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      const { name: given, arguments: args } = parsed as { name?: unknown; arguments?: unknown };
      const name = typeof given === "string" ? unprefixed(given) : given;
      if (typeof name === "string" && name) {
        if (args === undefined) return { type: "toolCall", id: callId(), name, arguments: {} };
        if (args && typeof args === "object" && !Array.isArray(args)) return { type: "toolCall", id: callId(), name, arguments: args as ToolCall["arguments"] };
        return { type: "toolCall", id: callId(), name, arguments: {}, argumentsError: `the arguments are not a JSON object: ${JSON.stringify(args).slice(0, 400)}` };
      }
    }
  } catch {
    // reported below, with the text the model sent
  }
  return { type: "toolCall", id: callId(), name: namedIn(body) ?? "unparsed_tool_call", arguments: {}, argumentsError: `the call is not the JSON object the protocol asks for: ${body.slice(0, 400)}` };
}

/** The end of the JSON object that starts at `from`, strings and escapes honoured, read no further than `limit`: the index after its closing brace, or -1. */
function jsonObjectEnd(s: string, from: number, limit: number): number {
  if (s[from] !== "{") return -1;
  let depth = 0;
  let inString = false;
  let escaped = false;
  for (let i = from; i < limit; i++) {
    const ch = s[i];
    if (inString) {
      if (escaped) escaped = false;
      else if (ch === "\\") escaped = true;
      else if (ch === '"') inString = false;
    } else if (ch === '"') inString = true;
    else if (ch === "{") depth++;
    else if (ch === "}" && --depth === 0) return i + 1;
  }
  return -1;
}

type Block = { raw: string; end: number; closed: boolean; json?: boolean };

/** The block that opens at `at`, read no further than `limit`: its JSON (read as JSON, so a tag inside a string is the string's) and where it ends. */
function readBlock(s: string, at: number, limit: number): Block {
  let i = at + CALL_OPEN.length;
  while (i < limit && /\s/.test(s[i])) i++;
  const jsonEnd = jsonObjectEnd(s, i, limit);
  if (jsonEnd > 0) {
    let k = jsonEnd;
    while (k < limit && /\s/.test(s[k])) k++;
    if (s.startsWith(CALL_CLOSE, k) && k + CALL_CLOSE.length <= limit) return { raw: s.slice(at + CALL_OPEN.length, jsonEnd), end: k + CALL_CLOSE.length, closed: true, json: true };
  }
  const close = s.indexOf(CALL_CLOSE, at + CALL_OPEN.length);
  if (close < 0 || close + CALL_CLOSE.length > limit) return { raw: s.slice(at + CALL_OPEN.length, limit), end: limit, closed: false };
  return { raw: s.slice(at + CALL_OPEN.length, close), end: close + CALL_CLOSE.length, closed: true };
}

/** The index after the last character before `end` that is not white space. */
function trimmedEnd(s: string, end: number): number {
  let e = end;
  while (e > 0 && /\s/.test(s[e - 1])) e--;
  return e;
}

function startsLine(s: string, at: number): boolean {
  for (let i = at - 1; i >= 0 && s[i] !== "\n"; i--) if (!/\s/.test(s[i])) return false;
  return true;
}

function refused(call: ToolCall, why: string): ToolCall {
  return { ...call, arguments: {}, argumentsError: `${why}: ${call.argumentsError ?? "the call was not run"}` };
}

/** A reply is read for calls up to this size; past it, it is text (a model's reply is far smaller). */
const MAX_PARSED_REPLY = 2 * 1024 * 1024;
/** At most this many opening tags are tried for one block (each is read no further than that block's end). */
const MAX_TRIES_PER_BLOCK = 64;
const MAX_CALLS = 64;

/**
 * A finished reply: its prose and its tool calls. The calls are the blocks that end the reply,
 * read from the end back, so the work is linear in the reply. A block quoted anywhere else (an
 * injection the model reports, an example) is text; one quoted as the last thing in the reply,
 * on a line of its own, is not told apart from a call. A last block written on the same line as
 * prose, or cut off before its end, is never run: it comes back as a call whose arguments are in
 * error, so that Pi tells the model, and the turn does not end as if it were an answer.
 */
export function parseReply(reply: string): ParsedReply {
  if (reply.length > MAX_PARSED_REPLY) return { text: reply, calls: [] };
  const calls: ToolCall[] = [];
  let end = trimmedEnd(reply, reply.length);
  // A run of blocks fenced as code: the closing fence is formatting, not text after the calls.
  let fenced = false;
  if (reply.endsWith("```", end) && startsLine(reply, end - 3)) {
    const close = reply.lastIndexOf(CALL_CLOSE, end);
    if (close >= 0 && !reply.slice(close + CALL_CLOSE.length, end - 3).trim()) {
      end = trimmedEnd(reply, end - 3);
      fenced = true;
    }
  }
  // A short tail with no word in it after the last block (a full stop, a stray closing tag):
  // the blocks are calls the model made, but not as the protocol says, so they are not run;
  // they come back in error, rather than being lost and the turn ending as if it were an answer.
  // A reply that reads whole as it ends is never read for a tail.
  let tailed = false;
  const whole = parseRun(reply, end, []);
  const lastOpen = whole.calls.length ? -1 : reply.lastIndexOf(CALL_OPEN, end - 1);
  if (lastOpen >= 0) {
    const b = readBlock(reply, lastOpen, end);
    const tail = b.closed ? reply.slice(b.end, end).split(CALL_CLOSE).join("").trim() : "";
    if (b.closed && b.end < end && tail.length <= 32 && !/[\p{L}\p{N}]/u.test(tail)) {
      end = b.end;
      tailed = true;
    }
  }
  const finish = (parsed: ParsedReply): ParsedReply => {
    let text = parsed.text;
    if (fenced) text = text.replace(/\n?[ \t]*```[\w-]*[ \t]*$/, "").replace(/\s+$/, "");
    const callsOut = tailed ? parsed.calls.map((c) => refused(c, "write nothing after the last block: these calls were not run")) : parsed.calls;
    return { text, calls: callsOut };
  };
  return finish(tailed ? parseRun(reply, end, calls) : whole);
}

/** The calls of the run of blocks that ends at `end`, read from the end back. */
function parseRun(reply: string, endAt: number, calls: ToolCall[]): ParsedReply {
  let end = endAt;
  // A last block the model was cut off in: an opening tag with no end after it.
  if (!reply.startsWith(CALL_CLOSE, end - CALL_CLOSE.length)) {
    const last = reply.lastIndexOf(CALL_OPEN, end - 1);
    if (last < 0) return { text: reply, calls: [] };
    const b = readBlock(reply, last, end);
    if (b.closed) return { text: reply, calls: [] };
    calls.push({ type: "toolCall", id: callId(), name: namedIn(b.raw) ?? "unparsed_tool_call", arguments: {}, argumentsError: `the call was cut off before its end, and was not run: ${b.raw.trim().slice(0, 400)}` });
    end = trimmedEnd(reply, last);
    if (!startsLine(reply, last)) return { text: reply.slice(0, end), calls };
  }
  // Whole blocks, from the last back: each must end where the one after it begins.
  while (calls.length < MAX_CALLS && end >= CALL_CLOSE.length && reply.startsWith(CALL_CLOSE, end - CALL_CLOSE.length)) {
    // The block whose JSON reads whole and ends here; an opening tag inside an earlier block's
    // string also "ends" here when read as a malformed block, so that counts only if none reads whole.
    let found = -1;
    let malformed = -1;
    let at = reply.lastIndexOf(CALL_OPEN, end - CALL_CLOSE.length - 1);
    for (let tries = 0; at >= 0 && tries < MAX_TRIES_PER_BLOCK; tries++, at = at > 0 ? reply.lastIndexOf(CALL_OPEN, at - 1) : -1) {
      const b = readBlock(reply, at, end);
      if (b.end !== end) continue;
      if (b.json && parsesAsJson(b.raw)) {
        found = at;
        break;
      }
      if (malformed < 0) malformed = at;
    }
    if (found < 0) found = malformed;
    if (found < 0) break;
    const call = parseCall(readBlock(reply, found, end).raw);
    if (!startsLine(reply, found)) {
      calls.unshift(refused(call, "start each block on a line of its own: this call was written after text on its line, and was not run"));
      end = trimmedEnd(reply, found);
      break;
    }
    calls.unshift(call);
    end = trimmedEnd(reply, found);
  }
  if (calls.length >= MAX_CALLS && reply.startsWith(CALL_CLOSE, end - CALL_CLOSE.length)) {
    calls.unshift({ type: "toolCall", id: callId(), name: "too_many_tool_calls", arguments: {}, argumentsError: `a reply may make at most ${MAX_CALLS} calls: the ones before these were not run` });
  }
  if (!calls.length) return { text: reply, calls: [] };
  return { text: reply.slice(0, end), calls };
}

function parsesAsJson(raw: string): boolean {
  try {
    JSON.parse(raw);
    return true;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// The CLI
// ---------------------------------------------------------------------------

export function cursorBinary(env: NodeJS.ProcessEnv = process.env): string {
  if (env.CURSOR_AGENT_BIN) return env.CURSOR_AGENT_BIN;
  const local = join(homedir(), ".local", "bin", "cursor-agent");
  return existsSync(local) ? local : "cursor-agent";
}

/**
 * The CLI's own sandbox: on, unless Pi runs under a guard of its own that says otherwise
 * (`PI_CURSOR_SANDBOX=disabled`). The swarm says so for a seat it holds at the kernel: the
 * CLI's sandbox does not start inside another (a user namespace in Landlock's, a seatbelt
 * in a seatbelt), and the swarm's guard and the deny-all permissions then hold the CLI.
 */
export function cursorSandbox(env: NodeJS.ProcessEnv = process.env): "enabled" | "disabled" {
  return env.PI_CURSOR_SANDBOX === "disabled" ? "disabled" : "enabled";
}

export function cursorArgs(model: string, workspace: string, chatId?: string, sandbox: "enabled" | "disabled" = cursorSandbox()): string[] {
  return [
    "-p", "--output-format", "stream-json", "--stream-partial-output",
    "--mode", "ask", "--sandbox", sandbox, "--trust",
    "--workspace", workspace, "--model", model,
    ...(chatId ? ["--resume", chatId] : []),
  ];
}

const ENV_KEPT = [
  "HOME", "PATH", "USER", "LOGNAME", "LANG", "LC_ALL", "TERM", "TMPDIR",
  "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME",
  "CURSOR_API_KEY", "CURSOR_API_ENDPOINT",
  "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "ALL_PROXY", "https_proxy", "http_proxy", "no_proxy", "all_proxy",
  "NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE", "SSL_CERT_DIR",
];

/** The CLI's environment: what it needs to find its login, reach its service and run, and no other key Pi's process holds. */
export function cursorEnv(env: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
  const out: NodeJS.ProcessEnv = {};
  for (const k of ENV_KEPT) if (env[k] !== undefined) out[k] = env[k];
  out.NO_OPEN_BROWSER = "1";
  return out;
}

const WORKSPACE_PREFIX = "pi-cursor-";

type Workspace = { dir: string; cwd: string };

/**
 * A chat's directory, named for the Pi process that made it (`pi-cursor-<pid>-…`): the CLI's
 * workspace (`ws`, empty but for the permissions that refuse every tool of the CLI's) and, while a
 * call runs, the id of its process group (`pgid`), beside it where the CLI does not look.
 */
export function makeWorkspace(): Workspace {
  const dir = mkdtempSync(join(tmpdir(), `${WORKSPACE_PREFIX}${process.pid}-`));
  const cwd = join(dir, "ws");
  mkdirSync(join(cwd, ".cursor"), { recursive: true, mode: 0o700 });
  writeFileSync(join(cwd, ".cursor", "cli.json"), `${JSON.stringify(DENY_ALL, null, 2)}\n`, { mode: 0o600 });
  return { dir, cwd };
}

function removeDir(dir: string): void {
  try {
    rmSync(dir, { recursive: true, force: true });
  } catch {
    // left for the next start's sweep
  }
}

function killGroup(pgid: number | undefined): void {
  if (!pgid) return;
  try {
    process.kill(-pgid, "SIGKILL");
  } catch {
    // the group is gone already
  }
}

function killPid(pid: number): void {
  try {
    process.kill(pid, "SIGKILL");
  } catch {
    // gone
  }
}

/**
 * The processes of group `pgid` that work in `cwd` (or under it), from /proc (Linux; elsewhere
 * none). The group's leader may be gone while what it started lives on; and a group id the system
 * has given to someone else since names processes that work elsewhere, which are not touched.
 */
function groupMembersIn(pgid: number, cwd: string): number[] {
  const out: number[] = [];
  let pids: string[] = [];
  try {
    pids = readdirSync("/proc").filter((n) => /^\d+$/.test(n));
  } catch {
    return out;
  }
  for (const p of pids) {
    try {
      const stat = readFileSync(`/proc/${p}/stat`, "utf8");
      // pid (comm) state ppid pgrp …: comm may hold spaces and parentheses, so read after the last ")".
      const fields = stat.slice(stat.lastIndexOf(")") + 2).split(" ");
      if (Number(fields[2]) !== pgid) continue;
      const where = readlinkSync(`/proc/${p}/cwd`);
      if (where === cwd || where.startsWith(`${cwd}/`)) out.push(Number(p));
    } catch {
      // gone, or not ours to read
    }
  }
  return out;
}

function processAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code === "EPERM";
  }
}

/**
 * What a Pi process that is gone left: its chat directories, and a CLI group a call of it was
 * running (recorded in `pgid`, killed only while /proc says that group's leader is cursor-agent).
 * Only directories this user owns are touched; another live process's (another seat on this
 * host) are left alone. Returns the names removed.
 */
export function sweepWorkspaces(root: string = tmpdir()): string[] {
  const removed: string[] = [];
  let names: string[] = [];
  try {
    names = readdirSync(root);
  } catch {
    return removed;
  }
  const uid = typeof process.getuid === "function" ? process.getuid() : undefined;
  for (const name of names) {
    const m = new RegExp(`^${WORKSPACE_PREFIX}(\\d+)-`).exec(name);
    if (!m) continue;
    const pid = Number(m[1]);
    if (pid === process.pid || processAlive(pid)) continue;
    const dir = join(root, name);
    try {
      const st = lstatSync(dir);
      if (!st.isDirectory() || (uid !== undefined && st.uid !== uid)) continue;
      const pgidFile = join(dir, "pgid");
      if (existsSync(pgidFile)) {
        const pgid = Number(readFileSync(pgidFile, "utf8").trim());
        if (Number.isInteger(pgid) && pgid > 1) for (const member of groupMembersIn(pgid, join(dir, "ws"))) killPid(member);
      }
      rmSync(dir, { recursive: true, force: true });
      removed.push(name);
    } catch {
      // not ours to remove, or not removable: left
    }
  }
  return removed;
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

type Chat = { chatId: string; ws: Workspace; model: string; sent: number; prefixHash: string; replyHash: string; lastUsed: number };

const MAX_IDLE_CHATS = 16;
/** Chats no call holds. A call takes its chat out for as long as it runs, so no other call resumes or removes it. */
const idle: Chat[] = [];
/** The process groups of calls under way, with their directories: killed and removed if Pi exits. */
const live = new Map<number, string>();

function hashOf(messages: readonly Message[]): string {
  const h = createHash("sha256");
  for (const m of messages) h.update(renderMessage(m)).update("\u0000");
  return h.digest("hex");
}

/**
 * Whether a chat can carry on with these messages, and what to send it: the chat holds exactly the
 * first `sent` messages (their hash), and the next message is the reply it gave (its hash); what
 * follows that reply is new. Anything else is a new chat with the whole transcript.
 */
export function planCall(chat: Pick<Chat, "model" | "sent" | "prefixHash" | "replyHash"> | undefined, messages: readonly Message[], model: string): { resume: boolean; send: Message[] } {
  const whole = { resume: false, send: [...messages] };
  if (!chat || chat.model !== model || messages.length <= chat.sent + 1) return whole;
  if (hashOf(messages.slice(0, chat.sent)) !== chat.prefixHash) return whole;
  if (hashOf([messages[chat.sent]]) !== chat.replyHash) return whole;
  const rest = messages.slice(chat.sent + 1);
  if (rest.some((m) => m.role === "assistant")) return whole;
  return { resume: true, send: rest };
}

/** The idle chat these messages carry on, taken out for this call, or none. */
function claimChat(messages: readonly Message[], model: string): { chat?: Chat; send: Message[] } {
  for (let i = idle.length - 1; i >= 0; i--) {
    const plan = planCall(idle[i], messages, model);
    if (plan.resume) {
      const [chat] = idle.splice(i, 1);
      return { chat, send: plan.send };
    }
  }
  return { send: [...messages] };
}

function keepIdle(chat: Chat): void {
  idle.push(chat);
  while (idle.length > MAX_IDLE_CHATS) {
    idle.sort((a, b) => a.lastUsed - b.lastUsed);
    removeDir(idle.shift()!.ws.dir);
  }
}

let cleanupArmed = false;
function armCleanup(): void {
  if (cleanupArmed) return;
  cleanupArmed = true;
  process.once("exit", () => {
    for (const [pgid, dir] of live) {
      killGroup(pgid);
      removeDir(dir);
    }
    live.clear();
    for (const chat of idle.splice(0)) removeDir(chat.ws.dir);
  });
}

// ---------------------------------------------------------------------------
// The stream
// ---------------------------------------------------------------------------

type CliEvent = {
  type?: string;
  subtype?: string;
  cwd?: string;
  session_id?: string;
  timestamp_ms?: number;
  is_error?: boolean;
  message?: { content?: { text?: string }[] };
  tool_call?: Record<string, { args?: unknown; result?: Record<string, unknown> } | undefined>;
  usage?: { inputTokens?: number; outputTokens?: number; cacheReadTokens?: number; cacheWriteTokens?: number };
};

/** Counted for each call: the CLI's own tool calls the model made. */
export const ownToolCalls = { total: 0 };

/**
 * Whether a finished call of the CLI's own tools did nothing: the CLI refused it (an error, a
 * permission denied, a rejection), or it was a search of the empty workspace that found nothing,
 * or a list of tool names. Anything else ran.
 */
export function ownToolHarmless(ev: CliEvent): boolean {
  const entry = Object.entries(ev.tool_call ?? {}).find(([k]) => k.endsWith("ToolCall"));
  const result = entry?.[1]?.result;
  if (!entry || !result || typeof result !== "object") return false;
  if ("error" in result || "permissionDenied" in result || "rejected" in result) return true;
  const success = JSON.stringify(result.success ?? null);
  switch (entry[0]) {
    case "getMcpToolsToolCall":
      return true;
    case "globToolCall":
      return /"files":\[\]/.test(success) && !/"totalFiles":[1-9]/.test(success);
    case "grepToolCall":
      return !/"totalMatchedLines":[1-9]/.test(success) && !/"matches":\[\{/.test(success);
    default:
      return false;
  }
}

/** Sent, once, to a chat whose model reached for the CLI's own tools and asked Pi for nothing. */
export const CORRECTION = [
  "Pi: your own built-in tools are switched off, and the call you just made was refused: it read and ran nothing.",
  `Pi's tools are the ${TOOL_PREFIX}… tools of the first message. Call them with ${CALL_OPEN} blocks at the end of your reply, exactly as the first message says, and answer again.`,
].join(" ");

type CliRun = {
  reply: string;
  finalText?: string;
  result?: CliEvent;
  own: number;
  ranOwnTool?: string;
  refused?: string;
  timedOut: boolean;
  spawnError?: Error;
  hookError?: unknown;
  code: number | null;
  stderr: string;
};

/** One `cursor-agent -p` run in a chat's workspace: its events read, its process group killed when it ends, however it ends. */
async function runCli(
  model: Model<Api>,
  ws: Workspace,
  chatId: string | undefined,
  prompt: string,
  options: SimpleStreamOptions | undefined,
  onStart: () => void,
  onReply: (replySoFar: string) => void,
): Promise<CliRun> {
  const run: CliRun = { reply: "", own: 0, timedOut: false, code: null, stderr: "" };
  const scoped = (options as { env?: Record<string, string | undefined> } | undefined)?.env;
  let child: ChildProcess;
  try {
    child = spawn(cursorBinary(), cursorArgs(model.id, ws.cwd, chatId), { cwd: ws.cwd, env: cursorEnv({ ...process.env, ...scoped }), detached: true, stdio: ["pipe", "pipe", "pipe"] });
  } catch (err) {
    run.spawnError = err instanceof Error ? err : new Error(String(err));
    return run;
  }
  const pgid = child.pid;
  if (pgid) {
    live.set(pgid, ws.dir);
    try {
      writeFileSync(join(ws.dir, "pgid"), String(pgid), { mode: 0o600 });
    } catch {
      // the exit handler still has it
    }
  }
  const exited = new Promise<number | null>((resolve) => {
    child.once("exit", (c) => resolve(c));
    child.once("error", (err) => {
      run.spawnError = err;
      resolve(null);
    });
  });
  const lines = createInterface({ input: child.stdout!, crlfDelay: Infinity });
  // Stop reading: kill the group and close stdout, so that a process outside the group that
  // holds it open cannot keep the turn waiting.
  const stop = () => {
    killGroup(pgid);
    child.stdout?.destroy();
    lines.close();
  };
  let afterExit: NodeJS.Timeout | undefined;
  child.once("exit", () => {
    afterExit = setTimeout(stop, 1000);
    afterExit.unref();
  });
  const onAbort = () => stop();
  options?.signal?.addEventListener("abort", onAbort, { once: true });
  const timeoutMs = options?.timeoutMs ?? 15 * 60_000;
  const timer = setTimeout(() => {
    run.timedOut = true;
    stop();
  }, timeoutMs);
  let afterResult: NodeJS.Timeout | undefined;
  child.stderr?.on("data", (b: Buffer) => {
    if (run.stderr.length < 8192) run.stderr += b.toString("utf8");
  });
  child.stdin?.on("error", () => undefined);
  child.stdin?.end(prompt);

  try {
    for await (const line of lines) {
      if (!line.trim()) continue;
      let ev: CliEvent;
      try {
        const parsed = JSON.parse(line) as unknown;
        if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) continue;
        ev = parsed as CliEvent;
      } catch {
        continue;
      }
      await options?.onProviderStreamEvent?.(ev, model);
      if (ev.type === "system" && ev.subtype === "init") {
        if (ev.cwd !== ws.cwd) {
          run.refused = `cursor-agent started in ${String(ev.cwd)}, not in the call's own workspace: the call was stopped`;
          stop();
          break;
        }
        await options?.onResponse?.({ status: 200, headers: {} }, model);
        onStart();
      } else if (ev.type === "assistant") {
        const text = (ev.message?.content ?? []).map((c) => c?.text ?? "").join("");
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
      } else if (ev.type === "tool_call" && ev.subtype === "completed" && !ownToolHarmless(ev)) {
        run.ranOwnTool = Object.keys(ev.tool_call ?? {}).find((k) => k.endsWith("ToolCall")) ?? "a tool";
        stop();
        break;
      } else if (ev.type === "result") {
        run.result = ev;
        // The answer is in: a CLI that does not exit after it is not waited for.
        afterResult = setTimeout(stop, 3000);
        afterResult.unref();
      }
    }
    run.code = await Promise.race([exited, new Promise<null>((resolve) => setTimeout(() => resolve(null), 5000).unref())]);
  } catch (err) {
    run.hookError = err;
  } finally {
    clearTimeout(timer);
    if (afterResult) clearTimeout(afterResult);
    if (afterExit) clearTimeout(afterExit);
    options?.signal?.removeEventListener("abort", onAbort);
    stop();
    if (pgid) live.delete(pgid);
    try {
      rmSync(join(ws.dir, "pgid"), { force: true });
    } catch {
      // gone with its directory
    }
  }
  return run;
}

/**
 * What the conversation holds after this reply, in tokens: the whole transcript as it is sent
 * to a new chat, and the reply, at four characters a token (Pi's own estimate). The CLI's
 * count cannot say it: it adds up every step of the run.
 */
export function contextTokens(messages: readonly Message[], reply: AssistantMessage): number {
  return Math.ceil((fullPrompt(messages).length + renderMessage(reply).length) / 4);
}

/** Why a run gave no answer, or nothing when it gave one. */
function runFailure(run: CliRun, timeoutMs: number): string | undefined {
  if (run.refused) return run.refused;
  if (run.ranOwnTool) return `cursor-agent ran one of its own tools (${run.ranOwnTool}) though its permissions refuse them: the turn was stopped`;
  if (run.hookError) return `the call was stopped: ${run.hookError instanceof Error ? run.hookError.message : String(run.hookError)}`;
  if (run.timedOut) return `cursor-agent did not finish within ${Math.round(timeoutMs / 1000)} s`;
  if (run.spawnError) return `cursor-agent could not be started (${cursorBinary()}): ${run.spawnError.message}`;
  if (run.result && !run.result.is_error) return undefined;
  const said = run.stderr.trim().split("\n").slice(-3).join(" ").slice(0, 600);
  return /not logged in|unauthori[sz]ed|authentication/i.test(said)
    ? "cursor-agent is not logged in: run `cursor-agent login` on this host, or set CURSOR_API_KEY"
    : `cursor-agent ended without an answer (exit ${run.code ?? "signal"}${said ? `: ${said}` : ""})`;
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
  // What the screen holds: one text block, only ever added to.
  let shownText = "";
  let textIndex = -1;
  let textEnded = false;
  let started = false;
  let ended = false;
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
  const endText = () => {
    if (textIndex < 0 || textEnded) return;
    textEnded = true;
    stream.push({ type: "text_end", contentIndex: textIndex, content: (output.content[textIndex] as { text: string }).text, partial: output });
  };
  const addUsage = (run: CliRun) => {
    const u = run.result?.usage ?? {};
    output.usage.input += u.inputTokens ?? 0;
    output.usage.output += u.outputTokens ?? 0;
    output.usage.cacheRead += u.cacheReadTokens ?? 0;
    output.usage.cacheWrite += u.cacheWriteTokens ?? 0;
    output.usage.cost = calculateCost(model, output.usage);
  };
  const fail = (reason: "error" | "aborted", message: string) => {
    if (ended) return;
    ended = true;
    endText();
    output.stopReason = reason;
    output.errorMessage = message;
    stream.push({ type: "error", reason, error: output });
    stream.end();
  };

  void (async () => {
    armCleanup();
    const messages = context.messages;
    const { chat, send } = claimChat(messages, model.id);
    const ws = chat?.ws ?? makeWorkspace();
    const forget = () => removeDir(ws.dir);
    let prompt = chat ? deltaPrompt(send) : fullPrompt(send);
    try {
      const replaced = await options?.onPayload?.({ model: model.id, resume: chat?.chatId ?? null, prompt }, model);
      if (replaced && typeof replaced === "object" && typeof (replaced as { prompt?: unknown }).prompt === "string") prompt = (replaced as { prompt: string }).prompt;
    } catch (err) {
      forget();
      fail("error", `the call was stopped before it was sent: ${err instanceof Error ? err.message : String(err)}`);
      return;
    }
    if (options?.signal?.aborted) {
      forget();
      fail("aborted", "aborted before the call");
      return;
    }

    const timeoutMs = options?.timeoutMs ?? 15 * 60_000;
    let chatId = chat?.chatId;
    let parsed: ParsedReply = { text: "", calls: [] };
    let before = "";
    for (let attempt = 0; attempt < 2; attempt++) {
      const lead = before ? `${before}\n\n` : "";
      const run = await runCli(model, ws, chatId, attempt === 0 ? prompt : CORRECTION, options, start, (r) => {
        start();
        const part = r.slice(0, shownLength(r));
        if (part) show(lead + part);
      });
      addUsage(run);
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
      parsed = { ...parsed, text: parsed.text ? lead + parsed.text : before };
      // The model reached for the CLI's own tools (refused) and asked Pi for nothing: tell it once.
      if (!(run.own > 0 && parsed.calls.length === 0 && chatId)) break;
      before = shownText;
    }

    start();
    // What was shown is a prefix of the final prose (white space is shown only once more follows it).
    show(parsed.text);
    if (textIndex >= 0 && (output.content[textIndex] as { text: string }).text !== parsed.text) (output.content[textIndex] as { text: string }).text = parsed.text;
    endText();
    for (const call of parsed.calls) {
      output.content.push(call);
      const index = output.content.length - 1;
      stream.push({ type: "toolcall_start", contentIndex: index, partial: output });
      stream.push({ type: "toolcall_end", contentIndex: index, toolCall: call, partial: output });
    }
    output.stopReason = parsed.calls.length ? "toolUse" : "stop";
    output.usage.totalTokens = contextTokens(messages, output);
    if (chatId) {
      output.responseId = chatId;
      keepIdle({ chatId, ws, model: model.id, sent: messages.length, prefixHash: hashOf(messages), replyHash: hashOf([output]), lastUsed: Date.now() });
    } else {
      forget();
    }
    ended = true;
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

/** For tests: forget every chat and count. */
export function _resetChatsForTests(): void {
  for (const chat of idle.splice(0)) removeDir(chat.ws.dir);
  ownToolCalls.total = 0;
}
