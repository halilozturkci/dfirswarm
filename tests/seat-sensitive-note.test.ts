/**
 * A seat that reads a sensitive output is told once, per seat and job, in one sentence at the end of its tool result: the output is
 * sensitive, the run records reads of it, the value does not belong in a post, the ledger or a command line, and it goes to another job as
 * an input (docs/adr/0018). The note informs and never blocks, like the evidence-code note. The classifier is the harness's one
 * (scripts/sensitive-access.ts): the seat asks the hub, which holds the run's index, or, with no hub (a host run), runs it here.
 * The sentence is one constant, quoted word for word by the worker prompt.
 */
import assert from "node:assert/strict";
import { access, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { after, test } from "node:test";
import * as board from "../extensions/board.ts";
import { SENSITIVE_READ_NOTE, couldNameOutput, initSandbox } from "../extensions/protocol.ts";
import { boardTable, Hub } from "../scripts/vm-hub.ts";
import { fixtureFiles, writeFiles } from "./sensitive-access-fixture.ts";

const REPO = resolve(import.meta.dirname, "..");
const dirs: string[] = [];
after(async () => {
  for (const d of dirs) await rm(d, { recursive: true, force: true });
});

async function scratch(prefix: string): Promise<string> {
  const d = await mkdtemp(join(tmpdir(), prefix));
  dirs.push(d);
  return d;
}

/** A run directory with the access-record fixture's chains and jobs (j000001 secret_output, j000034 derived, j000010 not sensitive). */
async function sensitiveRun(): Promise<string> {
  const base = await scratch("seat-note-");
  return writeFiles(base, fixtureFiles({ trace: [] }));
}

test("the prompt quotes the note word for word, and says it once", async () => {
  const prompt = (await readFile(join(REPO, "prompts", "worker-system.md"), "utf8")).replace(/\s+/g, " ");
  assert.ok(prompt.includes(`"${SENSITIVE_READ_NOTE}"`), "prompts/worker-system.md quotes the constant");
  assert.equal(prompt.split(SENSITIVE_READ_NOTE).length - 1, 1, "and says it in one place");
  // The note is one sentence and says what the ADR says it is for.
  assert.equal(SENSITIVE_READ_NOTE.split(/(?<=[.!?])\s/).length, 1);
  for (const part of ["sensitive", "records reads", "post", "ledger", "command line", "another job", "input"]) assert.ok(SENSITIVE_READ_NOTE.replace("records reads of", "records reads").includes(part), part);
});

test("which calls are worth asking about: a read tool or a shell that mentions the store, the catalogue, a kept output or a job, or names no path", () => {
  assert.equal(couldNameOutput("read", { path: "store/jobs/j000001/out/values.jsonl" }), true);
  assert.equal(couldNameOutput("bash", { command: "cat store/jobs/j000001/out/x" }), true);
  assert.equal(couldNameOutput("bash", { command: "echo j000001" }), true);
  assert.equal(couldNameOutput("grep", { pattern: "x" }), true, "no path: the classifier decides");
  assert.equal(couldNameOutput("read", { path: "inputs/disk.E01" }), false);
  assert.equal(couldNameOutput("bash", { command: "ls inputs" }), false);
  assert.equal(couldNameOutput("write", { path: "store/x" }), false, "not a reading tool");
  assert.equal(couldNameOutput("read", "store/x"), false);
  assert.equal(couldNameOutput(undefined, {}), false);
});

test("the hub answers sensitiveRead with the sensitive jobs the one classifier names for the row, and a possible reach is not a read", async () => {
  const S = await sensitiveRun();
  const dir = await scratch("seat-note-hub-");
  const hub = new Hub({ sandbox: S, dir, agents: ["agent-2"], tokens: { "agent-2": "t", system: "s" }, collector: join(dir, "none.sock"), backstop: false, quiet: true, settleMs: 0, herdrBin: "/usr/bin/false", forging: false });
  assert.deepEqual(await hub.sensitiveRead({ tool: "read", args: { path: "store/jobs/j000001/out/values.jsonl" } }), ["j000001"]);
  assert.deepEqual(await hub.sensitiveRead({ tool: "bash", args: { command: "ls store/jobs/j000034/out/decrypted && cat store/jobs/j000001/out/values.jsonl" } }), ["j000001", "j000034"]);
  assert.deepEqual(await hub.sensitiveRead({ tool: "read", args: { path: "store/jobs/j000010/out/x" } }), [], "a job that is not sensitive");
  assert.deepEqual(await hub.sensitiveRead({ tool: "bash", args: { command: "cat store/jobs/*/out/*" } }), [], "a command that walks a root could reach it: not a read");
  assert.deepEqual(await hub.sensitiveRead({ tool: "write", args: { path: "store/jobs/j000001/out/values.jsonl" } }), [], "not a reading tool");
  assert.deepEqual(await hub.sensitiveRead({ tool: "read", args: "store" }), []);
  assert.deepEqual(await hub.sensitiveRead(null), []);
  // It records nothing: the hub's lines are the trace's, and a question writes none.
  await access(join(S, "traces", "events.jsonl")).then(
    async () => assert.equal((await readFile(join(S, "traces", "events.jsonl"), "utf8")).includes("sensitive_access"), false),
    () => undefined,
  );
});

test("the seat's question reaches the hub's table as sensitiveRead, and a hub that does not answer it gives none", async () => {
  assert.ok(board.REMOTE_FUNCTIONS.includes("sensitiveRead"));
  const asked: unknown[] = [];
  const table = boardTable({ sandbox: "/nowhere", settle: async () => undefined, wrote: () => undefined, sensitiveRead: async (row) => (asked.push(row), ["j000001"]) });
  const row = { tool: "read", args: { path: "store/jobs/j000001/out/values.jsonl" } };
  assert.deepEqual(await table.sensitiveRead("agent-2", ["/nowhere", row], new AbortController().signal), ["j000001"]);
  assert.deepEqual(asked, [row]);
  const bare = boardTable({ sandbox: "/nowhere", settle: async () => undefined, wrote: () => undefined });
  assert.deepEqual(await bare.sensitiveRead("agent-2", ["/nowhere", row], new AbortController().signal), []);
});

type Handler = (e: unknown, c: unknown) => Promise<unknown>;

async function findLoader(): Promise<string | null> {
  const loader = join(REPO, "node_modules", "@earendil-works", "pi-coding-agent", "dist", "core", "extensions", "loader.js");
  return access(loader).then(() => loader, () => null);
}

test("through the extension (a host run, no hub): the result ends with the note once per seat and job, never blocks, and a failed read is not a read", async (t) => {
  const loaderPath = await findLoader();
  if (!loaderPath) {
    t.skip("Pi package not found");
    return;
  }
  const { loadExtensions } = (await import(loaderPath)) as { loadExtensions: (paths: string[], cwd: string) => Promise<{ extensions: Array<{ handlers: Map<string, unknown[]> }>; errors: unknown[] }> };
  const root = await scratch("seat-note-ext-");
  const saved = { id: process.env.AGENT_ID, socket: process.env.SWARM_BOARD_SOCKET };
  try {
    await initSandbox(root, { reset: true });
    for (const [rel, text] of Object.entries(fixtureFiles({ trace: [] }))) {
      if (!rel.startsWith("run1/") || /team\.json$/.test(rel) || rel.endsWith("traces/events.jsonl")) continue;
      await mkdir(dirname(join(root, rel.slice(5))), { recursive: true });
      await writeFile(join(root, rel.slice(5)), text);
    }
    process.env.AGENT_ID = "agent-2";
    delete process.env.SWARM_BOARD_SOCKET;
    const loaded = await loadExtensions([join(REPO, "extensions", "agent-swarm.ts")], root);
    assert.deepEqual(loaded.errors, []);
    const [swarm] = loaded.extensions;
    const ctx = { cwd: root, hasUI: false, ui: {} };
    for (const h of (swarm.handlers.get("session_start") ?? []) as Handler[]) await h({}, ctx);
    let n = 0;
    const result = async (toolName: string, input: Record<string, unknown>, o: { isError?: boolean } = {}) => {
      let out: { content?: Array<{ type: string; text: string }>; isError?: boolean } | undefined;
      for (const h of (swarm.handlers.get("tool_result") ?? []) as Handler[]) {
        const r = (await h({ type: "tool_result", toolName, toolCallId: `c${(n += 1)}`, input, content: [{ type: "text", text: "the output" }], details: {}, isError: o.isError ?? false }, ctx)) as typeof out;
        if (r) out = { ...out, ...r };
      }
      return out;
    };
    const notes = (out: Awaited<ReturnType<typeof result>>) => (out?.content ?? []).filter((c) => c.text === SENSITIVE_READ_NOTE).length;
    const first = await result("read", { path: "store/jobs/j000001/out/values.jsonl" });
    assert.equal(notes(first), 1, "the first read of j000001 is told");
    assert.equal(first?.content?.[0].text, "the output", "the result is the tool's own, the note after it");
    assert.notEqual(first?.isError, true, "it informs and never blocks");
    assert.equal(notes(await result("read", { path: "store/jobs/j000001/out/values.jsonl" })), 0, "once per seat and job");
    assert.equal(notes(await result("bash", { command: "cat store/jobs/j000001/out/values.jsonl" })), 0, "by whatever tool");
    assert.equal(notes(await result("bash", { command: "ls store/jobs/j000034/out/decrypted" })), 1, "another sensitive job is told again");
    assert.equal(notes(await result("read", { path: "store/jobs/j000010/out/x" })), 0, "a job that is not sensitive");
    assert.equal(notes(await result("bash", { command: "cat store/jobs/*/out/*" })), 0, "a possible reach is not a read");
    assert.equal(notes(await result("read", { path: "store/jobs/j000037/out/x" }, { isError: true })), 0, "a failed read is not a read");
    assert.equal(notes(await result("read", { path: "store/jobs/j000037/out/x" })), 1, "and does not use up the telling");
  } finally {
    if (saved.id === undefined) delete process.env.AGENT_ID; else process.env.AGENT_ID = saved.id;
    if (saved.socket !== undefined) process.env.SWARM_BOARD_SOCKET = saved.socket;
  }
});
