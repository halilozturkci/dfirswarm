/**
 * A shell call in a seat's own VM has a limit (extensions/agent-swarm.ts
 * shellTimeout): one that names no timeout gets the harness's default, one
 * that names more than the most gets the most, and one stopped there is told
 * that longer work is a job. Pi's bash has no limit of its own: a seat of the
 * run s082123 waited 178 minutes on a call that never returned, and the
 * nudger leaves a working seat alone.
 */
import assert from "node:assert/strict";
import { access, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { after, test } from "node:test";
import { SHELL_TIMEOUT_DEFAULT_S, SHELL_TIMEOUT_MAX_S, shellTimeout, shellTimeoutNote } from "../extensions/agent-swarm.ts";
import { initSandbox } from "../extensions/protocol.ts";

const REPO = resolve(import.meta.dirname, "..");
const dirs: string[] = [];
after(async () => {
  for (const d of dirs) await rm(d, { recursive: true, force: true });
});

test("the limit: the default for a call that names none, the most for one that names more, the call's own otherwise; both can be set", () => {
  assert.deepEqual(shellTimeout(undefined, {}), { seconds: SHELL_TIMEOUT_DEFAULT_S, why: "default" });
  assert.deepEqual(shellTimeout(0, {}), { seconds: SHELL_TIMEOUT_DEFAULT_S, why: "default" });
  assert.deepEqual(shellTimeout("60", {}), { seconds: SHELL_TIMEOUT_DEFAULT_S, why: "default" }, "not a number: the default");
  assert.deepEqual(shellTimeout(60, {}), { seconds: 60, why: null });
  assert.deepEqual(shellTimeout(100000, {}), { seconds: SHELL_TIMEOUT_MAX_S, why: "capped", asked: 100000 });
  assert.deepEqual(shellTimeout(undefined, { SWARM_SHELL_TIMEOUT_S: "120" }), { seconds: 120, why: "default" });
  assert.deepEqual(shellTimeout(undefined, { SWARM_SHELL_TIMEOUT_S: "5000", SWARM_SHELL_TIMEOUT_MAX_S: "600" }), { seconds: 600, why: "default" }, "the default is never over the most");
  assert.match(shellTimeoutNote({ seconds: 900, why: "default" }), /names no timeout has the harness's limit of 900 s\. Run longer work as a job \(job_run/);
  assert.match(shellTimeoutNote({ seconds: 1800, why: "capped", asked: 7200 }), /the 7200 s it asked for is over the harness's limit of 1800 s/);
});

async function findLoader(): Promise<string | null> {
  const loader = join(process.env.PI_PACKAGE_DIR ?? join(REPO, "node_modules", "@earendil-works", "pi-coding-agent"), "dist", "core", "extensions", "loader.js");
  return access(loader).then(() => loader, () => null);
}

test("through the extension: the call's input gets the limit before it runs, and a call stopped at a limit the harness set is told so, on the trace too", async (t) => {
  const loaderPath = await findLoader();
  if (!loaderPath) {
    t.skip("Pi package not found (set PI_PACKAGE_DIR, or npm install)");
    return;
  }
  const S = await mkdtemp(join(tmpdir(), "shell-timeout-"));
  dirs.push(S);
  await initSandbox(S, { reset: true });
  const keep = process.env.AGENT_ID;
  process.env.AGENT_ID = "agent00";
  try {
    const { loadExtensions } = (await import(loaderPath)) as { loadExtensions: (paths: string[], cwd: string) => Promise<{ extensions: Array<{ handlers: Map<string, Array<(e: unknown, c: unknown) => Promise<unknown>>> }>; errors: unknown[] }> };
    const out = await loadExtensions([join(REPO, "extensions", "agent-swarm.ts")], S);
    assert.deepEqual(out.errors, []);
    const handlers = out.extensions[0]!.handlers;
    const ctx = { cwd: S, hasUI: false, ui: {}, abort: () => undefined, shutdown: () => undefined, sessionManager: { getEntries: () => [], buildContextEntries: () => [], getBranch: () => [] } };
    const fire = async (event: string, payload: Record<string, unknown>) => {
      const outs: unknown[] = [];
      for (const h of handlers.get(event) ?? []) outs.push(await h({ type: event, ...payload }, ctx));
      return outs;
    };
    const none: Record<string, unknown> = { command: "sleep 100000" };
    await fire("tool_call", { toolName: "bash", toolCallId: "c1", input: none });
    assert.equal(none.timeout, SHELL_TIMEOUT_DEFAULT_S, "a call that names none is given the default");
    const long: Record<string, unknown> = { command: "sleep 100000", timeout: 100000 };
    await fire("tool_call", { toolName: "bash", toolCallId: "c2", input: long });
    assert.equal(long.timeout, SHELL_TIMEOUT_MAX_S);
    const own: Record<string, unknown> = { command: "ls", timeout: 30 };
    await fire("tool_call", { toolName: "bash", toolCallId: "c3", input: own });
    assert.equal(own.timeout, 30);
    // Stopped at the limit the harness set: the note comes after Pi's own words.
    const outs = await fire("tool_result", { toolName: "bash", toolCallId: "c1", input: none, isError: true, content: [{ type: "text", text: `Command timed out after ${SHELL_TIMEOUT_DEFAULT_S} seconds` }] });
    const content = (outs.find((o) => o && typeof o === "object" && "content" in (o as object)) as { content: Array<{ text: string }> } | undefined)?.content ?? [];
    assert.match(content.map((c) => c.text).join("\n"), /Command timed out after 900 seconds\nThe call was stopped at its limit: a shell call in your VM that names no timeout has the harness's limit of 900 s/);
    const rows = (await readFile(join(S, "traces", "events.jsonl"), "utf8")).trim().split("\n").map((l) => JSON.parse(l) as { tool: string; result: Record<string, unknown> });
    assert.ok(rows.some((r) => r.tool === "shell_timeout" && r.result.seconds === 900 && r.result.why === "default"));
    // A call the model gave its own limit, stopped there: nothing added.
    const mine = await fire("tool_result", { toolName: "bash", toolCallId: "c3", input: own, isError: true, content: [{ type: "text", text: "Command timed out after 30 seconds" }] });
    assert.ok(!JSON.stringify(mine).includes("stopped at its limit"));
  } finally {
    if (keep === undefined) delete process.env.AGENT_ID;
    else process.env.AGENT_ID = keep;
  }
});
