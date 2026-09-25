/**
 * A tool that writes its own trace row must be one the tool_result hook
 * leaves alone, or every call is on the trace twice: run s6725ba had 58
 * publish_file and 36 name calls each recorded both as themselves and as a
 * generic `{ok, output}` row. Read from the source: every tool the extension
 * registers whose execute calls logEvent with its own name is in SWARM_TOOLS.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { join } from "node:path";

const ROOT = join(import.meta.dirname, "..");

test("every tool that traces itself is skipped by the generic trace hook", async () => {
  const src = await readFile(join(ROOT, "extensions", "agent-swarm.ts"), "utf8");
  const set = /const SWARM_TOOLS = new Set\(\[([\s\S]*?)\]\);/.exec(src);
  assert.ok(set, "SWARM_TOOLS is where it was");
  const owned = new Set([...set[1].matchAll(/"([a-z_]+)"/g)].map((m) => m[1]));
  // Tools, not the trace's other events (agent_start, hub_lost, …), which
  // also go through logEvent but are never a tool_result.
  const registered = new Set([...src.matchAll(/registerTool\(\{\s*name:\s*"([a-z_]+)"/g)].map((m) => m[1]));
  const selfLogged = new Set([...src.matchAll(/logEvent\([^,]+,\s*agentId,\s*"([a-z_]+)"/g)].map((m) => m[1]).filter((name) => registered.has(name)));
  const compact = await readFile(join(ROOT, "extensions", "self-compact.ts"), "utf8");
  if (/SELF_COMPACT_TOOL = "self_compact"/.test(compact)) selfLogged.add("self_compact");
  assert.ok(selfLogged.size >= 10, `the scan found the self-tracing tools (${[...selfLogged].join(", ")})`);
  const missing = [...selfLogged].filter((name) => !owned.has(name)).sort();
  assert.deepEqual(missing, [], `these trace themselves and would be traced again by the hook: ${missing.join(", ")}`);
  for (const name of ["name", "publish_file", "skill", "self_compact"]) assert.ok(owned.has(name), `${name} is skipped by the hook`);
});
