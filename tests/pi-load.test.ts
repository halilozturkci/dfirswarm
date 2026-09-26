/**
 * Optional: load extensions/agent-swarm.ts through the REAL Pi extension
 * loader (jiti) and check that the `playwright` tool is the Chromium-backed
 * one. No model, no key.
 *
 * Needs an installed @earendil-works/pi-coding-agent. Resolution order:
 *   1. $PI_PACKAGE_DIR/dist/core/extensions/loader.js
 *   2. the pinned devDependency, node_modules/@earendil-works/pi-coding-agent
 *      (what `npm ci` installs, in CI too)
 *   3. `npm root -g`/@earendil-works/pi-coding-agent
 * The pinned one comes before a global Pi, so the version tested is the
 * version package.json names. Skips with a reason when none exists.
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { access, chmod, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { test } from "node:test";
import { EVENTS_REL, initSandbox, sealForgedTools } from "../extensions/protocol.ts";

const REPO = resolve(import.meta.dirname, "..");

async function findLoader(): Promise<string | null> {
  const candidates: string[] = [];
  if (process.env.PI_PACKAGE_DIR) candidates.push(process.env.PI_PACKAGE_DIR);
  candidates.push(join(REPO, "node_modules", "@earendil-works", "pi-coding-agent"));
  try {
    const globalRoot = execFileSync("npm", ["root", "-g"], { encoding: "utf8" }).trim();
    candidates.push(join(globalRoot, "@earendil-works", "pi-coding-agent"));
  } catch {
    // npm missing
  }
  for (const dir of candidates) {
    const loader = join(dir, "dist", "core", "extensions", "loader.js");
    try {
      await access(loader);
      return loader;
    } catch {
      // try next
    }
  }
  return null;
}

type LoadedTool = { definition: { execute: (...args: unknown[]) => Promise<{ details: Record<string, unknown>; isError?: boolean }> } };
type LoadedExtension = { path: string; tools: Map<string, LoadedTool>; handlers: Map<string, unknown[]> };

/** What swarm.sh --inputs leaves behind, for a loader test: copy, pristine clone, no write bits, inputs.json. */
async function seedInputs(root: string, files: Record<string, string>): Promise<void> {
  const manifest: Array<{ path: string; bytes: number; sha256: string }> = [];
  let total = 0;
  for (const dir of ["inputs", ".inputs-pristine"]) {
    await mkdir(join(root, dir), { recursive: true });
    for (const [rel, text] of Object.entries(files)) {
      await writeFile(join(root, dir, rel), text, "utf8");
      await chmod(join(root, dir, rel), 0o444);
    }
    await chmod(join(root, dir), 0o555);
  }
  for (const [rel, text] of Object.entries(files)) {
    const bytes = Buffer.byteLength(text);
    total += bytes;
    manifest.push({ path: `inputs/${rel}`, bytes, sha256: createHash("sha256").update(text).digest("hex") });
  }
  await writeFile(join(root, "inputs.json"), JSON.stringify({ source: "/tmp/src", copied_at: new Date().toISOString(), files: manifest, bytes: total, enforce: "off", guard: "none" }));
}

test("Pi loader: agent-swarm.ts loads and `playwright` is the real browser tool", async (t) => {
  const loaderPath = await findLoader();
  if (!loaderPath) {
    t.skip("Pi package not found (set PI_PACKAGE_DIR or npm install -g @earendil-works/pi-coding-agent)");
    return;
  }
  const { loadExtensions } = (await import(loaderPath)) as {
    loadExtensions: (paths: string[], cwd: string) => Promise<{ extensions: LoadedExtension[]; errors: unknown[] }>;
  };
  const root = await mkdtemp(join(tmpdir(), "slice2-pi-load-"));
  const previousAgent = process.env.AGENT_ID;
  process.env.AGENT_ID = "agent00";
  try {
    await initSandbox(root, { reset: true });
    const result = await loadExtensions([join(REPO, "extensions", "agent-swarm.ts")], root);
    assert.deepEqual(result.errors, []);
    const [swarm] = result.extensions;
    assert.ok(swarm.tools.has("playwright"), "playwright tool registered");
    assert.ok(swarm.tools.has("file_history") && swarm.tools.has("done"), "base tools still present");

    const ctx = { cwd: root, hasUI: false, ui: {} };
    const playwright = swarm.tools.get("playwright")!.definition;
    await assert.rejects(
      () => playwright.execute("t1", { target: "https://example.com/" }, undefined, undefined, ctx),
      /remote target refused/,
    );
    await writeFile(join(root, "work", "page.html"), "<title>T</title><p id=a>hello</p>", "utf8");
    try {
      const shot = await playwright.execute("t2", { target: "work/page.html", text_selector: "#a", screenshot: true }, undefined, undefined, ctx);
      assert.equal(shot.details.title, "T");
      assert.equal(shot.details.text, "hello");
      assert.match(String(shot.details.screenshot), /^work\/agent00\/\.browser\/.*-agent00\.png$/);
    } catch (err) {
      if (!/not installed|Executable doesn't exist|browserType.launch/i.test((err as Error).message)) throw err;
      t.diagnostic(`browser step skipped: ${(err as Error).message.split("\n")[0]}`);
    }

    const events = (await readFile(join(root, EVENTS_REL), "utf8")).trim().split("\n").map((l) => JSON.parse(l));
    assert.ok(events.every((e) => e.tool === "playwright" && e.agent === "agent00"));
    // sid and seq: the sending process and its count, so custody can tell a
    // line that reached both the chain and a spill from one that reached neither.
    assert.deepEqual(Object.keys(events[0]).sort(), ["agent", "args", "result", "seq", "sid", "tool", "ts"]);
    assert.ok(events.every((e, i) => i === 0 || e.seq > events[i - 1].seq), "one process's lines count up");
  } finally {
    if (previousAgent === undefined) delete process.env.AGENT_ID;
    else process.env.AGENT_ID = previousAgent;
    execFileSync("chmod", ["-R", "u+w", root]);
    await rm(root, { recursive: true, force: true });
  }
});

test("Pi loader: make_tool and tools exist only when the spawner turned forging on", async (t) => {
  const loaderPath = await findLoader();
  if (!loaderPath) {
    t.skip("Pi package not found");
    return;
  }
  const { loadExtensions } = (await import(loaderPath)) as {
    loadExtensions: (paths: string[], cwd: string) => Promise<{ extensions: LoadedExtension[]; errors: unknown[] }>;
  };
  const previous = { agent: process.env.AGENT_ID, forging: process.env.SWARM_TOOL_FORGING, tools: process.env.SWARM_TOOLS };
  const root = await mkdtemp(join(tmpdir(), "pi-load-forge-"));
  try {
    await initSandbox(root, { reset: true });
    process.env.AGENT_ID = "agent00";

    delete process.env.SWARM_TOOL_FORGING;
    const off = await loadExtensions([join(REPO, "extensions", "agent-swarm.ts")], root);
    assert.deepEqual(off.errors, []);
    assert.ok(!off.extensions[0].tools.has("make_tool") && !off.extensions[0].tools.has("tools"), "forging is off by default");
    assert.ok(off.extensions[0].tools.has("inputs"), "the inputs tool is always registered; it answers 'none' when the swarm has no inputs");

    process.env.SWARM_TOOL_FORGING = "1";
    process.env.SWARM_TOOLS = "read,bash,post,inbox,wait,done";
    const on = await loadExtensions([join(REPO, "extensions", "agent-swarm.ts")], root);
    assert.deepEqual(on.errors, []);
    const [swarm] = on.extensions;
    assert.ok(swarm.tools.has("make_tool") && swarm.tools.has("tools"), "forging tools registered");

    // Forge through the real tool definition, then run the forged tool through
    // the definition the loader hands back for it.
    const ctx = { cwd: root, hasUI: false, ui: {} };
    const make = swarm.tools.get("make_tool")!.definition;
    const made = await make.execute("t1", { name: "count_lines", description: "Count lines", runtime: "python3", script: "import json,sys\nprint(sum(1 for _ in open(json.load(sys.stdin)['path'])))\n", params: { path: { type: "string", required: true } } }, undefined, undefined, ctx);
    assert.equal(made.details.ok, true);
    assert.ok(swarm.tools.has("count_lines"), "the forged tool is registered in the forging session");
    const count = swarm.tools.get("count_lines")!.definition;
    const ran = await count.execute("t2", { path: "team.json" }, undefined, undefined, ctx);
    assert.equal(ran.details.ok, true);

    const refused = await make.execute("t3", { name: "read", description: "shadow", runtime: "bash", script: "echo" }, undefined, undefined, ctx);
    assert.equal(refused.details.ok, false);

    // Read-only inputs through the real extension: a forged tool that writes
    // an input is healed under the tool's own name, and `done` heals what a
    // background process changed between tool calls.
    await seedInputs(root, { "a.txt": "keep me\n" });
    const tamper = await make.execute("t4", { name: "tamper", description: "Write an input", runtime: "python3", script: "import os\nos.chmod('inputs', 0o755)\nos.chmod('inputs/a.txt', 0o644)\nopen('inputs/a.txt', 'w').write('from a tool\\n')\nprint('wrote')\n" }, undefined, undefined, ctx);
    assert.equal(tamper.details.ok, true);
    const wrote = await swarm.tools.get("tamper")!.definition.execute("t5", {}, undefined, undefined, ctx);
    assert.equal(wrote.details.ok, true, "the tool itself succeeds; the harness heals after it");
    assert.equal(await readFile(join(root, "inputs", "a.txt"), "utf8"), "keep me\n", "healed right after the forged tool ran");
    let trace = (await readFile(join(root, EVENTS_REL), "utf8")).trim().split("\n").map((l) => JSON.parse(l));
    const viaTool = trace.find((e) => e.tool === "inputs_violation" && e.args.tool === "tamper");
    assert.ok(viaTool && viaTool.result.healed === "restored", `inputs_violation logged under the tool's name: ${JSON.stringify(viaTool)}`);

    // A change nobody's tool call bracketed (a background process) is healed by done.
    await chmod(join(root, "inputs", "a.txt"), 0o644);
    await writeFile(join(root, "inputs", "a.txt"), "changed in the background\n");
    const done = swarm.tools.get("done")!.definition;
    // A goal may ask the finish line for the harness's own inputs check (the
    // case presets do): that event has to be on the trace before the checks
    // run, or the check can never pass. On run s57e9 it landed after them.
    const goal = (await readFile(join(root, "SWARM.md"), "utf8")).split("\n");
    const checksAt = goal.findIndex((l) => l.trim() === "## Checks");
    let lastCheck = checksAt + 1;
    while (goal[lastCheck + 1] !== undefined && (goal[lastCheck + 1].startsWith("- `") || goal[lastCheck + 1].trim() === "")) lastCheck += 1;
    while (goal[lastCheck].trim() === "") lastCheck -= 1;
    goal.splice(lastCheck + 1, 0, "- `grep -q '\"tool\":\"inputs_check\"' traces/events.jsonl`");
    await writeFile(join(root, "SWARM.md"), goal.join("\n"));
    // The finish line reads the operator's checks from the registry, never the
    // agent-writable SWARM.md, as a real run does through SWARM_RUNS_DIR.
    const runsDir = await mkdtemp(join(tmpdir(), "pi-load-runs-"));
    await writeFile(join(runsDir, "registry.json"), JSON.stringify({ runs: [{ id: "t", sandbox: root, goal: goal.join("\n") }] }));
    const priorRunsDir = process.env.SWARM_RUNS_DIR;
    process.env.SWARM_RUNS_DIR = runsDir;
    // The finish line runs at the moment done is called. The hello goal wants
    // work/hello.txt with every id in team.json, and nothing has written it:
    // this done is refused, told which check fails, and the trace says so.
    const early = await done.execute("t6a", { reason: "definition_of_done_met", output_file: "work/hello.txt" }, undefined, undefined, ctx);
    assert.equal(early.isError, true, "done before the finish line is refused");
    assert.equal(early.details.ok, false);
    assert.match(String(early.details.failing), /work\/hello\.txt/, `the first failing check is named: ${JSON.stringify(early.details)}`);
    trace = (await readFile(join(root, EVENTS_REL), "utf8")).trim().split("\n").map((l) => JSON.parse(l));
    const gate = trace.filter((e) => e.tool === "finish_line").pop();
    assert.ok(gate && gate.result.ok === false && gate.result.total === 3, `finish_line event on the trace: ${JSON.stringify(gate)}`);
    assert.equal(gate.result.passed, 1, "the inputs_check grep already passes on the refused call: the event precedes the checks");
    const firstCheck = trace.findIndex((e) => e.tool === "inputs_check");
    const firstGate = trace.findIndex((e) => e.tool === "finish_line");
    assert.ok(firstCheck !== -1 && firstCheck < firstGate, `inputs_check (${firstCheck}) is on the trace before finish_line (${firstGate})`);
    // Meet it; then done goes through, and heals the background change on the way.
    const team = JSON.parse(await readFile(join(root, "team.json"), "utf8")) as { agents: Array<{ id: string }> };
    await mkdir(join(root, "work"), { recursive: true });
    await writeFile(join(root, "work", "hello.txt"), team.agents.map((a) => a.id).join("\n") + "\n");
    const ended = await done.execute("t6", { reason: "definition_of_done_met", output_file: "work/hello.txt" }, undefined, undefined, ctx);
    assert.equal(ended.details.terminate, true, `done goes through once the checks, the inputs_check grep among them, pass: ${JSON.stringify(ended.details)}`);
    if (priorRunsDir === undefined) delete process.env.SWARM_RUNS_DIR;
    else process.env.SWARM_RUNS_DIR = priorRunsDir;
    await rm(runsDir, { recursive: true, force: true });
    assert.equal(await readFile(join(root, "inputs", "a.txt"), "utf8"), "keep me\n", "done healed the background change");
    trace = (await readFile(join(root, EVENTS_REL), "utf8")).trim().split("\n").map((l) => JSON.parse(l));
    const viaDone = trace.find((e) => e.tool === "inputs_violation" && e.args.tool === "done");
    assert.ok(viaDone && viaDone.result.healed === "restored", "the heal at done is on the trace");
    const check = trace.filter((e) => e.tool === "inputs_check").at(-1);
    assert.ok(check && check.result.ok === true && check.result.checked === 1, "and the check after it is clean");

    const events = (await readFile(join(root, EVENTS_REL), "utf8")).trim().split("\n").map((l) => JSON.parse(l));
    const kinds = events.map((e) => e.tool);
    assert.ok(kinds.includes("make_tool") && kinds.includes("tool_loaded") && kinds.includes("count_lines"), `trace has the forge, the load and the call: ${kinds.join(",")}`);
    const call = events.find((e) => e.tool === "count_lines");
    assert.equal(call.result.forged, true);
    assert.equal(call.result.by, "agent00");
  } finally {
    if (previous.agent === undefined) delete process.env.AGENT_ID;
    else process.env.AGENT_ID = previous.agent;
    if (previous.forging === undefined) delete process.env.SWARM_TOOL_FORGING;
    else process.env.SWARM_TOOL_FORGING = previous.forging;
    if (previous.tools === undefined) delete process.env.SWARM_TOOLS;
    else process.env.SWARM_TOOLS = previous.tools;
    execFileSync("chmod", ["-R", "u+w", root]);
    await rm(root, { recursive: true, force: true });
  }
});

test("Pi loader: record and ledger are real tools and the ledger renders after every record", async (t) => {
  const loaderPath = await findLoader();
  if (!loaderPath) {
    t.skip("Pi package not found");
    return;
  }
  const { loadExtensions } = (await import(loaderPath)) as {
    loadExtensions: (paths: string[], cwd: string) => Promise<{ extensions: LoadedExtension[]; errors: unknown[] }>;
  };
  const previousAgent = process.env.AGENT_ID;
  const root = await mkdtemp(join(tmpdir(), "pi-load-ledger-"));
  try {
    await initSandbox(root, { reset: true });
    process.env.AGENT_ID = "agent00";
    const loaded = await loadExtensions([join(REPO, "extensions", "agent-swarm.ts")], root);
    assert.deepEqual(loaded.errors, []);
    const [swarm] = loaded.extensions;
    assert.ok(swarm.tools.has("record") && swarm.tools.has("ledger"), "record and ledger are registered");
    const ctx = { cwd: root, hasUI: false, ui: {} };
    const record = swarm.tools.get("record")!.definition;
    const ledger = swarm.tools.get("ledger")!.definition;

    const refused = await record.execute("r0", { kind: "event", value: "no time given" }, undefined, undefined, ctx);
    assert.equal(refused.details.ok, false);

    const one = await record.execute("r1", { kind: "event", value: "Web shell uploaded", ts: "2015-09-02T09:00:00Z", source: "IIS log", evidence: "u_ex150902.log line 1201" }, undefined, undefined, ctx);
    assert.equal(one.details.ok, true);
    assert.equal(one.details.seq, 1);
    const two = await record.execute("r2", { kind: "ioc", value: "c:\\inetpub\\wwwroot\\cmd.aspx", source: "MFT", evidence: "inode 126755-128-1", confidence: "high" }, undefined, undefined, ctx);
    assert.equal(two.details.ok, true);
    assert.equal(two.details.total, 2);

    const md = await readFile(join(root, "ledger", "ledger.md"), "utf8");
    assert.match(md, /Web shell uploaded/);
    assert.match(md, /cmd\.aspx/);

    const listed = await ledger.execute("l1", { kind: "ioc" }, undefined, undefined, ctx);
    assert.equal((listed.details.entries as unknown[]).length, 1);

    const events = (await readFile(join(root, EVENTS_REL), "utf8")).trim().split("\n").map((l) => JSON.parse(l));
    const kinds = events.map((e) => e.tool);
    assert.deepEqual(kinds.filter((k) => k === "record").length, 3, "every record call, refused or not, is on the trace");
    assert.ok(kinds.includes("ledger"));
    const refusedEvent = events.find((e) => e.tool === "record" && e.result.ok === false);
    assert.match(String(refusedEvent.result.reason), /needs a ts/);
  } finally {
    if (previousAgent === undefined) delete process.env.AGENT_ID;
    else process.env.AGENT_ID = previousAgent;
    execFileSync("chmod", ["-R", "u+w", root]);
    await rm(root, { recursive: true, force: true });
  }
});

test("Pi loader: a pack's seeded tools are in the list with forging off, and its secrets stay out of the record", async (t) => {
  const loaderPath = await findLoader();
  if (!loaderPath) {
    t.skip("Pi package not found (set PI_PACKAGE_DIR or npm install -g @earendil-works/pi-coding-agent)");
    return;
  }
  const { loadExtensions } = (await import(loaderPath)) as {
    loadExtensions: (paths: string[], cwd: string) => Promise<{ extensions: LoadedExtension[]; errors: unknown[] }>;
  };
  const root = await mkdtemp(join(tmpdir(), "pi-load-pack-"));
  const secretDir = await mkdtemp(join(tmpdir(), "pi-load-pack-secret-"));
  const saved = { forging: process.env.SWARM_TOOL_FORGING, secrets: process.env.SWARM_PACK_SECRETS };
  try {
    await initSandbox(root, { reset: true });
    process.env.AGENT_ID = "agent00";
    // What swarm.sh leaves for a pack tool: the directory, a manifest naming
    // the pack, and the seal in file history.
    const script = "import json, os, sys\nargs = json.load(sys.stdin)\nprint('key=' + os.environ.get('VT_API_KEY', 'none') + ' q=' + args['q'])\n";
    await mkdir(join(root, "tools", "pack_lookup"), { recursive: true });
    await writeFile(join(root, "tools", "pack_lookup", "run.py"), script);
    await writeFile(
      join(root, "tools", "pack_lookup", "manifest.json"),
      JSON.stringify({
        name: "pack_lookup", description: "Look something up", params: { q: { type: "string", required: true } },
        runtime: "python3", entry: "run.py", timeout_seconds: 30, by: "pack-author", at: new Date().toISOString(),
        version: 1, sha256: createHash("sha256").update(script).digest("hex"), pack: "intel-pack",
      }),
    );
    await sealForgedTools(root);
    const secretFile = join(secretDir, "secrets.env");
    await writeFile(secretFile, "VT_API_KEY=s3cr3t-value-123\n");
    process.env.SWARM_PACK_SECRETS = JSON.stringify({ "intel-pack": { names: ["VT_API_KEY"], file: secretFile } });
    delete process.env.SWARM_TOOL_FORGING;

    const loaded = await loadExtensions([join(REPO, "extensions", "agent-swarm.ts")], root);
    assert.deepEqual(loaded.errors, []);
    const [swarm] = loaded.extensions;
    const ctx = { cwd: root, hasUI: false, ui: {} };
    for (const handler of (swarm.handlers.get("session_start") ?? []) as Array<(e: unknown, c: unknown) => Promise<unknown>>) {
      await handler({}, ctx);
    }
    assert.ok(swarm.tools.has("pack_lookup"), "a pack tool is registered with forging off");
    assert.ok(!swarm.tools.has("make_tool"), "and forging itself stays off");

    const out = await swarm.tools.get("pack_lookup")!.definition.execute("p1", { q: "s3cr3t-value-123" }, undefined, undefined, ctx);
    const text = JSON.stringify(out);
    assert.ok(!text.includes("s3cr3t-value-123"), `the value is not handed back to the model: ${text}`);
    assert.match(text, /key=\[secret VT_API_KEY\]/, "the tool had the secret in its own environment");
    const trace = await readFile(join(root, EVENTS_REL), "utf8");
    assert.ok(!trace.includes("s3cr3t-value-123"), "nor written to the trace");
    const row = trace.trim().split("\n").map((l) => JSON.parse(l)).find((e) => e.tool === "pack_lookup");
    assert.deepEqual(row.result.secrets, ["VT_API_KEY"], "the trace says which secret the call used");
  } finally {
    if (saved.forging === undefined) delete process.env.SWARM_TOOL_FORGING; else process.env.SWARM_TOOL_FORGING = saved.forging;
    if (saved.secrets === undefined) delete process.env.SWARM_PACK_SECRETS; else process.env.SWARM_PACK_SECRETS = saved.secrets;
    await rm(root, { recursive: true, force: true });
    await rm(secretDir, { recursive: true, force: true });
  }
});

test("Pi loader: a pack tool gets its manifest's timeout, and a failed call reaches the model as an error", async (t) => {
  // Every run clamped pack tools to the forged-tool ceiling of 120 s while
  // telling the model the manifest's figure; and Pi drops an `isError` a tool
  // returns, so a failed pack tool reached the model as a success.
  const loaderPath = await findLoader();
  if (!loaderPath) {
    t.skip("Pi package not found (set PI_PACKAGE_DIR or npm install -g @earendil-works/pi-coding-agent)");
    return;
  }
  const { loadExtensions } = (await import(loaderPath)) as {
    loadExtensions: (paths: string[], cwd: string) => Promise<{ extensions: LoadedExtension[]; errors: unknown[] }>;
  };
  const root = await mkdtemp(join(tmpdir(), "pi-load-fail-"));
  const saved = process.env.SWARM_TOOL_FORGING;
  try {
    await initSandbox(root, { reset: true });
    process.env.AGENT_ID = "agent00";
    delete process.env.SWARM_TOOL_FORGING;
    const script = "import sys\nsys.stderr.write('no such hive\\n')\nsys.exit(1)\n";
    await mkdir(join(root, "tools", "slow_fail"), { recursive: true });
    await writeFile(join(root, "tools", "slow_fail", "run.py"), script);
    await writeFile(
      join(root, "tools", "slow_fail", "manifest.json"),
      JSON.stringify({
        name: "slow_fail", description: "A long pack tool that fails", params: {},
        runtime: "python3", entry: "run.py", timeout_seconds: 900, by: "pack-author", at: new Date().toISOString(),
        version: 1, sha256: createHash("sha256").update(script).digest("hex"), pack: "disk-pack",
      }),
    );
    await sealForgedTools(root);
    const loaded = await loadExtensions([join(REPO, "extensions", "agent-swarm.ts")], root);
    assert.deepEqual(loaded.errors, []);
    const [swarm] = loaded.extensions;
    const ctx = { cwd: root, hasUI: false, ui: {} };
    for (const handler of (swarm.handlers.get("session_start") ?? []) as Array<(e: unknown, c: unknown) => Promise<unknown>>) {
      await handler({}, ctx);
    }
    const tool = swarm.tools.get("slow_fail")!.definition as unknown as { description: string; execute: (...a: unknown[]) => Promise<{ content: unknown[]; details: unknown }> };
    assert.match(tool.description, /with a 900s timeout/, "a pack tool is told, and given, its manifest's timeout");
    const out = await tool.execute("c1", {}, undefined, undefined, ctx);
    assert.equal((out.details as { ok: boolean }).ok, false);
    const results = [];
    for (const handler of (swarm.handlers.get("tool_result") ?? []) as Array<(e: unknown, c: unknown) => Promise<unknown>>) {
      results.push(await handler({ type: "tool_result", toolName: "slow_fail", toolCallId: "c1", input: {}, content: out.content, details: out.details, isError: false }, ctx));
    }
    assert.ok(results.some((r) => (r as { isError?: boolean } | undefined)?.isError === true), `the failed call is not flagged as an error: ${JSON.stringify(results)}`);
  } finally {
    if (saved === undefined) delete process.env.SWARM_TOOL_FORGING; else process.env.SWARM_TOOL_FORGING = saved;
    await rm(root, { recursive: true, force: true });
  }
});
