/**
 * The lines of a seat's prompt that hold for the whole run (extensions/seat-prompt.ts,
 * scripts/seat-prompt.ts): worded in one place, written at kickoff to two files Pi
 * appends to its own prompt sections, recognised by the extension in the prompt it is
 * given, and the two rules that change during a run reaching the run a hand-off
 * starts through the hand-off header. The same lines surviving a real hand-off,
 * through the real CLI, is tests/skills-e2e.test.ts.
 */
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { access, chmod, lstat, mkdir, mkdtemp, readdir, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { test } from "node:test";
import { budgetPressure, capSteerText, EVENTS_REL, initSandbox } from "../extensions/protocol.ts";
import { forgedHandoffLine, forgedSoFarLine, FORGE_PROMPT_LINE, inputsPromptLine, measuredInputsLine, runPromptLines, SELF_COMPACT_PROMPT_LINE, seatPromptLine } from "../extensions/seat-prompt.ts";
import { handoffHeader } from "../extensions/self-compact.ts";
import { readPackIndex, renderSkillsSection } from "../extensions/skills.ts";
import { twoPacks } from "./fixtures/skill-packs.ts";

const REPO = resolve(import.meta.dirname, "..");
const SCRIPT = join(REPO, "scripts", "seat-prompt.ts");

const INPUTS = { source: "/cases/evidence", files: [{ path: "inputs/a.txt", bytes: 5, sha256: "0".repeat(64) }, { path: "inputs/b.txt", bytes: 2_000, sha256: "1".repeat(64) }], bytes: 2_005 };

test("the lines are worded once: the seat's id and the stop rule, the inputs rule, the forging rule, the self-compaction mechanics", () => {
  assert.equal(seatPromptLine("s1234500"), "Your assigned id is s1234500. Use it on every post and claim. If done/SWARM_DONE exists on this turn, call done and stop.");
  const one = inputsPromptLine(INPUTS);
  assert.match(one, /^Read-only inputs: 2 file\(s\), 2 KB under inputs\/ \(from \/cases\/evidence\)\. Read them with read, grep or bash as much as you like\. Never write, delete, move or chmod anything under inputs\/: a write is refused or, where it gets through, detected, undone from the pristine copy and announced on the board\./);
  assert.ok(!/by the kernel/.test(one), "the rule claims what holds in every pane, not what one pane measured");
  // Evidence held in place (bind, or an attached image) has no copy to restore from: the rule does not say it is undone.
  for (const held of ["bind", "image"]) {
    const inPlace = inputsPromptLine({ ...INPUTS, held });
    assert.match(inPlace, /a write is refused or, where it gets through, detected and announced on the board \(there is no copy to restore it from\)\./, held);
    assert.ok(!/undone|pristine/.test(inPlace), `${held}: nothing is undone`);
  }
  assert.equal(inputsPromptLine({ ...INPUTS, held: "copy" }), one, "a copied run is the default");
  const sets = inputsPromptLine({ ...INPUTS, sets: [{ name: "disk", path: "inputs/disk", source: "/cases/disk", files: 1, bytes: 5 }, { name: "mem", path: "inputs/mem", source: "", files: 1, bytes: 2_000 }] } as never);
  assert.match(sets, /in 2 sets, inputs\/disk\/ \(from \/cases\/disk\), inputs\/mem\/ \(from the operator\)\./);
  assert.match(measuredInputsLine("kernel"), /^In this pane the kernel refuses a write to inputs\/ \(measured when it started\)\.$/);
  assert.match(measuredInputsLine("mode"), /^This pane has no kernel guard on inputs\/ \(measured when it started\): the tools refuse a write through write or edit, and a write that gets through a shell is detected, undone from the pristine copy and announced on the board\.$/);
  assert.match(measuredInputsLine("none", "bind"), /a write that gets through a shell is detected and announced on the board \(there is no copy to restore it from\)\.$/, "in place, a pane without the kernel guard cannot undo a write, and does not say it does");
  assert.ok(!/undone/.test(measuredInputsLine("none", "image")));
  assert.equal(forgedSoFarLine([]), "Nothing has been forged yet.");
  assert.equal(forgedHandoffLine([]), "Tool forging is on. Nothing has been forged yet. Call `tools` before you forge one, in case a peer has.", "nothing to see, so nothing for 'them' to refer to");
  assert.equal(forgedHandoffLine([{ name: "count_lines", by: "s1", version: 2 }]), "Tool forging is on. Forged so far: count_lines (by s1, v2). Call `tools` to see them.");
  assert.equal(forgedSoFarLine([{ name: "count_lines", by: "s1", version: 2 }, { name: "carve", by: "s2", version: 1 }]), "Forged so far: count_lines (by s1, v2), carve (by s2, v1).");
  assert.ok(FORGE_PROMPT_LINE.startsWith("Tool forging is on for this swarm.") && !FORGE_PROMPT_LINE.includes("Forged so far"));
  assert.ok(SELF_COMPACT_PROMPT_LINE.startsWith("Self-compaction is on.") && SELF_COMPACT_PROMPT_LINE.length > 800);
  assert.deepEqual(runPromptLines({ inputs: null, forging: false, selfCompact: false }), []);
  assert.deepEqual(runPromptLines({ inputs: INPUTS, forging: true, selfCompact: true }), [SELF_COMPACT_PROMPT_LINE, inputsPromptLine(INPUTS), FORGE_PROMPT_LINE]);
});

test("scripts/seat-prompt.ts writes the run's file and each seat's own, an empty run file when nothing applies, and says what it wrote", async () => {
  const root = await mkdtemp(join(tmpdir(), "seat-prompt-"));
  try {
    const run = (sandbox: string, ...rest: string[]) => JSON.parse(execFileSync("node", ["--experimental-strip-types", "--no-warnings", SCRIPT, "--sandbox", sandbox, ...rest], { encoding: "utf8" })) as Record<string, unknown> & { packs?: Array<{ id: string }>; lines: string[]; seats: string[] };

    // Nothing applies: no pack, no inputs, no forging, no self-compaction. The file is there and empty (it shadows an operator's global one).
    const bare = join(root, "bare");
    const report = run(bare, "--seat", "agent00", "--seat", "agent01");
    assert.deepEqual([report.written, report.lines, report.seats], [false, [], ["agent00", "agent01"]]);
    assert.equal(await readFile(join(bare, ".pi", "APPEND_SYSTEM.md"), "utf8"), "");
    assert.equal(await readFile(join(bare, ".pi", "seat-agent01.md"), "utf8"), `${seatPromptLine("agent01")}\n`);

    // Everything applies: the index first, then the lines, blank-line separated, one trailing newline.
    const full = join(root, "full");
    await mkdir(full, { recursive: true });
    await writeFile(join(full, "inputs.json"), JSON.stringify({ ...INPUTS, copied_at: "2026-10-07T00:00:00.000Z", enforce: "auto", guard: "none" }));
    const { a, b } = await twoPacks(root);
    const out = run(full, "--self-compact", "--forging", "--seat", "agent00", "--pack-dir", a, "--pack-dir", b);
    assert.deepEqual([out.written, out.lines, out.packs?.map((p) => p.id)], [true, ["self_compact", "inputs", "forging"], ["pack-a", "pack-b"]]);
    const index = renderSkillsSection(await Promise.all([a, b].map((d) => readPackIndex(d)))).text;
    assert.equal(await readFile(join(full, ".pi", "APPEND_SYSTEM.md"), "utf8"), `${[index, SELF_COMPACT_PROMPT_LINE, inputsPromptLine(INPUTS), FORGE_PROMPT_LINE].join("\n\n")}\n`);

    // The probe's line is written alone: the run's file is not touched.
    await writeFile(join(full, ".pi", "APPEND_SYSTEM.md"), "kept\n");
    run(full, "--seats-only", "--seat", "agent00pv");
    assert.equal(await readFile(join(full, ".pi", "APPEND_SYSTEM.md"), "utf8"), "kept\n");
    assert.equal(await readFile(join(full, ".pi", "seat-agent00pv.md"), "utf8"), `${seatPromptLine("agent00pv")}\n`);

    // Packs with no skills write no index, and a pack whose index cannot be read is reported with the rest written.
    const tools = join(root, "tools-only");
    await mkdir(join(tools, "tools"), { recursive: true });
    assert.equal(run(bare, "--pack-dir", tools).written, false);
    const broken = join(root, "broken");
    await mkdir(join(broken, "skills"), { recursive: true });
    const partial = run(bare, "--pack-dir", a, "--pack-dir", broken);
    assert.equal(partial.written, true);
    assert.deepEqual((partial.unreadable as Array<{ pack: string }>).map((u) => u.pack), ["broken"]);

    // A link planted at a name is replaced, never written through (a host pane's shell can write the sandbox, and a
    // resume runs the kickoff again in it): both targets outside the sandbox stay as they were.
    const planted = join(root, "planted");
    await mkdir(join(planted, ".pi"), { recursive: true });
    const outside = join(root, "outside");
    await mkdir(outside);
    await writeFile(join(outside, "run.txt"), "keep the run file\n");
    await writeFile(join(outside, "seat.txt"), "keep the seat file\n");
    await symlink(join(outside, "run.txt"), join(planted, ".pi", "APPEND_SYSTEM.md"));
    await symlink(join(outside, "seat.txt"), join(planted, ".pi", "seat-agent00.md"));
    run(planted, "--self-compact", "--seat", "agent00");
    assert.equal(await readFile(join(outside, "run.txt"), "utf8"), "keep the run file\n", "the run file's target is untouched");
    assert.equal(await readFile(join(outside, "seat.txt"), "utf8"), "keep the seat file\n", "the seat file's target is untouched");
    for (const name of ["APPEND_SYSTEM.md", "seat-agent00.md"]) assert.ok(!(await lstat(join(planted, ".pi", name))).isSymbolicLink(), `${name} is a file of its own now`);
    assert.equal(await readFile(join(planted, ".pi", "seat-agent00.md"), "utf8"), `${seatPromptLine("agent00")}\n`);
    // A .pi that is itself a link is refused, by name.
    const linked = join(root, "linked");
    await mkdir(linked);
    await symlink(outside, join(linked, ".pi"));
    const linkedRun = spawnSync("node", ["--experimental-strip-types", "--no-warnings", SCRIPT, "--sandbox", linked, "--seat", "agent00"], { encoding: "utf8" });
    assert.equal(linkedRun.status, 1);
    assert.match(linkedRun.stderr, /^seat-prompt\.ts: .*\.pi is a link\n$/);

    // A file it cannot write is named, and the exit says it failed: the kickoff's BLOCKER says why (it used to say "Node.js v24").
    if (process.getuid?.() !== 0) {
      const stuck = join(root, "stuck");
      await mkdir(join(stuck, ".pi"), { recursive: true });
      await writeFile(join(stuck, ".pi", "seat-agent00.md"), "old\n");
      await chmod(join(stuck, ".pi"), 0o555);
      const failed = spawnSync("node", ["--experimental-strip-types", "--no-warnings", SCRIPT, "--sandbox", stuck, "--seat", "agent00"], { encoding: "utf8" });
      await chmod(join(stuck, ".pi"), 0o755);
      assert.equal(failed.status, 1);
      assert.match(failed.stderr, /^seat-prompt\.ts: (EACCES|EPERM)[^\n]*\.pi\/APPEND_SYSTEM\.md[^\n]*\n$/, failed.stderr);
    }

    // Arguments.
    for (const bad of [[], ["--sandbox", bare, "--seat", "a b"], ["--sandbox", bare, "--nope"]]) {
      assert.throws(() => execFileSync("node", ["--experimental-strip-types", "--no-warnings", SCRIPT, ...bad], { stdio: "pipe" }), /usage|seat-prompt\.ts:/);
    }
    await assert.rejects(() => access(join(root, "never")), "nothing is written outside the sandbox");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// The extension: a line the prompt already carries is not said twice; one it lacks is added
// ---------------------------------------------------------------------------

async function findLoader(): Promise<string | null> {
  const dir = join(REPO, "node_modules", "@earendil-works", "pi-coding-agent");
  const loader = join(dir, "dist", "core", "extensions", "loader.js");
  return access(loader).then(() => loader, () => null);
}

type Handler = (event: unknown, ctx: unknown) => Promise<unknown>;

async function withExtension(t: { skip: (m: string) => void }, env: Record<string, string>, run: (prompt: (base: string) => Promise<string>, root: string) => Promise<void>): Promise<void> {
  const loaderFile = await findLoader();
  if (!loaderFile) {
    t.skip("Pi package not found (npm ci)");
    return;
  }
  const { loadExtensions } = (await import(loaderFile)) as { loadExtensions: (paths: string[], cwd: string) => Promise<{ extensions: Array<{ handlers: Map<string, Handler[]> }>; errors: unknown[] }> };
  const root = await mkdtemp(join(tmpdir(), "seat-ext-"));
  const names = ["AGENT_ID", "SWARM_SELF_COMPACT", "SWARM_TOOL_FORGING", "SWARM_TOOLS", "SWARM_PACK_DIRS"];
  const keep = Object.fromEntries(names.map((n) => [n, process.env[n]]));
  try {
    await initSandbox(root, { reset: true });
    await writeFile(join(root, "inputs.json"), JSON.stringify({ ...INPUTS, copied_at: "2026-10-07T00:00:00.000Z", enforce: "auto", guard: "none" }));
    for (const n of names) delete process.env[n];
    Object.assign(process.env, { AGENT_ID: "agent00", ...env });
    const loaded = (await loadExtensions([join(REPO, "extensions", "agent-swarm.ts")], root)).extensions[0]!;
    const ctx = { cwd: root, hasUI: false, ui: {}, sessionManager: { getEntries: () => [], buildContextEntries: () => [], getBranch: () => [] } };
    await run(async (base) => {
      let forced = "";
      for (const h of loaded.handlers.get("before_agent_start") ?? []) {
        const out = (await h({ type: "before_agent_start", prompt: "go", systemPrompt: base, systemPromptOptions: { cwd: root } }, ctx)) as { systemPrompt?: string } | undefined;
        if (out?.systemPrompt) forced = out.systemPrompt;
      }
      return forced;
    }, root);
  } finally {
    for (const n of names) {
      if (keep[n] === undefined) delete process.env[n];
      else process.env[n] = keep[n];
    }
    await rm(root, { recursive: true, force: true });
  }
}

const count = (text: string, part: string) => text.split(part).length - 1;
const rowsOf = async (root: string, tool: string) =>
  (await readFile(join(root, EVENTS_REL), "utf8").catch(() => "")).trim().split("\n").filter(Boolean).map((l) => JSON.parse(l) as { tool: string; args: Record<string, unknown>; result: Record<string, unknown> }).filter((r) => r.tool === tool);
const EVERY_LINE = { SWARM_SELF_COMPACT: "1", SWARM_TOOL_FORGING: "1", SWARM_TOOLS: "read,bash,done" };

test("a prompt that carries no persistent line (a manual start, a sandbox from before the files) is given each once, as it always was", async (t) => {
  await withExtension(t, EVERY_LINE, async (prompt) => {
    const forced = await prompt("BASE");
    assert.ok(forced.startsWith("BASE"));
    for (const line of [seatPromptLine("agent00"), inputsPromptLine(INPUTS), FORGE_PROMPT_LINE, SELF_COMPACT_PROMPT_LINE]) assert.equal(count(forced, line), 1, line.slice(0, 50));
    assert.match(forced, /In this pane the kernel refuses|This pane has no kernel guard on inputs\//, "and what this pane measured");
    assert.match(forced, /Nothing has been forged yet\./);
    assert.match(forced, /Nobody has given you a job\./);
  });
});

test("a prompt that carries them (the kickoff's files, in Pi's own sections) is only given what changes", async (t) => {
  await withExtension(t, EVERY_LINE, async (prompt, root) => {
    const run = await readFile(join(root, "inputs.json"), "utf8");
    assert.ok(run);
    const base = `PREAMBLE\n\n<addendum>\n${[SELF_COMPACT_PROMPT_LINE, inputsPromptLine(INPUTS), FORGE_PROMPT_LINE, seatPromptLine("agent00")].join("\n\n")}\n</addendum>`;
    const forced = await prompt(base);
    for (const line of [seatPromptLine("agent00"), inputsPromptLine(INPUTS), FORGE_PROMPT_LINE, SELF_COMPACT_PROMPT_LINE]) assert.equal(count(forced, line), 1, `${line.slice(0, 50)}: said once, not twice`);
    // What changes is still said: the name, the guard this pane measured, the tools forged so far.
    assert.match(forced, /Nobody has given you a job\./);
    assert.match(forced, /This pane has no kernel guard on inputs\/ \(measured when it started\)/);
    assert.match(forced, /\n\nNothing has been forged yet\./);
    assert.ok(forced.length < base.length + 1_100, "and little else");
    // The sentinel stands: the stop is said as the order it has become, without the id line again.
    await writeFile(join(root, "done", "SWARM_DONE"), "---\nby: agent01\n---\n");
    const over = await prompt(base);
    assert.match(over, /done\/SWARM_DONE exists\. Call done\(reason, output_file\) now and stop\. Do not start new work\./);
    assert.equal(count(over, "Your assigned id is agent00."), 1);
  });
});

test("a run with no forging, no inputs and no self-compaction has none of those lines, and a sentinel is told with the id when the seat's file is missing", async (t) => {
  await withExtension(t, {}, async (prompt, root) => {
    await rm(join(root, "inputs.json"));
    const forced = await prompt("BASE");
    assert.ok(!forced.includes("Read-only inputs") && !forced.includes("Tool forging") && !forced.includes("Self-compaction is on"));
    assert.equal(count(forced, "Your assigned id is agent00."), 1);
    await writeFile(join(root, "done", "SWARM_DONE"), "---\nby: agent01\n---\n");
    const over = await prompt("BASE");
    assert.ok(over.includes("Your assigned id is agent00.") && over.includes("done/SWARM_DONE exists. Call done"));
  });
});

test("a prompt that holds the path of a prompt file that is not there (Pi took the path as the text) is a fault, once, on the trace and the board", async (t) => {
  await withExtension(t, {}, async (prompt, root) => {
    const clean = `PREAMBLE\n\n<addendum>\n${seatPromptLine("agent00")}\n</addendum>`;
    await prompt(clean);
    assert.deepEqual(await rowsOf(root, "extension_error"), [], "a prompt with its files raises nothing");
    const gone = `PREAMBLE\n\n<addendum>\n${root}/.pi/APPEND_SYSTEM.md\n\n${root}/.pi/seat-agent00.md\n</addendum>`;
    const forced = await prompt(gone);
    await prompt(gone);
    const rows = await rowsOf(root, "extension_error");
    assert.equal(rows.length, 1, "said once, however many prompts are built");
    assert.deepEqual([rows[0]!.args.where, rows[0]!.result.ok], ["prompt files", false]);
    assert.match(String(rows[0]!.result.reason), /Pi was given \.pi\/seat-agent00\.md and \.pi\/APPEND_SYSTEM\.md as the text of the prompt: the file is not there/);
    const posts = await Promise.all((await readdir(join(root, "threads", "main")).catch(() => [] as string[])).map((f) => readFile(join(root, "threads", "main", f), "utf8")));
    assert.ok(posts.some((p) => /HARNESS FAULT: agent00 was started without its prompt files/.test(p)), posts.join("\n---\n"));
    // And the seat still gets its own id: the lines the prompt lacked are added to the forced one, as for a manual start.
    assert.equal(count(forced, seatPromptLine("agent00")), 1);
  });
});

test("the cap line the forced prompt says follows the run's stop policy and cap, as the live steer does", async (t) => {
  const withCap = async (change: Record<string, unknown>, expect: (forced: string) => void) =>
    withExtension(t, {}, async (prompt, root) => {
      const file = join(root, "budget.json");
      const budget = JSON.parse(await readFile(file, "utf8")) as Record<string, unknown>;
      await writeFile(file, JSON.stringify({ ...budget, ...change }));
      expect(await prompt("BASE"));
    });
  // cap-pause (the default): the run pauses for the operator to extend it; the seat is not told to call done.
  await withCap({ stop_policy: "cap-pause", cap_usd: 1, spent_usd: 5 }, (forced) => {
    assert.match(forced, /The run's spend cap \(\$5 of \$1\) is reached: it pauses in 2 minutes, for the operator to extend it or stop it\./);
    assert.match(forced, /do not call done unless the finish line is met/);
    assert.ok(!forced.includes("Call done(reason=cannot_complete)") && !forced.includes("Call done with reason cannot_complete"));
  });
  // cap-stop: told to stop, and a token cap is worded as one.
  await withCap({ stop_policy: "cap-stop", cap_usd: 0, spent_usd: 0, cap_tokens: 1000, tokens: 5000 }, (forced) => {
    assert.ok(forced.includes("Swarm token cap hit. Call done with reason cannot_complete and stop. Do not start new work."));
    assert.ok(!forced.includes("spent_usd="), "no dollar figures for a token cap");
  });
  // Under the operator's policy a cap is advisory: nothing is said.
  await withCap({ stop_policy: "operator", until_solved: true, cap_usd: 1, spent_usd: 5 }, (forced) => {
    assert.ok(!forced.includes("is reached") && !forced.includes("cap hit"), forced.slice(-300));
  });
});

// ---------------------------------------------------------------------------
// The two rules that change reach the hand-off's run through the header
// ---------------------------------------------------------------------------

test("the hand-off header carries the cap rule the run's stop policy gives, and the tools forged so far, and neither when there is none", () => {
  const facts = { claims: [], unread: {}, ledgerTotal: 0, ledgerMine: 0, sentinel: false, spentUsd: 0 };
  const plain = handoffHeader("agent00", 1, facts, true, "threshold");
  assert.ok(!plain.includes("cap") && !plain.includes("Tool forging"));
  assert.match(plain, /do not end your turn\. Work on until SWARM\.md's definition of done is met/);
  // The words are the live steer's (capSteerText), so the header cannot disagree with it: under cap-pause the run pauses for the
  // operator to extend it and the seat is told not to call done; the closing paragraph still says to work on.
  const pause = capSteerText({ ...budget(), stop_policy: "cap-pause" }, pressureOf({ ...budget(), stop_policy: "cap-pause" }));
  assert.match(pause, /it pauses in 2 minutes, for the operator to extend it or stop it/);
  assert.match(pause, /do not call done unless the finish line is met/);
  const header = handoffHeader("agent00", 2, { ...facts, capHit: pause, forged: "Tool forging is on. Forged so far: count_lines (by agent00, v1). Call `tools` to see them." }, true, "threshold");
  assert.ok(header.includes(`\n${pause}\n`));
  assert.ok(!header.includes("Call done(reason=cannot_complete)"), "no order to call done under cap-pause");
  assert.match(header, /\nTool forging is on\. Forged so far: count_lines \(by agent00, v1\)\. Call `tools` to see them\.\n/);
  assert.match(header, /do not end your turn\. Work on until SWARM\.md's definition of done is met/, "under cap-pause the seat works on");
  assert.ok(header.indexOf("it pauses in") < header.indexOf("This message is the harness, not a person"), "before the closing paragraph, with the facts");
  // Under cap-stop, and when the sentinel stands, the lines above order the seat to stop: the closing paragraph does not say "work on".
  const byTokens = { ...budget(), stop_policy: "cap-stop", cap_usd: 0, spent_usd: 0, cap_tokens: 1000, tokens: 5000 } as Parameters<typeof capSteerText>[0];
  const stop = capSteerText(byTokens, pressureOf(byTokens));
  assert.equal(stop, "Swarm token cap hit. Call done with reason cannot_complete and stop. Do not start new work.");
  for (const ordered of [{ capHit: stop, stopping: true }, { sentinel: true, stopping: true }]) {
    const h = handoffHeader("agent00", 3, { ...facts, ...ordered }, true, "threshold");
    assert.ok(!h.includes("Work on until") && !h.includes("do not end your turn"), JSON.stringify(ordered));
    assert.match(h, /The swarm is ending, as the lines above say: do what they say and start nothing new\./);
  }
});

function budget(): Parameters<typeof capSteerText>[0] {
  return { cap_usd: 1, spent_usd: 5, cap_tokens: 0, tokens: 0, wall_clock_minutes: 600, started_at: new Date().toISOString(), metered: true } as never;
}
function pressureOf(b: Parameters<typeof capSteerText>[0]) {
  return budgetPressure(b);
}
