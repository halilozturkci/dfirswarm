/**
 * The Linux pack: how a tool that runs a program ends it. The harness starts a tool in a process group of its own and
 * ends it by killing that group (extensions/protocol-core.ts, process.kill(-pid, SIGKILL)); a program the tool started in a
 * session of its own is outside that group and goes on running, and writing, after the tool is gone. These suites start each
 * tool the way the harness does, kill its group, and ask whether the stand-in engine and the program it started are dead.
 * The stand-ins are scripts: no real journalctl or dissect.target is on the machine that runs this.
 */
import assert from "node:assert/strict";
import { chmod, mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { JOURNAL, RECIPE, TRIAGE, TOOLS, body, gone, pidFile, refused, startDetached, tool, withCwd } from "./linux-pack-harness.ts";
import type { Json } from "./linux-pack-harness.ts";

const BEGIN = "# BEGIN SHARED PROCESS";
const END = "# END SHARED PROCESS";
const LINUX = join(TOOLS, "..");

async function pyFiles(dir: string): Promise<string[]> {
  const out: string[] = [];
  for (const e of await readdir(dir, { withFileTypes: true })) {
    const full = join(dir, e.name);
    if (e.isDirectory()) out.push(...(await pyFiles(full)));
    else if (e.name.endsWith(".py")) out.push(full);
  }
  return out;
}

async function processBlock(path: string): Promise<string> {
  const text = await readFile(path, "utf8");
  const start = text.indexOf(BEGIN);
  const end = text.indexOf(END);
  assert.ok(start >= 0 && end > start, `${path} carries the shared process block`);
  return text.slice(start, end + END.length);
}

test("the three programs that run programs carry the same process block, byte for byte, and no script of the pack starts one in a session of its own", async () => {
  const blocks = await Promise.all([JOURNAL, TRIAGE, RECIPE].map(processBlock));
  for (const other of blocks.slice(1)) assert.equal(other, blocks[0]);
  assert.ok(blocks[0].length > 3000);
  assert.match(blocks[0], /PR_SET_PDEATHSIG/);
  assert.match(blocks[0], /SIGTERM, signal\.SIGINT, signal\.SIGHUP/);
  const strip = (t: string): string => t.replace(/^\s*#.*$/gm, "").replace(/"""[\s\S]*?"""/g, "");
  for (const path of await pyFiles(LINUX)) {
    // The block's own listing of a process tree (`ps`) is the one place a program is run to completion, and it is bounded.
    const text = (await readFile(path, "utf8")).replace(blocks[0], "");
    assert.doesNotMatch(strip(text), /start_new_session|setsid|process_group|os\.setpgid|preexec_fn\s*=\s*os\./, `${path} starts a program outside the tool's process group`);
    assert.doesNotMatch(strip(text), /subprocess\.(run|call|check_output|check_call)\(/, `${path} runs a program with a call that does not end its children`);
    assert.doesNotMatch(text, /^import threading/m, `${path} uses a thread (preexec_fn and threads do not mix)`);
  }
});

/** A stand-in engine that records its pid, starts a program of its own that records its pid, and then waits. */
function engineScript(extra = ""): string {
  return `#!/usr/bin/env python3
import os, subprocess, sys, time
d = os.environ["STUB_DIR"]
${extra}
if not os.path.exists(d + "/engine.pid"):
    open(d + "/engine.pid", "w").write(str(os.getpid()))
    subprocess.Popen([sys.executable, "-c", "import os, time\\nopen(os.environ['STUB_DIR'] + '/child.pid', 'w').write(str(os.getpid()))\\ntime.sleep(300)"])
time.sleep(300)
`;
}

async function stage(cwd: string, bin: string, name: string, script: string): Promise<{ dir: string; env: Record<string, string> }> {
  const dir = join(cwd, "stub");
  await mkdir(dir, { recursive: true });
  await writeFile(join(bin, name), script);
  await chmod(join(bin, name), 0o755);
  await writeFile(join(cwd, "work", "journal"), "x");
  await writeFile(join(cwd, "inputs", "server.E01"), "image bytes\n");
  await writeFile(join(cwd, "target.json"), JSON.stringify({ paths: [join(cwd, "inputs", "server.E01")], name: "server" }));
  return { dir, env: { STUB_DIR: dir } };
}

type Case = { name: string; script: string; fake: string; args: (cwd: string) => unknown; argv?: (cwd: string) => string[] };
const CASES: Case[] = [
  { name: "journal_export", script: JOURNAL, fake: "journalctl", args: () => ({ path: "work/journal" }) },
  { name: "linux_triage", script: TRIAGE, fake: "target-query", args: () => ({ source: "inputs/server.E01", out_dir: "work/triage", groups: ["users"] }) },
  { name: "the linux-target recipe", script: RECIPE, fake: "target-query", args: () => ({}), argv: (cwd) => ["run", "--target", join(cwd, "target.json"), "--out", join(cwd, "recipe-out")] },
];

for (const c of CASES) {
  for (const how of ["group", "SIGTERM", "SIGINT", "SIGHUP"] as const) {
    test(`${c.name}: ${how === "group" ? "the harness killing the tool's process group" : how} ends the engine and the program it started`, async () => {
      await withCwd(async (cwd, bin) => {
        const { dir, env } = await stage(cwd, bin, c.fake, engineScript());
        const run = startDetached(c.script, cwd, c.args(cwd), env, bin, c.argv?.(cwd) ?? []);
        let engine = 0, child = 0;
        try {
          engine = await pidFile(join(dir, "engine.pid"));
          child = await pidFile(join(dir, "child.pid"));
          if (how === "group") run.killGroup();
          else run.signal(how);
          const code = await run.closed;
          if (how !== "group") assert.equal(code, 128 + { SIGTERM: 15, SIGINT: 2, SIGHUP: 1 }[how], `${how}: the tool says it was stopped by the signal`);
          assert.equal(await gone(engine), true, `${how}: the engine survived`);
          assert.equal(await gone(child), true, `${how}: what the engine started survived`);
        } finally {
          for (const pid of [engine, child]) if (pid) try { process.kill(pid, "SIGKILL"); } catch { /* gone */ }
        }
      });
    });
  }
}

test("linux_triage and the recipe still say terminated after a signal: the summary and the receipt are written by the dying tool", async () => {
  await withCwd(async (cwd, bin) => {
    const { dir, env } = await stage(cwd, bin, "target-query", engineScript());
    const run = startDetached(TRIAGE, cwd, { source: "inputs/server.E01", out_dir: "work/triage", groups: ["users"] }, env, bin);
    await pidFile(join(dir, "child.pid"));
    run.signal("SIGINT");
    await run.closed;
    const summary = JSON.parse(await readFile(join(cwd, "work", "triage", "summary.json"), "utf8"));
    assert.equal(summary.state, "terminated");
    assert.equal(summary.groups[0].functions[0].status, "failed");
    assert.equal(summary.status, "failed", "the one function there was did not run to an exit");
  });
  await withCwd(async (cwd, bin) => {
    const { dir, env } = await stage(cwd, bin, "target-query", engineScript());
    const run = startDetached(RECIPE, cwd, {}, env, bin, ["run", "--target", join(cwd, "target.json"), "--out", join(cwd, "recipe-out")]);
    await pidFile(join(dir, "child.pid"));
    run.signal("SIGHUP");
    await run.closed;
    const coverage = JSON.parse(await readFile(join(cwd, "recipe-out", "coverage.json"), "utf8"));
    assert.match(coverage.receipt_written, /terminated/);
    assert.equal(coverage.status, "failed", "the first function did not run to an exit");
    const summary = JSON.parse(await readFile(join(cwd, "recipe-out", "artefacts", "summary.json"), "utf8"));
    assert.equal(summary.state, "terminated", "the wrapper was asked to stop first and had its last word");
  });
});

test("a deadline ends the engine and what it started, whichever tool ran it", async () => {
  await withCwd(async (cwd, bin) => {
    // journal_export: max_seconds
    const { dir, env } = await stage(cwd, bin, "journalctl", engineScript());
    const started = Date.now();
    const out = body(await tool(JOURNAL, cwd, { path: "work/journal", max_seconds: 1 }, env, bin));
    assert.ok(Date.now() - started < 15_000);
    assert.equal(out.timed_out, true);
    assert.equal(out.status, "partial");
    assert.equal(await gone(await pidFile(join(dir, "engine.pid"))), true, "journalctl survived its deadline");
    assert.equal(await gone(await pidFile(join(dir, "child.pid"))), true, "what journalctl started survived its deadline");
  });
  await withCwd(async (cwd, bin) => {
    // linux_triage: timeout_seconds
    const { dir, env } = await stage(cwd, bin, "target-query", engineScript());
    const out = body(await tool(TRIAGE, cwd, { source: "inputs/server.E01", out_dir: "work/triage", groups: ["users"], timeout_seconds: 1, total_timeout_seconds: 5 }, env, bin));
    const fn = out.groups[0].functions[0];
    assert.equal(fn.status, "failed");
    assert.equal(fn.timed_out, true);
    assert.equal(await gone(await pidFile(join(dir, "engine.pid"))), true, "the function survived its timeout");
    assert.equal(await gone(await pidFile(join(dir, "child.pid"))), true, "what the function started survived its timeout");
  });
  await withCwd(async (cwd, bin) => {
    // the recipe's detect
    const { dir, env } = await stage(cwd, bin, "target-query", engineScript());
    const { spawnSync } = await import("node:child_process");
    const r = spawnSync("python3", [RECIPE, "detect", "--target", join(cwd, "target.json")], { cwd, env: { ...process.env, ...env, LINUX_TARGET_DETECT_SECONDS: "1", PATH: `${bin}:${process.env.PATH ?? ""}` }, encoding: "utf8" });
    assert.equal(r.status, 2);
    assert.equal(JSON.parse(String(r.stdout).trim()).applies, "unknown");
    assert.equal(await gone(await pidFile(join(dir, "engine.pid"))), true, "the probe survived its deadline");
    assert.equal(await gone(await pidFile(join(dir, "child.pid"))), true, "what the probe started survived its deadline");
  });
});

test("the timeouts of the tools that run programs are held under their manifests'", async () => {
  await withCwd(async (cwd, bin) => {
    await stage(cwd, bin, "target-query", "#!/bin/sh\nexit 0\n");
    for (const bad of [{ total_timeout_seconds: 14101 }, { timeout_seconds: 14101 }, { total_timeout_seconds: 99999 }]) {
      const err = refused(await tool(TRIAGE, cwd, { source: "inputs/server.E01", out_dir: "work/t", groups: ["users"], ...bad }, {}, bin));
      assert.match(err.error, /from 1 to 14100/, JSON.stringify(bad));
    }
    const manifest = (name: string): Promise<Json> => readFile(join(TOOLS, name, "manifest.json"), "utf8").then((t) => JSON.parse(t));
    const triage = await manifest("linux_triage");
    assert.ok(14100 < triage.timeout_seconds);
    assert.match(triage.params.total_timeout_seconds.description, /at most 14100/);
    const recipe = JSON.parse(await readFile(join(LINUX, "recipes", "linux-target", "recipe.json"), "utf8"));
    assert.ok(280 < 300 && recipe.limits.seconds >= 14400, "detect stops itself under the harness's 300 seconds, and the run under the recipe's limit");
    // A detect budget that is not a number, or is far too large, is read as the default or the ceiling, never a traceback.
    const { spawnSync } = await import("node:child_process");
    await writeFile(join(bin, "target-query"), "#!/usr/bin/env python3\nprint('linux')\n");
    for (const seconds of ["abc", "99999", "0", "-5"]) {
      const r = spawnSync("python3", [RECIPE, "detect", "--target", join(cwd, "target.json")], { cwd, env: { ...process.env, LINUX_TARGET_DETECT_SECONDS: seconds, PATH: `${bin}:${process.env.PATH ?? ""}` }, encoding: "utf8" });
      assert.equal(r.status, 0, `${seconds}: ${r.stderr}`);
    }
  });
});
