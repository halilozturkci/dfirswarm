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
import { spawnSync } from "node:child_process";
import { JOURNAL, RECIPE, TRIAGE, TOOLS, body, gone, pidFile, refused, startDetached, tool, withCwd } from "./linux-pack-harness.ts";
import type { Json } from "./linux-pack-harness.ts";
import { ROOT } from "./tool-library-harness.ts";

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
  // ... and it is the text the network pack's engine tools carry (the reference copy, with the walk that never starts at a program
  // already waited for, the seen set, and the libproc route on macOS that needs no ps), not an older one.
  assert.equal(blocks[0], await processBlock(join(LINUX, "..", "network-forensics", "tools", "zeek_run", "run.py")));
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

/**
 * A stand-in engine that starts a program of its own, records the pid of that program and then its own, and then waits.
 * The parent records both (the child does not have to be scheduled first), and writes its own pid last: when engine.pid is
 * there, child.pid is too, so a test that has read the one can read the other without a wait that depends on the machine.
 */
function engineScript(extra = ""): string {
  return `#!/usr/bin/env python3
import os, subprocess, sys, time
d = os.environ["STUB_DIR"]
${extra}
if not os.path.exists(d + "/engine.pid"):
    kid = subprocess.Popen(["sleep", "300"])
    open(d + "/child.pid", "w").write(str(kid.pid))
    open(d + "/engine.pid", "w").write(str(os.getpid()))
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

/** Kills what the stand-in recorded, whatever the test found: a stand-in that survived its tool would sleep for 300 seconds. */
async function reapRecorded(dir: string): Promise<void> {
  for (const name of ["engine.pid", "child.pid"]) {
    const pid = Number((await readFile(join(dir, name), "utf8").catch(() => "")).trim());
    if (pid > 1) try { process.kill(pid, "SIGKILL"); } catch { /* gone */ }
  }
}

/** A call that must come back: bounded, so that a tool whose program outlived it fails this case by name (it holds the pipe) and not the suite's timeout. */
async function comesBack<T>(call: Promise<T>, what: string, ms = 120_000): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([call, new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error(`${what} did not come back in ${ms} ms: what it started outlived its deadline`)), ms); })]);
  } finally {
    clearTimeout(timer);
  }
}

test("a deadline ends the engine and what it started, whichever tool ran it", async () => {
  // The deadlines below are the tools' own and short for a test, but not so short that a loaded machine ends the stand-in
  // before it has started its program (then there would be nothing to ask about): what is asked is the tool's own answer
  // (`timed_out`), the processes the stand-in recorded, and a wall bound far under the stand-in's 300 seconds, not a short time.
  await withCwd(async (cwd, bin) => {
    // journal_export: max_seconds
    const { dir, env } = await stage(cwd, bin, "journalctl", engineScript());
    try {
      const out = body(await comesBack(tool(JOURNAL, cwd, { path: "work/journal", max_seconds: 5 }, env, bin), "journal_export"));
      assert.equal(out.timed_out, true);
      assert.equal(out.status, "partial");
      assert.equal(await gone(await pidFile(join(dir, "engine.pid"))), true, "journalctl survived its deadline");
      assert.equal(await gone(await pidFile(join(dir, "child.pid"))), true, "what journalctl started survived its deadline");
    } finally {
      await reapRecorded(dir);
    }
  });
  await withCwd(async (cwd, bin) => {
    // linux_triage: timeout_seconds
    const { dir, env } = await stage(cwd, bin, "target-query", engineScript());
    try {
      const out = body(await comesBack(tool(TRIAGE, cwd, { source: "inputs/server.E01", out_dir: "work/triage", groups: ["users"], timeout_seconds: 5, total_timeout_seconds: 30 }, env, bin), "linux_triage"));
      const fn = out.groups[0].functions[0];
      assert.equal(fn.status, "failed");
      assert.equal(fn.timed_out, true);
      assert.equal(await gone(await pidFile(join(dir, "engine.pid"))), true, "the function survived its timeout");
      assert.equal(await gone(await pidFile(join(dir, "child.pid"))), true, "what the function started survived its timeout");
    } finally {
      await reapRecorded(dir);
    }
  });
  await withCwd(async (cwd, bin) => {
    // the recipe's detect
    const { dir, env } = await stage(cwd, bin, "target-query", engineScript());
    const { spawnSync } = await import("node:child_process");
    try {
      const r = spawnSync("python3", [RECIPE, "detect", "--target", join(cwd, "target.json")], { cwd, env: { ...process.env, ...env, LINUX_TARGET_DETECT_SECONDS: "5", PATH: `${bin}:${process.env.PATH ?? ""}` }, encoding: "utf8", timeout: 120_000, killSignal: "SIGKILL" });
      assert.equal(r.status, 2, `detect did not end at its own deadline: ${r.error?.message ?? r.stderr}`);
      assert.equal(JSON.parse(String(r.stdout).trim()).applies, "unknown");
      assert.equal(await gone(await pidFile(join(dir, "engine.pid"))), true, "the probe survived its deadline");
      assert.equal(await gone(await pidFile(join(dir, "child.pid"))), true, "what the probe started survived its deadline");
    } finally {
      await reapRecorded(dir);
    }
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
    for (const seconds of ["abc", "99999"]) {
      const r = spawnSync("python3", [RECIPE, "detect", "--target", join(cwd, "target.json")], { cwd, env: { ...process.env, LINUX_TARGET_DETECT_SECONDS: seconds, PATH: `${bin}:${process.env.PATH ?? ""}` }, encoding: "utf8", timeout: 120_000 });
      assert.equal(r.status, 0, `${seconds}: ${r.stderr}`);
    }
    // 0 and -5 are read as the one-second floor: not as no deadline, and not as the default of 240 seconds. A stand-in that needs
    // eight seconds is therefore cut, whatever the machine's speed (a fast one that answers at once would be cut by a loaded
    // machine's slow start, and the case would test the load).
    await writeFile(join(bin, "target-query"), "#!/bin/sh\nsleep 8\necho linux\n");
    for (const seconds of ["0", "-5"]) {
      const r = spawnSync("python3", [RECIPE, "detect", "--target", join(cwd, "target.json")], { cwd, env: { ...process.env, LINUX_TARGET_DETECT_SECONDS: seconds, PATH: `${bin}:${process.env.PATH ?? ""}` }, encoding: "utf8", timeout: 120_000 });
      assert.equal(r.status, 2, `${seconds}: ${r.stderr}`);
      assert.equal(JSON.parse(String(r.stdout).trim()).applies, "unknown", seconds);
      assert.doesNotMatch(r.stderr, /Traceback/, seconds);
    }
  });
});

/** Every .py of the repository's packs and of the tool library that carries the shared process block. */
async function carriers(): Promise<string[]> {
  const all = [...(await pyFiles(join(ROOT, "packs"))), ...(await pyFiles(join(ROOT, "tool-library")))];
  const out: string[] = [];
  for (const path of all) if ((await readFile(path, "utf8")).includes(BEGIN)) out.push(path);
  return out.sort();
}

/** Runs the process block of `path` the way the tool does (its text, in a namespace of its own) and then `code`. */
function withBlock(path: string, code: string): { status: number | null; stdout: string; stderr: string } {
  const driver = `
import os, signal, subprocess, sys, time
text = open(${JSON.stringify(path)}).read()
start = text.index(${JSON.stringify(BEGIN)}); end = text.index(${JSON.stringify(END)})
ns = {"os": os, "signal": signal, "subprocess": subprocess, "sys": sys, "time": time}
exec(text[start:end], ns)
${code}
`;
  const r = spawnSync("python3", ["-I", "-c", driver], { encoding: "utf8", timeout: 60_000, killSignal: "SIGKILL" });
  return { status: r.status, stdout: String(r.stdout), stderr: String(r.stderr) };
}

test("every carrier of the shared process block, in every pack and in the tool library, has the kill walk that never starts at a program already waited for", async () => {
  const paths = await carriers();
  assert.ok(paths.length >= 20, `found ${paths.length} carriers`);
  const texts = new Map<string, string[]>();
  for (const path of paths) {
    const block = await processBlock(path);
    texts.set(block, [...(texts.get(block) ?? []), path]);
    assert.match(block, /if proc\.poll\(\) is not None:\s+return/, `${path}: kill_tree starts a walk at a pid that was already waited for`);
    assert.match(block, /seen/, `${path}: the walk has no seen set`);
    assert.match(block, /PS_WAIT/, `${path}: the ps fallback is not given its wait`);
    assert.match(block, /_children_libproc/, `${path}: macOS has no route that needs no ps`);
  }
  // Two lineages: the engine tools' (one text in the network, base, linux, reverse-engineering and virtualization packs) and the
  // windows tools' (the same, with wait_for): no third, no older copy.
  assert.ok(texts.size <= 2, [...texts.values()].map((v) => v.join(",")).join(" | "));
});

test("kill_tree leaves alone the children of a pid whose program was already waited for, in every carrier", async () => {
  // A program that has been waited for has a pid that is free to be another process's. The walk below it would be that
  // process's children: here a stand-in for the new owner of the pid, with a child of its own that must survive.
  for (const path of await carriers()) {
    const r = withBlock(path, `
owner = subprocess.Popen(["sh", "-c", "sleep 300 & echo $!; wait"], stdout=subprocess.PIPE, text=True)
child = int(owner.stdout.readline())
class Waited:
    pid = owner.pid
    def poll(self): return 0
    def kill(self): raise SystemExit("kill_tree signalled a program that was already waited for")
try:
    ns["kill_tree"](Waited())
    time.sleep(0.3)
    os.kill(child, 0)
    print("child alive")
finally:
    for pid in (child, owner.pid):
        try: os.kill(pid, signal.SIGKILL)
        except OSError: pass
`);
    assert.equal(r.status, 0, `${path}: ${r.stderr}`);
    assert.match(r.stdout, /child alive/, path);
  }
});

test("the walk below a pid ends and lists each process once where the table is cyclic (a pid reused while it was read)", async () => {
  for (const path of await carriers()) {
    const r = withBlock(path, `
kids = {10: [11, 12], 11: [13], 13: [10], 12: []}
found = ns["_below"](kids, 10)
print(sorted(found))
`);
    assert.equal(r.status, 0, `${path}: ${r.stderr}`);
    assert.equal(r.stdout.trim(), "[11, 12, 13]", path);
  }
});
