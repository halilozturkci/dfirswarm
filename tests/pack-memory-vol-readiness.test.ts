/**
 * vol_readiness (memory-forensics): whether Volatility can be used here and on an image, offline, never a plugin's result.
 *
 * The tool is driven against a stand-in `vol` (a Python script whose behaviour the test lays down in a JSON file) so that every
 * case is exact: the listing, the windows.info answer and its log, the banners, the isfinfo table, a failing probe, a program that
 * hangs or ignores SIGTERM, a flood of output. The stand-in writes every argument vector it was called with, and records its pid,
 * so the tests can say that every call was offline and that no program is left. One real run is gated on a `vol` being present.
 * Each case fails on the base code, where the tool does not exist.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmod, mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { ROOT, withCwd } from "./tool-library-harness.ts";
import { MEM, SHAPES, json, rng, runTool } from "./memory-f1-support.ts";
import { interpreterDir } from "./host-gates.ts";

const VOL = join(MEM, "vol_readiness", "run.py");
const PY = spawnSync("python3", ["-c", "import sys; print(sys.executable)"], { encoding: "utf8" }).stdout.trim();
const SECOND = 1000;

type Behaviour = { stdout?: string; stderr?: string; code?: number; sleep?: number; ignore_term?: boolean; pid?: string; flood_err?: number; flood_out?: number };
type Config = { log: string; help?: Behaviour; info?: Behaviour; banners?: Behaviour; isfinfo?: Behaviour; other?: Behaviour };

// The layout argparse gives Volatility 3 (cli/__init__.py: add_subparsers(title="Plugins", metavar="PLUGIN")): one dotted name per line under the section.
const HELP = "usage: vol [-h] [-c CONFIG] ... PLUGIN ...\n\nPlugins:\n  PLUGIN\n    banners.Banners     Attempts to identify banners\n    linux.pslist.PsList  Lists the processes\n    windows.info.Info   Show OS and kernel details\n    windows.pslist.PsList  Lists the processes\n    windows.vadyarascan.VadYaraScan  Scans with YARA\n";
const HELP_ERR = "Volatility 3 Framework 2.28.2\n";
const GUID = "3844DBB920174967BE7AA4A2C20430FA";
const INFO_OK = `Variable\tValue\nKernel Base\t0xf80000000000\nSymbols\tfile:///opt/symbols/windows/ntkrnlmp.pdb/${GUID}-2.json.xz\n`;
const INFO_MISSING_ERR = `INFO volatility3.framework.automagic: DTB was found\nDEBUG fetch https://msdl.microsoft.com/download/symbols/ntkrnlmp.pdb/${GUID}2/ntkrnlmp.pd_ failed\n`;
// isfinfo.py of Volatility 3 2.28.2 has these seven columns and no other: the identifier (a banner, or a GUID and age) is in the last.
const ISF_HEAD = "URI\tValid\tNumber of base_types\tNumber of types\tNumber of symbols\tNumber of enums\tIdentifying information\n";
const isfRow = (uri: string, ident = "-"): string => `${uri}\tTrue\t1\t2\t3\t4\t${ident}\n`;
// An older layout with a column per kind, and a layout with no identifier column at all.
const ISF_HEAD_OLD = "URI\tValid\tNumber of base_types\tNumber of types\tNumber of symbols\tNumber of enums\tWindows info\tLinux banner\tMac banner\n";
const ISF_HEAD_NONE = "URI\tValid\tNumber of base_types\tNumber of types\tNumber of symbols\tNumber of enums\n";
const BANNER = "Linux version 5.15.0-91-generic (buildd@lcy02) (gcc 11.4.0) #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023";
const bannersOut = (...banners: string[]): string => "Offset\tBanner\n" + banners.map((b, i) => `0x${(0x1000 + i).toString(16)}\tb'${b}\\n'\n`).join("");

/** Lay down the stand-in `vol` in `bin` and its behaviour in cwd; returns the env the tool needs. */
async function stubVol(cwd: string, bin: string, cfg: Omit<Config, "log">): Promise<Record<string, string>> {
  const log = join(cwd, "vol-argv.log");
  await writeFile(join(cwd, "stub.json"), JSON.stringify({ log, ...cfg }));
  await writeFile(
    join(bin, "vol"),
    `#!${PY}
import json, os, signal, sys, time
cfg = json.load(open(os.environ["STUB_CFG"]))
a = sys.argv[1:]
open(cfg["log"], "a").write(json.dumps(a) + "\\n")
mode = "help" if "--help" in a else "isfinfo" if "isfinfo" in a else "banners" if "banners.Banners" in a else "info" if "windows.info" in a else "other"
b = cfg.get(mode, {})
if b.get("pid"):
    open(b["pid"], "w").write(str(os.getpid()))
if b.get("ignore_term"):
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
sys.stderr.write(b.get("stderr", "")); sys.stderr.flush()
sys.stdout.write(b.get("stdout", "")); sys.stdout.flush()
for key, fd in (("flood_err", sys.stderr), ("flood_out", sys.stdout)):
    n = b.get(key, 0)
    while n > 0:
        fd.write("x" * min(n, 65536) + "\\n"); n -= 65537
    fd.flush()
if b.get("sleep"):
    time.sleep(b["sleep"])
sys.exit(b.get("code", 0))
`,
  );
  await chmod(join(bin, "vol"), 0o755);
  await writeFile(join(cwd, "inputs", "mem.raw"), Buffer.alloc(8192));
  return { STUB_CFG: join(cwd, "stub.json") };
}

const argvLog = async (cwd: string): Promise<string[][]> =>
  (await readFile(join(cwd, "vol-argv.log"), "utf8").catch(() => "")).split("\n").filter(Boolean).map((l) => JSON.parse(l) as string[]);
const alive = (pid: number): boolean => { try { process.kill(pid, 0); return true; } catch { return false; } };
/** Whether a process is gone, giving it a moment: a stand-in killed as the tool ends is reaped by init after the tool exits, not before. */
const gone = async (pid: number, waitMs = 5_000): Promise<boolean> => {
  const until = Date.now() + waitMs;
  while (alive(pid)) {
    if (Date.now() > until) return false;
    await new Promise((r) => setTimeout(r, 50));
  }
  return true;
};
const pidOf = async (file: string): Promise<number | null> => { try { return Number((await readFile(file, "utf8")).trim()) || null; } catch { return null; } };

type Answer = { status: string; status_basis: string; verdict?: string; checks: Record<string, any>; missing: any[]; interrupted?: boolean; partial_results?: Record<string, any>; error?: string };

test("plugins: the listing is what vol lists, asked names are answered, nothing is invented, and every vol call is offline", { timeout: 120 * SECOND }, async () => {
  await withCwd(async (cwd, bin) => {
    const env = await stubVol(cwd, bin, { help: { stdout: HELP, stderr: HELP_ERR } });
    const run = await runTool(VOL, cwd, { plugins: ["windows.pslist", "windows.vadyarascan.VadYaraScan", "windows.malfind"] }, env, bin);
    const out = json<Answer>(run);
    assert.equal(out.checks.plugins.verdict, "blocked", "an asked plugin that is not listed makes the view blocked");
    assert.match(out.checks.plugins.reason, /windows\.malfind/);
    assert.equal(out.checks.plugins.volatility_version, "2.28.2");
    assert.deepEqual(out.checks.plugins.plugins.rows.map((r: any) => r.plugin), ["banners.Banners", "linux.pslist.PsList", "windows.info.Info", "windows.pslist.PsList", "windows.vadyarascan.VadYaraScan"]);
    const asked = Object.fromEntries(out.checks.plugins.asked.map((a: any) => [a.asked, a]));
    assert.equal(asked["windows.pslist"].listed, true, "a module name matches the class listed under it");
    assert.equal(asked["windows.malfind"].listed, false);
    assert.equal(out.verdict, "blocked");
    assert.equal(out.status, "complete", "blocked is a definite answer");
    const calls = await argvLog(cwd);
    assert.ok(calls.length >= 1 && calls.every((c) => c.includes("--offline")), `every vol call is offline: ${JSON.stringify(calls)}`);
    // all asked names listed: ready
    const ok = json<Answer>(await runTool(VOL, cwd, { plugins: ["windows.pslist"] }, env, bin));
    assert.equal(ok.verdict, "ready");
    assert.equal(ok.status, "complete");
  });
});

test("symbols, Windows: a Symbols row names the table; a missing table is named from the address the engine asked for, and isfinfo is searched for its GUID", { timeout: 120 * SECOND }, async () => {
  await withCwd(async (cwd, bin) => {
    let env = await stubVol(cwd, bin, { info: { stdout: INFO_OK, stderr: "DTB was found\n" } });
    let out = json<Answer>(await runTool(VOL, cwd, { path: "inputs/mem.raw", views: ["symbols"] }, env, bin));
    assert.equal(out.checks.symbols.verdict, "ready");
    assert.deepEqual(out.checks.symbols.table, { pdb: "ntkrnlmp.pdb", guid: "3844DBB9-2017-4967-BE7A-A4A2C20430FA", age: 2 });
    const info = (await argvLog(cwd))[0];
    assert.deepEqual(info.slice(0, 2), ["--offline", "-vv"]);
    assert.ok(info.includes("windows.info") && info.includes("inputs/mem.raw"));

    env = await stubVol(cwd, bin, { info: { stderr: INFO_MISSING_ERR, code: 1 }, isfinfo: { stdout: ISF_HEAD + isfRow("file:///t/other-1.json.xz") } });
    out = json<Answer>(await runTool(VOL, cwd, { path: "inputs/mem.raw", views: ["symbols"] }, env, bin));
    assert.equal(out.checks.symbols.verdict, "blocked");
    assert.deepEqual(out.checks.symbols.table_missing, { pdb: "ntkrnlmp.pdb", guid: "3844DBB9-2017-4967-BE7A-A4A2C20430FA", age: 2 }, "the age is hexadecimal in the address");
    assert.equal(out.checks.symbols.isfinfo_lists_guid, false);
    assert.equal(out.verdict, "blocked");
    assert.deepEqual(out.missing.map((m) => m.view), ["symbols"]);

    // the table is in the listing, the engine still could not use it: said, not hidden
    env = await stubVol(cwd, bin, { info: { stderr: INFO_MISSING_ERR, code: 1 }, isfinfo: { stdout: ISF_HEAD + isfRow(`file:///t/${GUID}-2.json.xz`) } });
    out = json<Answer>(await runTool(VOL, cwd, { path: "inputs/mem.raw", views: ["symbols"] }, env, bin));
    assert.equal(out.checks.symbols.isfinfo_lists_guid, true);
  });
});

test("symbols, Linux and macOS: a banner is matched exactly against isfinfo's banner columns; a near release is no match; a forged banner prints no secret", { timeout: 120 * SECOND }, async () => {
  await withCwd(async (cwd, bin) => {
    const noWindows = { info: { stderr: "Unsatisfied requirement\n", code: 1 } };
    // exact: ready
    let env = await stubVol(cwd, bin, { ...noWindows, banners: { stdout: bannersOut(BANNER) }, isfinfo: { stdout: ISF_HEAD + isfRow("file:///t/u.json.xz", `'${BANNER}\\n'`) } });
    let out = json<Answer>(await runTool(VOL, cwd, { path: "inputs/mem.raw", views: ["symbols"] }, env, bin));
    assert.equal(out.checks.symbols.verdict, "ready", JSON.stringify(out.checks.symbols));
    assert.equal(out.checks.symbols.operating_system, "linux");
    assert.equal(out.checks.symbols.banners[0].release, "5.15.0-91-generic");
    assert.equal(out.checks.symbols.banners[0].table, true);
    assert.ok(!JSON.stringify(out).includes("buildd@lcy02"), "only the release word of a banner is printed");
    // a table for a nearby build: no match, blocked
    const near = BANNER.replace("5.15.0-91-generic", "5.15.0-92-generic");
    env = await stubVol(cwd, bin, { ...noWindows, banners: { stdout: bannersOut(BANNER) }, isfinfo: { stdout: ISF_HEAD + isfRow("file:///t/u.json.xz", `'${near}\\n'`) } });
    out = json<Answer>(await runTool(VOL, cwd, { path: "inputs/mem.raw", views: ["symbols"] }, env, bin));
    assert.equal(out.checks.symbols.verdict, "blocked");
    assert.equal(out.checks.symbols.banners[0].table, false);
    // two banners, one table: unknown, not ready
    env = await stubVol(cwd, bin, { ...noWindows, banners: { stdout: bannersOut(BANNER, near) }, isfinfo: { stdout: ISF_HEAD + isfRow("file:///t/u.json.xz", `'${BANNER}\\n'`) } });
    out = json<Answer>(await runTool(VOL, cwd, { path: "inputs/mem.raw", views: ["symbols"] }, env, bin));
    assert.equal(out.checks.symbols.verdict, "unknown");
    assert.equal(out.status, "partial");
    // a macOS banner is read the same way
    const mac = "Darwin Kernel Version 23.4.0: Wed Feb 21 21:44:31 PST 2024; root:xnu-10063.101.15~2/RELEASE_X86_64";
    env = await stubVol(cwd, bin, { ...noWindows, banners: { stdout: bannersOut(mac) }, isfinfo: { stdout: ISF_HEAD + isfRow("file:///t/m.json.xz", `'${mac}\\n'`) } });
    out = json<Answer>(await runTool(VOL, cwd, { path: "inputs/mem.raw", views: ["symbols"] }, env, bin));
    assert.equal(out.checks.symbols.operating_system, "macos");
    assert.equal(out.checks.symbols.verdict, "ready");
    // a release word forged to carry a secret is not printed (the grammar of a release admits digits, dots and a closed list of tags)
    const token = SHAPES.ghp(rng(7));
    const forged = `Linux version 5.15.0-${token} (a@b) #1`;
    env = await stubVol(cwd, bin, { ...noWindows, banners: { stdout: bannersOut(forged) }, isfinfo: { stdout: ISF_HEAD + isfRow("file:///t/u.json.xz") } });
    const run = await runTool(VOL, cwd, { path: "inputs/mem.raw", views: ["symbols"] }, env, bin);
    assert.ok(!run.stdout.includes(token), "the forged release is not printed");
    assert.match(run.stdout, /<withheld \d+ characters/);
  });
});

test("an image no operating system is found in is unknown (never ready), and the status is partial", { timeout: 120 * SECOND }, async () => {
  await withCwd(async (cwd, bin) => {
    const env = await stubVol(cwd, bin, { info: { stderr: "Unsatisfied requirement\n", code: 1 }, banners: { stdout: "Offset\tBanner\n" } });
    const out = json<Answer>(await runTool(VOL, cwd, { path: "inputs/mem.raw", views: ["symbols"] }, env, bin));
    assert.equal(out.checks.symbols.verdict, "unknown");
    assert.equal(out.verdict, "unknown");
    assert.equal(out.status, "partial");
    assert.match(out.status_basis, /symbols/);
  });
});

test("a failing probe is blocked with its exit status; a secret-shaped token an engine prints in a failure is not printed", { timeout: 120 * SECOND }, async () => {
  await withCwd(async (cwd, bin) => {
    const token = SHAPES.ghp(rng(11));
    const env = await stubVol(cwd, bin, { help: { code: 3, stderr: `fatal: token ${token}\n` } });
    const run = await runTool(VOL, cwd, {}, env, bin);
    const out = json<Answer>(run);
    assert.equal(out.checks.plugins.verdict, "blocked");
    assert.equal(out.checks.plugins.exit_code, 3);
    assert.ok(!run.stdout.includes(token));
    // a windows.info failure with no table address and no banner: the first lines of the log are quoted, judged
    const env2 = await stubVol(cwd, bin, { info: { code: 1, stderr: `boom ${token}\n` }, banners: { code: 1 } });
    const run2 = await runTool(VOL, cwd, { path: "inputs/mem.raw", views: ["symbols"] }, env2, bin);
    assert.ok(!run2.stdout.includes(token));
    assert.equal(json<Answer>(run2).checks.symbols.verdict, "unknown");
  });
});

test("a vol that hangs is ended at the clock, with its tree, and the view is unknown", { timeout: 120 * SECOND }, async () => {
  await withCwd(async (cwd, bin) => {
    const pid = join(cwd, "vol.pid");
    const env = await stubVol(cwd, bin, { help: { sleep: 120, pid } });
    const run = await runTool(VOL, cwd, { max_seconds: 10 }, env, bin);
    const out = json<Answer>(run);
    assert.equal(out.checks.plugins.verdict, "unknown");
    assert.equal(out.checks.plugins.finished, false);
    assert.equal(out.status, "partial");
    assert.ok(run.ms < 25 * SECOND, `the call took ${run.ms} ms`);
    const stub = await pidOf(pid);
    assert.ok(stub && (await gone(stub)), "the stand-in vol is gone");
    // a step with no time left is not attempted: two programs, the clock gone after the first
    const env2 = await stubVol(cwd, bin, { info: { sleep: 120, pid } });
    const run2 = await runTool(VOL, cwd, { path: "inputs/mem.raw", views: ["symbols"], max_seconds: 10 }, env2, bin);
    assert.equal(json<Answer>(run2).checks.symbols.verdict, "unknown");
    const stub2 = await pidOf(pid);
    assert.ok(stub2 && (await gone(stub2)));
  });
});

test("SIGTERM ends the program (one that ignores SIGTERM too) and answers once: failed, interrupted, the views done, exit 143", { timeout: 120 * SECOND }, async () => {
  await withCwd(async (cwd, bin) => {
    for (const ignore of [false, true]) {
      const pid = join(cwd, `vol-${ignore}.pid`);
      const env = await stubVol(cwd, bin, { help: { sleep: 120, pid, ignore_term: ignore } });
      const run = await runTool(VOL, cwd, { views: ["fuse", "plugins"] }, env, bin, "SIGTERM", 0, async () => (await pidOf(pid)) !== null);
      assert.equal(run.code, 143, run.stderr);
      const out = json<Answer>(run);
      assert.equal(out.status, "failed");
      assert.equal(out.interrupted, true);
      assert.ok(out.partial_results && out.partial_results.fuse, "the view that had finished is kept");
      assert.equal(run.stdout.trim().split("\n}\n").length, 1, "one document");
      const stub = await pidOf(pid);
      assert.ok(stub && (await gone(stub)), `the stand-in is gone (ignore_term ${ignore})`);
    }
  });
});

test("two signals in a row give one document", { timeout: 120 * SECOND }, async () => {
  await withCwd(async (cwd, bin) => {
    const pid = join(cwd, "vol.pid");
    const env = await stubVol(cwd, bin, { help: { sleep: 120, pid } });
    const { spawn } = await import("node:child_process");
    const child = spawn("python3", [VOL], { cwd, env: { ...process.env, ...env, PATH: `${bin}:${process.env.PATH}` } });
    const out: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => out.push(c));
    child.stdin.end(JSON.stringify({}));
    for (let i = 0; i < 400 && (await pidOf(pid)) === null; i++) await new Promise((r) => setTimeout(r, 25));
    child.kill("SIGTERM");
    child.kill("SIGINT");
    const code = await new Promise<number | null>((resolve) => child.on("close", (c) => resolve(c)));
    const text = Buffer.concat(out).toString();
    assert.ok(code === 143 || code === 130, `exit ${code}`);
    assert.doesNotThrow(() => JSON.parse(text), "stdout holds exactly one JSON document");
    const stub = await pidOf(pid);
    assert.ok(stub && (await gone(stub)));
  });
});

test("a missing vol is blocked for the plugins and symbols views; the answer does not call it ready", { timeout: 120 * SECOND }, async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "inputs", "mem.raw"), Buffer.alloc(4096));
    const empty = join(cwd, "empty");
    await mkdir(empty);
    const run = await runTool(VOL, cwd, { path: "inputs/mem.raw", views: ["plugins", "symbols", "yara"] }, { PATH: `${await interpreterDir(empty)}:/usr/bin:/bin` });
    const out = json<Answer>(run);
    for (const v of ["plugins", "symbols", "yara"]) assert.equal(out.checks[v].verdict, "blocked", v);
    assert.equal(out.verdict, "blocked");
    assert.equal(out.status, "complete");
  });
});

test("yara: the binding is looked for in the Python that runs vol, from a neutral directory", { timeout: 120 * SECOND }, async () => {
  await withCwd(async (cwd, bin) => {
    const env = await stubVol(cwd, bin, {});
    // not installed: blocked
    let out = json<Answer>(await runTool(VOL, cwd, { views: ["yara"] }, { ...env, PYTHONPATH: "" }, bin));
    assert.equal(out.checks.yara.verdict, "blocked");
    // installed (a stand-in module on the interpreter's path): ready, with the version
    const site = join(cwd, "site");
    await mkdir(site);
    await writeFile(join(site, "yara.py"), "__version__ = '4.5.1'\n");
    out = json<Answer>(await runTool(VOL, cwd, { views: ["yara"] }, { ...env, PYTHONPATH: site }, bin));
    assert.equal(out.checks.yara.verdict, "ready", JSON.stringify(out.checks.yara));
    assert.equal(out.checks.yara.binding.yara.version, "4.5.1");
    assert.equal(out.checks.yara.binding.yara_x.imports, false);
    // a yara.py planted in the run directory (the evidence's) is not what imports
    await rm2(site);
    await writeFile(join(cwd, "yara.py"), "__version__ = 'planted'\nopen('planted-ran', 'w').write('1')\n");
    out = json<Answer>(await runTool(VOL, cwd, { views: ["yara"] }, { ...env, PYTHONPATH: "" }, bin));
    assert.equal(out.checks.yara.verdict, "blocked", "the planted module was not imported");
    assert.ok(!(await readdir(cwd)).includes("planted-ran"));
    // the interpreter is named on the first line of vol: a script with none is unknown, not ready
    await writeFile(join(bin, "vol"), "#!/bin/sh\nexit 0\n");
    out = json<Answer>(await runTool(VOL, cwd, { views: ["yara"] }, env, bin));
    assert.equal(out.checks.yara.verdict, "unknown");
    assert.equal(out.status, "partial");
  });
});

async function rm2(dir: string): Promise<void> {
  const { rm } = await import("node:fs/promises");
  await rm(dir, { recursive: true, force: true });
}

test("fuse: an absent or unopenable device and a missing helper are blocked, never unknown", { timeout: 120 * SECOND }, () => {
  const code = [
    "import importlib.util, json, sys",
    "spec = importlib.util.spec_from_file_location('t', sys.argv[1]); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)",
    "out = {}",
    "m.FUSE_DEVICE = '/nonexistent/fuse'; out['absent'] = m.check_fuse()['verdict']",
    "m.FUSE_DEVICE = '/etc/passwd'; out['not_a_device'] = m.check_fuse()['verdict']",
    "m.FUSE_DEVICE = '/dev/null'; m.shutil.which = lambda n: None; out['no_helper'] = m.check_fuse()['verdict']",
    "m.shutil.which = lambda n: '/usr/bin/fusermount3'; out['both'] = m.check_fuse()['verdict']",
    "print(json.dumps(out))",
  ].join("\n");
  const r = spawnSync("python3", ["-c", code, VOL], { encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
  assert.deepEqual(JSON.parse(r.stdout), { absent: "blocked", not_a_device: "blocked", no_helper: "blocked", both: "ready" });
});

test("the whole plugin list is kept in a file when it is longer than limit, and the answer names it", { timeout: 120 * SECOND }, async () => {
  await withCwd(async (cwd, bin) => {
    const names = Array.from({ length: 300 }, (_, i) => `mod${i}.Plugin${i}`);
    const env = await stubVol(cwd, bin, { help: { stdout: "Plugins:\n  {" + names.join(",") + "}\n" } });
    const run = await runTool(VOL, cwd, { limit: 5 }, env, bin);
    const out = json<Answer>(run);
    const plugins = out.checks.plugins.plugins;
    assert.equal(plugins.matched, 300);
    assert.equal(plugins.returned, 5);
    assert.equal(plugins.truncated, true);
    const kept = (await readFile(join(cwd, plugins.all_results), "utf8")).trim().split("\n");
    assert.equal(kept.length, 300);
    assert.deepEqual(new Set(kept.map((l) => JSON.parse(l).plugin)), new Set(names));
    // a rerun never replaces the file with a different one
    const again = json<Answer>(await runTool(VOL, cwd, { limit: 5 }, env, bin));
    assert.equal(again.checks.plugins.plugins.all_results, plugins.all_results);
  });
});

test("an engine that never stops writing is ended at the cap of what is read, and the view is unknown", { timeout: 180 * SECOND }, async () => {
  await withCwd(async (cwd, bin) => {
    const pid = join(cwd, "vol.pid");
    const env = await stubVol(cwd, bin, { info: { flood_err: 100 << 20, sleep: 120, pid } });
    const run = await runTool(VOL, cwd, { path: "inputs/mem.raw", views: ["symbols"], max_seconds: 60 }, env, bin);
    const out = json<Answer>(run);
    assert.equal(out.checks.symbols.verdict, "unknown");
    assert.match(out.checks.symbols.reason, /wrote more than the tool reads/);
    const stub = await pidOf(pid);
    assert.ok(stub && (await gone(stub)));
  });
});

test("hostile parameters give a JSON refusal, never a Traceback: NUL, a lone surrogate, a FIFO, nesting, wrong types, huge numbers, unknown names", { timeout: 120 * SECOND }, async () => {
  await withCwd(async (cwd, bin) => {
    const env = await stubVol(cwd, bin, {});
    const fifo = join(cwd, "inputs", "pipe.raw");
    assert.equal(spawnSync("mkfifo", [fifo]).status, 0);
    const bad: unknown[] = [
      { path: "inputs/mem.raw\u0000x", views: ["symbols"] },
      { path: "inputs/\ud800.raw", views: ["symbols"] },
      { path: "inputs/pipe.raw", views: ["symbols"] },
      { path: "inputs", views: ["symbols"] },
      { path: "inputs/absent.raw", views: ["symbols"] },
      { views: ["symbols"] },
      { path: "inputs/mem.raw" , views: ["plugins"] },
      { views: [] },
      { views: ["plugins", "plugins"] },
      { views: "plugins" },
      { views: [1] },
      { plugins: ["a b"] },
      { plugins: "x" },
      { max_seconds: 1e999 },
      { max_seconds: 10 ** 30 },
      { max_seconds: true },
      { max_seconds: "9" },
      { limit: 0 },
      { limit: 10 ** 30 },
      { limit: 1.5 },
      { surprise: 1 },
      { symbols_dir: "inputs/mem.raw", views: ["symbols"], path: "inputs/mem.raw" },
    ];
    for (const args of bad) {
      const t0 = Date.now();
      const run = await runTool(VOL, cwd, args, env, bin);
      assert.ok(!run.stderr.includes("Traceback"), `${JSON.stringify(args).slice(0, 80)}: ${run.stderr}`);
      const out = JSON.parse(run.stdout);
      assert.equal(out.status, "failed", JSON.stringify(args).slice(0, 80));
      assert.ok(out.error && out.status_basis);
      assert.equal(run.code, 1);
      assert.ok(Date.now() - t0 < 10 * SECOND, "a refusal is quick");
    }
    // the raw text: invalid JSON, a document nested far past the interpreter's recursion limit, not an object, invalid UTF-8
    const { spawn } = await import("node:child_process");
    for (const raw of [Buffer.from("{"), Buffer.from("[".repeat(200000)), Buffer.from("{\"a\":".repeat(100000)), Buffer.from("[1]"), Buffer.from([0x7b, 0x22, 0xff, 0x22, 0x3a, 0x31, 0x7d])]) {
      const child = spawn("python3", [VOL], { cwd, env: { ...process.env, ...env, PATH: `${bin}:${process.env.PATH}` } });
      let stdout = "", stderr = "";
      child.stdout.on("data", (c) => (stdout += c));
      child.stderr.on("data", (c) => (stderr += c));
      child.stdin.on("error", () => undefined);
      child.stdin.end(raw);
      const code = await new Promise<number | null>((r) => child.on("close", (c) => r(c)));
      assert.ok(!stderr.includes("Traceback"), stderr);
      assert.equal(JSON.parse(stdout).status, "failed");
      assert.equal(code, 1);
    }
    // a path that starts with "-" reaches vol as a path, not an option
    await writeFile(join(cwd, "-image.raw"), Buffer.alloc(4096));
    json<Answer>(await runTool(VOL, cwd, { path: "-image.raw", views: ["symbols"] }, await stubVol(cwd, bin, { info: { stdout: INFO_OK } }), bin));
    const call = (await argvLog(cwd)).find((c) => c.includes("windows.info"))!;
    assert.equal(call[call.indexOf("-f") + 1], "./-image.raw");
  });
});

test("the manifest says what the code does: no secret_output, the clock, the parameters, and every vol call in the script carries --offline", async () => {
  const man = JSON.parse(await readFile(join(ROOT, "packs", "memory-forensics", "tools", "vol_readiness", "manifest.json"), "utf8")) as Record<string, any>;
  assert.equal(man.secret_output, undefined, "nothing from the capture is written, so there is nothing to seal");
  assert.equal(man.timeout_seconds, 300);
  assert.deepEqual(Object.keys(man.params).sort(), ["limit", "max_seconds", "path", "plugins", "symbols_dir", "views"]);
  assert.equal(man.needs, undefined, "a tool that reports a missing FUSE must run without it");
  const script = await readFile(VOL, "utf8");
  const limits = (name: string): number => Number(new RegExp(`^${name} = ([0-9.]+)`, "m").exec(script)![1].split(".")[0]);
  assert.match(man.description, /default 200, at most 270/);
  assert.equal(script.match(/DEFAULT_SECONDS, MAX_SECONDS, MIN_SECONDS = 200\.0, 270\.0, 10\.0/)?.length, 1);
  assert.ok(limits("RESERVE") === 6 && man.description.includes("6 s reserve"));
  for (const [what, name] of [["help 90 s", "HELP_SECONDS"], ["windows.info or banners 150 s", "INFO_SECONDS"], ["isfinfo 120 s", "ISF_SECONDS"], ["the import probe 20 s", "PROBE_SECONDS"]]) {
    assert.ok(man.description.includes(what) && limits(name) === Number(/\d+/.exec(what.replace(/^.* (\d+) s$/, "$1"))![0]), what);
  }
  // every argument vector that starts a Volatility program is built with --offline (a bare vol call would be a way to fetch)
  const vectors = script.split("\n").filter((l) => /run_engine\(\[vol|base = \[vol|argv = \[vol/.test(l));
  assert.ok(vectors.length >= 3);
  for (const l of vectors) assert.match(l, /"--offline"/, l);
  assert.ok(!/start_new_session|setsid|preexec_fn\s*=/.test(script.replace(/^# BEGIN SHARED PROCESS[\s\S]*?^# END SHARED PROCESS/m, "")), "no session of its own outside the shared block");
});

test("one real run, when a Volatility is on PATH (otherwise skipped, and said so)", { timeout: 300 * SECOND }, async (t) => {
  const has = spawnSync("sh", ["-c", "command -v vol"], { encoding: "utf8" });
  if (has.status !== 0) { t.skip("no `vol` on PATH: the readings of the real listing, windows.info and isfinfo were not exercised"); return; }
  await withCwd(async (cwd) => {
    const out = json<Answer>(await runTool(VOL, cwd, { views: ["plugins", "fuse"] }));
    assert.ok(["ready", "blocked", "unknown"].includes(out.verdict!));
    assert.ok(out.checks.plugins.plugins_listed > 10, "the real listing names plugins");
  });
});

// ---- the real layout of isfinfo (Volatility 3 2.28.2, isfinfo.py) ----

const decodedBanners = (...b: string[]): string => "Offset\tBanner\n" + b.map((x, i) => `0x${(0x1000 + i).toString(16)}\t${x}\n`).join("");

test("isfinfo with the real column set: a table whose Identifying information is the image's banner is ready (decoded text, or the b'...' form of a cached table); a Windows identifier is no banner; an older layout is read too", { timeout: 120 * SECOND }, async () => {
  await withCwd(async (cwd, bin) => {
    const noWindows = { info: { stderr: "Unsatisfied requirement\n", code: 1 } };
    const ask = async (cfg: any) => json<Answer>(await runTool(VOL, cwd, { path: "inputs/mem.raw", views: ["symbols"] }, await stubVol(cwd, bin, { ...noWindows, ...cfg }), bin));
    // live mode: the identifier is the decoded text; the banner of banners.Banners is the decoded text too
    let out = await ask({ banners: { stdout: decodedBanners(BANNER) }, isfinfo: { stdout: ISF_HEAD + isfRow(`file:///t/${GUID}-2.json.xz`, `${GUID}2`) + isfRow("file:///t/u.json.xz", BANNER) } });
    assert.equal(out.checks.symbols.verdict, "ready", JSON.stringify(out.checks.symbols));
    assert.equal(out.checks.symbols.banners_with_table, 1);
    assert.equal(out.checks.symbols.tables_with_banner, 1, "a Windows identifier is no banner");
    assert.equal(out.checks.symbols.tables_listed, 2);
    // cached mode: str() of the bytes
    out = await ask({ banners: { stdout: decodedBanners(BANNER) }, isfinfo: { stdout: ISF_HEAD + isfRow("file:///t/u.json.xz", `b'${BANNER}\\n'`) } });
    assert.equal(out.checks.symbols.verdict, "ready");
    // a table for a nearby build is no match, on the real layout too
    out = await ask({ banners: { stdout: decodedBanners(BANNER) }, isfinfo: { stdout: ISF_HEAD + isfRow("file:///t/u.json.xz", BANNER.replace("11.4.0", "12.3.0")) } });
    assert.equal(out.checks.symbols.verdict, "blocked");
    assert.equal(out.checks.symbols.banners_with_table, 0);
    // the older layout (a column per kind) is read as well
    const oldRow = `file:///t/u.json.xz\tTrue\t1\t2\t3\t4\t-\t'${BANNER}\\n'\t-\n`;
    out = await ask({ banners: { stdout: bannersOut(BANNER) }, isfinfo: { stdout: ISF_HEAD_OLD + oldRow } });
    assert.equal(out.checks.symbols.verdict, "ready");
    // a header with no identifier column at all is unknown, never blocked
    out = await ask({ banners: { stdout: decodedBanners(BANNER) }, isfinfo: { stdout: ISF_HEAD_NONE + "file:///t/u.json.xz\tTrue\t1\t2\t3\t4\n" } });
    assert.equal(out.checks.symbols.verdict, "unknown");
    assert.match(out.checks.symbols.reason, /none of the columns this tool reads the identifier from/);
    assert.equal(out.status, "partial");
  });
});

test("symbols_dir with a semicolon is refused: Volatility's -s reads a semicolon-separated list", { timeout: 60 * SECOND }, async () => {
  await withCwd(async (cwd, bin) => {
    const env = await stubVol(cwd, bin, {});
    await mkdir(join(cwd, "a;b"));
    const out = json<Answer>(await runTool(VOL, cwd, { path: "inputs/mem.raw", views: ["symbols"], symbols_dir: "a;b" }, env, bin));
    assert.equal(out.status, "failed");
    assert.match(out.error ?? "", /semicolon/);
  });
});
