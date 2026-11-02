/**
 * vol_views (memory-forensics): one named question put to the installed Volatility, offline, with the engine's whole output kept.
 *
 * The tool is driven against a stand-in `vol` whose behaviour a test lays down in a JSON file: the plugin listing, the plugin's own
 * options, the rows it prints (the quick renderer's tab-separated table), the files it exports with -o, a failing run, a hang, a flood,
 * a program that ignores SIGTERM. The stand-in logs every argument vector and its working directory. The readiness receipt is built by
 * running the real vol_readiness against the same stand-in in one test. Canaries are random secret-shaped strings built from pieces
 * (tests/memory-f1-support.ts). One real run is gated on a `vol` being present. Each case fails on the base code, where the tool is missing.
 */
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmod, mkdir, readFile, readdir, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { ROOT, withCwd } from "./tool-library-harness.ts";
import { MEM, SHAPES, rng, runTool } from "./memory-f1-support.ts";

const VIEWS = join(MEM, "vol_views", "run.py");
const READY = join(MEM, "vol_readiness", "run.py");
const PY = spawnSync("python3", ["-c", "import sys; print(sys.executable)"], { encoding: "utf8" }).stdout.trim();
const SECOND = 1000;
const sha = (b: Buffer | string): string => createHash("sha256").update(b).digest("hex");

type Plugin = { stdout?: string; stderr?: string; code?: number; sleep?: number; ignore_term?: boolean; pid?: string; flood?: number; exports?: Record<string, string> };
type Config = { log: string; help?: string; help_err?: string; plugin_help?: string; run?: Plugin; info?: string };

const HELP = "usage: vol [-h] ...\n\nPlugins:\n  {windows.pslist.PsList,windows.cmdline.CmdLine,windows.malware.malfind.Malfind,linux.pslist.PsList,linux.lsof.Lsof,windows.info.Info,windows.dlllist.DllList,windows.dlllist.ModList}\n";
const HELP_ERR = "Volatility 3 Framework 2.28.2\n";
const PLUGIN_HELP = "usage: vol windows.pslist.PsList [-h] [--pid [PID ...]] [--dump]\n";
const HEADER = "PID\tPPID\tImageFileName\tOffset(V)\tThreads\tHandles\tCreateTime\n";
const row = (pid: number, name: string): string => `${pid}\t4\t${name}\t0xfa8000a0${pid.toString(16).padStart(4, "0")}\t12\t300\t2024-01-02 10:00:00.000000 UTC\n`;

async function stubVol(cwd: string, bin: string, cfg: Omit<Config, "log">): Promise<Record<string, string>> {
  const log = join(cwd, "vol-argv.log");
  await writeFile(join(cwd, "stub.json"), JSON.stringify({ log, ...cfg }));
  await writeFile(
    join(bin, "vol"),
    `#!${PY}
import json, os, signal, sys, time
cfg = json.load(open(os.environ["STUB_CFG"]))
a = sys.argv[1:]
open(cfg["log"], "a").write(json.dumps({"argv": a, "cwd": os.getcwd()}) + "\\n")
if a[-1:] == ["--help"] and len(a) == 2:
    sys.stderr.write(cfg.get("help_err", "")); sys.stdout.write(cfg.get("help", "")); sys.exit(0)
if a[-1:] == ["--help"]:
    sys.stdout.write(cfg.get("plugin_help", "")); sys.exit(0)
if "windows.info" in a:
    sys.stdout.write(cfg.get("info", "")); sys.exit(0)
b = cfg.get("run", {})
if b.get("pid"):
    open(b["pid"], "w").write(str(os.getpid()))
if b.get("ignore_term"):
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
if "-o" in a:
    d = a[a.index("-o") + 1]
    for name, content in b.get("exports", {}).items():
        open(os.path.join(d, name), "w").write(content)
sys.stderr.write(b.get("stderr", "")); sys.stderr.flush()
sys.stdout.write(b.get("stdout", "")); sys.stdout.flush()
n = b.get("flood", 0)
i = 0
while n > 0:
    line = "%d\\t4\\tflood%d.exe\\t0x1\\t1\\t1\\t2024-01-02\\n" % (1000 + i, i)
    sys.stdout.write(line); n -= len(line); i += 1
sys.stdout.flush()
if b.get("sleep"):
    time.sleep(b["sleep"])
sys.exit(b.get("code", 0))
`,
  );
  await chmod(join(bin, "vol"), 0o755);
  await writeFile(join(cwd, "inputs", "mem.raw"), Buffer.alloc(8192));
  await writeReceipt(cwd);
  return { STUB_CFG: join(cwd, "stub.json") };
}

async function writeReceipt(cwd: string, over: Record<string, unknown> = {}, name = "ready.json"): Promise<string> {
  await writeFile(join(cwd, "inputs", name), JSON.stringify({ parser: "vol_readiness/1", verdict: "ready", views_requested: ["plugins", "symbols"], inputs: { path: "inputs/mem.raw" }, volatility: { version: "2.28.2" }, ...over }));
  return `inputs/${name}`;
}

const calls = async (cwd: string): Promise<Array<{ argv: string[]; cwd: string }>> =>
  (await readFile(join(cwd, "vol-argv.log"), "utf8").catch(() => "")).split("\n").filter(Boolean).map((l) => JSON.parse(l));
const alive = (pid: number): boolean => { try { process.kill(pid, 0); return true; } catch { return false; } };
const pidOf = async (file: string): Promise<number | null> => { try { return Number((await readFile(file, "utf8")).trim()) || null; } catch { return null; } };
type Answer = Record<string, any>;
const parse = (r: { stdout: string; stderr: string }): Answer => {
  assert.ok(!r.stderr.includes("Traceback"), r.stderr);
  return JSON.parse(r.stdout) as Answer;
};
const files = async (dir: string): Promise<string[]> => {
  const found: string[] = [];
  const walk = async (d: string): Promise<void> => {
    for (const e of await readdir(d, { withFileTypes: true }).catch(() => [])) {
      if (e.isDirectory()) await walk(join(d, e.name)); else found.push(join(d, e.name));
    }
  };
  await walk(dir);
  return found.sort();
};
async function secretJob(cwd: string, n = 1): Promise<{ env: Record<string, string>; out: string }> {
  const out = join(cwd, `job-out-${n}`);
  await mkdir(out, { recursive: true });
  return { env: { JOB_ID: `job${n}`, OUT: out, SECRET_OUTPUT: "1" }, out };
}
const base = { path: "inputs/mem.raw", question: "windows.pslist", readiness: "inputs/ready.json" };
const CFG = { help: HELP, help_err: HELP_ERR, plugin_help: PLUGIN_HELP };

test("the question is resolved against the installed listing, run offline from /, and its whole output is judged, paged and kept; canaries in process names and command lines are not printed", { timeout: 120 * SECOND }, async () => {
  await withCwd(async (cwd, bin) => {
    const r = rng(31);
    const token = SHAPES.ghp(r), aws = SHAPES.aws_key(r), jwt = SHAPES.jwt(r);
    const rows = HEADER + row(4, "System") + row(300, "svchost.exe") + row(412, `proc_${token}.exe`) + `501\t4\tcmd.exe\t0x1\t1\t1\tx --key ${aws} --jwt ${jwt}\n`;
    const env = await stubVol(cwd, bin, { ...CFG, run: { stdout: "Volatility 3 Framework 2.28.2\n\n" + rows } });
    const run = await runTool(VIEWS, cwd, base, env, bin);
    const out = parse(run);
    assert.equal(out.plugin, "windows.pslist.PsList", "a module name resolves to the one class listed under it");
    assert.equal(out.status, "complete", out.status_basis);
    assert.equal(out.volatility, "2.28.2");
    assert.equal(out.scope.rows, 6, "the banner line and the four rows and the header are all lines of the output");
    assert.deepEqual(out.scope.columns.slice(0, 3), ["PID", "PPID", "ImageFileName"]);
    assert.equal(out.output.rows.length, out.scope.rows);
    for (const canary of [token, aws, jwt]) assert.ok(!run.stdout.includes(canary), `a printed slot holds a canary ${canary.slice(0, 6)}`);
    assert.ok(out.output.rows.some((x: any) => x.cells.includes("svchost.exe")));
    const log = await calls(cwd);
    assert.ok(log.every((c) => c.argv.includes("--offline")), JSON.stringify(log));
    const ran = log.find((c) => c.argv.includes("windows.pslist.PsList") && !c.argv.includes("--help"))!;
    assert.equal(ran.cwd, "/", "the plugin runs from /");
    assert.equal(ran.argv[ran.argv.indexOf("-f") + 1], join(await realpath(cwd), "inputs", "mem.raw"), "the image path is absolute");
    assert.deepEqual(out.secret_values, { contains_secret_values: false, raw_output_file: null, raw_output_bytes: null, artefacts: null });
    assert.deepEqual(await files(join(cwd, "work")), [], "nothing is written without write_values and a page that fits");
  });
});

async function realpath(p: string): Promise<string> {
  const { realpath: rp } = await import("node:fs/promises");
  return rp(p);
}

test("a question the installed Volatility does not list is refused, naming it; a module with several classes is refused, naming them; nothing runs", { timeout: 120 * SECOND }, async () => {
  await withCwd(async (cwd, bin) => {
    const env = await stubVol(cwd, bin, { ...CFG, run: { stdout: HEADER } });
    let out = parse(await runTool(VIEWS, cwd, { ...base, question: "windows.notaplugin" }, env, bin));
    assert.equal(out.status, "failed");
    assert.match(out.error, /does not list a plugin named windows\.notaplugin/);
    out = parse(await runTool(VIEWS, cwd, { ...base, question: "windows.dlllist" }, env, bin));
    assert.equal(out.status, "failed");
    assert.match(out.error, /more than one plugin/);
    assert.deepEqual(out.candidates.sort(), ["windows.dlllist.DllList", "windows.dlllist.ModList"]);
    // a module that is only a prefix of another name is not a match
    out = parse(await runTool(VIEWS, cwd, { ...base, question: "windows.pslis" }, env, bin));
    assert.equal(out.status, "failed");
    const log = await calls(cwd);
    assert.ok(log.every((c) => c.argv.includes("--help")), "only the listing was run");
  });
});

test("the readiness receipt is required, must be ready, for this image and cover the plugins and symbols views; a FIFO, a directory or a file outside the run directory is refused", { timeout: 120 * SECOND }, async () => {
  await withCwd(async (cwd, bin) => {
    const env = await stubVol(cwd, bin, { ...CFG, run: { stdout: HEADER + row(4, "System") } });
    const refused = async (args: Record<string, unknown>, why: RegExp): Promise<void> => {
      const out = parse(await runTool(VIEWS, cwd, args, env, bin));
      assert.equal(out.status, "failed", JSON.stringify(args));
      assert.match(out.error, why);
    };
    const before = (await calls(cwd)).length;
    await refused({ path: base.path, question: base.question }, /readiness is required/);
    await refused({ ...base, readiness: await writeReceipt(cwd, { verdict: "blocked" }, "b.json") }, /not ready/);
    await refused({ ...base, readiness: await writeReceipt(cwd, { verdict: "unknown" }, "u.json") }, /not ready/);
    await refused({ ...base, readiness: await writeReceipt(cwd, { parser: "something/1" }, "p.json") }, /not an answer of vol_readiness/);
    await refused({ ...base, readiness: await writeReceipt(cwd, { views_requested: ["plugins"] }, "v.json") }, /does not cover the plugins and symbols views/);
    await refused({ ...base, readiness: await writeReceipt(cwd, { inputs: { path: "inputs/other.raw" } }, "i.json") }, /another image/);
    await writeFile(join(cwd, "inputs", "junk.json"), "{ not json");
    await refused({ ...base, readiness: "inputs/junk.json" }, /not a JSON document/);
    await writeFile(join(cwd, "inputs", "list.json"), "[1]");
    await refused({ ...base, readiness: "inputs/list.json" }, /not an answer of vol_readiness/);
    await writeFile(join(cwd, "inputs", "nest.json"), "[".repeat(200000));
    await refused({ ...base, readiness: "inputs/nest.json" }, /not a JSON document/);
    await refused({ ...base, readiness: "/etc/passwd" }, /outside the run directory|not an answer|not a JSON/);
    await refused({ ...base, readiness: "inputs" }, /not a regular file/);
    await refused({ ...base, readiness: "inputs/none.json" }, /cannot be opened/);
    assert.equal(spawnSync("mkfifo", [join(cwd, "inputs", "fifo.json")]).status, 0);
    await refused({ ...base, readiness: "inputs/fifo.json" }, /not a regular file/);
    assert.equal((await calls(cwd)).length, before, "no vol program was started by any refusal");
    // an answer of the real vol_readiness is accepted
    await writeFile(join(cwd, "inputs", "windows.info"), "x");
    const cfgReal = { ...CFG, info: "Variable\tValue\nKernel Base\t0xf80000000000\nSymbols\tfile:///t/ntkrnlmp.pdb/3844DBB920174967BE7AA4A2C20430FA-2.json.xz\n", run: { stdout: HEADER + row(4, "System") } };
    const env2 = await stubVol(cwd, bin, cfgReal);
    const real = await runTool(READY, cwd, { path: "inputs/mem.raw", views: ["plugins", "symbols"] }, env2, bin);
    assert.equal(JSON.parse(real.stdout).verdict, "ready", real.stdout);
    await writeFile(join(cwd, "inputs", "real.json"), real.stdout);
    const out = parse(await runTool(VIEWS, cwd, { ...base, readiness: "inputs/real.json" }, env2, bin));
    assert.equal(out.status, "complete", JSON.stringify(out));
    assert.deepEqual(out.readiness, { verdict: "ready", volatility: "2.28.2" });
  });
});

test("pid and dump are passed only as options the plugin lists; dump needs write_values; a plugin without the option is refused before it runs", { timeout: 120 * SECOND }, async () => {
  await withCwd(async (cwd, bin) => {
    let env = await stubVol(cwd, bin, { ...CFG, run: { stdout: HEADER + row(4, "System") } });
    let out = parse(await runTool(VIEWS, cwd, { ...base, pid: [4, 300] }, env, bin));
    assert.equal(out.status, "complete");
    assert.deepEqual(out.options, ["--pid", "4", "300"]);
    const ran = (await calls(cwd)).find((c) => c.argv.includes("windows.pslist.PsList") && !c.argv.includes("--help"))!;
    assert.deepEqual(ran.argv.slice(ran.argv.indexOf("windows.pslist.PsList")), ["windows.pslist.PsList", "--pid", "4", "300"]);
    env = await stubVol(cwd, bin, { ...CFG, plugin_help: "usage: vol windows.pslist.PsList [-h]\n", run: { stdout: HEADER } });
    const ranBefore = (await calls(cwd)).filter((c) => c.argv.includes("-f")).length;
    out = parse(await runTool(VIEWS, cwd, { ...base, pid: [4] }, env, bin));
    assert.match(out.error, /does not list --pid/);
    assert.equal((await calls(cwd)).filter((c) => c.argv.includes("-f")).length, ranBefore, "the plugin did not run");
    out = parse(await runTool(VIEWS, cwd, { ...base, dump: true }, env, bin));
    assert.equal(out.dump, "refused");
    for (const bad of [[], [-1], [1.5], ["4"], [true], Array.from({ length: 65 }, (_, i) => i), [2 ** 32], "4"]) {
      assert.equal(parse(await runTool(VIEWS, cwd, { ...base, pid: bad }, env, bin)).status, "failed", JSON.stringify(bad));
    }
  });
});

test("write_values: refused outside a job and in one that is not secret output, before the image is looked at; in a secret job the raw output and the exported files are kept 0600 with their digests in manifest.jsonl, and the answer holds none of it", { timeout: 120 * SECOND }, async () => {
  await withCwd(async (cwd, bin) => {
    const canary = SHAPES.ghp(rng(41));
    const stdout = HEADER + row(4, "System") + `77\t4\tcmd.exe\t0x1\t1\t1\tx --token ${canary}\n`;
    const exportsText = { "pid.4.dmp": "dump-of-system", "pid.77.dmp": `dump-with-${canary}` };
    const env = await stubVol(cwd, bin, { ...CFG, run: { stdout, exports: exportsText } });
    const args = { ...base, write_values: true };
    for (const e of [{}, { JOB_ID: "j", OUT: join(cwd, "o") }] as Array<Record<string, string>>) {
      const before = (await calls(cwd)).length;
      const out = parse(await runTool(VIEWS, cwd, args, { ...env, ...e }, bin));
      assert.equal(out.write_values, "refused");
      assert.equal(out.written, false);
      assert.equal((await calls(cwd)).length, before, "no program started");
    }
    assert.deepEqual(await files(join(cwd, "work")), []);
    const { env: jobEnv, out: outDir } = await secretJob(cwd);
    const run = await runTool(VIEWS, cwd, { ...args, dump: true, pid: [4, 77] }, { ...env, ...jobEnv }, bin);
    const out = parse(run);
    assert.equal(out.status, "complete", out.status_basis);
    assert.ok(!run.stdout.includes(canary));
    assert.deepEqual(out.options, ["--pid", "4", "77", "--dump"]);
    const dir = join(outDir, "vol_views");
    assert.equal((await stat(dir)).mode & 0o777, 0o700);
    const raw = join(dir, out.secret_values.raw_output_file.split("/").pop());
    assert.match(out.secret_values.raw_output_file, /^store\/jobs\/job1\/out\/vol_views\/vol_views-[0-9a-f]{16}-output\.txt$/);
    assert.equal((await stat(raw)).mode & 0o777, 0o600);
    assert.equal((await readFile(raw, "utf8")), stdout, "the raw output, byte for byte");
    assert.equal(out.secret_values.raw_output_bytes, Buffer.byteLength(stdout));
    assert.equal(out.secret_values.artefacts.files, 2);
    const adir = join(dir, out.secret_values.artefacts.dir.split("/").pop());
    assert.equal((await stat(adir)).mode & 0o777, 0o700);
    assert.equal(await readFile(join(adir, "pid.77.dmp"), "utf8"), exportsText["pid.77.dmp"]);
    const manifest = (await readFile(join(dir, "manifest.jsonl"), "utf8")).trim().split("\n").map((l) => JSON.parse(l));
    assert.equal((await stat(join(dir, "manifest.jsonl"))).mode & 0o777, 0o600);
    assert.deepEqual(manifest.find((m) => m.row === "output"), { row: "output", file: raw.split("/").pop(), bytes: Buffer.byteLength(stdout), sha256: sha(stdout) });
    assert.equal(manifest.find((m) => m.file === "pid.4.dmp").sha256, sha(exportsText["pid.4.dmp"]));
    assert.equal(manifest.find((m) => m.file === "pid.77.dmp").bytes, Buffer.byteLength(exportsText["pid.77.dmp"]));
    for (const digest of [sha(stdout), sha(exportsText["pid.4.dmp"])]) assert.ok(!run.stdout.includes(digest), "no digest of memory content in the answer");
    // a second run in the job: an identical one names the same raw file, a different one the next free name; nothing is replaced
    const again = parse(await runTool(VIEWS, cwd, { ...args, dump: true, pid: [4, 77] }, { ...env, ...jobEnv }, bin));
    assert.equal(again.secret_values.raw_output_file, out.secret_values.raw_output_file);
    assert.notEqual(again.secret_values.artefacts.dir, out.secret_values.artefacts.dir, "each dump has a directory of its own");
    await stubVol(cwd, bin, { ...CFG, run: { stdout: stdout + row(900, "extra.exe"), exports: exportsText } });
    const other = parse(await runTool(VIEWS, cwd, { ...args }, { ...env, ...jobEnv }, bin));
    assert.match(other.secret_values.raw_output_file, /-output\.txt$/);
    assert.equal(await readFile(raw, "utf8"), stdout);
    assert.deepEqual((await files(outDir)).filter((f) => /\/\.[^/]*$/.test(f)), [], "no hidden temporary file");
  });
});

test("a long output is paged: the answer holds limit lines and the whole judged output is a file the answer names with its size and sha256", { timeout: 120 * SECOND }, async () => {
  await withCwd(async (cwd, bin) => {
    const env = await stubVol(cwd, bin, { ...CFG, run: { stdout: HEADER, flood: 3_000_000 } });
    const out = parse(await runTool(VIEWS, cwd, { ...base, limit: 25 }, env, bin));
    assert.equal(out.status, "complete");
    assert.equal(out.output.returned, 25);
    assert.equal(out.output.truncated, true);
    assert.ok(out.output.matched > 50000);
    const file = join(cwd, out.output.all_results);
    const body = await readFile(file);
    assert.equal(body.toString().trim().split("\n").length, out.output.matched);
    assert.equal(out.output.file_bytes, body.length);
    assert.equal(out.output.file_sha256, sha(body));
  });
});

test("the output cap ends the program and the answer is partial with what was read kept; a hang is ended at the clock with its rows kept", { timeout: 180 * SECOND }, async () => {
  await withCwd(async (cwd, bin) => {
    const pid = join(cwd, "run.pid");
    const env = await stubVol(cwd, bin, { ...CFG, run: { stdout: HEADER + row(4, "System"), flood: 8_000_000, sleep: 120, pid } });
    // the cap is the module's own constant; the test lowers it in a process of its own, as the harness would not
    const code = [
      "import importlib.util, sys",
      "spec = importlib.util.spec_from_file_location('t', sys.argv[1]); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)",
      "m.OUT_CAP = 2_000_000",
      "m.run_guarded()",
    ].join("\n");
    const child = spawn("python3", ["-c", code, VIEWS], { cwd, env: { ...process.env, ...env, PATH: `${bin}:${process.env.PATH}`, AGENT_ID: "s1" } });
    let stdout = "", stderr = "";
    child.stdout.on("data", (c) => (stdout += c));
    child.stderr.on("data", (c) => (stderr += c));
    child.stdin.end(JSON.stringify({ ...base, limit: 10 }));
    await new Promise<number | null>((r) => child.on("close", (c) => r(c)));
    assert.ok(!stderr.includes("Traceback"), stderr);
    const out = JSON.parse(stdout);
    assert.equal(out.status, "partial");
    assert.match(out.status_basis, /wrote more than the tool reads/);
    assert.ok(out.output.matched > 1000, "what was read is kept");
    const stub = await pidOf(pid);
    assert.ok(stub && !alive(stub), "the program was ended");
    // a hang
    const env2 = await stubVol(cwd, bin, { ...CFG, run: { stdout: HEADER + row(4, "System") + row(8, "smss.exe"), sleep: 120, pid } });
    const run = await runTool(VIEWS, cwd, { ...base, max_seconds: 30 }, env2, bin);
    const out2 = parse(run);
    assert.equal(out2.status, "partial");
    assert.match(out2.status_basis, /not finished in the time/);
    assert.equal(out2.scope.rows, 3);
    assert.ok(run.ms < 60 * SECOND, `${run.ms} ms`);
    const stub2 = await pidOf(pid);
    assert.ok(stub2 && !alive(stub2));
  });
});

test("a plugin that fails is a failure with its first log lines judged; an empty output and a log that says pages were missing are partial, not a clean absence", { timeout: 120 * SECOND }, async () => {
  await withCwd(async (cwd, bin) => {
    const token = SHAPES.ghp(rng(51));
    let env = await stubVol(cwd, bin, { ...CFG, run: { code: 1, stderr: `Unsatisfied requirement ${token}\n` } });
    let run = await runTool(VIEWS, cwd, base, env, bin);
    let out = parse(run);
    assert.equal(out.status, "failed");
    assert.equal(run.code, 1);
    assert.ok(!run.stdout.includes(token));
    assert.deepEqual(await files(join(cwd, "work")), []);
    env = await stubVol(cwd, bin, { ...CFG, run: { stdout: "" } });
    out = parse(await runTool(VIEWS, cwd, base, env, bin));
    assert.equal(out.status, "partial");
    assert.match(out.status_basis, /printed no row/);
    env = await stubVol(cwd, bin, { ...CFG, run: { stdout: HEADER + row(4, "System"), stderr: "WARNING volatility3.framework: Invalid address at 0x1000\n" } });
    out = parse(await runTool(VIEWS, cwd, base, env, bin));
    assert.equal(out.status, "partial");
    assert.equal(out.scope.pages_missing_lines, 1);
  });
});

test("SIGTERM, also at a plugin that ignores it, gives one document, exit 143, and keeps the files being written under a name ending in .partial", { timeout: 180 * SECOND }, async () => {
  await withCwd(async (cwd, bin) => {
    for (const ignore of [false, true]) {
      const pid = join(cwd, `sig-${ignore}.pid`);
      const { env: jobEnv, out: outDir } = await secretJob(cwd, 2 + Number(ignore));
      const env = await stubVol(cwd, bin, { ...CFG, run: { stdout: HEADER, flood: 400_000, sleep: 120, pid, ignore_term: ignore } });
      const run = await runTool(VIEWS, cwd, { ...base, write_values: true, limit: 5 }, { ...env, ...jobEnv }, bin, "SIGTERM", 0,
        async () => (await pidOf(pid)) !== null && (await readdir(join(outDir, "tool-output")).catch(() => [])).length > 0 && (await readdir(join(outDir, "vol_views")).catch(() => [])).length > 0);
      assert.equal(run.code, 143, run.stderr);
      const out = parse(run);
      assert.equal(out.status, "failed");
      assert.equal(out.interrupted, true);
      assert.equal(run.stdout.trim().split("\n}\n").length, 1, "one document");
      assert.ok(out.kept_results.length >= 2 && out.kept_results.every((n: string) => n.endsWith(".partial")), JSON.stringify(out.kept_results));
      assert.deepEqual((await files(outDir)).filter((f) => /\/\.[^/]*$/.test(f)), [], "no hidden temporary file");
      const stub = await pidOf(pid);
      assert.ok(stub && !alive(stub), `the stand-in is gone (ignore_term ${ignore})`);
    }
  });
});

test("hostile parameters give a JSON refusal, never a Traceback", { timeout: 120 * SECOND }, async () => {
  await withCwd(async (cwd, bin) => {
    const env = await stubVol(cwd, bin, { ...CFG, run: { stdout: HEADER } });
    assert.equal(spawnSync("mkfifo", [join(cwd, "inputs", "pipe.raw")]).status, 0);
    const bad: unknown[] = [
      {}, { ...base, path: "" }, { ...base, path: "inputs/mem.raw\u0000" }, { ...base, path: "inputs/\ud800" }, { ...base, path: "inputs/pipe.raw" }, { ...base, path: "inputs" },
      { ...base, path: "inputs/none.raw" }, { ...base, question: "" }, { ...base, question: "a b" }, { ...base, question: 7 }, { ...base, question: "x".repeat(129) },
      { ...base, question: "../../bin/sh" }, { ...base, question: "windows.pslist; id" }, { ...base, write_values: "yes" }, { ...base, dump: 1 }, { ...base, max_seconds: 1e999 },
      { ...base, max_seconds: 10 ** 30 }, { ...base, max_seconds: true }, { ...base, limit: 0 }, { ...base, limit: 10 ** 30 }, { ...base, symbols_dir: "inputs/mem.raw" },
      { ...base, symbols_dir: 3 }, { ...base, surprise: 1 },
    ];
    for (const args of bad) {
      const t0 = Date.now();
      const run = await runTool(VIEWS, cwd, args, env, bin);
      const out = parse(run);
      assert.equal(out.status, "failed", JSON.stringify(args).slice(0, 90));
      assert.ok(out.error && out.status_basis);
      assert.equal(run.code, 1);
      assert.ok(Date.now() - t0 < 10 * SECOND);
    }
    for (const raw of [Buffer.from("{"), Buffer.from("[".repeat(200000)), Buffer.from("{\"a\":".repeat(100000)), Buffer.from("[1]"), Buffer.from([0x7b, 0x22, 0xff, 0x22, 0x3a, 0x31, 0x7d])]) {
      const child = spawn("python3", [VIEWS], { cwd, env: { ...process.env, ...env, PATH: `${bin}:${process.env.PATH}` } });
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
    // an image whose name starts with "-" reaches vol as an absolute path an option cannot be mistaken for
    await writeFile(join(cwd, "-image.raw"), Buffer.alloc(4096));
    await writeReceipt(cwd, { inputs: { path: "-image.raw" } }, "dash.json");
    parse(await runTool(VIEWS, cwd, { path: "-image.raw", question: "windows.pslist", readiness: "inputs/dash.json" }, env, bin));
    const ran = (await calls(cwd)).find((c) => c.argv.includes("windows.pslist.PsList") && !c.argv.includes("--help"))!;
    assert.ok(ran.argv[ran.argv.indexOf("-f") + 1].startsWith("/"));
  });
});

test("the manifest declares secret_output for write_values and says what the code does; every vol call carries --offline", async () => {
  const man = JSON.parse(await readFile(join(ROOT, "packs", "memory-forensics", "tools", "vol_views", "manifest.json"), "utf8")) as Record<string, any>;
  assert.deepEqual(man.secret_output, { when_args: ["write_values"] });
  assert.equal(man.params.write_values.type, "boolean");
  assert.equal(man.params.write_values.default, undefined);
  assert.equal(man.timeout_seconds, 600);
  assert.equal(man.needs, undefined);
  assert.deepEqual(Object.keys(man.params).sort(), ["dump", "limit", "max_seconds", "path", "pid", "question", "readiness", "symbols_dir", "write_values"]);
  const script = await readFile(VIEWS, "utf8");
  const constant = (name: string): number => Number(new RegExp(`^${name} = ([0-9.]+)`, "m").exec(script)![1].split(".")[0]);
  assert.match(man.description, /default 420, at most 540/);
  assert.match(script, /DEFAULT_SECONDS, MAX_SECONDS, MIN_SECONDS = 420\.0, 540\.0, 10\.0/);
  assert.ok(man.description.includes("10 s reserve") && constant("RESERVE") === 10);
  assert.ok(man.description.includes("help 90 s, the plugin's --help 60 s") && constant("HELP_SECONDS") === 90 && constant("PLUGIN_HELP_SECONDS") === 60);
  assert.ok(man.description.includes("1 GiB of output") && /^OUT_CAP = 1 << 30/m.test(script) && man.description.includes("64 MiB of log") && /^ERR_SCAN_CAP = 64 << 20/m.test(script));
  assert.ok(man.description.includes("longer than 1 MiB") && /^MAX_LINE = 1 << 20/m.test(script));
  const vectors = script.split("\n").filter((l) => /^\s*base = \[vol|argv = base|run_engine\(base/.test(l));
  assert.ok(vectors.length >= 3, vectors.join("\n"));
  assert.match(script, /base = \[vol, "--offline"\]/);
  assert.ok(!/start_new_session|setsid/.test(script.replace(/^# BEGIN SHARED PROCESS[\s\S]*?^# END SHARED PROCESS/m, "")));
});

test("one real run, when a Volatility is on PATH (otherwise skipped, and said so)", { timeout: 300 * SECOND }, async (t) => {
  const has = spawnSync("sh", ["-c", "command -v vol"], { encoding: "utf8" });
  if (has.status !== 0) { t.skip("no `vol` on PATH: the readings of the real listing and of a plugin's output were not exercised"); return; }
  t.skip("a real run needs a small Windows image and its symbol table, which this repository does not carry (ask the owner for a public sample)");
});

test("symbols_dir takes no semicolon, and the listing is read in the layout argparse gives Volatility 3 (a dotted name per line under the PLUGIN section)", { timeout: 60 * SECOND }, async () => {
  await withCwd(async (cwd, bin) => {
    const real = "usage: vol [-h] ... PLUGIN ...\n\nPlugins:\n  PLUGIN\n    windows.pslist.PsList  Lists the processes\n    linux.lsof.Lsof  Lists open files\n";
    const env = await stubVol(cwd, bin, { help: real, help_err: HELP_ERR, plugin_help: PLUGIN_HELP, run: { stdout: HEADER + row(4, "System") } });
    const out = parse(await runTool(VIEWS, cwd, base, env, bin));
    assert.equal(out.plugin, "windows.pslist.PsList");
    assert.equal(out.status, "complete");
    await mkdir(join(cwd, "a;b"));
    const bad = parse(await runTool(VIEWS, cwd, { ...base, symbols_dir: "a;b" }, env, bin));
    assert.match(bad.error, /semicolon/);
  });
});
