/**
 * isf_intake (memory-forensics): an operator-supplied kernel turned into an ISF by dwarf2json, ready only on an exact banner match.
 *
 * Both programs are stand-ins laid down by the test: `vol` (banners.Banners prints the tab-separated table Volatility 3 documents) and
 * `dwarf2json` (--version, and `linux --elf|--system-map FILE` printing an ISF whose linux_banner symbol carries the banner as base64
 * constant_data, behind enough other symbols that the banner is not in the first block read). The banners are built here; the expected
 * verdicts, digests and file names are computed by the test. Each case fails on the base code, where the tool is missing.
 */
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmod, mkdir, readFile, readdir, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { ROOT, withCwd } from "./tool-library-harness.ts";
import { MEM, SHAPES, rng, runTool } from "./memory-f1-support.ts";

const ISF = join(MEM, "isf_intake", "run.py");
const PY = spawnSync("python3", ["-c", "import sys; print(sys.executable)"], { encoding: "utf8" }).stdout.trim();
const SECOND = 1000;
const sha = (b: Buffer | string): string => createHash("sha256").update(b).digest("hex");

const banner = (release: string, gcc = "gcc 11.4.0"): string => `Linux version ${release} (buildd@lcy02) (${gcc}) #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023`;
const B91 = banner("5.15.0-91-generic");
const bannersOut = (...b: string[]): string => "Offset\tBanner\n" + b.map((x, i) => `0x${(0x1000 + i).toString(16)}\tb'${x}\\n'\n`).join("");

type D2J = { banner?: string | null; code?: number; stderr?: string; sleep?: number; pid?: string; ignore_term?: boolean; extra?: number };
type Config = { log: string; banners?: string; vol_code?: number; d2j?: D2J };

async function stubs(cwd: string, bin: string, cfg: Omit<Config, "log">, only: { vol?: boolean; d2j?: boolean } = {}): Promise<Record<string, string>> {
  const log = join(cwd, "argv.log");
  await writeFile(join(cwd, "stub.json"), JSON.stringify({ log, ...cfg }));
  const head = `#!${PY}\nimport base64, json, os, signal, sys, time\ncfg = json.load(open(os.environ["STUB_CFG"]))\na = sys.argv[1:]\nopen(cfg["log"], "a").write(json.dumps({"prog": os.path.basename(sys.argv[0]), "argv": a, "cwd": os.getcwd()}) + "\\n")\n`;
  if (only.vol !== false) {
    await writeFile(join(bin, "vol"), head + `sys.stdout.write(cfg.get("banners", "")); sys.exit(cfg.get("vol_code", 0))\n`);
    await chmod(join(bin, "vol"), 0o755);
  }
  if (only.d2j !== false) {
    await writeFile(join(bin, "dwarf2json"), head + `
if a == ["--version"]:
    print("dwarf2json 0.9.0"); sys.exit(0)
b = cfg.get("d2j", {})
if b.get("pid"):
    open(b["pid"], "w").write(str(os.getpid()))
if b.get("ignore_term"):
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
sys.stderr.write(b.get("stderr", "")); sys.stderr.flush()
sym = {}
pad = b.get("extra", 200000)
sys.stdout.write('{"metadata": {"producer": {"name": "stub"}}, "symbols": {')
n = 0
while n < pad:
    s = '"sym%d": {"address": %d}, ' % (n, n); sys.stdout.write(s); n += len(s)
sys.stdout.flush()
if b.get("banner") is not None:
    data = base64.b64encode(b["banner"].encode()).decode()
    sys.stdout.write('"linux_banner": {"type": {"kind": "array", "count": 80, "subtype": {"kind": "base", "name": "char"}}, "address": 4096, "constant_data": "%s"}' % data)
else:
    sys.stdout.write('"last": {"address": 1}')
sys.stdout.write('}}\\n'); sys.stdout.flush()
if b.get("sleep"):
    time.sleep(b["sleep"])
sys.exit(b.get("code", 0))
`);
    await chmod(join(bin, "dwarf2json"), 0o755);
  }
  await writeFile(join(cwd, "inputs", "mem.lime"), Buffer.alloc(8192));
  await writeFile(join(cwd, "inputs", "vmlinux"), Buffer.from("not really elf"));
  return { STUB_CFG: join(cwd, "stub.json") };
}

const calls = async (cwd: string): Promise<Array<{ prog: string; argv: string[]; cwd: string }>> =>
  (await readFile(join(cwd, "argv.log"), "utf8").catch(() => "")).split("\n").filter(Boolean).map((l) => JSON.parse(l));
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
const args = { path: "inputs/mem.lime", debug: "inputs/vmlinux", kind: "elf", build_identity: "5.15.0-91-generic", symbols_out: "work/s1/symbols" };

test("ready only on an exact match: the table is placed, with its sha256, the converter's version and argv; the image's banners were found offline", { timeout: 120 * SECOND }, async () => {
  await withCwd(async (cwd, bin) => {
    const env = await stubs(cwd, bin, { banners: bannersOut(B91), d2j: { banner: B91 } });
    const out = parse(await runTool(ISF, cwd, args, env, bin));
    assert.equal(out.verdict, "ready", JSON.stringify(out));
    assert.equal(out.status, "complete");
    assert.equal(out.table.banner_equals_a_banner_of_the_image, true);
    assert.equal(out.table.kept, true);
    const dir = join(cwd, "work", "s1", "symbols");
    const listed = (await readdir(dir)).sort();
    assert.equal(listed.length, 1, listed.join(","));
    const name = `isf_intake-${sha(B91).slice(0, 16)}.json`;
    assert.deepEqual(listed, [name]);
    const body = await readFile(join(dir, name));
    assert.equal(out.table.sha256, sha(body));
    assert.equal(out.table.bytes, body.length);
    assert.ok(body.length > 150000, "the banner was found behind more than a block of other symbols");
    assert.equal((await stat(join(dir, name))).mode & 0o777, 0o600);
    assert.equal((await stat(dir)).mode & 0o777, 0o700);
    assert.equal(out.converter.version, "0.9.0");
    assert.equal(out.converter.exit_code, 0);
    assert.equal(out.converter.argv[0], "dwarf2json");
    assert.deepEqual(out.converter.argv.slice(1, 3), ["linux", "--elf"]);
    assert.equal(out.table.banner_release, "5.15.0-91-generic");
    assert.ok(!JSON.stringify(out).includes("buildd@lcy02"), "only the release word of a banner is printed");
    const log = await calls(cwd);
    const vol = log.find((c) => c.prog === "vol")!;
    assert.ok(vol.argv.includes("--offline") && vol.argv.includes("banners.Banners") && vol.cwd === "/");
    // an identical rerun names the same file and replaces nothing
    const again = parse(await runTool(ISF, cwd, args, env, bin));
    assert.equal(again.verdict, "ready");
    assert.deepEqual((await readdir(dir)).sort(), [name]);
  });
});

test("a near miss is no match: the same release with another compiler, a table for another release, a System.map (no banner): blocked, and no table is left", { timeout: 120 * SECOND }, async () => {
  await withCwd(async (cwd, bin) => {
    const dir = join(cwd, "work", "s1", "symbols");
    let env = await stubs(cwd, bin, { banners: bannersOut(B91), d2j: { banner: banner("5.15.0-91-generic", "gcc 12.3.0") } });
    let out = parse(await runTool(ISF, cwd, args, env, bin));
    assert.equal(out.verdict, "blocked");
    assert.match(out.verdict_basis, /differs from every banner of the image, even where the release is the same/);
    assert.equal(out.table.kept, false);
    assert.deepEqual(await files(dir), []);
    // another release in the table; the image names two kernels and the operator's identity is the first
    const other = banner("5.4.0-1-generic");
    env = await stubs(cwd, bin, { banners: bannersOut(B91, other), d2j: { banner: other } });
    out = parse(await runTool(ISF, cwd, args, env, bin));
    assert.equal(out.verdict, "blocked");
    assert.equal(out.table.banner_equals_a_banner_of_the_image, true);
    assert.equal(out.table.build_identity_agrees, false);
    assert.match(out.verdict_basis, /does not begin with the build identity/);
    assert.deepEqual(await files(dir), []);
    // a System.map: the table has no banner
    env = await stubs(cwd, bin, { banners: bannersOut(B91), d2j: { banner: null } });
    out = parse(await runTool(ISF, cwd, { ...args, kind: "system_map" }, env, bin));
    assert.equal(out.verdict, "blocked");
    assert.match(out.verdict_basis, /no linux_banner constant/);
    const conv = (await calls(cwd)).filter((c) => c.prog === "dwarf2json" && c.argv[0] === "linux").pop()!;
    assert.equal(conv.argv[1], "--system-map");
    assert.deepEqual(await files(dir), []);
  });
});

test("an image with no banner, or none for the operator's identity, ends the call before anything is converted", { timeout: 120 * SECOND }, async () => {
  await withCwd(async (cwd, bin) => {
    let env = await stubs(cwd, bin, { banners: "Offset\tBanner\n" });
    let out = parse(await runTool(ISF, cwd, args, env, bin));
    assert.equal(out.verdict, "blocked");
    assert.match(out.verdict_basis, /found no Linux banner/);
    env = await stubs(cwd, bin, { banners: bannersOut(banner("6.1.0-13-amd64")) });
    out = parse(await runTool(ISF, cwd, args, env, bin));
    assert.equal(out.verdict, "blocked");
    assert.match(out.verdict_basis, /no banner of the image begins/);
    assert.ok(!(await calls(cwd)).some((c) => c.prog === "dwarf2json" && c.argv[0] === "linux"), "the converter was not run");
    // a Darwin banner is not a Linux one: macOS is not handled
    env = await stubs(cwd, bin, { banners: bannersOut("Darwin Kernel Version 23.4.0: Wed Feb 21 root:xnu-10063/RELEASE_X86_64") });
    assert.equal(parse(await runTool(ISF, cwd, args, env, bin)).verdict, "blocked");
  });
});

test("a converter that fails is a failure with its log judged and no table; a missing converter or vol is a failure with verdict blocked", { timeout: 120 * SECOND }, async () => {
  await withCwd(async (cwd, bin) => {
    const token = SHAPES.ghp(rng(61));
    let env = await stubs(cwd, bin, { banners: bannersOut(B91), d2j: { banner: B91, code: 2, stderr: `unsupported DWARF version ${token}\n` } });
    let run = await runTool(ISF, cwd, args, env, bin);
    let out = parse(run);
    assert.equal(out.status, "failed");
    assert.equal(out.verdict, "blocked");
    assert.equal(run.code, 1);
    assert.ok(!run.stdout.includes(token));
    assert.deepEqual(await files(join(cwd, "work", "s1", "symbols")), []);
    const empty = join(cwd, "empty");
    await mkdir(empty);
    run = await runTool(ISF, cwd, args, { PATH: `${empty}:/usr/bin:/bin` });
    out = parse(run);
    assert.equal(out.status, "failed");
    assert.match(out.error, /dwarf2json is not on PATH/);
    env = await stubs(cwd, bin, {}, { vol: false });
    const bin2 = join(cwd, "bin2");
    await mkdir(bin2);
    await writeFile(join(bin2, "dwarf2json"), "#!/bin/sh\nexit 0\n");
    await chmod(join(bin2, "dwarf2json"), 0o755);
    run = await runTool(ISF, cwd, args, { PATH: `${bin2}:/usr/bin:/bin` });
    assert.match(parse(run).error, /no `vol` on PATH/);
  });
});

test("the converter that hangs is ended with its tree and the call is partial with no table; one that ignores SIGTERM too; more output than the cap ends it", { timeout: 180 * SECOND }, async () => {
  await withCwd(async (cwd, bin) => {
    const pid = join(cwd, "d2j.pid");
    const env = await stubs(cwd, bin, { banners: bannersOut(B91), d2j: { banner: B91, sleep: 120, pid, ignore_term: true } });
    const run = await runTool(ISF, cwd, { ...args, max_seconds: 30 }, env, bin);
    const out = parse(run);
    assert.equal(out.verdict, "unknown");
    assert.equal(out.status, "partial");
    assert.ok(run.ms < 60 * SECOND, `${run.ms} ms`);
    const stub = await pidOf(pid);
    assert.ok(stub && !alive(stub));
    assert.deepEqual(await files(join(cwd, "work", "s1", "symbols")), []);
    // the cap is the module's own constant, lowered in a process of its own
    const code = [
      "import importlib.util, sys",
      "spec = importlib.util.spec_from_file_location('t', sys.argv[1]); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)",
      "m.MAX_TABLE_BYTES = 100000",
      "m.run_guarded()",
    ].join("\n");
    const env2 = await stubs(cwd, bin, { banners: bannersOut(B91), d2j: { banner: B91, extra: 5_000_000, sleep: 120, pid } });
    const child = spawn("python3", ["-c", code, ISF], { cwd, env: { ...process.env, ...env2, PATH: `${bin}:${process.env.PATH}`, AGENT_ID: "s1" } });
    let stdout = "", stderr = "";
    child.stdout.on("data", (c) => (stdout += c));
    child.stderr.on("data", (c) => (stderr += c));
    child.stdin.end(JSON.stringify(args));
    await new Promise((r) => child.on("close", r));
    assert.ok(!stderr.includes("Traceback"), stderr);
    const capped = JSON.parse(stdout);
    assert.equal(capped.verdict, "unknown");
    assert.match(capped.verdict_basis, /wrote more than the tool reads/);
    const stub2 = await pidOf(pid);
    assert.ok(stub2 && !alive(stub2));
    assert.deepEqual(await files(join(cwd, "work", "s1", "symbols")), []);
  });
});

test("SIGTERM gives one document, exit 143, and removes the table being written", { timeout: 120 * SECOND }, async () => {
  await withCwd(async (cwd, bin) => {
    const pid = join(cwd, "sig.pid");
    const env = await stubs(cwd, bin, { banners: bannersOut(B91), d2j: { banner: B91, sleep: 120, pid } });
    const run = await runTool(ISF, cwd, args, env, bin, "SIGTERM", 0, async () => (await pidOf(pid)) !== null && (await files(join(cwd, "work", "s1", "symbols"))).length > 0);
    assert.equal(run.code, 143, run.stderr);
    const out = parse(run);
    assert.equal(out.status, "failed");
    assert.equal(out.interrupted, true);
    assert.equal(run.stdout.trim().split("\n}\n").length, 1);
    assert.deepEqual(await files(join(cwd, "work", "s1", "symbols")), []);
    const stub = await pidOf(pid);
    assert.ok(stub && !alive(stub));
  });
});

test("a debug file over the limit is refused before anything runs; symbols_out must be under the run directory (under $OUT in a job); hostile parameters never give a Traceback", { timeout: 120 * SECOND }, async () => {
  await withCwd(async (cwd, bin) => {
    const env = await stubs(cwd, bin, { banners: bannersOut(B91), d2j: { banner: B91 } });
    const code = [
      "import importlib.util, sys",
      "spec = importlib.util.spec_from_file_location('t', sys.argv[1]); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)",
      "m.MAX_DEBUG_BYTES = 4",
      "m.run_guarded()",
    ].join("\n");
    const child = spawn("python3", ["-c", code, ISF], { cwd, env: { ...process.env, ...env, PATH: `${bin}:${process.env.PATH}` } });
    let stdout = "";
    child.stdout.on("data", (c) => (stdout += c));
    child.stdin.end(JSON.stringify(args));
    await new Promise((r) => child.on("close", r));
    assert.match(JSON.parse(stdout).error, /larger than 4 bytes/);
    assert.equal((await calls(cwd)).length, 0, "nothing ran");
    assert.equal(parse(await runTool(ISF, cwd, { ...args, symbols_out: "/tmp/elsewhere" }, env, bin)).status, "failed");
    assert.equal(parse(await runTool(ISF, cwd, { ...args, symbols_out: "work/s1/symbols" }, { ...env, JOB_ID: "j", OUT: join(cwd, "o") }, bin)).status, "failed");
    assert.equal(spawnSync("mkfifo", [join(cwd, "inputs", "pipe")]).status, 0);
    const bad: unknown[] = [
      {}, { ...args, path: "" }, { ...args, path: "inputs/mem.lime\u0000" }, { ...args, path: "inputs/\ud800" }, { ...args, path: "inputs/pipe" }, { ...args, debug: "inputs/pipe" },
      { ...args, path: "inputs" }, { ...args, debug: "inputs/none" }, { ...args, kind: "macho" }, { ...args, kind: 3 }, { ...args, build_identity: "" }, { ...args, build_identity: "5 15" },
      { ...args, build_identity: "x".repeat(81) }, { ...args, build_identity: "../../x" }, { ...args, max_seconds: 1e999 }, { ...args, max_seconds: 10 ** 30 }, { ...args, max_seconds: true },
      { ...args, symbols_out: "" }, { ...args, symbols_out: 5 }, { ...args, surprise: 1 },
    ];
    for (const a of bad) {
      const t0 = Date.now();
      const run = await runTool(ISF, cwd, a, env, bin);
      const out = parse(run);
      assert.equal(out.status, "failed", JSON.stringify(a).slice(0, 90));
      assert.equal(run.code, 1);
      assert.ok(Date.now() - t0 < 10 * SECOND);
    }
    for (const raw of [Buffer.from("{"), Buffer.from("[".repeat(200000)), Buffer.from("{\"a\":".repeat(100000)), Buffer.from("[1]"), Buffer.from([0x7b, 0x22, 0xff, 0x22, 0x3a, 0x31, 0x7d])]) {
      const c = spawn("python3", [ISF], { cwd, env: { ...process.env, ...env, PATH: `${bin}:${process.env.PATH}` } });
      let so = "", se = "";
      c.stdout.on("data", (d) => (so += d));
      c.stderr.on("data", (d) => (se += d));
      c.stdin.on("error", () => undefined);
      c.stdin.end(raw);
      const status = await new Promise<number | null>((r) => c.on("close", (x) => r(x)));
      assert.ok(!se.includes("Traceback"), se);
      assert.equal(JSON.parse(so).status, "failed");
      assert.equal(status, 1);
    }
  });
});

test("canaries in the image's banner and in paths are not printed; the manifest says what the code does", async () => {
  await withCwd(async (cwd, bin) => {
    const token = SHAPES.ghp(rng(71));
    const forged = banner(`5.15.0-${token}`);
    const env = await stubs(cwd, bin, { banners: bannersOut(B91, forged), d2j: { banner: B91 } });
    await writeFile(join(cwd, "inputs", `k_${token}`), "x");
    const run = await runTool(ISF, cwd, { ...args, debug: `inputs/k_${token}` }, env, bin);
    assert.ok(!run.stdout.includes(token));
    assert.equal(parse(run).verdict, "ready");
  });
  const man = JSON.parse(await readFile(join(ROOT, "packs", "memory-forensics", "tools", "isf_intake", "manifest.json"), "utf8")) as Record<string, any>;
  assert.equal(man.secret_output, undefined, "a symbol table is not a secret");
  assert.equal(man.timeout_seconds, 600);
  assert.deepEqual(Object.keys(man.params).sort(), ["build_identity", "debug", "kind", "max_seconds", "path", "symbols_out"]);
  const script = await readFile(ISF, "utf8");
  assert.match(man.description, /default 420, at most 540/);
  assert.match(script, /DEFAULT_SECONDS, MAX_SECONDS, MIN_SECONDS = 420\.0, 540\.0, 10\.0/);
  assert.ok(man.description.includes("10 s reserve") && /^RESERVE = 10\.0/m.test(script));
  assert.ok(man.description.includes("banners at most 150 s") && /^BANNERS_SECONDS = 150\.0/m.test(script));
  assert.ok(man.description.includes("more than 4 GiB of converter output") && /^MAX_TABLE_BYTES = 4 << 30/m.test(script));
  assert.ok(man.description.includes("16 MiB of banner output") && /^INFO_CAP = 16 << 20/m.test(script));
  assert.ok(man.description.includes("larger than 8 GiB") && /^MAX_DEBUG_BYTES = 8 << 30/m.test(script));
  assert.match(script, /\[vol, "--offline", "-q", "-f", image, "banners\.Banners"\]/);
  assert.ok(!/start_new_session|setsid/.test(script.replace(/^# BEGIN SHARED PROCESS[\s\S]*?^# END SHARED PROCESS/m, "")));
});

test("one real run, when dwarf2json and vol are on PATH (otherwise skipped, and said so)", { timeout: 300 * SECOND }, async (t) => {
  const has = spawnSync("sh", ["-c", "command -v dwarf2json && command -v vol"], { encoding: "utf8" });
  if (has.status !== 0) { t.skip("no dwarf2json and vol on PATH: the real converter's output and Volatility's banner listing were not exercised"); return; }
  t.skip("a real run needs a kernel's debug file and a memory image of that kernel, which this repository does not carry");
});
