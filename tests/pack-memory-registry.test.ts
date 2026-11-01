/**
 * mem_registry (memory-forensics): the hive inventory and selected non-secret registry records, read through Volatility, offline.
 *
 * The tool is driven against a stand-in `vol` whose behaviour a test lays down in a JSON file. The hivelist and printkey outputs below are
 * written by hand to the columns Volatility 3's quick renderer documents (Offset / FileFullPath / File output; Last Write Time / Hive
 * Offset / Type / Key / Name / Data / Volatile); they are NOT recorded from a run of the pinned Volatility (2.28.2), which was not
 * available where this was written. One real run is gated on a `vol` being present. Canaries are random secret-shaped strings built from
 * pieces (tests/memory-f1-support.ts): a P2 check on every printed slot and file. Each case fails on the base code, where the tool is missing.
 */
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { chmod, mkdir, readFile, readdir, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { ROOT, withCwd } from "./tool-library-harness.ts";
import { MEM, SHAPES, rng, runTool } from "./memory-f1-support.ts";

const REG = join(MEM, "mem_registry", "run.py");
const PY = spawnSync("python3", ["-c", "import sys; print(sys.executable)"], { encoding: "utf8" }).stdout.trim();
const SECOND = 1000;

type Behaviour = { stdout?: string; stderr?: string; code?: number; sleep?: number; ignore_term?: boolean; pid?: string; rows?: number };
type Config = { log: string; help?: Behaviour; hivelist?: Behaviour; printkey?: Behaviour };

const HELP = "usage: vol [-h] ...\n\nPlugins:\n  {windows.registry.hivelist.HiveList,windows.registry.printkey.PrintKey,windows.info.Info}\n";
const HELP_ERR = "Volatility 3 Framework 2.28.2\n";
const SYSTEM = 0xf8a000010010, SAM = 0xf8a0001a2010, SECURITY = 0xf8a0001c9010, NTUSER = 0xf8a0002e5010, UNNAMED = 0xf8a000300010;
const hex = (n: number): string => "0x" + n.toString(16);
const HIVELIST = (unnamed = true): string =>
  "Volatility 3 Framework 2.28.2\n\nOffset\tFileFullPath\tFile output\n\n" +
  [[SYSTEM, "\\REGISTRY\\MACHINE\\SYSTEM"], [SAM, "\\SystemRoot\\System32\\Config\\SAM"], [SECURITY, "\\SystemRoot\\System32\\Config\\SECURITY"], [NTUSER, "\\??\\C:\\Users\\alice\\ntuser.dat"], ...(unnamed ? [[UNNAMED, ""]] : [])]
    .map(([o, p]) => `${hex(o as number)}\t${p}\tDisabled\n`).join("");
const PK_HEAD = "Volatility 3 Framework 2.28.2\n\nLast Write Time\tHive Offset\tType\tKey\tName\tData\tVolatile\n\n";
const pkRow = (hive: number, type: string, key: string, name: string, data = "-"): string =>
  `2024-01-02 10:00:00.000000 UTC\t${hex(hive)}\t${type}\t${key}\t${name}\t${data}\tFalse\n`;
const TCPIP = "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Services\\Tcpip\\Parameters";

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
mode = "help" if "--help" in a else "hivelist" if any("hivelist" in x for x in a) else "printkey" if any("printkey" in x for x in a) else "other"
b = cfg.get(mode, {})
if b.get("pid"):
    open(b["pid"], "w").write(str(os.getpid()))
if b.get("ignore_term"):
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
sys.stderr.write(b.get("stderr", "")); sys.stderr.flush()
sys.stdout.write(b.get("stdout", "")); sys.stdout.flush()
for i in range(b.get("rows", 0)):
    sys.stdout.write("2024-01-02 10:00:00.000000 UTC\\t0xf8a000010010\\tREG_SZ\\t\\\\REGISTRY\\\\MACHINE\\\\SYSTEM\\\\Row\\tv%d\\tdata%d\\tFalse\\n" % (i, i))
    sys.stdout.flush()
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
const pidOf = async (file: string): Promise<number | null> => { try { return Number((await readFile(file, "utf8")).trim()) || null; } catch { return null; } };
type Answer = Record<string, any>;
const parse = (r: { stdout: string; stderr: string }): Answer => {
  assert.ok(!r.stderr.includes("Traceback"), r.stderr);
  return JSON.parse(r.stdout) as Answer;
};

async function secretJob(cwd: string, n = 1): Promise<{ env: Record<string, string>; out: string }> {
  const out = join(cwd, "job-out");
  await mkdir(out, { recursive: true });
  return { env: { JOB_ID: `job${n}`, OUT: out, SECRET_OUTPUT: "1" }, out };
}

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

test("hivelist: one record per hive with its offset, plugin and version; SAM and SECURITY are named credential-class; coverage counts the unnamed one; every vol call is offline", { timeout: 120 * SECOND }, async () => {
  await withCwd(async (cwd, bin) => {
    const env = await stubVol(cwd, bin, { help: { stdout: HELP, stderr: HELP_ERR }, hivelist: { stdout: HIVELIST() } });
    const run = await runTool(REG, cwd, { path: "inputs/mem.raw" }, env, bin);
    const out = parse(run);
    assert.equal(out.mode, "hivelist");
    assert.equal(out.plugin, "windows.registry.hivelist.HiveList");
    assert.equal(out.volatility, "2.28.2");
    const rows: any[] = out.records.rows;
    assert.deepEqual(rows.map((r) => r.hive_offset), [SYSTEM, SAM, SECURITY, NTUSER, UNNAMED].map(hex));
    assert.deepEqual(rows.map((r) => r.credential_class), [false, true, true, false, false]);
    assert.ok(rows.every((r) => r.plugin === "windows.registry.hivelist.HiveList" && r.volatility === "2.28.2"));
    assert.deepEqual(out.coverage.hives_found, 5);
    assert.equal(out.coverage.hives_named, 4);
    assert.equal(out.status, "partial", "an unnamed hive is a hive whose name page was not readable");
    assert.match(out.status_basis, /1 of 5 hives have no readable name/);
    const calls = await argvLog(cwd);
    assert.ok(calls.length === 2 && calls.every((c) => c.includes("--offline")), JSON.stringify(calls));
    // all named, no missing page: complete
    await stubVol(cwd, bin, { help: { stdout: HELP, stderr: HELP_ERR }, hivelist: { stdout: HIVELIST(false) } });
    const ok = parse(await runTool(REG, cwd, { path: "inputs/mem.raw" }, env, bin));
    assert.equal(ok.status, "complete");
    assert.equal(ok.coverage.hives_read, 4);
    // the engine's log says pages were missing: partial, with the lines counted and quoted
    await stubVol(cwd, bin, { help: { stdout: HELP, stderr: HELP_ERR }, hivelist: { stdout: HIVELIST(false), stderr: "WARNING volatility3: Invalid address at 0xf8a0001\n" } });
    const miss = parse(await runTool(REG, cwd, { path: "inputs/mem.raw" }, env, bin));
    assert.equal(miss.status, "partial");
    assert.equal(miss.coverage.pages_missing_lines, 1);
  });
});

test("a plugin the installed vol does not list is a refusal, and a missing vol or an image no hive is found in says so", { timeout: 120 * SECOND }, async () => {
  await withCwd(async (cwd, bin) => {
    let env = await stubVol(cwd, bin, { help: { stdout: "Plugins:\n  {windows.info.Info}\n" } });
    let run = await runTool(REG, cwd, { path: "inputs/mem.raw" }, env, bin);
    let out = parse(run);
    assert.equal(out.status, "failed");
    assert.match(out.error, /does not list windows\.registry\.hivelist/);
    assert.equal(run.code, 1);
    env = await stubVol(cwd, bin, { help: { stdout: HELP }, hivelist: { stdout: "Offset\tFileFullPath\tFile output\n" } });
    out = parse(await runTool(REG, cwd, { path: "inputs/mem.raw" }, env, bin));
    assert.equal(out.status, "partial");
    assert.match(out.status_basis, /found no hive/);
    // no vol on PATH
    const empty = join(cwd, "empty");
    await mkdir(empty);
    run = await runTool(REG, cwd, { path: "inputs/mem.raw" }, { PATH: `${empty}:/usr/bin:/bin` });
    out = parse(run);
    assert.equal(out.status, "failed");
    assert.match(out.error, /no `vol` on PATH/);
  });
});

test("printkey: records carry offset, plugin and version; a credential-named key or value is withheld whole and written nowhere without write_values; a binary value is not printed; canaries are not printed", { timeout: 120 * SECOND }, async () => {
  await withCwd(async (cwd, bin) => {
    const r = rng(21);
    const token = SHAPES.ghp(r), aws = SHAPES.aws_key(r), jwt = SHAPES.jwt(r);
    const stdout = PK_HEAD +
      pkRow(SYSTEM, "Key", TCPIP, "Interfaces") +
      pkRow(SYSTEM, "REG_SZ", TCPIP, "Hostname", "WORKSTATION") +
      pkRow(SYSTEM, "REG_DWORD", TCPIP, "EnableICMPRedirect", "0x1") +
      pkRow(SYSTEM, "REG_BINARY", TCPIP, "DhcpIPAddress", "00 01 02 03") +
      pkRow(SYSTEM, "REG_SZ", TCPIP, "AdminPassword", "hunter2horse") +
      pkRow(SYSTEM, "REG_SZ", "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Control\\Lsa", "Authentication Packages", "msv1_0") +
      pkRow(SYSTEM, "REG_SZ", TCPIP, "Updater", token) +
      pkRow(SYSTEM, "REG_SZ", TCPIP, "Cloud", `key=${aws}`) +
      pkRow(SYSTEM, "Key", `${TCPIP}\\${jwt}`, "Child");
    const env = await stubVol(cwd, bin, { help: { stdout: HELP, stderr: HELP_ERR }, hivelist: { stdout: HIVELIST(false) }, printkey: { stdout } });
    const run = await runTool(REG, cwd, { path: "inputs/mem.raw", mode: "printkey", offset: hex(SYSTEM), key: "ControlSet001\\Services\\Tcpip", recurse: true, limit: 50 }, env, bin);
    const out = parse(run);
    assert.equal(out.status, "complete", out.status_basis);
    const rows: any[] = out.records.rows;
    assert.equal(rows.length, 9);
    assert.ok(rows.every((x) => x.hive_offset === hex(SYSTEM) && x.plugin === "windows.registry.printkey.PrintKey" && x.volatility === "2.28.2"));
    const by = (name: string) => rows.find((x) => x.name === name);
    assert.equal(by("Hostname").data, "WORKSTATION");
    assert.equal(by("EnableICMPRedirect").data, "0x1");
    assert.equal(by("DhcpIPAddress").data_state, "not_printed");
    assert.ok(!JSON.stringify(by("DhcpIPAddress")).includes("00 01 02 03"));
    assert.equal(by("AdminPassword").data_state, "withheld_credential");
    assert.match(by("AdminPassword").data, /^<withheld 12 characters/);
    assert.equal(by("Authentication Packages").data_state, "withheld_credential", "a value under a Lsa key is withheld");
    for (const secret of ["hunter2horse", "msv1_0", token, aws, jwt]) assert.ok(!run.stdout.includes(secret), `a printed slot holds a canary: ${secret.slice(0, 6)}`);
    assert.equal(out.secret_values.contains_secret_values, false);
    assert.equal(out.secret_values.values_withheld, 2);
    assert.match(out.secret_values.note, /not written anywhere/);
    // nothing was written anywhere but the tool-output of the call (no values file without write_values)
    for (const f of await files(cwd)) assert.ok(!/values\.jsonl|mem_registry\/?$/.test(f), f);
    const call = (await argvLog(cwd)).find((c) => c.some((x) => x.includes("printkey")))!;
    assert.ok(call.includes("--offline") && call.includes(`--offset=${hex(SYSTEM)}`) && call.includes("--key=ControlSet001\\Services\\Tcpip") && call.includes("--recurse"), JSON.stringify(call));
  });
});

test("SAM and SECURITY: refused outside a job, in a job that is not secret output, and by key path; nothing is read or written; with write_values in a secret job the values go to a 0600 file and never to the answer", { timeout: 120 * SECOND }, async () => {
  await withCwd(async (cwd, bin) => {
    const samRows = PK_HEAD + pkRow(SAM, "Key", "\\SAM\\Domains\\Account", "Users") + pkRow(SAM, "REG_BINARY", "\\SAM\\Domains\\Account\\Users\\000001F4", "V", "de ad be ef");
    const env = await stubVol(cwd, bin, { help: { stdout: HELP, stderr: HELP_ERR }, hivelist: { stdout: HIVELIST(false) }, printkey: { stdout: samRows } });
    const args = { path: "inputs/mem.raw", mode: "printkey", offset: hex(SAM) };
    // outside a job
    let run = await runTool(REG, cwd, args, env, bin);
    let out = parse(run);
    assert.equal(out.status, "failed");
    assert.equal(out.hive, "refused");
    assert.equal(out.written, false);
    assert.ok(!(await argvLog(cwd)).some((c) => c.some((x) => x.includes("printkey"))), "printkey was not run");
    // write_values outside a job, and in a job that is not secret output: refused before the image is looked at (no vol call at all)
    for (const e of [{}, { JOB_ID: "j", OUT: join(cwd, "o") }]) {
      const before = (await argvLog(cwd)).length;
      run = await runTool(REG, cwd, { ...args, write_values: true }, { ...env, ...e }, bin);
      out = parse(run);
      assert.equal(out.status, "failed");
      assert.equal(out.write_values, "refused");
      assert.equal((await argvLog(cwd)).length, before, "no vol call");
    }
    // a key under SAM in another hive is refused by its path, before the image is looked at
    run = await runTool(REG, cwd, { path: "inputs/mem.raw", mode: "printkey", offset: hex(SYSTEM), key: "SAM\\Domains" }, env, bin);
    assert.equal(parse(run).key, "refused");
    assert.deepEqual(await files(join(cwd, "work")), [], "nothing was written by any refusal");
    // the secret job: allowed, the values are in the file and not in the answer
    const { env: jobEnv, out: outDir } = await secretJob(cwd);
    run = await runTool(REG, cwd, { ...args, write_values: true }, { ...env, ...jobEnv }, bin);
    out = parse(run);
    assert.equal(out.status, "complete", out.status_basis);
    assert.equal(out.secret_values.contains_secret_values, true);
    assert.equal(out.secret_values.values_written, 1);
    assert.match(out.secret_values.values_file, /^store\/jobs\/job1\/out\/mem_registry\/mem_registry-[0-9a-f]{16}-values\.jsonl$/);
    assert.ok(!run.stdout.includes("de ad be ef"));
    const file = join(outDir, "mem_registry", out.secret_values.values_file.split("/").pop());
    assert.equal((await stat(file)).mode & 0o777, 0o600);
    assert.equal((await stat(join(outDir, "mem_registry"))).mode & 0o777, 0o700);
    assert.equal(JSON.parse((await readFile(file, "utf8")).trim()).data, "de ad be ef");
    // a second run in the same job: the same call is named the same file, a different one takes the next free name; the first is not replaced
    const first = await readFile(file, "utf8");
    await stubVol(cwd, bin, { help: { stdout: HELP, stderr: HELP_ERR }, hivelist: { stdout: HIVELIST(false) }, printkey: { stdout: PK_HEAD + pkRow(SAM, "REG_BINARY", "\\SAM\\Domains\\Account\\Users\\000001F4", "V", "00 00") } });
    const again = parse(await runTool(REG, cwd, { ...args, write_values: true }, { ...env, ...jobEnv }, bin));
    assert.match(again.secret_values.values_file, /-values-2\.jsonl$/);
    assert.equal(await readFile(file, "utf8"), first);
    assert.deepEqual((await readdir(join(outDir, "mem_registry"))).filter((n) => n.startsWith(".")), [], "no hidden temporary file is left");
  });
});

test("printkey: a hive that is not in the list, a missing offset, and a printkey that fails or prints no header are failures; a missing page is partial; a key with no record is partial", { timeout: 120 * SECOND }, async () => {
  await withCwd(async (cwd, bin) => {
    let env = await stubVol(cwd, bin, { help: { stdout: HELP }, hivelist: { stdout: HIVELIST(false) }, printkey: { stdout: PK_HEAD + pkRow(SYSTEM, "REG_SZ", TCPIP, "Hostname", "W"), stderr: "WARNING: PagedInvalidAddressException at 0x1000\n" } });
    let out = parse(await runTool(REG, cwd, { path: "inputs/mem.raw", mode: "printkey", offset: "0x1234" }, env, bin));
    assert.equal(out.status, "failed");
    assert.match(out.error, /not the offset of a hive/);
    out = parse(await runTool(REG, cwd, { path: "inputs/mem.raw", mode: "printkey" }, env, bin));
    assert.match(out.error, /printkey needs offset/);
    out = parse(await runTool(REG, cwd, { path: "inputs/mem.raw", mode: "printkey", offset: SYSTEM }, env, bin));
    assert.equal(out.status, "partial", "an integer offset is accepted, and a log line that says a page was missing makes the answer partial");
    assert.equal(out.coverage.pages_missing_lines, 1);
    env = await stubVol(cwd, bin, { help: { stdout: HELP }, hivelist: { stdout: HIVELIST(false) }, printkey: { code: 1, stderr: "Unsatisfied requirement\n" } });
    const run = await runTool(REG, cwd, { path: "inputs/mem.raw", mode: "printkey", offset: hex(SYSTEM) }, env, bin);
    assert.equal(parse(run).status, "failed");
    assert.equal(run.code, 1);
    env = await stubVol(cwd, bin, { help: { stdout: HELP }, hivelist: { stdout: HIVELIST(false) }, printkey: { stdout: "no table here\n" } });
    assert.match(parse(await runTool(REG, cwd, { path: "inputs/mem.raw", mode: "printkey", offset: hex(SYSTEM) }, env, bin)).error, /no header line/);
    env = await stubVol(cwd, bin, { help: { stdout: HELP }, hivelist: { stdout: HIVELIST(false) }, printkey: { stdout: PK_HEAD } });
    out = parse(await runTool(REG, cwd, { path: "inputs/mem.raw", mode: "printkey", offset: hex(SYSTEM), key: "Absent" }, env, bin));
    assert.equal(out.status, "partial");
    assert.match(out.status_basis, /printed no record/);
  });
});

test("max_records ends the read and the program, the answer is partial and says where; the whole is on disk", { timeout: 120 * SECOND }, async () => {
  await withCwd(async (cwd, bin) => {
    const pid = join(cwd, "pk.pid");
    const env = await stubVol(cwd, bin, { help: { stdout: HELP }, hivelist: { stdout: HIVELIST(false) }, printkey: { stdout: PK_HEAD, rows: 3000, sleep: 120, pid } });
    const out = parse(await runTool(REG, cwd, { path: "inputs/mem.raw", mode: "printkey", offset: hex(SYSTEM), max_records: 700, limit: 10 }, env, bin));
    assert.equal(out.status, "partial");
    assert.match(out.status_basis, /ended at max_records \(700\)/);
    assert.equal(out.records.matched, 700);
    assert.equal(out.records.returned, 10);
    assert.equal(out.records.truncated, true);
    const kept = (await readFile(join(cwd, out.records.all_results), "utf8")).trim().split("\n");
    assert.equal(kept.length, 700);
    const stub = await pidOf(pid);
    assert.ok(stub && !alive(stub), "the program was ended when the read was");
  });
});

test("a hang is ended at the clock (hivelist: a failure; printkey: the records read so far are kept, partial); SIGTERM, also at a program that ignores it, gives one document and names the file that was being written", { timeout: 180 * SECOND }, async () => {
  await withCwd(async (cwd, bin) => {
    const pid = join(cwd, "hang.pid");
    let env = await stubVol(cwd, bin, { help: { stdout: HELP }, hivelist: { sleep: 120, pid } });
    let run = await runTool(REG, cwd, { path: "inputs/mem.raw", max_seconds: 30 }, env, bin);
    let out = parse(run);
    assert.equal(out.status, "failed");
    assert.match(out.error, /hives could not be listed/);
    assert.ok(run.ms < 60 * SECOND, `${run.ms} ms`);
    let stub = await pidOf(pid);
    assert.ok(stub && !alive(stub));
    env = await stubVol(cwd, bin, { help: { stdout: HELP }, hivelist: { stdout: HIVELIST(false) }, printkey: { stdout: PK_HEAD, rows: 5, sleep: 120, pid } });
    run = await runTool(REG, cwd, { path: "inputs/mem.raw", mode: "printkey", offset: hex(SYSTEM), max_seconds: 45 }, env, bin);
    out = parse(run);
    assert.equal(out.status, "partial");
    assert.equal(out.records.matched, 5, "what was read before the time ran out is kept");
    assert.match(out.status_basis, /not finished in the time/);
    stub = await pidOf(pid);
    assert.ok(stub && !alive(stub));
    for (const ignore of [false, true]) {
      const p2 = join(cwd, `sig-${ignore}.pid`);
      const { env: jobEnv, out: outDir } = await secretJob(cwd, 5 + Number(ignore));
      env = await stubVol(cwd, bin, { help: { stdout: HELP }, hivelist: { stdout: HIVELIST(false) }, printkey: { stdout: PK_HEAD, rows: 400, sleep: 120, pid: p2, ignore_term: ignore } });
      const r2 = await runTool(REG, cwd, { path: "inputs/mem.raw", mode: "printkey", offset: hex(SYSTEM), limit: 5 }, { ...env, ...jobEnv }, bin, "SIGTERM", 0, async () => (await pidOf(p2)) !== null && (await readdir(join(outDir, "tool-output")).catch(() => [])).length > 0);
      assert.equal(r2.code, 143, r2.stderr);
      const o2 = parse(r2);
      assert.equal(o2.status, "failed");
      assert.equal(o2.interrupted, true);
      assert.equal(r2.stdout.trim().split("\n}\n").length, 1, "one document");
      assert.ok(o2.kept_results && o2.kept_results.some((n: string) => n.endsWith(".partial")), JSON.stringify(o2.kept_results));
      const left = await files(outDir);
      assert.ok(left.every((f) => !/\/\.[^/]*$/.test(f)), `no hidden temporary file: ${left.join(", ")}`);
      const stub2 = await pidOf(p2);
      assert.ok(stub2 && !alive(stub2), `the stand-in is gone (ignore_term ${ignore})`);
    }
  });
});

test("hostile parameters give a JSON refusal, never a Traceback", { timeout: 120 * SECOND }, async () => {
  await withCwd(async (cwd, bin) => {
    const env = await stubVol(cwd, bin, { help: { stdout: HELP } });
    assert.equal(spawnSync("mkfifo", [join(cwd, "inputs", "pipe.raw")]).status, 0);
    const base = { path: "inputs/mem.raw" };
    const bad: unknown[] = [
      {}, { path: "" }, { path: "inputs/mem.raw\u0000" }, { path: "inputs/\udc80" }, { path: "inputs/pipe.raw" }, { path: "inputs" }, { path: "inputs/absent.raw" },
      { ...base, mode: "everything" }, { ...base, mode: "printkey" }, { ...base, mode: "printkey", offset: "0xzz" }, { ...base, mode: "printkey", offset: -1 },
      { ...base, mode: "printkey", offset: 10 ** 30 }, { ...base, mode: "printkey", offset: true }, { ...base, mode: "printkey", offset: "0x1", key: 5 },
      { ...base, mode: "printkey", offset: "0x1", key: "a\u0000b" }, { ...base, offset: "0x1" }, { ...base, recurse: true }, { ...base, recurse: "yes" },
      { ...base, write_values: "yes" }, { ...base, max_seconds: 1e999 }, { ...base, max_seconds: 10 ** 30 }, { ...base, max_seconds: true },
      { ...base, limit: 0 }, { ...base, limit: 10 ** 30 }, { ...base, max_records: 0 }, { ...base, max_records: 10 ** 30 }, { ...base, surprise: 1 },
      { ...base, symbols_dir: "inputs/mem.raw" }, { ...base, symbols_dir: 3 },
    ];
    for (const args of bad) {
      const t0 = Date.now();
      const run = await runTool(REG, cwd, args, env, bin);
      const out = parse(run);
      assert.equal(out.status, "failed", JSON.stringify(args).slice(0, 90));
      assert.ok(out.error && out.status_basis);
      assert.equal(run.code, 1);
      assert.ok(Date.now() - t0 < 10 * SECOND);
    }
    for (const raw of [Buffer.from("{"), Buffer.from("[".repeat(200000)), Buffer.from("{\"a\":".repeat(100000)), Buffer.from("[1]"), Buffer.from([0x7b, 0x22, 0xff, 0x22, 0x3a, 0x31, 0x7d])]) {
      const child = spawn("python3", [REG], { cwd, env: { ...process.env, ...env, PATH: `${bin}:${process.env.PATH}` } });
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
    // a key or path that starts with "-" reaches vol in a form an option cannot be mistaken for
    await writeFile(join(cwd, "-image.raw"), Buffer.alloc(4096));
    const env2 = await stubVol(cwd, bin, { help: { stdout: HELP }, hivelist: { stdout: HIVELIST(false) }, printkey: { stdout: PK_HEAD } });
    await writeFile(join(cwd, "-image.raw"), Buffer.alloc(4096));
    parse(await runTool(REG, cwd, { path: "-image.raw", mode: "printkey", offset: hex(SYSTEM), key: "--recurse" }, env2, bin));
    const call = (await argvLog(cwd)).find((c) => c.some((x) => x.includes("printkey")))!;
    assert.equal(call[call.indexOf("-f") + 1], "./-image.raw");
    assert.ok(call.includes("--key=--recurse") && call.filter((x) => x === "--recurse").length === 0, JSON.stringify(call));
  });
});

test("the manifest declares secret_output for write_values and says what the code does; every vol call carries --offline", async () => {
  const man = JSON.parse(await readFile(join(ROOT, "packs", "memory-forensics", "tools", "mem_registry", "manifest.json"), "utf8")) as Record<string, any>;
  assert.deepEqual(man.secret_output, { when_args: ["write_values"] });
  assert.equal(man.params.write_values.type, "boolean");
  assert.equal(man.params.write_values.default, undefined);
  assert.equal(man.timeout_seconds, 600);
  assert.equal(man.needs, undefined);
  assert.deepEqual(Object.keys(man.params).sort(), ["key", "limit", "max_records", "max_seconds", "mode", "offset", "path", "recurse", "symbols_dir", "write_values"]);
  const script = await readFile(REG, "utf8");
  const constant = (name: string): number => Number(new RegExp(`^${name} = ([0-9.]+)`, "m").exec(script)![1].split(".")[0]);
  assert.match(man.description, /default 420, at most 540/);
  assert.match(script, /DEFAULT_SECONDS, MAX_SECONDS, MIN_SECONDS = 420\.0, 540\.0, 10\.0/);
  assert.equal(constant("RESERVE"), 8);
  assert.ok(man.description.includes("help 90 s, hivelist 150 s") && constant("HELP_SECONDS") === 90 && constant("HIVELIST_SECONDS") === 150);
  assert.ok(man.description.includes("1 GiB of printkey") && /^ROWS_CAP = 1 << 30/m.test(script));
  assert.ok(man.description.includes("default 100000, at most 2000000") && /DEFAULT_RECORDS, MAX_RECORDS = 100000, 2000000/.test(script));
  const vectors = script.split("\n").filter((l) => /argv = \[vol|run_engine\(\[vol/.test(l));
  assert.ok(vectors.length >= 3);
  for (const l of vectors) assert.match(l, /"--offline"/, l);
  assert.ok(!/start_new_session|setsid/.test(script.replace(/^# BEGIN SHARED PROCESS[\s\S]*?^# END SHARED PROCESS/m, "")));
  // the credential words the manifest lists are the ones the code tests
  for (const w of ["password", "secret", "token", "verifier", "hash", "ntlm", "lsa", "dpapi", "masterkey", "bootkey", "vault"]) {
    assert.ok(script.includes(w) && man.description.includes(w), w);
  }
});

test("one real run, when a Volatility is on PATH (otherwise skipped, and said so)", { timeout: 300 * SECOND }, async (t) => {
  const has = spawnSync("sh", ["-c", "command -v vol"], { encoding: "utf8" });
  if (has.status !== 0) { t.skip("no `vol` on PATH: the readings of the real hivelist and printkey output were not exercised"); return; }
  t.skip("a real run needs a small Windows image and its symbol table, which this repository does not carry (ask the owner for a public sample)");
});
