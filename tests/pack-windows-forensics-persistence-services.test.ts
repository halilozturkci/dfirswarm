/**
 * persistence_normalise, part 2: service keys and autorun keys, read from the SYSTEM, SOFTWARE and NTUSER.DAT hives.
 *
 * Where each layout comes from (the documented registry locations; no byte of a real hive is in this repository):
 *   services    SYSTEM\ControlSet00n\Services\<name>: ImagePath, Start (0 boot, 1 system, 2 automatic, 3 manual, 4 disabled), Type (1 kernel driver, 2 file
 *               system driver, 16 own process, 32 share process, 256 the interactive flag), DisplayName, ObjectName, FailureActions (bytes) and, under
 *               Parameters, ServiceDll.
 *   autoruns    SOFTWARE and NTUSER.DAT ...\Windows\CurrentVersion\Run and RunOnce (every value is one entry); SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
 *               (Shell, Userinit) and ...\Windows (AppInit_DLLs, LoadAppInit_DLLs); ...\Image File Execution Options\<image>\Debugger;
 *               SOFTWARE\Microsoft\Active Setup\Installed Components\<GUID>\StubPath.
 */
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { runPy, withCwd } from "./tool-library-harness.ts";
import { WIN, body, failed, tool } from "./windows-pack-harness.ts";
import { SHAPES, fragmentLeaked, leaked, plant } from "./windows-canary.ts";
import { jobEnv } from "./windows-tool-contract.ts";
import { VARIANTS, type Node, type Val, type Variant } from "./windows-stub-regipy.ts";

function dual(name: string, fn: (v: Variant) => Promise<void>): void {
  for (const v of VARIANTS) test(`${name} [${v.label}]`, { skip: v.skip }, () => fn(v));
}

type Row = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any
type Answer = {
  status: string;
  status_basis: string;
  items: Row[];
  item_count: number;
  items_by_mechanism: Record<string, number>;
  observation_counts: Record<string, number>;
  hives: Record<string, { hive_dirty: boolean; transaction_logs_beside_hive: string[]; transaction_logs_replayed: boolean }>;
  sources: Record<string, { present: boolean }>;
  cross_check: { result: string };
  interpretation_limits: string[];
  problems: string[];
  contains_blind_records: number | null;
  walk_stopped_by_time_limit: boolean;
  all_results?: string;
  [key: string]: unknown;
};

const TOOL = "persistence_normalise";
const sz = (name: string, value: string): Val => ({ name, type: "sz", value });
const esz = (name: string, value: string): Val => ({ name, type: "expand_sz", value });
const dw = (name: string, value: number): Val => ({ name, type: "dword", value });

type Svc = { name: string; values?: Val[]; dll?: string };
function system(services: Svc[], opts: { current?: number; sets?: string[] } = {}): Node {
  const sets = (opts.sets ?? ["ControlSet001"]).map((cs): Node => ({
    name: cs,
    children: [{ name: "Services", children: services.map((s): Node => ({ name: s.name, values: s.values ?? [], children: s.dll ? [{ name: "Parameters", values: [esz("ServiceDll", s.dll)] }] : undefined })) }],
  }));
  return { name: "ROOT", children: [{ name: "Select", values: [dw("Current", opts.current ?? 1)] }, ...sets] };
}

function chain(parts: string[], leaf: Node): Node {
  let node = leaf;
  for (const part of [...parts].reverse()) node = { name: part, children: [node] };
  return node;
}
type SoftwareOpts = { run?: Val[]; runOnce?: Val[]; winlogon?: Val[]; windows?: Val[]; ifeo?: Array<{ name: string; values: Val[] }>; activeSetup?: Array<{ name: string; values: Val[] }>; wow?: Val[] };
function software(o: SoftwareOpts): Node {
  const cv = (extra: Node[]): Node => ({ name: "CurrentVersion", children: extra });
  const win: Node[] = [];
  if (o.run || o.runOnce) win.push({ name: "Windows", children: [cv([...(o.run ? [{ name: "Run", values: o.run }] : []), ...(o.runOnce ? [{ name: "RunOnce", values: o.runOnce }] : [])])] });
  const nt: Node[] = [];
  if (o.winlogon) nt.push({ name: "Winlogon", values: o.winlogon });
  if (o.windows) nt.push({ name: "Windows", values: o.windows });
  if (o.ifeo) nt.push({ name: "Image File Execution Options", children: o.ifeo.map((e) => ({ name: e.name, values: e.values })) });
  const ms: Node[] = [...win];
  if (nt.length) ms.push({ name: "Windows NT", children: [{ name: "CurrentVersion", children: nt }] });
  if (o.activeSetup) ms.push({ name: "Active Setup", children: [{ name: "Installed Components", children: o.activeSetup.map((e) => ({ name: e.name, values: e.values })) }] });
  const children: Node[] = [{ name: "Microsoft", children: ms }];
  if (o.wow) children.push({ name: "Wow6432Node", children: [{ name: "Microsoft", children: [{ name: "Windows", children: [{ name: "CurrentVersion", children: [{ name: "Run", values: o.wow }] }] }] }] });
  return { name: "ROOT", children };
}
function ntuser(run: Val[], runOnce?: Val[]): Node {
  return { name: "ROOT", children: [chain(["Software", "Microsoft", "Windows"], { name: "CurrentVersion", children: [{ name: "Run", values: run }, ...(runOnce ? [{ name: "RunOnce", values: runOnce }] : [])] })] };
}

async function run(v: Variant, hives: Record<string, Node>, args: Record<string, unknown> = {}, env0: Record<string, string> = {}): Promise<{ out: Answer; cwd: string; raw: string; env: Record<string, string> }> {
  let result: { out: Answer; cwd: string; raw: string; env: Record<string, string> } | undefined;
  await withCwd(async (cwd) => {
    let env: Record<string, string> = {};
    const a: Record<string, unknown> = { ...args };
    for (const [role, root] of Object.entries(hives)) {
      env = await v.write(cwd, `work/${role.toUpperCase()}`, root);
      a[role] = `work/${role.toUpperCase()}`;
    }
    const r = await tool(TOOL, cwd, a, { ...env, ...env0 });
    result = { out: body<Answer>(r), cwd, raw: r.stdout, env };
  });
  return result as { out: Answer; cwd: string; raw: string; env: Record<string, string> };
}
const byPath = (out: Answer, p: string): Row => out.items.find((i) => i.path === p) as Row;

// --- services ------------------------------------------------------------------------------

dual("service keys: ImagePath, Start and Type with their labels, ServiceDll, FailureActions as bytes, the control set and which one is current", async (v) => {
  const fa = Buffer.from([1, 2, 3, 4, 5]);
  const { out } = await run(v, {
    system: system([
      { name: "Vendor Svc", values: [esz("ImagePath", "%SystemRoot%\\System32\\svchost.exe -k netsvcs"), dw("Start", 2), dw("Type", 32), sz("DisplayName", "Vendor Service"), sz("ObjectName", "LocalSystem"), { name: "FailureActions", type: "binary", value: fa }], dll: "C:\\Windows\\System32\\vendor.dll" },
      { name: "Drv", values: [esz("ImagePath", "\\SystemRoot\\drivers\\drv.sys"), dw("Start", 0), dw("Type", 1)] },
      { name: "Odd", values: [dw("Start", 9), dw("Type", 4096)] },
    ], { sets: ["ControlSet001", "ControlSet002"], current: 2 }),
  });
  const svc = out.items.filter((i) => i.mechanism === "service");
  assert.equal(svc.length, 6, "three services in two control sets");
  const a = svc.find((i) => i.path === "ControlSet002\\Vendor Svc") as Row;
  assert.equal(a.control_set, "ControlSet002");
  assert.equal(a.current_control_set, true);
  assert.equal((svc.find((i) => i.path === "ControlSet001\\Vendor Svc") as Row).current_control_set, false);
  assert.equal(a.image_path, "%SystemRoot%\\System32\\svchost.exe -k netsvcs");
  assert.deepEqual([a.start, a.start_label, a.type, a.type_label], ["2", "automatic", "32", "share process"]);
  assert.equal(a.service_dll, "C:\\Windows\\System32\\vendor.dll");
  assert.equal(a.display_name, "Vendor Service");
  assert.equal(a.object_name, "LocalSystem");
  assert.equal(a.failure_actions_length, "5");
  assert.equal(a.failure_actions_hex, fa.toString("hex"));
  assert.equal(a.key, "ControlSet002\\Services\\Vendor Svc");
  assert.equal(a.hive, "system");
  const odd = svc.find((i) => i.path === "ControlSet001\\Odd") as Row;
  assert.deepEqual([odd.start_label, odd.type_label], ["unknown", "unknown"]);
  assert.deepEqual(odd.observations, ["no_imagepath_and_no_servicedll_value"]);
  assert.deepEqual(a.observations, []);
  assert.equal(out.sources.services.present, true);
  assert.equal(out.cross_check.result, "not_run");
  assert.ok(out.interpretation_limits.some((l) => /service or an autorun entry is read as the registry holds it/.test(l)));
  assert.equal(out.status, "complete", out.status_basis);
});

dual("a Start value that is not a number is labelled so and makes the answer partial", async (v) => {
  const { out } = await run(v, { system: system([{ name: "Bad", values: [{ name: "Start", type: "binary", value: Buffer.from([2, 0]) }, esz("ImagePath", "x.exe")] }]) });
  assert.equal(out.status, "partial");
  assert.match(out.status_basis, /1 service Start or Type value\(s\) are not numbers/);
  assert.equal(byPath(out, "ControlSet001\\Bad").start_label, "not a number");
});

dual("a dirty SYSTEM hive is said to be, per hive, with its logs named and not replayed", async (v) => {
  await withCwd(async (cwd) => {
    const env = await v.write(cwd, "work/SYSTEM", system([{ name: "A", values: [esz("ImagePath", "a.exe")] }]), { primarySeq: 9, secondarySeq: 8 });
    await writeFile(join(cwd, "work", "SYSTEM.LOG1"), Buffer.alloc(512));
    const out = body<Answer>(await tool(TOOL, cwd, { system: "work/SYSTEM" }, env));
    assert.equal(out.hives.system.hive_dirty, true);
    assert.deepEqual(out.hives.system.transaction_logs_beside_hive, ["work/SYSTEM.LOG1"]);
    assert.equal(out.hives.system.transaction_logs_replayed, false);
    // A dirty hive whose logs were not replayed is never plainly complete, and the basis says which hive.
    assert.equal(out.status, "partial");
    assert.match(out.status_basis, /the system hive: the hive is dirty \(its sequence numbers 9 and 8 differ\) and no transaction log was replayed/);
    assert.match(out.status_basis, /found 1 \(transaction_logs_beside_hive\), and it replays none/);
    assert.deepEqual((out.hives.system as unknown as { transaction_logs_looked_for: string[] }).transaction_logs_looked_for, ["work/SYSTEM.LOG1", "work/SYSTEM.LOG2", "work/SYSTEM.LOG"]);
  });
});

// --- autorun keys -------------------------------------------------------------------------------

dual("autorun keys: Run and RunOnce (SOFTWARE, Wow6432Node and NTUSER.DAT), Winlogon, AppInit_DLLs, IFEO Debugger and Active Setup, each with its kind and place", async (v) => {
  const { out } = await run(v, {
    software: software({
      run: [sz("Updater", "C:\\Program Files\\Vendor\\upd.exe /silent")], runOnce: [sz("Once", "C:\\once.exe")], wow: [sz("Wow", "C:\\wow.exe")],
      winlogon: [sz("Shell", "explorer.exe"), sz("Userinit", "C:\\Windows\\system32\\userinit.exe,"), sz("Other", "ignored.exe")],
      windows: [sz("AppInit_DLLs", "C:\\hook.dll"), dw("LoadAppInit_DLLs", 1), sz("Unrelated", "ignored")],
      ifeo: [{ name: "notepad.exe", values: [sz("Debugger", "C:\\dbg.exe"), dw("GlobalFlag", 512)] }, { name: "calc.exe", values: [dw("GlobalFlag", 2)] }],
      activeSetup: [{ name: "{12345678-1234-1234-1234-123456789ABC}", values: [sz("StubPath", "C:\\stub.exe /install"), sz("Version", "1,0")] }],
    }),
    ntuser: ntuser([sz("UserApp", "C:\\Users\\a\\app.exe")], [sz("UserOnce", "C:\\Users\\a\\once.exe")]),
  });
  const auto = out.items.filter((i) => i.mechanism === "autorun");
  const kinds = (k: string): Row[] => auto.filter((i) => i.autorun_kind === k);
  assert.deepEqual(kinds("run").map((i) => [i.hive, i.value_name, i.command]).sort(), [["ntuser", "UserApp", "C:\\Users\\a\\app.exe"], ["software", "Updater", "C:\\Program Files\\Vendor\\upd.exe /silent"], ["software", "Wow", "C:\\wow.exe"]]);
  assert.deepEqual(kinds("runonce").map((i) => i.value_name).sort(), ["Once", "UserOnce"]);
  assert.deepEqual(kinds("winlogon").map((i) => i.value_name).sort(), ["Shell", "Userinit"], "only the two values the sweep is about");
  assert.deepEqual(kinds("appinit").map((i) => i.value_name).sort(), ["AppInit_DLLs", "LoadAppInit_DLLs"]);
  assert.deepEqual(kinds("ifeo").map((i) => [i.value_name, i.command]), [["Debugger", "C:\\dbg.exe"]], "an image with no Debugger value gives no entry");
  assert.equal((kinds("ifeo")[0] as Row).path, "Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\notepad.exe\\Debugger");
  assert.deepEqual(kinds("active_setup").map((i) => [i.value_name, i.command]), [["StubPath", "C:\\stub.exe /install"]]);
  assert.equal((kinds("run")[0] as Row).key.length > 0, true);
  assert.equal(out.sources.autoruns.present, true);
  assert.equal(out.status, "complete", out.status_basis);
  assert.equal(out.items_by_mechanism["autorun:ifeo"], 1);
});

dual("a SOFTWARE hive with autorun keys and no TaskCache is read; a hive with neither fails with JSON", async (v) => {
  const { out } = await run(v, { software: software({ run: [sz("A", "a.exe")] }) });
  assert.equal(out.item_count, 1);
  assert.equal(out.sources.tasks.present, false);
  assert.equal(out.status, "complete", out.status_basis);
  await withCwd(async (cwd) => {
    const env = await v.write(cwd, "work/EMPTY", { name: "ROOT", children: [{ name: "Other" }] });
    assert.match(failed(await tool(TOOL, cwd, { software: "work/EMPTY" }, env)).error, /no source key was found/);
  });
});

dual("a binary value under a Run key is kept as bytes and unsupported, not guessed", async (v) => {
  const { out } = await run(v, { software: software({ run: [{ name: "Blob", type: "binary", value: Buffer.from([1, 2, 3]) }] }) });
  assert.equal(out.status, "partial");
  assert.match(out.items[0].unsupported, /3 bytes, not text/);
  assert.equal(out.items[0].value_bytes_hex, "010203");
});

// --- withholding ---------------------------------------------------------------------------------

const FILE_SHAPES = SHAPES.filter((s) => s.fileOk && !s.residual && ["ghp", "glpat", "akia", "npm", "sk_live", "sendgrid"].includes(s.name));

async function filesUnder(dir: string): Promise<string[]> {
  const out: string[] = [];
  for (const e of await readdir(dir, { withFileTypes: true }).catch(() => [])) {
    const full = join(dir, e.name);
    if (e.isDirectory()) out.push(...(await filesUnder(full)));
    else out.push(await readFile(full, "utf8"));
  }
  return out;
}

dual("a token in ImagePath, ServiceDll, a Run value (name and data) and a Debugger is never printed whole, nor in a result file; contains cannot find it (oracle twin)", async (v) => {
  for (const shape of FILE_SHAPES) {
    const [canary] = plant(shape, 1, 21);
    const needle = canary.cores[0].slice(0, 12);
    await withCwd(async (cwd) => {
      const e1 = await v.write(cwd, "work/SYSTEM", system([{ name: "Svc", values: [esz("ImagePath", `C:\\svc\\run.exe --token ${canary.text}`)], dll: `C:\\dll\\${canary.text}.dll` }]));
      const e2 = await v.write(cwd, "work/SOFTWARE", software({ run: [sz(`Run ${canary.text}`, `C:\\x.exe --password ${canary.text}`)], ifeo: [{ name: "app.exe", values: [sz("Debugger", `C:\\d.exe ${canary.text}`)] }] }));
      const base = { system: "work/SYSTEM", software: "work/SOFTWARE", limit: 1 };
      const r = await tool(TOOL, cwd, base, { ...e1, ...e2 });
      const out = body<Answer>(r);
      const all = [r.stdout, ...(await filesUnder(join(cwd, "work", "s1")))];
      assert.equal(leaked([canary], all), 0, `${shape.name}: printed whole`);
      assert.equal(fragmentLeaked([canary], all), 0, `${shape.name}: a piece of it printed`);
      assert.ok(["partial", "complete"].includes(out.status));
      const probe = body<Answer>(await tool(TOOL, cwd, { system: "work/SYSTEM", software: "work/SOFTWARE", contains: needle }, { ...e1, ...e2 }));
      assert.equal(probe.item_count, 0, `${shape.name}: a needle inside withheld text must not match`);
      assert.ok((probe.contains_blind_records ?? 0) >= 1, `${shape.name}: blind`);
      assert.equal(probe.status, "partial");
      assert.ok(!JSON.stringify(probe).includes(needle));
    });
  }
  const { out } = await run(v, { system: system([{ name: "Harbor", values: [esz("ImagePath", "C:\\harbor\\svc.exe")] }, { name: "Other", values: [esz("ImagePath", "C:\\o.exe")] }]) }, { contains: "HARBOR" });
  assert.equal(out.item_count, 1);
  assert.equal(out.contains_blind_records, 0);
});

dual("write_values writes the originals of a service, a Run and a Debugger command to a 0600 file in a secret job and never to the answer", async (v) => {
  const [canary] = plant(FILE_SHAPES[0], 1, 9);
  await withCwd(async (cwd) => {
    const e1 = await v.write(cwd, "work/SYSTEM", system([{ name: "Svc", values: [esz("ImagePath", `C:\\svc.exe --password ${canary.text}`)] }]));
    const refused = failed(await tool(TOOL, cwd, { system: "work/SYSTEM", write_values: true }, e1));
    assert.match(refused.error, /secret_output|SECRET_OUTPUT|secret output/);
    const r = await tool(TOOL, cwd, { system: "work/SYSTEM", write_values: true }, { ...e1, ...jobEnv(cwd), SECRET_OUTPUT: "1" });
    body<Answer>(r);
    assert.equal(leaked([canary], [r.stdout]), 0);
    const file = join(cwd, "out", "persistence_normalise-values.jsonl");
    assert.equal(statSync(file).mode & 0o777, 0o600);
    assert.equal(leaked([canary], [readFileSync(file, "utf8")]), 1);
  });
});

// --- size, the clock, the signals ---------------------------------------------------------------------

dual("20,000 services in two control sets are read without a quadratic phase, and the counts are the file's", async (v) => {
  const services: Svc[] = Array.from({ length: 10_000 }, (_, i) => ({ name: `Svc${i}`, values: [esz("ImagePath", `C:\\svc\\s${i}.exe`), dw("Start", i % 5), dw("Type", 16)] }));
  await withCwd(async (cwd) => {
    const env = await v.write(cwd, "work/SYSTEM", system(services, { sets: ["ControlSet001", "ControlSet002"] }));
    const started = Date.now();
    const out = body<Answer>(await tool(TOOL, cwd, { system: "work/SYSTEM", limit: 10 }, env));
    assert.equal(out.item_count, 20_000);
    assert.equal(out.status, out.walk_stopped_by_time_limit ? "partial" : "complete", out.status_basis);
    assert.ok((Date.now() - started) / 1000 < 280);
    const lines = readFileSync(join(cwd, out.all_results as string), "utf8").trim().split("\n");
    assert.equal(lines.length, out.item_count);
  });
});

dual("a hive path that is a named pipe is refused at once for every hive role", async (v) => {
  await withCwd(async (cwd) => {
    const env = await v.write(cwd, "work/OK", system([]));
    assert.equal(spawnSync("mkfifo", [join(cwd, "work", "pipe")]).status, 0);
    const started = Date.now();
    for (const role of ["system", "ntuser", "software"]) assert.match(failed(await tool(TOOL, cwd, { [role]: "work/pipe" }, env)).error, /not a regular file/);
    assert.ok(Date.now() - started < 15_000);
  });
});

for (const variant of VARIANTS) {
  test(`stopped by SIGTERM while it writes service items the tool answers JSON, exits 143 and leaves no temporary file [${variant.label}]`, { skip: variant.skip }, async () => {
    await withCwd(async (cwd) => {
      const env = await variant.write(cwd, "work/SYSTEM", system(Array.from({ length: 8000 }, (_, i) => ({ name: `S${i}`, values: [esz("ImagePath", `C:\\s${i}.exe`)] }))));
      const child = spawn("python3", [join(WIN, TOOL, "run.py")], { cwd, env: { ...process.env, AGENT_ID: "s1", ...env } });
      let stdout = "";
      child.stdout.on("data", (c: Buffer) => (stdout += c.toString()));
      const closed = new Promise<number | null>((resolve) => child.on("close", (c) => resolve(c)));
      child.stdin.end(JSON.stringify({ system: "work/SYSTEM", limit: 1 }));
      const dir = join(cwd, "work", "s1", "tool-output");
      let seen = false;
      for (let waited = 0; waited < 60_000 && !seen; waited += 25) {
        seen = (await readdir(dir).catch(() => [] as string[])).some((n) => n.startsWith(".persistence_normalise"));
        if (!seen) await new Promise((r) => setTimeout(r, 25));
      }
      assert.ok(seen, "the tool never opened a temporary file");
      child.kill("SIGSTOP");
      child.kill("SIGTERM");
      child.kill("SIGCONT");
      assert.equal(await closed, 143);
      const out = JSON.parse(stdout) as Answer;
      assert.deepEqual([out.status, out.interrupted], ["failed", true]);
      assert.deepEqual((await readdir(dir)).filter((n) => n.startsWith(".")), []);
    });
  });
}

test("the manifest says what the tool reads, that no second reader is started, and is version 8", async () => {
  const manifest = JSON.parse(await readFile(join(WIN, TOOL, "manifest.json"), "utf8"));
  assert.equal(manifest.version, 8);
  assert.deepEqual(manifest.requires, [], "no second reader is started, so nothing is required");
  assert.match(manifest.description, /every ControlSetNNN Services key/);
  assert.match(manifest.description, /Second reader: NOT DONE/);
  assert.deepEqual(manifest.secret_output, { when_args: ["write_values"] });
  assert.ok(manifest.params.system && manifest.params.ntuser);
});

dual("a task file and a service of the same name stay two items of two mechanisms", async (v) => {
  await withCwd(async (cwd) => {
    const env = await v.write(cwd, "work/SYSTEM", system([{ name: "Same", values: [esz("ImagePath", "s.exe")] }]));
    await mkdir(join(cwd, "work", "Tasks"), { recursive: true });
    await writeFile(join(cwd, "work", "Tasks", "Same"), Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from('<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><Actions><Exec><Command>t.exe</Command></Exec></Actions></Task>', "utf16le")]));
    const out = body<Answer>(await tool(TOOL, cwd, { system: "work/SYSTEM", tasks_dir: "work/Tasks" }, env));
    assert.deepEqual(Object.keys(out.items_by_mechanism).sort(), ["scheduled_task", "service"]);
  });
});

dual("a time limit that falls inside the services stops the walk and counts what was not read", async (v) => {
  await withCwd(async (cwd) => {
    const env = await v.write(cwd, "work/SYSTEM", system(Array.from({ length: 4000 }, (_, i) => ({ name: `S${i}`, values: [esz("ImagePath", `C:\s${i}.exe`)] }))));
    // The clock is a count of looks at it, not of seconds (every look moves it 1 ms), so the limit falls after the same number of services on a slow
    // runner and on a fast one: a limit in real seconds fell after the last of the 4000 on a host that reads them in less than 45 ms.
    const src = (await readFile(join(WIN, TOOL, "run.py"), "utf8")).replace(/DEADLINE_SECONDS = \d+ /, "DEADLINE_SECONDS = 0.05 ")
      .replace("\nimport time\n", "\nimport time\n_looks = [0.0]\ndef _counted_clock():\n    _looks[0] += 0.001\n    return _looks[0]\ntime.monotonic = _counted_clock\n");
    assert.ok(src.includes("DEADLINE_SECONDS = 0.05 ") && src.includes("_counted_clock"));
    await mkdir(join(cwd, "copy", TOOL), { recursive: true });
    await writeFile(join(cwd, "copy", TOOL, "run.py"), src);
    const { runPy } = await import("./tool-library-harness.ts");
    const r = await runPy(join(cwd, "copy", TOOL, "run.py"), cwd, { system: "work/SYSTEM", limit: 5 }, undefined, { AGENT_ID: "s1", ...env });
    assert.equal(r.code, 0, r.stdout + r.stderr);
    const out = JSON.parse(r.stdout) as Answer;
    assert.equal(out.status, "partial");
    assert.equal(out.walk_stopped_by_time_limit, true);
    assert.match(out.status_basis, /time limit \(0 seconds, /);
    assert.ok((out.items_by_mechanism.service ?? 0) < 4000, "the walk stopped: the services after the limit are no items");
  });
});

// --- fix round 1 -------------------------------------------------------------------------------------

dual("a service value of a type that is not text (REG_BINARY, REG_MULTI_SZ, REG_DWORD) is kept, never dropped: no false 'no ImagePath' observation, unsupported, partial", async (v) => {
  const evil = Buffer.from("C:\\evil.exe\0", "utf16le");
  const node = (name: string, values: Val[], params?: Val[]): Node => ({ name, values, children: params ? [{ name: "Parameters", values: params }] : undefined });
  const root: Node = {
    name: "ROOT",
    children: [{ name: "Select", values: [dw("Current", 1)] }, { name: "ControlSet001", children: [{ name: "Services", children: [
      node("BinImage", [{ name: "ImagePath", type: "binary", value: evil }, dw("Start", 2)]),
      node("MultiImage", [{ name: "ImagePath", type: "multi_sz", value: ["C:\\a.exe", "C:\\b.exe"] }]),
      node("DwImage", [dw("ImagePath", 7)]),
      node("BinDll", [dw("Start", 3)], [{ name: "ServiceDll", type: "binary", value: evil }]),
      node("OddNames", [sz("ImagePath", "C:\\ok.exe"), { name: "DisplayName", type: "binary", value: Buffer.from([1, 2, 3]) }, dw("ObjectName", 5), sz("FailureActions", "text")]),
      node("Plain", [esz("ImagePath", "C:\\plain.exe")]),
      node("Nothing", [dw("Start", 4)]),
    ] }] }],
  };
  const { out } = await run(v, { system: root });
  const svc = (n: string): Row => byPath(out, `ControlSet001\\${n}`);
  assert.equal(svc("BinImage").image_path_value, evil.toString("hex"));
  assert.equal(svc("BinImage").image_path_value_type, "REG_BINARY");
  assert.equal(svc("MultiImage").image_path_value_type, "REG_MULTI_SZ");
  assert.equal(svc("MultiImage").image_path_value, "C:\\a.exe\nC:\\b.exe");
  assert.equal(svc("DwImage").image_path_value_type, "REG_DWORD");
  assert.equal(svc("BinDll").service_dll_value, evil.toString("hex"));
  assert.equal(svc("OddNames").display_name_value_type, "REG_BINARY");
  assert.equal(svc("OddNames").object_name_value_type, "REG_DWORD");
  assert.equal(svc("OddNames").failure_actions_value_type, "REG_SZ");
  for (const n of ["BinImage", "MultiImage", "DwImage", "BinDll", "OddNames"]) {
    assert.deepEqual(svc(n).observations, [], `${n}: a value exists, so no 'no ImagePath' observation`);
    assert.ok(svc(n).unsupported_fields.length >= 1, n);
  }
  assert.deepEqual(svc("Nothing").observations, ["no_imagepath_and_no_servicedll_value"]);
  assert.deepEqual(svc("Plain").observations, []);
  assert.equal(svc("Plain").unsupported_fields, undefined);
  assert.equal(out.status, "partial");
  assert.match(out.status_basis, /7 value\(s\) of a service key or of the TaskCache are not of the type the tool reads/);
  assert.equal(out.observation_counts.no_imagepath_and_no_servicedll_value, 1);
});

async function runCopy(cwd: string, edit: (s: string) => string, args: Record<string, unknown>, env: Record<string, string>): Promise<Answer> {
  const src = edit(await readFile(join(WIN, TOOL, "run.py"), "utf8"));
  await mkdir(join(cwd, "copy", TOOL), { recursive: true });
  await writeFile(join(cwd, "copy", TOOL, "run.py"), src);
  const r = await runPy(join(cwd, "copy", TOOL, "run.py"), cwd, args, undefined, { AGENT_ID: "s1", ...env });
  assert.equal(r.code, 0, r.stdout + r.stderr);
  return JSON.parse(r.stdout) as Answer;
}
const patch = (s: string, from: string, to: string): string => {
  const t = s.replace(from, to);
  assert.notEqual(t, s, `the patch did not apply: ${from}`);
  return t;
};
/** The tool's reading clock runs out at its k-th look at it (the clock of the writing is left alone). */
const readClockAfter = (k: number) => (s: string): string =>
  patch(patch(s, "\nimport random\n", `\nimport random\n_TICKS = [0]\n\n\ndef _ticks():\n    _TICKS[0] += 1\n    return _TICKS[0] > ${k}\n`), "if stopped[0] is None and out_of_time():", "if stopped[0] is None and _ticks():");
const notRead = (out: Answer): number => Number(/at least (\d+) entr\(ies\) were not read/.exec(out.status_basis)?.[1]);

dual("at its time limit in the services the count of what was not read is the services left in this control set and in the control sets to come, and the services read are written", async (v) => {
  await withCwd(async (cwd) => {
    const svcs = (tag: string): Svc[] => Array.from({ length: 2000 }, (_, i) => ({ name: `${tag}${i}`, values: [esz("ImagePath", `C:\\${tag}${i}.exe`)] }));
    const root: Node = system(svcs("A"), { sets: ["ControlSet001", "ControlSet002"] });
    root.children!.find((c) => c.name === "ControlSet002")!.children![0].children = svcs("B").map((s): Node => ({ name: s.name, values: s.values }));
    const env = await v.write(cwd, "work/SYSTEM", root);
    const out = await runCopy(cwd, readClockAfter(300), { system: "work/SYSTEM", limit: 5000 }, env);
    assert.equal(out.status, "partial");
    assert.ok(out.item_count > 100 && out.item_count < 2000, `${out.item_count} items`);
    assert.equal(out.item_count + notRead(out), 4000, out.status_basis);
    assert.equal(out.items.length, out.item_count, "the items read were written");
  });
});

dual("at its time limit in an autorun key the count is the values left in the key; the keys not started are named apart", async (v) => {
  await withCwd(async (cwd) => {
    const root = software({ run: Array.from({ length: 3000 }, (_, i) => sz(`R${i}`, `C:\\r${i}.exe`)) });
    const env = await v.write(cwd, "work/SOFTWARE", root);
    const out = await runCopy(cwd, readClockAfter(250), { software: "work/SOFTWARE", limit: 5000 }, env);
    assert.equal(out.status, "partial");
    assert.ok(out.item_count > 100 && out.item_count < 3000, `${out.item_count} items`);
    assert.equal(out.item_count + notRead(out), 3000, out.status_basis);
  });
});

dual("an autorun value of binary data names its own noun in the status, not DynamicInfo", async (v) => {
  const { out } = await run(v, { software: software({ run: [{ name: "Bin", type: "binary", value: Buffer.from([1, 2, 3]) }, sz("Ok", "C:\\ok.exe")] }) });
  assert.equal(out.status, "partial");
  assert.match(out.status_basis, /1 autorun value\(s\) are binary data, not text/);
  assert.ok(!/DynamicInfo/.test(out.status_basis));
});
