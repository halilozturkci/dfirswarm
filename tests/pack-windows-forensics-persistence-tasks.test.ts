/**
 * persistence_normalise, scheduled tasks: task XML files, the TaskCache of a SOFTWARE hive and an evtx_query result file, linked without a verdict.
 *
 * Where each layout comes from (the published notes; no byte of a real hive or task file is in this repository, and none of the offsets has been
 * checked against one):
 *   task XML       the Task Scheduler schema: Task/RegistrationInfo/{URI,Author,Date}, Principals/Principal/{UserId,RunLevel}, Triggers/*, Actions/Exec/{Command,
 *                  Arguments,WorkingDirectory}, Settings/{Enabled,Hidden}; the file is UTF-16 with a byte order mark.
 *   TaskCache      SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\{Tree,Tasks,Plain,Boot,Logon,Maintenance}: Tree\<path> holds Id (the GUID), Index
 *                  and SD; Tasks\{GUID} holds Path, Actions, Triggers and DynamicInfo; DynamicInfo is 28 or 36 bytes: version (2 or 3), creation FILETIME (4), last run
 *                  FILETIME (12), state (20), last result (24) and, in 36 bytes, the last success FILETIME (28).
 *   evtx_query     a JSON Lines result file whose rows carry event_id, channel, record_id, record_time_utc and a data object with TaskName.
 */
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { mkdir, readFile, readdir, symlink, writeFile } from "node:fs/promises";
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
  observation_counts: Record<string, number>;
  items_by_registration: Record<string, number>;
  wmi_repository: { result: string; note: string };
  interpretation_limits: string[];
  problems: string[];
  contains_blind_records: number | null;
  hive_dirty?: boolean;
  walk_stopped_by_time_limit: boolean;
  all_results?: string;
  [key: string]: unknown;
};

const TOOL = "persistence_normalise";
const FT = 133_443_104_001_234_567n;
const FT_ISO = "2023-11-13T00:53:20.1234567Z";
const u32le = (n: number): Buffer => { const b = Buffer.alloc(4); b.writeUInt32LE(n); return b; };
const u64le = (n: bigint): Buffer => { const b = Buffer.alloc(8); b.writeBigUInt64LE(n); return b; };
const guid = (i: number): string => `{${(0x10000000 + i).toString(16).toUpperCase().padStart(8, "0")}-0000-4000-8000-${String(i).padStart(12, "0")}}`;
const dyn36 = (): Buffer => Buffer.concat([u32le(3), u64le(FT), u64le(FT + 10_000_000n), u32le(3), u32le(0x41301), u64le(FT + 20_000_000n)]);
const dyn28 = (): Buffer => Buffer.concat([u32le(2), u64le(FT), u64le(FT + 10_000_000n), u32le(4), u32le(0)]);

type Entry = { path: string; id?: string; sd?: boolean; tree?: boolean; tasksKey?: boolean; info?: Buffer; actions?: Buffer; triggers?: Buffer; group?: string };

/** A SOFTWARE hive holding the TaskCache for these entries. */
function software(entries: Entry[], extra: Node[] = []): Node {
  const tree: Node = { name: "Tree", children: [] };
  const tasks: Node = { name: "Tasks", children: [] };
  const groups: Record<string, Node> = {};
  entries.forEach((e, i) => {
    const id = e.id ?? guid(i + 1);
    if (e.tree !== false) {
      const parts = e.path.split("\\").filter(Boolean);
      let at = tree;
      parts.forEach((part, k) => {
        let next = (at.children ??= []).find((c) => c.name === part);
        if (!next) { next = { name: part }; at.children!.push(next); }
        at = next;
        if (k === parts.length - 1) {
          at.values = [{ name: "Id", type: "sz", value: id }, { name: "Index", type: "dword", value: 3 }, ...(e.sd === false ? [] : [{ name: "SD", type: "binary" as const, value: Buffer.alloc(24, 1) }])];
        }
      });
    }
    if (e.tasksKey !== false) {
      const values: Val[] = [{ name: "Path", type: "sz", value: e.path }];
      if (e.info) values.push({ name: "DynamicInfo", type: "binary", value: e.info });
      if (e.actions) values.push({ name: "Actions", type: "binary", value: e.actions });
      if (e.triggers) values.push({ name: "Triggers", type: "binary", value: e.triggers });
      tasks.children!.push({ name: id, values });
    }
    if (e.group) (groups[e.group] ??= { name: e.group, children: [] }).children!.push({ name: id });
  });
  const cache: Node = { name: "TaskCache", children: [tree, tasks, ...Object.values(groups), ...extra] };
  let node: Node = cache;
  for (const part of ["Schedule", "CurrentVersion", "Windows NT", "Microsoft"]) node = { name: part, children: [node] };
  return { name: "ROOT", children: [node] };
}

function taskXml(o: { uri?: string; author?: string; command?: string; args?: string; trigger?: string; hidden?: boolean; extra?: string; userId?: string }): string {
  return `<?xml version="1.0" encoding="UTF-16"?>\n<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">\n  <RegistrationInfo><URI>${o.uri ?? "\\Vendor\\Job"}</URI><Author>${o.author ?? "Vendor"}</Author><Date>2023-11-13T00:53:20</Date></RegistrationInfo>\n  <Principals><Principal id="Author"><UserId>${o.userId ?? "S-1-5-18"}</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>\n  <Triggers><${o.trigger ?? "LogonTrigger"}><Enabled>true</Enabled></${o.trigger ?? "LogonTrigger"}></Triggers>\n  <Settings><Enabled>true</Enabled><Hidden>${o.hidden ? "true" : "false"}</Hidden></Settings>\n  <Actions Context="Author"><Exec><Command>${o.command ?? "C:\\Windows\\System32\\cmd.exe"}</Command><Arguments>${o.args ?? "/c echo hello"}</Arguments></Exec></Actions>${o.extra ?? ""}\n</Task>\n`;
}
const utf16bom = (s: string): Buffer => Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(s, "utf16le")]);

async function putTask(cwd: string, rel: string, content: Buffer | string): Promise<void> {
  const full = join(cwd, "work", "Tasks", ...rel.split("\\").filter(Boolean));
  await mkdir(join(full, ".."), { recursive: true });
  await writeFile(full, content);
}

async function run(v: Variant, entries: Entry[] | null, tasks: Record<string, Buffer | string> | null, args: Record<string, unknown> = {}, env0: Record<string, string> = {}): Promise<{ out: Answer; cwd: string; raw: string; env: Record<string, string> }> {
  let result: { out: Answer; cwd: string; raw: string; env: Record<string, string> } | undefined;
  await withCwd(async (cwd) => {
    const env = await v.write(cwd, "work/SOFTWARE", software(entries ?? []));
    const a: Record<string, unknown> = { ...args };
    if (entries) a.software = "work/SOFTWARE";
    if (tasks) {
      await mkdir(join(cwd, "work", "Tasks"), { recursive: true });
      for (const [rel, content] of Object.entries(tasks)) await putTask(cwd, rel, content);
      a.tasks_dir = "work/Tasks";
    }
    const r = await tool(TOOL, cwd, a, { ...env, ...env0 });
    result = { out: body<Answer>(r), cwd, raw: r.stdout, env };
  });
  return result as { out: Answer; cwd: string; raw: string; env: Record<string, string> };
}

// --- the link ----------------------------------------------------------------------------------

dual("a task found in the XML, in the Tree and in Tasks is one item with its fields, locators and DynamicInfo, and no observation", async (v) => {
  const { out } = await run(v, [{ path: "\\Vendor\\Job", info: dyn36(), actions: Buffer.from("act"), triggers: Buffer.from("trg"), group: "Logon" }, { path: "\\Other", info: dyn28() }],
    { "Vendor\\Job": utf16bom(taskXml({ author: "Vendor Ltd" })), Other: utf16bom(taskXml({ uri: "\\Other", trigger: "TimeTrigger" })) });
  assert.equal(out.status, "complete", out.status_basis + JSON.stringify(out.problems));
  assert.equal(out.item_count, 2);
  assert.deepEqual(out.observation_counts, {});
  assert.deepEqual(out.wmi_repository, { result: "not_examined", note: "WMI repository: not examined" });
  const job = out.items.find((i) => i.path === "\\Vendor\\Job") as Row;
  assert.deepEqual([job.registration.xml, job.registration.tree, job.registration.tasks_key, job.registration.tree_sd], ["present", "present", "present", "present"]);
  assert.deepEqual(job.registration.groups, ["Logon"]);
  assert.equal(job.xml_file, "Vendor\\Job");
  assert.equal(job.bom, "UTF-16LE");
  assert.equal(job.xml.author, "Vendor Ltd");
  assert.equal(job.xml.uri, "\\Vendor\\Job");
  assert.deepEqual(job.xml.trigger_kinds, ["LogonTrigger"]);
  assert.equal(job.xml.actions[0].kind, "Exec");
  assert.equal(job.xml.actions[0].locator, "Task/Actions/Exec[1]");
  assert.equal(job.xml.actions[0].command, "C:\\Windows\\System32\\cmd.exe");
  assert.equal(job.xml.user_id, "S-1-5-18");
  assert.equal(job.dynamic_info.layout, "dynamicinfo-36");
  assert.equal(job.dynamic_info.created, FT_ISO);
  assert.equal(job.dynamic_info.last_run, "2023-11-13T00:53:21.1234567Z");
  assert.equal(job.dynamic_info.last_success, "2023-11-13T00:53:22.1234567Z");
  assert.equal(job.dynamic_info.last_result, String(0x41301));
  assert.equal(job.dynamic_info.dynamic_info_hex, dyn36().toString("hex"));
  assert.equal(job.actions_length, "3");
  assert.equal(job.execution_evidence.source, "not_provided");
  const other = out.items.find((i) => i.path === "\\Other") as Row;
  assert.equal(other.dynamic_info.layout, "dynamicinfo-28");
  assert.ok(out.interpretation_limits.some((l) => /not a persistence verdict/.test(l)) && out.interpretation_limits.some((l) => /WMI repository: not examined/.test(l)));
});

dual("a mismatch is an observation about the inputs, never a verdict: XML without TaskCache, TaskCache without XML, a Tree entry without SD, Tasks without Tree", async (v) => {
  const { out } = await run(v, [
    { path: "\\Both" },
    { path: "\\CacheOnly" },
    { path: "\\NoSd", sd: false },
    { path: "\\Orphan", tree: false },
    { path: "\\NoTasksKey", tasksKey: false },
  ], { Both: utf16bom(taskXml({})), XmlOnly: utf16bom(taskXml({})), NoSd: utf16bom(taskXml({})), Orphan: utf16bom(taskXml({})), NoTasksKey: utf16bom(taskXml({})) });
  const obs = (p: string): string[] => (out.items.find((i) => i.path === p) as Row).observations;
  assert.deepEqual(obs("\\Both"), []);
  assert.deepEqual(obs("\\XmlOnly"), ["xml_without_taskcache"]);
  assert.deepEqual(obs("\\CacheOnly"), ["taskcache_without_xml"]);
  assert.deepEqual(obs("\\NoSd"), ["tree_entry_without_sd_value"]);
  assert.deepEqual(obs("\\Orphan"), ["tasks_key_without_tree_entry"]);
  assert.deepEqual(obs("\\NoTasksKey"), ["tree_entry_without_tasks_key"]);
  assert.match(String(out.observations_note), /none is a persistence verdict/);
  assert.ok(!JSON.stringify(out).match(/malicious|suspicious|persistence found|hidden task/i), "no verdict wording");
});

dual("with only one side given the other is not_provided and no mismatch is claimed", async (v) => {
  const onlyXml = (await run(v, null, { A: utf16bom(taskXml({})) })).out;
  assert.deepEqual(onlyXml.observation_counts, {});
  assert.equal((onlyXml.items[0] as Row).registration.taskcache, "not_provided");
  assert.equal((onlyXml.items[0] as Row).registration.xml, "present");
  const onlyHive = (await run(v, [{ path: "\\A" }], null)).out;
  assert.deepEqual(onlyHive.observation_counts, {});
  assert.equal((onlyHive.items[0] as Row).registration.xml, "not_provided");
});

dual("the byte order marks are read (UTF-16 both ways, UTF-8, none), and a file that is not text is refused with the reason", async (v) => {
  const xml = taskXml({});
  const { out } = await run(v, null, {
    le: utf16bom(xml), be: Buffer.concat([Buffer.from([0xfe, 0xff]), Buffer.from(xml, "utf16le").swap16()]), u8: Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(xml.replace(' encoding="UTF-16"', ""))]),
    none: Buffer.from(xml.replace(' encoding="UTF-16"', "")), junk: Buffer.from([0xff, 0xff, 0x00, 0x00, 0x80]), notxml: utf16bom("hello"),
  });
  const bom = (p: string): string => (out.items.find((i) => i.path === p) as Row).bom;
  assert.deepEqual(["\\le", "\\be", "\\u8", "\\none"].map(bom), ["UTF-16LE", "UTF-16BE", "UTF-8", "none"]);
  for (const p of ["\\le", "\\be", "\\u8", "\\none"]) assert.equal((out.items.find((i) => i.path === p) as Row).xml.actions[0].kind, "Exec", p);
  assert.ok((out.items.find((i) => i.path === "\\notxml") as Row).xml_refused);
  assert.equal(out.status, "partial");
  assert.match(out.status_basis, /task file\(s\) were not parsed/);
});

dual("a DOCTYPE with entities is refused before any parse: no expansion, no time spent, the item says why", async (v) => {
  const bomb = `<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;"><!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">]><Task><RegistrationInfo><Author>&lol3;</Author></RegistrationInfo></Task>`;
  const started = Date.now();
  const { out, raw } = await run(v, null, { Bomb: utf16bom(bomb), Plain: utf16bom(`<!DOCTYPE Task><Task/>`), Normal: utf16bom(taskXml({})) });
  assert.ok(Date.now() - started < 20_000);
  for (const p of ["\\Bomb", "\\Plain"]) assert.match((out.items.find((i) => i.path === p) as Row).xml_refused, /DOCTYPE or ENTITY declaration: refused/);
  assert.ok(!raw.includes("lollol"), "nothing was expanded");
  assert.equal((out.items.find((i) => i.path === "\\Normal") as Row).xml.actions[0].kind, "Exec");
  assert.equal(out.status, "partial");
});

dual("a pipe, a link and a file over the size limit in the tasks directory are skipped or refused and counted, with no wait", async (v) => {
  await withCwd(async (cwd) => {
    const env = await v.write(cwd, "work/SOFTWARE", software([{ path: "\\A" }]));
    await putTask(cwd, "A", utf16bom(taskXml({})));
    assert.equal(spawnSync("mkfifo", [join(cwd, "work", "Tasks", "Pipe")]).status, 0);
    await symlink(join(cwd, "work", "Tasks", "A"), join(cwd, "work", "Tasks", "Link"));
    await writeFile(join(cwd, "work", "Tasks", "Big"), Buffer.alloc((8 << 20) + 1, 0x41));
    const started = Date.now();
    const out = body<Answer>(await tool(TOOL, cwd, { software: "work/SOFTWARE", tasks_dir: "work/Tasks" }, env));
    assert.ok(Date.now() - started < 20_000);
    assert.equal(out.status, "partial");
    assert.match(out.status_basis, /1 link\(s\) and 1 other non-regular/);
    assert.match((out.items.find((i) => i.path === "\\Big") as Row).xml_refused, /over 8388608 bytes/);
    assert.equal(out.items.some((i) => i.path === "\\Link" || i.path === "\\Pipe"), false);
    const fifoHive = failed(await tool(TOOL, cwd, { software: "work/Tasks/Pipe" }, env));
    assert.match(fifoHive.error, /not a regular file/);
  });
});

dual("an unknown DynamicInfo is unsupported with its bytes, and the answer is partial naming the number", async (v) => {
  const { out } = await run(v, [{ path: "\\A", info: Buffer.alloc(20, 1) }, { path: "\\B", info: dyn28() }], null);
  assert.equal(out.status, "partial");
  assert.match(out.status_basis, /1 DynamicInfo value\(s\)/);
  const a = out.items.find((i) => i.path === "\\A") as Row;
  assert.equal(a.dynamic_info.layout, "unknown");
  assert.equal(a.dynamic_info.dynamic_info_hex, Buffer.alloc(20, 1).toString("hex"));
  assert.equal(a.dynamic_info.last_run, undefined);
});

// --- execution evidence ------------------------------------------------------------------------

dual("execution evidence is filled only from the evtx_query result file, by task name, for the listed events", async (v) => {
  await withCwd(async (cwd) => {
    const env = await v.write(cwd, "work/SOFTWARE", software([{ path: "\\Vendor\\Job" }]));
    const rows = [
      { event_id: 4698, channel: "Security", record_id: 11, record_time_utc: FT_ISO, data: { TaskName: "\\Vendor\\Job" } },
      { event_id: 106, channel: "Microsoft-Windows-TaskScheduler/Operational", record_id: 12, record_time_utc: FT_ISO, data: { TaskName: "\\vendor\\job" } },
      { event_id: 200, channel: "Microsoft-Windows-TaskScheduler/Operational", record_id: 13, record_time_utc: FT_ISO, data: { TaskName: "\\Gone" } },
      { event_id: 4624, channel: "Security", record_id: 14, record_time_utc: FT_ISO, data: { TaskName: "\\Vendor\\Job" } },
      { event_id: 4699, channel: "Application", record_id: 15, record_time_utc: FT_ISO, data: { TaskName: "\\Vendor\\Job" } },
    ];
    await writeFile(join(cwd, "work", "events.jsonl"), rows.map((r) => JSON.stringify(r)).join("\n") + "\nnot json\n");
    const out = body<Answer>(await tool(TOOL, cwd, { software: "work/SOFTWARE", evtx_results: "work/events.jsonl" }, env));
    const job = out.items.find((i) => i.path === "\\Vendor\\Job") as Row;
    assert.equal(job.execution_evidence.source, "evtx_results");
    assert.deepEqual(job.execution_evidence.events.map((e: Row) => [e.event_id, e.record_id]), [["4698", "11"], ["106", "12"]]);
    const gone = out.items.find((i) => i.path === "\\Gone") as Row;
    assert.deepEqual(gone.observations, ["events_only"]);
    assert.deepEqual([gone.registration.tree, gone.registration.tasks_key], ["absent", "absent"]);
    assert.equal(out.evtx_rows_read, 5);
    assert.equal(out.evtx_rows_ignored, 2);
    assert.equal(out.status, "partial");
    assert.match(out.status_basis, /1 line\(s\) of the evtx result file could not be read/);
  });
});

dual("more events than the listing holds for one task are counted, and the answer is partial", async (v) => {
  await withCwd(async (cwd) => {
    const env = await v.write(cwd, "work/SOFTWARE", software([{ path: "\\Busy" }]));
    const rows = Array.from({ length: 260 }, (_, i) => JSON.stringify({ event_id: 200, channel: "Microsoft-Windows-TaskScheduler/Operational", record_id: i, record_time_utc: FT_ISO, data: { TaskName: "\\Busy" } }));
    await writeFile(join(cwd, "work", "events.jsonl"), rows.join("\n"));
    const out = body<Answer>(await tool(TOOL, cwd, { software: "work/SOFTWARE", evtx_results: "work/events.jsonl" }, env));
    assert.equal((out.items[0] as Row).execution_evidence.events.length, 200);
    assert.match(out.status_basis, /60 event\(s\) past the 200 listed/);
  });
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

dual("a token in Arguments, in Command and in a task's file name is never printed whole, nor in a result file; contains cannot find it (oracle twin)", async (v) => {
  for (const shape of FILE_SHAPES) {
    const [canary] = plant(shape, 1, 11);
    const needle = canary.cores[0].slice(0, 12);
    await withCwd(async (cwd) => {
      const env = await v.write(cwd, "work/SOFTWARE", software([{ path: "\\Job", actions: Buffer.from(`--token ${canary.text}`, "utf16le") }]));
      await mkdir(join(cwd, "work", "Tasks"), { recursive: true });
      await putTask(cwd, "Job", utf16bom(taskXml({ args: `--password ${canary.text}`, command: `C:\\tools\\${canary.text}.exe` })));
      await putTask(cwd, canary.text, utf16bom(taskXml({})));
      const base = { software: "work/SOFTWARE", tasks_dir: "work/Tasks" };
      const r = await tool(TOOL, cwd, { ...base, limit: 1 }, env);
      const out = body<Answer>(r);
      const hexViews = [...r.stdout.matchAll(/"[a-z_]*hex": "([0-9a-f]{8,})"/g)].flatMap((m) => { const b = Buffer.from(m[1], "hex"); return [b.toString("latin1"), b.toString("utf16le")]; });
      const all = [r.stdout, ...(await filesUnder(join(cwd, "work", "s1"))), ...hexViews];
      assert.equal(leaked([canary], all), 0, `${shape.name}: printed whole`);
      assert.equal(fragmentLeaked([canary], all), 0, `${shape.name}: a piece of it printed`);
      assert.ok(["partial", "complete"].includes(out.status));
      const probe = body<Answer>(await tool(TOOL, cwd, { ...base, contains: needle }, env));
      assert.equal(probe.item_count, 0, `${shape.name}: a needle inside withheld text must not match`);
      assert.ok((probe.contains_blind_records ?? 0) >= 1, `${shape.name}: blind`);
      assert.equal(probe.status, "partial");
      assert.ok(!JSON.stringify(probe).includes(needle));
    });
  }
  await withCwd(async (cwd) => {
    const env = await v.write(cwd, "work/SOFTWARE", software([]));
    await putTask(cwd, "Notes", utf16bom(taskXml({ args: "/c harbor-notes.cmd" })));
    await putTask(cwd, "Other", utf16bom(taskXml({})));
    const hit = body<Answer>(await tool(TOOL, cwd, { tasks_dir: "work/Tasks", contains: "HARBOR" }, env));
    assert.equal(hit.item_count, 1);
    assert.equal(hit.contains_blind_records, 0);
    assert.equal(hit.filtered_out, 1);
  });
});

dual("write_values is refused outside a secret-output job, and in one the originals go to a 0600 file and never to the answer", async (v) => {
  const [canary] = plant(FILE_SHAPES[0], 1, 5);
  await withCwd(async (cwd) => {
    const env = await v.write(cwd, "work/SOFTWARE", software([]));
    await putTask(cwd, "Job", utf16bom(taskXml({ args: `--password ${canary.text}` })));
    const refused = failed(await tool(TOOL, cwd, { tasks_dir: "work/Tasks", write_values: true }, env));
    assert.match(refused.error, /secret_output|SECRET_OUTPUT|secret output/);
    const r = await tool(TOOL, cwd, { tasks_dir: "work/Tasks", write_values: true }, { ...env, ...jobEnv(cwd), SECRET_OUTPUT: "1" });
    body<Answer>(r);
    assert.equal(leaked([canary], [r.stdout]), 0);
    const file = join(cwd, "out", "persistence_normalise-values.jsonl");
    assert.equal(statSync(file).mode & 0o777, 0o600);
    assert.equal(leaked([canary], [readFileSync(file, "utf8")]), 1);
  });
});

dual("hostile file names (a 250-character one, control characters, a separator-looking one) are read and answered as JSON", async (v) => {
  const { out } = await run(v, null, { ["L".repeat(250)]: utf16bom(taskXml({})), ["a\u0001b\u0007c"]: utf16bom(taskXml({})), "dir.with.dots\\x y": utf16bom(taskXml({})) });
  assert.equal(out.item_count, 3);
  assert.ok(out.items.every((i) => typeof i.path === "string"));
});

// --- size, the clock, the signals ---------------------------------------------------------------------

dual("a TaskCache of 100,000 tasks and 3,000 task files is read without a quadratic phase, and its counts are the file's", async (v) => {
  const entries: Entry[] = Array.from({ length: 100_000 }, (_, i) => ({ path: `\\Folder${i % 50}\\Task${i}`, info: dyn28() }));
  await withCwd(async (cwd) => {
    const env = await v.write(cwd, "work/SOFTWARE", software(entries));
    for (let i = 0; i < 3000; i++) await putTask(cwd, `Folder${i % 50}\\Task${i}`, utf16bom(taskXml({ uri: `\\Task${i}` })));
    const started = Date.now();
    const out = body<Answer>(await tool(TOOL, cwd, { software: "work/SOFTWARE", tasks_dir: "work/Tasks", limit: 10 }, env));
    const secs = (Date.now() - started) / 1000;
    assert.equal(out.item_count, 100_000);
    assert.equal(out.status, out.walk_stopped_by_time_limit ? "partial" : "complete", out.status_basis);
    assert.equal(out.observation_counts.taskcache_without_xml, 97_000);
    assert.ok(secs < 280, `${secs} seconds`);
    const lines = readFileSync(join(cwd, out.all_results as string), "utf8").trim().split("\n");
    assert.equal(lines.length, out.item_count, "the counts are the file's");
  });
});

dual("at its own time limit the tool answers partial and says how many it did not read", async (v) => {
  await withCwd(async (cwd) => {
    const env = await v.write(cwd, "work/SOFTWARE", software(Array.from({ length: 30 }, (_, i) => ({ path: `\\T${i}` }))));
    for (let i = 0; i < 30; i++) await putTask(cwd, `T${i}`, utf16bom(taskXml({})));
    const src = (await readFile(join(WIN, TOOL, "run.py"), "utf8")).replace(/DEADLINE_SECONDS = \d+ /, "DEADLINE_SECONDS = 0 ");
    assert.ok(src.includes("DEADLINE_SECONDS = 0 "));
    await mkdir(join(cwd, "copy", TOOL), { recursive: true });
    await writeFile(join(cwd, "copy", TOOL, "run.py"), src);
    const r = await runPy(join(cwd, "copy", TOOL, "run.py"), cwd, { software: "work/SOFTWARE", tasks_dir: "work/Tasks" }, undefined, { AGENT_ID: "s1", ...env });
    assert.equal(r.code, 0, r.stdout + r.stderr);
    const out = JSON.parse(r.stdout) as Answer;
    assert.equal(out.status, "partial");
    assert.equal(out.walk_stopped_by_time_limit, true);
    assert.match(out.status_basis, /time limit \(0 seconds\)/);
    assert.match(out.status_basis, /were not read or written/);
  });
});

for (const [signal, code] of [["SIGTERM", 143], ["SIGINT", 130], ["SIGHUP", 129]] as Array<[NodeJS.Signals, number]>) {
  for (const variant of VARIANTS) {
    test(`stopped by ${signal} the tool answers JSON, exits ${code} and leaves no temporary file [${variant.label}]`, { skip: variant.skip }, async () => {
      await withCwd(async (cwd) => {
        const env = await variant.write(cwd, "work/SOFTWARE", software(Array.from({ length: 8000 }, (_, i) => ({ path: `\\F${i % 20}\\T${i}` }))));
        const child = spawn("python3", [join(WIN, TOOL, "run.py")], { cwd, env: { ...process.env, AGENT_ID: "s1", ...env } });
        let stdout = "";
        child.stdout.on("data", (c: Buffer) => (stdout += c.toString()));
        const closed = new Promise<number | null>((resolve) => child.on("close", (c) => resolve(c)));
        child.stdin.end(JSON.stringify({ software: "work/SOFTWARE", limit: 1 }));
        const dir = join(cwd, "work", "s1", "tool-output");
        let seen = false;
        for (let waited = 0; waited < 60_000 && !seen; waited += 25) {
          seen = (await readdir(dir).catch(() => [] as string[])).some((n) => n.startsWith(".persistence_normalise"));
          if (!seen) await new Promise((r) => setTimeout(r, 25));
        }
        assert.ok(seen, "the tool never opened a temporary file");
        child.kill("SIGSTOP");
        child.kill(signal);
        child.kill("SIGCONT");
        assert.equal(await closed, code);
        const out = JSON.parse(stdout) as Answer;
        assert.deepEqual([out.status, out.interrupted], ["failed", true]);
        assert.equal(out.signal, code - 128);
        assert.deepEqual((await readdir(dir)).filter((n) => n.startsWith(".")), [], "a temporary file was left");
      });
    });
  }
}

test("persistence_normalise is registered: names, secret_output, version and the words about the signal layer", async () => {
  const manifest = JSON.parse(await readFile(join(WIN, TOOL, "manifest.json"), "utf8"));
  assert.deepEqual(manifest.secret_output, { when_args: ["write_values"] });
  assert.ok(manifest.timeout_seconds > 294);
  assert.deepEqual(manifest.requires, []);
  assert.match(manifest.description, /WMI repository: not examined/);
  assert.match(manifest.description, /not done/i);
});

dual("wrong arguments are refused as JSON before any read", async (v) => {
  await withCwd(async (cwd) => {
    const env = await v.write(cwd, "work/SOFTWARE", software([]));
    for (const bad of [{}, { software: 1 }, { software: "work/SOFTWARE", limit: 0 }, { software: "work/SOFTWARE", contains: "" }, { software: "work/SOFTWARE", write_values: "yes" },
      { software: "work/nothere" }, { tasks_dir: "work/SOFTWARE" }, { tasks_dir: "work/nothere" }, { software: "work/SOFTWARE", evtx_results: "work/nothere" }]) {
      const r = failed(await tool(TOOL, cwd, bad, env));
      assert.ok(typeof r.error === "string" && r.error.length > 0, JSON.stringify(bad));
    }
    const noCache = await v.write(cwd, "work/EMPTY", { name: "ROOT", children: [{ name: "Other" }] });
    assert.match(failed(await tool(TOOL, cwd, { software: "work/EMPTY" }, noCache)).error, /no TaskCache key/);
  });
});

dual("a time limit that falls inside one directory of task files stops the scan and counts what was not read", async (v) => {
  await withCwd(async (cwd) => {
    const env = await v.write(cwd, "work/SOFTWARE", software([{ path: "\A" }]));
    const xml = utf16bom(taskXml({}));
    await mkdir(join(cwd, "work", "Tasks"), { recursive: true });
    for (let i = 0; i < 3000; i++) await writeFile(join(cwd, "work", "Tasks", `T${i}`), xml);
    const src = (await readFile(join(WIN, TOOL, "run.py"), "utf8")).replace(/DEADLINE_SECONDS = \d+ /, "DEADLINE_SECONDS = 0.05 ");
    await mkdir(join(cwd, "copy", TOOL), { recursive: true });
    await writeFile(join(cwd, "copy", TOOL, "run.py"), src);
    const r = await runPy(join(cwd, "copy", TOOL, "run.py"), cwd, { software: "work/SOFTWARE", tasks_dir: "work/Tasks", limit: 5 }, undefined, { AGENT_ID: "s1", ...env });
    assert.equal(r.code, 0, r.stdout + r.stderr);
    const out = JSON.parse(r.stdout) as Answer;
    assert.equal(out.status, "partial");
    assert.equal(out.walk_stopped_by_time_limit, true);
    assert.ok(Object.values(out.items_by_registration).reduce((x, y) => x + y, 0) < 3000, "the scan stopped: the files after the limit are no items");
    assert.match(out.status_basis, /time limit \(0 seconds\)/);
    assert.match(out.status_basis, /were not read or written/);
  });
});
