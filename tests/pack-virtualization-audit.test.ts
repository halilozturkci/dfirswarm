/**
 * virtualization-backup-forensics: backup_audit_normalise turns a job or task record into canonical events. The Proxmox
 * UPID task lines and vzdump log lines are written here from Proxmox's published task and log formats, and the declared
 * CSV, JSON Lines and XML exports from the shapes those formats have (RFC 4180, JSON Lines, XML 1.0), never from the
 * tool's output. Held here: an event says what a record says and where it was read; a time is read exactly as declared and
 * a time with no zone is never assumed UTC; a product with no fixtures is refused by name and no vendor layout is guessed;
 * a line that is not understood is counted and located, not dropped; free text stays out of the answer; and every limit is
 * reported.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { readFile, stat } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { AUDIT, CANARY, asJob, body, everythingBut, filesUnder, json, put, refused, rowsOf, tool, withCwd } from "./pack-virtualization-harness.ts";
import type { Json } from "./pack-virtualization-harness.ts";

const hex = (n: number, width = 8): string => n.toString(16).toUpperCase().padStart(width, "0");

function upid(o: { node?: string; pid?: number; start: number; type: string; id?: string; user?: string; end?: number; status?: string }): string {
  const head = `UPID:${o.node ?? "pve1"}:${hex(o.pid ?? 2931)}:${hex(54000)}:${hex(o.start)}:${o.type}:${o.id ?? ""}:${o.user ?? "root@pam"}:`;
  return o.end === undefined ? head : `${head} ${hex(o.end)} ${o.status ?? "OK"}`;
}

const T0 = 1_700_000_000;

test("a Proxmox task index: each UPID line is an event with its worker type, object, user, start and end, a category from the table, and a result that says where it came from", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/tasks/index", [
      upid({ start: T0, type: "vzdump", end: T0 + 120, status: "OK" }),
      upid({ start: T0 + 300, type: "qmdelsnapshot", id: "100", user: "root@pam!automation", end: T0 + 305, status: "OK" }),
      upid({ start: T0 + 400, type: "qmdestroy", id: "101", end: T0 + 401, status: "unable to destroy VM 101 - lock held" }),
      upid({ start: T0 + 500, type: "qmrollback", id: "100", end: T0 + 510, status: "WARNINGS: 1" }),
      upid({ start: T0 + 600, type: "prunejob", user: "root@pam", end: T0 + 610, status: "OK" }),
      upid({ start: T0 + 700, type: "garbage_collection", end: T0 + 900, status: "OK" }),
      upid({ start: T0 + 800, type: "verificationjob", end: T0 + 810, status: "OK" }),
      upid({ start: T0 + 900, type: "newtaskkind", id: "7" }),
      upid({ start: T0 + 950, type: "qm_delsnapshot_x", id: "7", end: T0 + 951, status: "OK" }),
      "",
      "this is not a task line",
    ].join("\n") + "\n");
    const out = body(await tool(AUDIT, cwd, { path: "inputs/tasks/index" }));
    assert.equal(out.counts.events, 9);
    assert.equal(out.counts.unparsed, 1);
    assert.equal(out.counts.blank, 1);
    assert.equal(out.status, "partial");
    assert.match(out.status_basis, /1 unparsed line/);
    assert.equal(out.problem_lines[0].reason, "not a UPID task line");
    assert.equal(out.problem_lines[0].line, 11);
    const ev = out.events;
    assert.deepEqual(ev.map((e: Json) => e.category), ["backup_job", "snapshot_delete", "vm_delete", "snapshot_rollback", "retention_prune", "retention_gc", "verification", "other", "snapshot_delete"]);
    assert.equal(ev[0].time_utc, "2023-11-14T22:13:20Z");
    assert.equal(ev[0].end_time_utc, "2023-11-14T22:15:20Z");
    assert.match(ev[0].time_basis, /UTC by definition/);
    assert.equal(ev[0].time_raw, hex(T0));
    assert.equal(ev[1].actor, "root@pam!automation");
    assert.equal(ev[1].object, "100");
    assert.equal(ev[1].host, "pve1");
    assert.equal(ev[0].result, "ok");
    assert.equal(ev[2].result, "error");
    assert.equal(ev[2].result_raw, "unable to destroy VM 101 - lock held");
    assert.equal(ev[3].result, "warning");
    assert.equal(ev[7].result, "unknown");
    assert.match(ev[7].result_basis, /no end time or status/);
    assert.match(ev[8].category_basis, /keyword 'delsnap'/);
    assert.match(ev[0].category_basis, /worker type table/);
    assert.deepEqual(ev[1].locator, { line: 2, byte_offset: ev[1].locator.byte_offset, byte_length: ev[1].locator.byte_length });
    assert.deepEqual(out.by_category, { backup_job: 1, snapshot_delete: 2, vm_delete: 1, snapshot_rollback: 1, retention_prune: 1, retention_gc: 1, verification: 1, other: 1 });
    assert.equal(out.time.first_utc, "2023-11-14T22:13:20Z");
    assert.match(out.time.note, /source order, not time order/);
  });
});

test("byte offsets and lengths find each line in the evidence; CRLF, a missing final newline, an over-long line and non-UTF-8 bytes are handled and counted", async () => {
  await withCwd(async (cwd) => {
    const a = upid({ start: T0, type: "vzdump", end: T0 + 1 });
    const b = upid({ start: T0 + 1, type: "qmstart", id: "9", end: T0 + 2 });
    const bad = Buffer.concat([Buffer.from("UPID:pve1:00000B73:0000D2C5:"), Buffer.from(hex(T0 + 2)), Buffer.from(":qmstop:caf"), Buffer.from([0xe9, 0xff]), Buffer.from(":root@pam:")]);
    const source = Buffer.concat([Buffer.from(a + "\r\n"), Buffer.from("x".repeat(5000) + "\n"), Buffer.from(b + "\n"), bad, Buffer.from("\n"), Buffer.from(upid({ start: T0 + 5, type: "qmreset", id: "2" }))]);
    await put(cwd, "inputs/index", source);
    const out = body(await tool(AUDIT, cwd, { path: "inputs/index", max_line_bytes: 4096 }));
    assert.equal(out.counts.over_line_limit, 1);
    assert.equal(out.problem_lines.find((p: Json) => p.line === 2).reason, "line over max_line_bytes: located, not read");
    assert.equal(out.problem_lines.find((p: Json) => p.line === 2).byte_offset, Buffer.byteLength(a) + 2);
    for (const e of out.events) {
      const slice = source.subarray(e.locator.byte_offset, e.locator.byte_offset + e.locator.byte_length).toString("latin1");
      assert.match(slice, /^UPID:/, `event ${e.seq} starts where its locator says`);
    }
    assert.equal(out.events.length, 4);
    assert.equal(out.events[2].object.startsWith("caf"), true, "non-UTF-8 bytes are escapes, not a crash");
    assert.equal(out.events[3].result, "unknown");
  });
});

const LOG = [
  "INFO: starting new backup job: vzdump 100 101 --mode snapshot --storage local --compress zstd",
  "INFO: Starting Backup of VM 100 (qemu)",
  "INFO: Backup started at 2024-01-05 02:00:01",
  "INFO: status = running",
  "INFO: include disk 'scsi0' 'local-lvm:vm-100-disk-0' 32G",
  "INFO: creating vzdump archive '/var/lib/vz/dump/vzdump-qemu-100-2024_01_05-02_00_01.vma.zst'",
  "INFO: archive file size: 1.20GB",
  "INFO: Finished Backup of VM 100 (00:00:45)",
  "INFO: Backup finished at 2024-01-05 02:00:46",
  "ERROR: Backup of VM 101 failed - storage 'local' is not online",
  "INFO: removing backup 'local:backup/vzdump-qemu-100-2023_12_01-02_00_00.vma.zst'",
  "WARN: something odd happened",
  "INFO: Backup job finished with errors",
  "TASK ERROR: job errors",
].join("\n") + "\n";

test("a vzdump log: events for the job, each guest, the archive, the removal and the TASK line; a node-local time is not UTC unless an offset is declared; free text is a length, not text", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/task.log", LOG);
    const run = await tool(AUDIT, cwd, { path: "inputs/task.log" });
    const out = body(run);
    const cats = out.events.map((e: Json) => e.category);
    assert.deepEqual(cats, ["backup_job", "backup_start", "backup_start", "archive_created", "backup_end", "backup_end", "backup_error", "retention_remove", "other", "task_end", "task_end"]);
    assert.equal(out.counts.unparsed, 3, "status, include disk and archive size are lines this tool has no pattern for: counted");
    assert.deepEqual(out.problem_lines.map((p: Json) => [p.line, p.reason]), [[4, "a INFO line this tool has no pattern for"], [5, "a INFO line this tool has no pattern for"], [7, "a INFO line this tool has no pattern for"]], "each is located by line");
    const times = out.events.filter((e: Json) => e.time_raw);
    assert.equal(times.length, 2);
    for (const t of times) {
      assert.equal(t.time_utc, null);
      assert.match(t.time_basis, /no zone in the value and none declared: naive local time, not assumed to be UTC/);
    }
    assert.equal(out.time.derived, 0);
    assert.equal(out.events[6].object, "101");
    assert.equal(out.events[6].result, "error");
    assert.equal(out.events[3].object, "/var/lib/vz/dump/vzdump-qemu-100-2024_01_05-02_00_01.vma.zst");
    assert.equal(out.events[7].object, "local:backup/vzdump-qemu-100-2023_12_01-02_00_00.vma.zst");
    assert.equal(out.events[10].result, "error");
    assert.equal(out.events[0].action_raw, "starting new backup job", "the action label is the tool's constant, not a cut of the evidence");
    assert.equal(run.stdout.includes("is not online"), false, "the free text of an error is not in the answer");
    assert.equal(run.stdout.includes("--compress zstd"), false);
    assert.equal(out.events[6].message_chars, "Backup of VM 101 failed - storage 'local' is not online".length);
    // with an offset declared
    const withOffset = body(await tool(AUDIT, cwd, { path: "inputs/task.log", time_zone_offset_minutes: 60 }));
    const first = withOffset.events.find((e: Json) => e.time_raw);
    assert.equal(first.time_utc, "2024-01-05T01:00:01Z");
    assert.match(first.time_basis, /fixed offset of 60 minutes declared by the caller; daylight saving is not accounted for/);
  });
});

test("write_text keeps each event's message and the originals of what was withheld in one 0600 file, in a job; outside one it is refused", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/task.log", LOG + `ERROR: Backup of VM 102 failed - upload to https://${CANARY.userinfo}@pbs.example.test/${CANARY.github} refused\n`);
    assert.match(refused(await tool(AUDIT, cwd, { path: "inputs/task.log", write_text: true })).error, /outside a job/);
    const run = await asJob(AUDIT, cwd, { path: "inputs/task.log", write_text: true });
    const out = body(run);
    assert.equal(out.text.written, out.counts.events - 0, "one message per event that has one is kept");
    const file = join(cwd, "out", "audit-values.jsonl");
    assert.equal((await stat(file)).mode & 0o777, 0o600);
    const rows = (await readFile(file, "utf8")).trimEnd().split("\n").map((l) => JSON.parse(l));
    assert.ok(rows.some((r) => r.message === "Backup of VM 101 failed - storage 'local' is not online"));
    assert.ok(rows.some((r) => String(r.message).includes(CANARY.github) && String(r.message).includes("S3cr3tPassw0rd")), "the original, whole, is in the values file");
    const rest = await everythingBut(cwd, run.stdout + run.stderr, ["inputs/task.log", "out/audit-values.jsonl"]);
    assert.equal(rest.includes(CANARY.github) || rest.includes("S3cr3tPassw0rd") || rest.includes("is not online"), false);
    assert.match(refused(await tool(AUDIT, cwd, { path: "inputs/task.log", write_text: true }, { JOB_ID: "j000001", OUT: join(cwd, "out") })).error, /values file already exists/);
  });
});

const CSV = `﻿When,Operation,Outcome,User,Object,Details\n2024-01-05T02:00:00Z,Delete restore point,Success,admin,vm100,"removed ""old"" point\nsecond line"\n2024-01-05 03:00:00,Job start,Failed,svc,vm101,x\n`;
const MAPPING = { time: "When", action: "Operation", result: "Outcome", actor: "User", object: "Object", message: "Details" };

test("a declared CSV: the caller's mapping reads the columns, the caller's category_map and result_map give the meaning, a zone-less time stays raw, and every event says the mapping is declared", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/export.csv", CSV);
    const run = await tool(AUDIT, cwd, {
      path: "inputs/export.csv", format: "declared_csv", product: "ExampleBackup", mapping: MAPPING,
      category_map: { "delete restore point": "retention_remove" }, result_map: { success: "ok", failed: "error" },
    });
    const out = body(run);
    assert.equal(out.status, "complete", out.status_basis);
    assert.equal(out.product_label, "ExampleBackup");
    assert.match(out.product_label_note, /not verified/);
    const [a, b] = out.events;
    assert.equal(a.category, "retention_remove");
    assert.equal(a.category_basis, "declared in category_map");
    assert.equal(a.result, "ok");
    assert.equal(a.result_basis, "declared in result_map");
    assert.equal(a.time_utc, "2024-01-05T02:00:00Z");
    assert.equal(a.object, "vm100");
    assert.deepEqual(a.locator, { record: 1, line: 3 }, "the multi-line quoted field ends on line 3");
    assert.match(a.mapping_declared_by, /the caller; the tool does not know the product/);
    assert.equal(b.category, "other");
    assert.match(b.category_basis, /not in the caller's category_map/);
    assert.equal(b.time_utc, null);
    assert.match(b.time_basis, /not assumed to be UTC/);
    assert.equal(b.result, "error");
    assert.deepEqual(out.unmapped_actions_top, [{ action: "Job start", count: 1 }]);
    assert.equal(a.message_chars, "removed \"old\" point\nsecond line".length);
    assert.equal(run.stdout.includes("removed"), false);
    // a declared offset converts it
    const off = body(await tool(AUDIT, cwd, { path: "inputs/export.csv", format: "declared_csv", mapping: MAPPING, time_zone_offset_minutes: -300 }));
    assert.equal(off.events[1].time_utc, "2024-01-05T08:00:00Z");
    assert.equal(off.events[0].time_utc, "2024-01-05T02:00:00Z", "a value that carries its own zone ignores the declared one");
  });
});

test("a declared CSV: a column the mapping names that is not in the header is a mapping error and no event is invented; ragged rows are counted and located; other delimiters and header-less files work", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/a.csv", "When,Operation\n2024-01-05T02:00:00Z,x\n");
    const missing = json(await tool(AUDIT, cwd, { path: "inputs/a.csv", format: "declared_csv", mapping: { time: "When", action: "Operation", result: "Outcome" } }));
    assert.equal(missing.status, "failed");
    assert.match(missing.mapping_errors[0], /declared column\(s\) Outcome are not in the header \(2 columns\)/);
    assert.equal(missing.counts.events, 0);
    await put(cwd, "inputs/b.csv", "When;Operation;Outcome\n2024-01-05T02:00:00Z;a;ok\n2024-01-05T02:00:01Z;b\n2024-01-05T02:00:02Z;c;ok;extra\n\n2024-01-05T02:00:03Z;d;ok\n");
    const ragged = body(await tool(AUDIT, cwd, { path: "inputs/b.csv", format: "declared_csv", delimiter: ";", mapping: { time: "When", action: "Operation", result: "Outcome" } }));
    assert.equal(ragged.counts.events, 2);
    assert.equal(ragged.counts.unparsed, 2);
    assert.equal(ragged.counts.blank, 1);
    assert.deepEqual(ragged.problem_lines.map((p: Json) => [p.record, p.line]), [[2, 3], [3, 4]]);
    assert.equal(ragged.status, "partial");
    await put(cwd, "inputs/c.csv", "2024-01-05T02:00:00Z,delete\n");
    const headerless = body(await tool(AUDIT, cwd, { path: "inputs/c.csv", format: "declared_csv", has_header: false, columns: ["t", "a"], mapping: { time: "t", action: "a" } }));
    assert.equal(headerless.events[0].action_raw, "delete");
    assert.match(refused(await tool(AUDIT, cwd, { path: "inputs/c.csv", format: "declared_csv", has_header: false, mapping: { time: "t", action: "a" } })).error, /needs columns/);
  });
});

test("a declared CSV: a field over the reader's limit and a quoted field that never closes end in a reported read error, not a hang or a traceback", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/big.csv", `When,Operation\n2024-01-05T02:00:00Z,"${"x".repeat(2_000_000)}"\n2024-01-05T02:00:01Z,fine\n`);
    const big = json(await tool(AUDIT, cwd, { path: "inputs/big.csv", format: "declared_csv", mapping: { time: "When", action: "Operation" } }));
    assert.ok(big.read_errors.length >= 1 || big.counts.unparsed >= 1);
    assert.equal(big.status, "partial");
    await put(cwd, "inputs/open.csv", `When,Operation\n2024-01-05T02:00:00Z,"never closed\n2024-01-05T02:00:01Z,fine\n`);
    const open = json(await tool(AUDIT, cwd, { path: "inputs/open.csv", format: "declared_csv", mapping: { time: "When", action: "Operation" } }));
    assert.ok(open.status === "partial" || open.status === "complete");
    assert.ok(open.counts.events <= 1);
  });
});

test("declared JSON Lines: dotted paths read nested fields, epoch milliseconds and strptime formats are read as declared, lines that are not JSON objects are counted and located", async () => {
  await withCwd(async (cwd) => {
    const lines = [
      JSON.stringify({ ts: 1_700_000_000_123, event: { name: "SnapshotRemove", result: "FAILED" }, who: { id: "svc" }, target: "vm9" }),
      JSON.stringify({ ts: "1700000001000", event: { name: "JobRun", result: "OK" } }),
      "not json",
      "[1,2]",
      JSON.stringify({ ts: -1, event: { name: "x" } }),
      "[".repeat(100_000),
      "",
    ];
    await put(cwd, "inputs/e.jsonl", lines.join("\n") + "\n");
    const out = body(await tool(AUDIT, cwd, { path: "inputs/e.jsonl", format: "declared_jsonl", time_format: "epoch_milliseconds", mapping: { time: "ts", action: "event.name", result: "event.result", actor: "who.id", object: "target" }, category_map: { snapshotremove: "snapshot_delete" }, result_map: { failed: "error", ok: "ok" } }));
    assert.equal(out.counts.events, 3);
    assert.equal(out.counts.unparsed, 3);
    assert.equal(out.events[0].time_utc, "2023-11-14T22:13:20.123000Z");
    assert.equal(out.events[0].category, "snapshot_delete");
    assert.equal(out.events[0].actor, "svc");
    assert.equal(out.events[1].time_utc, "2023-11-14T22:13:21Z");
    assert.equal(out.events[2].time_utc, null);
    assert.match(out.events[2].time_basis, /not a usable epoch value/);
    assert.deepEqual(out.problem_lines.map((p: Json) => p.line), [3, 4, 6]);
  });
});

test("declared time formats: strptime with and without a zone, ISO 8601 with a fraction and an offset, and a value that does not match the format says why", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/t.csv", ["t,a", "05/01/2024 02:00:00 +0200,x", "05/01/2024 02:00:00,y", "garbage,z", ""].join("\n"));
    const zoned = body(await tool(AUDIT, cwd, { path: "inputs/t.csv", format: "declared_csv", mapping: { time: "t", action: "a" }, time_format: "strptime:%d/%m/%Y %H:%M:%S %z" }));
    assert.equal(zoned.events[0].time_utc, "2024-01-05T00:00:00Z");
    assert.match(zoned.events[1].time_basis, /does not match the declared format/);
    const naive = body(await tool(AUDIT, cwd, { path: "inputs/t.csv", format: "declared_csv", mapping: { time: "t", action: "a" }, time_format: "strptime:%d/%m/%Y %H:%M:%S" }));
    assert.equal(naive.events[1].time_utc, null);
    assert.match(naive.events[1].time_basis, /not assumed to be UTC/);
    await put(cwd, "inputs/i.csv", ["t,a", "2024-01-05T02:00:00.123456+05:30,x", "2024-01-05T02:00:00,y", "2024-13-45T02:00:00Z,bad", ""].join("\n"));
    const iso = body(await tool(AUDIT, cwd, { path: "inputs/i.csv", format: "declared_csv", mapping: { time: "t", action: "a" } }));
    assert.equal(iso.events[0].time_utc, "2024-01-04T20:30:00.123456Z");
    assert.equal(iso.events[1].time_utc, null);
    assert.equal(iso.events[2].time_utc, null);
    assert.match(iso.events[2].time_basis, /does not match the declared format|not an ISO/);
    assert.equal(iso.time.derived, 1);
    assert.equal(iso.time.not_derived, 2);
  });
});

const XML = `<?xml version="1.0"?><Audit><Record id="1" when="2024-01-05T02:00:00Z"><Action>Delete</Action><Who><Name>admin</Name></Who><Result>Success</Result><Text>removed it</Text></Record><Record id="2" when="2024-01-05T03:00:00Z"><Action>Run</Action><Who><Name>svc</Name></Who></Record></Audit>`;
const XMAP = { time: "@when", action: "Action", actor: "Who/Name", result: "Result", object: "@id", message: "Text" };

test("declared XML: records are streamed one at a time, children and attributes are mapped by path, a DOCTYPE or entity is refused, and a million-element file is bounded by the record, not the file", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/a.xml", XML);
    const run = await tool(AUDIT, cwd, { path: "inputs/a.xml", format: "declared_xml", record_tag: "Record", mapping: XMAP, category_map: { delete: "snapshot_delete" } });
    const out = body(run);
    assert.equal(out.counts.events, 2);
    assert.equal(out.events[0].category, "snapshot_delete");
    assert.equal(out.events[0].actor, "admin");
    assert.equal(out.events[0].object, "1");
    assert.equal(out.events[0].time_utc, "2024-01-05T02:00:00Z");
    assert.equal(out.events[1].result, "unknown");
    assert.equal(out.events[1].result_basis, "no result field in the record");
    assert.equal(run.stdout.includes("removed it"), false);
    await put(cwd, "inputs/bomb.xml", `<!DOCTYPE a [<!ENTITY x "y">]><Audit><Record>&x;</Record></Audit>`);
    const refusedXml = json(await tool(AUDIT, cwd, { path: "inputs/bomb.xml", format: "declared_xml", record_tag: "Record", mapping: XMAP }));
    assert.match(refusedXml.read_errors.join(" "), /DOCTYPE or ENTITY declaration is refused/);
    assert.equal(refusedXml.counts.events, 0);
    const records = Array.from({ length: 50_000 }, (_, i) => `<Record id="${i}" when="2024-01-05T02:00:00Z"><Action>Run</Action></Record>`).join("");
    await put(cwd, "inputs/many.xml", `<Audit>${records}</Audit>`);
    const started = Date.now();
    const many = body(await asJob(AUDIT, cwd, { path: "inputs/many.xml", format: "declared_xml", record_tag: "Record", mapping: { time: "@when", action: "Action", object: "@id" }, limit: 5 }));
    assert.ok(Date.now() - started < 60_000);
    assert.equal(many.counts.events, 50_000);
    assert.equal(many.pages.events.truncated, true);
    assert.equal((await rowsOf(cwd, many, "events")).length, 50_000, "the whole is in the file");
    // a record with more elements than the bound, and a truncated file
    await put(cwd, "inputs/wide.xml", `<Audit><Record>${"<a/>".repeat(20_000)}</Record></Audit>`);
    const wide = json(await tool(AUDIT, cwd, { path: "inputs/wide.xml", format: "declared_xml", record_tag: "Record", mapping: XMAP }));
    assert.match(wide.read_errors.join(" "), /more than 10000 elements/);
    await put(cwd, "inputs/cut.xml", XML.slice(0, XML.length - 40));
    const cut = json(await tool(AUDIT, cwd, { path: "inputs/cut.xml", format: "declared_xml", record_tag: "Record", mapping: XMAP }));
    assert.equal(cut.counts.events >= 1, true, "records before the cut are kept");
    assert.equal(cut.status, "partial");
    assert.match(cut.read_errors.join(" "), /stopped being readable/);
    await put(cwd, "inputs/none.xml", `<Audit><Other/></Audit>`);
    assert.match(json(await tool(AUDIT, cwd, { path: "inputs/none.xml", format: "declared_xml", record_tag: "Record", mapping: XMAP })).read_errors.join(" "), /no <Record> element/);
  });
});

test("a product with no fixtures is refused by name and nothing is guessed; auto recognises only the Proxmox layouts and says what shape the rest has", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/job.csv", "a,b,c\n1,2,3\n");
    for (const product of ["Veeam", "commvault", "Rubrik", "NetBackup", "vCenter", "Some Brand We Never Heard Of"]) {
      const out = refused(await tool(AUDIT, cwd, { path: "inputs/job.csv", product }));
      assert.match(out.error, /unsupported: no fixture of its format exists/);
      assert.match(out.error, /declared_csv, declared_jsonl or declared_xml with a mapping you declare/);
      assert.equal(out.status, "failed");
    }
    assert.match(refused(await tool(AUDIT, cwd, { path: "inputs/job.csv", product: "Veeam" })).error, /a product this tool knows it does not read/);
    assert.match(refused(await tool(AUDIT, cwd, { path: "inputs/job.csv", product: "Zzz" })).error, /this tool does not know it/);
    for (const [name, text, shape, route] of [["j.csv", "a,b,c\n1,2,3\n", "delimited text", "declared_csv"], ["j.json", `{"a":1}\n`, "JSON", "declared_jsonl"], ["j.xml", "<a><b/></a>", "XML", "declared_xml"], ["j.txt", "hello world\n", "text", "declared_csv"]] as const) {
      await put(cwd, `inputs/${name}`, text);
      const out = json(await tool(AUDIT, cwd, { path: `inputs/${name}` }));
      assert.equal(out.status, "failed", name);
      assert.equal(out.unrecognised[0].shape, shape, name);
      assert.match(out.unrecognised[0].reason, new RegExp(`format ${route}`), name);
      assert.equal(out.counts.events, 0);
    }
    await put(cwd, "inputs/index", upid({ start: T0, type: "vzdump", end: T0 + 1 }) + "\n");
    assert.equal(body(await tool(AUDIT, cwd, { path: "inputs/index", product: "proxmox" })).counts.events, 1, "the Proxmox layouts are recognised by shape");
    await put(cwd, "inputs/task.log", LOG);
    assert.equal(body(await tool(AUDIT, cwd, { path: "inputs/task.log" })).events[0].category, "backup_job");
  });
});

test("several files are read as the same format with their own source ids; an unreadable one is named and the rest are read", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/i1", upid({ start: T0, type: "vzdump", end: T0 + 1 }) + "\n");
    await put(cwd, "inputs/i2", upid({ start: T0 + 5, type: "qmstart", id: "3", end: T0 + 6 }) + "\n");
    const out = body(await tool(AUDIT, cwd, { paths: ["inputs/i1", "inputs/none", "inputs/i2"] }));
    assert.deepEqual(out.events.map((e: Json) => e.source_id), ["S000001", "S000003"]);
    assert.equal(out.sources[1].state, "unreadable");
    assert.equal(out.status, "partial");
    assert.equal(out.problems.length, 1);
  });
});

test("argument errors are error documents: an unknown format, a bad mapping, a category that does not exist, an offset out of range, a time format that is not one", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/a.csv", "t,a\n1,x\n");
    const base = { path: "inputs/a.csv", format: "declared_csv", mapping: { time: "t", action: "a" } };
    const bad: Json[] = [
      {}, { path: "inputs/a.csv", format: "nope" }, { ...base, mapping: undefined }, { ...base, mapping: { time: "t" } }, { ...base, mapping: { time: "t", action: "a", secret: "x" } },
      { ...base, category_map: { x: "not_a_category" } }, { ...base, result_map: { x: "great" } }, { ...base, time_zone_offset_minutes: 9999 }, { ...base, time_zone_offset_minutes: 1.5 },
      { ...base, time_format: "banana" }, { ...base, delimiter: "ab" }, { ...base, max_line_bytes: 5 }, { ...base, paths: "x" }, { ...base, write_text: "yes" },
      { path: "inputs/a.csv", format: "declared_xml", mapping: { time: "t", action: "a" } },
    ];
    for (const args of bad) {
      const out = refused(await tool(AUDIT, cwd, args));
      assert.equal(out.status, "failed");
      assert.ok(out.error);
    }
  });
});

test("aggregates are bounded: more distinct objects than the cap are counted, not held; the events page is whole in its file; the time budget ends a long read as partial", async () => {
  await withCwd(async (cwd) => {
    const rows = ["t,a,o"];
    for (let i = 0; i < 30_000; i++) rows.push(`2024-01-05T02:00:00Z,run,vm${i}`);
    await put(cwd, "inputs/many.csv", rows.join("\n") + "\n");
    const out = body(await asJob(AUDIT, cwd, { path: "inputs/many.csv", format: "declared_csv", mapping: { time: "t", action: "a", object: "o" }, limit: 3 }));
    assert.equal(out.counts.events, 30_000);
    assert.equal(out.distinct.object.listed, 10_000);
    assert.equal(out.distinct.object.over_cap, 20_000);
    assert.equal((await rowsOf(cwd, out, "events")).length, 30_000);
    const quick = json(await tool(AUDIT, cwd, { path: "inputs/many.csv", format: "declared_csv", mapping: { time: "t", action: "a", object: "o" }, max_seconds: 0.05 }));
    assert.equal(quick.status, "partial");
    assert.match(quick.partial_reasons.join(" "), /max_seconds/);
    assert.ok(quick.counts.events < 30_000);
  });
});

test("names the answer shows are shape-checked: an actor, an object, a host, a result and a job that look like a token, a key or user-info are withheld", async () => {
  await withCwd(async (cwd) => {
    const C = CANARY;
    await put(cwd, "inputs/y.csv", `t,a\n${C.github},run\n${C.aws}${C.hex},run\n`);
    const timeRun = await tool(AUDIT, cwd, { path: "inputs/y.csv", format: "declared_csv", mapping: { time: "t", action: "a" } });
    const timeOut = body(timeRun);
    for (const needle of [C.github, C.aws, C.hex]) assert.equal(timeRun.stdout.includes(needle), false, "a raw time that looks like a token is withheld too");
    assert.match(timeOut.events[0].time_raw, /<(?:token-shaped text withheld \d+ characters|withheld: \d+ bytes, field time_raw)>/);
    await put(cwd, "inputs/x.csv", `t,a,o,u,h,r,j\n2024-01-05T02:00:00Z,run,/srv/${C.aws}/${C.hex},${C.github},host-${C.hex},fail ${C.userinfo}@h,job-${C.aws}\n`);
    const run = await tool(AUDIT, cwd, { path: "inputs/x.csv", format: "declared_csv", mapping: { time: "t", action: "a", object: "o", actor: "u", host: "h", result: "r", job: "j" } });
    const out = body(run);
    const all = await everythingBut(cwd, run.stdout + run.stderr, []);
    for (const needle of [C.github, C.aws, C.hex, "S3cr3tPassw0rd"]) assert.equal(all.includes(needle), false, needle.slice(0, 6));
    assert.ok(out.withheld.strings_changed >= 4);
    assert.match(out.events[0].actor, /<token-shaped text withheld \d+ characters>/);
  });
});

// ---- review fixes: each test below fails on the tool as first proposed ---------------------------------------------------

function noPiece(all: string, secret: string, from = 4): void {
  const low = all.toLowerCase();
  for (let k = from; k + 12 <= secret.length; k++) assert.equal(low.includes(secret.slice(k, k + 12).toLowerCase()), false, `a piece of ${secret.slice(0, 6)}... was shown`);
}

test("a Proxmox Backup Server task index is read: its UPID has one more field (the task counter) and an escaped worker id", async () => {
  await withCwd(async (cwd) => {
    // proxmox-backup's UPID display: UPID:{node}:{pid:08X}:{pstart:08X}:{task_id:08X}:{starttime:08X}:{worker_type}:{worker_id}:{auth_id}:
    // and a task list line is that UPID, then the end time ({:08X}) and the status
    const pbs = (task: number, start: number, type: string, wid: string, end?: number, status?: string): string =>
      `UPID:pbs1:${hex(1192)}:${hex(2141)}:${hex(task)}:${hex(start)}:${type}:${wid}:root@pam:` + (end === undefined ? "" : ` ${hex(end)} ${status}`);
    await put(cwd, "inputs/pbs/archive", [
      pbs(3, T0, "backup", "store1\\x3avm-100", T0 + 60, "OK"),
      pbs(4, T0 + 100, "garbage_collection", "store1", T0 + 400, "WARNINGS: 2"),
      pbs(5, T0 + 500, "prune", "store1\\x3avm-100", T0 + 501, "unable to acquire lock"),
      pbs(6, T0 + 900, "verify", "store1"),
    ].join("\n") + "\n");
    const out = body(await tool(AUDIT, cwd, { path: "inputs/pbs/archive" }));
    assert.equal(out.status, "complete", out.status_basis);
    assert.equal(out.counts.events, 4);
    const ev = out.events;
    assert.deepEqual(ev.map((e: Json) => [e.category, e.result, e.object, e.actor, e.host]), [
      ["backup_job", "ok", "store1:vm/100", "root@pam", "pbs1"], ["retention_gc", "warning", "store1", "root@pam", "pbs1"],
      ["retention_prune", "error", "store1:vm/100", "root@pam", "pbs1"], ["verification", "unknown", "store1", "root@pam", "pbs1"]]);
    assert.equal(ev[0].time_utc, "2023-11-14T22:13:20Z");
    assert.equal(ev[0].task.upid_layout, "proxmox_backup_server");
    assert.equal(ev[0].task.task_counter, 3);
    assert.equal(ev[0].task.worker_id_as_written, "store1\\x3avm-100");
  });
});

test("a declared JSON Lines or XML mapping whose time or action field the records do not have is partial, with the count per field", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/a.jsonl", `{"time":"2024-01-05T02:00:00Z","op":"x","who":null}\n{"time":"2024-01-05T03:00:00Z","op":"y"}\n`);
    let out = body(await tool(AUDIT, cwd, { path: "inputs/a.jsonl", format: "declared_jsonl", mapping: { time: "tmie", action: "opp", actor: "who" } }));
    assert.equal(out.status, "partial");
    assert.match(out.status_basis, /the declared time field \(tmie\) is absent from 2 of 2 record\(s\)/);
    assert.match(out.status_basis, /the declared action field \(opp\) is absent from 2 of 2 record\(s\)/);
    assert.deepEqual(out.declared_fields_absent.absent_by_field, { time: 2, action: 2, actor: 1 }, "null is present; a missing key is absent");
    out = body(await tool(AUDIT, cwd, { path: "inputs/a.jsonl", format: "declared_jsonl", mapping: { time: "time", action: "op", actor: "who" } }));
    assert.equal(out.status, "complete", "a field that is there and null is not absent; an optional field absent does not make it partial");
    await put(cwd, "inputs/a.xml", `<A><R when="2024-01-05T02:00:00Z"><Op>x</Op></R><R><Op>y</Op></R></A>`);
    out = body(await tool(AUDIT, cwd, { path: "inputs/a.xml", format: "declared_xml", record_tag: "R", mapping: { time: "@when", action: "Op" } }));
    assert.equal(out.status, "partial");
    assert.deepEqual(out.declared_fields_absent.absent_by_field, { time: 1 });
  });
});

test("a declared XML record is bounded in bytes: one record of many large children is counted and located, not held, and memory stays small", async () => {
  await withCwd(async (cwd) => {
    const big = "x".repeat(1 << 20);
    await put(cwd, "inputs/big.xml", `<A><R when="2024-01-05T02:00:00Z"><Op>a</Op></R><R when="2024-01-05T03:00:00Z">${`<T>${big}</T>`.repeat(60)}<Op>b</Op></R><R when="2024-01-05T04:00:00Z"><Op>c</Op></R></A>`);
    const wrapper = "import os,sys,resource\npid=os.fork()\nif pid==0:\n os.execvp('python3',['python3',sys.argv[1]])\n_,st,ru=os.wait4(pid,0)\nsys.stderr.write('RSS %d\\n' % ru.ru_maxrss)\nsys.exit(os.waitstatus_to_exitcode(st))\n";
    const run = await new Promise<{ stdout: string; stderr: string }>((resolve) => {
      const child = spawn("python3", ["-c", wrapper, AUDIT], { cwd, env: { ...process.env, AGENT_ID: "s1" } });
      const o: Buffer[] = [], e: Buffer[] = [];
      child.stdout.on("data", (c: Buffer) => o.push(c));
      child.stderr.on("data", (c: Buffer) => e.push(c));
      child.on("close", () => resolve({ stdout: Buffer.concat(o).toString(), stderr: Buffer.concat(e).toString() }));
      child.stdin.end(JSON.stringify({ path: "inputs/big.xml", format: "declared_xml", record_tag: "R", mapping: { time: "@when", action: "Op" } }));
    });
    const out = JSON.parse(run.stdout);
    assert.equal(out.counts.events, 2);
    assert.equal(out.counts.over_line_limit, 1);
    assert.match(out.problem_lines[0].reason, /a record over the reader's budget/);
    assert.equal(out.problem_lines[0].record, 2);
    assert.equal(out.status, "partial");
    const raw = Number(/RSS (\d+)/.exec(run.stderr)?.[1] ?? 0);
    const mb = process.platform === "darwin" ? raw / (1 << 20) : raw / 1024;
    assert.ok(mb < 160, `resident size ${mb.toFixed(0)} MB`);
  });
});

test("a time that does not match its declared format says so in a fixed phrase: no exception text, so neither time_basis nor not_derived_reasons can carry the value", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/t.csv", `t,a\n${CANARY.github},x\n${CANARY.aws},y\n`);
    for (const time_format of ["epoch_seconds", "strptime:%Y-%m-%d", "iso8601"]) {
      const run = await tool(AUDIT, cwd, { path: "inputs/t.csv", format: "declared_csv", mapping: { time: "t", action: "a" }, time_format, limit: 1 });
      const out = body(run);
      for (const reason of Object.keys(out.time.not_derived_reasons)) assert.doesNotMatch(reason, /ghp_|AKIA|could not convert|time data/, reason);
      const all = await everythingBut(cwd, run.stdout + run.stderr, ["inputs/t.csv"]);
      noPiece(all, CANARY.github);
      noPiece(all, CANARY.aws);
    }
  });
});

test("an unmapped action is withheld by shape before it is cut: no piece of a token at the cut is shown", async () => {
  await withCwd(async (cwd) => {
    // the old key was the action cut at 200 characters: 19 characters of the token were left, too short for the shape check
    await put(cwd, "inputs/t.csv", `t,a\n2024-01-05T02:00:00Z,${"x".repeat(180)} ${CANARY.github}\n`);
    const run = await tool(AUDIT, cwd, { path: "inputs/t.csv", format: "declared_csv", mapping: { time: "t", action: "a" } });
    body(run);
    noPiece(run.stdout + run.stderr, CANARY.github);
  });
});
