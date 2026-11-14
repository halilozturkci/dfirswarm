/**
 * virtualization-backup-forensics: backup_audit_normalise reads Proxmox Backup Server task log files (format pbs_task_log).
 *
 * Every fixture is SYNTHETIC and written here from the Proxmox Backup source that writes and reads task logs (proxmox-rest-server, worker_task.rs, the master
 * branch as served by git.proxmox.com, retrieved 2026-11-03): one task's log is the file tasks/<XX>/<UPID>; each line is `<RFC 3339 time>: <message>`; the last
 * line is `TASK OK`, `TASK WARNINGS: <count>`, `TASK ERROR: <message>` or `TASK unknown`. The documentation lists no message texts; the messages here are
 * invented in our own words. None of this was checked against a real export, and the answer says so (provenance.validated_against_real_export is false).
 */
import assert from "node:assert/strict";
import { createReadStream, createWriteStream } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { AUDIT, CANARY, asJob, body, everythingBut, json, put, startDetached, tool, withCwd } from "./pack-virtualization-harness.ts";
import type { Json } from "./pack-virtualization-harness.ts";

const FMT = { format: "pbs_task_log" };

function log(lines: string[], end = true): string {
  return lines.join("\n") + (end ? "\n" : "");
}

const CLEAN = [
  "2024-03-05T02:00:01+01:00: starting garbage collection on store store1",
  "2024-03-05T02:00:02+01:00: Start GC phase1 (mark used chunks)",
  "2024-03-05T02:00:40+01:00: Removed garbage: 1.5 GiB",
  "2024-03-05T02:00:41+01:00: TASK OK",
];

test("a clean task log: each line is an event, times are read from the offset in the line, the result is the closing line's, and the answer carries its provenance", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "in/UPID-gc", log(CLEAN));
    const out = body(await tool(AUDIT, cwd, { path: "in/UPID-gc", ...FMT }));
    assert.equal(out.status, "complete");
    assert.equal(out.parser, "backup_audit_normalise/3");
    assert.equal(out.counts.events, 4);
    assert.deepEqual(out.events.map((e: Json) => e.category), ["retention_gc", "retention_gc", "retention_gc", "task_end"]);
    assert.equal(out.events[0].time_utc, "2024-03-05T01:00:01Z");
    assert.equal(out.events[0].time_raw, "2024-03-05T02:00:01+01:00");
    assert.match(out.events[0].time_basis, /offset written in the value/);
    assert.equal(out.events[0].object, "store1");
    assert.equal(out.events[3].result, "ok");
    assert.equal(out.events[3].action_raw, "TASK OK");
    assert.match(out.events[0].category_basis, /this tool's table/);
    const p = out.provenance.find((x: Json) => x.format === "pbs_task_log");
    assert.equal(p.product, "proxmox_backup_server");
    assert.equal(p.schema_basis, "vendor_documentation");
    assert.equal(p.validated_against_real_export, false);
    assert.match(p.documentation, /retrieved 2026-11-03/);
  });
});

test("every answer carries provenance: the Proxmox VE formats say they come from synthetic fixtures, a declared mapping says it is the caller's", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "in/index", "UPID:pve1:00000B73:0000D2F0:65537F00:vzdump::root@pam: 65537F78 OK\n");
    const a = body(await tool(AUDIT, cwd, { path: "in/index", format: "pve_task_index" }));
    assert.equal(a.provenance[0].schema_basis, "synthetic_fixtures");
    assert.equal(a.provenance[0].validated_against_real_export, false);
    await put(cwd, "in/x.jsonl", '{"t":"2024-01-01T00:00:00Z","a":"backup"}\n');
    const b = body(await tool(AUDIT, cwd, { path: "in/x.jsonl", format: "declared_jsonl", product: "Example", mapping: { time: "t", action: "a" } }));
    assert.equal(b.provenance[0].schema_basis, "caller_declared_mapping");
    assert.equal(b.provenance[0].validated_against_real_export, false);
  });
});

test("an unknown line is counted and located, never guessed; the answer is partial", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "in/t", log([CLEAN[0], "this line has no time", "05.03.2024 02:00:02: a localised time is not RFC 3339", CLEAN[3]]));
    const out = body(await tool(AUDIT, cwd, { path: "in/t", ...FMT }));
    assert.equal(out.status, "partial");
    assert.equal(out.counts.unparsed, 2);
    assert.equal(out.counts.events, 2);
    assert.deepEqual(out.problem_lines.map((p: Json) => p.line), [2, 3]);
    assert.match(out.problem_lines[0].reason, /RFC 3339/);
  });
});

test("a log with no closing TASK line is partial and says why", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "in/t", log(CLEAN.slice(0, 3)));
    const out = body(await tool(AUDIT, cwd, { path: "in/t", ...FMT }));
    assert.equal(out.status, "partial");
    assert.match(out.partial_reasons.join(" "), /do not end with a TASK result line/);
    assert.equal(out.counts.events, 3);
    await put(cwd, "in/empty", "");
    assert.equal(body(await tool(AUDIT, cwd, { path: "in/empty", ...FMT })).status, "partial");
  });
});

test("a zoneless time is never assumed to be UTC; a declared offset is used and named", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "in/t", log(["2024-03-05T02:00:01: starting garbage collection on store s", "2024-03-05T02:00:09: TASK OK"]));
    const out = body(await tool(AUDIT, cwd, { path: "in/t", ...FMT }));
    assert.equal(out.events[0].time_utc, null);
    assert.equal(out.events[0].time_raw, "2024-03-05T02:00:01");
    assert.match(out.events[0].time_basis, /not assumed to be UTC/);
    assert.equal(out.time.derived, 0);
    const off = body(await tool(AUDIT, cwd, { path: "in/t", ...FMT, time_zone_offset_minutes: 60 }));
    assert.equal(off.events[0].time_utc, "2024-03-05T01:00:01Z");
    assert.match(off.events[0].time_basis, /60 minutes declared by the caller/);
    const z = log(["2024-03-05T01:00:01Z: x", "2024-03-05T01:00:02.250-05:00: TASK OK"]);
    await put(cwd, "in/z", z);
    const zz = body(await tool(AUDIT, cwd, { path: "in/z", ...FMT }));
    assert.equal(zz.events[0].time_utc, "2024-03-05T01:00:01Z");
    assert.equal(zz.events[1].time_utc, "2024-03-05T06:00:02.250Z");
  });
});

test("prune and garbage-collection tasks become retention events, with a category that says it is the tool's table", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "in/prune", log([
      "2024-03-05T03:00:00Z: Starting prune on datastore 'store1', root namespace group \"vm/100\"",
      "2024-03-05T03:00:01Z: remove vm/100/2024-01-01T00:00:00Z",
      "2024-03-05T03:00:02Z: keep vm/100/2024-03-04T00:00:00Z",
      "2024-03-05T03:00:03Z: TASK WARNINGS: 2",
    ]));
    const out = body(await tool(AUDIT, cwd, { path: "in/prune", ...FMT }));
    assert.deepEqual(out.events.map((e: Json) => e.category), ["retention_prune", "retention_remove", "retention_prune", "task_end"]);
    assert.equal(out.events[0].object, "store1");
    assert.equal(out.events[3].result, "warning");
    assert.equal(out.by_category.retention_remove, 1);
    assert.match(out.events[1].category_basis, /keyword/);
  });
});

test("a failed task: the closing TASK ERROR line is an error event, its text is not in the answer", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "in/t", log(["2024-03-05T02:00:01Z: starting new backup on datastore 'store1'", "2024-03-05T02:00:02Z: ERROR: chunk write failed", "2024-03-05T02:00:03Z: TASK ERROR: backup failed: connection reset by peer", "TASK unknown"]));
    const text = (await tool(AUDIT, cwd, { path: "in/t", ...FMT })).stdout;
    const out = JSON.parse(text);
    assert.deepEqual(out.events.map((e: Json) => e.result), ["unknown", "error", "error", "unknown"]);
    assert.equal(out.events[2].category, "task_end");
    assert.equal(out.events[3].time_utc, null, "a bare TASK line carries no time");
    assert.equal(out.events[2].message_chars, "TASK ERROR: backup failed: connection reset by peer".length);
    assert.doesNotMatch(text, /connection reset/);
    assert.equal(out.by_result.error, 2);
  });
});

test("a single 10 MB line is located and not read; the lines around it are", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "in/t", CLEAN[0] + "\n2024-03-05T02:00:02Z: " + "x".repeat(10 << 20) + "\n" + CLEAN[3] + "\n");
    const out = body(await tool(AUDIT, cwd, { path: "in/t", ...FMT }));
    assert.equal(out.counts.over_line_limit, 1);
    assert.equal(out.counts.events, 2);
    assert.equal(out.status, "partial");
    assert.equal(out.problem_lines[0].line, 2);
    assert.ok(out.problem_lines[0].byte_offset > 0);
  });
});

test("NUL bytes and invalid UTF-8 give one JSON answer, no traceback, and the odd lines are events or counted", async () => {
  await withCwd(async (cwd) => {
    const data = Buffer.concat([
      Buffer.from("2024-03-05T02:00:01Z: has a NUL \0 inside\n"),
      Buffer.from("2024-03-05T02:00:02Z: bad bytes \xff\xfe here\n"),
      Buffer.from("\0\0\0\n"),
      Buffer.from("2024-03-05\0T02:00:03Z: TASK OK\n"),
      Buffer.from("2024-03-05T02:00:04Z: TASK OK\n"),
    ], undefined);
    await put(cwd, "in/t", data);
    const run = await tool(AUDIT, cwd, { path: "in/t", ...FMT });
    assert.doesNotMatch(run.stderr, /Traceback/);
    const out = JSON.parse(run.stdout);
    assert.equal(out.counts.events, 3);
    assert.equal(out.counts.unparsed, 2);
    assert.equal(out.status, "partial");
    assert.equal(out.events[2].result, "ok");
  });
});

async function bigLog(path: string, lines: number): Promise<void> {
  const ws = createWriteStream(path);
  const w = (s: string) => new Promise<void>((r) => (ws.write(s) ? r() : ws.once("drain", () => r())));
  let buf: string[] = [];
  for (let i = 0; i < lines; i++) {
    buf.push(`2024-03-05T02:${String(Math.floor(i / 60) % 60).padStart(2, "0")}:${String(i % 60).padStart(2, "0")}Z: remove vm/100/${i}`);
    if (buf.length === 20000) { await w(buf.join("\n") + "\n"); buf = []; }
  }
  buf.push("2024-03-05T09:00:00Z: TASK OK");
  await w(buf.join("\n") + "\n");
  await new Promise<void>((r) => ws.end(r));
}

test("a file of a million lines is read within max_seconds, every row is on disk, and the inline list is cut at 512 KiB", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "in/x", "");
    await bigLog(join(cwd, "in/big"), 1_000_000);
    const t0 = Date.now();
    const run = await asJob(AUDIT, cwd, { path: "in/big", ...FMT, max_seconds: 30, limit: 100000 });
    const took = (Date.now() - t0) / 1000;
    assert.ok(took < 58, `took ${took}s`);
    const out = json(run);
    assert.ok(["complete", "partial"].includes(out.status));
    // A partial says why. A host that reaches max_seconds first names it in partial_reasons. A host that reads all 1,000,001 lines in time (an
    // idle M3 Max: about 29 s) judges the paging file's strings until the run's cap of characters judged (about 604,000 rows' worth), withholds
    // the 396,236 strings after it by their size, and is partial for that: the boundary names the stop and status_basis says it.
    if (out.status === "complete") assert.equal(out.counts.events, 1_000_001);
    else assert.ok(out.partial_reasons.length > 0 || (typeof out.boundary.stopped_by === "string" && /judging the strings stopped at /.test(out.status_basis)),
      `a partial answer says why: ${out.status_basis}`);
    assert.ok(Buffer.byteLength(run.stdout) < 2_000_000, "the inline list is cut");
    const file = out.pages.events.all_results;
    assert.ok(file, "the whole list is in a file");
    const real = file.replace(/^store\/jobs\/[^/]+\/out\//, "out/");
    let rows = 0;
    for await (const chunk of createReadStream(join(cwd, real))) for (const b of chunk as Buffer) if (b === 10) rows++;
    assert.equal(rows, out.counts.events, "the file holds what the count says");
  });
});

test("a SIGTERM during a long read ends with one JSON answer, partial, exit 143", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "in/x", "");
    await bigLog(join(cwd, "in/big"), 600_000);
    const child = startDetached(AUDIT, cwd, { path: "in/big", ...FMT, max_seconds: 50 }, { JOB_ID: "j000555", OUT: join(cwd, "out") });
    await new Promise((r) => setTimeout(r, 700));
    child.signal("SIGTERM");
    const code = await child.closed;
    const out = JSON.parse(child.stdout());
    if (code === 143) {
      assert.equal(out.status, "partial");
      assert.match(JSON.stringify(out), /SIGTERM/);
    } else {
      assert.equal(code, 0, "the run had already ended");
    }
  });
});

test("canaries in messages, store names and the file name never reach the answer; the message goes to the secret-output text file only", async () => {
  await withCwd(async (cwd) => {
    const secrets = [CANARY.github, CANARY.aws, CANARY.hex, CANARY.userinfo];
    const lines = [
      `2024-03-05T02:00:01Z: starting garbage collection on store ${CANARY.github}`,
      `2024-03-05T02:00:02Z: connecting to https://${CANARY.userinfo}@backup.example.net/repo with token ${CANARY.aws}`,
      `2024-03-05T02:00:03Z: password=${CANARY.hex}`,
      `2024-03-05T02:00:04Z: TASK ERROR: auth failed for ${CANARY.userinfo}`,
    ];
    await put(cwd, `in/${CANARY.aws}-task`, log(lines));
    const run = await asJob(AUDIT, cwd, { path: `in/${CANARY.aws}-task`, ...FMT, write_text: true });
    const out = json(run);
    const answer = run.stdout;
    for (const s of secrets) {
      for (let i = 0; i + 12 <= s.length; i += 4) assert.ok(!answer.includes(s.slice(i, i + 12)), `a window of a canary is in the answer: ${s.slice(0, 4)}...`);
    }
    assert.ok(out.events.length >= 1);
    const files = await everythingBut(cwd, answer, ["in"]);
    assert.ok(files.includes(CANARY.userinfo.split(":")[1]), "the message reaches the text file of the secret-output job");
  });
});

test("format auto does not recognise a timestamped log and names pbs_task_log in the reason", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "in/t", log(CLEAN));
    const out = json(await tool(AUDIT, cwd, { path: "in/t" }));
    assert.equal(out.unrecognised.length, 1);
    assert.match(out.unrecognised[0].reason, /pbs_task_log/);
    assert.equal(out.counts.events, 0);
  });
});
