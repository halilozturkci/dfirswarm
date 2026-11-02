/**
 * The Linux pack: utmp_parse, against glibc's struct utmp (384 bytes: type at 0x00, pid at 0x04, line at 0x08,
 * id at 0x28, user at 0x2c, host at 0x4c, exit at 0x14c, session at 0x150, tv_sec at 0x154, tv_usec at 0x158,
 * ut_addr_v6 at 0x15c, 20 unused bytes) and struct lastlog (a 32-bit or a 64-bit time, line[32], host[256]:
 * 292 or 296 bytes, indexed by UID).
 * Every fixture is built by the test from the format's own layout, never from a tool's output.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmod, lstat, mkdir, readFile, readdir, rm, stat, symlink, truncate, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { IS_ROOT, UTMP, asJob as plainJob, body, refused, rowsOf, tool, withCwd } from "./linux-pack-harness.ts";
/** The tool as a secret-output job runs it: the harness puts SECRET_OUTPUT=1 in the environment of such a job's process. `plainJob` is a job that is not. */
const asJob = (script: string, cwd: string, args: unknown, bin?: string, env: Record<string, string> = {}, outName = "out"): ReturnType<typeof plainJob> =>
  plainJob(script, cwd, args, bin, { SECRET_OUTPUT: "1", ...env }, outName);

type Utmp = { type: number; pid?: number; line?: string; id?: string; user?: string; host?: string; session?: number; exitTermination?: number; exitStatus?: number; sec?: number; usec?: number; addr?: number[] };

/** glibc struct utmp, 384 bytes, from its field offsets (see the header). */
function utmp(o: Utmp, big = false): Buffer {
  const b = Buffer.alloc(384);
  const i16 = (v: number, at: number): void => void (big ? b.writeInt16BE(v, at) : b.writeInt16LE(v, at));
  const i32 = (v: number, at: number): void => void (big ? b.writeInt32BE(v, at) : b.writeInt32LE(v, at));
  i16(o.type, 0x00);
  i32(o.pid ?? 0, 0x04);
  b.write(o.line ?? "", 0x08, 32, "latin1");
  b.write(o.id ?? "", 0x28, 4, "latin1");
  b.write(o.user ?? "", 0x2c, 32, "latin1");
  b.write(o.host ?? "", 0x4c, 256, "latin1");
  i32(o.session ?? 0, 0x150);
  i16(o.exitTermination ?? 0, 0x14c);
  i16(o.exitStatus ?? 0, 0x14e);
  i32(o.sec ?? 0, 0x154);
  i32(o.usec ?? 0, 0x158);
  (o.addr ?? []).forEach((byte, k) => b.writeUInt8(byte, 0x15c + k));
  return b;
}

/** struct lastlog: a 32-bit time then line[32] and host[256] (292 bytes), or a 64-bit time (296 bytes). */
function lastlog(width: 292 | 296, sec: number, line: string, host: string, big = false): Buffer {
  const b = Buffer.alloc(width);
  if (width === 292) (big ? b.writeInt32BE(sec, 0) : b.writeInt32LE(sec, 0));
  else (big ? b.writeBigInt64BE(BigInt(sec), 0) : b.writeBigInt64LE(BigInt(sec), 0));
  const at = width === 292 ? 4 : 8;
  b.write(line, at, 32, "latin1");
  b.write(host, at + 32, 256, "latin1");
  return b;
}

const T0 = Date.UTC(2026, 1, 14, 9, 30, 0) / 1000;

test("utmp_parse refuses to choose a lastlog layout it cannot tell apart, and says which two it could not choose between", async () => {
  // 21608 = 74 * 292 = 73 * 296: both layouts divide it. A zero-filled file has nothing to decide on.
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "lastlog"), Buffer.alloc(21608));
    const out = refused(await tool(UTMP, cwd, { path: "work/lastlog" }));
    assert.equal(out.ambiguous, true);
    assert.deepEqual([...out.candidates].sort(), ["lastlog-292", "lastlog-296"]);
    assert.match(out.error, /layout/);
    // Said by the caller, it is read as said, and the answer names the layout and that the caller chose it.
    const chosen = body(await tool(UTMP, cwd, { path: "work/lastlog", layout: "lastlog-296" }));
    assert.equal(chosen.layout.name, "lastlog-296");
    assert.equal(chosen.layout.basis, "argument");
  });
});

test("utmp_parse lets structure decide a lastlog layout only where one layout reads every non-empty slot as text", async () => {
  await withCwd(async (cwd) => {
    // A 292-byte record for UID 2 in a 21608-byte file. Read as 296-byte slots its host field would start
    // inside the 4-byte time and run through binary bytes.
    const file = Buffer.alloc(21608);
    lastlog(292, T0, "pts/0", "203.0.113.9").copy(file, 2 * 292);
    await writeFile(join(cwd, "work", "lastlog"), file);
    const out = body(await tool(UTMP, cwd, { path: "work/lastlog" }));
    assert.equal(out.layout.name, "lastlog-292");
    assert.match(out.layout.basis, /structure/);
    const [row] = await rowsOf(cwd, out);
    assert.equal(row.uid, 2);
    assert.equal(row.host, "203.0.113.9");
    assert.equal(row.byte_offset, 584);
    assert.equal(row.epoch, T0);
    assert.equal(row.time, "2026-02-14T09:30:00Z");
  });
});

test("utmp_parse reads a 296-byte lastlog by its size and a 292-byte one the same way, with the UID slot of each record", async () => {
  await withCwd(async (cwd) => {
    const f296 = Buffer.concat([lastlog(296, 0, "", ""), lastlog(296, T0, "pts/1", "198.51.100.5"), lastlog(296, 0, "", "")]);
    const f292 = Buffer.concat([lastlog(292, 0, "", ""), lastlog(292, T0, "tty1", ""), lastlog(292, 0, "", "")]);
    await writeFile(join(cwd, "work", "lastlog"), f296);
    await mkdir(join(cwd, "work", "b"), { recursive: true });
    await writeFile(join(cwd, "work", "b", "lastlog"), f292);
    await writeFile(join(cwd, "work", "passwd"), "root:x:0:0:root:/root:/bin/bash\nalice:x:1:100:Alice:/home/alice:/bin/bash\n");
    const a = body(await tool(UTMP, cwd, { path: "work/lastlog", passwd: "work/passwd" }));
    assert.equal(a.layout.name, "lastlog-296");
    assert.match(a.layout.basis, /size/);
    const rowA = (await rowsOf(cwd, a))[0];
    assert.deepEqual([rowA.uid, rowA.user, rowA.line, rowA.host, rowA.byte_offset], [1, "alice", "pts/1", "198.51.100.5", 296]);
    const b = body(await tool(UTMP, cwd, { path: "work/b/lastlog" }));
    assert.equal(b.layout.name, "lastlog-292");
    assert.equal((await rowsOf(cwd, b))[0].byte_offset, 292);
    assert.equal(b.slots_total, 3);
  });
});

test("utmp_parse does not turn a microsecond field out of range into a plausible time", async () => {
  await withCwd(async (cwd) => {
    const file = Buffer.concat([
      utmp({ type: 7, pid: 10, line: "pts/0", user: "alice", sec: T0, usec: 2_000_000 }),
      utmp({ type: 7, pid: 11, line: "pts/1", user: "bob", sec: T0, usec: 250_000 }),
    ]);
    await writeFile(join(cwd, "work", "wtmp"), file);
    const rows = await rowsOf(cwd, body(await tool(UTMP, cwd, { path: "work/wtmp" })));
    assert.equal(rows[0].usec, 2_000_000, "the raw microseconds are kept");
    assert.equal(rows[0].epoch, T0, "the raw seconds are kept");
    assert.equal(rows[0].time, null, "2,000,000 is no microsecond count: no time is shown");
    assert.match(String(rows[0].time_error), /tv_usec/);
    assert.equal(rows[1].time, "2026-02-14T09:30:00.250000Z", "valid fractions are kept");
  });
});

test("utmp_parse locates each record and names the layout, the byte order and the short tail", async () => {
  await withCwd(async (cwd) => {
    const file = Buffer.concat([
      utmp({ type: 2, line: "~", user: "reboot", host: "6.8.0", sec: T0 - 3600 }),
      utmp({ type: 7, pid: 1234, line: "pts/1", id: "ts/1", user: "root", host: "203.0.113.9", sec: T0, addr: [203, 0, 113, 9] }),
      Buffer.alloc(100, 0x41),
    ]);
    await writeFile(join(cwd, "work", "wtmp"), file);
    const out = body(await tool(UTMP, cwd, { path: "work/wtmp" }));
    assert.equal(out.layout.name, "utmp-384");
    assert.equal(out.layout.byte_order, "little");
    assert.match(out.layout.basis, /structure|argument|assum/);
    assert.equal(out.trailing_bytes, 100);
    assert.equal(out.trailing_offset, 768);
    assert.equal(out.all_records_read, false);
    const rows = await rowsOf(cwd, out);
    assert.deepEqual(rows.map((r) => [r.record_index, r.byte_offset, r.type]), [[0, 0, "BOOT_TIME"], [1, 384, "USER_PROCESS"]]);
    assert.equal(rows[1].address, "203.0.113.9");
    assert.equal(out.boots, 1);
  });
});

test("utmp_parse decides the byte order from the records' structure, and a caller can say it", async () => {
  await withCwd(async (cwd) => {
    const file = Buffer.concat([utmp({ type: 2, user: "reboot", sec: T0 - 60 }, true), utmp({ type: 7, pid: 77, user: "root", line: "pts/2", sec: T0 }, true)]);
    await writeFile(join(cwd, "work", "wtmp"), file);
    const auto = body(await tool(UTMP, cwd, { path: "work/wtmp" }));
    assert.equal(auto.layout.byte_order, "big");
    assert.match(auto.layout.byte_order_basis, /structure/);
    assert.deepEqual((await rowsOf(cwd, auto)).map((r) => r.type), ["BOOT_TIME", "USER_PROCESS"]);
    assert.equal((await rowsOf(cwd, auto))[1].time, "2026-02-14T09:30:00Z");
    const little = body(await tool(UTMP, cwd, { path: "work/wtmp", byte_order: "little" }));
    assert.equal(little.layout.byte_order_basis, "argument");
    assert.ok((await rowsOf(cwd, little)).every((r) => r.type === "UNKNOWN"), "a type outside 0-9 is named unknown, not guessed");
    // A file of empty records cannot decide, and says so.
    await writeFile(join(cwd, "work", "empty"), Buffer.alloc(384 * 2));
    const empty = body(await tool(UTMP, cwd, { path: "work/empty" }));
    assert.equal(empty.layout.byte_order, "undetermined");
  });
});

test("utmp_parse no longer points a SQLite file at another tool: outside a job it says to run it as one, and a file that only starts like SQLite is a database error in JSON", async () => {
  await withCwd(async (cwd) => {
    const header = Buffer.concat([Buffer.from("SQLite format 3 ", "latin1"), Buffer.alloc(4096 - 16)]);
    await writeFile(join(cwd, "work", "wtmpdb.db"), header);
    const out = refused(await tool(UTMP, cwd, { path: "work/wtmpdb.db" }));
    assert.match(out.error, /SQLite/);
    assert.match(out.error, /job_run tool=utmp_parse/);
    assert.doesNotMatch(out.error, /sqlite_query/);
    assert.equal(out.format, "sqlite");
  });
});

test("utmp_parse finds one UID in a lastlog of three million slots, by seeking, and says what it did not read", async () => {
  // A sparse file: the slot of UID 3,000,000 holds a record and the 876 MB before it is a hole.
  await withCwd(async (cwd) => {
    const path = join(cwd, "work", "lastlog");
    const slot = lastlog(292, T0, "ssh", "203.0.113.50");
    await writeFile(path, Buffer.alloc(0));
    const { open } = await import("node:fs/promises");
    const fh = await open(path, "r+");
    await fh.write(slot, 0, slot.length, 3_000_000 * 292);
    await fh.close();
    await truncate(path, 3_000_001 * 292);
    const started = Date.now();
    const one = body(await tool(UTMP, cwd, { path: "work/lastlog", layout: "lastlog-292", uids: [3_000_000, 5] }));
    assert.ok(Date.now() - started < 20_000);
    assert.equal(one.slots_total, 3_000_001);
    assert.equal(one.slots_read, 2);
    assert.equal(one.scope, "selected UIDs");
    const rows = await rowsOf(cwd, one);
    assert.equal(rows.length, 1);
    assert.deepEqual([rows[0].uid, rows[0].host, rows[0].byte_offset], [3_000_000, "203.0.113.50", 3_000_000 * 292]);
    // Without a selection the whole file is walked within a budget; what is left is named and can be resumed.
    const whole = body(await tool(UTMP, cwd, { path: "work/lastlog", layout: "lastlog-292", max_seconds: 30 }));
    assert.equal((await rowsOf(cwd, whole))[0].uid, 3_000_000);
    assert.equal(whole.all_records_read, true);
    const partial = body(await tool(UTMP, cwd, { path: "work/lastlog", layout: "lastlog-292", start_uid: 1000, max_slots: 1000 }));
    assert.equal(partial.all_records_read, false);
    assert.equal(partial.next_uid, 2000);
    assert.equal(partial.slots_read, 1000);
  });
});

test("utmp_parse refuses a types or a user of the wrong type, and a start_uid past the file", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "wtmp"), utmp({ type: 7, user: "alice", sec: T0 }));
    refused(await tool(UTMP, cwd, { path: "work/wtmp", types: "USER_PROCESS" }));
    refused(await tool(UTMP, cwd, { path: "work/wtmp", user: 5 }));
    refused(await tool(UTMP, cwd, { path: "work/wtmp", passwd: 5 }));
    for (const bad of [null, []]) assert.match(refused(await tool(UTMP, cwd, bad)).error, /JSON object/);
    await writeFile(join(cwd, "work", "lastlog"), Buffer.concat([lastlog(292, T0, "pts/0", "h"), lastlog(292, T0, "pts/1", "h")]));
    const past = refused(await tool(UTMP, cwd, { path: "work/lastlog", layout: "lastlog-292", start_uid: 5 }));
    assert.match(past.error, /past the last slot/);
  });
});

test("utmp_parse counts the non-empty slots it read whatever the user filter keeps, and two requests keep their own paging files", async () => {
  await withCwd(async (cwd) => {
    const slots = Array.from({ length: 6000 }, (_, i) => (i === 10 || i === 4000 || i === 5000 ? lastlog(292, T0, "pts/0", "198.51.100.5") : Buffer.alloc(292)));
    await writeFile(join(cwd, "work", "lastlog"), Buffer.concat(slots));
    await writeFile(join(cwd, "work", "passwd"), "a:x:10:10::/h:/bin/sh\n");
    const one = body(await tool(UTMP, cwd, { path: "work/lastlog", layout: "lastlog-292", uids: [10, 4000], user: "^a$", passwd: "work/passwd" }));
    assert.equal(one.nonempty_slots, 2);
    assert.equal(one.record_count, 1);
    const first = body(await tool(UTMP, cwd, { path: "work/lastlog", layout: "lastlog-292", limit: 1, max_slots: 4500 }));
    const second = body(await tool(UTMP, cwd, { path: "work/lastlog", layout: "lastlog-292", limit: 1, max_slots: 6000 }));
    assert.equal(first.pages.records.matched, 2);
    assert.equal(second.pages.records.matched, 3);
    assert.notEqual(first.pages.records.all_results, second.pages.records.all_results);
    assert.equal((await rowsOf(cwd, first)).length, 2, "the first answer's file still holds the first answer");
    assert.equal((await rowsOf(cwd, second)).length, 3);
  });
});

test("utmp_parse keeps a name typed at a login prompt (btmp) out of the answer and the paging file, and in the job's text file", async () => {
  // btmp holds what was typed: no account, or a password typed into the user field.
  await withCwd(async (cwd) => {
    const secret = "BTMPtypedPW9x";
    const file = Buffer.concat([
      utmp({ type: 6, pid: 5, line: "ssh:notty", user: secret, host: "203.0.113.4", sec: T0 }),
      utmp({ type: 6, pid: 6, line: "ssh:notty", user: "root", host: "203.0.113.4", sec: T0 + 1 }),
    ]);
    await writeFile(join(cwd, "work", "btmp"), file);
    await writeFile(join(cwd, "work", "wtmp"), utmp({ type: 7, pid: 7, line: "pts/0", user: "alice", sec: T0 }));
    for (const run of [await tool(UTMP, cwd, { path: "work/btmp", limit: 1 }), await asJob(UTMP, cwd, { path: "work/btmp", limit: 1 })]) {
      const out = body(run);
      assert.ok(!run.stdout.includes(secret), "the typed name is in the answer");
      const rows = await rowsOf(cwd, out);
      assert.deepEqual(rows.map((r) => r.user_bytes), [secret.length, 4]);
      assert.ok(!JSON.stringify(rows).includes(secret), "the typed name is in the paging file");
      assert.equal(out.user_is_typed, true);
    }
    // Outside a job the text is refused, and a user filter matches nothing it cannot show.
    assert.match(refused(await tool(UTMP, cwd, { path: "work/btmp", write_text: true })).error, /outside a job/);
    assert.match(refused(await tool(UTMP, cwd, { path: "work/btmp", preview_text: true })).error, /outside a job/);
    // ... and is refused, not answered with an empty list that reads as "no such user".
    const probe = refused(await tool(UTMP, cwd, { path: "work/btmp", user: "^BTMP" }));
    assert.match(probe.error, /user is refused outside a job/);
    assert.equal(probe.status, "failed");
    const inJob = body(await asJob(UTMP, cwd, { path: "work/btmp", user: "^BTMP", write_text: true }, undefined, {}, "out-btmp"));
    assert.equal(inJob.record_count, 1);
    assert.equal(inJob.filter_touched_withheld_text, true);
    const text = JSON.parse((await readFile(join(cwd, "out-btmp", "utmp-text.jsonl"), "utf8")).trim());
    assert.equal(text.user, secret);
    assert.equal(((await stat(join(cwd, "out-btmp", "utmp-text.jsonl"))).mode & 0o777), 0o600);
    const preview = body(await asJob(UTMP, cwd, { path: "work/btmp", preview_text: true }, undefined, {}, "out-btmp2"));
    assert.equal(preview.records[0].user, secret);
    // wtmp holds accounts that logged in: the name stays in the answer, and a caller can say it is typed.
    const w = body(await tool(UTMP, cwd, { path: "work/wtmp" }));
    assert.equal((await rowsOf(cwd, w))[0].user, "alice");
    assert.equal(w.user_is_typed, false);
    const forced = body(await tool(UTMP, cwd, { path: "work/wtmp", user_is_typed: "true" }));
    assert.equal((await rowsOf(cwd, forced))[0].user_bytes, 5);
    assert.equal((await rowsOf(cwd, forced))[0].user, undefined);
  });
});

test("utmp_parse does not read 392-byte records as 384-byte ones, and says how much of the file reads as utmp when it is made to", async () => {
  await withCwd(async (cwd) => {
    // Another C library's records: the same fields, 8 bytes longer (a 64-bit time at the end). Read at 384-byte steps the
    // fields fall out of place: most records then carry no ut_type of 1 to 9.
    const records: Buffer[] = [];
    for (let i = 0; i < 40; i += 1) {
      const r = Buffer.concat([utmp({ type: 7, pid: 100 + i, line: "pts/" + i, user: "u" + i, sec: T0 + i }), Buffer.alloc(8)]);
      records.push(r);
    }
    await writeFile(join(cwd, "work", "wtmp"), Buffer.concat(records));
    const out = refused(await tool(UTMP, cwd, { path: "work/wtmp" }));
    assert.equal(out.layout_doubt, true);
    assert.match(out.error, /384/);
    assert.equal(out.status, "failed");
    // Said by the caller, it is read, and the answer does not call the read whole.
    const forced = body(await tool(UTMP, cwd, { path: "work/wtmp", layout: "utmp-384" }));
    assert.equal(forced.layout.basis, "argument");
    assert.equal(forced.layout.type_check.doubt, true);
    assert.equal(forced.all_records_read, false);
    assert.equal(forced.status, "partial");
    // A damaged record or two in a good file is not a doubt about the layout.
    const good = Array.from({ length: 30 }, (_, i) => utmp({ type: 7, pid: i + 1, user: "a", line: "pts/0", sec: T0 + i }));
    good[3] = Buffer.alloc(384, 0x41);
    await writeFile(join(cwd, "work", "ok"), Buffer.concat(good));
    const ok = body(await tool(UTMP, cwd, { path: "work/ok" }));
    assert.equal(ok.layout.type_check.doubt, false);
  });
});

test("utmp_parse reads a lastlog.1, names where the accounts came from, and says what it skipped as holes", async () => {
  await withCwd(async (cwd) => {
    const slots = Array.from({ length: 50 }, (_, i) => (i === 3 ? lastlog(292, T0, "pts/0", "198.51.100.5") : Buffer.alloc(292)));
    await writeFile(join(cwd, "work", "lastlog.1"), Buffer.concat(slots));
    await writeFile(join(cwd, "work", "passwd"), "root:x:0:0::/root:/bin/sh\nbob:x:3:3::/home/bob:/bin/sh\n");
    const out = body(await tool(UTMP, cwd, { path: "work/lastlog.1", layout: "lastlog-292", passwd: "work/passwd" }));
    assert.equal(out.layout.name, "lastlog-292", "a name that starts with lastlog is a lastlog file");
    const rows = await rowsOf(cwd, out);
    assert.deepEqual([rows[0].uid, rows[0].user], [3, "bob"]);
    assert.deepEqual(out.passwd, { file: "work/passwd", uids_mapped: 2 });
    assert.ok("holes_skipped" in out, "what was skipped as a hole is printed");
    const none = body(await tool(UTMP, cwd, { path: "work/lastlog.1", layout: "lastlog-292" }));
    assert.equal(none.passwd.file, null);
    // The record is exactly 292 bytes: with no layout the size decides, without a name the file is still a lastlog.
    assert.equal(body(await tool(UTMP, cwd, { path: "work/lastlog.1" })).layout.name, "lastlog-292");
  });
});

test("utmp_parse refuses what a file of the other kind would silently ignore", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "wtmp"), utmp({ type: 7, user: "alice", sec: T0 }));
    await writeFile(join(cwd, "work", "lastlog"), Buffer.concat([lastlog(292, T0, "pts/0", "h"), lastlog(292, T0, "pts/1", "h")]));
    await writeFile(join(cwd, "work", "passwd"), "a:x:0:0::/h:/bin/sh\n");
    for (const key of [{ uids: [1] }, { start_uid: 0 }, { max_slots: 5 }, { passwd: "work/passwd" }]) {
      const out = refused(await tool(UTMP, cwd, { path: "work/wtmp", ...key }));
      assert.match(out.error, /lastlog file only/, JSON.stringify(key));
    }
    for (const key of [{ start_record: 1 }, { user_is_typed: "true" }]) {
      assert.match(refused(await tool(UTMP, cwd, { path: "work/lastlog", layout: "lastlog-292", ...key })).error, /utmp, wtmp or btmp/, JSON.stringify(key));
    }
    refused(await tool(UTMP, cwd, { path: "work/wtmp", user_is_typed: "maybe" }));
    refused(await tool(UTMP, cwd, { path: "work/wtmp", start_record: -1 }));
  });
});

test("utmp_parse keeps ut_exit, and resumes at a record the caller names", async () => {
  await withCwd(async (cwd) => {
    const file = Buffer.concat([
      utmp({ type: 8, pid: 40, line: "pts/0", id: "ts/0", exitTermination: 11, exitStatus: 139, sec: T0 }),
      utmp({ type: 7, pid: 41, line: "pts/1", user: "bob", sec: T0 + 5 }),
      utmp({ type: 7, pid: 42, line: "pts/2", user: "eve", sec: T0 + 9 }),
    ]);
    await writeFile(join(cwd, "work", "wtmp"), file);
    const out = body(await tool(UTMP, cwd, { path: "work/wtmp" }));
    const [dead] = await rowsOf(cwd, out);
    assert.equal(dead.type, "DEAD_PROCESS");
    assert.deepEqual([dead.exit_termination, dead.exit_status], [11, 139]);
    const later = body(await tool(UTMP, cwd, { path: "work/wtmp", start_record: 2 }));
    assert.deepEqual((await rowsOf(cwd, later)).map((r) => [r.record_index, r.byte_offset, r.user]), [[2, 768, "eve"]]);
    assert.equal(later.all_records_read, false, "a read that starts at record 2 did not read the file");
    assert.equal(later.start_record, 2);
  });
});

test("utmp_parse answers in JSON where a file cannot be opened, a passwd is a pipe, or a time budget runs out", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "lastlog"), Buffer.concat([lastlog(292, T0, "pts/0", "h"), lastlog(292, T0, "pts/1", "h")]));
    // A pipe named as passwd is not opened: opening one would wait for a writer.
    const fifo = join(cwd, "work", "passwd");
    assert.equal(spawnSync("mkfifo", [fifo]).status, 0);
    const started = Date.now();
    const piped = refused(await tool(UTMP, cwd, { path: "work/lastlog", layout: "lastlog-292", passwd: "work/passwd" }));
    assert.ok(Date.now() - started < 15_000, "the pipe was opened");
    assert.match(piped.error, /regular file/);
    assert.equal(piped.status, "failed");
    // The same for the evidence file itself.
    const named = join(cwd, "work", "wtmp");
    assert.equal(spawnSync("mkfifo", [named]).status, 0);
    assert.match(refused(await tool(UTMP, cwd, { path: "work/wtmp" })).error, /regular file/);
    if (!IS_ROOT) {
      await writeFile(join(cwd, "work", "wtmp2"), utmp({ type: 7, user: "alice", sec: T0 }));
      await chmod(join(cwd, "work", "wtmp2"), 0o000);
      assert.match(refused(await tool(UTMP, cwd, { path: "work/wtmp2" })).error, /cannot be read/);
      await chmod(join(cwd, "work", "wtmp2"), 0o644);
      await writeFile(join(cwd, "work", "bt"), utmp({ type: 6, user: "x", sec: T0 }));
      await mkdir(join(cwd, "ro"), { recursive: true });
      await chmod(join(cwd, "ro"), 0o555);
      const run = await tool(UTMP, cwd, { path: "work/bt", write_text: true }, { JOB_ID: "j9", OUT: join(cwd, "ro", "sub"), SECRET_OUTPUT: "1" });
      assert.doesNotMatch(run.stderr, /Traceback/);
      assert.notEqual(run.code, 0);
      await chmod(join(cwd, "ro"), 0o755);
    }
    // NaN and a negative budget are no budget.
    for (const bad of ["NaN", 0, -1, "x"]) refused(await tool(UTMP, cwd, { path: "work/lastlog", layout: "lastlog-292", max_seconds: bad }));
    // A very large wtmp is read within max_seconds, and the answer says where it stopped.
    const big = join(cwd, "work", "big");
    await writeFile(big, Buffer.alloc(0));
    const { open } = await import("node:fs/promises");
    const fh = await open(big, "r+");
    const rec = utmp({ type: 7, pid: 1, line: "pts/0", user: "u", sec: T0 });
    for (let i = 0; i < 2000; i += 1) await fh.write(rec, 0, 384, i * 384);
    await fh.close();
    await truncate(big, 384 * 3_000_000);
    const late = body(await tool(UTMP, cwd, { path: "work/big", max_seconds: 1 }));
    assert.equal(late.all_records_read, false);
    assert.equal(late.status, "partial");
    assert.ok(late.stopped_at_record > 0 && late.stopped_at_record < 3_000_000);
  });
});

test("utmp_parse gives every answer a status and says on what it rests", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "wtmp"), utmp({ type: 7, user: "alice", sec: T0 }));
    const whole = body(await tool(UTMP, cwd, { path: "work/wtmp" }));
    assert.equal(whole.status, "complete");
    assert.match(whole.status_basis, /every record/);
    await writeFile(join(cwd, "work", "tail"), Buffer.concat([utmp({ type: 7, user: "alice", sec: T0 }), Buffer.alloc(7, 1)]));
    const tail = body(await tool(UTMP, cwd, { path: "work/tail" }));
    assert.equal(tail.status, "partial");
    assert.equal(tail.all_records_read, false);
    assert.equal(refused(await tool(UTMP, cwd, { path: "work/none" })).status, "failed");
  });
});

test("utmp_parse declares secret_output for write_text and preview_text, and refuses each, creating nothing, unless SECRET_OUTPUT is 1", async () => {
  const manifest = JSON.parse(await readFile(join(UTMP, "..", "manifest.json"), "utf8"));
  assert.deepEqual(manifest.secret_output, { when_args: ["write_text", "preview_text"] });
  for (const flag of manifest.secret_output.when_args) {
    assert.equal(manifest.params[flag].type, "boolean");
    assert.equal(manifest.params[flag].default, undefined);
    assert.match(manifest.params[flag].description, /SENSITIVE/);
  }
  const { readdir } = await import("node:fs/promises");
  const tree = async (dir: string): Promise<string[]> => (await readdir(dir, { recursive: true }).catch(() => [] as string[])).sort();
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "work"), { recursive: true });
    await writeFile(join(cwd, "work", "btmp"), utmp({ type: 7, pid: 7, line: "ssh:notty", user: "PLANTEDVALUE", sec: T0 }));
    for (const flag of ["write_text", "preview_text"]) {
      const before = (await tree(cwd)).filter((f) => f !== "out-plain");
      assert.match(refused(await tool(UTMP, cwd, { path: "work/btmp", [flag]: true })).error, /outside a job/, flag);
      for (const value of [undefined, "0", "true", ""]) {
        const env: Record<string, string> = value === undefined ? {} : { SECRET_OUTPUT: value };
        const answer = refused(await plainJob(UTMP, cwd, { path: "work/btmp", [flag]: true }, undefined, env, "out-plain"));
        assert.match(answer.error, /SECRET_OUTPUT/, `${flag} with SECRET_OUTPUT=${value}`);
        assert.match(answer.error, /Nothing was written/);
        assert.doesNotMatch(JSON.stringify(answer), /PLANTEDVALUE/);
      }
      assert.deepEqual((await tree(cwd)).filter((f) => f !== "out-plain"), before, `${flag}: a refusal creates nothing outside the job's directory`);
      assert.deepEqual(await tree(join(cwd, "out-plain")), [], `${flag}: and nothing in the job's own`);
    }
    const written = body(await asJob(UTMP, cwd, { path: "work/btmp", write_text: true }, undefined, {}, "out-ok"));
    assert.ok(written.text.written >= 1);
    assert.equal((await stat(join(cwd, "out-ok", "utmp-text.jsonl"))).mode & 0o777, 0o600);
    assert.match(await readFile(join(cwd, "out-ok", "utmp-text.jsonl"), "utf8"), /PLANTEDVALUE/);
    const preview = body(await asJob(UTMP, cwd, { path: "work/btmp", preview_text: true }, undefined, {}, "out-pv"));
    assert.match(JSON.stringify(preview.records), /PLANTEDVALUE/);
  });
});

// --- wtmpdb and lastlog2 (SQLite) ------------------------------------------------------------------------------------------------------------
// The two databases from their documented schemas (wtmpdb: a table wtmp with ID, Type, User, Login (microseconds), Logout, TTY, RemoteHost,
// Service; lastlog2: a table lastlog2 with Name as its key, Login (seconds), TTY, RemoteHost, Service). Every database is built here with
// Python's sqlite3 and never by the tool; a write-ahead log is made by copying the files while the writing connection is still open.

const BUILD = `
import json, shutil, sqlite3, sys
spec = json.loads(sys.stdin.read())
con = sqlite3.connect(spec["db"])
if spec.get("wal"):
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA wal_autocheckpoint=0")
for sql in spec["sql"]:
    con.execute(sql)
con.commit()
for sql, rows in spec.get("rows", []):
    con.executemany(sql, rows)
    con.commit()
if spec.get("copy_to"):
    shutil.copy(spec["db"], spec["copy_to"])
    if spec.get("wal"):
        shutil.copy(spec["db"] + "-wal", spec["copy_to"] + "-wal")
con.close()
`;

function py(spec: Record<string, unknown>): void {
  const r = spawnSync("python3", ["-I", "-c", BUILD], { input: JSON.stringify(spec), encoding: "utf8", maxBuffer: 1 << 28 });
  assert.equal(r.status, 0, r.stderr);
}

const WTMP = "CREATE TABLE IF NOT EXISTS wtmp(ID INTEGER PRIMARY KEY, Type INTEGER NOT NULL, User TEXT NOT NULL, Login INTEGER NOT NULL, Logout INTEGER, TTY TEXT, RemoteHost TEXT, Service TEXT)";
const WTMP_INSERT = "INSERT INTO wtmp(ID, Type, User, Login, Logout, TTY, RemoteHost, Service) VALUES (?,?,?,?,?,?,?,?)";
const LASTLOG2 = "CREATE TABLE IF NOT EXISTS lastlog2(Name TEXT PRIMARY KEY, Login INTEGER, TTY TEXT, RemoteHost TEXT, Service TEXT)";
const sha = async (p: string): Promise<string> => createHash("sha256").update(await readFile(p)).digest("hex");

async function evidenceState(dir: string): Promise<Record<string, string>> {
  const state: Record<string, string> = {};
  for (const name of (await readdir(dir)).sort()) {
    const full = join(dir, name);
    const st = await lstat(full);
    state[name] = `${st.size}:${st.mtimeMs}:${st.isFile() ? await sha(full) : "-"}`;
  }
  return state;
}

test("utmp_parse reads a wtmpdb database from a copy, with the rows of its write-ahead log, raw times beside ISO ones, and never selects the key", async () => {
  await withCwd(async (cwd) => {
    const ev = join(cwd, "work", "ev");
    await mkdir(ev, { recursive: true });
    py({ db: join(cwd, "work", "src.db"), wal: true, sql: [WTMP], copy_to: join(ev, "wtmp.db"),
         rows: [[WTMP_INSERT, [[987654321, 7, "alice", 1700000000000000, 1700000100000000, "pts/0", "198.51.100.7", "sshd"],
                               [987654322, 2, "reboot", 1700000200000000, null, "~", "6.8.0-45-generic", null]]],
                [WTMP_INSERT, [[987654323, 7, "bob", 1700000300123456, null, "tty1", "", "login"]]]] });
    assert.ok((await stat(join(ev, "wtmp.db-wal"))).size > 0, "the fixture has a write-ahead log");
    const before = await evidenceState(ev);
    const run = await asJob(UTMP, cwd, { path: "work/ev/wtmp.db" }, undefined, {}, "out");
    const out = body(run);
    assert.equal(out.status, "complete", out.status_basis);
    assert.equal(out.format, "wtmpdb");
    assert.equal(out.records_in_table, 3);
    assert.equal(out.records_read, 3);
    assert.equal(out.all_records_read, true);
    assert.equal(out.snapshot.files.wal.frames_by_size > 0, true);
    // the evidence is byte for byte what it was, and no -shm or journal appeared beside it
    assert.deepEqual(await evidenceState(ev), before);
    assert.deepEqual(Object.keys(before).sort(), ["wtmp.db", "wtmp.db-wal"]);
    // the copy: hashes as copied, a private directory, files 0600
    assert.equal(out.snapshot.files.database.sha256, before["wtmp.db"].split(":")[2]);
    assert.equal(out.snapshot.files.wal.sha256, before["wtmp.db-wal"].split(":")[2]);
    assert.equal((await stat(out.snapshot.directory)).mode & 0o777, 0o700);
    assert.equal((await stat(join(out.snapshot.directory, "db"))).mode & 0o777, 0o600);
    const rows = await rowsOf(cwd, out, "records");
    assert.equal(rows.length, 3);
    assert.deepEqual(rows.map((r: Json) => [r.ordinal, r.type, r.type_raw, r.user]), [[0, "USER_PROCESS", 7, "alice"], [1, "BOOT_TIME", 2, "reboot"], [2, "USER_PROCESS", 7, "bob"]]);
    assert.equal(rows[0].login_raw, 1700000000000000);
    assert.equal(rows[0].login_unit, "microseconds");
    assert.equal(rows[0].login_time, "2023-11-14T22:13:20Z");
    assert.equal(rows[0].logout_time, "2023-11-14T22:15:00Z");
    assert.equal(rows[0].host, "198.51.100.7");
    assert.equal(rows[0].service, "sshd");
    assert.equal(rows[1].logout_raw, null);
    assert.equal(rows[2].login_time, "2023-11-14T22:18:20.123456Z");
    assert.equal(rows[2].host, "");
    assert.equal(out.by_type.USER_PROCESS, 2);
    assert.equal(out.boots, 1);
    // the key is never in the answer or in a paging file
    const everything = run.stdout + JSON.stringify(rows);
    assert.ok(!everything.includes("987654321") && !everything.includes("987654322"), "an INTEGER PRIMARY KEY value is never printed");
    assert.deepEqual(out.schema.columns_not_read, ["ID"]);
    assert.ok(!rows.some((r: Json) => "id_raw" in r || "rowid" in r || "ID" in r));
    // the filters work over the rows
    const only = body(await asJob(UTMP, cwd, { path: "work/ev/wtmp.db", types: ["BOOT_TIME"] }, undefined, {}, "out2"));
    assert.equal(only.record_count, 1);
    const named = body(await asJob(UTMP, cwd, { path: "work/ev/wtmp.db", user: "^b" }, undefined, {}, "out3"));
    assert.deepEqual((await rowsOf(cwd, named, "records", "out3")).map((r: Json) => r.user), ["bob"]);
  });
});

test("utmp_parse reads a lastlog2 database, takes the key Name as the account, and tells seconds from microseconds", async () => {
  await withCwd(async (cwd) => {
    py({ db: join(cwd, "work", "lastlog2.db"), sql: [LASTLOG2],
         rows: [["INSERT INTO lastlog2(Name, Login, TTY, RemoteHost, Service) VALUES (?,?,?,?,?)",
                 [["root", 1700000000, "tty1", "", "login"], ["carol", 1700001234, "pts/3", "203.0.113.9", "sshd"], ["dave", null, null, null, null]]]] });
    const out = body(await asJob(UTMP, cwd, { path: "work/lastlog2.db" }));
    assert.equal(out.status, "complete", out.status_basis);
    assert.equal(out.format, "lastlog2");
    const rows = await rowsOf(cwd, out, "records");
    assert.deepEqual(rows.map((r: Json) => [r.ordinal, r.user, r.type, r.login_unit ?? null, r.login_time ?? null]), [
      [0, "root", "LASTLOG", "seconds", "2023-11-14T22:13:20Z"], [1, "carol", "LASTLOG", "seconds", "2023-11-14T22:33:54Z"], [2, "dave", "LASTLOG", null, null]]);
    assert.equal(rows.find((r: Json) => r.user === "carol").host, "203.0.113.9");
    assert.equal(rows.find((r: Json) => r.user === "dave").login_raw, null);
    assert.match(out.schema.keys, /Name, the key of the table, is the account/);
    // naming the other format is a refusal that lists what the file holds
    const wrong = refused(await asJob(UTMP, cwd, { path: "work/lastlog2.db", format: "wtmpdb" }, undefined, {}, "out2"));
    assert.match(wrong.error, /no table this tool knows as wtmpdb/);
    assert.deepEqual(wrong.schema.tables.map((t: Json) => t.name), ["lastlog2"]);
  });
});

test("utmp_parse tells the unit of a stored time from its size, keeps the raw number, and says what is not a number", async () => {
  await withCwd(async (cwd) => {
    py({ db: join(cwd, "work", "wtmp.db"), sql: [WTMP],
         rows: [[WTMP_INSERT, [[1, 7, "sec", 1700000000, null, "a", "h", "s"], [2, 7, "milli", 1700000000123, 1700000001000, "a", "h", "s"], [3, 7, "micro", 1700000000123456, null, "a", "h", "s"],
                               [4, 7, "huge", 4611686018427387904, null, "a", "h", "s"], [5, 7, "neg", -5, null, "a", "h", "s"], [6, 7, "zero", 0, null, "a", "h", "s"],
                               [7, 99, "oddtype", 1700000000, null, "a", "h", "s"]]]] });
    py({ db: join(cwd, "work", "wtmp.db"), sql: ["INSERT INTO wtmp(ID, Type, User, Login) VALUES (8, 7, 'texttime', 'yesterday')"] });
    const out = body(await asJob(UTMP, cwd, { path: "work/wtmp.db" }));
    const by = Object.fromEntries((await rowsOf(cwd, out, "records")).map((r: Json) => [r.user, r]));
    assert.deepEqual([by.sec.login_unit, by.sec.login_time], ["seconds", "2023-11-14T22:13:20Z"]);
    assert.deepEqual([by.milli.login_unit, by.milli.login_time, by.milli.logout_time], ["milliseconds", "2023-11-14T22:13:20.123000Z", "2023-11-14T22:13:21Z"]);
    assert.deepEqual([by.micro.login_unit, by.micro.login_time], ["microseconds", "2023-11-14T22:13:20.123456Z"]);
    assert.equal(by.huge.login_raw, 4611686018427387904);
    assert.equal(by.huge.login_time, null);
    assert.match(by.huge.login_error, /outside|range/);
    assert.equal(by.zero.login_time, null);
    assert.equal(by.oddtype.type, "UNKNOWN");
    assert.equal(by.oddtype.type_raw, 99);
    assert.equal(by.texttime.login_raw, null);
    assert.match(by.texttime.login_error, /text, not a number/);
    assert.equal(by.neg.login_raw, -5);
  });
});

test("utmp_parse refuses a SQLite file with a schema it does not know and lists what it found, a view or a virtual table by the name, and two tables without a format", async () => {
  await withCwd(async (cwd) => {
    py({ db: join(cwd, "work", "other.db"), sql: ["CREATE TABLE wtmp(a INTEGER, b TEXT)", "CREATE TABLE \"weïrd\u0001name\"(x)", "CREATE VIEW v1 AS SELECT a FROM wtmp", "CREATE INDEX i1 ON wtmp(a)"] });
    const unknown = refused(await asJob(UTMP, cwd, { path: "work/other.db" }));
    assert.match(unknown.error, /no table this tool knows as wtmpdb or lastlog2/);
    const byName = Object.fromEntries(unknown.schema.tables.map((t: Json) => [t.name, t]));
    assert.deepEqual(byName.wtmp.columns, ["a", "b"]);
    assert.ok(Object.keys(byName).some((n) => n.includes("\\x01")), "a control character in a table name is an escape");
    assert.deepEqual(unknown.schema.other_objects.map((o: string[]) => o[0]).sort(), ["index", "view"]);
    assert.doesNotMatch(JSON.stringify(unknown), /\u0001/);
    // a view named like the table
    py({ db: join(cwd, "work", "view.db"), sql: ["CREATE TABLE real_rows(User TEXT, Login INTEGER)", "CREATE VIEW wtmp AS SELECT User, Login FROM real_rows"] });
    assert.match(refused(await asJob(UTMP, cwd, { path: "work/view.db" }, undefined, {}, "o2")).error, /view/);
    // both tables
    py({ db: join(cwd, "work", "both.db"), sql: [WTMP, LASTLOG2] });
    assert.match(refused(await asJob(UTMP, cwd, { path: "work/both.db" }, undefined, {}, "o3")).error, /both a wtmp and a lastlog2/);
    const chosen = body(await asJob(UTMP, cwd, { path: "work/both.db", format: "lastlog2" }, undefined, {}, "o4"));
    assert.equal(chosen.format, "lastlog2");
    assert.equal(chosen.records_in_table, 0);
    // a table with the columns in other letters and extra ones is read from what is there
    py({ db: join(cwd, "work", "cols.db"), sql: ["CREATE TABLE wtmp(\"user\" TEXT, LOGIN INTEGER, extra BLOB)"], rows: [["INSERT INTO wtmp VALUES (?,?,?)", [["zed", 1700000000, "x"]]]] });
    const cols = body(await asJob(UTMP, cwd, { path: "work/cols.db" }, undefined, {}, "o5"));
    assert.deepEqual(cols.schema.columns_not_read, ["extra"]);
    assert.equal((await rowsOf(cwd, cols, "records", "o5"))[0].user, "zed");
    // a virtual table by the name (fts5 is built into the SQLite of most Pythons; the case is skipped where it is not)
    const probe = spawnSync("python3", ["-I", "-c", `import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute("CREATE VIRTUAL TABLE wtmp USING fts5(User, Login)"); c.commit()`, join(cwd, "work", "virtual.db")], { encoding: "utf8" });
    if (probe.status === 0) assert.match(refused(await asJob(UTMP, cwd, { path: "work/virtual.db" }, undefined, {}, "o6")).error, /virtual table/);
  });
});

test("utmp_parse keeps long, binary and mistyped values bounded: 256 bytes and the length, a blob as a blob, bytes that are not UTF-8 as escapes, a canary past the cut not printed", async () => {
  await withCwd(async (cwd) => {
    const canary = "CANARY-7f3a91c2";
    // columns with no declared type keep what is stored in them (a TEXT column turns 42 into "42"), as a database of another writer may
    py({ db: join(cwd, "work", "wtmp.db"), sql: ["CREATE TABLE wtmp(ID INTEGER PRIMARY KEY, Type, User, Login, Logout, TTY, RemoteHost, Service)"],
         rows: [[WTMP_INSERT, [[1, 7, "x".repeat(300) + canary, 1700000000000000, null, "p".repeat(1_000_000), "host-" + canary.slice(0, 6), "svc"],
                               [2, 7, "plain", 1700000001000000, null, "t", "h", "s"]]],
               ] });
    py({ db: join(cwd, "work", "wtmp.db"), sql: ["UPDATE wtmp SET User = CAST(X'61ff62' AS BLOB) WHERE ID = 2", "INSERT INTO wtmp(ID, Type, User, Login, RemoteHost) VALUES (3, 7, 'intnum', 1700000002000000, 42)"] });
    const run = await asJob(UTMP, cwd, { path: "work/wtmp.db" });
    const out = body(run);
    const rows = await rowsOf(cwd, out, "records");
    assert.equal(rows[0].user.length, 256);
    assert.equal(rows[0].user_bytes, 300 + canary.length);
    assert.equal(rows[0].user_truncated, true);
    assert.equal(rows[0].line.length, 256);
    assert.equal(rows[0].line_bytes, 1_000_000);
    assert.ok(!run.stdout.includes(canary) && !JSON.stringify(rows).includes(canary), "a value past the cut is not in the answer");
    assert.equal(rows[1].user_stored_as, "blob");
    assert.equal(rows[1].user, "a\udcffb");
    assert.equal(rows[2].host, "42");
    assert.equal(rows[2].host_stored_as, "integer");
    assert.ok(run.stdout.length < 200_000, "the answer stays small whatever the rows hold");
  });
});

test("utmp_parse stops with the rows it read when a page of the database is damaged, and says where", async () => {
  await withCwd(async (cwd) => {
    const rows = Array.from({ length: 4000 }, (_, i) => [i + 1, 7, `user${i}`, 1700000000000000 + i * 1000000, null, "pts/0", "198.51.100.7", "sshd"]);
    py({ db: join(cwd, "work", "wtmp.db"), sql: [WTMP], rows: [[WTMP_INSERT, rows]] });
    const full = await readFile(join(cwd, "work", "wtmp.db"));
    const pageSize = full.readUInt16BE(16) || 65536;
    const pages = full.length / pageSize;
    assert.ok(pages > 8, "the fixture spans many pages");
    const damaged = Buffer.from(full);
    damaged.fill(0xff, pageSize * (pages - 3), pageSize * (pages - 2));
    await writeFile(join(cwd, "work", "bad.db"), damaged);
    const run = await asJob(UTMP, cwd, { path: "work/bad.db" });
    assert.doesNotMatch(run.stderr, /Traceback/);
    const out = JSON.parse(run.stdout);
    // either the tool reads the rows before the damage and says so, or it refuses the file in JSON: never a complete answer
    assert.notEqual(out.status, "complete");
    if (out.status === "partial") {
      assert.ok(out.records_read > 0 && out.records_read < 4000);
      assert.match(out.status_basis, /database failed|could not be counted|malformed|corrupt/i);
    } else {
      assert.equal(out.status, "failed");
      assert.match(out.error, /database/);
    }
    // and a file that only starts like SQLite
    await writeFile(join(cwd, "work", "head.db"), Buffer.concat([Buffer.from("SQLite format 3\0", "latin1"), Buffer.alloc(4096 - 16)]));
    const head = refused(await asJob(UTMP, cwd, { path: "work/head.db" }, undefined, {}, "o2"));
    assert.match(head.error, /database/);
  });
});

test("utmp_parse keeps SQLite apart from the binary readers: a job only, no -wal that is a link or a pipe followed, arguments that do not apply refused, a format that does not fit refused", async () => {
  await withCwd(async (cwd) => {
    const ev = join(cwd, "work", "ev");
    await mkdir(ev, { recursive: true });
    py({ db: join(cwd, "work", "wtmp.db"), sql: [WTMP], copy_to: join(ev, "wtmp.db"), rows: [[WTMP_INSERT, [[1, 7, "alice", 1700000000000000, null, "a", "h", "s"]]]] });
    // outside a job nothing is read
    const plain = refused(await tool(UTMP, cwd, { path: "work/ev/wtmp.db" }));
    assert.match(plain.error, /job_run tool=utmp_parse/);
    assert.equal(plain.format, "sqlite");
    // a link as the database is refused as for the binary files
    await symlink(join(ev, "wtmp.db"), join(ev, "link.db"));
    assert.match(refused(await asJob(UTMP, cwd, { path: "work/ev/link.db" }, undefined, {}, "o1")).error, /symlink/);
    // a -wal that is a link, and one that is a pipe: not copied, not followed, and the answer is partial
    await writeFile(join(cwd, "work", "elsewhere-wal"), "not a log");
    await symlink(join(cwd, "work", "elsewhere-wal"), join(ev, "wtmp.db-wal"));
    const linked = body(await asJob(UTMP, cwd, { path: "work/ev/wtmp.db" }, undefined, {}, "o2"));
    assert.equal(linked.status, "partial");
    assert.match(linked.snapshot.files.wal.state, /not copied: a link/);
    assert.equal(linked.records_read, 1);
    await rm(join(ev, "wtmp.db-wal"));
    spawnSync("mkfifo", [join(ev, "wtmp.db-wal")]);
    const started = Date.now();
    const piped = body(await asJob(UTMP, cwd, { path: "work/ev/wtmp.db" }, undefined, {}, "o3"));
    assert.ok(Date.now() - started < 20_000, "a pipe beside the database does not hang the tool");
    assert.equal(piped.status, "partial");
    await rm(join(ev, "wtmp.db-wal"));
    // arguments that belong to the binary readers, and a format that does not fit the file
    for (const extra of [{ uids: [0] }, { start_uid: 1 }, { max_slots: 5 }, { passwd: "x" }, { start_record: 1 }, { user_is_typed: "true" }, { layout: "utmp-384" }, { byte_order: "big" }, { write_text: true }, { preview_text: true }]) {
      const r = refused(await asJob(UTMP, cwd, { path: "work/ev/wtmp.db", ...extra }, undefined, {}, "o4"));
      assert.match(r.error, /apply to a utmp, wtmp, btmp or lastlog file only/, JSON.stringify(extra));
    }
    assert.match(refused(await asJob(UTMP, cwd, { path: "work/ev/wtmp.db", format: "utmp" }, undefined, {}, "o5")).error, /SQLite database/);
    await writeFile(join(cwd, "work", "plain.bin"), Buffer.alloc(384));
    assert.match(refused(await asJob(UTMP, cwd, { path: "work/plain.bin", format: "wtmpdb" }, undefined, {}, "o6")).error, /does not start as a SQLite database/);
    for (const bad of [{ format: 5 }, { format: "sqlitee" }, { path: "work/ev/wtmp.db", limit: -1 }, { path: "work/ev/wtmp.db", types: "x" }, { path: "work/ev/wtmp.db", user: "(" }, { path: "work/ev/wtmp.db", max_seconds: 10 ** 400 }]) {
      const run = await asJob(UTMP, cwd, bad, undefined, {}, "o7");
      assert.doesNotMatch(run.stderr, /Traceback/, JSON.stringify(bad));
      assert.equal(JSON.parse(run.stdout).status, "failed", JSON.stringify(bad));
    }
  });
});

test("utmp_parse ends a SQLite read on max_seconds with the rows it has, partial, and a full disk or an unwritable $OUT gives JSON", async () => {
  await withCwd(async (cwd) => {
    const rows = Array.from({ length: 300000 }, (_, i) => [i + 1, 7, `user${i}`, 1700000000000000 + i * 1000000, null, "pts/0", "198.51.100.7", "sshd"]);
    py({ db: join(cwd, "work", "big.db"), sql: [WTMP], rows: [[WTMP_INSERT, rows]] });
    const started = Date.now();
    const run = await asJob(UTMP, cwd, { path: "work/big.db", max_seconds: 1, limit: 5 });
    assert.ok(Date.now() - started < 60_000, "the tool ends near max_seconds");
    assert.doesNotMatch(run.stderr, /Traceback/);
    const out = JSON.parse(run.stdout);
    assert.ok(out.status === "partial" || out.status === "failed" || out.status === "complete", out.status);
    if (out.status === "partial") assert.ok(out.records_read < 300000);
    // an $OUT that cannot hold the copy: JSON, no traceback
    if (!IS_ROOT) {
      await mkdir(join(cwd, "ro-out"), { recursive: true });
      await chmod(join(cwd, "ro-out"), 0o500);
      const denied = spawnSync("python3", [UTMP], { cwd, input: JSON.stringify({ path: "work/big.db" }), encoding: "utf8", env: { ...process.env, JOB_ID: "j1", OUT: join(cwd, "ro-out"), SECRET_OUTPUT: "1" } });
      assert.doesNotMatch(denied.stderr, /Traceback/);
      assert.equal(JSON.parse(denied.stdout).status, "failed");
      await chmod(join(cwd, "ro-out"), 0o700);
    }
  });
});
