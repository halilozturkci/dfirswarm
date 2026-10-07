/**
 * The Linux pack: utmp_parse, against glibc's struct utmp (384 bytes: type at 0x00, pid at 0x04, line at 0x08,
 * id at 0x28, user at 0x2c, host at 0x4c, exit at 0x14c, session at 0x150, tv_sec at 0x154, tv_usec at 0x158,
 * ut_addr_v6 at 0x15c, 20 unused bytes) and struct lastlog (a 32-bit or a 64-bit time, line[32], host[256]:
 * 292 or 296 bytes, indexed by UID).
 * Every fixture is built by the test from the format's own layout, never from a tool's output.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmod, mkdir, readFile, stat, truncate, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { IS_ROOT, UTMP, asJob, body, refused, rowsOf, tool, withCwd } from "./linux-pack-harness.ts";

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

test("utmp_parse refuses a SQLite accounting database and points at the SQLite tools", async () => {
  await withCwd(async (cwd) => {
    const header = Buffer.concat([Buffer.from("SQLite format 3\0", "latin1"), Buffer.alloc(4096 - 16)]);
    await writeFile(join(cwd, "work", "wtmpdb.db"), header);
    const out = refused(await tool(UTMP, cwd, { path: "work/wtmpdb.db" }));
    assert.match(out.error, /SQLite/);
    assert.match(out.error, /sqlite_query/);
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
    const probe = body(await tool(UTMP, cwd, { path: "work/btmp", user: "^BTMP" }));
    assert.equal(probe.record_count, 0, "a filter on text the answer withholds is an oracle on it");
    assert.equal(probe.filter_touched_withheld_text, false);
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
      const run = await tool(UTMP, cwd, { path: "work/bt", write_text: true }, { JOB_ID: "j9", OUT: join(cwd, "ro", "sub") });
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
