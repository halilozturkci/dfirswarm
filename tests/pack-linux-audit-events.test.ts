/**
 * The Linux pack: audit_events, against the audit log's record format (audit.log(5)): one line per record,
 * `type=<TYPE> msg=audit(<seconds>.<milliseconds>:<serial>): <key=value ...>`, a value that has a space or a control character written as
 * hexadecimal text, PROCTITLE as the hexadecimal text of argv with a NUL between the arguments, EXECVE's aK= and its split form
 * aK_len= with aK[0]=, the optional node= prefix, and the ENRICHED format's 0x1d separator.
 * Every fixture is built by the test from that layout, never from the tool's output.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdir, readFile, readdir, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { gzipSync } from "node:zlib";
import { TOOLS, asJob as plainJob, body, filesUnder, gone, pidFile, put as putAt, refused, rowsOf, startDetached, tool, withCwd } from "./linux-pack-harness.ts";
import type { Json } from "./linux-pack-harness.ts";

const AUDIT = join(TOOLS, "audit_events", "run.py");
/** The tool as a secret-output job runs it: the harness puts SECRET_OUTPUT=1 in the environment of such a job's process. `plainJob` is a job that is not. */
const asJob = (cwd: string, args: unknown, env: Record<string, string> = {}, outName = "out"): ReturnType<typeof plainJob> =>
  plainJob(AUDIT, cwd, args, undefined, { SECRET_OUTPUT: "1", ...env }, outName);

const T0 = 1_700_000_000;
const hex = (text: string | Buffer): string => Buffer.from(text).toString("hex").toUpperCase();
const rec = (type: string, sec: number, serial: number, rest: string, o: { frac?: string; node?: string } = {}): string =>
  `${o.node ? `node=${o.node} ` : ""}type=${type} msg=audit(${sec}.${o.frac ?? "123"}:${serial}): ${rest}`;
const SYS = "arch=c000003e syscall=59 success=yes exit=0 a0=55d0 a1=55d1 a2=55d2 a3=0 items=2 ppid=100 pid=101 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3";
const SYS0 = SYS.replace("items=2 ", "items=0 ");
const ls = (...l: string[]): string => l.join("\n") + "\n";

async function put(cwd: string, rel: string, data: string | Buffer): Promise<void> {
  await mkdir(join(cwd, "work", rel, ".."), { recursive: true });
  await writeFile(join(cwd, "work", rel), data);
}

async function events(cwd: string, out: Json): Promise<Json[]> {
  return rowsOf(cwd, out, "events");
}

async function everything(cwd: string): Promise<string> {
  const parts: string[] = [];
  for (const rel of await filesUnder(join(cwd, "out"))) {
    if (rel === "audit-text.jsonl") continue;
    parts.push(await readFile(join(cwd, "out", rel), "utf8"));
  }
  return parts.join("\n");
}

test("audit_events groups the records of one event, reads a hex argument and a split EXECVE by length, and flags a missing PATH", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "audit.log", ls(
      rec("SYSCALL", T0, 456, `${SYS} comm="cat" exe="/usr/bin/cat" key="exec"`),
      // a1 is hex text (a space in it), a2 is split into two pieces of 4 and 3 bytes of its 7
      rec("EXECVE", T0, 456, `argc=3 a0="cat" a1=${hex("a b")} a2_len=7 a2[0]="abcd" a2[1]="efg"`),
      rec("CWD", T0, 456, `cwd="/srv/x"`),
      rec("PATH", T0, 456, `item=0 name="/usr/bin/cat" inode=1234 dev=fd:01 mode=0100755 ouid=0 ogid=0 nametype=NORMAL`),
      rec("PROCTITLE", T0, 456, `proctitle=${hex("cat\0a b\0abcdefg")}`),
    ));
    const out = body(await tool(AUDIT, cwd, { paths: ["work/audit.log"] }));
    assert.equal(out.events_total, 1);
    const [e] = await events(cwd, out);
    assert.deepEqual(e.types, ["SYSCALL", "EXECVE", "CWD", "PATH", "PROCTITLE"]);
    assert.equal(e.event, `${T0}.123:456`);
    assert.equal(e.time_raw, `${T0}.123`);
    assert.equal(e.time, "2023-11-14T22:13:20.123Z");
    assert.deepEqual(e.execve.arg_bytes, [3, 3, 7]);
    assert.equal(e.execve.argc, 3);
    assert.equal(e.execve.split_args, 1);
    assert.equal(e.execve.incomplete_args, 0);
    assert.equal(e.execve.hex_args, 1);
    assert.deepEqual(e.proctitle, { bytes: 15, argc: 3, hex: true });
    assert.equal(e.cwd_bytes, 6);
    assert.equal(e.paths[0].name_bytes, 12);
    assert.equal(e.syscall.success, "yes");
    assert.match(e.syscall_success_means, /not the command/);
    // items=2 says two PATH records, the group has one
    assert.deepEqual(e.missing_components.map((m: Json) => m.component), ["PATH"]);
    assert.equal(e.first.line, 1);
    assert.equal(e.last.line, 5);
    assert.equal(out.status, "complete");
    assert.equal(out.second_reader.status, "not_run");
  });
});

test("audit_events says an EXECVE is short of its argc, a split argument is short of its length, and an execve has no EXECVE record", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "audit.log", ls(
      rec("SYSCALL", T0, 1, SYS0),
      rec("EXECVE", T0, 1, `argc=3 a0="ls" a1_len=9 a1[0]="abc"`),
      rec("SYSCALL", T0 + 1, 2, SYS0),
      rec("PROCTITLE", T0 + 1, 2, `proctitle=${hex("ls")}`),
      // aarch64 (c00000b7) execve is 221
      rec("SYSCALL", T0 + 2, 3, `arch=c00000b7 syscall=221 success=yes exit=0 items=0 pid=5 auid=1000 uid=0`),
    ));
    const out = body(await tool(AUDIT, cwd, { paths: ["work/audit.log"] }));
    const [a, b, c] = await events(cwd, out);
    assert.deepEqual(a.missing_components.map((m: Json) => m.component).sort(), ["EXECVE arguments", "EXECVE argument pieces", "PROCTITLE"].sort());
    assert.equal(a.execve.incomplete_args, 1);
    assert.deepEqual(b.missing_components.map((m: Json) => m.component), ["EXECVE"]);
    assert.deepEqual(c.missing_components.map((m: Json) => m.component).sort(), ["EXECVE", "PROCTITLE"]);
  });
});

test("audit_events joins an event split across a rotation boundary, keeps the caller's order, and finds the serial restart, the time that goes back and the missing rotation", async () => {
  await withCwd(async (cwd) => {
    // audit.log.3 (oldest) ends in the middle of event 900; audit.log.1 continues it; audit.log.1 holds a serial restart (a reboot); a clock set back follows.
    await put(cwd, "audit.log.3", ls(
      rec("SYSCALL", T0, 899, SYS),
      rec("SYSCALL", T0 + 10, 900, SYS),
    ));
    await put(cwd, "audit.log.1", ls(
      rec("EXECVE", T0 + 10, 900, `argc=1 a0="x"`),
      rec("PROCTITLE", T0 + 10, 900, `proctitle=${hex("x")}`),
      rec("DAEMON_START", T0 + 20, 1, `op=start ver=3.0 format=enriched auid=4294967295 pid=1 res=success`),
      rec("SYSCALL", T0 + 21, 2, SYS),
      // the clock was set back by 100 s
      rec("SYSCALL", T0 - 80, 3, SYS),
      rec("SYSCALL", T0 - 79, 4, SYS),
      rec("SYSCALL", T0 + 30, 5, SYS),
    ));
    const out = body(await tool(AUDIT, cwd, { paths: ["work/audit.log.3", "work/audit.log.1"] }));
    const all = await events(cwd, out);
    const split = all.find((e) => e.serial === 900) as Json;
    assert.deepEqual(split.types, ["SYSCALL", "EXECVE", "PROCTITLE"]);
    assert.deepEqual(split.files, [0, 1]);
    assert.equal(out.events_total, 7);
    assert.deepEqual(out.serial_resets.shown.map((r: Json) => [r.from_serial, r.to_serial]), [[900, 1]]);
    assert.equal(out.time_regression_runs.total, 1);
    assert.equal(out.time_regression_runs.shown[0].groups, 2);
    assert.ok(out.time_regression_runs.shown[0].backwards_seconds >= 99 && out.time_regression_runs.shown[0].backwards_seconds <= 101);
    assert.deepEqual(out.rotation_inventory.rotation_gaps, [1, 2].filter((n) => n !== 1), "audit.log.2 is the rotation not given");
    assert.equal(out.rotation_inventory.gaps_between_files.length, 1);
    assert.equal(out.lost_and_daemon_records.shown[0].type, "DAEMON_START");
    // the same two files in the wrong order: the second starts before the first ends, and the tool says so
    const wrong = body(await tool(AUDIT, cwd, { paths: ["work/audit.log.1", "work/audit.log.3"] }));
    assert.equal(wrong.rotation_inventory.files_out_of_time_order.length, 1);
  });
});

test("audit_events lists a lost= counter and the daemon's records, and reads ENRICHED and CRLF lines", async () => {
  await withCwd(async (cwd) => {
    const enriched = `${rec("SYSCALL", T0, 7, SYS)}\x1dARCH=x86_64 SYSCALL=execve AUID=alice UID=root GID=root EXE=${hex("secret")}`;
    await put(cwd, "audit.log", `${enriched}\r\n${rec("USER_START", T0 + 1, 8, `pid=1 uid=0 auid=1000 ses=1 msg='op=PAM:session_open acct="alice" res=success'`)}\r\n` +
      ls(rec("CONFIG_CHANGE", T0 + 2, 9, "audit_enabled=1 old=1 lost=17 backlog=3 backlog_limit=8192 res=1")));
    const out = body(await tool(AUDIT, cwd, { paths: ["work/audit.log"] }));
    assert.equal(out.totals.crlf_lines, 2);
    assert.equal(out.totals.enriched_records, 1);
    const [a, b] = await events(cwd, out);
    assert.deepEqual(a.enriched.shown, { ARCH: "x86_64", SYSCALL: "execve", AUID: "alice", UID: "root", GID: "root" });
    assert.equal(a.enriched.other_fields, 1);
    assert.equal(b.records[0].fields.op, "PAM:session_open");
    assert.equal(b.records[0].fields.res, "success");
    assert.equal(b.records[0].withheld_bytes.acct, 5);
    const lost = out.lost_and_daemon_records.shown.find((r: Json) => r.type === "CONFIG_CHANGE");
    assert.equal(lost.lost, "17");
    assert.equal(lost.backlog, "3");
    assert.equal(out.status, "complete");
  });
});

test("audit_events reads a gzip rotation as a stream, and calls a truncated or damaged one partial", async () => {
  await withCwd(async (cwd) => {
    const text = ls(rec("SYSCALL", T0, 1, SYS), rec("SYSCALL", T0 + 1, 2, SYS));
    const gz = gzipSync(Buffer.from(text));
    await put(cwd, "audit.log.2.gz", gz);
    await put(cwd, "audit.log.1", ls(rec("SYSCALL", T0 + 2, 3, SYS)));
    const good = body(await tool(AUDIT, cwd, { paths: ["work/audit.log.2.gz", "work/audit.log.1"] }));
    assert.equal(good.events_total, 3);
    assert.equal(good.status, "complete");
    assert.equal(good.rotation_inventory.files.shown[0].compressed, true);
    // two members one after the other
    await put(cwd, "two.gz", Buffer.concat([gz, gzipSync(Buffer.from(ls(rec("SYSCALL", T0 + 9, 4, SYS))))]));
    assert.equal(body(await tool(AUDIT, cwd, { paths: ["work/two.gz"] })).events_total, 3);
    await put(cwd, "cut.gz", gz.subarray(0, gz.length - 12));
    const cut = body(await tool(AUDIT, cwd, { paths: ["work/cut.gz"] }));
    assert.equal(cut.status, "partial");
    assert.match(cut.rotation_inventory.files.shown[0].error, /gzip/);
    const broken = Buffer.from(gz);
    broken[20] ^= 0xff;
    broken[21] ^= 0xff;
    await put(cwd, "bad.gz", broken);
    const bad = body(await tool(AUDIT, cwd, { paths: ["work/bad.gz"] }));
    assert.equal(bad.status, "partial");
  });
});

test("audit_events locates a 10 MB line and does not parse it, reads NUL bytes and invalid UTF-8, and says the status is partial", async () => {
  await withCwd(async (cwd) => {
    const big = Buffer.alloc(10 * 1024 * 1024, 0x61);
    await put(cwd, "audit.log", Buffer.concat([
      Buffer.from(ls(rec("SYSCALL", T0, 1, SYS))),
      Buffer.from("type=EXECVE msg=audit(1700000000.123:2): argc=1 a0="), big, Buffer.from("\n"),
      Buffer.from(ls(rec("SYSCALL", T0 + 1, 3, SYS))),
      Buffer.from(`type=PATH msg=audit(${T0 + 2}.123:4): item=0 name="a\0b" inode=9\n`),
      Buffer.concat([Buffer.from(`type=PATH msg=audit(${T0 + 3}.123:5): item=0 name="`), Buffer.from([0xff, 0xfe, 0x80]), Buffer.from(`" inode=9\n`)]),
    ]));
    const out = body(await tool(AUDIT, cwd, { paths: ["work/audit.log"] }));
    assert.equal(out.status, "partial");
    assert.equal(out.all_lines_parsed, false);
    assert.equal(out.oversize_lines.total, 1);
    assert.equal(out.oversize_lines.shown[0].line, 2);
    assert.ok(out.oversize_lines.shown[0].bytes > 10 * 1024 * 1024);
    assert.equal(out.events_total, 4);
    assert.equal(out.totals.nul_lines, 1);
    assert.equal(out.totals.bad_utf8_lines, 1);
    assert.equal(out.totals.lines, 5);
    const rows = await events(cwd, out);
    assert.equal(rows.find((r) => r.serial === 4).paths[0].name_bytes, 3);
    assert.equal(rows.find((r) => r.serial === 5).paths[0].name_bytes, 3);
  });
});

test("audit_events never prints a command line, exe, cwd, PATH name, typed account or proctitle, in the answer, the paging files, the receipt, stderr or a path", async () => {
  await withCwd(async (cwd) => {
    const canaries = ["CANARYexecArgQ7x", "CANARYprotitleZ4k", "CANARYexeP9m", "CANARYcwdR2d", "CANARYpathN8v", "CANARYacctT5w", "CANARYcommH3j", "CANARYhostK6b", "CANARYother1c"];
    const [a, p, x, c, n, acct, comm, host, other] = canaries;
    const lines: string[] = [];
    for (let i = 0; i < 150; i++) {
      lines.push(rec("SYSCALL", T0 + i, i + 1, `${SYS} comm="${comm}" exe="/bin/${x}"`));
      lines.push(rec("EXECVE", T0 + i, i + 1, `argc=2 a0="sh" a1="-c ${a}${i}"`));
      lines.push(rec("CWD", T0 + i, i + 1, `cwd="/w/${c}"`));
      lines.push(rec("PATH", T0 + i, i + 1, `item=0 name="/p/${n}" inode=4`));
      lines.push(rec("PATH", T0 + i, i + 1, `item=1 name=${hex(`/p/${n} with space`)} inode=5`));
      lines.push(rec("PROCTITLE", T0 + i, i + 1, `proctitle=${hex(`sh\0-c ${p}`)}`));
      lines.push(rec("USER_LOGIN", T0 + i, i + 1000, `pid=1 uid=0 auid=4294967295 ses=1 msg='op=login acct="${acct}" exe="/usr/sbin/sshd" hostname=${host} addr=${host} terminal=ssh res=failed'`));
      lines.push(rec("TESTREC", T0 + i, i + 3000, `${other}=1 note=${other} fieldx="${other}"`));
    }
    await put(cwd, "audit.log", ls(...lines));
    const secret = await asJob(cwd, { paths: ["work/audit.log"], write_text: true, limit: 20 });
    const res = body(secret);
    assert.equal(res.pages.events.truncated, true);
    assert.equal(res.text.written, 150 * 8);
    const answer = secret.stdout + secret.stderr + (await everything(cwd)) + JSON.stringify(await filesUnder(cwd));
    for (const canary of canaries) {
      assert.ok(!answer.includes(canary), `${canary} is in the answer, a paging file, the receipt, stderr or a path`);
      assert.ok(!answer.includes(hex(canary)), `the hex of ${canary} is in the answer`);
    }
    // a hash of a command line is never written
    assert.doesNotMatch(answer, /[0-9a-f]{64}/);
    // the values are in the sealed text file, whole, and the file is private
    const text = await readFile(join(cwd, "out", "audit-text.jsonl"), "utf8");
    for (const canary of [a, p, x, c, n, acct, comm]) assert.ok(text.includes(canary), `${canary} is in the text file`);
    assert.equal((await stat(join(cwd, "out", "audit-text.jsonl"))).mode & 0o777, 0o600);
    assert.equal(res.text.contains_text_that_may_hold_secrets, true);
    // the answer's length of the withheld fields is the byte length, not the text
    const [first] = await events(cwd, res);
    assert.equal(first.records[0].withheld_bytes.exe, "/bin/".length + x.length);
    assert.equal(first.execve.arg_bytes[1], `-c ${a}0`.length);
  });
});

test("audit_events keeps the full text out of an ordinary call and refuses write_text unless the job was run as secret output, creating nothing", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "audit.log", ls(rec("SYSCALL", T0, 1, SYS)));
    const outside = refused(await tool(AUDIT, cwd, { paths: ["work/audit.log"], write_text: true }));
    assert.match(outside.error, /write_text is refused outside a job/);
    const plain = refused(await plainJob(AUDIT, cwd, { paths: ["work/audit.log"], write_text: true }));
    assert.match(plain.error, /not run as secret output/);
    assert.deepEqual(await filesUnder(join(cwd, "out")), []);
    const ok = body(await asJob(cwd, { paths: ["work/audit.log"], write_text: true }, {}, "out2"));
    assert.equal(ok.text.written, 1);
    // a file already at that name is refused by name
    const again = refused(await asJob(cwd, { paths: ["work/audit.log"], write_text: true }, {}, "out2"));
    assert.match(again.error, /already exists/);
    const manifest = JSON.parse(await readFile(join(TOOLS, "audit_events", "manifest.json"), "utf8"));
    assert.deepEqual(manifest.secret_output, { when_args: ["write_text", "compare_ausearch"] });
    assert.equal(manifest.params.write_text.type, "boolean");
  });
});

test("audit_events names uids from the supplied identity files only, leaves them numeric without, and marks auid 4294967295 unset", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "audit.log", ls(rec("SYSCALL", T0, 1, SYS), rec("SYSCALL", T0 + 1, 2, SYS.replace("auid=1000", "auid=4294967295"))));
    await put(cwd, "passwd", "root:x:0:0::/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\nbroken line\n");
    await put(cwd, "group", "root:x:0:\nstaff:x:50:alice\n");
    const without = body(await tool(AUDIT, cwd, { paths: ["work/audit.log"] }));
    const [n1, n2] = await events(cwd, without);
    assert.deepEqual(n1.identity.auid, { raw: "1000" });
    assert.equal(n2.identity.auid.unset, true);
    assert.match(without.identity.names_from, /numeric/);
    const withMap = body(await tool(AUDIT, cwd, { paths: ["work/audit.log"], identity: ["work/passwd", "work/group"] }));
    const [m1, m2] = await events(cwd, withMap);
    assert.deepEqual(m1.identity.auid, { raw: "1000", names: ["alice"] });
    assert.deepEqual(m1.identity.uid, { raw: "0", names: ["root"] });
    assert.deepEqual(m1.identity.gid, { raw: "0", names: ["root"] });
    assert.equal(m2.identity.auid.unset, true);
    assert.equal(withMap.identity.given[0].malformed_lines, 1);
    assert.match(withMap.identity.names_from, /never read/);
  });
});

test("audit_events filters on what it shows, and the filters agree with an oracle twin that reads the fixture on its own", async () => {
  await withCwd(async (cwd) => {
    const fixture: { type: string; sec: number; serial: number }[] = [];
    const lines: string[] = [];
    const kinds = ["SYSCALL", "USER_LOGIN", "USER_END", "CONFIG_CHANGE", "AVC"];
    for (let i = 0; i < 60; i++) {
      const type = kinds[i % kinds.length];
      fixture.push({ type, sec: T0 + i * 100, serial: i + 1 });
      lines.push(rec(type, T0 + i * 100, i + 1, type === "SYSCALL" ? SYS : "pid=1 uid=0 res=success"));
    }
    await put(cwd, "audit.log", ls(...lines));
    const since = new Date((T0 + 500) * 1000).toISOString();
    const until = "2023-11-14T23:30:00+01:00"; // 22:30:00Z
    const untilSec = Date.parse("2023-11-14T22:30:00Z") / 1000;
    const oracle = (types: string[]): number[] =>
      fixture.filter((f) => f.sec >= T0 + 500 && f.sec < untilSec && (types.length === 0 || types.some((t) => (t.endsWith("*") ? f.type.startsWith(t.slice(0, -1).toUpperCase()) : f.type === t.toUpperCase())))).map((f) => f.serial);
    for (const types of [[], ["SYSCALL"], ["USER_*"], ["syscall", "avc"], ["NOSUCH"]]) {
      const out = body(await tool(AUDIT, cwd, { paths: ["work/audit.log"], types, since, until, limit: 1000 }));
      assert.deepEqual((await events(cwd, out)).map((e) => e.serial), oracle(types), JSON.stringify(types));
      assert.equal(out.events_total, 60);
      assert.equal(out.events_matched, oracle(types).length);
    }
    // a bound without a zone is refused, never read in this machine's zone
    assert.match(refused(await tool(AUDIT, cwd, { paths: ["work/audit.log"], since: "2023-11-14T22:13:20" })).error, /zone/);
    assert.match(refused(await tool(AUDIT, cwd, { paths: ["work/audit.log"], since: "2024-01-01T00:00:00Z", until: "2023-01-01T00:00:00Z" })).error, /before/);
  });
});

test("audit_events answers hostile arguments in JSON and never with a traceback", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "audit.log", ls(rec("SYSCALL", T0, 1, SYS)));
    const cases: unknown[] = [
      {}, [], "x", 7, { paths: "work/audit.log" }, { paths: [] }, { paths: [1] }, { paths: [null] }, { paths: [["a"]] }, { paths: [{}] }, { paths: [""] },
      { paths: ["a\u0000b"] }, { paths: ["\ud800"] }, { paths: ["x".repeat(300)] }, { paths: ["x".repeat(5000)] }, { paths: Array.from({ length: 1001 }, () => "work/audit.log") },
      { paths: ["work/audit.log"], limit: 0 }, { paths: ["work/audit.log"], limit: -1 }, { paths: ["work/audit.log"], limit: 1e30 }, { paths: ["work/audit.log"], limit: "5" },
      { paths: ["work/audit.log"], max_seconds: 0 }, { paths: ["work/audit.log"], max_seconds: 1e400 }, { paths: ["work/audit.log"], max_seconds: "1" }, { paths: ["work/audit.log"], max_seconds: 10 ** 400 },
      { paths: ["work/audit.log"], types: "SYSCALL" }, { paths: ["work/audit.log"], types: [1] }, { paths: ["work/audit.log"], types: ["X".repeat(100)] },
      { paths: ["work/audit.log"], since: 5 }, { paths: ["work/audit.log"], since: "x".repeat(100) }, { paths: ["work/audit.log"], since: "9999-99-99T99:99:99Z" },
      { paths: ["work/audit.log"], identity: "x" }, { paths: ["work/audit.log"], identity: [] }, { paths: ["work/audit.log"], identity: [5] }, { paths: ["work/audit.log"], write_text: "yes" },
      { paths: ["work/audit.log"], identity: Array.from({ length: 9 }, () => "work/audit.log") },
    ];
    for (const args of cases) {
      const run = await tool(AUDIT, cwd, args);
      assert.doesNotMatch(run.stderr, /Traceback/, JSON.stringify(args).slice(0, 80));
      const doc = JSON.parse(run.stdout);
      assert.equal(doc.status, "failed", JSON.stringify(args).slice(0, 80));
      assert.notEqual(run.code, 0);
    }
    // deep nesting in the arguments, and a lone surrogate written as an escape
    const { spawnSync } = await import("node:child_process");
    for (const input of ["[".repeat(100_000) + "]".repeat(100_000), `{"paths": ${"[".repeat(50_000)}${"]".repeat(50_000)}}`, " ", `{"paths": ["work/audit.log"], "types": ["\ud800"]}`]) {
      const run = spawnSync("python3", [AUDIT], { cwd, input, encoding: "utf8", env: { ...process.env, AGENT_ID: "s1" } });
      assert.doesNotMatch(run.stderr, /Traceback/);
      assert.equal(JSON.parse(run.stdout).status === "failed" || run.status === 0, true);
    }
    // a missing file, a directory, a symlink and a pipe
    assert.match(refused(await tool(AUDIT, cwd, { paths: ["work/nope"] })).error, /cannot be read/);
    assert.match(refused(await tool(AUDIT, cwd, { paths: ["work"] })).error, /not a regular file/);
  });
});

test("audit_events refuses a symlink, a fifo and a disk image without opening them, and gives JSON for an unreadable file", async () => {
  await withCwd(async (cwd) => {
    const { symlink } = await import("node:fs/promises");
    const { spawnSync } = await import("node:child_process");
    await put(cwd, "audit.log", ls(rec("SYSCALL", T0, 1, SYS)));
    await symlink("audit.log", join(cwd, "work", "link.log"));
    assert.match(refused(await tool(AUDIT, cwd, { paths: ["work/link.log"] })).error, /symlink/);
    spawnSync("mkfifo", [join(cwd, "work", "pipe.log")]);
    const started = Date.now();
    assert.match(refused(await tool(AUDIT, cwd, { paths: ["work/pipe.log"] })).error, /not a regular file/);
    assert.ok(Date.now() - started < 10_000, "a fifo does not hang the tool");
    await put(cwd, "disk.dd", Buffer.concat([Buffer.from("EVF\x09\x0d\x0a\xff\x00", "latin1"), Buffer.alloc(600)]));
    assert.match(refused(await tool(AUDIT, cwd, { paths: ["work/disk.dd"] })).error, /disk image/);
  });
});

test("audit_events honours max_seconds within two seconds on a large log, and says where it stopped", async () => {
  await withCwd(async (cwd) => {
    const chunk: string[] = [];
    for (let i = 0; i < 20000; i++) chunk.push(rec("SYSCALL", T0 + (i % 5000), i + 1, SYS));
    const part = Buffer.from(ls(...chunk));
    await mkdir(join(cwd, "work"), { recursive: true });
    const parts = Array.from({ length: 60 }, () => part);
    await writeFile(join(cwd, "work", "audit.log"), Buffer.concat(parts));
    const started = Date.now();
    const out = body(await tool(AUDIT, cwd, { paths: ["work/audit.log"], max_seconds: 1, limit: 5 }));
    const took = (Date.now() - started) / 1000;
    assert.ok(took < 3.5, `took ${took}s for max_seconds 1`);
    assert.equal(out.status, "partial");
    assert.equal(out.stopped_because, "max_seconds");
    assert.ok(out.stopped.line > 0);
    assert.equal(out.rotation_inventory.files.shown[0].read, "partial");
  });
});

for (const signal of ["SIGTERM", "SIGINT", "SIGHUP"] as const) {
  test(`audit_events ends on ${signal} with one last word naming the paging file it had begun`, async () => {
    await withCwd(async (cwd) => {
      const chunk: string[] = [];
      for (let i = 0; i < 30000; i++) chunk.push(rec("SYSCALL", T0 + i, i + 1, SYS));
      const part = Buffer.from(ls(...chunk));
      await mkdir(join(cwd, "work"), { recursive: true });
      await writeFile(join(cwd, "work", "audit.log"), Buffer.concat(Array.from({ length: 12 }, () => part)));
      await mkdir(join(cwd, "out", "tool-output"), { recursive: true });
      const run = startDetached(AUDIT, cwd, { paths: ["work/audit.log"], limit: 5 }, { JOB_ID: "j000001", OUT: join(cwd, "out") });
      const until = Date.now() + 60_000;
      for (;;) {
        const names = await readdir(join(cwd, "out", "tool-output")).catch(() => [] as string[]);
        if (names.some((n) => n.startsWith("."))) break;
        if (Date.now() > until) {
          run.killGroup();
          assert.fail("the tool never began a paging file");
        }
        await new Promise((r) => setTimeout(r, 30));
      }
      run.signal(signal);
      const code = await Promise.race([run.closed, new Promise<"late">((r) => setTimeout(() => r("late"), 30_000))]);
      if (code === "late") {
        run.killGroup();
        assert.fail(`the tool ignored ${signal}`);
      }
      const num = { SIGTERM: 15, SIGINT: 2, SIGHUP: 1 }[signal];
      assert.equal(code, 128 + num);
      const docs = run.stdout().trim().split("\n");
      assert.equal(docs.length, 1, "exactly one document");
      const word = JSON.parse(docs[0]);
      assert.equal(word.status, "failed");
      assert.equal(word.stopped_by_signal, num);
      assert.deepEqual((await readdir(join(cwd, "out", "tool-output"))).filter((n) => n.startsWith(".")), []);
      assert.ok(word.paging_files_kept.events, "the last word names the paging file");
    });
  });
}

test("audit_events survives a few hundred mutated records without a traceback and counts what it could not read", async () => {
  await withCwd(async (cwd) => {
    // a seeded generator: the same cases on every run
    let seed = 12345;
    const next = (n: number): number => {
      seed = (seed * 1103515245 + 12345) & 0x7fffffff;
      return seed % n;
    };
    const base = [
      rec("SYSCALL", T0, 1, `${SYS} comm="a b" exe="/x"`), rec("EXECVE", T0, 1, `argc=2 a0="x" a1_len=5 a1[0]="ab" a1[1]="cde"`),
      rec("USER_LOGIN", T0, 2, `pid=1 msg='op=login acct="z" res=failed'`), rec("PROCTITLE", T0, 1, `proctitle=${hex("a\0b")}`),
      `${rec("SYSCALL", T0, 3, SYS)}\x1dARCH=x86_64 SYSCALL=execve`,
    ];
    const alphabet = ["=", " ", "\"", "'", "(", ")", ":", ".", "\x1d", "\0", "\r", "[", "]", "a", "9", "msg=audit(", "type=", "node=", "é", "\ud800"];
    const out: string[] = [];
    for (let i = 0; i < 1000; i++) {
      let line = base[next(base.length)];
      for (let k = 0; k <= next(4); k++) {
        const at = next(line.length + 1);
        const op = next(3);
        if (op === 0) line = line.slice(0, at) + alphabet[next(alphabet.length)] + line.slice(at);
        else if (op === 1) line = line.slice(0, at) + line.slice(at + 1 + next(6));
        else line = line.slice(0, at) + line.slice(at, at + next(40)).repeat(2) + line.slice(at);
      }
      out.push(line);
    }
    await put(cwd, "audit.log", Buffer.from(out.join("\n") + "\n", "utf8"));
    const res = await tool(AUDIT, cwd, { paths: ["work/audit.log"], limit: 5 });
    assert.doesNotMatch(res.stderr, /Traceback/);
    const doc = JSON.parse(res.stdout);
    assert.equal(res.code, 0, res.stdout.slice(0, 300));
    assert.ok(["complete", "partial"].includes(doc.status));
    assert.equal(doc.totals.records + doc.totals.unparsed_lines + doc.totals.blank_lines, doc.totals.lines);
  });
});

test("audit_events does not replace an earlier receipt with a smaller one, and writes only under its output directory", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "audit.log", ls(rec("SYSCALL", T0, 1, SYS)));
    await mkdir(join(cwd, "out"), { recursive: true });
    await writeFile(join(cwd, "out", "receipt.json"), "x".repeat(100_000));
    const out = body(await plainJob(AUDIT, cwd, { paths: ["work/audit.log"] }, undefined, {}));
    assert.equal((await stat(join(cwd, "out", "receipt.json"))).size, 100_000, "the earlier, larger receipt is untouched");
    assert.match(out.receipt, /receipt-[0-9a-f]{8}\.json$/);
    assert.deepEqual((await filesUnder(join(cwd, "out"))).sort(), ["receipt-" + out.receipt.split("receipt-")[1], "receipt.json"].sort());
    const receipt = JSON.parse(await readFile(join(cwd, "out", out.receipt.split("/").at(-1)), "utf8"));
    assert.equal(receipt.events_total, 1);
  });
});

test("audit_events' manifest declares what the script reads, carries the script's sha256 and the version PARSER names", async () => {
  const manifest = JSON.parse(await readFile(join(TOOLS, "audit_events", "manifest.json"), "utf8"));
  const script = await readFile(AUDIT);
  assert.equal(manifest.sha256, createHash("sha256").update(script).digest("hex"));
  assert.match(script.toString("utf8"), new RegExp(`^PARSER = "audit_events/${manifest.version}"$`, "m"));
  assert.match(manifest.description, /`status`.*`status_basis`/);
  for (const key of ["paths", "identity", "types", "since", "until", "limit", "max_seconds", "write_text"]) assert.ok(key in manifest.params, key);
  assert.ok(manifest.timeout_seconds > 240);
  assert.match(String(script.toString("utf8").match(/^MAX_SECONDS = [0-9.]+/m)), /MAX_SECONDS = 240/);
  assert.deepEqual(manifest.use.names, ["audit.log", "audit.log.*"]);
});

test("audit_events reads long hostile lines in linear time, within max_seconds, and counts what it could not parse", async () => {
  await withCwd(async (cwd) => {
    const head = `type=SYSCALL msg=audit(${T0}.123:`;
    const kinds = [
      " a".repeat(500_000), // a million bare tokens: no '=' anywhere
      "a=".repeat(400_000), // keys with empty values
      `x="` + "a".repeat(900_000), // a quote that is never closed
      "k=a".repeat(300_000), // one long value
      " ".repeat(1_000_000), // a long run of spaces
      `proctitle=${"41".repeat(450_000)}`, // a megabyte of hexadecimal text
      `msg='${"a=b ".repeat(200_000)}`, // an inner message that never ends
    ];
    const lines: string[] = [];
    for (let i = 0; i < 70; i++) lines.push(`${head}${i + 1}): ${kinds[i % kinds.length]}`);
    await put(cwd, "audit.log", ls(...lines));
    const started = Date.now();
    const out = body(await tool(AUDIT, cwd, { paths: ["work/audit.log"], max_seconds: 20, limit: 5 }));
    const took = (Date.now() - started) / 1000;
    assert.ok(took < 22, `took ${took}s`);
    assert.equal(out.totals.records, 70);
    assert.ok(["complete", "partial"].includes(out.status));
  });
});

test("audit_events keeps its bounded tables bounded when every record has a type of its own", async () => {
  await withCwd(async (cwd) => {
    const lines: string[] = [];
    for (let i = 0; i < 5000; i++) lines.push(`type=T${i}_${"X".repeat(40)} msg=audit(${T0}.000:${i + 1}): pid=1`);
    const one: string[] = [];
    for (let i = 0; i < 700; i++) one.push(`type=U${i} msg=audit(${T0}.000:99999): pid=1`);
    await put(cwd, "audit.log", ls(...lines, ...one));
    const out = body(await tool(AUDIT, cwd, { paths: ["work/audit.log"], limit: 3 }));
    assert.equal(Object.keys(out.by_type).length, 1000);
    assert.equal(out.by_type_other_records, 5700 - 1000);
    const last = (await events(cwd, out)).at(-1) as Json;
    assert.equal(last.serial, 99999);
    assert.equal(Object.keys(last.type_counts).length, 256);
    assert.equal(last.records.length, 256);
    assert.equal(last.records_not_kept, 700 - 256);
  });
});

// ---- the second reader: the installed ausearch, on a sample, in the tool's own process group (PKG-LIN-12) ---------------------

/** A stand-in ausearch. `mode` decides what it does with the sample (the probe file is always answered); every call is logged beside it. */
async function stub(bin: string, mode: "agree" | "disagree" | "hang" | "flood" | "exit7" | "noprobe" | "noversion"): Promise<void> {
  const sampleBody: Record<string, string> = {
    agree: 'cat "$f"',
    disagree: 'cat "$f"; echo "type=SYSCALL msg=audit(1700000099.001:777): arch=c000003e syscall=2"',
    hang: '( trap "" TERM HUP INT; exec sleep 600 ) & echo $! > "$d/child.pid"; echo $$ > "$d/pid"; wait',
    flood: 'yes "type=SYSCALL msg=audit(1700000099.001:777): arch=c000003e syscall=2"',
    exit7: 'cat "$f"; exit 7',
    noprobe: "exit 0",
    noversion: 'cat "$f"',
  };
  const probe = mode === "noprobe" ? "exit 0" : 'cat "$f"';
  const version = mode === "noversion" ? "exit 3" : 'echo "ausearch version 9.9.9"';
  await putAt(bin, "ausearch", `#!/bin/bash
d="$(dirname "$0")"
echo "$@" >> "$d/argv.log"
case "$1" in --version) ${version}; exit 0;; esac
f="$2"
case "$f" in *probe.log) ${probe};; *) ${sampleBody[mode]};; esac
`, 0o755);
}

const sampleLog = (): string => ls(
  rec("SYSCALL", T0, 1, SYS), rec("EXECVE", T0, 1, `argc=1 a0="x"`), rec("PROCTITLE", T0, 1, `proctitle=${hex("x")}`),
  rec("USER_LOGIN", T0 + 1, 2, `pid=1 uid=0 auid=1000 ses=1 msg='op=login acct="a" res=success'`),
);

test("audit_events compares itself with the installed ausearch on a sample: agree, disagree, and never ausearch's own interpretation", async () => {
  await withCwd(async (cwd, bin) => {
    await put(cwd, "audit.log", sampleLog());
    await stub(bin, "agree");
    const agree = body(await plainJob(AUDIT, cwd, { paths: ["work/audit.log"], compare_ausearch: true }, bin, { SECRET_OUTPUT: "1" }));
    assert.equal(agree.second_reader.status, "agree", JSON.stringify(agree.second_reader));
    assert.equal(agree.second_reader.version, "ausearch version 9.9.9");
    assert.equal(agree.second_reader.contract_confirmed, true);
    assert.deepEqual(agree.second_reader.sample, { file: 0, lines: 4, bytes: (await readFile(join(cwd, "work", "audit.log"))).length, records: 4, events: 2 });
    assert.deepEqual(agree.second_reader.differences, { records_only_here: 0, records_only_in_ausearch: 0, events_only_here: 0, events_only_in_ausearch: 0 });
    // the calls: a version, the probe and the sample, with -if and -r and never -i
    const calls = (await readFile(join(bin, "argv.log"), "utf8")).trim().split("\n");
    assert.equal(calls.length, 3);
    assert.equal(calls[0], "--version");
    assert.match(calls[1], /^-if \S+probe\.log -r$/);
    assert.match(calls[2], /^-if \S+sample\.log -r$/);
    assert.ok(calls.every((c) => !/(^| )-i( |$)/.test(c) && !c.includes("--interpret")), "ausearch is never asked to interpret");
    // the sample copy is gone, and nothing sensitive is left beside the answer
    assert.deepEqual((await readdir(join(cwd, "out"))).filter((n) => n.startsWith(".ausearch-")), []);
    await stub(bin, "disagree");
    const disagree = body(await plainJob(AUDIT, cwd, { paths: ["work/audit.log"], compare_ausearch: true }, bin, { SECRET_OUTPUT: "1" }, "out2"));
    assert.equal(disagree.second_reader.status, "disagree");
    assert.deepEqual(disagree.second_reader.differences, { records_only_here: 0, records_only_in_ausearch: 1, events_only_here: 0, events_only_in_ausearch: 1 });
    assert.doesNotMatch(JSON.stringify(disagree.second_reader), /777|syscall=2/, "the text of a difference is not shown");
    // no name comes from this machine: root is uid 0 here, and the answer has no name for it
    const ev = (await events(cwd, agree))[0];
    assert.deepEqual(ev.identity.uid, { raw: "0" });
  });
});

test("audit_events says not_run when the second reader is not asked for, not installed, wrong, or has no time", async () => {
  await withCwd(async (cwd, bin) => {
    await put(cwd, "audit.log", sampleLog());
    assert.match(body(await tool(AUDIT, cwd, { paths: ["work/audit.log"] })).second_reader.why, /not asked for/);
    for (const [mode, why] of [["noprobe", /file-input contract is not confirmed/], ["exit7", /exit code 7/], ["noversion", /did not print a version/]] as const) {
      await stub(bin, mode);
      const out = body(await plainJob(AUDIT, cwd, { paths: ["work/audit.log"], compare_ausearch: true }, bin, { SECRET_OUTPUT: "1" }, `out-${mode}`));
      assert.equal(out.second_reader.status, "not_run", mode);
      assert.match(out.second_reader.why, why, mode);
    }
    // an empty first file has nothing to sample
    await put(cwd, "empty.log", "");
    await stub(bin, "agree");
    const empty = body(await plainJob(AUDIT, cwd, { paths: ["work/empty.log"], compare_ausearch: true }, bin, { SECRET_OUTPUT: "1" }, "out-empty"));
    assert.match(empty.second_reader.why, /no audit record/);
  });
});

test("audit_events refuses compare_ausearch outside a job and in a job that was not run as secret output, running nothing", async () => {
  await withCwd(async (cwd, bin) => {
    await put(cwd, "audit.log", sampleLog());
    await stub(bin, "agree");
    assert.match(refused(await tool(AUDIT, cwd, { paths: ["work/audit.log"], compare_ausearch: true }, {}, bin)).error, /compare_ausearch is refused outside a job/);
    assert.match(refused(await plainJob(AUDIT, cwd, { paths: ["work/audit.log"], compare_ausearch: true }, bin)).error, /not run as secret output/);
    assert.equal(await stat(join(bin, "argv.log")).then(() => true, () => false), false, "ausearch was never started");
    const manifest = JSON.parse(await readFile(join(TOOLS, "audit_events", "manifest.json"), "utf8"));
    assert.deepEqual(manifest.secret_output, { when_args: ["write_text", "compare_ausearch"] });
    assert.equal(manifest.params.compare_ausearch.type, "boolean");
  });
});

test("audit_events ends a hanging ausearch and the child it forked that ignores SIGTERM, within max_seconds, and a bystander survives", async () => {
  await withCwd(async (cwd, bin) => {
    const { spawn } = await import("node:child_process");
    await put(cwd, "audit.log", sampleLog());
    await stub(bin, "hang");
    const bystander = spawn("sleep", ["300"], { detached: true, stdio: "ignore" });
    bystander.unref();
    try {
      const started = Date.now();
      const out = body(await plainJob(AUDIT, cwd, { paths: ["work/audit.log"], compare_ausearch: true, max_seconds: 20 }, bin, { SECRET_OUTPUT: "1" }));
      const took = (Date.now() - started) / 1000;
      assert.ok(took < 24, `took ${took}s for max_seconds 20`);
      assert.equal(out.second_reader.status, "not_run");
      assert.match(out.second_reader.why, /did not finish within its time/);
      assert.equal(await gone(Number(await readFile(join(bin, "pid"), "utf8")), 5000), true, "ausearch is gone");
      assert.equal(await gone(Number(await readFile(join(bin, "child.pid"), "utf8")), 5000), true, "the child that ignores SIGTERM is gone");
      process.kill(bystander.pid as number, 0);
    } finally {
      process.kill(bystander.pid as number, "SIGKILL");
    }
  });
});

test("audit_events ends an ausearch that floods its output at the cap, and says so", async () => {
  await withCwd(async (cwd, bin) => {
    await put(cwd, "audit.log", sampleLog());
    await stub(bin, "flood");
    const started = Date.now();
    const out = body(await plainJob(AUDIT, cwd, { paths: ["work/audit.log"], compare_ausearch: true, max_seconds: 60 }, bin, { SECRET_OUTPUT: "1" }));
    assert.ok(Date.now() - started < 40_000);
    assert.equal(out.second_reader.status, "not_run");
    assert.match(out.second_reader.why, /wrote more than 33554432 bytes/);
  });
});

test("audit_events ends ausearch and what it started on SIGTERM, with one document, and leaves no process", async () => {
  await withCwd(async (cwd, bin) => {
    await put(cwd, "audit.log", sampleLog());
    await stub(bin, "hang");
    await mkdir(join(cwd, "out"), { recursive: true });
    const run = startDetached(AUDIT, cwd, { paths: ["work/audit.log"], compare_ausearch: true, max_seconds: 60 }, { JOB_ID: "j000009", OUT: join(cwd, "out"), SECRET_OUTPUT: "1" }, bin);
    const pid = await pidFile(join(bin, "pid"));
    const child = await pidFile(join(bin, "child.pid"));
    run.signal("SIGTERM");
    const code = await Promise.race([run.closed, new Promise<"late">((r) => setTimeout(() => r("late"), 30_000))]);
    if (code === "late") {
      run.killGroup();
      assert.fail("the tool ignored SIGTERM");
    }
    assert.equal(code, 143);
    const docs = run.stdout().trim().split("\n");
    assert.equal(docs.length, 1);
    assert.equal(JSON.parse(docs[0]).stopped_by_signal, 15);
    assert.equal(await gone(pid, 5000), true);
    assert.equal(await gone(child, 5000), true);
  });
});

test("audit_events' real ausearch, when it is installed, agrees with this reader on a fixture and the version is recorded", async (t) => {
  const { spawnSync } = await import("node:child_process");
  const probe = spawnSync("ausearch", ["--version"], { encoding: "utf8" });
  if (probe.error || probe.status !== 0) {
    t.skip("ausearch is not installed on this machine");
    return;
  }
  await withCwd(async (cwd) => {
    await put(cwd, "audit.log", sampleLog());
    const out = body(await plainJob(AUDIT, cwd, { paths: ["work/audit.log"], compare_ausearch: true }, undefined, { SECRET_OUTPUT: "1" }));
    assert.ok(out.second_reader.version, "the installed version is recorded");
    assert.ok(["agree", "disagree", "not_run"].includes(out.second_reader.status));
  });
});
