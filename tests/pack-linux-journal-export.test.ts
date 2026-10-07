/**
 * The Linux pack: journal_export, against a journalctl stand-in that prints `-o json` entries as systemd's
 * "Journal JSON Format" shows them: every value a string, the cursor `s=..;i=..;b=..;m=..;t=..;x=..`,
 * `__REALTIME_TIMESTAMP` and `__MONOTONIC_TIMESTAMP` in microseconds, a field that is a byte array or null.
 * Every fixture is built by the test from the format's own layout, never from a tool's output.
 *
 * The tools that read command lines, messages or environments follow the secret-safe output pattern of
 * recovery_key_scan (docs/packs.md, "Secrets and sensitive output"): the answer is locators and structured
 * fields, and the text is written only on request, only in a job, only to a file under $OUT. What the answer
 * and the files it names hold is checked here for a planted secret.
 */
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { chmod, mkdir, readFile, readdir, stat, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { IS_ROOT, JOURNAL, asJob, body, everythingBut, exists, filesUnder, lines, refused, rowsOf, tool, withCwd } from "./linux-pack-harness.ts";
import type { Json } from "./linux-pack-harness.ts";

const BOOT_A = "9d6a4f4b7a7e4b2d9b2f0a1e3f4c5d6e";
const BOOT_B = "a1b2c3d4e5f60718293a4b5c6d7e8f90";
const MACHINE = "3f2e1d0c9b8a79685746352413020100";

function entry(seq: number, o: Record<string, string | number[] | null>): string {
  const hex = (n: number): string => n.toString(16);
  const rt = String(1_771_061_400_000_000 + seq * 1_000_000 + 123_456);
  const mono = String(5_000_000 + seq * 1_000_000);
  const boot = (o._BOOT_ID as string) ?? BOOT_A;
  const row: Record<string, unknown> = {
    __CURSOR: `s=739ad463348b4ceca5a9699c3d7d5e1f;i=${hex(0x3a00 + seq)};b=${boot};m=${hex(Number(mono))};t=${hex(Number(rt))};x=1a2b3c4d5e6f${hex(seq)}`,
    __REALTIME_TIMESTAMP: rt,
    __MONOTONIC_TIMESTAMP: mono,
    _BOOT_ID: boot,
    _MACHINE_ID: MACHINE,
    _HOSTNAME: "web01",
    _TRANSPORT: "journal",
    PRIORITY: "6",
    ...o,
  };
  return JSON.stringify(row);
}

/** A journalctl stand-in: prints the file STUB_LINES (or sleeps, or fails), and records its argv in STUB_ARGV. */
async function journalStub(bin: string): Promise<void> {
  const path = join(bin, "journalctl");
  await writeFile(
    path,
    `#!/usr/bin/env python3
import json, os, sys, time
open(os.environ["STUB_ARGV"], "a").write(json.dumps(sys.argv[1:]) + "\\n")
if "--verify" in sys.argv:
    sys.stdout.write(open(os.environ["STUB_VERIFY"]).read())
    sys.stderr.write("stub verify note\\n")
    sys.exit(int(os.environ.get("STUB_VERIFY_EXIT", "0")))
data = open(os.environ["STUB_LINES"], "rb").read()
sys.stdout.buffer.write(data)
sys.stdout.flush()
sys.stderr.write(os.environ.get("STUB_STDERR", ""))
time.sleep(float(os.environ.get("STUB_SLEEP", "0")))
sys.exit(int(os.environ.get("STUB_EXIT", "0")))
`,
  );
  await chmod(path, 0o755);
}

async function journalFixture(cwd: string, bin: string, native: string): Promise<Record<string, string>> {
  await journalStub(bin);
  await mkdir(join(cwd, "work", "journal"), { recursive: true });
  await writeFile(join(cwd, "work", "journal", "system.journal"), Buffer.concat([Buffer.from("LPKSHHRH"), Buffer.alloc(248)]));
  await writeFile(join(cwd, "stub-lines.jsonl"), native);
  return { STUB_LINES: join(cwd, "stub-lines.jsonl"), STUB_ARGV: join(cwd, "stub-argv.txt") };
}

const JOURNAL_SECRET = "hunter2-journal-secret";

function nativeJournal(): string {
  return (
    [
      entry(1, { MESSAGE: "Started Session 1 of user alice.", _PID: "812", _UID: "0", _COMM: "systemd", _EXE: "/usr/lib/systemd/systemd", _CMDLINE: "/sbin/init", _SYSTEMD_UNIT: "session-1.scope", SYSLOG_IDENTIFIER: "systemd" }),
      entry(2, { MESSAGE: `sudo: alice : COMMAND=/usr/bin/mount -o password=${JOURNAL_SECRET} //srv/share /mnt`, _PID: "900", _UID: "1000", _COMM: "sudo", _EXE: "/usr/bin/sudo", _CMDLINE: `sudo mount -o password=${JOURNAL_SECRET} //srv/share /mnt`, SYSLOG_IDENTIFIER: "sudo", _AUDIT_SESSION: "3" }),
      // The wall clock stepped back an hour within the boot: the realtime stamp is lower than the entry before's, the monotonic one higher.
      entry(3, { MESSAGE: "clock stepped", _PID: "1", _UID: "0", __REALTIME_TIMESTAMP: "1771057800000001", _SOURCE_REALTIME_TIMESTAMP: "1771057800000000" }),
      entry(4, { MESSAGE: [104, 105, 0, 255], _PID: "2", _UID: "0", _BOOT_ID: BOOT_B }),
      entry(5, { MESSAGE: null, _BOOT_ID: BOOT_B }),
    ].join("\n") + "\n"
  );
}

test("journal_export keeps the whole native export, with the cursor and both clocks, and offers the projection as well", async () => {
  await withCwd(async (cwd, bin) => {
    const native = nativeJournal();
    const env = await journalFixture(cwd, bin, native);
    const run = await asJob(JOURNAL, cwd, { path: "work/journal", write_text: true }, bin, env);
    const out = body(run);
    // Every byte journalctl wrote is in the file, in its order.
    const kept = await readFile(join(cwd, "out", "journal-native.jsonl"), "utf8");
    assert.equal(kept, native);
    assert.equal((await stat(join(cwd, "out", "journal-native.jsonl"))).mode & 0o777, 0o600);
    assert.equal(out.text.written, 5);
    assert.equal(out.entry_count, 5);
    assert.equal(out.status, "complete");
    assert.ok(out.status_basis);
    // The projection: the identity and the clocks, as raw values beside the decoded time.
    const rows = await rowsOf(cwd, out);
    assert.equal(rows.length, 5);
    assert.match(rows[1].cursor, /^s=739ad463348b4ceca5a9699c3d7d5e1f;i=/);
    assert.equal(rows[1].realtime_us, "1771061402123456");
    assert.equal(rows[1].monotonic_us, "5000002".replace("5000002", String(5_000_000 + 2_000_000)));
    assert.equal(rows[1].time, "2026-02-14T09:30:02.123456Z");
    assert.equal(rows[1].boot_id, BOOT_A);
    assert.equal(rows[1].machine_id, MACHINE);
    assert.equal(rows[1].audit_session, "3");
    assert.equal(rows[1].native_line, 2);
    assert.equal(rows[2].source_realtime_us, "1771057800000000");
    assert.equal(rows[2].realtime_us, "1771057800000001");
    // A field journalctl encodes as bytes or as null is counted, not turned into text.
    assert.equal(rows[3].message_encoding, "bytes");
    assert.equal(rows[4].message_encoding, "null");
    assert.equal(out.boots_seen, 2);
    const boots = Object.fromEntries(out.boots.map((b: Json) => [b.boot_id, b]));
    assert.equal(boots[BOOT_A].entries, 3);
    assert.equal(boots[BOOT_A].first_monotonic_us, String(6_000_000));
    // The export asked for every field in full and for this journal only.
    const argv: string[] = JSON.parse((await readFile(env.STUB_ARGV, "utf8")).trim().split("\n")[0]);
    assert.deepEqual(argv.slice(0, 2), ["--directory", "work/journal"]);
    assert.ok(argv.includes("--all") && argv.includes("--no-pager") && argv.includes("json"));
    assert.deepEqual(out.argv.slice(1), argv, "the argv is recorded as an array");
  });
});

test("journal_export does not say the clock is consistent within a boot, or that a missing directory means a volatile journal", async () => {
  await withCwd(async (cwd, bin) => {
    const env = await journalFixture(cwd, bin, nativeJournal());
    const out = body(await asJob(JOURNAL, cwd, { path: "work/journal" }, bin, env));
    assert.doesNotMatch(out.note, /clock is consistent/i);
    assert.doesNotMatch(out.note, /was volatile/i);
    assert.doesNotMatch(out.note, /everything before the last boot is gone/i);
    assert.doesNotMatch(out.note, /boot_id first and time second/i);
    assert.match(out.note, /monotonic/i);
    assert.match(out.note, /not (?:collected|in what you)|path was not/i);
  });
});

test("journal_export keeps messages and command lines out of its answer unless asked, in a job", async () => {
  await withCwd(async (cwd, bin) => {
    const env = await journalFixture(cwd, bin, nativeJournal());
    for (const run of [await tool(JOURNAL, cwd, { path: "work/journal", limit: 2 }, env, bin), await asJob(JOURNAL, cwd, { path: "work/journal", limit: 2 }, bin, env)]) {
      const out = body(run);
      assert.ok(out.records[1].message_bytes > 0 && out.records[1].cmdline_bytes > 0);
      assert.ok(!("message" in out.records[1]) && !("cmdline" in out.records[1]));
      assert.equal(out.text.written, 0);
      const all = await everythingBut(cwd, run.stdout, []);
      assert.ok(!all.includes(JOURNAL_SECRET), "no file of the answer carries the command line");
    }
    assert.match(refused(await tool(JOURNAL, cwd, { path: "work/journal", write_text: true }, env, bin)).error, /outside a job/);
    const preview = body(await asJob(JOURNAL, cwd, { path: "work/journal", preview_text: true }, bin, env));
    assert.ok(preview.records[1].message.includes(JOURNAL_SECRET));
    assert.ok(preview.records[1].cmdline.includes(JOURNAL_SECRET));
  });
});

test("journal_export asks for time bounds with their zone and records them", async () => {
  await withCwd(async (cwd, bin) => {
    const env = await journalFixture(cwd, bin, nativeJournal());
    const bad = refused(await asJob(JOURNAL, cwd, { path: "work/journal", since: "2026-02-14 00:00:00" }, bin, env));
    assert.match(bad.error, /UTC/);
    assert.match(refused(await asJob(JOURNAL, cwd, { path: "work/journal", until: "yesterday" }, bin, env)).error, /UTC/);
    assert.equal(await exists(env.STUB_ARGV), false, "journalctl was not run with a bound it would have read in this machine's zone");
    const ok = body(await asJob(JOURNAL, cwd, { path: "work/journal", since: "2026-02-14 00:00:00 UTC", until: "@1771100000" }, bin, env));
    assert.deepEqual(ok.time_bounds, { since: "2026-02-14 00:00:00 UTC", until: "@1771100000", interpretation: "as written, with its own zone" });
    const argv: string[] = JSON.parse((await readFile(env.STUB_ARGV, "utf8")).trim().split("\n")[0]);
    assert.ok(argv.includes("--since") && argv.includes("2026-02-14 00:00:00 UTC"));
  });
});

test("journal_export returns the paths and a partial status when journalctl does not finish, and names a line that is no JSON", async () => {
  await withCwd(async (cwd, bin) => {
    const env = await journalFixture(cwd, bin, nativeJournal() + "this is not json\n");
    const slow = body(await asJob(JOURNAL, cwd, { path: "work/journal", write_text: true, max_seconds: 1 }, bin, { ...env, STUB_SLEEP: "30" }));
    assert.equal(slow.timed_out, true);
    assert.equal(slow.status, "partial");
    assert.equal(slow.entry_count, 5, "what was read before the deadline is kept");
    assert.match(slow.text.file, /journal-native\.jsonl$/);
    assert.equal(slow.parse_errors.count, 1);
    assert.equal(slow.parse_errors.first[0].native_line, 6);
    assert.ok(!("text" in slow.parse_errors.first[0]));
    // A journalctl that fails and wrote nothing is an error with its stderr kept whole in a file.
    await writeFile(join(cwd, "empty.jsonl"), "");
    const failed = refused(await asJob(JOURNAL, cwd, { path: "work/journal" }, bin, { ...env, STUB_EXIT: "1", STUB_STDERR: "Journal file is corrupted\n", STUB_LINES: join(cwd, "empty.jsonl") }, "out-failed"));
    assert.match(failed.error, /journalctl/);
    assert.equal(failed.exit_code, 1);
    assert.equal(await readFile(join(cwd, "out-failed", "journalctl.stderr"), "utf8"), "Journal file is corrupted\n");
  });
});

test("journal_export verifies in a mode of its own and claims nothing about completeness", async () => {
  await withCwd(async (cwd, bin) => {
    const env = await journalFixture(cwd, bin, nativeJournal());
    await writeFile(join(cwd, "verify.txt"), "PASS: work/journal/system.journal\n");
    const out = body(await asJob(JOURNAL, cwd, { path: "work/journal", mode: "verify" }, bin, { ...env, STUB_VERIFY: join(cwd, "verify.txt") }));
    assert.equal(out.mode, "verify");
    assert.equal(out.exit_code, 0);
    assert.match(out.verify.output_file, /journal-verify\.txt$/);
    assert.equal(await readFile(join(cwd, "out", "journal-verify.txt"), "utf8"), "PASS: work/journal/system.journal\n");
    assert.equal("entry_count" in out, false, "verification exports nothing");
    assert.match(out.claims, /structural/i);
    assert.match(out.does_not_show, /missing|removed|complete/i);
    assert.equal("complete" in out, false);
    const argv: string[] = JSON.parse((await readFile(env.STUB_ARGV, "utf8")).trim().split("\n")[0]);
    assert.ok(argv.includes("--verify"));
  });
});

test("journal_export does not stop at a boot id that is a list, and counts the line that is longer than an entry may be", async () => {
  await withCwd(async (cwd, bin) => {
    const huge = JSON.stringify({ __CURSOR: "s=1;i=1;b=1;m=1;t=1;x=1", __REALTIME_TIMESTAMP: "1771061400000000", __MONOTONIC_TIMESTAMP: "1", _BOOT_ID: BOOT_A, MESSAGE: "m".repeat(33 * 1024 * 1024) });
    const native = [entry(1, {}), entry(2, { _BOOT_ID: [BOOT_A, BOOT_B] as unknown as string }), huge, entry(4, {})].join("\n") + "\n";
    const env = await journalFixture(cwd, bin, native);
    const out = body(await asJob(JOURNAL, cwd, { path: "work/journal", write_text: true }, bin, env));
    assert.equal(out.entry_count, 3, "the oversized line is not an entry");
    assert.equal(out.parse_errors.oversized_lines, 1);
    assert.equal(out.parse_errors.first[0].native_line, 3);
    assert.equal(out.entries_with_a_boot_id_that_is_not_text, 1);
    assert.equal(out.status, "partial");
    assert.equal(out.text.written, 4, "every line is in the native file, the long one included");
    assert.equal((await stat(join(cwd, "out", "journal-native.jsonl"))).size, Buffer.byteLength(native));
  });
});

test("journal_export ends journalctl and what it started at its deadline, and refuses a directory with links in it", async () => {
  await withCwd(async (cwd, bin) => {
    const env = await journalFixture(cwd, bin, nativeJournal());
    // The stand-in leaves a child holding the pipe open: killing only journalctl would not end the read.
    await writeFile(join(bin, "journalctl"), `#!/usr/bin/env python3
import os, subprocess, sys, time
open(os.environ["STUB_ARGV"], "a").write("run\\n")
sys.stdout.write(open(os.environ["STUB_LINES"]).read()); sys.stdout.flush()
subprocess.Popen(["sleep", "30"])
time.sleep(30)
`);
    await chmod(join(bin, "journalctl"), 0o755);
    const started = Date.now();
    const out = body(await asJob(JOURNAL, cwd, { path: "work/journal", max_seconds: 1 }, bin, env));
    assert.equal(out.timed_out, true);
    assert.ok(Date.now() - started < 6000, `took ${Date.now() - started} ms`);
    await symlink("/etc", join(cwd, "work", "journal", "elsewhere"));
    const refusedLinks = refused(await asJob(JOURNAL, cwd, { path: "work/journal" }, bin, env, "out-links"));
    assert.match(refusedLinks.error, /links/);
    assert.equal(refusedLinks.link_count, 1);
  });
});

test("journal_export's preview carries message and cmdline in the answer and its paging file carries none", async () => {
  await withCwd(async (cwd, bin) => {
    const env = await journalFixture(cwd, bin, nativeJournal());
    const out = body(await asJob(JOURNAL, cwd, { path: "work/journal", preview_text: true, limit: 2 }, bin, env));
    assert.ok(out.records[1].message.includes(JOURNAL_SECRET));
    assert.equal(out.text.answer_contains_text_that_may_hold_secrets, true);
    for (const f of await filesUnder(join(cwd, "out"))) assert.ok(!(await readFile(join(cwd, "out", f), "utf8")).includes(JOURNAL_SECRET), f);
  });
});

test("journal_export rejects arguments that are not an object and a field of the wrong type", async () => {
  await withCwd(async (cwd, bin) => {
    const env = await journalFixture(cwd, bin, nativeJournal());
    for (const bad of [null, [], "x"]) assert.match(refused(await tool(JOURNAL, cwd, bad, env, bin)).error, /JSON object/);
    for (const args of [{ path: "work/journal", unit: 5 }, { path: "work/journal", grep: [] }, { path: "work/journal", since: 5 }]) refused(await tool(JOURNAL, cwd, args, env, bin));
  });
});

test("journal_export asks journalctl to be quiet and reads its `-- No entries --` notice as an empty selection, not as a broken export", async () => {
  await withCwd(async (cwd, bin) => {
    // A real journalctl prints this line on stdout when nothing matches and --quiet is not given.
    const env = await journalFixture(cwd, bin, "-- No entries --\n");
    const out = body(await asJob(JOURNAL, cwd, { path: "work/journal", unit: "none.service" }, bin, env));
    assert.equal(out.entry_count, 0);
    assert.equal(out.no_entries_notices, 1);
    assert.equal(out.parse_errors.count, 0);
    assert.equal(out.status, "complete");
    const argv: string[] = JSON.parse((await readFile(env.STUB_ARGV, "utf8")).trim().split("\n")[0]);
    assert.ok(argv.includes("--quiet"), "the notice is not asked for");
  });
});

test("journal_export ends journalctl and its children when it is told to stop", async () => {
  await withCwd(async (cwd, bin) => {
    const env = await journalFixture(cwd, bin, nativeJournal());
    await writeFile(join(bin, "journalctl"), `#!/usr/bin/env python3
import os, subprocess, time
open(os.environ["STUB_PID"], "w").write(str(os.getpid()))
subprocess.Popen(["sleep", "60"])
time.sleep(60)
`);
    await chmod(join(bin, "journalctl"), 0o755);
    const pidFile = join(cwd, "stub.pid");
    await mkdir(join(cwd, "out"), { recursive: true });
    const child = spawn("python3", [JOURNAL], { cwd, env: { ...process.env, ...env, STUB_PID: pidFile, AGENT_ID: "s1", JOB_ID: "j000050", OUT: join(cwd, "out"), PATH: `${bin}:${process.env.PATH ?? ""}` }, stdio: ["pipe", "pipe", "pipe"] });
    child.stdin.end(JSON.stringify({ path: "work/journal" }));
    const exited = new Promise<number | null>((resolve) => child.on("close", (code) => resolve(code)));
    let pid = 0;
    for (let i = 0; i < 100 && !pid; i++) {
      await new Promise((r) => setTimeout(r, 100));
      pid = Number(await readFile(pidFile, "utf8").catch(() => "0"));
    }
    assert.ok(pid > 0);
    child.kill("SIGTERM");
    assert.equal(await exited, 143);
    await new Promise((r) => setTimeout(r, 300));
    assert.throws(() => process.kill(pid, 0), "journalctl did not outlive the tool");
    const kids = spawnSync("pgrep", ["-f", "sleep 60"], { encoding: "utf8" }).stdout.trim();
    assert.equal(kids, "", `nor did what it started: ${kids}`);
  });
});

test("journal_export never writes over an earlier output of the same job", async () => {
  await withCwd(async (cwd, bin) => {
    const env = await journalFixture(cwd, bin, nativeJournal());
    await writeFile(join(cwd, "verify.txt"), "PASS: first\n");
    const first = body(await asJob(JOURNAL, cwd, { path: "work/journal", mode: "verify" }, bin, { ...env, STUB_VERIFY: join(cwd, "verify.txt") }));
    await writeFile(join(cwd, "verify.txt"), "PASS: second\n");
    const second = body(await asJob(JOURNAL, cwd, { path: "work/journal", mode: "verify" }, bin, { ...env, STUB_VERIFY: join(cwd, "verify.txt") }));
    assert.notEqual(first.verify.output_file, second.verify.output_file);
    assert.match(second.verify.output_file, /journal-verify\.2\.txt$/);
    assert.equal(await readFile(join(cwd, "out", "journal-verify.txt"), "utf8"), "PASS: first\n");
    assert.equal(await readFile(join(cwd, "out", "journal-verify.2.txt"), "utf8"), "PASS: second\n");
    assert.match(second.verify.stderr_file, /journalctl\.2\.stderr$/);
    assert.equal(first.status, "complete");
  });
});

test("journal_export refuses a path that is not a file or a directory, a path through a link, and this machine's own journal, and answers with an error where it cannot write", async () => {
  await withCwd(async (cwd, bin) => {
    const env = await journalFixture(cwd, bin, nativeJournal());
    assert.equal(spawnSync("mkfifo", [join(cwd, "work", "pipe.journal")]).status, 0);
    assert.match(refused(await tool(JOURNAL, cwd, { path: "work/pipe.journal" }, env, bin)).error, /pipe, a socket or a device/);
    await mkdir(join(cwd, "work", "real"), { recursive: true });
    await writeFile(join(cwd, "work", "real", "system.journal"), "x");
    await symlink(join(cwd, "work", "real"), join(cwd, "work", "linked"));
    const through = refused(await tool(JOURNAL, cwd, { path: "work/linked/system.journal" }, env, bin));
    assert.match(through.error, /through a link/);
    assert.match(refused(await tool(JOURNAL, cwd, { path: "/var/log/journal" }, env, bin)).error, /own journal|no such file/);
    assert.equal(await exists(env.STUB_ARGV), false);
    if (!IS_ROOT) {
      const ro = join(cwd, "ro-out");
      await mkdir(ro, { recursive: true });
      await chmod(ro, 0o555);
      try {
        const bad = refused(await tool(JOURNAL, cwd, { path: "work/journal" }, { ...env, JOB_ID: "j000066", OUT: ro }, bin));
        assert.equal(bad.status, "failed");
      } finally {
        await chmod(ro, 0o755);
      }
    }
  });
});

test("journal_export refuses grep outside a job, matches the message text only in a job and says so, and shows a long previewed message cut with its length", async () => {
  await withCwd(async (cwd, bin) => {
    const env = await journalFixture(cwd, bin, nativeJournal());
    assert.match(refused(await tool(JOURNAL, cwd, { path: "work/journal", grep: "hunter" }, env, bin)).error, /oracle/);
    const inJob = body(await asJob(JOURNAL, cwd, { path: "work/journal", grep: "hunter" }, bin, env));
    assert.equal(inJob.filter_touched_withheld_text, true);
    const big = JSON.stringify({ __CURSOR: "s=1", __REALTIME_TIMESTAMP: "1771061400000000", __MONOTONIC_TIMESTAMP: "1", _BOOT_ID: BOOT_A, MESSAGE: "m".repeat(200_000), _CMDLINE: "c".repeat(100) });
    await writeFile(join(cwd, "stub-lines.jsonl"), big + "\n");
    const preview = body(await asJob(JOURNAL, cwd, { path: "work/journal", preview_text: true }, bin, env, "out-big"));
    assert.equal(preview.records[0].message.length, 65536);
    assert.equal(preview.records[0].preview_truncated.message, 200_000);
    assert.equal(preview.records[0].cmdline.length, 100);
  });
});

test("journal_export takes no NaN for a budget", async () => {
  await withCwd(async (cwd, bin) => {
    const env = await journalFixture(cwd, bin, nativeJournal());
    for (const literal of ["NaN", "Infinity", "-1", "0"]) {
      const r = spawnSync("python3", [JOURNAL], { cwd, input: `{"path":"work/journal","max_seconds":${literal}}`, encoding: "utf8", env: { ...process.env, ...env, PATH: `${bin}:${process.env.PATH ?? ""}` } });
      assert.equal(r.status, 1, literal);
      assert.match(JSON.parse(r.stdout).error, /max_seconds/);
    }
  });
});
