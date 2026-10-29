/**
 * The Linux pack: what a tool does with evidence that is large, hostile or odd, and what it says about it. Each case here is
 * one that the tool answered wrongly before: a clock that was read every 1,024 records (so a file of blank lines ran past its
 * deadline and said `complete`), a timer file projected whole into the answer, a regular expression of the caller's run over
 * text of the evidence's with no clock, a `complete` that meant "nothing was there", a byte offset that lost a byte per line.
 * Every fixture is built by the test from the format's own layout, never from a tool's output.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdir, open, readFile, readdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { runPySnippet } from "./tool-library-harness.ts";
import { CRON, JOURNAL, RECIPE, SHELL, UTMP, asJob, body, filesUnder, lines, put, refused, rowsOf, startDetached, tool, withCwd } from "./linux-pack-harness.ts";
import type { Json } from "./linux-pack-harness.ts";

/** A tool that must come back: a case whose tool is still running after `ms` is killed and fails by name (the old code ran for minutes). */
async function bounded(script: string, cwd: string, args: unknown, env: Record<string, string> = {}, ms = 90_000): Promise<{ out: Json; seconds: number }> {
  const started = Date.now();
  const run = startDetached(script, cwd, args, env);
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<"late">((resolve) => { timer = setTimeout(() => resolve("late"), ms); });
  const result = await Promise.race([run.closed, timeout]);
  clearTimeout(timer);
  if (result === "late") {
    run.killGroup();
    assert.fail(`the tool had not come back after ${ms} ms`);
  }
  assert.equal(result, 0, run.stdout().slice(0, 500));
  return { out: JSON.parse(run.stdout()), seconds: (Date.now() - started) / 1000 };
}

async function writeRepeated(path: string, unit: Buffer, times: number): Promise<void> {
  const fh = await open(path, "w");
  try {
    for (let i = 0; i < times; i++) await fh.write(unit);
  } finally {
    await fh.close();
  }
}

// ---- shell_history ----

test("shell_history reads the clock between lines: a file of blank lines ends at max_seconds as partial", async () => {
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "work", "ev", "home", "a"), { recursive: true });
    await writeRepeated(join(cwd, "work", "ev", "home", "a", ".bash_history"), Buffer.alloc(1 << 20, 10), 96);
    const { out, seconds } = await bounded(SHELL, cwd, { root: "work/ev", max_seconds: 2 });
    assert.equal(out.status, "partial", out.status_basis);
    assert.equal(out.all_files_read, false);
    assert.match(out.partial_reason, /max_seconds/);
    assert.equal(out.files[0].partial, true);
    assert.ok(seconds < 40, `took ${seconds} s for max_seconds 2`);
  });
});

test("shell_history reads the clock inside one stamped entry: data lines under a single stamp end at max_seconds", async () => {
  await withCwd(async (cwd) => {
    const file = join(cwd, "work", "ev", "home", "a", ".bash_history");
    await mkdir(join(file, ".."), { recursive: true });
    await writeFile(file, "#1700000000\n");
    const fh = await open(file, "a");
    const unit = Buffer.from("ls -la a\n".repeat(1 << 16));
    for (let i = 0; i < 100; i++) await fh.write(unit);
    await fh.close();
    const { out } = await bounded(SHELL, cwd, { root: "work/ev", max_seconds: 2 });
    assert.equal(out.status, "partial", out.status_basis);
    assert.match(out.partial_reason, /max_seconds/);
  });
});

test("shell_history reads the clock in a file with no newline: 8 MiB pieces are each followed by a look at it", async () => {
  await withCwd(async (cwd) => {
    const file = join(cwd, "work", "ev", "home", "a", ".bash_history");
    await mkdir(join(file, ".."), { recursive: true });
    const fh = await open(file, "w");
    await fh.write("echo start");
    await fh.truncate(3 * 1024 ** 3);       // a sparse 3 GiB with no newline: 384 pieces, 384 records at most
    await fh.close();
    const { out } = await bounded(SHELL, cwd, { root: "work/ev", max_seconds: 1 });
    assert.equal(out.status, "partial", out.status_basis);
    assert.match(out.partial_reason, /max_seconds/);
  });
});

test("shell_history's byte_offset is the position of the record's first byte, with LF and CRLF line ends", async () => {
  await withCwd(async (cwd) => {
    await put(join(cwd, "work", "ev"), "home/a/.bash_history", "ls -la\ncd /tmp\r\nwhoami\nid\n");
    const out = body(await tool(SHELL, cwd, { root: "work/ev" }));
    assert.deepEqual(out.records.map((r: Json) => r.byte_offset), [0, 7, 16, 23]);
    assert.deepEqual(out.records.map((r: Json) => r.line_start), [1, 2, 3, 4]);
    // The same through a stamped file and a zsh one, and a record after an 8 MiB piece.
    await put(join(cwd, "work", "ev2"), "home/b/.bash_history", "#1700000000\r\nls\r\n#1700000001\nid\n");
    const stamped = body(await tool(SHELL, cwd, { root: "work/ev2" }));
    assert.deepEqual(stamped.records.map((r: Json) => r.byte_offset), [0, 17]);
    await put(join(cwd, "work", "ev3"), "home/c/.zsh_history", ": 1700000000:0;ls\n: 1700000001:0;id\n");
    const zsh = body(await tool(SHELL, cwd, { root: "work/ev3" }));
    assert.deepEqual(zsh.records.map((r: Json) => r.byte_offset), [0, 18]);
  });
});

test("shell_history ends a contains expression that does not finish, and says so", async () => {
  await withCwd(async (cwd) => {
    await put(join(cwd, "work", "ev"), "home/a/.bash_history", lines("#1700000000", "a".repeat(40) + "b", "#1700000001", "echo after"));
    const { out, seconds } = await bounded(SHELL, cwd, { root: "work/ev", contains: "(a+)+$", max_seconds: 30 }, { JOB_ID: "j1", OUT: join(cwd, "out") });
    assert.equal(out.status, "partial", out.status_basis);
    assert.match(out.partial_reason, /contains expression did not finish/);
    assert.ok(seconds < 30, `took ${seconds} s`);
    // An expression that finishes is answered as before.
    const ok = body(await asJob(SHELL, cwd, { root: "work/ev", contains: "^echo" }));
    assert.equal(ok.record_count, 1);
    assert.equal(ok.status, "complete");
  });
});

test("shell_history does not call a root with no history file complete", async () => {
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "work", "empty"), { recursive: true });
    const out = body(await tool(SHELL, cwd, { root: "work/empty" }));
    assert.equal(out.status, "partial");
    assert.equal(out.all_files_read, false);
    assert.match(out.status_basis, /no history file was found/);
    // ... and a user filter that left every file out says so.
    await put(join(cwd, "work", "ev"), "home/a/.bash_history", "ls\n");
    const none = body(await tool(SHELL, cwd, { root: "work/ev", user: "nobody" }));
    assert.equal(none.status, "partial");
    assert.match(none.status_basis, /1 were left out by the user filter/);
  });
});

// ---- cron_dump ----

test("cron_dump keeps a timer of 300,000 assignments out of the answer: the row shows 50, the rest are paged", async () => {
  await withCwd(async (cwd) => {
    const dir = join(cwd, "work", "ev", "etc", "systemd", "system");
    await mkdir(dir, { recursive: true });
    await writeFile(join(dir, "big.timer"), "[Timer]\nOnCalendar=daily\n" + "a=b\n".repeat(300_000));
    const { out, seconds } = await bounded(CRON, cwd, { root: "work/ev" });
    const timer = out.entries.find((e: Json) => e.source === "systemd");
    assert.equal(timer.assignment_count, 300_001);
    assert.equal(timer.assignments.length, 50);
    assert.equal(timer.assignments_not_shown, 299_951);
    assert.equal(timer.schedule, "daily");
    assert.equal(out.pages.assignments.matched, 299_951);
    assert.equal(out.assignments_beyond_the_rows.length, 200);
    assert.equal(out.status, "complete", out.status_basis);
    assert.ok(JSON.stringify(out).length < 400_000, `the answer is ${JSON.stringify(out).length} bytes`);
    assert.ok(seconds < 80, `took ${seconds} s`);
    // Every assignment beyond the row is in the paging file, whole.
    const rows = await rowsOf(cwd, out, "assignments");
    assert.equal(rows.length, 299_951);
    assert.equal(rows[0].line, 52);
    assert.equal(rows[0].key, "a");
    assert.equal(rows[0].value_withheld, true);
  });
});

test("cron_dump's text file holds every assignment of a timer as a row of its own, the withheld values whole", async () => {
  await withCwd(async (cwd) => {
    const dir = join(cwd, "work", "ev", "etc", "systemd", "system");
    await mkdir(dir, { recursive: true });
    const text = "[Unit]\nDescription=secret-description\n[Timer]\nOnCalendar=hourly\nOnCalendar=\n" + Array.from({ length: 80 }, (_, i) => `Environment=K${i}=v${i}`).join("\n") + "\n";
    await writeFile(join(dir, "x.timer"), text);
    const out = body(await asJob(CRON, cwd, { root: "work/ev", write_text: true }));
    const timer = out.entries.find((e: Json) => e.source === "systemd");
    assert.equal(timer.assignment_count, 83);
    assert.equal(timer.assignments.length, 50);
    assert.equal(JSON.stringify(timer).includes("secret-description"), false);
    const kept = (await readFile(join(cwd, "out", "cron-text.jsonl"), "utf8")).trim().split("\n").map((l) => JSON.parse(l));
    const assignments = kept.filter((r) => r.record_type === "assignment");
    assert.equal(assignments.length, 83);
    assert.equal(assignments[0].value, "secret-description");
    assert.equal(assignments.at(-1).value, "K79=v79");
    assert.ok(assignments.every((r) => r.entry_id === timer.id));
  });
});

test("cron_dump reads the clock for every file: sixty thousand small tables in one directory end at max_seconds", async () => {
  await withCwd(async (cwd) => {
    const dir = join(cwd, "work", "ev", "etc", "cron.d");
    await mkdir(dir, { recursive: true });
    const line = "* * * * * root /bin/true\n";
    for (let batch = 0; batch < 60; batch++) {
      await Promise.all(Array.from({ length: 1000 }, (_, i) => writeFile(join(dir, `job${batch * 1000 + i}`), line)));
    }
    const { out } = await bounded(CRON, cwd, { root: "work/ev", max_seconds: 1 });
    assert.equal(out.status, "partial", out.status_basis);
    assert.ok(out.entries_total < 60_000, `read ${out.entries_total} files with max_seconds 1`);
    assert.match(out.partial_reason, /max_seconds/);
  });
});

test("cron_dump ends a contains expression that does not finish, and says so", async () => {
  await withCwd(async (cwd) => {
    const dir = join(cwd, "work", "ev", "etc", "cron.d");
    await mkdir(dir, { recursive: true });
    await writeFile(join(dir, "a"), `* * * * * root ${"a".repeat(40)}b\n* * * * * root echo\n`);
    const { out, seconds } = await bounded(CRON, cwd, { root: "work/ev", contains: "(a+)+$", max_seconds: 40 }, { JOB_ID: "j1", OUT: join(cwd, "out") });
    assert.equal(out.status, "partial", out.status_basis);
    assert.match(out.partial_reason, /contains expression did not finish/);
    assert.ok(seconds < 40, `took ${seconds} s`);
  });
});

test("cron_dump does not call a root with nothing in it, or a table with lines it could not read, complete", async () => {
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "work", "empty"), { recursive: true });
    const none = body(await tool(CRON, cwd, { root: "work/empty" }));
    assert.equal(none.status, "partial");
    assert.equal(none.all_checked_locations_read, false);
    assert.match(none.status_basis, /0 of \d+ place\(s\) listed were read/);
    await put(join(cwd, "work", "ev"), "etc/crontab", lines("-0 0 * * * root /x", "@every 5m root /y", "*/5 * * * ? root /z", "0 0 * * *", "0 0 * * * root /ok"));
    const some = body(await tool(CRON, cwd, { root: "work/ev" }));
    assert.equal(some.unparsed_lines, 4);
    assert.equal(some.status, "partial");
    assert.equal(some.all_checked_locations_read, false);
    assert.match(some.status_basis, /4 line\(s\) of a cron table matched no table shape/);
  });
});

test("cron_dump prints a user only where the field has the shape of a name, and a schedule only where the fields are schedules", async () => {
  await withCwd(async (cwd) => {
    const secret = "S3cretPw9Value";
    await put(join(cwd, "work", "ev"), "etc/cron.d/pasted", lines(
      `* * * * * DB_PASS=${secret} /bin/backup`,
      `* * * * * https://svc:${secret}@host/x run`,
      `1 2 3 password${secret} tokenXYZ root /opt/x`,
      "0 3 * jan-mar mon-fri root /opt/ok",
      "*/5 * * * Mon deploy$ /opt/ok2",
    ));
    const run = await tool(CRON, cwd, { root: "work/ev" });
    const out = body(run);
    assert.equal(run.stdout.includes(secret), false, "a word of a pasted line is in the answer");
    assert.equal(out.unparsed_lines, 3);
    const rows = await rowsOf(cwd, out, "entries");
    assert.deepEqual(rows.map((r) => [r.schedule, r.user]), [["0 3 * jan-mar mon-fri", "root"], ["*/5 * * * Mon", "deploy$"]]);
    const text = await asJob(CRON, cwd, { root: "work/ev", write_text: true }, undefined, {}, "out-t");
    assert.equal(body(text).unparsed_lines, 3);
    assert.ok((await readFile(join(cwd, "out-t", "cron-text.jsonl"), "utf8")).includes(secret), "the unparsed line is kept whole in the text file");
  });
});

// ---- utmp_parse ----

function btmpRecord(user: string): Buffer {
  const b = Buffer.alloc(384);
  b.writeInt16LE(6, 0);
  b.writeInt32LE(5, 4);
  b.write("ssh:notty", 8, 32, "latin1");
  b.write(user, 0x2c, 32, "latin1");
  b.write("203.0.113.4", 0x4c, 256, "latin1");
  b.writeInt32LE(1_771_061_400, 0x154);
  return b;
}

test("utmp_parse refuses a user filter on a typed file outside a job, instead of answering as if nobody matched", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "btmp"), Buffer.concat([btmpRecord("admin"), btmpRecord("root")]));
    const err = refused(await tool(UTMP, cwd, { path: "work/btmp", user: "admin" }));
    assert.match(err.error, /user is refused outside a job/);
    assert.equal(err.status, "failed");
    const job = body(await asJob(UTMP, cwd, { path: "work/btmp", user: "admin" }));
    assert.equal(job.record_count, 1);
    assert.equal(job.filter_touched_withheld_text, true);
    // On a file whose user is an account the filter is as it was, in or out of a job.
    await writeFile(join(cwd, "work", "wtmp"), Buffer.concat([btmpRecord("admin"), btmpRecord("root")]));
    assert.equal(body(await tool(UTMP, cwd, { path: "work/wtmp", user: "admin" })).record_count, 1);
  });
});

test("utmp_parse ends a user expression that does not finish on a typed name, and says where it stopped", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "btmp"), Buffer.concat([btmpRecord("a".repeat(31) + "b"), btmpRecord("root")]));
    const { out, seconds } = await bounded(UTMP, cwd, { path: "work/btmp", user: "(a+)+$", max_seconds: 40 }, { JOB_ID: "j1", OUT: join(cwd, "out") });
    assert.equal(out.status, "partial", out.status_basis);
    assert.equal(out.stopped_at_record, 0);
    assert.match(out.stopped_because, /user expression did not finish/);
    assert.ok(seconds < 40, `took ${seconds} s`);
  });
});

test("utmp_parse does not claim a byte order supported by records when every record is empty", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "wtmp"), Buffer.alloc(384 * 3));
    const out = body(await tool(UTMP, cwd, { path: "work/wtmp" }));
    assert.equal(out.layout.byte_order, "undetermined");
    assert.doesNotMatch(out.status_basis, /in a byte order the records support/);
    assert.match(out.status_basis, /undetermined/);
  });
});

// ---- the linux-target recipe ----

test("the linux-target recipe does not replace the receipt of an earlier run in the same --out", async () => {
  await withCwd(async (cwd, bin) => {
    await writeFile(join(bin, "target-query"), "#!/bin/sh\nexit 0\n");
    const { chmod } = await import("node:fs/promises");
    await chmod(join(bin, "target-query"), 0o755);
    await writeFile(join(cwd, "target.json"), JSON.stringify({ paths: [join(cwd, "inputs", "server.E01")], name: "server" }));
    await writeFile(join(cwd, "inputs", "server.E01"), "image bytes\n");
    const env = { ...process.env, PATH: `${bin}:${process.env.PATH ?? ""}` };
    const out = join(cwd, "receipt");
    const first = spawnSync("python3", [RECIPE, "run", "--target", join(cwd, "target.json"), "--out", out], { cwd, env, encoding: "utf8", timeout: 120_000 });
    assert.equal(first.status, 0, first.stdout + first.stderr);
    const before = { coverage: await readFile(join(out, "coverage.json"), "utf8"), summary: await readFile(join(out, "summary.json"), "utf8") };
    assert.equal(JSON.parse(before.coverage).status, "complete");
    const second = spawnSync("python3", [RECIPE, "run", "--target", join(cwd, "target.json"), "--out", out], { cwd, env, encoding: "utf8", timeout: 120_000 });
    assert.equal(second.status, 2, second.stdout);
    const answer = JSON.parse(second.stdout);
    assert.equal(answer.status, "failed");
    assert.match(answer.status_basis, /already holds a result of an earlier run/);
    assert.equal(await readFile(join(out, "coverage.json"), "utf8"), before.coverage, "the first receipt is as it was");
    assert.equal(await readFile(join(out, "summary.json"), "utf8"), before.summary, "the first summary is as it was");
    assert.ok((await readdir(join(out, "artefacts"))).length > 0);
    // A directory that is only empty is used.
    await mkdir(join(cwd, "fresh"));
    const third = spawnSync("python3", [RECIPE, "run", "--target", join(cwd, "target.json"), "--out", join(cwd, "fresh")], { cwd, env, encoding: "utf8", timeout: 120_000 });
    assert.equal(third.status, 0, third.stdout + third.stderr);
  });
});

// ---- the clock of a caller's expression, per record ----------------------------------------------------------------
// A match of `(a+)+$` on eighteen "a" and a "!" takes about 16 ms: well under the two seconds one match may take, so no
// single match was ended, and the loops looked at their own clock only every 1,024 / 2,048 / 4,096 records (and each match
// after the deadline still got 50 ms). A few thousand such records ran a minute past max_seconds, beyond the manifest's
// timeout, and no JSON came back. The clock is now read before every match, and no match is begun after the deadline.

const SLOW = `${"a".repeat(18)}!`;
const JOB_ENV = (cwd: string): Record<string, string> => ({ JOB_ID: "j1", OUT: join(cwd, "out") });

test("utmp_parse ends at max_seconds when every user match is slow: 4,300 records of 16 ms, max_seconds 2", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "btmp"), Buffer.concat(Array.from({ length: 4300 }, () => btmpRecord(SLOW))));
    const { out, seconds } = await bounded(UTMP, cwd, { path: "work/btmp", user: "(a+)+$", max_seconds: 2 }, JOB_ENV(cwd), 100_000);
    assert.equal(out.status, "partial", out.status_basis);
    assert.ok(out.stopped_at_record !== null && out.stopped_at_record < 4096, `stopped at ${out.stopped_at_record}`);
    if (out.stopped_because) assert.doesNotMatch(out.stopped_because, /did not finish within/, "the cause was the deadline, not one slow match");
    assert.ok(seconds < 12, `took ${seconds} s for max_seconds 2`);
  });
});

test("shell_history ends at max_seconds when every contains match is slow: 3,000 records of 16 ms, max_seconds 2", async () => {
  await withCwd(async (cwd) => {
    await put(join(cwd, "work", "ev"), "home/a/.bash_history", lines(...Array.from({ length: 3000 }, () => `echo ${SLOW}`)));
    const { out, seconds } = await bounded(SHELL, cwd, { root: "work/ev", contains: "(a+)+$", max_seconds: 2 }, JOB_ENV(cwd), 100_000);
    assert.equal(out.status, "partial", out.status_basis);
    assert.match(out.partial_reason, /max_seconds/);
    assert.doesNotMatch(out.partial_reason, /did not finish within/, "the cause was the deadline, not one slow match");
    assert.ok(seconds < 12, `took ${seconds} s for max_seconds 2`);
  });
});

test("cron_dump ends at max_seconds when every contains match is slow, names the place it stopped in, and says why", async () => {
  await withCwd(async (cwd) => {
    await put(join(cwd, "work", "ev"), "etc/crontab", lines(...Array.from({ length: 3000 }, () => `* * * * * root echo ${SLOW}`)));
    const { out, seconds } = await bounded(CRON, cwd, { root: "work/ev", contains: "(a+)+$", max_seconds: 2 }, JOB_ENV(cwd), 100_000);
    assert.equal(out.status, "partial", out.status_basis);
    assert.match(out.partial_reason, /max_seconds/);
    assert.doesNotMatch(out.partial_reason, /did not finish within/, "the cause was the deadline, not one slow match");
    assert.ok(seconds < 12, `took ${seconds} s for max_seconds 2`);
    // The place the inventory stopped in is in the census, and the basis does not say it was missing or a link.
    const stopped = out.locations.find((l: Json) => l.path === "etc/crontab");
    assert.match(stopped.state, /^stopped/);
    assert.match(out.status_basis, /the inventory stopped inside them/);
  });
});

test("lastlog: a slot whose user match was ended is not counted among the non-empty slots read, and the cause is the deadline", async () => {
  await withCwd(async (cwd) => {
    const width = 292;
    const slots = Array.from({ length: 30 }, () => {
      const b = Buffer.alloc(width);
      b.writeInt32LE(1_771_061_400, 0);
      b.write("pts/0", 4, 32, "latin1");
      return b;
    });
    await writeFile(join(cwd, "work", "lastlog"), Buffer.concat(slots));
    await writeFile(join(cwd, "work", "passwd"), Array.from({ length: 30 }, (_, i) => `${"a".repeat(22)}!${i}:x:${i}:${i}::/home/u:/bin/sh`).join("\n") + "\n");
    const { out, seconds } = await bounded(UTMP, cwd, { path: "work/lastlog", layout: "lastlog-292", passwd: "work/passwd", uids: Array.from({ length: 30 }, (_, i) => i), user: "(a+)+$", max_seconds: 1 }, {}, 100_000);
    assert.equal(out.status, "partial", out.status_basis);
    assert.equal(out.stopped, "max_seconds");
    assert.doesNotMatch(out.stopped_because, /did not finish within/);
    assert.ok(out.slots_read < 30);
    assert.equal(out.nonempty_slots, out.slots_read, "a slot that was not tested is not counted as read");
    assert.ok(seconds < 12, `took ${seconds} s for max_seconds 1`);
  });
});

// ---- cron_dump: a word in the user position, the paging cap ---------------------------------------------------------

test("cron_dump shows a word in the user position only for an account of the passwd, root or a lower-case name, and leaves the rest to the text file", async () => {
  await withCwd(async (cwd) => {
    const secrets = ["AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY", "Tr0ub4dor3xyz", "averyveryveryveryverylongusernamethatisnotreal"];
    const root = join(cwd, "work", "ev");
    await put(root, "etc/passwd", "root:x:0:0::/root:/bin/sh\nAlice:x:1000:1000::/home/Alice:/bin/sh\n");
    await put(root, "etc/cron.d/mixed", lines(
      "* * * * * Alice /bin/a",
      "* * * * * bob /bin/b",
      "* * * * * root /bin/r",
      ...secrets.map((s) => `* * * * * ${s} /bin/pasted`),
    ));
    const run = await tool(CRON, cwd, { root: "work/ev" });
    const out = body(run);
    for (const s of secrets) assert.equal(run.stdout.includes(s), false, `${s} is in the answer`);
    assert.equal(out.unparsed_lines, secrets.length);
    assert.equal(out.status, "partial");
    const rows = await rowsOf(cwd, out, "entries");
    assert.deepEqual(rows.map((r) => r.user), ["Alice", "bob", "root"]);
    const job = await asJob(CRON, cwd, { root: "work/ev", write_text: true }, undefined, {}, "out-u");
    assert.equal(body(job).unparsed_lines, secrets.length);
    const text = await readFile(join(cwd, "out-u", "cron-text.jsonl"), "utf8");
    for (const s of secrets) assert.ok(text.includes(s), `${s} is kept whole in the text file`);
  });
});

test("cron_dump stops writing its paging files at a cap, counts what it did not write, and says partial (a million-assignment timer)", async () => {
  await withCwd(async (cwd) => {
    const dir = join(cwd, "work", "ev", "etc", "systemd", "system");
    await mkdir(dir, { recursive: true });
    await writeFile(join(dir, "big.timer"), "[Timer]\nOnCalendar=daily\n" + "a=b\n".repeat(1_000_000));
    const { out } = await bounded(CRON, cwd, { root: "work/ev" });
    const page = out.pages.assignments;
    assert.equal(page.matched, 999_951);
    assert.ok(page.not_written > 0 && page.not_written < page.matched, `not_written ${page.not_written}`);
    assert.match(page.not_written_why, /at most 134217728 bytes together/);
    assert.equal(out.status, "partial", out.status_basis);
    assert.match(out.partial_reason, /paging files reached their cap/);
    const timer = out.entries.find((e: Json) => e.source === "systemd");
    assert.equal(timer.assignment_count, 1_000_001, "the count is whole");
    assert.equal(timer.assignments_not_paged, page.not_written);
    const rows = await rowsOf(cwd, out, "assignments");
    assert.equal(rows.length + page.not_written, 999_951, "every row is either in the file or counted as not written");
    const { stat } = await import("node:fs/promises");
    assert.ok((await stat(join(cwd, page.all_results))).size <= 134_217_728 + 4096, "the paging file is within the cap");
  });
});

// ---- a signal ends a tool with a last word and no unfinished temporary file ------------------------------------------

/** Start a tool, wait until it has begun a paging file (a dot-named temporary one), send SIGTERM, and read what is left. */
async function terminated(script: string, cwd: string, args: unknown): Promise<{ code: number | null; word: Json; dir: string }> {
  const dir = join(cwd, "out", "tool-output");
  await mkdir(join(cwd, "out"), { recursive: true });
  const run = startDetached(script, cwd, args, JOB_ENV(cwd));
  const until = Date.now() + 60_000;
  for (;;) {
    const names = await readdir(dir).catch(() => [] as string[]);
    if (names.some((n) => n.startsWith("."))) break;
    if (Date.now() > until) {
      run.killGroup();
      assert.fail("the tool never began a paging file");
    }
    await new Promise((r) => setTimeout(r, 50));
  }
  run.signal("SIGTERM");
  const code = await Promise.race([run.closed, new Promise<"late">((r) => setTimeout(() => r("late"), 30_000))]);
  if (code === "late") {
    run.killGroup();
    assert.fail("the tool ignored SIGTERM");
  }
  return { code, word: JSON.parse(run.stdout()), dir };
}

async function assertKept(cwd: string, result: { code: number | null; word: Json; dir: string }, key: string, minRows: number): Promise<void> {
  assert.equal(result.code, 143, "exit status of a SIGTERM");
  assert.equal(result.word.status, "failed");
  assert.equal(result.word.stopped_by_signal, 15);
  const names = await readdir(result.dir);
  assert.deepEqual(names.filter((n) => n.startsWith(".")), [], "no unfinished temporary file is left");
  const shown: string = result.word.paging_files_kept[key];
  assert.ok(shown, `the last word names the ${key} paging file`);
  const rows = (await readFile(join(cwd, "out", "tool-output", shown.split("/").at(-1) as string), "utf8")).trimEnd().split("\n").map((l) => JSON.parse(l));
  assert.ok(rows.length >= minRows, `${rows.length} rows kept`);
}

const FAST_THEN_SLOW = 400;

test("shell_history ends on SIGTERM with a last word, and keeps the paging file it had begun under its name", async () => {
  await withCwd(async (cwd) => {
    await put(join(cwd, "work", "ev"), "home/a/.bash_history", lines(...Array.from({ length: FAST_THEN_SLOW }, () => "echo a"), ...Array.from({ length: 4000 }, () => `echo ${SLOW}`)));
    const result = await terminated(SHELL, cwd, { root: "work/ev", contains: "(a+)+(\\s|$)", limit: 5 });
    await assertKept(cwd, result, "records", 6);
  });
});

test("cron_dump ends on SIGTERM with a last word, and keeps the paging file it had begun under its name", async () => {
  await withCwd(async (cwd) => {
    await put(join(cwd, "work", "ev"), "etc/crontab", lines(...Array.from({ length: FAST_THEN_SLOW }, () => "* * * * * root echo a"), ...Array.from({ length: 4000 }, () => `* * * * * root echo ${SLOW}`)));
    const result = await terminated(CRON, cwd, { root: "work/ev", contains: "(a+)+(\\s|$)", limit: 5 });
    await assertKept(cwd, result, "entries", 6);
  });
});

test("utmp_parse ends on SIGTERM with a last word, and keeps the paging file it had begun under its name", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "btmp"), Buffer.concat([...Array.from({ length: FAST_THEN_SLOW }, () => btmpRecord("a")), ...Array.from({ length: 4000 }, () => btmpRecord(SLOW))]));
    const result = await terminated(UTMP, cwd, { path: "work/btmp", user: "(a+)+(\\s|$)", limit: 5 });
    await assertKept(cwd, result, "records", 6);
  });
});

// ---- a signal that comes while a file is being written -------------------------------------------------------------

// Python can run a signal handler inside a buffered file's own flush, where the file refuses a second flush: the last word then
// left the paging file it was writing unfinished and unnamed (the SIGTERM tests above met it now and then on a loaded runner), and
// cut an answer that was being printed. This harness makes it happen every time: under the paging file, or under stdout, it puts a
// file whose first write sends the process SIGTERM, so the handler runs while the buffered layer above is in the middle of its flush.
const INSIDE_A_WRITE = String.raw`
import importlib.util, io, os, signal, sys, time
sys.dont_write_bytecode = True          # a __pycache__ beside the tool would be a file the sealed pack does not list
script, cwd, case = sys.argv[1:4]
for name in ("JOB_ID", "OUT"):
    os.environ.pop(name, None)
os.environ["AGENT_ID"] = "s1"
spec = importlib.util.spec_from_file_location("tool_under_test", script)
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)
os.chdir(cwd)
tool.install_signal_handlers()


class SignalInsideWrite(io.RawIOBase):
    def __init__(self, fd):
        self.fd, self.sent = fd, False

    def writable(self):
        return True

    def fileno(self):
        return self.fd

    def write(self, b):
        n = os.write(self.fd, b)
        if not self.sent:
            self.sent = True
            os.kill(os.getpid(), signal.SIGTERM)     # answered at the next instruction: here, inside the flush above
        return n


def inside_a_write(fd):
    return io.TextIOWrapper(io.BufferedWriter(SignalInsideWrite(fd), buffer_size=64), encoding="utf-8", write_through=True)


class SlowFlush(io.RawIOBase):
    def __init__(self, fd):
        self.fd = fd

    def writable(self):
        return True

    def fileno(self):
        return self.fd

    def write(self, b):
        time.sleep(0.5)                 # the last word's flush outlasts what the regex clock has left
        return os.write(self.fd, b)


if case == "clock":
    # A stop that comes during a slow match: the match's clock is still running when the last word begins.
    page = tool.LosslessPage(tool.TOOL, "records", 1)
    page.add({"n": 0})
    page.add({"n": 1})
    page._out.flush()
    held = page._out
    page._out = io.TextIOWrapper(io.BufferedWriter(SlowFlush(held.fileno()), buffer_size=1 << 16), encoding="utf-8")
    for n in range(2, 20):
        page.add({"n": n})
    tool.arm_regex_clock()
    signal.setitimer(signal.ITIMER_REAL, 0.1)
    os.kill(os.getpid(), signal.SIGTERM)
elif case == "page":
    page = tool.LosslessPage(tool.TOOL, "records", 1)
    page.add({"n": 0})
    page.add({"n": 1})                  # past the limit: the paging file is begun
    page._out.flush()
    held = page._out                    # keeps the descriptor open
    page._out = inside_a_write(held.fileno())
    for n in range(2, 200):
        page.add({"n": n, "pad": "x" * 40})
else:
    sys.stdout.flush()
    sys.stdout = inside_a_write(1)
    tool.fail("an error answer longer than the buffer " + "y" * 400)
print("the signal was never answered")
`;

for (const [name, script] of [["utmp_parse", UTMP], ["cron_dump", CRON], ["shell_history", SHELL]] as const) {
  test(`${name}: a signal while a row is being written still keeps the paging file under its name, every row in it whole`, async () => {
    await withCwd(async (cwd) => {
      const r = await runPySnippet(INSIDE_A_WRITE, [script, cwd, "page"], null);
      assert.equal(r.code, 143, `exit status of a SIGTERM: ${r.stdout}${r.stderr}`);
      const word = JSON.parse(r.stdout.trim().split("\n").at(-1) as string);
      assert.equal(word.stopped_by_signal, 15);
      const names = await readdir(join(cwd, "work", "s1", "tool-output"));
      assert.deepEqual(names.filter((n) => n.startsWith(".")), [], "no unfinished temporary file is left");
      const shown: string = word.paging_files_kept.records;
      assert.ok(shown, `the last word names the paging file: ${JSON.stringify(word.paging_files_kept)}`);
      const kept = await readFile(join(cwd, shown), "utf8");
      assert.ok(kept.endsWith("\n"), "the file ends at a whole row");
      const ns = kept.trimEnd().split("\n").map((l) => (JSON.parse(l) as { n: number }).n);
      assert.deepEqual(ns, ns.map((_, i) => i), "the rows in order from the first, none lost and none cut");
      assert.ok(ns.length >= 3, `${ns.length} rows kept: the one being written when the signal came is among them`);
    });
  });

  test(`${name}: a signal during a slow match keeps the paging file under its name, though the match's clock runs out in the last word`, async () => {
    await withCwd(async (cwd) => {
      const r = await runPySnippet(INSIDE_A_WRITE, [script, cwd, "clock"], null);
      assert.equal(r.code, 143, `exit status of a SIGTERM: ${r.stdout}${r.stderr}`);
      const word = JSON.parse(r.stdout.trim().split("\n").at(-1) as string);
      const names = await readdir(join(cwd, "work", "s1", "tool-output"));
      assert.deepEqual(names.filter((n) => n.startsWith(".")), [], "no unfinished temporary file is left");
      const shown: string = word.paging_files_kept.records;
      assert.ok(shown, `the last word names the paging file: ${JSON.stringify(word.paging_files_kept)}`);
      const ns = (await readFile(join(cwd, shown), "utf8")).trimEnd().split("\n").map((l) => (JSON.parse(l) as { n: number }).n);
      assert.deepEqual(ns, Array.from({ length: 20 }, (_, i) => i), "every row written before the stop is in it");
    });
  });

  test(`${name}: a signal while an answer is being written leaves that answer whole, with nothing after it`, async () => {
    await withCwd(async (cwd) => {
      const r = await runPySnippet(INSIDE_A_WRITE, [script, cwd, "answer"], null);
      assert.equal(r.code, 1, `the error answer's own exit status: ${r.stdout}${r.stderr}`);
      const doc = JSON.parse(r.stdout);
      assert.match(doc.error, /^an error answer longer than the buffer y{400}$/);
      assert.equal(doc.status, "failed");
    });
  });
}

// ---- journal_export: the walk for links ---------------------------------------------------------------------------

async function journalStub(bin: string): Promise<void> {
  const { chmod } = await import("node:fs/promises");
  await writeFile(join(bin, "journalctl"), "#!/bin/sh\nexit 0\n");
  await chmod(join(bin, "journalctl"), 0o755);
}

/** The tool, started the way the harness starts one and ended if it does not come back: a walk without a bound must fail this test and not run on. */
async function answer(script: string, cwd: string, args: unknown, bin: string, ms = 60_000): Promise<{ json: Json; seconds: number }> {
  const started = Date.now();
  const run = startDetached(script, cwd, args, {}, bin);
  const result = await Promise.race([run.closed, new Promise<"late">((r) => setTimeout(() => r("late"), ms))]);
  if (result === "late") {
    run.killGroup();
    assert.fail(`the tool had not come back after ${ms} ms`);
  }
  return { json: JSON.parse(run.stdout()), seconds: (Date.now() - started) / 1000 };
}

test("journal_export refuses the root directory by name, before it looks at anything below it", async () => {
  // The tool is not run on "/": the refusal is a function of its own, called here with the root and with spellings of it. A tool that
  // walked on would list the whole file system of the machine that runs the test.
  const probe = await runPySnippet(
    `import importlib.util, io, json, sys, contextlib
spec = importlib.util.spec_from_file_location("je", sys.argv[1])
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
out = []
for spelling in ("/", "//", "/.", "/usr/..", "/usr/bin/../.."):
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            m.refuse_root_directory(spelling)
        out.append(None)
    except SystemExit:
        out.append(json.loads(buf.getvalue()))
with contextlib.redirect_stdout(io.StringIO()):
    m.refuse_root_directory(sys.argv[2])
print(json.dumps(out))`,
    [JOURNAL, tmpdir()],
    null,
  );
  assert.equal(probe.code, 0, probe.stderr);
  for (const answer of JSON.parse(probe.stdout)) {
    assert.equal(answer.status, "failed");
    assert.match(answer.error, /refusing the root directory/);
  }
});

test("journal_export walks a directory for links within max_seconds and a cap, and says where it stopped", async () => {
  await withCwd(async (cwd, bin) => {
    await journalStub(bin);
    const dir = join(cwd, "work", "many");
    await mkdir(dir, { recursive: true });
    for (let batch = 0; batch < 101; batch++) {
      await Promise.all(Array.from({ length: 1000 }, (_, i) => writeFile(join(dir, `f${batch * 1000 + i}`), "")));
    }
    // More entries than a journal directory can have: not walked on, said so.
    const capped = await answer(JOURNAL, cwd, { path: "work/many" }, bin);
    assert.equal(capped.json.status, "failed");
    assert.match(capped.json.error, /could not be checked for links/);
    assert.match(capped.json.walk_ended_early, /more than 100000 entries/);
    assert.match(capped.json.walk_ended_early, /not a journal directory/);
    // A deadline that has already passed ends the walk on its first entries.
    const late = await answer(JOURNAL, cwd, { path: "work/many", max_seconds: 0.00001 }, bin);
    assert.equal(late.json.status, "failed");
    assert.match(late.json.walk_ended_early, /max_seconds passed after \d+ entries/);
    assert.ok(late.json.entries_looked_at < 100_000);
    // A real journal directory (a few files, no link) is still checked whole and read.
    await put(cwd, "work/real/1.journal", "x");
    const real = await answer(JOURNAL, cwd, { path: "work/real" }, bin);
    assert.notEqual(real.json.status, "failed", JSON.stringify(real.json).slice(0, 300));
  });
});
