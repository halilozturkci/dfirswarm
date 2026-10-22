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
import { join } from "node:path";
import { test } from "node:test";
import { CRON, RECIPE, SHELL, UTMP, asJob, body, lines, put, refused, rowsOf, startDetached, tool, withCwd } from "./linux-pack-harness.ts";
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

test("cron_dump keeps a timer of a million assignments out of the answer: the row shows 50, the rest are paged, the whole is in the text file", async () => {
  await withCwd(async (cwd) => {
    const dir = join(cwd, "work", "ev", "etc", "systemd", "system");
    await mkdir(dir, { recursive: true });
    await writeFile(join(dir, "big.timer"), "[Timer]\nOnCalendar=daily\n" + "a=b\n".repeat(1_000_000));
    const { out, seconds } = await bounded(CRON, cwd, { root: "work/ev" });
    const timer = out.entries.find((e: Json) => e.source === "systemd");
    assert.equal(timer.assignment_count, 1_000_001);
    assert.equal(timer.assignments.length, 50);
    assert.equal(timer.assignments_not_shown, 999_951);
    assert.equal(timer.schedule, "daily");
    assert.equal(out.pages.assignments.matched, 999_951);
    assert.equal(out.assignments_beyond_the_rows.length, 200);
    assert.equal(out.status, "complete", out.status_basis);
    assert.ok(JSON.stringify(out).length < 400_000, `the answer is ${JSON.stringify(out).length} bytes`);
    assert.ok(seconds < 80, `took ${seconds} s`);
    // Every assignment beyond the row is in the paging file, whole.
    const rows = await rowsOf(cwd, out, "assignments");
    assert.equal(rows.length, 999_951);
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
