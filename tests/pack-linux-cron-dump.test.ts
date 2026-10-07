/**
 * The Linux pack: cron_dump, against crontab(5) lines and systemd.timer(5) and systemd.unit(5) files.
 * Every fixture is built by the test from the format's own layout, never from a tool's output.
 *
 * The tools that read command lines, messages or environments follow the secret-safe output pattern of
 * recovery_key_scan (docs/packs.md, "Secrets and sensitive output"): the answer is locators and structured
 * fields, and the text is written only on request, only in a job, only to a file under $OUT. What the answer
 * and the files it names hold is checked here for a planted secret.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmod, mkdir, readFile, stat, symlink, truncate } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { CRON, IS_ROOT, SHELL, asJob, body, everythingBut, filesUnder, lines, put, refused, rowsOf, tool, withCwd } from "./linux-pack-harness.ts";
import type { Json } from "./linux-pack-harness.ts";

const CRON_SECRET = "s3cretCronValue99";
const SPOOL_SECRET = "abcdef123456tokenvalue";

test("cron_dump keeps every assignment of a timer in order, the empty one that resets a list included, with its section and line", async () => {
  await withCwd(async (cwd) => {
    const root = join(cwd, "work", "root");
    await put(root, "etc/systemd/system/backup.timer", "[Unit]\nDescription=Nightly backup\n\n[Timer]\nOnCalendar=daily\nOnCalendar=\nOnCalendar=*-*-* 02:00:00\nPersistent=true\nUnit=other.service\nUnit=backup.service\n\n[Install]\nWantedBy=timers.target\n");
    const out = body(await tool(CRON, cwd, { root: "work/root" }));
    const timer = (await rowsOf(cwd, out, "entries")).find((e) => e.source === "systemd");
    assert.ok(timer);
    const calendars = timer.assignments.filter((a: Json) => a.key === "OnCalendar");
    assert.deepEqual(calendars.map((a: Json) => [a.line, a.section, a.value]), [[5, "Timer", "daily"], [6, "Timer", ""], [7, "Timer", "*-*-* 02:00:00"]]);
    assert.deepEqual(timer.assignments.map((a: Json) => a.line), [2, 5, 6, 7, 8, 9, 10, 13]);
    assert.equal(timer.assignments.at(-1).section, "Install");
    assert.equal(timer.derived_basis.includes("not applied"), true, "the convenience fields say that empty assignments and drop-ins are not applied");
    assert.equal(timer.unit, "backup.service");
  });
});

test("cron_dump computes its coverage before it filters, so a filtered-out error still shows", async () => {
  await withCwd(async (cwd) => {
    if (IS_ROOT) return; // root reads a mode-000 file; the case needs a refused read
    const root = join(cwd, "work", "root");
    await put(root, "etc/cron.d/keep", "*/5 * * * * root /usr/bin/true\n");
    await put(root, "etc/systemd/system/locked.timer", "[Timer]\nOnBootSec=1min\n", 0o000);
    const out = body(await tool(CRON, cwd, { root: "work/root", contains: "cron.d/keep" }));
    assert.equal(out.entries_matched, 1);
    assert.equal(out.entries_total, 1, "an unreadable file is a read error, not an entry");
    assert.equal(out.all_checked_locations_read, false);
    assert.ok(out.read_errors.some((e: Json) => String(e.file).endsWith("locked.timer")));
    assert.equal("complete" in out, false);
  });
});

test("cron_dump names a scheduling file too large to read whole, and does not call the root fully read", async () => {
  await withCwd(async (cwd) => {
    const root = join(cwd, "work", "root");
    await put(root, "etc/cron.d/keep", "*/5 * * * * root /usr/bin/true\n");
    await put(root, "etc/cron.d/huge", "");
    await truncate(join(root, "etc/cron.d/huge"), 70 * 1024 * 1024);
    const out = body(await tool(CRON, cwd, { root: "work/root" }));
    assert.ok(out.read_errors.some((e: Json) => String(e.file).endsWith("huge") && /larger than/.test(e.error)));
    assert.equal(out.all_checked_locations_read, false);
    assert.equal(out.entries_total, 1);
  });
});

test("cron_dump looks in the user's own systemd directories and says what it did not look in", async () => {
  await withCwd(async (cwd) => {
    const root = join(cwd, "work", "root");
    await put(root, "etc/passwd", "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\nsvc:x:998:998::/var/lib/svc:/usr/sbin/nologin\n");
    await put(root, "home/alice/.config/systemd/user/sync.timer", "[Timer]\nOnCalendar=hourly\n");
    await put(root, "var/lib/svc/.config/systemd/user/job.timer", "[Timer]\nOnBootSec=5min\n");
    await put(root, "root/.config/systemd/user/r.timer", "[Timer]\nOnStartupSec=1min\n");
    await put(root, "etc/systemd/user/shared.timer", "[Timer]\nOnCalendar=weekly\n");
    await put(root, "etc/systemd/system/x.timer.d/override.conf", "[Timer]\nOnCalendar=\nOnCalendar=minutely\n");
    await put(root, "etc/systemd/system/x.timer", "[Timer]\nOnCalendar=daily\n");
    const out = body(await tool(CRON, cwd, { root: "work/root" }));
    const files = (await rowsOf(cwd, out, "entries")).map((e) => String(e.file).replace(/^.*work\/root\//, ""));
    for (const f of ["home/alice/.config/systemd/user/sync.timer", "var/lib/svc/.config/systemd/user/job.timer", "root/.config/systemd/user/r.timer", "etc/systemd/user/shared.timer"]) {
      assert.ok(files.includes(f), `${f} is listed: ${files.join(", ")}`);
    }
    const sync = (await rowsOf(cwd, out, "entries")).find((e) => String(e.file).endsWith("sync.timer"));
    assert.equal(sync.manager, "user");
    assert.match(out.home_source, /^etc\/passwd and directory listing/);
    assert.ok(out.unmerged_dropins.some((d: Json) => String(d.file).endsWith("x.timer.d/override.conf")), "a drop-in is listed, not merged");
    assert.ok(out.unsupported.length >= 3, "what is not read is named");
    assert.ok(out.unsupported.some((u: string) => /at/.test(u)));
    assert.ok(out.locations.every((l: Json) => typeof l.path === "string" && typeof l.state === "string"), "a census of every place looked in");
    assert.ok(out.locations.some((l: Json) => l.state === "missing"));
  });
});

test("cron_dump keeps the cron line and its command as written, and answers without the command or the environment values", async () => {
  await withCwd(async (cwd) => {
    const root = join(cwd, "work", "root");
    await put(
      root,
      "etc/crontab",
      lines("SHELL=/bin/sh", `DB_PASSWORD=${CRON_SECRET}`, "# m h dom mon dow user command", "17 * * * * root cd / && run-parts --report /etc/cron.hourly", "*/5 * * * *   root   /usr/bin/backup   --target  /srv/data", "@reboot root /opt/x/start.sh"),
    );
    await put(root, "var/spool/cron/crontabs/alice", `*/10 * * * * /home/alice/bin/sync.sh --token=${SPOOL_SECRET}\n`);
    const run = await tool(CRON, cwd, { root: "work/root", limit: 1 });
    const out = body(run);
    const rows = await rowsOf(cwd, out, "entries");
    const backup = rows.find((e) => e.line === 5);
    assert.equal(backup.schedule, "*/5 * * * *");
    assert.equal(backup.user, "root");
    assert.equal(backup.file_modified.length > 0, true);
    assert.ok(backup.command_bytes === "/usr/bin/backup   --target  /srv/data".length);
    assert.deepEqual(backup.environment_keys, ["SHELL", "DB_PASSWORD"]);
    assert.ok(!("command" in backup) && !("environment" in backup) && !("raw_line" in backup));
    const all = await everythingBut(cwd, run.stdout, []);
    assert.ok(!all.includes(CRON_SECRET) && !all.includes(SPOOL_SECRET), "no environment value and no command text in the answer or the files it names");
    assert.match(refused(await tool(CRON, cwd, { root: "work/root", write_text: true })).error, /outside a job/);
    const job = body(await asJob(CRON, cwd, { root: "work/root", write_text: true }));
    const text = (await readFile(join(cwd, "out", "cron-text.jsonl"), "utf8")).trimEnd().split("\n").map((l) => JSON.parse(l));
    const row = text.find((t) => t.line === 5);
    assert.equal(row.command, "/usr/bin/backup   --target  /srv/data", "the command is the exact substring of the line, spacing and all");
    assert.equal(row.raw_line, "*/5 * * * *   root   /usr/bin/backup   --target  /srv/data");
    assert.equal(row.environment.DB_PASSWORD, CRON_SECRET);
    assert.ok(text.find((t) => t.user === "alice").command.includes(SPOOL_SECRET));
    assert.equal(job.text.written, text.length);
    assert.equal((await stat(join(cwd, "out", "cron-text.jsonl"))).mode & 0o777, 0o600);
  });
});

test("cron_dump says a file's mtime contrast is a lead and not a conclusion, and counts the cron lines it could not read", async () => {
  await withCwd(async (cwd) => {
    const root = join(cwd, "work", "root");
    await put(root, "etc/cron.d/odd", "this is not a cron line\n*/5 * * * * root /bin/true\n");
    const out = body(await tool(CRON, cwd, { root: "work/root" }));
    assert.doesNotMatch(out.note, /on its own/);
    assert.match(out.note, /corroborat/i);
    assert.equal(out.unparsed_lines, 1);
    assert.equal((await rowsOf(cwd, out, "unparsed"))[0].line, 1);
    assert.match(String(out.coverage_note), /candidate|not the effective/i);
  });
});

test("cron_dump derives a schedule, a unit and a persistence flag only from the sections it shows", async () => {
  await withCwd(async (cwd) => {
    const root = join(cwd, "work", "root");
    await put(root, "etc/systemd/system/x.timer", "[Service]\nOnCalendar=SECRETSCHEDULE\nUnit=SECRETUNIT\nPersistent=SECRETPERSIST\n[Timer]\nOnBootSec=5min\n");
    const run = await tool(CRON, cwd, { root: "work/root" });
    const [timer] = (await rowsOf(cwd, body(run), "entries")).filter((e) => e.source === "systemd");
    assert.deepEqual(timer.schedules, ["5min"]);
    assert.equal(timer.unit, "x.service");
    assert.equal(timer.persistent, null);
    assert.ok(timer.assignments.filter((a: Json) => a.section === "Service").every((a: Json) => a.value_withheld === true));
    assert.ok(!run.stdout.includes("SECRET"));
  });
});

test("cron_dump reads a comment that ends in a backslash as one line, so the assignment after it is kept", async () => {
  await withCwd(async (cwd) => {
    const root = join(cwd, "work", "root");
    await put(root, "etc/systemd/system/c.timer", "[Timer]\n# a comment that ends with a backslash \\\nOnCalendar=daily\n");
    const [timer] = (await rowsOf(cwd, body(await tool(CRON, cwd, { root: "work/root" })), "entries")).filter((e) => e.source === "systemd");
    assert.deepEqual(timer.assignments.map((a: Json) => [a.line, a.key, a.value]), [[3, "OnCalendar", "daily"]]);
  });
});

test("cron_dump looks in the home of an account the passwd file no longer lists", async () => {
  await withCwd(async (cwd) => {
    const root = join(cwd, "work", "root");
    await put(root, "etc/passwd", "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n");
    await put(root, "home/ghost/.config/systemd/user/evil.timer", "[Timer]\nOnBootSec=1min\n");
    const out = body(await tool(CRON, cwd, { root: "work/root" }));
    assert.ok((await rowsOf(cwd, out, "entries")).some((e) => String(e.file).endsWith("home/ghost/.config/systemd/user/evil.timer")));
    assert.ok(out.homes_beyond_passwd >= 1, "the homes the account database does not account for are counted");
  });
});

test("cron_dump keeps an answer short where a table sets thousands of variables and runs thousands of jobs", async () => {
  await withCwd(async (cwd) => {
    const root = join(cwd, "work", "root");
    const body_ = Array.from({ length: 1500 }, (_, i) => `VAR${i}=v${i}\n* * * * * root /bin/job${i}\n`).join("");
    await put(root, "etc/crontab", body_);
    const started = Date.now();
    const run = await asJob(CRON, cwd, { root: "work/root", write_text: true });
    assert.ok(Date.now() - started < 10_000);
    assert.ok(run.stdout.length < 400_000, `the answer is ${run.stdout.length} bytes`);
    const out = JSON.parse(run.stdout);
    assert.equal(out.entries_total, 1500);
    const text = (await readFile(join(cwd, "out", "cron-text.jsonl"), "utf8")).trimEnd().split("\n").map((l) => JSON.parse(l));
    assert.equal(text.filter((t: Json) => t.record_type === "environment").length, 1500, "every assignment is in the file once");
    const last = text.filter((t: Json) => t.source === "cron").at(-1);
    assert.equal(last.environment, undefined, "past 100 variables the entry points at the environment rows");
    assert.equal(last.environment_in_rows, true);
  });
});

test("cron_dump never opens a pipe it finds in a scheduling directory", async () => {
  await withCwd(async (cwd) => {
    const root = join(cwd, "work", "root");
    await put(root, "etc/cron.d/keep", "*/5 * * * * root /usr/bin/true\n");
    await mkdir(join(root, "etc", "systemd", "system"), { recursive: true });
    assert.equal(spawnSync("mkfifo", [join(root, "etc", "systemd", "system", "p.timer")]).status, 0);
    assert.equal(spawnSync("mkfifo", [join(root, "etc", "cron.d", "pipe")]).status, 0);
    const out = body(await tool(CRON, cwd, { root: "work/root" }));
    assert.equal(out.skipped_special.length, 2);
    assert.equal(out.all_checked_locations_read, false);
  });
});

test("cron_dump's preview carries the text in the answer and its paging file carries none", async () => {
  await withCwd(async (cwd) => {
    const root = join(cwd, "work", "root");
    await put(root, "etc/crontab", "*/5 * * * * root /bin/a PREVIEWSECRETONE\n*/6 * * * * root /bin/b PREVIEWSECRETTWO\n");
    const out = body(await asJob(CRON, cwd, { root: "work/root", preview_text: true, limit: 1 }));
    assert.ok(out.entries[0].command.includes("PREVIEWSECRETONE"));
    assert.equal(out.text.answer_contains_text_that_may_hold_secrets, true);
    for (const f of await filesUnder(join(cwd, "out"))) assert.ok(!(await readFile(join(cwd, "out", f), "utf8")).includes("PREVIEWSECRET"), f);
  });
});

test("cron_dump rejects arguments that are not an object and a field of the wrong type", async () => {
  await withCwd(async (cwd) => {
    for (const bad of [null, [], "x"]) assert.match(refused(await tool(CRON, cwd, bad)).error, /JSON object/);
    await mkdir(join(cwd, "work", "root"), { recursive: true });
    refused(await tool(CRON, cwd, { root: "work/root", contains: 5 }));
  });
});

test("cron_dump shows the value of a timer key only where the key is one a timer is scheduled by", async () => {
  await withCwd(async (cwd) => {
    const root = join(cwd, "work", "root");
    await put(root, "etc/systemd/system/v.timer", "[Unit]\nDescription=SECRETDESCRIPTION token\n[Timer]\nOnCalendar=daily\nEnvironment=API_TOKEN=SECRETENVVALUE\nPersistent=true\n[Install]\nWantedBy=timers.target\nAlias=SECRETALIAS.timer\n");
    const run = await tool(CRON, cwd, { root: "work/root" });
    const [timer] = (await rowsOf(cwd, body(run), "entries")).filter((e) => e.source === "systemd");
    const byKey = Object.fromEntries(timer.assignments.map((a: Json) => [a.key, a]));
    assert.equal(byKey.OnCalendar.value, "daily");
    assert.equal(byKey.Persistent.value, "true");
    assert.equal(byKey.WantedBy.value, "timers.target");
    assert.equal(byKey.Description.value_withheld, true);
    assert.equal(byKey.Description.value_bytes, "SECRETDESCRIPTION token".length);
    assert.equal(byKey.Environment.value_withheld, true);
    assert.ok(!run.stdout.includes("SECRETDESCRIPTION") && !run.stdout.includes("SECRETENVVALUE"));
    assert.equal(byKey.Alias.value, "SECRETALIAS.timer", "Alias= is an install key and is shown");
  });
});

test("cron_dump reads a directory that two paths reach once, and names the alias", async () => {
  await withCwd(async (cwd) => {
    const root = join(cwd, "work", "root");
    await put(root, "usr/lib/systemd/system/vendor.timer", "[Timer]\nOnCalendar=weekly\n");
    await symlink("usr/lib", join(root, "lib"));
    const out = body(await tool(CRON, cwd, { root: "work/root" }));
    assert.equal(out.entries_total, 1, "the same timer is not counted twice");
    assert.ok(out.locations.some((l: Json) => l.path === "lib/systemd/system" && /alias of usr\/lib\/systemd\/system/.test(l.state)), JSON.stringify(out.locations.filter((l: Json) => /systemd\/system$/.test(l.path))));
  });
});

test("cron_dump's contains matches the fields the answer shows outside a job and the command only in a job, and says which", async () => {
  await withCwd(async (cwd) => {
    const root = join(cwd, "work", "root");
    await put(root, "etc/crontab", "*/5 * * * * root /usr/bin/curl --token=h\n*/6 * * * * root /bin/true\n");
    const outside = body(await tool(CRON, cwd, { root: "work/root", contains: "--token=h" }));
    assert.equal(outside.entries_matched, 0);
    assert.equal(outside.pages.entries.matched, 0, "no count of matches on the text of a command");
    assert.equal(outside.filter_touched_withheld_text, false);
    assert.equal(body(await tool(CRON, cwd, { root: "work/root", contains: "root" })).entries_matched, 2);
    const inJob = body(await asJob(CRON, cwd, { root: "work/root", contains: "--token=h" }));
    assert.equal(inJob.entries_matched, 1);
    assert.equal(inJob.filter_touched_withheld_text, true);
  });
});

test("cron_dump stops at max_seconds, takes no NaN for a budget, and answers with an error where it cannot write", async () => {
  await withCwd(async (cwd) => {
    const root = join(cwd, "work", "root");
    await put(root, "etc/crontab", Array.from({ length: 400_000 }, (_, i) => `* * * * * root /bin/job${i}\n`).join(""));
    const slow = body(await tool(CRON, cwd, { root: "work/root", max_seconds: 0.3 }));
    assert.equal(slow.status, "partial");
    assert.match(String(slow.partial_reason), /max_seconds/);
    assert.equal(slow.all_checked_locations_read, false);
    for (const literal of ["NaN", "Infinity", "-1", "0"]) {
      const r = spawnSync("python3", [CRON], { cwd, input: `{"root":"work/root","max_seconds":${literal}}`, encoding: "utf8" });
      assert.equal(r.status, 1, literal);
    }
    if (!IS_ROOT) {
      const ro = join(cwd, "ro-out");
      await mkdir(ro, { recursive: true });
      await chmod(ro, 0o555);
      try {
        const bad = refused(await tool(CRON, cwd, { root: "work/root", write_text: true }, { JOB_ID: "j000077", OUT: ro }));
        assert.equal(bad.status, "failed");
      } finally {
        await chmod(ro, 0o755);
      }
    }
  });
});

test("cron_dump reads a table of three hundred thousand jobs line by line, with a byte offset on each", async () => {
  await withCwd(async (cwd) => {
    const root = join(cwd, "work", "root");
    const head = "X=1\n";
    const lines_ = Array.from({ length: 300_000 }, (_, i) => `* * * * * root /bin/job${i}\n`);
    await put(root, "etc/crontab", head + lines_.join(""));
    const run = await asJob(CRON, cwd, { root: "work/root", write_text: true, max_seconds: 40 });
    const out = body(run);
    assert.equal(out.entries_total, 300_000);
    const rows = await rowsOf(cwd, out, "entries");
    const expected = Buffer.byteLength(head + lines_.slice(0, 299_999).join(""));
    assert.equal(rows.at(-1).byte_offset, expected);
    assert.equal(rows.at(-1).line, 300_000 + 1);
    assert.ok(run.stdout.length < 100_000);
  });
});

test("cron_dump counts a unit line that is no assignment, reads a timer that starts with a byte order mark, and ignores a home path that leaves the root", async () => {
  await withCwd(async (cwd) => {
    const root = join(cwd, "work", "root");
    await put(root, "etc/systemd/system/bom.timer", "\ufeff[Timer]\nOnCalendar=daily\nthis line has no equals sign\n");
    await put(root, "etc/passwd", "evil:x:1:1::/../../etc:/bin/sh\ndot:x:2:2::/home/./x:/bin/sh\nok:x:3:3::/home/ok:/bin/sh\n");
    const out = body(await tool(CRON, cwd, { root: "work/root" }));
    const [timer] = (await rowsOf(cwd, out, "entries")).filter((e) => e.source === "systemd");
    assert.equal(timer.assignments[0].section, "Timer", "a byte order mark does not hide the section header");
    assert.equal(timer.lines_without_assignment, 1);
    assert.deepEqual(out.homes_ignored, ["/../../etc", "/home/./x"]);
    assert.ok(out.locations.some((l: Json) => l.path === "home/ok/.config/systemd/user"));
  });
});

test("cron_dump pages its census and names the run-parts files it does not enter", async () => {
  await withCwd(async (cwd) => {
    const root = join(cwd, "work", "root");
    await put(root, "etc/cron.daily/top", "#!/bin/sh\n", 0o755);
    await put(root, "etc/cron.daily/sub/nested", "#!/bin/sh\n", 0o755);
    const accounts = Array.from({ length: 450 }, (_, i) => `u${i}:x:${1000 + i}:${1000 + i}::/home/u${i}:/bin/sh`).join("\n") + "\n";
    await put(root, "etc/passwd", accounts);
    const out = body(await asJob(CRON, cwd, { root: "work/root" }));
    assert.equal(out.run_parts_files_in_subdirectories_not_listed, 1);
    assert.equal(out.locations.length, 200);
    assert.ok(out.pages.locations.matched > 800 && out.pages.locations.truncated);
    assert.ok(out.pages.locations.all_results);
    assert.equal(out.entries.filter((e: Json) => e.source === "run-parts").length, 1);
  });
});
