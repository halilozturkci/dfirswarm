/**
 * The Linux pack: shell_history, against Bash's HISTTIMEFORMAT file (a `#<epoch>` line before each entry, an
 * entry running until the next stamp), zsh's EXTENDED_HISTORY (`: <epoch>:<elapsed>;<command>`, a newline
 * inside a command written after a backslash), fish's history (`- cmd:` and `  when:`) and plain client
 * histories.
 * Every fixture is built by the test from the format's own layout, never from a tool's output.
 *
 * The tools that read command lines, messages or environments follow the secret-safe output pattern of
 * recovery_key_scan (docs/packs.md, "Secrets and sensitive output"): the answer is locators and structured
 * fields, and the text is written only on request, only in a job, only to a file under $OUT. What the answer
 * and the files it names hold is checked here for a planted secret.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmod, mkdir, readFile, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { IS_ROOT, SHELL, asJob, body, everythingBut, filesUnder, lines, put, refused, rowsOf, tool, withCwd } from "./linux-pack-harness.ts";
import type { Json } from "./linux-pack-harness.ts";

const HIST_SECRET = "HistoryPw12345";

test("shell_history keeps a multi-line bash entry whole, stamped once, and says where its physical lines are", async () => {
  await withCwd(async (cwd) => {
    const root = join(cwd, "work", "ev");
    await put(root, "home/alice/.bash_history", lines("#1700000000", "ls -la", "#1700000005", "for i in 1 2; do", "  echo $i", "done", "#1700000010", "uname -a"));
    const out = body(await asJob(SHELL, cwd, { root: "work/ev" }));
    const rows = await rowsOf(cwd, out);
    assert.equal(rows.length, 3);
    assert.deepEqual(rows.map((r) => r.command_lines), [1, 3, 1]);
    assert.equal(rows[1].time, "2023-11-14T22:13:25Z");
    assert.equal(rows[1].time_raw, "1700000005");
    assert.deepEqual([rows[1].line_start, rows[1].line_end], [3, 6]);
    assert.equal(rows[1].boundary_basis, "bash timestamp line");
    assert.equal(out.files[0].format, "bash");
    assert.equal(out.files[0].physical_lines, 8);
  });
});

test("shell_history reads a zsh extended entry with a continuation as one command, and fish and client histories in their own forms", async () => {
  await withCwd(async (cwd) => {
    const root = join(cwd, "work", "ev");
    await put(root, "home/bob/.zsh_history", lines(": 1700000000:3;echo one", ": 1700000100:0;for i in 1 2; do\\", "echo $i\\", "done", ": 1700000200:1;pwd"));
    await put(root, "home/bob/.local/share/fish/fish_history", lines("- cmd: ls -la", "  when: 1700000300", "- cmd: echo a\\nb", "  when: 1700000400", "  paths:", "    - a"));
    await put(root, "home/bob/.mysql_history", lines("select\\0401;", "show\\040tables;"));
    await put(root, "home/bob/.lesshst", lines(".less-history-file:", ".search", '"needle'));
    const out = body(await asJob(SHELL, cwd, { root: "work/ev" }));
    const rows = await rowsOf(cwd, out);
    const zsh = rows.filter((r) => r.format === "zsh");
    assert.equal(zsh.length, 3);
    assert.deepEqual(zsh.map((r) => r.command_lines), [1, 3, 1]);
    assert.equal(zsh[1].time, "2023-11-14T22:15:00Z");
    assert.equal(zsh[0].elapsed_seconds, 3);
    assert.deepEqual([zsh[1].line_start, zsh[1].line_end], [2, 4]);
    const fish = rows.filter((r) => r.format === "fish");
    assert.equal(fish.length, 2);
    assert.equal(fish[1].command_lines, 2, "fish writes a newline inside a command as \\n");
    assert.equal(fish[1].time, "2023-11-14T22:20:00Z");
    const client = rows.filter((r) => r.format === "plain");
    assert.equal(client.length, 2);
    assert.ok(client.every((r) => r.time === null && r.boundary_basis === "physical line"));
    assert.ok(out.not_parsed_files.some((f: Json) => String(f.file).endsWith(".lesshst")), "less's state file is named, not read as commands");
  });
});

test("shell_history does not take a directory name for an account", async () => {
  await withCwd(async (cwd) => {
    const root = join(cwd, "work", "ev");
    await put(root, "root/.bash_history", lines("whoami"));
    await put(root, "home/alice/.bash_history", lines("id"));
    await put(root, "home/ghost/.bash_history", lines("id"));
    // With no account database the owner is unknown, and the directory's name is the only thing said.
    const bare = body(await asJob(SHELL, cwd, { root: "work/ev" }));
    const rootRow = (await rowsOf(cwd, bare)).find((r) => r.home === join(cwd, "work", "ev", "root") || String(r.home).endsWith("/root"));
    assert.equal(rootRow.user, "unknown");
    assert.equal(rootRow.home_basename, "root");
    assert.ok((await rowsOf(cwd, bare)).every((r) => r.user === "unknown"));
    // With the evidence's passwd, a home path that an account owns names it, and says where from.
    await put(root, "etc/passwd", "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n");
    const resolved = body(await asJob(SHELL, cwd, { root: "work/ev" }, undefined, {}, "out2"));
    const rows = await rowsOf(cwd, resolved);
    const user = (name: string): string => rows.find((r) => String(r.home).endsWith(`/${name}`)).user;
    assert.equal(user("root"), "root");
    assert.equal(user("alice"), "alice");
    assert.equal(user("ghost"), "unknown", "a home no account owns has no owner");
    assert.match(rows.find((r) => String(r.home).endsWith("/alice")).user_source, /etc\/passwd:2$/);
  });
});

test("shell_history answers without command text, and the text goes to a job's file only on request", async () => {
  await withCwd(async (cwd) => {
    const root = join(cwd, "work", "ev");
    await put(root, "home/alice/.bash_history", lines("#1700000000", `mysql -uroot -p${HIST_SECRET}`, "#1700000001", "ls", "#1700000002", "id"));
    await put(root, "home/alice/.mysql_history", lines(`alter user root identified by '${HIST_SECRET}x';`));
    for (const run of [await tool(SHELL, cwd, { root: "work/ev", limit: 1 }), await asJob(SHELL, cwd, { root: "work/ev", limit: 1 })]) {
      const out = body(run);
      assert.ok(out.records.length === 1 && !("command" in out.records[0]));
      assert.ok(out.records[0].command_bytes > 0);
      assert.equal(out.text.written, 0);
      assert.ok(!(await everythingBut(cwd, run.stdout, [])).includes(HIST_SECRET), "no command text reaches the answer or any file it names");
    }
    assert.match(refused(await tool(SHELL, cwd, { root: "work/ev", write_commands: true })).error, /outside a job/);
    assert.match(refused(await tool(SHELL, cwd, { root: "work/ev", preview_commands: true })).error, /outside a job/);
    const job = await asJob(SHELL, cwd, { root: "work/ev", write_commands: true, limit: 1 });
    const out = body(job);
    assert.ok(!job.stdout.includes(HIST_SECRET));
    assert.match(out.text.file, /out\/shell-history-commands\.jsonl$/);
    assert.equal((await stat(join(cwd, "out", "shell-history-commands.jsonl"))).mode & 0o777, 0o600);
    const text = (await readFile(join(cwd, "out", "shell-history-commands.jsonl"), "utf8")).trimEnd().split("\n").map((l) => JSON.parse(l));
    assert.equal(text.length, 4);
    assert.ok(text.some((t) => String(t.command).includes(`-p${HIST_SECRET}`)));
    assert.equal(text.find((t) => t.id === out.records[0].id).command, text[0].command);
    // The preview carries the text in the answer, in a job.
    const preview = body(await asJob(SHELL, cwd, { root: "work/ev", preview_commands: true, limit: 2 }, undefined, {}, "out3"));
    assert.ok(preview.records.some((r: Json) => String(r.command).includes(HIST_SECRET)));
  });
});

test("shell_history walks into a directory called dev or proc below the top, names what it left out, and names what it could not open", async () => {
  await withCwd(async (cwd) => {
    const root = join(cwd, "work", "ev");
    await put(root, "proc/1/.bash_history", lines("not evidence"));
    await put(root, "home/alice/dev/.bash_history", lines("a project directory called dev"));
    await put(root, "home/alice/.bash_history", lines("id"));
    if (!IS_ROOT) {
      await put(root, "home/locked/.bash_history", lines("id"));
      await chmod(join(root, "home", "locked"), 0o000);
    }
    try {
      const out = body(await asJob(SHELL, cwd, { root: "work/ev" }));
      const files = out.files.map((f: Json) => String(f.file).replace(/^.*work\/ev\//, ""));
      assert.ok(files.includes("home/alice/dev/.bash_history"), `a dev directory below the top is read: ${files.join(", ")}`);
      assert.ok(!files.some((f: string) => f.startsWith("proc/")));
      assert.deepEqual(out.excluded_dirs.map((d: Json) => d.path.replace(/^.*work\/ev\//, "")), ["proc"]);
      if (!IS_ROOT) {
        assert.ok(out.walk_errors.some((e: Json) => String(e.path).endsWith("home/locked")), JSON.stringify(out.walk_errors));
        assert.equal(out.all_files_read, false);
      }
    } finally {
      if (!IS_ROOT) await chmod(join(root, "home", "locked"), 0o755);
    }
  });
});

test("shell_history flags a bash entry that ends in a backslash and a file whose content is another shell's format", async () => {
  await withCwd(async (cwd) => {
    const root = join(cwd, "work", "ev");
    await put(root, "home/alice/.bash_history", lines("echo one \\", "two", ": 1700000000:0;this is a zsh header"));
    const out = body(await asJob(SHELL, cwd, { root: "work/ev" }));
    const rows = await rowsOf(cwd, out);
    assert.equal(rows[0].continuation_uncertain, true);
    assert.equal(rows[0].boundary_basis, "physical line");
    assert.equal(out.files[0].looks_like_other_format, "zsh extended history");
  });
});

test("shell_history continues a record past its size cap in the next one, flagged, and drops no line", async () => {
  await withCwd(async (cwd) => {
    const root = join(cwd, "work", "ev");
    const line = "x".repeat(50_000) + "\\";
    await put(root, "home/alice/.zsh_history", `: 1700000000:0;${Array.from({ length: 200 }, () => line).join("\n")}\nend\n`);
    const out = body(await asJob(SHELL, cwd, { root: "work/ev", write_commands: true }));
    const rows = await rowsOf(cwd, out);
    assert.ok(rows.length >= 2, "a 10 MB entry is more than one record");
    assert.ok(rows.slice(1).every((r) => r.split_at_cap === true), "the continuation is flagged");
    assert.equal(rows[0].split_at_cap, undefined);
    const text = (await readFile(join(cwd, "out", "shell-history-commands.jsonl"), "utf8")).trimEnd().split("\n").map((l) => JSON.parse(l));
    assert.equal(text.reduce((n: number, t: Json) => n + t.record_lines.length, 0), 201, "every physical line is in exactly one record");
  });
});

test("shell_history ends a zsh entry only at a line that does not continue it, and takes a huge elapsed field for no duration", async () => {
  await withCwd(async (cwd) => {
    const root = join(cwd, "work", "ev");
    await put(root, "home/alice/.zsh_history", lines(": 1700000000:0;echo a\\", "", ": 1700000100:0;echo b", `: 1700000200:${"9".repeat(5000)};ls`));
    const rows = await rowsOf(cwd, body(await asJob(SHELL, cwd, { root: "work/ev" })));
    assert.equal(rows.length, 3, "an empty line after a backslash is inside the command, and the next header starts the next entry");
    assert.deepEqual([rows[0].line_start, rows[0].line_end, rows[0].command_lines], [1, 2, 2]);
    assert.equal(rows[1].time_raw, "1700000100");
    assert.equal(rows[2].elapsed_seconds, undefined);
    assert.match(String(rows[2].time_error), /elapsed/);
  });
});

test("shell_history keeps trailing blank lines out of a stamped entry, and reads a line longer than a piece as one line in pieces", async () => {
  await withCwd(async (cwd) => {
    const root = join(cwd, "work", "ev");
    await put(root, "home/alice/.bash_history", lines("#1700000000", "id", "", "", "#1700000001", "pwd", ""));
    await put(root, "home/alice/.python_history", `${"x".repeat(9 * 1024 * 1024)}\nshort\n`);
    const out = body(await asJob(SHELL, cwd, { root: "work/ev", write_commands: true }));
    const text = (await readFile(join(cwd, "out", "shell-history-commands.jsonl"), "utf8")).trimEnd().split("\n").map((l) => JSON.parse(l));
    const bash = text.filter((t: Json) => t.format === "bash");
    assert.deepEqual(bash.map((t: Json) => t.command), ["id", "pwd"]);
    assert.deepEqual([bash[0].line_start, bash[0].line_end], [1, 2]);
    const python = text.filter((t: Json) => t.format === "plain");
    assert.ok(python.length >= 3, "the long line is more than one record, then the short one");
    assert.ok(python.slice(0, 2).every((t: Json) => t.split_at_cap === true), "every piece of it is flagged");
    assert.equal(out.files.find((f: Json) => f.format === "plain").physical_lines, 2, "a line read in pieces is still one physical line");
  });
});

test("shell_history reads a very long stamped entry in time that follows its length, and stops at its deadline inside a file", async () => {
  await withCwd(async (cwd) => {
    const root = join(cwd, "work", "ev");
    await put(root, "home/alice/.bash_history", `#1700000000\n${"ls\n".repeat(120_000)}`);
    const started = Date.now();
    const out = body(await asJob(SHELL, cwd, { root: "work/ev" }));
    assert.ok(Date.now() - started < 8000, `took ${Date.now() - started} ms`);
    assert.equal(out.files[0].records, 1);
    assert.equal(out.records[0].command_lines, 120_000);
  });
});

test("shell_history never opens a pipe named like a history file, and its paging file holds no preview text", async () => {
  await withCwd(async (cwd) => {
    const root = join(cwd, "work", "ev");
    await put(root, "home/alice/.bash_history", lines("echo PREVIEWSECRETONE", "echo PREVIEWSECRETTWO"));
    assert.equal(spawnSync("mkfifo", [join(root, "home", "alice", ".zsh_history")]).status, 0);
    const out = body(await asJob(SHELL, cwd, { root: "work/ev", preview_commands: true, limit: 1 }));
    assert.equal(out.skipped_special.length, 1);
    assert.equal(out.all_files_read, false);
    assert.ok(out.records[0].command.includes("PREVIEWSECRETONE"));
    for (const f of await filesUnder(join(cwd, "out"))) assert.ok(!(await readFile(join(cwd, "out", f), "utf8")).includes("PREVIEWSECRET"), f);
  });
});

test("shell_history rejects arguments that are not an object and a field of the wrong type", async () => {
  await withCwd(async (cwd) => {
    for (const bad of [null, [], "x"]) assert.match(refused(await tool(SHELL, cwd, bad)).error, /JSON object/);
    await mkdir(join(cwd, "work", "ev"), { recursive: true });
    for (const args of [{ root: "work/ev", contains: 5 }, { root: "work/ev", user: 5 }, { root: "work/ev", passwd: 5 }, { root: 5 }]) refused(await tool(SHELL, cwd, args));
  });
});

test("shell_history's contains matches the fields the answer shows outside a job and the command only in a job, and says which", async () => {
  await withCwd(async (cwd) => {
    const root = join(cwd, "work", "ev");
    await put(root, "home/alice/.bash_history", lines("curl --token=h https://example.invalid/", "ls"));
    const outside = body(await tool(SHELL, cwd, { root: "work/ev", contains: "--token=h" }));
    assert.equal(outside.record_count, 0, "no oracle on the text of a command outside a job");
    assert.equal(outside.filter_touched_withheld_text, false);
    assert.match(outside.contains_scope, /fields the answer shows/);
    assert.equal(body(await tool(SHELL, cwd, { root: "work/ev", contains: "alice" })).record_count, 2, "a shown field is matched");
    const inJob = body(await asJob(SHELL, cwd, { root: "work/ev", contains: "--token=h" }));
    assert.equal(inJob.record_count, 1);
    assert.equal(inJob.filter_touched_withheld_text, true);
    assert.equal(inJob.pages.records.matched, 1);
  });
});

test("shell_history keeps a password that is not UTF-8 whole in the sealed file, and counts its bytes, and one CR of two", async () => {
  await withCwd(async (cwd) => {
    const root = join(cwd, "work", "ev");
    await put(root, "home/alice/.bash_history", Buffer.concat([Buffer.from("mysql -uroot -pcaf"), Buffer.from([0xe9, 0xff]), Buffer.from("x\r\r\nls\n")]));
    const out = body(await asJob(SHELL, cwd, { root: "work/ev", write_commands: true }));
    const raw = await readFile(join(cwd, "out", "shell-history-commands.jsonl"), "utf8");
    assert.ok(raw.includes("\\udce9\\udcff"), "the bytes that are not UTF-8 are in the file as escapes that read back as them");
    const [first] = raw.trimEnd().split("\n").map((l) => JSON.parse(l));
    assert.equal(first.command, "mysql -uroot -pcaf\udce9\udcffx\r");
    assert.equal(out.records[0].command_bytes, "mysql -uroot -pcaf".length + 2 + "x\r".length);
    assert.match(body(await asJob(SHELL, cwd, { root: "work/ev" }, undefined, {}, "out-hint")).text.hint, /write_commands/);
  });
});

test("shell_history reads twenty million-less blank lines inside a stamped entry without holding them, and stops at max_seconds on lines that are only stamps", async () => {
  await withCwd(async (cwd) => {
    const root = join(cwd, "work", "ev");
    await put(root, "home/alice/.bash_history", `#1700000000\nid\n${"\n".repeat(4_000_000)}#1700000001\npwd\n`);
    const started = Date.now();
    const out = body(await asJob(SHELL, cwd, { root: "work/ev" }));
    assert.ok(Date.now() - started < 30_000, `took ${Date.now() - started} ms`);
    assert.equal(out.files[0].blank_lines, 4_000_000);
    assert.equal(out.files[0].records, 2);
    await put(root, "home/alice/.bash_history", "#1700000000\n".repeat(3_000_000));
    const slow = body(await asJob(SHELL, cwd, { root: "work/ev", max_seconds: 0.3 }, undefined, {}, "out-slow"));
    assert.equal(slow.status, "partial");
    assert.match(String(slow.partial_reason), /max_seconds/);
  });
});

test("shell_history answers with an error, not a traceback, where its output cannot be written or a directory cannot be searched, and takes no NaN for a budget", async () => {
  await withCwd(async (cwd) => {
    const root = join(cwd, "work", "ev");
    await put(root, "home/alice/.bash_history", lines("id"));
    if (!IS_ROOT) {
      const ro = join(cwd, "ro-out");
      await mkdir(ro, { recursive: true });
      await chmod(ro, 0o555);
      try {
        const bad = refused(await tool(SHELL, cwd, { root: "work/ev", write_commands: true }, { JOB_ID: "j000088", OUT: ro }));
        assert.equal(bad.status, "failed");
        assert.match(bad.error, /text file could not be created/);
        const bad2 = refused(await tool(SHELL, cwd, { root: "work/ev", limit: 1 }, { JOB_ID: "j000089", OUT: ro }).then(async (r) => (r.code === 0 ? tool(SHELL, cwd, { root: "work/ev", limit: 0 }, { JOB_ID: "j000089", OUT: ro }) : r)));
        assert.ok(bad2.error);
      } finally {
        await chmod(ro, 0o755);
      }
      await put(root, "home/closed/.bash_history", lines("id"));
      await chmod(join(root, "home", "closed"), 0o444);
      try {
        const out = body(await asJob(SHELL, cwd, { root: "work/ev" }, undefined, {}, "out-closed"));
        assert.ok(out.walk_errors.some((e: Json) => String(e.path).endsWith("closed/.bash_history")), JSON.stringify(out.walk_errors));
        assert.equal(out.status, "partial");
      } finally {
        await chmod(join(root, "home", "closed"), 0o755);
      }
    }
    for (const literal of ["NaN", "Infinity", "-1", "0", "100000"]) {
      const r = spawnSync("python3", [SHELL], { cwd, input: `{"root":"work/ev","max_seconds":${literal}}`, encoding: "utf8" });
      assert.equal(r.status, 1, `max_seconds ${literal}: ${r.stdout}`);
      assert.match(JSON.parse(r.stdout).error, /max_seconds/);
    }
  });
});

test("shell_history names owners from a passwd file the caller gives when the root is a file system root, and says where it read it", async () => {
  await withCwd(async (cwd) => {
    const root = join(cwd, "work", "ev");
    await put(root, "etc/hostname", "x\n");
    await put(root, "home/alice/.bash_history", lines("id"));
    await writeFile(join(cwd, "work", "other-passwd"), "root:x:0:0::/root:/bin/sh\nalice:x:1000:1000::/home/alice:/bin/sh\n");
    const out = body(await asJob(SHELL, cwd, { root: "work/ev", passwd: "work/other-passwd" }));
    assert.equal(out.records[0].user, "alice");
    assert.match(out.records[0].user_source, /other-passwd:2$/);
    assert.equal(out.passwd.read_as_file_system_root, true);
    // A tree with no etc/ is not a file system root unless the caller says so.
    const home = join(cwd, "work", "homes");
    await put(home, "alice/.bash_history", lines("id"));
    const bare = body(await asJob(SHELL, cwd, { root: "work/homes", passwd: "work/other-passwd" }, undefined, {}, "out-bare"));
    assert.equal(bare.records[0].user, "unknown");
    assert.match(bare.passwd.notes.join(" "), /root_is_file_system_root/);
    const said = body(await asJob(SHELL, cwd, { root: "work/homes", passwd: "work/other-passwd", root_is_file_system_root: true }, undefined, {}, "out-said"));
    assert.equal(said.records[0].user, "unknown", "a home directory's path /alice is not the account's /home/alice");
  });
});
