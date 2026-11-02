/**
 * The Linux pack: linux_persistence, against systemd's unit files (systemd.unit(5): sections, key=value lines, a trailing backslash that
 * continues a line, drop-ins in <unit>.d/*.conf applied in file-name order, an empty assignment that resets a list, links in .wants/ and
 * .requires/ directories for enablement, a link to /dev/null for a mask, a link to another unit for an alias, % specifiers in values),
 * crontab(5), the XDG autostart entry and rc.local. Every fixture is built by the test from those layouts, never from the tool's output.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdir, readFile, readdir, stat, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { TOOLS, asJob as plainJob, body, filesUnder, gone, put, refused, rowsOf, startDetached, tool, withCwd } from "./linux-pack-harness.ts";
import type { Json } from "./linux-pack-harness.ts";

const PERSIST = join(TOOLS, "linux_persistence", "run.py");
const asJob = (cwd: string, args: unknown, env: Record<string, string> = {}, outName = "out"): ReturnType<typeof plainJob> =>
  plainJob(PERSIST, cwd, args, undefined, { SECRET_OUTPUT: "1", ...env }, outName);
const ls = (...l: string[]): string => l.join("\n") + "\n";
const R = "work/r";

async function entries(cwd: string, out: Json): Promise<Json[]> {
  return rowsOf(cwd, out, "entries");
}
const kind = (rows: Json[], k: string): Json[] => rows.filter((r) => r.kind === k);
async function everything(cwd: string, skip: string[] = []): Promise<string> {
  const parts: string[] = [];
  for (const rel of await filesUnder(join(cwd, "out"))) if (!skip.includes(rel)) parts.push(await readFile(join(cwd, "out", rel), "utf8"));
  return parts.join("\n");
}

test("linux_persistence lists units, drop-ins that reset ExecStart=, masks, aliases and enablement links, keeps configuration and execution apart, and leaves the effective state unresolved", async () => {
  await withCwd(async (cwd) => {
    const sys = join(cwd, R, "etc/systemd/system");
    await put(sys, "foo.service", ls("[Unit]", "Description=foo", "", "[Service]", "Type=simple", "User=root", "ExecStart=/opt/app --flag", "Restart=always", "", "[Install]", "WantedBy=multi-user.target"));
    await put(sys, "foo.service.d/10-a.conf", ls("[Service]", "ExecStart=", "ExecStart=/bin/true"));
    await put(sys, "foo.service.d/20-b.conf", ls("[Service]", "Environment=X=1"));
    await put(sys, "foo.timer", ls("[Timer]", "OnCalendar=daily", "Persistent=true", "Unit=foo.service"));
    await put(sys, "foo.socket", ls("[Socket]", "ListenStream=0.0.0.0:2222", "Accept=no"));
    await put(sys, "foo.path", ls("[Path]", "PathExists=/tmp/go", "Unit=foo.service"));
    await mkdir(join(sys, "multi-user.target.wants"), { recursive: true });
    await symlink("../foo.service", join(sys, "multi-user.target.wants/foo.service"));
    await symlink("/dev/null", join(sys, "masked.service"));
    await symlink("foo.service", join(sys, "alias.service"));
    const out = body(await tool(PERSIST, cwd, { root: R }));
    const rows = await entries(cwd, out);
    const units = kind(rows, "unit");
    assert.deepEqual(units.map((u) => u.unit).sort(), ["foo.path", "foo.service", "foo.socket", "foo.timer"]);
    const foo = units.find((u) => u.unit === "foo.service") as Json;
    const exec = foo.configuration.assignments.find((a: Json) => a.key === "ExecStart");
    assert.deepEqual(exec.exec, { phase: "start", prefix_flags: "", words: 2, bytes: 15, empty: false });
    assert.equal(exec.value_withheld, true);
    assert.equal(exec.line, 7);
    assert.equal(exec.byte_offset, Buffer.byteLength(ls("[Unit]", "Description=foo", "", "[Service]", "Type=simple", "User=root")));
    assert.equal(foo.configuration.assignments.find((a: Json) => a.key === "Restart").value, "always");
    assert.equal(foo.configuration.assignments.find((a: Json) => a.key === "WantedBy").value, "multi-user.target");
    assert.equal(foo.execution, "not_attempted");
    assert.equal(foo.effective_state, "unresolved");
    // drop-ins in file-name order, the empty ExecStart= resets
    const drop = kind(rows, "dropin").sort((a, b) => a.dropin_order - b.dropin_order);
    assert.deepEqual(drop.map((d) => [d.file.split("/").at(-1), d.dropin_order, d.configuration.list_resets]), [["10-a.conf", 0, 1], ["20-b.conf", 1, 0]]);
    assert.equal(drop[0].unit, "foo.service");
    assert.equal(drop[0].configuration.assignments[0].resets_list, true);
    // timers, sockets and paths
    const timer = units.find((u) => u.unit === "foo.timer") as Json;
    assert.deepEqual(timer.configuration.assignments.map((a: Json) => a.value), ["daily", "true", "foo.service"]);
    assert.equal((units.find((u) => u.unit === "foo.socket") as Json).configuration.assignments[0].value, "0.0.0.0:2222");
    assert.equal((units.find((u) => u.unit === "foo.path") as Json).configuration.assignments[0].value, "/tmp/go");
    // links: enablement, mask, alias; never followed
    const links = Object.fromEntries(kind(rows, "link").map((l) => [l.name + ":" + l.link_kind, l]));
    assert.ok(links["foo.service:enablement"] && links["masked.service:mask"] && links["alias.service:alias"]);
    assert.equal(links["foo.service:enablement"].wanted_by_directory, "multi-user.target.wants");
    assert.equal(links["masked.service:mask"].target, "/dev/null");
    assert.equal(out.links.found, 3);
    assert.equal(out.effective_state.status, "unresolved");
    assert.equal(out.effective_state.why.length, 5);
    assert.match(out.effective_state.why.join(" "), /empty assignment resets/);
    assert.match(out.effective_state.why.join(" "), /systemctl cannot be asked about a disk/);
    assert.equal(out.execution.status, "not_attempted");
    assert.equal(out.status, "complete");
    assert.ok(out.locations.shown.some((l: Json) => l.path === "etc/systemd/system" && l.state === "read"));
    assert.ok(out.locations.shown.some((l: Json) => l.path === "run/systemd/system" && l.state === "missing"), "a place that is not there is named");
  });
});

test("linux_persistence says a copy with no links cannot show enablement, masks or aliases", async () => {
  await withCwd(async (cwd) => {
    await put(join(cwd, R), "etc/systemd/system/foo.service", ls("[Service]", "ExecStart=/bin/x"));
    await put(join(cwd, R), "etc/systemd/system/multi-user.target.wants/.keep", "");
    const out = body(await tool(PERSIST, cwd, { root: R }));
    assert.equal(out.links.found, 0);
    assert.match(out.links.note, /did not keep links/);
    assert.match(out.links.note, /cannot be read/);
  });
});

test("linux_persistence never prints an Exec line, an environment, a key name systemd does not define or a cron command, and writes them whole to the sealed text file only", async () => {
  await withCwd(async (cwd) => {
    const canaries = ["CANARYexecA1", "CANARYargB2", "CANARYenvC3", "CANARYkeyD4", "CANARYenvfileE5", "CANARYcronF6", "CANARYdeskG7", "CANARYlinkH8", "CANARYsecretI9", "CANARYsectionJ0"];
    const [exe, arg, env, key, envfile, cron, desk, link, secret, section] = canaries;
    const sys = join(cwd, R, "etc/systemd/system");
    await put(sys, "foo.service", ls(`[Service]`, `ExecStart=/opt/${exe}/run --token ${arg}`, `ExecStartPre=-/bin/${exe}`, `Environment="API=${env}" "B=2"`,
      `EnvironmentFile=-/etc/${envfile}`, `${key}=1`, `User=${secret}x y`, `WorkingDirectory=/srv/${secret}`, `Description=${secret}`, `[${section}]`, `a=b`));
    await put(sys, "foo.service.d/o.conf", ls("[Service]", `ExecStart=`, `ExecStart=/bin/${arg}`));
    await symlink(`/etc/${link}/target`, join(sys, "hostile.service"));
    await put(join(cwd, R), "etc/cron.d/job", ls(`PATH=/usr/bin:/${secret}`, `*/5 * * * * root /usr/bin/curl -u ${cron}:pw http://x`));
    await put(join(cwd, R), "etc/xdg/autostart/a.desktop", ls("[Desktop Entry]", "Type=Application", `Exec=/bin/${desk}`, "Hidden=false"));
    await put(join(cwd, R), "etc/rc.local", ls("#!/bin/sh", `/bin/${secret}`));
    const run = await asJob(cwd, { root: R, write_text: true, limit: 3 });
    const out = body(run);
    const text = await readFile(join(cwd, "out", "persistence-text.jsonl"), "utf8");
    const answer = run.stdout + run.stderr + (await everything(cwd, ["persistence-text.jsonl"])) + JSON.stringify(await filesUnder(join(cwd, "out")));
    for (const canary of canaries) assert.ok(!answer.includes(canary), `${canary} is in the answer, a paging file, stderr or a path`);
    for (const canary of [exe, arg, env, key, envfile, cron, desk, link, secret]) assert.ok(text.includes(canary), `${canary} is in the text file`);
    assert.equal((await stat(join(cwd, "out", "persistence-text.jsonl"))).mode & 0o777, 0o600);
    assert.equal(out.text.contains_text_that_may_hold_secrets, true);
    const all = await entries(cwd, out);
    const foo = kind(all, "unit")[0];
    const names = foo.configuration.assignments.map((a: Json) => a.key ?? "(withheld)");
    assert.ok(names.includes("(withheld)"), "a key name systemd does not define is a length");
    assert.ok(foo.configuration.assignments.some((a: Json) => a.key_withheld && a.key_bytes === key.length));
    assert.ok(foo.configuration.assignments.some((a: Json) => a.section_withheld && a.section_bytes === section.length));
    const environment = foo.configuration.assignments.find((a: Json) => a.key === "Environment");
    assert.deepEqual([environment.variables, environment.value_withheld], [2, true]);
    assert.equal(foo.configuration.assignments.find((a: Json) => a.key === "User").value, undefined, "a value that is not the shape of an account is a length");
    // the secrets' presence in the plain tool's answer
    const plain = body(await tool(PERSIST, cwd, { root: R }));
    assert.ok(!JSON.stringify(plain).includes(exe) && !JSON.stringify(plain).includes(cron));
  });
});

test("linux_persistence keeps write_text out of ordinary calls and refuses it, creating nothing, unless the job was run as secret output", async () => {
  await withCwd(async (cwd) => {
    await put(join(cwd, R), "etc/systemd/system/a.service", ls("[Service]", "ExecStart=/bin/x"));
    assert.match(refused(await tool(PERSIST, cwd, { root: R, write_text: true })).error, /write_text is refused outside a job/);
    assert.match(refused(await plainJob(PERSIST, cwd, { root: R, write_text: true })).error, /not run as secret output/);
    assert.deepEqual(await filesUnder(join(cwd, "out")), []);
    const manifest = JSON.parse(await readFile(join(TOOLS, "linux_persistence", "manifest.json"), "utf8"));
    assert.deepEqual(manifest.secret_output, { when_args: ["write_text"] });
    const ok = body(await asJob(cwd, { root: R, write_text: true }, {}, "out2"));
    assert.equal(ok.text.written, 1);
    assert.match(refused(await asJob(cwd, { root: R, write_text: true }, {}, "out2")).error, /already exists/);
  });
});

test("linux_persistence reads a unit directory reached twice through merged /usr once, and names the alias", async () => {
  await withCwd(async (cwd) => {
    await put(join(cwd, R), "usr/lib/systemd/system/a.service", ls("[Service]", "ExecStart=/bin/x"));
    await symlink("usr/lib", join(cwd, R, "lib"));
    const out = body(await tool(PERSIST, cwd, { root: R }));
    const rows = await entries(cwd, out);
    assert.equal(kind(rows, "unit").length, 1);
    const lib = out.locations.shown.find((l: Json) => l.path === "lib/systemd/system");
    assert.match(lib.state, /^(alias of usr\/lib\/systemd\/system|link or outside the root)/);
  });
});

test("linux_persistence does not follow a link loop, a link to the other end of a loop, or a link out of the root", async () => {
  await withCwd(async (cwd) => {
    const sys = join(cwd, R, "etc/systemd/system");
    await mkdir(sys, { recursive: true });
    await symlink("b.service", join(sys, "a.service"));
    await symlink("a.service", join(sys, "b.service"));
    await symlink(".", join(sys, "loop"));
    await symlink("../..", join(sys, "up"));
    await symlink("/etc", join(sys, "outside.service"));
    await symlink("/tmp", join(cwd, R, "etc/systemd/user"));
    const started = Date.now();
    const out = body(await tool(PERSIST, cwd, { root: R }));
    assert.ok(Date.now() - started < 10_000);
    const rows = await entries(cwd, out);
    assert.equal(kind(rows, "link").length, 5);
    assert.equal(kind(rows, "unit").length, 0);
    assert.ok(out.locations.shown.some((l: Json) => l.path === "etc/systemd/user" && /not followed/.test(l.state)));
  });
});

test("linux_persistence reads user units in the home of an account the passwd does not list, and says so", async () => {
  await withCwd(async (cwd) => {
    await put(join(cwd, R), "etc/passwd", "root:x:0:0::/root:/bin/bash\nbob:x:1000:1000::/home/bob:/bin/bash\n");
    await put(join(cwd, R), "home/bob/.config/systemd/user/b.service", ls("[Service]", "ExecStart=/bin/b"));
    await put(join(cwd, R), "home/ghost/.config/systemd/user/g.service", ls("[Service]", "ExecStart=/bin/g"));
    await put(join(cwd, R), "home/ghost/.config/autostart/g.desktop", ls("[Desktop Entry]", "Exec=/bin/g"));
    const out = body(await tool(PERSIST, cwd, { root: R }));
    const rows = await entries(cwd, out);
    const b = rows.find((r) => r.unit === "b.service") as Json;
    const g = rows.find((r) => r.unit === "g.service") as Json;
    assert.deepEqual([b.manager, b.home, b.account_in_passwd], ["user", "home/bob", true]);
    assert.deepEqual([g.manager, g.home, g.account_in_passwd], ["user", "home/ghost", false]);
    assert.equal(kind(rows, "autostart").length, 1);
    assert.equal(out.accounts.passwd_read, true);
  });
});

test("linux_persistence lists a unit over 8 MiB and does not read it, joins continued lines, and keeps % specifiers and invalid UTF-8 out of trouble", async () => {
  await withCwd(async (cwd) => {
    const sys = join(cwd, R, "etc/systemd/system");
    await mkdir(sys, { recursive: true });
    await writeFile(join(sys, "huge.service"), Buffer.concat([Buffer.from("[Service]\nExecStart=/bin/x\n"), Buffer.alloc(9 * 1024 * 1024, 0x23)]));
    await put(sys, "multi.service", ls("[Service]", "ExecStart=/bin/a \\", "   --b %i \\", "   --c %H", "# a comment \\", "Restart=on-failure", "WantedBy=getty@%i.service"));
    await writeFile(join(sys, "bad.service"), Buffer.concat([Buffer.from("[Service]\nExecStart=/bin/"), Buffer.from([0xff, 0xfe]), Buffer.from("\nUser=ro"), Buffer.from([0x80]), Buffer.from("t\n\xff\xfe=1\n", "latin1")]));
    const out = body(await tool(PERSIST, cwd, { root: R }));
    assert.equal(out.status, "partial");
    assert.equal(out.read_errors.total, 1);
    assert.match(out.read_errors.shown[0].error, /larger than the 8388608/);
    const rows = await entries(cwd, out);
    const multi = rows.find((r) => r.unit === "multi.service") as Json;
    const start = multi.configuration.assignments.find((a: Json) => a.key === "ExecStart");
    assert.deepEqual([start.line, start.last_line, start.exec.words], [2, 4, 5]);
    assert.equal(multi.configuration.assignments.find((a: Json) => a.key === "Restart").line, 6, "a comment line is not continued");
    assert.equal(multi.configuration.assignments.find((a: Json) => a.key === "WantedBy").value, "getty@%i.service");
    const bad = rows.find((r) => r.unit === "bad.service") as Json;
    assert.equal(bad.configuration.assignment_count, 3);
    assert.ok(bad.configuration.assignments.some((a: Json) => a.key_withheld), "a key that is not text systemd defines is a length");
  });
});

test("linux_persistence counts the rows of a journal_export records file that name a unit, and claims nothing about a unit they do not", async () => {
  await withCwd(async (cwd) => {
    await put(join(cwd, R), "etc/systemd/system/foo.service", ls("[Service]", "ExecStart=/bin/x"));
    await put(join(cwd, R), "etc/systemd/system/bar.service", ls("[Service]", "ExecStart=/bin/y"));
    await put(cwd, "work/rows.jsonl", [
      JSON.stringify({ unit: "foo.service", time: "2026-02-14T09:00:00Z" }), JSON.stringify({ unit: "foo.service", time: "2026-02-14T08:00:00Z" }),
      JSON.stringify({ user_unit: "u.service", time: "2026-02-14T10:00:00Z" }), "not json", JSON.stringify([1]), JSON.stringify({ unit: 5 }),
    ].join("\n") + "\n");
    const none = body(await tool(PERSIST, cwd, { root: R }));
    assert.equal(none.execution.status, "not_attempted");
    const out = body(await tool(PERSIST, cwd, { root: R, execution_rows: ["work/rows.jsonl"] }));
    assert.equal(out.execution.status, "read");
    assert.deepEqual(out.execution.per_unit.map((u: Json) => [u.unit, u.scope, u.rows, u.first_time, u.last_time]),
      [["foo.service", "system", 2, "2026-02-14T08:00:00Z", "2026-02-14T09:00:00Z"], ["u.service", "user", 1, "2026-02-14T10:00:00Z", "2026-02-14T10:00:00Z"]]);
    assert.equal(out.execution.listed_units, 2);
    assert.equal(out.execution.listed_units_named, 1);
    assert.equal(out.execution.files[0].rows_not_json, 1);
    assert.match(out.execution.note, /not shown to have been idle/);
    const missing = body(await tool(PERSIST, cwd, { root: R, execution_rows: ["work/none.jsonl"] }));
    assert.equal(missing.status, "partial");
    assert.equal(missing.execution.status, "partial");
  });
});

test("linux_persistence answers hostile arguments in JSON, refuses a file or a link as the root, and never opens a fifo", async () => {
  await withCwd(async (cwd) => {
    await put(join(cwd, R), "etc/systemd/system/a.service", ls("[Service]", "ExecStart=/bin/x"));
    spawnSync("mkfifo", [join(cwd, R, "etc/systemd/system/p.service")]);
    const cases: unknown[] = [{}, [], "x", { root: 5 }, { root: "" }, { root: "a\u0000b" }, { root: "\ud800" }, { root: "x".repeat(300) }, { root: R, limit: 0 }, { root: R, limit: "3" },
      { root: R, max_seconds: 0 }, { root: R, max_seconds: 10 ** 400 }, { root: R, execution_rows: "x" }, { root: R, execution_rows: [1] }, { root: R, execution_rows: Array.from({ length: 9 }, () => "x") },
      { root: R, write_text: 1 }, { root: "work/nope" }, { root: "work" + "/" + "r/etc/systemd/system/a.service" }];
    for (const args of cases) {
      const run = await tool(PERSIST, cwd, args);
      assert.doesNotMatch(run.stderr, /Traceback/, JSON.stringify(args).slice(0, 60));
      assert.equal(JSON.parse(run.stdout).status, "failed", JSON.stringify(args).slice(0, 60));
    }
    await symlink("r", join(cwd, "work", "rlink"));
    assert.match(refused(await tool(PERSIST, cwd, { root: "work/rlink" })).error, /not a link/);
    const nest = "[".repeat(100_000) + "]".repeat(100_000);
    const deep = spawnSync("python3", [PERSIST], { cwd, input: nest, encoding: "utf8" });
    assert.doesNotMatch(deep.stderr, /Traceback/);
    assert.equal(JSON.parse(deep.stdout).status, "failed");
    const started = Date.now();
    const out = body(await tool(PERSIST, cwd, { root: R }));
    assert.ok(Date.now() - started < 10_000, "a fifo does not hang the tool");
    assert.equal(out.not_regular.total, 1);
    await put(cwd, "work/disk.dd", Buffer.concat([Buffer.from("EVF\x09\x0d\x0a\xff\x00", "latin1"), Buffer.alloc(600)]));
    assert.match(refused(await tool(PERSIST, cwd, { root: "work/disk.dd" })).error, /disk image|not a link/);
  });
});

test("linux_persistence honours max_seconds on a directory of many units, says where it stopped, and an answer is one document", async () => {
  await withCwd(async (cwd) => {
    const sys = join(cwd, R, "etc/systemd/system");
    await mkdir(sys, { recursive: true });
    for (let i = 0; i < 20000; i++) await writeFile(join(sys, `u${String(i).padStart(5, "0")}.service`), "[Service]\nExecStart=/bin/x\n");
    const started = Date.now();
    const out = body(await tool(PERSIST, cwd, { root: R, max_seconds: 1, limit: 3 }));
    const took = (Date.now() - started) / 1000;
    assert.ok(took < 4.5, `took ${took}s`);
    assert.equal(out.status, "partial");
    assert.match(out.stopped_because, /max_seconds/);
    assert.ok(out.locations.shown.some((l: Json) => /stopped/.test(l.state)));
    const full = body(await tool(PERSIST, cwd, { root: R, max_seconds: 100, limit: 3 }));
    assert.equal(full.entries_total, 20000);
    assert.equal(full.status, "complete");
    assert.equal(full.truncated, true);
  });
});

for (const signal of ["SIGTERM", "SIGINT", "SIGHUP"] as const) {
  test(`linux_persistence ends on ${signal} with one last word naming the paging file it had begun`, async () => {
    await withCwd(async (cwd) => {
      const sys = join(cwd, R, "etc/systemd/system");
      await mkdir(sys, { recursive: true });
      const body1 = "[Service]\nExecStart=/bin/x\n";
      for (let i = 0; i < 30000; i++) await writeFile(join(sys, `u${String(i).padStart(5, "0")}.service`), body1);
      await mkdir(join(cwd, "out", "tool-output"), { recursive: true });
      const run = startDetached(PERSIST, cwd, { root: R, limit: 3 }, { JOB_ID: "j000001", OUT: join(cwd, "out") });
      const until = Date.now() + 90_000;
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
      assert.equal(word.stopped_by_signal, num);
      assert.equal(word.status, "failed");
      assert.deepEqual((await readdir(join(cwd, "out", "tool-output"))).filter((n) => n.startsWith(".")), []);
      assert.ok(word.paging_files_kept.entries);
    });
  });
}

test("linux_persistence gives JSON for a full disk and for an output directory it cannot write", async () => {
  await withCwd(async (cwd) => {
    const sys = join(cwd, R, "etc/systemd/system");
    await mkdir(sys, { recursive: true });
    for (let i = 0; i < 600; i++) await writeFile(join(sys, `u${i}.service`), `[Service]\nExecStart=/bin/x${"y".repeat(100)}\n`);
    await mkdir(join(cwd, "out"), { recursive: true });
    const env = { ...process.env, AGENT_ID: "s1", JOB_ID: "j000001", OUT: join(cwd, "out"), SECRET_OUTPUT: "1" };
    // a file size limit of 16 blocks: the paging file cannot grow past it
    const full = spawnSync("bash", ["-c", `ulimit -f 16; exec python3 ${PERSIST}`], { cwd, input: JSON.stringify({ root: R, limit: 2, write_text: true }), encoding: "utf8", env });
    assert.doesNotMatch(full.stderr, /Traceback/);
    const doc = JSON.parse(full.stdout);
    assert.equal(doc.status, "failed");
    assert.notEqual(full.status, 0);
    const missing = spawnSync("python3", [PERSIST], { cwd, input: JSON.stringify({ root: R, limit: 2 }), encoding: "utf8", env: { ...env, OUT: "/proc/nowhere" } });
    assert.doesNotMatch(missing.stderr, /Traceback/);
    assert.equal(JSON.parse(missing.stdout).status, "failed");
  });
});

test("linux_persistence's manifest declares what the script reads, carries the script's sha256 and the version PARSER names", async () => {
  const manifest = JSON.parse(await readFile(join(TOOLS, "linux_persistence", "manifest.json"), "utf8"));
  const script = await readFile(PERSIST);
  assert.equal(manifest.sha256, createHash("sha256").update(script).digest("hex"));
  assert.match(script.toString("utf8"), new RegExp(`^PARSER = "linux_persistence/${manifest.version}"$`, "m"));
  assert.match(manifest.description, /`status`.*`status_basis`/);
  for (const key of ["root", "execution_rows", "limit", "max_seconds", "write_text"]) assert.ok(key in manifest.params, key);
  assert.match(String(script.toString("utf8").match(/^MAX_SECONDS = [0-9.]+/m)), /MAX_SECONDS = 105/);
  assert.ok(105 < manifest.timeout_seconds);
});
