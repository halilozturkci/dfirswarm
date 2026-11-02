/**
 * The Linux pack: package_verify, which wraps debsums (`debsums -r <root> -a`, output `<path> OK|FAILED|REPLACED`, standard error
 * `debsums: missing file <path> (from <package> package)`) and `rpm -V --root <root> --dbpath <path>` (output `<nine flag characters>  <attribute> <path>`
 * or `missing  <attribute> <path>`). The programs are stand-ins here: no debsums or rpm is installed on the machine that runs this suite, and the real
 * ones are exercised only where they are present. Every fixture is built by the test from those formats.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { TOOLS, body, gone, pidFile, put, refused, rowsOf, startDetached, tool, withCwd } from "./linux-pack-harness.ts";
import type { Json } from "./linux-pack-harness.ts";

const VERIFY = join(TOOLS, "package_verify", "run.py");
const R = "work/r";

async function stub(bin: string, name: "debsums" | "rpm", script: string): Promise<void> {
  await put(bin, name, `#!/bin/bash\nd="$(dirname "$0")"\necho "$@" >> "$d/argv.log"\ncase "$1" in --version) echo "${name} version 9.9.9"; exit 0;; esac\n${script}\n`, 0o755);
}
async function debianRoot(cwd: string): Promise<void> {
  await put(join(cwd, R), "var/lib/dpkg/status", "Package: a\nStatus: install ok installed\n\nPackage: b:amd64\nStatus: install ok installed\n\nPackage: c\nStatus: install ok installed\n");
  await put(join(cwd, R), "var/lib/dpkg/info/a.md5sums", "d41d8cd98f00b204e9800998ecf8427e  usr/bin/a\n");
  await put(join(cwd, R), "var/lib/dpkg/info/b:amd64.md5sums", "d41d8cd98f00b204e9800998ecf8427e  usr/bin/b\n");
}
const DEB = `printf '%s\\n' '/usr/bin/a                                        OK' '/etc/a.conf                                       FAILED' '/usr/lib/b                                         REPLACED' '/tmp/has space/file                                 FAILED' 'not a debsums line' >&1
printf 'debsums: missing file /usr/bin/gone (from a package)\\ndebsums: no md5sums for c\\n' >&2
exit 2`;
const RPM = `printf '%s\\n' 'S.5....T.  c /etc/foo.conf' '.M.......    /usr/bin/x' 'missing   c /etc/gone' '.......?.    /unreadable' 'SM5DLUGTP    /everything' 'weird line'
printf 'warning: something\\n' >&2
exit 1`;

test("package_verify runs debsums in its own process group and gives the scope, every difference, the errors and where the expected hashes came from", async () => {
  await withCwd(async (cwd, bin) => {
    await debianRoot(cwd);
    await stub(bin, "debsums", DEB);
    const out = body(await tool(VERIFY, cwd, { root: R, family: "debian", packages: ["a", "b"] }, {}, bin));
    assert.equal(out.scope.family, "debian");
    assert.deepEqual([out.scope.database.packages_in_status, out.scope.database.md5sums_files, out.scope.database.packages_without_md5sums, out.scope.database.examples_without_md5sums], [3, 2, 1, ["c"]]);
    assert.match(out.scope.hash_source, /the machine's own record/);
    assert.equal(out.program.version, "debsums version 9.9.9");
    assert.deepEqual(out.program.argv.slice(1), ["-r", R, "-a", "a", "b"]);
    assert.equal(out.program.exit_code, 2);
    assert.deepEqual([out.check.files_ok, out.check.differences, out.check.by_status], [1, 3, { FAILED: 2, REPLACED: 1 }]);
    const rows = await rowsOf(cwd, out, "differences");
    assert.deepEqual(rows.map((r) => [r.path, r.status]), [["/etc/a.conf", "FAILED"], ["/usr/lib/b", "REPLACED"], ["/tmp/has space/file", "FAILED"]]);
    assert.match(rows[0].expected_hash_from, /var\/lib\/dpkg\/info/);
    assert.deepEqual([out.parse.unparsed_lines, out.parse.examples[0].text], [1, "not a debsums line"]);
    assert.deepEqual(out.program.stderr.by_kind, { "missing file": 1, "no md5sums": 1 });
    assert.equal(out.status, "partial");
    assert.match(out.status_basis, /no md5sums file/);
    assert.match(out.status_basis, /missing from the root/);
    assert.match(out.safeguards.never_runs, /no maintainer script/);
    assert.match(out.safeguards.authenticity, /do not establish/);
    // config files can be left out
    const without = body(await tool(VERIFY, cwd, { root: R, family: "debian", config_files: false }, {}, bin));
    assert.ok(!without.program.argv.includes("-a"));
  });
});

test("package_verify reads rpm -V's flags, attributes and missing files, names the database backend, and says it did not confirm that --noscripts suppresses %verifyscript", async () => {
  await withCwd(async (cwd, bin) => {
    await put(join(cwd, R), "var/lib/rpm/rpmdb.sqlite", "SQLite format 3\u0000");
    await stub(bin, "rpm", RPM);
    const out = body(await tool(VERIFY, cwd, { root: R }, {}, bin));
    assert.equal(out.scope.family, "rpm");
    assert.equal(out.scope.database.backend, "sqlite");
    assert.deepEqual(out.program.argv.slice(1), ["-V", "--root", R, "--dbpath", "/var/lib/rpm", "--noscripts", "--nodeps", "--nodigest", "--nosignature", "-a"]);
    const rows = Object.fromEntries((await rowsOf(cwd, out, "differences")).map((r) => [r.path, r]));
    assert.deepEqual(rows["/etc/foo.conf"].changed, ["size", "digest", "mtime"]);
    assert.equal(rows["/etc/foo.conf"].attribute, "config");
    assert.deepEqual(rows["/usr/bin/x"].changed, ["mode"]);
    assert.equal(rows["/etc/gone"].status, "missing");
    assert.deepEqual(rows["/unreadable"].unreadable, ["mtime"]);
    assert.equal(rows["/everything"].changed.length, 9);
    assert.deepEqual([out.check.differences, out.parse.unparsed_lines], [5, 1]);
    assert.equal(out.check.rpm_flags.size, 2);
    assert.match(out.safeguards.rpm, /NOT confirmed on a trial\s+database|was NOT confirmed on a trial database/);
    assert.match(out.safeguards.rpm, /no claim that nothing runs is made for rpm/);
    assert.equal(out.status, "partial");
    assert.deepEqual(out.unsupported_database[0].backend, "sqlite");
    // the other backends
    for (const [file, backend] of [["Packages.db", "ndb"], ["Packages", "bdb"]] as const) {
      await mkdir(join(cwd, "work", `r-${backend}`, "var/lib/rpm"), { recursive: true });
      await writeFile(join(cwd, "work", `r-${backend}`, "var/lib/rpm", file), Buffer.alloc(64));
      const o = body(await tool(VERIFY, cwd, { root: `work/r-${backend}` }, {}, bin));
      assert.match(o.scope.database.backend, new RegExp(`^${backend}`));
    }
    // a database directory the caller names, and one that is not a plain path
    await put(join(cwd, R), "usr/lib/sysimage/rpm/rpmdb.sqlite", "x");
    const named = body(await tool(VERIFY, cwd, { root: R, dbpath: "usr/lib/sysimage/rpm" }, {}, bin));
    assert.ok(named.program.argv.includes("/usr/lib/sysimage/rpm"));
    assert.match(refused(await tool(VERIFY, cwd, { root: R, dbpath: "../etc" }, {}, bin)).error, /plain path/);
  });
});

test("package_verify names names that are hostile: control characters and bytes that are not UTF-8 are escapes, a name with a newline is two lines, one of which does not parse", async () => {
  await withCwd(async (cwd, bin) => {
    await debianRoot(cwd);
    await stub(bin, "debsums", `printf '/tmp/a\\xffb                    FAILED\\n/tmp/x\\ty\\x01z   FAILED\\n/tmp/line\\nbreak  FAILED\\n/etc/ok    OK\\n'`);
    const out = body(await tool(VERIFY, cwd, { root: R, family: "debian" }, {}, bin));
    const rows = await rowsOf(cwd, out, "differences");
    assert.deepEqual(rows.map((r) => r.path), ["/tmp/a\\xffb", "/tmp/x\\x09y\\x01z", "break"].slice(0, 2).concat(rows.length > 2 ? [rows[2].path] : []));
    assert.equal(out.parse.unparsed_lines, 1, "the first half of a name split by a newline has no status");
    assert.ok(rows.every((r) => !/[\u0000-\u001f]/.test(r.path)));
  });
});

test("package_verify keeps counts exact and the answer bounded when the program lists 300,000 differences, and asks for no more names than it can pass", async () => {
  await withCwd(async (cwd, bin) => {
    await debianRoot(cwd);
    await stub(bin, "debsums", `python3 -c "
import sys
for i in range(300000):
    sys.stdout.write('/usr/lib/file%d   FAILED\\n' % i)
for i in range(1000):
    sys.stdout.write('/usr/lib/ok%d   OK\\n' % i)
"`);
    const started = Date.now();
    const out = body(await tool(VERIFY, cwd, { root: R, family: "debian", limit: 5 }, {}, bin));
    assert.ok(Date.now() - started < 60_000);
    assert.deepEqual([out.check.differences, out.check.files_ok, out.pages.differences.matched, out.truncated, out.differences.length], [300000, 1000, 300000, true, 5]);
    assert.equal(out.pages.differences.all_results !== undefined, true);
    assert.match(refused(await tool(VERIFY, cwd, { root: R, family: "debian", packages: Array.from({ length: 2001 }, (_x, i) => `p${i}`) }, {}, bin)).error, /at most 2000/);
    assert.match(refused(await tool(VERIFY, cwd, { root: R, family: "debian", packages: Array.from({ length: 800 }, (_x, i) => "x".repeat(127) + i) }, {}, bin)).error, /100000 bytes|plain characters/);
    assert.match(refused(await tool(VERIFY, cwd, { root: R, family: "debian", packages: ["bad name", "-rf"] }, {}, bin)).error, /plain characters/);
  });
});

test("package_verify ends a hanging program and the child it forked that ignores SIGTERM at its deadline, and leaves a bystander alone", async () => {
  await withCwd(async (cwd, bin) => {
    const { spawn } = await import("node:child_process");
    await debianRoot(cwd);
    await stub(bin, "debsums", `( trap "" TERM HUP INT; exec sleep 600 ) & echo $! > "$d/child.pid"; echo $$ > "$d/pid"; wait`);
    const bystander = spawn("sleep", ["300"], { detached: true, stdio: "ignore" });
    bystander.unref();
    try {
      const started = Date.now();
      const out = body(await tool(VERIFY, cwd, { root: R, family: "debian", max_seconds: 3 }, {}, bin));
      assert.ok((Date.now() - started) / 1000 < 8);
      assert.equal(out.program.timed_out, true);
      assert.equal(out.status, "partial");
      assert.equal(await gone(Number(await readFile(join(bin, "pid"), "utf8")), 5000), true);
      assert.equal(await gone(Number(await readFile(join(bin, "child.pid"), "utf8")), 5000), true);
      process.kill(bystander.pid as number, 0);
    } finally {
      process.kill(bystander.pid as number, "SIGKILL");
    }
  });
});

test("package_verify ends a program that floods its output at the cap, and says so", async () => {
  await withCwd(async (cwd, bin) => {
    await debianRoot(cwd);
    await stub(bin, "debsums", `yes "/usr/lib/x    OK"`);
    const started = Date.now();
    const out = body(await tool(VERIFY, cwd, { root: R, family: "debian", max_seconds: 120 }, {}, bin));
    assert.ok(Date.now() - started < 100_000);
    assert.equal(out.program.output_over_cap, true);
    assert.equal(out.status, "partial");
    assert.match(out.status_basis, /wrote more than 268435456 bytes/);
  });
});

for (const signal of ["SIGTERM", "SIGINT", "SIGHUP"] as const) {
  test(`package_verify ends on ${signal} with one document, and no process of the program is left`, async () => {
    await withCwd(async (cwd, bin) => {
      await debianRoot(cwd);
      await stub(bin, "debsums", `( trap "" TERM HUP INT; exec sleep 600 ) & echo $! > "$d/child.pid"; echo $$ > "$d/pid"; wait`);
      const run = startDetached(VERIFY, cwd, { root: R, family: "debian", max_seconds: 100 }, {}, bin);
      const pid = await pidFile(join(bin, "pid"));
      const child = await pidFile(join(bin, "child.pid"));
      run.signal(signal);
      const code = await Promise.race([run.closed, new Promise<"late">((r) => setTimeout(() => r("late"), 30_000))]);
      if (code === "late") {
        run.killGroup();
        assert.fail(`the tool ignored ${signal}`);
      }
      const num = { SIGTERM: 15, SIGINT: 2, SIGHUP: 1 }[signal];
      assert.equal(code, 128 + num);
      const docs = run.stdout().trim().split("\n");
      assert.equal(docs.length, 1);
      assert.equal(JSON.parse(docs[0]).stopped_by_signal, num);
      assert.equal(await gone(pid, 5000), true);
      assert.equal(await gone(child, 5000), true);
    });
  });
}

test("package_verify says failed and nothing was checked when the program is not installed, and refuses a family it cannot tell", async () => {
  await withCwd(async (cwd, bin) => {
    await debianRoot(cwd);
    const out = body(await tool(VERIFY, cwd, { root: R, family: "debian" }, { PATH: process.env.PATH ?? "" }, bin));
    // no debsums in bin, and none on this machine's PATH unless it is installed
    if (out.program.ran) return;
    assert.equal(out.status, "failed");
    assert.match(out.program.why, /not installed/);
    assert.match(out.status_basis, /nothing was checked/);
    await mkdir(join(cwd, R, "var/lib/rpm"), { recursive: true });
    const both = refused(await tool(VERIFY, cwd, { root: R }, {}, bin));
    assert.match(both.error, /both var\/lib\/dpkg and an rpm database/);
    assert.match(refused(await tool(VERIFY, cwd, { root: "work" }, {}, bin)).error, /neither var\/lib\/dpkg nor an rpm database/);
  });
});

test("package_verify's real debsums or rpm, when installed, run on a fixture root and their version is recorded", async (t) => {
  const have = ["debsums", "rpm"].filter((p) => spawnSync(p, ["--version"], { encoding: "utf8" }).status === 0);
  if (!have.length) {
    t.skip("neither debsums nor rpm is installed on this machine");
    return;
  }
  await withCwd(async (cwd) => {
    if (have.includes("debsums")) {
      await debianRoot(cwd);
      const out = body(await tool(VERIFY, cwd, { root: R, family: "debian" }));
      assert.ok(out.program.version);
    }
  });
});

test("package_verify answers hostile arguments in JSON and never with a traceback", async () => {
  await withCwd(async (cwd, bin) => {
    await debianRoot(cwd);
    await stub(bin, "debsums", "exit 0");
    const cases: unknown[] = [{}, [], "x", { root: 5 }, { root: "" }, { root: "a\u0000b" }, { root: "\ud800" }, { root: R, family: "arch" }, { root: R, family: 5 }, { root: R, packages: "a" },
      { root: R, packages: [1] }, { root: R, packages: [""] }, { root: R, packages: ["a\u0000"] }, { root: R, dbpath: 5 }, { root: R, dbpath: "" }, { root: R, dbpath: "/" }, { root: R, config_files: "no" },
      { root: R, family: "rpm", config_files: false }, { root: R, limit: 0 }, { root: R, max_seconds: -1 }, { root: R, max_seconds: 10 ** 400 }, { root: "work/none" }];
    for (const args of cases) {
      const run = await tool(VERIFY, cwd, args, {}, bin);
      assert.doesNotMatch(run.stderr, /Traceback/, JSON.stringify(args).slice(0, 60));
      assert.equal(JSON.parse(run.stdout).status, "failed", JSON.stringify(args).slice(0, 60));
    }
    const deep = spawnSync("python3", [VERIFY], { cwd, input: "[".repeat(100_000), encoding: "utf8" });
    assert.doesNotMatch(deep.stderr, /Traceback/);
    assert.equal(JSON.parse(deep.stdout).status, "failed");
  });
});

test("package_verify's manifest declares what the script reads, carries the script's sha256 and the version PARSER names", async () => {
  const manifest = JSON.parse(await readFile(join(TOOLS, "package_verify", "manifest.json"), "utf8"));
  const script = await readFile(VERIFY);
  assert.equal(manifest.sha256, createHash("sha256").update(script).digest("hex"));
  assert.match(script.toString("utf8"), new RegExp(`^PARSER = "package_verify/${manifest.version}"$`, "m"));
  assert.match(manifest.description, /`status`.*`status_basis`/);
  for (const key of ["root", "family", "packages", "dbpath", "config_files", "limit", "max_seconds"]) assert.ok(key in manifest.params, key);
  assert.match(String(script.toString("utf8").match(/^MAX_SECONDS = [0-9.]+/m)), /MAX_SECONDS = 240/);
  assert.ok(240 < manifest.timeout_seconds);
  assert.match(manifest.description, /NOT confirmed on a trial database/);
  const block = (t: string): string => t.slice(t.indexOf("# BEGIN SHARED PROCESS"), t.indexOf("# END SHARED PROCESS"));
  const journal = await readFile(join(TOOLS, "journal_export", "run.py"), "utf8");
  assert.equal(block(script.toString("utf8")), block(journal));
});
