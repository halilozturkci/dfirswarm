/**
 * The Linux pack: auth_log, against OpenSSH's, PAM's and sudo's own log line forms, traditional syslog and RFC
 * 3339 stamps, and gzip streams made by zlib.
 * Every fixture is built by the test from the format's own layout, never from a tool's output.
 *
 * The tools that read command lines, messages or environments follow the secret-safe output pattern of
 * recovery_key_scan (docs/packs.md, "Secrets and sensitive output"): the answer is locators and structured
 * fields, and the text is written only on request, only in a job, only to a file under $OUT. What the answer
 * and the files it names hold is checked here for a planted secret.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmod, mkdir, readFile, stat, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { gzipSync } from "node:zlib";
import { AUTH, IS_ROOT, asJob as plainJob, body, everythingBut, exists, filesUnder, lines, refused, rowsOf, tool, withCwd } from "./linux-pack-harness.ts";
import type { Json } from "./linux-pack-harness.ts";
/** The tool as a secret-output job runs it: the harness puts SECRET_OUTPUT=1 in the environment of such a job's process. `plainJob` is a job that is not. */
const asJob = (script: string, cwd: string, args: unknown, bin?: string, env: Record<string, string> = {}, outName = "out"): ReturnType<typeof plainJob> =>
  plainJob(script, cwd, args, bin, { SECRET_OUTPUT: "1", ...env }, outName);

const FP_ED = "SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8";
const FP_RSA = "SHA256:uNjrAGXtRBwLr4evnXZtCZbU6Cnt8L7tUBVdGJKEzcA";
const FP_CA = "SHA256:Wt0lxcJbxcHK0z2RdN5cOUd3K7xQmeX0QpHqsb4VLEc";

async function authDir(cwd: string, name: string, files: Record<string, string | Buffer>, mtimes: Record<string, Date> = {}): Promise<string> {
  const { utimes } = await import("node:fs/promises");
  const dir = join(cwd, "work", name);
  await mkdir(dir, { recursive: true });
  for (const [file, data] of Object.entries(files)) {
    await writeFile(join(dir, file), data);
    const when = mtimes[file] ?? new Date(Date.UTC(2026, 1, 20, 12, 0, 0));
    await utimes(join(dir, file), when, when);
  }
  return `work/${name}`;
}

test("auth_log keeps the key type and fingerprint of an ordinary `ssh2:` acceptance, and the certificate's identity", async () => {
  // The sshd line is "Accepted publickey for U from A port P ssh2: TYPE FINGERPRINT"; for a certificate
  // "ssh2: TYPE-CERT FP ID <key id> (serial N) CA TYPE FP". The old pattern's optional word after the
  // port ate "ssh2:", so the colon-anchored key group never matched and the fingerprint was lost.
  await withCwd(async (cwd) => {
    const path = await authDir(cwd, "ssh", {
      "auth.log": lines(
        `Feb 14 09:30:00 web01 sshd[2201]: Accepted publickey for alice from 192.0.2.10 port 12345 ssh2: ED25519 ${FP_ED}`,
        `Feb 14 09:30:01 web01 sshd[2202]: Accepted publickey for bob from 2001:db8::7 port 4222 ssh2: RSA ${FP_RSA}`,
        `Feb 14 09:30:02 web01 sshd[2203]: Accepted publickey for carol from 192.0.2.11 port 5000 ssh2: ED25519-CERT ${FP_ED} ID host-key-7 (serial 42) CA ED25519 ${FP_CA}`,
        `Feb 14 09:30:03 web01 sshd[2204]: Accepted password for dave from 192.0.2.12 port 22 ssh2`,
        `Feb 14 09:30:04 web01 sshd[2205]: Failed publickey for invalid user eve from 192.0.2.13 port 99 ssh2`,
      ),
    });
    const out = body(await tool(AUTH, cwd, { path }));
    const rows = await rowsOf(cwd, out);
    const by = (user: string): Json => rows.find((r) => r.user === user);
    assert.equal(by("alice").kind, "ssh_accepted");
    assert.equal(by("alice").keytype, "ED25519");
    assert.equal(by("alice").fingerprint, FP_ED);
    assert.equal(by("alice").source, "192.0.2.10");
    assert.equal(by("alice").port, 12345);
    assert.equal(by("bob").keytype, "RSA");
    assert.equal(by("bob").fingerprint, FP_RSA);
    assert.equal(by("bob").source, "2001:db8::7");
    assert.equal(by("carol").keytype, "ED25519-CERT");
    assert.equal(by("carol").fingerprint, FP_ED);
    assert.equal(by("carol").cert_id, "host-key-7");
    assert.equal(by("carol").cert_serial, 42);
    assert.equal(by("carol").ca_fingerprint, FP_CA);
    assert.equal(by("dave").method, "password");
    assert.equal(by("dave").fingerprint, undefined);
    const eve = rows.find((r) => r.invalid_user === true);
    assert.equal(eve.kind, "ssh_failed");
    assert.equal(eve.user, undefined, "a name the log says is no account is typed text: withheld");
    assert.equal(eve.user_withheld, true);
    assert.equal(eve.user_bytes, 3);
  });
});

test("auth_log reads a PAM failure as key=value pairs: user and source survive, the empty ones stay empty", async () => {
  // pam_unix writes "authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.0.2.5  user=alice"
  // (two spaces before user=) or, with no user= at all, ends at rhost. The old pattern let its lazy groups
  // finish before they captured anything.
  await withCwd(async (cwd) => {
    const path = await authDir(cwd, "pam", {
      "auth.log": lines(
        "Feb 14 09:30:02 web01 sshd[2201]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.0.2.5  user=alice",
        "Feb 14 09:30:03 web01 sudo: pam_unix(sudo:auth): authentication failure; logname=bob uid=1000 euid=0 tty=/dev/pts/1 ruser=bob rhost=  user=bob",
        "Feb 14 09:30:04 web01 sshd[2209]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.0.2.6",
        "Feb 14 09:30:05 web01 sshd[2210]: pam_unix(sshd:session): session opened for user carol(uid=1002) by (uid=0)",
        "Feb 14 09:30:06 web01 sudo: pam_unix(sudo:session): session opened for user root(uid=0) by bob(uid=1000)",
      ),
    });
    const out = body(await tool(AUTH, cwd, { path }));
    const rows = await rowsOf(cwd, out);
    assert.equal(rows.length, 5);
    assert.equal(rows[0].kind, "auth_failure");
    assert.equal(rows[0].user, undefined, "a PAM user= is what was typed: withheld");
    assert.equal(rows[0].user_bytes, 5);
    assert.equal(rows[0].source, "192.0.2.5");
    assert.equal(rows[0].pam_service, "sshd");
    assert.equal(rows[1].user_bytes, 3);
    assert.equal(rows[1].ruser, undefined, "ruser= is the login name a service was given: typed text, withheld like user=");
    assert.equal(rows[1].ruser_bytes, 3);
    assert.equal(rows[1].logname, "bob", "the real login name of the caller is not typed text");
    assert.equal(rows[1].source, undefined, "rhost= is empty: no source is invented");
    assert.equal(rows[2].source, "192.0.2.6");
    assert.equal(rows[2].user, undefined);
    assert.equal(rows[3].kind, "session_opened");
    assert.equal(rows[3].user, "carol");
    assert.equal(rows[3].uid, 1002);
    assert.equal(rows[3].pam_service, "sshd");
    assert.equal(rows[4].user, "root");
    assert.equal(rows[4].by, "bob");
    assert.equal(rows[4].pam_service, "sudo", "a PAM session is the named service's, not necessarily a login");
  });
});

test("auth_log never takes the word `user` for an address in a disconnect line, and names the authentication stage", async () => {
  await withCwd(async (cwd) => {
    const path = await authDir(cwd, "disc", {
      "auth.log": lines(
        "Feb 14 09:40:00 web01 sshd[1]: Disconnected from user alice 192.0.2.9 port 4222",
        "Feb 14 09:40:01 web01 sshd[2]: Received disconnect from 192.0.2.9 port 22:11: Bye Bye [preauth]",
        "Feb 14 09:40:02 web01 sshd[3]: Disconnected from authenticating user root 192.0.2.9 port 22 [preauth]",
        "Feb 14 09:40:03 web01 sshd[4]: Disconnected from invalid user bob 2001:db8::1 port 5 [preauth]",
        "Feb 14 09:40:04 web01 sshd[5]: Disconnected from 192.0.2.77 port 51000 [preauth]",
      ),
    });
    const rows = await rowsOf(cwd, body(await tool(AUTH, cwd, { path })));
    assert.equal(rows.length, 5);
    for (const r of rows) {
      assert.equal(r.kind, "ssh_disconnect");
      assert.notEqual(r.source, "user");
      assert.match(r.source, /^[0-9a-f.:]+$/i, `source is an address: ${JSON.stringify(r)}`);
    }
    assert.equal(rows[0].source, "192.0.2.9");
    assert.equal(rows[0].user, "alice");
    assert.equal(rows[0].port, 4222);
    assert.equal(rows[1].source, "192.0.2.9");
    assert.equal(rows[2].user, "root", "an authenticating user is an account the log names");
    assert.equal(rows[3].source, "2001:db8::1");
    assert.equal(rows[3].user, undefined, "an invalid user is typed text");
    assert.equal(rows[3].user_bytes, 3);
    assert.equal(rows[4].source, "192.0.2.77");
  });
});

test("auth_log calls `Accepted key` an authentication observation, not an installed key", async () => {
  // sshd at a verbose level logs "Accepted key TYPE FP found at FILE:LINE" when it matches an authorized_keys
  // entry. That is a login being authenticated, not a key being added; the old kind was key_added and its
  // fingerprint group captured the key type.
  await withCwd(async (cwd) => {
    const path = await authDir(cwd, "key", {
      "auth.log": lines(`Feb 14 09:30:00 web01 sshd[2201]: Accepted key ED25519 ${FP_ED} found at /home/alice/.ssh/authorized_keys:2`),
    });
    const out = body(await tool(AUTH, cwd, { path }));
    const [row] = await rowsOf(cwd, out);
    assert.equal(row.kind, "key_observed_authentication");
    assert.equal(row.keytype, "ED25519");
    assert.equal(row.fingerprint, FP_ED);
    assert.equal(row.authorized_keys_file, "/home/alice/.ssh/authorized_keys");
    assert.equal(row.authorized_keys_line, 2);
    assert.ok(!("key_added" in (out.by_kind ?? {})));
    // The old name is refused, with the reason, rather than matching nothing.
    const gone = refused(await tool(AUTH, cwd, { path, kinds: ["key_added"] }));
    assert.match(gone.error, /key_observed_authentication/);
  });
});

test("auth_log gives a line that is out of order its place, and counts a rollover only where the months wrap forward", async () => {
  // Jan 2, Dec 31, Jan 2 in one file whose mtime is in January: the December line is a reordered (or
  // late-written) line of the year before, not a second year-end. The old code added a year at every month
  // decrease: January, then December of the next year, then January of the year after.
  await withCwd(async (cwd) => {
    const mtime = new Date(Date.UTC(2026, 0, 3, 12, 0, 0));
    const path = await authDir(
      cwd,
      "reorder",
      {
        "auth.log": lines(
          "Jan  2 10:00:00 h sshd[1]: Failed password for root from 192.0.2.1 port 1 ssh2",
          "Dec 31 23:59:59 h sshd[2]: Failed password for root from 192.0.2.1 port 2 ssh2",
          "Jan  2 10:00:05 h sshd[3]: Failed password for root from 192.0.2.1 port 3 ssh2",
        ),
      },
      { "auth.log": mtime },
    );
    const out = body(await tool(AUTH, cwd, { path }));
    const [file] = out.files;
    assert.equal(file.rollovers, 0);
    assert.equal(file.reordered_lines, 1);
    assert.equal(file.first_year, 2026);
    assert.equal(file.last_year, 2026);
    assert.match(String(file.year_basis), /mtime/);
    const rows = await rowsOf(cwd, out);
    assert.deepEqual(rows.map((r) => r.time), ["2026-01-02T10:00:00", "2025-12-31T23:59:59", "2026-01-02T10:00:05"]);
    assert.deepEqual(rows.map((r) => Boolean(r.reordered)), [false, true, false]);
    assert.deepEqual(rows.map((r) => r.time_raw), ["Jan  2 10:00:00", "Dec 31 23:59:59", "Jan  2 10:00:05"], "the stamp as the file wrote it, spacing included");
    assert.ok(rows.every((r) => r.time_zone === "unknown"), "a traditional stamp carries no zone");
  });
});

test("auth_log still crosses a real year end, and a year argument is applied as given and said", async () => {
  await withCwd(async (cwd) => {
    const mtime = new Date(Date.UTC(2026, 0, 1, 0, 30, 0));
    const path = await authDir(
      cwd,
      "wrap",
      {
        "auth.log": lines(
          "Dec 30 23:58:01 h sshd[1]: Failed password for root from 192.0.2.1 port 1 ssh2",
          "Dec 31 23:59:59 h sshd[2]: Failed password for root from 192.0.2.1 port 2 ssh2",
          "Jan  1 00:02:11 h sshd[3]: Failed password for root from 192.0.2.1 port 3 ssh2",
        ),
      },
      { "auth.log": mtime },
    );
    const out = body(await tool(AUTH, cwd, { path }));
    assert.equal(out.files[0].rollovers, 1);
    assert.deepEqual((await rowsOf(cwd, out)).map((r) => r.time), ["2025-12-30T23:58:01", "2025-12-31T23:59:59", "2026-01-01T00:02:11"]);
    const given = body(await tool(AUTH, cwd, { path, year: 2019 }));
    assert.equal(given.files[0].year_basis, "argument");
    assert.equal(given.files[0].year_argument_spans_rollover, true);
    assert.ok((await rowsOf(cwd, given)).every((r) => String(r.time).startsWith("2019-")));
  });
});

test("auth_log counts a line it cannot place, takes no unknown month for January, and keeps `all_lines_parsed` honest", async () => {
  await withCwd(async (cwd) => {
    const path = await authDir(cwd, "bad", {
      "auth.log": lines(
        "Feb 14 09:30:00 web01 sshd[1]: Accepted password for alice from 192.0.2.10 port 22 ssh2",
        "Foo 12 10:00:00 web01 sshd[2]: Accepted password for mallory from 192.0.2.66 port 22 ssh2",
        "this line is not a syslog line at all",
        "Feb 31 10:00:00 web01 sshd[3]: Accepted password for alice from 192.0.2.10 port 22 ssh2",
      ),
    });
    const out = body(await tool(AUTH, cwd, { path }));
    assert.equal(out.all_lines_parsed, false);
    assert.equal(out.unparsed_lines, 2);
    const rows = await rowsOf(cwd, out);
    assert.ok(!rows.some((r) => r.user === "mallory"), "an unknown month is not January");
    const feb31 = rows.find((r) => r.line === 4);
    assert.ok(feb31, "a recognised line with an impossible date is kept");
    assert.equal(feb31.time, null);
    assert.match(String(feb31.time_error), /date/i);
    const unparsed = await rowsOf(cwd, out, "unparsed");
    assert.deepEqual(unparsed.map((u) => u.line), [2, 3]);
    assert.ok(unparsed.every((u) => typeof u.byte_offset === "number" && !("line_text" in u)));
    assert.equal((await rowsOf(cwd, out)).find((r) => r.user === "alice" && r.line === 1)?.line, 1);
  });
});

test("auth_log reports a gzip cut off mid-stream as partial and keeps what it read before the break", async () => {
  await withCwd(async (cwd) => {
    const text = Array.from({ length: 4000 }, (_, i) => `Feb 14 09:${String(i % 60).padStart(2, "0")}:00 web01 sshd[${i}]: Failed password for root from 192.0.2.${i % 200} port ${i} ssh2`).join("\n") + "\n";
    // Random-looking user names keep the stream from collapsing into a few bytes, so the cut falls inside it.
    const noisy = text.split("\n").map((l, i) => l.replace("root", `u${(i * 2654435761) % 99991}`)).join("\n");
    const whole = gzipSync(Buffer.from(noisy));
    const path = await authDir(cwd, "cut", { "auth.log.1.gz": whole.subarray(0, Math.floor(whole.length * 0.6)) });
    const out = body(await tool(AUTH, cwd, { path }));
    assert.equal(out.all_lines_parsed, false);
    assert.equal(out.read_errors.length, 1);
    assert.match(out.read_errors[0].file, /auth\.log\.1\.gz$/);
    assert.equal(out.files[0].partial, true);
    assert.ok(out.record_count > 0 && out.record_count < 4000, `read ${out.record_count} of 4000 before the break`);
  });
});

test("auth_log stops a gzip stream that expands past its cap and says so, with what it read before", async () => {
  await withCwd(async (cwd) => {
    const line = "Feb 14 09:30:00 web01 sshd[1]: Failed password for root from 192.0.2.1 port 1 ssh2\n";
    const path = await authDir(cwd, "bomb", { "auth.log.1.gz": gzipSync(Buffer.from(line.repeat(50_000))) });
    const out = body(await tool(AUTH, cwd, { path, max_expanded_bytes: 10_000 }));
    assert.equal(out.all_lines_parsed, false);
    assert.match(out.read_errors[0].error, /max_expanded_bytes/);
    assert.ok(out.record_count > 0 && out.record_count < 200, `read ${out.record_count} lines before the cap`);
    assert.equal(out.files[0].partial, true);
  });
});

test("auth_log keeps the stamp as written, the zone it carries, and the fractions of a second", async () => {
  await withCwd(async (cwd) => {
    const path = await authDir(cwd, "iso", {
      "auth.log": lines(
        "2026-02-14T09:30:00.123456+02:00 web01 sshd[1]: Accepted password for alice from 192.0.2.7 port 22 ssh2",
        "2026-02-14T09:31:00Z web01 sshd[2]: Accepted password for alice from 192.0.2.7 port 22 ssh2",
        "2026-02-14 09:32:00 web01 sshd[3]: Accepted password for alice from 192.0.2.7 port 22 ssh2",
      ),
    });
    const rows = await rowsOf(cwd, body(await tool(AUTH, cwd, { path })));
    assert.equal(rows[0].time_raw, "2026-02-14T09:30:00.123456+02:00");
    assert.equal(rows[0].time, "2026-02-14T09:30:00.123456", "time is the clock reading as written, whatever the zone");
    assert.equal(rows[0].time_utc, "2026-02-14T07:30:00.123456Z");
    assert.equal(rows[1].time, "2026-02-14T09:31:00");
    assert.equal(rows[0].time_zone, "+02:00");
    assert.equal(rows[1].time_utc, "2026-02-14T09:31:00Z");
    assert.equal(rows[1].time_zone, "Z");
    assert.equal(rows[2].time_utc, null);
    assert.equal(rows[2].time_zone, "unknown");
    assert.equal(rows[2].time, "2026-02-14T09:32:00");
  });
});

test("auth_log answers with fields and locators, and the text of a sudo line only in a job's file, on request", async () => {
  const SECRET = "Tr0ub4dor3xyz";
  const SUDO = `Feb 14 09:30:00 web01 sudo:   deploy : TTY=pts/0 ; PWD=/srv ; USER=root ; COMMAND=/usr/bin/mysql -uroot -p${SECRET} -e 'select 1'`;
  await withCwd(async (cwd) => {
    const path = await authDir(cwd, "sudo", {
      "auth.log": lines(SUDO, `Feb 14 09:30:01 web01 sshd[9]: Accepted password for deploy from 192.0.2.4 port 22 ssh2`, "Feb 14 09:30:02 web01 sshd[9]: Accepted password for deploy from 192.0.2.4 port 22 ssh2"),
    });
    // By default: structured fields, no text, in a job or not.
    for (const run of [await tool(AUTH, cwd, { path, limit: 1 }), await asJob(AUTH, cwd, { path, limit: 1 })]) {
      const out = body(run);
      const [first] = out.records;
      assert.equal(first.kind, "sudo");
      assert.equal(first.user, "deploy");
      assert.equal(first.target, "root");
      assert.equal(first.pwd, "/srv");
      assert.ok(first.command_bytes > 0);
      assert.ok(!("command" in first) && !("raw" in first));
      assert.equal(out.text.written, 0);
      const all = await everythingBut(cwd, run.stdout, []);
      assert.ok(!all.includes(SECRET), "the answer and every file under work/ and out/ are free of the command's text");
    }
    // The text is asked for, and only in a job.
    const outside = refused(await tool(AUTH, cwd, { path, write_text: true }));
    assert.match(outside.error, /outside a job/);
    assert.match(refused(await tool(AUTH, cwd, { path, preview_text: true })).error, /outside a job/);
    const job = await asJob(AUTH, cwd, { path, write_text: true, limit: 1 });
    const out = body(job);
    assert.equal(out.text.written, 3);
    assert.equal(out.text.contains_text_that_may_hold_secrets, true);
    assert.match(out.text.file, /out\/auth-text\.jsonl$/);
    assert.ok(!job.stdout.includes(SECRET), "the answer says where the text is, not what it is");
    const file = join(cwd, "out", "auth-text.jsonl");
    assert.equal((await stat(file)).mode & 0o777, 0o600);
    const rows = (await readFile(file, "utf8")).trimEnd().split("\n").map((l) => JSON.parse(l));
    assert.ok(rows[0].command.includes(SECRET));
    assert.equal(rows[0].line_text, SUDO);
    assert.equal(rows[0].id, out.records[0].id, "the text row and the answer's row are one finding");
    // The same asked again does not overwrite what is there.
    assert.match(refused(await asJob(AUTH, cwd, { path, write_text: true })).error, /already exists/);
    // The preview is the answer carrying the text, in a job.
    const preview = body(await asJob(AUTH, cwd, { path, preview_text: true }, undefined, {}, "out-preview"));
    assert.ok(preview.records[0].command.includes(SECRET));
  });
});

test("auth_log follows rotated and dated names in an order it states, and refuses a link", async () => {
  await withCwd(async (cwd) => {
    const mk = (d: number): string => lines(`Mar ${d} 10:00:00 h sshd[1]: Failed password for root from 192.0.2.1 port 1 ssh2`);
    const path = await authDir(cwd, "names", {
      "auth.log": mk(5),
      "auth.log.1": mk(4),
      "auth.log.2.gz": gzipSync(Buffer.from(mk(3))),
      "notes.txt": "not a log",
    });
    await symlink("/etc/passwd", join(cwd, path, "auth.log.3"));
    const out = body(await tool(AUTH, cwd, { path }));
    assert.deepEqual(out.files.map((f: Json) => f.path.split("/").pop()), ["auth.log.2.gz", "auth.log.1", "auth.log"]);
    assert.deepEqual(out.files.map((f: Json) => f.order_basis), ["numeric rotation suffix", "numeric rotation suffix", "current file"]);
    assert.equal(out.skipped_symlinks.length, 1);
    assert.equal(out.cross_file_order, "consistent");
    assert.match(refused(await tool(AUTH, cwd, { path: join(path, "auth.log.3") })).error, /symlink/);
  });
});

test("auth_log reads a PAM line's own key=value text as text: no key but its own seven can set a field or overwrite a locator", async () => {
  // A user name typed at a login prompt reaches the log, so `user=zed file=/etc/shadow line=99 id=A000777 kind=ssh_accepted raw=...`
  // is attacker-controlled text inside a pam_unix line, not a set of fields.
  await withCwd(async (cwd) => {
    const path = await authDir(cwd, "kv", {
      "auth.log": lines("Feb 14 09:30:02 web01 sshd[2201]: pam_unix(sshd:auth): authentication failure; uid=0 rhost=192.0.2.5  user=zed file=/etc/shadow line=99 byte_offset=0 id=A000777 kind=ssh_accepted raw=TYPEDSECRETWORD pid=7 host=evil time=1999"),
    });
    const run = await tool(AUTH, cwd, { path });
    const [row] = await rowsOf(cwd, body(run));
    assert.equal(row.kind, "auth_failure");
    // pam_unix writes user= last and the rest of the line is the name: `zed file=/etc/shadow ... time=1999` is all one typed text.
    const typed = "zed file=/etc/shadow line=99 byte_offset=0 id=A000777 kind=ssh_accepted raw=TYPEDSECRETWORD pid=7 host=evil time=1999";
    assert.equal(row.user_bytes, typed.length, "the typed user= is withheld, to the end of the line");
    assert.equal(row.source, "192.0.2.5");
    assert.equal(row.file, path + "/auth.log");
    assert.equal(row.line, 1);
    assert.equal(row.id, "A000001");
    assert.equal(row.host, "web01");
    assert.equal(row.pid, 2201);
    assert.ok(!run.stdout.includes("TYPEDSECRETWORD"), "no raw text in the default answer");
  });
});

test("auth_log survives a pid of five thousand digits, a stamp at the end of the calendar, an offset that is no offset, and a log of other compressions", async () => {
  await withCwd(async (cwd) => {
    const path = await authDir(cwd, "odd", {
      "auth.log": lines(
        `Feb 14 09:30:00 web01 sshd[${"9".repeat(5000)}]: Failed password for root from 192.0.2.1 port 1 ssh2`,
        "9999-12-31T23:59:59-05:00 web01 sshd[1]: Failed password for root from 192.0.2.1 port 1 ssh2",
        "0001-01-01T00:00:00+05:00 web01 sshd[1]: Failed password for root from 192.0.2.1 port 1 ssh2",
        "2026-02-14T09:30:00+99:99 web01 sshd[1]: Failed password for root from 192.0.2.1 port 1 ssh2",
      ),
      "auth.log.2.bz2": Buffer.concat([Buffer.from("BZh9"), Buffer.alloc(64)]),
    });
    const out = body(await tool(AUTH, cwd, { path }));
    const rows = await rowsOf(cwd, out);
    assert.equal(rows.filter((r) => r.kind === "ssh_failed").length, 3, "the first line is not placed by a pid it cannot hold");
    assert.ok(rows.some((r) => /range of a date/.test(String(r.time_error))), "an instant outside the calendar is a time_error");
    assert.ok(rows.some((r) => /not a valid offset/.test(String(r.time_error))));
    assert.ok(out.read_errors.some((e: Json) => /bzip2-compressed/.test(e.error)), JSON.stringify(out.read_errors));
    assert.equal(out.all_lines_parsed, false);
  });
});

test("auth_log does not spend quadratic time on a line of whitespace, and shows a long field cut with its whole length", async () => {
  await withCwd(async (cwd) => {
    const pad = " ".repeat(10_000);
    const reason = "r".repeat(40_000);
    const path = await authDir(cwd, "wide", {
      "auth.log": lines(
        `Feb 14 09:30:00 web01 sshd[1]: Accepted publickey for u from 192.0.2.1 port 22 ssh2: ED25519-CERT SHA256:x ID${pad}${pad}`,
        `Feb 14 09:30:01 web01 sshd[2]: Received disconnect from 192.0.2.1 port 22:11: ${reason}${pad}`,
      ),
    });
    const started = Date.now();
    const run = await asJob(AUTH, cwd, { path, write_text: true });
    assert.ok(Date.now() - started < 4000, `took ${Date.now() - started} ms`);
    const out = body(run);
    const disconnect = (await rowsOf(cwd, out)).find((r) => r.kind === "ssh_disconnect");
    assert.ok(String(disconnect.reason).length <= 256);
    assert.equal(disconnect.truncated_fields.reason, 40_000 + 10_000);
    const text = (await readFile(join(cwd, "out", "auth-text.jsonl"), "utf8")).trimEnd().split("\n").map((l) => JSON.parse(l));
    assert.equal(String(text.find((t: Json) => t.kind === "ssh_disconnect").reason).length, 40_000 + 10_000, "the whole is in the text file");
  });
});

test("auth_log keeps a gzip expansion cap through a line longer than a line may be", async () => {
  await withCwd(async (cwd) => {
    const path = await authDir(cwd, "longbomb", { "auth.log.1.gz": gzipSync(Buffer.alloc(8 * 1024 * 1024, 0x41)) });
    const started = Date.now();
    const out = body(await tool(AUTH, cwd, { path, max_expanded_bytes: 1_000_000 }));
    assert.ok(Date.now() - started < 4000);
    assert.match(out.read_errors[0].error, /max_expanded_bytes/);
    assert.equal(out.files[0].partial, true);
  });
});

test("auth_log does not let an invalid date move the months, and orders a dotted date suffix as a date", async () => {
  await withCwd(async (cwd) => {
    const mtime = new Date(Date.UTC(2026, 0, 10, 12, 0, 0));
    const path = await authDir(
      cwd,
      "invalid",
      {
        "auth.log": lines(
          "Jan  2 10:00:00 h sshd[1]: Failed password for root from 192.0.2.1 port 1 ssh2",
          "Feb 30 10:00:00 h sshd[2]: Failed password for root from 192.0.2.1 port 2 ssh2",
          "Jan  3 10:00:00 h sshd[3]: Failed password for root from 192.0.2.1 port 3 ssh2",
          "Jan  4 10:00:00 h sshd[4]: Failed password for root from 192.0.2.1 port 4 ssh2",
        ),
        "auth.log.20260101": lines("Jan  1 10:00:00 h sshd[5]: Failed password for root from 192.0.2.1 port 5 ssh2"),
        "auth.log.20251201": lines("Dec  1 10:00:00 h sshd[6]: Failed password for root from 192.0.2.1 port 6 ssh2"),
      },
      { "auth.log": mtime, "auth.log.20260101": mtime, "auth.log.20251201": mtime },
    );
    const out = body(await tool(AUTH, cwd, { path }));
    assert.deepEqual(out.files.map((f: Json) => f.path.split("/").pop()), ["auth.log.20251201", "auth.log.20260101", "auth.log"]);
    assert.deepEqual(out.files.map((f: Json) => f.order_basis), ["date suffix", "date suffix", "current file"]);
    const live = out.files[2];
    assert.equal(live.reordered_lines, 0, "a Feb 30 line does not turn the January lines after it into reordered ones");
    assert.equal(live.last_time, "2026-01-04T10:00:00");
  });
});

test("auth_log reads a line with a dated zone-bearing stamp as a time range for file order", async () => {
  await withCwd(async (cwd) => {
    const path = await authDir(cwd, "isorange", {
      "auth.log.1": lines("2026-03-05T10:00:00Z h sshd[1]: Failed password for root from 192.0.2.1 port 1 ssh2"),
      "auth.log": lines("2026-01-05T10:00:00Z h sshd[1]: Failed password for root from 192.0.2.1 port 1 ssh2"),
    });
    const out = body(await tool(AUTH, cwd, { path }));
    assert.equal(out.cross_file_order, "overlap", "the live file is older than the rotated one it should follow");
  });
});

test("auth_log tells su's account from its target, in both of the forms su writes", async () => {
  await withCwd(async (cwd) => {
    const path = await authDir(cwd, "su", {
      "auth.log": lines(
        "Feb 14 09:30:00 h su[1]: Successful su for root by alice",
        "Feb 14 09:30:01 h su[2]: (to root) alice on pts/0",
        "Feb 14 09:30:02 h su[3]: FAILED su for root by bob",
      ),
    });
    const rows = await rowsOf(cwd, body(await tool(AUTH, cwd, { path })));
    assert.deepEqual(rows.map((r) => [r.kind, r.user, r.target]), [["su", "alice", "root"], ["su", "alice", "root"], ["su_failed", "bob", "root"]]);
    assert.equal(rows[1].tty, "pts/0");
  });
});

test("auth_log never opens a pipe it finds where a log should be, and the paging file of a preview holds no text", async () => {
  await withCwd(async (cwd) => {
    const path = await authDir(cwd, "pipe", {
      "auth.log": lines(
        "Feb 14 09:30:00 web01 sudo:   a : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/echo PREVIEWSECRETONE",
        "Feb 14 09:30:01 web01 sudo:   a : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/echo PREVIEWSECRETTWO",
      ),
    });
    assert.equal(spawnSync("mkfifo", [join(cwd, path, "auth.log.1")]).status, 0);
    const out = body(await asJob(AUTH, cwd, { path, preview_text: true, limit: 1 }));
    assert.equal(out.skipped_special.length, 1);
    assert.equal(out.all_lines_parsed, false);
    assert.ok(out.records[0].command.includes("PREVIEWSECRETONE"), "the preview carries the text");
    assert.equal(out.text.answer_contains_text_that_may_hold_secrets, true);
    assert.equal(out.text.requested, false);
    for (const f of await filesUnder(join(cwd, "out"))) {
      assert.ok(!(await readFile(join(cwd, "out", f), "utf8")).includes("PREVIEWSECRET"), `${f} holds the text of a preview`);
    }
    assert.ok(out.pages.records.all_results, "the whole result is paged to a file that holds none of it");
  });
});

test("auth_log rejects arguments that are not an object, and a field of the wrong type, with an error and no traceback", async () => {
  await withCwd(async (cwd) => {
    for (const bad of [null, [], "x", 5]) assert.match(refused(await tool(AUTH, cwd, bad)).error, /JSON object/);
    await mkdir(join(cwd, "work", "a"), { recursive: true });
    await writeFile(join(cwd, "work", "a", "auth.log"), "x\n");
    for (const args of [{ path: "work/a", contains: 5 }, { path: "work/a", kinds: "sudo" }, { path: 5 }]) refused(await tool(AUTH, cwd, args));
  });
});

test("auth_log keeps every name typed at a prompt out of the answer and out of the paging file, and in the job's text file", async () => {
  // A name the log says is no account, and a PAM user=, are what someone typed: they can be a password in the wrong field.
  await withCwd(async (cwd) => {
    const path = await authDir(cwd, "typed", {
      "auth.log": lines(
        "Feb 14 09:30:00 web01 sshd[1]: Invalid user INVALIDUSERpw6 from 203.0.113.4 port 5",
        "Feb 14 09:30:01 web01 sshd[2]: Failed password for invalid user INVFAILEDpw7 from 203.0.113.4 port 6 ssh2",
        "Feb 14 09:30:02 web01 sshd[3]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.4  user=PAMTYPEDpw8",
        "Feb 14 09:30:03 web01 sshd[4]: Disconnected from invalid user INVDISCpw9 203.0.113.4 port 7 [preauth]",
        "Feb 14 09:30:04 web01 sshd[5]: Accepted password for realuser from 192.0.2.4 port 22 ssh2",
      ),
    });
    const secrets = ["INVALIDUSERpw6", "INVFAILEDpw7", "PAMTYPEDpw8", "INVDISCpw9"];
    for (const run of [await tool(AUTH, cwd, { path, limit: 1 }), await asJob(AUTH, cwd, { path, limit: 1 })]) {
      const out = body(run);
      const all = await everythingBut(cwd, run.stdout, []);
      for (const secret of secrets) assert.ok(!all.includes(secret), `${secret} is in the answer or a file it names`);
      assert.equal(out.pages.records.matched, 5);
    }
    const all = body(await tool(AUTH, cwd, { path }));
    const rows = await rowsOf(cwd, all);
    assert.deepEqual(rows.slice(0, 4).map((r) => r.user_bytes), [14, 12, 11, 10]);
    assert.equal(rows[4].user, "realuser", "an account the log names stays in the answer");
    const job = body(await asJob(AUTH, cwd, { path, write_text: true }, undefined, {}, "out-text"));
    const text = (await readFile(join(cwd, "out-text", "auth-text.jsonl"), "utf8")).trimEnd().split("\n").map((l) => JSON.parse(l));
    assert.deepEqual(text.slice(0, 4).map((t: Json) => t.user), ["INVALIDUSERpw6", "INVFAILEDpw7", "PAMTYPEDpw8", "INVDISCpw9"]);
    assert.equal(job.text.written, 5);
    const preview = body(await asJob(AUTH, cwd, { path, preview_text: true }, undefined, {}, "out-preview2"));
    assert.equal(preview.records[0].user, "INVALIDUSERpw6");
  });
});

test("auth_log dates a file from the lines that agree, not from a stray one, and not from a gap in the log", async () => {
  await withCwd(async (cwd) => {
    // January with one March line in it, the file last written on January 20th: the March line is the stray.
    const stray = await authDir(cwd, "stray", {
      "auth.log": lines(
        "Jan  2 10:00:00 h sshd[1]: Failed password for root from 192.0.2.1 port 1 ssh2",
        "Jan  3 10:00:00 h sshd[2]: Failed password for root from 192.0.2.1 port 2 ssh2",
        "Mar 15 10:00:00 h sshd[3]: Failed password for root from 192.0.2.1 port 3 ssh2",
        "Jan  4 10:00:00 h sshd[4]: Failed password for root from 192.0.2.1 port 4 ssh2",
      ),
    }, { "auth.log": new Date(Date.UTC(2026, 0, 20, 12, 0, 0)) });
    const a = body(await tool(AUTH, cwd, { path: stray }));
    const rowsA = await rowsOf(cwd, a);
    assert.deepEqual(rowsA.map((r) => String(r.time).slice(0, 10)), ["2026-01-02", "2026-01-03", "2026-03-15", "2026-01-04"]);
    assert.deepEqual(rowsA.map((r) => Boolean(r.reordered)), [false, false, true, false], "the stray line is the one marked");
    assert.equal(a.files[0].rollovers, 0);
    // A machine that was off for eight months: January, then September, and the file last written in September.
    const gap = await authDir(cwd, "gap", {
      "auth.log": lines(
        "Jan  5 10:00:00 h sshd[1]: Failed password for root from 192.0.2.1 port 1 ssh2",
        "Jan  6 10:00:00 h sshd[2]: Failed password for root from 192.0.2.1 port 2 ssh2",
        "Sep 20 10:00:00 h sshd[3]: Failed password for root from 192.0.2.1 port 3 ssh2",
        "Sep 21 10:00:00 h sshd[4]: Failed password for root from 192.0.2.1 port 4 ssh2",
      ),
    }, { "auth.log": new Date(Date.UTC(2026, 8, 22, 12, 0, 0)) });
    const b = body(await tool(AUTH, cwd, { path: gap }));
    assert.deepEqual((await rowsOf(cwd, b)).map((r) => String(r.time).slice(0, 10)), ["2026-01-05", "2026-01-06", "2026-09-20", "2026-09-21"]);
    assert.equal(b.files[0].reordered_lines, 0);
    assert.equal(b.files[0].rollovers, 0);
    // A year end is still found, and named by the line it was read at.
    const wrap = await authDir(cwd, "wrap2", {
      "auth.log": lines(
        "Dec 30 10:00:00 h sshd[1]: Failed password for root from 192.0.2.1 port 1 ssh2",
        "Jan  2 10:00:00 h sshd[2]: Failed password for root from 192.0.2.1 port 2 ssh2",
      ),
    }, { "auth.log": new Date(Date.UTC(2026, 0, 5, 12, 0, 0)) });
    const c = body(await tool(AUTH, cwd, { path: wrap }));
    assert.deepEqual(c.files[0].rollover_lines, [2]);
    assert.deepEqual((await rowsOf(cwd, c)).map((r) => String(r.time).slice(0, 10)), ["2025-12-30", "2026-01-02"]);
  });
});

test("auth_log reads the key=value tokens of a PAM line in linear time", async () => {
  await withCwd(async (cwd) => {
    const filler = "a".repeat(60_000);
    const path = await authDir(cwd, "pamslow", {
      "auth.log": lines(...Array.from({ length: 7 }, (_, i) => `Feb 14 09:30:0${i} web01 sshd[${i}]: pam_unix(sshd:auth): authentication failure; ${filler} rhost=192.0.2.5`)),
    });
    const started = Date.now();
    const out = body(await tool(AUTH, cwd, { path }));
    assert.ok(Date.now() - started < 5000, `took ${Date.now() - started} ms`);
    assert.equal((await rowsOf(cwd, out))[0].source, "192.0.2.5");
  });
});

test("auth_log keeps the rejected key of a failed publickey, a leap second, and the digits of a long fraction", async () => {
  await withCwd(async (cwd) => {
    const path = await authDir(cwd, "failedkey", {
      "auth.log": lines(
        `Feb 14 09:30:00 web01 sshd[1]: Failed publickey for root from 192.0.2.4 port 22 ssh2: RSA ${FP_RSA}`,
        "2026-06-30T23:59:60Z web01 sshd[2]: Failed password for root from 192.0.2.4 port 22 ssh2",
        "2026-02-14T09:30:00.1234567Z web01 sshd[3]: Failed password for root from 192.0.2.4 port 22 ssh2",
      ),
    });
    const rows = await rowsOf(cwd, body(await tool(AUTH, cwd, { path })));
    assert.equal(rows[0].keytype, "RSA");
    assert.equal(rows[0].fingerprint, FP_RSA);
    assert.equal(rows[1].time_error, undefined, "second 60 is a leap second, not an error");
    assert.match(rows[1].time_note, /leap second/);
    assert.equal(rows[2].time_utc, "2026-02-14T09:30:00.123456Z");
    assert.match(rows[2].time_note, /7 digits/);
  });
});

test("auth_log stops at max_seconds and names what it did not read", async () => {
  await withCwd(async (cwd) => {
    const line = "Feb 14 09:30:00 web01 sshd[1]: Failed password for root from 192.0.2.1 port 1 ssh2\n";
    const path = await authDir(cwd, "slow", { "auth.log": line.repeat(600_000), "auth.log.1": line });
    const out = body(await tool(AUTH, cwd, { path, max_seconds: 0.2 }));
    assert.equal(out.status, "partial");
    assert.match(out.read_errors[0].error, /max_seconds/);
    assert.equal(out.files_not_reached.length + out.files.filter((f: Json) => f.partial).length >= 1, true);
    assert.equal(out.all_lines_parsed, false);
    for (const bad of [0, -1, "5", Infinity, null].filter((v) => v !== null)) refused(await tool(AUTH, cwd, { path, max_seconds: bad as number }));
    assert.match(refused(await tool(AUTH, cwd, { path, max_seconds: 1e999 })).error, /max_seconds/);
  });
});

test("auth_log's contains matches the fields the answer shows outside a job, and the whole line only in a job, and says which", async () => {
  await withCwd(async (cwd) => {
    const path = await authDir(cwd, "oracle", {
      "auth.log": lines(
        "Feb 14 09:30:00 web01 sudo:   deploy : TTY=pts/0 ; PWD=/srv ; USER=root ; COMMAND=/usr/bin/curl --token=h",
        "Feb 14 09:30:01 web01 sshd[2]: Accepted password for deploy from 192.0.2.4 port 22 ssh2",
      ),
    });
    const outside = body(await tool(AUTH, cwd, { path, contains: "--token=h" }));
    assert.equal(outside.record_count, 0, "no oracle on the text of a command outside a job");
    assert.equal(outside.filter_touched_withheld_text, false);
    assert.match(outside.contains_scope, /fields the answer shows/);
    assert.equal(body(await tool(AUTH, cwd, { path, contains: "192.0.2.4" })).record_count, 1, "a shown field is matched");
    const inJob = body(await asJob(AUTH, cwd, { path, contains: "--token=h" }));
    assert.equal(inJob.record_count, 1);
    assert.equal(inJob.filter_touched_withheld_text, true);
  });
});

test("auth_log answers with an error, not a traceback, where it cannot write its paging file, and says status on every answer", async () => {
  await withCwd(async (cwd) => {
    const line = "Feb 14 09:30:00 web01 sshd[1]: Failed password for root from 192.0.2.1 port 1 ssh2\n";
    const path = await authDir(cwd, "status", { "auth.log": line.repeat(3) });
    const ok = body(await tool(AUTH, cwd, { path }));
    assert.equal(ok.status, "complete");
    assert.ok(ok.status_basis);
    await writeFile(join(cwd, "work", "status", "auth.log.1"), "this is no syslog line\n");
    assert.equal(body(await tool(AUTH, cwd, { path })).status, "partial");
    assert.equal(refused(await tool(AUTH, cwd, { path: "work/nothing-here" })).status, "failed");
    if (!IS_ROOT) {
      const ro = join(cwd, "ro-out");
      await mkdir(ro, { recursive: true });
      await chmod(ro, 0o555);
      try {
        const run = await tool(AUTH, cwd, { path, limit: 1 }, { JOB_ID: "j000099", OUT: ro });
        const bad = refused(run);
        assert.match(bad.error, /could not be written/);
        assert.equal(bad.status, "failed");
      } finally {
        await chmod(ro, 0o755);
      }
    }
  });
});

test("auth_log writes a byte that is not UTF-8 to the text file as an escape that reads back as the byte, and a lone CR stays", async () => {
  await withCwd(async (cwd) => {
    const bytes = Buffer.concat([Buffer.from("Feb 14 09:30:00 web01 sudo:   a : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/echo pw-"), Buffer.from([0xe9, 0xff]), Buffer.from("-end\r\r\n")]);
    const path = await authDir(cwd, "latin1", { "auth.log": bytes });
    const out = body(await asJob(AUTH, cwd, { path, write_text: true }));
    assert.equal(out.lines_with_invalid_utf8, 1);
    const raw = await readFile(join(cwd, "out", "auth-text.jsonl"), "utf8");
    assert.ok(raw.includes("\\udce9\\udcff"), "the two bytes are in the file as escapes");
    const [row] = raw.trimEnd().split("\n").map((l) => JSON.parse(l));
    assert.equal(Buffer.from(row.command, "utf8").length >= 0, true);
    assert.equal(row.command.endsWith("-end\r"), true, "one CR of the two is the line ending's, the other is the line's");
    assert.equal(out.records[0].command_bytes, "/bin/echo pw-".length + 2 + "-end\r".length);
  });
});

/**
 * A name someone typed at a prompt is withheld by its POSITION in a line the tool recognises, never by what it looks like. The
 * positions: the name after "Invalid user" / "Illegal user", after "Failed <method> for invalid user" / "illegal user", after
 * "Disconnected from invalid user", and the PAM user= and ruser= of pam_unix. Each position is filled below with eleven shapes
 * of secret (keys, tokens, passwords, passphrases with spaces, user-info, a PEM line, and text that looks like another field of
 * the same line) and the whole value is looked for in the answer and in the paging file. Rate on the old code: 78 of 88 shapes
 * in the answer; on this code: 0 of 88.
 */
const SHAPES: Record<string, string> = {
  aws: "AKIAIOSFODNN7EXAMPLE",
  awsSecret: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  base64: "Zk9mQ2xW7vB3nL8pR4tY6w/+==",
  jwt: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk",
  password: "Tr0ub4dor&3xyz",
  passphrase: "correct horse battery staple",
  assignment: "password=hunter2xyz",
  userinfo: "https://svc:s3cretpw@host.example/path",
  pem: "-----BEGIN-OPENSSH-KEY-----",
  fieldLike: "bob tty=PLANTEDTTYVALUE",
  fromLike: "bob from PLANTEDFROMVALUE",
};
const SLOTS: Record<string, (v: string) => string> = {
  invalidUser: (v) => `sshd[1]: Invalid user ${v} from 203.0.113.9 port 4000`,
  illegalUser: (v) => `sshd[1]: Illegal user ${v} from 203.0.113.9 port 4000`,
  failedInvalid: (v) => `sshd[1]: Failed password for invalid user ${v} from 203.0.113.9 port 4000 ssh2`,
  failedIllegal: (v) => `sshd[1]: Failed password for illegal user ${v} from 203.0.113.9 port 4000 ssh2`,
  disconnected: (v) => `sshd[1]: Disconnected from invalid user ${v} 203.0.113.9 port 4000 [preauth]`,
  pamUser: (v) => `sshd[1]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.9  user=${v}`,
  pamRuser: (v) => `dovecot: pam_unix(dovecot:auth): authentication failure; logname= uid=0 euid=0 tty=dovecot ruser=${v} rhost=203.0.113.9`,
  failedKey: (v) => `sshd[1]: Failed publickey for invalid user ${v} from 203.0.113.9 port 4000 ssh2: RSA SHA256:abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG`,
};

test("auth_log withholds a typed name by its position: eight positions, eleven shapes of secret, none in the answer or the paging file", async () => {
  await withCwd(async (cwd) => {
    const all: string[] = [];
    const planted: { slot: string; shape: string; value: string }[] = [];
    for (const [slot, make] of Object.entries(SLOTS)) {
      for (const [shape, value] of Object.entries(SHAPES)) {
        all.push(`Feb 14 09:30:00 web01 ${make(value)}`);
        planted.push({ slot, shape, value });
      }
    }
    const path = await authDir(cwd, "typed", { "auth.log": lines(...all) });
    const run = await tool(AUTH, cwd, { path, limit: 20 });
    const out = body(run);
    const rows = await rowsOf(cwd, out);
    const everything = await everythingBut(cwd, run.stdout, []);
    assert.equal(rows.length, planted.length, "every line is a record");
    const leaks = planted.filter((p) => everything.includes(p.value));
    assert.deepEqual(leaks, [], `${leaks.length} of ${planted.length} planted values reached the answer or the paging file`);
    // Every recognised position gives a typed field, with its whole length, in file order.
    for (const [i, p] of planted.entries()) {
      const field = p.slot === "pamRuser" ? "ruser" : "user";
      assert.equal(rows[i][field], undefined, `${p.slot}/${p.shape}: ${field} printed`);
      assert.equal(rows[i][`${field}_bytes`], Buffer.byteLength(p.value), `${p.slot}/${p.shape}: the whole name has its length`);
      assert.equal(rows[i].source, "203.0.113.9", `${p.slot}/${p.shape}: the source is the address after the name, not a word of the name`);
      assert.equal(rows[i].source_unvalidated, undefined, `${p.slot}/${p.shape}: nothing unvalidated stands in for a source`);
      assert.equal(rows[i].tty === undefined || rows[i].tty === "ssh" || rows[i].tty === "dovecot", true, `${p.slot}/${p.shape}: a tty= inside the name set a field`);
    }
    // A job's text file has the names whole.
    const job = body(await asJob(AUTH, cwd, { path, write_text: true }, undefined, {}, "out-typed"));
    const text = await readFile(join(cwd, "out-typed", "auth-text.jsonl"), "utf8");
    assert.ok(text.includes(SHAPES.passphrase) && text.includes(SHAPES.fromLike));
    assert.equal(job.record_count, planted.length);
  });
});

test("auth_log: the lines with no typed position print nothing a name could be in, and say so honestly in the skill's words", async () => {
  await withCwd(async (cwd) => {
    const path = await authDir(cwd, "other", {
      "auth.log": lines(
        "Feb 14 09:30:00 web01 sshd[1]: Connection closed by invalid user TYPEDWORD1 203.0.113.9 port 4000 [preauth]",
        "Feb 14 09:30:01 web01 sshd[1]: Disconnected from invalid user TYPEDWORD2",
        "Feb 14 09:30:02 web01 sshd[1]: error: maximum authentication attempts exceeded for invalid user TYPEDWORD3 from 203.0.113.9 port 4000 ssh2 [preauth]",
      ),
    });
    const run = await tool(AUTH, cwd, { path });
    const rows = await rowsOf(cwd, body(run));
    assert.deepEqual(rows.map((r) => r.kind), ["other", "other", "other"]);
    assert.ok(!run.stdout.includes("TYPEDWORD"), "an unrecognised line prints no field");
  });
});

test("auth_log reads a name with a from-clause in it as a name, and the real source after it", async () => {
  await withCwd(async (cwd) => {
    const path = await authDir(cwd, "from", {
      "auth.log": lines(
        "Feb 14 09:30:00 web01 sshd[1]: Invalid user x from 198.51.100.1 port 1 from 203.0.113.9 port 4000",
        "Feb 14 09:30:01 web01 sshd[1]: Failed password for invalid user x from 198.51.100.1 port 1 from 203.0.113.9 port 4000 ssh2",
        "Feb 14 09:30:02 web01 sshd[1]: Failed password for root from 203.0.113.9 port 4000 ssh2",
      ),
    });
    const rows = await rowsOf(cwd, body(await tool(AUTH, cwd, { path })));
    assert.deepEqual(rows.map((r) => r.source), ["203.0.113.9", "203.0.113.9", "203.0.113.9"]);
    assert.equal(rows[0].user_bytes, "x from 198.51.100.1 port 1".length);
    assert.equal(rows[2].user, "root", "an account the log does not call invalid is shown");
  });
});

test("auth_log reads the clock inside a line of many pieces: a file with no newline ends at max_seconds", async () => {
  await withCwd(async (cwd) => {
    const path = await authDir(cwd, "sparse", { "auth.log": "Feb 14 09:30:00 web01 sshd[1]: ok\n" });
    // 3 GiB with no newline after the first line, as a sparse file (no disk is written).
    const { open } = await import("node:fs/promises");
    const fh = await open(join(cwd, path, "auth.log"), "a");
    await fh.truncate(3 * 1024 ** 3);
    await fh.close();
    const started = Date.now();
    const out = body(await tool(AUTH, cwd, { path, max_seconds: 1 }));
    const took = (Date.now() - started) / 1000;
    assert.ok(took < 30, `took ${took} s for max_seconds 1`);
    assert.notEqual(out.status, "complete");
    assert.match(JSON.stringify(out.read_errors), /max_seconds/, "the deadline was read inside the long line, and the file is named as not read further");
  });
});

test("auth_log does not call the order of files consistent when one of them is ordered by its name only", async () => {
  await withCwd(async (cwd) => {
    const path = await authDir(cwd, "named", {
      "auth.log": lines("Feb 10 09:30:00 web01 sshd[1]: Failed password for root from 203.0.113.9 port 4000 ssh2"),
      "auth.log.bak": lines("Jan 10 09:30:00 web01 sshd[1]: Failed password for root from 203.0.113.9 port 4000 ssh2"),
    });
    const out = body(await tool(AUTH, cwd, { path }));
    assert.match(out.cross_file_order, /^not established: a file is ordered by its name only/);
    const one = await authDir(cwd, "one", { "auth.log.bak": lines("Feb 10 09:30:00 web01 sshd[1]: Failed password for root from 203.0.113.9 port 4000 ssh2") });
    assert.equal(body(await tool(AUTH, cwd, { path: one })).cross_file_order, "consistent");
  });
});

// ---- auth_log: the portless disconnect --------------------------------------------------------------------------

test("auth_log reads the whole tail of a portless 'Disconnected from invalid user' as the typed name", async () => {
  await withCwd(async (cwd) => {
    const path = await authDir(cwd, "portless", {
      "auth.log": lines(
        "Feb 14 09:30:00 web01 sshd[1]: Disconnected from invalid user a x port 1 PLANTEDSTAGEVALUE 203.0.113.9",
        "Feb 14 09:30:01 web01 sshd[1]: Disconnected from invalid user bob 203.0.113.9 port 4000 [preauth]",
        "Feb 14 09:30:02 web01 sshd[1]: Disconnected from invalid user c y port 2 203.0.113.8 port 4001 [preauth]",
      ),
    });
    const run = await tool(AUTH, cwd, { path });
    const rows = await rowsOf(cwd, body(run));
    assert.equal(run.stdout.includes("PLANTEDSTAGEVALUE"), false);
    assert.equal(rows[0].source, undefined);
    assert.equal(rows[0].port, undefined);
    assert.equal(rows[0].stage, undefined);
    assert.equal(rows[0].user_bytes, "a x port 1 PLANTEDSTAGEVALUE 203.0.113.9".length);
    assert.deepEqual([rows[1].source, rows[1].port, rows[1].stage], ["203.0.113.9", 4000, "[preauth]"]);
    assert.deepEqual([rows[2].source, rows[2].port, rows[2].user_bytes], ["203.0.113.8", 4001, "c y port 2".length]);
  });
});

// ---- auth_log: the year of a traditional line is an inference, and the answer says how weak ------------------------------

const FAILED = (stamp: string, n: number): string => `${stamp} h sshd[${n}]: Failed password for root from 192.0.2.1 port ${n} ssh2`;
const wholeDays = (a: Date, b: Date): number => Math.floor((b.getTime() - a.getTime()) / 86_400_000);

test("auth_log flags every record before a long forward step, names the step and the line that anchored the year, and does not move a date", async () => {
  await withCwd(async (cwd) => {
    // Spring setup lines, then autumn lines, and a file last written in a later year: the spring lines come out in the
    // autumn's year (the dating rule is unchanged), and the answer says that this is an assumption.
    const path = await authDir(
      cwd,
      "steps",
      {
        "auth.log": lines(
          FAILED("Apr 15 10:00:00", 1),
          FAILED("Apr 16 10:00:00", 2),
          FAILED("Oct  5 10:00:00", 3),
          FAILED("Oct  6 10:00:00", 4),
        ),
      },
      { "auth.log": new Date(Date.UTC(2031, 10, 20, 12, 0, 0)) },
    );
    const out = body(await tool(AUTH, cwd, { path }));
    const [file] = out.files;
    const rows = await rowsOf(cwd, out);
    assert.deepEqual(rows.map((r) => String(r.time).slice(0, 10)), ["2031-04-15", "2031-04-16", "2031-10-05", "2031-10-06"], "the dating rule did not move");
    assert.equal(out.status, "complete");
    assert.deepEqual(rows.map((r) => r.year_assumed === true), [true, true, false, false], "every record before the last long step, and none after it");
    assert.equal(file.forward_step_count, 1);
    assert.equal(file.forward_steps.length, 1);
    const expectedDays = wholeDays(new Date(Date.UTC(2000, 3, 16, 10)), new Date(Date.UTC(2000, 9, 5, 10)));
    assert.deepEqual(
      { line: file.forward_steps[0].line, from: file.forward_steps[0].from, to: file.forward_steps[0].to, days: file.forward_steps[0].days },
      { line: 3, from: "Apr 16 10:00:00", to: "Oct  5 10:00:00", days: expectedDays },
    );
    assert.equal(file.year_assumed_before_line, 3);
    assert.equal(out.pages.forward_steps.matched, 1);
    assert.equal(file.year_anchor.line, 4, "the last line in order is the line whose date the modification time anchored");
    assert.equal(file.year_anchor.stamp, "Oct  6 10:00:00");
    assert.equal(file.year_anchor.mtime, "2031-11-20T12:00:00Z");
    assert.equal(file.year_anchor.year, 2031);
    assert.equal(file.year_anchor.used_for_dating, true);
    // A step shorter than the bound is not a step, and the old fixture of a gap is unchanged: January to September is one.
    const near = await authDir(cwd, "near", { "auth.log": lines(FAILED("Mar  1 10:00:00", 1), FAILED("Apr 15 10:00:00", 2)) }, { "auth.log": new Date(Date.UTC(2026, 3, 16)) });
    const calm = body(await tool(AUTH, cwd, { path: near }));
    assert.equal(calm.files[0].forward_step_count, 0);
    assert.ok((await rowsOf(cwd, calm)).every((r) => r.year_assumed === undefined));
  });
});

test("auth_log keeps every forward step whole in a page and a year end that is also a long step is a step", async () => {
  await withCwd(async (cwd) => {
    // Quarterly lines for eight years: 31 steps of 90 days or more, three of them through a year end.
    const quarter = ["Jan  5", "Apr  5", "Jul  5", "Oct  5"];
    const all: string[] = [];
    for (let i = 0; i < 32; i++) all.push(FAILED(`${quarter[i % 4]} 10:00:00`, i + 1));
    const path = await authDir(cwd, "quarters", { "auth.log": lines(...all) }, { "auth.log": new Date(Date.UTC(2030, 11, 1)) });
    const out = body(await tool(AUTH, cwd, { path, limit: 5 }));
    const [file] = out.files;
    assert.equal(file.forward_step_count, 31);
    assert.equal(file.forward_steps.length, 20, "the inline list is capped");
    assert.equal(out.pages.forward_steps.matched, 31);
    assert.ok(out.pages.forward_steps.all_results, "the whole list is in the tool's page");
    const steps = await rowsOf(cwd, out, "forward_steps");
    assert.equal(steps.length, 31);
    assert.ok(steps.every((s) => s.days > 62 && s.file.endsWith("auth.log")));
    assert.ok(steps.some((s) => s.from.startsWith("Oct") && s.to.startsWith("Jan")), "a step through a year end is reported");
    const rows = await rowsOf(cwd, out);
    assert.equal(rows.length, 32);
    assert.equal(rows.filter((r) => r.year_assumed === true).length, 31, "every record before the last step, which ends at line 32; line 32 itself not");
  });
});

test("auth_log says when the modification time that anchors the year may be the time of a copy", async () => {
  await withCwd(async (cwd) => {
    const recent = { "auth.log": lines(FAILED("Oct  5 10:00:00", 1), FAILED("Oct  6 10:00:00", 2)) };
    // A copy made years after the log was last written.
    const now = new Date(Date.UTC(2031, 5, 1));
    const copied = await authDir(cwd, "copied", recent, { "auth.log": now });
    const a = body(await tool(AUTH, cwd, { path: copied })).files[0];
    assert.equal(a.mtime_may_be_copy_time, true);
    assert.match(a.mtime_may_be_copy_time_why.join(" "), /days after the last dated line/);
    // A live file: written the day of its last line.
    const live = await authDir(cwd, "live", recent, { "auth.log": new Date(Date.UTC(2026, 9, 6, 10, 30, 0)) });
    const b = body(await tool(AUTH, cwd, { path: live })).files[0];
    assert.equal(b.mtime_may_be_copy_time, false);
    assert.equal(b.mtime_may_be_copy_time_why, undefined);
    // A tree in which every file has one time, to within seconds, and a tree in which they differ.
    const same = new Date(Date.UTC(2026, 9, 6, 10, 30, 0));
    const tree = await authDir(
      cwd,
      "tree",
      { "auth.log": lines(FAILED("Oct  6 10:00:00", 1)), "auth.log.1": lines(FAILED("Oct  5 10:00:00", 1)), "auth.log.2": lines(FAILED("Oct  4 10:00:00", 1)) },
      { "auth.log": same, "auth.log.1": new Date(same.getTime() + 3000), "auth.log.2": new Date(same.getTime() + 6000) },
    );
    const together = body(await tool(AUTH, cwd, { path: tree }));
    assert.deepEqual(together.files.map((f: Json) => f.mtime_may_be_copy_time), [true, true, true]);
    assert.match(together.files[0].mtime_may_be_copy_time_why.join(" "), /same modification time/);
    const apart = await authDir(
      cwd,
      "apart",
      { "auth.log": lines(FAILED("Oct  6 10:00:00", 1)), "auth.log.1": lines(FAILED("Oct  5 10:00:00", 1)) },
      { "auth.log": new Date(Date.UTC(2026, 9, 6, 10, 30, 0)), "auth.log.1": new Date(Date.UTC(2026, 9, 5, 23, 59, 0)) },
    );
    assert.deepEqual(body(await tool(AUTH, cwd, { path: apart })).files.map((f: Json) => f.mtime_may_be_copy_time), [false, false]);
  });
});

/** A gzip stream with the header time (RFC 1952: bytes 4 to 7, little-endian) set to `seconds`. */
function gzipWithHeaderTime(text: string, seconds: number): Buffer {
  const data = Buffer.from(gzipSync(Buffer.from(text)));
  data.writeUInt32LE(seconds, 4);
  return data;
}

test("auth_log reads a gzip's header time beside the file's modification time and says whether they agree", async () => {
  await withCwd(async (cwd) => {
    const text = lines(FAILED("Oct  5 10:00:00", 1), FAILED("Oct  6 10:00:00", 2));
    const written = new Date(Date.UTC(2026, 9, 6, 10, 30, 0));
    const copiedAt = new Date(Date.UTC(2026, 10, 2, 8, 0, 0));
    const path = await authDir(
      cwd,
      "gz",
      {
        "auth.log.1.gz": gzipWithHeaderTime(text, written.getTime() / 1000),     // logrotate: the header is the log's own last write
        "auth.log.2.gz": gzipWithHeaderTime(text, written.getTime() / 1000),     // the same, then copied: the file has the copy's time
        "auth.log.3.gz": gzipWithHeaderTime(text, 0),                            // the compressor recorded no time
      },
      { "auth.log.1.gz": written, "auth.log.2.gz": copiedAt, "auth.log.3.gz": new Date(written.getTime() - 86_400_000) },
    );
    const out = body(await tool(AUTH, cwd, { path }));
    const byName = Object.fromEntries(out.files.map((f: Json) => [String(f.path).split("/").pop(), f]));
    const agree = byName["auth.log.1.gz"];
    assert.equal(agree.gzip_header_time, "2026-10-06T10:30:00Z");
    assert.equal(agree.modified, "2026-10-06T10:30:00Z");
    assert.equal(agree.gzip_header_agrees_with_modified, true);
    assert.equal(agree.mtime_may_be_copy_time, false);
    const differ = byName["auth.log.2.gz"];
    assert.equal(differ.gzip_header_time, "2026-10-06T10:30:00Z");
    assert.equal(differ.modified, "2026-11-02T08:00:00Z");
    assert.equal(differ.gzip_header_agrees_with_modified, false, "both are reported and the disagreement is said");
    assert.equal(differ.mtime_may_be_copy_time, true);
    assert.match(differ.mtime_may_be_copy_time_why.join(" "), /gzip header time/);
    const none = byName["auth.log.3.gz"];
    assert.equal(none.gzip_header_time, null);
    assert.equal(none.gzip_header_time_recorded, false, "a header time of 0 means none");
    assert.equal(none.gzip_header_agrees_with_modified, null);
  });
});

test("auth_log applies a year per file and per line range, validates the list, and says where it applied", async () => {
  await withCwd(async (cwd) => {
    const path = await authDir(
      cwd,
      "ranges",
      {
        "auth.log": lines(
          FAILED("Apr 15 10:00:00", 1),
          FAILED("Apr 16 10:00:00", 2),
          FAILED("Oct  5 10:00:00", 3),
          FAILED("Oct  6 10:00:00", 4),
          FAILED("Oct  7 10:00:00", 5),
        ),
        "auth.log.1": lines(FAILED("Sep  1 10:00:00", 1)),
      },
      { "auth.log": new Date(Date.UTC(2031, 10, 20)), "auth.log.1": new Date(Date.UTC(2031, 8, 2)) },
    );
    const file = `${path}/auth.log`;
    const out = body(await tool(AUTH, cwd, { path, years: [{ file, from_line: 1, year: 2016 }, { file, from_line: 3, year: 2019 }] }));
    const rows = (await rowsOf(cwd, out)).filter((r) => String(r.file).endsWith("/auth.log"));
    assert.deepEqual(rows.map((r) => String(r.time).slice(0, 10)), ["2016-04-15", "2016-04-16", "2019-10-05", "2019-10-06", "2019-10-07"]);
    assert.deepEqual(rows.map((r) => r.year), [2016, 2016, 2019, 2019, 2019]);
    assert.ok(rows.every((r) => r.year_assumed === undefined), "a year the caller gave is not an assumed one");
    const main = out.files.find((f: Json) => String(f.path).endsWith("/auth.log"));
    assert.match(main.year_basis, /years argument/);
    assert.deepEqual(main.years_applied, [{ from_line: 1, year: 2016, dated_lines: 2 }, { from_line: 3, year: 2019, dated_lines: 3 }]);
    assert.equal(main.years_span_rollover, false);
    const other = out.files.find((f: Json) => String(f.path).endsWith("/auth.log.1"));
    assert.match(other.year_basis, /^file mtime/, "a file with no range keeps the mtime basis");
    assert.equal(other.years_applied, undefined);
    // A range from line 2 on leaves line 1 to the modification time; `year` keeps its meaning for the lines no range covers.
    const partial = body(await tool(AUTH, cwd, { path, years: [{ file, from_line: 3, year: 2019 }], year: 2012 }));
    const prows = (await rowsOf(cwd, partial)).filter((r) => String(r.file).endsWith("/auth.log"));
    assert.deepEqual(prows.map((r) => r.year), [2012, 2012, 2019, 2019, 2019]);
    const spans = body(await tool(AUTH, cwd, { path: await authDir(cwd, "wraps", { "auth.log": lines(FAILED("Dec 31 23:00:00", 1), FAILED("Jan  1 00:10:00", 2)) }, { "auth.log": new Date(Date.UTC(2026, 0, 2)) }), years: [{ file: "work/wraps/auth.log", from_line: 1, year: 2020 }] }));
    assert.equal(spans.files[0].years_span_rollover, true, "a range that holds a year end applies one year to both sides, and says so");
  });
});

test("auth_log refuses a hostile years list in JSON before it reads or writes anything", async () => {
  await withCwd(async (cwd) => {
    const path = await authDir(cwd, "hostile", { "auth.log": lines(FAILED("Apr 15 10:00:00", 1), FAILED("Oct  5 10:00:00", 2)) });
    const file = `${path}/auth.log`;
    const entry = (from_line: number, year: unknown = 2019, f: string = file) => ({ file: f, from_line, year });
    const bad: Array<[string, unknown, RegExp]> = [
      ["an unknown file", [entry(1, 2019, "work/hostile/elsewhere.log")], /not one of the files/],
      ["overlapping ranges", [entry(2), entry(2)], /ascending|overlap/],
      ["descending ranges", [entry(5), entry(2)], /ascending|overlap/],
      ["a fractional year", [entry(1, 2019.5)], /year must be a whole year/],
      ["a string year", [entry(1, "2019")], /year must be a whole year/],
      ["a year out of range", [entry(1, 1969)], /year must be a whole year/],
      ["a boolean year", [entry(1, true)], /year must be a whole year/],
      ["line zero", [entry(0)], /from_line/],
      ["a fractional line", [entry(1.5)], /from_line/],
      ["an extra key", [{ ...entry(1), note: "x" }], /exactly file, from_line and year/],
      ["a bare number", [3], /exactly file, from_line and year/],
      ["not a list", { file }, /list/],
      ["more entries than are read", Array.from({ length: 1001 }, (_, i) => entry(i + 1)), /at most 1000/],
    ];
    for (const [what, years, why] of bad) {
      const answer = refused(await tool(AUTH, cwd, { path, years }));
      assert.equal(answer.status, "failed", what);
      assert.match(answer.error, why, what);
    }
    assert.deepEqual(await filesUnder(join(cwd, "work", "s1")), [], "a refusal wrote nothing");
    // The list at its bound is read.
    const edge = body(await tool(AUTH, cwd, { path, years: Array.from({ length: 1000 }, (_, i) => entry(i + 1)) }));
    assert.equal(edge.status, "complete");
  });
});

test("auth_log's first pass keeps one byte per dated line, not seventeen", () => {
  // The pass-one state is exercised on its own: a million dated lines in, and what the process holds for them, measured.
  const script = [
    "import importlib.util, sys, tracemalloc",
    `spec = importlib.util.spec_from_file_location('auth_log_run', ${JSON.stringify(AUTH)})`,
    "m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)",
    "N = 1_000_000",
    "tracemalloc.start()",
    "scan = m.MonthScan()",
    "packed = ((((10 * 32 + 5) * 24 + 10) * 60) * 61)",
    "for i in range(N):",
    "    scan.push(10, packed, i + 1)",
    "scan.finish()",
    "current, _peak = tracemalloc.get_traced_memory()",
    "print(current / N, len(scan.classes))",
  ].join("\n");
  const run = spawnSync("python3", ["-c", script], { encoding: "utf8" });
  assert.equal(run.status, 0, run.stderr);
  const [perLine, kept] = run.stdout.trim().split(" ").map(Number);
  assert.equal(kept, 1_000_000);
  assert.ok(perLine < 2, `pass one kept ${perLine} bytes per dated line`);
});

// ---- auth_log: the text flags are declared secret output, and refused unless SECRET_OUTPUT is 1 ----------------------------------

test("auth_log declares secret_output for write_text and preview_text, and refuses each, creating nothing, unless SECRET_OUTPUT is 1", async () => {
  const { dirname } = await import("node:path");
  const manifest = JSON.parse(await readFile(join(dirname(AUTH), "manifest.json"), "utf8"));
  assert.deepEqual(manifest.secret_output, { when_args: ["write_text", "preview_text"] });
  for (const flag of manifest.secret_output.when_args) {
    assert.equal(manifest.params[flag].type, "boolean");
    assert.equal(manifest.params[flag].default, undefined);
    assert.match(manifest.params[flag].description, /SENSITIVE/);
  }
  await withCwd(async (cwd) => {
    const path = await authDir(cwd, "declared", { "auth.log": lines("Oct  5 10:00:00 h sudo: bob : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/echo PLANTEDVALUE") });
    for (const flag of ["write_text", "preview_text"]) {
      const before = await filesUnder(cwd);
      assert.match(refused(await tool(AUTH, cwd, { path, [flag]: true })).error, /outside a job/, flag);
      for (const value of [undefined, "0", "true", ""]) {
        const env = value === undefined ? {} : { SECRET_OUTPUT: value };
        const answer = refused(await plainJob(AUTH, cwd, { path, [flag]: true }, undefined, env, "out-plain"));
        assert.match(answer.error, /SECRET_OUTPUT/, `${flag} with SECRET_OUTPUT=${value}`);
        assert.match(answer.error, /Nothing was written/);
        assert.doesNotMatch(JSON.stringify(answer), /PLANTEDVALUE/);
      }
      assert.deepEqual((await filesUnder(cwd)).filter((f) => !f.startsWith("out-plain/")), before, `${flag}: a refusal creates nothing outside the job's directory`);
      assert.deepEqual(await filesUnder(join(cwd, "out-plain")), [], `${flag}: and nothing in the job's own`);
    }
    // As a secret-output job: the file is written, mode 0600; the preview carries the text.
    const written = body(await asJob(AUTH, cwd, { path, write_text: true }, undefined, {}, "out-ok"));
    assert.equal(written.text.written, 1);
    assert.equal((await stat(join(cwd, "out-ok", "auth-text.jsonl"))).mode & 0o777, 0o600);
    assert.match(await readFile(join(cwd, "out-ok", "auth-text.jsonl"), "utf8"), /PLANTEDVALUE/);
    const preview = body(await asJob(AUTH, cwd, { path, preview_text: true }, undefined, {}, "out-pv"));
    assert.match(JSON.stringify(preview.records), /PLANTEDVALUE/);
  });
});
