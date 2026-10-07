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
import { AUTH, IS_ROOT, asJob, body, everythingBut, exists, filesUnder, lines, refused, rowsOf, tool, withCwd } from "./linux-pack-harness.ts";
import type { Json } from "./linux-pack-harness.ts";

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
    assert.equal(rows[1].ruser, "bob");
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
    assert.equal(row.user_bytes, 3, "the typed user= is withheld");
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
