/**
 * network-forensics: zeek_run drives Zeek over a capture and reads its logs back.
 *
 * Zeek is not on every machine these suites run on, so a stand-in program plays it: `--version` prints a
 * version line, and a run copies prepared log files into the directory it is started in, the way Zeek writes
 * its logs into the working directory. The log files are written from the layout Zeek's documentation gives for
 * its ASCII logs (#separator, #set_separator, #empty_field, #unset_field, #path, #fields, #types, then rows) and
 * for its JSON logs, never from this tool's output. That proves the wrapper's logic (the policy script it
 * writes, the checksum switch, the reading of a header, the counting of what does not fit it, what is withheld
 * inline); it proves nothing about a real Zeek: whether the installed build has a policy by a given name, and
 * what it hashes, is a thing the logs of that build show.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { ZEEK, asJob, body, everythingUnder, exists, filesUnder, gone, pidFile, put, refused, startDetached, stub, tool, withCwd } from "./pack-network-harness.ts";
import type { Json } from "./pack-network-harness.ts";

const sha = (b: Buffer | string): string => createHash("sha256").update(b).digest("hex");

const ZEEK_STUB = `#!/bin/sh
printf '%s\\n' "$*" >> "$STUB_LOG"
for a in "$@"; do
  case "$a" in
    --version) [ -f "$STUB_DIR/version-fail" ] && { echo "zeek: version failed on request" >&2; exit 3; }; printf 'zeek version 8.0.10-stand-in\\n'; exit 0;;
  esac
done
[ -f "$STUB_DIR/sleep" ] && { echo $$ > "$STUB_DIR/engine.pid"; sleep 60 & echo $! > "$STUB_DIR/child.pid"; echo started > "$STUB_DIR/started"; wait; }
[ -f "$STUB_DIR/version-fail" ] && case "$*" in *--version*) echo "zeek: version failed on request" >&2; exit 3;; esac
[ -d "$STUB_DIR/logs" ] && cp -R "$STUB_DIR/logs/." .
[ -f "$STUB_DIR/stderr" ] && cat "$STUB_DIR/stderr" >&2
if [ -f "$STUB_DIR/exit" ]; then exit "$(cat "$STUB_DIR/exit")"; fi
exit 0
`;

async function stage(cwd: string, bin: string, logs: Record<string, string>, o: { exit?: number; sleep?: boolean; stderr?: string; versionFail?: boolean } = {}): Promise<string> {
  const dir = join(cwd, "stub");
  await rm(dir, { recursive: true, force: true });
  await mkdir(join(dir, "logs"), { recursive: true });
  await stub(bin, "zeek", ZEEK_STUB);
  for (const [name, text] of Object.entries(logs)) await writeFile(join(dir, "logs", name), text);
  if (o.exit !== undefined) await writeFile(join(dir, "exit"), String(o.exit));
  if (o.sleep) await writeFile(join(dir, "sleep"), "1");
  if (o.versionFail) await writeFile(join(dir, "version-fail"), "1");
  if (o.stderr) await writeFile(join(dir, "stderr"), o.stderr);
  await writeFile(join(cwd, "zeek-calls.txt"), "");
  return dir;
}

const env = (cwd: string) => ({ STUB_DIR: join(cwd, "stub"), STUB_LOG: join(cwd, "zeek-calls.txt") });
const capture = (cwd: string) => put(cwd, "work/c.pcap", Buffer.from("not read by the stand-in")).then(() => "work/c.pcap");

/** A Zeek ASCII log as its documentation lays it out: header lines, the rows, a close line. Tabs are real tabs. */
function tsvLog(path: string, fields: string[], types: string[], rows: string[][], o: { separator?: string; separatorEscape?: string } = {}): string {
  const sep = o.separator ?? "\t";
  const head = [
    `#separator ${o.separatorEscape ?? "\\x09"}`,
    ["#set_separator", ","].join(sep),
    ["#empty_field", "(empty)"].join(sep),
    ["#unset_field", "-"].join(sep),
    ["#path", path].join(sep),
    ["#open", "2023-11-14-22-13-20"].join(sep),
    ["#fields", ...fields].join(sep),
    ["#types", ...types].join(sep),
  ];
  return [...head, ...rows.map((r) => r.join(sep)), ["#close", "2023-11-14-22-14-00"].join(sep)].join("\n") + "\n";
}

const CONN_FIELDS = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "duration", "orig_bytes", "resp_bytes", "local_orig", "tunnel_parents"];
const CONN_TYPES = ["time", "string", "addr", "port", "addr", "port", "enum", "interval", "count", "count", "bool", "set[string]"];
const CONN_ROW = ["1700000000.123456", "CYWJAH2BG8ssSd3Mpk", "10.0.0.5", "50000", "203.0.113.7", "443", "tcp", "0.25", "120", "3400", "T", "(empty)"];

const FILES_FIELDS = ["ts", "fuid", "source", "seen_bytes", "total_bytes", "filename"];
const FILES_TYPES = ["time", "string", "string", "count", "count", "string"];

test("files.log without a hash column is said so; with one, the hashes are counted and a short object's hash stays out of the inline records", async () => {
  await withCwd(async (cwd, bin) => {
    await stage(cwd, bin, {
      "conn.log": tsvLog("conn", CONN_FIELDS, CONN_TYPES, [CONN_ROW]),
      "files.log": tsvLog("files", FILES_FIELDS, FILES_TYPES, [["1700000001.5", "FRnTpZ3Fp5vYbpNQP", "HTTP", "5000", "5000", "report.pdf"]]),
    });
    const out = body(await tool(ZEEK, cwd, { path: await capture(cwd), out_dir: "work/z" }, env(cwd), bin));
    assert.equal(out.hashes_produced, false);
    assert.deepEqual(out.hash_fields, []);
    assert.equal(out.files_log.records, 1);
    assert.equal(out.files_log.records_with_a_hash, 0);
    assert.doesNotMatch(out.note + JSON.stringify(out), /a hash per reassembled object/);
    assert.equal(out.ok, true);
    // Version, command, checksum switch and policy script are recorded.
    assert.match(out.zeek_version, /8\.0\.10/);
    assert.equal(out.checksum_validation, false);
    assert.ok(out.command.includes("-C"), "checksums off is -C, and it is said");
    assert.match(out.checksum_note, /NOT validated/);
    assert.deepEqual(out.policy.requested, ["policy/frameworks/files/hash-all-files"]);
    const script = await readFile(join(cwd, "work/z/network-forensics.local.zeek"), "utf8");
    assert.match(script, /^@load policy\/frameworks\/files\/hash-all-files$/m);
    assert.equal(out.policy.script_sha256, sha(script));
    assert.equal(out.policy.script, "work/z/network-forensics.local.zeek");
    const calls = await readFile(join(cwd, "zeek-calls.txt"), "utf8");
    assert.match(calls, /-C -r .*work\/c\.pcap .*network-forensics\.local\.zeek/);
  });
  await withCwd(async (cwd, bin) => {
    const big = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    await stage(cwd, bin, {
      "files.log": tsvLog("files", [...FILES_FIELDS, "md5", "sha1", "sha256"], [...FILES_TYPES, "string", "string", "string"], [
        ["1700000001.5", "FRnTpZ3Fp5vYbpNQP", "HTTP", "5000", "5000", "report.pdf", "d41d8cd98f00b204e9800998ecf8427e", "da39a3ee5e6b4b0d3255bfef95601890afd80709", big],
        ["1700000002.5", "FaB8gP2c4eRtUvWx1", "HTTP", "40", "40", "pw.txt", "c4ca4238a0b923820dcc509a6f75849b", "356a192b7913b04c54574d18c28d46e6395428ab", "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b"],
      ]),
    });
    const out = body(await tool(ZEEK, cwd, { path: await capture(cwd), out_dir: "work/z" }, env(cwd), bin));
    assert.equal(out.hashes_produced, true);
    assert.deepEqual(out.hash_fields, ["md5", "sha1", "sha256"]);
    assert.equal(out.files_log.records_with_a_hash, 2);
    const [first, second] = out.logs.files.records;
    assert.equal(first.sha256, big, "an object of 5000 bytes keeps its hash inline");
    assert.match(second.sha256, /shorter than 128 bytes/);
    assert.match(second.md5, /shorter than 128 bytes/);
    assert.doesNotMatch(JSON.stringify(out), /6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b/);
    assert.equal(out.withheld.inline_records.short_hashes, 3);
    // Zeek's own log is whole.
    assert.match(await readFile(join(cwd, "work/z/files.log"), "utf8"), /6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b/);
  });
});

test("a policy is a name, never a path or a script from the evidence; none loads nothing; checksum_validation drops -C", async () => {
  await withCwd(async (cwd, bin) => {
    await stage(cwd, bin, { "conn.log": tsvLog("conn", CONN_FIELDS, CONN_TYPES, [CONN_ROW]) });
    for (const bad of ["inputs/evil.zeek", "/etc/passwd", "../x", "policy/../../x", "work/mine.zeek", "a b", ""]) {
      const err = refused(await tool(ZEEK, cwd, { path: await capture(cwd), out_dir: "work/refused", policies: [bad] }, env(cwd), bin));
      assert.match(err.error, /policy is a name Zeek resolves/);
      assert.equal(await exists(join(cwd, "work/refused")), false, "nothing written for a refused policy");
    }
    assert.equal((await readFile(join(cwd, "zeek-calls.txt"), "utf8")).includes("-r"), false, "zeek was never run for a refused policy");
    const none = body(await tool(ZEEK, cwd, { path: await capture(cwd), out_dir: "work/none", policies: [], checksum_validation: true }, env(cwd), bin));
    assert.equal(none.policy.script, null);
    assert.match(none.policy.note, /base scripts only/);
    assert.equal(none.command.includes("-C"), false);
    assert.equal(none.checksum_validation, true);
    assert.equal(await exists(join(cwd, "work/none/network-forensics.local.zeek")), false);
    const many = body(await tool(ZEEK, cwd, { path: await capture(cwd), out_dir: "work/many", policies: ["policy/protocols/ssl/validate-certs", "policy/misc/capture-loss"] }, env(cwd), bin));
    const script = await readFile(join(cwd, "work/many/network-forensics.local.zeek"), "utf8");
    assert.match(script, /@load policy\/protocols\/ssl\/validate-certs\n@load policy\/misc\/capture-loss\n/);
    assert.equal(many.policy.script_sha256, sha(script));
  });
});

test("the log reader follows the log's own header: another separator, escapes, sets, unset and empty, times with their fractions, bool, ints", async () => {
  await withCwd(async (cwd, bin) => {
    const rows = [
      // a field holding a tab as \x09 and a UTF-8 e-acute as \xc3\xa9, a set of two, a port, a bool
      ["1700000000.123456", "CYWJAH2BG8ssSd3Mpk", "10.0.0.5", "50000", "203.0.113.7", "443", "tcp", "-", "120", "-", "F", "a,b"],
      ["1700000000.000001", "C2", "2001:db8::1", "123", "2001:db8::2", "53", "udp", "1.5", "0", "7", "T", "(empty)"],
    ];
    const logText = tsvLog("conn", CONN_FIELDS, CONN_TYPES, rows, { separator: "|", separatorEscape: "\\x7c" });
    await stage(cwd, bin, { "conn.log": logText });
    const out = body(await tool(ZEEK, cwd, { path: await capture(cwd), out_dir: "work/z" }, env(cwd), bin));
    const conn = out.logs.conn;
    assert.equal(conn.total, 2);
    assert.equal(conn.malformed, 0);
    const [a, b] = conn.records;
    assert.equal(a.ts, "1700000000.123456", "the raw time is kept");
    assert.equal(a.ts_utc, "2023-11-14T22:13:20.123456Z");
    assert.equal(a["id.orig_p"], 50000);
    assert.equal(a.duration, null, "a - is unset");
    assert.equal(a.local_orig, false);
    assert.deepEqual(a.tunnel_parents, ["a", "b"]);
    assert.equal(b.ts_utc, "2023-11-14T22:13:20.000001Z");
    assert.deepEqual(b.tunnel_parents, [], "(empty) is an empty set");
    assert.equal(b.duration, 1.5);
    assert.equal(b.local_orig, true);
    assert.equal(b["id.orig_h"], "2001:db8::1");
    assert.deepEqual(conn.types, CONN_TYPES);
  });
  await withCwd(async (cwd, bin) => {
    const fields = ["ts", "uid", "user_agent"];
    const types = ["time", "string", "string"];
    // \\x09 is a tab and \\xc3\\xa9 is e-acute, written as Zeek writes a byte it cannot print
    await stage(cwd, bin, { "http.log": tsvLog("http", fields, types, [["1700000000.5", "C1", "Mozilla\\x09tab-\\xc3\\xa9"]]) });
    const out = body(await tool(ZEEK, cwd, { path: await capture(cwd), out_dir: "work/z" }, env(cwd), bin));
    assert.equal(out.logs.http.records[0].user_agent, "Mozilla\ttab-é");
  });
});

test("a record that does not fit its header is counted with its line, kept whole in malformed-<log>.jsonl, and the run is not ok", async () => {
  await withCwd(async (cwd, bin) => {
    const text = tsvLog("conn", CONN_FIELDS, CONN_TYPES, [
      CONN_ROW,
      CONN_ROW.slice(0, 11), // one column too few
      ["1700000003", "C3", "10.0.0.5", "not-a-port", "203.0.113.7", "443", "tcp", "0.25", "1", "2", "T", "(empty)"],
    ]);
    await stage(cwd, bin, { "conn.log": text });
    const result = await tool(ZEEK, cwd, { path: await capture(cwd), out_dir: "work/z" }, env(cwd), bin);
    assert.equal(result.code, 1);
    const out = JSON.parse(result.stdout);
    assert.equal(out.ok, false);
    assert.equal(out.malformed_records, 2);
    assert.equal(out.logs.conn.total, 1);
    assert.equal(out.malformed[0].line, 10, "the physical line, counting the header");
    assert.match(out.malformed[0].why, /11 columns, and the header names 12 fields/);
    assert.match(out.malformed[1].why, /not a port/);
    assert.equal(out.malformed_files.conn, "malformed-conn.jsonl");
    const kept = (await readFile(join(cwd, "work/z/malformed-conn.jsonl"), "utf8")).trimEnd().split("\n").map((l) => JSON.parse(l));
    assert.equal(kept.length, 2);
    assert.equal(kept[0].raw, CONN_ROW.slice(0, 11).join("\t"));
    assert.equal(kept[0].byte_offset > 0, true);
    assert.equal(((await stat(join(cwd, "work/z/malformed-conn.jsonl"))).mode & 0o777).toString(8), "600");
    // The raw lines are not in the answer.
    assert.equal(result.stdout.includes("not-a-port"), false);
  });
});

test("a log with no header is a counted refusal to decode, not an empty list; JSON logs are read, and a line that is not an object is counted", async () => {
  await withCwd(async (cwd, bin) => {
    await stage(cwd, bin, { "dns.log": "1700000000.1\tC1\tquery\n", "conn.log": [JSON.stringify({ ts: 1700000000.25, uid: "C9", proto: "tcp" }), "{broken", "[1,2]", ""].join("\n") });
    const result = await tool(ZEEK, cwd, { path: await capture(cwd), out_dir: "work/z" }, env(cwd), bin);
    assert.equal(result.code, 1);
    const out = JSON.parse(result.stdout);
    assert.equal(out.logs.dns.total, 0);
    assert.equal(out.logs.dns.malformed, 1);
    assert.match(out.malformed.find((m: Json) => m.log === "dns").why, /before any #fields header/);
    assert.equal(out.logs.conn.format, "json");
    assert.equal(out.logs.conn.total, 1);
    assert.equal(out.logs.conn.records[0].uid, "C9");
    assert.equal(out.logs.conn.records[0].ts_utc, "2023-11-14T22:13:20.25Z");
    assert.equal(out.logs.conn.malformed, 2);
    assert.deepEqual(out.malformed.filter((m: Json) => m.log === "conn").map((m: Json) => m.line), [2, 3]);
  });
});

test("requested logs Zeek did not write are kept apart from logs it wrote with no records; reporter, weird and capture_loss are summarised whatever is asked for", async () => {
  await withCwd(async (cwd, bin) => {
    await stage(cwd, bin, {
      "conn.log": tsvLog("conn", CONN_FIELDS, CONN_TYPES, [CONN_ROW]),
      "dns.log": tsvLog("dns", ["ts", "uid"], ["time", "string"], []),
      "reporter.log": tsvLog("reporter", ["ts", "level", "message", "location"], ["time", "enum", "string", "string"], [
        ["1700000000.1", "Reporter::WARNING", "Analyzer confirmed too late", "-"],
        ["1700000000.2", "Reporter::ERROR", "no such script", "-"],
        ["1700000000.3", "Reporter::WARNING", "again", "-"],
      ]),
      "weird.log": tsvLog("weird", ["ts", "name"], ["time", "string"], [["1700000000.1", "bad_HTTP_request"], ["1700000000.2", "bad_HTTP_request"], ["1700000000.3", "possible_split_routing"]]),
      "capture_loss.log": tsvLog("capture_loss", ["ts", "gaps", "acks", "percent_lost"], ["time", "count", "count", "double"], [["1700000000.1", "5", "100", "5.0"], ["1700000001.1", "1", "100", "1.0"]]),
    });
    const out = body(await tool(ZEEK, cwd, { path: await capture(cwd), out_dir: "work/z", logs: ["conn", "dns", "ssl"] }, env(cwd), bin));
    assert.deepEqual(out.logs_requested_not_written, ["ssl"]);
    assert.deepEqual(out.logs_empty, ["dns"]);
    assert.deepEqual(Object.keys(out.logs).sort(), ["conn", "dns"]);
    assert.equal(out.logs.dns.total, 0);
    assert.deepEqual(out.engine_diagnostics.reporter.levels, { "Reporter::WARNING": 2, "Reporter::ERROR": 1 });
    assert.equal(out.engine_diagnostics.reporter.records, 3);
    assert.deepEqual(out.engine_diagnostics.weird.by_name, { bad_HTTP_request: 2, possible_split_routing: 1 });
    assert.equal(out.engine_diagnostics.capture_loss.max_percent_lost, 5);
    assert.equal(out.engine_diagnostics.capture_loss.gaps, 6);
    assert.equal(out.engine_diagnostics.capture_loss_note, null);
    // Without a capture_loss.log, its absence is not a finding.
  });
  await withCwd(async (cwd, bin) => {
    await stage(cwd, bin, { "conn.log": tsvLog("conn", CONN_FIELDS, CONN_TYPES, [CONN_ROW]) });
    const out = body(await tool(ZEEK, cwd, { path: await capture(cwd), out_dir: "work/z" }, env(cwd), bin));
    assert.match(out.engine_diagnostics.capture_loss_note, /says nothing about loss/);
  });
});

test("inline records withhold secret-named fields, URL user-info and query values, and an FTP PASS argument; Zeek's own logs stay whole and the directory is private", async () => {
  await withCwd(async (cwd, bin) => {
    const http = tsvLog("http", ["ts", "uid", "method", "uri", "referrer", "username", "password", "cookie"], ["time", "string", "string", "string", "string", "string", "string", "string"], [
      ["1700000000.1", "C1", "GET", "/login?session=SuperSecretSession987&n=2", "http://alice:HunterTwo22@portal.example.test/home", "alice", "S3cretPassw0rd", "sid=abc123def456"],
    ]);
    const ftp = tsvLog("ftp", ["ts", "uid", "user", "password", "command", "arg"], ["time", "string", "string", "string", "string", "string"], [
      ["1700000000.2", "C2", "bob", "-", "USER", "bob"],
      ["1700000000.3", "C2", "bob", "-", "PASS", "FtpSecret!99"],
    ]);
    await stage(cwd, bin, { "http.log": http, "ftp.log": ftp });
    const result = await asJob(ZEEK, cwd, { path: await capture(cwd), out_dir: "out/z" }, bin, env(cwd));
    const out = body(result);
    const recs = out.logs.http.records;
    assert.equal(recs[0].method, "GET");
    assert.equal(recs[0].username, "alice", "a user name is evidence, not a secret value");
    assert.match(recs[0].password, /^<withheld \d+ characters>$/);
    assert.match(recs[0].cookie, /^<withheld \d+ characters>$/);
    assert.match(recs[0].uri, /^\/login\?session=<withheld \d+ characters>&n=<withheld 1 characters>$/);
    assert.match(recs[0].referrer, /^http:\/\/<userinfo withheld \d+ characters>@portal\.example\.test\/home$/);
    assert.equal(out.logs.ftp.records[0].arg, "bob");
    assert.match(out.logs.ftp.records[1].arg, /^<withheld \d+ characters>$/);
    for (const secret of ["SuperSecretSession987", "HunterTwo22", "S3cretPassw0rd", "sid=abc123def456", "FtpSecret!99"]) {
      assert.equal(result.stdout.includes(secret), false, `${secret} reached the answer`);
    }
    // The evidence itself is whole, in a private place.
    assert.match(await readFile(join(cwd, "out/z/http.log"), "utf8"), /S3cretPassw0rd/);
    assert.equal(((await stat(join(cwd, "out/z"))).mode & 0o777).toString(8), "700");
    assert.equal(((await stat(join(cwd, "out/z/http.log"))).mode & 0o777).toString(8), "600");
    assert.equal(((await stat(join(cwd, "out/z/zeek.stderr"))).mode & 0o777).toString(8), "600");
    assert.equal(out.out_dir_contains_secret_values, true);
    assert.match(out.out_dir_note, /secret_output: true/);
    assert.ok(out.withheld.inline_records.fields >= 3);
  });
});

test("a run that outlives its time is killed with what it started, and says what it had written", async () => {
  await withCwd(async (cwd, bin) => {
    const dir = await stage(cwd, bin, { "conn.log": tsvLog("conn", CONN_FIELDS, CONN_TYPES, [CONN_ROW]) }, { sleep: true });
    const started = Date.now();
    const err = refused(await tool(ZEEK, cwd, { path: await capture(cwd), out_dir: "work/z", timeout_seconds: 10 }, env(cwd), bin));
    assert.ok(Date.now() - started < 40_000);
    assert.match(err.error, /did not finish in time/);
    assert.deepEqual(err.logs_written_so_far, []);
    const pid = Number((await readFile(join(dir, "child.pid"), "utf8")).trim());
    await new Promise((r) => setTimeout(r, 300));
    assert.throws(() => process.kill(pid, 0), /ESRCH/, "what Zeek started is gone");
  });
});

test("a Zeek that exits with an error keeps its logs and its whole diagnostic, and no logs at all is an error naming where its output is", async () => {
  await withCwd(async (cwd, bin) => {
    await stage(cwd, bin, { "conn.log": tsvLog("conn", CONN_FIELDS, CONN_TYPES, [CONN_ROW]) }, { exit: 9, stderr: "error: could not find script policy/nope\n" });
    const result = await tool(ZEEK, cwd, { path: await capture(cwd), out_dir: "work/z", policies: ["policy/nope"] }, env(cwd), bin);
    assert.equal(result.code, 1);
    const out = JSON.parse(result.stdout);
    assert.equal(out.ok, false);
    assert.equal(out.exit_code, 9);
    assert.match(await readFile(join(cwd, out.stderr), "utf8"), /could not find script policy\/nope/);
    assert.equal(out.logs.conn.total, 1);
  });
  await withCwd(async (cwd, bin) => {
    await stage(cwd, bin, {}, { exit: 2 });
    const err = refused(await tool(ZEEK, cwd, { path: await capture(cwd), out_dir: "work/z" }, env(cwd), bin));
    assert.match(err.error, /wrote no logs/);
    assert.equal(err.exit_code, 2);
    assert.ok(err.stderr);
  });
});

test("in a job out_dir must be under $OUT, and a second run into the same directory is refused", async () => {
  await withCwd(async (cwd, bin) => {
    await stage(cwd, bin, { "conn.log": tsvLog("conn", CONN_FIELDS, CONN_TYPES, [CONN_ROW]) });
    const outside = refused(await asJob(ZEEK, cwd, { path: await capture(cwd), out_dir: "work/elsewhere" }, bin, env(cwd)));
    assert.match(outside.error, /\$OUT/);
    body(await asJob(ZEEK, cwd, { path: await capture(cwd), out_dir: "out/z" }, bin, env(cwd)));
    const again = refused(await asJob(ZEEK, cwd, { path: await capture(cwd), out_dir: "out/z" }, bin, env(cwd)));
    assert.match(again.error, /already holds files/);
    assert.deepEqual((await filesUnder(join(cwd, "out/z"))).filter((f) => f.endsWith(".tmp")), []);
  });
});

test("free text in any field is scrubbed inline: a URL in a notice's msg, a token in weird's addl, a JWT in a file-name list, a user agent; identifiers, hashes and times stay", async () => {
  await withCwd(async (cwd, bin) => {
    const JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r";
    const TOK = "Zk9mQ2xW7vB3nL8pR4tY6wD1sFgHjK";
    const notice = tsvLog("notice", ["ts", "uid", "note", "msg", "sub"], ["time", "string", "string", "string", "string"], [
      ["1700000000.1", "CYWJAH2BG8ssSd3Mpk", "HTTP::Basic_Auth", `request to http://alice:Sup3rS3cret@10.0.0.1/admin?token=${TOK}`, "-"],
    ]);
    const weird = tsvLog("weird", ["ts", "name", "addl"], ["time", "string", "string"], [["1700000000.2", "bad_request", `/x?session=${TOK}`]]);
    const http = tsvLog("http", ["ts", "uid", "user_agent", "orig_filenames", "resp_filenames"], ["time", "string", "string", "vector[string]", "vector[string]"], [
      ["1700000000.3", "C1", `agent/1.0 key=${TOK}`, `${JWT},report.pdf`, "-"],
    ]);
    const files = tsvLog("files", [...FILES_FIELDS, "sha256"], [...FILES_TYPES, "string"], [["1700000001.5", "FRnTpZ3Fp5vYbpNQP", "HTTP", "5000", "5000", "report.pdf", "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b"]]);
    await stage(cwd, bin, { "notice.log": notice, "weird.log": weird, "http.log": http, "files.log": files });
    const result = await asJob(ZEEK, cwd, { path: await capture(cwd), out_dir: "out/z" }, bin, env(cwd));
    const out = body(result);
    for (const secret of ["Sup3rS3cret", TOK, JWT, "dBjftJeZ4CVPmB92K27uhbUJU1p1r"]) assert.equal(result.stdout.includes(secret), false, `${secret.slice(0, 12)} reached the answer`);
    assert.match(out.logs.notice.records[0].msg, /^request to http:\/\/<userinfo withheld \d+ characters>@10\.0\.0\.1\/admin\?token=<withheld \d+ characters>$/);
    assert.equal(out.logs.http.records[0].orig_filenames[1], "report.pdf", "an ordinary name in the same list is left alone");
    assert.match(out.logs.http.records[0].orig_filenames[0], /^<token-shaped text withheld \d+ characters>$/);
    assert.match(out.logs.http.records[0].user_agent, /^agent\/1\.0 key=<token-shaped text withheld 30 characters>$/);
    // Identifiers, hashes and times are not touched.
    assert.equal(out.logs.http.records[0].uid, "C1");
    assert.equal(out.logs.files.records[0].sha256, "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b");
    assert.equal(out.logs.http.records[0].ts_utc, "2023-11-14T22:13:20.3Z");
    // The counters of the inline copy and of the shared block are not one dictionary overwriting the other.
    assert.ok(out.withheld.inline_records.text >= 2 && out.withheld.inline_records.urls >= 2, JSON.stringify(out.withheld));
    assert.ok(out.withheld.shared_block.text >= 2 && out.withheld.shared_block.urls >= 2, "the shared block's counters are kept apart from the inline ones");
    // Zeek's own log is whole.
    assert.match(await readFile(join(cwd, "out/z/notice.log"), "utf8"), /Sup3rS3cret/);
  });
});

test("the harness ends a tool by killing its process group, and that ends Zeek and what Zeek started; SIGINT and SIGHUP do the same", async () => {
  for (const how of ["group", "SIGINT", "SIGHUP"] as const) {
    await withCwd(async (cwd, bin) => {
      const dir = await stage(cwd, bin, { "conn.log": tsvLog("conn", CONN_FIELDS, CONN_TYPES, [CONN_ROW]) }, { sleep: true });
      const run = startDetached(ZEEK, cwd, { path: await capture(cwd), out_dir: "work/z" }, env(cwd), bin);
      let engine = 0, child = 0;
      try {
        engine = await pidFile(join(dir, "engine.pid"));
        child = await pidFile(join(dir, "child.pid"));
        if (how === "group") run.killGroup();
        else run.signal(how);
        await run.closed;
        assert.equal(await gone(engine), true, `${how}: Zeek survived`);
        assert.equal(await gone(child), true, `${how}: what Zeek started survived`);
      } finally {
        for (const pid of [engine, child]) try { process.kill(pid, "SIGKILL"); } catch { /* gone */ }
      }
    });
  }
});

test("timeout_seconds is held under the manifest's limit", async () => {
  await withCwd(async (cwd, bin) => {
    await stage(cwd, bin, { "conn.log": tsvLog("conn", CONN_FIELDS, CONN_TYPES, [CONN_ROW]) });
    for (const bad of [1101, 5000, 9]) {
      const err = refused(await tool(ZEEK, cwd, { path: await capture(cwd), out_dir: "work/z", timeout_seconds: bad }, env(cwd), bin));
      assert.match(err.error, /timeout_seconds must be an integer from 10 to 1100/, String(bad));
    }
    assert.equal(await exists(join(cwd, "work/z")), false);
  });
});

test("the reader is strict about types: a time, a count or an interval that is not one is malformed, NaN and infinity stay text so the answer is valid JSON, and a time before 1970 is the instant it names", async () => {
  await withCwd(async (cwd, bin) => {
    const types = ["time", "string", "count", "interval", "int"];
    const fields = ["ts", "uid", "n", "dur", "delta"];
    const good = ["1700000000.123456", "C1", "7", "1.5", "-3"];
    const rows = [
      good,
      ["notatime", "C2", "7", "1.5", "-3"],
      ["1700000000.1", "C3", "1_000", "1.5", "-3"],
      ["1700000000.1", "C4", " 7 ", "1.5", "-3"],
      ["1700000000.1", "C5", "+7", "1.5", "-3"],
      ["1700000000.1", "C6", "\u0667", "1.5", "-3"],
      ["1700000000.1", "C7", "7", "1.5.2", "-3"],
      ["1700000000.1", "C8", "7", "1.5", "+3"],
      ["1700000000.1", "C9", "7", "nan", "-3"],
      ["1700000000.1", "C10", "7", "inf", "-3"],
      ["-1.500000", "C11", "7", "1.5", "-3"],
      ["-0.25", "C12", "7", "1.5", "-3"],
    ];
    await stage(cwd, bin, { "x.log": tsvLog("x", fields, types, rows) });
    const result = await tool(ZEEK, cwd, { path: await capture(cwd), out_dir: "work/z" }, env(cwd), bin);
    assert.equal(result.code, 1);
    const out = JSON.parse(result.stdout); // strict: NaN or Infinity would not parse
    assert.equal(out.malformed_records, 7, JSON.stringify(out.malformed.map((m: Json) => m.why)));
    const recs = Object.fromEntries(out.logs.x.records.map((r: Json) => [r.uid, r]));
    assert.equal(recs.C9.dur, "nan");
    assert.equal(recs.C10.dur, "inf");
    assert.equal(recs.C11.ts_utc, "1969-12-31T23:59:58.500000Z");
    assert.equal(recs.C12.ts_utc, "1969-12-31T23:59:59.75Z");
    assert.equal(recs.C1.n, 7);
  });
});

test("a header that was bad does not make the rows after the next good header malformed; a JSON files.log names its hash keys; a failing --version is a problem", async () => {
  await withCwd(async (cwd, bin) => {
    const bad = ["#separator \\x09", "#fields\tts\tuid", "#types\ttime", "1700000000.1\tC1", "#fields\tts\tuid", "#types\ttime\tstring", "1700000001.1\tC2", "1700000002.1\tC3", ""].join("\n");
    const json = [JSON.stringify({ ts: 1700000000.5, fuid: "F1", md5: "d41d8cd98f00b204e9800998ecf8427e", total_bytes: 500, seen_bytes: 500 }), ""].join("\n");
    await stage(cwd, bin, { "x.log": bad, "files.log": json });
    const result = await tool(ZEEK, cwd, { path: await capture(cwd), out_dir: "work/z" }, env(cwd), bin);
    const out = JSON.parse(result.stdout);
    assert.equal(out.logs.x.total, 2, "the two rows under the good header were read");
    assert.equal(out.malformed_records, 1, "only the row under the bad header is malformed");
    assert.deepEqual(out.hash_fields, ["md5"]);
    assert.equal(out.hashes_produced, true);
    assert.match(out.hash_note, /only hashes_produced/);
  });
  await withCwd(async (cwd, bin) => {
    await stage(cwd, bin, { "conn.log": tsvLog("conn", CONN_FIELDS, CONN_TYPES, [CONN_ROW]) }, { versionFail: true });
    const result = await tool(ZEEK, cwd, { path: await capture(cwd), out_dir: "work/z" }, env(cwd), bin);
    assert.equal(result.code, 1);
    const out = JSON.parse(result.stdout);
    assert.equal(out.zeek_version, null);
    assert.equal(out.ok, false);
    assert.match(JSON.stringify(out.problems), /--version/);
  });
});
