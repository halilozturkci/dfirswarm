/**
 * network-forensics: network_log_summary normalises web, Squid and firewall logs into one table.
 *
 * The log lines are written from the formats' own definitions (the common and combined log format of Apache and
 * nginx, Squid's native access.log field order, netfilter-style upper-case KEY=VALUE records with a syslog or an
 * ISO 8601 prefix), never from this tool's output. What is held here: a timestamp column that says what it is
 * (raw text, a UTC value only where the line gives enough to derive one, and where the zone came from), byte
 * offsets that find each line in the evidence, decoding substitutions and line endings counted, secrets withheld
 * from the table and the answer, and every bound (line length, gzip expansion, distinct values) reported.
 */
import assert from "node:assert/strict";
import { gzipSync } from "node:zlib";
import { readFile, stat } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { LOGS, asJob, body, everythingUnder, exists, put, refused, tool, withCwd } from "./pack-network-harness.ts";
import type { Json } from "./pack-network-harness.ts";

const WEB = '192.0.2.1 - bob [14/Nov/2023:23:13:20 +0100] "GET /a HTTP/1.1" 200 12 "-" "ua/1.0"';
const SQUID = "1700000000.123 30 192.0.2.2 TCP_MISS/200 321 GET http://example.test/a alice DIRECT/203.0.113.80 text/html";
const FW_SYSLOG = "Nov 14 fw DROP IN=eth0 OUT=eth1 SRC=192.0.2.3 DST=203.0.113.8 NAT_SRC=198.51.100.7 NAT_DST=10.0.0.8 LEN=60 PROTO=TCP SPT=51515 DPT=443 SYN ACK";
const FW_ISO = "2023-11-14T23:13:20.123456+01:00 fw kernel: ACCEPT IN=eth0 OUT= SRC=192.0.2.4 DST=203.0.113.9 LEN=40 PROTO=UDP SPT=5353 DPT=53";

async function table(cwd: string, dir: string, name = "normalized.tsv"): Promise<Json[]> {
  const lines = (await readFile(join(cwd, dir, name), "utf8")).trimEnd().split("\n");
  const head = lines[0].split("\t");
  return lines.slice(1).map((l) => Object.fromEntries(l.split("\t").map((v, i) => [head[i], v])));
}

test("each format keeps its time as written, and a UTC time only where the line gives enough to derive one, with where the zone came from", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/l.log", [WEB, SQUID, FW_SYSLOG, FW_ISO].join("\n") + "\n");
    const out = body(await tool(LOGS, cwd, { path: "inputs/l.log", out_dir: "work/o" }, {}));
    assert.equal(out.lines, 4);
    assert.equal(out.parsed, 4);
    const rows = await table(cwd, "work/o");
    const by = Object.fromEntries(rows.map((r) => [r.format + (r.timestamp_raw.startsWith("2023") ? "-iso" : ""), r]));
    assert.equal(by.web.timestamp_raw, "14/Nov/2023:23:13:20 +0100");
    assert.equal(by.web.timestamp_utc, "2023-11-14T22:13:20Z", "the offset in the line was applied");
    assert.match(by.web.timezone_source, /offset written in the line/);
    assert.equal(by.squid.timestamp_raw, "1700000000.123");
    assert.equal(by.squid.timestamp_utc, "2023-11-14T22:13:20.123Z");
    assert.match(by.squid.timezone_source, /epoch seconds/);
    assert.equal(by.firewall.timestamp_raw, "Nov 14 fw DROP");
    assert.equal(by.firewall.timestamp_utc, "", "a syslog stamp has no year and no zone: nothing is derived, nothing is assumed UTC");
    assert.match(by.firewall.timezone_source, /no year and no zone/);
    assert.equal(by["firewall-iso"].timestamp_utc, "2023-11-14T22:13:20.123456Z");
    assert.match(by["firewall-iso"].timezone_source, /zone written in the line/);
    for (const r of rows) assert.ok(r.timestamp_raw !== "", "every row has its raw time");
    assert.equal(out.timestamps.derived, 3);
    assert.equal(out.timestamps.not_derived, 1);
    // The old mixed column and the raw line column are gone.
    assert.equal("timestamp" in rows[0], false);
    assert.equal("raw" in rows[0], false);
    // The grammars' other fields survive.
    assert.equal(by.squid.user, "alice");
    assert.equal(by.squid.hierarchy, "DIRECT/203.0.113.80");
    assert.equal(by.firewall.nat_src, "198.51.100.7");
    assert.equal(by.firewall.tcp_flags, "SYN,ACK");
    assert.equal(by.web.user_agent, "ua/1.0");
  });
});

test("byte offsets and lengths find each line in the evidence, with CRLF, a line with no line end and invalid UTF-8 counted", async () => {
  await withCwd(async (cwd) => {
    const bad = Buffer.concat([Buffer.from('192.0.2.9 - - [14/Nov/2023:22:13:20 +0000] "GET /caf'), Buffer.from([0xe9]), Buffer.from(' HTTP/1.1" 200 5 "-" "ua"')]);
    const source = Buffer.concat([Buffer.from(WEB + "\r\n"), Buffer.from("\n"), bad, Buffer.from("\n"), Buffer.from(SQUID)]);
    await put(cwd, "inputs/l.log", source);
    const out = body(await tool(LOGS, cwd, { path: "inputs/l.log", out_dir: "work/o" }, {}));
    assert.equal(out.lines, 4);
    assert.equal(out.blank, 1);
    assert.equal(out.crlf_lines, 1);
    assert.equal(out.decoding_substituted, 1);
    assert.equal(out.last_line_has_no_line_end, true);
    const rows = await table(cwd, "work/o");
    const blank = (await table(cwd, "work/o", "unparsed.tsv"))[0];
    assert.equal(blank.parse_status, "blank");
    for (const r of [...rows, blank]) {
      const slice = source.subarray(Number(r.byte_offset), Number(r.byte_offset) + Number(r.byte_length));
      assert.ok(source.subarray(0, Number(r.byte_offset)).toString("latin1").split("\n").length - 1 === Number(r.line) - 1, `line ${r.line} starts after ${Number(r.line) - 1} line ends`);
      assert.ok(slice.length === Number(r.byte_length));
    }
    assert.equal(source.subarray(Number(rows[0].byte_offset), Number(rows[0].byte_offset) + Number(rows[0].byte_length)).toString().startsWith("192.0.2.1"), true);
    const substituted = rows.find((r) => r.decoding === "substituted");
    assert.ok(substituted);
    assert.equal(Number(substituted.byte_offset), Buffer.byteLength(WEB + "\r\n") + 1, "the offset counts bytes, not characters");
    assert.equal(rows.find((r) => r.format === "squid").decoding, "exact");
  });
});

const TOKEN = "Zk9mQ2xW7vB3nL8pR4tY6wD1sFgHjK";
const SECRETS = ["SuperSecretToken987", "PassWord1234", TOKEN, "hunter2hunter2"];

test("a request target loses its user-info, token-shaped path text and query values; an unparsed line's text is not in the table; nothing secret is in the answer", async () => {
  await withCwd(async (cwd) => {
    const lines = [
      `192.0.2.1 - - [14/Nov/2023:22:13:20 +0000] "GET /get/${TOKEN}?token=SuperSecretToken987&n=2 HTTP/1.1" 200 12 "-" "ua"`,
      `1700000000.1 30 192.0.2.2 TCP_MISS/200 321 GET http://alice:PassWord1234@example.test/a?pw=hunter2hunter2 alice DIRECT/203.0.113.80 text/html`,
      "login attempt password=hunter2hunter2 from somewhere",
    ];
    await put(cwd, "inputs/l.log", lines.join("\n") + "\n");
    const result = await tool(LOGS, cwd, { path: "inputs/l.log", out_dir: "work/o" }, {});
    const out = body(result);
    const everything = await everythingUnder(cwd, result.stdout, ["work/o"]);
    for (const secret of SECRETS) assert.equal(everything.includes(secret), false, `${secret} reached the answer or a table`);
    const rows = await table(cwd, "work/o");
    assert.match(rows[0].target, /^\/get\/<token-shaped text withheld 30 characters>\?token=<withheld 19 characters>&n=<withheld 1 characters>$/);
    assert.match(rows[1].target, /^http:\/\/<userinfo withheld 18 characters>@example\.test\/a\?pw=<withheld 14 characters>$/);
    assert.equal(rows[1].user, "alice", "a user name is evidence");
    const bad = await table(cwd, "work/o", "unparsed.tsv");
    assert.deepEqual(Object.keys(bad[0]), ["line", "byte_offset", "byte_length", "parse_status", "reason", "decoding"]);
    assert.equal(bad[0].line, "3");
    assert.equal(out.secret_values.written, 0);
    assert.equal(out.out_dir_contains_secret_values, true);
    assert.equal(((await stat(join(cwd, "work/o"))).mode & 0o777).toString(8), "700");
    assert.equal(((await stat(join(cwd, "work/o/normalized.tsv"))).mode & 0o777).toString(8), "600");
  });
});

test("write_values puts the originals in one 0600 job file, is refused outside a job, and a second run in the same job is refused and leaves the first alone", async () => {
  await withCwd(async (cwd) => {
    const secretLine = `192.0.2.1 - - [14/Nov/2023:22:13:20 +0000] "GET /get?token=SuperSecretToken987 HTTP/1.1" 200 12 "-" "ua"`;
    await put(cwd, "inputs/l.log", [secretLine, "free text password=hunter2hunter2", WEB].join("\n") + "\n");
    const args = { path: "inputs/l.log", out_dir: "work/plain", write_values: true };
    const outside = refused(await tool(LOGS, cwd, args, {}));
    assert.match(outside.error, /outside a job/);
    assert.equal(await exists(join(cwd, "work/plain")), false);
    const first = body(await asJob(LOGS, cwd, { ...args, out_dir: "out/one" }));
    assert.equal(first.secret_values.written, 2);
    const file = join(cwd, "out", "network-log-values.jsonl");
    assert.equal(((await stat(file)).mode & 0o777).toString(8), "600");
    const rows = (await readFile(file, "utf8")).trimEnd().split("\n").map((l) => JSON.parse(l));
    assert.deepEqual(rows.map((r: Json) => [r.status, r.line]), [["parsed", 1], ["unparsed", 2]]);
    assert.equal(rows[0].target, "/get?token=SuperSecretToken987");
    assert.equal(rows[1].value, "free text password=hunter2hunter2");
    assert.match(rows[0].finding_id, /^L\d{6}$/);
    const before = await readFile(file, "utf8");
    const second = refused(await asJob(LOGS, cwd, { ...args, out_dir: "out/two" }));
    assert.match(second.error, /already exists/);
    assert.equal(await readFile(file, "utf8"), before);
    // Nothing withheld, nothing written: an empty 0600 file, and the answer says written: 0.
    await put(cwd, "inputs/clean.log", WEB + "\n");
    const empty = body(await asJob(LOGS, cwd, { path: "inputs/clean.log", out_dir: "out3/x", write_values: true }, undefined, {}, "out3"));
    assert.equal(empty.secret_values.written, 0);
    assert.equal((await stat(join(cwd, "out3", "network-log-values.jsonl"))).size, 0);
  });
});

test("a line over the limit is located and not read; a gzip that expands past its cap or is cut off is a structured error that keeps the rows read before it", async () => {
  await withCwd(async (cwd) => {
    const long = "x".repeat(10_000);
    await put(cwd, "inputs/l.log", [WEB, long, SQUID].join("\n") + "\n");
    const out = body(await tool(LOGS, cwd, { path: "inputs/l.log", out_dir: "work/o", max_line_bytes: 4096 }, {}));
    assert.equal(out.lines, 3);
    assert.equal(out.parsed, 2);
    assert.equal(out.lines_over_limit, 1);
    const bad = await table(cwd, "work/o", "unparsed.tsv");
    assert.equal(bad[0].parse_status, "line_over_limit");
    assert.equal(Number(bad[0].byte_length), 10_001);
    assert.equal(Number(bad[0].byte_offset), Buffer.byteLength(WEB) + 1);
    // Offsets of the line after it are still right.
    assert.equal(Number((await table(cwd, "work/o"))[1].byte_offset), Buffer.byteLength(WEB) + 1 + 10_001);

    const many = Array.from({ length: 6000 }, (_, i) => WEB.replace("192.0.2.1", `192.0.2.${i % 250}`)).join("\n") + "\n";
    await put(cwd, "inputs/big.log.gz", gzipSync(Buffer.from(many)));
    const capped = await tool(LOGS, cwd, { path: "inputs/big.log.gz", out_dir: "work/capped", max_expanded_bytes: 1 << 20 }, {});
    assert.equal(Buffer.byteLength(many) > 400_000, true);
    // The cap is at least a mebibyte, and this log is smaller: it completes. Then a log that is larger is cut.
    assert.equal(JSON.parse(capped.stdout).complete, true);
    const huge = Buffer.from(many.repeat(3));
    await put(cwd, "inputs/huge.log.gz", gzipSync(huge));
    const cut = await tool(LOGS, cwd, { path: "inputs/huge.log.gz", out_dir: "work/cut", max_expanded_bytes: 1 << 20 }, {});
    assert.equal(cut.code, 1);
    const answer = JSON.parse(cut.stdout);
    assert.equal(answer.complete, false);
    assert.equal(answer.ok, false);
    assert.equal(answer.read_error.error, "expansion_limit");
    assert.ok(answer.read_error.stream_offset > 0 && answer.read_error.stream_offset <= (1 << 20) + 200);
    assert.equal((await table(cwd, "work/cut")).length, answer.parsed, "the rows read before the cap are in the table");
    assert.match(answer.note, /READ STOPPED EARLY/);

    const whole = gzipSync(Buffer.from(many));
    await put(cwd, "inputs/cut.log.gz", whole.subarray(0, Math.floor(whole.length * 0.6)));
    const corrupt = await tool(LOGS, cwd, { path: "inputs/cut.log.gz", out_dir: "work/corrupt" }, {});
    assert.equal(corrupt.code, 1);
    assert.doesNotMatch(corrupt.stderr, /Traceback/);
    const broken = JSON.parse(corrupt.stdout);
    assert.equal(broken.complete, false);
    assert.equal(broken.read_error.error, "EOFError");
    assert.ok(broken.read_error.last_complete_line >= 1, "the position it got to is named");
    assert.ok(broken.parsed >= 1 && broken.parsed < 6000);
    assert.equal((await table(cwd, "work/corrupt")).length, broken.parsed);
    // A file that starts like a gzip and is not one: an error naming where it stopped, not a traceback.
    await put(cwd, "inputs/garbage.gz", Buffer.concat([Buffer.from([0x1f, 0x8b]), Buffer.from("this is not a deflate stream at all")]));
    const garbage = await tool(LOGS, cwd, { path: "inputs/garbage.gz", out_dir: "work/garbage" }, {});
    assert.equal(garbage.code, 1);
    assert.doesNotMatch(garbage.stderr, /Traceback/);
    const g = JSON.parse(garbage.stdout);
    assert.equal(g.complete, false);
    assert.equal(g.read_error.last_complete_line, 0);
    assert.equal(g.lines, 0);
  });
});

test("a gzip log is read as its decompressed stream, and its offsets say so", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/l.log.gz", gzipSync(Buffer.from([WEB, SQUID].join("\n") + "\n")));
    const out = body(await tool(LOGS, cwd, { path: "inputs/l.log.gz", out_dir: "work/o" }, {}));
    assert.equal(out.compression, "gzip");
    assert.equal(out.offsets_are_in, "the decompressed stream");
    const rows = await table(cwd, "work/o");
    assert.equal(Number(rows[1].byte_offset), Buffer.byteLength(WEB) + 1);
  });
});

test("aggregates hold at most max_distinct_values per category and count what went past it", async () => {
  await withCwd(async (cwd) => {
    const lines = Array.from({ length: 6 }, (_, i) => WEB.replace("192.0.2.1", `192.0.2.${i + 1}`));
    await put(cwd, "inputs/l.log", lines.join("\n") + "\n");
    const out = body(await tool(LOGS, cwd, { path: "inputs/l.log", out_dir: "work/o", max_distinct_values: 3 }, {}));
    assert.deepEqual(out.distinct_cap_reached, { src: 3 });
    assert.equal(out.aggregate.src.length, 3);
    assert.equal(out.aggregate.status[0].count, 6, "a category under its cap is whole");
    assert.equal((await table(cwd, "work/o")).length, 6, "the table holds every line whatever the cap");
  });
});

test("in a job out_dir must be under $OUT, a second run into the same directory is refused, and bad parameters are JSON errors", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/l.log", WEB + "\n");
    const outside = refused(await asJob(LOGS, cwd, { path: "inputs/l.log", out_dir: "work/elsewhere" }));
    assert.match(outside.error, /\$OUT/);
    body(await asJob(LOGS, cwd, { path: "inputs/l.log", out_dir: "out/o" }));
    assert.match(refused(await asJob(LOGS, cwd, { path: "inputs/l.log", out_dir: "out/o" })).error, /already holds files/);
    for (const bad of [{ max_line_bytes: 10 }, { max_expanded_bytes: 5 }, { max_distinct_values: 0 }, { write_values: "yes" }, { format: "iis" }]) {
      const err = refused(await tool(LOGS, cwd, { path: "inputs/l.log", out_dir: "work/bad", ...bad }, {}));
      assert.ok(err.error, JSON.stringify(bad));
    }
    const noargs = await tool(LOGS, cwd, [] as unknown as Json, {});
    assert.notEqual(noargs.code, 0);
    assert.doesNotMatch(noargs.stderr, /Traceback/);
  });
});

test("the combined-format referer is a column, redacted like the target, with the original in the values file", async () => {
  await withCwd(async (cwd) => {
    const TOK = "Zk9mQ2xW7vB3nL8pR4tY6wD1sFgHjK";
    const line = (ref: string): string => `192.0.2.1 - - [14/Nov/2023:22:13:20 +0000] "GET /a HTTP/1.1" 200 12 "${ref}" "ua"`;
    await put(cwd, "inputs/l.log", [line(`http://alice:pw1234@portal.example.test/home/${TOK}?sid=hunter2hunter2`), line("-"), line("https://example.test/plain")].join("\n") + "\n");
    const result = await asJob(LOGS, cwd, { path: "inputs/l.log", out_dir: "out/o", write_values: true });
    const out = body(result);
    const rows = await table(cwd, "out/o");
    assert.match(rows[0].referer, /^http:\/\/<userinfo withheld 12 characters>@portal\.example\.test\/home\/<token-shaped text withheld 30 characters>\?sid=<withheld 14 characters>$/);
    assert.equal(rows[1].referer, "", "a referer of - is no referer");
    assert.equal(rows[2].referer, "https://example.test/plain");
    const everything = await everythingUnder(cwd, result.stdout, ["out"], ["out/network-log-values.jsonl"]);
    for (const secret of ["pw1234", TOK, "hunter2hunter2"]) assert.equal(everything.includes(secret), false, secret);
    const values = (await readFile(join(cwd, "out/network-log-values.jsonl"), "utf8")).trimEnd().split("\n").map((l) => JSON.parse(l));
    assert.equal(values.length, 1);
    assert.match(values[0].referer, /alice:pw1234@portal/);
    assert.equal(out.secret_values.written, 1);
  });
});

test("a time with no offset, an RFC 5424 time and a firewall line with no prefix each say what they are", async () => {
  await withCwd(async (cwd) => {
    const lines = [
      '192.0.2.1 - - [14/Nov/2023:22:13:20] "GET /a HTTP/1.1" 200 12 "-" "ua"',
      "<4>1 2023-11-14T23:13:20.123Z fw kernel - - - IN=eth0 SRC=192.0.2.4 DST=203.0.113.9 LEN=40 PROTO=UDP SPT=5353 DPT=53",
      "SRC=192.0.2.5 DST=203.0.113.9 LEN=40 PROTO=UDP SPT=5353 DPT=53",
      "<4>Nov 14 22:13:20 fw kernel: IN=eth0 SRC=192.0.2.6 DST=203.0.113.9 PROTO=TCP SPT=1 DPT=2",
    ];
    await put(cwd, "inputs/l.log", lines.join("\n") + "\n");
    body(await tool(LOGS, cwd, { path: "inputs/l.log", out_dir: "work/o" }, {}));
    const rows = await table(cwd, "work/o");
    assert.equal(rows[0].timestamp_utc, "");
    assert.equal(rows[0].timezone_source, "no zone offset is written in the line");
    assert.equal(rows[1].timestamp_utc, "2023-11-14T23:13:20.123Z");
    assert.match(rows[1].timezone_source, /zone written in the line/);
    assert.equal(rows[2].timezone_source, "no timestamp in the line");
    assert.equal(rows[2].timestamp_raw, "");
    assert.equal(rows[3].timestamp_utc, "");
    assert.match(rows[3].timezone_source, /no year and no zone/);
  });
});

test("a leading byte order mark is not part of the first field, and an aggregate key is cut at a limit and counted", async () => {
  await withCwd(async (cwd) => {
    const longMethod = "M".repeat(2000);
    const lines = [WEB, `192.0.2.7 - - [14/Nov/2023:22:13:20 +0000] "${longMethod} /x HTTP/1.1" 200 5 "-" "ua"`];
    await put(cwd, "inputs/l.log", Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(lines.join("\n") + "\n")]));
    const out = body(await tool(LOGS, cwd, { path: "inputs/l.log", out_dir: "work/o" }, {}));
    assert.equal(out.bom_stripped, 1);
    const rows = await table(cwd, "work/o");
    assert.equal(rows[0].src, "192.0.2.1");
    assert.equal(rows[0].byte_offset, "0");
    assert.equal(Number(rows[1].byte_offset), 3 + Buffer.byteLength(WEB) + 1, "offsets still count the mark");
    assert.equal(out.aggregate_keys_cut, 1);
    assert.ok(out.aggregate.method.every((m: Json) => m.value.length < 600));
    assert.equal(rows[1].method.length, 2000, "the table holds the whole value");
    assert.match(out.aggregate_note, /exact only while distinct_cap_reached is null/);
  });
});

test("the values file holds a line that is not UTF-8 as escapes, byte for byte, and a run that fails gives the job's one file back", async () => {
  await withCwd(async (cwd) => {
    const bad = Buffer.concat([Buffer.from("free text password="), Buffer.from([0xe9, 0xff]), Buffer.from("end")]);
    await put(cwd, "inputs/l.log", Buffer.concat([Buffer.from(WEB + "\n"), bad, Buffer.from("\n")]));
    body(await asJob(LOGS, cwd, { path: "inputs/l.log", out_dir: "out/o", write_values: true }));
    const text = await readFile(join(cwd, "out/network-log-values.jsonl"), "utf8");
    assert.match(text, /free text password=\\udce9\\udcffend/);
    const row = JSON.parse(text.trimEnd());
    assert.deepEqual(Buffer.from(row.value as string, "utf8").length > 0, true);
    assert.equal(row.value.includes("\ufffd"), false, "no replacement character");
  });
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/garbage.gz", Buffer.concat([Buffer.from([0x1f, 0x8b]), Buffer.from("this is not a deflate stream at all")]));
    await put(cwd, "inputs/ok.log", WEB + "\n");
    const failed = await asJob(LOGS, cwd, { path: "inputs/garbage.gz", out_dir: "out/a", write_values: true });
    assert.equal(failed.code, 1);
    assert.equal(await exists(join(cwd, "out/network-log-values.jsonl")), false, "nothing was written, so the file was given back");
    const again = body(await asJob(LOGS, cwd, { path: "inputs/ok.log", out_dir: "out/b", write_values: true }));
    assert.equal(again.secret_values.requested, true);
  });
});
