/**
 * network-forensics: conn_series turns a Zeek conn.log (TSV or JSON lines) or a capture into unique connection observations and a start-time series that beacon_score reads.
 *
 * The Zeek logs here are built from Zeek's documented conn.log fields (the #separator/#set_separator/#empty_field/#unset_field/#fields/#types header and the TSV or JSON
 * row); no Zeek runs. A capture is listed by tshark, and a stand-in `tshark` plays it with the documented `-T fields` output of a plan built together with the capture bytes.
 * That proves the wrapper and the model; it proves nothing about the real programs' field values: one test runs the real tshark when it is installed and says so when not.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, readFile, readdir, stat, writeFile } from "node:fs/promises";
import { basename, join } from "node:path";
import { test } from "node:test";
import { BEACON, CONNS, NET, TOOLS, TCP, body, exists, filesUnder, frameTcp4, frameUdp4, gone, pcapClassic, put, refused, startDetached, stub, tool, withCwd } from "./pack-network-harness.ts";
import type { Json } from "./pack-network-harness.ts";
import { CUT_FLOODERS, FEW, PY_LEAVE, alive, exec, floodTheVersionProbe, pids, reap, snapshot, sleep } from "./network-process-harness.ts";
import { NO_SETSID, NO_ADOPTION } from "./host-gates.ts";

type Row = { ts: number | string; uid?: string | null; oh?: string; op?: number | string; rh?: string; rp?: number | string; proto?: string; service?: string | null; duration?: number | string; ob?: number | string; rb?: number | string; state?: string; opk?: number | string; rpk?: number | string };

const FIELDS = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service", "duration", "orig_bytes", "resp_bytes", "conn_state", "orig_pkts", "resp_pkts", "tunnel_parents"];
const TYPES = ["time", "string", "addr", "port", "addr", "port", "enum", "string", "interval", "count", "count", "string", "count", "count", "set[string]"];

function header(fields = FIELDS, types = TYPES, sep = "\t"): string {
  const esc = sep === "\t" ? "\\x09" : `\\x${sep.charCodeAt(0).toString(16).padStart(2, "0")}`;
  return [`#separator ${esc}`, `#set_separator${sep},`, `#empty_field${sep}(empty)`, `#unset_field${sep}-`, "#path" + sep + "conn", "#open" + sep + "2026-11-04-00-00-00", `#fields${sep}${fields.join(sep)}`, `#types${sep}${types.join(sep)}`].join("\n") + "\n";
}

const cellOf = (v: unknown): string => (v === undefined || v === null ? "-" : v === "" ? "(empty)" : String(v));
function tsvRow(r: Row, fields = FIELDS, sep = "\t"): string {
  const map: Record<string, unknown> = { ts: r.ts, uid: r.uid === undefined ? `C${Math.abs(Number(r.ts) * 7919 | 0)}x` : r.uid, "id.orig_h": r.oh ?? "10.0.0.5", "id.orig_p": r.op ?? 50000, "id.resp_h": r.rh ?? "203.0.113.7", "id.resp_p": r.rp ?? 443,
    proto: r.proto ?? "tcp", service: r.service === undefined ? "ssl" : r.service, duration: r.duration ?? 1.5, orig_bytes: r.ob ?? 100, resp_bytes: r.rb ?? 200, conn_state: r.state ?? "SF", orig_pkts: r.opk ?? 4, resp_pkts: r.rpk ?? 5, tunnel_parents: "" };
  return fields.map((f) => cellOf(map[f])).join(sep);
}
const tsv = (rows: Row[]): string => header() + rows.map((r) => tsvRow(r)).join("\n") + "\n#close\t2026-11-04-01-00-00\n";
const jsonl = (rows: Row[], nested = false): string => rows.map((r) => {
  const o: Json = nested ? { ts: r.ts, uid: r.uid ?? `Cj${r.ts}`, id: { orig_h: r.oh ?? "10.0.0.5", orig_p: r.op ?? 50000, resp_h: r.rh ?? "203.0.113.7", resp_p: r.rp ?? 443 } }
    : { ts: r.ts, uid: r.uid ?? `Cj${r.ts}`, "id.orig_h": r.oh ?? "10.0.0.5", "id.orig_p": r.op ?? 50000, "id.resp_h": r.rh ?? "203.0.113.7", "id.resp_p": r.rp ?? 443 };
  Object.assign(o, { proto: r.proto ?? "tcp", service: r.service === undefined ? "ssl" : r.service, duration: r.duration ?? 1.5, orig_bytes: r.ob ?? 100, resp_bytes: r.rb ?? 200, conn_state: r.state ?? "SF", orig_pkts: r.opk ?? 4, resp_pkts: r.rpk ?? 5 });
  return JSON.stringify(o);
}).join("\n") + "\n";

const T0 = 1_700_000_000;
const beaconRows = (n: number, step: number, extra: Partial<Row> = {}): Row[] => Array.from({ length: n }, (_, i) => ({ ts: T0 + i * step, uid: `Cb${i}`, op: 1024 + (i % 60000), ...extra }));
const run = (cwd: string, bin: string, args: Json, extra: Record<string, string> = {}) => tool(CONNS, cwd, args, { STUB_DIR: join(cwd, "stub"), ...extra }, bin);
const tail = (shownPath: string): string => basename(shownPath);
const out_ = (cwd: string, shownPath: string): string => join(cwd, "work/s1/tool-output", tail(shownPath));
const base = { conn_log: "inputs/conn.log" };

// ---- the Zeek log -------------------------------------------------------------------------------------------------------------------

test("a TSV conn.log gives unique observations with locator, start, duration, bytes, packets, state, service and the time semantics; a repeated uid is one observation", async () => {
  await withCwd(async (cwd, bin) => {
    const rows: Row[] = [{ ts: T0 + 2, uid: "CAAA" }, { ts: T0 + 1, uid: "CBBB", proto: "udp", service: "dns", op: 53000, rp: 53, ob: 40, rb: 120, state: "SF" }, { ts: T0 + 2, uid: "CAAA" }, { ts: T0 + 3, uid: "CCCC", service: null, duration: "-", ob: "-" },
      { ts: T0 + 4, uid: "CDDD", oh: "2001:db8::5", rh: "2001:db8::7", rp: 8443 }];
    await put(cwd, "inputs/conn.log", tsv(rows));
    const out = body(await run(cwd, bin, { ...base }));
    assert.equal(out.status, "complete", out.status_basis);
    assert.equal(out.observations_total, 4);
    assert.equal(out.counts.duplicates, 1);
    const byUid = Object.fromEntries(out.observations.map((o: Json) => [o.uid, o]));
    assert.deepEqual(byUid.CAAA.locator, { source: "inputs/conn.log", line: 9, byte_offset: Buffer.byteLength(tsv(rows).split("\n").slice(0, 8).join("\n") + "\n") });
    assert.deepEqual([byUid.CBBB.proto, byUid.CBBB.bytes.orig, byUid.CBBB.bytes.resp, byUid.CBBB.packets.orig, byUid.CBBB.state, byUid.CBBB.service], ["udp", 40, 120, 4, "SF", "dns"]);
    assert.equal(byUid.CAAA.start.utc, "2023-11-14T22:13:22.000000Z");
    assert.match(byUid.CAAA.time_semantics, /first packet Zeek saw of the connection, not one event per exchange/);
    assert.equal(byUid.CCCC.service, null, "the unset field is null");
    assert.equal(byUid.CCCC.duration_seconds, null);
    assert.equal(byUid.CCCC.bytes.orig, null);
    assert.equal(byUid.CDDD.orig.ip, "2001:db8::5", "IPv6 is read like IPv4");
    assert.equal(out.series.events, 4);
    const series = (await readFile(out_(cwd, out.series.file), "utf8")).trim().split("\n").map(Number);
    assert.deepEqual(series, [T0 + 1, T0 + 2, T0 + 3, T0 + 4], "one epoch per line, ascending, a log in order of connection end is re-sorted");
    assert.equal((await stat(out_(cwd, out.series.file))).mode & 0o777, 0o600);
  });
});

test("Zeek's own conventions: a rotated log with a second header block, reordered #fields, a changed separator and set separator, (empty) and - cells, set[string] types", async () => {
  await withCwd(async (cwd, bin) => {
    const second = ["uid", "ts", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service", "tunnel_parents"];
    const typesSecond = ["string", "time", "addr", "port", "addr", "port", "enum", "set[string]", "set[string]"];
    const sepB = "\u001f";
    const text = tsv([{ ts: T0, uid: "CFIRST" }])
      + header(second, typesSecond, sepB)
      + [`CSEC1${sepB}${T0 + 10}${sepB}10.0.0.9${sepB}41000${sepB}198.51.100.2${sepB}80${sepB}tcp${sepB}http,ssl${sepB}(empty)`,
        `CSEC2${sepB}${T0 + 20}${sepB}10.0.0.9${sepB}41001${sepB}198.51.100.2${sepB}80${sepB}tcp${sepB}-${sepB}-`].join("\n") + "\n";
    await put(cwd, "inputs/conn.log", text);
    const out = body(await run(cwd, bin, { ...base }));
    assert.equal(out.status, "complete", out.status_basis);
    assert.equal(out.observations_total, 3);
    const by = Object.fromEntries(out.observations.map((o: Json) => [o.uid, o]));
    assert.equal(by.CSEC1.service, "http,ssl", "a set[string] is joined with the set separator read from its header");
    assert.equal(by.CSEC2.service, null);
    assert.equal(by.CSEC1.state, null, "a column the second block lacks is unset");
    assert.match(out.notes.join(" "), /2 header blocks/);
  });
});

test("JSON lines, flat or with a nested id, with epoch or ISO times", async () => {
  await withCwd(async (cwd, bin) => {
    await put(cwd, "inputs/conn.log", jsonl([{ ts: T0, uid: "Cj1" }, { ts: "2023-11-14T22:13:21+00:00", uid: "Cj2" }], false) + jsonl([{ ts: T0 + 5, uid: "Cj3" }], true));
    const out = body(await run(cwd, bin, { ...base }));
    assert.equal(out.status, "complete", out.status_basis);
    assert.equal(out.observations_total, 3);
    assert.equal(out.counts.log.json_rows, 3);
    assert.deepEqual((await readFile(out_(cwd, out.series.file), "utf8")).trim().split("\n").map(Number), [T0, T0 + 1, T0 + 5]);
  });
});

// ---- the series and beacon_score ---------------------------------------------------------------------------------------------------------

test("beacon_score accepts the produced series file as timestamps_file and measures the schedule that was put in", async () => {
  await withCwd(async (cwd, bin) => {
    await put(cwd, "inputs/conn.log", tsv(beaconRows(60, 300)));
    const out = body(await run(cwd, bin, { ...base, window_end: "2023-11-15T05:00:00+00:00", sensor_coverage_confirmed: true }));
    assert.deepEqual(out.beacon_score_arguments, { timestamps_file: out.series.file, window_end: "2023-11-15T05:00:00+00:00", sensor_coverage_confirmed: true });
    const score = body(await tool(BEACON, cwd, { timestamps_file: `work/s1/tool-output/${tail(out.series.file)}`, window_end: out.beacon_score_arguments.window_end, sensor_coverage_confirmed: true, label: "conn series" }, {}, bin));
    assert.equal(score.status, "complete", score.status_basis);
    assert.match(JSON.stringify(score), /300/, "the median interval of the schedule put in");
  });
});

test("coverage is carried only as given: without window_end it is not passed on, and without the flag it is never set", async () => {
  await withCwd(async (cwd, bin) => {
    await put(cwd, "inputs/conn.log", tsv(beaconRows(10, 60)));
    const a = body(await run(cwd, bin, { ...base, sensor_coverage_confirmed: true }));
    assert.deepEqual(Object.keys(a.beacon_score_arguments), ["timestamps_file"]);
    assert.match(a.notes.join(" "), /sensor_coverage_confirmed was given without window_end/);
    const b = body(await run(cwd, bin, { ...base, window_end: T0 + 10_000 }));
    assert.equal("sensor_coverage_confirmed" in b.beacon_score_arguments, false);
    assert.equal(b.coverage.sensor_coverage_confirmed, false);
  });
});

// ---- the window and zones ------------------------------------------------------------------------------------------------------------------

test("the window is start inclusive, end exclusive, on the connection's start; zones are explicit and a zone-less time is refused", async () => {
  await withCwd(async (cwd, bin) => {
    await put(cwd, "inputs/conn.log", tsv(beaconRows(10, 1)));
    const edge = body(await run(cwd, bin, { ...base, window_start: T0 + 3, window_end: T0 + 6 }));
    assert.deepEqual(edge.observations.map((o: Json) => o.start.raw), [String(T0 + 3), String(T0 + 4), String(T0 + 5)]);
    assert.equal(edge.counts.outside_window, 7);
    // the same instants given with a zone
    await put(cwd, "inputs/conn.log", tsv(beaconRows(10, 10)));
    const zoned = body(await run(cwd, bin, { ...base, window_start: "2023-11-15T01:13:50+03:00", window_end: "2023-11-14T22:14:30Z" }));
    assert.equal(zoned.observations_total >= 1, true);
    assert.equal(zoned.scope.window.start_epoch, 1_700_000_030);
    for (const [args, pattern] of [[{ window_start: "2023-11-14T22:13:50" }, /window_start has no zone/], [{ window_end: "tomorrow" }, /window_end not an epoch or an ISO 8601 time/], [{ window_start: T0 + 5, window_end: T0 + 5 }, /window_end must be after window_start/]] as Array<[Json, RegExp]>) {
      const err = refused(await run(cwd, bin, { ...base, ...args }));
      assert.match(err.error, pattern);
    }
    const assumed = body(await run(cwd, bin, { ...base, window_start: "2023-11-14T22:13:50", assume_utc: true }));
    assert.match(assumed.notes.join(" "), /1 window time\(s\) with no zone were read as UTC/);
  });
});

// ---- filters ------------------------------------------------------------------------------------------------------------------------------

test("filters: host, port and proto select; the service filter reads the shown text, so a withheld service value is not an oracle", async () => {
  await withCwd(async (cwd, bin) => {
    const token = "aGVsbG8gd29ybGQgYmFzZTY0IHRva2Vu0123456789abcdef";
    const rows: Row[] = [{ ts: T0, uid: "Cs1", service: "ssl" }, { ts: T0 + 1, uid: "Cs2", service: "dns", proto: "udp", rp: 53 }, { ts: T0 + 2, uid: "Cs3", service: token, oh: "10.0.0.6" }, { ts: T0 + 3, uid: "Cs4", service: "ssl", rh: "192.0.2.9" }];
    await put(cwd, "inputs/conn.log", tsv(rows));
    const uids = async (args: Json): Promise<string[]> => body(await run(cwd, bin, { ...base, ...args })).observations.map((o: Json) => o.uid).sort();
    assert.deepEqual(await uids({ host: "10.0.0.6" }), ["Cs3"]);
    assert.deepEqual(await uids({ port: 53 }), ["Cs2"]);
    assert.deepEqual(await uids({ proto: "udp" }), ["Cs2"]);
    assert.deepEqual(await uids({ service: "ssl" }), ["Cs1", "Cs4"]);
    // the oracle twin: asking for the withheld value by its true text finds nothing; the same answer as asking for a value that is not there
    const guess = body(await run(cwd, bin, { ...base, service: token }));
    const none = body(await run(cwd, bin, { ...base, service: "nothing-like-it" }));
    assert.equal(guess.observations_total, 0);
    assert.equal(none.observations_total, 0);
    assert.equal(JSON.stringify(guess.scope).includes(token), false, "the filter text is not echoed in clear when it is token-shaped");
    // the unfiltered view withholds it, the file holds it
    const all = body(await run(cwd, bin, { ...base }));
    assert.equal(JSON.stringify(all).includes(token), false);
    assert.equal(all.counts.service_withheld_not_matched, 0);
  });
});

test("canaries in service and uid are in no inline row; the whole file holds them; the file is owner-only", async () => {
  await withCwd(async (cwd, bin) => {
    const uidCanary = "CzZ9yYxX8wWvV7uUtT6sS5rR", service = "q9w8e7r6t5y4u3i2o1p0a9s8d7f6g5h4";
    const rows = Array.from({ length: 30 }, (_, i): Row => ({ ts: T0 + i, uid: i === 0 ? uidCanary : `Cn${i}`, service: i === 0 ? service : "ssl" }));
    await put(cwd, "inputs/conn.log", tsv(rows));
    const r = await run(cwd, bin, { ...base, limit: 5 });
    const out = body(r);
    assert.equal(r.stdout.includes(uidCanary), false);
    assert.equal(r.stdout.includes(service), false);
    assert.equal(out.observations_total, 30);
    const file = join(cwd, "work/s1/tool-output", basename(out.all_results));
    const whole = (await readFile(file, "utf8")).trim().split("\n").map((l) => JSON.parse(l));
    assert.equal(whole.length, 30);
    assert.equal(whole[0].uid, uidCanary);
    assert.equal(whole[0].service, service);
    assert.equal((await stat(file)).mode & 0o077, 0);
  });
});

// ---- hostile logs ---------------------------------------------------------------------------------------------------------------------------

test("hostile logs: a 10 MB line, no #fields, mismatched columns, NUL, non-UTF-8, a gzip file are counted or refused, never echoed, never a crash", async () => {
  await withCwd(async (cwd, bin) => {
    const good = tsvRow({ ts: T0, uid: "Cg1" });
    const big = "x".repeat(10_000_000);
    const text = Buffer.concat([Buffer.from(header() + good + "\n" + big + "\n" + "1\t2\t3\n" + "A\0B\n"), Buffer.from([0xff, 0xfe, 0x0a]), Buffer.from(tsvRow({ ts: T0 + 1, uid: "Cg2" }) + "\n")]);
    await put(cwd, "inputs/conn.log", text);
    const r = await run(cwd, bin, { ...base });
    const out = body(r);
    assert.equal(out.status, "partial");
    assert.equal(out.observations_total, 2);
    assert.deepEqual([out.counts.log.long_lines, out.counts.log.mismatched_columns, out.counts.log.nul_lines, out.counts.log.non_utf8_lines], [1, 1, 1, 1]);
    assert.equal(r.stdout.length < 100_000, true);
    assert.equal(r.stdout.includes("xxxxxxxxxx"), false);
    await put(cwd, "inputs/nofields.log", "#separator \\x09\n" + good + "\n" + good + "\n");
    const nf = body(await run(cwd, bin, { conn_log: "inputs/nofields.log" }));
    assert.equal(nf.status, "partial");
    assert.equal(nf.observations_total, 0);
    assert.equal(nf.counts.log.rows_before_fields, 2);
    await put(cwd, "inputs/missing.log", header(["ts", "uid"], ["time", "string"]) + `${T0}\tCx\n`);
    const mf = body(await run(cwd, bin, { conn_log: "inputs/missing.log" }));
    assert.equal(mf.counts.log.rows_without_required_fields, 1);
    await put(cwd, "inputs/log.gz", Buffer.from([0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3]));
    assert.match(refused(await run(cwd, bin, { conn_log: "inputs/log.gz" })).error, /gzip-compressed/);
  });
});

test("bad values in good rows: a time that is not a time, an address that is not an address, a port out of range", async () => {
  await withCwd(async (cwd, bin) => {
    await put(cwd, "inputs/conn.log", tsv([{ ts: "nope", uid: "Cb1" }, { ts: T0, uid: "Cb2", oh: "999.1.1.1" }, { ts: T0, uid: "Cb3", op: 70000 }, { ts: T0 + 1, uid: "Cb4" }, { ts: "NaN", uid: "Cb5" }]));
    const out = body(await run(cwd, bin, { ...base }));
    assert.equal(out.status, "partial");
    assert.equal(out.observations_total, 1);
    assert.match(out.problems.join(" "), /not an epoch or an ISO time with a zone/);
  });
});

test("refusals are JSON with exit 1", async () => {
  await withCwd(async (cwd, bin) => {
    await put(cwd, "inputs/conn.log", tsv(beaconRows(3, 1)));
    const cases: Array<[Json, RegExp]> = [[{}, /exactly one of conn_log/], [{ ...base, capture: "inputs/c.pcap" }, /exactly one of conn_log/], [{ ...base, extra: 1 }, /unknown parameters: extra/], [{ ...base, host: "x" }, /host must be an IP/],
      [{ ...base, proto: "sctp" }, /proto must be tcp, udp or icmp/], [{ ...base, port: 70000 }, /port must be an integer/], [{ ...base, max_seconds: 1 }, /max_seconds must be an integer from 10/], [{ conn_log: "inputs/none.log" }, /no such file/],
      [{ ...base, assume_utc: "y" }, /assume_utc must be true or false/], [{ ...base, udp_gap_seconds: 0 }, /udp_gap_seconds must be an integer/]];
    for (const [args, pattern] of cases) {
      const err = refused(await run(cwd, bin, args));
      assert.match(err.error, pattern, JSON.stringify(args));
      assert.equal(err.status, "failed");
    }
  });
});

// ---- the capture ------------------------------------------------------------------------------------------------------------------------------

const TSHARK = `#!/usr/bin/env python3
import json, os, sys, time
d = os.environ["STUB_DIR"]
args = sys.argv[1:]
open(os.path.join(d, "calls.log"), "a").write(json.dumps(args) + "\\n")
${PY_LEAVE}
missing = [m for m in os.environ.get("STUB_MISSING", "").split(",") if m]
NAMES = ["frame.number", "frame.time_epoch", "frame.len", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst", "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport", "tcp.flags", "tcp.seq_raw"]
if args[:1] == ["--version"]:
    print("TShark (Wireshark) 4.4.0 stand-in"); sys.exit(0)
if args[:2] == ["-G", "fields"]:
    for n in NAMES:
        if n not in missing: print("F\\tName of " + n + "\\t" + n + "\\tFT_STRING\\tip\\t\\t0x0\\t")
    sys.exit(0)
if os.environ.get("STUB_MODE") == "hang-listing" and "-T" in args:
    import subprocess
    child = subprocess.Popen(["sleep", "300"]); open(os.path.join(d, "child.pid"), "w").write(str(child.pid))
    open(os.path.join(d, "started"), "w").write("1")
    time.sleep(300)
cols = [args[i + 1] for i, a in enumerate(args) if a == "-e"]
if os.environ.get("STUB_LEFT") and "-T" in args:
    leave_behind(d, os.environ["STUB_LEFT"], (os.readlink("/proc/self/fd/2") if os.path.isdir("/proc/self") else __import__("fcntl").fcntl(2, 50, bytes(1024)).split(bytes(1))[0].decode()))
for f in json.load(open(os.path.join(d, "plan.json"))):
    print("\\t".join(str(f.get(c, "")) for c in cols))
`;

type Pkt = { t: number; src: string; dst: string; sport: number; dport: number; proto: "tcp" | "udp"; flags?: number; seq?: number; len?: number };
function capture(pkts: Pkt[]): { plan: Json[]; pcap: Buffer } {
  const plan = pkts.map((k, i) => {
    const v6 = k.src.includes(":");
    const row: Json = { "frame.number": i + 1, "frame.time_epoch": `${k.t}`, "frame.len": k.len ?? 60, [v6 ? "ipv6.src" : "ip.src"]: k.src, [v6 ? "ipv6.dst" : "ip.dst"]: k.dst };
    if (k.proto === "tcp") Object.assign(row, { "tcp.srcport": k.sport, "tcp.dstport": k.dport, "tcp.flags": `0x${(k.flags ?? TCP.ACK).toString(16).padStart(4, "0")}`, "tcp.seq_raw": k.seq ?? 0 });
    else Object.assign(row, { "udp.srcport": k.sport, "udp.dstport": k.dport });
    return row;
  });
  const frames = pkts.filter((k) => !k.src.includes(":")).map((k) => ({ sec: Math.floor(k.t), frame: k.proto === "tcp"
    ? frameTcp4({ src: k.src, dst: k.dst, sport: k.sport, dport: k.dport, flags: k.flags ?? TCP.ACK, seq: k.seq ?? 0 })
    : frameUdp4({ src: k.src, dst: k.dst, sport: k.sport, dport: k.dport, payload: "x" }) }));
  return { plan, pcap: pcapClassic(frames) };
}
async function setupCapture(cwd: string, bin: string, pkts: Pkt[]): Promise<string> {
  const dir = join(cwd, "stub");
  await mkdir(dir, { recursive: true });
  const built = capture(pkts);
  await writeFile(join(dir, "plan.json"), JSON.stringify(built.plan));
  await stub(bin, "tshark", TSHARK);
  await put(cwd, "inputs/capture.pcap", built.pcap);
  return dir;
}
const C = "10.0.0.5", S = "203.0.113.7";

test("a capture: a retransmitted SYN is not a second connection, port reuse is, UDP is the tuple plus an inactivity gap, IPv6 is like IPv4, midstream is said", async () => {
  await withCwd(async (cwd, bin) => {
    const syn = (t: number, seq: number, sport = 50000): Pkt => ({ t, src: C, dst: S, sport, dport: 443, proto: "tcp", flags: TCP.SYN, seq });
    const pkts: Pkt[] = [
      syn(T0, 1000), syn(T0 + 1, 1000), syn(T0 + 3, 1000),                                     // one connection, two retransmissions
      { t: T0 + 3.1, src: S, dst: C, sport: 443, dport: 50000, proto: "tcp", flags: TCP.SYN | TCP.ACK, seq: 9000 },
      { t: T0 + 3.2, src: C, dst: S, sport: 50000, dport: 443, proto: "tcp", flags: TCP.ACK, seq: 1001, len: 1400 },
      { t: T0 + 4, src: C, dst: S, sport: 50000, dport: 443, proto: "tcp", flags: TCP.FIN | TCP.ACK, seq: 2400 },
      syn(T0 + 100, 777),                                                                         // the same ports, a new ISN: a new connection
      { t: T0 + 200, src: C, dst: "8.8.8.8", sport: 41000, dport: 53, proto: "udp" },
      { t: T0 + 230, src: "8.8.8.8", dst: C, sport: 53, dport: 41000, proto: "udp" },            // 30 s later: the same connection (gap 60)
      { t: T0 + 400, src: C, dst: "8.8.8.8", sport: 41000, dport: 53, proto: "udp" },            // 170 s after: a new one
      { t: T0 + 500, src: "2001:db8::5", dst: "2001:db8::7", sport: 52000, dport: 443, proto: "tcp", flags: TCP.SYN, seq: 5 },
      { t: T0 + 600, src: C, dst: S, sport: 55555, dport: 22, proto: "tcp", flags: TCP.ACK, seq: 1 },   // no SYN: midstream
    ];
    await setupCapture(cwd, bin, pkts);
    const out = body(await run(cwd, bin, { capture: "inputs/capture.pcap", limit: 50 }));
    assert.equal(out.status, "complete", out.status_basis);
    assert.equal(out.counts.capture.syn_retransmissions, 2);
    assert.equal(out.counts.capture.port_reuse, 1);
    assert.equal(out.observations_total, 6, JSON.stringify(out.observations.map((o: Json) => [o.proto, o.start.raw])));
    const tcp443 = out.observations.filter((o: Json) => o.proto === "tcp" && o.resp.port === 443 && o.orig.ip === C);
    assert.deepEqual(tcp443.map((o: Json) => o.start.raw), [String(T0), String(T0 + 100)]);
    assert.deepEqual([tcp443[0].packets.orig, tcp443[0].packets.resp, tcp443[0].bytes.orig], [5, 1, 60 * 4 + 1400]);
    assert.match(tcp443[0].bytes.basis, /frame length/);
    const udp = out.observations.filter((o: Json) => o.proto === "udp");
    assert.equal(udp.length, 2);
    assert.deepEqual([udp[0].packets.orig, udp[0].packets.resp], [1, 1]);
    assert.ok(out.observations.some((o: Json) => o.orig.ip === "2001:db8::5"));
    const mid = out.observations.find((o: Json) => o.flags.includes("midstream"));
    assert.equal(mid.start.raw, String(T0 + 600));
    assert.match(out.notes.join(" "), /already open when the capture began or had no SYN/);
    assert.deepEqual((await readFile(out_(cwd, out.series.file), "utf8")).trim().split("\n").map(Number), [T0, T0 + 100, T0 + 200, T0 + 400, T0 + 500, T0 + 600]);
  });
});

test("a capture whose tshark lacks a field is refused by name or partial: no tcp.seq_raw means a retransmitted SYN cannot be told apart", async () => {
  await withCwd(async (cwd, bin) => {
    await setupCapture(cwd, bin, [{ t: T0, src: C, dst: S, sport: 1, dport: 2, proto: "tcp", flags: TCP.SYN, seq: 1 }]);
    const lacking = refused(await run(cwd, bin, { capture: "inputs/capture.pcap" }, { STUB_MISSING: "tcp.flags" }));
    assert.match(lacking.error, /lacks the field\(s\) tcp.flags/);
    const partial = body(await run(cwd, bin, { capture: "inputs/capture.pcap" }, { STUB_MISSING: "tcp.seq_raw" }));
    assert.equal(partial.status, "partial");
    assert.match(partial.problems.join(" "), /lacks tcp.seq_raw/);
  });
});

// ---- bounds --------------------------------------------------------------------------------------------------------------------------------------

test("5,000,000 rows: the table and the series stop at the cap, the answer is partial and says so, and time and memory are bounded (measured)", { timeout: 1_200_000 }, async () => {
  await withCwd(async (cwd, bin) => {
    const gen = join(cwd, "gen.py");
    await writeFile(gen, `import sys\nh=sys.argv[1]\nwith open(sys.argv[2],"w") as f:\n    f.write(open(h).read())\n    for i in range(5000000):\n        f.write("%d.%06d\\tC%d\\t10.0.%d.%d\\t%d\\t203.0.113.7\\t443\\ttcp\\tssl\\t1.5\\t100\\t200\\tSF\\t4\\t5\\t(empty)\\n" % (1700000000+i//10, (i%10)*1000, i, (i>>8)&255, i&255, 1024+i%60000))\n`);
    await writeFile(join(cwd, "header.txt"), header());
    const made = spawnSync("python3", [gen, join(cwd, "header.txt"), join(cwd, "inputs/conn.log")], { encoding: "utf8" });
    assert.equal(made.status, 0, made.stderr);
    const t0 = Date.now();
    const r = await run(cwd, bin, { ...base, limit: 25, max_seconds: 1000 });
    const seconds = (Date.now() - t0) / 1000;
    const out = body(r);
    process.stderr.write(`# conn_series 5,000,000 rows: ${seconds.toFixed(1)} s, max_rss ${out.resources.max_rss_kb} kB, status ${out.status}, kept ${out.resources.connections_kept}\n`);
    assert.ok(seconds < 1100);
    assert.equal(out.status, "partial");
    assert.equal(out.observations_total, 3_000_000);
    assert.equal(out.counts.over_cap, 2_000_000);
    assert.match(out.problems.join(" "), /past the 3000000-connection cap/);
    assert.equal(out.series.events, 3_000_000);
    assert.ok(out.resources.max_rss_kb < 3_000_000, `peak ${out.resources.max_rss_kb} kB`);
    const lines = (await readFile(out_(cwd, out.series.file), "utf8")).trim().split("\n");
    assert.equal(lines.length, 3_000_000);
  });
});

test("four simultaneous runs each finish inside the manifest's timeout and agree", { timeout: 600_000 }, async () => {
  await withCwd(async (cwd, bin) => {
    await put(cwd, "inputs/conn.log", tsv(beaconRows(200_000, 1)));
    const t0 = Date.now();
    const outs = (await Promise.all([0, 1, 2, 3].map((i) => run(cwd, bin, { ...base, limit: 10 + i })))).map(body);
    assert.ok(Date.now() - t0 < 500_000);
    assert.deepEqual(outs.map((o) => o.observations_total), [200_000, 200_000, 200_000, 200_000]);
  });
});

test("the tool's own clock: a log that takes longer than max_seconds is cut, said to be cut, and never complete", { timeout: 300_000 }, async () => {
  await withCwd(async (cwd, bin) => {
    await put(cwd, "inputs/conn.log", tsv(beaconRows(1_500_000, 1)));
    const out = body(await run(cwd, bin, { ...base, max_seconds: 10 }));
    assert.equal(out.status, "partial");
    assert.match(out.problems.join(" "), /own clock \(max_seconds\) ran out while reading the log/);
    assert.equal(out.observations_total < 1_500_000, true);
  });
});

// ---- stops --------------------------------------------------------------------------------------------------------------------------------------

test("a tshark that outlives the clock is killed with what it started; a stop signal gives one JSON answer with the stage and removes the temporary directory", async () => {
  await withCwd(async (cwd, bin) => {
    const dir = await setupCapture(cwd, bin, [{ t: T0, src: C, dst: S, sport: 1, dport: 2, proto: "udp" }]);
    const t0 = Date.now();
    const r = await run(cwd, bin, { capture: "inputs/capture.pcap", max_seconds: 10 }, { STUB_MODE: "hang-listing" });
    assert.ok(Date.now() - t0 < 30_000);
    assert.equal(refused(r).status, "failed");
    assert.equal(await gone(Number((await readFile(join(dir, "child.pid"), "utf8")).trim())), true);
    assert.deepEqual((await filesUnder(join(cwd, "work"))).filter((f) => f.split("/").some((p) => p.startsWith("."))), []);
  });
  for (const [sig, code] of [["SIGTERM", 143], ["SIGINT", 130], ["SIGHUP", 129]] as const) {
    await withCwd(async (cwd, bin) => {
      const dir = await setupCapture(cwd, bin, [{ t: T0, src: C, dst: S, sport: 1, dport: 2, proto: "udp" }]);
      const r = startDetached(CONNS, cwd, { capture: "inputs/capture.pcap" }, { STUB_DIR: dir, STUB_MODE: "hang-listing", AGENT_ID: "s1" }, bin);
      for (let i = 0; i < 400 && !(await exists(join(dir, "started"))); i++) await new Promise((res) => setTimeout(res, 50));
      r.signal(sig);
      assert.equal(await r.closed, code, sig);
      const last = JSON.parse(r.stdout());
      assert.equal(r.stdout().trim().split("\n").length, 1);
      assert.deepEqual([last.status, last.interrupted_by_signal, last.stage], ["partial", code - 128, "listing the packets (tshark -T fields)"]);
      assert.equal(await gone(Number((await readFile(join(dir, "child.pid"), "utf8")).trim())), true);
      assert.deepEqual((await filesUnder(join(cwd, "work"))).filter((f) => f.split("/").some((p) => p.startsWith("."))), []);
    });
  }
});

// ---- fuzz (at most 1,000 cases; 300 here) ----------------------------------------------------------------------------------------------------------

test("fuzz: 300 logs of random lines, headers and values never end without JSON or in a traceback", { timeout: 900_000 }, async () => {
  let seed = 31337;
  const rnd = (n: number): number => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed % n; };
  const pieces = ["", "-", "(empty)", "1700000000.5", "nan", "inf", "-5", "10.0.0.1", "::1", "999.0.0.1", "tcp", "udp", "icmp", "sctp", "ssl,http", "\u0000", "é", "70000", "1e400", "#fields", "#types", "#separator \\x09", "{", "{}", '{"ts":1}', "\t\t", "x".repeat(300)];
  await withCwd(async (cwd, bin) => {
    for (let i = 0; i < 300; i++) {
      const lines: string[] = [];
      if (rnd(4)) lines.push(header(rnd(2) ? FIELDS : FIELDS.slice(0, 1 + rnd(FIELDS.length)), TYPES));
      for (let k = 0; k < 1 + rnd(20); k++) {
        if (rnd(3) === 0) lines.push(Array.from({ length: rnd(18) }, () => pieces[rnd(pieces.length)]).join("\t"));
        else lines.push(tsvRow({ ts: rnd(4) ? T0 + k : pieces[rnd(pieces.length)], uid: rnd(5) ? `Cf${k}` : null, op: rnd(5) ? 40000 : pieces[rnd(pieces.length)], proto: rnd(5) ? "tcp" : pieces[rnd(pieces.length)] }));
      }
      await put(cwd, "inputs/conn.log", lines.join("\n"));
      const r = await run(cwd, bin, { ...base, limit: 1 + rnd(30) });
      assert.doesNotMatch(r.stderr, /Traceback/, `case ${i}`);
      const out = JSON.parse(r.stdout);
      assert.ok(["complete", "partial", "failed"].includes(out.status), `case ${i}`);
      if (out.status === "complete") assert.equal(out.problems.length, 0);
    }
  });
});

// ---- the manifest -----------------------------------------------------------------------------------------------------------------------------------

test("the manifest names the parameters the script reads, defines the behaviour the card lists, and carries the sha256 and version of its script", async () => {
  const manifest: Json = JSON.parse(await readFile(join(TOOLS, "conn_series", "manifest.json"), "utf8"));
  const script = await readFile(CONNS, "utf8");
  assert.equal(manifest.sha256, createHash("sha256").update(script).digest("hex"));
  const t = script.match(/^TOOL = \{"name": "([a-z_]+)", "version": (\d+)\}$/m)!;
  assert.deepEqual([t[1], Number(t[2])], ["conn_series", manifest.version]);
  assert.match(script, /^PARSER = "conn_series\/\d+"$/m);
  assert.ok((await stat(CONNS)).mode & 0o111);
  assert.equal(manifest.secret_output, "required");
  assert.equal(manifest.timeout_seconds, 1200);
  const read = new Set<string>();
  for (const m of script.matchAll(/(?:text_arg|int_in)\(args, "([a-z_]+)"/g)) read.add(m[1]);
  for (const m of script.matchAll(/args\.get\("([a-z_]+)"/g)) read.add(m[1]);
  for (const m of script.matchAll(/for key in \(("[a-z_]+"(?:, "[a-z_]+")*)\)/g)) for (const k of m[1].split(", ")) read.add(k.slice(1, -1));
  for (const key of Object.keys(manifest.params)) assert.ok(read.has(key), `${key} is read`);
  for (const key of read) if (["conn_log", "capture", "host", "port", "proto", "service", "window_start", "window_end", "assume_utc", "sensor_coverage_confirmed", "udp_gap_seconds", "tcp_gap_seconds", "limit", "max_seconds"].includes(key)) assert.ok(key in manifest.params, key);
  for (const key of Object.keys(JSON.parse(manifest.example))) assert.ok(key in manifest.params, key);
  for (const claim of ["retransmit", "inactivity gap", "IPv6", "set[", "(empty)", "#separator", "rotation", "zone", "sensor_coverage_confirmed", "timestamps_file", "first packet", "shown text", "3,000,000", "NOT VERIFIED", "SIGTERM"]) assert.ok(manifest.description.includes(claim), claim);
  const source = script.replace(/^\s*#.*$/gm, "").replace(/"""[\s\S]*?"""/g, "");
  assert.doesNotMatch(source, /start_new_session|setsid|threading/);
  const pack: Json = JSON.parse(await readFile(join(NET, "pack.json"), "utf8"));
  assert.ok(pack.tools.includes("conn_series"));
});

test("with the real tshark: a capture of two TCP connections and a UDP exchange is built into connections", async (t) => {
  const probe = spawnSync("tshark", ["--version"], { encoding: "utf8" });
  if (probe.error || probe.status !== 0) {
    t.skip("tshark is not installed here; the stand-in's documented output stands in, so the field values of a real build are not verified by this suite");
    return;
  }
  await withCwd(async (cwd) => {
    const built = capture([{ t: T0, src: C, dst: S, sport: 50000, dport: 443, proto: "tcp", flags: TCP.SYN, seq: 1 }, { t: T0 + 1, src: C, dst: S, sport: 50000, dport: 443, proto: "tcp", flags: TCP.SYN, seq: 1 },
      { t: T0 + 50, src: C, dst: S, sport: 50001, dport: 443, proto: "tcp", flags: TCP.SYN, seq: 9 }, { t: T0 + 60, src: C, dst: "8.8.8.8", sport: 41000, dport: 53, proto: "udp" }]);
    await put(cwd, "inputs/capture.pcap", built.pcap);
    const out = body(await tool(CONNS, cwd, { capture: "inputs/capture.pcap" }, {}));
    assert.equal(out.observations_total, 3);
    assert.equal(out.counts.capture.syn_retransmissions, 1);
  });
});

// ---- a process tshark leaves behind (the shared process block's settle()) ---------------------------------------------------------------------
// conn_series reports what tshark printed on a pipe and writes its series file itself, so it is not held to the rule that a host which cannot show the absence of a leftover
// makes the answer partial; but a process settle() ended is a fact, and the answer is then partial and says so.

test("a process tshark leaves behind is ended before the answer and makes it partial; a clean run says program_group; a host that cannot show there was none does not make it partial", { skip: NO_ADOPTION }, async () => {
  const pkts: Pkt[] = [{ t: T0, src: C, dst: S, sport: 50000, dport: 443, proto: "tcp", flags: TCP.SYN, seq: 1000 }, { t: T0 + 1, src: C, dst: S, sport: 50000, dport: 443, proto: "tcp", flags: TCP.ACK, seq: 1001 }];
  for (const variant of ["stderr", "plain", "setsid", "double"]) {
    await withCwd(async (cwd, bin) => {
      try {
        const dir = await setupCapture(cwd, bin, pkts);
        const result = await exec(CONNS, [], { capture: "inputs/capture.pcap" }, cwd, bin, { STUB_DIR: dir, STUB_LEFT: variant }, "linux");
        assert.equal(result.code, 0, result.stderr + result.stdout);
        const out = JSON.parse(result.stdout);
        assert.equal(out.status, "partial", `${variant}: ${out.status_basis}`);
        assert.equal(out.ok, false);
        assert.ok(out.program_group.left_behind >= 1, JSON.stringify(out.program_group));
        assert.match(JSON.stringify(out.problems), /left \d+ process\(es\) running after it ended/);

        const left = await pids(cwd);
        assert.ok(left.length >= 1, `${variant}: the stand-in left a process`);
        for (const pid of left) assert.equal(alive(pid), false, `${variant}: leftover ${pid} is gone`);
        const now = await snapshot(cwd);
        await sleep(1600);
        assert.deepEqual(await snapshot(cwd), now, `${variant}: nothing changed after the answer`);
      } finally {
        await reap(cwd);
      }
    });
  }
  await withCwd(async (cwd, bin) => {
    const dir = await setupCapture(cwd, bin, pkts);
    const out = JSON.parse((await exec(CONNS, [], { capture: "inputs/capture.pcap" }, cwd, bin, { STUB_DIR: dir }, "linux")).stdout);
    assert.equal(out.status, "complete", out.status_basis);
    assert.deepEqual([out.program_group.left_behind, out.program_group.unproven, out.program_group.subreaper], [0, [], true]);
    for (const host of ["darwin", "refused"] as const) {
      const other = JSON.parse((await exec(CONNS, [], { capture: "inputs/capture.pcap", limit: 49 }, cwd, bin, { STUB_DIR: dir }, host)).stdout);
      assert.equal(other.status, "complete", `${host}: a tool that reports only what tshark printed is not held: ${other.status_basis}`);
      assert.equal(other.program_group.subreaper, false);
      assert.ok(other.program_group.unproven.length >= 1, host);
    }
  });
});

// ---- a pipe cut at the byte cap of the shared block (PKG-P8c) ---------------------------------------------------------------------------------------
// The version probe is the pipe conn_series reads through the block. A writer in a session of its own, started after tshark printed its version, floods that pipe: the block cuts it at 1 MiB (PIPE_CUT).
// On Linux the tool also adopts and ends it (left_behind >= 1); where it cannot (darwin, prctl refused) nothing finds it and only the cut is left to say the pipe was mixed: that was `complete` on the
// batch head. The sentence is looked for in the status_basis / problems, not in program_group.notes. A clean run stays complete on every host.

for (const flood of CUT_FLOODERS) {
  for (const host of ["linux", "refused", "darwin"] as const) {
    test(`conn_series: a version probe cut at the byte cap (${flood}, ${host}) is partial and says a process went on writing`, { timeout: 120000, skip: NO_SETSID }, async () => {
      
      await withCwd(async (cwd, bin) => {
        try {
          const dir = await setupCapture(cwd, bin, [{ t: T0, src: C, dst: S, sport: 50000, dport: 443, proto: "tcp", flags: TCP.SYN, seq: 1000 }, { t: T0 + 1, src: C, dst: S, sport: 50000, dport: 443, proto: "tcp", flags: TCP.ACK, seq: 1001 }]);
          await floodTheVersionProbe(bin, "tshark", "TShark (Wireshark) 4.4.0 stand-in");
          const result = await exec(CONNS, [], { capture: "inputs/capture.pcap" }, cwd, bin, { STUB_DIR: dir, CUT_FLOOD: flood }, host);
          assert.equal(result.code, 0, result.stderr + result.stdout);
          const out = JSON.parse(result.stdout);
          assert.equal(out.status, "partial", `${out.status_basis}`);
          assert.equal(out.ok, false);
          const said = JSON.stringify([out.status_basis, out.problems]);
          assert.match(said, /a process that held a program's pipe after the program ended went on writing: the tool read no more than 1048576 bytes of it/);
          assert.match(said, /tshark's version line/);
          assert.match(JSON.stringify(out.program_group.notes), /went on writing/);
          if (host === "linux") {
            assert.ok(out.program_group.left_behind >= 1, JSON.stringify(out.program_group));
            for (const pid of await pids(cwd)) assert.equal(alive(pid), false, `flooder ${pid} is gone`);
          } else {
            assert.equal(out.program_group.left_behind, 0, "nothing was found: the cut alone makes it partial");
          }
        } finally {
          await reap(cwd);
        }
      });
    });
  }
}

test("conn_series: a conn.log runs no program, so a flooder that nothing started changes nothing: the answer is complete (no cut)", async () => {
  await withCwd(async (cwd, bin) => {
    const dir = await setupCapture(cwd, bin, [{ t: T0, src: C, dst: S, sport: 50000, dport: 443, proto: "tcp", flags: TCP.SYN, seq: 1000 }]);
    await floodTheVersionProbe(bin, "tshark", "TShark (Wireshark) 4.4.0 stand-in");
    await put(cwd, "inputs/conn.log", tsv([{ ts: T0, uid: "CAAA" }]));
    const result = await exec(CONNS, [], { conn_log: "inputs/conn.log" }, cwd, bin, { STUB_DIR: dir, CUT_FLOOD: "setsidyes" }, "refused");
    const out = JSON.parse(result.stdout);
    assert.equal(out.status, "complete", out.status_basis);
    assert.equal(out.program_group.left_behind, 0);
    assert.deepEqual(await pids(cwd), [], "the stand-in was never started");
  });
});
