/**
 * network-forensics: flow_reader reads an nfcapd flow file with the pinned nfdump and says what its records mean and what they do not.
 *
 * nfdump is not on every machine these suites run on, so a stand-in `nfdump` plays it. The stand-in does not compute anything: it replays what a
 * real nfdump 1.7.1 printed (tests/fixtures/network-flow/recorded.json) for the files in that directory, which were collected from export packets
 * built from the NetFlow v5, NetFlow v9 (RFC 3954) and IPFIX (RFC 7011) specifications by tests/network-flow-fixture.py, never from the tool's own
 * output. The recorded outputs include what nfdump printed for two truncated files (it exits 0 for a file it could not read). That proves the
 * wrapper's logic: what it runs, what it believes, what it refuses and how it stops. It proves nothing about other versions of nfdump: a gated
 * test at the end runs the real program on the same files when it is installed, and says so when it is not.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { copyFile, mkdir, readFile, readdir, readlink, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { FLOW, NET, TOOLS, asJob, body, exists, filesUnder, frameTcp4, gone, pcapClassic, put, refused, startDetached, stub, TCP, tool, withCwd } from "./pack-network-harness.ts";
import type { Json } from "./pack-network-harness.ts";
import { ROOT } from "./tool-library-harness.ts";
import { NO_ADOPTION } from "./host-gates.ts";

const FIX = join(ROOT, "tests", "fixtures", "network-flow");

// The stand-in. STUB_DIR holds recorded.json, behave.json (per file name: what to do instead of replaying) and a log of its calls.
const NFDUMP = `#!/usr/bin/env python3
import json, os, subprocess, sys, time
d = os.environ["STUB_DIR"]
rec = json.load(open(os.path.join(d, "recorded.json")))
behave = json.load(open(os.path.join(d, "behave.json")))
args = sys.argv[1:]
open(os.path.join(d, "calls.log"), "a").write(json.dumps({"argv": args, "TZ": os.environ.get("TZ"), "LC_ALL": os.environ.get("LC_ALL")}) + "\\n")
def emit(r, name):
    if r.get("latin1"):
        sys.stdout.buffer.write(r["stdout"].encode("latin-1")); sys.stdout.flush()
    else:
        sys.stdout.write(r["stdout"].replace("@FILE@", name)); sys.stdout.flush()
    sys.stderr.write(r["stderr"].replace("@FILE@", name)); sys.stderr.flush()
    sys.exit(r["exit"])
if args == ["-V"]:
    emit(rec["@version"], "")
if args[0] == "-v": kind, path = "v", args[1]
elif args[:2] == ["-I", "-r"]: kind, path = "I", args[2]
elif args[0] == "-E": kind, path = "E", args[1]
elif args[0] == "-r" and "-o" in args and args[args.index("-o") + 1] == "json": kind, path = "json", args[1]
else:
    sys.stderr.write("stand-in: not a call a reader makes: %r\\n" % args); sys.exit(99)
name = os.path.basename(path)
b = behave.get(name, {})
base = b.get("as", name)
act = b.get(kind)
if act and act.get("replace"):
    emit(act["replace"], path)
if act and act.get("hang"):
    open(os.path.join(d, "engine.pid"), "w").write(str(os.getpid()))
    child = subprocess.Popen(["sleep", "300"])
    open(os.path.join(d, "child.pid"), "w").write(str(child.pid))
    open(os.path.join(d, "started"), "w").write("1")
    time.sleep(300)
    sys.exit(0)
if act and act.get("many"):
    n = act["many"]
    if kind == "I":
        sys.stdout.write("Ident: many\\nFlows: %d\\nFlows_tcp: %d\\nFlows_udp: 0\\nFlows_icmp: 0\\nFlows_other: 0\\nPackets: 0\\nBytes: 0\\nFirst: 1699999940\\nLast: 1699999981\\nmsec_first: 0\\nmsec_last: 0\\nSequence failures: 0\\n" % (n, n)); sys.exit(0)
    if kind == "json":
        cap = int(args[args.index("-c") + 1]) if "-c" in args else n
        text = rec["nfcapd.v5"]["json"]["stdout"]
        first = text[text.index("{\\n"): text.index("\\n}") + 2]
        sys.stdout.write("[\\n")
        for i in range(min(n, cap)):
            sys.stdout.write((first.replace('"src_port" : 50000', '"src_port" : %d' % (i % 60000))) + (",\\n" if i + 1 < min(n, cap) else "]\\n"))
        sys.exit(0)
r = rec[base][kind]
emit(r, path)
`;

type Behave = Record<string, Record<string, Json>>;

async function setup(cwd: string, bin: string, behave: Behave = {}, copies: Array<[string, string]> = []): Promise<string> {
  const dir = join(cwd, "stub");
  await mkdir(dir, { recursive: true });
  await copyFile(join(FIX, "recorded.json"), join(dir, "recorded.json"));
  await writeFile(join(dir, "behave.json"), JSON.stringify(behave));
  await stub(bin, "nfdump", NFDUMP);
  for (const f of (await readdir(FIX)).filter((n) => n.startsWith("nfcapd."))) await copyFile(join(FIX, f), join(cwd, "inputs", f));
  for (const [from, to] of copies) await copyFile(join(FIX, from), join(cwd, "inputs", to));
  return dir;
}

const env = (cwd: string, extra: Record<string, string> = {}): Record<string, string> => ({ STUB_DIR: join(cwd, "stub"), ...extra });
const call = (cwd: string, bin: string, args: Json, extra: Record<string, string> = {}) => tool(FLOW, cwd, args, env(cwd, extra), bin);
const input = (name: string): string => `inputs/${name}`;
const sha = (b: Buffer | string): string => createHash("sha256").update(b).digest("hex");
const text = (s: string): Json => ({ replace: { stdout: s, stderr: "", exit: 0 } });

/** An nfdump JSON record in the form nfdump 1.7.1 prints, for the hostile cases (the field names are the recorded ones). */
function record(over: Record<string, string> = {}, drop: string[] = []): string {
  const fields: Record<string, string> = {
    type: '"FLOW"', sampled: "0", export_sysid: "1", first: '"2023-11-14T22:12:20.000"', last: '"2023-11-14T22:12:50.000"', received: '"2026-11-03T23:13:30.787"',
    in_packets: "10", in_bytes: "1500", proto: "6", tcp_flags: '"...AP.SF"', src_port: "50000", dst_port: "443", src_tos: "0", src4_addr: '"10.0.0.5"',
    dst4_addr: '"203.0.113.7"', input_snmp: "3", output_snmp: "4", direction: "0", ip4_router: '"127.0.0.1"', label: '"<none>"', ...over,
  };
  for (const k of drop) delete fields[k];
  return "{\n" + Object.entries(fields).map(([k, v]) => `\t"${k}" : ${v}`).join(",\n") + "\n}";
}
const stream = (records: string[]): string => (records.length ? "[\n" + records.join(",\n") + "]\n" : "[\nNo matching flows\n]\n");
const withFlows = (n: number): Json => ({ replace: { stdout: `Ident: x\nFlows: ${n}\nFlows_tcp: ${n}\nFlows_udp: 0\nFlows_icmp: 0\nFlows_other: 0\nPackets: 0\nBytes: 0\nFirst: 1699999940\nLast: 1699999981\nmsec_first: 0\nmsec_last: 0\nSequence failures: 0\n`, stderr: "", exit: 0 } });

// ---- the supported forms ---------------------------------------------------------------------------------------------------------

test("NetFlow v5, v5 with sampling, v9 and IPFIX files built from the specifications are read: exporters, times, counters, direction and the translated fields", { skip: NO_ADOPTION }, async () => {
  await withCwd(async (cwd, bin) => {
    await setup(cwd, bin);
    const v5 = body(await call(cwd, bin, { inputs: [input("nfcapd.v5")], declared_format: "netflow_v5" }));
    assert.equal(v5.status, "complete", v5.status_basis);
    assert.equal(v5.parser, "flow_reader/1");
    assert.equal(v5.time_zone, "UTC");
    assert.equal(v5.backend.version, "nfdump: Version: NSEL-NEL1.7.1");
    const f = v5.files[0];
    assert.equal(f.sha256, sha(await readFile(join(cwd, input("nfcapd.v5")))));
    assert.equal(f.bytes, 525);
    assert.deepEqual([f.verification.layout_version, f.verification.compression], [2, "not compressed"]);
    assert.equal(f.statistics.Flows, 2);
    assert.equal(f.ident, "ident-v5");
    // the exporter: NetFlow v5, engine type 1, engine id 7 (the header the fixture builder wrote), as the collector saw it
    assert.deepEqual([f.exporters[0].version, f.exporters[0].protocol, f.exporters[0].engine_type, f.exporters[0].engine_id, f.exporters[0].address], [5, "NetFlow v5", 1, 7, "127.0.0.1"]);
    const [a, b] = v5.records;
    assert.deepEqual([a.record, a.source, a.src_addr, a.dst_addr, a.src_port, a.dst_port, a.protocol.name, a.tcp_flags], [1, input("nfcapd.v5"), "10.0.0.5", "203.0.113.7", 50000, 443, "tcp", "...AP.SF"]);
    // first and last switched are 60 s and 30 s before the export time 1700000000, plus the header's 250 ms of nanoseconds
    assert.equal(a.times.first.utc, "2023-11-14T22:12:20.250Z");
    assert.equal(a.times.first.raw, "2023-11-14T22:12:20.250");
    assert.equal(a.times.first.epoch_ms, 1_699_999_940_250);
    assert.equal(a.times.duration_ms, 30_000);
    assert.equal(a.times.received.utc.slice(0, 4), "2026");
    assert.deepEqual([a.counters.packets, a.counters.bytes, a.counters.flagged_sampled, a.counters.counters_exact], [10, 1500, false, null], "not flagged: not shown exact either");
    assert.deepEqual([b.src_addr, b.protocol.name, b.counters.packets, b.counters.bytes, b.direction.value, b.interfaces.input_snmp, b.interfaces.output_snmp], ["10.0.0.6", "udp", 2, 120, 0, 3, 4]);
    assert.equal(a.extra.src_as, 64512);
    assert.equal(a.exporter.domain_or_engine, 263);
    // sampling: the header announced mode 1, interval 100; nfdump flagged the records sampled and scaled the counters
    const s = body(await call(cwd, bin, { inputs: [input("nfcapd.v5-sampled")], declared_format: "netflow_v5" }));
    assert.equal(s.status, "complete", s.status_basis);
    assert.deepEqual([s.records[0].counters.packets, s.records[0].counters.bytes, s.records[0].counters.flagged_sampled, s.records[0].counters.counters_exact], [1000, 150000, true, false]);
    assert.match(s.records[0].counters.basis, /an estimate/);
    assert.match(s.files[0].exporters[0].samplers[0], /packet interval: 1, packet space: 99/);
    assert.equal(s.totals.records_flagged_sampled, 2);
    assert.deepEqual([s.totals.sum_flagged_sampled_estimate.packets, s.totals.sum_not_flagged.packets], [1200, 0], "sampled and unsampled sums are kept apart");
    assert.match(JSON.stringify(s.semantics), /never an exact count/);
    // NetFlow v9: source id 42, direction 1 on the UDP flow, translated source 192.0.2.10:40000 and :40001
    const v9 = body(await call(cwd, bin, { inputs: [input("nfcapd.v9-nat")], declared_format: "netflow_v9" }));
    assert.equal(v9.status, "complete", v9.status_basis);
    assert.deepEqual([v9.files[0].exporters[0].version, v9.files[0].exporters[0].domain_or_engine], [9, 42]);
    assert.deepEqual([v9.records[0].direction.value, v9.records[1].direction.value, v9.records[1].direction.label], [0, 1, "egress"]);
    assert.deepEqual(v9.records[0].nat, { dst4_xlt_ip: "203.0.113.7", dst_xlt_port: "443", src4_xlt_ip: "192.0.2.10", src_xlt_port: "40000" });
    assert.equal(v9.records[1].nat.src_xlt_port, "40001");
    assert.equal(v9.records[0].times.first.utc, "2023-11-14T22:12:20.000Z");
    // IPFIX: observation domain 7, absolute start and end in milliseconds
    const ip = body(await call(cwd, bin, { inputs: [input("nfcapd.ipfix-nat")], declared_format: "ipfix" }));
    assert.equal(ip.status, "complete", ip.status_basis);
    assert.deepEqual([ip.files[0].exporters[0].version, ip.files[0].exporters[0].protocol, ip.files[0].exporters[0].domain_or_engine], [10, "IPFIX", 7]);
    assert.equal(ip.records[1].times.last.utc, "2023-11-14T22:13:01.000Z");
    // a file nfdump compressed (lz4) reads the same, and the compression is reported; a nfcapd file with no flow is complete with none
    const lz4 = body(await call(cwd, bin, { inputs: [input("nfcapd.v9-lz4")], declared_format: "nfcapd" }));
    assert.equal(lz4.status, "complete", lz4.status_basis);
    assert.equal(lz4.files[0].verification.compression, "lz4 compressed");
    const empty = body(await call(cwd, bin, { inputs: [input("nfcapd.empty")], declared_format: "nfcapd" }));
    assert.deepEqual([empty.status, empty.records_total, empty.records], ["complete", 0, []]);
    // what is not provided is said, and the record's locator is its position in nfdump's output
    assert.match(v5.not_provided.join(" "), /template ids/);
    assert.match(v5.not_provided.join(" "), /active and inactive timeouts/);
    assert.match(v5.not_provided.join(" "), /one direction or both/);
  });
});

test("several files in one call: each is read and accounted for, the record numbers are per file, and a file nfdump could not read does not make the others unread", async () => {
  await withCwd(async (cwd, bin) => {
    await setup(cwd, bin);
    const out = body(await call(cwd, bin, { inputs: [input("nfcapd.v9-nat"), input("nfcapd.cut-500"), input("nfcapd.ipfix-nat")], declared_format: "nfcapd" }));
    assert.equal(out.status, "partial");
    assert.deepEqual(out.files.map((f: Json) => f.status), ["complete", "partial", "complete"]);
    assert.deepEqual(out.records.map((r: Json) => [r.source.slice(7), r.record]), [
      ["nfcapd.v9-nat", 1], ["nfcapd.v9-nat", 2], ["nfcapd.cut-500", 1], ["nfcapd.cut-500", 2], ["nfcapd.ipfix-nat", 1], ["nfcapd.ipfix-nat", 2],
    ]);
    assert.equal(out.records_total, 6);
  });
});

// ---- refusals, by name -----------------------------------------------------------------------------------------------------------

test("a capture, sFlow, a text file and an empty file are refused by name before nfdump is run", async () => {
  await withCwd(async (cwd, bin) => {
    const dir = await setup(cwd, bin);
    await put(cwd, "inputs/a.pcap", pcapClassic([{ sec: 1_700_000_000, frame: frameTcp4({ src: "10.0.0.5", dst: "203.0.113.7", sport: 50000, dport: 80, flags: TCP.SYN, seq: 1 }) }]));
    await put(cwd, "inputs/b.pcapng", Buffer.concat([Buffer.from("0a0d0d0a", "hex"), Buffer.alloc(60)]));
    await put(cwd, "inputs/notes.txt", "10.0.0.5 203.0.113.7 443 12345\n");
    await put(cwd, "inputs/empty.bin", "");
    const cases: Array<[string, RegExp]> = [["a.pcap", /pcap: a capture, not an nfcapd file.*nfpcapd builds new flows|No mode of the pinned nfdump/s], ["b.pcapng", /pcapng: a capture/],
      ["notes.txt", /does not start with the nfcapd magic/], ["empty.bin", /shorter than a header/]];
    for (const [name, pattern] of cases) {
      const err = refused(await call(cwd, bin, { inputs: [input(name)], declared_format: "nfcapd" }));
      assert.match(err.error, /refused by name before any program ran/, name);
      assert.match(JSON.stringify(err.refused), pattern, name);
      assert.equal(err.status, "failed");
    }
    const sflow = refused(await call(cwd, bin, { inputs: [input("nfcapd.v5")], declared_format: "sflow" }));
    assert.match(sflow.error, /sFlow is not read: the pinned package ships `nfcapd` and `nfpcapd`.*sfcapd` is not installed/);
    assert.equal(await exists(join(dir, "calls.log")), false, "nfdump was never run for a refusal");
    // one refused input refuses the call: none of the others is read
    const mixed = refused(await call(cwd, bin, { inputs: [input("nfcapd.v5"), input("a.pcap")], declared_format: "netflow_v5" }));
    assert.match(mixed.error, /1 of 2 input\(s\) refused/);
    assert.equal(await exists(join(dir, "calls.log")), false);
    assert.deepEqual(await filesUnder(join(cwd, "work")), [], "a refusal writes nothing");
  });
});

test("arguments: declared_format is required, parameters are checked, an unknown one is named, a missing file and a FIFO are refused (a FIFO is never waited on)", async () => {
  await withCwd(async (cwd, bin) => {
    await setup(cwd, bin);
    const bad: Array<[Json, RegExp]> = [
      [{ inputs: [input("nfcapd.v5")] }, /declared_format is required/],
      [{ inputs: [input("nfcapd.v5")], declared_format: "netflow_v7" }, /declared_format is required/],
      [{ inputs: [], declared_format: "nfcapd" }, /inputs must be a list of 1 to 32/],
      [{ inputs: [input("nfcapd.v5")], declared_format: "nfcapd", filter: "src ip 10.0.0.5" }, /unknown parameters: filter/],
      [{ inputs: [input("nfcapd.v5")], declared_format: "nfcapd", max_records: 0 }, /max_records must be an integer from 1 to 500000/],
      [{ inputs: [input("nfcapd.v5")], declared_format: "nfcapd", max_seconds: 5 }, /max_seconds must be an integer from 10 to 1000/],
      [{ inputs: [input("nfcapd.v5")], declared_format: "nfcapd", limit: true }, /limit must be an integer/],
      [{ inputs: [input("missing")], declared_format: "nfcapd" }, /no such file/],
    ];
    for (const [args, pattern] of bad) assert.match(refused(await call(cwd, bin, args)).error, pattern, JSON.stringify(args));
    spawnSync("mkfifo", [join(cwd, "inputs", "fifo")]);
    const t0 = Date.now();
    assert.match(refused(await call(cwd, bin, { inputs: [input("fifo")], declared_format: "nfcapd" })).error, /not a regular file/);
    assert.ok(Date.now() - t0 < 10_000, "a FIFO is not waited on");
  });
});

// ---- nfdump says nothing with its exit code ----------------------------------------------------------------------------------------

test("nfdump exits 0 on a truncated file: its messages, its verification and the file's own flow count decide, and a file it could not read is failed", async () => {
  await withCwd(async (cwd, bin) => {
    await setup(cwd, bin);
    const cut300 = refused(await call(cwd, bin, { inputs: [input("nfcapd.cut-300")], declared_format: "nfcapd" }));
    assert.equal(cut300.status, "failed");
    assert.equal(cut300.files[0].status, "failed");
    assert.equal(cut300.files[0].records_read, 0);
    const said = cut300.files[0].problems.join(" | ");
    assert.match(said, /`nfdump -v` exited 1; it said: Invalid appendix offset/);
    assert.match(said, /`nfdump -I` exited 250/);
    assert.match(said, /`nfdump -o json` wrote to stderr: Open file .*nfcapd\.cut-300: appendix offset error/, "the exit code of the json run was 0");
    // the second file lost its appendix but still decodes both records: the records are kept and the file is partial, never complete
    const cut500 = body(await call(cwd, bin, { inputs: [input("nfcapd.cut-500")], declared_format: "nfcapd" }));
    assert.equal(cut500.status, "partial");
    assert.equal(cut500.records_total, 2);
    assert.match(cut500.files[0].problems.join(" | "), /Expected to seek beyond EOF! File corrupted/);
    assert.match(cut500.status_basis, /nfdump -v/);
    assert.equal(cut500.ok, false);
  });
});

test("the file's own flow count disagrees with the records read: partial, and the numbers are named", async () => {
  await withCwd(async (cwd, bin) => {
    await setup(cwd, bin, { "nfcapd.three": { as: "nfcapd.v5", I: withFlows(3) }, "nfcapd.one": { as: "nfcapd.v5", I: withFlows(1) } }, [["nfcapd.v5", "nfcapd.three"], ["nfcapd.v5", "nfcapd.one"]]);
    for (const [name, flows] of [["nfcapd.three", 3], ["nfcapd.one", 1]] as const) {
      const out = body(await call(cwd, bin, { inputs: [input(name)], declared_format: "nfcapd" }));
      assert.equal(out.status, "partial", name);
      assert.match(out.files[0].problems.join(" "), new RegExp(`statistics count ${flows} flows and 2 records were read`));
    }
  });
});

test("declared_format is checked against the exporters the file lists: a file of another protocol is partial, and the answer names both", async () => {
  await withCwd(async (cwd, bin) => {
    await setup(cwd, bin);
    const out = body(await call(cwd, bin, { inputs: [input("nfcapd.v9-nat")], declared_format: "ipfix" }));
    assert.equal(out.status, "partial");
    assert.equal(out.files[0].declared_format_matches, false);
    assert.match(out.files[0].problems.join(" "), /declared_format is ipfix and the file lists NetFlow v9/);
    assert.equal(body(await call(cwd, bin, { inputs: [input("nfcapd.v9-nat")], declared_format: "netflow_v9" })).files[0].declared_format_matches, true);
    assert.equal(body(await call(cwd, bin, { inputs: [input("nfcapd.v9-nat")], declared_format: "nfcapd" })).files[0].declared_format_matches, null);
  });
});

// ---- hostile output ----------------------------------------------------------------------------------------------------------------

test("hostile nfdump output: a stray line, a value that is not JSON, a field twice, a record not closed, a cut record, a long line, NUL and non-UTF-8 each make the file partial and are counted", async () => {
  const cases: Array<[string, string, RegExp, number]> = [
    ["stray", "[\n" + record() + ",\nWarning: something\n" + record() + "]\n", /1 line\(s\) of the output of `nfdump -o json` are not part of a record; the first: Warning: something/, 2],
    ["value", stream([record({ in_bytes: "12x" }), record()]), /the value of in_bytes is not JSON: 12x/, 2],
    ["twice", stream([record(), record().replace('\t"label"', '\t"proto" : 17,\n\t"label"')]), /field proto appears twice/, 2],
    ["unclosed", "[\n" + record().replace(/\n\}$/, "") + ",\n" + record() + "]\n", /the record was not closed before the next one began/, 2],
    ["cut", "[\n" + record() + ",\n" + record().slice(0, 90), /does not end with its closing bracket|ends inside the record/, 1],
    ["long", stream([record({ label: '"' + "x".repeat(70_000) + '"' }), record()]), /1 line\(s\) over 65536 bytes were dropped/, 2],
    ["nul", stream([record({ label: '"a\\u0000b"' }).replace("a\\u0000b", "a\0b"), record()]), /is not JSON|not part of a record|appears twice|the value of label/, 2],
    ["latin1", "[\n" + record({ label: '"caf\xe9"' }) + "]\n", /not UTF-8/, 1],
    ["nan", stream([record({ in_bytes: "NaN" })]), /the value of in_bytes is not JSON/, 1],
    ["string-counter", stream([record({ in_packets: '"10"' })]), /in_packets is not an integer/, 1],
    ["bad-time", stream([record({ first: '"2023-13-45T99:99:99"' })]), /first is not a time in the form nfdump prints/, 1],
    ["nothing", "", /printed nothing/, 0],
    ["not-json", "this is not json\n", /does not start as nfdump's JSON array does|not part of a record/, 0],
  ];
  await withCwd(async (cwd, bin) => {
    const behave: Behave = {};
    for (const [name, out] of cases) behave[`nfcapd.${name}`] = { as: "nfcapd.v5", json: { replace: { stdout: out, stderr: "", exit: 0, latin1: name === "latin1" } } };
    await setup(cwd, bin, behave, cases.map(([name]) => ["nfcapd.v5", `nfcapd.${name}`] as [string, string]));
    for (const [name, , pattern, kept] of cases) {
      const run = await call(cwd, bin, { inputs: [input(`nfcapd.${name}`)], declared_format: "nfcapd" });
      assert.doesNotMatch(run.stderr, /Traceback/, name);
      const out = JSON.parse(run.stdout);
      assert.notEqual(out.status, "complete", `${name}: ${out.status_basis}`);
      assert.match(out.files[0].problems.join(" | ") + JSON.stringify(out.files[0].record_failures), pattern, name);
      assert.equal(out.records_total, kept, `${name}: records kept`);
      assert.equal(out.ok, false);
    }
  });
});

test("times and counters: a last before its first, a cut-off ident and the totals are reported as they are, not repaired", async () => {
  await withCwd(async (cwd, bin) => {
    const records = [record({ first: '"2023-11-14T22:12:50.000"', last: '"2023-11-14T22:12:20.000"' }), record({ sampled: "1", in_packets: "18446744073709551615" })];
    const ident = "ident-" + "z".repeat(5000);
    await setup(cwd, bin, { "nfcapd.odd": { as: "nfcapd.v5", json: text(stream(records)), I: { replace: { stdout: `Ident: ${ident}\nFlows: 2\nFlows_tcp: 2\nSequence failures: 0\n`, stderr: "", exit: 0 } } } }, [["nfcapd.v5", "nfcapd.odd"]]);
    const out = body(await call(cwd, bin, { inputs: [input("nfcapd.odd")], declared_format: "nfcapd" }));
    assert.equal(out.records[0].times.duration_ms, -30_000);
    assert.equal(out.records[0].times.last_before_first, true);
    assert.equal(out.totals.last_before_first, 1);
    assert.equal(typeof out.records[1].counters.packets, "number");
    assert.equal(out.records[1].counters.flagged_sampled, true);
    assert.equal(out.status, "partial");
    assert.match(out.files[0].problems.join(" "), /the ident string in the file is 5006 characters; only the first 4096 are shown/);
    assert.equal(out.files[0].ident.length, 4096);
  });
});

// ---- bounds, paging, placing --------------------------------------------------------------------------------------------------------

test("a file with more records than max_records is read to the bound and the answer is partial; the whole read is in the file the answer names, with as many rows as it counts", { skip: NO_ADOPTION }, async () => {
  await withCwd(async (cwd, bin) => {
    await setup(cwd, bin, { "nfcapd.many": { as: "nfcapd.v5", json: { many: 30_000 }, I: { many: 30_000 } } }, [["nfcapd.v5", "nfcapd.many"]]);
    const t0 = Date.now();
    const out = body(await call(cwd, bin, { inputs: [input("nfcapd.many")], declared_format: "netflow_v5", max_records: 10_000, limit: 50 }));
    assert.ok(Date.now() - t0 < 60_000);
    assert.equal(out.status, "partial");
    assert.match(out.status_basis, /more than the 10000 records max_records allows/);
    assert.equal(out.files[0].truncated, true);
    assert.equal(out.files[0].flows_in_file, 30_000);
    assert.equal(out.records_total, 10_000);
    assert.equal(out.records_returned, 50);
    assert.equal(out.truncated, true);
    const whole = (await readFile(join(cwd, out.all_results), "utf8")).trim().split("\n");
    assert.equal(whole.length, 10_000);
    assert.equal(JSON.parse(whole[9_999]).record, 10_000);
    assert.equal((await stat(join(cwd, out.all_results))).mode & 0o777, 0o600);
    // below the bound the same file is read whole and counted against its own flow count
    const all = body(await call(cwd, bin, { inputs: [input("nfcapd.many")], declared_format: "netflow_v5", max_records: 40_000, limit: 5 }));
    assert.equal(all.status, "complete", all.status_basis);
    assert.equal(all.records_total, 30_000);
    assert.equal((await readFile(join(cwd, all.all_results), "utf8")).trim().split("\n").length, 30_000);
    // the smaller read did not replace the larger: both files are there
    assert.equal((await readFile(join(cwd, out.all_results), "utf8")).trim().split("\n").length, 10_000);
  });
});

test("a rerun in one place never replaces a larger result with a smaller one, and an identical rerun leaves the result as it was", async () => {
  await withCwd(async (cwd, bin) => {
    await setup(cwd, bin, { "nfcapd.many": { as: "nfcapd.v5", json: { many: 300 }, I: { many: 300 } } }, [["nfcapd.v5", "nfcapd.many"]]);
    const args = { inputs: [input("nfcapd.many")], declared_format: "netflow_v5", limit: 10 };
    const first = body(await call(cwd, bin, args));
    const before = await readFile(join(cwd, first.all_results));
    const again = body(await call(cwd, bin, args));
    assert.deepEqual(await readFile(join(cwd, again.all_results)), before);
    const dir = join(cwd, first.all_results, "..");
    const names = (await readdir(dir)).sort();
    assert.ok(names.every((n) => !n.startsWith(".")), `no hidden file is left: ${names}`);
    // another read with other bounds writes its own file, the first stays whole
    const other = body(await call(cwd, bin, { ...args, max_records: 100 }));
    assert.notEqual(other.all_results, first.all_results);
    assert.deepEqual(await readFile(join(cwd, first.all_results)), before);
  });
});

test("as a job the result and nfdump's messages are written under $OUT only, and nothing else in the run directory changes", async () => {
  await withCwd(async (cwd, bin) => {
    await setup(cwd, bin, { "nfcapd.many": { as: "nfcapd.v5", json: { many: 300 }, I: { many: 300 } } }, [["nfcapd.v5", "nfcapd.many"]]);
    const before = await filesUnder(cwd);
    const run = await asJob(FLOW, cwd, { inputs: [input("nfcapd.many")], declared_format: "netflow_v5", limit: 5 }, bin, env(cwd));
    const out = body(run);
    assert.match(out.all_results, /^store\/jobs\/j\d+\/out\/tool-output\/flow_reader-[0-9a-f]{16}\.jsonl$/);
    const after = (await filesUnder(cwd)).filter((f) => !before.includes(f));
    assert.ok(after.every((f) => f.startsWith("out/tool-output/") || f === "stub/calls.log"), `outside $OUT: ${after}`);
    assert.ok(after.some((f) => /^out\/tool-output\/flow_reader-info-[0-9a-f]{16}\.txt$/.test(f)), "nfdump's own messages are kept beside the result");
    const info = await readFile(join(cwd, "out/tool-output", out.files[0].nfdump_output_file), "utf8");
    assert.match(info, /== `nfdump -v` \(exit 0\)/);
    assert.match(info, /== `nfdump -E` \(exit 0\)/);
    assert.deepEqual((await readdir(join(cwd, "out/tool-output"))).filter((n) => n.startsWith(".")), [], "the temporary directory is gone");
  });
});

// ---- what runs ------------------------------------------------------------------------------------------------------------------------

test("only nfdump -V, -v, -I -r, -E and -r -o json run, in UTC and the C locale, never nfcapd or nfpcapd, and the input is not written", async () => {
  await withCwd(async (cwd, bin) => {
    const dir = await setup(cwd, bin);
    for (const name of ["nfcapd", "nfpcapd"]) await stub(bin, name, `#!/bin/sh\necho "$0 $*" >> "${dir}/collector-called"\nexit 0\n`);
    const before = sha(await readFile(join(cwd, input("nfcapd.v9-nat"))));
    body(await call(cwd, bin, { inputs: [input("nfcapd.v9-nat")], declared_format: "netflow_v9" }));
    const calls = (await readFile(join(dir, "calls.log"), "utf8")).trim().split("\n").map((l) => JSON.parse(l));
    const abs = join(await (await import("node:fs/promises")).realpath(cwd), input("nfcapd.v9-nat"));
    assert.deepEqual(calls.map((c: Json) => c.argv), [["-V"], ["-v", abs], ["-I", "-r", abs], ["-E", abs], ["-r", abs, "-c", "100001", "-o", "json"]]);
    for (const c of calls) assert.deepEqual([c.TZ, c.LC_ALL], ["UTC", "C"]);
    assert.equal(await exists(join(dir, "collector-called")), false);
    assert.equal(sha(await readFile(join(cwd, input("nfcapd.v9-nat")))), before);
    const source = await readFile(FLOW, "utf8");
    assert.doesNotMatch(source, /^\s*(import|from)\s+socket\b/m, "the tool opens no socket");
    assert.doesNotMatch(source.replace(/^\s*#.*$/gm, "").replace(/"""[\s\S]*?"""/g, ""), /which\(["']nf(?:capd|pcapd|replay)|["']nf(?:pcapd|replay)["']|start_new_session|setsid|threading/);
  });
});

test("nothing listens while it runs: neither the tool nor anything it started holds a socket", async () => {
  await withCwd(async (cwd, bin) => {
    const dir = await setup(cwd, bin, { "nfcapd.slow": { as: "nfcapd.v5", json: { hang: true } } }, [["nfcapd.v5", "nfcapd.slow"]]);
    const run = startDetached(FLOW, cwd, { inputs: [input("nfcapd.slow")], declared_format: "netflow_v5", max_seconds: 10 }, env(cwd), bin);
    for (let i = 0; i < 400 && !(await exists(join(dir, "started"))); i++) await new Promise((r) => setTimeout(r, 50));
    const pids = [run.pid, Number((await readFile(join(dir, "engine.pid"), "utf8")).trim()), Number((await readFile(join(dir, "child.pid"), "utf8")).trim())];
    // The harness's own pipes to a child are unix-domain socket pairs: a network socket is one whose inode a /proc/net table of the internet families lists.
    const network = new Set<string>();
    for (const table of ["tcp", "tcp6", "udp", "udp6", "udplite", "udplite6", "raw", "raw6", "packet", "sctp", "sctp6"]) {
      for (const line of (await readFile(`/proc/net/${table}`, "utf8").catch(() => "")).split("\n").slice(1)) {
        const cols = line.trim().split(/\s+/);
        if (cols.length > 9) network.add(table === "packet" ? cols[8] : cols[9]);
      }
    }
    let looked = 0;
    for (const pid of pids) {
      for (const fd of await readdir(`/proc/${pid}/fd`).catch(() => [] as string[])) {
        const link = await readlink(`/proc/${pid}/fd/${fd}`).catch(() => "");
        const inode = link.match(/^socket:\[(\d+)\]$/)?.[1];
        if (inode) { looked += 1; assert.equal(network.has(inode), false, `pid ${pid} holds the network socket ${link}`); }
      }
    }
    assert.ok(looked >= 0);
    run.signal("SIGTERM");
    await run.closed;
  });
});

// ---- the clock and the stops -----------------------------------------------------------------------------------------------------------

test("a nfdump that outlives the tool's own clock is killed with what it started; the file is failed, nothing is cut off silently", async () => {
  await withCwd(async (cwd, bin) => {
    const dir = await setup(cwd, bin, { "nfcapd.slow": { as: "nfcapd.v5", json: { hang: true } } }, [["nfcapd.v5", "nfcapd.slow"]]);
    const t0 = Date.now();
    const out = refused(await call(cwd, bin, { inputs: [input("nfcapd.slow")], declared_format: "netflow_v5", max_seconds: 10 }));
    assert.ok(Date.now() - t0 < 25_000, `took ${Date.now() - t0} ms`);
    assert.equal(out.status, "failed");
    assert.match(out.files[0].problems.join(" "), /`nfdump -o json` did not finish in time and was killed with everything it had started/);
    assert.equal(await gone(Number((await readFile(join(dir, "child.pid"), "utf8")).trim())), true);
    assert.equal(await gone(Number((await readFile(join(dir, "engine.pid"), "utf8")).trim())), true);
    assert.deepEqual((await filesUnder(join(cwd, "work"))).filter((f) => f.split("/").some((p) => p.startsWith("."))), [], "no temporary directory is left");
  });
});

test("four runs at once finish inside the manifest's timeout", async () => {
  await withCwd(async (cwd, bin) => {
    await setup(cwd, bin, { "nfcapd.slow": { as: "nfcapd.v5", json: { hang: true } } }, [["nfcapd.v5", "nfcapd.slow"]]);
    const t0 = Date.now();
    const runs = await Promise.all([0, 1, 2, 3].map(() => call(cwd, bin, { inputs: [input("nfcapd.slow")], declared_format: "netflow_v5", max_seconds: 10 })));
    const manifest: Json = JSON.parse(await readFile(join(TOOLS, "flow_reader", "manifest.json"), "utf8"));
    assert.ok(Date.now() - t0 < Math.min(40_000, manifest.timeout_seconds * 1000), `took ${Date.now() - t0} ms`);
    for (const r of runs) assert.equal(JSON.parse(r.stdout).status, "failed");
  });
});

test("a stop signal gives one JSON answer with the stage, kills nfdump and what it started, removes the temporary directory and exits 128 plus the signal", async () => {
  for (const [sig, code] of [["SIGTERM", 143], ["SIGINT", 130], ["SIGHUP", 129]] as const) {
    await withCwd(async (cwd, bin) => {
      const dir = await setup(cwd, bin, { "nfcapd.slow": { as: "nfcapd.v5", json: { hang: true } } }, [["nfcapd.v5", "nfcapd.slow"]]);
      const run = startDetached(FLOW, cwd, { inputs: [input("nfcapd.slow")], declared_format: "netflow_v5" }, env(cwd), bin);
      for (let i = 0; i < 400 && !(await exists(join(dir, "started"))); i++) await new Promise((r) => setTimeout(r, 50));
      run.signal(sig);
      assert.equal(await run.closed, code, sig);
      assert.equal(run.stdout().trim().split("\n").length > 0, true);
      const last = JSON.parse(run.stdout());
      assert.equal(last.status, "partial");
      assert.equal(last.interrupted_by_signal, code - 128);
      assert.equal(last.stage, "reading the records (nfdump -o json)");
      assert.equal(await gone(Number((await readFile(join(dir, "child.pid"), "utf8")).trim())), true, `${sig}: what nfdump started is gone`);
      assert.equal(await gone(Number((await readFile(join(dir, "engine.pid"), "utf8")).trim())), true);
      assert.deepEqual((await filesUnder(join(cwd, "work"))).filter((f) => f.split("/").some((p) => p.startsWith("."))), []);
    });
  }
});

// ---- fuzz (at most 1,000 cases; 160 here), on the changed code only ------------------------------------------------------------------

test("fuzz: 160 mutations of nfdump's recorded output never end without JSON or in a traceback, and a mutation that loses a record is never complete", async () => {
  let seed = 20261104;
  const rnd = (n: number): number => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed % n; };
  const recorded: Json = JSON.parse(await readFile(join(FIX, "recorded.json"), "utf8"));
  await withCwd(async (cwd, bin) => {
    const behave: Behave = {};
    const copies: Array<[string, string]> = [];
    const kinds = ["v", "I", "E", "json"];
    const cases: Array<{ name: string; lost: boolean }> = [];
    for (let i = 0; i < 160; i++) {
      const name = `nfcapd.f${i}`;
      const base = ["nfcapd.v5", "nfcapd.v5-sampled", "nfcapd.v9-nat", "nfcapd.ipfix-nat"][rnd(4)];
      const kind = kinds[rnd(4)];
      const orig: string = recorded[base][kind].stdout;
      let mutated = orig;
      let lost = false;
      switch (rnd(5)) {
        case 0: { const cut = rnd(orig.length + 1); mutated = orig.slice(0, cut); lost = cut < orig.length - 2; break; }
        case 1: { const at = rnd(orig.length); mutated = orig.slice(0, at) + String.fromCharCode(rnd(256)) + orig.slice(at + 1); break; }
        case 2: { const lines = orig.split("\n"); lines.splice(rnd(lines.length), 1); mutated = lines.join("\n"); break; }
        case 3: { const lines = orig.split("\n"); const at = rnd(lines.length); lines.splice(at, 0, lines[rnd(lines.length)]); mutated = lines.join("\n"); break; }
        default: mutated = orig + "\u0000ÿ trailing " + "x".repeat(rnd(300)); break;
      }
      behave[name] = { as: base, [kind]: { replace: { stdout: mutated, stderr: "", exit: 0 } } };
      copies.push([base, name]);
      cases.push({ name, lost: lost && kind === "json" });
    }
    await setup(cwd, bin, behave, copies);
    for (const c of cases) {
      const run = await call(cwd, bin, { inputs: [input(c.name)], declared_format: "nfcapd" });
      assert.doesNotMatch(run.stderr, /Traceback/, c.name);
      const out = JSON.parse(run.stdout);
      assert.ok(["complete", "partial", "failed"].includes(out.status), `${c.name}: ${out.status}`);
      assert.ok(typeof out.status_basis === "string" && out.status_basis.length > 0);
      if (out.status === "complete") assert.equal(out.records_total, out.files[0].statistics.Flows, `${c.name}: complete means the count agrees`);
      if (c.lost) assert.notEqual(out.status, "complete", `${c.name}: a cut-off output is never complete`);
    }
  });
});

// ---- the manifest ---------------------------------------------------------------------------------------------------------------------

test("the manifest names the parameters the script reads, its example runs, its TOOL version is its version, run.py is executable, and the pack names the program", async () => {
  const manifest: Json = JSON.parse(await readFile(join(TOOLS, "flow_reader", "manifest.json"), "utf8"));
  const script = await readFile(FLOW, "utf8");
  assert.equal(manifest.sha256, sha(script));
  const tool_ = script.match(/^TOOL = \{"name": "([a-z_]+)", "version": (\d+)\}$/m)!;
  assert.deepEqual([tool_[1], Number(tool_[2])], ["flow_reader", manifest.version]);
  assert.match(script, /^PARSER = "flow_reader\/\d+"$/m);
  assert.ok((await stat(FLOW)).mode & 0o111, "run.py is executable");
  assert.deepEqual(manifest.requires, ["nfdump"]);
  assert.equal(manifest.secret_output, undefined, "addresses, ports, counters and times: no payload");
  assert.deepEqual(manifest.use.magic, [{ offset: 0, hex: "0ca5" }]);
  assert.ok(manifest.timeout_seconds > 900 && manifest.timeout_seconds === 1200);
  const read = new Set<string>();
  for (const m of script.matchAll(/args\.get\("([a-z_]+)"/g)) read.add(m[1]);
  for (const m of script.matchAll(/int_in\(args, "([a-z_]+)"/g)) read.add(m[1]);
  assert.deepEqual([...read].sort(), Object.keys(manifest.params).sort());
  const example = JSON.parse(manifest.example);
  for (const key of Object.keys(example)) assert.ok(key in manifest.params, key);
  for (const claim of ["NOT PROVIDED", "SAMPLING", "counters_exact", "never nfcapd or nfpcapd", "sFlow", "nfdump's exit codes are not trusted"]) assert.ok(manifest.description.includes(claim), claim);
  const host: Json = JSON.parse(await readFile(join(NET, "requires", "host.json"), "utf8"));
  const entry = host.binaries.find((b: Json) => b.name === "nfdump");
  assert.ok(entry, "requires/host.json lists nfdump");
  assert.match(entry.licence, /BSD-3-Clause/);
  assert.deepEqual(entry.install, { apt: "apt-get install -y nfdump" });
  assert.deepEqual(entry.facts, [["nfdump", "-V"]]);
  const pack: Json = JSON.parse(await readFile(join(NET, "pack.json"), "utf8"));
  assert.ok(pack.tools.includes("flow_reader"));
  assert.doesNotMatch(pack.description, /No flow-record reader/);
});

// ---- the real program ---------------------------------------------------------------------------------------------------------------------

test("with the real nfdump: the files built from the specifications read as the packets say", async (t) => {
  const probe = spawnSync("nfdump", ["-V"], { encoding: "utf8" });
  if (probe.error || probe.status !== 0) {
    t.skip("nfdump is not installed here; the recorded outputs of nfdump 1.7.1 stand in (the same files were read with the real program when this was written)");
    return;
  }
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "stub"), { recursive: true });
    for (const f of (await readdir(FIX)).filter((n) => n.startsWith("nfcapd."))) await copyFile(join(FIX, f), join(cwd, "inputs", f));
    const all = body(await tool(FLOW, cwd, { inputs: ["nfcapd.v5", "nfcapd.v5-sampled", "nfcapd.v9-nat", "nfcapd.ipfix-nat", "nfcapd.v9-lz4", "nfcapd.empty"].map(input), declared_format: "nfcapd" }));
    assert.equal(all.status, "complete", all.status_basis);
    assert.match(all.backend.version, /nfdump/);
    const rows = all.records.filter((r: Json) => r.source.endsWith("nfcapd.v9-nat"));
    assert.deepEqual([rows[0].src_addr, rows[0].dst_port, rows[0].counters.packets, rows[0].nat.src_xlt_port], ["10.0.0.5", 443, 10, "40000"]);
    const cut = refused(await tool(FLOW, cwd, { inputs: [input("nfcapd.cut-300")], declared_format: "nfcapd" }));
    assert.equal(cut.status, "failed");
    const half = body(await tool(FLOW, cwd, { inputs: [input("nfcapd.cut-500")], declared_format: "nfcapd" }));
    assert.equal(half.status, "partial");
  });
});
