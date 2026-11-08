/**
 * network-forensics: quic_inspect lists every QUIC datagram tshark dissects, with the decoding limits of each row, and models connections without taking a UDP tuple for a session.
 *
 * Wireshark is not on every machine these suites run on, so a stand-in `tshark` plays it: it prints what the documentation says tshark prints (`--version`,
 * `-G currentprefs`, `-G fields`, `-T fields` rows with `-E occurrence=a`) from a plan built here, together with the capture the plan describes (real
 * UDP datagrams whose first bytes are an unprotected QUIC long or short header: the header form, type, version and connection ids are not
 * header-protected, so a real tshark reads them without keys). That proves the wrapper: which fields it asks for, how it reads the lists of a coalesced
 * datagram, the attempt model (Retry, Version Negotiation, migration, unlinked short headers), what the answer prints, where the whole table goes, and how
 * the tool stops. It proves nothing about the real tshark's field values: one test runs the real program when it is installed and says so when it is not.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { mkdir, readFile, readdir, stat, writeFile } from "node:fs/promises";
import { basename, join } from "node:path";
import { test } from "node:test";
import { NET, QUICI, TOOLS, asJob, body, exists, filesUnder, frameUdp4, gone, pcapClassic, put, refused, startDetached, stub, tool, withCwd } from "./pack-network-harness.ts";
import type { Json } from "./pack-network-harness.ts";
import { CUT_FLOODERS, FEW, PY_LEAVE, alive, exec, floodTheVersionProbe, pids, reap, snapshot, sleep } from "./network-process-harness.ts";
import { NO_SETSID, NO_ADOPTION } from "./host-gates.ts";

const TSHARK = `#!/usr/bin/env python3
import json, os, re, sys, time
d = os.environ["STUB_DIR"]
args = sys.argv[1:]
open(os.path.join(d, "calls.log"), "a").write(json.dumps(args) + "\\n")
${PY_LEAVE}
mode = os.environ.get("STUB_MODE", "")
prefs = os.environ.get("STUB_PREFS", "tls")
missing = [m for m in os.environ.get("STUB_MISSING", "").split(",") if m]
NAMES = ["frame.number", "frame.time_epoch", "frame.interface_id", "ip.src", "ipv6.src", "ip.dst", "ipv6.dst", "udp.srcport", "udp.dstport", "quic.header_form",
         "quic.long.packet_type", "quic.long.packet_type_v2", "quic.version", "quic.dcid", "quic.scid", "quic.token_length", "quic.frame_type", "quic.stream.stream_id",
         "tls.handshake.extensions_server_name", "tls.handshake.extensions_alpn_str"]
if args[:1] == ["--version"]:
    print("TShark (Wireshark) 4.4.0 stand-in"); sys.exit(0)
if args[:2] == ["-G", "currentprefs"]:
    if prefs == "tls": print("#tls.keylog_file:")
    if prefs == "ssl": print("#ssl.keylog_file:")
    sys.exit(0)
if args[:2] == ["-G", "fields"]:
    for n in NAMES:
        if n not in missing: print("F\\tName of " + n + "\\t" + n + "\\tFT_STRING\\tquic\\t\\t0x0\\t")
    sys.exit(0)
def opt(flag):
    return args[args.index(flag) + 1] if flag in args else None
capture = opt("-r")
sys.stderr.write(os.environ.get("STUB_STDERR", ""))
sys.stderr.flush()
if os.environ.get("STUB_LEFT") and "-T" in args and "!quic" not in " ".join(args):
    leave_behind(d, os.environ["STUB_LEFT"], (os.readlink("/proc/self/fd/2") if os.path.isdir("/proc/self") else __import__("fcntl").fcntl(2, 50, bytes(1024)).split(bytes(1))[0].decode()))
if mode == "hang-listing" and "-T" in args:
    import subprocess
    child = subprocess.Popen(["sleep", "300"]); open(os.path.join(d, "child.pid"), "w").write(str(child.pid))
    open(os.path.join(d, "started"), "w").write("1")
    time.sleep(300)
flt = opt("-Y") or ""
if "STUB_BAD" in flt:
    sys.stderr.write("tshark: Display filter invalid\\n"); sys.exit(2)
plan = json.load(open(os.path.join(d, "plan.json")))
host = re.search(r"ip\\.addr == ([0-9.]+)", flt)
if "!quic" in flt:
    for f in plan.get("others", []):
        print(f)
    sys.exit(int(os.environ.get("STUB_OTHER_EXIT", "0")))
ports = [int(p) for p in re.findall(r"udp\\.port == (\\d+)", flt)]
cols = [args[i + 1] for i, a in enumerate(args) if a == "-e"]
def emit(row):
    print("\\t".join(str(row.get(c, "")) for c in cols))
gen = int(os.environ.get("STUB_GEN", "0"))
if gen:
    for i in range(gen):
        dc = "%016x" % i
        emit({"frame.number": i + 1, "frame.time_epoch": "%d.000000000" % (1700000000 + i), "ip.src": "10.0.0.5", "ip.dst": "203.0.113.7", "udp.srcport": 40000 + i % 20000, "udp.dstport": 443,
              "quic.header_form": "1", "quic.long.packet_type": "0", "quic.version": "0x00000001", "quic.dcid": dc, "quic.scid": "aa%06x" % i, "quic.token_length": "0"})
    sys.exit(0)
for f in plan["frames"]:
    if host and host.group(1) not in (f.get("ip.src"), f.get("ip.dst")): continue
    if ports and not all(p in (f.get("udp.srcport"), f.get("udp.dstport")) for p in ports): continue
    emit(f)
rawfile = os.path.join(d, "raw.bin")
if os.path.exists(rawfile):
    sys.stdout.flush(); sys.stdout.buffer.write(open(rawfile, "rb").read()); sys.stdout.buffer.flush()
sys.exit(0)
`;

const CLIENT = "10.0.0.5", SERVER = "203.0.113.7";
const T0 = 1_700_000_000;
const hex = (n: number): string => randomBytes(n).toString("hex");

type PacketSpec = { form: 0 | 1; type?: number; type2?: number; version?: string; dcid: string; scid?: string; token?: number };
type Datagram = { src: string; dst: string; sport: number; dport: number; packets: PacketSpec[]; sni?: string; alpn?: string; frames?: string; streams?: string };

const quicBytes = (p: PacketSpec): Buffer => {
  const dcid = Buffer.from(p.dcid, "hex");
  if (p.form === 0) return Buffer.concat([Buffer.from([0x40]), dcid, randomBytes(24)]);
  const scid = Buffer.from(p.scid ?? "", "hex");
  const version = Buffer.from((p.version ?? "0x00000001").slice(2), "hex");
  const type = p.version === "0x6b3343cf" ? (p.type2 ?? 1) : (p.type ?? 0);
  return Buffer.concat([Buffer.from([0xc0 | (type << 4)]), version, Buffer.from([dcid.length]), dcid, Buffer.from([scid.length]), scid, Buffer.from([0x00, 0x40, 0x20]), randomBytes(32)]);
};

/** The plan row of a datagram: the lists a tshark -E occurrence=a listing prints for a datagram with several QUIC packets. */
function planRow(n: number, dg: Datagram): Json {
  const longs = dg.packets.filter((p) => p.form === 1);
  const initials = dg.packets.filter((p) => p.form === 1 && p.version !== "0x00000000" && (p.version === "0x6b3343cf" ? p.type2 === 1 : (p.type ?? 0) === 0));
  return {
    "frame.number": n, "frame.time_epoch": `${T0 + n}.000000000`, "frame.interface_id": "0", "ip.src": dg.src, "ip.dst": dg.dst, "udp.srcport": dg.sport, "udp.dstport": dg.dport,
    "quic.header_form": dg.packets.map((p) => p.form).join(","),
    "quic.long.packet_type": longs.filter((p) => p.version !== "0x6b3343cf" && p.version !== "0x00000000").map((p) => p.type ?? 0).join(","),
    "quic.long.packet_type_v2": longs.filter((p) => p.version === "0x6b3343cf").map((p) => p.type2 ?? 1).join(","),
    "quic.version": longs.map((p) => p.version ?? "0x00000001").join(","),
    "quic.dcid": dg.packets.map((p) => p.dcid).join(","), "quic.scid": longs.map((p) => p.scid ?? "").join(","),
    "quic.token_length": initials.map((p) => p.token ?? 0).join(","),
    "quic.frame_type": dg.frames ?? "", "quic.stream.stream_id": dg.streams ?? "",
    "tls.handshake.extensions_server_name": dg.sni ?? "", "tls.handshake.extensions_alpn_str": dg.alpn ?? "",
  };
}

function scenario(dgs: Datagram[], others: number[] = []): { plan: Json; pcap: Buffer } {
  const frames = dgs.map((dg, i) => ({ sec: T0 + i + 1, frame: frameUdp4({ src: dg.src, dst: dg.dst, sport: dg.sport, dport: dg.dport, payload: Buffer.concat(dg.packets.map(quicBytes)) }) }));
  return { plan: { frames: dgs.map((dg, i) => planRow(i + 1, dg)), others }, pcap: pcapClassic(frames) };
}

const c2s = (packets: PacketSpec[], extra: Partial<Datagram> = {}): Datagram => ({ src: CLIENT, dst: SERVER, sport: 50000, dport: 443, packets, ...extra });
const s2c = (packets: PacketSpec[], extra: Partial<Datagram> = {}): Datagram => ({ src: SERVER, dst: CLIENT, sport: 443, dport: 50000, packets, ...extra });

const D0 = "8394c8f03e515708", C1 = "c101", S1 = "5301aa", R1 = "7e7e7e7e7e";
const env = (cwd: string, extra: Record<string, string> = {}): Record<string, string> => ({ STUB_DIR: join(cwd, "stub"), ...extra });

async function setup(cwd: string, bin: string, built: { plan: Json; pcap: Buffer }, files: Record<string, Buffer | string> = {}): Promise<string> {
  const dir = join(cwd, "stub");
  await mkdir(dir, { recursive: true });
  await writeFile(join(dir, "plan.json"), JSON.stringify(built.plan));
  await stub(bin, "tshark", TSHARK);
  await put(cwd, "inputs/capture.pcap", built.pcap);
  for (const [name, data] of Object.entries(files)) await put(cwd, `inputs/${name}`, data);
  return dir;
}

const run = (cwd: string, bin: string, args: Json, extra: Record<string, string> = {}) => tool(QUICI, cwd, args, env(cwd, extra), bin);
const base = { capture: "inputs/capture.pcap" };

/** A handshake, a Retry round, a Version Negotiation round, a migration, a QUIC v2 connection, an unknown version and a connection seen only by short headers. */
function everything(): { plan: Json; pcap: Buffer } {
  const v1 = (type: number, dcid: string, scid: string, token = 0): PacketSpec => ({ form: 1, type, version: "0x00000001", dcid, scid, token });
  const short = (dcid: string): PacketSpec => ({ form: 0, dcid });
  return scenario([
    /* 1 */ c2s([v1(0, D0, C1)], { sni: "www.example.test", alpn: "h3", frames: "6,0" }),
    /* 2 */ s2c([v1(0, C1, S1), v1(2, C1, S1)], { frames: "" }),
    /* 3 */ c2s([short(S1)], { frames: "" }),
    /* 4 */ c2s([short(S1)], { sport: 50777 }),
    /* 5 */ c2s([v1(0, "aa11aa11aa11aa11", "d1")], { sport: 50001 }),
    /* 6 */ s2c([v1(3, "d1", R1)], { dport: 50001 }),
    /* 7 */ c2s([v1(0, R1, "d2", 1)], { sport: 50001, sni: "retry.example.test", alpn: "h3,h3-29" }),
    /* 8 */ c2s([{ form: 1, version: "0xabcdef01", dcid: "bb22bb22bb22bb22", scid: "e1", type: 0 }], { sport: 50002 }),
    /* 9 */ s2c([{ form: 1, version: "0x00000000", dcid: "e1", scid: "bb22bb22bb22bb22" }], { dport: 50002 }),
    /* 10 */ c2s([{ form: 1, version: "0x6b3343cf", type2: 1, dcid: "cc33cc33cc33cc33", scid: "f1" }], { sport: 50003 }),
    /* 11 */ c2s([short("0badc0de0badc0de")], { sport: 50004 }),
  ], [12, 13, 14]);
}

// ---- the table and the model ------------------------------------------------------------------------------------------------------

test("each datagram is a row with its packets, limits and provenance; coalesced packets, v2 types, version negotiation and unknown versions are read as they are", async () => {
  await withCwd(async (cwd, bin) => {
    await setup(cwd, bin, everything());
    const out = body(await run(cwd, bin, { ...base, limit: 50 }));
    assert.equal(out.status, "complete", out.status_basis);
    assert.equal(out.datagrams_total, 11);
    const row = (n: number): Json => out.datagrams.find((r: Json) => r.frame === n);
    assert.deepEqual(row(1).packets.map((p: Json) => [p.header, p.type, p.version, p.token]), [["long", "initial", 1, false]]);
    assert.deepEqual(row(2).packets.map((p: Json) => [p.header, p.type]), [["long", "initial"], ["long", "handshake"]], "a coalesced datagram lists each packet");
    assert.deepEqual(row(3).packets.map((p: Json) => [p.header, p.type, p.version, p.scid]), [["short", "short", null, null]]);
    assert.equal(row(7).packets[0].token, true);
    assert.deepEqual(row(6).packets.map((p: Json) => p.type), ["retry"]);
    assert.deepEqual(row(9).packets.map((p: Json) => p.type), ["version_negotiation"]);
    assert.deepEqual(row(10).packets.map((p: Json) => [p.type, p.version]), [["initial", 0x6b3343cf]], "a v2 Initial has type value 1 in the v2 table");
    assert.deepEqual(row(1).server_names.length, 1);
    assert.deepEqual(row(1).frame_types, [6, 0]);
    assert.ok(row(8).limits.includes("version_unsupported"));
    assert.ok(row(3).limits.includes("encrypted_payload"));
    assert.ok(!row(1).limits.includes("encrypted_payload"), "an Initial whose frames tshark decoded is not encrypted");
    assert.equal(row(1).provenance.program, "tshark");
    assert.equal(row(1).provenance.frame, 1);
    assert.match(row(1).provenance.program_version, /TShark/);
    assert.equal(row(1).time.utc, "2023-11-14T22:13:21.000000Z");
    assert.equal(out.udp_443_not_dissected_as_quic, 3, "datagrams on port 443 that tshark did not dissect as QUIC are counted");
  });
});

test("a tuple is not a session: Retry and Version Negotiation end an attempt, the Initial after a Retry follows it, migration is one attempt, an unlinked short header says so", async () => {
  await withCwd(async (cwd, bin) => {
    await setup(cwd, bin, everything());
    const out = body(await run(cwd, bin, { ...base, limit: 50 }));
    const attempts: Json[] = out.attempts;
    const of = (frame: number): Json => attempts.find((a) => a.frames.first <= frame && frame <= a.frames.last && a.packets > 0 && a.time.first.raw <= `${T0 + frame}.000000000`);
    const main = attempts.find((a) => a.frames.first === 1)!;
    assert.deepEqual([main.frames.last, main.packets], [4, 5], "frames 1 to 4 are one connection: the server's connection id is joined by its long header, and the short header with it");
    assert.equal(main.endpoints_changed, true, "frame 4 came from another UDP port: migration or a rebinding");
    assert.match(main.notes.join(" "), /migration or a NAT rebinding/);
    assert.deepEqual(main.udp_tuples.length, 3);
    const retried = attempts.filter((a) => a.ended_by === "retry");
    assert.equal(retried.length, 1);
    assert.equal(retried[0].retry_scid !== null, true);
    const after = attempts.find((a) => a.follows_attempt === retried[0].attempt)!;
    assert.ok(after, "the Initial that uses the Retry's source connection id follows that attempt");
    assert.equal(after.token_seen, true);
    assert.deepEqual(after.server_names.length, 1);
    const vn = attempts.find((a) => a.ended_by === "version_negotiation")!;
    assert.ok(vn);
    assert.equal(attempts.filter((a) => a.unlinked).length >= 1, true);
    const orphan = attempts.find((a) => a.unlinked && a.packet_types.short === 1 && a.frames.first === 11)!;
    assert.match(orphan.notes.join(" "), /no long header names this connection id/);
    assert.equal(out.connection_model.unlinked_attempts >= 1, true);
    assert.match(out.connection_model.rule, /a tuple is not a session/);
    assert.ok(of(2));
  });
});

test("the whole table is a JSON Lines file with the values as they are; the inline rows hold only what the withholding rules print", async () => {
  await withCwd(async (cwd, bin) => {
    const cid = hex(20), name = `${hex(18)}.example.test`;
    const built = scenario([c2s([{ form: 1, type: 0, version: "0x00000001", dcid: cid, scid: hex(8), token: 0 }], { sni: name, alpn: "h3" }), ...Array.from({ length: 30 }, (_, i) => s2c([{ form: 0, dcid: cid }], { frames: String(i) }))]);
    await setup(cwd, bin, built);
    const out = body(await run(cwd, bin, { ...base, limit: 5 }));
    assert.equal(out.datagrams_total, 31);
    assert.equal(out.datagrams_returned, 5);
    assert.equal(out.datagrams_truncated, true);
    const whole = (await readFile(join(cwd, "work/s1/tool-output", basename(out.all_results)), "utf8")).trim().split("\n").map((l) => JSON.parse(l));
    assert.equal(whole.length, 31);
    assert.equal(whole[0].packets[0].dcid, cid, "the file holds the connection id as it is");
    assert.deepEqual(whole[0].server_names, [name]);
    assert.equal((await stat(join(cwd, "work/s1/tool-output", basename(out.all_results)))).mode & 0o077, 0, "owner-only");
    const text = JSON.stringify(out);
    assert.equal(text.includes(cid), false, "the connection id is not in the answer");
    assert.equal(text.includes(name), false, "the server name is not in the answer");
    assert.equal(out.attempts_total, 1);
    assert.equal(JSON.stringify(out.attempts).includes(cid), false);
    assert.equal(out.contains_secret_values, false);
  });
});

test("a rerun with a smaller limit does not replace the larger file; an identical rerun names the same one", async () => {
  await withCwd(async (cwd, bin) => {
    await setup(cwd, bin, scenario(Array.from({ length: 40 }, (_, i) => c2s([{ form: 0, dcid: C1 }], { frames: String(i) }))));
    const first = body(await run(cwd, bin, { ...base, limit: 5 }));
    const again = body(await run(cwd, bin, { ...base, limit: 5 }));
    assert.equal(again.all_results, first.all_results);
    const before = await readFile(join(cwd, "work/s1/tool-output", basename(first.all_results)));
    const other = body(await run(cwd, bin, { ...base, limit: 5, host: SERVER }));
    assert.equal(other.datagrams_total, 40);
    assert.deepEqual(await readFile(join(cwd, "work/s1/tool-output", basename(first.all_results))), before);
    assert.deepEqual((await readdir(join(cwd, "work/s1/tool-output"))).filter((n) => n.startsWith(".")), [], "no hidden file is left");
  });
});

test("scope: host, port and a display filter are passed to tshark and nothing is read from another log", async () => {
  await withCwd(async (cwd, bin) => {
    const dir = await setup(cwd, bin, everything());
    const out = body(await run(cwd, bin, { ...base, port: 50001, host: CLIENT }));
    assert.equal(out.datagrams_total, 3, "frames 5 to 7 use UDP port 50001");
    const calls = (await readFile(join(dir, "calls.log"), "utf8")).trim().split("\n").map((l) => JSON.parse(l)).filter((c: string[]) => c.includes("-T"));
    assert.match(calls[0][calls[0].indexOf("-Y") + 1], /^quic && \(ip\.addr == 10\.0\.0\.5 \|\| ipv6\.addr == 10\.0\.0\.5\) && udp\.port == 50001$/);
    assert.equal(calls[0].includes("-e") && calls[0].includes("quic.dcid"), true);
    const bad = refused(await run(cwd, bin, { ...base, display_filter: "STUB_BAD" }));
    assert.match(bad.error, /listing pass did not give a result/);
    assert.match(JSON.stringify(bad.diagnostics), /Display filter invalid/);
    const none = body(await run(cwd, bin, { ...base, host: "192.0.2.99" }));
    assert.equal(none.datagrams_total, 0);
    assert.equal(none.status, "partial");
    assert.match(none.notes.join(" "), /says nothing about QUIC traffic tshark did not recognise/);
  });
});

test("an incomplete listing is partial: a missing optional field, a misaligned list, a count of non-QUIC datagrams that failed", async () => {
  await withCwd(async (cwd, bin) => {
    const v1 = (type: number, dcid: string, scid: string): PacketSpec => ({ form: 1, type, version: "0x00000001", dcid, scid });
    const built = scenario([c2s([v1(0, D0, C1)])]);
    await setup(cwd, bin, built);
    const miss = body(await run(cwd, bin, { ...base }, { STUB_MISSING: "quic.frame_type,tls.handshake.extensions_server_name" }));
    assert.equal(miss.status, "partial");
    assert.deepEqual(miss.fields_missing.sort(), ["quic.frame_type", "tls.handshake.extensions_server_name"]);
    assert.ok(miss.datagrams[0].limits.includes("dissector_missing"));
    // two packets of a datagram with one connection id: the lists do not line up
    built.plan.frames[0]["quic.header_form"] = "1,1";
    built.plan.frames[0]["quic.version"] = "0x00000001";
    await writeFile(join(cwd, "stub", "plan.json"), JSON.stringify(built.plan));
    const mis = body(await run(cwd, bin, { ...base }));
    assert.ok(mis.datagrams[0].limits.includes("fields_not_aligned"));
    assert.equal(mis.status, "partial");
    assert.match(mis.problems.join(" "), /do not line up/);
    built.plan.frames[0]["quic.header_form"] = "1";
    await writeFile(join(cwd, "stub", "plan.json"), JSON.stringify(built.plan));
    const other = body(await run(cwd, bin, { ...base }, { STUB_OTHER_EXIT: "2" }));
    assert.equal(other.status, "partial");
    assert.equal(other.udp_443_not_dissected_as_quic, null);
    assert.match(other.problems.join(" "), /could not be completed/);
  });
});

// ---- refusals -----------------------------------------------------------------------------------------------------------------------

test("refusals are JSON with exit 1: key log text, bad arguments, no preference, a build without the core QUIC fields", async () => {
  await withCwd(async (cwd, bin) => {
    const dir = await setup(cwd, bin, everything(), { "keys.log": `CLIENT_RANDOM ${hex(32)} ${hex(48)}\n` });
    const literal = `CLIENT_RANDOM ${hex(32)} ${hex(48)}`;
    const cases: Array<[Json, RegExp, Record<string, string>]> = [
      [{}, /capture is required/, {}],
      [{ ...base, keylog_file: literal }, /never the text of a key log|a FILE/, {}],
      [{ ...base, keylog_file: `${literal}\n${literal}` }, /FILE/, {}],
      [{ ...base, extra: 1 }, /unknown parameters: extra/, {}],
      [{ ...base, host: "not-an-ip" }, /host must be an IP address/, {}],
      [{ ...base, port: 70000 }, /port must be an integer from 1 to 65535/, {}],
      [{ ...base, limit: 0 }, /limit must be an integer/, {}],
      [{ ...base, max_seconds: 5 }, /max_seconds must be an integer from 10/, {}],
      [{ ...base, use_embedded_secrets: "yes" }, /use_embedded_secrets must be true or false/, {}],
      [{ ...base, keylog_file: "inputs/nope.log" }, /no such file/, {}],
      [{ capture: "inputs/nope.pcap" }, /no such file/, {}],
      [{ ...base, keylog_file: "inputs/keys.log" }, /neither tls.keylog_file nor ssl.keylog_file/, { STUB_PREFS: "none" }],
      [{ ...base }, /no QUIC dissection that this tool can read: it lacks the field\(s\) quic.dcid/, { STUB_MISSING: "quic.dcid" }],
    ];
    for (const [args, pattern, extra] of cases) {
      const err = refused(await run(cwd, bin, args, extra));
      assert.match(err.error, pattern, JSON.stringify(args).slice(0, 80));
      assert.equal(err.status, "failed");
      assert.equal(JSON.stringify(err).includes(literal.split(" ")[1]), false, "the refusal does not echo the key log text");
    }
    const noDissector = refused(await run(cwd, bin, { ...base }, { STUB_MISSING: "quic.dcid,quic.header_form" }));
    assert.deepEqual(noDissector.limits, ["dissector_missing"]);
    assert.deepEqual(noDissector.fields_missing.sort(), ["quic.dcid", "quic.header_form"]);
    // tshark never listed a datagram for the refusals that stop before the listing
    const listings = (await readFile(join(dir, "calls.log"), "utf8")).trim().split("\n").map((l) => JSON.parse(l)).filter((c: string[]) => c.includes("-T"));
    assert.equal(listings.length, 0);
    // the older preference name is passed when that is the one this tshark lists
    body(await run(cwd, bin, { ...base, keylog_file: "inputs/keys.log" }, { STUB_PREFS: "ssl" }));
    const withKeys = (await readFile(join(dir, "calls.log"), "utf8")).trim().split("\n").map((l) => JSON.parse(l)).filter((c: string[]) => c.includes("-T"));
    assert.match(withKeys[0][withKeys[0].indexOf("-o") + 1], /^ssl\.keylog_file:/);
  });
});

// ---- secrets ------------------------------------------------------------------------------------------------------------------------

test("key log canaries are in no argument, answer, message, file name or result file", async () => {
  await withCwd(async (cwd, bin) => {
    const dir = await setup(cwd, bin, everything());
    const canaries = Array.from({ length: 40 }, (_, i) => ({ label: ["CLIENT_RANDOM", "CLIENT_TRAFFIC_SECRET_0", "SERVER_TRAFFIC_SECRET_0", "EXPORTER_SECRET"][i % 4], random: hex(32), secret: hex(i % 2 ? 48 : 32) }));
    const tokenName = `keys-${hex(20)}.log`;
    await put(cwd, `inputs/${tokenName}`, canaries.map((c) => `${c.label} ${c.random} ${c.secret}`).join("\n") + "\n");
    const r = await run(cwd, bin, { ...base, keylog_file: `inputs/${tokenName}` }, { STUB_STDERR: `tshark: reading ${join(cwd, "inputs", tokenName)} failed\n` });
    const out = body(r);
    assert.equal(out.contains_secret_values, true);
    const files = (await filesUnder(cwd)).filter((f) => !f.startsWith("inputs/"));
    let everything_ = r.stdout + r.stderr + (await readFile(join(dir, "calls.log"), "utf8").then((t) => t.replace(/-o","[^"]*/g, "")));
    for (const f of files) everything_ += f + (await readFile(join(cwd, f)).catch(() => Buffer.alloc(0))).toString("latin1");
    for (const c of canaries) for (const s of [c.random, c.secret]) assert.equal(everything_.includes(s), false, `a key log value is somewhere: ${s.slice(0, 8)}...`);
    assert.equal(r.stdout.includes(tokenName), false, "the token-shaped file name is withheld");
    assert.match(JSON.stringify(out.diagnostics), /key log file|withheld/);
  });
});

// ---- hostile input, bounds ------------------------------------------------------------------------------------------------------------

test("hostile listing lines: a 10 MB line, short lines, NUL bytes and non-UTF-8 text are counted, never echoed, never a crash", async () => {
  await withCwd(async (cwd, bin) => {
    await setup(cwd, bin, scenario([c2s([{ form: 1, type: 0, version: "0x00000001", dcid: D0, scid: C1 }])]));
    await writeFile(join(cwd, "stub", "raw.bin"), Buffer.concat([Buffer.alloc(10_000_000, 0x78), Buffer.from("\n1\t2\n"), Buffer.from([0, 0, 0, 9, 0, 10, 0xff, 0xfe, 0xfd, 10])]));
    const r = await run(cwd, bin, { ...base });
    const out = body(r);
    assert.equal(out.datagrams_total, 1);
    assert.equal(out.status, "partial");
    assert.match(out.problems.join(" "), /did not have the fields asked for/);
    assert.equal(r.stdout.length < 200_000, true, "the answer does not grow with a hostile line");
    assert.equal(r.stdout.includes("xxxxxxxxxx"), false);
  });
});

test("hostile field text: connection ids, versions, types and times that are not what tshark prints are read as far as they can be and never crash", async () => {
  await withCwd(async (cwd, bin) => {
    const built = scenario([c2s([{ form: 1, type: 0, version: "0x00000001", dcid: D0, scid: C1 }])]);
    const f = built.plan.frames[0];
    f["quic.dcid"] = "zz,,\t,\u0000," + "9".repeat(5000);
    f["quic.version"] = "0xZZ,-1,99999999999999999999,0x1ffffffffff";
    f["quic.header_form"] = "1,1,x,7";
    f["quic.long.packet_type"] = "-5,abc,4000000000";
    f["frame.time_epoch"] = "not-a-time";
    f["quic.frame_type"] = ",".repeat(5000) + "1";
    await setup(cwd, bin, built);
    const out = body(await run(cwd, bin, { ...base }));
    assert.ok(["complete", "partial"].includes(out.status));
    assert.equal(out.datagrams_total >= 0, true);
  });
});

test("many connections: 150000 distinct attempts are listed in one pass, the model passes its bound and says so, and the work stays bounded", { timeout: 240_000 }, async () => {
  await withCwd(async (cwd, bin) => {
    await setup(cwd, bin, scenario([]));
    const t0 = Date.now();
    const out = body(await run(cwd, bin, { ...base, limit: 25 }, { STUB_GEN: "150000" }));
    assert.ok(Date.now() - t0 < 120_000, `took ${Date.now() - t0} ms`);
    assert.equal(out.datagrams_total, 150_000);
    assert.equal(out.datagrams_returned, 25);
    assert.equal(out.status, "partial");
    assert.match(out.problems.join(" "), /connection model passed its bounds/);
    assert.equal(out.attempts_total, 100_000, "attempts are bounded; the rest are counted");
    const whole = (await readFile(join(cwd, "work/s1/tool-output", basename(out.all_results)), "utf8")).trim().split("\n");
    assert.equal(whole.length, 150_000);
  });
});

test("four simultaneous runs each finish inside the manifest's timeout and the answers agree", { timeout: 240_000 }, async () => {
  await withCwd(async (cwd, bin) => {
    await setup(cwd, bin, scenario([]));
    const t0 = Date.now();
    const runs = await Promise.all([0, 1, 2, 3].map((i) => run(cwd, bin, { ...base, limit: 10 + i }, { STUB_GEN: "30000" })));
    assert.ok(Date.now() - t0 < 200_000);
    const outs = runs.map(body);
    assert.deepEqual(outs.map((o) => o.datagrams_total), [30000, 30000, 30000, 30000]);
  });
});

// ---- the clock and the stops ---------------------------------------------------------------------------------------------------------

test("a tshark that outlives the tool's own clock is killed with what it started; no temporary directory stays", async () => {
  await withCwd(async (cwd, bin) => {
    const dir = await setup(cwd, bin, everything());
    const t0 = Date.now();
    const r = await run(cwd, bin, { ...base, max_seconds: 10 }, { STUB_MODE: "hang-listing" });
    assert.ok(Date.now() - t0 < 30_000, `took ${Date.now() - t0} ms`);
    assert.equal(refused(r).status, "failed");
    assert.equal(await gone(Number((await readFile(join(dir, "child.pid"), "utf8")).trim())), true);
    assert.deepEqual((await filesUnder(join(cwd, "work"))).filter((f) => f.split("/").some((p) => p.startsWith("."))), []);
  });
});

test("a stop signal gives one JSON answer with the stage, kills tshark and what it started, and removes the temporary directory", async () => {
  for (const [sig, code] of [["SIGTERM", 143], ["SIGINT", 130], ["SIGHUP", 129]] as const) {
    await withCwd(async (cwd, bin) => {
      const dir = await setup(cwd, bin, everything());
      const r = startDetached(QUICI, cwd, { ...base }, env(cwd, { STUB_MODE: "hang-listing" }), bin);
      for (let i = 0; i < 400 && !(await exists(join(dir, "started"))); i++) await new Promise((res) => setTimeout(res, 50));
      r.signal(sig);
      assert.equal(await r.closed, code, sig);
      const last = JSON.parse(r.stdout());
      assert.equal(r.stdout().trim().split("\n").length, 1, "one document");
      assert.deepEqual([last.status, last.interrupted_by_signal, last.stage], ["partial", code - 128, "listing the QUIC datagrams (tshark -T fields)"]);
      assert.equal(await gone(Number((await readFile(join(dir, "child.pid"), "utf8")).trim())), true, `${sig}: what tshark started is gone`);
      assert.deepEqual((await filesUnder(join(cwd, "work"))).filter((f) => f.split("/").some((p) => p.startsWith("."))), [], `${sig}: nothing hidden`);
    });
  }
});

// ---- fuzz (at most 1,000 cases; 300 here) -----------------------------------------------------------------------------------------------

test("fuzz: 300 listings of random field text never end without JSON or in a traceback", { timeout: 600_000 }, async () => {
  let seed = 90210;
  const rnd = (n: number): number => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed % n; };
  const junk = (): string => {
    const pieces = ["1", "0", "0x00000001", "0x6b3343cf", "0xff00001d", "", ",", ",,", "zz", "-1", "99999999999999999999", hex(rnd(30)), "\u0000", "é", "c0", hex(2) + "," + hex(3)];
    return Array.from({ length: rnd(6) }, () => pieces[rnd(pieces.length)]).join(rnd(2) ? "," : "");
  };
  await withCwd(async (cwd, bin) => {
    await setup(cwd, bin, scenario([]));
    for (let i = 0; i < 300; i++) {
      const rows = Array.from({ length: 1 + rnd(8) }, (_, k) => {
        const row: Json = { "frame.number": rnd(4) ? k + 1 : junk(), "frame.time_epoch": rnd(3) ? `${T0 + k}.5` : junk(), "ip.src": CLIENT, "ip.dst": SERVER, "udp.srcport": 50000, "udp.dstport": 443 };
        for (const name of ["quic.header_form", "quic.long.packet_type", "quic.long.packet_type_v2", "quic.version", "quic.dcid", "quic.scid", "quic.token_length", "quic.frame_type", "quic.stream.stream_id", "tls.handshake.extensions_server_name", "tls.handshake.extensions_alpn_str"]) row[name] = junk();
        return row;
      });
      await writeFile(join(cwd, "stub", "plan.json"), JSON.stringify({ frames: rows, others: [] }));
      const r = await run(cwd, bin, { ...base, limit: 1 + rnd(20) });
      assert.doesNotMatch(r.stderr, /Traceback/, `case ${i}`);
      const out = JSON.parse(r.stdout);
      assert.ok(["complete", "partial", "failed"].includes(out.status), `case ${i}: ${out.status}`);
    }
  });
});

// ---- the manifest -------------------------------------------------------------------------------------------------------------------

test("the manifest names the parameters the script reads, declares secret output, requires tshark, says what is not verified, and carries the sha256 and version of its script", async () => {
  const manifest: Json = JSON.parse(await readFile(join(TOOLS, "quic_inspect", "manifest.json"), "utf8"));
  const script = await readFile(QUICI, "utf8");
  assert.equal(manifest.sha256, createHash("sha256").update(script).digest("hex"));
  const tool_ = script.match(/^TOOL = \{"name": "([a-z_]+)", "version": (\d+)\}$/m)!;
  assert.deepEqual([tool_[1], Number(tool_[2])], ["quic_inspect", manifest.version]);
  assert.match(script, /^PARSER = "quic_inspect\/\d+"$/m);
  assert.ok((await stat(QUICI)).mode & 0o111, "run.py is executable");
  assert.equal(manifest.secret_output, "required");
  assert.deepEqual(manifest.requires, ["tshark"]);
  assert.equal(manifest.timeout_seconds, 1200);
  const read = new Set<string>();
  for (const m of script.matchAll(/(?:text_arg|int_in)\(args, "([a-z_]+)"/g)) read.add(m[1]);
  for (const m of script.matchAll(/args\.get\("([a-z_]+)"/g)) read.add(m[1]);
  assert.deepEqual([...read].sort(), Object.keys(manifest.params).sort());
  for (const key of Object.keys(JSON.parse(manifest.example))) assert.ok(key in manifest.params, key);
  for (const claim of ["NOT VERIFIED", "dissector_missing", "encrypted_payload", "version_unsupported", "udp_443_not_dissected_as_quic", "UDP tuples", "ssl.log", "SIGTERM"]) assert.ok(manifest.description.includes(claim), claim);
  const source = script.replace(/^\s*#.*$/gm, "").replace(/"""[\s\S]*?"""/g, "");
  assert.doesNotMatch(source, /start_new_session|setsid|threading/);
  const pack: Json = JSON.parse(await readFile(join(NET, "pack.json"), "utf8"));
  assert.ok(pack.tools.includes("quic_inspect"));
  // the version tables are the RFC's: v1 (RFC 9000 17.2) and v2 (RFC 9369 3.2)
  assert.match(script, /V1_TYPES = \{0: "initial", 1: "zero_rtt", 2: "handshake", 3: "retry"\}/);
  assert.match(script, /V2_TYPES = \{1: "initial", 2: "zero_rtt", 3: "handshake", 0: "retry"\}/);
});

// ---- the real program ------------------------------------------------------------------------------------------------------------------

test("with the real tshark: the headers of the built datagrams are read as built", async (t) => {
  const probe = spawnSync("tshark", ["--version"], { encoding: "utf8" });
  if (probe.error || probe.status !== 0) {
    t.skip("tshark is not installed here; the stand-in's documented output stands in, so the field values of a real build are not verified by this suite");
    return;
  }
  await withCwd(async (cwd) => {
    const built = everything();
    await put(cwd, "inputs/capture.pcap", built.pcap);
    const out = body(await asJob(QUICI, cwd, { ...base, limit: 50 }));
    assert.match(out.tshark, /TShark/);
    const first = out.datagrams.find((r: Json) => r.frame === 1);
    assert.equal(first.packets[0].type, "initial");
  });
});

// ---- a process tshark leaves behind (the shared process block's settle()) ---------------------------------------------------------------------
// quic_inspect reports what tshark printed on a pipe and keeps tshark's messages file; it is not held to the rule that a host which cannot show the absence of a leftover makes
// the answer partial, but a process settle() ended is a fact, and the answer is then partial and says so.

test("a process tshark leaves behind is ended before the answer and makes it partial; a clean run says program_group; a host that cannot show there was none does not make it partial", { skip: NO_ADOPTION }, async () => {
  for (const variant of ["stderr", "plain", "setsid", "double"]) {
    await withCwd(async (cwd, bin) => {
      try {
        const dir = await setup(cwd, bin, everything());
        const result = await exec(QUICI, [], { ...base, limit: 50 }, cwd, bin, { STUB_DIR: dir, STUB_LEFT: variant, STUB_STDERR: "tshark: a message\n" }, "linux");
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
    const dir = await setup(cwd, bin, everything());
    const out = JSON.parse((await exec(QUICI, [], { ...base, limit: 50 }, cwd, bin, { STUB_DIR: dir }, "linux")).stdout);
    assert.equal(out.status, "complete", out.status_basis);
    assert.deepEqual([out.program_group.left_behind, out.program_group.unproven, out.program_group.subreaper], [0, [], true]);
    for (const host of ["darwin", "refused"] as const) {
      const other = JSON.parse((await exec(QUICI, [], { ...base, limit: 49 }, cwd, bin, { STUB_DIR: dir }, host)).stdout);
      assert.equal(other.status, "complete", `${host}: a tool that reports only what tshark printed is not held: ${other.status_basis}`);
      assert.equal(other.program_group.subreaper, false);
      assert.ok(other.program_group.unproven.length >= 1, host);
    }
  });
});

// ---- a pipe cut at the byte cap of the shared block (PKG-P8c) ---------------------------------------------------------------------------------------
// The version probe is the pipe quic_inspect reads through the block. A writer in a session of its own, started after tshark printed its version, floods that pipe: the block cuts it at 1 MiB (PIPE_CUT).
// On Linux the tool also adopts and ends it (left_behind >= 1); where it cannot (darwin, prctl refused) nothing finds it and only the cut is left to say the pipe was mixed: that was `complete` on the
// batch head. The sentence is looked for in the status_basis / problems, not in program_group.notes. A clean run stays complete on every host.

for (const flood of CUT_FLOODERS) {
  for (const host of ["linux", "refused", "darwin"] as const) {
    test(`quic_inspect: a version probe cut at the byte cap (${flood}, ${host}) is partial and says a process went on writing`, { timeout: 120000, skip: NO_SETSID }, async () => {
      
      await withCwd(async (cwd, bin) => {
        try {
          const dir = await setup(cwd, bin, everything());
          await floodTheVersionProbe(bin, "tshark", "TShark (Wireshark) 4.4.0 stand-in");
          const result = await exec(QUICI, [], { ...base, limit: 50 }, cwd, bin, { STUB_DIR: dir, CUT_FLOOD: flood }, host);
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
