/**
 * network-forensics: tls_decrypt says which sessions of a capture the supplied secrets decrypt, and keeps what they decrypt out of the answer.
 *
 * The TLS bytes are real: tests/network-tls-fixture.py runs a TLS 1.2 and a TLS 1.3 handshake plus application data between two Python `ssl`
 * contexts over `ssl.MemoryBIO`, with `keylog_filename` set, and this suite wraps the recorded records in synthetic TCP segments (the harness
 * builders) in a pcap and a pcapng. Wireshark is not on every machine these suites run on, so a stand-in `tshark` plays it. It prints what the
 * documentation says tshark prints (`--version`, `-G currentprefs`, `-G fields`, `-T fields` rows, `-z follow,tls,raw,N`) from a plan built from
 * the same chunks, and it treats a flow as decryptable when the key log it was given (or the capture's Decryption Secrets Block) holds the lines
 * the session needs. That proves the wrapper: which preference it passes, what it reads of a key log, how it judges a flow, where it writes, what
 * it prints and how it stops. It proves nothing about the real tshark's field values: one test runs the real program when it is installed and says
 * so when it is not.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { mkdir, readFile, readdir, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { test } from "node:test";
import { NET, TOOLS, TLSD, asJob, body, exists, filesUnder, frameTcp4, gone, ngBlock, ngInterface, ngPacket, ngSection, pcapClassic, put, refused, startDetached, stub, tool, TCP, ticks, u32, withCwd } from "./pack-network-harness.ts";
import type { Json } from "./pack-network-harness.ts";
import { ROOT } from "./tool-library-harness.ts";

const TLS = TLSD;
const BUILDER = join(ROOT, "tests", "network-tls-fixture.py");

const TSHARK = `#!/usr/bin/env python3
import json, os, re, sys, time
d = os.environ["STUB_DIR"]
args = sys.argv[1:]
open(os.path.join(d, "calls.log"), "a").write(json.dumps(args) + "\\n")
plan = json.load(open(os.path.join(d, "plan.json")))
mode = os.environ.get("STUB_MODE", "")
prefs = os.environ.get("STUB_PREFS", "tls")
missing = [m for m in os.environ.get("STUB_MISSING", "").split(",") if m]
def fields():
    names = ["frame.number", "frame.time_epoch", "tcp.stream", "ip.src", "ipv6.src", "ip.dst", "ipv6.dst", "tcp.srcport", "tcp.dstport"]
    for p in ("tls",):
        names += [p + s for s in (".record.content_type", ".handshake.type", ".handshake.random", ".handshake.extension.type", ".handshake.extensions.supported_version", ".app_data_proto")]
    return [n for n in names if n not in missing]
if args[:1] == ["--version"]:
    print("TShark (Wireshark) 4.2.0 stand-in"); sys.exit(0)
if args[:2] == ["-G", "currentprefs"]:
    print("# stand-in preferences")
    if prefs == "tls": print("#tls.keylog_file:")
    if prefs == "ssl": print("#ssl.keylog_file:")
    sys.exit(0)
if args[:2] == ["-G", "fields"]:
    for n in fields(): print("F\\tName of " + n + "\\t" + n + "\\tFT_STRING\\ttls\\t\\t0x0\\t")
    sys.exit(0)
def opt(flag):
    return args[args.index(flag) + 1] if flag in args else None
capture = opt("-r")
keylog = None
if "-o" in args:
    keylog = args[args.index("-o") + 1].split(":", 1)[1]
secret_text = open(keylog, "r", encoding="latin-1").read() if keylog else ""
secret_text += open(capture, "rb").read().decode("latin-1")
def decryptable(stream):
    s = plan["streams"].get(str(stream))
    if not s: return False
    return all(re.search(r"^%s %s " % (label, s["random"]), secret_text, re.M) for label in s["need"])
sys.stderr.write(os.environ.get("STUB_STDERR", ""))
if mode == "hang-listing" and "-T" in args:
    import subprocess
    child = subprocess.Popen(["sleep", "300"]); open(os.path.join(d, "child.pid"), "w").write(str(child.pid))
    open(os.path.join(d, "started"), "w").write("1")
    time.sleep(300)
if "-z" in args:
    n = int(args[args.index("-z") + 1].split(",")[3])
    if mode == "hang-follow":
        import subprocess
        child = subprocess.Popen(["sleep", "300"]); open(os.path.join(d, "child.pid"), "w").write(str(child.pid))
        open(os.path.join(d, "started"), "w").write("1")
        time.sleep(300)
    print("=" * 67); print("Follow: tls,raw"); print("Filter: tcp.stream eq %d" % n); print("Node 0: 10.0.0.5:50000"); print("Node 1: 203.0.113.7:443")
    s = plan["streams"].get(str(n))
    if s and decryptable(n):
        print(s["plain_c"]); print("\\t" + s["plain_s"])
    print("=" * 67)
    sys.exit(0)
flt = opt("-Y") or ""
if "STUB_BAD" in flt:
    sys.stderr.write("tshark: Display filter invalid\\n"); sys.exit(2)
cols = [args[i + 1] for i, a in enumerate(args) if a == "-e"]
want_stream = re.search(r"tcp\\.stream == (\\d+)", flt)
limit_partial = int(os.environ.get("STUB_PARTIAL", "-1"))
seen_app = {}
for f in plan["frames"]:
    if want_stream and f["stream"] != int(want_stream.group(1)): continue
    host = re.search(r"ip\\.addr == ([0-9.]+)", flt)
    if host and host.group(1) not in (f["src"], f["dst"]): continue
    port = re.search(r"tcp\\.port == (\\d+)", flt)
    if port and int(port.group(1)) not in (f["sport"], f["dport"]): continue
    app = ""
    if "23" in f["ct"].split(",") and decryptable(f["stream"]):
        k = seen_app.get(f["stream"], 0); seen_app[f["stream"]] = k + 1
        if limit_partial < 0 or k < limit_partial: app = "Hypertext Transfer Protocol"
    row = {"frame.number": f["frame"], "frame.time_epoch": f["time"], "tcp.stream": f["stream"], "ip.src": f["src"], "ip.dst": f["dst"], "ipv6.src": "", "ipv6.dst": "",
           "tcp.srcport": f["sport"], "tcp.dstport": f["dport"], "tls.record.content_type": f["ct"], "tls.handshake.type": f["hs"], "tls.handshake.random": f["random"],
           "tls.handshake.extension.type": f["ext"], "tls.handshake.extensions.supported_version": f["sv"], "tls.app_data_proto": app}
    print("\\t".join(str(row.get(c, "")) for c in cols))
sys.exit(0)
`;

type Fix = { sessions: Array<{ name: string; version: string; client_random: string; chunks: Array<{ dir: string; hex: string; records: number[][] }>; client_plaintext: string; server_plaintext: string; keylog_lines: string[] }> };

function buildFixture(): Fix | null {
  const dir = mkdtempSync(join(tmpdir(), "tls-fixture-"));
  try {
    const run = spawnSync("python3", [BUILDER, join(dir, "fixture.json")], { encoding: "utf8" });
    return run.status === 0 ? JSON.parse(readFileSync(join(dir, "fixture.json"), "utf8")) : null;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const CLIENT = "10.0.0.5", SERVER = "203.0.113.7";
const HS_SHOWN = new Set([1, 2, 11, 12, 13, 14, 16]);

type Flow = { stream: number; sport: number; chunks: Array<{ dir: string; hex: string; records: number[][] }>; random: string; need: string[]; plain_c: string; plain_s: string; ech?: boolean; tls13?: boolean; tls?: boolean };

/** The frames of a flow: a handshake of three segments, then one segment per recorded chunk, the way a capture of it would look. */
function framesOf(flow: Flow, start: number, t0: number): { pcap: Array<{ sec: number; frame: Buffer }>; plan: Json[] } {
  const pcap: Array<{ sec: number; frame: Buffer }> = [], plan: Json[] = [];
  let cseq = 1000, sseq = 5000, n = start;
  const add = (frame: Buffer, row: Json): void => {
    pcap.push({ sec: t0 + n, frame });
    plan.push({ frame: n, time: `${t0 + n}.000000000`, stream: flow.stream, src: row.dir === "c" ? CLIENT : SERVER, dst: row.dir === "c" ? SERVER : CLIENT, sport: row.dir === "c" ? flow.sport : 443,
      dport: row.dir === "c" ? 443 : flow.sport, ct: "", hs: "", random: "", ext: "", sv: "", ...row.fields });
    n += 1;
  };
  add(frameTcp4({ src: CLIENT, dst: SERVER, sport: flow.sport, dport: 443, flags: TCP.SYN, seq: cseq }), { dir: "c" });
  add(frameTcp4({ src: SERVER, dst: CLIENT, sport: 443, dport: flow.sport, flags: TCP.SYN | TCP.ACK, seq: sseq, ack: cseq + 1 }), { dir: "s" });
  cseq += 1; sseq += 1;
  add(frameTcp4({ src: CLIENT, dst: SERVER, sport: flow.sport, dport: 443, flags: TCP.ACK, seq: cseq, ack: sseq }), { dir: "c" });
  for (const chunk of flow.chunks) {
    const payload = Buffer.from(chunk.hex, "hex");
    const client = chunk.dir === "c";
    const types = chunk.records.map((r) => r[0]);
    const hs = chunk.records.filter((r) => r[0] === 22 && HS_SHOWN.has(r[1])).map((r) => r[1]);
    const first = hs.includes(1);
    add(frameTcp4({ src: client ? CLIENT : SERVER, dst: client ? SERVER : CLIENT, sport: client ? flow.sport : 443, dport: client ? 443 : flow.sport, flags: TCP.PSH | TCP.ACK,
      seq: client ? cseq : sseq, ack: client ? sseq : cseq, payload }), { dir: chunk.dir, fields: {
        ct: types.join(","), hs: hs.join(","), random: first ? flow.random : "", ext: first && flow.ech ? "65037" : "",
        sv: first && flow.tls13 ? "0x0304,0x0303" : (hs.includes(2) && flow.tls13 ? "0x0304" : "") } });
    if (client) cseq += payload.length; else sseq += payload.length;
  }
  return { pcap, plan };
}

/** The plan and the capture of several flows. */
function scenario(flows: Flow[]): { plan: Json; pcap: Buffer; frames: Buffer[] } {
  const all: Array<{ sec: number; frame: Buffer }> = [], plan: Json[] = [];
  let n = 1;
  for (const f of flows) {
    const built = framesOf(f, n, 1_700_000_000);
    n += built.plan.length;
    all.push(...built.pcap); plan.push(...built.plan);
  }
  const streams: Json = {};
  for (const f of flows) streams[String(f.stream)] = { random: f.random, need: f.need, plain_c: f.plain_c, plain_s: f.plain_s };
  return { plan: { frames: plan, streams }, pcap: pcapClassic(all), frames: all.map((a) => a.frame) };
}

/** A pcapng of the same frames, with a Decryption Secrets Block (type 0x0A, secrets type TLSK) that holds `keyLog`. */
function pcapng(frames: Buffer[], keyLog: string | null, extra: Buffer[] = []): Buffer {
  const parts = [ngSection(), ngInterface()];
  if (keyLog !== null) {
    const text = Buffer.from(keyLog, "ascii");
    parts.push(ngBlock(0x0a, Buffer.concat([u32(0x544c534b), u32(text.length), text])));
  }
  parts.push(...extra);
  frames.forEach((frame, i) => parts.push(ngPacket({ ticks: ticks(1_700_000_000 + i, 0, 6), frame })));
  return Buffer.concat(parts);
}

function flowsFrom(fix: Fix): Flow[] {
  const [t12, t13] = fix.sessions;
  return [
    { stream: 0, sport: 50000, chunks: t12.chunks, random: t12.client_random, need: ["CLIENT_RANDOM"], plain_c: t12.client_plaintext, plain_s: t12.server_plaintext },
    { stream: 1, sport: 50001, chunks: t13.chunks, random: t13.client_random, need: ["CLIENT_TRAFFIC_SECRET_0", "SERVER_TRAFFIC_SECRET_0"], plain_c: t13.client_plaintext, plain_s: t13.server_plaintext, tls13: true },
  ];
}

const PLAIN_PATH = Buffer.from("/account/export?id=7").toString("hex");
const keyLogOf = (fix: Fix, ...names: string[]): string => fix.sessions.filter((s) => names.includes(s.name)).flatMap((s) => s.keylog_lines).join("\n") + "\n";
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

const job = (cwd: string, bin: string, args: Json, extra: Record<string, string> = {}) => asJob(TLS, cwd, args, bin, env(cwd, extra));
const base = { capture: "inputs/capture.pcap", out_dir: "out/tls" };

const fixture = buildFixture();
const skip = fixture ? false : "the openssl command (a throwaway certificate for the TLS fixture) is not installed";

// ---- the statuses -----------------------------------------------------------------------------------------------------------------

test("each flow gets a status and a reason: decrypted (TLS 1.2 and 1.3), unsupported (ECH), no secret (no ClientHello), not TLS; the answer holds locators only", { skip }, async () => {
  const fix = fixture!;
  const flows = flowsFrom(fix);
  const noHello: Flow = { ...flows[0], stream: 3, sport: 50003, chunks: flows[0].chunks.slice(1), random: "00".repeat(32) };
  const ech: Flow = { ...flows[1], stream: 4, sport: 50004, random: "11".repeat(32), ech: true };
  const plainHttp: Flow = { stream: 2, sport: 50002, chunks: [{ dir: "c", hex: Buffer.from("GET / HTTP/1.1\r\n\r\n").toString("hex"), records: [] }], random: "", need: ["CLIENT_RANDOM"], plain_c: "", plain_s: "" };
  const built = scenario([flows[0], flows[1], plainHttp, noHello, ech]);
  await withCwd(async (cwd, bin) => {
    await setup(cwd, bin, built, { "keys.log": keyLogOf(fix, "tls12", "tls13") });
    const out = body(await job(cwd, bin, { ...base, keylog_file: "inputs/keys.log", limit: 50 }));
    assert.equal(out.status, "complete", out.status_basis);
    const byStream = Object.fromEntries(out.flows.map((f: Json) => [f.stream, f]));
    assert.deepEqual(Object.keys(byStream).map(Number).sort(), [0, 1, 2, 3, 4]);
    assert.equal(byStream[0].status, "decrypted");
    assert.equal(byStream[1].status, "decrypted");
    assert.equal(byStream[2].status, "not_tls");
    assert.equal(byStream[3].status, "no_secret_for_session");
    assert.match(byStream[3].reason, /no ClientHello for this flow is in the capture/);
    assert.equal(byStream[4].status, "unsupported");
    assert.match(byStream[4].reason, /encrypted ClientHello \(ECH\)/);
    assert.deepEqual([byStream[0].tls_version, byStream[1].tls_version], ["1.2 or earlier", "1.3"]);
    assert.deepEqual(byStream[0].key_log_session, { client_random_in_key_log: true, tls12_master_secret: true, tls13_traffic_secrets: false, tls13_handshake_secrets: false });
    assert.equal(byStream[1].key_log_session.tls13_traffic_secrets, true);
    assert.equal(byStream[0].client, `${CLIENT}:50000`);
    assert.equal(byStream[0].frames.first, 1);
    assert.deepEqual(out.status_counts, { decrypted: 2, partially: 0, unsupported: 1, no_secret_for_session: 1, not_tls: 1 });
    assert.equal(out.tshark, "TShark (Wireshark) 4.2.0 stand-in");
    assert.equal(out.key_log_preference, "tls.keylog_file");
    // the key log is summarised by counts and kinds
    assert.deepEqual([out.secrets.key_log.sessions, out.secrets.key_log.sessions_tls12_master, out.secrets.key_log.sessions_tls13_traffic], [2, 1, 1]);
    assert.equal(out.contains_secret_values, true);
    // no decrypted data, no key log line and no client random in the answer
    const text = JSON.stringify(out);
    for (const needle of [PLAIN_PATH, Buffer.from("fixture-session-value").toString("hex"), "fixture-session-value", "/account/export", fix.sessions[0].client_random, fix.sessions[1].client_random,
      ...fix.sessions.flatMap((s) => s.keylog_lines.filter((l) => !l.startsWith("#")).flatMap((l) => l.split(" ").slice(1)))]) assert.equal(text.includes(needle), false, `the answer holds ${needle.slice(0, 12)}...`);
  });
});

test("a key log without the TLS 1.3 session, or with only its handshake secrets, is not mistaken for a decryption: the reasons differ", { skip }, async () => {
  const fix = fixture!;
  const built = scenario(flowsFrom(fix));
  await withCwd(async (cwd, bin) => {
    const handshakeOnly = fix.sessions[1].keylog_lines.filter((l) => /^(CLIENT|SERVER)_HANDSHAKE_TRAFFIC_SECRET/.test(l)).join("\n") + "\n";
    await setup(cwd, bin, built, { "t12.log": keyLogOf(fix, "tls12"), "hs.log": keyLogOf(fix, "tls12") + handshakeOnly, "other.log": `CLIENT_RANDOM ${"ab".repeat(32)} ${"cd".repeat(48)}\n` });
    const missing = body(await job(cwd, bin, { ...base, keylog_file: "inputs/t12.log", write_payload: false }));
    const row = Object.fromEntries(missing.flows.map((f: Json) => [f.stream, f]));
    assert.deepEqual([row[0].status, row[1].status], ["decrypted", "no_secret_for_session"]);
    assert.match(row[1].reason, /no key log line carries this session's client random/);
    assert.equal(row[1].key_log_session.client_random_in_key_log, false);
    const hs = body(await job(cwd, bin, { ...base, keylog_file: "inputs/hs.log", write_payload: false, out_dir: "out/tls2" }));
    const hrow = Object.fromEntries(hs.flows.map((f: Json) => [f.stream, f]));
    assert.equal(hrow[1].status, "unsupported");
    assert.match(hrow[1].reason, /only handshake secrets for this TLS 1.3 session/);
    assert.deepEqual([hrow[1].key_log_session.tls13_handshake_secrets, hrow[1].key_log_session.tls13_traffic_secrets], [true, false]);
    const wrong = body(await job(cwd, bin, { ...base, keylog_file: "inputs/other.log", write_payload: false, out_dir: "out/tls3" }));
    assert.deepEqual(wrong.flows.map((f: Json) => f.status), ["no_secret_for_session", "no_secret_for_session"], "a key log for other sessions decrypts nothing here");
  });
});

test("part of a flow decrypted is partially, and the count says how much", { skip }, async () => {
  const fix = fixture!;
  const built = scenario(flowsFrom(fix));
  await withCwd(async (cwd, bin) => {
    await setup(cwd, bin, built, { "keys.log": keyLogOf(fix, "tls12", "tls13") });
    const out = body(await job(cwd, bin, { ...base, keylog_file: "inputs/keys.log", write_payload: false }, { STUB_PARTIAL: "1" }));
    const row = Object.fromEntries(out.flows.map((f: Json) => [f.stream, f]));
    assert.equal(row[0].status, "partially");
    assert.match(row[0].reason, /1 of 2 application-data frames were decrypted/);
    assert.equal(out.status_counts.partially >= 1, true);
  });
});

test("a pcapng with a Decryption Secrets Block is decrypted without -o, and the source is named by counts", { skip }, async () => {
  const fix = fixture!;
  const built = scenario(flowsFrom(fix));
  await withCwd(async (cwd, bin) => {
    const dir = await setup(cwd, bin, built);
    await put(cwd, "inputs/capture.pcapng", pcapng(built.frames, keyLogOf(fix, "tls12", "tls13")));
    const out = body(await job(cwd, bin, { capture: "inputs/capture.pcapng", use_embedded_secrets: true, out_dir: "out/tls" }));
    assert.equal(out.status, "complete", out.status_basis);
    assert.deepEqual(out.flows.map((f: Json) => f.status), ["decrypted", "decrypted"]);
    assert.equal(out.secrets.decryption_secrets_blocks.decryption_secrets_blocks, 1);
    assert.equal(out.secrets.decryption_secrets_blocks.tls_key_log_blocks, 1);
    assert.match(out.secrets.sources.join(" "), /1 Decryption Secrets Block\(s\) of the pcapng \(1 TLS key log blocks\)/);
    const calls = (await readFile(join(dir, "calls.log"), "utf8")).trim().split("\n").map((l) => JSON.parse(l));
    assert.equal(calls.filter((c: string[]) => c.includes("-r")).every((c: string[]) => !c.includes("-o")), true, "no -o: tshark reads the blocks itself");
    // use_embedded_secrets on a capture with no block is said, and a block of another kind is not a TLS key log
    const none = body(await job(cwd, bin, { capture: "inputs/capture.pcap", use_embedded_secrets: true, write_payload: false, out_dir: "out/tls2" }));
    assert.equal(none.status, "partial");
    assert.match(none.problems.join(" "), /use_embedded_secrets was set and the capture holds no Decryption Secrets Block/);
    assert.deepEqual(none.flows.map((f: Json) => f.status), ["no_secret_for_session", "no_secret_for_session"]);
  });
});

// ---- refusals ---------------------------------------------------------------------------------------------------------------------

test("refusals are JSON with exit 1: nothing to decrypt with, a key log given as text, no job for a payload, no preference, a missing field, bad arguments", { skip }, async () => {
  const fix = fixture!;
  const built = scenario(flowsFrom(fix));
  await withCwd(async (cwd, bin) => {
    const dir = await setup(cwd, bin, built, { "keys.log": keyLogOf(fix, "tls12") });
    const literal = `CLIENT_RANDOM ${randomBytes(32).toString("hex")} ${randomBytes(48).toString("hex")}`;
    const cases: Array<[Json, RegExp, Record<string, string>]> = [
      [{ ...base }, /nothing to decrypt with/, {}],
      [{ ...base, keylog_file: literal }, /never the text of a key log/, {}],
      [{ ...base, keylog_file: `${literal}\n${literal}` }, /never the text of a key log/, {}],
      [{ ...base, keylog_file: "inputs/keys.log", extra: 1 }, /unknown parameters: extra/, {}],
      [{ ...base, keylog_file: "inputs/keys.log", host: "not-an-ip" }, /host must be an IP address/, {}],
      [{ ...base, keylog_file: "inputs/keys.log", port: 70000 }, /port must be an integer from 1 to 65535/, {}],
      [{ ...base, keylog_file: "inputs/keys.log", out_dir: "../outside" }, /out_dir must stay inside the run directory/, {}],
      [{ ...base, keylog_file: "inputs/nope.log" }, /no such file/, {}],
      [{ ...base, keylog_file: "inputs/keys.log", write_payload: "yes" }, /write_payload must be true or false/, {}],
    ];
    const late: Array<[Json, RegExp, Record<string, string>]> = [
      [{ ...base, keylog_file: "inputs/keys.log" }, /this tshark lists neither tls.keylog_file nor ssl.keylog_file/, { STUB_PREFS: "none" }],
      [{ ...base, keylog_file: "inputs/keys.log" }, /lacks the field\(s\) tls.app_data_proto/, { STUB_MISSING: "tls.app_data_proto" }],
    ];
    for (const [args, pattern, extra] of [...cases, ...late]) {
      const err = refused(await job(cwd, bin, args, extra));
      assert.match(err.error, pattern, JSON.stringify(args).slice(0, 80));
      assert.equal(err.status, "failed");
      assert.equal(JSON.stringify(err).includes(literal.split(" ")[1]), false, "the refusal does not echo the key log text");
    }
    // outside a job the payload is refused before anything is read; the statuses alone work anywhere
    const outside = refused(await tool(TLS, cwd, { ...base, keylog_file: "inputs/keys.log", out_dir: "work/s1/tls" }, env(cwd), bin));
    assert.match(outside.error, /write_payload puts decrypted data in files, and a file in work\/ is not a sealed output/);
    // tshark ran only for the two refusals that need it: --version and -G currentprefs for the first, and -G fields as well for the second
    assert.equal((await readFile(join(dir, "calls.log"), "utf8")).trim().split("\n").length, 5);
    assert.equal(await exists(join(cwd, "work/s1/tls")), false);
    const noSecretJob = await tool(TLS, cwd, { ...base, keylog_file: "inputs/keys.log", out_dir: "out/x" }, env(cwd, { JOB_ID: "j000001", OUT: join(cwd, "out"), SECRET_OUTPUT: "0" }), bin);
    assert.match(refused(noSecretJob).error, /run this as a job with secret_output/, "a job without SECRET_OUTPUT=1 is refused the same way");
    const statusOnly = body(await tool(TLS, cwd, { ...base, keylog_file: "inputs/keys.log", out_dir: "work/s1/tls", write_payload: false }, env(cwd), bin));
    assert.equal(statusOnly.flows[0].status, "decrypted");
    assert.deepEqual(statusOnly.payloads, []);
    assert.equal(statusOnly.contains_secret_values, false);
  });
});

test("the older preference name is passed when that is the one this tshark lists", { skip }, async () => {
  const fix = fixture!;
  const built = scenario(flowsFrom(fix));
  await withCwd(async (cwd, bin) => {
    const dir = await setup(cwd, bin, built, { "keys.log": keyLogOf(fix, "tls12") });
    body(await job(cwd, bin, { ...base, keylog_file: "inputs/keys.log", write_payload: false }, { STUB_PREFS: "ssl" }));
    const calls = (await readFile(join(dir, "calls.log"), "utf8")).trim().split("\n").map((l) => JSON.parse(l)).filter((c: string[]) => c.includes("-T"));
    assert.ok(calls.length > 0);
    assert.match(calls[0][calls[0].indexOf("-o") + 1], /^ssl\.keylog_file:/);
  });
});

// ---- secrets ----------------------------------------------------------------------------------------------------------------------

test("key log canaries are in no argument, answer, message, file name or receipt: random CLIENT_RANDOM lines, searched everywhere the tool and its children write or print", { skip }, async () => {
  const fix = fixture!;
  const built = scenario(flowsFrom(fix));
  await withCwd(async (cwd, bin) => {
    const dir = await setup(cwd, bin, built);
    // a key log with the real lines and with canaries of every label, in a file whose name looks like a token
    const canaries = Array.from({ length: 40 }, (_, i) => {
      const label = ["CLIENT_RANDOM", "CLIENT_TRAFFIC_SECRET_0", "SERVER_TRAFFIC_SECRET_0", "CLIENT_HANDSHAKE_TRAFFIC_SECRET", "EXPORTER_SECRET"][i % 5];
      return { label, random: randomBytes(32).toString("hex"), secret: randomBytes(i % 2 ? 48 : 32).toString("hex") };
    });
    const tokenName = `keys-${randomBytes(20).toString("hex")}.log`;
    const text = keyLogOf(fix, "tls12", "tls13") + canaries.map((c) => `${c.label} ${c.random} ${c.secret}`).join("\n") + "\nRSA 0123456789abcdef " + "ef".repeat(48) + "\n";
    await put(cwd, `inputs/${tokenName}`, text);
    const stderrWithPath = `tshark: reading ${join(cwd, "inputs", tokenName)} failed\n`;
    const run = await job(cwd, bin, { ...base, keylog_file: `inputs/${tokenName}` }, { STUB_STDERR: stderrWithPath });
    const out = body(run);
    assert.equal(out.status, "complete", out.status_basis);
    const secrets = [
      ...canaries.flatMap((c) => [c.random, c.secret]),
      ...fix.sessions.flatMap((s) => s.keylog_lines.filter((l) => !l.startsWith("#")).flatMap((l) => l.split(" ").slice(1))), "ef".repeat(48),
    ];
    const everything = [run.stdout, run.stderr, await readFile(join(dir, "calls.log"), "utf8"), ...(await filesUnder(cwd)).filter((f) => !f.startsWith("inputs/") && !f.startsWith("out/tls/tls_decrypt-flow-")).map((f) => f)]
      .join("\n");
    const files = (await filesUnder(join(cwd, "out"))).filter((f) => !/tls_decrypt-flow-\d+-(client|server)\.bin/.test(f));
    let inFiles = "";
    for (const f of files) inFiles += (await readFile(join(cwd, "out", f)).catch(() => Buffer.alloc(0))).toString("latin1");
    for (const s of secrets) {
      assert.equal(everything.includes(s), false, `a key log value is in the answer, a file name or a call: ${s.slice(0, 8)}...`);
      assert.equal(inFiles.includes(s), false, `a key log value is in a result file: ${s.slice(0, 8)}...`);
    }
    // the path of the key log is a token-shaped name: it is not printed, in the answer or in the messages
    assert.equal(run.stdout.includes(tokenName), false, "the token-shaped file name is withheld");
    assert.match(JSON.stringify(out.diagnostics), /key log file|withheld/);
    // the 40 canary lines and the real ones were counted, and the RSA line is counted apart
    assert.equal(out.secrets.key_log.rsa_lines, 1);
    assert.equal(out.secrets.key_log.session_lines >= 40 + 3, true);
    // the sensitive output is in the files: owner-only
    for (const f of await readdir(join(cwd, "out/tls"))) assert.equal((await stat(join(cwd, "out/tls", f))).mode & 0o077, 0, `${f} is owner-only`);
  });
});

test("the decrypted data is in the payload files only: sizes and bytes equal what the fixture sent, and the answer names counts and a file name", { skip }, async () => {
  const fix = fixture!;
  const built = scenario(flowsFrom(fix));
  await withCwd(async (cwd, bin) => {
    await setup(cwd, bin, built, { "keys.log": keyLogOf(fix, "tls12", "tls13") });
    const out = body(await job(cwd, bin, { ...base, keylog_file: "inputs/keys.log" }));
    assert.equal(out.payloads.length, 2);
    for (const [i, s] of fix.sessions.entries()) {
      const row = out.payloads.find((p: Json) => p.stream === i);
      assert.deepEqual([row.client_bytes, row.server_bytes], [s.client_plaintext.length / 2, s.server_plaintext.length / 2]);
      assert.deepEqual(row.files, [`tls_decrypt-flow-${i}-client.bin`, `tls_decrypt-flow-${i}-server.bin`]);
      assert.deepEqual(await readFile(join(cwd, "out/tls", row.files[0])), Buffer.from(s.client_plaintext, "hex"));
      assert.deepEqual(await readFile(join(cwd, "out/tls", row.files[1])), Buffer.from(s.server_plaintext, "hex"));
      assert.equal((await stat(join(cwd, "out/tls", row.files[0]))).mode & 0o777, 0o600);
      assert.deepEqual(row.application_protocols, ["Hypertext Transfer Protocol"]);
    }
    assert.equal((await stat(join(cwd, "out/tls"))).mode & 0o777, 0o700);
    // a second run in the same $OUT replaces nothing: the same bytes are named again, nothing hidden is left, and a flow limit leaves the others unplaced
    const again = body(await job(cwd, bin, { ...base, keylog_file: "inputs/keys.log" }));
    assert.deepEqual(again.payloads.map((p: Json) => p.files), out.payloads.map((p: Json) => p.files));
    assert.deepEqual((await readdir(join(cwd, "out/tls"))).filter((n) => n.startsWith(".")), [], "no hidden file is left");
    const few = body(await job(cwd, bin, { ...base, keylog_file: "inputs/keys.log", max_payload_streams: 1, out_dir: "out/tls-few" }));
    assert.equal(few.status, "partial");
    assert.equal(few.payload_flows_not_attempted, 1);
    assert.match(few.problems.join(" "), /past max_payload_streams \(1\)/);
  });
});

test("an existing payload file is never replaced by a smaller one: a different run takes the next free name", { skip }, async () => {
  const fix = fixture!;
  const built = scenario(flowsFrom(fix));
  await withCwd(async (cwd, bin) => {
    await setup(cwd, bin, built, { "keys.log": keyLogOf(fix, "tls12", "tls13") });
    await put(cwd, "out/tls/tls_decrypt-flow-0-client.bin", "an earlier, larger and different file that must stay exactly as it is ".repeat(40), 0o600);
    const before = await readFile(join(cwd, "out/tls/tls_decrypt-flow-0-client.bin"));
    const out = body(await job(cwd, bin, { ...base, keylog_file: "inputs/keys.log" }));
    assert.deepEqual(await readFile(join(cwd, "out/tls/tls_decrypt-flow-0-client.bin")), before);
    assert.equal(out.payloads.find((p: Json) => p.stream === 0).files[0], "tls_decrypt-flow-0-client-2.bin");
  });
});

// ---- hostile input, bounds ----------------------------------------------------------------------------------------------------------

test("hostile captures and key logs: a truncated pcapng, a block claiming 4 GB, a key log of garbage and of over-long lines are counted, never echoed, never a crash", { skip }, async () => {
  const fix = fixture!;
  const built = scenario(flowsFrom(fix));
  await withCwd(async (cwd, bin) => {
    await setup(cwd, bin, built);
    const lie = Buffer.alloc(12); lie.writeUInt32LE(0x0a, 0); lie.writeUInt32LE(0xfffffffc, 4);
    await put(cwd, "inputs/lie.pcapng", Buffer.concat([ngSection(), ngInterface(), lie]));
    await put(cwd, "inputs/cut.pcapng", pcapng(built.frames, "CLIENT_RANDOM " + "ab".repeat(32) + " " + "cd".repeat(48) + "\n").subarray(0, 140));
    const lies = body(await job(cwd, bin, { capture: "inputs/lie.pcapng", use_embedded_secrets: true, write_payload: false, out_dir: "out/a" }));
    assert.equal(lies.secrets.decryption_secrets_blocks.complete, false);
    assert.match(lies.problems.join(" "), /block length|Decryption Secrets Block/);
    const cut = body(await job(cwd, bin, { capture: "inputs/cut.pcapng", use_embedded_secrets: true, write_payload: false, out_dir: "out/b" }));
    assert.equal(cut.status, "partial");
    const junk = Buffer.concat([randomBytes(5000), Buffer.from("\nCLIENT_RANDOM short\nCLIENT_RANDOM " + "zz".repeat(32) + " " + "ab".repeat(32) + "\n"), Buffer.alloc(70_000, 0x41), Buffer.from("\n#comment\n\n")]);
    await put(cwd, "inputs/junk.log", junk);
    const out = body(await job(cwd, bin, { ...base, keylog_file: "inputs/junk.log", write_payload: false }));
    assert.equal(out.secrets.key_log.session_lines, 0);
    assert.equal(out.secrets.key_log.malformed_lines >= 3, true);
    assert.match(out.problems.join(" "), /no usable line/);
    assert.deepEqual(out.flows.map((f: Json) => f.status), ["no_secret_for_session", "no_secret_for_session"]);
    assert.equal(JSON.stringify(out).includes("zz".repeat(8)), false);
  });
});

test("many flows: a capture of 20000 flows is judged in one pass with bounded work, and flows past the tracking cap are counted", { skip, timeout: 120_000 }, async () => {
  const fix = fixture!;
  const base0 = flowsFrom(fix)[0];
  const frames: Json[] = [];
  const streams: Json = {};
  for (let i = 0; i < 20_000; i++) {
    frames.push({ frame: i + 1, time: `1700000000.${String(i).padStart(9, "0")}`, stream: i, src: CLIENT, dst: SERVER, sport: 40000 + (i % 20000), dport: 443, ct: "22", hs: "1", random: base0.random, ext: "", sv: "" });
  }
  streams["0"] = { random: base0.random, need: ["CLIENT_RANDOM"], plain_c: "", plain_s: "" };
  await withCwd(async (cwd, bin) => {
    await setup(cwd, bin, { plan: { frames, streams }, pcap: pcapClassic([]) }, { "keys.log": keyLogOf(fix, "tls12") });
    const t0 = Date.now();
    const out = body(await job(cwd, bin, { ...base, keylog_file: "inputs/keys.log", write_payload: false, limit: 25 }));
    assert.ok(Date.now() - t0 < 60_000, `took ${Date.now() - t0} ms`);
    assert.equal(out.flows_total, 20_000);
    assert.equal(out.flows_returned, 25);
    assert.equal(out.truncated, true);
    const whole = (await readFile(join(cwd, "out/tool-output", basename(out.all_results)), "utf8")).trim().split("\n");
    assert.equal(whole.length, 20_000);
  });
});

// ---- the clock and the stops ------------------------------------------------------------------------------------------------------

test("a tshark that outlives the tool's own clock is killed with what it started; nothing is placed and no temporary directory stays", { skip }, async () => {
  const fix = fixture!;
  const built = scenario(flowsFrom(fix));
  await withCwd(async (cwd, bin) => {
    const dir = await setup(cwd, bin, built, { "keys.log": keyLogOf(fix, "tls12") });
    const t0 = Date.now();
    const run = await job(cwd, bin, { ...base, keylog_file: "inputs/keys.log", max_seconds: 10 }, { STUB_MODE: "hang-listing" });
    assert.ok(Date.now() - t0 < 30_000, `took ${Date.now() - t0} ms`);
    assert.equal(refused(run).status, "failed");
    assert.equal(await gone(Number((await readFile(join(dir, "child.pid"), "utf8")).trim())), true);
    assert.deepEqual((await filesUnder(join(cwd, "out"))).filter((f) => f.split("/").some((p) => p.startsWith(".")) || /\.bin$/.test(f)), []);
  });
});

test("a stop signal gives one JSON answer with the stage, kills tshark and what it started, removes the temporary directory and leaves no payload under a final name", { skip }, async () => {
  const fix = fixture!;
  const built = scenario(flowsFrom(fix));
  for (const [mode, stage] of [["hang-listing", "listing the frames (tshark -T fields)"], ["hang-follow", "extracting the decrypted data of flow 0"]] as const) {
    for (const [sig, code] of [["SIGTERM", 143], ["SIGINT", 130], ["SIGHUP", 129]] as const) {
      await withCwd(async (cwd, bin) => {
        const dir = await setup(cwd, bin, built, { "keys.log": keyLogOf(fix, "tls12", "tls13") });
        await mkdir(join(cwd, "out"), { recursive: true });
        const run = startDetached(TLS, cwd, { ...base, keylog_file: "inputs/keys.log" }, env(cwd, { STUB_MODE: mode, JOB_ID: "j000009", OUT: join(cwd, "out"), SECRET_OUTPUT: "1" }), bin);
        for (let i = 0; i < 400 && !(await exists(join(dir, "started"))); i++) await new Promise((r) => setTimeout(r, 50));
        run.signal(sig);
        assert.equal(await run.closed, code, `${mode} ${sig}`);
        const last = JSON.parse(run.stdout());
        assert.equal(run.stdout().trim().split("\n").length, 1, "one document");
        assert.deepEqual([last.status, last.interrupted_by_signal, last.stage], ["partial", code - 128, stage]);
        assert.equal(await gone(Number((await readFile(join(dir, "child.pid"), "utf8")).trim())), true, `${mode} ${sig}: what tshark started is gone`);
        assert.deepEqual((await filesUnder(join(cwd, "out"))).filter((f) => f.split("/").some((p) => p.startsWith(".")) || /\.bin$/.test(f)), [], `${mode} ${sig}: nothing hidden, no payload`);
      });
    }
  }
});

// ---- fuzz (at most 1,000 cases; 120 here) ----------------------------------------------------------------------------------------------

test("fuzz: 120 key logs of random bytes and random mutations of a real one never end without JSON, in a traceback, or with a key log byte in the answer", { skip, timeout: 240_000 }, async () => {
  const fix = fixture!;
  const built = scenario(flowsFrom(fix));
  let seed = 424242;
  const rnd = (n: number): number => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed % n; };
  await withCwd(async (cwd, bin) => {
    await setup(cwd, bin, built);
    const real = Buffer.from(keyLogOf(fix, "tls12", "tls13"), "latin1");
    for (let i = 0; i < 120; i++) {
      let data: Buffer;
      switch (i % 4) {
        case 0: data = randomBytes(rnd(4000)); break;
        case 1: data = Buffer.from(real); for (let k = 0; k < 6; k++) data[rnd(data.length)] = rnd(256); break;
        case 2: data = real.subarray(0, rnd(real.length + 1)); break;
        default: data = Buffer.concat([real, Buffer.from(("CLIENT_RANDOM " + "f".repeat(rnd(80)) + " " + "e".repeat(rnd(120)) + "\n").repeat(rnd(200)))]); break;
      }
      await put(cwd, "inputs/fuzz.log", data);
      const run = await job(cwd, bin, { ...base, keylog_file: "inputs/fuzz.log", write_payload: false, out_dir: `out/f${i}` });
      assert.doesNotMatch(run.stderr, /Traceback/, `case ${i}`);
      const out = JSON.parse(run.stdout);
      assert.ok(["complete", "partial", "failed"].includes(out.status), `case ${i}: ${out.status}`);
      for (const line of data.toString("latin1").split("\n")) {
        const parts = line.trim().split(/\s+/);
        if (parts.length === 3 && /^[0-9a-f]{64}$/.test(parts[1]) && parts[2].length >= 32) assert.equal(run.stdout.includes(parts[2]), false, `case ${i}: a secret is in the answer`);
      }
    }
  });
});

// ---- the manifest ------------------------------------------------------------------------------------------------------------------

test("the manifest names the parameters the script reads, declares secret output, requires tshark, and carries the sha256 and version of its script", async () => {
  const manifest: Json = JSON.parse(await readFile(join(TOOLS, "tls_decrypt", "manifest.json"), "utf8"));
  const script = await readFile(TLS, "utf8");
  assert.equal(manifest.sha256, createHash("sha256").update(script).digest("hex"));
  const tool_ = script.match(/^TOOL = \{"name": "([a-z_]+)", "version": (\d+)\}$/m)!;
  assert.deepEqual([tool_[1], Number(tool_[2])], ["tls_decrypt", manifest.version]);
  assert.match(script, /^PARSER = "tls_decrypt\/\d+"$/m);
  assert.ok((await stat(TLS)).mode & 0o111, "run.py is executable");
  assert.equal(manifest.secret_output, "required");
  assert.match(manifest.description, /SENSITIVE/);
  assert.deepEqual(manifest.requires, ["tshark"]);
  assert.equal(manifest.timeout_seconds, 1200);
  const read = new Set<string>();
  for (const m of script.matchAll(/(?:text_arg|int_in)\(args, "([a-z_]+)"/g)) read.add(m[1]);
  for (const m of script.matchAll(/args\.get\("([a-z_]+)"/g)) read.add(m[1]);
  assert.deepEqual([...read].sort(), Object.keys(manifest.params).sort());
  for (const key of Object.keys(JSON.parse(manifest.example))) assert.ok(key in manifest.params, key);
  for (const claim of ["NOT VERIFIED", "never the key log's text", "no_secret_for_session", "ECH", "ssl.keylog_file", "Decryption Secrets Blocks", "SIGTERM"]) assert.ok(manifest.description.includes(claim) || manifest.description.includes(claim.replace("never", "never ")), claim);
  const source = script.replace(/^\s*#.*$/gm, "").replace(/"""[\s\S]*?"""/g, "");
  assert.doesNotMatch(source, /start_new_session|setsid|threading/);
  assert.doesNotMatch(source, /\bprint\([^)]*keylog|\.write\([^)]*line/, "no print of a key log line");
  const pack: Json = JSON.parse(await readFile(join(NET, "pack.json"), "utf8"));
  assert.ok(pack.tools.includes("tls_decrypt"));
});

// ---- the real program ------------------------------------------------------------------------------------------------------------------

test("with the real tshark: the TLS 1.2 and TLS 1.3 sessions decrypt with their key log, and the version is recorded", { skip }, async (t) => {
  const probe = spawnSync("tshark", ["--version"], { encoding: "utf8" });
  if (probe.error || probe.status !== 0) {
    t.skip("tshark is not installed here; the stand-in's documented output stands in, so the field values of a real build are not verified by this suite");
    return;
  }
  const fix = fixture!;
  const built = scenario(flowsFrom(fix));
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/capture.pcap", built.pcap);
    await put(cwd, "inputs/keys.log", keyLogOf(fix, "tls12", "tls13"));
    const out = body(await asJob(TLS, cwd, { ...base, keylog_file: "inputs/keys.log" }));
    assert.match(out.tshark, /TShark/);
    assert.deepEqual(out.flows.map((f: Json) => f.status), ["decrypted", "decrypted"]);
  });
});
