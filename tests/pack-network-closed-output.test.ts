/**
 * network-forensics: a tshark that closes its standard output and goes on running does not hold a tool past its own clock.
 *
 * pcap_extract (the field list and the association listing), conn_series, quic_inspect and tls_decrypt (their one stream_program text)
 * and the network-capture recipe (its field list) read tshark's pipe themselves and then wait for tshark. A program that closed the pipe
 * and kept running was waited for without a bound, so the tool answered only when the harness killed it. The stand-in here prints what it
 * is asked for, writes its pid, closes its standard output and sleeps: the answer must come within the tool's clock and a small grace, be
 * one JSON document that is not complete, and the stand-in must be gone. The stand-in proves nothing about a real tshark's output.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { PYTHON3 } from "./host-gates.ts";
import { CONNS, EXTRACT, QUICI, RECIPE, TLSD, frameUdp4, gone, pcapClassic, put, stub, tool, withCwd } from "./pack-network-harness.ts";
import type { Json, Run } from "./pack-network-harness.ts";

// The fields the stand-in lists for `-G fields`: those conn_series, quic_inspect and tls_decrypt read (the recipe and pcap_extract cases
// make the field list itself the one that closes, or fail it, so its content does not matter there).
const FIELDS = ["frame.number", "frame.time_epoch", "frame.len", "frame.interface_id", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst", "tcp.srcport", "tcp.dstport",
  "udp.srcport", "udp.dstport", "tcp.flags", "tcp.seq_raw", "tcp.stream", "quic.header_form", "quic.long.packet_type", "quic.long.packet_type_v2", "quic.version",
  "quic.dcid", "quic.scid", "quic.token_length", "quic.frame_type", "quic.stream.stream_id", "tls.handshake.extensions_server_name",
  "tls.handshake.extensions_alpn_str", "tls.record.content_type", "tls.handshake.type", "tls.handshake.random", "tls.handshake.extension.type",
  "tls.handshake.extensions.supported_version", "tls.app_data_proto"];

// STUB_CLOSE names the call that closes its output and sleeps: "fields" (tshark -G fields) or "listing" (tshark -T fields).
// STUB_FIELDS_FAIL makes -G fields exit 1 (pcap_extract then asks for its fields unchecked and goes on to the listing).
const TSHARK = `#!/usr/bin/env python3
import os, sys, time
d = os.environ["STUB_DIR"]
args = sys.argv[1:]
FIELDS = ${JSON.stringify(FIELDS)}
def close_and_sleep():
    open(os.path.join(d, "tshark.pid"), "w").write(str(os.getpid()))
    sys.stdout.flush()
    os.close(1)
    time.sleep(300)
    sys.exit(0)
if args[:1] == ["--version"]:
    print("TShark (Wireshark) 4.4.0 stand-in"); sys.exit(0)
if args[:2] == ["-G", "currentprefs"]:
    print("#tls.keylog_file:"); sys.exit(0)
if args[:2] == ["-G", "fields"]:
    if os.environ.get("STUB_FIELDS_FAIL"):
        sys.exit(1)
    for n in FIELDS:
        print("F\\tName of " + n + "\\t" + n + "\\tFT_STRING\\tproto\\t\\t0x0\\t")
    if os.environ.get("STUB_CLOSE") == "fields":
        close_and_sleep()
    sys.exit(0)
if "--export-objects" in args:
    spec = args[args.index("--export-objects") + 1]
    if spec == "help":
        sys.stderr.write('tshark: The available export object types for the "--export-objects" option are:\\n    http\\n'); sys.exit(0)
    dest = spec.split(",", 1)[1]
    open(os.path.join(dest, "object.bin"), "wb").write(b"X" * 300)
    sys.exit(0)
if "-T" in args:
    cols = [args[i + 1] for i, a in enumerate(args) if a == "-e"]
    row = {"frame.number": "1", "frame.time_epoch": "1700000000.000000", "frame.len": "60", "ip.src": "10.0.0.5", "ip.dst": "203.0.113.7",
           "udp.srcport": "41000", "udp.dstport": "53"}
    if "header=y" in args:
        print("\\t".join(cols))
    else:
        print("\\t".join(row.get(c, "") for c in cols))
    if os.environ.get("STUB_CLOSE") == "listing":
        close_and_sleep()
    sys.exit(0)
sys.exit(0)
`;

const CAPINFOS = `#!/bin/sh
case "$1" in --version) echo 'Capinfos (Wireshark) 4.2.0 (stand-in)'; exit 0;; esac
echo "File name: stand-in"
exit 0
`;

async function stage(cwd: string, bin: string): Promise<string> {
  const dir = join(cwd, "stub");
  await mkdir(dir, { recursive: true });
  await stub(bin, "tshark", TSHARK);
  await stub(bin, "capinfos", CAPINFOS);
  // A key log line of the NSS form whose values are zeros and ones: synthetic, it opens nothing.
  await put(cwd, "inputs/keys.log", `CLIENT_RANDOM ${"00".repeat(32)} ${"11".repeat(48)}\n`);
  await put(cwd, "inputs/capture.pcap", pcapClassic([{ sec: 1_700_000_000, frame: frameUdp4({ src: "10.0.0.5", dst: "203.0.113.7", sport: 41000, dport: 53, payload: "x" }) }]));
  return dir;
}

/** The answer, how long it took, and whether the stand-in that closed its output is gone. */
async function timed(run: () => Promise<Run>, dir: string): Promise<{ out: Run; ms: number; standInGone: boolean }> {
  const began = Date.now();
  const out = await run();
  const ms = Date.now() - began;
  const pid = Number((await readFile(join(dir, "tshark.pid"), "utf8")).trim());
  assert.ok(pid > 0, "the stand-in wrote its pid, so it was the call that closed its output");
  return { out, ms, standInGone: await gone(pid, 5_000) };
}

function oneAnswer(out: Run): Json {
  assert.doesNotMatch(out.stderr, /Traceback/);
  return JSON.parse(out.stdout);     // one JSON document (it may span lines): a second one, or none, does not parse
}

const GRACE_MS = 4_000;   // the interpreter's start, the answer and a loaded host, above the tool's own clock

test("pcap_extract: a tshark -G fields that closes its output and goes on running is ended at the clock; the answer is partial", async () => {
  await withCwd(async (cwd, bin) => {
    const dir = await stage(cwd, bin);
    const { out, ms, standInGone } = await timed(() => tool(EXTRACT, cwd, { path: "inputs/capture.pcap", out_dir: "work/s1/x", protocols: ["http"], timeout_seconds: 8 },
      { STUB_DIR: dir, STUB_CLOSE: "fields" }, bin), dir);
    assert.ok(ms < 8_000 + GRACE_MS, `answered after ${ms} ms`);
    const answer = oneAnswer(out);
    assert.equal(answer.status, "partial", answer.status_basis);
    assert.match(JSON.stringify(answer), /tshark -G fields did not finish in time/);
    assert.equal(standInGone, true);
  });
});

test("pcap_extract: an association listing that closes its output and goes on running is killed at the deadline; the answer is partial", async () => {
  await withCwd(async (cwd, bin) => {
    const dir = await stage(cwd, bin);
    const { out, ms, standInGone } = await timed(() => tool(EXTRACT, cwd, { path: "inputs/capture.pcap", out_dir: "work/s1/x", protocols: ["http"], timeout_seconds: 8 },
      { STUB_DIR: dir, STUB_CLOSE: "listing", STUB_FIELDS_FAIL: "1" }, bin), dir);
    assert.ok(ms < 8_000 + GRACE_MS, `answered after ${ms} ms`);
    const answer = oneAnswer(out);
    assert.equal(answer.status, "partial", answer.status_basis);
    assert.match(JSON.stringify(answer), /the listing pass was killed at the shared deadline/);
    assert.equal(standInGone, true);
  });
});

for (const [name, script, args] of [
  ["conn_series", CONNS, { capture: "inputs/capture.pcap", max_seconds: 10 }],
  ["quic_inspect", QUICI, { capture: "inputs/capture.pcap", max_seconds: 10 }],
  ["tls_decrypt", TLSD, { capture: "inputs/capture.pcap", keylog_file: "inputs/keys.log", out_dir: "work/s1/t", write_payload: false, max_seconds: 10 }],
] as const) {
  test(`${name}: a listing that closes its output and goes on running is timed out at the clock, not waited for; the answer is not complete`, async () => {
    await withCwd(async (cwd, bin) => {
      const dir = await stage(cwd, bin);
      const { out, ms, standInGone } = await timed(() => tool(script, cwd, args, { STUB_DIR: dir, STUB_CLOSE: "listing" }, bin), dir);
      assert.ok(ms < 10_000 + GRACE_MS, `answered after ${ms} ms`);
      const answer = oneAnswer(out);
      assert.notEqual(answer.status, "complete", answer.status_basis);
      assert.match(JSON.stringify(answer), /timed out|did not finish before (its share of )?the tool's own clock/);
      assert.equal(standInGone, true);
    });
  });
}

test("conn_series: a tshark -G fields that closes its output and goes on running is ended at the clock (the stream_program the three tools share)", async () => {
  await withCwd(async (cwd, bin) => {
    const dir = await stage(cwd, bin);
    const { out, ms, standInGone } = await timed(() => tool(CONNS, cwd, { capture: "inputs/capture.pcap", max_seconds: 10 }, { STUB_DIR: dir, STUB_CLOSE: "fields" }, bin), dir);
    assert.ok(ms < 10_000 + GRACE_MS, `answered after ${ms} ms`);
    const answer = oneAnswer(out);
    assert.notEqual(answer.status, "complete", answer.status_basis);
    assert.equal(standInGone, true);
  });
});

function recipe(cwd: string, bin: string, argv: string[], env: Record<string, string>): Promise<Run> {
  return new Promise((resolve, reject) => {
    const child = spawn(PYTHON3, [RECIPE, ...argv], { cwd, env: { ...process.env, PATH: `${bin}:${process.env.PATH ?? ""}`, ...env } });
    const out: Buffer[] = [], err: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => out.push(c));
    child.stderr.on("data", (c: Buffer) => err.push(c));
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stdout: Buffer.concat(out).toString("utf8"), stderr: Buffer.concat(err).toString("utf8") }));
    child.stdin.end();
  });
}

test("network-capture recipe: a tshark -G fields that closes its output and goes on running is ended at the recipe's clock; the receipt is partial", async () => {
  await withCwd(async (cwd, bin) => {
    const dir = await stage(cwd, bin);
    const target = JSON.stringify({ paths: ["inputs/capture.pcap"] });
    const { out, ms, standInGone } = await timed(() => recipe(cwd, bin, ["run", "--target", target, "--out", "work/cat"],
      { STUB_DIR: dir, STUB_CLOSE: "fields", NETWORK_CAPTURE_SECONDS: "6" }), dir);
    assert.ok(ms < 6_000 + GRACE_MS, `answered after ${ms} ms`);
    const answer = oneAnswer(out);
    assert.equal(answer.status, "partial", answer.status_basis);
    const coverage = JSON.parse(await readFile(join(cwd, "work", "cat", "coverage.json"), "utf8"));
    assert.equal(coverage.status, "partial");
    assert.match(JSON.stringify(coverage.steps), /tshark -G fields did not finish in time/);
    assert.equal(standInGone, true);
  });
});
