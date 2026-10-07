/**
 * network-forensics: pcap_summary reads a file the evidence supplied, so a damaged capture must end in the tool's own
 * JSON, whatever is wrong with it. A seeded mutation fuzz (the seed is fixed, so a failure repeats): captures built
 * from the pcap and pcapng layouts are damaged byte by byte, cut and padded, and every run must exit 0 or 1, print one
 * JSON document, and never a Python traceback.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { SUMMARY, TCP, drop, frameTcp4, frameTcp6, frameUdp4, ngInterface, ngPacket, ngSection, ngStats, pcapClassic, ticks, tool, withCwd } from "./pack-network-harness.ts";

function prng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const frames = [
  frameTcp4({ src: "10.0.0.5", dst: "203.0.113.7", sport: 50000, dport: 443, flags: TCP.SYN, seq: 1 }),
  frameTcp4({ src: "203.0.113.7", dst: "10.0.0.5", sport: 443, dport: 50000, flags: TCP.SYN | TCP.ACK, seq: 9, ack: 2 }),
  frameTcp6({ src: "2001:db8::1", dst: "2001:db8::2", sport: 40000, dport: 80, flags: TCP.PSH | TCP.ACK, payload: "hello" }),
  frameUdp4({ src: "10.0.0.5", dst: "10.0.0.1", sport: 5353, dport: 53, payload: "q" }),
];

const classic = (): Buffer => pcapClassic(frames.map((frame, i) => ({ sec: 1_700_000_000 + i, frac: i * 10, frame })));
const pcapng = (): Buffer => Buffer.concat([
  ngSection(), ngInterface({ snaplen: 65535 }),
  ...frames.map((frame, i) => ngPacket({ ticks: ticks(1_700_000_000 + i, 5, 6), frame })),
  ngStats({ recv: 4n, drop: 0n }),
]);

test("two hundred damaged captures end in JSON, never in a traceback", async () => {
  await withCwd(async (cwd) => {
    const random = prng(20261007);
    const pick = (n: number): number => Math.floor(random() * n);
    for (let n = 0; n < 200; n++) {
      const data = Buffer.from((n % 2 ? pcapng() : classic()));
      let bytes = data;
      for (let k = 1 + pick(6); k > 0; k--) {
        const mode = random();
        if (mode < 0.6) {
          bytes = Buffer.from(bytes);
          bytes[pick(bytes.length)] = pick(256);
        } else if (mode < 0.8) {
          bytes = bytes.subarray(0, 1 + pick(bytes.length - 1));
        } else {
          const at = pick(bytes.length);
          bytes = Buffer.concat([bytes.subarray(0, at), Buffer.from(Array.from({ length: 1 + pick(8) }, () => pick(256))), bytes.subarray(at)]);
        }
      }
      const path = await drop(cwd, `work/f${n}.pcap`, bytes);
      const run = await tool(SUMMARY, cwd, { path }, {});
      assert.doesNotMatch(run.stderr, /Traceback/, `case ${n}: ${run.stderr.slice(-300)}`);
      assert.ok(run.code === 0 || run.code === 1, `case ${n} exited ${run.code}`);
      assert.doesNotThrow(() => JSON.parse(run.stdout), `case ${n} printed no JSON`);
    }
  });
});
