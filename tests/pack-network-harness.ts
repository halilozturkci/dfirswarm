/**
 * Helpers the network-forensics suites share: running a pack tool as a call and as a job (JOB_ID and OUT set,
 * the way the job service runs it), builders for classic pcap and pcapng files, Ethernet/IP/TCP/UDP frames and
 * the stand-in programs (tshark, zeek, suricata) the tools drive.
 *
 * Every capture here is built from the file formats' own layouts (the pcap savefile format and the pcapng
 * block structure; RFC 791, RFC 8200, RFC 9293 and RFC 768 for the headers), never from a tool's output. The
 * stand-in programs print what the programs' documentation says they print; none of them proves anything about
 * a real tshark, Zeek or Suricata, and the suites say so where it matters.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { chmod, mkdir, readFile, readdir, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { ROOT, runPy } from "./tool-library-harness.ts";
export { withCwd } from "./tool-library-harness.ts";

export const NET = join(ROOT, "packs", "network-forensics");
export const TOOLS = join(NET, "tools");
export const SUMMARY = join(TOOLS, "pcap_summary", "run.py");
export const BEACON = join(TOOLS, "beacon_score", "run.py");
export const ZEEK = join(TOOLS, "zeek_run", "run.py");
export const SURICATA = join(TOOLS, "suricata_run", "run.py");
export const EXTRACT = join(TOOLS, "pcap_extract", "run.py");
export const LOGS = join(TOOLS, "network_log_summary", "run.py");
export const RECIPE = join(NET, "recipes", "network-capture", "run.py");
export const AGENT = { AGENT_ID: "s1" };

export type Run = { code: number | null; stdout: string; stderr: string };
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type Json = any;

export async function tool(script: string, cwd: string, args: unknown, env: Record<string, string> = {}, bin?: string): Promise<Run> {
  return runPy(script, cwd, args, bin, { ...AGENT, ...env });
}

let jobs = 0;
/** The tool as a job runs it: JOB_ID and OUT set, OUT inside the run directory (`out`, or the directory named). */
export async function asJob(script: string, cwd: string, args: unknown, bin?: string, env: Record<string, string> = {}, outName = "out"): Promise<Run> {
  await mkdir(join(cwd, outName), { recursive: true });
  jobs += 1;
  return tool(script, cwd, args, { JOB_ID: `j${String(jobs).padStart(6, "0")}`, OUT: join(cwd, outName), ...env }, bin);
}

export function body(out: Run): Json {
  assert.equal(out.code, 0, out.stderr + out.stdout);
  assert.doesNotMatch(out.stderr, /Traceback/);
  return JSON.parse(out.stdout);
}

/** An answer that is a refusal: a JSON error and a nonzero exit, never a traceback. */
export function refused(out: Run): Json {
  assert.notEqual(out.code, 0, out.stdout);
  assert.doesNotMatch(out.stderr, /Traceback/);
  return JSON.parse(out.stdout);
}

/**
 * A tool started the way the harness starts one (extensions/protocol-core.ts, runForgedTool): in a process group
 * of its own (`detached`), ended by killing that group with SIGKILL. A program the tool started in a session of
 * its own is not in that group and outlives it; one started in the tool's own group is ended with it.
 */
export function startDetached(script: string, cwd: string, args: unknown, env: Record<string, string> = {}, bin?: string, argv: string[] = []): { pid: number; closed: Promise<number | null>; stdout: () => string; killGroup: () => void; signal: (s: NodeJS.Signals) => void } {
  const child = spawn("python3", [script, ...argv], { cwd, env: { ...process.env, ...(bin ? { PATH: `${bin}:${process.env.PATH ?? ""}` } : {}), ...AGENT, ...env }, detached: true, stdio: ["pipe", "pipe", "pipe"] });
  const chunks: Buffer[] = [];
  child.stdout.on("data", (c: Buffer) => chunks.push(c));
  child.stderr.on("data", () => undefined);
  child.stdin.end(JSON.stringify(args));
  const closed = new Promise<number | null>((resolve) => child.on("close", (code) => resolve(code)));
  return {
    pid: child.pid as number,
    closed,
    stdout: () => Buffer.concat(chunks).toString("utf8"),
    killGroup: () => process.kill(-(child.pid as number), "SIGKILL"),
    signal: (sig) => process.kill(child.pid as number, sig),
  };
}

/** Whether a process is gone, giving it a moment (a killed process is reaped by its parent or by init). */
export async function gone(pid: number, waitMs = 1500): Promise<boolean> {
  const until = Date.now() + waitMs;
  for (;;) {
    try {
      process.kill(pid, 0);
    } catch {
      return true;
    }
    if (Date.now() > until) return false;
    await new Promise((r) => setTimeout(r, 50));
  }
}

/** Read a pid a stand-in wrote, waiting for it. */
export async function pidFile(path: string, waitMs = 5000): Promise<number> {
  const until = Date.now() + waitMs;
  for (;;) {
    const text = await readFile(path, "utf8").catch(() => "");
    if (text.trim()) return Number(text.trim());
    if (Date.now() > until) throw new Error(`no pid in ${path}`);
    await new Promise((r) => setTimeout(r, 50));
  }
}

export async function exists(path: string): Promise<boolean> {
  return stat(path).then(() => true, () => false);
}

/** Every file under a directory, relative to it. */
export async function filesUnder(dir: string): Promise<string[]> {
  const out: string[] = [];
  const walk = async (d: string, prefix: string): Promise<void> => {
    for (const e of await readdir(d, { withFileTypes: true }).catch(() => [])) {
      if (e.isDirectory()) await walk(join(d, e.name), `${prefix}${e.name}/`);
      else out.push(`${prefix}${e.name}`);
    }
  };
  await walk(dir, "");
  return out.sort();
}

/** What a call left where an agent reads it, as one string: the answer and every file under the named directories. */
export async function everythingUnder(cwd: string, answer: string, dirs: string[], skip: string[] = []): Promise<string> {
  const parts = [answer];
  for (const d of dirs) {
    for (const f of await filesUnder(join(cwd, d))) {
      if (skip.includes(`${d}/${f}`)) continue;
      parts.push(`${d}/${f}\n` + (await readFile(join(cwd, d, f)).then((b) => b.toString("latin1"), () => "")));
    }
  }
  return parts.join("\n");
}

export async function put(root: string, rel: string, text: string | Buffer, mode?: number): Promise<void> {
  const full = join(root, rel);
  await mkdir(join(full, ".."), { recursive: true });
  await writeFile(full, text);
  if (mode !== undefined) await chmod(full, mode);
}

/** An executable stand-in for a program, written into `bin`. */
export async function stub(bin: string, name: string, script: string): Promise<void> {
  const path = join(bin, name);
  await writeFile(path, script.startsWith("#!") ? script : `#!/bin/sh\n${script}`);
  await chmod(path, 0o755);
}

// --- frames --------------------------------------------------------------------------------------------------

function ip4(address: string): Buffer {
  return Buffer.from(address.split(".").map((n) => Number(n)));
}

export function ip6(address: string): Buffer {
  // Full or `::`-compressed text to 16 bytes.
  const [head, tail] = address.split("::");
  const left = head ? head.split(":") : [];
  const right = tail !== undefined && tail ? tail.split(":") : [];
  const groups = [...left, ...Array(address.includes("::") ? 8 - left.length - right.length : 0).fill("0"), ...right];
  const out = Buffer.alloc(16);
  groups.forEach((g, i) => out.writeUInt16BE(parseInt(g, 16), i * 2));
  return out;
}

export const TCP = { FIN: 0x01, SYN: 0x02, RST: 0x04, PSH: 0x08, ACK: 0x10 };

export type TcpOpts = { src: string; dst: string; sport: number; dport: number; flags: number; seq?: number; ack?: number; payload?: Buffer | string; vlan?: boolean };

/** Ethernet II + IPv4 + TCP (RFC 791, RFC 9293): 14 + 20 + 20 header bytes, then the payload. Checksums left zero. */
export function frameTcp4(o: TcpOpts): Buffer {
  const payload = Buffer.from(o.payload ?? "");
  const tcp = Buffer.alloc(20);
  tcp.writeUInt16BE(o.sport, 0);
  tcp.writeUInt16BE(o.dport, 2);
  tcp.writeUInt32BE((o.seq ?? 0) >>> 0, 4);
  tcp.writeUInt32BE((o.ack ?? 0) >>> 0, 8);
  tcp.writeUInt8(5 << 4, 12);
  tcp.writeUInt8(o.flags, 13);
  tcp.writeUInt16BE(8192, 14);
  const ip = Buffer.alloc(20);
  ip.writeUInt8(0x45, 0);
  ip.writeUInt16BE(20 + 20 + payload.length, 2);
  ip.writeUInt16BE(1, 4);
  ip.writeUInt8(64, 8);
  ip.writeUInt8(6, 9);
  ip4(o.src).copy(ip, 12);
  ip4(o.dst).copy(ip, 16);
  const eth = Buffer.alloc(14);
  Buffer.from([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]).copy(eth, 0);
  eth.writeUInt16BE(0x0800, 12);
  return Buffer.concat([eth, ip, tcp, payload]);
}

/** Ethernet II + IPv6 + TCP (RFC 8200): 14 + 40 + 20 header bytes. */
export function frameTcp6(o: TcpOpts): Buffer {
  const payload = Buffer.from(o.payload ?? "");
  const tcp = Buffer.alloc(20);
  tcp.writeUInt16BE(o.sport, 0);
  tcp.writeUInt16BE(o.dport, 2);
  tcp.writeUInt32BE((o.seq ?? 0) >>> 0, 4);
  tcp.writeUInt32BE((o.ack ?? 0) >>> 0, 8);
  tcp.writeUInt8(5 << 4, 12);
  tcp.writeUInt8(o.flags, 13);
  tcp.writeUInt16BE(8192, 14);
  const ip = Buffer.alloc(40);
  ip.writeUInt32BE(0x60000000, 0);
  ip.writeUInt16BE(20 + payload.length, 4);
  ip.writeUInt8(6, 6);
  ip.writeUInt8(64, 7);
  ip6(o.src).copy(ip, 8);
  ip6(o.dst).copy(ip, 24);
  const eth = Buffer.alloc(14);
  eth.writeUInt16BE(0x86dd, 12);
  return Buffer.concat([eth, ip, tcp, payload]);
}

export type UdpOpts = { src: string; dst: string; sport: number; dport: number; payload?: Buffer | string };

/** Ethernet II + IPv4 + UDP (RFC 768): 14 + 20 + 8 header bytes. */
export function frameUdp4(o: UdpOpts): Buffer {
  const payload = Buffer.from(o.payload ?? "");
  const udp = Buffer.alloc(8);
  udp.writeUInt16BE(o.sport, 0);
  udp.writeUInt16BE(o.dport, 2);
  udp.writeUInt16BE(8 + payload.length, 4);
  const ip = Buffer.alloc(20);
  ip.writeUInt8(0x45, 0);
  ip.writeUInt16BE(20 + 8 + payload.length, 2);
  ip.writeUInt8(64, 8);
  ip.writeUInt8(17, 9);
  ip4(o.src).copy(ip, 12);
  ip4(o.dst).copy(ip, 16);
  const eth = Buffer.alloc(14);
  eth.writeUInt16BE(0x0800, 12);
  return Buffer.concat([eth, ip, udp, payload]);
}

// --- captures ------------------------------------------------------------------------------------------------

export type Pkt = { sec: number; frac?: number; frame: Buffer; orig?: number };

/** A classic pcap file: the 24-byte global header, then a 16-byte record header and the bytes per packet. */
export function pcapClassic(packets: Pkt[], o: { snaplen?: number; nano?: boolean; link?: number } = {}): Buffer {
  const head = Buffer.alloc(24);
  head.writeUInt32LE(o.nano ? 0xa1b23c4d : 0xa1b2c3d4, 0);
  head.writeUInt16LE(2, 4);
  head.writeUInt16LE(4, 6);
  head.writeUInt32LE(o.snaplen ?? 65535, 16);
  head.writeUInt32LE(o.link ?? 1, 20);
  const parts: Buffer[] = [head];
  for (const p of packets) {
    const rec = Buffer.alloc(16);
    rec.writeUInt32LE(p.sec, 0);
    rec.writeUInt32LE(p.frac ?? 0, 4);
    rec.writeUInt32LE(p.frame.length, 8);
    rec.writeUInt32LE(p.orig ?? p.frame.length, 12);
    parts.push(rec, p.frame);
  }
  return Buffer.concat(parts);
}

const pad4 = (n: number): number => (4 - (n % 4)) % 4;

/** One pcapng block: type, total length, body (padded to 32 bits), total length again. */
export function ngBlock(type: number, bodyBytes: Buffer): Buffer {
  const padded = Buffer.concat([bodyBytes, Buffer.alloc(pad4(bodyBytes.length))]);
  const total = 12 + padded.length;
  const out = Buffer.alloc(total);
  out.writeUInt32LE(type >>> 0, 0);
  out.writeUInt32LE(total, 4);
  padded.copy(out, 8);
  out.writeUInt32LE(total, total - 4);
  return out;
}

/** An option: code, length, value padded to 32 bits. */
export function ngOption(code: number, value: Buffer): Buffer {
  const head = Buffer.alloc(4);
  head.writeUInt16LE(code, 0);
  head.writeUInt16LE(value.length, 2);
  return Buffer.concat([head, value, Buffer.alloc(pad4(value.length))]);
}

export const ngEnd = (): Buffer => Buffer.alloc(4);

export function ngSection(): Buffer {
  const body = Buffer.alloc(16);
  body.writeUInt32LE(0x1a2b3c4d, 0);
  body.writeUInt16LE(1, 4);
  body.writeUInt16LE(0, 6);
  body.writeBigInt64LE(-1n, 8);
  return ngBlock(0x0a0d0d0a, body);
}

export function ngInterface(o: { link?: number; snaplen?: number; options?: Buffer[] } = {}): Buffer {
  const head = Buffer.alloc(8);
  head.writeUInt16LE(o.link ?? 1, 0);
  head.writeUInt32LE(o.snaplen ?? 0, 4);
  const opts = o.options && o.options.length ? Buffer.concat([...o.options, ngEnd()]) : Buffer.alloc(0);
  return ngBlock(1, Buffer.concat([head, opts]));
}

export function ngPacket(o: { iface?: number; ticks: bigint; frame: Buffer; orig?: number }): Buffer {
  const head = Buffer.alloc(20);
  head.writeUInt32LE(o.iface ?? 0, 0);
  head.writeUInt32LE(Number((o.ticks >> 32n) & 0xffffffffn), 4);
  head.writeUInt32LE(Number(o.ticks & 0xffffffffn), 8);
  head.writeUInt32LE(o.frame.length, 12);
  head.writeUInt32LE(o.orig ?? o.frame.length, 16);
  return ngBlock(6, Buffer.concat([head, o.frame, Buffer.alloc(pad4(o.frame.length))]));
}

/** An Interface Statistics Block: interface id, a 64-bit timestamp, then options (isb_ifrecv = 4, isb_ifdrop = 5). */
export function ngStats(o: { iface?: number; recv?: bigint; drop?: bigint }): Buffer {
  const head = Buffer.alloc(12);
  head.writeUInt32LE(o.iface ?? 0, 0);
  const opts: Buffer[] = [];
  const u64 = (n: bigint): Buffer => {
    const b = Buffer.alloc(8);
    b.writeBigUInt64LE(n, 0);
    return b;
  };
  if (o.recv !== undefined) opts.push(ngOption(4, u64(o.recv)));
  if (o.drop !== undefined) opts.push(ngOption(5, u64(o.drop)));
  return ngBlock(5, Buffer.concat([head, ...opts, ngEnd()]));
}

export const u32 = (n: number): Buffer => {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(n, 0);
  return b;
};

/** A time as ticks of 10^-`digits` seconds since the epoch. */
export function ticks(seconds: number, fractionTicks: number, digits: number): bigint {
  return BigInt(seconds) * 10n ** BigInt(digits) + BigInt(fractionTicks);
}

/** Write a Buffer under cwd and return its path as the tool is given it (relative). */
export async function drop(cwd: string, rel: string, data: Buffer | string): Promise<string> {
  await put(cwd, rel, data);
  return rel;
}
