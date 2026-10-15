/**
 * Helpers the virtualization-backup-forensics suites share: running a pack tool as a call and as a job (JOB_ID and OUT
 * set, the way the job service runs it), builders for the disk formats the chain checker reads, the configuration files
 * the inventory reads and the task records the audit normaliser reads, and a stand-in qemu-img.
 *
 * Every fixture here is built from the formats' public descriptions, never from a tool's output: the VMDK descriptor
 * and sparse-extent header (VMware's Virtual Disk Format 1.1), the VHD footer and dynamic-disk header (Microsoft's VHD
 * specification), the VHDX headers, region table and metadata (MS-VHDX, with its own CRC-32C), the QCOW2 header,
 * extensions and snapshot table (QEMU's qcow2 specification), .vmx/.vmsd key = "value" lines, libvirt's domain XML,
 * Proxmox's configuration and UPID task lines. They prove the tool reads what these descriptions say; none of them proves
 * anything about a file a real product wrote, and the suites say so where it matters.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { chmod, mkdir, readFile, readdir, stat, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { ROOT, runPy } from "./tool-library-harness.ts";
export { withCwd } from "./tool-library-harness.ts";

export const VIRT = join(ROOT, "packs", "virtualization-backup-forensics");
export const TOOLS = join(VIRT, "tools");
export const INVENTORY = join(TOOLS, "virtualization_inventory", "run.py");
export const CHAIN = join(TOOLS, "snapshot_chain_check", "run.py");
export const AUDIT = join(TOOLS, "backup_audit_normalise", "run.py");
export const ALL_TOOLS = { virtualization_inventory: INVENTORY, snapshot_chain_check: CHAIN, backup_audit_normalise: AUDIT } as const;
export const AGENT = { AGENT_ID: "s1" };
export const IS_ROOT = typeof process.getuid === "function" && process.getuid() === 0;

export type Run = { code: number | null; stdout: string; stderr: string };
export type Page = { matched: number; returned: number; truncated: boolean; all_results?: string };
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

/** An answer that is not a clean exit: it is still one JSON document and never a traceback. */
export function json(out: Run): Json {
  assert.doesNotMatch(out.stderr, /Traceback/, out.stderr.slice(-400));
  return JSON.parse(out.stdout);
}

export function refused(out: Run): Json {
  assert.notEqual(out.code, 0, out.stdout);
  assert.doesNotMatch(out.stderr, /Traceback/);
  return JSON.parse(out.stdout);
}

export async function exists(path: string): Promise<boolean> {
  return stat(path).then(() => true, () => false);
}

export async function put(root: string, rel: string, data: string | Buffer, mode?: number): Promise<string> {
  const full = join(root, rel);
  await mkdir(dirname(full), { recursive: true });
  await writeFile(full, data);
  if (mode !== undefined) await chmod(full, mode);
  return full;
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

/**
 * The rows of a list an answer pages: the inline page, or the whole in the file the page names. A job's paging file is
 * named store/jobs/<id>/out/..., which a test run finds under `outDir`.
 */
export async function rowsOf(cwd: string, out: Json, key: string, outDir = "out"): Promise<Json[]> {
  const page: Page | undefined = out.pages?.[key];
  if (page?.all_results) {
    const real = page.all_results.replace(/^store\/jobs\/[^/]+\/out\//, `${outDir}/`);
    const text = await readFile(join(cwd, real), "utf8");
    return text.trimEnd().split("\n").filter(Boolean).map((l) => JSON.parse(l));
  }
  return out[key] ?? [];
}

/**
 * Everything a call left where an agent reads it, as one string: the answer, every job output directory (`out*`) and the
 * agent's own tool-output pages (`work/s1`), less the files named in `skip` (the fixtures under inputs/ and work/ are the
 * evidence and hold the planted secret on purpose).
 */
export async function everythingBut(cwd: string, answer: string, skip: string[] = []): Promise<string> {
  const parts = [answer];
  const roots = (await readdir(cwd)).filter((d) => d.startsWith("out")).concat(["work/s1"]);
  for (const root of roots) {
    for (const f of await filesUnder(join(cwd, root))) {
      if (skip.includes(`${root}/${f}`)) continue;
      parts.push(await readFile(join(cwd, root, f), "utf8").catch(() => ""));
    }
  }
  return parts.join("\n");
}

// ---- byte builders ---------------------------------------------------------------------------------------------------

export function u16(n: number, le = true): Buffer { const b = Buffer.alloc(2); le ? b.writeUInt16LE(n) : b.writeUInt16BE(n); return b; }
export function u32(n: number, le = true): Buffer { const b = Buffer.alloc(4); le ? b.writeUInt32LE(n >>> 0) : b.writeUInt32BE(n >>> 0); return b; }
export function u64(n: bigint | number, le = true): Buffer { const b = Buffer.alloc(8); le ? b.writeBigUInt64LE(BigInt(n)) : b.writeBigUInt64BE(BigInt(n)); return b; }

/** A GUID as VHDX stores it: the first three fields little-endian, the rest as written. */
export function guidBytes(text: string): Buffer {
  const h = text.replace(/[{}-]/g, "");
  assert.equal(h.length, 32);
  const b = Buffer.from(h, "hex");
  return Buffer.concat([Buffer.from(b.subarray(0, 4)).reverse(), Buffer.from(b.subarray(4, 6)).reverse(), Buffer.from(b.subarray(6, 8)).reverse(), b.subarray(8)]);
}

/** CRC-32C (Castagnoli), bit by bit: written here from the polynomial, not taken from the tool. */
export function crc32c(data: Buffer): number {
  let crc = 0xffffffff;
  for (const byte of data) {
    crc ^= byte;
    for (let k = 0; k < 8; k++) crc = crc & 1 ? (crc >>> 1) ^ 0x82f63b78 : crc >>> 1;
  }
  return (crc ^ 0xffffffff) >>> 0;
}

// ---- VMDK -------------------------------------------------------------------------------------------------------------

export type Extent = { access?: string; sectors: number; type?: string; name?: string; offset?: number };

export function vmdkDescriptor(o: { cid: string; parentCid?: string; createType?: string; parentHint?: string; extents: Extent[]; version?: number }): string {
  const lines = ["# Disk DescriptorFile", `version=${o.version ?? 1}`, "encoding=\"UTF-8\"", `CID=${o.cid}`, `parentCID=${o.parentCid ?? "ffffffff"}`, `createType="${o.createType ?? "monolithicFlat"}"`];
  if (o.parentHint !== undefined) lines.push(`parentFileNameHint="${o.parentHint}"`);
  lines.push("", "# Extent description");
  for (const e of o.extents) lines.push(`${e.access ?? "RW"} ${e.sectors} ${e.type ?? "FLAT"}${e.name !== undefined ? ` "${e.name}"` : ""}${e.offset !== undefined ? ` ${e.offset}` : ""}`);
  lines.push("", "# The Disk Data Base", "#DDB", "", "ddb.adapterType = \"lsilogic\"", "ddb.virtualHWVersion = \"14\"");
  return lines.join("\n") + "\n";
}

/** A sparse extent: the 512-byte KDMV header (VMware Virtual Disk Format 1.1) and, when given, a descriptor at sector 1. */
export function vmdkSparse(o: { descriptor?: string; unclean?: boolean; flags?: number; version?: number; newline?: [number, number, number, number]; capacity?: number }): Buffer {
  const header = Buffer.alloc(512);
  header.write("KDMV", 0, "latin1");
  header.writeUInt32LE(o.version ?? 1, 4);
  header.writeUInt32LE(o.flags ?? 1, 8);
  header.writeBigUInt64LE(BigInt(o.capacity ?? 2048), 12);
  header.writeBigUInt64LE(128n, 20);
  const desc = o.descriptor ? Buffer.from(o.descriptor, "latin1") : Buffer.alloc(0);
  const sectors = Math.ceil(desc.length / 512);
  if (desc.length) {
    header.writeBigUInt64LE(1n, 28);
    header.writeBigUInt64LE(BigInt(sectors), 36);
  }
  header.writeUInt32LE(512, 44);
  header.writeBigUInt64LE(BigInt(1 + sectors), 64);
  header[72] = o.unclean ? 1 : 0;
  const nl = o.newline ?? [0x0a, 0x20, 0x0d, 0x0a];
  header[73] = nl[0]; header[74] = nl[1]; header[75] = nl[2]; header[76] = nl[3];
  const padded = Buffer.alloc(sectors * 512);
  desc.copy(padded);
  return Buffer.concat([header, padded, Buffer.alloc(4096)]);
}

// ---- VHD --------------------------------------------------------------------------------------------------------------

const VHD_EPOCH = Date.UTC(2000, 0, 1) / 1000;

function vhdChecksum(buf: Buffer, at: number): number {
  let sum = 0;
  for (let i = 0; i < buf.length; i++) if (i < at || i >= at + 4) sum += buf[i];
  return (~sum) >>> 0;
}

export function uuidBytes(text: string): Buffer { return Buffer.from(text.replace(/-/g, ""), "hex"); }

export function vhdFooter(o: { type: 2 | 3 | 4; uid: string; dataOffset?: bigint; created?: number; saved?: boolean; size?: bigint; breakChecksum?: boolean }): Buffer {
  const f = Buffer.alloc(512);
  f.write("conectix", 0, "latin1");
  f.writeUInt32BE(2, 8);
  f.writeUInt32BE(0x00010000, 12);
  f.writeBigUInt64BE(o.dataOffset ?? 0xffffffffffffffffn, 16);
  f.writeUInt32BE(o.created ?? 1_700_000_000 - VHD_EPOCH, 24);
  f.write("tstc", 28, "latin1");
  f.writeUInt32BE(0x00010000, 32);
  f.write("Wi2k", 36, "latin1");
  f.writeBigUInt64BE(o.size ?? 1048576n, 40);
  f.writeBigUInt64BE(o.size ?? 1048576n, 48);
  f.writeUInt32BE(0x00200101, 56);
  f.writeUInt32BE(o.type, 60);
  uuidBytes(o.uid).copy(f, 68);
  f[84] = o.saved ? 1 : 0;
  f.writeUInt32BE((vhdChecksum(f, 64) ^ (o.breakChecksum ? 1 : 0)) >>> 0, 64);
  return f;
}

export type VhdLocator = { code: string; text: string; encoding?: "utf16le" | "utf8" };

export function vhdDifferencing(o: { uid: string; parentUid: string; parentName: string; parentStamp?: number; locators?: VhdLocator[] }): Buffer {
  const footer = vhdFooter({ type: 4, uid: o.uid, dataOffset: 512n });
  const hdr = Buffer.alloc(1024);
  hdr.write("cxsparse", 0, "latin1");
  hdr.writeBigUInt64BE(0xffffffffffffffffn, 8);
  hdr.writeBigUInt64BE(1536n, 16);
  hdr.writeUInt32BE(0x00010000, 24);
  hdr.writeUInt32BE(1, 28);
  hdr.writeUInt32BE(2097152, 32);
  uuidBytes(o.parentUid).copy(hdr, 40);
  hdr.writeUInt32BE(o.parentStamp ?? 700_000_000, 56);
  Buffer.from(o.parentName, "utf16le").swap16().copy(hdr, 64);
  // Locator data starts at byte 4096, each block padded to a whole sector.
  const blocks: Buffer[] = [];
  let offset = 4096;
  (o.locators ?? []).forEach((l, i) => {
    const data = l.encoding === "utf8" ? Buffer.from(l.text, "utf8") : Buffer.from(l.text, "utf16le");
    hdr.write(l.code, 576 + 24 * i, "latin1");
    hdr.writeUInt32BE(512, 576 + 24 * i + 4);
    hdr.writeUInt32BE(data.length, 576 + 24 * i + 8);
    hdr.writeBigUInt64BE(BigInt(offset), 576 + 24 * i + 16);
    const padded = Buffer.alloc(Math.ceil(data.length / 512) * 512);
    data.copy(padded);
    blocks.push(padded);
    offset += padded.length;
  });
  hdr.writeUInt32BE(vhdChecksum(hdr, 36), 36);
  return Buffer.concat([footer, hdr, Buffer.alloc(512), Buffer.alloc(4096 - 512 - 1024 - 512), ...blocks, footer]);
}

export function vhdDynamic(o: { uid: string; saved?: boolean; mismatchCopy?: boolean }): Buffer {
  const footer = vhdFooter({ type: 3, uid: o.uid, dataOffset: 512n, saved: o.saved });
  const hdr = Buffer.alloc(1024);
  hdr.write("cxsparse", 0, "latin1");
  hdr.writeBigUInt64BE(0xffffffffffffffffn, 8);
  hdr.writeBigUInt64BE(1536n, 16);
  hdr.writeUInt32BE(0x00010000, 24);
  hdr.writeUInt32BE(1, 28);
  hdr.writeUInt32BE(2097152, 32);
  hdr.writeUInt32BE(vhdChecksum(hdr, 36), 36);
  const tail = o.mismatchCopy ? vhdFooter({ type: 3, uid: o.uid, dataOffset: 512n, saved: o.saved, created: 1_600_000_000 - VHD_EPOCH }) : footer;
  return Buffer.concat([footer, hdr, Buffer.alloc(512), tail]);
}

export function vhdFixed(uid: string): Buffer {
  return Buffer.concat([Buffer.alloc(4096, 0x41), vhdFooter({ type: 2, uid })]);
}

// ---- VHDX -------------------------------------------------------------------------------------------------------------

export const G = {
  metadata: "8B7CA206-4790-4B9A-B8FE-575F050F886E",
  bat: "2DC27766-F623-4200-9D64-115E9BFD4A08",
  fileParams: "CAA16737-FA36-4D43-B3B6-33F0AA44E76B",
  diskSize: "2FA54224-CD1B-4876-B211-5DBED83BF4B8",
  diskId: "BECA12AB-B2E6-4523-93EF-C309E000C746",
  parentLocator: "A8D35F2D-B30B-454D-ABF7-D3D84834AB0C",
  locatorVhdx: "B04AEFB7-D19E-4A81-B789-25B8E9445913",
  zero: "00000000-0000-0000-0000-000000000000",
};

function vhdxHeader(o: { seq: bigint; fileGuid: string; dataGuid: string; logGuid: string; version?: number; logLength?: number; breakCrc?: boolean }): Buffer {
  const h = Buffer.alloc(4096);
  h.write("head", 0, "latin1");
  h.writeBigUInt64LE(o.seq, 8);
  guidBytes(o.fileGuid).copy(h, 16);
  guidBytes(o.dataGuid).copy(h, 32);
  guidBytes(o.logGuid).copy(h, 48);
  h.writeUInt16LE(0, 64);
  h.writeUInt16LE(o.version ?? 1, 66);
  h.writeUInt32LE(o.logLength ?? 0, 68);
  h.writeBigUInt64LE(1048576n, 72);
  h.writeUInt32LE((crc32c(h) ^ (o.breakCrc ? 1 : 0)) >>> 0, 4);
  return h;
}

export type VhdxOptions = {
  diskId: string;
  /**
   * The DataWriteGuid both headers carry (MS-VHDX 2.2.2): what a child's parent_linkage records of its parent. It is
   * deliberately not the VirtualDiskId by default, so that a reader comparing the linkage with the wrong field fails.
   */
  dataWriteGuid?: string;
  parent?: { linkage?: string; linkage2?: string; relative?: string; absolute?: string; volume?: string; locatorType?: string };
  headers?: [Partial<Parameters<typeof vhdxHeader>[0]>, Partial<Parameters<typeof vhdxHeader>[0]>];
  hasParentFlag?: boolean;
  regionBadSignature?: boolean;
};

export function vhdx(o: VhdxOptions): Buffer {
  const base = { fileGuid: "11111111-1111-1111-1111-111111111111", dataGuid: o.dataWriteGuid ?? "22222222-2222-2222-2222-222222222222", logGuid: G.zero };
  assert.notEqual(base.dataGuid.toUpperCase(), o.diskId.toUpperCase(), "a VHDX fixture keeps its DataWriteGuid apart from its VirtualDiskId");
  const h1 = vhdxHeader({ seq: 1n, ...base, ...(o.headers?.[0] ?? {}) });
  const h2 = vhdxHeader({ seq: 2n, ...base, ...(o.headers?.[1] ?? {}) });
  const item = (id: string, off: number, len: number): Buffer => Buffer.concat([guidBytes(id), u32(off), u32(len), u32(0), u32(0)]);
  // metadata items laid out from 64 KiB into the region
  const items: { id: string; data: Buffer }[] = [];
  const params = Buffer.concat([u32(33554432), u32((o.hasParentFlag ?? !!o.parent) ? 2 : 0)]);
  items.push({ id: G.fileParams, data: params });
  items.push({ id: G.diskSize, data: u64(1n << 30n) });
  items.push({ id: G.diskId, data: guidBytes(o.diskId) });
  if (o.parent) {
    const pairs: [string, string][] = [];
    if (o.parent.linkage) pairs.push(["parent_linkage", `{${o.parent.linkage}}`]);
    if (o.parent.linkage2) pairs.push(["parent_linkage2", `{${o.parent.linkage2}}`]);
    if (o.parent.relative) pairs.push(["relative_path", o.parent.relative]);
    if (o.parent.volume) pairs.push(["volume_path", o.parent.volume]);
    if (o.parent.absolute) pairs.push(["absolute_win32_path", o.parent.absolute]);
    const head = Buffer.concat([guidBytes(o.parent.locatorType ?? G.locatorVhdx), u16(0), u16(pairs.length)]);
    const entries = Buffer.alloc(12 * pairs.length);
    const strings: Buffer[] = [];
    let at = head.length + entries.length;
    pairs.forEach(([k, v], i) => {
      const kb = Buffer.from(k, "utf16le"), vb = Buffer.from(v, "utf16le");
      entries.writeUInt32LE(at, 12 * i); entries.writeUInt32LE(at + kb.length, 12 * i + 4);
      entries.writeUInt16LE(kb.length, 12 * i + 8); entries.writeUInt16LE(vb.length, 12 * i + 10);
      strings.push(kb, vb); at += kb.length + vb.length;
    });
    items.push({ id: G.parentLocator, data: Buffer.concat([head, entries, ...strings]) });
  }
  const table = Buffer.alloc(65536);
  table.write("metadata", 0, "latin1");
  table.writeUInt16LE(items.length, 10);
  const data: Buffer[] = [];
  let off = 65536;
  items.forEach((it, i) => {
    item(it.id, off, it.data.length).copy(table, 32 + 32 * i);
    data.push(it.data, Buffer.alloc((-it.data.length) & 7));
    off += it.data.length + ((-it.data.length) & 7);
  });
  const region = Buffer.alloc(65536);
  region.write(o.regionBadSignature ? "xxxx" : "regi", 0, "latin1");
  region.writeUInt32LE(2, 8);
  Buffer.concat([guidBytes(G.bat), u64(4194304), u32(1048576), u32(1)]).copy(region, 16);
  Buffer.concat([guidBytes(G.metadata), u64(1048576), u32(1048576), u32(1)]).copy(region, 48);
  region.writeUInt32LE(crc32c(region), 4);
  const file = Buffer.alloc(1048576 + 65536 + Buffer.concat(data).length);
  file.write("vhdxfile", 0, "latin1");
  h1.copy(file, 65536); h2.copy(file, 131072);
  region.copy(file, 196608); region.copy(file, 262144);
  table.copy(file, 1048576);
  Buffer.concat(data).copy(file, 1048576 + 65536);
  return file;
}

// ---- QCOW2 ------------------------------------------------------------------------------------------------------------

export type QcowSnapshot = { id: string; name: string; date: number; dateNsec?: number; vmClock?: bigint; extra?: Buffer };

export function qcow2(o: {
  version?: 2 | 3; backing?: string; backingFormat?: string; size?: bigint; clusterBits?: number; incompat?: bigint; autoclear?: bigint;
  snapshots?: QcowSnapshot[]; declared?: number; backingSizeField?: number; snapshotsOffset?: number;
}): Buffer {
  const version = o.version ?? 3;
  const clusterBits = o.clusterBits ?? 16;
  const header = Buffer.alloc(version === 3 ? 104 : 72);
  header.write("QFI\xfb", 0, "latin1");
  header.writeUInt32BE(version, 4);
  const backing = o.backing !== undefined ? Buffer.from(o.backing, "utf8") : Buffer.alloc(0);
  const backingAt = 4096;
  header.writeBigUInt64BE(backing.length ? BigInt(backingAt) : 0n, 8);
  header.writeUInt32BE(o.backingSizeField ?? backing.length, 16);
  header.writeUInt32BE(clusterBits, 20);
  header.writeBigUInt64BE(o.size ?? 1073741824n, 24);
  header.writeUInt32BE(0, 32);
  header.writeUInt32BE(1, 36);
  header.writeBigUInt64BE(0x20000n, 40);
  header.writeBigUInt64BE(0x10000n, 48);
  header.writeUInt32BE(1, 56);
  const snaps = o.snapshots ?? [];
  const snapAt = o.snapshotsOffset ?? 8192;
  header.writeUInt32BE(o.declared ?? snaps.length, 60);
  header.writeBigUInt64BE(snaps.length || o.declared ? BigInt(snapAt) : 0n, 64);
  if (version === 3) {
    header.writeBigUInt64BE(o.incompat ?? 0n, 72);
    header.writeBigUInt64BE(0n, 80);
    header.writeBigUInt64BE(o.autoclear ?? 0n, 88);
    header.writeUInt32BE(4, 96);
    header.writeUInt32BE(104, 100);
  }
  const exts: Buffer[] = [];
  if (o.backingFormat) {
    const fmt = Buffer.from(o.backingFormat);
    exts.push(u32(0xe2792aca, false), u32(fmt.length, false), fmt, Buffer.alloc((-fmt.length) & 7));
  }
  exts.push(u32(0, false), u32(0, false));
  const entries: Buffer[] = [];
  for (const s of snaps) {
    const id = Buffer.from(s.id), name = Buffer.from(s.name), extra = s.extra ?? Buffer.alloc(0);
    const head = Buffer.alloc(40);
    head.writeBigUInt64BE(0x30000n, 0); head.writeUInt32BE(1, 8); head.writeUInt16BE(id.length, 12); head.writeUInt16BE(name.length, 14);
    head.writeUInt32BE(s.date, 16); head.writeUInt32BE(s.dateNsec ?? 0, 20); head.writeBigUInt64BE(s.vmClock ?? 0n, 24); head.writeUInt32BE(0, 32); head.writeUInt32BE(extra.length, 36);
    const entry = Buffer.concat([head, extra, id, name]);
    entries.push(entry, Buffer.alloc((-entry.length) & 7));
  }
  const file = Buffer.alloc(snapAt + Buffer.concat(entries).length + 4096);
  header.copy(file, 0);
  Buffer.concat(exts).copy(file, header.length);
  backing.copy(file, backingAt);
  Buffer.concat(entries).copy(file, snapAt);
  return file;
}

// ---- configuration text ----------------------------------------------------------------------------------------------

export function vmx(pairs: [string, string][]): string { return [".encoding = \"UTF-8\"", ...pairs.map(([k, v]) => `${k} = "${v}"`)].join("\n") + "\n"; }

export type VmsdSnapshot = { index: number; uid: string; name: string; parent?: string; disks: string[]; high?: string; low?: string };
export function vmsd(o: { lastUid?: number; current?: number; snapshots: VmsdSnapshot[]; count?: number }): string {
  const lines = [".encoding = \"UTF-8\"", `snapshot.lastUID = "${o.lastUid ?? o.snapshots.length}"`];
  if (o.snapshots.length) lines.push(`snapshot.current = "${o.current ?? o.snapshots[o.snapshots.length - 1].uid}"`);
  lines.push(`snapshot.numSnapshots = "${o.count ?? o.snapshots.length}"`);
  for (const s of o.snapshots) {
    lines.push(`snapshot${s.index}.uid = "${s.uid}"`, `snapshot${s.index}.filename = "vm-Snapshot${s.uid}.vmsn"`, `snapshot${s.index}.displayName = "${s.name}"`);
    if (s.parent) lines.push(`snapshot${s.index}.parent = "${s.parent}"`);
    lines.push(`snapshot${s.index}.createTimeHigh = "${s.high ?? "371000"}"`, `snapshot${s.index}.createTimeLow = "${s.low ?? "123456"}"`, `snapshot${s.index}.numDisks = "${s.disks.length}"`);
    s.disks.forEach((d, i) => lines.push(`snapshot${s.index}.disk${i}.fileName = "${d}"`, `snapshot${s.index}.disk${i}.node = "scsi0:${i}"`));
  }
  return lines.join("\n") + "\n";
}

// ---- a stand-in qemu-img -----------------------------------------------------------------------------------------------

/**
 * A qemu-img that prints what its documentation says `info --output=json` prints, and records its argv one call per line.
 * MODE (env): ok | hang | fail | notjson | size:<n>
 */
export async function stubQemu(dir: string): Promise<string> {
  const bin = join(dir, "bin");
  await mkdir(bin, { recursive: true });
  await writeFile(join(bin, "qemu-img"), `#!/usr/bin/env python3
import json, os, sys, time
log = os.environ.get("QEMU_STUB_LOG")
if log:
    open(log, "a").write(json.dumps(sys.argv[1:]) + "\\n")
mode = os.environ.get("QEMU_STUB_MODE", "ok")
if mode == "hang":
    open(os.environ["QEMU_STUB_PID"], "w").write(str(os.getpid()))
    time.sleep(600)
if mode == "fail":
    sys.stderr.write("qemu-img: Could not open '" + sys.argv[-1] + "': Image is corrupt\\n")
    sys.exit(1)
if mode == "notjson":
    print("not json at all")
    sys.exit(0)
size = int(mode.split(":")[1]) if mode.startswith("size:") else 1073741824
fmt = sys.argv[sys.argv.index("-f") + 1] if "-f" in sys.argv else "raw"
print(json.dumps({"virtual-size": size, "filename": sys.argv[-1], "format": fmt, "actual-size": 4096, "dirty-flag": False}))
`);
  await chmod(join(bin, "qemu-img"), 0o755);
  return bin;
}

/**
 * A tool started the way the harness starts one (extensions/protocol-core.ts): in a process group of its own (`detached`),
 * ended by killing that group with SIGKILL. A program the tool started in a session of its own is not in that group and
 * outlives it; one started in the tool's own group is ended with it.
 */
export function startDetached(script: string, cwd: string, args: unknown, env: Record<string, string> = {}, bin?: string): { pid: number; closed: Promise<number | null>; stdout: () => string; killGroup: () => void; signal: (s: NodeJS.Signals) => void } {
  const child = spawn("python3", [script], { cwd, env: { ...process.env, ...(bin ? { PATH: `${bin}:${process.env.PATH ?? ""}` } : {}), ...AGENT, ...env }, detached: true, stdio: ["pipe", "pipe", "pipe"] });
  const chunks: Buffer[] = [];
  child.stdout.on("data", (c: Buffer) => chunks.push(c));
  child.stderr.on("data", () => undefined);
  child.stdin.end(JSON.stringify(args));
  const closed = new Promise<number | null>((resolve) => child.on("exit", (code) => resolve(code)));
  return {
    pid: child.pid as number,
    closed,
    stdout: () => Buffer.concat(chunks).toString("utf8"),
    killGroup: () => process.kill(-(child.pid as number), "SIGKILL"),
    signal: (sig) => process.kill(child.pid as number, sig),
  };
}

export async function gone(pid: number, waitMs = 2500): Promise<boolean> {
  const until = Date.now() + waitMs;
  for (;;) {
    try { process.kill(pid, 0); } catch { return true; }
    if (Date.now() > until) return false;
    await new Promise((r) => setTimeout(r, 50));
  }
}

export async function pidFile(path: string, waitMs = 8000): Promise<number> {
  const until = Date.now() + waitMs;
  for (;;) {
    const text = await readFile(path, "utf8").catch(() => "");
    if (text.trim()) return Number(text.trim());
    if (Date.now() > until) throw new Error(`no pid in ${path}`);
    await new Promise((r) => setTimeout(r, 50));
  }
}

/** Seeded generator, so a fuzz failure repeats. */
export function prng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** The secrets every canary test plants: shapes the withholding rule names, written here, not taken from a tool. */
export const CANARY = {
  github: "ghp_" + "aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5",
  aws: "AKIA" + "IOSFODNN7EXAMPLE",
  hex: "d41d8cd98f00b204e9800998ecf8427e" + "5ca9",
  userinfo: "admin:S3cr3tPassw0rd",
};
