/**
 * Helpers the reverse-engineering suites share: running a pack tool as a call and as a job (JOB_ID and OUT set,
 * the way the job service runs it), and builders for the files the tools read.
 *
 * Every fixture here is built from the format's own layout and never from a tool's output:
 *   - PE: the Microsoft PE/COFF specification (DOS header with e_lfanew at 0x3C, the 20-byte COFF header,
 *     the PE32 (224-byte) and PE32+ (240-byte) optional headers, 40-byte section headers, the import
 *     directory table of 20-byte descriptors, import lookup tables, hint/name entries);
 *   - ELF: the System V gABI (a 52-byte Elf32_Ehdr and a 64-byte Elf64_Ehdr, 32- and 56-byte program
 *     headers, 8- and 16-byte dynamic entries, 40- and 64-byte section headers);
 *   - Mach-O: <mach-o/loader.h> and <mach-o/fat.h> (28- and 32-byte headers, load commands, a fat header
 *     that is always stored big-endian, byte-swapped when it reads FAT_CIGAM);
 *   - ZIP: the PKWARE APPNOTE (local file header, central directory header, end of central directory record);
 *   - PDF and RTF: the literal tokens of ISO 32000 and the RTF specification.
 */
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { chmod, mkdir, readFile, readdir, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { deflateRawSync } from "node:zlib";
import { ROOT, runPy } from "./tool-library-harness.ts";
export { withCwd } from "./tool-library-harness.ts";

export const RE = join(ROOT, "packs", "reverse-engineering");
export const TOOLS = join(RE, "tools");
export const PE_INFO = join(TOOLS, "pe_info", "run.py");
export const DOC_PROBE = join(TOOLS, "doc_probe", "run.py");
export const ENTROPY = join(TOOLS, "entropy_map", "run.py");
export const FUZZY = join(TOOLS, "fuzzy_hash", "run.py");
export const RECIPE = join(RE, "recipes", "static-binary", "run.py");
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

/** An answer that is a refusal or a failure: a JSON object and a nonzero exit, never a traceback. */
export function refused(out: Run): Json {
  assert.notEqual(out.code, 0, out.stdout);
  assert.doesNotMatch(out.stderr, /Traceback/);
  return JSON.parse(out.stdout);
}

/**
 * A tool started the way the harness starts one (extensions/protocol-core.ts, runForgedTool): in a process group of
 * its own (`detached`), ended by killing that group with SIGKILL. A program the tool started in a session of its
 * own is not in that group and outlives it; one started in the tool's own group is ended with it.
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
export async function gone(pid: number, waitMs = 2000): Promise<boolean> {
  const until = Date.now() + waitMs;
  for (;;) {
    try {
      process.kill(pid, 0);
    } catch {
      return true;
    }
    // A zombie waiting for its parent to reap it is not running.
    const state = spawnSync("ps", ["-o", "stat=", "-p", String(pid)], { encoding: "utf8" }).stdout.trim();
    if (state.startsWith("Z")) return true;
    if (Date.now() > until) return false;
    await new Promise((r) => setTimeout(r, 50));
  }
}

/** Read a pid a stand-in wrote, waiting for it. */
export async function pidFile(path: string, waitMs = 8000): Promise<number> {
  const until = Date.now() + waitMs;
  for (;;) {
    const text = await readFile(path, "utf8").catch(() => "");
    if (text.trim()) return Number(text.trim());
    if (Date.now() > until) throw new Error(`no pid in ${path}`);
    await new Promise((r) => setTimeout(r, 50));
  }
}

/** The processes whose parent is `pid`, from ps. */
export function childrenOf(pid: number): number[] {
  const out = spawnSync("ps", ["-A", "-o", "pid=,ppid="], { encoding: "utf8" }).stdout;
  return out.split("\n").map((l) => l.trim().split(/\s+/).map(Number)).filter((f) => f.length === 2 && f[1] === pid).map((f) => f[0]!);
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
export async function everythingUnder(cwd: string, answer: string, dirs: string[]): Promise<string> {
  const parts = [answer];
  for (const d of dirs) {
    for (const f of await filesUnder(join(cwd, d))) {
      parts.push(`${d}/${f}\n` + (await readFile(join(cwd, d, f)).then((b) => b.toString("latin1"), () => "")));
    }
  }
  return parts.join("\n");
}

export async function put(root: string, rel: string, data: string | Buffer, mode?: number): Promise<string> {
  const full = join(root, rel);
  await mkdir(join(full, ".."), { recursive: true });
  await writeFile(full, data);
  if (mode !== undefined) await chmod(full, mode);
  return full;
}

/** An executable stand-in for a program, written into `bin`. */
export async function stub(bin: string, name: string, script: string): Promise<void> {
  const path = join(bin, name);
  await writeFile(path, script.startsWith("#!") ? script : `#!/bin/sh\n${script}`);
  await chmod(path, 0o755);
}

// --- little helpers ------------------------------------------------------------------------------------------

export function u16(value: number, big = false): Buffer {
  const b = Buffer.alloc(2);
  if (big) b.writeUInt16BE(value);
  else b.writeUInt16LE(value);
  return b;
}
export function u32(value: number, big = false): Buffer {
  const b = Buffer.alloc(4);
  if (big) b.writeUInt32BE(value >>> 0);
  else b.writeUInt32LE(value >>> 0);
  return b;
}
export function u64(value: number | bigint, big = false): Buffer {
  const b = Buffer.alloc(8);
  if (big) b.writeBigUInt64BE(BigInt(value));
  else b.writeBigUInt64LE(BigInt(value));
  return b;
}
function pad(buf: Buffer, to: number): Buffer {
  const n = (to - (buf.length % to)) % to;
  return n ? Buffer.concat([buf, Buffer.alloc(n)]) : buf;
}
function cstr(text: string): Buffer {
  return Buffer.concat([Buffer.from(text, "latin1"), Buffer.from([0])]);
}

// --- PE (Microsoft PE/COFF specification) -----------------------------------------------------------------------

export type PeSection = { name: string; data: Buffer; flags: number; vsize?: number; rawSizeOverride?: number };
export type PeImport = { dll: string; functions: string[] };
export type PeOptions = {
  plus?: boolean;                       // PE32+ (0x20b) instead of PE32 (0x10b)
  machine?: number;
  stamp?: number;
  characteristics?: number;
  entry?: number;
  subsystem?: number;
  sections?: PeSection[];
  imports?: PeImport[];                 // built into an .idata section placed last
  importsTerminated?: boolean;          // default true: the all-zero descriptor that ends the table
  importDirectorySize?: number;         // the Size field of data directory 1 as declared (default: the true size)
  idataRawSize?: number;                // SizeOfRawData of the .idata section as declared
  exportName?: string;                  // an export directory whose Name field is this, in its own .edata section
  certificate?: { offset: number; size: number };   // data directory 4: a FILE OFFSET, not an RVA
  numberOfRvaAndSizes?: number;         // default 16
  optionalHeaderSize?: number;          // SizeOfOptionalHeader as declared (default: the true size)
  cutOptionalHeaderTo?: number;         // the file ends this many bytes into the optional header
  trailing?: Buffer;                    // bytes appended after the last section (an overlay)
  extraDirectories?: Record<number, { rva: number; size: number }>;
};

export const SCN_CODE = 0x20;
export const SCN_INIT = 0x40;
export const SCN_EXEC = 0x20000000;
export const SCN_READ = 0x40000000;
export const SCN_WRITE = 0x80000000;

export type BuiltPe = { file: Buffer; optionalAt: number; sectionTableAt: number; importRva: number; sectionOffsets: number[] };

/** A PE image: DOS header, PE signature, COFF header, optional header, section table, then section raw data. */
export function buildPe(o: PeOptions = {}): BuiltPe {
  const plus = !!o.plus;
  const fileAlign = 0x200;
  const sectionAlign = 0x1000;
  const secs: PeSection[] = [...(o.sections ?? [{ name: ".text", data: Buffer.from("code-bytes"), flags: SCN_CODE | SCN_EXEC | SCN_READ }])];
  const optSize = plus ? 240 : 224;
  const dirs: { rva: number; size: number }[] = Array.from({ length: 16 }, () => ({ rva: 0, size: 0 }));
  for (const [i, d] of Object.entries(o.extraDirectories ?? {})) dirs[Number(i)] = d;

  // Where the section headers end decides the first raw data offset.
  const peAt = 0x80;
  const nSections = secs.length + (o.imports ? 1 : 0) + (o.exportName !== undefined ? 1 : 0);
  const headersEnd = peAt + 4 + 20 + optSize + nSections * 40;
  const sizeOfHeaders = Math.ceil(headersEnd / fileAlign) * fileAlign;

  // Assign RVAs now, so the import and export structures can name each other's addresses.
  let rva = sectionAlign;
  const placed = secs.map((s) => {
    const p = { ...s, rva };
    rva += Math.ceil(Math.max(s.vsize ?? s.data.length, 1) / sectionAlign) * sectionAlign;
    return p;
  });
  let importRva = 0;
  let idata: Buffer | null = null;
  if (o.imports) {
    importRva = rva;
    const word = plus ? 8 : 4;
    const descriptors = (o.imports.length + 1) * 20;
    // Layout after the descriptors: for each library its ILT, then (copy of it as) its IAT, then names.
    let cursor = descriptors;
    const lib = o.imports.map((imp) => {
      const iltAt = cursor;
      cursor += (imp.functions.length + 1) * word;
      const iatAt = cursor;
      cursor += (imp.functions.length + 1) * word;
      return { imp, iltAt, iatAt };
    });
    const thunkEnd = cursor;
    const names: Buffer[] = [];
    const nameRva = new Map<string, number>();
    const put = (key: string, buf: Buffer) => {
      nameRva.set(key, importRva + cursor);
      names.push(buf);
      cursor += buf.length;
    };
    for (const { imp } of lib) {
      put("dll:" + imp.dll, cstr(imp.dll));
      if (cursor % 2) {
        names.push(Buffer.from([0]));
        cursor += 1;
      }
      for (const fn of imp.functions) {
        if (fn.startsWith("#")) continue;
        // IMAGE_IMPORT_BY_NAME: a 2-byte hint, then the name and its NUL, padded to an even length.
        const entry = pad(Buffer.concat([u16(0), cstr(fn)]), 2);
        put(`fn:${imp.dll}:${fn}`, entry);
      }
    }
    const parts: Buffer[] = [];
    const table = Buffer.alloc(descriptors);
    lib.forEach(({ imp, iltAt, iatAt }, i) => {
      table.writeUInt32LE(importRva + iltAt, i * 20);            // OriginalFirstThunk
      table.writeUInt32LE(nameRva.get("dll:" + imp.dll)!, i * 20 + 12); // Name
      table.writeUInt32LE(importRva + iatAt, i * 20 + 16);       // FirstThunk
    });
    if (o.importsTerminated === false) {
      // No all-zero terminator: the last descriptor is a copy of the first.
      table.copy(table, o.imports.length * 20, 0, 20);
    }
    parts.push(table);
    const thunks = Buffer.alloc(thunkEnd - descriptors);
    for (const { imp, iltAt, iatAt } of lib) {
      imp.functions.forEach((fn, k) => {
        let value: bigint;
        if (fn.startsWith("#")) value = (plus ? 1n << 63n : 1n << 31n) | BigInt(Number(fn.slice(1)));
        else value = BigInt(nameRva.get(`fn:${imp.dll}:${fn}`)!);
        for (const at of [iltAt, iatAt]) {
          if (plus) thunks.writeBigUInt64LE(value, at - descriptors + k * 8);
          else thunks.writeUInt32LE(Number(value), at - descriptors + k * 4);
        }
      });
    }
    parts.push(thunks);
    // names region
    const nameBytes = Buffer.concat(names);
    idata = Buffer.concat([...parts, nameBytes]);
    dirs[1] = { rva: importRva, size: o.importDirectorySize ?? descriptors };
    placed.push({ name: ".idata", data: idata, flags: SCN_INIT | SCN_READ | SCN_WRITE, rva: importRva, rawSizeOverride: o.idataRawSize });
    rva += Math.ceil(idata.length / sectionAlign) * sectionAlign;
  }
  if (o.exportName !== undefined) {
    const at = rva;
    const dir = Buffer.alloc(40);
    dir.writeUInt32LE(at + 40, 12); // Name RVA: the string follows the 40-byte directory
    const data = Buffer.concat([dir, cstr(o.exportName)]);
    dirs[0] = { rva: at, size: data.length };
    placed.push({ name: ".edata", data, flags: SCN_INIT | SCN_READ, rva: at });
    rva += sectionAlign;
  }
  if (o.certificate) dirs[4] = { rva: o.certificate.offset, size: o.certificate.size };

  // Raw data offsets.
  let raw = sizeOfHeaders;
  const sectionOffsets: number[] = [];
  const rawBlocks = placed.map((s) => {
    const data = pad(s.data, fileAlign);
    const at = raw;
    raw += data.length;
    sectionOffsets.push(at);
    return { s, at, data };
  });

  const dos = Buffer.alloc(0x80);
  dos.write("MZ", 0, "latin1");
  dos.writeUInt32LE(peAt, 0x3c);
  const coff = Buffer.concat([
    Buffer.from("PE\0\0", "latin1"),
    u16(o.machine ?? (plus ? 0x8664 : 0x014c)),
    u16(nSections),
    u32(o.stamp ?? 0x5f000000),
    u32(0),
    u32(0),
    u16(o.optionalHeaderSize ?? optSize),
    u16(o.characteristics ?? 0x0102),
  ]);
  const opt = Buffer.alloc(optSize);
  opt.writeUInt16LE(plus ? 0x20b : 0x10b, 0);
  opt.writeUInt32LE(o.entry ?? 0x1000, 16);
  if (plus) opt.writeBigUInt64LE(0x140000000n, 24);
  else opt.writeUInt32LE(0x400000, 28);
  opt.writeUInt32LE(sectionAlign, 32);
  opt.writeUInt32LE(fileAlign, 36);
  opt.writeUInt32LE(rva, 56);                    // SizeOfImage
  opt.writeUInt32LE(sizeOfHeaders, 60);
  opt.writeUInt16LE(o.subsystem ?? 3, 68);
  opt.writeUInt16LE(0x8140, 70);                 // DYNAMIC_BASE | NX_COMPAT | TERMINAL_SERVER_AWARE
  opt.writeUInt32LE(o.numberOfRvaAndSizes ?? 16, plus ? 108 : 92);
  const dirsAt = plus ? 112 : 96;
  dirs.forEach((d, i) => {
    opt.writeUInt32LE(d.rva, dirsAt + i * 8);
    opt.writeUInt32LE(d.size, dirsAt + i * 8 + 4);
  });
  const table = Buffer.alloc(nSections * 40);
  rawBlocks.forEach(({ s, at, data }, i) => {
    const e = i * 40;
    table.write(s.name, e, "latin1");
    table.writeUInt32LE(s.vsize ?? s.data.length, e + 8);
    table.writeUInt32LE(s.rva, e + 12);
    table.writeUInt32LE(s.rawSizeOverride ?? data.length, e + 16);
    table.writeUInt32LE(at, e + 20);
    table.writeUInt32LE(s.flags >>> 0, e + 36);
  });
  let file: Buffer = Buffer.concat([dos, coff, opt, table]);
  file = pad(file, fileAlign);
  file = Buffer.concat([file, ...rawBlocks.map((b) => b.data), o.trailing ?? Buffer.alloc(0)]);
  if (o.cutOptionalHeaderTo !== undefined) file = file.subarray(0, peAt + 24 + o.cutOptionalHeaderTo);
  return { file, optionalAt: peAt + 24, sectionTableAt: peAt + 24 + optSize, importRva, sectionOffsets };
}

// --- ELF (System V gABI) -----------------------------------------------------------------------------------------

export type ElfOptions = {
  cls: 32 | 64;
  big?: boolean;                        // ELFDATA2MSB
  type?: number;                        // e_type (default 2, ET_EXEC)
  machine?: number;                     // e_machine
  entry?: number;
  headerOnly?: boolean;                 // just the Ehdr: 52 bytes for ELF32, 64 for ELF64
  needed?: string[];                    // DT_NEEDED entries of a PT_DYNAMIC segment
  runpath?: string;
  rpath?: string;
  soname?: string;
  interp?: string;                      // a PT_INTERP segment
  sections?: { name: string; type: number; flags?: number; data?: Buffer }[];   // adds section headers
  dynamicInSections?: boolean;          // also describe the dynamic array by an SHT_DYNAMIC section
  noDynamicSegment?: boolean;           // keep the dynamic array but give no PT_DYNAMIC
  noLoadMapping?: boolean;              // PT_DYNAMIC present, but DT_STRTAB names an address no PT_LOAD maps
  extendedCounts?: boolean;             // e_phnum = 0xFFFF (PN_XNUM), e_shnum = 0 and e_shstrndx = 0xFFFF (SHN_XINDEX): the real values are in section header 0
};

const ELF_BASE = 0x400000;

/** An ELF file: Ehdr, program headers (PT_LOAD over the whole file, PT_DYNAMIC, PT_INTERP), the data they name, then sections. */
export function buildElf(o: ElfOptions): Buffer {
  const w = o.cls === 64;
  const big = !!o.big;
  const U16 = (v: number) => u16(v, big);
  const U32 = (v: number) => u32(v, big);
  const UW = (v: number | bigint) => (w ? u64(v, big) : u32(Number(v), big));
  const ehsize = w ? 64 : 52;
  const phentsize = w ? 56 : 32;
  const shentsize = w ? 64 : 40;
  if (o.headerOnly) {
    const hdr = Buffer.alloc(ehsize);
    hdr.write("\x7fELF", 0, "latin1");
    hdr[4] = w ? 2 : 1;
    hdr[5] = big ? 2 : 1;
    hdr[6] = 1;
    U16(o.type ?? 2).copy(hdr, 16);
    U16(o.machine ?? (w ? 0x3e : 0x03)).copy(hdr, 18);
    U32(1).copy(hdr, 20);
    UW(o.entry ?? 0x1000).copy(hdr, 24);
    // e_phoff, e_shoff = 0 and no tables; e_ehsize and the two entry sizes as the spec says
    const tail = w ? 52 : 40;
    U16(ehsize).copy(hdr, tail);
    U16(phentsize).copy(hdr, tail + 2);
    U16(shentsize).copy(hdr, tail + 6);
    return hdr;
  }
  const hasDynamic = !!(o.needed || o.runpath || o.rpath || o.soname) && !o.noDynamicSegment;
  const wantsDynamicData = !!(o.needed || o.runpath || o.rpath || o.soname);
  const hasInterp = o.interp !== undefined;
  const nph = 1 + (hasDynamic ? 1 : 0) + (hasInterp ? 1 : 0);
  const phAt = ehsize;
  const dataAt = phAt + nph * phentsize;

  // Data: the interpreter string, the dynamic string table, then the dynamic array.
  const chunks: Buffer[] = [];
  let at = dataAt;
  const place = (b: Buffer) => {
    const where = at;
    chunks.push(b);
    at += b.length;
    return where;
  };
  const interpAt = hasInterp ? place(cstr(o.interp!)) : 0;
  let strtab = Buffer.from([0]);
  const strOff = (s: string) => {
    const off = strtab.length;
    strtab = Buffer.concat([strtab, cstr(s)]);
    return off;
  };
  const dyn: [number, number | bigint][] = [];
  if (wantsDynamicData) {
    for (const n of o.needed ?? []) dyn.push([1, strOff(n)]);
    if (o.soname) dyn.push([14, strOff(o.soname)]);
    if (o.rpath) dyn.push([15, strOff(o.rpath)]);
    if (o.runpath) dyn.push([29, strOff(o.runpath)]);
  }
  const strtabAt = wantsDynamicData ? place(strtab) : 0;
  if (at % 8) place(Buffer.alloc(8 - (at % 8)));
  const dynsz = w ? 16 : 8;
  let dynAt = 0;
  let dynSize = 0;
  if (wantsDynamicData) {
    const strtabAddr = o.noLoadMapping ? 0x7ff00000 : ELF_BASE + strtabAt;
    const entries = [...dyn, [5, strtabAddr], [10, strtab.length], [0, 0]] as [number, number | bigint][];
    dynAt = place(Buffer.concat(entries.map(([tag, val]) => Buffer.concat([w ? u64(BigInt(tag), big) : u32(tag, big), UW(val)]))));
    dynSize = entries.length * dynsz;
  }
  const body = Buffer.concat(chunks);

  // Sections, after the data.
  let sectionBytes = Buffer.alloc(0);
  let shnum = 0;
  let shoff = 0;
  let shstrndx = 0;
  if (o.sections || o.dynamicInSections) {
    const list = [{ name: "", type: 0, flags: 0, data: Buffer.alloc(0) }, ...(o.sections ?? []).map((s) => ({ flags: 0, data: Buffer.alloc(0), ...s }))];
    if (o.dynamicInSections && wantsDynamicData) {
      list.push({ name: ".dynstr", type: 3, flags: 2, data: strtab });
      list.push({ name: ".dynamic", type: 6, flags: 3, data: body.subarray(dynAt - dataAt, dynAt - dataAt + dynSize) });
    }
    const shstr = Buffer.concat([Buffer.from([0]), ...list.slice(1).map((s) => cstr(s.name)), cstr(".shstrtab")]);
    const offsets: number[] = [0];
    let p = 1;
    for (const s of list.slice(1)) {
      offsets.push(p);
      p += s.name.length + 1;
    }
    const shstrOff = p;
    list.push({ name: ".shstrtab", type: 3, flags: 0, data: shstr });
    offsets.push(shstrOff);
    // Section contents first, then the header table.
    let cursor = ehsize + nph * phentsize + body.length;
    const datas: Buffer[] = [];
    const contentAt: number[] = [];
    for (const s of list) {
      contentAt.push(cursor);
      datas.push(s.data);
      cursor += s.data.length;
    }
    shoff = cursor;
    shnum = list.length;
    shstrndx = list.length - 1;
    const headers = list.map((s, i) => {
      const dynIdx = list.findIndex((x) => x.name === ".dynstr");
      let link = s.name === ".dynamic" ? dynIdx : 0;
      let info = 0;
      let size = s.data.length;
      // The address a section says it has: .dynstr names DT_STRTAB's address when the file maps it through no PT_LOAD.
      const addr = s.name === ".dynstr" ? (o.noLoadMapping ? 0x7ff00000 : ELF_BASE + strtabAt) : 0;
      if (i === 0 && o.extendedCounts) {
        // Section header 0 holds the real counts: sh_size = e_shnum, sh_info = e_phnum, sh_link = e_shstrndx.
        size = list.length;
        info = nph;
        link = list.length - 1;
      }
      return Buffer.concat([U32(offsets[i]!), U32(s.type), UW(s.flags ?? 0), UW(addr), UW(contentAt[i]!), UW(size), U32(link), U32(info), UW(1), UW(0)]);
    });
    sectionBytes = Buffer.concat([...datas, ...headers]);
  }

  const fileLen = ehsize + nph * phentsize + body.length + sectionBytes.length;
  // Program headers.
  const phdr = (type: number, flags: number, offset: number, vaddr: number, filesz: number, memsz: number, align: number) =>
    w
      ? Buffer.concat([U32(type), U32(flags), UW(offset), UW(vaddr), UW(vaddr), UW(filesz), UW(memsz), UW(align)])
      : Buffer.concat([U32(type), UW(offset), UW(vaddr), UW(vaddr), UW(filesz), UW(memsz), U32(flags), UW(align)]);
  const phs: Buffer[] = [phdr(1, 5, 0, ELF_BASE, fileLen, fileLen, 0x1000)];
  if (hasInterp) phs.push(phdr(3, 4, interpAt, ELF_BASE + interpAt, o.interp!.length + 1, o.interp!.length + 1, 1));
  if (hasDynamic) phs.push(phdr(2, 6, dynAt, ELF_BASE + dynAt, dynSize, dynSize, 8));

  const hdr = Buffer.alloc(ehsize);
  hdr.write("\x7fELF", 0, "latin1");
  hdr[4] = w ? 2 : 1;
  hdr[5] = big ? 2 : 1;
  hdr[6] = 1;
  U16(o.type ?? 2).copy(hdr, 16);
  U16(o.machine ?? (w ? 0x3e : 0x03)).copy(hdr, 18);
  U32(1).copy(hdr, 20);
  UW(o.entry ?? ELF_BASE + 0x100).copy(hdr, 24);
  UW(phAt).copy(hdr, w ? 32 : 28);
  UW(shoff).copy(hdr, w ? 40 : 32);
  const tail = w ? 52 : 40;
  U16(ehsize).copy(hdr, tail);
  U16(phentsize).copy(hdr, tail + 2);
  U16(o.extendedCounts ? 0xffff : nph).copy(hdr, tail + 4);
  U16(shentsize).copy(hdr, tail + 6);
  U16(o.extendedCounts ? 0 : shnum).copy(hdr, tail + 8);
  U16(o.extendedCounts ? 0xffff : shstrndx).copy(hdr, tail + 10);
  return Buffer.concat([hdr, ...phs, body, sectionBytes]);
}

// --- Mach-O (<mach-o/loader.h>, <mach-o/fat.h>) --------------------------------------------------------------------

export const CPU_X86_64 = 0x01000007;
export const CPU_ARM64 = 0x0100000c;
export const CPU_POWERPC = 18;

export type MachCommand =
  | { dylib: string; cmd: number; stamp?: number }
  | { segment: string; vmaddr?: number; vmsize?: number; fileoff?: number; filesize?: number }
  | { main: number }
  | { signature: { offset: number; size: number } }
  | { raw: number; size: number };

export type MachOptions = { wide?: boolean; big?: boolean; cputype?: number; filetype?: number; commands?: MachCommand[]; flags?: number; sizeofcmdsOverride?: number; ncmdsOverride?: number };

/** A thin Mach-O: mach_header (28 bytes) or mach_header_64 (32), then the load commands. */
export function buildMacho(o: MachOptions = {}): Buffer {
  const wide = o.wide !== false;
  const big = !!o.big;
  const U32 = (v: number) => u32(v, big);
  const U64 = (v: number | bigint) => u64(v, big);
  const cmds = (o.commands ?? []).map((c) => {
    if ("dylib" in c) {
      // struct dylib_command: cmd, cmdsize, then dylib { name offset, timestamp, current_version, compat_version }, name
      const nameBytes = pad(cstr(c.dylib), wide ? 8 : 4);
      const size = 24 + nameBytes.length;
      return Buffer.concat([U32(c.cmd), U32(size), U32(24), U32(c.stamp ?? 2), U32(0x10000), U32(0x10000), nameBytes]);
    }
    if ("segment" in c) {
      const name = Buffer.alloc(16);
      name.write(c.segment, 0, "latin1");
      if (wide) {
        return Buffer.concat([U32(0x19), U32(72), name, U64(c.vmaddr ?? 0), U64(c.vmsize ?? 0x1000), U64(c.fileoff ?? 0), U64(c.filesize ?? 0x1000), U32(7), U32(5), U32(0), U32(0)]);
      }
      return Buffer.concat([U32(0x1), U32(56), name, U32(c.vmaddr ?? 0), U32(c.vmsize ?? 0x1000), U32(c.fileoff ?? 0), U32(c.filesize ?? 0x1000), U32(7), U32(5), U32(0), U32(0)]);
    }
    if ("main" in c) return Buffer.concat([U32(0x80000028), U32(24), U64(c.main), U64(0)]);
    if ("signature" in c) return Buffer.concat([U32(0x1d), U32(16), U32(c.signature.offset), U32(c.signature.size)]);
    return Buffer.concat([U32(c.raw), U32(c.size), Buffer.alloc(Math.max(0, c.size - 8))]);
  });
  const body = Buffer.concat(cmds);
  const magic = wide ? (big ? Buffer.from([0xfe, 0xed, 0xfa, 0xcf]) : Buffer.from([0xcf, 0xfa, 0xed, 0xfe])) : big ? Buffer.from([0xfe, 0xed, 0xfa, 0xce]) : Buffer.from([0xce, 0xfa, 0xed, 0xfe]);
  const header = Buffer.concat([
    magic,
    U32(o.cputype ?? (wide ? CPU_X86_64 : 7)),
    U32(0),
    U32(o.filetype ?? 2),
    U32(o.ncmdsOverride ?? cmds.length),
    U32(o.sizeofcmdsOverride ?? body.length),
    U32(o.flags ?? 0x200000),
    ...(wide ? [U32(0)] : []),
  ]);
  return Buffer.concat([header, body]);
}

/**
 * A universal binary: fat_header { magic, nfat_arch } then fat_arch { cputype, cpusubtype, offset, size, align }
 * per slice (fat_arch_64 carries 64-bit offset and size). The header is stored big-endian; a file whose first
 * bytes read FAT_CIGAM (be ba fe ca) stores it little-endian.
 */
export function buildFat(slices: { cputype: number; data: Buffer }[], o: { littleEndianHeader?: boolean; arch64?: boolean } = {}): Buffer {
  const le = !!o.littleEndianHeader;
  const U32 = (v: number) => u32(v, !le);
  const U64 = (v: number) => u64(v, !le);
  const entry = o.arch64 ? 32 : 20;
  const head = 8 + slices.length * entry;
  const rows: Buffer[] = [];
  const offsets: number[] = [];
  let offset = Math.ceil(head / 0x4000) * 0x4000;
  for (const s of slices) {
    offsets.push(offset);
    rows.push(
      o.arch64
        ? Buffer.concat([U32(s.cputype), U32(0), U64(offset), U64(s.data.length), U32(14), U32(0)])
        : Buffer.concat([U32(s.cputype), U32(0), U32(offset), U32(s.data.length), U32(14)]),
    );
    offset = Math.ceil((offset + s.data.length) / 0x4000) * 0x4000;
  }
  const magic = o.arch64 ? (le ? [0xbf, 0xba, 0xfe, 0xca] : [0xca, 0xfe, 0xba, 0xbf]) : le ? [0xbe, 0xba, 0xfe, 0xca] : [0xca, 0xfe, 0xba, 0xbe];
  const out: Buffer[] = [Buffer.from(magic), U32(slices.length), ...rows];
  let cursor = head;
  slices.forEach((s, i) => {
    out.push(Buffer.alloc(offsets[i]! - cursor), s.data);
    cursor = offsets[i]! + s.data.length;
  });
  return Buffer.concat(out);
}

// --- ZIP (PKWARE APPNOTE) ---------------------------------------------------------------------------------------

const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();
export function crc32(buf: Buffer): number {
  let c = 0xffffffff;
  for (const b of buf) c = CRC_TABLE[(c ^ b) & 0xff]! ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

export type ZipEntry = {
  name: string;
  data: Buffer;
  method?: 0 | 8 | 12 | 14;     // stored, deflate, bzip2 or LZMA (the last two with `compressed` given)
  flags?: number;               // general purpose bit flag (bit 0: encrypted)
  compressed?: Buffer;          // precomputed compressed bytes (overrides compressing `data`)
  declaredSize?: number;        // the uncompressed size the headers say
};

/** A ZIP archive: local headers and data, the central directory, the end of central directory record. */
export function buildZip(entries: ZipEntry[], o: { comment?: string; commentBytes?: Buffer; zip64?: boolean } = {}): Buffer {
  const locals: Buffer[] = [];
  const central: Buffer[] = [];
  let offset = 0;
  for (const e of entries) {
    const method = e.method ?? 8;
    const compressed = e.compressed ?? (method === 8 ? deflateRawSync(e.data) : e.data);
    const crc = crc32(e.data);
    const name = Buffer.from(e.name, "utf8");
    const flags = (e.flags ?? 0) | 0x0800;
    const size = e.declaredSize ?? e.data.length;
    const dosTime = ((12 << 11) | (30 << 5) | 0) & 0xffff;
    const dosDate = (((2024 - 1980) << 9) | (5 << 5) | 17) & 0xffff;
    const local = Buffer.concat([
      u32(0x04034b50),
      u16(20),
      u16(flags),
      u16(method),
      u16(dosTime),
      u16(dosDate),
      u32(crc),
      u32(compressed.length),
      u32(size),
      u16(name.length),
      u16(0),
      name,
      compressed,
    ]);
    central.push(
      Buffer.concat([
        u32(0x02014b50),
        u16(20),
        u16(20),
        u16(flags),
        u16(method),
        u16(dosTime),
        u16(dosDate),
        u32(crc),
        u32(compressed.length),
        u32(size),
        u16(name.length),
        u16(0),
        u16(0),
        u16(0),
        u16(0),
        u32(0),
        u32(offset),
        name,
      ]),
    );
    locals.push(local);
    offset += local.length;
  }
  const dir = Buffer.concat(central);
  const comment = o.commentBytes ?? Buffer.from(o.comment ?? "", "utf8");
  if (o.zip64) {
    // APPNOTE 4.3.14-4.3.16: the zip64 end of central directory record and its locator precede an end record that
    // holds the sentinel values (0xFFFF entries, 0xFFFFFFFF size and offset).
    const record = Buffer.concat([u32(0x06064b50), u64(44), u16(45), u16(45), u32(0), u32(0), u64(entries.length), u64(entries.length), u64(dir.length), u64(offset)]);
    const locator = Buffer.concat([u32(0x07064b50), u32(0), u64(offset + dir.length), u32(1)]);
    const eocd64 = Buffer.concat([u32(0x06054b50), u16(0), u16(0), u16(0xffff), u16(0xffff), u32(0xffffffff), u32(0xffffffff), u16(comment.length), comment]);
    return Buffer.concat([...locals, dir, record, locator, eocd64]);
  }
  const count = Math.min(entries.length, 0xffff);
  const eocd = Buffer.concat([u32(0x06054b50), u16(0), u16(0), u16(count), u16(count), u32(dir.length), u32(offset), u16(comment.length), comment]);
  return Buffer.concat([...locals, dir, eocd]);
}

export const REL_NS = "http://schemas.openxmlformats.org/package/2006/relationships";
export const REL_TYPE = "http://schemas.openxmlformats.org/officeDocument/2006/relationships";
function xmlAttr(value: string): string {
  return value.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/"/g, "&quot;").replace(/'/g, "&apos;");
}

export function rels(items: { id: string; type: string; target: string; mode?: string }[], quote = '"'): string {
  const q = quote;
  return (
    `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<Relationships xmlns=${q}${REL_NS}${q}>` +
    items
      .map((r) => `<Relationship Id=${q}${r.id}${q} Type=${q}${REL_TYPE}/${r.type}${q} Target=${q}${xmlAttr(r.target)}${q}${r.mode ? ` TargetMode=${q}${r.mode}${q}` : ""}/>`)
      .join("") +
    "</Relationships>"
  );
}

/** Bytes a short Python program prints, for a fixture Node cannot build (bzip2, LZMA): the program is written here, from the format. */
export function pyBytes(code: string): Buffer {
  const r = spawnSync("python3", ["-c", code], { maxBuffer: 1 << 28 });
  assert.equal(r.status, 0, String(r.stderr));
  return r.stdout;
}

export async function assertNoTraceback(out: Run): Promise<void> {
  assert.doesNotMatch(out.stderr, /Traceback/);
}
