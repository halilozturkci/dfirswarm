/**
 * Fixtures for prefetch_mam and mam_scan, built from the layouts and never from a tool's output.
 *
 * A Prefetch (SCCA) file as the libscca layout notes lay it out: the version at 0, "SCCA" at 4, the file size at 0x0C,
 * the executable name (UTF-16LE, 60 bytes) at 0x10, the hash at 0x4C; the file information from 0x54 (metrics array offset
 * and entries, trace chains offset and entries, filename strings offset and size, volume information offset, entries and
 * size); the last-run FILETIMEs (0x78 in version 17, 0x80 after, one slot in 17 and 23, eight from 26); the filename strings
 * as one UTF-16LE list of NUL-terminated names; and a volume entry (device path offset and character count, creation
 * FILETIME, serial number, then the path itself).
 *
 * Where the run count sits: in versions 17 and 23 at 0x90 and 0x98. In 26, 30 and 31 it depends on the size of the file
 * information, which is the file metrics array offset (the word at 0x54) less 0x50: Windows 10 files carry 224 (metrics
 * array at 0x130, run count at 0xD0) and 216 (0x128, run count at 0xC8, and the word at 0xD0 holds something else: 0 or 3
 * in the files this was checked on). The builder writes either, with the other position holding a decoy.
 */
import { u16z } from "./windows-pack-harness.ts";

export type Scca = {
  version: number;
  exe: string;
  hash: number;
  runCount: number;
  lastRuns: bigint[];
  names: string[];
  device?: string;
  serial?: number;
  created?: bigint;
  /** The file information size: 224 (the default) or 216 in versions 26, 30 and 31. */
  infoSize?: number;
  /** The metrics array offset written at 0x54, whatever the size says (a layout nobody has seen). */
  metricsAt?: number;
};

export function scca(o: Scca): Buffer {
  const slots = o.version === 17 || o.version === 23 ? 1 : 8;
  const lastAt = o.version === 17 ? 0x78 : 0x80;
  const infoSize = o.infoSize ?? 224;
  const countAt = o.version === 17 ? 0x90 : o.version === 23 ? 0x98 : infoSize === 216 ? 0xc8 : 0xd0;
  // The offsets libscca gives for 17 and 23 (84 plus a file information of 68 and 156 bytes); the tools do not read them there.
  const metricsAt = o.metricsAt ?? (o.version === 17 ? 0x98 : o.version === 23 ? 0xf0 : 0x50 + infoSize);
  const names = Buffer.concat(o.names.map((n) => u16z(n)));
  const namesAt = 0x200;
  const volsAt = namesAt + Math.ceil(names.length / 8) * 8;
  const device = o.device === undefined ? Buffer.alloc(0) : u16z(o.device);
  const b = Buffer.alloc(volsAt + 0x68 + device.length + 8);
  b.writeUInt32LE(o.version, 0);
  b.write("SCCA", 4, "latin1");
  b.writeUInt32LE(0x0f, 8);
  b.writeUInt32LE(b.length, 12);
  Buffer.from(o.exe, "utf16le").copy(b, 0x10);
  b.writeUInt32LE(o.hash, 0x4c);
  b.writeUInt32LE(metricsAt, 0x54);
  b.writeUInt32LE(o.names.length, 0x58);
  b.writeUInt32LE(metricsAt + 32 * o.names.length, 0x5c);
  b.writeUInt32LE(0, 0x60);
  b.writeUInt32LE(namesAt, 0x64);
  b.writeUInt32LE(names.length, 0x68);
  b.writeUInt32LE(volsAt, 0x6c);
  b.writeUInt32LE(o.device === undefined ? 0 : 1, 0x70);
  b.writeUInt32LE(0x68 + device.length, 0x74);
  if (o.version >= 26 && infoSize === 216) b.writeUInt32LE(3, 0xd0); // what the 224 layout calls the run count is something else here
  o.lastRuns.slice(0, slots).forEach((t, i) => b.writeBigUInt64LE(t, lastAt + i * 8));
  b.writeUInt32LE(o.runCount, countAt);
  names.copy(b, namesAt);
  if (o.device !== undefined) {
    b.writeUInt32LE(0x68, volsAt);
    b.writeUInt32LE(o.device.length + 1, volsAt + 4);
    b.writeBigUInt64LE(o.created ?? 0n, volsAt + 8);
    b.writeUInt32LE(o.serial ?? 0, volsAt + 16);
    device.copy(b, volsAt + 0x68);
  }
  return b;
}

/**
 * Xpress Huffman (the MS-XCA LZ77+Huffman format MAM uses): chunks of up to 65536 output bytes, each a
 * 256-byte table of 512 four-bit code lengths and then a bit stream read as little-endian 16-bit words, most
 * significant bit first. Every symbol is given a 9-bit code here (a complete code: 512 symbols of length 9), so
 * symbol s has code s: literals are 0..255 and a match (offset 1, 3 to 17 bytes) is 256 + length - 3. A chunk
 * ends after the symbol that takes it to 65536 bytes and is followed by one zero word; the last by two. With
 * `bare`, the last chunk ends with its last data word and nothing after it, as a stream cut from a file does.
 */
export function xpressHuffman(ops: Array<number | { match: number }>, o: { bare?: boolean } = {}): Buffer {
  const out: Buffer[] = [];
  let i = 0;
  while (i < ops.length) {
    let size = 0;
    const words: number[] = [];
    let acc = 0;
    let nbits = 0;
    const put = (symbol: number): void => {
      for (let b = 8; b >= 0; b--) {
        acc = (acc << 1) | ((symbol >> b) & 1);
        if (++nbits === 16) {
          words.push(acc);
          acc = 0;
          nbits = 0;
        }
      }
    };
    while (i < ops.length && size < 65536) {
      const op = ops[i++];
      if (typeof op === "number") {
        put(op);
        size += 1;
      } else {
        put(256 + op.match - 3);
        size += op.match;
      }
    }
    if (nbits) words.push(acc << (16 - nbits));
    const last = i >= ops.length;
    if (!(o.bare && last)) {
      words.push(0);
      if (last) words.push(0);
    }
    out.push(Buffer.alloc(256, 0x99));
    const w = Buffer.alloc(words.length * 2);
    words.forEach((v, k) => w.writeUInt16LE(v, k * 2));
    out.push(w);
  }
  return Buffer.concat(out);
}

/** A MAM container: "MAM", the method byte, the declared uncompressed size, the compressed data. */
export function mam(declared: number, compressed: Buffer, method = 4): Buffer {
  const head = Buffer.alloc(8);
  head.write("MAM", 0, "latin1");
  head[3] = method;
  head.writeUInt32LE(declared, 4);
  return Buffer.concat([head, compressed]);
}

export const mamOf = (plain: Buffer, o: { bare?: boolean } = {}): Buffer => mam(plain.length, xpressHuffman([...plain], o));

export type PrefetchOut = {
  status: string;
  container: { mam: boolean; declared_uncompressed_size?: number; decompressed_size?: number; bytes_past_declared_size?: number; why?: string; method?: number };
  version?: number;
  supported?: boolean;
  exe_name?: string;
  prefetch_hash?: string;
  run_count?: number | null;
  file_information_size?: number;
  last_runs?: string[];
  last_runs_detail?: Array<{ slot: number; filetime: string; utc: string }>;
  filename_strings?: string[];
  volumes_decoded?: Array<{ device_path: string | null; serial_number: string; created_utc: string | null }>;
  volumes_claimed?: number;
  file_size_matches?: boolean;
  problems: string[];
  all_strings?: unknown;
};

export type ScanOut = {
  status: string;
  count: number;
  hits: Array<{
    offset: number;
    uncomp: number;
    version?: number;
    supported?: boolean;
    name?: string;
    run_count?: number | null;
    file_information_size?: number;
    filename_strings?: string[];
    last_runs?: string[];
    problems?: string[];
  }>;
  candidates: number;
  parsed: number;
  failed: number;
  failed_by_reason: Record<string, number>;
  failures: Array<{ offset: number; reason: string }>;
  filtered_by_name: number;
  size_out_of_range: number;
  unsupported_variant_signatures: number;
};

export const RUN_1 = 133_443_104_001_234_567n; // 2023-11-13T00:53:20.1234567Z
export const SAMPLE_NAMES = [
  "\\VOLUME{01d9aaaabbbb0000-1a2b3c4d}\\WINDOWS\\SYSTEM32\\NTDLL.DLL",
  "\\VOLUME{01d9aaaabbbb0000-1a2b3c4d}\\USERS\\ÖZGÜR\\DOCUMENTS\\RAPOR-ÇALIŞMA.DOCX",
  "\\VOLUME{01d9aaaabbbb0000-1a2b3c4d}\\PROGRAM FILES\\EXAMPLE\\EXAMPLE.EXE",
];

export function sample(version: number, o: Partial<Scca> = {}): Buffer {
  return scca({
    version,
    exe: "EXAMPLE.EXE",
    hash: 0xa1b2c3d4,
    runCount: 7,
    lastRuns: [RUN_1, RUN_1 + 10_000_000n, 0n, 0n, 0n, 0n, 0n, 0n],
    names: SAMPLE_NAMES,
    device: "\\VOLUME{01d9aaaabbbb0000-1a2b3c4d}",
    serial: 0x1a2b3c4d,
    created: RUN_1 - 5_000_000_000n,
    ...o,
  });
}
