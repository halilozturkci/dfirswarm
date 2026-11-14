/**
 * userassist_bam_shimcache against hives described once and read twice: by a stand-in for regipy (always) and by the real library with real regf bytes
 * (where it is installed).
 *
 * Where each layout comes from (the published notes the tool's own header cites; no byte of a real hive is in this repository, and none of these offsets
 * has been checked against one):
 *   UserAssist   value names ROT13 (ASCII letters only); data of 72 bytes: session id (0), run count (4), focus count (8), focus time in ms (12), the last-run
 *                FILETIME (60); data of 16 bytes: session id (0), run count (4), last-run FILETIME (8).
 *   BAM, DAM     ...\Services\bam\State\UserSettings\<SID>: value name an NT device path, data 24 bytes, FILETIME first.
 *   ShimCache    Windows 7: magic 0xBADC0FEE, count (4), a 128-byte header, 32-byte (32-bit) or 48-byte (64-bit) entries: path length, maximum length, path
 *                offset (4 or, after 4 bytes of padding, 8), FILETIME, insert flags, shim flags, data size (4 or 8) and data offset, the path stored after
 *                the entries. Windows 10: the first u32 is the offset of the first record (0x30), records "10ts", 4 unknown, body size, then path length, path,
 *                FILETIME, data size, data. Windows 8.1: header of 0x80, "10ts" records with the insert and shim flags before the FILETIME; Windows 8.0:
 *                "00ts" records with a package name (length, name) before the flags.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { withCwd } from "./tool-library-harness.ts";
import { WIN, body, failed, tool } from "./windows-pack-harness.ts";
import { VARIANTS, type Node, type Val, type Variant } from "./windows-stub-regipy.ts";

function dual(name: string, fn: (v: Variant) => Promise<void>): void {
  for (const v of VARIANTS) test(`${name} [${v.label}]`, { skip: v.skip }, () => fn(v));
}

type Row = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any
type Answer = {
  status: string;
  status_basis: string;
  records: Row[];
  record_count: number;
  records_by_source: Record<string, number>;
  unsupported_count: number;
  filtered_out: number;
  contains_blind_records: number | null;
  problems: string[];
  problem_count: number;
  hive_dirty: boolean;
  transaction_logs_beside_hive: string[];
  transaction_logs_replayed: boolean;
  interpretation_limits: string[];
  cross_check: { result: string };
  sources: Record<string, { present: boolean }>;
  all_results?: string;
  walk_stopped_by_time_limit: boolean;
  [key: string]: unknown;
};

const TOOL = "userassist_bam_shimcache";
const FT = 133_443_104_001_234_567n; // 2023-11-13T00:53:20.1234567Z
const FT_ISO = "2023-11-13T00:53:20.1234567Z";
const rot13 = (s: string): string => s.replace(/[A-Za-z]/g, (c) => String.fromCharCode(((c.charCodeAt(0) - (c <= "Z" ? 65 : 97) + 13) % 26) + (c <= "Z" ? 65 : 97)));
const u16le = (n: number): Buffer => { const b = Buffer.alloc(2); b.writeUInt16LE(n); return b; };
const u32le = (n: number): Buffer => { const b = Buffer.alloc(4); b.writeUInt32LE(n); return b; };
const u64le = (n: bigint): Buffer => { const b = Buffer.alloc(8); b.writeBigUInt64LE(n); return b; };
const utf16 = (s: string): Buffer => Buffer.from(s, "utf16le");

const ua72 = (session: number, run: number, focus: number, ms: number, ft: bigint): Buffer => {
  const b = Buffer.alloc(72);
  b.writeUInt32LE(session, 0); b.writeUInt32LE(run, 4); b.writeUInt32LE(focus, 8); b.writeUInt32LE(ms, 12); b.writeBigUInt64LE(ft, 60);
  return b;
};
const ua16 = (session: number, run: number, ft: bigint): Buffer => Buffer.concat([u32le(session), u32le(run), u64le(ft)]);
const bam24 = (ft: bigint): Buffer => Buffer.concat([u64le(ft), Buffer.alloc(16)]);

const UA_KEY = ["Software", "Microsoft", "Windows", "CurrentVersion", "Explorer", "UserAssist"];
function ntuser(values: Val[], guid = "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}"): Node {
  let leaf: Node = { name: "Count", values };
  let node: Node = { name: guid, children: [leaf] };
  for (const part of [...UA_KEY].reverse()) node = { name: part, children: [node] };
  return { name: "ROOT", children: [node] };
}
function system(opts: { bam?: Array<{ sid: string; values: Val[] }>; dam?: Array<{ sid: string; values: Val[] }>; shim?: Buffer; current?: number; bamPath?: "state" | "old" }): Node {
  const cs: Node[] = [];
  const services: Node[] = [];
  const tail = opts.bamPath === "old" ? [] : [{ name: "State" }];
  const settings = (kind: string, list: Array<{ sid: string; values: Val[] }>): Node => {
    const users: Node = { name: "UserSettings", children: list.map((e) => ({ name: e.sid, values: e.values })) };
    return { name: kind, children: tail.length ? [{ name: "State", children: [users] }] : [users] };
  };
  if (opts.bam) services.push(settings("bam", opts.bam));
  if (opts.dam) services.push(settings("dam", opts.dam));
  const control: Node[] = [];
  if (opts.shim) control.push({ name: "Session Manager", children: [{ name: "AppCompatCache", values: [{ name: "AppCompatCache", type: "binary", value: opts.shim }] }] });
  cs.push({ name: "ControlSet001", children: [{ name: "Services", children: services }, { name: "Control", children: control }] });
  return { name: "ROOT", children: [{ name: "Select", values: [{ name: "Current", type: "dword", value: opts.current ?? 1 }] }, ...cs] };
}

const SIDA = "S-1-5-21-1111111111-2222222222-3333333333-1001";
const SIDB = "S-1-5-21-1111111111-2222222222-3333333333-1002";

// --- ShimCache blobs ------------------------------------------------------------------

function shim7(entries: Array<{ path: string; ft: bigint; ins?: number; shim?: number }>, wide: boolean, declared?: number): Buffer {
  const size = wide ? 48 : 32;
  const header = Buffer.alloc(128);
  header.writeUInt32LE(0xbadc0fee, 0);
  header.writeUInt32LE(declared ?? entries.length, 4);
  let pathAt = 128 + size * entries.length;
  const rows: Buffer[] = [];
  const paths: Buffer[] = [];
  for (const e of entries) {
    const p = utf16(e.path);
    const row = Buffer.alloc(size);
    row.writeUInt16LE(p.length, 0);
    row.writeUInt16LE(p.length + 2, 2);
    if (wide) { row.writeBigUInt64LE(BigInt(pathAt), 8); row.writeBigUInt64LE(e.ft, 16); row.writeUInt32LE(e.ins ?? 2, 24); row.writeUInt32LE(e.shim ?? 0, 28); }
    else { row.writeUInt32LE(pathAt, 4); row.writeBigUInt64LE(e.ft, 8); row.writeUInt32LE(e.ins ?? 2, 16); row.writeUInt32LE(e.shim ?? 0, 20); }
    rows.push(row);
    paths.push(p);
    pathAt += p.length;
  }
  return Buffer.concat([header, ...rows, ...paths]);
}

/** One "ts" record: tag, 4 unknown, body size, body. */
function tsRecord(tag: string, body: Buffer): Buffer {
  return Buffer.concat([Buffer.from(tag, "latin1"), Buffer.alloc(4), u32le(body.length), body]);
}
function shim10(entries: Array<{ path: string; ft: bigint; data?: Buffer }>, first = 0x30): Buffer {
  return Buffer.concat([Buffer.alloc(first), ...entries.map((e) => {
    const p = utf16(e.path);
    const data = e.data ?? Buffer.from([1, 2, 3, 4]);
    return tsRecord("10ts", Buffer.concat([u16le(p.length), p, u64le(e.ft), u32le(data.length), data]));
  })]);
}
function withHeaderWord(buf: Buffer, word: number): Buffer { buf.writeUInt32LE(word, 0); return buf; }
function shim81(entries: Array<{ path: string; ft: bigint; ins: number; shim: number }>): Buffer {
  const header = Buffer.alloc(0x80); header.writeUInt32LE(0x80, 0);
  return Buffer.concat([header, ...entries.map((e) => {
    const p = utf16(e.path);
    const data = Buffer.from([9, 9]);
    return tsRecord("10ts", Buffer.concat([u16le(p.length), p, u32le(e.ins), u32le(e.shim), u64le(e.ft), u32le(data.length), data]));
  })]);
}
function shim80(entries: Array<{ path: string; pkg: string; ft: bigint; ins: number; shim: number }>): Buffer {
  const header = Buffer.alloc(0x80); header.writeUInt32LE(0x80, 0);
  return Buffer.concat([header, ...entries.map((e) => {
    const p = utf16(e.path), k = utf16(e.pkg);
    const data = Buffer.from([7]);
    return tsRecord("00ts", Buffer.concat([u16le(p.length), p, u16le(k.length), k, u32le(e.ins), u32le(e.shim), u64le(e.ft), u32le(data.length), data]));
  })]);
}
const win10 = (entries: Array<{ path: string; ft: bigint; data?: Buffer }>): Buffer => withHeaderWord(shim10(entries), 0x30);

async function run(v: Variant, root: Node, args: Record<string, unknown> = {}, opts: { primarySeq?: number; secondarySeq?: number } = {}, file = "work/h.dat"): Promise<{ out: Answer; cwd: string; raw: string }> {
  let result: { out: Answer; cwd: string; raw: string } | undefined;
  await withCwd(async (cwd) => {
    const env = await v.write(cwd, file, root, opts);
    const r = await tool(TOOL, cwd, { hive: file, ...args }, env);
    result = { out: body<Answer>(r), cwd, raw: r.stdout };
  });
  return result as { out: Answer; cwd: string; raw: string };
}

// --- UserAssist ------------------------------------------------------------------------

dual("UserAssist: the 72-byte and 16-byte layouts decode, with the raw and the ROT13-decoded name side by side, non-ASCII names included", async (v) => {
  // The second name has a character above U+00FF, so the hive stores it as UTF-16 (as Windows does) and its other non-ASCII letters survive.
  const names = ["UEME_RUNPATH:C:\\Tools\\Alpha Tool.exe", "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\\u015eirket\\Caf\u00e9\\na\u00efve.exe", "Microsoft.Windows.Explorer"];
  const { out } = await run(v, ntuser([
    { name: rot13(names[0]), type: "binary", value: ua72(3, 12, 4, 90_000, FT) },
    { name: rot13(names[1]), type: "binary", value: ua16(0, 5, FT) },
    { name: rot13(names[2]), type: "binary", value: ua72(1, 0, 0, 0, 0n) },
  ]));
  assert.equal(out.status, "complete", out.status_basis + JSON.stringify(out.problems));
  assert.equal(out.record_count, 3);
  assert.deepEqual(out.records_by_source, { userassist: 3, bam: 0, shimcache: 0, dam: 0 });
  const by = (n: string): Row => out.records.find((r) => r.name_decoded === n) as Row;
  const a = by(names[0]);
  assert.equal(a.name_raw, rot13(names[0]));
  assert.equal(a.layout, "userassist-72");
  assert.match(a.layout_basis, /72 bytes/);
  assert.deepEqual([a.session_id, a.run_count, a.focus_count, a.focus_time_ms], ["3", "12", "4", "90000"]);
  assert.equal(a.last_execution, FT_ISO);
  assert.equal(a.last_execution_filetime, String(FT));
  assert.equal(a.raw_hex, ua72(3, 12, 4, 90_000, FT).toString("hex"));
  assert.equal(a.raw_length, "72");
  assert.equal(a.sid, null);
  assert.match(a.sid_basis, /does not name its owner/);
  assert.equal(a.value_type, "REG_BINARY");
  const b = by(names[1]);
  assert.equal(b.layout, "userassist-16");
  assert.deepEqual([b.run_count, b.last_execution], ["5", FT_ISO]);
  assert.equal(b.focus_count, undefined);
  assert.equal(by(names[2]).last_execution, null, "a zero FILETIME is no time");
  assert.equal(by(names[2]).last_execution_filetime, "0");
  assert.equal(out.cross_check.result, "not_run");
  assert.ok(out.interpretation_limits.some((l) => /not execution/.test(l)) && out.interpretation_limits.some((l) => /not a user with no entry/.test(l)) && out.interpretation_limits.some((l) => /not an execution time|not a time the program ran/.test(l)));
});

dual("UserAssist: a name the hive stores one byte a character with a letter above 0x7F is shown as regipy gives it, U+FFFD for the letter, and the answer is partial and says so", async (v) => {
  // Windows stores "M\u00fcller" one byte a character (every character is below U+0100); regipy decodes such a name as ASCII.
  const lost = "C:\\Users\\M\u00fcller\\tool.exe";
  const { out } = await run(v, ntuser([
    { name: rot13(lost), type: "binary", value: ua72(1, 2, 0, 0, FT) },
    { name: rot13("C:\\Users\\plain\\tool.exe"), type: "binary", value: ua72(1, 3, 0, 0, FT) },
  ]));
  assert.equal(out.status, "partial", out.status_basis);
  assert.equal(out.record_count, 2);
  assert.ok(out.records.some((r) => r.name_decoded === "C:\\Users\\M\ufffdller\\tool.exe"), JSON.stringify(out.records.map((r) => r.name_decoded)));
  assert.ok(out.problems.some((p) => /1 value name\(s\) here hold U\+FFFD where regipy could not decode a character/.test(p)), JSON.stringify(out.problems));
});

dual("UserAssist: owner_sid is recorded as given by the caller, and the sid filter finds it", async (v) => {
  const root = ntuser([{ name: rot13("C:\\a\\one.exe"), type: "binary", value: ua72(1, 1, 1, 1, FT) }]);
  const given = await run(v, root, { owner_sid: SIDA });
  assert.equal(given.out.records[0].sid, SIDA);
  assert.match(given.out.records[0].sid_basis, /given by the caller/);
  const hit = await run(v, root, { owner_sid: SIDA, sid: SIDA.toLowerCase() });
  assert.equal(hit.out.record_count, 1);
  const miss = await run(v, root, { owner_sid: SIDA, sid: SIDB });
  assert.equal(miss.out.record_count, 0);
  assert.equal(miss.out.filtered_out, 1);
  const none = await run(v, root, { sid: SIDA });
  assert.equal(none.out.record_count, 0, "a record with no SID never matches a sid filter");
});

dual("UserAssist: a value of an unknown length is unsupported with its bytes kept, and the answer is partial naming the number", async (v) => {
  const odd = Buffer.from(Array.from({ length: 20 }, (_, i) => i + 1));
  const { out } = await run(v, ntuser([
    { name: rot13("C:\\a\\one.exe"), type: "binary", value: ua72(1, 2, 3, 4, FT) },
    { name: "HRZR_PGYFRFFVBA", type: "binary", value: odd },
    { name: rot13("truncated"), type: "binary", value: ua72(1, 2, 3, 4, FT).subarray(0, 40) },
  ]));
  assert.equal(out.status, "partial");
  assert.equal(out.unsupported_count, 2);
  assert.match(out.status_basis, /2 record\(s\)/);
  const u = out.records.find((r) => r.name_raw === "HRZR_PGYFRFFVBA") as Row;
  assert.equal(u.layout, "unknown");
  assert.match(u.unsupported, /20 bytes/);
  assert.equal(u.raw_hex, odd.toString("hex"), "the raw bytes are kept");
  assert.equal(u.run_count, undefined, "nothing is decoded from an unknown layout");
  assert.equal(u.name_decoded, "UEME_CTLSESSION");
  const t = out.records.find((r) => r.name_decoded === "truncated") as Row;
  assert.match(t.unsupported, /40 bytes/);
  assert.equal(t.raw_length, "40");
});

dual("UserAssist: a value of another type is unsupported, not decoded", async (v) => {
  const { out } = await run(v, ntuser([{ name: "Version", type: "dword", value: 5 }]));
  assert.equal(out.status, "partial");
  assert.match((out.records[0] as Row).unsupported, /not binary data/);
});

dual("UserAssist: a name of 300 characters and a name with control characters are read and answered as JSON", async (v) => {
  const long = "C:\\" + "Folder\\".repeat(40) + "tool.exe";
  const ctl = "C:\\dir\u0001\u0007\\x.exe";
  const { out } = await run(v, ntuser([
    { name: rot13(long), type: "binary", value: ua72(1, 1, 1, 1, FT) },
    { name: rot13(ctl), type: "binary", value: ua72(1, 1, 1, 1, FT) },
  ]));
  assert.equal(out.record_count, 2);
  assert.ok(["complete", "partial"].includes(out.status));
  assert.ok(out.records.every((r) => typeof r.layout === "string"));
});

// --- BAM and DAM ------------------------------------------------------------------------

dual("BAM and DAM: the SID is the name of the key, the FILETIME is the first 8 bytes, and the version values are counted, not listed", async (v) => {
  const { out } = await run(v, system({
    bam: [
      { sid: SIDA, values: [
        { name: "\\Device\\HarddiskVolume3\\Windows\\System32\\cmd.exe", type: "binary", value: bam24(FT) },
        { name: "Version", type: "dword", value: 1 },
        { name: "SequenceNumber", type: "dword", value: 42 },
      ] },
      { sid: SIDB, values: [{ name: "\\Device\\HarddiskVolume3\\Users\\b\\tool.exe", type: "binary", value: bam24(FT + 10_000_000n) }] },
    ],
    dam: [{ sid: SIDA, values: [{ name: "\\Device\\HarddiskVolume3\\dam.exe", type: "binary", value: bam24(FT) }] }],
  }));
  assert.equal(out.status, "complete", out.status_basis + JSON.stringify(out.problems));
  assert.equal(out.record_count, 3);
  assert.equal(out.metadata_values_not_listed, 2);
  const cmd = out.records.find((r) => /cmd\.exe$/.test(r.path)) as Row;
  assert.equal(cmd.source, "bam");
  assert.equal(cmd.sid, SIDA);
  assert.equal(cmd.sid_basis, "the name of the key the value is in");
  assert.equal(cmd.last_execution, FT_ISO);
  assert.equal(cmd.layout, "bam-24");
  assert.equal(cmd.control_set, "ControlSet001");
  assert.equal(cmd.current_control_set, true);
  assert.equal(cmd.raw_hex, bam24(FT).toString("hex"));
  assert.equal((out.records.find((r) => /dam\.exe$/.test(r.path)) as Row).source, "dam");
  const other = out.records.find((r) => /tool\.exe$/.test(r.path)) as Row;
  assert.equal(other.sid, SIDB);
  assert.equal(other.last_execution, "2023-11-13T00:53:21.1234567Z");
  const onlyB = (await run(v, system({ bam: [{ sid: SIDA, values: [{ name: "\\Device\\HarddiskVolume3\\a.exe", type: "binary", value: bam24(FT) }] }, { sid: SIDB, values: [{ name: "\\Device\\HarddiskVolume3\\b.exe", type: "binary", value: bam24(FT) }] }] }), { sid: SIDB })).out;
  assert.deepEqual(onlyB.records.map((r) => r.path), ["\\Device\\HarddiskVolume3\\b.exe"]);
  assert.equal(onlyB.filtered_out, 1);
});

dual("BAM: the older key without State is read, and a value of an unknown length is unsupported", async (v) => {
  const { out } = await run(v, system({ bamPath: "old", bam: [{ sid: SIDA, values: [
    { name: "\\Device\\HarddiskVolume2\\a.exe", type: "binary", value: bam24(FT) },
    { name: "\\Device\\HarddiskVolume2\\b.exe", type: "binary", value: Buffer.alloc(8, 1) },
  ] }] }), { source: "bam" });
  assert.equal(out.record_count, 2);
  assert.equal(out.unsupported_count, 1);
  assert.equal(out.status, "partial");
  assert.deepEqual(Object.keys(out.sources), ["bam"]);
});

// --- ShimCache -----------------------------------------------------------------------------

const PATHS = ["C:\\Windows\\System32\\cmd.exe", "C:\\Users\\a\\Downloads\\Tool \u00e9.exe", "\\\\server\\share\\x.dll"];

dual("ShimCache: the Windows 7 layout in its 64-bit and 32-bit shapes decodes path, FILETIME and flags", async (v) => {
  for (const wide of [true, false]) {
    const { out } = await run(v, system({ shim: shim7(PATHS.map((p, i) => ({ path: p, ft: FT + BigInt(i) * 10_000_000n, ins: 2 + i, shim: i })), wide) }), { source: "shimcache" });
    assert.equal(out.status, "complete", out.status_basis + JSON.stringify(out.problems));
    assert.equal(out.record_count, 3);
    const first = out.records[0];
    assert.equal(first.layout, wide ? "shimcache-win7-64" : "shimcache-win7-32");
    assert.match(first.layout_basis, /not verified against a real hive/);
    assert.deepEqual(out.records.map((r) => r.path), PATHS, "the cache's own order");
    assert.equal(out.records[1].last_modified, "2023-11-13T00:53:21.1234567Z");
    assert.equal(out.records[1].last_modified_filetime, String(FT + 10_000_000n));
    assert.deepEqual([out.records[2].insert_flags, out.records[2].shim_flags], ["4", "2"]);
    assert.equal(out.records[0].last_execution, undefined, "a ShimCache time is never called an execution time");
    assert.equal(out.records[0].sid, null);
    assert.equal(out.records[0].entry_position, "0");
  }
});

dual("ShimCache: the Windows 10, 8.1 and 8.0 layouts decode and a record's data size is checked against its body", async (v) => {
  const data = Buffer.alloc(10, 5);
  const w10 = (await run(v, system({ shim: win10([{ path: PATHS[0], ft: FT, data }, { path: PATHS[1], ft: FT }]) }), { source: "shimcache" })).out;
  assert.equal(w10.status, "complete", w10.status_basis);
  assert.deepEqual(w10.records.map((r) => [r.layout, r.path, r.last_modified, r.data_length]), [["shimcache-win10", PATHS[0], FT_ISO, "10"], ["shimcache-win10", PATHS[1], FT_ISO, "4"]]);
  assert.equal(w10.records[0].raw_hex.includes(data.toString("hex")), false, "the entry's data blob is counted, not written out");
  const w81 = (await run(v, system({ shim: shim81([{ path: PATHS[0], ft: FT, ins: 6, shim: 7 }]) }), { source: "shimcache" })).out;
  assert.deepEqual([w81.records[0].layout, w81.records[0].path, w81.records[0].last_modified, w81.records[0].insert_flags, w81.records[0].shim_flags], ["shimcache-win8.1", PATHS[0], FT_ISO, "6", "7"]);
  const w80 = (await run(v, system({ shim: shim80([{ path: PATHS[1], pkg: "Contoso.App", ft: FT, ins: 1, shim: 2 }]) }), { source: "shimcache" })).out;
  assert.deepEqual([w80.records[0].layout, w80.records[0].path, w80.records[0].last_modified, w80.records[0].insert_flags], ["shimcache-win8.0", PATHS[1], FT_ISO, "1"]);
});

dual("ShimCache: an unknown header, a truncated entry, a record whose data size lies and a header that declares too many are unsupported or problems, never decoded by guess", async (v) => {
  const unknown = (await run(v, system({ shim: Buffer.concat([u32le(0x12345678), Buffer.alloc(200, 1)]) }), { source: "shimcache" })).out;
  assert.equal(unknown.status, "partial");
  assert.equal(unknown.records[0].layout, "unknown");
  assert.match(unknown.records[0].unsupported, /no known layout/);
  assert.equal(unknown.records[0].raw_length, "204");
  const xp = (await run(v, system({ shim: Buffer.concat([u32le(0xdeadbeef), Buffer.alloc(396)]) }), { source: "shimcache" })).out;
  assert.match(xp.records[0].layout_basis, /XP/);
  const full = win10([{ path: PATHS[0], ft: FT }, { path: PATHS[1], ft: FT }]);
  const cut = (await run(v, system({ shim: full.subarray(0, full.length - 12) }), { source: "shimcache" })).out;
  assert.equal(cut.status, "partial");
  assert.equal(cut.records[0].path, PATHS[0]);
  assert.match(cut.records[1].unsupported, /claims \d+ body bytes/);
  const lying = Buffer.from(win10([{ path: PATHS[0], ft: FT }]));
  lying.writeUInt32LE(99, lying.length - 8); // the data size field, 4 + 4 bytes from the end
  const lie = (await run(v, system({ shim: lying }), { source: "shimcache" })).out;
  assert.match(lie.records[0].unsupported, /does not fit the Windows 10 record shape/);
  assert.equal(lie.status, "partial");
  const many = (await run(v, system({ shim: shim7([{ path: PATHS[0], ft: FT }], true, 5000) }), { source: "shimcache" })).out;
  assert.equal(many.status, "partial");
  assert.ok(many.problems.some((p) => /declares 5000 entries and [0-9]+ fit/.test(p)));
  const bad = Buffer.from(shim7([{ path: PATHS[0], ft: FT }], true));
  bad.writeUInt16LE(60000, 128); // a path length that runs off the value
  const off = (await run(v, system({ shim: bad }), { source: "shimcache" })).out;
  assert.equal(off.records[0].layout, "unknown");
});

// --- the hive ---------------------------------------------------------------------------------

dual("a hive that is dirty is said to be, with its logs named and not replayed; a hive without any source key fails with JSON", async (v) => {
  await withCwd(async (cwd) => {
    const env = await v.write(cwd, "work/NTUSER.DAT", ntuser([{ name: rot13("a"), type: "binary", value: ua16(1, 1, FT) }]), { primarySeq: 12, secondarySeq: 11 });
    await writeFile(join(cwd, "work", "NTUSER.DAT.LOG1"), Buffer.alloc(512));
    const out = body<Answer>(await tool(TOOL, cwd, { hive: "work/NTUSER.DAT" }, env));
    assert.equal(out.hive_dirty, true);
    assert.deepEqual(out.transaction_logs_beside_hive, ["work/NTUSER.DAT.LOG1"]);
    assert.equal(out.transaction_logs_replayed, false);
    // A dirty hive whose logs were not replayed is never plainly complete: the records may differ from the live registry's.
    assert.equal(out.status, "partial");
    assert.match(out.status_basis, /the hive is dirty \(its sequence numbers 12 and 11 differ\) and no transaction log was replayed: the tool looked for \.LOG1, \.LOG2 and \.LOG beside the hive \(transaction_logs_looked_for\) and found 1 \(transaction_logs_beside_hive\), and it replays none/);
    assert.match(out.status_basis, /may differ from the live registry \(give registry_recover the hive and its logs/);
    assert.deepEqual((out as unknown as { transaction_logs_looked_for: string[] }).transaction_logs_looked_for, ["work/NTUSER.DAT.LOG1", "work/NTUSER.DAT.LOG2", "work/NTUSER.DAT.LOG"]);
    const cleanEnv = await v.write(cwd, "work/clean/NTUSER.DAT", ntuser([{ name: rot13("a"), type: "binary", value: ua16(1, 1, FT) }]));
    const clean = body<Answer>(await tool(TOOL, cwd, { hive: "work/clean/NTUSER.DAT" }, cleanEnv));
    assert.deepEqual([clean.hive_dirty, clean.status], [false, "complete"], "the same hive with its sequence numbers equal is complete");
    assert.ok(out.interpretation_limits.some((l) => /not replayed/.test(l)));
    const env2 = await v.write(cwd, "work/empty.dat", { name: "ROOT", children: [{ name: "Other" }] });
    const gone = failed(await tool(TOOL, cwd, { hive: "work/empty.dat" }, env2));
    assert.match(gone.error, /no source key/);
    const explicit = failed(await tool(TOOL, cwd, { hive: "work/NTUSER.DAT", source: "bam" }, env));
    assert.match(explicit.error, /no source key/);
  });
});

dual("wrong arguments are refused as JSON before any read", async (v) => {
  await withCwd(async (cwd) => {
    const env = await v.write(cwd, "work/h.dat", ntuser([]));
    for (const bad of [{}, { hive: 1 }, { hive: "work/h.dat", source: "x" }, { hive: "work/h.dat", limit: 0 }, { hive: "work/h.dat", contains: "" }, { hive: "work/h.dat", sid: "nope" },
      { hive: "work/h.dat", owner_sid: 5 }, { hive: "work/h.dat", write_values: "yes" }, { hive: "work/nothere.dat" }, { hive: "work" }]) {
      const r = failed(await tool(TOOL, cwd, bad, env));
      assert.ok(typeof r.error === "string" && r.error.length > 0, JSON.stringify(bad));
    }
    const notHive = join(cwd, "work", "junk.dat");
    await writeFile(notHive, "not a hive");
    assert.match(failed(await tool(TOOL, cwd, { hive: "work/junk.dat" }, env)).error, /could not open the hive/);
  });
});

// --- withholding, filters, files, hostile input ---------------------------------------------------------------

import { spawnSync } from "node:child_process";
import { readFileSync, statSync } from "node:fs";
import { SHAPES, fragmentLeaked, leaked, plant } from "./windows-canary.ts";
import { jobEnv } from "./windows-tool-contract.ts";

const FILE_SHAPES = SHAPES.filter((s) => s.fileOk && !s.residual && ["ghp", "glpat", "akia", "npm", "sk_live", "sendgrid"].includes(s.name));

/** Everything a run wrote under cwd (the result files), as text. */
async function filesUnder(dir: string): Promise<string[]> {
  const out: string[] = [];
  for (const e of await readdir(dir, { withFileTypes: true }).catch(() => [])) {
    const full = join(dir, e.name);
    if (e.isDirectory()) out.push(...(await filesUnder(full)));
    else out.push(await readFile(full, "utf8"));
  }
  return out;
}
/** Hexadecimal in an answer read back as the text it holds (Latin-1 and UTF-16LE), so that a secret hidden in raw_hex is found too. */
function unhex(text: string): string[] {
  const views: string[] = [];
  for (const m of text.matchAll(/"raw_hex": "([0-9a-f]{8,})"/g)) {
    const b = Buffer.from(m[1], "hex");
    views.push(b.toString("latin1"), b.toString("utf16le"), b.subarray(1).toString("utf16le"));
  }
  return views;
}

dual("a token-shaped file name is never printed whole, in any of the three sources, nor its hexadecimal, nor its result file; the filters look only at the shown text (oracle twin)", async (v) => {
  for (const shape of FILE_SHAPES) {
    const [canary] = plant(shape, 1, 7);
    const core = canary.cores[0];
    const fileName = `C:\\Users\\a\\${canary.text}.exe`;
    await withCwd(async (cwd) => {
      const env = await v.write(cwd, "work/NTUSER.DAT", ntuser([{ name: rot13(fileName), type: "binary", value: ua72(1, 1, 1, 1, FT) }]));
      const env2 = await v.write(cwd, "work/SYSTEM", system({
        bam: [{ sid: SIDA, values: [{ name: `\\Device\\HarddiskVolume3\\Users\\a\\${canary.text}.exe`, type: "binary", value: bam24(FT) }] }],
        shim: win10([{ path: fileName, ft: FT }]),
      }));
      const runs = [
        await tool(TOOL, cwd, { hive: "work/NTUSER.DAT", limit: 1 }, env),
        await tool(TOOL, cwd, { hive: "work/SYSTEM", limit: 1 }, env2),
        await tool(TOOL, cwd, { hive: "work/SYSTEM", source: "shimcache", limit: 1 }, env2),
      ];
      const outs = runs.map((r) => body<Answer>(r));
      const texts = [...runs.map((r) => r.stdout), ...(await filesUnder(join(cwd, "work", "s1")))];
      const all = [...texts, ...texts.flatMap(unhex)];
      assert.equal(all.findIndex((t) => t.includes(core)), -1, `${shape.name}: printed whole, in text ${all.findIndex((t) => t.includes(core))} of ${texts.length}: ` + all.map((t) => t.slice(Math.max(t.indexOf(core) - 60, 0), t.indexOf(core) + 60)).find((t, i) => all[i].includes(core)));
      assert.equal(leaked([canary], all), 0, `${shape.name}: printed whole`);
      assert.equal(fragmentLeaked([canary], all), 0, `${shape.name}: a piece of it printed`);
      // the oracle twin: a needle that is only in the withheld text finds nothing (and says it was blind); the same needle in plain text finds the record
      const needle = core.slice(0, 12);
      for (const [hive, e, source] of [["work/NTUSER.DAT", env, "userassist"], ["work/SYSTEM", env2, "shimcache"], ["work/SYSTEM", env2, "bam"]] as Array<[string, Record<string, string>, string]>) {
        const probe = body<Answer>(await tool(TOOL, cwd, { hive, source, contains: needle }, e));
        assert.equal(probe.record_count, 0, `${shape.name}/${source}: a needle inside withheld text must not match`);
        assert.equal(probe.contains_blind_records, 1, `${shape.name}/${source}: blind`);
        assert.equal(probe.status, "partial");
        assert.match(probe.status_basis, /contains_blind_records|may be in what is withheld/);
        assert.ok(!JSON.stringify(probe).includes(needle), "the needle is not echoed");
      }
      assert.ok(outs.every((o) => o.status === "partial" || o.status === "complete"));
    });
  }
  await withCwd(async (cwd) => {
    const plain = "C:\\Users\\a\\harbor-notes.exe";
    const env = await v.write(cwd, "work/NTUSER.DAT", ntuser([{ name: rot13(plain), type: "binary", value: ua72(1, 1, 1, 1, FT) }, { name: rot13("C:\\other.exe"), type: "binary", value: ua72(1, 1, 1, 1, FT) }]));
    const hit = body<Answer>(await tool(TOOL, cwd, { hive: "work/NTUSER.DAT", contains: "HARBOR" }, env));
    assert.equal(hit.record_count, 1);
    assert.equal(hit.contains_blind_records, 0);
    assert.equal(hit.filtered_out, 1);
    assert.equal(hit.status, "complete");
    const rawName = body<Answer>(await tool(TOOL, cwd, { hive: "work/NTUSER.DAT", contains: rot13("harbor") }, env));
    assert.equal(rawName.record_count, 1, "the raw (ROT13) name is shown too, so it can be matched");
  });
});

dual("the result file holds every record and the answer's counts equal it, in a job and outside one", async (v) => {
  const values = Array.from({ length: 600 }, (_, i) => ({ name: `\\Device\\HarddiskVolume3\\App${String(i).padStart(4, "0")}\\run.exe`, type: "binary" as const, value: bam24(FT + BigInt(i)) }));
  await withCwd(async (cwd) => {
    const env = await v.write(cwd, "work/SYSTEM", system({ bam: [{ sid: SIDA, values }] }));
    for (const jobbed of [false, true]) {
      const e = jobbed ? { ...env, ...jobEnv(cwd) } : env;
      const out = body<Answer>(await tool(TOOL, cwd, { hive: "work/SYSTEM", limit: 100 }, e));
      assert.equal(out.record_count, 600);
      assert.equal(out.records.length, 100);
      assert.equal(out.truncated, true);
      assert.equal(out.records_by_source.bam, 600);
      assert.ok(out.all_results, "the whole result is named");
      const file = jobbed ? join(cwd, "out", "tool-output", String(out.all_results).split("/").pop() as string) : join(cwd, out.all_results as string);
      const lines = readFileSync(file, "utf8").trim().split("\n");
      assert.equal(lines.length, 600, jobbed ? "in a job" : "outside a job");
      assert.ok(lines.every((l) => JSON.parse(l).layout === "bam-24"));
      assert.equal(statSync(file).size > 0, true);
    }
  });
});

dual("write_values is refused outside a secret-output job, and in one the originals go to a 0600 file and never to the answer", async (v) => {
  const [canary] = plant(FILE_SHAPES[0], 1, 3);
  await withCwd(async (cwd) => {
    const env = await v.write(cwd, "work/SYSTEM", system({ shim: win10([{ path: `C:\\x\\${canary.text}.exe`, ft: FT }]) }));
    const refused = failed(await tool(TOOL, cwd, { hive: "work/SYSTEM", write_values: true }, env));
    assert.match(refused.error, /secret_output|SECRET_OUTPUT|secret output/);
    const job = { ...env, ...jobEnv(cwd), SECRET_OUTPUT: "1" };
    const run = await tool(TOOL, cwd, { hive: "work/SYSTEM", write_values: true }, job);
    const out = body<Answer>(run);
    assert.equal(leaked([canary], [run.stdout]), 0);
    const file = join(cwd, "out", "userassist_bam_shimcache-values.jsonl");
    assert.equal(statSync(file).mode & 0o777, 0o600);
    assert.equal(leaked([canary], [readFileSync(file, "utf8")]), 1, "the original is in the values file");
    assert.ok(["complete", "partial"].includes(out.status));
  });
});

dual("a hive path that is a named pipe is refused at once, and thousands of values and entries are read without a quadratic phase", async (v) => {
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "work"), { recursive: true });
    const fifo = join(cwd, "work", "pipe.dat");
    assert.equal(spawnSync("mkfifo", [fifo]).status, 0);
    const started = Date.now();
    const env0 = await v.write(cwd, "work/ok.dat", ntuser([]));
    const refused = failed(await tool(TOOL, cwd, { hive: "work/pipe.dat" }, env0));
    assert.match(refused.error, /not a regular file/);
    assert.ok(Date.now() - started < 10_000, "no wait on a pipe");
    const many = Array.from({ length: 6000 }, (_, i) => ({ name: rot13(`C:\\Apps\\App${i}\\run.exe`), type: "binary" as const, value: ua72(i, i, i, i, FT) }));
    const env = await v.write(cwd, "work/NTUSER.DAT", ntuser(many));
    const t0 = Date.now();
    const out = body<Answer>(await tool(TOOL, cwd, { hive: "work/NTUSER.DAT", limit: 10 }, env));
    assert.equal(out.record_count, 6000);
    assert.equal(out.status, "complete", out.status_basis);
    assert.ok(Date.now() - t0 < 80_000, "6,000 values in well under the manifest's time");
    const entries = Array.from({ length: 6000 }, (_, i) => ({ path: `C:\\Apps\\App${i}\\run.exe`, ft: FT + BigInt(i) }));
    const env2 = await v.write(cwd, "work/SYSTEM", system({ shim: win10(entries) }));
    const out2 = body<Answer>(await tool(TOOL, cwd, { hive: "work/SYSTEM", limit: 10 }, env2));
    assert.equal(out2.record_count, 6000);
    assert.equal(out2.status, "complete", out2.status_basis);
  });
});

dual("a ShimCache value over the size this tool writes out as hexadecimal is counted and the answer is partial", async (v) => {
  await withCwd(async (cwd) => {
    const env = await v.write(cwd, "work/SYSTEM", system({ shim: Buffer.concat([u32le(0x12345678), Buffer.alloc((1 << 19) + 10, 1)]) }));
    const out = body<Answer>(await tool(TOOL, cwd, { hive: "work/SYSTEM" }, env));
    assert.equal(out.status, "partial");
    assert.match(out.status_basis, /raw_not_shown/);
    assert.equal(out.records[0].raw_hex, undefined);
    assert.equal(out.records[0].raw_length, String((1 << 19) + 14));
  });
});

test("the tool is registered: manifest names, input magic and the secret_output declaration", async () => {
  const manifest = JSON.parse(await readFile(join(WIN, TOOL, "manifest.json"), "utf8"));
  assert.deepEqual(manifest.use.names, ["NTUSER.DAT", "SYSTEM"]);
  assert.deepEqual(manifest.secret_output, { when_args: ["write_values"] });
  assert.equal(manifest.version, 11);
  assert.deepEqual(manifest.requires, [], "no second reader is started, so nothing is required");
  assert.ok(manifest.timeout_seconds > 84);
  assert.match(manifest.description, /cross_check|second reader/);
});

// --- the clock and the signals -----------------------------------------------------------------

import { runPy } from "./tool-library-harness.ts";

dual("at its own time limit the tool answers partial and says how many it did not read, for every source", async (v) => {
  await withCwd(async (cwd) => {
    const env = await v.write(cwd, "work/NTUSER.DAT", ntuser(Array.from({ length: 20 }, (_, i) => ({ name: rot13(`C:\a${i}.exe`), type: "binary" as const, value: ua72(i, i, i, i, FT) }))));
    const env2 = await v.write(cwd, "work/SYSTEM", system({ bam: [{ sid: SIDA, values: [{ name: "\Device\HarddiskVolume3\a.exe", type: "binary", value: bam24(FT) }] }], shim: win10([{ path: PATHS[0], ft: FT }, { path: PATHS[1], ft: FT }]) }));
    const src = (await readFile(join(WIN, TOOL, "run.py"), "utf8")).replace(/DEADLINE_SECONDS = \d+ /, "DEADLINE_SECONDS = 0 ");
    assert.ok(src.includes("DEADLINE_SECONDS = 0 "));
    await mkdir(join(cwd, "copy", TOOL), { recursive: true });
    await writeFile(join(cwd, "copy", TOOL, "run.py"), src);
    for (const [hive, source, e] of [["work/NTUSER.DAT", "userassist", env], ["work/SYSTEM", "bam", env2], ["work/SYSTEM", "shimcache", env2]] as Array<[string, string, Record<string, string>]>) {
      const r = await runPy(join(cwd, "copy", TOOL, "run.py"), cwd, { hive, source }, undefined, { AGENT_ID: "s1", ...e });
      assert.equal(r.code, 0, r.stdout + r.stderr);
      const out = JSON.parse(r.stdout) as Answer;
      assert.equal(out.status, "partial", source);
      assert.equal(out.walk_stopped_by_time_limit, true, source);
      assert.match(out.status_basis, /time limit \(0 seconds\)/, source);
      assert.match(out.status_basis, /were not read/, source);
    }
  });
});

for (const [signal, code] of [["SIGTERM", 143], ["SIGINT", 130], ["SIGHUP", 129]] as Array<[NodeJS.Signals, number]>) {
  for (const variant of VARIANTS) {
    test(`stopped by ${signal} the tool answers JSON, exits ${code} and leaves no temporary file [${variant.label}]`, { skip: variant.skip }, async () => {
      await withCwd(async (cwd) => {
        const many = Array.from({ length: 12_000 }, (_, i) => ({ name: rot13(`C:\Apps\App${i}\run.exe`), type: "binary" as const, value: ua72(i, i, i, i, FT) }));
        const env = await variant.write(cwd, "work/NTUSER.DAT", ntuser(many));
        const child = spawn("python3", [join(WIN, TOOL, "run.py")], { cwd, env: { ...process.env, AGENT_ID: "s1", ...env } });
        let stdout = "";
        child.stdout.on("data", (c: Buffer) => (stdout += c.toString()));
        const closed = new Promise<number | null>((resolve) => child.on("close", (c) => resolve(c)));
        child.stdin.end(JSON.stringify({ hive: "work/NTUSER.DAT", limit: 1 }));
        const dir = join(cwd, "work", "s1", "tool-output");
        let seen = false;
        for (let waited = 0; waited < 40_000 && !seen; waited += 25) {
          seen = (await readdir(dir).catch(() => [] as string[])).some((n) => n.startsWith(".userassist_bam_shimcache"));
          if (!seen) await new Promise((r) => setTimeout(r, 25));
        }
        assert.ok(seen, "the tool never opened a temporary file");
        child.kill("SIGSTOP");
        child.kill(signal);
        child.kill("SIGCONT");
        assert.equal(await closed, code);
        const out = JSON.parse(stdout) as Answer;
        assert.deepEqual([out.status, out.interrupted], ["failed", true]);
        assert.equal(out.signal, code - 128);
        assert.deepEqual((await readdir(dir)).filter((n) => n.startsWith(".")), [], "a temporary file was left");
      });
    });
  }
}

dual("a time limit that falls inside one key's values stops the value loop and counts what was not read", async (v) => {
  await withCwd(async (cwd) => {
    const env = await v.write(cwd, "work/NTUSER.DAT", ntuser(Array.from({ length: 30_000 }, (_, i) => ({ name: rot13(`C:\Apps\App${i}\run.exe`), type: "binary" as const, value: ua72(i, i, i, i, FT) }))));
    const src = (await readFile(join(WIN, TOOL, "run.py"), "utf8")).replace(/DEADLINE_SECONDS = \d+ /, "DEADLINE_SECONDS = 1 ");
    await mkdir(join(cwd, "copy", TOOL), { recursive: true });
    await writeFile(join(cwd, "copy", TOOL, "run.py"), src);
    const r = await runPy(join(cwd, "copy", TOOL, "run.py"), cwd, { hive: "work/NTUSER.DAT", limit: 5 }, undefined, { AGENT_ID: "s1", ...env });
    assert.equal(r.code, 0, r.stdout + r.stderr);
    const out = JSON.parse(r.stdout) as Answer;
    assert.equal(out.status, "partial");
    assert.equal(out.walk_stopped_by_time_limit, true);
    assert.ok(out.record_count < 30_000, "the loop stopped");
    assert.match(out.status_basis, /time limit \(1 seconds\)/);
  });
});

// --- fix round 1 -------------------------------------------------------------------------------------

async function runCopy(cwd: string, edit: (s: string) => string, args: Record<string, unknown>, env: Record<string, string>): Promise<Answer> {
  const src = edit(await readFile(join(WIN, TOOL, "run.py"), "utf8"));
  await mkdir(join(cwd, "copy", TOOL), { recursive: true });
  await writeFile(join(cwd, "copy", TOOL, "run.py"), src);
  const r = await runPy(join(cwd, "copy", TOOL, "run.py"), cwd, args, undefined, { AGENT_ID: "s1", ...env });
  assert.equal(r.code, 0, r.stdout + r.stderr);
  return JSON.parse(r.stdout) as Answer;
}
const patch = (s: string, from: string, to: string): string => {
  const t = s.replace(from, to);
  assert.notEqual(t, s, `the patch did not apply: ${from}`);
  return t;
};
/** The tool's clock runs out at its k-th look at it. */
const clockAfter = (k: number) => (s: string): string =>
  patch(patch(s, "\nimport random\n", `\nimport random\n_TICKS = [0]\n\n\ndef _ticks():\n    _TICKS[0] += 1\n    return _TICKS[0] > ${k}\n`), "if stopped[0] is None and out_of_time():", "if stopped[0] is None and _ticks():");
const valuesNotRead = (out: Answer): number => Number(/at least (\d+) value\(s\) and (\d+) ShimCache entr\(ies\) were not read/.exec(out.status_basis)?.[1]);

dual("at its time limit in a UserAssist key the count of values not read is the values left in that key, and the values read are the records", async (v) => {
  await withCwd(async (cwd) => {
    const env = await v.write(cwd, "work/NTUSER.DAT", ntuser(Array.from({ length: 5000 }, (_, i) => ({ name: rot13(`C:\\Apps\\App${i}\\run.exe`), type: "binary" as const, value: ua72(i, i, i, i, FT) }))));
    const out = await runCopy(cwd, clockAfter(1500), { hive: "work/NTUSER.DAT", limit: 6000 }, env);
    assert.equal(out.status, "partial");
    assert.equal(out.walk_stopped_by_time_limit, true);
    assert.ok(out.record_count > 100 && out.record_count < 5000, `${out.record_count} records`);
    assert.equal(out.record_count + valuesNotRead(out), 5000, out.status_basis);
  });
});

dual("at its time limit in a BAM key the count is the values left in that key, and the SID keys not started are named apart", async (v) => {
  await withCwd(async (cwd) => {
    const many = (tag: string, count: number): Val[] => Array.from({ length: count }, (_, i) => ({ name: `\\Device\\HarddiskVolume3\\${tag}\\a${i}.exe`, type: "binary" as const, value: bam24(FT) }));
    const env = await v.write(cwd, "work/SYSTEM", system({ bam: [{ sid: SIDA, values: many("a", 3000) }, { sid: SIDB, values: many("b", 100) }] }));
    const out = await runCopy(cwd, clockAfter(1000), { hive: "work/SYSTEM", source: "bam", limit: 6000 }, env);
    assert.equal(out.status, "partial");
    const read = out.record_count;
    assert.ok(read > 100 && read < 3000, `${read} records`);
    // the order of the two SID keys is the print order, so the key in hand holds 3,000 or 100 values: the count is true for either
    const left = valuesNotRead(out);
    assert.ok(read + left === 3000 || read + left === 100, `${read} read, ${left} not read`);
    assert.match(out.status_basis, /1 key\(s\) were not started and what they hold is not counted/);
  });
});

dual("a list of values too long to put in print order in the time left is read in a random order and the answer says so", async (v) => {
  await withCwd(async (cwd) => {
    const env = await v.write(cwd, "work/NTUSER.DAT", ntuser(Array.from({ length: 50 }, (_, i) => ({ name: rot13(`C:\\a${i}.exe`), type: "binary" as const, value: ua72(i, i, i, i, FT) }))));
    const out = await runCopy(cwd, (s) => patch(s, "ORDER_CAP = 100000 ", "ORDER_CAP = 10 "), { hive: "work/NTUSER.DAT", limit: 100 }, env);
    assert.equal(out.record_count, 50);
    assert.match(out.status_basis, /list\(s\) \(\d+ item\(s\) in all\) were too long to put in print order/);
    const normal = await runCopy(cwd, (s) => s, { hive: "work/NTUSER.DAT", limit: 100 }, env);
    assert.equal(normal.status, "complete", normal.status_basis);
  });
});

dual("a key of 1,000,000-scale values is not put in order past the clock: the tool answers JSON with its own scaled clock (ORDER_COST makes the list unordered)", async (v) => {
  await withCwd(async (cwd) => {
    const env = await v.write(cwd, "work/NTUSER.DAT", ntuser(Array.from({ length: 4000 }, (_, i) => ({ name: rot13(`C:\\a${i}.exe`), type: "binary" as const, value: ua72(i, i, i, i, FT) }))));
    // a 5-second clock and an item cost of 0.01 s: the 4,000-item list does not fit half the time left, so it is not ordered
    const out = await runCopy(cwd, (s) => patch(patch(s, "ORDER_COST = 0.0003 ", "ORDER_COST = 0.01 "), /DEADLINE_SECONDS = \d+ /.exec(s)![0], "DEADLINE_SECONDS = 5 "), { hive: "work/NTUSER.DAT", limit: 10 }, env);
    assert.match(out.status_basis, /too long to put in print order/);
    assert.ok(out.record_count > 0);
  });
});

dual("the length guards: UserAssist is read at 72 and 16 bytes only, BAM at 24 only; one byte more or less is unsupported with its bytes", async (v) => {
  const { out } = await run(v, ntuser([
    { name: rot13("C:\\ok72.exe"), type: "binary", value: ua72(1, 1, 1, 1, FT) }, { name: rot13("C:\\ok16.exe"), type: "binary", value: ua16(1, 1, FT) },
    { name: rot13("C:\\l73.exe"), type: "binary", value: Buffer.concat([ua72(1, 1, 1, 1, FT), Buffer.from([0])]) }, { name: rot13("C:\\l71.exe"), type: "binary", value: ua72(1, 1, 1, 1, FT).subarray(0, 71) },
    { name: rot13("C:\\l17.exe"), type: "binary", value: Buffer.concat([ua16(1, 1, FT), Buffer.from([0])]) }, { name: rot13("C:\\l15.exe"), type: "binary", value: ua16(1, 1, FT).subarray(0, 15) },
  ]));
  assert.equal(out.unsupported_count, 4);
  const layouts = Object.fromEntries(out.records.map((r) => [r.name_decoded, r.layout]));
  assert.deepEqual(layouts, { "C:\\ok72.exe": "userassist-72", "C:\\ok16.exe": "userassist-16", "C:\\l73.exe": "unknown", "C:\\l71.exe": "unknown", "C:\\l17.exe": "unknown", "C:\\l15.exe": "unknown" });
  const bam = (await run(v, system({ bam: [{ sid: SIDA, values: [
    { name: "\\Device\\HarddiskVolume3\\ok.exe", type: "binary", value: bam24(FT) }, { name: "\\Device\\HarddiskVolume3\\l25.exe", type: "binary", value: Buffer.concat([bam24(FT), Buffer.from([0])]) },
    { name: "\\Device\\HarddiskVolume3\\l23.exe", type: "binary", value: bam24(FT).subarray(0, 23) },
  ] }] }))).out;
  assert.equal(bam.unsupported_count, 2);
  assert.equal(bam.records.filter((r) => r.layout === "bam-24").length, 1);
});

dual("a sid filter that does not match a record whose SID key name is withheld counts it as blind, and the withheld name is not printed", async (v) => {
  const [canary] = plant(FILE_SHAPES[0], 1, 13);
  const root = system({ bam: [{ sid: SIDA, values: [{ name: "\\Device\\HarddiskVolume3\\a.exe", type: "binary", value: bam24(FT) }] }, { sid: canary.text, values: [{ name: "\\Device\\HarddiskVolume3\\b.exe", type: "binary", value: bam24(FT) }] }] });
  const { out, raw } = await run(v, root, { sid: SIDA });
  assert.equal(out.record_count, 1);
  assert.equal(out.contains_blind_records, 1);
  assert.equal(leaked([canary], [raw]), 0);
});
