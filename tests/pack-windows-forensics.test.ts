/**
 * The windows-forensics pack's tools, against fixtures the test builds from the
 * formats' own layouts and never from a tool's output.
 *
 * Where each layout comes from:
 *   lnk_parse    MS-SHLLINK (the shell link header, LinkInfo, VolumeID,
 *                CommonNetworkRelativeLink), every offset from the start of its
 *                own structure.
 *   jumplist     the DestList stream as libyal's jump list format notes lay it out:
 *                a 32-byte header; an entry's fixed part of 114 bytes (version 1)
 *                or 130 bytes (versions 3 and 4) with the path length in
 *                characters at 0x70 or 0x80 and the path after it; a 4-byte
 *                trailer after the path in versions 3 and 4.
 *   registry     the regf layout (a 4096-byte base block, hbins of cells: nk, li,
 *                vk, value lists, data), written by `hive()` below.
 *   programs     a stub on PATH stands in for each program a tool calls
 *                (esedbexport, vshadowinfo, yara, zircolite, hayabusa, icat), written
 *                to behave as that program's documented output does.
 *
 * To see that a test fails on the code it was written against, point
 * WINDOWS_PACK_TOOLS at a copy of the pack's tools as they were before the fix:
 *
 *   git archive origin/claude/pack-standard-and-links packs/windows-forensics/tools | tar -x -C /tmp/old
 *   WINDOWS_PACK_TOOLS=/tmp/old/packs/windows-forensics/tools \
 *     node --experimental-strip-types --test tests/pack-windows-forensics.test.ts
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmod, mkdir, readFile, readdir, stat, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { ROOT, withCwd } from "./tool-library-harness.ts";
import {
  AGENT, DISSECT, REGIPY, WIN, asciiz, body, everyFileUnder, exists, failed, py, pythonCanImport, stub, stubModule, tool, u16, u16z,
  type Run,
} from "./windows-pack-harness.ts";
import { hive } from "./windows-hive.ts";

// --- lnk_parse ------------------------------------------------------------------

const SHELL_LINK_CLSID = Buffer.from("0114020000000000c000000000000046", "hex");
const FILETIME_BASE = 133_443_104_000_000_000n + 1_234_567n; // 2023-11-13T00:53:20.1234567Z

/** The 76-byte ShellLinkHeader: HeaderSize, LinkCLSID, LinkFlags, FileAttributes, three FILETIMEs, FileSize, IconIndex, ShowCommand, HotKey, three reserved fields. */
function lnkHeader(flags: number, times: [bigint, bigint, bigint] = [FILETIME_BASE, FILETIME_BASE + 10_000_000n, FILETIME_BASE + 20_000_000n]): Buffer {
  const h = Buffer.alloc(0x4c);
  h.writeUInt32LE(0x4c, 0);
  SHELL_LINK_CLSID.copy(h, 4);
  h.writeUInt32LE(flags, 0x14);
  h.writeUInt32LE(0x20, 0x18);
  h.writeBigUInt64LE(times[0], 0x1c);
  h.writeBigUInt64LE(times[1], 0x24);
  h.writeBigUInt64LE(times[2], 0x2c);
  h.writeUInt32LE(4321, 0x34);
  h.writeUInt32LE(1, 0x3c);
  return h;
}

/** VolumeID: VolumeIDSize, DriveType, DriveSerialNumber, VolumeLabelOffset (0x10), then the ANSI label. */
function volumeId(driveType: number, serial: number, label: string): Buffer {
  const text = asciiz(label);
  const v = Buffer.alloc(0x10 + text.length);
  v.writeUInt32LE(v.length, 0);
  v.writeUInt32LE(driveType, 4);
  v.writeUInt32LE(serial, 8);
  v.writeUInt32LE(0x10, 12);
  text.copy(v, 0x10);
  return v;
}

/** CommonNetworkRelativeLink with the 0x14-byte fixed part: ValidDevice and ValidNetType, the net name, the device name. */
function networkLink(netName: string, deviceName: string, provider: number): Buffer {
  const net = asciiz(netName);
  const dev = asciiz(deviceName);
  const n = Buffer.alloc(0x14 + net.length + dev.length);
  n.writeUInt32LE(n.length, 0);
  n.writeUInt32LE(3, 4);
  n.writeUInt32LE(0x14, 8);
  n.writeUInt32LE(0x14 + net.length, 12);
  n.writeUInt32LE(provider, 16);
  net.copy(n, 0x14);
  dev.copy(n, 0x14 + net.length);
  return n;
}

/**
 * LinkInfo with a 0x1C-byte header (ANSI offsets only) or a 0x24-byte one (the two
 * Unicode offsets after them). Layout: LinkInfoSize, LinkInfoHeaderSize, LinkInfoFlags,
 * VolumeIDOffset, LocalBasePathOffset, CommonNetworkRelativeLinkOffset,
 * CommonPathSuffixOffset, [LocalBasePathOffsetUnicode, CommonPathSuffixOffsetUnicode].
 */
function linkInfo(o: { volume?: Buffer; localAnsi?: string; localUnicode?: string; network?: Buffer; suffixAnsi?: string; suffixUnicode?: string }): Buffer {
  const unicode = o.localUnicode !== undefined || o.suffixUnicode !== undefined;
  const headerSize = unicode ? 0x24 : 0x1c;
  const parts: Buffer[] = [];
  let at = headerSize;
  const place = (b: Buffer | undefined): number => {
    if (!b) return 0;
    const where = at;
    parts.push(b);
    at += b.length;
    return where;
  };
  const volumeOffset = place(o.volume);
  const localOffset = place(o.localAnsi === undefined ? undefined : asciiz(o.localAnsi));
  const networkOffset = place(o.network);
  const suffixOffset = place(asciiz(o.suffixAnsi ?? ""));
  const localUnicodeOffset = place(o.localUnicode === undefined ? undefined : u16z(o.localUnicode));
  const suffixUnicodeOffset = place(o.suffixUnicode === undefined ? undefined : u16z(o.suffixUnicode));
  const h = Buffer.alloc(headerSize);
  h.writeUInt32LE(at, 0);
  h.writeUInt32LE(headerSize, 4);
  h.writeUInt32LE((o.volume ? 1 : 0) | (o.network ? 2 : 0), 8);
  h.writeUInt32LE(volumeOffset, 12);
  h.writeUInt32LE(localOffset, 16);
  h.writeUInt32LE(networkOffset, 20);
  h.writeUInt32LE(suffixOffset, 24);
  if (unicode) {
    h.writeUInt32LE(localUnicodeOffset, 28);
    h.writeUInt32LE(suffixUnicodeOffset, 32);
  }
  return Buffer.concat([h, ...parts]);
}

type LnkOut = {
  ok: boolean;
  created: string | null;
  created_filetime: string;
  accessed: string | null;
  written: string | null;
  linkinfo_size?: number;
  linkinfo_header_size?: number;
  volume?: { drive_type: number; drive_type_name: string; serial_number: string; label: string };
  local_base_path?: string;
  local_base_path_ansi?: string | null;
  local_base_path_unicode?: string;
  common_path?: string;
  common_path_suffix_ansi?: string | null;
  network?: { net_name: string; device_name: string; provider_type: string; provider_name?: string };
  linkinfo_target?: string;
  linkinfo_target_kind?: string;
  problems: string[];
  structure_complete: boolean;
};

const TERMINAL = Buffer.alloc(4);

test("lnk_parse reads LinkInfo by the MS-SHLLINK layout: the local path, the volume serial, drive type and label", async () => {
  // The fields were unpacked in the wrong order (LinkInfoFlags taken for the volume
  // offset, the VolumeID offset for the local path's), so the local path came out as
  // one stray byte from inside the VolumeID, and no serial was read at all.
  await withCwd(async (cwd) => {
    const lnk = Buffer.concat([
      lnkHeader(0x02),
      linkInfo({ volume: volumeId(3, 0x1a2b3c4d, "SYSTEM"), localAnsi: "C:\\case\\report.txt" }),
      TERMINAL,
    ]);
    await writeFile(join(cwd, "work", "local.lnk"), lnk);
    const out = body<LnkOut>(await tool("lnk_parse", cwd, { path: "work/local.lnk", size: 4096 }));
    assert.equal(out.ok, true);
    assert.equal(out.local_base_path, "C:\\case\\report.txt");
    assert.equal(out.linkinfo_target, "C:\\case\\report.txt");
    assert.equal(out.linkinfo_target_kind, "local");
    assert.equal(out.volume?.serial_number, "1A2B3C4D");
    assert.equal(out.volume?.drive_type, 3);
    assert.equal(out.volume?.drive_type_name, "fixed");
    assert.equal(out.volume?.label, "SYSTEM");
    assert.equal(out.structure_complete, true);
    assert.deepEqual(out.problems, []);
  });
});

test("lnk_parse reads the Unicode path and suffix at their own offsets when the header is 0x24 bytes", async () => {
  // The ANSI path was decoded as UTF-16 and the Unicode offsets were never read.
  await withCwd(async (cwd) => {
    const lnk = Buffer.concat([
      lnkHeader(0x02),
      linkInfo({
        volume: volumeId(2, 0xdeadbeef, "USBSTICK"),
        localAnsi: "C:\\case\\rapor",
        localUnicode: "C:\\case\\rapör",
        suffixAnsi: "notlar.txt",
        suffixUnicode: "notlär.txt",
      }),
      TERMINAL,
    ]);
    await writeFile(join(cwd, "work", "unicode.lnk"), lnk);
    const out = body<LnkOut>(await tool("lnk_parse", cwd, { path: "work/unicode.lnk" }));
    assert.equal(out.linkinfo_header_size, 0x24);
    assert.equal(out.local_base_path_ansi, "C:\\case\\rapor");
    assert.equal(out.local_base_path_unicode, "C:\\case\\rapör");
    assert.equal(out.local_base_path, "C:\\case\\rapör", "the Unicode form is preferred where the file has one");
    assert.equal(out.common_path, "notlär.txt");
    assert.equal(out.linkinfo_target, "C:\\case\\rapör" + "notlär.txt");
    assert.equal(out.volume?.drive_type_name, "removable");
    assert.equal(out.volume?.serial_number, "DEADBEEF");
  });
});

test("lnk_parse reads a CommonNetworkRelativeLink: the share, the device and the provider, and joins the suffix", async () => {
  await withCwd(async (cwd) => {
    const lnk = Buffer.concat([
      lnkHeader(0x02),
      linkInfo({ network: networkLink("\\\\fileserver\\finance", "Z:", 0x00020000), suffixAnsi: "Q4.xlsx" }),
      TERMINAL,
    ]);
    await writeFile(join(cwd, "work", "unc.lnk"), lnk);
    const out = body<LnkOut>(await tool("lnk_parse", cwd, { path: "work/unc.lnk" }));
    assert.equal(out.network?.net_name, "\\\\fileserver\\finance");
    assert.equal(out.network?.device_name, "Z:");
    assert.equal(out.network?.provider_type, "0x00020000");
    assert.equal(out.linkinfo_target, "\\\\fileserver\\finance\\Q4.xlsx");
    assert.equal(out.linkinfo_target_kind, "network");
    assert.equal(out.volume, undefined, "a network link has no VolumeID, and none is invented");
  });
});

test("lnk_parse keeps the raw FILETIMEs beside the dates, with every fractional digit, by integer arithmetic", async () => {
  // 133443104001234567 ticks is 2023-11-13T00:53:20.1234567Z; a float division by ten
  // lost the last digits, and the raw value was not returned at all.
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "t.lnk"), Buffer.concat([lnkHeader(0x00), TERMINAL]));
    const out = body<LnkOut>(await tool("lnk_parse", cwd, { path: "work/t.lnk" }));
    assert.equal(out.created_filetime, String(FILETIME_BASE));
    assert.equal(out.created, "2023-11-13T00:53:20.1234567Z");
    assert.equal(out.accessed, "2023-11-13T00:53:21.1234567Z");
    assert.equal(out.written, "2023-11-13T00:53:22.1234567Z");
  });
});

test("lnk_parse says a read that ends inside LinkInfo ends there, and does not read the strings after it from the wrong place", async () => {
  await withCwd(async (cwd) => {
    const lnk = Buffer.concat([
      lnkHeader(0x02 | 0x04 | 0x80),
      linkInfo({ volume: volumeId(3, 1, "X"), localAnsi: "C:\\a\\b.txt" }),
      Buffer.from([4, 0]),
      u16("name"),
      TERMINAL,
    ]);
    await writeFile(join(cwd, "work", "cut.lnk"), lnk);
    const out = body<LnkOut>(await tool("lnk_parse", cwd, { path: "work/cut.lnk", size: 0x4c + 20 }));
    assert.equal(out.structure_complete, false);
    assert.ok(out.problems.some((p) => /LinkInfo declares \d+ bytes and 20 were read/.test(p)), out.problems.join(" | "));
    assert.equal(out.local_base_path, undefined);
    // Read whole, the same file is complete and its string data is in place.
    const whole = body<LnkOut & { name: string }>(await tool("lnk_parse", cwd, { path: "work/cut.lnk" }));
    assert.equal(whole.structure_complete, true);
    assert.equal(whole.name, "name");
  });
});

test("lnk_parse refuses an arguments error and a file that is no link, with an error and a non-zero exit", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "no.lnk"), Buffer.alloc(200, 7));
    const notLink = failed(await tool("lnk_parse", cwd, { path: "work/no.lnk" }));
    assert.match(notLink.error, /not a LNK header/);
    assert.match(failed(await tool("lnk_parse", cwd, { path: "work/no.lnk", offset: -4 })).error, /offset must be a whole number/);
    assert.match(failed(await tool("lnk_parse", cwd, { path: "work/no.lnk", size: "big" })).error, /size must be a whole number/);
  });
});

// --- jumplist -------------------------------------------------------------------

const LNK_MAGIC = Buffer.from("4c0000000114020000000000c000000000000046", "hex");

// olefile reads a compound file; this stub reads a JSON map of stream names to hex,
// which is all jumplist asks of it.
const OLEFILE_STUB = String.raw`
import json


def isOleFile(path):
    return True


class _Stream:
    def __init__(self, data):
        self._data = data

    def read(self):
        return self._data


class OleFileIO:
    def __init__(self, path):
        with open(path, encoding="utf-8") as fh:
            self._streams = json.load(fh)

    def listdir(self):
        return [[name] for name in self._streams]

    def get_size(self, name):
        return len(bytes.fromhex(self._streams[name]))

    def openstream(self, name):
        return _Stream(bytes.fromhex(self._streams[name]))

    def close(self):
        pass
`;

type DestEntry = { number: number; host: string; filetime: bigint; pin: number; path: string };

/** A DestList stream: a 32-byte header, then entries by their version's layout (114-byte fixed part in version 1; 130 bytes and a 4-byte trailer in 3 and 4). */
function destList(version: number, entries: DestEntry[]): Buffer {
  const header = Buffer.alloc(32);
  header.writeUInt32LE(version, 0);
  header.writeUInt32LE(entries.length, 4);
  header.writeUInt32LE(entries.filter((e) => e.pin !== -1).length, 8);
  const fixed = version === 1 ? 114 : 130;
  const charsAt = version === 1 ? 0x70 : 0x80;
  const trailer = version === 1 ? 0 : 4;
  const rows = entries.map((e) => {
    const b = Buffer.alloc(fixed + e.path.length * 2 + trailer);
    b.write(e.host, 0x48, "latin1");
    b.writeUInt32LE(e.number, 0x58);
    b.writeUInt32LE(0x11223344, 0x5c);
    b.writeUInt32LE(0x55667788, 0x60);
    b.writeBigUInt64LE(e.filetime, 0x64);
    b.writeInt32LE(e.pin, 0x6c);
    if (version !== 1) for (let i = 0; i < 4; i++) b.writeUInt32LE(0xa1 + i, 0x70 + i * 4);
    b.writeUInt16LE(e.path.length, charsAt);
    b.write(e.path, fixed, "utf16le");
    return b;
  });
  return Buffer.concat([header, ...rows]);
}

type JumpEntry = {
  entry_number: number;
  stream: string;
  path: string;
  hostname: string;
  last_access: string | null;
  last_access_filetime: string;
  pin_status: number;
  pinned: boolean;
  access_count?: unknown;
};
type Jump = {
  status: string;
  files: Array<{
    file: string;
    format?: string;
    destlist_version?: number;
    entries: JumpEntry[];
    entry_count: number;
    problems?: string[];
    links: Array<{ stream?: string; is_link: boolean; path?: string; last_access?: string | null; carved?: boolean }>;
    method?: string;
    error?: string;
  }>;
  file_count: number;
  files_failed: number;
};

for (const version of [1, 3, 4]) {
  test(`jumplist reads a version ${version} DestList by its own layout: the path, the host, the last access and the pin state of every entry`, async () => {
    // One 118-byte layout with the path length at 0x74 was used for every version, so a version 3 or 4
    // list came back with three-NUL paths, a pin state of "pinned" for an unpinned entry, and no problem.
    await withCwd(async (cwd) => {
      const env = await stubModule(cwd, { "olefile.py": OLEFILE_STUB });
      const entries: DestEntry[] = [
        { number: 1, host: "WIN-DC01", filetime: 133_443_104_001_234_567n, pin: -1, path: "\\\\fileserver\\finance\\Q4.xlsx" },
        { number: 10, host: "WIN-DC01", filetime: 133_443_104_101_234_567n, pin: 3, path: "C:\\case\\report.txt" },
      ];
      const streams: Record<string, string> = { DestList: destList(version, entries).toString("hex") };
      streams["1"] = Buffer.concat([LNK_MAGIC, Buffer.from("one")]).toString("hex");
      streams["a"] = Buffer.concat([LNK_MAGIC, Buffer.from("ten")]).toString("hex");
      streams["b"] = Buffer.concat([LNK_MAGIC.subarray(0, 4), Buffer.alloc(30, 0x41)]).toString("hex");
      await writeFile(join(cwd, "work", "1b4dd67f29cb1962.automaticDestinations-ms"), JSON.stringify(streams), "utf8");
      const out = body<Jump>(await tool("jumplist", cwd, { path: "work/1b4dd67f29cb1962.automaticDestinations-ms" }, env));
      const file = out.files[0];
      assert.equal(out.status, "complete");
      assert.equal(file.destlist_version, version);
      assert.deepEqual(file.problems ?? [], []);
      assert.equal(file.entry_count, 2);
      const [first, second] = file.entries;
      assert.equal(first.path, "\\\\fileserver\\finance\\Q4.xlsx");
      assert.equal(first.hostname, "WIN-DC01");
      assert.equal(first.entry_number, 1);
      assert.equal(first.stream, "1");
      assert.equal(first.last_access, "2023-11-13T00:53:20.1234567Z");
      assert.equal(first.last_access_filetime, "133443104001234567");
      assert.equal(first.pinned, false);
      assert.equal(first.pin_status, -1);
      assert.equal(second.path, "C:\\case\\report.txt");
      assert.equal(second.stream, "a");
      assert.equal(second.pinned, true);
      assert.equal(second.pin_status, 3);
      assert.equal(second.last_access_filetime, "133443104101234567");
      assert.equal(second.last_access, "2023-11-13T00:53:30.1234567Z");
      assert.equal(first.access_count, undefined, "no access count is claimed");
      // The links carry the DestList's path by their stream name, and only a whole link header counts as a link.
      const byStream = Object.fromEntries(file.links.map((l) => [l.stream, l]));
      assert.equal(byStream["1"].path, "\\\\fileserver\\finance\\Q4.xlsx");
      assert.equal(byStream["a"].path, "C:\\case\\report.txt");
      assert.equal(byStream["b"].is_link, false, "four bytes of the header are not a link");
    });
  });
}

test("jumplist refuses a DestList version it does not read, with a problem and no entries, and the status says partial", async () => {
  await withCwd(async (cwd) => {
    const env = await stubModule(cwd, { "olefile.py": OLEFILE_STUB });
    const odd = destList(3, [{ number: 1, host: "H", filetime: 133_443_104_000_000_000n, pin: -1, path: "C:\\a.txt" }]);
    odd.writeUInt32LE(2, 0);
    await writeFile(join(cwd, "work", "a.automaticDestinations-ms"), JSON.stringify({ DestList: odd.toString("hex") }), "utf8");
    const out = body<Jump>(await tool("jumplist", cwd, { path: "work/a.automaticDestinations-ms" }, env));
    assert.equal(out.status, "partial");
    assert.equal(out.files[0].entry_count, 0);
    assert.ok((out.files[0].problems ?? []).some((p) => /version 2 is not one this parser reads/.test(p)));
  });
});

test("jumplist reports a file it could not read as a failure with a count, and exits non-zero when none could be read", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "x.automaticDestinations-ms"), "not a compound file");
    // An olefile that says this is not a compound file: every automaticDestinations file fails, loudly.
    const env = await stubModule(cwd, { "olefile.py": "def isOleFile(p):\n    return False\n" });
    const out = await tool("jumplist", cwd, { path: "work/x.automaticDestinations-ms" }, env);
    assert.notEqual(out.code, 0);
    const parsed = JSON.parse(out.stdout) as Jump;
    assert.equal(parsed.status, "failed");
    assert.equal(parsed.files_failed, 1);
  });
});

test("jumplist calls a customDestinations-ms split a carve, and marks each link carved", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "x.customDestinations-ms"), Buffer.concat([Buffer.from([2, 0, 0, 0]), LNK_MAGIC, Buffer.from("A".repeat(40)), LNK_MAGIC, Buffer.from("B".repeat(30))]));
    const out = body<Jump>(await tool("jumplist", cwd, { path: "work/x.customDestinations-ms" }));
    assert.match(out.files[0].method ?? "", /carved/);
    assert.ok(out.files[0].links.every((l) => l.carved === true));
    assert.equal(out.files[0].links.length, 2);
  });
});

// --- registry hives -------------------------------------------------------------

test("the hive fixture is a hive regipy opens, with the keys and typed values written into it", { skip: REGIPY }, async () => {
  await withCwd(async (cwd) => {
    const bytes = hive({
      name: "ROOT",
      children: [
        { name: "A", values: [{ name: "s", type: "sz", value: "hello" }, { name: "d", type: "dword", value: 1700000000 }] },
        { name: "B", children: [{ name: "C", values: [{ name: "m", type: "multi_sz", value: ["x", "yz"] }, { name: "bin", type: "binary", value: Buffer.from([1, 2, 3, 4, 5, 6]) }] }] },
      ],
    });
    await writeFile(join(cwd, "work", "T.hve"), bytes);
    const out = py(
      [
        "import json, sys",
        "from regipy.registry import RegistryHive",
        "h = RegistryHive(sys.argv[1])",
        "a = h.get_key('\\\\A')",
        "c = h.get_key('\\\\B\\\\C')",
        "print(json.dumps({'a': [(v.name, v.value_type, str(v.value)) for v in a.iter_values()], 'c': [(v.name, v.value_type, str(v.value)) for v in c.iter_values()],",
        " 'subs': [k.name for k in h.root.iter_subkeys()] if hasattr(h, 'root') else []}))",
      ].join("\n"),
      join(cwd, "work", "T.hve"),
    );
    const got = JSON.parse(out) as { a: string[][]; c: string[][]; subs: string[] };
    assert.deepEqual(got.a.map((r) => r.slice(0, 2)), [["s", "REG_SZ"], ["d", "REG_DWORD"]]);
    assert.equal(got.a[0][2], "hello");
    assert.equal(got.a[1][2], "1700000000");
    assert.equal(got.c[0][1], "REG_MULTI_SZ");
    assert.equal(got.c[1][1], "REG_BINARY");
  });
});

// --- amcache_apps ---------------------------------------------------------------

// Its tests are in tests/pack-windows-forensics-registry.test.ts, each run against a stand-in for regipy and against the real library.

// --- browser_history ------------------------------------------------------------

type BrowserOut = {
  columns: string[];
  rows: Array<Record<string, unknown>>;
  row_count: number;
  results?: Array<{ rows: Array<Record<string, unknown>> }>;
  query_note?: string;
  sidecars_copied: string[];
  wal_present: boolean;
  wal_bytes: number;
  wal_checkpoint: { log_frames: number; checkpointed_frames: number };
  wal_frames_replayed: number;
  wal_replayed?: unknown;
  sensitive_columns_withheld: Array<{ table: string; column: string; cells_withheld: number; total_length: number }>;
  all_results?: string;
};

// Chromium's History: `urls` is one row per URL, `visits` one row per visit. 13344307200123456 is
// 1699833600.123456 s after the Unix epoch, the Chromium time base being microseconds since 1601.
const CHROME_HISTORY_FIXTURE = [
  "import sqlite3, sys",
  "c = sqlite3.connect(sys.argv[1])",
  "c.executescript('''",
  "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, typed_count INTEGER, last_visit_time INTEGER);",
  "CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER, from_visit INTEGER, transition INTEGER, visit_duration INTEGER);",
  "INSERT INTO urls VALUES (1, 'http://example.test/a', 'A', 2, 1, 13344307300123456);",
  "INSERT INTO visits VALUES (1, 1, 13344307200123456, 0, 805306369, 5000000);",
  "INSERT INTO visits VALUES (2, 1, 13344307300123456, 1, 0, 0);",
  "''')",
  "c.commit()",
].join("\n");

test("browser_history lists every visit with its raw time, transition and referring visit, and keeps the URL summary a summary", async () => {
  // The named queries read `urls` (one row per URL), so two visits to one URL came back as one row
  // under the name chrome_history; the visit table was never read.
  await withCwd(async (cwd) => {
    py(CHROME_HISTORY_FIXTURE, join(cwd, "work", "History"));
    const visits = body<BrowserOut>(await tool("browser_history", cwd, { path: "work/History", query: "chrome_visits" }));
    assert.equal(visits.row_count, 2);
    assert.deepEqual(visits.rows.map((r) => r.visit_id), [1, 2]);
    assert.deepEqual(visits.rows.map((r) => r.transition_core), ["typed", "link"]);
    assert.equal(visits.rows[0].transition_raw, 805306369, "the raw value, qualifiers included, beside the core type");
    assert.equal(visits.rows[0].visit_time_raw, 13344307200123456);
    assert.equal(visits.rows[0].visit_utc, "2023-11-13T00:00:00.123456Z", "microseconds kept");
    assert.equal(visits.rows[1].from_visit, 1);
    assert.equal(visits.rows[0].url, "http://example.test/a");

    const summary = body<BrowserOut>(await tool("browser_history", cwd, { path: "work/History", query: "chrome_url_summary" }));
    assert.equal(summary.row_count, 1);
    assert.equal(summary.rows[0].visit_count, 2);

    // The old name still answers, as the summary it always was, and says so.
    const old = body<BrowserOut>(await tool("browser_history", cwd, { path: "work/History", query: "chrome_history" }));
    assert.equal(old.row_count, 1);
    assert.match(old.query_note ?? "", /one row per URL/);
    assert.match(old.query_note ?? "", /chrome_visits/);
  });
});

test("browser_history reads Firefox's moz_historyvisits joined to moz_places, with the visit type named and the raw value kept", async () => {
  await withCwd(async (cwd) => {
    py(
      [
        "import sqlite3, sys",
        "c = sqlite3.connect(sys.argv[1])",
        "c.executescript('''",
        "CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, last_visit_date INTEGER);",
        "CREATE TABLE moz_historyvisits (id INTEGER PRIMARY KEY, from_visit INTEGER, place_id INTEGER, visit_date INTEGER, visit_type INTEGER);",
        "INSERT INTO moz_places VALUES (1, 'http://example.test/f', 'F', 2, 1699833700123456);",
        "INSERT INTO moz_historyvisits VALUES (1, 0, 1, 1699833600123456, 2);",
        "INSERT INTO moz_historyvisits VALUES (2, 1, 1, 1699833700123456, 5);",
        "''')",
        "c.commit()",
      ].join("\n"),
      join(cwd, "work", "places.sqlite"),
    );
    const visits = body<BrowserOut>(await tool("browser_history", cwd, { path: "work/places.sqlite", query: "firefox_visits" }));
    assert.equal(visits.row_count, 2);
    assert.deepEqual(visits.rows.map((r) => r.visit_type), ["typed", "redirect_permanent"]);
    assert.deepEqual(visits.rows.map((r) => r.visit_type_raw), [2, 5]);
    assert.equal(visits.rows[0].visit_utc, "2023-11-13T00:00:00.123456Z");
    const summary = body<BrowserOut>(await tool("browser_history", cwd, { path: "work/places.sqlite", query: "firefox_url_summary" }));
    assert.equal(summary.row_count, 1);
  });
});

const WAL_FIXTURE = [
  "import os, sqlite3, sys",
  "c = sqlite3.connect(sys.argv[1])",
  "c.execute('PRAGMA journal_mode=WAL')",
  "c.execute('PRAGMA wal_autocheckpoint=0')",
  "c.execute('CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INT, typed_count INT, last_visit_time INT)')",
  "c.execute(\"INSERT INTO urls VALUES (1, 'http://example.test/a', 'A', 1, 0, 13350000000000000)\")",
  "c.commit()",
  "c.execute(\"INSERT INTO urls VALUES (2, 'http://203.0.113.24/upload.aspx', 'shell', 9, 1, 13350000060000000)\")",
  "c.commit()",
  "os._exit(0)",
].join("\n");

test("browser_history says how many frames of the write-ahead log SQLite replayed, not just that a -wal file was copied", async () => {
  // `wal_replayed` was true whenever a -wal sidecar existed, and said nothing of whether SQLite found a
  // valid log in it.
  await withCwd(async (cwd) => {
    py(WAL_FIXTURE, join(cwd, "work", "History"));
    const wal = await readFile(join(cwd, "work", "History-wal"));
    assert.ok(wal.length > 0, "the fixture must leave an unplayed WAL beside the database");
    const out = body<BrowserOut>(await tool("browser_history", cwd, { path: "work/History", query: "chrome_url_summary" }));
    assert.equal(out.wal_present, true);
    assert.equal(out.wal_bytes, wal.length);
    assert.ok(out.wal_frames_replayed >= 2, JSON.stringify(out.wal_checkpoint));
    assert.equal(out.wal_checkpoint.checkpointed_frames, out.wal_frames_replayed);
    assert.deepEqual(out.rows.map((r) => r.url), ["http://203.0.113.24/upload.aspx", "http://example.test/a"], "the row only the log holds is seen");
    assert.equal(out.wal_replayed, undefined, "the old flag is gone: it meant only that a sidecar was copied");
    // The original and its log are untouched.
    assert.deepEqual(await readFile(join(cwd, "work", "History-wal")), wal);
  });
});

test("browser_history reports a damaged -wal as present with no frames replayed", async () => {
  await withCwd(async (cwd) => {
    py(WAL_FIXTURE, join(cwd, "work", "History"));
    await writeFile(join(cwd, "work", "History-wal"), Buffer.alloc(8192, 0x41));
    const out = body<BrowserOut>(await tool("browser_history", cwd, { path: "work/History", query: "tables" }));
    assert.equal(out.wal_present, true);
    assert.equal(out.wal_frames_replayed, 0);
  });
});

test("browser_history opens its copy under an authorizer: a statement that begins like a read but writes is refused, and so is a pragma that sets", async () => {
  // The only guard was a textual prefix check, which `WITH ... INSERT` and `PRAGMA x = n` pass.
  await withCwd(async (cwd) => {
    py(CHROME_HISTORY_FIXTURE, join(cwd, "work", "History"));
    const before = await readFile(join(cwd, "work", "History"));
    const insert = failed(await tool("browser_history", cwd, { path: "work/History", sql: "WITH x AS (SELECT 'http://evil.test/') INSERT INTO urls (url) SELECT * FROM x" }));
    assert.match(insert.error, /sqlite refused the query/);
    assert.match(String(insert.reason), /not authorized/);
    const pragma = failed(await tool("browser_history", cwd, { path: "work/History", sql: "PRAGMA user_version = 77" }));
    assert.match(String(pragma.reason), /not authorized/);
    const attach = failed(await tool("browser_history", cwd, { path: "work/History", sql: "WITH x AS (SELECT 1) SELECT * FROM x; ATTACH DATABASE 'work/other.db' AS o" }));
    assert.match(attach.error, /SELECT, WITH or PRAGMA/, "the prefix check still holds first");
    // Reports still work.
    const info = body<BrowserOut>(await tool("browser_history", cwd, { path: "work/History", sql: "PRAGMA table_info(urls)" }));
    assert.ok(info.row_count >= 5);
    assert.deepEqual(await readFile(join(cwd, "work", "History")), before, "the evidence is never opened for writing");
    assert.equal(await exists(join(cwd, "work", "other.db")), false);
  });
});

const SENSITIVE_PASSWORD = "Summer2024!hunter2";
const SENSITIVE_COOKIE = "SESSIONTOKEN-9f8e7d6c5b4a-planted";
const SENSITIVE_BLOB = Buffer.from("v10" + "k3yM4t3r14l-planted-ciphertext-bytes", "latin1");

const LOGIN_FIXTURE = [
  "import sqlite3, sys",
  "c = sqlite3.connect(sys.argv[1])",
  "c.executescript('''",
  "CREATE TABLE logins (origin_url TEXT, action_url TEXT, username_element TEXT, username_value TEXT, password_element TEXT, password_value BLOB, signon_realm TEXT, date_created INTEGER, times_used INTEGER);",
  "CREATE TABLE cookies (creation_utc INTEGER, host_key TEXT, name TEXT, value TEXT, encrypted_value BLOB, path TEXT, expires_utc INTEGER);",
  "CREATE TABLE token_service (service TEXT, encrypted_token BLOB);",
  "''')",
  "c.execute('INSERT INTO logins VALUES (?,?,?,?,?,?,?,?,?)', ('https://portal.example.test/', 'https://portal.example.test/login', 'user', 'alice', 'pass', sys.argv[2].encode('latin1'), 'https://portal.example.test/', 13344307200000000, 4))",
  "c.execute('INSERT INTO cookies VALUES (?,?,?,?,?,?,?)', (13344307200000000, '.example.test', 'sid', sys.argv[3], bytes.fromhex(sys.argv[4]), '/', 13344397200000000))",
  "c.execute('INSERT INTO token_service VALUES (?,?)', ('Gaia', bytes.fromhex(sys.argv[4])))",
  "c.commit()",
].join("\n");


test("browser_history never echoes a password, a cookie value or an encrypted blob from Login Data or Cookies, in any query, and says which columns it withheld", async () => {
  // A SELECT * over `logins` and `cookies` printed password_value and the cookie values whole,
  // and `SELECT hex(...)` or `substr(...)` gave them back in any other shape.
  await withCwd(async (cwd) => {
    py(LOGIN_FIXTURE, join(cwd, "work", "Login Data"), SENSITIVE_PASSWORD, SENSITIVE_COOKIE, SENSITIVE_BLOB.toString("hex"));
    const queries = [
      "SELECT * FROM logins",
      "SELECT hex(password_value) AS h, length(password_value) AS n FROM logins",
      "SELECT substr(value, 1, 8) AS head, quote(encrypted_value) AS q FROM cookies",
      "SELECT * FROM cookies; SELECT * FROM token_service",
    ];
    for (const sql of queries) {
      const run = await tool("browser_history", cwd, { path: "work/Login Data", sql, limit: 1 });
      const out = body<BrowserOut>(run);
      const wholeAnswer = run.stdout + run.stderr;
      const encodings = [
        SENSITIVE_PASSWORD, SENSITIVE_COOKIE, SENSITIVE_BLOB.toString("latin1"),
        Buffer.from(SENSITIVE_PASSWORD).toString("hex"), Buffer.from(SENSITIVE_COOKIE).toString("hex"), SENSITIVE_BLOB.toString("hex"),
        Buffer.from(SENSITIVE_PASSWORD).toString("base64"), Buffer.from(SENSITIVE_COOKIE).toString("base64"), SENSITIVE_BLOB.toString("base64"),
        SENSITIVE_PASSWORD.slice(0, 6), SENSITIVE_COOKIE.slice(0, 12), "hunter2", "k3yM4t3r14l",
      ];
      for (const secret of encodings) assert.equal(wholeAnswer.toLowerCase().includes(secret.toLowerCase()), false, `${sql}: ${secret}`);
      assert.ok(out.sensitive_columns_withheld.length >= 3, sql);
      // And no file the answer names, nor anything the tool left under work/, holds one.
      for (const file of await everyFileUnder(join(cwd, "work"))) {
        if (file.endsWith("Login Data")) continue;
        const text = (await readFile(file)).toString("latin1").toLowerCase();
        for (const secret of encodings) assert.equal(text.includes(secret.toLowerCase()), false, `${file}: ${secret}`);
      }
    }
    const logins = body<BrowserOut>(await tool("browser_history", cwd, { path: "work/Login Data", sql: "SELECT origin_url, username_value, password_value, times_used FROM logins" }));
    assert.equal(logins.rows[0].origin_url, "https://portal.example.test/");
    assert.equal(logins.rows[0].username_value, "alice", "a username is returned; it is not a secret");
    assert.equal(logins.rows[0].password_value, `[withheld: ${SENSITIVE_PASSWORD.length} bytes]`, "only the length of a withheld cell is left");
    assert.equal(logins.rows[0].times_used, 4);
    const withheld = Object.fromEntries(logins.sensitive_columns_withheld.map((w) => [`${w.table}.${w.column}`, w]));
    assert.equal(withheld["logins.password_value"].cells_withheld, 1);
    assert.equal(withheld["logins.password_value"].total_length, SENSITIVE_PASSWORD.length);
    assert.equal(withheld["cookies.value"].cells_withheld, 1);
    assert.equal(withheld["cookies.encrypted_value"].cells_withheld, 1);
    assert.equal(withheld["token_service.encrypted_token"].cells_withheld, 1, "a column whose name says token and encrypted is withheld in any table");
    // The disposable copy, which held the originals, is gone.
    const leftovers = [...(await readdir(join(cwd, "work"))), ...(await readdir(join(cwd, "work", "s1")).catch(() => [] as string[]))].filter((n) => n.startsWith(".browser-scratch"));
    assert.deepEqual(leftovers, []);
  });
});

test("browser_history keeps two result columns of one name apart, and says which it renamed", async () => {
  await withCwd(async (cwd) => {
    py(CHROME_HISTORY_FIXTURE, join(cwd, "work", "History"));
    const out = body<BrowserOut>(await tool("browser_history", cwd, { path: "work/History", sql: "SELECT u.id, v.id FROM urls u JOIN visits v ON v.url = u.id ORDER BY v.id" }));
    assert.deepEqual(out.columns, ["id", "id_2"]);
    assert.deepEqual(out.rows, [{ id: 1, id_2: 1 }, { id: 1, id_2: 2 }]);
  });
});

test("browser_history names a file that is not a database, with whether it has the SQLite header and its size, never its bytes", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "History"), Buffer.from("this is not sqlite, it is only text padded out to a page".padEnd(4096, " ")));
    const err = failed(await tool("browser_history", cwd, { path: "work/History", query: "tables" }));
    assert.match(err.error, /not a SQLite database/);
    assert.equal(err.size, 4096);
    assert.equal(err.sqlite_header, false);
    assert.equal(err.first_bytes_hex, undefined, "the first bytes of a file can be a secret and are not echoed");
  });
});

// --- yara_scan ------------------------------------------------------------------

type YaraOut = {
  status: string;
  complete: boolean;
  timed_out: boolean;
  yara_exit_status: number;
  yara_argv: string[];
  rules_sha256: string;
  matches: Array<{ rule: string; file: string; string_matches: number }>;
  match_count: number;
  string_matches: Array<{ finding_id: string; rule: string; file: string; identifier: string; offset: number; offset_hex: string; length: number | null }>;
  string_match_count: number;
  string_matches_page: { all_results?: string };
  stderr_file: string | null;
  stderr_line_count: number;
  warnings: string[];
  secret_values: { requested: boolean; written: number; values_file: string | null; contains_secret_values: boolean };
};

const PLANTED = "password=Summer2024!";

/** A yara stand-in: it prints what yara 4.x prints for `-s -L` (`rule file`, then `0x<offset>:<length>:$id: <data>`). */
const YARA_STUB = (extra = ""): string => `
case "$1" in
  --version) echo 4.5.8; exit 0;;
  --help) printf '%s\\n' '  -s,  --print-strings   print matching strings' '  -L,  --print-string-length   print length of matched strings' '  -N,  --no-follow-symlinks   do not follow symlinks'; exit 0;;
esac
for last; do :; done
${extra}
echo "pw $last"
echo '0x6:20:$a: ${PLANTED}'
echo '0x21:4:$m: 4D 5A 90 00'
echo "other $last"
echo '0x40:3:$k: abc'
`;

test("yara_scan reports the rule, file, string identifier, offset and length of a match and never the matched bytes", async () => {
  // `-s` prints the matched bytes, and they went into the answer: a rule that found `password=` put
  // the password in stdout and in the job log.
  await withCwd(async (cwd, bin) => {
    await stub(bin, "yara", YARA_STUB());
    await writeFile(join(cwd, "work", "rules.yar"), "rule pw { condition: true }");
    await writeFile(join(cwd, "work", "sample.bin"), `xxxxxx${PLANTED}`);
    const run = await tool("yara_scan", cwd, { rules: "work/rules.yar", target: "work/sample.bin" }, {}, bin);
    const out = body<YaraOut>(run);
    assert.equal(out.status, "complete");
    assert.equal(out.match_count, 2);
    assert.deepEqual(out.matches.map((m) => [m.rule, m.string_matches]), [["pw", 2], ["other", 1]]);
    assert.deepEqual(out.string_matches[0], { finding_id: "S000001", rule: "pw", file: "work/sample.bin", identifier: "$a", offset: 6, offset_hex: "0x6", length: 20 });
    assert.equal(out.string_match_count, 3);
    for (const piece of [PLANTED, "Summer2024", "password=", Buffer.from(PLANTED).toString("hex"), Buffer.from(PLANTED).toString("base64"), "4D 5A 90 00"]) {
      assert.equal((run.stdout + run.stderr).includes(piece), false, piece);
    }
    assert.equal(out.secret_values.requested, false);
    assert.equal(out.secret_values.written, 0);
    // Nothing the tool wrote holds them either: yara's text is read as a stream and dropped.
    const files = await everyFileUnder(join(cwd, "work"));
    for (const file of files) assert.equal((await readFile(file)).toString("latin1").includes("Summer2024") && !file.endsWith("sample.bin"), false, file);
    assert.ok(out.yara_argv.includes("-s") && out.yara_argv.includes("-L"));
    assert.match(out.rules_sha256, /^[0-9a-f]{64}$/);
  });
});

test("yara_scan writes the matched bytes only on write_matches, only in a job, only to a 0600 file under $OUT, with the finding ids of the answer", async () => {
  await withCwd(async (cwd, bin) => {
    await stub(bin, "yara", YARA_STUB());
    await writeFile(join(cwd, "work", "rules.yar"), "rule pw { condition: true }");
    await writeFile(join(cwd, "work", "sample.bin"), "x");
    // Outside a job the request is refused and nothing is written.
    const refused = failed(await tool("yara_scan", cwd, { rules: "work/rules.yar", target: "work/sample.bin", write_matches: true }, {}, bin));
    assert.match(refused.error, /refused outside a job/);
    assert.deepEqual((await everyFileUnder(join(cwd, "work"))).filter((f) => f.includes("yara-matched")), []);
    // In a job.
    const outDir = join(cwd, "out");
    await mkdir(outDir, { recursive: true });
    const run = await tool("yara_scan", cwd, { rules: "work/rules.yar", target: "work/sample.bin", write_matches: true }, { JOB_ID: "j000007", OUT: outDir }, bin);
    const out = body<YaraOut>(run);
    assert.equal(out.secret_values.requested, true);
    assert.equal(out.secret_values.written, 3);
    assert.equal(out.secret_values.values_file, "store/jobs/j000007/out/yara-matched-strings.jsonl");
    assert.equal(out.secret_values.contains_secret_values, true);
    for (const piece of yaraPieces()) assert.equal((run.stdout + run.stderr).includes(piece), false, `even then the answer itself has no ${piece}`);
    const file = join(outDir, "yara-matched-strings.jsonl");
    assert.equal((await stat(file)).mode & 0o777, 0o600);
    const rows = (await readFile(file, "utf8")).trimEnd().split("\n").map((l) => JSON.parse(l) as { finding_id: string; value: string; offset: number; length: number; identifier: string });
    assert.deepEqual(rows.map((r) => r.finding_id), out.string_matches.map((m) => m.finding_id));
    assert.equal(rows[0].value, PLANTED);
    assert.equal(rows[0].offset, 6);
    assert.equal(rows[0].length, 20);
    // Nothing else the tool wrote holds the value, in any form: only the sealed values file does.
    for (const other of (await everyFileUnder(cwd)).filter((f) => f !== file && !f.endsWith("sample.bin") && !f.endsWith("rules.yar") && !f.includes("/bin/"))) {
      const text = (await readFile(other)).toString("latin1");
      for (const piece of yaraPieces()) assert.equal(text.includes(piece), false, `${other} holds ${piece}`);
    }
    // A second run in the same job, the values file already there: it scans all the same, writes the next
    // numbered file, names it, and the first file is as it was (it was refused without scanning).
    const before = await readFile(file);
    const again = body<YaraOut>(await tool("yara_scan", cwd, { rules: "work/rules.yar", target: "work/sample.bin", write_matches: true }, { JOB_ID: "j000007", OUT: outDir }, bin));
    assert.equal(again.status, "complete");
    assert.equal(again.string_match_count, 3);
    assert.equal(again.secret_values.values_file, "store/jobs/j000007/out/yara-matched-strings-2.jsonl");
    assert.equal(again.secret_values.written, 3);
    assert.deepEqual(await readFile(file), before);
    assert.equal((await stat(join(outDir, "yara-matched-strings-2.jsonl"))).mode & 0o777, 0o600);
  });
});

/** The planted value in every form an answer could carry it: whole, its words, its fragments, hex and base64 of each. */
function yaraPieces(): string[] {
  const raw = ["Summer2024!", "Summer2024", "password=Summer2024!", "password=", "Summer", "2024!"];
  return [...raw, ...raw.map((r) => Buffer.from(r).toString("hex")), ...raw.map((r) => Buffer.from(r).toString("base64").replace(/=+$/, "")), "4D 5A 90 00"].filter((x) => x.length >= 5 || x === "2024!");
}

test("yara_scan keeps the whole of a run it had to stop: status partial, complete false, the matches read before the time limit and the stderr file", async () => {
  // A timeout threw away everything yara had printed, and the answer was "did not finish".
  await withCwd(async (cwd, bin) => {
    await stub(bin, "yara", YARA_STUB(`echo "warning: rule slow" >&2\n`).replace(`echo "other $last"`, `echo "other $last"\nsleep 30`));
    await writeFile(join(cwd, "work", "rules.yar"), "rule pw { condition: true }");
    await writeFile(join(cwd, "work", "sample.bin"), "x");
    const started = Date.now();
    const out = body<YaraOut>(await tool("yara_scan", cwd, { rules: "work/rules.yar", target: "work/sample.bin", timeout_seconds: 2 }, {}, bin));
    assert.ok(Date.now() - started < 20_000, "the stub's sleep must have been killed, not waited for");
    assert.equal(out.status, "partial");
    assert.equal(out.complete, false);
    assert.equal(out.timed_out, true);
    assert.equal(out.match_count, 2, "the matches printed before the stop are kept");
    assert.deepEqual(out.warnings, ["warning: rule slow"], "warnings are kept, not suppressed with -w");
    assert.ok(out.stderr_file);
    assert.equal((await readFile(join(cwd, out.stderr_file as string), "utf8")).trim(), "warning: rule slow");
  });
});

test("yara_scan reports a yara that fails with a rule error as failed with its stderr, and a non-zero exit after matches as partial", async () => {
  await withCwd(async (cwd, bin) => {
    await writeFile(join(cwd, "work", "rules.yar"), "rule pw { condition: true }");
    await writeFile(join(cwd, "work", "sample.bin"), "x");
    await stub(bin, "yara", `case "$1" in --version) echo 4.5.8; exit 0;; --help) echo '  -L, --print-string-length'; exit 0;; esac\necho 'rules.yar(1): error: syntax error, unexpected identifier' >&2\nexit 1`);
    const bad = JSON.parse((await tool("yara_scan", cwd, { rules: "work/rules.yar", target: "work/sample.bin" }, {}, bin)).stdout) as YaraOut;
    assert.equal(bad.status, "failed");
    assert.equal(bad.yara_exit_status, 1);
    assert.match(bad.warnings[0], /syntax error/);
    await stub(bin, "yara", YARA_STUB(`echo 'error scanning b: could not open file' >&2`).replace("\necho '0x40:3:$k: abc'", "\necho '0x40:3:$k: abc'\nexit 1"));
    const part = body<YaraOut>(await tool("yara_scan", cwd, { rules: "work/rules.yar", target: "work/sample.bin" }, {}, bin));
    assert.equal(part.status, "partial");
    assert.equal(part.complete, false);
    assert.equal(part.match_count, 2);
  });
});

test("yara_scan pages its string matches past limit and keeps every one in the file the page names", async () => {
  await withCwd(async (cwd, bin) => {
    await stub(bin, "yara", `case "$1" in --version) echo 4.5.8; exit 0;; --help) echo '  -L, --print-string-length'; exit 0;; esac\nfor last; do :; done\necho "bulk $last"\ni=0; while [ $i -lt 450 ]; do printf '0x%x:4:$s: abcd\\n' $((i*16)); i=$((i+1)); done`);
    await writeFile(join(cwd, "work", "rules.yar"), "rule bulk { condition: true }");
    await writeFile(join(cwd, "work", "sample.bin"), "x");
    const out = body<YaraOut>(await tool("yara_scan", cwd, { rules: "work/rules.yar", target: "work/sample.bin", limit: 100 }, {}, bin));
    assert.equal(out.string_match_count, 450);
    assert.equal(out.string_matches.length, 100);
    const all = (await readFile(join(cwd, out.string_matches_page.all_results as string), "utf8")).trimEnd().split("\n").map((l) => JSON.parse(l) as { offset: number });
    assert.equal(all.length, 450);
    assert.equal(all[449].offset, 449 * 16);
  });
});

test("yara_scan against the installed yara: the matched bytes stay out of the answer", async (t) => {
  if (spawnSync("yara", ["--version"]).status !== 0) return t.skip("yara is not installed on this host");
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "rules.yar"), 'rule pw { strings: $a = /password=[A-Za-z0-9!]+/ $w = "world" wide ascii nocase condition: any of them }');
    await writeFile(join(cwd, "work", "sample.bin"), `hello ${PLANTED} world`);
    const run = await tool("yara_scan", cwd, { rules: "work/rules.yar", target: "work/sample.bin" });
    const out = body<YaraOut>(run);
    assert.equal(out.status, "complete");
    assert.equal(out.string_match_count, 2);
    assert.deepEqual(out.string_matches.map((m) => [m.identifier, m.offset, m.length]), [["$a", 6, 20], ["$w", 27, 5]]);
    assert.equal(run.stdout.includes("Summer2024"), false);
  });
});

// --- esedb_query ----------------------------------------------------------------

type EseOut = {
  status: string;
  complete: boolean;
  exporter_exit_status: number;
  exporter_version: string | null;
  timed_out: boolean;
  export_reused: boolean;
  stdout_file: string;
  stderr_file: string;
  tables?: string[];
  tables_in_partial_export?: string[];
  warning?: string;
  table?: string;
  columns?: string[];
  duplicate_columns_renamed?: string[];
  rows?: Array<Record<string, string | number>>;
  row_count?: number;
  candidates?: string[];
  db_sha256: string;
};

/** esedbexport as libesedb's utility behaves: `esedbexport -t <root> <db>` writes <root>.export/<table>.<index>, tab separated, and `-V` prints a version. */
const ESEDBEXPORT_STUB = (body: string): string => `
if [ "$1" = "-V" ]; then echo "esedbexport 20231020"; exit 0; fi
root="$2"
echo run >> "$COUNT_FILE"
mkdir -p "$root.export"
${body}
`;

test("esedb_query does not turn a failed export into a clean table listing: status partial, the exporter's output kept whole in files", async () => {
  // An export directory that existed was taken for success whatever the exporter's exit status, so a
  // run that died after one table listed that table as the database's contents.
  await withCwd(async (cwd, bin) => {
    await stub(bin, "esedbexport", ESEDBEXPORT_STUB(`printf 'ContainerId\\tName\\n1\\tContent\\n' > "$root.export/Containers.4"\necho "libesedb: unable to open table 7: page checksum mismatch" >&2\necho "exporting table 1 of 12" \nexit 1`));
    await writeFile(join(cwd, "work", "WebCacheV01.dat"), "ESE stand-in");
    const out = body<EseOut>(await tool("esedb_query", cwd, { path: "work/WebCacheV01.dat" }, { COUNT_FILE: join(cwd, "count") }, bin));
    assert.equal(out.status, "partial");
    assert.equal(out.complete, false);
    assert.equal(out.exporter_exit_status, 1);
    assert.equal(out.exporter_version, "esedbexport 20231020");
    assert.equal(out.tables, undefined, "a partial export is never listed as the database's tables");
    assert.deepEqual(out.tables_in_partial_export, ["Containers"]);
    assert.match(out.warning ?? "", /PARTIAL export/);
    assert.match(await readFile(join(cwd, out.stderr_file), "utf8"), /page checksum mismatch/);
    assert.match(await readFile(join(cwd, out.stdout_file), "utf8"), /exporting table 1 of 12/);
    // Reading from it is allowed, and says so on every answer.
    const one = body<EseOut>(await tool("esedb_query", cwd, { path: "work/WebCacheV01.dat", table: "Containers" }, { COUNT_FILE: join(cwd, "count") }, bin));
    assert.equal(one.status, "partial");
    assert.equal(one.rows?.[0].Name, "Content");
  });
});

test("esedb_query refuses a table name that matches two export files and lists them, and reads one by its file name", async () => {
  // `hits[0]` took the first of the matches without a word.
  await withCwd(async (cwd, bin) => {
    await stub(bin, "esedbexport", ESEDBEXPORT_STUB(`printf 'Id\\tName\\n1\\tfirst\\n' > "$root.export/Containers.4"\nprintf 'Id\\tName\\n2\\tsecond\\n' > "$root.export/Containers.12"`));
    await writeFile(join(cwd, "work", "WebCacheV01.dat"), "ESE stand-in");
    const env = { COUNT_FILE: join(cwd, "count") };
    const err = failed(await tool("esedb_query", cwd, { path: "work/WebCacheV01.dat", table: "Containers" }, env, bin));
    assert.match(err.error, /more than one export file/);
    assert.deepEqual(err.candidates, ["Containers.12", "Containers.4"]);
    const second = body<EseOut>(await tool("esedb_query", cwd, { path: "work/WebCacheV01.dat", table: "Containers.12" }, env, bin));
    assert.equal(second.rows?.[0].Name, "second");
  });
});

test("esedb_query exports a database once, keeps the export under its digest, and reuses it for the next call", async () => {
  // The whole database was exported into a temp directory on every call, even to list the tables, and deleted.
  await withCwd(async (cwd, bin) => {
    await stub(bin, "esedbexport", ESEDBEXPORT_STUB(`printf 'Id\\tName\\n1\\ta\\n' > "$root.export/T.0"`));
    await writeFile(join(cwd, "work", "SRUDB.dat"), "ESE stand-in");
    const env = { COUNT_FILE: join(cwd, "count") };
    const first = body<EseOut>(await tool("esedb_query", cwd, { path: "work/SRUDB.dat" }, env, bin));
    const second = body<EseOut>(await tool("esedb_query", cwd, { path: "work/SRUDB.dat", table: "T" }, env, bin));
    assert.equal(first.export_reused, false);
    assert.equal(second.export_reused, true);
    assert.equal((await readFile(join(cwd, "count"), "utf8")).trim().split("\n").length, 1, "the exporter ran once");
    assert.match(first.db_sha256, /^[0-9a-f]{64}$/);
    const manifest = JSON.parse(await readFile(join(cwd, "work", "s1", "esedb-export", first.db_sha256.slice(0, 16), "export-manifest.json"), "utf8")) as { db_sha256: string; exporter_exit_status: number; files: Record<string, unknown> };
    assert.equal(manifest.db_sha256, first.db_sha256);
    assert.equal(manifest.exporter_exit_status, 0);
    assert.deepEqual(Object.keys(manifest.files), ["T.0"]);
    // Changed bytes are another export.
    await writeFile(join(cwd, "work", "SRUDB.dat"), "ESE stand-in, changed");
    const third = body<EseOut>(await tool("esedb_query", cwd, { path: "work/SRUDB.dat" }, env, bin));
    assert.equal(third.export_reused, false);
  });
});

test("esedb_query numbers every row, keeps columns that share a name apart, and keeps a cell of any size whole", async () => {
  await withCwd(async (cwd, bin) => {
    const big = "x".repeat(2_000_000);
    await stub(bin, "esedbexport", ESEDBEXPORT_STUB(`printf 'Id\\tName\\tName\\n1\\ta\\tb\\n2\\tc\\t${big}\\n' > "$root.export/Dup.2"`));
    await writeFile(join(cwd, "work", "x.edb"), "ESE stand-in");
    const out = body<EseOut>(await tool("esedb_query", cwd, { path: "work/x.edb", table: "Dup" }, { COUNT_FILE: join(cwd, "count") }, bin));
    assert.deepEqual(out.columns, ["Id", "Name", "Name"]);
    assert.deepEqual(out.duplicate_columns_renamed, ["Name_2"]);
    assert.deepEqual(out.rows?.map((r) => r._row), [1, 2]);
    assert.equal(out.rows?.[0].Name_2, "b");
    assert.equal((out.rows?.[1].Name_2 as string).length, 2_000_000);
  });
});

test("esedb_query keeps what a time-limited export wrote and says it was stopped", async () => {
  await withCwd(async (cwd, bin) => {
    await stub(bin, "esedbexport", ESEDBEXPORT_STUB(`printf 'Id\\n1\\n' > "$root.export/Part.0"\nsleep 30`));
    await writeFile(join(cwd, "work", "x.edb"), "ESE stand-in");
    const started = Date.now();
    const out = body<EseOut>(await tool("esedb_query", cwd, { path: "work/x.edb", export_timeout_seconds: 1 }, { COUNT_FILE: join(cwd, "count") }, bin));
    assert.ok(Date.now() - started < 20_000);
    assert.equal(out.status, "partial");
    assert.equal(out.timed_out, true);
    assert.deepEqual(out.tables_in_partial_export, ["Part"]);
    // A partial export is not reused as a complete one: the next call exports again.
    const again = body<EseOut>(await tool("esedb_query", cwd, { path: "work/x.edb", export_timeout_seconds: 1 }, { COUNT_FILE: join(cwd, "count") }, bin));
    assert.equal(again.export_reused, false);
  });
});

// --- sigma_hunt -----------------------------------------------------------------
// These tests are in tests/pack-windows-forensics-evtx.test.ts.

// --- vss_stores -----------------------------------------------------------------

type VssOut = {
  status: string;
  stores: Array<{ store: number; identifier?: string; creation_time?: string; mount_argv: string[][]; mount_with: string }>;
  store_count: number;
  stores_claimed: number | null;
  problems: string[];
  exit_code: number;
  note?: string;
  error?: string;
  stderr_file: string;
  stdout_file: string;
};

/** vshadowinfo's report as libvshadow prints it: a header, `Number of stores`, then a `Store: n` block of tab-indented fields per snapshot. */
const SHADOW_REPORT = (claimed: number | null, shown: number): string => {
  const lines = ["vshadowinfo 20240504", "", "Volume Shadow Snapshot information:"];
  if (claimed !== null) lines.push(`\tNumber of stores:\t${claimed}`);
  for (let i = 1; i <= shown; i++) {
    lines.push("", `Store: ${i}`, `\tIdentifier\t\t: 0b3cd1ec-aaaa-bbbb-cccc-00000000000${i}`, `\tCreation time\t\t: Oct 14, 2023 16:14:3${i}.000000000 UTC`, "\tVolume size\t\t: 53 GiB (57982058496 bytes)");
  }
  return lines.join("\n");
};

const vshadowinfoStub = (report: string, stderr = "", exit = 0): string => `cat <<'REPORT'\n${report}\nREPORT\n${stderr ? `echo '${stderr}' >&2\n` : ""}exit ${exit}`;

test("vss_stores says failed, never 'no stores', when vshadowinfo fails, and keeps its whole stderr in a file", async () => {
  // A failing vshadowinfo left `stores` empty, and the tool printed "No shadow-copy stores were observed on this
  // volume": an absence-shaped answer for a failure.
  await withCwd(async (cwd, bin) => {
    await stub(bin, "vshadowinfo", vshadowinfoStub("", "vshadowinfo: unable to open volume.\nlibvshadow: unsupported format version 9", 1));
    await writeFile(join(cwd, "work", "disk.raw"), Buffer.alloc(4096));
    const run = await tool("vss_stores", cwd, { image: "work/disk.raw", offset: 1048576 }, {}, bin);
    const out = failed(run) as unknown as VssOut;
    assert.equal(out.status, "failed");
    assert.equal(out.exit_code, 1);
    assert.doesNotMatch(run.stdout, /No shadow-copy stores were observed/);
    assert.match(out.note ?? "", /not a finding/);
    assert.match(await readFile(join(cwd, out.stderr_file), "utf8"), /unsupported format version 9/);
  });
});

test("vss_stores reports a count mismatch between the stores vshadowinfo claims and the stores it could read as partial", async () => {
  await withCwd(async (cwd, bin) => {
    await stub(bin, "vshadowinfo", vshadowinfoStub(SHADOW_REPORT(2, 1)));
    await writeFile(join(cwd, "work", "disk.raw"), Buffer.alloc(4096));
    const out = body<VssOut>(await tool("vss_stores", cwd, { image: "work/disk.raw" }, {}, bin));
    assert.equal(out.status, "partial");
    assert.equal(out.stores_claimed, 2);
    assert.equal(out.store_count, 1);
    assert.ok(out.problems.some((p) => /reports 2 store\(s\) and 1 could be read/.test(p)));
    assert.match(out.note ?? "", /incomplete/);
  });
});

test("vss_stores reads a complete report, and quotes every operand of the mount command it suggests", async () => {
  // The suggested command interpolated the image path into a shell string without quoting.
  await withCwd(async (cwd, bin) => {
    await stub(bin, "vshadowinfo", vshadowinfoStub(SHADOW_REPORT(2, 2)));
    await writeFile(join(cwd, "work", "my disk;touch pwned.raw"), Buffer.alloc(4096));
    const out = body<VssOut>(await tool("vss_stores", cwd, { image: "work/my disk;touch pwned.raw", offset: 4096 }, {}, bin));
    assert.equal(out.status, "complete");
    assert.equal(out.store_count, 2);
    assert.equal(out.stores[0].identifier, "0b3cd1ec-aaaa-bbbb-cccc-000000000001");
    assert.equal(out.stores[1].creation_time, "Oct 14, 2023 16:14:32.000000000 UTC");
    assert.deepEqual(out.stores[0].mount_argv[1], ["vshadowmount", "-o", "4096", "work/my disk;touch pwned.raw", "work/s1/vss/"]);
    assert.match(out.stores[0].mount_with, /'work\/my disk;touch pwned\.raw'/);
    assert.equal(out.problems.length, 0);
  });
});

test("vss_stores says zero stores only when vshadowinfo ran, exited 0 and reported zero itself, and words it as a bounded negative", async () => {
  await withCwd(async (cwd, bin) => {
    await writeFile(join(cwd, "work", "disk.raw"), Buffer.alloc(4096));
    await stub(bin, "vshadowinfo", vshadowinfoStub(SHADOW_REPORT(0, 0)));
    const none = body<VssOut>(await tool("vss_stores", cwd, { image: "work/disk.raw" }, {}, bin));
    assert.equal(none.status, "complete");
    assert.equal(none.store_count, 0);
    assert.match(none.note ?? "", /reported 0 stores/);
    assert.match(none.note ?? "", /does not establish that none was ever made/);
    // An output it does not recognise is a failure, not zero stores.
    await stub(bin, "vshadowinfo", vshadowinfoStub("something else entirely"));
    const odd = failed(await tool("vss_stores", cwd, { image: "work/disk.raw" }, {}, bin)) as unknown as VssOut;
    assert.equal(odd.status, "failed");
    assert.ok(odd.problems.some((p) => /does not recognise its format/.test(p)));
  });
});

test("vss_stores says an EWF image has to be exposed raw first", async () => {
  await withCwd(async (cwd, bin) => {
    await stub(bin, "vshadowinfo", vshadowinfoStub("", "unable to open volume", 1));
    await writeFile(join(cwd, "work", "disk.E01"), Buffer.concat([Buffer.from([0x45, 0x56, 0x46, 0x09, 0x0d, 0x0a, 0xff, 0x00]), Buffer.alloc(100)]));
    const out = failed(await tool("vss_stores", cwd, { image: "work/disk.E01" }, {}, bin)) as unknown as VssOut;
    assert.ok(out.problems.some((p) => /EWF \(E01\) signature/.test(p)));
  });
});

// --- indx_carve -----------------------------------------------------------------

/**
 * An INDX record as MS-NTFS-style documentation lays it out (little-endian): "INDX", the update
 * sequence array offset (0x04) and count (0x06), the node header at 0x18 (offset of the first entry
 * from 0x18, live size, allocated size, flags), index entries (the MFT reference, entry length, key
 * length, flags, then the $FILE_NAME key at 0x10), and, in each 512-byte unit, the last two bytes
 * replaced by the update sequence number with the real bytes in the array.
 */
const INDX_TIME = 133_500_000_000_000_001n;

function indxFileName(parent: bigint, name: string): Buffer {
  const b = Buffer.alloc(0x42 + 2 * name.length);
  b.writeBigUInt64LE(parent | (1n << 48n), 0);
  for (let i = 0; i < 4; i++) b.writeBigUInt64LE(INDX_TIME + BigInt(i) * 10_000_000n, 8 + i * 8);
  b.writeBigUInt64LE(4096n, 0x28);
  b.writeUInt32LE(0x20, 0x38);
  b[0x40] = name.length;
  b[0x41] = 1;
  Buffer.from(name, "utf16le").copy(b, 0x42);
  return b;
}

function indxEntry(ref: bigint, content: Buffer, flags = 0, lengthOverride?: number): Buffer {
  let length = 0x10 + content.length;
  length += (8 - (length % 8)) % 8;
  const b = Buffer.alloc(length);
  b.writeBigUInt64LE(ref, 0);
  b.writeUInt16LE(lengthOverride ?? length, 8);
  b.writeUInt16LE(content.length, 10);
  b.writeUInt16LE(flags, 12);
  content.copy(b, 0x10);
  return b;
}

function indxBlock(vcn: number, live: Buffer[], slack: Buffer[], o: { usaCount?: number; breakUnit?: number } = {}): Buffer {
  const b = Buffer.alloc(4096);
  b.write("INDX", 0, "latin1");
  const usaOffset = 0x28;
  const usaCount = o.usaCount ?? 9;
  b.writeUInt16LE(usaOffset, 4);
  b.writeUInt16LE(usaCount, 6);
  b.writeBigUInt64LE(BigInt(vcn), 0x10);
  let at = 0x40;
  for (const e of [...live, indxEntry(0n, Buffer.alloc(0), 0x02)]) {
    e.copy(b, at);
    at += e.length;
  }
  const total = at - 0x18;
  for (const e of slack) {
    e.copy(b, at);
    at += e.length;
  }
  b.writeUInt32LE(0x40 - 0x18, 0x18);
  b.writeUInt32LE(total, 0x1c);
  b.writeUInt32LE(4096 - 0x18, 0x20);
  const sequence = Buffer.from([0x07, 0x00]);
  sequence.copy(b, usaOffset);
  for (let i = 1; i < 9; i++) {
    const end = i * 512 - 2;
    if (i < usaCount) b.copy(b, usaOffset + i * 2, end, end + 2);
    // A unit whose last two bytes do not carry the sequence number is a block torn between writes.
    (o.breakUnit === i ? Buffer.from([0xee, 0xee]) : sequence).copy(b, end);
  }
  return b;
}

type IndxOut = {
  status: string;
  blocks: number;
  blocks_fixup_failed: number;
  blocks_salvaged: number;
  entries_excluded_unreliable: number;
  entry_count: number;
  entries: Array<{ name: string; source: string; block_offset: number; fixup_ok: boolean; node_ok: boolean; salvaged: boolean; created: string | null; created_filetime: string }>;
  problems: Array<{ offset: number; why: string }>;
  note: string;
};

const indxSet = (n: number, tag: string): { live: Buffer[]; slack: Buffer[] } => ({
  live: [indxEntry(100n + BigInt(n), indxFileName(64n, `live-${tag}.txt`))],
  slack: [indxEntry(200n + BigInt(n), indxFileName(64n, `old-${tag}.txt`))],
});

test("indx_carve leaves out the entries of a block whose update sequence check failed, and marks them when asked for", async () => {
  // A block whose fixup failed was recorded under `problems`, but every entry carved from it was
  // emitted as if sound: a row looked as reliable as one from a good block.
  await withCwd(async (cwd) => {
    const good = indxSet(1, "good");
    const torn = indxSet(2, "torn");
    await writeFile(join(cwd, "work", "I30"), Buffer.concat([indxBlock(0, good.live, good.slack), indxBlock(1, torn.live, torn.slack, { breakUnit: 3 })]));
    const out = body<IndxOut>(await tool("indx_carve", cwd, { path: "work/I30" }));
    assert.deepEqual(out.entries.map((e) => e.name).sort(), ["live-good.txt", "old-good.txt"]);
    assert.ok(out.entries.every((e) => e.fixup_ok === true && e.node_ok === true && e.salvaged === false && e.block_offset === 0));
    assert.equal(out.blocks, 2);
    assert.equal(out.blocks_fixup_failed, 1);
    assert.equal(out.blocks_salvaged, 1);
    assert.equal(out.entries_excluded_unreliable, 2, "what was left out is counted");
    assert.equal(out.status, "partial");
    assert.deepEqual(out.problems.map((p) => [p.offset, p.why]), [[4096, "sector 3 does not carry the update sequence number"]]);
    assert.match(out.note, /left out \(2\), unless include_unreliable is true/);

    const all = body<IndxOut>(await tool("indx_carve", cwd, { path: "work/I30", include_unreliable: true }));
    assert.equal(all.entry_count, 4);
    const torned = all.entries.filter((e) => e.block_offset === 4096);
    assert.equal(torned.length, 2);
    assert.ok(torned.every((e) => e.fixup_ok === false && e.salvaged === true), "every entry from the torn block carries the flag");
    assert.equal(all.entries_excluded_unreliable, 0);
  });
});

test("indx_carve checks the update sequence array covers the block, and a live entry's length against the live region, and names each failure", async () => {
  await withCwd(async (cwd) => {
    const a = indxSet(1, "short-usa");
    const b = indxSet(2, "bad-length");
    // The array claims 5 values for a block that has 8 units; and an entry whose length runs past the live region.
    const shortUsa = indxBlock(0, a.live, a.slack, { usaCount: 5 });
    const badLength = indxBlock(1, [indxEntry(300n, indxFileName(64n, "overlong.txt"), 0, 0x400)], b.slack);
    await writeFile(join(cwd, "work", "I30"), Buffer.concat([shortUsa, badLength]));
    const out = body<IndxOut>(await tool("indx_carve", cwd, { path: "work/I30", include_unreliable: true }));
    assert.equal(out.blocks_salvaged, 2);
    assert.ok(out.problems.some((p) => p.offset === 0 && /holds 4 fixup value\(s\) and the block has 8 512-byte unit\(s\)/.test(p.why)), JSON.stringify(out.problems));
    assert.ok(out.problems.some((p) => p.offset === 4096 && /live entry at block offset \d+ has a length \(1024\)/.test(p.why)), JSON.stringify(out.problems));
    assert.ok(out.entries.every((e) => e.salvaged));
    const byDefault = body<IndxOut>(await tool("indx_carve", cwd, { path: "work/I30" }));
    assert.equal(byDefault.entry_count, 0);
    assert.equal(byDefault.entries_excluded_unreliable > 0, true);
  });
});

test("indx_carve returns the raw FILETIMEs beside the dates and no longer says slack times are the set a timestomper does not reach", async () => {
  await withCwd(async (cwd) => {
    const s = indxSet(1, "x");
    await writeFile(join(cwd, "work", "I30"), indxBlock(0, s.live, s.slack));
    const out = body<IndxOut>(await tool("indx_carve", cwd, { path: "work/I30", slack_only: true }));
    assert.equal(out.entries.length, 1);
    assert.equal(out.entries[0].source, "slack");
    assert.equal(out.entries[0].created_filetime, "133500000000000001");
    assert.equal(out.entries[0].created, "2024-01-17T21:20:00.0000001Z");
    assert.doesNotMatch(out.note, /timestomper/);
    assert.match(out.note, /stale index material/);
    assert.match(out.note, /not evidence that they were left unaltered/);
  });
});

// --- prefetch_mam and mam_scan --------------------------------------------------

// The builders (an SCCA file in its layouts, an Xpress Huffman stream, a MAM container) and the answer types are shared with
// tests/pack-windows-forensics-prefetch.test.ts: tests/windows-prefetch-fixtures.ts.
import { RUN_1, SAMPLE_NAMES, mam, sample, scca, type PrefetchOut } from "./windows-prefetch-fixtures.ts";

test("prefetch_mam reads a version 30 file by its layout: the run count, last runs by integer arithmetic, every filename string whole, and the first volume", async () => {
  // The strings were found by a regular expression that matched ASCII-range UTF-16 only, so a path with a
  // non-ASCII character was missed; the last-run fraction was rounded through a float.
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "EXAMPLE.EXE-A1B2C3D4.pf"), sample(30));
    const out = body<PrefetchOut>(await tool("prefetch_mam", cwd, { path: "work/EXAMPLE.EXE-A1B2C3D4.pf" }));
    assert.equal(out.status, "complete");
    assert.equal(out.container.mam, false);
    assert.equal(out.version, 30);
    assert.equal(out.exe_name, "EXAMPLE.EXE");
    assert.equal(out.prefetch_hash, "A1B2C3D4");
    assert.equal(out.run_count, 7);
    assert.deepEqual(out.last_runs, ["2023-11-13T00:53:20.1234567Z", "2023-11-13T00:53:21.1234567Z"]);
    assert.equal(out.last_runs_detail?.[0].filetime, String(RUN_1));
    assert.deepEqual(out.filename_strings, SAMPLE_NAMES, "the section the header locates, every name whole, non-ASCII included");
    assert.equal(out.volumes_decoded?.[0].device_path, "\\VOLUME{01d9aaaabbbb0000-1a2b3c4d}");
    assert.equal(out.volumes_decoded?.[0].serial_number, "1A2B3C4D");
    assert.equal(out.file_size_matches, true);
    assert.deepEqual(out.problems, []);
    assert.equal(out.all_strings, undefined, "the printable-run search is gone");
  });
});

test("prefetch_mam reads a version 23 file at its own offsets: the run count at 0x98 and one last-run slot", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "a.pf"), sample(23));
    const out = body<PrefetchOut>(await tool("prefetch_mam", cwd, { path: "work/a.pf" }));
    assert.equal(out.version, 23);
    assert.equal(out.run_count, 7);
    assert.deepEqual(out.last_runs, ["2023-11-13T00:53:20.1234567Z"]);
  });
});

test("prefetch_mam returns unsupported for a version it does not read, and interprets none of its version-dependent fields", async () => {
  // Version 99 was read as if it were 30: a last-run time and a run count came out of bytes that mean something else.
  await withCwd(async (cwd) => {
    const odd = sample(30);
    odd.writeUInt32LE(99, 0);
    await writeFile(join(cwd, "work", "odd.pf"), odd);
    const out = body<PrefetchOut>(await tool("prefetch_mam", cwd, { path: "work/odd.pf" }));
    assert.equal(out.status, "unsupported");
    assert.equal(out.supported, false);
    assert.equal(out.version, 99);
    assert.equal(out.exe_name, "EXAMPLE.EXE", "the version-independent header is still read");
    assert.equal(out.last_runs, undefined);
    assert.equal(out.run_count, undefined);
    assert.equal(out.filename_strings, undefined);
    assert.match(out.problems[0], /version 99 is not one this parser reads/);
  });
});

test("prefetch_mam refuses a MAM method it does not read, by name, and inflates nothing", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "v.pf"), mam(1000, Buffer.alloc(300), 0x84));
    const out = body<PrefetchOut>(await tool("prefetch_mam", cwd, { path: "work/v.pf" }));
    assert.equal(out.status, "unsupported");
    assert.equal(out.container.method, 0x84);
    assert.match(out.container.why ?? "", /method byte 0x84 is not the Xpress Huffman method/);
    assert.match(out.problems[0], /checksum/);
  });
});

test("prefetch_mam and mam_scan carry the same MAM, decompression and SCCA code", async () => {
  // The tools are standalone, so the shared reader is a copy; this holds the two copies identical.
  const mark = "# ---- Shared by prefetch_mam and mam_scan";
  const a = await readFile(join(WIN, "prefetch_mam", "run.py"), "utf8");
  const b = await readFile(join(WIN, "mam_scan", "run.py"), "utf8");
  const shared = (text: string, end: string): string => text.slice(text.indexOf(mark), text.indexOf(end)).trimEnd();
  const one = shared(a, "\n\n\ndef fail(");
  const two = shared(b, "\n\n\nSIG4 =");
  assert.ok(one.length > 3000, "the shared block was found");
  assert.ok(one === two, "the shared MAM and SCCA code differs between prefetch_mam and mam_scan");
});

// --- recyclebin_i ---------------------------------------------------------------

type RecycleEntry = {
  file: string;
  file_bytes?: number;
  header_version?: number;
  original_size?: number;
  deleted_at?: string | null;
  deleted_filetime?: string;
  original_path?: string;
  path_characters_declared?: number;
  truncated: boolean;
  trailing_bytes?: number;
  note?: string;
  error?: string;
  r_file: string | null;
  bin_directory_sid?: string;
};
type RecycleOut = { status: string; entries: RecycleEntry[]; entry_count: number; found: number; parsed: number; records_truncated: number; unknown_header: number; unreadable: number };

/** $I as documented: header (8), original size (8), deletion FILETIME (8); version 1 then holds 520 bytes of UTF-16LE path (544 in all); version 2 a 4-byte character count (the NUL included) and that many characters. */
function recycleV2(path: string, size: bigint, filetime: bigint, declared?: number): Buffer {
  const text = u16z(path);
  const b = Buffer.alloc(0x1c + text.length);
  b.writeBigUInt64LE(2n, 0);
  b.writeBigUInt64LE(size, 8);
  b.writeBigUInt64LE(filetime, 0x10);
  b.writeUInt32LE(declared ?? path.length + 1, 0x18);
  text.copy(b, 0x1c);
  return b;
}

function recycleV1(path: string, size: bigint, filetime: bigint): Buffer {
  const b = Buffer.alloc(544);
  b.writeBigUInt64LE(1n, 0);
  b.writeBigUInt64LE(size, 8);
  b.writeBigUInt64LE(filetime, 0x10);
  Buffer.from(path, "utf16le").copy(b, 0x18);
  return b;
}

test("recyclebin_i reads a complete version 2 and version 1 record, with the deletion time exact, the $R counterpart and the bin's SID", async () => {
  await withCwd(async (cwd) => {
    const sid = "S-1-5-21-1111111111-2222222222-3333333333-1001";
    const dir = join(cwd, "work", "recycle", sid);
    await mkdir(dir, { recursive: true });
    await writeFile(join(dir, "$IABCDEF.rtf"), recycleV2("C:\\Users\\joker\\Confidential.rtf", 439n, RUN_1));
    await writeFile(join(dir, "$RABCDEF.rtf"), "content");
    await writeFile(join(dir, "$IGHIJKL.txt"), recycleV1("C:\\Users\\joker\\notes-ğüşiöç.txt", 12n, RUN_1 + 10_000_000n));
    const out = body<RecycleOut>(await tool("recyclebin_i", cwd, { path: "work/recycle" }));
    assert.equal(out.status, "complete");
    assert.equal(out.found, 2);
    assert.equal(out.parsed, 2);
    const [v2, v1] = out.entries;
    assert.equal(v2.original_path, "C:\\Users\\joker\\Confidential.rtf");
    assert.equal(v2.original_size, 439);
    assert.equal(v2.deleted_at, "2023-11-13T00:53:20.1234567Z");
    assert.equal(v2.deleted_filetime, String(RUN_1));
    assert.equal(v2.truncated, false);
    assert.equal(v2.r_file, "$RABCDEF.rtf");
    assert.equal(v2.bin_directory_sid, sid);
    assert.equal(v1.original_path, "C:\\Users\\joker\\notes-ğüşiöç.txt");
    assert.equal(v1.header_version, 1);
    assert.equal(v1.r_file, null, "no $R beside it");
    assert.deepEqual(out.entries.map((e) => e.file.split("/").pop()), ["$IABCDEF.rtf", "$IGHIJKL.txt"], "sorted traversal");
  });
});

test("recyclebin_i reports a truncated record as truncated, with the bytes it has, and does not return a short path as a whole one", async () => {
  // A 24-byte header returned an empty path with no error, and a record that claimed 100 characters and
  // supplied one returned "A" as if it were the whole path.
  await withCwd(async (cwd) => {
    const dir = join(cwd, "work", "recycle");
    await mkdir(dir, { recursive: true });
    await writeFile(join(dir, "$IHEADER.bin"), recycleV1("", 5n, RUN_1).subarray(0, 24));
    const oneChar = recycleV2("A", 5n, RUN_1, 100);
    await writeFile(join(dir, "$ICLAIMS.bin"), oneChar);
    const out = body<RecycleOut>(await tool("recyclebin_i", cwd, { path: "work/recycle" }));
    assert.equal(out.status, "partial");
    assert.equal(out.records_truncated, 2);
    const claims = out.entries.find((e) => e.file.endsWith("$ICLAIMS.bin"))!;
    assert.equal(claims.truncated, true);
    assert.equal(claims.path_characters_declared, 100);
    assert.equal(claims.original_path, "A");
    assert.match(claims.note ?? "", /declares 100 path characters \(228 bytes in all\) and this file has 32 bytes/);
    const header = out.entries.find((e) => e.file.endsWith("$IHEADER.bin"))!;
    assert.equal(header.truncated, true);
    assert.match(header.note ?? "", /a version 1 record is 544 bytes and this file has 24/);
  });
});

test("recyclebin_i reads the whole of a long path, past the 4096 bytes it used to read, and names an unknown header and an oversize file", async () => {
  await withCwd(async (cwd) => {
    const dir = join(cwd, "work", "recycle");
    await mkdir(dir, { recursive: true });
    const long = "C:\\" + "d".repeat(3000) + "\\end.txt";
    await writeFile(join(dir, "$ILONG.txt"), recycleV2(long, 1n, RUN_1));
    const odd = Buffer.alloc(64);
    odd.writeBigUInt64LE(9n, 0);
    await writeFile(join(dir, "$IODD.bin"), odd);
    await writeFile(join(dir, "$IHUGE.bin"), Buffer.alloc(1024 * 1024 + 10));
    const out = body<RecycleOut>(await tool("recyclebin_i", cwd, { path: "work/recycle" }));
    const byName = Object.fromEntries(out.entries.map((e) => [e.file.split("/").pop(), e]));
    assert.equal(byName["$ILONG.txt"].original_path, long);
    assert.equal(byName["$ILONG.txt"].truncated, false);
    assert.match(byName["$IODD.bin"].error ?? "", /unknown header version 9/);
    assert.equal(byName["$IODD.bin"].original_path, undefined);
    assert.match(byName["$IHUGE.bin"].error ?? "", /not a \$I|a few hundred bytes/);
    assert.equal(out.unknown_header, 1);
    assert.equal(out.unreadable, 1);
    assert.equal(out.status, "partial");
  });
});

// --- utf16_urls -----------------------------------------------------------------

type UrlOut = {
  status: string;
  candidates: Array<{ encoding: string; offset: number; length_bytes: number; text: string; continued?: boolean; piece_of_a_longer_run?: boolean }>;
  candidate_count: number;
  by_encoding: { ascii: number; utf16le: number };
  groups: Array<{ text: string; encoding: string; occurrences: number; first_offset: number }>;
  distinct_count: number;
  groups_complete: boolean;
  filtered_out_by_contains: number;
  pieces: number;
  all_results?: string;
  urls?: unknown;
};

const wide = (text: string): Buffer => Buffer.from(text, "utf16le");

test("utf16_urls returns a URL of any length whole and keeps every occurrence with its own offset", async () => {
  // The ASCII pattern stopped after 300 characters without marking it, and a `seen` set dropped every
  // occurrence after the first, with its offset.
  await withCwd(async (cwd) => {
    const long = "https://example.test/" + "segment/".repeat(75) + "end?page=1";
    assert.ok(long.length > 600);
    const filler = Buffer.alloc(3000, 0xff);
    const file = Buffer.concat([filler, Buffer.from(long), filler, Buffer.from(long), filler]);
    await writeFile(join(cwd, "work", "mem.raw"), file);
    const out = body<UrlOut>(await tool("utf16_urls", cwd, { path: "work/mem.raw" }));
    assert.equal(out.candidate_count, 2);
    assert.deepEqual(out.candidates.map((c) => c.offset), [3000, 3000 + long.length + 3000]);
    assert.ok(out.candidates.every((c) => c.text === long && c.encoding === "ascii" && c.length_bytes === long.length));
    assert.equal(out.urls, undefined, "the field is `candidates` now");
    assert.equal(out.distinct_count, 1);
    assert.deepEqual(out.groups.map((g) => [g.occurrences, g.first_offset]), [[2, 3000]]);
  });
});

test("utf16_urls finds a URL that straddles a read window once, in ASCII and in UTF-16LE, and keeps a run longer than the carry whole in pieces", async () => {
  await withCwd(async (cwd) => {
    const chunk = 131072;
    const ascii = "http://straddle.test/path/to/a/page?id=7";
    const utf16 = wide("https://wide.test/visited/entry?x=1");
    const file = Buffer.alloc(chunk * 3, 0xff);
    Buffer.from(ascii).copy(file, chunk - 15);
    utf16.copy(file, chunk * 2 - 21);
    const big = "http://long.test/" + "a".repeat(200_000);
    const withBig = Buffer.concat([file, Buffer.from(big), Buffer.alloc(100, 0xff)]);
    await writeFile(join(cwd, "work", "mem.raw"), withBig);
    const out = body<UrlOut>(await tool("utf16_urls", cwd, { path: "work/mem.raw", chunk }));
    const small = out.candidates.filter((c) => !c.piece_of_a_longer_run);
    assert.deepEqual(small.map((c) => [c.encoding, c.offset, c.text]), [
      ["ascii", chunk - 15, ascii],
      ["utf16le", chunk * 2 - 21, "https://wide.test/visited/entry?x=1"],
    ]);
    const pieces = out.candidates.filter((c) => c.piece_of_a_longer_run);
    assert.ok(pieces.length >= 2, "a run past the carry is returned in pieces");
    assert.equal(pieces.map((p) => p.text).join(""), big, "every character of it is kept");
    assert.deepEqual(pieces.map((p) => p.continued), pieces.map((_, i) => i < pieces.length - 1));
    assert.equal(pieces[0].offset, chunk * 3);
    for (let i = 1; i < pieces.length; i++) assert.equal(pieces[i].offset, pieces[i - 1].offset + pieces[i - 1].length_bytes, "pieces are adjacent");
  });
});

test("utf16_urls keeps a UTF-16LE run only where it holds an anchor, applies `contains`, and counts what it filtered", async () => {
  await withCwd(async (cwd) => {
    const file = Buffer.concat([
      Buffer.alloc(50, 0xff),
      wide("Visited: someone@file:///C:/Users/x/report.docx"),
      Buffer.alloc(20, 0xff),
      wide("a long run of printable text in two byte characters that names no address at all"),
      Buffer.alloc(20, 0xff),
      wide("http://192.168.4.7/admin/panel"),
      Buffer.from("http://other.test/page-one"),
    ]);
    await writeFile(join(cwd, "work", "WebCacheV01.dat"), file);
    const all = body<UrlOut>(await tool("utf16_urls", cwd, { path: "work/WebCacheV01.dat" }));
    assert.deepEqual(all.candidates.map((c) => [c.encoding, c.text]), [
      ["ascii", "http://other.test/page-one"],
      ["utf16le", "Visited: someone@file:///C:/Users/x/report.docx"],
      ["utf16le", "http://192.168.4.7/admin/panel"],
    ], "the ASCII scan reports first, then the UTF-16LE scan; no run without an anchor is a candidate");
    const only = body<UrlOut>(await tool("utf16_urls", cwd, { path: "work/WebCacheV01.dat", contains: "192.168" }));
    assert.deepEqual(only.candidates.map((c) => c.text), ["http://192.168.4.7/admin/panel"]);
    assert.equal(only.filtered_out_by_contains, 2);
  });
});

// --- regkv ----------------------------------------------------------------------

// Its tests are in tests/pack-windows-forensics-registry.test.ts, each run against a stand-in for regipy and against the real library.

// --- evtx_query and evtx_carve -------------------------------------------------
// These tests are in tests/pack-windows-forensics-evtx.test.ts, with the stand-ins in tests/windows-stub-evtx.ts.

// --- usn_journal ----------------------------------------------------------------

/**
 * USN records by the layouts of the tool's own documentation (USN_RECORD_V2: length, version, 8-byte file and parent
 * references (entry in the low 48 bits, sequence in the high 16), Usn at 0x18, FILETIME at 0x20, reason, source, security
 * id and attributes from 0x28, name length and offset at 0x38; V3 has 16-byte references and everything after them 0x10
 * later; V4 has no name or time).
 */
function usn(version: 2 | 3 | 4, o: { name?: string; usn: bigint; entry: bigint; seq: bigint; parent: bigint; parentSeq: bigint; reason: number; source?: number; security?: number; attrs?: number; filetime?: bigint }): Buffer {
  const name = Buffer.from(o.name ?? "", "utf16le");
  const head = version === 2 ? 0x3c : version === 3 ? 0x4c : 0x40 + 32;
  let length = head + name.length;
  length += (8 - (length % 8)) % 8;
  const r = Buffer.alloc(length);
  r.writeUInt32LE(length, 0);
  r.writeUInt16LE(version, 4);
  if (version === 2) {
    r.writeBigUInt64LE(o.entry | (o.seq << 48n), 0x08);
    r.writeBigUInt64LE(o.parent | (o.parentSeq << 48n), 0x10);
    r.writeBigUInt64LE(o.usn, 0x18);
    r.writeBigInt64LE(o.filetime ?? 0n, 0x20);
    r.writeUInt32LE(o.reason, 0x28);
    r.writeUInt32LE(o.source ?? 0, 0x2c);
    r.writeUInt32LE(o.security ?? 0, 0x30);
    r.writeUInt32LE(o.attrs ?? 0, 0x34);
    r.writeUInt16LE(name.length, 0x38);
    r.writeUInt16LE(0x3c, 0x3a);
    name.copy(r, 0x3c);
  } else if (version === 3) {
    r.writeBigUInt64LE(o.entry | (o.seq << 48n), 0x08);
    r.writeBigUInt64LE(o.parent | (o.parentSeq << 48n), 0x18);
    r.writeBigUInt64LE(o.usn, 0x28);
    r.writeBigInt64LE(o.filetime ?? 0n, 0x30);
    r.writeUInt32LE(o.reason, 0x38);
    r.writeUInt32LE(o.source ?? 0, 0x3c);
    r.writeUInt32LE(o.security ?? 0, 0x40);
    r.writeUInt32LE(o.attrs ?? 0, 0x44);
    r.writeUInt16LE(name.length, 0x48);
    r.writeUInt16LE(0x4c, 0x4a);
    name.copy(r, 0x4c);
  } else {
    r.writeBigUInt64LE(o.entry | (o.seq << 48n), 0x08);
    r.writeBigUInt64LE(o.parent | (o.parentSeq << 48n), 0x18);
    r.writeBigUInt64LE(o.usn, 0x28);
    r.writeUInt32LE(o.reason, 0x30);
    r.writeUInt32LE(o.source ?? 0, 0x34);
    r.writeUInt32LE(0, 0x38);
    r.writeUInt16LE(1, 0x3c);
    r.writeUInt16LE(16, 0x3e);
    r.writeBigInt64LE(0n, 0x40);
    r.writeBigInt64LE(4096n, 0x48);
  }
  return r;
}

type UsnRow = { version: number; name: string | null; usn: number; timestamp?: string | null; timestamp_filetime?: string; file_reference: number | null; file_sequence: number | null; parent_reference: number | null; parent_sequence: number | null; source_info?: number; security_id?: number; attributes_raw?: number; reason_raw: number; offset: number };
type UsnOut = {
  records_read: number;
  record_count: number;
  records: UsnRow[];
  unrecognised_bytes: number;
  unrecognised_ranges: Array<{ offset: number; bytes: number }>;
  prefix_unrecognised_bytes: number;
  nameless_excluded_by_filter: number;
  malformed_skipped?: unknown;
};

test("usn_journal keeps the parent's sequence number, the source info, the security id and the raw attributes of v2 and v3 records, with the FILETIME exact", async () => {
  // A v2 row kept the parent reference but not its sequence, and neither version kept source, security id or the raw
  // attributes word, so a record could not be joined to a reused MFT entry.
  await withCwd(async (cwd) => {
    const v2 = usn(2, { name: "report.docx", usn: 4096n, entry: 33194n, seq: 3n, parent: 5n, parentSeq: 7n, reason: 0x100, source: 2, security: 0x55, attrs: 0x20, filetime: FILETIME_BASE });
    const v3 = usn(3, { name: "upload.aspx", usn: 4200n, entry: 40000n, seq: 2n, parent: 5n, parentSeq: 9n, reason: 0x80000200, source: 4, security: 0x66, attrs: 0x2020, filetime: FILETIME_BASE + 10_000_000n });
    await writeFile(join(cwd, "work", "J"), Buffer.concat([v2, v3, Buffer.alloc(4096)]));
    const out = body<UsnOut>(await tool("usn_journal", cwd, { path: "work/J" }));
    const [a, b] = out.records;
    assert.equal(a.parent_sequence, 7);
    assert.equal(a.parent_reference, 5);
    assert.deepEqual([a.source_info, a.security_id, a.attributes_raw], [2, 0x55, 0x20]);
    assert.equal(a.timestamp_filetime, String(FILETIME_BASE));
    assert.equal(a.timestamp, "2023-11-13T00:53:20.1234567Z");
    assert.equal(b.parent_sequence, 9);
    assert.deepEqual([b.source_info, b.security_id, b.attributes_raw], [4, 0x66, 0x2020]);
    assert.equal(b.timestamp, "2023-11-13T00:53:21.1234567Z");
  });
});

test("usn_journal counts bytes it could not read as a record, in ranges and apart from the zeros of the sparse front, and calls a V4 record excluded by a name filter what it is", async () => {
  // `skipped` counted 8-byte steps after the first record, and a name filter silently left out every V4 record,
  // which has no name.
  await withCwd(async (cwd) => {
    const page = 4096;
    const a = usn(2, { name: "a.txt", usn: 1000n, entry: 10n, seq: 1n, parent: 5n, parentSeq: 5n, reason: 0x100 });
    const v4 = usn(4, { usn: 2000n, entry: 10n, seq: 1n, parent: 5n, parentSeq: 5n, reason: 0x1 });
    const b = usn(2, { name: "b.txt", usn: 3000n, entry: 11n, seq: 1n, parent: 5n, parentSeq: 5n, reason: 0x100 });
    const junk = Buffer.alloc(24, 0xff);
    const prefixJunk = Buffer.alloc(16, 0xee);
    const journal = Buffer.concat([Buffer.alloc(page), prefixJunk, a, junk, v4, b, Buffer.alloc(page)]);
    await writeFile(join(cwd, "work", "J"), journal);
    const all = body<UsnOut>(await tool("usn_journal", cwd, { path: "work/J" }));
    assert.equal(all.records_read, 3);
    assert.equal(all.prefix_unrecognised_bytes, 16);
    assert.equal(all.unrecognised_bytes, 24);
    assert.deepEqual(all.unrecognised_ranges, [{ offset: page + 16 + a.length, bytes: 24 }]);
    assert.equal(all.malformed_skipped, undefined, "the old count of steps is gone");
    const filtered = body<UsnOut>(await tool("usn_journal", cwd, { path: "work/J", name: "\\.txt$" }));
    assert.equal(filtered.records_read, 3);
    assert.deepEqual(filtered.records.map((r) => r.name), ["a.txt", "b.txt"]);
    assert.equal(filtered.nameless_excluded_by_filter, 1, "the V4 record the filter could not match is counted");
    const withNameless = body<UsnOut>(await tool("usn_journal", cwd, { path: "work/J", name: "\\.txt$", include_nameless: true }));
    assert.deepEqual(withNameless.records.map((r) => r.version), [2, 4, 2]);
    assert.equal(withNameless.nameless_excluded_by_filter, 0);
  });
});

// --- shellbags ------------------------------------------------------------------

// Its tests are in tests/pack-windows-forensics-registry.test.ts, each run against a stand-in for regipy and against the real library.

// --- mft_records ----------------------------------------------------------------

/**
 * An $MFT record as the tool's documentation lays it out: "FILE", the update sequence array at 0x04/0x06, the
 * sequence number at 0x10, the first attribute at 0x14, flags at 0x16 (1 in use), the used and allocated sizes at 0x18
 * and 0x1C, the base record reference at 0x20 and the record number at 0x2C; a resident attribute is its type, length,
 * resident flag, name length and offset, attribute id (0x0E), content length (0x10) and offset (0x14), then the content;
 * $STANDARD_INFORMATION holds four FILETIMEs and the flags at 0x20, $FILE_NAME a parent reference, four FILETIMEs, sizes,
 * flags, the name length (0x40) and namespace (0x41) and the name from 0x42. The last two bytes of every 512-byte
 * sector hold the update sequence number, the real bytes being in the array.
 */
const MFT_TIME = 133_500_000_000_000_001n;

function mftAttr(type: number, content: Buffer, o: { id?: number; name?: string; declaredContentLength?: number } = {}): Buffer {
  const nameBytes = Buffer.from(o.name ?? "", "utf16le");
  const nameOffset = 0x18;
  let contentOffset = nameOffset + nameBytes.length;
  contentOffset += (8 - (contentOffset % 8)) % 8;
  let total = contentOffset + content.length;
  total += (8 - (total % 8)) % 8;
  const b = Buffer.alloc(total);
  b.writeUInt32LE(type, 0);
  b.writeUInt32LE(total, 4);
  b[8] = 0;
  b[9] = (o.name ?? "").length;
  b.writeUInt16LE(nameBytes.length ? nameOffset : 0, 10);
  b.writeUInt16LE(o.id ?? 0, 0x0e);
  b.writeUInt32LE(o.declaredContentLength ?? content.length, 0x10);
  b.writeUInt16LE(contentOffset, 0x14);
  nameBytes.copy(b, nameOffset);
  content.copy(b, contentOffset);
  return b;
}

const mftStandardInfo = (t: bigint, flags = 0x20): Buffer => {
  const b = Buffer.alloc(0x48);
  for (let i = 0; i < 4; i++) b.writeBigUInt64LE(t, i * 8);
  b.writeUInt32LE(flags, 0x20);
  return b;
};

function mftFileName(parent: bigint, parentSeq: bigint, name: string, t: bigint): Buffer {
  const b = Buffer.alloc(0x42 + name.length * 2);
  b.writeBigUInt64LE(parent | (parentSeq << 48n), 0);
  for (let i = 0; i < 4; i++) b.writeBigUInt64LE(t, 8 + i * 8);
  b.writeBigUInt64LE(4096n, 0x28);
  b.writeBigUInt64LE(10n, 0x30);
  b.writeUInt32LE(0x20, 0x38);
  b[0x40] = name.length;
  b[0x41] = 1;
  Buffer.from(name, "utf16le").copy(b, 0x42);
  return b;
}

function mftRecord(number: number, attrs: Buffer[], o: { sequence?: number; flags?: number; base?: bigint; endMarker?: boolean } = {}): Buffer {
  const size = 1024;
  const b = Buffer.alloc(size);
  b.write("FILE", 0, "latin1");
  const usaOffset = 0x30;
  const usaCount = size / 512 + 1;
  b.writeUInt16LE(usaOffset, 4);
  b.writeUInt16LE(usaCount, 6);
  b.writeUInt16LE(o.sequence ?? 1, 0x10);
  let first = usaOffset + usaCount * 2;
  first += (8 - (first % 8)) % 8;
  b.writeUInt16LE(first, 0x14);
  b.writeUInt16LE(o.flags ?? 1, 0x16);
  if (o.base !== undefined) b.writeBigUInt64LE(o.base, 0x20);
  b.writeUInt32LE(number, 0x2c);
  let at = first;
  for (const a of attrs) {
    a.copy(b, at);
    at += a.length;
  }
  if (o.endMarker !== false) b.writeUInt32LE(0xffffffff, at);
  b.writeUInt32LE(at + 8, 0x18);
  b.writeUInt32LE(size, 0x1c);
  const sequence = Buffer.from([0x0b, 0x00]);
  sequence.copy(b, usaOffset);
  for (let i = 1; i < usaCount; i++) {
    const end = i * 512 - 2;
    b.copy(b, usaOffset + i * 2, end, end + 2);
    sequence.copy(b, end);
  }
  return b;
}

type MftOut = {
  status: string;
  record_size: number;
  record_size_from: string;
  records_with_structural_errors: number;
  entries: Array<{
    entry: number;
    primary_name?: string;
    unreliable?: boolean;
    structural_errors?: string[];
    flags: string[];
    names: Array<{ name: string; instance: number; parent_entry: number; parent_sequence: number; created: string | null }>;
    data_streams: Array<{ name: string; instance: number; resident: boolean; real_size?: number }>;
    standard_information?: { created: string | null; instance: number };
    attribute_list_resolved?: boolean;
    base_record: number | null;
    base_sequence: number | null;
    is_extension_record?: boolean;
  }>;
  problems: Array<{ record: number; why: string }>;
  note: string;
};

test("mft_records checks every nested range against its own attribute: a $FILE_NAME whose name runs past the attribute is an error, not a decoded name", async () => {
  // Nested ranges were checked against the whole record, so a damaged length let a name be read from the bytes of the
  // attribute after it.
  await withCwd(async (cwd) => {
    const good = mftRecord(40, [mftAttr(0x10, mftStandardInfo(MFT_TIME)), mftAttr(0x30, mftFileName(5n, 5n, "ok.txt", MFT_TIME)), mftAttr(0x80, Buffer.from("hello"))]);
    // The $FILE_NAME claims a 40-character name and its content holds only the 8 characters it was built with; the
    // attribute after it is a $DATA whose bytes would complete the name if the range ran into it.
    const short = mftAttr(0x30, mftFileName(5n, 5n, "abcdefgh", MFT_TIME));
    short[0x40 + 0x18] = 40;
    const spill = mftAttr(0x80, Buffer.from("x".repeat(60), "utf16le"));
    const bad = mftRecord(41, [mftAttr(0x10, mftStandardInfo(MFT_TIME)), short, spill]);
    // A $STANDARD_INFORMATION whose content is only 16 bytes, shorter than the times it should hold.
    const stub = mftRecord(42, [mftAttr(0x10, Buffer.alloc(16)), mftAttr(0x30, mftFileName(5n, 5n, "z.txt", MFT_TIME))]);
    await writeFile(join(cwd, "work", "MFT"), Buffer.concat([good, bad, stub]));
    const out = body<MftOut>(await tool("mft_records", cwd, { path: "work/MFT" }));
    assert.equal(out.record_size, 1024);
    assert.equal(out.record_size_from, "the allocated size in the first record's header");
    const [a, b, c] = out.entries;
    assert.equal(a.unreliable, undefined);
    assert.equal(a.primary_name, "ok.txt");
    assert.equal(b.names.length, 0, "no name was decoded from a range that does not fit");
    assert.equal(b.unreliable, true);
    assert.ok((b.structural_errors ?? []).some((e) => /declares a 40-character name, which runs past its content/.test(e)), JSON.stringify(b.structural_errors));
    assert.equal(c.standard_information, undefined, "no times were read from a short $STANDARD_INFORMATION");
    assert.ok((c.structural_errors ?? []).some((e) => /\$STANDARD_INFORMATION .* shorter than the 36 it needs/.test(e)));
    assert.equal(c.names[0].name, "z.txt", "what was sound is kept");
    assert.equal(out.records_with_structural_errors, 2);
    assert.equal(out.problems.length, 2);
    assert.equal(out.status, "partial");
  });
});

test("mft_records counts a record whose update sequence fixup failed and a slot with no signature, instead of leaving them to a flag on one record and a silent skip", async () => {
  // The fixup failure was a flag on the record only, and a zeroed or damaged slot was skipped with nothing but the
  // difference between two counters to show it.
  await withCwd(async (cwd) => {
    const good = mftRecord(60, [mftAttr(0x10, mftStandardInfo(MFT_TIME)), mftAttr(0x30, mftFileName(5n, 5n, "fine.txt", MFT_TIME))]);
    const torn = mftRecord(61, [mftAttr(0x10, mftStandardInfo(MFT_TIME)), mftAttr(0x30, mftFileName(5n, 5n, "torn.txt", MFT_TIME))]);
    torn[510] = 0x99; // the last two bytes of the first sector no longer match the update sequence number
    const blank = Buffer.alloc(1024);
    const junk = Buffer.alloc(1024, 0x41);
    await writeFile(join(cwd, "work", "MFT"), Buffer.concat([good, torn, blank, junk]));
    const out = body<MftOut & { records_scanned: number; records_parsed: number; records_fixup_failed: number; slots_without_signature: number }>(
      await tool("mft_records", cwd, { path: "work/MFT" }));
    assert.equal(out.records_scanned, 4);
    assert.equal(out.records_parsed, 2);
    assert.equal(out.records_fixup_failed, 1);
    assert.equal(out.slots_without_signature, 2);
    const torn_entry = out.entries.find((e) => e.entry === 61);
    assert.ok(torn_entry && torn_entry.flags.includes("fixup_failed") && torn_entry.unreliable === true);
    assert.match(out.note, /records_fixup_failed/);
  });
});

test("mft_records says when an attribute chain does not end with its marker, gives every name and stream its instance id, and keeps the base record's sequence", async () => {
  await withCwd(async (cwd) => {
    const ads = mftRecord(50, [
      mftAttr(0x10, mftStandardInfo(MFT_TIME), { id: 0 }),
      mftAttr(0x30, mftFileName(5n, 3n, "host.txt", MFT_TIME), { id: 1 }),
      mftAttr(0x80, Buffer.from("main"), { id: 2 }),
      mftAttr(0x80, Buffer.from("MZ payload"), { id: 4, name: "payload.exe" }),
    ]);
    const listed = mftRecord(51, [mftAttr(0x10, mftStandardInfo(MFT_TIME)), mftAttr(0x20, Buffer.alloc(32)), mftAttr(0x30, mftFileName(5n, 5n, "big.bin", MFT_TIME))]);
    const extension = mftRecord(52, [mftAttr(0x80, Buffer.alloc(8), { id: 9 })], { base: 51n | (7n << 48n), flags: 1 });
    const open = mftRecord(53, [mftAttr(0x10, mftStandardInfo(MFT_TIME))], { endMarker: false });
    await writeFile(join(cwd, "work", "MFT"), Buffer.concat([ads, listed, extension, open]));
    const out = body<MftOut>(await tool("mft_records", cwd, { path: "work/MFT" }));
    const [r50, r51, r52, r53] = out.entries;
    assert.deepEqual(r50.data_streams.map((s) => [s.name, s.instance]), [["", 2], ["payload.exe", 4]]);
    assert.equal(r50.names[0].instance, 1);
    assert.equal(r50.names[0].parent_sequence, 3);
    assert.equal(r50.standard_information?.instance, 0);
    assert.ok(r51.flags.includes("has_attribute_list"));
    assert.equal(r51.attribute_list_resolved, false);
    assert.equal(r52.base_record, 51);
    assert.equal(r52.base_sequence, 7);
    assert.equal(r52.is_extension_record, true);
    assert.ok((r53.structural_errors ?? []).some((e) => /(runs out at offset \d+ without an end marker|attribute header at offset \d+ does not fit the record)/.test(e)), JSON.stringify(r53.structural_errors));
    assert.match(out.note, /\$ATTRIBUTE_LIST is not resolved and no parent path is rebuilt/);
    assert.doesNotMatch(out.note, /defensible confirmation is \$LogFile/);
  });
});

// --- extract_stream -------------------------------------------------------------

type StreamOut = {
  status: string;
  output?: string;
  size?: number;
  sha256?: string;
  image: string;
  offset_sectors: number;
  inode: string;
  entry: number;
  attribute_type: number | null;
  attribute_id: number | null;
  icat_exit_status: number;
  stderr_file: string | null;
  stderr_bytes: number;
  partial_file?: string;
  partial_bytes?: number;
  error?: string;
};

/** icat as the Sleuth Kit has it: `icat -o <sector offset> <image> <inode>` writes the stream to stdout. */
const ICAT_STUB = (body: string): string => `
# record the arguments, one to a line
printf '%s\\n' "$@" > "$ICAT_ARGS"
${body}
`;

test("extract_stream writes the stream to a named file under the run with its size and sha256, and prints none of it", async () => {
  // It printed the whole stream as base64 on stdout (a 30 second limit, no digest, no size), and a large stream
  // could not be returned at all.
  await withCwd(async (cwd, bin) => {
    await stub(bin, "icat", ICAT_STUB(`i=0; while [ $i -lt 5 ]; do head -c 1048576 /dev/zero | tr '\\0' 'A'; i=$((i+1)); done; echo "icat: warning: slack space ignored" >&2`));
    await writeFile(join(cwd, "work", "disk.raw"), Buffer.alloc(1024));
    const args = join(cwd, "icat-args");
    const run = await tool("extract_stream", cwd, { image: "work/disk.raw", inode: "168-128-4", offset: 2048, output: "work/s1/168-128-4.bin" }, { ICAT_ARGS: args }, bin);
    const out = body<StreamOut>(run);
    assert.equal(out.status, "complete");
    assert.equal(out.size, 5 * 1048576);
    const written = await readFile(join(cwd, "work", "s1", "168-128-4.bin"));
    assert.equal(written.length, 5 * 1048576);
    assert.equal(out.sha256, createHash("sha256").update(written).digest("hex"));
    assert.ok(run.stdout.length < 2000, "the answer is a record, not the bytes");
    assert.deepEqual([out.entry, out.attribute_type, out.attribute_id, out.offset_sectors], [168, 128, 4, 2048]);
    assert.equal(out.stderr_bytes > 0, true);
    assert.match(await readFile(join(cwd, out.stderr_file as string), "utf8"), /slack space ignored/);
    assert.deepEqual((await readFile(args, "utf8")).trim().split("\n"), ["-o", "2048", "work/disk.raw", "168-128-4"]);
  });
});

test("extract_stream calls a failed icat a failure: what it wrote is kept as .partial, its whole stderr is kept, and the exit is non-zero", async () => {
  await withCwd(async (cwd, bin) => {
    await stub(bin, "icat", ICAT_STUB(`printf 'partial bytes'\necho "Error looking up inode: 9999" >&2\necho "second line of the message" >&2\nexit 1`));
    await writeFile(join(cwd, "work", "disk.raw"), Buffer.alloc(1024));
    const failure = await tool("extract_stream", cwd, { image: "work/disk.raw", inode: "9999", output: "work/s1/x.bin" }, { ICAT_ARGS: join(cwd, "icat-args") }, bin);
    const out = failed(failure) as unknown as StreamOut;
    assert.equal(out.status, "failed");
    assert.equal(out.icat_exit_status, 1);
    assert.equal(out.partial_file, "work/s1/x.bin.partial");
    assert.equal(out.partial_bytes, 13);
    assert.equal(await exists(join(cwd, "work", "s1", "x.bin")), false, "no file passes for an extraction");
    assert.equal(await readFile(join(cwd, "work", "s1", "x.bin.partial"), "utf8"), "partial bytes");
    assert.equal(await readFile(join(cwd, out.stderr_file as string), "utf8"), "Error looking up inode: 9999\nsecond line of the message\n");
  });
});

test("extract_stream never overwrites a file, never writes under inputs/ or outside the run, and refuses an inode it cannot read before it runs icat", async () => {
  await withCwd(async (cwd, bin) => {
    await stub(bin, "icat", ICAT_STUB(`printf 'x'`));
    await writeFile(join(cwd, "work", "disk.raw"), Buffer.alloc(1024));
    await mkdir(join(cwd, "work", "s1"), { recursive: true });
    const env = { ICAT_ARGS: join(cwd, "icat-args") };
    await writeFile(join(cwd, "work", "s1", "taken.bin"), "evidence");
    assert.match(failed(await tool("extract_stream", cwd, { image: "work/disk.raw", inode: "5", output: "work/s1/taken.bin" }, env, bin)).error, /already exists/);
    assert.equal(await readFile(join(cwd, "work", "s1", "taken.bin"), "utf8"), "evidence");
    assert.match(failed(await tool("extract_stream", cwd, { image: "work/disk.raw", inode: "5", output: "inputs/x.bin" }, env, bin)).error, /cannot be under inputs/);
    assert.match(failed(await tool("extract_stream", cwd, { image: "work/disk.raw", inode: "5", output: "work/../inputs/y.bin" }, env, bin)).error, /cannot be under inputs/);
    assert.match(failed(await tool("extract_stream", cwd, { image: "work/disk.raw", inode: "5", output: "/tmp/outside-the-run.bin" }, env, bin)).error, /inside the run directory/);
    // A link in the run that points out of it is resolved first, and refused as the place it leads to.
    await symlink("../../../elsewhere/planted", join(cwd, "work", "s1", "link.bin"));
    assert.match(failed(await tool("extract_stream", cwd, { image: "work/disk.raw", inode: "5", output: "work/s1/link.bin" }, env, bin)).error, /inside the run directory/);
    await symlink("taken.bin", join(cwd, "work", "s1", "samedir.bin"));
    assert.match(failed(await tool("extract_stream", cwd, { image: "work/disk.raw", inode: "5", output: "work/s1/samedir.bin" }, env, bin)).error, /already exists/);
    assert.equal(await readFile(join(cwd, "work", "s1", "taken.bin"), "utf8"), "evidence", "nothing was written through the link");
    for (const inode of ["5; rm -rf /", "1-2-3-4", "abc", "-5", ""]) {
      assert.match(failed(await tool("extract_stream", cwd, { image: "work/disk.raw", inode, output: "work/s1/z.bin" }, env, bin)).error, /inode must be an address/, inode);
    }
    assert.equal(await exists(join(cwd, "icat-args")), false, "a refused call never reaches icat");
  });
});

// --- manifests ------------------------------------------------------------------

test("every windows-forensics tool manifest declares the programs its script runs, and says what it needs the engine for", async () => {
  // None of the twenty manifests had `requires`, so an image chosen from the manifests could lack the program a tool calls
  // (tests/recipe.test.sh scans only tool-library/). sigma_hunt needs ONE of two engines and declares neither: its description says so.
  const programs = ["fls", "icat", "istat", "img_stat", "mmls", "esedbexport", "yara", "vshadowinfo", "ewfexport", "sqlite3", "vol"];
  const dirs = await readdir(WIN);
  assert.equal(dirs.length, 20);
  for (const name of dirs.sort()) {
    const manifest = JSON.parse(await readFile(join(WIN, name, "manifest.json"), "utf8")) as { entry: string; requires?: string[]; description: string; use?: unknown };
    const script = await readFile(join(WIN, name, manifest.entry), "utf8");
    assert.ok(Array.isArray(manifest.requires), `${name}: requires is declared (an empty list says none)`);
    const used = programs.filter((p) => new RegExp(`["']${p}["']\\s*[,\\]]`).test(script) || new RegExp(`which\\(["']${p}["']\\)`).test(script));
    for (const p of used) assert.ok(manifest.requires?.includes(p), `${name} runs ${p} and does not declare it`);
    for (const p of manifest.requires ?? []) assert.ok(programs.includes(p), `${name}: ${p} is declared but is not a program this check knows`);
  }
  const sigma = JSON.parse(await readFile(join(WIN, "sigma_hunt", "manifest.json"), "utf8")) as { requires: string[]; description: string };
  assert.deepEqual(sigma.requires, []);
  assert.match(sigma.description, /Zircolite or Hayabusa; either is enough/);
});
