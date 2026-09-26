/**
 * Pack tools that stopped at a limit, read a sample or sliced a value keep
 * every result now: a page inline, and the whole list in a file the output
 * names. Every fixture here is built by the test itself, from the documented
 * layouts; no evidence file is read and nothing reaches the network. Where a
 * tool needs a library this host may not have (python-evtx for a chunk with
 * real BinXML, regipy for a hive, olefile for a compound file), a stub module
 * on PYTHONPATH stands in for it, the way the other suites put a stub program
 * on PATH.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmod, mkdir, readdir, readFile, stat, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { ROOT, runPy, runPySnippet, withCwd } from "./tool-library-harness.ts";

const WIN = join(ROOT, "packs", "windows-forensics", "tools");
const MEM = join(ROOT, "packs", "memory-forensics", "tools");
const ENC = join(ROOT, "packs", "encrypted-containers", "tools");
const LIB = join(ROOT, "tool-library");
const AGENT = { AGENT_ID: "s1" };

type Page = { matched: number; returned: number; truncated: boolean; all_results?: string };
type Run = { code: number | null; stdout: string; stderr: string };

async function tool(script: string, cwd: string, args: unknown, env: Record<string, string> = {}, bin?: string): Promise<Run> {
  return runPy(script, cwd, args, bin, { ...AGENT, ...env });
}

function body<T>(out: Run): T {
  assert.equal(out.code, 0, out.stderr + out.stdout);
  assert.doesNotMatch(out.stderr, /Traceback/);
  return JSON.parse(out.stdout) as T;
}

function refused(out: Run): { error: string } {
  assert.notEqual(out.code, 0, out.stdout);
  assert.doesNotMatch(out.stderr, /Traceback/);
  return JSON.parse(out.stdout) as { error: string };
}

/** The rows of the file a page names: the whole result, in order. */
async function allRows<T>(cwd: string, page: Page): Promise<T[]> {
  assert.ok(page.all_results, "the output must name the file holding the whole result");
  assert.match(page.all_results, /^work\/s1\/tool-output\/.+\.jsonl$/);
  const text = await readFile(join(cwd, page.all_results), "utf8");
  return text.trimEnd().split("\n").map((line) => JSON.parse(line) as T);
}

/** Run a Python fixture builder; its argv follows the code. */
async function build(code: string, ...args: string[]): Promise<void> {
  const out = await runPySnippet(code, args, null);
  assert.equal(out.code, 0, out.stderr);
}

async function exists(path: string): Promise<boolean> {
  return stat(path).then(() => true, () => false);
}

async function stubModule(cwd: string, files: Record<string, string>): Promise<Record<string, string>> {
  const dir = join(cwd, "pystub");
  for (const [name, text] of Object.entries(files)) {
    await mkdir(join(dir, name, ".."), { recursive: true });
    await writeFile(join(dir, name), text, "utf8");
  }
  return { PYTHONPATH: dir };
}

// --- archive_probe --------------------------------------------------------------

const ZIP_BUILDER = String.raw`
import sys, zipfile
path = sys.argv[1]
with zipfile.ZipFile(path, "w") as z:
    for i in range(7):
        z.writestr("file-%d.txt" % i, "content %d\n" % i)
data = bytearray(open(path, "rb").read())
# Mark the last three entries encrypted in the central directory, where the
# encryption flag is read from.
at = data.find(b"PK\x01\x02")
while at >= 0:
    name_len = int.from_bytes(data[at + 28:at + 30], "little")
    name = bytes(data[at + 46:at + 46 + name_len]).decode()
    if name in ("file-4.txt", "file-5.txt", "file-6.txt"):
        data[at + 8] |= 1
    at = data.find(b"PK\x01\x02", at + 4)
open(path, "wb").write(data)
`;

test("archive_probe lists every ZIP entry and counts every encrypted one past the page", async () => {
  // It listed infolist()[:limit] and counted encryption over that slice
  // only, so an archive whose encrypted members came after the first
  // `limit` entries was reported as not protected at all.
  await withCwd(async (cwd) => {
    await build(ZIP_BUILDER, join(cwd, "work", "seven.zip"));
    const out = body<Page & {
      entries: { name: string }[];
      entry_count: number;
      encrypted_entries: number;
      protected: boolean;
      schemes: string[];
    }>(await tool(join(ENC, "archive_probe", "run.py"), cwd, { path: "work/seven.zip", limit: 3 }));
    assert.deepEqual(out.entries.map((e) => e.name), ["file-0.txt", "file-1.txt", "file-2.txt"]);
    assert.equal(out.entry_count, 7);
    assert.equal(out.matched, 7);
    assert.equal(out.returned, 3);
    assert.equal(out.truncated, true);
    assert.equal(out.encrypted_entries, 3);
    assert.equal(out.protected, true);
    assert.deepEqual(out.schemes, ["ZipCrypto (legacy, weak)"]);
    const rows = await allRows<{ name: string; encrypted: boolean }>(cwd, out);
    assert.deepEqual(rows.map((r) => r.name), [0, 1, 2, 3, 4, 5, 6].map((i) => `file-${i}.txt`));
    assert.deepEqual(rows.map((r) => r.encrypted), [false, false, false, false, true, true, true]);
  });
});

test("archive_probe finds a PDF's encryption dictionary in the trailer of a file past 8 MiB", async () => {
  // It read the first 8 MiB, and a PDF names /Encrypt in its trailer, at the
  // end: a large encrypted PDF was reported as opening with nothing.
  await withCwd(async (cwd) => {
    const pdf = Buffer.concat([
      Buffer.from("%PDF-1.7\n"),
      Buffer.alloc(9 * 1024 * 1024, 0x20),
      Buffer.from("\n5 0 obj\n<< /Filter /Standard /V 5 /R 6 /P -1028 >>\nendobj\ntrailer\n<< /Encrypt 5 0 R >>\n%%EOF\n"),
    ]);
    await writeFile(join(cwd, "work", "large.pdf"), pdf);
    const out = body<{ protected: boolean; r: number; scheme: string; permissions_flags: number }>(
      await tool(join(ENC, "archive_probe", "run.py"), cwd, { path: "work/large.pdf" }),
    );
    assert.equal(out.protected, true);
    assert.equal(out.r, 6);
    assert.equal(out.scheme, "AES-256");
    assert.equal(out.permissions_flags, -1028);
  });
});

function sevenZip(header: Buffer): Buffer {
  const packed = Buffer.from("packed-stream-bytes");
  const start = Buffer.alloc(32);
  Buffer.from([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c, 0x00, 0x04]).copy(start, 0);
  start.writeBigUInt64LE(BigInt(packed.length), 12);
  start.writeBigUInt64LE(BigInt(header.length), 20);
  return Buffer.concat([start, packed, header]);
}

const AES_CODER = Buffer.from([0x06, 0xf1, 0x07, 0x01]);

test("archive_probe reads every string of a 7-Zip header, from the header itself", async () => {
  // It read strings from the first 4 KiB, which is packed data, and kept
  // ten of them. The header, with the names, is at the end of the file.
  await withCwd(async (cwd) => {
    const names = [0, 1, 2, 3, 4, 5, 6, 7].map((i) => `document-${i}.docx`);
    const plain = Buffer.concat([
      Buffer.from([0x01, 0x04, 0x06]),
      AES_CODER,
      Buffer.from([0x05, 0x11]),
      ...names.map((n) => Buffer.from(`${n}\u0000`, "utf16le")),
      Buffer.from([0x00]),
    ]);
    await writeFile(join(cwd, "work", "plain.7z"), sevenZip(plain));
    const out = body<Page & {
      header_kind: string;
      names_readable: boolean;
      protected: boolean;
      strings_in_header: string[];
      strings_in_header_count: number;
    }>(await tool(join(ENC, "archive_probe", "run.py"), cwd, { path: "work/plain.7z", limit: 3 }));
    assert.equal(out.header_kind, "plain");
    assert.equal(out.names_readable, true);
    assert.equal(out.protected, true, "an AES coder in a plain header means the data is encrypted");
    assert.deepEqual(out.strings_in_header, names.slice(0, 3));
    assert.equal(out.strings_in_header_count, 8);
    assert.deepEqual(await allRows<string>(cwd, out), names);

    // An encoded header whose coder list names AES hides the names too.
    const encoded = Buffer.concat([Buffer.from([0x17, 0x06, 0x00, 0x01, 0x09, 0x20, 0x07, 0x0b, 0x01, 0x00, 0x02, 0x24]), AES_CODER, Buffer.alloc(8)]);
    await writeFile(join(cwd, "work", "hidden.7z"), sevenZip(encoded));
    const hidden = body<{ header_kind: string; names_readable: boolean; protected: boolean }>(
      await tool(join(ENC, "archive_probe", "run.py"), cwd, { path: "work/hidden.7z" }),
    );
    assert.deepEqual([hidden.header_kind, hidden.names_readable, hidden.protected], ["encoded", false, true]);

    // A header past the end of the file is said to be missing, not guessed at.
    const whole = sevenZip(plain);
    await writeFile(join(cwd, "work", "short.7z"), whole.subarray(0, whole.length - 10));
    const short = body<{ header_problem: string; names_readable: null }>(
      await tool(join(ENC, "archive_probe", "run.py"), cwd, { path: "work/short.7z" }),
    );
    assert.match(short.header_problem, /past the end of the file/);
    assert.equal(short.names_readable, null);
  });
});

// --- evtx_carve -----------------------------------------------------------------

// python-evtx stands in for itself only with real BinXML, which is not built
// by hand here; this stub reads a record count from the chunk and renders
// each record as the event XML the tool summarises.
const EVTX_STUB = String.raw`
import struct

class _Record:
    def __init__(self, number, offset):
        self._number = number
        self._offset = offset

    def offset(self):
        return self._offset

    def xml(self):
        return ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
                '<Provider Name="Stub"/><EventID>4624</EventID><EventRecordID>%d</EventRecordID>'
                '<Channel>Stub/Operational</Channel><Computer>HOST</Computer></System>'
                '<EventData><Data Name="n">%d</Data></EventData></Event>' % (self._number, self._number))


class ChunkHeader:
    def __init__(self, buf, offset):
        self._first, self._count = struct.unpack_from("<II", buf, offset + 8)

    def verify(self):
        return True

    def records(self):
        for i in range(self._count):
            yield _Record(self._first + i, 0x200 + i * 0x100)
`;

const WINDOW = 1 << 22;

async function carveBlob(path: string): Promise<number[]> {
  // Four chunks: one after noise, one whose magic straddles the tool's 4 MiB
  // read window, one after it, and one cut short by the end of the file.
  const size = WINDOW + 3 * 65536;
  const blob = Buffer.alloc(size, 0x2e);
  const chunks: [number, number, number][] = [
    [1000, 1, 4],
    [WINDOW - 3, 5, 4],
    [WINDOW - 3 + 65536 + 100, 9, 4],
    [size - 1000, 13, 2],
  ];
  for (const [at, first, count] of chunks) {
    blob.write("ElfChnk\u0000", at, "latin1");
    blob.writeUInt32LE(first, at + 8);
    blob.writeUInt32LE(count, at + 12);
  }
  await writeFile(path, blob);
  return chunks.map(([at]) => at);
}

type Carve = Page & {
  records: { record_id: number; chunk_offset: number }[];
  record_count: number;
  chunks_found: number;
  channels: string[];
  sweep_complete: boolean;
  resume_start: number | null;
  problems: { offset: number; why: string }[];
};

test("evtx_carve keeps every record past the page and reads a chunk cut short by the end of the file", async () => {
  // It stopped at `limit` records, and a chunk running past the end of the
  // file was dropped without a word: exactly the truncated .evtx it exists
  // to read.
  await withCwd(async (cwd) => {
    const env = await stubModule(cwd, { "Evtx/__init__.py": "", "Evtx/Evtx.py": EVTX_STUB });
    const offsets = await carveBlob(join(cwd, "work", "blob.bin"));
    const out = body<Carve>(await tool(join(WIN, "evtx_carve", "run.py"), cwd, { path: "work/blob.bin", limit: 5 }, env));
    assert.equal(out.chunks_found, 4);
    assert.equal(out.record_count, 14);
    assert.equal(out.records.length, 5);
    assert.equal(out.truncated, true);
    assert.deepEqual(out.channels, ["Stub/Operational"]);
    assert.equal(out.sweep_complete, true);
    assert.equal(out.resume_start, null);
    const rows = await allRows<{ record_id: number; chunk_offset: number }>(cwd, out);
    assert.deepEqual(rows.map((r) => r.record_id), Array.from({ length: 14 }, (_, i) => i + 1));
    assert.deepEqual([...new Set(rows.map((r) => r.chunk_offset))], offsets);
    assert.ok(
      out.problems.some((p) => p.offset === offsets[3] && /runs past the end of the file/.test(p.why)),
      JSON.stringify(out.problems),
    );
  });
});

test("evtx_carve stops at chunk_limit before a chunk and names where to carry on", async () => {
  await withCwd(async (cwd) => {
    const env = await stubModule(cwd, { "Evtx/__init__.py": "", "Evtx/Evtx.py": EVTX_STUB });
    const offsets = await carveBlob(join(cwd, "work", "blob.bin"));
    const first = body<Carve>(await tool(join(WIN, "evtx_carve", "run.py"), cwd, { path: "work/blob.bin", chunk_limit: 2 }, env));
    assert.equal(first.sweep_complete, false);
    assert.equal(first.resume_start, offsets[2]);
    assert.deepEqual(first.records.map((r) => r.record_id), [1, 2, 3, 4, 5, 6, 7, 8]);
    const rest = body<Carve>(await tool(join(WIN, "evtx_carve", "run.py"), cwd, {
      path: "work/blob.bin",
      chunk_limit: 2,
      start: first.resume_start,
    }, env));
    assert.equal(rest.sweep_complete, true);
    assert.deepEqual(rest.records.map((r) => r.record_id), [9, 10, 11, 12, 13, 14]);
  });
});

// --- mft_records ----------------------------------------------------------------

const MFT_BUILDER = String.raw`
import struct, sys, datetime
EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
def ft(iso):
    dt = datetime.datetime.fromisoformat(iso).replace(tzinfo=datetime.timezone.utc)
    return int((dt - EPOCH).total_seconds()) * 10_000_000
def attr(atype, content):
    coff = 0x18
    total = coff + len(content); total += (-total) % 8
    b = bytearray(total)
    struct.pack_into("<IIBBHHH", b, 0, atype, total, 0, 0, 0, 0, 0)
    struct.pack_into("<IH", b, 0x10, len(content), coff)
    b[coff:coff + len(content)] = content
    return bytes(b)
def si(t):
    return struct.pack("<QQQQI", t, t, t, t, 0x20) + b"\x00" * 0x24
def fn(name, t):
    return (struct.pack("<Q", 5 | (5 << 48)) + struct.pack("<QQQQ", t, t, t, t)
            + struct.pack("<QQ", 4096, 10) + struct.pack("<II", 0x20, 0)
            + struct.pack("<BB", len(name), 1) + name.encode("utf-16-le"))
def fixup(b):
    usa_off, usa_count = 0x30, len(b) // 512 + 1
    struct.pack_into("<HH", b, 0x04, usa_off, usa_count)
    sig = b"\x0b\x00"
    b[usa_off:usa_off + 2] = sig
    for i in range(1, usa_count):
        end = i * 512 - 2
        b[usa_off + i * 2:usa_off + i * 2 + 2] = bytes(b[end:end + 2])
        b[end:end + 2] = sig
    return bytes(b)
def record(number, attrs, first=0x38):
    b = bytearray(1024)
    b[0:4] = b"FILE"
    struct.pack_into("<H", b, 0x10, 1)
    struct.pack_into("<HH", b, 0x14, first, 1)
    struct.pack_into("<I", b, 0x2C, number)
    off = first
    for a in attrs:
        b[off:off + len(a)] = a
        off += len(a)
    if off + 8 <= 1024:
        struct.pack_into("<I", b, off, 0xFFFFFFFF)
    struct.pack_into("<II", b, 0x18, min(off + 8, 1024), 1024)
    return fixup(b)
t = ft("2026-03-01T10:00:00")
out = b"\x00" * (1024 * 1025)          # a slice that opens with more than 1 MiB of zeroed records
for n in range(40, 47):
    out += record(n, [attr(0x10, si(t)), attr(0x30, fn("file-%d.txt" % n, t))])
# A non-resident $DATA header only 16 bytes long, ending the record: its sizes
# lie past the record's end.
broken = bytearray(16)
struct.pack_into("<IIBB", broken, 0, 0x80, 16, 1, 0)
out += record(47, [bytes(broken)], first=1008)
open(sys.argv[1], "wb").write(out)
`;

test("mft_records reads every record past the page, past a zeroed first MiB, and past a record it cannot parse", async () => {
  // It stopped at `limit`, looked for the first FILE magic in the first
  // MiB only, and a record whose attribute ran off its end raised
  // struct.error and ended the whole run with a traceback.
  await withCwd(async (cwd) => {
    await build(MFT_BUILDER, join(cwd, "work", "MFT"));
    const out = body<Page & {
      record_size: number;
      records_scanned: number;
      entries: { entry: number; primary_name: string }[];
      entry_count: number;
      problems: { record: number; offset: number; why: string }[];
      problem_count: number;
    }>(await tool(join(WIN, "mft_records", "run.py"), cwd, { path: "work/MFT", limit: 3 }));
    assert.equal(out.record_size, 1024);
    assert.equal(out.records_scanned, 1025 + 8);
    assert.deepEqual(out.entries.map((e) => e.entry), [40, 41, 42]);
    assert.equal(out.entry_count, 7);
    const rows = await allRows<{ entry: number; primary_name: string }>(cwd, out);
    assert.deepEqual(rows.map((r) => r.entry), [40, 41, 42, 43, 44, 45, 46]);
    assert.deepEqual(rows.map((r) => r.primary_name), [40, 41, 42, 43, 44, 45, 46].map((n) => `file-${n}.txt`));
    assert.equal(out.problem_count, 1);
    assert.equal(out.problems[0].record, 1025 + 7);
    assert.equal(out.problems[0].offset, (1025 + 7) * 1024);
    assert.match(out.problems[0].why, /did not parse/);
  });
});

// --- indx_carve -----------------------------------------------------------------

const INDX_BUILDER = String.raw`
import struct, sys
T = 133500000000000000
def fn(parent, name):
    b = bytearray(0x42 + 2 * len(name))
    struct.pack_into("<Q", b, 0, parent | (1 << 48))
    struct.pack_into("<QQQQ", b, 8, T, T, T, T)
    struct.pack_into("<QQ", b, 0x28, 4096, 0)      # real size 0: an entry header never reads as a name
    struct.pack_into("<I", b, 0x38, 0x20)
    b[0x40] = len(name)
    b[0x41] = 1
    b[0x42:] = name.encode("utf-16-le")
    return bytes(b)
def entry(ref, content, flags=0):
    length = 0x10 + len(content)
    length += (-length) % 8
    b = bytearray(length)
    struct.pack_into("<QHHH", b, 0, ref, length, len(content), flags)
    b[0x10:0x10 + len(content)] = content
    return bytes(b)
def block(vcn, live, slack):
    b = bytearray(4096)
    b[0:4] = b"INDX"
    usa_off, usa_count = 0x28, 9
    struct.pack_into("<HH", b, 4, usa_off, usa_count)
    struct.pack_into("<Q", b, 0x10, vcn)
    at = 0x40
    for e in live + [entry(0, b"", flags=0x02)]:
        b[at:at + len(e)] = e
        at += len(e)
    total = at - 0x18
    for e in slack:
        b[at:at + len(e)] = e
        at += len(e)
    struct.pack_into("<III", b, 0x18, 0x40 - 0x18, total, 4096 - 0x18)
    sig = b"\x07\x00"
    b[usa_off:usa_off + 2] = sig
    for i in range(1, usa_count):
        end = i * 512 - 2
        b[usa_off + i * 2:usa_off + i * 2 + 2] = bytes(b[end:end + 2])
        b[end:end + 2] = sig
    return bytes(b)
out = b""
for n in range(3):
    live = [entry(100 + i, fn(64, "live-%d-%d.txt" % (n, i))) for i in range(2)]
    # Ten-character names: a $FILE_NAME 86 bytes long, not a multiple of 8.
    slack = [entry(200 + i, fn(64, "old-%d%d.txt" % (n, i))) for i in range(3)]
    out += block(n, live, slack)
# Forty-five INDX magics with no block behind them, one every 64 bytes.
out += (b"INDX" + b"\x00" * 60) * 45
open(sys.argv[1], "wb").write(out)
`;

test("indx_carve recovers every slack entry, keeps every entry past the page and names every problem", async () => {
  // After a slack hit the walk stepped by the name's own length and lost
  // the 8-byte alignment, so every later slack entry in the block was
  // missed; it stopped at `limit`; it skipped a whole block after a magic
  // whose fixup failed; and it printed problems[:40].
  await withCwd(async (cwd) => {
    await build(INDX_BUILDER, join(cwd, "work", "I30"));
    const out = body<Page & {
      blocks: number;
      entries: { name: string; source: string }[];
      entry_count: number;
      from_slack: number;
      from_live: number;
      problems: { offset: number; why: string }[];
      problem_count: number;
      all_problems?: string;
    }>(await tool(join(WIN, "indx_carve", "run.py"), cwd, { path: "work/I30", limit: 4 }));
    assert.equal(out.entry_count, 15);
    assert.equal(out.entries.length, 4);
    assert.equal(out.from_slack, 9);
    assert.equal(out.from_live, 6);
    const rows = await allRows<{ name: string; source: string }>(cwd, out);
    assert.deepEqual(
      rows.filter((r) => r.source === "slack").map((r) => r.name),
      ["old-00.txt", "old-01.txt", "old-02.txt", "old-10.txt", "old-11.txt", "old-12.txt", "old-20.txt", "old-21.txt", "old-22.txt"],
    );
    assert.equal(rows.filter((r) => r.source === "live").length, 6);
    assert.equal(out.blocks, 3 + 45);
    assert.equal(out.problem_count, 45);
    assert.equal(out.problems.length, 40);
    const problems = await allRows<{ offset: number }>(cwd, { matched: 45, returned: 40, truncated: true, all_results: out.all_problems });
    assert.deepEqual(problems.map((p) => p.offset), Array.from({ length: 45 }, (_, i) => 3 * 4096 + i * 64));

    const slackOnly = body<{ entry_count: number; from_live: number }>(
      await tool(join(WIN, "indx_carve", "run.py"), cwd, { path: "work/I30", slack_only: true }),
    );
    assert.deepEqual([slackOnly.entry_count, slackOnly.from_live], [9, 0]);
  });
});

// --- shellbags ------------------------------------------------------------------

// regipy reads a real hive; this stub reads a JSON tree of keys and values
// with the attributes the tool uses (name, header.last_modified,
// iter_values, iter_subkeys, get_key).
const REGIPY_STUB = String.raw`
import json


class _Header:
    def __init__(self, stamp):
        self.last_modified = stamp


class _Value:
    def __init__(self, name, value):
        self.name = name
        self.value = value


class _Key:
    def __init__(self, name, spec):
        self.name = name
        self.header = _Header(spec.get("stamp", 133500000000000000))
        self._values = spec.get("values", {})
        self._subkeys = spec.get("subkeys", {})

    def iter_values(self):
        for name, value in self._values.items():
            yield _Value(name, value)

    def iter_subkeys(self):
        for name, spec in self._subkeys.items():
            yield _Key(name, spec)


class RegistryHive:
    def __init__(self, path):
        with open(path, encoding="utf-8") as fh:
            spec = json.load(fh)
        self.root = _Key(spec.get("name", "ROOT"), spec)

    def get_key(self, path):
        node = self.root
        for part in [p for p in path.split("\\") if p]:
            node = next((k for k in node.iter_subkeys() if k.name.lower() == part.lower()), None)
            if node is None:
                raise KeyError("no key %s" % path)
        return node
`;

function volumeItem(letter: string): string {
  const raw = Buffer.from([0x2f, ...Buffer.from(`${letter}:\\`, "latin1"), 0x00]);
  const size = Buffer.alloc(2);
  size.writeUInt16LE(raw.length + 2);
  return Buffer.concat([size, raw]).toString("hex");
}

function namedItem(name: string): string {
  return Buffer.concat([Buffer.from([0x20, 0x00, 0x99]), Buffer.from(name, "utf16le")]).toString("hex");
}

function mruList(slots: number[]): string {
  const b = Buffer.alloc((slots.length + 1) * 4);
  slots.forEach((s, i) => b.writeInt32LE(s, i * 4));
  b.writeInt32LE(-1, slots.length * 4);
  return b.toString("hex");
}

function bagHive(): unknown {
  const top: Record<string, unknown> = {};
  const values: Record<string, string> = { MRUListEx: mruList([3, 2, 1, 0]) };
  for (const slot of [0, 1, 2, 3]) {
    const letter = "CDEF"[slot];
    values[String(slot)] = volumeItem(letter);
    top[String(slot)] = {
      values: { 0: namedItem(`Folder-${letter}0`), 1: namedItem(`Folder-${letter}1`), MRUListEx: mruList([1, 0]) },
      subkeys: { 0: {}, 1: {} },
    };
  }
  const bag = { values, subkeys: top };
  return {
    name: "ROOT",
    subkeys: { "Local Settings": { subkeys: { Software: { subkeys: { Microsoft: { subkeys: { Windows: { subkeys: { Shell: { subkeys: { BagMRU: bag } } } } } } } } } } },
  };
}

test("shellbags walks the whole tree past the page and names the keys below max_depth", async () => {
  // It stopped the walk at `limit` entries, printed problems[:40], and a
  // key deeper than max_depth was passed over without a word.
  await withCwd(async (cwd) => {
    const env = await stubModule(cwd, { "regipy/__init__.py": "", "regipy/registry.py": REGIPY_STUB });
    await writeFile(join(cwd, "work", "UsrClass.dat"), JSON.stringify(bagHive()), "utf8");
    const out = body<Page & {
      entries: { path: string; depth: number }[];
      entry_count: number;
      recovered_by_strings: number;
      not_walked_below_max_depth: unknown[];
      problem_count: number;
    }>(await tool(join(WIN, "shellbags", "run.py"), cwd, { hive: "work/UsrClass.dat", limit: 5 }, env));
    assert.equal(out.entry_count, 12);
    assert.equal(out.entries.length, 5);
    assert.equal(out.recovered_by_strings, 8, "counted over every entry, not the page");
    assert.deepEqual(out.not_walked_below_max_depth, []);
    assert.equal(out.problem_count, 0);
    const rows = await allRows<{ path: string; depth: number; mru_position: number | null }>(cwd, out);
    assert.deepEqual(rows.map((r) => r.path), [
      "C:", "C:\\Folder-C0", "C:\\Folder-C1",
      "D:", "D:\\Folder-D0", "D:\\Folder-D1",
      "E:", "E:\\Folder-E0", "E:\\Folder-E1",
      "F:", "F:\\Folder-F0", "F:\\Folder-F1",
    ]);
    assert.equal(rows[9].mru_position, 0, "slot 3 was browsed last");

    const shallow = body<{ entry_count: number; not_walked_below_max_depth: { key: string; depth: number; subkeys: number }[] }>(
      await tool(join(WIN, "shellbags", "run.py"), cwd, { hive: "work/UsrClass.dat", max_depth: 1 }, env),
    );
    assert.equal(shallow.entry_count, 4);
    assert.deepEqual(
      shallow.not_walked_below_max_depth.map((k) => [k.key.split("\\").slice(-2).join("\\"), k.depth, k.subkeys]),
      [["BagMRU\\0", 2, 2], ["BagMRU\\1", 2, 2], ["BagMRU\\2", 2, 2], ["BagMRU\\3", 2, 2]],
    );
  });
});

// --- jumplist -------------------------------------------------------------------

const LNK_MAGIC = Buffer.from("4c0000000114020000000000c000000000000046", "hex");

function customDestinations(tag: string, count: number): { file: Buffer; payloads: Buffer[] } {
  const payloads = Array.from({ length: count }, (_, i) => Buffer.concat([LNK_MAGIC, Buffer.from(`${tag}-link-${i}-`.padEnd(40 + i, "x"))]));
  return { file: Buffer.concat([Buffer.from([2, 0, 0, 0]), ...payloads]), payloads };
}

type JumpFile = Page & {
  file: string;
  links: { written_to?: string; stream?: string; path?: string }[];
  link_count: number;
  links_truncated?: boolean;
  entries?: unknown[];
  application_id?: string;
};

test("jumplist writes and keeps every link structure past the page", async () => {
  // It stopped at `limit` links, so the links after it were neither
  // returned nor written to out_dir for lnk_parse.
  await withCwd(async (cwd) => {
    const { file, payloads } = customDestinations("a", 7);
    await writeFile(join(cwd, "work", "5f7b5f1e01b83767.customDestinations-ms"), file);
    const out = body<{ files: JumpFile[] }>(await tool(join(WIN, "jumplist", "run.py"), cwd, {
      path: "work/5f7b5f1e01b83767.customDestinations-ms",
      out_dir: "work/s1/links",
      limit: 3,
    }));
    const one = out.files[0];
    assert.equal(one.links.length, 3);
    assert.equal(one.link_count, 7);
    assert.equal(one.links_truncated, true);
    const rows = await allRows<{ written_to: string }>(cwd, one);
    assert.equal(rows.length, 7);
    for (const [i, row] of rows.entries()) {
      assert.match(row.written_to, /^work\/s1\/links\//);
      assert.deepEqual(await readFile(join(cwd, row.written_to)), payloads[i]);
    }
  });
});

test("jumplist never overwrites a link written from another jump list of the same name", async () => {
  // Two users' folders hold a jump list with the same application id; the
  // second user's links were written over the first's.
  await withCwd(async (cwd) => {
    const a = customDestinations("userA", 2);
    const b = customDestinations("userB", 2);
    for (const [user, list] of [["userA", a], ["userB", b]] as const) {
      await mkdir(join(cwd, "work", "lists", user), { recursive: true });
      await writeFile(join(cwd, "work", "lists", user, "5f7b5f1e01b83767.customDestinations-ms"), list.file);
    }
    const out = body<{ files: JumpFile[] }>(await tool(join(WIN, "jumplist", "run.py"), cwd, {
      path: "work/lists",
      out_dir: "work/s1/links",
    }));
    const written = out.files.flatMap((f) => f.links.map((l) => l.written_to as string));
    assert.equal(new Set(written).size, 4);
    const contents = await Promise.all(written.map((w) => readFile(join(cwd, w), "hex")));
    assert.deepEqual(contents.sort(), [...a.payloads, ...b.payloads].map((p) => p.toString("hex")).sort());
    assert.equal((await readdir(join(cwd, "work", "s1", "links"))).length, 4);

    // Run again: the same bytes land on the same files, no new copies.
    const again = body<{ files: JumpFile[] }>(await tool(join(WIN, "jumplist", "run.py"), cwd, { path: "work/lists", out_dir: "work/s1/links" }));
    assert.deepEqual(again.files.flatMap((f) => f.links.map((l) => l.written_to)), written);
    assert.equal((await readdir(join(cwd, "work", "s1", "links"))).length, 4);
  });
});

test("jumplist refuses an out_dir under inputs/ or outside the run directory", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "x.customDestinations-ms"), customDestinations("x", 1).file);
    for (const outDir of ["inputs/links", "work/../inputs/links", "../escaped-links", "/tmp", "."]) {
      const r = refused(await tool(join(WIN, "jumplist", "run.py"), cwd, { path: "work/x.customDestinations-ms", out_dir: outDir }));
      assert.match(r.error, /out_dir (cannot be under inputs|must be a directory inside the run directory)/, outDir);
    }
    assert.equal(await exists(join(cwd, "inputs", "links")), false);
    assert.equal(await exists(join(cwd, "..", "escaped-links")), false);
  });
});

// olefile reads a compound file; this stub reads a JSON map of stream names
// to hex, which is all read_automatic asks of it.
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

    def openstream(self, name):
        return _Stream(bytes.fromhex(self._streams[name]))

    def close(self):
        pass
`;

function destList(paths: string[]): Buffer {
  const header = Buffer.alloc(32);
  header.writeUInt32LE(3, 0);
  header.writeUInt32LE(paths.length, 4);
  const entries = paths.map((p, i) => {
    const b = Buffer.alloc(118 + p.length * 2 + 4);
    b.write("WIN-HOST", 0x48, "latin1");
    b.writeUInt32LE(i + 1, 0x58);
    b.writeUInt32LE(1, 0x64);
    b.writeInt32LE(-1, 0x70);
    b.writeUInt16LE(p.length, 0x74);
    b.write(p, 118, "utf16le");
    return b;
  });
  return Buffer.concat([header, ...entries]);
}

test("jumplist keeps every stream of an automaticDestinations-ms past the page", async () => {
  await withCwd(async (cwd) => {
    const env = await stubModule(cwd, { "olefile.py": OLEFILE_STUB });
    const paths = [1, 2, 3, 4, 5, 6].map((i) => `C:\\Users\\a\\Documents\\report-${i}.docx`);
    const streams: Record<string, string> = { DestList: destList(paths).toString("hex") };
    for (let i = 1; i <= 6; i++) streams[i.toString(16)] = Buffer.concat([LNK_MAGIC, Buffer.from(`auto-${i}`)]).toString("hex");
    await writeFile(join(cwd, "work", "1b4dd67f29cb1962.automaticDestinations-ms"), JSON.stringify(streams), "utf8");
    const out = body<{ files: JumpFile[] }>(await tool(join(WIN, "jumplist", "run.py"), cwd, {
      path: "work/1b4dd67f29cb1962.automaticDestinations-ms",
      out_dir: "work/s1/auto",
      limit: 2,
    }, env));
    const one = out.files[0];
    assert.equal(one.application_id, "1b4dd67f29cb1962");
    assert.equal(one.links.length, 2);
    assert.equal(one.link_count, 6);
    assert.equal((one.entries as unknown[]).length, 6);
    const rows = await allRows<{ stream: string; path: string; written_to: string }>(cwd, one);
    assert.deepEqual(rows.map((r) => r.path), paths);
    assert.equal((await readdir(join(cwd, "work", "s1", "auto"))).length, 6);
  });
});

// --- lnk_parse ------------------------------------------------------------------

const LNK_BUILDER = String.raw`
import struct, sys
CLSID = bytes.fromhex("0114020000000000c000000000000046")
def block(sig, payload):
    return struct.pack("<II", 8 + len(payload), sig) + payload
def lnk(name):
    h = bytearray(0x4C)
    struct.pack_into("<I", h, 0, 0x4C)
    h[4:20] = CLSID
    struct.pack_into("<I", h, 0x14, 0x04 | 0x80)          # HasName, IsUnicode
    body = struct.pack("<H", len(name)) + name.encode("utf-16-le")
    icon = block(0xA0000007, b"%SystemRoot%\\icons.dll".ljust(260, b"\x00")
                 + "%SystemRoot%\\icons.dll".encode("utf-16-le").ljust(520, b"\x00"))
    far = block(0xA0000009, b"\x00" * 9000
                + "BeyondTheFirstWindow\x00SecondString\x00\x00".encode("utf-16-le"))
    return bytes(h) + body + icon + far + b"\x00\x00\x00\x00"
name = "LongName-" + "abcdefghij" * 30
one = lnk(name)
open(sys.argv[1], "wb").write(one)
junk = b"\x01" * 100
open(sys.argv[2], "wb").write(junk + one + junk[:50] + lnk(name + "-2") + junk[:50] + lnk(name + "-3") + junk)
`;

type Lnk = {
  ok: boolean;
  name: string;
  utf16_strings: string[];
  structure_complete: boolean;
  bytes_read: number;
  extra: { sig: string; hex?: string; icon_env_ascii?: string; icon_env_u16?: string }[];
};

test("lnk_parse reads every UTF-16 string whole, past the first 8 KiB, and a whole icon block", async () => {
  // Strings were cut at 256 characters, the sweep stopped at 8192 bytes,
  // the character after a string's NUL was skipped, and the icon
  // environment block was reported as its first 32 bytes.
  await withCwd(async (cwd) => {
    await build(LNK_BUILDER, join(cwd, "work", "one.lnk"), join(cwd, "work", "dump.bin"));
    const name = "LongName-" + "abcdefghij".repeat(30);
    const out = body<Lnk>(await tool(join(WIN, "lnk_parse", "run.py"), cwd, { path: "work/one.lnk", size: 16384 }));
    assert.equal(out.ok, true);
    assert.equal(out.name, name);
    assert.ok(out.utf16_strings.some((s) => s.includes(name)), "the 309-character name is read whole");
    assert.ok(out.utf16_strings.includes("BeyondTheFirstWindow"), "a string past 8192 bytes is found");
    assert.ok(out.utf16_strings.includes("SecondString"), "the next string keeps its first character");
    assert.equal(out.structure_complete, true);
    const icon = out.extra.find((e) => e.sig === "0xa0000007");
    assert.ok(icon);
    assert.equal(icon.hex?.length, (8 + 260 + 520) * 2);
    assert.equal(icon.icon_env_ascii, "%SystemRoot%\\icons.dll");
    assert.equal(icon.icon_env_u16, "%SystemRoot%\\icons.dll");

    // Read short, the structure is said to run past what was read.
    const short = body<Lnk>(await tool(join(WIN, "lnk_parse", "run.py"), cwd, { path: "work/one.lnk" }));
    assert.equal(short.bytes_read, 4096);
    assert.equal(short.structure_complete, false);
  });
});

test("lnk_parse scans every link whole, each up to the next header, and keeps the ones past the page", async () => {
  // Each hit was cut to 2048 bytes, so a link's later blocks and strings
  // were lost without a word.
  await withCwd(async (cwd) => {
    await build(LNK_BUILDER, join(cwd, "work", "one.lnk"), join(cwd, "work", "dump.bin"));
    const size = (await stat(join(cwd, "work", "dump.bin"))).size;
    const out = body<Page & { count: number; hits: Lnk[]; bytes_read: number }>(
      await tool(join(WIN, "lnk_parse", "run.py"), cwd, { dump: "work/dump.bin", size, scan: true, max: 2 }),
    );
    assert.equal(out.count, 3);
    assert.equal(out.hits.length, 2);
    assert.equal(out.bytes_read, size);
    const rows = await allRows<Lnk>(cwd, out);
    assert.equal(rows.length, 3);
    for (const row of rows) {
      assert.equal(row.structure_complete, true);
      assert.ok(row.utf16_strings.includes("BeyondTheFirstWindow"));
    }
    assert.deepEqual(rows.map((r) => r.name.slice(-2)), ["ij", "-2", "-3"]);
  });
});

// --- mem_profile ----------------------------------------------------------------

test("mem_profile reads a 64-bit crash dump's physical-memory descriptor at its padded offset", async () => {
  // _PHYSICAL_MEMORY_DESCRIPTOR64 is NumberOfRuns (4 bytes), 4 bytes of
  // padding, NumberOfPages (8), then the runs at 0x98. Reading it unpadded
  // takes the padding for the page count and every run from the wrong place.
  await withCwd(async (cwd) => {
    const head = Buffer.alloc(0x2000);
    head.write("PAGEDU64", 0, "latin1");
    head.writeUInt32LE(10, 0x08);
    head.writeUInt32LE(19041, 0x0c);
    head.writeUInt32LE(2, 0x88);
    head.writeUInt32LE(0xdeadbeef, 0x8c);
    head.writeBigUInt64LE(0x180n, 0x90);
    head.writeBigUInt64LE(0x1n, 0x98);
    head.writeBigUInt64LE(0x100n, 0xa0);
    head.writeBigUInt64LE(0x200n, 0xa8);
    head.writeBigUInt64LE(0x80n, 0xb0);
    head.writeUInt32LE(1, 0xf98);
    await writeFile(join(cwd, "work", "memory.dmp"), head);
    const out = body<{ container: Record<string, unknown>; notes: string[] }>(
      await tool(join(MEM, "mem_profile", "run.py"), cwd, { path: "work/memory.dmp", scan_mb: 1 }),
    );
    const c = out.container;
    assert.equal(c.format, "Windows crash dump");
    assert.equal(c.bits, 64);
    assert.equal(c.header_problem, undefined);
    assert.equal(c.run_count, 2);
    assert.equal(c.pages_total, 0x180);
    assert.equal(c.runs_pages_total, 0x180);
    assert.deepEqual(c.memory_runs, [
      { start_page: 1, pages: 0x100, start_byte: 0x1000, bytes: 0x100000 },
      { start_page: 0x200, pages: 0x80, start_byte: 0x200000, bytes: 0x80000 },
    ]);
    assert.equal(c.contiguous, false);
    assert.ok(out.notes.some((n) => /not contiguous: 2 memory runs/.test(n)));
  });
});

// --- mem_carve ------------------------------------------------------------------

const CARVE_WINDOW = 1 << 22;

test("mem_carve neither double-counts nor loses a hit at its 4 MiB block boundary", async () => {
  // The last bytes of each block are searched again with the next one, so a
  // signature split across the boundary is found; one wholly inside those
  // bytes must not be reported twice.
  await withCwd(async (cwd) => {
    const blob = Buffer.alloc(2 * CARVE_WINDOW + 64);
    blob.write("regf", CARVE_WINDOW - 14, "latin1");        // inside the overlap, not at its edge
    blob.write("FILE0", CARVE_WINDOW - 5, "latin1");        // ends exactly at the boundary
    blob.write("ElfChnk\u0000", 2 * CARVE_WINDOW - 3, "latin1"); // straddles the second boundary
    await writeFile(join(cwd, "work", "memory.raw"), blob);
    const out = body<{
      hits: { kind: string; offset: number }[];
      hit_count: number;
      by_kind: Record<string, number>;
      complete_results: string;
      preview_limited: boolean;
    }>(await tool(join(MEM, "mem_carve", "run.py"), cwd, { path: "work/memory.raw", results_to: "work/s1/hits.jsonl" }));
    assert.deepEqual(out.hits.map((h) => [h.kind, h.offset]), [
      ["registry hive", CARVE_WINDOW - 14],
      ["MFT record", CARVE_WINDOW - 5],
      ["event log chunk", 2 * CARVE_WINDOW - 3],
    ]);
    assert.equal(out.hit_count, 3);
    assert.deepEqual(out.by_kind, { "registry hive": 1, "MFT record": 1, "event log chunk": 1 });
    const lines = (await readFile(join(cwd, "work", "s1", "hits.jsonl"), "utf8")).trimEnd().split("\n");
    assert.equal(lines.length, 3);

    // One kind alone has a shorter overlap; the split signature is still found once.
    const one = body<{ hit_count: number; hits: { offset: number }[] }>(
      await tool(join(MEM, "mem_carve", "run.py"), cwd, { path: "work/memory.raw", kinds: ["event log chunk"] }),
    );
    assert.deepEqual(one.hits.map((h) => h.offset), [2 * CARVE_WINDOW - 3]);
    assert.equal(one.hit_count, 1);

    // A bounded preview keeps every hit in the file it names.
    const preview = body<{ hits: unknown[]; hit_count: number; preview_limited: boolean; complete_results: string }>(
      await tool(join(MEM, "mem_carve", "run.py"), cwd, { path: "work/memory.raw", limit: 1, results_to: "work/s1/all.jsonl" }),
    );
    assert.equal(preview.hits.length, 1);
    assert.equal(preview.hit_count, 3);
    assert.equal(preview.preview_limited, true);
    assert.equal((await readFile(preview.complete_results, "utf8")).trimEnd().split("\n").length, 3);
  });
});

test("mem_carve refuses an output path outside work/<id>/", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "inputs", "memory.raw"), Buffer.concat([Buffer.alloc(100), Buffer.from("regf"), Buffer.alloc(100)]));
    const cases: [Record<string, unknown>, RegExp][] = [
      [{ results_to: "../outside.jsonl" }, /output must stay inside the run directory/],
      [{ results_to: "/tmp/outside.jsonl" }, /output must stay inside the run directory/],
      [{ results_to: "inputs/hits.jsonl" }, /under your own work\/<your id>\//],
      [{ results_to: "work/../inputs/hits.jsonl" }, /under your own work\/<your id>\//],
      [{ results_to: "work/hits.jsonl" }, /inside work\/<your id>\/, not work\/ itself/],
      [{ extract_to: "../carved" }, /output must stay inside the run directory/],
      [{ extract_to: "inputs/carved" }, /under your own work\/<your id>\//],
      [{ limit: 5 }, /results_to is required/],
    ];
    for (const [extra, message] of cases) {
      const r = refused(await tool(join(MEM, "mem_carve", "run.py"), cwd, { path: "inputs/memory.raw", ...extra }));
      assert.match(r.error, message, JSON.stringify(extra));
    }
    assert.equal(await exists(join(cwd, "..", "outside.jsonl")), false);
    assert.equal(await exists(join(cwd, "inputs", "hits.jsonl")), false);
    assert.equal(await exists(join(cwd, "inputs", "carved")), false);
    assert.equal(await exists(join(cwd, "work", "hits.jsonl")), false);
  });
});

// --- mem_fs ---------------------------------------------------------------------

test("mem_fs refuses a mount outside work/<id>/ before it looks for MemProcFS", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "inputs", "memory.raw"), Buffer.alloc(4096));
    await mkdir(join(cwd, "work", "s1"), { recursive: true });
    await symlink(join(cwd, "inputs"), join(cwd, "work", "s1", "to-inputs"));
    const cases: [string, RegExp][] = [
      [".", /not the run directory itself/],
      ["../mnt", /mount must stay inside the run directory/],
      ["/tmp/mnt", /mount must stay inside the run directory/],
      ["inputs/mnt", /under your own work\/<your id>\//],
      ["work", /under your own work\/<your id>\//],
      ["work/mnt", /inside work\/<your id>\/, not work\/ itself/],
      ["work/../inputs/mnt", /under your own work\/<your id>\//],
      ["work/s1/to-inputs/mnt", /under your own work\/<your id>\//],
    ];
    for (const [mount, message] of cases) {
      const r = refused(await tool(join(MEM, "mem_fs", "run.py"), cwd, { path: "inputs/memory.raw", mount }));
      assert.match(r.error, message, mount);
    }
    assert.equal(await exists(join(cwd, "inputs", "mnt")), false);
    assert.equal(await exists(join(cwd, "work", "mnt")), false);
    assert.equal(await exists(join(cwd, "..", "mnt")), false);

    // A mount under work/<id>/ passes the check and goes on to MemProcFS
    // (not on this host's PATH, or unable to read an image of zeros).
    const r = await tool(join(MEM, "mem_fs", "run.py"), cwd, { path: "inputs/memory.raw", mount: "work/s1/mem", timeout_seconds: 10 });
    const answer = JSON.parse(r.stdout) as { error?: string };
    assert.doesNotMatch(answer.error ?? "", /mount must/);
  });
});

// --- evtx_query, file_carver, sigscan_e01 (tool-library) ----------------------

const EVTX_BUILDER = String.raw`
import struct, sys
def header(chunks):
    h = bytearray(4096)
    h[0:8] = b"ElfFile\x00"
    struct.pack_into("<QQQIHHHH", h, 8, 0, chunks - 1, 1, 0x80, 1, 3, 0x1000, chunks)
    return bytes(h)
def record(number, size):
    r = bytearray(size)
    struct.pack_into("<IIQQ", r, 0, 0x2A2A, size, number, 0)
    r[0x18:0x28] = b"\xff" * 16                    # not BinXML
    struct.pack_into("<I", r, size - 4, size)
    return bytes(r)
def chunk(first, next_offset):
    c = bytearray(65536)
    c[0:8] = b"ElfChnk\x00"
    c[0x200:0x200 + len(first)] = first
    struct.pack_into("<I", c, 0x28, 0x80)
    struct.pack_into("<I", c, 0x30, next_offset)
    return bytes(c)
# Chunk one: an ordinary record whose content does not parse. Chunk two, the
# last: a record whose length sends the next one past the end of the file,
# with a next-record offset that says to keep going.
one = chunk(record(1, 0x30), 0x230)
two = chunk(record(2, 0x10000 - 0x200), 0xFFFFFFFF)
open(sys.argv[1], "wb").write(header(2) + one + two)
`;

test("evtx_query answers a malformed record chain with an error row and keeps the rows before it", async (t) => {
  // A record length pointing past the end of the file raised inside
  // python-evtx's record iterator, outside the tool's per-record handler:
  // a traceback, and nothing returned at all, not even the earlier rows.
  const probe = await runPySnippet("import Evtx", [], null);
  if (probe.code !== 0) {
    t.skip("python-evtx is not installed on this host");
    return;
  }
  await withCwd(async (cwd) => {
    await build(EVTX_BUILDER, join(cwd, "work", "broken.evtx"));
    const out = body<{ count: number; events: { parse_error?: string; chunk_offset?: number; record_offset?: number }[] }>(
      await tool(join(LIB, "evtx_query", "run.py"), cwd, { path: "work/broken.evtx" }),
    );
    assert.equal(out.count, 3);
    assert.equal(out.events.length, 3);
    assert.ok(out.events.every((e) => e.parse_error), JSON.stringify(out.events));
    assert.deepEqual(out.events.map((e) => e.record_offset ?? null), [4096 + 0x200, 4096 + 65536 + 0x200, null]);
    assert.equal(out.events[2].chunk_offset, 4096 + 65536);
    assert.match(out.events[2].parse_error ?? "", /record chain of this chunk broke/);
  });
});

const SQLITE_BUILDER = String.raw`
import sqlite3, sys, os
path = sys.argv[1]
db = sqlite3.connect(path)
db.execute("PRAGMA page_size = 1024")
db.execute("CREATE TABLE t (v TEXT)")
db.executemany("INSERT INTO t VALUES (?)", [("row %d " % i + "x" * 200,) for i in range(40)])
db.commit()
db.close()
data = open(path, "rb").read()
open(sys.argv[2], "wb").write(b"\x00" * 1000 + data + b"\xAA" * 5000)
`;

test("file_carver refuses a carve whose format size exceeds max_size instead of cutting it", async () => {
  await withCwd(async (cwd) => {
    await build(SQLITE_BUILDER, join(cwd, "work", "t.db"), join(cwd, "work", "blob.bin"));
    const db = await readFile(join(cwd, "work", "t.db"));
    assert.ok(db.length > 4096, `the database must span pages, got ${db.length}`);
    const script = join(LIB, "file_carver", "run.py");
    const r = await tool(script, cwd, { path: "work/blob.bin", offset: 1000, sig_type: "SQLite", max_size: 4096, output: "work/s1/carved.db" });
    const answer = refused(r) as { error: string; required_size: number; max_size: number };
    assert.match(answer.error, /complete file is larger than max_size/);
    assert.equal(answer.required_size, db.length);
    assert.equal(answer.max_size, 4096);
    assert.equal(await exists(join(cwd, "work", "s1", "carved.db")), false, "no partial file is written");

    const whole = body<{ ok: boolean; size: number; sha256: string }>(
      await tool(script, cwd, { path: "work/blob.bin", offset: 1000, sig_type: "SQLite", max_size: db.length, output: "work/s1/carved.db" }),
    );
    assert.equal(whole.size, db.length);
    assert.equal(whole.sha256, createHash("sha256").update(db).digest("hex"));
    assert.deepEqual(await readFile(join(cwd, "work", "s1", "carved.db")), db);
  });
});

test("sigscan_e01 names sector zero as unread instead of silently moving the start", async () => {
  // TSK img_cat will not read sector zero. The scan continues at byte 512,
  // and the first sector is listed as an unread range, so "no hit there"
  // is never claimed for bytes nobody read.
  await withCwd(async (cwd, bin) => {
    const image = Buffer.alloc(2048, 0x2e);
    image.write("NEEDLE", 100, "latin1");
    image.write("NEEDLE", 700, "latin1");
    await writeFile(join(cwd, "inputs", "disk.raw"), image);
    await writeFile(join(bin, "img_stat"), "#!/bin/sh\necho 'Size of data in bytes: 2048'\n", "utf8");
    await writeFile(
      join(bin, "img_cat"),
      String.raw`#!/usr/bin/env python3
import sys
args = sys.argv[1:]
first, last = int(args[args.index("-s") + 1]), int(args[args.index("-e") + 1])
if first < 1:
    sys.exit("img_cat: sector 0 cannot be read")
with open(args[-1], "rb") as fh:
    fh.seek(first * 512)
    sys.stdout.buffer.write(fh.read((last - first + 1) * 512))
`,
      "utf8",
    );
    await chmod(join(bin, "img_stat"), 0o755);
    await chmod(join(bin, "img_cat"), 0o755);
    const out = body<{
      start: number;
      scan_start: number;
      hits: { offset: number }[];
      hit_count: number;
      unread_ranges: { start: number; end: number; stderr: string }[];
      unread_range_count: number;
      reached_end: boolean;
    }>(await tool(join(LIB, "sigscan_e01", "run.py"), cwd, { image: "inputs/disk.raw", needle_ascii: "NEEDLE", start: 0 }, {}, bin));
    assert.equal(out.start, 0);
    assert.equal(out.scan_start, 512);
    assert.equal(out.unread_range_count, 1);
    assert.equal(out.unread_ranges[0].start, 0);
    assert.equal(out.unread_ranges[0].end, 512);
    assert.match(out.unread_ranges[0].stderr, /sector zero/);
    assert.deepEqual(out.hits.map((h) => h.offset), [700], "the needle in sector zero is not claimed as scanned");
    assert.equal(out.hit_count, 1);
    assert.equal(out.reached_end, true);
  });
});
