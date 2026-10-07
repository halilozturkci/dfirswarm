/**
 * The file-system tools of the windows-forensics pack (mft_records, indx_carve, usn_journal, recyclebin_i) on the inputs
 * that used to give a complete answer with nothing in it, a silent drop, or a hang. Fixtures follow the layouts: an $MFT
 * record is "FILE", an update sequence array at 0x04/0x06, the first attribute at 0x14, flags at 0x16, the used and
 * allocated sizes at 0x18 and 0x1C and the record number at 0x2C, its attributes after it, and the last two bytes of each
 * 512-byte sector replaced by the update sequence number; an INDX block holds a node header at 0x18 and index entries
 * (MFT reference, entry length, key length, flags, the $FILE_NAME key at 0x10); a USN record starts with its length and
 * major and minor version; a $I record is header, size, FILETIME, character count and a UTF-16LE path.
 *
 * Red check: WINDOWS_PACK_TOOLS=<a copy of the tools before the fixes> node --test tests/pack-windows-forensics-fs.test.ts
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmod, closeSync, mkdir, openSync, symlink, writeFile } from "node:fs";
import { test } from "node:test";
import { join } from "node:path";
import { promisify } from "node:util";
import { withCwd } from "./tool-library-harness.ts";
import { body, failed, tool, u16z } from "./windows-pack-harness.ts";

const fsWrite = promisify(writeFile);
const fsMkdir = promisify(mkdir);
const fsSymlink = promisify(symlink);
const fsChmod = promisify(chmod);
const isRoot = typeof process.getuid === "function" && process.getuid() === 0;

// --- $MFT -----------------------------------------------------------------------

const TIME = 133_500_000_000_000_001n;

function attr(type: number, content: Buffer): Buffer {
  let contentOffset = 0x18;
  let total = contentOffset + content.length;
  total += (8 - (total % 8)) % 8;
  const b = Buffer.alloc(total);
  b.writeUInt32LE(type, 0);
  b.writeUInt32LE(total, 4);
  b.writeUInt32LE(content.length, 0x10);
  b.writeUInt16LE(contentOffset, 0x14);
  content.copy(b, contentOffset);
  return b;
}

function standardInfo(): Buffer {
  const b = Buffer.alloc(0x48);
  for (let i = 0; i < 4; i++) b.writeBigUInt64LE(TIME, i * 8);
  return b;
}

function fileName(parent: bigint, name: string): Buffer {
  const b = Buffer.alloc(0x42 + name.length * 2);
  b.writeBigUInt64LE(parent | (5n << 48n), 0);
  for (let i = 0; i < 4; i++) b.writeBigUInt64LE(TIME, 8 + i * 8);
  b[0x40] = name.length;
  b[0x41] = 1;
  Buffer.from(name, "utf16le").copy(b, 0x42);
  return b;
}

function record(number: number, name: string, o: { used?: number } = {}): Buffer {
  const size = 1024;
  const b = Buffer.alloc(size);
  b.write("FILE", 0, "latin1");
  const usaOffset = 0x30;
  b.writeUInt16LE(usaOffset, 4);
  b.writeUInt16LE(3, 6);
  b.writeUInt16LE(1, 0x10);
  b.writeUInt16LE(0x38, 0x14);
  b.writeUInt16LE(1, 0x16);
  b.writeUInt32LE(number, 0x2c);
  let at = 0x38;
  for (const a of [attr(0x10, standardInfo()), attr(0x30, fileName(5n, name))]) {
    a.copy(b, at);
    at += a.length;
  }
  b.writeUInt32LE(0xffffffff, at);
  b.writeUInt32LE(o.used ?? at + 8, 0x18);
  b.writeUInt32LE(size, 0x1c);
  const sequence = Buffer.from([0x0b, 0x00]);
  sequence.copy(b, usaOffset);
  for (let i = 1; i < 3; i++) {
    const end = i * 512 - 2;
    b.copy(b, usaOffset + i * 2, end, end + 2);
    sequence.copy(b, end);
  }
  return b;
}

type MftOut = {
  status: string;
  records_scanned: number;
  records_parsed: number;
  slots_zeroed: number;
  slots_unrecognised: number;
  slots_without_signature: number;
  alignment_offset: number;
  trailing_bytes?: number;
  entries: Array<{ entry: number; primary_name?: string; unreliable?: boolean; structural_errors?: string[] }>;
  problems: Array<{ offset: number; why: string }>;
  problem_count: number;
};

test("mft_records reads a file that does not begin on a record boundary at its own alignment, and says so", async () => {
  // 512 bytes that are not records, then two records: slots counted from byte 0 matched nothing and the answer was
  // complete with no record in it.
  await withCwd(async (cwd) => {
    await fsWrite(join(cwd, "work", "MFT"), Buffer.concat([Buffer.alloc(512), record(40, "a.txt"), record(41, "b.txt")]));
    const out = body<MftOut>(await tool("mft_records", cwd, { path: "work/MFT" }));
    assert.equal(out.records_parsed, 2);
    assert.deepEqual(out.entries.map((e) => e.primary_name), ["a.txt", "b.txt"]);
    assert.equal(out.alignment_offset, 512);
    assert.equal(out.status, "partial");
    assert.match(out.problems[0].why, /first record begins at byte 512, which is not a multiple of the 1024-byte record size/);
  });
});

test("mft_records says when no slot of the file holds a record, instead of a complete answer with none", async () => {
  await withCwd(async (cwd) => {
    await fsWrite(join(cwd, "work", "MFT"), Buffer.alloc(2048, 0x41));
    const out = body<MftOut>(await tool("mft_records", cwd, { path: "work/MFT", record_size: 1024 }));
    assert.equal(out.records_parsed, 0);
    assert.equal(out.status, "partial");
    assert.ok(out.problems.some((p) => /no record was read: 2 slot\(s\) of 1024 bytes/.test(p.why)), JSON.stringify(out.problems));
  });
});

test("mft_records counts 45 bytes after the last record as trailing bytes, not as a record that failed to parse", async () => {
  // A tail shorter than the 48 bytes a record header needs raised an error inside the parser and made the run partial.
  await withCwd(async (cwd) => {
    const tail = Buffer.concat([Buffer.from("FILE"), Buffer.alloc(41)]);
    await fsWrite(join(cwd, "work", "MFT"), Buffer.concat([record(40, "a.txt"), tail]));
    const out = body<MftOut>(await tool("mft_records", cwd, { path: "work/MFT" }));
    assert.equal(out.records_parsed, 1);
    assert.equal(out.trailing_bytes, 45);
    assert.equal(out.problem_count, 0);
    assert.equal(out.status, "complete");
  });
});

test("mft_records says when the file ends inside a record", async () => {
  await withCwd(async (cwd) => {
    await fsWrite(join(cwd, "work", "MFT"), Buffer.concat([record(40, "a.txt"), record(41, "b.txt").subarray(0, 700)]));
    const out = body<MftOut>(await tool("mft_records", cwd, { path: "work/MFT" }));
    assert.equal(out.status, "partial");
    assert.ok(out.problems.some((p) => /the file ends inside this record: 700 of its 1024 bytes/.test(p.why)), JSON.stringify(out.problems));
  });
});

test("mft_records tells a zeroed slot from one that holds data and has no signature", async () => {
  // slots_without_signature put the unused slots at the end of an $MFT and damaged slots in one number.
  await withCwd(async (cwd) => {
    const junk = Buffer.alloc(1024, 0x41);
    await fsWrite(join(cwd, "work", "MFT"), Buffer.concat([record(40, "a.txt"), Buffer.alloc(1024), junk, record(43, "d.txt"), Buffer.alloc(1024)]));
    const out = body<MftOut>(await tool("mft_records", cwd, { path: "work/MFT" }));
    assert.equal(out.records_parsed, 2);
    assert.equal(out.slots_zeroed, 2);
    assert.equal(out.slots_unrecognised, 1);
    assert.equal(out.slots_without_signature, 3);
    assert.equal(out.status, "partial");
    assert.equal(out.problems.filter((p) => /holds data but neither a FILE nor a BAAD signature \(it begins 41414141\)/.test(p.why)).length, 1);
  });
  // Zeroed slots alone, at the end, are ordinary: nothing partial.
  await withCwd(async (cwd) => {
    await fsWrite(join(cwd, "work", "MFT"), Buffer.concat([record(40, "a.txt"), record(41, "b.txt"), Buffer.alloc(2048)]));
    const out = body<MftOut>(await tool("mft_records", cwd, { path: "work/MFT" }));
    assert.equal(out.slots_zeroed, 2);
    assert.equal(out.slots_unrecognised, 0);
    assert.equal(out.status, "complete");
  });
});

test("mft_records reports a used size larger than the record instead of correcting it without a word", async () => {
  await withCwd(async (cwd) => {
    await fsWrite(join(cwd, "work", "MFT"), Buffer.concat([record(40, "a.txt"), record(41, "b.txt", { used: 5000 })]));
    const out = body<MftOut>(await tool("mft_records", cwd, { path: "work/MFT" }));
    const bad = out.entries.find((e) => e.entry === 41)!;
    assert.equal(bad.unreliable, true);
    assert.ok((bad.structural_errors ?? []).some((e) => /used size \(5000\) is larger than the record \(1024 bytes\)/.test(e)), JSON.stringify(bad.structural_errors));
    assert.equal(bad.primary_name, "b.txt", "what was sound is kept");
    assert.equal(out.status, "partial");
  });
});

test("mft_records answers with JSON, and without opening it, for a file it cannot read and for a FIFO", async (t) => {
  await withCwd(async (cwd) => {
    if (!isRoot) {
      await fsWrite(join(cwd, "work", "MFT"), record(40, "a.txt"));
      await fsChmod(join(cwd, "work", "MFT"), 0);
      const out = failed(await tool("mft_records", cwd, { path: "work/MFT" }));
      assert.match(out.error, /could not read the \$MFT/);
    }
    const made = spawnSync("mkfifo", [join(cwd, "work", "FIFO")]);
    if (made.status !== 0) return t.skip("mkfifo is not available");
    const fifo = failed(await tool("mft_records", cwd, { path: "work/FIFO" }));
    assert.match(fifo.error, /not a regular file/);
    assert.equal(fifo.not_attempted, 1);
  });
});

// --- INDX -----------------------------------------------------------------------

function indxFileName(parent: bigint, name: string, o: { times?: bigint; declaredChars?: number } = {}): Buffer {
  const b = Buffer.alloc(0x42 + 2 * name.length);
  b.writeBigUInt64LE(parent | (1n << 48n), 0);
  const stamp = o.times ?? TIME;
  for (let i = 0; i < 4; i++) b.writeBigUInt64LE(stamp, 8 + i * 8);
  b.writeUInt32LE(0x20, 0x38);
  b[0x40] = o.declaredChars ?? name.length;
  b[0x41] = 1;
  Buffer.from(name, "utf16le").copy(b, 0x42);
  return b;
}

function indxEntry(ref: bigint, content: Buffer, flags = 0, keyLength?: number): Buffer {
  let length = 0x10 + content.length;
  length += (8 - (length % 8)) % 8;
  const b = Buffer.alloc(length);
  b.writeBigUInt64LE(ref, 0);
  b.writeUInt16LE(length, 8);
  b.writeUInt16LE(keyLength ?? content.length, 10);
  b.writeUInt16LE(flags, 12);
  content.copy(b, 0x10);
  return b;
}

function indxBlock(live: Buffer[]): Buffer {
  const b = Buffer.alloc(4096);
  b.write("INDX", 0, "latin1");
  const usaOffset = 0x28;
  b.writeUInt16LE(usaOffset, 4);
  b.writeUInt16LE(9, 6);
  let at = 0x40;
  for (const e of [...live, indxEntry(0n, Buffer.alloc(0), 0x02)]) {
    e.copy(b, at);
    at += e.length;
  }
  b.writeUInt32LE(0x40 - 0x18, 0x18);
  b.writeUInt32LE(at - 0x18, 0x1c);
  b.writeUInt32LE(4096 - 0x18, 0x20);
  const sequence = Buffer.from([0x07, 0x00]);
  sequence.copy(b, usaOffset);
  for (let i = 1; i < 9; i++) {
    const end = i * 512 - 2;
    b.copy(b, usaOffset + i * 2, end, end + 2);
    sequence.copy(b, end);
  }
  return b;
}

type IndxOut = {
  status: string;
  entries: Array<{ name: string; source: string; mft_entry?: number; unreliable?: boolean; unreliable_reasons?: string[]; created: string | null }>;
  live_entries_unreadable: number;
  live_entries_flagged_unreliable: number;
  problems: Array<{ offset: number; why: string }>;
  note: string;
};

test("indx_carve reports a live entry whose name is longer than its key, instead of reading the name from the bytes after it", async () => {
  await withCwd(async (cwd) => {
    const good = indxEntry(100n, indxFileName(64n, "good.txt"));
    // The key holds a 0x42-byte header and 8 bytes of name; the name length byte says 20 characters.
    const content = indxFileName(64n, "short.txt", { declaredChars: 20 });
    const bad = indxEntry(101n, content, 0, 0x42 + 8);
    // The bytes that would complete the name if the key's end were not looked at: a second, perfectly good name.
    const after = indxEntry(102n, indxFileName(64n, "after.txt"));
    await fsWrite(join(cwd, "work", "I30"), indxBlock([good, bad, after]));
    const out = body<IndxOut>(await tool("indx_carve", cwd, { path: "work/I30" }));
    assert.deepEqual(out.entries.map((e) => e.name).sort(), ["after.txt", "good.txt"]);
    assert.equal(out.live_entries_unreadable, 1);
    assert.equal(out.status, "partial");
    assert.ok(out.problems.some((p) => /a live entry \(MFT entry 101, sequence 0\) was not read as a name: the name is 20 characters/.test(p.why)), JSON.stringify(out.problems));
    assert.match(out.note, /1 live entry\(ies\) were walked but could not be read as a name/);
  });
});

test("indx_carve keeps a live entry whose times are 0 and all ones, flagged unreliable, and counts it, instead of dropping it", async () => {
  await withCwd(async (cwd) => {
    const zero = indxEntry(100n, indxFileName(64n, "zero.txt", { times: 0n }));
    const ones = indxEntry(101n, indxFileName(64n, "ones.txt", { times: 0xffffffffffffffffn }));
    const fine = indxEntry(102n, indxFileName(64n, "fine.txt"));
    await fsWrite(join(cwd, "work", "I30"), indxBlock([zero, ones, fine]));
    const out = body<IndxOut>(await tool("indx_carve", cwd, { path: "work/I30" }));
    const byName = Object.fromEntries(out.entries.map((e) => [e.name, e]));
    assert.deepEqual(Object.keys(byName).sort(), ["fine.txt", "ones.txt", "zero.txt"]);
    assert.equal(byName["zero.txt"].unreliable, true);
    assert.equal(byName["zero.txt"].created, null);
    assert.match((byName["ones.txt"].unreliable_reasons ?? [])[0], /created and modified times are both 0, all ones/);
    assert.equal(byName["fine.txt"].unreliable, undefined);
    assert.equal(out.live_entries_flagged_unreliable, 2);
    assert.equal(out.live_entries_unreadable, 0);
  });
});

test("indx_carve reports a live entry that has no key", async () => {
  await withCwd(async (cwd) => {
    const keyless = indxEntry(103n, Buffer.alloc(8), 0, 0);
    await fsWrite(join(cwd, "work", "I30"), indxBlock([indxEntry(100n, indxFileName(64n, "a.txt")), keyless]));
    const out = body<IndxOut>(await tool("indx_carve", cwd, { path: "work/I30" }));
    assert.equal(out.live_entries_unreadable, 1);
    assert.ok(out.problems.some((p) => /MFT entry 103.*the entry has no key/.test(p.why)));
  });
});

test("indx_carve answers with JSON for a file it cannot read and for a FIFO", async (t) => {
  await withCwd(async (cwd) => {
    if (!isRoot) {
      await fsWrite(join(cwd, "work", "I30"), indxBlock([indxEntry(100n, indxFileName(64n, "a.txt"))]));
      await fsChmod(join(cwd, "work", "I30"), 0);
      assert.match(failed(await tool("indx_carve", cwd, { path: "work/I30" })).error, /could not read the file/);
    }
    if (spawnSync("mkfifo", [join(cwd, "work", "FIFO")]).status !== 0) return t.skip("mkfifo is not available");
    const fifo = failed(await tool("indx_carve", cwd, { path: "work/FIFO" }));
    assert.equal(fifo.not_attempted, 1);
  });
});

// --- USN ------------------------------------------------------------------------

function usnV2(name: string, usn: bigint): Buffer {
  const text = Buffer.from(name, "utf16le");
  let length = 0x3c + text.length;
  length += (8 - (length % 8)) % 8;
  const r = Buffer.alloc(length);
  r.writeUInt32LE(length, 0);
  r.writeUInt16LE(2, 4);
  r.writeUInt16LE(0, 6);
  r.writeBigUInt64LE(33194n | (3n << 48n), 0x08);
  r.writeBigUInt64LE(5n | (7n << 48n), 0x10);
  r.writeBigUInt64LE(usn, 0x18);
  r.writeBigInt64LE(133_443_104_000_000_000n, 0x20);
  r.writeUInt32LE(0x100, 0x28);
  r.writeUInt16LE(text.length, 0x38);
  r.writeUInt16LE(0x3c, 0x3a);
  text.copy(r, 0x3c);
  return r;
}

/** A record of a major version no reader here knows: its length, major and minor version, then bytes. */
function usnFuture(major: number, minor: number, length: number): Buffer {
  const r = Buffer.alloc(length, 0x5a);
  r.writeUInt32LE(length, 0);
  r.writeUInt16LE(major, 4);
  r.writeUInt16LE(minor, 6);
  return r;
}

type UsnOut = {
  records_read: number;
  records: Array<{ version: number; minor_version: number; name: string | null; offset: number }>;
  unrecognised_bytes: number;
  unsupported_version_records: number;
  unsupported_version_bytes: number;
  unsupported_versions: Record<string, number>;
  unsupported_version_list: Array<{ offset: number; major_version: number; minor_version: number; length: number }>;
};

test("usn_journal names a record of an unsupported major version, with its offset and minor version, and keeps counting its bytes", async () => {
  await withCwd(async (cwd) => {
    const first = usnV2("one.txt", 4096n);
    const future = usnFuture(99, 7, 0x40);
    await fsWrite(join(cwd, "work", "J"), Buffer.concat([first, future, usnV2("two.txt", 8192n), Buffer.alloc(4096)]));
    const out = body<UsnOut>(await tool("usn_journal", cwd, { path: "work/J" }));
    assert.deepEqual(out.records.map((r) => r.name), ["one.txt", "two.txt"]);
    assert.deepEqual(out.records.map((r) => r.minor_version), [0, 0]);
    assert.equal(out.unsupported_version_records, 1);
    assert.deepEqual(out.unsupported_versions, { "99": 1 });
    assert.deepEqual(out.unsupported_version_list, [{ offset: first.length, major_version: 99, minor_version: 7, length: 0x40 }]);
    assert.equal(out.unsupported_version_bytes, 0x40);
    assert.equal(out.unrecognised_bytes, 0x40, "the bytes are still counted as not read");
  });
});

test("usn_journal does not call garbage a record of another version: a length that leads nowhere is unrecognised bytes", async () => {
  await withCwd(async (cwd) => {
    // The 'record' claims 0x40 bytes and what follows it is neither zeros nor a record.
    const garbage = Buffer.concat([usnFuture(99, 0, 0x40), Buffer.alloc(16, 0xee)]);
    await fsWrite(join(cwd, "work", "J"), Buffer.concat([usnV2("one.txt", 4096n), garbage, Buffer.alloc(64, 0xee), usnV2("two.txt", 8192n)]));
    const out = body<UsnOut>(await tool("usn_journal", cwd, { path: "work/J" }));
    assert.equal(out.unsupported_version_records, 0);
    assert.ok(out.unrecognised_bytes > 0);
    assert.equal(out.records_read, 2);
  });
});

test("usn_journal refuses a FIFO without opening it", { timeout: 30000 }, async (t) => {
  await withCwd(async (cwd) => {
    const fifo = join(cwd, "work", "FIFO");
    if (spawnSync("mkfifo", [fifo]).status !== 0) return t.skip("mkfifo is not available");
    // A writer holds the FIFO open so that a tool that opens it does not block forever, and lets go after a moment.
    const writer = openSync(fifo, "r+");
    setTimeout(() => closeSync(writer), 1500);
    const out = failed(await tool("usn_journal", cwd, { path: "work/FIFO" }));
    assert.match(out.error, /not a regular file/);
    assert.equal(out.not_attempted, 1);
  });
});

// --- $I -------------------------------------------------------------------------

function iRecord(path: string): Buffer {
  const text = u16z(path);
  const b = Buffer.alloc(0x1c + text.length);
  b.writeBigUInt64LE(2n, 0);
  b.writeBigUInt64LE(10n, 8);
  b.writeBigUInt64LE(133_500_000_000_000_001n, 0x10);
  b.writeUInt32LE(path.length + 1, 0x18);
  text.copy(b, 0x1c);
  return b;
}

type RecycleOut = {
  status: string;
  found: number;
  parsed: number;
  unreadable: number;
  not_attempted: number;
  entries: Array<{ file: string; original_path?: string; error?: string; not_attempted?: boolean }>;
};

const base = (file: string): string => file.split("/").pop()!;

test("recyclebin_i does not open a FIFO named $I..., and reads the rest of the bin", { timeout: 30000 }, async (t) => {
  // The FIFO hung the read to the 60 second limit and the whole bin was lost with it.
  await withCwd(async (cwd) => {
    const dir = join(cwd, "work", "bin");
    await fsMkdir(dir, { recursive: true });
    await fsWrite(join(dir, "$IAAAAAA.txt"), iRecord("C:\\a.txt"));
    await fsWrite(join(dir, "$ICCCCCC.txt"), iRecord("C:\\c.txt"));
    if (spawnSync("mkfifo", [join(dir, "$IBBBBBB.txt")]).status !== 0) return t.skip("mkfifo is not available");
    const writer = openSync(join(dir, "$IBBBBBB.txt"), "r+");
    setTimeout(() => closeSync(writer), 1500);
    const out = body<RecycleOut>(await tool("recyclebin_i", cwd, { path: "work/bin" }));
    const byName = Object.fromEntries(out.entries.map((e) => [base(e.file), e]));
    assert.equal(byName["$IAAAAAA.txt"].original_path, "C:\\a.txt");
    assert.equal(byName["$ICCCCCC.txt"].original_path, "C:\\c.txt");
    assert.match(byName["$IBBBBBB.txt"].error ?? "", /a FIFO, not a regular file: it is not opened/);
    assert.equal(byName["$IBBBBBB.txt"].not_attempted, true);
    assert.equal(out.not_attempted, 1);
    assert.equal(out.unreadable, 0);
    assert.equal(out.parsed, 2);
    assert.equal(out.status, "partial");
  });
});

test("recyclebin_i does not follow a link: not a directory named as the path, not one inside it, not a $I that is one", async () => {
  await withCwd(async (cwd) => {
    const elsewhere = join(cwd, "work", "elsewhere");
    await fsMkdir(elsewhere, { recursive: true });
    await fsWrite(join(elsewhere, "$IOUTSIDE.txt"), iRecord("C:\\outside.txt"));
    const dir = join(cwd, "work", "bin");
    await fsMkdir(dir, { recursive: true });
    await fsWrite(join(dir, "$IINSIDE.txt"), iRecord("C:\\inside.txt"));
    await fsSymlink(elsewhere, join(dir, "sub"));
    await fsSymlink(join(elsewhere, "$IOUTSIDE.txt"), join(dir, "$ILINKED.txt"));
    await fsSymlink(dir, join(cwd, "work", "bin-link"));
    const refused = failed(await tool("recyclebin_i", cwd, { path: "work/bin-link" }));
    assert.match(refused.error, /symbolic link to a directory: it is not followed/);
    assert.equal(refused.not_attempted, 1);
    const out = body<RecycleOut>(await tool("recyclebin_i", cwd, { path: "work/bin" }));
    const names = out.entries.map((e) => base(e.file)).sort();
    assert.deepEqual(names, ["$IINSIDE.txt", "$ILINKED.txt", "sub"]);
    assert.ok(!out.entries.some((e) => (e.original_path ?? "").includes("outside")));
    assert.equal(out.not_attempted, 2);
    assert.equal(out.status, "partial");
  });
});

test("recyclebin_i names a directory it could not list instead of leaving it out of the bin", async (t) => {
  if (isRoot) return t.skip("root lists every directory");
  await withCwd(async (cwd) => {
    const dir = join(cwd, "work", "bin");
    await fsMkdir(join(dir, "locked"), { recursive: true });
    await fsWrite(join(dir, "$IAAAAAA.txt"), iRecord("C:\\a.txt"));
    await fsChmod(join(dir, "locked"), 0);
    try {
      const out = body<RecycleOut>(await tool("recyclebin_i", cwd, { path: "work/bin" }));
      const locked = out.entries.find((e) => base(e.file) === "locked")!;
      assert.match(locked.error ?? "", /the directory could not be listed/);
      assert.equal(out.not_attempted, 1);
      assert.equal(out.status, "partial");
    } finally {
      await fsChmod(join(dir, "locked"), 0o755);
    }
  });
});
