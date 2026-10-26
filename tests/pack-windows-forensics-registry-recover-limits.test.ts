/**
 * registry_recover: the limits of the replay and of the records, against logs and hives written from the layouts by hand
 * (tests/windows-t1-fixtures.ts, tests/windows-hive.ts), never from a tool's output.
 *
 * What the cases hold:
 *   - an entry that cannot be applied as written (no page, a hive bins size that is not a positive multiple of 4096, a page that is not
 *     whole 512-byte sectors, more bins than the hive file can have) is named under `unrecovered` with the reason and is not applied, however
 *     valid its two hashes are; the work it asks for is not done, and no copy is made for it;
 *   - a log of many entries and one entry of many references are scanned within the tool's own clock and bounds, and what is past a bound
 *     is named (never dropped) and makes the status partial;
 *   - the copy takes the root cell offset and last-written time from the base block of the log that holds the last applied entry, and the
 *     flags from that entry, as the specification says; a log whose own base block checksum is wrong is not believed;
 *   - a hive too big for the reader that holds it whole is replayed and not read, and the answer says so;
 *   - a name or a data size longer than its cell is not followed into the next cell: the bytes of a withheld value that sit there are in no
 *     path, name or answer (the cells are checked against the layout, not against a fixture's own reading).
 */
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { readFile, stat, truncate, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { withCwd } from "./tool-library-harness.ts";
import { REGIPY, WIN, body, everyFileUnder, stub, tool } from "./windows-pack-harness.ts";
import { prng } from "./windows-canary.ts";
import { hive } from "./windows-hive.ts";
import type { HiveKey } from "./windows-hive.ts";
import { BASE_BLOCK, differingPages, hvleLog, logHeader, marvin32, withSequences, xorChecksum } from "./windows-t1-fixtures.ts";

type Answer = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

const RECORDS = !REGIPY;
const skip = REGIPY;

function generation(n: number): Buffer {
  const children: HiveKey[] = [{ name: "Run", values: [{ name: "App", type: "sz", value: `C:\\gen${n}.exe` }] }];
  return hive({ name: "ROOT", children: [{ name: "Software", children }] }, { primarySeq: 10, secondarySeq: 10 });
}
const G = [0, 1].map((n) => generation(n));
const BINS = G[0].length - BASE_BLOCK;
const DIRTY = withSequences(G[0], 12, 11);

/** An HvLE entry written field by field: any count, size and references, with both hashes right for what the bytes are (the pages' hash only when `hash1` is asked for). */
function rawEntry(o: { sequence: number; hbs: number; refs: Array<[number, number]>; count?: number; pages?: Buffer; flags?: number; hash1?: boolean /* false: leave the pages hash wrong */ }): Buffer {
  const count = o.count ?? o.refs.length;
  const refs = Buffer.alloc(8 * o.refs.length);
  o.refs.forEach(([off, size], i) => {
    refs.writeUInt32LE(off, 8 * i);
    refs.writeUInt32LE(size, 8 * i + 4);
  });
  const pages = o.pages ?? Buffer.alloc(o.refs.reduce((a, [, s]) => a + s, 0));
  const size = Math.ceil((40 + refs.length + pages.length) / 512) * 512;
  const e = Buffer.alloc(size);
  e.write("HvLE", 0, "latin1");
  e.writeUInt32LE(size, 4);
  e.writeUInt32LE(o.flags ?? 0, 8);
  e.writeUInt32LE(o.sequence, 12);
  e.writeUInt32LE(o.hbs, 16);
  e.writeUInt32LE(count, 20);
  refs.copy(e, 40);
  pages.copy(e, 40 + refs.length);
  if (o.hash1 !== false) e.writeBigUInt64LE(marvin32(e.subarray(40)), 24);
  e.writeBigUInt64LE(marvin32(e.subarray(0, 32)), 32);
  return e;
}
const logOf = (...entries: Buffer[]): Buffer => Buffer.concat([logHeader(G[1], { primary: 11 }), ...entries]);

async function run(cwd: string, hiveData: Buffer, log: Buffer | null, extra: Record<string, unknown> = {}, env: Record<string, string> = {}): Promise<Answer> {
  await writeFile(join(cwd, "work", "h.dat"), hiveData);
  const args: Record<string, unknown> = { hive: "work/h.dat", export: false, limit: 5, ...extra };
  if (log) {
    await writeFile(join(cwd, "work", "h.log1"), log);
    args.log1 = "work/h.log1";
  }
  return body<Answer>(await tool("registry_recover", cwd, args, env));
}

test("an entry whose hashes hold but which cannot be applied as written is named and not applied: no page, a bins size of 0 or not a multiple of 4096, a page that is not whole sectors", async () => {
  const page = differingPages(G[0], G[1])[0];
  const cases: Array<[string, Buffer, RegExp]> = [
    ["no page", rawEntry({ sequence: 11, hbs: BINS, refs: [] }), /lists no page/],
    ["a bins size of 0 and no page", rawEntry({ sequence: 11, hbs: 0, refs: [] }), /(lists no page|not a positive multiple of 4096)/],
    ["a bins size of 0 with a page", rawEntry({ sequence: 11, hbs: 0, refs: [[page.offset, page.data.length]], pages: page.data }), /positive multiple of 4096/],
    ["a bins size that is not a multiple of 4096", rawEntry({ sequence: 11, hbs: BINS + 1, refs: [[page.offset, page.data.length]], pages: page.data }), /positive multiple of 4096/],
    ["a page of 100 bytes", rawEntry({ sequence: 11, hbs: BINS, refs: [[page.offset, 100]], pages: page.data.subarray(0, 100) }), /whole 512-byte sectors/],
    ["a page at an offset that is not a sector", rawEntry({ sequence: 11, hbs: BINS, refs: [[page.offset + 7, 512]], pages: page.data.subarray(0, 512) }), /whole 512-byte sectors/],
  ];
  for (const [label, entry, why] of cases) {
    await withCwd(async (cwd) => {
      const out = await run(cwd, DIRTY, logOf(entry));
      assert.equal(out.replayed, false, `${label}: an entry that cannot be applied as written is not applied`);
      assert.equal(out.entries_applied, 0, label);
      assert.equal(out.status, "partial", label);
      assert.equal(out.recovered_copy ?? null, null, `${label}: no copy`);
      assert.match(JSON.stringify(out.unrecovered), why, label);
    });
  }
});

test("an entry that declares more hive bins than the hive file can have is refused before a copy of that size is made, whatever its hashes", async () => {
  const page = differingPages(G[0], G[1])[0];
  for (const hbs of [0x20000000, 0x7ffff000, 0xfffff000]) {
    await withCwd(async (cwd) => {
      const out = await run(cwd, DIRTY, logOf(rawEntry({ sequence: 11, hbs, refs: [[page.offset, page.data.length]], pages: page.data })));
      assert.equal(out.replayed, false, `hbs ${hbs.toString(16)}`);
      assert.equal(out.status, "partial");
      assert.equal(out.recovered_copy ?? null, null);
      assert.match(JSON.stringify(out.unrecovered), /more than this tool writes/);
      for (const f of await everyFileUnder(cwd)) assert.ok((await stat(f)).size < 1 << 20, `${f}: nothing the size of the declared bins is written`);
    });
  }
  // Growth the hive file can account for (here 8 MiB past its bins) is applied, and the zeros it adds are named.
  await withCwd(async (cwd) => {
    const grown = BINS + 8 * 2 ** 20;
    const out = await run(cwd, DIRTY, logOf(rawEntry({ sequence: 11, hbs: grown, refs: [[page.offset, page.data.length]], pages: page.data })));
    assert.equal(out.replayed, true);
    assert.equal((await stat(join(cwd, out.recovered_copy))).size, BASE_BLOCK + grown);
    assert.match(JSON.stringify(out.unrecovered), /which are zeros/);
    assert.equal(out.status, "partial");
  });
});

test("an entry of two million references that are not whole sectors is refused in the first block, not read to its end", async () => {
  await withCwd(async (cwd) => {
    const count = 2_000_000;
    const refs = Buffer.alloc(8 * count);
    for (let i = 0; i < count; i++) refs.writeUInt32LE(1, 8 * i + 4); // (0, 1 byte), the same page again and again
    const size = Math.ceil((40 + refs.length + count) / 512) * 512;
    const e = Buffer.alloc(size);
    e.write("HvLE", 0, "latin1");
    e.writeUInt32LE(size, 4);
    e.writeUInt32LE(11, 12);
    e.writeUInt32LE(BINS, 16);
    e.writeUInt32LE(count, 20);
    refs.copy(e, 40);
    e.writeBigUInt64LE(marvin32(e.subarray(40)), 24);
    e.writeBigUInt64LE(marvin32(e.subarray(0, 32)), 32);
    const out = await run(cwd, DIRTY, logOf(e), { max_seconds: 20 });
    assert.equal(out.replayed, false);
    assert.equal(out.status, "partial");
    assert.match(JSON.stringify(out.unrecovered), /(more than the \d+ 512-byte sectors|whole 512-byte sectors)/);
    assert.ok(out.elapsed_seconds < 5, `refused at once (${out.elapsed_seconds} s)`);
  });
  // The same page 100,000 times, in a hive whose bins are big enough to hold that many sectors: the first reference is the fault.
  await withCwd(async (cwd) => {
    const count = 100_000;
    const refs = Array.from({ length: count }, () => [0, 1] as [number, number]);
    const out = await run(cwd, DIRTY, logOf(rawEntry({ sequence: 11, hbs: count * 512, refs })), { max_seconds: 20 });
    assert.equal(out.replayed, false);
    assert.match(JSON.stringify(out.unrecovered), /page reference 0 \(offset 0, 1 bytes\) does not name whole 512-byte sectors/);
    assert.ok(out.elapsed_seconds < 5);
  });
});

test("a log of more entries than the scan holds is scanned up to the bound and the rest is named, with where it starts", async () => {
  await withCwd(async (cwd) => {
    // Every entry is the same bytes (the same sequence number, which does not follow): 50,001 of them, one reference each.
    const one = rawEntry({ sequence: 99, hbs: BINS, refs: [[0, 512]] });
    assert.equal(one.length, 1024);
    const entries = Buffer.alloc(one.length * 50_001);
    for (let i = 0; i < 50_001; i++) one.copy(entries, i * one.length);
    const out = await run(cwd, DIRTY, Buffer.concat([logHeader(G[1], { primary: 99 }), entries]), { max_seconds: 60 });
    assert.equal(out.status, "partial");
    assert.equal(out.replayed, false);
    const receipt = JSON.parse(await readFile(join(cwd, out.receipt), "utf8")) as Answer;
    assert.match(receipt.logs[0].trailing.reason, /more than 50000 entries/);
    assert.ok(out.unrecovered_count >= 50_001, "every entry that was scanned is unrecovered, and the rest of the log is one more");
    assert.equal(receipt.logs[0].entry_count, 50_000, "the entries scanned are counted");
    assert.equal(receipt.logs[0].trailing.offset, 512 + 50_000 * 1024, "where the unscanned rest begins is in the receipt");
    assert.equal(receipt.logs[0].trailing.bytes, 1024, "and how much is left");
  });
});

test("a pages hash that takes longer than the tool's clock ends in the time limit, named, with the entry not applied", async () => {
  await withCwd(async (cwd) => {
    const count = 120_000;
    const refs: Array<[number, number]> = Array.from({ length: count }, (_v, i) => [i * 512, 512] as [number, number]);
    const hbs = Math.ceil((count * 512) / 4096) * 4096;
    const out = await run(cwd, DIRTY, logOf(rawEntry({ sequence: 11, hbs: Math.max(hbs, BINS), refs, pages: Buffer.alloc(count * 512), hash1: false })), { max_seconds: 1 });
    assert.equal(out.replayed, false);
    assert.equal(out.status, "partial");
    assert.match(out.status_basis, /time limit/);
    assert.ok(out.elapsed_seconds < 8, `ended near its clock (${out.elapsed_seconds} s)`);
    // The refs of the entry are not lost: the receipt names where they are in the log.
    assert.match(JSON.stringify(out.unrecovered), /page_references|hive_ranges/);
  });
});

test("the copy takes the root cell offset and the last-written time from the base block of the log that holds the last applied entry, and the flags from that entry", async () => {
  const pages = differingPages(G[0], G[1]);
  const entry = (flags: number): Buffer => rawEntry({ sequence: 11, hbs: BINS, refs: pages.map((p) => [p.offset, p.data.length] as [number, number]), pages: Buffer.concat(pages.map((p) => p.data)), flags });
  const header = (mutate: (h: Buffer) => void, fix = true): Buffer => {
    const h = logHeader(G[1], { primary: 11 });
    mutate(h);
    if (fix) h.writeUInt32LE(xorChecksum(h), 0x1fc);
    return h;
  };
  await withCwd(async (cwd) => {
    const log = Buffer.concat([header((h) => { h.writeUInt32LE(0x1234, 0x24); h.writeBigUInt64LE(133_999_000_000_000_000n, 0x0c); }), entry(2)]);
    const out = await run(cwd, DIRTY, log);
    assert.equal(out.replayed, true);
    assert.equal(out.status, "complete", out.status_basis);
    const copy = await readFile(join(cwd, out.recovered_copy));
    assert.equal(copy.readUInt32LE(0x24), 0x1234, "root cell offset from the log's base block");
    assert.equal(copy.readBigUInt64LE(0x0c), 133_999_000_000_000_000n, "last-written time from the log's base block");
    assert.equal(copy.readUInt32LE(0x90), 2, "flags from the last applied entry");
    assert.equal(copy.readUInt32LE(0x1fc), xorChecksum(copy.subarray(0, 512)), "the checksum covers them");
    const receipt = JSON.parse(await readFile(join(cwd, out.receipt), "utf8")) as Answer;
    for (const field of ["root_cell_offset", "last_written", "flags"]) assert.ok(receipt.replay.base_block_fields_changed.includes(field), `${field} is named as changed`);
    assert.equal(receipt.replay.base_block_from_log.taken, true);
  });
  await withCwd(async (cwd) => {
    // A log whose base block checksum is wrong is not believed: the copy keeps the original's fields, and the answer says so (partial).
    const log = Buffer.concat([header((h) => { h.writeUInt32LE(0x1234, 0x24); }, false), entry(2)]);
    const out = await run(cwd, DIRTY, log);
    assert.equal(out.replayed, true);
    assert.equal(out.status, "partial");
    assert.match(out.status_basis, /checksum/);
    const copy = await readFile(join(cwd, out.recovered_copy));
    assert.equal(copy.readUInt32LE(0x24), DIRTY.readUInt32LE(0x24));
    assert.equal(copy.readUInt32LE(0x90), DIRTY.readUInt32LE(0x90));
  });
});

test("a hive past the size regipy can hold whole is replayed and not read, and the answer says so", { skip }, async () => {
  await withCwd(async (cwd) => {
    const file = join(cwd, "work", "big.dat");
    await writeFile(file, G[0]);
    await truncate(file, 600 * 2 ** 20);
    const r = await tool("registry_recover", cwd, { hive: "work/big.dat", limit: 1 });
    const out = body<Answer>(r);
    assert.equal(out.records.status, "skipped");
    assert.match(out.records.why, /regipy holds the whole hive in memory/);
    assert.equal(out.status, "partial");
    assert.match(out.status_basis, /skipped/);
    assert.ok(out.elapsed_seconds < 30);
  });
});

// ---- names and data longer than their cells ----------------------------------------------------------------------------------------

const CANARY = "CANARY-Zq7xK2mV9wP4rT8jN3";
/** Two keys: `Early`, whose cells come first in the file, and `Late`, whose Password value is after them; a name or a size that runs on from Early reads Late's cells. */
function overrunHive(): Buffer {
  return hive({
    name: "ROOT",
    children: [{
      name: "Software",
      children: [
        { name: "Early", values: [{ name: "A", type: "binary", value: Buffer.alloc(300, 0x41) }, { name: "Plain", type: "sz", value: "visible" }] },
        { name: "Late", values: [{ name: "Password", type: "binary", value: Buffer.from(CANARY, "latin1") }, { name: "Note", type: "sz", value: "visible-too" }] },
      ],
    }],
  }, { primarySeq: 10, secondarySeq: 10 });
}
/** The offsets (of the signature) of the nk and vk records whose name is `name`. */
function recordAt(buf: Buffer, sig: "nk" | "vk", name: string): number {
  const at = sig === "nk" ? 0x4c : 0x14;
  const lenAt = sig === "nk" ? 0x48 : 2;
  for (let p = buf.indexOf(sig, BASE_BLOCK); p !== -1; p = buf.indexOf(sig, p + 2)) {
    if (buf.readInt32LE(p - 4) >= 0) continue;
    if (buf.readUInt16LE(p + lenAt) === name.length && buf.subarray(p + at, p + at + name.length).toString("latin1") === name) return p;
  }
  throw new Error(`no ${sig} record named ${name}`);
}
const everything = async (cwd: string): Promise<string> => {
  const parts: string[] = [];
  for (const f of await everyFileUnder(cwd)) if (!f.endsWith("/work/h.dat") && !f.endsWith("recovered.hive")) parts.push((await readFile(f)).toString("latin1"));
  return parts.join("\n");
};
const seenIn = (text: string): boolean => text.includes(CANARY) || text.toLowerCase().includes(Buffer.from(CANARY, "latin1").toString("hex"));

test("a key name or a value name longer than its cell does not read the next cell: the withheld value there is in no path, no name and no answer", { skip }, async () => {
  const base = overrunHive();
  const canaryAt = base.indexOf(CANARY, BASE_BLOCK);
  assert.ok(canaryAt > 0);
  const cases: Array<[string, (b: Buffer) => void]> = [
    ["a key name", (b) => { const p = recordAt(b, "nk", "Early"); b.writeUInt16LE(canaryAt + 8 - (p + 0x4c), p + 0x48); }],
    ["a value name", (b) => { const p = recordAt(b, "vk", "A"); b.writeUInt16LE(canaryAt + 8 - (p + 0x14), p + 2); b.writeUInt16LE(1, p + 0x10); }],
    ["a value name stored as UTF-16", (b) => { const p = recordAt(b, "vk", "A"); b.writeUInt16LE(canaryAt + 8 - (p + 0x14), p + 2); b.writeUInt16LE(0, p + 0x10); }],
  ];
  for (const [label, damage] of cases) {
    await withCwd(async (cwd) => {
      const h = Buffer.from(base);
      damage(h);
      await writeFile(join(cwd, "work", "h.dat"), h);
      const out = body<Answer>(await tool("registry_recover", cwd, { hive: "work/h.dat", limit: 100 }, {}));
      assert.equal(seenIn(JSON.stringify(out)), false, `${label}: not in the answer`);
      assert.equal(seenIn(await everything(cwd)), false, `${label}: not in any file the tool wrote`);
      assert.equal(out.status, "partial", `${label}: said`);
      assert.match(JSON.stringify(out.records.problems), /name is withheld/, label);
      const keys = (await readFile(join(cwd, out.records.keys_file), "utf8")).trim().split("\n").map((l) => JSON.parse(l) as Answer);
      // The record that was read with a name that could not be is shown with its place, and a value under one is withheld, not printed.
      assert.ok(keys.some((r) => /name withheld/.test(String(r.name ?? r.path ?? ""))), `${label}: the record says its name was withheld`);
      assert.ok(keys.some((r) => r.name === "Note"), `${label}: the other records are read`);
    });
  }
});

test("a value data size longer than its cell is cut at the cell: the bytes of the next cell are not in the value", { skip }, async () => {
  const base = overrunHive();
  const canaryAt = base.indexOf(CANARY, BASE_BLOCK);
  await withCwd(async (cwd) => {
    const h = Buffer.from(base);
    const p = recordAt(h, "vk", "A");
    const dataCell = BASE_BLOCK + h.readUInt32LE(p + 8);
    h.writeUInt32LE(canaryAt + 8 - (dataCell + 4), p + 4); // the data would run on into Late's cells
    await writeFile(join(cwd, "work", "h.dat"), h);
    const out = body<Answer>(await tool("registry_recover", cwd, { hive: "work/h.dat", limit: 100 }));
    assert.equal(seenIn(JSON.stringify(out)), false);
    assert.equal(seenIn(await everything(cwd)), false);
    assert.equal(out.status, "partial");
    assert.match(JSON.stringify(out.records.problems), /only the cell's bytes are read/);
  });
});

test("structure-aware damage to the cells of a hive (100 cases): no withheld value in a path or a name, JSON every time", { skip }, async () => {
  const base = overrunHive();
  const cells: Array<{ at: number; sig: string }> = [];
  for (let p = BASE_BLOCK + 0x20; p < base.length - 8; p++) {
    const sig = base.subarray(p, p + 2).toString("latin1");
    if (["nk", "vk", "li"].includes(sig) && base.readInt32LE(p - 4) < 0) cells.push({ at: p, sig });
  }
  const rnd = prng(20261026);
  const pick = <T,>(xs: T[]): T => xs[Math.floor(rnd() * xs.length)];
  const leakedNames: string[] = [];
  for (let i = 0; i < 100; i++) {
    const h = Buffer.from(base);
    for (let k = 0; k < 1 + Math.floor(rnd() * 3); k++) {
      const c = pick(cells);
      const [field, width] = c.sig === "nk" ? pick([[0x48, 2], [0x14, 4], [0x24, 4], [0x1c, 4], [0x28, 4], [2, 2]]) : c.sig === "vk" ? pick([[2, 2], [4, 4], [8, 4], [0x10, 2]]) : pick([[2, 2], [4, 4]]);
      const value = pick([0, 1, 2, 0xffff, 0xffffffff, 0x7fffffff, 0x80000000, Math.floor(rnd() * 0x100000000), c.at - BASE_BLOCK, 0x20, h.length - BASE_BLOCK]);
      if (c.at + field + width <= h.length) {
        if (width === 2) h.writeUInt16LE(value & 0xffff, c.at + field);
        else h.writeUInt32LE(value >>> 0, c.at + field);
      }
    }
    await withCwd(async (cwd) => {
      await writeFile(join(cwd, "work", "h.dat"), h);
      const r = await tool("registry_recover", cwd, { hive: "work/h.dat", limit: 50 });
      assert.doesNotMatch(r.stderr, /Traceback/, `case ${i}`);
      const out = JSON.parse(r.stdout) as Answer;
      assert.ok(out.status, `case ${i}: JSON`);
      if (out.records?.keys_file) {
        const rows = (await readFile(join(cwd, out.records.keys_file), "utf8")).trim().split("\n").filter(Boolean).map((l) => JSON.parse(l) as Answer);
        for (const row of rows) for (const f of ["key", "path", "name"]) if (seenIn(String(row[f] ?? ""))) leakedNames.push(`case ${i} ${f}`);
      }
      if (seenIn(JSON.stringify({ ...out, keys_inline: undefined, records: { ...out.records, keys_inline: undefined } }).replace(/"data[^"]*":\s*"[^"]*"/g, ""))) leakedNames.push(`case ${i} answer`);
    });
  }
  assert.deepEqual(leakedNames, []);
});

test("the limits are said in the manifest and the receipt", async () => {
  const manifest = JSON.parse(await readFile(join(process.cwd(), "packs/windows-forensics/tools/registry_recover/manifest.json"), "utf8")) as Answer;
  for (const word of ["512 MiB", "50,000", "whole 512-byte sectors", "last-written", "name withheld"]) assert.match(manifest.description, new RegExp(word.replace(/[-/\\^$*+?.()|[\]{}]/g, "\\$&")), word);
});

// ---- the independent reader, the hashes and a signal ----------------------------------------------------------------------------------

const LINUX = process.platform === "linux" ? false : "address space is limited on Linux, where the tool runs";

test("regfexport is stopped when it prints far more than the hive can hold: the reason is said, its counts are not compared, and the status is partial", { skip }, async () => {
  await withCwd(async (cwd, bin) => {
    await stub(bin, "regfexport", "exec yes 'Key path: x'");
    await writeFile(join(cwd, "work", "h.dat"), G[0]);
    const began = Date.now();
    const out = body<Answer>(await tool("registry_recover", cwd, { hive: "work/h.dat", limit: 5, export: true, max_seconds: 60 }, {}, bin));
    const reader = out.records.independent_reader.regfexport;
    assert.ok(Date.now() - began < 20_000, `returned in ${Date.now() - began} ms, not at the tool's clock`);
    assert.equal(reader.ran, true);
    assert.equal(reader.finished, false);
    assert.equal(reader.agrees, undefined, "an unfinished count is not compared");
    assert.ok(reader.output_bytes > 64 * 2 ** 20 && reader.output_bytes < 80 * 2 ** 20, `${reader.output_bytes} bytes were read before it was stopped`);
    assert.match(reader.why_not_finished, /printed more than \d+ bytes/);
    assert.equal(out.status, "partial");
    assert.match(out.status_basis, /regfexport printed more than/);
  });
});

test("regfexport gets a ceiling on its memory: a program that wants three gigabytes for a small hive fails, and that is said", { skip: skip || LINUX }, async () => {
  await withCwd(async (cwd, bin) => {
    await stub(bin, "regfexport", "exec python3 -c \"b = bytearray(3 << 30); print('Key path: x')\"");
    await writeFile(join(cwd, "work", "h.dat"), G[0]);
    const out = body<Answer>(await tool("registry_recover", cwd, { hive: "work/h.dat", limit: 5, export: true }, {}, bin));
    const reader = out.records.independent_reader.regfexport;
    assert.equal(reader.finished, false);
    assert.ok(reader.limits.address_space_bytes >= 2 ** 30 && reader.limits.address_space_bytes < 2 ** 30 + 1e6, JSON.stringify(reader.limits));
    assert.match(reader.why_not_finished, /exited with status \d+/);
    assert.match(reader.why_not_finished, /held to \d+ bytes of address space/);
    assert.equal(out.status, "partial");
  });
});

/** The tool as a module with its clock set to run out when `armed` says so; `after` names the function whose return arms it. */
function inProcess(cwd: string, args: Record<string, unknown>, after: string): { status: number | null; stdout: string; stderr: string } {
  const code = [
    "import importlib.util, json, sys",
    "spec = importlib.util.spec_from_file_location('rrun', sys.argv[1])",
    "m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)",
    "state = {'out': False}",
    "real = getattr(m, sys.argv[2])",
    "def arm(*a, **k):",
    "    r = real(*a, **k)",
    "    state['out'] = True",
    "    return r",
    "setattr(m, sys.argv[2], arm)",
    "m.out_of_time = lambda *a, **k: state['out']",
    "m.main()",
  ].join("\n");
  return spawnSync("python3", ["-c", code, join(WIN, "registry_recover", "run.py"), after], { cwd, encoding: "utf8", input: JSON.stringify(args), env: { ...process.env, AGENT_ID: "s1" }, maxBuffer: 1 << 26 });
}

test("the hive and the logs are hashed with the tool's clock looked at: a hash the time limit stopped is not made, the receipt names it, and the status is partial", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "h.dat"), DIRTY);
    await writeFile(join(cwd, "work", "h.log1"), logOf(rawEntry({ sequence: 11, hbs: BINS, refs: [[differingPages(G[0], G[1])[0].offset, 512]], pages: differingPages(G[0], G[1])[0].data.subarray(0, 512) })));
    // The clock runs out as soon as the base block of the hive has been read, which is before the first hash.
    const r = inProcess(cwd, { hive: "work/h.dat", log1: "work/h.log1", export: false, limit: 5 }, "read_base");
    assert.equal(r.status, 0, r.stderr);
    const out = JSON.parse(r.stdout) as Answer;
    assert.equal(out.status, "partial");
    assert.match(out.status_basis, /not every file was hashed \(the hive: the time limit was reached after 0 bytes of \d+ were hashed; log1: the time limit was reached after 0 bytes of \d+ were hashed\)/);
    const receipt = JSON.parse(await readFile(join(cwd, out.receipt), "utf8")) as Answer;
    assert.equal(receipt.hive_original.sha256, null);
    assert.match(receipt.hive_original.sha256_not_made, /time limit/);
    assert.equal(receipt.not_hashed.length, 2);
    assert.equal(out.recovered_copy ?? null, null, "no replay was made in no time");
    assert.match(receipt.replay.reason, /time limit was reached while the logs were scanned, before an applicable entry was found/);
  });
});

test("a signal that ends the tool after the recovered copy was placed and before its receipt leaves no recovered copy behind", { skip }, async () => {
  await withCwd(async (cwd, bin) => {
    const pidFile = join(cwd, "regfexport.pid");
    await stub(bin, "regfexport", `echo $$ > "${pidFile}"; exec sleep 60`);
    const page = differingPages(G[0], G[1])[0];
    await writeFile(join(cwd, "work", "h.dat"), DIRTY);
    await writeFile(join(cwd, "work", "h.log1"), logOf(rawEntry({ sequence: 11, hbs: BINS, refs: [[page.offset, page.data.length]], pages: page.data })));
    const child = spawn("python3", [join(WIN, "registry_recover", "run.py")], { cwd, env: { ...process.env, AGENT_ID: "s1", PATH: `${bin}:${process.env.PATH}` }, stdio: ["pipe", "pipe", "pipe"] });
    const chunks: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => chunks.push(c));
    child.stdin.end(JSON.stringify({ hive: "work/h.dat", log1: "work/h.log1", limit: 5, export: true, max_seconds: 60 }));
    // regfexport is running, which is after the copy was placed and before the receipt.
    for (let i = 0; i < 100 && !(await stat(pidFile).then(() => true, () => false)); i++) await new Promise((r) => setTimeout(r, 100));
    assert.ok((await everyFileUnder(join(cwd, "work"))).some((f) => f.endsWith("recovered.hive")), "the copy had been placed");
    child.kill("SIGTERM");
    const code = await new Promise<number | null>((resolve) => child.on("close", (c) => resolve(c)));
    assert.equal(code, 143);
    const last = JSON.parse(Buffer.concat(chunks).toString("utf8")) as Answer;
    assert.equal(last.status, "interrupted");
    assert.match(last.status_basis, /the recovered copy, which had no receipt yet/);
    const left = await everyFileUnder(join(cwd, "work"));
    assert.deepEqual(left.filter((f) => /recovered/.test(f)), [], "no recovered copy without its receipt");
    assert.deepEqual(left.filter((f) => /receipt/.test(f)), []);
  });
});
