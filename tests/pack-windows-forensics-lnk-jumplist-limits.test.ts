/**
 * lnk_jumplist: the limits of the compound-file reader and the container checks, against files written from MS-CFB by hand
 * (tests/windows-t1-fixtures.ts for a well-formed one; the damaged ones are that file with named bytes changed, or built here field by field),
 * never from a tool's output.
 *
 * What the cases hold:
 *   - a small file cannot make the tool use time or memory out of proportion to it: a DIFAT that lists one FAT sector again and again, many
 *     streams on one chain, and a chain of millions of sectors each end in bounded time and memory (peak resident size is measured), with
 *     the problem named once with a count and not as a line for every repeat;
 *   - the container is checked, not only read: sectors or mini sectors that two chains hold, a directory entry with no name, a DestList entry
 *     that names a stream that is no link, a FAT that does not mark its own sectors, a tree that names an entry that is not allocated,
 *     a container with streams and no DestList, each make the status partial; a container with no stream at all (an empty jump list) is complete;
 *   - every case that is damaged is damaged in one place, so the one problem that is named is the one that was made.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFile, truncate, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { withCwd } from "./tool-library-harness.ts";
import { WIN, body, pythonCanImport, tool } from "./windows-pack-harness.ts";
import { FILETIME_A, cfb, destList, lnk } from "./windows-t1-fixtures.ts";

type Answer = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any
type Row = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

const END = 0xfffffffe;
const FREE = 0xffffffff;
const FATSECT = 0xfffffffd;
const DIFSECT = 0xfffffffc;
const LNK = lnk({ local: { path: "C:\\case\\report.txt", serial: 0x1a2b3c4d, label: "SYSTEM" }, name: "Report" });
const entries = (n: number[]): Buffer => destList(4, n.map((k) => ({ number: k, host: "WKS", filetime: FILETIME_A + BigInt(k) * 10_000_000n, pin: -1, path: `C:\\case\\f${k}.txt` })));
const AUTO = (): Buffer => cfb([{ name: "1", data: LNK }, { name: "2", data: LNK }, { name: "DestList", data: entries([1, 2]) }]);

const rowsOf = async (cwd: string, out: Answer): Promise<Row[]> => (await readFile(join(cwd, out.rows_file ?? ""), "utf8")).trim().split("\n").map((l) => JSON.parse(l) as Row);
const containerOf = async (cwd: string, out: Answer): Promise<Row> => (await rowsOf(cwd, out)).find((r) => r.row === "container")!;

/** Run the tool and say how much memory it peaked at: a wrapper that starts it and reads the peak resident size of its child (bytes on macOS, KiB elsewhere). */
function measured(cwd: string, args: unknown): { answer: Answer; rssMb: number; seconds: number; cpu: number } {
  const code = [
    "import json, os, resource, subprocess, sys, time",
    "t = time.time()",
    "p = subprocess.run([sys.executable, sys.argv[1]], input=sys.argv[2], capture_output=True, text=True, env={**os.environ, 'AGENT_ID': 's1'})",
    "ru = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss",
    "cpu = resource.getrusage(resource.RUSAGE_CHILDREN).ru_utime + resource.getrusage(resource.RUSAGE_CHILDREN).ru_stime",
    "print(json.dumps({'out': p.stdout, 'err': p.stderr[-300:], 'mb': ru / (1 << 20) if sys.platform == 'darwin' else ru / 1024, 'sec': time.time() - t, 'cpu': cpu}))",
  ].join("\n");
  const r = spawnSync("python3", ["-c", code, join(WIN, "lnk_jumplist", "run.py"), JSON.stringify(args)], { cwd, encoding: "utf8", maxBuffer: 1 << 28 });
  assert.equal(r.status, 0, r.stderr);
  const w = JSON.parse(r.stdout) as { out: string; err: string; mb: number; sec: number; cpu: number };
  assert.doesNotMatch(w.err, /Traceback/);
  return { answer: JSON.parse(w.out) as Answer, rssMb: w.mb, seconds: w.sec, cpu: w.cpu };
}

// ---- files that are small and ask for a lot ------------------------------------------------------------------------------------------

/** A compound file of `difat` DIFAT sectors that each list the one FAT sector 127 times, a header that declares 0xFFFFFFFF FAT sectors, and an empty directory. */
function difatBomb(difat: number): Buffer {
  const header = Buffer.alloc(512);
  Buffer.from("d0cf11e0a1b11ae1", "hex").copy(header, 0);
  header.writeUInt16LE(3, 0x1a);
  header.writeUInt16LE(0xfffe, 0x1c);
  header.writeUInt16LE(9, 0x1e);
  header.writeUInt16LE(6, 0x20);
  const fat = difat; // the sector that is the FAT comes after the DIFAT sectors
  [0xffffffff, fat + 1, 0, 4096, END, 0, 0, difat].forEach((v, i) => header.writeUInt32LE(v >>> 0, 0x2c + 4 * i));
  for (let i = 0; i < 109; i++) header.writeUInt32LE(fat, 0x4c + 4 * i);
  const parts = [header];
  for (let k = 0; k < difat; k++) {
    const s = Buffer.alloc(512);
    for (let i = 0; i < 127; i++) s.writeUInt32LE(fat, 4 * i);
    s.writeUInt32LE(k + 1 < difat ? k + 1 : END, 508);
    parts.push(s);
  }
  const f = Buffer.alloc(512);
  for (let i = 0; i < 128; i++) f.writeUInt32LE(END, 4 * i);
  parts.push(f, Buffer.alloc(512));
  return Buffer.concat(parts);
}

/** A directory entry as 128 bytes. */
function dirEntry(name: string, type: number, left: number, right: number, child: number, start: number, size: number): Buffer {
  const e = Buffer.alloc(128);
  const raw = Buffer.from(name, "utf16le");
  raw.copy(e, 0);
  e.writeUInt16LE(name ? raw.length + 2 : 0, 64);
  e[66] = type;
  e[67] = 1;
  e.writeUInt32LE(left >>> 0, 68);
  e.writeUInt32LE(right >>> 0, 72);
  e.writeUInt32LE(child >>> 0, 76);
  e.writeUInt32LE(start >>> 0, 116);
  e.writeUInt32LE(size >>> 0, 120);
  return e;
}

/** `streams` streams that all start at the one chain of `chain` sectors. */
function sharedChain(streams: number, chain: number): Buffer {
  const dirSectors = Math.ceil((streams + 1) / 4);
  let fats = 1;
  while (fats * 128 < fats + dirSectors + chain) fats++;
  assert.ok(fats <= 109);
  const total = fats + dirSectors + chain;
  const table = new Uint32Array(fats * 128).fill(FREE);
  for (let i = 0; i < fats; i++) table[i] = FATSECT;
  for (let i = 0; i < dirSectors; i++) table[fats + i] = i + 1 < dirSectors ? fats + i + 1 : END;
  const c0 = fats + dirSectors;
  for (let i = 0; i < chain; i++) table[c0 + i] = i + 1 < chain ? c0 + i + 1 : END;
  const header = Buffer.alloc(512);
  Buffer.from("d0cf11e0a1b11ae1", "hex").copy(header, 0);
  header.writeUInt16LE(3, 0x1a);
  header.writeUInt16LE(0xfffe, 0x1c);
  header.writeUInt16LE(9, 0x1e);
  header.writeUInt16LE(6, 0x20);
  [fats, fats, 0, 4096, END, 0, END, 0].forEach((v, i) => header.writeUInt32LE(v >>> 0, 0x2c + 4 * i));
  for (let i = 0; i < 109; i++) header.writeUInt32LE(i < fats ? i : FREE, 0x4c + 4 * i);
  const out = Buffer.alloc(512 + total * 512);
  header.copy(out, 0);
  Buffer.from(table.buffer).copy(out, 512);
  const dir = Buffer.alloc(dirSectors * 512);
  dirEntry("Root Entry", 5, FREE, FREE, streams ? 1 : FREE, END, 0).copy(dir, 0);
  for (let i = 0; i < streams; i++) dirEntry(`s${i}`, 2, FREE, i + 1 < streams ? i + 2 : FREE, FREE, c0, chain * 512).copy(dir, (i + 1) * 128);
  dir.copy(out, 512 + fats * 512);
  LNK.subarray(0, 20).copy(out, 512 + c0 * 512);
  return out;
}

test("a 1 MB file whose 2,000 DIFAT sectors each list one FAT sector 127 times is read in bounded time and memory: the repeat is one line with its count, and the DIFAT chain the file cannot need is not read", async () => {
  await withCwd(async (cwd) => {
    const file = difatBomb(2000);
    assert.ok(file.length < 1.1e6);
    await writeFile(join(cwd, "work", "x.automaticDestinations-ms"), file);
    const m = measured(cwd, { path: "work/x.automaticDestinations-ms" });
    assert.ok(m.rssMb < 150, `peak ${m.rssMb.toFixed(0)} MB`);
    assert.ok(m.seconds < 5, `${m.seconds.toFixed(1)} s`);
    assert.equal(m.answer.status, "partial");
    const problems: string[] = (await containerOf(cwd, m.answer)).problems;
    assert.ok(problems.some((p) => /FAT sector 2000 more than once/.test(p) && /and \d+ more of this kind/.test(p)), problems.join(" | "));
    assert.ok(problems.some((p) => /DIFAT chain is longer than a file of \d+ sectors can need \(0 DIFAT sectors at most\); the rest of it is not read/.test(p)), problems.join(" | "));
    assert.ok(problems.length < 20, "a kind of problem is one line, not one for every repeat");
  });
});

test("400 streams on one 4,000-sector chain are read in linear time and bounded memory: the first holds the chain, the others stop where it begins and say so", async () => {
  await withCwd(async (cwd) => {
    const file = sharedChain(400, 4000);
    await writeFile(join(cwd, "work", "x.automaticDestinations-ms"), file);
    const m = measured(cwd, { path: "work/x.automaticDestinations-ms", max_seconds: 10 });
    assert.ok(m.rssMb < 150, `peak ${m.rssMb.toFixed(0)} MB`);
    assert.ok(m.seconds < 3, `${m.seconds.toFixed(1)} s`);
    assert.equal(m.answer.status, "partial");
    const rows = await rowsOf(cwd, m.answer);
    const box = rows.find((r) => r.row === "container")!;
    assert.ok(box.problems.some((p: string) => /shares sector \d+ with stream 's0'/.test(p) && /and 398 more of this kind/.test(p)), box.problems.join(" | "));
    assert.ok(box.problems.length < 20);
    const streams = rows.filter((r) => r.row === "stream");
    assert.equal(streams.length, 400);
    const first = streams.find((r) => r.name === "s0")!;
    assert.equal(first.chain_whole, true);
    assert.equal(first.extents[0].bytes, 4000 * 512);
    const second = streams.find((r) => r.name === "s1")!;
    assert.equal(second.chain_whole, false);
    assert.match(second.problems[0], /shares sector \d+ with stream 's0'/, "a stream's own row says where its chain meets the other's");
  });
});

test("a stream chain of three million sectors is followed within the tool's clock and memory: the extents are joined as they are found", async () => {
  await withCwd(async (cwd) => {
    const chain = 3_000_000;
    let fats = 1;
    let difat = 0;
    for (;;) {
      difat = fats > 109 ? Math.ceil((fats - 109) / 127) : 0;
      if (fats * 128 >= fats + difat + 1 + chain) break;
      fats++;
    }
    const dir = fats + difat;
    const c0 = dir + 1;
    const table = new Uint32Array(fats * 128).fill(FREE);
    for (let i = 0; i < fats; i++) table[i] = FATSECT;
    for (let i = 0; i < difat; i++) table[fats + i] = DIFSECT;
    table[dir] = END;
    for (let i = 0; i < chain; i++) table[c0 + i] = i + 1 < chain ? c0 + i + 1 : END;
    const header = Buffer.alloc(512);
    Buffer.from("d0cf11e0a1b11ae1", "hex").copy(header, 0);
    header.writeUInt16LE(3, 0x1a);
    header.writeUInt16LE(0xfffe, 0x1c);
    header.writeUInt16LE(9, 0x1e);
    header.writeUInt16LE(6, 0x20);
    [fats, dir, 0, 4096, END, 0, difat ? fats : END, difat].forEach((v, i) => header.writeUInt32LE(v >>> 0, 0x2c + 4 * i));
    for (let i = 0; i < 109; i++) header.writeUInt32LE(i < fats ? i : FREE, 0x4c + 4 * i);
    const difatSectors: Buffer[] = [];
    for (let k = 0; k < difat; k++) {
      const s = Buffer.alloc(512);
      for (let i = 0; i < 127; i++) {
        const n = 109 + k * 127 + i;
        s.writeUInt32LE(n < fats ? n : FREE, 4 * i);
      }
      s.writeUInt32LE(k + 1 < difat ? fats + k + 1 : END, 508);
      difatSectors.push(s);
    }
    const d = Buffer.alloc(512);
    dirEntry("Root Entry", 5, FREE, FREE, 1, END, 0).copy(d, 0);
    dirEntry("s", 2, FREE, FREE, FREE, c0, chain * 512).copy(d, 128);
    const head = Buffer.concat([header, Buffer.from(table.buffer), ...difatSectors, d]);
    const path = join(cwd, "work", "x.automaticDestinations-ms");
    await writeFile(path, head);
    await truncate(path, 512 + (c0 + chain) * 512); // the chain's sectors are a sparse hole: 1.5 GB that is not on the disk
    const m = measured(cwd, { path: "work/x.automaticDestinations-ms", max_seconds: 2 });
    assert.ok(m.rssMb < 250, `peak ${m.rssMb.toFixed(0)} MB`);
    assert.ok(m.seconds < 15, `${m.seconds.toFixed(1)} s against a clock of 2`);
    assert.equal(m.answer.status, "partial");
    const box = await containerOf(cwd, m.answer);
    const text = box.problems.join(" | ");
    if (/time limit/.test(text)) assert.match(m.answer.status_basis, /time limit/);
    else assert.match(text, /no stream named DestList/);
  });
});

// ---- a container that reads and does not hold together --------------------------------------------------------------------------------

/** The byte offset of the directory entry named `name` in a well-formed file made by the fixture (its directory is one chain: the header gives the first sector). */
function entryAt(file: Buffer, name: string): number {
  const dirStart = file.readUInt32LE(0x30);
  for (let i = 0; i < 64; i++) {
    const at = 512 + dirStart * 512 + i * 128;
    const len = file.readUInt16LE(at + 64);
    if (len > 2 && file.subarray(at, at + len - 2).toString("utf16le") === name) return at;
  }
  throw new Error(`no directory entry ${name}`);
}
/** The byte offset of the FAT entry for sector `n` (the fixture has one FAT sector, the first sector of the file after the header). */
const fatEntry = (file: Buffer, n: number): number => 512 + file.readUInt32LE(0x4c) * 512 + 4 * n;

const DAMAGES: Array<[string, (f: Buffer) => void, RegExp]> = [
  ["two streams that share mini sectors (the first stream starts where the DestList does)", (f) => f.writeUInt32LE(f.readUInt32LE(entryAt(f, "DestList") + 116), entryAt(f, "1") + 116), /shares mini sector \d+ with stream/],
  ["a DestList entry whose name length is zero (the DestList is no longer found)", (f) => f.writeUInt16LE(0, entryAt(f, "DestList") + 64), /name length of 0 bytes/],
  ["a stream entry whose name length is 2 (a name of no character)", (f) => f.writeUInt16LE(2, entryAt(f, "2") + 64), /name length of 2 bytes/],
  ["a FAT sector that the FAT does not mark as one", (f) => f.writeUInt32LE(END, fatEntry(f, 0)), /not marked as a FAT sector/],
  ["a directory tree that names an entry that is not allocated", (f) => { f[entryAt(f, "2") + 66] = 0; }, /not allocated/],
  ["a directory tree that names the root again", (f) => f.writeUInt32LE(0, entryAt(f, "2") + 68), /loops, or names an entry twice/],
  ["a stream with a child pointer", (f) => f.writeUInt32LE(3, entryAt(f, "1") + 76), /has a child pointer/],
  ["a root entry whose mini stream is smaller than the sectors the streams use", (f) => f.writeUInt32LE(4, entryAt(f, "Root Entry") + 120), /past the end of the mini stream, which the root entry declares as 4 bytes/],
  ["a stream size with high bits set in a version 3 file", (f) => f.writeUInt32LE(1, entryAt(f, "2") + 124), /high 32 bits are zero/],
  ["a header that gives directory sectors in a version 3 file", (f) => f.writeUInt32LE(5, 0x28), /keeps zero there/],
  ["a mini stream cutoff of 100", (f) => f.writeUInt32LE(100, 0x38), /not the 4096/],
  ["an allocated entry the tree never reaches", (f) => f.writeUInt32LE(FREE, entryAt(f, "1") + 72), /never reaches it/],
];

test("a container that reads but does not hold together is partial, with the one problem that was made named", async () => {
  await withCwd(async (cwd) => {
    const good = AUTO();
    await writeFile(join(cwd, "work", "good.automaticDestinations-ms"), good);
    const ok = body<Answer>(await tool("lnk_jumplist", cwd, { path: "work/good.automaticDestinations-ms" }));
    assert.equal(ok.status, "complete", ok.status_basis);
    for (const [label, damage, why] of DAMAGES) {
      const f = Buffer.from(good);
      damage(f);
      await writeFile(join(cwd, "work", "x.automaticDestinations-ms"), f);
      const out = body<Answer>(await tool("lnk_jumplist", cwd, { path: "work/x.automaticDestinations-ms" }));
      assert.equal(out.status, "partial", `${label}: ${out.status_basis}`);
      const box = await containerOf(cwd, out);
      assert.equal(box.consistent, false, label);
      assert.match(box.problems.join(" | "), why, label);
    }
  });
});

test("a DestList entry that names a stream that is no shell link is a container problem, and so are two entries that name one stream", async () => {
  await withCwd(async (cwd) => {
    const notLink = cfb([{ name: "1", data: LNK }, { name: "2", data: Buffer.alloc(200, 0x5a) }, { name: "DestList", data: entries([1, 2]) }]);
    await writeFile(join(cwd, "work", "a.automaticDestinations-ms"), notLink);
    const a = body<Answer>(await tool("lnk_jumplist", cwd, { path: "work/a.automaticDestinations-ms" }));
    assert.equal(a.status, "partial");
    const box = await containerOf(cwd, a);
    assert.match(box.problems.join(" | "), /DestList entry 2 names stream '2', which is not a shell link \(its first bytes are 5a5a5a5a5a5a5a5a\)/);
    const entry = (await rowsOf(cwd, a)).find((r) => r.row === "destlist_entry" && r.entry_number === 2)!;
    assert.equal(entry.stream_is_link, false);
    // Two entries of one number: the stream is named twice.
    await writeFile(join(cwd, "work", "b.automaticDestinations-ms"), cfb([{ name: "1", data: LNK }, { name: "DestList", data: entries([1, 1]) }]));
    const b = body<Answer>(await tool("lnk_jumplist", cwd, { path: "work/b.automaticDestinations-ms" }));
    assert.equal(b.status, "partial");
    assert.match((await containerOf(cwd, b)).problems.join(" | "), /both name stream '1'/);
  });
});

test("a compound file with streams and no DestList is partial; one with no stream at all (what Windows leaves for an empty jump list) is complete", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "a.automaticDestinations-ms"), cfb([{ name: "1", data: LNK }]));
    const a = body<Answer>(await tool("lnk_jumplist", cwd, { path: "work/a.automaticDestinations-ms" }));
    assert.equal(a.status, "partial");
    assert.match((await containerOf(cwd, a)).problems.join(" | "), /no stream named DestList/);
    const empty = cfb([]);
    await writeFile(join(cwd, "work", "e.automaticDestinations-ms"), empty);
    const e = body<Answer>(await tool("lnk_jumplist", cwd, { path: "work/e.automaticDestinations-ms" }));
    assert.equal(e.status, "complete", e.status_basis);
    const file = (await rowsOf(cwd, e)).find((r) => r.row === "file")!;
    assert.equal(file.kind, "compound file without a DestList");
  });
});

// ---- a DestList is bounded in the work it asks for and the memory it holds ------------------------------------------------------------

/** A version 1 DestList of `n` entries (114 bytes each: the path is empty) that name streams numbered from `first`, so none of them need exist. */
const manyEntries = (n: number, first = 0x100000): Buffer => destList(1, Array.from({ length: n }, (_v, i) => ({ number: first + i, host: "", filetime: FILETIME_A, pin: -1, path: "" })));

test("6,000 streams and 30,000 DestList entries that name none of them are matched in linear time: the entries are looked up by name, not by a pass over every stream", async () => {
  await withCwd(async (cwd) => {
    const streams = [{ name: "DestList", data: manyEntries(30_000) }, ...Array.from({ length: 6000 }, (_v, i) => ({ name: (0x10000 + i).toString(16), data: Buffer.alloc(0) }))];
    await writeFile(join(cwd, "work", "x.automaticDestinations-ms"), cfb(streams));
    const m = measured(cwd, { path: "work/x.automaticDestinations-ms", max_seconds: 10 });
    assert.ok(m.cpu < 8, `${m.cpu.toFixed(1)} s of CPU for 1.8e8 stream-by-entry steps if they are all made (the host's load is not counted)`);
    assert.equal(m.answer.status, "partial");
    const rows = await rowsOf(cwd, m.answer);
    assert.equal(rows.filter((r) => r.row === "destlist_entry").length, 30_000);
    assert.equal(rows.filter((r) => r.row === "stream").length, 6001);
    assert.ok(rows.filter((r) => r.row === "destlist_entry").every((r) => r.stream_present === false));
    const dl = rows.find((r) => r.row === "destlist")!;
    assert.equal(dl.entries_read, 30_000);
    assert.equal(dl.entries_not_read_from, undefined, "under the bound, nothing is left unread");
  });
});

/** A container whose only stream is a DestList of `n` entries written in sectors that are in reverse order in the file: every sector is an extent of its own. */
function reversedDestList(n: number): { file: Buffer; offsetOf: (streamOffset: number) => number; sectors: number } {
  const data = manyEntries(n);
  const D = Math.ceil(data.length / 512);
  let fats = 1;
  while (fats * 128 < fats + 1 + D) fats++;
  assert.ok(fats <= 109);
  const c0 = fats + 1;
  const physical = (k: number): number => c0 + (D - 1 - k);
  const table = new Uint32Array(fats * 128).fill(FREE);
  for (let i = 0; i < fats; i++) table[i] = FATSECT;
  table[fats] = END;
  for (let k = 0; k < D; k++) table[physical(k)] = k + 1 < D ? physical(k + 1) : END;
  const header = Buffer.alloc(512);
  Buffer.from("d0cf11e0a1b11ae1", "hex").copy(header, 0);
  header.writeUInt16LE(3, 0x1a);
  header.writeUInt16LE(0xfffe, 0x1c);
  header.writeUInt16LE(9, 0x1e);
  header.writeUInt16LE(6, 0x20);
  [fats, fats, 0, 4096, END, 0, END, 0].forEach((v, i) => header.writeUInt32LE(v >>> 0, 0x2c + 4 * i));
  for (let i = 0; i < 109; i++) header.writeUInt32LE(i < fats ? i : FREE, 0x4c + 4 * i);
  const file = Buffer.alloc(512 + (c0 + D) * 512);
  header.copy(file, 0);
  Buffer.from(table.buffer).copy(file, 512);
  dirEntry("Root Entry", 5, FREE, FREE, 1, END, 0).copy(file, 512 + fats * 512);
  dirEntry("DestList", 2, FREE, FREE, FREE, physical(0), data.length).copy(file, 512 + fats * 512 + 128);
  for (let k = 0; k < D; k++) data.copy(file, 512 + physical(k) * 512, k * 512, Math.min(data.length, (k + 1) * 512));
  return { file, offsetOf: (s) => 512 + physical(Math.floor(s / 512)) * 512 + (s % 512), sectors: D };
}

test("a DestList of 4,000 fragments and 20,000 entries is mapped to the file by bisection: each entry costs the fragments it touches, not all of them", async () => {
  await withCwd(async (cwd) => {
    const r = reversedDestList(20_000);
    assert.ok(r.sectors > 4000);
    await writeFile(join(cwd, "work", "x.automaticDestinations-ms"), r.file);
    const m = measured(cwd, { path: "work/x.automaticDestinations-ms", max_seconds: 10 });
    assert.ok(m.cpu < 8, `${m.cpu.toFixed(1)} s of CPU (a pass over every fragment for every entry is 9e7 steps)`);
    const rows = await rowsOf(cwd, m.answer);
    const entriesOut = rows.filter((r2) => r2.row === "destlist_entry");
    assert.equal(entriesOut.length, 20_000);
    // Entry 7 lies inside a sector (114 bytes each: 32 + 114 * 6 = 716 is in the second sector); entry 3 starts at 32 + 228 = 260 and ends at 374, inside the first.
    for (const i of [0, 2, 3, 4, 5, 6, 7, 9_999, 19_999]) {
      const start = 32 + 114 * i;
      const row = entriesOut[i];
      assert.equal(row.stream_offset, start);
      const inOne = Math.floor(start / 512) === Math.floor((start + 0x82 - 1) / 512);
      assert.equal(row.container_contiguous, inOne, `entry ${i + 1}`);
      assert.equal(row.container_offset, r.offsetOf(start), `entry ${i + 1}`);
    }
    assert.ok(entriesOut.some((e) => e.container_contiguous === false), "the reversed sectors really break an entry that crosses one");
  });
});

test("a DestList of 60,000 entries is read to its first 50,000: the rest is named by where it starts and how long it is", async () => {
  await withCwd(async (cwd) => {
    const dl = manyEntries(60_000);
    await writeFile(join(cwd, "work", "x.automaticDestinations-ms"), cfb([{ name: "DestList", data: dl }]));
    const m = measured(cwd, { path: "work/x.automaticDestinations-ms" });
    assert.ok(m.rssMb < 150, `peak ${m.rssMb.toFixed(0)} MB`);
    assert.equal(m.answer.status, "partial");
    const rows = await rowsOf(cwd, m.answer);
    const row = rows.find((r) => r.row === "destlist")!;
    assert.equal(row.entries_read, 50_000);
    assert.equal(row.entries_claimed, 60_000);
    assert.equal(row.entries_not_read_from, 32 + 114 * 50_000);
    assert.match(row.problems.join(" | "), /holds more than the 50000 entries this tool reads: the first 50000 are read, and the rest \(from stream offset 5700032, 1140000 bytes\) is not/);
    assert.equal(rows.filter((r) => r.row === "destlist_entry").length, 50_000);
    assert.equal(m.answer.container_problems, 2, "the cut DestList and the entries that name no stream");
  });
});

test("a stream whose DestList entry lies past the bound is not called an orphan as if the DestList had been read whole", async () => {
  await withCwd(async (cwd) => {
    const dl = Buffer.concat([manyEntries(50_000, 0x200000), manyEntries(1, 0x1)]);
    dl.writeUInt32LE(50_001, 4);
    const f = cfb([{ name: "DestList", data: dl }, { name: "1", data: LNK }]);
    await writeFile(join(cwd, "work", "x.automaticDestinations-ms"), f);
    const out = body<Answer>(await tool("lnk_jumplist", cwd, { path: "work/x.automaticDestinations-ms" }));
    assert.equal(out.status, "partial");
    const rows = await rowsOf(cwd, out);
    const s = rows.find((r) => r.row === "stream" && r.name === "1")!;
    assert.equal(s.in_destlist, null);
    assert.match(s.orphan, /none of the 50000 DestList entries read has an entry for \(the DestList was read only to its first 50000 entries\)/);
  });
});

test("the clock is looked at while the DestList entries are matched to the streams: when it runs out the entries after that point have no row, the container says so, and the streams are not examined", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "x.automaticDestinations-ms"), cfb([{ name: "DestList", data: manyEntries(1500) }, { name: "1", data: LNK }]));
    // The tool is loaded as a module and its clock is made to run out when the 1,000th entry is mapped to the file (a real one would need a file that takes
    // seconds); everything else is the tool as it runs.
    const code = [
      "import importlib.util, io, json, sys",
      "spec = importlib.util.spec_from_file_location('lnkrun', sys.argv[1])",
      "m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)",
      "state = {'n': 0, 'out': False}",
      "real = m.map_range",
      "def counted(*a):",
      "    state['n'] += 1",
      "    if state['n'] >= 1000: state['out'] = True",
      "    return real(*a)",
      "m.map_range = counted",
      "m.out_of_time = lambda: state['out']",
      "m.main()",
    ].join("\n");
    const r = spawnSync("python3", ["-c", code, join(WIN, "lnk_jumplist", "run.py")], { cwd, encoding: "utf8", input: JSON.stringify({ path: "work/x.automaticDestinations-ms" }), env: { ...process.env, AGENT_ID: "s1" }, maxBuffer: 1 << 26 });
    assert.equal(r.status, 0, r.stderr);
    const out = JSON.parse(r.stdout) as Answer;
    assert.equal(out.status, "partial");
    assert.match(out.status_basis, /time limit/);
    const box = await containerOf(cwd, out);
    assert.match(box.problems.join(" | "), /the time limit was reached after 1023 of the 1500 DestList entries were matched to the streams: the entries after them have no row/);
    const rows = await rowsOf(cwd, out);
    assert.equal(rows.filter((x) => x.row === "destlist_entry").length, 1023);
    assert.equal(rows.filter((x) => x.row === "stream").length, 0, "the streams after a time limit are not examined, and none is called an orphan");
  });
});

test("jumplist reads a DestList to its first 50,000 entries and names the rest; a DestList of exactly 50,000 is read whole and has no problem", { skip: pythonCanImport("olefile") ? false : "olefile is not installed on this host" }, async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "exact.automaticDestinations-ms"), cfb([{ name: "DestList", data: manyEntries(50_000) }]));
    await writeFile(join(cwd, "work", "over.automaticDestinations-ms"), cfb([{ name: "DestList", data: manyEntries(50_001) }]));
    const exact = body<Answer>(await tool("jumplist", cwd, { path: "work/exact.automaticDestinations-ms", limit: 3 }));
    const exactFile = exact.files[0] as Answer;
    assert.equal(exactFile.entry_count, 50_000);
    assert.deepEqual(exactFile.problems, []);
    assert.equal(exact.status, "complete");
    const over = body<Answer>(await tool("jumplist", cwd, { path: "work/over.automaticDestinations-ms", limit: 3 }));
    const overFile = over.files[0] as Answer;
    assert.equal(overFile.entry_count, 50_000);
    assert.equal(overFile.entries_not_read_from, 32 + 114 * 50_000);
    assert.match(overFile.problems.join(" | "), /holds more than the 50000 entries this tool reads: the first 50000 are read, and the rest \(from stream offset 5700032, 114 bytes\) is not/);
    assert.equal(over.status, "partial");
  });
});
