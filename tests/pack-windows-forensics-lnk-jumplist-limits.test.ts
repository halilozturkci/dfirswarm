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
import { WIN, body, tool } from "./windows-pack-harness.ts";
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
function measured(cwd: string, args: unknown): { answer: Answer; rssMb: number; seconds: number } {
  const code = [
    "import json, os, resource, subprocess, sys, time",
    "t = time.time()",
    "p = subprocess.run([sys.executable, sys.argv[1]], input=sys.argv[2], capture_output=True, text=True, env={**os.environ, 'AGENT_ID': 's1'})",
    "ru = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss",
    "print(json.dumps({'out': p.stdout, 'err': p.stderr[-300:], 'mb': ru / (1 << 20) if sys.platform == 'darwin' else ru / 1024, 'sec': time.time() - t}))",
  ].join("\n");
  const r = spawnSync("python3", ["-c", code, join(WIN, "lnk_jumplist", "run.py"), JSON.stringify(args)], { cwd, encoding: "utf8", maxBuffer: 1 << 28 });
  assert.equal(r.status, 0, r.stderr);
  const w = JSON.parse(r.stdout) as { out: string; err: string; mb: number; sec: number };
  assert.doesNotMatch(w.err, /Traceback/);
  return { answer: JSON.parse(w.out) as Answer, rssMb: w.mb, seconds: w.sec };
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
