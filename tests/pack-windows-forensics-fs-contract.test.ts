/**
 * The four file-system readers (mft_records, usn_journal, indx_carve, recyclebin_i) against the tool contract (docs/packs.md, section 8), with the
 * helpers of tests/windows-tool-contract.ts: a stop signal at four moments gives one JSON document and no hidden file, a zero deadline gives a
 * partial answer that names the clock, a rerun with a smaller result never replaces the larger file, and an argument of the wrong type gets JSON.
 * Also what only these tools can show: indx_carve says partial when it found no block, mft_records says partial when the forced record size is
 * contradicted by the file, a name expression that would take forever is stopped, with_resident is held to a secret-output job, and the four carry
 * the PLACE, PAGE and STOP blocks of regkv byte for byte.
 *
 * Fixtures follow the layouts (an $MFT record: "FILE", update sequence array, attributes, end marker; an INDX block: node header and index entries;
 * a USN_RECORD_V2; a $I file: header, size, FILETIME, character count, UTF-16LE path), never a tool's output.
 *
 * Red check: WINDOWS_PACK_TOOLS=<a copy of the tools before the fixes> node --experimental-strip-types --test tests/pack-windows-forensics-fs-contract.test.ts
 */
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { readdir } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { withCwd } from "./tool-library-harness.ts";
import { WIN, u16z } from "./windows-pack-harness.ts";
import {
  assertJsonAnswer, assertStopped, fuzzTool, manifestOf, rerunSmaller, runTool, stopAt, typeConfused, withDeadline, type Moment, type StopSignal,
} from "./windows-tool-contract.ts";

const SIGNALS: StopSignal[] = ["SIGTERM", "SIGINT", "SIGHUP"];
const TIME = 133_500_000_000_000_001n;
type Answer = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

// --- fixtures -------------------------------------------------------------------------------------------------------------------------

function attr(type: number, content: Buffer): Buffer {
  let total = 0x18 + content.length;
  total += (8 - (total % 8)) % 8;
  const b = Buffer.alloc(total);
  b.writeUInt32LE(type, 0);
  b.writeUInt32LE(total, 4);
  b.writeUInt32LE(content.length, 0x10);
  b.writeUInt16LE(0x18, 0x14);
  content.copy(b, 0x18);
  return b;
}

function mftRecord(number: number, name: string, size = 1024): Buffer {
  const si = Buffer.alloc(0x48);
  for (let i = 0; i < 4; i++) si.writeBigUInt64LE(TIME, i * 8);
  const fn = Buffer.alloc(0x42 + name.length * 2);
  fn.writeBigUInt64LE(5n | (5n << 48n), 0);
  for (let i = 0; i < 4; i++) fn.writeBigUInt64LE(TIME, 8 + i * 8);
  fn[0x40] = name.length;
  fn[0x41] = 1;
  Buffer.from(name, "utf16le").copy(fn, 0x42);
  const b = Buffer.alloc(size);
  const units = size / 512;
  b.write("FILE", 0, "latin1");
  b.writeUInt16LE(0x30, 4);
  b.writeUInt16LE(units + 1, 6);
  b.writeUInt16LE(1, 0x10);
  b.writeUInt16LE(0x38, 0x14);
  b.writeUInt16LE(1, 0x16);
  b.writeUInt32LE(number, 0x2c);
  let at = 0x38;
  for (const a of [attr(0x10, si), attr(0x30, fn)]) {
    a.copy(b, at);
    at += a.length;
  }
  b.writeUInt32LE(0xffffffff, at);
  b.writeUInt32LE(at + 8, 0x18);
  b.writeUInt32LE(size, 0x1c);
  const sequence = Buffer.from([0x0b, 0x00]);
  sequence.copy(b, 0x30);
  for (let i = 1; i <= units; i++) {
    const end = i * 512 - 2;
    b.copy(b, 0x30 + i * 2, end, end + 2);
    sequence.copy(b, end);
  }
  return b;
}

/** An $MFT of `count` records. */
function mftFile(count: number, name = (i: number) => `file${i}.txt`): Buffer {
  const out = Buffer.alloc(count * 1024);
  for (let i = 0; i < count; i++) mftRecord(i, name(i)).copy(out, i * 1024);
  return out;
}

function usnV2(name: string, usn: bigint): Buffer {
  const text = Buffer.from(name, "utf16le");
  let length = 0x3c + text.length;
  length += (8 - (length % 8)) % 8;
  const r = Buffer.alloc(length);
  r.writeUInt32LE(length, 0);
  r.writeUInt16LE(2, 4);
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

function usnFile(count: number): Buffer {
  const one = usnV2("report.docx", 1n);
  const out = Buffer.alloc(count * one.length);
  for (let i = 0; i < count; i++) {
    one.copy(out, i * one.length);
    out.writeBigUInt64LE(BigInt(i) * 112n, i * one.length + 0x18);
  }
  return out;
}

function indxName(name: string): Buffer {
  const b = Buffer.alloc(0x42 + 2 * name.length);
  b.writeBigUInt64LE(5n | (1n << 48n), 0);
  for (let i = 0; i < 4; i++) b.writeBigUInt64LE(TIME, 8 + i * 8);
  b.writeUInt32LE(0x20, 0x38);
  b[0x40] = name.length;
  b[0x41] = 1;
  Buffer.from(name, "utf16le").copy(b, 0x42);
  return b;
}

function indxEntry(ref: bigint, content: Buffer, flags = 0): Buffer {
  let length = 0x10 + content.length;
  length += (8 - (length % 8)) % 8;
  const b = Buffer.alloc(length);
  b.writeBigUInt64LE(ref, 0);
  b.writeUInt16LE(length, 8);
  b.writeUInt16LE(content.length, 10);
  b.writeUInt16LE(flags, 12);
  content.copy(b, 0x10);
  return b;
}

function indxBlock(names: string[]): Buffer {
  const b = Buffer.alloc(4096);
  b.write("INDX", 0, "latin1");
  b.writeUInt16LE(0x28, 4);
  b.writeUInt16LE(9, 6);
  let at = 0x40;
  for (const e of [...names.map((n, i) => indxEntry(BigInt(100 + i) | (1n << 48n), indxName(n))), indxEntry(0n, Buffer.alloc(0), 0x02)]) {
    e.copy(b, at);
    at += e.length;
  }
  b.writeUInt32LE(0x40 - 0x18, 0x18);
  b.writeUInt32LE(at - 0x18, 0x1c);
  b.writeUInt32LE(4096 - 0x18, 0x20);
  const sequence = Buffer.from([0x07, 0x00]);
  sequence.copy(b, 0x28);
  for (let i = 1; i < 9; i++) {
    const end = i * 512 - 2;
    b.copy(b, 0x28 + i * 2, end, end + 2);
    sequence.copy(b, end);
  }
  return b;
}

function indxFile(blocks: number, per = 6): Buffer {
  return Buffer.concat(Array.from({ length: blocks }, (_, b) => indxBlock(Array.from({ length: per }, (_, i) => `doc${b}-${i}.txt`))));
}

function iRecord(path: string): Buffer {
  const text = u16z(path);
  const b = Buffer.alloc(0x1c + text.length);
  b.writeBigUInt64LE(2n, 0);
  b.writeBigUInt64LE(10n, 8);
  b.writeBigUInt64LE(TIME, 0x10);
  b.writeUInt32LE(path.length + 1, 0x18);
  text.copy(b, 0x1c);
  return b;
}

function recycleDir(cwd: string, count: number): string {
  const dir = join(cwd, "work", "bin", "S-1-5-21-1-2-3-1001");
  mkdirSync(dir, { recursive: true });
  const one = iRecord("C:\\Users\\a\\Documents\\report.docx");
  for (let i = 0; i < count; i++) writeFileSync(join(dir, `$I${String(i).padStart(6, "0")}.docx`), one);
  return "work/bin";
}

// --- the four tools as a table --------------------------------------------------------------------------------------------------------

type Case = {
  tool: string;
  /** Writes an input of n records (at a fixed path, over an earlier one) and returns the arguments, with a one-row inline page so that a file is written. */
  make: (cwd: string, n: number) => Record<string, unknown>;
  small: number;
  large: number;
  /** A page size that makes the answer larger than the pipe. */
  printArgs: Record<string, unknown>;
};

function put(cwd: string, rel: string, bytes: Buffer): string {
  mkdirSync(join(cwd, "work"), { recursive: true });
  writeFileSync(join(cwd, rel), bytes);
  return rel;
}

const CASES: Case[] = [
  { tool: "mft_records", make: (cwd, n) => ({ path: put(cwd, "work/mft.bin", mftFile(n)), limit: 1 }), small: 300, large: 40_000, printArgs: { limit: 2000 } },
  { tool: "usn_journal", make: (cwd, n) => ({ path: put(cwd, "work/usn.bin", usnFile(n)), limit: 1 }), small: 300, large: 400_000, printArgs: { limit: 10000 } },
  { tool: "indx_carve", make: (cwd, n) => ({ path: put(cwd, "work/i30.bin", indxFile(n)), limit: 1 }), small: 40, large: 6_000, printArgs: { limit: 10000 } },
  {
    tool: "recyclebin_i",
    make: (cwd, n) => {
      rmSync(join(cwd, "work", "bin"), { recursive: true, force: true });
      return { path: recycleDir(cwd, n), limit: 1 };
    },
    small: 120, large: 25_000, printArgs: { limit: 10000 },
  },
];

for (const c of CASES) {
  test(`${c.tool}: a deadline of zero ends in a partial answer that names the clock`, async () => {
    await withCwd(async (cwd) => {
      const answer = assertJsonAnswer(await runTool(withDeadline(c.tool, 0), cwd, c.make(cwd, c.small)), c.tool);
      assert.equal(answer.status, "partial");
      assert.match(String(answer.status_basis), /clock/);
      assert.equal(answer.stopped_by_time_limit, true);
    });
  });

  for (const signal of SIGNALS) {
    for (const moment of ["early", "temp"] as Moment[]) {
      test(`${c.tool}: ${signal} at ${moment} gives one JSON document, exit 128 plus the signal and no hidden file`, async () => {
        await withCwd(async (cwd) => {
          const run = await stopAt(c.tool, c.make(cwd, c.large), {}, moment, signal, { cwd });
          assert.equal(assertStopped(run, signal).answered, true);
        });
      });
    }
  }

  test(`${c.tool}: a signal while the answer is being written does not cut it`, async () => {
    await withCwd(async (cwd) => {
      const args = { ...c.make(cwd, c.large), ...c.printArgs };
      const run = await stopAt(c.tool, args, {}, "print", "SIGTERM", { cwd });
      const got = assertStopped(run, "SIGTERM");
      assert.equal(got.answered, false, "the answer was written whole, then the tool ended by itself");
      assert.ok(run.stdout.length > 100_000, `${run.stdout.length} bytes`);
    });
  });

  test(`${c.tool}: a rerun with a smaller result keeps the first file and names the second under -2`, async () => {
    await withCwd(async (cwd) => {
      const args = c.make(cwd, 60);
      const out = await rerunSmaller(c.tool, args, args, {}, { cwd, between: () => void c.make(cwd, 8) });
      assert.ok(out.added.length >= 1);
    });
  });

  test(`${c.tool}: arguments of the wrong type (250 sets) are all answered in JSON`, async () => {
    await withCwd(async (cwd) => {
      const { limit: _limit, ...base } = c.make(cwd, c.small);
      const seed = 2026;
      const statuses = await fuzzTool(c.tool, typeConfused(manifestOf(c.tool), 250, seed, base), seed, { cwd });
      assert.ok((statuses.failed ?? 0) > 0, JSON.stringify(statuses));
    });
  });
}

test("mft_records, usn_journal and indx_carve: a name expression that takes exponential time is stopped, and the answer is partial", async () => {
  await withCwd(async (cwd) => {
    const long = "a".repeat(250) + "!";
    const cases: Array<[string, Record<string, unknown>]> = [
      ["mft_records", { path: put(cwd, "work/mft.bin", mftFile(3, () => long.slice(0, 200) + "!")), name: "(a+)+$" }],
      ["usn_journal", { path: put(cwd, "work/usn.bin", Buffer.concat([usnV2(long, 1n), usnV2(long, 2n)])), name: "(a+)+$" }],
      ["indx_carve", { path: put(cwd, "work/i30.bin", indxBlock([long.slice(0, 200) + "!"])), name: "(a+)+$" }],
    ];
    for (const [tool, args] of cases) {
      const started = Date.now();
      const run = await runTool(tool, cwd, args);
      const answer = assertJsonAnswer(run, tool);
      assert.ok(Date.now() - started < 20_000, `${tool} took ${Date.now() - started} ms`);
      assert.equal(answer.status, "partial", `${tool}: ${JSON.stringify(answer).slice(0, 300)}`);
      assert.match(String(answer.status_basis), /expression/, tool);
    }
  });
});

test("mft_records: a forced record_size twice the real one is a problem and the answer is partial; 2**62 is refused as JSON", async () => {
  await withCwd(async (cwd) => {
    const path = put(cwd, "work/mft.bin", mftFile(40));
    const twice = assertJsonAnswer(await runTool("mft_records", cwd, { path, record_size: 2048 }), "2048") as Answer;
    assert.equal(twice.status, "partial");
    assert.match(String(twice.status_basis), /problem/);
    assert.ok(twice.problems.some((p: Answer) => /record_size argument \(2048\) disagrees/.test(p.why)), JSON.stringify(twice.problems).slice(0, 300));
    const right = assertJsonAnswer(await runTool("mft_records", cwd, { path, record_size: 1024 }), "1024");
    assert.equal(right.status, "complete");
    assert.equal(right.records_parsed, 40);
    const huge = await runTool("mft_records", cwd, { path, record_size: 2 ** 62 });
    assert.notEqual(huge.code, 0);
    assert.equal(assertJsonAnswer(huge, "2**62").status, "failed");
  });
});

test("indx_carve: a text file, 4 KB of random bytes, 8 KB of zeros and INDX with 8 bytes find no block, and none is complete", async () => {
  await withCwd(async (cwd) => {
    const inputs: Array<[string, Buffer]> = [
      ["text", Buffer.from("this is a text file, not an index\n".repeat(50))],
      ["random", randomBytes(4096).fill(0x41, 0, 8)],
      ["zeros", Buffer.alloc(8192)],
      ["short", Buffer.concat([Buffer.from("INDX"), Buffer.alloc(8, 1)])],
    ];
    for (const [label, bytes] of inputs) {
      const answer = assertJsonAnswer(await runTool("indx_carve", cwd, { path: put(cwd, `work/${label}.bin`, bytes) }), label) as Answer;
      assert.equal(answer.status, "partial", `${label}: ${JSON.stringify(answer).slice(0, 300)}`);
      assert.notEqual(answer.status, "complete");
      assert.ok(answer.problem_count >= 1, label);
    }
    // a real block is still complete
    const real = assertJsonAnswer(await runTool("indx_carve", cwd, { path: put(cwd, "work/real.bin", indxFile(3)) }), "real");
    assert.equal(real.status, "complete");
    assert.match(String(real.status_basis), /every INDX signature/);
  });
});

test("mft_records: with_resident is declared secret output and refused as JSON, before anything is made, outside such a job", async () => {
  await withCwd(async (cwd) => {
    const path = put(cwd, "work/mft.bin", mftFile(30));
    assert.deepEqual(manifestOf("mft_records") as unknown, JSON.parse(readFileSync(join(WIN, "mft_records", "manifest.json"), "utf8")));
    const manifest = JSON.parse(readFileSync(join(WIN, "mft_records", "manifest.json"), "utf8")) as Answer;
    assert.deepEqual(manifest.secret_output, { when_args: ["with_resident"] });
    assert.equal(manifest.params.with_resident.type, "boolean");
    const refused = await runTool("mft_records", cwd, { path, with_resident: true, limit: 1 }, { SECRET_OUTPUT: "0" });
    assert.notEqual(refused.code, 0);
    assert.equal(assertJsonAnswer(refused, "with_resident").status, "failed");
    assert.deepEqual((await readdir(join(cwd, "work"))).sort(), ["mft.bin"], "nothing was created");
    const allowed = assertJsonAnswer(await runTool("mft_records", cwd, { path, with_resident: true }, { SECRET_OUTPUT: "1" }), "secret");
    assert.equal(allowed.status, "complete");
  });
});

test("recyclebin_i walks a name that is not UTF-8 and answers one JSON document (a file system that keeps raw names; skipped elsewhere)", async (t) => {
  await withCwd(async (cwd) => {
    const dir = join(cwd, "work", "bin", "S-1-5-21-1-2-3-1001");
    mkdirSync(dir, { recursive: true });
    try {
      writeFileSync(Buffer.concat([Buffer.from(dir + "/$I"), Buffer.from([0xff, 0xfe, 0x80]), Buffer.from(".docx")]), iRecord("C:\\a.docx"));
    } catch {
      t.skip("this file system does not keep names that are not UTF-8");
      return;
    }
    const names = await readdir(dir);
    if (names.length !== 1 || !/\ufffd|[\udc80-\udcff]/.test(names[0])) {
      t.skip("this file system rewrote the name");
      return;
    }
    const answer = assertJsonAnswer(await runTool("recyclebin_i", cwd, { path: "work/bin", limit: 1 }), "raw name");
    assert.equal(answer.status, "complete");
    assert.equal(answer.parsed, 1);
  });
});

test("mft_records, usn_journal, indx_carve and recyclebin_i carry the PLACE, PAGE and STOP blocks of regkv, byte for byte", () => {
  const block = (text: string, name: string): string => {
    const begin = `# BEGIN SHARED ${name}`;
    const end = `# END SHARED ${name}`;
    assert.ok(text.includes(begin), `no ${begin}`);
    return text.slice(text.indexOf(begin), text.indexOf(end) + end.length);
  };
  const digest = (s: string): string => createHash("sha256").update(s).digest("hex");
  const reg = readFileSync(join(WIN, "regkv", "run.py"), "utf8");
  for (const tool of CASES.map((c) => c.tool)) {
    const text = readFileSync(join(WIN, tool, "run.py"), "utf8");
    for (const name of ["PLACE", "PAGE", "STOP"]) assert.equal(digest(block(text, name)), digest(block(reg, name)), `${tool} ${name}`);
    assert.doesNotMatch(text, /\bLosslessPage\(/, `${tool} pages through NoReplacePage`);
    assert.match(text, /^DEADLINE_SECONDS = \d+ /m, tool);
  }
});
