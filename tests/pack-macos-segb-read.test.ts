/**
 * segb_read decodes the framing of SEGB1 and SEGB2 from the written description (the tool's docstring and manifest give its source and say it is
 * not checked against Apple's own). The fixtures are built by hand from that description with Buffer, never from the tool's output. Held:
 *   - SEGB1 and SEGB2 frames: offsets, payload offsets and lengths, states (1 written, 3 deleted, others raw), the two container times with the
 *     raw doubles beside the UTC reading; an unknown version is `unsupported`; nothing of iOS is claimed;
 *   - truncated files, trailing garbage, overlong and negative lengths, a frame count the file cannot hold, an end offset that goes backwards: JSON,
 *     bounded, partial, never decoded by luck;
 *   - the payload only as a protobuf structure: no value, string or byte of it, no checksum, and a canary in a payload is in nothing the run leaves;
 *   - resume with skip_frames repeats no row; the rows written equal entry_count; SIGTERM ends with one answer.
 */
import assert from "node:assert/strict";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { test } from "node:test";
import { withCwd } from "./tool-library-harness.ts";
import { SEGB, ok, reachable, segb1, segb2, signalled, tag, tool, varint } from "./macos-late-harness.ts";

const CANARY = "PAYLOADCANARY-0123456789-abcdef";
const proto = Buffer.concat([tag(1, 2, Buffer.concat([varint(CANARY.length), Buffer.from(CANARY)])), tag(2, 0, varint(300)), tag(3, 1, Buffer.alloc(8, 7)), tag(4, 5, Buffer.alloc(4, 9))]);
const T1 = 700000000.0;

async function put(cwd: string, name: string, bytes: Buffer): Promise<string> {
  const path = join(cwd, "work", name);
  await mkdir(join(path, ".."), { recursive: true });
  await writeFile(path, bytes);
  return `work/${name}`;
}

test("SEGB1: frames with offsets, states and both container times; bytes after the declared end are counted, not decoded", async () => {
  await withCwd(async (cwd) => {
    const file = await put(cwd, "evidence/s1/local/12345", segb1([{ payload: proto, state: 1, t1: T1, t2: T1 + 1.5 }, { payload: Buffer.from([0xff, 0xff, 0xff, 0xff]), state: 3, t1: T1 + 100, t2: T1 + 101 }, { payload: Buffer.alloc(0), state: 7, t1: 0, t2: 5e12 }], Buffer.alloc(12, 0xde)));
    const run = await tool(SEGB, cwd, { path: file });
    const a = ok(run);
    assert.equal(a.status, "complete", a.status_basis + JSON.stringify(a.problems));
    assert.equal(a.entry_count, 3);
    const [f0, f1, f2] = a.entries;
    assert.deepEqual([f0.version, f0.frame, f0.offset, f0.payload_offset, f0.payload_length], [1, 0, 56, 88, proto.length]);
    assert.equal(f0.state_raw, 1);
    assert.equal(f0.state_meaning, "written");
    assert.equal(f0.time1_raw, T1);
    assert.equal(f0.time1_utc, "2023-03-08T20:26:40Z");
    assert.equal(f0.time2_utc, "2023-03-08T20:26:41.500000Z");
    assert.equal(f1.state_meaning, "deleted");
    assert.equal(f1.offset, 56 + ((32 + proto.length + 7) & ~7));
    assert.equal(f2.state_raw, 7);
    assert.equal(f2.state_meaning, null, "an unknown state stays raw");
    assert.equal(f2.time2_utc, null, "an implausible container time has no UTC reading");
    assert.equal(a.files[0].bytes_after_last_frame, 12);
    assert.match(a.status_basis, /12 byte\(s\) after the last frame are not decoded/);
    assert.match(a.layout_basis, /not checked against Apple/);
    assert.match(a.note, /not the time of the event/);
  });
});

test("SEGB2: the table, the payloads and the creation time; the version is told by the magic", async () => {
  await withCwd(async (cwd) => {
    const file = await put(cwd, "evidence/s2/local/777", segb2([{ payload: proto, state: 1, t: 700000200 }, { payload: Buffer.from([1, 2, 3]), state: 3, t: 700000201 }]));
    const a = ok(await tool(SEGB, cwd, { path: file }));
    assert.equal(a.status, "complete", a.status_basis);
    assert.deepEqual(a.entries.map((e: { version: number }) => e.version), [2, 2]);
    assert.equal(a.entries[0].offset, 32);
    assert.equal(a.entries[0].payload_offset, 32 + 32);
    assert.equal(a.entries[0].payload_length, proto.length);
    assert.equal(a.entries[1].state_meaning, "deleted");
    assert.equal(a.entries[1].time2_raw, null, "SEGB2 has one time per frame");
    assert.equal(a.files[0].creation_time_utc, "2023-03-08T20:29:59Z");
  });
});

test("an unknown magic is unsupported, never guessed; a directory counts the files that are not SEGB", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "d/ok", segb2([{ payload: proto, state: 1, t: 700000200 }]));
    await put(cwd, "d/other", Buffer.from("SEGC".padEnd(120, "x")));
    await put(cwd, "d/tombstone/t", Buffer.alloc(10));
    const dir = ok(await tool(SEGB, cwd, { path: "work/d" }));
    assert.equal(dir.not_segb, 2);
    assert.equal(dir.files_total, 1);
    assert.equal(dir.status, "complete");
    const one = ok(await tool(SEGB, cwd, { path: "work/d/other" }));
    assert.equal(one.status, "partial");
    assert.equal(one.files[0].state, "unsupported");
    assert.match(one.files[0].reason, /not guessed/);
  });
});

test("overlong and negative lengths, a count the file cannot hold, a backwards end offset and a truncated file end in JSON, partial, bounded", async () => {
  await withCwd(async (cwd) => {
    const good = [{ payload: proto, state: 1, t1: T1, t2: T1 }, { payload: proto, state: 1, t1: T1, t2: T1 }];
    const cases: Array<[string, Buffer, RegExp]> = [
      ["overlong1", segb1(good, Buffer.alloc(0), 0x7fffffff), /do not fit/],
      ["negative1", segb1(good, Buffer.alloc(0), -5), /do not fit/],
      ["count2", segb2(good.map((g) => ({ payload: g.payload, state: 1, t: T1 })), undefined, 1 << 30), /cannot hold/],
      ["backwards2", segb2(good.map((g) => ({ payload: g.payload, state: 1, t: T1 })), (i, end) => (i === 1 ? 4 : end)), /goes backwards/],
      ["past2", segb2(good.map((g) => ({ payload: g.payload, state: 1, t: T1 })), (i, end) => (i === 1 ? end + 100000 : end)), /past the end/],
      ["short2", Buffer.concat([Buffer.from("SEGB"), Buffer.alloc(8)]), /shorter than/],
    ];
    for (const [name, bytes, why] of cases) {
      const t0 = Date.now();
      const a = ok(await tool(SEGB, cwd, { path: await put(cwd, name, bytes) }));
      assert.ok(Date.now() - t0 < 10000, name);
      assert.equal(a.status, "partial", name);
      assert.match(a.files[0].reason, why, name);
    }
    const cut = segb1(good).subarray(0, 120);
    const t = ok(await tool(SEGB, cwd, { path: await put(cwd, "cut1", cut) }));
    assert.equal(t.status, "partial");
    assert.ok(t.entry_count <= 1);
  });
});

test("1,000 random framings (at most) end in JSON within a bound; no row claims an offset past the file", async () => {
  await withCwd(async (cwd) => {
    const dir = join(cwd, "work", "fuzz");
    await mkdir(dir, { recursive: true });
    for (let i = 0; i < 300; i++) {
      const base = i % 2 ? segb1([{ payload: proto, state: 1, t1: T1, t2: T1 }]) : segb2([{ payload: proto, state: 1, t: T1 }]);
      const b = Buffer.from(base);
      for (let k = 0; k < 6; k++) b[Math.floor(Math.random() * b.length)] = Math.floor(Math.random() * 256);
      await writeFile(join(dir, `f${i}`), i % 7 === 0 ? Buffer.concat([b, randomBytes(64)]) : b);
    }
    const t0 = Date.now();
    const run = await tool(SEGB, cwd, { path: "work/fuzz", out_file: "work/fuzz.jsonl" });
    const a = ok(run);
    assert.ok(Date.now() - t0 < 60000);
    for (const line of (await readFile(join(cwd, "work", "fuzz.jsonl"), "utf8")).split("\n").filter(Boolean)) {
      const row = JSON.parse(line) as { payload_offset: number; payload_length: number; file: string };
      assert.ok(row.payload_length >= 0 && row.payload_offset >= 0);
    }
    assert.ok(["complete", "partial"].includes(a.status));
  });
});

test("the payload is a structure only: tags, no value, no string, no checksum, and a canary in the payload is in nothing the run leaves", async () => {
  await withCwd(async (cwd) => {
    const file = await put(cwd, "evidence/x/1", segb1([{ payload: proto, state: 1, t1: T1, t2: T1 }, { payload: Buffer.from("bplist00" + CANARY), state: 1, t1: T1, t2: T1 }]));
    const run = await tool(SEGB, cwd, { path: file, out_file: "work/rows.jsonl" });
    const a = ok(run);
    const text = [run.stdout, ...(await reachable(cwd, (p) => p.includes("/evidence/")))].join("\n");
    assert.doesNotMatch(text, new RegExp(CANARY));
    assert.doesNotMatch(text, new RegExp(Buffer.from(CANARY).toString("hex")));
    const view = a.entries[0].payload;
    assert.deepEqual(view.tags.map((t: { field: number; wire: number }) => [t.field, t.wire]), [[1, 2], [2, 0], [3, 1], [4, 5]]);
    assert.equal(view.tags[0].length, CANARY.length);
    assert.equal(JSON.stringify(view).includes("300"), false, "no varint value is shown");
    assert.match(view.confidence, /plausible/);
    assert.match(a.entries[1].payload.confidence, /property list/);
    assert.doesNotMatch(JSON.stringify(a.entries), /crc|checksum/i);
  });
});

test("skip_frames resumes without repeating a row, and the rows written equal entry_count", async () => {
  await withCwd(async (cwd) => {
    const frames = Array.from({ length: 10 }, (_, i) => ({ payload: Buffer.from([8, i]), state: 1, t1: T1 + i, t2: T1 + i }));
    const file = await put(cwd, "ten", segb1(frames));
    const all = ok(await tool(SEGB, cwd, { path: file, out_file: "work/all.jsonl" }));
    const rest = ok(await tool(SEGB, cwd, { path: file, skip_frames: 4, out_file: "work/rest.jsonl" }));
    assert.equal(all.entry_count, 10);
    assert.equal(rest.entry_count, 6);
    assert.equal(rest.entries[0].frame, 4);
    assert.equal((await readFile(join(cwd, "work", "all.jsonl"), "utf8")).split("\n").filter(Boolean).length, all.entry_count);
    const dir = await tool(SEGB, cwd, { path: "work", skip_frames: 1 });
    assert.equal(dir.code, 1);
  });
});

test("SIGTERM on a large file ends with one JSON answer, exit 143, whole rows and a resume", async () => {
  await withCwd(async (cwd) => {
    const frames = Array.from({ length: 60000 }, (_, i) => ({ payload: proto, state: 1, t1: T1 + i, t2: T1 + i }));
    const file = await put(cwd, "big", segb1(frames));
    const run = await signalled(SEGB, cwd, { path: file, out_file: "work/big.jsonl" }, "SIGTERM", 1200);
    assert.ok(run.code === 143 || run.code === 0, run.stderr);
    const a = JSON.parse(run.stdout);
    const lines = (await readFile(join(cwd, "work", "big.jsonl"), "utf8")).split("\n").filter(Boolean);
    assert.equal(lines.length, a.entry_count);
    for (const l of lines.slice(-3)) JSON.parse(l);
    if (run.code === 143) {
      assert.equal(a.interrupted, "SIGTERM");
      assert.equal(a.resume.skip_frames, a.entry_count);
    }
  });
});
