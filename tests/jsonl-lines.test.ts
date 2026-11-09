/**
 * The one LF-only JSONL reader (extensions/jsonl-lines.ts). Node's readline also ends a line at U+2028 and U+2029, which JSON.stringify
 * writes raw, and at a lone CR; a record that holds one was read as broken pieces and an intact trace was reported edited.
 */
import assert from "node:assert/strict";
import { createInterface } from "node:readline";
import { Readable } from "node:stream";
import { test } from "node:test";
import { jsonlLines, jsonlRecords } from "../extensions/jsonl-lines.ts";

const stream = (...chunks: Array<Buffer | string>): Readable => Readable.from(chunks, { objectMode: false });
const collect = async <T>(it: AsyncIterable<T>): Promise<T[]> => {
  const out: T[] = [];
  for await (const x of it) out.push(x);
  return out;
};

const TWO = `${JSON.stringify({ a: "before after" })}\n${JSON.stringify({ b: "x y" })}\n`;

test("a two-record file whose strings hold raw U+2028 and U+2029 reads as 2 records (readline reads 4)", async () => {
  assert.ok(TWO.includes(" ") && TWO.includes(" "), "JSON.stringify writes both characters raw");
  // readline splits at both characters on Node 24 (4 lines: the defect this reader replaces) and not on Node 22 (2): the reader's answer
  // does not depend on the Node it runs on.
  const rl = createInterface({ input: Readable.from([TWO]), crlfDelay: Infinity });
  const viaReadline = (await collect(rl)).length;
  assert.ok(viaReadline === 2 || viaReadline === 4, `readline read ${viaReadline} lines`);
  if (Number(process.versions.node.split(".")[0]) >= 24) assert.equal(viaReadline, 4, "readline splits at U+2028 and U+2029 on this Node");
  const lines = await collect(jsonlLines(stream(TWO)));
  assert.equal(lines.length, 2);
  assert.deepEqual(lines.map((l) => JSON.parse(l)), [{ a: "before after" }, { b: "x y" }]);
});

test("a CR before the LF stays part of the record, and a lone CR does not end one", async () => {
  assert.deepEqual(await collect(jsonlLines(stream('{"a":1}\r\n{"b":2}\r\n'))), ['{"a":1}\r', '{"b":2}\r']);
  assert.deepEqual(await collect(jsonlLines(stream("one\rtwo\nthree\n"))), ["one\rtwo", "three"]);
});

test("a last record without an LF is yielded and marked; a file ending in an LF has no empty last record; an empty line is a record", async () => {
  const recs = await collect(jsonlRecords(stream("a\n\nlast")));
  assert.deepEqual(recs.map((r) => [r.text, r.terminated]), [["a", true], ["", true], ["last", false]]);
  assert.deepEqual((await collect(jsonlRecords(stream("a\nb\n")))).map((r) => r.text), ["a", "b"]);
  assert.deepEqual(await collect(jsonlRecords(stream(""))), []);
});

test("offsets and lengths are in bytes and exact, whatever the chunking", async () => {
  const text = `é x\n${"y".repeat(5)}\nzz`;
  const bytes = Buffer.from(text, "utf8");
  for (const size of [1, 2, 3, 5, 7, bytes.length]) {
    const chunks: Buffer[] = [];
    for (let i = 0; i < bytes.length; i += size) chunks.push(bytes.subarray(i, i + size));
    const recs = await collect(jsonlRecords(stream(...chunks)));
    assert.deepEqual(recs.map((r) => [r.offset, r.length, r.text]), [[0, 6, "é x"], [7, 5, "yyyyy"], [13, 2, "zz"]], `chunks of ${size}`);
    for (const r of recs) assert.deepEqual(bytes.subarray(r.offset, r.offset + r.length), r.bytes, "the record's own bytes are at its offset");
  }
});

test("a multibyte character split across a chunk boundary decodes whole", async () => {
  const euro = Buffer.from("€", "utf8"); // 3 bytes
  const recs = await collect(jsonlLines(stream(Buffer.concat([Buffer.from('{"v":"'), euro.subarray(0, 1)]), Buffer.concat([euro.subarray(1), Buffer.from('"}\n')]))));
  assert.deepEqual(recs, ['{"v":"€"}']);
});

test("a single record far larger than a stream chunk comes whole, and invalid UTF-8 is replaced in the text but kept in the bytes", async () => {
  const big = "q".repeat(5_000_000);
  const recs = await collect(jsonlRecords(Readable.from([Buffer.from(big.slice(0, 1_000_000)), Buffer.from(big.slice(1_000_000)), Buffer.from("\nnext\n")], { objectMode: false })));
  assert.equal(recs.length, 2);
  assert.equal(recs[0]!.length, 5_000_000);
  assert.equal(recs[1]!.offset, 5_000_001);
  const bad = await collect(jsonlRecords(stream(Buffer.from([0x61, 0xff, 0xfe, 0x62, 0x0a]))));
  assert.equal(bad[0]!.text, "a��b");
  assert.deepEqual([...bad[0]!.bytes], [0x61, 0xff, 0xfe, 0x62]);
});

test("stopping early ends the stream (a for-await that breaks leaves nothing open)", async () => {
  const source = stream("a\nb\nc\n");
  for await (const line of jsonlLines(source)) {
    assert.equal(line, "a");
    break;
  }
  await new Promise((r) => setImmediate(r));
  assert.equal(source.destroyed, true);
});
