/**
 * thumbcache_read: the slack of an entry, the bytes between the end of its parts (header, identifier, padding, data) and the end of its
 * declared size.
 *
 * A reader that steps from entry to entry by the declared size alone does not see what lies in that slack: an entry whose size is inflated
 * swallows the entries after it, and bytes hidden there are never counted. The tool reads on from the end of an entry's parts: an entry that
 * begins in the slack is read as any other (listed, its image written) and marked inside_entry_at; bytes there that are neither an entry nor
 * zero are counted in bytes_not_in_an_entry and make the file and the answer partial; a slack of zeros changes nothing.
 *
 * The caches are built here by a builder of this file's own, from the published layout of the Vista (0x14) and Windows 10 (0x20) formats,
 * not from the tool's output and not from the builder of the other thumbcache test.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { withCwd } from "./tool-library-harness.ts";
import { WIN } from "./windows-pack-harness.ts";
import { assertJsonAnswer, runTool } from "./windows-tool-contract.ts";

const TOOL = "thumbcache_read";
type Row = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any
type Answer = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

// --- three small images, one of each kind the tool names ------------------------------------------------------------------------------------

function makeBmp(): Buffer {
  const pixels = Buffer.alloc(2 * 2 * 4, 0x42);
  const header = Buffer.alloc(54);
  header.write("BM", 0, "latin1");
  header.writeUInt32LE(54 + pixels.length, 2);
  header.writeUInt32LE(54, 10);
  header.writeUInt32LE(40, 14);
  header.writeInt32LE(2, 18);
  header.writeInt32LE(2, 22);
  header.writeUInt16LE(1, 26);
  header.writeUInt16LE(32, 28);
  return Buffer.concat([header, pixels]);
}

function makePng(): Buffer {
  const chunk = Buffer.alloc(25);
  chunk.writeUInt32BE(13, 0);
  chunk.write("IHDR", 4, "latin1");
  chunk.writeUInt32BE(16, 8);
  chunk.writeUInt32BE(9, 12);
  return Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), chunk, Buffer.from("0000000049454e44ae426082", "hex")]);
}

const makeJpeg = (): Buffer => Buffer.concat([Buffer.from([0xff, 0xd8, 0xff, 0xdb]), Buffer.alloc(300, 0x33), Buffer.from([0xff, 0xd9])]);

const BMP = makeBmp();
const PNG = makePng();
const JPEG = makeJpeg();
const IMAGES = [BMP, PNG, JPEG];
const digest = (b: Buffer): string => createHash("sha256").update(b).digest("hex");

// --- the layout: file header, entry header, identifier, padding, data -------------------------------------------------------------------------

type Spec = { hash: bigint; data: Buffer; slack?: Buffer; sizeOverride?: number };

/** One entry of version 0x14 (56-byte header with a four-character extension) or 0x20 (56-byte header with a width and a height). */
function makeEntry(version: 0x14 | 0x20, spec: Spec): Buffer {
  const identifier = Buffer.from(spec.data.length ? spec.hash.toString(16).padStart(16, "0") : "", "utf16le");
  const header = Buffer.alloc(56);
  const slack = spec.slack ?? Buffer.alloc(0);
  header.write("CMMM", 0, "latin1");
  header.writeUInt32LE(spec.sizeOverride ?? 56 + identifier.length + spec.data.length + slack.length, 4);
  header.writeBigUInt64LE(spec.hash, 8);
  let at = 16;
  if (version === 0x14) {
    header.write("j\0p\0g\0\0\0", 16, "latin1");
    at = 24;
  }
  header.writeUInt32LE(identifier.length, at); // identifier length
  header.writeUInt32LE(0, at + 4); // padding length
  header.writeUInt32LE(spec.data.length, at + 8); // data length
  at += 12;
  if (version === 0x20) at += 8; // width and height, left zero
  // at: an unknown field, then the data and header checksums (left zero)
  return Buffer.concat([header, identifier, spec.data, slack]);
}

/** A file header (24 bytes for both versions) followed by `body`; the first entry is the header's end, the first free byte the file's end. */
function makeCache(version: 0x14 | 0x20, body: Buffer): Buffer {
  const header = Buffer.alloc(24);
  header.write("CMMM", 0, "latin1");
  header.writeUInt32LE(version, 4);
  header.writeUInt32LE(version === 0x14 ? 1 : 3, 8); // the size class "96": the second type of the Vista table, the fourth of the Windows 10 one
  const at = version === 0x14 ? 12 : 16;
  header.writeUInt32LE(24, at);
  header.writeUInt32LE(24 + body.length, at + 4);
  return Buffer.concat([header, body]);
}

const realEntries = (version: 0x14 | 0x20): Buffer[] => [
  makeEntry(version, { hash: 0x1111111111111111n, data: BMP }),
  makeEntry(version, { hash: 0x2222222222222222n, data: PNG }),
  makeEntry(version, { hash: 0x3333333333333333n, data: JPEG }),
];

function put(cwd: string, rel: string, bytes: Buffer): string {
  mkdirSync(join(cwd, rel, ".."), { recursive: true });
  writeFileSync(join(cwd, rel), bytes);
  return rel;
}

async function read(cwd: string, rel: string): Promise<Answer> {
  const run = await runTool(TOOL, cwd, { path: rel });
  return { ...assertJsonAnswer(run, rel), exit: run.code };
}

function assertImagesOut(cwd: string, out: Answer, label: string): void {
  const withImage = (out.entries as Row[]).filter((r) => r.data_size > 0);
  assert.deepEqual(withImage.map((r) => r.sha256), IMAGES.map(digest), `${label}: every stored image is listed`);
  for (const [i, row] of withImage.entries()) {
    assert.ok(row.written, `${label}: image ${i + 1} is written`);
    assert.ok(readFileSync(join(cwd, row.written)).equals(IMAGES[i]), `${label}: image ${i + 1} byte for byte`);
  }
  assert.equal(out.images_written, 3, label);
}

for (const version of [0x14, 0x20] as const) {
  const v = `0x${version.toString(16)}`;

  test(`${v}: an empty entry whose declared size covers the three entries after it swallows none of them`, async () => {
    await withCwd(async (cwd) => {
      const three = realEntries(version);
      const swallowed = three.reduce((n, e) => n + e.length, 0);
      const wrapper = makeEntry(version, { hash: 0x9999n, data: Buffer.alloc(0), sizeOverride: 56 + swallowed });
      const out = await read(cwd, put(cwd, `work/s3-${v}/thumbcache_96.db`, makeCache(version, Buffer.concat([wrapper, ...three]))));
      assert.equal(out.entry_count, 4, out.status_basis);
      assertImagesOut(cwd, out, "swallow three");
      const rows = out.entries as Row[];
      assert.deepEqual([rows[0].offset, rows[0].entry_size, rows[0].slack_bytes, rows[0].inside_entry_at], [24, 56 + swallowed, swallowed, undefined]);
      assert.deepEqual(rows.slice(1).map((r) => r.inside_entry_at), [24, 24, 24], "each swallowed entry names the entry whose size covers it");
      const [said] = out.files;
      assert.equal(said.entries_inside_another_entry, 3);
      assert.deepEqual(said.bytes_not_in_an_entry, { zero_bytes: 0, other_bytes: 0, other: 0 }, "every byte of the slack is an entry");
      assert.match(said.problems.join("\n"), /3 entr\(ies\) begin inside the declared size of another entry/);
      assert.match(out.status_basis, /3 entr\(ies\) begin inside the declared size of another entry/);
      assert.match(said.status_basis, /3 of them begin inside the declared size of another entry/);
    });
  });

  test(`${v}: an entry whose declared size covers the next one lists that entry and writes its image`, async () => {
    await withCwd(async (cwd) => {
      const [first, second, third] = realEntries(version);
      const inflated = Buffer.from(first);
      inflated.writeUInt32LE(first.length + second.length, 4);
      const out = await read(cwd, put(cwd, `work/s1-${v}/thumbcache_96.db`, makeCache(version, Buffer.concat([inflated, second, third]))));
      assert.equal(out.entry_count, 3, out.status_basis);
      assertImagesOut(cwd, out, "swallow one");
      const rows = out.entries as Row[];
      assert.deepEqual(rows.map((r) => r.inside_entry_at), [undefined, 24, undefined]);
      assert.equal(rows[0].slack_bytes, second.length);
      assert.equal(rows[1].image_type, "png");
      assert.equal(out.files[0].entries_inside_another_entry, 1);
    });
  });

  test(`${v}: a slack of zeros is the entry's own: complete, and nothing is counted`, async () => {
    await withCwd(async (cwd) => {
      const [first, second, third] = realEntries(version);
      const padded = makeEntry(version, { hash: 0x1111111111111111n, data: BMP, slack: Buffer.alloc(200) });
      assert.equal(padded.length, first.length + 200);
      const out = await read(cwd, put(cwd, `work/z-${v}/thumbcache_96.db`, makeCache(version, Buffer.concat([padded, second, third]))));
      assert.equal(out.status, "complete", out.status_basis);
      assert.equal(out.exit, 0);
      assert.equal(out.entry_count, 3);
      assertImagesOut(cwd, out, "zero slack");
      assert.equal((out.entries as Row[])[0].slack_bytes, 200);
      assert.deepEqual(out.files[0].bytes_not_in_an_entry, { zero_bytes: 0, other_bytes: 0, other: 0 });
      assert.deepEqual(out.files[0].problems, []);
      assert.equal(out.files[0].entries_inside_another_entry, undefined);
    });
  });

  test(`${v}: bytes in an entry's slack that are neither an entry nor zero are counted and make the file and the answer partial`, async () => {
    await withCwd(async (cwd) => {
      const [, second, third] = realEntries(version);
      const junk = Buffer.alloc(150, 0xa5);
      const slack = Buffer.concat([Buffer.alloc(10), junk, Buffer.alloc(40)]);
      const padded = makeEntry(version, { hash: 0x1111111111111111n, data: BMP, slack });
      const out = await read(cwd, put(cwd, `work/j-${v}/thumbcache_96.db`, makeCache(version, Buffer.concat([padded, second, third]))));
      assert.equal(out.status, "partial", out.status_basis);
      assert.equal(out.files[0].status, "partial");
      assert.equal(out.entry_count, 3, "the entries after the slack are read");
      assertImagesOut(cwd, out, "junk slack");
      const [said] = out.files;
      assert.deepEqual([said.bytes_not_in_an_entry.other, said.bytes_not_in_an_entry.other_bytes], [1, slack.length], "the stretch is counted, up to the slack's end");
      assert.equal(said.slack_stretches_not_zero, 1);
      const partsEnd = 24 + 56 + 32 + BMP.length;
      assert.match(said.problems.join("\n"), new RegExp(`${slack.length} byte\\(s\\) at offset ${partsEnd} lie inside the declared size of the entry at offset 24`));
      assert.match(said.status_basis, /1 stretch\(es\) of the file \(200 bytes\) are neither an entry nor zero/);
      assert.equal(said.entries_inside_another_entry, undefined, "no signature in the junk: no entry is made of it");
    });
  });
}

test("an entry whose declared size passes the end of the file, its parts whole: the entries after its parts are read, and the answer is partial", async () => {
  await withCwd(async (cwd) => {
    const [first, second, third] = realEntries(0x20);
    const huge = Buffer.from(first);
    huge.writeUInt32LE(0x7fffffff, 4);
    const out = await read(cwd, put(cwd, "work/past/thumbcache_96.db", makeCache(0x20, Buffer.concat([huge, second, third]))));
    assert.equal(out.status, "partial");
    assert.equal(out.entry_count, 3);
    assertImagesOut(cwd, out, "past the end");
    const rows = out.entries as Row[];
    assert.deepEqual([rows[0].truncated, rows[1].inside_entry_at, rows[2].inside_entry_at], [true, 24, 24]);
  });
});

test("the manifest says what is done with an entry's slack", () => {
  const manifest = JSON.parse(readFileSync(join(WIN, TOOL, "manifest.json"), "utf8"));
  assert.match(manifest.description, /inside_entry_at/);
  assert.match(manifest.description, /slack/);
});
