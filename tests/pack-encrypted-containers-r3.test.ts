/**
 * encrypted-containers: archive_probe's byte account, judged as one design (PKG-ENC-01). Every test here fails on archive_probe as the
 * batch head had it. Fixtures are built from the APPNOTE's record layouts (ZIP) and RAR 4's block layout, never from the tool's own output.
 *
 * The account: every byte of a ZIP is a member, the directory, a Zip64 record or the End record with its comment, or it is dark; dark bytes
 * are searched for anything shaped like an archive. The manifest says that the shape holds "whatever shape the archive has (damaged or
 * missing End record, local headers only)", so an archive made of local headers whose sizes are in a data descriptor (bit 3 of the flags:
 * the sizes in the header are zero, the way a streaming writer such as `zip -` or Java's ZipOutputStream writes them) has to be found too,
 * and a RAR 4 archive whose main header is longer than the 57 bytes the first 64 bytes of a region hold.
 */
import assert from "node:assert/strict";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { crc32 } from "node:zlib";
import { ROOT, runPy, withCwd } from "./tool-library-harness.ts";

const PROBE = join(ROOT, "packs", "encrypted-containers", "tools", "archive_probe", "run.py");
type Json = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

async function probe(cwd: string, name: string, data: Buffer): Promise<Json> {
  await mkdir(join(cwd, "inputs"), { recursive: true });
  await writeFile(join(cwd, "inputs", name), data);
  const run = await runPy(PROBE, cwd, { path: `inputs/${name}` }, undefined, { AGENT_ID: "s1" });
  assert.equal(run.code, 0, run.stderr + run.stdout);
  assert.doesNotMatch(run.stderr, /Traceback/);
  return JSON.parse(run.stdout) as Json;
}

const u16 = (n: number): Buffer => {
  const b = Buffer.alloc(2);
  b.writeUInt16LE(n);
  return b;
};
const u32 = (n: number): Buffer => {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(n >>> 0);
  return b;
};

/** A plain stored ZIP of the given members: local headers, a directory, an End record. `gap` goes between the last member and the directory. */
function zipOf(members: Array<{ name: string; data: string }>, gap: Buffer = Buffer.alloc(0)): Buffer {
  const parts: Buffer[] = [];
  const central: Buffer[] = [];
  let at = 0;
  for (const m of members) {
    const name = Buffer.from(m.name);
    const data = Buffer.from(m.data);
    const local = Buffer.concat([u32(0x04034b50), u16(20), u16(0), u16(0), u16(0), u16(0), u32(crc32(data)), u32(data.length), u32(data.length), u16(name.length), u16(0), name, data]);
    central.push(Buffer.concat([u32(0x02014b50), u16(20), u16(20), u16(0), u16(0), u16(0), u16(0), u32(crc32(data)), u32(data.length), u32(data.length), u16(name.length), u16(0), u16(0), u16(0), u16(0), u32(0), u32(at), name]));
    parts.push(local);
    at += local.length;
  }
  const dir = Buffer.concat(central);
  return Buffer.concat([...parts, gap, dir, u32(0x06054b50), u16(0), u16(0), u16(members.length), u16(members.length), u32(dir.length), u32(at + gap.length), u16(0)]);
}

/**
 * An archive made of local headers only, the way a streaming writer makes one: bit 3 of the flags is set, the CRC and both sizes in the
 * header are zero, and a data descriptor (with its signature) after the data carries them. There is no directory and no End record.
 */
function streamedLocalHeaders(members: Array<{ name: string; data: string }>): Buffer {
  const parts: Buffer[] = [];
  for (const m of members) {
    const name = Buffer.from(m.name);
    const data = Buffer.from(m.data);
    parts.push(Buffer.concat([u32(0x04034b50), u16(20), u16(8), u16(0), u16(0), u16(0), u32(0), u32(0), u32(0), u16(name.length), u16(0), name, data, u32(0x08074b50), u32(crc32(data)), u32(data.length), u32(data.length)]));
  }
  return Buffer.concat(parts);
}

const outer = zipOf([{ name: "outer.txt", data: "the examined archive" }]);
const found = (out: Json): boolean => Boolean(out.archive_behind ?? out.archive_in_gap ?? out.archive_in_front);

test("an archive made of streamed local headers (data descriptors, sizes zero in the header) between the members and the directory is found, as the manifest says local headers only are", async () => {
  await withCwd(async (cwd) => {
    const hidden = streamedLocalHeaders([{ name: "hidden-1.txt", data: "first hidden member" }, { name: "hidden-2.txt", data: "second hidden member" }]);
    const out = await probe(cwd, "gap.zip", zipOf([{ name: "outer.txt", data: "the examined archive" }], hidden));
    assert.ok(found(out), `the archive is named: status ${out.status} protected ${out.protected} keys ${Object.keys(out).filter((k) => /archive|dark|doubt/.test(k))}`);
    assert.equal(out.status, "partial");
    assert.notEqual(out.protected, false, "protected is not false over a hidden archive");
  });
});

test("the same archive behind the examined ZIP's End record, and in front of it, still leaves the answer partial", async () => {
  await withCwd(async (cwd) => {
    const hidden = streamedLocalHeaders([{ name: "hidden.txt", data: "hidden member" }]);
    for (const [label, bytes] of [["behind", Buffer.concat([outer, hidden])], ["front", Buffer.concat([hidden, outer])]] as const) {
      const out = await probe(cwd, `${label}.zip`, bytes);
      assert.equal(out.status, "partial", label);
      assert.notEqual(out.protected, false, label);
    }
  });
});


test("a streamed archive whose descriptor does not match its data is not a shape (a constant that spells the signatures is not an archive)", async () => {
  await withCwd(async (cwd) => {
    const name = Buffer.from("x.txt");
    const bad = Buffer.concat([u32(0x04034b50), u16(20), u16(8), u16(0), u16(0), u16(0), u32(0), u32(0), u32(0), u16(name.length), u16(0), name, Buffer.from("data"), u32(0x08074b50), u32(0), u32(9999), u32(9999)]);
    const out = await probe(cwd, "stub.zip", Buffer.concat([outer, bad]));
    assert.equal(out.archive_behind, undefined, "a descriptor whose sizes do not fit the data is no archive");
  });
});

/** RAR 4: the marker block, then a main header (type 0x73) of `hsize` bytes whose CRC is the low 16 bits of the CRC-32 of the header from its type on. */
function rar4(hsize: number): Buffer {
  const marker = Buffer.from("526172211a0700", "hex");
  const body = Buffer.alloc(hsize - 2); // type, flags, size (2), then the main header's reserved fields and any extra bytes
  body[0] = 0x73;
  body.writeUInt16LE(0, 1);
  body.writeUInt16LE(hsize, 3);
  const crc = crc32(body) & 0xffff;
  return Buffer.concat([marker, u16(crc), body]);
}

test("a streamed member whose data is megabytes long is found by its descriptor, and one whose descriptor is out of reach is dark_unsearched, never complete", async () => {
  await withCwd(async (cwd) => {
    const big = Buffer.alloc(3 << 20, 0x41);
    const hidden = streamedLocalHeaders([{ name: "big.bin", data: big.toString("latin1") }]);
    const out = await probe(cwd, "bigstream.zip", zipOf([{ name: "outer.txt", data: "the examined archive" }], hidden));
    assert.ok(found(out), `found: status ${out.status} protected ${out.protected}`);
    // A streamed local header and then 17 MiB with no descriptor in it: the search stops at its reach and says so.
    const name = Buffer.from("never-ends.bin");
    const open = Buffer.concat([u32(0x04034b50), u16(20), u16(8), u16(0), u16(0), u16(0), u32(0), u32(0), u32(0), u16(name.length), u16(0), name, Buffer.alloc(17 << 20, 0x42)]);
    const cut = await probe(cwd, "never.zip", zipOf([{ name: "outer.txt", data: "the examined archive" }], open));
    assert.notEqual(cut.status, "complete", `a descriptor out of reach is not a clean account: ${cut.status}`);
    assert.notEqual(cut.protected, false);
    assert.ok(cut.dark_unsearched, `the search says it did not look at all of them: keys ${Object.keys(cut).filter((k) => /dark|archive/.test(k))}`);
  });
});

test("a RAR 4 main header longer than the 57 bytes a region's first 64 bytes hold is a shape too", async () => {
  await withCwd(async (cwd) => {
    for (const hsize of [13, 57, 58, 200, 4000]) {
      const out = await probe(cwd, `rar-${hsize}.zip`, zipOf([{ name: "outer.txt", data: "the examined archive" }], Buffer.concat([rar4(hsize), Buffer.alloc(64)])));
      assert.ok(found(out), `a RAR 4 block with a main header of ${hsize} bytes is named: ${JSON.stringify(out).slice(0, 300)}`);
      assert.equal(out.status, "partial", `main header ${hsize}`);
    }
  });
});
