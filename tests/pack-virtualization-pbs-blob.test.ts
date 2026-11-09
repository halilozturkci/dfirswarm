/**
 * virtualization-backup-forensics: backup_audit_normalise identifies Proxmox Backup Server data blobs (format pbs_blob), reads the payload of an uncompressed
 * index.json.blob (the snapshot manifest) and client.log.blob, and never decrypts or inflates anything.
 *
 * Every blob is SYNTHETIC and built here from the layout in the Proxmox Backup source (pbs-datastore: file_formats.rs, data_blob.rs, manifest.rs, as served by
 * git.proxmox.com, retrieved 2026-11-03): an 8-byte magic that says how the payload is stored, a 4-byte little-endian CRC32 of the bytes after the header, the
 * payload; the header of an encrypted blob is 44 bytes (magic, CRC, a 16-byte IV, a 16-byte tag). Nothing here was checked against a real datastore.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { crc32 } from "node:zlib";
import { AUDIT, CANARY, body, json, put, tool, withCwd } from "./pack-virtualization-harness.ts";
import type { Json } from "./pack-virtualization-harness.ts";

const MAGIC = {
  uncompressed: Buffer.from([66, 171, 56, 7, 190, 131, 112, 161]),
  compressed: Buffer.from([49, 185, 88, 66, 111, 182, 163, 127]),
  encrypted: Buffer.from([123, 103, 133, 190, 34, 45, 76, 240]),
  encrypted_compressed: Buffer.from([230, 89, 27, 191, 11, 191, 216, 11]),
};
const CHUNK_INDEX = Buffer.from([47, 127, 65, 237, 145, 253, 15, 205]);

function crcLe(data: Buffer): Buffer {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(crc32(data) >>> 0);
  return b;
}
function blob(kind: keyof typeof MAGIC, payload: Buffer, opts: { badCrc?: boolean } = {}): Buffer {
  const encrypted = kind.startsWith("encrypted");
  const iv = encrypted ? Buffer.alloc(32, 7) : Buffer.alloc(0);          // IV and tag
  const rest = Buffer.concat([iv, payload]);
  const crc = opts.badCrc ? Buffer.from([1, 2, 3, 4]) : crcLe(encrypted ? payload : payload);
  return Buffer.concat([MAGIC[kind], crc, rest]);
}
const manifest = (files: Json[], extra: Json = {}): Buffer =>
  Buffer.from(JSON.stringify({ "backup-type": "vm", "backup-id": "100", "backup-time": 1709604000, files, unprotected: {}, ...extra }));
const file = (name: string, size = 1024) => ({ filename: name, size, csum: "0123456789abcdef".repeat(4), "crypt-mode": "none" });

async function run(cwd: string, name: string, data: Buffer, extra: Record<string, unknown> = {}) {
  await put(cwd, `snap/${name}`, data);
  return tool(AUDIT, cwd, { path: `snap/${name}`, ...extra });
}

test("an uncompressed index.json.blob: identified by its magic under auto, CRC checked, the manifest's files, sizes and checksums become events", async () => {
  await withCwd(async (cwd) => {
    const out = body(await run(cwd, "index.json.blob", blob("uncompressed", manifest([file("drive-scsi0.img.fidx", 4096), file("qemu-server.conf.blob", 300)]))));
    assert.equal(out.status, "complete", out.status_basis);
    assert.equal(out.sources[0].format, "pbs_blob");
    const b = out.events[0].blob;
    assert.equal(b.kind, "uncompressed");
    assert.equal(b.crc_check, "ok");
    assert.equal(b.crc_stored, b.crc_computed);
    assert.equal(b.payload, "read");
    const snap = out.events.find((e: Json) => e.action_raw === "snapshot manifest");
    assert.equal(snap.object, "vm/100");
    assert.equal(snap.time_utc, "2024-03-05T02:00:00Z");
    assert.match(snap.time_basis, /epoch seconds, UTC by definition/);
    const files = out.events.filter((e: Json) => e.action_raw === "manifest file");
    assert.deepEqual(files.map((e: Json) => [e.setting.filename, e.setting.size]), [["drive-scsi0.img.fidx", 4096], ["qemu-server.conf.blob", 300]]);
    assert.equal(files[0].setting.csum, "0123456789abcdef".repeat(4));
    const p = out.provenance.find((x: Json) => x.format === "pbs_blob");
    assert.equal(p.validated_against_real_export, false);
  });
});

test("an uncompressed client.log.blob: each line of the payload is an event whose text is not printed", async () => {
  await withCwd(async (cwd) => {
    const out = body(await run(cwd, "client.log.blob", blob("uncompressed", Buffer.from("starting the backup of vm 100\nfinished without errors\n"))));
    assert.equal(out.status, "complete");
    assert.equal(out.counts.events, 3);
    assert.equal(out.events[1].action_raw, "client log line");
    assert.equal(out.events[1].message_chars, "starting the backup of vm 100".length);
    assert.doesNotMatch(JSON.stringify(out), /starting the backup/);
  });
});

test("a compressed blob is identified and counted, not inflated; the answer says its payload was not read and is partial", async () => {
  await withCwd(async (cwd) => {
    const frame = Buffer.concat([Buffer.from([0x28, 0xb5, 0x2f, 0xfd]), Buffer.from("not really a zstd stream, never inflated")]);
    const out = body(await run(cwd, "index.json.blob", blob("compressed", frame)));
    assert.equal(out.events[0].blob.kind, "compressed");
    assert.equal(out.events[0].blob.crc_check, "ok");
    assert.equal(out.events[0].blob.payload_is_zstd_frame, true);
    assert.equal(out.events[0].blob.payload, "not_read_compressed");
    assert.equal(out.counts.events, 1);
    assert.equal(out.status, "partial");
    assert.match(out.partial_reasons.join(" "), /not inflated/);
    const other = body(await run(cwd, "client.log.blob", blob("compressed", Buffer.from("plain bytes, no frame"))));
    assert.equal(other.events[0].blob.payload_is_zstd_frame, false);
  });
});

test("encrypted and encrypted-and-compressed blobs are identified and never decrypted: the payload bytes are not in the answer", async () => {
  await withCwd(async (cwd) => {
    for (const kind of ["encrypted", "encrypted_compressed"] as const) {
      const cipher = Buffer.from("CIPHERTEXT-MARKER-0123456789abcdef-" + CANARY.aws);
      const out = body(await run(cwd, "index.json.blob", blob(kind, cipher)));
      assert.equal(out.events[0].blob.kind, kind);
      assert.equal(out.events[0].blob.header_bytes, 44);
      assert.equal(out.events[0].blob.payload, "not_read_encrypted");
      assert.equal(out.events[0].blob.crc_check, "not_checked");
      assert.equal(out.counts.events, 1);
      assert.equal(out.status, "partial");
      assert.doesNotMatch(JSON.stringify(out), /CIPHERTEXT-MARKER|AKIA/);
    }
  });
});

test("a CRC mismatch is reported with both values and makes the answer partial; the payload is still read", async () => {
  await withCwd(async (cwd) => {
    const out = body(await run(cwd, "index.json.blob", blob("uncompressed", manifest([file("a.blob")]), { badCrc: true })));
    assert.equal(out.events[0].blob.crc_check, "mismatch");
    assert.notEqual(out.events[0].blob.crc_stored, out.events[0].blob.crc_computed);
    assert.equal(out.status, "partial");
    assert.match(out.partial_reasons.join(" "), /CRC32/);
  });
});

test("a truncated header, an unknown magic and a chunk index are not blobs: named, located, nothing guessed", async () => {
  await withCwd(async (cwd) => {
    const short = json(await run(cwd, "index.json.blob", MAGIC.uncompressed.subarray(0, 5), { format: "pbs_blob" }));
    assert.equal(short.status, "failed");
    assert.match(JSON.stringify(short.problems), /truncated header/);
    const enc = json(await run(cwd, "index.json.blob", Buffer.concat([MAGIC.encrypted, Buffer.alloc(20)]), { format: "pbs_blob" }));
    assert.match(JSON.stringify(enc.problems), /truncated header/);
    const unknown = json(await run(cwd, "x.blob", Buffer.concat([Buffer.from("NOTABLOB"), Buffer.alloc(40)]), { format: "pbs_blob" }));
    assert.match(JSON.stringify(unknown.problems), /none of the four data blob magics/);
    const idx = json(await run(cwd, "x.fidx", Buffer.concat([CHUNK_INDEX, Buffer.alloc(64)])));
    assert.equal(idx.unrecognised.length, 1, "a chunk index is not a data blob and auto does not read it");
    assert.equal(idx.counts.events, 0);
  });
});

test("canaries in manifest file names and in client log lines never reach the answer", async () => {
  await withCwd(async (cwd) => {
    const m = body(await run(cwd, "index.json.blob", blob("uncompressed", manifest([file(CANARY.github), file(CANARY.aws + ".fidx"), file(`https://${CANARY.userinfo}@h.example.net/x`)]))));
    const l = body(await run(cwd, "client.log.blob", blob("uncompressed", Buffer.from(`token=${CANARY.github}\nconnect https://${CANARY.userinfo}@h.example.net\npassword ${CANARY.hex}\n`))));
    for (const text of [JSON.stringify(m), JSON.stringify(l)]) {
      for (const s of [CANARY.github, CANARY.aws, CANARY.hex, CANARY.userinfo]) {
        for (let i = 0; i + 12 <= s.length; i += 3) assert.ok(!text.includes(s.slice(i, i + 12)), `a window of a canary is in the answer (${s.slice(0, 4)}...)`);
      }
    }
  });
});

test("hostile payloads: a nesting bomb, an odd manifest, a size far over the cap, entries that are not file records", async () => {
  await withCwd(async (cwd) => {
    const bomb = body(await run(cwd, "index.json.blob", blob("uncompressed", Buffer.from("[".repeat(500000)))));
    assert.equal(bomb.counts.unparsed, 1);
    assert.equal(bomb.status, "partial");
    const odd = body(await run(cwd, "index.json.blob", blob("uncompressed", manifest([file("ok.blob"), "x", { filename: "no-size" }, { ...file("bad-csum"), csum: "zz" }, { ...file("extra"), surprise: 1 }], { novel: true }))));
    assert.equal(odd.counts.unparsed, 3);
    assert.deepEqual(odd.problem_lines.map((p: Json) => p.line), [2, 3, 4]);
    assert.equal(odd.blobs.unknown_manifest_fields_tolerated, 2);
    assert.equal(odd.status, "partial");
    const notJson = body(await run(cwd, "index.json.blob", blob("uncompressed", Buffer.from("{not json"))));
    assert.equal(notJson.counts.unparsed, 1);
    const huge = Buffer.concat([Buffer.from('{"files":["'), Buffer.alloc(17 << 20, 0x61), Buffer.from('"]}')]);
    const big = body(await run(cwd, "index.json.blob", blob("uncompressed", huge)));
    assert.equal(big.events[0].blob.payload, "not_read_over_cap");
    assert.equal(big.events[0].blob.crc_check, "ok");
    assert.equal(big.status, "partial");
    await put(cwd, "snap/sparse.blob", Buffer.concat([MAGIC.uncompressed, Buffer.alloc(8)]));
    assert.doesNotMatch((await tool(AUDIT, cwd, { path: "snap/sparse.blob", format: "pbs_blob" })).stderr, /Traceback/);
  });
});

test("a manifest of 100,000 files is read within max_seconds and its whole list is on disk", async () => {
  await withCwd(async (cwd) => {
    const files = Array.from({ length: 100000 }, (_, i) => file(`chunk-${i}.blob`, i));
    const t0 = Date.now();
    const run1 = await run(cwd, "index.json.blob", blob("uncompressed", manifest(files)), { max_seconds: 30, limit: 100 });
    assert.ok((Date.now() - t0) / 1000 < 58);
    const out = JSON.parse(run1.stdout);
    assert.ok(["complete", "partial"].includes(out.status));
    if (out.status === "complete") assert.equal(out.counts.events, 100002);
    assert.ok(Buffer.byteLength(run1.stdout) < 2_000_000);
    assert.ok(out.pages.events.all_results || out.counts.events <= 100);
  });
});
