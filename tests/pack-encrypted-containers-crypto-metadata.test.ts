/**
 * crypto_metadata: the encryption metadata of a volume through the reader that knows it (cryptsetup luksDump, bdeinfo, fvdeinfo,
 * fsapfsinfo). The volumes below are built from the formats' own layouts (the LUKS1 on-disk specification, cryptsetup's LUKS2 binary
 * header and JSON area, the BitLocker boot sector with its three metadata block offsets, the Core Storage signature, the APFS container
 * superblock), never from the tool's output. The readers are stand-ins that print what the libraries document; none of them proves
 * anything about a real build, and the real cryptsetup is used only when it is on this host's PATH (t.skip otherwise).
 *
 * Held here: the scheme is named from the bytes; the reader's program, argv, version and exit code are kept; a missing reader is
 * `unavailable` and named, never an empty list; a reader that fails, times out or prints too much is `partial`; no key, salt, digest,
 * UUID, label, protector GUID, description or recovery-password-shaped text reaches the answer, the page file, an error or any file the
 * tool leaves; a forged keyslot count is paged losslessly; hostile parameters and special files give JSON refusals; a stop signal gives
 * one document, the exit status 128 + the signal and no reader left.
 */
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { mkdir, readFile, readdir, symlink, writeFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { test } from "node:test";
import { type Json, asJob, body, everythingUnder, filesUnder, gone, pidFile, put, refused, startDetached, stub, tool, withCwd } from "./pack-network-harness.ts";
import { ROOT } from "./tool-library-harness.ts";

const SCRIPT = join(ROOT, "packs", "encrypted-containers", "tools", "crypto_metadata", "run.py");

const hex = (n: number): string => randomBytes(n).toString("hex");
const uuid = (): string => `${hex(4)}-${hex(2)}-${hex(2)}-${hex(2)}-${hex(6)}`;
const b64 = (n: number): string => randomBytes(n).toString("base64");

function pad(buf: Buffer, size: number): Buffer {
  const out = Buffer.alloc(size);
  buf.copy(out, 0, 0, Math.min(buf.length, size));
  return out;
}

/** The LUKS1 on-disk header: 208 fixed bytes, eight 48-byte key slots (active, iterations, salt[32], key material offset, stripes). */
function luks1(uuidText: string, active: number[] = [1]): Buffer {
  const h = Buffer.alloc(592);
  Buffer.from("LUKS\xba\xbe", "latin1").copy(h, 0);
  h.writeUInt16BE(1, 6);
  h.write("aes", 8, "ascii");
  h.write("xts-plain64", 40, "ascii");
  h.write("sha256", 72, "ascii");
  h.writeUInt32BE(4096, 104);
  h.writeUInt32BE(64, 108);
  randomBytes(20).copy(h, 112);
  randomBytes(32).copy(h, 132);
  h.writeUInt32BE(1000, 164);
  h.write(uuidText, 168, "ascii");
  for (let i = 0; i < 8; i++) {
    const at = 208 + i * 48;
    h.writeUInt32BE(active.includes(i) ? 0x00ac71f3 : 0x0000dead, at);
    h.writeUInt32BE(active.includes(i) ? 123456 : 0, at + 4);
    randomBytes(32).copy(h, at + 8);
    h.writeUInt32BE(8 + i * 504, at + 40);
    h.writeUInt32BE(4000, at + 44);
  }
  return h;
}

/** The LUKS2 binary header (4096 bytes) and a JSON area: magic, version 2, header size, sequence id, label, checksum algorithm, salt, UUID, subsystem. */
function luks2(hdr: number, label: string, uuidText: string, json: string): Buffer {
  const h = Buffer.alloc(2 * hdr);
  for (const start of [0, hdr]) {
    Buffer.from(start === 0 ? "LUKS\xba\xbe" : "SKUL\xba\xbe", "latin1").copy(h, start);
    h.writeUInt16BE(2, start + 6);
    h.writeBigUInt64BE(BigInt(hdr), start + 8);
    h.writeBigUInt64BE(1n, start + 16);
    h.write(label, start + 24, "ascii");
    h.write("sha256", start + 72, "ascii");
    randomBytes(64).copy(h, start + 104);
    h.write(uuidText, start + 168, "ascii");
    h.writeBigUInt64BE(BigInt(start), start + 256);
    h.write(json, start + 4096, "ascii");
  }
  return h;
}

const CANARY_SALT = b64(32);
const CANARY_DIGEST = b64(32);

function luks2Json(salt = CANARY_SALT, digest = CANARY_DIGEST, extraSlots = 0): string {
  const keyslots: Record<string, unknown> = {
    "0": { type: "luks2", key_size: 64, af: { type: "luks1", stripes: 4000, hash: "sha256" },
           area: { type: "raw", offset: "32768", size: "258048", encryption: "aes-xts-plain64", key_size: 64 },
           kdf: { type: "argon2id", time: 4, memory: 1048576, cpus: 4, salt } },
    "1": { type: "luks2", key_size: 64, af: { type: "luks1", stripes: 4000, hash: "sha256" },
           area: { type: "raw", offset: "290816", size: "258048", encryption: "aes-xts-plain64", key_size: 64 },
           kdf: { type: "pbkdf2", hash: "sha256", iterations: 1000000, salt } },
  };
  for (let i = 0; i < extraSlots; i++) keyslots[String(i + 2)] = { type: "luks2", key_size: 64 };
  return JSON.stringify({
    keyslots,
    tokens: { "0": { type: "luks2-keyring", keyslots: ["0"], key_description: "kd-" + hex(8) } },
    segments: { "0": { type: "crypt", offset: "16777216", iv_tweak: "0", size: "dynamic", encryption: "aes-xts-plain64", sector_size: 512 } },
    digests: { "0": { type: "pbkdf2", keyslots: ["0", "1"], segments: ["0"], hash: "sha256", iterations: 123456, salt, digest } },
    config: { json_size: "12288", keyslots_size: "4161536" },
  });
}

/** A BitLocker boot sector: "-FVE-FS-" at 3, the sector size, and three metadata block offsets at 0xB0, 0xB8 and 0xC0; the blocks hold the signature and a version. */
function bitlocker(offsets = [4096, 8192, 12288]): Buffer {
  const b = Buffer.alloc(16384 + 512);
  b.write("-FVE-FS-", 3, "ascii");
  b.writeUInt16LE(512, 11);
  offsets.forEach((o, i) => {
    b.writeBigUInt64LE(BigInt(o), 176 + 8 * i);
    if (o > 0 && o + 64 < b.length) {
      b.write("-FVE-FS-", o, "ascii");
      b.writeUInt16LE(64, o + 8);
      b.writeUInt16LE(2, o + 10);
    }
  });
  return b;
}

function coreStorage(): Buffer {
  const b = Buffer.alloc(8192);
  b.write("CS", 88, "ascii");
  return b;
}

/** An APFS container superblock: object header (32 bytes), "NXSB", block size, block count, ..., nx_fs_oid[100] at 184, nx_flags at 1264. */
function apfs(flags: bigint, volumes = 2): Buffer {
  const b = Buffer.alloc(8192);
  b.write("NXSB", 32, "ascii");
  b.writeUInt32LE(4096, 36);
  b.writeBigUInt64LE(65536n, 40);
  b.writeUInt32LE(100, 180);
  for (let i = 0; i < volumes; i++) b.writeBigUInt64LE(BigInt(1026 + i), 184 + 8 * i);
  b.writeBigUInt64LE(flags, 1264);
  return b;
}

const LUKS1_DUMP = (uuidText: string, enabled: number[]): string => {
  const lines = ["LUKS header information", "Version:        1", "Cipher name:    aes", "Cipher mode:    xts-plain64", "Hash spec:      sha256",
    "Payload offset: 4096", "MK bits:        512", `MK digest:      ${hex(20).replace(/(..)/g, "$1 ").trim()}`, `MK salt:        ${hex(16)} ${hex(16)}`,
    "MK iterations:  1000", `UUID:           ${uuidText}`, ""];
  for (let i = 0; i < 8; i++) {
    lines.push(`Key Slot ${i}: ${enabled.includes(i) ? "ENABLED" : "DISABLED"}`);
    if (enabled.includes(i)) lines.push("\tIterations:         123456", `\tSalt:               ${hex(16)} ${hex(16)}`, `\tKey material offset:\t${8 + i * 504}`, "\tAF stripes:            4000");
  }
  return lines.join("\n");
};

const stubCryptsetup = (dump: string, extra = ""): string => `#!/bin/sh
if [ "$1" = "--version" ]; then echo "cryptsetup 2.6.1"; exit 0; fi
printf '%s\\n' "$@" > "${LOGPATH}"
${extra}
cat <<'DUMP_EOF'
${dump}
DUMP_EOF
`;

const stubBde = (canaryGuid: string, canaryRecovery: string): string => `#!/bin/sh
if [ "$1" = "-V" ]; then echo "bdeinfo 20221031"; exit 0; fi
printf '%s\\n' "$@" > "${LOGPATH}"
cat <<'BDE_EOF'
bdeinfo 20221031

BitLocker Drive Encryption information:
	Encryption method		: AES-XTS 128-bit
	Volume identifier		: ${canaryGuid}
	Creation time			: Mon Jan 01, 2018 10:11:12.000000000 UTC
	Description			: DESK ${canaryRecovery}
	Number of key protectors	: 3

Key protector 0:
	Identifier			: ${canaryGuid}
	Type				: Recovery password
Key protector 1:
	Identifier			: ${uuid()}
	Type				: TPM
	Salt				: ${CANARY_SALT}
Key protector 2:
	Identifier			: ${uuid()}
	Type				: Clear key
BDE_EOF
`;

let LOGPATH = "";

async function volume(cwd: string, name: string, content: Buffer, before = 0): Promise<string> {
  await writeFile(join(cwd, name), Buffer.concat([Buffer.alloc(before), content]));
  return name;
}

const everything = (cwd: string, answer: string): Promise<string> => everythingUnder(cwd, answer, ["out", "work"]);

test("a LUKS2 volume at an offset: the keyslots, segments, digests and tokens as records, nothing secret, the slice removed", async () => {
  await withCwd(async (cwd, bin) => {
    LOGPATH = join(cwd, "argv.log");
    const label = "lbl" + hex(6);
    const volUuid = uuid();
    await stub(bin, "cryptsetup", stubCryptsetup(luks2Json()));
    const vol = await volume(cwd, "disk.img", luks2(16384, label, volUuid, luks2Json()), 1048576);
    const run = await asJob(SCRIPT, cwd, { path: vol, offset: 1048576 }, bin);
    const a = body(run);
    assert.equal(a.status, "complete", a.status_basis);
    assert.equal(a.scheme, "LUKS2");
    assert.equal(a.structural.header_size_bytes, 16384);
    assert.equal(a.structural.label_present, true);
    assert.equal(a.structural.uuid_present, true);
    assert.equal(a.reader.program, "cryptsetup");
    assert.equal(a.reader.version, "cryptsetup 2.6.1");
    assert.equal(a.reader.exit_code, 0);
    const argv = (await readFile(join(cwd, "argv.log"), "utf8")).split("\n").filter(Boolean);
    assert.deepEqual(argv.slice(0, 2), ["luksDump", "--dump-json-metadata"]);
    assert.equal(a.counts.keyslot, 2);
    assert.equal(a.counts.segment, 1);
    assert.equal(a.counts.digest, 1);
    assert.equal(a.counts.token, 1);
    const kinds = a.records.map((r: Json) => r.kind);
    assert.deepEqual(kinds, ["keyslot", "keyslot", "segment", "digest", "token"]);
    assert.equal(a.records[0].kdf.type, "argon2id");
    assert.equal(a.records[0].kdf.memory, 1048576);
    assert.equal(a.records[1].kdf.iterations, 1000000);
    assert.equal(a.records[3].hash, "sha256");
    assert.equal(a.records[4].keyslots_linked, 1);
    const all = await everything(cwd, run.stdout);
    for (const c of [label, volUuid, CANARY_SALT, CANARY_DIGEST]) assert.ok(!all.includes(c), "a secret or identifier reached an output");
    const left = (await filesUnder(join(cwd, "out"))).concat(await filesUnder(join(cwd, "work")));
    assert.deepEqual(left.filter((f) => /\.cm-/.test(f)), [], "the slice and the output files of the reader are removed");
  });
});

test("a LUKS1 volume: the key slot table from the reader agrees with the header, salts and digests are not read", async () => {
  await withCwd(async (cwd, bin) => {
    LOGPATH = join(cwd, "argv.log");
    const volUuid = uuid();
    await stub(bin, "cryptsetup", stubCryptsetup(LUKS1_DUMP(volUuid, [0, 2])));
    const vol = await volume(cwd, "v.img", luks1(volUuid, [0, 2]));
    const run = await asJob(SCRIPT, cwd, { path: vol }, bin);
    const a = body(run);
    assert.equal(a.status, "complete", a.status_basis);
    assert.equal(a.scheme, "LUKS1");
    assert.equal(a.structural.enabled_slots, 2);
    assert.equal(a.fields.cipher, "aes");
    assert.equal(a.fields.cipher_mode, "xts-plain64");
    assert.equal(a.records.filter((r: Json) => r.state === "enabled").length, 2);
    assert.equal(a.records[2].key_material_offset_sectors, 1016);
    assert.ok(!(await readFile(join(cwd, "argv.log"), "utf8")).includes("--dump-json-metadata"));
    const all = await everything(cwd, run.stdout);
    assert.ok(!all.includes(volUuid));
    assert.doesNotMatch(all, /MK digest|MK salt|Salt:/);
  });
});

test("a LUKS1 reader that disagrees with the header is partial, with the disagreement named", async () => {
  await withCwd(async (cwd, bin) => {
    LOGPATH = join(cwd, "argv.log");
    const volUuid = uuid();
    await stub(bin, "cryptsetup", stubCryptsetup(LUKS1_DUMP(volUuid, [0, 1, 2, 3])));
    const vol = await volume(cwd, "v.img", luks1(volUuid, [0]));
    const a = body(await asJob(SCRIPT, cwd, { path: vol }, bin));
    assert.equal(a.status, "partial");
    assert.match(a.inconsistencies.join(" "), /differ from the header's slot table/);
  });
});

test("BitLocker: the key protectors by type, identifiers and the description only by presence, the clear key flagged", async () => {
  await withCwd(async (cwd, bin) => {
    LOGPATH = join(cwd, "argv.log");
    const guid = uuid();
    const recovery = Array.from({ length: 8 }, () => String(100000 + (randomBytes(3).readUIntBE(0, 3) % 900000))).join("-");
    await stub(bin, "bdeinfo", stubBde(guid, recovery));
    const vol = await volume(cwd, "bl.img", bitlocker(), 4096);
    const run = await asJob(SCRIPT, cwd, { path: vol, offset: 4096 }, bin);
    const a = body(run);
    assert.equal(a.status, "complete", a.status_basis);
    assert.equal(a.scheme, "BitLocker");
    assert.deepEqual(a.structural.metadata_blocks.map((b: Json) => b.valid), [true, true, true]);
    assert.equal(a.structural.metadata_blocks[0].file_offset, 4096 + 4096);
    assert.equal(a.fields.encryption_method, "AES-XTS 128-bit");
    assert.equal(a.fields.volume_identifier_present, true);
    assert.equal(a.fields.description_present, true);
    assert.deepEqual(a.records.map((r: Json) => r.type), ["recovery password", "tpm", "clear key"]);
    assert.equal(a.clear_key_protector_listed, true);
    const argv = (await readFile(join(cwd, "argv.log"), "utf8")).split("\n").filter(Boolean);
    assert.deepEqual(argv.slice(0, 2), ["-o", "4096"]);
    const all = await everything(cwd, run.stdout);
    for (const c of [guid, recovery, CANARY_SALT]) assert.ok(!all.includes(c), "a secret or identifier reached an output");
  });
});

test("BitLocker with a protector count the reader does not keep is partial", async () => {
  await withCwd(async (cwd, bin) => {
    LOGPATH = join(cwd, "argv.log");
    await stub(bin, "bdeinfo", stubBde(uuid(), "x").replace("Number of key protectors\t: 3", "Number of key protectors\t: 5"));
    const vol = await volume(cwd, "bl.img", bitlocker());
    const a = body(await asJob(SCRIPT, cwd, { path: vol }, bin));
    assert.equal(a.status, "partial");
    assert.match(a.inconsistencies.join(" "), /says 5 key protectors and lists 3/);
  });
});

test("Core Storage and APFS: the reader's counts, and the container flag this tool reads itself", async () => {
  await withCwd(async (cwd, bin) => {
    LOGPATH = join(cwd, "argv.log");
    await stub(bin, "fvdeinfo", `#!/bin/sh\nif [ "$1" = "-V" ]; then echo "fvdeinfo 20221030"; exit 0; fi\ncat <<'EOF'\nCore Storage information:\n\tNumber of physical volumes\t: 1\n\tNumber of logical volume groups\t: 1\n\tEncryption method\t: AES-XTS\n\tVolume key\t: ${hex(32)}\nEOF\n`);
    await stub(bin, "fsapfsinfo", `#!/bin/sh\nif [ "$1" = "-V" ]; then echo "fsapfsinfo 20221031"; exit 0; fi\ncat <<'EOF'\nContainer information:\n\tNumber of volumes\t: 2\n\tVolume name\t: ${"vn" + hex(8)}\nEOF\n`);
    const cs = body(await asJob(SCRIPT, cwd, { path: await volume(cwd, "cs.img", coreStorage()) }, bin));
    assert.equal(cs.status, "complete", cs.status_basis);
    assert.equal(cs.scheme, "Apple Core Storage");
    assert.deepEqual(cs.records.map((r: Json) => [r.label, r.value]), [["number of physical volumes", 1], ["number of logical volume groups", 1]]);
    assert.equal(cs.fields.encryption_method, "AES-XTS");
    assert.ok(cs.limits.some((l: string) => /APFS volume is not established/.test(l)));
    const run = await asJob(SCRIPT, cwd, { path: await volume(cwd, "apfs.img", apfs(4n, 3)) }, bin);
    const ap = body(run);
    assert.equal(ap.status, "complete", ap.status_basis);
    assert.equal(ap.structural.software_crypto_flag, true);
    assert.equal(ap.structural.volume_slots_in_use, 3);
    assert.equal(ap.structural.block_size, 4096);
    assert.deepEqual(ap.records.map((r: Json) => r.value), [2]);
    assert.ok(ap.limits.some((l: string) => /no snapshots, no Fusion, no T2/.test(l)));
    const plain = body(await asJob(SCRIPT, cwd, { path: await volume(cwd, "apfs2.img", apfs(0n, 1)) }, bin));
    assert.equal(plain.structural.software_crypto_flag, false);
  });
});

test("a missing reader is unavailable and named, with the structure this tool read; never an empty list", async () => {
  await withCwd(async (cwd) => {
    const vol = await volume(cwd, "v.img", luks1(uuid()));
    const a = body(await asJob(SCRIPT, cwd, { path: vol }, undefined, { PATH: "/usr/bin:/bin" }));
    assert.equal(a.status, "unavailable");
    assert.equal(a.reader.program, "cryptsetup");
    assert.equal(a.reader.status, "unavailable");
    assert.match(a.status_basis, /cryptsetup is not on PATH/);
    assert.equal(a.protectors_listed, null);
    assert.equal(a.records.length, 0);
    assert.equal(a.structural.enabled_slots, 1);
  });
});

test("a reader that fails, rejects the option, prints no fields or prints too much is partial, never an empty list", async () => {
  await withCwd(async (cwd, bin) => {
    LOGPATH = join(cwd, "argv.log");
    const vol = await volume(cwd, "v.img", luks2(16384, "x", uuid(), luks2Json()));
    await stub(bin, "cryptsetup", `#!/bin/sh\nif [ "$1" = "--version" ]; then echo "cryptsetup 2.0.1"; exit 0; fi\necho "cryptsetup: unrecognized option '--dump-json-metadata'" >&2\nexit 1\n`);
    let a = body(await asJob(SCRIPT, cwd, { path: vol }, bin));
    assert.equal(a.status, "partial");
    assert.equal(a.reader.exit_code, 1);
    assert.equal(a.reader.rejected_option, true);
    assert.match(a.status_basis, /not an empty list of protectors/);
    await stub(bin, "cryptsetup", `#!/bin/sh\nif [ "$1" = "--version" ]; then echo "cryptsetup 2.6.1"; exit 0; fi\necho "not json at all"\n`);
    a = body(await asJob(SCRIPT, cwd, { path: vol }, bin));
    assert.equal(a.status, "partial");
    assert.match(a.status_basis, /not the JSON metadata/);
    await stub(bin, "cryptsetup", `#!/bin/sh\nif [ "$1" = "--version" ]; then echo "cryptsetup 2.6.1"; exit 0; fi\nhead -c 9000000 /dev/zero | tr '\\0' 'a'\n`);
    a = body(await asJob(SCRIPT, cwd, { path: vol }, bin));
    assert.equal(a.status, "partial");
    assert.match(a.status_basis, /more than the 8388608 this tool reads/);
  });
});

test("a forged LUKS2 header size or a cut-short header is partial and no reader is run on it", async () => {
  await withCwd(async (cwd, bin) => {
    LOGPATH = join(cwd, "argv.log");
    await stub(bin, "cryptsetup", stubCryptsetup(luks2Json()));
    const forged = luks2(16384, "x", uuid(), luks2Json());
    forged.writeBigUInt64BE(12345n, 8);
    const a = body(await asJob(SCRIPT, cwd, { path: await volume(cwd, "f.img", forged) }, bin));
    assert.equal(a.status, "partial");
    assert.match(a.status_basis, /cryptsetup was not run/);
    assert.equal(await readFile(join(cwd, "argv.log")).then(() => true, () => false), false);
    const cut = body(await asJob(SCRIPT, cwd, { path: await volume(cwd, "c.img", luks1(uuid()).subarray(0, 300)) }, bin));
    assert.equal(cut.status, "partial");
    assert.match(cut.status_basis, /cut short/);
    const v3 = luks1(uuid());
    v3.writeUInt16BE(3, 6);
    const un = body(await asJob(SCRIPT, cwd, { path: await volume(cwd, "v3.img", v3) }, bin));
    assert.equal(un.supported, false);
    assert.equal(un.status, "partial");
  });
});

test("a forged keyslot count is paged losslessly: the page is the limit, the whole is in the file the answer names", async () => {
  await withCwd(async (cwd, bin) => {
    LOGPATH = join(cwd, "argv.log");
    await stub(bin, "cryptsetup", stubCryptsetup(luks2Json(CANARY_SALT, CANARY_DIGEST, 5000)));
    const vol = await volume(cwd, "v.img", luks2(16384, "x", uuid(), luks2Json()));
    const a = body(await asJob(SCRIPT, cwd, { path: vol, limit: 3 }, bin));
    assert.equal(a.status, "complete", a.status_basis);
    assert.equal(a.counts.keyslot, 5002);
    assert.equal(a.returned, 3);
    assert.equal(a.matched, 5002 + 3);
    assert.equal(a.truncated, true);
    const files = await readdir(join(cwd, "out", "tool-output"));
    const whole = files.find((f) => f.endsWith(".jsonl"));
    assert.ok(whole, "the whole result is kept on disk");
    assert.equal((await readFile(join(cwd, "out", "tool-output", whole as string), "utf8")).trim().split("\n").length, 5005);
  });
});

test("an offset past the end, hostile parameters and special files are JSON refusals, never a traceback or a hang", async () => {
  await withCwd(async (cwd, bin) => {
    LOGPATH = join(cwd, "argv.log");
    await stub(bin, "cryptsetup", stubCryptsetup(luks2Json()));
    const vol = await volume(cwd, "v.img", luks1(uuid()));
    const hostile: unknown[] = [
      { path: vol, offset: 10 ** 9 },
      { path: vol, offset: -1 }, { path: vol, offset: 1.5 }, { path: vol, offset: "0" }, { path: vol, offset: true }, { path: vol, offset: 10 ** 40 },
      { path: vol, limit: 0 }, { path: vol, limit: 10 ** 9 }, { path: vol, limit: "5" }, { path: vol, max_seconds: 0 }, { path: vol, max_seconds: 10 ** 9 },
      { path: 5 }, { path: "" }, { path: "a\u0000b" }, { path: "x".repeat(300) }, { path: "x/".repeat(3000) }, { path: ["a"] }, { path: null },
      { path: "." }, { path: cwd }, [], "string", 7, null, { path: "\ud800" },
    ];
    for (const args of hostile) {
      const run = await asJob(SCRIPT, cwd, args, bin);
      const a = refused(run);
      assert.equal(a.status, "failed", JSON.stringify(args));
      assert.ok(a.error && a.status_basis);
    }
    const nested = await asJob(SCRIPT, cwd, "[".repeat(200000), bin);
    assert.equal(refused(nested).status, "failed");
    await symlink(join(cwd, "v.img"), join(cwd, "link.img"));
    assert.match(refused(await asJob(SCRIPT, cwd, { path: "link.img" }, bin)).error, /symbolic link/);
    assert.match(refused(await asJob(SCRIPT, cwd, { path: "missing.img" }, bin)).error, /could not be read/);
    const fifo = join(cwd, "pipe.img");
    assert.equal(spawnSync("mkfifo", [fifo]).status, 0);
    const started = Date.now();
    assert.match(refused(await asJob(SCRIPT, cwd, { path: "pipe.img" }, bin)).error, /not a regular file/);
    assert.ok(Date.now() - started < 10_000, "a FIFO does not hold the tool");
    await writeFile(join(cwd, "empty.img"), "");
    assert.match(refused(await asJob(SCRIPT, cwd, { path: "empty.img" }, bin)).error, /empty/);
  });
});

test("a call that is not a job still answers: the files go under work/<agent>", async () => {
  await withCwd(async (cwd, bin) => {
    LOGPATH = join(cwd, "argv.log");
    await stub(bin, "cryptsetup", stubCryptsetup(LUKS1_DUMP("u", [0])));
    const vol = await volume(cwd, "v.img", luks1(uuid(), [0]));
    const a = body(await tool(SCRIPT, cwd, { path: vol }, { ARGV_LOG: join(cwd, "argv.log") }, bin));
    assert.equal(a.status, "complete", a.status_basis);
    assert.deepEqual((await filesUnder(join(cwd, "work"))).filter((f) => f.includes(".cm-")), []);
  });
});

test("a reader that outlives the tool's clock is ended with what it started: partial, one document, no process left", async () => {
  await withCwd(async (cwd, bin) => {
    LOGPATH = join(cwd, "argv.log");
    const pid = join(cwd, "reader.pid");
    await stub(bin, "bdeinfo", `#!/bin/sh\nif [ "$1" = "-V" ]; then echo "bdeinfo 20221031"; exit 0; fi\necho $$ > "${pid}"\nsleep 60 &\nwait\n`);
    const vol = await volume(cwd, "bl.img", bitlocker());
    const started = Date.now();
    const a = body(await asJob(SCRIPT, cwd, { path: vol, max_seconds: 4 }, bin));
    assert.ok(Date.now() - started < 20_000, "the clock held");
    assert.equal(a.status, "partial");
    assert.match(a.status_basis, /time budget was reached/);
    assert.ok(await gone(await pidFile(pid)), "the reader is gone");
  });
});

test("SIGTERM during a reader: one JSON document, exit 143, the reader gone, the scratch files removed", async () => {
  await withCwd(async (cwd, bin) => {
    LOGPATH = join(cwd, "argv.log");
    const pid = join(cwd, "reader.pid");
    await stub(bin, "bdeinfo", `#!/bin/sh\nif [ "$1" = "-V" ]; then echo "bdeinfo 20221031"; exit 0; fi\necho $$ > "${pid}"\nsleep 60\n`);
    const vol = await volume(cwd, "bl.img", bitlocker());
    await mkdir(join(cwd, "out"), { recursive: true });
    const run = startDetached(SCRIPT, cwd, { path: vol }, { JOB_ID: "j1", OUT: join(cwd, "out"), SECRET_OUTPUT: "1" }, bin);
    const reader = await pidFile(pid);
    run.signal("SIGTERM");
    assert.equal(await run.closed, 143);
    const docs = run.stdout().trim().split("\n").filter(Boolean);
    assert.equal(docs.length, 1, "exactly one document");
    const a = JSON.parse(run.stdout());
    assert.equal(a.status, "failed");
    assert.equal(a.interrupted, true);
    assert.ok(await gone(reader), "the reader is gone");
    assert.deepEqual((await filesUnder(join(cwd, "out"))).filter((f) => f.includes(".cm-")), []);
  });
});

test("the worst case at the limits stays under the clock: 8 MiB of hostile reader lines, and a LUKS2 JSON area full of keyslots", async () => {
  await withCwd(async (cwd, bin) => {
    LOGPATH = join(cwd, "argv.log");
    // lines of blanks and colons (the shape that makes a backtracking label rule slow), 7.5 MiB of them
    await stub(bin, "bdeinfo", `#!/bin/sh\nif [ "$1" = "-V" ]; then echo "bdeinfo 20221031"; exit 0; fi\nawk 'BEGIN { s = sprintf("%550s", ""); for (i = 0; i < 14000; i++) print s ":" s ":" }'\n`);
    const started = Date.now();
    const a = body(await asJob(SCRIPT, cwd, { path: await volume(cwd, "bl.img", bitlocker()) }, bin));
    assert.ok(Date.now() - started < 40_000, `hostile bdeinfo output took ${Date.now() - started} ms`);
    assert.equal(a.status, "partial");
    const keys = Array.from({ length: 150000 }, (_, i) => `"${i}":{"type":"luks2"}`).join(",");
    const json = `{"keyslots":{${keys}},"segments":{},"digests":{},"tokens":{},"config":{"json_size":"12288"}}`;
    await stub(bin, "cryptsetup", stubCryptsetup(json));
    const t2 = Date.now();
    const b = body(await asJob(SCRIPT, cwd, { path: await volume(cwd, "l.img", luks2(16384, "x", uuid(), luks2Json())), limit: 10 }, bin));
    assert.ok(Date.now() - t2 < 60_000, `a forged keyslot area took ${Date.now() - t2} ms`);
    assert.equal(b.counts.keyslot, 150000);
    assert.equal(b.returned, 10);
  });
});

test("the real cryptsetup reads a LUKS1 header built from the specification (gated on the program being installed)", async (t) => {
  const which = spawnSync("sh", ["-c", "command -v cryptsetup"]);
  if (which.status !== 0) {
    t.skip("cryptsetup is not on this host's PATH");
    return;
  }
  await withCwd(async (cwd) => {
    const vol = await volume(cwd, "v.img", luks1(uuid(), [0]));
    const a = body(await asJob(SCRIPT, cwd, { path: vol }, undefined));
    assert.ok(["complete", "partial"].includes(a.status));
    assert.equal(a.scheme, "LUKS1");
  });
});

test("the tool carries the shared blocks of its lineage byte for byte, STOP first, and starts nothing in a session of its own", async () => {
  const text = await readFile(SCRIPT, "utf8");
  const sibling = await readFile(join(ROOT, "packs", "encrypted-containers", "tools", "tcrypt_header", "run.py"), "utf8");
  const cut = (t: string, n: string): string => t.slice(t.indexOf(`# BEGIN SHARED ${n}`), t.indexOf(`# END SHARED ${n}`));
  for (const n of ["STOP", "WITHHOLDING", "NAMES", "PROCESS"]) assert.equal(cut(text, n), cut(sibling, n), n);
  for (const n of ["PLACE", "PAGE", "WITHHOLDING", "NAMES", "PROCESS"]) assert.ok(text.indexOf("# BEGIN SHARED STOP") < text.indexOf(`# BEGIN SHARED ${n}`), n);
  assert.doesNotMatch(text.replace(/^\s*#.*$/gm, "").replace(/"""[\s\S]*?"""/g, ""), /start_new_session|setsid|process_group/);
});
