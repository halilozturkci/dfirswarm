/**
 * encrypted-containers: the findings of the second independent review (R2) of archive_probe, crypto_id and recovery_key_scan, one test each.
 * Every test here fails on the tools as they were. Fixtures are built from the APPNOTE's record layouts, never from a tool's own output.
 */
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { chmod, mkdir, readFile, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { crc32 } from "node:zlib";
import { ROOT, runPy, withCwd } from "./tool-library-harness.ts";

const ENC = join(ROOT, "packs", "encrypted-containers");
const PROBE = join(ENC, "tools", "archive_probe", "run.py");
const ID = join(ENC, "tools", "crypto_id", "run.py");
const SCAN = join(ENC, "tools", "recovery_key_scan", "run.py");
const AGENT = { AGENT_ID: "s1" };

type Run = { code: number | null; stdout: string; stderr: string };
type Json = Record<string, any>;

const tool = (script: string, cwd: string, args: unknown, env: Record<string, string> = {}, bin?: string): Promise<Run> =>
  runPy(script, cwd, args, bin, { ...AGENT, ...env });

function answer(out: Run, code = 0): Json {
  assert.equal(out.code, code, out.stderr + out.stdout);
  assert.doesNotMatch(out.stderr, /Traceback/);
  return JSON.parse(out.stdout) as Json;
}

const DOS_DATE = ((2026 - 1980) << 9) | (3 << 5) | 14;
const DOS_TIME = (9 << 11) | (30 << 5) | 22;

type Member = { name: string; flags?: number; localFlags?: number; data?: Buffer; version?: number; method?: number; dd?: boolean; gapAfter?: Buffer };
type Dummy = { name: string; offset: number; size: number };

/** A ZIP from the APPNOTE's record layouts. `localFlags` is the local header's flags where they are not the directory's. */
type Mutation = "sigflip" | "cdsize+1" | "cdsize-1" | "cdsize0" | "digsig" | "noEnd" | "noDir" | "commentOverrun";

function buildZip(members: Member[], opts: { disk?: number; cdDisk?: number; dropLocal?: boolean; zip64Extensible?: number; base?: number; mutate?: Mutation; extraEntries?: Dummy[]; gapBeforeDirectory?: Buffer } = {}): Buffer {
  const parts: Buffer[] = [];
  const central: Buffer[] = [];
  let at = opts.base ?? 0; // the offsets count from the start of the file (`zip -A`) when a base is given
  for (const m of members) {
    const name = Buffer.from(m.name, "utf8");
    const data = m.data ?? Buffer.from("x");
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(m.version ?? 20, 4);
    local.writeUInt16LE((m.localFlags ?? m.flags ?? 0) | (m.dd ? 8 : 0), 6);
    local.writeUInt16LE(m.method ?? 0, 8);
    local.writeUInt32LE(m.dd ? 0 : data.length, 18);
    local.writeUInt32LE(m.dd ? 0 : data.length, 22);
    local.writeUInt16LE(name.length, 26);
    const descriptor = m.dd ? Buffer.concat([Buffer.from("PK\x07\x08", "latin1"), Buffer.alloc(4), (() => { const b = Buffer.alloc(8); b.writeUInt32LE(data.length, 0); b.writeUInt32LE(data.length, 4); return b; })()]) : Buffer.alloc(0);
    const record = opts.dropLocal ? Buffer.alloc(30 + name.length + data.length) : Buffer.concat([local, name, data, descriptor, m.gapAfter ?? Buffer.alloc(0)]);
    const c = Buffer.alloc(46);
    c.writeUInt32LE(0x02014b50, 0);
    c.writeUInt16LE(20, 4);
    c.writeUInt16LE(m.version ?? 20, 6);
    c.writeUInt16LE((m.flags ?? 0) | (m.dd ? 8 : 0), 8);
    c.writeUInt16LE(m.method ?? 0, 10);
    c.writeUInt16LE(DOS_TIME, 12);
    c.writeUInt16LE(DOS_DATE, 14);
    c.writeUInt32LE(data.length, 20);
    c.writeUInt32LE(data.length, 24);
    c.writeUInt16LE(name.length, 28);
    c.writeUInt32LE(at, 42);
    central.push(Buffer.concat([c, name]));
    parts.push(record);
    at += record.length;
  }
  if (opts.gapBeforeDirectory) {
    parts.push(opts.gapBeforeDirectory);
    at += opts.gapBeforeDirectory.length;
  }
  for (const d of opts.extraEntries ?? []) {
    const name = Buffer.from(d.name, "utf8");
    const c = Buffer.alloc(46);
    c.writeUInt32LE(0x02014b50, 0);
    c.writeUInt16LE(20, 4);
    c.writeUInt16LE(20, 6);
    c.writeUInt16LE(DOS_TIME, 12);
    c.writeUInt16LE(DOS_DATE, 14);
    c.writeUInt32LE(d.size, 20);
    c.writeUInt32LE(d.size, 24);
    c.writeUInt16LE(name.length, 28);
    c.writeUInt32LE(d.offset, 42);
    central.push(Buffer.concat([c, name]));
  }
  const total = members.length + (opts.extraEntries?.length ?? 0);
  const cd = Buffer.concat(central);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(opts.mutate === "sigflip" ? 0x06054b51 : 0x06054b50, 0);
  eocd.writeUInt16LE(opts.disk ?? 0, 4);
  eocd.writeUInt16LE(opts.cdDisk ?? 0, 6);
  eocd.writeUInt16LE(total, 8);
  eocd.writeUInt16LE(total, 10);
  eocd.writeUInt32LE(opts.mutate === "cdsize+1" ? cd.length + 1 : opts.mutate === "cdsize-1" ? cd.length - 1 : opts.mutate === "cdsize0" ? 0 : cd.length, 12);
  eocd.writeUInt32LE(at, 16);
  if (opts.mutate === "commentOverrun") eocd.writeUInt16LE(4000, 20);
  if (opts.mutate === "noDir") return Buffer.concat(parts);
  if (opts.mutate === "noEnd") return Buffer.concat([...parts, cd]);
  if (opts.mutate === "digsig") return Buffer.concat([...parts, cd, Buffer.from("PK\x05\x05", "latin1"), Buffer.from([16, 0]), Buffer.alloc(16, 0x53), eocd]);
  if (opts.zip64Extensible === undefined) return Buffer.concat([...parts, cd, eocd]);
  // A Zip64 end record with extensible data (its size field above 44), a locator, and an End record that points to both.
  const rec = Buffer.alloc(56 + opts.zip64Extensible);
  rec.write("PK\x06\x06", 0, "latin1");
  rec.writeBigUInt64LE(BigInt(44 + opts.zip64Extensible), 4);
  rec.writeUInt16LE(45, 12);
  rec.writeUInt16LE(45, 14);
  rec.writeBigUInt64LE(BigInt(total), 24);
  rec.writeBigUInt64LE(BigInt(total), 32);
  rec.writeBigUInt64LE(BigInt(cd.length), 40);
  rec.writeBigUInt64LE(BigInt(at), 48);
  rec.fill(0x41, 56);
  const loc = Buffer.alloc(20);
  loc.write("PK\x06\x07", 0, "latin1");
  loc.writeBigUInt64LE(BigInt(at + cd.length), 8);
  loc.writeUInt32LE(1, 16);
  eocd.writeUInt16LE(0xffff, 8);
  eocd.writeUInt16LE(0xffff, 10);
  eocd.writeUInt32LE(0xffffffff, 12);
  eocd.writeUInt32LE(0xffffffff, 16);
  return Buffer.concat([...parts, cd, rec, loc, eocd]);
}

const plain = (n: number, prefix = "p") => Array.from({ length: n }, (_, i) => ({ name: `${prefix}/${String(i).padStart(5, "0")}-a-fairly-long-member-name.txt` }));

// --- P1-A: 7-Zip expands wildcards in the archive's name ------------------------------------------------------------------

const REAL_7Z = ["7z", "7zz", "7za"].find((n) => spawnSync(n, ["i"], { stdio: "ignore" }).status === 0);

/** A 7z stand-in that behaves as 7-Zip does for a name with `?` or `*`: without -spd it lists every sibling's archive as well. */
async function globbingSeven(bin: string): Promise<void> {
  const script = `#!/bin/sh
spd=no
last=""
for a in "$@"; do [ "$a" = "-spd" ] && spd=yes; last="$a"; done
printf '\\n7-Zip 26.00\\n\\nListing archive: %s\\n\\n--\\nPath = %s\\nType = 7z\\nPhysical Size = 100\\nHeaders Size = 50\\nMethod = LZMA2:12\\nSolid = +\\nBlocks = 1\\n\\n----------\\nPath = plain.txt\\nSize = 1\\nPacked Size = 1\\nEncrypted = -\\nMethod = LZMA2:12\\n\\n' "$last" "$last"
case "$last" in
  *\\?*|*\\**)
    if [ "$spd" = no ]; then
      printf 'Listing archive: sibling.7z\\n\\n--\\nPath = sibling.7z\\nType = 7z\\n\\n----------\\nPath = secret0.txt\\nSize = 9\\nPacked Size = 9\\nEncrypted = +\\nMethod = LZMA2:12 7zAES:19\\n\\nPath = secret1.txt\\nSize = 9\\nPacked Size = 9\\nEncrypted = +\\nMethod = LZMA2:12 7zAES:19\\n\\n'
    fi ;;
esac
exit 0
`;
  await writeFile(join(bin, "7z"), script);
  await chmod(join(bin, "7z"), 0o755);
}

async function sevenArchive(cwd: string, name: string): Promise<void> {
  // The start header of a 7z whose next header is empty (only the signature matters for the dispatch).
  // 100 bytes, as the stand-ins' listings say ("Physical Size = 100"): the archive must cover the file.
  const start = Buffer.alloc(100);
  Buffer.from([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c, 0x00, 0x04]).copy(start, 0);
  await writeFile(join(cwd, "work", name), start);
}

test("archive_probe never lets 7-Zip expand a wildcard in the archive's name (a file called ?.7z lists itself, not its siblings)", async () => {
  await withCwd(async (cwd, bin) => {
    await globbingSeven(bin);
    await sevenArchive(cwd, "?.7z");
    await sevenArchive(cwd, "*.7z");
    for (const name of ["?.7z", "*.7z"]) {
      const out = answer(await tool(PROBE, cwd, { path: `work/${name}` }, {}, bin));
      assert.equal(out.member_count, 1, name);
      assert.deepEqual(out.members.map((m: Json) => m.name), ["plain.txt"]);
      assert.equal(out.protected, false);
      assert.equal(out.status, "complete");
    }
  });
});

test("archive_probe: 7-Zip output that is not one archive's listing is not taken as the archive's (a second listing, a stray line, a repeated key)", async () => {
  await withCwd(async (cwd, bin) => {
    await sevenArchive(cwd, "a.7z");
    const head = "\\n7-Zip 26.00\\n\\n--\\nPath = a.7z\\nType = 7z\\n\\n----------\\n";
    const cases: Record<string, string> = {
      // two archives listed (an old build that expands the name, or a path that matched more than one file)
      second_listing: `${head}Path = one.txt\\nSize = 1\\nEncrypted = -\\n\\n--\\nPath = b.7z\\nType = 7z\\n\\n----------\\nPath = two.txt\\nSize = 1\\nEncrypted = -\\n\\n`,
      // a member name with a line break, printed as it is by a build that does not escape it, forged "Encrypted = -" and a blank line
      stray_line: `${head}Path = A\\nEncrypted = -\\n\\nSize = 5\\nEncrypted = +\\n\\n`,
      repeated_key: `${head}Path = A\\nEncrypted = +\\nEncrypted = -\\n\\n`,
    };
    for (const [name, body] of Object.entries(cases)) {
      await writeFile(join(bin, "7z"), `#!/bin/sh\nprintf '${body}'\nexit 0\n`);
      await chmod(join(bin, "7z"), 0o755);
      const out = answer(await tool(PROBE, cwd, { path: "work/a.7z" }, {}, bin));
      assert.equal(out.status, "partial", name);
      assert.notEqual(out.protected, false, name);
      assert.equal(out.listing.status, "listing_not_one_archive", name);
    }
  });
});

test("archive_probe: a 7-Zip warning with exit 0 (data after the end of the archive) is not a complete listing, and protected is not false", async () => {
  await withCwd(async (cwd, bin) => {
    await sevenArchive(cwd, "a.7z");
    await writeFile(join(bin, "7z"), `#!/bin/sh
printf '\\n--\\nPath = a.7z\\nType = 7z\\nPhysical Size = 100\\n\\n----------\\nPath = plain.txt\\nSize = 1\\nEncrypted = -\\n\\nWarnings: 1\\n'
echo 'WARNING:' >&2
echo 'There are some data after the end of the payload data' >&2
exit 0
`);
    await chmod(join(bin, "7z"), 0o755);
    const out = answer(await tool(PROBE, cwd, { path: "work/a.7z" }, {}, bin));
    assert.notEqual(out.status, "complete");
    assert.notEqual(out.protected, false);
  });
});

test("archive_probe lists a real file called ?.7z through the installed 7-Zip as itself alone", { skip: REAL_7Z ? false : "no 7z on PATH" }, async (t) => {
  await withCwd(async (cwd) => {
    const ev = join(cwd, "ev");
    await mkdir(ev, { recursive: true });
    await writeFile(join(cwd, "enc.txt"), "x".repeat(50));
    await writeFile(join(cwd, "plain.txt"), "p");
    const sz = (args: string[]) => spawnSync(REAL_7Z!, args, { cwd, stdio: "ignore" });
    sz(["a", "-y", "-psecret1", join(ev, "a.7z"), "enc.txt"]);
    sz(["a", "-y", join(ev, "?.7z"), "plain.txt"]);
    // Not every 7-Zip build writes an archive under a name with a wildcard in it; where it does not, there is no such file to list.
    if (!(await stat(join(ev, "?.7z")).then(() => true, () => false)) || !(await stat(join(ev, "a.7z")).then(() => true, () => false))) return t.skip("this 7z did not create the archives");
    const out = answer(await tool(PROBE, cwd, { path: "ev/?.7z" }));
    assert.equal(out.member_count, 1);
    assert.deepEqual(out.members.map((m: Json) => m.name), ["plain.txt"]);
    assert.equal(out.protected, false);
  });
});

// --- P1-B: the document reader that exists is named -----------------------------------------------------------------------

test("archive_probe and crypto_id name doc_structure, not 'not available yet' or 'planned', for a PDF and an OLE file", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "a.pdf"), "%PDF-1.4\n1 0 obj\n<< /Encrypt 5 0 R >>\nendobj\n%%EOF\n");
    await writeFile(join(cwd, "work", "a.doc"), Buffer.concat([Buffer.from("d0cf11e0a1b11ae1", "hex"), Buffer.alloc(600)]));
    for (const script of [PROBE, ID]) {
      for (const f of ["a.pdf", "a.doc"]) {
        const out = await tool(script, cwd, { path: `work/${f}` });
        const doc = answer(out);
        assert.match(doc.next_reader, /doc_structure/, `${script} ${f}`);
        assert.match(doc.next_reader, /reverse-engineering pack/);
        assert.doesNotMatch(out.stdout, /not available yet|planned for|reader is not provided/i);
      }
    }
  });
});

// --- P1-C and what followed: the file is accounted for, not only checked for contradictions ------------------------------

const FIRST = [{ name: "a.txt", flags: 1 }, { name: "b.txt", flags: 1 }, { name: "c.txt" }];
const MZ_STUB = Buffer.concat([Buffer.from("MZ"), Buffer.alloc(2000, 0x90)]);
const JUNK = Buffer.from(Array.from({ length: 50 }, (_, i) => (i * 37 + 11) & 0x7f | 0x20));

test("archive_probe: a second archive appended, larger than the last 64 KiB, is not 'complete' with 'protected: false'", async () => {
  await withCwd(async (cwd) => {
    const first = buildZip(FIRST);
    const second = buildZip(plain(3000));
    assert.ok(second.length > 200_000, "the second archive's directory is above 64 KiB");
    await writeFile(join(cwd, "work", "two.zip"), Buffer.concat([first, second]));
    const out = answer(await tool(PROBE, cwd, { path: "work/two.zip" }));
    assert.equal(out.status, "partial");
    assert.notEqual(out.protected, false);
    assert.equal(out.archive_in_front.at, 0);
    assert.deepEqual(out.archive_in_front.region, [0, first.length]);
    assert.match(out.status_basis, /another archive, whole or damaged, shares this file/);
  });
});

// The first archive in every shape 7-Zip still lists (a damaged End record, a missing one, no directory at all, a signature record between the
// directory and the End record, an End record whose comment runs into the next archive, a Zip64 record with 450 bytes of extensible data), behind
// every kind of prefix, and a second archive of either size behind it. None of them is a complete answer, and none says `protected: false`.
test("archive_probe: an archive in front is found whatever shape its own End record has, behind any prefix, before a small or a big archive", async () => {
  await withCwd(async (cwd) => {
    const shapes: Record<string, Buffer> = {
      intact: buildZip(FIRST),
      sigflip: buildZip(FIRST, { mutate: "sigflip" }),
      "cdsize+1": buildZip(FIRST, { mutate: "cdsize+1" }),
      "cdsize-1": buildZip(FIRST, { mutate: "cdsize-1" }),
      cdsize0: buildZip(FIRST, { mutate: "cdsize0" }),
      digsig: buildZip(FIRST, { mutate: "digsig" }),
      noEnd: buildZip(FIRST, { mutate: "noEnd" }),
      noDir: buildZip(FIRST, { mutate: "noDir" }),
      commentOverrun: buildZip(FIRST, { mutate: "commentOverrun" }),
      zip64ext450: buildZip(FIRST, { zip64Extensible: 450 }),
    };
    const prefixes: Record<string, Buffer> = { none: Buffer.alloc(0), mz: MZ_STUB, junk: JUNK, spanning: Buffer.from("PK\x07\x08", "latin1"), pk00: Buffer.from("PK00", "latin1") };
    const backs: Record<string, Buffer> = { big: buildZip(plain(3000)), small: buildZip(plain(1)) };
    let cases = 0;
    for (const [shape, front] of Object.entries(shapes)) {
      for (const [pn, prefix] of Object.entries(prefixes)) {
        for (const [bn, back] of Object.entries(backs)) {
          const name = `${shape}-${pn}-${bn}.bin`;
          await writeFile(join(cwd, "work", name), Buffer.concat([prefix, front, back]));
          const out = answer(await tool(PROBE, cwd, { path: `work/${name}` }));
          cases++;
          assert.notEqual(out.status, "complete", name);
          assert.notEqual(out.protected, false, name);
        }
      }
    }
    assert.equal(cases, 100);
  });
});

// The last archive's offsets count from the start of the file (what `zip -A` and `zip -F` write), so that the first member is not where a
// bound computed from the End record's offset would put the front of the archive.
test("archive_probe: an archive in front of one whose offsets are absolute is found (zip -A)", async () => {
  await withCwd(async (cwd) => {
    const first = buildZip(FIRST);
    for (const [pn, prefix] of [["none", Buffer.alloc(0)], ["mz", MZ_STUB], ["junk", JUNK]] as const) {
      for (const n of [1, 3000]) {
        const second = buildZip(plain(n), { base: prefix.length + first.length });
        await writeFile(join(cwd, "work", `abs-${pn}-${n}.bin`), Buffer.concat([prefix, first, second]));
        const out = answer(await tool(PROBE, cwd, { path: `work/abs-${pn}-${n}.bin` }));
        assert.notEqual(out.status, "complete", `${pn} ${n}`);
        assert.notEqual(out.protected, false, `${pn} ${n}`);
        assert.equal(out.archive_in_front.region[1], prefix.length + first.length, `${pn} ${n}`);
        assert.equal(out.entry_count, n);
      }
    }
    // Absolute offsets alone (an adjusted self-extracting archive) are the archive and nothing else: complete.
    const adjusted = Buffer.concat([MZ_STUB, buildZip(plain(20), { base: MZ_STUB.length })]);
    await writeFile(join(cwd, "work", "adjusted.exe"), adjusted);
    const ok = answer(await tool(PROBE, cwd, { path: "work/adjusted.exe" }));
    assert.deepEqual([ok.status, ok.protected, ok.entry_count], ["complete", false, 20]);
  });
});

// Another format in front: a 7-Zip start header (with its CRC right) and a RAR block (with its CRC right).
test("archive_probe: a 7-Zip or RAR archive in front of a ZIP is found", async () => {
  await withCwd(async (cwd) => {
    const startHeader = Buffer.alloc(32);
    Buffer.from([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c, 0x00, 0x04]).copy(startHeader, 0);
    startHeader.writeUInt32LE(crc32(startHeader.subarray(12, 32)), 8);
    const rar5body = Buffer.from([0x03, 0x01, 0x00, 0x00]); // header size 3, type 1 (main), flags 0, archive flags 0
    const rar5 = Buffer.alloc(8 + 4 + 4);
    Buffer.from("Rar!\x1a\x07\x01\x00", "latin1").copy(rar5, 0);
    rar5.writeUInt32LE(crc32(rar5body), 8);
    rar5body.copy(rar5, 12);
    const second = buildZip(plain(3000));
    for (const [label, front] of [["7z", startHeader], ["rar5", rar5]] as const) {
      for (const [pn, prefix] of [["none", Buffer.alloc(0)], ["mz", MZ_STUB], ["junk", JUNK]] as const) {
        await writeFile(join(cwd, "work", `${label}-${pn}.bin`), Buffer.concat([prefix, front, Buffer.alloc(40, 0x61), second]));
        const out = answer(await tool(PROBE, cwd, { path: `work/${label}-${pn}.bin` }));
        // With the 7z or the RAR at byte 0 the file is read as that format (no ZIP is read at all).
        if (out.container === "ZIP") assert.notEqual(out.status, "complete", `${label} ${pn}`);
        assert.notEqual(out.protected, false, `${label} ${pn}`);
      }
    }
  });
});

test("archive_probe: self-extracting stubs, executables and polyglots in front of one archive stay complete", async () => {
  await withCwd(async (cwd) => {
    const zip = buildZip(plain(3000));
    const enc = buildZip([{ name: "a.txt", flags: 1 }, { name: "b.txt" }]);
    // An unzip stub holds the record signatures as constants, and nothing that follows them is a record.
    const unzipStub = Buffer.concat([Buffer.from("MZ"), Buffer.alloc(300, 0x90), Buffer.from("PK\x05\x06"), Buffer.from("PK\x03\x04PK\x01\x02PK\x06\x06PK\x06\x07"), Buffer.alloc(5000, 0x41), Buffer.from("PK\x05\x06\x00\x00\x00\x00\x03\x00\x03\x00"), Buffer.alloc(2000, 0x42)]);
    // The all-zero End record of a ZIP library (python's zipimport, libzip): an empty archive, which holds no member.
    const zipLibrary = Buffer.concat([Buffer.from("\x7fELF"), Buffer.alloc(100, 0x07), Buffer.from("PK\x05\x06"), Buffer.alloc(18), Buffer.alloc(100, 0x07)]);
    const stubs: Record<string, Buffer> = {
      unzip_stub: unzipStub,
      zip_library: zipLibrary,
      elf: Buffer.concat([Buffer.from("\x7fELF"), Buffer.alloc(4000, 0x07)]),
      shell: Buffer.from("#!/bin/sh\nexec java -jar \"$0\" \"$@\"\n"),
      png_polyglot: Buffer.concat([Buffer.from("\x89PNG\r\n\x1a\n"), Buffer.alloc(100_000, 0x5a)]),
    };
    for (const [name, stub] of Object.entries(stubs)) {
      for (const [label, archive, protectedWant, abs] of [["plain", zip, false, false], ["encrypted", enc, true, false], ["adjusted", buildZip(plain(20), { base: stub.length }), false, true]] as const) {
        await writeFile(join(cwd, "work", `${name}-${label}.bin`), Buffer.concat([stub, archive]));
        const out = answer(await tool(PROBE, cwd, { path: `work/${name}-${label}.bin` }));
        assert.equal(out.status, "complete", `${name} ${label}: ${out.status_basis}`);
        assert.equal(out.protected, protectedWant, `${name} ${label}`);
        assert.equal(out.archive_in_front, undefined, abs ? `${name} ${label}` : label);
        assert.equal(out.dark_unsearched, undefined);
      }
    }
  });
});

test("archive_probe: bytes no member claims that hold more archive signatures than can be checked are named as not searched, and the answer is partial", async () => {
  await withCwd(async (cwd) => {
    const stub = Buffer.concat([Buffer.from("MZ"), ...Array.from({ length: 20_500 }, () => Buffer.from("PK\x05\x06xxxxxxxxxxxxxxxxxx"))]);
    await writeFile(join(cwd, "work", "many.bin"), Buffer.concat([stub, buildZip(plain(10))]));
    const out = answer(await tool(PROBE, cwd, { path: "work/many.bin" }));
    assert.equal(out.status, "partial");
    assert.notEqual(out.protected, false);
    assert.match(out.dark_unsearched.why, /more than 20000 archive signatures/);
  });
});

// 7-Zip is a second reader: where it reads the file as a ZIP and lists other members, or reads it as another format, the answer is partial.
test("archive_probe compares what 7-Zip lists with what it read: a different count, a different format and a listing that does not finish are partial", async () => {
  await withCwd(async (cwd, bin) => {
    await writeFile(join(cwd, "work", "two.zip"), buildZip([{ name: "a.txt" }, { name: "b.txt" }]));
    const listing = (type: string, members: number, encrypted: number) => {
      const rows = Array.from({ length: members }, (_, i) => `Path = m${i}\nSize = 1\nEncrypted = ${i < encrypted ? "+" : "-"}\n\n`).join("");
      return `\n--\nPath = two.zip\nType = ${type}\nPhysical Size = 1\n\n----------\n${rows}`;
    };
    const cases: Array<[string, string, string]> = [
      ["same", listing("zip", 2, 0), "complete"],
      ["more members", listing("zip", 3, 1), "partial"],
      ["an encrypted member", listing("zip", 2, 1), "partial"],
      ["another format", listing("7z", 2, 0), "partial"],
      ["a program (a stub)", listing("PE", 5, 0), "complete"],
    ];
    for (const [label, body, want] of cases) {
      await writeFile(join(bin, "7z"), `#!/bin/sh\nprintf '${body.replace(/\n/g, "\\n")}'\nexit 0\n`);
      await chmod(join(bin, "7z"), 0o755);
      const out = answer(await tool(PROBE, cwd, { path: "work/two.zip" }, {}, bin));
      assert.equal(out.status, want, label);
      if (want === "partial") assert.notEqual(out.protected, false, label);
    }
    // A 7-Zip that does not finish within the tool's clock.
    await writeFile(join(bin, "7z"), "#!/bin/sh\nprintf '\\n--\\nPath = two.zip\\nType = zip\\n\\n----------\\n'\nexec sleep 20\n");
    await chmod(join(bin, "7z"), 0o755);
    const slow = answer(await tool(PROBE, cwd, { path: "work/two.zip", max_seconds: 2 }, {}, bin));
    assert.equal(slow.status, "partial");
    assert.notEqual(slow.protected, false);
  });
});

// --- P1-D: the local header's flags -----------------------------------------------------------------------------------

test("archive_probe: a member the directory calls plain and its local header calls encrypted is not 'protected: false', nor 'complete'", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "lh.zip"), buildZip([{ name: "s.txt", flags: 0, localFlags: 1 }]));
    const out = answer(await tool(PROBE, cwd, { path: "work/lh.zip" }));
    assert.equal(out.encrypted_entries, 0);
    assert.notEqual(out.protected, false);
    assert.notEqual(out.status, "complete");
    assert.equal(out.local_header_flags.conflicts, 1);
    assert.equal(out.local_header_flags.examples[0].local_header_says_encrypted, true);
    assert.match(out.status_basis, /central directory and the local header disagree/);

    // The other way round (the directory says encrypted): protected stays true, the status is still not complete.
    await writeFile(join(cwd, "work", "lh2.zip"), buildZip([{ name: "s.txt", flags: 1, localFlags: 0 }]));
    const back = answer(await tool(PROBE, cwd, { path: "work/lh2.zip" }));
    assert.equal(back.protected, true);
    assert.notEqual(back.status, "complete");
    assert.equal(back.local_header_flags.conflicts, 1);

    // Agreement: complete, and the comparison is counted.
    await writeFile(join(cwd, "work", "lh3.zip"), buildZip([{ name: "s.txt" }, { name: "t.txt", flags: 1 }]));
    const same = answer(await tool(PROBE, cwd, { path: "work/lh3.zip" }));
    assert.equal(same.status, "complete");
    assert.deepEqual(same.local_header_flags, { compared: 2, conflicts: 0, unreadable: 0 });
  });
});

test("archive_probe: a member with no local header where the directory says is not 'protected: false'", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "nolocal.zip"), buildZip([{ name: "s.txt" }], { dropLocal: true }));
    const out = answer(await tool(PROBE, cwd, { path: "work/nolocal.zip" }));
    assert.equal(out.local_header_flags.unreadable, 1);
    assert.equal(out.protected, null);
    assert.equal(out.status, "partial");
  });
});

// --- P3-3, P3-11 -------------------------------------------------------------------------------------------------------

test("archive_probe reads a Zip64 end record with extensible data (its size field above 44)", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "ext.zip"), buildZip([{ name: "a.txt", flags: 1 }, { name: "b.txt" }], { zip64Extensible: 24 }));
    const out = answer(await tool(PROBE, cwd, { path: "work/ext.zip" }));
    assert.equal(out.status, "complete");
    assert.equal(out.entry_count, 2);
    assert.equal(out.encrypted_entries, 1);
    assert.equal(out.zip64, true);
    assert.equal(out.zip64_extensible_data_bytes, 24);
  });
});

test("archive_probe says that an End record with disk numbers is one part of a split archive", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "last.zip"), buildZip([{ name: "a.txt" }], { disk: 1, cdDisk: 1 }));
    const out = answer(await tool(PROBE, cwd, { path: "work/last.zip" }));
    assert.deepEqual([out.split_archive.this_disk, out.split_archive.central_directory_disk], [1, 1]);
    assert.match(out.split_archive.note, /other parts/);
    assert.equal(out.entry_count, 1);
    assert.equal(out.status, "complete");
  });
});

// --- P3-4: a special file is not "no such file" -------------------------------------------------------------------------

test("archive_probe and crypto_id call a device node a file that is not a regular one, not 'no such file'", async (t) => {
  if (process.platform === "win32") return t.skip("no device nodes");
  await withCwd(async (cwd) => {
    for (const script of [PROBE, ID]) {
      const out = await tool(script, cwd, { path: "/dev/null" });
      assert.equal(out.code, 1, out.stdout);
      const err = JSON.parse(out.stdout) as Json;
      assert.equal(err.status, "failed");
      assert.match(err.error, /not a regular file/);
      assert.doesNotMatch(err.error, /no such file/);
    }
    const missing = JSON.parse((await tool(PROBE, cwd, { path: "work/missing.zip" })).stdout) as Json;
    assert.match(missing.error, /no such file/);
  });
});

// --- P3-8 --------------------------------------------------------------------------------------------------------------

test("the LUKS skill does not say crypto_id prints none of the file's bytes while it prints header facts", async () => {
  const text = await readFile(join(ENC, "skills", "volumes", "luks-filevault.md"), "utf8");
  assert.doesNotMatch(text, /prints none of the file's bytes/);
  assert.match(text, /prints no raw bytes of the file/);
});

// --- P2-A: one document on every path --------------------------------------------------------------------------------------

/** Run a tool under RLIMIT_FSIZE, as a full disk or a quota answers a write: EFBIG, as ENOSPC would. */
function limited(script: string, cwd: string, args: unknown, env: Record<string, string>, bytes: number): Promise<Run> {
  const wrapper = "import sys, resource, runpy\nresource.setrlimit(resource.RLIMIT_FSIZE, (%d, %d))\nscript = sys.argv[1]\nsys.argv = [script]\nrunpy.run_path(script, run_name='__main__')\n".replace(/%d/g, String(bytes));
  return new Promise((resolve, reject) => {
    const child = spawn("python3", ["-c", wrapper, script], { cwd, env: { ...process.env, ...AGENT, ...env } });
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => out.push(c));
    child.stderr.on("data", (c: Buffer) => err.push(c));
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stdout: Buffer.concat(out).toString("utf8"), stderr: Buffer.concat(err).toString("utf8") }));
    child.stdin.end(JSON.stringify(args));
  });
}

test("recovery_key_scan prints exactly one JSON document when the page file cannot be written and the values file holds unflushed rows", async (t) => {
  if (process.platform === "win32") return t.skip("RLIMIT_FSIZE");
  await withCwd(async (cwd) => {
    // 3,000 recovery passwords (eight groups of six digits, each divisible by 11), built from the rule, not from the tool.
    let seed = 7;
    const next = () => (seed = (seed * 1103515245 + 12345) & 0x7fffffff);
    const lines: string[] = [];
    for (let i = 0; i < 3000; i++) lines.push(Array.from({ length: 8 }, () => String(11 * (next() % 60000)).padStart(6, "0")).join("-"));
    await writeFile(join(cwd, "work", "dense.txt"), lines.join("\n") + "\n");
    for (const bytes of [3000, 20000]) {
      const outDir = join(cwd, `out${bytes}`);
      const out = await limited(SCAN, cwd, { path: "work/dense.txt", write_values: true, limit: 5 }, { JOB_ID: "j1", OUT: outDir, SECRET_OUTPUT: "1" }, bytes);
      assert.equal(out.code, 1, out.stdout + out.stderr);
      assert.doesNotMatch(out.stderr, /Traceback/);
      const documents = out.stdout.split("\n").filter((l) => l.trim());
      assert.equal(documents.length, 1, `${bytes}: ${documents.length} documents on stdout`);
      const doc = JSON.parse(documents[0]) as Json;
      assert.equal(doc.status, "failed");
      assert.match(doc.error, /cannot be written/);
    }
  });
});

// --- Verification of the first fixes (PR #216): the same bugs through variants ------------------------------------------------

// The Zip64 end record with extensible data in a file whose stub's offsets were not adjusted, and a fake End record in the comment.
test("archive_probe: a Zip64 end record with extensible data behind an unadjusted stub is read, and a fake End record in its comment is named", async () => {
  await withCwd(async (cwd) => {
    const base = buildZip([{ name: "a.txt", flags: 1 }, { name: "b.txt" }], { zip64Extensible: 8 });
    const stub = Buffer.concat([Buffer.from("MZ"), Buffer.alloc(500, 0x90)]);
    await writeFile(join(cwd, "work", "raw.exe"), Buffer.concat([stub, base]));
    const honest = answer(await tool(PROBE, cwd, { path: "work/raw.exe" }));
    assert.equal(honest.entry_count, 2);
    assert.equal(honest.status, "complete");
    assert.equal(honest.protected, true);
    // The same record with a comment that holds an empty End record.
    const eocdAt = base.length - 22;
    const withComment = Buffer.from(base);
    withComment.writeUInt16LE(22, eocdAt + 20);
    await writeFile(join(cwd, "work", "fake.exe"), Buffer.concat([stub, withComment, Buffer.concat([Buffer.from("PK\x05\x06"), Buffer.alloc(18)])]));
    const fake = answer(await tool(PROBE, cwd, { path: "work/fake.exe" }));
    assert.notEqual(fake.protected, false);
    assert.notEqual(fake.status, "complete");
  });
});

// N2: a warning that 7-Zip prints is decided from every line of its output, not from the five that are kept for display.
test("archive_probe: a 7-Zip warning is seen after more than five diagnostics, and a record line that is no key = value makes the listing not the archive's", async () => {
  await withCwd(async (cwd, bin) => {
    await sevenArchive(cwd, "a.7z");
    const footer = "\n--\nPath = a.7z\nType = 7z\nPhysical Size = 100\n\n----------\nPath = plain.txt\nSize = 1\nEncrypted = -\n\n";
    const cases: Record<string, { body: string; listing: string }> = {
      // six errors, then the warnings footer: the first five fill the display list
      errors_then_warning: { body: `${footer}${Array.from({ length: 6 }, (_, i) => `ERROR: ${i}\n`).join("")}\nWarnings: 1\n`, listing: "listed_with_warnings" },
      // an archive property that says data follows the archive, and no footer line at all
      tail_size: { body: "\n--\nPath = a.7z\nType = 7z\nPhysical Size = 100\nTail Size = 64\n\n----------\nPath = plain.txt\nSize = 1\nEncrypted = -\n\n", listing: "listed_with_warnings" },
      // p7zip 16.02: a member name with line breaks is printed as it is
      forged_name: { body: `\n--\nPath = a.7z\nType = 7z\n\n----------\nPath = x\n${Array.from({ length: 6 }, (_, i) => `ERROR: ${i}\n`).join("")}Size = 4\nEncrypted = -\n\nWarnings: 1\n`, listing: "listing_not_one_archive" },
    };
    for (const [name, c] of Object.entries(cases)) {
      await writeFile(join(bin, "7z"), `#!/bin/sh\nprintf '${c.body}'\nexit 0\n`);
      await chmod(join(bin, "7z"), 0o755);
      const out = answer(await tool(PROBE, cwd, { path: "work/a.7z" }, {}, bin));
      assert.equal(out.listing.status, c.listing, name);
      assert.equal(out.status, "partial", name);
      assert.notEqual(out.protected, false, name);
      assert.doesNotMatch(out.status_basis, /without warnings/, name);
    }
  });
});

test("archive_probe lists a plain 7-Zip archive with an encrypted one appended as partial, protected not false (the installed 7-Zip)", { skip: REAL_7Z ? false : "no 7z on PATH" }, async (t) => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "plain.txt"), "p".repeat(50));
    await writeFile(join(cwd, "secret.txt"), "s".repeat(50));
    const sz = (args: string[]) => spawnSync(REAL_7Z!, args, { cwd, stdio: "ignore" });
    sz(["a", "-y", "plain.7z", "plain.txt"]);
    sz(["a", "-y", "-psecret1", "enc.7z", "secret.txt"]);
    const [a, b] = await Promise.all([readFile(join(cwd, "plain.7z")), readFile(join(cwd, "enc.7z"))]).catch(() => [null, null] as const);
    if (!a || !b) return t.skip("this 7z did not create the archives");
    await writeFile(join(cwd, "work", "both.7z"), Buffer.concat([a, b]));
    const out = answer(await tool(PROBE, cwd, { path: "work/both.7z" }));
    assert.notEqual(out.status, "complete");
    assert.notEqual(out.protected, false);
  });
});

// --- The 7-Zip listing: protected is false only of a whole listing -------------------------------------------------------------

test("archive_probe: a 7-Zip listing the clock cut never says protected: false", async () => {
  await withCwd(async (cwd, bin) => {
    await sevenArchive(cwd, "big.7z");
    const rows = Array.from({ length: 50 }, (_, i) => `Path = a${i}\\nSize = 1\\nEncrypted = -\\n\\n`).join("");
    await writeFile(join(bin, "7z"), `#!/bin/sh\nprintf '\\n--\\nPath = big.7z\\nType = 7z\\n\\n----------\\n${rows}'\nexec sleep 20\n`);
    await chmod(join(bin, "7z"), 0o755);
    const out = answer(await tool(PROBE, cwd, { path: "work/big.7z", max_seconds: 2 }, {}, bin));
    assert.equal(out.listing.status, "timed_out");
    assert.equal(out.status, "partial");
    assert.equal(out.protected, null);
    assert.ok(out.member_count > 0, "the members read before the stop are still listed");
  });
});

test("archive_probe: a truncated plain 7z called 'wrong password.7z' is not a header that 7-Zip says is encrypted", async () => {
  await withCwd(async (cwd, bin) => {
    // A start header that points past the end of the file: the archive is cut short.
    const start = Buffer.alloc(32);
    Buffer.from([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c, 0x00, 0x04]).copy(start, 0);
    start.writeBigUInt64LE(100n, 12);
    start.writeBigUInt64LE(50n, 20);
    start.writeUInt32LE(crc32(start.subarray(12, 32)), 8);
    for (const name of ["wrong password.7z", "Cannot open encrypted archive.7z"]) {
      await writeFile(join(cwd, "work", name), start);
      // 7-Zip echoes the path on its error line, as it does, and says what is wrong with the file.
      await writeFile(join(bin, "7z"), `#!/bin/sh\nlast=""\nfor a in "$@"; do last="$a"; done\nprintf '\\nListing archive: %s\\n\\nERROR: %s : Unexpected end of archive\\n\\nErrors: 1\\n' "$last" "$last"\nexit 2\n`);
      await chmod(join(bin, "7z"), 0o755);
      const out = answer(await tool(PROBE, cwd, { path: `work/${name}` }, {}, bin));
      assert.equal(out.status, "partial", name);
      assert.notEqual(out.header_encrypted, true, name);
      assert.notEqual(out.protected, true, name);
      assert.doesNotMatch(out.status_basis, /header is encrypted/, name);
    }
  });
});

// --- The third verification: the bytes of the file are accounted for, whatever the author puts in the directory or in the headers ------------

/** The environment in which no 7-Zip program is on the PATH of the tool (python's shutil.which is told so). */
async function withoutSeven(cwd: string): Promise<Record<string, string>> {
  await mkdir(join(cwd, "site"), { recursive: true });
  await writeFile(join(cwd, "site", "sitecustomize.py"), "import shutil\n_w = shutil.which\nshutil.which = lambda c, *a, **k: None if str(c) in ('7z','7zz','7za') else _w(c, *a, **k)\n");
  return { PYTHONPATH: join(cwd, "site") };
}

/** A local header and its data and nothing else (an archive made of local headers only), with the fields a filter on the values would reject. */
function localOnly(f: { version?: number; method?: number; name?: string; flags?: number }): Buffer {
  const name = Buffer.from(f.name ?? "s.txt", "utf8");
  const data = Buffer.from("SECRETSECRET");
  const h = Buffer.alloc(30);
  h.writeUInt32LE(0x04034b50, 0);
  h.writeUInt16LE(f.version ?? 20, 4);
  h.writeUInt16LE(f.flags ?? 1, 6);
  h.writeUInt16LE(f.method ?? 0, 8);
  h.writeUInt16LE(DOS_TIME, 10);
  h.writeUInt16LE(DOS_DATE, 12);
  h.writeUInt32LE(data.length, 18);
  h.writeUInt32LE(data.length, 22);
  h.writeUInt16LE(name.length, 26);
  return Buffer.concat([h, name, data]);
}

test("archive_probe: an archive in front made of local headers with a field no filter on values would accept is found, with and without 7-Zip", async () => {
  await withCwd(async (cwd) => {
    const hidden = await withoutSeven(cwd);
    const odd: Record<string, Buffer> = {
      version101: localOnly({ version: 101 }), version255: localOnly({ version: 255 }), method11: localOnly({ method: 11 }), method13: localOnly({ method: 13 }),
      method1000: localOnly({ method: 1000 }), methodFFFF: localOnly({ method: 0xffff }), nameLength0: localOnly({ name: "" }), plain20: localOnly({}),
    };
    const prefixes: Record<string, Buffer> = { none: Buffer.alloc(0), mz: MZ_STUB, elf: Buffer.concat([Buffer.from("\x7fELF"), Buffer.alloc(3000, 0x07)]) };
    let cases = 0;
    for (const [fn, front] of Object.entries(odd)) {
      for (const [pn, prefix] of Object.entries(prefixes)) {
        for (const [bn, back] of [["small", buildZip(plain(1))], ["big", buildZip(plain(3000))]] as const) {
          await writeFile(join(cwd, "work", "x.bin"), Buffer.concat([prefix, front, back]));
          for (const [label, env] of [["7-Zip as installed", {}], ["no 7-Zip", hidden]] as const) {
            const out = answer(await tool(PROBE, cwd, { path: "work/x.bin" }, env));
            cases++;
            assert.notEqual(out.status, "complete", `${fn} ${pn} ${bn} ${label}`);
            assert.notEqual(out.protected, false, `${fn} ${pn} ${bn} ${label}`);
          }
        }
      }
    }
    assert.equal(cases, 96);
  });
});

test("archive_probe: one more directory entry that names the first member of an archive in front does not hide that archive", async () => {
  await withCwd(async (cwd) => {
    const hidden = await withoutSeven(cwd);
    const front = buildZip([{ name: "readme.txt" }, { name: "s0.txt", flags: 1 }, { name: "s1.txt", flags: 1 }]);
    // The second archive counts its offsets from the start of the file, and its directory names the first member of the first archive as well.
    const back = buildZip(plain(3), { base: front.length, extraEntries: [{ name: "readme.txt", offset: 0, size: 1 }] });
    await writeFile(join(cwd, "work", "dummy.zip"), Buffer.concat([front, back]));
    for (const env of [{}, hidden]) {
      const out = answer(await tool(PROBE, cwd, { path: "work/dummy.zip" }, env));
      assert.notEqual(out.status, "complete");
      assert.notEqual(out.protected, false);
      assert.ok(out.archive_in_gap || out.archive_in_front, "A's other members, its directory or its End record are named");
    }
  });
});

test("archive_probe: an archive between two members, or between the last member and the directory, is found; a block that holds no archive there is not", async () => {
  await withCwd(async (cwd) => {
    const hidden = await withoutSeven(cwd);
    const secret = buildZip([{ name: "s0.txt", flags: 1 }, { name: "s1.txt", flags: 1 }]);
    const apkBlock = Buffer.concat([Buffer.alloc(8), Buffer.from(Array.from({ length: 300 }, (_, i) => (i * 131 + 7) & 0xff)), Buffer.alloc(8), Buffer.from("APK Sig Block 42")]);
    const layouts: Record<string, [Buffer, boolean]> = {
      "an archive between two members": [buildZip([{ name: "m0.txt", gapAfter: secret }, { name: "m1.txt" }]), true],
      "an archive before the directory": [buildZip([{ name: "m0.txt" }, { name: "m1.txt" }], { gapBeforeDirectory: secret }), true],
      "an APK signing block before the directory": [buildZip([{ name: "m0.txt" }, { name: "m1.txt" }], { gapBeforeDirectory: apkBlock }), false],
      "zero padding between members": [buildZip([{ name: "m0.txt", gapAfter: Buffer.alloc(4096) }, { name: "m1.txt" }]), false],
      "members with data descriptors": [buildZip([{ name: "m0.txt", dd: true }, { name: "m1.txt", dd: true }, { name: "m2.txt" }]), false],
    };
    for (const [label, [zip, found]] of Object.entries(layouts)) {
      await writeFile(join(cwd, "work", "g.zip"), zip);
      for (const env of [{}, hidden]) {
        const out = answer(await tool(PROBE, cwd, { path: "work/g.zip" }, env));
        if (found) {
          assert.notEqual(out.status, "complete", label);
          assert.notEqual(out.protected, false, label);
          assert.ok(out.archive_in_gap, label);
        } else {
          assert.equal(out.status, "complete", `${label}: ${out.status_basis}`);
          assert.equal(out.protected, false, label);
        }
      }
    }
  });
});

test("archive_probe says whether a second reader compared the list, and answers differently when it did not", async () => {
  await withCwd(async (cwd, bin) => {
    const hidden = await withoutSeven(cwd);
    await writeFile(join(cwd, "work", "one.zip"), buildZip([{ name: "a.txt" }]));
    const none = answer(await tool(PROBE, cwd, { path: "work/one.zip" }, hidden));
    assert.equal(none.status, "complete");
    assert.equal(none.cross_check.result, "not_installed");
    assert.match(none.status_basis, /7-Zip is not installed, so no second reader compared the list/);
    const listing = (members: number, encrypted: number) => {
      const rows = Array.from({ length: members }, (_, i) => `Path = m${i}\\nSize = 1\\nEncrypted = ${i < encrypted ? "+" : "-"}\\n\\n`).join("");
      return `\\n--\\nPath = one.zip\\nType = zip\\n\\n----------\\n${rows}`;
    };
    await writeFile(join(bin, "7z"), `#!/bin/sh\nprintf '${listing(1, 0)}'\nexit 0\n`);
    await chmod(join(bin, "7z"), 0o755);
    const agrees = answer(await tool(PROBE, cwd, { path: "work/one.zip" }, {}, bin));
    assert.equal(agrees.status, "complete");
    assert.equal(agrees.cross_check.result, "agrees");
    assert.match(agrees.status_basis, /second reader, lists the same members/);
    // 7-Zip exits with 2 on a header error and still prints a listing: it is compared, not set aside as "could not open".
    await writeFile(join(bin, "7z"), `#!/bin/sh\nprintf '${listing(2, 1)}'\nexit 2\n`);
    const differs = answer(await tool(PROBE, cwd, { path: "work/one.zip" }, {}, bin));
    assert.equal(differs.status, "partial");
    assert.notEqual(differs.protected, false);
    assert.equal(differs.cross_check.result, "differs");
  });
});

test("archive_probe: a 7z with an encrypted header followed by a clean ZIP is not the listing of the ZIP", async () => {
  await withCwd(async (cwd, bin) => {
    // A start header that points at an encoded header whose coder list names AES, then the ZIP.
    const header = Buffer.concat([Buffer.from([0x17, 0x06, 0xf1, 0x07, 0x01]), Buffer.alloc(15, 0x11)]);
    const start = Buffer.alloc(32);
    Buffer.from([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c, 0x00, 0x04]).copy(start, 0);
    start.writeBigUInt64LE(0n, 12);
    start.writeBigUInt64LE(BigInt(header.length), 20);
    start.writeUInt32LE(crc32(header), 28);
    start.writeUInt32LE(crc32(start.subarray(12, 32)), 8);
    const zip = buildZip([{ name: "z.txt" }]);
    await writeFile(join(cwd, "work", "eh.7z"), Buffer.concat([start, header, zip]));
    // 7-Zip cannot open the 7z without a password, falls over to the ZIP at the end of the file, and lists that without a warning.
    await writeFile(join(bin, "7z"), `#!/bin/sh\nprintf '\\n--\\nPath = eh.7z\\nType = zip\\nPhysical Size = ${zip.length}\\n\\n----------\\nPath = z.txt\\nSize = 1\\nEncrypted = -\\n\\n'\nexit 0\n`);
    await chmod(join(bin, "7z"), 0o755);
    const out = answer(await tool(PROBE, cwd, { path: "work/eh.7z" }, {}, bin));
    assert.equal(out.status, "partial");
    assert.equal(out.protected, true, "the start header shows an encrypted header");
    assert.equal(out.listing.status, "not_the_whole_7z");
    assert.notEqual(out.member_count, 1, "the ZIP's member is not listed as the 7z's");
    // A damaged start header gives the same: the format 7-Zip read is not the one the tool took the file for.
    const damaged = Buffer.from(start);
    damaged.writeUInt32LE(0, 8);
    await writeFile(join(cwd, "work", "bad.7z"), Buffer.concat([damaged, header, zip]));
    const bad = answer(await tool(PROBE, cwd, { path: "work/bad.7z" }, {}, bin));
    assert.equal(bad.status, "partial");
    assert.notEqual(bad.protected, false);
  });
});
