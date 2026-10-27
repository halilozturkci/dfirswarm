/**
 * encrypted-containers: the findings of the second independent review (R2) of archive_probe, crypto_id and recovery_key_scan, one test each.
 * Every test here fails on the tools as they were. Fixtures are built from the APPNOTE's record layouts, never from a tool's own output.
 */
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { chmod, mkdir, readFile, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
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

type Member = { name: string; flags?: number; localFlags?: number; data?: Buffer };

/** A ZIP from the APPNOTE's record layouts. `localFlags` is the local header's flags where they are not the directory's. */
function buildZip(members: Member[], opts: { disk?: number; cdDisk?: number; dropLocal?: boolean; zip64Extensible?: number } = {}): Buffer {
  const parts: Buffer[] = [];
  const central: Buffer[] = [];
  let at = 0;
  for (const m of members) {
    const name = Buffer.from(m.name, "utf8");
    const data = m.data ?? Buffer.from("x");
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(m.localFlags ?? m.flags ?? 0, 6);
    local.writeUInt32LE(data.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(name.length, 26);
    const record = opts.dropLocal ? Buffer.alloc(30 + name.length + data.length) : Buffer.concat([local, name, data]);
    const c = Buffer.alloc(46);
    c.writeUInt32LE(0x02014b50, 0);
    c.writeUInt16LE(20, 4);
    c.writeUInt16LE(20, 6);
    c.writeUInt16LE(m.flags ?? 0, 8);
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
  const cd = Buffer.concat(central);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(opts.disk ?? 0, 4);
  eocd.writeUInt16LE(opts.cdDisk ?? 0, 6);
  eocd.writeUInt16LE(members.length, 8);
  eocd.writeUInt16LE(members.length, 10);
  eocd.writeUInt32LE(cd.length, 12);
  eocd.writeUInt32LE(at, 16);
  if (opts.zip64Extensible === undefined) return Buffer.concat([...parts, cd, eocd]);
  // A Zip64 end record with extensible data (its size field above 44), a locator, and an End record that points to both.
  const rec = Buffer.alloc(56 + opts.zip64Extensible);
  rec.write("PK\x06\x06", 0, "latin1");
  rec.writeBigUInt64LE(BigInt(44 + opts.zip64Extensible), 4);
  rec.writeUInt16LE(45, 12);
  rec.writeUInt16LE(45, 14);
  rec.writeBigUInt64LE(BigInt(members.length), 24);
  rec.writeBigUInt64LE(BigInt(members.length), 32);
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
  const start = Buffer.alloc(32);
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

// --- P1-C: an archive in front of the one read, beyond the last 64 KiB ----------------------------------------------------

test("archive_probe: a second archive appended, larger than the last 64 KiB, is not 'complete' with 'protected: false'", async () => {
  await withCwd(async (cwd) => {
    const first = buildZip([{ name: "a.txt", flags: 1 }, { name: "b.txt", flags: 1 }, { name: "c.txt" }]);
    const second = buildZip(plain(3000));
    assert.ok(second.length > 200_000, "the second archive's directory is above 64 KiB");
    await writeFile(join(cwd, "work", "two.zip"), Buffer.concat([first, second]));
    const out = answer(await tool(PROBE, cwd, { path: "work/two.zip" }));
    assert.equal(out.status, "partial");
    assert.notEqual(out.protected, false);
    assert.equal(out.archive_in_front.offset, 0);
    assert.equal(out.archive_in_front.chosen_archive_begins, first.length);
    assert.match(out.status_basis, /another archive lies in front/);
  });
});

test("archive_probe: a self-extracting stub or a plain archive in front of nothing stays complete", async () => {
  await withCwd(async (cwd) => {
    const zip = buildZip(plain(20));
    // The offsets in a self-extracting archive count from the start of the file in some tools and from the start of the archive in others:
    // here they count from the archive, as the tool allows for.
    await writeFile(join(cwd, "work", "sfx.zip"), Buffer.concat([Buffer.from("MZ"), Buffer.alloc(998, 0x90), zip]));
    await writeFile(join(cwd, "work", "one.zip"), zip);
    for (const f of ["sfx.zip", "one.zip"]) {
      const out = answer(await tool(PROBE, cwd, { path: `work/${f}` }));
      assert.equal(out.status, "complete", f);
      assert.equal(out.protected, false, f);
      assert.equal(out.archive_in_front, undefined);
    }
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

// N1: the first archive does not start with a ZIP signature (a stub, junk, a spanning marker), and the second one has a big directory.
test("archive_probe: an archive in front that does not start with a ZIP signature is found from its End record, beyond the last 64 KiB", async () => {
  await withCwd(async (cwd) => {
    const first = buildZip([{ name: "a.txt", flags: 1 }, { name: "b.txt", flags: 1 }, { name: "c.txt" }]);
    const second = buildZip(plain(3000));
    assert.ok(second.length > 200_000);
    const front: Record<string, Buffer> = {
      mz_stub: Buffer.concat([Buffer.from("MZ"), Buffer.alloc(2000, 0x90)]),
      junk: Buffer.from(Array.from({ length: 50 }, (_, i) => (i * 37 + 11) & 0xff)),
      spanning_marker: Buffer.from("PK\x07\x08", "latin1"),
    };
    for (const [name, prefix] of Object.entries(front)) {
      await writeFile(join(cwd, "work", `${name}.bin`), Buffer.concat([prefix, first, second]));
      const out = answer(await tool(PROBE, cwd, { path: `work/${name}.bin` }));
      assert.equal(out.status, "partial", name);
      assert.notEqual(out.protected, false, name);
      assert.equal(out.archive_in_front.found_by, "an End record before the archive read", name);
      assert.equal(out.archive_in_front.chosen_archive_begins, prefix.length + first.length, name);
      assert.equal(out.archive_in_front.offset, prefix.length, name);
      assert.match(out.status_basis, /another archive lies at byte|End record of another archive/, name);
    }
  });
});

test("archive_probe: self-extracting stubs, executables and polyglots in front of one archive stay complete", async () => {
  await withCwd(async (cwd) => {
    const zip = buildZip(plain(3000));
    const enc = buildZip([{ name: "a.txt", flags: 1 }, { name: "b.txt" }]);
    // An unzip stub holds the record signatures as constants, and nothing that follows them is a directory.
    const unzipStub = Buffer.concat([Buffer.from("MZ"), Buffer.alloc(300, 0x90), Buffer.from("PK\x05\x06"), Buffer.from("PK\x03\x04PK\x01\x02PK\x06\x06PK\x06\x07"), Buffer.alloc(5000, 0x41), Buffer.from("PK\x05\x06\x00\x00\x00\x00\x03\x00\x03\x00"), Buffer.alloc(2000, 0x42)]);
    const stubs: Record<string, Buffer> = {
      unzip_stub: unzipStub,
      elf: Buffer.concat([Buffer.from("\x7fELF"), Buffer.alloc(4000, 0x07)]),
      shell: Buffer.from("#!/bin/sh\nexec java -jar \"$0\" \"$@\"\n"),
      png_polyglot: Buffer.concat([Buffer.from("\x89PNG\r\n\x1a\n"), Buffer.alloc(100_000, 0x5a)]),
    };
    for (const [name, stub] of Object.entries(stubs)) {
      for (const [label, archive, protectedWant] of [["plain", zip, false], ["encrypted", enc, true]] as const) {
        await writeFile(join(cwd, "work", `${name}-${label}.bin`), Buffer.concat([stub, archive]));
        const out = answer(await tool(PROBE, cwd, { path: `work/${name}-${label}.bin` }));
        assert.equal(out.status, "complete", `${name} ${label}: ${out.status_basis}`);
        assert.equal(out.protected, protectedWant, `${name} ${label}`);
        assert.equal(out.archive_in_front, undefined);
        assert.equal(out.front_unsearched, undefined);
      }
    }
  });
});

test("archive_probe: bytes in front of the archive that hold too many End record signatures to check are named as not searched, and the answer is partial", async () => {
  await withCwd(async (cwd) => {
    const stub = Buffer.concat([Buffer.from("MZ"), ...Array.from({ length: 2500 }, () => Buffer.from("PK\x05\x06xxxxxxxxxxxxxxxxxx"))]);
    await writeFile(join(cwd, "work", "many.bin"), Buffer.concat([stub, buildZip(plain(10))]));
    const out = answer(await tool(PROBE, cwd, { path: "work/many.bin" }));
    assert.equal(out.status, "partial");
    assert.notEqual(out.protected, false);
    assert.match(out.front_unsearched.why, /more than 2000 End record signatures/);
  });
});

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
