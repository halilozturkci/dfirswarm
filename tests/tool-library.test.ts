/**
 * Library wrappers must not eval caller JSON into the shell. These three
 * used to `eval "$(python3 -c … print(f"OUTPUT={d[\"output\"]}") …)"`, so
 * `output` of `x$(touch pwned)` or a pattern of `'; os.system("id"); '` ran
 * as code. They now json.load and pass values on argv / to re.search.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmod, mkdir, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { failingStub, LIB, runPy, runPySnippet, runSh, withCwd } from "./tool-library-harness.ts";

type LibraryManifest = {
  name: string;
  runtime: string;
  entry: string;
  by: string;
  version: number;
  description: string;
  sha256: string;
};

async function libraryManifests(): Promise<LibraryManifest[]> {
  const dirs = await readdir(LIB, { withFileTypes: true });
  const out: LibraryManifest[] = [];
  for (const d of dirs) {
    if (!d.isDirectory()) continue;
    const raw = await readFile(join(LIB, d.name, "manifest.json"), "utf8").catch(() => null);
    if (raw) out.push(JSON.parse(raw) as LibraryManifest);
  }
  return out.sort((a, b) => a.name.localeCompare(b.name));
}

test("every library manifest hashes the script sitting next to it", async () => {
  // The harness refuses a tool whose bytes do not match its manifest, so a
  // script edited without rehashing is a tool that cannot be called at all.
  // Nothing else in the repo checks this, and the drift is invisible until
  // a run needs the tool.
  const manifests = await libraryManifests();
  assert.ok(manifests.length >= 30, `expected a populated library, got ${manifests.length}`);
  for (const m of manifests) {
    const bytes = await readFile(join(LIB, m.name, m.entry));
    assert.equal(
      createHash("sha256").update(bytes).digest("hex"),
      m.sha256,
      `${m.name}/${m.entry} does not hash to its manifest sha256`,
    );
  }
});

test("the library README lists what the manifests say", async () => {
  const manifests = await libraryManifests();
  const readme = await readFile(join(LIB, "README.md"), "utf8");
  const rows = readme
    .split("\n")
    .filter((line) => /^\| `[a-z0-9_]+` \|/.test(line))
    .map((line) => line.slice(2, -2).split(" | "));
  assert.deepEqual(
    rows.map((r) => r[0]),
    manifests.map((m) => `\`${m.name}\``),
    "the table must list every tool, in name order",
  );
  for (const [i, m] of manifests.entries()) {
    const [, runtime, by, version, what] = rows[i];
    assert.equal(runtime, m.runtime, `${m.name}: runtime`);
    assert.equal(by, `\`${m.by}\``, `${m.name}: author`);
    assert.equal(version, String(m.version), `${m.name}: version`);
    const one = m.description.split(/\s+/).join(" ");
    assert.equal(what, one.length <= 109 ? one : `${one.slice(0, 109)}\u2026`, `${m.name}: description`);
  }
});

test("library scripts do not contain eval", async () => {
  const names = ["icat_extract", "grep_filelist", "icat_root", "fls_root", "check_inputs", "volrun"];
  for (const name of names) {
    const py = await readFile(join(LIB, name, "run.py"), "utf8");
    assert.doesNotMatch(py, /\beval\s*\(/);
    const sh = join(LIB, name, "run.sh");
    await assert.rejects(readFile(sh), /ENOENT/, `${name}/run.sh must be gone`);
  }
});

test("icat_extract treats output as a path, not a shell command", async () => {
  await withCwd(async (cwd, bin) => {
    const out = await runPy(join(LIB, "icat_extract", "run.py"), cwd, {
      inode: 12,
      output: "work/x$(touch pwned).bin",
    }, bin);
    assert.equal(out.code, 0, out.stderr);
    const pwned = await readFile(join(cwd, "pwned")).catch(() => null);
    assert.equal(pwned, null, "command substitution in output must not run");
    const body = JSON.parse(out.stdout) as { path: string; size: number };
    assert.equal(body.path, "work/x$(touch pwned).bin");
    assert.equal(body.size, Buffer.byteLength("extracted-bytes"));
    const args = await readFile(join(cwd, "icat-args.txt"), "utf8");
    assert.match(args, /^-o\n0\ninputs\/AF-Case2\.E01\n12\n/);
    const saved = await readFile(join(cwd, "work", "x$(touch pwned).bin"), "utf8");
    assert.equal(saved, "extracted-bytes");
  });
});

test("icat_root treats inode and output as argv, not eval", async () => {
  await withCwd(async (cwd, bin) => {
    const out = await runPy(join(LIB, "icat_root", "run.py"), cwd, {
      inode: "7; touch pwned",
      output: "work/out.txt; touch pwned",
    }, bin);
    assert.equal(out.code, 0, out.stderr);
    const pwned = await readFile(join(cwd, "pwned")).catch(() => null);
    assert.equal(pwned, null);
    const args = await readFile(join(cwd, "icat-args.txt"), "utf8");
    assert.match(args, /^-o\n503808\ninputs\/Webserver\.E01\n7; touch pwned\n/);
    const saved = await readFile(join(cwd, "work", "out.txt; touch pwned"), "utf8");
    assert.equal(saved, "extracted-bytes");
  });
});

test("grep_filelist does not exec a pattern as Python", async () => {
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "catalog", "AF-Case2.E01", "p0"), { recursive: true });
    await writeFile(join(cwd, "catalog", "AF-Case2.E01", "p0", "filelist.txt"), "safe.txt\n", "utf8");
    const out = await runPy(join(LIB, "grep_filelist", "run.py"), cwd, {
      pattern: "'; os.system(\"touch pwned\"); '",
    });
    assert.equal(out.code, 0, out.stderr);
    const pwned = await readFile(join(cwd, "pwned")).catch(() => null);
    assert.equal(pwned, null, "os.system in the pattern must not run");
    const hits = JSON.parse(out.stdout) as string[];
    assert.deepEqual(hits, []);
  });
});

test("icat_extract fails closed when the image is missing", async () => {
  await withCwd(async (cwd, bin) => {
    const out = await runPy(join(LIB, "icat_extract", "run.py"), cwd, {
      inode: 12,
      output: "work/empty.bin",
      image: "inputs/no-such.E01",
    }, bin);
    assert.notEqual(out.code, 0);
    const body = JSON.parse(out.stdout) as { error: string };
    assert.match(body.error, /not found/);
    const planted = await readFile(join(cwd, "work", "empty.bin")).catch(() => null);
    assert.equal(planted, null, "must not write a 0-byte extract for a missing image");
  });
});

test("fls_root reads JSON stdin and fails if the image is missing", async () => {
  await withCwd(async (cwd, bin) => {
    const out = await runPy(join(LIB, "fls_root", "run.py"), cwd, {
      inode: 99,
      image: "inputs/no-such.E01",
    }, bin);
    assert.notEqual(out.code, 0);
    assert.match(out.stdout, /not found/);

    await writeFile(
      join(bin, "fls"),
      `#!/bin/sh
printf '%s\\n' "$@" > "${cwd}/fls-args.txt"
printf 'd/d 2: .\\n'
`,
      "utf8",
    );
    await chmod(join(bin, "fls"), 0o755);
    const listed = await runPy(join(LIB, "fls_root", "run.py"), cwd, {
      inode: 1831425,
      recursive: true,
      image: "inputs/Webserver.E01",
      offset: 503808,
    }, bin);
    assert.equal(listed.code, 0, listed.stderr);
    const args = await readFile(join(cwd, "fls-args.txt"), "utf8");
    assert.match(args, /^-o\n503808\n-r\ninputs\/Webserver\.E01\n1831425\n/);
    assert.match(listed.stdout, /d\/d 2/);
  });
});

test("csearch fails when catalog files are absent instead of printing (no matches)", async () => {
  await withCwd(async (cwd) => {
    const out = await runPy(join(LIB, "csearch", "run.py"), cwd, {
      patterns: ["passwd"],
      files: ["filelist"],
    });
    assert.notEqual(out.code, 0);
    assert.doesNotMatch(out.stdout, /\(no matches\)/);
    const body = JSON.parse(out.stdout) as { error: string };
    assert.match(body.error, /not found/);

    await mkdir(join(cwd, "catalog", "case", "p0"), { recursive: true });
    await writeFile(join(cwd, "catalog", "case", "p0", "filelist.txt"), "etc/passwd\n", "utf8");
    const hit = await runPy(join(LIB, "csearch", "run.py"), cwd, {
      patterns: ["passwd"],
      files: ["filelist"],
      catalog_root: "catalog/case/p0",
    });
    assert.equal(hit.code, 0, hit.stderr);
    assert.match(hit.stdout, /\[filelist\] etc\/passwd/);
  });
});

test("chunk_needles fails closed when the E01 is missing", async () => {
  await withCwd(async (cwd, bin) => {
    const out = await runPy(join(LIB, "chunk_needles", "run.py"), cwd, {
      needles: "foo",
      inode: 12,
    }, bin);
    assert.notEqual(out.code, 0);
    const body = JSON.parse(out.stdout) as { error: string };
    assert.match(body.error, /not found/);
  });
});

test("check_inputs diffs inputs.json instead of always reporting OK", async () => {
  await withCwd(async (cwd) => {
    const missingMan = await runPy(join(LIB, "check_inputs", "run.py"), cwd, {});
    assert.notEqual(missingMan.code, 0);
    assert.match(missingMan.stdout, /inputs\.json not found/);

    await writeFile(
      join(cwd, "inputs.json"),
      JSON.stringify({
        source: "/tmp/src",
        files: [{ path: "inputs/AF-Case2.E01", bytes: 4, sha256: "deadbeef" }],
        bytes: 4,
      }),
      "utf8",
    );
    const mismatch = await runPy(join(LIB, "check_inputs", "run.py"), cwd, {});
    assert.notEqual(mismatch.code, 0);
    const bad = JSON.parse(mismatch.stdout) as { status: string; modified: string[] };
    assert.equal(bad.status, "FAIL");
    assert.ok(bad.modified.includes("inputs/AF-Case2.E01"));

    const { createHash } = await import("node:crypto");
    await rm(join(cwd, "inputs", "Webserver.E01"), { force: true });
    const bytes = await readFile(join(cwd, "inputs", "AF-Case2.E01"));
    const sha = createHash("sha256").update(bytes).digest("hex");
    await writeFile(
      join(cwd, "inputs.json"),
      JSON.stringify({
        source: "/tmp/src",
        files: [{ path: "inputs/AF-Case2.E01", bytes: bytes.length, sha256: sha }],
        bytes: bytes.length,
      }),
      "utf8",
    );
    const ok = await runPy(join(LIB, "check_inputs", "run.py"), cwd, {});
    assert.equal(ok.code, 0, ok.stderr);
    assert.equal((JSON.parse(ok.stdout) as { status: string }).status, "OK");
  });
});

test("volrun declares params and passes args as argv, not a shell string", async () => {
  const man = JSON.parse(await readFile(join(LIB, "volrun", "manifest.json"), "utf8")) as {
    params: Record<string, unknown>;
  };
  assert.ok(man.params.image);
  assert.ok(man.params.plugin);
  await withCwd(async (cwd, bin) => {
    await writeFile(join(cwd, "inputs", "mem.dmp"), "dmp\n", "utf8");
    await writeFile(
      join(bin, "vol"),
      `#!/bin/sh
python3 -c 'import json,sys; json.dump(sys.argv[1:], open("vol-args.json","w"))' "$@"
`,
      "utf8",
    );
    await chmod(join(bin, "vol"), 0o755);
    const out = await runPy(join(LIB, "volrun", "run.py"), cwd, {
      image: "inputs/mem.dmp",
      plugin: "windows.pslist",
      args: ["--pid", "356; id"],
    }, bin);
    assert.equal(out.code, 0, out.stderr);
    const argv = JSON.parse(await readFile(join(cwd, "vol-args.json"), "utf8")) as string[];
    assert.deepEqual(argv, ["-f", "inputs/mem.dmp", "windows.pslist", "--pid", "356; id"]);
  });
});

function fakeAesBlob(): Buffer {
  // AES v2 header, no extensions, zeros for iv/enc/macs — HMAC will fail.
  return Buffer.concat([
    Buffer.from("AES"),
    Buffer.from([2, 0, 0, 0]),
    Buffer.alloc(16),
    Buffer.alloc(48),
    Buffer.alloc(32),
    Buffer.alloc(16),
    Buffer.from([16]),
    Buffer.alloc(32),
  ]);
}

test("aescrypt_v2_decrypt requires a password and does not write before HMAC", async () => {
  await withCwd(async (cwd) => {
    const src = join(cwd, "inputs", "secret.aes");
    await writeFile(src, fakeAesBlob());
    const noPw = await runPy(join(LIB, "aescrypt_v2_decrypt", "run.py"), cwd, { path: "inputs/secret.aes" });
    assert.notEqual(noPw.code, 0);
    assert.match(noPw.stdout, /password is required/);
    const nextToSource = await readFile(join(cwd, "inputs", "secret.aes.dec")).catch(() => null);
    assert.equal(nextToSource, null);

    const hmac = await runPy(
      join(LIB, "aescrypt_v2_decrypt", "run.py"),
      cwd,
      { path: "inputs/secret.aes", password: "wrong", output: "work/garbage.dec" },
      undefined,
      { AGENT_ID: "agent07" },
    );
    assert.notEqual(hmac.code, 0);
    assert.match(hmac.stdout, /HMAC failed/);
    const garbage = await readFile(join(cwd, "work", "garbage.dec")).catch(() => null);
    assert.equal(garbage, null, "HMAC failure must not leave plaintext-shaped bytes");
    const defaultNextTo = await readFile(join(cwd, "inputs", "secret.aes.dec")).catch(() => null);
    assert.equal(defaultNextTo, null);

    const underInputs = await runPy(join(LIB, "aescrypt_v2_decrypt", "run.py"), cwd, {
      path: "inputs/secret.aes",
      password: "wrong",
      output: "inputs/secret.aes.dec",
    });
    assert.notEqual(underInputs.code, 0);
    assert.match(underInputs.stdout, /inputs/);
    const leaked = await readFile(join(cwd, "inputs", "secret.aes.dec")).catch(() => null);
    assert.equal(leaked, null);
  });
});

/**
 * A BitLocker volume laid out the way libbde documents it, not the way the
 * parser happens to read it: a 64-byte FVE block header, a 48-byte metadata
 * header whose size field is repeated 12 bytes in, then variable-size
 * entries. A fixture written from the implementation would agree with
 * whatever offsets the implementation picked, so it would prove nothing.
 */
function fakeBitlockerVolume(): Buffer {
  const BLOCK_HEADER = 64;
  const METADATA_HEADER = 48;
  const VMK_ENTRY = 40;
  const buf = Buffer.alloc(0x20000, 0);
  buf.write("-FVE-FS-", 3, "ascii");
  // Volume header: three uint64 byte offsets to the metadata blocks.
  buf.writeBigUInt64LE(0x10000n, 0xa0);
  buf.writeBigUInt64LE(0x18000n, 0xa8);
  buf.writeBigUInt64LE(0x1c000n, 0xb0);
  // The old tool took its GUID and its encryption method from the sector
  // after the boot record. Both are decoys, and neither may be reported.
  buf.write("AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE", 512, "ascii");
  buf.writeUInt16LE(0x8000, 512 + 0x28);
  const guid = Buffer.from("a1b2c3d4e5f60718293a4b5c6d7e8f90", "hex");
  const keyGuid = Buffer.from("0f1e2d3c4b5a69788796a5b4c3d2e1f0", "hex");
  const writeMeta = (off: number) => {
    // FVE metadata block header.
    buf.write("-FVE-FS-", off, "ascii");
    buf.writeUInt16LE(BLOCK_HEADER, off + 8); // the block header's own size
    buf.writeUInt16LE(2, off + 10); // version
    buf.writeBigUInt64LE(0x20000n, off + 16); // encrypted volume size
    buf.writeUInt32LE(1, off + 28); // volume header sectors
    buf.writeBigUInt64LE(0x10000n, off + 32);
    buf.writeBigUInt64LE(0x18000n, off + 40);
    buf.writeBigUInt64LE(0x1c000n, off + 48);
    buf.writeBigUInt64LE(0n, off + 56); // volume header offset
    // FVE metadata header.
    const meta = off + BLOCK_HEADER;
    const metaSize = METADATA_HEADER + VMK_ENTRY;
    buf.writeUInt32LE(metaSize, meta); // the metadata, its entries included
    buf.writeUInt32LE(1, meta + 4); // version
    buf.writeUInt32LE(METADATA_HEADER, meta + 8);
    buf.writeUInt32LE(metaSize, meta + 12); // the copy the parser checks against
    guid.copy(buf, meta + 16);
    buf.writeUInt32LE(3, meta + 32); // next nonce counter
    buf.writeUInt32LE(0x8004, meta + 36); // AES-XTS 128
    buf.writeBigUInt64LE(0n, meta + 40); // creation time
    // One VMK entry, protected by a recovery password.
    const e = meta + METADATA_HEADER;
    buf.writeUInt16LE(VMK_ENTRY, e);
    buf.writeUInt16LE(2, e + 2); // entry type: volume master key
    buf.writeUInt16LE(2, e + 4); // value type
    buf.writeUInt16LE(1, e + 6); // version
    keyGuid.copy(buf, e + 8);
    buf.writeBigUInt64LE(0n, e + 24); // last modification time
    buf.writeUInt16LE(0x0800, e + 34); // protection type: recovery password
  };
  writeMeta(0x10000);
  writeMeta(0x18000);
  writeMeta(0x1c000);
  return buf;
}

test("fve_metadata reads header offsets, not the three sectors after the boot record", async () => {
  await withCwd(async (cwd) => {
    const img = join(cwd, "inputs", "bitlocker.raw");
    await writeFile(img, fakeBitlockerVolume());
    const out = await runPy(join(LIB, "fve_metadata", "run.py"), cwd, { path: "inputs/bitlocker.raw" });
    assert.equal(out.code, 0, out.stderr + out.stdout);
    const body = JSON.parse(out.stdout) as {
      volume_guid: string;
      encryption_method: string;
      key_protectors: string[];
      recovery_password_protector: boolean;
      metadata_blocks: unknown[];
    };
    assert.doesNotMatch(out.stdout, /\nFVE metadata block/);
    assert.equal(body.volume_guid, "d4c3b2a1-f6e5-1807-293a-4b5c6d7e8f90");
    assert.notEqual(body.volume_guid, "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE");
    assert.equal(body.encryption_method, "AES-XTS 128");
    assert.deepEqual(body.key_protectors, ["recovery password"]);
    assert.equal(body.recovery_password_protector, true);
    assert.equal(body.metadata_blocks.length, 3);

    const missing = await runPy(join(LIB, "fve_metadata", "run.py"), cwd, { path: "inputs/nope.raw" });
    assert.notEqual(missing.code, 0);
    assert.match(JSON.parse(missing.stdout).error, /not found/);
  });
});

test("fve_metadata refuses a metadata size that disagrees with its own copy", async () => {
  await withCwd(async (cwd) => {
    // The metadata header repeats its size 12 bytes in. Disagreement means
    // the read landed somewhere that is not a metadata header, and a
    // forensic answer from there would be plausible and wrong.
    const buf = fakeBitlockerVolume();
    buf.writeUInt32LE(0x4000, 0x10000 + 64 + 12);
    const img = join(cwd, "inputs", "torn.raw");
    await writeFile(img, buf);
    const out = await runPy(join(LIB, "fve_metadata", "run.py"), cwd, { path: "inputs/torn.raw" });
    assert.notEqual(out.code, 0);
    assert.match(JSON.parse(out.stdout).error, /disagrees with its copy/);
  });
});

test("icat_root says why icat failed instead of exiting on its code alone", async () => {
  await withCwd(async (cwd, bin) => {
    // A bare non-zero exit gave the agent an empty stdout and no way to tell
    // a bad inode from a missing image, so the next turn guessed.
    await writeFile(join(bin, "icat"), '#!/bin/sh\necho "cannot find inode" >&2\nexit 1\n', "utf8");
    await chmod(join(bin, "icat"), 0o755);
    const out = await runPy(join(LIB, "icat_root", "run.py"), cwd, { inode: 99 }, bin);
    assert.notEqual(out.code, 0);
    const body = JSON.parse(out.stdout) as { error: string; exit_code: number; stderr: string };
    assert.match(body.error, /icat failed/);
    assert.equal(body.exit_code, 1);
    assert.match(body.stderr, /cannot find inode/);
  });
});

test("grep_filelist names a bad pattern instead of raising re.error", async () => {
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "catalog", "AF-Case2.E01", "p0"), { recursive: true });
    await writeFile(join(cwd, "catalog", "AF-Case2.E01", "p0", "filelist.txt"), "safe.txt\n", "utf8");
    const bad = await runPy(join(LIB, "grep_filelist", "run.py"), cwd, { pattern: "unclosed[" });
    assert.notEqual(bad.code, 0);
    assert.match(JSON.parse(bad.stdout).error, /not a valid regular expression/);
  });
});

test("grep_filelist fails closed when the catalog filelist is absent", async () => {
  await withCwd(async (cwd) => {
    let out = await runPy(join(LIB, "grep_filelist", "run.py"), cwd, { pattern: "." });
    assert.notEqual(out.code, 0);
    assert.match(JSON.parse(out.stdout).error, /no catalog file list under catalog\//);
    out = await runPy(join(LIB, "grep_filelist", "run.py"), cwd, { pattern: ".", path: "catalog/gone/p0/filelist.txt" });
    assert.notEqual(out.code, 0);
    assert.match(JSON.parse(out.stdout).error, /cannot read the catalog filelist/);
  });
});

// grep_filelist read catalog/AF-Case2.E01/p0/filelist.txt on every case, and
// the library's catalog_search was a first version that read
// catalog/SysInternalsCase.E01 and nothing else, while the docs hand the
// library to any run with --tools-from tool-library.
test("the library's catalog searches read the case in front of them, not the one they were written on", async () => {
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "catalog", "Case4.E01", "p2048"), { recursive: true });
    await writeFile(join(cwd, "catalog", "Case4.E01", "p2048", "filelist.txt"), "r/r 1: Users/alice/NTUSER.DAT\nr/r 2: Windows/notepad.exe\n");
    let r = await runPy(join(LIB, "grep_filelist", "run.py"), cwd, { pattern: "ntuser" });
    assert.equal(r.code, 0, r.stderr + r.stdout);
    assert.deepEqual(JSON.parse(r.stdout), ["r/r 1: Users/alice/NTUSER.DAT"]);
    r = await runPy(join(LIB, "catalog_search", "run.py"), cwd, { pattern: "notepad" });
    assert.equal(r.code, 0, r.stderr + r.stdout);
    assert.equal(JSON.parse(r.stdout).hits[0].line, "r/r 2: Windows/notepad.exe");
    await mkdir(join(cwd, "catalog", "Other.E01", "p0"), { recursive: true });
    await writeFile(join(cwd, "catalog", "Other.E01", "p0", "filelist.txt"), "r/r 3: x\n");
    r = await runPy(join(LIB, "grep_filelist", "run.py"), cwd, { pattern: "x" });
    assert.notEqual(r.code, 0);
    assert.deepEqual(JSON.parse(r.stdout).candidates, ["catalog/Case4.E01/p2048/filelist.txt", "catalog/Other.E01/p0/filelist.txt"]);
    r = await runPy(join(LIB, "grep_filelist", "run.py"), cwd, { pattern: "x", path: "catalog/Other.E01/p0/filelist.txt" });
    assert.deepEqual(JSON.parse(r.stdout), ["r/r 3: x"]);
  });
  const lib = join(LIB, "catalog_search");
  const pack = join(LIB, "..", "packs", "computer-forensics-base", "tools", "catalog_search");
  assert.equal(await readFile(join(lib, "run.py"), "utf8"), await readFile(join(pack, "run.py"), "utf8"), "the library's catalog_search is the pack's");
  assert.deepEqual(JSON.parse(await readFile(join(lib, "manifest.json"), "utf8")), JSON.parse(await readFile(join(pack, "manifest.json"), "utf8")));
});

// A broad search returned up to 70K characters a call, and an agent that
// wanted the rest searched again with a bigger limit: the lines past the
// limit were counted and dropped. Every match is kept now, and paged.
test("catalog_search keeps every match in a named file and pages through them", async () => {
  const script = join(LIB, "..", "packs", "computer-forensics-base", "tools", "catalog_search", "run.py");
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "catalog", "Case4.E01", "p2048"), { recursive: true });
    const lines = Array.from({ length: 120 }, (_, i) => `r/r ${i + 1}: Windows/Prefetch/APP${i + 1}.EXE.pf`);
    await writeFile(join(cwd, "catalog", "Case4.E01", "p2048", "filelist.txt"), `r/r 999: Users/readme.txt\n${lines.join("\n")}\n`);
    const env = { AGENT_ID: "sab12301" };
    let r = await runPy(script, cwd, { pattern: "prefetch" }, undefined, env);
    assert.equal(r.code, 0, r.stderr + r.stdout);
    let got = JSON.parse(r.stdout);
    assert.equal(got.matched, 120);
    assert.equal(got.returned, 50, "fifty by default");
    assert.equal(got.next_offset, 50);
    assert.equal(got.hits[0].n, 2, "a hit keeps its line number in the catalogue file");
    assert.match(got.all_matches, /^work\/sab12301\/catalog-search\/filelist-[0-9a-f]{16}\.txt$/);
    const kept = (await readFile(join(cwd, got.all_matches), "utf8")).trimEnd().split("\n");
    assert.equal(kept.length, 120, "every match is in the file");
    assert.equal(kept[119], `121\t${lines[119]}`);
    const first = got.all_matches;
    r = await runPy(script, cwd, { pattern: "prefetch", offset: 100 }, undefined, env);
    got = JSON.parse(r.stdout);
    assert.equal(got.returned, 20);
    assert.equal(got.hits[0].line, lines[100]);
    assert.equal(got.next_offset, null, "the last page says there is no next one");
    assert.equal(got.all_matches, first, "the same search names the same file");
    // A search that fits in one page writes nothing.
    r = await runPy(script, cwd, { pattern: "readme" }, undefined, env);
    got = JSON.parse(r.stdout);
    assert.equal(got.matched, 1);
    assert.equal(got.next_offset, null);
    assert.equal(got.all_matches, undefined);
    r = await runPy(script, cwd, { pattern: "x", limit: "many" }, undefined, env);
    assert.notEqual(r.code, 0);
    assert.match(JSON.parse(r.stdout).error, /whole numbers/);
  });
});

test("aescrypt_v2_decrypt refuses an output that resolves back under inputs/", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "inputs", "secret.aes"), fakeAesBlob());
    // "inputs/" is not a prefix of this path, but it is where the file lands,
    // and a decrypted secret written there would show up as tampering in the
    // next inputs check.
    const out = await runPy(join(LIB, "aescrypt_v2_decrypt", "run.py"), cwd, {
      path: "inputs/secret.aes",
      password: "pw",
      output: "work/../inputs/leaked.txt",
    });
    assert.notEqual(out.code, 0);
    assert.match(JSON.parse(out.stdout).error, /cannot be under inputs/);
    const leaked = await readFile(join(cwd, "inputs", "leaked.txt")).catch(() => null);
    assert.equal(leaked, null);
  });
});

test("aescrypt_v2_decrypt reports a truncated file instead of an IndexError", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "inputs", "stub.aes"), Buffer.concat([Buffer.from("AES"), Buffer.from([2, 0, 0, 0])]));
    const out = await runPy(join(LIB, "aescrypt_v2_decrypt", "run.py"), cwd, {
      path: "inputs/stub.aes",
      password: "pw",
      output: "work/stub.txt",
    });
    assert.notEqual(out.code, 0);
    assert.doesNotMatch(out.stderr, /Traceback/);
    assert.match(JSON.parse(out.stdout).error, /truncated/);
  });
});

test("master_icat reads its arguments once, so the output branch runs", async () => {
  await withCwd(async (cwd, bin) => {
    // Two `python3 -c` readers meant the second got EOF, and under `set -e`
    // the script died before icat ever ran.
    const out = await runSh(join(LIB, "master_icat", "run.sh"), cwd, {
      inode: 42,
      output: "work/hdfs/out.bin",
    }, bin);
    assert.equal(out.code, 0, out.stderr);
    const body = JSON.parse(out.stdout) as { inode: number; output: string; size: number };
    assert.equal(body.inode, 42);
    assert.equal(body.output, "work/hdfs/out.bin");
    assert.equal(body.size, "extracted-bytes".length);
    const args = await readFile(join(cwd, "icat-args.txt"), "utf8");
    assert.match(args, /^-o\n2048\ninputs\/HDFS-Master\.E01\n42\n/);
  });
});

test("master_icat refuses an inode that is not a number and an escaping output", async () => {
  await withCwd(async (cwd, bin) => {
    const bad = await runSh(join(LIB, "master_icat", "run.sh"), cwd, { inode: "7; touch pwned" }, bin);
    assert.notEqual(bad.code, 0);
    assert.match(bad.stdout, /inode must be a non-negative integer/);
    const escaped = await runSh(join(LIB, "master_icat", "run.sh"), cwd, {
      inode: 7,
      output: "../outside.bin",
    }, bin);
    assert.notEqual(escaped.code, 0);
    assert.match(escaped.stdout, /must stay inside the run directory/);
    const pwned = await readFile(join(cwd, "pwned")).catch(() => null);
    assert.equal(pwned, null);
  });
});

test("icat writers refuse an output that resolves under inputs/, and do not run icat", async () => {
  // A prefix check on the string the caller typed misses work/../inputs/x.
  // These four used to write there; aescrypt_v2_decrypt already refused it.
  const writers: Array<{ name: string; run: (cwd: string, bin: string, output: string) => Promise<{ code: number | null; stdout: string }> }> = [
    {
      name: "icat_extract",
      run: (cwd, bin, output) => runPy(join(LIB, "icat_extract", "run.py"), cwd, { inode: 7, output }, bin),
    },
    {
      name: "icat_root",
      run: (cwd, bin, output) => runPy(join(LIB, "icat_root", "run.py"), cwd, { inode: 7, output }, bin),
    },
    {
      name: "hdfs_node_icat",
      run: (cwd, bin, output) => runPy(join(LIB, "hdfs_node_icat", "run.py"), cwd, { inode: "7", output, node: "master" }, bin),
    },
    {
      name: "master_icat",
      run: (cwd, bin, output) => runSh(join(LIB, "master_icat", "run.sh"), cwd, { inode: 7, output }, bin),
    },
  ];
  for (const writer of writers) {
    await withCwd(async (cwd, bin) => {
      const out = await writer.run(cwd, bin, "work/../inputs/leaked.bin");
      assert.notEqual(out.code, 0, writer.name);
      assert.match(out.stdout, /cannot be under inputs/, writer.name);
      const leaked = await readFile(join(cwd, "inputs", "leaked.bin")).catch(() => null);
      assert.equal(leaked, null, writer.name);
      const args = await readFile(join(cwd, "icat-args.txt"), "utf8").catch(() => null);
      assert.equal(args, null, `${writer.name} must not reach icat`);
    });
  }
});

test("extract_stream returns the bytes, and an icat failure as JSON rather than base64", async () => {
  await withCwd(async (cwd, bin) => {
    const good = await runSh(join(LIB, "extract_stream", "run.sh"), cwd, {
      image: "inputs/AF-Case2.E01",
      inode: "168-128-4",
      offset: 0,
    }, bin);
    assert.equal(good.code, 0, good.stderr);
    assert.equal(Buffer.from(good.stdout.trim(), "base64").toString("utf8"), "extracted-bytes");

    // It used to be `icat … 2>&1 | base64`: the error text was encoded as if
    // it were file content, and the pipe made the status base64's, so every
    // call exited 0. A caller decoding that got a plausible-looking blob.
    await failingStub(bin, "icat", "Error looking up inode: 9999");
    const bad = await runSh(join(LIB, "extract_stream", "run.sh"), cwd, {
      image: "inputs/AF-Case2.E01",
      inode: "9999",
      offset: 0,
    }, bin);
    assert.equal(bad.code, 1, "a failed extraction must not exit 0");
    const body = JSON.parse(bad.stdout) as { error: string; status: number; stderr: string };
    assert.equal(body.error, "icat failed");
    assert.equal(body.status, 1);
    assert.match(body.stderr, /Error looking up inode/);
  });
});

test("extract_stream refuses arguments it cannot use", async () => {
  await withCwd(async (cwd, bin) => {
    const noImage = await runSh(join(LIB, "extract_stream", "run.sh"), cwd, { inode: "5" }, bin);
    assert.notEqual(noImage.code, 0);
    assert.match(noImage.stdout, /image must be a single-line path/);
    const badOffset = await runSh(join(LIB, "extract_stream", "run.sh"), cwd, {
      image: "inputs/AF-Case2.E01",
      inode: "5",
      offset: -1,
    }, bin);
    assert.notEqual(badOffset.code, 0);
    assert.match(badOffset.stdout, /offset must be a non-negative sector count/);
    const args = await readFile(join(cwd, "icat-args.txt"), "utf8").catch(() => null);
    assert.equal(args, null, "a refused call must not reach icat");
  });
});

async function imgStubs(bin: string, sizeLine: string | null): Promise<void> {
  if (sizeLine === null) {
    await failingStub(bin, "img_stat", "Cannot determine file type");
  } else {
    const stat = join(bin, "img_stat");
    await writeFile(stat, `#!/bin/sh\necho "${sizeLine}"\n`, "utf8");
    await chmod(stat, 0o755);
  }
  const cat = join(bin, "img_cat");
  // 1024 bytes with the needle at offset 100 of the chunk.
  await writeFile(
    cat,
    `#!/bin/sh\npython3 -c 'import sys; sys.stdout.buffer.write(b"." * 100 + b"NEEDLE" + b"." * 918)'\n`,
    "utf8",
  );
  await chmod(cat, 0o755);
}

type Scan = {
  hits: { offset: number; sector: number }[];
  hit_count: number;
  media_size: number | null;
  media_size_source: string | null;
  reached_end: boolean;
  end: number;
};

test("sigscan_e01 scans the range img_stat gives it", async () => {
  await withCwd(async (cwd, bin) => {
    await imgStubs(bin, "Size of data in bytes: 4096");
    const out = await runPy(join(LIB, "sigscan_e01", "run.py"), cwd, {
      image: "inputs/AF-Case2.E01",
      needle_ascii: "NEEDLE",
      start: 512,
      length: 1024,
    }, bin);
    assert.equal(out.code, 0, out.stderr);
    const body = JSON.parse(out.stdout) as Scan;
    assert.equal(body.hit_count, 1);
    assert.equal(body.hits[0].offset, 612);
    assert.equal(body.hits[0].sector, 1);
    assert.equal(body.media_size, 4096);
    assert.equal(body.media_size_source, "img_stat");
    assert.equal(body.reached_end, true);
  });
});

test("sigscan_e01 refuses to invent a media size when img_stat cannot give one", async () => {
  await withCwd(async (cwd, bin) => {
    await imgStubs(bin, null);
    // It used to assume 42949672960 bytes — 40 GiB — and report that as the
    // image's size. On anything smaller it walked a range that does not
    // exist, read nothing, and called the result "no hits". A scan that says
    // a signature is absent has to have covered the span it names.
    const out = await runPy(join(LIB, "sigscan_e01", "run.py"), cwd, {
      image: "inputs/AF-Case2.E01",
      needle_ascii: "NEEDLE",
    }, bin);
    assert.equal(out.code, 1, out.stderr);
    assert.doesNotMatch(out.stdout, /42949672960/, "the hard-coded 40 GiB guess must be gone");
    const body = JSON.parse(out.stdout) as { error: string; img_stat: string };
    assert.match(body.error, /cannot determine the media size/);
    assert.match(body.img_stat, /Cannot determine file type/);

    // With an explicit length the caller has bounded the scan, so it runs.
    const bounded = await runPy(join(LIB, "sigscan_e01", "run.py"), cwd, {
      image: "inputs/AF-Case2.E01",
      needle_ascii: "NEEDLE",
      start: 512,
      length: 1024,
    }, bin);
    assert.equal(bounded.code, 0, bounded.stderr);
    const scan = JSON.parse(bounded.stdout) as Scan;
    assert.equal(scan.media_size, null);
    assert.equal(scan.media_size_source, "length argument");
    assert.equal(scan.end, 1536);
    assert.equal(scan.hit_count, 1);
  });
});

const RENDER_DRIVER = [
  "import importlib.util, json, sys, types",
  "stubs = {'regipy': {}, 'regipy.registry': {'RegistryHive': object},",
  "         'regipy.exceptions': {'RegistryKeyNotFoundException': type('E', (Exception,), {})}}",
  "for name, attrs in stubs.items():",
  "    mod = types.ModuleType(name)",
  "    for k, v in attrs.items():",
  "        setattr(mod, k, v)",
  "    sys.modules[name] = mod",
  "spec = importlib.util.spec_from_file_location('regkeys', sys.argv[1])",
  "mod = importlib.util.module_from_spec(spec)",
  "spec.loader.exec_module(mod)",
  "out = []",
  "for case in json.load(sys.stdin):",
  "    raw = bytes.fromhex(case['hex']) if 'hex' in case else case['value']",
  "    value, encoding = mod.render(raw, case['type'])",
  "    out.append({'value': value, 'encoding': encoding})",
  "print(json.dumps(out))",
].join("\n");

test("regkeys renders a value by its registry type, so REG_BINARY stays hex", async () => {
  // Every bytes value used to be decoded utf-16-le with errors="replace",
  // which turned a ShimCache or UserAssist blob into mojibake that reads
  // like text; "replace" never raises, so the hex branch under it was dead.
  // regkv and reg_hive_query already answer hex for the same value.
  const sz = `${Buffer.from("C:\\Windows", "utf16le").toString("hex")}0000`;
  const multi = Buffer.from("a\u0000b\u0000", "utf16le").toString("hex");
  const binary = "deadbeef00ff";
  const out = await runPySnippet(RENDER_DRIVER, [join(LIB, "regkeys", "run.py")], [
    { type: "REG_SZ", hex: sz },
    { type: "REG_MULTI_SZ", hex: multi },
    { type: "REG_BINARY", hex: binary },
    { type: "REG_NONE", hex: binary },
    { type: "REG_DWORD", value: 1234 },
  ]);
  assert.equal(out.code, 0, out.stderr);
  const rendered = JSON.parse(out.stdout) as { value: unknown; encoding: string | null }[];
  assert.deepEqual(rendered[0], { value: "C:\\Windows", encoding: "utf-16-le" });
  assert.deepEqual(rendered[1], { value: ["a", "b"], encoding: "utf-16-le" });
  assert.deepEqual(rendered[2], { value: binary, encoding: "hex" });
  assert.deepEqual(rendered[3], { value: binary, encoding: "hex" });
  assert.deepEqual(rendered[4], { value: 1234, encoding: null });
});

test("the tools that name an image take one as a parameter", async () => {
  // Three of these hard-coded the image they were written for, so they were
  // unusable on any other case. A default is fine; no way to override it is
  // a tool the next run has to write again.
  for (const name of ["icat_root", "master_icat", "hdfs_node_icat", "fls_root", "sigscan_e01", "chunk_needles"]) {
    const manifest = JSON.parse(await readFile(join(LIB, name, "manifest.json"), "utf8")) as { params: Record<string, unknown> };
    const keys = Object.keys(manifest.params);
    assert.ok(
      keys.includes("image") || keys.includes("path") || keys.includes("e01"),
      `${name} names an image in its script but takes no parameter for one (params: ${keys.join(", ")})`,
    );
  }
});

test("icat_root and master_icat read the image they are given, not the one they were written for", async () => {
  await withCwd(async (cwd, bin) => {
    // The default image is not in this directory, and neither is the one
    // named here: both must be reported as missing rather than assumed.
    const out = await runPy(join(LIB, "icat_root", "run.py"), cwd, {
      inode: 12,
      image: "inputs/NotHere.E01",
    }, bin);
    assert.notEqual(out.code, 0);
    assert.match(out.stdout, /image not found/);
    assert.match(out.stdout, /NotHere\.E01/, "the message names the image it was given");

    await writeFile(join(cwd, "inputs", "Other.E01"), "img\n", "utf8");
    const ok = await runPy(join(LIB, "icat_root", "run.py"), cwd, { inode: 12, image: "inputs/Other.E01", offset: 2048 }, bin);
    assert.equal(ok.code, 0, ok.stderr);
    const args = await readFile(join(cwd, "icat-args.txt"), "utf8");
    assert.match(args, /^-o\n2048\ninputs\/Other\.E01\n12\n/, "the offset and image reached icat");

    const viaSh = await runSh(join(LIB, "master_icat", "run.sh"), cwd, {
      inode: 7,
      output: "work/out.bin",
      image: "inputs/Other.E01",
      offset: 63,
    }, bin);
    assert.equal(viaSh.code, 0, viaSh.stderr);
    const body = JSON.parse(viaSh.stdout) as { image: string; offset: number };
    assert.equal(body.image, "inputs/Other.E01");
    assert.equal(body.offset, 63);
  });
});


// Every Python tool a pack or the library ships, read for a name it uses at
// module level and never binds: a NameError waits for the first call that
// reaches it. catalog_search read `d` for `args` and failed every call in a
// real run.
test("no pack or library tool uses a module-level name it never binds", async () => {
  const { spawnSync } = await import("node:child_process");
  const scan = `
import builtins, glob, symtable, sys
bad = []
for p in sorted(glob.glob("packs/*/tools/*/*.py") + glob.glob("tool-library/*/*.py")):
    src = open(p, encoding="utf-8", errors="replace").read()
    st = symtable.symtable(src, p, "exec")
    for s in st.get_symbols():
        if s.is_referenced() and not (s.is_assigned() or s.is_imported() or s.is_parameter()) and s.get_name() not in dir(builtins):
            bad.append("%s: %s" % (p, s.get_name()))
print("\\n".join(bad))
`;
  const r = spawnSync("python3", ["-c", scan], { cwd: join(LIB, ".."), encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
  assert.equal(r.stdout.trim(), "", `unbound names:\n${r.stdout}`);
});

test("catalog_search finds the filesystem the catalogue names by its sector, and asks which when there are several", async () => {
  await withCwd(async (cwd) => {
    const script = join(LIB, "..", "packs", "computer-forensics-base", "tools", "catalog_search", "run.py");
    // As scripts/evidence-catalog.sh writes it: one directory per filesystem,
    // named by its first sector; a usual first partition is p2048.
    await mkdir(join(cwd, "catalog", "Case4", "p2048"), { recursive: true });
    await writeFile(join(cwd, "catalog", "Case4", "p2048", "filelist.txt"), "Users/alice/NTUSER.DAT\nWindows/Prefetch/CHROME.EXE-1.pf\n");
    await writeFile(join(cwd, "catalog", "Case4", "partitions.txt"), "002:  000:000   0000002048   ...   NTFS\n");
    let r = await runPy(script, cwd, { pattern: "prefetch", which: "filelist" });
    assert.equal(r.code, 0, r.stderr + r.stdout);
    assert.match(r.stdout, /CHROME\.EXE-1\.pf/);
    assert.match(r.stdout, /"partition": "p2048"/);
    assert.doesNotMatch(r.stdout, /NTUSER/);
    r = await runPy(script, cwd, { pattern: "NTFS", which: "partitions" });
    assert.equal(r.code, 0, r.stderr + r.stdout);
    // A second filesystem: the caller says which, by directory or by sector.
    await mkdir(join(cwd, "catalog", "Case4", "p409600"), { recursive: true });
    await writeFile(join(cwd, "catalog", "Case4", "p409600", "filelist.txt"), "Data/secret.txt\n");
    r = await runPy(script, cwd, { pattern: "secret", which: "filelist" });
    assert.notEqual(r.code, 0);
    assert.match(r.stdout, /several filesystems.*pass partition=/);
    assert.match(r.stdout, /p409600/);
    r = await runPy(script, cwd, { pattern: "secret", which: "filelist", partition: "409600" });
    assert.equal(r.code, 0, r.stderr + r.stdout);
    assert.match(r.stdout, /Data\/secret\.txt/);
    // A file the catalogue did not write is said, never a traceback.
    r = await runPy(script, cwd, { pattern: "x", which: "timeline", partition: "p2048" });
    assert.notEqual(r.code, 0);
    assert.match(r.stdout, /is not in the catalogue/);
    assert.doesNotMatch(r.stdout + r.stderr, /Traceback/);
    // A second catalogue: catalog= names it.
    await mkdir(join(cwd, "catalog", "Other", "p0"), { recursive: true });
    await writeFile(join(cwd, "catalog", "Other", "p0", "filelist.txt"), "Other/file.txt\n");
    await writeFile(join(cwd, "catalog", "Other", "partitions.txt"), "No partition table: inputs/Other is one NTFS volume starting at sector 0.\n");
    r = await runPy(script, cwd, { pattern: "file", which: "filelist", partition: "p2048" });
    assert.match(r.stdout + r.stderr, /several catalogues; pass catalog=/);
    r = await runPy(script, cwd, { pattern: "file", which: "filelist", catalog: join("catalog", "Other") });
    assert.equal(r.code, 0, r.stderr + r.stdout);
    assert.match(r.stdout, /Other\/file\.txt/);
  });
});

test("icat_extract and chunk_needles find an image by its catalogue when it has no extension, and the offset with it", async () => {
  // Run 2 on Linux: the evidence was a raw dd named after the host
  // (inputs/s4a-challenge4), and every icat_extract call answered "no disk
  // image under inputs/". On macOS the same tool read Case4.E01 at sector 0
  // and icat said "Cannot determine file system type": the filesystem the
  // catalogue lists is at 2048.
  const tools = join(LIB, "..", "packs", "computer-forensics-base", "tools");
  await withCwd(async (cwd, bin) => {
    await rm(join(cwd, "inputs", "AF-Case2.E01"));
    await rm(join(cwd, "inputs", "Webserver.E01"));
    await writeFile(join(cwd, "inputs", "s4a-challenge4"), "raw\n");
    await writeFile(join(cwd, "inputs", "memdump.mem"), "mem\n");
    await mkdir(join(cwd, "catalog", "s4a-challenge4", "p2048"), { recursive: true });
    await writeFile(join(cwd, "catalog", "s4a-challenge4", "partitions.txt"), "002:  000:000   0000002048   ...   Linux (0x83)\n");
    await mkdir(join(cwd, "catalog", "memdump.mem"), { recursive: true });
    await writeFile(join(cwd, "catalog", "memdump.mem", "pslist.txt"), "PID\n");

    let r = await runPy(join(tools, "icat_extract", "run.py"), cwd, { inode: 12, output: "work/x.bin" }, bin);
    assert.equal(r.code, 0, r.stderr + r.stdout);
    let body = JSON.parse(r.stdout) as { image: string; offset: number };
    assert.equal(body.image, "inputs/s4a-challenge4");
    assert.equal(body.offset, 2048);
    assert.equal(await readFile(join(cwd, "icat-args.txt"), "utf8"), "-o\n2048\ninputs/s4a-challenge4\n12\n");

    r = await runPy(join(tools, "chunk_needles", "run.py"), cwd, { needles: "extracted", inode: 12 }, bin);
    assert.equal(r.code, 0, r.stderr + r.stdout);
    assert.equal(await readFile(join(cwd, "icat-args.txt"), "utf8"), "-o\n2048\ninputs/s4a-challenge4\n12\n");
    assert.equal((JSON.parse(r.stdout) as { hits: Record<string, { ascii: number }> }).hits.extracted.ascii, 1);

    // A second filesystem: the caller says which; a given 0 is 0.
    await mkdir(join(cwd, "catalog", "s4a-challenge4", "p409600"), { recursive: true });
    r = await runPy(join(tools, "icat_extract", "run.py"), cwd, { inode: 12, output: "work/x.bin" }, bin);
    assert.notEqual(r.code, 0);
    assert.match(r.stdout + r.stderr, /several filesystems in inputs\/s4a-challenge4; pass offset=/);
    assert.match(r.stdout + r.stderr, /\[2048, 409600\]/);
    r = await runPy(join(tools, "icat_extract", "run.py"), cwd, { inode: 12, output: "work/x.bin", offset: 0 }, bin);
    assert.equal(r.code, 0, r.stderr + r.stdout);
    assert.equal(await readFile(join(cwd, "icat-args.txt"), "utf8"), "-o\n0\ninputs/s4a-challenge4\n12\n");
  });

  // A nested input with a space and a non-ASCII letter: the catalogue's name
  // for it is what evidence-catalog.sh's `tr` makes of its bytes.
  await withCwd(async (cwd, bin) => {
    await rm(join(cwd, "inputs", "AF-Case2.E01"));
    await rm(join(cwd, "inputs", "Webserver.E01"));
    const rel = "olay ş/disk";
    await mkdir(join(cwd, "inputs", "olay ş"), { recursive: true });
    await writeFile(join(cwd, "inputs", rel), "raw\n");
    const { spawnSync } = await import("node:child_process");
    const slug = spawnSync("bash", ["-c", "printf '%s' \"$1\" | tr -c 'A-Za-z0-9._-' '_'", "_", rel], { encoding: "utf8", env: { ...process.env, LC_ALL: "C" } }).stdout;
    await mkdir(join(cwd, "catalog", slug, "p63"), { recursive: true });
    await writeFile(join(cwd, "catalog", slug, "partitions.txt"), "002:  000:000   0000000063   ...   NTFS\n");
    const r = await runPy(join(tools, "icat_extract", "run.py"), cwd, { inode: 5, output: "work/y.bin" }, bin);
    assert.equal(r.code, 0, r.stderr + r.stdout);
    const body = JSON.parse(r.stdout) as { image: string; offset: number };
    assert.equal(body.image, `inputs/${rel}`);
    assert.equal(body.offset, 63);
  });
});

test("sqlite_query opens a database read-only by URI, on a read-only directory, whatever its name", async (t) => {
  // It passed `sqlite3 -uri`, an option the shell does not have: every call
  // with readonly=true (the default) failed in the macOS run. A WAL database
  // in another agent's read-only work directory is the case immutable=1 is for.
  const { spawnSync } = await import("node:child_process");
  if (spawnSync("sqlite3", ["-version"]).status !== 0) {
    t.skip("no sqlite3 shell on this host");
    return;
  }
  for (const script of [
    join(LIB, "..", "packs", "computer-forensics-base", "tools", "sqlite_query", "run.py"),
    join(LIB, "sqlite_query", "run.py"),
  ]) {
    await withCwd(async (cwd) => {
      const dir = join(cwd, "work", "agent 03 #1");
      await mkdir(dir, { recursive: true });
      const db = join(dir, "ActivitiesCache.db");
      const made = spawnSync("sqlite3", [db, "pragma journal_mode=wal; create table a(x); insert into a values(7);"], { encoding: "utf8" });
      assert.equal(made.status, 0, made.stderr);
      await chmod(dir, 0o555);
      try {
        const r = await runPy(script, cwd, { db_path: "work/agent 03 #1/ActivitiesCache.db", sql: "select x from a;", csv: true });
        assert.equal(r.code, 0, r.stderr + r.stdout);
        const out = JSON.parse(r.stdout) as { ok: boolean; stdout: string };
        assert.equal(out.ok, true);
        assert.equal(out.stdout, "x\n7\n");
      } finally {
        await chmod(dir, 0o755);
      }
    });
  }
});

// regipy's get_key, as regipy 6 has it: a path with a backslash loses its
// first part (taken for the root's name) unless it starts with one.
const ROOTED_DRIVER = [
  "import importlib.util, json, sys, types",
  "class NotFound(Exception): pass",
  "class Key:",
  "    def __init__(self, name, path, kids=()):",
  "        self.name, self.path, self.kids = name, path, {k.name.lower(): k for k in kids}",
  "    def get_subkey(self, name, raise_on_missing=True):",
  "        return self.kids.get(name.lower())",
  "    def iter_subkeys(self):",
  "        return iter(self.kids.values())",
  "def tree(name, path, spec):",
  "    return Key(name, path, [tree(k, path + '\\\\' + k, v) for k, v in spec.items()])",
  "shell = {'Microsoft': {'Windows': {'Shell': {'BagMRU': {}}}}}",
  "class Hive:",
  "    def __init__(self):",
  "        self.root = Key('S-1-5-21-1_Classes', '', [tree('Local Settings', '\\\\Local Settings', {'Software': shell}), tree('Software', '\\\\Software', shell)])",
  "        self.root.kids = {k.name.lower(): k for k in self.root.kids.values()}",
  "    def get_key(self, key_path):",
  "        if key_path == '\\\\': return self.root",
  "        parts = key_path.split('\\\\')[1:] if '\\\\' in key_path else [key_path]",
  "        k = self.root.get_subkey(parts.pop(0))",
  "        for p in parts:",
  "            if not k: break",
  "            k = k.get_subkey(p)",
  "        if not k: raise NotFound(key_path)",
  "        return k",
  "for name, attrs in {'regipy': {}, 'regipy.registry': {'RegistryHive': Hive}, 'regipy.exceptions': {'RegistryKeyNotFoundException': NotFound}}.items():",
  "    m = types.ModuleType(name)",
  "    for k, v in attrs.items(): setattr(m, k, v)",
  "    sys.modules[name] = m",
  "spec = importlib.util.spec_from_file_location('tool', sys.argv[1])",
  "mod = importlib.util.module_from_spec(spec)",
  "spec.loader.exec_module(mod)",
  "out = []",
  "for p in json.load(sys.stdin):",
  "    try: out.append(mod.rooted_key(Hive(), p).path)",
  "    except NotFound: out.append(None)",
  "print(json.dumps(out))",
].join("\n");

test("the registry tools read a key from the hive's root, whatever form the path comes in", async () => {
  // Without a leading backslash regipy dropped the path's first part:
  // shellbags looked for Local Settings\...\BagMRU in a UsrClass.dat that has
  // it and said "no BagMRU root" (third CTF round), and in an NTUSER.DAT the
  // same path answered Software\...\BagMRU under the name asked for.
  const bag = "Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU";
  for (const script of [
    join(LIB, "..", "packs", "windows-forensics", "tools", "shellbags", "run.py"),
    join(LIB, "..", "packs", "windows-forensics", "tools", "regkv", "run.py"),
    join(LIB, "regkv", "run.py"),
    join(LIB, "regkeys", "run.py"),
  ]) {
    const out = await runPySnippet(ROOTED_DRIVER, [script], [bag, `\\${bag}`, `S-1-5-21-1_Classes\\${bag}`, bag.replaceAll("\\", "/"), "Software\\Microsoft", "Microsoft\\Windows", ""]);
    assert.equal(out.code, 0, `${script}: ${out.stderr}`);
    assert.deepEqual(JSON.parse(out.stdout), [`\\${bag}`, `\\${bag}`, `\\${bag}`, `\\${bag}`, "\\Software\\Microsoft", null, ""], script);
  }
});

test("a registry key that is not there is answered with the deepest key that is, and the names under it", async () => {
  // Sixth CTF round: regkv asked for ControlSet001\\Enum\\USBPRINT and
  // ...\\Print\\Printers and answered regipy's traceback twice; the agent
  // needed the names that were there to ask again.
  const driver = ROOTED_DRIVER.replace(
    /out = \[\][\s\S]*$/,
    ["out = [mod.nearest_key(Hive(), p) for p in json.load(sys.stdin)]", "print(json.dumps(out))"].join("\n"),
  );
  for (const script of [
    join(LIB, "..", "packs", "windows-forensics", "tools", "shellbags", "run.py"),
    join(LIB, "..", "packs", "windows-forensics", "tools", "regkv", "run.py"),
    join(LIB, "regkv", "run.py"),
    join(LIB, "regkeys", "run.py"),
  ]) {
    const out = await runPySnippet(driver, [script], [
      "Local Settings\\Software\\Microsoft\\Windows\\Shell\\Printers",
      "\\Software\\Nope\\Deeper",
      "S-1-5-21-1_Classes/Software/microsoft",
    ]);
    assert.equal(out.code, 0, `${script}: ${out.stderr}`);
    assert.deepEqual(JSON.parse(out.stdout), [
      { deepest_found: "\\Local Settings\\Software\\Microsoft\\Windows\\Shell", missing: "Printers", subkeys_there: ["BagMRU"] },
      { deepest_found: "\\Software", missing: "Nope", subkeys_there: ["Microsoft"] },
      { deepest_found: "\\Software\\Microsoft", missing: null, subkeys_there: [] },
    ], script);
  }
});

test("sqlite_query says a file is not SQLite, and whether it looks encrypted, instead of \"file is not a database\"", async () => {
  // Sixth CTF round: Element's SQLCipher events.db answered only sqlite3's
  // "file is not a database", twice, to two agents.
  const { randomBytes } = await import("node:crypto");
  for (const script of [
    join(LIB, "..", "packs", "computer-forensics-base", "tools", "sqlite_query", "run.py"),
    join(LIB, "sqlite_query", "run.py"),
  ]) {
    await withCwd(async (cwd) => {
      await mkdir(join(cwd, "work"), { recursive: true });
      await writeFile(join(cwd, "work", "events.db"), randomBytes(8192));
      await writeFile(join(cwd, "work", "notes.db"), Buffer.from("PK\u0003\u0004" + "just some text in a zip-ish file ".repeat(40)));
      let r = await runPy(script, cwd, { db_path: "work/events.db", sql: "select 1;" });
      assert.notEqual(r.code, 0);
      let body = JSON.parse(r.stdout) as { ok: boolean; error: string; header_hex: string; first_page_entropy_bits_per_byte: number; reading: string };
      assert.equal(body.ok, false);
      assert.match(body.error, /not a SQLite file/);
      assert.equal(body.header_hex.length, 32);
      assert.ok(body.first_page_entropy_bits_per_byte > 7.5, String(body.first_page_entropy_bits_per_byte));
      assert.match(body.reading, /encrypted database/);
      r = await runPy(script, cwd, { db_path: "work/notes.db", sql: "select 1;" });
      body = JSON.parse(r.stdout);
      assert.equal(body.header_hex.slice(0, 8), "504b0304");
      assert.match(body.reading, /another format/);
      r = await runPy(script, cwd, { db_path: "work/none.db", sql: "select 1;" });
      assert.deepEqual(JSON.parse(r.stdout), { ok: false, error: "database not found", db_path: "work/none.db" });
    });
  }
});

test("chunk_needles streams what icat gives it, never holding it whole, and says why icat failed", async () => {
  // Sixth CTF round: chunk_needles on pagefile.sys held icat's output in
  // memory until the VM's kernel killed it, twice, and nothing was said.
  for (const script of [
    join(LIB, "..", "packs", "computer-forensics-base", "tools", "chunk_needles", "run.py"),
    join(LIB, "chunk_needles", "run.py"),
  ]) {
    assert.doesNotMatch(await readFile(script, "utf8"), /BytesIO\(r\.stdout\)/, `${script} reads icat's output whole`);
    await withCwd(async (cwd, bin) => {
      const icat = join(bin, "icat");
      await writeFile(icat, `#!/bin/sh\npython3 -c 'import sys; w = sys.stdout.buffer.write\nfor _ in range(48): w(b"." * 1048576)\nw(b"NEEDLEX")'\n`, "utf8");
      await chmod(icat, 0o755);
      let r = await runPy(script, cwd, { needles: "NEEDLEX", inode: 80513, image: "inputs/AF-Case2.E01", offset: 2048 }, bin);
      assert.equal(r.code, 0, r.stderr + r.stdout);
      const body = JSON.parse(r.stdout) as { scanned_bytes: number; hits: Record<string, { ascii: number }> };
      assert.equal(body.scanned_bytes, 48 * 1048576 + 7);
      assert.equal(body.hits.NEEDLEX.ascii, 1, "a needle at the very end of the stream is found");
      await writeFile(icat, `#!/bin/sh\necho "Cannot determine file system type" >&2\nexit 1\n`, "utf8");
      r = await runPy(script, cwd, { needles: "x", inode: 5, image: "inputs/AF-Case2.E01", offset: 0 }, bin);
      assert.notEqual(r.code, 0);
      assert.match((JSON.parse(r.stdout) as { error: string }).error, /Cannot determine file system type/);
    });
  }
});

test("sqlite_query gives back bytes that are not UTF-8 as escapes instead of dying on them", async (t) => {
  // Sixth CTF round: an ActivitiesCache Payload with such bytes was a
  // UnicodeDecodeError traceback.
  const { spawnSync } = await import("node:child_process");
  if (spawnSync("sqlite3", ["-version"]).status !== 0) {
    t.skip("no sqlite3 shell on this host");
    return;
  }
  for (const script of [
    join(LIB, "..", "packs", "computer-forensics-base", "tools", "sqlite_query", "run.py"),
    join(LIB, "sqlite_query", "run.py"),
  ]) {
    await withCwd(async (cwd) => {
      await mkdir(join(cwd, "work"), { recursive: true });
      const made = spawnSync("sqlite3", [join(cwd, "work", "a.db"), "create table a(x); insert into a values(cast(x'ff41' as text));"], { encoding: "utf8" });
      assert.equal(made.status, 0, made.stderr);
      const r = await runPy(script, cwd, { db_path: "work/a.db", sql: "select x from a;" });
      assert.equal(r.code, 0, r.stderr + r.stdout);
      assert.equal((JSON.parse(r.stdout) as { stdout: string }).stdout, "\\xffA\n");
    });
  }
});

test("browser_history runs several statements one by one, and still refuses one that could write", async () => {
  // Sixth CTF round: "schema; count" answered "You can only execute one
  // statement at a time", to two agents.
  const { spawnSync } = await import("node:child_process");
  for (const script of [
    join(LIB, "..", "packs", "windows-forensics", "tools", "browser_history", "run.py"),
    join(LIB, "browser_history", "run.py"),
  ]) {
    await withCwd(async (cwd) => {
      await mkdir(join(cwd, "work"), { recursive: true });
      const made = spawnSync("python3", ["-c", "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.executescript(\"create table urls(url); insert into urls values('http://a;b'),('http://c');\"); c.commit()", join(cwd, "work", "h.db")], { encoding: "utf8" });
      assert.equal(made.status, 0, made.stderr);
      let r = await runPy(script, cwd, { path: "work/h.db", sql: "select count(*) n from urls; select url from urls where url like '%;%';" });
      assert.equal(r.code, 0, r.stderr + r.stdout);
      const many = JSON.parse(r.stdout) as { results: Array<{ sql: string; rows: Array<Record<string, unknown>> }> };
      assert.deepEqual(many.results.map((x) => x.rows), [[{ n: 2 }], [{ url: "http://a;b" }]], "a ; inside a string stays in its statement");
      r = await runPy(script, cwd, { path: "work/h.db", sql: "select count(*) n from urls" });
      const one = JSON.parse(r.stdout) as { rows: unknown[]; results?: unknown };
      assert.deepEqual(one.rows, [{ n: 2 }]);
      assert.equal(one.results, undefined, "one statement answers as it always has");
      r = await runPy(script, cwd, { path: "work/h.db", sql: "select 1; delete from urls" });
      assert.notEqual(r.code, 0);
      assert.deepEqual(JSON.parse(r.stdout), { error: "sql must be a SELECT, WITH or PRAGMA", statement: "delete from urls" });
    });
  }
});

test("shellbags decodes the shell items regipy hands over as hex, with the GUID in its place", async () => {
  // regipy gives a REG_BINARY value as a hex string; the tool took only
  // bytes, so no item was ever decoded (third CTF round). And a root
  // folder's GUID read its last two groups two bytes early.
  const driver = [
    "import importlib.util, json, sys",
    "spec = importlib.util.spec_from_file_location('shellbags', sys.argv[1])",
    "mod = importlib.util.module_from_spec(spec)",
    "spec.loader.exec_module(mod)",
    "cases = json.load(sys.stdin)",
    "print(json.dumps({",
    "  'items': [mod.decode_item(mod.binary(h)) for h in cases['items']],",
    "  'order': mod.mru_order({'MRUListEx': mod.binary(cases['mru'])}),",
    "  'not_hex': mod.binary('MRUListEx'),",
    "}, default=str))",
  ].join("\n");
  const out = await runPySnippet(driver, [join(LIB, "..", "packs", "windows-forensics", "tools", "shellbags", "run.py")], {
    items: ["14001f50e04fd020ea3a6910a2d808002b30309d", "14001f80cb859f6720028040b29b5540cc05aab6", "19002f5a3a5c000000000000000000000000000000000000"],
    mru: "03000000010000000200000000000000ffffffff",
  });
  assert.equal(out.code, 0, out.stderr);
  const got = JSON.parse(out.stdout) as { items: Array<{ type: string; guid?: string; name: string }>; order: number[]; not_hex: null };
  assert.equal(got.items[0].type, "root folder");
  assert.equal(got.items[0].guid, "{20D04FE0-3AEA-1069-A2D8-08002B30309D}", "My Computer");
  assert.equal(got.items[1].guid, "{679F85CB-0220-4080-B29B-5540CC05AAB6}", "Quick access");
  assert.equal(got.items[2].type, "volume");
  assert.equal(got.items[2].name, "Z:\\");
  assert.deepEqual(got.order, [3, 1, 2, 0]);
  assert.equal(got.not_hex, null);
});

test("catalog_search takes a catalogue by the name the index gives it, and bad input is an answer, not a traceback", async () => {
  // Third CTF round: catalog=Case4.E01 (the name catalog/README.md lists)
  // was FileNotFoundError; sqlite_query without sql= was KeyError; ioc_scan
  // on a missing path was FileNotFoundError.
  const tools = join(LIB, "..", "packs", "computer-forensics-base", "tools");
  await withCwd(async (cwd) => {
    for (const [dir, line] of [["p2048", "Users/alice/NTUSER.DAT"], ["p409600", "Data/secret.txt"]]) {
      await mkdir(join(cwd, "catalog", "Case4.E01", dir), { recursive: true });
      await writeFile(join(cwd, "catalog", "Case4.E01", dir, "filelist.txt"), `${line}\n`);
    }
    await mkdir(join(cwd, "catalog", "memdump.mem"), { recursive: true });
    let r = await runPy(join(tools, "catalog_search", "run.py"), cwd, { pattern: "NTUSER", which: "filelist", catalog: "Case4.E01", partition: "2048" });
    assert.equal(r.code, 0, r.stderr + r.stdout);
    assert.match(r.stdout, /NTUSER\.DAT/);
    r = await runPy(join(tools, "catalog_search", "run.py"), cwd, { pattern: "secret", which: "filelist", catalog: "Case4.E01/p409600" });
    assert.equal(r.code, 0, r.stderr + r.stdout);
    assert.match(r.stdout, /Data\/secret\.txt/);
    r = await runPy(join(tools, "catalog_search", "run.py"), cwd, { pattern: "x", which: "filelist", catalog: "Case5.E01" });
    assert.notEqual(r.code, 0);
    assert.deepEqual(JSON.parse(r.stdout + r.stderr), { ok: false, error: "no catalogue Case5.E01", candidates: ["Case4.E01", "memdump.mem"] });
    // A disk and a memory catalogue: the disk's is the one with filesystems.
    await writeFile(join(cwd, "catalog", "Case4.E01", "partitions.txt"), "002:  000:000   0000002048   ...   NTFS\n");
    r = await runPy(join(tools, "catalog_search", "run.py"), cwd, { pattern: "NTUSER", which: "filelist", partition: "p2048" });
    assert.equal(r.code, 0, r.stderr + r.stdout);
    assert.match(r.stdout, /NTUSER\.DAT/);
    // Two disks: the caller says which, from a JSON list.
    await mkdir(join(cwd, "catalog", "Other.E01"), { recursive: true });
    await writeFile(join(cwd, "catalog", "Other.E01", "partitions.txt"), "\n");
    r = await runPy(join(tools, "catalog_search", "run.py"), cwd, { pattern: "x", which: "filelist" });
    assert.deepEqual(JSON.parse(r.stdout + r.stderr).candidates, ["Case4.E01", "Other.E01", "memdump.mem"], "several catalogues are a JSON list");

    r = await runPy(join(tools, "ioc_scan", "run.py"), cwd, { path: "work/nothing-here.txt", needles: "x" });
    assert.notEqual(r.code, 0);
    assert.deepEqual(JSON.parse(r.stdout), { error: "no such file", path: "work/nothing-here.txt" });
    r = await runPy(join(tools, "ioc_scan", "run.py"), cwd, { path: "work", needles: "x" });
    assert.match(JSON.parse(r.stdout).error, /a directory, not a file/);
    for (const lnk of [join(LIB, "lnk_parse", "run.py"), join(LIB, "..", "packs", "windows-forensics", "tools", "lnk_parse", "run.py")]) {
      r = await runPy(lnk, cwd, { path: "work/missing.lnk" });
      assert.deepEqual(JSON.parse(r.stdout), { error: "no such file", path: "work/missing.lnk" }, lnk);
    }
    r = await runPy(join(tools, "sqlite_query", "run.py"), cwd, { db_path: "work/x.db", query: "tables" });
    assert.notEqual(r.code, 0);
    assert.match(r.stdout, /"error": "need sql"/);
    assert.doesNotMatch(r.stdout + r.stderr, /Traceback/);
  });
});

test("icat_extract refuses an inode the catalogue lists only as a directory, and names a file's catalogued path", async () => {
  // Third CTF round: d/d 84284 (Edge's History directory) extracted as
  // EdgeHistory.db, 272 bytes of $INDEX_ROOT, then "file is not a database".
  const tool = join(LIB, "..", "packs", "computer-forensics-base", "tools", "icat_extract", "run.py");
  await withCwd(async (cwd, bin) => {
    await rm(join(cwd, "inputs", "Webserver.E01"));
    await mkdir(join(cwd, "catalog", "AF-Case2.E01", "p2048"), { recursive: true });
    await writeFile(join(cwd, "catalog", "AF-Case2.E01", "partitions.txt"), "002:  000:000   0000002048   ...   NTFS\n");
    await writeFile(
      join(cwd, "catalog", "AF-Case2.E01", "p2048", "filelist.txt"),
      [
        "d/d 84284-144-1:\tUsers/IEUser/AppData/Local/Packages/Edge/AC/MicrosoftEdge/History",
        "r/r 87381-128-1:\tUsers/IEUser/AppData/Local/Microsoft/Windows/AppCache/container.dat",
        "r/r * 842840-128-4(realloc):\tUsers/x/other.etl",
        "",
      ].join("\n"),
    );
    let r = await runPy(tool, cwd, { inode: 84284, output: "work/EdgeHistory.db" }, bin);
    assert.notEqual(r.code, 0);
    const refused = JSON.parse(r.stdout) as { error: string; path: string };
    assert.match(refused.error, /inode 84284 is a directory/);
    assert.equal(refused.path, "Users/IEUser/AppData/Local/Packages/Edge/AC/MicrosoftEdge/History");
    r = await runPy(tool, cwd, { inode: 87381, output: "work/container.dat" }, bin);
    assert.equal(r.code, 0, r.stderr + r.stdout);
    assert.equal((JSON.parse(r.stdout) as { catalog_path: string }).catalog_path, "Users/IEUser/AppData/Local/Microsoft/Windows/AppCache/container.dat");
    // An attribute named on purpose is the caller's call.
    r = await runPy(tool, cwd, { inode: "84284-144-1", output: "work/index.bin" }, bin);
    assert.equal(r.code, 0, r.stderr + r.stdout);
  });
});

// The catalogue grows while a run goes on: generations under catalog/gen/,
// each change a numbered revision. A search names the revision it read, a
// generation is named by its id, an archive's member list is `members`, and
// the catalogue's own directories are never taken for a catalogue.
test("catalog_search reads a revision's generations, an archive's members, and names the revision it read", async () => {
  const script = join(LIB, "..", "packs", "computer-forensics-base", "tools", "catalog_search", "run.py");
  await withCwd(async (cwd) => {
    const C = join(cwd, "catalog");
    await mkdir(join(C, "disk.E01", "p0"), { recursive: true });
    await writeFile(join(C, "disk.E01", "partitions.txt"), "No partition table\n");
    await writeFile(join(C, "disk.E01", "p0", "filelist.txt"), "r/r 5: Users/a/NTUSER.DAT\n");
    await mkdir(join(C, "gen", "g0001"), { recursive: true });
    await writeFile(join(C, "gen", "g0001", "members.tsv"), "n\ttype\tpath\n0\tfile\tprivate/var/mobile/sms.db\n1\tfile\tother\n");
    for (const n of ["0", "1"]) await mkdir(join(C, "revisions", n), { recursive: true });
    await writeFile(join(C, "revisions", "0", "index.json"), JSON.stringify({ revision: 0, generations: [] }));
    await writeFile(join(C, "revisions", "0", "MANIFEST.json"), "{}");
    await writeFile(join(C, "revisions", "1", "index.json"), JSON.stringify({ revision: 1, generations: [{ id: "g0001" }] }));
    await writeFile(join(C, "revisions", "1", "MANIFEST.json"), "{}");
    // A revision still being written (no MANIFEST yet) is not read.
    await mkdir(join(C, "revisions", "2"), { recursive: true });
    await mkdir(join(C, "probes", "x"), { recursive: true });
    let r = await runPy(script, cwd, { pattern: "ntuser" });
    assert.equal(r.code, 0, r.stderr + r.stdout);
    let got = JSON.parse(r.stdout);
    assert.equal(got.hits[0].line, "r/r 5: Users/a/NTUSER.DAT", "gen/, revisions/ and probes/ are not catalogues");
    assert.equal(got.revision, 1, "the newest complete revision");
    r = await runPy(script, cwd, { pattern: "sms", which: "members", catalog: "g0001" });
    assert.equal(r.code, 0, r.stderr + r.stdout);
    got = JSON.parse(r.stdout);
    assert.equal(got.matched, 1);
    assert.equal(got.file, "catalog/gen/g0001/members.tsv");
    r = await runPy(script, cwd, { pattern: "sms", which: "members", catalog: "g0001", revision: 0 });
    assert.notEqual(r.code, 0, "a generation the pinned revision does not list is not read");
    assert.deepEqual(JSON.parse(r.stdout + r.stderr).candidates, ["disk.E01"]);
    r = await runPy(script, cwd, { pattern: "x", revision: 2 });
    assert.match(JSON.parse(r.stdout + r.stderr).error, /no complete revision 2/);
  });
});
