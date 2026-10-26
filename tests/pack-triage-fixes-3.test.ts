/**
 * triage-collection: the findings of the second independent review of the collection-intake recipe and the manifest tools, one
 * test per finding. Every test here fails on the code it replaced (TRIAGE_TOOLS names another copy of the tools and TRIAGE_RECIPE
 * another copy of the recipe, to show it):
 *   - a gzip tar whose CRC-32 is wrong was `complete` (the check was never made);
 *   - a second stream or garbage after a bzip2 or xz stream was `complete`;
 *   - one decompress call, or one tar metadata record, held gigabytes in memory (a 3 KB .tbz2 killed a 1 GiB process);
 *   - a directory merely named `uploads` or `[root]` anywhere in the path exempted an unopened nested archive;
 *   - a zip with another archive in front of it, or bytes after its end record, was `complete`;
 *   - a digest of a credential store nested deeper than eight levels was printed;
 *   - a binary-looking record kept 4 KiB of its head in memory for every member;
 *   - a tar whose end-marker block was damaged (not zero) was `complete`;
 *   - a digest in a path column of a credential-store row was printed;
 *   - verify called every delivered file `unexpected` against a record that was not read whole;
 *   - coverage said `no_file_and_no_record` for a question whose records were not all read.
 * Every digest here is of a made-up byte string; nothing is read back from a tool to build a fixture.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { runPySnippet } from "./tool-library-harness.ts";
import { KAPE_COPY_HEADER, TOOLS, TRIAGE, body, filesUnder, kapeCopyRow, put, tableRows, tool, uac3, withCwd } from "./pack-triage-harness.ts";
import type { Json } from "./pack-triage-harness.ts";

const RECIPE = process.env.TRIAGE_RECIPE ?? join(TRIAGE, "recipes", "collection-intake", "run.py");
const PARSE = join(TOOLS, "collection_manifest_parse", "run.py");
const VERIFY = join(TOOLS, "collection_manifest_verify", "run.py");
const COVER = join(TOOLS, "collection_coverage", "run.py");
const digest = (algorithm: string, data: string | Buffer) => createHash(algorithm).update(data).digest("hex");

async function recipe(args: string[], cwd: string, env: Record<string, string> = {}): Promise<{ code: number | null; stdout: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn("python3", [RECIPE, ...args], { cwd, env: { ...process.env, ...env } });
    const out: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => out.push(c));
    child.stderr.on("data", (c: Buffer) => out.push(c));
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stdout: Buffer.concat(out).toString("utf8") }));
  });
}

const target = (p: string) => JSON.stringify({ paths: [p] });
const cov = async (cwd: string, out: string): Promise<Json> => JSON.parse(await readFile(join(cwd, out, "coverage.json"), "utf8"));
const jsonl = async (path: string): Promise<Json[]> => (await readFile(path, "utf8")).trim().split("\n").filter(Boolean).map((l) => JSON.parse(l));

/** Run the recipe on a file and say how much memory the process held at most (the recipe is the only child). */
const RSS = `
import json, resource, subprocess, sys
recipe, verb, target, out = sys.argv[1:5]
args = [sys.executable, recipe, verb, "--target", target] + (["--out", out] if verb == "run" else [])
p = subprocess.run(args, capture_output=True, text=True)
peak = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
print(json.dumps({"code": p.returncode, "peak_mb": peak / (1 << 20 if sys.platform == "darwin" else 1 << 10), "stdout": p.stdout[:400]}))
`;
async function measured(verb: string, path: string, cwd: string, out = "o", env: Record<string, string> = {}): Promise<{ code: number; peak_mb: number; stdout: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn("python3", ["-c", RSS, RECIPE, verb, target(path), join(cwd, out)], { cwd, env: { ...process.env, ...env } });
    const out_: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => out_.push(c));
    child.stderr.on("data", (c: Buffer) => out_.push(c));
    child.on("error", reject);
    child.on("close", () => {
      try {
        resolve(JSON.parse(Buffer.concat(out_).toString("utf8")));
      } catch (e) {
        reject(new Error(Buffer.concat(out_).toString("utf8")));
      }
    });
  });
}

const BUILD = `
import sys, json, io, tarfile, zipfile, gzip, bz2, lzma, struct, base64
spec = json.load(sys.stdin)
def member(name, data, typ=None):
    data = data.encode() if isinstance(data, str) else data
    ti = tarfile.TarInfo(name); ti.size = len(data)
    if typ: ti.type = typ
    return ti.tobuf(tarfile.USTAR_FORMAT) + data + b"\\0" * (-len(data) % 512)
def plain(members, end_blocks=2):
    return b"".join(member(n, d) for n, d in members) + b"\\0" * (512 * end_blocks)
def wrap(kind, data):
    return {"tar": lambda d: d, "tgz": gzip.compress, "tbz2": bz2.compress, "txz": lzma.compress}[kind](data)
kind, path, members = spec["kind"], spec["path"], spec.get("members", [])
if kind in ("tar", "tgz", "tbz2", "txz"):
    data = wrap(kind, plain(members, spec.get("end_blocks", 2)))
    how = spec.get("mutate")
    if how == "gz_crc":
        data = bytearray(data); data[-8] ^= 1; data = bytes(data)
    elif how == "gz_stored_flip":
        # a stored deflate block holds the bytes as they are: one flipped bit in a member's data leaves the stream valid and the CRC-32 wrong
        raw = gzip.compress(plain(members), compresslevel=0)
        at = raw.index(b"aaaa"); data = bytearray(raw); data[at] ^= 0x20; data = bytes(data)
    elif how == "append_stream":
        data += wrap(kind, plain(spec["append"]))
    elif how == "append_bytes":
        data += bytes(spec["bytes"])
    elif how == "append_zeros":
        data += b"\\0" * spec["zeros"]
    open(path, "wb").write(data)
elif kind == "damaged_end":
    # the block where the end marker should be is not a header and not zero (a damaged header), then the zero blocks
    open(path, "wb").write(plain(members, 0) + bytes([1]) * 512 + b"\\0" * 1024)
elif kind == "cut_header":
    open(path, "wb").write(gzip.compress(plain(members)[:spec["keep"]]))
elif kind == "meta":
    # a pax header that declares spec["bytes"] bytes of metadata, followed by that many zero bytes
    ti = tarfile.TarInfo("x"); ti.type = tarfile.XHDTYPE; ti.size = spec["bytes"]
    open(path, "wb").write(gzip.compress(ti.tobuf(tarfile.USTAR_FORMAT) + bytes(spec["bytes"]) + plain(members)))
elif kind == "bomb_tbz2":
    c = bz2.BZ2Compressor(); f = open(path, "wb")
    ti = tarfile.TarInfo("zeros.bin"); ti.size = spec["bytes"]
    f.write(c.compress(ti.tobuf(tarfile.USTAR_FORMAT)))
    chunk = bytes(1 << 22); left = spec["bytes"]
    while left > 0:
        n = min(left, len(chunk)); f.write(c.compress(chunk[:n])); left -= n
    f.write(c.compress(bytes(-spec["bytes"] % 512 + 1024))); f.write(c.flush()); f.close()
elif kind == "zip":
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for entry in members:
            name, data = entry[0], entry[1]
            z.writestr(name, base64.b64decode(entry[2]) if len(entry) > 2 else data)
elif kind == "zip_joined":
    first, second = io.BytesIO(), io.BytesIO()
    for buf, ms in ((first, spec["first"]), (second, members)):
        with zipfile.ZipFile(buf, "w") as z:
            for name, data in ms: z.writestr(name, data)
    open(path, "wb").write(first.getvalue() + second.getvalue() if spec["order"] == "first_then_second" else second.getvalue() + first.getvalue())
elif kind == "zip_trailing":
    with zipfile.ZipFile(path, "w") as z:
        for name, data in members: z.writestr(name, data)
    open(path, "ab").write(b"X" * 20)
elif kind == "zip_gap":
    with zipfile.ZipFile(path, "w") as z:
        for i, (name, data) in enumerate(members):
            if i == 1:
                z.fp.write(b"JUNK" * 8); z.start_dir = z.fp.tell()          # the writer carries on after the bytes it did not write itself
            z.writestr(name, data)
elif kind == "zip_many":
    with zipfile.ZipFile(path, "w", zipfile.ZIP_STORED) as z:
        for i in range(spec["count"]): z.writestr("d%d/uac.log" % i, bytes(4096))
`;

async function build(spec: Json): Promise<void> {
  const run = await runPySnippet(BUILD, [], spec);
  assert.equal(run.code, 0, run.stderr);
}

const sha1Row = (name: string, data: string) => kapeCopyRow(`C:\\${name}`, `D:\\o\\C\\${name}`, data.length).replace("da39a3ee5e6b4b0d3255bfef95601890afd80709", digest("sha1", data));
const COPY_LOG = `${KAPE_COPY_HEADER}\n${sha1Row("a.txt", "aaaa")}\n${sha1Row("b.txt", "bbbb")}\n`;
const KAPE_MEMBERS: Array<[string, string]> = [["K/2026_CopyLog.csv", COPY_LOG], ["K/C/a.txt", "aaaa"], ["K/C/b.txt", "bbbb"]];
const SECOND: Array<[string, string]> = [["K2/2027_CopyLog.csv", COPY_LOG]];

async function runOn(cwd: string, name: string, path: string): Promise<Json> {
  const run = await recipe(["run", "--target", target(path), "--out", `o_${name}`], cwd);
  assert.equal(run.code, 0, `${name}: ${run.stdout}`);
  return cov(cwd, `o_${name}`);
}

// ---- R2-P1-1: the gzip CRC-32 --------------------------------------------------------------------------------------------------

test("recipe: a gzip tar whose CRC-32 is wrong is partial, however the damage came about; a whole one is complete", async () => {
  await withCwd(async (cwd) => {
    await build({ kind: "tgz", path: join(cwd, "ok.tgz"), members: KAPE_MEMBERS });
    assert.equal((await runOn(cwd, "ok", join(cwd, "ok.tgz"))).status, "complete");
    await build({ kind: "tgz", path: join(cwd, "crc.tgz"), members: KAPE_MEMBERS, mutate: "gz_crc" });
    const crc = await runOn(cwd, "crc", join(cwd, "crc.tgz"));
    assert.equal(crc.status, "partial", crc.status_basis);
    assert.match(crc.status_basis, /gzip CRC-32 is not that of the bytes the stream returned/);
    // one flipped bit in the data of a member of a stored deflate stream: the stream stays valid, only the CRC-32 can tell
    await build({ kind: "tgz", path: join(cwd, "flip.tgz"), members: KAPE_MEMBERS, mutate: "gz_stored_flip" });
    const flip = await runOn(cwd, "flip", join(cwd, "flip.tgz"));
    assert.equal(flip.status, "partial", flip.status_basis);
    assert.match(flip.status_basis, /CRC-32/);
    const detect = await recipe(["detect", "--target", target(join(cwd, "crc.tgz"))], cwd);
    assert.equal(detect.code, 0, detect.stdout);
    assert.match(JSON.parse(detect.stdout).listing_note, /CRC-32/, "detect carries the note");
  });
});

// ---- R2-P1-2: a second stream, or garbage, after a bzip2 or xz stream ---------------------------------------------------------

test("recipe: a second stream or garbage after a bzip2 or xz stream is partial; xz padding of zero bytes is not", async () => {
  await withCwd(async (cwd) => {
    for (const kind of ["tbz2", "txz"]) {
      const word = kind === "tbz2" ? "bzip2" : "xz";
      await build({ kind, path: join(cwd, `second.${kind}`), members: KAPE_MEMBERS, mutate: "append_stream", append: SECOND });
      const second = await runOn(cwd, `second_${kind}`, join(cwd, `second.${kind}`));
      assert.equal(second.status, "partial", `${kind} + a second stream: ${second.status_basis}`);
      assert.match(second.status_basis, new RegExp(`follow the ${word} stream`));
      await build({ kind, path: join(cwd, `junk.${kind}`), members: KAPE_MEMBERS, mutate: "append_bytes", bytes: [97, 98, 99] });
      const junk = await runOn(cwd, `junk_${kind}`, join(cwd, `junk.${kind}`));
      assert.equal(junk.status, "partial", `${kind} + garbage: ${junk.status_basis}`);
      const detect = await recipe(["detect", "--target", target(join(cwd, `junk.${kind}`))], cwd);
      assert.match(JSON.parse(detect.stdout).listing_note, /follow the/, `${kind}: detect carries the note`);
    }
    await build({ kind: "txz", path: join(cwd, "pad.txz"), members: KAPE_MEMBERS, mutate: "append_zeros", zeros: 8 });
    assert.equal((await runOn(cwd, "pad", join(cwd, "pad.txz"))).status, "complete", "xz stream padding is legal");
    await build({ kind: "txz", path: join(cwd, "pad5.txz"), members: KAPE_MEMBERS, mutate: "append_zeros", zeros: 5 });
    assert.equal((await runOn(cwd, "pad5", join(cwd, "pad5.txz"))).status, "partial", "padding that is not a multiple of four bytes is not padding");
  });
});

// ---- R2-P1-3: memory and the clock inside one decompress call or one metadata record -----------------------------------------

test("recipe: a few hundred bytes of bzip2 that expand to half a gigabyte are read in steps (the memory stays small)", { timeout: 300000 }, async () => {
  await withCwd(async (cwd) => {
    const path = join(cwd, "bomb.tbz2");
    await build({ kind: "bomb_tbz2", path, bytes: 512 * 1024 * 1024 });
    const ran = await measured("run", path, cwd, "o_bomb", { RECIPE_SECONDS: "600" });
    assert.equal(ran.code, 0, ran.stdout);
    assert.ok(ran.peak_mb < 200, `peak memory ${ran.peak_mb} MB`);
    const detect = await measured("detect", path, cwd, "o_d");
    assert.ok(detect.peak_mb < 200, `detect: peak memory ${detect.peak_mb} MB`);
  });
});

test("recipe: a tar metadata record over the bound is refused before it is read; detect says it could not tell", async () => {
  await withCwd(async (cwd) => {
    const path = join(cwd, "meta.tgz");
    await build({ kind: "meta", path, bytes: 2 * 1024 * 1024, members: KAPE_MEMBERS });
    const detect = await recipe(["detect", "--target", target(path)], cwd);
    assert.equal(detect.code, 2, detect.stdout);
    assert.match(JSON.parse(detect.stdout).why, /metadata record of 2097152 bytes, over the bound/);
    const run = await recipe(["run", "--target", target(path), "--out", "o_meta"], cwd);
    assert.equal(run.code, 2, run.stdout);
    assert.equal((await cov(cwd, "o_meta")).status, "failed");
    // a record under the bound is read: a long path in a pax header
    const ok = join(cwd, "long.tgz");
    await build({ kind: "tgz", path: ok, members: [["K/2026_CopyLog.csv", COPY_LOG], ["K/C/" + "d/".repeat(120) + "a.txt", "aaaa"]] });
    assert.equal((await recipe(["detect", "--target", target(ok)], cwd)).code, 0);
  });
});

// ---- R2-P3: the end-of-archive marker is a zero block --------------------------------------------------------------------------

test("recipe: a damaged block where the tar's end marker should be is partial, not complete", async () => {
  await withCwd(async (cwd) => {
    await build({ kind: "damaged_end", path: join(cwd, "dmg.tar"), members: KAPE_MEMBERS });
    const c = await runOn(cwd, "dmg", join(cwd, "dmg.tar"));
    assert.equal(c.status, "partial", c.status_basis);
    assert.match(c.status_basis, /end-of-archive marker should start is not zero/);
    const detect = await recipe(["detect", "--target", target(join(cwd, "dmg.tar"))], cwd);
    assert.match(JSON.parse(detect.stdout).listing_note, /not zero/);
  });
});

test("recipe detect: a tar cut before its first header is 'could not tell', not 'does not apply'", async () => {
  await withCwd(async (cwd) => {
    await build({ kind: "cut_header", path: join(cwd, "cut.tgz"), members: KAPE_MEMBERS, keep: 100 });
    const detect = await recipe(["detect", "--target", target(join(cwd, "cut.tgz"))], cwd);
    assert.equal(detect.code, 2, detect.stdout);
    assert.match(JSON.parse(detect.stdout).why, /could not tell/);
  });
});

// ---- R2-P2-1: the nested-archive exemption is by a collector's layout, not by a directory's name ----------------------------------

const INNER: Array<[string, string]> = [["K/2026_CopyLog.csv", COPY_LOG]];

async function innerZip(cwd: string): Promise<string> {
  await build({ kind: "zip", path: join(cwd, "inner.zip"), members: INNER });
  return (await readFile(join(cwd, "inner.zip"))).toString("base64");
}

test("recipe: a directory named uploads or [root] that is not a collector's own does not exempt an archive inside the archive", async () => {
  await withCwd(async (cwd) => {
    const inner = await innerZip(cwd);
    const kape = (extra: string) => [["K/2026_CopyLog.csv", COPY_LOG], ["K/C/a.txt", "aaaa"], ["K/C/b.txt", "bbbb"], [extra, "", inner]];
    for (const [name, where] of [["uploads", "K/case/uploads/hostB_kape.zip"], ["root", "K/[root]/hostB.zip"], ["top_uploads", "uploads/hostB.zip"]]) {
      await build({ kind: "zip", path: join(cwd, `${name}.zip`), members: kape(where) });
      const c = await runOn(cwd, name, join(cwd, `${name}.zip`));
      assert.equal(c.status, "partial", `${where}: ${c.status_basis}`);
      assert.equal(c.nested_archives_not_opened_and_not_collected_files_total, 1, where);
      assert.match(c.status_basis, /archive\(s\) inside the archive were not opened and may hold records/);
    }
    // a collector's own layout: a Velociraptor container's uploads directory, a UAC run's [root], and a file a record names
    const velo = [["V/collection_context.json", "{}"], ["V/uploads.json", JSON.stringify({ vfs_path: "auto/C%3A/a.txt", file_size: 4, uploaded_size: 4 }) + "\n"],
      ["V/uploads/auto/C%3A/a.txt", "aaaa"], ["V/uploads/auto/C%3A/Users/a/data.zip", "", inner]];
    await build({ kind: "zip", path: join(cwd, "velo.zip"), members: velo });
    const v = await runOn(cwd, "velo", join(cwd, "velo.zip"));
    assert.equal(v.nested_archives_total, 1);
    assert.equal(v.nested_archives_not_opened_and_not_collected_files_total, 0, "below a Velociraptor container's uploads directory");
    const uac = [["U/uac.log", `${uac3("INF", "start")}\n`], ["U/[root]/var/backups/old.zip", "", inner], ["U/hash_executables/hash_executables.md5", `${"a".repeat(32)}  /bin/x\n`]];
    await build({ kind: "zip", path: join(cwd, "uac.zip"), members: uac });
    const u = await runOn(cwd, "uac", join(cwd, "uac.zip"));
    assert.equal(u.nested_archives_not_opened_and_not_collected_files_total, 0, "below the [root] of a UAC run");
    assert.match(u.status_basis, /below the \[root\] of a UAC run, below the uploads directory of a Velociraptor container, or named by a record/);
  });
});

// ---- R2-P2-2: a zip with something before, between or after its members -----------------------------------------------------------

test("recipe: a zip with another archive in front, bytes between members or bytes after its end record is partial", async () => {
  await withCwd(async (cwd) => {
    await build({ kind: "zip", path: join(cwd, "ok.zip"), members: KAPE_MEMBERS });
    assert.equal((await runOn(cwd, "ok", join(cwd, "ok.zip"))).status, "complete");
    for (const order of ["first_then_second", "second_then_first"]) {
      await build({ kind: "zip_joined", path: join(cwd, `${order}.zip`), members: KAPE_MEMBERS, first: SECOND, order });
      const c = await runOn(cwd, order, join(cwd, `${order}.zip`));
      assert.equal(c.status, "partial", `${order}: ${c.status_basis}`);
      assert.match(c.status_basis, /byte\(s\) come before the first member/, order);
    }
    await build({ kind: "zip_trailing", path: join(cwd, "trailing.zip"), members: KAPE_MEMBERS });
    const trailing = await runOn(cwd, "trailing", join(cwd, "trailing.zip"));
    assert.equal(trailing.status, "partial", trailing.status_basis);
    assert.match(trailing.status_basis, /20 byte\(s\) follow the zip's end record/);
    await build({ kind: "zip_gap", path: join(cwd, "gap.zip"), members: KAPE_MEMBERS });
    const gap = await runOn(cwd, "gap", join(cwd, "gap.zip"));
    assert.equal(gap.status, "partial", gap.status_basis);
    assert.match(gap.status_basis, /32 byte\(s\) lie between the member/);
    const detect = await recipe(["detect", "--target", target(join(cwd, "first_then_second.zip"))], cwd);
    assert.match(JSON.parse(detect.stdout).listing_note, /come before the first member/);
  });
});

// ---- R2-P2-3: no depth below which a digest of a credential store is printed ---------------------------------------------------------

const SAM_BYTES = "regf-sam-hive-of-the-source-host";
const SAM_SHA256 = digest("sha256", SAM_BYTES);
const DEEP = (levels: number, leaf: string): Json => {
  let value: Json = { sha256: leaf };
  for (let i = 0; i < levels; i++) value = { [`n${i}`]: value };
  return value;
};

test("parse and the recipe: the digest of a credential store is withheld however deep it is nested in the record's fields", async () => {
  await withCwd(async (cwd) => {
    for (const levels of [8, 9, 14, 60]) {
      const row = JSON.stringify({ Upload: { Path: "C:\\Windows\\System32\\config\\SAM", Size: SAM_BYTES.length, StoredSize: SAM_BYTES.length, StoredName: "auto/C%3A/SAM", ...DEEP(levels, SAM_SHA256) } });
      const results = `${row}\n`;
      await put(cwd, `inputs/v${levels}/collection_context.json`, "{}");
      await put(cwd, `inputs/v${levels}/uploads/auto/C%3A/SAM`, SAM_BYTES);
      await put(cwd, `inputs/v${levels}/results/Windows.KapeFiles.Targets.json`, results);
      const run = await tool(PARSE, cwd, { root: `inputs/v${levels}` });
      const out = body(run);
      const rows = await tableRows(cwd, out.tables.records);
      assert.ok(!run.stdout.includes(SAM_SHA256) && !JSON.stringify(rows).includes(SAM_SHA256), `${levels} levels: the digest is in the parse output`);
      assert.match(JSON.stringify(rows), /withheld, 64 characters/, `${levels} levels`);
      await build({ kind: "zip", path: join(cwd, `v${levels}.zip`), members: [[`v/collection_context.json`, "{}"], [`v/results/Windows.KapeFiles.Targets.json`, results], ["v/uploads/auto/C%3A/SAM", SAM_BYTES]] });
      const ran = await recipe(["run", "--target", target(join(cwd, `v${levels}.zip`)), "--out", `o_v${levels}`], cwd);
      assert.equal(ran.code, 0, ran.stdout);
      const text = (await Promise.all((await readdir(join(cwd, `o_v${levels}`))).map((f) => readFile(join(cwd, `o_v${levels}`, f), "utf8")))).join("\n");
      assert.ok(!text.includes(SAM_SHA256), `${levels} levels: the digest is in the recipe's outputs`);
    }
  });
});

// ---- R2-P2-4: no per-member head kept for a record refused as binary ---------------------------------------------------------------

test("recipe: 30,000 binary-looking records keep no head each (the memory stays near a run over small members)", { timeout: 300000 }, async () => {
  await withCwd(async (cwd) => {
    await build({ kind: "zip_many", path: join(cwd, "many.zip"), count: 30000 });
    const ran = await measured("run", join(cwd, "many.zip"), cwd, "o_many", { RECIPE_SECONDS: "600" });
    assert.equal(ran.code, 0, ran.stdout);
    assert.ok(ran.peak_mb < 160, `peak memory ${ran.peak_mb} MB`);
  });
});

test("recipe: a delivery of many members stops, partial and with JSON, at 60% of the memory the process may hold", { timeout: 300000 }, async () => {
  await withCwd(async (cwd) => {
    await build({ kind: "zip_many", path: join(cwd, "many.zip"), count: 30000 });
    const run = await recipe(["run", "--target", target(join(cwd, "many.zip")), "--out", "o_mem"], cwd, { COLLECTION_INTAKE_MEMORY_BYTES: String(120 * 1024 * 1024), RECIPE_SECONDS: "600" });
    assert.equal(run.code, 0, run.stdout);
    const c = await cov(cwd, "o_mem");
    assert.equal(c.status, "partial");
    assert.match(c.status_basis, /the memory bound \(\d+ MB held of the 120 MB this process may hold\)/);
    assert.ok(c.members > 0 && c.members < 30000, `${c.members} members were read`);
    const detect = await recipe(["detect", "--target", target(join(cwd, "many.zip"))], cwd, { COLLECTION_INTAKE_MEMORY_BYTES: String(20 * 1024 * 1024) });
    assert.equal(detect.code, 0, detect.stdout);
    assert.match(JSON.parse(detect.stdout).listing_note, /the memory bound/);
  });
});

// ---- P3: a digest in a path column; verify and coverage over a record that was not read whole -------------------------------------

test("parse and recipe: a short row of a credential store that puts the digest in a path column prints no digest", async () => {
  await withCwd(async (cwd) => {
    const sha1 = digest("sha1", SAM_BYTES);
    const log = `${KAPE_COPY_HEADER},Note\n2026-02-14 09:12:00.123,C:\\Windows\\System32\\config\\SAM,${sha1}\n` +
      `${kapeCopyRow("C:\\Windows\\System32\\config\\SAM", "D:\\o\\C\\Windows\\System32\\config\\SAM", SAM_BYTES.length)},${sha1}\n`;
    await put(cwd, "inputs/k/r_CopyLog.csv", log);
    const run = await tool(PARSE, cwd, { root: "inputs/k" });
    const out = body(run);
    const rows = await tableRows(cwd, out.tables.records);
    assert.ok(!run.stdout.includes(sha1) && !JSON.stringify(rows).includes(sha1), "the sha1 of the SAM hive is printed by parse");
    await build({ kind: "zip", path: join(cwd, "k.zip"), members: [["k/r_CopyLog.csv", log]] });
    assert.equal((await recipe(["run", "--target", target(join(cwd, "k.zip")), "--out", "o_k"], cwd)).code, 0);
    const text = (await Promise.all((await readdir(join(cwd, "o_k"))).map((f) => readFile(join(cwd, "o_k", f), "utf8")))).join("\n");
    assert.ok(!text.includes(sha1), "the sha1 of the SAM hive is in the recipe's outputs");
  });
});

test("verify: a file is not called unexpected against a record that was not read whole; against one that was, it is", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/k/C/a.txt", "aaaa");
    await put(cwd, "inputs/k/C/stray.txt", "stray");
    await put(cwd, "inputs/k/r_CopyLog.csv", `${KAPE_COPY_HEADER}\n${sha1Row("a.txt", "aaaa")}\n`);
    const whole = body(await tool(VERIFY, cwd, { root: "inputs/k" }));
    assert.equal(whole.by_status.unexpected, 1);
    assert.equal(whole.denominators.delivered_files_not_decided_the_record_was_not_read_whole, 0);
    // a UTF-16 copy log is not read at all: no file can be called unexpected against it
    await put(cwd, "inputs/u/C/a.txt", "aaaa");
    await put(cwd, "inputs/u/C/stray.txt", "stray");
    await put(cwd, "inputs/u/r_CopyLog.csv", Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(`${KAPE_COPY_HEADER}\n`, "utf16le")]));
    const cut = body(await tool(VERIFY, cwd, { root: "inputs/u" }));
    assert.equal(cut.status, "partial");
    assert.equal(cut.by_status.unexpected, 0, "the record was not read");
    assert.equal(cut.denominators.delivered_files_not_decided_the_record_was_not_read_whole, 2);
  });
});

test("coverage: a question over records that were not all read has the state no_file_and_no_record_read and a statement that agrees with `requested`", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/u/C/a.txt", "a");
    await put(cwd, "inputs/u/r_CopyLog.csv", `${KAPE_COPY_HEADER}\n${kapeCopyRow("C:\\a.txt", "D:\\o\\C\\a.txt", 1)}\n`);   // a KAPE run with no skip log
    const out = body(await tool(COVER, cwd, { root: "inputs/u", questions: [{ id: "q", source_paths: ["*zzz*"] }], requested: ["c:/zzz/*"] }));
    assert.equal(out.requested[0].state, "unknown_records_unread");
    const q = out.questions[0];
    assert.ok(!q.state.includes("no_file_and_no_record"), JSON.stringify(q.state));
    assert.ok(q.state.includes("no_file_and_no_record_read") && q.state.includes("some_records_unreadable"), JSON.stringify(q.state));
    assert.doesNotMatch(q.statement, /The delivery holds nothing under these patterns/);
    assert.match(q.statement, /No delivered file matches and no record that was read mentions these patterns; some collector records could not be read whole/);
  });
});

test("the coverage skill names the new state", async () => {
  const skill = await readFile(join(TRIAGE, "skills", "coverage", "delivered-collection.md"), "utf8");
  assert.match(skill, /no_file_and_no_record_read/);
  assert.ok((await filesUnder(join(TRIAGE, "recipes", "collection-intake"))).includes("run.py"));
});
