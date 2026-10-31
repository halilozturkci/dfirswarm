/**
 * triage-collection, the collection-intake recipe: what its archive checks say they check.
 *   - An archive inside the archive is found by its first bytes (zip, tar, gzip, bzip2, xz, 7z, rar or cab magic) whatever its suffix: a `.dat`
 *     member that starts `PK\x03\x04` is named, and the run is partial where it may hold records. A zip-based document or package (docx, xlsx,
 *     pptx, odt, jar, apk and the like) is a zip by its bytes: it is listed (`document_or_package`) and does not by itself make the run partial.
 *     A collected file below a recognised layout, or one a record names as delivered, still does not make it partial.
 *   - A tar that ends with one zero block is accepted (GNU tar does, with a warning) and noted; two is the standard.
 * The members are built from the formats' own definitions: the signatures of each format, an OOXML package's [Content_Types].xml, a USTAR
 * header written by the standard library and cut or padded by hand.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { runPySnippet } from "./tool-library-harness.ts";
import { KAPE_COPY_HEADER, TRIAGE, kapeCopyRow, veloLogRow, veloResultRow, veloUploadsRow, withCwd } from "./pack-triage-harness.ts";
import type { Json } from "./pack-triage-harness.ts";

const RECIPE = join(TRIAGE, "recipes", "collection-intake", "run.py");
const digest = (algorithm: string, data: string | Buffer) => createHash(algorithm).update(data).digest("hex");

async function recipe(args: string[], cwd: string): Promise<{ code: number | null; stdout: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn("python3", [RECIPE, ...args], { cwd });
    const out: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => out.push(c));
    child.stderr.on("data", (c: Buffer) => out.push(c));
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stdout: Buffer.concat(out).toString("utf8") }));
  });
}
const target = (p: string) => JSON.stringify({ paths: [p] });

/** Every format's own signature, and a real container where the standard library writes one. Printed as JSON: name -> base64. */
const SAMPLES = `
import base64, bz2, gzip, io, json, lzma, tarfile, zipfile
out = {}
b = io.BytesIO()
with zipfile.ZipFile(b, "w") as z:
    z.writestr("inner/2026_run_CopyLog.csv", "x")
out["zip"] = b.getvalue()
out["gzip"] = gzip.compress(b"hello")
out["bzip2"] = bz2.compress(b"hello")
out["xz"] = lzma.compress(b"hello")
out["7z"] = b"7z\\xbc\\xaf\\x27\\x1c\\x00\\x04" + b"\\x00" * 24
out["rar"] = b"Rar!\\x1a\\x07\\x00" + b"\\x00" * 16
out["cab"] = b"MSCF\\x00\\x00\\x00\\x00" + b"\\x00" * 24
t = io.BytesIO()
with tarfile.open(fileobj=t, mode="w", format=tarfile.USTAR_FORMAT) as tf:
    info = tarfile.TarInfo("inner/x.txt"); info.size = 5
    tf.addfile(info, io.BytesIO(b"hello"))
out["tar"] = t.getvalue()
o = io.BytesIO()
with zipfile.ZipFile(o, "w") as z:                       # an OOXML package: a zip with [Content_Types].xml
    z.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>')
    z.writestr("word/document.xml", "<w:document/>")
out["ooxml"] = o.getvalue()
print(json.dumps({k: base64.b64encode(v).decode() for k, v in out.items()}))
`;

async function samples(): Promise<Record<string, Buffer>> {
  const run = await runPySnippet(SAMPLES, [], null);
  assert.equal(run.code, 0, run.stderr);
  return Object.fromEntries(Object.entries(JSON.parse(run.stdout) as Record<string, string>).map(([k, v]) => [k, Buffer.from(v, "base64")]));
}

const MAKE_ZIP = `
import base64, sys, zipfile, json
out, spec = sys.argv[1], json.loads(sys.argv[2])
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
    for name, data in spec:
        z.writestr(name, base64.b64decode(data))
`;
async function zip(path: string, members: Array<[string, Buffer | string]>): Promise<void> {
  const spec = members.map(([n, d]) => [n, Buffer.from(d).toString("base64")]);
  const run = await runPySnippet(MAKE_ZIP, [path, JSON.stringify(spec)], null);
  assert.equal(run.code, 0, run.stderr);
}

/** A KAPE copy log naming C:\\notes.txt ("hello"), and the file: a run that is complete when nothing else is wrong. */
const COPY = (() => {
  const row = kapeCopyRow("C:\\notes.txt", "D:\\o\\C\\notes.txt", 5).replace("da39a3ee5e6b4b0d3255bfef95601890afd80709", digest("sha1", "hello").toUpperCase());
  return `${KAPE_COPY_HEADER}\n${row}\n`;
})();
const BASE_MEMBERS: Array<[string, Buffer | string]> = [["2026_run_CopyLog.csv", COPY], ["C/notes.txt", "hello"]];

async function runOn(cwd: string, name: string): Promise<{ code: number | null; cov: Json }> {
  const run = await recipe(["run", "--target", target(join(cwd, name)), "--out", `out-${name}`], cwd);
  const cov = JSON.parse(await readFile(join(cwd, `out-${name}`, "coverage.json"), "utf8")) as Json;
  return { code: run.code, cov };
}

test("a member that holds archive magic is named as a nested archive whatever its suffix, and the run is partial", async () => {
  const s = await samples();
  await withCwd(async (cwd) => {
    await zip(join(cwd, "clean.zip"), BASE_MEMBERS);
    const clean = await runOn(cwd, "clean.zip");
    assert.equal(clean.cov.status, "complete", clean.cov.status_basis);
    for (const format of ["zip", "gzip", "bzip2", "xz", "7z", "rar", "cab", "tar"]) {
      for (const suffix of [".dat", "", ".bin"]) {
        const name = `with-${format}${suffix.replace(".", "-") || "-none"}.zip`;
        await zip(join(cwd, name), [...BASE_MEMBERS, [`data/blob${suffix}`, s[format]!]]);
        const { code, cov } = await runOn(cwd, name);
        assert.equal(code, 0);
        assert.equal(cov.status, "partial", `${format} in blob${suffix}: ${cov.status_basis}`);
        assert.equal(cov.nested_archives_total, 1, `${format}${suffix}`);
        assert.equal(cov.nested_archives[0].found_by, "bytes");
        assert.equal(cov.nested_archives[0].format, format);
        assert.equal(cov.nested_archives_not_opened_and_not_collected_files_total, 1);
        assert.match(cov.status_basis, /archive\(s\) inside the archive were not opened and may hold records/);
        const inventory = await readFile(join(cwd, `out-${name}`, "inventory.tsv"), "utf8");
        assert.match(inventory, new RegExp(`data/blob${suffix.replace(".", "\\.")}\\t.*an archive inside the archive, found by bytes \\(${format}\\)`), "the note is in inventory.tsv");
      }
    }
    // a suffix and the bytes agree
    await zip(join(cwd, "both.zip"), [...BASE_MEMBERS, ["data/inner.zip", s.zip!]]);
    assert.equal((await runOn(cwd, "both.zip")).cov.nested_archives[0].found_by, "suffix and bytes");
    // a member that is not an archive by its bytes, with a plain name, is not named
    await zip(join(cwd, "plain.zip"), [...BASE_MEMBERS, ["data/blob.dat", "just text, PK is not at the start"]]);
    assert.equal((await runOn(cwd, "plain.zip")).cov.status, "complete");
  });
});

// A USTAR archive with a member, cut after the member's data and given one or two zero blocks, as a tar writer or a hand does.
const MAKE_TAR = `
import io, sys, tarfile, hashlib
out, blocks = sys.argv[1], int(sys.argv[2])
buf = io.BytesIO()
rows = ("CopiedTimestamp,SourceFile,DestinationFile,FileSize,SourceFileSha1,DeferredCopy,CreatedOnUtc,ModifiedOnUtc,LastAccessedOnUtc,CopyDuration\\n"
        "2026-02-14 09:12:00.123,C:\\\\notes.txt,D:\\\\o\\\\C\\\\notes.txt,5," + hashlib.sha1(b"hello").hexdigest().upper() + ",False,2026-01-01 00:00:00.000,2026-01-02 03:04:05.678,2026-01-03 00:00:00.000,0.0123\\n").encode()
with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tf:
    for name, data in (("2026_run_CopyLog.csv", rows), ("C/notes.txt", b"hello")):
        info = tarfile.TarInfo(name); info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    end = tf.offset                                        # the end of the last member's data, padded to a block
data = buf.getvalue()[:end] + b"\\0" * 512 * blocks
open(out, "wb").write(data)
`;

test("a tar that ends with one zero block is read and noted, one with two is read and not noted", async () => {
  await withCwd(async (cwd) => {
    const results: Record<number, Json> = {};
    for (const blocks of [1, 2]) {
      const made = await runPySnippet(MAKE_TAR, [join(cwd, `t${blocks}.tar`), String(blocks)], null);
      assert.equal(made.code, 0, made.stderr);
      const detect = await recipe(["detect", "--target", target(join(cwd, `t${blocks}.tar`))], cwd);
      assert.equal(detect.code, 0, detect.stdout);
      const { code, cov } = await runOn(cwd, `t${blocks}.tar`);
      assert.equal(code, 0);
      assert.equal(cov.status, "complete", `${blocks} block(s): ${cov.status_basis}`);
      assert.equal(cov.members, 2);
      results[blocks] = cov;
    }
    assert.deepEqual(results[2]!.notes, [], "two blocks: no note");
    assert.equal(results[1]!.notes.length, 1, "one block: a note");
    assert.match(results[1]!.notes[0], /one zero block, not two/);
    // trailing garbage after the marker is still a problem
    const made = await runPySnippet(MAKE_TAR, [join(cwd, "t3.tar"), "2"], null);
    assert.equal(made.code, 0);
    const garbage = Buffer.concat([await readFile(join(cwd, "t3.tar")), Buffer.from("trailing garbage that is not zero")]);
    await (await import("node:fs/promises")).writeFile(join(cwd, "t4.tar"), garbage);
    const bad = await runOn(cwd, "t4.tar");
    assert.equal(bad.cov.status, "partial");
  });
});

test("the docstring, the message and the README say what the tar end check accepts and where it is tested", async () => {
  const text = await readFile(RECIPE, "utf8");
  assert.match(text, /two zero blocks is the standard; one is accepted, as GNU tar does, and noted in coverage\.json/);
  assert.match(text, /no end-of-archive marker \(two zero blocks is the standard and one is accepted, as GNU tar does\)/);
  assert.match(text, /CI runs the suites on Python 3\.12 \(Linux\) and 3\.14\s+\(macOS\), not on the 3\.11 of the analysis image/);
  assert.match(text, /on a Python without those internals the end is `unknown` and the run is partial/);
  const readme = (await readFile(join(TRIAGE, "README.md"), "utf8")).replace(/\s+/g, " ");
  assert.match(readme, /found by its first bytes/);
  assert.match(readme, /Python 3\.12 \(Linux\) and 3\.14 \(macOS\)/);
  assert.match(readme, /two zero blocks: one is accepted, as GNU tar does, and noted/);
});

test("an OOXML package is a zip by its bytes: collected below a recognised root it does not make the run partial, and outside one it is listed and not by itself a reason to be partial", async () => {
  const s = await samples();
  await withCwd(async (cwd) => {
    // below the uploads directory of a Velociraptor container
    const text = s.ooxml!;
    const sha = digest("sha256", text);
    const members: Array<[string, Buffer | string]> = [
      ["v/uploads.json", veloUploadsRow("auto/C:/Users/a/report.docx", text.length, text.length) + "\n"],
      ["v/uploads/auto/C%3A/Users/a/report.docx", text],
      ["v/results/A.json", veloResultRow("C:/Users/a/report.docx").replace("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9", sha) + "\n"],
      ["v/log.json", veloLogRow("INFO", "collection finished") + "\n"],
    ];
    await zip(join(cwd, "v.zip"), members);
    const velo = await runOn(cwd, "v.zip");
    assert.equal(velo.cov.nested_archives_total, 1, "the package is a zip by its bytes and is named");
    assert.equal(velo.cov.nested_archives[0].document_or_package, true);
    assert.equal(velo.cov.nested_archives_not_opened_and_not_collected_files_total, 0, "and it is a collected file, below the uploads directory");
    assert.doesNotMatch(String(velo.cov.status_basis), /archive\(s\) inside the archive were not opened/);
    // outside a recognised root, named like a document: listed, and not by itself a reason to be partial
    await zip(join(cwd, "doc.zip"), [...BASE_MEMBERS, ["Users/a/report.docx", text]]);
    const doc = await runOn(cwd, "doc.zip");
    assert.equal(doc.cov.nested_archives_zip_documents_and_packages_total, 1);
    assert.equal(doc.cov.nested_archives_not_opened_and_not_collected_files_total, 0);
    assert.equal(doc.cov.status, "complete", doc.cov.status_basis);
    // the same bytes under a name that is not a document's: a zip that may hold records
    await zip(join(cwd, "dat.zip"), [...BASE_MEMBERS, ["Users/a/report.dat", text]]);
    const dat = await runOn(cwd, "dat.zip");
    assert.equal(dat.cov.status, "partial");
    assert.equal(dat.cov.nested_archives_not_opened_and_not_collected_files_total, 1);
  });
});
