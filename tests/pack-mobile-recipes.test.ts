/**
 * The mobile pack's recipes, against archives the test builds from the formats' own layouts and stand-ins for
 * iLEAPP and ALEAPP that print what those programs print and write a report folder the way they do.
 *
 * Tar: Python's tarfile writes the archive (GNU format, so a name that is not UTF-8 is kept as bytes). An adb
 * backup is "ANDROID BACKUP\n", the version, the compression flag and the encryption scheme on their own lines,
 * then a tar, zlib-compressed when the flag says so; a member's content is streamed through the compressor, so
 * 300 MiB of zeros costs a few hundred KiB on disk.
 *
 * To see that a test fails on the code it was written against, point MOBILE_PACK at a copy of the pack as it
 * was before the fixes:
 *
 *   git archive edcfe913 packs/mobile-forensics | tar -x -C /tmp/old   # the pack as it was before these fixes (1.2.0)
 *   MOBILE_PACK=/tmp/old/packs/mobile-forensics node --experimental-strip-types --test tests/pack-mobile-recipes.test.ts
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { chmod, mkdir, readFile, readdir, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { ROOT, runPySnippet, withCwd } from "./tool-library-harness.ts";

const PACK = process.env.MOBILE_PACK ?? join(ROOT, "packs", "mobile-forensics");
const RECIPES = join(PACK, "recipes");

async function exists(path: string): Promise<boolean> {
  return stat(path).then(() => true, () => false);
}

/** Run a Python fixture builder; its argv follows the code. */
async function build(code: string, ...args: string[]): Promise<void> {
  const out = await runPySnippet(code, args, null);
  assert.equal(out.code, 0, out.stderr);
}

/** Every regular file under a directory (not following links), with its bytes. */
async function filesUnder(dir: string): Promise<{ path: string; data: Buffer }[]> {
  const found: { path: string; data: Buffer }[] = [];
  const walk = async (d: string): Promise<void> => {
    for (const entry of await readdir(d, { withFileTypes: true })) {
      const p = join(d, entry.name);
      if (entry.isDirectory()) await walk(p);
      else if (entry.isFile()) found.push({ path: p, data: await readFile(p) });
    }
  };
  await walk(dir);
  return found;
}

// --- the recipes ------------------------------------------------------------------------

type RecipeRun = { code: number | null; stdout: string; stderr: string };

function recipe(name: string, args: string[], cwd: string, env: Record<string, string> = {}, extraPath?: string): Promise<RecipeRun> {
  return new Promise((resolve, reject) => {
    const e = { ...process.env, ...env };
    if (extraPath) e.PATH = `${extraPath}:${e.PATH ?? ""}`;
    const child = spawn("python3", [join(RECIPES, name, "run.py"), ...args], { cwd, env: e });
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => out.push(c));
    child.stderr.on("data", (c: Buffer) => err.push(c));
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stdout: Buffer.concat(out).toString("utf8"), stderr: Buffer.concat(err).toString("utf8") }));
  });
}

const target = (path: string): string => JSON.stringify({ paths: [path] });

type Coverage = {
  recipe: string; status: string; covered: string; not_covered: string; limits_hit: string[]; errors: string[];
  modules?: { log_format_recognised: boolean; counts: Record<string, number>; records_reported_by_modules: number; tracebacks_on_stderr: number; report_layout: string; files_beside_the_report?: string; files_left_in_program_directories?: Record<string, number> };
  payload_stream?: string; tar_end?: string; decompressed_bytes?: number; categories?: Record<string, number>;
};

async function coverage(out: string): Promise<Coverage> {
  return JSON.parse(await readFile(join(out, "coverage.json"), "utf8")) as Coverage;
}

/** A recipe run under a wrapper that reports the peak resident memory (bytes) of the recipe's own process. */
const MEASURE = String.raw`
import resource, runpy, sys
script = sys.argv[1]
sys.argv = [script] + sys.argv[2:]
try:
    runpy.run_path(script, run_name="__main__")
except SystemExit as exit:
    code = exit.code
else:
    code = 0
usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
sys.stderr.write("MAXRSS %d\n" % (usage if sys.platform == "darwin" else usage * 1024))
sys.exit(code)
`;

async function measuredRecipe(name: string, args: string[], cwd: string, extraPath?: string): Promise<{ result: RecipeRun; maxrss: number }> {
  return new Promise((resolve, reject) => {
    const e = { ...process.env };
    if (extraPath) e.PATH = `${extraPath}:${e.PATH ?? ""}`;
    const child = spawn("python3", ["-c", MEASURE, join(RECIPES, name, "run.py"), ...args], { cwd, env: e });
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => out.push(c));
    child.stderr.on("data", (c: Buffer) => err.push(c));
    child.on("error", reject);
    child.on("close", (code) => {
      const stderr = Buffer.concat(err).toString("utf8");
      const m = /MAXRSS (\d+)/.exec(stderr);
      assert.ok(m, stderr);
      resolve({ result: { code, stdout: Buffer.concat(out).toString("utf8"), stderr: stderr.replace(/MAXRSS \d+\n/, "") }, maxrss: Number(m[1]) });
    });
  });
}

/**
 * A tar built from a spec, with the faults a real acquisition has: members (a file with a size, a symlink or a hard link,
 * or a zip made of the names given), a header whose checksum is wrong, an end block or none, a tar cut at a byte, a GNU long-name
 * header that declares more than it carries, and gzip, xz or bzip2 around it.
 */
const TARX = String.raw`
import bz2, gzip, io, json, lzma, sys, tarfile, zipfile
path, spec = sys.argv[1], json.loads(sys.argv[2])
buf = bytearray()
if spec.get("long_header_first"):
    info = tarfile.TarInfo("././@LongLink")
    info.type = tarfile.GNUTYPE_LONGNAME
    info.size = spec["long_header_first"]
    buf += info.tobuf(tarfile.GNU_FORMAT, "utf-8", "surrogateescape")
for m in spec["members"]:
    info = tarfile.TarInfo(m["name"])
    kind = m.get("type", "file")
    info.mtime = 1700000000
    data = b""
    if kind in ("symlink", "hardlink"):
        info.type = tarfile.SYMTYPE if kind == "symlink" else tarfile.LNKTYPE
        info.linkname = m["link"]
    elif m.get("zip"):
        mem = io.BytesIO()
        with zipfile.ZipFile(mem, "w") as z:
            for n in m["zip"]:
                z.writestr(n, b"x")
        data = mem.getvalue()
        info.size = len(data)
    else:
        data = b"x" * m.get("size", 0)
        info.size = len(data)
    head = bytearray(info.tobuf(tarfile.GNU_FORMAT, "utf-8", "surrogateescape"))
    if m.get("bad_checksum"):
        head[-512 + 148:-512 + 156] = b"777777\0 "
    buf += head + data + b"\0" * (-len(data) % 512)
if spec.get("long_header_last"):
    info = tarfile.TarInfo("././@LongLink")
    info.type = tarfile.GNUTYPE_LONGNAME
    info.size = spec["long_header_last"]
    buf += info.tobuf(tarfile.GNU_FORMAT, "utf-8", "surrogateescape")
if spec.get("end", True):
    buf += b"\0" * 1024
if spec.get("pad_to"):
    buf += b"\0" * (-len(buf) % spec["pad_to"])
if spec.get("cut_at") is not None:
    buf = buf[:spec["cut_at"]]
raw = bytes(buf)
comp = spec.get("compress", "none")
if comp == "gz": raw = gzip.compress(raw)
elif comp == "xz": raw = lzma.compress(raw)
elif comp == "bz2": raw = bz2.compress(raw)
if spec.get("cut_compressed") is not None:
    raw = raw[:spec["cut_compressed"]]
open(path, "wb").write(raw)
`;

/** A tar of the named members (name -> bytes), made by Python's tarfile. */
const TAR = String.raw`
import io, json, sys, tarfile
path, spec = sys.argv[1], json.loads(sys.argv[2])
with tarfile.open(path, "w", format=tarfile.GNU_FORMAT) as archive:
    for name, size in spec:
        info = tarfile.TarInfo(name)
        info.size = size
        info.mtime = 1700000000
        archive.addfile(info, io.BytesIO(b"x" * size))
`;

/** A stand-in for iLEAPP or ALEAPP: writes a report folder like the real one, with the log lines the test gives. */
async function standin(bin: string, name: string, script: string): Promise<void> {
  await mkdir(bin, { recursive: true });
  await writeFile(join(bin, name), `#!/usr/bin/env bash\nwhile [[ $# -gt 0 ]]; do case "$1" in -o) out="$2"; shift 2;; -t) kind="$2"; shift 2;; -i) src="$2"; shift 2;; *) shift;; esac; done\n${script}\n`, "utf8");
  await chmod(join(bin, name), 0o755);
}

const REPORT = String.raw`d="$out/Reports_2026-10-01"; mkdir -p "$d/_TSV Exports" "$d/_Timeline" "$d/_HTML"; : > "$d/_Timeline/tl.db"; : > "$d/_HTML/index.html"`;

/** Log lines in the shape iLEAPP v2026.4.1 prints, for a stand-in: a module that found records, one that found nothing, one that failed. */
const LOG = {
  header: (n: number): string => `echo "Artifact to parse: ${n}"`,
  found: (i: number, n: number, name: string, mod: string, records: number): string =>
    `echo "[${i}/${n}] ${name} [${mod}] artifact started at 09:29:44 UTC"; printf 'a\\tb\\n1\\t2\\n' > "$d/_TSV Exports/${name}.tsv"; echo "Found ${records} records for ${name}"; echo "${name} [${mod}] artifact completed in 0.0s"`,
  nofile: (i: number, n: number, name: string, mod: string): string =>
    `echo "[${i}/${n}] ${name} [${mod}] artifact started at 09:29:44 UTC"; echo "No file found"; echo "${name} [${mod}] artifact completed in 0.0s"`,
  nodata: (i: number, n: number, name: string, mod: string): string =>
    `echo "[${i}/${n}] ${name} [${mod}] artifact started at 09:29:44 UTC"; echo "No data found for ${name}"; echo "${name} [${mod}] artifact completed in 0.0s"`,
  failed: (i: number, n: number, name: string, mod: string): string =>
    `echo "[${i}/${n}] ${name} [${mod}] artifact started at 09:29:44 UTC"; echo "Error with /some/path/${name}.sqlite:"; echo " - unable to open database: file:None?mode=ro"
echo "Reading ${name} artifact had errors!"; echo "Error was list index out of range"; echo "Exception Traceback: Traceback (most recent call last):"; echo "  File \\"x.py\\", line 1, in ${name}"
echo "${name} [${mod}] artifact failed after 0.0s"`,
  readerror: (i: number, n: number, name: string, mod: string): string =>
    `echo "[${i}/${n}] ${name} [${mod}] artifact started at 09:29:44 UTC"; echo "${name}: error reading /case/path/db: no such table: t54-SECRET-TABLE"; echo "No data found for ${name}"; echo "${name} [${mod}] artifact completed in 0.0s"`,
  started: (i: number, n: number, name: string, mod: string): string => `echo "[${i}/${n}] ${name} [${mod}] artifact started at 09:29:44 UTC"`,
  end: `echo "Processes completed."`,
};

for (const [recipeName, program, marker, label, otherMarker] of [
  ["ios-ileapp", "ileapp", "private/var/mobile/Library/SMS/sms.db", "iLEAPP", "data/system/packages.xml"],
  ["android-aleapp", "aleapp", "data/system/packages.xml", "ALEAPP", "private/var/mobile/Library/SMS/sms.db"],
] as const) {
  test(`${recipeName} is complete only when its log accounts for every module and none errored (exit 0 and a TSV are not enough)`, async () => {
    await withCwd(async (cwd, bin) => {
      const tar = join(cwd, "work", "acq.tar");
      await build(TAR, tar, JSON.stringify([[marker, 16], ["data/data/com.example/databases/x.db", 4]]));
      const run = async (out: string, lines: string[]): Promise<{ result: RecipeRun; coverage: Coverage; tsv: string[] }> => {
        await standin(bin, program, `${REPORT}\n${lines.join("\n")}`);
        const result = await recipe(recipeName, ["run", "--target", target(tar), "--out", join(cwd, out)], cwd, {}, bin);
        const tsv = (await exists(join(cwd, out, "modules.tsv"))) ? (await readFile(join(cwd, out, "modules.tsv"), "utf8")).trimEnd().split("\n") : [];
        return { result, coverage: await coverage(join(cwd, out)), tsv };
      };
      // A module failed while another wrote its report, and the program exited 0: partial, and which module.
      const bad = await run("bad", [LOG.header(2), LOG.found(1, 2, "Messages", "messages", 2), LOG.failed(2, 2, "addressBook", "addressBook"), LOG.end]);
      assert.equal(bad.result.code, 0);
      assert.equal(bad.coverage.status, "partial", "exit 0 and a TSV said complete before");
      assert.deepEqual(bad.coverage.modules?.counts, { completed: 1, no_record: 0, unsupported: 0, errored: 1, errors_logged: 0, unknown: 0 });
      assert.ok(bad.coverage.errors.some((e) => /1 module\(s\) errored: addressBook/.test(e)), JSON.stringify(bad.coverage.errors));
      assert.match(bad.tsv[2], /^1\terrored\taddressBook\taddressBook\t0\t\d+\t/);
      assert.doesNotMatch(bad.coverage.covered, /ran every module/);
      assert.doesNotMatch(JSON.stringify(bad.coverage) + bad.tsv.join("\n"), /list index out of range|unable to open/, "the module's error text is in the kept log, not in the receipt");
      // Every module completed: complete, with what each says it found. A module that found nothing is no_record, never "absent".
      const good = await run("good", [LOG.header(3), LOG.found(1, 3, "Messages", "messages", 2), LOG.nofile(2, 3, "Notes", "notes"), LOG.nodata(3, 3, "Mail", "mail"), LOG.end]);
      assert.equal(good.coverage.status, "complete", JSON.stringify(good.coverage));
      assert.deepEqual(good.coverage.modules?.counts, { completed: 1, no_record: 2, unsupported: 0, errored: 0, errors_logged: 0, unknown: 0 });
      assert.equal(good.coverage.modules?.log_format_recognised, true);
      assert.equal(good.coverage.modules?.records_reported_by_modules, 2);
      assert.equal(good.tsv[0], "n\tstatus\tartefact\tmodule\trecords\tlogged_error_lines\tlog\tline");
      assert.match(good.tsv[1], new RegExp(`^0\\tcompleted\\tMessages\\tmessages\\t2\\t0\\t${program}.stdout\\t\\d+$`));
      assert.match(good.tsv[2], /^1\tno_record\tNotes\tnotes\t0\t0\t/);
      assert.match(good.tsv[3], /^2\tno_record\tMail\tmail\t0\t0\t/);
      assert.match(await readFile(join(cwd, "good", "index.tsv"), "utf8"), /^modules\.tsv\t/m);
      // A module that completed but wrote error lines (it could not read a table and said so): not complete, and its text is not copied.
      const logged = await run("logged", [LOG.header(2), LOG.found(1, 2, "Messages", "messages", 2), LOG.readerror(2, 2, "Telegram", "telegram"), LOG.end]);
      assert.equal(logged.coverage.status, "partial");
      assert.equal(logged.coverage.modules?.counts.errors_logged, 1);
      assert.match(logged.tsv[2], /^1\terrors_logged\tTelegram\ttelegram\t0\t1\t/);
      assert.doesNotMatch(JSON.stringify(logged.coverage) + logged.tsv.join("\n"), /SECRET-TABLE/);
      // The words a module uses for a failure it goes past are many: each of these, in a module that completes, is not "completed".
      for (const [i, line] of ["Could not open database file", "The database is malformed, skipping it", "Invalid schema version 9", "Database is corrupt", "Permission denied reading the file",
        "cannot decode attributedBody", "No such table: message", "unsupported schema"].entries()) {
        const odd = await run(`odd${i}`, [LOG.header(1), `echo "[1/1] Messages [messages] artifact started at 09:29:44 UTC"; echo "${line}"; echo "Found 0 records for Messages"; echo "Messages [messages] artifact completed in 0.0s"`, LOG.end]);
        assert.equal(odd.coverage.status, "partial", line);
        assert.equal(odd.coverage.modules?.counts.errors_logged, 1, line);
      }
      // A module that started and said nothing more is unknown, and a log that stops short of the modules it announced is not complete.
      const cut = await run("cut", [LOG.header(2), LOG.found(1, 2, "Messages", "messages", 2), LOG.started(2, 2, "Notes", "notes")]);
      assert.equal(cut.coverage.status, "partial");
      assert.equal(cut.coverage.modules?.counts.unknown, 1);
      const short = await run("short", [LOG.header(3), LOG.found(1, 3, "Messages", "messages", 2), LOG.nofile(2, 3, "Notes", "notes"), LOG.end]);
      assert.equal(short.coverage.status, "partial");
      assert.ok(short.coverage.errors.some((e) => /says 3 modules would be parsed and 2 started/.test(e)), JSON.stringify(short.coverage.errors));
      const noend = await run("noend", [LOG.header(1), LOG.found(1, 1, "Messages", "messages", 2)]);
      assert.equal(noend.coverage.status, "partial");
      assert.ok(noend.coverage.errors.some((e) => /does not end with its processing-completed line/.test(e)));
      // No module lines at all (a release that logs another way): every module is unknown, and the run is partial.
      const silent = await run("silent", [String.raw`printf 'a\tb\n1\t2\n' > "$d/_TSV Exports/Messages.tsv"`]);
      assert.equal(silent.coverage.status, "partial");
      assert.equal(silent.coverage.modules?.log_format_recognised, false);
      assert.ok(silent.coverage.errors.some((e) => /no module lines/.test(e)));
      // A traceback on stderr is a problem even if the exit status is 0.
      const trace = await run("trace", [LOG.header(1), LOG.found(1, 1, "Messages", "messages", 2), LOG.end, `echo "Traceback (most recent call last):" >&2; echo "  boom" >&2`]);
      assert.equal(trace.coverage.status, "partial");
      assert.equal(trace.coverage.modules?.tracebacks_on_stderr, 1);
      assert.match(await readFile(join(cwd, "trace", `${program}.stderr`), "utf8"), /Traceback/, `${label}'s stderr is kept whole`);
    });
  });

  test(`${recipeName} keeps every file the program leaves in its scratch tree, runs it from a directory under the output (a relative one too) and never writes the run directory`, async () => {
    await withCwd(async (cwd, bin) => {
      const tar = join(cwd, "work", "acq.tar");
      await build(TAR, tar, JSON.stringify([[marker, 16]]));
      // The program writes a log beside its report folder, a file in its working directory, one in its temp directory and a link in its working directory.
      await standin(bin, program, `${REPORT}\n${LOG.header(1)}\n${LOG.found(1, 1, "Messages", "messages", 2)}\n${LOG.end}
echo "log beside the report" > "$out/run-log.txt"; pwd > "$out/../cwd-seen.txt"; echo "left in cwd" > ./left-in-cwd.txt; echo "temp" > "$TMPDIR/left-in-tmp.txt"; ln -s /tmp ./linked-directory; mkdir -p "$TMPDIR/sub/deeper"`);
      // A read-only run directory: the recipe is started from it, as a job's worker is. The output is given relative to it, as a caller may.
      const runDir = join(cwd, "ro-run");
      await mkdir(runDir);
      await mkdir(join(cwd, "rel"));
      const out = join(cwd, "rel", "out-dir");
      await chmod(runDir, 0o555);
      const result = await recipe(recipeName, ["run", "--target", target(tar), "--out", "../rel/out-dir"], runDir, {}, bin);
      assert.equal(result.code, 0, result.stdout + result.stderr);
      const cov = await coverage(out);
      assert.equal(cov.status, "complete", JSON.stringify(cov));
      // The sibling file is kept, whole, beside the report; the report is where it was.
      assert.equal(await readFile(join(out, `${program}-run-files`, "run-log.txt"), "utf8"), "log beside the report\n");
      assert.equal(await exists(join(out, program, "_TSV Exports", "Messages.tsv")), true, "the one report folder is the report");
      assert.equal(cov.modules?.report_layout.startsWith("one report folder; 1 file(s) beside it"), true, JSON.stringify(cov.modules));
      // The program ran with its working directory and TMPDIR under the output, and what it left there is counted and kept (a link too).
      assert.equal((await readFile(join(out, "cwd-seen.txt"), "utf8")).trim().endsWith(`${program}-cwd`), true);
      assert.equal(await readFile(join(out, `${program}-cwd`, "left-in-cwd.txt"), "utf8"), "left in cwd\n");
      assert.equal(await readFile(join(out, `${program}-tmp`, "left-in-tmp.txt"), "utf8"), "temp\n");
      assert.deepEqual(cov.modules?.files_left_in_program_directories, { [`${program}-cwd`]: 2, [`${program}-tmp`]: 1 });
      // Nothing was written to the run directory, and the scratch directory is gone.
      assert.deepEqual(await readdir(runDir), []);
      assert.equal(await exists(join(out, `${program}-run`)), false);
      // A second run into the same output leaves the first run's coverage and report as they are.
      const before = (await readFile(join(out, "coverage.json"))).toString();
      const again = await recipe(recipeName, ["run", "--target", target(tar), "--out", "../rel/out-dir"], runDir, {}, bin);
      assert.equal(again.code, 2);
      assert.equal(JSON.parse(again.stdout).status, "refused");
      assert.equal((await readFile(join(out, "coverage.json"))).toString(), before, "the earlier coverage.json is untouched");
      assert.equal(await exists(join(out, program, "_TSV Exports", "Messages.tsv")), true);
    });
  });

  test(`${recipeName} dispatches a zip by its signature or its end record, and says a damaged one is not readable`, async () => {
    await withCwd(async (cwd) => {
      const good = join(cwd, "work", "good.zip");
      await build(`import sys, zipfile\nz = zipfile.ZipFile(sys.argv[1], "w")\nz.writestr(sys.argv[2], b"x")\nz.close()\n`, good, marker);
      const detect = await recipe(recipeName, ["detect", "--target", target(good)], cwd);
      assert.equal(detect.code, 0, detect.stdout);
      assert.equal(JSON.parse(detect.stdout).applies, true);
      // Data before the first local header (a self-extracting archive): still a zip.
      const data = await readFile(good);
      const prefixed = join(cwd, "work", "prefixed.zip");
      await writeFile(prefixed, Buffer.concat([Buffer.alloc(100, 0x41), data]));
      assert.equal(JSON.parse((await recipe(recipeName, ["detect", "--target", target(prefixed)], cwd)).stdout).applies, true);
      // The end-of-central-directory record is cut off: whatever this Python's is_zipfile says, a zip that cannot be read is said so.
      const broken = join(cwd, "work", "broken.zip");
      await writeFile(broken, data.subarray(0, data.length - 12));
      const bad = await recipe(recipeName, ["detect", "--target", target(broken)], cwd);
      assert.equal(bad.code, 1);
      assert.match(JSON.parse(bad.stdout).why, /not a readable zip/);
      // A zip with no marker of this platform is not this recipe's.
      const other = join(cwd, "work", "other.zip");
      await build(`import sys, zipfile\nz = zipfile.ZipFile(sys.argv[1], "w")\nz.writestr("readme.txt", b"x")\nz.close()\n`, other);
      assert.equal(JSON.parse((await recipe(recipeName, ["detect", "--target", target(other)], cwd)).stdout).applies, false);
    });
  });

  /** A recipe run over a tar with a stand-in program whose log lines the test gives, and what it wrote. */
  async function replay(cwd: string, bin: string, tar: string, out: string, script: string): Promise<{ result: RecipeRun; coverage: Coverage; tsv: string[] }> {
    await standin(bin, program, script);
    const result = await recipe(recipeName, ["run", "--target", target(tar), "--out", join(cwd, out)], cwd, {}, bin);
    const tsv = (await exists(join(cwd, out, "modules.tsv"))) ? (await readFile(join(cwd, out, "modules.tsv"), "utf8")).trimEnd().split("\n") : [];
    return { result, coverage: await coverage(join(cwd, out)), tsv };
  }

  test(`${recipeName} reads the log as the program prints it: a count with thousands separators, records beside "No data found", a version gate`, async () => {
    // Lines of this shape are those of real iLEAPP v2026.4.1 runs: the unified-log module prints "Found 167,304 records"
    // and, in the same module, "No data found for ..." for its other artefacts; a module gated by the OS version says so.
    await withCwd(async (cwd, bin) => {
      const tar = join(cwd, "work", "acq.tar");
      await build(TAR, tar, JSON.stringify([[marker, 16]]));
      const tsvLine = String.raw`printf 'a\tb\n1\t2\n' > "$d/_TSV Exports/logarchive.tsv"`;
      const lines = [
        LOG.header(4),
        `echo "[1/4] logarchive [logarchive] artifact started at 16:25:53 UTC"; echo "Reading Apple Unified Logs natively with unifiedlog_iterator 0.7.0"; echo "Unified Logs finished: 167,304 records in 0:07, 22,519 rec/s"; ${tsvLine}
echo "Found 167,304 records for logarchive"; echo "Found 18,897 records for logarchive artifacts"; echo "No data found for logarchive time change"; echo "No data found for logarchive flashlight"; echo "logarchive [logarchive] artifact completed in 25.3s"; echo ""`,
        `echo "[2/4] Ph094_1 [Ph094Ios14REFforAssetAnalysis] artifact started at 16:25:22 UTC"; echo "Unsupported version for PhotoData-Photos.sqlite for iOS 16.3"; echo "No data found for Ph094.1-iOS14_Ref_for_Asset_Analysis-PhDaPsql"; echo "Ph094_1 [Ph094Ios14REFforAssetAnalysis] artifact completed in 0.0s"; echo ""`,
        `echo "[3/4] wifi [wifi] artifact started at 16:26:01 UTC"; echo "Found 1,234 records for Wi-Fi"; echo "wifi [wifi] artifact completed in 0.1s"; echo ""`,
        LOG.nofile(4, 4, "Notes", "notes"),
        LOG.end,
      ];
      const run = await replay(cwd, bin, tar, "real", `${REPORT}\n${lines.join("\n")}`);
      assert.equal(run.coverage.status, "complete", JSON.stringify(run.coverage));
      assert.deepEqual(run.coverage.modules?.counts, { completed: 2, no_record: 1, unsupported: 1, errored: 0, errors_logged: 0, unknown: 0 });
      assert.equal(run.coverage.modules?.records_reported_by_modules, 167304 + 18897 + 1234);
      assert.match(run.tsv[1], /^0\tcompleted\tlogarchive\tlogarchive\t186201\t0\t/, "records beside 'No data found' lines are records");
      assert.match(run.tsv[2], /^1\tunsupported\tPh094_1\tPh094Ios14REFforAssetAnalysis\t0\t0\t/);
      assert.match(run.tsv[3], /^2\tcompleted\twifi\twifi\t1234\t0\t/);
      assert.match(run.coverage.covered, /1 that do not take this operating-system version/);
      // A gate is not an error: the line is not counted as one.
      assert.equal(run.tsv[2].split("\t")[5], "0");
      // index.tsv names the logs that modules.tsv points into.
      const index = await readFile(join(cwd, "real", "index.tsv"), "utf8");
      assert.match(index, new RegExp(`^${program}\\.stdout\\t`, "m"));
      assert.match(index, new RegExp(`^${program}\\.stderr\\t`, "m"));
    });
  });

  test(`${recipeName} is not complete over a log that gives no count and no end, or that speaks of an error outside a module`, async () => {
    await withCwd(async (cwd, bin) => {
      const tar = join(cwd, "work", "acq.tar");
      await build(TAR, tar, JSON.stringify([[marker, 16]]));
      // Module lines with no "Artifact to parse", no [i/N] prefix and no end line (the shape older releases print): the run cannot tell
      // that every module was run, and was complete before.
      const bare = await replay(cwd, bin, tar, "bare", `${REPORT}
echo "Messages [messages] artifact started at 09:29:44 UTC"; printf 'a\tb\n1\t2\n' > "$d/_TSV Exports/Messages.tsv"; echo "Found 2 records for Messages"; echo "Messages [messages] artifact completed in 0.0s"`);
      assert.equal(bare.coverage.status, "partial");
      assert.ok(bare.coverage.errors.some((e) => /does not say how many modules it will parse/.test(e)), JSON.stringify(bare.coverage.errors));
      assert.ok(bare.coverage.errors.some((e) => /does not end with its processing-completed line/.test(e)), JSON.stringify(bare.coverage.errors));
      // An error line after the last module, and one between two modules, count: they are not in any module.
      const outside = await replay(cwd, bin, tar, "outside", `${REPORT}
${[LOG.header(2), LOG.found(1, 2, "Messages", "messages", 2), `echo "OSError: [Errno 28] No space left on device SECRET-PATH"`, LOG.nofile(2, 2, "Notes", "notes"), LOG.end, `echo "Error: report generation failed SECRET-DETAIL"`].join("\n")}`);
      assert.equal(outside.coverage.status, "partial", JSON.stringify(outside.coverage));
      assert.equal(outside.coverage.modules?.counts.errors_logged, 0, "the lines belong to no module");
      assert.ok(outside.coverage.errors.some((e) => new RegExp(`2 log line\\(s\\) outside any module speak of an error \\(${program}\\.stdout line 5, ${program}\\.stdout line 10\\)`).test(e)), JSON.stringify(outside.coverage.errors));
      assert.doesNotMatch(JSON.stringify(outside.coverage) + outside.tsv.join("\n"), /SECRET|No space left|report generation/, "the lines are named by place, never copied");
    });
  });

  test(`${recipeName} reads stderr into the same account, and a line on stderr that nothing explains is a problem`, async () => {
    await withCwd(async (cwd, bin) => {
      const tar = join(cwd, "work", "acq.tar");
      await build(TAR, tar, JSON.stringify([[marker, 16]]));
      const log = [LOG.header(1), LOG.found(1, 1, "Messages", "messages", 2), LOG.end].join("\n");
      // A release that logs everything to stderr (Python's logging does): its count and end line are read, and the run is complete.
      const onStderr = await replay(cwd, bin, tar, "onstderr", `${REPORT}\n{\n${log}\n} >&2`);
      assert.equal(onStderr.coverage.status, "complete", JSON.stringify(onStderr.coverage));
      assert.equal(onStderr.coverage.modules?.log_format_recognised, true);
      // The same module lines with no end line anywhere are not complete, whichever stream they are on.
      const noEnd = await replay(cwd, bin, tar, "noend-stderr", `${REPORT}\n{\n${[LOG.header(1), LOG.found(1, 1, "Messages", "messages", 2)].join("\n")}\n} >&2`);
      assert.equal(noEnd.coverage.status, "partial");
      // A line on stderr that is not a log line, and one that names an error, with exit 0 and no traceback: not complete.
      const killed = await replay(cwd, bin, tar, "killed", `${REPORT}\n${log}\necho "Killed" >&2`);
      assert.equal(killed.coverage.status, "partial");
      assert.ok(killed.coverage.errors.some((e) => /1 line\(s\) on stderr that nothing explains/.test(e)), JSON.stringify(killed.coverage.errors));
      const named = await replay(cwd, bin, tar, "named", `${REPORT}\n${log}\necho "ERROR:root:could not parse /case/x: database disk image is malformed" >&2`);
      assert.equal(named.coverage.status, "partial");
      assert.ok(named.coverage.errors.some((e) => new RegExp(`outside any module speak of an error \\(${program}\\.stderr line 1\\)`).test(e)), JSON.stringify(named.coverage.errors));
      assert.doesNotMatch(JSON.stringify(named.coverage), /database disk image|\/case\/x/);
    });
  });

  test(`${recipeName} takes a tar whose last member is a zip for a tar, and a zip for a zip`, async () => {
    // zipfile finds the end record of a zip that is a MEMBER near the end of a tar: dispatch by the library's answer
    // would run the program with -t zip on a tar.
    await withCwd(async (cwd) => {
      const members = join(cwd, "work", "members.tar");
      await build(TARX, members, JSON.stringify({ members: [{ name: marker, size: 16 }, { name: "docs/inner.zip", zip: [otherMarker] }] }));
      const found = JSON.parse((await recipe(recipeName, ["detect", "--target", target(members)], cwd)).stdout) as { applies: boolean; why: string };
      assert.equal(found.applies, true, found.why);
      assert.match(found.why, /^tar members/);
      // The marker only inside the inner zip: the tar has none, and the inner zip is not opened.
      const inner = join(cwd, "work", "inner.tar");
      await build(TARX, inner, JSON.stringify({ members: [{ name: "readme.txt", size: 10 }, { name: "docs/inner.zip", zip: [marker] }] }));
      const none = JSON.parse((await recipe(recipeName, ["detect", "--target", target(inner)], cwd)).stdout) as { applies: boolean; why: string };
      assert.equal(none.applies, false);
      assert.match(none.why, /^tar has no .* marker$/);
      // Compressed tars are tars as well.
      for (const compress of ["gz", "xz", "bz2"]) {
        const packed = join(cwd, "work", `packed.${compress}`);
        await build(TARX, packed, JSON.stringify({ compress, members: [{ name: marker, size: 16 }] }));
        const answer = JSON.parse((await recipe(recipeName, ["detect", "--target", target(packed)], cwd)).stdout) as { applies: boolean; why: string };
        assert.equal(answer.applies, true, `${compress}: ${answer.why}`);
      }
    });
  });

  test(`${recipeName} does not read an extended header that declares more than it will hold, when it looks for the marker`, async () => {
    await withCwd(async (cwd) => {
      for (const compress of ["none", "gz"]) {
        const tar = join(cwd, "work", `long-${compress}.tar`);
        await build(TARX, tar, JSON.stringify({ compress, long_header_first: 200 * 1024 * 1024, members: [{ name: marker, size: 16 }] }));
        const { result, maxrss } = await measuredRecipe(recipeName, ["detect", "--target", target(tar)], cwd);
        const answer = JSON.parse(result.stdout) as { applies: boolean; why: string };
        assert.equal(answer.applies, false, answer.why);
        assert.match(answer.why, /before a header the scan does not read \(an extended header of 209715200 bytes at offset 0\)/);
        assert.ok(maxrss < 100 * 1024 * 1024, `${compress}: ${maxrss} bytes resident`);
      }
    });
  });

  test(`${recipeName} lists what it wrote with the log files, labels the program's copies of the acquisition as copies, and counts only a report as a report`, async () => {
    await withCwd(async (cwd, bin) => {
      const tar = join(cwd, "work", "acq.tar");
      await build(TAR, tar, JSON.stringify([[marker, 16]]));
      const log = [LOG.header(1), LOG.nofile(1, 1, "Messages", "messages"), LOG.end].join("\n");
      // Only copies of the acquisition's own files, one of them a .tsv: nothing was parsed.
      const copies = await replay(cwd, bin, tar, "copies", `d="$out/Reports_2026"; mkdir -p "$d/data/private/var" "$d/_HTML"; printf 'a\n' > "$d/data/private/var/leftover.tsv"; : > "$d/data/private/var/keychain-2.db"\n${log}`);
      assert.equal(copies.coverage.status, "failed", JSON.stringify(copies.coverage));
      const index = await readFile(join(cwd, "copies", "index.tsv"), "utf8");
      assert.match(index, /leftover\.tsv\tcopy of a file of the acquisition that .* read \(leftover\.tsv\), not a report/);
      assert.match(index, /keychain-2\.db\tcopy of a file of the acquisition/);
      assert.doesNotMatch(index, /artefact report leftover|database keychain-2/);
      // Beside a real report both are listed, each as what it is.
      const both = await replay(cwd, bin, tar, "both", `${REPORT}; mkdir -p "$d/data/private/var"; : > "$d/data/private/var/keychain-2.db"; printf 'a\tb\n1\t2\n' > "$d/_TSV Exports/Messages.tsv"\n${log}`);
      assert.equal(both.coverage.status, "complete", JSON.stringify(both.coverage));
      const rows = (await readFile(join(cwd, "both", "index.tsv"), "utf8")).trimEnd().split("\n");
      assert.ok(rows.some((r) => /_TSV Exports\/Messages\.tsv\t.*artefact report Messages/.test(r)), rows.join("\n"));
      assert.ok(rows.some((r) => /keychain-2\.db\tcopy of a file of the acquisition/.test(r)), rows.join("\n"));
    });
  });

  test(`${recipeName} reads a log line to a bound, not whole`, async () => {
    // A line of 96 MiB in the log (a module that prints a blob) was read whole before it was cut.
    await withCwd(async (cwd, bin) => {
      const tar = join(cwd, "work", "acq.tar");
      await build(TAR, tar, JSON.stringify([[marker, 16]]));
      await standin(bin, program, `${REPORT}
${LOG.header(1)}
echo "[1/1] Messages [messages] artifact started at 09:29:44 UTC"; printf 'a\tb\n1\t2\n' > "$d/_TSV Exports/Messages.tsv"
head -c 100663296 /dev/zero | tr '\\0' 'a'; echo
echo "Found 2 records for Messages"; echo "Messages [messages] artifact completed in 0.0s"
${LOG.end}`);
      const { result, maxrss } = await measuredRecipe(recipeName, ["run", "--target", target(tar), "--out", join(cwd, "longline")], cwd, bin);
      assert.equal(result.code, 0, result.stdout + result.stderr);
      const cov = await coverage(join(cwd, "longline"));
      assert.equal(cov.status, "complete", JSON.stringify(cov));
      assert.equal(cov.modules?.records_reported_by_modules, 2);
      assert.ok(maxrss < 64 * 1024 * 1024, `${maxrss} bytes resident`);
    });
  });
}

// --- android-backup ---------------------------------------------------------------------

/**
 * An adb backup: the text header, then the tar (zlib-compressed when asked). `members` are [name, size] with
 * zero bytes of content; a member's content is streamed through the compressor, so 300 MiB of zeros costs a
 * few hundred KiB on disk.
 */
const AB = String.raw`
import io, json, sys, tarfile, zlib
path, spec = sys.argv[1], json.loads(sys.argv[2])
header = ("ANDROID BACKUP\n%s\n%s\n%s\n" % (spec.get("version", 5), 1 if spec.get("compress", True) else 0, spec.get("encryption", "none"))).encode()
if spec.get("encryption_lines"):
    header += ("\n".join(spec["encryption_lines"]) + "\n").encode()
with open(path, "wb") as out:
    out.write(header)
    comp = zlib.compressobj(9) if spec.get("compress", True) else None
    def emit(chunk):
        out.write(comp.compress(chunk) if comp else chunk)
    for index, (name, size) in enumerate(spec.get("members", [])):
        info = tarfile.TarInfo(name)
        info.size = size
        info.mtime = 1700000000
        head = bytearray(info.tobuf(tarfile.GNU_FORMAT, "utf-8", "surrogateescape"))
        if spec.get("bad_checksum") == index:
            head[148:156] = b"777777\0 "
        emit(bytes(head))
        remaining = size
        while remaining:
            n = min(remaining, 1 << 20)
            emit(b"\0" * n)
            remaining -= n
        pad = (-size) % 512
        if pad:
            emit(b"\0" * pad)
    if spec.get("long_header"):
        # An extended header (GNU long name) that declares a size it does not carry.
        info = tarfile.TarInfo("././@LongLink")
        info.type = tarfile.GNUTYPE_LONGNAME
        info.size = spec["long_header"]
        emit(info.tobuf(tarfile.GNU_FORMAT, "utf-8", "surrogateescape"))
    if spec.get("end", True):
        emit(b"\0" * 1024)
    if comp:
        tail = comp.flush()
        if spec.get("truncate_stream"):
            tail = b""
        out.write(tail)
    if spec.get("trailing"):
        out.write(b"\x99" * spec["trailing"])
    if spec.get("second_stream"):
        info = tarfile.TarInfo(spec["second_stream"])
        info.size = 5
        out.write(zlib.compress(info.tobuf(tarfile.GNU_FORMAT, "utf-8", "surrogateescape") + b"hello" + b"\0" * 507 + b"\0" * 1024))
`;

const SALT = "A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8091A2B3C4D5E6F708192A3B4C5D6";
const CHECK = "0F1E2D3C4B5A69788796A5B4C3D2E1F00F1E2D3C4B5A69788796A5B4C3D2E1F0";
const IV = "00112233445566778899AABBCCDDEEFF";
const BLOB = "FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA98";

test("android-backup stops a payload that expands past its budget, says partial, and keeps the members it listed", async () => {
  // Each compressed piece was decompressed without a bound: the input was read in pieces and the output was not.
  await withCwd(async (cwd) => {
    const ab = join(cwd, "work", "bomb.ab");
    await build(AB, ab, JSON.stringify({ members: [["apps/com.example/db/a.db", 512], ["apps/com.example/f/huge.bin", 300 * 1024 * 1024]] }));
    assert.ok((await stat(ab)).size < 2 * 1024 * 1024, "the bomb is small on disk");
    const out = join(cwd, "bomb");
    const result = await recipe("android-backup", ["run", "--target", target(ab), "--out", out, "--max-decompressed-bytes", String(16 * 1024 * 1024)], cwd);
    assert.equal(result.code, 0, result.stdout + result.stderr);
    const cov = await coverage(out);
    assert.equal(cov.status, "partial");
    assert.equal(cov.payload_stream, "not_reached");
    assert.ok(cov.limits_hit.some((l) => /decompressed output budget of 16777216 bytes/.test(l)), JSON.stringify(cov.limits_hit));
    assert.ok((cov.decompressed_bytes ?? 0) <= 16 * 1024 * 1024);
    const members = (await readFile(join(out, "members.tsv"), "utf8")).trimEnd().split("\n");
    assert.equal(members[0], "n\ttype\tpath\tbytes\tmtime_utc\tmode\tlink\tpath_b64");
    assert.match(members[1], /^0\tfile\tapps\/com\.example\/db\/a\.db\t512\t2023-11-14T22:13:20Z\t/);
    // Within a budget that holds it, the same backup is complete and the stream's end marker is verified.
    const small = join(cwd, "work", "small.ab");
    await build(AB, small, JSON.stringify({ members: [["apps/com.example/db/a.db", 512], ["shared/0/DCIM/p.jpg", 100000]] }));
    const ok = join(cwd, "small");
    assert.equal((await recipe("android-backup", ["run", "--target", target(small), "--out", ok], cwd)).code, 0);
    const done = await coverage(ok);
    assert.equal(done.status, "complete");
    assert.equal(done.payload_stream, "reached");
    assert.equal(done.tar_end, "reached");
    assert.equal(done.covered, "2 embedded tar members");
    // A stream cut off before its end marker is not complete.
    const cut = join(cwd, "work", "cut.ab");
    await build(AB, cut, JSON.stringify({ members: [["apps/a/db/x.db", 512]], truncate_stream: true }));
    const cutOut = join(cwd, "cut");
    await recipe("android-backup", ["run", "--target", target(cut), "--out", cutOut], cwd);
    const cutCov = await coverage(cutOut);
    assert.equal(cutCov.status, "partial");
    assert.equal(cutCov.payload_stream, "truncated");
  });
});

test("android-backup reports a version or a scheme it does not read as unsupported, and prints no key-derivation value", async () => {
  await withCwd(async (cwd) => {
    const v99 = join(cwd, "work", "v99.ab");
    await build(AB, v99, JSON.stringify({ version: 99, members: [["apps/a/db/x.db", 512]] }));
    const out99 = join(cwd, "v99");
    assert.equal((await recipe("android-backup", ["run", "--target", target(v99), "--out", out99], cwd)).code, 0);
    const cov99 = await coverage(out99);
    assert.equal(cov99.status, "partial");
    assert.match(cov99.covered, /version 99 is not one this recipe reads/);
    assert.ok(cov99.errors.some((e) => /unsupported: header version 99/.test(e)));
    assert.equal((await readFile(join(out99, "members.tsv"), "utf8")).trimEnd().split("\n").length, 1, "nothing was listed");
    // An unknown scheme is unsupported; AES-256's header is described by its shape, and its salts, IV and key blob are not printed.
    const odd = join(cwd, "work", "odd.ab");
    await build(AB, odd, JSON.stringify({ encryption: "ROT-13" }));
    const oddOut = join(cwd, "odd");
    await recipe("android-backup", ["run", "--target", target(odd), "--out", oddOut], cwd);
    assert.ok((await coverage(oddOut)).errors.some((e) => /unsupported: payload encryption scheme ROT-13/.test(e)));
    const aes = join(cwd, "work", "aes.ab");
    await build(AB, aes, JSON.stringify({ encryption: "AES-256", encryption_lines: [SALT, CHECK, "10000", IV, BLOB] }));
    const aesOut = join(cwd, "aes");
    const run = await recipe("android-backup", ["run", "--target", target(aes), "--out", aesOut], cwd);
    assert.equal(run.code, 0, run.stdout + run.stderr);
    const header = JSON.parse(await readFile(join(aesOut, "backup.json"), "utf8")) as { encryption: string; encryption_header: Record<string, unknown> };
    assert.equal(header.encryption, "AES-256");
    assert.deepEqual(header.encryption_header, {
      layout: "user salt, checksum salt, rounds, IV, master key blob (as the format documents it)",
      user_salt_chars: 64, checksum_salt_chars: 64, rounds: 10000, user_iv_chars: 32, master_key_blob_chars: 88, values_printed: false,
    });
    for (const secret of [SALT, CHECK, IV, BLOB]) {
      for (const f of await filesUnder(aesOut)) assert.equal(f.data.includes(Buffer.from(secret)), false, `${f.path} holds a header value`);
      assert.equal(run.stdout.includes(secret), false);
    }
    const aesCov = await coverage(aesOut);
    assert.equal(aesCov.status, "partial");
    assert.ok(aesCov.errors.some((e) => /AES-256; opening it needs a password/.test(e)));
    // detect still applies: the preparation of every adb backup is on the record.
    assert.equal(JSON.parse((await recipe("android-backup", ["detect", "--target", target(odd)], cwd)).stdout).applies, true);
  });
});

test("android-backup is complete only when the tar's end-of-archive block came, compressed or not", async () => {
  // A backup cut at a member boundary, or in the middle of a header, ended the listing quietly and was complete.
  await withCwd(async (cwd) => {
    for (const compress of [false, true]) {
      const name = compress ? "zlib" : "plain";
      const whole = join(cwd, "work", `${name}.ab`);
      await build(AB, whole, JSON.stringify({ compress, members: [["apps/a/db/x.db", 600], ["apps/a/db/y.db", 700], ["apps/a/db/z.db", 800]] }));
      const full = join(cwd, `${name}-full`);
      await recipe("android-backup", ["run", "--target", target(whole), "--out", full], cwd);
      const done = await coverage(full);
      assert.equal(done.status, "complete", JSON.stringify(done));
      assert.equal(done.tar_end, "reached");
      // No end block (the member list is whole, the marker is not): partial.
      const open = join(cwd, "work", `${name}-noend.ab`);
      await build(AB, open, JSON.stringify({ compress, end: false, members: [["apps/a/db/x.db", 600], ["apps/a/db/y.db", 700]] }));
      const noEnd = join(cwd, `${name}-noend`);
      await recipe("android-backup", ["run", "--target", target(open), "--out", noEnd], cwd);
      const c = await coverage(noEnd);
      assert.equal(c.status, "partial", `${name}: ${JSON.stringify(c)}`);
      assert.equal(c.tar_end, "missing");
      assert.ok(c.errors.some((e) => /without its end-of-archive block/.test(e)));
    }
    // An uncompressed file cut 200 bytes into the third member's header.
    const plain = join(cwd, "work", "plain.ab");
    const data = await readFile(plain);
    const cutAt = data.indexOf(Buffer.from("apps/a/db/z.db"));
    await writeFile(join(cwd, "work", "cut-header.ab"), data.subarray(0, cutAt + 200));
    await recipe("android-backup", ["run", "--target", target(join(cwd, "work", "cut-header.ab")), "--out", join(cwd, "cut-header")], cwd);
    const cut = await coverage(join(cwd, "cut-header"));
    assert.equal(cut.status, "partial");
    assert.equal(cut.tar_end, "missing");
  });
});

/** An adb backup whose tar is built block by block, as the formats lay it out (ustar header, pax records, GNU sparse extension blocks). */
const RAWTAR = String.raw`
import json, random, sys, zlib
path, spec = sys.argv[1], json.loads(sys.argv[2])
def block(name, size_field, flag=b"0"):
    b = bytearray(512)
    b[0:len(name)] = name
    b[100:108] = b"0000644\0"; b[108:116] = b"0000000\0"; b[116:124] = b"0000000\0"
    b[124:136] = size_field; b[136:148] = b"14000000000\0"; b[148:156] = b"        "; b[156:157] = flag; b[257:265] = b"ustar  \0"
    b[148:156] = b"%06o\0 " % (sum(b) & 0o777777)
    return bytes(b)
def pad(d): return d + b"\0" * (-len(d) % 512)
def record(k, v):
    body = b" %s=%s\n" % (k, v); n = len(body) + 1
    while len(str(n)) + len(body) != n: n = len(str(n)) + len(body)
    return b"%d%s" % (n, body)
rnd = random.Random(7)
def data(n): return bytes(rnd.getrandbits(8) for _ in range(n)) if n < 100000 else (bytes(rnd.getrandbits(8) for _ in range(4096)) * (n // 4096 + 1))[:n]
out = b""
for m in spec["members"]:
    kind = m["kind"]
    if kind == "plain":
        d = data(m["size"]); out += block(m["name"].encode(), b"%011o\0" % len(d)) + pad(d)
    elif kind == "pax_size":
        # the real size is in the pax record, the ustar size is 0 (POSIX pax: the record wins)
        rec = record(b"size", b"%d" % m["size"])
        d = b"\0" * m["size"] if m.get("zeros") else data(m["size"])
        out += block(b"PaxHeaders/x", b"%011o\0" % len(rec), b"x") + pad(rec) + block(m["name"].encode(), b"%011o\0" % 0) + pad(d)
    elif kind == "pax_text_size":
        rec = record(b"size", b"notanumber")
        d = data(m["size"])
        out += block(b"PaxHeaders/t", b"%011o\0" % len(rec), b"x") + pad(rec) + block(m["name"].encode(), b"%011o\0" % len(d)) + pad(d)
    elif kind == "global_size":
        rec = record(b"size", b"0")
        d = data(m["size"])
        out += block(b"PaxHeaders/g", b"%011o\0" % len(rec), b"g") + pad(rec) + block(m["name"].encode(), b"%011o\0" % len(d)) + pad(d)
    elif kind == "pax_big":
        rec = b"".join(record(b"SCHILY.xattr.user.k%d" % i, b"v" * 200) for i in range(m["records"]))
        out += block(b"PaxHeaders/y", b"%011o\0" % len(rec), b"x") + pad(rec) + block(m["name"].encode(), b"%011o\0" % 10) + pad(b"0123456789")
    elif kind == "sparse":
        d = data(m["size"])
        b = bytearray(block(m["name"].encode(), b"%011o\0" % len(d), b"S"))
        b[482] = 1; b[483:495] = b"%011o\0" % (1 << 20); b[148:156] = b"        "; b[148:156] = b"%06o\0 " % (sum(b) & 0o777777)
        out += bytes(b) + bytes(512) + pad(d)   # one extension block (its isextended byte is 0), then the data
out += b"\0" * 1024
header = b"ANDROID BACKUP\n5\n%d\nnone\n" % (1 if spec.get("compress", True) else 0)
open(path, "wb").write(header + (zlib.compress(out) if spec.get("compress", True) else out))
`;

test("android-backup follows the sizes the tar reader follows: a pax size record, GNU sparse extension blocks, a pax header of megabytes", async () => {
  // The watch read only the ustar size: a valid pax archive whose entry size is in the pax record was read as cut short,
  // a sparse entry with extension blocks as damaged, and a long pax header as too large.
  await withCwd(async (cwd) => {
    const cases: [string, Record<string, unknown>[], string[]][] = [
      ["pax-size", [{ kind: "pax_size", name: "apps/a/f/big.bin", size: 200000 }, { kind: "plain", name: "apps/a/db/after.db", size: 10 }], ["apps/a/f/big.bin", "apps/a/db/after.db"]],
      ["pax-zeros", [{ kind: "pax_size", name: "apps/a/f/zero.bin", size: 200000, zeros: true }, { kind: "plain", name: "apps/a/db/after.db", size: 10 }], ["apps/a/f/zero.bin", "apps/a/db/after.db"]],
      ["sparse", [{ kind: "sparse", name: "apps/a/f/sparse.bin", size: 3000 }, { kind: "plain", name: "apps/a/db/after.db", size: 10 }], ["apps/a/f/sparse.bin", "apps/a/db/after.db"]],
      ["pax-big", [{ kind: "pax_big", name: "apps/a/f/xattr.bin", records: 9000 }, { kind: "plain", name: "apps/a/db/after.db", size: 10 }], ["apps/a/f/xattr.bin", "apps/a/db/after.db"]],
    ];
    for (const compress of [false, true]) {
      for (const [name, members, expected] of cases) {
        const ab = join(cwd, "work", `${name}-${compress}.ab`);
        await build(RAWTAR, ab, JSON.stringify({ compress, members }));
        const out = join(cwd, `${name}-${compress}`);
        const result = await recipe("android-backup", ["run", "--target", target(ab), "--out", out], cwd);
        assert.equal(result.code, 0, result.stdout + result.stderr);
        const cov = await coverage(out);
        assert.equal(cov.status, "complete", `${name} compress=${compress}: ${JSON.stringify(cov)}`);
        assert.equal(cov.tar_end, "reached", name);
        const listed = (await readFile(join(out, "members.tsv"), "utf8")).trimEnd().split("\n").slice(1).map((l) => l.split("\t")[2]);
        assert.deepEqual(listed, expected, name);
      }
    }
    // Truncated inside the pax-sized data: partial, never "reached" from a wrong position.
    const ab = join(cwd, "work", "pax-size-false.ab");
    const data = await readFile(ab.replace("pax-size-false", "pax-size-false"));
    await writeFile(join(cwd, "work", "pax-cut.ab"), data.subarray(0, data.length - 100000));
    await recipe("android-backup", ["run", "--target", target(join(cwd, "work", "pax-cut.ab")), "--out", join(cwd, "pax-cut")], cwd);
    const cut = await coverage(join(cwd, "pax-cut"));
    assert.equal(cut.status, "partial");
    assert.notEqual(cut.tar_end, "reached");
  });
});

test("android-backup does not read an extended header that declares more than it will hold, and says so", async () => {
  // The tar library reads a GNU long name or a pax header whole into memory: 300 MiB declared in a 600-byte header.
  await withCwd(async (cwd) => {
    for (const compress of [false, true]) {
      const name = compress ? "zlib" : "plain";
      const ab = join(cwd, "work", `${name}-long.ab`);
      await build(AB, ab, JSON.stringify({ compress, long_header: 300 * 1024 * 1024, members: [["apps/a/db/x.db", 100]] }));
      const out = join(cwd, `${name}-long`);
      const result = await recipe("android-backup", ["run", "--target", target(ab), "--out", out], cwd);
      assert.equal(result.code, 0, result.stdout + result.stderr);
      const cov = await coverage(out);
      assert.equal(cov.status, "partial", JSON.stringify(cov));
      assert.ok(cov.limits_hit.some((l) => /extended header at offset \d+ declares 314572800 bytes, over the limit of 16777216/.test(l)), JSON.stringify(cov.limits_hit));
      assert.equal((await readFile(join(out, "members.tsv"), "utf8")).trimEnd().split("\n").length, 2, "the member before the header is listed");
    }
  });
});

test("android-backup prints only a scheme word from the header, and a line that is not one only as a length", async () => {
  await withCwd(async (cwd) => {
    const ab = join(cwd, "work", "secretish.ab");
    await build(AB, ab, JSON.stringify({ encryption: "deadbeef".repeat(8) }));
    const out = join(cwd, "secretish");
    const run = await recipe("android-backup", ["run", "--target", target(ab), "--out", out], cwd);
    const detect = await recipe("android-backup", ["detect", "--target", target(ab)], cwd);
    for (const f of await filesUnder(out)) assert.equal(f.data.includes(Buffer.from("deadbeef")), false, f.path);
    assert.equal(run.stdout.includes("deadbeef"), false);
    assert.equal(detect.stdout.includes("deadbeef"), false);
    assert.match(JSON.stringify(await coverage(out)), /not a scheme word: 64 characters, not printed/);
  });
});

test("android-backup lists a member whose name is not UTF-8 without raising, with its exact bytes", async () => {
  await withCwd(async (cwd) => {
    const ab = join(cwd, "work", "names.ab");
    await build(AB, ab, JSON.stringify({ compress: false, members: [["apps/com.example/db/\udcffbad\tname.db", 16], ["apps/com.example/db/plain.db", 8]] }));
    const out = join(cwd, "names");
    const result = await recipe("android-backup", ["run", "--target", target(ab), "--out", out], cwd);
    assert.equal(result.code, 0, result.stdout + result.stderr);
    assert.equal((await coverage(out)).status, "complete");
    const rows = (await readFile(join(out, "members.tsv"), "utf8")).trimEnd().split("\n").slice(1).map((l) => l.split("\t"));
    assert.equal(rows.length, 2);
    assert.equal(rows[0][2], "apps/com.example/db/\\xffbad\\tname.db");
    assert.equal(Buffer.from(rows[0][7], "base64").toString("latin1"), "apps/com.example/db/\xffbad\tname.db");
  });
});

test("android-backup is partial when the tar library stops quietly at a header it refuses, and says where", async () => {
  // The library ends a listing without a word at a header whose checksum does not match, or whose size is a pax record that is not a number;
  // the watch walked past it to the end block, so the run said complete over a listing that lacked members.
  await withCwd(async (cwd) => {
    for (const compress of [false, true]) {
      const name = compress ? "zlib" : "plain";
      const ab = join(cwd, "work", `${name}-badsum.ab`);
      await build(AB, ab, JSON.stringify({ compress, bad_checksum: 1, members: [["apps/a/db/a.db", 600], ["apps/a/db/b.db", 700], ["apps/a/db/c.db", 800]] }));
      const out = join(cwd, `${name}-badsum`);
      assert.equal((await recipe("android-backup", ["run", "--target", target(ab), "--out", out], cwd)).code, 0);
      const cov = await coverage(out);
      assert.equal(cov.status, "partial", `${name}: ${JSON.stringify(cov)}`);
      assert.ok(cov.errors.some((e) => /the tar header at offset 1536 is not one the tar reader accepts .*stopped there, after 1 members/.test(e)), JSON.stringify(cov.errors));
      assert.equal(cov.tar_end, "not_reached");
      assert.equal((await readFile(join(out, "members.tsv"), "utf8")).trimEnd().split("\n").length, 2, "only the member before the header is listed");
      // A pax size that is not a number reads as 0 for the library, which then reads the data as a header; a global header's size record applies to the member after it.
      for (const [kind, label] of [["pax_text_size", "text"], ["global_size", "global"]] as const) {
        const raw = join(cwd, "work", `${name}-${label}.ab`);
        await build(RAWTAR, raw, JSON.stringify({ compress, members: [{ kind, name: "apps/a/f/odd.bin", size: 700 }, { kind: "plain", name: "apps/a/db/after.db", size: 10 }] }));
        const rawOut = join(cwd, `${name}-${label}`);
        await recipe("android-backup", ["run", "--target", target(raw), "--out", rawOut], cwd);
        const rawCov = await coverage(rawOut);
        assert.equal(rawCov.status, "partial", `${name} ${label}: ${JSON.stringify(rawCov)}`);
        assert.ok(rawCov.errors.some((e) => /is not one the tar reader accepts/.test(e)), JSON.stringify(rawCov.errors));
      }
    }
  });
});

test("android-backup counts the bytes after the zlib stream's end and says partial, and tells a damaged stream", async () => {
  await withCwd(async (cwd) => {
    const members = [["apps/a/db/x.db", 600], ["apps/a/db/y.db", 700]];
    const whole = join(cwd, "work", "whole.ab");
    await build(AB, whole, JSON.stringify({ members }));
    await recipe("android-backup", ["run", "--target", target(whole), "--out", join(cwd, "whole")], cwd);
    const done = await coverage(join(cwd, "whole"));
    assert.equal(done.status, "complete");
    assert.equal((done as unknown as { bytes_after_stream: number }).bytes_after_stream, 0);
    const garbage = join(cwd, "work", "garbage.ab");
    await build(AB, garbage, JSON.stringify({ members, trailing: 2400 }));
    await recipe("android-backup", ["run", "--target", target(garbage), "--out", join(cwd, "garbage")], cwd);
    const g = await coverage(join(cwd, "garbage"));
    assert.equal(g.status, "partial", JSON.stringify(g));
    assert.equal((g as unknown as { bytes_after_stream: number }).bytes_after_stream, 2400);
    assert.ok(g.errors.some((e) => /2400 byte\(s\) follow the zlib stream's end marker/.test(e)), JSON.stringify(g.errors));
    // A second stream that holds another member is the same: counted, not read, and the run is not complete.
    const second = join(cwd, "work", "second.ab");
    await build(AB, second, JSON.stringify({ members, second_stream: "apps/hidden/second.db" }));
    await recipe("android-backup", ["run", "--target", target(second), "--out", join(cwd, "second")], cwd);
    const two = await coverage(join(cwd, "second"));
    assert.equal(two.status, "partial", JSON.stringify(two));
    assert.ok(((two as unknown as { bytes_after_stream: number }).bytes_after_stream) > 0);
    assert.equal((await readFile(join(cwd, "second", "members.tsv"), "utf8")).includes("hidden"), false, "the second stream is not read");
    // A byte changed inside the stream: partial, and not "reached".
    const bytes = await readFile(whole);
    const hurt = Buffer.from(bytes);
    hurt[Math.floor(hurt.length / 2)] ^= 0xff;
    await writeFile(join(cwd, "work", "hurt.ab"), hurt);
    await recipe("android-backup", ["run", "--target", target(join(cwd, "work", "hurt.ab")), "--out", join(cwd, "hurt")], cwd);
    const h = await coverage(join(cwd, "hurt"));
    assert.equal(h.status, "partial", JSON.stringify(h));
    assert.notEqual(h.payload_stream, "reached");
  });
});

test("android-backup says a header line that is not ASCII is not ASCII, and prints no byte of it", async () => {
  await withCwd(async (cwd) => {
    const ab = join(cwd, "work", "nonascii.ab");
    await writeFile(ab, Buffer.concat([Buffer.from("ANDROID BACKUP\n5\n1\nAES-256\n"), Buffer.from([0x41, 0xff, 0x42, 0x0a]), Buffer.from("00\n10000\n00\n00\n")]));
    const run = await recipe("android-backup", ["run", "--target", target(ab), "--out", join(cwd, "nonascii")], cwd);
    const detect = await recipe("android-backup", ["detect", "--target", target(ab)], cwd);
    for (const text of [run.stdout, detect.stdout]) {
      assert.match(text, /user salt line is not ASCII/);
      assert.doesNotMatch(text, /codec|0xff|position|byte/i);
    }
  });
});

test("android-backup and ios-filesystem refuse to write over an earlier run, and leave it as it was", async () => {
  await withCwd(async (cwd) => {
    const ab = join(cwd, "work", "once.ab");
    await build(AB, ab, JSON.stringify({ members: [["apps/a/db/x.db", 600]] }));
    const tar = join(cwd, "work", "once.tar");
    await build(TAR, tar, JSON.stringify([["private/var/mobile/Library/SMS/sms.db", 16]]));
    for (const [name, input] of [["android-backup", ab], ["ios-filesystem", tar]] as const) {
      const out = join(cwd, name);
      assert.equal((await recipe(name, ["run", "--target", target(input), "--out", out], cwd)).code, 0);
      const before = await filesUnder(out);
      const again = await recipe(name, ["run", "--target", target(input), "--out", out], cwd);
      assert.equal(again.code, 2, again.stdout + again.stderr);
      assert.equal(JSON.parse(again.stdout).status, "refused");
      assert.deepEqual(await filesUnder(out), before, `${name}: the earlier run's files are as they were`);
    }
  });
});

// --- ios-filesystem ------------------------------------------------------------------------

test("ios-filesystem keeps a member's name as the archive spelled it, and both members of a duplicated database", async () => {
  // It stripped every leading dot and slash from a name, and a database that occurred twice kept only the last size.
  await withCwd(async (cwd) => {
    const tar = join(cwd, "work", "phone.tar");
    await build(TAR, tar, JSON.stringify([
      ["private/var/mobile/Library/SMS/sms.db", 16],
      ["private/var/mobile/Library/SMS/sms.db-wal", 3],
      ["..config/private/var/mobile/cache.sqlite", 7],
      ["./private/var/mobile/Library/CallHistoryDB/CallHistory.storedata", 5],
      ["private/var/mobile/Library/SMS/sms.db", 20],
      ["private/var/mobile/Library/\udcffbytes.db", 9],
    ]));
    const out = join(cwd, "ios");
    const result = await recipe("ios-filesystem", ["run", "--target", target(tar), "--out", out], cwd);
    assert.equal(result.code, 0, result.stdout + result.stderr);
    const cov = await coverage(out);
    assert.equal(cov.status, "complete");
    assert.equal(cov.covered, "6 tar members; 3 forensic structures; 4 SQLite families");
    const sqlite = (await readFile(join(out, "sqlite.tsv"), "utf8")).trimEnd().split("\n");
    assert.equal(sqlite[0], "path\tdb_bytes\twal_bytes\tshm_bytes\tjournal_bytes\tpath_b64\tmembers\ttypes");
    const rows = Object.fromEntries(sqlite.slice(1).map((l) => { const c = l.split("\t"); return [c[0], c]; }));
    // The duplicate: both sizes, in archive order, and both member positions.
    const sms = rows["private/var/mobile/Library/SMS/sms.db"];
    assert.equal(sms[1], "16|20");
    assert.equal(sms[2], "3");
    assert.equal(sms[6], "db=0,wal=1,db=4");
    // The name is not trimmed: ..config is part of it, and so is a leading ./
    assert.ok(rows["..config/private/var/mobile/cache.sqlite"], Object.keys(rows).join());
    assert.ok(rows["./private/var/mobile/Library/CallHistoryDB/CallHistory.storedata"]);
    // A name that is not UTF-8: escaped, with its exact bytes.
    const odd = rows["private/var/mobile/Library/\\xffbytes.db"];
    assert.ok(odd, Object.keys(rows).join());
    assert.equal(Buffer.from(odd[5], "base64").toString("latin1"), "private/var/mobile/Library/\xffbytes.db");
    const artifacts = (await readFile(join(out, "artifacts.tsv"), "utf8")).trimEnd().split("\n");
    assert.equal(artifacts[0], "category\tpath\tbytes\tmtime_utc\ttype\tn\tpath_b64");
    const comm = artifacts.map((l) => l.split("\t")).filter((c) => c[0] === "communications");
    assert.ok(comm.some((c) => c[1] === "./private/var/mobile/Library/CallHistoryDB/CallHistory.storedata" && c[5] === "3"));
    assert.ok(comm.some((c) => c[1] === "private/var/mobile/Library/SMS/sms.db" && c[5] === "0"));
    assert.ok(comm.some((c) => c[1] === "private/var/mobile/Library/SMS/sms.db" && c[5] === "4"), "the second occurrence is its own row");
    // The scratch grouping file is gone.
    assert.equal(await exists(join(out, "sqlite-families.work.db")), false);
  });
});

const IOS = "private/var/mobile/Library";

test("ios-filesystem is complete only when the end-of-archive block came, and a header the library refuses ends the listing in the open", async () => {
  // A tar cut at a member boundary, in the middle of a header, or at a header with a bad checksum was complete unless the cut fell inside data.
  await withCwd(async (cwd) => {
    const members = [0, 1, 2, 3].map((i) => ({ name: `${IOS}/SMS/m${i}.db`, size: 600 }));   // a header and 1024 bytes of data: 1536 bytes each
    const run = async (name: string, spec: Record<string, unknown>): Promise<Coverage> => {
      const tar = join(cwd, "work", `${name}.tar`);
      await build(TARX, tar, JSON.stringify({ members, ...spec }));
      const out = join(cwd, name);
      const result = await recipe("ios-filesystem", ["run", "--target", target(tar), "--out", out], cwd);
      assert.equal(result.code, 0, result.stdout + result.stderr);
      return coverage(out);
    };
    const whole = await run("whole", {});
    assert.equal(whole.status, "complete", JSON.stringify(whole));
    assert.equal(whole.covered, "4 tar members; 0 forensic structures; 4 SQLite families");
    const noEnd = await run("noend", { end: false });
    assert.equal(noEnd.status, "partial");
    assert.equal(noEnd.tar_end, "missing");
    assert.ok(noEnd.errors.some((e) => /without its end-of-archive block/.test(e)), JSON.stringify(noEnd.errors));
    const cutHeader = await run("cuthead", { cut_at: 3 * 1536 + 200 });
    assert.equal(cutHeader.status, "partial", JSON.stringify(cutHeader));
    assert.equal(cutHeader.tar_end, "missing");
    const bad = await run("badsum", { members: members.map((m, i) => (i === 1 ? { ...m, bad_checksum: true } : m)) });
    assert.equal(bad.status, "partial", JSON.stringify(bad));
    assert.ok(bad.errors.some((e) => /the tar header at offset 1536 is not one the tar reader accepts .*after 1 members/.test(e)), JSON.stringify(bad.errors));
    assert.equal(bad.covered, "1 tar members; 0 forensic structures; 1 SQLite families");
    assert.equal(whole.tar_end, "reached");
    // A compressed tar is read the same way: whole is complete; a stream cut off before its end marker is partial.
    for (const compress of ["gz", "xz", "bz2"]) {
      const packed = await run(`whole-${compress}`, { compress });
      assert.equal(packed.status, "complete", `${compress}: ${JSON.stringify(packed)}`);
      assert.equal(packed.tar_end, "reached");
      // A stream cut before its end marker: the members it still decodes are listed and the run is partial; one that decodes nothing (bzip2 decodes whole blocks) is not a tar, and says why.
      const cutTar = join(cwd, "work", `cut-${compress}.tar`);
      await build(TARX, cutTar, JSON.stringify({ members, compress, cut_compressed: -12 }));
      const cutRun = await recipe("ios-filesystem", ["run", "--target", target(cutTar), "--out", join(cwd, `cut-${compress}`)], cwd);
      if (cutRun.code === 0) {
        const cutCov = await coverage(join(cwd, `cut-${compress}`));
        assert.equal(cutCov.status, "partial", `${compress}: ${JSON.stringify(cutCov)}`);
        assert.ok(cutCov.errors.some((e) => /cut short or damaged|without its end-of-archive block/.test(e)), JSON.stringify(cutCov.errors));
      } else {
        assert.match(JSON.parse(cutRun.stdout).why, /stream ends before its end marker/, `${compress}: ${cutRun.stdout}`);
      }
    }
  });
});

test("ios-filesystem finds the main database of a family that has no SQLite suffix, and says what a link is", async () => {
  // The base of a -wal was a family member only if it ended in .db, .sqlite and so on: CloudKit's `db`, with `db-wal` beside it, showed no size.
  await withCwd(async (cwd) => {
    const tar = join(cwd, "work", "families.tar");
    await build(TARX, tar, JSON.stringify({ members: [
      { name: `${IOS}/CloudKit/cloudd_db/db`, size: 4096 },
      { name: `${IOS}/CloudKit/cloudd_db/db-wal`, size: 100 },
      { name: `${IOS}/CloudKit/cloudd_db/db-shm`, size: 32768 },
      { name: `${IOS}/Telegram/accounts/db_sqlite`, size: 500 },
      { name: `${IOS}/SMS/sms.db`, size: 16 },
      { name: `${IOS}/SMS/sms.db-wal`, type: "symlink", link: "/etc/passwd" },
      { name: `${IOS}/SMS/hard.db`, type: "hardlink", link: `${IOS}/SMS/sms.db` },
      { name: `${IOS}/SMS/sym.db`, type: "symlink", link: `${IOS}/SMS/sms.db` },
    ] }));
    const out = join(cwd, "families");
    assert.equal((await recipe("ios-filesystem", ["run", "--target", target(tar), "--out", out], cwd)).code, 0);
    const rows = Object.fromEntries((await readFile(join(out, "sqlite.tsv"), "utf8")).trimEnd().split("\n").slice(1).map((l) => { const c = l.split("\t"); return [c[0], c]; }));
    const cloud = rows[`${IOS}/CloudKit/cloudd_db/db`];
    assert.ok(cloud, Object.keys(rows).join("\n"));
    assert.deepEqual([cloud[1], cloud[2], cloud[3], cloud[6], cloud[7]], ["4096", "100", "32768", "db=0,wal=1,shm=2", "db=file,wal=file,shm=file"]);
    assert.equal(rows[`${IOS}/Telegram/accounts/db_sqlite`], undefined, "a database with no suffix and no companion is not found by its name");
    assert.match(await readFile(join(out, "index.tsv"), "utf8"), /a database with no suffix and no companion is not found by its name/);
    // A link has the size 0 and is not an empty database: its type says so.
    assert.equal(rows[`${IOS}/SMS/sms.db`][7], "db=file,wal=symlink");
    assert.equal(rows[`${IOS}/SMS/hard.db`][7], "db=hardlink");
    assert.equal(rows[`${IOS}/SMS/sym.db`][7], "db=symlink");
  });
});

test("ios-filesystem does not read an extended header that declares more than it will hold", async () => {
  // A 600-byte header that declares a 200 MiB GNU long name took 648 MB and was complete.
  await withCwd(async (cwd) => {
    for (const compress of ["none", "gz"]) {
      const tar = join(cwd, "work", `long-${compress}.tar`);
      await build(TARX, tar, JSON.stringify({ compress, long_header_last: 200 * 1024 * 1024, end: false, members: [{ name: `${IOS}/SMS/sms.db`, size: 16 }] }));
      const out = join(cwd, `long-${compress}`);
      const { result, maxrss } = await measuredRecipe("ios-filesystem", ["run", "--target", target(tar), "--out", out], cwd);
      assert.equal(result.code, 0, result.stdout + result.stderr);
      const cov = await coverage(out);
      assert.equal(cov.status, "partial", JSON.stringify(cov));
      assert.ok(cov.limits_hit.some((l) => /extended header at offset 1024 declares 209715200 bytes, over the limit of 16777216: it is not read, and the listing stopped after 1 members/.test(l)), JSON.stringify(cov.limits_hit));
      assert.equal(cov.covered, "1 tar members; 1 forensic structures; 1 SQLite families");
      assert.ok(maxrss < 100 * 1024 * 1024, `${compress}: ${maxrss} bytes resident`);
    }
    // A file that is not a tar is refused at its first header.
    const zeros = join(cwd, "work", "zeros.bin");
    await writeFile(zeros, Buffer.alloc(1 << 20));
    const none = JSON.parse((await recipe("ios-filesystem", ["detect", "--target", target(zeros)], cwd)).stdout) as { applies: boolean; why: string };
    assert.equal(none.applies, false);
    assert.match(none.why, /^not a readable tar/);
  });
});

const RECIPE_FILES = ["android-backup", "ios-filesystem", "ios-ileapp", "android-aleapp"];

test("the tar watch is the same code in the four recipes that read a tar, and the tar listing in the three that open one by its path", async () => {
  const between = (text: string, start: string, end: string): string => {
    const a = text.indexOf(start);
    const b = text.indexOf(end, a);
    assert.ok(a >= 0 && b > a, `${start} ... ${end} not found`);
    return text.slice(a, b);
  };
  const texts = new Map<string, string>();
  for (const name of RECIPE_FILES) texts.set(name, await readFile(join(RECIPES, name, "run.py"), "utf8"));
  const watch = RECIPE_FILES.map((n) => between(texts.get(n) as string, "# --- tar watch: begin", "# --- tar watch: end"));
  for (const copy of watch.slice(1)) assert.equal(copy, watch[0]);
  const listing = RECIPE_FILES.filter((n) => n !== "android-backup").map((n) => between(texts.get(n) as string, "# --- tar listing: begin", "# --- tar listing: end"));
  for (const copy of listing.slice(1)) assert.equal(copy, listing[0]);
  assert.equal((texts.get("android-backup") as string).includes("# --- tar listing: begin"), false);
});

/** The watch against the tar library: archives of every shape the library writes and some it reads, whole and damaged. */
const DIFFERENTIAL = String.raw`
import io, random, struct, sys, tarfile
text = open(sys.argv[1], encoding="utf-8").read()
start = text.index("# --- tar watch: begin")
end = text.index("# --- tar watch: end")
exec(compile(text[start:end], "watch", "exec"))
rnd = random.Random(20261007)

def build(fmt):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=fmt, encoding="utf-8") as t:
        for i in range(rnd.randint(1, 8)):
            kind = rnd.choice(["file", "file", "file", "dir", "symlink", "hardlink", "longname", "unicode", "bigmtime"])
            name = "d%d/" % i + {"longname": "n" * rnd.randint(101, 400), "unicode": "café-中文-%d" % i}.get(kind, "f%d" % i)
            info = tarfile.TarInfo(name)
            info.mtime = 1700000000.5 if kind == "bigmtime" else 1700000000
            data = b""
            if kind == "dir":
                info.type = tarfile.DIRTYPE
            elif kind in ("symlink", "hardlink"):
                info.type = tarfile.SYMTYPE if kind == "symlink" else tarfile.LNKTYPE
                info.linkname = "d0/f0" if kind == "hardlink" else "x" * rnd.choice([5, 150])
            else:
                data = bytes(rnd.getrandbits(8) for _ in range(rnd.choice([0, 1, 511, 512, 513, 2000])))
                info.size = len(data)
            try:
                t.addfile(info, io.BytesIO(data))
            except ValueError:
                pass
    return buf.getvalue()

def listing(raw):
    names = []
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as t:
            for m in t:
                names.append(m.name)
                t.members = []
    except tarfile.TarError:
        pass
    return names

def walked(raw):
    w = TarWatch()
    w.walk(io.BytesIO(raw), len(raw))
    return w

def fed(raw):
    w = TarWatch()
    i = 0
    while i < len(raw):
        n = rnd.choice([1, 7, 511, 512, 513, 4096, 10240])
        w.feed(raw[i:i + n])
        i += n
    return w

checked = 0
bad = []
for fmt in (tarfile.GNU_FORMAT, tarfile.PAX_FORMAT, tarfile.USTAR_FORMAT):
    for _ in range(40):
        raw = build(fmt)
        cases = [("whole", raw)]
        cases.append(("cut-boundary", raw[:512 * rnd.randint(1, max(1, len(raw) // 512 - 2))]))
        cases.append(("cut-anywhere", raw[:rnd.randint(1, len(raw) - 1)]))
        flipped = bytearray(raw)
        flipped[rnd.randrange(0, min(len(flipped), 1536))] ^= 0x55
        cases.append(("flipped", bytes(flipped)))
        for label, data in cases:
            if not data:
                continue
            names = listing(data)
            for how, w in (("walk", walked(data)), ("feed", fed(data))):
                checked += 1
                if w.members != len(names):
                    bad.append("%s %s %s: library %d, watch %d" % (fmt, label, how, len(names), w.members))
                if label == "whole" and not (w.ended and w.members == len(names)):
                    bad.append("%s whole %s: end block not seen" % (fmt, how))
                if label == "cut-anywhere" and w.ended and data[-1024:] != b"\0" * 1024 and w.end_at is not None and w.end_at + 512 > len(data):
                    bad.append("%s cut %s: end block beyond the data" % (fmt, how))
print("CHECKED", checked)
for line in bad[:10]:
    print("DIFF", line)
sys.exit(1 if bad else 0)
`;

test("the tar watch counts what the tar library lists, for every format the library writes, whole and damaged, walked and fed", async () => {
  const out = await runPySnippet(DIFFERENTIAL, [join(RECIPES, "ios-filesystem", "run.py")], null);
  assert.equal(out.code, 0, out.stdout + out.stderr);
  assert.match(out.stdout, /CHECKED \d{3,}/);
});

test("the module receipt of the two LEAPP recipes is the same code", async () => {
  const between = (text: string, start: string, end: string): string => {
    const a = text.indexOf(start);
    const b = text.indexOf(end, a);
    assert.ok(a >= 0 && b > a, `${start} ... ${end} not found`);
    return text.slice(a, b);
  };
  const ios = await readFile(join(RECIPES, "ios-ileapp", "run.py"), "utf8");
  const android = await readFile(join(RECIPES, "android-aleapp", "run.py"), "utf8");
  const receipt = (t: string): string => between(t, "# The log lines a LEAPP", "# --- end of the module receipt").replace(/held equal to the one in the \w+ recipe/, "");
  assert.equal(receipt(ios), receipt(android));
});

