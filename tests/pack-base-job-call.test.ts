/**
 * computer-forensics-base, called the way a job calls it: the working directory is the run's root and every path is
 * relative to it, with spaces in it (store/jobs/<id>/out/tree/.../User Data/...). A tool that works only from its
 * own directory, or only with an absolute path, has no working call in a job: browser_storage gave its reader, which
 * runs with / as its working directory, the caller's relative path, and failed 8 calls of 8 with FileNotFoundError
 * in every data file (Batman III runs, finding I-11), and its answer hid the path it was given behind the
 * withholding. The same form is held here for catalog_search and for the ad1-items recipe.
 *
 * The other two parts hold what a catalogue search and a catalogue's coverage record claim (finding I-10):
 * catalog_search over a list its generation calls partial is partial, never `complete` with 0 matches, and
 * ad1-items writes `covered` from what it read.
 *
 * browser_storage's reader (ccl_chromium_reader) is not on every host. The reader here is a stand-in that does the
 * one thing the defect was about: it opens each data file by the path the tool handed it, from the working directory
 * the tool gave it, and says whether it could. The pack's own tests run the real reader where its venv is
 * (packs/computer-forensics-base/tests/test_browser_storage.py, JobForm).
 */
import assert from "node:assert/strict";
import { chmod, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { test } from "node:test";
import { ad1Data, ad1Image, ad1Segments } from "./ad1-fixture.ts";
import { PYTHON3 } from "./host-gates.ts";
import { runPy } from "./tool-library-harness.ts";

// PACK_DIR points the suite at another copy of the pack (the way a fix is shown to fail on the code before it), as the pack's own tests take it.
const CFB = process.env.PACK_DIR || join(import.meta.dirname, "..", "packs", "computer-forensics-base");
const CATALOG_SEARCH = join(CFB, "tools", "catalog_search", "run.py");
const BROWSER_STORAGE = join(CFB, "tools", "browser_storage", "run.py");
const AD1_ITEMS = join(CFB, "recipes", "ad1-items", "run.py");

type Answer = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

/** A run root: catalog/, store/ and inputs/ under a directory whose own name has a space too. */
async function withRun(fn: (run: string) => Promise<void>): Promise<void> {
  // /tmp on macOS: its per-user temporary directory holds a token-shaped part, which the tools withhold from a path they print.
  const top = await realpath(await mkdtemp(join(process.platform === "darwin" ? "/tmp" : tmpdir(), "job-call-")));
  const run = join(top, "run root");
  try {
    for (const d of ["catalog", "store/jobs", "inputs", "work"]) await mkdir(join(run, d), { recursive: true });
    await fn(run);
  } finally {
    await rm(top, { recursive: true, force: true });
  }
}

const json = (r: { stdout: string; stderr: string }): Answer => {
  try {
    return JSON.parse(r.stdout) as Answer;
  } catch {
    throw new Error(`not one JSON answer: ${r.stdout.slice(0, 400)} ${r.stderr.slice(0, 400)}`);
  }
};

const MEMBERS = "n\ttype\tpath\n0\tdir\tC:\n1\tfile\tC:/Users/alice/notes.txt\n2\tfile\tC:/Users/alice/holiday.avi\n";
const SEGMENT_ERROR = "the image has 12 segments and 11 of them (case.ad2, case.ad3, ..., case.ad12) are not there, beside the first or in this job's view: what lies in them is not read";

/** An ad1-items coverage record as the recipe writes it, complete or with segments missing. */
function coverage(partial: boolean): Answer {
  return {
    recipe: "ad1-items", format: "AD1", items: 3, files: 2, folders: 1, checked: 2,
    segments_missing: partial ? ["case.ad2", "case.ad3"] : [],
    covered: "what was read",
    not_covered: partial ? "of this image: the items in the segments that are not there. Of any AD1 image: unallocated space" : "unallocated space",
    limits_hit: [], errors: partial ? [SEGMENT_ERROR] : [],
    status: partial ? "partial" : "complete",
    status_basis: partial ? "a segment is missing" : "every item of the tree was listed",
  };
}

/** A catalogue as the harness publishes one generation: catalog/gen/g0001/, the same files at catalog/<alias>/, and a revision that lists it. */
async function catalogue(run: string, alias: string, cov: Answer | null, opts: { index?: boolean; status?: string } = {}): Promise<void> {
  for (const d of [join(run, "catalog", "gen", "g0001"), join(run, "catalog", alias)]) {
    await mkdir(d, { recursive: true });
    await writeFile(join(d, "members.tsv"), MEMBERS);
    if (cov) await writeFile(join(d, "coverage.json"), JSON.stringify(cov, null, 2));
  }
  await mkdir(join(run, "catalog", "revisions", "1"), { recursive: true });
  const generation = { id: "g0001", recipe: "computer-forensics-base/ad1-items", target: { ref: "input:My Images/case one.ad1" }, status: opts.status ?? cov?.status ?? "unknown", coverage: cov, alias: `catalog/${alias}`, trigger: "kickoff" };
  await writeFile(join(run, "catalog", "revisions", "1", "index.json"), JSON.stringify({ revision: 1, generations: opts.index === false ? [] : [generation] }));
  await writeFile(join(run, "catalog", "revisions", "1", "MANIFEST.json"), "{}");
}

const JOB = (run: string, id = "j000007") => ({ JOB_ID: id, OUT: join(run, "store", "jobs", id, "out"), AGENT_ID: "s0000001" });

// ---- catalog_search: the list's own status goes with every answer (I-10) --------------------------------------------------------

test("catalog_search over a partial generation is partial: 0 matches is a lower bound, never complete (I-10)", async () => {
  await withRun(async (run) => {
    await catalogue(run, "My Images_case one.ad1", coverage(true));
    // The call of the runs: a pattern the partial list does not hold. It was complete, "every line of the catalogue file was searched".
    for (const args of [{ pattern: "\\.mkv", which: "members" }, { pattern: "\\.mkv", which: "members", catalog: "g0001" }, { pattern: "\\.mkv", which: "members", catalog: "catalog/My Images_case one.ad1" }]) {
      const r = await runPy(CATALOG_SEARCH, run, args, undefined, JOB(run));
      const a = json(r);
      assert.equal(r.code, 0, r.stdout);
      assert.equal(a.matched, 0);
      assert.equal(a.complete, false, JSON.stringify(args));
      assert.equal(a.status, "partial");
      assert.match(a.status_basis, /^the list searched is partial \(generation g0001, computer-forensics-base\/ad1-items\): the image has 12 segments and 11 of them/);
      assert.match(a.status_basis, /matched is a lower bound over the object and 0 matches is not an absence$/);
      assert.equal(a.generation.id, "g0001");
      assert.equal(a.generation.status, "partial");
      assert.equal(a.generation.object, "input:My Images/case one.ad1");
      assert.match(a.generation.not_covered, /the items in the segments that are not there/);
      assert.ok(a.generation.why.includes(SEGMENT_ERROR), "the generation's own reason is carried");
      assert.ok(a.generation.why.some((w: string) => /^segments_missing: case\.ad2$/.test(w)));
    }
    // A match in a partial list is a match, and the answer is still partial.
    const hit = json(await runPy(CATALOG_SEARCH, run, { pattern: "\\.avi$", which: "members" }, undefined, JOB(run)));
    assert.equal(hit.matched, 1);
    assert.equal(hit.hits[0].line, "2\tfile\tC:/Users/alice/holiday.avi");
    assert.deepEqual([hit.complete, hit.status], [false, "partial"]);
    assert.match(hit.status_basis, /this page holds 1 of the 1 matches/);
  });
});

test("catalog_search over a complete generation is complete and says what the list does not cover; a list with no record says so", async () => {
  await withRun(async (run) => {
    await catalogue(run, "case.ad1", coverage(false));
    let a = json(await runPy(CATALOG_SEARCH, run, { pattern: "notes", which: "members" }, undefined, JOB(run)));
    assert.deepEqual([a.matched, a.complete, a.status], [1, true, "complete"]);
    assert.deepEqual([a.generation.id, a.generation.status, a.generation.not_covered], ["g0001", "complete", "unallocated space"]);
    assert.equal(a.generation.why, undefined, "a complete list carries no reasons");
    assert.equal(a.list_partial, undefined);
    assert.match(a.status_basis, /every line of the catalogue file was searched; .*The list is complete as its coverage record says/);
  });
  await withRun(async (run) => {
    // A catalogue directory with a list and nothing that says how far the list goes (no coverage.json, no generation).
    await mkdir(join(run, "catalog", "old case", "p2048"), { recursive: true });
    await writeFile(join(run, "catalog", "old case", "p2048", "filelist.txt"), "r/r 5: Users/a/NTUSER.DAT\n");
    const a = json(await runPy(CATALOG_SEARCH, run, { pattern: "ntuser" }, undefined, JOB(run)));
    assert.deepEqual([a.matched, a.complete, a.status], [1, true, "complete"]);
    assert.deepEqual(a.generation, { status: "not recorded" });
    assert.match(a.status_basis, /Nothing records whether the list itself is whole .*complete over the list's text, not over the object/);
  });
});

test("catalog_search takes the status that is not complete from either record, and a record it cannot read is not a complete list", async () => {
  // The revision's index says complete; the coverage record beside the list says partial (or the other way round): partial.
  for (const [indexed, beside] of [["complete", true], ["partial", false]] as Array<[string, boolean]>) {
    await withRun(async (run) => {
      await catalogue(run, "case.ad1", coverage(beside), { status: indexed });
      const index = JSON.parse(await readFile(join(run, "catalog", "revisions", "1", "index.json"), "utf8"));
      index.generations[0].coverage = coverage(indexed === "partial");
      await writeFile(join(run, "catalog", "revisions", "1", "index.json"), JSON.stringify(index));
      const a = json(await runPy(CATALOG_SEARCH, run, { pattern: "x", which: "members" }, undefined, JOB(run)));
      assert.deepEqual([a.complete, a.status, a.generation.status], [false, "partial", "partial"], `${indexed} in the index`);
    });
  }
  // No generation in the revision read, and the record beside the list alone says partial.
  await withRun(async (run) => {
    await catalogue(run, "case.ad1", coverage(true), { index: false });
    const a = json(await runPy(CATALOG_SEARCH, run, { pattern: "x", which: "members", catalog: "case.ad1" }, undefined, JOB(run)));
    assert.deepEqual([a.complete, a.status, a.generation.status], [false, "partial", "partial"]);
    assert.equal(a.generation.id, undefined);
    assert.match(a.status_basis, /^the list searched is partial \(its coverage record, ad1-items\)/);
  });
  // A coverage record that is not JSON, and one that gives no status: whether the list is whole is not known, so the answer is not complete.
  for (const text of ["{not json", JSON.stringify({ recipe: "ad1-items" }), JSON.stringify([1])]) {
    await withRun(async (run) => {
      await catalogue(run, "case.ad1", null, { index: false });
      await writeFile(join(run, "catalog", "case.ad1", "coverage.json"), text);
      const a = json(await runPy(CATALOG_SEARCH, run, { pattern: "notes", which: "members", catalog: "case.ad1" }, undefined, JOB(run)));
      assert.deepEqual([a.matched, a.complete, a.status, a.generation.status], [1, false, "partial", "unknown"], text);
      assert.match(a.status_basis, /^whether the list searched is whole is not known/);
    });
  }
  // A generation the harness recorded as failed is not a complete list either.
  await withRun(async (run) => {
    await catalogue(run, "case.ad1", { ...coverage(true), status: "failed" });
    const a = json(await runPy(CATALOG_SEARCH, run, { pattern: "notes", which: "members" }, undefined, JOB(run)));
    assert.deepEqual([a.complete, a.status, a.generation.status], [false, "partial", "failed"]);
    assert.match(a.status_basis, /^the list searched is failed \(generation g0001/);
  });
});

test("catalog_search bounds the reasons it repeats from a generation's record", async () => {
  await withRun(async (run) => {
    const cov = coverage(true);
    cov.errors = Array.from({ length: 40 }, (_, i) => `item ${i} cannot be read: ${"x".repeat(900)}`);
    await catalogue(run, "case.ad1", cov);
    const a = json(await runPy(CATALOG_SEARCH, run, { pattern: "notes", which: "members" }, undefined, JOB(run)));
    assert.equal(a.generation.why.length, 5);
    assert.equal(a.generation.why_total, 43, "40 errors, two missing segments and the record's own basis");
    assert.ok(a.generation.why.every((w: string) => w.length <= 403));
    assert.ok(JSON.stringify(a).length < 8000, "the answer does not carry the whole record");
  });
});

test("catalog_search with no which on a member-list catalogue (an AD1 image's) names which: \"members\" in its refusal", async () => {
  await withRun(async (run) => {
    await catalogue(run, "case.ad1", coverage(false));
    let r = await runPy(CATALOG_SEARCH, run, { pattern: "notes" }, undefined, JOB(run));
    let a = json(r);
    assert.equal(r.code, 1);
    assert.deepEqual([a.ok, a.status], [false, "failed"]);
    assert.match(a.error, /holds no filesystem listing: it is a member list \(members\.tsv, an archive's or an AD1 image's\), and which=filelist reads a disk's\. Pass which: "members" to search it/);
    assert.deepEqual(a.try, { which: "members" });
    assert.equal(a.which_defaulted, true);
    r = await runPy(CATALOG_SEARCH, run, { pattern: "notes", which: "timeline" }, undefined, JOB(run));
    a = json(r);
    assert.match(a.error, /which=timeline reads a disk's\. Pass which: "members"/);
    assert.equal(a.which_defaulted, false);
    // What the refusal names works.
    a = json(await runPy(CATALOG_SEARCH, run, { pattern: "notes", ...a.try }, undefined, JOB(run)));
    assert.equal(a.matched, 1);
    // partitions on a member-list catalogue: the file is not there, and the refusal names the list that is.
    a = json(await runPy(CATALOG_SEARCH, run, { pattern: "x", which: "partitions" }, undefined, JOB(run)));
    assert.match(a.error, /partitions\.txt is not in the catalogue; it holds a member list: pass which: "members"/);
    assert.deepEqual(a.try, { which: "members" });
  });
  // A catalogue with neither keeps the refusal it had.
  await withRun(async (run) => {
    await mkdir(join(run, "catalog", "empty"), { recursive: true });
    const a = json(await runPy(CATALOG_SEARCH, run, { pattern: "x" }, undefined, JOB(run)));
    assert.match(a.error, /holds no filesystem listing \(see its partitions\.txt and README\.md\)/);
    assert.equal(a.try, undefined);
  });
});

// ---- ad1-items: covered is what was read (I-10, the record) --------------------------------------------------------------------

function recipe(cwd: string, target: string[], out: string, env: Record<string, string> = {}): { code: number | null; answer: Answer; cov: Answer } {
  const r = spawnSync(PYTHON3, [AD1_ITEMS, "run", "--target", JSON.stringify({ paths: target }), "--out", out], { cwd, encoding: "utf8", env: { ...process.env, ...env } });
  const cov = JSON.parse(spawnSync("cat", [join(cwd, out, "coverage.json")], { encoding: "utf8" }).stdout || "{}") as Answer;
  return { code: r.status, answer: JSON.parse(r.stdout.trim().split("\n").pop() || "{}") as Answer, cov };
}

// The big file does not compress, so that the image spans several 64 KiB segments.
const TREE = [{ name: "C:", folder: true, children: [
  { name: "Program Files", folder: true, children: [{ name: "big.bin", content: randomBytes(150000) }] },
  { name: "Users", folder: true, children: [{ name: "notes.txt", content: Buffer.from("after the big one") }] },
] }];

test("ad1-items writes covered and not_covered from what it read: a partial read is never described as every item of the tree", async () => {
  await withRun(async (run) => {
    const dir = join(run, "inputs", "My Images");
    await mkdir(dir, { recursive: true });
    const segs = ad1Segments(ad1Data(TREE).data, 65536);
    assert.ok(segs.length >= 3);
    for (const [i, s] of segs.entries()) await writeFile(join(dir, `case one.ad${i + 1}`), s);
    const first = "inputs/My Images/case one.ad1";

    // Whole: every item, as before, now with the counts it rests on.
    const whole = recipe(run, [first], "store/jobs/j000001/out");
    assert.equal(whole.cov.status, "complete", JSON.stringify(whole.cov));
    assert.equal(whole.cov.covered, "every item of the image's tree (5: 2 files, 3 folders), with its metadata, and each of those files' content inflated and checked against the digests the image records");
    assert.doesNotMatch(whole.cov.not_covered, /^of this image/);
    assert.match(whole.cov.not_covered, /^anything the imager did not put in the image/);

    // The last segment gone: status partial, and covered says how many items, not "every item".
    await rm(join(dir, `case one.ad${segs.length}`));
    const short = recipe(run, [first], "store/jobs/j000002/out");
    assert.equal(short.cov.status, "partial");
    assert.deepEqual(short.cov.segments_missing, [`case one.ad${segs.length}`]);
    assert.doesNotMatch(short.cov.covered, /every item/);
    assert.match(short.cov.covered, new RegExp(`^the ${short.cov.items} item\\(s\\) of the image's tree that this run listed \\(${short.cov.files} files, ${short.cov.folders} folders\\), with their metadata, which is not the whole tree \\(see not_covered\\)`));
    assert.match(short.cov.not_covered, /^of this image: the items and the content that lie in the 1 segment\(s\) that are not there \(segments_missing\)/);
    assert.match(short.cov.not_covered, /\. Of any AD1 image: anything the imager did not put in the image/);
    assert.ok(short.cov.items < 5 || short.cov.checked < short.cov.files, "the fixture loses something with its last segment");

    // Only the first segment, as the old kickoff gave it: the same, and what is not inflated is counted.
    for (let k = 2; k < segs.length; k += 1) await rm(join(dir, `case one.ad${k}`));
    const one = recipe(run, [first], "store/jobs/j000003/out");
    assert.equal(one.cov.status, "partial");
    assert.doesNotMatch(one.cov.covered, /every item/);
    assert.match(one.cov.not_covered, new RegExp(`^of this image: the items and the content that lie in the ${segs.length - 1} segment\\(s\\) that are not there`));
  });
});

test("ad1-items past its time limit says how many files' content it inflated, and a listing cut at a limit says the tree is not whole", async () => {
  await withRun(async (run) => {
    await writeFile(join(run, "inputs", "case.ad1"), ad1Image(TREE));
    const late = recipe(run, ["inputs/case.ad1"], "store/jobs/j000001/out", { RECIPE_SECONDS: "0", RECIPE_LISTING_SECONDS: "600" });
    assert.equal(late.cov.status, "partial");
    assert.equal(late.cov.covered, "every item of the image's tree (5: 2 files, 3 folders), with its metadata, and the content of 0 of those 2 file(s) inflated, 0 of them compared with the digests the image records");
    assert.match(late.cov.not_covered, /^of this image: the content of 2 listed file\(s\), which was not inflated or not inflated to its end \(check not-read; 2 of them at the time limit\)\. Of any AD1 image: /);
    const cut = recipe(run, ["inputs/case.ad1"], "store/jobs/j000002/out", { RECIPE_SECONDS: "0", RECIPE_LISTING_SECONDS: "0" });
    assert.equal(cut.cov.status, "partial");
    assert.equal(cut.cov.items, 1, "the listing's clock lets the first item through and stops");
    assert.match(cut.cov.covered, /^the 1 item\(s\) of the image's tree that this run listed \(0 files, 1 folders\), with their metadata, which is not the whole tree/);
    assert.match(cut.cov.not_covered, /^of this image: every item after the 1 listed, in the image's order \(the listing stopped at a limit: limits_hit\)/);
  });
});

// ---- the job form: cwd is the run root, the path is run-relative and has spaces (E12, I-11) ---------------------------------------

/** A DFIRSWARM_SRC_DIR whose ccl_indexeddb_dump venv python is a stand-in for the reader's process (see the head of this file). */
async function standInReader(run: string): Promise<string> {
  const src = join(run, "work", "src");
  const bin = join(src, "ccl_indexeddb_dump", ".venv", "bin");
  await mkdir(bin, { recursive: true });
  const body = join(src, "reader.py");
  await writeFile(body, [
    "import json, os, sys",
    "spec = json.load(sys.stdin)",
    "files = []",
    "for name, kind in spec['files']:",
    "    entry = {'name': name, 'kind': kind, 'size': None, 'records': 0, 'put': 0, 'delete': 0, 'unknown': 0, 'records_in_compressed_blocks': 0, 'status': 'read'}",
    "    try:",
    "        fd = os.open(os.path.join(spec['path'], name), os.O_RDONLY | os.O_NOFOLLOW)",
    "        entry['size'] = os.fstat(fd).st_size",
    "        os.close(fd)",
    "    except OSError as exc:",
    "        entry.update({'status': 'failed', 'stage': 'open', 'error_class': type(exc).__name__})",
    "    files.append(entry)",
    "print(json.dumps({'ok': True, 'versions': {'cwd': os.getcwd(), 'path_is_absolute': os.path.isabs(spec['path'])}, 'files': files, 'format': 'leveldb',",
    "                  'records_total': 0, 'counts': {}, 'previews': [], 'decode_errors': {}, 'leveldb': {}}))",
  ].join("\n") + "\n");
  // The tool starts it as: <python> -I -c <the reader's code>, with the specification on stdin; the stand-in takes the stdin and ignores the code.
  await writeFile(join(bin, "python"), `#!/bin/sh\nexec '${PYTHON3}' '${body}'\n`);
  await chmod(join(bin, "python"), 0o755);
  return src;
}

const STORE = "store/jobs/j000005/out/tree/Users/Bruce Wayne/AppData/Local/Google/Chrome/User Data/Default/IndexedDB/https_app.example_0.indexeddb.leveldb";

test("browser_storage in a job's form: a run-relative path with spaces reaches the reader, which runs elsewhere, and the answer names the path as given (I-11)", async () => {
  await withRun(async (run) => {
    const src = await standInReader(run);
    await mkdir(join(run, STORE), { recursive: true });
    await writeFile(join(run, STORE, "000003.log"), Buffer.alloc(64, 1));
    await writeFile(join(run, STORE, "000005.ldb"), Buffer.alloc(128, 2));
    await writeFile(join(run, STORE, "MANIFEST-000001"), Buffer.alloc(16, 3));
    const r = await runPy(BROWSER_STORAGE, run, { path: STORE }, undefined, { ...JOB(run), DFIRSWARM_SRC_DIR: src });
    const a = json(r);
    assert.equal(a.reader.cwd, "/", "the reader's process does not run in the caller's directory");
    assert.equal(a.reader.path_is_absolute, true, "so it is given the directory by an absolute path");
    assert.deepEqual(a.files.map((f: Answer) => [f.name, f.status, f.size, f.error_class]), [["000003.log", "read", 64, undefined], ["000005.ldb", "read", 128, undefined]], "every data file the tool listed is one the reader could open");
    assert.notEqual(a.status, "failed", a.status_basis);
    // The answer repeats the caller's own argument, whole: it was "<token-shaped text withheld 85 characters> Data/Default/...".
    assert.equal(a.path, STORE);
    assert.doesNotMatch(JSON.stringify(a), /withheld \d+ characters> Data/);
  });
});

test("browser_storage names the path as given in its refusals too, and still escapes what could break a line", async () => {
  await withRun(async (run) => {
    const src = await standInReader(run);
    const absent = STORE.replace("Default", "Profile 1");
    let a = json(await runPy(BROWSER_STORAGE, run, { path: absent }, undefined, { ...JOB(run), DFIRSWARM_SRC_DIR: src }));
    assert.deepEqual([a.status, a.path], ["failed", absent]);
    // The shape of the path of the runs: up to its first space it is one token-shaped run to the shape rules, and was printed as a marker.
    const long = "store/jobs/j000044/out/q7-selected/Users/ExampleUser/AppData/Local/Google/Chrome/User Data/Default/Local Storage/leveldb";
    a = json(await runPy(BROWSER_STORAGE, run, { path: long }, undefined, { ...JOB(run), DFIRSWARM_SRC_DIR: src }));
    assert.deepEqual([a.status, a.path], ["failed", long]);
    await mkdir(join(run, STORE), { recursive: true });
    a = json(await runPy(BROWSER_STORAGE, run, { path: STORE }, undefined, { ...JOB(run), DFIRSWARM_SRC_DIR: src }));
    assert.deepEqual([a.status, a.unsupported, a.path], ["failed", "no LevelDB data files", STORE]);
    a = json(await runPy(BROWSER_STORAGE, run, { path: "store/a\tb​/c\nd" }, undefined, { ...JOB(run), DFIRSWARM_SRC_DIR: src }));
    assert.equal(a.path, "store/a\\tb/c\\nd", "a tab and a line break are escaped, a zero-width character removed");
    // An absolute path is still taken as it is.
    await writeFile(join(run, STORE, "000003.log"), Buffer.alloc(8, 1));
    a = json(await runPy(BROWSER_STORAGE, run, { path: join(run, STORE) }, undefined, { ...JOB(run), DFIRSWARM_SRC_DIR: src }));
    assert.deepEqual(a.files.map((f: Answer) => f.status), ["read"]);
    assert.equal(a.path, join(run, STORE));
  });
});

test("catalog_search in a job's form: a catalogue named by a run-relative path with spaces, the matches kept under $OUT", async () => {
  await withRun(async (run) => {
    await catalogue(run, "My Images_case one.ad1", coverage(false));
    await mkdir(join(run, "catalog", "Disk Two.E01", "p2048"), { recursive: true });
    await writeFile(join(run, "catalog", "Disk Two.E01", "p2048", "filelist.txt"), Array.from({ length: 60 }, (_, i) => `r/r ${i}: Users/Bruce Wayne/file ${i}.txt`).join("\n") + "\n");
    const env = JOB(run);
    let a = json(await runPy(CATALOG_SEARCH, run, { pattern: "notes", which: "members", catalog: "catalog/My Images_case one.ad1" }, undefined, env));
    assert.deepEqual([a.matched, a.file, a.status], [1, "catalog/My Images_case one.ad1/members.tsv", "complete"]);
    a = json(await runPy(CATALOG_SEARCH, run, { pattern: "Bruce Wayne/file", catalog: "Disk Two.E01", limit: 10 }, undefined, env));
    assert.deepEqual([a.matched, a.returned, a.next_offset], [60, 10, 10]);
    assert.match(a.all_matches, /^store\/jobs\/j000007\/out\/catalog-search\/filelist-[0-9a-f]{16}\.txt$/);
    const kept = await readFile(join(run, a.all_matches), "utf8");
    assert.equal(kept.split("\n").filter(Boolean).length, 60);
  });
});

test("ad1-items in a job's form: a run-relative target and output with spaces", async () => {
  await withRun(async (run) => {
    await mkdir(join(run, "inputs", "My Images"), { recursive: true });
    await writeFile(join(run, "inputs", "My Images", "case one.ad1"), ad1Image(TREE));
    const { code, answer, cov } = recipe(run, ["inputs/My Images/case one.ad1"], "store/jobs/j000001/out dir");
    assert.equal(code, 0);
    assert.deepEqual([answer.ok, answer.status, answer.items], [true, "complete", 5]);
    assert.equal(cov.target, "inputs/My Images/case one.ad1");
    const members = await readFile(join(run, "store/jobs/j000001/out dir/members.tsv"), "utf8");
    assert.match(members, /\tC:\/Users\/notes\.txt\t/);
  });
});
