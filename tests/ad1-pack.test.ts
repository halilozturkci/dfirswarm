/**
 * AD1 in the packs: the base pack's ad1-items recipe lists an AccessData AD1
 * logical image (detect by its headers, every item with its metadata, each
 * file inflated and checked against the digests the image records), and its
 * ad1_extract tool writes the tree out, so that, run as a job, the derived
 * catalogue takes what is inside. The harness learns nothing about AD1: the
 * census and the derived catalogue ask the pack. Every image here is built by
 * tests/ad1-fixture.ts, but one: a real FTK Imager image from Fox-IT's
 * dissect.evidence (tests/fixtures/ad1/), which holds the reader to what FTK
 * Imager writes where the synthetic ones only mirror its assumptions. No case
 * evidence is read.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { deflateSync } from "node:zlib";
import { ad1Data, ad1Image, ad1Item, ad1Logical, ad1Segments, md5, sha1, sha256, type Ad1Node } from "./ad1-fixture.ts";
import { JobService, type JobRecord } from "../scripts/job-service.ts";
import { storePaths, verifyJournalText, type JournalLine } from "../scripts/evidence-store.ts";
import { localWorker } from "./job-service-worker.ts";
import { runPy } from "./tool-library-harness.ts";

const ROOT = join(import.meta.dirname, "..");
const CFB = join(ROOT, "packs", "computer-forensics-base");
const RECIPE = join(CFB, "recipes", "ad1-items", "run.py");
const TOOL = join(CFB, "tools", "ad1_extract", "run.py");
const FTK = join(ROOT, "tests", "fixtures", "ad1", "compressed.ad1");
const B = (s: string) => Buffer.from(s);

const zipBytes = spawnSync("python3", ["-c", "import io,zipfile,sys\nb=io.BytesIO()\nwith zipfile.ZipFile(b,'w') as z: z.writestr('inner.txt','inner')\nsys.stdout.buffer.write(b.getvalue())"]).stdout;
const notes = B("a line of notes\n".repeat(100));

/**
 * The tree most cases use, in the order the image lists it:
 *   0 C:/  1 Users/  2 alice/  3 notes.txt  4 NOTES.txt  5 empty.txt
 *   6 tampered.bin  7 evidence.zip  8 ../  9 climb.txt  10 caf\xe9  11 readme.txt
 */
function tree(): Ad1Node[] {
  return [{
    name: "C:", folder: true, children: [
      { name: "Users", folder: true, children: [
        { name: "alice", folder: true, children: [
          { name: "notes.txt", content: notes },
          { name: "NOTES.txt", content: B("the same name, another case") },
          { name: "empty.txt", content: Buffer.alloc(0) },
          { name: "tampered.bin", content: B("the bytes as they are"), wrongMd5: true },
          { name: "evidence.zip", content: zipBytes },
        ] },
      ] },
      { name: "..", folder: true, children: [{ name: "climb.txt", content: B("x") }] },
      { name: Buffer.from([0x63, 0x61, 0x66, 0xe9]), content: B("a name that is not UTF-8") },
      { name: "readme.txt", content: B("no digests"), meta: [[2, 2, "1"], [5, 9, "20240102T030405"]] },
    ],
  }];
}

function dir(prefix: string): string {
  return mkdtempSync(join(tmpdir(), prefix));
}

function py(script: string, args: string[], env: Record<string, string> = {}): { code: number | null; out: string; err: string } {
  const r = spawnSync("python3", [script, ...args], { encoding: "utf8", env: { ...process.env, ...env } });
  return { code: r.status, out: r.stdout, err: r.stderr };
}

const detect = (path: string, ...extra: string[]) => {
  const r = py(RECIPE, ["detect", "--target", JSON.stringify({ paths: [path], name: path }), ...extra]);
  return { code: r.code, v: JSON.parse(r.out.trim().split("\n").pop() ?? "{}") as { applies: boolean; why: string } };
};

function runRecipe(paths: string[], env: Record<string, string> = {}) {
  const out = dir("ad1-out-");
  const r = py(RECIPE, ["run", "--target", JSON.stringify({ paths }), "--out", out], env);
  const cov = JSON.parse(readFileSync(join(out, "coverage.json"), "utf8")) as Record<string, unknown> & { status: string; errors: string[]; limits_hit: string[]; mismatches: number[] };
  return { r, out, cov };
}

type Row = Record<string, string>;
function tsv(path: string): Row[] {
  // Lines, not the file's trailing whitespace: a last row may end in empty fields.
  const [head, ...lines] = readFileSync(path, "utf8").replace(/\n$/, "").split("\n");
  const cols = head.split("\t");
  return lines.map((l) => Object.fromEntries(l.split("\t").map((v, i) => [cols[i], v])));
}

test("detect takes a version 4 AD1 image by its headers, whatever its name, and says why it turns the rest down", () => {
  const d = dir("ad1-detect-");
  writeFileSync(join(d, "case.ad1"), ad1Image(tree()));
  writeFileSync(join(d, "renamed.bin"), ad1Image(tree()));
  const two = ad1Segments(ad1Data([{ name: "big.bin", content: randomBytes(70000) }]).data, 65536);
  assert.equal(two.length, 2);
  writeFileSync(join(d, "split.ad2"), two[1]);
  writeFileSync(join(d, "enc.ad1"), Buffer.concat([B("ADCRYPT\0"), Buffer.alloc(600)]));
  writeFileSync(join(d, "v3.ad1"), ad1Image(tree(), { version: 3 }));
  writeFileSync(join(d, "a.zip"), zipBytes);
  for (const [f, applies, why] of [
    ["case.ad1", true, /AD1 logical image \(version 4, segment 1 of 1\)/],
    ["renamed.bin", true, /version 4/],
    ["split.ad2", false, /segment 2 of 2 of an AD1 image: the image is read, and catalogued, from its first segment/],
    ["enc.ad1", false, /encrypted AD1 image \(ADCRYPT header\)/],
    ["v3.ad1", false, /version 3: this recipe reads version 4/],
    ["a.zip", false, /no ADSEGMENTEDFILE header/],
  ] as const) {
    const { code, v } = detect(join(d, f), "--probe-out", join(d, "probe"));
    assert.equal(code, applies ? 0 : 1, `${f}: ${JSON.stringify(v)}`);
    assert.equal(v.applies, applies);
    assert.match(v.why, why, f);
  }
});

test("run lists every item in the image's order with its size, times and recorded digests, inflates each file to check them, and keeps every metadata entry", () => {
  const d = dir("ad1-run-");
  writeFileSync(join(d, "case.ad1"), ad1Image(tree(), { chunkSize: 512 }));
  const { r, out, cov } = runRecipe([join(d, "case.ad1")]);
  assert.equal(r.code, 0, r.err + r.out);
  assert.equal(cov.status, "complete", JSON.stringify(cov));
  assert.deepEqual([cov.items, cov.files, cov.folders, cov.checked], [12, 8, 4, 8]);
  assert.deepEqual(cov.mismatches, [6], "the tampered file's content is not what the image records");
  const head = readFileSync(join(out, "members.tsv"), "utf8").split("\n")[0].split("\t");
  assert.deepEqual(head.slice(0, 14), ["n", "type", "path", "path_b64", "size", "packed", "mtime", "tz", "mode", "uid", "gid", "link", "locator", "flags"], "archive-members' columns first, so catalog_search and member: refs read it alike");
  const rows = tsv(join(out, "members.tsv"));
  assert.deepEqual(rows.map((x) => x.n), Array.from({ length: 12 }, (_, i) => String(i)));
  assert.deepEqual(rows.map((x) => x.path), ["C:", "C:/Users", "C:/Users/alice", "C:/Users/alice/notes.txt", "C:/Users/alice/NOTES.txt", "C:/Users/alice/empty.txt", "C:/Users/alice/tampered.bin", "C:/Users/alice/evidence.zip", "C:/..", "C:/../climb.txt", "C:/caf\\xe9", "C:/readme.txt"]);
  const n3 = rows[3];
  assert.equal(n3.type, "file");
  assert.equal(n3.size, String(notes.length));
  assert.ok(Number(n3.packed) > 0 && Number(n3.packed) < notes.length, "packed is the zlib chunks' bytes");
  assert.deepEqual([n3.mtime, n3.atime, n3.btime, n3.tz], ["2024-01-02T03:04:06.654321", "2024-01-02T03:04:05.123456", "2024-01-01T00:00:00", "unknown"], "modified (0x9), accessed (0x7), created (0x8), as dissect reads them");
  assert.deepEqual([n3.md5, n3.sha1, n3.sha256, n3.check, n3.class], [md5(notes), sha1(notes), sha256(notes), "ok", "regular file"]);
  assert.match(n3.locator, /^ad1:item=\d+$/);
  assert.equal(rows[0].type, "dir");
  assert.equal(rows[0].class, "folder");
  assert.equal(rows[0].check, "", "a folder has no content to check");
  assert.deepEqual([rows[5].size, rows[5].check, rows[5].sha256], ["0", "ok", sha256(Buffer.alloc(0))], "an empty file has no chunk table and matches its recorded digests");
  assert.deepEqual([rows[6].check, rows[6].flags], ["mismatch", "hash-mismatch"]);
  assert.equal(rows[8].flags, "escapes-root");
  assert.equal(rows[9].flags, "escapes-root", "a name under one that climbs is flagged too");
  assert.equal(rows[10].flags, "name-not-utf8");
  assert.equal(Buffer.from(rows[10].path_b64, "base64").toString("latin1"), "C:/caf\xe9");
  assert.deepEqual([rows[11].md5, rows[11].check, rows[11].mtime], ["", "no-stored-hash", "2024-01-02T03:04:05"]);
  const attrs = tsv(join(out, "attributes.tsv"));
  assert.equal(attrs.filter((a) => a.n === "3").length, 8, "every metadata entry of an item is kept");
  assert.ok(attrs.some((a) => a.n === "3" && a.label === "hidden" && a.text === "false"));
  const image = JSON.parse(readFileSync(join(out, "image.json"), "utf8"));
  assert.equal(image.logical_image.version, 4);
  assert.equal(image.data_source_name, "synthetic source [NTFS]");
  assert.deepEqual(image.metadata, [{ category: 1, key: "0x10002", label: "data source name", text: "synthetic source [NTFS]" }]);
  assert.deepEqual(image.segments, [{ segment: 1, name: "case.ad1", present: true, bytes: readFileSync(join(d, "case.ad1")).length }]);
  const index = readFileSync(join(out, "index.tsv"), "utf8");
  assert.deepEqual(index.trimEnd().split("\n").map((l) => l.split("\t")[0]), ["members.tsv", "attributes.tsv", "image.json"]);
  assert.match(index, /12 items: 8 files, 4 folders.*; 1 file\(s\) whose content does not match the digests the image records/);
  assert.deepEqual(readdirSync(out).sort(), ["attributes.tsv", "coverage.json", "image.json", "index.tsv", "members.tsv"], "nothing is extracted");
});

test("a damaged image is listed as far as it reads, and every break is named: a loop, an address outside, a chunk past its size, a cut file", () => {
  const d = dir("ad1-bad-");
  const t = tree();
  const users = t[0].children![0];
  const readme = t[0].children![3];
  const climbs = t[0].children![1];
  const bomb: Ad1Node = { name: "bomb.bin", chunks: [deflateSync(Buffer.alloc(10000))], size: 10000 };
  t[0].children![0].children![0].children!.push(bomb);
  const { data, addr } = ad1Data(t, { chunkSize: 1024 });
  const bad = Buffer.from(data);
  bad.writeBigUInt64LE(BigInt(addr.get(users)!), addr.get(readme)!);     // readme's next sibling: back to Users
  bad.writeBigUInt64LE(1n << 40n, addr.get(climbs)! + 8);                 // the ".." folder's first child: far outside
  writeFileSync(join(d, "bad.ad1"), ad1Segments(bad)[0]);
  const { r, out, cov } = runRecipe([join(d, "bad.ad1")]);
  assert.equal(r.code, 0, r.err);
  assert.equal(cov.status, "partial");
  const errors = cov.errors.join("\n");
  assert.match(errors, /the tree loops back to item address \d+ under C:: not followed/);
  assert.match(errors, /item at address 1099511627776 under C:\/\.\. cannot be read: address 1099511627776 \(\+48\) is outside the image's data; it and the siblings after it are not listed/);
  assert.match(errors, /item \d+ \(C:\/Users\/alice\/bomb\.bin, ad1:item=\d+\): its chunk 0 inflates past the chunk size of 1024/);
  const rows = tsv(join(out, "members.tsv"));
  assert.equal(rows.length, 12, "every item that reads is listed once (the 13 less climb.txt, whose address was broken), the loop not followed");
  assert.equal(rows.find((x) => x.path.endsWith("bomb.bin"))!.check, "not-read");
  // Cut part way through readme.txt's item: what comes before is whole.
  const cut = ad1Segments(data)[0].subarray(0, 512 + addr.get(readme)! + 20);
  writeFileSync(join(d, "cut.ad1"), cut);
  const c = runRecipe([join(d, "cut.ad1")]);
  assert.equal(c.cov.status, "partial");
  assert.match(c.cov.errors.join("\n"), /runs past the end of segment 1: the image is truncated/);
  assert.equal(tsv(join(c.out, "members.tsv")).length, 12, "the items before the cut are listed");
});

test("an image in several segments is read across them, by name beside the first or as the target lists them, and a missing one is named", () => {
  const d = dir("ad1-seg-");
  const big = randomBytes(150000);
  const segs = ad1Segments(ad1Data([{ name: "big.bin", content: big }, { name: "small.txt", content: B("after the big one") }]).data, 65536);
  assert.equal(segs.length, 3);
  segs.forEach((s, i) => writeFileSync(join(d, `case.ad${i + 1}`), s));
  const whole = runRecipe([join(d, "case.ad1")]);
  assert.equal(whole.cov.status, "complete", JSON.stringify(whole.cov));
  const rows = tsv(join(whole.out, "members.tsv"));
  assert.deepEqual(rows.map((x) => [x.path, x.sha256, x.check]), [["big.bin", sha256(big), "ok"], ["small.txt", sha256(B("after the big one")), "ok"]]);
  assert.deepEqual(JSON.parse(readFileSync(join(whole.out, "image.json"), "utf8")).segments.map((s: { name: string; present: boolean }) => [s.name, s.present]), [["case.ad1", true], ["case.ad2", true], ["case.ad3", true]]);
  // Named otherwise, the target lists them in order.
  const other = dir("ad1-seg-named-");
  segs.forEach((s, i) => writeFileSync(join(other, `part-${i + 1}`), s));
  assert.equal(runRecipe([1, 2, 3].map((k) => join(other, `part-${k}`))).cov.status, "complete");
  rmSync(join(d, "case.ad3"));
  const short = runRecipe([join(d, "case.ad1")]);
  assert.equal(short.cov.status, "partial");
  assert.deepEqual(short.cov.segments_missing, ["case.ad3"]);
  assert.match(short.cov.errors.join("\n"), /the image has 3 segments and 1 of them \(case\.ad3\) is not there, beside the first or in this job's view \(a job is given only the segments it declares\)/);
  assert.match(short.cov.errors.join("\n"), /is in segment 3, which is not there \(case\.ad3\)/);
});

test("past the time limit the recipe stops inflating, never listing, and says so", () => {
  const d = dir("ad1-limit-");
  writeFileSync(join(d, "case.ad1"), ad1Image(tree()));
  const { cov, out } = runRecipe([join(d, "case.ad1")], { RECIPE_SECONDS: "0" });
  assert.equal(cov.status, "partial");
  assert.match(cov.limits_hit[0], /^seconds: past the limit, the content of 8 file\(s\) was not inflated, so their digests were not checked \(check not-read\); every item is still listed$/);
  const rows = tsv(join(out, "members.tsv"));
  assert.equal(rows.length, 12);
  assert.ok(rows.filter((x) => x.type === "file").every((x) => x.check === "not-read" && x.sha256 === ""), "no file is checked, every one says so");
});

function runDir(): string {
  const cwd = dir("ad1-tool-");
  mkdirSync(join(cwd, "inputs"));
  mkdirSync(join(cwd, "work", "s1"), { recursive: true });
  writeFileSync(join(cwd, "inputs", "case.ad1"), ad1Image(tree(), { chunkSize: 512 }));
  return cwd;
}

test("ad1_extract writes the tree out, checks each file, renames what this file system cannot hold, and names it all in its manifest", async () => {
  const cwd = runDir();
  const r = await runPy(TOOL, cwd, { image: "inputs/case.ad1" }, undefined, { AGENT_ID: "s1" });
  assert.equal(r.code, 0, r.stderr + r.stdout);
  const res = JSON.parse(r.stdout);
  assert.equal(res.out_dir, "work/s1/ad1/case", "called directly, it writes under the agent's own work/");
  assert.deepEqual([res.items, res.files, res.folders, res.renamed, res.mismatches, res.checked], [12, 8, 4, 3, 1, 8]);
  assert.match(res.note, /run it as a job \(job_run tool=ad1_extract\)/);
  const base = join(cwd, "work", "s1", "ad1", "case");
  assert.deepEqual(readFileSync(join(base, "C:", "Users", "alice", "notes.txt")), notes);
  assert.deepEqual(readFileSync(join(base, "C:", "Users", "alice", "evidence.zip")), zipBytes);
  assert.equal(readFileSync(join(base, "C:", "Users", "alice", "NOTES.txt~n4"), "utf8"), "the same name, another case", "a name a sibling took, letter case aside, is renamed");
  assert.equal(readFileSync(join(base, "C:", "%2E%2E", "climb.txt"), "utf8"), "x", "a name that climbs stays inside");
  assert.equal(readFileSync(join(base, "C:", "caf%E9"), "utf8"), "a name that is not UTF-8");
  assert.equal(readFileSync(join(base, "C:", "Users", "alice", "empty.txt")).length, 0);
  const man = tsv(join(base, "ad1_extract.tsv"));
  assert.equal(man.length, 12);
  const m = (n: number) => man.find((x) => x.n === String(n))!;
  assert.deepEqual([m(3).written, m(3).sha256, m(3).check], ["C:/Users/alice/notes.txt", sha256(notes), "ok"]);
  assert.deepEqual([m(4).written, m(4).note], ["C:/Users/alice/NOTES.txt~n4", "renamed"]);
  assert.deepEqual([m(6).check, m(8).written, m(8).path, m(10).path], ["mismatch", "C:/%2E%2E", "C:/..", "C:/caf\\xe9"]);
  assert.equal(m(11).check, "no-stored-hash");
  assert.ok(!existsSync(join(cwd, "inputs", "C:")) && readdirSync(join(cwd, "inputs")).length === 1, "nothing beside the evidence");
});

test("ad1_extract takes the items named, a folder with its subtree, and refuses a place outside the run, under inputs/ or already used", async () => {
  const cwd = runDir();
  const some = await runPy(TOOL, cwd, { image: "inputs/case.ad1", members: [2, 10], out_dir: "work/s1/some" }, undefined, { AGENT_ID: "s1" });
  assert.equal(some.code, 0, some.stderr + some.stdout);
  const man = tsv(join(cwd, "work", "s1", "some", "ad1_extract.tsv"));
  assert.deepEqual(man.map((x) => x.n), ["2", "3", "4", "5", "6", "7", "10"], "alice's subtree and the one file, nothing else");
  assert.ok(!existsSync(join(cwd, "work", "s1", "some", "C:", "readme.txt")));
  const absent = await runPy(TOOL, cwd, { image: "inputs/case.ad1", members: [3, 99], out_dir: "work/s1/absent" }, undefined, { AGENT_ID: "s1" });
  assert.equal(absent.code, 1);
  assert.match(JSON.parse(absent.stdout).errors[0], /no item 99 in this read of the image \(it listed 12 items\)/);
  for (const [out_dir, why] of [["inputs/x", /cannot be under inputs/], ["../elsewhere", /must be inside the run directory/], [".", /must be inside the run directory/], ["work/s1/some", /already holds something/]] as const) {
    const r = await runPy(TOOL, cwd, { image: "inputs/case.ad1", out_dir }, undefined, { AGENT_ID: "s1" });
    assert.equal(r.code, 1, out_dir);
    assert.match(JSON.parse(r.stdout).error, why, out_dir);
  }
  const none = await runPy(TOOL, cwd, { image: "inputs/case.ad1", members: [] }, undefined, { AGENT_ID: "s1" });
  assert.match(JSON.parse(none.stdout).error, /members is a non-empty list of item numbers \(n\) or locators \(ad1:item=<address>\).*leave it out to take every item/);
  const notAd1 = await runPy(TOOL, cwd, { image: "inputs/../work/s1/some/ad1_extract.tsv" }, undefined, { AGENT_ID: "s1" });
  assert.match(JSON.parse(notAd1.stdout).error, /not an AD1 image this tool reads: no ADSEGMENTEDFILE header/);
  assert.deepEqual(readdirSync(join(cwd, "inputs")), ["case.ad1"]);
});

test("in a job ad1_extract writes under $OUT, and a file whose content breaks is kept as .partial and said", async () => {
  const cwd = runDir();
  const t = tree();
  t[0].children![0].children![0].children!.push({ name: "bomb.bin", chunks: [deflateSync(Buffer.alloc(10000))], size: 10000 });
  writeFileSync(join(cwd, "inputs", "bad.ad1"), ad1Image(t, { chunkSize: 1024 }));
  const out = join(cwd, ".jobs", "j000007");
  mkdirSync(out, { recursive: true });
  const r = await runPy(TOOL, cwd, { image: "inputs/bad.ad1" }, undefined, { AGENT_ID: "s1", JOB_ID: "j000007", OUT: out });
  assert.equal(r.code, 1, "an item that broke fails the call, after the rest is written");
  const res = JSON.parse(r.stdout);
  assert.equal(res.out_dir, join(out, "bad"));
  assert.equal(res.note, undefined, "in a job there is nothing to say about work/");
  assert.match(res.errors[0], /item 8 \(C:\/Users\/alice\/bomb\.bin, ad1:item=\d+\): its chunk 0 inflates past the chunk size of 1024/);
  assert.ok(existsSync(join(out, "bad", "C:", "Users", "alice", "bomb.bin.partial")));
  assert.ok(!existsSync(join(out, "bad", "C:", "Users", "alice", "bomb.bin")));
  const row = tsv(join(out, "bad", "ad1_extract.tsv")).find((x) => x.n === "8")!;
  assert.deepEqual([row.written, row.check, row.note], ["C:/Users/alice/bomb.bin.partial", "not-read", "partial: 0 of 10000 bytes kept"]);
  assert.deepEqual(readFileSync(join(out, "bad", "C:", "Users", "alice", "notes.txt")), notes, "the rest is whole");
  // In a job only $OUT is written: a place under work/ is refused before anything is read.
  const elsewhere = await runPy(TOOL, cwd, { image: "inputs/case.ad1", out_dir: "work/s1/x" }, undefined, { AGENT_ID: "s1", JOB_ID: "j000007", OUT: out });
  assert.equal(elsewhere.code, 1);
  assert.match(JSON.parse(elsewhere.stdout).error, /in a job out_dir must be inside \$OUT/);
});

test("a real FTK Imager image reads as dissect.evidence reads it: its items, content, digests and the time keys", async () => {
  const { r, out, cov } = runRecipe([FTK]);
  assert.equal(r.code, 0, r.err);
  assert.equal(cov.status, "complete", JSON.stringify(cov));
  const rows = tsv(join(out, "members.tsv"));
  assert.deepEqual(rows.map((x) => [x.n, x.type, x.path, x.size, x.check, x.class]), [["0", "file", "doc1.txt", "17", "ok", "regular file"], ["1", "file", "doc2.txt", "142", "ok", "regular file"]]);
  // dissect's own test asserts doc1.txt's atime; its mtime is the save, 18 s after the file was made.
  assert.deepEqual([rows[0].atime, rows[0].btime, rows[0].mtime], ["2017-03-31T18:02:31.189682", "2017-03-31T18:02:31.189682", "2017-03-31T18:02:49.722616"]);
  const image = JSON.parse(readFileSync(join(out, "image.json"), "utf8"));
  assert.equal(image.data_source_name, "E:\\\\AD1_test", "the paths are under the data source name");
  assert.deepEqual(image.segment_header, { index: 1, count: 1, bytes: 1572864000, header: 512 }, "FTK Imager's default segment, 1500 MB");
  assert.match(readFileSync(join(out, "index.tsv"), "utf8"), /paths under the data source name E:\\\\AD1_test/);
  const labels = Object.fromEntries(tsv(join(out, "attributes.tsv")).filter((a) => a.n === "0").map((a) => [a.key, a.label]));
  assert.deepEqual([labels["0x7"], labels["0x8"], labels["0x9"], labels["0x1e"], labels["0x1003"]], ["accessed", "created", "modified", "actual file", "system"]);
  const cwd = dir("ad1-ftk-");
  mkdirSync(join(cwd, "inputs"));
  cpSync(FTK, join(cwd, "inputs", "compressed.ad1"));
  const x = await runPy(TOOL, cwd, { image: "inputs/compressed.ad1" }, undefined, { AGENT_ID: "s1" });
  assert.equal(x.code, 0, x.stdout + x.stderr);
  assert.equal(readFileSync(join(cwd, "work", "s1", "ad1", "compressed", "doc1.txt"), "utf8"), "Inhoud document 1");
  assert.equal(readFileSync(join(cwd, "work", "s1", "ad1", "compressed", "doc2.txt")).length, 142);
});

test("headers that claim too much are refused before anything is read: segments, chunk size, version, a name", () => {
  const d = dir("ad1-hostile-");
  const good = ad1Image(tree());
  const patched = (f: (b: Buffer) => void) => {
    const b = Buffer.from(good);
    f(b);
    return b;
  };
  const cases: Array<[string, Buffer, RegExp]> = [
    ["count.ad1", patched((b) => b.writeUInt32LE(0xffffffff, 0x1c)), /the image has 4294967295 segments \(this reader takes 1 to 4096\)/],
    ["chunk0.ad1", patched((b) => b.writeUInt32LE(0, 512 + 24)), /its chunks are 0 bytes \(this reader takes 512 to 16777216\)/],
    ["chunkbig.ad1", patched((b) => b.writeUInt32LE(1 << 30, 512 + 24)), /its chunks are 1073741824 bytes/],
    ["v3.ad1", patched((b) => b.writeUInt32LE(3, 512 + 16)), /version 3: this reader reads version 4/],
  ];
  for (const [f, bytes, why] of cases) {
    writeFileSync(join(d, f), bytes);
    const started = Date.now();
    const { r, cov } = runRecipe([join(d, f)]);
    assert.equal(r.code, 2, f);
    assert.equal(cov.status, "unsupported", f);
    assert.match(String(cov.why), why, f);
    assert.ok(Date.now() - started < 10000, `${f} took ${Date.now() - started} ms`);
  }
  assert.match(detect(join(d, "count.ad1")).v.why, /4294967295 segments/, "detect turns it down too");
  // A data source name past its bound is named, not read; the items still are.
  writeFileSync(join(d, "name.ad1"), patched((b) => b.writeUInt32LE(2 << 20, 512 + 44)));
  const named = runRecipe([join(d, "name.ad1")]);
  assert.equal(named.cov.status, "partial");
  assert.match(named.cov.errors.join("\n"), /the data source name says it is 2097152 bytes long: not read/);
  assert.equal(tsv(join(named.out, "members.tsv")).length, 12);
});

test("a chunk table, a chunk, a name, a metadata chain or a tree that claims too much is named, not followed", () => {
  const d = dir("ad1-claims-");
  const t = tree();
  const notesNode = t[0].children![0].children![0].children![0];
  const tampered = t[0].children![0].children![0].children![3];
  const readme = t[0].children![3];
  const climb = t[0].children![1].children![0];
  const { data, addr } = ad1Data(t, { chunkSize: 512 });
  const bad = Buffer.from(data);
  // notes.txt says it is 2^60 bytes in 2^40 chunks: the table cannot hold them.
  const n = addr.get(notesNode)!;
  bad.writeBigUInt64LE(1n << 60n, n + 32);
  const table = Number(bad.readBigUInt64LE(n + 24));
  bad.writeBigUInt64LE(1n << 40n, table);
  // tampered.bin's one chunk runs far past what a chunk's zlib stream can be.
  const tt = Number(bad.readBigUInt64LE(addr.get(tampered)! + 24));
  bad.writeBigUInt64LE(bad.readBigUInt64LE(tt + 8) + 5000n, tt + 16);
  // readme.txt's first metadata entry points back at itself.
  const meta = Number(bad.readBigUInt64LE(addr.get(readme)! + 16));
  bad.writeBigUInt64LE(BigInt(meta), meta);
  // climb.txt says its name is 70000 bytes.
  bad.writeUInt32LE(70000, addr.get(climb)! + 44);
  writeFileSync(join(d, "claims.ad1"), ad1Segments(bad)[0]);
  const started = Date.now();
  const { cov, out } = runRecipe([join(d, "claims.ad1")]);
  assert.ok(Date.now() - started < 10000, `took ${Date.now() - started} ms`);
  assert.equal(cov.status, "partial");
  const errors = cov.errors.join("\n");
  assert.match(errors, /item 3 \(C:\/Users\/alice\/notes\.txt, ad1:item=\d+\): its chunk table lists 1099511627776 chunks for 1152921504606846976 bytes/);
  assert.match(errors, /item 6 \(C:\/Users\/alice\/tampered\.bin, ad1:item=\d+\): its chunk 0 runs from address \d+ to \d+/);
  assert.match(errors, /under C: cannot be read: the metadata chain loops back to address \d+/);
  assert.match(errors, /under C:\/\.\. cannot be read: its name is 70000 bytes long/);
  assert.equal(tsv(join(out, "members.tsv")).length, 10, "every item but readme.txt and climb.txt is listed");
  // A tree deeper than the reader follows: its deepest items are named, not listed.
  let deep: Ad1Node = { name: "leaf.txt", content: B("deep") };
  for (let i = 0; i < 1030; i += 1) deep = { name: `d${i}`, folder: true, children: [deep] };
  writeFileSync(join(d, "deep.ad1"), ad1Image([deep]));
  const t0 = Date.now();
  const dp = runRecipe([join(d, "deep.ad1")]);
  assert.ok(Date.now() - t0 < 20000, `the deep tree took ${Date.now() - t0} ms`);
  assert.equal(dp.cov.status, "partial");
  assert.match(dp.cov.errors.join("\n"), /is nested deeper than 1024 levels: it and the siblings after it are not listed/);
  assert.equal(tsv(join(dp.out, "members.tsv")).length, 1024);
});

test("an item's locator names it in a partial read and in a whole one alike, where its number may not, and ad1_extract takes either", async () => {
  // A{B, C}, D, E with B and C alone in the second segment.
  const span = 65536 - 512;
  const data = ad1Logical((put, at) => {
    const e = ad1Item(put, "E.txt");
    const dd = ad1Item(put, "D.txt", { next: e.at });
    const a = ad1Item(put, "A", { folder: true, next: dd.at });
    put(Buffer.alloc(span - at() + 16));
    const c = ad1Item(put, "C.txt");
    const b = ad1Item(put, "B.txt", { next: c.at });
    a.header.writeBigUInt64LE(BigInt(b.at), 8);
    return a.at;
  });
  const segs = ad1Segments(data, 65536);
  assert.equal(segs.length, 2);
  const cwd = dir("ad1-locator-");
  mkdirSync(join(cwd, "inputs"));
  segs.forEach((s, i) => writeFileSync(join(cwd, "inputs", `n.ad${i + 1}`), s));
  const whole = runRecipe([join(cwd, "inputs", "n.ad1")]);
  const all = tsv(join(whole.out, "members.tsv"));
  assert.deepEqual(all.map((x) => [x.n, x.path]), [["0", "A"], ["1", "A/B.txt"], ["2", "A/C.txt"], ["3", "D.txt"], ["4", "E.txt"]]);
  const dLocator = all[3].locator;
  rmSync(join(cwd, "inputs", "n.ad2"));
  const partial = runRecipe([join(cwd, "inputs", "n.ad1")]);
  const some = tsv(join(partial.out, "members.tsv"));
  assert.deepEqual(some.map((x) => [x.n, x.path, x.locator]), [["0", "A", all[0].locator], ["1", "D.txt", dLocator], ["2", "E.txt", all[4].locator]], "after the break the numbers move; the locators do not");
  // The partial read's n=1 is D.txt; with every segment back, n=1 is B.txt. The locator is D.txt in both.
  writeFileSync(join(cwd, "inputs", "n.ad2"), segs[1]);
  mkdirSync(join(cwd, "work", "s1"), { recursive: true });
  const byLocator = await runPy(TOOL, cwd, { image: "inputs/n.ad1", members: [dLocator], out_dir: "work/s1/loc" }, undefined, { AGENT_ID: "s1" });
  assert.equal(byLocator.code, 0, byLocator.stdout);
  assert.deepEqual(tsv(join(cwd, "work", "s1", "loc", "ad1_extract.tsv")).map((x) => [x.n, x.path, x.locator]), [["3", "D.txt", dLocator]]);
  const byNumber = await runPy(TOOL, cwd, { image: "inputs/n.ad1", members: [1], out_dir: "work/s1/num" }, undefined, { AGENT_ID: "s1" });
  assert.deepEqual(tsv(join(cwd, "work", "s1", "num", "ad1_extract.tsv")).map((x) => x.path), ["A/B.txt"]);
  const unknown = await runPy(TOOL, cwd, { image: "inputs/n.ad1", members: ["ad1:item=7"], out_dir: "work/s1/none" }, undefined, { AGENT_ID: "s1" });
  assert.match(JSON.parse(unknown.stdout).errors[0], /no item at ad1:item=7 in this read of the image/);
});

test("ad1_extract renames every name a file system cannot hold, keeps a file's children beside it, and a name a sibling took stays taken", async () => {
  const cwd = dir("ad1-names-");
  mkdirSync(join(cwd, "inputs"));
  const long = "x".repeat(300);
  writeFileSync(join(cwd, "inputs", "names.ad1"), ad1Image([{
    name: "root", folder: true, children: [
      { name: "a/b", content: B("slash") },
      { name: "nul\0here", content: B("nul") },
      { name: "", content: B("empty") },
      { name: long, content: B("long") },
      { name: "notes.txt~n7", content: B("a literal name like a rename") },
      { name: "notes.txt", content: B("lower") },
      { name: "NOTES.txt", content: B("upper") },
      { name: "withstream.txt.ad1-children", content: B("a name like a children directory") },
      { name: "withstream.txt", content: B("base"), children: [{ name: "stream", content: B("ads") }] },
    ],
  }]));
  const r = await runPy(TOOL, cwd, { image: "inputs/names.ad1" }, undefined, { AGENT_ID: "s1" });
  assert.equal(r.code, 0, r.stdout + r.stderr);
  const man = tsv(join(cwd, "work", "s1", "ad1", "names", "ad1_extract.tsv"));
  const written = Object.fromEntries(man.map((x) => [x.n, x.written]));
  assert.equal(written["1"], "root/a%2Fb");
  assert.equal(written["2"], "root/nul%00here");
  assert.equal(written["3"], "root/%");
  assert.match(written["4"], /^root\/x{197}~[0-9a-f]{16}$/);
  assert.equal(written["5"], "root/notes.txt~n7");
  assert.equal(written["7"], "root/NOTES.txt~n7.2", "the rename is checked again: a literal sibling already holds the first choice");
  assert.equal(written["8"], "root/withstream.txt.ad1-children");
  assert.equal(written["10"], "root/withstream.txt.ad1-children~n9/stream", "a file's children go beside it, in a directory no sibling holds");
  const base = join(cwd, "work", "s1", "ad1", "names");
  for (const [n, text] of [["1", "slash"], ["7", "upper"], ["10", "ads"]]) assert.equal(readFileSync(join(base, written[n]), "utf8"), text);
  assert.deepEqual(man.filter((x) => x.note.includes("renamed")).map((x) => x.n), ["1", "2", "3", "4", "7"]);
});

test("a write that fails leaves the file as .partial, the manifest says so, and the call says why", () => {
  const cwd = dir("ad1-full-");
  mkdirSync(join(cwd, "inputs"));
  const big = randomBytes(100000);
  writeFileSync(join(cwd, "inputs", "big.ad1"), ad1Image([{ name: "small.txt", content: B("fits") }, { name: "big.bin", content: big }, { name: "after.txt", content: B("fits too") }]));
  // A file-size limit stands in for a full disk: the write fails part way (EFBIG).
  const r = spawnSync("bash", ["-c", `ulimit -f 32; exec python3 '${TOOL}'`], { cwd, input: JSON.stringify({ image: "inputs/big.ad1" }), encoding: "utf8", env: { ...process.env, AGENT_ID: "s1" } });
  assert.equal(r.status, 1, r.stdout + r.stderr);
  assert.doesNotMatch(r.stderr, /Traceback/);
  const res = JSON.parse(r.stdout);
  assert.match(res.errors[0], /item 1 \(big\.bin, ad1:item=\d+\): the write failed: File too large/);
  const base = join(cwd, "work", "s1", "ad1", "big");
  assert.ok(!existsSync(join(base, "big.bin")), "no truncated file keeps its own name");
  assert.ok(existsSync(join(base, "big.bin.partial")));
  const man = tsv(join(base, "ad1_extract.tsv"));
  assert.deepEqual(man.map((x) => [x.written, x.check]), [["small.txt", "ok"], ["big.bin.partial", "not-written"], ["after.txt", "ok"]]);
  assert.match(man[1].note, /^partial: \d+ of 100000 bytes kept$/);
});

// --- the review's fixes: one allocator for partial names, two statuses, budgets, coverage first ---

test("two items that would both be kept as a partial of the same name are kept as two distinct files, and nothing earlier is overwritten", () => {
  // Item 0 is a whole file named like the first partial name, item 1 one named like the second; item 2 is
  // broken, so its content is kept as a partial whose two obvious names are both taken. The old tool replaced
  // item 1's file with the partial.
  const cwd = dir("ad1-partial-names-");
  mkdirSync(join(cwd, "inputs"));
  const broken: Ad1Node = { name: "a.bin", chunks: [deflateSync(Buffer.alloc(10000))], size: 10000 };
  writeFileSync(join(cwd, "inputs", "p.ad1"), ad1Image([{ name: "a.bin.partial", content: B("first whole file") }, { name: "a.bin.partial~n2", content: B("second whole file") }, broken], { chunkSize: 1024 }));
  const r = spawnSync("python3", [TOOL], { cwd, input: JSON.stringify({ image: "inputs/p.ad1" }), encoding: "utf8", env: { ...process.env, AGENT_ID: "s1" } });
  assert.equal(r.status, 1, r.stdout + r.stderr);
  const base = join(cwd, "work", "s1", "ad1", "p");
  assert.equal(readFileSync(join(base, "a.bin.partial"), "utf8"), "first whole file");
  assert.equal(readFileSync(join(base, "a.bin.partial~n2"), "utf8"), "second whole file", "the second whole file was not overwritten");
  assert.ok(!existsSync(join(base, "a.bin")), "no truncated file keeps its own name");
  const man = tsv(join(base, "ad1_extract.tsv"));
  const row = man.find((x) => x.n === "2")!;
  assert.match(row.written, /^a\.bin\.partial~/);
  assert.notEqual(row.written, "a.bin.partial");
  assert.notEqual(row.written, "a.bin.partial~n2");
  assert.equal(new Set(man.map((x) => x.written)).size, 3, "three items, three distinct files");
  assert.equal(sha256(readFileSync(join(base, row.written))), row.sha256, "a partial row's sha256 is of the bytes kept");
});

test("a size recorded for a partial is the bytes kept, and its sha256 is of them", () => {
  const cwd = dir("ad1-partial-size-");
  mkdirSync(join(cwd, "inputs"));
  const big = randomBytes(100000);
  writeFileSync(join(cwd, "inputs", "big.ad1"), ad1Image([{ name: "big.bin", content: big }]));
  const r = spawnSync("bash", ["-c", `ulimit -f 32; exec python3 '${TOOL}'`], { cwd, input: JSON.stringify({ image: "inputs/big.ad1" }), encoding: "utf8", env: { ...process.env, AGENT_ID: "s1" } });
  assert.equal(r.status, 1, r.stdout + r.stderr);
  const base = join(cwd, "work", "s1", "ad1", "big");
  const kept = readFileSync(join(base, "big.bin.partial"));
  const row = tsv(join(base, "ad1_extract.tsv"))[0];
  assert.equal(Number(row.size), kept.length, "the size is what the file holds, not what was counted before the write failed");
  assert.equal(row.sha256, sha256(kept));
});

test("a digest mismatch is an integrity finding of its own: ok is false, the extraction is complete, and the two statuses say so", async () => {
  const cwd = runDir();
  const r = await runPy(TOOL, cwd, { image: "inputs/case.ad1" }, undefined, { AGENT_ID: "s1" });
  assert.equal(r.code, 0, "the files were written: the exit status is 0 for a complete extraction");
  const res = JSON.parse(r.stdout);
  assert.deepEqual([res.processing_status, res.integrity_status, res.ok, res.mismatches], ["complete", "mismatch", false, 1]);
  assert.match(res.integrity_note, /does not match the digests the image records/);
  const cov = JSON.parse(readFileSync(join(cwd, "work", "s1", "ad1", "case", "ad1_extract.coverage.json"), "utf8"));
  assert.deepEqual([cov.processing_status, cov.integrity_status], ["complete", "mismatch"]);
  // An image whose every file matches is verified, and ok.
  writeFileSync(join(cwd, "inputs", "clean.ad1"), ad1Image([{ name: "a.txt", content: B("fine") }, { name: "b.txt", content: B("also fine") }]));
  const ok = JSON.parse((await runPy(TOOL, cwd, { image: "inputs/clean.ad1" }, undefined, { AGENT_ID: "s1" })).stdout);
  assert.deepEqual([ok.processing_status, ok.integrity_status, ok.ok], ["complete", "verified", true]);
  // A file with no stored digest cannot be said to match.
  writeFileSync(join(cwd, "inputs", "nohash.ad1"), ad1Image([{ name: "r.txt", content: B("no digests"), meta: [[2, 2, "1"]] }]));
  const unverified = JSON.parse((await runPy(TOOL, cwd, { image: "inputs/nohash.ad1" }, undefined, { AGENT_ID: "s1" })).stdout);
  assert.deepEqual([unverified.integrity_status, unverified.no_stored_hash], ["unverified", 1]);
});

test("the item budget and the byte budget stop ad1_extract, keep what it wrote, and say so", async () => {
  const cwd = runDir();
  const byItems = await runPy(TOOL, cwd, { image: "inputs/case.ad1", max_items: 3 }, undefined, { AGENT_ID: "s1" });
  assert.equal(byItems.code, 0, "a stop at a budget is a valid answer for what was examined: the tool ran");
  const a = JSON.parse(byItems.stdout);
  assert.equal(a.processing_status, "partial");
  assert.match(a.stopped_by_budget, /item budget of 3 items/);
  assert.equal(a.items, 3);
  assert.match(a.errors.join("\n"), /every item after it in the image's order were not written or listed/);
  writeFileSync(join(cwd, "inputs", "two.ad1"), ad1Image([{ name: "a.bin", content: randomBytes(5000) }, { name: "b.bin", content: B("never reached") }], { chunkSize: 512 }));
  const byBytes = await runPy(TOOL, cwd, { image: "inputs/two.ad1", max_bytes: 1000 }, undefined, { AGENT_ID: "s1" });
  assert.equal(byBytes.code, 0, "the file the byte budget cut is kept as a partial and says so; the call itself ran");
  assert.equal(JSON.parse(byBytes.stdout).processing_status, "partial");
  const b = JSON.parse(byBytes.stdout);
  assert.match(b.stopped_by_budget, /output budget of 1000 bytes/);
  const base = join(cwd, "work", "s1", "ad1", "two");
  assert.ok(existsSync(join(base, "a.bin.partial")) && !existsSync(join(base, "a.bin")) && !existsSync(join(base, "b.bin")));
  assert.ok(readFileSync(join(base, "a.bin.partial")).length <= 1000 + 512, "what was kept is within a chunk of the budget");
  for (const bad of [{ max_items: 0 }, { max_bytes: -1 }, { max_seconds: 10 ** 9 }]) {
    const r = await runPy(TOOL, cwd, { image: "inputs/case.ad1", out_dir: `work/s1/bad${Object.keys(bad)[0]}`, ...bad }, undefined, { AGENT_ID: "s1" });
    assert.equal(r.code, 1, JSON.stringify(bad));
  }
});

test("an item the walk did not reach before a budget stop is not claimed absent", async () => {
  const cwd = runDir();
  const r = await runPy(TOOL, cwd, { image: "inputs/case.ad1", members: [3, 5, 11], max_items: 1 }, undefined, { AGENT_ID: "s1" });
  assert.equal(r.code, 0);
  const res = JSON.parse(r.stdout);
  assert.match(res.stopped_by_budget, /item budget of 1 items/);
  const text = res.errors.join("\n");
  assert.match(text, /item 11 was not reached before the call stopped/);
  assert.doesNotMatch(text, /no item 11 in this read of the image/, "an item after the stop is not an item that is not there");
});

test("the walk budget stops ad1_extract, and a wanted item it never reached is not called absent", async () => {
  const cwd = runDir();
  const r = await runPy(TOOL, cwd, { image: "inputs/case.ad1", max_walk: 5 }, undefined, { AGENT_ID: "s1" });
  assert.equal(r.code, 0);
  const res = JSON.parse(r.stdout);
  assert.equal(res.processing_status, "partial");
  assert.match(res.stopped_by_budget, /walk budget of 5 items/);
  assert.equal(res.items, 5);
  const some = await runPy(TOOL, cwd, { image: "inputs/case.ad1", members: [11], max_walk: 5, out_dir: "work/s1/walk2" }, undefined, { AGENT_ID: "s1" });
  const text = JSON.parse(some.stdout).errors.join("\n");
  assert.match(text, /item 11 was not reached before the call stopped/);
  assert.doesNotMatch(text, /no item 11 in this read/);
  const bad = await runPy(TOOL, cwd, { image: "inputs/case.ad1", max_walk: 0, out_dir: "work/s1/walk3" }, undefined, { AGENT_ID: "s1" });
  assert.equal(bad.code, 1);
});

test("what ad1_extract holds while it walks is the depth of the tree, not the number of items", () => {
  const d = dir("ad1-memory-");
  mkdirSync(join(d, "inputs"));
  const dirs: Ad1Node[] = [];
  for (let k = 0; k < 100; k++) {
    const kids: Ad1Node[] = [];
    for (let i = 0; i < 1000; i++) kids.push({ name: `f${i}.txt`, content: Buffer.alloc(0) });
    dirs.push({ name: `d${k}`, folder: true, children: kids });
  }
  writeFileSync(join(d, "inputs", "big.ad1"), ad1Image(dirs));
  const wrapper = "import json, resource, subprocess, sys\n" +
    "p = subprocess.run([sys.executable, sys.argv[1]], input=sys.argv[2], capture_output=True, text=True)\n" +
    "print(json.dumps({'out': p.stdout, 'peak': resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss}))\n";
  const r = spawnSync("python3", ["-c", wrapper, TOOL, JSON.stringify({ image: "inputs/big.ad1" })], { cwd: d, encoding: "utf8", env: { ...process.env, AGENT_ID: "s1" } });
  const got = JSON.parse(r.stdout) as { out: string; peak: number };
  const res = JSON.parse(got.out);
  assert.deepEqual([res.processing_status, res.items, res.files, res.folders], ["complete", 100100, 100000, 100]);
  const peak = got.peak * (process.platform === "darwin" ? 1 : 1024);
  assert.ok(peak < 60 * 1024 * 1024, `the peak was ${peak} bytes for 100,100 items (the earlier code needed 100 MB)`);
});

test("a locator with a digit that is not a decimal digit is refused with a message, not a traceback", async () => {
  const cwd = runDir();
  for (const bad of ["ad1:item=\u00b2", "ad1:item=\u0663", "ad1:item="]) {
    const r = await runPy(TOOL, cwd, { image: "inputs/case.ad1", members: [bad] }, undefined, { AGENT_ID: "s1" });
    assert.equal(r.code, 1, bad);
    assert.doesNotMatch(r.stderr, /Traceback/, bad);
    assert.match(JSON.parse(r.stdout).error, /an item number \(n\) or a locator/, bad);
  }
});

test("a partial is kept by a rename where the file system holds no hard links", () => {
  const cwd = dir("ad1-nolink-");
  mkdirSync(join(cwd, "inputs"));
  mkdirSync(join(cwd, "shim"));
  writeFileSync(join(cwd, "shim", "sitecustomize.py"), "import os\n\ndef _no(*a, **k):\n    raise OSError(1, 'Operation not permitted')\n\nos.link = _no\n");
  writeFileSync(join(cwd, "inputs", "big.ad1"), ad1Image([{ name: "big.bin", content: randomBytes(100000) }]));
  const r = spawnSync("bash", ["-c", `ulimit -f 32; exec python3 '${TOOL}'`], { cwd, input: JSON.stringify({ image: "inputs/big.ad1" }), encoding: "utf8", env: { ...process.env, AGENT_ID: "s1", PYTHONPATH: join(cwd, "shim") } });
  assert.equal(r.status, 1, r.stdout + r.stderr);
  const base = join(cwd, "work", "s1", "ad1", "big");
  assert.ok(existsSync(join(base, "big.bin.partial")), "what was written is kept, not removed because link() is refused");
  assert.ok(!existsSync(join(base, "big.bin")));
  const row = tsv(join(base, "ad1_extract.tsv"))[0];
  assert.equal(Number(row.size), readFileSync(join(base, "big.bin.partial")).length);
  assert.match(row.note, /partial: \d+ of 100000 bytes kept/);
});

test("the recipe does not call an image verified when a file in it records no digest", () => {
  const d = dir("ad1-nohash-");
  writeFileSync(join(d, "nohash.ad1"), ad1Image([{ name: "r.txt", content: B("no digests"), meta: [[2, 2, "1"]] }, { name: "ok.txt", content: B("fine") }]));
  const { cov } = runRecipe([join(d, "nohash.ad1")]);
  assert.equal(cov.status, "complete");
  assert.equal((cov as Record<string, unknown>).integrity_status, "unverified");
  assert.equal((cov as Record<string, unknown>).no_stored_hash, 1);
  writeFileSync(join(d, "clean.ad1"), ad1Image([{ name: "a.txt", content: B("fine") }]));
  assert.equal((runRecipe([join(d, "clean.ad1")]).cov as Record<string, unknown>).integrity_status, "verified");
});

test("the recipe's coverage says a mismatch apart from whether every item was processed, and a metadata chain longer than the reader allows is named", () => {
  const d = dir("ad1-integrity-");
  writeFileSync(join(d, "case.ad1"), ad1Image(tree()));
  const { cov } = runRecipe([join(d, "case.ad1")]);
  assert.equal(cov.status, "complete");
  assert.equal((cov as Record<string, unknown>).integrity_status, "mismatch");
  // An item whose metadata chain is longer than the reader's cap (65536 entries) is not read further.
  const many: Ad1Node = { name: "meta.bin", content: B("x"), meta: Array.from({ length: 70000 }, (_, i) => [3, 0x7000 + (i % 100), "v"] as [number, number, string]) };
  writeFileSync(join(d, "many.ad1"), ad1Image([many]));
  const long = runRecipe([join(d, "many.ad1")]);
  assert.match(long.cov.errors.join("\n"), /a metadata chain holds more than 65536 entries/);
});

test("the reader is one block, the same in the recipe and the tool", () => {
  const block = (p: string) => {
    const t = readFileSync(p, "utf8");
    const a = t.indexOf("# --- AD1 reader");
    const b = t.indexOf("# --- end of the AD1 reader");
    assert.ok(a > 0 && b > a, p);
    return t.slice(a, b);
  };
  assert.equal(block(RECIPE), block(TOOL));
});

test("file_type names an AD1 image and its encrypted form by their first bytes", async () => {
  const cwd = runDir();
  writeFileSync(join(cwd, "inputs", "enc.ad1"), Buffer.concat([B("ADCRYPT\0"), Buffer.alloc(600)]));
  writeFileSync(join(cwd, "inputs", "split.ad10"), ad1Segments(ad1Data([{ name: "big.bin", content: randomBytes(70000) }]).data, 65536)[1]);
  const r = await runPy(join(CFB, "tools", "file_type", "run.py"), cwd, { path: "inputs" });
  const files = JSON.parse(r.stdout).files as Array<{ file: string; type: string; extension_matches: boolean }>;
  assert.deepEqual(files.map((f) => [f.file, f.type, f.extension_matches]), [
    ["inputs/case.ad1", "AccessData AD1 logical image (a segment)", true],
    ["inputs/enc.ad1", "AccessData AD1 logical image, encrypted", true],
    ["inputs/split.ad10", "AccessData AD1 logical image (a segment)", true],
  ]);
});

test("the census catalogues an AD1 input with the base pack's recipe, and names a further segment as read from its first", () => {
  const sb = dir("ad1-census-");
  mkdirSync(join(sb, "inputs"));
  writeFileSync(join(sb, "inputs", "case.ad1"), ad1Image(tree()));
  ad1Segments(ad1Data([{ name: "big.bin", content: randomBytes(70000) }]).data, 65536).forEach((s, i) => writeFileSync(join(sb, "inputs", `split.ad${i + 1}`), s));
  const r = spawnSync("python3", [join(ROOT, "scripts", "evidence_catalog.py"), sb, "--recipes-from", CFB], { encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
  const rows = Object.fromEntries(readFileSync(join(sb, "catalog", "coverage.tsv"), "utf8").trimEnd().split("\n").slice(1).map((l) => { const [p, , status, why] = l.split("\t"); return [p, [status, why]]; }));
  assert.deepEqual(rows["inputs/case.ad1"], ["catalogued", "under catalog/case.ad1/ by computer-forensics-base/ad1-items:complete"]);
  assert.deepEqual(rows["inputs/split.ad1"], ["catalogued", "under catalog/split.ad1/ by computer-forensics-base/ad1-items:complete"], "its second segment is read from beside it");
  assert.equal(rows["inputs/split.ad2"][0], "not catalogued");
  assert.match(rows["inputs/split.ad2"][1], /computer-forensics-base\/ad1-items: segment 2 of 2 of an AD1 image: the image is read, and catalogued, from its first segment/);
  assert.equal(tsv(join(sb, "catalog", "case.ad1", "members.tsv")).length, 12);
  assert.match(readFileSync(join(sb, "catalog", "README.md"), "utf8"), /^Summary: .*, 2 AD1 logical image\(s\), /m);
});

// --- the derived catalogue goes on from what ad1_extract writes ---------------

const lines = (S: string): JournalLine[] => verifyJournalText(readFileSync(storePaths(S).journal, "utf8")).lines;
const of = (S: string, type: string) => lines(S).filter((l) => l.type === type);

async function eventually(ok: () => boolean, what: string, ms = 30000): Promise<void> {
  const end = Date.now() + ms;
  while (!ok()) {
    if (Date.now() > end) throw new Error(`not within ${ms} ms: ${what}`);
    await new Promise((r) => setTimeout(r, 50));
  }
}

async function until(svc: JobService, id: string): Promise<JobRecord> {
  await eventually(() => ["committed", "failed", "cancelled"].includes(svc.jobs.get(id)?.state ?? ""), `job ${id} done`);
  return svc.jobs.get(id)!;
}

test("an AD1 image a job makes is catalogued by the derived catalogue, and what ad1_extract writes from it, as a job, is catalogued in turn", async () => {
  const S = join(dir("ad1-derived-"), "run");
  for (const d of ["inputs", "tools", "catalog", "work/a1"]) mkdirSync(join(S, d), { recursive: true });
  writeFileSync(join(S, "inputs.json"), JSON.stringify({ files: [] }));
  cpSync(join(CFB, "tools", "ad1_extract"), join(S, "tools", "ad1_extract"), { recursive: true });
  const src = join(dir("ad1-src-"), "made.ad1");
  writeFileSync(src, ad1Image(tree()));
  const posts: Array<[string, string]> = [];
  const svc = new JobService({
    sandbox: S, run: "s000000", image: "img:test", workers: 2, workerCpus: 1, workerMemoryMib: 512, allowHosts: [], openNet: false,
    packDirs: [CFB], forging: false, minFreeMb: 1, derived: true,
    runWorker: localWorker(), destroyWorker: async () => ({ ok: true }),
    notify: async (to, body) => { posts.push([to, body]); }, identity: async (a) => ({ name: `${a}-name` }),
  });
  await svc.start();
  try {
    const made = await svc.submit("a1", { kind: "command", command: `cp '${src}' "$OUT/made.ad1"`, inputs: [] });
    assert.ok(made.ok, !made.ok ? made.reason : "");
    await until(svc, made.job.id);
    await eventually(() => of(S, "generation_committed").length > 0, "the AD1 image's generation");
    const offer = of(S, "derived_offered")[0] as JournalLine & { offered: Array<{ path: string; recipes: string[] }> };
    assert.deepEqual(offer.offered.map((o) => [o.path, o.recipes]), [["made.ad1", ["computer-forensics-base/ad1-items"]]], "offered by its own measure, to the recipe that reads it");
    const gen = of(S, "generation_committed")[0];
    assert.deepEqual([gen.recipe, gen.status], ["computer-forensics-base/ad1-items", "complete"]);
    assert.equal(tsv(join(S, "catalog", "gen", String(gen.generation), "members.tsv")).length, 12);
    // Extracted as a job, the zip inside it is offered and catalogued in turn.
    const ex = await svc.submit("a1", { kind: "tool", tool: "ad1_extract", args: { image: `store/jobs/${made.job.id}/out/made.ad1`, out_dir: "{OUT}/made" }, inputs: [`job:${made.job.id}`] });
    assert.ok(ex.ok, !ex.ok ? ex.reason : "");
    const job = await until(svc, ex.job.id);
    assert.equal(job.status, "ok", readFileSync(join(storePaths(S).jobs, ex.job.id, "stdout.log"), "utf8"));
    assert.deepEqual(readFileSync(join(storePaths(S).jobs, ex.job.id, "out", "made", "C:", "Users", "alice", "evidence.zip")), zipBytes);
    await eventually(() => of(S, "generation_committed").some((l) => l.recipe === "computer-forensics-base/archive-members"), "the zip's generation");
    const zipGen = of(S, "generation_committed").find((l) => l.recipe === "computer-forensics-base/archive-members")!;
    assert.equal((zipGen.target as { ref: string }).ref, `job:${ex.job.id}/made/C:/Users/alice/evidence.zip`);
    assert.equal(zipGen.status, "complete");
  } finally {
    await svc.stop("over");
  }
});
