/**
 * ad1_extract's ways of choosing, and the ad1-items recipe's two phases
 * (the Batman III runs, findings I-09 and I-24): a list with nothing written
 * out (`list: true`), members by path pattern (`paths`) or from a file
 * (`members_file`), a walk that stops once every item named is written, a
 * selection judged apart from the image, selectors that say what they were
 * taken for, answers that name the store's paths and never a staging path, a
 * whole tree written only on purpose, and a catalogue whose listing is whole
 * on disk before a byte of content is inflated.
 *
 * Every image is built by tests/ad1-fixture.ts, from the format's layout: an
 * item's address is the one the builder gave it, never one the reader read.
 * No case evidence is read.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ad1Data, ad1Image, ad1Item, ad1Logical, ad1Segments, sha256, type Ad1Node } from "./ad1-fixture.ts";
import { runPy } from "./tool-library-harness.ts";

const ROOT = join(import.meta.dirname, "..");
const CFB = join(ROOT, "packs", "computer-forensics-base");
const RECIPE = join(CFB, "recipes", "ad1-items", "run.py");
const TOOL = join(CFB, "tools", "ad1_extract", "run.py");
const B = (s: string) => Buffer.from(s);
const notes = B("a line of notes\n".repeat(100));

/**
 * In the image's order:
 *   0 C:/  1 Users/  2 alice/  3 notes.txt  4 Report.TXT  5 empty.txt
 *   6 bob/  7 notes.txt  8 Windows/  9 system.evtx  10 readme.txt
 */
function tree(): Ad1Node[] {
  return [{
    name: "C:", folder: true, children: [
      { name: "Users", folder: true, children: [
        { name: "alice", folder: true, children: [
          { name: "notes.txt", content: notes },
          { name: "Report.TXT", content: B("a report") },
          { name: "empty.txt", content: Buffer.alloc(0) },
        ] },
        { name: "bob", folder: true, children: [{ name: "notes.txt", content: B("bob's notes") }] },
      ] },
      { name: "Windows", folder: true, children: [{ name: "system.evtx", content: B("events") }] },
      { name: "readme.txt", content: B("read me") },
    ],
  }];
}

const PATHS = ["C:", "C:/Users", "C:/Users/alice", "C:/Users/alice/notes.txt", "C:/Users/alice/Report.TXT", "C:/Users/alice/empty.txt",
  "C:/Users/bob", "C:/Users/bob/notes.txt", "C:/Windows", "C:/Windows/system.evtx", "C:/readme.txt"];

type Row = Record<string, string>;
function tsv(path: string): Row[] {
  const [head, ...lines] = readFileSync(path, "utf8").replace(/\n$/, "").split("\n");
  const cols = head.split("\t");
  return lines.map((l) => Object.fromEntries(l.split("\t").map((v, i) => [cols[i], v])));
}

/** A run directory with the tree as inputs/case.ad1, and the address the builder gave each item, in the image's order. */
function runDir(): { cwd: string; addr: number[] } {
  const cwd = mkdtempSync(join(tmpdir(), "ad1-select-"));
  mkdirSync(join(cwd, "inputs"));
  mkdirSync(join(cwd, "work", "s1"), { recursive: true });
  const t = tree();
  const built = ad1Data(t, { chunkSize: 512 });
  writeFileSync(join(cwd, "inputs", "case.ad1"), ad1Segments(built.data)[0]);
  const order: Ad1Node[] = [];
  const visit = (nodes: Ad1Node[]): void => { for (const n of nodes) { order.push(n); visit(n.children ?? []); } };
  visit(t);
  return { cwd, addr: order.map((n) => built.addr.get(n)!) };
}

const call = async (cwd: string, args: Record<string, unknown>, env: Record<string, string> = {}) => {
  const r = await runPy(TOOL, cwd, { image: "inputs/case.ad1", ...args }, undefined, { AGENT_ID: "s1", ...env });
  assert.doesNotMatch(r.stderr, /Traceback/, r.stderr);
  return { code: r.code, stdout: r.stdout, res: JSON.parse(r.stdout) };
};

test("list: true writes no file of the image out: every item as n, locator, type, size and path in a list, a bounded page in the answer", async () => {
  const { cwd, addr } = runDir();
  const { code, res } = await call(cwd, { list: true, out_dir: "work/s1/list", show: 3 });
  assert.equal(code, 0, JSON.stringify(res));
  assert.deepEqual([res.ok, res.mode, res.status, res.selection, res.image_status, res.integrity_status, res.unreferenced_check], [true, "list", "complete", "complete", "complete", "not_applicable", "run"]);
  assert.deepEqual([res.rows_total, res.shown, res.truncated, res.files, res.folders, res.content_bytes], [11, 3, true, 6, 5, notes.length + 8 + 11 + 6 + 7]);
  assert.deepEqual(res.columns, ["n", "locator", "type", "size", "path"]);
  assert.deepEqual(res.rows[2], { n: 2, locator: `ad1:item=${addr[2]}`, type: "dir", size: 0, path: "C:/Users/alice" });
  assert.match(res.note, /rows holds the first 3 of 11: every row is in list/);
  assert.match(res.status_basis, /every item of it was listed \(11\).*nothing was extracted/);
  const rows = tsv(join(cwd, "work", "s1", "list", "ad1_list.tsv"));
  assert.deepEqual(rows.map((x) => [x.n, x.locator, x.path]), PATHS.map((p, i) => [String(i), `ad1:item=${addr[i]}`, p]), "the builder's own addresses, in the image's order");
  assert.deepEqual([rows[3].type, rows[3].size, rows[6].type], ["file", String(notes.length), "dir"]);
  assert.deepEqual(readdirSync(join(cwd, "work", "s1", "list")).sort(), ["ad1_extract.coverage.json", "ad1_list.tsv"], "the list and the coverage record, and nothing of the image");
  const cov = JSON.parse(readFileSync(join(cwd, "work", "s1", "list", "ad1_extract.coverage.json"), "utf8"));
  assert.deepEqual([cov.mode, cov.processing_status, cov.image_status], ["list", "complete", "complete"]);
  // With a selection, the list is what the same call without list would write.
  const dry = await call(cwd, { list: true, members: [6], out_dir: "work/s1/dry" });
  assert.deepEqual(tsv(join(cwd, "work", "s1", "dry", "ad1_list.tsv")).map((x) => x.path), ["C:/Users/bob", "C:/Users/bob/notes.txt"]);
  assert.deepEqual([dry.res.status, dry.res.image_status, dry.res.walk.to_end], ["complete", "complete", true], "a folder's subtree is whole only if the tree is: walked to the end");
  const dryFile = await call(cwd, { list: true, members: [7], out_dir: "work/s1/dryfile" });
  assert.deepEqual([dryFile.res.rows_total, dryFile.res.image_status, dryFile.res.walk.stopped_early_at.n], [1, "not_checked", 8]);
  for (const bad of [1, "yes"]) assert.match((await call(cwd, { list: bad })).res.error, /list is true or false/);
});

test("paths takes the items whose whole path matches a pattern, letter case aside, a folder with its subtree, and a pattern that matches nothing is said", async () => {
  const { cwd } = runDir();
  const some = await call(cwd, { paths: ["*/alice/*.txt", "c:/windows"], out_dir: "work/s1/paths" });
  assert.equal(some.code, 0, some.stdout);
  assert.deepEqual(tsv(join(cwd, "work", "s1", "paths", "ad1_extract.tsv")).map((x) => x.n), ["3", "4", "5", "8", "9"], "Report.TXT by a lower-case pattern; Windows with what is under it");
  assert.deepEqual([some.res.status, some.res.selected.by, some.res.image_status, some.res.walk.to_end], ["complete", "paths", "complete", true], "a pattern may match the last item: the tree is walked to its end");
  assert.deepEqual(some.res.selected.paths_matched, { "*/alice/*.txt": 3, "c:/windows": 1 });
  assert.deepEqual(readFileSync(join(cwd, "work", "s1", "paths", "C:", "Users", "alice", "notes.txt")), notes);
  assert.ok(!existsSync(join(cwd, "work", "s1", "paths", "C:", "Users", "bob")));
  // "?" is one character, "*" any run with "/" in it, and a pattern with neither is the whole path.
  const one = await call(cwd, { list: true, paths: ["C:/Users/???/notes.txt", "C:/readme.txt", "*.EVTX"], out_dir: "work/s1/one" });
  assert.deepEqual(tsv(join(cwd, "work", "s1", "one", "ad1_list.tsv")).map((x) => x.n), ["7", "9", "10"]);
  const none = await call(cwd, { paths: ["*.avi", "*.txt"], out_dir: "work/s1/none" });
  assert.equal(none.code, 1, "a pattern that names nothing is not a complete answer");
  assert.deepEqual([none.res.status, none.res.files], ["partial", 5]);
  assert.match(none.res.errors[0], /no item's path matches "\*\.avi" in this read of the image \(it listed 11 items\)/);
  assert.match(none.res.status_basis, /^1 selector\(s\) named no item that was met \(see errors\)$/);
  // A pattern with "?" costs its length times the path's, so it is not tried on a path past 1024 characters, and the answer says so
  // rather than call the selection whole; a pattern of "*" alone is tried on every path.
  const deep = mkdtempSync(join(tmpdir(), "ad1-select-deep-"));
  mkdirSync(join(deep, "inputs"));
  let node: Ad1Node = { name: "leaf.txt", content: B("deep") };
  for (let k = 0; k < 8; k++) node = { name: `${"d".repeat(199)}${k}`, folder: true, children: [node] };
  writeFileSync(join(deep, "inputs", "case.ad1"), ad1Image([node, { name: "top.txt", content: B("top") }]));
  const starOnly = await call(deep, { list: true, paths: ["*/leaf.txt"], out_dir: "work/s1/star" });
  assert.deepEqual([starOnly.code, starOnly.res.status, starOnly.res.rows_total], [0, "complete", 1]);
  const withMark = await call(deep, { list: true, paths: ["*/leaf.tx?", "top.tx?"], out_dir: "work/s1/mark" });
  assert.deepEqual([withMark.code, withMark.res.status, withMark.res.rows_total], [1, "partial", 1], "top.txt is listed; the deep path was not tried");
  assert.match(withMark.res.errors.join("\n"), /^4 item\(s\) have a path longer than 1024 characters, on which the pattern\(s\) with \? were not tried .*they are not claimed not to match/);
  assert.equal(withMark.res.errors.length, 1, "the pattern that was not tried everywhere is not said to match nothing");
  assert.match(withMark.res.status_basis, /^4 item\(s\) have a path too long for a pattern with \? to be tried on \(see errors\)$/);
  for (const bad of [[], "*.txt", [""], [1], Array.from({ length: 65 }, () => "*")]) assert.match((await call(cwd, { paths: bad })).res.error, /paths is a list of 1 to 64 patterns/);
});

test("a call that names files stops once they are written, and is answered for them: selection complete, the image said not to have been checked", async () => {
  const { cwd, addr } = runDir();
  const one = await call(cwd, { members: [3], out_dir: "work/s1/one" });
  assert.equal(one.code, 0, one.stdout);
  assert.deepEqual([one.res.ok, one.res.status, one.res.selection, one.res.integrity_status, one.res.image_status, one.res.unreferenced_check], [true, "complete", "complete", "verified", "not_checked", "not_run"]);
  assert.deepEqual(one.res.walk, { items_looked_at: 5, to_end: false, stopped_early_at: { n: 4, path: "C:/Users/alice/Report.TXT" } }, "it looked at the item after the one asked for, and no further");
  assert.match(one.res.status_basis, /^every item named \(1\) was found and written; the walk stopped there, at item 4 of the image's order, so the rest of the image was not looked at and the image-wide checks were not run \(image_status\)$/);
  assert.match(one.res.image_basis, /the items after it in the image's order were not looked at, and the image-wide checks .* were not run/);
  assert.match(one.res.integrity_note, /verified is of the 1 file\(s\) written.*the unreferenced-data check did not run \(the walk stopped once every item named was written\)/);
  assert.equal(one.res.unreferenced_data, undefined);
  assert.deepEqual(tsv(join(cwd, "work", "s1", "one", "ad1_extract.tsv")).map((x) => [x.n, x.sha256, x.check]), [["3", sha256(notes), "ok"]]);
  // A locator and a number together are both waited for, in whatever order they were named.
  const two = await call(cwd, { members: [7, `ad1:item=${addr[4]}`], out_dir: "work/s1/two" });
  assert.deepEqual(tsv(join(cwd, "work", "s1", "two", "ad1_extract.tsv")).map((x) => x.n), ["4", "7"]);
  assert.deepEqual([two.res.status, two.res.walk.stopped_early_at.n, two.res.selected.numbers_found, two.res.selected.locators_found], ["complete", 8, 1, 1]);
  // A folder takes its subtree, and a subtree is whole only if the tree is: the walk goes to the end and the checks are run.
  const folder = await call(cwd, { members: [`ad1:item=${addr[2]}`, 7], out_dir: "work/s1/folder" });
  assert.deepEqual(tsv(join(cwd, "work", "s1", "folder", "ad1_extract.tsv")).map((x) => x.n), ["2", "3", "4", "5", "7"]);
  assert.deepEqual([folder.res.status, folder.res.image_status, folder.res.unreferenced_check, folder.res.walk], ["complete", "complete", "run", { items_looked_at: 11, to_end: true }]);
  assert.equal(folder.res.status_basis, "the tree was walked to its end, every item selected was written (2 named, with the subtree of each: 5 items), and the data the tree leads to accounts for the image's");
  // The last item of the image: the walk ends by itself, and the image-wide checks are run and said.
  const last = await call(cwd, { members: [10], out_dir: "work/s1/last" });
  assert.deepEqual([last.res.status, last.res.image_status, last.res.unreferenced_check, last.res.walk.to_end], ["complete", "complete", "run", true]);
});

test("a pointer zeroed inside a folder cuts its subtree with no error: a call for the folder is partial, a call for a file is answered for the file", async () => {
  const t = tree();
  const built = ad1Data(t, { chunkSize: 512 });
  // notes.txt's next pointer zeroed: Report.TXT and empty.txt are no longer in alice's subtree, and no read fails.
  const notesAt = built.addr.get(t[0].children![0].children![0].children![0])!;
  const cut = Buffer.from(built.data);
  cut.fill(0, notesAt, notesAt + 8);
  const cwd = mkdtempSync(join(tmpdir(), "ad1-select-cut-"));
  mkdirSync(join(cwd, "inputs"));
  writeFileSync(join(cwd, "inputs", "case.ad1"), ad1Segments(cut)[0]);
  const folder = await call(cwd, { members: [2], out_dir: "work/s1/folder" });
  assert.equal(folder.code, 1, folder.stdout);
  assert.deepEqual([folder.res.ok, folder.res.status, folder.res.selection, folder.res.integrity_status, folder.res.image_status, folder.res.files], [false, "partial", "partial", "unverified", "partial", 1],
    "the one file left under alice is written, and the subtree is not called whole");
  assert.match(folder.res.errors.join("\n"), /bytes of the image's data that are not zero are reached by no item/);
  assert.equal(folder.res.status_basis, "the tree does not account for all of the image's data (see errors)");
  // The file itself is found by its number and matches its digests: that answer does not rest on the rest of the tree.
  const file = await call(cwd, { members: [3], out_dir: "work/s1/file" });
  assert.deepEqual([file.code, file.res.status, file.res.integrity_status, file.res.image_status], [0, "complete", "verified", "not_checked"]);
  assert.deepEqual(readFileSync(join(cwd, "work", "s1", "file", "C:", "Users", "alice", "notes.txt")), notes);
  // The last file of the image, by its number in this read: the walk ends by itself, the check runs, and what it finds is the image's.
  const last = await call(cwd, { members: [8], out_dir: "work/s1/last" });
  assert.deepEqual([last.code, last.res.status, last.res.integrity_status, last.res.image_status, last.res.unreferenced_check, last.res.errors], [0, "complete", "verified", "partial", "run", undefined]);
  assert.match(last.res.image_errors.join("\n"), /reached by no item/);
  assert.match(last.res.integrity_note, /^verified is of the 1 file\(s\) written: .*; the tree does not account for all of the image's data \(image_status\), which is a finding about the image and not about these files$/);
});

test("what is wrong elsewhere in the image is the image's status, not the selection's; what may have cut the selection is the selection's", async () => {
  // A{B, C}, D, E with B and C alone in a second segment, which is not there.
  const span = 65536 - 512;
  const at: Record<string, number> = {};
  const data = ad1Logical((put, where) => {
    const e = ad1Item(put, "E.txt");
    const d = ad1Item(put, "D.txt", { next: e.at });
    const a = ad1Item(put, "A", { folder: true, next: d.at });
    put(Buffer.alloc(span - where() + 16));
    const c = ad1Item(put, "C.txt");
    const b = ad1Item(put, "B.txt", { next: c.at });
    a.header.writeBigUInt64LE(BigInt(b.at), 8);
    Object.assign(at, { a: a.at, d: d.at });
    return a.at;
  });
  const segs = ad1Segments(data, 65536);
  const cwd = mkdtempSync(join(tmpdir(), "ad1-select-seg-"));
  mkdirSync(join(cwd, "inputs"));
  writeFileSync(join(cwd, "inputs", "case.ad1"), segs[0]);
  // D.txt lies in the first segment: it is written whole, and the missing segment is said as the image's.
  const d = await call(cwd, { members: [`ad1:item=${at.d}`], out_dir: "work/s1/d" });
  assert.equal(d.code, 0, d.stdout);
  assert.deepEqual([d.res.ok, d.res.status, d.res.selection, d.res.errors, d.res.image_status], [true, "complete", "complete", undefined, "not_checked"]);
  assert.match(d.res.image_errors[0], /the image has 2 segments and 1 of them \(case\.ad2\) is not there/);
  assert.deepEqual(d.res.segments_missing, ["case.ad2"]);
  // A's children lie in the missing segment: the folder was asked for with its subtree, and the subtree is cut.
  const a = await call(cwd, { members: [`ad1:item=${at.a}`], out_dir: "work/s1/a" });
  assert.equal(a.code, 1, a.stdout);
  assert.deepEqual([a.res.ok, a.res.status, a.res.selection], [false, "partial", "partial"]);
  assert.match(a.res.errors.join("\n"), /item at address \d+ under A cannot be read: address \d+ is in segment 2, which is not there/);
  assert.equal(a.res.status_basis, "1 segment(s) of the image are not there; 1 item(s) of the tree could not be read (see errors)");
  // A file that was named, whose own child (a stream, say) lies in the missing segment: the file is written, and the call is not
  // called complete, because what could not be read comes right after what was taken.
  const fAt: Record<string, number> = {};
  const withChild = ad1Logical((put, where) => {
    const d2 = ad1Item(put, "D.txt");
    const f = ad1Item(put, "F.bin", { next: d2.at });
    put(Buffer.alloc(span - where() + 16));
    const stream = ad1Item(put, "stream");
    f.header.writeBigUInt64LE(BigInt(stream.at), 8);
    Object.assign(fAt, { f: f.at, d: d2.at });
    return f.at;
  });
  writeFileSync(join(cwd, "inputs", "child.ad1"), ad1Segments(withChild, 65536)[0]);
  const f = await call(cwd, { image: "inputs/child.ad1", members: [`ad1:item=${fAt.f}`], out_dir: "work/s1/f" });
  assert.deepEqual([f.code, f.res.status, f.res.files], [1, "partial", 1]);
  assert.equal(f.res.status_basis, "1 item(s) inside or right after what was taken could not be read, so a subtree may be cut (see errors)");
  assert.match(f.res.errors[0], /item at address \d+ under F\.bin cannot be read: address \d+ is in segment 2, which is not there/);
  const d3 = await call(cwd, { image: "inputs/child.ad1", members: [`ad1:item=${fAt.d}`], out_dir: "work/s1/d3" });
  assert.deepEqual([d3.code, d3.res.status, d3.res.errors], [0, "complete", undefined], "the same unreadable item, met before anything was taken, is the image's");
  assert.match(d3.res.image_errors.join("\n"), /under F\.bin cannot be read/);
  // The whole tree, or a pattern, cannot be whole unless the list is: there the image's errors are the call's, as before.
  const all = await call(cwd, { whole: true, out_dir: "work/s1/all" });
  assert.equal(all.code, 1);
  assert.deepEqual([all.res.status, all.res.image_status, all.res.image_errors], ["partial", "partial", undefined]);
  assert.match(all.res.status_basis, /^1 segment\(s\) of the image are not there; 1 item\(s\) of the tree could not be read \(see errors\)$/);
  const glob = await call(cwd, { paths: ["D.txt"], out_dir: "work/s1/glob" });
  assert.deepEqual([glob.code, glob.res.status, glob.res.files], [1, "partial", 1]);
});

test("a number given as text is taken as the number and said; a locator whose value is an item number, and a number that is an item's address, get a hint", async () => {
  const { cwd, addr } = runDir();
  const quoted = await call(cwd, { members: ["3"], out_dir: "work/s1/quoted" });
  assert.equal(quoted.code, 0, quoted.stdout);
  assert.deepEqual(tsv(join(cwd, "work", "s1", "quoted", "ad1_extract.tsv")).map((x) => x.path), ["C:/Users/alice/notes.txt"]);
  assert.deepEqual(quoted.res.adjusted, ['1 member(s) were given as text made of digits ("3"): each was taken as an item number (n), as the number itself is; an item\'s address is written ad1:item=<address>']);
  // ad1:item=<n>: no item has the address 3, and 3 is an item's number.
  const asLocator = await call(cwd, { members: ["ad1:item=3"], out_dir: "work/s1/asloc" });
  assert.equal(asLocator.code, 1);
  assert.deepEqual([asLocator.res.status, asLocator.res.files], ["failed", 0]);
  assert.match(asLocator.res.errors[0], /^no item at ad1:item=3 in this read of the image; 3 is a valid item number: did you mean item number 3 \(C:\/Users\/alice\/notes\.txt\)\? Pass it as the number 3, not as a locator; the nearest items this read holds are at ad1:item=\d+/);
  // A bare address: no item has that number, so it is not read as one in silence, and the item at that address is named.
  assert.ok(addr[7] > 11, "the address is not also an item number of this image");
  const bare = await call(cwd, { members: [addr[7]], out_dir: "work/s1/bare" });
  assert.equal(bare.code, 1);
  assert.equal(bare.res.files, 0, "nothing is written for a selector that named nothing");
  assert.match(bare.res.errors[0], new RegExp(`^no item ${addr[7]} in this read of the image \\(it listed 11 items\\)\\. A bare number is an item number \\(n\\), counted from 0 in the image's order .*; ${addr[7]} is the address of item number 7 \\(C:/Users/bob/notes\\.txt\\): did you mean the locator "ad1:item=${addr[7]}"\\?`));
  // A value that is neither stays refused, before anything is read.
  for (const bad of ["notes.txt", "3.0", "-3", "ad1:item=3 ", 3.5, true, null]) assert.match((await call(cwd, { members: [bad] })).res.error, /members holds .*: an item number \(n, as a number: 1234\) or a locator/);
});

test("members_file takes the selectors from a file: a table's locator or n column, a column by name or number, or one selector a line", async () => {
  const { cwd, addr } = runDir();
  await call(cwd, { list: true, out_dir: "work/s1/list" });
  const listed = readFileSync(join(cwd, "work", "s1", "list", "ad1_list.tsv"), "utf8").split("\n");
  // A cut of the tool's own list: the header and two rows. The locator column is taken without being named.
  writeFileSync(join(cwd, "work", "s1", "cut.tsv"), [listed[0], listed[4], listed[10], ""].join("\n"));
  const byLocator = await call(cwd, { members_file: "work/s1/cut.tsv", out_dir: "work/s1/f1" });
  assert.equal(byLocator.code, 0, byLocator.stdout);
  assert.deepEqual(tsv(join(cwd, "work", "s1", "f1", "ad1_extract.tsv")).map((x) => x.n), ["3", "9"]);
  assert.deepEqual(byLocator.res.members_file, { path: "work/s1/cut.tsv", column: "locator", locators: 2, numbers: 0 });
  assert.deepEqual([byLocator.res.status, byLocator.res.selected.by, byLocator.res.walk.stopped_early_at.n], ["complete", "members", 10], "two files: the walk stops after the second");
  const byName = await call(cwd, { members_file: "work/s1/cut.tsv", column: "n", out_dir: "work/s1/f2" });
  assert.deepEqual([byName.res.members_file.column, byName.res.members_file.numbers, byName.res.files], ["n", 2, 2]);
  const byNumber = await call(cwd, { members_file: "work/s1/cut.tsv", column: 2, out_dir: "work/s1/f3" });
  assert.deepEqual([byNumber.res.members_file.column, byNumber.res.members_file.locators, byNumber.res.files], ["locator", 2, 2]);
  // One a line, no header, comments and empty lines passed over, CRLF taken; members and the file are one selection.
  writeFileSync(join(cwd, "work", "s1", "lines.txt"), `# bob's notes and the readme\r\nad1:item=${addr[7]}\r\n\r\n10\r\n`);
  const lines = await call(cwd, { members_file: "work/s1/lines.txt", members: [5], out_dir: "work/s1/f4" });
  assert.deepEqual(tsv(join(cwd, "work", "s1", "f4", "ad1_extract.tsv")).map((x) => x.n), ["5", "7", "10"]);
  assert.deepEqual(lines.res.members_file, { path: "work/s1/lines.txt", column: 1, locators: 1, numbers: 1 });
  // A locator the image does not hold (a list a model wrote from memory) is named, and the rest is written.
  writeFileSync(join(cwd, "work", "s1", "invented.txt"), `ad1:item=${addr[3]}\nad1:item=${addr[3] + 1}\n`);
  const invented = await call(cwd, { members_file: "work/s1/invented.txt", out_dir: "work/s1/f5" });
  assert.deepEqual([invented.code, invented.res.status, invented.res.files, invented.res.selected.locators, invented.res.selected.locators_found], [1, "partial", 1, 2, 1]);
  assert.match(invented.res.errors[0], new RegExp(`^no item at ad1:item=${addr[3] + 1} in this read of the image`));
  // Refusals, each before anything is written.
  writeFileSync(join(cwd, "work", "s1", "bad.txt"), "3\nC:/Users/alice/notes.txt\n");
  writeFileSync(join(cwd, "work", "s1", "wide.tsv"), "a\tb\n1\t2\n");
  writeFileSync(join(cwd, "work", "s1", "empty.txt"), "# nothing\n\n");
  for (const [args, why] of [
    [{ members_file: "work/s1/bad.txt" }, /neither a locator \(ad1:item=<address>\) nor an item number: line 2: "C:\/Users\/alice\/notes\.txt"; nothing was extracted/],
    [{ members_file: "work/s1/wide.tsv" }, /has 2 columns and none is named locator or n: name the one that holds the selectors/],
    [{ members_file: "work/s1/cut.tsv", column: "address" }, /has no column named "address" in its first line \(it has: "n", "locator", "type", "size", "path"\)/],
    [{ members_file: "work/s1/cut.tsv", column: 9 }, /has 5 column\(s\) in its first line, and column 9 was asked for/],
    [{ members_file: "work/s1/cut.tsv", column: "path" }, /neither a locator .* nor an item number: line 2/],
    [{ members_file: "work/s1/empty.txt" }, /holds no selector/],
    [{ members_file: "work/s1/absent.txt" }, /members_file cannot be read: No such file or directory/],
    [{ members_file: "work/s1" }, /members_file cannot be read/],
    [{ column: "n", members: [3] }, /column goes with members_file/],
    [{ members_file: "work/s1/cut.tsv", column: 0 }, /column is a header's name \(locator, n\) or a column's number from 1/],
  ] as const) {
    const r = await call(cwd, { ...args, out_dir: "work/s1/refused" });
    assert.equal(r.code, 1, JSON.stringify(args));
    assert.match(r.res.error, why, JSON.stringify(args));
    assert.ok(!existsSync(join(cwd, "work", "s1", "refused")), JSON.stringify(args));
  }
});

test("a call that names nothing writes a small image out, and answers for a large one with its list: the whole tree is written only with whole: true", async () => {
  const { cwd } = runDir();
  // 11 items, 5 allowed: the call lists, and says how to have the tree.
  const guarded = await call(cwd, { whole_guard_items: 5, out_dir: "work/s1/guarded" });
  assert.equal(guarded.code, 0, guarded.stdout);
  assert.deepEqual([guarded.res.ok, guarded.res.mode, guarded.res.status, guarded.res.rows_total, guarded.res.integrity_status], [true, "list", "complete", 11, "not_applicable"]);
  assert.match(guarded.res.whole_not_written, /^the image holds more than 5 items or 2147483648 bytes of content, and the call named no members, paths or members_file: nothing was extracted and the image's items are listed instead\. .*whole: true writes the whole tree/);
  assert.deepEqual(readdirSync(join(cwd, "work", "s1", "guarded")).sort(), ["ad1_extract.coverage.json", "ad1_list.tsv"], "nothing of the image was written");
  assert.equal(tsv(join(cwd, "work", "s1", "guarded", "ad1_list.tsv")).length, 11);
  // The bytes of content count too: the tree holds more than 1000.
  const byBytes = await call(cwd, { whole_guard_bytes: 1000, out_dir: "work/s1/bytes" });
  assert.deepEqual([byBytes.res.mode, byBytes.res.rows_total], ["list", 11]);
  assert.match(byBytes.res.whole_not_written, /more than 50000 items or 1000 bytes of content/);
  // whole: true is the tree, whatever the thresholds; so is a selection, which the guard never meets.
  const whole = await call(cwd, { whole: true, whole_guard_items: 5, out_dir: "work/s1/whole" });
  assert.deepEqual([whole.code, whole.res.mode, whole.res.status, whole.res.items, whole.res.files, whole.res.whole_not_written], [0, "extract", "complete", 11, 6, undefined]);
  const named = await call(cwd, { members: [0], whole_guard_items: 5, out_dir: "work/s1/named" });
  assert.deepEqual([named.res.mode, named.res.items, named.res.status], ["extract", 11, "complete"]);
  // Within the thresholds (the defaults: 50,000 items, 2 GiB) a call that names nothing writes the tree, as it always did.
  const small = await call(cwd, { out_dir: "work/s1/small" });
  assert.deepEqual([small.code, small.res.mode, small.res.items, small.res.selected.by], [0, "extract", 11, "whole"]);
  assert.ok(!existsSync(join(cwd, "work", "s1", "small", "ad1_list.tsv")));
  for (const bad of [0, "5", 1.5]) assert.match((await call(cwd, { whole_guard_items: bad })).res.error, /whole_guard_items is a whole number from 1 to/);
  assert.match((await call(cwd, { whole: "yes" })).res.error, /whole is true or false/);
});

test("a partial answer's status_basis names the causes that applied and no other, and a budget-stopped verified says the unreferenced-data check did not run", async () => {
  const { cwd } = runDir();
  const budget = await call(cwd, { whole: true, max_items: 5, out_dir: "work/s1/budget" });
  assert.equal(budget.code, 0, "a budget's stop between items is exit 0");
  assert.deepEqual([budget.res.status, budget.res.integrity_status, budget.res.image_status, budget.res.unreferenced_check], ["partial", "verified", "not_checked", "not_run"]);
  assert.equal(budget.res.status_basis, "a budget stopped the call (the item budget of 5 items was reached) (see errors)");
  assert.match(budget.res.integrity_note, /^verified is of the 2 file\(s\) written: each matches the MD5 and SHA-1 the image records for it; the unreferenced-data check did not run \(a budget stopped the walk\), so nothing is said of whether the image holds items the tree does not lead to$/);
  assert.match(budget.res.image_basis, /the walk stopped before the end of the tree \(the item budget of 5 items was reached\), after 6 items: the image-wide checks .* were not run/);
  const absent = await call(cwd, { members: [3, 99], out_dir: "work/s1/absent" });
  assert.equal(absent.res.status_basis, "1 selector(s) named no item that was met (see errors)");
  const walk = await call(cwd, { members: [9], max_walk: 4, out_dir: "work/s1/walk" });
  assert.deepEqual([walk.code, walk.res.status], [0, "failed"]);
  assert.equal(walk.res.status_basis, "a budget stopped the call (the walk budget of 4 items was reached); 1 selector(s) named no item that was reached before the stop (see errors): no item was written");
  // A complete whole-tree answer says the check ran, and has nothing to add to verified.
  const all = await call(cwd, { whole: true, out_dir: "work/s1/all" });
  assert.deepEqual([all.res.status, all.res.integrity_status, all.res.unreferenced_check], ["complete", "verified", "run"]);
  assert.equal(all.res.integrity_note, "verified is of the 6 file(s) written: each matches the MD5 and SHA-1 the image records for it");
});

test("in a job every path an answer names is the store's (job:<id>/<path>), the list's and a refusal's included", async () => {
  const { cwd } = runDir();
  const out = join(cwd, ".jobs", "j000042");
  mkdirSync(out, { recursive: true });
  const env = { JOB_ID: "j000042", OUT: out };
  const listed = await call(cwd, { list: true }, env);
  assert.deepEqual([listed.res.out_dir, listed.res.out_relative, listed.res.list, listed.res.coverage], ["job:j000042/case", "case", "job:j000042/case/ad1_list.tsv", "job:j000042/case/ad1_extract.coverage.json"]);
  assert.ok(existsSync(join(out, "case", "ad1_list.tsv")));
  assert.ok(!listed.stdout.includes(out), listed.stdout);
  assert.equal(listed.res.note.includes("not sealed"), false);
  const taken = await call(cwd, { members: [3], out_dir: "{OUT}/x".replace("{OUT}", out) }, env);
  assert.deepEqual([taken.res.out_dir, taken.res.manifest], ["job:j000042/x", "job:j000042/x/ad1_extract.tsv"]);
  const top = await call(cwd, { members: [9], out_dir: out + "/" }, env);
  assert.deepEqual([top.code, top.res.error, top.res.out_dir], [1, "out_dir already holds something: name a new or empty directory", out + "/"], "a refusal repeats the caller's own words");
  // The default directory, refused because it is taken, is named by its place under $OUT.
  const again = await call(cwd, { members: [3] }, env);
  assert.deepEqual([again.code, again.res.out_dir], [1, "$OUT/case"]);
  assert.ok(!again.stdout.includes(out), again.stdout);
});

test("on 400,000 items a one-member call returns in under 10 seconds with selection complete, and the list of every item in under 30", async () => {
  const cwd = mkdtempSync(join(tmpdir(), "ad1-select-big-"));
  mkdirSync(join(cwd, "inputs"));
  const dirs: Ad1Node[] = [];
  for (let k = 0; k < 400; k++) {
    const kids: Ad1Node[] = [];
    for (let i = 0; i < 1000; i++) kids.push({ name: `f${i}.txt`, content: i === 500 ? B(`file 500 of d${k}`) : Buffer.alloc(0) });
    dirs.push({ name: `d${k}`, folder: true, children: kids });
  }
  writeFileSync(join(cwd, "inputs", "case.ad1"), ad1Image(dirs));
  try {
    // d200 is item 200 * 1001; its f500.txt is 501 items on.
    const n = 200 * 1001 + 501;
    let began = Date.now();
    const one = await call(cwd, { members: [n], out_dir: "work/s1/one" });
    const oneMs = Date.now() - began;
    assert.equal(one.code, 0, one.stdout);
    assert.deepEqual([one.res.status, one.res.selection, one.res.integrity_status, one.res.files, one.res.walk.items_looked_at], ["complete", "complete", "verified", 1, n + 2]);
    assert.equal(readFileSync(join(cwd, "work", "s1", "one", "d200", "f500.txt"), "utf8"), "file 500 of d200");
    assert.ok(oneMs < 10_000, `the one-member call took ${oneMs} ms`);
    // Without a selection the image is past the guard (50,000 items): the call answers with the list.
    began = Date.now();
    const listed = await call(cwd, { out_dir: "work/s1/list" });
    const listMs = Date.now() - began;
    assert.deepEqual([listed.code, listed.res.mode, listed.res.status, listed.res.rows_total, listed.res.files, listed.res.folders, listed.res.shown, listed.res.truncated], [0, "list", "complete", 400400, 400000, 400, 50, true]);
    assert.match(listed.res.whole_not_written, /^the image holds more than 50000 items or 2147483648 bytes of content/);
    const lines = readFileSync(join(cwd, "work", "s1", "list", "ad1_list.tsv"), "utf8").split("\n");
    assert.equal(lines.length, 400400 + 2);
    assert.match(lines[n + 1], new RegExp(`^${n}\\tad1:item=\\d+\\tfile\\t16\\td200/f500\\.txt$`));
    assert.ok(listMs < 30_000, `the list took ${listMs} ms`);
  } finally {
    rmSync(cwd, { recursive: true, force: true });
  }
});

/** The recipe run in a directory of its own: its exit code, its last answer and its coverage record. */
function runRecipe(image: string, env: Record<string, string> = {}) {
  const out = mkdtempSync(join(tmpdir(), "ad1-phase-out-"));
  const r = spawnSync("python3", [RECIPE, "run", "--target", JSON.stringify({ paths: [image] }), "--out", out], { encoding: "utf8", env: { ...process.env, ...env } });
  return { r, out, said: JSON.parse(r.stdout.trim().split("\n").pop() ?? "{}"), cov: JSON.parse(readFileSync(join(out, "coverage.json"), "utf8")) };
}

test("the ad1-items recipe lists first: every listing file is whole and the record says digests pending before any content is inflated, then the digests are filled in", () => {
  const { cwd } = runDir();
  const image = join(cwd, "inputs", "case.ad1");
  // What is on disk at the moment the digest pass begins, copied aside by a wrapper that then lets the pass run.
  const snap = mkdtempSync(join(tmpdir(), "ad1-phase-snap-"));
  const out = mkdtempSync(join(tmpdir(), "ad1-phase-out-"));
  const wrapper = [
    "import importlib.util, shutil, sys",
    "spec = importlib.util.spec_from_file_location('ad1_items', sys.argv[1]); mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)",
    "inner = mod.digest_pass",
    "def digest_pass(img, out_dir, cov, deadline):",
    "    shutil.copytree(out_dir, sys.argv[2], dirs_exist_ok=True)",
    "    return inner(img, out_dir, cov, deadline)",
    "mod.digest_pass = digest_pass",
    "sys.exit(mod.main(['run.py', 'run', '--target', sys.argv[3], '--out', sys.argv[4]]))",
  ].join("\n");
  const r = spawnSync("python3", ["-c", wrapper, RECIPE, snap, JSON.stringify({ paths: [image] }), out], { encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr + r.stdout);
  // Phase 1, as it stood: the four listing files and a record that says what is still to come.
  assert.deepEqual(readdirSync(snap).sort(), ["attributes.tsv", "coverage.json", "image.json", "index.tsv", "members.tsv"]);
  const early = JSON.parse(readFileSync(join(snap, "coverage.json"), "utf8"));
  assert.deepEqual([early.status, early.phase, early.items, early.files, early.checked, early.digests_pending, early.integrity_status], ["partial", "listing complete; digests pending", 11, 6, 0, 6, "unverified"]);
  assert.deepEqual([early.phases.listing.status, early.phases.digests.status, early.phases.digests.files_pending], ["complete", "pending", 6]);
  assert.match(early.status_basis, /the listing phase is done \(11 items in [\d.]+ s; members\.tsv, attributes\.tsv, image\.json and index\.tsv are whole\); the digest pass is running/);
  assert.match(early.not_covered, /the content of 6 listed file\(s\), which the digest pass has not inflated \(check pending, sha256 empty\)/);
  const listed = tsv(join(snap, "members.tsv"));
  assert.deepEqual(listed.map((x) => x.path), PATHS, "every item is listed before the digests");
  assert.deepEqual(listed.map((x) => [x.check, x.sha256]), PATHS.map((_, i) => ([0, 1, 2, 6, 8].includes(i) ? ["", ""] : ["pending", ""])));
  assert.deepEqual([listed[3].size, listed[3].md5.length, listed[3].locator.startsWith("ad1:item=")], [String(notes.length), 32, true], "all but sha256 and check is there");
  assert.match(readFileSync(join(snap, "index.tsv"), "utf8"), /digests pending: the content of 6 file\(s\) is not inflated yet \(sha256 empty, check pending\)/);
  assert.equal(JSON.parse(readFileSync(join(snap, "image.json"), "utf8")).items, 11);
  // Phase 2: the same rows, with sha256 and check filled in, and a record that says both phases are done.
  const done = tsv(join(out, "members.tsv"));
  assert.deepEqual(done.map((x) => ({ ...x, sha256: "", check: x.check ? "pending" : "" })), listed, "nothing but sha256 and check moved");
  assert.deepEqual([done[3].sha256, done[3].check, done[5].check], [sha256(notes), "ok", "ok"]);
  const cov = JSON.parse(readFileSync(join(out, "coverage.json"), "utf8"));
  assert.deepEqual([cov.status, cov.phase, cov.checked, cov.digests_pending, cov.integrity_status, cov.phases.digests.status], ["complete", "listing complete; digests complete", 6, 0, "verified", "complete"]);
  assert.doesNotMatch(readFileSync(join(out, "index.tsv"), "utf8"), /pending/);
  assert.deepEqual(readdirSync(out).filter((x) => x.endsWith(".tmp")), [], "the copy the digests were written to is renamed over members.tsv");
});

test("RECIPE_PHASE=listing ends the recipe after the listing: partial, digests pending, and never verified", () => {
  const { cwd } = runDir();
  const image = join(cwd, "inputs", "case.ad1");
  const { r, out, said, cov } = runRecipe(image, { RECIPE_PHASE: "listing" });
  assert.equal(r.status, 0, r.stderr + r.stdout);
  assert.deepEqual(said, { ok: true, status: "partial", format: "AD1", items: 11, phase: "listing complete; digests pending" });
  assert.deepEqual([cov.status, cov.phase, cov.checked, cov.digests_pending, cov.integrity_status, cov.phases.listing.status, cov.phases.digests.status], ["partial", "listing complete; digests pending", 0, 6, "unverified", "complete", "not_run"]);
  assert.match(cov.status_basis, /^the listing is whole .*; the digest pass has not run: the content of 6 file\(s\) was not inflated, their sha256 is empty and their check says pending$/);
  assert.match(cov.not_covered, /the run was asked for the listing alone \(RECIPE_PHASE=listing\)/);
  assert.deepEqual(tsv(join(out, "members.tsv")).filter((x) => x.type === "file").map((x) => [x.check, x.sha256]), Array.from({ length: 6 }, () => ["pending", ""]));
  // The whole run gives what the one-pass recipe gave.
  const all = runRecipe(image);
  assert.deepEqual([all.said.status, all.said.phase, all.cov.status, all.cov.checked], ["complete", "listing complete; digests complete", "complete", 6]);
  const bad = spawnSync("python3", [RECIPE, "run", "--target", JSON.stringify({ paths: [image] }), "--out", mkdtempSync(join(tmpdir(), "ad1-phase-bad-"))], { encoding: "utf8", env: { ...process.env, RECIPE_PHASE: "digests" } });
  assert.equal(bad.status, 2);
  assert.match(JSON.parse(bad.stdout).error, /RECIPE_PHASE is listing \(phase 1 only\) or all/);
});

test("a stop during the digest pass leaves the listing as phase 1 wrote it, a record that says so, and no half-written copy", () => {
  const { cwd } = runDir();
  const image = join(cwd, "inputs", "case.ad1");
  const out = mkdtempSync(join(tmpdir(), "ad1-phase-stop-"));
  // The stop arrives after the third file's digest was made: the pass is in the middle of its copy of members.tsv.
  const wrapper = [
    "import importlib.util, os, signal, sys",
    "spec = importlib.util.spec_from_file_location('ad1_items', sys.argv[1]); mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)",
    "inner, seen = mod.digest_of, [0]",
    "def digest_of(*a):",
    "    got = inner(*a)",
    "    seen[0] += 1",
    "    if seen[0] == 3:",
    "        os.kill(os.getpid(), signal.SIGTERM)",
    "    return got",
    "mod.digest_of = digest_of",
    "sys.exit(mod.main(['run.py', 'run', '--target', sys.argv[2], '--out', sys.argv[3]]))",
  ].join("\n");
  const r = spawnSync("python3", ["-c", wrapper, RECIPE, JSON.stringify({ paths: [image] }), out], { encoding: "utf8" });
  assert.equal(r.status, 128 + 15, r.stderr + r.stdout);
  const said = JSON.parse(r.stdout.trim().split("\n").pop()!);
  assert.deepEqual([said.status, said.interrupted, said.phase], ["partial", true, "listing complete; digests pending"]);
  const cov = JSON.parse(readFileSync(join(out, "coverage.json"), "utf8"));
  assert.deepEqual([cov.status, cov.interrupted, cov.phase, cov.checked, cov.digests_pending, cov.digests_discarded, cov.integrity_status, cov.phases.digests.status], ["partial", true, "listing complete; digests pending", 0, 6, 3, "unverified", "interrupted"]);
  assert.match(cov.status_basis, /stopped by signal 15 during the digest pass: members\.tsv is the whole listing as phase 1 wrote it \(check pending on its files\), and the digests made before the stop \(3 file\(s\)\) were not kept/);
  const rows = tsv(join(out, "members.tsv"));
  assert.equal(rows.length, 11);
  assert.deepEqual(rows.filter((x) => x.type === "file").map((x) => x.check), Array.from({ length: 6 }, () => "pending"), "what the record says is what the file holds");
  assert.deepEqual(readdirSync(out).sort(), ["attributes.tsv", "coverage.json", "image.json", "index.tsv", "members.tsv"]);
});
