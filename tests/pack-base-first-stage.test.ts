/**
 * computer-forensics-base: the first-stage-candidates recipe and the note evidence/first-stage.
 *
 * The capability is done when a macro document that sits outside the usual folders is ranked first. The fixture is a small volume
 * written here: a profile with an ordinary document and a macro-enabled workbook under Documents, a legacy document on the Desktop, and
 * a macro-enabled document deep under Music, with the traces a first stage leaves beside it (a Recent shortcut of its name, its name in
 * the profile's registry hive and in an antivirus log, the document application's Prefetch file). A seat that looked only under
 * Documents, Desktop and Downloads would not have listed it. The recipe is run as the job service runs one: `run --target <JSON> --out
 * <dir>` from the run's root, every path relative and with spaces. Held too: the member-list form (names only), the rule the ranking
 * exists for (a "cannot be determined" needs the whole member list searched, and `whole_list_read` is false when it was not), the three
 * answers of detect, and that ad1-items declares its listing phase.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmod, lstat, mkdir, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { PYTHON3 } from "./host-gates.ts";
import { CFB, py, withRun, type Doc } from "./pack-base-media-fixture.ts";

const RECIPE = join(CFB, "recipes", "first-stage-candidates", "run.py");
const OUTSIDE = "Users/sam/Music/old albums/notes for you.docm";

/** The volume and a member list of it (a TSV with a path column, Windows separators); argv: the directory for both. */
const BUILD = String.raw`
import os, sys, zipfile
top = sys.argv[1]
root = top + "/vol one"
def w(path, data=b"x"):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    open(path, "wb").write(data)
def ooxml(path, vba):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("word/document.xml", "<w/>")
        if vba:
            z.writestr("word/vbaProject.bin", b"\xd0\xcf\x11\xe0")
sam = root + "/Users/sam"
ooxml(sam + "/Documents/quarterly plan.docx", False)
ooxml(sam + "/Documents/team budget.xlsm", True)
ooxml(sam + "/Music/old albums/notes for you.docm", True)
ooxml(sam + "/Pictures/renamed.docx", True)                     # a VBA project under a name that is not macro-enabled
w(sam + "/Desktop/letter.doc", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 600)
w(sam + "/Desktop/~$letter.doc")
w(sam + "/AppData/Roaming/Microsoft/Windows/Recent/notes for you.docm.lnk")
w(sam + "/NTUSER.DAT", b"regf" + b"\x00" * 100 + "[F00000000][T01DA]*C:\\Users\\sam\\Music\\old albums\\Notes For You.docm".encode("utf-16-le"))
w(root + "/Windows/System32/winevt/Logs/Microsoft-Windows-Windows Defender%4Operational.evtx", b"ElfFile\x00" + "file:_C:\\Users\\sam\\Music\\old albums\\notes for you.docm".encode("utf-16-le"))
w(root + "/Windows/Prefetch/WINWORD.EXE-1A2B3C4D.pf", b"MAM\x04")
for i in range(40):
    w(sam + "/Pictures/holiday %02d.jpg" % i)
rows = ["n\tlocator\ttype\tsize\tpath", "0\tx:0\tfolder\t0\tC:"]
n = 0
for d, _dirs, files in sorted(os.walk(root)):
    for f in sorted(files):
        n += 1
        rows.append("%d\tx:%d\tfile\t%d\tC:\\%s" % (n, n, os.path.getsize(os.path.join(d, f)), os.path.relpath(os.path.join(d, f), root).replace("/", "\\")))
os.makedirs(top + "/listing", exist_ok=True)
open(top + "/listing/members.tsv", "w").write("\n".join(rows) + "\n")
# The coverage record the recipe that wrote a list leaves beside it (a catalogue generation's coverage.json): this one says the list is whole.
open(top + "/listing/coverage.json", "w").write('{"recipe": "a-lister", "status": "complete", "status_basis": "every item of the image was listed"}')
print(n)
`;

function recipe(run: string, verb: "detect" | "run", target: unknown, out?: string, env: Record<string, string> = {}): { code: number | null; doc: Doc; stderr: string } {
  const r = spawnSync(PYTHON3, [RECIPE, verb, "--target", typeof target === "string" ? target : JSON.stringify(target), ...(out ? ["--out", out] : [])], { cwd: run, encoding: "utf8", env: { ...process.env, ...env }, timeout: 60_000 });
  let doc: Doc = {};
  try {
    doc = JSON.parse(r.stdout) as Doc;
  } catch {
    doc = { not_json: r.stdout.slice(0, 300) };
  }
  return { code: r.status, doc, stderr: r.stderr };
}

const table = async (path: string): Promise<Doc[]> => {
  const [head, ...rows] = (await readFile(path, "utf8")).trim().split("\n").map((l) => l.split("\t"));
  return rows.map((r) => Object.fromEntries(head!.map((h, i) => [h, r[i]])));
};

test("a macro document outside the usual folders is ranked first, with the signals that put it there, and the whole list was read", async () => {
  await withRun(async (run) => {
    const members = Number(py(BUILD, [join(run, "inputs/case files")], run).trim());
    const out = "store/jobs/j000001/out/first stage";
    const r = recipe(run, "run", { paths: ["inputs/case files/vol one"] }, out);
    assert.equal(r.code, 0, JSON.stringify(r.doc) + r.stderr);
    assert.equal(r.stderr, "");
    assert.deepEqual([r.doc.status, r.doc.members, r.doc.whole_list_read], ["complete", members, true]);
    assert.equal(r.doc.first[0].path, OUTSIDE);
    const rows = await table(join(run, out, "candidates.tsv"));
    assert.deepEqual(rows.map((x) => x.path), [OUTSIDE, "Users/sam/Pictures/renamed.docx", "Users/sam/Documents/team budget.xlsm", "Users/sam/Desktop/letter.doc"]);
    assert.deepEqual([rows[0]!.rank, rows[0]!.kind, rows[0]!.profile], ["1", "word", "sam"]);
    assert.ok(Number(rows[0]!.score) >= Number(rows[1]!.score) + 5, "it stands well above the next");
    for (const signal of [/\+3 a macro-enabled name \(\.docm\)/, /\+4 a VBA project inside, by the member list of its ZIP directory \(no member was opened\)/, /\+2 inside the profile but outside its usual document folders/,
      /\+3 a Recent shortcut carries its name \(the same profile\)/, /\+2 its name occurs in the bytes of the profile's NTUSER\.DAT .*the key was not read/, /\+4 its name occurs in the bytes of an antivirus log or detection file \(the event was not read\)/,
      /\+1 a Prefetch file of WINWORD\.EXE exists/]) {
      assert.match(rows[0]!.signals, signal);
    }
    // The workbook under Documents is a candidate too, and its row says where it lies: nothing is dropped for being ordinary.
    assert.match(rows[2]!.signals, /\+0 in a usual document folder/);
    assert.match(rows[1]!.signals, /\+4 a VBA project inside.*\+3 its name \(\.docx\) is not a macro-enabled one/, "a VBA project under a plain name is found in a tree, and the mismatch counts");
    assert.ok(!rows.some((x) => x.path.includes("quarterly plan") || x.path.includes("~$")), "a plain document without a project and an owner file are no candidates");
    const cov = JSON.parse(await readFile(join(run, out, "coverage.json"), "utf8")) as Doc;
    assert.deepEqual([cov.status, cov.whole_list_read, cov.members, cov.candidates, cov.mode], ["complete", true, members, 4, "tree"]);
    assert.match(cov.rule, /To answer "cannot be determined" to a "which file" question the whole member list must have been searched: whole_list_read says whether it was \(the recipe read the whole tree or list, and a member list's own coverage record says the list is complete\)\./);
    assert.match(cov.not_covered, /no macro was read or run/);
    assert.deepEqual(cov.sources, { recent_shortcuts: 1, registry_hives: 1, antivirus_files: 1, prefetch_applications: ["winword.exe"] });
  });
});

test("a member list gives the same first rank from names alone, and says what a list cannot hold", async () => {
  await withRun(async (run) => {
    const members = Number(py(BUILD, [join(run, "inputs/case files")], run).trim());
    const out = "store/jobs/j000001/out/from list";
    const r = recipe(run, "run", { paths: ["inputs/case files/listing/members.tsv"] }, out);
    assert.equal(r.code, 0, JSON.stringify(r.doc));
    const rows = await table(join(run, out, "candidates.tsv"));
    assert.equal(rows[0]!.path, "C:\\Users\\sam\\Music\\old albums\\notes for you.docm", "the path as the list has it: a backslash is one backslash, as in the list's text");
    assert.equal(rows.length, 3, "a project under a plain name is not seen from names");
    assert.doesNotMatch(rows[0]!.signals, /VBA project|NTUSER|antivirus/);
    assert.match(rows[0]!.signals, /a Recent shortcut carries its name/);
    const cov = JSON.parse(await readFile(join(run, out, "coverage.json"), "utf8")) as Doc;
    assert.deepEqual([cov.mode, cov.whole_list_read, cov.members, cov.list_form], ["member list", true, members + 1, "a TSV with a path column (column 5)"]);
    assert.deepEqual([cov.status, cov.list_read_to_its_end, cov.list_coverage.status, r.doc.list_coverage], ["complete", true, "complete", "complete"]);
    assert.match(cov.status_basis, /its own coverage record says the list is complete/);
    assert.match(cov.not_covered, /a member list has names only: nothing inside a file was read/);
  });
});

test("a member list that is itself partial, or whose coverage is not recorded, makes the ranking partial and whole_list_read false", async () => {
  await withRun(async (run) => {
    py(BUILD, [join(run, "inputs/case files")], run);
    const record = join(run, "inputs/case files/listing/coverage.json");
    // The shape a lister writes when a segment of its image is missing: the list it wrote holds only what it could read.
    await writeFile(record, JSON.stringify({ recipe: "a-lister", status: "partial", segments_missing: ["image.s03"], limits_hit: [],
      status_basis: "a segment is missing: what lies in it is not listed" }));
    const cut = recipe(run, "run", { paths: ["inputs/case files/listing/members.tsv"] }, "store/jobs/j000001/out/partial list");
    assert.equal(cut.code, 0, JSON.stringify(cut.doc));
    assert.deepEqual([cut.doc.status, cut.doc.whole_list_read, cut.doc.list_coverage], ["partial", false, "partial"]);
    const cov = JSON.parse(await readFile(join(run, "store/jobs/j000001/out/partial list/coverage.json"), "utf8")) as Doc;
    assert.deepEqual([cov.status, cov.whole_list_read, cov.list_read_to_its_end, cov.list_coverage.status, cov.list_coverage.recipe], ["partial", false, true, "partial", "a-lister"]);
    assert.deepEqual(cov.list_coverage.why, ["segments_missing: image.s03", "a segment is missing: what lies in it is not listed"]);
    assert.match(cov.status_basis, /^the ranking is of part of what was asked: the member list itself is not known to be whole: its coverage record \(coverage\.json\) says partial: segments_missing: image\.s03/);
    const rows = await table(join(run, "store/jobs/j000001/out/partial list/candidates.tsv"));
    assert.equal(rows.length, 3, "what the list holds is still ranked");

    await rm(record);
    const bare = recipe(run, "run", { paths: ["inputs/case files/listing/members.tsv"] }, "store/jobs/j000001/out/bare list");
    assert.deepEqual([bare.doc.status, bare.doc.whole_list_read, bare.doc.list_coverage], ["partial", false, "not recorded"]);
    const bareCov = JSON.parse(await readFile(join(run, "store/jobs/j000001/out/bare list/coverage.json"), "utf8")) as Doc;
    assert.match(bareCov.list_coverage.why[0], /^no coverage\.json beside the list/);

    await writeFile(record, "{not json");
    const unreadable = recipe(run, "run", { paths: ["inputs/case files/listing/members.tsv"] }, "store/jobs/j000001/out/odd list");
    assert.deepEqual([unreadable.doc.status, unreadable.doc.whole_list_read, unreadable.doc.list_coverage], ["partial", false, "unknown"]);
  });
});

test("a link in a tree is ranked by its own name and not followed, and makes the run partial; no output file is written through a link", async () => {
  await withRun(async (run) => {
    py(BUILD, [join(run, "inputs/case files")], run);
    // The link's target, outside the tree, holds a VBA project: it must not be read.
    py(String.raw`
import sys, zipfile
with zipfile.ZipFile(sys.argv[1], "w") as z:
    z.writestr("word/vbaProject.bin", b"x")
`, [join(run, "inputs/elsewhere.docm")], run);
    await mkdir(join(run, "inputs/case files/vol one/Users/sam/Downloads"), { recursive: true });
    await symlink(join(run, "inputs/elsewhere.docm"), join(run, "inputs/case files/vol one/Users/sam/Downloads/invoice copy.docm"));
    const out = "store/jobs/j000001/out/linked";
    await mkdir(join(run, out), { recursive: true });
    const victim = join(run, "inputs/left alone.txt");
    await writeFile(victim, "unchanged\n");
    for (const name of ["index.tsv", "candidates.tsv.tmp", "coverage.json.tmp"]) await symlink(victim, join(run, out, name));
    const r = recipe(run, "run", { paths: ["inputs/case files/vol one"] }, out);
    assert.equal(r.code, 0, JSON.stringify(r.doc) + r.stderr);
    assert.deepEqual([r.doc.status, r.doc.whole_list_read], ["partial", true]);
    const rows = await table(join(run, out, "candidates.tsv"));
    const row = rows.find((x) => x.path === "Users/sam/Downloads/invoice copy.docm");
    assert.ok(row, "the link is ranked by its name");
    assert.match(row!.signals, /\+0 a link in the tree: not followed, so only its own name was read/);
    assert.match(row!.signals, /\+0 not told whether it holds a VBA project: it is a link, which is not followed/);
    assert.doesNotMatch(row!.signals, /\+4 a VBA project inside/);
    const cov = JSON.parse(await readFile(join(run, out, "coverage.json"), "utf8")) as Doc;
    assert.equal(cov.links_not_followed, 1);
    assert.match(cov.status_basis, /1 link\(s\) in the tree were not followed: each is ranked by its own name only/);
    assert.equal(await readFile(victim, "utf8"), "unchanged\n", "nothing was written through a link in the output directory");
    assert.ok((await lstat(join(run, out, "index.tsv"))).isFile());
    assert.match(await readFile(join(run, out, "index.tsv"), "utf8"), /^candidates\.tsv\tfirst-stage candidates/);
  });
});

test("a list that was not read whole says so: whole_list_read is false and the status partial", async () => {
  await withRun(async (run) => {
    py(BUILD, [join(run, "inputs/case files")], run);
    for (const target of ["inputs/case files/vol one", "inputs/case files/listing/members.tsv"]) {
      const out = `store/jobs/j000001/out/cut ${target.endsWith(".tsv") ? "list" : "tree"}`;
      const r = recipe(run, "run", { paths: [target] }, out, { RECIPE_MEMBERS: "12" });
      assert.equal(r.code, 0);
      assert.deepEqual([r.doc.status, r.doc.whole_list_read], ["partial", false], target);
      const cov = JSON.parse(await readFile(join(run, out, "coverage.json"), "utf8")) as Doc;
      assert.equal(cov.whole_list_read, false);
      assert.match(cov.limits_hit[0], /^members: the (tree|list) has more than 12/);
      assert.match(cov.status_basis, /the ranking is of part of what was asked/);
    }
  });
});

test("detect has three answers, and a target that cannot be used is a JSON answer", async () => {
  await withRun(async (run) => {
    py(BUILD, [join(run, "inputs/case files")], run);
    assert.deepEqual([recipe(run, "detect", { paths: ["inputs/case files/vol one"] }).code, recipe(run, "detect", { paths: ["inputs/case files/listing/members.tsv"] }).code], [0, 0]);
    const no = recipe(run, "detect", { paths: ["inputs/case files/vol one/Windows/Prefetch"] });
    assert.deepEqual([no.code, no.doc.applies], [1, false]);
    const unknown = recipe(run, "detect", { paths: ["inputs/case files/absent"] });
    assert.deepEqual([unknown.code, unknown.doc.applies], [2, "unknown"]);
    for (const target of ["not json", "[]", { paths: [] }, { paths: [7] }, { paths: ["a\u0000b"] }]) {
      const r = recipe(run, "run", target, "store/jobs/j000001/out/x");
      assert.equal(r.code, 2, JSON.stringify(target));
      assert.equal(r.doc.ok, false);
      assert.equal(r.stderr, "");
    }
    const usage = recipe(run, "detect", { paths: ["x"] }, undefined);
    assert.ok(usage.code !== null);
  });
});

const cov = async (run: string, out: string): Promise<Doc> => JSON.parse(await readFile(join(run, out, "coverage.json"), "utf8")) as Doc;

test("the name search reads the clock inside a block: many names and a large hive of near misses end within the recipe's own seconds", async () => {
  await withRun(async (run) => {
    // 20,000 macro-enabled names and an 8 MiB hive whose text is all near misses of them (b00001.docm against a00001.docm). A search that
    // tests every name against a 4 MiB block before it looks at the clock again holds the run far past its seconds.
    py(String.raw`
import os, sys
root = sys.argv[1]
d = root + "/Users/sam/AppData/Local/Temp"
os.makedirs(d)
for i in range(20000):
    open(d + "/a%05d.docm" % i, "wb").close()
blk = "".join("b%05d.docm;" % (i % 100000) for i in range(200000)).encode("utf-16-le")[:4 << 20]
with open(root + "/Users/sam/NTUSER.DAT", "wb") as f:
    f.write(blk + blk)
`, [join(run, "inputs/many names")], run);
    const began = Date.now();
    const r = recipe(run, "run", { paths: ["inputs/many names"] }, "store/jobs/j000001/out/many", { RECIPE_SECONDS: "8" });
    const seconds = (Date.now() - began) / 1000;
    assert.equal(r.code, 0, JSON.stringify(r.doc) + r.stderr);
    assert.ok(seconds < 25, `the run took ${seconds} s against a limit of 8 s`);
    const c = await cov(run, "store/jobs/j000001/out/many");
    assert.equal(c.candidates, 20000);
    // Whatever the host's speed, the answer is consistent: a run the clock stopped says so.
    if (c.status === "complete") assert.equal(c.not_read_to_the_end, undefined);
    else assert.match(c.limits_hit.join(" "), /^seconds: the clock ran out/);
  });
});

test("a document under a plain name whose VBA check cannot be told is ranked, says so, and makes the run partial", async () => {
  await withRun(async (run) => {
    py(BUILD, [join(run, "inputs/case files")], run);
    // It begins like a ZIP and has no end-of-central-directory record.
    await writeFile(join(run, "inputs/case files/vol one/Users/sam/Pictures/statement.docx"), Buffer.concat([Buffer.from("PK\u0003\u0004"), Buffer.alloc(300)]));
    const out = "store/jobs/j000001/out/not told";
    const r = recipe(run, "run", { paths: ["inputs/case files/vol one"] }, out);
    assert.equal(r.code, 0, JSON.stringify(r.doc) + r.stderr);
    const rows = await table(join(run, out, "candidates.tsv"));
    const row = rows.find((x) => x.path === "Users/sam/Pictures/statement.docx");
    assert.ok(row, "the document is ranked");
    assert.match(row!.signals, /\+0 not told whether it holds a VBA project: it begins like a ZIP and has no end-of-central-directory record/);
    const c = await cov(run, out);
    assert.deepEqual([r.doc.status, c.status, c.whole_list_read], ["partial", "partial", true]);
    assert.match(c.not_read_to_the_end.join(" "), /whether a VBA project is inside could not be told for 1 document/);
    assert.doesNotMatch(c.status_basis, /every macro-capable document/);
  });
});

test("every candidate is a row: a list of 25,000 macro-enabled names gives 25,000 ranked rows", async () => {
  await withRun(async (run) => {
    py(String.raw`
import os, sys
top = sys.argv[1]
os.makedirs(top)
rows = ["path"] + ["C:\\Users\\sam\\AppData\\Local\\Temp\\report %05d.docm" % i for i in range(25000)]
open(top + "/members.tsv", "w").write("\n".join(rows) + "\n")
open(top + "/coverage.json", "w").write('{"recipe": "a-lister", "status": "complete"}')
`, [join(run, "inputs/big list")], run);
    const out = "store/jobs/j000001/out/big";
    const r = recipe(run, "run", { paths: ["inputs/big list/members.tsv"] }, out);
    assert.equal(r.code, 0, JSON.stringify(r.doc) + r.stderr);
    assert.deepEqual([r.doc.status, r.doc.candidates, r.doc.whole_list_read], ["complete", 25000, true]);
    const rows = await table(join(run, out, "candidates.tsv"));
    assert.equal(rows.length, 25000, "no row is cut");
    assert.equal(rows[24999]!.rank, "25000");
    assert.match(await readFile(join(run, out, "index.tsv"), "utf8"), /first-stage candidates \(25000\)/);
  });
});

test("more antivirus files than the recipe searches is a limit: in limits_hit, and the run partial", async () => {
  await withRun(async (run) => {
    py(String.raw`
import os, sys
root = sys.argv[1]
os.makedirs(root + "/Users/sam/Downloads")
open(root + "/Users/sam/Downloads/parcel note.docm", "wb").close()
d = root + "/ProgramData/Microsoft/Windows Defender/Support"
os.makedirs(d)
for i in range(450):
    text = "detected: C:\\Users\\sam\\Downloads\\parcel note.docm" if i == 449 else "nothing"
    open(d + "/MPLog-%03d.log" % i, "wb").write(text.encode("utf-16-le"))
`, [join(run, "inputs/av tree")], run);
    const out = "store/jobs/j000001/out/av";
    const r = recipe(run, "run", { paths: ["inputs/av tree"] }, out);
    assert.equal(r.code, 0, JSON.stringify(r.doc) + r.stderr);
    const c = await cov(run, out);
    assert.deepEqual([r.doc.status, c.status, c.antivirus_files_not_searched, c.whole_list_read], ["partial", "partial", 50, true], "every name was read; one signal's source was cut");
    assert.match(c.limits_hit.join(" "), /^antivirus: more than 400 antivirus logs and detection files/);
  });
});

test("a coverage record counts only for the list it stands for: another list beside it, a link to a list elsewhere, a record that contradicts itself", async () => {
  await withRun(async (run) => {
    py(BUILD, [join(run, "inputs/case files")], run);
    const listing = join(run, "inputs/case files/listing");
    // Another list beside a complete record (as attributes.tsv lies beside ad1-items' record): the record says nothing of it.
    await writeFile(join(listing, "subset.tsv"), (await readFile(join(listing, "members.tsv"), "utf8")).split("\n").slice(0, 8).join("\n") + "\n");
    const other = recipe(run, "run", { paths: ["inputs/case files/listing/subset.tsv"] }, "store/jobs/j000001/out/subset");
    assert.deepEqual([other.doc.status, other.doc.whole_list_read, other.doc.list_coverage], ["partial", false, "not named"]);
    // A link to a list whose own directory's record is partial, with a complete record beside the link.
    await mkdir(join(run, "inputs/cut gen"));
    await writeFile(join(run, "inputs/cut gen/members.tsv"), await readFile(join(listing, "members.tsv"), "utf8"));
    await writeFile(join(run, "inputs/cut gen/coverage.json"), JSON.stringify({ status: "partial", segments_missing: ["image.s02"] }));
    await mkdir(join(run, "inputs/link gen"));
    await symlink(join(run, "inputs/cut gen/members.tsv"), join(run, "inputs/link gen/members.tsv"));
    await writeFile(join(run, "inputs/link gen/coverage.json"), JSON.stringify({ status: "complete" }));
    const linked = recipe(run, "run", { paths: ["inputs/link gen/members.tsv"] }, "store/jobs/j000001/out/linked list");
    assert.deepEqual([linked.doc.status, linked.doc.whole_list_read, linked.doc.list_coverage], ["partial", false, "partial"]);
    assert.deepEqual((await cov(run, "store/jobs/j000001/out/linked list")).list_coverage.why, ["segments_missing: image.s02"]);
    // A record that says complete and lists a missing segment.
    await writeFile(join(listing, "coverage.json"), JSON.stringify({ status: "complete", segments_missing: ["image.s03"] }));
    const odd = recipe(run, "run", { paths: ["inputs/case files/listing/members.tsv"] }, "store/jobs/j000001/out/odd");
    assert.deepEqual([odd.doc.status, odd.doc.whole_list_read, odd.doc.list_coverage], ["partial", false, "partial"]);
    assert.match((await cov(run, "store/jobs/j000001/out/odd")).list_coverage.why[0], /says complete and lists segments_missing: it contradicts itself/);
  });
});

test("detect exits 2 where it cannot tell, and reads a list past its first megabytes", async () => {
  await withRun(async (run) => {
    // A list sorted by path: Program Files fills the first 5 MiB, the profile comes after.
    py(String.raw`
import os, sys
top = sys.argv[1]
os.makedirs(top)
with open(top + "/members.tsv", "w") as f:
    f.write("path\n")
    i = 0
    while f.tell() < 5 << 20:
        f.write("C:\\Program Files\\Vendor\\lib\\part %07d.dll\n" % i)
        i += 1
    f.write("C:\\Users\\sam\\NTUSER.DAT\n")
`, [join(run, "inputs/sorted")], run);
    const late = recipe(run, "detect", { paths: ["inputs/sorted/members.tsv"] });
    assert.deepEqual([late.code, late.doc.applies], [0, true], JSON.stringify(late.doc));
    if (process.getuid?.() !== 0) {
      // A directory that cannot be listed, and no profile in the rest: not told.
      await mkdir(join(run, "inputs/shut/Windows/locked"), { recursive: true });
      await chmod(join(run, "inputs/shut/Windows/locked"), 0o000);
      try {
        const shut = recipe(run, "detect", { paths: ["inputs/shut"] });
        assert.deepEqual([shut.code, shut.doc.applies], [2, "unknown"], JSON.stringify(shut.doc));
        assert.match(shut.doc.why, /could not be listed/);
      } finally {
        await chmod(join(run, "inputs/shut/Windows/locked"), 0o755);
      }
    }
    // A call detect cannot use is no answer about the object.
    for (const target of ["not json", { paths: [] }]) {
      const bad = recipe(run, "detect", target);
      assert.deepEqual([bad.code, bad.doc.applies], [2, "unknown"], JSON.stringify(target));
    }
  });
});

test("a ZIP directory of millions of records is walked no further than 20,000 records: memory stays small, and the run is partial", async () => {
  await withRun(async (run) => {
    // A .docm whose central directory declares 600,000 records (local header, records, end record).
    const doc = join(run, "inputs/zip tree/Users/sam/Downloads/huge.docm");
    py(String.raw`
import os, struct, sys
p, n = sys.argv[1], 600000
os.makedirs(os.path.dirname(p))
lh = struct.pack("<IHHHHHIIIHH", 0x04034b50, 20, 0, 0, 0, 0, 0, 0, 0, 1, 0) + b"a"
cd = struct.pack("<IHHHHHHIIIHHHHHII", 0x02014b50, 20, 20, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0) + b"a"
with open(p, "wb") as f:
    f.write(lh)
    for _ in range(n // 100000):
        f.write(cd * 100000)
    f.write(struct.pack("<IHHHHIIH", 0x06054b50, 0, 0, 0xFFFF, 0xFFFF, len(cd) * n, len(lh), 0))
`, [doc], run);
    const measured = JSON.parse(py(String.raw`
import importlib.util, json, resource, sys, time
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("first_stage", sys.argv[1])
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
unit = 1 if sys.platform == "darwin" else 1024
before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * unit
answer = m.vba_in_file(sys.argv[2], "word", time.monotonic() + 60)
after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * unit
print(json.dumps({"answer": list(answer), "grew": after - before}))
`, [RECIPE, doc], run)) as Doc;
    assert.ok(measured.grew < 64 << 20, `memory grew by ${measured.grew} bytes`);
    assert.equal(measured.answer[0], null);
    assert.match(measured.answer[1], /more than 20000 members: the first 20000 were walked/);
    const out = "store/jobs/j000001/out/zip";
    const r = recipe(run, "run", { paths: ["inputs/zip tree"] }, out);
    assert.equal(r.code, 0, JSON.stringify(r.doc) + r.stderr);
    const c = await cov(run, out);
    assert.equal(c.status, "partial");
    assert.match(c.limits_hit.join(" "), /^vba: a ZIP directory of more than 20000 members was walked only that far \(1 document/);
  });
});

test("a link to a directory outside the tree is not entered, and whole_list_read says the tree was not read whole", async () => {
  await withRun(async (run) => {
    py(BUILD, [join(run, "inputs/case files")], run);
    await mkdir(join(run, "inputs/elsewhere/share"), { recursive: true });
    await writeFile(join(run, "inputs/elsewhere/share/hidden.docm"), "x");
    await symlink(join(run, "inputs/elsewhere/share"), join(run, "inputs/case files/vol one/Users/sam/Share"));
    const r = recipe(run, "run", { paths: ["inputs/case files/vol one"] }, "store/jobs/j000001/out/dir link");
    const c = await cov(run, "store/jobs/j000001/out/dir link");
    assert.deepEqual([r.doc.status, r.doc.whole_list_read, c.links_to_directories_outside], ["partial", false, 1]);
    // A link to a directory inside the tree loses nothing: what lies below it is read under its own path.
    await rm(join(run, "inputs/case files/vol one/Users/sam/Share"));
    await symlink(join(run, "inputs/case files/vol one/Users/sam/Music"), join(run, "inputs/case files/vol one/Users/sam/My Music"));
    const inside = recipe(run, "run", { paths: ["inputs/case files/vol one"] }, "store/jobs/j000001/out/inner link");
    assert.deepEqual([inside.doc.status, inside.doc.whole_list_read], ["partial", true]);
  });
});

/** Loads the recipe as a module (its ENDS block holds nothing then) and runs `body` with it as `m`; the last line printed is JSON. */
const HARNESS = String.raw`
import importlib.util, json, os, sys, time, tracemalloc
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("first_stage", sys.argv[1])
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
target, out = sys.argv[2], sys.argv[3]
`;

const lastJson = (text: string): Doc => JSON.parse(text.trim().split("\n").pop()!) as Doc;

test("no registry hive or antivirus file is opened past the clock: the ones not reached are counted, and the run is partial (P1-4)", async () => {
  await withRun(async (run) => {
    py(String.raw`
import os, sys
root = sys.argv[1]
for i in range(300):
    d = root + "/Users/u%03d" % i
    os.makedirs(d)
    open(d + "/NTUSER.DAT", "wb").write(b"regf" + b"\x00" * 64)
os.makedirs(root + "/Users/bob/Downloads")
open(root + "/Users/bob/Downloads/parcel.docm", "wb").write(b"PK\x03\x04")
`, [join(run, "inputs/hives")], run);
    // The clock is 2 s (its 90 %, 1.8 s, is the deadline), and the one VBA check sleeps past it: every hive comes after the deadline.
    const r = py(HARNESS + String.raw`
m.limits = lambda: (2, 5000000)
real_vba, real_names, late = m.vba_in_file, m.names_in_file, []
began = time.monotonic()
def slow(*a):
    time.sleep(2.2)
    return real_vba(*a)
def names(*a):
    if time.monotonic() > began + 2.0:
        late.append(a[0])
    return real_names(*a)
m.vba_in_file, m.names_in_file = slow, names
m.run(target, out)
print(json.dumps({"late": len(late)}))
`, [RECIPE, "inputs/hives", "store/jobs/j000001/out/hives"], run);
    assert.equal(lastJson(r).late, 0, "a hive was opened after the deadline");
    const c = await cov(run, "store/jobs/j000001/out/hives");
    assert.equal(c.status, "partial");
    assert.equal(c.not_read_or_judged.files_not_searched_past_the_clock, 300);
    assert.match(c.limits_hit.join(" "), /seconds: the clock ran out before 300 registry hive\(s\) or antivirus file\(s\) were searched/);
  });
});

test("a member list keeps no hive's path, and a directory of many entries is held a batch at a time: memory stays small (P1-5)", async () => {
  await withRun(async (run) => {
    py(String.raw`
import os, sys
top = sys.argv[1]
os.makedirs(top + "/list")
prefix = "C:\\" + "\\".join(["p" * 50] * 8)
with open(top + "/list/members.tsv", "w") as f:
    f.write("type\tpath\n")
    for i in range(100000):
        f.write("file\t%s\\Users\\u%06d\\NTUSER.DAT\n" % (prefix, i))
open(top + "/list/coverage.json", "w").write('{"recipe": "a-lister", "status": "complete"}')
d = top + "/tree/" + "d" * 100
os.makedirs(d)
for i in range(20000):
    open("%s/%s%05d.txt" % (d, "f" * 190, i), "wb").close()
`, [join(run, "inputs/big")], run);
    const peak = (target: string, out: string): Doc => lastJson(py(HARNESS + String.raw`
m.DIRECTORY_BATCH = 1000
tracemalloc.start()
m.run(target, out)
print(json.dumps({"peak": tracemalloc.get_traced_memory()[1]}))
`, [RECIPE, target, out], run));
    const list = peak("inputs/big/list/members.tsv", "store/jobs/j000001/out/list");
    assert.ok(list.peak < 16 << 20, `a list of 100,000 hive rows held ${list.peak} bytes at its peak`);
    const lc = await cov(run, "store/jobs/j000001/out/list");
    assert.deepEqual([lc.status, lc.members, lc.sources.registry_hives], ["complete", 100000, 100000]);
    const tree = peak("inputs/big/tree", "store/jobs/j000001/out/tree");
    assert.ok(tree.peak < 6 << 20, `a directory of 20,000 long names held ${tree.peak} bytes at its peak`);
    const tc = await cov(run, "store/jobs/j000001/out/tree");
    assert.deepEqual([tc.status, tc.members, tc.directories_read_in_batches], ["complete", 20000, 1], "every name was read, a batch at a time");
  });
});

test("a row with no cell in the path column is a name not read: the run is partial and whole_list_read false (P1-6)", async () => {
  await withRun(async (run) => {
    const dir = join(run, "inputs/short rows");
    await mkdir(dir, { recursive: true });
    await writeFile(join(dir, "members.tsv"), "n\ttype\tsize\tpath\n1\tfile\t1\n2\tfile\t1\tC:\\Users\\bob\\AppData\\Local\\Temp\\invoice.docm\n");
    await writeFile(join(dir, "coverage.json"), '{"recipe": "a-lister", "status": "complete"}');
    const r = recipe(run, "run", { paths: ["inputs/short rows/members.tsv"] }, "store/jobs/j000001/out/short");
    assert.deepEqual([r.doc.status, r.doc.whole_list_read, r.doc.candidates], ["partial", false, 1]);
    const c = await cov(run, "store/jobs/j000001/out/short");
    assert.equal(c.not_read_or_judged.list_rows_without_a_path, 1);
    assert.match(c.status_basis, /has no cell in its path column/);
  });
});

test("a list of exactly the members limit is whole; a list outside the declared forms is partial; a name that is not text is counted", async () => {
  await withRun(async (run) => {
    const doc = "C:\\Users\\bob\\AppData\\Local\\Temp\\invoice.docm";
    const write = async (name: string, body: Buffer | string): Promise<string> => {
      const dir = join(run, "inputs", name);
      await mkdir(dir, { recursive: true });
      await writeFile(join(dir, "members.tsv"), body);
      await writeFile(join(dir, "coverage.json"), '{"recipe": "a-lister", "status": "complete"}');
      return `inputs/${name}/members.tsv`;
    };
    const exact = recipe(run, "run", { paths: [await write("exact", `path\n${doc}\nC:\\Users\\bob\\a.txt\n`)] }, "store/jobs/j000001/out/exact", { RECIPE_MEMBERS: "2" });
    assert.deepEqual([exact.doc.status, exact.doc.members, exact.doc.whole_list_read], ["complete", 2, true], "two rows under a limit of two are not more than two");
    const over = recipe(run, "run", { paths: [await write("over", `path\n${doc}\nC:\\Users\\bob\\a.txt\nC:\\Users\\bob\\b.txt\n`)] }, "store/jobs/j000001/out/over", { RECIPE_MEMBERS: "2" });
    assert.deepEqual([over.doc.status, over.doc.whole_list_read], ["partial", false]);
    const capital = recipe(run, "run", { paths: [await write("capital", `n\tPath\n1\t${doc}\n`)] }, "store/jobs/j000001/out/capital");
    assert.deepEqual([capital.doc.status, capital.doc.candidates], ["complete", 1], "a Path header is the path column");
    for (const [name, body, form] of [
      ["cr only", `path\r${doc}\r`, /carriage return alone/],
      ["utf16", Buffer.from(`\ufeffpath\n${doc}\n`, "utf16le"), /NUL bytes/],
      ["tab", `${doc}\t12\n`, /a path a line/],
    ] as const) {
      const out = `store/jobs/j000001/out/${name}`;
      const r = recipe(run, "run", { paths: [await write(name, body)] }, out);
      assert.deepEqual([r.doc.status, r.doc.whole_list_read], ["partial", false], name);
      const c = await cov(run, out);
      assert.ok(c.not_read_or_judged.list_lines_of_another_form >= 1, name);
      assert.match(c.list_form, form, name);
    }
    const index = lastJson(py(HARNESS + String.raw`
print(json.dumps({"unencodable": m.name_index(["plain.docm", "bad\udcff.docm"])[2]}))
`, [RECIPE, ".", "."], run));
    assert.equal(index.unencodable, 1, "a name that is not text cannot be searched for in bytes, and is counted");
  });
});

test("the recipe is run on demand, ad1-items declares its listing phase, and the note carries the rule on its card", async () => {
  const spec = JSON.parse(await readFile(join(CFB, "recipes", "first-stage-candidates", "recipe.json"), "utf8")) as Doc;
  assert.deepEqual([spec.id, spec.auto, spec.outputs, spec.purpose], ["first-stage-candidates", [], ["candidates.tsv", "coverage.json", "index.tsv"], "inventory"]);
  assert.match(spec.covers, /It reads and runs no macro/);
  const ad1 = JSON.parse(await readFile(join(CFB, "recipes", "ad1-items", "recipe.json"), "utf8")) as Doc;
  assert.deepEqual(ad1.phases, ["listing"], "the job service runs a recipe that declares the phase once with RECIPE_PHASE=listing, then whole");
  assert.match(await readFile(join(CFB, "recipes", "ad1-items", "run.py"), "utf8"), /RECIPE_PHASE=listing ends the run after phase 1/);
  const note = await readFile(join(CFB, "skills", "evidence", "first-stage.md"), "utf8");
  const card = /^card: (.+)$/m.exec(note)?.[1] ?? "";
  assert.ok(card.length > 100 && card.length <= 700);
  assert.match(card, /catalog_request target=<tree or member list> recipe=first-stage-candidates/);
  assert.match(card, /To answer "cannot be determined" to a "which file" question the whole member list must have been searched\./);
  assert.match(note.replace(/\s+/g, " "), /A search of Documents, Desktop and Downloads alone is not a search\./);
});
