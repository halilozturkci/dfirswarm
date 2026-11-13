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
import { readFile } from "node:fs/promises";
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
open(top + "/members list.tsv", "w").write("\n".join(rows) + "\n")
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
    assert.match(cov.rule, /To answer "cannot be determined" to a "which file" question the whole member list must have been searched: whole_list_read says whether it was\./);
    assert.match(cov.not_covered, /no macro was read or run/);
    assert.deepEqual(cov.sources, { recent_shortcuts: 1, registry_hives: 1, antivirus_files: 1, prefetch_applications: ["winword.exe"] });
  });
});

test("a member list gives the same first rank from names alone, and says what a list cannot hold", async () => {
  await withRun(async (run) => {
    const members = Number(py(BUILD, [join(run, "inputs/case files")], run).trim());
    const out = "store/jobs/j000001/out/from list";
    const r = recipe(run, "run", { paths: ["inputs/case files/members list.tsv"] }, out);
    assert.equal(r.code, 0, JSON.stringify(r.doc));
    const rows = await table(join(run, out, "candidates.tsv"));
    assert.equal(rows[0]!.path, "C:\\\\Users\\\\sam\\\\Music\\\\old albums\\\\notes for you.docm", "the path as the list has it, backslashes escaped");
    assert.equal(rows.length, 3, "a project under a plain name is not seen from names");
    assert.doesNotMatch(rows[0]!.signals, /VBA project|NTUSER|antivirus/);
    assert.match(rows[0]!.signals, /a Recent shortcut carries its name/);
    const cov = JSON.parse(await readFile(join(run, out, "coverage.json"), "utf8")) as Doc;
    assert.deepEqual([cov.mode, cov.whole_list_read, cov.members, cov.list_form], ["member list", true, members + 1, "a TSV with a path column (column 5)"]);
    assert.match(cov.not_covered, /a member list has names only: nothing inside a file was read/);
  });
});

test("a list that was not read whole says so: whole_list_read is false and the status partial", async () => {
  await withRun(async (run) => {
    py(BUILD, [join(run, "inputs/case files")], run);
    for (const target of ["inputs/case files/vol one", "inputs/case files/members list.tsv"]) {
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
    assert.deepEqual([recipe(run, "detect", { paths: ["inputs/case files/vol one"] }).code, recipe(run, "detect", { paths: ["inputs/case files/members list.tsv"] }).code], [0, 0]);
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
