/**
 * ransomware-response: everything the two tools derive from a name they withhold, and the check at the point of output.
 *
 * - an appended extension is a piece of the name: when the name of a note-named file is withheld, the extension is withheld with it, counted
 *   and not tabled (the extension of an ordinary encrypted file is the evidence and stays);
 * - the order of a listing, the numbers handed out in it and the files a limit keeps never follow the text of a withheld name: names that print
 *   alike come in an order drawn afresh every run (twin trees with the raw ids swapped give the same answer);
 * - a second check, written apart from the rule that withholds names, reads every string on its way out: with the first rule removed, no
 *   identifier reaches the answer, a row or a file;
 * - the smaller points of the same review: pages are ASCII, a failed page write says why, an unexpected failure names no path, the clock
 *   runs inside a note, the classes the rule withholds and the ones it prints are measured.
 *
 * Every identifier is drawn at test time from pieces, never a literal that looks like a real secret.
 */
import assert from "node:assert/strict";
import { randomBytes, randomInt } from "node:crypto";
import { mkdir, readFile, readdir, utimes, writeFile } from "node:fs/promises";
import { basename, join } from "node:path";
import { test } from "node:test";
import { ROOT, runPySnippet, withCwd } from "./tool-library-harness.ts";
import { LOAD, NOTES, SURVEY, body, filesUnder, refused, runWithoutFirstRule, tool } from "./ransomware-pack-harness.ts";

const HEX = "0123456789abcdef";
const pick = (alphabet: string, n: number): string => Array.from({ length: n }, () => alphabet[randomInt(alphabet.length)]).join("");
const hexId = (n = 16): string => {
  for (;;) {
    const s = pick(HEX, n);
    if (/[a-f]/.test(s) && /\d/.test(s)) return s; // letters and digits both: the shape the rule withholds
  }
};
const NOTE = "Your files are encrypted. To decrypt your files, pay in bitcoin and restore your files.\n";
const MARKER = "<identifier-shaped name withheld>";
const JOB = { JOB_ID: "j000001" };

type Row = Record<string, unknown>;
type Pages = Record<string, { all_results?: string; matched: number }>;

/** The text of every file a job wrote under its out directory, keyed by name. */
const written = (out: string): Promise<Record<string, string>> => filesUnder(out);

/** The rows of a page file named in an answer (in a job the answer cites store/jobs/<job>/out/…: the file is under `out`). */
async function pageRows(out: string, cited: string): Promise<Row[]> {
  const text = await readFile(join(out, "tool-output", basename(cited)), "utf8");
  return text.trimEnd().split("\n").map((line) => JSON.parse(line) as Row);
}

// ---- P1-A: an appended extension is a piece of the name ---------------------------------------------------------------------------

test("encrypted_survey withholds the extension of a note-named file with its name: 40 ids in 40 extensions, none printed anywhere", async () => {
  await withCwd(async (cwd) => {
    const ev = join(cwd, "work", "ev", "t2");
    await mkdir(ev, { recursive: true });
    const ids: string[] = [];
    for (let i = 0; i < 40; i++) {
      const id = hexId();
      ids.push(id);
      await writeFile(join(ev, `README.txt.${id}`), randomBytes(6000)); // note-named by "readme"; a known extension, then an unknown one: the id
    }
    const evidenceId = hexId(12);
    await writeFile(join(ev, `budget.xlsx.id-${evidenceId}.locked`), randomBytes(6000)); // an ordinary encrypted file: its name is the evidence
    const out = join(cwd, "out");
    await mkdir(out);
    const run = await tool(SURVEY, cwd, { root: "work/ev", limit: 5 }, { ...JOB, OUT: out });
    const answer = body<{ candidates: Row[]; appended_extension_observations: Row[]; coverage: Record<string, number>; pages: Pages }>(run);
    const everything = run.stdout + Object.values(await written(out)).join("\n");
    assert.equal(ids.filter((id) => everything.includes(id)).length, 0, "an identifier was printed through an extension");
    assert.equal(answer.coverage.appended_extensions_withheld, 40);
    assert.equal(answer.coverage.candidate_files, 41);
    const rows = await pageRows(out, answer.pages.candidates.all_results as string);
    const noteRows = rows.filter((r) => String(r.file).endsWith(MARKER));
    assert.equal(noteRows.length, 40);
    for (const r of noteRows) assert.match(String(r.appended_extension), /^<extension withheld/);
    // the table holds the evidence's extension and nothing of the withheld names
    assert.deepEqual(answer.appended_extension_observations.map((r) => r.extension), [`.locked`]);
    const evidenceRow = rows.find((r) => String(r.file).includes(evidenceId));
    assert.ok(evidenceRow, "the ordinary encrypted file keeps its whole name");
    assert.equal(evidenceRow.appended_extension, ".locked");
  });
});

// ---- P1-B: the order of rows, ids and the sample ----------------------------------------------------------------------------------

/** 12 directories named by ids, each with a note of its own size and a locked file; returns the id of the size. */
async function orderTree(root: string): Promise<Map<number, string>> {
  const ids = new Set<string>();
  while (ids.size < 12) ids.add(hexId());
  const bySize = new Map<number, string>();
  let k = 0;
  for (const id of [...ids].sort(() => randomInt(3) - 1)) {
    await mkdir(join(root, id), { recursive: true });
    const text = NOTE + "x".repeat(k * 7);
    await writeFile(join(root, id, "README.txt"), text);
    bySize.set(Buffer.byteLength(text), id);
    await writeFile(join(root, id, "a.docx.locked"), randomBytes(6000 + k));
    k++;
  }
  return bySize;
}

const ORDER_RUNS = 5;

test("ransom_note_scan: rows, note ids and the order of directories do not follow the raw order of withheld names", async () => {
  await withCwd(async (cwd) => {
    const bySize = await orderTree(join(cwd, "work", "ev"));
    const raw = [...bySize.values()].sort();
    const orders: string[][] = [];
    const firstNoteOfSmallest: string[] = [];
    for (let i = 0; i < ORDER_RUNS; i++) {
      const answer = body<{ notes: { bytes: number; note_id: string; file: string }[] }>(await tool(NOTES, cwd, { root: "work/ev" }));
      assert.equal(answer.notes.length, 12);
      assert.ok(answer.notes.every((n) => n.file === `work/ev/${MARKER}/README.txt`));
      const order = answer.notes.map((n) => bySize.get(n.bytes) as string);
      orders.push(order);
      assert.deepEqual(answer.notes.map((n) => n.note_id), Array.from({ length: 12 }, (_, j) => `N${String(j + 1).padStart(6, "0")}`));
      firstNoteOfSmallest.push(answer.notes[order.indexOf(raw[0])].note_id);
    }
    for (const order of orders) assert.notDeepEqual(order, raw, "the rows come out in the raw order of the withheld ids");
    assert.ok(new Set(orders.map((o) => o.join())).size >= 2, "the order of withheld names is drawn afresh every run");
    assert.ok(new Set(firstNoteOfSmallest).size >= 2, "the number handed to the note of the smallest id is the same in every run");
  });
});

test("encrypted_survey: rows, the note-name table and the first `sample` candidates do not follow the raw order of withheld names", async () => {
  await withCwd(async (cwd) => {
    const bySize = await orderTree(join(cwd, "work", "ev"));
    const raw = [...bySize.values()].sort();
    const orders: string[][] = [];
    const sampled: string[] = [];
    for (let i = 0; i < ORDER_RUNS; i++) {
      const answer = body<{ note_name_candidates: { bytes: number }[]; candidates: Row[] }>(await tool(SURVEY, cwd, { root: "work/ev", sample: 3, census: false }));
      assert.equal(answer.note_name_candidates.length, 12);
      orders.push(answer.note_name_candidates.map((n) => bySize.get(n.bytes) as string));
      // the candidates are the locked files; the profiled ones are the sample: which three directories they sit in is the question
      const profiled = answer.candidates.filter((c) => c.profiled === true);
      assert.equal(profiled.length, 3);
      sampled.push(profiled.map((c) => c.bytes).join());
    }
    for (const order of orders) assert.notDeepEqual(order, raw);
    assert.ok(new Set(orders.map((o) => o.join())).size >= 2);
    assert.ok(new Set(sampled).size >= 2, "the sample is the first three withheld directories in the same order every run");
  });
});

/** The answer with what two runs legitimately differ in normalised: the hex digest in the name of a table file. */
const normal = (text: string): string => text.replace(/[0-9a-f]{16}/g, "<digest>");

async function twin(script: string, id: string, args: Record<string, unknown>): Promise<string> {
  let answer = "";
  await withCwd(async (cwd) => {
    const when = new Date("2026-01-02T03:04:05Z");
    const files: [string, Buffer | string][] = [
      ["Alpha/README.txt", NOTE + "a"], ["Zulu/README.txt", NOTE + "zz"], [`${id}/README.txt`, NOTE + "wwww"], [`${id}/a.docx.locked`, Buffer.alloc(6000, 7)],
      ["Alpha/a.docx.locked", Buffer.alloc(6001, 9)], ["Zulu/a.docx.locked", Buffer.alloc(6002, 5)],
    ];
    for (const [name, data] of files) {
      const path = join(cwd, "work", "ev", name);
      await mkdir(join(path, ".."), { recursive: true });
      await writeFile(path, data);
      await utimes(path, when, when);
    }
    const run = await tool(script, cwd, { root: "work/ev", ...args });
    body(run);
    answer = normal(run.stdout);
  });
  return answer;
}

test("twin trees with the raw id of one withheld directory swapped give the same answer, in both tools and at limit 1", async () => {
  const low = "1" + pick(HEX, 7) + "a1b2c3d4"; // sorts before the visible siblings' names by its text
  const high = "f" + "f".repeat(7) + "a1b2c3d4"; // after them
  for (const [name, script] of [["ransom_note_scan", NOTES], ["encrypted_survey", SURVEY]] as const) {
    for (const args of [{}, { limit: 1 }, { limit: 2 }, { sample: 1 }]) {
      assert.equal(await twin(script, low, args), await twin(script, high, args), `${name} ${JSON.stringify(args)}: the answer depends on the withheld name`);
    }
  }
});

// ---- P2-B: the check at the point of output -----------------------------------------------------------------------------------


const UNIT = LOAD + String.raw`
out = {}
for n, p in (("encrypted_survey", sys.argv[1]), ("ransom_note_scan", sys.argv[2])):
    m = load(p, n)
    ident, other = sys.argv[3], sys.argv[4]
    r = {}
    r["clean_untouched"] = m.release({"status": "complete", "x": ["a", {"b": "README.txt"}]}) == {"status": "complete", "x": ["a", {"b": "README.txt"}]}
    r["path"] = m.seal_row({"file": "work/ev/%s/x.txt" % ident})["file"]
    r["key"] = list(m.seal_row({ident + "abc": 1}))[0]
    r["ext"] = m.seal_row({"appended_extension": "." + ident})["appended_extension"]
    r["list"] = m.seal_row({"a": ["fine", "dir " + ident]})["a"][1]
    base = "budget.xlsx.id-" + ident + ".locked"
    r["evidence_path"] = m.seal_row({"file": "work/ev/" + base}, base)["file"] == "work/ev/" + base
    r["evidence_ext"] = m.seal_row({"appended_extension": ".id-" + ident + ".locked"}, base)["appended_extension"] == ".id-" + ident + ".locked"
    r["evidence_dir_still_checked"] = m.seal_row({"file": "work/%s/%s" % (other, base)}, base)["file"]
    note = "README_" + ident + ".txt"
    r["note_named_is_no_evidence"] = m.seal_row({"file": "work/ev/" + note}, note)["file"]
    r["digest_key_free"] = m.seal_row({"sha256": ident * 4, "tail_hex": ident})["sha256"] == ident * 4
    r["serial_free"] = m.seal_row({"finding_id": "F1000000", "note_id": "N000001"})["finding_id"] == "F1000000"
    r["serial_in_other_key_not"] = m.seal_row({"x": "F1000000"})["x"]
    r["sealed_twice_counts_once"] = None
    before = m.BOUNDARY["replaced"]
    row = m.seal_row({"file": "w/" + ident + "/x"})
    m.seal_row(row)
    r["sealed_twice_counts_once"] = m.BOUNDARY["replaced"] - before
    r["release_partial"] = m.release({"status": "complete", "complete": "complete", "status_basis": "ok", "file": "a/" + ident + "/b"})["status"]
    r["release_boundary"] = "boundary" in m.release({"status": "complete", "file": "a/" + ident + "/b"})
    out[n] = r
print(json.dumps(out))
`;

test("the backstop replaces an identifier-shaped string in a path, a key, an extension and a list, passes an evidence name and refuses the claim for a note name", async () => {
  const ident = hexId();
  const other = hexId();
  const run = await runPySnippet(UNIT, [SURVEY, NOTES, ident, other], null);
  assert.equal(run.code, 0, run.stderr);
  const all = JSON.parse(run.stdout) as Record<string, Record<string, unknown>>;
  assert.deepEqual(all.encrypted_survey, all.ransom_note_scan, "the two tools carry one backstop");
  const r = all.ransom_note_scan;
  for (const field of ["path", "key", "ext", "list"]) {
    assert.match(String(r[field]), /withheld at the output/, field);
    assert.ok(!String(r[field]).includes(ident), field);
  }
  assert.equal(r.evidence_path, true);
  assert.equal(r.evidence_ext, true);
  assert.match(String(r.evidence_dir_still_checked), /withheld at the output/);
  assert.match(String(r.note_named_is_no_evidence), /withheld at the output/);
  assert.equal(r.digest_key_free, true);
  assert.equal(r.serial_free, true);
  assert.match(String(r.serial_in_other_key_not), /withheld at the output/);
  assert.equal(r.sealed_twice_counts_once, 1);
  assert.equal(r.release_partial, "partial");
  assert.equal(r.release_boundary, true);
  assert.equal(r.clean_untouched, true);
});

test("with the first rule removed, no identifier reaches the answer, a row or a file of either tool: the backstop alone holds", async () => {
  await withCwd(async (cwd) => {
    const dirId = hexId();
    const deepId = hexId(24);
    const noteExt = hexId();
    const rootId = hexId();
    const evidenceId = hexId(12);
    // one tree whose directories, note names and extensions carry ids, and one whose root does
    const base = join(cwd, "work", "ev");
    await mkdir(join(base, dirId, "sub"), { recursive: true });
    await mkdir(join(base, deepId), { recursive: true });
    await writeFile(join(base, dirId, "README.txt"), NOTE);
    await writeFile(join(base, dirId, "sub", "HOWTO.txt"), NOTE);
    await writeFile(join(base, deepId, "a.docx.locked"), randomBytes(6000));
    await writeFile(join(base, `README.txt.${noteExt}`), randomBytes(6000));
    await writeFile(join(base, `budget.xlsx.id-${evidenceId}.locked`), randomBytes(6000)); // the evidence: printed on purpose
    await mkdir(join(cwd, "work", `case-${rootId}`, "ev"), { recursive: true });
    await writeFile(join(cwd, "work", `case-${rootId}`, "ev", "README.txt"), NOTE);
    for (const [script, label] of [[SURVEY, "encrypted_survey"], [NOTES, "ransom_note_scan"]] as const) {
      const out = join(cwd, "out-" + label);
      await mkdir(out);
      const run = await runWithoutFirstRule(script, JSON.stringify({ root: "work/ev", limit: 1 }), cwd, out);
      assert.doesNotMatch(run.stderr, /Traceback/, label);
      const printed = run.stdout + Object.values(await written(out)).join("\n");
      for (const id of [dirId, deepId, noteExt]) assert.ok(!printed.includes(id), `${label} printed ${id} with the first rule removed`);
      const answer = JSON.parse(run.stdout) as { status: string; boundary?: { strings_replaced_at_the_output: number } };
      assert.equal(answer.status, "partial", label);
      assert.ok((answer.boundary?.strings_replaced_at_the_output ?? 0) >= 3, `${label}: ${JSON.stringify(answer.boundary)}`);
      if (label === "encrypted_survey") assert.ok(printed.includes(evidenceId), "an ordinary encrypted file's name is still printed: it is the evidence");
      const rooted = await runWithoutFirstRule(script, JSON.stringify({ root: `work/case-${rootId}/ev` }), cwd, join(cwd, "out-root-" + label));
      assert.ok(!(rooted.stdout + Object.values(await written(join(cwd, "out-root-" + label))).join("\n")).includes(rootId), `${label} printed the id of its root`);
    }
  });
});

test("the backstop and the name rule agree on random names (1,000 cases, count only)", async () => {
  const code = LOAD + String.raw`
import random, string
m = load(sys.argv[1])
rnd = random.Random(20261020)
AL, DG, HEX = string.ascii_letters, string.digits, "0123456789abcdef"
def ch(a, n): return "".join(rnd.choice(a) for _ in range(n))
pieces = [lambda: ch(AL, rnd.randint(1, 24)), lambda: ch(DG, rnd.randint(1, 14)), lambda: ch(AL + DG, rnd.randint(1, 20)),
          lambda: ch(string.ascii_lowercase, rnd.randint(4, 20)), lambda: ch(string.ascii_uppercase, rnd.randint(4, 20)), lambda: ch(HEX, 2), lambda: ch(DG, 3),
          lambda: "".join(chr(0x660 + int(c)) for c in ch(DG, rnd.randint(3, 13))), lambda: "​", lambda: "Ａ１ｂ２"]
seps = ["", "", "-", "_", ".", " ", ",", ":"]
disagree = 0
for _ in range(1000):
    s = "".join(rnd.choice(pieces)() + rnd.choice(seps) for _ in range(rnd.randint(1, 9)))
    if m.shaped(s) != (m._why(s) is not None):
        disagree += 1
print(disagree)
`;
  for (const script of [SURVEY, NOTES]) {
    const run = await runPySnippet(code, [script, "0"], null);
    assert.equal(run.code, 0, run.stderr);
    assert.equal(run.stdout.trim(), "0", `${basename(script)}: the second check reads a name differently from the first`);
  }
});

// ---- P3 ---------------------------------------------------------------------------------------------------------------------------

test("a page file is ASCII: U+2028, U+0085 and a bidi override in a name are escaped, and a row is always a line", async () => {
  await withCwd(async (cwd) => {
    const ev = join(cwd, "work", "ev");
    await mkdir(ev, { recursive: true });
    const names = ["a b.docx.locked", "c\u0085d.docx.locked", "e‮f.docx.locked"];
    for (const n of names) await writeFile(join(ev, n), randomBytes(6000));
    const answer = body<{ pages: Pages }>(await tool(SURVEY, cwd, { root: "work/ev", limit: 1 }));
    const text = await readFile(join(cwd, answer.pages.candidates.all_results as string), "utf8");
    assert.ok(/^[\x20-\x7e\n]*$/.test(text), "a non-ASCII character is in the page file");
    for (const escape of ["\\u2028", "\\u0085", "\\u202e"]) assert.ok(text.includes(escape), escape);
    assert.equal(text.trimEnd().split("\n").length, 3);
    for (const line of text.trimEnd().split("\n")) JSON.parse(line);
  });
});

test("a result that cannot be written is a failed answer with a status_basis, in both tools, and names no path of the output", async () => {
  await withCwd(async (cwd) => {
    const ev = join(cwd, "work", "ev");
    await mkdir(ev, { recursive: true });
    for (let i = 0; i < 3; i++) {
      await writeFile(join(ev, `README${i}.txt`), NOTE);
      await writeFile(join(ev, `a${i}.docx.locked`), randomBytes(6000));
    }
    const out = join(cwd, "out");
    await mkdir(out);
    await writeFile(join(out, "tool-output"), "a file where the directory should be");
    for (const [script, label] of [[SURVEY, "encrypted_survey"], [NOTES, "ransom_note_scan"]] as const) {
      const failed = refused(await tool(script, cwd, { root: "work/ev", limit: 1 }, { ...JOB, OUT: out })) as unknown as { error: string; status: string; status_basis: string };
      assert.equal(failed.status, "failed", label);
      assert.ok(failed.status_basis.length > 30, label);
      assert.ok(!failed.error.includes(out), `${label} names the output path: ${failed.error}`);
    }
  });
});

const BREAK = String.raw`
import errno, os, runpy, sys
mode, script = sys.argv[1], sys.argv[2]
if mode == "keyerror":
    _real = os.scandir
    def scandir(path="."):
        if "ev" in str(path):
            raise KeyError("/secret/place/" + str(path))
        return _real(path)
    os.scandir = scandir
else:
    _open = os.open
    def op(path, flags, *a, **k):
        if flags & os.O_EXCL and "tool-output" in str(path) and not os.path.basename(str(path)).startswith("."):
            raise FileExistsError(errno.EEXIST, "exists", str(path))
        return _open(path, flags, *a, **k)
    os.open = op
sys.argv = [script]
runpy.run_path(script, run_name="__main__")
`;

test("an unexpected failure names no path: not the output's, not the text of the exception", async () => {
  await withCwd(async (cwd) => {
    const ev = join(cwd, "work", "ev");
    await mkdir(ev, { recursive: true });
    for (const n of ["README.txt", "README2.txt"]) await writeFile(join(ev, n), NOTE);
    for (const n of ["a.docx.locked", "b.docx.locked"]) await writeFile(join(ev, n), randomBytes(6000));
    const out = join(cwd, "out-" + pick(HEX, 8));
    await mkdir(out);
    const { spawn } = await import("node:child_process");
    const go = (mode: string, script: string): Promise<{ code: number | null; stdout: string }> =>
      new Promise((resolve) => {
        const child = spawn("python3", ["-c", BREAK, mode, script], { cwd, env: { ...process.env, AGENT_ID: "s1", JOB_ID: "j000001", OUT: out } });
        const stdout: Buffer[] = [];
        child.stdout.on("data", (c: Buffer) => stdout.push(c));
        child.on("close", (code) => resolve({ code, stdout: Buffer.concat(stdout).toString("utf8") }));
        child.stdin.end(JSON.stringify({ root: "work/ev", limit: 1 }));
      });
    for (const script of [SURVEY, NOTES]) {
      for (const mode of ["keyerror", "no-free-name"]) {
        const ended = await go(mode, script);
        assert.equal(ended.code, 1, `${basename(script)} ${mode}: ${ended.stdout}`);
        const answer = JSON.parse(ended.stdout) as { error: string; status: string };
        assert.equal(answer.status, "failed");
        assert.ok(!ended.stdout.includes("/secret") && !ended.stdout.includes(out) && !ended.stdout.includes(cwd), `${basename(script)} ${mode}: ${answer.error}`);
        assert.match(answer.error, mode === "keyerror" ? /^unexpected failure: KeyError at line \d+ of the tool$/ : /no free name for a result file/);
      }
    }
  });
});

test("ransom_note_scan: the clock runs inside a note, and the note is reported as partly scanned (not finished past the limit)", async () => {
  await withCwd(async (cwd) => {
    const ev = join(cwd, "work", "ev");
    await mkdir(ev, { recursive: true });
    await writeFile(join(ev, "README.txt"), "x@y.zz ".repeat(1_000_000)); // a million e-mail addresses: seconds of matching
    const started = Date.now();
    const answer = body<{ status: string; status_basis: string; coverage: Record<string, number>; notes: Row[]; indicator_counts: { email?: { occurrences: number } } }>(
      await tool(NOTES, cwd, { root: "work/ev", max_size: 8_000_000, max_seconds: 1 }),
    );
    const seconds = (Date.now() - started) / 1000;
    assert.equal(answer.status, "partial");
    assert.equal(answer.coverage.notes_partly_scanned, 1);
    assert.match(String(answer.notes[0].scan_stopped), /time limit/);
    assert.match(answer.status_basis, /partly scanned/);
    // How many addresses were counted before the clock ran out depends on the speed of the CPU (on a slow one none may be): the clock stop is
    // what is asserted, not a count.
    assert.ok((answer.indicator_counts.email?.occurrences ?? 0) < 1_000_000, "the note was scanned to its end");
    assert.ok(seconds < 8, `the run took ${seconds} s past a 1 s limit`);
  });
});

test("a well-known directory name is printed, any case, and its neighbour with an identifier is not", async () => {
  await withCwd(async (cwd) => {
    const id = hexId();
    for (const script of [SURVEY, NOTES]) {
      const ev = join(cwd, "work", script === SURVEY ? "ev-survey" : "ev-scan");
      for (const d of ["Windows/System32", "Windows/SysWOW64", "AppData/Local/Microsoft/Windows/INetCache", "ProgramData/MSOCache", "Chrome/GPUCache", "Chrome/IndexedDB", "Documents/WindowsPowerShell/PSReadLine", "Framework64", "var/lib/docker/overlay2", "vmfs/volumes/datastore1", "Other/SYSTEM32"]) {
        await mkdir(join(ev, d), { recursive: true });
        await writeFile(join(ev, d, "README.txt"), NOTE);
      }
      await mkdir(join(ev, "Windows", id), { recursive: true });
      await writeFile(join(ev, "Windows", id, "README.txt"), NOTE);
      const rel = ev.slice(cwd.length + 1);
      const run = await tool(script, cwd, { root: rel, limit: 500 });
      const answer = body<Record<string, Row[]>>(run);
      const rows = (script === SURVEY ? answer.note_name_candidates : answer.notes).map((r) => String(r.file));
      assert.equal(rows.length, 12);
      for (const name of ["System32", "SysWOW64", "INetCache", "MSOCache", "GPUCache", "IndexedDB", "PSReadLine", "Framework64", "overlay2", "datastore1", "SYSTEM32"]) {
        assert.ok(rows.some((f) => f.includes(`/${name}/`)), `${name} was withheld`);
      }
      assert.ok(rows.some((f) => f.includes(`Windows/${MARKER}/`)));
      assert.ok(!run.stdout.includes(id));
    }
  });
});

// ---- the classes the rule withholds and prints, measured ---------------------------------------------------------------------------

const RATES = LOAD + String.raw`
import random, string
tools = {"encrypted_survey": load(sys.argv[1], "es"), "ransom_note_scan": load(sys.argv[2], "rns")}
rnd = random.Random(int(sys.argv[4]))
N = int(sys.argv[3])
LO, UP, DG, HEX = string.ascii_lowercase, string.ascii_uppercase, string.digits, "0123456789abcdef"
def pick(a, n): return "".join(rnd.choice(a) for _ in range(n))
def pairs(k, sep): return sep.join(pick(HEX, 2) for _ in range(k))
shapes = {
  "lower_8": lambda: pick(LO, 8), "lower_12": lambda: pick(LO, 12), "lower_15": lambda: pick(LO, 15), "lower_16": lambda: pick(LO, 16), "lower_24": lambda: pick(LO, 24),
  "upper_8": lambda: pick(UP, 8), "upper_15": lambda: pick(UP, 15), "upper_16": lambda: pick(UP, 16), "upper_24": lambda: pick(UP, 24),
  "mixed_letters_24": lambda: pick(string.ascii_letters, 24),
  "decimal_8": lambda: pick(DG, 8), "decimal_9": lambda: pick(DG, 9), "decimal_10": lambda: pick(DG, 10),
  "arabic_indic_12": lambda: "".join(chr(0x660 + int(c)) for c in pick(DG, 12)), "arabic_indic_9": lambda: "".join(chr(0x660 + int(c)) for c in pick(DG, 9)),
  "zero_width_split_hex_16": lambda: "​".join(pick(HEX, 4) for _ in range(4)),
  "hex_pairs_colon_16": lambda: pairs(16, ":"), "hex_pairs_dash_8": lambda: pairs(8, "-"), "hex_pairs_dash_7": lambda: pairs(7, "-"), "hex_pairs_space_8": lambda: pairs(8, " "),
  "decimal_groups_space_3x4": lambda: " ".join(pick(DG, 4) for _ in range(3)), "decimal_groups_comma_3x4": lambda: ",".join(pick(DG, 4) for _ in range(3)),
  "decimal_groups_space_2x4": lambda: " ".join(pick(DG, 4) for _ in range(2)),
  "base32_16": lambda: pick("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 16),
  "cyrillic_homoglyph_12": lambda: "".join(rnd.choice("АВЕКМНОРСТХ" + DG) for _ in range(12)),
  "caps_7_dash_caps_7": lambda: pick(UP, 7) + "-" + pick(UP, 7),
}
out = {tool: {} for tool in tools}
for name, g in shapes.items():
    ids = [g() for _ in range(N)]
    for tool, m in tools.items():
        out[tool][name] = sum(1 for i in ids if i in m.shown("/x/%s/README.txt" % i, count=False)) / N
print(json.dumps(out))
`;

test("single-case letters from 16 up, hex pairs, digit groups and digits of any script are withheld; the classes printed anyway are measured", async () => {
  const N = 1000;
  const run = await runPySnippet(RATES, [SURVEY, NOTES, String(N), String(randomInt(1, 1e9))], null);
  assert.equal(run.code, 0, run.stderr);
  const rates = JSON.parse(run.stdout) as Record<string, Record<string, number>>;
  assert.deepEqual(rates.encrypted_survey, rates.ransom_note_scan, "the two tools judge a name alike");
  const r = rates.ransom_note_scan;
  for (const shape of ["lower_16", "lower_24", "upper_16", "upper_24", "decimal_10", "arabic_indic_12", "zero_width_split_hex_16", "hex_pairs_colon_16",
    "hex_pairs_dash_8", "hex_pairs_space_8", "decimal_groups_space_3x4", "decimal_groups_comma_3x4", "base32_16"]) {
    assert.ok(r[shape] <= 0.003, `${shape} printed ${r[shape]}`);
  }
  // printed whole, as the manifest says (a token of up to 15 letters of one case is a word to the rule)
  for (const shape of ["lower_8", "lower_12", "lower_15", "upper_8", "upper_15", "decimal_8", "decimal_9", "arabic_indic_9", "decimal_groups_space_2x4", "caps_7_dash_caps_7"]) {
    assert.ok(r[shape] >= 0.99, `${shape} printed ${r[shape]}`);
  }
  assert.ok(r.mixed_letters_24 < 0.02, `mixed_letters_24 ${r.mixed_letters_24}`); // 0.5%: capitals among small letters can read as words
  assert.ok(r.hex_pairs_dash_7 > 0.1 && r.hex_pairs_dash_7 < 0.5, `hex_pairs_dash_7 ${r.hex_pairs_dash_7}`);
  assert.ok(r.cyrillic_homoglyph_12 > 0.9, "a mix of look-alike letters is a known residual");
});

// ---- the words: manifests, skills, changelog -------------------------------------------------------------------------------------------

test("the manifests, the skill and the module notes say what is printed, what the check is and what the clock and a kill leave behind", async () => {
  const read = (rel: string) => readFile(join(ROOT, "packs", "ransomware-response", rel), "utf8");
  for (const name of ["encrypted_survey", "ransom_note_scan"]) {
    const d = (JSON.parse(await read(`tools/${name}/manifest.json`)) as { description: string }).description;
    for (const text of ["16 or more letters of one case", "up to 15", "hex digits joined", "SIGKILL", "timeout_seconds", "max_seconds", "second check", "drawn afresh"]) {
      assert.ok(d.includes(text), `${name} does not say: ${text}`);
    }
  }
  const survey = (JSON.parse(await read("tools/encrypted_survey/manifest.json")) as { description: string }).description;
  assert.match(survey, /extension of .* is withheld/);
  const skill = await read("skills/scope/triage-tools.md");
  for (const text of ["Every other file", "16 letters", "3%"]) assert.ok(skill.includes(text), `the skill does not say: ${text}`);
  const names = await readdir(join(ROOT, "changelog.d"));
  assert.ok(names.some((n) => /ransomware/.test(n)));
});

// ---- the new patterns are linear -----------------------------------------------------------------------------------------------------

const HOSTILE = LOAD + String.raw`
import time
out = {}
for n, p in (("encrypted_survey", sys.argv[1]), ("ransom_note_scan", sys.argv[2])):
    m = load(p, n)
    for size in (4096, 32768):
        cases = {
          "pairs": "ab-" * (size // 3), "pairs_then_junk": ("ab-" * 7 + "abc ") * (size // 25), "pairs_long_then_x": "ab-" * (size // 3 - 1) + "abc",
          "pairs_break": "ab.cd.ef.01.02.03.04.zz." * (size // 24), "groups": "123 " * (size // 4), "groups_then_x": "1234 " * (size // 5 - 1) + "5678x",
          "groups_short": "12 " * (size // 3), "digit_run_sep": "1" * (size - 2) + " 1", "digits": "1" * size, "arabic_digits": "١" * size,
          "arabic_groups": "١٢٣ " * (size // 4), "zwsp_hex": "a​1" * (size // 3), "nfkc_expand": "ﷺ" * (size // 3), "caps": "A" * size,
          "caps_lower": "Ab" * (size // 2), "lower": "a" * size, "slashes": "a1/" * (size // 3), "userinfo": "a:" * (size // 4) + "@",
          "pairs_brackets": "ab[" * (size // 3), "pairs_glued": "xab-" * (size // 4), "pairs_any_separator": "ab(ab)ab=ab|" * (size // 12),
          "pairs_seven_then_glue": ("ab:" * 7 + "xab ") * (size // 25), "pairs_slashes": "ab/" * (size // 3), "pairs_newlines": "ab\n" * (size // 3),
          "pairs_long_then_x": "ab-cd " * (size // 6 - 1) + "abc", "pairs_with_fullwidth": "ａｂ:" * (size // 3),
        }
        for label, text in cases.items():
            for fn, call in (("shown", lambda t: m.shown("a/" + t + "/b", count=False)), ("why", lambda t: m._why(t)), ("refuse", lambda t: m._refuse(t, None)),
                             ("seal_row", lambda t: m.seal_row({"file": t, "x": [t]}, None))):
                t0 = time.perf_counter()
                call(text)
                out["%s %s %s %d" % (n, fn, label, size)] = time.perf_counter() - t0
print(json.dumps(out))
`;

test("the patterns added for hex pairs, digit groups, other scripts and the backstop are linear on hostile text of 4,096 and 32,768 characters", async () => {
  const run = await runPySnippet(HOSTILE, [SURVEY, NOTES], null);
  assert.equal(run.code, 0, run.stderr);
  const times = JSON.parse(run.stdout) as Record<string, number>;
  assert.ok(Object.keys(times).length > 100);
  for (const [label, seconds] of Object.entries(times)) assert.ok(seconds < 1.5, `${label}: ${seconds} s`);
});
