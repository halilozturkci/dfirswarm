/**
 * ransomware-response: the second check reads names, not the tool's own sentences.
 *
 * - a size of 10 or more digits in a reason or a status basis ("the read budget (4294967296 bytes) was spent", "larger than max_size
 *   (5368709120 bytes ...") is a number, not an identifier: it is printed, and the answer is not made partial by it;
 * - the type of an error (IsADirectoryError, NotADirectoryError, BlockingIOError) is a word, not letters that do not read as words;
 * - the place of a replaced string never names a key that came from data, whatever the key looks like;
 * - the receipt that ends the census says what the answer says.
 *
 * Every identifier is drawn at test time from pieces, never a literal that looks like a real secret.
 */
import assert from "node:assert/strict";
import { randomBytes, randomInt } from "node:crypto";
import { mkdir, readFile, truncate, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { runPySnippet, withCwd } from "./tool-library-harness.ts";
import { LOAD, NOTES, SURVEY, body, runPatched, tool } from "./ransomware-pack-harness.ts";

const HEX = "0123456789abcdef";
const pick = (alphabet: string, n: number): string => Array.from({ length: n }, () => alphabet[randomInt(alphabet.length)]).join("");
const hexId = (n = 16): string => {
  for (;;) {
    const s = pick(HEX, n);
    if (/[a-f]/.test(s) && /\d/.test(s)) return s;
  }
};
const NOTE = "Your files are encrypted. To decrypt your files, pay in bitcoin and restore your files.\n";

type Row = Record<string, unknown>;

// ---- a size in the tool's own sentence ----------------------------------------------------------------------------------------------

test("a size of 10 or more digits is read as a size in the tool's own sentences (reason, status_basis, partial_reasons) and as a name anywhere else", async () => {
  const code = LOAD + String.raw`
out = {}
for n, p in (("encrypted_survey", sys.argv[1]), ("ransom_note_scan", sys.argv[2])):
    m = load(p, n)
    r = {}
    sentence = "larger than max_size (5368709120 bytes, max_size is 200000): not read"
    r["answer_stays_complete"] = m.release({"status": "complete", "status_basis": "ok", "reason": sentence})["status"]
    r["reason_kept"] = m.seal_row({"reason": sentence})["reason"] == sentence
    budget = "the read budget (4294967296 bytes) was spent: 3 files have no entropy measurement or no profile"
    r["status_basis_kept"] = m.seal_row({"status_basis": budget})["status_basis"] == budget
    r["partial_reasons_kept"] = m.seal_row({"partial_reasons": [budget, "2 files could not be read"]})["partial_reasons"][0] == budget
    r["file_replaced"] = m.seal_row({"file": "dir/12345678901 bytes/x"})["file"]
    r["digits_not_a_size_replaced"] = m.seal_row({"reason": "the file 12345678901 was left"})["reason"]
    r["digits_before_other_word_replaced"] = m.seal_row({"reason": "the file 12345678901 byte was left"})["reason"]
    r["other_classes_still_read"] = m.seal_row({"reason": "the entry %s could not be examined" % ("a1b2c3d4" + "e5f6a7b8")})["reason"]
    out[n] = r
print(json.dumps(out))
`;
  const run = await runPySnippet(code, [SURVEY, NOTES], null);
  assert.equal(run.code, 0, run.stderr);
  const all = JSON.parse(run.stdout) as Record<string, Record<string, unknown>>;
  assert.deepEqual(all.encrypted_survey, all.ransom_note_scan, "the two tools carry one second check");
  const r = all.ransom_note_scan;
  assert.equal(r.reason_kept, true);
  assert.equal(r.status_basis_kept, true);
  assert.equal(r.partial_reasons_kept, true);
  assert.match(String(r.file_replaced), /withheld at the output: a long run of digits/);
  assert.match(String(r.digits_not_a_size_replaced), /a long run of digits/);
  assert.match(String(r.digits_before_other_word_replaced), /a long run of digits/);
  assert.match(String(r.other_classes_still_read), /letters and digits in one run/);
  assert.equal(r.answer_stays_complete, "complete");
});

test("ransom_note_scan: a name-matched file of 5 GiB is listed with its size in the reason, and the answer says nothing was replaced", async () => {
  await withCwd(async (cwd) => {
    const ev = join(cwd, "work", "ev");
    await mkdir(ev, { recursive: true });
    await writeFile(join(ev, "restore_backup.vhdx"), "");
    await truncate(join(ev, "restore_backup.vhdx"), 5 * 1024 ** 3); // sparse
    const answer = body<{ status: string; boundary?: unknown; rejected: Row[]; partial_reasons: string[] }>(await tool(NOTES, cwd, { root: "work/ev" }));
    assert.equal(answer.rejected.length, 1);
    assert.match(String(answer.rejected[0].reason), /larger than max_size \(5368709120 bytes, max_size is 200000\): not read/);
    assert.equal(answer.boundary, undefined, "the size was taken for an identifier");
    assert.equal(answer.status, "partial");
    assert.ok(answer.partial_reasons.every((r) => !/first rule missed/.test(r)), answer.partial_reasons.join("; "));
  });
});

test("encrypted_survey: a spent read budget of the default size (4294967296 bytes) is explained in status_basis and partial_reasons, not replaced", async () => {
  await withCwd(async (cwd) => {
    const ev = join(cwd, "work", "ev");
    await mkdir(ev, { recursive: true });
    for (let i = 0; i < 3; i++) await writeFile(join(ev, `file${i}.bin`), randomBytes(9000));
    const out = join(cwd, "out");
    await mkdir(out);
    // the budget is spent at once: no 4 GiB of reads are needed to reach the sentence
    const run = await runPatched(SURVEY, "m.Budget.allows = lambda self, n: False", JSON.stringify({ root: "work/ev" }), cwd, out);
    assert.equal(run.code, 0, run.stderr + run.stdout);
    const answer = JSON.parse(run.stdout) as { status: string; status_basis: string; partial_reasons: string[]; boundary?: unknown };
    assert.equal(answer.status, "partial");
    assert.match(answer.status_basis, /the read budget \(4294967296 bytes\) was spent: 3 files have no entropy measurement or no profile/);
    assert.ok(answer.partial_reasons.some((r) => r.includes("(4294967296 bytes)")), answer.partial_reasons.join("; "));
    assert.equal(answer.boundary, undefined, "the examiner's own budget was taken for an identifier");
    assert.doesNotMatch(run.stdout, /withheld at the output/);
  });
});

// ---- the type of an error is a word ---------------------------------------------------------------------------------------------------

test("an error's type is printed: every builtin exception name passes the second check in describe() and in an unexpected failure", async () => {
  const code = LOAD + String.raw`
import builtins
out = {}
for n, p in (("encrypted_survey", sys.argv[1]), ("ransom_note_scan", sys.argv[2])):
    m = load(p, n)
    bad = []
    for name, cls in vars(builtins).items():
        if not (isinstance(cls, type) and issubclass(cls, BaseException)): continue
        if issubclass(cls, OSError):
            try: exc = cls(5, "Input/output error")
            except Exception: continue
            text = m.describe(exc)
        else:
            text = "%s at line 1234 of the tool" % name
        row = m.seal_row({"error": text, "reason": "the entry could not be examined"})
        if row["error"] != text: bad.append(name)
    out[n] = bad
print(json.dumps(out))
`;
  const run = await runPySnippet(code, [SURVEY, NOTES], null);
  assert.equal(run.code, 0, run.stderr);
  assert.deepEqual(JSON.parse(run.stdout), { encrypted_survey: [], ransom_note_scan: [] });
});

// ---- the place of a replaced string -------------------------------------------------------------------------------------------------------

test("the place of a replaced string never names a key that came from data, whatever the key looks like", async () => {
  const code = LOAD + String.raw`
out = {}
for n, p in (("encrypted_survey", sys.argv[1]), ("ransom_note_scan", sys.argv[2])):
    m = load(p, n)
    ident = sys.argv[3]
    keyed = ident.lower()                 # a key of lower-case letters and digits looks like a plain word to the pattern of a place
    value = "dir " + sys.argv[4]
    row = m.seal_row({keyed: {"inner": value}, "list": [{keyed + "x": [value]}]})
    places = [w["at"] for w in m.BOUNDARY["where"]]
    out[n] = {"places": places, "leaked": any(keyed in at for at in places), "key_kept": any(keyed in k for k in row)}
print(json.dumps(out))
`;
  const run = await runPySnippet(code, [SURVEY, NOTES, "a" + hexId(15), hexId(20)], null);
  assert.equal(run.code, 0, run.stderr);
  const out = JSON.parse(run.stdout) as Record<string, { places: string[]; leaked: boolean; key_kept: boolean }>;
  for (const [name, r] of Object.entries(out)) {
    assert.equal(r.places.length, 4, `${name}: ${r.places.join(",")}`);
    assert.equal(r.leaked, false, `${name}: a key that came from data is in a place: ${r.places.join(",")}`);
    assert.equal(r.key_kept, false, `${name}: the key itself was printed`);
    assert.deepEqual([...r.places].sort(), ["/*", "/*/inner", "/list/0/*", "/list/0/*/0"], name); // the keys themselves and the strings under them
  }
});

// ---- the receipt and the answer -------------------------------------------------------------------------------------------------------------

test("encrypted_survey: a string only the answer holds is replaced there, and the receipt that ends the census says partial as the answer does", async () => {
  await withCwd(async (cwd) => {
    const ev = join(cwd, "work", "ev");
    await mkdir(ev, { recursive: true });
    await writeFile(join(ev, "a.docx.locked"), randomBytes(6000));
    const odd = hexId(16); // an argument the tool does not know: echoed in the answer only
    const out = join(cwd, "out");
    await mkdir(out);
    const run = await tool(SURVEY, cwd, { root: "work/ev", [odd]: 1 }, { JOB_ID: "j000001", OUT: out });
    const answer = body<{ status: string; unrecognised_parameters: string[]; boundary?: { strings_replaced_at_the_output: number }; census: { file: string } }>(run);
    assert.ok(!run.stdout.includes(odd), "an argument named like an identifier was echoed");
    assert.equal(answer.status, "partial");
    assert.ok((answer.boundary?.strings_replaced_at_the_output ?? 0) >= 1);
    const lines = (await readFile(join(out, "tool-output", answer.census.file.split("/").pop() as string), "utf8")).trimEnd().split("\n");
    const receipt = JSON.parse(lines[lines.length - 1]) as { record: string; status: string; complete: string };
    assert.equal(receipt.record, "receipt");
    assert.equal(receipt.status, answer.status, "the receipt says complete, the answer says partial");
    assert.equal(receipt.complete, answer.status);
  });
});

test("encrypted_survey: when nothing is replaced the receipt and the answer both say complete, and the census is named as it is placed", async () => {
  await withCwd(async (cwd) => {
    const ev = join(cwd, "work", "ev");
    await mkdir(ev, { recursive: true });
    await writeFile(join(ev, "a.docx.locked"), randomBytes(6000));
    const out = join(cwd, "out");
    await mkdir(out);
    const first = body<{ status: string; census: { file: string } }>(await tool(SURVEY, cwd, { root: "work/ev", limit: 1 }, { JOB_ID: "j000001", OUT: out }));
    // a second run with other limits takes the next free name: the answer names the file it was placed in
    const second = body<{ status: string; census: { file: string } }>(await tool(SURVEY, cwd, { root: "work/ev", limit: 2, census: false }, { JOB_ID: "j000001", OUT: out }));
    assert.notEqual(first.census.file, second.census.file);
    for (const answer of [first, second]) {
      const lines = (await readFile(join(out, "tool-output", answer.census.file.split("/").pop() as string), "utf8")).trimEnd().split("\n");
      const receipt = JSON.parse(lines[lines.length - 1]) as { record: string; status: string };
      assert.equal(receipt.record, "receipt");
      assert.equal(receipt.status, answer.status);
    }
  });
});
