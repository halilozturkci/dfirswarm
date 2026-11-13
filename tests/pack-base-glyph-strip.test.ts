/**
 * computer-forensics-base: glyph_strip, the glyph count, the strip and the candidate set of a line of text in a picture.
 *
 * The line is drawn here, from a 5 x 7 bitmap font of this file's own, so the fixture owes nothing to the tool. It holds an apostrophe
 * and a backtick, an l and an I, an O and a 0: the capability is done when the count is right and a reading with two two-way positions
 * gives a candidate set of four that contains the line as drawn. The reading, the candidates and the OCR text are in files, never in
 * the answer. The OCR engine is a program the image may lack: without it the answer says so; with a stand-in on PATH the answer says
 * which reader read what; and a stand-in that leaves a late child holding its output pipe (an abandoned holder) does not hold the tool
 * and makes the answer partial.
 */
import assert from "node:assert/strict";
import { chmod, lstat, mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { CLEAN } from "./host-gates.ts";
import { call, CFB, filesBelow, greyPng, withRun, type Doc } from "./pack-base-media-fixture.ts";

// 5 x 7 glyphs, a row a string. The apostrophe and the backtick differ by their slant, l and I by their serifs, O and 0 by a slash.
const FONT: Record<string, string[]> = {
  x: [".....", ".....", "#...#", ".#.#.", "..#..", ".#.#.", "#...#"],
  "'": ["..#..", "..#..", ".#...", ".....", ".....", ".....", "....."],
  "`": [".#...", "..#..", "...#.", ".....", ".....", ".....", "....."],
  l: [".##..", "..#..", "..#..", "..#..", "..#..", "..#..", ".###."],
  I: ["#####", "..#..", "..#..", "..#..", "..#..", "..#..", "#####"],
  O: [".###.", "#...#", "#...#", "#...#", "#...#", "#...#", ".###."],
  "0": [".###.", "#..##", "#.#.#", "#.#.#", "#.#.#", "##..#", ".###."],
  "7": ["#####", "....#", "...#.", "..#..", "..#..", ".#...", ".#..."],
  a: [".....", ".....", ".###.", "....#", ".####", "#...#", ".####"],
  p: [".....", ".....", "####.", "#...#", "####.", "#....", "#...."],
};

/** One line of text as a grey picture: each glyph scaled, two blank columns between glyphs, a wide gap for a space, dark ink on light paper (or the reverse). */
function line(text: string, scale = 3, inverted = false): Buffer {
  const columns: number[][] = [];
  const blank = (n: number): void => {
    for (let i = 0; i < n * scale; i++) columns.push(new Array(7 * scale).fill(0));
  };
  blank(4);
  for (const ch of text) {
    if (ch === " ") {
      blank(7);
      continue;
    }
    const glyph = FONT[ch]!;
    for (let x = 0; x < 5; x++) for (let k = 0; k < scale; k++) columns.push(Array.from({ length: 7 * scale }, (_, y) => (glyph[Math.floor(y / scale)]![x] === "#" ? 1 : 0)));
    blank(2);
  }
  blank(4);
  const height = 7 * scale + 16;
  const [ink, paper] = inverted ? [235, 20] : [15, 240];
  return greyPng(Array.from({ length: height }, (_, y) => columns.map((col) => (y >= 8 && y < 8 + 7 * scale && col[y - 8] ? ink : paper))));
}

const TRUTH = "x'7lO a`I0p";

test("a line with an apostrophe and a backtick, an l and an I gives the right count and a four-candidate set that contains the truth", async () => {
  await withRun(async (run, out) => {
    await writeFile(join(run, "inputs/case files/line one.png"), line(TRUTH));
    // The reader's doubt: position 1 is ' or `, position 3 is l or I. The reading itself has both wrong.
    const reading = "x`7IO a`I0p";
    const r = await call("glyph_strip", run, { image: "inputs/case files/line one.png", reading, uncertain: [{ at: 1, among: "'`" }, { at: 3, among: "lI" }], ocr: "none" }, { out });
    assert.equal(r.code, 0, r.stdout + r.stderr);
    assert.equal(r.stderr, "");
    const a = r.doc;
    assert.equal(a.status, "complete", a.status_basis);
    assert.equal(a.count, 10, "ten glyphs: the eleven characters less the space");
    assert.deepEqual(a.spaces_after, [5], "the gap after the fifth glyph is the space");
    assert.equal(a.glyphs.length, 10);
    assert.deepEqual([a.polarity, a.ink_bands], ["dark on light", 1]);
    // The apostrophe and the backtick sit high: their boxes end well above the line's bottom, and every glyph has a crop.
    assert.ok(a.glyphs[1].above_line_bottom >= 9 && a.glyphs[6].above_line_bottom >= 9);
    assert.ok(a.glyphs.every((g: Doc, i: number) => g.index === i + 1 && /glyph-\d{3}\.png$/.test(g.crop)));
    assert.equal(a.candidates.candidate_set_size, 4);
    assert.equal(a.candidates.confidence, "medium");
    assert.match(a.candidates.record_as, /a candidate set of 4, at medium confidence/);
    assert.deepEqual(a.candidates.uncertain_positions, [{ at: 1, alternatives: 2, glyph: 2 }, { at: 3, alternatives: 2, glyph: 4 }]);
    const candidates = (await readFile(join(out, "glyph_strip", "candidates.txt"), "utf8")).trim().split("\n");
    assert.equal(candidates.length, 4);
    assert.equal(candidates[0], reading, "the reading itself is the first candidate");
    assert.ok(candidates.includes(TRUTH), "the set contains the line as it was drawn");
    assert.equal(new Set(candidates).size, 4);
    assert.equal((await lstat(join(out, "glyph_strip", "candidates.txt"))).mode & 0o777, 0o600);
    // Under $OUT, and nowhere else: the strip, a crop a glyph and the candidates.
    assert.deepEqual(filesBelow(out), ["glyph_strip/candidates.txt", ...Array.from({ length: 10 }, (_, i) => `glyph_strip/glyph-${String(i + 1).padStart(3, "0")}.png`), "glyph_strip/strip.png"].sort());
    assert.deepEqual(filesBelow(join(run, "work")), []);
    // Neither the reading nor a candidate is in the answer.
    for (const text of [reading, TRUTH, ...candidates]) assert.ok(!r.stdout.includes(text), "no reading in the answer");
    assert.deepEqual(a.readers.map((x: Doc) => x.reader), ["glyph_strip (this tool)", "the caller"]);
    assert.equal(a.readers[1].agrees_with_count, true);
    assert.match(a.ocr.said, /no OCR engine was asked for/);
  });
});

test("glyphs that are the same drawing are grouped and tied; the default classes; a light-on-dark crop; a reading of another length", async () => {
  await withRun(async (run, out) => {
    await writeFile(join(run, "inputs/case files/same.png"), line("lxl 0O", 4, true));
    const tied = await call("glyph_strip", run, { image: "inputs/case files/same.png", reading: "lxl 0O", uncertain: [{ at: 0, among: "lI" }, { at: 2, among: "lI" }], ocr: "none" }, { out });
    assert.equal(tied.doc.polarity, "light on dark");
    assert.equal(tied.doc.count, 5);
    assert.deepEqual(tied.doc.same_shape_groups, [[1, 3]]);
    assert.deepEqual(tied.doc.candidates.positions_tied, [[0, 2]]);
    assert.equal(tied.doc.candidates.candidate_set_size, 2, "two uncertain positions with one drawing are one choice");
    assert.deepEqual((await readFile(join(out, "glyph_strip", "candidates.txt"), "utf8")).trim().split("\n"), ["lxl 0O", "IxI 0O"]);
    // No `uncertain`: every character of the reading that is in a class. l (4 look-alikes) twice, tied; x (2); 0 and O (3 each), two drawings.
    const classes = await call("glyph_strip", run, { image: "inputs/case files/same.png", reading: "lxl 0O", ocr: "none" }, { out });
    assert.equal(classes.doc.candidates.candidate_set_size, 4 * 2 * 3 * 3);
    assert.match(classes.doc.candidates.uncertain_from, /every character of the reading that is in a confusable class/);
    // A reading with another number of characters: the readers disagree, nothing is tied, and the answer says why.
    const off = await call("glyph_strip", run, { image: "inputs/case files/same.png", reading: "lxl0", uncertain: [0, 2], ocr: "none" }, { out });
    assert.equal(off.doc.readers[1].agrees_with_count, false);
    assert.match(off.doc.candidates.glyphs_not_matched, /4 characters besides spaces and the line has 5 ink runs/);
    assert.equal(off.doc.candidates.candidate_set_size, 16);
    // A set larger than max_candidates is counted exactly and written in part: partial.
    const cut = await call("glyph_strip", run, { image: "inputs/case files/same.png", reading: "lxl 0O", max_candidates: 5, ocr: "none" }, { out });
    assert.deepEqual([cut.doc.status, cut.doc.complete, cut.doc.candidates.candidate_set_size, cut.doc.candidates.candidates_written, cut.doc.candidates.truncated], ["partial", false, 72, 5, true]);
  });
});

/** A stand-in OCR engine on a PATH of its own: `--version` prints a name, a read prints one line; `late` leaves a child holding stdout. */
async function engine(run: string, text: string, late = false): Promise<string> {
  const bin = join(run, "work", "bin");
  await mkdir(bin, { recursive: true });
  await writeFile(join(bin, "line.txt"), text + "\n");
  const say = `cat "$(dirname "$0")/line.txt"`;
  const body = late
    ? `#!/bin/sh\nif [ "$1" = "--version" ]; then echo "tesseract 0.0-standin"; exit 0; fi\n${say}\n( sleep 4; echo late ) &\nexit 0\n`
    : `#!/bin/sh\nif [ "$1" = "--version" ]; then echo "tesseract 0.0-standin"; exit 0; fi\ncase "$2" in stdout) ${say};; *) exit 3;; esac\n`;
  await writeFile(join(bin, "tesseract"), body);
  await chmod(join(bin, "tesseract"), 0o755);
  return `${bin}:/usr/bin:/bin`;
}

test("an OCR engine is a second reader when the image holds one, and the answer says so when it does not", async () => {
  await withRun(async (run, out) => {
    await writeFile(join(run, "inputs/case files/line one.png"), line(TRUTH));
    const args = { image: "inputs/case files/line one.png", reading: "x`7IO a`I0p", uncertain: [{ at: 1, among: "'`" }, { at: 3, among: "lI" }] };
    // No engine on PATH.
    const without = await call("glyph_strip", run, args, { out, path: "/usr/bin:/bin" });
    assert.equal(without.doc.status, "complete");
    assert.equal(without.doc.ocr.available, false);
    assert.match(without.doc.ocr.said, /no OCR engine is in this image \(tesseract is not on PATH\)/);
    assert.deepEqual(without.doc.readers.map((x: Doc) => x.reader), ["glyph_strip (this tool)", "the caller"]);
    // A stand-in engine that reads the line with the apostrophe right and the l wrong.
    const ocrText = "x'7IO a`I0p";
    const withIt = await call("glyph_strip", run, args, { out, path: await engine(run, ocrText) });
    assert.equal(withIt.doc.status, CLEAN, withIt.doc.status_basis);
    assert.deepEqual(withIt.doc.ocr, { available: true, engine: "tesseract 0.0-standin", read: true, characters: 11, characters_without_spaces: 10, text_file: "store/jobs/j000001/out/glyph_strip-2/ocr.txt" });
    assert.deepEqual(withIt.doc.readers.map((x: Doc) => [x.reader, x.agrees_with_count ?? null]), [["tesseract 0.0-standin", true], ["glyph_strip (this tool)", null], ["the caller", true]]);
    assert.deepEqual(withIt.doc.reading_against_ocr, { same_length: true, positions_that_differ: [1], differ: 1, of_them_uncertain: 1 });
    assert.equal(await readFile(join(out, "glyph_strip-2", "ocr.txt"), "utf8"), ocrText + "\n");
    assert.ok(!withIt.stdout.includes(ocrText), "the OCR text is not in the answer");
    assert.ok("program_group" in withIt.doc);
  });
});

test("an engine that leaves a late child holding its pipe (an abandoned holder) does not hold the tool, and the answer is partial", async () => {
  await withRun(async (run, out) => {
    await writeFile(join(run, "inputs/case files/line one.png"), line(TRUTH));
    const r = await call("glyph_strip", run, { image: "inputs/case files/line one.png" }, { out, path: await engine(run, "x'7lO a`I0p", true), limitMs: 30_000 });
    assert.equal(r.killed, false);
    assert.ok(r.ms < 3500, `the tool answered in ${r.ms} ms, before the holder's four seconds were up`);
    assert.equal(r.doc.status, "partial", r.stdout);
    assert.equal(r.doc.count, 10);
    assert.equal(r.doc.ocr.read, true, "what the engine wrote before it ended is its reading");
    assert.ok(r.doc.program_group.left_behind > 0 || r.doc.program_group.unproven.length > 0);
    assert.ok(!r.stdout.includes("late"), "what the holder wrote after the program ended is not the reading");
  });
});

test("the rules are in the manifest, in every refusal and on the note's card; the note carries the candidate-set rule", async () => {
  const manifest = JSON.parse(await readFile(join(CFB, "tools", "glyph_strip", "manifest.json"), "utf8")) as Doc;
  const note = await readFile(join(CFB, "skills", "data", "glyphs.md"), "utf8");
  await withRun(async (run, out) => {
    const refused = await call("glyph_strip", run, { reading: "abc" }, { out });
    assert.equal(refused.code, 1);
    const rules = refused.doc.rules as string[];
    assert.ok(rules.length >= 3 && rules.length <= 5);
    for (const rule of rules) assert.ok(manifest.description.includes(rule));
    assert.match(rules[0]!, /recorded at MEDIUM confidence as a candidate set, never as one string/);
    assert.match(refused.doc.error, /image is required/);
    const wrong = await call("glyph_strip", run, { image: "inputs/x.png", uncertain: [1] }, { out });
    assert.match(wrong.doc.error, /uncertain goes with reading.*positions from 0/);
  });
  const card = /^card: (.+)$/m.exec(note)?.[1] ?? "";
  assert.ok(card.length > 100 && card.length <= 700, "the card is shown whole");
  assert.match(card, /"uncertain": \[\{"at": 4, "among": "lI"\}/);
  assert.match(card, /recorded at MEDIUM confidence as a candidate set/);
  assert.match(note.replace(/\s+/g, " "), /The reading is then recorded at \*\*medium\*\* confidence as a candidate set of `candidate_set_size` with `candidates_file`, never as one string/);
  assert.match(await readFile(join(CFB, "skills", "data", "documents-media.md"), "utf8"), /makes the reading a candidate set at medium confidence \(`data\/glyphs`\)/);
  // The image declaration names the engine and the font set the note relies on.
  const host = JSON.parse(await readFile(join(CFB, "requires", "host.json"), "utf8")) as { binaries: Doc[] };
  const tesseract = host.binaries.find((b) => b.name === "tesseract")!;
  assert.equal(tesseract.optional, true);
  assert.match(tesseract.install.apt, /tesseract-ocr tesseract-ocr-eng fonts-dejavu-core/);
});
