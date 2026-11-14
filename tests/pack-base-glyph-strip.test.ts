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
import { call, CFB, filesBelow, greyPng, ROOT, withRun, type Doc } from "./pack-base-media-fixture.ts";
import { spawnSync } from "node:child_process";
import { PYTHON3 } from "./host-gates.ts";

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
    // The OCR text's length is not in the answer either: only whether its characters besides spaces are as many as the ink runs.
    assert.deepEqual(withIt.doc.ocr, { available: true, engine: "tesseract 0.0-standin", read: true, read_from: "the crop as this tool decoded it (its first frame, grey), not the file", text_file: "store/jobs/j000001/out/glyph_strip-2/ocr.txt" });
    assert.deepEqual(Object.keys(withIt.doc.readers[0]).sort(), ["agrees_with_count", "read", "reader"], "the OCR reader's entry carries no length");
    assert.ok(!withIt.stdout.includes('"same_length"'));
    assert.deepEqual(withIt.doc.readers.map((x: Doc) => [x.reader, x.agrees_with_count ?? null]), [["tesseract 0.0-standin", true], ["glyph_strip (this tool)", null], ["the caller", true]]);
    // Where the two texts differ follows the OCR text, which the answer does not show: the positions are in a file of their own, never in
    // the answer, so that calls with readings varied a character at a time cannot rebuild ocr.txt from answers.
    const against = withIt.doc.reading_against_ocr as Doc;
    assert.deepEqual(Object.keys(against).sort(), ["file", "what"]);
    assert.equal(against.file, "store/jobs/j000001/out/glyph_strip-2/reading_against_ocr.tsv");
    for (const key of ["positions_that_differ", "differ", "of_them_uncertain"]) assert.ok(!withIt.stdout.includes(`"${key}"`), `${key} is not in the answer`);
    const rows = (await readFile(join(out, "glyph_strip-2", "reading_against_ocr.tsv"), "utf8")).trim().split("\n").map((l) => l.split("\t"));
    assert.deepEqual(rows[0], ["at", "differs", "uncertain"]);
    assert.equal(rows.length, 1 + 400 + 1, "a row for each of the first 400 positions whatever the two lengths, and the length row: the size says nothing of the OCR text");
    assert.deepEqual(rows.at(-1), ["same_length", "1", "-"]);
    assert.deepEqual(rows.slice(1, 12).filter((r) => r[1] === "1").map((r) => [r[0], r[2]]), [["1", "1"]], "position 1 differs, and it was marked uncertain");
    assert.ok(rows.slice(12, -1).every((r) => r[1] === "1" && r[2] === "0"), "a position past the reading differs");
    assert.equal((await lstat(join(out, "glyph_strip-2", "reading_against_ocr.tsv"))).mode & 0o777, 0o600);
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

/** Groups of glyphs on one line: the glyphs of a group touch (no blank column between them), two blank columns between groups. */
function touching(groups: string[], scale = 3): Buffer {
  const columns: number[][] = [];
  const blank = (n: number): void => {
    for (let i = 0; i < n * scale; i++) columns.push(new Array(7 * scale).fill(0));
  };
  blank(4);
  for (const group of groups) {
    for (const ch of group) {
      const glyph = FONT[ch]!;
      for (let x = 0; x < 5; x++) for (let k = 0; k < scale; k++) columns.push(Array.from({ length: 7 * scale }, (_, y) => (glyph[Math.floor(y / scale)]![x] === "#" ? 1 : 0)));
    }
    blank(2);
  }
  blank(4);
  return greyPng(Array.from({ length: 7 * scale + 16 }, (_, y) => columns.map((col) => (y >= 8 && y < 8 + 7 * scale && col[y - 8] ? 15 : 240))));
}

test("glyphs that are the same drawing but read as two characters are not tied: the reading is the first candidate and every combination is in the set", async () => {
  await withRun(async (run, out) => {
    // Three l's drawn alike. A reader who reads them as l, I and 1 is not overruled by the drawing: the set keeps every combination of the
    // three classes (4 x 4 x 4), the reading first, and the answer names the pairs that are one drawing read as two characters.
    await writeFile(join(run, "inputs/case files/three.png"), line("lll"));
    const apart = await call("glyph_strip", run, { image: "inputs/case files/three.png", reading: "lI1", ocr: "none" }, { out });
    assert.equal(apart.doc.status, "complete", apart.doc.status_basis);
    assert.deepEqual(apart.doc.same_shape_groups, [[1, 2, 3]]);
    const c = apart.doc.candidates as Doc;
    assert.equal(c.candidate_set_size, 64);
    assert.equal(c.positions_tied, undefined, "nothing is tied against the reading");
    assert.deepEqual(c.same_drawing_read_apart, [[0, 1], [0, 2], [1, 2]]);
    assert.equal(c.first_line_is_the_reading, true);
    const lines = (await readFile(join(out, "glyph_strip", "candidates.txt"), "utf8")).trim().split("\n");
    assert.equal(lines.length, 64);
    assert.equal(lines[0], "lI1", "the reading itself is the first candidate");
    assert.equal(new Set(lines).size, 64);
    for (const text of ["lll", "III", "111", "|||", "1Il"]) assert.ok(lines.includes(text), `${text} is in the set`);
    // Read as l, I and l: the two l's are tied (one choice), the I is not tied to either, and the reading is still first.
    const tied = await call("glyph_strip", run, { image: "inputs/case files/three.png", reading: "lIl", ocr: "none" }, { out });
    const t = tied.doc.candidates as Doc;
    assert.deepEqual([t.candidate_set_size, t.positions_tied, t.same_drawing_read_apart, t.first_line_is_the_reading], [16, [[0, 2]], [[0, 1], [1, 2]], true]);
    const tiedLines = (await readFile(join(out, "glyph_strip-2", "candidates.txt"), "utf8")).trim().split("\n");
    assert.equal(tiedLines[0], "lIl");
    assert.ok(tiedLines.every((l) => l[0] === l[2]), "a tied pair holds one character in every candidate");
    assert.ok(!apart.stdout.includes("lI1") && !tied.stdout.includes("lIl"), "no reading in the answer");
  });
});

test("a picture of a shape no line has is refused by its header, before a row of it is decoded", async () => {
  await withRun(async (run, out) => {
    // A column one pixel wide and 100,000 high, and a thread 300,000 wide and 2 high: both within the pixel bound, neither a line.
    await writeFile(join(run, "inputs/case files/column.png"), greyPng(Array.from({ length: 100_000 }, (_, y) => [y % 50 < 25 ? 15 : 240])));
    const thread = Array.from({ length: 300_000 }, (_, x) => (x % 50 < 25 ? 15 : 240));
    await writeFile(join(run, "inputs/case files/thread.png"), greyPng([thread, thread]));
    for (const [name, size] of [["column.png", "1 x 100000"], ["thread.png", "300000 x 2"]]) {
      const r = await call("glyph_strip", run, { image: `inputs/case files/${name}`, ocr: "none" }, { out, limitMs: 30_000 });
      assert.deepEqual([r.code, r.doc.status], [1, "failed"], r.stdout);
      assert.match(r.doc.error, new RegExp(`the picture is ${size} pixels: this tool takes a crop of one line \\(up to 6000000 pixels, at most 2000 high and 50000 wide\\)`));
      assert.ok(r.ms < 10_000, `${name} was refused in ${r.ms} ms`);
    }
    assert.deepEqual(filesBelow(out), [], "nothing was written for a refused picture");
  });
});

test("399 tall glyphs drawn alike and read alike are compared and tied well inside the clock", async () => {
  await withRun(async (run, out) => {
    // 399 bars 1,400 pixels tall, drawn alike and read alike: every pair is compared (pixel by pixel, the old way, that took 17 s on an
    // M-series host) and all are tied into one choice, well inside the clock.
    const row = Array.from({ length: 4000 }, (_, x) => (x >= 5 && (x - 5) % 10 < 4 && (x - 5) / 10 < 399 ? 15 : 240));
    const paper = row.map(() => 240);
    await writeFile(join(run, "inputs/case files/bars.png"), greyPng(Array.from({ length: 1420 }, (_, y) => (y >= 10 && y < 1410 ? row : paper))));
    const bars = await call("glyph_strip", run, { image: "inputs/case files/bars.png", reading: "l".repeat(399), ocr: "none" }, { out, limitMs: 60_000 });
    assert.equal(bars.doc.count, 399, bars.stdout.slice(0, 400));
    assert.equal(bars.doc.status, "complete", bars.doc.status_basis);
    assert.equal(bars.doc.candidates.candidate_set_size, 4);
    assert.equal(bars.doc.candidates.positions_tied.length, 398);
    assert.ok(bars.doc.seconds < 8, `399 tied glyphs took ${bars.doc.seconds} s`);
  });
});

test("a blank crop with a reading has its candidate set written, and a run that is itself the median width can be wide", async () => {
  await withRun(async (run, out) => {
    await writeFile(join(run, "inputs/case files/blank.png"), greyPng(Array.from({ length: 40 }, () => new Array(200).fill(240))));
    const blank = await call("glyph_strip", run, { image: "inputs/case files/blank.png", reading: "lO", ocr: "none" }, { out });
    assert.deepEqual([blank.code, blank.doc.status, blank.doc.count], [0, "complete", 0], blank.stdout);
    assert.equal(blank.doc.candidates.candidate_set_size, 12);
    assert.equal(blank.doc.candidates.candidates_file, "store/jobs/j000001/out/glyph_strip/candidates.txt");
    assert.match(blank.doc.candidates.glyphs_not_matched, /2 characters besides spaces and the line has 0 ink runs/);
    assert.equal((await readFile(join(out, "glyph_strip", "candidates.txt"), "utf8")).trim().split("\n").length, 12);
    assert.equal(blank.doc.readers.at(-1).agrees_with_count, false);
    // An a, then two pairs of touching x's: two of the three runs are pairs, so the median width is a pair's; each pair is still wide.
    await writeFile(join(run, "inputs/case files/pairs.png"), touching(["a", "xx", "xx"]));
    const pairs = await call("glyph_strip", run, { image: "inputs/case files/pairs.png", ocr: "none" }, { out });
    assert.deepEqual(pairs.doc.glyphs.map((g: Doc) => g.width), [15, 30, 30]);
    assert.deepEqual(pairs.doc.wide, [2, 3]);
  });
});

test("an OCR engine that floods its output is read up to its bound and ended, and the call answers in time", async () => {
  await withRun(async (run, out) => {
    await writeFile(join(run, "inputs/case files/line one.png"), line(TRUTH));
    const bin = join(run, "work", "bin");
    await mkdir(bin, { recursive: true });
    await writeFile(join(bin, "tesseract"), `#!/bin/sh\nif [ "$1" = "--version" ]; then echo "tesseract 0.0-standin"; exit 0; fi\nexec yes "a line that never ends"\n`);
    await chmod(join(bin, "tesseract"), 0o755);
    const r = await call("glyph_strip", run, { image: "inputs/case files/line one.png", reading: "x'7lO a`I0p" }, { out, path: `${bin}:/usr/bin:/bin`, limitMs: 40_000 });
    assert.equal(r.killed, false);
    assert.ok(r.ms < 8000, `the tool answered in ${r.ms} ms, not at the engine's 20-second clock`);
    assert.equal(r.doc.count, 10);
    assert.deepEqual([r.doc.ocr.read, r.doc.ocr.engine], [false, "tesseract 0.0-standin"]);
    assert.match(r.doc.ocr.said, /the OCR engine did not read the crop \(it wrote more than 65536 bytes\)/);
    assert.equal(r.doc.reading_against_ocr, undefined);
    assert.ok(!filesBelow(out).some((f) => f.endsWith("ocr.txt")), "no OCR text was written");
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

// ---- the second verification of 1.17.1: Pillow's decode ends at the clock; the OCR engine is not started past it; the frames are named ---

/** Pillow as the tool sees it (the tool runs without -I, so a user site counts). */
const pillowHere = (cwd: string): boolean => spawnSync(PYTHON3, ["-c", "import PIL.Image"], { cwd }).status === 0;

/** A fixture script that needs Pillow (run without -I, as the tool is): its stdout, or a failed assertion. */
function withPillow(code: string, args: string[], cwd: string): string {
  const r = spawnSync(PYTHON3, ["-c", code, ...args], { cwd, encoding: "utf8", maxBuffer: 64 << 20 });
  assert.equal(r.status, 0, `the fixture builder failed: ${r.stderr.slice(-600)}`);
  return r.stdout;
}

/**
 * A progressive JPEG with `n` more AC scans of its one component, each coding every block in end-of-band runs (EOB14: one code of one bit
 * in the scan's own table, then 14 bits of run length, so 32767 blocks in 15 bits; ISO/IEC 10918-1 G.1.2.2). A decoder works through
 * every block of every scan, so the scans cost time far beyond their bytes. 3000 x 2000 pixels (a crop this tool takes): 93,750 blocks.
 */
const JPEG_SCANS = String.raw`
import io, struct, sys
from PIL import Image, ImageDraw
out, n, w, h = sys.argv[1], int(sys.argv[2]), 3000, 2000
im = Image.new("L", (w, h), 255)
d = ImageDraw.Draw(im)
for i in range(0, w - 20, 40): d.rectangle([i + 5, 20, i + 20, h - 20], fill=0)
buf = io.BytesIO(); im.save(buf, "JPEG", progressive=True, quality=90); data = buf.getvalue()
assert data[-2:] == b"\xff\xd9"
left, bits = ((w + 7) // 8) * ((h + 7) // 8), ""
while left > 0:
    run = min(left, 32767); assert run >= 16384; bits += "0" + format(run - 16384, "014b"); left -= run
bits += "1" * (-len(bits) % 8)
entropy = bytearray()
for i in range(0, len(bits), 8):
    entropy.append(int(bits[i:i + 8], 2))
    if entropy[-1] == 0xFF: entropy.append(0)
table = bytes([0x10]) + bytes([1] + [0] * 15) + bytes([0xE0])
dht = b"\xff\xc4" + struct.pack(">H", 2 + len(table)) + table
scan = b"\xff\xda" + struct.pack(">H", 8) + bytes([1, 1, 0x00, 1, 63, 0x00]) + bytes(entropy)
open(out, "wb").write(data[:-2] + dht + scan * n + b"\xff\xd9")
`;

test("a JPEG of 250,000 scans is refused by its count, and with that bound lifted Pillow's decode is ended at the clock", async () => {
  await withRun(async (run, out) => {
    if (!pillowHere(run)) return;
    withPillow(JPEG_SCANS, [join(run, "inputs/case files/scans.jpg"), "250000"], run);
    const refused = await call("glyph_strip", run, { image: "inputs/case files/scans.jpg", max_seconds: 5, ocr: "none" }, { out, limitMs: 40_000 });
    assert.ok(refused.ms < 10_000, `${refused.ms} ms`);
    assert.equal(refused.doc.status, "failed");
    assert.match(refused.doc.error, /a JPEG of 25000\d scans \(start-of-scan markers\): this tool hands Pillow a JPEG of up to 256/);
    // The bound of scans is lifted (an environment variable for the tests): Pillow, which reads no clock of its own, decodes in a child
    // that the tool kills at its clock (the decode of all the scans takes over a minute).
    const lifted = await call("glyph_strip", run, { image: "inputs/case files/scans.jpg", max_seconds: 5, ocr: "none" }, { out, limitMs: 40_000, env: { TOOL_MAX_JPEG_SCANS: "100000000" } });
    assert.equal(lifted.killed, false, "the call ended by itself");
    assert.ok(lifted.ms < 12_000, `answered in ${lifted.ms} ms on a 5 second clock`);
    assert.equal(lifted.doc.status, "failed", lifted.stdout.slice(0, 600));
    assert.match(lifted.doc.error, /the tool's clock \(max_seconds 5\) ran out while the picture was being read/);
  });
});

test("the OCR engine is not started once the clock is nearly out; a picture of several frames says the others were not read; the chunk walk reads the clock", async () => {
  await withRun(async (run, out) => {
    await writeFile(join(run, "inputs/case files/line one.png"), line(TRUTH));
    // A stand-in whose --version takes four of the five seconds: no time is left to read the crop, so the engine is not run on it.
    const bin = join(run, "work", "bin");
    await mkdir(bin, { recursive: true });
    await writeFile(join(bin, "tesseract"), `#!/bin/sh\nif [ "$1" = "--version" ]; then sleep 4; echo "tesseract 0.0-standin"; exit 0; fi\necho "x'7lO a\`I0p"\n`);
    await chmod(join(bin, "tesseract"), 0o755);
    const late = await call("glyph_strip", run, { image: "inputs/case files/line one.png", max_seconds: 5 }, { out, path: `${bin}:/usr/bin:/bin`, limitMs: 30_000 });
    assert.ok(late.ms < 7_000, `answered in ${late.ms} ms on a 5 second clock`);
    assert.equal(late.doc.status, "partial", late.stdout.slice(0, 600));
    assert.equal(late.doc.ocr.read, false);
    assert.match(late.doc.ocr.said, /not run on the crop: the tool's clock had less than 2 seconds left/);
    assert.match(late.doc.partial_reasons.join(" "), /OCR engine was not run/);

    // A PNG whose 8 x 8 picture is followed by 22 million empty chunks: the built-in reader's walk of them reads the clock.
    const fs = await import("node:fs");
    const { deflateSync, crc32 } = await import("node:zlib");
    const chunk = (kind: string, body: Buffer): Buffer => {
      const head = Buffer.alloc(8);
      head.writeUInt32BE(body.length, 0);
      head.write(kind, 4, "latin1");
      const crc = Buffer.alloc(4);
      crc.writeUInt32BE(crc32(Buffer.concat([head.subarray(4), body])), 0);
      return Buffer.concat([head, body, crc]);
    };
    const ihdr = Buffer.alloc(13);
    ihdr.writeUInt32BE(8, 0);
    ihdr.writeUInt32BE(8, 4);
    ihdr[8] = 8;
    const fd = fs.openSync(join(run, "inputs/case files/chunks.png"), "w");
    fs.writeSync(fd, Buffer.concat([Buffer.from("89504e470d0a1a0a", "hex"), chunk("IHDR", ihdr), chunk("IDAT", deflateSync(Buffer.concat(Array.from({ length: 8 }, () => Buffer.from([0, 255, 255, 255, 255, 255, 255, 255, 255])))))]));
    const many = Buffer.concat(Array.from({ length: 65536 }, () => chunk("zzZz", Buffer.alloc(0))));
    for (let i = 0; i < Math.floor((250 << 20) / many.length); i++) fs.writeSync(fd, many);
    fs.writeSync(fd, chunk("IEND", Buffer.alloc(0)));
    fs.closeSync(fd);
    const chunks = await call("glyph_strip", run, { image: "inputs/case files/chunks.png", max_seconds: 5, ocr: "none", reader: "builtin" }, { out, limitMs: 40_000 });
    assert.equal(chunks.killed, false);
    assert.ok(chunks.ms < 10_000, `answered in ${chunks.ms} ms on a 5 second clock`);
    assert.match(chunks.doc.error, /clock \(max_seconds 5\) ran out while the picture was being read/);

    if (!pillowHere(run)) return;
    withPillow(String.raw`
import sys
from PIL import Image
first = Image.open(sys.argv[1]).convert("L")
second = Image.new("L", first.size, 255)
first.save(sys.argv[2], save_all=True, append_images=[second], duration=100)
`, [join(run, "inputs/case files/line one.png"), join(run, "inputs/case files/two frames.gif")], run);
    const two = await call("glyph_strip", run, { image: "inputs/case files/two frames.gif", ocr: "none" }, { out });
    assert.equal(two.doc.count, 10, two.stdout.slice(0, 600));
    assert.equal(two.doc.status, "partial");
    assert.match(two.doc.frames_not_read, /holds frames after the first, and they were not read/);
  });
});

test("the OCR engine reads the crop as this tool decoded it, never the file; an engine ended by a signal is partial; a lone surrogate is refused; every read-apart pair is counted", async () => {
  await withRun(async (run, out) => {
    await writeFile(join(run, "inputs/case files/line one.png"), line(TRUTH));
    const args = { image: "inputs/case files/line one.png", reading: "x`7IO a`I0p", uncertain: [{ at: 1, among: "'`" }, { at: 3, among: "lI" }] };
    // A stand-in engine that keeps what it was given: the path, and a copy of the file.
    const bin = join(run, "work", "seen");
    await mkdir(bin, { recursive: true });
    await writeFile(join(bin, "tesseract"), `#!/bin/sh\nif [ "$1" = "--version" ]; then echo "tesseract 0.0-standin"; exit 0; fi\nprintf '%s' "$1" > "$(dirname "$0")/path.txt"\ncp "$1" "$(dirname "$0")/given.png"\necho "the line"\n`);
    await chmod(join(bin, "tesseract"), 0o755);
    const r = await call("glyph_strip", run, args, { out, path: `${bin}:/usr/bin:/bin` });
    assert.equal(r.code, 0, r.stdout + r.stderr);
    assert.equal(r.doc.ocr.read, true, JSON.stringify(r.doc.ocr));
    const given = await readFile(join(bin, "given.png"));
    const path = await readFile(join(bin, "path.txt"), "utf8");
    assert.ok(!path.endsWith("line one.png"), `the engine was given ${path}, not the evidence file`);
    assert.match(path, /\.ocr-input\.png$/);
    assert.deepEqual([given.readUInt32BE(16), given.readUInt32BE(20), given[24], given[25]], [r.doc.pixels.split(" x ").map(Number)[0], r.doc.pixels.split(" x ").map(Number)[1], 8, 0], "an 8-bit grey PNG of the crop's size");
    assert.ok(!filesBelow(out).some((f) => f.includes(".ocr-input")), "the decoded crop given to the engine is removed after");
    // An engine ended by a signal made no reading: partial, and the signal is said.
    await writeFile(join(bin, "tesseract"), `#!/bin/sh\nif [ "$1" = "--version" ]; then echo "tesseract 0.0-standin"; exit 0; fi\nkill -9 $$\n`);
    const killed = await call("glyph_strip", run, args, { out, path: `${bin}:/usr/bin:/bin` });
    assert.equal(killed.doc.status, "partial", killed.doc.status_basis);
    assert.equal(killed.doc.not_read_or_judged.ocr_not_read, 1);
    assert.match(killed.doc.ocr.said, /ended by signal 9/);
    // A lone surrogate in among or in a class is refused as one JSON document, not an unexpected failure.
    for (const bad of [{ ...args, uncertain: [{ at: 3, among: "l\ud800" }], ocr: "none" }, { ...args, uncertain: undefined, classes: ["l\udfff"], ocr: "none" }]) {
      const refused = await call("glyph_strip", run, bad, { out });
      assert.equal(refused.code, 1, refused.stdout + refused.stderr);
      assert.equal(refused.doc.status, "failed");
      assert.match(refused.doc.error, /among must be|classes must be/);
    }
    // Fifteen l's drawn alike, read as eight l's and seven I's: 56 pairs are one drawing read apart (the answer lists 50 and counts them
    // all), and the positions read alike are tied, two choices of two.
    await writeFile(join(run, "inputs/case files/many.png"), line("l".repeat(15)));
    const reading = "lIlIlIlIlIlIlIl";
    const many = await call("glyph_strip", run, { image: "inputs/case files/many.png", reading, uncertain: Array.from({ length: 15 }, (_, at) => ({ at, among: "lI" })), ocr: "none" }, { out });
    assert.equal(many.code, 0, many.stdout + many.stderr);
    const c = many.doc.candidates as Doc;
    assert.deepEqual([c.same_drawing_read_apart.length, c.same_drawing_read_apart_total, c.candidate_set_size, c.candidates_written], [50, 56, 4, 4]);
    assert.equal(many.doc.not_read_or_judged.read_apart_pairs_not_listed, 6);
    assert.equal(many.doc.status, "partial");
  });
});

test("a JPEG crop cut short and given its end marker back is damaged and partial; the whole one is not", { skip: pillowHere(ROOT) ? false : "Pillow does not import here: the tool reads no JPEG without it" }, async () => {
  await withRun(async (run, out) => {
    // The line in the top third; the rest light grey, so that the cut part holds no ink.
    await writeFile(join(run, "work/s1/line.png"), line(TRUTH));
    withPillow(String.raw`
import io, sys
from PIL import Image
d = sys.argv[1]
top = Image.open(d + "/line.png").convert("L")
im = Image.new("L", (top.width, top.height * 3), 235); im.paste(top, (0, 0))
for name, kw in (("base", {}), ("prog", {"progressive": True})):
    b = io.BytesIO(); im.save(b, "JPEG", quality=95, **kw); data = b.getvalue()
    open(d + "/" + name + ".jpg", "wb").write(data)
    open(d + "/" + name + " cut.jpg", "wb").write(data[:int(len(data) * 0.6)] + b"\xff\xd9")
    Image.open(d + "/" + name + " cut.jpg").load()
`, [join(run, "work/s1")], run);
    for (const name of ["base", "prog"]) {
      const whole = await call("glyph_strip", run, { image: `work/s1/${name}.jpg`, ocr: "none" }, { out });
      assert.equal(whole.doc.status, "complete", `${name}: ${whole.doc.status_basis}`);
      assert.equal(whole.doc.not_read_or_judged.picture_damaged, 0);
      const cut = await call("glyph_strip", run, { image: `work/s1/${name} cut.jpg`, ocr: "none" }, { out });
      assert.equal(cut.doc.status, "partial", `${name}: ${cut.doc.status_basis}`);
      assert.equal(cut.doc.not_read_or_judged.picture_damaged, 1);
      assert.match(cut.doc.picture_damaged, /coded data ends|cut|corrupt/i, name);
    }
  });
});
