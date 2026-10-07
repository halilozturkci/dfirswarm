/**
 * encrypted_survey, against fixtures the test builds itself: a "random" file is
 * node's own random bytes, a plain one is English text, a sparse file is made with
 * truncate, a trailer is a constant the test chose. The windows' offsets are those
 * the tool's manifest states (head at 0, the middle centred on half the size, the end
 * flush with it, 65536 bytes each), computed here from the file's size.
 *
 * It is a survey: it names candidates, buckets what it could not measure or read,
 * and never says how much of a tree "is encrypted".
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { chmod, mkdir, readFile, symlink, truncate, utimes, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { ROOT, runPySnippet, withCwd } from "./tool-library-harness.ts";
import { EIO_SITE, SURVEY, allRows, body, refused, tool } from "./ransomware-pack-harness.ts";
import type { Page } from "./ransomware-pack-harness.ts";

// --- encrypted_survey --------------------------------------------------------------

type SurveyRow = {
  record: string;
  file: string;
  bytes: number;
  status: string;
  reasons: string[];
  reason?: string;
  head_entropy: number | null;
  appended_extension: string | null;
  mtime_ns: number | null;
  modified_utc: string | null;
  mtime_error?: string;
  windows?: { name: string; offset: number; length: number; entropy: number }[];
  windows_overlap?: boolean;
  profiled?: boolean;
  profile_skipped?: string;
  tail_hex?: string;
  name_reasons?: string[];
  error?: string;
  rows?: number;
  complete?: string;
};
type Survey = {
  parser: string;
  root: string;
  complete: string;
  partial_reasons: string[];
  coverage: Record<string, number | Record<string, number>>;
  bytes: Record<string, number>;
  candidate_file_fraction: number | null;
  fraction_basis: string;
  candidates: SurveyRow[];
  appended_extension_observations: { extension: string; files: number }[];
  all_files_mtime_hourly: { hour_utc: string; files: number }[];
  candidate_mtime_hourly: { hour_utc: string; files: number }[];
  clock: string;
  repeated_tails: { tail_hex: string; files: number }[];
  shared_tail_suffix: { suffix_hex: string; bytes: number; across_files: number; basis: string } | null;
  low_entropy_tail_candidates: { file: string }[];
  note_name_candidates: { file: string }[];
  exclusions: { path: string; reason: string }[];
  skipped: { path: string; reason: string }[];
  census: { file: string; rows: number } | null;
  sampling: { method: string; sample: number; profiled: number; candidates_not_profiled: number };
  pages: Record<string, Page>;
  truncated: boolean;
  measures: string;
  unrecognised_parameters?: string[];
};

async function sparse(path: string, size: number): Promise<void> {
  await writeFile(path, "");
  await truncate(path, size);
}

const PLAIN = Buffer.from("The quarterly figures were reviewed on Monday and approved without change. ".repeat(2000));

test("encrypted_survey names a compressed archive and a renamed document as candidates, and has no 'not encrypted' count", async () => {
  // It published not_encrypted, proportion_encrypted and bytes_intact for what
  // it had only failed to match, and read a .zip as encrypted without a word.
  await withCwd(async (cwd) => {
    const ev = join(cwd, "work", "ev", "Users", "a");
    await mkdir(ev, { recursive: true });
    await writeFile(join(ev, "photos.zip"), randomBytes(100_000));
    await writeFile(join(ev, "report.doc.locked"), randomBytes(100_000));
    await writeFile(join(ev, "notes.txt"), PLAIN.subarray(0, 100_000));
    await writeFile(join(ev, "tiny.txt"), PLAIN.subarray(0, 3000));
    const out = await tool(SURVEY, cwd, { root: "work/ev" });
    const survey = body<Survey>(out);
    for (const old of ["not_encrypted", "proportion_encrypted", "bytes_intact", "bytes_encrypted_like", "encrypted_like", "partially_encrypted", "shared_file_suffix", "repeated_file_tails"]) {
      assert.ok(!out.stdout.includes(`"${old}"`), `${old} is still an output field`);
    }
    assert.doesNotMatch(out.stdout, /percent encrypted|proportion actually encrypted|intact/i);
    const rows = await allRows<SurveyRow>(cwd, { all_results: survey.census?.file } as Page);
    const byName = Object.fromEntries(rows.filter((r) => r.record === "file").map((r) => [r.file.split("/").pop(), r]));
    assert.equal(byName["photos.zip"].status, "candidate");
    assert.deepEqual(byName["photos.zip"].reasons, ["head_entropy_at_least_7.5"]);
    assert.equal(byName["report.doc.locked"].status, "candidate");
    assert.deepEqual([...byName["report.doc.locked"].reasons].sort(), ["appended_extension_after_known_extension", "head_entropy_at_least_7.5"]);
    assert.equal(byName["report.doc.locked"].appended_extension, ".locked");
    assert.equal(byName["notes.txt"].status, "noncandidate");
    assert.equal(byName["tiny.txt"].status, "unmeasured");
    assert.equal(byName["tiny.txt"].reason, "too_small_for_entropy");
    assert.equal(byName["tiny.txt"].head_entropy, null);
    const c = survey.coverage as Record<string, number>;
    assert.equal(c.regular_files_visited, 4);
    assert.equal(c.candidate_files, 2);
    assert.equal(c.noncandidate_files, 1);
    assert.equal(c.unmeasured_files, 1);
    assert.equal(c.read_failed_files, 0);
    assert.equal(survey.candidate_file_fraction, 0.5);
    assert.match(survey.fraction_basis, /regular files visited/);
    assert.deepEqual(survey.bytes, { candidate_bytes: 200_000, noncandidate_bytes: 100_000, unmeasured_bytes: 3000, read_failed_bytes: 0 });
    assert.equal(survey.complete, "complete");
    assert.match(survey.measures, /does not measure how much of any file was encrypted/);
  });
});

test("encrypted_survey records a file it could not read in a bucket of its own, not among the files that matched nothing", async () => {
  // A read failure fell through to "intact".
  await withCwd(async (cwd) => {
    const ev = join(cwd, "work", "ev");
    await mkdir(ev, { recursive: true });
    await mkdir(join(cwd, "pystub"), { recursive: true });
    await writeFile(join(cwd, "pystub", "sitecustomize.py"), EIO_SITE);
    await writeFile(join(ev, "unreadable.bin"), randomBytes(100_000));
    await writeFile(join(ev, "unreadable.db.crypt"), randomBytes(100_000));
    await writeFile(join(ev, "fine.txt"), PLAIN.subarray(0, 100_000));
    const survey = body<Survey>(await tool(SURVEY, cwd, { root: "work/ev" }, { PYTHONPATH: join(cwd, "pystub") }));
    const c = survey.coverage as Record<string, number>;
    assert.equal(c.read_failed_files, 2);
    assert.equal(c.noncandidate_files, 1);
    assert.equal(c.candidate_files, 0);
    assert.equal(survey.bytes.read_failed_bytes, 200_000);
    assert.equal(survey.complete, "partial");
    assert.ok(survey.partial_reasons.some((r) => /could not be read/.test(r)), survey.partial_reasons.join());
    const rows = (await allRows<SurveyRow>(cwd, { all_results: survey.census?.file } as Page)).filter((r) => r.status === "read_failed");
    assert.equal(rows.length, 2);
    assert.ok(rows.every((r) => /Input\/output error|EIO/.test(r.error ?? "")));
    // A name that matched is kept on the row of the file it could not read.
    assert.deepEqual(rows.find((r) => r.file.endsWith(".crypt"))?.name_reasons, ["appended_extension_after_known_extension"]);
  });
});

test("encrypted_survey says what it read, where, and that three windows can overlap", async () => {
  await withCwd(async (cwd) => {
    const ev = join(cwd, "work", "ev");
    await mkdir(ev, { recursive: true });
    const big = Buffer.concat([randomBytes(300_000)]);
    await writeFile(join(ev, "big.xlsx.locked"), big);
    await writeFile(join(ev, "small.xlsx.locked"), randomBytes(100_000));
    const survey = body<Survey>(await tool(SURVEY, cwd, { root: "work/ev", tail_bytes: 16 }));
    const byName = Object.fromEntries(survey.candidates.map((r) => [r.file.split("/").pop() ?? "", r]));
    // Spec: head at 0, middle centred on size/2, end flush with the end; 65536 bytes each.
    assert.deepEqual(byName["big.xlsx.locked"].windows?.map((w) => [w.name, w.offset, w.length]), [
      ["head", 0, 65536],
      ["middle", 150_000 - 32768, 65536],
      ["end", 300_000 - 65536, 65536],
    ]);
    assert.equal(byName["big.xlsx.locked"].windows_overlap, false);
    assert.equal(byName["small.xlsx.locked"].windows_overlap, true);
    assert.equal(byName["big.xlsx.locked"].tail_hex, big.subarray(-16).toString("hex"));
    assert.equal(survey.sampling.profiled, 2);
    assert.match(survey.sampling.method, /first .* candidates .* traversal order/);
  });
});

test("encrypted_survey calls a shared trailer an observation pending a reference match, never a family marker", async () => {
  await withCwd(async (cwd) => {
    const ev = join(cwd, "work", "ev");
    await mkdir(ev, { recursive: true });
    const trailer = Buffer.from("deadbeef4b455931", "hex");
    for (let i = 0; i < 2; i++) await writeFile(join(ev, `f${i}.docx.lockd`), Buffer.concat([randomBytes(80_000), trailer]));
    await writeFile(join(ev, "other.pdf.lockd"), Buffer.concat([randomBytes(80_000), randomBytes(8)]));
    const solo = body<Survey>(await tool(SURVEY, cwd, { root: "work/ev", tail_bytes: 8 }));
    assert.equal(solo.shared_tail_suffix, null, "three files do not share one trailer");
    assert.deepEqual(solo.repeated_tails.map((t) => [t.tail_hex, t.files]), [[trailer.toString("hex"), 2]]);
    await writeFile(join(ev, "other.pdf.lockd"), Buffer.concat([randomBytes(80_000), trailer]));
    const out = await tool(SURVEY, cwd, { root: "work/ev", tail_bytes: 8 });
    const survey = body<Survey>(out);
    assert.deepEqual(survey.shared_tail_suffix && [survey.shared_tail_suffix.suffix_hex, survey.shared_tail_suffix.basis, survey.shared_tail_suffix.across_files],
      [trailer.toString("hex"), "observation", 3]);
    assert.doesNotMatch(out.stdout, /family marker|better identifier/);
    assert.deepEqual(survey.repeated_tails.map((t) => t.files), [3]);
    assert.deepEqual(survey.appended_extension_observations, [{ extension: ".lockd", files: 3 }]);
    // With the default tail the random bytes before the trailer differ, and the common suffix is still the trailer.
    const wide = body<Survey>(await tool(SURVEY, cwd, { root: "work/ev" }));
    assert.equal(wide.shared_tail_suffix?.suffix_hex, trailer.toString("hex"));
    assert.deepEqual(wide.repeated_tails, []);
  });
});

test("encrypted_survey reports the trailer of two files that share eight bytes as an observation", async () => {
  await withCwd(async (cwd) => {
    const ev = join(cwd, "work", "ev");
    await mkdir(ev, { recursive: true });
    const trailer = Buffer.from("0badc0de0badf00d", "hex");
    await writeFile(join(ev, "a.pdf.crypt"), Buffer.concat([randomBytes(60_000), trailer]));
    await writeFile(join(ev, "b.pdf.crypt"), Buffer.concat([randomBytes(70_000), trailer]));
    const survey = body<Survey>(await tool(SURVEY, cwd, { root: "work/ev" }));
    assert.deepEqual(survey.shared_tail_suffix && [survey.shared_tail_suffix.suffix_hex, survey.shared_tail_suffix.bytes, survey.shared_tail_suffix.across_files, survey.shared_tail_suffix.basis],
      [trailer.toString("hex"), 8, 2, "observation"]);
  });
});

test("encrypted_survey lists a top-level dev directory it left unread, with the reason, and reads one deeper down", async () => {
  // It pruned every directory named proc, sys or dev wherever it stood, silently.
  await withCwd(async (cwd) => {
    const ev = join(cwd, "work", "ev");
    await mkdir(join(ev, "dev"), { recursive: true });
    await mkdir(join(ev, "home", "dev"), { recursive: true });
    await writeFile(join(ev, "dev", "x.docx.locked"), randomBytes(10_000));
    await writeFile(join(ev, "home", "dev", "y.docx.locked"), randomBytes(10_000));
    const survey = body<Survey>(await tool(SURVEY, cwd, { root: "work/ev" }));
    assert.equal((survey.coverage as Record<string, number>).candidate_files, 1);
    assert.equal(survey.exclusions.length, 1);
    assert.match(survey.exclusions[0].path, /ev\/dev$/);
    assert.match(survey.exclusions[0].reason, /exclude_top_level_dirs/);
    assert.equal((survey.coverage as Record<string, number>).directories_excluded, 1);
    assert.equal(survey.complete, "partial");
    assert.ok(survey.partial_reasons.some((r) => /excluded/.test(r)));
    const all = body<Survey>(await tool(SURVEY, cwd, { root: "work/ev", exclude_top_level_dirs: [] }));
    assert.equal((all.coverage as Record<string, number>).candidate_files, 2);
    assert.equal(all.exclusions.length, 0);
    assert.equal(all.complete, "complete");
  });
});

test("encrypted_survey follows no link, and lists a link and a special file as skipped", async () => {
  await withCwd(async (cwd) => {
    const ev = join(cwd, "work", "ev");
    await mkdir(join(ev, "d"), { recursive: true });
    await mkdir(join(cwd, "outside"), { recursive: true });
    await writeFile(join(cwd, "outside", "far.bin"), randomBytes(100_000));
    await symlink(join(cwd, "outside", "far.bin"), join(ev, "d", "link.docx.locked"));
    await symlink(join(cwd, "outside"), join(ev, "linked-dir"));
    const fifo = spawnSync("mkfifo", [join(ev, "d", "pipe")]);
    assert.equal(fifo.status, 0, "mkfifo");
    await writeFile(join(ev, "d", "real.txt"), PLAIN.subarray(0, 8000));
    const survey = body<Survey>(await tool(SURVEY, cwd, { root: "work/ev" }));
    const c = survey.coverage as Record<string, number>;
    assert.equal(c.regular_files_visited, 1);
    assert.equal(c.links_not_followed, 2);
    assert.equal(c.special_files_skipped, 1);
    const names = survey.skipped.map((s) => s.path.split("/").pop()).sort();
    assert.deepEqual(names, ["link.docx.locked", "linked-dir", "pipe"]);
    assert.ok(survey.skipped.every((s) => /not followed|not a regular file/.test(s.reason)));
    assert.equal(survey.complete, "partial");
  });
});

test("encrypted_survey stops reading at its byte budget, names the files it did not measure, and is partial", async () => {
  await withCwd(async (cwd) => {
    const ev = join(cwd, "work", "ev");
    await mkdir(ev, { recursive: true });
    for (const n of ["a.bin", "b.bin", "c.bin"]) await writeFile(join(ev, n), randomBytes(100_000));
    const survey = body<Survey>(await tool(SURVEY, cwd, { root: "work/ev", read_budget_bytes: 70_000 }));
    const c = survey.coverage as Record<string, number | Record<string, number>>;
    assert.equal(c.candidate_files, 1);
    assert.equal(c.unmeasured_files, 2);
    assert.deepEqual(c.unmeasured_by_reason, { read_budget_spent: 2 });
    assert.ok((c.bytes_read as number) <= 70_000);
    assert.equal(c.read_budget_bytes, 70_000);
    assert.equal(survey.complete, "partial");
    assert.ok(survey.partial_reasons.some((r) => /read budget/.test(r)));
    assert.match(survey.candidates[0].profile_skipped ?? "", /read_budget_spent/);
    assert.match(refused(await tool(SURVEY, cwd, { root: "work/ev", sample: 10 ** 9 })).error, /sample/);
    assert.match(refused(await tool(SURVEY, cwd, { root: "work/ev", tail_bytes: 10 ** 6 })).error, /tail_bytes/);
  });
});

test("encrypted_survey keeps every file in the census, and a receipt that says the file is whole", async () => {
  // The JSONL held the candidates only; the survey could not be checked against it.
  await withCwd(async (cwd) => {
    const ev = join(cwd, "work", "ev");
    await mkdir(ev, { recursive: true });
    for (let i = 0; i < 12; i++) await writeFile(join(ev, `n${String(i).padStart(2, "0")}.txt`), PLAIN.subarray(0, 8000));
    for (let i = 0; i < 5; i++) await writeFile(join(ev, `c${i}.doc.locked`), randomBytes(8000));
    const survey = body<Survey>(await tool(SURVEY, cwd, { root: "work/ev", limit: 3 }));
    assert.equal(survey.candidates.length, 3);
    assert.equal(survey.pages.candidates.truncated, true);
    assert.ok(survey.census);
    const rows = await allRows<SurveyRow>(cwd, { all_results: survey.census.file } as Page);
    const files = rows.filter((r) => r.record === "file");
    assert.equal(files.length, 17);
    assert.deepEqual(files.map((r) => r.file), [...files.map((r) => r.file)].sort(), "name order");
    const receipt = rows[rows.length - 1];
    assert.equal(receipt.record, "receipt");
    assert.equal(receipt.rows, rows.length - 1);
    assert.equal(receipt.complete, "complete");
    assert.equal(survey.census.rows, 17);
    const cands = await allRows<SurveyRow>(cwd, survey.pages.candidates);
    assert.equal(cands.length, 5);
  });
});

test("encrypted_survey keeps its mtime histograms apart, labelled as file-system times, and never dies on a time it cannot convert", async () => {
  await withCwd(async (cwd) => {
    const ev = join(cwd, "work", "ev");
    await mkdir(ev, { recursive: true });
        const noon = Date.UTC(2026, 3, 12, 2, 10, 0) / 1000;
    await writeFile(join(ev, "a.doc.locked"), randomBytes(8000));
    await utimes(join(ev, "a.doc.locked"), noon, noon);
    await writeFile(join(ev, "b.txt"), PLAIN.subarray(0, 8000));
    await utimes(join(ev, "b.txt"), noon - 86_400, noon - 86_400);
    await writeFile(join(ev, "c.txt"), PLAIN.subarray(0, 8000));
    await utimes(join(ev, "c.txt"), noon - 86_400, noon - 86_400);
    const out = await tool(SURVEY, cwd, { root: "work/ev" });
    const survey = body<Survey>(out);
    assert.deepEqual(survey.all_files_mtime_hourly.map((h) => [h.hour_utc, h.files]), [["2026-04-11T02:00:00Z", 2], ["2026-04-12T02:00:00Z", 1]]);
    assert.deepEqual(survey.candidate_mtime_hourly.map((h) => [h.hour_utc, h.files]), [["2026-04-12T02:00:00Z", 1]]);
    assert.match(survey.clock, /filesystem mtime as collected/);
    assert.match(survey.clock, /not an execution time/);
    assert.doesNotMatch(out.stdout, /brackets|to the minute|when the encryption ran/);
    // A time a datetime cannot hold is one file's problem: the row says so and the survey goes on.
    const probe = await runPySnippet(
      `import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("survey", sys.argv[1])
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
print(json.dumps([m.iso_utc(10**21), m.iso_utc(-10**20), m.iso_utc(1776046200 * 10**9 + 123456789)]))`,
      [SURVEY, cwd],
      null,
    );
    assert.equal(probe.code, 0, probe.stderr);
    assert.deepEqual(JSON.parse(probe.stdout), [null, null, "2026-04-13T02:10:00.123456Z"]);
  });
});

test("encrypted_survey reads windows past 4 GiB of a sparse file at the right offsets and does not call its zeroes plaintext", async (t) => {
  await withCwd(async (cwd) => {
    const ev = join(cwd, "work", "ev");
    await mkdir(ev, { recursive: true });
    const size = 8 * 2 ** 30;
    try {
      await sparse(join(ev, "disk.vmdk.locked"), size);
      await sparse(join(ev, "disk2.vmdk"), size);
    } catch (e) {
      return t.skip(`no sparse files here: ${String(e)}`);
    }
    const started = Date.now();
    const survey = body<Survey>(await tool(SURVEY, cwd, { root: "work/ev" }));
    assert.ok(Date.now() - started < 30_000, "it read the file, not the windows");
    const c = survey.coverage as Record<string, number>;
    assert.ok(c.bytes_read < 1 << 20, `read ${c.bytes_read} bytes`);
    const cand = survey.candidates[0];
    assert.deepEqual(cand.windows?.map((w) => [w.offset, w.length, w.entropy]), [
      [0, 65536, 0],
      [size / 2 - 32768, 65536, 0],
      [size - 65536, 65536, 0],
    ]);
    // Zeroes are a low-entropy end window of a name candidate, and the survey says that is all it is.
    assert.equal(survey.low_entropy_tail_candidates.length, 1);
    assert.equal(c.noncandidate_files, 1, "a zero-filled file is not a candidate; that says nothing about its content");
    assert.equal(survey.bytes.noncandidate_bytes, size);
  });
});

test("encrypted_survey refuses an argument that is not a JSON object, and names a parameter it does not know", async () => {
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "work", "ev"), { recursive: true });
    await writeFile(join(cwd, "work", "ev", "a.txt"), "x");
    for (const bad of [[], "work/ev", null, 3]) assert.match(refused(await tool(SURVEY, cwd, bad)).error, /JSON object/);
    const survey = body<Survey>(await tool(SURVEY, cwd, { root: "work/ev", exclude_dirs: ["x"] }));
    assert.deepEqual(survey.unrecognised_parameters, ["exclude_dirs"]);
    assert.match(refused(await tool(SURVEY, cwd, { root: "work/nope" })).error, /no such directory/);
  });
});

test("encrypted_survey lists the files whose name looks like a note, as names, and says to read them with ransom_note_scan", async () => {
  await withCwd(async (cwd) => {
    const ev = join(cwd, "work", "ev");
    await mkdir(ev, { recursive: true });
    await writeFile(join(ev, "HOW_TO_RESTORE.txt"), "x");
    await writeFile(join(ev, "budget.txt"), "x");
    const survey = body<Survey>(await tool(SURVEY, cwd, { root: "work/ev" }));
    assert.deepEqual(survey.note_name_candidates.map((n) => n.file.split("/").pop()), ["HOW_TO_RESTORE.txt"]);
  });
});

test("encrypted_survey's census and pager take a path with a lone surrogate, as a file name that is not UTF-8 gives", async () => {
  // A name from an old system reaches Python as lone surrogates (APFS refuses to create one, so the
  // components are driven directly): written as UTF-8 they raise, written as JSON escapes they do not.
  await withCwd(async (cwd) => {
    const probe = await runPySnippet(
      `import importlib.util, json, os, sys
spec = importlib.util.spec_from_file_location("survey", sys.argv[1])
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
os.chdir(sys.argv[2])
os.environ["AGENT_ID"] = "s1"
census = m.Census(["k", "census"])
census.add({"record": "file", "file": "dir/budget_\udcff\udcfe.xlsx.locked"})
census.finish({"complete": "complete"})
rows = [json.loads(l) for l in open(census.shown, encoding="utf-8")]
page = m.LosslessPage("t", ["k"], 1)
for i in range(2):
    page.add({"file": "dir/b_\udcff_%d" % i})
done = page.finish()
print(json.dumps([len(rows), rows[0]["file"] == "dir/budget_\udcff\udcfe.xlsx.locked", rows[1]["record"], done["matched"]]))`,
      [SURVEY, cwd],
      null,
    );
    assert.equal(probe.code, 0, probe.stderr);
    assert.deepEqual(JSON.parse(probe.stdout), [2, true, "receipt", 2]);
  });
});

test("encrypted_survey withholds a note-named file's identifier-shaped name everywhere it would print it, and counts it", async () => {
  // ransom_note_scan hides the name of a note that carries the victim's identifier; the survey printed it in
  // note_name_candidates and in the census, and the two tools are named together on one tree.
  await withCwd(async (cwd) => {
    const ev = join(cwd, "work", "ev");
    await mkdir(ev, { recursive: true });
    const idA = "Zq7Rk2Vx9LmT4pWn8Hc3";
    const idB = "Bd5Fn8Qs2KhW7yTa4Lc9";
    const idC = "Mx3Jp6Vc9RgN2uEb5Sk8";
    await writeFile(join(ev, `README-${idA}.txt`), "x");
    await writeFile(join(ev, `README-${idB}.txt.locked`), randomBytes(10_000));
    await writeFile(join(ev, `report-${idC}.docx.locked`), randomBytes(10_000));
    await writeFile(join(ev, "README.txt"), "x");
    const out = await tool(SURVEY, cwd, { root: "work/ev", limit: 1 });
    const survey = body<Survey & { paths_withheld: number }>(out);
    const census = JSON.stringify(await allRows<SurveyRow>(cwd, { all_results: survey.census?.file } as Page));
    const pages = JSON.stringify(await Promise.all(["candidates", "note_name_candidates"].map((k) => allRows<unknown>(cwd, survey.pages[k]).catch(() => []))));
    const printed = out.stdout + census + pages;
    for (const id of [idA, idB]) assert.ok(!printed.includes(id), `a note-named file's identifier-shaped name is printed (${id})`);
    // A file that is not named like a note is listed by its name: it is an encrypted file, and its name is evidence.
    assert.ok(printed.includes(idC));
    assert.equal(survey.paths_withheld, 2, "counted once per file whose name was withheld: the two note-named files");
    const noteRows = await allRows<{ file: string }>(cwd, survey.pages.note_name_candidates);
    assert.deepEqual(noteRows.map((n) => n.file).sort(), ["work/ev/<identifier-shaped name withheld>", "work/ev/<identifier-shaped name withheld>", "work/ev/README.txt"]);
    const manifest = JSON.parse(await readFile(join(ROOT, "packs", "ransomware-response", "tools", "encrypted_survey", "manifest.json"), "utf8")) as { description: string };
    assert.match(manifest.description, /withh[eo]ld/);
  });
});

test("encrypted_survey catches an identifier between the known extension and the new one, and explains the entropy of a .gz", async () => {
  // The rule looked at the penultimate extension only: report.docx.id[AB12CD34].locked was a miss. And a real
  // compressed file of an extension the tool did not know had no alternative explanation.
  await withCwd(async (cwd) => {
    const ev = join(cwd, "work", "ev");
    await mkdir(ev, { recursive: true });
    await writeFile(join(ev, "report.docx.id[AB12CD34].locked"), PLAIN.subarray(0, 8000));
    await writeFile(join(ev, "data.gz"), randomBytes(10_000));
    await writeFile(join(ev, "images.tar.gz"), PLAIN.subarray(0, 8000));
    await writeFile(join(ev, "notes.v2.final"), PLAIN.subarray(0, 8000));
    await writeFile(join(ev, "clip.mkv"), randomBytes(10_000));
    const survey = body<Survey>(await tool(SURVEY, cwd, { root: "work/ev" }));
    const rows = Object.fromEntries((await allRows<SurveyRow & { alternative_explanation?: string }>(cwd, { all_results: survey.census?.file } as Page)).filter((r) => r.record === "file").map((r) => [r.file.split("/").pop() ?? "", r]));
    assert.equal(rows["report.docx.id[AB12CD34].locked"].status, "candidate");
    assert.deepEqual(rows["report.docx.id[AB12CD34].locked"].reasons, ["appended_extension_after_known_extension"]);
    assert.equal(rows["report.docx.id[AB12CD34].locked"].appended_extension, ".locked");
    assert.equal(rows["data.gz"].status, "candidate");
    assert.match(rows["data.gz"].alternative_explanation ?? "", /gz/);
    assert.match(rows["clip.mkv"].alternative_explanation ?? "", /mkv/);
    assert.equal(rows["images.tar.gz"].status, "noncandidate", "a .tar.gz is a known pair, not an appended extension");
    assert.equal(rows["notes.v2.final"].status, "noncandidate");
  });
});

test("encrypted_survey counts the overflow of each histogram on its own", async () => {
  // Both histograms incremented index 0 of one list, and one line added the two together.
  await withCwd(async (cwd) => {
    const ev = join(cwd, "work", "ev");
    await mkdir(ev, { recursive: true });
    const t0 = Date.UTC(2026, 3, 12, 0, 10, 0) / 1000;
    const files: [string, Buffer, number][] = [
      ["a1.doc.locked", randomBytes(8000), 0],
      ["a2.doc.locked", randomBytes(8000), 1],
      ["a3.doc.locked", randomBytes(8000), 2],
      ["b1.txt", PLAIN.subarray(0, 8000), 3],
      ["b2.txt", PLAIN.subarray(0, 8000), 4],
    ];
    for (const [name, data, hour] of files) {
      await writeFile(join(ev, name), data);
      await utimes(join(ev, name), t0 + hour * 3600, t0 + hour * 3600);
    }
    const probe = await runPySnippet(
      `import contextlib, importlib.util, io, json, os, sys
spec = importlib.util.spec_from_file_location("survey", sys.argv[1])
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
m.HOUR_CAP = 2
os.chdir(sys.argv[2]); os.environ["AGENT_ID"] = "s1"
sys.stdin = io.StringIO(json.dumps({"root": "work/ev"}))
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    m.main()
print(buf.getvalue())`,
      [SURVEY, cwd],
      null,
    );
    assert.equal(probe.code, 0, probe.stderr);
    const survey = JSON.parse(probe.stdout) as { histogram_tables: { all_files: string; candidates: string }; all_files_mtime_hourly: unknown[]; candidate_mtime_hourly: unknown[] };
    assert.equal(survey.all_files_mtime_hourly.length, 2);
    assert.equal(survey.candidate_mtime_hourly.length, 2);
    assert.match(survey.histogram_tables.all_files, /capped: 2 distinct hours held.* 3 files not counted/);
    assert.match(survey.histogram_tables.candidates, /capped: 2 distinct hours held.* 1 files not counted/);
  });
});

test("a permissions refusal is a read failure too, where the user is not root", async (t) => {
  if (process.getuid?.() === 0) return t.skip("root reads a mode-000 file; the read failure is covered by the EIO case");
  await withCwd(async (cwd) => {
    const ev = join(cwd, "work", "ev");
    await mkdir(ev, { recursive: true });
    await writeFile(join(ev, "locked.db.crypt"), randomBytes(10_000));
    await chmod(join(ev, "locked.db.crypt"), 0o000);
    try {
      const survey = body<Survey>(await tool(SURVEY, cwd, { root: "work/ev" }));
      assert.equal((survey.coverage as Record<string, number>).read_failed_files, 1);
    } finally {
      await chmod(join(ev, "locked.db.crypt"), 0o600);
    }
  });
});
