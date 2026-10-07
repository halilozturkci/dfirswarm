/**
 * network-forensics: beacon_score measures how tightly a series of event times clusters around its median
 * interval, and nothing more. A long last gap is an interval that ended in another event, not a pattern that
 * stopped; "stopped" needs an observation window and a statement that the sensor kept recording; a ratio of
 * events to the count a constant schedule would give is a density, not a completeness; a time with no zone
 * is refused rather than made UTC; a time that is not a finite number is counted, never scored; the whole
 * interval list is kept.
 *
 * The series are built here from arithmetic (a start, a step, an offset), not from another tool's output.
 */
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { BEACON, asJob, body, drop, filesUnder, refused, tool, withCwd } from "./pack-network-harness.ts";

const T0 = 1_771_070_000;
const step = (n: number, every: number, from = T0): number[] => Array.from({ length: n }, (_, i) => from + i * every);

test("a last interval five times the median is a long final gap, and says nothing about a cessation without a declared window", async () => {
  await withCwd(async (cwd) => {
    const times = [...step(8, 60), T0 + 7 * 60 + 300]; // seven 60 s intervals, then 300 s
    const out = body(await tool(BEACON, cwd, { timestamps: times, label: "c2-looking" }));
    assert.equal(out.stopped, undefined, "the old name asserted what was never observed");
    assert.equal(out.long_final_gap.present, true);
    assert.equal(out.long_final_gap.final_interval_seconds, 300);
    assert.equal(out.long_final_gap.ratio, 5);
    assert.equal(out.cessation.assessed, false);
    assert.match(out.cessation.reason_not_assessed, /window_end/);
    assert.doesNotMatch(JSON.stringify(out), /this pattern stopped|moved to another channel/);
  });
});

test("with the window ending at the last event nothing is said to have stopped; with a longer declared window and the sensor confirmed, the silence is stated and bounded", async () => {
  await withCwd(async (cwd) => {
    const times = [...step(8, 60), T0 + 7 * 60 + 300];
    const last = times[times.length - 1];
    const same = body(await tool(BEACON, cwd, { timestamps: times, window_end: last, sensor_coverage_confirmed: true }));
    assert.equal(same.cessation.assessed, true);
    assert.equal(same.cessation.silent_after_last_event_seconds, 0);
    assert.equal(same.cessation.silent_over_4x_median, false);
    assert.doesNotMatch(same.cessation.statement, /stopped/);
    // A declared end ten medians after the last event, the sensor recording throughout.
    const later = body(await tool(BEACON, cwd, { timestamps: times, window_end: last + 600, sensor_coverage_confirmed: true }));
    assert.equal(later.cessation.silent_over_4x_median, true);
    assert.match(later.cessation.statement, /no event in this series/i);
    assert.match(later.cessation.statement, /other (series|destinations|protocols)/i);
    // A window without the sensor statement is not enough to say anything.
    const unconfirmed = body(await tool(BEACON, cwd, { timestamps: times, window_end: last + 600 }));
    assert.equal(unconfirmed.cessation.assessed, false);
    assert.match(unconfirmed.cessation.reason_not_assessed, /sensor/);
    // A window that ends before the last event is a mistake, not a series.
    assert.match(refused(await tool(BEACON, cwd, { timestamps: times, window_end: last - 1, sensor_coverage_confirmed: true })).error, /window_end/);
  });
});

test("a time written without a zone is refused unless the caller says to read it as UTC, and then every such value is counted", async () => {
  await withCwd(async (cwd) => {
    const naive = step(8, 60).map((t) => new Date(t * 1000).toISOString().replace("Z", "").replace(/\.\d+$/, ""));
    const err = refused(await tool(BEACON, cwd, { timestamps: naive }));
    assert.match(err.error, /zone/);
    assert.equal(err.timestamps_without_zone, 8);
    const ok = body(await tool(BEACON, cwd, { timestamps: naive, assume_utc: true }));
    assert.equal(ok.naive_timestamps_assumed_utc, 8);
    assert.equal(ok.median_interval_seconds, 60);
    // Offsets are read as offsets: wall-clock text at +03:00 that denotes the same instants gives the same series.
    const offset = step(8, 60).map((t) => new Date((t + 3 * 3600) * 1000).toISOString().replace(/\.\d+Z$/, "+03:00"));
    const shifted = body(await tool(BEACON, cwd, { timestamps: offset }));
    assert.equal(shifted.naive_timestamps_assumed_utc, 0);
    assert.equal(shifted.first, new Date(T0 * 1000).toISOString().replace(".000Z", ".000000Z"));
    assert.equal(shifted.median_interval_seconds, 60);
  });
});

test("a value that is not a finite number of seconds is counted and named, never scored", async () => {
  await withCwd(async (cwd) => {
    const out = body(await tool(BEACON, cwd, { timestamps: [...step(8, 60), "nan", "inf", "-Infinity", "yesterday", 99_999_999_999_999] }));
    assert.equal(out.events, 8);
    assert.equal(out.rejected.non_finite, 3);
    assert.equal(out.rejected.unparseable, 1);
    assert.equal(out.rejected.out_of_range, 1);
    assert.ok(out.first_rejected.length >= 3);
    assert.equal(out.median_interval_seconds, 60);
  });
});

test("duplicate times are counted apart from distinct events, and the minimum applies to the distinct ones", async () => {
  await withCwd(async (cwd) => {
    const dupes = [T0, T0, T0, T0 + 60, T0 + 60, T0 + 120, T0 + 180, T0 + 240, T0 + 300];
    const out = body(await tool(BEACON, cwd, { timestamps: dupes, min_events: 5 }));
    assert.equal(out.events, 9);
    assert.equal(out.distinct_events, 6);
    assert.equal(out.duplicate_timestamps, 3);
    assert.equal(out.zero_intervals, undefined, "a field that always equalled duplicate_timestamps is gone");
    const refusedFew = refused(await tool(BEACON, cwd, { timestamps: [T0, T0, T0, T0, T0, T0, T0 + 60, T0 + 120], min_events: 6 }));
    assert.match(refusedFew.error, /distinct/);
    assert.equal(refusedFew.distinct_events, 3);
  });
});

test("the ratio is called what it is, and the old causal explanation is gone", async () => {
  await withCwd(async (cwd) => {
    // Six events in a 600 s span with a 60 s median leave three of the ten a constant schedule would give.
    const out = body(await tool(BEACON, cwd, { timestamps: [T0, T0 + 60, T0 + 120, T0 + 300, T0 + 360, T0 + 600] }));
    assert.equal(out.completeness, undefined);
    assert.ok(out.event_density_ratio < 1);
    assert.doesNotMatch(JSON.stringify(out), /capture rolled|connections are missing/);
    assert.match(out.note, /not a verdict|heuristic/i);
    // A score names a dispersion, not an implant.
    assert.ok(["tight_cluster", "clustered", "loose_cluster", "dispersed", "unmeasurable"].includes(out.shape));
    assert.doesNotMatch(out.shape, /beacon|timer/);
  });
});

test("ten thousand events: every interval is kept, in a file the answer names, and the inline part is bounded", async () => {
  await withCwd(async (cwd) => {
    const times = step(10_000, 30);
    const path = await drop(cwd, "work/series.txt", ["# one time per line, epoch seconds", ...times.map(String), ""].join("\n"));
    const out = body(await tool(BEACON, cwd, { timestamps_file: path }));
    assert.equal(out.events, 10_000);
    assert.equal(out.intervals.count, 9_999);
    assert.ok(out.intervals_inline.length <= 40);
    assert.equal(out.intervals_page.truncated, true);
    const whole = (await readFile(join(cwd, out.intervals_page.all_results), "utf8")).trimEnd().split("\n").map((l) => JSON.parse(l));
    assert.equal(whole.length, 9_999);
    assert.ok(whole.every((r) => r.seconds === 30));
    // And as a job, into $OUT.
    const job = body(await asJob(BEACON, cwd, { timestamps_file: path, out_dir: "out/beacon" }));
    assert.match(job.intervals_page.all_results, /^store\/jobs\/j\d+\/out\/tool-output\//);
    assert.ok((await filesUnder(join(cwd, "out/beacon"))).includes("intervals.tsv"));
    const tsv = (await readFile(join(cwd, "out/beacon/intervals.tsv"), "utf8")).trimEnd().split("\n");
    assert.equal(tsv.length, 10_000, "a header and 9,999 intervals");
  });
});

test("a timestamps file that cannot be read, or a series given twice, is refused in JSON", async () => {
  await withCwd(async (cwd) => {
    assert.match(refused(await tool(BEACON, cwd, { timestamps_file: "work/none.txt" })).error, /timestamps_file/);
    assert.match(refused(await tool(BEACON, cwd, { timestamps: [1, 2, 3, 4, 5, 6], timestamps_file: "work/x" })).error, /one of/);
    assert.match(refused(await tool(BEACON, cwd, {})).error, /timestamps/);
    assert.match(refused(await asJob(BEACON, cwd, { timestamps: step(8, 60), out_dir: "work/elsewhere" })).error, /\$OUT/);
  });
});

test("each interval names the positions in the supplied series it comes from; a line too long to be a time is counted and not held; in a job the interval file is cited at its sealed place", async () => {
  await withCwd(async (cwd) => {
    // out of order on purpose: the position is the one in the input, not in the sorted series
    const times = [T0 + 300, T0, T0 + 60, T0 + 60, T0 + 120, T0 + 180, T0 + 240];
    const out = body(await asJob(BEACON, cwd, { timestamps: times, out_dir: "out/iv" }));
    assert.deepEqual(out.intervals_inline.length, 5);
    assert.match(out.intervals_tsv, /^store\/jobs\/j\d+\/out\/iv\/intervals\.tsv$/, "the page already named a sealed path; the table now does too");
    const lines = (await readFile(join(cwd, "out/iv/intervals.tsv"), "utf8")).trimEnd().split("\n");
    assert.equal(lines[0], "index\tfrom_utc\tto_utc\tseconds\tfrom_input_index\tto_input_index");
    assert.deepEqual(lines[1].split("\t").slice(3), ["60.0", "1", "2"], "T0 is input 1, the first T0+60 is input 2 (the repeat, input 3, is not a second event)");
    assert.deepEqual(lines[5].split("\t").slice(3), ["60.0", "6", "0"], "the last event in time is the first one in the input");
    assert.match(out.input_index_note, /positions in the series you supplied/);
    // a file with one giant line
    const huge = "9".repeat(5_000_000);
    await drop(cwd, "work/times.txt", [...step(6, 60), "", `# a comment`, huge].map(String).join("\n") + "\n");
    const run = await tool(BEACON, cwd, { timestamps_file: "work/times.txt", min_events: 3 });
    const file = JSON.parse(run.stdout);
    assert.equal(file.lines_over_limit, 1);
    assert.equal(file.rejected.unparseable, 1);
    assert.equal(file.distinct_events, 6);
  });
});
