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
    assert.equal(out.status, "partial", "values that were not scored are not a complete answer");
    assert.equal(out.all_values_scored, false);
    assert.match(out.status_basis, /5 of the 13 values supplied were not scored \(1 unparseable, 3 non finite, 1 out of range\)/);
    assert.doesNotMatch(out.status_basis, /every interval is in the list$/);
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

// --- D-network-F1 ----------------------------------------------------------------------------------------------------------

import { spawnSync } from "node:child_process";
import { createRng, planted } from "./pack-network-canaries.ts";
import type { Json } from "./pack-network-harness.ts";
import { startDetached } from "./pack-network-harness.ts";

test("an integer too large for a float is a number that is not epoch seconds: counted out_of_range, never an unexpected failure", async () => {
  await withCwd(async (cwd) => {
    const huge = "1" + "0".repeat(400);
    const input = `{"timestamps": [${step(8, 60).join(", ")}, ${huge}, -${huge}], "min_events": 6}`;
    const run = spawnSync("python3", [BEACON], { cwd, input, encoding: "utf8" });
    assert.equal(run.status, 0, run.stdout + run.stderr);
    const out = JSON.parse(run.stdout);
    assert.equal(out.events, 8);
    assert.equal(out.rejected.out_of_range, 2);
    assert.equal(out.median_interval_seconds, 60);
    assert.equal(out.status, "partial");
    assert.match(out.status_basis, /2 of the 10 values supplied were not scored/);
  });
});

test("the ISO 8601 forms accepted are the tool's own, the same on every Python: hour 24 and a bare fraction point are refused everywhere, a zone is taken from Z, +hh, +hh:mm and +hhmm", async () => {
  await withCwd(async (cwd) => {
    const good = ["2023-11-14T22:13:20Z", "2023-11-14 22:13:20Z", "2023-11-14T23:13:20+01:00", "2023-11-14T23:13:20+0100", "2023-11-14T23:13:20+01", "2023-11-14T22:13:20.5Z", "2023-11-14T22:13:20.123456789Z", "2023-11-14T22:13Z"];
    const bad = ["2023-11-14T24:00:00Z", "2023-11-14T22:13:20.Z", "2023-11-14T22:13:60Z", "20231114T221320Z", "2023-11-14T22:13:20,5Z", "2023-02-30T10:00:00Z", "2023-11-14T22:13:20+25:00", "2023-11-14T22:13:20 PST"];
    const base = step(8, 60);
    const ok = body(await tool(BEACON, cwd, { timestamps: [...base, ...good] }));
    assert.equal(ok.rejected.unparseable, 0, JSON.stringify(ok.first_rejected));
    assert.equal(ok.events, 8 + good.length);
    const no = body(await tool(BEACON, cwd, { timestamps: [...base, ...bad] }));
    assert.equal(no.rejected.unparseable, bad.length, JSON.stringify(no.first_rejected));
    // the same instant three ways is one distinct event
    const same = refused(await tool(BEACON, cwd, { timestamps: ["2023-11-14T22:13:20Z", "2023-11-14T23:13:20+01:00", "2023-11-14T22:13:20.000Z"], min_events: 3 }));
    assert.equal(same.distinct_events, 1);
    assert.equal(same.usable, 3);
    // a date alone and a date with minutes carry no zone: refused unless assume_utc
    assert.match(refused(await tool(BEACON, cwd, { timestamps: [...base, "2023-11-14"] })).error, /zone/);
    assert.equal(body(await tool(BEACON, cwd, { timestamps: [...base, "2023-11-14"], assume_utc: true })).naive_timestamps_assumed_utc, 1);
  });
});

test("a rejected value is never printed back: its position, reason and length only; a token in a timestamps_file is not in the answer; a label is a few plain words", async () => {
  await withCwd(async (cwd) => {
    const rng = createRng(77);
    const secrets = ["ghp", "akia", "jwt", "xoxb"].map((s) => planted(rng, s as "ghp"));
    await drop(cwd, "work/log.txt", [...step(8, 60).map(String), ...secrets.map((s) => `Authorization: Bearer ${s}`), ""].join("\n"));
    const result = await tool(BEACON, cwd, { timestamps_file: "work/log.txt" });
    const out = body(result);
    assert.equal(out.rejected.unparseable, 4);
    for (const s of secrets) assert.equal(result.stdout.includes(s), false);
    assert.deepEqual(Object.keys(out.first_rejected[0]).sort(), ["index", "length", "reason"]);
    const naive = refused(await tool(BEACON, cwd, { timestamps: [...step(8, 60), `${secrets[0]}-2023-11-14T22:13:20`, "2023-11-14T22:13:20"] }));
    assert.equal(naive.timestamps_without_zone, 1);
    assert.equal(JSON.stringify(naive).includes(secrets[0]), false);
    const window = refused(await tool(BEACON, cwd, { timestamps: step(8, 60), window_end: secrets[1] }));
    assert.equal(JSON.stringify(window).includes(secrets[1]), false);
    for (const label of secrets) {
      const err = refused(await tool(BEACON, cwd, { timestamps: step(8, 60), label }));
      assert.match(err.error, /label must be a few plain words/);
      assert.equal(JSON.stringify(err).includes(label), false);
    }
    assert.equal(body(await tool(BEACON, cwd, { timestamps: step(8, 60), label: "10.0.0.5 -> 203.0.113.7:443 (SYN observations)" })).label, "10.0.0.5 -> 203.0.113.7:443 (SYN observations)");
  });
});

test("a series out of time order is scored as the same series, with the input positions of the first of each time; sorted input takes the same path to the same answer", async () => {
  await withCwd(async (cwd) => {
    const times = step(200, 60).map((t, i) => t + (i % 7) * 0.001);
    const shuffled = [...times].sort((a, b) => ((a * 7919) % 101) - ((b * 7919) % 101));
    const a = body(await asJob(BEACON, cwd, { timestamps: times, out_dir: "out/a" }));
    const b = body(await asJob(BEACON, cwd, { timestamps: shuffled, out_dir: "out/b" }));
    for (const key of ["events", "distinct_events", "median_interval_seconds", "median_absolute_deviation_seconds", "mad_over_median", "shape", "first", "last"]) assert.deepEqual(a[key], b[key], key);
    const rowsA = (await readFile(join(cwd, "out/a/intervals.tsv"), "utf8")).trimEnd().split("\n").slice(1).map((l) => l.split("\t").slice(0, 4).join("\t"));
    const rowsB = (await readFile(join(cwd, "out/b/intervals.tsv"), "utf8")).trimEnd().split("\n").slice(1).map((l) => l.split("\t").slice(0, 4).join("\t"));
    assert.deepEqual(rowsA, rowsB);
    const fromB = (await readFile(join(cwd, "out/b/intervals.tsv"), "utf8")).trimEnd().split("\n")[1].split("\t");
    assert.equal(shuffled[Number(fromB[4])], times[0], "the first event in time is at the input position the row names");
  });
});

test("every answer carries status and status_basis; the tool's own clock ends the read with a partial answer for the values read; a stop signal prints partial JSON", async () => {
  await withCwd(async (cwd) => {
    const ok = body(await tool(BEACON, cwd, { timestamps: step(8, 60) }));
    assert.equal(ok.status, "complete");
    assert.match(ok.status_basis, /whole series/);
    assert.equal(ok.all_values_scored, true);
    assert.equal(refused(await tool(BEACON, cwd, { timestamps: [1] })).status, "failed");
    assert.match(refused(await tool(BEACON, cwd, { timestamps: step(8, 60), max_seconds: 120 })).error, /max_seconds/);
    const lines: string[] = [];
    for (let i = 0; i < 1_600_000; i++) lines.push(String(T0 + i * 3));
    await drop(cwd, "work/big.txt", lines.join("\n") + "\n");
    const began = Date.now();
    const cut = body(await tool(BEACON, cwd, { timestamps_file: "work/big.txt", max_seconds: 1 }));
    assert.ok(Date.now() - began < 45_000);
    assert.equal(cut.status, "partial");
    assert.equal(cut.series_complete, false);
    assert.ok(cut.stopped_reading_at_input_index > 0 && cut.stopped_reading_at_input_index < 1_600_000);
    assert.equal(cut.values_supplied, cut.events);
    assert.match(cut.status_basis, /max_seconds 1/);
    for (const [sig, code] of [["SIGTERM", 143], ["SIGINT", 130], ["SIGHUP", 129]] as const) {
      const run = startDetached(BEACON, cwd, { timestamps_file: "work/big.txt", max_seconds: 40 });
      await new Promise((r) => setTimeout(r, 700));
      run.signal(sig);
      assert.equal(await run.closed, code, `${sig}: ${run.stdout().slice(0, 200)}`);
      const last = JSON.parse(run.stdout());
      assert.equal(last.status, "partial");
      assert.equal(last.interrupted_by_signal, code - 128);
    }
  });
});

test("the cap on events is the one the manifest states, and a series above it is refused in JSON", async () => {
  await withCwd(async (cwd) => {
    const manifest = JSON.parse(await readFile(join(BEACON, "..", "manifest.json"), "utf8"));
    assert.match(manifest.params.timestamps_file.description, /3,000,000/);
    assert.match(manifest.description, /3,000,000-event cap/);
    await drop(cwd, "work/over.txt", "1700000000\n".repeat(3_000_001));
    const err = refused(await tool(BEACON, cwd, { timestamps_file: "work/over.txt" }));
    assert.match(err.error, /more than 3000000 events/);
  });
});

test("every rejected value is listed, however many: five inline, all in a file the answer names (positions, reasons, lengths)", async () => {
  await withCwd(async (cwd) => {
    const junk = Array.from({ length: 23 }, (_, i) => (i % 2 ? "yesterday" : "nan"));
    const out = body(await tool(BEACON, cwd, { timestamps: [...step(8, 60), ...junk] }));
    assert.equal(out.first_rejected.length, 5);
    assert.equal(out.rejected.unparseable + out.rejected.non_finite, 23);
    const all = (await readFile(join(cwd, out.all_rejected), "utf8")).trimEnd().split("\n").map((l) => JSON.parse(l));
    assert.equal(all.length, 23);
    assert.deepEqual(all.slice(0, 2).map((r: Json) => r.index), [8, 9]);
    const naive = Array.from({ length: 9 }, (_, i) => `2023-11-14T22:13:2${i}`);
    const err = refused(await tool(BEACON, cwd, { timestamps: [...step(8, 60), ...naive] }));
    assert.equal(err.timestamps_without_zone, 9);
    assert.equal(err.first_without_zone.length, 5);
    assert.equal((await readFile(join(cwd, err.all_without_zone), "utf8")).trimEnd().split("\n").length, 9);
  });
});
