/**
 * entropy_map against files whose entropy is known from their construction: all zeros is 0 bits per byte, every
 * byte value equally often is 8, 128 values equally often is 7 (Shannon, log2 of the number of equiprobable
 * symbols). The expected values are computed here from byte counts, never taken from the tool.
 *
 * What these cases hold: the complete profile is written to a file that is never another call's file; a rerun in
 * the same output directory leaves the first profile alone; the threshold is compared on the unrounded value;
 * what is held in memory and in the answer is bounded and the whole is on disk; the answer says how many bytes it
 * processed and whether it finished.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmod, mkdir, readFile, stat, truncate } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { ENTROPY, asJob, body, exists, filesUnder, put, refused, tool, withCwd } from "./pack-re-harness.ts";
import type { Json } from "./pack-re-harness.ts";

function shannon(counts: number[]): number {
  const total = counts.reduce((a, b) => a + b, 0);
  let h = 0;
  for (const c of counts) if (c) h -= (c / total) * Math.log2(c / total);
  return h;
}

function rows(text: string): string[][] {
  return text.trim().split("\n").slice(1).map((l) => l.split("\t"));
}

test("known distributions: zeros are 0 bits, all 256 byte values are 8, and the profile rows say so", async () => {
  await withCwd(async (cwd) => {
    const flat = Buffer.alloc(4096 * 2);
    const uniform = Buffer.alloc(4096 * 2);
    for (let i = 0; i < uniform.length; i++) uniform[i] = i & 0xff;
    await put(cwd, "work/flat.bin", flat);
    await put(cwd, "work/uniform.bin", uniform);
    const a = body(await tool(ENTROPY, cwd, { path: "work/flat.bin" }));
    const b = body(await tool(ENTROPY, cwd, { path: "work/uniform.bin" }));
    assert.equal(a.overall_entropy, 0);
    assert.ok(Math.abs(b.overall_entropy - shannon(new Array(256).fill(32))) < 1e-9);
    assert.equal(b.overall_entropy, 8);
    assert.equal(a.bytes_processed, 8192);
    assert.equal(b.windows_measured, 2);
    assert.equal(b.status, "complete");
    assert.equal(b.schema_version, 2);
    assert.equal(b.tool.name, "entropy_map");
    assert.deepEqual(b.high_entropy_runs, [{ start: 0, end: 8192, bytes: 8192, peak: 8 }]);
    const file = await readFile(join(cwd, "work", "s1", "tool-output", b.profile_file), "utf8");
    assert.equal(file.split("\n")[0], "offset\tbytes\tentropy");
    assert.deepEqual(rows(file).map((r) => [Number(r[0]), Number(r[1]), Number(r[2])]), [[0, 4096, 8], [4096, 4096, 8]]);
  });
});

test("a short final window is measured over its own bytes and says how long it was", async () => {
  await withCwd(async (cwd) => {
    const buf = Buffer.alloc(4096 + 100);
    for (let i = 0; i < 100; i++) buf[4096 + i] = i & 1;
    await put(cwd, "work/tail.bin", buf);
    const out = body(await tool(ENTROPY, cwd, { path: "work/tail.bin" }));
    assert.equal(out.windows_measured, 2);
    assert.equal(out.final_window_bytes, 100);
    const last = out.profile[1];
    assert.equal(last.bytes, 100);
    assert.ok(Math.abs(last.entropy - 1) < 1e-9, "50 zeros and 50 ones are one bit per byte");
  });
});

test("the threshold is compared on the unrounded entropy: 6.99999 bits is not at or above 7", async () => {
  await withCwd(async (cwd) => {
    // 126 byte values 32 times, one 31 times and one 33 times: 4096 bytes whose entropy is just under 7 and
    // rounds to 7.000 at three decimals.
    const counts = [...new Array(126).fill(32), 31, 33];
    const h = shannon(counts);
    assert.ok(h < 7 && Number(h.toFixed(3)) === 7, `the fixture's entropy is ${h}`);
    const buf = Buffer.alloc(4096);
    let at = 0;
    counts.forEach((c, v) => {
      for (let i = 0; i < c; i++) buf[at++] = v;
    });
    await put(cwd, "work/edge.bin", buf);
    const below = body(await tool(ENTROPY, cwd, { path: "work/edge.bin", threshold: 7 }));
    assert.equal(below.high_entropy_windows, 0, "compared after rounding, this window would count as high");
    assert.deepEqual(below.high_entropy_runs, []);
    assert.match(below.threshold_basis, /unrounded.*>=/i);
    const above = body(await tool(ENTROPY, cwd, { path: "work/edge.bin", threshold: 6.9999 }));
    assert.equal(above.high_entropy_windows, 1);
  });
});

test("two files measured in one job output directory leave two profiles, and neither overwrites the other", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "work/a.bin", Buffer.alloc(8192, 1));
    await put(cwd, "work/b.bin", Buffer.alloc(16384, 2));
    const a = body(await asJob(ENTROPY, cwd, { path: "work/a.bin" }));
    const b = body(await asJob(ENTROPY, cwd, { path: "work/b.bin" }));
    assert.notEqual(a.profile_file, b.profile_file);
    const files = (await filesUnder(join(cwd, "out"))).filter((f) => f.endsWith(".tsv"));
    assert.equal(files.length, 2, files.join(","));
    assert.equal(rows(await readFile(join(cwd, "out", a.profile_file), "utf8")).length, 2);
    assert.equal(rows(await readFile(join(cwd, "out", b.profile_file), "utf8")).length, 4);
  });
});

test("the same file measured again in the same directory keeps the first profile and names it", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "work/a.bin", Buffer.alloc(8192, 1));
    const first = body(await asJob(ENTROPY, cwd, { path: "work/a.bin", output_name: "profile.tsv" }));
    assert.equal(first.profile_file, "profile.tsv");
    const before = await readFile(join(cwd, "out", "profile.tsv"), "utf8");
    const second = body(await asJob(ENTROPY, cwd, { path: "work/a.bin", window: 1024, output_name: "profile.tsv" }));
    assert.notEqual(second.profile_file, "profile.tsv");
    assert.equal(second.earlier_file_kept, "profile.tsv");
    assert.equal(await readFile(join(cwd, "out", "profile.tsv"), "utf8"), before, "the first profile is as it was");
    assert.equal(rows(await readFile(join(cwd, "out", second.profile_file), "utf8")).length, 8);
  });
});

test("outside a job the profile is written under work/<agent>/tool-output; in a job only under $OUT", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "work/a.bin", Buffer.alloc(8192, 1));
    const call = body(await tool(ENTROPY, cwd, { path: "work/a.bin" }));
    assert.ok(await exists(join(cwd, "work", "s1", "tool-output", call.profile_file)));
    const job = body(await asJob(ENTROPY, cwd, { path: "work/a.bin" }));
    assert.ok(await exists(join(cwd, "out", job.profile_file)));
    assert.equal((await filesUnder(join(cwd, "work", "s1", "tool-output"))).length, 1, "the job wrote nothing outside $OUT");
  });
});

test("the answer holds a preview of max_windows rows and the whole profile is on disk", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "work/many.bin", Buffer.alloc(64 * 600, 3));
    const out = body(await tool(ENTROPY, cwd, { path: "work/many.bin", window: 64, max_windows: 100 }));
    assert.equal(out.windows_measured, 600);
    assert.equal(out.profile.length, 100);
    assert.equal(out.inline_profile_complete, false);
    assert.equal(out.profile_complete, true);
    assert.equal(rows(await readFile(join(cwd, "work", "s1", "tool-output", out.profile_file), "utf8")).length, 600);
  });
});

test("runs are bounded in memory and in the answer: past 1,000 runs the whole list is a file", async () => {
  await withCwd(async (cwd) => {
    // Windows of 64 bytes: 64 distinct values (6 bits) then 64 zeros (0 bits), 1,500 times over.
    const hi = Buffer.from(Array.from({ length: 64 }, (_, i) => i));
    const lo = Buffer.alloc(64);
    const buf = Buffer.concat(Array.from({ length: 1500 }, () => Buffer.concat([hi, lo])));
    await put(cwd, "work/alt.bin", buf);
    const out = body(await tool(ENTROPY, cwd, { path: "work/alt.bin", window: 64, threshold: 5.9, max_windows: 10 }));
    assert.equal(out.high_entropy_run_count, 1500);
    assert.equal(out.high_entropy_runs.length, 1000);
    assert.ok(out.runs_file);
    const runs = rows(await readFile(join(cwd, "work", "s1", "tool-output", out.runs_file), "utf8"));
    assert.equal(runs.length, 1500);
    assert.deepEqual(runs[0]!.map(Number), [0, 64, 64, 6]);
    assert.equal(out.status, "complete");
  });
});

test("window and arguments are bounded and typed", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "work/a.bin", Buffer.alloc(100, 1));
    for (const args of [{ window: 63 }, { window: 1 << 27 }, { window: 100.5 }, { threshold: 0 }, { threshold: 9 }, { max_windows: 0 }, { output_name: "../x" }, { output_name: "a/b" }, { output_name: ".hidden" }]) {
      const out = refused(await tool(ENTROPY, cwd, { path: "work/a.bin", ...args }));
      assert.ok(out.error, JSON.stringify(args));
    }
    await put(cwd, "work/empty.bin", Buffer.alloc(0));
    assert.match(refused(await tool(ENTROPY, cwd, { path: "work/empty.bin" })).error, /empty/);
  });
});

test("a profile that cannot be written is a JSON error and no clean answer", { skip: process.getuid?.() === 0 }, async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "work/a.bin", Buffer.alloc(8192, 1));
    await put(cwd, "work/s1/keep", "x");
    await chmod(join(cwd, "work", "s1"), 0o500);
    try {
      const out = refused(await tool(ENTROPY, cwd, { path: "work/a.bin" }));
      assert.match(out.error, /profile|write|create/i);
    } finally {
      await chmod(join(cwd, "work", "s1"), 0o700);
    }
  });
});

test("the note says what entropy is and does not call a high value packing", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "work/a.bin", Buffer.alloc(8192, 1));
    const out = body(await tool(ENTROPY, cwd, { path: "work/a.bin" }));
    assert.doesNotMatch(out.note, /is packed|A section at/);
    assert.match(out.note, /measurement|feature/i);
    assert.ok((await stat(join(cwd, "work", "s1", "tool-output", out.profile_file))).size > 0);
  });
});

// --- review round ---------------------------------------------------------------------------------------------------------

test("a file that cannot be read is a failure that creates no profile file", { skip: process.getuid?.() === 0 }, async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "work/secret.bin", Buffer.alloc(8192, 1), 0o000);
    const out = refused(await tool(ENTROPY, cwd, { path: "work/secret.bin" }));
    assert.equal(out.status, "failed");
    assert.match(out.error, /could not be opened|Permission/i);
    assert.deepEqual(await filesUnder(join(cwd, "work", "s1")), [], "no header-only profile was left behind");
  });
});

test("the tool has its own clock: max_seconds ends a pass over a file too big for it, and the answer says how far it got", async () => {
  await withCwd(async (cwd) => {
    const path = await put(cwd, "work/big.bin", Buffer.alloc(16));
    await truncate(path, 4 * 2 ** 30); // 4 GiB, a hole: the pass takes minutes
    const started = Date.now();
    const out = body(await tool(ENTROPY, cwd, { path: "work/big.bin", max_seconds: 1 }));
    assert.ok((Date.now() - started) / 1000 < 30);
    assert.equal(out.status, "partial");
    assert.equal(out.profile_complete, false);
    assert.ok(out.bytes_processed >= 0 && out.bytes_processed < out.bytes, `${out.bytes_processed} of ${out.bytes}`);
    assert.ok(out.problems.some((p: string) => /max_seconds|time/i.test(p)), JSON.stringify(out.problems));
    assert.equal(out.bytes_processed % 4096, 0);
    const rowsInFile = rows(await readFile(join(cwd, "work", "s1", "tool-output", out.profile_file), "utf8")).length;
    assert.equal(rowsInFile, out.windows_measured, "the profile holds every window measured before the stop");
    for (const bad of [0, 281, 1.5, "9"]) assert.match(refused(await tool(ENTROPY, cwd, { path: "work/big.bin", max_seconds: bad })).error, /max_seconds/);
  });
});

test("a directory or a pipe is not 'no such file'", async () => {
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "work", "d"), { recursive: true });
    assert.match(refused(await tool(ENTROPY, cwd, { path: "work/d" })).error, /not a regular file \(a directory\)/);
    assert.match(refused(await tool(ENTROPY, cwd, { path: "work/none" })).error, /no such file/);
  });
});

// --- bounds: a profile that is never cut, files that are private, a clock inside a window ---------------------------------------------

test("a window that would give the profile more rows than the cap is refused before anything is read, with the cap and the smallest window that fits named", async () => {
  await withCwd(async (cwd) => {
    const path = await put(cwd, "work/sparse.bin", Buffer.alloc(16));
    await truncate(path, 2 ** 30); // 1 GiB, a hole
    const out = refused(await tool(ENTROPY, cwd, { path: "work/sparse.bin", window: 64 }));
    assert.equal(out.status, "failed");
    assert.match(out.error, /16777216 rows, more than the 4000000 the profile file may hold: nothing was read/);
    assert.equal(out.max_profile_rows, 4_000_000);
    assert.equal(out.rows_needed, 2 ** 24);
    const fitting = Math.ceil(2 ** 30 / 4_000_000);
    assert.equal(out.smallest_window_that_fits, fitting);
    assert.match(out.error, new RegExp(`smallest window that fits is ${fitting} bytes`));
    assert.equal(typeof out.status_basis, "string");
    assert.deepEqual(await filesUnder(join(cwd, "work", "s1")), [], "nothing was created");
    // The window it names is accepted (the pass is cut short by the clock here only to keep the case quick): one byte less is refused.
    const accepted = body(await tool(ENTROPY, cwd, { path: "work/sparse.bin", window: fitting, max_seconds: 1 }));
    assert.equal(accepted.window, fitting);
    assert.notEqual(accepted.status, "failed");
    const rowsNeeded = refused(await tool(ENTROPY, cwd, { path: "work/sparse.bin", window: fitting - 1 }));
    assert.ok(rowsNeeded.rows_needed > 4_000_000);
  });
});

test("the profile and the runs file are created mode 0600 under a umask of 022, and a rerun leaves the first alone", async () => {
  await withCwd(async (cwd) => {
    // 2,050 windows of 256 bytes, alternately every byte value (8 bits) and zeros: 1,025 high runs, so the runs go to a file too
    const hi = Buffer.from(Array.from({ length: 256 }, (_, i) => i));
    const buf = Buffer.concat(Array.from({ length: 1025 }, () => Buffer.concat([hi, Buffer.alloc(256)])));
    await put(cwd, "work/alt.bin", buf);
    const old = process.umask(0o022);
    try {
      const out = body(await tool(ENTROPY, cwd, { path: "work/alt.bin", window: 256 }));
      assert.equal(out.high_entropy_run_count, 1025);
      assert.ok(out.runs_file);
      for (const name of [out.profile_file, out.runs_file]) {
        assert.equal(((await stat(join(cwd, "work", "s1", "tool-output", name))).mode & 0o777).toString(8), "600", name);
      }
      const again = body(await tool(ENTROPY, cwd, { path: "work/alt.bin", window: 256 }));
      assert.notEqual(again.profile_file, out.profile_file);
      assert.equal(((await stat(join(cwd, "work", "s1", "tool-output", again.profile_file))).mode & 0o777).toString(8), "600");
      assert.equal(rows(await readFile(join(cwd, "work", "s1", "tool-output", out.profile_file), "utf8")).length, 2050);
    } finally {
      process.umask(old);
    }
  });
});

test("max_windows is bounded at 10,000: one more is refused, the ceiling is accepted, and the rest of the profile is in the file", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "work/many.bin", Buffer.alloc(64 * 12_000, 3));
    assert.match(refused(await tool(ENTROPY, cwd, { path: "work/many.bin", window: 64, max_windows: 10_001 })).error, /max_windows must be an integer from 1 to 10000/);
    const out = body(await tool(ENTROPY, cwd, { path: "work/many.bin", window: 64, max_windows: 10_000 }));
    assert.equal(out.profile.length, 10_000);
    assert.equal(out.windows_measured, 12_000);
    assert.equal(out.inline_profile_complete, false);
    assert.equal(rows(await readFile(join(cwd, "work", "s1", "tool-output", out.profile_file), "utf8")).length, 12_000);
  });
});

const CLOCK = [
  "import importlib.util, io, json, sys, time",
  "spec = importlib.util.spec_from_file_location('tool_under_test', sys.argv[1])",
  "m = importlib.util.module_from_spec(spec)",
  "spec.loader.exec_module(m)",
  // a clock that moves 0.3 s at every look: the deadline (1 s) falls inside the first window of four pieces
  "ticks = [0.0]",
  "def fake():",
  "    ticks[0] += 0.3",
  "    return ticks[0]",
  "time.monotonic = fake",
  "sys.stdin = io.StringIO(json.dumps({'path': sys.argv[2], 'window': 4 << 20, 'max_seconds': 1}))",
  "try:",
  "    m.main()",
  "except SystemExit:",
  "    pass",
].join("\n");

test("the clock is looked at inside a window: a window the clock stops is not measured, and the answer names the last whole one", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "work/w.bin", Buffer.alloc(16 << 20, 5));
    const r = spawnSync("python3", ["-c", CLOCK, ENTROPY, "work/w.bin"], { cwd, encoding: "utf8", env: { ...process.env, AGENT_ID: "s1" } });
    assert.doesNotMatch(r.stderr, /Traceback/, r.stderr);
    const out = JSON.parse(r.stdout) as Json;
    assert.ok(out.problems.some((p: string) => /inside the window at offset \d+, after \d+ of its 4194304 bytes: that window is not measured/.test(p)), JSON.stringify(out.problems));
    assert.equal(out.bytes_processed, out.windows_measured * (4 << 20), "the profile holds whole windows only");
    assert.equal(out.status, out.bytes_processed ? "partial" : "failed");
    assert.match(out.status_basis, /inside the window/);
    const file = await readFile(join(cwd, "work", "s1", "tool-output", out.profile_file), "utf8");
    assert.equal(rows(file).length, out.windows_measured);
  });
});

test("a 64 MiB window under max_seconds 1 ends within seconds of the limit, on whole windows", async () => {
  await withCwd(async (cwd) => {
    const path = await put(cwd, "work/big.bin", Buffer.alloc(16));
    await truncate(path, 2 ** 30);
    const started = Date.now();
    // counting 64 MiB takes longer than a second on most machines, so the first window may be the one the clock stops (failed: nothing whole
    // was measured, a non-zero exit) or a later one (partial); either way the profile holds whole windows only and the call ends near the limit
    const ran = await tool(ENTROPY, cwd, { path: "work/big.bin", window: 64 << 20, max_seconds: 1 });
    const out = JSON.parse(ran.stdout) as Json;
    assert.doesNotMatch(ran.stderr, /Traceback/);
    assert.ok(Date.now() - started < 30_000, `${Date.now() - started} ms`);
    assert.ok(out.status === "partial" || out.status === "failed", out.status);
    assert.equal(out.bytes_processed % (64 << 20), 0);
    assert.ok(out.bytes_processed < out.bytes);
    assert.match(out.status_basis, /max_seconds/);
    assert.equal(rows(await readFile(join(cwd, "work", "s1", "tool-output", out.profile_file), "utf8")).length, out.windows_measured);
  });
});

test("every answer and refusal carries a one-sentence status_basis: complete, partial and each kind of failure", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "work/a.bin", Buffer.alloc(8192, 1));
    const complete = body(await tool(ENTROPY, cwd, { path: "work/a.bin" }));
    assert.equal(complete.status, "complete");
    assert.match(complete.status_basis, /every window of the file was measured/);
    await put(cwd, "work/empty.bin", Buffer.alloc(0));
    await mkdir(join(cwd, "work", "d"), { recursive: true });
    for (const args of [{ path: "work/none" }, { path: "work/d" }, { path: "work/empty.bin" }, { path: "work/a.bin", window: 1 }, { path: "work/a.bin", threshold: 0 }, { path: "work/a.bin", max_windows: 10_001 },
      { path: "work/a.bin", max_seconds: 0 }, { path: "work/a.bin", output_name: "../x" }, {}, { path: 5 }]) {
      const out = refused(await tool(ENTROPY, cwd, args));
      assert.equal(out.status, "failed", JSON.stringify(args));
      assert.ok(typeof out.status_basis === "string" && out.status_basis.length > 0 && !out.status_basis.includes("\n"), JSON.stringify(args));
    }
    const big = await put(cwd, "work/big.bin", Buffer.alloc(16));
    await truncate(big, 2 ** 31);
    const partial = body(await tool(ENTROPY, cwd, { path: "work/big.bin", max_seconds: 1 }));
    assert.equal(partial.status, "partial");
    assert.match(partial.status_basis, /max_seconds/);
  });
});
