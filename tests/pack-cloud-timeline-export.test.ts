/**
 * cloud_timeline_export: an externally sorted timeline JSONL and a spreadsheet-safe CSV from normalised streams. Rows are built here from the
 * canonical field names (the ones cloud_normalise writes), never from a tool's output.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createWriteStream } from "node:fs";
import { mkdir, readFile, readdir, stat } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { TOOLS, asJob, body, exists, put, refused, spawnTool, tool, withDir } from "./cloud-pack-harness.ts";
import type { Json, Run } from "./cloud-pack-harness.ts";
import { JWT, leaked, rnd } from "./cloud-pack-secrets.ts";
import { peakRssPrelude } from "./peak-rss.ts";

const TL = join(TOOLS, "cloud_timeline_export", "run.py");
const DIR = "work/s1/cloud-timeline";
const PW = "Hu7!kQ2zRw9x";

const row = (id: string, time_utc: string | undefined, extra: Json = {}): Json => ({ provider: "gcp", adapter: "gcp_audit", parser: "cloud_normalise/1", event_id: id, ...(time_utc ? { time_utc, time_raw: time_utc, time_status: "zoned" } : {}), principal: "a@example.org", action: "m", outcome: "success", ...extra });
const jsonl = (rows: Json[]): string => rows.map((r) => JSON.stringify(r)).join("\n") + "\n";
const lines = async (cwd: string, name: string, dir = DIR): Promise<Json[]> => (await readFile(join(cwd, dir, name), "utf8")).split("\n").filter(Boolean).map((l) => JSON.parse(l));

/** RFC 4180 reading of a CSV text (quotes, doubled quotes, commas and line breaks inside a quoted cell), after the byte order mark. */
function csvRows(text: string): string[][] {
  assert.equal(text.charCodeAt(0), 0xfeff, "UTF-8 with a byte order mark");
  const out: string[][] = [];
  let cell = "";
  let rowCells: string[] = [];
  let q = false;
  for (let i = 1; i < text.length; i++) {
    const c = text[i];
    if (q) {
      if (c === '"') {
        if (text[i + 1] === '"') { cell += '"'; i++; } else q = false;
      } else cell += c;
    } else if (c === '"') q = true;
    else if (c === ",") { rowCells.push(cell); cell = ""; } else if (c === "\r" && text[i + 1] === "\n") { rowCells.push(cell); out.push(rowCells); rowCells = []; cell = ""; i++; } else cell += c;
  }
  if (cell || rowCells.length) { rowCells.push(cell); out.push(rowCells); }
  return out;
}

test("rows come out in UTC order with ties broken by source order, across two files and many runs and a merge pass; nothing is lost or removed", async () => {
  await withDir(async (cwd) => {
    const times = ["2026-02-14T09:00:05Z", "2026-02-14T09:00:01Z", "2026-02-14T09:00:03Z", "2026-02-14T09:00:01Z", "2026-02-14T09:00:05Z", "2026-02-14T09:00:02Z"];
    const a: Json[] = [];
    const b: Json[] = [];
    for (let i = 0; i < 400; i++) a.push(row(`a${i}`, times[i % times.length]));
    for (let i = 0; i < 300; i++) b.push(row(`b${i}`, times[(i + 2) % times.length]));
    b.push(b[0]);                      // a repeated row stays repeated
    await put(cwd, "work/ev/a.jsonl", jsonl(a));
    await put(cwd, "work/ev/b.jsonl", jsonl(b));
    const out = body(await tool(TL, cwd, { paths: ["work/ev/a.jsonl", "work/ev/b.jsonl"], chunk_rows: 2 }));
    assert.equal(out.status, "complete", out.status_basis);
    assert.equal(out.coverage.rows_dated, 701);
    assert.ok(out.coverage.runs_written >= 300, `runs ${out.coverage.runs_written}`);
    assert.ok(out.coverage.merge_passes >= 1, "more than 64 runs take an intermediate pass");
    const all = [...a.map((r, i) => ({ r, order: i })), ...b.map((r, i) => ({ r, order: a.length + i }))];
    const sorted = all.sort((x, y) => (x.r.time_utc < y.r.time_utc ? -1 : x.r.time_utc > y.r.time_utc ? 1 : x.order - y.order));
    const want = sorted.map((x) => x.r.event_id);
    const got = await lines(cwd, "timeline.jsonl");
    assert.deepEqual(got.map((r) => r.event_id), want);
    assert.deepEqual(got.map((r) => r.timeline.seq), sorted.map((x) => x.order + 1), "sequence numbers are the source order");
    assert.equal(got.filter((r) => r.event_id === "b0").length, 2, "the repeated row is repeated");
    assert.deepEqual((await readdir(join(cwd, DIR))).sort(), ["coverage.json", "rejected.jsonl", "timeline-unknown-time.csv", "timeline-unknown-time.jsonl", "timeline.csv", "timeline.jsonl"]);
    const first = got[0];
    assert.equal(first.timeline.input_file, "work/ev/a.jsonl");
    assert.ok(first.timeline.input_record >= 1 && first.timeline.input_line >= 1);
    assert.equal(first.timeline.time_basis, "time_utc");
    assert.equal(first.principal, "a@example.org", "the input row is unchanged");
    const csv = csvRows(await readFile(join(cwd, DIR, "timeline.csv"), "utf8"));
    assert.equal(csv.length, 702);
    assert.deepEqual(csv.slice(1).map((c) => c[12]), want, "the CSV has the same rows in the same order");
  });
});

test("fractions of a second sort as numbers, not as text: .5 before .50001 before .6, and a time without a fraction before both", async () => {
  await withDir(async (cwd) => {
    const t = ["2026-02-14T09:00:00.6Z", "2026-02-14T09:00:00.50001Z", "2026-02-14T09:00:00Z", "2026-02-14T09:00:00.5Z", "2026-02-14T09:00:00.123456789Z", "2026-02-14T08:59:59.999999999Z"];
    await put(cwd, "work/ev/a.jsonl", jsonl(t.map((x, i) => row(`f${i}`, x))));
    body(await tool(TL, cwd, { path: "work/ev/a.jsonl" }));
    assert.deepEqual((await lines(cwd, "timeline.jsonl")).map((r) => r.event_id), ["f5", "f2", "f4", "f3", "f1", "f0"]);
    assert.deepEqual((await lines(cwd, "timeline.jsonl")).map((r) => r.timeline.sort_time_utc), ["2026-02-14T08:59:59.999999999Z", "2026-02-14T09:00:00Z", "2026-02-14T09:00:00.123456789Z", "2026-02-14T09:00:00.5Z", "2026-02-14T09:00:00.50001Z", "2026-02-14T09:00:00.6Z"]);
  });
});

test("mixed zones are ordered by their instants; a time with no zone, an ambiguous one and a row with no time go to the unknown-time section, in source order, never at the epoch", async () => {
  await withDir(async (cwd) => {
    await put(cwd, "work/ev/a.jsonl", jsonl([
      row("z1", undefined, { time_raw: "2026-02-14T09:00:00+02:00" }),            // 07:00Z
      row("z2", undefined, { time_raw: "2026-02-14T03:00:00-05:00" }),            // 08:00Z
      row("z3", "2026-02-14T07:30:00Z"),
      row("u1", undefined, { time_raw: "2026-02-14T09:00:00" }),
      row("u2", undefined),
      row("u3", undefined, { time_raw: "03/04/2026 10:00:00" }),
      row("u4", undefined, { time_raw: "not a time" }),
      row("u5", "0000-00-00T00:00:00Z"),
      row("u6", undefined, { time_raw: 1771059600 }),
    ]));
    const out = body(await tool(TL, cwd, { path: "work/ev/a.jsonl" }));
    assert.equal(out.coverage.rows_dated, 3);
    assert.equal(out.coverage.rows_unknown_time, 6);
    assert.deepEqual((await lines(cwd, "timeline.jsonl")).map((r) => r.event_id), ["z1", "z3", "z2"]);
    assert.deepEqual((await lines(cwd, "timeline.jsonl")).map((r) => r.timeline.time_basis), ["time_raw (decoded)", "time_utc", "time_raw (decoded)"]);
    const unknown = await lines(cwd, "timeline-unknown-time.jsonl");
    assert.deepEqual(unknown.map((r) => r.event_id), ["u1", "u2", "u3", "u4", "u5", "u6"], "source order");
    assert.ok(unknown.every((r) => r.timeline.section === "unknown_time" && r.timeline.sort_time_utc === null && r.timeline.unknown_time_reason));
    assert.match(unknown[0].timeline.unknown_time_reason, /no_zone/);
    assert.match(unknown[1].timeline.unknown_time_reason, /no time_utc and no time_raw/);
    assert.match(unknown[2].timeline.unknown_time_reason, /ambiguous_date_order/);
    assert.ok(!JSON.stringify(await lines(cwd, "timeline.jsonl")).includes("1970"), "no row is at the epoch");
  });
});

test("every formula-injection prefix is neutralised in the CSV, also after white space and invisible characters; the raw value stays in the JSONL; ordinary text is untouched", async () => {
  const hostile = ["=1+1", "+1+1", "-1+1", "@SUM(A1)", "\t=1", "\r=1", " =1+1", "  \t +cmd|' /C calc'!A0", " =1", "​@x", "﻿-2", " +1", "\n=1", "=HYPERLINK(\"http://e.example\",\"x\")", "-5"];
  const safe = ["alice@example.org", "a=b", "1+1", "x - y", "  plain", "3.5", "naïve, with comma", 'she said "hi"', "two\nlines"];
  await withDir(async (cwd) => {
    const rows = [...hostile, ...safe].map((p, i) => row(`c${i}`, `2026-02-14T09:00:${String(i).padStart(2, "0")}Z`, { principal: p, resource: p, user_agent: p }));
    await put(cwd, "work/ev/a.jsonl", jsonl(rows));
    body(await tool(TL, cwd, { path: "work/ev/a.jsonl" }));
    const csv = csvRows(await readFile(join(cwd, DIR, "timeline.csv"), "utf8"));
    const head = csv[0];
    const col = (n: string): number => head.indexOf(n);
    assert.ok(col("principal") > 0 && col("resource") > 0 && col("user_agent") > 0);
    const rawRows = await lines(cwd, "timeline.jsonl");
    hostile.forEach((p, i) => {
      for (const c of ["principal", "resource", "user_agent"]) assert.equal(csv[i + 1][col(c)], "'" + p, `${JSON.stringify(p)} in ${c}`);
      assert.equal(rawRows[i].principal, p, "the raw value stays in the JSONL");
    });
    safe.forEach((p, i) => {
      for (const c of ["principal", "resource", "user_agent"]) assert.equal(csv[hostile.length + i + 1][col(c)], p, `${JSON.stringify(p)} is untouched`);
    });
    for (const r of csv.slice(1)) for (const cell of r) assert.ok(!/^[\s ​﻿ ]*[=+@\-]/.test(cell.replace(/^'/, "") === cell ? cell : "ok") || cell.startsWith("'") || /^\d{4}-/.test(cell), `a cell is still a formula: ${JSON.stringify(cell)}`);
  });
});

test("a row that is not an object, a malformed line and an over-long row are rejected, located and counted; the rest are sorted and the run is partial", async () => {
  await withDir(async (cwd) => {
    await put(cwd, "work/ev/a.jsonl", [JSON.stringify(row("r1", "2026-02-14T09:00:02Z")), "{broken", "42", JSON.stringify(row("r2", "2026-02-14T09:00:01Z"))].join("\n") + "\n");
    const out = body(await tool(TL, cwd, { path: "work/ev/a.jsonl" }));
    assert.equal(out.status, "partial");
    assert.equal(out.coverage.rows_rejected, 2);
    assert.deepEqual((await lines(cwd, "timeline.partial.jsonl")).map((r) => r.event_id), ["r2", "r1"]);
    const rej = await lines(cwd, "rejected.jsonl");
    assert.deepEqual(rej.map((r) => r.line), [2, 3]);
    assert.ok(!(await exists(join(cwd, DIR, "timeline.jsonl"))), "the final name holds only a result that read everything");
  });
});

test("a directory gives only its normalised streams; rejected.jsonl and coverage.json beside them are not rows", async () => {
  await withDir(async (cwd) => {
    await put(cwd, "work/ev/normalised.jsonl", jsonl([row("n1", "2026-02-14T09:00:00Z")]));
    await put(cwd, "work/ev/normalised.2.jsonl", jsonl([row("n2", "2026-02-14T08:00:00Z")]));
    await put(cwd, "work/ev/rejected.jsonl", jsonl([{ file: "x", record: 1, reason: "r" }]));
    await put(cwd, "work/ev/coverage.json", JSON.stringify({ status: "complete" }));
    const out = body(await tool(TL, cwd, { path: "work/ev" }));
    assert.equal(out.coverage.rows_read, 2);
    assert.equal(out.status, "partial", "the entries that were not taken are named, and the run is partial");
    assert.ok(out.coverage.skipped_entries >= 2);
    assert.deepEqual((await lines(cwd, "timeline.partial.jsonl")).map((r) => r.event_id), ["n2", "n1"]);
  });
});

test("an input row that already has a timeline field keeps it as input_timeline; the producer's duplicate annotation and every other field are kept", async () => {
  await withDir(async (cwd) => {
    await put(cwd, "work/ev/a.jsonl", jsonl([row("t1", "2026-02-14T09:00:00Z", { timeline: { seq: 99 }, duplicate_of_an_earlier_record: true, locator: { file: "f", record: 3, line: 7 }, extra_field: [1, 2] })]));
    const out = body(await tool(TL, cwd, { path: "work/ev/a.jsonl" }));
    assert.equal(out.coverage.rows_annotated_duplicate_by_their_producer, 1);
    assert.equal(out.coverage.rows_with_a_timeline_field_renamed, 1);
    const [r] = await lines(cwd, "timeline.jsonl");
    assert.deepEqual(r.input_timeline, { seq: 99 });
    assert.equal(r.timeline.seq, 1);
    assert.equal(r.duplicate_of_an_earlier_record, true);
    assert.deepEqual(r.locator, { file: "f", record: 3, line: 7 });
    assert.deepEqual(r.extra_field, [1, 2]);
  });
});

test("rows that are not cloud_normalise's go through the withholding rules; a cloud_normalise row is copied as it is; originals go to the 0600 file only on write_values", async () => {
  const secret = "Zq" + rnd(18, 201) + "!9";
  await withDir(async (cwd) => {
    await put(cwd, "work/ev/a.jsonl", jsonl([
      row("w1", "2026-02-14T09:00:00Z", { parser: "other/1", password: secret, note: `Authorization: Bearer ${JWT}`, text: `login with password=${PW}` }),
      row("w2", "2026-02-14T09:00:01Z", { note: "kept as the producer cleaned it", marker: "trusted" }),
    ]));
    const run = await asJob(TL, cwd, { path: "work/ev/a.jsonl", write_values: true }, { SECRET_OUTPUT: "1" });
    const out = body(run);
    assert.equal(out.coverage.rows_cleaned_here, 1);
    assert.equal(out.coverage.rows_trusted, 1);
    let all = run.stdout + run.stderr;
    for (const f of await readdir(join(cwd, "out", "cloud-timeline"))) all += await readFile(join(cwd, "out", "cloud-timeline", f), "utf8");
    assert.equal(leaked(secret, all), undefined);
    assert.equal(leaked(JWT, all), undefined);
    assert.equal(leaked(PW, all), undefined);
    assert.match(all, /kept as the producer cleaned it/);
    const values = await readFile(join(cwd, "out", "cloud-timeline-values.jsonl"), "utf8");
    assert.ok(values.includes(secret));
    assert.equal((await stat(join(cwd, "out", "cloud-timeline-values.jsonl"))).mode & 0o777, 0o600);
    const refusal = refused(await tool(TL, cwd, { path: "work/ev/a.jsonl", write_values: true }));
    assert.equal(refusal.write_values, "refused");
  });
});

test("a second run in one directory never replaces the first: equal bytes reuse the names, different input is kept beside them", async () => {
  await withDir(async (cwd) => {
    await put(cwd, "work/ev/a.jsonl", jsonl([row("e1", "2026-02-14T09:00:00Z"), row("e2", "2026-02-14T09:00:01Z")]));
    body(await tool(TL, cwd, { path: "work/ev/a.jsonl" }));
    const first = await readFile(join(cwd, DIR, "timeline.jsonl"), "utf8");
    body(await tool(TL, cwd, { path: "work/ev/a.jsonl" }));
    assert.deepEqual((await readdir(join(cwd, DIR))).filter((n) => /\.2\./.test(n)), [], "equal bytes: no second set");
    await put(cwd, "work/ev/b.jsonl", jsonl([row("e3", "2026-02-14T09:00:00Z")]));
    const second = body(await tool(TL, cwd, { path: "work/ev/b.jsonl" }));
    assert.equal(await readFile(join(cwd, DIR, "timeline.jsonl"), "utf8"), first, "the first result is untouched");
    assert.match(second.outputs.timeline_jsonl, /timeline\.2\.jsonl$/);
    assert.equal((await lines(cwd, "timeline.2.jsonl")).length, 1);
  });
});

test("the clock is one: a run that reaches time_limit_seconds is partial and publishes name.partial.ext, holding a correct prefix of the order, and ends near the limit", async () => {
  await withDir(async (cwd) => {
    const rows: Json[] = [];
    for (let i = 0; i < 200_000; i++) rows.push(row(`k${i}`, `2026-02-${String(1 + (i % 27)).padStart(2, "0")}T${String(i % 24).padStart(2, "0")}:${String(i % 60).padStart(2, "0")}:${String((i * 7) % 60).padStart(2, "0")}Z`, { pad: "benign words ".repeat(20) }));
    await put(cwd, "work/ev/a.jsonl", jsonl(rows));
    const t0 = Date.now();
    const out = body(await tool(TL, cwd, { path: "work/ev/a.jsonl", time_limit_seconds: 4, chunk_rows: 20000 }));
    const took = Date.now() - t0;
    assert.equal(out.status, "partial", out.status_basis);
    assert.ok(took < 4000 + 12_000, `took ${took} ms`);
    assert.ok(!(await exists(join(cwd, DIR, "timeline.jsonl"))));
    assert.ok(await exists(join(cwd, DIR, "coverage.partial.json")));
    if (await exists(join(cwd, DIR, "timeline.partial.jsonl"))) {
      const got = await lines(cwd, "timeline.partial.jsonl");
      const times = got.map((r) => r.time_utc);
      assert.deepEqual(times, times.slice().sort(), "what is written is in order");
      assert.equal(got.length, out.coverage.rows_written_in_order);
    }
    assert.match(out.problems.join(" "), /clock|share/);
  });
});

test("SIGTERM, at the start, in the read and in the merge, leaves no half file under a final name and no temporary file, with one line of JSON and exit 143", async (t) => {
  await withDir(async (cwd) => {
    const rows: Json[] = [];
    for (let i = 0; i < 400_000; i++) rows.push(row(`s${i}`, `2026-02-${String(1 + (i % 27)).padStart(2, "0")}T${String(i % 24).padStart(2, "0")}:${String(i % 60).padStart(2, "0")}:${String((i * 7) % 60).padStart(2, "0")}Z`, { pad: "benign words ".repeat(10) }));
    await put(cwd, "work/ev/a.jsonl", jsonl(rows));
    let signalled = 0;
    for (const delay of [300, 2500, 5500, 8500]) {
      await mkdir(join(cwd, "work", "s1"), { recursive: true });
      const out = `work/s1/sig-${delay}`;
      const { child, done } = spawnTool(TL, cwd, { path: "work/ev/a.jsonl", out_dir: out, time_limit_seconds: 300, chunk_rows: 50_000 });
      await new Promise((r) => setTimeout(r, delay));
      child.kill("SIGTERM");
      const run = await done;
      if (run.code === 0) continue;                 // finished before the signal
      signalled++;
      assert.equal(run.code, 143, run.stderr);
      assert.doesNotMatch(run.stderr, /Traceback/);
      const line = JSON.parse(run.stdout.trim().split("\n").pop() as string);
      assert.equal(line.interrupted, true);
      assert.equal(line.status, "partial");
      const left = await readdir(join(cwd, out)).catch(() => [] as string[]);
      assert.deepEqual(left.filter((n) => !/^coverage\.partial(\.\d+)?\.json$/.test(n)), [], `${delay} ms (${line.stage}): only the partial coverage is left`);
    }
    if (!signalled) t.diagnostic("every run finished before its signal");
  });
});

test("argument errors are typed JSON: no path, an unknown argument, a bad chunk size, an unreadable or missing path; the manifest declares secret_output and the clock", async () => {
  await withDir(async (cwd) => {
    for (const bad of [{}, { bogus: 1 }, { path: "work/ev/missing.jsonl" }, { path: 5 }]) refused(await tool(TL, cwd, bad));
    await put(cwd, "work/ev/a.jsonl", jsonl([row("x", "2026-02-14T09:00:00Z")]));
    for (const bad of [{ chunk_rows: 1 }, { chunk_rows: "x" }, { chunk_bytes: 10 }, { time_limit_seconds: 481 }, { out_dir: "../x" }]) refused(await tool(TL, cwd, { path: "work/ev/a.jsonl", ...bad }));
    await put(cwd, "work/ev/archive.jsonl", Buffer.from("PK\x03\x04rest"));
    const arch = refused(await tool(TL, cwd, { path: "work/ev/archive.jsonl", out_dir: "work/s1/ar" }));
    assert.equal(arch.status, "failed");
  });
  const m = JSON.parse(await readFile(join(TOOLS, "cloud_timeline_export", "manifest.json"), "utf8"));
  assert.deepEqual(m.secret_output, { when_args: ["write_values"] });
  assert.equal(m.timeout_seconds, 600);
});

// ---- the memory bound -------------------------------------------------------------------------------------------------------------------------

const ROWS = Number(process.env.CLOUD_TIMELINE_ROWS ?? 1_000_000);

test(`${ROWS} rows are sorted within a memory bound (CLOUD_TIMELINE_ROWS sets the count; the default is 1,000,000)`, { timeout: 3_600_000 }, async () => {
  const wrapper = peakRssPrelude() + String.raw`
import runpy
sys.argv = [sys.argv[1]]
try:
    runpy.run_path(sys.argv[0], run_name="__main__")
except SystemExit:
    pass
sys.stderr.write("MAXRSS %d\n" % self_peak_bytes())
`;
  await withDir(async (cwd) => {
    await mkdir(join(cwd, "work", "ev"), { recursive: true });
    const ws = createWriteStream(join(cwd, "work", "ev", "big.jsonl"));
    let state = 987654321;
    const rnd01 = (): number => ((state = (state * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff);
    for (let i = 0; i < ROWS; i++) {
      const day = 1 + Math.floor(rnd01() * 27);
      const sec = Math.floor(rnd01() * 86400);
      const t = `2026-02-${String(day).padStart(2, "0")}T${String(Math.floor(sec / 3600)).padStart(2, "0")}:${String(Math.floor((sec % 3600) / 60)).padStart(2, "0")}:${String(sec % 60).padStart(2, "0")}Z`;
      const text = JSON.stringify({ provider: "gcp", adapter: "gcp_audit", parser: "cloud_normalise/1", event_id: `e${i}`, time_raw: t, time_utc: t, time_status: "zoned", principal: `user${i % 1000}@example.org`, action: "storage.objects.get", resource: `projects/_/buckets/b/objects/o${i}`, outcome: "success" }) + "\n";
      if (!ws.write(text)) await new Promise<void>((r) => ws.once("drain", () => r()));
    }
    await new Promise<void>((r) => ws.end(() => r()));
    const t0 = Date.now();
    const run: Run = await new Promise((resolve, reject) => {
      const child = spawn("python3", ["-c", wrapper, TL], { cwd, env: { ...process.env, AGENT_ID: "s1" } });
      const o: Buffer[] = [];
      const e: Buffer[] = [];
      child.stdout.on("data", (c: Buffer) => o.push(c));
      child.stderr.on("data", (c: Buffer) => e.push(c));
      child.on("error", reject);
      child.on("close", (code) => resolve({ code, stdout: Buffer.concat(o).toString("utf8"), stderr: Buffer.concat(e).toString("utf8") }));
      child.stdin.end(JSON.stringify({ path: "work/ev/big.jsonl", limit: 10, time_limit_seconds: 480 }));
    });
    const peak = /MAXRSS (\d+)/.exec(run.stderr);
    assert.ok(peak, run.stderr);
    const out = JSON.parse(run.stdout);
    console.log(`${ROWS} rows: peak RSS ${Number(peak[1]) >> 20} MiB, ${Math.round((Date.now() - t0) / 1000)} s, status ${out.status}, runs ${out.coverage.runs_written}, merge passes ${out.coverage.merge_passes}`);
    assert.ok(Number(peak[1]) < 400 << 20, `peak resident size ${Number(peak[1]) >> 20} MiB`);
    assert.equal(out.status, "complete", out.status_basis);
    assert.equal(out.coverage.rows_dated, ROWS);
    // the order, checked by reading the output once
    const { createReadStream } = await import("node:fs");
    const { createInterface } = await import("node:readline");
    let prev = "";
    let n = 0;
    let bad = 0;
    for await (const l of createInterface({ input: createReadStream(join(cwd, "work", "s1", "cloud-timeline", "timeline.jsonl")) })) {
      const t = l.slice(l.indexOf('"time_utc":"') + 12, l.indexOf('"time_utc":"') + 32);
      if (t < prev) bad++;
      prev = t;
      n++;
    }
    assert.equal(n, ROWS);
    assert.equal(bad, 0, "every row is at or after the one before it");
  });
});
