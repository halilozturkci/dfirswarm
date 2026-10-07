/**
 * evtx_query, evtx_carve and sigma_hunt against fixtures built to the formats, not from the tools' own output.
 *
 *   evtx_query   python-evtx's file header (chunk count, next record number), chunks and records, as a JSON description
 *                the stand-in library reads (tests/windows-stub-evtx.ts); the log's size is padded to what its header declares
 *                unless a test says the log is cut short.
 *   evtx_carve   real bytes: a 64 KiB chunk to the libevtx layout with real CRC-32s, and a stand-in python-evtx that, like
 *                the library, accepts garbage without complaint.
 *   sigma_hunt   engine stand-ins that write what Hayabusa and Zircolite write.
 *
 * To see a test fail on the code it was written against, point WINDOWS_PACK_TOOLS at a copy of the pack's tools as they were:
 *   WINDOWS_PACK_TOOLS=/tmp/wf-prev/packs/windows-forensics/tools node --test tests/pack-windows-forensics-evtx.test.ts
 */
import assert from "node:assert/strict";
import { chmod, mkdir, readFile, readdir, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { WIN, body, exists, failed, py, pythonCanImport, stub, stubModule, tool, type Run } from "./windows-pack-harness.ts";
import { withCwd } from "./tool-library-harness.ts";
import { CHUNK_BYTES, EVTX_CARVE_STUB, EVTX_QUERY_STUB, eventXml, evtxChunk, evtxFileHeader } from "./windows-stub-evtx.ts";

const root = process.getuid ? process.getuid() === 0 : false;

// --- evtx_query -----------------------------------------------------------------

type EvtxRec = { offset: number; xml?: string; xml_error?: string; filetime?: string; chain_error?: string; number?: number };
type EvtxSpec = {
  header?: { chunk_count?: number; next_record_number?: number };
  header_error?: string;
  unpadded?: boolean;
  chunks: Array<{ offset: number; records: EvtxRec[]; enumeration_error?: string }>;
};

const goodRec = (offset: number, eid: number, rec: number, time: string | undefined, data: Array<[string, string]> = []): EvtxRec => ({
  offset,
  number: rec,
  xml: eventXml({ eid, rec, time, data }),
  filetime: "133443104001234567",
});

type EvtxQueryOut = {
  status: string;
  file_bytes: number;
  chunks_declared: number | null;
  chunks_read: number;
  bytes_expected: number | null;
  next_record_number_declared: number | null;
  highest_record_id_read: number | null;
  records_examined: number;
  events_matched: number;
  parse_errors: number;
  events_without_time_excluded: number;
  time_range_utc: { from: string | null; until_exclusive: string | null } | null;
  count: number;
  events: Array<{ event_id: number; record_id: number; record_offset: number; chunk_offset: number; timestamp: string; record_filetime: string | null; record_time_utc: string | null; data: Record<string, string>; xml?: string }>;
  errors: Array<{ parse_error: string; record_offset?: number | null; chunk_offset?: number | null }>;
  problems: string[];
  result_file: string;
  result_file_requested?: string;
};

/** The log as the stand-in library reads it, its size made what its header declares (a JSON file may end in blanks) unless the case is a cut-short log. */
async function evtxCase(cwd: string, spec: EvtxSpec, args: Record<string, unknown> = {}, env: Record<string, string> = {}): Promise<Run> {
  const stubs = await stubModule(cwd, { "Evtx/__init__.py": "", "Evtx/Evtx.py": EVTX_QUERY_STUB });
  const text = JSON.stringify(spec);
  const declared = 4096 + (spec.header?.chunk_count ?? spec.chunks.length) * CHUNK_BYTES;
  await writeFile(join(cwd, "work", "Security.evtx"), spec.unpadded ? text : text + " ".repeat(Math.max(0, declared - text.length)), "utf8");
  return tool("evtx_query", cwd, { path: "work/Security.evtx", ...args }, { ...stubs, ...env });
}

const DAY: EvtxSpec = { chunks: [{ offset: 4096, records: [
  goodRec(4608, 4624, 1, "2026-09-01 09:59:59.000000"),
  goodRec(5000, 4624, 2, "2026-09-01 10:00:00.500000"),
  goodRec(5400, 4672, 3, "2026-09-01 10:05:00.000000"),
  goodRec(5800, 4624, 4, "2026-09-02 08:00:00.000000"),
] }] };

test("evtx_query counts what matched apart from what it could not read: a record that does not parse is a parse error, not a match", async () => {
  await withCwd(async (cwd) => {
    const out = body<EvtxQueryOut>(await evtxCase(cwd, {
      chunks: [{ offset: 4096, records: [
        goodRec(4608, 4624, 11, "2026-09-01 10:00:00.123456", [["TargetUserName", "alice"]]),
        { offset: 5000, xml_error: "BinXML template could not be expanded" },
        goodRec(5400, 4625, 13, "2026-09-01 10:00:02.000000", [["TargetUserName", "bob"]]),
      ] }],
    }));
    assert.equal(out.records_examined, 3);
    assert.equal(out.events_matched, 2);
    assert.equal(out.parse_errors, 1);
    assert.equal(out.count, 2, "count is the events that matched");
    assert.equal(out.status, "partial");
    assert.deepEqual(out.events.map((e) => [e.event_id, e.record_id, e.record_offset, e.chunk_offset]), [[4624, 11, 4608, 4096], [4625, 13, 5400, 4096]]);
    assert.equal(out.events[0].data.TargetUserName, "alice");
    assert.match(out.errors[0].parse_error, /^BinXML template could not be expanded/);
    const rows = (await readFile(join(cwd, out.result_file), "utf8")).trimEnd().split("\n").map((l) => JSON.parse(l) as { xml?: string; record_offset: number });
    assert.deepEqual(rows.map((r) => r.record_offset), [4608, 5000, 5400]);
    assert.ok(rows[0].xml?.includes("<EventID>4624</EventID>"));
  });
});

test("evtx_query keeps the raw FILETIME of the record header beside its time, and the SystemTime the XML carries", async () => {
  await withCwd(async (cwd) => {
    const out = body<EvtxQueryOut>(await evtxCase(cwd, { chunks: [{ offset: 4096, records: [goodRec(4608, 4624, 11, "2026-09-01 10:00:00.123456")] }] }));
    assert.equal(out.events[0].record_filetime, "133443104001234567");
    assert.equal(out.events[0].record_time_utc, "2023-11-13T00:53:20.1234567Z");
    assert.equal(out.events[0].timestamp, "2026-09-01 10:00:00.123456");
    assert.equal(out.status, "complete");
    assert.equal(out.chunks_declared, 1);
    assert.equal(out.chunks_read, 1);
    assert.equal(out.bytes_expected, 4096 + CHUNK_BYTES);
  });
});

test("evtx_query ends a broken record chain with a row naming its chunk and goes on to the next chunk, and says when the chunks themselves could not be enumerated", async () => {
  await withCwd(async (cwd) => {
    const out = body<EvtxQueryOut>(await evtxCase(cwd, {
      chunks: [
        { offset: 4096, records: [goodRec(4608, 4624, 1, "2026-09-01 10:00:00.000000"), { offset: 4700, chain_error: "record length points past the chunk" }] },
        { offset: 69632, records: [goodRec(70144, 4624, 5, "2026-09-01 11:00:00.000000")] },
        { offset: 135168, records: [], enumeration_error: "unexpected end of file at chunk 3" },
      ],
    }));
    assert.deepEqual(out.events.map((e) => e.record_id), [1, 5], "the chunk after the broken chain is still read");
    assert.equal(out.parse_errors, 2);
    assert.match(out.errors[0].parse_error, /record chain of this chunk broke: record length points past the chunk/);
    assert.match(out.errors[1].parse_error, /chunk enumeration failed after offset 69632/);
    assert.ok(out.problems.some((p) => /could not be enumerated past offset 69632/.test(p)));
    assert.equal(out.chunks_read, 2);
    assert.equal(out.chunks_declared, 3);
    assert.ok(out.problems.some((p) => /gave 2 of the 3 chunks/.test(p)));
    assert.equal(out.status, "partial");
  });
});

test("evtx_query filters by event id, record range and a time prefix, and validates every argument before it opens an output file", async () => {
  await withCwd(async (cwd) => {
    const day = body<EvtxQueryOut>(await evtxCase(cwd, DAY, { start_time: "2026-09-01", end_time: "2026-09-01" }));
    assert.deepEqual(day.events.map((e) => e.record_id), [1, 2, 3], "a date is a span: the whole of 2026-09-01");
    assert.deepEqual(day.time_range_utc, { from: "2026-09-01T00:00:00.0000000Z", until_exclusive: "2026-09-02T00:00:00.0000000Z" });
    const window = body<EvtxQueryOut>(await evtxCase(cwd, DAY, { start_time: "2026-09-01T10:00", end_time: "2026-09-01T10:00", event_ids: [4624] }));
    assert.deepEqual(window.events.map((e) => e.record_id), [2]);
    const range = body<EvtxQueryOut>(await evtxCase(cwd, DAY, { start_record: 3, end_record: 4 }));
    assert.deepEqual(range.events.map((e) => e.record_id), [3, 4]);
    assert.equal(range.records_examined, 4, "records outside the filters are still examined, and counted");
    const bad = failed(await evtxCase(cwd, DAY, { limit: 0, out_file: "work/s1/never.jsonl" }));
    assert.match(bad.error, /limit must be a whole number of at least 1/);
    assert.equal(await exists(join(cwd, "work", "s1", "never.jsonl")), false, "no output file was made for a refused call");
    assert.match(failed(await evtxCase(cwd, DAY, { event_ids: ["4624"] })).error, /event_ids must be a list of whole numbers/);
  });
});

test("evtx_query says a file it cannot open is an error, not a traceback", async () => {
  await withCwd(async (cwd) => {
    const env = await stubModule(cwd, { "Evtx/__init__.py": "", "Evtx/Evtx.py": EVTX_QUERY_STUB });
    await writeFile(join(cwd, "work", "junk.evtx"), "this is not an event log");
    assert.match(failed(await tool("evtx_query", cwd, { path: "work/junk.evtx" }, env)).error, /could not open the event log/);
  });
});

test("evtx_query says a log cut short is partial, with what its header declares against what was read, and not a complete log with no records", async () => {
  // The guard around the chunk walk caught an exception the library never raises, so a truncated file read as complete.
  await withCwd(async (cwd) => {
    const cut = body<EvtxQueryOut>(await evtxCase(cwd, {
      header: { chunk_count: 3, next_record_number: 40 },
      unpadded: true,
      chunks: [{ offset: 4096, records: [goodRec(4608, 4624, 1, "2026-09-01 10:00:00.000000")] }],
    }));
    assert.equal(cut.status, "partial");
    assert.equal(cut.chunks_declared, 3);
    assert.equal(cut.chunks_read, 1);
    assert.equal(cut.bytes_expected, 4096 + 3 * CHUNK_BYTES);
    assert.ok(cut.file_bytes < cut.bytes_expected);
    assert.equal(cut.next_record_number_declared, 40);
    assert.equal(cut.highest_record_id_read, 1);
    assert.ok(cut.problems.some((p) => /the log is cut short/.test(p)), cut.problems.join("|"));
    assert.ok(cut.problems.some((p) => /gave 1 of the 3 chunks/.test(p)), cut.problems.join("|"));
    // No chunk at all, though the header declares two: partial, with zero records examined.
    const empty = body<EvtxQueryOut>(await evtxCase(cwd, { header: { chunk_count: 2 }, chunks: [] }));
    assert.equal(empty.records_examined, 0);
    assert.equal(empty.status, "partial");
    assert.ok(empty.problems.some((p) => /gave 0 of the 2 chunks/.test(p)));
    // A header that cannot be read says the log's extent is not known.
    const broken = body<EvtxQueryOut>(await evtxCase(cwd, { header_error: "file header magic is wrong", chunks: [{ offset: 4096, records: [goodRec(4608, 4624, 1, "2026-09-01 10:00:00.000000")] }] }));
    assert.equal(broken.status, "partial");
    assert.equal(broken.chunks_declared, null);
    assert.ok(broken.problems.some((p) => /file header could not be read.*file header magic is wrong/.test(p)));
  });
});

test("evtx_query reads a time argument as ISO 8601 and converts it to UTC: a Z suffix keeps the second's records, an offset is applied, a word or a reversed range is refused", async () => {
  // The bounds were compared as text, so "2026-09-01T10:00:00Z" sorted after "2026-09-01T10:00:00.500000" and dropped the
  // second's records; "yesterday" returned an empty answer marked complete; +03:00 was ignored; a start after the end gave nothing.
  await withCwd(async (cwd) => {
    const z = body<EvtxQueryOut>(await evtxCase(cwd, DAY, { start_time: "2026-09-01T10:00:00Z", end_time: "2026-09-01T10:00:00Z" }));
    assert.deepEqual(z.events.map((e) => e.record_id), [2], "Z at the lower bound keeps the records of that second");
    const offset = body<EvtxQueryOut>(await evtxCase(cwd, DAY, { start_time: "2026-09-01T13:00:00+03:00", end_time: "2026-09-01T13:00:00+03:00" }));
    assert.deepEqual(offset.events.map((e) => e.record_id), [2], "13:00 at +03:00 is 10:00 UTC");
    const minus = body<EvtxQueryOut>(await evtxCase(cwd, DAY, { start_time: "2026-09-01T05:00-05:00", end_time: "2026-09-01T05:00-05:00" }));
    assert.deepEqual(minus.events.map((e) => e.record_id), [2], "05:00 at -05:00 is 10:00 UTC, and a minute is a span of a minute");
    const fraction = body<EvtxQueryOut>(await evtxCase(cwd, DAY, { start_time: "2026-09-01T10:00:00.5", end_time: "2026-09-01T10:00:00.5" }));
    assert.deepEqual(fraction.events.map((e) => e.record_id), [2], "a tenth of a second is a span of a tenth");
    const open = body<EvtxQueryOut>(await evtxCase(cwd, DAY, { start_time: "2026-09-01T10:00:00.6" }));
    assert.deepEqual(open.events.map((e) => e.record_id), [3, 4]);
    assert.match(failed(await evtxCase(cwd, DAY, { start_time: "yesterday" })).error, /start_time is not an ISO 8601 UTC time/);
    assert.match(failed(await evtxCase(cwd, DAY, { end_time: "2026-09-01T25:00" })).error, /end_time is not a real date or time|end_time is not an ISO 8601/);
    assert.match(failed(await evtxCase(cwd, DAY, { start_time: "2026-02-30" })).error, /start_time is not a real date or time/);
    assert.match(failed(await evtxCase(cwd, DAY, { start_time: "2026-09-02", end_time: "2026-09-01" })).error, /start_time is after end_time/);
    assert.match(failed(await evtxCase(cwd, DAY, { start_record: 5, end_record: 3 })).error, /start_record is after end_record/);
  });
});

test("evtx_query counts a record with no SystemTime that a time range cannot place, leaves it out and says the run is partial; with no time filter it is an event like any other", async () => {
  await withCwd(async (cwd) => {
    const spec: EvtxSpec = { chunks: [{ offset: 4096, records: [
      goodRec(4608, 4624, 1, "2026-09-01 10:00:00.000000"),
      goodRec(5000, 4624, 2, undefined),
      goodRec(5400, 4624, 3, "not a time"),
    ] }] };
    const ranged = body<EvtxQueryOut>(await evtxCase(cwd, spec, { start_time: "2026-09-01" }));
    assert.deepEqual(ranged.events.map((e) => e.record_id), [1]);
    assert.equal(ranged.events_without_time_excluded, 2);
    assert.equal(ranged.status, "partial");
    assert.ok(ranged.problems.some((p) => /2 record\(s\) have no usable SystemTime/.test(p)));
    const plain = body<EvtxQueryOut>(await evtxCase(cwd, spec));
    assert.deepEqual(plain.events.map((e) => e.record_id), [1, 2, 3]);
    assert.equal(plain.events_without_time_excluded, 0);
    assert.equal(plain.status, "complete");
  });
});

test("evtx_query never replaces or truncates an earlier result: the same arguments again make a new file and name both, and a needle is not in the name", async () => {
  // The name was a digest of every argument, `contains` included, and the file was opened for writing: a second run with the
  // same arguments truncated the first result in place.
  await withCwd(async (cwd) => {
    const first = body<EvtxQueryOut>(await evtxCase(cwd, DAY, { contains: "SECRET-NEEDLE-1" }));
    const before = await readFile(join(cwd, first.result_file), "utf8");
    const again = body<EvtxQueryOut>(await evtxCase(cwd, DAY, { contains: "SECRET-NEEDLE-1" }));
    assert.notEqual(again.result_file, first.result_file);
    assert.match(again.result_file, /-2\.jsonl$/);
    assert.equal(again.result_file_requested, first.result_file);
    assert.equal(await readFile(join(cwd, first.result_file), "utf8"), before, "the first result is as it was");
    // A different needle (or none) lands in a name made of the same arguments: the needle shapes no part of it.
    const other = body<EvtxQueryOut>(await evtxCase(cwd, DAY, { contains: "another" }));
    const base = (name: string): string => name.replace(/-\d+\.jsonl$/, ".jsonl");
    assert.equal(base(other.result_file), base(first.result_file));
    // A file already at out_file is not truncated either.
    await writeFile(join(cwd, "work", "mine.jsonl"), "keep me\n");
    const named = body<EvtxQueryOut>(await evtxCase(cwd, DAY, { out_file: "work/mine.jsonl" }));
    assert.equal(await readFile(join(cwd, "work", "mine.jsonl"), "utf8"), "keep me\n");
    assert.equal(named.result_file, "work/mine-2.jsonl");
    assert.equal(named.result_file_requested, "work/mine.jsonl");
    // A link planted at the name is not written through.
    await symlink(join(cwd, "elsewhere.jsonl"), join(cwd, "work", "link.jsonl"));
    const linked = body<EvtxQueryOut>(await evtxCase(cwd, DAY, { out_file: "work/link.jsonl" }));
    assert.equal(await exists(join(cwd, "elsewhere.jsonl")), false);
    assert.equal(linked.result_file, "work/link-2.jsonl");
  });
});

test("evtx_query cites a job's result by a path made safe, and keeps it under $OUT", async () => {
  await withCwd(async (cwd) => {
    const outDir = join(cwd, "joblab", "out");
    await mkdir(outDir, { recursive: true });
    const out = body<EvtxQueryOut>(await evtxCase(cwd, DAY, {}, { JOB_ID: "../x y", OUT: outDir }));
    assert.match(out.result_file, /^store\/jobs\/\.\._x_y\/out\/evtx-query-[0-9a-f]{16}\.jsonl$/);
    assert.equal((await readdir(outDir)).length, 1);
  });
});

test("evtx_query answers an output it cannot write with JSON that says where results go, not a traceback", async (t) => {
  if (root) return t.skip("root writes a read-only directory");
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "blocker"), "a file where a directory should be");
    assert.match(failed(await evtxCase(cwd, DAY, { out_file: "work/blocker/result.jsonl" })).error, /the whole result cannot be written to work\/blocker\/result\.jsonl/);
    await mkdir(join(cwd, "work", "isadir"));
    const beside = body<EvtxQueryOut>(await evtxCase(cwd, DAY, { out_file: "work/isadir" }));
    assert.equal(beside.result_file, "work/isadir-2", "a directory at the name is a name taken: the result is made beside it");
    assert.equal(beside.result_file_requested, "work/isadir");
    await chmod(join(cwd, "work"), 0o555);
    try {
      const out = failed(await evtxCase(cwd, DAY));
      assert.match(out.error, /the whole result cannot be written to work\/s1\/tool-output\//);
      assert.match(out.error, /work\/<your id>\//);
    } finally {
      await chmod(join(cwd, "work"), 0o755);
    }
  });
});

// --- evtx_carve -----------------------------------------------------------------

type CarveOut = {
  status: string;
  records: Array<{ record_id: number; chunk_offset: number; chunk_verified: boolean; data?: Record<string, string | string[]>; xml?: string }>;
  record_count: number;
  candidates: number;
  signatures_rejected: number;
  chunks_found: number;
  chunks_parsed: number;
  chunks_checksum_ok: number;
  sweep_complete: boolean;
  resume_start: number | null;
  range_requested: { start: number; end: number; file_bytes: number };
  range_examined: { start: number; end: number };
  problems: Array<{ offset: number; why: string }>;
  problem_count: number;
  all_problems?: string;
  all_results?: string;
};

async function carveEnv(cwd: string): Promise<Record<string, string>> {
  return stubModule(cwd, { "Evtx/__init__.py": "", "Evtx/Evtx.py": EVTX_CARVE_STUB });
}

const carveXml = (n: number, data: Array<[string, string]> = []): string => eventXml({ eid: 4688, rec: n, data });

test("evtx_carve keeps a repeated EventData name as a list and the whole XML in the result file even when the result is small", async () => {
  await withCwd(async (cwd) => {
    const env = await carveEnv(cwd);
    const blob = Buffer.concat([Buffer.alloc(100, 0x2e), evtxChunk([
      { number: 1, xml: carveXml(1, [["Path", "C:\\first.exe"], ["Path", "C:\\second.exe"], ["User", "svc"]]) },
      { number: 2, xml: carveXml(2) },
    ]), Buffer.alloc(30, 0x2e)]);
    await writeFile(join(cwd, "work", "blob.bin"), blob);
    const out = body<CarveOut>(await tool("evtx_carve", cwd, { path: "work/blob.bin" }, env));
    assert.equal(out.record_count, 2);
    assert.deepEqual(out.records[0].data, { Path: ["C:\\first.exe", "C:\\second.exe"], User: "svc" });
    assert.equal(out.records[0].xml, undefined, "the inline summary has no XML unless asked");
    assert.equal(out.chunks_found, 1);
    assert.equal(out.chunks_checksum_ok, 1);
    assert.equal(out.records[0].chunk_verified, true);
    assert.ok(out.all_results, "the whole result is in a file even though it fits the page");
    const rows = (await readFile(join(cwd, out.all_results as string), "utf8")).trimEnd().split("\n").map((l) => JSON.parse(l) as { xml: string });
    assert.ok(rows[0].xml.includes("C:\\first.exe") && rows[0].xml.includes("C:\\second.exe"));
    const withXml = body<CarveOut>(await tool("evtx_carve", cwd, { path: "work/blob.bin", with_xml: true }, env));
    assert.ok(withXml.records[0].xml?.includes("C:\\second.exe"));
  });
});

test("evtx_carve does not take a forged ElfChnk signature for a chunk: with the library as it is, which accepts garbage, thousands of them are rejected with a problem each and none is parsed", async () => {
  // ChunkHeader() does not raise on garbage, so every signature was built, parsed and counted: 10,000 fakes and a limit of
  // 500 candidates gave 200 chunks parsed, none verified, no problem, and a resume offset past 12,000 bytes of noise.
  await withCwd(async (cwd) => {
    const env = await carveEnv(cwd);
    const noise = Buffer.alloc(10_240 * 64);
    for (let i = 0; i < 10_000; i++) noise.write("ElfChnk\u0000", i * 64, "latin1");
    await writeFile(join(cwd, "work", "noise.bin"), Buffer.concat([noise, evtxChunk([{ number: 7, xml: carveXml(7) }])]));
    const first = body<CarveOut>(await tool("evtx_carve", cwd, { path: "work/noise.bin", candidate_limit: 500 }, env));
    assert.equal(first.candidates, 500);
    assert.equal(first.signatures_rejected, 500);
    assert.equal(first.chunks_found, 0);
    assert.equal(first.chunks_parsed, 0);
    assert.equal(first.chunks_checksum_ok, 0);
    assert.equal(first.sweep_complete, false);
    assert.equal(first.resume_start, 500 * 64);
    assert.equal(first.status, "partial");
    assert.equal(first.problem_count, 500);
    assert.equal(first.problems.length, 40, "problems are a page");
    assert.match(first.problems[0].why, /an ElfChnk signature that is not a chunk: its header size is 0, not 128/);
    const spilled = (await readFile(join(cwd, first.all_problems as string), "utf8")).trimEnd().split("\n");
    assert.equal(spilled.length, 500, "the whole list is in a file");
    assert.deepEqual(first.range_examined, { start: 0, end: 500 * 64 });
    const rest = body<CarveOut>(await tool("evtx_carve", cwd, { path: "work/noise.bin", start: first.resume_start as number, candidate_limit: 20_000 }, env));
    assert.equal(rest.sweep_complete, true);
    assert.equal(rest.signatures_rejected, 9_500);
    assert.equal(rest.chunks_found, 1);
    assert.equal(rest.chunks_parsed, 1);
    assert.equal(rest.chunks_checksum_ok, 1);
    assert.equal(rest.record_count, 1);
    assert.equal(rest.records[0].record_id, 7);
  });
});

test("evtx_carve names why a signature is not a chunk header: a size that is not 128, offsets outside the chunk, a first record after the last, a signature at the end of the file", async () => {
  await withCwd(async (cwd) => {
    const env = await carveEnv(cwd);
    const forge = (set: (b: Buffer) => void): Buffer => {
      const b = Buffer.alloc(CHUNK_BYTES);
      b.write("ElfChnk\u0000", 0, "latin1");
      b.writeUInt32LE(0x80, 0x28);
      b.writeUInt32LE(0x200, 0x30);
      set(b);
      return b;
    };
    const parts = [
      forge((b) => b.writeUInt32LE(0x40, 0x28)),
      forge((b) => b.writeUInt32LE(0x20000, 0x30)),
      forge((b) => b.writeUInt32LE(0x10001, 0x2c)),
      forge((b) => { b.writeUInt32LE(0x400, 0x30); b.writeBigUInt64LE(9n, 0x08); b.writeBigUInt64LE(3n, 0x10); }),
      Buffer.from("ElfChnk\u0000", "latin1").subarray(0, 8),
    ];
    const blob = Buffer.concat([...parts.slice(0, 4), Buffer.alloc(100), parts[4], Buffer.alloc(50)]);
    await writeFile(join(cwd, "work", "forged.bin"), blob);
    const out = body<CarveOut>(await tool("evtx_carve", cwd, { path: "work/forged.bin" }, env));
    assert.equal(out.signatures_rejected, 5);
    assert.equal(out.chunks_found, 0);
    const why = out.problems.map((p) => p.why).join("\n");
    assert.match(why, /its header size is 64, not 128/);
    assert.match(why, /its record offsets \(last 0, free space 131072\) lie outside a 65536-byte chunk/);
    assert.match(why, /its record offsets \(last 65537, free space 512\) lie outside/);
    assert.match(why, /its first record number 9 is after its last, 3/);
    assert.match(why, /the file ends 58 bytes after the signature and a chunk header is 128 bytes/);
  });
});

test("evtx_carve verifies a real chunk's checksums, marks one whose records fail theirs, and reads the records of both", async () => {
  await withCwd(async (cwd) => {
    const env = await carveEnv(cwd);
    const blob = Buffer.concat([
      evtxChunk([{ number: 1, xml: carveXml(1) }]),
      evtxChunk([{ number: 2, xml: carveXml(2) }], { corrupt: true }),
    ]);
    await writeFile(join(cwd, "work", "two.bin"), blob);
    const out = body<CarveOut>(await tool("evtx_carve", cwd, { path: "work/two.bin" }, env));
    assert.equal(out.chunks_found, 2);
    assert.equal(out.chunks_parsed, 2);
    assert.equal(out.chunks_checksum_ok, 1);
    assert.deepEqual(out.records.map((r) => [r.record_id, r.chunk_offset, r.chunk_verified]), [[1, 0, true], [2, CHUNK_BYTES, false]]);
    assert.equal(out.signatures_rejected, 0);
  });
});

test("evtx_carve refuses a negative or empty range and a start past the file, and says the range it was asked to sweep", async () => {
  await withCwd(async (cwd) => {
    const env = await carveEnv(cwd);
    await writeFile(join(cwd, "work", "blob.bin"), Buffer.alloc(5000, 0x2e));
    assert.match(failed(await tool("evtx_carve", cwd, { path: "work/blob.bin", start: -5 }, env)).error, /start must be a whole number of at least 0/);
    assert.match(failed(await tool("evtx_carve", cwd, { path: "work/blob.bin", max_bytes: 0 }, env)).error, /max_bytes must be a whole number of at least 1/);
    assert.match(failed(await tool("evtx_carve", cwd, { path: "work/blob.bin", limit: 0 }, env)).error, /limit must be a whole number of at least 1/);
    assert.match(failed(await tool("evtx_carve", cwd, { path: "work/blob.bin", start: 6000 }, env)).error, /start is past the end of the file/);
    const part = body<CarveOut>(await tool("evtx_carve", cwd, { path: "work/blob.bin", start: 1000, max_bytes: 2000 }, env));
    assert.deepEqual(part.range_requested, { start: 1000, end: 3000, file_bytes: 5000 });
    assert.deepEqual(part.range_examined, { start: 1000, end: 3000 });
  });
});

test("evtx_carve answers a file it cannot read, and a result it cannot write, with JSON and not a traceback", async (t) => {
  if (root) return t.skip("root reads and writes anything");
  await withCwd(async (cwd) => {
    const env = await carveEnv(cwd);
    await writeFile(join(cwd, "work", "locked.bin"), evtxChunk([{ number: 1, xml: carveXml(1) }]));
    await chmod(join(cwd, "work", "locked.bin"), 0o000);
    assert.match(failed(await tool("evtx_carve", cwd, { path: "work/locked.bin" }, env)).error, /the sweep could not read work\/locked\.bin/);
    await chmod(join(cwd, "work", "locked.bin"), 0o644);
    await chmod(join(cwd, "work"), 0o555);
    try {
      assert.match(failed(await tool("evtx_carve", cwd, { path: "work/locked.bin" }, env)).error, /cannot be written to work\/s1\/tool-output\//);
    } finally {
      await chmod(join(cwd, "work"), 0o755);
    }
  });
});

// --- the real python-evtx ---------------------------------------------------------

// What the stand-ins above claim of the library is held to the library itself where it is installed (CI installs no pip
// packages, so these are skipped there): the file header's accessors, the chunk walk that stops at the end of the file
// without raising, and a ChunkHeader that accepts garbage. Records are not built here: BinXML is the library's business.
const REAL_EVTX = pythonCanImport("Evtx.Evtx") ? false : "python-evtx is not installed on this host";

test("the real python-evtx accepts a forged chunk without complaint, walks only the chunks the file holds, and gives the file header's counts", { skip: REAL_EVTX }, async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "cut.evtx"), Buffer.concat([evtxFileHeader(3, 40), evtxChunk([]), Buffer.alloc(1000)]));
    const out = py(
      [
        "import sys",
        "from Evtx.Evtx import ChunkHeader, FileHeader",
        "garbage = b'ElfChnk\\x00' + b'\\xff' * 0x10000",
        "c = ChunkHeader(garbage, 0)",
        "assert c.verify() is False and c.header_size() == 0xFFFFFFFF",
        "buf = open(sys.argv[1], 'rb').read()",
        "h = FileHeader(buf, 0)",
        "assert (h.header_chunk_size(), h.chunk_count(), h.next_record_number()) == (4096, 3, 40), (h.header_chunk_size(), h.chunk_count(), h.next_record_number())",
        "assert len(list(h.chunks())) == 1",
        "print('ok')",
      ].join("\n"),
      join(cwd, "work", "cut.evtx"),
    );
    assert.equal(out.trim(), "ok");
  });
});

test("evtx_query accounts for a log against its header with the real library: complete when every declared chunk is read, partial when the file ends first", { skip: REAL_EVTX }, async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "whole.evtx"), Buffer.concat([evtxFileHeader(2, 1), evtxChunk([]), evtxChunk([])]));
    const whole = body<EvtxQueryOut>(await tool("evtx_query", cwd, { path: "work/whole.evtx" }));
    assert.equal(whole.status, "complete");
    assert.deepEqual([whole.chunks_declared, whole.chunks_read, whole.bytes_expected, whole.file_bytes], [2, 2, 4096 + 2 * CHUNK_BYTES, 4096 + 2 * CHUNK_BYTES]);
    assert.equal(whole.records_examined, 0);
    await writeFile(join(cwd, "work", "cut.evtx"), Buffer.concat([evtxFileHeader(3, 40), evtxChunk([]), Buffer.alloc(1000)]));
    const cut = body<EvtxQueryOut>(await tool("evtx_query", cwd, { path: "work/cut.evtx" }));
    assert.equal(cut.status, "partial");
    assert.deepEqual([cut.chunks_declared, cut.chunks_read, cut.bytes_expected], [3, 1, 4096 + 3 * CHUNK_BYTES]);
    assert.equal(cut.next_record_number_declared, 40);
    assert.ok(cut.problems.some((p) => /the log is cut short/.test(p)));
    assert.ok(cut.problems.some((p) => /gave 1 of the 3 chunks/.test(p)));
  });
});

test("evtx_carve with the real python-evtx: forged signatures are rejected before the library sees them, and a real chunk is built and its checksums verified by the library", { skip: REAL_EVTX }, async () => {
  await withCwd(async (cwd) => {
    const noise = Buffer.alloc(3000 * 64);
    for (let i = 0; i < 3000; i++) noise.write("ElfChnk\u0000", i * 64, "latin1");
    await writeFile(join(cwd, "work", "mixed.bin"), Buffer.concat([noise, evtxChunk([])]));
    const out = body<CarveOut>(await tool("evtx_carve", cwd, { path: "work/mixed.bin" }));
    assert.equal(out.candidates, 3001);
    assert.equal(out.signatures_rejected, 3000);
    assert.equal(out.chunks_found, 1);
    assert.equal(out.chunks_parsed, 1);
    assert.equal(out.chunks_checksum_ok, 1, "the library's own verify() agrees with the checksums the fixture wrote");
    assert.equal(out.problem_count, 3000);
  });
});

// --- sigma_hunt -----------------------------------------------------------------

type Detection = { rule: string; level: string | null; level_rank: number | null; record_id: number | null; time: string | null };
type HuntOut = {
  status: string;
  complete: boolean;
  exit_code: number;
  timed_out: boolean;
  run_dir: string;
  engine: string;
  engine_detections_read: number;
  detections: Detection[];
  detection_count: number;
  below_min_level: number;
  unknown_levels: Record<string, number>;
  malformed_lines: number;
  malformed_file: { path: string; bytes: number } | null;
  ruleset: { source: string; kind?: string; files?: number; digest: string | null };
  all_detections: { path: string; rows: number };
  engine_stderr: { path: string; bytes: number };
};

/** Hayabusa as it is called here: `hayabusa json-timeline -f|-d <input> -o <out> -w -q`, writing one JSON object per line to <out>. */
const HAYABUSA_STUB = (lines: string[], tail = ""): string => `
out=""
while [ $# -gt 0 ]; do case "$1" in -o) out="$2"; shift;; esac; shift; done
cat > "$out" <<'JSONL'
${lines.join("\n")}
JSONL
${tail}
`;

const hb = (title: string, level: string | undefined, id: number, time = "2026-09-01T10:00:00Z"): string =>
  JSON.stringify({ RuleTitle: title, ...(level === undefined ? {} : { Level: level }), Timestamp: time, EventID: 4688, Channel: "Security", Computer: "WS01", RecordID: id, Details: { Cmd: "x" } });

test("sigma_hunt ranks the level words Hayabusa writes (crit, med, info), and keeps a level it does not know instead of dropping it", async () => {
  // rank() was 0 for any word but the five full names, so a `crit` or `med` detection was filtered out
  // by min_level without a word.
  await withCwd(async (cwd, bin) => {
    await stub(bin, "hayabusa", HAYABUSA_STUB([
      hb("Critical rule", "crit", 1, "2026-09-01T10:00:01Z"),
      hb("Medium rule", "med", 2, "2026-09-01T10:00:02Z"),
      hb("High rule", "high", 3, "2026-09-01T10:00:03Z"),
      hb("Info rule", "info", 4),
      hb("Low rule", "low", 5),
      hb("Odd rule", "evil", 6, "2026-09-01T10:00:06Z"),
      hb("Levelless rule", undefined, 7, "2026-09-01T10:00:07Z"),
    ]));
    await writeFile(join(cwd, "work", "Security.evtx"), "evtx");
    const out = body<HuntOut>(await tool("sigma_hunt", cwd, { path: "work/Security.evtx", out_dir: "work/s1/hunt", engine: "hayabusa", min_level: "medium" }, {}, bin));
    assert.equal(out.status, "complete");
    assert.equal(out.engine_detections_read, 7);
    assert.deepEqual(out.detections.map((d) => d.rule), ["Odd rule", "Levelless rule", "Critical rule", "High rule", "Medium rule"], "unknown levels first, then critical down, nothing dropped but what min_level names");
    assert.deepEqual(out.detections.map((d) => d.level_rank), [null, null, 4, 3, 2]);
    assert.equal(out.below_min_level, 2, "info and low are below medium, and counted");
    assert.deepEqual(out.unknown_levels, { evil: 1, "(no level)": 1 });
    assert.equal(out.detection_count, 5);
    assert.equal(out.all_detections.rows, 5);
  });
});

test("sigma_hunt marks a run whose engine exited non-zero partial, and never reads an earlier run's result in its place", async () => {
  // It accepted any result file in out_dir whatever the engine's exit status, so an engine that failed
  // could be answered with the file an earlier invocation left.
  await withCwd(async (cwd, bin) => {
    await writeFile(join(cwd, "work", "Security.evtx"), "evtx");
    await stub(bin, "hayabusa", HAYABUSA_STUB([hb("First run", "high", 1)]));
    const first = body<HuntOut>(await tool("sigma_hunt", cwd, { path: "work/Security.evtx", out_dir: "work/s1/hunt", engine: "hayabusa" }, {}, bin));
    assert.equal(first.status, "complete");
    // The engine now writes nothing and exits 0: the old result is not this run's.
    await stub(bin, "hayabusa", "exit 0");
    const stale = failed(await tool("sigma_hunt", cwd, { path: "work/Security.evtx", out_dir: "work/s1/hunt", engine: "hayabusa" }, {}, bin));
    assert.match(stale.error, /wrote no result file/);
    // An engine that leaves a result and then fails is a partial run, with its exit status.
    await stub(bin, "hayabusa", HAYABUSA_STUB([hb("Second run", "high", 2)], `echo "engine: could not read channel Microsoft-Windows-X" >&2\nexit 3`));
    const partial = body<HuntOut>(await tool("sigma_hunt", cwd, { path: "work/Security.evtx", out_dir: "work/s1/hunt", engine: "hayabusa" }, {}, bin));
    assert.equal(partial.status, "partial");
    assert.equal(partial.complete, false);
    assert.equal(partial.exit_code, 3);
    assert.deepEqual(partial.detections.map((d) => d.rule), ["Second run"]);
    assert.notEqual(partial.run_dir, first.run_dir, "each invocation has a directory of its own");
    assert.match(await readFile(join(cwd, partial.engine_stderr.path), "utf8"), /could not read channel/);
  });
});

test("sigma_hunt counts a line of the engine's result it cannot read, keeps it whole in a file, and says the run is partial", async () => {
  // A malformed JSON Lines row was passed over with `continue`: the detection it held was never counted.
  await withCwd(async (cwd, bin) => {
    const broken = '{"RuleTitle": "Cut off", "Level": "high", "Timestamp": "2026-09-01T1';
    await stub(bin, "hayabusa", HAYABUSA_STUB([hb("Good one", "high", 1), broken, hb("Good two", "high", 2, "2026-09-01T10:00:02Z")]));
    await writeFile(join(cwd, "work", "Security.evtx"), "evtx");
    const out = body<HuntOut>(await tool("sigma_hunt", cwd, { path: "work/Security.evtx", out_dir: "work/s1/hunt", engine: "hayabusa" }, {}, bin));
    assert.equal(out.status, "partial");
    assert.equal(out.malformed_lines, 1);
    assert.equal(out.engine_detections_read, 2);
    assert.ok(out.malformed_file);
    assert.match(await readFile(join(cwd, out.malformed_file.path), "utf8"), /line 2\t\{"RuleTitle": "Cut off"/);
  });
});

test("sigma_hunt reads Hayabusa's pretty-printed objects as a stream, and records the ruleset's digest", async () => {
  await withCwd(async (cwd, bin) => {
    await writeFile(join(cwd, "work", "Security.evtx"), "evtx");
    // Objects written one after another across lines (Hayabusa's default JSON timeline), not one per line.
    const pretty = [hb("A", "high", 1), hb("B", "critical", 2)].map((o) => JSON.stringify(JSON.parse(o), null, 2)).join("\n");
    await stub(bin, "hayabusa", HAYABUSA_STUB([pretty]));
    await mkdir(join(cwd, "work", "rules", "sub"), { recursive: true });
    await writeFile(join(cwd, "work", "rules", "a.yml"), "title: a\n");
    await writeFile(join(cwd, "work", "rules", "sub", "b.yml"), "title: b\n");
    const run = body<HuntOut>(await tool("sigma_hunt", cwd, { path: "work/Security.evtx", out_dir: "work/s1/hunt", engine: "hayabusa", rules: "work/rules" }, {}, bin));
    assert.deepEqual(run.detections.map((d) => d.rule), ["B", "A"]);
    assert.equal(run.status, "complete");
    assert.equal(run.ruleset.kind, "directory");
    assert.equal(run.ruleset.files, 2);
    assert.match(run.ruleset.digest ?? "", /^[0-9a-f]{64}$/);
    const noRules = body<HuntOut>(await tool("sigma_hunt", cwd, { path: "work/Security.evtx", out_dir: "work/s1/hunt", engine: "hayabusa" }, {}, bin));
    assert.equal(noRules.ruleset.digest, null);
    assert.match(noRules.ruleset.source, /bundled rules/);
  });
});

test("sigma_hunt's merge sort orders detections by level and time across runs of rows spilled to disk", async () => {
  // The normalised detections were built and sorted whole in memory; they are now a bounded-memory merge.
  await withCwd(async (cwd) => {
    const out = py(
      [
        "import importlib.util, json, os, sys, random",
        "spec = importlib.util.spec_from_file_location('sh', sys.argv[1]); sh = importlib.util.module_from_spec(spec); spec.loader.exec_module(sh)",
        "sh.SORT_RUN_BYTES = 300",
        "random.seed(3)",
        "rows = [(random.choice([None, 0, 1, 2, 3, 4]), '2026-09-01T10:%02d:00Z' % random.randrange(60), i) for i in range(400)]",
        "s = sh.Sorted(sys.argv[2])",
        "for lvl, t, i in rows: s.add({'rule': 'r%d' % i, 'time': t, 'level_rank': lvl}, lvl)",
        "first, count = s.write(os.path.join(sys.argv[2], 'out.jsonl'), 5)",
        "got = [json.loads(l) for l in open(os.path.join(sys.argv[2], 'out.jsonl'))]",
        "want = sorted(rows, key=lambda r: (0 if r[0] is None else 1 + (4 - r[0]), r[1], r[2]))",
        "assert count == 400 and len(got) == 400 and len(first) == 5",
        "assert [g['rule'] for g in got] == ['r%d' % w[2] for w in want]",
        "assert len([n for n in os.listdir(sys.argv[2]) if n.startswith('.sort-')]) == 0",
        "print('ok')",
      ].join("\n"),
      join(WIN, "sigma_hunt", "run.py"),
      join(cwd, "work"),
    );
    assert.equal(out.trim(), "ok");
  });
});

test("sigma_hunt refuses an out_dir this run cannot write and names the places that work, and runs in one that it can", async () => {
  // work/hunt is not under the agent's own work/<id>/, which is all the harness lets a VM write: the tool looked for an
  // engine, made the directory, and failed with a permission error (or a traceback) after that.
  await withCwd(async (cwd, bin) => {
    await stub(bin, "hayabusa", HAYABUSA_STUB([hb("A", "high", 1)]));
    await writeFile(join(cwd, "work", "Security.evtx"), "evtx");
    for (const place of ["work/hunt", "work/other/hunt", "hunt", "work"]) {
      const refused = failed(await tool("sigma_hunt", cwd, { path: "work/Security.evtx", out_dir: place, engine: "hayabusa" }, {}, bin));
      assert.match(refused.error, /out_dir is not a place this run can write: use a directory under your own work\/s1\//, place);
      assert.deepEqual(refused.writable, ["work/s1/...", "work/extracted/s1/...", "work/quarantine/s1/...", "tool-output/s1/..."]);
    }
    assert.equal(await exists(join(cwd, "work", "hunt")), false, "nothing was made for a refused out_dir");
    for (const place of ["work/s1/hunt", "work/extracted/s1/hunt", "tool-output/s1/hunt"]) {
      const ok = body<HuntOut>(await tool("sigma_hunt", cwd, { path: "work/Security.evtx", out_dir: place, engine: "hayabusa" }, {}, bin));
      assert.equal(ok.status, "complete", place);
    }
  });
});

test("sigma_hunt in a job writes under $OUT and refuses any other out_dir", async () => {
  await withCwd(async (cwd, bin) => {
    await stub(bin, "hayabusa", HAYABUSA_STUB([hb("A", "high", 1)]));
    await writeFile(join(cwd, "work", "Security.evtx"), "evtx");
    const outDir = join(cwd, "joblab", "out");
    await mkdir(outDir, { recursive: true });
    const job = { JOB_ID: "j1", OUT: outDir };
    const refused = failed(await tool("sigma_hunt", cwd, { path: "work/Security.evtx", out_dir: "work/s1/hunt", engine: "hayabusa" }, job, bin));
    assert.match(refused.error, /out_dir must be under \$OUT in a job/);
    const ok = body<HuntOut>(await tool("sigma_hunt", cwd, { path: "work/Security.evtx", out_dir: "joblab/out/hunt", engine: "hayabusa" }, job, bin));
    assert.equal(ok.status, "complete");
    assert.match(ok.run_dir, /^joblab\/out\/hunt\/hunt-/);
  });
});

test("sigma_hunt answers an out_dir it cannot make with JSON, not a traceback", async (t) => {
  if (root) return t.skip("root writes a read-only directory");
  await withCwd(async (cwd, bin) => {
    await stub(bin, "hayabusa", HAYABUSA_STUB([hb("A", "high", 1)]));
    await writeFile(join(cwd, "work", "Security.evtx"), "evtx");
    await chmod(join(cwd, "work"), 0o555);
    try {
      const out = failed(await tool("sigma_hunt", cwd, { path: "work/Security.evtx", out_dir: "work/s1/hunt", engine: "hayabusa" }, {}, bin));
      assert.match(out.error, /the run directory cannot be made under out_dir/);
    } finally {
      await chmod(join(cwd, "work"), 0o755);
    }
  });
});

test("sigma_hunt reads a line-delimited result whose FIRST line is damaged one line at a time, and does not take the whole file for one unreadable value", async () => {
  // A first line that did not parse made the file a document; the document reader then held the rest of the file in memory
  // and kept all of it as one unreadable item, so every detection after the first line was lost.
  await withCwd(async (cwd, bin) => {
    const damaged = '{"RuleTitle": "Cut off", "Level": "high", "Timestamp": "2026-09-01T1';
    await stub(bin, "hayabusa", HAYABUSA_STUB([damaged, hb("Good one", "high", 1), hb("Good two", "critical", 2), hb("Good three", "medium", 3)]));
    await writeFile(join(cwd, "work", "Security.evtx"), "evtx");
    const out = body<HuntOut>(await tool("sigma_hunt", cwd, { path: "work/Security.evtx", out_dir: "work/s1/hunt", engine: "hayabusa" }, {}, bin));
    assert.equal(out.status, "partial");
    assert.equal(out.malformed_lines, 1);
    assert.equal(out.engine_detections_read, 3);
    assert.deepEqual(out.detections.map((d) => d.rule), ["Good two", "Good one", "Good three"]);
    assert.match(await readFile(join(cwd, out.malformed_file!.path), "utf8"), /^line 1\t\{"RuleTitle": "Cut off"/);
  });
});

test("sigma_hunt streams what is left of a document that stops making sense to its file in chunks, and keeps every byte of it", async () => {
  // `rest` was built in memory: 64 MiB after a syntax error was 64 MiB of memory (a document read whole up to a 256 MiB cap).
  await withCwd(async (cwd) => {
    const tail = "x".repeat(1_000_000);
    const text = `[\n${JSON.stringify({ RuleTitle: "Before", Level: "high" })},\n@@ not json @@\n${tail}\n${tail}\n`;
    await writeFile(join(cwd, "work", "result.json"), text);
    const out = py(
      [
        "import importlib.util, sys, tracemalloc, os",
        "spec = importlib.util.spec_from_file_location('sh', sys.argv[1]); sh = importlib.util.module_from_spec(spec); spec.loader.exec_module(sh)",
        "m = sh.Malformed(sys.argv[3])",
        "tracemalloc.start()",
        "values = list(sh.json_values(sys.argv[2], m))",
        "m.close()",
        "peak = tracemalloc.get_traced_memory()[1]",
        "assert len(values) == 1 and values[0]['RuleTitle'] == 'Before', values",
        "assert m.count == 1",
        "kept = open(sys.argv[3], encoding='utf-8').read()",
        "assert kept.startswith('from the value at the start of this text\\t@@ not json @@\\\\n'), kept[:80]",
        "assert kept.split('\\t', 1)[1].count('x') == 2_000_000, kept.count('x')",
        "print('peak', peak)",
      ].join("\n"),
      join(WIN, "sigma_hunt", "run.py"),
      join(cwd, "work", "result.json"),
      join(cwd, "work", "malformed.txt"),
    );
    const peak = Number(out.trim().split(" ")[1]);
    assert.ok(peak < 6_000_000, `the remainder is streamed: peak ${peak}`);
  });
});

test("sigma_hunt never writes into an earlier run's directory: the same call twice is two directories, and the first is as it was", async () => {
  await withCwd(async (cwd, bin) => {
    await stub(bin, "hayabusa", HAYABUSA_STUB([hb("A", "high", 1)]));
    await writeFile(join(cwd, "work", "Security.evtx"), "evtx");
    const one = body<HuntOut>(await tool("sigma_hunt", cwd, { path: "work/Security.evtx", out_dir: "work/s1/hunt", engine: "hayabusa" }, {}, bin));
    const kept = await readFile(join(cwd, one.run_dir, "detections.jsonl"), "utf8");
    const two = body<HuntOut>(await tool("sigma_hunt", cwd, { path: "work/Security.evtx", out_dir: "work/s1/hunt", engine: "hayabusa" }, {}, bin));
    assert.notEqual(one.run_dir, two.run_dir);
    assert.equal(await readFile(join(cwd, one.run_dir, "detections.jsonl"), "utf8"), kept);
    assert.equal((await readdir(join(cwd, "work", "s1", "hunt"))).length, 2);
  });
});
