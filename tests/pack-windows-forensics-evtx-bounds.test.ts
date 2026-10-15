/**
 * evtx_query and evtx_carve against logs and blobs made to cost: a chunk whose string or template table loops, a library call that never
 * returns, a log whose header counts fewer chunks than the file holds, a record whose XML is not well-formed.
 *
 * Fixtures are real bytes written to the libevtx layout (tests/windows-stub-evtx.ts): the file header, 64 KiB chunks with a 0x80-byte header,
 * the string table at 0x80 (64 offsets) and the template table at 0x180 (32 offsets), records from 0x200. The stand-in library reads them as
 * python-evtx does; the real library runs where it is installed. A table entry points at a node whose first dword is the next offset.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, readFile, readdir, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { ROOT, runPy, withCwd } from "./tool-library-harness.ts";
import { WIN, body, failed, py, pythonCanImport, stubModule, tool } from "./windows-pack-harness.ts";
import { CHUNK_BYTES, EVTX_CARVE_STUB, eventXml, evtxChunk, evtxFileHeader } from "./windows-stub-evtx.ts";

type Answer = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

const REAL = pythonCanImport("Evtx.Evtx") ? false : "python-evtx is not installed on this host";

/** A chunk of `n` records numbered from `first`. */
const chunkOf = (first: number, n: number, o: { time?: string } = {}): Buffer =>
  evtxChunk(Array.from({ length: n }, (_, i) => ({ number: first + i, xml: eventXml({ eid: 4624, rec: first + i, time: o.time ?? "2026-09-01 10:00:00.000000", data: [["TargetUserName", "u" + (first + i)]] }) })));

/** A chunk whose string table's first chain names itself: python-evtx follows it for ever. */
function stringLoop(chunk: Buffer): Buffer {
  const c = Buffer.from(chunk);
  c.writeUInt32LE(0xf000, 0x80);
  c.writeUInt32LE(0xf000, 0xf000);
  return c;
}

/** A chunk whose template table names a node (token 0x0C before it, its own offset four bytes before it) whose next pointer is itself. */
function templateLoop(chunk: Buffer): Buffer {
  const c = Buffer.from(chunk);
  const at = 0xf010;
  c.writeUInt8(0x0c, at - 10);
  c.writeUInt32LE(at, at - 4);
  c.writeUInt32LE(at, at);
  c.writeUInt32LE(at, 0x180);
  return c;
}

async function putLog(cwd: string, chunks: Buffer[], o: { declared?: number; flags?: number; inject?: Record<string, unknown>; name?: string } = {}): Promise<Record<string, string>> {
  const name = o.name ?? "Security.evtx";
  const stubs = await stubModule(cwd, { "Evtx/__init__.py": "", "Evtx/Evtx.py": EVTX_CARVE_STUB });
  await writeFile(join(cwd, "work", name), Buffer.concat([evtxFileHeader(o.declared ?? chunks.length, 1, o.flags ?? 0), ...chunks]));
  await writeFile(join(cwd, "work", name + ".inject.json"), JSON.stringify(o.inject ?? {}));
  return stubs;
}

const readRows = async (cwd: string, file: string): Promise<Answer[]> => (await readFile(join(cwd, file), "utf8")).split("\n").filter(Boolean).map((l) => JSON.parse(l) as Answer);

/** Run a tool with a wall clock; at the limit only the child started here is killed, by its PID. */
function runLimited(script: string, cwd: string, args: unknown, env: Record<string, string>, ms: number): Promise<{ code: number | null; stdout: string; stderr: string; timedOut: boolean; ms: number }> {
  return new Promise((resolve) => {
    const started = Date.now();
    const child = spawn("python3", [script], { cwd, env: { ...process.env, AGENT_ID: "s1", ...env } });
    let stdout = "";
    let stderr = "";
    let timedOut = false;
    child.stdout.on("data", (c: Buffer) => (stdout += c.toString()));
    child.stderr.on("data", (c: Buffer) => (stderr += c.toString()));
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, ms);
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ code, stdout, stderr, timedOut, ms: Date.now() - started });
    });
    child.stdin.end(JSON.stringify(args));
  });
}

// --- evtx_query: the chunks the file holds -----------------------------------------------

test("evtx_query reads the chunks the file holds past the header's count, flags them, and says the log is dirty", async () => {
  // It read only the chunks the file header declares and said complete: on a real dirty log the newest chunk was missed (749 of 757
  // records), and a header count forced to 1 gave 149 records, complete.
  await withCwd(async (cwd) => {
    const env = await putLog(cwd, [chunkOf(1, 3), chunkOf(4, 3), chunkOf(7, 2)], { declared: 1, flags: 1 });
    const out = body<Answer>(await tool("evtx_query", cwd, { path: "work/Security.evtx" }, env));
    assert.equal(out.records_examined, 8, "every record of the three chunks");
    assert.equal(out.highest_record_id_read, 8);
    assert.equal(out.chunks_declared, 1);
    assert.equal(out.chunks_in_file, 3);
    assert.equal(out.chunks_read, 3);
    assert.equal(out.chunks_read_beyond_declared, 2);
    assert.equal(out.header_dirty, true);
    assert.match(out.beyond_declared_note, /2 chunk\(s\) past the 1 its header declares: 2 were read.*dirty/);
    assert.equal(out.status, "complete", "everything the file holds was read");
    const rows = await readRows(cwd, out.result_file);
    assert.deepEqual(rows.map((r) => r.chunk_beyond_declared), [false, false, false, true, true, true, true, true]);
  });
});

test("evtx_query does not read what only looks like a chunk past the header's count: a rejected signature is a problem and the run is partial", async () => {
  await withCwd(async (cwd) => {
    const forged = Buffer.alloc(CHUNK_BYTES);
    forged.write("ElfChnk\u0000", 0, "latin1"); // header size 0 where 0x80 belongs
    const env = await putLog(cwd, [chunkOf(1, 2), forged, Buffer.alloc(CHUNK_BYTES)], { declared: 1 });
    const out = body<Answer>(await tool("evtx_query", cwd, { path: "work/Security.evtx" }, env));
    assert.equal(out.records_examined, 2);
    assert.equal(out.chunks_beyond_declared_rejected, 1);
    assert.equal(out.chunk_slots_beyond_declared_empty, 1, "an all-zero slot past the count is free space, not a problem");
    assert.equal(out.status, "partial");
    assert.ok(out.problems.some((p: string) => /did not pass the chunk header checks/.test(p)), out.problems.join("|"));
    assert.match(out.chunks_not_read[0][1], /header size is 0, not 128/);
  });
});

test("evtx_query names a declared chunk with no signature instead of reading garbage as records", async () => {
  await withCwd(async (cwd) => {
    const env = await putLog(cwd, [chunkOf(1, 2), Buffer.alloc(CHUNK_BYTES, 0x41)], { declared: 2 });
    const out = body<Answer>(await tool("evtx_query", cwd, { path: "work/Security.evtx" }, env));
    assert.equal(out.records_examined, 2);
    assert.equal(out.status, "partial");
    assert.ok(out.problems.some((p: string) => /1 chunk\(s\) the file header declares have no ElfChnk signature/.test(p)));
    assert.equal(out.parse_errors, 1);
  });
});

test("evtx_query's result file is private to its owner and is not left under the name of a result when the run is stopped", async () => {
  await withCwd(async (cwd) => {
    const env = await putLog(cwd, [chunkOf(1, 2)]);
    const out = body<Answer>(await tool("evtx_query", cwd, { path: "work/Security.evtx" }, env));
    assert.equal((await stat(join(cwd, out.result_file))).mode & 0o777, 0o600);
    assert.deepEqual((await readdir(join(cwd, "work", "s1", "tool-output"))).filter((n) => n.startsWith(".")), []);
  });
});

// --- a chunk that would not end ------------------------------------------------------------

for (const [label, make] of [["string table", stringLoop], ["template table", templateLoop]] as Array<[string, (c: Buffer) => Buffer]>) {
  test(`evtx_query and evtx_carve end on a chunk whose ${label} loops, name it, and keep the records of the other chunks (the stand-in follows the tables as the library does)`, async () => {
    await withCwd(async (cwd) => {
      const chunks = [chunkOf(1, 2), make(chunkOf(3, 2)), chunkOf(5, 2)];
      const env = await putLog(cwd, chunks);
      const q = await runLimited(join(WIN, "evtx_query", "run.py"), cwd, { path: "work/Security.evtx" }, env, 30_000);
      assert.equal(q.timedOut, false);
      const query = JSON.parse(q.stdout) as Answer;
      assert.equal(query.records_examined, 4, "the two chunks that are sound");
      assert.equal(query.chunks_not_read_count, 1);
      assert.match(query.chunks_not_read[0][1], new RegExp(`${label.split(" ")[0]} table entry \\d+ loops back to offset 0x`));
      assert.equal(query.status, "partial");
      const blob = join(cwd, "work", "blob.bin");
      await writeFile(blob, Buffer.concat(chunks));
      const c = await runLimited(join(WIN, "evtx_carve", "run.py"), cwd, { path: "work/blob.bin" }, env, 30_000);
      assert.equal(c.timedOut, false);
      const carve = JSON.parse(c.stdout) as Answer;
      assert.equal(carve.record_count, 4);
      assert.equal(carve.chunks_not_read_tables, 1);
      assert.ok(carve.problems.some((p: Answer) => /loops back/.test(p.why)));
    });
  });
}

test("a library call that never returns is given up after the chunk's time, and the chunks after it are read", async () => {
  // A chunk the table check cannot see (a record whose rendering never ends) held the whole run: no deadline, no answer.
  await withCwd(async (cwd) => {
    const stub = EVTX_CARVE_STUB.replace("    def xml(self):\n        n = self.length()", "    def xml(self):\n        if b\"HANG\" in bytes(self._buf[self._offset + 24:self._offset + 60]):\n            while True:\n                pass\n        n = self.length()");
    assert.notEqual(stub, EVTX_CARVE_STUB);
    const stubs = await stubModule(cwd, { "Evtx/__init__.py": "", "Evtx/Evtx.py": stub });
    const hanging = evtxChunk([{ number: 3, xml: "HANG" + eventXml({ eid: 1, rec: 3 }) }]);
    const chunks = [chunkOf(1, 2), hanging, chunkOf(5, 2)];
    await writeFile(join(cwd, "work", "Security.evtx"), Buffer.concat([evtxFileHeader(3, 1), ...chunks]));
    await writeFile(join(cwd, "work", "Security.evtx.inject.json"), "{}");
    await writeFile(join(cwd, "work", "blob.bin"), Buffer.concat(chunks));
    for (const name of ["evtx_query", "evtx_carve"]) {
      const src = (await readFile(join(WIN, name, "run.py"), "utf8")).replace("CHUNK_SECONDS = 8", "CHUNK_SECONDS = 1");
      assert.ok(src.includes("CHUNK_SECONDS = 1"));
      await mkdir(join(cwd, "copy", name), { recursive: true });
      await writeFile(join(cwd, "copy", name, "run.py"), src);
      const run = await runLimited(join(cwd, "copy", name, "run.py"), cwd, { path: name === "evtx_query" ? "work/Security.evtx" : "work/blob.bin" }, stubs, 25_000);
      assert.equal(run.timedOut, false, name);
      assert.ok(run.ms < 15_000, `${name} took ${run.ms} ms`);
      const out = JSON.parse(run.stdout) as Answer;
      assert.equal(out.status, "partial", name);
      assert.ok(JSON.stringify(out).includes("more than 1 seconds"), name + " names the time: " + run.stdout.slice(0, 300));
      if (name === "evtx_query") assert.equal(out.records_examined, 4);
      else assert.equal(out.record_count, 4);
    }
  });
});

test("a stop signal inside a library call that never returns unwinds it: JSON, exit 143, nothing left under the name of a result", async () => {
  await withCwd(async (cwd) => {
    const stub = EVTX_CARVE_STUB.replace("    def xml(self):\n        n = self.length()", "    def xml(self):\n        if b\"HANG\" in bytes(self._buf[self._offset + 24:self._offset + 60]):\n            open(os.environ[\"READY\"], \"w\").close()\n            while True:\n                pass\n        n = self.length()");
    const stubs = await stubModule(cwd, { "Evtx/__init__.py": "", "Evtx/Evtx.py": stub });
    const chunks = [chunkOf(1, 2), evtxChunk([{ number: 3, xml: "HANG" + eventXml({ eid: 1, rec: 3 }) }])];
    await writeFile(join(cwd, "work", "Security.evtx"), Buffer.concat([evtxFileHeader(2, 1), ...chunks]));
    await writeFile(join(cwd, "work", "Security.evtx.inject.json"), "{}");
    await writeFile(join(cwd, "work", "blob.bin"), Buffer.concat(chunks));
    for (const [name, rel] of [["evtx_query", "work/Security.evtx"], ["evtx_carve", "work/blob.bin"]]) {
      const ready = join(cwd, name + ".ready");
      const child = spawn("python3", [join(WIN, name, "run.py")], { cwd, env: { ...process.env, AGENT_ID: "s1", READY: ready, ...stubs } });
      let stdout = "";
      child.stdout.on("data", (c: Buffer) => (stdout += c.toString()));
      const closed = new Promise<number | null>((resolve) => child.on("close", (code) => resolve(code)));
      child.stdin.end(JSON.stringify({ path: rel }));
      for (let waited = 0; waited < 20_000; waited += 25) {
        if (await stat(ready).then(() => true, () => false)) break;
        await new Promise((r) => setTimeout(r, 25));
      }
      child.kill("SIGTERM");
      assert.equal(await closed, 143, name);
      const out = JSON.parse(stdout) as Answer;
      assert.equal(out.status, "interrupted", name);
      assert.equal(out.signal, 15);
      if (name === "evtx_query") {
        assert.match(out.partial_result_file, /\.partial.*\.jsonl$/);
        const rows = await readRows(cwd, out.partial_result_file);
        assert.equal(rows.length, 2, "the records read before the stop are in the partial file");
        assert.deepEqual((await readdir(join(cwd, "work", "s1", "tool-output"))).filter((n) => !n.includes(".partial")), []);
      } else {
        assert.equal(out.sweep_complete, false);
        assert.equal(out.record_count, 2);
        assert.equal(typeof out.resume_start, "number");
      }
    }
  });
});

test("evtx_query and evtx_carve stop at their own time limit, say partial, and say where to go on", async () => {
  await withCwd(async (cwd) => {
    const chunks = [chunkOf(1, 2), chunkOf(3, 2)];
    const env = await putLog(cwd, chunks);
    await writeFile(join(cwd, "work", "blob.bin"), Buffer.concat(chunks));
    for (const name of ["evtx_query", "evtx_carve"]) {
      const src = (await readFile(join(WIN, name, "run.py"), "utf8")).replace(/DEADLINE_SECONDS = \d+ /, "DEADLINE_SECONDS = 0 ");
      assert.ok(src.includes("DEADLINE_SECONDS = 0 "));
      await mkdir(join(cwd, "copy", name), { recursive: true });
      await writeFile(join(cwd, "copy", name, "run.py"), src);
      const run = await runPy(join(cwd, "copy", name, "run.py"), cwd, { path: name === "evtx_query" ? "work/Security.evtx" : "work/blob.bin" }, undefined, { AGENT_ID: "s1", ...env });
      const out = JSON.parse(run.stdout) as Answer;
      assert.equal(out.status, "partial", name);
      assert.equal(out.walk_stopped_by_time_limit, true, name);
      assert.match(out.status_basis, /time limit|problem/, name);
      if (name === "evtx_carve") {
        assert.equal(out.sweep_complete, false);
        assert.equal(out.resume_start, 0, "the first candidate was not begun");
      }
    }
  });
});

// --- evtx_carve ----------------------------------------------------------------------------

test("evtx_carve keeps a record whose XML is not well-formed, with the XML and the reason, instead of dropping it", async () => {
  // python-evtx does not escape a quote in an attribute: the record was a problem line and its XML was gone.
  await withCwd(async (cwd) => {
    const bad = eventXml({ eid: 4688, rec: 2, data: [["NewProcessName", "x"]] }).replace('Name="NewProcessName"', 'Name="a"b"');
    const chunk = evtxChunk([{ number: 1, xml: eventXml({ eid: 4624, rec: 1 }) }, { number: 2, xml: bad }, { number: 3, xml: eventXml({ eid: 4624, rec: 3 }) }]);
    const env = await putLog(cwd, [chunk]);
    await writeFile(join(cwd, "work", "blob.bin"), chunk);
    const out = body<Answer>(await tool("evtx_carve", cwd, { path: "work/blob.bin" }, env));
    assert.equal(out.record_count, 3);
    assert.equal(out.records_malformed_kept, 1);
    const rows = await readRows(cwd, out.all_results);
    const malformed = rows.find((r) => r.parse_error);
    assert.ok(malformed && malformed.xml.includes('Name="a"b"'), "the XML is kept");
    assert.match(malformed!.parse_error, /malformed/);
    assert.equal(out.status, "partial");
  });
});

test("evtx_carve does not count a chunk whose header passes and whose bytes are noise as a clean find", async () => {
  await withCwd(async (cwd) => {
    const forged = Buffer.alloc(CHUNK_BYTES, 0x5a);
    forged.write("ElfChnk\u0000", 0, "latin1");
    forged.writeBigUInt64LE(1n, 0x08);
    forged.writeBigUInt64LE(9n, 0x10);
    forged.writeUInt32LE(0x80, 0x28);
    forged.writeUInt32LE(0x300, 0x2c);
    forged.writeUInt32LE(0x400, 0x30);
    forged.fill(0, 0x80, 0x200); // the tables are empty: nothing for the library to follow
    await writeFile(join(cwd, "work", "blob.bin"), forged);
    const env = await stubModule(cwd, { "Evtx/__init__.py": "", "Evtx/Evtx.py": EVTX_CARVE_STUB });
    const out = body<Answer>(await tool("evtx_carve", cwd, { path: "work/blob.bin" }, env));
    assert.equal(out.chunks_found, 1);
    assert.equal(out.chunks_checksum_ok, 0);
    assert.equal(out.chunks_unverified_and_empty, 1);
    assert.equal(out.status, "partial");
    assert.ok(out.problems.some((p: Answer) => /probably not a chunk/.test(p.why)));
  });
});

test("evtx_carve names its result files from what was asked about, never from the needle, and never replaces one that is there", async () => {
  await withCwd(async (cwd) => {
    const env = await putLog(cwd, []);
    const blob = Buffer.concat([chunkOf(1, 3), chunkOf(4, 3)]);
    await writeFile(join(cwd, "work", "blob.bin"), blob);
    const run = (extra: Record<string, unknown>) => tool("evtx_carve", cwd, { path: "work/blob.bin", ...extra }, env);
    const a = body<Answer>(await run({ contains: "u1" }));
    const b = body<Answer>(await run({ contains: "u2" }));
    for (const needle of ["u1", "u2", "U1"]) {
      // the name the old tool made: sha256 of json.dumps([path, start, end, sorted(event ids), contains], sort_keys=True)
      const guessed = py(
        "import hashlib, json, sys\nprint(hashlib.sha256(json.dumps(['work/blob.bin', 0, int(sys.argv[2]), [], sys.argv[1]], sort_keys=True, default=str).encode()).hexdigest()[:16])",
        needle, String(blob.length),
      ).trim();
      for (const out of [a, b]) assert.ok(!String(out.all_results).includes(guessed), `${out.all_results} carries a digest of ${needle}`);
    }
    assert.notEqual(a.all_results, b.all_results);
    assert.match(String(b.all_results), /-2\.jsonl$/);
    const again = body<Answer>(await run({ contains: "u1" }));
    assert.equal(again.all_results, a.all_results, "the same result keeps its name");
    // A rerun that stops sooner (chunk_limit) is another result: it does not replace the larger one.
    const whole = body<Answer>(await run({}));
    const before = await readFile(join(cwd, whole.all_results), "utf8");
    const short = body<Answer>(await run({ chunk_limit: 1 }));
    assert.notEqual(short.all_results, whole.all_results);
    assert.equal(await readFile(join(cwd, whole.all_results), "utf8"), before, "the larger file is as it was");
    assert.ok((await readRows(cwd, whole.all_results)).length > (await readRows(cwd, short.all_results)).length);
  });
});

test("evtx_carve prints at most 100 channels and counts the rest; every channel is in a file", async () => {
  await withCwd(async (cwd) => {
    const env = await putLog(cwd, []);
    const records = Array.from({ length: 150 }, (_, i) => ({ number: i + 1, xml: eventXml({ eid: 1, rec: i + 1, channel: "Chan-" + String(i).padStart(3, "0") }) }));
    const half = evtxChunk(records.slice(0, 75));
    const rest = evtxChunk(records.slice(75));
    await writeFile(join(cwd, "work", "blob.bin"), Buffer.concat([half, rest]));
    const out = body<Answer>(await tool("evtx_carve", cwd, { path: "work/blob.bin", limit: 1 }, env));
    assert.equal(out.channel_count, 150);
    assert.equal(out.channels.length, 100);
    assert.ok(out.all_channels);
    assert.equal((await readFile(join(cwd, out.all_channels), "utf8")).split("\n").filter(Boolean).length, 150);
  });
});

test("evtx_query and evtx_carve refuse a path that is not a regular file, and an out_file that is not text, as JSON", async () => {
  await withCwd(async (cwd) => {
    const env = await putLog(cwd, [chunkOf(1, 1)]);
    for (const name of ["evtx_query", "evtx_carve"]) {
      const err = failed(await tool(name, cwd, { path: "work" }, env));
      assert.match(err.error, /not a regular file/, name);
      assert.equal(err.status, "failed");
      assert.ok(String(err.status_basis).length > 10);
    }
    // A name with a byte that is not UTF-8: a file system that refuses it (macOS) gives a JSON failure, one that takes it (Linux) a result whose name is escaped.
    const odd = await tool("evtx_query", cwd, { path: "work/Security.evtx", out_file: "work/\udcff.jsonl" }, env);
    assert.doesNotMatch(odd.stderr, /Traceback/);
    const oddOut = JSON.parse(odd.stdout) as Answer;
    assert.ok(typeof oddOut.status_basis === "string");
    if (odd.code !== 0) {
      assert.equal(oddOut.status, "failed");
      assert.match(oddOut.error, /out_file is not a path|cannot be written/);
    } else {
      assert.ok(["complete", "partial"].includes(oddOut.status));
    }
  });
});

// --- the real library ----------------------------------------------------------------------

test("with the real python-evtx, a chunk whose string table loops is refused before the library sees it, in evtx_query and in evtx_carve", { skip: REAL }, async () => {
  await withCwd(async (cwd) => {
    const chunks = [evtxChunk([]), stringLoop(evtxChunk([])), evtxChunk([])];
    await writeFile(join(cwd, "work", "Security.evtx"), Buffer.concat([evtxFileHeader(3, 1), ...chunks]));
    await writeFile(join(cwd, "work", "blob.bin"), Buffer.concat(chunks));
    const q = await runLimited(join(WIN, "evtx_query", "run.py"), cwd, { path: "work/Security.evtx" }, {}, 30_000);
    assert.equal(q.timedOut, false, "evtx_query ended");
    assert.equal((JSON.parse(q.stdout) as Answer).chunks_not_read_count, 1);
    const c = await runLimited(join(WIN, "evtx_carve", "run.py"), cwd, { path: "work/blob.bin" }, {}, 30_000);
    assert.equal(c.timedOut, false, "evtx_carve ended");
    assert.equal((JSON.parse(c.stdout) as Answer).chunks_not_read_tables, 1);
  });
});

test("with the real python-evtx, the log's own header count does not hide a chunk: the file of a dirty log is read to its end", { skip: REAL }, async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "dirty.evtx"), Buffer.concat([evtxFileHeader(1, 1, 1), evtxChunk([]), evtxChunk([]), evtxChunk([])]));
    const out = body<Answer>(await tool("evtx_query", cwd, { path: "work/dirty.evtx" }));
    assert.equal(out.chunks_declared, 1);
    assert.equal(out.chunks_in_file, 3);
    assert.equal(out.chunks_read, 3);
    assert.equal(out.chunks_read_beyond_declared, 2);
    assert.equal(out.header_dirty, true);
  });
});

// --- twins, shared blocks ------------------------------------------------------------------

test("evtx_query's tool-library twin is byte-equal to the pack's tool", async () => {
  for (const file of ["run.py", "manifest.json"]) {
    assert.ok((await readFile(join(WIN, "evtx_query", file))).equals(await readFile(join(ROOT, "tool-library", "evtx_query", file))), `${file} differs from the tool-library copy`);
  }
});

test("the windows-forensics tools that carry a shared block (place, page, evtx read) carry it identically", async () => {
  for (const [begin, end, expect] of [
    ["# BEGIN SHARED PLACE", "# END SHARED PLACE", ["evtx_query", "evtx_carve"]],
    ["# BEGIN SHARED PAGE", "# END SHARED PAGE", ["evtx_carve"]],
    ["# BEGIN SHARED EVTX READ", "# END SHARED EVTX READ", ["evtx_query", "evtx_carve"]],
  ] as Array<[string, string, string[]]>) {
    const found: Record<string, string> = {};
    for (const name of await readdir(WIN)) {
      const text = await readFile(join(WIN, name, "run.py"), "utf8").catch(() => "");
      if (text.includes(begin)) found[name] = text.slice(text.indexOf(begin), text.indexOf(end) + end.length);
    }
    for (const name of expect) assert.ok(found[name], `${name} lacks ${begin}`);
    assert.equal(new Set(Object.values(found).map((b) => createHash("sha256").update(b).digest("hex"))).size, 1, `${begin} differs between ${Object.keys(found).join(", ")}`);
  }
});
