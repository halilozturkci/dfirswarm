/**
 * minidump_map (memory-forensics): a Windows process dump read from its own streams. Every dump here is built by
 * tests/pack-memory-minidump-support.ts from the published layouts, in a 64-bit full-memory form (Memory64List) and a 32-bit partial form
 * (MemoryList), and every expected address, offset and byte comes from that generator, never from the tool.
 *
 * What is held: each view's facts; that an address which is not in the dump is said to be absent and never read as zero; that a module
 * with a gap is written only with allow_gaps, then with a map of the gap and status partial; that memory content is written only in a job
 * run as secret output and never printed; that a truncated or malformed dump gives a partial that names the stream and the file offset,
 * and no traceback; paging (total, returned, next_offset); that a chain of `find` calls gives each hit once, the hits that start at one
 * address never split by a stop; and the shared blocks the script carries.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, test } from "node:test";
import { PYTHON3 } from "./host-gates.ts";
import { ROOT } from "./tool-library-harness.ts";
import { rng } from "./memory-f1-support.ts";
import {
  assemble, bareDump, type Built, call, doc, encode, handleEntry, hex, IMAGE, inProcess, mdString, memoryInfo, moduleEntry, PAGE, PRIVATE, RW, RWX, RX, scene, SCRIPT, SIGMA, STRADDLE,
  TOOL_DIR, u16, u32, u64, WIDE_NEEDLE,
} from "./pack-memory-minidump-support.ts";

const B62 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const r = rng(20261113);
/** A token-shaped secret made at run time (no literal of one is in the repository): 28 base62 characters, digits among them. */
const SECRET = Array.from({ length: 28 }, (_, i) => (i % 5 === 4 ? "0123456789"[Math.floor(r() * 10)] : B62[Math.floor(r() * 62)])).join("");

let dir = "";
let d64: Built;
let d32: Built;
const JOB = (out: string): Record<string, string> => ({ JOB_ID: "j000042", OUT: out, SECRET_OUTPUT: "1" });

before(async () => {
  dir = await mkdtemp(join(tmpdir(), "minidump-"));
  await mkdir(join(dir, "inputs"), { recursive: true });
  d64 = encode(scene(64, SECRET));
  d32 = encode(scene(32, SECRET), { memoryList: true });
  await writeFile(join(dir, "inputs", "p64.dmp"), d64.file);
  await writeFile(join(dir, "inputs", "p32.dmp"), d32.file);
});
after(async () => { await rm(dir, { recursive: true, force: true }); });

const ask = async (args: Record<string, unknown>, env: Record<string, string> = {}): Promise<Record<string, any>> => doc(await call(dir, args, env));
const both = (): Array<[string, Built]> => [["inputs/p64.dmp", d64], ["inputs/p32.dmp", d32]];

test("summary: header, flags, kind of dump, system, process, exception, handles, totals, and the command line by the PEB (64- and 32-bit)", async () => {
  for (const [path, d] of both()) {
    const a = await ask({ path });
    const s = d.scene;
    assert.equal(a.status, "complete", JSON.stringify(a.problems));
    assert.equal(a.view, "summary");
    assert.equal(a.header.signature, "MDMP");
    assert.equal(a.header.version, "0xa793");
    assert.equal(a.header.streams, 11);
    assert.equal(a.header.time.raw, s.time);
    assert.equal(a.header.time.utc, "2026-03-01T12:10:00Z");
    assert.equal(a.header.flags, hex(s.flags));
    assert.equal(a.header.flag_names.includes("WithFullMemory"), s.bits === 64);
    assert.ok(a.header.flag_names.includes("WithThreadInfo"));
    assert.equal(a.dump_kind.kind, s.bits === 64 ? "full-memory process dump" : "partial process dump");
    assert.equal(a.system.architecture, s.bits === 64 ? "x64" : "x86");
    assert.equal(a.system.pointer_bytes, s.bits / 8);
    assert.equal(a.system.windows_version, "10.0.19045");
    assert.equal(a.system.processors, 8);
    assert.equal(a.system.service_pack, "Service Pack 1");
    assert.equal(a.process.process_id, 6068);
    assert.equal(a.process.process_create_time.utc, "2026-03-01T12:00:00Z");
    assert.equal(a.process.integrity_level.name, "high");
    assert.equal(a.process.build_string, "19041.1.amd64fre.vb_release.191206-1406");
    assert.deepEqual(a.counts, { streams: 11, modules: 2, unloaded_modules: 1, threads: 2, memory_ranges: 9, memory_ranges_declared: 9, memory_ranges_empty: 0,
      memory_ranges_overlapping: 0, memory_ranges_cut_by_end_of_file: 0, memory_ranges_not_readable: 0, memory_info_regions: 11, memory_info_regions_overlapping: 0 });
    assert.equal(a.memory.mapped_bytes, d.mapped);
    assert.equal(a.memory.declared_bytes, d.mapped);
    assert.equal(a.exception.thread_id, 4242);
    assert.equal(a.exception.code, "0xc0000005");
    assert.equal(a.exception.code_name, "ACCESS_VIOLATION");
    assert.equal(a.exception.address, hex(s.payload + 0x1234n));
    assert.equal(a.exception.address_in_module.name, "payload.exe");
    assert.equal(a.exception.address_in_module.rva, "0x1234");
    assert.deepEqual(a.exception.parameters, ["0x0", "0xdeadbeef"]);
    assert.deepEqual(a.handles.by_type, { File: 2, Mutant: 1 });
    assert.equal(a.handles.with_an_object_name, 1);
    assert.doesNotMatch(JSON.stringify(a.handles), /notes\.txt/, "a handle's object name is counted, not printed");
    assert.deepEqual(a.streams.map((x: any) => x.name).sort(), ["Exception", "HandleData", s.bits === 64 ? "Memory64List" : "MemoryList", "MemoryInfoList", "MiscInfo", "ModuleList",
      "SystemInfo", "ThreadInfoList", "ThreadList", "ThreadNames", "UnloadedModuleList"].sort());
    for (const row of a.streams) assert.deepEqual([row.file_offset, row.bytes], [d.streams[row.name].at, d.streams[row.name].size], row.name);
    // the PEB walk: TEB -> PEB -> process parameters
    const pp = a.process_parameters;
    assert.equal(pp.reached, true);
    assert.equal(pp.peb, hex(s.peb));
    assert.equal(pp.image_base, hex(s.payload));
    assert.equal(pp.image_base_module.name, "payload.exe");
    assert.equal(pp.image_path.shown, s.imagePath);
    assert.equal(pp.current_directory.shown, s.currentDirectory);
    assert.equal(pp.command_line.va, hex(s.commandLineVa));
    assert.equal(pp.command_line.file_offset, d.offsetOf(s.commandLineVa));
    assert.equal(pp.command_line.characters, s.commandLine.length);
    assert.match(pp.command_line.shown, /payload\.exe" --mode fast --token=<secret value withheld 28 characters>$/);
    // the planted token is nowhere in the answer, whole or as a run of 12 characters
    const text = JSON.stringify(a);
    for (let i = 0; i + 12 <= SECRET.length; i++) assert.ok(!text.includes(SECRET.slice(i, i + 12)), `a piece of the secret at ${i}`);
    assert.ok(a.boundary.spans_withheld >= 1);
  }
});

test("modules: base, size, name, timestamp, checksum, version, PDB record, the unloaded module, and how much of each image the dump holds", async () => {
  for (const [path, d] of both()) {
    const a = await ask({ path, view: "modules" });
    const s = d.scene;
    assert.equal(a.status, "complete");
    assert.deepEqual(a.page, { total: 3, offset: 0, returned: 3, next_offset: null, truncated: false });
    const [payload, ntdll, gone] = a.modules;
    assert.deepEqual([payload.state, payload.base, payload.size, payload.end, payload.name, payload.path], ["loaded", hex(s.payload), 0x5000, hex(s.payload + 0x5000n), "payload.exe", s.imagePath]);
    assert.deepEqual([payload.timestamp.raw, payload.timestamp.utc, payload.checksum], [0x65f0a1b2, new Date(0x65f0a1b2 * 1000).toISOString().replace(".000Z", "Z"), "0x1a2b3"]);
    assert.equal(payload.file_version, "1.2.3.4");
    assert.deepEqual([payload.pdb.format, payload.pdb.guid, payload.pdb.age, payload.pdb.path, payload.pdb.read, payload.pdb.path_cut, payload.pdb.declared_bytes, payload.pdb_record],
      ["RSDS", "33221100554477668899AABBCCDDEEFF", 3, "D:\\build\\payload.pdb", true, false, 24 + "D:\\build\\payload.pdb".length + 1, "read"]);
    assert.deepEqual([gone.pdb, gone.pdb_record], [undefined, undefined], "an unloaded module's entry has no CodeView record to declare");
    assert.deepEqual([payload.image_bytes_in_dump, payload.image_coverage_percent], [0x4000, 80]);
    assert.deepEqual([ntdll.name, ntdll.file_version, ntdll.image_bytes_in_dump, ntdll.image_coverage_percent], ["ntdll.dll", "10.0.19041.3996", 0x4000, 100]);
    assert.deepEqual([gone.state, gone.name, gone.size, gone.checksum], ["unloaded", "winhttp.dll", 0x9000, "0x3c3c3"]);
    // paging: one row a call reaches every row, and says total, returned and next
    const seen: string[] = [];
    for (let offset: number | null = 0; offset !== null;) {
      const page: Record<string, any> = await ask({ path, view: "modules", offset, limit: 1 });
      assert.equal(page.page.total, 3);
      assert.equal(page.page.returned, 1);
      assert.equal(page.status, page.page.next_offset === null ? "complete" : "partial");
      seen.push(page.modules[0].name);
      offset = page.page.next_offset;
    }
    assert.deepEqual(seen, ["payload.exe", "ntdll.dll", "winhttp.dll"]);
  }
});

test("memory: every range with its file offset and the protection the MemoryInfoList gives it; filters; the regions, in the dump or not", async () => {
  for (const [path, d] of both()) {
    const s = d.scene;
    const a = await ask({ path, view: "memory" });
    assert.equal(a.status, "complete");
    assert.equal(a.page.total, 9);
    assert.equal(a.totals.mapped_bytes, d.mapped);
    assert.deepEqual(a.ranges.map((x: any) => [x.va, x.bytes, x.file_offset]), s.ranges.map((x) => [hex(x.va), x.data.length, d.offsetOf(x.va)]));
    assert.ok(a.ranges.every((x: any) => x.bytes_in_file === x.bytes && x.source === (s.bits === 64 ? "Memory64List" : "MemoryList")));
    const text = a.ranges.find((x: any) => x.va === hex(s.payload));
    assert.deepEqual([text.region.protect, text.region.type, text.region.state, text.regions_spanned, text.module.name], ["READONLY", "IMAGE", "COMMIT", 2, "payload.exe"]);
    const rwx = await ask({ path, view: "memory", protect: "execute_write" });
    assert.deepEqual(rwx.ranges.map((x: any) => [x.va, x.region.protect, x.region.type]), [[hex(s.rwx), "EXECUTE_READWRITE", "PRIVATE"]]);
    assert.equal(rwx.page.total, 1);
    const priv = await ask({ path, view: "memory", type: "private", protect: "write" });
    assert.equal(priv.page.total, 6, "the two heap ranges, the RWX page, the stack, the TEB and the PEB");
    const regions = await ask({ path, view: "memory", list: "regions" });
    assert.equal(regions.page.total, 11);
    const rdata = regions.regions.find((x: any) => x.base === hex(s.payload + 0x2000n));
    assert.deepEqual([rdata.state, rdata.protect, rdata.bytes, rdata.bytes_in_dump], ["COMMIT", "READONLY", 0x1000, 0], "the region exists in the process and no byte of it is in the dump");
    const reserved = regions.regions.find((x: any) => x.state === "RESERVE");
    assert.deepEqual([reserved.base, reserved.bytes_in_dump, reserved.protect], [hex(s.heap + 0x2000n), 0, "none"]);
    // paging by two
    let n = 0;
    for (let offset: number | null = 0; offset !== null;) {
      const page: Record<string, any> = await ask({ path, view: "memory", offset, limit: 2 });
      assert.equal(page.page.total, 9);
      n += page.page.returned;
      if (page.page.next_offset !== null) assert.equal(page.page.next_offset, offset + 2);
      offset = page.page.next_offset;
    }
    assert.equal(n, 9);
  }
});

test("threads: ids, TEB, stack, register values of an x64 and an x86 context, start address, creation time and name", async () => {
  for (const [path, d] of both()) {
    const s = d.scene;
    const a = await ask({ path, view: "threads" });
    assert.equal(a.status, "complete");
    assert.equal(a.page.total, 2);
    const [t1, t2] = a.threads;
    assert.deepEqual([t1.thread_id, t1.teb, t1.teb_in_dump, t1.name], [4242, hex(s.teb), true, "main"]);
    assert.deepEqual([t1.stack.va, t1.stack.bytes, t1.stack.file_offset], [hex(s.stack), 0x2000, d.offsetOf(s.stack)]);
    assert.equal(t1.context.decoded, true);
    const reg = t1.context.registers;
    if (s.bits === 64) assert.deepEqual([t1.context.layout, reg.rip, reg.rsp, reg.rax, t1.context.eflags, t1.context.segments.cs], ["x64 CONTEXT", hex(s.payload + 0x1234n), hex(s.stack + 0x1f00n), "0x1122334455667788", "0x246", "0x33"]);
    else assert.deepEqual([t1.context.layout, reg.eip, reg.esp, reg.eax, reg.eflags, t1.context.segments.cs], ["x86 CONTEXT", hex(s.payload + 0x1234n), hex(s.stack + 0x1f00n), "0x11223344", "0x246", "0x23"]);
    assert.deepEqual([t1.instruction_pointer_in_module.name, t1.instruction_pointer_in_module.rva, t1.stack_pointer_in_stack], ["payload.exe", "0x1234", true]);
    assert.deepEqual([t1.info.start_address, t1.info.start_address_in_module.name], [hex(s.ntdll + 0x100n), "ntdll.dll"]);
    assert.equal(t1.info.create_time.utc, "2026-03-01T12:00:00.1234567Z");
    assert.deepEqual([t2.thread_id, t2.teb_in_dump, t2.instruction_pointer_in_module, t2.info.start_address_in_module, t2.name], [4343, false, null, null, undefined],
      "a thread whose code is in no module is said so, and nothing is claimed of it");
  }
});

test("va: an address in the dump gives its file offset; one that is not is said to be absent, not zero", async () => {
  for (const [path, d] of both()) {
    const s = d.scene;
    const inText = s.payload + 0x1234n, inGap = s.payload + 0x2800n, nowhere = 0x10n, lastOfData = s.payload + 0x4fffn;
    const a = await ask({ path, view: "va", addresses: [hex(inText), Number(inGap), hex(nowhere), hex(lastOfData).slice(2)] });
    assert.equal(a.status, "complete");
    assert.deepEqual(a.counts, { in_dump: 2, not_in_dump: 2 });
    const [text, gap, low, last] = a.addresses;
    assert.deepEqual([text.va, text.in_dump, text.file_offset, text.module.rva, text.region.protect], [hex(inText), true, d.offsetOf(inText), "0x1234", "EXECUTE_READ"]);
    assert.equal(d.file[text.file_offset], s.payloadImage[0x1234], "the byte at that offset is the image's byte");
    assert.equal(text.bytes_from_here_in_range, 0x2000 - 0x1234);
    assert.deepEqual([gap.in_dump, gap.why_not, gap.file_offset], [false, "not in the dump", undefined]);
    assert.match(gap.meaning, /unknown, not zero/);
    assert.deepEqual([gap.region.state, gap.region.protect, gap.module.name], ["COMMIT", "READONLY", "payload.exe"], "the process had the page; the dump does not");
    assert.deepEqual([gap.nearest_range_below.end, gap.nearest_range_above.va], [hex(s.payload + 0x2000n), hex(s.payload + 0x3000n)]);
    assert.deepEqual([low.in_dump, low.nearest_range_below, low.region], [false, null, null]);
    assert.deepEqual([last.in_dump, last.file_offset, last.bytes_from_here_in_range], [true, d.offsetOf(lastOfData), 1]);
    const one = await ask({ path, view: "va", va: hex(s.heap) });
    assert.deepEqual([one.addresses.length, one.addresses[0].file_offset], [1, d.offsetOf(s.heap)]);
  }
});

const listed = async (root: string): Promise<string[]> => (await readdir(root, { recursive: true }).catch(() => [] as string[])).map(String).sort();

test("read: what is present is said without writing; bytes go to a file only in a job run as secret output; a gap is never written silently", async () => {
  for (const [path, d] of both()) {
    const s = d.scene;
    const out = await mkdtemp(join(dir, "out-read-"));
    const whole = { path, view: "read", va: hex(s.payload + 0x1000n), length: 0x1000 };
    const dry = await ask(whole);
    assert.deepEqual([dry.status, dry.coverage.bytes_present, dry.coverage.bytes_absent, dry.coverage.coverage_percent, dry.output.written], ["complete", 0x1000, 0, 100, false]);
    // write_values outside a job, and in a job that is not secret output, is refused before anything is read
    for (const env of [{}, { JOB_ID: "j000042", OUT: out }] as Array<Record<string, string>>) {
      const refused = await call(dir, { ...whole, write_values: true }, env);
      const a = doc(refused);
      assert.deepEqual([refused.code, a.status, a.write_values, a.written], [1, "failed", "refused", false]);
      assert.match(a.error, /secret output|outside a job/);
    }
    assert.deepEqual(await listed(out), []);
    const wrote = await ask({ ...whole, write_values: true }, JOB(out));
    assert.deepEqual([wrote.status, wrote.output.written, wrote.output.file_bytes, wrote.output.contains_secret_values], ["complete", true, 0x1000, true]);
    assert.match(wrote.output.note, /file_bytes is the length of the range that was asked for.*sha256 is in digests_in, with its size, and not in this answer/, "the note says what the answer gives");
    assert.doesNotMatch(JSON.stringify(wrote), /"sha256"\s*:/, "no digest of memory content is in the answer");
    assert.match(wrote.output.file, /^store\/jobs\/j000042\/out\/minidump_map\/read-[0-9a-f]+-4096\.bin$/);
    const name = wrote.output.file.split("/").pop() as string;
    const bytes = await readFile(join(out, "minidump_map", name));
    assert.ok(bytes.equals(s.payloadImage.subarray(0x1000, 0x2000)), "the file is the memory at that address");
    assert.equal((await stat(join(out, "minidump_map", name))).mode & 0o777, 0o600);
    assert.equal((await stat(join(out, "minidump_map"))).mode & 0o777, 0o700);
    // the digest is beside the file, never in the answer
    const digest = createHash("sha256").update(bytes).digest("hex");
    const manifest = (await readFile(join(out, "minidump_map", "manifest.jsonl"), "utf8")).trim().split("\n").map((l) => JSON.parse(l));
    assert.ok(manifest.some((m) => m.file === name && m.sha256 === digest && m.bytes === 0x1000));
    assert.doesNotMatch(JSON.stringify(wrote), /[0-9a-f]{64}/);
    // a second run does not replace the first
    const again = await ask({ ...whole, write_values: true }, JOB(out));
    assert.notEqual(again.output.file, wrote.output.file);
    assert.match(again.output.file, /read-[0-9a-f]+-4096-2\.bin$/);

    // across the gap: .text, the absent .rdata page, the start of .data
    const across = { path, view: "read", va: hex(s.payload + 0x1800n), length: 0x2000 };
    const dryGap = await ask(across);
    assert.deepEqual([dryGap.status, dryGap.coverage.bytes_present, dryGap.coverage.bytes_absent, dryGap.coverage.gaps, dryGap.coverage.coverage_percent], ["partial", 0x1000, 0x1000, 1, 50]);
    assert.deepEqual(dryGap.gaps.map((g: any) => [g.offset, g.va, g.bytes, g.state, g.why]), [[0x800, hex(s.payload + 0x2000n), 0x1000, "absent", "not in the dump"]]);
    const before = await listed(out);
    const refusedGap = await ask({ ...across, write_values: true }, JOB(out));
    assert.deepEqual([refusedGap.status, refusedGap.output.written, refusedGap.output.refused], ["partial", false, true]);
    assert.match(refusedGap.status_basis, /nothing was written: allow_gaps was not set/);
    assert.deepEqual(await listed(out), before, "a refusal writes nothing");
    const gappy = await ask({ ...across, write_values: true, allow_gaps: true }, JOB(out));
    assert.deepEqual([gappy.status, gappy.output.written, gappy.output.zero_filled_bytes], ["partial", true, 0x1000]);
    assert.match(gappy.output.file, /\.gaps\.bin$/, "the name itself says the file has gaps");
    assert.match(gappy.status_basis, /4096 of 8192 bytes \(50\.0000%\) are not in the dump: they are gaps, not zeros/);
    const got = await readFile(join(out, "minidump_map", gappy.output.file.split("/").pop()));
    const expect = Buffer.concat([s.payloadImage.subarray(0x1800, 0x2000), Buffer.alloc(0x1000), s.payloadImage.subarray(0x3000, 0x3800)]);
    assert.ok(got.equals(expect));
    const map = JSON.parse(await readFile(join(out, "minidump_map", gappy.output.map_file.split("/").pop()), "utf8"));
    assert.deepEqual([map.bytes_present, map.bytes_absent, map.file], [0x1000, 0x1000, gappy.output.file.split("/").pop()]);
    assert.deepEqual(map.segments.map((x: any) => [x.offset, x.bytes, x.state]), [[0, 0x800, "present"], [0x800, 0x1000, "absent"], [0x1800, 0x800, "present"]]);
    assert.deepEqual(map.segments.filter((x: any) => x.state === "present").map((x: any) => x.file_offset), [d.offsetOf(s.payload + 0x1800n), d.offsetOf(s.payload + 0x3000n)]);
    // a range with nothing in the dump
    const none = await ask({ path, view: "read", va: "0x10", length: 64, write_values: true, allow_gaps: true }, JOB(out));
    assert.deepEqual([none.status, none.coverage.bytes_present, none.output.written], ["partial", 0, false]);
    assert.equal((await listed(out)).filter((n) => n.split("/").pop()?.startsWith(".")).length, 0, "no hidden temporary file is left");
  }
});

test("module: the image as it lay in memory, with a coverage figure, the sections, and the gap mapped; a whole module is complete", async () => {
  for (const [path, d] of both()) {
    const s = d.scene;
    const out = await mkdtemp(join(dir, "out-module-"));
    const dry = await ask({ path, view: "module", module: "PAYLOAD.EXE" });
    assert.equal(dry.status, "partial");
    assert.deepEqual(dry.coverage, { bytes: 0x5000, bytes_present: 0x4000, bytes_absent: 0x1000, gaps: 1, coverage_percent: 80 });
    assert.deepEqual(dry.gaps.map((g: any) => [g.offset, g.bytes]), [[0x2000, 0x1000]]);
    assert.equal(dry.output.written, false);
    assert.deepEqual([dry.pe.read, dry.pe.machine, dry.pe.entry_point_rva, dry.pe.size_of_image, dry.pe.size_of_image_matches_module_list, dry.pe.timestamp_matches_module_list],
      [true, s.bits === 64 ? "0x8664" : "0x14c", "0x1000", 0x5000, true, true]);
    assert.deepEqual(dry.pe.sections.map((x: any) => [x.name, x.rva, x.virtual_size, x.bytes_in_dump, x.coverage_percent, x.executable, x.writable]),
      [[".text", "0x1000", 0x1000, 0x1000, 100, true, false], [".rdata", "0x2000", 0x1000, 0, 0, false, false], [".data", "0x3000", 0x2000, 0x2000, 100, false, true]]);
    const refused = await ask({ path, view: "module", base: hex(s.payload), write_values: true }, JOB(out));
    assert.deepEqual([refused.status, refused.output.written, refused.output.refused], ["partial", false, true]);
    assert.deepEqual(await listed(out), []);
    const wrote = await ask({ path, view: "module", module: s.imagePath, write_values: true, allow_gaps: true }, JOB(out));
    assert.deepEqual([wrote.status, wrote.output.written, wrote.output.file_bytes, wrote.output.zero_filled_bytes], ["partial", true, 0x5000, 0x1000]);
    assert.match(wrote.output.file, /module-[0-9a-f]+-20480\.gaps\.img$/);
    const image = await readFile(join(out, "minidump_map", wrote.output.file.split("/").pop()));
    const expect = Buffer.from(s.payloadImage);
    expect.fill(0, 0x2000, 0x3000);
    assert.ok(image.equals(expect), "present bytes are the image's, and the gap is zero in the file");
    assert.ok(!image.equals(s.payloadImage), "the gap's real bytes (which the process held) are not in the dump");
    const map = JSON.parse(await readFile(join(out, "minidump_map", wrote.output.map_file.split("/").pop()), "utf8"));
    assert.deepEqual(map.segments.map((x: any) => [x.offset, x.bytes, x.state]), [[0, 0x2000, "present"], [0x2000, 0x1000, "absent"], [0x3000, 0x2000, "present"]]);
    assert.equal(map.coverage_percent, 80);
    // a module that is whole
    const whole = await ask({ path, view: "module", module: "ntdll.dll", write_values: true }, JOB(out));
    assert.deepEqual([whole.status, whole.coverage.coverage_percent, whole.coverage.gaps, whole.output.written, whole.output.zero_filled_bytes], ["complete", 100, 0, true, undefined]);
    assert.match(whole.output.file, /module-[0-9a-f]+-16384\.img$/);
    assert.ok((await readFile(join(out, "minidump_map", whole.output.file.split("/").pop()))).equals(s.ntdllImage));
    assert.match(whole.status_basis, /every byte of the module's image \(16384 bytes at 0x[0-9a-f]+\) is in the dump and was written/);
    // names that do not resolve are refused as JSON
    for (const args of [{ module: "nosuch.dll" }, { base: hex(s.payload + 0x10n) }, { module: "x", base: 1 }, {}]) {
      const run = await call(dir, { path, view: "module", ...args });
      assert.deepEqual([run.code, doc(run).status], [1, "failed"], JSON.stringify(args));
    }
  }
});

test("find: a text needle as UTF-8 and UTF-16LE, a hex needle, a needle across two adjacent ranges, bounded hits with a resume address", async () => {
  for (const [path, d] of both()) {
    const s = d.scene;
    const sigma = await ask({ path, view: "find", needle: SIGMA });
    assert.equal(sigma.status, "complete");
    assert.deepEqual(sigma.hits.map((h: any) => [h.va, h.file_offset, h.form, h.bytes, h.module.name, h.module.rva, h.protect]),
      [[hex(s.payload + 0x3010n), d.offsetOf(s.payload + 0x3010n), "utf-8", 16, "payload.exe", "0x3010", "READWRITE"]]);
    assert.equal(d.file.subarray(sigma.hits[0].file_offset, sigma.hits[0].file_offset + 16).toString("latin1"), SIGMA, "the bytes at the reported offset are the needle");
    assert.deepEqual([sigma.page.total, sigma.page.returned, sigma.page.truncated, sigma.page.resume_va], [1, 1, false, null]);
    assert.equal(sigma.searched.bytes, d.mapped, "every byte the dump holds was searched");
    assert.doesNotMatch(JSON.stringify(sigma.hits), new RegExp(SIGMA), "a hit is a position, never content");
    const wide = await ask({ path, view: "find", needle: WIDE_NEEDLE });
    assert.deepEqual(wide.hits.map((h: any) => [h.va, h.file_offset, h.form, h.bytes, h.module]), [[hex(s.heap + 0x1800n), d.offsetOf(s.heap + 0x1800n), "utf-16le", 22, undefined]]);
    assert.deepEqual((await ask({ path, view: "find", needle: WIDE_NEEDLE, encodings: ["utf-8"] })).hits, []);
    const folded = await ask({ path, view: "find", needle: WIDE_NEEDLE.toUpperCase(), ignore_case: true });
    assert.deepEqual(folded.hits.map((h: any) => [h.va, h.form]), [[hex(s.heap + 0x1800n), "utf-16le"]]);
    assert.deepEqual((await ask({ path, view: "find", needle: WIDE_NEEDLE.toUpperCase() })).hits, []);
    // the needle starts six bytes before the end of one range and ends in the next, which is adjacent in the address space
    // (and, in the 32-bit dump, somewhere else in the file)
    const across = await ask({ path, view: "find", needle: STRADDLE });
    assert.deepEqual(across.hits.map((h: any) => [h.va, h.file_offset]), [[hex(s.heap + 0xffan), d.offsetOf(s.heap + 0xffan)]]);
    if (s.bits === 32) assert.notEqual(d.offsetOf(s.heap + 0x1000n), (d.offsetOf(s.heap + 0xfffn) as number) + 1, "the two ranges are apart in the file");
    // hex: the PE signature of both images, in address order
    const pe = await ask({ path, view: "find", needle_hex: "50 45 00 00" });
    assert.deepEqual(pe.hits.map((h: any) => h.va), [hex(s.payload + 0x80n), hex(s.ntdll + 0x80n)].sort((a, b) => (BigInt(a) < BigInt(b) ? -1 : 1)));
    // bounded: one hit a call, and the resume address reaches the rest
    const first = await ask({ path, view: "find", needle_hex: "50450000", max_hits: 1 });
    assert.deepEqual([first.status, first.page.returned, first.page.truncated, first.page.total], ["partial", 1, true, null]);
    assert.match(first.status_basis, /max_hits \(1\) was reached/);
    const rest = await ask({ path, view: "find", needle_hex: "50450000", max_hits: 1, va_start: first.page.resume_va });
    assert.deepEqual([rest.status, rest.hits.length, rest.page.resume_va], ["complete", 1, null]);
    assert.deepEqual([first.hits[0].va, rest.hits[0].va], pe.hits.map((h: any) => h.va));
    // what a stopped search says it searched is the memory below its resume address (it was 0 when max_hits stopped inside the first piece)
    assert.ok(first.searched.bytes > 0 && first.searched.bytes < d.mapped, `${first.searched.bytes}`);
    assert.equal(first.searched.bytes + rest.searched.bytes, d.mapped, "the two calls searched every byte once between them");
    // a window: only what lies inside it
    const window = await ask({ path, view: "find", needle_hex: "50450000", va_start: hex(s.ntdll), va_end: hex(s.ntdll + 0x1000n) });
    assert.deepEqual([window.hits.length, window.searched.bytes, window.status], [1, 0x1000, "complete"]);
    // a needle across the gap is not invented: the last bytes of .text and the first of .data are not adjacent
    const tail = s.payloadImage.subarray(0x1ffc, 0x2000), head = s.payloadImage.subarray(0x3000, 0x3004);
    assert.deepEqual((await ask({ path, view: "find", needle_hex: Buffer.concat([tail, head]).toString("hex") })).hits, []);
  }
});

test("a module whose name is shaped like a secret is withheld, cannot be guessed by name, and is named by its base", async () => {
  const s = scene(64, SECRET);
  const random = Array.from({ length: 24 }, (_, i) => (i % 3 === 2 ? "0123456789"[Math.floor(r() * 10)] : B62[Math.floor(r() * 62)])).join("");
  s.modules[1].name = `C:\\ProgramData\\${random}.dll`;
  const built = encode(s);
  await writeFile(join(dir, "inputs", "named.dmp"), built.file);
  const a = await ask({ path: "inputs/named.dmp", view: "modules" });
  assert.ok(!JSON.stringify(a).includes(random.slice(0, 12)) && !JSON.stringify(a).includes(random.slice(12)));
  assert.match(a.modules[1].name, /withheld \d+ characters/);
  const guess = await call(dir, { path: "inputs/named.dmp", view: "module", module: `${random}.dll` });
  assert.deepEqual([guess.code, doc(guess).status], [1, "failed"], "the withheld name answers no guess");
  const byBase = await ask({ path: "inputs/named.dmp", view: "module", base: a.modules[1].base });
  assert.deepEqual([byBase.status, byBase.coverage.coverage_percent], ["complete", 100]);
});

test("a truncated dump: the stream and the file offset are named, the answer is a truthful partial, and nothing is read as zero", async () => {
  for (const d of [d64, d32]) {
    const s = d.scene;
    const listName = s.bits === 64 ? "Memory64List" : "MemoryList";
    // (1) cut inside the memory: in the 64-bit dump the last range in address order is the last in the file; in the 32-bit one the first is
    const cutAt = d.file.length - 0x1800;
    await writeFile(join(dir, "inputs", "cut.dmp"), d.file.subarray(0, cutAt));
    const sum = await ask({ path: "inputs/cut.dmp" });
    assert.equal(sum.status, "partial");
    assert.equal(sum.counts.memory_ranges_cut_by_end_of_file, 1);
    assert.equal(sum.memory.declared_bytes, d.mapped);
    assert.equal(sum.memory.mapped_bytes, d.mapped - 0x1800);
    const fault = sum.problems.find((p: any) => p.stream === listName);
    assert.ok(fault && Number.isInteger(fault.file_offset) && /run past the end of the file/.test(fault.problem), JSON.stringify(sum.problems));
    assert.match(sum.status_basis, new RegExp(`truncated or malformed in ${listName}`));
    const lost = s.ranges.find((x) => (d.offsetOf(x.va) as number) < cutAt && (d.offsetOf(x.va) as number) + x.data.length > cutAt) as { va: bigint; data: Buffer };
    const lookedUp = await ask({ path: "inputs/cut.dmp", view: "va", addresses: [hex(lost.va), hex(lost.va + BigInt(lost.data.length - 1))] });
    assert.equal(lookedUp.status, "partial");
    assert.deepEqual([lookedUp.addresses[0].in_dump, lookedUp.addresses[0].file_offset], [true, d.offsetOf(lost.va)], "what the file still holds of the range is read");
    const lastByte = lookedUp.addresses[1];
    assert.deepEqual([lastByte.in_dump, lastByte.file_offset], [false, undefined]);
    assert.match(lastByte.why_not, /the file ends before these bytes \(a truncated dump\)/);
    const found = await ask({ path: "inputs/cut.dmp", view: "find", needle: SIGMA });
    assert.equal(found.status, "partial", "a search of a truncated dump is not complete");
    assert.equal(found.searched.bytes, d.mapped - 0x1800);

    // (2) cut inside the ModuleList: the entries before the cut are reported, the fault names the stream and where
    const inModules = d.streams.ModuleList.at + 4 + 108 + 40;
    await writeFile(join(dir, "inputs", "cut2.dmp"), d.file.subarray(0, inModules));
    const mods = await ask({ path: "inputs/cut2.dmp", view: "modules" });
    assert.equal(mods.status, "partial");
    assert.deepEqual(mods.modules.map((m: any) => [m.state, m.name]), [["loaded", "payload.exe"]], "the one whole entry is reported");
    const named = mods.problems.filter((p: any) => p.stream === "ModuleList");
    assert.ok(named.length >= 1 && named.every((p: any) => Number.isInteger(p.file_offset)), JSON.stringify(mods.problems));
    assert.ok(named.some((p: any) => p.file_offset === d.streams.ModuleList.at));
    for (const view of ["summary", "memory", "threads"]) assert.equal((await ask({ path: "inputs/cut2.dmp", view })).status, "partial", view);

    // (3) every cut of the file answers with one JSON document and no traceback
    const cuts = [0, 3, 4, 31, 32, 40, 32 + 12 * 11 - 1, d.streams.SystemInfo.at + 10, d.streams.ThreadList.at + 2, d.streams.MemoryInfoList.at + 20, d.streams.Exception.at + 100, d.memoryAt - 1, d.memoryAt + 1];
    for (const n of cuts) {
      await writeFile(join(dir, "inputs", "cut3.dmp"), d.file.subarray(0, n));
      for (const view of ["summary", "modules", "memory", "threads"]) {
        const run = await call(dir, { path: "inputs/cut3.dmp", view });
        const a = doc(run);
        assert.ok(n < 32 ? a.status === "failed" && run.code === 1 : a.status === "partial" && run.code === 0, `cut at ${n}, ${view}: ${a.status}`);
        if (n < 32) assert.match(a.error, n < 4 ? /not a minidump/ : /truncated minidump: the header is 32 bytes/);
      }
    }
  }
});

test("what is not a minidump, or a version this tool does not read, is refused; odd tables are bounded and said", async () => {
  const s = scene(64, SECRET);
  const put = async (name: string, data: Buffer): Promise<string> => { await writeFile(join(dir, "inputs", name), data); return `inputs/${name}`; };
  for (const [data, why] of [[Buffer.concat([Buffer.from("MZ"), Buffer.alloc(200)]), /begins with MZ/], [Buffer.concat([Buffer.from("PAGEDU64"), Buffer.alloc(200)]), /kernel crash dump/],
    [Buffer.alloc(0), /not a minidump/], [encode(s, { version: 0x1234 }).file, /version word is 0x1234/]] as Array<[Buffer, RegExp]>) {
    const run = await call(dir, { path: await put("not.dmp", data) });
    const a = doc(run);
    assert.deepEqual([run.code, a.status], [1, "failed"]);
    assert.match(a.error, why);
  }
  const missing = await call(dir, { path: "inputs/absent.dmp" });
  assert.deepEqual([missing.code, doc(missing).status], [1, "failed"]);
  assert.equal(doc(await call(dir, { path: "inputs" })).status, "failed", "a directory is refused");

  // a module count far above what the stream holds
  const big = Buffer.from(d64.file);
  big.writeUInt32LE(0xffffffff, d64.streams.ModuleList.at);
  const counted = await ask({ path: await put("count.dmp", big), view: "modules" });
  assert.equal(counted.status, "partial");
  assert.equal(counted.counts.loaded, 2, "the entries the stream has room for");
  assert.match(counted.problems[0].problem, /declares 4294967295 entries of 108 bytes and holds room for 2/);
  // a range count far above what the stream holds, and a range that claims the whole address space
  const ranges = Buffer.from(d64.file);
  ranges.writeBigUInt64LE(0xffffffffffffffffn, d64.streams.Memory64List.at);
  ranges.writeBigUInt64LE(0xffffffffffffffffn, d64.streams.Memory64List.at + 16 + 16 * 8 + 8);
  const wild = await ask({ path: await put("ranges.dmp", ranges) });
  assert.equal(wild.status, "partial");
  assert.equal(wild.counts.memory_ranges, 9);
  assert.equal(wild.memory.mapped_bytes, d64.mapped, "bytes the file does not hold are not counted as mapped");
  // a table whose header declares an entry of a gigabyte is not read, and is said
  const fat = Buffer.from(d64.file);
  fat.writeUInt32LE(0x40000000, d64.streams.MemoryInfoList.at + 4);
  const refusedTable = await ask({ path: await put("entry.dmp", fat), view: "memory" });
  assert.equal(refusedTable.status, "partial");
  assert.match(JSON.stringify(refusedTable.problems), /MemoryInfoList.*declares 1073741824 bytes an entry/);
  assert.equal(refusedTable.ranges[0].region, null);
  // two ranges over the same addresses: each address is read from one place, and the answer says there was a second copy
  const over = Buffer.from(d64.file);
  const first = d64.scene.ranges[0];
  over.writeBigUInt64LE(first.va + 0x800n, d64.streams.Memory64List.at + 16 + 16);
  const lapped = await ask({ path: await put("overlap.dmp", over) });
  assert.equal(lapped.status, "partial");
  assert.equal(lapped.counts.memory_ranges_overlapping, 1);
  assert.match(JSON.stringify(lapped.problems), /overlap a range that starts earlier/);
  // the comment the dump's writer left (procdump puts its command line there) is read, line by line, and judged like any string
  const noted = await ask({ path: await put("comment.dmp", encode(s, { comment: `*** "C:\\Tools\\procdump.exe" -ma 6068\r\n*** key=${SECRET}` }).file) });
  assert.deepEqual([noted.status, noted.header.streams, noted.comments[0].stream, noted.comments[0].lines[0]], ["complete", 12, "CommentW", '*** "C:\\Tools\\procdump.exe" -ma 6068']);
  assert.ok(!JSON.stringify(noted.comments).includes(SECRET.slice(4, 20)), "a secret-shaped part of a comment is withheld");
  assert.deepEqual(noted.streams_not_read, []);
  // a dump with no memory and no module list at all
  const bare = encode(s, { dropStreams: ["Memory64List", "ModuleList", "MemoryInfoList", "ThreadInfoList", "ThreadNames"] });
  const path = await put("bare.dmp", bare.file);
  const sum = await ask({ path });
  assert.deepEqual([sum.status, sum.dump_kind.kind, sum.memory.mapped_bytes, sum.process_parameters.reached], ["complete", "process dump without memory", 0, false]);
  assert.ok(["Memory64List", "MemoryList", "ModuleList", "MemoryInfoList"].every((n) => sum.streams_absent.includes(n)));
  assert.deepEqual((await ask({ path, view: "va", va: hex(s.payload) })).addresses[0].in_dump, false);
  assert.deepEqual((await ask({ path, view: "find", needle: SIGMA })).searched.bytes, 0);
  assert.equal(doc(await call(dir, { path, view: "module", module: "payload.exe" })).status, "failed");
  assert.equal(doc(await call(dir, { path, view: "memory", protect: "execute" })).status, "failed", "a filter the dump cannot answer is refused, not answered with nothing");
  assert.equal((await ask({ path, view: "threads" })).threads[0].info, undefined);
});

test("a dump with random bytes changed answers every view with one JSON document and no traceback (600 mutations)", { timeout: 600_000 }, async () => {
  const views = ["summary", "modules", "memory", "threads", "find", "module", "va", "read"];
  const failures: string[] = [];
  const rand = rng(77);
  const work: Array<{ name: string; args: Record<string, unknown> }> = [];
  for (let i = 0; i < 600; i++) {
    const d = i % 2 ? d64 : d32;
    const data = Buffer.from(d.file);
    const head = d.memoryAt;                                   // the streams, where a changed byte changes the parse
    const n = 1 + Math.floor(rand() * 6);
    for (let k = 0; k < n; k++) {
      const at = Math.floor(rand() * head);
      if (at < 4 && i % 10) continue;                          // most mutations keep the signature
      if (rand() < 0.5) data[at] = Math.floor(rand() * 256);
      else data.writeUInt32LE([0xffffffff, 0x7fffffff, 0, 0x80000000, d.file.length - 1][Math.floor(rand() * 5)], Math.min(at, head - 4));
    }
    const name = `fuzz-${i}.dmp`;
    await writeFile(join(dir, "inputs", name), data);
    const view = views[i % views.length];
    const extra: Record<string, unknown> = view === "find" ? { needle: "payload" } : view === "module" ? { base: hex(d.scene.payload) } : view === "va" ? { va: hex(d.scene.heap) }
      : view === "read" ? { va: hex(d.scene.payload), length: 0x5000 } : {};
    work.push({ name: `${name} ${view}`, args: { path: `inputs/${name}`, view, ...extra } });
  }
  let next = 0;
  await Promise.all(Array.from({ length: 8 }, async () => {
    while (next < work.length) {
      const w = work[next++];
      const run = await call(dir, w.args);
      try {
        const a = doc(run);
        if (!["complete", "partial", "failed"].includes(a.status) || typeof a.status_basis !== "string") failures.push(`${w.name}: status ${a.status}`);
        if (![0, 1].includes(run.code as number)) failures.push(`${w.name}: exit ${run.code}`);
        if (/unexpected failure/.test(a.error ?? "")) failures.push(`${w.name}: ${a.error} at line ${a.line}`);
        if (run.ms > 30_000) failures.push(`${w.name}: ${run.ms} ms`);
      } catch (e) {
        failures.push(`${w.name}: ${(e as Error).message.slice(0, 300)}`);
      }
    }
  }));
  assert.deepEqual(failures, []);
});

test("the script carries the shared blocks byte for byte, ends by its own exit, and the manifest says the rules a reader needs", async () => {
  const text = await readFile(SCRIPT, "utf8");
  const reference = await readFile(join(ROOT, "packs", "memory-forensics", "tools", "carve_handoff", "run.py"), "utf8");
  const block = (t: string, name: string): string => {
    const m = t.match(new RegExp(`# BEGIN SHARED ${name}\\n[\\s\\S]*?# END SHARED ${name}\\n`));
    assert.ok(m, `no ${name} block`);
    return m[0];
  };
  for (const name of ["ENDS", "WITHHOLDING", "SHOWN"]) assert.equal(block(text, name), block(reference, name), name);
  assert.ok(text.indexOf("# BEGIN SHARED ENDS\n") < text.search(/^(import [\w.]+|from [\w.]+ import )/m), "the ENDS block comes before the file's own imports");
  assert.match(text, /\n    _leave\(exit_code\)\n$/);
  assert.doesNotMatch(text, /ensure_ascii\s*=\s*False/);
  assert.doesNotMatch(text, /subprocess|os\.system|socket|urllib|start_new_session/, "it starts no program and uses no network");
  const manifest = JSON.parse(await readFile(join(TOOL_DIR, "manifest.json"), "utf8"));
  assert.equal(manifest.name, "minidump_map");
  assert.equal(String(manifest.version), (text.match(/^TOOL = (\d+)$/m) as RegExpMatchArray)[1], "the manifest's version is the script's");
  assert.equal(manifest.sha256, createHash("sha256").update(text).digest("hex"), "the manifest carries the digest of the script (pack.sh seal writes it)");
  assert.deepEqual(manifest.secret_output, { when_args: ["write_values"] });
  assert.equal(manifest.params.write_values.type, "boolean");
  assert.ok(manifest.timeout_seconds >= 300);
  for (const rule of [/not in the dump is not zero/i, /can have gaps/i, /allow_gaps/, /`find`/, /cipher_state_scan/, /not a memory image/i, /SENSITIVE/, /status partial/])
    assert.match(manifest.description, rule);
  for (const view of ["summary", "modules", "memory", "threads", "va", "read", "module", "find"]) assert.ok(manifest.description.includes(view), view);
  // every parameter the script takes is declared, and no other
  const taken = (text.match(/allowed = \{([^}]+)\}/) as RegExpMatchArray)[1].match(/"(\w+)"/g)!.map((x) => x.slice(1, -1)).sort();
  assert.deepEqual(Object.keys(manifest.params).sort(), taken);
  JSON.parse(manifest.example);
});

test("the count of bytes present (running totals) agrees with a walk of the ranges, on 20,000 random queries over ranges with cuts", () => {
  const code = [
    "import importlib.util, random, sys",
    "spec = importlib.util.spec_from_file_location('m', sys.argv[1]); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)",
    "rnd = random.Random(7); bad = 0",
    "for trial in range(200):",
    "    d = object.__new__(m.Dump); d.seg_va, d.seg_len, d.seg_have, d.seg_off, d.seg_sum = [], [], [], [], [0]",
    "    at = rnd.randrange(0, 50)",
    "    for i in range(rnd.randrange(0, 12)):",
    "        n = rnd.randrange(1, 40); have = n if rnd.random() < 0.7 else rnd.randrange(0, n + 1)",
    "        d.seg_va.append(at); d.seg_len.append(n); d.seg_have.append(have); d.seg_off.append(1000 * i); d.seg_sum.append(d.seg_sum[-1] + have)",
    "        at += n + (0 if rnd.random() < 0.3 else rnd.randrange(1, 30))",
    "    for q in range(100):",
    "        va = rnd.randrange(0, at + 60); n = rnd.randrange(1, 120)",
    "        walked = list(d.pieces(va, n))",
    "        bad += d.present(va, n) != sum(k for _v, k, off, _w in walked if off is not None)",
    "        bad += sum(k for _v, k, _o, _w in walked) != n or [v for v, _k, _o, _w in walked] != sorted(v for v, _k, _o, _w in walked)",
    "print(bad)",
  ].join("\n");
  const out = spawnSync(PYTHON3, ["-c", code, SCRIPT], { encoding: "utf8", env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1" } });
  assert.equal(out.status, 0, out.stderr);
  assert.equal(out.stdout.trim(), "0");
});

test("u32 and u64 of the generator write little-endian (the fixtures are what the format says, not what the tool reads)", () => {
  assert.deepEqual([...u32(0x504d444d)], [0x4d, 0x44, 0x4d, 0x50]);
  assert.deepEqual([...u64(0x0102030405060708n)], [8, 7, 6, 5, 4, 3, 2, 1]);
  assert.equal(d64.file.subarray(0, 4).toString("latin1"), "MDMP");
  assert.equal(d64.file.readUInt16LE(4), 0xa793);
  assert.equal(PAGE, 4096);
});

// ---- the findings of the first independent verification (2026-11-13), each on a dump built here ----

/** About 30 ms for the display rules to judge, and printable: thirty components of user-info-shaped pieces with a character NFKC makes long. */
const COSTLY = Array.from({ length: 30 }, () => "\ufdfa:\ufdfa@\ufdfa ".repeat(15)).join("\\");

test("module by name: 16,384 modules that share one costly name are answered at once, and names that have to be judged one by one end at max_seconds", { timeout: 300_000 }, async () => {
  const N = 16384;
  const shared = assemble((put) => {
    const costly = put(mdString(COSTLY));
    const real = put(mdString("C:\\Windows\\System32\\kernel32.dll"));
    return [{ type: 4, body: Buffer.concat([u32(N), ...Array.from({ length: N }, (_, i) => moduleEntry({ base: 0x10000n * BigInt(i + 1), size: 0x1000, nameRva: i === N - 1 ? real : costly }))]) }];
  });
  await writeFile(join(dir, "inputs", "manymods.dmp"), shared.file);
  // the name loop took 611.8 s on this shape with max_seconds 5 (one judgement of the same string for each module)
  const found = await call(dir, { path: "inputs/manymods.dmp", view: "module", module: "KERNEL32.dll", max_seconds: 5 });
  const fa = doc(found);
  assert.deepEqual([fa.module.name, fa.module.base, fa.coverage.bytes_present], ["kernel32.dll", hex(0x10000n * BigInt(N)), 0]);
  assert.ok(found.ms < 20_000, `the lookup took ${found.ms} ms`);
  const none = await call(dir, { path: "inputs/manymods.dmp", view: "module", module: "nosuch.dll", max_seconds: 5 });
  assert.deepEqual([none.code, doc(none).status], [1, "failed"]);
  assert.match(doc(none).error, /no module of the module list has that name/);
  assert.ok(none.ms < 20_000, `the lookup of a name no module has took ${none.ms} ms`);
  // 1,500 different costly names, and a name asked for that the cheap comparison cannot rule out (it begins as every one of them does and
  // then holds a placeholder): each has to be judged, which is 45 s of work, and the clock ends it with an answer that says so
  const M = 1500;
  const apart = assemble((put) => [{ type: 4, body: Buffer.concat([u32(M), ...Array.from({ length: M }, (_, i) => moduleEntry({ base: 0x10000n * BigInt(i + 1), size: 0x1000, nameRva: put(mdString(`a${i}\\${COSTLY}`)) }))]) }]);
  await writeFile(join(dir, "inputs", "slowmods.dmp"), apart.file);
  const slow = await call(dir, { path: "inputs/slowmods.dmp", view: "module", module: "a<x>", max_seconds: 1 });
  const sa = doc(slow);
  assert.deepEqual([slow.code, sa.status, sa.out_of_time, sa.modules], [1, "failed", true, M]);
  assert.match(sa.error, /max_seconds \(1\) was reached while the module names were compared with the one asked for \(\d+ of 1500 compared\): no module was chosen/);
  assert.ok(sa.compared > 0 && sa.compared < M, `${sa.compared} names were compared`);
  assert.ok(slow.ms < 15_000, `the call with max_seconds 1 took ${slow.ms} ms`);
  // a name that differs in its own text is ruled out without being judged: the same list answers at once
  const quick = await call(dir, { path: "inputs/slowmods.dmp", view: "module", module: "kernel32.dll", max_seconds: 1 });
  assert.match(doc(quick).error, /no module of the module list has that name/);
  // and a page of view modules over them ends at the clock with the rows it has and the offset of the next
  const page = doc(await call(dir, { path: "inputs/slowmods.dmp", view: "modules", limit: 1000, max_seconds: 1 }));
  assert.deepEqual([page.status, page.page.truncated, page.page.next_offset], ["partial", true, page.page.returned]);
});

test("find, stopped by the clock, by max_hits or by a read that fails, resumes where the unsearched bytes begin: the calls together give every hit once", { timeout: 300_000 }, async () => {
  const A = 0x100000n, C = 0x200000n;
  const ab = Buffer.alloc(1300, 0x2e), c = Buffer.alloc(500, 0x2e);       // A is 1,000 bytes, B the 300 after it (adjacent); C is elsewhere
  const narrow = Buffer.from("NeedleXY", "latin1"), wide = Buffer.from("NeedleXY", "utf16le");
  for (const at of [56, 250, 630, 990, 1270]) wide.copy(ab, at);           // across pieces of 64 bytes, and across A and B
  for (let at = 5; at + 8 <= 1300; at += 61) if (ab.subarray(at - 1, at + 9).every((b) => b === 0x2e)) narrow.copy(ab, at);
  narrow.copy(ab, 996);                                                     // across A and B
  Buffer.from("Need", "latin1").copy(ab, 1296);                             // the end of B and the start of C are not adjacent:
  Buffer.from("leXY", "latin1").copy(c, 0);                                 // this is no hit
  for (const at of [10, 60, 250, 492]) narrow.copy(c, at);
  const built = assemble(() => [{ type: 9, body: Buffer.concat([u64(3), u64(0), u64(A), u64(1000), u64(A + 1000n), u64(300), u64(C), u64(500)]) }], { flags: 2n, memory: Buffer.concat([ab, c]) });
  await writeFile(join(dir, "inputs", "chain.dmp"), built.file);
  // the hits, from the buffers: [va, form, file offset], in address order
  const expected: Array<[string, string, number]> = [];
  for (const [base, buf, fileAt] of [[A, ab, built.memoryAt], [C, c, built.memoryAt + 1300]] as Array<[bigint, Buffer, number]>)
    for (const [form, bytes] of [["utf-8", narrow], ["utf-16le", wide]] as Array<[string, Buffer]>)
      for (let at = buf.indexOf(bytes); at >= 0; at = buf.indexOf(bytes, at + 1)) expected.push([hex(base + BigInt(at)), form, fileAt + at]);
  expected.sort((x, y) => (BigInt(x[0]) < BigInt(y[0]) ? -1 : 1));
  assert.ok(expected.length > 25 && expected.some(([, form]) => form === "utf-16le"));
  const base = { path: "inputs/chain.dmp", view: "find", needle: "NeedleXY" };
  const whole = await ask(base);
  assert.deepEqual([whole.status, whole.searched.bytes], ["complete", 1800]);
  assert.deepEqual(whole.hits.map((h: any) => [h.va, h.form, h.file_offset]), expected);
  const chain = (more: Record<string, unknown>, mode: { chunk?: number; lateAfter?: number }): { hits: Array<[string, string, number]>; calls: number; searched: number; reasons: Set<string> } => {
    const hits: Array<[string, string, number]> = [];
    const reasons = new Set<string>();
    let start = "0x0", calls = 0, searched = 0;
    for (;;) {
      const a = inProcess(dir, { ...base, ...more, va_start: start }, mode);
      calls++;
      hits.push(...a.hits.map((h: any) => [h.va, h.form, h.file_offset] as [string, string, number]));
      searched += a.searched.bytes;
      if (a.page.resume_va === null) { assert.equal(a.status, "complete"); break; }
      assert.equal(a.status, "partial");
      reasons.add((a.status_basis.match(/stopped early: ([a-z_]+)/) as RegExpMatchArray)[1]);
      assert.match(a.page.how_to_continue, /every hit that starts below that address is in this answer and none that starts at or above it is/);
      assert.ok(a.hits.every((h: any) => BigInt(h.va) < BigInt(a.page.resume_va)), "no hit at or above the resume address is in the answer");
      assert.ok(BigInt(a.page.resume_va) > BigInt(start), `the resume address ${a.page.resume_va} is above ${start}`);
      start = a.page.resume_va;
      assert.ok(calls < 400);
    }
    return { hits, calls, searched, reasons };
  };
  // (1) the clock, looked at after every piece of 64 bytes: a hit across the resume address was lost (766 of 767 in the verifier's chain)
  for (const lateAfter of [1, 2, 5]) {
    const timed = chain({}, { chunk: 64, lateAfter });
    assert.deepEqual(timed.hits, expected, `lateAfter ${lateAfter}: every hit, in order, none twice`);
    assert.equal(timed.searched, 1800, "the calls searched every byte once between them");
    assert.ok(timed.calls > 5 && timed.reasons.has("max_seconds"), `${timed.calls} calls`);
  }
  // (2) max_hits, with two forms of different lengths around every piece boundary
  for (const max_hits of [1, 3]) {
    const counted = chain({ max_hits }, { chunk: 64 });
    assert.deepEqual(counted.hits, expected, `max_hits ${max_hits}`);
    assert.equal(counted.searched, 1800);
    assert.equal(counted.calls, Math.ceil(expected.length / max_hits), "a call stops at max_hits only when a further hit exists");
  }
  // (3) both at once
  assert.deepEqual(chain({ max_hits: 2 }, { chunk: 64, lateAfter: 3 }).hits, expected);
  // (4) a read that comes back short at file offset memory + 700: the search stops there, says so, and gives every hit below its resume
  // address; the search from that address (the file whole again) gives the rest
  const cut = inProcess(dir, base, { chunk: 64, failAt: built.memoryAt + 700 });
  assert.equal(cut.status, "partial");
  assert.match(cut.status_basis, new RegExp(`the dump could not be read at file offset ${built.memoryAt + 700}; memory from 0x[0-9a-f]+ on was not searched`));
  assert.match(JSON.stringify(cut.problems), /a read of 64 bytes returned 60/);
  const resume = BigInt(cut.page.resume_va);
  assert.ok(resume > A + 600n && resume <= A + 640n, `the resume address ${cut.page.resume_va} is at or before the piece that failed, by less than a needle`);
  assert.deepEqual(cut.hits.map((h: any) => h.va), expected.map((e) => e[0]).filter((va) => BigInt(va) < resume));
  assert.equal(cut.searched.bytes, Number(resume - A));
  const rest = await ask({ ...base, va_start: cut.page.resume_va });
  assert.equal(rest.status, "complete");
  assert.deepEqual([...cut.hits, ...rest.hits].map((h: any) => [h.va, h.form, h.file_offset]), expected);
});

test("find: the hits that start at one address (both forms of a one-character needle) are never split by a stop, and every chain gives each hit once and ends", { timeout: 300_000 }, async () => {
  // The verifier's dump: one range at 0x100000 holding `a\0` at +0x10, +0x20, +0x30 and `a` at +0x40. At each of the first three addresses
  // the needle "a" has two hits, UTF-16LE and UTF-8; with max_hits 1 the answer gave the UTF-16LE one and resume_va on the same address,
  // and the chain from there gave it again for ever.
  const A = 0x100000n;
  const mem = Buffer.alloc(0x80, 0x2e);
  for (const at of [0x10, 0x20, 0x30]) Buffer.from("a\0", "latin1").copy(mem, at);
  mem[0x40] = 0x61;
  const { head } = bareDump([{ va: A, size: mem.length }]);
  await writeFile(join(dir, "inputs", "groups.dmp"), Buffer.concat([head, mem]));
  const hitsOf = (buf: Buffer, base: bigint, forms: Array<[string, Buffer]>): Array<[string, string]> => {
    const out: Array<[bigint, string]> = [];
    for (const [form, bytes] of forms) for (let at = buf.indexOf(bytes); at >= 0; at = buf.indexOf(bytes, at + 1)) out.push([base + BigInt(at), form]);
    out.sort((x, y) => (x[0] !== y[0] ? (x[0] < y[0] ? -1 : 1) : x[1] < y[1] ? -1 : 1));     // utf-16le sorts before utf-8 at one address
    return out.map(([va, form]) => [hex(va), form]);
  };
  const one = (t: string): Array<[string, Buffer]> => [["utf-8", Buffer.from(t, "utf8")], ["utf-16le", Buffer.from(t, "utf16le")]];
  const expected = hitsOf(mem, A, one("a"));
  assert.deepEqual(expected.map((e) => e[0]), ["0x100010", "0x100010", "0x100020", "0x100020", "0x100030", "0x100030", "0x100040"]);
  type Answer = Record<string, any>;
  const chain = async (args: Record<string, unknown>, run: (a: Record<string, unknown>) => Promise<Answer> | Answer, limit = 50): Promise<{ hits: Array<[string, string]>; answers: Answer[] }> => {
    const hits: Array<[string, string]> = [];
    const answers: Answer[] = [];
    let start = "0x0";
    for (;;) {
      const a = await run({ ...args, va_start: start });
      answers.push(a);
      hits.push(...a.hits.map((h: any) => [h.va, h.form] as [string, string]));
      if (a.page.resume_va === null) { assert.equal(a.status, "complete"); break; }
      assert.equal(a.status, "partial");
      assert.ok(a.hits.length > 0, "a stop that is not the clock or a failed read gives at least one hit");
      assert.ok(a.hits.every((h: any) => BigInt(h.va) < BigInt(a.page.resume_va)), "no hit at or above the resume address is in the answer");
      assert.ok(BigInt(a.page.resume_va) > BigInt(start), `the resume address ${a.page.resume_va} is above ${start}`);
      start = a.page.resume_va;
      assert.ok(answers.length < limit, `the chain did not end in ${limit} calls (it gave ${hits.length} hits)`);
    }
    return { hits, answers };
  };
  const base = { path: "inputs/groups.dmp", view: "find", needle: "a" };
  for (const max_hits of [1, 2, 3, 4]) {
    for (const [how, run] of [["a call of the tool", (a: Record<string, unknown>) => ask(a)], ["pieces of 16 bytes", (a: Record<string, unknown>) => inProcess(dir, a, { chunk: 16 })]] as const) {
      const got = await chain({ ...base, max_hits }, run);
      assert.deepEqual(got.hits, expected, `max_hits ${max_hits}, ${how}: every hit once, in order`);
      for (const a of got.answers) {
        if (a.hits.length > max_hits) {
          assert.deepEqual([max_hits, a.hits.length, new Set(a.hits.map((h: any) => h.va)).size], [1, 2, 1], "only a group at the head passes max_hits");
          assert.match(a.page.same_address_note, /^the first 2 hits start at one address, 0x1000[1-3]0 \(one per form of the needle\): a stop never splits the hits at one address, so all of them are in this answer, past max_hits \(1\)$/);
        } else {
          assert.equal(a.page.same_address_note, undefined);
        }
      }
      // max_hits 1 and 2 give one address a call (the next would pass max_hits); 3 takes the last two addresses in one; 4 the first two
      assert.equal(got.answers.length, { 1: 4, 2: 4, 3: 3, 4: 2 }[max_hits], `max_hits ${max_hits}, ${how}: ${got.answers.length} calls`);
    }
  }
  // the page's byte ceiling, with a dense one-character needle (a hit of each form at every even address) and a module whose name escapes
  // to six bytes a character in JSON, so that 1,000 rows pass 256 KiB: the cut moves back to the first hit of its address
  const D = 0x200000n, size = 0x800;
  const dense = Buffer.from("Q\0".repeat(size / 2), "latin1");
  const longName = "C:\\Program Files\\" + "\u00e9".repeat(100) + ".dll";
  const dd = bareDump([{ va: D, size }], { module: { base: D, size, name: longName } });
  await writeFile(join(dir, "inputs", "dense.dmp"), Buffer.concat([dd.head, dense]));
  const denseExpected = hitsOf(dense, D, one("Q"));
  assert.equal(denseExpected.length, size);
  const cut = await chain({ path: "inputs/dense.dmp", view: "find", needle: "Q", max_hits: 1000 }, (a) => ask(a));
  assert.equal(cut.hits.length, denseExpected.length, "no hit twice");
  assert.deepEqual(cut.hits, denseExpected);
  assert.ok(cut.answers.length > 3 && cut.answers.slice(0, -1).every((a) => /stopped early: the answer reached 262144 bytes of JSON/.test(a.status_basis)), "the byte ceiling is what cut each page");
  for (const a of cut.answers) assert.equal(a.hits.length % 2, 0, "a page holds whole addresses: both forms of each");
  // a needle of several characters: its two forms never start at one address, so max_hits 1 gives one hit a call, as before
  const multi = Buffer.alloc(0x100, 0x2e);
  for (const at of [0x08, 0x40, 0x42, 0x90]) Buffer.from("ab", "latin1").copy(multi, at);
  for (const at of [0x20, 0x60, 0xc1]) Buffer.from("ab", "utf16le").copy(multi, at);
  const md = bareDump([{ va: A, size: multi.length }]);
  await writeFile(join(dir, "inputs", "multi.dmp"), Buffer.concat([md.head, multi]));
  const multiExpected = hitsOf(multi, A, one("ab"));
  assert.equal(multiExpected.length, 7);
  for (const [how, run] of [["a call of the tool", (a: Record<string, unknown>) => ask(a)], ["pieces of 16 bytes", (a: Record<string, unknown>) => inProcess(dir, a, { chunk: 16 })]] as const) {
    const got = await chain({ path: "inputs/multi.dmp", view: "find", needle: "ab", max_hits: 1 }, run);
    assert.deepEqual(got.hits, multiExpected, how);
    assert.equal(got.answers.length, multiExpected.length, `${how}: one hit a call`);
    assert.ok(got.answers.every((a) => a.hits.length === 1 && a.page.same_address_note === undefined));
  }
});

test("summary counts every handle's type: a type name that was not read, not listed or not readable is counted apart and the answer is partial", async () => {
  const handles = (types: number, o: { untyped?: number; lost?: number } = {}): Buffer => assemble((put) => {
    const rows: Buffer[] = [];
    for (let i = 0; i < 600; i++) rows.push(handleEntry(4 * (i + 1), put(mdString(`Type${i % types}`))));    // a string a handle, as a writer lays them out
    for (let i = 0; i < (o.untyped ?? 0); i++) rows.push(handleEntry(0x4000 + 4 * i, 0));
    for (let i = 0; i < (o.lost ?? 0); i++) rows.push(handleEntry(0x5000 + 4 * i, 0x7fff0000 + 64 * i));
    return [{ type: 12, body: Buffer.concat([u32(16), u32(32), u32(rows.length), u32(0), ...rows]) }];
  }).file;
  const expect300 = Object.fromEntries(Array.from({ length: 300 }, (_, i) => [`Type${i}`, 2]));
  // 300 names over 600 strings: the 44 names past the 256 most frequent RVAs were "without a type name", with status complete
  await writeFile(join(dir, "inputs", "handles.dmp"), handles(300, { untyped: 5 }));
  const all = await ask({ path: "inputs/handles.dmp" });
  assert.equal(all.status, "complete", JSON.stringify(all.problems));
  assert.deepEqual(all.handles.by_type, expect300);
  assert.deepEqual([all.handles.handles, all.handles.without_a_type_name, all.handles.type_name_unreadable, all.handles.type_name_not_listed, all.handles.type_name_not_read, all.handles.type_name_strings_read],
    [605, 5, 0, 0, 0, 600]);
  // three handles whose type name is past the end of the file: counted apart, each in problems, and the answer is partial
  await writeFile(join(dir, "inputs", "handles-lost.dmp"), handles(300, { untyped: 5, lost: 3 }));
  const lost = await ask({ path: "inputs/handles-lost.dmp" });
  assert.equal(lost.status, "partial");
  assert.deepEqual(lost.handles.by_type, expect300);
  assert.deepEqual([lost.handles.without_a_type_name, lost.handles.type_name_unreadable], [5, 3]);
  assert.equal(lost.problems.filter((x: any) => x.stream === "HandleData" && /a handle's type name: a MINIDUMP_STRING declared at file offset \d+, at or past the end of the file/.test(x.problem)).length, 3);
  assert.match(lost.status_basis, /the handle count by type is not whole: 0 handle\(s\) have a type name that was not read, 0 one past the names listed, 3 one the file does not hold/);
  // more distinct names than the answer lists: the handles of the names past the bound are counted apart, and said
  await writeFile(join(dir, "inputs", "handles-many.dmp"), handles(600, { untyped: 5 }));
  const many = await ask({ path: "inputs/handles-many.dmp" });
  assert.equal(many.status, "partial");
  assert.deepEqual([Object.keys(many.handles.by_type).length, many.handles.type_name_not_listed, many.handles.without_a_type_name, many.handles.type_names_listed_at_most], [512, 88, 5, 512]);
  assert.match(JSON.stringify(many.problems), /more than 512 distinct type names: 88 handle\(s\)/);
  // the clock: after a hundred strings it is over; the 500 handles left are "type name not read", never "without a type name"
  const timed = inProcess(dir, { path: "inputs/handles.dmp" }, { lateAfter: 101 });
  assert.equal(timed.status, "partial");
  assert.deepEqual([timed.handles.type_name_strings_read, timed.handles.type_name_not_read, timed.handles.without_a_type_name], [100, 500, 5]);
  assert.equal(Object.values(timed.handles.by_type as Record<string, number>).reduce((n, v) => n + v, 0), 100);
  assert.match(JSON.stringify(timed.problems), /max_seconds was reached after the type names at 100 of 600 distinct TypeNameRva values were read: 500 handle\(s\)/);
});

test("modules: a PDB record that is declared and cannot be read whole is in problems and partial, and is told apart from a module without one; a cut path says so", async () => {
  const longPath = "D:\\" + Array.from({ length: 30 }, (_, i) => `build directory ${i}`).join("\\") + "\\payload.pdb";       // 608 characters, no component over 128
  assert.ok(longPath.length > 560);
  const rsds = (path: string, nul = true): Buffer => Buffer.concat([Buffer.from("RSDS"), Buffer.from("00112233445566778899aabbccddeeff", "hex"), u32(7), Buffer.from(path + (nul ? "\0" : ""), "utf8")]);
  const build = (kinds: string[]): { file: Buffer; memoryAt: number; at: Record<number, number> } => assemble((put) => {
    const name = kinds.map((k, i) => put(mdString(`C:\\app\\m${i}-${k}.dll`)));
    const cv: Record<string, [number, number]> = {
      none: [0, 0], past: [64, 0x7fff0000], cut: [64, 0],                 // "cut" is pointed at the last ten bytes of the file below
      long: [24 + longPath.length + 1, put(rsds(longPath))], good: [24 + 7, put(rsds("ok.pdb"))], nb10: [30, put(Buffer.concat([Buffer.from("NB10"), Buffer.alloc(26, 0x61)]))],
    };
    return [{ type: 4, body: Buffer.concat([u32(kinds.length), ...kinds.map((k, i) => moduleEntry({ base: 0x10000n * BigInt(i + 1), size: 0x1000, nameRva: name[i], cv: cv[k] }))]) }];
  }, { memory: Buffer.concat([Buffer.from("RSDS"), Buffer.alloc(6, 1)]) });
  const kinds = ["none", "past", "cut", "long", "good", "nb10"];
  const bad = build(kinds);
  bad.file.writeUInt32LE(bad.memoryAt, bad.at[4] + 4 + 108 * 2 + 80);        // the CvRecord RVA of module 2: ten bytes before the end of the file
  await writeFile(join(dir, "inputs", "cv.dmp"), bad.file);
  const a = await ask({ path: "inputs/cv.dmp", view: "modules" });
  assert.equal(a.status, "partial");
  assert.match(a.status_basis, /malformed in ModuleList/);
  const [none, past, cut, long, good, nb10] = a.modules;
  assert.deepEqual(a.modules.map((m: any) => m.pdb_record), ["none declared", "declared, not readable", "declared, not readable", "read", "read", "read, not RSDS"]);
  assert.equal(none.pdb, null);
  assert.deepEqual([past.pdb.read, past.pdb.format, past.pdb.declared_bytes, past.pdb.file_offset], [false, null, 64, 0x7fff0000]);
  assert.match(past.pdb.why_not, /at or past the end of the file \(\d+ bytes\): not read \(problems\)\. A record is declared, so this is not an entry without one/);
  assert.equal(past.pdb.location, "declared_not_readable");
  assert.deepEqual([cut.pdb.read, cut.pdb.format, cut.pdb.file_offset], [false, "RSDS", bad.memoryAt], "the record begins with RSDS and the file ends ten bytes into it");
  assert.deepEqual([long.pdb.read, long.pdb.format, long.pdb.age, long.pdb.path_cut, long.pdb.path_bytes_read, long.pdb.path], [true, "RSDS", 7, true, 520, longPath.slice(0, 520)]);
  assert.match(long.pdb.path_note, /the first 520 bytes of its path were read and the path does not end in them/);
  assert.deepEqual([good.pdb.read, good.pdb.path, good.pdb.path_cut, good.pdb.guid], [true, "ok.pdb", false, "33221100554477668899AABBCCDDEEFF"]);
  assert.deepEqual([nb10.pdb.read, nb10.pdb.format], [true, "not RSDS"]);
  const said = a.problems.map((x: any) => [x.stream, x.file_offset, x.problem.replace(/:.*/, "")]);
  assert.deepEqual(said, [["ModuleList", 0x7fff0000, "the CodeView (PDB) record of module 1"], ["ModuleList", bad.memoryAt, "the CodeView (PDB) record of module 2"],
    ["ModuleList", long.pdb.file_offset, "the CodeView (PDB) record of module 3"]]);
  assert.match(a.problems[1].problem, /64 bytes declared at file offset \d+ and the file \(\d+ bytes\) ends 10 bytes into it/);
  // the same list without the three faulty records is complete, and a module with no record is still "none declared"
  await writeFile(join(dir, "inputs", "cv-ok.dmp"), build(["none", "good", "nb10"]).file);
  const ok = await ask({ path: "inputs/cv-ok.dmp", view: "modules" });
  assert.deepEqual([ok.status, ok.problems, ok.modules.map((m: any) => m.pdb_record)], ["complete", [], ["none declared", "read", "read, not RSDS"]]);
  // view module reads the same record: a module whose record cannot be read is partial there too
  const one = await ask({ path: "inputs/cv.dmp", view: "module", base: "0x20000" });
  assert.deepEqual([one.module.pdb_record, one.status], ["declared, not readable", "partial"]);
  // a record whose first bytes are in the file and whose declared end is past it: what was read is printed, cut_by_file says so, partial
  const pad = assemble((put) => {
    const name = put(mdString("C:\\app\\m0-good.dll"));
    const cvAt = put(rsds("ok.pdb"));
    return [{ type: 4, body: Buffer.concat([u32(1), moduleEntry({ base: 0x10000n, size: 0x1000, nameRva: name, cv: [24 + 7, cvAt] })]) }];
  }, { memory: Buffer.alloc(1000) });
  const cvSizeAt = pad.at[4] + 4 + 76;
  const cvRva = pad.file.readUInt32LE(cvSizeAt + 4);
  const avail = pad.file.length - cvRva;
  assert.ok(avail >= 544, "the file holds the bytes the reader takes of the record");
  pad.file.writeUInt32LE(avail + 100, cvSizeAt);
  await writeFile(join(dir, "inputs", "cv-past-end.dmp"), pad.file);
  const past2 = await ask({ path: "inputs/cv-past-end.dmp", view: "modules" });
  assert.deepEqual([past2.status, past2.modules[0].pdb_record, past2.modules[0].pdb.read, past2.modules[0].pdb.cut_by_file, past2.modules[0].pdb.path],
    ["partial", "read", true, true, "ok.pdb"]);
  assert.match(JSON.stringify(past2.problems), /\d+ bytes declared at file offset \d+ and the file \(\d+ bytes\) ends \d+ bytes into it/);
});

test("memory: the protect and type filters ask every region a range lies over, and the row says which part met them", async () => {
  // range 1 lies over a READWRITE and an EXECUTE_READWRITE private region (a writer joins neighbours); range 2 over a READWRITE private
  // region and an EXECUTE_READ image one
  const regions = [{ base: 0x10000n, size: 0x1000, protect: RW, type: PRIVATE }, { base: 0x11000n, size: 0x1000, protect: RWX, type: PRIVATE },
    { base: 0x20000n, size: 0x1000, protect: RW, type: PRIVATE }, { base: 0x21000n, size: 0x1000, protect: RX, type: IMAGE }];
  const build = (order: typeof regions): Buffer => assemble(() => [
    { type: 16, body: Buffer.concat([u32(16), u32(48), u64(order.length), ...order.map(memoryInfo)]) },
    { type: 9, body: Buffer.concat([u64(2), u64(0), u64(0x10000n), u64(0x2000), u64(0x20000n), u64(0x2000)]) },
  ], { flags: 2n, memory: Buffer.alloc(0x4000, 0x90) }).file;
  await writeFile(join(dir, "inputs", "joined.dmp"), build(regions));
  const path = "inputs/joined.dmp";
  const rwx = await ask({ path, view: "memory", protect: "execute_write", type: "private" });
  assert.equal(rwx.status, "complete");
  assert.deepEqual(rwx.ranges.map((x: any) => [x.va, x.bytes, x.region.protect, x.regions_spanned]), [["0x10000", 0x2000, "READWRITE", 2]], "the range was not returned: its first region is READWRITE");
  assert.deepEqual(rwx.ranges[0].matched, { regions: 1, bytes: 0x1000, whole_range: false,
    first: { va: "0x11000", end: "0x12000", region: { base: "0x11000", bytes: 0x1000, state: "COMMIT", protect: "EXECUTE_READWRITE", type: "PRIVATE", allocation_base: "0x11000", allocation_protect: "READWRITE" } } });
  assert.deepEqual([rwx.totals.ranges, rwx.totals.ranges_matching, rwx.page.total], [2, 1, 1]);
  assert.match(rwx.filter.rule, /any region it overlaps meets the filter/);
  // list regions and list ranges agree
  const asRegions = await ask({ path, view: "memory", protect: "execute_write", type: "private", list: "regions" });
  assert.deepEqual(asRegions.regions.map((x: any) => x.base), ["0x11000"]);
  // the two filters are asked of the same region: range 2 has a writable region and an executable one, and no region that is both
  assert.deepEqual((await ask({ path, view: "memory", protect: "execute_write" })).ranges.map((x: any) => x.va), ["0x10000"]);
  assert.deepEqual((await ask({ path, view: "memory", protect: "execute", type: "private" })).ranges.map((x: any) => x.va), ["0x10000"]);
  const exec = await ask({ path, view: "memory", protect: "execute" });
  assert.deepEqual(exec.ranges.map((x: any) => [x.va, x.matched.first.va, x.matched.first.region.type, x.matched.bytes]), [["0x10000", "0x11000", "PRIVATE", 0x1000], ["0x20000", "0x21000", "IMAGE", 0x1000]]);
  const write = await ask({ path, view: "memory", protect: "write" });
  assert.deepEqual(write.ranges.map((x: any) => [x.va, x.matched.regions, x.matched.bytes, x.matched.whole_range]), [["0x10000", 2, 0x2000, true], ["0x20000", 1, 0x1000, false]]);
  assert.equal((await ask({ path, view: "memory" })).ranges[0].matched, undefined, "without a filter there is no matched part");
  // a MemoryInfoList that is not in address order gives the same rows, and the answer says it was sorted
  await writeFile(join(dir, "inputs", "unsorted.dmp"), build([...regions].reverse()));
  const unsorted = await ask({ path: "inputs/unsorted.dmp", view: "memory", protect: "execute_write", type: "private" });
  assert.deepEqual(unsorted.ranges.map((x: any) => [x.va, x.matched.first.va]), [["0x10000", "0x11000"]]);
  assert.equal(unsorted.status, "partial");
  assert.match(JSON.stringify(unsorted.problems), /MemoryInfoList.*the regions are not in address order \(entry 1, at 0x20000, comes after one at 0x21000\): they were sorted/);
});

test("smaller truths: a ThreadExList beside a ThreadList, names the summary does not read, and a Windows path of more than 128 characters", async () => {
  // both thread lists: the ThreadList is the one read, and the other is named as not read
  const lists = (types: number[]): Buffer => assemble(() => types.map((type) => ({ type, body: u32(0) }))).file;
  await writeFile(join(dir, "inputs", "threads-both.dmp"), lists([3, 8]));
  const bothLists = await ask({ path: "inputs/threads-both.dmp" });
  assert.deepEqual(bothLists.streams_not_read, ["ThreadExList"]);
  assert.match(bothLists.streams_not_read_note, /the threads are read from the ThreadList/);
  await writeFile(join(dir, "inputs", "threads-ex.dmp"), lists([8]));
  const exOnly = await ask({ path: "inputs/threads-ex.dmp" });
  assert.deepEqual([exOnly.streams_not_read, exOnly.streams_not_read_note], [[], undefined], "alone, the ThreadExList is the list that is read");
  // a module whose name RVA is outside the file: the summary does not read names and says so; view modules reads them and is partial
  const longPath = "C:\\Program Files\\Vendor Suite\\" + Array.from({ length: 8 }, (_, i) => `component directory ${i}`).join("\\") + "\\library.dll";
  assert.ok(longPath.length > 128 && !longPath.includes("/"));
  const mods = assemble((put) => [{ type: 4, body: Buffer.concat([u32(2), moduleEntry({ base: 0x10000n, size: 0x1000, nameRva: 0x7ffffff0 }), moduleEntry({ base: 0x20000n, size: 0x1000, nameRva: put(mdString(longPath)) })]) }]).file;
  await writeFile(join(dir, "inputs", "names.dmp"), mods);
  const sum = await ask({ path: "inputs/names.dmp" });
  assert.equal(sum.status, "complete");
  assert.match(sum.status_basis, /module names, PDB records and thread contexts are not read in this view/);
  assert.match(sum.not_read_in_this_view, /a module's name and PDB record.*are read by the views modules and threads/);
  const listed = await ask({ path: "inputs/names.dmp", view: "modules" });
  assert.equal(listed.status, "partial");
  assert.deepEqual([listed.modules[0].name, listed.modules[0].name_why_not], [null, "the name string at file offset 2147483632 could not be read (problems)"]);
  // the long path: every component is short, so it is printed (it was withheld whole, as one component, for want of a `/`), and it names the module
  assert.deepEqual([listed.modules[1].name, listed.modules[1].path], ["library.dll", longPath]);
  const byPath = await ask({ path: "inputs/names.dmp", view: "module", module: longPath.toUpperCase() });
  assert.equal(byPath.module.base, "0x20000");
  // a component of more than 128 characters is still withheld, and so is a long path with a token in it
  const tokenish = Array.from({ length: 28 }, (_, i) => (i % 5 === 4 ? "0123456789"[Math.floor(r() * 10)] : B62[Math.floor(r() * 62)])).join("");
  const held = assemble((put) => [{ type: 4, body: Buffer.concat([u32(2),
    moduleEntry({ base: 0x10000n, size: 0x1000, nameRva: put(mdString(`C:\\Users\\bob\\${"d".repeat(129)}\\x.dll`)) }),
    moduleEntry({ base: 0x20000n, size: 0x1000, nameRva: put(mdString(`${longPath.slice(0, -12)}\\${tokenish}\\y.dll`)) })]) }]).file;
  await writeFile(join(dir, "inputs", "held.dmp"), held);
  const kept = await ask({ path: "inputs/held.dmp", view: "modules" });
  assert.match(kept.modules[0].path, /^<withheld \d+ characters: a component over 128 characters>$/);
  assert.equal(kept.modules[0].name, "x.dll");
  for (let i = 0; i + 12 <= tokenish.length; i++) assert.ok(!JSON.stringify(kept).includes(tokenish.slice(i, i + 12)), `a piece of the token at ${i}`);
  assert.match(kept.modules[1].path, /^<withheld \d+ characters: /, "the backstop reads the path as it stands and calls the token a secret: withheld whole");
});

/**
 * Every (size, RVA) location the tool follows, laid out here from the published layouts: a thread's context and stack (MINIDUMP_THREAD:
 * the stack descriptor at +24, the context's size and RVA at +40), the exception's context (MINIDUMP_EXCEPTION_STREAM +160), a memory
 * descriptor, a thread's, a module's and a handle type's name, a CodeView record and a stream of the directory. Each is pointed at RVA 0
 * (the header), past the end of the file, at a record the file cuts and at one smaller than its type; each must be partial, named in
 * problems, and never said to be absent.
 */
type Where = number | "here" | "tail" | "past";
const NOT_ABSENT = /no context record|has no context|gives no name|none is declared/;
const sysInfo = (put: (b: Buffer) => number, arch: number): Buffer =>
  Buffer.concat([u16(arch), u16(6), u16(0x9e0d), Buffer.from([8, 1]), u32(10), u32(0), u32(19045), u32(2), u32(put(mdString("Service Pack 1"))), u16(0x100), u16(0), Buffer.alloc(24)]);
/** A CONTEXT of `bytes` bytes (an x64 one has its rip at 0xf8 and rsp at 0x98; an x86 one its eip at 0xb8 and esp at 0xc4). */
const ctxBytes = (bits: 32 | 64, bytes: number): Buffer => {
  const c = Buffer.alloc(Math.max(bytes, 0x100));
  if (bits === 64) { c.writeBigUInt64LE(0x7ff6a1b21234n, 0xf8); c.writeBigUInt64LE(0xe51f701f00n, 0x98); } else { c.writeUInt32LE(0x401234, 0xb8); c.writeUInt32LE(0x18ff00, 0xc4); }
  return c.subarray(0, bytes);
};
/** A dump with SystemInfo and one thread (ThreadList, or ThreadExList with `ex`), its context and stack placed by `ctx` and `stack`. */
function threadDump(bits: 32 | 64, ctx: { size: number; at: Where; body?: Buffer }, stack: { size: number; at: Where }, o: { ex?: boolean; tail?: Buffer } = {}): Buffer {
  let ctxAt = 0, stackAt = 0;
  const built = assemble((put) => {
    if (ctx.at === "here") ctxAt = put(ctx.body ?? ctxBytes(bits, ctx.size));
    if (stack.at === "here") stackAt = put(Buffer.alloc(stack.size, 0x5a));
    const entry = Buffer.concat([u32(77), u32(0), u32(0x20), u32(8), u64(bits === 64 ? 0xe51f400000n : 0x7ffde000n), u64(bits === 64 ? 0xe51f700000n : 0x18e000n),
      u32(stack.size), u32(stackAt), u32(ctx.size), u32(ctxAt), ...(o.ex ? [u64(0), u32(0), u32(0)] : [])]);
    return [{ type: 7, body: sysInfo(put, bits === 64 ? 9 : 0) }, { type: o.ex ? 8 : 3, body: Buffer.concat([u32(1), entry]) }];
  }, { memory: o.tail });
  const entry = built.at[o.ex ? 8 : 3] + 4;
  const place = (w: Where, field: number): void => {
    if (typeof w === "number") built.file.writeUInt32LE(w, entry + field);
    else if (w === "tail") built.file.writeUInt32LE(built.memoryAt, entry + field);
    else if (w === "past") built.file.writeUInt32LE(built.file.length + 4096, entry + field);
  };
  place(ctx.at, 44);
  place(stack.at, 36);
  return built.file;
}
const goodStack = { size: 0x200, at: "here" as Where };
const declaredFault = (a: Record<string, any>, stream: string, what: RegExp): void => {
  assert.equal(a.status, "partial", JSON.stringify(a.problems));
  assert.match(a.status_basis, new RegExp(`malformed in [^;]*${stream}`));
  assert.ok(a.problems.some((x: any) => x.stream === stream && what.test(x.problem) && Number.isInteger(x.file_offset)), JSON.stringify(a.problems));
};

test("a thread's context at RVA 0, past the file, cut by the file or smaller than its architecture's CONTEXT is partial, named, and never decoded as one", async () => {
  const at = async (name: string, file: Buffer, view = "threads"): Promise<Record<string, any>> => { await writeFile(join(dir, "inputs", name), file); return ask({ path: `inputs/${name}`, view }); };
  // a clean x64 and x86 thread: complete, decoded, the stack read from its descriptor
  for (const bits of [64, 32] as const) {
    const ok = await at(`ctx-ok-${bits}.dmp`, threadDump(bits, { size: bits === 64 ? 1232 : 716, at: "here" }, goodStack));
    assert.deepEqual([ok.status, ok.problems, ok.threads[0].context.location, ok.threads[0].context.decoded, ok.threads[0].stack.location, ok.threads[0].stack.bytes_in_file],
      ["complete", [], "read", true, "read", 0x200]);
    assert.equal(ok.threads[0].context.layout, bits === 64 ? "x64 CONTEXT" : "x86 CONTEXT");
  }
  // declared and not readable: RVA 0, past the file, undersized for the architecture (in ThreadList and ThreadExList)
  const cases: Array<[string, 32 | 64, { size: number; at: Where }, RegExp]> = [
    ["x64 at RVA 0", 64, { size: 1232, at: 0 }, /context of thread 77 \(entry 0\): 1232 bytes declared at file offset 0, where the file's header is/],
    ["x86 at RVA 0", 32, { size: 716, at: 0 }, /context of thread 77 \(entry 0\): 716 bytes declared at file offset 0/],
    ["x64 past the file", 64, { size: 1232, at: "past" }, /1232 bytes declared at file offset \d+, at or past the end of the file/],
    ["x64 of 128 bytes", 64, { size: 128, at: "here" }, /128 bytes are declared and an x64 CONTEXT needs at least 1232/],
    ["x86 of 100 bytes", 32, { size: 100, at: "here" }, /100 bytes are declared and an x86 CONTEXT needs at least 716/],
    ["x64 of 716 bytes", 64, { size: 716, at: "here" }, /716 bytes are declared and an x64 CONTEXT needs at least 1232/],
  ];
  for (const ex of [false, true]) {
    for (const [label, bits, ctx, what] of cases) {
      const a = await at("ctx-bad.dmp", threadDump(bits, ctx, goodStack, { ex }));
      const stream = ex ? "ThreadExList" : "ThreadList";
      declaredFault(a, stream, what);
      const c = a.threads[0].context;
      assert.deepEqual([c.location, c.decoded, c.layout, c.registers, a.threads[0].instruction_pointer_in_module], ["declared_not_readable", false, undefined, undefined, undefined], `${label} (${stream})`);
      assert.match(c.why_not, /not read/);
      assert.doesNotMatch(JSON.stringify(a.threads[0]), NOT_ABSENT, label);
    }
  }
  // cut by the file: the registers are decoded when the bytes the file holds reach them, and the answer is partial either way
  const cut300 = await at("ctx-cut.dmp", threadDump(64, { size: 1232, at: "tail" }, goodStack, { tail: ctxBytes(64, 300) }));
  declaredFault(cut300, "ThreadList", /1232 bytes declared at file offset \d+ and the file \(\d+ bytes\) ends 300 bytes into it/);
  assert.deepEqual([cut300.threads[0].context.location, cut300.threads[0].context.cut_by_file, cut300.threads[0].context.decoded, cut300.threads[0].context.registers.rip],
    ["cut_by_file", true, true, "0x7ff6a1b21234"]);
  const cut100 = await at("ctx-cut2.dmp", threadDump(64, { size: 1232, at: "tail" }, goodStack, { tail: ctxBytes(64, 100) }));
  declaredFault(cut100, "ThreadList", /ends 100 bytes into it/);
  assert.deepEqual([cut100.threads[0].context.location, cut100.threads[0].context.decoded], ["cut_by_file", false]);
  assert.match(cut100.threads[0].context.why_not, /the file ends 100 bytes into the record/);
  // none declared: 0 bytes (at RVA 0, or at an RVA) is no record and no fault, said as what the entry declares
  const none = await at("ctx-none.dmp", threadDump(64, { size: 0, at: 0 }, goodStack));
  assert.deepEqual([none.status, none.threads[0].context.location, none.threads[0].context.why_not], ["complete", "none", "none is declared (0 bytes at RVA 0)"]);
  const zero = await at("ctx-zero.dmp", threadDump(64, { size: 0, at: 64 }, goodStack));
  assert.deepEqual([zero.status, zero.threads[0].context.location], ["complete", "none"]);
  assert.match(zero.threads[0].context.why_not, /^0 bytes are declared \(at file offset 64\)/);
});

test("a thread's stack descriptor at RVA 0 or past the file holds no byte of the file; one the file cuts holds what it holds; each is partial", async () => {
  const ctx = { size: 1232, at: "here" as Where };
  const at = async (name: string, file: Buffer): Promise<Record<string, any>> => { await writeFile(join(dir, "inputs", name), file); return ask({ path: `inputs/${name}`, view: "threads" }); };
  const zero = await at("stack-0.dmp", threadDump(64, ctx, { size: 0x1000, at: 0 }));
  declaredFault(zero, "ThreadList", /the stack of thread 77 \(entry 0\): 4096 bytes declared at file offset 0, where the file's header is/);
  assert.deepEqual([zero.threads[0].stack.location, zero.threads[0].stack.bytes_in_file, zero.threads[0].stack.bytes_in_memory_lists], ["declared_not_readable", 0, 0],
    "the header's bytes are not the stack's");
  const past = await at("stack-past.dmp", threadDump(64, ctx, { size: 0x1000, at: "past" }));
  declaredFault(past, "ThreadList", /the stack of thread 77 \(entry 0\): 4096 bytes declared at file offset \d+, at or past the end of the file/);
  assert.deepEqual([past.threads[0].stack.location, past.threads[0].stack.bytes_in_file], ["declared_not_readable", 0]);
  const cut = await at("stack-cut.dmp", threadDump(64, ctx, { size: 0x1000, at: "tail" }, { tail: Buffer.alloc(100, 0x5a) }));
  declaredFault(cut, "ThreadList", /the stack of thread 77 \(entry 0\): 4096 bytes declared at file offset \d+ and the file \(\d+ bytes\) ends 100 bytes into it/);
  assert.deepEqual([cut.threads[0].stack.location, cut.threads[0].stack.bytes_in_file], ["cut_by_file", 100]);
  for (const a of [zero, past, cut]) assert.doesNotMatch(JSON.stringify(a.threads[0].stack), NOT_ABSENT);
  // a full-memory dump lays a stack out at RVA 0 with its bytes in the Memory64List: whole there, it is read by address and is no fault;
  // with part of its range missing from the memory lists, the RVA of 0 is the fault it is anywhere else
  const full = (held: number): Buffer => assemble((put) => {
    const entry = Buffer.concat([u32(77), u32(0), u32(0x20), u32(8), u64(0n), u64(0xe51f700000n), u32(0x200), u32(0), u32(1232), u32(put(ctxBytes(64, 1232)))]);
    return [{ type: 7, body: sysInfo(put, 9) }, { type: 3, body: Buffer.concat([u32(1), entry]) },
      { type: 9, body: Buffer.concat([u64(1), u64(0), u64(0xe51f700000n), u64(held)]) }];
  }, { flags: 2n, memory: Buffer.alloc(held, 0x5a) }).file;
  const whole = await at("stack-full.dmp", full(0x200));
  assert.deepEqual([whole.status, whole.problems, whole.threads[0].stack.location, whole.threads[0].stack.bytes_in_file, whole.threads[0].stack.bytes_in_memory_lists],
    ["complete", [], "in_memory_lists", 0, 0x200]);
  const half = await at("stack-half.dmp", full(0x100));
  declaredFault(half, "ThreadList", /the stack of thread 77 \(entry 0\): 512 bytes declared at file offset 0, where the file's header is/);
  assert.deepEqual([half.threads[0].stack.location, half.threads[0].stack.bytes_in_file, half.threads[0].stack.bytes_in_memory_lists], ["declared_not_readable", 0, 0x100]);
});

test("the exception's context location and NumberParameters, memory descriptors at RVA 0, thread, module and handle-type names and directory entries are judged by the same rule", async () => {
  const exception = (ctx: [number, 0 | "good" | "tail" | "past"], params = 2, tail?: Buffer): Buffer => {
    const built = assemble((put) => {
      const good = put(ctxBytes(64, 1232));
      const e = Buffer.alloc(168);
      e.writeUInt32LE(77, 0);
      e.writeUInt32LE(0xc0000005, 8);
      e.writeBigUInt64LE(0x401000n, 24);
      e.writeUInt32LE(params, 32);
      e.writeUInt32LE(ctx[0], 160);
      e.writeUInt32LE(ctx[1] === "good" ? good : 0, 164);
      return [{ type: 7, body: sysInfo(put, 9) }, { type: 6, body: e }];
    }, { memory: tail });
    if (ctx[1] === "tail") built.file.writeUInt32LE(built.memoryAt, built.at[6] + 164);
    if (ctx[1] === "past") built.file.writeUInt32LE(built.file.length + 99, built.at[6] + 164);
    return built.file;
  };
  const sum = async (name: string, file: Buffer, args: Record<string, unknown> = {}): Promise<Record<string, any>> => { await writeFile(join(dir, "inputs", name), file); return ask({ path: `inputs/${name}`, ...args }); };
  const clean = await sum("exc-ok.dmp", exception([1232, "good"]));
  assert.deepEqual([clean.status, clean.problems, clean.exception.context.location], ["complete", [], "read"]);
  for (const [label, file, what] of [
    ["at RVA 0", exception([1232, 0]), /the context of the exception's thread: 1232 bytes declared at file offset 0/],
    ["past the file", exception([1232, "past"]), /at or past the end of the file/],
    ["cut by the file", exception([1232, "tail"], 2, Buffer.alloc(50)), /ends 50 bytes into it/],
    ["of 716 bytes in an x64 dump", exception([716, "good"]), /716 bytes are declared and an x64 CONTEXT needs at least 1232/],
  ] as Array<[string, Buffer, RegExp]>) {
    const a = await sum("exc-bad.dmp", file);
    declaredFault(a, "Exception", what);
    assert.notEqual(a.exception.context.location, "read", label);
    assert.doesNotMatch(JSON.stringify(a.exception.context), NOT_ABSENT, label);
  }
  const params = await sum("exc-params.dmp", exception([1232, "good"], 16));
  declaredFault(params, "Exception", /NumberParameters is 16 and EXCEPTION_RECORD holds at most 15/);
  assert.equal(params.exception.parameters.length, 15);

  // a MemoryList descriptor at RVA 0: the header's bytes are not mapped as the process's memory; a Memory64List whose BaseRva is 0 likewise
  const list32 = assemble((put) => {
    const data = put(Buffer.alloc(0x100, 0x41));
    return [{ type: 5, body: Buffer.concat([u32(2), u64(0x10000n), u32(0x40), u32(0), u64(0x20000n), u32(0x100), u32(data)]) }];
  }).file;
  const mem = await sum("mem-rva0.dmp", list32, { view: "memory" });
  declaredFault(mem, "MemoryList", /the memory range at 0x10000: 64 bytes declared at file offset 0, where the file's header is/);
  assert.deepEqual(mem.ranges.map((x: any) => x.va), ["0x20000"], "the range at RVA 0 is not mapped");
  const va = await sum("mem-rva0.dmp", list32, { view: "va", va: "0x10000" });
  assert.deepEqual([va.status, va.addresses[0].in_dump], ["partial", false]);
  const counted = await sum("mem-rva0.dmp", list32);
  assert.equal(counted.counts.memory_ranges_not_readable, 1);
  const list64 = assemble(() => [{ type: 9, body: Buffer.concat([u64(1), u64(0), u64(0x10000n), u64(0x20)]) }], { flags: 2n }).file;     // BaseRva 0
  const mem64 = await sum("mem64-rva0.dmp", list64, { view: "memory" });
  declaredFault(mem64, "Memory64List", /the memory of the Memory64List \(1 ranges, from its BaseRva\): 32 bytes declared at file offset 0/);
  assert.deepEqual(mem64.ranges, []);

  // a ThreadNames entry at RVA 0: the name was not read, partial, and not "no name"
  const named = assemble((put) => [{ type: 7, body: sysInfo(put, 9) },
    { type: 3, body: Buffer.concat([u32(1), u32(77), u32(0), u32(0x20), u32(8), u64(0n), u64(0n), u32(0), u32(0), u32(0), u32(0)]) },
    { type: 24, body: Buffer.concat([u32(1), u32(77), u64(0n)]) }]).file;
  const tn = await sum("tname-rva0.dmp", named, { view: "threads" });
  declaredFault(tn, "ThreadNames", /the name of thread 77: a MINIDUMP_STRING declared at file offset 0, where the file's header is/);
  assert.deepEqual([tn.threads[0].name, tn.threads[0].name_why_not], [null, "the ThreadNames entry gives a name at RVA 0 and it could not be read (problems)"]);

  // a module whose name RVA is 0: modules and memory are partial (memory names the module that holds a range's address)
  const mods = assemble((put) => {
    const data = put(Buffer.alloc(0x100, 0x41));
    return [{ type: 4, body: Buffer.concat([u32(1), moduleEntry({ base: 0x20000n, size: 0x1000, nameRva: 0 })]) },
      { type: 5, body: Buffer.concat([u32(1), u64(0x20000n), u32(0x100), u32(data)]) }];
  }).file;
  const m0 = await sum("modname-rva0.dmp", mods, { view: "modules" });
  declaredFault(m0, "ModuleList", /the name of module 0: a MINIDUMP_STRING declared at file offset 0/);
  assert.equal(m0.modules[0].name, null);
  assert.match(m0.modules[0].name_why_not, /name RVA is 0, where the file's header is: the name was not read \(problems\), and this is not a module without a name/);
  const memView = await sum("modname-rva0.dmp", mods, { view: "memory" });
  assert.equal(memView.status, "partial", "a module name the memory view could not read makes it partial");

  // CodeView at RVA 0 and of two bytes (smaller than a signature): declared, not readable, never "read, not RSDS"
  const cv = assemble((put) => {
    const two = put(Buffer.from("RS"));
    return [{ type: 4, body: Buffer.concat([u32(2), moduleEntry({ base: 0x10000n, size: 0x1000, nameRva: put(mdString("a.dll")), cv: [64, 0] }),
      moduleEntry({ base: 0x20000n, size: 0x1000, nameRva: put(mdString("b.dll")), cv: [2, two] })]) }];
  }).file;
  const cvs = await sum("cv-more.dmp", cv, { view: "modules" });
  declaredFault(cvs, "ModuleList", /the CodeView \(PDB\) record of module 1: 2 bytes are declared and a CodeView record \(a 4-byte signature\) needs at least 4/);
  assert.deepEqual(cvs.modules.map((x: any) => [x.pdb_record, x.pdb.location, x.pdb.read]), [["declared, not readable", "declared_not_readable", false], ["declared, not readable", "declared_not_readable", false]]);
  assert.ok(cvs.problems.some((x: any) => /CodeView \(PDB\) record of module 0: 64 bytes declared at file offset 0/.test(x.problem)));

  // a stream of the directory at RVA 0: no byte of the header is read as the stream
  const dirRva0 = assemble((put) => [{ type: 4, body: Buffer.concat([u32(1), moduleEntry({ base: 0x10000n, size: 0x1000, nameRva: put(mdString("a.dll")) })]) }]).file;
  dirRva0.writeUInt32LE(0, dirRva0.readUInt32LE(12) + 8);
  const d0 = await sum("dir-rva0.dmp", dirRva0);
  declaredFault(d0, "ModuleList", /the ModuleList stream \(directory entry 0\): 112 bytes declared at file offset 0/);
  assert.deepEqual([d0.streams[0].bytes_in_file, d0.streams[0].location, d0.counts.modules], [0, "declared_not_readable", 0]);

  // an RVA inside the header that is not 0 is the header too: a stream at 4, a name at 12, memory at 4, and the directory itself
  const dirRva4 = assemble((put) => [{ type: 4, body: Buffer.concat([u32(1), moduleEntry({ base: 0x10000n, size: 0x1000, nameRva: put(mdString("a.dll")) })]) }]).file;
  dirRva4.writeUInt32LE(4, dirRva4.readUInt32LE(12) + 8);
  const d4 = await sum("dir-rva4.dmp", dirRva4);
  declaredFault(d4, "ModuleList", /the ModuleList stream \(directory entry 0\): 112 bytes declared at file offset 4, where the file's header is/);
  assert.deepEqual([d4.streams[0].bytes_in_file, d4.streams[0].location], [0, "declared_not_readable"]);
  const n12 = await sum("modname-rva12.dmp", assemble(() => [{ type: 4, body: Buffer.concat([u32(1), moduleEntry({ base: 0x10000n, size: 0x1000, nameRva: 12 })]) }]).file, { view: "modules" });
  declaredFault(n12, "ModuleList", /the name of module 0: a MINIDUMP_STRING declared at file offset 12, where the file's header is/);
  assert.match(n12.modules[0].name_why_not, /name RVA is 12, where the file's header is/);
  const list32at4 = Buffer.from(list32);
  list32at4.writeUInt32LE(4, list32at4.indexOf(Buffer.concat([u64(0x10000n), u32(0x40)])) + 12);
  const mem4 = await sum("mem-rva4.dmp", list32at4, { view: "memory" });
  declaredFault(mem4, "MemoryList", /the memory range at 0x10000: 64 bytes declared at file offset 4, where the file's header is/);
  assert.deepEqual(mem4.ranges.map((x: any) => x.va), ["0x20000"]);
  const list64at4 = assemble(() => [{ type: 9, body: Buffer.concat([u64(1), u64(4), u64(0x10000n), u64(0x20)]) }], { flags: 2n }).file;
  const mem64at4 = await sum("mem64-rva4.dmp", list64at4, { view: "memory" });
  declaredFault(mem64at4, "Memory64List", /32 bytes declared at file offset 4, where the file's header is/);
  assert.deepEqual(mem64at4.ranges, []);
  for (const at of [0, 4, 31]) {
    const moved = Buffer.from(dirRva0);
    moved.writeUInt32LE(at, 12);                                  // StreamDirectoryRva
    const m = await sum(`dir-at-${at}.dmp`, moved);
    assert.equal(m.status, "partial", `directory at ${at}`);
    assert.deepEqual(m.streams, [], `no entry is read from the header (directory at ${at})`);
    assert.ok(m.problems.some((x: any) => x.stream === "directory" && /inside the header \(its first 32 bytes\); no entry is read from it/.test(x.problem)), JSON.stringify(m.problems));
  }
});

test("lossy decoding is said and partial; an empty handle type name has its own key; a clean dump is complete in every view", async () => {
  const lossy = assemble((put) => {
    const name = put(Buffer.concat([u32(10), Buffer.from("a\0b\0", "latin1"), Buffer.from([0x00, 0xd8]), Buffer.from("c\0.\0", "latin1"), Buffer.alloc(2)]));      // a lone high surrogate
    const rec = put(Buffer.concat([Buffer.from("RSDS"), Buffer.alloc(16, 1), u32(1), Buffer.from("C:\\", "latin1"), Buffer.from([0xff, 0xfe]), Buffer.from("\\x.pdb\0", "latin1")]));
    return [{ type: 4, body: Buffer.concat([u32(1), moduleEntry({ base: 0x10000n, size: 0x1000, nameRva: name, cv: [24 + 12, rec] })]) }];
  }).file;
  await writeFile(join(dir, "inputs", "lossy.dmp"), lossy);
  const l = await ask({ path: "inputs/lossy.dmp", view: "modules" });
  assert.equal(l.status, "partial");
  assert.ok(l.modules[0].name.includes("\ufffd") && l.modules[0].pdb.path.includes("\ufffd"));
  assert.equal(l.modules[0].pdb.path_lossy, true);
  assert.ok(l.problems.some((x: any) => /the name of module 0: the string is not valid UTF-16/.test(x.problem)), JSON.stringify(l.problems));
  assert.ok(l.problems.some((x: any) => /the path is not UTF-8 \(1 byte sequence\(s\) could not be decoded\)/.test(x.problem) || /the path is not UTF-8/.test(x.problem)), JSON.stringify(l.problems));

  const handles = assemble((put) => {
    const empty = put(mdString(""));
    const file = put(mdString("File"));
    return [{ type: 12, body: Buffer.concat([u32(16), u32(32), u32(3), u32(0), handleEntry(4, empty), handleEntry(8, file), handleEntry(12, 0)]) }];
  }).file;
  await writeFile(join(dir, "inputs", "handles-empty.dmp"), handles);
  const h = await ask({ path: "inputs/handles-empty.dmp" });
  assert.equal(h.status, "complete", JSON.stringify(h.problems));
  assert.deepEqual([h.handles.by_type, h.handles.without_a_type_name], [{ "<an empty type name>": 1, File: 1 }, 1]);

  for (const [path, d] of both()) {
    const s = d.scene;
    const views: Array<Record<string, unknown>> = [{ view: "summary" }, { view: "modules" }, { view: "memory" }, { view: "memory", list: "regions" }, { view: "threads" },
      { view: "va", va: hex(s.heap) }, { view: "read", va: hex(s.heap), length: 64 }, { view: "module", module: "ntdll.dll" }, { view: "find", needle: SIGMA }];
    for (const args of views) {
      const a = await ask({ path, ...args });
      assert.deepEqual([a.status, a.problems], ["complete", []], `${path} ${JSON.stringify(args)}`);
    }
    const t = await ask({ path, view: "threads" });
    assert.ok(t.threads.every((x: any) => x.context.location === "read" && x.stack.location === "read" && x.stack.bytes_in_file === x.stack.bytes));
    assert.equal((await ask({ path })).exception.context.location, "read");
  }
});
