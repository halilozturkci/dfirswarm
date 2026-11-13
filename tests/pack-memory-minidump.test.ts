/**
 * minidump_map (memory-forensics): a Windows process dump read from its own streams. Every dump here is built by
 * tests/pack-memory-minidump-support.ts from the published layouts, in a 64-bit full-memory form (Memory64List) and a 32-bit partial form
 * (MemoryList), and every expected address, offset and byte comes from that generator, never from the tool.
 *
 * What is held: each view's facts; that an address which is not in the dump is said to be absent and never read as zero; that a module
 * with a gap is written only with allow_gaps, then with a map of the gap and status partial; that memory content is written only in a job
 * run as secret output and never printed; that a truncated or malformed dump gives a partial that names the stream and the file offset,
 * and no traceback; paging (total, returned, next_offset); and the shared blocks the script carries.
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
import { type Built, call, doc, encode, hex, PAGE, scene, SCRIPT, SIGMA, STRADDLE, TOOL_DIR, u32, u64, WIDE_NEEDLE } from "./pack-memory-minidump-support.ts";

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
      memory_ranges_overlapping: 0, memory_ranges_cut_by_end_of_file: 0, memory_info_regions: 11 });
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
    assert.deepEqual(payload.pdb, { format: "RSDS", guid: "33221100554477668899AABBCCDDEEFF", age: 3, path: "D:\\build\\payload.pdb" });
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
