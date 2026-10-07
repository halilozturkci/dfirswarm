/**
 * pe_info against fixtures built from the formats' own layouts (tests/pack-re-harness.ts), never from the
 * tool's output: the Microsoft PE/COFF specification, the System V gABI for ELF, <mach-o/loader.h> and
 * <mach-o/fat.h> for Mach-O.
 *
 * What these cases hold: a field names what it reads (a certificate table is declared, not a verified
 * signature); a header that is shorter than the spec says is parsed as far as it goes and the answer is
 * `partial`, not clean; an ELF32 header is 52 bytes; the dependencies of an ELF come from the loader's view
 * (PT_DYNAMIC), not from section names; every slice of a universal binary is read, in the byte order its
 * header declares; and a table that does not fit its section says so.
 */
import assert from "node:assert/strict";
import { chmod, readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import {
  CPU_ARM64,
  CPU_X86_64,
  PE_INFO,
  SCN_CODE,
  SCN_EXEC,
  SCN_INIT,
  SCN_READ,
  SCN_WRITE,
  asJob,
  body,
  buildElf,
  buildFat,
  buildMacho,
  buildPe,
  exists,
  put,
  refused,
  tool,
  withCwd,
} from "./pack-re-harness.ts";
import type { Json } from "./pack-re-harness.ts";

async function pe(cwd: string, buf: Buffer, args: Record<string, unknown> = {}, env: Record<string, string> = {}): Promise<Json> {
  await put(cwd, "work/sample.bin", buf);
  return body(await tool(PE_INFO, cwd, { path: "work/sample.bin", ...args }, env));
}

// --- PE ----------------------------------------------------------------------------------------------------------

test("a well-formed PE32 is read whole, and its certificate directory is declared, not verified", async () => {
  await withCwd(async (cwd) => {
    const built = buildPe({
      imports: [
        { dll: "KERNEL32.dll", functions: ["ExitProcess", "GetLastError"] },
        { dll: "WS2_32.dll", functions: ["#115", "connect"] },
      ],
      exportName: "sample.dll",
      certificate: { offset: 0x1000, size: 0x40 },
      stamp: 0x5f000000,
    });
    const out = await pe(cwd, built.file);
    assert.equal(out.format, "PE");
    assert.equal(out.bits, 32);
    assert.equal(out.machine, "i386");
    assert.equal(out.status, "complete", JSON.stringify(out.problems));
    assert.equal(out.compile_timestamp_raw, 0x5f000000);
    assert.equal(out.compile_timestamp, "2020-07-04T04:05:20Z");
    assert.deepEqual(out.imports.map((i: Json) => i.library), ["KERNEL32.dll", "WS2_32.dll"]);
    assert.deepEqual(out.imports[0].functions, ["ExitProcess", "GetLastError"]);
    assert.deepEqual(out.imports[1].functions, ["#115", "connect"]);
    assert.equal(out.export_name, "sample.dll");
    // The data directory 4 entry is a file offset and a size: its presence, not a signature.
    assert.equal(out.certificate_table_declared, true);
    assert.equal(out.certificate_table.offset, 0x1000);
    assert.equal(out.certificate_table.size, 0x40);
    assert.equal(out.certificate_table.within_file, false, "offset 0x1000 is past the end of this small file");
    assert.ok(!("signed" in out), "pe_info.signed named a nonzero directory size a signature");
    assert.ok(Array.isArray(out.coverage.structures_not_read));
    assert.ok(out.coverage.structures_not_read.some((s: string) => /resource/i.test(s)));
  });
});

test("a PE whose optional header is cut short is partial, with the reason, and no field read past the cut", async () => {
  await withCwd(async (cwd) => {
    // The file ends 100 bytes into a 224-byte optional header.
    const built = buildPe({ cutOptionalHeaderTo: 100 });
    const out = await pe(cwd, built.file);
    assert.equal(out.status, "partial", JSON.stringify(out));
    assert.match(out.header_problem, /optional header/i);
    assert.ok(out.problems.length >= 1);
    assert.doesNotMatch(JSON.stringify(out), /complete static structure/);
    // Fields before the cut are still read.
    assert.equal(out.bits, 32);
    assert.equal(out.entry_point, "0x1000");
    assert.ok(!("subsystem" in out) || out.subsystem === undefined || out.problems.some((p: string) => /subsystem|optional/i.test(p)));
  });
});

test("optional-header fields are read against the declared optional-header size, not against the file", async () => {
  await withCwd(async (cwd) => {
    // SizeOfOptionalHeader says 96: the fixed fields fit, the 16 data directories do not. The bytes after the
    // 96th are the section table, and a reader that goes by file length reads them as directory entries.
    const built = buildPe({ optionalHeaderSize: 96 });
    const out = await pe(cwd, built.file);
    assert.equal(out.status, "partial");
    assert.equal(out.certificate_table_declared, false);
    assert.deepEqual(out.data_directories ?? [], []);
    assert.ok(out.problems.some((p: string) => /data director/i.test(p)), JSON.stringify(out.problems));
  });
});

test("only the data directories that fit in the declared optional header are read", async () => {
  await withCwd(async (cwd) => {
    // 112 bytes: PE32 fixed fields (96) plus two directory entries (export, import).
    const built = buildPe({ optionalHeaderSize: 112, exportName: "x.dll" });
    const out = await pe(cwd, built.file);
    assert.equal(out.status, "partial");
    assert.ok((out.data_directories ?? []).every((d: Json) => d.index < 2), JSON.stringify(out.data_directories));
    assert.equal(out.certificate_table_declared, false);
  });
});

test("an import table that runs past its section is a problem, not a clean read of the next section", async () => {
  await withCwd(async (cwd) => {
    const built = buildPe({
      imports: [{ dll: "KERNEL32.dll", functions: ["ExitProcess"] }],
      importsTerminated: false,
      importDirectorySize: 60,
      idataRawSize: 40,
    });
    const out = await pe(cwd, built.file);
    assert.equal(out.status, "partial", JSON.stringify(out));
    assert.match(out.import_table_problem ?? "", /section|terminat|file-backed/i);
    // Only the two descriptors inside the section are descriptors. The bytes after them in the file are the
    // thunk tables of this fixture, and a reader that goes by file length reads them as a third descriptor.
    assert.equal(out.imports.length, 2, JSON.stringify(out.imports));
  });
});

test("a certificate directory with garbage in it is only declared: offset, size, whether it lies in the file", async () => {
  await withCwd(async (cwd) => {
    const trailing = Buffer.from("this is not a WIN_CERTIFICATE structure at all, just text".padEnd(64, "."));
    const built = buildPe({ trailing });
    // Point data directory 4 at the trailing bytes, which sit after the last section.
    const at = built.file.length - trailing.length;
    const second = buildPe({ trailing, certificate: { offset: at, size: trailing.length } });
    assert.equal(second.file.length - trailing.length, at, "the layout is unchanged by the certificate entry");
    const out = await pe(cwd, second.file);
    assert.equal(out.certificate_table_declared, true);
    assert.equal(out.certificate_table.within_file, true);
    assert.ok(!("signed" in out));
    // The first entry's header is read from the spec's WIN_CERTIFICATE layout: dwLength, wRevision, wCertificateType.
    assert.ok("first_entry" in out.certificate_table);
    assert.match(out.note, /not|only/i);
  });
});

test("the PE flags are triage features and the note does not call a section packed", async () => {
  await withCwd(async (cwd) => {
    const built = buildPe({ sections: [{ name: ".text", data: Buffer.alloc(16), vsize: 0x10000, flags: SCN_CODE | SCN_EXEC | SCN_READ | SCN_WRITE }] });
    const out = await pe(cwd, built.file);
    assert.equal(out.sections[0].writable_and_executable, true);
    assert.doesNotMatch(out.note, /\bis packed\b/);
    assert.doesNotMatch(JSON.stringify(out), /"packed_shape"/);
    assert.match(out.note, /triage|inventory/i);
  });
});

test("section entropy is measured in bounded work, and a section left unmeasured says why", async () => {
  await withCwd(async (cwd) => {
    const data = Buffer.alloc(8192);
    for (let i = 0; i < data.length; i++) data[i] = (i * 131 + (i >> 3)) & 0xff;
    const built = buildPe({ sections: [{ name: ".text", data, flags: SCN_CODE | SCN_EXEC | SCN_READ }] });
    const full = await pe(cwd, built.file);
    assert.equal(typeof full.sections[0].entropy, "number");
    const small = await pe(cwd, built.file, { max_entropy_bytes: 1000 });
    assert.equal(small.sections[0].entropy, null);
    assert.match(small.sections[0].entropy_note, /budget/i);
    assert.equal(small.status, "partial");
    assert.ok(small.limits_hit.some((l: string) => /entropy/i.test(l)));
  });
});

test("a long import list is paged: the whole in a file under the tool-output directory, named in the answer", async () => {
  await withCwd(async (cwd) => {
    const built = buildPe({ imports: [{ dll: "KERNEL32.dll", functions: ["A1", "A2", "A3"] }] });
    const out = await pe(cwd, built.file, { limit: 2 });
    assert.equal(out.tables.imports.matched, 3);
    assert.equal(out.tables.imports.returned, 2);
    assert.equal(out.tables.imports.truncated, true);
    assert.equal(out.truncated, true);
    assert.equal(out.status, "complete", "the parse was whole: only the answer's listing is cut, and the whole is on disk");
    const file = join(cwd, out.tables.imports.all_results);
    const rows = (await readFile(file, "utf8")).trim().split("\n").map((l) => JSON.parse(l));
    assert.deepEqual(rows.map((r) => r.function), ["A1", "A2", "A3"]);
    // A second run leaves the first file where it was.
    const again = await pe(cwd, built.file, { limit: 2 });
    assert.notEqual(again.tables.imports.all_results, out.tables.imports.all_results);
    assert.ok(await exists(join(cwd, out.tables.imports.all_results)));
  });
});

test("in a job the whole listing goes under $OUT only", async () => {
  await withCwd(async (cwd) => {
    const built = buildPe({ imports: [{ dll: "KERNEL32.dll", functions: ["A1", "A2", "A3"] }] });
    await put(cwd, "work/sample.bin", built.file);
    const out = body(await asJob(PE_INFO, cwd, { path: "work/sample.bin", limit: 1 }));
    assert.match(out.tables.imports.all_results, /^store\/jobs\/j\d+\/out\/tool-output\//);
    const name = out.tables.imports.all_results.split("/").pop();
    assert.ok(await exists(join(cwd, "out", "tool-output", name)));
    assert.ok(!(await exists(join(cwd, "work", "s1", "tool-output"))), "nothing was written outside $OUT");
  });
});

test("a result that cannot be written whole says so and stays partial, with no traceback", { skip: process.getuid?.() === 0 }, async () => {
  await withCwd(async (cwd) => {
    const built = buildPe({ imports: [{ dll: "KERNEL32.dll", functions: ["A1", "A2", "A3"] }] });
    await put(cwd, "work/sample.bin", built.file);
    await put(cwd, "work/s1/keep", "x");
    await chmod(join(cwd, "work", "s1"), 0o500);
    try {
      const out = body(await tool(PE_INFO, cwd, { path: "work/sample.bin", limit: 1 }));
      assert.equal(out.status, "partial");
      assert.equal(out.tables.imports.truncated, true);
      assert.ok(!out.tables.imports.all_results);
      assert.match(out.tables.imports.not_written ?? "", /could not|cannot|permission/i);
    } finally {
      await chmod(join(cwd, "work", "s1"), 0o700);
    }
  });
});

test("an MZ file that is not a PE says what its extended header is", async () => {
  await withCwd(async (cwd) => {
    const dos = Buffer.alloc(0x100);
    dos.write("MZ", 0, "latin1");
    dos.writeUInt32LE(0x80, 0x3c);
    dos.write("NE", 0x80, "latin1");
    await put(cwd, "work/sample.bin", dos);
    const out = refused(await tool(PE_INFO, cwd, { path: "work/sample.bin" }));
    assert.equal(out.status, "unsupported");
    assert.match(out.error, /NE/);
  });
});

test("a PE too short to hold its own headers fails loudly with the part it could not read", async () => {
  await withCwd(async (cwd) => {
    const full = buildPe({}).file;
    await put(cwd, "work/sample.bin", full.subarray(0, 0x84));
    const out = refused(await tool(PE_INFO, cwd, { path: "work/sample.bin" }));
    assert.equal(out.status, "failed");
    assert.match(out.error, /COFF|PE/);
  });
});

// --- ELF ---------------------------------------------------------------------------------------------------------

test("a 52-byte ELF32 header is an ELF header", async () => {
  await withCwd(async (cwd) => {
    const buf = buildElf({ cls: 32, headerOnly: true, entry: 0x8048000 });
    assert.equal(buf.length, 52);
    const out = await pe(cwd, buf);
    assert.equal(out.format, "ELF");
    assert.equal(out.bits, 32);
    assert.equal(out.endian, "little");
    assert.equal(out.machine, "i386");
    assert.equal(out.entry_point, "0x8048000");
    assert.equal(out.status, "complete", JSON.stringify(out.problems));
    assert.ok(!("error" in out));
  });
});

test("a 64-byte ELF64 header is read, and one cut short is a failure that names the size it needs", async () => {
  await withCwd(async (cwd) => {
    const buf = buildElf({ cls: 64, headerOnly: true });
    assert.equal(buf.length, 64);
    const out = await pe(cwd, buf);
    assert.equal(out.bits, 64);
    assert.equal(out.machine, "x86-64");
    await put(cwd, "work/short.bin", buf.subarray(0, 60));
    const bad = refused(await tool(PE_INFO, cwd, { path: "work/short.bin" }));
    assert.equal(bad.status, "failed");
    assert.match(bad.error, /64/);
  });
});

test("an ELF whose class byte is no class is unsupported, not read as 32-bit", async () => {
  await withCwd(async (cwd) => {
    const buf = buildElf({ cls: 64, headerOnly: true });
    buf[4] = 0;
    await put(cwd, "work/sample.bin", buf);
    const out = refused(await tool(PE_INFO, cwd, { path: "work/sample.bin" }));
    assert.equal(out.status, "unsupported");
    assert.match(out.error, /class/i);
  });
});

for (const [cls, big] of [
  [32, false],
  [32, true],
  [64, false],
  [64, true],
] as const) {
  test(`ELF${cls} ${big ? "big" : "little"}-endian with no section headers: dependencies come from PT_DYNAMIC`, async () => {
    await withCwd(async (cwd) => {
      const buf = buildElf({ cls, big, needed: ["libc.so.6", "libm.so.6"], runpath: "$ORIGIN/../lib", soname: "libx.so.1", interp: "/lib/ld-linux.so.2" });
      const out = await pe(cwd, buf);
      assert.equal(out.status, "complete", JSON.stringify(out.problems));
      assert.equal(out.endian, big ? "big" : "little");
      assert.deepEqual(out.needed_libraries, ["libc.so.6", "libm.so.6"]);
      assert.equal(out.runpath, "$ORIGIN/../lib");
      assert.equal(out.soname, "libx.so.1");
      assert.equal(out.interpreter, "/lib/ld-linux.so.2");
      assert.equal(out.section_headers_absent, true);
      assert.equal(out.stripped, null, "symbols cannot be judged without section headers");
      assert.equal(out.dynamic.source, "PT_DYNAMIC");
      const dyn = out.segments.find((s: Json) => s.type_name === "PT_DYNAMIC");
      assert.ok(dyn, "the segment table names PT_DYNAMIC");
    });
  });
}

test("sections with unrelated names do not hide the dependencies the loader reads", async () => {
  await withCwd(async (cwd) => {
    const buf = buildElf({ cls: 64, needed: ["libssl.so.3"], sections: [{ name: "x1", type: 1, flags: 6, data: Buffer.from("code") }, { name: "x2", type: 3 }] });
    const out = await pe(cwd, buf);
    assert.deepEqual(out.needed_libraries, ["libssl.so.3"]);
  });
});

test("an ELF with section headers and no symbol-table section is stripped; one with an SHT_SYMTAB is not, by type and not by name", async () => {
  await withCwd(async (cwd) => {
    const plain = await pe(cwd, buildElf({ cls: 64, sections: [{ name: ".text", type: 1, flags: 6, data: Buffer.from("code") }] }));
    assert.equal(plain.section_headers_absent, false);
    assert.equal(plain.stripped, true);
    const withSymbols = await pe(cwd, buildElf({ cls: 64, sections: [{ name: ".text", type: 1, flags: 6 }, { name: ".junk", type: 2, data: Buffer.alloc(48) }] }));
    assert.equal(withSymbols.stripped, false);
  });
});

test("with no PT_DYNAMIC the dynamic array is found through an SHT_DYNAMIC section, and the answer says which view it used", async () => {
  await withCwd(async (cwd) => {
    const buf = buildElf({ cls: 64, needed: ["libz.so.1"], noDynamicSegment: true, dynamicInSections: true });
    const out = await pe(cwd, buf);
    assert.deepEqual(out.needed_libraries, ["libz.so.1"]);
    assert.match(out.dynamic.source, /SHT_DYNAMIC/);
  });
});

test("a DT_STRTAB that no PT_LOAD maps is not guessed: no libraries, and a problem that says so", async () => {
  await withCwd(async (cwd) => {
    const out = await pe(cwd, buildElf({ cls: 64, needed: ["libc.so.6"], noLoadMapping: true }));
    assert.deepEqual(out.needed_libraries, []);
    assert.equal(out.status, "partial");
    assert.ok(out.problems.some((p: string) => /DT_STRTAB|string table/i.test(p)), JSON.stringify(out.problems));
  });
});

test("an ELF with no dynamic information does not claim static linking", async () => {
  await withCwd(async (cwd) => {
    const out = await pe(cwd, buildElf({ cls: 64 }));
    assert.deepEqual(out.needed_libraries, []);
    assert.equal(out.dynamic.source, null);
    assert.match(out.dynamic.note, /does not|not show/i);
    assert.doesNotMatch(JSON.stringify(out), /statically linked|is static/i);
  });
});

// --- Mach-O ------------------------------------------------------------------------------------------------------

const LC_LOAD_DYLIB = 0x0c;
const LC_ID_DYLIB = 0x0d;
const LC_LOAD_WEAK_DYLIB = 0x80000018;
const LC_REEXPORT_DYLIB = 0x8000001f;

function thin(libs: [number, string][], extra = {}): Buffer {
  return buildMacho({
    commands: [{ segment: "__TEXT" }, ...libs.map(([cmd, dylib]) => ({ dylib, cmd })), { main: 0x3f00 }, { signature: { offset: 0x8000, size: 0x100 } }],
    ...extra,
  });
}

function checkSlices(out: Json): void {
  assert.equal(out.format, "Mach-O universal binary");
  assert.equal(out.slices.length, 2);
  const [a, b] = out.slices;
  assert.equal(a.cpu_type_name, "x86-64");
  assert.equal(b.cpu_type_name, "ARM64");
  assert.equal(a.status, "complete");
  assert.equal(b.status, "complete");
  assert.deepEqual(a.macho.linked_libraries, ["/usr/lib/libSystem.B.dylib"]);
  assert.deepEqual(b.macho.linked_libraries, ["/usr/lib/libSystem.B.dylib", "/usr/lib/libweak.dylib", "/usr/lib/libre.dylib"]);
  assert.equal(b.macho.install_name, "/usr/lib/libself.dylib");
  assert.equal(b.macho.entry_offset, 0x3f00);
  assert.deepEqual(b.macho.code_signature, { offset: 0x8000, size: 0x100 });
  assert.equal(out.status, "complete", JSON.stringify(out.problems));
}

const SLICE_A = (): Buffer => thin([[LC_LOAD_DYLIB, "/usr/lib/libSystem.B.dylib"]], { cputype: CPU_X86_64 });
const SLICE_B = (): Buffer =>
  thin(
    [
      [LC_LOAD_DYLIB, "/usr/lib/libSystem.B.dylib"],
      [LC_LOAD_WEAK_DYLIB, "/usr/lib/libweak.dylib"],
      [LC_REEXPORT_DYLIB, "/usr/lib/libre.dylib"],
      [LC_ID_DYLIB, "/usr/lib/libself.dylib"],
    ],
    { cputype: CPU_ARM64 },
  );

test("a universal binary with the standard big-endian header: every slice is read, with its own libraries", async () => {
  await withCwd(async (cwd) => {
    const out = await pe(cwd, buildFat([{ cputype: CPU_X86_64, data: SLICE_A() }, { cputype: CPU_ARM64, data: SLICE_B() }]));
    checkSlices(out);
    assert.equal(out.fat_byte_order, "big");
  });
});

test("a universal binary whose header reads FAT_CIGAM is a little-endian header, and its slice table is read as one", async () => {
  await withCwd(async (cwd) => {
    const out = await pe(cwd, buildFat([{ cputype: CPU_X86_64, data: SLICE_A() }, { cputype: CPU_ARM64, data: SLICE_B() }], { littleEndianHeader: true }));
    checkSlices(out);
    assert.equal(out.fat_byte_order, "little");
  });
});

test("a 64-bit fat header (FAT_MAGIC_64) is read", async () => {
  await withCwd(async (cwd) => {
    const out = await pe(cwd, buildFat([{ cputype: CPU_X86_64, data: SLICE_A() }, { cputype: CPU_ARM64, data: SLICE_B() }], { arch64: true }));
    checkSlices(out);
  });
});

test("a thin Mach-O in each byte order and width: the byte order is read from the magic", async () => {
  await withCwd(async (cwd) => {
    for (const [wide, big] of [
      [false, false],
      [false, true],
      [true, false],
      [true, true],
    ] as const) {
      const out = await pe(cwd, buildMacho({ wide, big, cputype: wide ? CPU_X86_64 : 7, commands: [{ segment: "__TEXT" }, { dylib: "/usr/lib/libz.1.dylib", cmd: LC_LOAD_DYLIB }] }));
      assert.equal(out.format, "Mach-O", `${wide ? 64 : 32}-bit ${big ? "big" : "little"}-endian: ${JSON.stringify(out)}`);
      assert.equal(out.bits, wide ? 64 : 32);
      assert.equal(out.byte_order, big ? "big" : "little");
      assert.deepEqual(out.linked_libraries, ["/usr/lib/libz.1.dylib"]);
      assert.equal(out.status, "complete");
    }
  });
});

test("a Java class file shares the universal magic: it is not read as a Mach-O, and no slice is invented", async () => {
  await withCwd(async (cwd) => {
    // CAFEBABE, minor_version 0, major_version 61 (Java 17), then constant-pool-like bytes.
    const klass = Buffer.concat([Buffer.from([0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 61]), Buffer.alloc(120, 7)]);
    await put(cwd, "work/sample.bin", klass);
    const out = refused(await tool(PE_INFO, cwd, { path: "work/sample.bin" }));
    assert.equal(out.status, "failed");
    assert.ok(!out.slices || out.slices.every((s: Json) => s.status !== "complete"));
    assert.match(out.error, /Java|slice|Mach-O/i);
  });
});

test("a universal binary inside a slice is not recursed into: the slice says it is nested and unsupported", async () => {
  await withCwd(async (cwd) => {
    const inner = buildFat([{ cputype: CPU_X86_64, data: SLICE_A() }]);
    const out = await pe(cwd, buildFat([{ cputype: CPU_ARM64, data: inner }, { cputype: CPU_X86_64, data: SLICE_A() }]));
    assert.equal(out.slices[0].status, "unsupported");
    assert.match(out.slices[0].reason, /nested|universal/i);
    assert.equal(out.slices[1].status, "complete");
    assert.equal(out.status, "partial");
  });
});

test("load commands are bounded by sizeofcmds and the slice, whatever ncmds claims", async () => {
  await withCwd(async (cwd) => {
    const out = await pe(cwd, buildMacho({ commands: [{ segment: "__TEXT" }, { dylib: "/usr/lib/libz.1.dylib", cmd: LC_LOAD_DYLIB }], ncmdsOverride: 0x7fffffff }));
    assert.equal(out.status, "partial");
    assert.deepEqual(out.linked_libraries, ["/usr/lib/libz.1.dylib"]);
    assert.ok(out.problems.some((p: string) => /ncmds|load command/i.test(p)));
  });
});

test("a slice that lies outside the file is reported as outside, not read", async () => {
  await withCwd(async (cwd) => {
    const fat = buildFat([{ cputype: CPU_X86_64, data: SLICE_A() }]);
    // Make the slice's size larger than the file holds.
    fat.writeUInt32BE(fat.length + 100000, 8 + 12);
    await put(cwd, "work/sample.bin", fat);
    const out = refused(await tool(PE_INFO, cwd, { path: "work/sample.bin" }));
    assert.equal(out.slices[0].in_file, false);
    assert.equal(out.slices[0].status, "failed");
    assert.equal(out.status, "failed");
  });
});

// --- arguments and failures ----------------------------------------------------------------------------------------

test("arguments are typed, and a file that is none of the three formats is unsupported with its first bytes", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "work/sample.bin", "just some text");
    const out = refused(await tool(PE_INFO, cwd, { path: "work/sample.bin" }));
    assert.equal(out.status, "unsupported");
    assert.equal(out.head_hex, Buffer.from("just").toString("hex"));
    const bad = refused(await tool(PE_INFO, cwd, { path: "work/sample.bin", limit: 0 }));
    assert.match(bad.error, /limit/);
    const bad2 = refused(await tool(PE_INFO, cwd, { path: "work/sample.bin", with_imports: "yes" }));
    assert.match(bad2.error, /with_imports/);
  });
});

test("an unreadable file is a JSON error, never a traceback", { skip: process.getuid?.() === 0 }, async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "work/sample.bin", buildPe({}).file, 0o000);
    const out = refused(await tool(PE_INFO, cwd, { path: "work/sample.bin" }));
    assert.ok(out.error);
  });
});

// Sanity on the builders themselves: the fixtures are what the formats say, so that a test cannot pass by sharing a
// reading mistake with the tool.
test("the builders lay the structures at the offsets the specifications give", () => {
  const built = buildPe({ imports: [{ dll: "A.dll", functions: ["f"] }] });
  assert.equal(built.file.subarray(0, 2).toString("latin1"), "MZ");
  assert.equal(built.file.readUInt32LE(0x3c), 0x80);
  assert.equal(built.file.subarray(0x80, 0x84).toString("latin1"), "PE\0\0");
  assert.equal(built.file.readUInt16LE(0x84), 0x014c);
  assert.equal(built.file.readUInt16LE(0x84 + 16), 224, "SizeOfOptionalHeader of a PE32 with 16 directories");
  assert.equal(built.file.readUInt16LE(0x98), 0x10b, "optional header magic");
  assert.equal(buildElf({ cls: 32, headerOnly: true }).length, 52);
  assert.equal(buildElf({ cls: 64, headerOnly: true }).length, 64);
  const m = buildMacho({ wide: true });
  assert.equal(m.length, 32);
  assert.equal(m.readUInt32LE(0), 0xfeedfacf);
  assert.equal(buildMacho({ wide: false }).length, 28);
  const f = buildFat([{ cputype: CPU_X86_64, data: Buffer.alloc(40) }]);
  assert.equal(f.readUInt32BE(0), 0xcafebabe);
  assert.equal(f.readUInt32BE(4), 1);
  assert.equal(f.readUInt32BE(8), CPU_X86_64);
  assert.equal(f.readUInt32BE(16), 0x4000, "fat_arch.offset");
  assert.equal(SCN_INIT | SCN_READ, 0x40000040);
});
