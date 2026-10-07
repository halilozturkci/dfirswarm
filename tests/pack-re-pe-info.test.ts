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
import { spawnSync } from "node:child_process";
import { chmod, mkdir, readFile } from "node:fs/promises";
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
  u32,
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
    const options = {
      imports: [
        { dll: "KERNEL32.dll", functions: ["ExitProcess", "GetLastError"] },
        { dll: "WS2_32.dll", functions: ["#115", "connect"] },
      ],
      exportName: "sample.dll",
      stamp: 0x5f000000,
      trailing: Buffer.alloc(0x40, 7),
    };
    // The certificate table is the 64 bytes after the last section: its offset is where the layout without it ends.
    const at = buildPe(options).file.length - 0x40;
    const built = buildPe({ ...options, certificate: { offset: at, size: 0x40 } });
    const out = await pe(cwd, built.file);
    assert.equal(out.format, "PE");
    assert.equal(out.bits, 32);
    assert.equal(out.machine, "i386");
    assert.equal(out.status, "complete", JSON.stringify(out.problems));
    assert.equal(out.header_timestamp_raw, 0x5f000000);
    assert.equal(out.header_timestamp_utc, "2020-07-04T04:05:20Z");
    assert.ok(!("compile_timestamp" in out) && !("compile_timestamp_raw" in out), "a header field is not named for what a linker may not have written");
    assert.match(out.header_timestamp_note, /1970-01-01.*not a time/s);
    assert.deepEqual(out.imports.map((i: Json) => i.library), ["KERNEL32.dll", "WS2_32.dll"]);
    assert.deepEqual(out.imports[0].functions, ["ExitProcess", "GetLastError"]);
    assert.deepEqual(out.imports[1].functions, ["#115", "connect"]);
    assert.equal(out.export_name, "sample.dll");
    // The data directory 4 entry is a file offset and a size: its presence, not a signature.
    assert.equal(out.certificate_table_declared, true);
    assert.equal(out.certificate_table.offset, at);
    assert.equal(out.certificate_table.size, 0x40);
    assert.equal(out.certificate_table.within_file, true);
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
    // The bytes after the last section are an overlay, located but not read: here they are exactly the certificate table, and
    // the answer says so, so that a signed file's table is not read as appended content.
    assert.equal(out.overlay_offset, at);
    assert.equal(out.overlay_bytes, trailing.length);
    assert.equal(out.overlay_is_certificate_table, true);
    assert.equal(out.overlay_bytes_outside_certificate_table, 0);
  });
});

test("the data directories that name a CLR header, a TLS directory and resources are said, not read", async () => {
  await withCwd(async (cwd) => {
    const built = buildPe({ extraDirectories: { 14: { rva: 0x1000, size: 72 }, 9: { rva: 0x1000, size: 24 } } });
    const out = await pe(cwd, built.file);
    assert.equal(out.declares_clr_runtime_header, true);
    assert.equal(out.declares_tls, true);
    assert.equal(out.declares_resources, false);
    assert.deepEqual(out.data_directories.map((d: Json) => d.name), ["tls", "clr_runtime_header"]);
    assert.ok(out.coverage.structures_not_read.some((s: string) => /CLR/.test(s)));
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

test("extended counts in section header 0 (PN_XNUM, a zero e_shnum, SHN_XINDEX) are followed", async () => {
  await withCwd(async (cwd) => {
    const buf = buildElf({ cls: 64, needed: ["libc.so.6"], sections: [{ name: ".text", type: 1, flags: 6, data: Buffer.from("code") }], extendedCounts: true });
    const out = await pe(cwd, buf);
    assert.equal(out.extended_program_header_count, true);
    assert.equal(out.extended_section_count, true);
    assert.equal(out.program_headers, 2);
    assert.deepEqual(out.sections.map((s: Json) => s.name), ["", ".text", ".shstrtab"], "the names come from the string table SHN_XINDEX names");
    assert.deepEqual(out.needed_libraries, ["libc.so.6"]);
    assert.equal(out.status, "complete", JSON.stringify(out.problems));
  });
});

test("a DT_STRTAB no PT_LOAD maps is found through the string-table section that has its address, and the answer says so", async () => {
  await withCwd(async (cwd) => {
    const out = await pe(cwd, buildElf({ cls: 64, needed: ["libm.so.6"], noLoadMapping: true, dynamicInSections: true }));
    assert.deepEqual(out.needed_libraries, ["libm.so.6"]);
    assert.match(out.dynamic.string_table.resolved_via, /SHT_STRTAB section whose address is DT_STRTAB/);
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
    commands: [{ segment: "__TEXT" }, ...libs.map(([cmd, dylib]) => ({ dylib, cmd })), { main: 0x3f00 }, { signature: { offset: 16, size: 8 } }],
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
  assert.deepEqual(b.macho.code_signature, { offset: 16, size: 8 });
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

test("a Java class file shares the universal magic: it is not read as a Mach-O, whatever its version makes of the slice count", async () => {
  await withCwd(async (cwd) => {
    // CAFEBABE, minor_version 0, major_version 61 (Java 17), then constant-pool-like bytes: read as a fat header this declares
    // 61 slices. Class file major versions 45 and up (JDK 1.1) read as plausible slice counts.
    for (const major of [45, 52, 61, 69]) {
      const klass = Buffer.concat([Buffer.from([0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, major]), Buffer.alloc(2000, 7)]);
      await put(cwd, "work/sample.bin", klass);
      const out = refused(await tool(PE_INFO, cwd, { path: "work/sample.bin" }));
      assert.equal(out.status, "unsupported", `major ${major}`);
      assert.equal(out.format, "Java class file");
      assert.ok(!out.slices, `major ${major}: no slice is invented`);
      assert.deepEqual(out.class_file_version, { major, minor: 0 });
      assert.match(out.error, /Java class file/);
    }
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

// --- review round: ranges beyond the end of the file, time, limits, names ------------------------------------------------

/** The offset of the n-th section header of a built ELF, and the sizes of its entries. */
function shdrAt(elf: Buffer, n: number): { at: number; wide: boolean } {
  const wide = elf[4] === 2;
  const shoff = wide ? Number(elf.readBigUInt64LE(40)) : elf.readUInt32LE(32);
  return { at: shoff + n * (wide ? 64 : 40), wide };
}

test("an ELF section whose bytes run past the end of the file is a problem, and its entropy says over how many bytes it was measured", async () => {
  await withCwd(async (cwd) => {
    const elf = buildElf({ cls: 32, sections: [{ name: ".text", type: 1, flags: 6, data: Buffer.from("code".repeat(40)) }, { name: ".symtab", type: 2, data: Buffer.alloc(64, 3) }] });
    const sec = shdrAt(elf, 2); // .symtab
    elf.writeUInt32LE(1408, sec.at + 20); // sh_size of an Elf32_Shdr: far more than the file holds
    const out = await pe(cwd, elf);
    assert.equal(out.status, "partial", JSON.stringify(out.problems));
    assert.ok(out.problems.some((p: string) => /section 2 .*past the end of the \d+-byte file/.test(p)), JSON.stringify(out.problems));
    const row = out.sections[2];
    assert.equal(row.file_range_in_file, false);
    assert.match(row.entropy_note, /measured over \d+ of 1408 bytes/);
    // An SHT_NOBITS section has no bytes in the file: its size past the end is not a problem.
    const bss = buildElf({ cls: 64, sections: [{ name: ".bss", type: 8, flags: 3 }] });
    bss.writeBigUInt64LE(1n << 30n, shdrAt(bss, 1).at + 32);
    const clean = await pe(cwd, bss);
    assert.equal(clean.status, "complete", JSON.stringify(clean.problems));
  });
});

test("an ELF segment whose bytes run past the end of the file is a problem", async () => {
  await withCwd(async (cwd) => {
    const elf = buildElf({ cls: 32, needed: ["libc.so.6"] });
    elf.writeUInt32LE(2 << 20, 52 + 16); // p_filesz of the first Elf32_Phdr
    const out = await pe(cwd, elf);
    assert.equal(out.status, "partial");
    assert.ok(out.problems.some((p: string) => /segment 0 .*past the end of the \d+-byte file/.test(p)), JSON.stringify(out.problems));
    assert.match(out.segments[0].entropy_note, /measured over \d+ of 2097152 bytes/);
  });
});

test("a PE whose certificate table lies past the end of the file is partial: the first entry's header was not read", async () => {
  await withCwd(async (cwd) => {
    const out = await pe(cwd, buildPe({ certificate: { offset: 0x7fffffff, size: 0x1000 } }).file);
    assert.equal(out.certificate_table.within_file, false);
    assert.equal(out.status, "partial");
    assert.ok(out.problems.some((p: string) => /certificate table .*not inside the .*-byte file/.test(p)), JSON.stringify(out.problems));
    // A file cut inside its certificate table is the same finding.
    const trailing = Buffer.alloc(300, 9);
    const base = buildPe({ trailing });
    const at = base.file.length - trailing.length;
    const whole = buildPe({ trailing, certificate: { offset: at, size: 300 } }).file;
    const cut = await pe(cwd, whole.subarray(0, whole.length - 100));
    assert.equal(cut.status, "partial");
  });
});

test("a Mach-O segment or code signature beyond the end of its slice is a problem", async () => {
  await withCwd(async (cwd) => {
    const outside = buildMacho({ commands: [{ segment: "__TEXT", fileoff: 0x4000, filesize: 0x1000 }, { signature: { offset: 0x8000, size: 0x100 } }] });
    const out = await pe(cwd, outside);
    assert.equal(out.status, "partial");
    assert.ok(out.problems.some((p: string) => /segment __TEXT.*past the end/.test(p)), JSON.stringify(out.problems));
    assert.ok(out.problems.some((p: string) => /code signature .*past the end/.test(p)), JSON.stringify(out.problems));
    // A slice of a universal binary is judged against the slice, not the file.
    const fat = buildFat([{ cputype: CPU_X86_64, data: buildMacho({ commands: [{ segment: "__TEXT", fileoff: 0, filesize: 0x3000 }] }) }, { cputype: CPU_ARM64, data: Buffer.alloc(0x6000) }]);
    const sliced = await pe(cwd, fat);
    assert.equal(sliced.status, "partial", "0x3000 bytes of segment in a slice of fewer than 0x3000");
  });
});

test("the run time of pe_info does not grow with sections times thunks: sixty-five thousand sections and three thousand thunks", async () => {
  await withCwd(async (cwd) => {
    const sections = Array.from({ length: 65_534 }, (_, i) => ({ name: `s${i % 1000}`, data: Buffer.from([i & 0xff]), flags: SCN_INIT | SCN_READ }));
    const built = buildPe({ sections, imports: [{ dll: "A.dll", functions: ["f"], repeat: 3000 }] });
    await put(cwd, "work/many.bin", built.file);
    const started = Date.now();
    const out = body(await tool(PE_INFO, cwd, { path: "work/many.bin" }));
    const seconds = (Date.now() - started) / 1000;
    assert.equal(out.import_function_count, 3000);
    assert.equal(out.sections_read, 65_535);
    assert.ok(seconds < 8, `${seconds} s for 65,535 sections and 3,000 thunks`);
  });
});

test("the tool has its own clock: max_seconds ends a read that would take longer, keeps what it read and says so", async () => {
  await withCwd(async (cwd) => {
    const built = buildPe({ imports: [{ dll: "A.dll", functions: ["f"], repeat: 4_000_000 }] });
    await put(cwd, "work/slow.bin", built.file);
    const started = Date.now();
    const out = body(await tool(PE_INFO, cwd, { path: "work/slow.bin", max_seconds: 1 }));
    assert.ok((Date.now() - started) / 1000 < 20);
    assert.equal(out.status, "partial");
    assert.ok(out.limits_hit.some((l: string) => /time|max_seconds/i.test(l)), JSON.stringify(out.limits_hit));
    // How many thunks were counted before the clock ran out depends on the machine (a slow runner may count none): the contract
    // is that the count, when there is one, is a lower bound that stops short of the file, and that the answer says it stopped.
    assert.ok(out.import_function_count === null || (out.import_function_count >= 0 && out.import_function_count < 4_000_000), String(out.import_function_count));
    assert.ok(out.coverage.structures_not_read.length > 0 || out.problems.length > 0 || out.limits_hit.length > 0);
    const bad = refused(await tool(PE_INFO, cwd, { path: "work/slow.bin", max_seconds: 0 }));
    assert.match(bad.error, /max_seconds/);
  });
});

function macho(ncmds: number, command: (i: number) => Buffer): Buffer {
  const body = Buffer.concat(Array.from({ length: ncmds }, (_, i) => command(i)));
  const header = Buffer.alloc(32);
  Buffer.from([0xcf, 0xfa, 0xed, 0xfe]).copy(header, 0);
  header.writeUInt32LE(CPU_X86_64, 4);
  header.writeUInt32LE(2, 12);
  header.writeUInt32LE(ncmds, 16);
  header.writeUInt32LE(body.length, 20);
  return Buffer.concat([header, body]);
}

test("more load commands than the limit is a limit hit and a partial slice, not a complete read", async () => {
  await withCwd(async (cwd) => {
    const filler = macho(70_000, () => Buffer.concat([u32(0x7f), u32(8)]));
    const out = await pe(cwd, filler);
    assert.equal(out.status, "partial");
    assert.equal(out.load_commands_read, 65_536);
    assert.ok(out.limits_hit.some((l: string) => /load commands/.test(l)), JSON.stringify(out.limits_hit));
  });
});

test("the load commands are a table kept whole in a file when they are more than the answer holds", async () => {
  await withCwd(async (cwd) => {
    const dylib = (i: number) => {
      const name = Buffer.from(`/usr/lib/lib${i}.dylib\0`.padEnd(40, "\0"));
      return Buffer.concat([u32(0x0c), u32(24 + name.length), u32(24), u32(2), u32(0x10000), u32(0x10000), name]);
    };
    const out = await pe(cwd, macho(2000, dylib), { limit: 100 });
    assert.equal(out.linked_libraries.length, 2000);
    assert.equal(out.commands.length, 100);
    assert.equal(out.tables.load_commands.matched, 2000);
    assert.equal(out.tables.load_commands.truncated, true);
    const rows = (await readFile(join(cwd, out.tables.load_commands.all_results), "utf8")).trim().split("\n");
    assert.equal(rows.length, 2000);
  });
});

test("a Mach-O command whose size is not aligned, a library name with no terminator, and slices that overlap are problems", async () => {
  await withCwd(async (cwd) => {
    const odd = await pe(cwd, macho(1, () => Buffer.concat([u32(0x0c), u32(27), u32(24), u32(2), u32(0x10000), u32(0x10000), Buffer.from("abc")])));
    assert.equal(odd.status, "partial");
    assert.ok(odd.problems.some((p: string) => /not a multiple of 8/.test(p)), JSON.stringify(odd.problems));
    const name = Buffer.from("/usr/lib/libx.dylib"); // no NUL inside the command
    const unterminated = await pe(cwd, macho(1, () => Buffer.concat([u32(0x0c), u32(24 + name.length + 5), u32(24), u32(2), u32(0x10000), u32(0x10000), name, Buffer.alloc(5, 0x41)])));
    assert.ok(unterminated.problems.some((p: string) => /terminator/.test(p)), JSON.stringify(unterminated.problems));
    const fat = buildFat([{ cputype: CPU_X86_64, data: SLICE_A() }, { cputype: CPU_ARM64, data: SLICE_B() }]);
    fat.writeUInt32BE(fat.readUInt32BE(8 + 8), 8 + 20 + 8); // the second slice starts where the first does
    const overlap = await pe(cwd, fat);
    assert.equal(overlap.status, "partial");
    assert.ok(overlap.problems.some((p: string) => /slices 0 and 1 overlap/.test(p)), JSON.stringify(overlap.problems));
  });
});

test("more than 65,535 program headers is a limit hit, not a silent cut", async () => {
  await withCwd(async (cwd) => {
    const phnum = 70_000;
    const hdr = Buffer.alloc(64);
    hdr.write("\x7fELF", 0, "latin1");
    hdr[4] = 2;
    hdr[5] = 1;
    hdr[6] = 1;
    hdr.writeUInt16LE(2, 16);
    hdr.writeUInt16LE(0x3e, 18);
    hdr.writeBigUInt64LE(64n, 32); // e_phoff
    const shoff = 64 + phnum * 56;
    hdr.writeBigUInt64LE(BigInt(shoff), 40); // e_shoff
    hdr.writeUInt16LE(64, 52);
    hdr.writeUInt16LE(56, 54);
    hdr.writeUInt16LE(0xffff, 56); // e_phnum: PN_XNUM, the real count is section header 0's sh_info
    hdr.writeUInt16LE(64, 58);
    hdr.writeUInt16LE(1, 60);
    const sh0 = Buffer.alloc(64);
    sh0.writeUInt32LE(phnum, 44); // sh_info
    const out = await pe(cwd, Buffer.concat([hdr, Buffer.alloc(phnum * 56), sh0]));
    assert.equal(out.program_headers, phnum);
    assert.equal(out.status, "partial");
    assert.ok(out.limits_hit.some((l: string) => /program headers/.test(l)), JSON.stringify(out.limits_hit));
  });
});

test("with_imports false says the import directory was not read, and does not list an empty import table", async () => {
  await withCwd(async (cwd) => {
    const out = await pe(cwd, buildPe({ imports: [{ dll: "A.dll", functions: ["f"] }] }).file, { with_imports: false });
    assert.equal(out.imports, null);
    assert.ok(!out.coverage.structures_read.some((x: string) => /import directory/.test(x)));
    assert.ok(out.coverage.structures_not_read.some((x: string) => /import directory.*not requested/.test(x)));
  });
});

test("every answer carries problems, limits and coverage; a directory, a pipe and a missing file are not all 'no such file'", async () => {
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "work", "d"), { recursive: true });
    spawnSync("mkfifo", [join(cwd, "work", "pipe")]);
    const dir = refused(await tool(PE_INFO, cwd, { path: "work/d" }));
    assert.match(dir.error, /not a regular file \(a directory\)/);
    const pipe = refused(await tool(PE_INFO, cwd, { path: "work/pipe" }));
    assert.match(pipe.error, /not a regular file \(a named pipe\)/);
    const none = refused(await tool(PE_INFO, cwd, { path: "work/none" }));
    assert.match(none.error, /no such file/);
    for (const answer of [dir, pipe, none, refused(await tool(PE_INFO, cwd, { path: "work/none", limit: 0 }))]) {
      assert.ok(Array.isArray(answer.problems) && Array.isArray(answer.limits_hit), JSON.stringify(answer));
      assert.ok(Array.isArray(answer.coverage.structures_not_read) && answer.coverage.structures_not_read.length > 0);
    }
    await put(cwd, "work/dos.bin", "MZ" + "\0".repeat(100));
    const failed = refused(await tool(PE_INFO, cwd, { path: "work/dos.bin" }));
    assert.equal(failed.status, "failed");
    assert.ok(Array.isArray(failed.coverage.structures_not_read));
  });
});

test("a dynamic string that carries user-info or a query value is withheld, with where it lies in the file", async () => {
  await withCwd(async (cwd) => {
    const runpath = "/opt/lib:https://svc:hunter2pw@pkg.example/lib?sig=Zk3pQ9x7LmN2vB8dTrYw5uHc1aEf";
    const elf = buildElf({ cls: 64, needed: ["libc.so.6"], runpath, interp: "/lib64/ld-linux-x86-64.so.2" });
    const out = await pe(cwd, elf);
    const text = JSON.stringify(out);
    for (const secret of ["hunter2pw", "Zk3pQ9x7LmN2vB8dTrYw5uHc1aEf", "svc:"]) assert.ok(!text.includes(secret), `${secret} is in the answer`);
    assert.deepEqual(out.needed_libraries, ["libc.so.6"]);
    assert.equal(out.interpreter, "/lib64/ld-linux-x86-64.so.2");
    const field = out.withheld_fields.find((f: Json) => f.field === "runpath");
    assert.ok(field && typeof field.file_offset === "number" && field.length === runpath.length, JSON.stringify(out.withheld_fields));
    assert.equal(elf.subarray(field.file_offset, field.file_offset + field.length).toString(), runpath, "the offset names the string in the sample");
    // Ordinary library names and paths are untouched.
    const plain = await pe(cwd, buildElf({ cls: 64, needed: ["libstdc++.so.6"], runpath: "$ORIGIN/../lib" }));
    assert.deepEqual(plain.withheld_fields ?? [], []);
    assert.equal(plain.runpath, "$ORIGIN/../lib");
  });
});
