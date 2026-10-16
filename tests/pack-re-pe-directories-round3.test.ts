/**
 * pe_directories, the findings of the third review: PointerToRawData against FileAlignment (PE/COFF: FileAlignment "should be a power
 * of 2 between 512 and 64 K, inclusive", equal to SectionAlignment when that is below the page size, and an executable image's
 * PointerToRawData "must be a multiple of FileAlignment"); the problem list's cap tested before a message is withheld. Fixtures from
 * the PE/COFF layout (tests/pack-re-doc-fixtures.ts buildPeDirs), with sections moved by hand, never from the tool's output.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { test } from "node:test";
import { DOC_STRUCTURE, PE_DIRECTORIES, body, put, tool, withCwd } from "./pack-re-harness.ts";
import type { Json } from "./pack-re-harness.ts";
import { buildPeDirs } from "./pack-re-doc-fixtures.ts";

function sectionHeaderAt(file: Buffer, name: string): number {
  const pe = file.readUInt32LE(0x3c);
  const optSize = file.readUInt16LE(pe + 4 + 16);
  const count = file.readUInt16LE(pe + 4 + 2);
  for (let i = 0; i < count; i++) {
    const at = pe + 24 + optSize + 40 * i;
    if (file.subarray(at, at + 8).toString("latin1").replace(/\0+$/, "") === name) return at;
  }
  throw new Error(`no section ${name}`);
}

/** The exports fixture with SectionAlignment and FileAlignment set, and .rdata's bytes moved to the first offset past the file's end that is
 * a multiple of `to` and not of `notTo`. */
function aligned(sa: number, fa: number, to: number, notTo: number): { file: Buffer; moved: number } {
  const pe = buildPeDirs({ exports: { functions: [{ name: "Alpha" }, { name: "Beta" }] } });
  const opt = pe.file.readUInt32LE(0x3c) + 24;
  pe.file.writeUInt32LE(sa, opt + 32);
  pe.file.writeUInt32LE(fa, opt + 36);
  const at = sectionHeaderAt(pe.file, ".rdata");
  const raw = pe.file.readUInt32LE(at + 20), size = pe.file.readUInt32LE(at + 16);
  let moved = pe.file.length;
  while (moved % to || moved % notTo === 0) moved++;
  const file = Buffer.concat([pe.file, Buffer.alloc(moved - pe.file.length, 0xcc), pe.file.subarray(raw, raw + size)]);
  file.writeUInt32LE(moved, at + 20);
  return { file, moved };
}

test("P3 FileAlignment 0x1000 and a section at a multiple of 512 that is not one of 0x1000: read as written, said, partial", async () => {
  await withCwd(async (cwd) => {
    const { file, moved } = aligned(0x1000, 0x1000, 0x200, 0x1000);
    await put(cwd, "work/a.dll", file);
    const a = body(await tool(PE_DIRECTORIES, cwd, { path: "work/a.dll" }));
    assert.equal(a.status, "partial");
    // the fixture's other sections sit at multiples of 512 too: every one is listed, each read from its own value
    const rows = a.sections_not_a_multiple_of_file_alignment as Json[];
    assert.deepEqual(rows.find((r) => r.section === ".rdata"), { section: ".rdata", pointer_to_raw_data: moved, file_alignment: 0x1000, read_from: moved });
    assert.ok(rows.every((r) => r.read_from === r.pointer_to_raw_data));
    assert.ok(a.problems.some((p: string) => new RegExp(`^${rows.length} section\\(s\\) have a PointerToRawData that is not a multiple of FileAlignment \\(0x1000\\)`).test(p)), JSON.stringify(a.problems));
    assert.match(a.sections_note, /a multiple of 512 that is not one of FileAlignment included.*is read as written/);
    assert.deepEqual(a.tables.exports.rows.map((r: Json) => r.name), ["Alpha", "Beta"]);
  });
});

test("P3 FileAlignment 0x100 with SectionAlignment 0x1000 (neither 512..64K nor the low-alignment case): said, partial, read as written", async () => {
  await withCwd(async (cwd) => {
    const { file } = aligned(0x1000, 0x100, 0x100, 0x200);
    await put(cwd, "work/b.dll", file);
    const a = body(await tool(PE_DIRECTORIES, cwd, { path: "work/b.dll" }));
    assert.equal(a.status, "partial");
    assert.ok(a.problems.some((p: string) => /^FileAlignment is 0x100 with SectionAlignment 0x1000: PE\/COFF wants a power of 2 from 512 to 64K/.test(p)), JSON.stringify(a.problems));
    assert.equal(a.sections_not_a_multiple_of_file_alignment, undefined);
    assert.match(a.sections_note, /every value when FileAlignment is below 512, is read as written/);
    assert.deepEqual(a.tables.exports.rows.map((r: Json) => r.name), ["Alpha", "Beta"]);
  });
});

test("P3 the conforming cases stay complete: FileAlignment 0x200, and the low-alignment case (FileAlignment = SectionAlignment = 0x40)", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "work/c.dll", buildPeDirs({ exports: { functions: [{ name: "Alpha" }] } }).file);
    const c = body(await tool(PE_DIRECTORIES, cwd, { path: "work/c.dll" }));
    assert.equal(c.status, "complete", JSON.stringify(c.problems));
    const { file } = aligned(0x40, 0x40, 0x40, 0x200);
    await put(cwd, "work/d.dll", file);
    const d = body(await tool(PE_DIRECTORIES, cwd, { path: "work/d.dll" }));
    assert.equal(d.status, "complete", JSON.stringify(d.problems));
    assert.equal(d.sections_note, undefined);
  });
});

test("P3 the problem list's cap is tested before a message is withheld: past 100 problems, no message is scrubbed again", () => {
  const code = [
    "import importlib.util, json, sys",
    "spec = importlib.util.spec_from_file_location('t', sys.argv[1]); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)",
    "calls = [0]",
    "real = m.scrub",
    "def counted(text, kind='text'):",
    "    calls[0] += 1",
    "    return real(text, kind)",
    "m.scrub = counted",
    "ctx = m.Ctx('k', {'limit': 1, 'max_stream_bytes': 1, 'max_total_bytes': 1, 'max_ratio': 1}, None, 10)",
    "for i in range(50000):",
    "    ctx.problem('problem %d at offset %d' % (i, i))",
    "print(json.dumps({'calls': calls[0], 'listed': len(ctx.problems), 'dropped': ctx.problems_dropped}))",
  ].join("\n");
  for (const path of [PE_DIRECTORIES, DOC_STRUCTURE]) {
    const r = spawnSync("python3", ["-I", "-c", code, path], { encoding: "utf8", env: { ...process.env, AGENT_ID: "s1" } });
    assert.equal(r.status, 0, r.stderr);
    assert.deepEqual(JSON.parse(r.stdout), { calls: 100, listed: 100, dropped: 49900 }, path);
  }
});

test("P3 a tool-output directory that is a symbolic link is refused: nothing is written through it", async () => {
  await withCwd(async (cwd) => {
    const { mkdir, readdir, symlink } = await import("node:fs/promises");
    const { join } = await import("node:path");
    await put(cwd, "work/in/e.dll", buildPeDirs({ exports: { imageName: "a.dll", functions: [{ name: "AKIAIOSFODNN7EXAMPLE" }, { name: "B" }, { name: "C" }] } }).file);
    await mkdir(join(cwd, "elsewhere"), { recursive: true });
    await mkdir(join(cwd, "work", "s1"), { recursive: true });
    await symlink(join(cwd, "elsewhere"), join(cwd, "work", "s1", "tool-output"));
    const a = body(await tool(PE_DIRECTORIES, cwd, { path: "work/in/e.dll", limit: 1 }));
    assert.deepEqual(await readdir(join(cwd, "elsewhere")), []);
    assert.equal(a.status, "partial");
    assert.ok(a.problems.some((p: string) => /is a symbolic link: refused, nothing written through it/.test(p)), JSON.stringify(a.problems));
  });
});
