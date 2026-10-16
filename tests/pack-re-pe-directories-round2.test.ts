/**
 * pe_directories, the findings of the second review, one case each: the section mapping for images whose FileAlignment is below 512,
 * version string tables whose keys withhold to one text, a CodeView GUID whose bytes are text, and the one way out that every key and
 * value passes (shared with doc_structure). Fixtures follow the Microsoft PE/COFF specification (the optional header's SectionAlignment
 * and FileAlignment at offsets 32 and 36, 40-byte section headers, the debug directory's RSDS record) and the VS_VERSIONINFO layout.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { test } from "node:test";
import { PE_DIRECTORIES, body, put, tool, withCwd } from "./pack-re-harness.ts";
import type { Json } from "./pack-re-harness.ts";
import { buildPeDirs, vsBlock } from "./pack-re-doc-fixtures.ts";

const GHP = "ghp_Ab3dEf5hIj7lMn9pQr1tUv3xYz5bCd7fGh9j";
const OTHER = "ghp_Zz9yXw8vUt7sRq6pOn5mLk4jIh3gFe2dCb1a";

async function run(cwd: string, name: string, data: Buffer, args: Record<string, unknown> = {}): Promise<{ a: Json; text: string }> {
  await put(cwd, `work/${name}`, data);
  const r = await tool(PE_DIRECTORIES, cwd, { path: `work/${name}`, ...args });
  return { a: body(r), text: r.stdout };
}

/** The file offset of the section header named `name` ([PE/COFF] 3.4: 40 bytes each, after the optional header). */
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

const utf16z = (s: string): Buffer => Buffer.from(s + "\0", "utf16le");

test("PointerToRawData with FileAlignment below 512 (PE/COFF allows it when SectionAlignment is below the page size, and the two are then equal) is read as written, not rounded to 512", async () => {
  await withCwd(async (cwd) => {
    const pe = buildPeDirs({ exports: { functions: [{ name: "Alpha" }, { name: "Beta" }] } });
    const opt = pe.file.readUInt32LE(0x3c) + 24;
    pe.file.writeUInt32LE(0x40, opt + 32); // SectionAlignment
    pe.file.writeUInt32LE(0x40, opt + 36); // FileAlignment
    // Move .rdata's bytes to an offset that is a multiple of 0x40 and not of 0x200: a reader that rounds to 512 reads other bytes.
    const at = sectionHeaderAt(pe.file, ".rdata");
    const raw = pe.file.readUInt32LE(at + 20), size = pe.file.readUInt32LE(at + 16);
    const pad = (0x240 - (pe.file.length % 0x200) + 0x200) % 0x200;
    const moved = pe.file.length + pad;
    const file = Buffer.concat([pe.file, Buffer.alloc(pad, 0xcc), pe.file.subarray(raw, raw + size)]);
    file.writeUInt32LE(moved, at + 20);
    assert.equal(moved % 0x40, 0);
    assert.notEqual(moved % 0x200, 0);
    const { a } = await run(cwd, "low.dll", file);
    assert.equal(a.file_alignment, 0x40);
    assert.deepEqual(a.tables.exports.rows.map((r: Json) => r.name), ["Alpha", "Beta"]);
    assert.equal(a.sections_read_from_rounded_offsets, undefined);
  });
});

test("two version string tables whose keys are withheld to one text are both kept (the second as '#2'), and neither key is printed", async () => {
  await withCwd(async (cwd) => {
    const fixed = Buffer.alloc(52);
    fixed.writeUInt32LE(0xfeef04bd, 0);
    const str = (k: string, v: string): Buffer => vsBlock(k, utf16z(v), [], { text: true, valueLength: v.length + 1 });
    const t1 = vsBlock(GHP, Buffer.alloc(0), [str("CompanyName", "First Corp")], { text: true });
    const t2 = vsBlock(OTHER, Buffer.alloc(0), [str("CompanyName", "Second Corp")], { text: true });
    const version = vsBlock("VS_VERSION_INFO", fixed, [vsBlock("StringFileInfo", Buffer.alloc(0), [t1, t2], { text: true })]);
    const pe = buildPeDirs({ resources: [{ type: 16, name: 1, lang: 1033, data: version }] });
    const { a, text } = await run(cwd, "v.dll", pe.file);
    assert.ok(!text.includes(GHP.slice(4, 13)) && !text.includes(OTHER.slice(4, 13)));
    const tables = a.resources.version_info.string_tables;
    assert.equal(Object.keys(tables).length, 2, JSON.stringify(tables));
    assert.deepEqual(Object.values(tables).map((t: Json) => t.CompanyName.value).sort(), ["First Corp", "Second Corp"]);
    assert.ok(Object.keys(tables).some((k) => / #2$/.test(k)));
  });
});

test("a CodeView GUID whose sixteen bytes read as text is withheld, by its length; neither the text nor its hex is printed", async () => {
  await withCwd(async (cwd) => {
    const pe = buildPeDirs({ debug: [{ type: 2, guid: Buffer.from(GHP.slice(0, 16)) }] });
    const { a, text } = await run(cwd, "g.dll", pe.file);
    assert.equal(a.debug.entries[0].codeview.guid, "<16 bytes that read as text, withheld>");
    assert.ok(!text.toLowerCase().includes(Buffer.from(GHP.slice(4, 13)).toString("hex")));
    const plain = buildPeDirs({ debug: [{ type: 2, guid: Buffer.from("0609020000000000c000000000000046", "hex") }] });
    const { a: b } = await run(cwd, "p.dll", plain.file);
    assert.equal(b.debug.entries[0].codeview.guid, "00020906-0000-0000-C000-000000000046");
  });
});

test("pe_directories binds the linear span finder, and it finds what the shared block's token_spans finds on generated text", () => {
  const code = [
    "import importlib.util, random, sys",
    "spec = importlib.util.spec_from_file_location('pd', sys.argv[1]); pd = importlib.util.module_from_spec(spec); spec.loader.exec_module(pd)",
    "assert pd.token_spans is pd._linear_token_spans",
    "rnd = random.Random(7)",
    "atoms = ['/', '=', '\\n', 'aB3d', 'ghp_Ab3dEf5hIj7lMn9pQr1tUv3x', 'AKIAIOSFODNN7EXAMPLE', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY', '@', ':', '//', 'x']",
    "print(sum(pd._shared_token_spans(s) != pd._linear_token_spans(s) for s in (''.join(rnd.choice(atoms) for _ in range(rnd.randint(0, 40))) for _ in range(10000))))",
  ].join("\n");
  const r = spawnSync("python3", ["-I", "-c", code, PE_DIRECTORIES], { encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
  assert.equal(r.stdout.trim(), "0");
});
