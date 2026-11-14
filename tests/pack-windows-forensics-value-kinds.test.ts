/**
 * windows-forensics: the known limits of the final verification of 1.8.8, each a value read as something its registry type does not make it.
 *
 *   - amcache_apps read a legacy time value (11, 12, 17: FILETIME; f: Unix linker time) of a binary type from its hex text, and int() took
 *     hex text whose digits are all 0-9 for a decimal: a made-up time, complete. A time is now read only from a number (or a REG_FILETIME).
 *   - HIVE BOUNDS cell_short took the absolute value of a cell's size, so data in a free cell (a size of zero or more) was read as allocated.
 *   - persistence_normalise showed a service or Run value of type REG_FILETIME or REG_LINK as text with no note of its type.
 *   - shellbags decoded a BagMRU slot of type REG_SZ whose text is even-length hex as shell-item bytes.
 *
 * Every hive is written here from the regf layout (tests/windows-hive.ts, tests/windows-hive-writer.ts); nothing is taken from a case.
 */
import assert from "node:assert/strict";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { withCwd } from "./tool-library-harness.ts";
import { REGIPY, body, tool } from "./windows-pack-harness.ts";
import { hive, type HiveKey } from "./windows-hive.ts";
import { HiveWriter, REG, hiveWith } from "./windows-hive-writer.ts";

type Answer = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

const REG_LINK = 6;
const REG_FILETIME = 16;
const nest = (path: string[], leaf: HiveKey): HiveKey => path.reduceRight<HiveKey>((child, name) => ({ name, children: [child] }), leaf);

async function run(name: string, cwd: string, args: Record<string, string>, files: Record<string, Buffer>): Promise<Answer> {
  await mkdir(join(cwd, "work"), { recursive: true });
  for (const [file, data] of Object.entries(files)) await writeFile(join(cwd, "work", file), data);
  return body<Answer>(await tool(name, cwd, args));
}

test("amcache_apps reads a legacy time only from a number: a binary value whose hex digits are all 0-9 is said, not read as a time", { skip: REGIPY }, async () => {
  await withCwd(async (cwd) => {
    const amcache = hive({
      name: "ROOT",
      children: [nest(["Root", "File", "vol1"], {
        name: "1000",
        values: [
          { name: "11", type: "binary", value: Buffer.from("0130000000000000", "hex") },
          { name: "f", type: "binary", value: Buffer.from("12345678", "hex") },
          { name: "12", type: "qword", value: 133_443_104_001_234_567n },
          { name: "15", type: "sz", value: "C:\\Fixtures\\a.exe" },
        ],
      })],
    });
    const out = await run("amcache_apps", cwd, { hive: "work/Amcache.hve" }, { "Amcache.hve": amcache });
    assert.equal(out.status, "partial");
    const row = out.entries[0];
    assert.equal(row.last_modified_timestamp_utc, null);
    assert.equal(row.last_modified_timestamp_filetime, null);
    assert.equal(row.linker_compile_time_utc, null);
    assert.equal(row.created_timestamp_filetime, "133443104001234567", "a REG_QWORD time is read as before");
    assert.match(JSON.stringify(out.problems), /read as last_modified_timestamp is of type REG_BINARY, not a number/);
    assert.match(JSON.stringify(out.problems), /read as linker_compile_time is of type REG_BINARY, not a number/);
  });
});

test("HIVE BOUNDS: a value whose data cell is free (its size is not negative) is not read as allocated data", { skip: REGIPY }, async () => {
  await withCwd(async (cwd) => {
    let freed = 0;
    const data = hiveWith((w) => {
      freed = w.cell(Buffer.alloc(8, 0x33));
      return [w.cell(HiveWriter.vk("Freed", REG.binary, 8, freed)), w.value("Ok", REG.binary, Buffer.alloc(8, 2))];
    });
    data.writeInt32LE(-data.readInt32LE(4096 + freed), 4096 + freed);
    const out = await run("regkv", cwd, { hive: "work/free.dat", key: "K" }, { "free.dat": data });
    assert.equal(out.status, "partial");
    assert.ok(!("Freed" in out.values), JSON.stringify(out.values));
    assert.equal(out.values.Ok, "0202020202020202");
    assert.match(JSON.stringify(out.problems), /\(REG_BINARY\) is not read: its data cell \(offset \d+\) is a free cell \(its size, 16, is not negative\)/);
  });
});

test("persistence_normalise keeps a service or Run value of type REG_LINK or REG_FILETIME with its type and a note, never as a plain command", { skip: REGIPY }, async () => {
  await withCwd(async (cwd) => {
    const ft = Buffer.alloc(8);
    ft.writeBigUInt64LE(133_443_104_000_000_000n);
    const system = hive({
      name: "ROOT",
      children: [
        { name: "Select", values: [{ name: "Current", type: "dword", value: 1 }] },
        nest(["ControlSet001", "Services"], {
          name: "Linked",
          values: [
            { name: "ImagePath", type: "sz", value: "C:\\Fixtures\\svc.exe", typeNumber: REG_LINK },
            { name: "Start", type: "dword", value: 2 },
            { name: "Type", type: "dword", value: 16 },
          ],
        }),
      ],
    });
    const software = hive({
      name: "ROOT",
      children: [nest(["Microsoft", "Windows", "CurrentVersion"], { name: "Run", values: [{ name: "Timed", type: "binary", value: ft, typeNumber: REG_FILETIME }] })],
    });
    const out = await run("persistence_normalise", cwd, { system: "work/SYSTEM", software: "work/SOFTWARE" }, { SYSTEM: system, SOFTWARE: software });
    assert.equal(out.status, "partial");
    const svc = out.items.find((i: Answer) => i.mechanism === "service");
    assert.equal(svc.image_path, undefined, "a REG_LINK is not given as the image path");
    assert.equal(svc.image_path_value_type, "REG_LINK");
    assert.match(JSON.stringify(svc.unsupported_fields), /ImagePath is a REG_LINK value/);
    const run_ = out.items.find((i: Answer) => i.mechanism === "autorun");
    assert.equal(run_.value_type, "REG_FILETIME");
    assert.match(run_.unsupported, /a REG_FILETIME value, not REG_SZ or REG_EXPAND_SZ/);
    assert.match(out.status_basis, /autorun value\(s\) are of a registry type that is not a command/);
  });
});

test("shellbags decodes only a binary slot: a REG_SZ slot whose text is even-length hex is said, not decoded as a shell item", { skip: REGIPY }, async () => {
  await withCwd(async (cwd) => {
    const mru = Buffer.alloc(8);
    mru.writeInt32LE(0, 0);
    mru.writeInt32LE(-1, 4);
    const ntuser = hive({
      name: "ROOT",
      children: [nest(["Software", "Microsoft", "Windows", "Shell"], {
        name: "BagMRU",
        values: [{ name: "0", type: "sz", value: "14001f50e04fd0203aea6910a2d808002b30309d" }, { name: "MRUListEx", type: "binary", value: mru }],
        children: [{ name: "0" }],
      })],
    });
    const out = await run("shellbags", cwd, { hive: "work/NTUSER.DAT" }, { "NTUSER.DAT": ntuser });
    assert.equal(out.status, "partial");
    const entry = out.entries.find((e: Answer) => e.slot === "0");
    assert.equal(entry.item.decoded, "none", JSON.stringify(entry.item));
    assert.match(JSON.stringify(out.problems), /the slot's value is of type REG_SZ, not binary data: it is not decoded as a shell item/);
  });
});
