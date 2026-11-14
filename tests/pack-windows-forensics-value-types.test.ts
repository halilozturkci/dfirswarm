/**
 * windows-forensics, the seventh verification's five P1s, all in the typed part of the shared HIVE BOUNDS block's read_values: a value is now
 * found the same way whatever its type (in its record, inside its own data cell, or put together from a big data record's segments, each
 * inside its cell) and only then taken by its type, by one table (VALUE_TYPES in the block).
 *
 *   - Big data was put together for six types only: for REG_RESOURCE_LIST, REG_LINK, an unknown type or a device property the "db" record and
 *     the bytes after it were the value, complete.
 *   - registry_recover wrote every REG_FILETIME as "data": null; it now writes the ISO time and the FILETIME number.
 *   - A FILETIME past the year 9999 was 1601-01-01, complete; it is now its 8 bytes and a problem.
 *   - A value declaring more than its data cell holds was given with the next cells' bytes (a withheld neighbour's among them); it is not read.
 *   - Binary types went through regipy's text decoding, which strips NULs: 8 bytes 01 00*7 were one character. They are now their bytes, whole.
 *
 * Every hive is written here from the regf layout (tests/windows-hive-writer.ts); nothing is taken from a tool's output.
 */
import assert from "node:assert/strict";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { withCwd } from "./tool-library-harness.ts";
import { REGIPY, body, tool } from "./windows-pack-harness.ts";
import { HiveWriter, REG, SEGMENT, hiveWith, multi, u16 } from "./windows-hive-writer.ts";

type Answer = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

const EXPAND_SZ = 2;
const LINK = 6;
const RESOURCE_LIST = 8;
const FULL_RESOURCE_DESCRIPTOR = 9;
const FILETIME = 16;
const UNKNOWN = 0x77;
const DEVPROP_UINT32 = 0xffff0007;
const DEVPROP_FILETIME = 0xffff0010;
const DEVPROP_BOOLEAN = 0xffff0011;
const DEVPROP_BINARY = 0xffff0009;

const ft = (n: bigint): Buffer => {
  const b = Buffer.alloc(8);
  b.writeBigUInt64LE(n);
  return b;
};

async function run(name: string, cwd: string, file: string, data: Buffer, args: Record<string, unknown>): Promise<{ out: Answer; stdout: string }> {
  await mkdir(join(cwd, "work"), { recursive: true });
  await writeFile(join(cwd, "work", file), data);
  const r = await tool(name, cwd, { hive: `work/${file}`, ...args });
  return { out: body<Answer>(r), stdout: r.stdout };
}

/** 20,480 bytes that hold no text: a 16-byte pattern. */
const BIG = Buffer.concat(Array.from({ length: 1280 }, () => Buffer.from("10000000000000000000000000000000", "hex")));

test("a big data value is put together for every type: the segments' bytes are the value, never the db record and what follows it", { skip: REGIPY }, async () => {
  await withCwd(async (cwd) => {
    const text = u16("x".repeat(BIG.length / 2));
    for (const [type, data, label, shown] of [
      [RESOURCE_LIST, BIG, "REG_RESOURCE_LIST", BIG.toString("hex")],
      [FULL_RESOURCE_DESCRIPTOR, BIG, "REG_FULL_RESOURCE_DESCRIPTOR", BIG.toString("hex")],
      [UNKNOWN, BIG, String(UNKNOWN), BIG.toString("hex")],
      [DEVPROP_BINARY, BIG, String(DEVPROP_BINARY), BIG.toString("hex")],
      [LINK, text, "REG_LINK", "x".repeat(BIG.length / 2)],
      [REG.binary, BIG, "REG_BINARY", BIG.toString("hex")],
    ] as Array<[number, Buffer, string, string]>) {
      // What follows the db record in the file is a cell of 0x22 bytes: the old reading gave the record and those bytes as the value.
      const hive = hiveWith((w) => [w.value("V", type, data), w.cell(HiveWriter.vk("Last", REG.dword, 0x80000004, 7))], 24_000);
      const { out } = await run("regkv", cwd, `h${type}.dat`, hive, { key: "K" });
      assert.equal(out.status, "complete", `${label}: ${JSON.stringify(out.problems)}`);
      assert.equal(out.value_types.V, label);
      assert.equal(out.values.V, shown, `${label}: the value is the segments' bytes`);
      assert.equal(out.values.Last, 7);
    }
  });
});

test("a value that declares more than its data cell holds, or a big data value whose segment runs past its cell, is not read: the next cells' bytes are never its value", { skip: REGIPY }, async () => {
  await withCwd(async (cwd) => {
    const secret = Buffer.concat([u16("hunter2-Secret-Value"), Buffer.alloc(2)]);
    const hive = hiveWith((w) => {
      const a = w.cell(HiveWriter.vk("A", REG.binary, 160, w.cell(Buffer.alloc(8, 1))));
      const p = w.value("Password", REG.sz, secret);
      const ok = w.value("Ok", REG.binary, Buffer.alloc(8, 2));
      return [a, p, ok];
    });
    const { out, stdout } = await run("regkv", cwd, "cell.dat", hive, { key: "K" });
    assert.equal(out.status, "partial");
    assert.ok(!("A" in out.values), JSON.stringify(out.values.A)?.slice(0, 80));
    assert.equal(out.values.Ok, "0202020202020202");
    assert.match(JSON.stringify(out.problems), /\(REG_BINARY\) is not read: it declares 160 bytes of data and its data cell \(offset \d+\) holds 12: the bytes past the cell are not its data/);
    assert.equal(stdout.includes(secret.subarray(0, 14).toString("hex")), false, "the withheld neighbour's bytes are not printed");

    const big = hiveWith((w) => {
      const first = w.cell(Buffer.alloc(SEGMENT, 0x41));
      const short = w.cell(Buffer.alloc(100, 0x42));
      return [w.cell(HiveWriter.vk("Big", REG.binary, SEGMENT + 4000, w.db([first, short]))), w.value("Ok", REG.binary, Buffer.alloc(8, 2))];
    }, 8000);
    const b = (await run("regkv", cwd, "seg.dat", big, { key: "K" })).out;
    assert.equal(b.status, "partial");
    assert.ok(!("Big" in b.values));
    assert.match(JSON.stringify(b.problems), /it declares 4000 bytes of data and the cell of its segment 2 of 2 \(offset \d+\) holds 100/);
  });
});

test("binary, unknown and device-property types are their bytes, whole and never trimmed of NULs; text that is not UTF-16 is its bytes and a problem", { skip: REGIPY }, async () => {
  await withCwd(async (cwd) => {
    const hive = hiveWith((w) => [
      w.value("Frd", FULL_RESOURCE_DESCRIPTOR, Buffer.from("0100000000000000", "hex")),
      w.value("Unk", 0x1234, Buffer.from("616200000000", "hex")),
      w.value("DevU32", DEVPROP_UINT32, Buffer.from("41000000", "hex")),
      w.value("DevBool", DEVPROP_BOOLEAN, Buffer.from("00", "hex")),
      w.value("Text", REG.sz, Buffer.concat([u16("ok"), Buffer.alloc(3)])),
    ]);
    const { out } = await run("regkv", cwd, "types.dat", hive, { key: "K" });
    assert.equal(out.status, "complete", JSON.stringify(out.problems));
    assert.deepEqual(out.values, { DevBool: "00", DevU32: "41000000", Frd: "0100000000000000", Text: "ok", Unk: "616200000000" });
    assert.deepEqual(out.value_lengths, { DevBool: 1, DevU32: 4, Frd: 8, Text: 2, Unk: 6 });
    assert.deepEqual([out.value_types.DevU32, out.value_types.DevBool, out.value_types.Unk], [String(DEVPROP_UINT32), String(DEVPROP_BOOLEAN), String(0x1234)]);

    const bad = hiveWith((w) => [
      w.value("Odd", REG.sz, Buffer.concat([u16("cmd.exe"), Buffer.alloc(2), Buffer.from("X")])),
      w.value("Surrogate", EXPAND_SZ, Buffer.concat([u16("ok"), Buffer.from([0x41, 0xd8, 0x80, 0x00]), Buffer.alloc(2)])),
      w.value("Multi", REG.multi_sz, multi(["one", "", "two"])),
    ]);
    const b = (await run("regkv", cwd, "bad.dat", bad, { key: "K" })).out;
    assert.equal(b.status, "partial");
    assert.equal(b.values.Odd, Buffer.concat([u16("cmd.exe"), Buffer.alloc(2), Buffer.from("X")]).toString("hex"));
    assert.equal(b.values.Surrogate, "6f006b0041d880000000");
    assert.deepEqual(b.values.Multi, ["one", "two"]);
    const said = JSON.stringify(b.problems);
    assert.match(said, /\(REG_SZ\) is not valid UTF-16 text from byte 16 of its 17: its bytes are given, not text/);
    assert.match(said, /\(REG_EXPAND_SZ\) is not valid UTF-16 text from byte 4 of its 10/);
    assert.match(said, /\(REG_MULTI_SZ\) holds 1 string\(s\) after the empty string that ends its list: they are given/);
  });
});

test("a REG_FILETIME is its exact ISO time (registry_recover writes the FILETIME beside it, never null); one past 9999 is its bytes and a problem", { skip: REGIPY }, async () => {
  await withCwd(async (cwd) => {
    const good = hiveWith((w) => [
      w.value("Whole", FILETIME, ft(133443104000000000n)),
      w.value("Ticks", FILETIME, ft(133443104123456789n)),
      w.value("Dev", DEVPROP_FILETIME, ft(133443104123456789n)),
    ]);
    const r = (await run("regkv", cwd, "ft.dat", good, { key: "K" })).out;
    assert.equal(r.status, "complete", JSON.stringify(r.problems));
    assert.deepEqual([r.values.Whole, r.values.Ticks], ["2023-11-13T00:53:20.0000000Z", "2023-11-13T00:53:32.3456789Z"]);
    assert.deepEqual([r.value_types.Dev, r.values.Dev], [String(DEVPROP_FILETIME), ft(133443104123456789n).toString("hex")]);

    const rec = (await run("registry_recover", cwd, "ft2.dat", good, {})).out;
    assert.equal(rec.status, "complete", rec.status_basis);
    const rows = (await readFile(join(cwd, rec.records.keys_file), "utf8")).trimEnd().split("\n").map((l) => JSON.parse(l) as Answer).filter((x) => x.row === "value");
    const by = Object.fromEntries(rows.map((x) => [x.name, x]));
    assert.deepEqual([by.Whole.data, by.Whole.filetime, by.Whole.length], ["2023-11-13T00:53:20.0000000Z", "133443104000000000", 8]);
    assert.deepEqual([by.Ticks.data, by.Ticks.filetime], ["2023-11-13T00:53:32.3456789Z", "133443104123456789"]);
    assert.deepEqual([by.Dev.type, by.Dev.data_hex], [String(DEVPROP_FILETIME), ft(133443104123456789n).toString("hex")]);
    for (const x of rows) assert.ok(x.data !== null && (x.data !== undefined || x.data_hex !== undefined), JSON.stringify(x));

    const far = hiveWith((w) => [w.value("Max", FILETIME, Buffer.alloc(8, 0xff)), w.value("Y10000", FILETIME, ft(2650467744000000000n))]);
    const f = (await run("regkv", cwd, "far.dat", far, { key: "K" })).out;
    assert.equal(f.status, "partial");
    assert.deepEqual([f.values.Max, f.values.Y10000], ["ffffffffffffffff", ft(2650467744000000000n).toString("hex")]);
    assert.equal((JSON.stringify(f.problems).match(/holds a FILETIME past the end of the year 9999, which has no date: its 8 bytes are given, not a time/g) ?? []).length, 2);
    const fr = (await run("registry_recover", cwd, "far2.dat", far, {})).out;
    assert.equal(fr.status, "partial");
    assert.match(JSON.stringify(fr.records.problems), /holds a FILETIME past the end of the year 9999/);
  });
});
