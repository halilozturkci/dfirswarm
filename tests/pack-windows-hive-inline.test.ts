/**
 * Three things the hive readers got wrong on a real SYSTEM hive, each held here on a hive written from the regf layout (tests/windows-hive.ts):
 *
 *   A value whose data is inside its record (four bytes at most) and whose type regipy has no branch for (a device property, a type above
 *   0xFFFF0000; an unknown type) came back as the rest of the hive file: megabytes for four bytes. The shared HIVE BOUNDS block's data budget
 *   then stopped the walk, and registry_recover read 184 of 70,010 values. The block now reads such a value from its record.
 *
 *   registry_recover bounded its inline pages by rows only and printed 144.8 MB. Every inline page is bounded by bytes too, a long row is
 *   shown by its small fields with its line in the file, and `next` says where to read on.
 *
 *   regipy leaves a value out without a word (a value of type 0x00200000 by design, which the HIVE BOUNDS block now reads as its bytes; the
 *   rest of a list after a record it cannot parse). registry_recover counts what the keys declare against what it was given, names each key
 *   that is short, and is partial.
 *
 * And the wording a dirty hive gets is one text in the five readers that carry it.
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { withCwd } from "./tool-library-harness.ts";
import { WIN, body, tool } from "./windows-pack-harness.ts";
import { VARIANTS, retype, type Node } from "./windows-stub-regipy.ts";

type Answer = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any
const REAL = VARIANTS.find((v) => v.real)!;
const DEVPROP_BOOLEAN = 0xffff0011;

/** A hive with inline values of types regipy has no branch for, beside ordinary ones, and enough other data that "the rest of the file" is large. */
function devices(extra: Node[] = []): Node {
  return {
    name: "ROOT",
    children: [
      {
        name: "ControlSet001",
        children: [
          {
            name: "Properties",
            values: [
              { name: "Present", type: DEVPROP_BOOLEAN, value: Buffer.from([0xff, 0, 0, 0]) },
              { name: "Odd", type: 0x1234, value: Buffer.from([7, 8]) },
              { name: "Count", type: "dword", value: 5 },
              { name: "Name", type: "sz", value: "disk" },
            ],
          },
          { name: "Bulk", values: Array.from({ length: 40 }, (_, i) => ({ name: `blob${i}`, type: "binary" as const, value: Buffer.alloc(8000, 0x41 + (i % 20)) })) },
          ...extra,
        ],
      },
    ],
  };
}

test("regkv reads an inline value of a type regipy has no branch for from its record: four bytes, not the rest of the hive", { skip: REAL.skip }, async () => {
  await withCwd(async (cwd) => {
    const env = await REAL.write(cwd, "work/SYSTEM", devices());
    const run = await tool("regkv", cwd, { hive: "work/SYSTEM", key: "ControlSet001\\Properties" }, env);
    const out = body<Answer>(run);
    assert.ok(run.stdout.length < 20_000, `the answer is ${run.stdout.length} bytes for four small values`);
    assert.equal(out.status, "complete", out.status_basis);
    // A type Windows does not define, and a device property, is the record's own bytes, whole, named by its number (VALUE_TYPES in the block).
    assert.equal(out.values.Present, "ff000000");
    assert.equal(out.values.Odd, "0708");
    assert.deepEqual([out.value_types.Present, out.value_types.Odd], [String(DEVPROP_BOOLEAN), String(0x1234)]);
    assert.equal(out.values.Count, 5);
    assert.equal(out.values.Name, "disk");
    assert.deepEqual([out.value_lengths.Present, out.value_lengths.Odd], [4, 2]);
  });
});

test("registry_recover reads every value of such a hive, and its answer stays small: the inline pages are bounded by bytes, a long row is shown by its line", { skip: REAL.skip }, async () => {
  await withCwd(async (cwd) => {
    const big: Node = { name: "Large", values: Array.from({ length: 700 }, (_, i) => ({ name: `v${String(i).padStart(3, "0")}`, type: "binary" as const, value: Buffer.alloc(6000, 0x30 + (i % 10)) })) };
    const env = await REAL.write(cwd, "work/SYSTEM", devices([big]));
    const run = await tool("registry_recover", cwd, { hive: "work/SYSTEM", limit: 5000 }, env);
    const out = body<Answer>(run);
    assert.ok(run.stdout.length < 1 << 20, `the answer is ${run.stdout.length} bytes`);
    assert.equal(out.status, "complete", out.status_basis);
    const records = out.records;
    assert.deepEqual([records.keys, records.values, records.values_declared_by_keys, records.values_not_yielded_by_regipy, records.problem_count], [5, 744, 744, 0, 0]);
    assert.equal(records.inline_values_bounded, true);
    const page = records.keys_page;
    assert.deepEqual([page.total, page.cut_by, page.inline_limits.page_bytes, page.inline_limits.row_bytes], [749, "bytes", 131072, 4096]);
    assert.ok(page.returned < 749 && page.returned === out.keys_inline.length);
    assert.ok(page.inline_bytes <= 131072);
    assert.deepEqual(page.next, { file: records.keys_file, line: page.returned + 1 });
    assert.ok(page.rows_shortened_inline >= 40, "the 8,000-byte values are shown by their small fields");
    const all = readFileSync(join(cwd, records.keys_file), "utf8").trimEnd().split("\n").map((l) => JSON.parse(l) as Answer);
    assert.equal(all.length, 749, "every key and value is whole in the file");
    const shortened = out.keys_inline.find((r: Answer) => r.inline_omitted);
    assert.deepEqual([shortened.row, shortened.type, shortened.length, shortened.unit], ["value", "REG_BINARY", 8000, "bytes"]);
    assert.deepEqual(shortened.data_hex, { omitted_characters: 16000 });
    const whole = all[shortened.inline_omitted.line - 1];
    assert.deepEqual([whole.key, whole.name, whole.data_hex.length], [shortened.key, shortened.name, 16000], "the line the page names is that row, whole");
    assert.ok(shortened.inline_omitted.row_bytes > 16000 && shortened.inline_omitted.row_bytes < 16400, "the row's size in the file is said");
    // The rows of the page are the first rows of the file, in order.
    out.keys_inline.forEach((r: Answer, i: number) => assert.equal(r.name ?? r.path, all[i].name ?? all[i].path));
    const present = all.find((r) => r.name === "Present");
    assert.ok(present && present.length <= 4, `the device property is its own four bytes at most, not ${present?.length}`);
    // The receipt carries the same bounded page, not the rows.
    assert.ok(readFileSync(join(cwd, out.receipt)).length < 1 << 20);
  });
});

test("registry_recover reads a value of type 0x00200000 as its bytes, and says which values the reading left out: a list that ends at a record it cannot parse", { skip: REAL.skip }, async () => {
  await withCwd(async (cwd) => {
    const root: Node = { name: "ROOT", children: [{ name: "Driver", values: [{ name: "A", type: "dword", value: 1 }, { name: "Hidden", type: "binary", value: Buffer.alloc(40, 9) }, { name: "B", type: "sz", value: "x" }] }] };
    const env = await REAL.writePatched(cwd, "work/SYSTEM", root, { real: (buf) => retype(buf, "Hidden", 0x200000), stub: () => undefined });
    const read = body<Answer>(await tool("registry_recover", cwd, { hive: "work/SYSTEM" }, env));
    assert.equal(read.status, "complete", read.status_basis);
    assert.deepEqual([read.records.values, read.records.values_declared_by_keys, read.records.values_not_yielded_by_regipy], [3, 3, 0]);
    const rows = readFileSync(join(cwd, read.records.keys_file), "utf8").trimEnd().split("\n").map((l) => JSON.parse(l) as Answer);
    const hidden = rows.find((r) => r.name === "Hidden")!;
    assert.deepEqual([hidden.type, hidden.length, hidden.data_hex], [String(0x200000), 40, "09".repeat(40)]);

    // A value record whose signature is not "vk": the list ends there without an error, as regipy's does, and the count the key declares says so.
    const broken = await REAL.writePatched(cwd, "work/SYSTEM2", root, { real: (buf) => { buf.write("xx", vkAt(buf, "Hidden"), "latin1"); }, stub: () => undefined });
    const out = body<Answer>(await tool("registry_recover", cwd, { hive: "work/SYSTEM2" }, broken));
    assert.equal(out.status, "partial");
    assert.deepEqual([out.records.values, out.records.values_declared_by_keys, out.records.values_not_yielded_by_regipy, out.records.keys_short_of_values], [1, 3, 2, 1]);
    assert.match(out.records.problems[0].error, /the key declares 3 value\(s\) and regipy gave 1: the 2 it left out are not in keys\.jsonl \(the library ends a key's list at a value record it cannot parse/);
    assert.equal(out.records.problems[0].where, "Driver");
  });
});

/** The offset of the "vk" record of the value named `name` (its name sits 0x14 bytes in). */
function vkAt(buf: Buffer, name: string): number {
  const bytes = Buffer.from(name, "latin1");
  for (let at = 0x1000; at + 0x14 + bytes.length <= buf.length; at++) {
    if (buf[at] === 0x76 && buf[at + 1] === 0x6b && buf.readUInt16LE(at + 2) === bytes.length && buf.subarray(at + 0x14, at + 0x14 + bytes.length).equals(bytes)) return at;
  }
  throw new Error("no value named " + name);
}

test("the wording of a dirty hive is one text in regkv, amcache_apps, shellbags, userassist_bam_shimcache and persistence_normalise", () => {
  const cut = (name: string): string => {
    const text = readFileSync(join(WIN, name, "run.py"), "utf8");
    const from = text.indexOf('LOG_SUFFIXES = (".LOG1", ".LOG2", ".LOG")');
    const to = text.indexOf('"found none (they are not in what this job can read)"', from);
    assert.ok(from > 0 && to > from, `${name} carries the text`);
    return text.slice(from, text.indexOf("\n\n\n", to));
  };
  const first = cut("regkv");
  assert.match(first, /def hive_state\(h, hive_path\):/);
  assert.match(first, /def dirty_caveat\(state\):/);
  for (const name of ["amcache_apps", "shellbags", "userassist_bam_shimcache", "persistence_normalise"]) assert.equal(cut(name), first, name);
  // The twins of the two that have one are the same files.
  for (const name of ["regkv", "amcache_apps"]) {
    assert.ok(readFileSync(join(WIN, name, "run.py")).equals(readFileSync(join(WIN, "..", "..", "..", "tool-library", name, "run.py"))), `${name}: the tool-library twin is byte-equal`);
  }
});
