/**
 * pe_directories, the findings of the review of its first version, one case each, named after the finding. Every file is laid out
 * by hand to the Microsoft PE/COFF specification (tests/pack-re-doc-fixtures.ts, buildPeDirs) and then changed field by field the
 * way the finding describes, never built from the tool's output. What these cases hold: the delay-load tables are read once each
 * and bounded by the file, every bound of the version reader is said, a REPRO build's stamps are not times, a section is read from
 * the bytes the loader maps, and a canary planted in every printable place is in no file the call writes.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile, stat } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { PE_DIRECTORIES, asJob, body, filesUnder, put, tool, withCwd } from "./pack-re-harness.ts";
import type { Json, Run } from "./pack-re-harness.ts";
import { buildPeDirs, versionResource } from "./pack-re-doc-fixtures.ts";

const AKIA = "AKIAIOSFODNN7EXAMPLE";
const GHP = "ghp_Ab3dEf5hIj7lMn9pQr1tUv3xYz5bCd7fGh9j";
const CANARY_SLICES = [AKIA, AKIA.slice(0, 12), GHP, GHP.slice(0, 12)];

async function run(cwd: string, name: string, data: Buffer, args: Record<string, unknown> = {}): Promise<{ a: Json; text: string }> {
  await put(cwd, `work/${name}`, data);
  const r = await tool(PE_DIRECTORIES, cwd, { path: `work/${name}`, ...args });
  return { a: body(r), text: r.stdout };
}

/** The tool with a hard limit on its wall time (killed past it), and how long it took. */
function bounded(cwd: string, args: Record<string, unknown>, killAfterMs: number): { run: Run; seconds: number } {
  const t0 = Date.now();
  const r = spawnSync("python3", [PE_DIRECTORIES], { cwd, input: JSON.stringify(args), encoding: "utf8", maxBuffer: 1 << 28, timeout: killAfterMs, killSignal: "SIGKILL", env: { ...process.env, AGENT_ID: "s1" } });
  return { run: { code: r.status, stdout: r.stdout, stderr: r.stderr }, seconds: (Date.now() - t0) / 1000 };
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

test("P2 delay-load: 2,000 descriptors sharing one name table list it once, and overlapping tables are not listed again: the table file is bounded by the file", async () => {
  await withCwd(async (cwd) => {
    // Descriptor 0 has a name table of 20,000 ordinals; descriptors 1 to 1,999 are given the same table ([PE/COFF] 5.8.1: the
    // delay import name table RVA is at offset 16 of each 32-byte descriptor).
    const ordinals = Array.from({ length: 20_000 }, (_v, i) => i + 1);
    const pe = buildPeDirs({ delayImports: [{ dll: "a.dll", functions: ordinals }, ...Array.from({ length: 1999 }, () => ({ dll: "b.dll", functions: [] as number[] }))] });
    const descs = pe.rawOf(pe.rvas.delayImports!);
    const int0 = pe.file.readUInt32LE(descs + 16);
    for (let d = 1; d < 2000; d++) pe.file.writeUInt32LE(int0, descs + 32 * d + 16);
    await put(cwd, "work/shared.dll", pe.file);
    const { run: r, seconds } = bounded(cwd, { path: "work/shared.dll", max_seconds: 5 }, 60_000);
    const a = body(r);
    assert.ok(seconds < 5 + 5, `the call took ${seconds.toFixed(1)} s`);
    assert.equal(a.tables.delay_imports.matched, 20_000, "the shared table is listed once");
    // 2,000 libraries: the answer lists the first `limit` (1,000) and the whole list is in the file named beside it.
    assert.equal(a.delay_imports.libraries.length, 1000);
    assert.equal(a.delay_imports.libraries_not_shown.items, 2000);
    const all = (await readFile(join(cwd, a.delay_imports.libraries_not_shown.all_results), "utf8")).trim().split("\n").map((l) => JSON.parse(l));
    assert.equal(all.filter((l: Json) => l.name_table_shared_with === 0).length, 1999);
    assert.ok(a.problems.some((p: string) => /delay-load descriptor 1: its name table starts inside the one descriptor 0 uses/.test(p)), JSON.stringify(a.problems.slice(0, 3)));
    // Overlapping tables: descriptor d's table starts 8 x d bytes into descriptor 0's.
    for (let d = 1; d < 2000; d++) pe.file.writeUInt32LE(int0 + 8 * d, descs + 32 * d + 16);
    await put(cwd, "work/overlap.dll", pe.file);
    const o = bounded(cwd, { path: "work/overlap.dll", max_seconds: 5 }, 60_000);
    const b = body(o.run);
    assert.equal(b.tables.delay_imports.matched, 20_000, "every thunk is listed once");
  });
});

test("D5 a zero-length String block in the version information is a problem, and the version status is partial", async () => {
  await withCwd(async (cwd) => {
    const pe = buildPeDirs({ resources: [{ type: 16, name: 1, lang: 1033, data: versionResource() }] });
    // [VS_VERSIONINFO] String: wLength, wValueLength, wType, then szKey. The first String's wLength is set to 0.
    const key = pe.file.indexOf(Buffer.from("CompanyName\0", "utf16le"));
    pe.file.writeUInt16LE(0, key - 6);
    const { a } = await run(cwd, "v0.exe", pe.file);
    assert.equal(a.status, "partial");
    assert.equal(a.resources.version_info.status, "partial");
    assert.ok(a.problems.some((p: string) => /a version block in a StringTable at offset \d+ has a length that does not fit/.test(p)), JSON.stringify(a.problems));
  });
});

test("version bounds: more than 50 keys beyond the well-known ones and a resource over max_stream_bytes are limits, never silent", async () => {
  await withCwd(async (cwd) => {
    const strings = Object.fromEntries(Array.from({ length: 300 }, (_v, i) => [`Key${i}`, `v${i}`]));
    const pe = buildPeDirs({ resources: [{ type: 16, name: 1, lang: 1033, data: versionResource({ strings }) }] });
    const { a } = await run(cwd, "v300.exe", pe.file);
    assert.ok(a.limits_hit.some((l: string) => /hold \d+ keys beyond the well-known ones: the first 50 are named/.test(l)), JSON.stringify(a.limits_hit));
    const small = buildPeDirs({ resources: [{ type: 16, name: 1, lang: 1033, data: versionResource() }] });
    const { a: b } = await run(cwd, "vcut.exe", small.file, { max_stream_bytes: 100 });
    assert.ok(b.limits_hit.some((l: string) => /the version resource is \d+ bytes, over max_stream_bytes \(100\): its first 100 bytes were read/.test(l)), JSON.stringify(b.limits_hit));
  });
});

test("the debug directory past 1,024 entries and CLR stream headers past 4,096 are limits, never a silent cut", async () => {
  await withCwd(async (cwd) => {
    const pe = buildPeDirs({ debug: Array.from({ length: 1100 }, () => ({ type: 13 })) });
    const { a } = await run(cwd, "dbg.exe", pe.file);
    assert.ok(a.limits_hit.some((l: string) => /the debug directory declares 1100 entries: the first 1024 are read/.test(l)), JSON.stringify(a.limits_hit));
    const clr = buildPeDirs({ clr: { streams: Array.from({ length: 5000 }, (_v, i) => ({ name: `#S${i}`, size: 4 })) } });
    const { a: b } = await run(cwd, "clr.exe", clr.file);
    assert.ok(b.limits_hit.some((l: string) => /the CLR metadata declares 5000 stream headers: the first 4096 are read/.test(l)), JSON.stringify(b.limits_hit));
  });
});

test("REPRO: without a REPRO entry a debug stamp is a time; with one, no stamp of the file is rendered as a time", async () => {
  await withCwd(async (cwd) => {
    const plain = buildPeDirs({ debug: [{ type: 2, stamp: 0x65000000 }], exports: { stamp: 0x65000000, functions: [{ name: "A" }] } });
    const { a } = await run(cwd, "p.exe", plain.file);
    assert.equal(a.debug.entries[0].time_date_stamp_utc, "2023-09-12T06:06:56Z");
    assert.equal(a.exports.time_date_stamp_utc, "2023-09-12T06:06:56Z");
    const repro = buildPeDirs({ debug: [{ type: 2, stamp: 0x65000000 }, { type: 16, stamp: 0x65000000 }], exports: { stamp: 0x65000000, functions: [{ name: "A" }] } });
    const { a: b } = await run(cwd, "r.exe", repro.file);
    assert.deepEqual(b.debug.entries.map((e: Json) => e.time_date_stamp_utc), [null, null]);
    assert.equal(b.exports.time_date_stamp_utc, null);
    assert.match(b.exports.time_date_stamp_note, /a hash of the build/);
  });
});

test("PointerToRawData off a 512 multiple with FileAlignment 512 (PE/COFF: a multiple of FileAlignment, which is 512 or more here) is read rounded down to 512, and both values are in the answer", async () => {
  await withCwd(async (cwd) => {
    const pe = buildPeDirs({ exports: { functions: [{ name: "Alpha" }, { name: "Beta" }] } });
    const at = sectionHeaderAt(pe.file, ".rdata");
    const raw = pe.file.readUInt32LE(at + 20);
    pe.file.writeUInt32LE(raw + 0x10, at + 20);
    const { a } = await run(cwd, "u.dll", pe.file);
    assert.deepEqual(a.tables.exports.rows.map((r: Json) => r.name), ["Alpha", "Beta"], "the exports are read from the bytes the loader maps");
    assert.deepEqual(a.sections_read_from_rounded_offsets, [{ section: ".rdata", pointer_to_raw_data: raw + 0x10, read_from: raw }]);
  });
});

test("D4 a manifest that declares an encoding the reader cannot decode is a problem, not a failure", async () => {
  await withCwd(async (cwd) => {
    const pe = buildPeDirs({ resources: [{ type: 24, name: 1, lang: 1033, data: Buffer.from('<?xml version="1.0" encoding="UTV-8"?><assembly/>') }] });
    const { a } = await run(cwd, "m.exe", pe.file);
    assert.equal(a.status, "partial");
    assert.equal(a.resources.manifest.status, "encoding_not_readable");
    assert.ok(a.problems.some((p: string) => /the manifest declares an encoding the XML reader cannot decode/.test(p)), JSON.stringify(a.problems));
  });
});

test("a file that is not a PE gives the first four bytes of its head only", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "work/t.bin", GHP);
    const r = await tool(PE_DIRECTORIES, cwd, { path: "work/t.bin" });
    const a = JSON.parse(r.stdout);
    assert.equal(a.status, "unsupported");
    assert.equal(a.head_hex, Buffer.from(GHP.slice(0, 4)).toString("hex"));
  });
});

test("an extracted resource's digest is in no answer (a hash of a planted token confirms it); with write_values, in a job, it is in the values file only", async () => {
  await withCwd(async (cwd) => {
    const data = Buffer.from("resource bytes, exactly");
    const digest = createHash("sha256").update(data).digest("hex");
    const pe = buildPeDirs({ resources: [{ type: 10, name: 1, lang: 1033, data }] });
    const { a, text } = await run(cwd, "x.exe", pe.file, { extract_to: "work/s1/r", extract: ["resource:0"] });
    assert.equal("sha256" in a.extracted[0], false);
    assert.ok(!text.includes(digest));
    const r = await asJob(PE_DIRECTORIES, cwd, { path: "work/x.exe", extract_to: "out/r", extract: ["resource:0"], write_values: true });
    const job = body(r);
    assert.ok(!r.stdout.includes(digest));
    const values = (await readFile(join(cwd, "out", "pe-directories-values.jsonl"), "utf8")).trim().split("\n").map((l) => JSON.parse(l));
    const v = values.find((x: Json) => x.field === "extracted_resource_sha256");
    assert.equal(v.value, digest);
    assert.equal(v.finding_id, job.extracted[0].sha256_in_values_file);
  });
});

test("P1-4 a canary planted in every printable place of a PE is in no table file and no answer, with limit 1, in a job and outside one", async () => {
  await withCwd(async (cwd) => {
    const pe = buildPeDirs({
      exports: { imageName: `${GHP}.dll`, functions: [{ name: AKIA }, { name: `x${GHP}` }, { name: "Plain", forward: `HOST.${GHP}` }] },
      delayImports: [{ dll: `${AKIA}.dll`, functions: [GHP, "plain", 7] }],
      resources: [{ type: GHP.slice(0, 30), name: AKIA, lang: 1033, data: Buffer.from("r") }, { type: 16, name: 1, lang: 1033, data: versionResource({ strings: { CompanyName: GHP, [AKIA]: "x", FileDescription: AKIA } }) }],
      debug: [{ type: 2, pdb: `C:\\${GHP}\\${AKIA}.pdb` }],
      clr: { version: GHP.slice(0, 30), streams: [{ name: AKIA.slice(0, 20), size: 4 }, { name: "#~", size: 4 }] },
    });
    await put(cwd, "work/in/c.dll", pe.file);
    for (const job of [false, true]) {
      const r = job ? await asJob(PE_DIRECTORIES, cwd, { path: "work/in/c.dll", limit: 1 }) : await tool(PE_DIRECTORIES, cwd, { path: "work/in/c.dll", limit: 1 });
      const a = body(r);
      assert.ok(Object.values(a.tables).some((t: Json) => t.all_results), "limit 1 writes at least one table file");
      for (const slice of CANARY_SLICES) assert.ok(!r.stdout.includes(slice), `${job ? "job: " : ""}${slice} is in the answer`);
      for (const dir of ["work", "out"]) {
        for (const f of await filesUnder(join(cwd, dir))) {
          const path = `${dir}/${f}`;
          if (path.startsWith("work/in/")) continue;
          if (/withheld-names/.test(f)) {
            assert.equal(((await stat(join(cwd, path))).mode & 0o777), 0o600);
            continue;
          }
          const text = (await readFile(join(cwd, path))).toString("latin1");
          for (const slice of CANARY_SLICES) assert.ok(!text.includes(slice), `${job ? "job: " : ""}${slice} is in ${path}`);
        }
      }
    }
  });
});
