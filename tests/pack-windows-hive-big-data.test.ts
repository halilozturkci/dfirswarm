/**
 * The shared HIVE BOUNDS block reads every value of a key itself (with the real regipy), and checks a big data value before its data is put
 * together. regipy 6.3 put together whatever a "db" record's list of segments named and then parsed a REG_MULTI_SZ with construct's
 * GreedyRange(CString), which is quadratic in a string that no NUL ends: one 16 KB segment named 160 times in a 24 KB hive was a 2.5 MiB value,
 * and regkv took 69 s against its 30 s timeout; registry_recover gave its first byte at 224 s; a 548 KB hive that declared a 2 GiB value held
 * 4.4 GB of memory, and under a 2 GiB limit the tool was killed without JSON.
 *
 * The hives here are written by this test from the regf layout (a 4096-byte base block, one hbin of cells; a key is an "nk" cell, a value a
 * "vk" cell, a value of more than 16,344 bytes a "db" cell: signature, segment count, offset of a list of segment offsets, each segment a cell
 * of at most 16,344 bytes of data), never from a reader's output.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { PYTHON3 } from "./host-gates.ts";
import { ROOT, runPy, withCwd } from "./tool-library-harness.ts";
import { AGENT, REGIPY, WIN, body, tool } from "./windows-pack-harness.ts";
import { VARIANTS } from "./windows-stub-regipy.ts";
import { HiveWriter, REG, SEGMENT, hiveWith, multi, u16 } from "./windows-hive-writer.ts";

type Answer = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

const NORMAL = ["one", "two", "", "three"];
const BIG_NORMAL = Array.from({ length: 3000 }, (_, i) => "entry" + String(i).padStart(5, "0"));

/**
 * The key K: a REG_MULTI_SZ db value whose list names one segment four times (the hive is padded so that its size alone does not refuse
 * it); a REG_BINARY db value that declares 2 GiB; a REG_MULTI_SZ db value of distinct segments whose last 2 MiB no NUL ends; a small and a
 * big REG_MULTI_SZ that are what Windows writes; a DWORD after them all.
 */
function forged(): Buffer {
  return hiveWith((w) => {
    const segment = w.cell(Buffer.alloc(SEGMENT, 0x41));
    const repeated = w.cell(HiveWriter.vk("Repeated", REG.multi_sz, 4 * SEGMENT, w.db([segment, segment, segment, segment])));
    const huge = w.cell(HiveWriter.vk("Huge", REG.binary, 0x7ffffff0, w.db([segment])));
    const loose = w.value("Loose", REG.multi_sz, Buffer.concat([u16("first"), Buffer.alloc(2), Buffer.alloc(2 << 20, 0).fill(u16("A"))]));
    const normal = w.value("Normal", REG.multi_sz, multi(NORMAL));
    const bigNormal = w.value("BigNormal", REG.multi_sz, multi(BIG_NORMAL));
    const after = w.value("After", REG.dword, Buffer.from([7, 0, 0, 0]));
    return [repeated, huge, loose, normal, bigNormal, after];
  }, 4 * SEGMENT + 4096);
}

async function placed(cwd: string, rel: string, bytes: Buffer): Promise<void> {
  await mkdir(join(cwd, rel, ".."), { recursive: true });
  await writeFile(join(cwd, rel), bytes);
}

async function timed(name: string, cwd: string, args: unknown, at = join(WIN, name, "run.py")): Promise<{ out: Answer; seconds: number }> {
  const started = Date.now();
  const run = await runPy(at, cwd, args, undefined, AGENT);
  const seconds = (Date.now() - started) / 1000;
  return { out: body<Answer>(run), seconds };
}

const REPEATED = /its value 1 of the 6 its list holds \(REG_MULTI_SZ\) is not read: its list of segments names one segment more than once \(1 distinct of 4\)/;
const HUGE = /its value 2 of the 6 its list holds \(REG_BINARY\) is not read: it declares 2147483632 bytes of data, more than the \d+ bytes the hive file holds past its base block/;
const LOOSE = /its value 3 of the 6 its list holds \(REG_MULTI_SZ\) ends in 2097152 byte\(s\) that no NUL ends: they are not in the answer/;

for (const [label, at] of [["regkv", join(WIN, "regkv", "run.py")], ["the tool-library twin of regkv", join(ROOT, "tool-library", "regkv", "run.py")]] as const) {
  test(`${label} refuses a big data value whose segment list repeats a segment or declares 2 GiB, reads an unterminated 2 MiB REG_MULTI_SZ in seconds, and reads normal ones as before`, { skip: REGIPY }, async () => {
    await withCwd(async (cwd) => {
      await placed(cwd, "work/h.dat", forged());
      const { out, seconds } = await timed("regkv", cwd, { hive: "work/h.dat", key: "K" }, at);
      assert.ok(seconds < 15, `regkv took ${seconds} s`);
      assert.equal(out.status, "partial", out.status_basis);
      const said = out.problems.map((p: Answer) => p.error);
      for (const re of [REPEATED, HUGE, LOOSE]) assert.ok(said.some((e: string) => re.test(e)), `${re}: ${JSON.stringify(said)}`);
      assert.ok(said.some((e: string) => /declares 6 values and 4 were read \(this tool did not read 2 of them/.test(e)), JSON.stringify(said));
      assert.deepEqual(Object.keys(out.values).sort(), ["After", "BigNormal", "Loose", "Normal"]);
      assert.deepEqual(out.values.Normal, ["one", "two", "three"], "regipy's shape: the strings, empty ones left out");
      assert.deepEqual(out.values.BigNormal, BIG_NORMAL);
      assert.deepEqual(out.values.Loose, ["first"], "the strings before the bytes no NUL ends are kept");
      assert.equal(out.values.After, 7, "the values after a refused one are read");
    });
  });
}

test("registry_recover refuses the same values in seconds, counts them as its own and not as values regipy left out", { skip: REGIPY }, async () => {
  await withCwd(async (cwd) => {
    await placed(cwd, "work/SYSTEM", forged());
    const { out, seconds } = await timed("registry_recover", cwd, { hive: "work/SYSTEM", max_seconds: 20 });
    assert.ok(seconds < 15, `registry_recover took ${seconds} s`);
    assert.equal(out.status, "partial", out.status_basis);
    const said = out.records.problems.map((p: Answer) => p.error);
    for (const re of [REPEATED, HUGE, LOOSE]) assert.ok(said.some((e: string) => re.test(e)), `${re}: ${JSON.stringify(said)}`);
    assert.deepEqual([out.records.values, out.records.values_not_read_by_bounds, out.records.values_not_yielded_by_regipy], [4, 2, 0]);
    assert.match(out.status_basis, /2 of the 6 value\(s\) the keys declare were not read by this tool/);
    assert.doesNotMatch(out.status_basis, /not given by regipy/);
  });
});

test("shellbags refuses the same values in seconds and says so", { skip: REGIPY }, async () => {
  await withCwd(async (cwd) => {
    await placed(cwd, "work/UsrClass.dat", forged());
    const { out, seconds } = await timed("shellbags", cwd, { hive: "work/UsrClass.dat", key: "K" });
    assert.ok(seconds < 15, `shellbags took ${seconds} s`);
    assert.equal(out.status, "partial", out.status_basis);
    const said = out.problems.map((p: Answer) => p.why);
    for (const re of [REPEATED, HUGE, LOOSE]) assert.ok(said.some((e: string) => re.test(e)), `${re}: ${JSON.stringify(said)}`);
  });
});

test("a 2 GiB big data value is refused without its memory: regkv and registry_recover stay small (peak RSS of the child)", { skip: REGIPY }, async () => {
  await withCwd(async (cwd) => {
    const bytes = hiveWith((w) => {
      const segments = Array.from({ length: 30 }, () => w.cell(Buffer.alloc(SEGMENT, 0x42)));
      // The list names its 30 segments again and again, as many times as 2 GiB needs.
      const needed = Math.ceil(0x7ffffff0 / SEGMENT);
      const list = Array.from({ length: needed }, (_, i) => segments[i % segments.length]);
      return [w.cell(HiveWriter.vk("Huge", REG.binary, 0x7ffffff0, w.db(list, 0xffff)))];
    });
    await placed(cwd, "work/h.dat", bytes);
    // getrusage(RUSAGE_CHILDREN) of a parent that runs only the tool: ru_maxrss is bytes on macOS and KiB on Linux.
    const measure = String.raw`
import json, os, resource, subprocess, sys
p = subprocess.run([sys.executable, sys.argv[1]], input=sys.argv[2].encode(), capture_output=True, cwd=sys.argv[3], env=dict(os.environ, AGENT_ID="s1"), timeout=120)
rss = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss * (1 if sys.platform == "darwin" else 1024)
print(json.dumps({"code": p.returncode, "rss": rss, "out": json.loads(p.stdout)}))
`;
    for (const [name, args] of [["regkv", { hive: "work/h.dat", key: "K" }], ["registry_recover", { hive: "work/h.dat" }]] as const) {
      const run = spawnSync(PYTHON3, ["-c", measure, join(WIN, name, "run.py"), JSON.stringify(args), cwd], { encoding: "utf8", timeout: 150_000 });
      assert.equal(run.status, 0, run.stderr);
      const { code, rss, out } = JSON.parse(run.stdout) as { code: number; rss: number; out: Answer };
      assert.equal(code, 0);
      assert.ok(rss < 256 * 1024 * 1024, `${name} peaked at ${Math.round(rss / 1048576)} MiB`);
      const problems = name === "regkv" ? out.problems : out.records.problems;
      assert.ok(problems.some((p: Answer) => /\(REG_BINARY\) is not read: it declares 2147483632 bytes of data/.test(p.error)), JSON.stringify(problems));
      assert.equal(out.status, "partial");
    }
  });
});

test("a REG_MULTI_SZ holding a string that is not valid UTF-16 gives regipy's strings (those before it) and says what was dropped", { skip: REGIPY }, async () => {
  await withCwd(async (cwd) => {
    // "ok", then a lone high surrogate (U+D800), then "after": regipy's GreedyRange stops at the string it cannot decode.
    const data = Buffer.concat([u16("ok"), Buffer.alloc(2), Buffer.from([0x00, 0xd8]), Buffer.alloc(2), u16("after"), Buffer.alloc(4)]);
    await placed(cwd, "work/h.dat", hiveWith((w) => [w.value("Broken", REG.multi_sz, data), w.value("Normal", REG.multi_sz, multi(NORMAL))]));
    const { out } = await timed("regkv", cwd, { hive: "work/h.dat", key: "K" });
    assert.deepEqual(out.values.Broken, ["ok"]);
    assert.deepEqual(out.values.Normal, ["one", "two", "three"]);
    assert.equal(out.status, "partial");
    assert.ok(out.problems.some((p: Answer) => /its value 1 of the 2 its list holds \(REG_MULTI_SZ\) holds a string that is not valid UTF-16: it and the rest of the data, 18 byte\(s\), are not in the answer/.test(p.error)), JSON.stringify(out.problems));
  });
});

// A key looked up by its path (amcache_apps' Root\\InventoryApplicationFile, shellbags' BagMRU roots) was found with regipy's get_key, which
// reads each subkey list on the way until a name matches: a root whose list is an index naming one leaf of 500 other keys 65,535 times is
// 33 million key records, read past any clock. The lookup now goes through the block's bounded subkey lists.
// (The real library only: the stand-in holds such an index as a list of 33 million names.)
for (const v of VARIANTS.filter((x) => x.real)) {
  test(`amcache_apps and shellbags look a key up through the block: an index on the way that repeats a list is read to the hive's bound [${v.label}]`, { skip: v.skip }, async () => {
    await withCwd(async (cwd) => {
      const others = Array.from({ length: 500 }, (_, i) => ({ name: "Other" + String(i).padStart(4, "0") }));
      const env = await v.write(cwd, "work/Amcache.hve", { name: "ROOT", children: [{ name: "Root", children: others, indexRepeats: 65_535 }] });
      for (const [name, args] of [["amcache_apps", { hive: "work/Amcache.hve", limit: 20 }], ["shellbags", { hive: "work/Amcache.hve", key: "Root\\BagMRU" }]] as const) {
        const started = Date.now();
        const run = await tool(name, cwd, args, env);
        const seconds = (Date.now() - started) / 1000;
        assert.ok(seconds < 20, `${name} took ${seconds} s`);
        const out = JSON.parse(run.stdout) as Answer;
        assert.doesNotMatch(run.stderr, /Traceback/);
        assert.ok(JSON.stringify(out).length > 0 && (out.status === "partial" || out.status === "failed"), `${name}: ${out.status}`);
        if (name === "amcache_apps") assert.ok(out.problems.some((p: string) => /more keys than a \d+-byte hive can hold/.test(p)), JSON.stringify(out.problems));
      }
    });
  });
}
