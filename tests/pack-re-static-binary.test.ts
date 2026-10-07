/**
 * The static-binary recipe: `run.py detect --target T` says whether the recipe applies to an object, and
 * `run.py run --target T --out DIR` catalogues it. Fixtures are built from the formats' layouts
 * (tests/pack-re-harness.ts), never from a tool's output.
 *
 * What these cases hold: the recipe's status comes from what the parsers say they read (their own `status`), not
 * from their exit codes; a nonempty output file is never called a complete structure; a child's output goes to
 * a file as it is written; the complete entropy profile is indexed; applicability is judged from enough
 * structure to tell an executable from a coincident magic prefix.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdir, readFile, stat } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { CPU_X86_64, RECIPE, buildElf, buildFat, buildMacho, buildPe, exists, filesUnder, put, withCwd } from "./pack-re-harness.ts";
import type { Json } from "./pack-re-harness.ts";

function recipe(verb: "detect" | "run", target: string, extra: string[] = [], env: Record<string, string> = {}): { code: number | null; out: Json; stderr: string } {
  const r = spawnSync("python3", [RECIPE, verb, "--target", JSON.stringify({ paths: [target] }), ...extra], { encoding: "utf8", env: { ...process.env, ...env } });
  let out: Json = null;
  try {
    out = JSON.parse(r.stdout);
  } catch {
    out = { unparsable: r.stdout };
  }
  return { code: r.status, out, stderr: r.stderr };
}

async function catalogue(cwd: string, buf: Buffer, env: Record<string, string> = {}): Promise<{ run: ReturnType<typeof recipe>; dir: string; coverage: Json; index: string }> {
  const sample = await put(cwd, "inputs/sample.bin", buf);
  const dir = join(cwd, "catalog");
  const run = recipe("run", sample, ["--out", dir], env);
  const coverage = JSON.parse(await readFile(join(dir, "coverage.json"), "utf8"));
  const index = await readFile(join(dir, "index.tsv"), "utf8").catch(() => "");
  return { run, dir, coverage, index };
}

test("a PE whose optional header is cut short is partial, and no line of the index calls its structure complete", async () => {
  await withCwd(async (cwd) => {
    // The file ends 100 bytes into the optional header: the parser exits 0 with a header problem.
    const { run, coverage, index } = await catalogue(cwd, buildPe({ cutOptionalHeaderTo: 100 }).file);
    assert.equal(coverage.status, "partial", JSON.stringify(coverage));
    assert.equal(run.out.status, "partial");
    assert.equal(run.code, 0, "partial is a result with its coverage stated, not a failed run");
    assert.doesNotMatch(index, /complete static structure/);
    assert.match(index, /^binary\.json\t.*partial/m);
    assert.ok(coverage.warnings.some((w: string) => /optional header/i.test(w)), JSON.stringify(coverage.warnings));
    assert.ok(coverage.errors.some((e: string) => /pe_info.*partial/i.test(e)));
    assert.equal(coverage.pe_info.status, "partial");
    assert.ok(coverage.omissions.some((o: string) => /resources/i.test(o)));
  });
});

test("a PE the parser reads whole is complete, and the complete entropy profile is a file the index names", async () => {
  await withCwd(async (cwd) => {
    const built = buildPe({ imports: [{ dll: "KERNEL32.dll", functions: ["ExitProcess", "GetLastError", "Sleep", "CloseHandle", "ReadFile", "WriteFile", "VirtualAlloc"] }] });
    const { run, dir, coverage, index } = await catalogue(cwd, built.file);
    assert.equal(coverage.status, "complete", JSON.stringify(coverage));
    assert.equal(run.code, 0);
    assert.deepEqual(coverage.limits_hit, []);
    assert.match(index, /^entropy-windows\.tsv\t.*complete/m);
    const profile = (await readFile(join(dir, "entropy-windows.tsv"), "utf8")).trim().split("\n");
    assert.equal(profile[0], "offset\tbytes\tentropy");
    assert.equal(profile.length - 1, Math.ceil(built.file.length / 65536));
    const binary = JSON.parse(await readFile(join(dir, "binary.json"), "utf8"));
    assert.equal(binary.status, "complete");
    assert.equal(binary.imports[0].library, "KERNEL32.dll");
    // every file the index names is in the directory
    for (const line of index.trim().split("\n")) assert.ok(await exists(join(dir, line.split("\t")[0]!)), line);
  });
});

test("the recipe writes the entropy profile into its own --out even when the caller's OUT names another directory", async () => {
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "elsewhere"), { recursive: true });
    const { dir } = await catalogue(cwd, buildPe({}).file, { OUT: join(cwd, "elsewhere"), JOB_ID: "j000001" });
    assert.ok(await exists(join(dir, "entropy-windows.tsv")));
    assert.deepEqual(await filesUnder(join(cwd, "elsewhere")), [], "nothing leaked into the caller's OUT");
  });
});

test("a table the parser kept whole in a file is indexed and present in the recipe's directory", async () => {
  await withCwd(async (cwd) => {
    const functions = Array.from({ length: 5100 }, (_, i) => `Fn${String(i).padStart(5, "0")}`);
    const { dir, coverage, index } = await catalogue(cwd, buildPe({ imports: [{ dll: "BIG.dll", functions }] }).file);
    assert.equal(coverage.status, "complete", JSON.stringify(coverage.warnings));
    const line = index.trim().split("\n").find((l) => /^tool-output\//.test(l));
    assert.ok(line, index);
    const file = join(dir, line!.split("\t")[0]!);
    assert.equal((await readFile(file, "utf8")).trim().split("\n").length, 5100, "the whole import list, one row per function");
  });
});

test("a format variant the parser does not read is said by the parser's own status, and its output is kept", async () => {
  await withCwd(async (cwd) => {
    // PE signature present, optional header magic 0x107 (a ROM image): detected as a PE, not read by the parser.
    const built = buildPe({});
    built.file.writeUInt16LE(0x107, built.optionalAt);
    const { run, dir, coverage, index } = await catalogue(cwd, built.file);
    assert.equal(coverage.pe_info.status, "unsupported");
    assert.equal(coverage.status, "partial", "the whole-file entropy is still a usable result");
    assert.ok(coverage.errors.some((e: string) => /unsupported/i.test(e)));
    assert.ok((await stat(join(dir, "binary.json"))).size > 0, "the parser's output was streamed to its file");
    assert.match(await readFile(join(dir, "binary.json"), "utf8"), /ROM image/);
    assert.doesNotMatch(index, /complete static structure/);
    assert.equal(run.out.ok, false);
  });
});

test("applicability: a header-only ELF32 and every Mach-O form are executables; a coincident magic is not", async () => {
  await withCwd(async (cwd) => {
    const says = async (name: string, buf: Buffer): Promise<Json> => {
      const file = await put(cwd, `inputs/${name}`, buf);
      return recipe("detect", file).out;
    };
    assert.equal((await says("elf32", buildElf({ cls: 32, headerOnly: true }))).applies, true);
    assert.equal((await says("elf64", buildElf({ cls: 64, needed: ["libc.so.6"] }))).applies, true);
    assert.equal((await says("macho", buildMacho({ wide: false, big: true }))).applies, true);
    const fat = buildFat([{ cputype: CPU_X86_64, data: buildMacho({}) }]);
    assert.equal((await says("fat", fat)).applies, true);
    assert.equal((await says("fatle", buildFat([{ cputype: CPU_X86_64, data: buildMacho({}) }], { littleEndianHeader: true }))).applies, true);

    // A Java class file begins with the universal-binary magic.
    const klass = Buffer.concat([Buffer.from([0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 61]), Buffer.alloc(120, 7)]);
    const java = await says("klass", klass);
    assert.equal(java.applies, false);
    assert.match(java.why, /Java|universal|slice/i);
    // 0x7f ELF with a class byte that is no class
    const bad = buildElf({ cls: 64, headerOnly: true });
    bad[4] = 7;
    const notElf = await says("badelf", bad);
    assert.equal(notElf.applies, false);
    assert.match(notElf.why, /class/i);
    // An ELF magic and nothing else
    assert.equal((await says("stub", Buffer.from("\x7fELF\x02\x01\x01\x00", "latin1"))).applies, false);
    // MZ that does not lead to a PE signature
    const dos = Buffer.alloc(0x100);
    dos.write("MZ", 0, "latin1");
    dos.writeUInt32LE(0x80, 0x3c);
    assert.equal((await says("dos", dos)).applies, false);
    assert.equal((await says("pe", buildPe({}).file)).applies, true);
  });
});

test("an object the recipe does not apply to gets a coverage file that says unsupported and why", async () => {
  await withCwd(async (cwd) => {
    const sample = await put(cwd, "inputs/x.bin", Buffer.concat([Buffer.from([0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 61]), Buffer.alloc(120, 7)]));
    const dir = join(cwd, "catalog");
    const run = recipe("run", sample, ["--out", dir]);
    assert.equal(run.out.status, "unsupported");
    assert.equal(run.code, 2);
    const coverage = JSON.parse(await readFile(join(dir, "coverage.json"), "utf8"));
    assert.equal(coverage.status, "unsupported");
    assert.match(coverage.why, /Java|universal|slice/i);
  });
});
