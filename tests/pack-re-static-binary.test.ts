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
import { mkdir, readFile, readdir, stat, truncate } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { CPU_X86_64, RECIPE, buildElf, buildFat, buildMacho, buildPe, childrenOf, exists, filesUnder, gone, put, startDetached, withCwd } from "./pack-re-harness.ts";
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

// --- review round ---------------------------------------------------------------------------------------------------------

test("a second run into the same directory replaces nothing the first wrote, and the index names both results", async () => {
  await withCwd(async (cwd) => {
    const sample = await put(cwd, "inputs/sample.bin", buildPe({ imports: [{ dll: "KERNEL32.dll", functions: ["ExitProcess", "Sleep"] }] }).file);
    const dir = join(cwd, "catalog");
    const first = recipe("run", sample, ["--out", dir]);
    assert.equal(first.code, 0);
    const before = await readFile(join(dir, "binary.json"), "utf8");
    const profileBefore = (await filesUnder(dir)).find((f) => f.startsWith("entropy-windows"))!;
    const second = recipe("run", sample, ["--out", dir]);
    assert.equal(second.code, 0);
    assert.equal(await readFile(join(dir, "binary.json"), "utf8"), before, "the first result is as it was");
    assert.ok(await exists(join(dir, "binary-2.json")), (await filesUnder(dir)).join(","));
    assert.ok(await exists(join(dir, profileBefore)));
    const index = await readFile(join(dir, "index.tsv"), "utf8");
    assert.match(index, /^binary-2\.json\t/m);
    assert.match(index, /^binary\.json\t.*earlier run/m, "the first result is still named");
    const coverage = JSON.parse(await readFile(join(dir, "coverage.json"), "utf8")) as Json;
    assert.equal(coverage.status, "complete");
    assert.equal(coverage.outputs.binary, "binary-2.json");
  });
});

test("a clean run leaves no empty file behind", async () => {
  await withCwd(async (cwd) => {
    const { dir } = await catalogue(cwd, buildPe({}).file);
    for (const f of await filesUnder(dir)) assert.ok((await stat(join(dir, f))).size > 0, `${f} is empty`);
  });
});

test("recipe.json offers every magic that detect accepts, so a derived file of each form is offered to it", async () => {
  const recipeJson = JSON.parse(await readFile(join(RECIPE, "..", "recipe.json"), "utf8")) as Json;
  const offered = recipeJson.magic.map((m: Json) => m.hex).sort();
  assert.deepEqual(offered, ["4d5a", "7f454c46", "bebafeca", "bfbafeca", "cafebabe", "cafebabf", "cefaedfe", "cffaedfe", "feedface", "feedfacf"].sort());
  assert.ok(recipeJson.outputs.includes("entropy-windows.tsv"));
});

test("the recipe's own budget is handed to each tool as that tool's clock: --seconds ends a long pass as a partial result, not a kill", async () => {
  await withCwd(async (cwd) => {
    const sample = await put(cwd, "inputs/big.exe", buildPe({}).file);
    await truncate(sample, 2 ** 31); // a hole of 2 GiB: the entropy pass takes about a minute
    const dir = join(cwd, "catalog");
    const started = Date.now();
    const run = recipe("run", sample, ["--out", dir, "--seconds", "4"]);
    assert.ok((Date.now() - started) / 1000 < 30, "the recipe waited for the whole pass");
    assert.equal(run.code, 0);
    const coverage = JSON.parse(await readFile(join(dir, "coverage.json"), "utf8")) as Json;
    assert.equal(coverage.status, "partial");
    assert.equal(coverage.entropy_map.status, "partial", JSON.stringify(coverage.entropy_map));
    assert.ok(coverage.entropy_map.bytes_processed >= 0 && coverage.entropy_map.bytes_processed < 2 ** 31);   // how far it got depends on the machine
    assert.ok(coverage.limits_hit.some((l: string) => /entropy/.test(l)));
  });
});

test("a recipe killed alone leaves no tool running past its budget", { skip: process.platform === "win32" }, async () => {
  await withCwd(async (cwd) => {
    const sample = await put(cwd, "inputs/big.exe", buildPe({}).file);
    await truncate(sample, 2 ** 31);
    const dir = join(cwd, "catalog");
    const run = startDetached(RECIPE, cwd, {}, {}, undefined, ["run", "--target", JSON.stringify({ paths: [sample] }), "--out", dir, "--seconds", "4"]);
    // entropy_map creates its profile file as it starts: from then on it is the running child.
    const until = Date.now() + 15000;
    let kids: number[] = [];
    for (;;) {
      const files = await readdir(dir).catch(() => [] as string[]);
      kids = childrenOf(run.pid);
      if (files.some((f) => f.startsWith("entropy-windows")) && kids.length) break;
      if (Date.now() > until) throw new Error(`the recipe did not reach its entropy pass: ${files.join(",")}`);
      await new Promise((r) => setTimeout(r, 50));
    }
    assert.ok(kids.length, "the recipe started a tool");
    process.kill(run.pid, "SIGKILL"); // the recipe alone, as the catalogue does at its limit: not its group
    await run.closed;
    try {
      // Linux ends the child with its parent; elsewhere the child ends at its own clock, which the recipe set from its budget.
      for (const pid of kids) assert.equal(await gone(pid, 9000), true, `the tool ${pid} outlived the recipe's budget`);
    } finally {
      for (const pid of kids) try { process.kill(pid, "SIGKILL"); } catch { /* gone */ }
    }
  });
});
