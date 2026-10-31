/**
 * The programs the reverse-engineering pack declares, run for real. The stand-in suites (tests/pack-re-fuzzy-hash.test.ts,
 * tests/pack-re-capa-floss.test.ts, ...) replace each program with a script that prints what its documentation says; they say nothing
 * about the program. This file runs the pack's tool or recipe that calls a program, or, for a program no tool calls (r2, upx, readelf,
 * yara), the command line a skill of the pack documents, against the real program on a small fixture built here, and asserts what the
 * stand-in suites assert about the answer. Each case records the program's own version output (`t.diagnostic`, so it is in the test
 * report) and skips honestly, naming the program that is missing, when the program is not on PATH. A skip is not a pass: the report
 * says which programs ran.
 *
 * Nothing is downloaded here: installing a program is the machine's business (the pack's requires/host.json pins them).
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { copyFile, mkdir, readFile, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import type { TestContext } from "node:test";
import { ENTROPY, FUZZY, PE_INFO, RE, body, buildElf, buildPe, put, tool, withCwd } from "./pack-re-harness.ts";
import type { Json } from "./pack-re-harness.ts";

const CAPA_FLOSS = join(RE, "recipes", "capa-floss", "run.py");

function have(program: string): boolean {
  return spawnSync("sh", ["-c", `command -v ${program}`], { encoding: "utf8" }).status === 0;
}

/** The first line a program prints for its version flag (stdout or stderr), or why there is none. */
function versionLine(program: string, flags: string[]): string {
  const r = spawnSync(program, flags, { encoding: "utf8", timeout: 30_000 });
  const text = `${r.stdout ?? ""}\n${r.stderr ?? ""}`.split("\n").map((l) => l.trim()).find((l) => l.length > 0);
  return text ?? `no output (exit ${r.status})`;
}

function record(t: TestContext, program: string, flags: string[]): string {
  const line = versionLine(program, flags);
  t.diagnostic(`${program} ${flags.join(" ")}: ${line}`);
  return line;
}

/** `skip` for a case that needs these programs: the reason names the ones that are missing, or false when all are present. */
function needs(...programs: string[]): string | false {
  const missing = programs.filter((p) => !have(p));
  return missing.length ? `${missing.join(", ")} ${missing.length === 1 ? "is" : "are"} not installed on this machine` : false;
}

const sha256 = (buf: Buffer): string => createHash("sha256").update(buf).digest("hex");

/** Deterministic pseudo-random bytes (xorshift32): enough variety for TLSH and ssdeep, the same on every run. */
function noise(n: number, seed = 0x2545f491): Buffer {
  const out = Buffer.alloc(n);
  let x = seed >>> 0;
  for (let i = 0; i < n; i++) {
    x ^= x << 13; x >>>= 0;
    x ^= x >>> 17;
    x ^= x << 5; x >>>= 0;
    out[i] = x & 0xff;
  }
  return out;
}

// --- ssdeep and tlsh, through fuzzy_hash -----------------------------------------------------------------------------------------------

async function fuzzy(cwd: string): Promise<{ out: Json; data: Buffer }> {
  const data = noise(64 * 1024);
  await put(cwd, "work/sample.bin", data);
  const changed = Buffer.from(data);
  for (let i = 0; i < 64; i++) changed[1000 + i] ^= 0xff;
  await put(cwd, "work/changed.bin", changed);
  const out = body(await tool(FUZZY, cwd, { path: "work/sample.bin", compare_to: "work/changed.bin" }));
  return { out, data };
}

test("ssdeep, through fuzzy_hash: a digest of the form the program prints, the version it reports, the file's SHA-256", { skip: needs("ssdeep", "tlsh") }, async (t) => {
  record(t, "ssdeep", ["-V"]);
  await withCwd(async (cwd) => {
    const { out, data } = await fuzzy(cwd);
    const f = out.files[0];
    assert.equal(f.sha256, sha256(data));
    assert.equal(f.ssdeep_status, "ok", JSON.stringify(f));
    assert.match(f.ssdeep, /^\d+:[A-Za-z0-9+/]+:[A-Za-z0-9+/]*$/);
    assert.deepEqual(out.engines.ssdeep.argv_per_file, ["ssdeep", "-b", "--", "<file>"]);
    assert.ok(String(out.engines.ssdeep.version_command_output).length > 0, "the engine's version output is recorded");
    assert.ok(["complete", "partial"].includes(out.status), out.status);
  });
});

test("tlsh, through fuzzy_hash: a digest of the length TLSH writes, a distance for two similar files and 0 for a file against itself", { skip: needs("ssdeep", "tlsh") }, async (t) => {
  record(t, "tlsh", ["-version"]);
  await withCwd(async (cwd) => {
    const { out } = await fuzzy(cwd);
    const f = out.files[0];
    assert.equal(f.tlsh_status, "ok", JSON.stringify(f));
    assert.match(f.tlsh, /^(T1)?[0-9A-F]{70}$/);
    assert.equal(typeof out.comparison.tlsh_distance, "number", JSON.stringify(out.comparison));
    assert.ok(out.comparison.tlsh_distance > 0, "a changed copy is not at distance 0");
    assert.equal(out.comparison.same_sha256, false);
    assert.ok(String(out.engines.tlsh.version_command_output).length > 0);
    const same = body(await tool(FUZZY, cwd, { path: "work/sample.bin", compare_to: "work/sample.bin" }));
    assert.equal(same.comparison.tlsh_distance, 0);
    assert.equal(same.comparison.same_sha256, true);
  });
});

// --- capa and FLOSS, through the capa-floss recipe --------------------------------------------------------------------------------------

async function recipeRun(cwd: string, engine: "capa" | "floss"): Promise<{ coverage: Json; out: string; status: number | null; stdout: string }> {
  await put(cwd, "inputs/s.exe", buildPe({}).file);
  const out = join(cwd, "catalog");
  const r = spawnSync("python3", [CAPA_FLOSS, "run", "--target", JSON.stringify({ paths: ["inputs/s.exe"] }), "--out", out, "--seconds", "240"], { cwd, encoding: "utf8", timeout: 300_000 });
  const coverage = JSON.parse(await readFile(join(out, "coverage.json"), "utf8")) as Json;
  assert.ok(coverage.engines[engine], `coverage.json names ${engine}`);
  return { coverage, out, status: r.status, stdout: r.stdout };
}

for (const [program, flags] of [["capa", ["--version"]], ["floss", ["--version"]]] as const) {
  test(`${program}, through the capa-floss recipe: its argv, version output and exit code are recorded, and the status is judged by the exit code and the output's shape`, { skip: needs(program) }, async (t) => {
    record(t, program, [...flags]);
    await withCwd(async (cwd) => {
      const { coverage, out, stdout } = await recipeRun(cwd, program);
      const e = coverage.engines[program];
      assert.equal(e.installed, true);
      assert.ok(Array.isArray(e.argv) && e.argv[0] === program, JSON.stringify(e.argv));
      assert.ok(e.version_command && typeof e.version_command.first_line === "string" && e.version_command.first_line.length > 0, "the version output is recorded");
      assert.ok(["complete", "partial", "failed"].includes(e.status), e.status);
      if (e.exit_code === 0) {
        assert.ok((await stat(join(out, e.file))).size > 0, "the program's whole output is a file");
      } else {
        assert.equal(e.status, "failed");
        assert.match(e.reason, /exited with status|time limit|could not be started/);
      }
      assert.equal(JSON.parse(stdout).status, coverage.status, "the receipt and the recipe's answer agree");
      for (const f of ["coverage.json", "index.tsv"]) assert.ok((await stat(join(out, f))).size > 0);
    });
  });
}

// --- r2, upx, readelf, yara: no tool of the pack calls them; the skills document the command lines, run here for real ---------------

test("r2: the byte-range copy `r2 -N -n -q -c \"wtf FILE SIZE @ OFFSET\" SAMPLE` that runtimes/python-packaged and macho/structure document writes exactly those bytes", { skip: needs("r2") }, async (t) => {
  record(t, "r2", ["-v"]);
  await withCwd(async (cwd) => {
    const data = noise(4096, 77);
    await put(cwd, "inputs/sample.bin", data);
    const offset = 1000;
    const size = 777;
    const run = spawnSync("r2", ["-N", "-n", "-q", "-c", `wtf ${join(cwd, "slice.bin")} ${size} @ ${offset}`, join(cwd, "inputs", "sample.bin")], { cwd, encoding: "utf8", timeout: 60_000 });
    assert.equal(run.status, 0, run.stderr);
    assert.equal(sha256(await readFile(join(cwd, "slice.bin"))), sha256(data.subarray(offset, offset + size)));
    // `r2 -N -q -c 'aaa; afl'` of the same file does not fail on a file with no code either: it prints nothing it can call a function
    const functions = spawnSync("r2", ["-N", "-q", "-c", "aaa; afl", join(cwd, "inputs", "sample.bin")], { cwd, encoding: "utf8", timeout: 120_000 });
    assert.equal(functions.status, 0, functions.stderr);
  });
});

test("upx: `upx -t` recognises a file this machine's upx packed, `upx -l` lists it, and `upx -d -o` restores the original bytes into a named copy", { skip: needs("upx", "true") }, async (t) => {
  record(t, "upx", ["--version"]);
  await withCwd(async (cwd) => {
    const real = spawnSync("sh", ["-c", "command -v true"], { encoding: "utf8" }).stdout.trim();
    await copyFile(real, join(cwd, "original.bin"));
    const original = await readFile(join(cwd, "original.bin"));
    const packed = spawnSync("upx", ["-q", "-o", join(cwd, "packed.bin"), join(cwd, "original.bin")], { cwd, encoding: "utf8", timeout: 120_000 });
    if (packed.status !== 0) return t.skip(`upx could not pack this machine's /bin/true (${(packed.stderr || packed.stdout).split("\n")[0]})`);
    assert.equal(spawnSync("upx", ["-t", join(cwd, "packed.bin")], { cwd, timeout: 60_000 }).status, 0, "upx -t recognises the packed file");
    assert.equal(spawnSync("upx", ["-l", join(cwd, "packed.bin")], { cwd, timeout: 60_000 }).status, 0);
    assert.notEqual(spawnSync("upx", ["-t", join(cwd, "original.bin")], { cwd, timeout: 60_000 }).status, 0, "a file upx did not pack is not recognised");
    const restored = spawnSync("upx", ["-q", "-d", "-o", join(cwd, "restored.bin"), join(cwd, "packed.bin")], { cwd, encoding: "utf8", timeout: 120_000 });
    assert.equal(restored.status, 0, restored.stderr);
    assert.equal(sha256(await readFile(join(cwd, "restored.bin"))), sha256(original), "the decompressed copy is the original");
    assert.equal(sha256(await readFile(join(cwd, "packed.bin"))) === sha256(original), false);
    // pe_info reads the packed file as the ELF it is, executing nothing; its entropy is a measurement, not a verdict
    const read = body(await tool(PE_INFO, cwd, { path: "packed.bin" }));
    assert.ok(["complete", "partial"].includes(read.status), read.status);
    const profile = body(await tool(ENTROPY, cwd, { path: "packed.bin" }));
    assert.equal(profile.status, "complete");
    assert.ok(profile.overall_entropy > 0);
  });
});

test("readelf: `readelf -d` of an ELF fixture lists the libraries pe_info reports as needed, and `readelf -h` agrees on class and machine", { skip: needs("readelf") }, async (t) => {
  record(t, "readelf", ["--version"]);
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/fixture.so", buildElf({ cls: 64, needed: ["libc.so.6", "libm.so.6"], soname: "libfixture.so.1", machine: 0x3e }));
    const dynamic = spawnSync("readelf", ["-d", "-W", join(cwd, "inputs", "fixture.so")], { encoding: "utf8", timeout: 60_000 });
    assert.equal(dynamic.status, 0, dynamic.stderr);
    const libs = [...dynamic.stdout.matchAll(/\(NEEDED\)\s+Shared library: \[([^\]]+)\]/g)].map((m) => m[1]);
    const header = spawnSync("readelf", ["-h", join(cwd, "inputs", "fixture.so")], { encoding: "utf8", timeout: 60_000 });
    assert.equal(header.status, 0, header.stderr);
    const read = body(await tool(PE_INFO, cwd, { path: "inputs/fixture.so" }));
    assert.deepEqual([...read.needed_libraries].sort(), [...libs].sort(), `readelf lists ${JSON.stringify(libs)}; pe_info ${JSON.stringify(read.needed_libraries)}`);
    assert.match(header.stdout, /Class:\s+ELF64/);
    assert.match(header.stdout, /Machine:\s+Advanced Micro Devices X86-64/);
  });
});

test("yara: `yara -s RULES SAMPLE` prints the matched string with its offset, and a rule that does not match prints nothing", { skip: needs("yara") }, async (t) => {
  record(t, "yara", ["--version"]);
  await withCwd(async (cwd) => {
    const sample = Buffer.concat([noise(500, 5), Buffer.from("needle-string-for-the-fixture"), noise(500, 6)]);
    await put(cwd, "inputs/sample.bin", sample);
    await writeFile(join(cwd, "hit.yar"), 'rule fixture_hit { strings: $a = "needle-string-for-the-fixture" condition: $a }\n');
    await writeFile(join(cwd, "miss.yar"), 'rule fixture_miss { strings: $a = "absent-string-from-the-fixture" condition: $a }\n');
    const hit = spawnSync("yara", ["-s", join(cwd, "hit.yar"), join(cwd, "inputs", "sample.bin")], { encoding: "utf8", timeout: 60_000 });
    assert.equal(hit.status, 0, hit.stderr);
    assert.match(hit.stdout, /^fixture_hit /m);
    assert.match(hit.stdout, new RegExp(`0x${(500).toString(16)}:\\$a: needle-string-for-the-fixture`));
    const miss = spawnSync("yara", ["-s", join(cwd, "miss.yar"), join(cwd, "inputs", "sample.bin")], { encoding: "utf8", timeout: 60_000 });
    assert.equal(miss.status, 0, miss.stderr);
    assert.equal(miss.stdout.trim(), "");
    await mkdir(join(cwd, "work"), { recursive: true });
  });
});
