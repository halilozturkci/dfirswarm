/**
 * What the three memory-forensics tools share: the paging block (all three), the SHOWN block (mem_fs, mem_profile) and the shared
 * WITHHOLDING block it reads (the one every pack's tools carry), held equal by this test; the time the judging takes on strings built to
 * make a regular expression slow; the backstop at the serialisation boundary; and the declarations the manifests make.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { ROOT, withCwd } from "./tool-library-harness.ts";
import { CARVE, FS, PROFILE, SHAPES, fsStub, json, rng, runTool } from "./memory-f1-support.ts";

const block = (text: string, name: string): string => {
  const m = text.match(new RegExp(`# BEGIN SHARED ${name}\\n[\\s\\S]*?# END SHARED ${name}\\n`));
  assert.ok(m, `no ${name} block`);
  return m[0];
};
const read = (p: string) => readFile(p, "utf8");

test("the paging block is the same text in mem_carve, mem_fs and mem_profile; the shown block in mem_fs and mem_profile", async () => {
  const [carve, fs, profile] = await Promise.all([read(CARVE), read(FS), read(PROFILE)]);
  assert.equal(block(fs, "PAGE"), block(carve, "PAGE"));
  assert.equal(block(profile, "PAGE"), block(carve, "PAGE"));
  assert.equal(block(profile, "SHOWN"), block(fs, "SHOWN"));
  assert.doesNotMatch(carve, /BEGIN SHARED SHOWN/, "mem_carve prints no string from the capture");
});

test("the withholding block the shown block reads is the one the other packs carry, byte for byte", async () => {
  const reference = block(await read(join(ROOT, "packs", "computer-forensics-base", "tools", "sqlite_query", "run.py")), "WITHHOLDING");
  assert.equal(block(await read(FS), "WITHHOLDING"), reference);
  assert.equal(block(await read(PROFILE), "WITHHOLDING"), reference);
});

test("no ensure_ascii=False is left in the three tools, and a lone surrogate is written as an escape (P2-9)", async () => {
  for (const tool of [CARVE, FS, PROFILE]) assert.doesNotMatch(await read(tool), /ensure_ascii\s*=\s*False/, tool);
  const code = [
    "import importlib.util, json, sys, tempfile, os",
    "spec = importlib.util.spec_from_file_location('t', sys.argv[1]); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)",
    "d = tempfile.mkdtemp(); os.environ.pop('JOB_ID', None); os.chdir(d)",
    "p = m.LosslessPage('t', ['k'], 2)",
    "for n in ['a', 'b', 'p\\udcffq', 'c']: p.add({'name': n})",
    "r = p.finish(); print(open(os.path.join(d, 'work', 'tool', 'tool-output', os.path.basename(r['all_results'])), encoding='ascii').read().count('udcff'))",
  ].join("\n");
  for (const tool of [CARVE, FS, PROFILE]) {
    const out = spawnSync("python3", ["-c", code, tool], { encoding: "utf8" });
    assert.equal(out.status, 0, out.stderr);
    assert.equal(out.stdout.trim(), "1", tool);
  }
});

test("judging a string takes linear time: 4,096 and 32,768 characters built to slow a regular expression, with the triggers of each layer (ReDoS)", async () => {
  const code = [
    "import importlib.util, sys, time",
    "spec = importlib.util.spec_from_file_location('t', sys.argv[1]); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)",
    "units = ['a:', 'a-', 'a/', 'A1', 'a@', ':@', 'x=', 'password=', 'Ab1', '=', '+', '_', 'ab', '0x', 'S-1-5-', 'a.', '\\u00e9\\u0301', 'AKIA', '//a:']",
    "worst = 0",
    "for n in (4096, 32768):",
    "    for u in units:",
    "        for tail in ('', '@', '!', '\\x00'):",
    "            s = (u * (n // len(u) + 1))[:n] + tail",
    "            for kind in ('name', 'path', 'text'):",
    "                t = time.monotonic(); m.shown(s, kind); worst = max(worst, time.monotonic() - t)",
    "            t = time.monotonic(); m.sealed({'k': s}); worst = max(worst, time.monotonic() - t)",
    "print('%.2f' % worst)",
  ].join("\n");
  for (const tool of [FS, PROFILE]) {
    const out = spawnSync("python3", ["-c", code, tool], { encoding: "utf8", timeout: 240_000 });
    assert.equal(out.status, 0, out.stderr);
    assert.ok(Number(out.stdout.trim()) < 2.5, `${tool}: the slowest string took ${out.stdout.trim()} s`);
  }
});

test("the backstop replaces a string the tool did not mark as read from the capture, and the answer says partial", async () => {
  await withCwd(async (cwd, bin) => {
    const token = SHAPES.ghp(rng(8));
    const env = await fsStub(cwd, bin, { tree: { "a/b": "" } });
    // the image's own name is caller-supplied text echoed in the answer: a token in it is not printed
    await writeFile(join(cwd, "inputs", `mem_${token}.raw`), Buffer.alloc(4096));
    const run = await runTool(FS, cwd, { path: `inputs/mem_${token}.raw`, mount: "work/s1/m", mode: "list", timeout_seconds: 30 }, env, bin);
    const out = json<{ status: string; status_basis: string }>(run);
    assert.ok(!run.stdout.includes(token));
    assert.equal(out.status, "partial");
    assert.match(out.status_basis, /backstop replaced/);
  });
});

test("the manifests declare what the tools do: secret_output for write_values in mem_fs and mem_carve, the clock and the bounds in mem_carve and mem_fs", async () => {
  const man = async (t: string) => JSON.parse(await read(join(ROOT, "packs", "memory-forensics", "tools", t, "manifest.json")));
  for (const t of ["mem_fs", "mem_carve"]) {
    const m = await man(t);
    assert.deepEqual(m.secret_output, { when_args: ["write_values"] });
    assert.equal(m.params.write_values.type, "boolean");
    assert.equal(m.params.write_values.default, undefined);
    assert.ok(!/cannot see whether/.test(m.description));
  }
  const carve = await man("mem_carve");
  assert.ok(carve.params.max_seconds && carve.params.max_results_bytes);
  assert.ok(carve.timeout_seconds >= 900);
  assert.match((await man("mem_fs")).params.timeout_seconds.description, /2 to 480/);
});
