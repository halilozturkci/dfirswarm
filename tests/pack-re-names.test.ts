/**
 * A file name that is not valid UTF-8 reaches a tool as a string with a lone surrogate (Python maps the byte 0xff
 * to U+DCFF, and JSON can carry that as an escape). None of the pack's tools may raise on it, and every answer is
 * JSON: a name is printed escaped, never encoded into a stream that cannot hold it.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { test } from "node:test";
import { join } from "node:path";
import { writeFile, mkdir } from "node:fs/promises";
import { DOC_PROBE, ENTROPY, FUZZY, PE_INFO, RECIPE, buildPe, buildZip, stub, tool, withCwd } from "./pack-re-harness.ts";
import type { Json } from "./pack-re-harness.ts";

const BAD = "x\udcff.bin"; // the file is written with the byte 0xff in its name

/** The path of a new file named with the byte 0xff, or null where the file system refuses such a name (macOS does). */
async function put(cwd: string, data: Buffer): Promise<string | null> {
  const dir = join(cwd, "work");
  await mkdir(dir, { recursive: true });
  try {
    await writeFile(Buffer.concat([Buffer.from(dir + "/x"), Buffer.from([0xff]), Buffer.from(".bin")]), data);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "EILSEQ") return null;
    throw error;
  }
  return `work/${BAD}`;
}

test("pe_info, doc_probe and entropy_map answer for a file whose name is not UTF-8, in JSON and without a traceback", async (t) => {
  await withCwd(async (cwd) => {
    const pe = await put(cwd, buildPe({ imports: [{ dll: "A.dll", functions: ["f"] }] }).file);
    if (!pe) t.skip("this file system refuses a name that is not UTF-8 (macOS): the branch runs on Linux; the error path below does run");
    if (pe) {
      for (const [script, expected] of [[PE_INFO, "complete"], [ENTROPY, "complete"]] as const) {
        const out = await tool(script, cwd, { path: pe, limit: 1 });
        assert.equal(out.code, 0, out.stderr + out.stdout);
        assert.doesNotMatch(out.stderr, /Traceback/);
        assert.equal((JSON.parse(out.stdout) as Json).status, expected);
      }
      const zip = await put(cwd, buildZip([{ name: "word/document.xml", data: Buffer.from("<d/>") }]));
      const doc = await tool(DOC_PROBE, cwd, { path: zip! });
      assert.equal(doc.code, 0, doc.stderr + doc.stdout);
      assert.doesNotMatch(doc.stderr, /Traceback/);
      assert.equal((JSON.parse(doc.stdout) as Json).status, "complete");
    }
    // A name that is not there at all is a JSON error, on every file system.
    const none = await tool(PE_INFO, cwd, { path: "work/none\udcfe.bin" });
    assert.notEqual(none.code, 0);
    assert.doesNotMatch(none.stderr, /Traceback/);
    assert.match((JSON.parse(none.stdout) as Json).error, /no such file/);
  });
});

test("fuzzy_hash and the static-binary recipe do the same", async (t) => {
  await withCwd(async (cwd, bin) => {
    await stub(bin, "ssdeep", `echo 'ssdeep,1.1--blocksize:hash:hash,filename'\necho "3:abc:def,\\"$(basename "$3")\\""`);
    await stub(bin, "tlsh", `printf 'T1${"AB".repeat(35)}\\t%s\\n' "$2"`);
    const sample = await put(cwd, buildPe({}).file);
    const missing = `work/gone\udcfe.bin`;
    for (const script of [FUZZY]) {
      const none = await tool(script, cwd, { path: missing }, {}, bin);
      assert.notEqual(none.code, 0);
      assert.doesNotMatch(none.stderr, /Traceback/);
      assert.match((JSON.parse(none.stdout) as Json).error, /no such file/);
    }
    const gone = spawnSync("python3", [RECIPE, "detect", "--target", JSON.stringify({ paths: [missing] })], { cwd, encoding: "utf8" });
    assert.doesNotMatch(gone.stderr, /Traceback/);
    assert.equal((JSON.parse(gone.stdout) as Json).ok, false);
    if (!sample) {
      t.skip("this file system refuses a name that is not UTF-8 (macOS): the branch runs on Linux; the error path above does run");
      return;
    }
    const out = await tool(FUZZY, cwd, { path: sample }, {}, bin);
    assert.equal(out.code, 0, out.stderr + out.stdout);
    assert.doesNotMatch(out.stderr, /Traceback/);
    assert.equal((JSON.parse(out.stdout) as Json).status, "complete");
    const run = spawnSync("python3", [RECIPE, "run", "--target", JSON.stringify({ paths: [sample] }), "--out", join(cwd, "catalog")], { cwd, encoding: "utf8" });
    assert.equal(run.status, 0, run.stderr + run.stdout);
    assert.doesNotMatch(run.stderr, /Traceback/);
    assert.equal((JSON.parse(run.stdout) as Json).status, "complete");
  });
});
