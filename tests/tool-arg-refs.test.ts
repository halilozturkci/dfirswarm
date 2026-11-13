/**
 * References in a tool job's arguments (scripts/tool-arg-refs.ts): a whole
 * argument that is job:, import: or input: becomes the path the worker sees,
 * $OUT and ${OUT} at an argument's head become {OUT}, and a reference that
 * names nothing is refused with the form that works.
 */
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import { argRefsWords, resolveToolArgs } from "../scripts/tool-arg-refs.ts";

const S = mkdtempSync(join(tmpdir(), "tool-arg-refs-"));
after(() => rmSync(S, { recursive: true, force: true }));
mkdirSync(join(S, "store/jobs/j000007/out/a dir"), { recursive: true });
writeFileSync(join(S, "store/jobs/j000007/out/a dir/hive file"), "x");
mkdirSync(join(S, "store/jobs/j000008/out"), { recursive: true });
mkdirSync(join(S, "store/imports/mat-1/out"), { recursive: true });
writeFileSync(join(S, "store/imports/mat-1/out/tool.bin"), "x");
mkdirSync(join(S, "inputs/set one"), { recursive: true });
writeFileSync(join(S, "inputs/set one/disk.img"), "x");
symlinkSync("/etc/hosts", join(S, "store/jobs/j000007/out/link"));
const state = (id: string) => ({ j000007: "committed", j000008: "running" })[id];
const run = (args: Record<string, unknown>) => resolveToolArgs(S, "t", args, state);

test("the five ways a seat writes a path: a job reference, the same with out/, an input, $OUT and a plain path", () => {
  const r = run({ hive: "job:j000007/a dir/hive file", same: "job:j000007/out/a dir/hive file", image: "input:set one/disk.img", out_dir: "$OUT/x y", other: "${OUT}", plain: "work/a1/x.txt", whole: "job:j000007", prog: "import:mat-1/tool.bin" });
  assert.ok(r.ok, (r as { reason?: string }).reason);
  assert.deepEqual(r.args, { hive: "store/jobs/j000007/out/a dir/hive file", same: "store/jobs/j000007/out/a dir/hive file", image: "inputs/set one/disk.img", out_dir: "{OUT}/x y", other: "{OUT}", plain: "work/a1/x.txt", whole: "store/jobs/j000007/out", prog: "store/imports/mat-1/out/tool.bin" });
  assert.deepEqual(r.resolved.map((x) => [x.at, x.object]), [["hive", "job:j000007"], ["same", "job:j000007"], ["image", "input:set one/disk.img"], ["whole", "job:j000007"], ["prog", "import:mat-1"]]);
  assert.match(argRefsWords(r.resolved), /^The tool was given the paths of the references in its arguments \(hive: job:j000007\/a dir\/hive file is store\/jobs\/j000007\/out\/a dir\/hive file; .*and 2 more\)\.$/);
  assert.equal(argRefsWords([]), "");
});

test("references inside lists and objects are read; a reference inside a longer text is left alone", () => {
  const r = run({ paths: ["job:j000007/a dir", "x"], o: { deep: ["input:set one/disk.img"] }, note: "see job:j000007/a dir for it", n: 3, b: true, z: null });
  assert.ok(r.ok);
  assert.deepEqual(r.args, { paths: ["store/jobs/j000007/out/a dir", "x"], o: { deep: ["inputs/set one/disk.img"] }, note: "see job:j000007/a dir for it", n: 3, b: true, z: null });
  assert.deepEqual(r.resolved.map((x) => x.at), ["paths[0]", "o.deep[0]"]);
});

test("a reference that names nothing is refused before the job runs, with what to do", () => {
  const refused = (args: Record<string, unknown>, re: RegExp) => {
    const r = run(args);
    assert.equal(r.ok, false, JSON.stringify(r));
    assert.match((r as { reason: string }).reason, re);
  };
  refused({ f: "job:j000009/x" }, /^tool t: f names job:j000009, and this run has no job j000009 \(jobs lists them\)$/);
  refused({ f: "job:j000008/x" }, /names job:j000008, whose output is not sealed yet \(it is running\): a tool reads a job's files once job_status says it is committed/);
  refused({ f: "job:j000007/nope.txt" }, /names job:j000007\/nope\.txt, and job j000007 has no nope\.txt \(job_status j000007 lists its files/);
  refused({ f: "job:j000007/../j000008/out" }, /the path inside a job has no parent step/);
  refused({ f: "job:j000007/link" }, /has no link/); // a link is not followed
  refused({ f: "input:none.img" }, /names input:none\.img, and the run has no inputs\/none\.img \(inputs\.json lists the inputs by path\)/);
  refused({ f: "input:../store" }, /an input is input:<its path under inputs\/>/);
  refused({ f: "import:mat-9/x" }, /import mat-9 has no x/);
  refused({ a: ["ok", { b: "job:j000009/x" }] }, /^tool t: a\[1\]\.b names job:j000009/);
});

test("hostile shapes do not throw: deep nesting, a NUL, a huge string, odd ids", () => {
  let deep: unknown = "job:j000007/a dir";
  for (let i = 0; i < 40; i += 1) deep = [deep];
  assert.ok(run({ deep }).ok);
  assert.equal(run({ f: "job:j000007/a\0b" }).ok, false);
  assert.ok(run({ f: `job:${"x".repeat(100000)}` }).ok, "not a job id: left as it is");
  assert.deepEqual((run({ f: "job:J000007/x", g: "jobs:j000007/x", h: "$OUTSIDE/x", i: "x$OUT/y" }) as { args: unknown }).args, { f: "job:J000007/x", g: "jobs:j000007/x", h: "$OUTSIDE/x", i: "x$OUT/y" });
});
