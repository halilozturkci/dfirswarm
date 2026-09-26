/**
 * Agents on the base image, the packs' programs in the job images: a pack
 * tool that fails in the agent's VM for want of a program or a module runs
 * again as a job in its pack's image (extensions/agent-swarm.ts). These are
 * the two decisions that rerun rests on, and the pager's home inside a job.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { lacksProgram, ownPathsToOut } from "../extensions/protocol.ts";
import { LIB, runPy, withCwd } from "./tool-library-harness.ts";

const run = (stderr: string, exit_code: number | null = 1, stdout = "") => ({ exit_code, stdout, stderr });

test("a run that failed for want of a program or a module is told apart from one that failed on its input", () => {
  assert.match(lacksProgram(run("FileNotFoundError: [Errno 2] No such file or directory: 'icat'")) ?? "", /icat is not in this VM/);
  assert.match(lacksProgram(run("ModuleNotFoundError: No module named 'pyewf'")) ?? "", /pyewf is not in this VM/);
  assert.match(lacksProgram(run("bash: line 1: esedbexport: command not found", 127)) ?? "", /esedbexport is not in this VM/);
  assert.match(lacksProgram(run("", 0, '{"error": "vshadowinfo is not installed"}')) ?? "", /vshadowinfo is not in this VM/);
  assert.match(lacksProgram(run("", 127)) ?? "", /exit 127/);
  assert.equal(lacksProgram(run("FileNotFoundError: [Errno 2] No such file or directory: 'inputs/Case4.E01'")), null, "a missing evidence path is the caller's, not the VM's");
  assert.equal(lacksProgram(run('{"error": "no FILE record in this slice"}')), null);
  assert.equal(lacksProgram(run("", 0, '{"ok": true}')), null);
});

test("a path under the agent's own work/ becomes the job's $OUT, and nothing else is touched", () => {
  const args = { output: "work/s01/carved/a.bin", image: "inputs/disk.E01", nested: { out_dir: "./work/s01/jl" }, list: ["work/s01/x", "work/s02/y"], n: 3 };
  assert.deepEqual(ownPathsToOut(args, "s01"), { output: "{OUT}/carved/a.bin", image: "inputs/disk.E01", nested: { out_dir: "{OUT}/jl" }, list: ["{OUT}/x", "work/s02/y"], n: 3 });
  assert.deepEqual(ownPathsToOut(args, undefined), args, "no agent, no mapping");
});

test("inside a job a paging tool writes its whole result under $OUT and names it by where the store will hold it", async () => {
  await withCwd(async (cwd) => {
    const out = join(cwd, ".jobs", "j000042");
    await mkdir(out, { recursive: true });
    const lines = Array.from({ length: 12 }, (_, i) => `r/r ${i + 1}: Windows/Prefetch/APP${i + 1}.EXE.pf`);
    await writeFile(join(cwd, "filelist.txt"), `${lines.join("\n")}\n`);
    const r = await runPy(join(LIB, "catalog_grep", "run.py"), cwd, { pattern: "prefetch", path: "filelist.txt", limit: 3 }, undefined, { AGENT_ID: "s01", JOB_ID: "j000042", OUT: out });
    assert.equal(r.code, 0, r.stderr + r.stdout);
    const got = JSON.parse(r.stdout);
    assert.equal(got.matched, 12);
    assert.match(got.all_results, /^store\/jobs\/j000042\/out\/tool-output\/catalog_grep-[0-9a-f]{16}\.jsonl$/);
    const kept = (await readFile(join(out, "tool-output", got.all_results.split("/").pop()), "utf8")).trimEnd().split("\n");
    assert.equal(kept.length, 12, "every row is in $OUT");
  });
});
