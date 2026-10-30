/**
 * Agents on the base image, the packs' programs in the job images: a pack
 * tool that fails in the agent's VM for want of a program or a module runs
 * again as a job in its pack's image (extensions/agent-swarm.ts). These are
 * the decisions that rerun rests on — whether to rerun, and which of the
 * paths it was given the job writes to its $OUT — and the pager's home
 * inside a job.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { heldOwnPaths, lacksProgram, ownPathsToOut, stagedPaths, stagedPathsIn, toolArgsForJob, writtenToOf } from "../extensions/protocol.ts";
import { LIB, ROOT, runPy, withCwd } from "./tool-library-harness.ts";

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
  // Every place the agent's VM may write, not work/<id>/ alone: an extraction
  // under work/extracted/<id>/ failed read-only in the job on the first round.
  assert.deepEqual(
    ownPathsToOut({ output: "work/extracted/s01/vault.vhdx", q: "work/quarantine/s01/x.exe", t: "tool-output/s01/big.json", peer: "work/extracted/s02/y" }, "s01"),
    { output: "{OUT}/extracted/vault.vhdx", q: "{OUT}/quarantine/x.exe", t: "{OUT}/tool-output/big.json", peer: "work/extracted/s02/y" },
  );
});

test("any way of naming a place in the agent's own directories maps alike, and nothing outside them does", () => {
  const root = "/runs/s9";
  assert.deepEqual(
    ownPathsToOut({
      abs: "/runs/s9/work/extracted/s01/places.sqlite",
      dots: "work/s02/../s01/./carved//a.bin",
      home: "work/s01",
      slash: "work/extracted/s01/",
      other_run: "/runs/s8/work/s01/x",
      climbs: "work/s01/../../inputs/disk.E01",
      peer: "/runs/s9/work/s02/x",
      given: "{OUT}/already",
      text: "alpha|beta",
      inside: "sys/proc/proc.txt",
    }, "s01", { root }),
    {
      abs: "{OUT}/extracted/places.sqlite",
      dots: "{OUT}/carved/a.bin",
      home: "{OUT}",
      slash: "{OUT}/extracted",
      other_run: "/runs/s8/work/s01/x",
      climbs: "work/s01/../../inputs/disk.E01",
      peer: "/runs/s9/work/s02/x",
      given: "{OUT}/already",
      text: "alpha|beta",
      inside: "sys/proc/proc.txt",
    },
  );
});

test("a rerun reads what the agent's directories already hold where it is, writes the rest to $OUT, and says where each went", async () => {
  await withCwd(async (cwd) => {
    // What the agent extracted before (a database, a directory of hives) is
    // an input: mapped, it would be looked for in an empty $OUT. What a failed
    // attempt in the agent's VM left (an empty output file, an empty output
    // directory) is still a place to write.
    await mkdir(join(cwd, "work", "extracted", "s01"), { recursive: true });
    await writeFile(join(cwd, "work", "extracted", "s01", "WebCacheV01.dat"), "ese");
    await mkdir(join(cwd, "work", "s01", "hives"), { recursive: true });
    await writeFile(join(cwd, "work", "s01", "hives", "SYSTEM"), "regf");
    await mkdir(join(cwd, "work", "s01", "zeek"), { recursive: true });
    await writeFile(join(cwd, "work", "s01", "partial.bin"), "");
    const args = {
      path: "work/extracted/s01/WebCacheV01.dat",
      dir: `${cwd}/work/s01/hives`,
      out_dir: "work/s01/zeek",
      output: "work/s01/partial.bin",
      out_file: "work/extracted/s01/rows.jsonl",
      image: "inputs/disk.E01",
    };
    const held = await heldOwnPaths(cwd, args, "s01");
    assert.deepEqual([...held].sort(), ["work/extracted/s01/WebCacheV01.dat", "work/s01/hives"]);
    const mapped = ownPathsToOut(args, "s01", { root: cwd, held });
    assert.deepEqual(mapped, {
      path: "work/extracted/s01/WebCacheV01.dat",
      dir: `${cwd}/work/s01/hives`,
      out_dir: "{OUT}/zeek",
      output: "{OUT}/partial.bin",
      out_file: "{OUT}/extracted/rows.jsonl",
      image: "inputs/disk.E01",
    });
    assert.deepEqual(writtenToOf(args, mapped, "j000013"), {
      "work/s01/zeek": "store/jobs/j000013/out/zeek",
      "work/s01/partial.bin": "store/jobs/j000013/out/partial.bin",
      "work/extracted/s01/rows.jsonl": "store/jobs/j000013/out/extracted/rows.jsonl",
    });
    assert.deepEqual(writtenToOf({ out_dir: "work/s01" }, ownPathsToOut({ out_dir: "work/s01" }, "s01"), "j000014"), { "work/s01": "store/jobs/j000014/out" });
  });
});

test("icat_extract, rerun as a job with the output it was given, writes it to $OUT, where unmapped the worker could not write it", async () => {
  // The first basic-flow round: six icat_extract reruns with output under
  // work/extracted/<id>/ each failed "Read-only file system" in the worker.
  // Here the worker's view is made the same way: work/ read-only, $OUT the
  // one place to write, and a stub icat on PATH.
  await withCwd(async (cwd, bin) => {
    const out = join(cwd, ".jobs", "j000013");
    await mkdir(out, { recursive: true });
    await mkdir(join(cwd, "work", "extracted", "s01"), { recursive: true });
    await chmod(join(cwd, "work", "extracted", "s01"), 0o555);
    await chmod(join(cwd, "work"), 0o555);
    try {
      const given = { image: "inputs/AF-Case2.E01", offset: 2048, inode: "102124-128-4", output: "work/extracted/s01/vault.vhdx" };
      const mapped = ownPathsToOut(given, "s01", { root: cwd, held: await heldOwnPaths(cwd, given, "s01") });
      const argsInJob = JSON.parse(JSON.stringify(mapped).split("{OUT}").join(out)) as Record<string, unknown>;
      const script = join(ROOT, "packs", "computer-forensics-base", "tools", "icat_extract", "run.py");
      const r = await runPy(script, cwd, argsInJob, bin, { AGENT_ID: "s01", JOB_ID: "j000013", OUT: out });
      assert.equal(r.code, 0, r.stderr + r.stdout);
      assert.equal(await readFile(join(out, "extracted", "vault.vhdx"), "utf8"), "extracted-bytes");
      assert.deepEqual(writtenToOf(given, mapped, "j000013"), { "work/extracted/s01/vault.vhdx": "store/jobs/j000013/out/extracted/vault.vhdx" });
      // What it printed names the staging place; `paths` names the sealed one.
      assert.deepEqual(stagedPaths(r.stdout, cwd, "j000013"), { [join(out, "extracted", "vault.vhdx")]: "store/jobs/j000013/out/extracted/vault.vhdx" });
      // Unmapped, the worker could not write it: what the round saw.
      const unmapped = await runPy(script, cwd, given, bin, { AGENT_ID: "s01", JOB_ID: "j000013", OUT: out });
      assert.notEqual(unmapped.code, 0);
    } finally {
      await chmod(join(cwd, "work"), 0o755);
      await chmod(join(cwd, "work", "extracted", "s01"), 0o755);
    }
  });
});

test("job_run maps a tool's output path as a rerun does: linux_triage's out_dir under work/<id>/ is written to $OUT", async () => {
  // The first microVM case run: three job_run calls of linux_triage with
  // out_dir work/<id>/triage, as its manifest asks, were each refused before
  // anything ran, since job_run passed the path through unmapped.
  await withCwd(async (cwd, bin) => {
    const out = join(cwd, ".jobs", "j000013");
    await mkdir(out, { recursive: true });
    await writeFile(join(bin, "target-query"), "#!/bin/sh\nexit 0\n", "utf8");
    await chmod(join(bin, "target-query"), 0o755);
    await chmod(join(cwd, "work"), 0o555);
    try {
      const given = { source: "inputs/Webserver.E01", out_dir: "work/s02/triage", groups: ["identity"], timeout_seconds: 30, total_timeout_seconds: 60 };
      const mapped = await toolArgsForJob(cwd, given, "s02");
      assert.equal(mapped.out_dir, "{OUT}/triage");
      assert.deepEqual(writtenToOf(given, mapped, "j000013"), { "work/s02/triage": "store/jobs/j000013/out/triage" });
      const script = join(ROOT, "packs", "linux-forensics", "tools", "linux_triage", "run.py");
      const env = { AGENT_ID: "s02", JOB_ID: "j000013", OUT: out };
      const unmapped = await runPy(script, cwd, given, bin, env);
      assert.match(unmapped.stdout, /in a job out_dir must be a new directory/, "unmapped: what the run saw");
      const r = await runPy(script, cwd, JSON.parse(JSON.stringify(mapped).split("{OUT}").join(out)) as Record<string, unknown>, bin, env);
      assert.doesNotMatch(r.stdout, /in a job out_dir must be/, r.stdout);
      assert.ok(JSON.parse(await readFile(join(out, "triage", "summary.json"), "utf8")), "its summary is under $OUT/triage");
    } finally {
      await chmod(join(cwd, "work"), 0o755);
    }
  });
  const src = await readFile(join(ROOT, "extensions", "agent-swarm.ts"), "utf8");
  assert.match(src, /tool: params\.tool, args: toolArgs/, "job_run submits the mapped arguments");
});

test("the places a rerun's output names under its staging directory are mapped to where the job sealed them", async () => {
  // A tool run as a job prints what it wrote as the worker saw it: under
  // <run>/.jobs/<id>/, or .jobs/<id>/ from the run's directory. That place is
  // gone once the job is sealed; the output stays as it is, and `paths` says
  // where each place it names is now.
  const root = "/runs/s9";
  const out = [
    '{"path": "/runs/s9/.jobs/j000013/extracted/vault.vhdx", "size": 3}',
    '{"out_dir": ".jobs/j000013/zeek", "logs": {"conn": {"file": ".jobs/j000013/zeek/conn.log"}}}',
    "wrote ./.jobs/j000013/carved/a.bin, and /runs/s9/.jobs/j000013 holds the rest.",
    "left alone: .jobs/j000014/other, foo.jobs/j000013/x, /elsewhere/.jobs/j000013/y, work/s01/.jobs/j000013/z",
  ].join("\n");
  assert.deepEqual(stagedPaths(out, root, "j000013"), {
    "/runs/s9/.jobs/j000013/extracted/vault.vhdx": "store/jobs/j000013/out/extracted/vault.vhdx",
    ".jobs/j000013/zeek": "store/jobs/j000013/out/zeek",
    ".jobs/j000013/zeek/conn.log": "store/jobs/j000013/out/zeek/conn.log",
    "./.jobs/j000013/carved/a.bin": "store/jobs/j000013/out/carved/a.bin",
    "/runs/s9/.jobs/j000013": "store/jobs/j000013/out",
  });
  await withCwd(async (cwd) => {
    // The sealed stdout.log is read whole, a line at a time: past the page an
    // answer carries.
    const lines = Array.from({ length: 3000 }, (_, i) => `row ${i}`);
    lines.push(`${cwd}/.jobs/j000021/csv/usn.csv`);
    await mkdir(join(cwd, "store", "jobs", "j000021"), { recursive: true });
    await writeFile(join(cwd, "store", "jobs", "j000021", "stdout.log"), `${lines.join("\n")}\n`);
    assert.deepEqual(await stagedPathsIn(join(cwd, "store", "jobs", "j000021", "stdout.log"), cwd, "j000021"), {
      [`${cwd}/.jobs/j000021/csv/usn.csv`]: "store/jobs/j000021/out/csv/usn.csv",
    });
  });
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
