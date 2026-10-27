/**
 * The memory-forensics pack, after the independent R2 review of mem_carve v7, mem_fs v7 and mem_profile v6: in a job the hit list and
 * the engine's mount (and the logs beside it) are under $OUT and nowhere else, a list that fails on a row beyond the inline page is not
 * complete, a list that was given up leaves no file nobody names, an answer that was written is not turned into a signal death by the
 * interpreter's shutdown, and an explicit hit list is flushed as it is written. Every case here fails on the tools as they were at
 * origin/main 3e6d4314 (run the suite with MEM_TOOLS_DIR pointing at a checkout of it to see that).
 *
 * What the tools do with the clock, the disk and the engine is faked by a sitecustomize on PYTHONPATH that is active only in a process
 * whose script is a run.py and only for the variables a test sets (the stub engine it starts is not affected).
 */
import assert from "node:assert/strict";
import { access, mkdir, readFile, readdir, realpath, rm, writeFile } from "node:fs/promises";
import { basename, join } from "node:path";
import { test } from "node:test";
import { withCwd } from "./tool-library-harness.ts";
import { CARVE, FS, PROFILE, fsStub, json, runTool } from "./memory-f1-support.ts";

const exists = (p: string) => access(p).then(() => true, () => false);

async function shimDir(cwd: string): Promise<string> {
  const dir = join(cwd, "shim-r2");
  await mkdir(dir, { recursive: true });
  await writeFile(join(dir, "sitecustomize.py"), `import os, signal, sys
_tool = bool(sys.argv) and sys.argv[0].endswith("run.py")
if os.environ.get("FAKE_ISMOUNT"):
    os.path.ismount = lambda p: os.path.isdir(os.path.join(p, "sys"))
_bad = os.environ.get("FAKE_LSTAT_FAIL")
if _bad and _tool:
    _lstat = os.lstat
    def _failing(p, *a, **k):
        if os.path.basename(str(p)).startswith(_bad):
            raise OSError(5, "Input/output error")
        return _lstat(p, *a, **k)
    os.lstat = _failing
_nap = float(os.environ.get("FAKE_DUMPS_SLEEP", "0") or 0)
if _nap and _tool:
    import json, time
    _dumps = json.dumps
    def _slow(*a, **k):
        time.sleep(_nap)
        return _dumps(*a, **k)
    json.dumps = _slow
if os.environ.get("FAKE_SIGNAL_AT_EXIT") and _tool:
    class _Late:
        def __del__(self):
            os.kill(os.getpid(), signal.SIGHUP)
    _late = _Late()
`);
  return dir;
}

const jobIn = (cwd: string, secret = true) => {
  const out = join(cwd, ".jobs", "j000001");
  return { out, env: { JOB_ID: "j000001", OUT: out, ...(secret ? { SECRET_OUTPUT: "1" } : {}) } as Record<string, string> };
};
const regfImage = (hits: number, spacing = 128): Buffer => {
  const blob = Buffer.alloc(hits * spacing);
  for (let i = 0; i < hits; i++) blob.write("regf", i * spacing, "latin1");
  return blob;
};

type Carve = { status: string; error?: string; hit_count: number; complete_results?: string; results_to?: string };
type Fs = {
  status: string; status_basis: string; error?: string; phase?: string; complete: boolean; entry_count: number;
  entries: Record<string, unknown>[]; partial_results?: string; mount?: string;
};

// --- P2-3: in a job the output is $OUT and nothing else -----------------------------------------------------------------------

test("mem_carve in a job writes its hit list under $OUT only, secret output or not (P2-3)", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "inputs", "memory.raw"), regfImage(3));
    await mkdir(join(cwd, "work", "s1"), { recursive: true });
    for (const secret of [true, false]) {
      const { out, env } = jobIn(cwd, secret);
      await mkdir(out, { recursive: true });
      for (const results_to of ["work/s1/h.jsonl", join(cwd, "work", "s1", "h.jsonl"), "work/s1/sub/h.jsonl"]) {
        const run = await runTool(CARVE, cwd, { path: "inputs/memory.raw", results_to }, env);
        const answer = json<Carve>(run);
        assert.equal(run.code, 1, `${results_to}: ${run.stdout.slice(0, 300)}`);
        assert.equal(answer.status, "failed");
        assert.match(answer.error as string, /results_to must be a file under \$OUT in a job/);
      }
      assert.deepEqual(await readdir(join(cwd, "work", "s1")), [], "a refused call created nothing outside $OUT, not even a directory");
      // a path under $OUT is written, relative to the run or absolute
      const inside = json<Carve>(await runTool(CARVE, cwd, { path: "inputs/memory.raw", results_to: join(out, "h.jsonl") }, env));
      assert.equal(inside.status, "complete");
      assert.equal(inside.complete_results, join(await realpath(out), "h.jsonl"));
      assert.equal((await readFile(join(out, "h.jsonl"), "utf8")).trimEnd().split("\n").length, 3);
    }
  });
});

test("mem_carve outside a job still writes its hit list under work/<id>/ (P2-3 does not take that away)", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "inputs", "memory.raw"), regfImage(3));
    const run = json<Carve>(await runTool(CARVE, cwd, { path: "inputs/memory.raw", results_to: "work/s1/h.jsonl" }));
    assert.equal(run.status, "complete");
    assert.equal((await readFile(join(cwd, "work", "s1", "h.jsonl"), "utf8")).trimEnd().split("\n").length, 3);
  });
});

test("mem_fs in a job mounts under $OUT only, so the engine's logs are never beside a mount elsewhere (P2-3)", async () => {
  await withCwd(async (cwd, bin) => {
    const env = await fsStub(cwd, bin, { tree: { "proc/a.txt": "alpha\n", "sys/x": "" } });
    await writeFile(join(cwd, "inputs", "memory.raw"), Buffer.alloc(4096));
    await mkdir(join(cwd, "work", "s1"), { recursive: true });
    for (const secret of [true, false]) {
      const { out, env: job } = jobIn(cwd, secret);
      await mkdir(out, { recursive: true });
      for (const mount of ["work/s1/mem", join(cwd, "work", "s1", "mem"), "work/s1/deep/mem"]) {
        const run = await runTool(FS, cwd, { path: "inputs/memory.raw", mount, mode: "list", timeout_seconds: 10 }, { ...env, ...job }, bin);
        const answer = json<Fs>(run);
        assert.equal(run.code, 1, `${mount}: ${run.stdout.slice(0, 300)}`);
        assert.equal(answer.status, "failed");
        assert.match(answer.error as string, /mount must be a directory under \$OUT in a job/);
      }
      assert.deepEqual(await readdir(join(cwd, "work", "s1")), [], "no mount directory and no engine log outside $OUT");
      assert.equal(await exists(join(cwd, "stub2-started.log")), false, "the engine was never started");
      const inside = json<Fs>(await runTool(FS, cwd, { path: "inputs/memory.raw", mount: join(out, "mem"), mode: "list", timeout_seconds: 20 }, { ...env, ...job }, bin));
      assert.equal(inside.status, "complete", JSON.stringify(inside).slice(0, 300));
      assert.ok((await readdir(out)).some((n) => n.startsWith("mem.memprocfs-") && n.endsWith(".stdout.log")), "the logs are beside the mount, under $OUT");
      await rm(join(cwd, "stub2-started.log"), { force: true });
    }
  });
});

// --- P2-4: a list is complete only when no row failed, wherever the row sits --------------------------------------------------

test("mem_fs list is partial when the rows that failed are beyond the inline page (P2-4)", async () => {
  await withCwd(async (cwd, bin) => {
    const tree: Record<string, string> = { "sys/x": "" };
    for (let i = 0; i < 6; i++) tree[`d/f${i}`] = "x";
    tree["d/zz-bad"] = "x";
    const stub = await fsStub(cwd, bin, { tree });
    const shim = await shimDir(cwd);
    await writeFile(join(cwd, "inputs", "memory.raw"), Buffer.alloc(4096));
    const run = await runTool(FS, cwd, { path: "inputs/memory.raw", mount: "work/s1/mem", mode: "list", list: "d", limit: 3, timeout_seconds: 20 },
      { ...stub, PYTHONPATH: shim, FAKE_ISMOUNT: "1", FAKE_LSTAT_FAIL: "zz-bad" }, bin);
    const answer = json<Fs>(run);
    assert.equal(answer.entry_count, 7);
    assert.equal(answer.entries.length, 3, "the failing row is not on the inline page");
    assert.ok(!answer.entries.some((row) => "error" in row));
    assert.equal(answer.status, "partial", answer.status_basis);
    assert.equal(answer.complete, false);
    assert.match(answer.status_basis, /1 entries could not be read/);
  });
});

test("mem_fs list with no failing row is still complete (P2-4 counts failures, nothing else)", async () => {
  await withCwd(async (cwd, bin) => {
    const tree: Record<string, string> = { "sys/x": "" };
    for (let i = 0; i < 6; i++) tree[`d/f${i}`] = "x";
    const stub = await fsStub(cwd, bin, { tree });
    const shim = await shimDir(cwd);
    await writeFile(join(cwd, "inputs", "memory.raw"), Buffer.alloc(4096));
    const answer = json<Fs>(await runTool(FS, cwd, { path: "inputs/memory.raw", mount: "work/s1/mem", mode: "list", list: "d", limit: 3, timeout_seconds: 20 },
      { ...stub, PYTHONPATH: shim, FAKE_ISMOUNT: "1", FAKE_LSTAT_FAIL: "zz-bad" }, bin));
    assert.equal(answer.status, "complete");
    assert.equal(answer.complete, true);
  });
});

// --- P3-2: a read that was given up leaves no file nobody names ---------------------------------------------------------------

test("mem_fs list that misses its deadline stops its worker and names the rows it kept (P3-2)", async () => {
  await withCwd(async (cwd, bin) => {
    const tree: Record<string, string> = { "sys/x": "" };
    for (let i = 0; i < 200; i++) tree[`d/n${String(i).padStart(3, "0")}`] = "x";
    const stub = await fsStub(cwd, bin, { tree });
    const shim = await shimDir(cwd);
    await writeFile(join(cwd, "inputs", "memory.raw"), Buffer.alloc(4096));
    const run = await runTool(FS, cwd, { path: "inputs/memory.raw", mount: "work/s1/mem", mode: "list", list: "d", limit: 10, timeout_seconds: 3 },
      { ...stub, PYTHONPATH: shim, FAKE_ISMOUNT: "1", FAKE_DUMPS_SLEEP: "0.02" }, bin);
    const answer = json<Fs>(run);
    assert.equal(answer.status, "failed", run.stdout.slice(0, 300));
    assert.equal(answer.phase, "read");
    assert.match(answer.error as string, /did not finish within the 3s deadline/);
    const kept = (await readdir(join(cwd, "work", "s1", "tool-output"), { recursive: true })).filter((n) => /\.jsonl/.test(n));
    assert.ok(typeof answer.partial_results === "string", `a file of rows exists (${kept.join(", ")}) and the answer does not name it`);
    assert.deepEqual(kept.map((n) => basename(n)), [basename(answer.partial_results as string)], "the only file of rows is the one the answer names, and it is not hidden");
    const lines = (await readFile(join(cwd, answer.partial_results as string), "utf8")).trimEnd().split("\n").length;
    assert.ok(lines > 10 && lines < 200, `${lines} rows: some were kept and the worker did not go on to the end`);
  });
});

// --- P3-1: the answer was written; the interpreter's shutdown does not turn it into a signal death -----------------------------

test("a stop that arrives during the interpreter's shutdown does not change the exit of a finished call (P3-1)", async () => {
  await withCwd(async (cwd, bin) => {
    const shim = await shimDir(cwd);
    const late = { PYTHONPATH: shim, FAKE_SIGNAL_AT_EXIT: "1" };
    await writeFile(join(cwd, "inputs", "memory.raw"), regfImage(5));
    const carve = await runTool(CARVE, cwd, { path: "inputs/memory.raw" }, late);
    assert.equal(json<Carve>(carve).status, "complete");
    assert.deepEqual([carve.code, carve.signal], [0, null], "mem_carve");

    const profile = await runTool(PROFILE, cwd, { path: "inputs/memory.raw" }, late);
    assert.ok(json<{ status: string }>(profile).status);
    assert.deepEqual([profile.code, profile.signal], [0, null], "mem_profile");

    const stub = await fsStub(cwd, bin, { tree: { "proc/a.txt": "alpha\n", "sys/x": "" } });
    const fs = await runTool(FS, cwd, { path: "inputs/memory.raw", mount: "work/s1/mem", mode: "list", timeout_seconds: 20 }, { ...stub, ...late, FAKE_ISMOUNT: "1" }, bin);
    assert.equal(json<Fs>(fs).status, "complete");
    assert.deepEqual([fs.code, fs.signal], [0, null], "mem_fs");

    // a refusal keeps its exit status 1 and its single document
    const refused = await runTool(CARVE, cwd, { path: "inputs/nothing.raw" }, late);
    assert.equal(json<Carve>(refused).status, "failed");
    assert.deepEqual([refused.code, refused.signal], [1, null], "a refusal");
  });
});

// --- P3-4: an explicit hit list is flushed as it is written --------------------------------------------------------------------

test("mem_carve flushes an explicit hit list to disk as it is written, not only at the end (P3-4)", async () => {
  await withCwd(async (cwd) => {
    const hits = 3000;
    await writeFile(join(cwd, "inputs", "memory.raw"), regfImage(hits));
    const runner = join(cwd, "runner.py");
    // the tool's own source with the interval lowered to 64 KiB, and every fsync counted
    await writeFile(runner, `import os, sys
path = os.environ["RUN_PY"]
src = open(path).read().replace("SYNC_EVERY = 256 << 20", "SYNC_EVERY = 1 << 16")
real = os.fsync
def counting(fd):
    with open(os.environ["FSYNC_LOG"], "a") as f:
        f.write("x\\n")
    return real(fd)
os.fsync = counting
sys.argv[0] = path
exec(compile(src, path, "exec"), {"__name__": "__main__", "__file__": path})
`);
    const log = join(cwd, "fsync.log");
    const env = { RUN_PY: CARVE, FSYNC_LOG: log };
    const run = await runTool(runner, cwd, { path: "inputs/memory.raw", results_to: "work/s1/h.jsonl" }, env);
    const answer = json<Carve>(run);
    assert.equal(answer.status, "complete", run.stdout.slice(0, 300));
    assert.equal(answer.hit_count, hits);
    const written = (await readFile(join(cwd, "work", "s1", "h.jsonl"), "utf8")).trimEnd().split("\n");
    assert.equal(written.length, hits);
    assert.deepEqual(written.slice(0, 3).map((l) => JSON.parse(l).signature_offset), [0, 128, 256], "the hit list is whole and in order");
    const syncs = (await readFile(log, "utf8")).trimEnd().split("\n").length;
    assert.ok(syncs >= 5, `${syncs} fsync calls for a hit list of ${written.join("\n").length} bytes at a 64 KiB interval`);
  });
});
