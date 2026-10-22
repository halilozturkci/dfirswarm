/**
 * mem_fs, after the review of the memory-forensics pack: a second export in one job, the secret-output gate, signals, the timeout bound,
 * names and engine text judged before they are shown, non-UTF-8 names, status, and the bound on `limit`. The engine is a stub on PATH
 * (tests/memory-f1-support.ts). Every case here fails on the tool as it was on main.
 */
import assert from "node:assert/strict";
import { mkdir, readFile, readdir, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { withCwd } from "./tool-library-harness.ts";
import { FS, PWD12, SHAPES, fsStub, json, rng, runTool } from "./memory-f1-support.ts";

type Item = { item_id: string; virtual_path: string; output?: string; bytes?: number; status: string };
type Fs = {
  status: string; status_basis: string; complete?: boolean; error?: string; signal?: number; phase?: string; blocked_by?: string[] | null;
  items?: Item[]; entries?: { name: string; directory?: boolean; size?: number; name_withheld?: boolean }[]; entry_count?: number; counts?: Record<string, number>;
  secret_values?: { requested: boolean; written: number; values_dir: string | null; manifest: string | null; contains_secret_values: boolean };
  names?: { withheld_or_changed: number; originals_file: string | null }; boundary?: Record<string, unknown>;
  limit_clamped_to?: number; complete_results?: string; logs?: { stdout: string; stderr: string };
  engine_stderr?: { lines: string[] }; stderr?: string; stdout?: string;
};
const jobDir = async (cwd: string, id = "j000042", secret = true) => {
  const out = join(cwd, ".jobs", id);
  await mkdir(out, { recursive: true });
  return { out, job: { JOB_ID: id, OUT: out, ...(secret ? { SECRET_OUTPUT: "1" } : {}) } };
};
const image = async (cwd: string) => writeFile(join(cwd, "inputs", "memory.raw"), Buffer.alloc(4096));
const manifestRows = async (out: string) => (await readFile(join(out, "mem_fs", "export-manifest.jsonl"), "utf8")).trimEnd().split("\n").map((l) => JSON.parse(l) as Record<string, unknown>);

test("a second export in the same job output adds its rows, counts its file, and says it holds secret values (P2-1)", async () => {
  await withCwd(async (cwd, bin) => {
    const env = await fsStub(cwd, bin, { tree: { "proc/a.txt": "alpha\n", "proc/b.txt": "bravo\n", "sys/x": "" } });
    await image(cwd);
    const { out, job } = await jobDir(cwd);
    const base = { path: "inputs/memory.raw", mode: "export", write_values: true, timeout_seconds: 30 };
    const one = json<Fs>(await runTool(FS, cwd, { ...base, mount: join(out, "m1"), paths: ["proc/a.txt"] }, { ...env, ...job }, bin));
    assert.equal(one.secret_values?.written, 1);
    const two = json<Fs>(await runTool(FS, cwd, { ...base, mount: join(out, "m2"), paths: ["proc/b.txt", "proc/a.txt"] }, { ...env, ...job }, bin));
    assert.deepEqual(two.items?.map((i) => i.status.split(":")[0]), ["exported", "refused"], JSON.stringify(two.items));
    assert.equal(two.secret_values?.written, 1, "the file this call wrote is counted");
    assert.equal(two.secret_values?.contains_secret_values, true);
    assert.ok(two.secret_values?.values_dir);
    const rows = await manifestRows(out);
    assert.deepEqual(rows.map((r) => r.virtual_path).sort(), ["proc/a.txt", "proc/b.txt"], "every file on disk has a manifest row");
    assert.equal(await readFile(join(out, "mem_fs", "proc", "b.txt"), "utf8"), "bravo\n");
    // a call that writes nothing new still says the job's output holds values from an earlier call
    const three = json<Fs>(await runTool(FS, cwd, { ...base, mount: join(out, "m3"), paths: ["proc/a.txt"] }, { ...env, ...job }, bin));
    assert.equal(three.secret_values?.written, 0);
    assert.equal(three.secret_values?.contains_secret_values, true);
  });
});

test("mem_fs writes content only in a job run as secret output, and refuses before it starts the engine otherwise (P2-2)", async () => {
  await withCwd(async (cwd, bin) => {
    const env = await fsStub(cwd, bin, { tree: { "proc/a.txt": "alpha\n" } });
    await image(cwd);
    const { out, job } = await jobDir(cwd, "j000043", false);
    const refused = json<Fs>(await runTool(FS, cwd, { path: "inputs/memory.raw", mount: join(out, "m"), mode: "export", write_values: true, paths: ["proc/a.txt"] }, { ...env, ...job }, bin));
    assert.equal(refused.status, "failed");
    assert.match(refused.error as string, /not run as secret output/);
    await assert.rejects(stat(join(out, "mem_fs")), "nothing was created");
    await assert.rejects(stat(env.STUB_LOG), "MemProcFS was not started");
    // list with write_values is a values mode too
    const list = json<Fs>(await runTool(FS, cwd, { path: "inputs/memory.raw", mount: join(out, "m"), mode: "list", write_values: true }, { ...env, ...job }, bin));
    assert.match(list.error as string, /not run as secret output/);
  });
  const manifest = JSON.parse(await readFile(join(import.meta.dirname, "..", "packs", "memory-forensics", "tools", "mem_fs", "manifest.json"), "utf8"));
  assert.deepEqual(manifest.secret_output, { when_args: ["write_values"] });
  assert.doesNotMatch(manifest.description, /cannot see whether/);
});

test("mem_fs bounds timeout_seconds below the tool's 600 s and answers with JSON (P2-6)", async () => {
  await withCwd(async (cwd, bin) => {
    const env = await fsStub(cwd, bin, { tree: { "proc/a.txt": "alpha\n" } });
    await image(cwd);
    for (const timeout_seconds of [481, 600, 100000]) {
      const refused = json<Fs>(await runTool(FS, cwd, { path: "inputs/memory.raw", mount: "work/s1/m", timeout_seconds }, env, bin));
      assert.equal(refused.status, "failed");
      assert.match(refused.error as string, /from 2 to 480/);
    }
    await assert.rejects(stat(env.STUB_LOG), "the engine was not started for a refused bound");
  });
});

test("mem_fs ends with one JSON answer on SIGTERM, stops its engine, and leaves no mount (P2-5)", async () => {
  await withCwd(async (cwd, bin) => {
    const pidFile = join(cwd, "engine.pid");
    const env = await fsStub(cwd, bin, { tree: { "proc/a.txt": "alpha\n" }, mode: "never", pidFile });
    await image(cwd);
    const run = await runTool(FS, cwd, { path: "inputs/memory.raw", mount: "work/s1/m", mode: "list", timeout_seconds: 60 }, env, bin, "SIGTERM", 1500);
    assert.equal(run.code, 143, run.stderr);
    assert.doesNotMatch(run.stderr, /Traceback/);
    const out = json<Fs>(run);
    assert.equal(out.status, "interrupted");
    assert.equal(out.signal, 15);
    assert.ok(run.ms < 15_000);
    const pid = Number(await readFile(pidFile, "utf8"));
    assert.throws(() => process.kill(pid, 0), "the engine is gone");
    assert.deepEqual(await readdir(join(cwd, "work", "s1", "m")), []);
    const hup = await runTool(FS, cwd, { path: "inputs/memory.raw", mount: "work/s1/m2", mode: "list", timeout_seconds: 60 }, env, bin, "SIGINT", 1000);
    assert.equal(hup.code, 130);
    assert.doesNotMatch(hup.stderr, /Traceback|KeyboardInterrupt/);
  });
});

test("mem_fs prints no listed name whole when it is a secret of a shape the boundary reads, and keeps the plain ones (P2-8)", async () => {
  await withCwd(async (cwd, bin) => {
    const r = rng(11);
    const tree: Record<string, string> = { "sys/x": "" };
    const secrets: [string, string][] = [];
    for (const [shape, make] of Object.entries(SHAPES)) {
      for (let i = 0; i < 20; i++) {
        const s = make(r);
        const name = s.replace(/\//g, "_"); // a name holds no "/": a file name made of a base64 key writes it as "_"
        secrets.push([shape, name]);
        tree[`name/${name}`] = "";
      }
    }
    const plain = ["1234-notepad.exe", "{8b9f2a1c-4d3e-4f50-9a7b-1c2d3e4f5a6b}", "S-1-5-21-1004336348-1177238915-682003330-512", "ffffe0014c3a5000", "Microsoft.Windows.Cortana_cw5n1h2txyewy", "WindowsPackageManagerServer", "System32", "config", "ntuser.dat", "Program Files (x86)"];
    for (const p of plain) tree[`name/${p}`] = "";
    const env = await fsStub(cwd, bin, { tree });
    await image(cwd);
    const out = json<Fs>(await runTool(FS, cwd, { path: "inputs/memory.raw", mount: "work/s1/m", mode: "list", list: "name", timeout_seconds: 60, limit: 5000 }, env, bin));
    const printed = JSON.stringify(out);
    const leaked: Record<string, number> = {};
    for (const [shape, name] of secrets) if (printed.includes(name)) leaked[shape] = (leaked[shape] ?? 0) + 1;
    assert.deepEqual(leaked, {}, "whole secrets printed, by shape");
    for (const p of plain) assert.ok(out.entries?.some((e) => e.name === p), `${p} was changed`);
    assert.ok((out.names?.withheld_or_changed ?? 0) >= secrets.length * 0.9);
    assert.ok(out.status === "complete" || /backstop replaced/.test(out.status_basis), "a partial listing says why: the backstop replaced a string the layers before it let through");
    // the plain ones come first, in order; the changed ones follow
    const flags = out.entries?.map((e) => !!e.name_withheld) ?? [];
    assert.equal(flags.indexOf(true), flags.lastIndexOf(false) + 1);
    // a twelve-character password alone in a name is not recognised, by design: it is the stated residual
    const pw = PWD12(rng(5));
    const env2 = await fsStub(cwd, bin, { tree: { [`name/${pw}`]: "", "sys/x": "" } });
    const shown = json<Fs>(await runTool(FS, cwd, { path: "inputs/memory.raw", mount: "work/s1/m2", mode: "list", list: "name", timeout_seconds: 60 }, env2, bin));
    assert.ok(shown.entries?.some((e) => e.name === pw), "printed as it is");
  });
});

test("in a secret job, list with write_values keeps the original names in a 0600 file and prints none of them (P2-8)", async () => {
  await withCwd(async (cwd, bin) => {
    const secret = SHAPES.ghp(rng(3));
    const env = await fsStub(cwd, bin, { tree: { [`name/${secret}`]: "", "name/plain.txt": "", "sys/x": "" } });
    await image(cwd);
    const { out, job } = await jobDir(cwd);
    const run = await runTool(FS, cwd, { path: "inputs/memory.raw", mount: join(out, "m"), mode: "list", list: "name", write_values: true, timeout_seconds: 60 }, { ...env, ...job }, bin);
    const answer = json<Fs>(run);
    assert.ok(!run.stdout.includes(secret));
    assert.equal(answer.names?.withheld_or_changed, 1);
    assert.match(answer.names?.originals_file as string, /\/mem_fs\/names\.jsonl$/);
    const file = join(out, "mem_fs", "names.jsonl");
    assert.equal((await stat(file)).mode & 0o777, 0o600);
    assert.ok((await readFile(file, "utf8")).includes(secret));
    // a second call in the job takes the next name and does not fail
    const again = json<Fs>(await runTool(FS, cwd, { path: "inputs/memory.raw", mount: join(out, "m2"), mode: "list", list: "name", write_values: true, timeout_seconds: 60 }, { ...env, ...job }, bin));
    assert.equal(again.status, "complete");
    assert.match(again.names?.originals_file as string, /names\.1\.jsonl$/);
  });
});

test("mem_fs does not echo the engine's output in a failure, keeps its logs 0600, and names what the host lacks (P2-8, P3-6, P3-7)", async () => {
  await withCwd(async (cwd, bin) => {
    const secret = SHAPES.aws_secret40(rng(9));
    const token = SHAPES.github_pat(rng(2));
    const env = await fsStub(cwd, bin, { tree: { "sys/x": "" }, mode: "exit", stderrText: `FUSE is not available: /dev/fuse is missing\nlast key ${secret}\nAPI_TOKEN=${token}` });
    await image(cwd);
    const run = await runTool(FS, cwd, { path: "inputs/memory.raw", mount: "work/s1/m", mode: "list", timeout_seconds: 30 }, env, bin);
    const out = json<Fs>(run);
    assert.equal(out.status, "failed");
    assert.equal(out.phase, "startup");
    assert.ok(!run.stdout.includes(secret) && !run.stdout.includes(token), "a secret on the engine's stderr is in the answer");
    assert.match(JSON.stringify(out.engine_stderr?.lines), /FUSE is not available/, "the plain line is still shown");
    assert.equal(out.stderr, undefined);
    assert.equal(out.stdout, undefined);
    for (const log of [out.logs?.stdout, out.logs?.stderr]) assert.equal((await stat(log as string)).mode & 0o777, 0o600);
    assert.ok((await readFile(out.logs?.stderr as string, "utf8")).includes(secret), "the whole log is the file");
    assert.ok(Array.isArray(out.blocked_by) || out.blocked_by === null);
  });
});

test("mem_fs gives a status and a basis, counts a path no worker reached, and clamps limit (P2-11, P2-12)", async () => {
  await withCwd(async (cwd, bin) => {
    const tree: Record<string, string> = { "sys/x": "" };
    for (let i = 0; i < 30; i++) tree[`d/f${String(i).padStart(2, "0")}`] = "";
    const env = await fsStub(cwd, bin, { tree });
    await image(cwd);
    const list = json<Fs>(await runTool(FS, cwd, { path: "inputs/memory.raw", mount: "work/s1/m", mode: "list", list: "d", limit: 1_000_000_000, timeout_seconds: 30 }, env, bin));
    assert.equal(list.status, "complete");
    assert.match(list.status_basis, /30 entries/);
    assert.equal(list.limit_clamped_to, 5000);
    const { out, job } = await jobDir(cwd);
    const exp = json<Fs>(await runTool(FS, cwd, { path: "inputs/memory.raw", mount: join(out, "m"), mode: "export", write_values: true, paths: ["d/f00", "d/missing"], timeout_seconds: 30 }, { ...env, ...job }, bin));
    assert.equal(exp.status, "partial");
    assert.equal(exp.complete, false);
    assert.match(exp.status_basis, /1 of 2/);
    const bad = json<Fs>(await runTool(FS, cwd, { path: "inputs/nothing.raw", mount: "work/s1/m" }, env, bin));
    assert.equal(bad.status, "failed");
    assert.ok((bad.status_basis as string).length > 20);
  });
});

test("mem_fs keeps different Unicode names in different output files (P3-3)", async () => {
  await withCwd(async (cwd, bin) => {
    const env = await fsStub(cwd, bin, { tree: { "d/café.txt": "one", "d/cafè.txt": "two", "d/100%.txt": "three", "d/100_.txt": "four", "sys/x": "" } });
    await image(cwd);
    const { out, job } = await jobDir(cwd);
    const exp = json<Fs>(await runTool(FS, cwd, { path: "inputs/memory.raw", mount: join(out, "m"), mode: "export", write_values: true, paths: ["d/café.txt", "d/cafè.txt", "d/100%.txt", "d/100_.txt"], timeout_seconds: 30 }, { ...env, ...job }, bin));
    assert.deepEqual(exp.counts, { requested: 4, exported: 4, failed: 0, refused: 0, not_exported: 0, partial: 0, not_attempted: 0 });
    assert.equal(await readFile(join(out, "mem_fs", "d", "caf%C3%A9.txt"), "utf8"), "one");
    assert.equal(await readFile(join(out, "mem_fs", "d", "caf%C3%A8.txt"), "utf8"), "two");
  });
});

test("mem_fs lists and exports a name that is not UTF-8, and its counts add up (P2-9)", { skip: process.platform === "darwin" ? "this file system refuses a name that is not UTF-8" : false }, async () => {
  await withCwd(async (cwd, bin) => {
    const env = await fsStub(cwd, bin, { tree: { "sys/x": "" } });
    const tree = env.STUB_TREE;
    await mkdir(join(tree, "d"), { recursive: true });
    const raw = Buffer.concat([Buffer.from(join(tree, "d") + "/p"), Buffer.from([0xff])]);
    const { writeFileSync } = await import("node:fs");
    writeFileSync(raw, "x");
    for (let i = 0; i < 300; i++) writeFileSync(join(tree, "d", `f${i}`), "");
    await image(cwd);
    const list = json<Fs>(await runTool(FS, cwd, { path: "inputs/memory.raw", mount: "work/s1/m", mode: "list", list: "d", limit: 200, timeout_seconds: 30 }, env, bin));
    assert.equal(list.entry_count, 301);
    assert.ok(list.complete_results);
    const whole = (await readFile(join(cwd, list.complete_results as string), "utf8")).trimEnd().split("\n");
    assert.equal(whole.length, 301);
    assert.ok(whole.some((l) => l.includes("\\xff")), "the byte is written, not lost");
  });
});
