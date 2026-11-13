/**
 * A program a job's worker could not execute is said in its reason
 * (scripts/job-exec-refused.ts). In a worker nothing under store/ (sealed
 * files have no execute bit), work/extracted/, work/quarantine/, inputs/ or
 * the job's own $OUT can run in place; a seat that supplied itself a program
 * found the way (a copy in an executable temporary directory inside the job)
 * only after two failed jobs, each of which said "exit 126" or "exit 127: a
 * program it runs is not in its image". What the reply says depends on where
 * the program stands: a supplied program is run from a copy, evidence is read
 * and never run, and the shell's other reasons for 126 are quoted. The match
 * is on the shell's exit status, its own lines and the loader's words; no
 * program is named.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import { describe, JobService, jobView } from "../scripts/job-service.ts";
import { storePaths } from "../scripts/evidence-store.ts";
import { execRefused, execRefusedIn, execRefusedWords, LOADER_REFUSAL, placeOf, type ExecRefused } from "../scripts/job-exec-refused.ts";
import { localWorker } from "./job-service-worker.ts";

const dirs: string[] = [];
after(async () => {
  for (const d of dirs) {
    // The store seals what a job wrote read-only.
    spawnSync("chmod", ["-R", "u+w", d]);
    await rm(d, { recursive: true, force: true });
  }
});

const RUN = "/runs/s3472f0";
const OUT = `${RUN}/.jobs/j000090`;
const at = { cwd: RUN, isFile: (p: string) => p.endsWith("/prog") || p.endsWith("/dropper") };
const esc = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

test("what counts: the shell's status 126 with its own line, the loader's refusal to map a segment at any status, a permission denied on an existing file under a read-only mount at another status; a denied write is not read", () => {
  // The shell, as it said it for a program unpacked into $OUT (exit 126).
  assert.deepEqual(execRefusedIn(`/job/command.sh: line 29: ${OUT}/root/usr/bin/tool: Permission denied`, { ...at, exit: 126 }), { error: "Permission denied", path: `${OUT}/root/usr/bin/tool` });
  // A sealed file in the store has no execute bit: relative, read from where the job started.
  assert.deepEqual(execRefusedIn("/job/command.sh: line 5: store/imports/mat-0002/out/prog: Permission denied", { ...at, exit: 126 }), { error: "Permission denied", path: `${RUN}/store/imports/mat-0002/out/prog` });
  assert.deepEqual(execRefusedIn("bash: tool: Permission denied", { ...at, exit: 126 }), { error: "Permission denied", path: null });
  // The shell's other reasons for 126, in bash 3.2's words and bash 5's.
  assert.deepEqual(execRefusedIn(`bash: line 4: ${OUT}/root/bin/tool: cannot execute binary file: Exec format error`, { ...at, exit: 126 }), { error: "Exec format error", path: `${OUT}/root/bin/tool` });
  assert.deepEqual(execRefusedIn(`/job/command.sh: line 4: ${OUT}/root/bin/tool: cannot execute binary file`, { ...at, exit: 126 }), { error: "Exec format error", path: `${OUT}/root/bin/tool` });
  assert.deepEqual(execRefusedIn(`bash: ${OUT}/run.sh: /usr/bin/env python3^M: bad interpreter: No such file or directory`, { ...at, exit: 126 }), { error: "bad interpreter", path: `${OUT}/run.sh` });
  assert.deepEqual(execRefusedIn(`bash: ${OUT}/d: Is a directory`, { ...at, exit: 126 }), { error: "Is a directory", path: `${OUT}/d` });
  assert.deepEqual(execRefusedIn(`/job/command.sh: line 3: ${OUT}/d: is a directory`, { ...at, exit: 126 }), { error: "Is a directory", path: `${OUT}/d` });
  // A missing interpreter is 127 in bash 5 on Linux, and it is no missing program.
  assert.deepEqual(execRefusedIn(`bash: ${OUT}/run.sh: /usr/bin/foo: bad interpreter: No such file or directory`, { ...at, exit: 127 }), { error: "bad interpreter", path: `${OUT}/run.sh` });
  assert.deepEqual(execRefusedIn(`/job/command.sh: line 4: ${OUT}/script: cannot execute: required file not found`, { ...at, exit: 127 }), { error: "bad interpreter", path: `${OUT}/script` });
  assert.equal(execRefusedIn(`bash: ${OUT}/run.sh: /usr/bin/foo: bad interpreter: No such file or directory`, { ...at, exit: 1 }), null);
  // Those lines at another status are the program's own words, not the shell's.
  assert.equal(execRefusedIn(`bash: ${OUT}/d: Is a directory`, { ...at, exit: 1 }), null);
  assert.equal(execRefusedIn("tool: cannot execute binary file", { ...at, exit: 2 }), null);
  // At another status a permission denied counts only for an existing file under a directory a worker mounts read-only (a write there is "Read-only file system").
  assert.deepEqual(execRefusedIn(`PermissionError: [Errno 13] Permission denied: '${RUN}/store/imports/mat-0001/out/prog'`, { ...at, exit: 1 }), { error: "Permission denied", path: `${RUN}/store/imports/mat-0001/out/prog` });
  assert.deepEqual(execRefusedIn(`PermissionError: [Errno 13] Permission denied: '${RUN}/inputs/dropper'`, { ...at, exit: 1 }), { error: "Permission denied", path: `${RUN}/inputs/dropper` });
  // ... not for a path that is no file there (a write that makes a new one), nor one outside those directories ($OUT: a read-only directory in it).
  assert.equal(execRefusedIn(`PermissionError: [Errno 13] Permission denied: '${RUN}/store/jobs/j000003/new'`, { ...at, exit: 1 }), null);
  assert.equal(execRefusedIn(`touch: cannot touch '${RUN}/notes.txt': Permission denied`, { ...at, exit: 1 }), null);
  assert.equal(execRefusedIn(`PermissionError: [Errno 13] Permission denied: '${OUT}/prog'`, { ...at, exit: 1 }), null);
  assert.equal(execRefusedIn(`touch: cannot touch '${OUT}/ro/new': Permission denied`, { ...at, exit: 1 }), null);
  assert.equal(execRefusedIn("fopen: Permission denied", { ...at, exit: 1 }), null);
  // The dynamic loader, for the program or a library it loads from a no-exec mount: at any status, the path it names.
  assert.deepEqual(execRefusedIn(`${OUT}/root/usr/bin/tool: error while loading shared libraries: ${OUT}/root/usr/bin/tool: ${LOADER_REFUSAL}`, { ...at, exit: 127 }), { error: LOADER_REFUSAL, path: `${OUT}/root/usr/bin/tool` });
  assert.deepEqual(execRefusedIn(`/job/x: error while loading shared libraries: ${OUT}/root/lib/libfoo.so.62: ${LOADER_REFUSAL}`, { ...at, exit: 1 }), { error: LOADER_REFUSAL, path: `${OUT}/root/lib/libfoo.so.62` });
  assert.deepEqual(execRefusedIn(`error while loading shared libraries: ${LOADER_REFUSAL}`, { ...at, exit: 127 }), { error: LOADER_REFUSAL, path: null });
  // A library that is merely missing is not a refusal to execute (the image does not hold it).
  assert.equal(execRefusedIn("tool: error while loading shared libraries: libfoo.so.1: cannot open shared object file: No such file or directory", { ...at, exit: 127 }), null);
  assert.equal(execRefusedIn("KeyError: 'entries'", { ...at, exit: 126 }), null);
  assert.equal(execRefusedIn("bash: tool: command not found", { ...at, exit: 127 }), null);
});

test("at exit 0, only the shell's own line for an existing file in the job's $OUT is read: a script that went on after a copied program could not run (the run sf4406b's j000279)", () => {
  const noexec = [{ guest: OUT, host: "/host/staging/j000090" }];
  const there = (p: string) => p === "/host/staging/j000090/mat-0002/bin/zbarimg";
  const line = `/job/command.sh: line 58: ${OUT}/mat-0002/bin/zbarimg: Permission denied`;
  assert.deepEqual(execRefusedIn(line, { cwd: RUN, exit: 0, noexec, isFile: there }), { error: "Permission denied", path: `${OUT}/mat-0002/bin/zbarimg` });
  assert.equal(execRefusedIn(line, { cwd: RUN, exit: 0, noexec, isFile: () => false }), null, "a file that is not there: a refused write or a missing one, not read here");
  assert.equal(execRefusedIn(line, { cwd: RUN, exit: 0, isFile: there }), null, "no no-exec place given: not read");
  assert.equal(execRefusedIn(`/job/command.sh: line 3: /tmp/x/prog: Permission denied`, { cwd: RUN, exit: 0, noexec, isFile: () => true }), null, "a file outside $OUT: not read at exit 0");
  assert.equal(execRefusedIn(`cp: cannot open '${OUT}/mat-0002/bin/zbarimg': Permission denied`, { cwd: RUN, exit: 0, noexec, isFile: there }), null, "another program's words: not read");
});

test("where a program stands decides what the reply says: a supplied import, evidence (an evidence import too), anywhere else", () => {
  assert.equal(placeOf(`${RUN}/store/imports/mat-0002/out/prog`, RUN), "supplied");
  for (const p of [`${RUN}/inputs/dropper`, `${RUN}/inputs/set/x`, `${RUN}/work/extracted/a1/x`, `${RUN}/work/quarantine/a1/x`, `${RUN}/store/imports/ev-0001/out/x`]) assert.equal(placeOf(p, RUN), "evidence", p);
  for (const p of [`${OUT}/root/bin/tool`, `${RUN}/store/jobs/j000003/out/x`, `${RUN}/store/imports/j000031/out/x`, "/usr/bin/tool", `${RUN}/work/a1/x`]) assert.equal(placeOf(p, RUN), "other", p);
  assert.equal(placeOf(null, RUN), "other");
});

test("a job's stdout, stderr and every stderr file it kept are read whole; the first line is named with where it is, the rest counted; status 126 alone is enough, and says that no line names the program", async () => {
  const base = await mkdtemp(join(tmpdir(), "xr-"));
  dirs.push(base);
  const ctl = join(base, "job");
  const out = join(base, "out");
  await mkdir(join(out, "p1"), { recursive: true });
  await mkdir(ctl, { recursive: true });
  // Nothing refused: no hint, at any status.
  await writeFile(join(ctl, "stdout.log"), "wc: 0\n");
  await writeFile(join(ctl, "stderr.log"), "Traceback (most recent call last):\nKeyError: 'entries'\n");
  assert.equal(await execRefused({ ctl, out, exit: 1, ...at }), null);
  assert.equal(await execRefused({ ctl, out, exit: 0, ...at }), null);
  // Status 126 and no line anywhere (the shell's words went into a file of the job's own that is not a stderr file).
  await writeFile(join(out, "version.txt"), `/job/command.sh: line 29: ${OUT}/root/usr/bin/tool: Permission denied\n`);
  assert.deepEqual(await execRefused({ ctl, out, exit: 126, ...at }), { error: null, path: null, file: null, line: null, text: null, lines: 0, files: 0 });
  // A line in a far corner of a long stdout, and in a kept stderr file.
  const said = `/job/command.sh: line 9: ${RUN}/store/imports/mat-0002/out/prog: Permission denied`;
  await writeFile(join(ctl, "stdout.log"), `${"x".repeat(3 << 20)}\nline\n${said}\n`);
  await writeFile(join(out, "p1", "run.stderr"), `bash: ${OUT}/root/bin/tool: Permission denied\nbash: ${OUT}/root/bin/tool: Permission denied\n`);
  const x = await execRefused({ ctl, out, exit: 126, ...at });
  assert.deepEqual(x, { error: "Permission denied", path: `${RUN}/store/imports/mat-0002/out/prog`, file: "stdout.log", line: 3, text: said, lines: 3, files: 2 });
  // At another status a permission denied counts for the file under the store (it exists) and not for the lines about $OUT; the loader's words still count wherever they are said.
  assert.deepEqual(await execRefused({ ctl, out, exit: 1, ...at }), { error: "Permission denied", path: `${RUN}/store/imports/mat-0002/out/prog`, file: "stdout.log", line: 3, text: said, lines: 1, files: 1 });
  await writeFile(join(ctl, "stdout.log"), "");
  assert.equal(await execRefused({ ctl, out, exit: 1, ...at }), null);
  const loader = `${OUT}/root/lib/libx.so.1: ${LOADER_REFUSAL}`;
  await writeFile(join(out, "p1", "run.stderr"), `${OUT}/root/bin/tool: error while loading shared libraries: ${loader}\nbash: ${OUT}/root/bin/tool: Permission denied\n${OUT}/root/bin/tool: error while loading shared libraries: ${loader}\n`);
  const y = await execRefused({ ctl, out, exit: 127, ...at });
  assert.equal(y?.error, LOADER_REFUSAL);
  assert.deepEqual([y?.path, y?.file, y?.line, y?.lines, y?.files], [`${OUT}/root/lib/libx.so.1`, "out/p1/run.stderr", 1, 2, 1]);
  // A line too long to be said whole is named by where it is, not cut.
  await writeFile(join(ctl, "stdout.log"), `/job/command.sh: line 9: ${RUN}/store/imports/mat-0002/out/${"d".repeat(2500)}/prog: Permission denied\n`);
  await writeFile(join(out, "p1", "run.stderr"), "");
  assert.equal((await execRefused({ ctl, out, exit: 126, ...at }))?.text, null);
});

test("the words: a supplied program is run from a copy; evidence is read and never run; the shell's other reasons for 126 are quoted and no copy is suggested; the whole path and place are always said", () => {
  const base: ExecRefused = { error: "Permission denied", path: `${RUN}/store/imports/mat-0002/out/prog`, file: "stdout.log", line: 3, text: "line", lines: 3, files: 2 };
  const o = { job: "j000090", out: OUT, cwd: RUN };
  // Supplied.
  const supplied = execRefusedWords(base, o);
  assert.match(supplied, /^a program it ran could not be executed \("Permission denied" on \/runs\/s3472f0\/store\/imports\/mat-0002\/out\/prog, store\/jobs\/j000090\/stdout\.log line 3; 3 such lines in 2 files\)\./);
  assert.match(supplied, /Nothing a worker holds in store\/ can be executed where it stands: sealed files have no execute bit\. This is a program the operator supplied: name it in the job's programs \(programs: \["import:mat-<n>"\]\), which copies it into an executable directory with its bin\/ on PATH and its lib\/ on LD_LIBRARY_PATH; or copy the program, and every library it loads, into an executable temporary directory inside the job \(for example one made with mktemp -d under \/tmp\), make it executable there and run it from that copy; what it writes that you want kept goes to \$OUT \(\/runs\/s3472f0\/\.jobs\/j000090\)$/);
  // Evidence: no recipe, the operator's tool-supply or a reimplementation.
  for (const p of [`${RUN}/inputs/dropper`, `${RUN}/work/extracted/a1/x/dropper`, `${RUN}/work/quarantine/a1/x`, `${RUN}/store/imports/ev-0001/out/e`]) {
    const w = execRefusedWords({ ...base, path: p, file: "out/p1/run.stderr", lines: 1, files: 1 }, o);
    assert.ok(w.includes(` on ${p}, job:j000090/p1/run.stderr line 3)`), "the path is whole and the file is cited as the job's output");
    assert.match(w, /evidence is read, never run, and a job that runs code recovered from it is flagged\. For a program you trust, ask the operator to supply one \(swarm\.sh tool-supply\); otherwise reimplement the step as a read of the bytes$/);
    assert.doesNotMatch(w, /mktemp|temporary directory|chmod|executable there/, `no recipe for evidence: ${w}`);
  }
  // Anywhere else (a job's own $OUT, an earlier job's output): the rule first, the recipe only for what the operator supplied.
  const other = execRefusedWords({ ...base, path: `${OUT}/root/bin/tool` }, o);
  assert.match(other, /Evidence is read, never run, and code recovered from it \(an extraction, a job's output\) is not run in a job: ask the operator to supply a program you trust \(swarm\.sh tool-supply\), or reimplement the step\. A program the operator supplied \(import:mat-<n>\), or unpacked from one, is run from a copy: copy the program, and every library it loads, into an executable temporary directory/);
  assert.ok(other.indexOf("Evidence is read, never run") < other.indexOf("mktemp"));
  // The loader says it for a file system that forbids executing, and for a worker with no memory.
  const mapped = execRefusedWords({ ...base, error: LOADER_REFUSAL, path: `${OUT}/root/lib/libx.so.1` }, o);
  assert.match(mapped, /\("failed to map segment from shared object" on \/runs\/s3472f0\/\.jobs\/j000090\/root\/lib\/libx\.so\.1, store\/jobs\/j000090\/stdout\.log line 3; 3 such lines in 2 files\)\. The loader says this when the file system forbids executing the file, and also when the worker had no memory left to map it\. /);
  // The shell's other reasons: its own line, and it is not about where the program stands.
  for (const [error, text, re] of [
    ["Exec format error", `bash: ${OUT}/tool: cannot execute binary file`, /another architecture, or not a program at all\): compare what it is built for with what the worker is \(uname -m\)$/],
    ["bad interpreter", `bash: ${OUT}/run.sh: /bin/foo^M: bad interpreter: No such file or directory`, /\(or, for a compiled program, its dynamic loader\) is not in the worker, or that line ends in a carriage return \(a file written on Windows\): read its first line$/],
    ["Is a directory", `bash: ${OUT}/d: Is a directory`, /name the file inside it$/],
  ] as const) {
    const w = execRefusedWords({ ...base, error, text, path: `${OUT}/x`, lines: 1, files: 1 }, o);
    assert.ok(w.startsWith(`a program it ran could not be executed (the shell says "${text}", store/jobs/j000090/stdout.log line 3). That is not a matter of where it stands, and copying it elsewhere will not change it: `), w);
    assert.match(w, re);
    assert.doesNotMatch(w, /mktemp|temporary directory|chmod/, `no copy for ${error}`);
  }
  // A line too long to quote is named by its error and path.
  assert.match(execRefusedWords({ ...base, error: "Exec format error", text: null, path: `${OUT}/x`, lines: 1, files: 1 }, o), /^a program it ran could not be executed \(Exec format error on \/runs\/s3472f0\/\.jobs\/j000090\/x, store\/jobs\/j000090\/stdout\.log line 3\)\./);
  // Status 126 alone: what it means, where the line may be, and the rule (the place is unknown).
  const bare = execRefusedWords({ error: null, path: null, file: null, line: null, text: null, lines: 0, files: 0 }, o);
  assert.match(bare, /^a program it ran could not be executed: exit 126 is the shell's status for a command it found and could not run \(no right to execute it, a file built for another machine, an interpreter that is missing, a directory\), and no line in stdout\.log, stderr\.log or a stderr file the job kept says which \(if the program's stderr went into a file of the job's own, it is there\)\. Nothing a worker holds in store\//);
  assert.match(bare, /Evidence is read, never run/);
});

test("through the service: a job that could not execute a program has it in its reason, on its record, on the journal and in what its requester is told, by where the program stands; the loader's refusal is no missing program, a missing program still is, and a refused write is still a refused write", async () => {
  const S = join(mkdtempSync(join(tmpdir(), "xr-jobs-")), "run");
  dirs.push(join(S, ".."));
  for (const d of ["inputs", "tools", "catalog", "work/a1", "work/extracted/a1", "store/imports/mat-0001/out", "store/imports/ev-0001/out"]) mkdirSync(join(S, d), { recursive: true });
  writeFileSync(join(S, "inputs.json"), JSON.stringify({ files: [] }));
  const plant = (rel: string, mode: number) => {
    writeFileSync(join(S, rel), "#!/bin/sh\necho hi\n", { mode });
    chmodSync(join(S, rel), mode);
  };
  plant("store/imports/mat-0001/out/prog", 0o444);
  plant("store/imports/ev-0001/out/e", 0o444);
  plant("inputs/dropper", 0o644);
  plant("work/extracted/a1/x", 0o644);
  const svc = new JobService({ sandbox: S, run: "s000000", image: "img:test", workers: 1, workerCpus: 1, workerMemoryMib: 512, allowHosts: [], openNet: false, packDirs: [], forging: false, minFreeMb: 1, runWorker: localWorker(), destroyWorker: async () => ({ ok: true }), notify: async () => undefined, identity: async () => ({}) });
  await svc.start();
  const run = async (command: string) => {
    const r = await svc.submit("a1", { kind: "command", command, inputs: ["all"] });
    assert.ok(r.ok, !r.ok ? r.reason : "");
    const end = Date.now() + 20_000;
    let job = svc.jobs.get(r.job.id)!;
    while (!["committed", "failed", "cancelled"].includes(job.state) && Date.now() < end) {
      await new Promise((res) => setTimeout(res, 50));
      job = svc.jobs.get(r.job.id)!;
    }
    return job;
  };
  const journal = () => readFileSync(storePaths(S).journal, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l) as Record<string, unknown>);
  const S_RE = esc(S);
  // A program unpacked into $OUT with no execute bit: exit 126, the shell's own words on stderr; the place is the job's own, so the rule comes first and the recipe is for what was supplied.
  const denied = await run(`printf '#!/bin/sh\\necho hi\\n' > "$OUT/prog"; "$OUT/prog"`);
  assert.equal(denied.status, "failed");
  assert.equal(denied.exit, 126);
  const out = join(S, ".jobs", denied.id);
  // The local worker runs the job's script on this host, so the shell names the staging directory $OUT stands for here.
  assert.match(denied.reason ?? "", new RegExp(`^exit 126: a program it ran could not be executed \\("Permission denied" on \\S+/prog, store/jobs/${denied.id}/stderr\\.log line 1\\)\\. Nothing a worker holds in store/, work/extracted/, work/quarantine/, inputs/ or its own \\$OUT can be executed where it stands`));
  assert.match(denied.reason ?? "", /Evidence is read, never run/);
  assert.ok((denied.reason ?? "").endsWith(`what it writes that you want kept goes to $OUT (${out})`));
  assert.match(denied.exec_refused?.path ?? "", /\/prog$/);
  assert.equal(denied.exec_refused?.error, "Permission denied");
  assert.equal(denied.program_missing, undefined);
  // The same program run by a script that goes on and ends 0: the job is ok, and its reason and its requester's post say what did not run.
  const swallowed = await run(`printf '#!/bin/sh\necho hi\n' > "$OUT/prog"; "$OUT/prog"; "$OUT/prog"; echo went on`);
  assert.equal(swallowed.status, "ok");
  assert.equal(swallowed.exit, 0);
  assert.match(swallowed.reason ?? "", /^exit 0, but a program it ran could not be executed \("Permission denied" on \S+\/prog, store\/jobs\/\S+\/stderr\.log line 1; 2 such lines in that file\)/);
  assert.equal(swallowed.exec_refused?.error, "Permission denied");
  assert.match(describe(swallowed), /\) done \(exit 0, but a program it ran could not be executed/);
  assert.ok(journal().some((l) => l.type === "job_exec_refused" && l.job === swallowed.id && l.exit === 0));
  // A script that ends 0 with no such line has no reason.
  const fine = await run(`echo fine`);
  assert.equal(fine.status, "ok");
  assert.equal(fine.reason, undefined);
  assert.equal(fine.exec_refused, undefined);
  assert.equal(denied.write_refused, undefined);
  assert.ok(journal().some((l) => l.type === "job_exec_refused" && l.job === denied.id && l.exit === 126 && l.path === denied.exec_refused?.path));
  assert.ok(journal().some((l) => l.type === "job_finished" && l.job === denied.id && l.reason === denied.reason), "the journal's job_finished carries the reason whole");
  assert.ok(describe(denied).includes(denied.reason!), "the post its requester gets says it whole");
  assert.equal((await jobView(S, denied)).reason, denied.reason, "and so does job_run's and job_status's answer");
  // A supplied program in the store, run in place: the recipe.
  const supplied = await run("store/imports/mat-0001/out/prog");
  assert.equal(supplied.exit, 126);
  assert.match(supplied.reason ?? "", new RegExp(`^exit 126: a program it ran could not be executed \\("Permission denied" on ${S_RE}/store/imports/mat-0001/out/prog, store/jobs/${supplied.id}/stderr\\.log line 1\\)\\. Nothing a worker holds in store/ can be executed where it stands: sealed files have no execute bit\\. This is a program the operator supplied: name it in the job's programs \\(programs: \\["import:mat-<n>"\\]\\), which copies it into an executable directory with its bin/ on PATH and its lib/ on LD_LIBRARY_PATH; or copy the program, and every library it loads, into an executable temporary directory`));
  assert.equal(supplied.write_refused, undefined);
  // Evidence run in place: no recipe, the operator's tool-supply.
  for (const [cmd, path] of [["inputs/dropper", "inputs/dropper"], ["work/extracted/a1/x", "work/extracted/a1/x"], ["store/imports/ev-0001/out/e", "store/imports/ev-0001/out/e"]] as const) {
    const ev = await run(cmd);
    assert.equal(ev.exit, 126, cmd);
    assert.ok((ev.reason ?? "").includes(`("Permission denied" on ${S}/${path}, `), ev.reason);
    assert.match(ev.reason ?? "", /evidence is read, never run, and a job that runs code recovered from it is flagged\. For a program you trust, ask the operator to supply one \(swarm\.sh tool-supply\)/);
    assert.doesNotMatch(ev.reason ?? "", /mktemp|temporary directory/);
  }
  // A program run by a program that reports its own status (a script's subprocess call): exit 1, and the denied file exists under a read-only mount: an exec, not a write.
  const sub = await run(`echo "PermissionError: [Errno 13] Permission denied: '$PWD/store/imports/mat-0001/out/prog'" >&2; exit 1`);
  assert.equal(sub.exit, 1);
  assert.match(sub.reason ?? "", new RegExp(`^exit 1: a program it ran could not be executed \\("Permission denied" on ${S_RE}/store/imports/mat-0001/out/prog, `));
  assert.match(sub.reason ?? "", /This is a program the operator supplied/);
  assert.equal(sub.write_refused, undefined);
  // The same words about a path that is no file there are a write.
  const wrote2 = await run(`echo "PermissionError: [Errno 13] Permission denied: '$PWD/store/jobs/j999999/new.txt'" >&2; exit 1`);
  assert.match(wrote2.reason ?? "", /^exit 1: a write outside \$OUT was refused/);
  assert.equal(wrote2.exec_refused, undefined);
  // Status 126 with the shell's words sent into a file of the job's own: no line names the program, and the reply says so.
  const hidden = await run(`printf '#!/bin/sh\\n' > "$OUT/prog"; "$OUT/prog" > "$OUT/version.txt" 2>&1`);
  assert.equal(hidden.exit, 126);
  assert.match(hidden.reason ?? "", /^exit 126: a program it ran could not be executed: exit 126 is the shell's status for a command it found and could not run .*no line in stdout\.log, stderr\.log or a stderr file the job kept says which/);
  assert.equal(hidden.exec_refused?.path, null);
  // The shell's other reasons for 126: its own line, and no copy is suggested.
  const format = await run(`printf '\\177ELF\\0\\0\\0' > "$OUT/bin"; chmod +x "$OUT/bin"; "$OUT/bin"`);
  assert.equal(format.exit, 126);
  assert.equal(format.exec_refused?.error, "Exec format error");
  assert.match(format.reason ?? "", /^exit 126: a program it ran could not be executed \(the shell says ".*cannot execute binary file.*", store\/jobs\/j\d+\/stderr\.log line 1\)\. That is not a matter of where it stands/);
  assert.doesNotMatch(format.reason ?? "", /mktemp|temporary directory/);
  const interp = await run(`printf '#!/no/such/interpreter\\n' > "$OUT/script"; chmod +x "$OUT/script"; "$OUT/script"`);
  assert.ok([126, 127].includes(interp.exit ?? 0), `bash says 126 or 127 for a missing interpreter: ${interp.exit}`);
  assert.equal(interp.program_missing, undefined, "a missing interpreter is no program missing from the image");
  assert.equal(interp.exec_refused?.error, "bad interpreter");
  assert.match(interp.reason ?? "", /(bad interpreter|required file not found).*That is not a matter of where it stands.*first line$/);
  const dir = await run(`mkdir "$OUT/d"; "$OUT/d"`);
  assert.equal(dir.exit, 126);
  assert.equal(dir.exec_refused?.error, "Is a directory");
  // The loader's refusal to map a segment (exit 127) is no program missing from the image.
  const mapped = await run(`echo "$OUT/root/usr/bin/tool: error while loading shared libraries: $OUT/root/usr/bin/tool: ${LOADER_REFUSAL}" >&2; exit 127`);
  assert.equal(mapped.exit, 127);
  assert.match(mapped.reason ?? "", new RegExp(`^exit 127: a program it ran could not be executed \\("${LOADER_REFUSAL}" on `));
  assert.match(mapped.reason ?? "", /also when the worker had no memory left to map it/);
  assert.equal(mapped.program_missing, undefined);
  assert.ok(!journal().some((l) => l.type === "job_program_missing" && l.job === mapped.id));
  // A directory made read-only inside $OUT and written to: a refused write in the job's own space is no program that could not be executed, and its reason is the exit status.
  if (process.getuid?.() !== 0) {
    const ro = await run(`mkdir "$OUT/ro" && chmod 555 "$OUT/ro" && touch "$OUT/ro/new"`);
    assert.equal(ro.exit, 1);
    assert.equal(ro.reason, "exit 1");
    assert.equal(ro.exec_refused, undefined);
  }
  // A program the image does not hold is still that.
  const missing = await run("no-such-program-here-xyz");
  assert.equal(missing.exit, 127);
  assert.match(missing.reason ?? "", /^exit 127: a program it runs is not in its image/);
  assert.equal(missing.exec_refused, undefined);
  // A refused write is still a refused write, and a failure that is neither keeps "exit N".
  const wrote = await run(`echo "OSError: [Errno 30] Read-only file system: '$PWD/notes.log'" >&2; exit 1`);
  assert.match(wrote.reason ?? "", /^exit 1: a write outside \$OUT was refused/);
  assert.equal(wrote.exec_refused, undefined);
  const other = await run(`echo "KeyError: 'entries'" >&2; exit 1`);
  assert.equal(other.reason, "exit 1");
  // A job that succeeded is not read for it, whatever its stderr says.
  const ok = await run(`echo "bash: $OUT/prog: Permission denied" >&2; exit 0`);
  assert.equal(ok.status, "ok");
  assert.equal(ok.exec_refused, undefined);
  await svc.stop("test over");
});

test("the worker prompt says where a program can and cannot be executed in a job, and that evidence is read, never run", () => {
  const prompt = readFileSync(join(import.meta.dirname, "..", "prompts", "worker-system.md"), "utf8").replace(/\s+/g, " ");
  for (const must of [
    "A job cannot run a program where it stands in store/, work/extracted/, work/quarantine/, inputs/ or $OUT (sealed files have no execute bit and the others are no-exec).",
    "Evidence is read, never run: code recovered from it is not run in a job, so reimplement the step or ask the operator for a program you trust (swarm.sh tool-supply).",
    "A program the operator supplied (import:mat-<n>) is run from a copy: copy it, and every library it loads, into an executable temporary directory inside the job and run it from there.",
    "A job that failed on this says so in its reason.",
  ]) assert.ok(prompt.includes(must), `prompts/worker-system.md does not say: ${must}`);
});
