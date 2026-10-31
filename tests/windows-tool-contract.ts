/**
 * One test helper for the contract every windows-forensics tool that pages and runs on a clock carries (docs/packs.md, section 8): the
 * tool stops on a signal with one JSON document and no hidden file, it has its own deadline, a rerun never puts a smaller result where a
 * larger one is, and an argument of the wrong type gets JSON. The tool-family suites import this module and keep their cases in files of
 * their own, so that the same code proves the same sentence for every tool.
 *
 *  - withDeadline(tool, seconds)      a copy of the tool with its DEADLINE_SECONDS constant set (0 makes any input hostile)
 *  - stopAt(...) + assertStopped(...)  a stop signal at one of four moments, and what must be true after it
 *  - rerunSmaller(...)                two runs in one job $OUT, the second with a smaller result
 *  - typeConfused(...) + assertJsonAnswer(...)  up to 1,000 argument sets of the wrong type, each of which must be answered in JSON
 *
 * Every process a helper starts is recorded by pid and ended by the helper (a run has a timeout of 60 seconds at most; the recorded
 * processes are also ended when this process exits). Nothing here is a claim about a tool's own answers beyond the contract: a suite adds
 * the cases of its tools' formats.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import type { ChildProcess } from "node:child_process";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import { WIN, stub } from "./windows-pack-harness.ts";

/** The status word of the STOP block's answer. One constant, so that a sweep that renames the word changes one line. */
export const STOP_STATUS = "interrupted";
export const SIGNAL_NUMBER = { SIGTERM: 15, SIGINT: 2, SIGHUP: 1 } as const;
export type StopSignal = keyof typeof SIGNAL_NUMBER;
export type Moment = "early" | "temp" | "child" | "print";
export const MAX_RUN_MS = 60_000;

/** A tool is named (a directory of packs/windows-forensics/tools) or given as the path of a run.py. */
export type ToolRef = string;
export type Env = Record<string, string>;
export type Exit = { code: number | null; signal: NodeJS.Signals | null };
export type Done = Exit & { stdout: string; stderr: string };

export function scriptOf(tool: ToolRef): string {
  return tool.endsWith(".py") ? tool : join(WIN, tool, "run.py");
}

// --- every process and directory the helpers make is recorded and ended ------------------------------------------------------------

const livePids = new Set<number>();
const temporaryDirs = new Set<string>();

/** End every process the helpers started that is still alive (a tool that outlived its test, a stand-in program that was recorded). */
export function endRecorded(): void {
  for (const pid of livePids) {
    try {
      process.kill(pid, "SIGKILL");
    } catch {
      /* already gone */
    }
  }
  livePids.clear();
}

/** Remove the directories the helpers made (copies of tools, prefixes). */
export function removeTemporary(): void {
  for (const dir of temporaryDirs) rmSync(dir, { recursive: true, force: true });
  temporaryDirs.clear();
}

process.on("exit", () => {
  endRecorded();
  removeTemporary();
});

function temporary(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  temporaryDirs.add(dir);
  return dir;
}

function alive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

async function until<T>(what: string, waitMs: number, probe: () => T | undefined | false): Promise<T> {
  const stop = Date.now() + waitMs;
  for (;;) {
    const got = probe();
    if (got !== undefined && got !== false) return got;
    if (Date.now() > stop) throw new Error(`gave up waiting for ${what}`);
    await new Promise((r) => setTimeout(r, 20));
  }
}

// --- one started tool --------------------------------------------------------------------------------------------------------------

export type Started = {
  child: ChildProcess;
  pid: number;
  closed: Promise<Exit>;
  stdout: () => string;
  stderr: () => string;
  /** Stop reading the tool's stdout (it is then blocked in a write of a large answer) and start again. */
  hold: () => void;
  release: () => void;
};

/** Start a tool the way the harness does (a JSON document on stdin, AGENT_ID set), recorded by pid, killed at MAX_RUN_MS. */
export function startTool(tool: ToolRef, cwd: string, args: unknown, env: Env = {}, rawStdin?: string): Started {
  const child = spawn("python3", [scriptOf(tool)], { cwd, env: { ...process.env, AGENT_ID: "s1", ...env }, stdio: ["pipe", "pipe", "pipe"] });
  const pid = child.pid as number;
  livePids.add(pid);
  const out: Buffer[] = [];
  const err: Buffer[] = [];
  child.stdout.on("data", (c: Buffer) => out.push(c));
  child.stderr.on("data", (c: Buffer) => err.push(c));
  child.stdin.on("error", () => undefined); // a tool that ended without reading its arguments
  child.stdin.end(rawStdin ?? JSON.stringify(args));
  const timer = setTimeout(() => child.kill("SIGKILL"), MAX_RUN_MS);
  // The tool has ended when its process has (a program it started and left alive holds the pipes open, so "close" would wait for that program):
  // what it wrote is read for a moment more, then the answer is final.
  const closed = new Promise<Exit>((resolve) => {
    let settled = false;
    const settle = (code: number | null, signal: NodeJS.Signals | null): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      livePids.delete(pid);
      resolve({ code, signal });
    };
    child.on("close", settle);
    child.on("exit", (code, signal) => setTimeout(() => settle(code, signal), 300));
  });
  return {
    child,
    pid,
    closed,
    stdout: () => Buffer.concat(out).toString("utf8"),
    stderr: () => Buffer.concat(err).toString("utf8"),
    hold: () => child.stdout?.pause(),
    release: () => child.stdout?.resume(),
  };
}

export async function runTool(tool: ToolRef, cwd: string, args: unknown, env: Env = {}, rawStdin?: string): Promise<Done> {
  const run = startTool(tool, cwd, args, env, rawStdin);
  const exit = await run.closed;
  return { ...exit, stdout: run.stdout(), stderr: run.stderr() };
}

/** The environment of a job: JOB_ID and an $OUT under cwd, which is made. */
export function jobEnv(cwd: string, jobId = "j000001", outName = "out"): Env {
  mkdirSync(join(cwd, outName), { recursive: true });
  return { JOB_ID: jobId, OUT: join(cwd, outName) };
}

// --- the deadline -----------------------------------------------------------------------------------------------------------------

/**
 * A copy of the tool in a temporary tools directory with `DEADLINE_SECONDS = <seconds> ` (the constant, a space, then its comment).
 * Returns the path of the copied run.py. `also` names sibling tool directories to copy beside it (lnk_jumplist loads two). Throws when
 * the constant is not there.
 */
export function withDeadline(tool: ToolRef, seconds: number, also: string[] = []): string {
  assert.ok(Number.isInteger(seconds) && seconds >= 0, "seconds is a whole number");
  const source = scriptOf(tool);
  const text = readFileSync(source, "utf8");
  const pattern = /^DEADLINE_SECONDS = \d+(?= )/m;
  if (!pattern.test(text)) throw new Error(`${source} has no line "DEADLINE_SECONDS = <int> <comment>"`);
  const tools = join(temporary("deadline-"), "tools");
  const name = basename(dirname(source));
  for (const dir of [name, ...also]) cpSync(join(dirname(dirname(source)), dir), join(tools, dir), { recursive: true });
  const copy = join(tools, name, "run.py");
  writeFileSync(copy, text.replace(pattern, `DEADLINE_SECONDS = ${seconds}`));
  assert.ok(readFileSync(copy, "utf8").includes(`DEADLINE_SECONDS = ${seconds} `), "the deadline was set");
  return copy;
}

// --- a stop signal ----------------------------------------------------------------------------------------------------------------

export type StopRun = Done & {
  moment: Moment;
  sent: StopSignal;
  cwd: string;
  /** Directories where no hidden file may be left. */
  dirs: string[];
  /** The pids of the stand-in programs the tool had started when the signal came. */
  children: number[];
};

/** The places a tool writes a page's temporary file: work/<agent>/tool-output outside a job, $OUT and $OUT/tool-output in one. */
export function outputDirs(cwd: string, env: Env = {}): string[] {
  const dirs = [join(cwd, "work", "s1", "tool-output")];
  if (env.OUT) dirs.push(env.OUT, join(env.OUT, "tool-output"));
  return dirs;
}

function hiddenFiles(dirs: string[]): string[] {
  const found: string[] = [];
  const walk = (dir: string): void => {
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      if (e.name.startsWith(".")) found.push(join(dir, e.name));
      if (e.isDirectory() && !e.name.startsWith(".")) walk(join(dir, e.name));
    }
  };
  for (const dir of dirs) walk(dir);
  return found;
}

/**
 * Run `tool` and send `signal` at `moment`:
 *  - early: the module has run as far as the end of its STOP block, and the signal is sent from there (the interpreter's own start is not claimed);
 *  - temp:  a hidden file exists under tool-output/ or $OUT; the tool is held (SIGSTOP), signalled and let go, so that the signal cannot land after the answer;
 *  - child: `opts.pidFile` holds the pid of a stand-in program the tool started; the same hold;
 *  - print: the answer is larger than the pipe and stdout is not read, so the tool is blocked in the write.
 * `opts.cwd` is where the tool runs (its inputs are there). A moment that is never reached throws: the input was not large enough.
 */
export async function stopAt(tool: ToolRef, args: unknown, env: Env, moment: Moment, signal: StopSignal, opts: { cwd: string; pidFile?: string; waitMs?: number }): Promise<StopRun> {
  const { cwd } = opts;
  const waitMs = Math.min(opts.waitMs ?? 45_000, MAX_RUN_MS - 5_000);
  const base = { moment, sent: signal, cwd, dirs: outputDirs(cwd, env), children: [] as number[] };
  if (moment === "early") {
    const text = readFileSync(scriptOf(tool), "utf8");
    const end = text.indexOf("# END SHARED STOP");
    if (end < 0) throw new Error(`${scriptOf(tool)} has no STOP block, so there is no moment after its handlers are installed`);
    const dir = temporary("stop-early-");
    const script = join(dir, "prefix.py");
    writeFileSync(script, `${text.slice(0, text.indexOf("\n", end) + 1)}\nimport os as _os, signal as _signal, time as _time\n_os.kill(_os.getpid(), _signal.${signal})\n_time.sleep(30)\nprint("survived")\n`);
    const done = await runTool(script, dir, undefined, env, "");
    return { ...done, ...base, cwd: dir, dirs: [] };
  }
  const run = startTool(tool, cwd, args, env);
  try {
    if (moment === "temp") {
      await until("a hidden temporary file", waitMs, () => {
        if (run.child.exitCode !== null || run.child.signalCode !== null) throw new Error("the tool ended before it wrote a hidden temporary file: the input is too small to reach that moment");
        return hiddenFiles(base.dirs).length > 0 || undefined;
      });
    } else if (moment === "child") {
      if (!opts.pidFile) throw new Error("the child moment needs opts.pidFile");
      const pidFile = opts.pidFile;
      const pid = await until("the stand-in program's pid", waitMs, () => {
        if (run.child.exitCode !== null || run.child.signalCode !== null) throw new Error("the tool ended before it started the stand-in program");
        const text = existsSync(pidFile) ? readFileSync(pidFile, "utf8").trim() : "";
        return /^\d+$/.test(text) ? Number(text) : undefined;
      });
      base.children.push(pid);
      livePids.add(pid);
    } else {
      // print: wait for the first bytes, then stop reading; the pipe fills and the tool blocks in the write.
      await new Promise<void>((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error("the tool wrote nothing")), waitMs);
        run.child.stdout?.once("data", () => {
          clearTimeout(timer);
          run.hold();
          resolve();
        });
      });
      await new Promise((r) => setTimeout(r, 500));
      if (run.child.exitCode !== null || run.child.signalCode !== null) throw new Error("the tool ended before it could be signalled: its answer is too small to fill the pipe");
    }
    if (moment === "print") {
      run.child.kill(signal);
      await new Promise((r) => setTimeout(r, 200));
      run.release();
    } else {
      run.child.kill("SIGSTOP");
      run.child.kill(signal);
      run.child.kill("SIGCONT");
    }
    const exit = await run.closed;
    return { ...exit, stdout: run.stdout(), stderr: run.stderr(), ...base };
  } catch (error) {
    run.child.kill("SIGKILL");
    await run.closed;
    throw error;
  }
}

/**
 * What must be true after a stop signal: exactly one JSON document on stdout; if its status is the STOP block's word the exit is 128 plus
 * the signal (and the document names the signal); if the tool ended first, the document is the tool's own whole answer; no hidden file is
 * left in tool-output/ or $OUT; no recorded stand-in program is alive. Returns whether the signal was answered (false: the tool's answer was whole first).
 */
export function assertStopped(run: StopRun, signal: StopSignal = run.sent): { answered: boolean; answer: Record<string, unknown> } {
  const where = `[${run.moment} ${signal}]`;
  const left = hiddenFiles(run.dirs);
  const kids = run.children.filter(alive);
  for (const pid of kids) {
    try {
      process.kill(pid, "SIGKILL");
    } catch {
      /* gone */
    }
  }
  assert.deepEqual(kids, [], `${where} a stand-in program started by the tool is still alive`);
  assert.deepEqual(left, [], `${where} hidden files were left behind`);
  assert.doesNotMatch(run.stderr, /Traceback/, `${where} a traceback on stderr`);
  assert.ok(run.signal === null, `${where} the tool was ended by signal ${run.signal} with no handler to answer it (stdout: ${run.stdout.slice(0, 200)})`);
  let answer: unknown;
  try {
    answer = JSON.parse(run.stdout);
  } catch (error) {
    assert.fail(`${where} stdout is not exactly one JSON document (${String(error)}): ${run.stdout.slice(0, 300)} ... ${run.stdout.slice(-200)}`);
  }
  assert.ok(answer !== null && typeof answer === "object" && !Array.isArray(answer), `${where} the document is not an object`);
  const doc = answer as Record<string, unknown>;
  if (doc.status === STOP_STATUS) {
    assert.equal(run.code, 128 + SIGNAL_NUMBER[signal], `${where} exit code`);
    if (doc.signal !== undefined) assert.equal(doc.signal, SIGNAL_NUMBER[signal], `${where} the signal named`);
    return { answered: true, answer: doc };
  }
  assert.ok(["complete", "partial", "failed"].includes(String(doc.status)), `${where} an answer with status ${String(doc.status)}`);
  return { answered: false, answer: doc };
}

/** A stand-in program for the child moment: it records its pid (it replaces the shell, so the pid is the program's) and waits. */
export async function standIn(bin: string, name: string, pidFile: string): Promise<void> {
  await stub(bin, name, `echo $$ > '${pidFile}'\nexec sleep 120`);
}

// --- a rerun with a smaller result ---------------------------------------------------------------------------------------------

function snapshot(dir: string): Map<string, Buffer> {
  const files = new Map<string, Buffer>();
  const walk = (d: string, prefix: string): void => {
    let entries;
    try {
      entries = readdirSync(d, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      if (e.isDirectory()) walk(join(d, e.name), `${prefix}${e.name}/`);
      else if (!e.name.startsWith(".")) files.set(prefix + e.name, readFileSync(join(d, e.name)));
    }
  };
  walk(dir, "");
  return files;
}

/**
 * Two runs of one tool in one job $OUT, the second with a smaller result (the caller chooses the arguments so that both name the same
 * file). The first run's files are as they were; the second run's file is under `<stem>-2<suffix>` and the second answer names it.
 */
export async function rerunSmaller(tool: ToolRef, first: unknown, second: unknown, env: Env, opts: { cwd: string; between?: () => Promise<void> | void }): Promise<{ first: Done; second: Done; kept: string[]; added: string[] }> {
  const job = { ...env, ...jobEnv(opts.cwd) };
  const out = job.OUT;
  const one = await runTool(tool, opts.cwd, first, job);
  assert.doesNotMatch(one.stderr, /Traceback/);
  const before = snapshot(out);
  assert.ok(before.size > 0, `the first run wrote no result file under ${out}; the case proves nothing (stdout: ${one.stdout.slice(0, 200)})`);
  await opts.between?.(); // the caller may change the input, so that the second run is smaller under the same name
  const two = await runTool(tool, opts.cwd, second, job);
  assert.doesNotMatch(two.stderr, /Traceback/);
  const after = snapshot(out);
  for (const [name, bytes] of before) {
    assert.ok(after.has(name), `the first run's file ${name} is gone`);
    assert.ok(after.get(name)?.equals(bytes), `the first run's file ${name} was replaced (${bytes.length} bytes before, ${after.get(name)?.length} after)`);
  }
  const added = [...after.keys()].filter((name) => !before.has(name));
  assert.ok(added.length > 0, "the second run wrote no file of its own");
  assert.ok(added.some((name) => /-2\.[A-Za-z0-9]+$/.test(name)), `no new file ends in -2<suffix>: ${added.join(", ")}`);
  for (const name of added) assert.ok(two.stdout.includes(basename(name)), `the second answer does not name ${name}`);
  return { first: one, second: two, kept: [...before.keys()], added };
}

// --- arguments of the wrong type ----------------------------------------------------------------------------------------------------

type Manifest = { params?: Record<string, unknown> };

function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** Each wrong JSON type for a parameter: an array, an object, a string, a boolean, a float, 2**62, a negative number, null, a string with a NUL, one with a lone surrogate. */
export const WRONG_VALUES: unknown[] = [[], [1], {}, { a: 1 }, "x", "", true, false, 1.5, 2 ** 62, -1, 0, null, "a\u0000b", "\ud800", "\udfff"];

/**
 * Up to 1,000 argument sets of the wrong type, the same for the same seed: first the top level (`[]`, `5`, `"x"`, `null`), then each
 * parameter of the manifest as each wrong value (the other parameters are `base`, the valid arguments the caller gives), then random
 * combinations. The seed is printed, so that a failure can be replayed with it.
 */
export function typeConfused(manifest: Manifest, n: number, seed: number, base: Record<string, unknown> = {}): unknown[] {
  assert.ok(Number.isInteger(n) && n >= 1 && n <= 1000, "n is from 1 to 1000");
  console.log(`typeConfused: ${n} sets, seed ${seed}`);
  const sets: unknown[] = [[], 5, "x", null];
  const names = Object.keys(manifest.params ?? {});
  for (const name of names) for (const wrong of WRONG_VALUES) sets.push({ ...base, [name]: wrong });
  const random = mulberry32(seed);
  const pick = <T>(list: T[]): T => list[Math.floor(random() * list.length)] as T;
  while (sets.length < n && names.length > 0) {
    const set: Record<string, unknown> = { ...base };
    const count = 1 + Math.floor(random() * Math.min(3, names.length));
    for (let i = 0; i < count; i++) set[pick(names)] = pick(WRONG_VALUES);
    sets.push(set);
  }
  return sets.slice(0, n);
}

/** One JSON object on stdout with `status` and a non-empty `status_basis`, and no traceback on stderr. */
export function assertJsonAnswer(run: { code: number | null; stdout: string; stderr: string; signal?: NodeJS.Signals | null }, label = ""): Record<string, unknown> {
  const where = label ? ` [${label}]` : "";
  assert.doesNotMatch(run.stderr, /Traceback/, `a traceback on stderr${where}: ${run.stderr.slice(-300)}`);
  assert.ok(!run.signal, `the tool was ended by ${run.signal}${where}`);
  let doc: unknown;
  try {
    doc = JSON.parse(run.stdout);
  } catch {
    assert.fail(`stdout is not one JSON document${where} (exit ${run.code}): ${run.stdout.slice(0, 200)} / stderr ${run.stderr.slice(-200)}`);
  }
  assert.ok(doc !== null && typeof doc === "object" && !Array.isArray(doc), `the answer is not a JSON object${where}`);
  const answer = doc as Record<string, unknown>;
  assert.equal(typeof answer.status, "string", `no status${where}: ${run.stdout.slice(0, 200)}`);
  assert.ok(typeof answer.status_basis === "string" && answer.status_basis.length > 0, `no status_basis${where}: ${run.stdout.slice(0, 200)}`);
  return answer;
}

/** Run every set against the tool (at most 6 at once) and require a JSON answer for each. Returns how many ended with each status. */
export async function fuzzTool(tool: ToolRef, sets: unknown[], seed: number, opts: { cwd: string; env?: Env }): Promise<Record<string, number>> {
  const statuses: Record<string, number> = {};
  let next = 0;
  const worker = async (): Promise<void> => {
    for (;;) {
      const i = next++;
      if (i >= sets.length) return;
      const run = await runTool(tool, opts.cwd, sets[i], opts.env ?? {});
      const label = `seed ${seed}, set ${i}: ${JSON.stringify(sets[i])}`.slice(0, 300);
      const answer = assertJsonAnswer(run, label);
      statuses[String(answer.status)] = (statuses[String(answer.status)] ?? 0) + 1;
    }
  };
  await Promise.all(Array.from({ length: 6 }, worker));
  return statuses;
}

export function manifestOf(tool: ToolRef): Manifest {
  return JSON.parse(readFileSync(join(dirname(scriptOf(tool)), "manifest.json"), "utf8")) as Manifest;
}

export function sizeOf(path: string): number {
  return statSync(path).size;
}
