/**
 * A program a job's worker could not execute, said where the agent reads the
 * job's result.
 *
 * In a worker nothing can run where it stands in store/ (sealTree keeps a
 * sealed file read-only, mode 0444, with no execute bit), in work/extracted/
 * or work/quarantine/ (read-only and no-exec), in inputs/ (no-exec) or in the
 * job's own $OUT and control directory (no-exec). A program supplied to the
 * run (swarm.sh tool-supply), or one unpacked from a supplied package into
 * $OUT, therefore fails there. On a live run (s3472f0) two jobs failed that
 * way, one with "exit 126" and one with "exit 127: a program it runs is not
 * in its image" (the loader's own words for a segment it could not map),
 * before a seat found the way: a copy in an executable temporary directory
 * inside the job.
 *
 * What the reply says depends on where the program stands, because the way
 * is not the same for everything. A supplied program (store/imports/mat-*) is
 * run from a copy. Evidence (inputs/, work/extracted/, work/quarantine/, an
 * evidence import) is read, never run: the contract flags a job that runs code
 * recovered from it and asks for a reimplementation, a trusted program or the
 * operator's word first, so the reply sends the seat to the operator's
 * tool-supply, not to a recipe for running it. Anywhere else (the job's own
 * $OUT, an earlier job's output, no path found) it says both, in that order.
 * And the shell's other reasons for 126 (a file built for another machine, an
 * interpreter that is missing, a directory) are not about where a program
 * stands: the shell's own line is quoted and no copy is suggested.
 *
 * A job that ended non-zero is read, on the shell's and the loader's own
 * words only: the exit status 126 (the shell found the command and could not
 * execute it), with the shell's line that names the program when there is one
 * ("Permission denied", "cannot execute binary file", "bad interpreter", "Is a
 * directory"); the dynamic loader's "failed to map segment from shared
 * object", at any status; and, at another status, a "Permission denied" that
 * names a file which exists under a directory a worker mounts read-only
 * (store/, inputs/, work/extracted/, work/quarantine/), where a write is
 * refused with "Read-only file system" and an existing file that cannot be
 * opened is one that cannot be executed (a program run by a program that
 * reports its own status, a Python subprocess call). A "Permission denied"
 * anywhere else at another status is not read here: nothing in the line tells
 * a program that could not be executed from a file that could not be written
 * (a read-only directory in $OUT), and a denied write is
 * job-write-refused.ts's. One exception, at any status, 0 included: the
 * shell's own "line N: <path>: Permission denied" for an existing file in the
 * job's own $OUT (writable, mounted no-exec), where a script went on after a
 * program it copied there could not run and ended 0 (the run sf4406b), so the
 * job is ok and its reason says what did not run. The job's stdout, its stderr and every stderr file
 * it kept in $OUT are read whole, a line at a time. Generic: no program is
 * named or recognised.
 */
import { lstatSync } from "node:fs";
import { isAbsolute, join, normalize, resolve } from "node:path";
import { DENIED, eachLine, keptStderr, pathIn, within } from "./job-write-refused.ts";

/** The dynamic loader's refusal to map a segment of a program or library from a file system that cannot execute (it says it too when the worker has no memory left to map it). */
export const LOADER_REFUSAL = "failed to map segment from shared object";
/** The shell's other reasons for status 126 (127 for a missing interpreter on Linux), none of them about where a program stands. */
export const FORMAT_REFUSAL = "Exec format error";
export const INTERPRETER_REFUSAL = "bad interpreter";
export const DIRECTORY_REFUSAL = "Is a directory";

export type ExecError = typeof DENIED | typeof LOADER_REFUSAL | typeof FORMAT_REFUSAL | typeof INTERPRETER_REFUSAL | typeof DIRECTORY_REFUSAL;

/** A line said whole in the reply when it is no longer than this; a longer one is named by where it is. */
export const QUOTE_MAX = 2000;

/** What was refused: the first line that says so (or none, when only the exit status does), and how many such lines there are. */
export type ExecRefused = {
  /** What the first line says; null when no line does and the exit status 126 alone is the sign. */
  error: ExecError | null;
  /** The path that line names, resolved, or null when it names none. */
  path: string | null;
  /** Where that line is: `stdout.log`, `stderr.log`, or `out/<path>` for a file the job kept. */
  file: string | null;
  line: number | null;
  /** The line itself, when it is short enough to be said whole. */
  text: string | null;
  /** Every such line, in every file read. */
  lines: number;
  files: number;
};

/** Whether a path is a regular file on this host (the run's directories are the worker's at the same paths). */
const isRegularFile = (p: string): boolean => {
  try {
    return lstatSync(p).isFile();
  } catch {
    return false;
  }
};

/** The directories a worker mounts read-only, where an existing file that cannot be opened is one that cannot be executed. */
const readOnlyPlaces = (cwd: string): string[] => [join(cwd, "store"), join(cwd, "inputs"), join(cwd, "work", "extracted"), join(cwd, "work", "quarantine")];

/** Where a program stands, as far as what the reply should say goes: a supplied program, evidence, or anywhere else. */
export type Place = "supplied" | "evidence" | "other";
export function placeOf(path: string | null, cwd: string): Place {
  if (path === null) return "other";
  if (within(path, join(cwd, "store", "imports"))) {
    // ev-<n> is evidence added after the kickoff; mat-<n> is what the operator supplied.
    const id = path.slice(join(cwd, "store", "imports").length + 1).split("/")[0] ?? "";
    return /^mat-\d+$/.test(id) ? "supplied" : /^ev-\d+$/.test(id) ? "evidence" : "other";
  }
  if (within(path, join(cwd, "inputs")) || within(path, join(cwd, "work", "extracted")) || within(path, join(cwd, "work", "quarantine"))) return "evidence";
  return "other";
}

/**
 * Whether a line says a program could not be executed: the error and the
 * path it names (resolved from `cwd` when relative), or null. `exit` is the
 * job's status: the shell's lines count at 126 (a missing interpreter at 127 too); the loader's refusal at any
 * status; a "Permission denied" at another status only when it names an
 * existing file under a directory a worker mounts read-only (`isFile` says
 * whether a path is one, the host's by default).
 */
export function execRefusedIn(line: string, o: { cwd: string; exit: number | null; isFile?: (path: string) => boolean; noexec?: ReadonlyArray<{ guest: string; host: string }> }): { error: ExecError; path: string | null } | null {
  const resolved = (named: string | null | undefined) => (!named ? null : isAbsolute(named) ? normalize(named) : resolve(o.cwd, named));
  if (line.includes(LOADER_REFUSAL)) {
    // "<program>: error while loading shared libraries: <file it could not map>: failed to map segment from shared object"
    const named = /error while loading shared libraries: (.+?): failed to map segment from shared object/.exec(line)?.[1];
    return { error: LOADER_REFUSAL, path: resolved(named) };
  }
  // A missing interpreter is 126 in bash 3.2 and 127 in bash 5 on Linux (the kernel says ENOENT); the line says "No such file or directory" either way, and at 127 it is no missing program.
  // bash 5.1 and later on Linux say "cannot execute: required file not found" (and 127) for the same.
  if ((o.exit === 126 || o.exit === 127) && (line.includes(INTERPRETER_REFUSAL) || line.includes("cannot execute: required file not found"))) {
    return { error: INTERPRETER_REFUSAL, path: resolved(/(?:^|: )([^\s:]+): [^:]*: bad interpreter/.exec(line)?.[1] ?? /(?:^|: )([^\s:]+): cannot execute: required file not found/.exec(line)?.[1]) };
  }
  if (o.exit === 126) {
    // bash 3.2 says "cannot execute binary file" alone; bash 5 adds ": Exec format error".
    if (line.includes("cannot execute binary file")) return { error: FORMAT_REFUSAL, path: resolved(/(?:^|: )(\S+): cannot execute binary file/.exec(line)?.[1]) };
    // bash 5 on Linux says "Is a directory" (strerror), bash 3.2 says "is a directory".
    if (/is a directory/i.test(line)) return { error: DIRECTORY_REFUSAL, path: resolved(/(?:^|: )([^\s:]+): [Ii]s a directory/.exec(line)?.[1]) };
    if (line.includes(DENIED)) return { error: DENIED, path: resolved(pathIn(line, DENIED)) };
    return null;
  }
  if (line.includes(DENIED)) {
    const path = resolved(pathIn(line, DENIED));
    if (path !== null && readOnlyPlaces(o.cwd).some((d) => within(path, d)) && (o.isFile ?? isRegularFile)(path)) return { error: DENIED, path };
    // The shell's own line for a command it found and could not execute, inside a script that went on ("<script>: line 54: <path>: Permission
    // denied", status 126 for that command and the job's own status whatever came last: the run sf4406b's j000279 printed it 26 times for
    // a supplied program copied into $OUT, and ended 0). Read on a file that exists in the job's own $OUT, which is writable and mounted
    // no-exec, so a denial there is no refused write.
    const shell = /(?:^|: )line \d+: (\/[^:]+): Permission denied\s*$/.exec(line)?.[1];
    const place = shell ? (o.noexec ?? []).find((m) => within(normalize(shell), m.guest)) : undefined;
    if (shell && place) {
      const host = join(place.host, normalize(shell).slice(place.guest.length));
      if ((o.isFile ?? isRegularFile)(host)) return { error: DENIED, path: normalize(shell) };
    }
  }
  return null;
}

/**
 * A program the job could not execute, read from its control directory's
 * stdout.log and stderr.log and the stderr files it kept in `out`, or null.
 * `exit` is the status it ended with: 126 alone is enough (the shell's own
 * status for a command it found and could not execute), and says so when no
 * line names the program (its stderr may have gone into a file of the job's
 * own). `cwd` is where the job started (a relative path is read from there).
 */
export async function execRefused(o: { ctl: string; out: string; cwd: string; exit: number | null; isFile?: (path: string) => boolean; noexec?: ReadonlyArray<{ guest: string; host: string }> }): Promise<ExecRefused | null> {
  const seen: { first: Pick<ExecRefused, "error" | "path" | "file" | "line" | "text"> | null; lines: number; files: Set<string> } = { first: null, lines: 0, files: new Set() };
  const read = async (path: string, name: string) => {
    await eachLine(path, (line, n) => {
      const r = execRefusedIn(line, o);
      if (!r) return;
      seen.lines += 1;
      seen.files.add(name);
      seen.first ??= { ...r, file: name, line: n, text: line.trim().length <= QUOTE_MAX ? line.trim() : null };
    });
  };
  await read(join(o.ctl, "stdout.log"), "stdout.log");
  await read(join(o.ctl, "stderr.log"), "stderr.log");
  for (const rel of await keptStderr(o.out)) await read(join(o.out, rel), `out/${rel}`);
  if (seen.first) return { ...seen.first, lines: seen.lines, files: seen.files.size };
  return o.exit === 126 ? { error: null, path: null, file: null, line: null, text: null, lines: 0, files: 0 } : null;
}

/** What to do, by where the program stands. */
function wayOn(place: Place, out: string): string {
  const copy = `copy the program, and every library it loads, into an executable temporary directory inside the job (for example one made with mktemp -d under /tmp), make it executable there and run it from that copy; what it writes that you want kept goes to $OUT (${out})`;
  if (place === "supplied") {
    return `Nothing a worker holds in store/ can be executed where it stands: sealed files have no execute bit. This is a program the operator supplied, so ${copy}`;
  }
  if (place === "evidence") {
    return "Nothing a worker holds in inputs/, work/extracted/ or work/quarantine/ can be executed where it stands, and nothing there is to be: evidence is read, never run, and a job that runs code recovered from it is flagged. For a program you trust, ask the operator to supply one (swarm.sh tool-supply); otherwise reimplement the step as a read of the bytes";
  }
  return `Nothing a worker holds in store/, work/extracted/, work/quarantine/, inputs/ or its own $OUT can be executed where it stands: sealed files have no execute bit and the others are mounted no-exec. Evidence is read, never run, and code recovered from it (an extraction, a job's output) is not run in a job: ask the operator to supply a program you trust (swarm.sh tool-supply), or reimplement the step. A program the operator supplied (import:mat-<n>), or unpacked from one, is run from a copy: ${copy}`;
}

/**
 * What the agent is told, whole: what could not be executed and where it
 * says so (as the store will hold it), and, by where the program stands, what
 * to do. The shell's other reasons for 126 are quoted and no copy is
 * suggested for them.
 */
export function execRefusedWords(x: ExecRefused, o: { job: string; out: string; cwd: string }): string {
  const where = x.file === null ? "" : x.file.startsWith("out/") ? `job:${o.job}/${x.file.slice(4)}` : `store/jobs/${o.job}/${x.file}`;
  const more = x.lines > 1 ? `; ${x.lines} such lines in ${x.files === 1 ? "that file" : `${x.files} files`}` : "";
  if (x.error === null || x.file === null) {
    return `a program it ran could not be executed: exit 126 is the shell's status for a command it found and could not run (no right to execute it, a file built for another machine, an interpreter that is missing, a directory), and no line in stdout.log, stderr.log or a stderr file the job kept says which (if the program's stderr went into a file of the job's own, it is there). ${wayOn("other", o.out)}`;
  }
  if (x.error === FORMAT_REFUSAL || x.error === INTERPRETER_REFUSAL || x.error === DIRECTORY_REFUSAL) {
    const said = x.text === null ? `${x.error}${x.path ? ` on ${x.path}` : ""}` : `the shell says "${x.text}"`;
    const what =
      x.error === FORMAT_REFUSAL
        ? "the file is not a program this worker's CPU can run (built for another architecture, or not a program at all): compare what it is built for with what the worker is (uname -m)"
        : x.error === INTERPRETER_REFUSAL
          ? "the interpreter named on its first line (or, for a compiled program, its dynamic loader) is not in the worker, or that line ends in a carriage return (a file written on Windows): read its first line"
          : "a directory was named where a program was meant: name the file inside it";
    return `a program it ran could not be executed (${said}, ${where} line ${x.line}${more}). That is not a matter of where it stands, and copying it elsewhere will not change it: ${what}`;
  }
  const quoted = `"${x.error}"${x.path ? ` on ${x.path}` : ""}`;
  const head = `a program it ran could not be executed (${quoted}, ${where} line ${x.line}${more})`;
  const loader = x.error === LOADER_REFUSAL ? ". The loader says this when the file system forbids executing the file, and also when the worker had no memory left to map it" : "";
  return `${head}${loader}. ${wayOn(placeOf(x.path, o.cwd), o.out)}`;
}
