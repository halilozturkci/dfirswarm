/**
 * Helpers the network-forensics process-sweep suites share: running a tool the way the harness starts one (a process group of its own) on a Linux host or one
 * that is not (sys.platform patched, or PR_SET_CHILD_SUBREAPER refused), the abandoned children a stand-in program leaves (a shell function and a script, and a
 * Python function for the stand-ins written in Python), and what a run leaves under the working directory.
 */
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

export const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));
export const alive = (pid: number): boolean => {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
};

// ---- running a tool the way the harness starts one, on a Linux host or one that is not ---------------------------------------------------------------

export const PRELUDE = `
import sys, os, subprocess, selectors, ctypes, json, re, time, hashlib, shutil, signal, stat, errno, functools, runpy, select, tempfile, collections, calendar, datetime, resource, pathlib
script = sys.argv[1]
sys.argv = sys.argv[1:]
`;
export const DARWIN = `${PRELUDE}
sys.platform = "darwin"
runpy.run_path(script, run_name="__main__")
`;
export const REFUSED = `${PRELUDE}
class Refusing(object):
    def prctl(self, *a):
        return -1
ctypes.CDLL = lambda *a, **k: Refusing()
runpy.run_path(script, run_name="__main__")
`;
export type Host = "linux" | "darwin" | "refused";
export const WRAPPERS: Record<Host, string | undefined> = { linux: undefined, darwin: DARWIN, refused: REFUSED };
export type Run = { code: number | null; stdout: string; stderr: string };

export function exec(script: string, argv: string[], stdin: unknown, cwd: string, bin: string, env: Record<string, string>, host: Host): Promise<Run> {
  return new Promise((resolve, reject) => {
    const wrapper = WRAPPERS[host];
    const args = wrapper ? ["-c", wrapper, script, ...argv] : [script, ...argv];
    const child = spawn("python3", args, { cwd, env: { ...process.env, PATH: `${bin}:${process.env.PATH ?? ""}`, AGENT_ID: "s1", ...env }, detached: true });
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => out.push(c));
    child.stderr.on("data", (c: Buffer) => err.push(c));
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stdout: Buffer.concat(out).toString("utf8"), stderr: Buffer.concat(err).toString("utf8") }));
    child.stdin.on("error", () => undefined);
    child.stdin.end(stdin === undefined ? "" : JSON.stringify(stdin));
  });
}

// ---- the leftover: one shell function and one script, used by every stand-in ------------------------------------------------------------------------

export const LEAVE_SH = `
leave() {
  [ -n "$STUB_LEFT" ] || return 0
  t="$1"
  n0=$(cat "$STUB_DIR/left.pids" 2>/dev/null | wc -l)
  case "$STUB_LEFT" in
    plain)    STUB_LMODE=append "$STUB_DIR/leftover.sh" "$t" & ;;
    stdout)   STUB_LMODE=stdout "$STUB_DIR/leftover.sh" "$t" & ;;
    setsid)   STUB_LMODE=append setsid "$STUB_DIR/leftover.sh" "$t" </dev/null >/dev/null 2>&1 & ;;
    double)   ( STUB_LMODE=append setsid "$STUB_DIR/leftover.sh" "$t" </dev/null >/dev/null 2>&1 & ) ;;
    rewrite)  STUB_LMODE=rewrite setsid "$STUB_DIR/leftover.sh" "$t" </dev/null >/dev/null 2>&1 & ;;
    periodic) STUB_LMODE=periodic setsid "$STUB_DIR/leftover.sh" "$t" </dev/null >/dev/null 2>&1 & ;;
    # what a program may leave on the pipes a tool reads (PKG-P6): a sleeper that holds every descriptor the program had, a slow writer on the program's standard output, and a holder of the standard input only
    sleeper)  sleep 600 & echo $! >> "$STUB_DIR/left.pids" ;;
    slow)     ( while :; do printf x; sleep 0.2; done ) & echo $! >> "$STUB_DIR/left.pids" ;;
    stdin)    sleep 600 >/dev/null 2>&1 & echo $! >> "$STUB_DIR/left.pids" ;;
    # full-speed writers: a leftover that floods a pipe dies of SIGPIPE the moment the tool closes its end, so the tool must look for it before it closes the pipes
    fast)     ( while :; do printf x; sleep 0.001; done ) & echo $! >> "$STUB_DIR/left.pids" ;;
    yes)      ( exec yes y ) & echo $! >> "$STUB_DIR/left.pids" ;;
    errflood) ( exec yes e >&2 ) & echo $! >> "$STUB_DIR/left.pids" ;;
  esac
  # the program does not end before the leftover has started and written its pid (the tool settles the moment the program is gone)
  i=0
  while [ "$i" -lt 100 ]; do
    [ "$(cat "$STUB_DIR/left.pids" 2>/dev/null | wc -l)" -gt "$n0" ] && break
    sleep 0.02; i=$((i + 1))
  done
}
`;
export const LEFTOVER_SH = `#!/bin/sh
echo $$ >> "$STUB_DIR/left.pids"
t="$1"
# STUB_LSLEEP: how long the leftover lives before it writes (a program whose pipes the tool reads needs one that outlives the pipe grace)
case "$STUB_LMODE" in
  stdout) sleep "\${STUB_LSLEEP:-1}"; echo late-stdout;;
  rewrite) sleep "\${STUB_LSLEEP:-1}"; : > "$t"; echo rewritten >> "$t";;
  periodic) while :; do echo tick >> "$t"; sleep 0.1; done;;
  *) sleep "\${STUB_LSLEEP:-1}"; echo late >> "$t";;
esac
`;
export const VARIANTS = ["plain", "stdout", "setsid", "double", "rewrite", "periodic"];
export const FEW = ["stdout", "setsid"];
/** The leftovers that probe a reader of a pipe: none of them ever ends by itself. */
/** The same without the floods, for a tool whose program writes its standard output to a file the tool then reads whole (a flood of gigabytes in that file is the program's own output, read at the speed of the log parser, not a pipe held). */
export const FILE_HOLDERS = ["sleeper", "slow", "stdin", "fast"];
export const HOLDERS = ["sleeper", "slow", "stdin", "fast", "yes", "errflood"];

export async function stubDir(cwd: string): Promise<string> {
  const dir = join(cwd, "stub");
  await mkdir(dir, { recursive: true });
  await writeFile(join(dir, "leftover.sh"), LEFTOVER_SH, { mode: 0o755 });
  return dir;
}
export const sh = (body: string): string => `#!/bin/sh\n${LEAVE_SH}\n${body}`;

// ---- what a run leaves under the working directory ---------------------------------------------------------------------------------------------

export async function snapshot(cwd: string): Promise<Record<string, string>> {
  const out: Record<string, string> = {};
  const walk = async (d: string, rel: string): Promise<void> => {
    for (const e of await readdir(d, { withFileTypes: true }).catch(() => [])) {
      const r = rel ? `${rel}/${e.name}` : e.name;
      if (rel === "" && (e.name === "stub" || e.name === "bin")) continue;
      if (e.isDirectory()) await walk(join(d, e.name), r);
      else if (e.isFile()) out[r] = createHash("sha256").update(await readFile(join(d, e.name)).catch(() => Buffer.alloc(0))).digest("hex");
    }
  };
  await walk(cwd, "");
  return out;
}
export async function pids(cwd: string): Promise<number[]> {
  return (await readFile(join(cwd, "stub", "left.pids"), "utf8").catch(() => "")).split(/\s+/).filter(Boolean).map(Number);
}
export async function reap(cwd: string): Promise<void> {
  for (const pid of await pids(cwd)) if (alive(pid)) process.kill(pid, "SIGKILL");
}


/** For a stand-in written in Python: `leave_behind(d, variant, target)` forks the leftover and returns when it has started and written its pid to d/left.pids. Variants: stderr (holds the
 * program's stderr and writes to it), plain (writes to `target` by name, no descriptor), setsid, double. The child closes every other descriptor, the pipe the tool reads included. */
export const PY_LEAVE = `
def leave_behind(d, variant, target):
    r, w = os.pipe()
    if os.fork() != 0:
        os.close(w)
        os.read(r, 1)
        os.close(r)
        return
    os.close(r)
    if variant == "double":
        if os.fork() != 0:
            os._exit(0)
    if variant in ("setsid", "double"):
        os.setsid()
    open(os.path.join(d, "left.pids"), "a").write("%d\\n" % os.getpid())
    keep = (2, w) if variant == "stderr" else (w,)
    for fd in range(0, 256):
        if fd not in keep:
            try:
                os.close(fd)
            except OSError:
                pass
    os.write(w, b"1")
    os.close(w)
    time.sleep(1.0)
    if variant == "stderr":
        os.write(2, b"late-stderr\\n")
    else:
        open(target, "ab").write(b"late\\n")
    os._exit(0)
`;
