/**
 * Shared helpers of the memory-forensics fix suites (tests/pack-memory-f1-*.test.ts): a signal-sending runner, a stub MemProcFS whose tree
 * the test lays out, and random secret-shaped canaries built from pieces (no literal of a real-looking secret is in the repository).
 */
import { spawn } from "node:child_process";
import { chmod, mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { ROOT } from "./tool-library-harness.ts";

/** MEM_TOOLS_DIR points the suites at another copy of the tools (a checkout of main, to show a case fails there). */
export const MEM = process.env.MEM_TOOLS_DIR ?? join(ROOT, "packs", "memory-forensics", "tools");
export const CARVE = join(MEM, "mem_carve", "run.py");
export const PROFILE = join(MEM, "mem_profile", "run.py");
export const FS = join(MEM, "mem_fs", "run.py");

export type Run = { code: number | null; signal: string | null; stdout: string; stderr: string; ms: number };

/** Run a tool, send it `signal` after `afterMs` (when given), and collect everything. */
export function runTool(script: string, cwd: string, args: unknown, env: Record<string, string> = {}, bin?: string, signal?: NodeJS.Signals, afterMs = 0): Promise<Run> {
  const e: NodeJS.ProcessEnv = { AGENT_ID: "s1", ...process.env, ...env };
  delete e.JOB_ID; delete e.OUT; delete e.SECRET_OUTPUT;
  Object.assign(e, { AGENT_ID: "s1" }, env);
  if (bin) e.PATH = `${bin}:${e.PATH ?? ""}`;
  const t0 = Date.now();
  return new Promise((resolve, reject) => {
    const child = spawn("python3", [script], { cwd, env: e });
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => out.push(c));
    child.stderr.on("data", (c: Buffer) => err.push(c));
    child.on("error", reject);
    child.on("close", (code, sig) => resolve({ code, signal: sig, stdout: Buffer.concat(out).toString("utf8"), stderr: Buffer.concat(err).toString("utf8"), ms: Date.now() - t0 }));
    child.stdin.end(JSON.stringify(args));
    if (signal) setTimeout(() => { try { child.kill(signal); } catch { /* gone already */ } }, afterMs);
  });
}

export const json = <T = Record<string, any>>(run: Run): T => {
  if (run.stderr.includes("Traceback")) throw new Error(`traceback: ${run.stderr}`);
  return JSON.parse(run.stdout) as T;
};

/** A seeded generator, so a canary run is the same every time. */
export function rng(seed: number): () => number {
  let s = seed >>> 0;
  return () => {
    s = (s + 0x6d2b79f5) >>> 0;
    let t = s;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const B62 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const pick = (r: () => number, alphabet: string, n: number): string => Array.from({ length: n }, () => alphabet[Math.floor(r() * alphabet.length)]).join("");
const b64 = (r: () => number, bytes: number): string => Buffer.from(Array.from({ length: bytes }, () => Math.floor(r() * 256))).toString("base64");

/** Realistic secret shapes, each assembled from pieces at run time. The value is the whole secret. */
export const SHAPES: Record<string, (r: () => number) => string> = {
  aws_key: (r) => "AK" + "IA" + pick(r, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 16),
  ghp: (r) => "gh" + "p_" + pick(r, B62, 36),
  github_pat: (r) => "github" + "_pat_" + pick(r, B62 + "_", 59),
  slack: (r) => "xo" + "xb-" + pick(r, "0123456789", 12) + "-" + pick(r, "0123456789", 13) + "-" + pick(r, B62, 24),
  stripe: (r) => "sk_" + "live_" + pick(r, B62, 24),
  glpat: (r) => "gl" + "pat-" + pick(r, B62 + "_-", 20),
  b64_16: (r) => b64(r, 16),
  b64_20: (r) => b64(r, 20),
  b64_32: (r) => b64(r, 32),
  aws_secret40: (r) => pick(r, B62 + "/+", 40),
  jwt: (r) => ["eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", b64(r, 24).replace(/[+/=]/g, "x"), b64(r, 32).replace(/[+/=]/g, "y")].join("."),
  hex40: (r) => pick(r, "0123456789abcdef", 40),
  userinfo: (r) => "adm" + "in:" + pick(r, B62, 10) + "@10.0.0.5",
};
/** A twelve-character password alone in a name: not recognised, by design (below the 16-character floor). */
export const PWD12 = (r: () => number): string => pick(r, B62 + "!#%", 12);

export type StubOptions = {
  /** files and directories of the mounted tree: a path ending in "/" is a directory; the value is the file's content */
  tree: Record<string, string | Buffer>;
  mode?: "" | "exit" | "never";
  links?: [string, string][];
  /** text the stub writes to its stderr */
  stderrText?: string;
  /** a file the stub writes its pid to */
  pidFile?: string;
  /** bytes of text the stub writes to each of its stdout and stderr */
  flood?: number;
};

/** A stub `memprocfs` on PATH that makes the directory a mount would have made (see tests/pack-memory-forensics.test.ts), and the env it needs. */
export async function fsStub(cwd: string, bin: string, o: StubOptions): Promise<Record<string, string>> {
  const tree = join(cwd, "stubtree2");
  for (const [rel, content] of Object.entries(o.tree)) {
    if (rel.endsWith("/")) { await mkdir(join(tree, rel), { recursive: true }); continue; }
    await mkdir(join(tree, rel, ".."), { recursive: true });
    await writeFile(join(tree, rel), content);
  }
  await mkdir(join(tree, "sys"), { recursive: true });
  const log = join(cwd, "stub2-started.log");
  await writeFile(
    join(bin, "memprocfs"),
    `#!/usr/bin/env python3
import json, os, shutil, signal, sys, time
args = sys.argv[1:]
mount = args[args.index("-mount") + 1]
with open(os.environ["STUB_LOG"], "a") as f:
    f.write("started " + " ".join(args) + "\\n")
if os.environ.get("STUB_PID"):
    open(os.environ["STUB_PID"], "w").write(str(os.getpid()))
print("stub memprocfs: initialising")
if os.environ.get("STUB_STDERR"):
    print(os.environ["STUB_STDERR"], file=sys.stderr, flush=True)
if os.environ.get("STUB_FLOOD"):
    line = ("x" * 1023 + "\\n").encode()
    for _ in range(int(os.environ["STUB_FLOOD"]) // 1024):
        sys.stdout.buffer.write(line)
        sys.stderr.buffer.write(line)
    sys.stdout.buffer.flush()
    sys.stderr.buffer.flush()
sys.stdout.flush()
if os.environ.get("STUB_MODE") == "exit":
    sys.exit(3)
def clear():
    for name in os.listdir(mount):
        p = os.path.join(mount, name)
        shutil.rmtree(p) if os.path.isdir(p) and not os.path.islink(p) else os.unlink(p)
def bye(*_):
    clear()
    sys.exit(0)
signal.signal(signal.SIGTERM, bye)
if os.environ.get("STUB_MODE") != "never":
    tree = os.environ["STUB_TREE"]
    for name in sorted(os.listdir(tree), key=lambda n: n == "sys"):
        if name == "sys":
            for link, target in json.loads(os.environ.get("STUB_LINKS", "[]")):
                os.symlink(target.replace("{mount}", mount), os.path.join(mount, link))
        src, dst = os.path.join(tree, name), os.path.join(mount, name)
        shutil.copytree(src, dst, symlinks=True) if os.path.isdir(src) else shutil.copy(src, dst)
while True:
    time.sleep(0.05)
`,
  );
  await chmod(join(bin, "memprocfs"), 0o755);
  const shim = join(cwd, "mountshim2");
  await mkdir(shim, { recursive: true });
  await writeFile(join(shim, "sitecustomize.py"), "import os, os.path\nos.path.ismount = lambda p: os.path.isdir(os.path.join(p, 'sys'))\n");
  return {
    PYTHONPATH: shim, STUB_TREE: tree, STUB_LOG: log, STUB_MODE: o.mode ?? "", STUB_LINKS: JSON.stringify(o.links ?? []),
    STUB_STDERR: o.stderrText ?? "", ...(o.pidFile ? { STUB_PID: o.pidFile } : {}), ...(o.flood ? { STUB_FLOOD: String(o.flood) } : {}),
  };
}

/**
 * A directory for PYTHONPATH whose sitecustomize.py makes time.monotonic() move by FAKE_CLOCK_STEP seconds on every call (the clock a
 * tool reads is then a count of looks at it, not of seconds), and makes os.path.getsize() report FAKE_GETSIZE_EXTRA more bytes for a
 * path ending in FAKE_GETSIZE_SUFFIX (a file that ends before the size it was measured at), and sets RLIMIT_FSIZE to FAKE_FSIZE bytes
 * for a process that runs a tool (a write past it is a short write and then EFBIG: a disk that fills), and with FAKE_ISMOUNT makes a directory
 * with a sys/ inside it a mount point (the stub engine's tree). Nothing happens without those variables.
 */
export async function shimDir(cwd: string): Promise<string> {
  const dir = join(cwd, "shim-f2");
  await mkdir(dir, { recursive: true });
  await writeFile(join(dir, "sitecustomize.py"), `import os, sys, time
_step = float(os.environ.get("FAKE_CLOCK_STEP", "0") or 0)
if _step:
    _now = [0.0]
    def _mono():
        _now[0] += _step
        return _now[0]
    time.monotonic = _mono
_extra = int(os.environ.get("FAKE_GETSIZE_EXTRA", "0") or 0)
if _extra:
    _getsize = os.path.getsize
    _suffix = os.environ.get("FAKE_GETSIZE_SUFFIX", "")
    def _fake(p):
        n = _getsize(p)
        return n + _extra if str(p).endswith(_suffix) else n
    os.path.getsize = _fake
_fsize = int(os.environ.get("FAKE_FSIZE", "0") or 0)
if _fsize and sys.argv:
    import resource
    _hard = resource.getrlimit(resource.RLIMIT_FSIZE)[1]
    # the tool is limited; the stub engine it starts (which inherits the limit) is not
    resource.setrlimit(resource.RLIMIT_FSIZE, (_fsize if sys.argv[0].endswith("run.py") else _hard, _hard))
if os.environ.get("FAKE_ISMOUNT"):
    os.path.ismount = lambda p: os.path.isdir(os.path.join(p, "sys"))
`);
  return dir;
}
