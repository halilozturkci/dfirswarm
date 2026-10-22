/**
 * Shared helpers for the macos-forensics suites that test the four tools as a job runs them: builders for the formats the tools read (FSEvents
 * pages, a knowledgeC-shaped database, a property list, a stand-in unified log reader) written from the formats' layouts and never from a tool's
 * output, a runner that can signal a tool and measure its CPU and memory, and a reader of every file a run left behind.
 */
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import { ROOT, runPy, runPySnippet } from "./tool-library-harness.ts";

export const MAC = join(ROOT, "packs", "macos-forensics", "tools");
export const PLIST = join(MAC, "plist_read", "run.py");
export const FS = join(MAC, "fsevents_parse", "run.py");
export const KC = join(MAC, "knowledgec_query", "run.py");
export const UL = join(MAC, "unified_log", "run.py");
export const TOOLS = { plist_read: PLIST, fsevents_parse: FS, knowledgec_query: KC, unified_log: UL } as const;
export const PYTHON = spawnSync("python3", ["-c", "import sys; print(sys.executable)"], { encoding: "utf8" }).stdout.trim();

export type Run = { code: number | null; stdout: string; stderr: string };
export type Json = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

const AGENT = { AGENT_ID: "s1" };

/** The tool as an agent runs it (no job). */
export function tool(script: string, cwd: string, args: unknown, env: Record<string, string> = {}, bin?: string): Promise<Run> {
  return runPy(script, cwd, args, bin, { ...AGENT, ...env });
}

/** As a job that the harness runs as secret output: JOB_ID, OUT inside the run directory, SECRET_OUTPUT=1. */
export async function secretJob(script: string, cwd: string, args: unknown, env: Record<string, string> = {}, bin?: string): Promise<Run> {
  await mkdir(join(cwd, "out"), { recursive: true });
  return tool(script, cwd, args, { JOB_ID: "j-1", OUT: join(cwd, "out"), SECRET_OUTPUT: "1", ...env }, bin);
}

/** As a job that is not secret output. */
export async function plainJob(script: string, cwd: string, args: unknown, env: Record<string, string> = {}, bin?: string): Promise<Run> {
  await mkdir(join(cwd, "out"), { recursive: true });
  return tool(script, cwd, args, { JOB_ID: "j-1", OUT: join(cwd, "out"), ...env }, bin);
}

export function body(out: Run): Json {
  assert.doesNotMatch(out.stderr, /Traceback/, out.stderr);
  return JSON.parse(out.stdout) as Json;
}

export function ok(out: Run): Json {
  assert.equal(out.code, 0, out.stderr + out.stdout);
  return body(out);
}

/** Every file under a directory, recursively. */
export async function filesUnder(dir: string): Promise<string[]> {
  const found: string[] = [];
  for (const entry of await readdir(dir, { withFileTypes: true }).catch(() => [])) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) found.push(...(await filesUnder(full)));
    else found.push(full);
  }
  return found;
}

/** The text of every file a run could have written that an agent could read, apart from the evidence and the files named in `skip`. */
export async function reachable(cwd: string, skip: (path: string) => boolean = () => false): Promise<string[]> {
  const out: string[] = [];
  for (const dir of ["work", "out"]) {
    for (const file of await filesUnder(join(cwd, dir))) {
      if (file.includes("/evidence/") || skip(file)) continue;
      out.push((await readFile(file)).toString("utf8"));
    }
  }
  return out;
}

// ---- FSEvents -------------------------------------------------------------------------------------------------------------------------------

export const CREATED = 0x01000000;
export const REMOVED = 0x02000000;
export const FILE_EVENT = 0x00008000;

export function fsRecord(path: string | Buffer, id: bigint, flags: number, node?: bigint): Buffer {
  const fixed = Buffer.alloc(node === undefined ? 12 : 20);
  fixed.writeBigUInt64LE(id, 0);
  fixed.writeUInt32LE(flags >>> 0, 8);
  if (node !== undefined) fixed.writeBigUInt64LE(node, 12);
  return Buffer.concat([typeof path === "string" ? Buffer.from(path, "utf8") : path, Buffer.from([0]), fixed]);
}

/** A page: the 12-byte header (magic, four unknown bytes, the length as u32 little-endian), then the records. */
export function fsPage(magic: string, records: Buffer[]): Buffer {
  const content = Buffer.concat(records);
  const header = Buffer.alloc(12);
  header.write(magic, 0, "latin1");
  header.writeUInt32LE(12 + content.length, 8);
  return Buffer.concat([header, content]);
}

export const gz = (data: Buffer): Buffer => gzipSync(data);

export async function fsDir(cwd: string, name: string, files: Record<string, Buffer>): Promise<string> {
  const dir = join(cwd, "work", name);
  await mkdir(dir, { recursive: true });
  for (const [file, bytes] of Object.entries(files)) await writeFile(join(dir, file), bytes);
  return `work/${name}`;
}

// ---- knowledgeC -----------------------------------------------------------------------------------------------------------------------------

/**
 * A knowledgeC-shaped database (Apple's CoreData names: ZOBJECT with its foreign keys to ZSTRUCTUREDMETADATA and ZSOURCE), built by SQLite itself.
 * argv: path, rows, mode; stdin: {names: the extra TEXT columns of ZOBJECT (a count or a list), over: {z_pk: {column: value}}}.
 */
export const KC_BUILD = `
import json, os, sqlite3, sys
path, rows = sys.argv[1], int(sys.argv[2])
spec = json.load(sys.stdin)        # the column names and the overrides come on stdin: a spec can pass the 131,072 bytes one argument may hold
names_extra = spec["names"] if isinstance(spec["names"], list) else ["ZX%d" % i for i in range(spec["names"])]
extra = len(names_extra)
over = spec["over"]
mode = sys.argv[3]
con = sqlite3.connect(path)
if mode == "wal":
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA wal_autocheckpoint=0")
def q(name):
    return '"' + name.replace('"', '""') + '"'
cols = "".join(", %s TEXT" % q(n) for n in names_extra)
con.execute("CREATE TABLE ZOBJECT (Z_PK INTEGER PRIMARY KEY, ZSTREAMNAME VARCHAR, ZVALUESTRING VARCHAR, ZVALUEINTEGER INTEGER, ZVALUEDOUBLE FLOAT, ZVALUETYPECODE INTEGER, ZSTARTDATE TIMESTAMP, ZENDDATE TIMESTAMP, ZCREATIONDATE TIMESTAMP, ZSECONDSFROMGMT INTEGER, ZUUID BLOB, ZSTRUCTUREDMETADATA INTEGER, ZSOURCE INTEGER%s)" % cols)
con.execute("CREATE TABLE ZSTRUCTUREDMETADATA (Z_PK INTEGER PRIMARY KEY, Z_DKSAFARIHISTORYMETADATAKEY__TITLE VARCHAR, Z_DKSAFARIHISTORYMETADATAKEY__URL VARCHAR, ZBLOBCOL BLOB)")
con.execute("CREATE TABLE ZSOURCE (Z_PK INTEGER PRIMARY KEY, ZBUNDLEID VARCHAR, ZDEVICEID VARCHAR)")
for i in range(1, 20):
    con.execute("INSERT INTO ZSOURCE VALUES (?, ?, ?)", (i, "com.example.app%d" % i, "DEVICE-%04d" % i))
for i in range(1, 50):
    con.execute("INSERT INTO ZSTRUCTUREDMETADATA VALUES (?, ?, ?, NULL)", (i, "Title %d" % i, "https://example.com/page%d" % i))
streams = ["/app/inFocus", "/app/usage", "/display/isBacklit", "/device/isLocked", "/safari/history"]
batch = []
for i in range(1, rows + 1):
    start = 700000000.0 + i * 5
    row = [i, streams[i % 5], ("com.example.app%d" % (i % 19)) if i % 3 else None, i % 2, None, 1, start, start + 3.5, start + 4, 3600, bytes([i % 256]) * 16, 1 + i % 49, 1 + i % 19] + ["v%d" % i for _ in range(extra)]
    for column, value in over.get(str(i), {}).items():
        names = ["Z_PK", "ZSTREAMNAME", "ZVALUESTRING", "ZVALUEINTEGER", "ZVALUEDOUBLE", "ZVALUETYPECODE", "ZSTARTDATE", "ZENDDATE", "ZCREATIONDATE", "ZSECONDSFROMGMT", "ZUUID", "ZSTRUCTUREDMETADATA", "ZSOURCE"] + names_extra
        row[names.index(column)] = bytes.fromhex(value["hex"]) if isinstance(value, dict) else value
    batch.append(tuple(row))
    if len(batch) >= 5000:
        con.executemany("INSERT INTO ZOBJECT VALUES (%s)" % ",".join("?" * (13 + extra)), batch)
        batch = []
if batch:
    con.executemany("INSERT INTO ZOBJECT VALUES (%s)" % ",".join("?" * (13 + extra)), batch)
con.commit()
if mode == "wal":
    # a row that exists only in the write-ahead log: committed, never checkpointed; the live files are copied out whole
    con.execute("INSERT INTO ZOBJECT (Z_PK, ZSTREAMNAME, ZVALUESTRING, ZSTARTDATE) VALUES (?, ?, ?, ?)", (rows + 1, "/wal-only", "only-in-wal", 700000001.5))
    con.commit()
    import shutil
    shutil.copy(path, path + ".copy")
    shutil.copy(path + "-wal", path + ".copy-wal")
    con.close()
    for suffix in ("", "-wal", "-shm"):
        try:
            os.unlink(path + suffix)
        except OSError:
            pass
    os.rename(path + ".copy", path)
    os.rename(path + ".copy-wal", path + "-wal")
else:
    con.close()
`;

export async function kcDb(cwd: string, name: string, rows: number, extra: number | string[] = 0, over: Record<string, Record<string, unknown>> = {}, mode: "plain" | "wal" = "plain"): Promise<string> {
  const path = join(cwd, "work", name);
  const out = await runPySnippet(KC_BUILD, [path, String(rows), mode], { names: extra, over });
  assert.equal(out.code, 0, out.stderr);
  return `work/${name}`;
}

// ---- unified log ----------------------------------------------------------------------------------------------------------------------------

/**
 * A stand-in for the iterator on a PATH that holds nothing else (a Mac's own /usr/bin/log would be chosen first). `script` is Python run with the
 * iterator's arguments in `a`, `out` the --output file and `inp` the --input directory.
 */
export async function ulStandin(cwd: string, script: string): Promise<string> {
  const bin = join(cwd, "ulbin");
  await mkdir(bin, { recursive: true });
  const { symlink } = await import("node:fs/promises");
  await symlink(PYTHON, join(bin, "python3")).catch(() => undefined);
  const file = join(bin, "unifiedlog_iterator");
  await writeFile(file, `#!${PYTHON}
import json, os, sys, time
a = sys.argv[1:]
if "--version" in a:
    print("unifiedlog_iterator 9.9.9-test")
    sys.exit(0)
out = a[a.index("--output") + 1]
inp = a[a.index("--input") + 1]
${script}
`);
  const { chmod } = await import("node:fs/promises");
  await chmod(file, 0o755);
  return bin;
}

export async function logarchive(cwd: string, name = "x.logarchive"): Promise<string> {
  const dir = join(cwd, "work", name);
  await mkdir(join(dir, "timesync"), { recursive: true });
  await writeFile(join(dir, "timesync", "0000.timesync"), "");
  return `work/${name}`;
}

/** A copy of /private/var/db: diagnostics and uuidtext side by side. */
export async function dbCopy(cwd: string, extraFiles = 0, size = 1): Promise<string> {
  const root = join(cwd, "work", "vardb");
  await mkdir(join(root, "diagnostics", "timesync"), { recursive: true });
  await mkdir(join(root, "uuidtext", "0A"), { recursive: true });
  await writeFile(join(root, "diagnostics", "timesync", "0000.timesync"), "t");
  await writeFile(join(root, "uuidtext", "0A", "B"), "u");
  for (let i = 0; i < extraFiles; i++) await writeFile(join(root, "uuidtext", "0A", "F" + i), Buffer.alloc(size, 1));
  return "work/vardb";
}

export function ul(cwd: string, bin: string, args: Record<string, unknown>, env: Record<string, string> = {}, job = false): Promise<Run> {
  return runPy(UL, cwd, args, undefined, { ...AGENT, PATH: bin, ...env, ...(job ? { JOB_ID: "j-1", OUT: join(cwd, "out"), SECRET_OUTPUT: "1" } : {}) });
}

// ---- running a tool under a signal, with a measured cost --------------------------------------------------------------------------------------

/**
 * Runs the tool, waits until `ready()` is true (polled), sends it `signal`, and returns what it printed and how it ended. A tool that never reaches
 * the state ends the test after `limitMs`.
 */
export async function runAndSignal(script: string, cwd: string, args: unknown, signal: NodeJS.Signals, ready: () => Promise<boolean>, env: Record<string, string> = {}, bin?: string, limitMs = 60_000): Promise<Run & { signalled: boolean; signal: string | null }> {
  const child = spawn("python3", [script], { cwd, env: { ...process.env, ...AGENT, ...env, ...(bin ? { PATH: bin } : {}) } });
  const so: Buffer[] = [];
  const se: Buffer[] = [];
  child.stdout.on("data", (c: Buffer) => so.push(c));
  child.stderr.on("data", (c: Buffer) => se.push(c));
  const closed = new Promise<{ code: number | null; signal: string | null }>((resolve) => child.on("close", (code, sig) => resolve({ code, signal: sig })));
  child.stdin.on("error", () => undefined);
  child.stdin.end(JSON.stringify(args));
  let signalled = false;
  const started = Date.now();
  while (!signalled && Date.now() - started < limitMs) {
    if (child.exitCode !== null) break;
    if (await ready().catch(() => false)) {
      child.kill(signal);
      signalled = true;
      break;
    }
    await new Promise((r) => setTimeout(r, 15));
  }
  if (!signalled) child.kill("SIGKILL");
  const end = await closed;
  return { code: end.code, signal: end.signal, signalled, stdout: Buffer.concat(so).toString("utf8"), stderr: Buffer.concat(se).toString("utf8") };
}

/** CPU seconds (user + system) of the tool, and its peak resident memory, read from the child's rusage. */
export async function measured(script: string, cwd: string, args: unknown, env: Record<string, string> = {}): Promise<{ cpu: number; mb: number; wall: number; stdout: string; code: number | null; stderr: string }> {
  const code = `
import json, os, resource, subprocess, sys, time
begun = time.monotonic()
p = subprocess.run([sys.executable, sys.argv[1]], input=sys.stdin.buffer.read(), capture_output=True)
r = resource.getrusage(resource.RUSAGE_CHILDREN)
rss = r.ru_maxrss / 1e6 if sys.platform == "darwin" else r.ru_maxrss / 1e3
sys.stdout.buffer.write(p.stdout)
sys.stderr.write("MEASURED=%f,%f,%f,%d\\n" % (r.ru_utime + r.ru_stime, rss, time.monotonic() - begun, p.returncode))
sys.stderr.buffer.write(p.stderr)
`;
  const out = await new Promise<Run>((resolve, reject) => {
    const child = spawn("python3", ["-c", code, script], { cwd, env: { ...process.env, ...AGENT, ...env } });
    const so: Buffer[] = [];
    const se: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => so.push(c));
    child.stderr.on("data", (c: Buffer) => se.push(c));
    child.on("error", reject);
    child.on("close", (c) => resolve({ code: c, stdout: Buffer.concat(so).toString("utf8"), stderr: Buffer.concat(se).toString("utf8") }));
    child.stdin.end(JSON.stringify(args));
  });
  const m = /MEASURED=([0-9.]+),([0-9.]+),([0-9.]+),(-?\d+)/.exec(out.stderr);
  assert.ok(m, out.stderr);
  return { cpu: Number(m[1]), mb: Number(m[2]), wall: Number(m[3]), code: Number(m[4]), stdout: out.stdout, stderr: out.stderr.replace(/MEASURED=.*\n/, "") };
}
