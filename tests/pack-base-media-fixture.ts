/**
 * What the suites of the base pack's picture, video and cache tools share (tests/pack-base-qr-read.test.ts, -glyph-strip, -frame-survey,
 * -cache-body, -first-stage, -media-contract): a run root with a space in its name, a call made the way `job_run` makes it (the working
 * directory is the run's root, every path relative to it, $OUT the job's own output directory), and a small PNG writer for fixtures that
 * are drawn here, pixel by pixel, never by the tool under test.
 */
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { mkdir, mkdtemp, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { deflateSync } from "node:zlib";
import { PYTHON3 } from "./host-gates.ts";

export const ROOT = join(import.meta.dirname, "..");
// PACK_DIR points the suites at another copy of the pack, as the pack's own tests take it.
export const CFB = process.env.PACK_DIR || join(ROOT, "packs", "computer-forensics-base");
export const tool = (name: string): string => join(CFB, "tools", name, "run.py");
export type Doc = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any
export type Ran = { code: number | null; stdout: string; stderr: string; doc: Doc; ms: number; killed: boolean };

/** A run root whose own name has a space: inputs/, work/s1/ and one job's output directory. */
export async function withRun(fn: (run: string, out: string) => Promise<void>): Promise<void> {
  const top = await realpath(await mkdtemp(join(process.platform === "darwin" ? "/tmp" : tmpdir(), "media-")));
  const run = join(top, "run root");
  const out = join(run, "store", "jobs", "j000001", "out");
  try {
    for (const d of ["inputs/case files", "work/s1", "store/jobs/j000001/out"]) await mkdir(join(run, d), { recursive: true });
    await fn(run, out);
  } finally {
    await rm(top, { recursive: true, force: true });
  }
}

/** One call of a tool, as a job (JOB_ID and OUT set) unless `shell` is given; never longer than `limitMs`. */
export function call(name: string, run: string, args: unknown, opts: { out?: string; env?: Record<string, string>; limitMs?: number; signal?: { signal: NodeJS.Signals; afterMs: number }; path?: string } = {}): Promise<Ran> {
  return new Promise((resolve) => {
    const env: Record<string, string | undefined> = { ...process.env, AGENT_ID: "s1", ...(opts.out ? { JOB_ID: "j000001", OUT: opts.out } : {}), ...opts.env };
    if (!opts.out) {
      delete env.JOB_ID;
      delete env.OUT;
    }
    if (opts.path !== undefined) env.PATH = opts.path;
    const started = Date.now();
    const child = spawn(PYTHON3, [tool(name)], { cwd: run, env });
    const so: Buffer[] = [];
    const se: Buffer[] = [];
    let killed = false;
    const timer = setTimeout(() => {
      killed = true;
      child.kill("SIGKILL");
    }, opts.limitMs ?? 60_000);
    const stopper = opts.signal ? setTimeout(() => child.kill(opts.signal!.signal), opts.signal.afterMs) : null;
    child.stdout.on("data", (c: Buffer) => so.push(c));
    child.stderr.on("data", (c: Buffer) => se.push(c));
    child.on("error", () => undefined);
    child.on("close", (code) => {
      clearTimeout(timer);
      if (stopper) clearTimeout(stopper);
      const stdout = Buffer.concat(so).toString("utf8");
      let doc: Doc = {};
      try {
        doc = JSON.parse(stdout) as Doc;
      } catch {
        doc = { not_json: stdout.slice(0, 300) };
      }
      resolve({ code, stdout, stderr: Buffer.concat(se).toString("utf8"), doc, ms: Date.now() - started, killed });
    });
    child.stdin.on("error", () => undefined);
    child.stdin.end(typeof args === "string" ? args : JSON.stringify(args));
  });
}

/** A Python snippet run for a fixture (never the tool under test): its stdout, or a failed assertion with its stderr. */
export function py(code: string, args: string[], cwd: string): string {
  const r = spawnSync(PYTHON3, ["-I", "-c", code, ...args], { cwd, encoding: "utf8", maxBuffer: 64 << 20 });
  assert.equal(r.status, 0, `the fixture builder failed: ${r.stderr.slice(-600)}`);
  return r.stdout;
}

function crc32(buf: Buffer): number {
  let c = ~0;
  for (const b of buf) {
    c ^= b;
    for (let k = 0; k < 8; k++) c = c & 1 ? (c >>> 1) ^ 0xedb88320 : c >>> 1;
  }
  return ~c >>> 0;
}

/** An 8-bit grey PNG from rows of pixel values, written from the format (signature, IHDR, one IDAT, IEND). */
export function greyPng(rows: number[][]): Buffer {
  const height = rows.length;
  const width = rows[0]!.length;
  const raw = Buffer.alloc(height * (width + 1));
  rows.forEach((row, y) => {
    raw[y * (width + 1)] = 0;
    row.forEach((v, x) => (raw[y * (width + 1) + 1 + x] = v));
  });
  const chunk = (kind: string, body: Buffer): Buffer => {
    const head = Buffer.alloc(8);
    head.writeUInt32BE(body.length, 0);
    head.write(kind, 4, "latin1");
    const tail = Buffer.alloc(4);
    tail.writeUInt32BE(crc32(Buffer.concat([head.subarray(4), body])), 0);
    return Buffer.concat([head, body, tail]);
  };
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8;
  return Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), chunk("IHDR", ihdr), chunk("IDAT", deflateSync(raw)), chunk("IEND", Buffer.alloc(0))]);
}

/** Every file below a directory, as paths relative to it, sorted. */
export function filesBelow(dir: string): string[] {
  const r = spawnSync("find", [dir, "-type", "f"], { encoding: "utf8" });
  return r.stdout.split("\n").filter(Boolean).map((p) => p.slice(dir.length + 1)).sort();
}
