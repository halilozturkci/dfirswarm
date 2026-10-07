/**
 * Helpers the cloud pack's tool suites share: running a pack tool as a call and as a job (JOB_ID and OUT set, the way the
 * job service runs it), reading the rows an answer pages, and finding where a planted secret ended up. Each suite builds its
 * fixtures from the formats' own layouts (CloudTrail's record, Microsoft Graph's signIn, the audit schema's native event,
 * the Reports API's activity) and never from a tool's output.
 */
import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, readdir, stat, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import { spawn } from "node:child_process";
import type { ChildProcess } from "node:child_process";
import { ROOT } from "./tool-library-harness.ts";

const CLOUD = join(ROOT, "packs", "cloud-forensics");
/** CLOUD_PACK_TOOLS runs a suite against another copy of the tools (an earlier head, to show that a regression test fails there). */
export const TOOLS = process.env.CLOUD_PACK_TOOLS ?? join(CLOUD, "tools");
export const TRAIL = join(TOOLS, "cloudtrail_parse", "run.py");
export const SIGNIN = join(TOOLS, "signin_analyse", "run.py");
export const UAL = join(TOOLS, "ual_parse", "run.py");
export const AGENT = { AGENT_ID: "s1" };

export type Run = { code: number | null; stdout: string; stderr: string; signal?: string | null };
export type Page = { matched: number; returned: number; truncated: boolean; all_results?: string };
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type Json = any;

export async function withDir(fn: (cwd: string) => Promise<void>): Promise<void> {
  const cwd = await mkdtemp(join(tmpdir(), "cloud-eval-"));
  try {
    await mkdir(join(cwd, "work", "s1"), { recursive: true });
    await mkdir(join(cwd, "inputs"), { recursive: true });
    await fn(cwd);
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
}

/** A tool's process is killed after this long, so a tool that hangs fails the test and not the suite. */
export const DEADLINE_MS = 120_000;

/** Start a tool and return its process and the promise of its result; the process is killed (SIGKILL) at the deadline. */
export function spawnTool(script: string, cwd: string, args: unknown, env: Record<string, string> = {}, deadlineMs = DEADLINE_MS): { child: ChildProcess; done: Promise<Run> } {
  const child = spawn("python3", [script], { cwd, env: { ...process.env, ...AGENT, ...env } });
  const out: Buffer[] = [];
  const err: Buffer[] = [];
  child.stdout?.on("data", (c: Buffer) => out.push(c));
  child.stderr?.on("data", (c: Buffer) => err.push(c));
  let killed = false;
  const timer = setTimeout(() => {
    killed = true;
    child.kill("SIGKILL");
  }, deadlineMs);
  const done = new Promise<Run>((resolve, reject) => {
    child.on("error", (e) => {
      clearTimeout(timer);
      reject(e);
    });
    child.on("close", (code, signal) => {
      clearTimeout(timer);
      const stderr = Buffer.concat(err).toString("utf8") + (killed ? `\n[harness] killed after ${deadlineMs} ms` : "");
      resolve({ code, stdout: Buffer.concat(out).toString("utf8"), stderr, signal });
    });
  });
  child.stdin?.on("error", () => undefined);
  child.stdin?.end(JSON.stringify(args));
  return { child, done };
}

export async function tool(script: string, cwd: string, args: unknown, env: Record<string, string> = {}): Promise<Run> {
  return spawnTool(script, cwd, args, env).done;
}

let jobs = 0;
/** The tool as a job runs it: JOB_ID and OUT set, OUT inside the run directory (`out`, or the directory named). */
export async function asJob(script: string, cwd: string, args: unknown, env: Record<string, string> = {}, outName = "out", job?: string): Promise<Run> {
  await mkdir(join(cwd, outName), { recursive: true });
  jobs += 1;
  return tool(script, cwd, args, { JOB_ID: job ?? `j${String(jobs).padStart(6, "0")}`, OUT: join(cwd, outName), ...env });
}

export function body(out: Run): Json {
  assert.equal(out.code, 0, out.stderr + out.stdout);
  assert.doesNotMatch(out.stderr, /Traceback/);
  return JSON.parse(out.stdout);
}

export function refused(out: Run): Json {
  assert.notEqual(out.code, 0, out.stdout);
  assert.doesNotMatch(out.stderr, /Traceback/);
  return JSON.parse(out.stdout);
}

export async function exists(path: string): Promise<boolean> {
  return stat(path).then(() => true, () => false);
}

/** Every file under a directory, relative to it. */
export async function filesUnder(dir: string): Promise<string[]> {
  const out: string[] = [];
  const walk = async (d: string, prefix: string): Promise<void> => {
    for (const e of await readdir(d, { withFileTypes: true }).catch(() => [])) {
      if (e.isDirectory()) await walk(join(d, e.name), `${prefix}${e.name}/`);
      else out.push(`${prefix}${e.name}`);
    }
  };
  await walk(dir, "");
  return out.sort();
}

/**
 * The rows of a list an answer pages: the inline page, or the whole in the file the page names. A job's paging file is
 * named store/jobs/<id>/out/..., which a test run finds under `outDir`.
 */
export async function rowsOf(cwd: string, out: Json, key: string, outDir = "out"): Promise<Json[]> {
  const page: Page | undefined = out.pages?.[key];
  if (page?.all_results) {
    const real = page.all_results.replace(/^store\/jobs\/[^/]+\/out\//, `${outDir}/`);
    const text = await readFile(join(cwd, real), "utf8");
    return text.trimEnd().split("\n").filter(Boolean).map((l) => JSON.parse(l));
  }
  return out[key] ?? [];
}

/**
 * Everything a call left where an agent reads it, as one string: the answer, every job output directory (`out*`) and the
 * agent's own tool-output pages (`work/s1`). `skip` names files that are meant to hold the planted secret (the sealed
 * values file, the evidence under `work/`).
 */
export async function everythingBut(cwd: string, answer: string, skip: string[]): Promise<string> {
  const parts = [answer];
  const roots = (await readdir(cwd)).filter((d) => d.startsWith("out")).concat(["work/s1"]);
  for (const root of roots) {
    for (const f of await filesUnder(join(cwd, root))) {
      if (skip.includes(`${root}/${f}`)) continue;
      parts.push(await readFile(join(cwd, root, f), "utf8").catch(() => ""));
    }
  }
  return parts.join("\n");
}

export async function put(root: string, rel: string, text: string | Buffer): Promise<string> {
  const full = join(root, rel);
  await mkdir(join(full, ".."), { recursive: true });
  await writeFile(full, text);
  return full;
}

export const gz = (text: string): Buffer => gzipSync(Buffer.from(text, "utf8"));
export const lines = (...ls: string[]): string => ls.join("\n") + "\n";

// ---- CloudTrail's record, from its documented layout ---------------------------------------------------------------

export type Ev = Record<string, unknown>;

/** A CloudTrail event with the fields every record carries; `over` replaces or adds. */
export function ct(over: Ev): Ev {
  return {
    eventVersion: "1.08",
    eventTime: "2026-02-14T09:00:00Z",
    eventSource: "sts.amazonaws.com",
    eventName: "AssumeRole",
    awsRegion: "us-east-1",
    sourceIPAddress: "198.51.100.7",
    userAgent: "aws-cli/2.15.0",
    requestID: "11111111-2222-3333-4444-555555555555",
    eventID: "e-0",
    readOnly: true,
    eventType: "AwsApiCall",
    managementEvent: true,
    recipientAccountId: "111122223333",
    eventCategory: "Management",
    ...over,
  };
}

export const ALICE = { type: "IAMUser", principalId: "AIDAEXAMPLEALICE", arn: "arn:aws:iam::999988887777:user/alice", accountId: "999988887777", accessKeyId: "AKIAEXAMPLEALICE1", userName: "alice" };

/** The identity of a session: userIdentity of type AssumedRole with its sessionContext. */
export function session(arn: string, key: string | undefined, created: string, issuerArn = "arn:aws:iam::111122223333:role/Admin", account = "111122223333"): Ev {
  return {
    type: "AssumedRole",
    principalId: "AROAEXAMPLEROLE:alice-session",
    arn,
    accountId: account,
    ...(key ? { accessKeyId: key } : {}),
    sessionContext: {
      sessionIssuer: { type: "Role", principalId: "AROAEXAMPLEROLE", arn: issuerArn, accountId: account, userName: "Admin" },
      attributes: { creationDate: created, mfaAuthenticated: "false" },
    },
  };
}

/** The response of a successful AssumeRole: the temporary credentials and the assumed-role user. */
export function assumedResponse(key: string, arn: string, token = "TOKEN-NOT-A-SECRET"): Ev {
  return {
    credentials: { accessKeyId: key, expiration: "Feb 14, 2026, 10:00:00 AM", sessionToken: token },
    assumedRoleUser: { assumedRoleId: "AROAEXAMPLEROLE:alice-session", arn },
  };
}

export const trail = (...records: Ev[]): string => JSON.stringify({ Records: records });
