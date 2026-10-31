/**
 * A caller-supplied path that is a FIFO (nobody writes to it) must never hold a tool: every path one of the five
 * tools opens or reads is checked as a regular file before it is opened, with the tool's clock already running, and
 * the answer is JSON within seconds. Each case spawns the tool, waits at most 12 s, and if it has not ended ends
 * that exact pid itself (so a failing run leaves nothing behind) and fails the test.
 */
import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { chmod, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { ROOT } from "./tool-library-harness.ts";

const ENC = join(ROOT, "packs", "encrypted-containers", "tools");
const WAIT_MS = 12_000;

async function run(tool: string, cwd: string, args: unknown, env: Record<string, string>): Promise<{ answered: boolean; json: Record<string, any> | null; ms: number }> {
  const child = spawn("python3", [join(ENC, tool, "run.py")], { cwd, env: { ...process.env, AGENT_ID: "s1", ...env } });
  const chunks: Buffer[] = [];
  child.stdout.on("data", (c: Buffer) => chunks.push(c));
  child.stdin.end(JSON.stringify(args));
  const t0 = Date.now();
  const ended = await new Promise<boolean>((resolve) => {
    const timer = setTimeout(() => {
      child.kill("SIGKILL"); // the exact pid we started, and only it
      resolve(false);
    }, WAIT_MS);
    child.on("exit", () => {
      clearTimeout(timer);
      resolve(true);
    });
  });
  const text = Buffer.concat(chunks).toString("utf8").trim();
  let json: Record<string, any> | null = null;
  try {
    json = JSON.parse(text);
  } catch { /* none */ }
  return { answered: ended && json !== null, json, ms: Date.now() - t0 };
}

async function scratch<T>(fn: (cwd: string, out: string, fifo: string) => Promise<T>): Promise<T> {
  const root = await mkdtemp(join(tmpdir(), "fifo-test-"));
  try {
    const cwd = join(root, "cwd");
    const out = join(root, "out");
    await mkdir(join(cwd, "work"), { recursive: true });
    await mkdir(out, { recursive: true });
    const fifo = join(cwd, "work", "pipe");
    execFileSync("mkfifo", ["-m", "600", fifo]);
    return await fn(cwd, out, fifo);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

const JOB = (out: string) => ({ JOB_ID: "j1", OUT: out, SECRET_OUTPUT: "1" });

test("tcrypt_header: a FIFO as password_file is refused as JSON within seconds, not read", async () => {
  await scratch(async (cwd, out, fifo) => {
    await writeFile(join(cwd, "work", "v.img"), "volume bytes");
    const r = await run("tcrypt_header", cwd, { source: "work/v.img", password_file: fifo, max_seconds: 3 }, JOB(out));
    assert.ok(r.answered, `no answer within ${WAIT_MS} ms`);
    assert.equal(r.json!.status, "failed");
    assert.match(r.json!.error, /not a regular file/);
  });
});

test("tcrypt_header: a FIFO as a keyfile or as source is refused as JSON", async () => {
  await scratch(async (cwd, out, fifo) => {
    await writeFile(join(cwd, "work", "v.img"), "volume bytes");
    await writeFile(join(cwd, "work", "pw"), "x\n");
    await chmod(join(cwd, "work", "pw"), 0o600);
    const k = await run("tcrypt_header", cwd, { source: "work/v.img", password_file: "work/pw", keyfiles: [fifo], max_seconds: 3 }, JOB(out));
    assert.ok(k.answered && k.json!.status === "failed", JSON.stringify(k.json));
    const s = await run("tcrypt_header", cwd, { source: fifo, password_file: "work/pw", max_seconds: 3 }, JOB(out));
    assert.ok(s.answered && s.json!.status === "failed", JSON.stringify(s.json));
  });
});

test("password_recover: a FIFO as source, hash_file or candidates is refused as JSON", async () => {
  await scratch(async (cwd, out, fifo) => {
    await writeFile(join(cwd, "work", "c.txt"), "a\n");
    await writeFile(join(cwd, "work", "h.txt"), "h\n");
    for (const args of [{ source: fifo, format: "zip", candidates: "work/c.txt" }, { hash_file: fifo, format: "zip", candidates: "work/c.txt" },
                        { hash_file: "work/h.txt", format: "zip", candidates: fifo }]) {
      const r = await run("password_recover", cwd, { ...args, max_seconds: 3 }, JOB(out));
      assert.ok(r.answered, `no answer for ${JSON.stringify(args).slice(0, 40)}`);
      assert.equal(r.json!.status, "failed");
    }
  });
});

test("archive_probe, crypto_id and recovery_key_scan: a FIFO as path is refused as JSON", async () => {
  await scratch(async (cwd, _out, fifo) => {
    for (const tool of ["archive_probe", "crypto_id", "recovery_key_scan"]) {
      const r = await run(tool, cwd, { path: fifo }, {});
      assert.ok(r.answered, `${tool}: no answer within ${WAIT_MS} ms`);
      assert.equal(r.json!.status, "failed", tool);
    }
  });
});
