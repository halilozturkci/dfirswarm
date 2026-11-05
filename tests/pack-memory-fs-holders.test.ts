/**
 * mem_fs (PKG-P6): the reader of the engine's pipes, probed with what an engine may leave on them. mem_fs carries no PROCESS block (it drives MemProcFS, a long-running FUSE
 * server that it stops and unmounts itself, and it copies bytes it reads from the mount), so it is not a process_apply carrier; but its drain threads read the engine's pipes,
 * and a program that holds them must neither hold the tool nor stay running. pack-memory-engine-descendants.test.ts has the sleeper that holds the pipes (and the holder in a
 * session of its own, and the tool that does not lead its group); here the holder is a writer that never stops and one that holds no pipe at all (a session of its own, no
 * descriptor). Each case: the tool answers in seconds, with a status, and the holder that holds the pipes is ended.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { withCwd } from "./tool-library-harness.ts";
import { FS, fsStub } from "./memory-f1-support.ts";
import { gone, pidFile } from "./pack-network-harness.ts";

function ask(cwd: string, args: unknown, env: Record<string, string>, bin: string): Promise<{ ms: number; stdout: string; code: number | null; endGroup: () => void }> {
  const began = Date.now();
  const e: NodeJS.ProcessEnv = { ...process.env, AGENT_ID: "s1", ...env, PATH: `${bin}:${process.env.PATH ?? ""}` };
  delete e.JOB_ID; delete e.OUT; delete e.SECRET_OUTPUT;
  const child = spawn("python3", [FS], { cwd, env: e, detached: true, stdio: ["pipe", "pipe", "ignore"] });
  const chunks: Buffer[] = [];
  child.stdout.on("data", (c: Buffer) => chunks.push(c));
  child.stdin.end(JSON.stringify(args));
  const endGroup = (): void => { try { process.kill(-(child.pid as number), "SIGKILL"); } catch { /* gone */ } };
  return new Promise((resolve) => {
    child.on("close", (code) => resolve({ ms: Date.now() - began, stdout: Buffer.concat(chunks).toString("utf8"), code, endGroup }));
  });
}

for (const [name, holder] of [
  ["a writer that never stops, holding the pipes", "sh -c 'while :; do printf x; sleep 0.2; done'"],
  ["a writer that never stops, in a session of its own, holding the pipes", "setsid sh -c 'while :; do printf x; sleep 0.2; done'"],
] as const) {
  test(`mem_fs: an engine that ended and left ${name} does not hold the tool, and the holder is ended`, { timeout: 120000 }, async () => {
    await withCwd(async (cwd, bin) => {
      const holdPid = join(cwd, "hold.pid");
      const env = await fsStub(cwd, bin, { tree: { "proc/a.txt": "alpha\n", "sys/x": "" }, hold: { seconds: 40, pidFile: holdPid } });
      // the stand-in engine starts `sleep` and records its pid: the sleeper is replaced by the writer
      const script = await readFile(join(bin, "memprocfs"), "utf8");
      const swapped = script.replace('subprocess.Popen(["sleep", os.environ["STUB_HOLD"]], start_new_session=bool(os.environ.get("STUB_HOLD_SESSION")))',
        `subprocess.Popen(["/bin/sh", "-c", ${JSON.stringify(holder.replace(/^setsid sh -c '|'$/g, "").replace(/^sh -c '|'$/g, ""))}], start_new_session=${holder.startsWith("setsid") ? "True" : "False"})`);
      assert.notEqual(swapped, script, "the stand-in was changed");
      await writeFile(join(bin, "memprocfs"), swapped);
      await writeFile(join(cwd, "inputs", "memory.raw"), Buffer.alloc(4096));
      let holderPid = 0;
      let ran: Awaited<ReturnType<typeof ask>> | undefined;
      try {
        ran = await ask(cwd, { path: "inputs/memory.raw", mount: join(cwd, "work", "s1", "m"), mode: "list", timeout_seconds: 30 }, env, bin);
        holderPid = await pidFile(holdPid, 5000);
        assert.ok(ran.ms < 25_000, `took ${ran.ms} ms: the call waited for the program the engine left`);
        const answer = JSON.parse(ran.stdout);
        assert.ok(["complete", "partial"].includes(answer.status), ran.stdout);
        assert.equal(await gone(holderPid, 10_000), true, "the program the engine left was not ended");
      } finally {
        ran?.endGroup();
        if (holderPid) { try { process.kill(holderPid, "SIGKILL"); } catch { /* gone */ } }
      }
    });
  });
}
