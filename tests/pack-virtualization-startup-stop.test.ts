/**
 * virtualization-backup-forensics: the three tools install their stop handlers (SIGTERM, SIGINT, SIGHUP) when the module has run
 * as far as the block that defines them, not when main() starts. A signal from there on gives one JSON answer that names it
 * and exit 128 plus the signal number; before this change the same signal ended the tool with no answer (exit -15, or a
 * KeyboardInterrupt traceback for SIGINT) for as long as the rest of a module of about 3,000 to 4,000 lines took to run.
 *
 *  - the gap is made deterministic by running the source up to and including the installer's call and sending the signal
 *    there (the way tests/pack-shared-stop.test.ts does for the STOP carriers); the start of the interpreter and the compiling of the file
 *    cannot be closed from inside the file, and the manifests say so;
 *  - the whole tool, signalled while main() waits for its arguments, ends the same way;
 *  - each manifest states the window that remains.
 */
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

const PACK = join(import.meta.dirname, "..", "packs", "virtualization-backup-forensics", "tools");
const TOOLS: Array<[string, RegExp]> = [
  ["virtualization_inventory", /^install_stop_handlers\(\)$/m],
  ["backup_audit_normalise", /^install_stop_handlers\(\)$/m],
  ["snapshot_chain_check", /^install_signal_handlers\(\)$/m],
];
const SIGNALS = { SIGTERM: 15, SIGINT: 2, SIGHUP: 1 } as const;

/** The source up to and including the module-level line that installs the handlers; the test fails if there is none. */
async function prefixOf(tool: string, call: RegExp): Promise<string> {
  const text = await readFile(join(PACK, tool, "run.py"), "utf8");
  const m = call.exec(text);
  assert.ok(m, `${tool}: no module-level call that installs the stop handlers`);
  const mainAt = text.indexOf("\ndef main():");
  assert.ok(mainAt > 0 && m.index < mainAt, `${tool}: the call is not before main()`);
  return text.slice(0, text.indexOf("\n", m.index) + 1);
}

for (const [tool, call] of TOOLS) {
  for (const [name, number] of Object.entries(SIGNALS)) {
    test(`${tool}: ${name} after the module has run as far as the installer gives one JSON answer and exit ${128 + number}`, async () => {
      const dir = await mkdtemp(join(tmpdir(), "b21-startup-stop-"));
      try {
        const script = join(dir, "prefix.py");
        await writeFile(script, `${await prefixOf(tool, call)}\nimport os as _os, signal as _signal, time as _time\n_os.kill(_os.getpid(), _signal.${name})\n_time.sleep(30)\nprint("survived")\n`);
        const ran = spawnSync("python3", [script], { cwd: dir, encoding: "utf8", timeout: 60_000, env: { ...process.env, AGENT_ID: "s1" } });
        assert.equal(ran.status, 128 + number, `${ran.stdout} ${ran.stderr}`);
        assert.doesNotMatch(ran.stderr, /Traceback|KeyboardInterrupt/);
        const answer = JSON.parse(ran.stdout); // the whole output is one document: a second answer would not parse
        assert.equal(answer.tool, tool);
        assert.equal(answer.status, "partial");
        assert.equal(answer.stopped_by_signal, name);
        assert.doesNotMatch(ran.stdout, /survived/);
      } finally {
        await rm(dir, { recursive: true, force: true });
      }
    });
  }

  test(`${tool}: the whole tool, signalled while main() waits for its arguments, gives one JSON answer and exit 143`, async () => {
    const dir = await mkdtemp(join(tmpdir(), "b21-startup-stop-"));
    try {
      const child = spawn("python3", [join(PACK, tool, "run.py")], { cwd: dir, env: { ...process.env, AGENT_ID: "s1" }, stdio: ["pipe", "pipe", "pipe"] });
      let out = "";
      let err = "";
      child.stdout.on("data", (c: Buffer) => (out += c.toString()));
      child.stderr.on("data", (c: Buffer) => (err += c.toString()));
      const closed = new Promise<number | null>((resolve) => child.on("close", (code) => resolve(code)));
      await new Promise((r) => setTimeout(r, 1500));
      assert.equal(child.exitCode, null, "the tool is waiting on stdin");
      child.kill("SIGTERM");
      const code = await Promise.race([closed, new Promise<string>((r) => setTimeout(() => r("hung"), 20_000))]);
      if (code === "hung") child.kill("SIGKILL");
      assert.equal(code, 143, `${out} ${err}`);
      assert.equal(JSON.parse(out).stopped_by_signal, "SIGTERM");
      assert.doesNotMatch(err, /Traceback/);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  test(`${tool}: the manifest states the window that remains`, async () => {
    const manifest = JSON.parse(await readFile(join(PACK, tool, "manifest.json"), "utf8"));
    assert.match(manifest.description, /SIGTERM, SIGINT or SIGHUP/);
    assert.match(manifest.description, /interpreter starts and compiles/);
  });
}
