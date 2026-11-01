/**
 * password_recover: refused outside a secret_output job, before anything is read; runs the matching *2john helper (or takes a
 * hash by reference) and then a stand-in john, with no candidate value ever on an argv, in an env dump, on stdout, on stderr
 * or in the answer; the hash, pot, session, log and show-output files sit only under $OUT, mode 0600; a budget hit answers
 * partial, a helper that writes no hash answers failed, a format with no helper on PATH answers unsupported, and SIGTERM
 * during john ends the tool with one JSON answer and the child gone. Stand-ins (never real john, which this host may lack):
 * their argv and environment are recorded to a file outside $OUT, which is the test's own scaffolding, not the tool's output.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { chmod, mkdir, mkdtemp, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { ROOT, runPy } from "./tool-library-harness.ts";

const SCRIPT = join(ROOT, "packs", "encrypted-containers", "tools", "password_recover", "run.py");
const AGENT = { AGENT_ID: "s1" };
const CANARY = "Tr0ub4dor&3-canary-9f2c";

type Run = { code: number | null; stdout: string; stderr: string };

function answer<T>(out: Run, code = 0): T {
  assert.equal(out.code, code, out.stderr + out.stdout);
  assert.doesNotMatch(out.stderr, /Traceback/);
  return JSON.parse(out.stdout) as T;
}

/** A fresh scratch directory: cwd for the tool, a job output dir ($OUT), and a stand-in bin/ not on the tool's own path by default. */
async function scratch<T>(fn: (dirs: { cwd: string; out: string; bin: string; argvLog: string }) => Promise<T>): Promise<T> {
  const root = await mkdtemp(join(tmpdir(), "pr-test-"));
  try {
    const cwd = join(root, "cwd");
    const out = join(root, "out");
    const bin = join(root, "bin");
    const argvLog = join(root, "argv.log");
    await mkdir(cwd, { recursive: true });
    await mkdir(out, { recursive: true });
    await mkdir(bin, { recursive: true });
    return await fn({ cwd, out, bin, argvLog });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

/** A stand-in program on PATH: `exec` is POSIX sh, run with $@ as its own arguments; every call appends "name argv..." to argvLog. */
async function stub(bin: string, name: string, argvLog: string, exec: string): Promise<void> {
  const path = join(bin, name);
  await writeFile(path, `#!/bin/sh\nprintf '%s [HOME=%s]' "${name}" "$HOME" >> "${argvLog}"\nfor a in "$@"; do printf ' |%s' "$a" >> "${argvLog}"; done\nprintf '\\n' >> "${argvLog}"\n${exec}\n`, "utf8");
  await chmod(path, 0o755);
}

// Plain string concatenation, never a template literal: the shell text below uses "${...}" parameter expansion, which a
// JS template literal (String.raw included) would try to interpolate as a JS expression.
const JOHN = [
  'case "$1" in',
  '  --version) echo "John the Ripper 1.9.0-jumbo-test"; exit 0 ;;',
  'esac',
  'SHOW=',
  'POT=',
  'for a in "$@"; do',
  '  case "$a" in',
  '    --show) SHOW=1 ;;',
  '    --pot=*) POT=$(printf \'%s\' "$a" | sed \'s/^--pot=//\') ;;',
  '  esac',
  'done',
  'if [ -n "$SHOW" ]; then',
  '  if [ -n "$JOHN_RECOVERED" ]; then echo "1 password hash cracked, 0 left"; else echo "0 password hashes cracked, 1 left"; fi',
  '  exit 0',
  'fi',
  'if [ -n "$SLOW_JOHN" ]; then sleep "$SLOW_JOHN"; fi',
  'if [ -n "$JOHN_EXIT" ]; then exit "$JOHN_EXIT"; fi',
  'if [ -n "$POT" ] && [ -n "$JOHN_RECOVERED" ]; then printf \'%s:%s\\n\' "testhash0" "$CANARY_VALUE" >> "$POT"; fi',
  'exit 0',
].join("\n");

const HELPER_OK = "echo '$pkzip$0*fakehash*file.zip:::file.zip'";
const HELPER_FAIL = "exit 1";

async function runTool(cwd: string, args: unknown, env: Record<string, string>, bin?: string): Promise<Run> {
  return runPy(SCRIPT, cwd, args, bin, { ...AGENT, ...env });
}

// --- the refusal, before anything else is read ------------------------------------------------------------------------------

test("password_recover refuses outside a secret_output job, before reading its own stdin", async () => {
  await scratch(async ({ cwd }) => {
    for (const env of [{}, { JOB_ID: "j1" }, { JOB_ID: "j1", OUT: "/does/not/matter" }, { JOB_ID: "j1", OUT: "/x", SECRET_OUTPUT: "0" }]) {
      // stdin is poison: a tool that read it before the env check would choke on it, or echo the reason.
      const out = await runTool(cwd, "not valid json at all " + CANARY, env as Record<string, string>);
      const a = answer<{ error: string }>(out, 1);
      assert.match(a.error, /refused outside a job run as secret output/);
      assert.doesNotMatch(out.stdout, new RegExp(CANARY));
    }
  });
});

test("the refusal is this fails-on-base regression: the old code (no such check) would read stdin and fail differently", async () => {
  // A minimal stand-in for "no refusal check": calling the real tool with bad JSON and no job env must still be the SAME
  // refusal (not a JSON-parse error), which is what distinguishes the check from its absence.
  await scratch(async ({ cwd }) => {
    const out = await runTool(cwd, "{not json", {});
    const a = answer<{ error: string }>(out, 1);
    assert.match(a.error, /refused outside a job run as secret output/, "a parse error would read 'arguments are not valid JSON' instead");
  });
});

// --- argument validation (inside a secret_output job, so these reach the parser) --------------------------------------------

test("give exactly one of source or hash_file", async () => {
  await scratch(async ({ cwd, out }) => {
    const env = { JOB_ID: "j1", OUT: out, SECRET_OUTPUT: "1" };
    const neither = answer<{ error: string }>(await runTool(cwd, {}, env), 1);
    assert.match(neither.error, /give exactly one of source.*hash_file/);
    const both = answer<{ error: string }>(await runTool(cwd, { source: "a", hash_file: "b" }, env), 1);
    assert.match(both.error, /give exactly one of source.*hash_file/);
  });
});

// --- unsupported: the format's helper is not on PATH --------------------------------------------------------------------------

test("a format whose helper is not on this host's PATH answers unsupported and runs nothing", async () => {
  await scratch(async ({ cwd, out, bin, argvLog }) => {
    await stub(bin, "john", argvLog, JOHN);
    await writeFile(join(cwd, "evidence.zip"), "PK\x03\x04fake");
    await writeFile(join(cwd, "candidates.txt"), "password1\npassword2\n", "utf8");
    const env = { JOB_ID: "j1", OUT: out, SECRET_OUTPUT: "1", PATH: `${bin}:${process.env.PATH}` };
    const a = answer<{ status: string; status_basis: string; format: string }>(await runTool(cwd, {
      source: "evidence.zip", candidates: "candidates.txt",
    }, env));
    assert.equal(a.status, "unsupported");
    assert.match(a.status_basis, /zip2john is not on PATH/);
    assert.equal(a.format, "zip");
    const log = await readFile(argvLog, "utf8").catch(() => "");
    assert.doesNotMatch(log, /zip2john/, "nothing was run for an unsupported format");
  });
});

// --- failed: the helper ran but wrote no hash -----------------------------------------------------------------------------

test("a helper that exits non-zero and writes no hash answers failed", async () => {
  await scratch(async ({ cwd, out, bin, argvLog }) => {
    await stub(bin, "john", argvLog, JOHN);
    await stub(bin, "zip2john", argvLog, HELPER_FAIL);
    await writeFile(join(cwd, "evidence.zip"), "PK\x03\x04fake");
    await writeFile(join(cwd, "candidates.txt"), "password1\n");
    const env = { JOB_ID: "j1", OUT: out, SECRET_OUTPUT: "1", PATH: `${bin}:${process.env.PATH}` };
    const a = answer<{ status: string; status_basis: string }>(await runTool(cwd, {
      source: "evidence.zip", candidates: "candidates.txt",
    }, env));
    assert.equal(a.status, "failed");
    assert.match(a.status_basis, /zip2john exited .* wrote no hash/);
  });
});

// --- the full, gated run: stand-in helper and john, format inferred from the extension --------------------------------------

test("a gated run with stand-in helper and john: no candidate value on an argv or in an env dump, pot/session/log under $OUT mode 0600, the canary never reaches stdout, stderr or the answer, and the recovered count is read from john --show", async () => {
  await scratch(async ({ cwd, out, bin, argvLog }) => {
    await stub(bin, "john", argvLog, JOHN);
    await stub(bin, "zip2john", argvLog, HELPER_OK);
    await writeFile(join(cwd, "evidence.zip"), "PK\x03\x04fake");
    await writeFile(join(cwd, "candidates.txt"), `password1\n${CANARY}\npassword3\n`);
    const env = {
      JOB_ID: "j000042", OUT: out, SECRET_OUTPUT: "1", PATH: `${bin}:${process.env.PATH}`,
      JOHN_RECOVERED: "1", CANARY_VALUE: CANARY,
    };
    const run = await runTool(cwd, { source: "evidence.zip", candidates: "candidates.txt", rules: "wordlist" }, env);
    const a = answer<{
      status: string; status_basis: string; format: string; recovered: number; hash_count: number; candidate_count: number;
      pot_file: string; hash_file: string; versions: { john: string; helper: string | null };
    }>(run);
    assert.equal(a.status, "complete");
    assert.equal(a.format, "zip");
    assert.equal(a.recovered, 1);
    assert.equal(a.candidate_count, 3);
    assert.ok(a.hash_count >= 1);
    assert.match(a.pot_file, /^store\/jobs\/j000042\/out\//);
    assert.equal(a.versions.john, "John the Ripper 1.9.0-jumbo-test");

    // The canary (the exact candidate string, and what the stand-in "recovered") is nowhere a reader could see it.
    assert.doesNotMatch(run.stdout, new RegExp(CANARY));
    assert.doesNotMatch(run.stderr, new RegExp(CANARY));
    assert.doesNotMatch(JSON.stringify(a), new RegExp(CANARY));

    // No candidate value, and no value at all, on any argv john or the helper were called with.
    const log = await readFile(argvLog, "utf8");
    assert.doesNotMatch(log, new RegExp(CANARY), "the candidate list is a file path, never a value on an argv");
    assert.doesNotMatch(log, /password1|password3/);
    assert.match(log, /--wordlist=.*candidates\.txt/, "john was given the candidate file by path");
    assert.match(log, /--rules=Wordlist/);
    assert.match(log, /--session=/, "john was given a session path");
    for (const line of log.split("\n").filter((l) => l.trim())) assert.match(line, new RegExp(`\\[HOME=${out.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`), `HOME is under $OUT: ${line}`);

    // The sealed files sit only under $OUT, mode 0600, and the canary DOES live in the pot file (sealed, never printed).
    const files = await readdir(out);
    assert.ok(files.some((f) => f.startsWith("password_recover-hash")));
    assert.ok(files.some((f) => f.startsWith("password_recover-john.pot")));
    for (const f of files) {
      if (f === "password_recover-home") continue;
      const st = await stat(join(out, f));
      if (st.isFile()) assert.equal(st.mode & 0o777, 0o600, `${f} is ${(st.mode & 0o777).toString(8)}`);
    }
    const pot = await readFile(join(out, files.find((f) => f.startsWith("password_recover-john.pot"))!), "utf8");
    assert.match(pot, new RegExp(CANARY), "the recovered value lives in the sealed pot file, which this check reads directly (not through the tool's own output)");
  });
});

// --- hash_file: an existing hash from another sealed job, no helper run -----------------------------------------------------

test("hash_file skips the helper entirely", async () => {
  await scratch(async ({ cwd, out, bin, argvLog }) => {
    await stub(bin, "john", argvLog, JOHN);
    await writeFile(join(cwd, "existing.hash"), "$pkzip$0*...already-extracted...\n");
    await writeFile(join(cwd, "candidates.txt"), "password1\n");
    const env = { JOB_ID: "j1", OUT: out, SECRET_OUTPUT: "1", PATH: `${bin}:${process.env.PATH}` };
    const a = answer<{ status: string; hash_file: string }>(await runTool(cwd, {
      hash_file: "existing.hash", format: "zip", candidates: "candidates.txt",
    }, env));
    assert.equal(a.status, "complete");
    assert.match(a.hash_file, /existing\.hash$/);
    const log = await readFile(argvLog, "utf8");
    assert.doesNotMatch(log, /2john/, "no helper was run");
  });
});

// --- a budget hit answers partial --------------------------------------------------------------------------------------------

test("a budget hit while john is running answers partial, not complete", async () => {
  await scratch(async ({ cwd, out, bin, argvLog }) => {
    await stub(bin, "john", argvLog, JOHN);
    await stub(bin, "zip2john", argvLog, HELPER_OK);
    await writeFile(join(cwd, "evidence.zip"), "PK\x03\x04fake");
    await writeFile(join(cwd, "candidates.txt"), "password1\n");
    const env = { JOB_ID: "j1", OUT: out, SECRET_OUTPUT: "1", PATH: `${bin}:${process.env.PATH}`, SLOW_JOHN: "5" };
    const a = answer<{ status: string; status_basis: string }>(await runTool(cwd, {
      source: "evidence.zip", candidates: "candidates.txt", max_seconds: 1,
    }, env));
    assert.equal(a.status, "partial");
    assert.match(a.status_basis, /time budget \(1 seconds\)/, "the real max_seconds, not the default");
  });
});

// --- SIGTERM during john: one JSON answer, exit 128+15, the child gone, nothing outside $OUT ----------------------------------

test("SIGTERM while john is running ends the tool with one JSON answer and the child reaped", async () => {
  await scratch(async ({ cwd, out, bin, argvLog }) => {
    await stub(bin, "john", argvLog, JOHN);
    await stub(bin, "zip2john", argvLog, HELPER_OK);
    await writeFile(join(cwd, "evidence.zip"), "PK\x03\x04fake");
    await writeFile(join(cwd, "candidates.txt"), "password1\n");
    const env = {
      ...process.env, ...AGENT, JOB_ID: "j1", OUT: out, SECRET_OUTPUT: "1", PATH: `${bin}:${process.env.PATH}`, SLOW_JOHN: "30",
    } as Record<string, string>;
    const child = spawn("python3", [SCRIPT], { cwd, env });
    const chunks: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => chunks.push(c));
    child.stdin.end(JSON.stringify({ source: "evidence.zip", candidates: "candidates.txt", max_seconds: 300 }));
    await new Promise((r) => setTimeout(r, 700));
    child.kill("SIGTERM");
    const code = await new Promise<number | null>((resolve) => child.on("exit", (c) => resolve(c)));
    assert.equal(code, 128 + 15);
    const text = Buffer.concat(chunks).toString("utf8");
    assert.equal(text.trim().split("\n").filter((l) => l.trim()).length, 1, "exactly one JSON document");
    const a = JSON.parse(text) as { status: string };
    assert.match(a.status, /partial|failed/);
    // The stand-in john (slept 30s) must be gone well before its sleep would have ended on its own.
    await new Promise((r) => setTimeout(r, 300));
    const ps = await new Promise<string>((resolve) => {
      const p = spawn("pgrep", ["-f", join(bin, "john")]);
      let o = "";
      p.stdout.on("data", (c: Buffer) => (o += c));
      p.on("close", () => resolve(o));
    });
    assert.equal(ps.trim(), "", "the stand-in john (and its sleep) was killed with the tool");
  });
});

// --- fix round: nothing tried is never `complete` -----------------------------------------------------------------------

const JOHN_NONE_LOADED = JOHN.replace('echo "1 password hash cracked, 0 left"', 'echo "No password hashes loaded (see FAQ)"');
const HELPER_NO_VERSION = 'case "$1" in --version) exit 1 ;; esac\necho \'$pkzip$0*fakehash*file.zip:::file.zip\'';

async function jobEnv(out: string, bin: string, extra: Record<string, string> = {}): Promise<Record<string, string>> {
  return { JOB_ID: "j1", OUT: out, SECRET_OUTPUT: "1", PATH: `${bin}:${process.env.PATH}`, ...extra };
}

test("a hash file of blank lines answers failed with hash_count 0, and john is not run", async () => {
  await scratch(async ({ cwd, out, bin, argvLog }) => {
    await stub(bin, "john", argvLog, JOHN);
    await writeFile(join(cwd, "blank.hash"), "\n   \n\n");
    await writeFile(join(cwd, "candidates.txt"), "password1\n");
    const a = answer<{ status: string; hash_count: number; status_basis: string }>(await runTool(cwd, {
      hash_file: "blank.hash", format: "zip", candidates: "candidates.txt",
    }, await jobEnv(out, bin)));
    assert.equal(a.status, "failed");
    assert.equal(a.hash_count, 0);
    assert.doesNotMatch(a.status_basis, /tried every candidate/);
    assert.doesNotMatch(await readFile(argvLog, "utf8"), /--wordlist/);
  });
});

test("a helper that writes only a blank line answers failed, not complete", async () => {
  await scratch(async ({ cwd, out, bin, argvLog }) => {
    await stub(bin, "john", argvLog, JOHN);
    await stub(bin, "zip2john", argvLog, "echo");
    await writeFile(join(cwd, "evidence.zip"), "PK\x03\x04fake");
    await writeFile(join(cwd, "candidates.txt"), "password1\n");
    const a = answer<{ status: string; hash_count: number }>(await runTool(cwd, { source: "evidence.zip", candidates: "candidates.txt" }, await jobEnv(out, bin)));
    assert.equal(a.status, "failed");
    assert.equal(a.hash_count, 0);
  });
});

test("john that loads no hash (exit 0, 'No password hashes loaded') answers failed", async () => {
  await scratch(async ({ cwd, out, bin, argvLog }) => {
    await stub(bin, "john", argvLog, JOHN_NONE_LOADED);
    await writeFile(join(cwd, "h.hash"), "notahash:xyz\n");
    await writeFile(join(cwd, "candidates.txt"), "password1\n");
    const a = answer<{ status: string; status_basis: string; recovered: number }>(await runTool(cwd, {
      hash_file: "h.hash", format: "zip", candidates: "candidates.txt",
    }, await jobEnv(out, bin, { JOHN_RECOVERED: "1" })));
    assert.equal(a.status, "failed");
    assert.match(a.status_basis, /loaded no hash/);
    assert.equal(a.recovered, 0);
  });
});

test("an empty candidate list answers failed, not a vacuous complete", async () => {
  await scratch(async ({ cwd, out, bin, argvLog }) => {
    await stub(bin, "john", argvLog, JOHN);
    await writeFile(join(cwd, "h.hash"), "$pkzip$0*x\n");
    await writeFile(join(cwd, "candidates.txt"), "\n\n");
    const a = answer<{ status: string; status_basis: string }>(await runTool(cwd, {
      hash_file: "h.hash", format: "zip", candidates: "candidates.txt",
    }, await jobEnv(out, bin)));
    assert.equal(a.status, "failed");
    assert.match(a.status_basis, /candidate list holds no line/);
  });
});

test("versions.helper says 'not reported by this build' when the helper reports none, never a claim of a pin", async () => {
  await scratch(async ({ cwd, out, bin, argvLog }) => {
    await stub(bin, "john", argvLog, JOHN);
    await stub(bin, "zip2john", argvLog, HELPER_NO_VERSION);
    await writeFile(join(cwd, "evidence.zip"), "PK\x03\x04fake");
    await writeFile(join(cwd, "candidates.txt"), "password1\n");
    const a = answer<{ status: string; versions: { helper: string } }>(await runTool(cwd, { source: "evidence.zip", candidates: "candidates.txt" }, await jobEnv(out, bin)));
    assert.equal(a.status, "complete");
    assert.equal(a.versions.helper, "not reported by this build");
  });
});

test("hash_file without format is refused (there is no source to infer it from)", async () => {
  await scratch(async ({ cwd, out, bin, argvLog }) => {
    await stub(bin, "john", argvLog, JOHN);
    await writeFile(join(cwd, "h.hash"), "$pkzip$0*x\n");
    await writeFile(join(cwd, "candidates.txt"), "password1\n");
    const a = answer<{ error: string }>(await runTool(cwd, { hash_file: "h.hash", candidates: "candidates.txt" }, await jobEnv(out, bin)), 1);
    assert.match(a.error, /format is required with hash_file/);
  });
});
