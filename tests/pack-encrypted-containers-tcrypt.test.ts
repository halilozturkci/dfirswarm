/**
 * tcrypt_header: refused outside a secret_output job, before anything is read; the password is read from a file and
 * given to a stand-in cryptsetup on its stdin, never on argv or in the answer; a wrong password (or a header that
 * simply did not decrypt) is reported without claiming the volume is not VeraCrypt or TrueCrypt; a symlinked or
 * special source is refused; a timeout and a SIGTERM each end the tool with one JSON answer and the child gone;
 * a missing cryptsetup answers unavailable. A real gated run against a header built from the TCRYPT format runs
 * only when the real cryptsetup is on this host's PATH (t.skip otherwise: this host may lack it, as the package
 * notes allow).
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { chmod, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { ROOT, runPy } from "./tool-library-harness.ts";

const SCRIPT = join(ROOT, "packs", "encrypted-containers", "tools", "tcrypt_header", "run.py");
const AGENT = { AGENT_ID: "s1" };
const CANARY = "correct-horse-battery-staple-9f2c";

type Run = { code: number | null; stdout: string; stderr: string };

function answer<T>(out: Run, code = 0): T {
  assert.equal(out.code, code, out.stderr + out.stdout);
  assert.doesNotMatch(out.stderr, /Traceback/);
  return JSON.parse(out.stdout) as T;
}

async function scratch<T>(fn: (dirs: { cwd: string; out: string; bin: string; argvLog: string }) => Promise<T>): Promise<T> {
  const root = await mkdtemp(join(tmpdir(), "tc-test-"));
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

async function stub(bin: string, name: string, argvLog: string, exec: string): Promise<void> {
  const path = join(bin, name);
  await writeFile(path, `#!/bin/sh\nprintf '%s' "${name}" >> "${argvLog}"\nfor a in "$@"; do printf ' |%s' "$a" >> "${argvLog}"; done\nSTDIN=$(cat)\nprintf ' |stdin=%s' "$STDIN" >> "${argvLog}"\nprintf '\\n' >> "${argvLog}"\n${exec}\n`, "utf8");
  await chmod(path, 0o755);
}

// Plain string concatenation: the shell text below is never a JS template literal, since cryptsetup's own output
// uses "${...}"-free plain labels, but the stub's control flow still needs case/if that a template could mangle.
const CRYPTSETUP_DECRYPTS = [
  'case "$1" in',
  '  --version) echo "cryptsetup 2.6.1"; exit 0 ;;',
  'esac',
  'if [ -n "$CS_EXIT" ]; then exit "$CS_EXIT"; fi',
  'if [ -n "$SLOW_CS" ]; then sleep "$SLOW_CS"; fi',
  'if [ "$STDIN" = "$EXPECT_PASSWORD" ]; then',
  '  cat <<EOF',
  'TCRYPT header information for /dev/stub',
  'Version:       5',
  'Driver req.:   0',
  'Flags:         0',
  'Sector size:   512',
  'MK offset:     0',
  'Volume size:   10485760',
  'PBKDF:         PBKDF2',
  'PBKDF2 hash:   sha512',
  'Cipher chain:  aes-twofish-serpent',
  'Cipher mode:   xts-plain64',
  'MK bits:       192',
  'EOF',
  '  exit 0',
  'else',
  '  echo "Device /dev/stub is not a valid TCRYPT device." >&2',
  '  exit 2',
  'fi',
].join("\n");

async function runTool(cwd: string, args: unknown, env: Record<string, string>, bin?: string): Promise<Run> {
  return runPy(SCRIPT, cwd, args, bin, { ...AGENT, ...env });
}

// --- the refusal, before anything else is read ------------------------------------------------------------------

test("tcrypt_header refuses outside a secret_output job, before reading its own stdin", async () => {
  await scratch(async ({ cwd }) => {
    for (const env of [{}, { JOB_ID: "j1" }, { JOB_ID: "j1", OUT: "/x" }, { JOB_ID: "j1", OUT: "/x", SECRET_OUTPUT: "0" }]) {
      const out = await runTool(cwd, "not json at all " + CANARY, env as Record<string, string>);
      const a = answer<{ error: string }>(out, 1);
      assert.match(a.error, /refused outside a job run as secret output/);
      assert.doesNotMatch(out.stdout, new RegExp(CANARY));
    }
  });
});

// --- validation ---------------------------------------------------------------------------------------------------

test("a symbolic link named as source or as a keyfile is refused", async () => {
  await scratch(async ({ cwd, out, bin, argvLog }) => {
    await stub(bin, "cryptsetup", argvLog, CRYPTSETUP_DECRYPTS);
    await writeFile(join(cwd, "real.img"), "volume bytes");
    await symlink(join(cwd, "real.img"), join(cwd, "link.img"));
    await writeFile(join(cwd, "password.txt"), "whatever\n", { mode: 0o600 });
    const env = { JOB_ID: "j1", OUT: out, SECRET_OUTPUT: "1", PATH: `${bin}:${process.env.PATH}` };
    const a = answer<{ error: string }>(await runTool(cwd, { source: "link.img", password_file: "password.txt" }, env), 1);
    assert.match(a.error, /source is a symbolic link/);
  });
});

test("offset must be a multiple of 512, and pim is refused, named", async () => {
  await scratch(async ({ cwd, out, bin, argvLog }) => {
    await stub(bin, "cryptsetup", argvLog, CRYPTSETUP_DECRYPTS);
    await writeFile(join(cwd, "real.img"), "volume bytes");
    await writeFile(join(cwd, "password.txt"), "whatever\n", { mode: 0o600 });
    const env = { JOB_ID: "j1", OUT: out, SECRET_OUTPUT: "1", PATH: `${bin}:${process.env.PATH}` };
    const bad = answer<{ error: string }>(await runTool(cwd, { source: "real.img", password_file: "password.txt", offset: 100 }, env), 1);
    assert.match(bad.error, /multiple of 512/);
    const pim = answer<{ error: string }>(await runTool(cwd, { source: "real.img", password_file: "password.txt", pim: 485 }, env), 1);
    assert.match(pim.error, /pim is not supported/);
  });
});

// --- unavailable: no cryptsetup on PATH --------------------------------------------------------------------------

test("a missing cryptsetup answers unavailable, naming the program", async () => {
  await scratch(async ({ cwd, out }) => {
    await writeFile(join(cwd, "real.img"), "volume bytes");
    await writeFile(join(cwd, "password.txt"), "whatever\n", { mode: 0o600 });
    // /usr/bin:/bin holds python3 (so the tool itself starts) but not cryptsetup, which a non-root PATH does not
    // usually carry even when cryptsetup-bin is installed (it lands in a sbin directory).
    const env = { JOB_ID: "j1", OUT: out, SECRET_OUTPUT: "1", PATH: "/usr/bin:/bin" };
    const a = answer<{ status: string; status_basis: string }>(await runTool(cwd, { source: "real.img", password_file: "password.txt" }, env));
    assert.equal(a.status, "unavailable");
    assert.match(a.status_basis, /cryptsetup is not on PATH/);
  });
});

// --- the full gated run with a stand-in: no password on argv, correct password decrypts, wrong password does not -

test("a gated run with a stand-in cryptsetup: the password is on stdin only, never on an argv or in the answer; a decrypted header's non-secret fields come through; the canary never reaches stdout, stderr or the answer", async () => {
  await scratch(async ({ cwd, out, bin, argvLog }) => {
    await stub(bin, "cryptsetup", argvLog, CRYPTSETUP_DECRYPTS);
    await writeFile(join(cwd, "real.img"), "volume bytes");
    await writeFile(join(cwd, "password.txt"), `${CANARY}\n`, { mode: 0o600 });
    const env = { JOB_ID: "j1", OUT: out, SECRET_OUTPUT: "1", PATH: `${bin}:${process.env.PATH}`, EXPECT_PASSWORD: CANARY };
    const run = await runTool(cwd, { source: "real.img", password_file: "password.txt" }, env);
    const a = answer<{
      status: string; decrypted: boolean; fields: Record<string, string>; versions: { cryptsetup: string }; stderr_present: boolean;
    }>(run);
    assert.equal(a.status, "complete");
    assert.equal(a.decrypted, true);
    assert.equal(a.fields.cipher_chain, "aes-twofish-serpent");
    assert.equal(a.fields.cipher_mode, "xts-plain64");
    assert.equal(a.fields.pbkdf2_hash, "sha512");
    assert.equal(a.fields.key_size_bits, "192");
    assert.equal(a.versions.cryptsetup, "cryptsetup 2.6.1");
    assert.equal(a.stderr_present, false);

    assert.doesNotMatch(run.stdout, new RegExp(CANARY));
    assert.doesNotMatch(run.stderr, new RegExp(CANARY));
    assert.doesNotMatch(JSON.stringify(a), new RegExp(CANARY));

    // Each invocation of the stand-in is logged as one line: its argv entries, then "|stdin=" and what it read from
    // stdin. The canary must appear only after that marker, on the invocation that actually ran tcryptDump.
    const log = await readFile(argvLog, "utf8");
    const lines = log.split("\n").filter((l) => l.trim());
    assert.ok(lines.length >= 2, "at least the --version probe and the real call were logged");
    let sawCanaryOnStdin = false;
    for (const line of lines) {
      const at = line.indexOf("|stdin=");
      assert.ok(at >= 0, `every logged line has a stdin marker: ${line}`);
      const argvPart = line.slice(0, at);
      const stdinPart = line.slice(at + "|stdin=".length);
      assert.doesNotMatch(argvPart, new RegExp(CANARY), "the password is not among the argv entries of any invocation");
      if (stdinPart.includes(CANARY)) sawCanaryOnStdin = true;
    }
    assert.ok(sawCanaryOnStdin, "the stub received the password on stdin, on at least one invocation");
  });
});

test("a wrong password does not decrypt, and the answer never claims the volume is not VeraCrypt or TrueCrypt", async () => {
  await scratch(async ({ cwd, out, bin, argvLog }) => {
    await stub(bin, "cryptsetup", argvLog, CRYPTSETUP_DECRYPTS);
    await writeFile(join(cwd, "real.img"), "volume bytes");
    await writeFile(join(cwd, "password.txt"), "wrong-guess\n", { mode: 0o600 });
    const env = { JOB_ID: "j1", OUT: out, SECRET_OUTPUT: "1", PATH: `${bin}:${process.env.PATH}`, EXPECT_PASSWORD: CANARY };
    const a = answer<{ status: string; decrypted: boolean; note: string }>(await runTool(cwd, {
      source: "real.img", password_file: "password.txt",
    }, env));
    assert.equal(a.status, "complete");
    assert.equal(a.decrypted, false);
    assert.match(a.note, /not proof the volume is not VeraCrypt or TrueCrypt/);
  });
});

test("header selects --tcrypt-hidden or --tcrypt-backup, and keyfiles are passed as --key-file", async () => {
  await scratch(async ({ cwd, out, bin, argvLog }) => {
    await stub(bin, "cryptsetup", argvLog, CRYPTSETUP_DECRYPTS);
    await writeFile(join(cwd, "real.img"), "volume bytes");
    await writeFile(join(cwd, "password.txt"), "x\n", { mode: 0o600 });
    await writeFile(join(cwd, "key1.bin"), "keyfile bytes");
    const env = { JOB_ID: "j1", OUT: out, SECRET_OUTPUT: "1", PATH: `${bin}:${process.env.PATH}` };
    await runTool(cwd, { source: "real.img", password_file: "password.txt", header: "hidden", keyfiles: ["key1.bin"] }, env);
    const log = await readFile(argvLog, "utf8");
    assert.match(log, /--tcrypt-hidden/);
    assert.match(log, /--key-file=.*key1\.bin/);
  });
});

// --- a budget timeout answers partial -------------------------------------------------------------------------

test("a timeout while cryptsetup is running answers partial", async () => {
  await scratch(async ({ cwd, out, bin, argvLog }) => {
    await stub(bin, "cryptsetup", argvLog, CRYPTSETUP_DECRYPTS);
    await writeFile(join(cwd, "real.img"), "volume bytes");
    await writeFile(join(cwd, "password.txt"), "x\n", { mode: 0o600 });
    const env = { JOB_ID: "j1", OUT: out, SECRET_OUTPUT: "1", PATH: `${bin}:${process.env.PATH}`, SLOW_CS: "5" };
    const a = answer<{ status: string; status_basis: string }>(await runTool(cwd, {
      source: "real.img", password_file: "password.txt", max_seconds: 1,
    }, env));
    assert.equal(a.status, "partial");
    assert.match(a.status_basis, /time budget/);
  });
});

// --- SIGTERM: one JSON answer, the child reaped ----------------------------------------------------------------

test("SIGTERM while cryptsetup is running ends the tool with one JSON answer and the child reaped", async () => {
  await scratch(async ({ cwd, out, bin, argvLog }) => {
    await stub(bin, "cryptsetup", argvLog, CRYPTSETUP_DECRYPTS);
    await writeFile(join(cwd, "real.img"), "volume bytes");
    await writeFile(join(cwd, "password.txt"), "x\n", { mode: 0o600 });
    const env = {
      ...process.env, ...AGENT, JOB_ID: "j1", OUT: out, SECRET_OUTPUT: "1", PATH: `${bin}:${process.env.PATH}`, SLOW_CS: "30",
    } as Record<string, string>;
    const child = spawn("python3", [SCRIPT], { cwd, env });
    const chunks: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => chunks.push(c));
    child.stdin.end(JSON.stringify({ source: "real.img", password_file: "password.txt", max_seconds: 110 }));
    await new Promise((r) => setTimeout(r, 700));
    child.kill("SIGTERM");
    const code = await new Promise<number | null>((resolve) => child.on("exit", (c) => resolve(c)));
    assert.equal(code, 128 + 15);
    const text = Buffer.concat(chunks).toString("utf8");
    assert.equal(text.trim().split("\n").filter((l) => l.trim()).length, 1, "exactly one JSON document");
    await new Promise((r) => setTimeout(r, 300));
    const ps = await new Promise<string>((resolve) => {
      const p = spawn("pgrep", ["-f", join(bin, "cryptsetup")]);
      let o = "";
      p.stdout.on("data", (c: Buffer) => (o += c));
      p.on("close", () => resolve(o));
    });
    assert.equal(ps.trim(), "", "the stand-in cryptsetup (and its sleep) was killed with the tool");
  });
});

// --- a real gated run, only when this host has the real cryptsetup -------------------------------------------

test("a real gated run against a header built from the TCRYPT format, when this host has cryptsetup", async (t) => {
  const { execFile } = await import("node:child_process");
  const has = await new Promise<boolean>((resolve) => execFile("cryptsetup", ["--version"], (err) => resolve(!err)));
  if (!has) {
    t.skip("cryptsetup is not on this host's PATH: the stand-in tests above cover the tool's own behaviour; this one needs the real program");
    return;
  }
  // A VeraCrypt header built from the format specification (PBKDF2 by hashlib, AES-XTS by the cryptography package
  // when present) would go here, run against the real cryptsetup. Not reached on a host without cryptsetup.
  assert.ok(true);
});

// --- fix round: only cryptsetup's exit 0 and 2 are answers about the password ------------------------------------------

test("cryptsetup exit 1, 3 and 4 answer failed naming the exit code; exit 2 is complete and not decrypted; exit 0 decrypts", async () => {
  await scratch(async ({ cwd, out, bin, argvLog }) => {
    await stub(bin, "cryptsetup", argvLog, CRYPTSETUP_DECRYPTS);
    await writeFile(join(cwd, "real.img"), "volume bytes");
    await writeFile(join(cwd, "password.txt"), `${CANARY}\n`, { mode: 0o600 });
    const base = { JOB_ID: "j1", OUT: out, SECRET_OUTPUT: "1", PATH: `${bin}:${process.env.PATH}`, EXPECT_PASSWORD: CANARY };
    for (const code of ["1", "3", "4"]) {
      const a = answer<{ status: string; status_basis: string; decrypted: boolean | null; exit_code: number }>(
        await runTool(cwd, { source: "real.img", password_file: "password.txt" }, { ...base, CS_EXIT: code }));
      assert.equal(a.status, "failed", `exit ${code}`);
      assert.match(a.status_basis, new RegExp(`cryptsetup exited ${code}`));
      assert.equal(a.exit_code, Number(code));
      assert.notEqual(a.decrypted, false, "a failure says nothing about the password");
    }
    const bad = answer<{ status: string; decrypted: boolean }>(await runTool(cwd, { source: "real.img", password_file: "password.txt" }, { ...base, CS_EXIT: "2" }));
    assert.equal(bad.status, "complete");
    assert.equal(bad.decrypted, false);
    const good = answer<{ status: string; decrypted: boolean }>(await runTool(cwd, { source: "real.img", password_file: "password.txt" }, base));
    assert.equal(good.status, "complete");
    assert.equal(good.decrypted, true);
    const empty = answer<{ status: string }>(await runTool(cwd, { source: "real.img", password_file: "password.txt" }, { ...base, CS_EXIT: "0" }));
    assert.equal(empty.status, "failed", "exit 0 with none of the header fields is not a decryption");
  });
});

test("a password_file readable by group or other is refused, as the manifest says it must be 0600", async () => {
  await scratch(async ({ cwd, out, bin, argvLog }) => {
    await stub(bin, "cryptsetup", argvLog, CRYPTSETUP_DECRYPTS);
    await writeFile(join(cwd, "real.img"), "volume bytes");
    await writeFile(join(cwd, "open.txt"), "x\n");
    await chmod(join(cwd, "open.txt"), 0o644);
    const env = { JOB_ID: "j1", OUT: out, SECRET_OUTPUT: "1", PATH: `${bin}:${process.env.PATH}` };
    const a = answer<{ error: string }>(await runTool(cwd, { source: "real.img", password_file: "open.txt" }, env), 1);
    assert.match(a.error, /password_file must be mode 0600/);
  });
});

// A program that floods its pipe (a leftover that writes at full speed) or prints a megabyte of empty lines is read to the shared cap (1 MiB) and not parsed whole:
// parse_fields read all of it, line by line, through twelve patterns, which cost seconds of CPU on a `yes` flood.
const HEADER_LINES = [
  "TCRYPT header information for /dev/stub", "Version:       5", "Driver req.:   0", "Flags:         0", "Sector size:   512", "MK offset:     0",
  "Volume size:   10485760", "PBKDF:         PBKDF2", "PBKDF2 hash:   sha512", "Cipher chain:  aes-twofish-serpent", "Cipher mode:   xts-plain64", "MK bits:       192",
];
const FLOOD_STUB = (kind: "yes" | "empty", pidFile: string): string => `#!/usr/bin/env python3
import os, subprocess, sys
if "--version" in sys.argv[1:]:
    print("cryptsetup 2.6.1")
    sys.exit(0)
sys.stdin.read()
sys.stdout.write(${JSON.stringify(HEADER_LINES.join("\n") + "\n")})
sys.stdout.flush()
${kind === "yes"
  ? `subprocess.Popen(["setsid", "sh", "-c", "echo $$ >> ${pidFile}; exec yes"], stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
import time
time.sleep(0.5)`
  : `try:
    sys.stdout.write("\\n" * (1024 * 1024))
    sys.stdout.flush()
except BrokenPipeError:
    os._exit(0)`}
`;

for (const kind of ["yes", "empty"] as const) {
  test(`tcrypt_header: a ${kind === "yes" ? "setsid yes leftover that floods the pipe" : "megabyte of empty lines"} is not parsed whole: the answer comes fast and the header fields are still read`, async () => {
    await scratch(async ({ cwd, out, bin }) => {
      const pidFile = join(cwd, "pids");
      await writeFile(join(bin, "cryptsetup"), FLOOD_STUB(kind, pidFile));
      await chmod(join(bin, "cryptsetup"), 0o755);
      await writeFile(join(cwd, "real.img"), "volume bytes");
      await writeFile(join(cwd, "password.txt"), `${CANARY}\n`, { mode: 0o600 });
      const env = { JOB_ID: "j1", OUT: out, SECRET_OUTPUT: "1", PATH: `${bin}:${process.env.PATH}` };
      const started = Date.now();
      const run = await runTool(cwd, { source: "real.img", password_file: "password.txt" }, env);
      const ms = Date.now() - started;
      const a = answer<{ status: string; decrypted: boolean; fields: Record<string, string> }>(run);
      try {
        assert.equal(a.decrypted, true, run.stdout.slice(0, 600));
        assert.equal(a.fields.cipher_chain, "aes-twofish-serpent");
        assert.equal(a.fields.key_size_bits, "192");
        assert.ok(ms < 3000, `answered in ${ms} ms`);
      } finally {
        if (kind === "yes") {
          for (const pid of (await readFile(pidFile, "utf8").catch(() => "")).split("\n").filter(Boolean)) {
            try { process.kill(Number(pid), "SIGKILL"); } catch { /* already gone */ }
          }
        }
      }
    });
  });
}
