/**
 * macos_triage runs the pinned mac_apt (1.33.2, amd64 image only) and reads its LOG for one status per plugin. mac_apt is NOT installed in this
 * test machine and was never run to build the tool: every case below drives the tool with a stand-in `mac_apt.py` written here from what was READ in
 * the source of v1.33.2 (the argument shape, the log file name and the texts of the start, plugin start, plugin end, plugin exception and finish
 * lines). The prefix of a log line, the wording of an empty or unsupported plugin and the per-plugin file names were NOT read and are invented here
 * (and the tool must not depend on the prefix: one case uses a second style and one none). So these cases prove the tool's reading of those shapes,
 * its refusals, its process handling and its answers, and nothing about a real mac_apt run.
 *
 * Held: a plugin is `parsed` only from lines the tool recognises (a traceback, an error line, an exception, a missing end line are `failed` however
 * the stand-in exits); an exit 0 after logged errors is not complete; ALL and FAST are at best partial; a log with no start line (a wrong input
 * mode) is failed; a mismatched input type is refused before the program starts; a password is only a sealed file passed as -pf and never read;
 * a hang is ended at the tool's own deadline with its children; SIGTERM ends the tool and the program with one JSON answer; a rerun makes a
 * directory of its own; nothing is written outside the run directory; no log text reaches the answer; the manifest declares secret_output required.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { chmod, lstat, mkdir, readFile, readdir, stat, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { withCwd } from "./tool-library-harness.ts";
import { MAC, body, filesUnder, leader, ok, secretJob, signalled, tool } from "./macos-late-harness.ts";
import type { Json } from "./macos-late-harness.ts";
import { NO_ADOPTION } from "./host-gates.ts";

const TRIAGE = join(MAC, "macos_triage", "run.py");

const PRE = `
import os, signal, sys, time
argv = sys.argv[1:]
HERE = os.path.dirname(os.path.abspath(__file__))
if argv == ["-h"]:
    print("usage: mac_apt.py [-h] [-o OUTPUT_PATH] input_type input_path plugin [plugin ...]")
    print()
    print("macOS Artifact Parsing Tool, version 1.33.2")
    sys.exit(0)
TYPES = ["AFF4", "AXIOMZIP", "DD", "DMG", "E01", "MOUNTED", "SPARSE", "UAC", "VMDK", "VR"]
out = argv[argv.index("-o") + 1]
ti = [i for i, a in enumerate(argv) if a in TYPES][0]
itype, inp, plugins = argv[ti], argv[ti + 1], argv[ti + 2:]
LOG = os.path.join(out, "Log.20261104-120000.txt")
FORMAT = "__FORMAT__"
def log(line, level="INFO"):
    with open(LOG, "a") as f:
        f.write(FORMAT % (level, line) + "\\n")
def start():
    log("Started macOS Artifact Parsing Tool, version 1.33.2")
def plugin(name, lines=(), ran=True):
    log("-" * 50)
    log("Running plugin " + name)
    for l in lines:
        log(l)
    if ran:
        log(name + " plugin ran for 00:00:01")
def finish():
    log("Finished in time = 00:00:02")
    log("Review the Log file and report any ERRORs or EXCEPTIONS to the developers")
`;

async function stand(bin: string, script: string, format = "2026-11-04 12:00:00,000|MAIN|%s|%s"): Promise<void> {
  await mkdir(bin, { recursive: true });
  const file = join(bin, "mac_apt.py");
  await writeFile(file, `#!/usr/bin/env python3\n${PRE.replace('"__FORMAT__"', JSON.stringify(format))}\n${script}\n`);
  await chmod(file, 0o755);
}

const OK_TWO = `
start()
plugin("TCC", ["Processed 3 rows"])
plugin("BASHSESSIONS", ["Processed 1 file"])
finish()
`;

/** An E01-looking file: the signature the tool checks before it starts the program. */
async function e01(cwd: string, name = "mac.E01"): Promise<string> {
  await writeFile(join(cwd, "work", name), Buffer.concat([Buffer.from([0x45, 0x56, 0x46, 0x09, 0x0d, 0x0a, 0xff, 0x00]), Buffer.alloc(4096)]));
  return `work/${name}`;
}
const run = async (cwd: string, bin: string, args: Json, env: Record<string, string> = {}) => secretJob(TRIAGE, cwd, args, env, bin);
const alive = (pid: number): boolean => {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
};
async function gone(pids: number[], ms = 5000): Promise<boolean> {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (!pids.some(alive)) return true;
    await new Promise((r) => setTimeout(r, 100));
  }
  return !pids.some(alive);
}
const pidsOf = async (file: string): Promise<number[]> => (await readFile(file, "utf8").catch(() => "")).split(/\s+/).filter(Boolean).map(Number);
/** Where an answer's shown path really is: store/jobs/<job>/out/... is the job's out/ directory. */
const real = (cwd: string, shown: string): string => join(cwd, "out", shown.replace(/^store\/jobs\/[^/]+\/out\//, ""));
const status = (a: Json, name: string): string => a.plugins.find((p: Json) => p.plugin === name)?.status;

test("explicit plugins that the log shows run to their end are parsed and the run is complete; the argv and the version are recorded", { skip: NO_ADOPTION }, async () => {
  await withCwd(async (cwd, bin) => {
    await stand(bin, `open(os.path.join(HERE, "argv.txt"), "w").write(repr(argv))\n${OK_TWO}`);
    const a = ok(await run(cwd, bin, { path: await e01(cwd), input_type: "e01", plugins: ["tcc", "BashSessions"], formats: ["csv", "jsonl"] }));
    assert.equal(a.status, "complete", a.status_basis + JSON.stringify(a.problems));
    assert.equal(a.reader.version_line, "1.33.2");
    assert.deepEqual(a.counts, { parsed: 2, empty: 0, unsupported: 0, failed: 0, not_started: 0 });
    assert.equal(status(a, "TCC"), "parsed");
    assert.equal(a.input_type, "E01");
    assert.deepEqual(a.plugins_requested, ["TCC", "BASHSESSIONS"]);
    assert.equal(a.log.started, true);
    assert.equal(a.log.finished, true);
    assert.match(a.log_source, /^the log file mac_apt writes/);
    assert.match(a.source_basis.not_observed, /never observed/);
    const argv = (await readFile(join(bin, "argv.txt"), "utf8")).replaceAll("'", "");
    assert.match(argv, /^\[-o, [^,]+\/out, -c, -j, E01, [^,]*work\/mac\.E01, TCC, BASHSESSIONS\]$/, argv);
    assert.deepEqual(a.argv.slice(-4), ["E01", "<input>", "TCC", "BASHSESSIONS"]);
    assert.equal(((await stat(real(cwd, a.stdout_file))).mode & 0o777).toString(8), "600");
    assert.ok(a.plugins_file.endsWith("plugins.json"));
  });
});

test("a log without the line shape (time|logger|LEVEL|message, read from the source and never observed) is not recognised: failed, never complete", async () => {
  await withCwd(async (cwd, bin) => {
    await stand(bin, OK_TWO, "%.0s%s");
    const a = body(await run(cwd, bin, { path: await e01(cwd), input_type: "E01", plugins: ["TCC", "BASHSESSIONS"] }));
    assert.equal(a.status, "failed");
    assert.ok(a.log.unanchored_lines >= 4);
    assert.match(a.problems.join("\n"), /without the line shape/);
  });
});

test("ALL and FAST are at best partial: the plugins they expand to are not listed by anything read", async () => {
  await withCwd(async (cwd, bin) => {
    await stand(bin, OK_TWO);
    for (const plugins of [undefined, ["ALL"], ["FAST", "SPOTLIGHT-"]]) {
      const a = ok(await run(cwd, bin, { path: await e01(cwd), input_type: "E01", ...(plugins ? { plugins } : {}) }));
      assert.equal(a.status, "partial", JSON.stringify(plugins));
      assert.match(a.problems.join("\n"), /expands to are not listed|plugins mac_apt expands it to/);
      assert.equal(a.counts.parsed, 2);
    }
  });
});

test("an exit 0 after a traceback in a plugin's run is failed for that plugin and never complete", async () => {
  await withCwd(async (cwd, bin) => {
    await stand(bin, `
start()
plugin("TCC", ["Processed 3 rows"])
plugin("KEYCHAINS", ["Traceback (most recent call last):", '  File "x.py", line 1, in <module>', "KeyError: 1"], ran=False)
log("An exception occurred while running plugin - KEYCHAINS", "ERROR")
plugin("BASHSESSIONS", ["Processed 1 file"])
finish()
`);
    const r = await run(cwd, bin, { path: await e01(cwd), input_type: "E01", plugins: ["TCC", "KEYCHAINS", "BASHSESSIONS"] });
    const a = ok(r);
    assert.equal(a.exit_code, 0);
    assert.equal(a.status, "partial");
    assert.equal(status(a, "KEYCHAINS"), "failed");
    assert.equal(status(a, "TCC"), "parsed");
    assert.equal(status(a, "BASHSESSIONS"), "parsed");
    assert.equal(a.counts.failed, 1);
    assert.doesNotMatch(r.stdout, /KeyError|x\.py/, "no log text in the answer");
  });
});

test("an error line inside a plugin's run, with the plugin's end line present, is failed", async () => {
  await withCwd(async (cwd, bin) => {
    await stand(bin, `start()\nplugin("TCC", ["x"])\nlog("-" * 50)\nlog("Running plugin SAFARI")\nlog("db problem", "ERROR")\nlog("SAFARI plugin ran for 00:00:01")\nfinish()\n`);
    const a = ok(await run(cwd, bin, { path: await e01(cwd), input_type: "E01", plugins: ["TCC", "SAFARI"] }));
    assert.equal(a.status, "partial");
    assert.equal(status(a, "SAFARI"), "failed");
    assert.equal(status(a, "TCC"), "parsed");
  });
});

test("a plugin whose run holds only lines saying nothing was found is empty; a warning alone does not fail it", { skip: NO_ADOPTION }, async () => {
  await withCwd(async (cwd, bin) => {
    await stand(bin, `start()\nplugin("QUARANTINE", ["No quarantine entries found"])\nplugin("TCC", ["rows"])\nplugin("WARNED", ["fine"])\nfinish()\n`);
    const a = ok(await run(cwd, bin, { path: await e01(cwd), input_type: "E01", plugins: ["QUARANTINE", "TCC", "WARNED"] }));
    assert.equal(status(a, "QUARANTINE"), "empty");
    assert.equal(status(a, "TCC"), "parsed");
    assert.equal(a.status, "complete", a.status_basis + JSON.stringify(a.problems));
    await stand(bin, `start()\nplugin("WARNED", ["fine", "odd thing"])\nlog("careful", "WARNING")\nfinish()\n`);
    const w = ok(await run(cwd, bin, { path: await e01(cwd), input_type: "E01", plugins: ["WARNED"] }));
    assert.equal(w.plugins[0].status, "parsed");
  });
});

test("a plugin that says it does not support something is unsupported; mac_apt finding no macOS installation makes every requested plugin unsupported and the run failed", async () => {
  await withCwd(async (cwd, bin) => {
    await stand(bin, `start()\nplugin("OLDONE", ["This artifact is not supported on this macOS version"])\nplugin("TCC", ["rows"])\nfinish()\n`);
    const a = ok(await run(cwd, bin, { path: await e01(cwd), input_type: "E01", plugins: ["OLDONE", "TCC"] }));
    assert.equal(status(a, "OLDONE"), "unsupported");
    assert.equal(a.status, "partial");
    await stand(bin, `start()\nlog("Could not find OSX/macOS installation!", "ERROR")\nlog("Finished in time = 00:00:01")\n`);
    const r = await run(cwd, bin, { path: await e01(cwd), input_type: "E01", plugins: ["TCC", "BASHSESSIONS"] });
    const n = body(r);
    assert.equal(r.code, 1);
    assert.equal(n.status, "failed");
    assert.equal(n.log.no_macos_installation, true);
    assert.deepEqual(n.plugins.map((p: Json) => p.status), ["unsupported", "unsupported"]);
    assert.equal(n.counts.not_started, 2);
  });
});

test("a log that stops before the finish line, or a plugin with no end line, is partial; nothing is parsed from it", async () => {
  await withCwd(async (cwd, bin) => {
    await stand(bin, `start()\nplugin("TCC", ["rows"])\nplugin("SAFARI", ["rows"], ran=False)\n`);
    const a = ok(await run(cwd, bin, { path: await e01(cwd), input_type: "E01", plugins: ["TCC", "SAFARI"] }));
    assert.equal(a.status, "partial");
    assert.equal(status(a, "TCC"), "parsed");
    assert.equal(status(a, "SAFARI"), "failed");
    assert.match(a.problems.join("\n"), /finish line/);
  });
});

test("a requested plugin that never started is failed (not started), and a plugin nobody asked for does not hide it", async () => {
  await withCwd(async (cwd, bin) => {
    await stand(bin, `start()\nplugin("TCC", ["rows"])\nplugin("OTHER", ["rows"])\nfinish()\n`);
    const a = ok(await run(cwd, bin, { path: await e01(cwd), input_type: "E01", plugins: ["TCC", "SAFARI"] }));
    assert.equal(a.status, "partial");
    assert.equal(status(a, "SAFARI"), "failed");
    assert.equal(a.counts.not_started, 1);
  });
});

test("a wrong input mode as mac_apt sees it (no start line, exit 0) is failed; a mismatched input type is refused before the program starts", async () => {
  await withCwd(async (cwd, bin) => {
    await stand(bin, `print("Exiting -> something went wrong")\nsys.exit(0)\n`);
    const r = await run(cwd, bin, { path: await e01(cwd), input_type: "E01", plugins: ["TCC"] });
    const a = body(r);
    assert.equal(r.code, 1);
    assert.equal(a.status, "failed");
    assert.equal(a.exit_code, 0);
    assert.match(a.status_basis, /nothing was recognised as a mac_apt run/);
    // a text file is not an E01, a folder is not a DMG, a file is not MOUNTED, a plain file is not a UAC collection
    await writeFile(join(cwd, "work", "t.txt"), "text");
    await mkdir(join(cwd, "work", "dir"), { recursive: true });
    await stand(bin, `open(os.path.join(HERE, "ran.txt"), "w").write("ran")\n${OK_TWO}`);
    for (const [path, type, re] of [
      ["work/t.txt", "E01", /EVF signature/],
      ["work/dir", "DMG", /not a regular file/],
      ["work/t.txt", "MOUNTED", /takes a folder/],
      ["work/t.txt", "UAC", /\.zip, \.tar/],
      ["work/t.txt", "DMG", /koly/],
      ["work/t.txt", "SPARSE", /signature/],
      ["work/t.txt", "VMDK", /VMDK/],
      ["work/t.txt", "AFF4", /zip/],
      ["work/missing", "DD", /does not exist/],
    ] as const) {
      const x = await run(cwd, bin, { path, input_type: type, plugins: ["TCC"] });
      const j = body(x);
      assert.equal(x.code, 1, `${path} ${type}`);
      assert.equal(j.status, "failed");
      assert.match(j.error, re, `${path} ${type}`);
    }
    assert.equal(await readFile(join(bin, "ran.txt"), "utf8").catch(() => null), null, "mac_apt never started for a refused input");
    await symlink(join(cwd, "work", "t.txt"), join(cwd, "work", "link.dd"));
    const l = body(await run(cwd, bin, { path: "work/link.dd", input_type: "DD", plugins: ["TCC"] }));
    assert.match(l.error, /symbolic link/);
    assert.equal((await run(cwd, bin, { path: "work/dir", input_type: "MOUNTED", plugins: ["TCC"] })).code, 0, "a folder is MOUNTED");
  });
});

test("arguments: an unknown one (a password among them), a bad input type, bad plugin names and bad formats are refused as JSON before anything is made", async () => {
  await withCwd(async (cwd, bin) => {
    await stand(bin, OK_TWO);
    const path = await e01(cwd);
    const cases: Array<[Json, RegExp]> = [
      [{ path, input_type: "E01", password: "x" }, /unknown argument/],
      [{ path, input_type: "E01", p: "x" }, /unknown argument/],
      [{ path, input_type: "ISO" }, /input_type is required/],
      [{ path }, /input_type is required/],
      [{ input_type: "E01" }, /path is required/],
      [{ path, input_type: "E01", plugins: [] }, /plugins must be/],
      [{ path, input_type: "E01", plugins: ["TCC", "tcc"] }, /twice/],
      [{ path, input_type: "E01", plugins: ["-o"] }, /plugins must be/],
      [{ path, input_type: "E01", plugins: ["A B"] }, /plugins must be/],
      [{ path, input_type: "E01", formats: ["pdf"] }, /formats must be/],
      [{ path, input_type: "E01", max_seconds: -1 }, /max_seconds/],
      [{ path, input_type: "E01", already_decrypted: "yes" }, /already_decrypted/],
    ];
    for (const [args, re] of cases) {
      const r = await run(cwd, bin, args);
      assert.equal(r.code, 1, JSON.stringify(args));
      const a = body(r);
      assert.equal(a.status, "failed");
      assert.match(a.error, re, JSON.stringify(args));
      assert.equal(typeof a.status_basis, "string");
    }
    assert.deepEqual(await readdir(join(cwd, "out")), [], "nothing was made");
  });
});

test("a FileVault password is only a sealed file passed as -pf: the file is checked and never read, a loose mode is refused, and its content is nowhere", { skip: NO_ADOPTION }, async () => {
  await withCwd(async (cwd, bin) => {
    await stand(bin, `open(os.path.join(HERE, "argv.txt"), "w").write(repr(argv))\n${OK_TWO}`);
    const canary = "Vault-Canary-0f1e2d3c4b5a69788796";
    await writeFile(join(cwd, "work", "pw.txt"), canary, { mode: 0o644 });
    await chmod(join(cwd, "work", "pw.txt"), 0o644);
    const path = await e01(cwd);
    const loose = body(await run(cwd, bin, { path, input_type: "E01", plugins: ["TCC"], password_file: "work/pw.txt" }));
    assert.match(loose.error, /mode 0600/);
    await chmod(join(cwd, "work", "pw.txt"), 0o600);
    const r = await run(cwd, bin, { path, input_type: "E01", plugins: ["TCC", "BASHSESSIONS"], password_file: "work/pw.txt" });
    const a = ok(r);
    assert.equal(a.status, "complete");
    assert.equal(a.password_file_used, true);
    assert.ok(a.argv.includes("<password_file>"));
    const argv = await readFile(join(bin, "argv.txt"), "utf8");
    assert.match(argv, /'-pf', 'work\/pw\.txt'/);
    assert.ok(!argv.includes(canary), "the secret is not in argv");
    for (const f of await filesUnder(cwd)) {
      if (f.endsWith("pw.txt")) continue;
      assert.ok(!(await readFile(f)).includes(canary), f);
    }
    assert.ok(!r.stdout.includes(canary) && !r.stderr.includes(canary));
    await symlink(join(cwd, "work", "pw.txt"), join(cwd, "work", "pwl.txt"));
    assert.match(body(await run(cwd, bin, { path, input_type: "E01", password_file: "work/pwl.txt" })).error, /not a regular file/);
    assert.match(body(await run(cwd, bin, { path, input_type: "E01", password_file: "work/pw.txt", already_decrypted: true })).error, /opposite/);
    const d = ok(await run(cwd, bin, { path, input_type: "E01", plugins: ["TCC", "BASHSESSIONS"], already_decrypted: true }));
    assert.equal(d.already_decrypted, true);
    assert.match((await readFile(join(bin, "argv.txt"), "utf8")), /'-d'/);
  });
});

test("a missing mac_apt.py (the arm64 image leaves it out) is a failed answer with exit 1 and the packaging reason, never an empty result", async () => {
  await withCwd(async (cwd) => {
    const r = await secretJob(TRIAGE, cwd, { path: await e01(cwd), input_type: "E01", plugins: ["TCC"] }, { PATH: "/usr/bin:/bin" });
    const a = body(r);
    assert.equal(r.code, 1);
    assert.equal(a.status, "failed");
    assert.equal(a.reader.found, null);
    assert.match(a.status_basis, /not installed/);
    assert.match(a.problems.join(" "), /mac_apt\.py .*not on PATH|statx helper/);
    assert.equal(a.plugins, undefined);
  });
});

test("a nonzero exit, a log read from the console, and a version the pin does not name are each partial at best", async () => {
  await withCwd(async (cwd, bin) => {
    const path = await e01(cwd);
    await stand(bin, `${OK_TWO}\nsys.exit(3)\n`);
    const a = ok(await run(cwd, bin, { path, input_type: "E01", plugins: ["TCC", "BASHSESSIONS"] }));
    assert.equal(a.status, "partial");
    assert.equal(a.exit_code, 3);
    // no Log.<time>.txt: the lines go to the console only
    await stand(bin, `
def con(line): print("12:00:00|MAIN|INFO|" + line)
con("Started macOS Artifact Parsing Tool, version 1.33.2")
con("Running plugin TCC")
con("TCC plugin ran for 00:00:01")
con("Finished in time = 00:00:01")
`);
    const c = ok(await run(cwd, bin, { path, input_type: "E01", plugins: ["TCC"] }));
    assert.equal(c.status, "partial");
    assert.match(c.log_source, /no Log\.<time>\.txt was found/);
    assert.equal(status(c, "TCC"), "parsed");
    await stand(bin, `start()\nplugin("TCC", ["rows"])\nfinish()\n`);
    await writeFile(join(bin, "mac_apt.py"), (await readFile(join(bin, "mac_apt.py"), "utf8")).replaceAll("version 1.33.2", "version 1.36.2"));
    const v = ok(await run(cwd, bin, { path, input_type: "E01", plugins: ["TCC"] }));
    assert.equal(v.status, "partial");
    assert.match(v.problems.join("\n"), /pack pins 1\.33\.2/);
  });
});

test("a hang is ended at the tool's own deadline with what it started; the log written so far is read, and the run is not complete", async () => {
  await withCwd(async (cwd, bin) => {
    const pids = join(cwd, "pids.txt");
    await stand(bin, `
start()
plugin("TCC", ["rows"])
log("Running plugin SLOW")
import subprocess
c = subprocess.Popen(["sleep", "300"])
open(${JSON.stringify(pids)}, "a").write("%d %d\\n" % (os.getpid(), c.pid))
time.sleep(300)
`);
    const t0 = Date.now();
    const r = await run(cwd, bin, { path: await e01(cwd), input_type: "E01", plugins: ["TCC", "SLOW"], max_seconds: 2 });
    const a = body(r);
    assert.ok(Date.now() - t0 < 30_000);
    assert.equal(a.timed_out, true);
    assert.equal(a.status, "partial");
    assert.equal(status(a, "SLOW"), "failed");
    assert.equal(status(a, "TCC"), "parsed");
    assert.match(a.problems.join("\n"), /did not end in 2 seconds/);
    assert.ok(await gone(await pidsOf(pids)), "mac_apt and its child are gone");
  });
});

test("a flood on stdout is ended at max_output_bytes and kept whole on disk", async () => {
  await withCwd(async (cwd, bin) => {
    await stand(bin, `start()\nplugin("TCC", ["rows"])\nline = "x" * 1023 + "\\n"\nwhile True:\n    sys.stdout.write(line * 64)\n    sys.stdout.flush()\n`);
    const a = ok(await run(cwd, bin, { path: await e01(cwd), input_type: "E01", plugins: ["TCC"], max_output_bytes: 2_000_000, max_seconds: 60 }).then((r) => ({ ...r, code: 0 })));
    assert.equal(a.output_capped, true);
    assert.notEqual(a.status, "complete");
    assert.ok((await stat(real(cwd, a.stdout_file))).size >= 2_000_000);
  });
});

test("SIGTERM ends the tool and mac_apt with its child: one JSON answer, exit 143, partial with the plugins read before the stop", async () => {
  await withCwd(async (cwd, bin) => {
    const pids = join(cwd, "pids.txt");
    await stand(bin, `
start()
plugin("TCC", ["rows"])
log("Running plugin SLOW")
import subprocess
c = subprocess.Popen(["sleep", "300"])
open(${JSON.stringify(pids)}, "a").write("%d %d\\n" % (os.getpid(), c.pid))
time.sleep(300)
`);
    await mkdir(join(cwd, "out"), { recursive: true });
    const path = await e01(cwd);
    const done = signalled(TRIAGE, cwd, { path, input_type: "E01", plugins: ["TCC", "SLOW"] }, "SIGTERM", 2500, { JOB_ID: "j-1", OUT: join(cwd, "out"), SECRET_OUTPUT: "1" }, bin);
    const r = await done;
    assert.equal(r.code, 143, r.stderr);
    const a = body(r);
    assert.equal(a.interrupted, "SIGTERM");
    assert.equal(a.status, "partial", JSON.stringify(a));
    assert.ok(await gone(await pidsOf(pids)));
  });
});

test("a program that ends while a child holds its descriptors does not hold the tool, and the child is ended", async () => {
  await withCwd(async (cwd, bin) => {
    const pids = join(cwd, "pids.txt");
    await stand(bin, `
start()
plugin("TCC", ["rows"])
finish()
import subprocess
c = subprocess.Popen(["sleep", "300"])
open(${JSON.stringify(pids)}, "a").write("%d\\n" % c.pid)
`);
    const t0 = Date.now();
    const a = body(await leader(TRIAGE, cwd, { path: await e01(cwd), input_type: "E01", plugins: ["TCC"] }, { JOB_ID: "j-1", OUT: join(cwd, "out"), SECRET_OUTPUT: "1" }, bin));
    assert.ok(Date.now() - t0 < 30_000);
    assert.equal(a.status, "partial", "a daemon left holding the pipes is a problem the answer names");
    assert.match(a.problems.join(" "), /held its pipes/);
    assert.ok(await gone(await pidsOf(pids)));
  });
});

test("everything is written under the run directory: cwd, TMPDIR and HOME of the program are inside it; a rerun makes a directory of its own and keeps the first", { skip: NO_ADOPTION }, async () => {
  await withCwd(async (cwd, bin) => {
    await mkdir(join(cwd, "out"), { recursive: true });
    await stand(bin, `
open("stray.txt", "w").write("in cwd")
open(os.path.join(os.environ["TMPDIR"], "t.txt"), "w").write("tmp")
open(os.path.join(os.environ["HOME"], "h.txt"), "w").write("home")
open(os.path.join(out, "TCC_tcc.csv"), "w").write("a,b\\n1,2\\n")
open(os.path.join(out, "mac_apt.db"), "w").write("db")
${OK_TWO}
`);
    const before = new Set(await readdir(cwd));
    const args = { path: await e01(cwd), input_type: "E01", plugins: ["TCC", "BASHSESSIONS"] };
    const a = ok(await run(cwd, bin, args));
    const b = ok(await run(cwd, bin, args));
    assert.notEqual(a.run_directory, b.run_directory);
    assert.equal(a.status, "complete");
    const after = (await readdir(cwd)).filter((n) => !before.has(n));
    assert.deepEqual(after, [], "no new entry beside the out/ and work/ directories");
    for (const f of await filesUnder(join(cwd, "work"))) assert.ok(f.endsWith("mac.E01"), `unexpected file ${f}`);
    const mine = (await filesUnder(join(cwd, "out"))).map((f) => f.slice(join(cwd, "out").length + 1));
    assert.ok(mine.some((f) => f.endsWith("cwd/stray.txt")));
    assert.ok(mine.some((f) => f.endsWith("tmp/t.txt")));
    assert.ok(mine.some((f) => f.endsWith("home/h.txt")));
    assert.ok(a.files.some((f: Json) => f.file === "TCC_tcc.csv" && f.plugin_match?.includes("TCC")), JSON.stringify(a.files));
    assert.ok(a.files.some((f: Json) => f.file === "mac_apt.db" && !f.plugin_match));
    assert.equal(a.files_total, 3);
    assert.ok(a.stdout_file.startsWith("store/jobs/j-1/out/tool-output/macos_triage-"));
  });
});

test("log text and token-shaped plugin names do not reach the answer; the log is kept whole in a file", async () => {
  await withCwd(async (cwd, bin) => {
    const token = "ghp_" + "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5";
    await stand(bin, `
start()
plugin("TCC", ["opened /Users/alice/secret-project/notes.txt with password=Hunter2Hunter2"])
plugin(${JSON.stringify(token)}, ["rows"])
finish()
`);
    const r = await run(cwd, bin, { path: await e01(cwd), input_type: "E01", plugins: ["TCC", token] });
    const a = ok(r);
    assert.doesNotMatch(r.stdout, /alice|secret-project|Hunter2/);
    assert.ok(!r.stdout.includes(token), "a token-shaped plugin name is withheld by the boundary");
    assert.equal(a.counts.parsed, 2);
    const log = (await filesUnder(join(cwd, "out"))).find((f) => /Log\.\d{8}-\d{6}\.txt$/.test(f)) as string;
    assert.ok((await readFile(log, "utf8")).includes("Hunter2Hunter2"), "the kept log is whole");
  });
});

test("the manifest declares secret_output required and says what was read and what was never observed; the program is declared", async () => {
  const m = JSON.parse(await readFile(join(MAC, "macos_triage", "manifest.json"), "utf8")) as Json;
  assert.equal(m.secret_output, "required");
  assert.match(m.description, /SENSITIVE/);
  assert.match(m.description, /not installed or run to build this tool/);
  assert.match(m.description, /never observed/i);
  assert.deepEqual(m.requires, ["mac_apt.py"]);
  assert.ok(m.timeout_seconds >= 7200 && m.description.includes("default 6600"));
  const src = await readFile(TRIAGE, "utf8");
  assert.match(src, /DEFAULT_MAX_SECONDS = 6600/);
  assert.ok(src.includes("start_new_session") === false || !/start_new_session\s*=\s*True/.test(src));
  assert.equal((await stat(TRIAGE)).mode & 0o777, 0o755);
});

test("the tool without a job is not secret output: the harness's manifest key is what makes it one (the tool itself answers either way)", async () => {
  await withCwd(async (cwd, bin) => {
    await stand(bin, OK_TWO);
    const a = ok(await tool(TRIAGE, cwd, { path: await e01(cwd), input_type: "E01", plugins: ["TCC", "BASHSESSIONS"] }, {}, bin));
    assert.ok(a.run_directory.startsWith("work/s1/tool-output/macos_triage-"));
  });
});


// ---- the macos-artefacts recipe ---------------------------------------------------------------------------------------------------------------

const RECIPE = join(MAC, "..", "recipes", "macos-artefacts", "run.py");

type Ran = { code: number | null; stdout: string; stderr: string };
function recipe(cwd: string, bin: string, args: string[], env: Record<string, string> = {}): Promise<Ran> {
  return new Promise((resolve, reject) => {
    const child = spawn("python3", [RECIPE, ...args], { cwd, env: { ...process.env, PATH: `${bin}:${process.env.PATH ?? ""}`, ...env }, detached: true });
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => out.push(c));
    child.stderr.on("data", (c: Buffer) => err.push(c));
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stdout: Buffer.concat(out).toString("utf8"), stderr: Buffer.concat(err).toString("utf8") }));
  });
}
const tgt = (path: string, plugins?: string[]): string => JSON.stringify({ paths: [path], ...(plugins ? { plugins } : {}) });
const detect = async (cwd: string, bin: string, path: string, env: Record<string, string> = {}): Promise<{ code: number | null; j: Json }> => {
  const r = await recipe(cwd, bin, ["detect", "--target", tgt(path)], env);
  return { code: r.code, j: JSON.parse(r.stdout) as Json };
};
const coverage = async (out: string): Promise<Json> => JSON.parse(await readFile(join(out, "coverage.json"), "utf8")) as Json;

/** A GPT disk with one partition entry of the given type GUID (the mixed-endian bytes as the table stores them). */
function gptDisk(guid: string): Buffer {
  const disk = Buffer.alloc(512 * 40);
  disk.write("EFI PART", 512, "latin1");
  disk.writeBigUInt64LE(2n, 512 + 72);
  disk.writeUInt32LE(128, 512 + 80);
  disk.writeUInt32LE(128, 512 + 84);
  const [a, b, c, d, e] = guid.split("-");
  const entry = Buffer.concat([Buffer.from(a, "hex").reverse(), Buffer.from(b, "hex").reverse(), Buffer.from(c, "hex").reverse(), Buffer.from(d + e, "hex")]);
  entry.copy(disk, 1024);
  return disk;
}

test("recipe detect: what it applies to, what it does not, and what it cannot tell", async () => {
  await withCwd(async (cwd, bin) => {
    await stand(bin, OK_TWO);
    const w = (name: string, data: Buffer | string) => writeFile(join(cwd, "work", name), data);
    await e01(cwd);
    await w("t.txt", "plain text, nothing of an image");
    await w("sparse.sparseimage", Buffer.concat([Buffer.from("sprs"), Buffer.alloc(2048)]));
    await w("apfs.img", Buffer.concat([Buffer.alloc(32), Buffer.from("NXSB"), Buffer.alloc(2048)]));
    await w("hfs.img", Buffer.concat([Buffer.alloc(1024), Buffer.from("H+"), Buffer.alloc(2048)]));
    await w("mac.dmg", Buffer.concat([Buffer.alloc(4096), Buffer.from("koly"), Buffer.alloc(508)]));
    await w("apple.raw", gptDisk("7c3457ef-0000-11aa-aa11-00306543ecac"));
    await w("windows.raw", gptDisk("ebd0a0a2-b9e5-4433-87c0-68b6b72699c7"));
    await mkdir(join(cwd, "work", "vol", "System", "Library", "CoreServices"), { recursive: true });
    await w("vol/System/Library/CoreServices/SystemVersion.plist", "<plist/>");
    await mkdir(join(cwd, "work", "plain"), { recursive: true });
    for (const [p, code, re] of [
      ["work/mac.E01", 0, /Expert Witness/],
      ["work/sparse.sparseimage", 0, /sparse/],
      ["work/apfs.img", 0, /APFS container/],
      ["work/hfs.img", 0, /HFS\+/],
      ["work/mac.dmg", 0, /UDIF/],
      ["work/apple.raw", 0, /GPT partition of the type of APFS/],
      ["work/windows.raw", 1, /GPT with no partition of an Apple type/],
      ["work/vol", 0, /MOUNTED/],
      ["work/plain", 1, /without System/],
      ["work/t.txt", 1, /no signature/],
      ["work/missing", 2, /cannot be told/],
    ] as const) {
      const d = await detect(cwd, bin, p);
      assert.equal(d.code, d.j.applies === true ? 0 : d.j.applies === false ? 1 : 2, p);
      assert.equal(d.code, code, `${p}: ${JSON.stringify(d.j)}`);
      assert.match(d.j.why, re, p);
    }
    // an object that looks right but no mac_apt.py on this machine: cannot tell, exit 2 (not a claim that it does not apply)
    const none = await detect(cwd, bin, "work/mac.E01", { PATH: "/usr/bin:/bin" });
    assert.equal(none.code, 2);
    assert.equal(none.j.applies, "unknown");
    await symlink(join(cwd, "work", "mac.E01"), join(cwd, "work", "ln.E01"));
    assert.equal((await detect(cwd, bin, "work/ln.E01")).code, 1);
    const bad = await recipe(cwd, bin, ["detect", "--target", "not json"]);
    assert.equal(bad.code, 2);
    assert.equal(JSON.parse(bad.stdout).applies, "unknown");
  });
});

test("recipe run: coverage.json says complete for named plugins the log accounts for; FAST is partial; every file it wrote is marked secret_bearing", async () => {
  await withCwd(async (cwd, bin) => {
    await stand(bin, `open(os.path.join(HERE, "argv.txt"), "w").write(repr(argv))\nopen(os.path.join(out, "mac_apt.db"), "w").write("db")\n${OK_TWO}`);
    const path = await e01(cwd);
    const done = await recipe(cwd, bin, ["run", "--target", tgt(path, ["tcc", "bashsessions"]), "--out", "r1"]);
    assert.equal(done.code, 0, done.stdout + done.stderr);
    assert.equal(JSON.parse(done.stdout).status, "complete");
    const c = await coverage(join(cwd, "r1"));
    assert.equal(c.status, "complete");
    assert.equal(c.plugins.counts.parsed, 2);
    assert.match(c.plugins.not_observed, /never observed/i);
    assert.ok("mac_apt/mac_apt.db" in c.secret_bearing && "mac_apt.stdout" in c.secret_bearing);
    for (const name of Object.keys(c.secret_bearing)) assert.ok((await stat(join(cwd, "r1", name))).isFile(), name);
    const tsv = await readFile(join(cwd, "r1", "plugins.tsv"), "utf8");
    assert.match(tsv, /^plugin\tstatus\t/);
    assert.match(tsv, /\nTCC\tparsed\t/);
    assert.match(await readFile(join(cwd, "r1", "index.tsv"), "utf8"), /mac_apt\/mac_apt\.db\t2\t/);
    assert.match((await readFile(join(bin, "argv.txt"), "utf8")).replaceAll("'", ""), /, -c, E01, [^,]*mac\.E01, TCC, BASHSESSIONS\]$/);
    const fast = await recipe(cwd, bin, ["run", "--target", tgt(path), "--out", "r2"]);
    assert.equal(fast.code, 0);
    assert.equal((await coverage(join(cwd, "r2"))).status, "partial");
    assert.match((await coverage(join(cwd, "r2"))).errors.join(" "), /expands it to/);
  });
});

test("recipe run: a traceback behind an exit 0, a cut log, a log with no start line and no macOS installation are never complete", async () => {
  await withCwd(async (cwd, bin) => {
    const path = await e01(cwd);
    const cases: Array<[string, string, string, RegExp]> = [
      ["traceback", `start()\nplugin("TCC", ["Traceback (most recent call last):", "KeyError: 1"], ran=False)\nlog("An exception occurred while running plugin - TCC", "ERROR")\nplugin("BASH", ["x"])\nfinish()\n`, "partial", /plugin\(s\) failed/],
      ["cut", `start()\nplugin("TCC", ["x"])\nplugin("BASH", ["x"], ran=False)\n`, "partial", /finish line/],
      ["wrong mode", `print("Exiting -> Invalid")\n`, "failed", /nothing was parsed/],
      ["no macOS", `start()\nlog("Could not find OSX/macOS installation!", "ERROR")\nlog("Finished in time = 00:00:01")\n`, "failed", /nothing was parsed/],
      ["outside error", `start()\nlog("boom", "ERROR")\nplugin("TCC", ["x"])\nplugin("BASH", ["x"])\nfinish()\n`, "partial", /outside any plugin/],
    ];
    let n = 0;
    for (const [name, script, want, re] of cases) {
      await stand(bin, script);
      const r = await recipe(cwd, bin, ["run", "--target", tgt(path, ["TCC", "BASH"]), "--out", `c${n}`]);
      const c = await coverage(join(cwd, `c${n++}`));
      assert.equal(c.status, want, `${name}: ${c.status_basis}`);
      assert.match(c.status_basis, re, name);
      assert.notEqual(JSON.parse(r.stdout).status, "complete", name);
    }
  });
});

test("recipe run: a hang is ended at its limit with its children, coverage.json says partial, and the log written so far is read", async () => {
  await withCwd(async (cwd, bin) => {
    const pids = join(cwd, "pids.txt");
    await stand(bin, `start()\nplugin("TCC", ["x"])\nlog("Running plugin SLOW")\nimport subprocess\nc = subprocess.Popen(["sleep", "300"])\nopen(${JSON.stringify(pids)}, "a").write("%d %d\\n" % (os.getpid(), c.pid))\ntime.sleep(300)\n`);
    const r = await recipe(cwd, bin, ["run", "--target", tgt(await e01(cwd), ["TCC", "SLOW"]), "--out", "h", "--max-seconds", "2"]);
    assert.equal(r.code, 1);
    const c = await coverage(join(cwd, "h"));
    assert.equal(c.status, "partial");
    assert.match(c.status_basis, /did not finish in the 2 seconds/);
    assert.ok(await gone(await pidsOf(pids)));
  });
});

test("recipe run: SIGTERM ends mac_apt and its child, exit 143, and coverage.json (written first) says partial", async () => {
  await withCwd(async (cwd, bin) => {
    const pids = join(cwd, "pids.txt");
    await stand(bin, `start()\nplugin("TCC", ["x"])\nimport subprocess\nc = subprocess.Popen(["sleep", "300"])\nopen(${JSON.stringify(pids)}, "a").write("%d %d\\n" % (os.getpid(), c.pid))\ntime.sleep(300)\n`);
    const path = await e01(cwd);
    const child = spawn("python3", [RECIPE, "run", "--target", tgt(path, ["TCC"]), "--out", "s"], { cwd, env: { ...process.env, PATH: `${bin}:${process.env.PATH ?? ""}` }, detached: true });
    const out: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => out.push(c));
    const closed = new Promise<number | null>((res) => child.on("close", (code) => res(code)));
    await new Promise((r) => setTimeout(r, 2500));
    child.kill("SIGTERM");
    assert.equal(await closed, 143);
    assert.equal((await coverage(join(cwd, "s"))).status, "partial");
    assert.match(Buffer.concat(out).toString(), /stopped by SIGTERM/);
    assert.ok(await gone(await pidsOf(pids)));
  });
});

test("recipe run: a rerun in the same output directory refuses and leaves every file as it was; nothing is written outside the output directory", async () => {
  await withCwd(async (cwd, bin) => {
    await stand(bin, `open("stray.txt", "w").write("in cwd")\n${OK_TWO}`);
    const path = await e01(cwd);
    const before = new Set(await readdir(cwd));
    const a = await recipe(cwd, bin, ["run", "--target", tgt(path, ["TCC", "BASHSESSIONS"]), "--out", "o"]);
    assert.equal(a.code, 0);
    const files = await filesUnder(join(cwd, "o"));
    const kept = new Map<string, string>();
    for (const f of files) kept.set(f, (await readFile(f)).toString("base64"));
    const b = await recipe(cwd, bin, ["run", "--target", tgt(path, ["TCC", "BASHSESSIONS"]), "--out", "o"]);
    assert.equal(b.code, 2);
    assert.match(JSON.parse(b.stdout).status_basis, /never writes over one/);
    for (const f of files) assert.equal((await readFile(f)).toString("base64"), kept.get(f), f);
    assert.deepEqual((await filesUnder(join(cwd, "o"))).sort(), files.sort());
    assert.deepEqual((await readdir(cwd)).filter((n) => !before.has(n)), ["o"]);
    for (const f of await filesUnder(join(cwd, "work"))) assert.ok(f.endsWith("mac.E01"), f);
  });
});

test("recipe run: with no mac_apt.py the run is refused, because detect could not tell", async () => {
  await withCwd(async (cwd, bin) => {
    const r = await recipe(cwd, bin, ["run", "--target", tgt(await e01(cwd)), "--out", "n"], { PATH: "/usr/bin:/bin" });
    assert.equal(r.code, 2);
    assert.match(JSON.parse(r.stdout).status_basis, /not one this recipe reads here/);
  });
});

test("the recipe and the tool carry one copy of the log reader, and the recipe's JSON is a broad extraction that names its exclusions", async () => {
  const cut = (text: string): string => text.slice(text.indexOf("# macapt-log-reader: start"), text.indexOf("# macapt-log-reader: stop"));
  const [a, b] = [cut(await readFile(TRIAGE, "utf8")), cut(await readFile(RECIPE, "utf8"))];
  assert.ok(a.length > 3000);
  assert.equal(a, b);
  const r = JSON.parse(await readFile(join(MAC, "..", "recipes", "macos-artefacts", "recipe.json"), "utf8")) as Json;
  assert.equal(r.purpose, "broad_extraction");
  assert.equal(r.capability, "macos-artifacts");
  assert.deepEqual(r.auto, []);
  assert.ok(r.exclusions.length >= 4);
  assert.equal((await stat(RECIPE)).mode & 0o777, 0o755);
});

// ---- the error vocabulary does not rest on an uppercase level word that was never observed; the recipe's files are exclusive ---------------------

test("a lowercase error line or a failure sentence inside a plugin's run is failed, in the tool and the recipe, whatever the logger name is", async () => {
  await withCwd(async (cwd, bin) => {
    const path = await e01(cwd);
    let n = 0;
    for (const sentence of ["error: could not open database", "Failed to parse database", "unable to read the file", "Exception while reading", "cannot decode record"]) {
      for (const format of ["2026-11-04 12:00:00,000|MAIN|%s|%s", "2026-11-04 12:00:00,000|a.b|%s|%s"]) {
        await stand(bin, `start()\nplugin("TCC", ["Processed 3 rows"])\nplugin("SAFARI", [${JSON.stringify(sentence)}])\nfinish()\n`, format);
        const a = ok(await run(cwd, bin, { path, input_type: "E01", plugins: ["TCC", "SAFARI"] }));
        assert.equal(status(a, "SAFARI"), "failed", sentence);
        assert.equal(status(a, "TCC"), "parsed");
        assert.notEqual(a.status, "complete", sentence);
        const dir = `v${n++}`;
        await recipe(cwd, bin, ["run", "--target", tgt(path, ["TCC", "SAFARI"]), "--out", dir]);
        const c = await coverage(join(cwd, dir));
        assert.notEqual(c.status, "complete", sentence);
        assert.match(await readFile(join(cwd, dir, "plugins.tsv"), "utf8"), /\nSAFARI\tfailed\t/);
      }
    }
    // the hint of the source's own finish lines names ERRORs and EXCEPTIONS and is not an error line; a parsed plugin says what its status rests on
    await stand(bin, OK_TWO);
    const good = ok(await run(cwd, bin, { path, input_type: "E01", plugins: ["TCC", "BASHSESSIONS"] }));
    assert.equal(good.status, "complete");
    assert.match(good.plugins[0].reason, /rests on a log format never observed/);
    assert.match(good.status_basis, /never observed/);
  });
});

test("the recipe creates its files exclusively: any name it writes that already exists refuses the run (exit 2) with nothing touched, and a planted link is not followed", async () => {
  await withCwd(async (cwd, bin) => {
    await stand(bin, OK_TWO);
    const path = await e01(cwd);
    for (const name of ["plugins.tsv", "index.tsv", "mac_apt.stdout", "mac_apt.stderr", "coverage.json.tmp"]) {
      const out = join(cwd, `x-${name}`);
      await mkdir(out, { recursive: true });
      await writeFile(join(out, name), Buffer.alloc(5000, 0x41));
      const r = await recipe(cwd, bin, ["run", "--target", tgt(path, ["TCC", "BASHSESSIONS"]), "--out", out]);
      assert.equal(r.code, 2, name);
      assert.deepEqual((await readdir(out)).sort(), [name]);
      assert.equal((await stat(join(out, name))).size, 5000, `${name} is untouched`);
      const link = join(cwd, `y-${name}`);
      await mkdir(link, { recursive: true });
      await writeFile(join(cwd, `victim-${name}`), "keep");
      await symlink(join(cwd, `victim-${name}`), join(link, name));
      assert.equal((await recipe(cwd, bin, ["run", "--target", tgt(path, ["TCC", "BASHSESSIONS"]), "--out", link])).code, 2);
      assert.equal(await readFile(join(cwd, `victim-${name}`), "utf8"), "keep", `a link at ${name} is not followed`);
      assert.deepEqual((await readdir(link)).sort(), [name]);
    }
    const fresh = await recipe(cwd, bin, ["run", "--target", tgt(path, ["TCC", "BASHSESSIONS"]), "--out", "fresh"]);
    assert.equal(fresh.code, 0);
    const c = await coverage(join(cwd, "fresh"));
    for (const name of ["plugins.tsv", "index.tsv", "coverage.json", "mac_apt.stdout", "mac_apt.stderr"]) assert.ok(name in c.secret_bearing, name);
    assert.equal(((await stat(join(cwd, "fresh", "plugins.tsv"))).mode & 0o777).toString(8), "600");
  });
});

// ---- a name created by another process after the start check -----------------------------------------------------------------------------------

test("the recipe: a name another process creates after the start check (a file, or a dangling link) is refused with JSON and exit 2, nothing foreign is touched and coverage.json stays partial", async () => {
  await withCwd(async (cwd, bin) => {
    const path = await e01(cwd);
    for (const name of ["plugins.tsv", "index.tsv"]) {
      for (const how of ["file", "link"]) {
        const victim = join(cwd, `victim-${how}-${name}`);
        const target = `os.path.join(os.path.dirname(out), ${JSON.stringify(name)})`;
        const plant = how === "file" ? `open(${target}, "w").write("foreign")` : `os.symlink(${JSON.stringify(victim)}, ${target})`;
        await stand(bin, `${plant}\n${OK_TWO}`);
        const dir = join(cwd, `race-${how}-${name}`);
        const r = await recipe(cwd, bin, ["run", "--target", tgt(path, ["TCC", "BASHSESSIONS"]), "--out", dir]);
        const label = `${how} ${name}: ${r.stdout}${r.stderr}`;
        assert.equal(r.code, 2, label);
        assert.doesNotMatch(r.stderr, /Traceback/, label);
        const a = JSON.parse(r.stdout) as Json;
        assert.equal(a.ok, false, label);
        assert.equal(a.status, "failed", label);
        assert.match(a.status_basis, /another process may have created a name/, label);
        assert.equal((await coverage(dir)).status, "partial", label);
        if (how === "file") assert.equal(await readFile(join(dir, name), "utf8"), "foreign", label);
        else {
          assert.equal((await lstat(join(dir, name))).isSymbolicLink(), true, label);
          await assert.rejects(stat(victim), label);
        }
        if (name === "plugins.tsv") await assert.rejects(stat(join(dir, "index.tsv")), label);
      }
    }
  });
});

test("the recipe: a link planted at coverage.json or a scratch directory name between the start check and its use is refused and never followed", async () => {
  await withCwd(async (cwd, bin) => {
    await stand(bin, OK_TWO);
    const path = await e01(cwd);
    const hook = join(cwd, "hook.py");
    // in-process: the recipe's own first coverage write is the moment after the start check and before the names are used
    await writeFile(hook, [
      "import importlib.util, os, sys",
      "spec = importlib.util.spec_from_file_location('macrecipe', sys.argv[1])",
      "m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)",
      "out, name, target = sys.argv[2], sys.argv[3], sys.argv[4]",
      "real = m.write_coverage",
      "def planted(*a, **k):",
      "    if k.get('first') and name == 'coverage.json':",
      "        os.symlink(target, os.path.join(out, name))",
      "    real(*a, **k)",
      "    if k.get('first') and name != 'coverage.json':",
      "        os.symlink(target, os.path.join(out, name))",
      "m.write_coverage = planted",
      "m.shutil.which = lambda p: sys.argv[5]",
      "sys.exit(m.run(sys.argv[6], 'E01', ['TCC'], out))",
    ].join("\n"));
    for (const name of ["mac_apt", "mac_apt-cwd", "mac_apt-tmp", "mac_apt-home", "coverage.json"]) {
      const out = join(cwd, `plant-${name}`);
      const victim = join(cwd, `victim-dir-${name}`);
      await mkdir(victim, { recursive: true });
      await mkdir(out, { recursive: true });
      const child = spawn("python3", [hook, RECIPE, out, name, victim, join(bin, "mac_apt.py"), join(cwd, path)], { cwd, env: { ...process.env, PATH: `${bin}:${process.env.PATH ?? ""}` } });
      const chunks: Buffer[] = [];
      child.stdout.on("data", (c: Buffer) => chunks.push(c));
      child.stderr.on("data", (c: Buffer) => chunks.push(c));
      const code = await new Promise<number | null>((res) => child.on("close", (c) => res(c)));
      const text = Buffer.concat(chunks).toString();
      assert.equal(code, 2, `${name}: ${text}`);
      assert.doesNotMatch(text, /Traceback/, name);
      assert.deepEqual(await readdir(victim), [], `${name}: nothing was written through the link`);
      assert.equal((await lstat(join(out, name))).isSymbolicLink(), true, name);
    }
  });
});
