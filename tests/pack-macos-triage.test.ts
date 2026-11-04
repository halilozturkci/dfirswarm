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
import { chmod, mkdir, readFile, readdir, stat, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { withCwd } from "./tool-library-harness.ts";
import { MAC, body, filesUnder, leader, ok, secretJob, signalled, tool } from "./macos-late-harness.ts";
import type { Json } from "./macos-late-harness.ts";

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

async function stand(bin: string, script: string, format = "2026-11-04 12:00:00,000 - MAIN - %s - %s"): Promise<void> {
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

test("explicit plugins that the log shows run to their end are parsed and the run is complete; the argv and the version are recorded", async () => {
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

test("the prefix of a log line is not relied on: no prefix at all reads the same", async () => {
  await withCwd(async (cwd, bin) => {
    await stand(bin, OK_TWO, "%.0s%s");
    const a = ok(await run(cwd, bin, { path: await e01(cwd), input_type: "E01", plugins: ["TCC", "BASHSESSIONS"] }));
    assert.equal(a.status, "complete", a.status_basis + JSON.stringify(a.problems));
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

test("a plugin whose run holds only lines saying nothing was found is empty; a warning alone does not fail it", async () => {
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

test("a FileVault password is only a sealed file passed as -pf: the file is checked and never read, a loose mode is refused, and its content is nowhere", async () => {
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
def con(line): print("12:00:00 INFO " + line)
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

test("everything is written under the run directory: cwd, TMPDIR and HOME of the program are inside it; a rerun makes a directory of its own and keeps the first", async () => {
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

void spawn;
