/**
 * The running output caps of the shared PROCESS block (docs/packs.md, section 7, "What a program leaves behind", and section 8, "A tool that starts a
 * program"): communicate_bounded used to read a running program's standard output and standard error with no byte cap, so a program that printed
 * 1.13 GB (ffprobe's JSON of stream tags) made the tool hold 2.36 GB and die in a 2 GB box with no answer. Now each stream has a cap while the program
 * runs (STDOUT_CAP 64 MiB kept; STDERR_CAP 8 MiB read, its head and last STDERR_TAIL kept; or the caller's `caps`): past it the program is ended on
 * the deadline's own path (kill_tree: its tree only), the stream comes back with `cut` set (Output.cut, output_cut()), OUTPUT_CUT counts the call and
 * process_apply turns a complete answer partial; a carrier never takes a cut output for a whole one.
 *
 * Two parts:
 *   the block   the block's text, cut out of one carrier of each of the eleven packs that carry it (and the tool library), run on its own against a
 *               stand-in that floods standard output and one that floods standard error, each with a child the "tool" already had beside it: the
 *               call returns at once with what it kept and the cut said, the stand-in is ended, the other child is not touched, the peak resident
 *               memory (getrusage) stays bounded, and process_apply makes the answer partial with the cut in it;
 *   the tools   a carrier of each pack whose own code reads a program's output through the block (frame_survey, tcrypt_header, package_verify, zeek_run,
 *               ransomware_family_match, snapshot_chain_check, lnk_jumplist), run whole against a stand-in program that floods: it answers with one
 *               JSON document, partial or failed with the cut said, the stand-in is ended, and the tool's peak resident memory is bounded. The
 *               macos, memory, mobile and reverse-engineering packs carry the block but read no program's output through it (their pipe readers are
 *               their own, with caps of their own), so the block part is what holds there.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { PYTHON3 } from "./host-gates.ts";
import { qcow2 } from "./pack-virtualization-harness.ts";
import { lnk } from "./windows-t1-fixtures.ts";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
type Answer = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any
const MB = 1 << 20;
/** The most a whole tool may hold at its peak in these runs: a 2 GB box is the case that failed; the block alone holds about 230 MB at its default caps. */
const TOOL_PEAK_MB = 700;
const BLOCK_PEAK_MB = 400;

const alive = (pid: number): boolean => {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
};
const pidsIn = (file: string): number[] => {
  try {
    return readFileSync(file, "utf8").split("\n").filter(Boolean).map(Number);
  } catch {
    return [];
  }
};
async function gone(pids: number[], waitMs = 3000): Promise<number[]> {
  const until = Date.now() + waitMs;
  let left = pids.filter(alive);
  while (left.length && Date.now() < until) {
    await new Promise((r) => setTimeout(r, 50));
    left = left.filter(alive);
  }
  return left;
}

/** A program that writes its pid to $FLOOD_PIDS and then floods standard output (1) or standard error (2) for ever, with `head` first. */
const FLOOD = (stream: 1 | 2, head = ""): string => `#!${PYTHON3}
import os
f = os.environ.get("FLOOD_PIDS")
if f:
    open(f, "a").write("%d\\n" % os.getpid())
os.write(${stream}, ${JSON.stringify(head)}.encode())
chunk = b"\\\\u0001" * 10000
while True:
    os.write(${stream}, chunk)
`;

// ---- the block, on its own, in one carrier of each pack -----------------------------------------------------------------------------------------

const BLOCK_CARRIERS = [
  "packs/computer-forensics-base/tools/archive_extract/run.py",
  "packs/encrypted-containers/tools/tcrypt_header/run.py",
  "packs/linux-forensics/tools/audit_events/run.py",
  "packs/macos-forensics/tools/apfs_inventory/run.py",
  "packs/memory-forensics/tools/isf_intake/run.py",
  "packs/mobile-forensics/tools/heic_inspect/run.py",
  "packs/network-forensics/tools/zeek_run/run.py",
  "packs/ransomware-response/tools/ransomware_family_match/run.py",
  "packs/reverse-engineering/tools/fuzzy_hash/run.py",
  "packs/virtualization-backup-forensics/tools/snapshot_chain_check/run.py",
  "packs/windows-forensics/tools/yara_scan/run.py",
  "tool-library/yara_scan/run.py",
];

const CASE = String.raw`
import json, os, re, resource, signal, subprocess, sys, time
src = open(sys.argv[1]).read()
block = re.search(r"^# BEGIN SHARED PROCESS\n.*?^# END SHARED PROCESS\n", src, re.S | re.M).group(0)
flood, pids, stream, caps = sys.argv[2], sys.argv[3], sys.argv[4], json.loads(sys.argv[5])
ns = {"os": os, "signal": signal, "subprocess": subprocess, "sys": sys, "describe": str}
exec(block, ns)
bystander = subprocess.Popen(["sleep", "30"])            # a child the tool already had: no program's, and never the block's to end
proc = ns["spawn"]([flood], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=dict(os.environ, FLOOD_PIDS=pids))
ns["ACTIVE"].append(proc)
t = time.monotonic()
out, err, timed_out = ns["communicate_bounded"](proc, 60, caps=tuple(caps) if caps else None)
elapsed = time.monotonic() - t
ns["ACTIVE"].remove(proc)
peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / (1048576 if sys.platform == "darwin" else 1024)
answer = ns["process_apply"]({"status": "complete", "ok": True, "status_basis": "the program ran"})
print(json.dumps({"elapsed": elapsed, "out_len": len(out), "err_len": len(err), "out_cut": out.cut, "err_cut": err.cut, "first": ns["output_cut"](out, err),
    "err_head": err[:6].decode("latin-1"), "err_marker": b"bytes of standard error not kept" in err, "timed_out": timed_out, "returncode": proc.returncode,
    "counted": ns["OUTPUT_CUT"]["cut"], "notes": ns["process_notes"](), "answer": answer, "peak_mb": peak, "bystander_alive": bystander.poll() is None}))
bystander.kill()
bystander.wait()
`;

type BlockResult = {
  elapsed: number; out_len: number; err_len: number; out_cut: string | null; err_cut: string | null; first: string | null; err_head: string; err_marker: boolean;
  timed_out: boolean; returncode: number | null; counted: number; notes: string[]; answer: Answer; peak_mb: number; bystander_alive: boolean;
};

async function runBlock(carrier: string, stream: 1 | 2, caps: [number, number] | null): Promise<{ r: BlockResult; pids: number[] }> {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "outcap-")));
  try {
    const flood = join(dir, "flood");
    writeFileSync(flood, FLOOD(stream, stream === 2 ? "FIRST " : ""));
    chmodSync(flood, 0o755);
    const pids = join(dir, "flood.pids");
    const child = spawn(PYTHON3, ["-c", CASE, join(ROOT, carrier), flood, pids, String(stream), JSON.stringify(caps)], { detached: true, stdio: ["ignore", "pipe", "pipe"] });
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => out.push(c));
    child.stderr.on("data", (c: Buffer) => err.push(c));
    const code = await new Promise<number | null>((resolve) => child.on("exit", (c) => resolve(c)));
    const text = Buffer.concat(out).toString("utf8");
    assert.equal(code, 0, `${carrier}: ${Buffer.concat(err).toString("utf8").slice(-800)} ${text.slice(-300)}`);
    return { r: JSON.parse(text.trim().split("\n").pop() as string) as BlockResult, pids: pidsIn(pids) };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

for (const carrier of BLOCK_CARRIERS) {
  const where = carrier.split("/").slice(0, -1).join("/");
  test(`the block in ${where}: a program that floods standard output is ended at 64 MiB kept, the cut is said, its memory bounded, no other process touched`, async () => {
    const { r, pids } = await runBlock(carrier, 1, null);
    assert.equal(r.out_len, 64 * MB, "the first 64 MiB are kept");
    assert.match(r.out_cut ?? "", /^the program printed more than 67108864 bytes on its standard output; the tool kept the first 67108864 and did not read the rest; the tool ended the program there$/);
    assert.equal(r.err_cut, null);
    assert.equal(r.first, r.out_cut, "output_cut() names it");
    assert.equal(r.timed_out, false, "a cut is not a timeout");
    assert.ok(r.returncode !== 0 && r.returncode !== null, `the program was ended (${r.returncode})`);
    assert.ok(r.elapsed < 10, `${r.elapsed.toFixed(1)} s`);
    assert.ok(r.peak_mb < BLOCK_PEAK_MB, `the process held ${r.peak_mb.toFixed(0)} MiB at its peak`);
    assert.equal(r.counted, 1, "OUTPUT_CUT counts the call");
    assert.ok(r.notes.includes(r.out_cut as string), "process_notes() says it");
    assert.equal(r.answer.status, "partial");
    assert.equal(r.answer.ok, false);
    assert.match(r.answer.status_basis, /the program ran; a program's output was not read whole: the program printed more than 67108864 bytes on its standard output/);
    assert.equal(pids.length, 1);
    assert.deepEqual(await gone(pids), [], "the stand-in is ended");
    assert.equal(r.bystander_alive, true, "the child the tool already had is not touched");
  });

  test(`the block in ${where}: a program that floods standard error is ended at 8 MiB, its head and last 1 MiB are kept and the cut is said`, async () => {
    const { r, pids } = await runBlock(carrier, 2, null);
    assert.equal(r.out_len, 0);
    assert.equal(r.err_head, "FIRST ", "the head of standard error is kept");
    assert.equal(r.err_marker, true, "the bytes not kept are said between the head and the tail");
    assert.ok(r.err_len > 8 * MB && r.err_len < 8 * MB + 4096, `${r.err_len} bytes of standard error returned`);
    assert.match(r.err_cut ?? "", /^the program printed more than 8388608 bytes on its standard error; the tool kept the first 7340032 and the last 1048576; the tool ended the program there$/);
    assert.equal(r.out_cut, null);
    assert.ok(r.elapsed < 10 && r.peak_mb < BLOCK_PEAK_MB, `${r.elapsed.toFixed(1)} s, ${r.peak_mb.toFixed(0)} MiB`);
    assert.equal(r.answer.status, "partial");
    assert.match(r.answer.status_basis, /on its standard error/);
    assert.deepEqual(await gone(pids), [], "the stand-in is ended");
    assert.equal(r.bystander_alive, true);
  });

  test(`the block in ${where}: the caller's caps are the ones held`, async () => {
    const { r, pids } = await runBlock(carrier, 1, [65536, 4096]);
    assert.equal(r.out_len, 65536);
    assert.match(r.out_cut ?? "", /more than 65536 bytes on its standard output; the tool kept the first 65536/);
    assert.ok(r.peak_mb < 120, `${r.peak_mb.toFixed(0)} MiB`);
    assert.deepEqual(await gone(pids), []);
  });
}

// ---- the tools whose own code reads a program's output through the block --------------------------------------------------------------------------

type Measured = { code: number; stdout: string; stderr: string; peak_mb: number; ms: number };
const MEASURE = String.raw`
import json, resource, subprocess, sys, time
t = time.monotonic()
p = subprocess.run([sys.executable, sys.argv[1]], input=sys.stdin.buffer.read(), capture_output=True)
r = resource.getrusage(resource.RUSAGE_CHILDREN)
print(json.dumps({"code": p.returncode, "stdout": p.stdout.decode("utf-8", "replace"), "stderr": p.stderr.decode("utf-8", "replace")[-4000:],
    "peak_mb": r.ru_maxrss / (1048576 if sys.platform == "darwin" else 1024), "ms": (time.monotonic() - t) * 1000}))
`;

/** The tool, run by a python that waits for it and reads the largest resident set of what it waited for (the tool; its stand-ins are small). */
function measured(script: string, cwd: string, args: unknown, env: Record<string, string>): Promise<Measured> {
  return new Promise((resolve, reject) => {
    const child = spawn(PYTHON3, ["-c", MEASURE, script], { cwd, env: { ...process.env, AGENT_ID: "s1", ...env }, detached: true });
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => out.push(c));
    child.stderr.on("data", (c: Buffer) => err.push(c));
    child.on("error", reject);
    const timer = setTimeout(() => { try { process.kill(-(child.pid as number), "SIGKILL"); } catch { /* gone */ } }, 120_000);
    child.on("close", () => {
      clearTimeout(timer);
      try {
        resolve(JSON.parse(Buffer.concat(out).toString("utf8")) as Measured);
      } catch (e) {
        reject(new Error(`${String(e)}: ${Buffer.concat(err).toString("utf8").slice(-800)}`));
      }
    });
    child.stdin.end(JSON.stringify(args));
  });
}

function withCwd(fn: (cwd: string, bin: string, pids: string) => Promise<void>): Promise<void> {
  const cwd = realpathSync(mkdtempSync(join(tmpdir(), "outcap-tool-")));
  for (const d of ["inputs", "work/s1", "bin"]) mkdirSync(join(cwd, d), { recursive: true });
  const pids = join(cwd, "flood.pids");
  return fn(cwd, join(cwd, "bin"), pids).finally(async () => {
    for (const pid of pidsIn(pids)) { try { process.kill(pid, "SIGKILL"); } catch { /* gone */ } }
    rmSync(cwd, { recursive: true, force: true });
  });
}
function program(bin: string, name: string, text: string): void {
  writeFileSync(join(bin, name), text);
  chmodSync(join(bin, name), 0o755);
}
/** A shell stand-in: `version` answers a version request (or floods when it is null), `rest` is the rest of the program. */
function standin(bin: string, name: string, versionFlag: string, version: string | null, rest: string, stream: 1 | 2 = 1, head = ""): void {
  program(bin, `${name}-flood`, FLOOD(stream, head));
  const flood = `exec "$(dirname "$0")/${name}-flood"`;
  program(bin, name, `#!/bin/sh\ncase "$1" in ${versionFlag}) ${version === null ? flood : `echo "${version}"; exit 0`};; esac\n${rest.replace("FLOOD", flood)}\n`);
}
const pkg = (pack: string, tool: string): string => join(ROOT, "packs", pack, "tools", tool, "run.py");
const job = (cwd: string): Record<string, string> => {
  const out = join(cwd, "store", "jobs", "j000001", "out");
  mkdirSync(out, { recursive: true });
  return { JOB_ID: "j000001", OUT: out };
};

async function checkTool(name: string, m: Measured, pids: string, said: RegExp, statuses = ["partial", "failed"]): Promise<Answer> {
  assert.doesNotMatch(m.stderr, /Traceback/, `${name}: ${m.stderr}`);
  let answer: Answer;
  try {
    answer = JSON.parse(m.stdout) as Answer;
  } catch {
    assert.fail(`${name}: not one JSON document (exit ${m.code}): ${m.stdout.slice(0, 300)} ${m.stderr.slice(-600)}`);
  }
  assert.ok(statuses.includes(answer.status), `${name}: ${answer.status}: ${answer.status_basis}`);
  assert.match(JSON.stringify(answer), said, `${name}: the cut is said: ${JSON.stringify(answer).slice(0, 1500)}`);
  assert.ok(m.peak_mb < TOOL_PEAK_MB, `${name} held ${m.peak_mb.toFixed(0)} MiB at its peak`);
  assert.ok(m.ms < 60_000, `${name} took ${m.ms} ms`);
  const flooders = pidsIn(pids);
  assert.ok(flooders.length >= 1, `${name}: the stand-in flooded`);
  assert.deepEqual(await gone(flooders), [], `${name}: the stand-in is ended`);
  return answer;
}

test("frame_survey (computer-forensics-base): ffprobe printing JSON past its cap is ended, its output is not parsed, and the survey fails saying so", async () => {
  await withCwd(async (cwd, bin, pids) => {
    standin(bin, "ffprobe", "-version", "ffprobe version 6.0", "FLOOD", 1, '{"streams": [{"codec_name": "x", "tags": {"t": "');
    program(bin, "ffmpeg", "#!/bin/sh\nexit 0\n");
    writeFileSync(join(cwd, "inputs", "v.mp4"), "the stand-ins read no byte of it");
    const m = await measured(pkg("computer-forensics-base", "frame_survey"), cwd, { video: "inputs/v.mp4" }, { ...job(cwd), PATH: `${bin}:/usr/bin:/bin`, FLOOD_PIDS: pids });
    const a = await checkTool("frame_survey", m, pids, /ffprobe's output was not read whole, so it was not parsed: the program printed more than \d+ bytes on its standard output/, ["failed"]);
    assert.match(a.status_basis, /the video stream could not be read/);
  });
});

test("tcrypt_header (encrypted-containers): cryptsetup printing past its cap on standard error is ended and nothing is said about the password", async () => {
  await withCwd(async (cwd, bin, pids) => {
    standin(bin, "cryptsetup", "--version", "cryptsetup 2.7.0", "FLOOD", 2, "WARNING ");
    writeFileSync(join(cwd, "work", "real.img"), "volume bytes");
    writeFileSync(join(cwd, "work", "password.txt"), "a password\n", { mode: 0o600 });
    const m = await measured(pkg("encrypted-containers", "tcrypt_header"), cwd, { source: "work/real.img", password_file: "work/password.txt", max_seconds: 30 }, { ...job(cwd), SECRET_OUTPUT: "1", PATH: `${bin}:${process.env.PATH}`, FLOOD_PIDS: pids });
    const a = await checkTool("tcrypt_header", m, pids, /cryptsetup's output was not read whole \(the program printed more than \d+ bytes on its standard error/, ["failed"]);
    assert.equal(a.decrypted, null);
  });
});

test("package_verify (linux-forensics): debsums printing its version past the cap is ended there, its version not taken, and the answer is partial and says so", async () => {
  await withCwd(async (cwd, bin, pids) => {
    standin(bin, "debsums", "--version", null, "exit 0");
    const r = join(cwd, "work", "r", "var", "lib", "dpkg");
    mkdirSync(join(r, "info"), { recursive: true });
    writeFileSync(join(r, "status"), "Package: a\nStatus: install ok installed\n");
    writeFileSync(join(r, "info", "a.md5sums"), "d41d8cd98f00b204e9800998ecf8427e  usr/bin/a\n");
    const m = await measured(pkg("linux-forensics", "package_verify"), cwd, { root: "work/r", family: "debian", packages: ["a"] }, { ...job(cwd), PATH: `${bin}:${process.env.PATH}`, FLOOD_PIDS: pids });
    const a = await checkTool("package_verify", m, pids, /a program's output was not read whole: the program printed more than 65536 bytes on its standard output/, ["partial"]);
    assert.equal(a.program.version ?? null, null, "a version text past its cap is not taken");
  });
});

const CONN = [
  "#separator \\x09", "#set_separator\t,", "#empty_field\t(empty)", "#unset_field\t-", "#path\tconn", "#open\t2023-11-14-22-13-20",
  "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto", "#types\ttime\tstring\taddr\tport\taddr\tport\tenum",
  "1700000000.123456\tCYWJAH2BG8ssSd3Mpk\t10.0.0.5\t50000\t203.0.113.7\t443\ttcp", "#close\t2023-11-14-22-14-00",
].join("\n") + "\n";

test("zeek_run (network-forensics): zeek printing its version past the cap is ended, the version is not recorded, and the logs' answer is partial", async () => {
  await withCwd(async (cwd, bin, pids) => {
    writeFileSync(join(cwd, "conn.log.src"), CONN);
    standin(bin, "zeek", "--version", null, `cp "${join(cwd, "conn.log.src")}" conn.log\nexit 0`);
    writeFileSync(join(cwd, "work", "c.pcap"), "not read by the stand-in");
    const m = await measured(pkg("network-forensics", "zeek_run"), cwd, { path: "work/c.pcap", out_dir: "work/z" }, { PATH: `${bin}:${process.env.PATH}`, FLOOD_PIDS: pids });
    const a = await checkTool("zeek_run", m, pids, /`zeek --version` printed past its cap and was ended/, ["partial"]);
    assert.equal(a.zeek_version, null, "a version text past its cap is not recorded");
  });
});

test("ransomware_family_match (ransomware-response): yara printing past its cap is ended, its batch's matches are not taken, and the answer is partial", async () => {
  await withCwd(async (cwd, bin, pids) => {
    standin(bin, "yara", "--version", "4.5.0", "FLOOD");
    const note = join(cwd, "info.txt");
    writeFileSync(note, "x\n");
    const rows = [
      { finding_id: "N000001", note_id: "N000001", file: note, offset: 0, kind: "note_preview", encoding: "utf-8", validation: null, value: "preview" },
    ];
    writeFileSync(join(cwd, "vals.jsonl"), rows.map((r) => JSON.stringify(r)).join("\n") + "\n");
    const m = await measured(pkg("ransomware-response", "ransomware_family_match"), cwd, { values_file: "vals.jsonl", extensions: [".phobos"], max_seconds: 30 }, { PATH: `${bin}:${process.env.PATH}`, FLOOD_PIDS: pids });
    await checkTool("ransomware_family_match", m, pids, /yara printed past its output cap on 1 batches and was ended there/, ["partial"]);
  });
});

test("snapshot_chain_check (virtualization-backup-forensics): qemu-img printing JSON past its cap is ended, its answer not parsed, and the second reading is missing", async () => {
  await withCwd(async (cwd, bin, pids) => {
    standin(bin, "qemu-img", "--version", "qemu-img version 8.2.0", "FLOOD", 1, '{"virtual-size": ');
    mkdirSync(join(cwd, "inputs", "q"), { recursive: true });
    writeFileSync(join(cwd, "inputs", "q", "base.qcow2"), qcow2({ size: 1073741824n }));
    const m = await measured(pkg("virtualization-backup-forensics", "snapshot_chain_check"), cwd, { root: "inputs/q", qemu_img: "auto" }, { PATH: `${bin}:${process.env.PATH}`, FLOOD_PIDS: pids });
    await checkTool("snapshot_chain_check", m, pids, /qemu-img printed past its cap and was ended/, ["partial"]);
  });
});

test("lnk_jumplist (windows-forensics): lnkinfo printing past its cap is ended, not compared, and the answer is partial", async () => {
  await withCwd(async (cwd, bin, pids) => {
    standin(bin, "lnkinfo", "--never", null, "FLOOD", 2);
    writeFileSync(join(cwd, "work", "report.lnk"), lnk({ local: { path: "C:\\case\\report.txt", serial: 0x1a2b3c4d, label: "SYSTEM" }, name: "Report" }));
    const m = await measured(pkg("windows-forensics", "lnk_jumplist"), cwd, { path: "work/report.lnk" }, { PATH: `${bin}:${process.env.PATH}`, FLOOD_PIDS: pids });
    const a = await checkTool("lnk_jumplist", m, pids, /lnkinfo printed past its cap and was ended/, ["partial"]);
    assert.match(a.status_basis, /printed past the shared block's output cap/);
  });
});
