/**
 * The pipe-shape matrix (AGENTS.md rule 2: a defect that keeps coming back across tools sits in a block they carry in common). Every place in the
 * reverse-engineering, ransomware-response and virtualization-backup-forensics packs that reads a program's pipe is driven with a program of each shape and must answer
 * within its clock, with a truthful `timed_out`, the leftover dead afterwards:
 *   silent       the program exits 0 and leaves a process that holds its stdout and stderr and says nothing
 *   stderr       the same, holding stderr only
 *   stdin        the same, holding stdin only (the program's input pipe)
 *   writer10     a leftover that writes a line every 10 ms
 *   writer700    a leftover that writes a line every 0.7 s
 *   flood        a leftover that is `yes`
 *   never        a program that does not exit (it printed a line first)
 *   nonzero      a program that exits 3 and leaves a silent holder
 *   quiet        a program that exits 0 with nothing left behind (the control: nothing is lost, nothing waits)
 * The readers: the three hand-written run_program of clr_inspect, authenticode_verify and doc_structure (a program-exited check at the top of the loop, one second of
 * grace, then settle()), the shared block's preflight and communicate_bounded (ransomware_family_match, snapshot_chain_check and the capa-floss and static-binary
 * copies), and the two recipes' and the capa-floss recipe's file readers (run_to_files, run_child). Then the tools that read a pipe, end to end, with a holder.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { alive, sleep } from "./network-process-harness.ts";
import { NO_ADOPTION } from "./host-gates.ts";
import { RE, TOOLS, buildPe, put, stub, withCwd } from "./pack-re-harness.ts";
import type { Json } from "./pack-re-harness.ts";
import { qcow2 } from "./pack-virtualization-harness.ts";
import { ROOT } from "./tool-library-harness.ts";

const FILES: Record<string, string> = {
  clr_inspect: join(TOOLS, "clr_inspect", "run.py"),
  authenticode_verify: join(TOOLS, "authenticode_verify", "run.py"),
  doc_structure: join(TOOLS, "doc_structure", "run.py"),
  ransomware_family_match: join(ROOT, "packs", "ransomware-response", "tools", "ransomware_family_match", "run.py"),
  snapshot_chain_check: join(ROOT, "packs", "virtualization-backup-forensics", "tools", "snapshot_chain_check", "run.py"),
  "capa-floss": join(RE, "recipes", "capa-floss", "run.py"),
  "static-binary": join(RE, "recipes", "static-binary", "run.py"),
};

/** The programs: `$PIDF` is the file the leftover's pid is appended to. */
const SHAPES: Record<string, string> = {
  silent: `sleep 600 & echo $! >> "$PIDF"; echo out; exit 0`,
  stderr: `sleep 600 >/dev/null & echo $! >> "$PIDF"; echo out; exit 0`,
  stdin: `sleep 600 >/dev/null 2>&1 & echo $! >> "$PIDF"; echo out; exit 0`,
  writer10: `( while :; do echo tick; sleep 0.01; done ) & echo $! >> "$PIDF"; echo out; exit 0`,
  writer700: `( while :; do echo tick; sleep 0.7; done ) & echo $! >> "$PIDF"; echo out; exit 0`,
  flood: `( sleep 0.2; exec yes ) & echo $! >> "$PIDF"; echo out; exit 0`,
  // full-speed writers that start at once (the program's words are printed after them): a leftover that writes this fast dies of SIGPIPE the moment a pipe is closed,
  // so a reader that closes before settle() looks counts none and reads as clean
  writer1: `( while :; do printf x; sleep 0.001; done ) & echo $! >> "$PIDF"; echo out; exit 0`,
  yesout: `yes & echo $! >> "$PIDF"; echo out; exit 0`,
  yeserr: `yes >&2 & echo $! >> "$PIDF"; echo out; exit 0`,
  never: `echo $$ >> "$PIDF"; echo out; sleep 600`,
  nonzero: `sleep 600 & echo $! >> "$PIDF"; echo out; exit 3`,
  quiet: `echo out; exit 0`,
};
const LEAVING = ["silent", "stderr", "stdin", "writer10", "writer700", "flood", "nonzero", "writer1", "yesout", "yeserr"];
const FAST = ["writer1", "yesout", "yeserr"];

const DRIVER = `
import importlib.util, json, os, subprocess, sys, time
path, kind, shape, seconds, pidf = sys.argv[1], sys.argv[2], sys.argv[3], float(sys.argv[4]), sys.argv[5]
shapes = json.loads(sys.argv[6])
os.environ["PIDF"] = pidf
spec = importlib.util.spec_from_file_location("m", path)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
argv = ["sh", "-c", shapes[shape].replace("$PIDF", '"' + pidf + '"')]
started = time.monotonic()
res = {}
if kind == "run_program":
    rec = m.run_program(argv, seconds, 1 << 16)
    res = {"exit_code": rec["exit_code"], "timed_out": rec["timed_out"], "capped": rec["capped"], "flooded": rec.get("flooded", False), "out": len(rec["output"])}
elif kind == "preflight":
    code, out, err, timed = m.preflight(argv, seconds)
    res = {"exit_code": code, "timed_out": timed, "out": len(out)}
elif kind == "stdin":
    proc = m.spawn(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    m.ACTIVE.append(proc)
    try:
        out, err, timed = m.communicate_bounded(proc, seconds, input=b"a line\\n" * 200000)
    finally:
        m.ACTIVE.remove(proc)
    res = {"exit_code": None if timed else proc.returncode, "timed_out": timed, "out": len(out)}
elif kind == "run_to_files":
    code, timed = m.run_to_files(argv, os.path.join(os.path.dirname(pidf), "o"), os.path.join(os.path.dirname(pidf), "e"), seconds)
    res = {"exit_code": code, "timed_out": timed}
elif kind == "run_child":
    # the static-binary recipe's own reader: a tool run with its arguments on stdin and its output in files
    script = os.path.join(os.path.dirname(pidf), "child.py")
    open(script, "w").write("import os, subprocess, sys\\nsys.stdin.read()\\nos.execvp('sh', ['sh', '-c', os.environ['SHAPE']])\\n")
    d = os.path.dirname(pidf)
    code, timed = m.run_child(script, {}, os.path.join(d, "o"), os.path.join(d, "e"), dict(os.environ, SHAPE=shapes[shape]), seconds)
    res = {"exit_code": code, "timed_out": timed}
res["elapsed"] = round(time.monotonic() - started, 3)
res["left_behind"] = m.LEFT["left_behind"]
res["cut"] = m.PIPE_CUT["cut"] if hasattr(m, "PIPE_CUT") else 0
pids = [int(x) for x in open(pidf).read().split()] if os.path.exists(pidf) else []
def up(pid):
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    try:
        return open("/proc/%d/stat" % pid).read().rsplit(")", 1)[1].split()[0] != "Z"
    except OSError:
        return False
time.sleep(0.2)
res["alive"] = [p for p in pids if up(p)]
res["pids"] = pids
print(json.dumps(res))
`;

type Probe = { exit_code: number | null; timed_out: boolean; out?: number; capped?: boolean; flooded?: boolean; elapsed: number; left_behind: number; alive: number[]; pids: number[]; cut?: number };

async function probe(file: string, kind: string, shape: string, seconds: number, cwd: string): Promise<Probe> {
  await writeFile(join(cwd, "driver.py"), DRIVER);
  const pidf = join(cwd, "stub", "left.pids");
  await mkdir(join(cwd, "stub"), { recursive: true });
  return new Promise((resolve, reject) => {
    const child = spawn("python3", ["-I", join(cwd, "driver.py"), file, kind, shape, String(seconds), pidf, JSON.stringify(SHAPES)], { cwd, detached: true, stdio: ["ignore", "pipe", "pipe"] });
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => out.push(c));
    child.stderr.on("data", (c: Buffer) => err.push(c));
    const guard = setTimeout(() => {
      try {
        process.kill(-(child.pid as number), "SIGKILL");
      } catch {
        // gone
      }
      reject(new Error(`${file} ${kind} ${shape}: no answer in ${seconds + 40} s`));
    }, (seconds + 40) * 1000);
    child.on("close", () => {
      clearTimeout(guard);
      try {
        resolve(JSON.parse(Buffer.concat(out).toString("utf8").trim().split("\n").pop() ?? "") as Probe);
      } catch {
        reject(new Error(`${file} ${kind} ${shape}: ${Buffer.concat(err).toString("utf8")}${Buffer.concat(out).toString("utf8")}`));
      }
    });
  });
}

async function reapPids(p: Probe | undefined, cwd: string): Promise<void> {
  const text = await readFile(join(cwd, "stub", "left.pids"), "utf8").catch(() => "");
  for (const pid of text.split(/\s+/).filter(Boolean).map(Number)) if (alive(pid)) process.kill(pid, "SIGKILL");
  void p;
}

const LIMIT = 20;
/** One reader, every shape. `kind` names how the reader is called. */
function matrix(tool: string, kind: string, shapes = Object.keys(SHAPES)): void {
  for (const shape of shapes) {
    // a leftover that holds the program's pipes is found and ended only where the tool can adopt orphans (macOS answers that it cannot prove there was none: the darwin cases of the process-apply suites)
    test(`${tool} ${kind}: ${shape}`, { skip: LEAVING.includes(shape) ? NO_ADOPTION : false }, async () => {
      await withCwd(async (cwd) => {
        let p: Probe | undefined;
        try {
          if (shape === "never") {
            p = await probe(FILES[tool], kind, shape, 3, cwd);
            if (kind === "run_to_files" || kind === "run_child") assert.equal(p.timed_out, true, `${JSON.stringify(p)}`);
            else assert.equal(p.timed_out, true, `the program never ended: ${JSON.stringify(p)}`);
            assert.ok(p.elapsed < 3 + 5, `answered at ${p.elapsed} s for a clock of 3 s`);
            assert.deepEqual(p.alive, [], "the program that never ended is dead");
            return;
          }
          p = await probe(FILES[tool], kind, shape, LIMIT, cwd);
          if (FAST.includes(shape)) {
            // the program printed its words and ended while a leftover wrote at full speed: not a timeout, in time, the leftover dead, and the call knows something was left
            // (counted by settle(), or said as a flood or a cut at the byte cap), never clean
            assert.equal(p.timed_out, false, `${JSON.stringify(p)}`);
            assert.ok(p.elapsed < 6, `answered at ${p.elapsed} s for a clock of ${LIMIT} s (${shape})`);
            assert.deepEqual(p.alive, [], `the leftover is dead afterwards: ${JSON.stringify(p)}`);
            assert.ok(p.left_behind >= 1 || p.flooded === true || p.capped === true || (p.cut ?? 0) >= 1, `a leftover that wrote at full speed was counted: ${JSON.stringify(p)}`);
            return;
          }
          // the program ended: the answer says so, with its exit code, and does not say it timed out
          assert.equal(p.timed_out, false, `${JSON.stringify(p)}`);
          assert.equal(p.exit_code, shape === "nonzero" ? 3 : 0, `${JSON.stringify(p)}`);
          if (p.capped !== undefined) assert.equal(p.capped, false, "a leftover's flood is not the program's output past the cap");
          if (p.flooded !== undefined) assert.equal(p.flooded, shape === "flood", "a flood after the program ended is said, and only that");
          // one second of grace for the pipe, then settle(): well inside the clock, whatever the leftover writes
          assert.ok(p.elapsed < 6, `answered at ${p.elapsed} s for a clock of ${LIMIT} s (${shape})`);
          assert.deepEqual(p.alive, [], `the leftover is dead afterwards: ${JSON.stringify(p)}`);
          if (LEAVING.includes(shape) && kind !== "run_to_files" && kind !== "run_child") assert.ok(p.pids.length >= 1);
          if (shape === "quiet") {
            assert.equal(p.left_behind, 0);
            if (p.out !== undefined) assert.ok(p.out >= 4, "the control's output is kept");
            assert.ok(p.elapsed < 2, `a program with nothing left behind waits for nothing: ${p.elapsed} s`);
          } else if (["silent", "stderr", "stdin", "nonzero"].includes(shape) && (kind === "run_program" || kind === "preflight" || kind === "stdin")) {
            // a leftover that writes dies of SIGPIPE once the pipe is let go, and may be gone before settle() looks: only the silent ones are counted for certain
            assert.ok(p.left_behind >= 1, `a leftover was ended and counted: ${JSON.stringify(p)}`);
            // one that holds the program's output pipe gets its second of grace (a holder of stdin alone holds no output: the pipe is at its end at once)
            if (shape !== "stdin") assert.ok(p.elapsed >= 0.9, `the pipe is given its second of grace: ${p.elapsed} s`);
          }
        } finally {
          await reapPids(p, cwd);
        }
      });
    });
  }
}

// the three hand-written readers of the pack
matrix("clr_inspect", "run_program");
matrix("authenticode_verify", "run_program");
matrix("doc_structure", "run_program");
// the shared block's readers, in each carrier of these packs that reads a program's pipe
matrix("ransomware_family_match", "preflight");
matrix("ransomware_family_match", "stdin");
matrix("snapshot_chain_check", "preflight");
matrix("capa-floss", "preflight");
matrix("static-binary", "preflight");
// the file readers: the program is waited for, not its pipe
matrix("capa-floss", "run_to_files");
matrix("static-binary", "run_child", ["silent", "writer10", "flood", "never", "nonzero", "quiet"]);

// ---- the tools that read a pipe, end to end, with a holder ---------------------------------------------------------------------------------------------

async function timed<T>(fn: () => Promise<T>): Promise<{ value: T; ms: number }> {
  const start = Date.now();
  const value = await fn();
  return { value, ms: Date.now() - start };
}
async function runTool(file: string, cwd: string, bin: string, args: unknown, env: Record<string, string> = {}): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn("python3", [file], { cwd, env: { ...process.env, PATH: `${bin}:${process.env.PATH ?? ""}`, AGENT_ID: "s1", PIDF: join(cwd, "stub", "left.pids"), ...env }, detached: true });
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => out.push(c));
    child.stderr.on("data", (c: Buffer) => err.push(c));
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stdout: Buffer.concat(out).toString("utf8"), stderr: Buffer.concat(err).toString("utf8") }));
    child.stdin.end(JSON.stringify(args));
  });
}
const parse = (r: { stdout: string; stderr: string }): Json => {
  assert.doesNotMatch(r.stderr, /Traceback/);
  return JSON.parse(r.stdout);
};
const HOLDERS = ["silent", "writer10", "flood", "writer1", "yesout"] as const;
/** The holders that write at full speed: they die of SIGPIPE when the pipe is cut, and the cut says partial on every host; the others are found only where the tool adopts orphans. */
const FLOODS = ["flood", "yesout"];
const STRICT = ["silent", "writer10"];
const HOLD: Record<string, string> = {
  silent: `sleep 600 & echo $! >> "$PIDF"`,
  // a leftover starts writing after the program has printed its words and ended: the words are the program's, the lines after them are not
  writer10: `( sleep 0.1; while :; do echo tick; sleep 0.01; done ) & echo $! >> "$PIDF"`,
  flood: `( sleep 0.2; exec yes ) & echo $! >> "$PIDF"`,
  writer1: `( while :; do printf x; sleep 0.001; done ) & echo $! >> "$PIDF"`,
  yesout: `yes & echo $! >> "$PIDF"`,
};

for (const shape of HOLDERS) {
  test(`authenticode_verify end to end, a ${shape} holder on osslsigncode: the verification is read, nothing is said to have timed out, the holder is dead`, { skip: FLOODS.includes(shape) ? false : NO_ADOPTION }, async () => {
    await withCwd(async (cwd, bin) => {
      await mkdir(join(cwd, "stub"), { recursive: true });
      await stub(bin, "osslsigncode", `case "$1" in
--version) printf 'osslsigncode 2.5, using:\\n'; exit 0;;
verify) ${HOLD[shape]}; printf 'Current PE checksum   : 00000000\\nCalculated PE checksum: 00007FBE\\n\\nNo signature found\\n\\nFailed\\n'; exit 1;;
esac
exit 2`);
      await put(cwd, "work/a.exe", buildPe({}).file);
      try {
        const { value, ms } = await timed(() => runTool(FILES.authenticode_verify, cwd, bin, { path: "work/a.exe", max_seconds: 30 }));
        const a = parse(value);
        assert.ok(ms < 12000, `${ms} ms`);
        assert.doesNotMatch(a.status_basis, /did not finish/);
        assert.notEqual(a.status, "complete", "a process was left and ended");
        if (STRICT.includes(shape)) {
          assert.equal(a.verifier.exit_code, 1);
          assert.equal(a.status, "partial");
          assert.equal(a.verification, "unsigned");
        }
        if (shape === "silent") assert.ok(a.program_group.left_behind >= 1);
      } finally {
        await reapPids(undefined, cwd);
      }
      for (const pid of (await readFile(join(cwd, "stub", "left.pids"), "utf8")).split(/\s+/).filter(Boolean).map(Number)) assert.equal(alive(pid), false, `pid ${pid}`);
    });
  });
}

for (const shape of HOLDERS) {
  test(`ransomware_family_match end to end, a ${shape} holder on yara: the hits are read, the answer is in time, the holder is dead`, { skip: FLOODS.includes(shape) ? false : NO_ADOPTION }, async () => {
    await withCwd(async (cwd, bin) => {
      await mkdir(join(cwd, "stub"), { recursive: true });
      await stub(bin, "yara", `if [ "$1" = "--version" ]; then echo 4.5.0; exit 0; fi
cat > /dev/null
${HOLD[shape]}
exit 0`);
      const note = join(cwd, "ev", "info.txt");
      await mkdir(join(cwd, "ev"), { recursive: true });
      await writeFile(note, "!!! All of your files are encrypted !!!\n");
      await writeFile(join(cwd, "vals.jsonl"), JSON.stringify({ finding_id: "N000001", note_id: "N000001", file: note, offset: 0, kind: "note_preview", encoding: "utf-8", validation: null, value: "preview" }) + "\n");
      try {
        const { value, ms } = await timed(() => runTool(FILES.ransomware_family_match, cwd, bin, { values_file: "vals.jsonl", extensions: [".phobos"], max_seconds: 30 }));
        const a = parse(value);
        // the block's communicate_bounded keeps what a flood writes in the second after the program ended (PKG-P0b caps that); the call is still far inside its 120 s
        assert.ok(ms < (shape === "flood" ? 60000 : 12000), `${ms} ms`);
        assert.equal(a.engine.ran, true);
        assert.doesNotMatch(a.status_basis, /timed out|time limit/);
        assert.equal(a.status, "partial");
        if (shape === "silent") assert.ok(a.program_group.left_behind >= 1);
      } finally {
        await reapPids(undefined, cwd);
      }
      await sleep(100);
      for (const pid of (await readFile(join(cwd, "stub", "left.pids"), "utf8")).split(/\s+/).filter(Boolean).map(Number)) assert.equal(alive(pid), false, `pid ${pid}`);
    });
  });
}

for (const shape of HOLDERS) {
  test(`snapshot_chain_check end to end, a ${shape} holder on qemu-img: the reading is taken, the answer is in time, the holder is dead`, { skip: FLOODS.includes(shape) ? false : NO_ADOPTION }, async () => {
    await withCwd(async (cwd, bin) => {
      await mkdir(join(cwd, "stub"), { recursive: true });
      await stub(bin, "qemu-img", `${HOLD[shape]}
printf '{"virtual-size": 1073741824, "filename": "x", "format": "qcow2", "actual-size": 4096, "dirty-flag": false}\\n'
exit 0`);
      await put(cwd, "inputs/q/base.qcow2", qcow2({ size: 1073741824n }));
      try {
        const { value, ms } = await timed(() => runTool(FILES.snapshot_chain_check, cwd, bin, { root: "inputs/q", qemu_img: "auto", max_seconds: 30 }));
        const a = parse(value);
        assert.ok(ms < 12000, `${ms} ms`);
        assert.equal(a.qemu_img.checked + a.qemu_img.failed >= 1, true);
        assert.equal(a.disks[0].qemu_img.timed_out, false, "qemu-img ended 0: it did not time out");
        assert.equal(a.disks[0].qemu_img.exit_code, 0);
        assert.notEqual(a.status, "complete", "a process was left and ended");
        if (shape === "silent") {
          assert.equal(a.qemu_img.failed, 0, "qemu-img's JSON was read whole");
          assert.equal(a.status, "partial");
          assert.ok(a.program_group.left_behind >= 1);
        }
      } finally {
        await reapPids(undefined, cwd);
      }
      for (const pid of (await readFile(join(cwd, "stub", "left.pids"), "utf8")).split(/\s+/).filter(Boolean).map(Number)) assert.equal(alive(pid), false, `pid ${pid}`);
    });
  });
}
