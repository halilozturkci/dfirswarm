/**
 * The helpers of tests/windows-tool-contract.ts, proved twice: they pass on the three tools that carry the windows STOP, PAGE and PLACE
 * blocks (regkv, shellbags, amcache_apps), and each one fails on a stand-in tool that breaks its property (no handler, a second document
 * while the answer is written, a temporary file left, a smaller result put over a larger one, a traceback on `[]`, a child left alive, a
 * deadline that is not read). A helper that passes a broken tool would be a false claim of every suite that uses it.
 */
import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import { withCwd } from "./tool-library-harness.ts";
import { VARIANTS, type Node } from "./windows-stub-regipy.ts";
import {
  STOP_STATUS, assertJsonAnswer, assertStopped, endRecorded, fuzzTool, jobEnv, manifestOf, removeTemporary, rerunSmaller, runTool, standIn, stopAt, typeConfused,
  withDeadline, type Moment, type StopSignal,
} from "./windows-tool-contract.ts";

after(() => {
  endRecorded();
  removeTemporary();
});

const SIGNALS: StopSignal[] = ["SIGTERM", "SIGINT", "SIGHUP"];
const STAND_IN = VARIANTS[0];
const keys = (n: number, prefix = "K"): Node[] => Array.from({ length: n }, (_, i) => ({ name: prefix + String(i).padStart(5, "0") }));

// --- planted stand-in tools -----------------------------------------------------------------------------------------------------

type Bug = "none" | "nohandler" | "seconddoc" | "templeft" | "replace" | "traceback" | "childleft" | "nodeadline";

/**
 * A small tool with the contract, and one way to break it. Its modes (the `mode` argument): big (a 3 MB answer), temp (a hidden file, then
 * waits), child (starts the stand-in program `contract-child` and waits), write (a result of `rows` lines, placed without replacing),
 * clock (loops until its deadline).
 */
function stubSource(bug: Bug): string {
  return String.raw`#!/usr/bin/env python3
import json, os, signal, subprocess, sys, time
from pathlib import Path

BUG = "${bug}"
TEMPS = []
CHILDREN = []
DEADLINE_SECONDS = 30  # a stand-in
# BEGIN SHARED STOP
def _on_signal(signum, _frame):
    if BUG != "templeft":
        for t in TEMPS:
            try:
                os.unlink(t)
            except OSError:
                pass
    if BUG != "childleft":
        for c in CHILDREN:
            c.kill()
    os.write(1, (json.dumps({"error": "stopped", "status": "interrupted", "status_basis": "stopped by signal %d" % signum, "signal": signum}) + "\n").encode())
    os._exit(128 + signum)


if BUG != "nohandler":
    for _s in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(_s, _on_signal)
# END SHARED STOP


def out_dir():
    if os.environ.get("JOB_ID") and os.environ.get("OUT"):
        return Path(os.environ["OUT"]) / "tool-output"
    return Path("work") / os.environ.get("AGENT_ID", "tool") / "tool-output"


def say(doc):
    if BUG != "seconddoc":
        signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT, signal.SIGHUP})
    sys.stdout.write(json.dumps(doc) + "\n")
    sys.stdout.flush()


def fail(message):
    say({"error": message, "status": "failed", "status_basis": "the arguments were refused: " + message})
    sys.exit(1)


def place(tmp, path):
    if BUG == "replace":
        os.replace(tmp, path)
        return path
    n = 1
    while True:
        candidate = path if n == 1 else path.with_name("%s-%d%s" % (path.stem, n, path.suffix))
        try:
            fd = os.open(str(candidate), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            n += 1
            continue
        os.close(fd)
        os.replace(tmp, candidate)
        return candidate


def main():
    args = json.loads(sys.stdin.read() or "null")
    if BUG == "traceback":
        mode = args["mode"]
    else:
        if not isinstance(args, dict):
            fail("the arguments are one JSON object")
        mode = args.get("mode", "write")
        if not isinstance(mode, str) or mode not in ("big", "temp", "child", "write", "clock"):
            fail("mode is one of big, temp, child, write, clock")
    rows = args.get("rows", 5) if isinstance(args, dict) else 5
    if isinstance(rows, bool) or not isinstance(rows, int) or not 0 <= rows <= 100000:
        fail("rows is a whole number from 0 to 100000")
    if mode == "big":
        say({"status": "complete", "status_basis": "a large answer", "blob": "x" * 3_000_000})
    elif mode == "temp":
        d = out_dir()
        d.mkdir(parents=True, exist_ok=True)
        tmp = d / ".stub-held"
        tmp.write_text("held")
        TEMPS.append(str(tmp))
        time.sleep(40)
        os.unlink(tmp)
        say({"status": "complete", "status_basis": "waited"})
    elif mode == "child":
        CHILDREN.append(subprocess.Popen(["contract-child"]))
        CHILDREN[0].wait()
        say({"status": "complete", "status_basis": "the child ended"})
    elif mode == "clock":
        end = time.monotonic() + (0 if BUG == "none" and DEADLINE_SECONDS == 0 else DEADLINE_SECONDS)
        while BUG != "nodeadline" and time.monotonic() < end:
            time.sleep(0.01)
        if BUG == "nodeadline":
            time.sleep(1)
        say({"status": "partial", "status_basis": "the clock ran out"})
    else:
        d = out_dir()
        d.mkdir(parents=True, exist_ok=True)
        tmp = d / ".stub-tmp"
        tmp.write_text("".join("row %d\n" % i for i in range(rows)))
        placed = place(tmp, d / "stub.jsonl")
        say({"status": "complete", "status_basis": "wrote %d rows" % rows, "all_results": placed.name})


if __name__ == "__main__":
    main()
`;
}

async function planted(bug: Bug, root: string): Promise<string> {
  const dir = join(root, bug, "tools", `stub_${bug}`);
  await mkdir(dir, { recursive: true });
  const script = join(dir, "run.py");
  await writeFile(script, stubSource(bug));
  await writeFile(join(dir, "manifest.json"), JSON.stringify({ params: { mode: { type: "string" }, rows: { type: "integer" } } }));
  return script;
}

async function scratch(): Promise<{ root: string; done: () => Promise<void> }> {
  const root = await mkdtemp(join(tmpdir(), "contract-"));
  return { root, done: () => rm(root, { recursive: true, force: true }) };
}

const MOMENTS: Array<[Moment, Record<string, unknown>]> = [
  ["early", {}],
  ["temp", { mode: "temp" }],
  ["child", { mode: "child" }],
  ["print", { mode: "big" }],
];

/** Run a planted tool at a moment; returns what assertStopped says, or the failure it threw. */
async function stopPlanted(script: string, cwd: string, moment: Moment, args: Record<string, unknown>, signal: StopSignal): Promise<{ failure?: string }> {
  const bin = join(cwd, "bin");
  const pidFile = join(cwd, "child.pid");
  await standIn(bin, "contract-child", pidFile);
  const env = { PATH: `${bin}:${process.env.PATH ?? ""}` };
  const run = await stopAt(script, args, env, moment, signal, { cwd, pidFile });
  try {
    assertStopped(run, signal);
    return {};
  } catch (error) {
    return { failure: String((error as Error).message) };
  }
}

// --- the helpers pass a tool that keeps the contract ------------------------------------------------------------------------------

test("a planted tool without a bug passes every moment and every signal (the control of the cases that follow)", async () => {
  const s = await scratch();
  try {
    const script = await planted("none", s.root);
    for (const [moment, args] of MOMENTS) {
      for (const signal of SIGNALS) {
        const cwd = await mkdtemp(join(s.root, "run-"));
        const got = await stopPlanted(script, cwd, moment, args, signal);
        assert.equal(got.failure, undefined, `${moment} ${signal}: ${got.failure}`);
      }
    }
  } finally {
    await s.done();
  }
});

test("withDeadline sets the constant in a copy, leaves the tool alone, and throws when the line is absent", async () => {
  const s = await scratch();
  try {
    const script = await planted("none", s.root);
    const zero = withDeadline(script, 0);
    assert.notEqual(zero, script);
    assert.match(await readFile(zero, "utf8"), /^DEADLINE_SECONDS = 0 /m);
    assert.match(await readFile(script, "utf8"), /^DEADLINE_SECONDS = 30 /m);
    const nolines = join(s.root, "plain.py");
    await writeFile(nolines, "print(1)\n");
    assert.throws(() => withDeadline(nolines, 0), /no line "DEADLINE_SECONDS/);
    // the pack's tools carry the line the helper edits
    for (const tool of ["regkv", "shellbags", "amcache_apps"]) assert.match(await readFile(withDeadline(tool, 0), "utf8"), /^DEADLINE_SECONDS = 0 /m, tool);
  } finally {
    await s.done();
  }
});

test("withDeadline(…, 0) turns the clock of the three registry tools hostile: partial with a status_basis", async () => {
  await withCwd(async (cwd) => {
    const tree: Node[] = [{ name: "Root", children: [{ name: "A", children: keys(5) }, { name: "B", children: keys(5) }, { name: "InventoryApplicationFile", children: keys(5) }] }];
    const env = await STAND_IN.write(cwd, "work/h.dat", { name: "HIVE", children: tree });
    for (const [tool, args] of [
      ["regkv", { hive: "work/h.dat", key: "Root", recurse: true, depth: 3 }],
      ["shellbags", { hive: "work/h.dat", key: "Root" }],
      ["amcache_apps", { hive: "work/h.dat" }],
    ] as Array<[string, Record<string, unknown>]>) {
      const answer = assertJsonAnswer(await runTool(withDeadline(tool, 0), cwd, args, { ...env }), tool);
      assert.equal(answer.status, "partial", tool);
    }
  });
});

test("withDeadline catches a planted tool that does not read its clock", async () => {
  const s = await scratch();
  try {
    const good = withDeadline(await planted("none", s.root), 0);
    const bad = withDeadline(await planted("nodeadline", s.root), 0);
    const cwd = await mkdtemp(join(s.root, "run-"));
    const started = Date.now();
    const answer = assertJsonAnswer(await runTool(good, cwd, { mode: "clock" }), "good");
    assert.equal(answer.status, "partial");
    assert.ok(Date.now() - started < 1_500, "a zero deadline ends at once");
    // the bad stub sleeps a second past the clock: the caller's own check (a time bound) is what sees it
    const slow = Date.now();
    await runTool(bad, cwd, { mode: "clock" });
    assert.ok(Date.now() - slow >= 1_000);
  } finally {
    await s.done();
  }
});

for (const variant of [VARIANTS[0]]) {
  test(`stopAt and assertStopped pass regkv, shellbags and amcache_apps at early, temp and print, with all three signals [${variant.label}]`, async () => {
    await withCwd(async (cwd) => {
      const big: Node[] = [{ name: "Root", children: [{ name: "InventoryApplicationFile", children: keys(25_000).map((k) => ({ ...k, children: [{ name: "c" }] })) }] }];
      const env = await variant.write(cwd, "work/h.dat", { name: "HIVE", children: big });
      const cases: Array<[string, Record<string, unknown>, Record<string, unknown>]> = [
        ["regkv", { hive: "work/h.dat", key: "Root\\InventoryApplicationFile", recurse: true, depth: 2, limit: 1 }, { hive: "work/h.dat", key: "Root\\InventoryApplicationFile", recurse: true, depth: 2, limit: 5000 }],
        ["shellbags", { hive: "work/h.dat", key: "Root\\InventoryApplicationFile", limit: 1 }, { hive: "work/h.dat", key: "Root\\InventoryApplicationFile", limit: 5000 }],
        ["amcache_apps", { hive: "work/h.dat", limit: 1 }, { hive: "work/h.dat", limit: 5000 }],
      ];
      for (const [tool, small, large] of cases) {
        for (const signal of SIGNALS) {
          assertStopped(await stopAt(tool, small, env, "early", signal, { cwd }), signal);
          const hidden = assertStopped(await stopAt(tool, small, env, "temp", signal, { cwd }), signal);
          assert.equal(hidden.answered, true, `${tool} ${signal} answered at the temp moment`);
        }
        const printed = assertStopped(await stopAt(tool, large, env, "print", "SIGTERM", { cwd }), "SIGTERM");
        assert.equal(printed.answered, false, `${tool}: the signal waited for the answer to be written whole`);
      }
    });
  });
}

test("rerunSmaller passes the three registry tools: the first file is kept and the second takes -2 and is named", async () => {
  await withCwd(async (cwd) => {
    const row = { name: "Path", type: "sz" as const, value: "C:\\a.exe" };
    const write = (n: number) =>
      STAND_IN.write(cwd, "work/h.dat", {
        name: "HIVE",
        children: [{ name: "Big", children: keys(n).map((k) => ({ ...k, values: [row] })) }, { name: "Root", children: [{ name: "InventoryApplicationFile", children: keys(n).map((k) => ({ ...k, values: [row] })) }] }],
      });
    const env = await write(60);
    for (const [tool, args] of [
      ["regkv", { hive: "work/h.dat", key: "Big", recurse: true, depth: 1, limit: 2 }],
      ["shellbags", { hive: "work/h.dat", key: "Big", limit: 2 }],
      ["amcache_apps", { hive: "work/h.dat", limit: 2 }],
    ] as Array<[string, Record<string, unknown>]>) {
      await write(60);
      const out = await rerunSmaller(tool, args, args, env, { cwd, between: async () => void (await write(8)) });
      assert.ok(out.added.length >= 1, tool);
      await rm(join(cwd, "out"), { recursive: true, force: true });
    }
  });
});

test("typeConfused is repeatable by seed, bounded at 1,000, and every set is answered in JSON by the three registry tools", async () => {
  const manifest = manifestOf("regkv");
  const a = typeConfused(manifest, 200, 7);
  const b = typeConfused(manifest, 200, 7);
  assert.deepEqual(a, b);
  assert.notDeepEqual(typeConfused(manifest, 200, 8), a);
  assert.deepEqual(a.slice(0, 4), [[], 5, "x", null]);
  assert.throws(() => typeConfused(manifest, 1001, 1), /1 to 1000/);
  const sets = JSON.stringify(a);
  for (const wrong of ["\\u0000", "\\ud800", "4611686018427388000", "1.5", "-1"]) assert.ok(sets.includes(wrong), `the sets hold ${wrong}`);
  await withCwd(async (cwd) => {
    const env = await STAND_IN.write(cwd, "work/h.dat", { name: "HIVE", children: [{ name: "Root", children: keys(3) }] });
    for (const [tool, base] of [
      ["regkv", { hive: "work/h.dat", key: "Root" }],
      ["shellbags", { hive: "work/h.dat", key: "Root" }],
      ["amcache_apps", { hive: "work/h.dat" }],
    ] as Array<[string, Record<string, unknown>]>) {
      const statuses = await fuzzTool(tool, typeConfused(manifestOf(tool), 150, 11, base), 11, { cwd, env });
      assert.ok(Object.values(statuses).reduce((x, y) => x + y, 0) === 150, tool);
    }
  });
});

// --- each helper fails on a tool that breaks its property -----------------------------------------------------------------------------

test("a tool with no handler is caught at early, temp and child (at print the signal is held back, so the answer is whole and the tool passes)", async () => {
  const s = await scratch();
  try {
    const script = await planted("nohandler", s.root);
    for (const [moment, args] of MOMENTS.filter(([m]) => m !== "print")) {
      const cwd = await mkdtemp(join(s.root, "run-"));
      const got = await stopPlanted(script, cwd, moment, args, "SIGTERM");
      assert.ok(got.failure, `${moment}: a tool with no handler passed`);
    }
  } finally {
    await s.done();
  }
});

test("a tool that writes a second document while its answer is written is caught at print", async () => {
  const s = await scratch();
  try {
    const script = await planted("seconddoc", s.root);
    const got = await stopPlanted(script, await mkdtemp(join(s.root, "run-")), "print", { mode: "big" }, "SIGTERM");
    assert.match(got.failure ?? "", /not exactly one JSON document/);
  } finally {
    await s.done();
  }
});

test("a tool that leaves a hidden temporary file is caught at temp", async () => {
  const s = await scratch();
  try {
    const script = await planted("templeft", s.root);
    const got = await stopPlanted(script, await mkdtemp(join(s.root, "run-")), "temp", { mode: "temp" }, "SIGINT");
    assert.match(got.failure ?? "", /hidden files were left behind/);
  } finally {
    await s.done();
  }
});

test("a tool that leaves a started program alive is caught at child, and the helper ends the program itself", async () => {
  const s = await scratch();
  try {
    const script = await planted("childleft", s.root);
    const cwd = await mkdtemp(join(s.root, "run-"));
    const got = await stopPlanted(script, cwd, "child", { mode: "child" }, "SIGHUP");
    assert.match(got.failure ?? "", /stand-in program started by the tool is still alive/);
    const pid = Number((await readFile(join(cwd, "child.pid"), "utf8")).trim());
    await new Promise((r) => setTimeout(r, 100));
    assert.throws(() => process.kill(pid, 0), "the stand-in program was ended by the helper");
  } finally {
    await s.done();
  }
});

test("a tool that puts a smaller result over a larger one is caught by rerunSmaller; the tool that places it under -2 passes", async () => {
  const s = await scratch();
  try {
    const good = await planted("none", s.root);
    const ok = await rerunSmaller(good, { mode: "write", rows: 50 }, { mode: "write", rows: 5 }, {}, { cwd: await mkdtemp(join(s.root, "run-")) });
    assert.deepEqual(ok.added, ["tool-output/stub-2.jsonl"]);
    const bad = await planted("replace", s.root);
    await assert.rejects(rerunSmaller(bad, { mode: "write", rows: 50 }, { mode: "write", rows: 5 }, {}, { cwd: await mkdtemp(join(s.root, "run-")) }), /was replaced \(\d+ bytes before/);
  } finally {
    await s.done();
  }
});

test("rerunSmaller refuses a first run that wrote no file (it would prove nothing)", async () => {
  const s = await scratch();
  try {
    const good = await planted("none", s.root);
    await assert.rejects(rerunSmaller(good, { mode: "big", rows: 0 }, { mode: "write", rows: 5 }, { ...jobEnv(s.root, "x") }, { cwd: await mkdtemp(join(s.root, "run-")) }), /wrote no result file/);
  } finally {
    await s.done();
  }
});

test("a traceback on a top-level [] is caught by assertJsonAnswer, and the tool that refuses in JSON passes the whole fuzz", async () => {
  const s = await scratch();
  try {
    const cwd = await mkdtemp(join(s.root, "run-"));
    const bad = await planted("traceback", s.root);
    const run = await runTool(bad, cwd, []);
    assert.throws(() => assertJsonAnswer(run, "[]"), /traceback/);
    await assert.rejects(fuzzTool(bad, typeConfused(manifestOf(bad), 30, 3), 3, { cwd }), /traceback|not one JSON document/);
    const good = await planted("none", s.root);
    const statuses = await fuzzTool(good, typeConfused(manifestOf(good), 60, 3), 3, { cwd });
    assert.ok((statuses.failed ?? 0) > 0);
  } finally {
    await s.done();
  }
});

test("assertJsonAnswer wants a status and a non-empty status_basis, and one JSON object", () => {
  const ok = { code: 0, stdout: JSON.stringify({ status: "complete", status_basis: "all read" }), stderr: "" };
  assert.equal(assertJsonAnswer(ok).status, "complete");
  assert.throws(() => assertJsonAnswer({ ...ok, stdout: JSON.stringify({ status: "failed" }) }), /status_basis/);
  assert.throws(() => assertJsonAnswer({ ...ok, stdout: JSON.stringify({ status: "failed", status_basis: "" }) }), /status_basis/);
  assert.throws(() => assertJsonAnswer({ ...ok, stdout: "[]" }), /not a JSON object/);
  assert.throws(() => assertJsonAnswer({ ...ok, stdout: ok.stdout + ok.stdout }), /not one JSON document/);
  assert.throws(() => assertJsonAnswer({ ...ok, stderr: "Traceback (most recent call last):" }), /traceback/);
  assert.equal(STOP_STATUS, "interrupted");
});
