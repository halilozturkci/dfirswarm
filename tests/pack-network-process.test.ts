/**
 * The process block the network pack's engine tools (and archive_extract) share: how it finds what an engine started so that
 * a deadline or a signal ends the whole tree. The block is run here as text, with the /proc listing taken away and libproc
 * and ps replaced, so the same cases run on macOS and on Linux: the child of the engine must be gone each time, a program
 * that is not below the engine must stay, and ps is given long enough to answer on a loaded host.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmod, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { EXTRACT } from "./pack-network-harness.ts";
import { withCwd } from "./tool-library-harness.ts";

const CODE = `
import json, os, signal, subprocess, sys, time, types
data = json.loads(sys.stdin.read())
real_isdir = os.path.isdir
shim_path = types.SimpleNamespace(**{k: getattr(os.path, k) for k in dir(os.path) if not k.startswith("__")})
shim_path.isdir = lambda p: False if p == "/proc/self" else real_isdir(p)
shim = types.SimpleNamespace(**{k: getattr(os, k) for k in dir(os) if not k.startswith("__")})
shim.path = shim_path
ns = {"os": shim, "signal": signal, "subprocess": subprocess, "sys": sys}
exec(data["block"], ns)
mode = data["mode"]
if mode == "libproc_empty":
    ns["_children_libproc"] = lambda pid: []
elif mode == "libproc_working_and_empty":
    ns["_children_libproc"] = lambda pid: [] if pid != os.getpid() else [engine.pid]
elif mode == "libproc_missing":
    ns["_children_libproc"] = lambda pid: None
engine = subprocess.Popen(["sh", "-c", "sleep 300 & echo $! > " + data["grandchild"] + "; wait"])
decoy = subprocess.Popen(["sleep", "300"])
for _ in range(100):
    if os.path.exists(data["grandchild"]) and open(data["grandchild"]).read().strip():
        break
    time.sleep(0.05)
grandchild = int(open(data["grandchild"]).read())
began = time.monotonic()
ns["kill_tree"](engine)
engine.wait()
took = time.monotonic() - began
time.sleep(0.3)
def alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False
result = {"took": took, "grandchild_alive": alive(grandchild), "decoy_alive": decoy.poll() is None}
decoy.kill()
try:
    os.kill(grandchild, signal.SIGKILL)
except OSError:
    pass
print(json.dumps(result))
`;

async function processBlock(): Promise<string> {
  const text = await readFile(EXTRACT, "utf8");
  return text.slice(text.indexOf("# BEGIN SHARED PROCESS"), text.indexOf("# END SHARED PROCESS"));
}

async function run(cwd: string, bin: string, mode: string, name: string): Promise<{ took: number; grandchild_alive: boolean; decoy_alive: boolean }> {
  const out = spawnSync("python3", ["-c", CODE], { cwd, input: JSON.stringify({ block: await processBlock(), mode, grandchild: join(cwd, `${name}.pid`) }), encoding: "utf8", env: { ...process.env, PATH: `${bin}:${process.env.PATH}` } });
  assert.equal(out.status, 0, out.stderr);
  return JSON.parse(out.stdout);
}

async function slowPs(bin: string, seconds: number): Promise<void> {
  const real = spawnSync("sh", ["-c", "command -v ps"], { encoding: "utf8" }).stdout.trim();
  await writeFile(join(bin, "ps"), `#!/bin/sh\nsleep ${seconds}\nexec ${real} "$@"\n`);
  await chmod(join(bin, "ps"), 0o755);
}

test("when libproc lists nothing the tree is still found: ps is asked, the engine's grandchild is killed and a program beside the engine is not", async () => {
  await withCwd(async (cwd, bin) => {
    const seen = await run(cwd, bin, "libproc_empty", "a");
    assert.equal(seen.grandchild_alive, false, "the grandchild survived");
    assert.equal(seen.decoy_alive, true, "a program that is not below the engine was killed");
  });
});

test("when libproc is missing the tree is found from ps, and a ps that needs 4 seconds is waited for (the wait was 3 seconds: the grandchild survived)", async () => {
  await withCwd(async (cwd, bin) => {
    await slowPs(bin, 4);
    const seen = await run(cwd, bin, "libproc_missing", "b");
    assert.ok(seen.took >= 3.5, `took ${seen.took}`);
    assert.equal(seen.grandchild_alive, false, "the grandchild survived a slow ps");
    assert.equal(seen.decoy_alive, true);
  });
});

test("when libproc has just listed the engine as the tool's own child, an empty answer for the engine is believed and ps is not run", async () => {
  await withCwd(async (cwd, bin) => {
    await slowPs(bin, 30);
    const seen = await run(cwd, bin, "libproc_working_and_empty", "c");
    assert.ok(seen.took < 8, `took ${seen.took}: ps was waited for`);
    assert.equal(seen.decoy_alive, true);
  });
});

const REAPED = `
import json, os, signal, subprocess, sys, time
data = json.loads(sys.stdin.read())
ns = {"os": os, "signal": signal, "subprocess": subprocess, "sys": sys}
exec(data["block"], ns)
# a program that was started and waited for, whose pid is now (as if reused) the pid of an unrelated process that has a child of its own
done = subprocess.Popen(["true"])
done.wait()
unrelated = subprocess.Popen(["sh", "-c", "sleep 300 & echo $! > " + data["child"] + "; wait"])
for _ in range(100):
    if os.path.exists(data["child"]) and open(data["child"]).read().strip():
        break
    time.sleep(0.05)
child = int(open(data["child"]).read())
done.pid = unrelated.pid
ns["ACTIVE"].append(done)
ns["kill_tree"](done)
time.sleep(0.3)
def alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False
result = {"unrelated_alive": unrelated.poll() is None, "child_alive": alive(child), "walked": ns["descendants"](unrelated.pid) != []}
for pid in (child, unrelated.pid):
    try:
        os.kill(pid, signal.SIGKILL)
    except OSError:
        pass
print(json.dumps(result))
`;

test("a program that was already waited for is not walked or signalled, even when its pid is another process's by now: that process and its child survive", async () => {
  await withCwd(async (cwd, bin) => {
    const out = spawnSync("python3", ["-c", REAPED], { cwd, input: JSON.stringify({ block: await processBlock(), child: join(cwd, "reaped.pid") }), encoding: "utf8", env: { ...process.env, PATH: `${bin}:${process.env.PATH}` } });
    assert.equal(out.status, 0, out.stderr);
    const seen = JSON.parse(out.stdout);
    assert.equal(seen.unrelated_alive, true, "a process that only has the reused pid was killed");
    assert.equal(seen.child_alive, true, "the child of the process that has the reused pid was killed");
    assert.equal(seen.walked, true, "the unrelated process does have a child to walk (the case is real)");
  });
});

test("the walk below an engine has no bound of its own: 300 children and a 60-deep chain are all found and killed", async () => {
  await withCwd(async (cwd, bin) => {
    await writeFile(join(cwd, "chain.sh"), 'if [ "$1" -gt 0 ]; then sh "$0" $(( $1 - 1 )) & wait; else sleep 300; fi\n');
    const code = `
import json, os, signal, subprocess, sys, time
data = json.loads(sys.stdin.read())
ns = {"os": os, "signal": signal, "subprocess": subprocess, "sys": sys}
exec(data["block"], ns)
engine = subprocess.Popen(["sh", "-c", "for i in $(seq 300); do sleep 300 & done; sh chain.sh 60 & wait"], cwd=data["cwd"])
time.sleep(3)
found = ns["descendants"](engine.pid)
ns["kill_tree"](engine)
engine.wait()
time.sleep(0.5)
alive = 0
for p in found:
    try:
        os.kill(p, 0)
        alive += 1
    except OSError:
        pass
print(json.dumps({"found": len(found), "alive": alive}))
`;
    const out = spawnSync("python3", ["-c", code], { cwd, input: JSON.stringify({ block: await processBlock(), cwd }), encoding: "utf8", timeout: 60_000 });
    assert.equal(out.status, 0, out.stderr);
    const seen = JSON.parse(out.stdout);
    assert.ok(seen.found >= 360, `found ${seen.found}`);
    assert.equal(seen.alive, 0, "some of what was found survived");
  });
});
