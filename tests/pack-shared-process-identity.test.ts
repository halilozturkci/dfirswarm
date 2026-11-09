/**
 * The process block on a host with no /proc (macOS), where one process is read two ways: libproc gives the start time of a child seen while the
 * program runs, and `ps` gives the table the leftovers are looked for in. The two write one start time differently, so a leftover seen through
 * libproc and listed through ps was taken for another process that had the pid, and was never ended. This file runs the block on a Linux host
 * made to look like that (no /proc/self, libproc answered from /proc, `ps` as it is) and holds that the leftover is found and ended, in both
 * lineages of the block. (On macOS itself the same cases run against the real libproc in tests/pack-shared-process.test.ts.)
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { join } from "node:path";
import { test } from "node:test";
import { PYTHON3, onlyLinux } from "./host-gates.ts";
import { gone, pidFile, withCwd } from "./pack-network-harness.ts";
import { ROOT } from "./tool-library-harness.ts";

const SIM = String.raw`
import json, os, re, signal, subprocess, sys, time, types
src = open(sys.argv[1]).read()
block = re.search(r"^# BEGIN SHARED PROCESS\n.*?^# END SHARED PROCESS\n", src, re.S | re.M).group(0)
work = sys.argv[2]
fake_sys = types.SimpleNamespace(platform="darwin", stdout=sys.stdout, stderr=sys.stderr, stdin=sys.stdin, exit=sys.exit, argv=sys.argv, executable=sys.executable, version_info=sys.version_info)
real_isdir = os.path.isdir
class FakeOs:
    def __getattr__(self, n): return getattr(os, n)
    path = types.SimpleNamespace(**{k: getattr(os.path, k) for k in dir(os.path) if not k.startswith("__")})
fo = FakeOs()
fo.path.isdir = lambda p: False if str(p).startswith("/proc") else real_isdir(p)
ns = {"os": fo, "signal": signal, "subprocess": subprocess, "sys": fake_sys, "describe": str}
exec(block, ns)
def stat_fields(pid):
    data = open("/proc/%s/stat" % pid, "rb").read()
    return data[data.rindex(b")") + 2:].split()
def start_of(pid):
    try:
        return (int(stat_fields(pid)[19]), 0)
    except OSError:
        return None
def kids_of(pid):
    out = []
    for e in os.listdir("/proc"):
        if e.isdigit():
            try:
                if int(stat_fields(e)[1]) == pid:
                    out.append(int(e))
            except OSError:
                pass
    return out
ns["_libproc_start"] = start_of
ns["_children_libproc"] = kids_of
holder = work + "/holder.pid"
proc = ns["spawn"](["sh", "-c", "sleep 120 & echo $! > " + holder + "; sleep 0.8; echo '{\"ok\": true}'; exit 0"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
ns["ACTIVE"].append(proc)
out, err, timed_out = ns["communicate_bounded"](proc, 30)
ns["ACTIVE"].remove(proc)
print(json.dumps({"out": out.decode(), "timed_out": timed_out, "verdict": ns["process_verdict"]()}), flush=True)
`;

const FAMILIES: [string, string][] = [
  ["general", join(ROOT, "packs", "network-forensics", "tools", "zeek_run", "run.py")],
  ["windows", join(ROOT, "packs", "windows-forensics", "tools", "yara_scan", "run.py")],
];

for (const [family, script] of FAMILIES) {
  test(`${family}: a leftover seen through libproc and listed through ps is the same process, and is ended`, { skip: onlyLinux("the stand-in for libproc reads /proc") }, async () => {
    await withCwd(async (cwd) => {
      let holder = 0;
      let group = 0;
      try {
        const child = spawn(PYTHON3, ["-c", SIM, script, cwd], { detached: true, stdio: ["ignore", "pipe", "pipe"] });
        group = child.pid as number;
        const out: Buffer[] = [];
        child.stdout.on("data", (c: Buffer) => out.push(c));
        const code = await new Promise<number | null>((resolve) => child.on("exit", resolve));
        holder = await pidFile(join(cwd, "holder.pid"), 5000);
        assert.equal(code, 0);
        const seen = JSON.parse(Buffer.concat(out).toString("utf8"));
        assert.equal(seen.timed_out, false);
        assert.equal(await gone(holder, 5000), true, "the program's leftover was not ended");
      } finally {
        if (group) try { process.kill(-group, "SIGKILL"); } catch { /* gone */ }
        if (holder) try { process.kill(holder, "SIGKILL"); } catch { /* gone */ }
      }
    });
  });
}
