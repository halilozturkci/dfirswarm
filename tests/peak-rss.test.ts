/**
 * The peak-memory helper (tests/fixtures/peak_rss.py, tests/peak-rss.ts), and the suites that use it.
 *
 * `ru_maxrss` on Linux counts the process image that exec replaced. A test that bounds a tool's memory with it reads the
 * size of whatever forked the tool, which depends on the host and on what the test was holding. The helper reads VmHWM of
 * the image the process runs now. These cases pin that, and that no suite reads `ru_maxrss` on its own again.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import { peakRssPrelude } from "./peak-rss.ts";

const ROOT = join(import.meta.dirname, "..");
const LINUX = process.platform === "linux";
const MiB = 1024 * 1024;

function py(code: string): { status: number | null; stdout: string; stderr: string } {
  const r = spawnSync("python3", ["-c", peakRssPrelude() + code], { encoding: "utf8", timeout: 60_000 });
  return { status: r.status, stdout: r.stdout, stderr: r.stderr };
}

/** A parent that holds 160 MiB and starts a child that holds almost nothing, which is the case ru_maxrss gets wrong. */
const FAT_PARENT = `
import json, resource, subprocess
big = bytearray(160 * 1024 * 1024)
for i in range(0, len(big), 4096):
    big[i] = 1
`;

test("a tiny child of a parent holding 160 MiB reads as tiny, where ru_maxrss reads as the parent", { skip: !LINUX && "the inherited peak is a Linux behaviour" }, () => {
  const r = py(
    FAT_PARENT +
      `
p, peak = run_peak(["python3", "-c", "pass"], capture_output=True)
rusage = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss * 1024
print(json.dumps({"peak": peak, "rusage": rusage}))
`,
  );
  assert.equal(r.status, 0, r.stderr);
  const got = JSON.parse(r.stdout) as { peak: number; rusage: number };
  assert.ok(got.peak < 60 * MiB, `the child's own peak was ${got.peak} bytes`);
  assert.ok(got.peak > 0, "the child was sampled");
  // The control: the number the tests used to read. It carries the parent's image on this kernel; if a kernel stops doing
  // that, the helper is still right and this line is the only one that changes.
  assert.ok(got.rusage > 120 * MiB, `ru_maxrss read ${got.rusage} bytes, the parent's size`);
});

test("the process's own peak after exec is its new image, not the image that was replaced", { skip: !LINUX && "the inherited peak is a Linux behaviour" }, () => {
  const r = py(
    FAT_PARENT +
      `
code = "import json, resource; from peak_rss import self_peak_bytes; print(json.dumps({'own': self_peak_bytes(), 'rusage': resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024}))"
p, peak = run_peak(["python3", "-c", code], capture_output=True, text=True, env={**__import__("os").environ, "PYTHONPATH": ${JSON.stringify(join(ROOT, "tests", "fixtures"))}})
print(p.stdout)
`,
  );
  assert.equal(r.status, 0, r.stderr);
  const got = JSON.parse(r.stdout) as { own: number; rusage: number };
  assert.ok(got.own < 60 * MiB, `its own peak was ${got.own} bytes`);
});

test("a child that holds 200 MiB reads as about that, sampled while it runs", () => {
  const r = py(`
import json
code = "b = bytearray(200 * 1024 * 1024)\\nfor i in range(0, len(b), 4096): b[i] = 1\\nimport time; time.sleep(0.3)"
p, peak = run_peak(["python3", "-c", code], capture_output=True)
print(json.dumps({"peak": peak, "code": p.returncode}))
`);
  assert.equal(r.status, 0, r.stderr);
  const got = JSON.parse(r.stdout) as { peak: number; code: number };
  assert.equal(got.code, 0);
  if (!LINUX) return; // macOS reads the child's rusage, in bytes
  assert.ok(got.peak >= 190 * MiB && got.peak < 400 * MiB, `the child's peak was ${got.peak} bytes`);
});

test("a child killed at its timeout still reports its peak, and the output it had written", () => {
  const r = py(`
import json, subprocess
try:
    run_peak(["python3", "-c", "import sys, time; sys.stdout.write('seen'); sys.stdout.flush(); time.sleep(60)"], capture_output=True, timeout=1.5)
    print(json.dumps({"timed_out": False}))
except subprocess.TimeoutExpired as exc:
    print(json.dumps({"timed_out": True, "peak": exc.peak_bytes, "stdout": exc.stdout.decode()}))
`);
  assert.equal(r.status, 0, r.stderr);
  const got = JSON.parse(r.stdout) as { timed_out: boolean; peak: number; stdout: string };
  assert.equal(got.timed_out, true);
  assert.equal(got.stdout, "seen");
  if (LINUX) assert.ok(got.peak > 0 && got.peak < 100 * MiB, `peak ${got.peak}`);
});

/** The suites that bound a tool's memory read it through the helper. */
const READERS = [
  "tests/ad1-pack.test.ts",
  "tests/macos-pack-harness.ts",
  "tests/pack-macos-forensics.test.ts",
  "tests/pack-encrypted-containers.test.ts",
  "tests/pack-encrypted-containers-fixes.test.ts",
  "tests/pack-mobile-forensics.test.ts",
  "tests/pack-mobile-recipes.test.ts",
  "tests/pack-network-pcap-summary.test.ts",
  "tests/pack-re-doc-structure-review.test.ts",
  "tests/pack-re-doc-structure-round2.test.ts",
  "tests/pack-re-doc-structure-round3.test.ts",
  "tests/pack-triage-fixes-3.test.ts",
  "tests/pack-virtualization-audit.test.ts",
  "tests/pack-virtualization-fuzz.test.ts",
  "tests/pack-windows-forensics-links.test.ts",
  "tests/pack-windows-forensics-lnk-jumplist-limits.test.ts",
  "tests/fixtures/windows-boundary-driver.py",
  "tests/pack-encrypted-containers-p3.test.ts",
  "tests/pack-ransomware-limit.test.ts",
  "tests/pack-windows-forensics-browser-contract.test.ts",
];

test("none of the suites that bound a tool's memory reads ru_maxrss itself", () => {
  const offenders = READERS.filter((f) => /ru_maxrss/.test(readFileSync(join(ROOT, f), "utf8")));
  assert.deepEqual(offenders, []);
  for (const f of READERS) {
    const text = readFileSync(join(ROOT, f), "utf8");
    assert.match(text, f.endsWith(".py") ? /peak_rss/ : /peak-rss\.ts/, `${f} reads the peak through the helper`);
  }
});
