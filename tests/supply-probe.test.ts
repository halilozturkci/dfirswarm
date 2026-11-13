/**
 * A supplied program is tested against a known answer in a job before the
 * seats rely on it (swarm.sh tool-supply --provides).
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { decide, PROBE_PAYLOAD, probeFor, probePost, probeQrBase64, runProbes, type HubCall } from "../scripts/supply-probe.ts";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const QRGEN = join(ROOT, "scripts", "lib", "qrgen.py");

test("the probe's QR symbol is a real one: reference format bits, a reference Reed-Solomon block, zero syndromes, a PNG", () => {
  const py = `
import sys; sys.path.insert(0, ${JSON.stringify(join(ROOT, "scripts", "lib"))}); import qrgen
assert format(qrgen.format_bits(0), "015b") == "111011111000100"
assert format(qrgen.format_bits(5), "015b") == "110001100011000"
data = [32, 91, 11, 120, 209, 114, 220, 77, 67, 64, 236, 17, 236]
assert qrgen.rs_remainder(data, 13) == [168, 72, 22, 82, 217, 54, 156, 0, 46, 15, 180, 122, 16]
for v, (d, e, _) in qrgen.VERSIONS.items():
    cw = qrgen.codewords_for(b"k" * (d - 2), v)
    assert len(cw) == d + e and not any(qrgen.syndromes(cw, e)), v
m = qrgen.matrix("${PROBE_PAYLOAD}")
assert len(m) == 21 and all(len(r) == 21 for r in m)
assert [m[0][i] for i in range(7)] == [1] * 7 and m[13][8] == 1
print("ok")
`;
  assert.equal(execFileSync("python3", ["-I", "-c", py], { encoding: "utf8" }).trim(), "ok");
  const dir = mkdtempSync(join(tmpdir(), "qrgen-"));
  execFileSync("python3", ["-I", QRGEN, PROBE_PAYLOAD, join(dir, "p.png")]);
  assert.deepEqual([...readFileSync(join(dir, "p.png")).subarray(0, 8)], [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  assert.ok(probeQrBase64().length > 200);
});

test("a probe passes only on the known answer; a decoder that reads no image fails, with what it printed", () => {
  const p = probeFor("qr-decode", "QUJD")!;
  assert.match(p.command, /zbarimg -q --raw "\$OUT\/probe\.png"/);
  assert.equal(decide(p, { id: "j000009", state: "committed", status: "ok" }, `${PROBE_PAYLOAD}\n`, "").ok, true);
  const broken = decide(p, { id: "j000010", state: "committed", status: "failed", reason: "exit 2" }, "", "ERROR: NoDecodeDelegateForThisImageFormat `PNG' @ error/constitute.c/ReadImage/594\n");
  assert.equal(broken.ok, false);
  assert.match(broken.said, /FAILED.*exit 2.*NoDecodeDelegateForThisImageFormat/);
  assert.equal(decide(p, { id: "j000011", state: "committed", status: "ok" }, "", "").ok, false, "silence with exit 0 is not a pass");
  assert.equal(decide(p, { id: "j000012", state: "running" }, "", "").ok, false);
  assert.equal(probeFor("ocr", "x"), null);
  assert.ok(probeFor("video-decode", "x") && probeFor("image-convert", "x"));
});

test("the probes run as jobs that name the supplied import in programs, and the seats are told which capability does not work", async () => {
  const calls: Array<[string, Record<string, unknown>]> = [];
  let n = 0;
  const call: HubCall = async (fn, arg) => {
    calls.push([fn, arg]);
    if (fn === "jobSubmit") return { ok: true, job: { job: `j00000${(n += 1)}`, state: "accepted" } };
    const id = String(arg.job_id);
    return id === "j000001"
      ? { ok: true, job: { job: id, state: "committed", status: "failed", reason: "exit 2", stderr: { tail: "NoDecodeDelegateForThisImageFormat" } } }
      : { ok: true, job: { job: id, state: "committed", status: "ok" }, stdout: { text: "frames=5\n" } };
  };
  const r = await runProbes(call, "mat-0002", ["qr-decode", "video-decode", "ocr"], { qr: "QUJD", sleep: async () => undefined });
  assert.equal(r.ok, false);
  assert.deepEqual(r.probes.map((x) => [x.capability, x.ok]), [["qr-decode", false], ["video-decode", true], ["ocr", false]]);
  const subs = calls.filter(([fn]) => fn === "jobSubmit");
  assert.equal(subs.length, 2, "a capability with no test starts no job");
  for (const [, arg] of subs) assert.deepEqual(arg.programs, ["import:mat-0002"]);
  const post = probePost("mat-0002", r.probes);
  assert.match(post, /qr-decode: DOES NOT WORK/);
  assert.match(post, /video-decode: WORKS/);
  assert.match(post, /must not be read as a negative/);
  assert.doesNotMatch(probePost("mat-0001", [r.probes[1]!]), /must not be read as a negative/);
});
