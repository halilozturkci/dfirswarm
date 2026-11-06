/**
 * FUSE in the VMs: a tool that mounts says so in its manifest (`needs: ["fuse"]`), the harness reads the word and knows no tool, a VM or a
 * worker without /dev/fuse is named for that tool and for no other, the image record has a fuse field, and the tools that mount give one
 * form of "no FUSE" (a `no_fuse` object: reason, what the host lacks, what to do).
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import { JobService } from "../scripts/job-service.ts";
import { imageFit, packNeeds, type PackNeed } from "../scripts/vm.ts";
import { withCwd } from "./tool-library-harness.ts";
import { FS, fsStub, json, runTool } from "./memory-f1-support.ts";
import { localWorker } from "./job-service-worker.ts";

const ROOT = join(import.meta.dirname, "..");
const dirs: string[] = [];
after(async () => {
  for (const d of dirs) {
    spawnSync("chmod", ["-R", "u+w", d]);
    await rm(d, { recursive: true, force: true });
  }
});

test("the manifests of the tools that mount declare needs fuse, and packNeeds reads it from the field", () => {
  const needs = packNeeds([join(ROOT, "packs/memory-forensics"), join(ROOT, "packs/windows-forensics"), join(ROOT, "packs/network-forensics")]);
  const by = Object.fromEntries(needs.map((n) => [n.id, n.mounts]));
  assert.deepEqual(by["memory-forensics"], ["mem_fs"]);
  assert.deepEqual(by["windows-forensics"], ["vss_materialise", "vss_stores"]);
  assert.equal(by["network-forensics"], undefined);
});

const need = (id: string, mounts?: string[]): PackNeed => ({ id, version: "1", seal: "s", required: [], ...(mounts ? { mounts } : {}) });

test("a VM probe without /dev/fuse gives a warning for the tool that declares it and none for another; a probe with it, or none, gives none", () => {
  const needs = [need("memory-forensics", ["mem_fs"]), need("network-forensics")];
  const without = imageFit({ fuse: false, missing_binaries: [] }, needs, false);
  assert.equal(without.blockers.length, 0);
  const warned = without.warnings.filter((w) => /mounts/.test(w));
  assert.equal(warned.length, 1, JSON.stringify(without.warnings));
  assert.match(warned[0]!, /pack memory-forensics' tool mem_fs mounts \(its manifest needs fuse\) and this VM has no \/dev\/fuse: it will answer failed with no_fuse/);
  assert.ok(!without.warnings.some((w) => /network-forensics/.test(w) && /fuse/.test(w)));
  assert.deepEqual(imageFit({ fuse: true, missing_binaries: [] }, needs, false).warnings.filter((w) => /fuse/.test(w)), []);
  assert.deepEqual(imageFit({ missing_binaries: [] }, needs, false).warnings.filter((w) => /fuse/.test(w)), [], "a probe that did not measure it says nothing");
  // The image's own record: no fusermount.
  const noHelper = imageFit({ fuse: true, missing_binaries: [], image: { fuse: { fusermount: false } } }, needs, false);
  assert.ok(noHelper.warnings.some((w) => /tool mem_fs mounts .* this image has no fusermount3 or fusermount/.test(w)), JSON.stringify(noHelper.warnings));
});

test("the install records whether the image has fusermount", () => {
  const src = readFileSync(join(ROOT, "images/install.py"), "utf8");
  assert.match(src, /record\["fuse"\] = \{"fusermount": bool\(shutil\.which\("fusermount3", path=IMAGE_PATH\) or shutil\.which\("fusermount", path=IMAGE_PATH\)\)\}/);
});

function toolFiles(S: string, name: string, needs: string[] | null): void {
  const dir = join(S, "tools", name);
  mkdirSync(dir, { recursive: true });
  const body = `import json, sys\njson.load(sys.stdin)\nprint(json.dumps({"status": "failed"}))\nsys.exit(1)\n`;
  writeFileSync(join(dir, "run.py"), body);
  writeFileSync(join(dir, "manifest.json"), JSON.stringify({ name, params: {}, runtime: "python3", entry: "run.py", timeout_seconds: 30, sha256: createHash("sha256").update(body).digest("hex"), ...(needs ? { needs } : {}) }));
}

test("a worker without /dev/fuse is probed, and a failed job of a tool that needs fuse names it; a tool that does not need it is not named", async () => {
  const S = join(mkdtempSync(join(tmpdir(), "fuse-jobs-")), "run");
  dirs.push(join(S, ".."));
  for (const d of ["inputs", "tools", "catalog", "work/a1"]) mkdirSync(join(S, d), { recursive: true });
  writeFileSync(join(S, "inputs.json"), JSON.stringify({ files: [] }));
  toolFiles(S, "mounter", ["fuse"]);
  toolFiles(S, "plain", null);
  const was = process.env.DFIRSWARM_FUSE_DEVICE;
  process.env.DFIRSWARM_FUSE_DEVICE = join(S, "no-such-device");
  try {
    const svc = new JobService({ sandbox: S, run: "s000000", image: "img:test", workers: 1, workerCpus: 1, workerMemoryMib: 512, allowHosts: [], openNet: false, packDirs: [], forging: false, minFreeMb: 1, runWorker: localWorker(), destroyWorker: async () => ({ ok: true }), notify: async () => undefined, identity: async () => ({}) });
    await svc.start();
    const run = async (tool: string) => {
      const r = await svc.submit("a1", { kind: "tool", tool, args: {} });
      assert.ok(r.ok, !r.ok ? r.reason : "");
      const end = Date.now() + 20_000;
      let job = svc.jobs.get(r.job.id)!;
      while (!["committed", "failed", "cancelled"].includes(job.state) && Date.now() < end) {
        await new Promise((res) => setTimeout(res, 50));
        job = svc.jobs.get(r.job.id)!;
      }
      return job;
    };
    const mounter = await run("mounter");
    assert.deepEqual(mounter.worker_probe, { fuse: false });
    assert.equal(mounter.needs_unmet?.need, "fuse");
    assert.equal(mounter.needs_unmet?.tool, "mounter");
    assert.match(mounter.reason ?? "", /^exit 1: the tool needs a FUSE mount and this worker VM \(image img:test\) has no \/dev\/fuse: that is a limit of the worker, not a finding about the evidence/);
    const plain = await run("plain");
    assert.deepEqual(plain.worker_probe, { fuse: false }, "the worker is probed for every job");
    assert.equal(plain.needs_unmet, undefined);
    assert.equal(plain.reason, "exit 1");
    // A worker that has the device: probed, true, nothing named.
    process.env.DFIRSWARM_FUSE_DEVICE = "/dev/null";
    const present = await run("mounter");
    assert.deepEqual(present.worker_probe, { fuse: true }, "/dev/null is a character device, as /dev/fuse is");
    assert.equal(present.needs_unmet, undefined);
  } finally {
    if (was === undefined) delete process.env.DFIRSWARM_FUSE_DEVICE;
    else process.env.DFIRSWARM_FUSE_DEVICE = was;
  }
});

test("mem_fs and vss_stores give one form of no FUSE: a no_fuse object with the reason, what is lacking, and what to do", async () => {
  const form = (o: Record<string, unknown>) => {
    const nf = o.no_fuse as { reason?: string; blocked_by?: string[]; what_to_do?: string };
    assert.equal(nf.reason, "no_fuse");
    assert.ok(Array.isArray(nf.blocked_by) && nf.blocked_by.some((b) => /fuse/.test(b)), JSON.stringify(nf));
    assert.match(nf.what_to_do ?? "", /Run this job where \/dev\/fuse exists/);
    return nf;
  };
  const absent = join(tmpdir(), "no-such-fuse-device");
  // mem_fs: the engine (a stub) fails at startup, and the host lacks the device.
  await withCwd(async (cwd, bin) => {
    const env = await fsStub(cwd, bin, { tree: { "sys/x": "" }, mode: "exit", stderrText: "FUSE is not available" });
    writeFileSync(join(cwd, "inputs", "memory.raw"), Buffer.alloc(4096));
    const out = json<{ status: string; no_fuse?: unknown } & Record<string, unknown>>(await runTool(FS, cwd, { path: "inputs/memory.raw", mount: "work/s1/m", mode: "list", timeout_seconds: 30 }, { ...env, DFIRSWARM_FUSE_DEVICE: absent }, bin));
    assert.equal(out.status, "failed");
    form(out);
  });
  // vss_stores: a listing that found a store says the mount commands cannot work here; the listing itself stays complete.
  await withCwd(async (cwd, bin) => {
    writeFileSync(join(bin, "vshadowinfo"), `#!/bin/sh\nprintf 'vshadowinfo 20240504\\n\\nVolume Shadow Snapshot information:\\n\\tNumber of stores:\\t1\\n\\nStore: 1\\n\\tIdentifier\\t\\t: 11111111-2222-3333-4444-555555555555\\n\\tCreation time\\t\\t: Oct 05, 2026 10:00:00.000000000 UTC\\n'\n`, { mode: 0o755 });
    writeFileSync(join(bin, "vshadowmount"), "#!/bin/sh\nexit 0\n", { mode: 0o755 });
    writeFileSync(join(cwd, "inputs", "vol.raw"), Buffer.alloc(4096));
    const run = await runTool(join(ROOT, "packs/windows-forensics/tools/vss_stores/run.py"), cwd, { image: "inputs/vol.raw" }, { DFIRSWARM_FUSE_DEVICE: absent }, bin);
    const out = json<Record<string, unknown>>(run);
    assert.equal(out.fuse_present, false);
    assert.notEqual(out.status, "failed", JSON.stringify(out).slice(0, 400));
    form(out);
  });
});
