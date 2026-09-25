/**
 * A stand-in for a worker VM in the job service's tests: the job's own
 * run.sh run on this machine, its /job and $OUT mapped to the host
 * directories the VM would have mounted, timeout(1) left out (macOS has
 * none; the tests give no job long enough to need it).
 */
import { spawnSync } from "node:child_process";
import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { WorkerSpec } from "../scripts/vm.ts";

/** What a worker VM would do, done here: the same script, the same mounts, as host paths. */
export function localWorker(record: WorkerSpec[] = [], behaviour: { fenced?: () => boolean } = {}) {
  return async (spec: WorkerSpec) => {
    record.push(spec);
    const ctl = spec.mounts.find((m) => m.guest === "/job")!.host;
    const out = spec.mounts.find((m) => (m.guest ?? "").includes("/work/.jobs/"))!;
    const local = (text: string) => text.split("/job/").join(`${ctl}/`).split(out.guest!).join(out.host);
    // What the hub wrote for the job names guest paths: here they are the host's.
    for (const f of readdirSync(ctl)) if (f !== "run.sh" && f.endsWith(".json")) writeFileSync(join(ctl, f), local(readFileSync(join(ctl, f), "utf8")));
    const script = local(readFileSync(join(ctl, "run.sh"), "utf8")).replace(/timeout --kill-after=10 (\d+) /g, "").replace(/timeout 300 /g, "");
    writeFileSync(join(ctl, "run-local.sh"), script);
    const env = { ...process.env, ...spec.env, OUT: out.host };
    const r = spawnSync("bash", [join(ctl, "run-local.sh")], { cwd: spec.workdir, env, encoding: "utf8" });
    return { code: r.status, fenced: behaviour.fenced ? behaviour.fenced() : true, ...(behaviour.fenced && !behaviour.fenced() ? { fence_error: "msb still has it" } : {}) };
  };
}

