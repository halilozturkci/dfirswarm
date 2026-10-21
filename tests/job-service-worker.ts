/**
 * A stand-in for a worker VM in the job service's tests: the job's own
 * run.sh run on this machine, its /job and $OUT mapped to the host
 * directories the VM would have mounted, timeout(1) left out (macOS has
 * none; the tests give no job long enough to need it).
 */
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import type { WorkerSpec } from "../scripts/vm.ts";

/** What a worker VM would do, done here: the same script, the same mounts, as host paths. */
export function localWorker(record: WorkerSpec[] = [], behaviour: { fenced?: () => boolean } = {}) {
  return async (spec: WorkerSpec) => {
    record.push(spec);
    const ctl = spec.mounts.find((m) => m.guest === "/job")!.host;
    const out = spec.mounts.find((m) => m.host.includes(".staging/") && m.host.endsWith("/out"))!;
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

/**
 * localWorker with the script run beside the test, not instead of it: the
 * test's own process keeps running while the job does, so a test can ask the
 * service about a job that is running (job_status mid-run) and then let it go.
 */
export function asyncLocalWorker(record: WorkerSpec[] = []) {
  return async (spec: WorkerSpec) => {
    record.push(spec);
    const ctl = spec.mounts.find((m) => m.guest === "/job")!.host;
    const out = spec.mounts.find((m) => m.host.includes(".staging/") && m.host.endsWith("/out"))!;
    const local = (text: string) => text.split("/job/").join(`${ctl}/`).split(out.guest!).join(out.host);
    for (const f of readdirSync(ctl)) if (f !== "run.sh" && f.endsWith(".json")) writeFileSync(join(ctl, f), local(readFileSync(join(ctl, f), "utf8")));
    const script = local(readFileSync(join(ctl, "run.sh"), "utf8")).replace(/timeout --kill-after=10 (\d+) /g, "").replace(/timeout 300 /g, "");
    writeFileSync(join(ctl, "run-local.sh"), script);
    const env = { ...process.env, ...spec.env, OUT: out.host };
    const code = await new Promise<number | null>((done) => {
      const child = spawn("bash", [join(ctl, "run-local.sh")], { cwd: spec.workdir, env, stdio: "ignore" });
      child.on("close", (c) => done(c));
      child.on("error", () => done(null));
    });
    return { code, fenced: true };
  };
}

/** inputs.json as the kickoff writes it: every file under inputs/, its size and sha256 (a declared input resolves through it). */
export function listInputs(S: string): void {
  const files: Array<{ path: string; bytes: number; sha256: string }> = [];
  const walk = (rel: string) => {
    for (const name of readdirSync(join(S, rel)).sort()) {
      const p = `${rel}/${name}`;
      const st = statSync(join(S, p));
      if (st.isDirectory()) walk(p);
      else files.push({ path: p, bytes: st.size, sha256: createHash("sha256").update(readFileSync(join(S, p))).digest("hex") });
    }
  };
  walk("inputs");
  writeFileSync(join(S, "inputs.json"), JSON.stringify({ files }));
}

/**
 * Every share of a worker at its guest path under `G`, as the VM's mounts
 * would lay them out: a share with nothing mounted inside it is one link to
 * its host directory; one with shares inside is a directory of links to its
 * entries, except the names that lead to the shares inside, laid out the same
 * way. What a job can name is what the shares hold, nothing beside them.
 */
function layOut(G: string, mounts: Array<{ host: string; guest?: string }>): void {
  const byGuest = new Map(mounts.map((m) => [m.guest ?? m.host, m.host]));
  const guests = [...byGuest.keys()];
  const build = (guest: string, host: string | null) => {
    const target = join(G, guest);
    const nested = guests.filter((g) => g !== guest && g.startsWith(`${guest}/`));
    mkdirSync(dirname(target), { recursive: true });
    if (!nested.length) {
      if (host) symlinkSync(host, target);
      else mkdirSync(target, { recursive: true });
      return;
    }
    mkdirSync(target, { recursive: true });
    const direct = new Set(nested.map((g) => g.slice(guest.length + 1).split("/")[0]));
    if (host) for (const name of readdirSync(host)) if (!direct.has(name)) symlinkSync(join(host, name), join(target, name));
    for (const name of direct) {
      const child = `${guest}/${name}`;
      build(child, byGuest.get(child) ?? (host && existsSync(join(host, name)) ? join(host, name) : null));
    }
  };
  for (const g of guests.filter((g) => !guests.some((o) => o !== g && g.startsWith(`${o}/`)))) build(g, byGuest.get(g)!);
}

/**
 * A stand-in worker that honours the mounts: the job's run.sh run on this
 * machine inside a guest tree laid out from its shares alone (the run's
 * directory is that tree's, so an undeclared input, a sibling or the live
 * scratch is simply not there), /job and $OUT mapped to their host
 * directories. Read-only and no-exec are the VM's; here, only the layout.
 */
export function mountedWorker(record: WorkerSpec[] = []) {
  return async (spec: WorkerSpec) => {
    record.push(spec);
    const G = mkdtempSync(join(tmpdir(), "guest-"));
    try {
      const shares = spec.mounts.filter((m) => m.guest !== "/job");
      layOut(G, shares);
      const ctl = spec.mounts.find((m) => m.guest === "/job")!.host;
      const S = spec.workdir;
      const local = (text: string) => text.split(S).join(join(G, S)).split("/job/").join(`${ctl}/`);
      for (const f of readdirSync(ctl)) if (f === "command.sh" || (f !== "run.sh" && f.endsWith(".json"))) writeFileSync(join(ctl, f), local(readFileSync(join(ctl, f), "utf8")));
      const script = local(readFileSync(join(ctl, "run.sh"), "utf8")).replace(/timeout --kill-after=10 (\d+) /g, "").replace(/timeout 300 /g, "");
      writeFileSync(join(ctl, "run-local.sh"), script);
      const env = { ...process.env, ...spec.env, OUT: join(G, spec.env.OUT), SWARM_SANDBOX: join(G, S) };
      const r = spawnSync("bash", [join(ctl, "run-local.sh")], { cwd: join(G, S), env, encoding: "utf8" });
      return { code: r.status, fenced: true };
    } finally {
      rmSync(G, { recursive: true, force: true });
    }
  };
}
