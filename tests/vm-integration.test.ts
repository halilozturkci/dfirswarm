/**
 * Real microVMs, the way a run makes them (scripts/vm.ts) and serves them
 * (scripts/vm-hub.ts). Needs a host that can boot one — macOS on Apple
 * silicon, or Linux with /dev/kvm — and the base image (VM_TEST_IMAGE,
 * default dfirswarm-base:dev-<arch>). Skipped otherwise, unless
 * DFIRSWARM_VM_TESTS=1 says the host must be able to (CI's KVM job).
 *
 *   npm run test:vm
 *
 * What it proves, each against the host's own view of the files:
 *   - guest root cannot write the run's floor, the evidence or the trace, by
 *     writing, remounting or unmounting — and unmounting a writable hole
 *     leaves the read-only floor, not the host;
 *   - a copy of the evidence (--inputs-copy), inputs/ and .inputs-pristine/,
 *     is held like evidence in place: each its own read-only, no-exec mount
 *     over the floor, which the probe reads and the kickoff holds a VM to;
 *   - a VM reaches its allowed host and nothing else, by name or by address,
 *     and a local model's port on the host but no other port;
 *   - a secret never enters the guest, only its placeholder, and is in no
 *     kept disk or log after finish;
 *   - two VMs posting and recording at once through the hub lose nothing and
 *     never share an id — the failure the shared directory had;
 *   - in a VM the shared work/ is read-only, a peer's directory is not one's
 *     own, extracted material (one's own or a peer's) does not run, and a
 *     deliverable is published through the hub with its bytes;
 *   - a tool forged through the hub, and one seeded like a pack's, runs in a
 *     VM only as its sealed bytes; a VM's own file is recorded and restored
 *     without the hub opening it;
 *   - a claim on a file a peer just published waits out the guest cache
 *     (the default settle, not zero);
 *   - finish snapshots and removes a run's VMs, and reap touches only the VMs
 *     its own registry recorded;
 *   - end to end, Pi in its VM calls a scripted model and posts through the
 *     hub, with the evidence refused to it by the kernel.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync, readlinkSync, realpathSync } from "node:fs";
import { cp, mkdir, mkdtemp, readdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { createServer, type Server } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join, relative } from "node:path";
import { after, before, test } from "node:test";
import { fileURLToPath } from "node:url";
import { initSandbox, readLedger } from "../extensions/protocol.ts";
import { Hub } from "../scripts/vm-hub.ts";
import { createVms, finishRun, imageCatalog, msbBinary, netCheck, probeHost, reapVms, registryLabel, runVms, vmName, type VmSpec } from "../scripts/vm.ts";
import { execFileSync } from "node:child_process";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const ARCH = process.arch === "arm64" ? "arm64" : "amd64";
const IMAGE = process.env.VM_TEST_IMAGE || `dfirswarm-base:dev-${ARCH}`;
const REQUIRED = process.env.DFIRSWARM_VM_TESTS === "1";

let skip: string | false = false;
const cleanups: Array<() => Promise<unknown>> = [];

before(async () => {
  const probe = await probeHost(IMAGE).catch((err: Error) => ({ ok: false, reasons: [err.message], image_present: false }));
  if (!probe.ok || probe.image_present === false) {
    skip = `this host cannot run the VM tests (${probe.ok ? `no image ${IMAGE}` : probe.reasons.join("; ")})`;
    if (REQUIRED) throw new Error(skip);
  }
});

after(async () => {
  for (const c of cleanups.reverse()) await c().catch(() => undefined);
});

function msb(...args: string[]): string {
  return execFileSync(msbBinary(), args, { encoding: "utf8", timeout: 120_000 });
}

/**
 * The same, without blocking this process: needed whenever the guest talks
 * to the hub, which runs in this process and must keep answering.
 */
async function inVmAsync(name: string, script: string): Promise<string> {
  const { spawn } = await import("node:child_process");
  return new Promise<string>((done) => {
    const child = spawn(msbBinary(), ["exec", name, "--", "sh", "-c", script], { stdio: ["ignore", "pipe", "pipe"] });
    let out = "";
    child.stdout.on("data", (d) => (out += d));
    child.stderr.on("data", (d) => (out += d));
    const timer = setTimeout(() => child.kill(), 120_000);
    child.on("close", () => {
      clearTimeout(timer);
      done(out);
    });
  });
}

/** Run a shell command in a VM as its root; stdout, whatever the exit. */
function inVm(name: string, script: string): string {
  try {
    return execFileSync(msbBinary(), ["exec", name, "--", "sh", "-c", script], { encoding: "utf8", timeout: 120_000 });
  } catch (err) {
    return String((err as { stdout?: string }).stdout ?? "");
  }
}

async function fingerprint(root: string, skipDirs: string[]): Promise<Map<string, string>> {
  const out = new Map<string, string>();
  async function walk(dir: string) {
    for (const e of await readdir(dir, { withFileTypes: true })) {
      const abs = join(dir, e.name);
      const rel = relative(root, abs);
      if (skipDirs.some((s) => rel === s || rel.startsWith(`${s}/`))) continue;
      if (e.isDirectory()) await walk(abs);
      else if (e.isFile()) out.set(rel, createHash("sha256").update(await readFile(abs)).digest("hex") + `:${(await stat(abs)).mode}`);
    }
  }
  await walk(root);
  return out;
}

type Rig = { run: string; sandbox: string; hub: Hub; hubDir: string; spec: VmSpec; lines: Record<string, unknown>[]; evidence: string };

/**
 * A sandbox, its evidence, a hub and a stand-in collector; the VMs are made
 * by the test. The evidence is held in place (inputs/ a link to it, its
 * directory mounted) unless `held` says copy: then inputs/ is the run's own
 * directory and .inputs-pristine/ its clone, each mounted on its own, as
 * --inputs-copy leaves a run.
 */
async function rig(run: string, agents: string[], extra: Partial<VmSpec> = {}, hubOptions: { settleMs?: number; forging?: boolean } = {}, held: "bind" | "copy" = "bind"): Promise<Rig> {
  const base = await mkdtemp(join(tmpdir(), "vmit-"));
  const sandbox = join(base, "runs", run);
  await mkdir(sandbox, { recursive: true });
  await initSandbox(sandbox, { swarmId: run, agentIds: agents, capUsd: 1, wallClockMinutes: 30 });
  const evidence = join(base, "evidence");
  await mkdir(join(evidence, "mail"), { recursive: true });
  await writeFile(join(evidence, "notes.txt"), "case notes\n");
  await writeFile(join(evidence, "mail", "a.bin"), "suspect bytes");
  const { symlink } = await import("node:fs/promises");
  if (held === "copy") {
    // The modes stay the host's defaults, a file executable by its own mode
    // among them, so that what refuses a write or a run below is the share's
    // flag, which the probe reads, and never a mode bit.
    await writeFile(join(evidence, "run.sh"), "#!/bin/sh\necho ran\n", { mode: 0o755 });
    for (const d of ["inputs", ".inputs-pristine"]) await cp(evidence, join(sandbox, d), { recursive: true });
  } else {
    await symlink(evidence, join(sandbox, "inputs"));
  }
  for (const a of agents) {
    await mkdir(join(sandbox, "tool-output", a), { recursive: true });
    await mkdir(join(sandbox, ".pi-sessions", a), { recursive: true });
  }
  await writeFile(join(sandbox, "traces", "events.jsonl"), '{"ts":"t","agent":"system","tool":"agent_start","args":{},"result":{}}\n');
  const hubDir = await mkdtemp("/tmp/dfh-");
  const lines: Record<string, unknown>[] = [];
  const collectorPath = join(hubDir, "col.sock");
  const collector: Server = createServer((socket) => {
    let buffer = "";
    socket.setEncoding("utf8");
    socket.on("data", (chunk: string) => {
      buffer += chunk;
      let cut;
      while ((cut = buffer.indexOf("\n")) >= 0) {
        lines.push(JSON.parse(buffer.slice(0, cut)));
        buffer = buffer.slice(cut + 1);
        socket.write('{"ok":true}\n');
      }
    });
    socket.on("error", () => undefined);
  });
  await new Promise<void>((r) => collector.listen(collectorPath, () => r()));
  const hub = new Hub({ sandbox, dir: hubDir, agents, tokens: {}, collector: collectorPath, backstop: false, quiet: true, settleMs: "settleMs" in hubOptions ? hubOptions.settleMs : 0, forging: hubOptions.forging === true });
  await hub.start();
  const spec: VmSpec = {
    run,
    sandbox,
    image: IMAGE,
    pull: "never",
    cpus: 1,
    memory_mib: 1024,
    max_duration_sec: 1800,
    hub_dir: hubDir,
    mounts: [
      { host: join(ROOT, "extensions"), readonly: true },
      // As the kickoff writes them (swarm.sh inputs_mount_dirs): in place,
      // the source where inputs/ leads; a copy, inputs/ and .inputs-pristine/
      // each its own share after the floor.
      ...(held === "copy"
        ? [
            { host: join(sandbox, "inputs"), readonly: true, noexec: true },
            { host: join(sandbox, ".inputs-pristine"), readonly: true, noexec: true },
          ]
        : [{ host: evidence, readonly: true, noexec: true }]),
    ],
    env: { SWARM_ID: run },
    agents: agents.map((id) => ({ id, model: "none/none" })),
    allow_hosts: [],
    providers: [],
    records_dir: join(sandbox, "vm"),
    registry: join(base, "runs", "registry.json"),
    ...extra,
  };
  cleanups.push(async () => {
    for (const a of agents) {
      try {
        msb("stop", vmName(run, a));
      } catch {
        // already stopped
      }
      try {
        msb("rm", vmName(run, a));
      } catch {
        // already removed
      }
    }
    await hub.stop();
    collector.close();
    await rm(hubDir, { recursive: true, force: true });
    await rm(base, { recursive: true, force: true });
  });
  return { run, sandbox, hub, hubDir, spec, lines, evidence };
}

test("guest root cannot change the run's floor, the evidence or the trace, by any of the ways it could try", async (t) => {
  if (skip) return t.skip(skip);
  const r = await rig("vmt1", ["vmt100"]);
  const created = await createVms(r.spec);
  assert.deepEqual(created.failures, [], JSON.stringify(created.failures));
  const name = vmName(r.run, "vmt100");
  // In place: the probe read the evidence's own mount as no-exec, and had
  // no pristine clone to measure.
  const probe = created.records[0]?.probe ?? {};
  assert.equal(probe.inputs, "ro");
  assert.equal(probe.inputs_exec, "noexec", "the evidence in place is on a no-exec mount");
  assert.ok(!("inputs_pristine" in probe) && !("inputs_pristine_exec" in probe), "in place there is no clone, and nothing is measured for one");
  const floorBefore = await fingerprint(r.sandbox, ["work", "tool-output", ".pi-sessions", "vm"]);
  const evidenceBefore = await fingerprint(r.evidence, []);
  const S = r.sandbox;
  const out = inVm(name, `
    w() { if ( printf x >> "$1" ) 2>/dev/null; then echo "WROTE $1"; else echo "refused $1"; fi; }
    w "${S}/traces/events.jsonl"; w "${S}/SWARM.md"; w "${S}/inputs/notes.txt"; w "${S}/budget.json"
    # The evidence's own mount, by the guest kernel's table, before anything is remounted.
    echo "evidence-mount: $(awk -v p="${r.evidence}" '$5 == p { print $6 }' /proc/self/mountinfo | tail -1)"
    mount -o remount,rw "${S}" 2>/dev/null; mount -o remount,rw "${r.evidence}" 2>/dev/null
    grep -q " ${S} virtiofs rw" /proc/mounts && echo "floor-flag: rw" || echo "floor-flag: ro"
    printf 'remounted: '; w "${S}/SWARM.md"
    printf 'remounted: '; w "${r.evidence}/notes.txt"
    # Lazily: a plain umount of a mount with mounts under it is EBUSY, and the
    # write after it would prove nothing about what an unmount leaves.
    umount -l "${S}/work/vmt100" 2>/dev/null && echo "umount-scratch: done" || echo "umount-scratch: refused"
    w "${S}/work/vmt100/after-umount.txt"
    umount -l "${S}/.pi-sessions/vmt100" 2>/dev/null && echo "umount-session: done" || echo "umount-session: refused"
    w "${S}/.pi-sessions/vmt100/planted"
    umount -l "${S}" 2>/dev/null && echo "umount-floor: done" || echo "umount-floor: refused"
    # With the floor unmounted the path is the guest's own disk: a write
    # there lands in the VM, and the host's trace must not move.
    mkdir -p "${S}/traces" 2>/dev/null; printf 'after-floor-umount: '; w "${S}/traces/events.jsonl"
    rm -rf "${r.evidence}/notes.txt" 2>/dev/null; chmod 777 "${r.evidence}/mail/a.bin" 2>/dev/null; echo done
  `);
  assert.match(out, /refused .*events\.jsonl/);
  assert.match(out, /refused .*SWARM\.md/);
  assert.match(out, /refused .*inputs\/notes\.txt/);
  assert.match(out, /^evidence-mount: ro(,|$)/m, `the evidence in place is mounted read-only: ${out}`);
  assert.match(out, /^evidence-mount: [^\n]*\bnoexec\b/m, `the evidence in place is mounted no-exec: ${out}`);
  // The guest kernel may flip its own flag (it does, measured: "rw" after
  // the remount); the share is read-only on the host side, and that is what
  // refuses the write. The flag is read so the case is known, not assumed.
  assert.match(out, /floor-flag: (rw|ro)/, `the remount's effect on the guest's flag was read\n${out}`);
  assert.match(out, /remounted: refused .*SWARM\.md/);
  assert.match(out, /remounted: refused .*notes\.txt/);
  // Every write through a mount the host shares was refused. The one after
  // the floor was unmounted went to the guest's own disk (measured: the
  // guest can do that), and the host's floor, trace included, is unchanged
  // below.
  assert.doesNotMatch(out.split("\n").filter((l) => !l.startsWith("after-floor-umount:")).join("\n"), /WROTE/, out);
  // Root in the guest can unmount its own holes; what is under them is the
  // read-only floor, never the host's directory.
  assert.match(out, /umount-scratch: done/, `the unmount was not made, so the write after it proves nothing\n${out}`);
  assert.match(out, /refused .*work\/vmt100\/after-umount\.txt/, "unmounting the scratch hole leaves the read-only floor, not a writable host");
  assert.match(out, /umount-session: done/, out);
  assert.equal(await readFile(join(r.sandbox, "traces", "events.jsonl"), "utf8"), '{"ts":"t","agent":"system","tool":"agent_start","args":{},"result":{}}\n', "the host's trace is what it was");
  const floorAfter = await fingerprint(r.sandbox, ["work", "tool-output", ".pi-sessions", "vm"]);
  const evidenceAfter = await fingerprint(r.evidence, []);
  assert.deepEqual([...floorAfter], [...floorBefore], "the host's copy of the run's floor did not change");
  assert.deepEqual([...evidenceAfter], [...evidenceBefore], "the host's evidence did not change, in bytes or mode");
  assert.ok(!existsSync(join(r.sandbox, "work", "vmt100", "after-umount.txt")));
  assert.ok(!existsSync(join(r.sandbox, ".pi-sessions", "vmt100", "planted")), "a write after unmounting the session hole never reached the host");
});

test("a copy of the evidence (--inputs-copy) is held in a VM like evidence in place: inputs/ and .inputs-pristine/ each its own read-only, no-exec mount over the floor, read so by the probe", async (t) => {
  if (skip) return t.skip(skip);
  // Run s8760fa (2026-10-05): the copy lay on the floor's share alone,
  // read-only but not no-exec, and every seat's probe refused its VM. The
  // kickoff now gives inputs/ and .inputs-pristine/ their own shares after
  // the floor (the rig mounts them as it does), so the mount that holds the
  // files is the one whose flags the probe reads.
  const r = await rig("vmtc", ["vmtc00"], {}, {}, "copy");
  const created = await createVms(r.spec);
  assert.deepEqual(created.failures, [], JSON.stringify(created.failures));
  const probe = created.records[0]?.probe ?? {};
  assert.equal(probe.inputs, "ro");
  assert.equal(probe.inputs_exec, "noexec", "the copy's own mount is no-exec");
  assert.equal(probe.inputs_pristine, "ro", "the clone is read-only");
  assert.equal(probe.inputs_pristine_exec, "noexec", "the clone's own mount is no-exec");
  const S = r.sandbox;
  const copyBefore = await fingerprint(join(S, "inputs"), []);
  const cloneBefore = await fingerprint(join(S, ".inputs-pristine"), []);
  const out = inVm(vmName(r.run, "vmtc00"), `
    opts() { awk -v p="$1" '$5 == p { print $6 }' /proc/self/mountinfo | tail -1; }
    echo "inputs-mount: $(opts "${S}/inputs")"
    echo "pristine-mount: $(opts "${S}/.inputs-pristine")"
    w() { if ( printf x >> "$1" ) 2>/dev/null; then echo "WROTE $1"; else echo "refused $1"; fi; }
    w "${S}/inputs/notes.txt"; w "${S}/inputs/new.txt"; w "${S}/.inputs-pristine/notes.txt"; w "${S}/.inputs-pristine/new.txt"
    chmod 777 "${S}/inputs/notes.txt" 2>/dev/null && echo "CHMOD inputs" || echo "refused chmod inputs"
    rm -f "${S}/.inputs-pristine/notes.txt" 2>/dev/null && echo "REMOVED pristine" || echo "refused rm pristine"
    # test -x asks access(X_OK), which a no-exec mount refuses: the mode bits are asked instead.
    stat -c %A "${S}/inputs/run.sh" | grep -q x && echo "run.sh executable by its mode"
    "${S}/inputs/run.sh" 2>/dev/null && echo "INPUTS EXECUTED" || echo "inputs noexec held"
    "${S}/.inputs-pristine/run.sh" 2>/dev/null && echo "PRISTINE EXECUTED" || echo "pristine noexec held"
    # The same bytes run off the mount: the flag, not the file, refused it.
    cp "${S}/inputs/run.sh" /tmp/run.sh && /tmp/run.sh 2>/dev/null | grep -q ran && echo "the same bytes run elsewhere"
  `);
  for (const which of ["inputs", "pristine"]) {
    assert.match(out, new RegExp(`^${which}-mount: ro(,|$)`, "m"), `${which}/ is its own read-only mount: ${out}`);
    assert.match(out, new RegExp(`^${which}-mount: [^\n]*\\bnoexec\\b`, "m"), `${which}/ is its own no-exec mount: ${out}`);
  }
  assert.match(out, /refused .*inputs\/notes\.txt/, out);
  assert.match(out, /refused .*inputs\/new\.txt/, out);
  assert.match(out, /refused .*\.inputs-pristine\/notes\.txt/, out);
  assert.match(out, /refused .*\.inputs-pristine\/new\.txt/, out);
  assert.match(out, /refused chmod inputs/, out);
  assert.match(out, /refused rm pristine/, out);
  assert.match(out, /run\.sh executable by its mode/, `the file under test is executable by its mode: ${out}`);
  assert.match(out, /inputs noexec held/, "nothing in the copy runs");
  assert.match(out, /pristine noexec held/, "nothing in the clone runs");
  assert.match(out, /the same bytes run elsewhere/, `the flag refused the run, not the file: ${out}`);
  assert.doesNotMatch(out, /EXECUTED|WROTE|CHMOD|REMOVED/, out);
  assert.deepEqual([...(await fingerprint(join(S, "inputs"), []))], [...copyBefore], "the host's copy did not change, in bytes or mode");
  assert.deepEqual([...(await fingerprint(join(S, ".inputs-pristine"), []))], [...cloneBefore], "the host's clone did not change, in bytes or mode");

  // The control: the same copy with only the floor's share, as run s8760fa
  // was given it. The probe reads the floor's mount, which allows execution,
  // and the VM is refused for it: the check was never weakened, the mounts
  // were what was missing.
  const bare = await rig("vmtd", ["vmtd00"], { mounts: [{ host: join(ROOT, "extensions"), readonly: true }] }, {}, "copy");
  const refused = await createVms(bare.spec);
  assert.equal(refused.failures.length, 1, JSON.stringify(refused.failures));
  assert.match(refused.failures[0]!.reasons.join("; "), /the evidence can execute in the VM \(exec\)/, "a copy on the floor's share alone is refused");
});

test("a VM reaches its allowed host and the names under an allowed suffix, and no other name or address", async (t) => {
  if (skip) return t.skip(skip);
  // Real hosts on the internet: an offline host says so instead of failing.
  if (process.env.DFIRSWARM_OFFLINE === "1") return t.skip("DFIRSWARM_OFFLINE=1");
  const r = await rig("vmt2", ["vmt200"], { allow_hosts: ["registry.npmjs.org", "*.github.com"] });
  const created = await createVms(r.spec);
  assert.deepEqual(created.failures, []);
  const name = vmName(r.run, "vmt200");
  const out = inVm(name, `
    code() { curl -s -o /dev/null -m 15 -w '%{http_code}' "$1" 2>/dev/null || echo fail; }
    # An allowed host is another party's server: it can answer a gateway error (504 from api.github.com on a hosted runner) or not at all for a moment. The
    # policy is what is under test, so an allowed name is asked up to four times until it gives a status that is not a server error; a name the policy
    # denies is asked once and never answers.
    reach() { for try in 1 2 3 4; do c=$(code "$1"); case "$c" in 5??|fail|000) sleep 2;; *) break;; esac; done; echo "$c"; }
    echo "allowed=$(reach https://registry.npmjs.org/)"
    echo "suffix=$(reach https://api.github.com/)"
    echo "denied=$(code https://example.com/)"
    echo "ip=$(code https://1.1.1.1/)"
    getent hosts example.com >/dev/null 2>&1 && echo "resolved=yes" || echo "resolved=no"
  `);
  assert.match(out, /allowed=(200|301|302|304)/, out);
  // A server error after four asks is still the host answering through the rule (a name the policy denies gives no status at all, below): the policy is what is tested.
  assert.match(out, /suffix=(200|301|302|304|403|5\d\d)/, `a name under an allowed *.suffix is reachable\n${out}`);
  assert.match(out, /denied=(000|fail)/, out);
  assert.match(out, /ip=(000|fail)/, out);
  assert.match(out, /resolved=no/, "a name outside the rules does not resolve");
});

test("a local model's port on the host is reachable through the host gateway, and no other port", async (t) => {
  if (skip) return t.skip(skip);
  // In its own process: inVm() blocks this one while the guest calls it.
  const { spawn } = await import("node:child_process");
  const port = 18000 + Math.floor(Math.random() * 1000);
  const srv = spawn(process.execPath, ["-e", `require("node:http").createServer((q, s) => s.end("local model here\\n")).listen(${port}, "127.0.0.1")`], { stdio: "ignore" });
  cleanups.push(async () => srv.kill());
  // Something listens on the next port too: its refusal is then the VM's
  // policy, not an empty port.
  const other = spawn(process.execPath, ["-e", `require("node:http").createServer((q, s) => s.end("another service\\n")).listen(${port + 1}, "127.0.0.1")`], { stdio: "ignore" });
  cleanups.push(async () => other.kill());
  // Until it answers, not a fixed half second.
  const { connect } = await import("node:net");
  for (let i = 0; i < 100; i++) {
    const up = await new Promise<boolean>((done) => {
      const c = connect(port, "127.0.0.1", () => {
        c.end();
        done(true);
      });
      c.on("error", () => done(false));
    });
    if (up) break;
    await new Promise((r) => setTimeout(r, 50));
  }
  const r = await rig("vmt7", ["vmt700"], { providers: [{ provider: "lmstudio", kind: "local", hosts: [], port }] });
  assert.deepEqual((await createVms(r.spec)).failures, []);
  const out = inVm(vmName(r.run, "vmt700"), `
    curl -s -m 5 http://host.microsandbox.internal:${port}/ || echo refused-model
    curl -s -m 5 http://host.microsandbox.internal:${port + 1}/ || echo refused-other-port
    curl -s -m 5 https://example.com/ >/dev/null && echo reached-public || echo refused-public
  `);
  assert.match(out, /local model here/, out);
  assert.match(out, /refused-other-port/, "only the model's port is open on the host");
  assert.doesNotMatch(out, /another service/, "the service on the next port was not reached");
  assert.match(out, /refused-public/);
  const record = JSON.parse(await readFile(join(r.sandbox, "vm", "vmt700.json"), "utf8"));
  assert.deepEqual(record.network.host_ports, [port]);
});

test("a secret never enters the guest: the VM holds its placeholder", async (t) => {
  if (skip) return t.skip(skip);
  const base = await mkdtemp(join(tmpdir(), "vmsec-"));
  cleanups.push(() => rm(base, { recursive: true, force: true }));
  const value = `dfirswarm-test-secret-${createHash("sha256").update(String(Date.now())).digest("hex").slice(0, 16)}`;
  await writeFile(join(base, "secret"), value);
  const r = await rig("vmt3", ["vmt300"], { pack_secrets: [{ name: "VT_API_KEY", value_file: join(base, "secret"), hosts: ["www.virustotal.com"] }] });
  const created = await createVms(r.spec);
  assert.deepEqual(created.failures, []);
  const name = vmName(r.run, "vmt300");
  // -D skip: a FIFO under /run held grep until the exec's timeout (the test
  // took over three minutes); a device or a pipe holds no file's bytes.
  const out = inVm(name, `printf 'env=%s\\n' "$VT_API_KEY"; (env; cat /proc/1/environ 2>/dev/null; grep -rs -D skip "${value}" /root /etc /run /tmp) | grep -c "${value}" || true`);
  assert.match(out, /env=dfirswarm-secret-vtapikey-[0-9a-f]{24}/, `the guest holds a placeholder under the secret's own name\n${out}`);
  assert.match(out, /^0$/m, "the value is nowhere in the guest's environment or files");
  const record = JSON.parse(await readFile(join(r.sandbox, "vm", "vmt300.json"), "utf8"));
  assert.deepEqual(record.secrets, [{ name: "VT_API_KEY", env: "VT_API_KEY", hosts: ["www.virustotal.com"] }], "the record names the secret, its variable and its host, never its value");
  assert.ok(!JSON.stringify(record).includes(value));
  // Nor on the host, at rest, outside msb's own database: not in the
  // sandbox's directory under msb's home, the run or the hub's directory.
  // msb's database holds a live VM's configuration, the secret's value with
  // it (measured on Linux; ADR 0009, Limits), and is checked after finish
  // below. The guest's disk and root filesystem are the guest's files,
  // searched from inside above: reading an 8 GiB disk image from here took
  // the test past three minutes.
  const msbHome = process.env.MSB_HOME || join(process.env.HOME || "", ".microsandbox");
  // A search that could not read what it was given is not "not found":
  // grep's 1 is no match, anything else a failure of the check itself.
  const found = (args: string[], where: string[]): string => {
    for (const w of where) assert.ok(existsSync(w), `the check's own input is missing: ${w}`);
    try {
      // Sockets and FIFOs (the hub's directory holds them) are not files to
      // read: skipped, not an error.
      return execFileSync("grep", ["-D", "skip", ...args, ...where], { encoding: "utf8", env: { ...process.env, LC_ALL: "C" } }).trim();
    } catch (err) {
      const e = err as { status?: number; stdout?: string };
      if (e.status === 1) return "";
      throw new Error(`grep failed (exit ${e.status}): ${String(e.stdout ?? "")}`);
    }
  };
  const atRest = found(["-rlF", "--exclude=upper.ext4", "--exclude-dir=rootfs", "--exclude-dir=checkpoint-store", "--exclude-dir=checkpoints", value], [join(msbHome, "sandboxes", name), r.sandbox, r.hubDir]);
  assert.equal(atRest, "", `the value is on the host's disk in: ${atRest}`);
  // Nor after finish: the kept disk (loaded back as msb loads it) and the
  // logs kept beside it.
  const done = await finishRun(r.run, r.sandbox, { snapshot: true, registry: r.spec.registry });
  assert.ok(done.some((e) => e.snapshot), `the disk was kept: ${JSON.stringify(done)}`);
  cleanups.push(() => rm(`${r.sandbox}.vm-snapshots`, { recursive: true, force: true }));
  const dest = await mkdtemp(join(tmpdir(), "vmsec-load-"));
  cleanups.push(() => rm(dest, { recursive: true, force: true }));
  let loaded = "";
  try {
    loaded = msb("snapshot", "load", "--dest", dest, join(`${r.sandbox}.vm-snapshots`, "vmt300.msb"));
  } catch (err) {
    loaded = String((err as { stdout?: string }).stdout ?? "");
  }
  const digest = loaded.match(/sha256:[0-9a-f]{64}/)?.[0];
  // The disk really came back: an empty directory would pass any search.
  assert.ok(digest, `msb did not load the kept disk: ${loaded}`);
  assert.ok(readdirSync(dest).length > 0, "the loaded disk is empty");
  const keptLogs = join(`${r.sandbox}.vm-snapshots`, "vmt300.logs");
  const inKept = found(["-rlaF", "--exclude=*.ext4", "--exclude=*.raw", "--exclude=*.qcow2", value], [dest, ...(existsSync(keptLogs) ? [keptLogs] : [])]);
  if (digest) {
    try {
      msb("snapshot", "remove", "--force", "--quiet", digest);
    } catch {
      // not in msb's index
    }
  }
  assert.equal(inKept, "", `the value is in the kept disk's files or logs: ${inKept}`);
  // And once the VM is removed, not in msb's database either: finish drops
  // the free pages the removed VM's rows left (scrubMsbDatabase).
  const scrub = done.find((e) => e.agent === "vmt300") as { msb_db?: string } | undefined;
  const record300 = JSON.parse(readFileSync(join(r.sandbox, "vm", "vmt300.json"), "utf8")) as { msb_db?: string };
  assert.equal(record300.msb_db, scrub?.msb_db, "the VM's record does not carry the scrub's outcome");
  let haveSqlite = true;
  try {
    execFileSync("sh", ["-c", "command -v sqlite3"], { stdio: "ignore" });
  } catch {
    haveSqlite = false;
  }
  // In CI nothing else holds msb's database: the scrub must have completed.
  if (process.env.CI) assert.equal(scrub?.msb_db, "scrubbed", "CI's host needs sqlite3, and nothing else holds msb's database there");
  if (scrub?.msb_db === "scrubbed") {
    const inDb = found(["-rlaF", value], [join(msbHome, "db")]);
    assert.equal(inDb, "", `the value outlived its VM in msb's database: ${inDb}`);
  } else {
    assert.ok(!haveSqlite || scrub?.msb_db === "busy", `a host with sqlite3 did not scrub msb's database: ${scrub?.msb_db}`);
    t.diagnostic(`msb's database was not scrubbed (${scrub?.msb_db ?? "no answer"}): the value in it was not searched for`);
  }
});

test("a body with a percent sign reaches a secret's host from the VM's fetch, sent chunked", async (t) => {
  if (skip) return t.skip(skip);
  // msb 0.7.2 closed a Content-Length request whose first TLS record held
  // the credential header and a `%` or `\u` of the body (run se064eb: every
  // compaction summary of one agent). extensions/vm-egress.ts sends such a
  // body chunked; this is that, against the real msb and a real host.
  const base = await mkdtemp(join(tmpdir(), "vmegress-"));
  cleanups.push(() => rm(base, { recursive: true, force: true }));
  await writeFile(join(base, "secret"), "dfirswarm-test-not-a-key");
  const r = await rig("vmtg", ["vmtg00"], { pack_secrets: [{ name: "VT_API_KEY", value_file: join(base, "secret"), hosts: ["www.virustotal.com"] }] });
  const created = await createVms(r.spec);
  assert.deepEqual(created.failures, []);
  const script = [
    `const { installChunkedEgress } = await import(${JSON.stringify(join(ROOT, "extensions", "vm-egress.ts"))});`,
    `const body = JSON.stringify({ q: "GET /dvwa/?q=%27%20OR%201%3D1 \\u2014 100 %" });`,
    `const call = async () => { try { const r = await fetch("https://www.virustotal.com/api/v3/urls", { method: "POST", headers: { "content-type": "application/json", "x-apikey": process.env.VT_API_KEY }, body }); await r.text(); return String(r.status); } catch (e) { return "socket:" + (e.cause?.code ?? e.message); } };`,
    `const plain = await call();`,
    `const installed = installChunkedEgress();`,
    `console.log(JSON.stringify({ hosts: process.env.SWARM_SECRET_HOSTS, plain, installed, chunked: await call() }));`,
  ].join("\n");
  const out = await inVmAsync(vmName(r.run, "vmtg00"), `cat > /tmp/egress.mjs <<'JS'\n${script}\nJS\nnode /tmp/egress.mjs`);
  const line = out.split("\n").find((l) => l.startsWith("{"));
  assert.ok(line, `no answer from the guest:\n${out}`);
  const got = JSON.parse(line) as { hosts: string; plain: string; installed: boolean; chunked: string };
  assert.equal(got.hosts, "www.virustotal.com", "the VM is told its secret's host");
  assert.equal(got.installed, true);
  assert.match(got.chunked, /^\d{3}$/, `the chunked request reached the host: ${line}`);
  // Not asserted: a fixed msb lets the plain one through too, and then the
  // wrapper can go.
  t.diagnostic(`plain Content-Length request: ${got.plain}`);
});

test("a large mounted text file is text to grep, and SEEK_DATA and SEEK_HOLE answer as Linux means them", async (t) => {
  if (skip) return t.skip(skip);
  // On a macOS host msb swapped the two, every mounted file looked like one
  // hole, and grep printed "binary file matches" for a catalogue file list
  // (run s882f8d). images/seekfix.c, preloaded in the image, swaps them back.
  const r = await rig("vmth", ["vmth00"]);
  const big = join(r.evidence, "filelist.txt");
  await writeFile(big, `${"r/r 1-128-1:\tUsers/x/AppData/Local/file.dat\n".repeat(6000)}r/r 2-128-1:\tUsers/IEUser/AppData/Local/Microsoft/Windows/AppCache/container.dat\n`);
  const size = (await stat(big)).size;
  const created = await createVms(r.spec);
  assert.deepEqual(created.failures, []);
  const out = inVm(
    vmName(r.run, "vmth00"),
    `grep -F container.dat ${big} 2>&1; python3 -c 'import os; fd=os.open("${big}", os.O_RDONLY); print("seek", os.lseek(fd, 0, os.SEEK_DATA), os.lseek(fd, 0, os.SEEK_HOLE))'`,
  );
  assert.match(out, /^r\/r 2-128-1:\tUsers\/IEUser\/AppData\/Local\/Microsoft\/Windows\/AppCache\/container\.dat$/m, `grep printed the line:\n${out}`);
  assert.doesNotMatch(out, /binary file matches/);
  assert.match(out, new RegExp(`^seek 0 ${size}$`, "m"), `data at 0, the only hole at the end:\n${out}`);
});

test("two VMs posting and recording at once through the hub lose nothing and never share an id", async (t) => {
  if (skip) return t.skip(skip);
  const r = await rig("vmt4", ["vmt400", "vmt401"]);
  const created = await createVms(r.spec);
  assert.deepEqual(created.failures, []);
  const N = 40;
  const script = (who: string) => `
    /.msb/scripts/dfirswarm-bridge
    cd "${r.sandbox}" && node --experimental-strip-types --no-warnings --input-type=module -e '
      const B = await import("${join(ROOT, "extensions", "board.ts")}");
      const ctx = { sandboxRoot: process.cwd(), agentId: "${who}" };
      await Promise.all(Array.from({ length: ${N} }, async (_, i) => {
        await B.postMessage(ctx, { tag: "result", body: "${who} post " + i });
        const rec = await B.recordEntry(ctx, { kind: "ioc", value: "${who}-ioc-" + i, source: "test", evidence: "sha256sum test", confidence: "low" });
        if (!rec.ok) throw new Error(rec.reason);
      }));
      console.log("sent");
    ' 2>&1`;
  // Async, so this process — which is the hub — keeps answering; and with
  // stdin closed, because `msb exec` relays stdin and waits for its end.
  const { spawn } = await import("node:child_process");
  const run = (name: string, who: string) =>
    new Promise<string>((done) => {
      const child = spawn(msbBinary(), ["exec", name, "--", "sh", "-c", script(who)], { stdio: ["ignore", "pipe", "pipe"] });
      let out = "";
      child.stdout.on("data", (d) => (out += d));
      child.stderr.on("data", (d) => (out += d));
      const timer = setTimeout(() => child.kill(), 300_000);
      child.on("close", () => {
        clearTimeout(timer);
        done(out);
      });
    });
  const [a, b] = await Promise.all([run(vmName(r.run, "vmt400"), "vmt400"), run(vmName(r.run, "vmt401"), "vmt401")]);
  assert.match(a, /sent/, a);
  assert.match(b, /sent/, b);
  const posts = (await readdir(join(r.sandbox, "threads", "main"))).filter((f) => f.endsWith(".md"));
  assert.equal(posts.length, 2 * N, "every post landed");
  const ids = posts.map((f) => f.slice(0, 6));
  assert.equal(new Set(ids).size, ids.length, "no two posts share an id");
  for (const who of ["vmt400", "vmt401"]) assert.equal(posts.filter((f) => f.endsWith(`-${who}.md`)).length, N, `${who}'s posts are all its own`);
  const ledger = await readLedger(r.sandbox);
  assert.equal(ledger.length, 2 * N, "every ledger record landed");
  assert.deepEqual([...new Set(ledger.map((e) => e.by))].sort(), ["vmt400", "vmt401"]);
});

test("finish keeps each disk and removes the VMs; reap touches only its own registry's VMs", async (t) => {
  if (skip) return t.skip(skip);
  const r = await rig("vmt5", ["vmt500"]);
  const other = await rig("vmt6", ["vmt600"], { registry: "/somewhere/else/registry.json" });
  assert.deepEqual((await createVms(r.spec)).failures, []);
  assert.deepEqual((await createVms(other.spec)).failures, []);
  const vms = await runVms();
  const mine = vms.find((v) => v.name === vmName("vmt6", "vmt600"));
  assert.equal(mine?.registry, registryLabel("/somewhere/else/registry.json"));

  const finished = await finishRun("vmt5", r.sandbox);
  assert.equal(finished.length, 1);
  assert.ok(finished[0].snapshot && existsSync(finished[0].snapshot), `a snapshot was kept: ${JSON.stringify(finished)}`);
  const record = JSON.parse(await readFile(join(r.sandbox, "vm", "vmt500.json"), "utf8"));
  assert.equal(record.snapshot.sha256, createHash("sha256").update(readFileSync(finished[0].snapshot as string)).digest("hex"));
  assert.ok(record.stopped_at);
  assert.equal((await runVms("vmt5")).length, 0, "the run's VM is gone");
  // Custody checks the kept disk with msb's own integrity record, not only
  // against the hash the finish wrote itself.
  const { takeCustody } = await import("../scripts/custody.ts");
  const custody = await takeCustody(r.sandbox, { run: "vmt5" });
  const kept = custody.vms?.find((v) => v.agent === "vmt500")?.snapshot as { verified?: boolean; msb_verified?: boolean | null } | undefined;
  assert.equal(kept?.verified, true, JSON.stringify(custody.vms));
  assert.equal(kept?.msb_verified, true, `msb verified the snapshot it made: ${JSON.stringify(custody.vms)}`);
  assert.equal((await finishRun("vmt5", r.sandbox)).length, 0, "a second finish is a no-op");
  assert.ok(record.installed_outside_image && typeof record.installed_outside_image === "object" && !record.installed_outside_image.error, `the stop-time inventory was taken: ${JSON.stringify(record.installed_outside_image)}`);

  // A kickoff that died while preparing: its record says prepared, hours ago.
  // A reap of one other run leaves it; a reap of it keeps its disk, as a
  // stop would, and removes the VM.
  await mkdir(dirname(r.spec.registry as string), { recursive: true });
  assert.deepEqual((await createVms(r.spec)).failures, []);
  await writeFile(r.spec.registry as string, JSON.stringify({ runs: [{ id: "vmt5", state: "prepared", started_at: new Date(Date.now() - 3 * 3600_000).toISOString(), sandbox: r.sandbox }] }));
  assert.deepEqual(await reapVms({ registry: r.spec.registry, only: "some-other-run" }), [], "a reap of one run touches no other");
  assert.equal((await runVms("vmt5")).length, 1);
  await rm(`${r.sandbox}.vm-snapshots/vmt500.msb`, { force: true });
  assert.deepEqual(await reapVms({ registry: r.spec.registry, only: "vmt5" }), [vmName("vmt5", "vmt500")], "a stale prepared run's VM is reaped");
  assert.ok(existsSync(`${r.sandbox}.vm-snapshots/vmt500.msb`), "and its disk was kept first");

  // vmt6's registry has no running run: a reap of *that* registry removes it,
  // and a reap of any other registry never does.
  await writeFile(r.spec.registry as string, JSON.stringify({ runs: [] }));
  assert.deepEqual(await reapVms({ registry: r.spec.registry }), [], "a reap of another registry leaves vmt6 alone");
  assert.equal((await runVms("vmt6")).length, 1);
  assert.deepEqual(await reapVms({ run: "vmt6" }), [vmName("vmt6", "vmt600")], "named outright, it is reaped");
  assert.equal((await runVms("vmt6")).length, 0);
});

/** A 1.44 MB FAT12 volume holding HELLO.TXT: a disk image the catalog knows, made here. */
function floppy(): Buffer {
  const img = Buffer.alloc(2880 * 512);
  img.set([0xeb, 0x3c, 0x90], 0);
  img.write("MSWIN4.1", 3, "ascii");
  img.writeUInt16LE(512, 11); // bytes per sector
  img[13] = 1; // sectors per cluster
  img.writeUInt16LE(1, 14); // reserved sectors
  img[16] = 2; // FATs
  img.writeUInt16LE(224, 17); // root entries
  img.writeUInt16LE(2880, 19); // sectors
  img[21] = 0xf0;
  img.writeUInt16LE(9, 22); // sectors per FAT
  img.writeUInt16LE(18, 24);
  img.writeUInt16LE(2, 26);
  img[38] = 0x29;
  img.writeUInt32LE(0x1234abcd, 39);
  img.write("SYNTHETIC  FAT12   ", 43, "ascii");
  img.writeUInt16LE(0xaa55, 510);
  for (const fat of [1, 10]) img.set([0xf0, 0xff, 0xff, 0xff, 0x0f, 0x00], fat * 512);
  const root = 19 * 512;
  img.write("SYNTHETIC  ", root, "ascii");
  img[root + 11] = 0x08; // volume label
  img.write("HELLO   TXT", root + 32, "ascii");
  img[root + 32 + 11] = 0x20;
  img.writeUInt16LE(2, root + 32 + 26); // first cluster
  img.writeUInt32LE(6, root + 32 + 28); // size
  img.write("hello\n", 33 * 512, "ascii");
  return img;
}

test("the catalog runs in a throwaway VM of the image, with the image's tools, and leaves the evidence and no VM behind", async (t) => {
  if (skip) return t.skip(skip);
  const r = await rig("vmt8", ["vmt800"]);
  await writeFile(join(r.evidence, "floppy.img"), floppy());
  const sandbox = realpathSync(r.sandbox);
  // Mounted where inputs/ points, as the kickoff does (it links the real path).
  const evidence = readlinkSync(join(sandbox, "inputs"));
  const evidenceBefore = await fingerprint(evidence, []);
  const floorBefore = await fingerprint(sandbox, ["catalog"]);

  // What the image holds decides what the catalog can build; the host's own
  // tools must not show through. VM_TEST_CATALOG_IMAGE names an image with
  // The Sleuth Kit (CI builds disk for it): then the disk must be catalogued,
  // not merely allowed to be.
  const catalogImage = process.env.VM_TEST_CATALOG_IMAGE || IMAGE;
  assert.deepEqual((await createVms({ ...r.spec, image: catalogImage })).failures, []);
  const imageHasTsk = inVm(vmName(r.run, "vmt800"), "command -v fsstat >/dev/null && command -v fls >/dev/null && echo yes || echo no").trim() === "yes";
  if (process.env.VM_TEST_CATALOG_IMAGE) assert.ok(imageHasTsk, `${catalogImage} was named for the catalog test and has no Sleuth Kit`);

  // With the run's allowed hosts, as a kickoff with --allow-host passes them.
  const result = await imageCatalog(catalogImage, sandbox, [evidence], { memoryMib: 1024, allowHosts: ["registry.npmjs.org", "*.github.com"] });
  assert.equal(result.code, 0, result.output);
  const readme = await readFile(join(sandbox, "catalog", "README.md"), "utf8");
  if (imageHasTsk) {
    assert.match(readme, /^Summary: 1 disk image\(s\)/, readme);
    assert.match(await readFile(join(sandbox, "catalog", "floppy.img", "p0", "filelist.txt"), "utf8"), /HELLO\.TXT/);
  } else {
    assert.match(readme, /^Summary: 0 disk image\(s\)/, `an image without The Sleuth Kit catalogued a disk: the host's tools showed through\n${readme}`);
  }
  assert.deepEqual([...(await fingerprint(evidence, []))], [...evidenceBefore], "the evidence did not change");
  assert.deepEqual([...(await fingerprint(sandbox, ["catalog", "vm"]))], [...floorBefore].filter(([k]) => !k.startsWith("vm/")), "the catalog wrote nothing but catalog/");
  assert.doesNotMatch(msb("list"), /dfs-catalog-/, "the catalog's VM is gone");
});

test("in a VM the shared work/ is read-only, a peer's directory is not one's own, extracted material cannot run, and a deliverable is published through the hub", async (t) => {
  if (skip) return t.skip(skip);
  const r = await rig("vmt9", ["vmt900", "vmt901"]);
  assert.deepEqual((await createVms(r.spec)).failures, []);
  const S = r.sandbox;
  // A peer makes a file executable in its own extracted corner first.
  const peer = await inVmAsync(vmName(r.run, "vmt901"), `
    printf '#!/bin/sh\necho ran\n' > "${S}/work/extracted/vmt901/peer.sh" && chmod +x "${S}/work/extracted/vmt901/peer.sh" && echo "peer file made"
  `);
  assert.match(peer, /peer file made/, peer);
  const out = await inVmAsync(vmName(r.run, "vmt900"), `
    w() { if ( printf x > "$1" ) 2>/dev/null; then echo "WROTE $1"; else echo "refused $1"; fi; }
    w "${S}/work/shared.md"; w "${S}/work/vmt901/theirs.md"; w "${S}/work/extracted/vmt901/theirs.bin"
    printf '# findings\n' > "${S}/work/vmt900/report.md" && echo "own ok"
    printf '#!/bin/sh\necho ran\n' > "${S}/work/extracted/vmt900/x.sh"; chmod +x "${S}/work/extracted/vmt900/x.sh"
    # test -x asks access(X_OK), which a no-exec mount refuses: the mode bits are asked instead.
    [ -f "${S}/work/extracted/vmt900/x.sh" ] && stat -c %A "${S}/work/extracted/vmt900/x.sh" | grep -q x && echo "own file there"
    "${S}/work/extracted/vmt900/x.sh" 2>/dev/null && echo "EXECUTED" || echo "noexec held"
    for i in $(seq 40); do [ -f "${S}/work/extracted/vmt901/peer.sh" ] && break; sleep 0.25; done
    [ -f "${S}/work/extracted/vmt901/peer.sh" ] && stat -c %A "${S}/work/extracted/vmt901/peer.sh" | grep -q x && echo "peer file there"
    "${S}/work/extracted/vmt901/peer.sh" 2>/dev/null && echo "PEER EXECUTED" || echo "peer noexec held"
    /.msb/scripts/dfirswarm-bridge; sleep 0.5
    # The request's writer stays open until the hub answers: a half-closed
    # connection is ended by the guest's bridge before a slow reply arrives.
    # Without its bytes a publish is refused: the hub does not open a file
    # in a seat's own directory.
    { printf '%s\\n' '{"t":"rpc","fn":"publishFile","args":[null,"work/vmt900/report.md","work/report.md"]}'; sleep 4; } | socat -t 30 - UNIX-CONNECT:/run/dfirswarm/hub.sock 2>&1 | sed 's/^/rawpublish /'
    b64="$(base64 -w0 "${S}/work/vmt900/report.md" 2>/dev/null || base64 "${S}/work/vmt900/report.md" | tr -d '\\n')"
    { printf '{"t":"rpc","fn":"publishFile","args":[null,"work/vmt900/report.md","work/report.md",{"bytes_b64":"%s"}]}\\n' "$b64"; sleep 8; } | socat -t 30 - UNIX-CONNECT:/run/dfirswarm/hub.sock 2>&1 | sed 's/^/publish /'
  `);
  assert.match(out, /refused .*work\/shared\.md/, out);
  assert.match(out, /refused .*work\/vmt901\/theirs\.md/, "a peer's scratch is read-only here");
  assert.match(out, /refused .*work\/extracted\/vmt901\/theirs\.bin/, "a peer's extracted material is read-only here");
  assert.match(out, /own ok/, out);
  assert.match(out, /own file there/, `the file under test exists and is executable by its mode: ${out}`);
  assert.match(out, /noexec held/, "nothing under work/extracted/ runs");
  assert.match(out, /peer file there/, `the peer's file is visible here: ${out}`);
  assert.match(out, /peer noexec held/, "a peer's extracted file does not run in another VM");
  assert.doesNotMatch(out, /EXECUTED/);
  assert.match(out, /rawpublish .*bytes with the call/, `a publish without its bytes is refused: ${out}`);
  assert.match(out, /"ok":true/, `the publish went through the hub: ${out}`);
  assert.equal(await readFile(join(S, "work", "report.md"), "utf8"), "# findings\n", "the deliverable is on the host, written by the hub");
  const claims = await readdir(join(S, "locks")).catch(() => []);
  assert.ok(claims.length >= 1, "the destination was claimed for the publisher");
});

test("the catalog's VM, parsing hostile evidence as root, can write catalog/ and nothing else of the run or the evidence", async (t) => {
  if (skip) return t.skip(skip);
  const r = await rig("vmtc", ["vmtc00"]);
  const S = r.sandbox;
  await writeFile(join(S, "inputs.json"), '{"files":[]}\n');
  const before = await fingerprint(S, ["catalog", "vm"]);
  const evidenceBefore = await fingerprint(r.evidence, []);
  const out = await imageCatalog(IMAGE, S, [r.evidence], {
    command: `
      w() { if ( printf x >> "$1" ) 2>/dev/null; then echo "WROTE $1"; else echo "refused $1"; fi; }
      w "${S}/inputs.json"; w "${S}/SWARM.md"; w "${S}/traces/events.jsonl"; w "${r.evidence}/notes.txt"
      mkdir -p "${S}/tools/planted" 2>/dev/null && echo "MADE tools" || echo "refused tools"
      printf 'index\n' > "${S}/catalog/README.md" && echo "catalog ok"
    `,
  });
  assert.match(out.output, /catalog ok/, out.output);
  assert.doesNotMatch(out.output, /WROTE|MADE/, out.output);
  assert.deepEqual(await fingerprint(S, ["catalog", "vm"]), before, "nothing of the run outside catalog/ changed");
  assert.deepEqual(await fingerprint(r.evidence, []), evidenceBefore, "the evidence is unchanged");
});

test("in a VM a forged tool and a seeded one run only as their sealed bytes, and a seat's own file is recorded and restored without the hub opening it", async (t) => {
  if (skip) return t.skip(skip);
  const r = await rig("vmtf", ["vmtf00"], { env: { SWARM_ID: "vmtf", SWARM_TOOL_FORGING: "1" } }, { forging: true });
  const S = r.sandbox;
  // A tool seeded the way a pack's is: copied into tools/ and sealed into history on the host.
  const { sealForgedTools } = await import("../extensions/protocol.ts");
  const script = "echo seeded-ran\n";
  await mkdir(join(S, "tools", "seeded_tool"), { recursive: true });
  await writeFile(join(S, "tools", "seeded_tool", "run.sh"), script);
  await writeFile(join(S, "tools", "seeded_tool", "manifest.json"), JSON.stringify({ name: "seeded_tool", description: "Seeded.", params: {}, runtime: "bash", entry: "run.sh", timeout_seconds: 30, by: "harness", at: new Date().toISOString(), version: 1, sha256: createHash("sha256").update(script).digest("hex"), pack: "a-pack" }));
  await sealForgedTools(S);
  assert.deepEqual((await createVms(r.spec)).failures, []);
  const code = `
    const P = await import(${JSON.stringify(join(ROOT, "extensions", "protocol.ts"))});
    const B = await import(${JSON.stringify(join(ROOT, "extensions", "board.ts"))});
    const S = ${JSON.stringify(S)};
    const ctx = { sandboxRoot: S, agentId: "vmtf00" };
    const say = (k, v) => console.log(k + " " + JSON.stringify(v));
    const forged = await B.forgeTool(ctx, { name: "echo_here", description: "Echo.", runtime: "bash", script: "echo forged-ran\\n" });
    say("forged", forged.ok);
    for (const name of ["echo_here", "seeded_tool"]) {
      const sealed = await B.forgedToolSeal(S, name);
      const manifest = JSON.parse(require("node:fs").readFileSync(S + "/tools/" + name + "/manifest.json", "utf8"));
      const run = await P.runForgedTool(S, manifest, {}, { agentId: "vmtf00", sealed });
      say(name, run.stdout.trim());
    }
    const fs = await import("node:fs/promises");
    await fs.writeFile(S + "/work/vmtf00/notes.md", "one\\n");
    const r1 = await B.recordFileVersion(S, "work/vmtf00/notes.md", "vmtf00");
    await fs.writeFile(S + "/work/vmtf00/notes.md", "two\\n");
    await B.recordFileVersion(S, "work/vmtf00/notes.md", "vmtf00");
    const back = await B.restoreFileVersion(ctx, "work/vmtf00/notes.md", r1.rev);
    say("restored", back.ok);
    say("now", await fs.readFile(S + "/work/vmtf00/notes.md", "utf8"));
  `;
  const { writeFile: wf } = await import("node:fs/promises");
  await wf(join(S, "work", "vmtf00-check.mjs"), `import { createRequire } from "node:module"; const require = createRequire(import.meta.url);\n${code}`);
  const out = await inVmAsync(vmName(r.run, "vmtf00"), `/.msb/scripts/dfirswarm-bridge; sleep 0.5; cd "${S}" && node --experimental-strip-types --no-warnings work/vmtf00-check.mjs 2>&1`);
  assert.match(out, /forged true/, out);
  assert.match(out, /echo_here "forged-ran"/, `the forged tool ran in the VM as its sealed bytes: ${out}`);
  assert.match(out, /seeded_tool "seeded-ran"/, `the seeded tool ran in the VM: ${out}`);
  assert.match(out, /restored true/, out);
  assert.match(out, /now "one\\n"/, `the restore was made in the VM: ${out}`);
  assert.equal(await readFile(join(S, "work", "vmtf00", "notes.md"), "utf8"), "one\n", "and the host sees it");
  const history = await readdir(join(S, "history"));
  assert.ok(history.length >= 1, "the revisions are in history/, written by the hub from the bytes the VM sent");
});

test("a claim on a file a peer just published waits out the guest cache, with the default settle", async (t) => {
  if (skip) return t.skip(skip);
  const r = await rig("vmts", ["vmts00", "vmts01"], {}, { settleMs: undefined });
  assert.deepEqual((await createVms(r.spec)).failures, []);
  const S = r.sandbox;
  await writeFile(join(S, "work", "vmts00", "report.md"), "# from vmts00\n").catch(async () => {
    await mkdir(join(S, "work", "vmts00"), { recursive: true });
    await writeFile(join(S, "work", "vmts00", "report.md"), "# from vmts00\n");
  });
  const { callBoard } = await import("../extensions/board.ts");
  const published = (await callBoard(r.hub.socketFor("vmts00"), "publishFile", [null, "work/vmts00/report.md", "work/report.md", { bytes_b64: Buffer.from("# from vmts00\n").toString("base64") }])) as { ok: boolean };
  assert.equal(published.ok, true);
  await callBoard(r.hub.socketFor("vmts00"), "releaseFile", [null, "work/report.md"]);
  const t0 = Date.now();
  const claim = (await callBoard(r.hub.socketFor("vmts01"), "claimFile", [null, "work/report.md", { reason: "take over the report" }])) as { ok: boolean };
  const waited = Date.now() - t0;
  assert.equal(claim.ok, true);
  assert.ok(waited >= 5500, `the peer's claim waited out the cache window (${waited} ms)`);
});

test("in a VM an 8 MiB deliverable, a large trace line and a long prompt cross the hub link in parts, whole, while the budget still answers within seconds", async (t) => {
  if (skip) return t.skip(skip);
  const r = await rig("vmtb", ["vmtb00"]);
  assert.deepEqual((await createVms(r.spec)).failures, []);
  const S = r.sandbox;
  // The guest's own board client and trace, as the extension uses them. One
  // write of about 262 KB stalled the vsock path for good (215 KB passed),
  // and every call behind it on the connection waited until the seat was
  // stopped as cut off from the hub.
  const content = Array.from({ length: 12_000 }, (_, i) => `row ${i} of a file the agent wrote`).join("\n");
  const brief = Array.from({ length: 4_000 }, (_, i) => `step ${i}: keep going`).join("\n");
  const code = `
    const B = await import(${JSON.stringify(join(ROOT, "extensions", "board.ts"))});
    const P = await import(${JSON.stringify(join(ROOT, "extensions", "protocol.ts"))});
    const { createHash, randomBytes } = await import("node:crypto");
    const fs = await import("node:fs/promises");
    const S = ${JSON.stringify(S)};
    const ctx = { sandboxRoot: S, agentId: "vmtb00" };
    const say = (k, v) => console.log(k + " " + JSON.stringify(v));
    const prompts = [];
    const link = B.openHubLink(process.env.SWARM_BOARD_SOCKET, (p) => prompts.push(p.text));
    const bytes = randomBytes(8 * 1024 * 1024);
    await fs.writeFile(S + "/work/vmtb00/big.bin", bytes);
    say("sha", createHash("sha256").update(bytes).digest("hex"));
    let done = false;
    const t0 = Date.now();
    const publishing = B.publishFile(ctx, "work/vmtb00/big.bin", "work/big.bin").then(
      (res) => say("published", { ok: res.ok, reason: res.reason ?? null, ms: Date.now() - t0 }),
      (err) => say("published", { ok: false, reason: String(err && err.message), ms: Date.now() - t0 }),
    ).finally(() => { done = true; });
    const budgets = [];
    let during = 0;
    do {
      await new Promise((ok) => setTimeout(ok, 200));
      const b0 = Date.now();
      const budget = await B.readBudgetLive(S);
      budgets.push(Date.now() - b0);
      if (!done) during++;
      if (typeof budget.spent_usd !== "number") say("budget odd", budget);
    } while (!done && budgets.length < 600);
    await publishing;
    say("budget ms", budgets);
    say("during", during);
    const content = await fs.readFile(S + "/work/vmtb00-content.txt", "utf8");
    await P.appendEvent(S, { agent: "vmtb00", tool: "write", args: { path: "work/vmtb00/notes.md", content }, result: { ok: true } });
    say("traced", true);
    const until = Date.now() + 60_000;
    while (!prompts.length && Date.now() < until) await new Promise((ok) => setTimeout(ok, 100));
    say("prompt sha", prompts.length ? createHash("sha256").update(prompts[0]).digest("hex") : null);
    link.close();
  `;
  await writeFile(join(S, "work", "vmtb00-check.mjs"), code);
  await writeFile(join(S, "work", "vmtb00-content.txt"), content);
  const running = inVmAsync(vmName(r.run, "vmtb00"), `/.msb/scripts/dfirswarm-bridge; sleep 0.5; cd "${S}" && node --experimental-strip-types --no-warnings work/vmtb00-check.mjs 2>&1`);
  // The prompt goes as soon as the guest's link is up: fetched in parts on
  // the link while the publish goes up in parts on the board's connection.
  const deadline = Date.now() + 120_000;
  while (r.hub.statusSnapshot().vmtb00?.connected !== true && Date.now() < deadline) await new Promise((ok) => setTimeout(ok, 100));
  assert.equal(r.hub.prompt("vmtb00", brief, { deliver: "followUp", kind: "brief" }), true, "the guest's link came up");
  const out = await running;
  assert.match(out, /published \{"ok":true/, `the publish went through the hub: ${out}`);
  const sha = /sha "([0-9a-f]{64})"/.exec(out)?.[1];
  assert.ok(sha, out);
  const landed = await readFile(join(S, "work", "big.bin"));
  assert.equal(landed.length, 8 * 1024 * 1024, "every byte arrived");
  assert.equal(createHash("sha256").update(landed).digest("hex"), sha, "the deliverable on the host is the guest's file, byte for byte");
  const budgets = JSON.parse(/budget ms (\[[^\]]*\])/.exec(out)?.[1] ?? "[]") as number[];
  assert.ok(budgets.length >= 1, out);
  assert.ok(Math.max(...budgets) < 5_000, `the budget answered within seconds throughout (${budgets.join(", ")} ms)`);
  assert.doesNotMatch(out, /budget odd/, out);
  assert.match(out, /traced true/, out);
  const line = r.lines.find((l) => l.tool === "write" && l.agent === "vmtb00");
  assert.equal((line?.args as { content?: string } | undefined)?.content, content, "the trace line reached the collector whole");
  assert.match(out, new RegExp(`prompt sha "${createHash("sha256").update(brief).digest("hex")}"`), `the long prompt arrived in the guest whole: ${out}`);
});

test("the network check boots the run's policy in a throwaway VM: allowed hosts answer, others do not resolve, and one provider's placeholder never reaches another's host", async (t) => {
  if (skip) return t.skip(skip);
  // Real hosts on the internet: an offline host says so instead of failing.
  if (process.env.DFIRSWARM_OFFLINE === "1") return t.skip("DFIRSWARM_OFFLINE=1");
  const r = await netCheck(IMAGE, ["api.deepseek.com", "pypi.org", "*.blob.core.windows.net", "127.0.0.1:8080"]);
  const text = r.rows.map((x) => `${x.ok ? "ok" : "FAIL"} ${x.check}: ${x.host} -> ${x.result}`).join("\n");
  assert.ok(r.ok, text);
  assert.ok(r.rows.some((x) => /outside the list/.test(x.check) && /000$/.test(x.result)), text);
  assert.ok(r.rows.some((x) => /stopped on its way to pypi\.org/.test(x.check) && x.ok), text);
  assert.doesNotMatch(msb("list"), /dfs-netcheck-/, "the check's VM is gone");
});

test("a finish lock left by a stop that was interrupted does not hold the next stop", async (t) => {
  if (skip) return t.skip(skip);
  const sandbox = await mkdtemp(join(tmpdir(), "vmlock-"));
  cleanups.push(() => rm(sandbox, { recursive: true, force: true }));
  await mkdir(join(sandbox, "vm", ".finish.lock"), { recursive: true });
  // A pid nobody has: the stop that held it is gone.
  await writeFile(join(sandbox, "vm", ".finish.lock", "pid"), "999999\n");
  const started = Date.now();
  assert.deepEqual(await finishRun("vmt-nolock", sandbox), [], "no VM of that run, and no wait");
  assert.ok(Date.now() - started < 10_000, `the dead owner's lock was waited on for ${Date.now() - started} ms`);
  assert.equal(existsSync(join(sandbox, "vm", ".finish.lock")), false, "and the lock is released after");
});

test("end to end: Pi runs in its VM with the harness extension, calls a scripted model on the host, posts through the hub, and finds the evidence guarded by the kernel", async (t) => {
  if (skip) return t.skip(skip);
  const base = await mkdtemp(join(tmpdir(), "vme2e-"));
  cleanups.push(() => rm(base, { recursive: true, force: true }));
  // A model on this host, scripted: the first turn posts to the board, the
  // second says it is done. OpenAI's streaming shape, as Pi calls it.
  const port = 19000 + Math.floor(Math.random() * 500);
  const requests = join(base, "requests.log");
  await writeFile(join(base, "model.mjs"), `
import { createServer } from "node:http";
import { appendFileSync } from "node:fs";
createServer((req, res) => {
  let body = "";
  req.on("data", (d) => (body += d));
  req.on("end", () => {
    appendFileSync(${JSON.stringify(requests)}, req.url + "\\n");
    const toolDone = (JSON.parse(body || "{}").messages || []).some((m) => m.role === "tool");
    res.writeHead(200, { "content-type": "text/event-stream" });
    const send = (o) => res.write("data: " + JSON.stringify(o) + "\\n\\n");
    const chunk = (delta, finish) => send({ id: "c", object: "chat.completion.chunk", model: "m1", choices: [{ index: 0, delta, finish_reason: finish }] });
    if (!toolDone) {
      chunk({ role: "assistant", content: null, tool_calls: [{ index: 0, id: "call_1", type: "function", function: { name: "post", arguments: JSON.stringify({ tag: "result", body: "hello from inside the VM" }) } }] }, null);
      chunk({}, "tool_calls");
    } else {
      chunk({ role: "assistant", content: "Posted." }, null);
      chunk({}, "stop");
    }
    res.end("data: [DONE]\\n\\n");
  });
}).listen(${port}, "127.0.0.1");
`);
  const { spawn } = await import("node:child_process");
  const model = spawn(process.execPath, [join(base, "model.mjs")], { stdio: "ignore" });
  cleanups.push(async () => model.kill());
  const { connect } = await import("node:net");
  for (let i = 0; i < 100; i++) {
    const up = await new Promise<boolean>((done) => {
      const c = connect(port, "127.0.0.1", () => {
        c.end();
        done(true);
      });
      c.on("error", () => done(false));
    });
    if (up) break;
    await new Promise((r) => setTimeout(r, 50));
  }
  // Pi's store on the host: the scripted provider, as a local server.
  const piDir = join(base, "pi");
  await mkdir(piDir, { recursive: true });
  await writeFile(join(piDir, "auth.json"), "{}\n");
  await writeFile(join(piDir, "models.json"), JSON.stringify({ providers: { scripted: { baseUrl: `http://127.0.0.1:${port}/v1`, api: "openai-completions", apiKey: "none", models: [{ id: "m1", name: "m1", reasoning: false, input: ["text"], contextWindow: 32000, maxTokens: 2000, cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 } }] } } }));
  const r = await rig("vmte", ["vmte00"], {
    pi_agent_dir: piDir,
    providers: [{ provider: "scripted", kind: "local", hosts: [`127.0.0.1:${port}`], port }],
    env: { SWARM_ID: "vmte", PI_OFFLINE: "1" },
  });
  r.spec.agents = [{ id: "vmte00", model: "scripted/m1" }];
  r.spec.mounts = [
    ...r.spec.mounts,
    { host: join(ROOT, "scripts"), readonly: true },
    { host: join(ROOT, "prompts"), readonly: true },
    { host: join(ROOT, "node_modules", "typebox"), readonly: true },
  ];
  // The evidence manifest the kickoff writes: what makes the agent probe
  // inputs/ at the start of its session.
  const files = [];
  for (const rel of ["notes.txt", "mail/a.bin"]) {
    const bytes = await readFile(join(r.evidence, rel));
    files.push({ path: `inputs/${rel}`, bytes: bytes.length, sha256: createHash("sha256").update(bytes).digest("hex") });
  }
  await writeFile(join(r.sandbox, "inputs.json"), JSON.stringify({ source: r.evidence, copied_at: new Date().toISOString(), files, bytes: files.reduce((n, f) => n + f.bytes, 0), guard: "microvm", enforce: "on", held: "bind" }));
  const created = await createVms(r.spec);
  assert.deepEqual(created.failures, [], JSON.stringify(created.failures));
  const S = r.sandbox;
  const out = await inVmAsync(
    vmName(r.run, "vmte00"),
    `/.msb/scripts/dfirswarm-pi -p --approve --name vmte00 --session-dir "${S}/.pi-sessions/vmte00" -e "${join(ROOT, "extensions", "agent-swarm.ts")}" --model scripted/m1 "Post hello to the board." 2>&1 | tail -20`,
  );
  assert.match(out, /Posted\./, `Pi finished its turn in the VM\n${out}`);
  const calls = (await readFile(requests, "utf8").catch(() => "")).trim().split("\n").filter(Boolean);
  assert.ok(calls.length >= 2, `the scripted model was called through the host gateway: ${calls.join(", ")}`);
  const tools = r.lines.map((l) => String(l.tool));
  assert.ok(tools.includes("agent_start"), `the extension started and its line came through the hub: ${tools.join(", ")}`);
  const guard = r.lines.find((l) => l.tool === "inputs_guard") as { result?: { enforced?: string } } | undefined;
  assert.equal(guard?.result?.enforced, "kernel", `the evidence is refused to the agent by the kernel: ${JSON.stringify(guard)}`);
  assert.ok(tools.includes("post"), `the post was recorded: ${tools.join(", ")}`);
  const posts = await readdir(join(S, "threads", "main"));
  const mine = posts.find((f) => f.endsWith("-vmte00.md"));
  assert.ok(mine, `the hub wrote the agent's post on the board: ${posts.join(", ")}`);
  assert.match(await readFile(join(S, "threads", "main", mine as string), "utf8"), /hello from inside the VM/);
});
