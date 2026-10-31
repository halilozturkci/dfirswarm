/**
 * `swarm.sh start --pack-tools-as-jobs PACK[,PACK]`: the tools of those packs
 * are not registered as Pi tools. The contract lists each with its
 * description and parameters, and a seat runs one as job_run(tool, args)
 * through the job service. Without the option nothing changes.
 *
 * The extension is driven as a seat's is in a VM: its board calls go to a hub
 * socket, here a small server over the hub's own call table and a real job
 * service whose worker is the local stand-in. The kickoff is read from
 * `swarm.sh start --no-start`, which makes a prepared microVM run without
 * starting a VM.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type Server, type Socket } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import extension from "../extensions/agent-swarm.ts";
import { closeBoardClients } from "../extensions/board.ts";
import { initSandbox } from "../extensions/protocol.ts";
import { storePaths } from "../scripts/evidence-store.ts";
import { JobService } from "../scripts/job-service.ts";
import { boardTable } from "../scripts/vm-hub.ts";
import { listInputs, localWorker } from "./job-service-worker.ts";

const ROOT = join(import.meta.dirname, "..");
const PILOT = "virtualization-backup-forensics";
const linux = process.platform === "linux";

type Json = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any
type Tool = { name: string; description?: string; parameters?: unknown; execute: (id: string, params: Json, signal: undefined, update: undefined, ctx: { cwd: string }) => Promise<{ content: Array<{ text: string }>; details: Json; isError?: boolean }> };

const ENV_KEYS = ["AGENT_ID", "SWARM_BOARD_SOCKET", "SWARM_TRACE_SOCKET", "SWARM_PACK_TOOLS_AS_JOBS", "SWARM_TOOL_FORGING", "SWARM_TOOLS", "SWARM_PACK_PROGRAMS_IN_JOBS", "SWARM_ISOLATION"];
const envWas = Object.fromEntries(ENV_KEYS.map((k) => [k, process.env[k]]));
function restoreEnv(): void {
  for (const k of ENV_KEYS) {
    if (envWas[k] === undefined) delete process.env[k];
    else process.env[k] = envWas[k];
  }
}

const cleanups: Array<() => unknown> = [];
after(async () => {
  restoreEnv();
  closeBoardClients();
  for (const c of cleanups.reverse()) {
    try {
      await c();
    } catch {
      // the rest still goes
    }
  }
});

/** A directory the store sealed read-only, removed. */
function removeTree(d: string): void {
  spawnSync("chmod", ["-R", "u+w", d]);
  rmSync(d, { recursive: true, force: true });
}

function tmp(prefix: string): string {
  const d = mkdtempSync(join(tmpdir(), prefix));
  cleanups.push(() => removeTree(d));
  return d;
}

/** A tool of a sandbox as a pack seeds it: manifest with the pack it came from, and a script whose hash the manifest holds. */
function seed(S: string, name: string, pack: string | null, params: Record<string, unknown>, script: string, description = "Does one thing."): void {
  mkdirSync(join(S, "tools", name), { recursive: true });
  writeFileSync(join(S, "tools", name, "run.py"), script);
  const sha256 = createHash("sha256").update(script).digest("hex");
  writeFileSync(
    join(S, "tools", name, "manifest.json"),
    JSON.stringify({ name, description, params, runtime: "python3", entry: "run.py", timeout_seconds: 60, by: pack ?? "a0", at: "2026-01-01T00:00:00Z", version: 1, sha256, ...(pack ? { pack } : {}) }),
  );
}

const WRITER = "import json,sys,os\nd=json.load(sys.stdin)\nos.makedirs(os.path.dirname(d['output']), exist_ok=True)\nopen(d['output'],'w').write(d['text'])\nprint(json.dumps({'ok': True}))\n";

/** Load the extension as a seat of a run: the registered tools, and the handlers of each event. */
function load(env: Record<string, string | undefined>): { tools: Map<string, Tool>; fire: (event: string, ctx: { cwd: string }) => Promise<void> } {
  const tools = new Map<string, Tool>();
  const handlers = new Map<string, Array<(e: unknown, c: unknown) => unknown>>();
  const base: Record<string, unknown> = {
    registerTool: (t: Tool) => tools.set(t.name, t),
    on: (event: string, fn: (e: unknown, c: unknown) => unknown) => handlers.set(event, [...(handlers.get(event) ?? []), fn]),
  };
  const pi = new Proxy(base, { get: (target, key) => (key in target ? target[key as string] : () => undefined) });
  // The environment is the seat's for as long as the test uses it (the extension reads the hub's socket when it calls): the next load, or the end of the file, puts it back.
  restoreEnv();
  for (const k of ENV_KEYS) delete process.env[k];
  Object.assign(process.env, { AGENT_ID: "a0" }, env);
  extension(pi as never);
  return {
    tools,
    fire: async (event, ctx) => {
      for (const fn of handlers.get(event) ?? []) await fn({}, ctx);
    },
  };
}

/** The hub of a seat's VM: the call table of scripts/vm-hub.ts over a socket, with a job service whose worker runs on this machine. */
async function hub(S: string): Promise<{ socket: string; svc: JobService }> {
  const svc = new JobService({
    sandbox: S, run: "s000000", image: "img:test", workers: 2, workerCpus: 1, workerMemoryMib: 512, allowHosts: [], openNet: false,
    packDirs: [join(ROOT, "packs", "computer-forensics-base")], forging: true, minFreeMb: 1,
    runWorker: localWorker(), destroyWorker: async () => ({ ok: true }),
    notify: async () => undefined, identity: async (a) => ({ name: `${a} the examiner` }),
  });
  await svc.start();
  cleanups.push(() => svc.stop("test over"));
  const table = boardTable({ sandbox: S, settle: async () => undefined, wrote: () => undefined, ids: ["a0"], jobs: () => svc }) as unknown as Record<string, (who: string, a: unknown[], s: AbortSignal) => Promise<unknown>>;
  const dir = mkdtempSync("/tmp/pj.");
  cleanups.push(() => removeTree(dir));
  const socket = join(dir, "h.sock");
  const sockets = new Set<Socket>();
  const server: Server = createServer((c) => {
    sockets.add(c);
    c.on("close", () => sockets.delete(c));
    c.on("error", () => undefined);
    c.setEncoding("utf8");
    let buf = "";
    c.on("data", (chunk: string) => {
      buf += chunk;
      let cut;
      while ((cut = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, cut);
        buf = buf.slice(cut + 1);
        let msg: { t?: string; id?: number; fn?: string; args?: unknown[] };
        try {
          msg = JSON.parse(line);
        } catch {
          continue;
        }
        if (msg.t !== "rpc" || !msg.fn) continue;
        const fn = table[msg.fn];
        const reply = (o: Json) => {
          if (!c.destroyed) c.write(`${JSON.stringify({ id: msg.id, ...o })}\n`);
        };
        if (!fn) {
          reply({ ok: false, error: `no ${msg.fn} in this fake hub` });
          continue;
        }
        fn("a0", msg.args ?? [], new AbortController().signal).then(
          (result) => reply({ ok: true, result }),
          (err: Error) => reply({ ok: false, error: err.message }),
        );
      }
    });
  });
  await new Promise<void>((r) => server.listen(socket, () => r()));
  cleanups.push(async () => {
    for (const s of sockets) s.destroy();
    await new Promise((r) => server.close(r));
  });
  return { socket, svc };
}

/** A run's sandbox holding a pilot pack's two tools, another pack's tool, and one a seat forged. */
async function runWith(): Promise<string> {
  const S = join(tmp("pack-jobs-"), "run");
  mkdirSync(S, { recursive: true });
  await initSandbox(S, { swarmId: "s000000", agentIds: ["a0"], capUsd: 5, wallClockMinutes: 30 });
  for (const d of ["inputs", "catalog", "work/a0"]) mkdirSync(join(S, d), { recursive: true });
  writeFileSync(join(S, "inputs.json"), JSON.stringify({ files: [] }));
  listInputs(S);
  seed(S, "pilot_write", "pilot-pack", { output: { type: "string", required: true, description: "Where" }, text: { type: "string", required: true }, note: { type: "integer" } }, WRITER, "Writes\n  its text to a file.");
  seed(S, "pilot_idle", "pilot-pack", {}, "print('{}')\n");
  seed(S, "other_tool", "other-pack", { path: { type: "string", required: true } }, "print('{}')\n");
  seed(S, "forged_tool", null, {}, "print('{}')\n");
  return S;
}

const PILOT_TOOLS = ["pilot_write", "pilot_idle"];
const OTHERS = ["other_tool", "forged_tool"];

test("with the option for the pilot pack, its tools are not registered and every other is; without it, all are", { skip: !linux, timeout: 120_000 }, async () => {
  const S = await runWith();
  const { socket } = await hub(S);
  const without = load({ SWARM_BOARD_SOCKET: socket });
  await without.fire("session_start", { cwd: S });
  for (const t of [...PILOT_TOOLS, ...OTHERS]) assert.ok(without.tools.has(t), `${t} is registered without the option`);
  const withIt = load({ SWARM_BOARD_SOCKET: socket, SWARM_PACK_TOOLS_AS_JOBS: "pilot-pack" });
  await withIt.fire("session_start", { cwd: S });
  for (const t of PILOT_TOOLS) assert.ok(!withIt.tools.has(t), `${t} is a Pi tool with the option`);
  for (const t of OTHERS) assert.ok(withIt.tools.has(t), `${t} left the tool list`);
  assert.ok(withIt.tools.has("job_run"), "job_run, the one call that runs them, is registered");
  // Naming a pack the run does not carry skips nothing.
  const other = load({ SWARM_BOARD_SOCKET: socket, SWARM_PACK_TOOLS_AS_JOBS: "no-such-pack" });
  await other.fire("session_start", { cwd: S });
  for (const t of [...PILOT_TOOLS, ...OTHERS]) assert.ok(other.tools.has(t), `${t} is registered when the option names another pack`);
  // The same decision for a seat that forges: the pilot's tools are left out, a forged one is not.
  const forging = load({ SWARM_BOARD_SOCKET: socket, SWARM_PACK_TOOLS_AS_JOBS: "pilot-pack", SWARM_TOOL_FORGING: "1", SWARM_TOOLS: "read,bash" });
  await forging.fire("session_start", { cwd: S });
  for (const t of PILOT_TOOLS) assert.ok(!forging.tools.has(t), `${t} is a Pi tool in a forging run`);
  for (const t of OTHERS) assert.ok(forging.tools.has(t), `${t} left the tool list of a forging run`);
});

test("a seat with no hub to take the job keeps the tools: a tool is never lost", { skip: !linux, timeout: 60_000 }, async () => {
  const S = await runWith();
  const host = load({ SWARM_PACK_TOOLS_AS_JOBS: "pilot-pack" });
  await host.fire("session_start", { cwd: S });
  for (const t of [...PILOT_TOOLS, ...OTHERS]) assert.ok(host.tools.has(t), `${t} is missing from a seat that has no job service`);
});

test("job_run(tool, args) runs a pilot tool through the job path, sealed; a wrong or missing argument is refused naming the manifest's parameters", { skip: !linux, timeout: 120_000 }, async () => {
  const S = await runWith();
  const { socket } = await hub(S);
  const seat = load({ SWARM_BOARD_SOCKET: socket, SWARM_PACK_TOOLS_AS_JOBS: "pilot-pack" });
  await seat.fire("session_start", { cwd: S });
  const jobRun = seat.tools.get("job_run")!;
  const ctx = { cwd: S };
  const ran = await jobRun.execute("c", { tool: "pilot_write", args: { output: "{OUT}/sub/result.txt", text: "carved" }, wait_seconds: 60 }, undefined, undefined, ctx);
  assert.equal(ran.isError, undefined, ran.content[0]!.text);
  const id = ran.details.job as string;
  assert.match(id, /^j\d+$/, "it ran as a job");
  assert.equal(readFileSync(join(storePaths(S).jobs, id, "out", "sub", "result.txt"), "utf8"), "carved", "and its output is sealed in the store");
  const record = JSON.parse(readFileSync(join(storePaths(S).jobs, id, "job.json"), "utf8")) as Json;
  assert.equal(record.spec.kind, "tool");
  assert.equal(record.spec.tool, "pilot_write");

  const refused = async (args: Json, why: RegExp) => {
    const r = await jobRun.execute("c", { tool: "pilot_write", args, wait_seconds: 5 }, undefined, undefined, ctx);
    assert.equal(r.isError, true);
    const text = r.content[0]!.text;
    assert.match(text, why);
    assert.match(text, /Parameters of pilot_write: output: string, text: string, note\?: integer/, `the refusal does not name the parameters: ${text}`);
    assert.equal(r.details.ok, false);
  };
  await refused({ text: "x" }, /needs output/);
  await refused({ output: "{OUT}/a", text: 5 }, /text must be a string/);
  await refused({ output: "{OUT}/a", text: "x", extra: 1 }, /takes no extra/);
  await refused({ output: "{OUT}/a", text: "x", note: "n" }, /note must be an integer/);
  // A refusal that is not about the arguments gets nothing added.
  const none = await jobRun.execute("c", { tool: "no_such_tool", args: {}, wait_seconds: 5 }, undefined, undefined, ctx);
  assert.equal(none.isError, true);
  assert.match(none.content[0]!.text, /no tool no_such_tool in this run/);
  assert.doesNotMatch(none.content[0]!.text, /Parameters of/);
  // A tool called by its old name is no tool of the seat: it goes through job_run, and nowhere else.
  assert.equal(seat.tools.get("pilot_write"), undefined);
});

// ---------------------------------------------------------------------------
// The kickoff

function swarm(home: string, runs: string, args: string[], env: Record<string, string> = {}): { code: number; out: string } {
  const r = spawnSync("bash", [join(ROOT, "scripts", "swarm.sh"), ...args], {
    encoding: "utf8",
    timeout: 120_000,
    env: { ...process.env, SWARM_RUNS_DIR: runs, DFIRSWARM_HOME: home, SWARM_HUBS_DIR: join(home, "hubs"), MSB_HOME: join(home, "msb-home"), SWARM_ISOLATION: "", SWARM_VM_IMAGE: "", SWARM_IMAGES_LOCK: "", ...env },
  });
  return { code: r.status ?? -1, out: `${r.stdout}${r.stderr}` };
}

function kickoff() {
  const base = mkdtempSync("/tmp/pk.");
  cleanups.push(() => removeTree(base));
  const home = join(base, "home");
  const runs = join(base, "runs");
  mkdirSync(home, { recursive: true });
  const install = (dir: string) => {
    const r = spawnSync("bash", [join(ROOT, "scripts", "pack.sh"), "install", dir, "--yes"], { encoding: "utf8", timeout: 120_000, env: { ...process.env, DFIRSWARM_HOME: home } });
    assert.equal(r.status, 0, `${dir}: ${r.stdout}${r.stderr}`);
  };
  const manifest = JSON.parse(readFileSync(join(ROOT, "packs", PILOT, "pack.json"), "utf8")) as { depends?: Array<string | { id: string }> };
  for (const dep of manifest.depends ?? []) install(join(ROOT, "packs", (typeof dep === "string" ? dep : dep.id).replace(/[<>=~^ ].*$/, "")));
  install(join(ROOT, "packs", PILOT));
  const start = (extra: string[], label: string) =>
    swarm(home, runs, ["start", "--model", "solo/model", "--provider-host", "solo=api.solo.example", "--n", "2", "--cap-usd", "1", "--no-start", "--goal-file", join(ROOT, "prompts", "goals", "hello.md"), "--toolbox", "off", "--workers", "1", "--vm-memory", "512", "--worker-memory", "512", "--label", label, ...extra]);
  const record = (label: string): Json => (JSON.parse(readFileSync(join(runs, "registry.json"), "utf8")) as { runs: Json[] }).runs.find((r) => r.label === label)!;
  return { base, home, runs, install, start, record };
}

const pilotManifests = () =>
  readdirSync(join(ROOT, "packs", PILOT, "tools"))
    .map((d) => JSON.parse(readFileSync(join(ROOT, "packs", PILOT, "tools", d, "manifest.json"), "utf8")) as { name: string; description: string; params?: Record<string, { type?: string; required?: boolean }> })
    .sort((a, b) => a.name.localeCompare(b.name));

test("the contract lists each pilot tool with its description and parameters and says to call job_run; the record, the seats' environment and Pi's list follow", { skip: !linux, timeout: 300_000 }, () => {
  const k = kickoff();
  const plain = k.start([ "--isolation", "microvm", "--pack", PILOT], "plain");
  assert.equal(plain.code, 0, plain.out);
  const plainSandbox = k.record("plain").sandbox as string;
  assert.doesNotMatch(readFileSync(join(plainSandbox, "SWARM.md"), "utf8"), /Pack tools run as jobs/, "without the option the contract has no such section");
  assert.equal(k.record("plain").pack_tools_as_jobs, undefined, "and the record no such key");
  const plainSpec = readFileSync(join(plainSandbox, "vm-spec.json"), "utf8");
  assert.doesNotMatch(plainSpec, /SWARM_PACK_TOOLS_AS_JOBS/);

  const r = k.start(["--isolation", "microvm", "--pack", PILOT, "--pack-tools-as-jobs", PILOT], "piloted");
  assert.equal(r.code, 0, r.out);
  assert.match(r.out, new RegExp(`Pack tools:\\s+${PILOT}: run as jobs`));
  assert.deepEqual(k.record("piloted").pack_tools_as_jobs, [PILOT]);
  const sandbox = k.record("piloted").sandbox as string;
  const md = readFileSync(join(sandbox, "SWARM.md"), "utf8");
  const at = md.indexOf("## Pack tools run as jobs");
  assert.ok(at > 0, "SWARM.md has the section");
  assert.ok(at > md.indexOf("## Tool jobs"), "after the Tool jobs section it extends");
  const section = md.slice(at, md.indexOf("\n## ", at + 1));
  assert.match(section, /`job_run\(tool: <name>, args: \{\.\.\.\}\)`/);
  const manifests = pilotManifests();
  assert.ok(manifests.length >= 3, "the pilot pack has its tools");
  for (const m of manifests) {
    const params = Object.entries(m.params ?? {}).map(([name, p]) => `${name}${p.required ? "" : "?"}: ${p.type ?? "string"}`);
    const line = `- \`${m.name}\` (${PILOT}): ${m.description.replace(/\s+/g, " ").trim()} Parameters: ${params.length ? params.join(", ") : "no params"}.`;
    assert.ok(section.includes(line), `the section lacks the line of ${m.name}:\n${line}\n--- section ---\n${section}`);
  }
  // Every pilot tool is on disk in the run for the job service to run, and none is named to Pi.
  for (const m of manifests) assert.ok(existsSync(join(sandbox, "tools", m.name, "manifest.json")), `${m.name} is not in the run`);
  const spec = JSON.parse(readFileSync(join(sandbox, "vm-spec.json"), "utf8")) as { env: Record<string, string> };
  assert.equal(spec.env.SWARM_PACK_TOOLS_AS_JOBS, PILOT, "the seats are told");
});

test("Pi's allowlist, built by the kickoff, names the other seeded tools and not the pilot pack's", { skip: !linux, timeout: 60_000 }, () => {
  // The kickoff's own lines, run over a sandbox that holds the same four tools as above: nothing is copied from them.
  const sh = readFileSync(join(ROOT, "scripts", "swarm.sh"), "utf8");
  const from = sh.indexOf('  if [[ "$forging" -eq 0 && -d "$sandbox/tools" ]]; then');
  assert.ok(from > 0, "the kickoff names seeded tools to Pi where it did");
  const block = sh.slice(from, sh.indexOf("\n  fi\n", from) + 6);
  const S = tmp("pi-allow-");
  for (const [name, pack] of [["pilot_write", "pilot-pack"], ["pilot_idle", "pilot-pack"], ["other_tool", "other-pack"], ["forged_tool", ""]] as const) {
    mkdirSync(join(S, "tools", name), { recursive: true });
    writeFileSync(join(S, "tools", name, "manifest.json"), JSON.stringify({ name, ...(pack ? { pack } : {}) }));
  }
  const names = (asJobs: string) => {
    const r = spawnSync("bash", ["-c", `f() { local forging=0 sandbox="$1" pack_tools_as_jobs="$2" PI_TOOLS="read,bash"\n${block}\n  printf '%s' "$PI_TOOLS"; }; f "$1" "$2"`, "bash", S, asJobs], { encoding: "utf8", timeout: 30_000 });
    assert.equal(r.status, 0, r.stderr);
    return r.stdout.split(",").slice(2).sort();
  };
  assert.deepEqual(names(""), ["forged_tool", "other_tool", "pilot_idle", "pilot_write"]);
  assert.deepEqual(names("pilot-pack"), ["forged_tool", "other_tool"]);
  assert.deepEqual(names("other-pack,pilot-pack"), ["forged_tool"]);
});

test("the option is refused where a tool would be lost: a host run, --no-jobs, a pack the run does not carry, a pack with secrets, a pack with no tool, a bad id", { skip: !linux, timeout: 600_000 }, () => {
  const k = kickoff();
  const refuse = (extra: string[], why: RegExp, label: string) => {
    const r = k.start(extra, label);
    assert.equal(r.code, 2, `${label}: ${r.out}`);
    assert.match(r.out, why, `${label}: ${r.out}`);
    assert.equal(k.record(label), undefined, `${label}: a refused kickoff wrote a run`);
  };
  refuse(["--isolation", "host", "--pack", PILOT, "--pack-tools-as-jobs", PILOT], /needs?.* the job service|through the job service, which only a microVM run has/, "host");
  refuse(["--isolation", "microvm", "--no-jobs", "--pack", PILOT, "--pack-tools-as-jobs", PILOT], /--no-jobs turns it off/, "nojobs");
  refuse(["--isolation", "microvm", "--pack", PILOT, "--pack-tools-as-jobs", "windows-forensics"], /windows-forensics, which is not one of the packs of this run/, "notcarried");
  refuse(["--isolation", "microvm", "--pack", PILOT, "--pack-tools-as-jobs", "Not A Pack"], /takes pack ids, comma-separated/, "badid");
  refuse(["--isolation", "microvm", "--pack", PILOT, "--pack-tools-as-jobs", `${PILOT},`], /takes pack ids, comma-separated/, "trailing");
  refuse(["--isolation", "microvm", "--pack-tools-as-jobs", PILOT], /not one of the packs of this run/, "nopack");

  // A pack that declares secrets, and one with no tool, built for the test.
  const src = join(k.base, "src");
  const make = (id: string, secrets: boolean, tool: boolean) => {
    const dir = join(src, id);
    mkdirSync(join(dir, "skills", "area"), { recursive: true });
    mkdirSync(join(dir, "requires"), { recursive: true });
    writeFileSync(join(dir, "LICENCE"), "Test pack.\n");
    writeFileSync(join(dir, "requires", "host.json"), '{ "binaries": [] }\n');
    writeFileSync(join(dir, "skills", "area", "start.md"), `---\nid: area/start\ntitle: Start\nwhen: Always.\nneeds: []\ntools: []\nrequires_host: []\nrouter: true\n---\n\nBody.\n`);
    if (tool) {
      mkdirSync(join(dir, "tools", "echo_tool"), { recursive: true });
      writeFileSync(join(dir, "tools", "echo_tool", "manifest.json"), '{ "name": "echo_tool", "description": "Echo.", "params": { "text": { "type": "string" } }, "runtime": "python3", "entry": "run.py", "timeout_seconds": 10 }\n');
      writeFileSync(join(dir, "tools", "echo_tool", "run.py"), 'import json\nprint(json.dumps({"ok": True}))\n');
    }
    writeFileSync(
      join(dir, "pack.json"),
      JSON.stringify({ id, name: id, version: "1.0.0", description: "A pack for the suite.", licence: "AGPL-3.0-or-later", depends: [], requires: { host: "requires/host.json" }, secrets: secrets ? [{ name: "TEST_API_KEY", title: "A key", why: "For the suite.", required: false, hosts: ["api.example.test"] }] : [] }),
    );
    const sealed = spawnSync("bash", [join(ROOT, "scripts", "pack.sh"), "seal", dir], { encoding: "utf8", timeout: 120_000 });
    assert.equal(sealed.status, 0, sealed.stdout + sealed.stderr);
    const installed = spawnSync("bash", [join(ROOT, "scripts", "pack.sh"), "install", dir, "--yes"], { encoding: "utf8", timeout: 120_000, env: { ...process.env, DFIRSWARM_HOME: k.home, TEST_API_KEY: "test-value-not-a-secret" } });
    assert.equal(installed.status, 0, installed.stdout + installed.stderr);
  };
  make("keyed-test-pack", true, true);
  make("toolless-test-pack", false, false);
  refuse(["--isolation", "microvm", "--pack", "keyed-test-pack", "--pack-tools-as-jobs", "keyed-test-pack"], /keyed-test-pack, which declares secrets/, "secrets");
  refuse(["--isolation", "microvm", "--pack", "toolless-test-pack", "--pack-tools-as-jobs", "toolless-test-pack"], /toolless-test-pack, which carries no tool/, "toolless");
});

test("a resume keeps the mode the run started in: another list is refused, a run started without the option cannot take it, and one started with it keeps it", { skip: !linux, timeout: 600_000 }, () => {
  const k = kickoff();
  const first = k.start(["--isolation", "microvm", "--pack", PILOT, "--pack-tools-as-jobs", PILOT], "resumable");
  assert.equal(first.code, 0, first.out);
  const id = k.record("resumable").id as string;
  const resume = (extra: string[]) =>
    swarm(k.home, k.runs, ["start", "--model", "solo/model", "--provider-host", "solo=api.solo.example", "--n", "2", "--cap-usd", "1", "--no-start", "--goal-file", join(ROOT, "prompts", "goals", "hello.md"), "--toolbox", "off", "--workers", "1", "--vm-memory", "512", "--worker-memory", "512", "--isolation", "microvm", "--pack", PILOT, "--resume-of", id, ...extra]);
  const dropped = resume([]);
  assert.equal(dropped.code, 0, dropped.out);
  assert.match(dropped.out, new RegExp(`Pack tools:\\s+${PILOT}: run as jobs`), "the recorded mode is kept when the options omit it");
  assert.deepEqual(k.record("resumable").pack_tools_as_jobs, [PILOT]);
  const changed = resume(["--pack-tools-as-jobs", "computer-forensics-base"]);
  assert.equal(changed.code, 2, changed.out);
  assert.match(changed.out, /a resume keeps the way the run's tools are called/);

  const plain = k.start(["--isolation", "microvm", "--pack", PILOT], "plain-run");
  assert.equal(plain.code, 0, plain.out);
  const plainId = k.record("plain-run").id as string;
  const late = swarm(k.home, k.runs, ["start", "--model", "solo/model", "--provider-host", "solo=api.solo.example", "--n", "2", "--cap-usd", "1", "--no-start", "--goal-file", join(ROOT, "prompts", "goals", "hello.md"), "--toolbox", "off", "--workers", "1", "--vm-memory", "512", "--worker-memory", "512", "--isolation", "microvm", "--pack", PILOT, "--pack-tools-as-jobs", PILOT, "--resume-of", plainId]);
  assert.equal(late.code, 2, late.out);
  assert.match(late.out, /would leave them without those tools/);
});
