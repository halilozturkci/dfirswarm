/**
 * How the windows-forensics tools that run a program end it. The harness ends a tool that runs too long, or is aborted, by
 * killing the tool's process group (extensions/protocol-core.ts: process.kill(-pid, SIGKILL)); a program the tool started in a
 * session of its own is not in that group and goes on writing after the tool is gone (Zeek wrote conn.log six seconds after
 * its tool was killed). The five tools (esedb_query, extract_stream, sigma_hunt, vss_stores, yara_scan) share one process
 * block: the program stays in the tool's group, the kernel is asked to kill it with the tool, the tool's own deadline kills it
 * and what it started, and SIGTERM, SIGINT and SIGHUP do the same and leave a last word.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { withCwd } from "./tool-library-harness.ts";
import { AGENT, WIN, stub } from "./windows-pack-harness.ts";

const TOOLS = ["esedb_query", "extract_stream", "sigma_hunt", "vss_stores", "yara_scan"];

const stripped = (text: string): string => text.replace(/"""[\s\S]*?"""/g, "").replace(/^\s*#.*$/gm, "");
const block = (text: string): string => {
  const m = /# BEGIN SHARED PROCESS[\s\S]*?# END SHARED PROCESS/.exec(text);
  assert.ok(m, "the shared process block is there");
  return m[0];
};

test("the five tools carry one and the same process block, and no tool of the pack starts a program outside its own group", async () => {
  const copies = new Set<string>();
  for (const tool of TOOLS) copies.add(block(await readFile(join(WIN, tool, "run.py"), "utf8")));
  assert.equal(copies.size, 1, "the copies of the shared process block are equal");
  for (const tool of await readdir(WIN)) {
    const text = await readFile(join(WIN, tool, "run.py"), "utf8");
    const outside = stripped(TOOLS.includes(tool) ? text.replace(block(text), "") : text);
    assert.doesNotMatch(outside, /start_new_session|\bsetsid\b|preexec_fn|os\.setpgid|os\.setpgrp|killpg/, `${tool} starts or kills a program by a group of its own`);
  }
});

/** A tool started the way the harness starts one: in a process group of its own (`detached`), ended by killing that group. */
function startDetached(tool: string, cwd: string, args: unknown, env: Record<string, string>, bin: string) {
  const child = spawn("python3", [join(WIN, tool, "run.py")], {
    cwd,
    env: { ...process.env, PATH: `${bin}:${process.env.PATH ?? ""}`, ...AGENT, ...env },
    detached: true,
    stdio: ["pipe", "pipe", "pipe"],
  });
  const chunks: Buffer[] = [];
  child.stdout.on("data", (c: Buffer) => chunks.push(c));
  child.stderr.on("data", () => undefined);
  child.stdin.end(JSON.stringify(args));
  const closed = new Promise<number | null>((resolve) => child.on("close", (code) => resolve(code)));
  return {
    closed,
    stdout: () => Buffer.concat(chunks).toString("utf8"),
    killGroup: () => process.kill(-(child.pid as number), "SIGKILL"),
    signal: (sig: NodeJS.Signals) => process.kill(child.pid as number, sig),
  };
}

async function gone(pid: number, waitMs = 3000): Promise<boolean> {
  const until = Date.now() + waitMs;
  for (;;) {
    try {
      process.kill(pid, 0);
    } catch {
      return true;
    }
    if (Date.now() > until) return false;
    await new Promise((r) => setTimeout(r, 50));
  }
}

async function pidOf(path: string, waitMs = 8000): Promise<number> {
  const until = Date.now() + waitMs;
  for (;;) {
    const text = await readFile(path, "utf8").catch(() => "");
    if (text.trim()) return Number(text.trim());
    if (Date.now() > until) throw new Error(`no pid in ${path}`);
    await new Promise((r) => setTimeout(r, 50));
  }
}

function reap(...pids: number[]): void {
  for (const pid of pids) {
    try {
      process.kill(pid, "SIGKILL");
    } catch {
      /* gone */
    }
  }
}

/** The program a tool runs, as a stand-in that starts a child of its own and then waits for it, answering the probes quickly. */
const HANG = `echo $$ > "$PIDS/engine.pid"\nsleep 300 &\necho $! > "$PIDS/child.pid"\nwait`;
const PROBES: Record<string, string> = {
  esedb_query: `if [ "$1" = "-V" ]; then echo "esedbexport 20231020"; exit 0; fi\nroot="$2"; mkdir -p "$root.export"\n`,
  extract_stream: "",
  sigma_hunt: `case "$1" in --version|-V) echo "hayabusa 2.0"; exit 0;; esac\n`,
  vss_stores: "",
  yara_scan: `case "$1" in\n  --version) echo 4.5.8; exit 0;;\n  --help) printf '%s\\n' '  -s,  --print-strings   print matching strings' '  -L,  --print-string-length   print length of matched strings' '  -N,  --no-follow-symlinks   do not follow symlinks'; exit 0;;\nesac\n`,
};
const PROGRAM: Record<string, string> = { esedb_query: "esedbexport", extract_stream: "icat", sigma_hunt: "hayabusa", vss_stores: "vshadowinfo", yara_scan: "yara" };

async function prepare(tool: string, cwd: string, bin: string): Promise<{ args: Record<string, unknown>; pids: string }> {
  const pids = join(cwd, "pids");
  await mkdir(pids, { recursive: true });
  await stub(bin, PROGRAM[tool], `${PROBES[tool]}${HANG}`);
  await writeFile(join(cwd, "work", "input.bin"), "stand-in input\n");
  const args: Record<string, Record<string, unknown>> = {
    esedb_query: { path: "work/input.bin" },
    extract_stream: { image: "work/input.bin", inode: "5-128-1", offset: 0, output: "work/s1/stream.bin" },
    sigma_hunt: { path: "work/input.bin", out_dir: "work/s1/hunt" },
    vss_stores: { image: "work/input.bin" },
    yara_scan: { rules: "work/rules.yar", target: "work/input.bin" },
  };
  await writeFile(join(cwd, "work", "rules.yar"), "rule r { condition: true }\n");
  return { args: args[tool], pids };
}

for (const tool of TOOLS) {
  test(`${tool}: killing the tool's process group, as the harness does, ends the program and what it started`, async () => {
    await withCwd(async (cwd, bin) => {
      const { args, pids } = await prepare(tool, cwd, bin);
      const run = startDetached(tool, cwd, args, { PIDS: pids }, bin);
      const engine = await pidOf(join(pids, "engine.pid"));
      const child = await pidOf(join(pids, "child.pid"));
      try {
        run.killGroup();
        await run.closed;
        assert.ok(await gone(engine), "the program is gone with the tool");
        assert.ok(await gone(child), "what the program started is gone with it");
      } finally {
        reap(engine, child);
      }
    });
  });

  test(`${tool}: SIGTERM stops the program and what it started, and the tool says it was interrupted`, async () => {
    await withCwd(async (cwd, bin) => {
      const { args, pids } = await prepare(tool, cwd, bin);
      const run = startDetached(tool, cwd, args, { PIDS: pids }, bin);
      const engine = await pidOf(join(pids, "engine.pid"));
      const child = await pidOf(join(pids, "child.pid"));
      try {
        run.signal("SIGTERM");
        assert.equal(await run.closed, 143);
        const said = JSON.parse(run.stdout()) as { status: string; signal: number; error: string };
        assert.equal(said.status, "interrupted");
        assert.equal(said.signal, 15);
        assert.match(said.error, /stopped by signal 15/);
        assert.ok(await gone(engine), "the program is gone");
        assert.ok(await gone(child), "what it started is gone");
      } finally {
        reap(engine, child);
      }
    });
  });
}

for (const [name, sig, code] of [["SIGINT", "SIGINT", 130], ["SIGHUP", "SIGHUP", 129]] as const) {
  test(`${name} ends a tool the way SIGTERM does: the program and its child are killed and the exit status is 128 plus the signal`, async () => {
    await withCwd(async (cwd, bin) => {
      const { args, pids } = await prepare("extract_stream", cwd, bin);
      const run = startDetached("extract_stream", cwd, args, { PIDS: pids }, bin);
      const engine = await pidOf(join(pids, "engine.pid"));
      const child = await pidOf(join(pids, "child.pid"));
      try {
        run.signal(sig);
        assert.equal(await run.closed, code);
        assert.equal((JSON.parse(run.stdout()) as { status: string }).status, "interrupted");
        assert.ok(await gone(engine));
        assert.ok(await gone(child));
      } finally {
        reap(engine, child);
      }
    });
  });
}

const DEADLINE: Record<string, Record<string, unknown>> = {
  esedb_query: { export_timeout_seconds: 2 },
  extract_stream: { timeout_seconds: 2 },
  sigma_hunt: { timeout_seconds: 10 },
  yara_scan: { timeout_seconds: 2 },
};

for (const tool of Object.keys(DEADLINE)) {
  test(`${tool}: its own deadline kills the program and what it started`, async () => {
    await withCwd(async (cwd, bin) => {
      const { args, pids } = await prepare(tool, cwd, bin);
      const run = startDetached(tool, cwd, { ...args, ...DEADLINE[tool] }, { PIDS: pids }, bin);
      const engine = await pidOf(join(pids, "engine.pid"));
      const child = await pidOf(join(pids, "child.pid"));
      try {
        const started = Date.now();
        await run.closed;
        assert.ok(Date.now() - started < 30_000, "the tool ended at its own deadline");
        assert.ok(await gone(engine), "the program is gone");
        assert.ok(await gone(child), "what it started is gone");
      } finally {
        reap(engine, child);
      }
    });
  });
}

test("esedb_query makes again an export that a signal stopped, instead of handing the exporter a directory that exists", async () => {
  await withCwd(async (cwd, bin) => {
    const pids = join(cwd, "pids");
    await mkdir(pids, { recursive: true });
    await writeFile(join(cwd, "work", "WebCacheV01.dat"), "ESE stand-in");
    // libesedb refuses an export root that exists: a stopped export leaves one.
    const script = (rest: string) =>
      `if [ "$1" = "-V" ]; then echo "esedbexport 20231020"; exit 0; fi\nroot="$2"\nif [ -e "$root.export" ]; then echo "export path exists" >&2; exit 1; fi\nmkdir -p "$root.export"\n${rest}`;
    await stub(bin, "esedbexport", script(HANG));
    const first = startDetached("esedb_query", cwd, { path: "work/WebCacheV01.dat" }, { PIDS: pids }, bin);
    const engine = await pidOf(join(pids, "engine.pid"));
    const child = await pidOf(join(pids, "child.pid"));
    try {
      first.signal("SIGTERM");
      assert.equal(await first.closed, 143);
      await stub(bin, "esedbexport", script(`printf 'ContainerId\\tName\\n1\\tContent\\n' > "$root.export/Containers.4"\nexit 0`));
      const second = startDetached("esedb_query", cwd, { path: "work/WebCacheV01.dat" }, { PIDS: pids }, bin);
      assert.equal(await second.closed, 0, second.stdout());
      const out = JSON.parse(second.stdout()) as { status: string; exporter_exit_status: number; tables: string[] };
      assert.equal(out.exporter_exit_status, 0);
      assert.equal(out.status, "complete");
      assert.deepEqual(out.tables, ["Containers"]);
    } finally {
      reap(engine, child);
    }
  });
});

test("a timeout asked for above the tool's own limit is lowered below the manifest's, and the manifests say it", async () => {
  const limits: Record<string, [string, number, number]> = {
    esedb_query: ["export_timeout_seconds", 270, 300],
    extract_stream: ["timeout_seconds", 270, 300],
    sigma_hunt: ["timeout_seconds", 1000, 1200],
    yara_scan: ["timeout_seconds", 110, 120],
  };
  for (const [tool, [param, cap, manifestLimit]] of Object.entries(limits)) {
    const manifest = JSON.parse(await readFile(join(WIN, tool, "manifest.json"), "utf8")) as { timeout_seconds: number; params: Record<string, { description: string }> };
    assert.equal(manifest.timeout_seconds, manifestLimit, tool);
    assert.ok(cap < manifestLimit, tool);
    assert.match(manifest.params[param].description, new RegExp(`at most ${cap}`), `${tool}'s manifest states its cap`);
    const source = await readFile(join(WIN, tool, "run.py"), "utf8");
    assert.ok(new RegExp(`\\b${cap}\\b`).test(source), `${tool} enforces ${cap}`);
  }
});
