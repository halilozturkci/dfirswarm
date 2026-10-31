/**
 * encrypted-containers P3 residuals (ENC-07/08/09/10, RE-03's pager half): a symlinked tool-output, work/ or agent
 * directory is refused by name, nothing written through it; a huge flat directory is walked in bounded memory and
 * named within the stop's grace; `limit` has a ceiling; a 7z listing ends when 7z itself ends, not when a child it
 * forked lets go of the pipe. Every case here fails on the tools as they were before this round.
 */
import assert from "node:assert/strict";
import { chmod, mkdir, readdir, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { ROOT, runPy, runPySnippet, withCwd } from "./tool-library-harness.ts";

const ENC = join(ROOT, "packs", "encrypted-containers", "tools");
const SCAN = join(ENC, "recovery_key_scan", "run.py");
const PROBE = join(ENC, "archive_probe", "run.py");
const AGENT = { AGENT_ID: "s1" };

type Run = { code: number | null; stdout: string; stderr: string };
type Json = Record<string, any>;

async function tool(script: string, cwd: string, args: unknown, env: Record<string, string> = {}, bin?: string): Promise<Run> {
  return runPy(script, cwd, args, bin, { ...AGENT, ...env });
}

function body(out: Run): Json {
  assert.equal(out.code, 0, out.stderr + out.stdout);
  assert.doesNotMatch(out.stderr, /Traceback/);
  return JSON.parse(out.stdout) as Json;
}

// --- ENC-07 / RE-03: a symlinked tool-output, work/ or agent directory is refused -------------------------------

// A well-formed BitLocker recovery password (eight groups of six digits, each divisible by 11): one per file, so
// five files give five findings, which overflows limit: 1 and forces the findings page to write to tool-output.
const QUOTIENTS = [4103, 51234, 7, 65535, 12345, 999, 40000, 20202];
const RECOVERY_KEY = QUOTIENTS.map((q) => String(q * 11).padStart(6, "0")).join("-");

test("recovery_key_scan refuses a symlinked tool-output directory outside a job: nothing is written through it, and the answer fails loudly rather than guessing a location", async () => {
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "work", "ev"), { recursive: true });
    for (let i = 0; i < 5; i++) await writeFile(join(cwd, "work", "ev", `k${i}.txt`), `${RECOVERY_KEY}\n`);
    await mkdir(join(cwd, "elsewhere"), { recursive: true });
    await mkdir(join(cwd, "work", "s1"), { recursive: true });
    await symlink(join(cwd, "elsewhere"), join(cwd, "work", "s1", "tool-output"));
    const out = await tool(SCAN, cwd, { path: "work/ev", limit: 1 });
    assert.equal(out.code, 1, out.stdout + out.stderr);
    const a = JSON.parse(out.stdout) as Json;
    assert.deepEqual(await readdir(join(cwd, "elsewhere")), []);
    assert.equal(a.status, "failed");
    assert.match(a.error, /is a symbolic link: refused, nothing written through it/);
  });
});

test("recovery_key_scan refuses a symlinked work/ directory itself (not just tool-output)", async () => {
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "ev"), { recursive: true });
    for (let i = 0; i < 5; i++) await writeFile(join(cwd, "ev", `k${i}.txt`), `${RECOVERY_KEY}\n`);
    await mkdir(join(cwd, "elsewhere-work"), { recursive: true });
    await rm(join(cwd, "work"), { recursive: true, force: true }); // withCwd made a real work/; replace it with the link
    await symlink(join(cwd, "elsewhere-work"), join(cwd, "work"));
    const out = await tool(SCAN, cwd, { path: "ev", limit: 1 });
    assert.equal(out.code, 1, out.stdout + out.stderr);
    const a = JSON.parse(out.stdout) as Json;
    assert.match(a.error, /is a symbolic link: refused, nothing written through it/);
    assert.deepEqual(await readdir(join(cwd, "elsewhere-work")), []);
  });
});

test("recovery_key_scan refuses a symlinked agent directory under work/ too", async () => {
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "ev"), { recursive: true });
    for (let i = 0; i < 5; i++) await writeFile(join(cwd, "ev", `k${i}.txt`), `${RECOVERY_KEY}\n`);
    await mkdir(join(cwd, "elsewhere-agent"), { recursive: true });
    await mkdir(join(cwd, "work"), { recursive: true });
    await symlink(join(cwd, "elsewhere-agent"), join(cwd, "work", "s1"));
    const out = await tool(SCAN, cwd, { path: "ev", limit: 1 });
    assert.equal(out.code, 1, out.stdout + out.stderr);
    const a = JSON.parse(out.stdout) as Json;
    assert.match(a.error, /is a symbolic link: refused, nothing written through it/);
    assert.deepEqual(await readdir(join(cwd, "elsewhere-agent")), []);
  });
});

test("recovery_key_scan's write_values (secret_output) refuses a symlinked \\$OUT directory structure too", async () => {
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "ev"), { recursive: true });
    await writeFile(join(cwd, "ev", "k0.txt"), `${RECOVERY_KEY}\n`);
    const realOut = join(cwd, "real-out");
    await mkdir(realOut, { recursive: true });
    const outDir = join(cwd, "out-link");
    await symlink(realOut, outDir);
    const out = await tool(SCAN, cwd, { path: "ev", write_values: true }, { JOB_ID: "j000001", OUT: outDir, SECRET_OUTPUT: "1" });
    // $OUT itself is a link: own_dir's walk starts at the first component after $OUT, which here is $OUT's own
    // last path segment, so this is refused the same way: nothing is written through the link.
    assert.equal(out.code, 1, out.stdout + out.stderr);
  });
});

const MAKE_ZIP = String.raw`
import sys, zipfile
path, n = sys.argv[1], int(sys.argv[2])
with zipfile.ZipFile(path, "w") as z:
    for i in range(n):
        z.writestr("m%d.txt" % i, "member %d\n" % i)
`;

test("archive_probe refuses a symlinked $OUT/tool-output directory in a job: nothing is written through it", async () => {
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "out"), { recursive: true });
    await mkdir(join(cwd, "elsewhere"), { recursive: true });
    await symlink(join(cwd, "elsewhere"), join(cwd, "out", "tool-output"));
    const zipPath = join(cwd, "work", "many.zip");
    await mkdir(join(cwd, "work"), { recursive: true });
    const made = await runPySnippet(MAKE_ZIP, [zipPath, "4"], null);
    assert.equal(made.code, 0, made.stderr);
    const out = await tool(PROBE, cwd, { path: "work/many.zip", limit: 1 }, { JOB_ID: "j000001", OUT: join(cwd, "out") });
    assert.equal(out.code, 1, out.stdout + out.stderr);
    const a = JSON.parse(out.stdout) as Json;
    assert.deepEqual(await readdir(join(cwd, "elsewhere")), []);
    assert.equal(a.status, "failed");
    assert.match(a.error, /is a symbolic link: refused, nothing written through it/);
  });
});

// --- ENC-08: a huge flat directory is walked in bounded memory, and a stop names the unreached part within the grace ---

const CHUNKED_WALK = String.raw`
import json, os, resource, subprocess, sys, time
call = json.load(sys.stdin)
t0 = time.time()
rss0 = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
p = subprocess.run(["python3", sys.argv[1]], input=json.dumps(call["args"]).encode(), capture_output=True, cwd=sys.argv[2],
                    env={**os.environ, "AGENT_ID": "s1", **call.get("env", {})})
u = resource.getrusage(resource.RUSAGE_CHILDREN)
try:
    out = json.loads(p.stdout)
except ValueError:
    out = None
print(json.dumps({"code": p.returncode, "wall": time.time() - t0, "out": out, "err": p.stderr.decode()[-800:], "max_rss_kb": u.ru_maxrss - rss0}))
`;

const MAKE_FLAT_DIR = String.raw`
import os, sys
d, n = sys.argv[1], int(sys.argv[2])
os.makedirs(d, exist_ok=True)
for i in range(n):
    os.close(os.open(os.path.join(d, "f%07d.txt" % i), os.O_CREAT | os.O_WRONLY, 0o644))
print("done")
`;

test("recovery_key_scan walks 600,000 files in one directory with bounded memory, and max_seconds: 1 still answers partial with coverage inside the stop's grace", { timeout: 120_000 }, async () => {
  await withCwd(async (cwd) => {
    const flat = join(cwd, "work", "flat");
    const made = await runPySnippet(MAKE_FLAT_DIR, [flat, "600000"], null);
    assert.equal(made.code, 0, made.stderr);

    const run = await runPySnippet(CHUNKED_WALK, [SCAN, cwd], { args: { path: "work/flat", max_seconds: 1 } });
    assert.equal(run.code, 0, run.stderr);
    const { out, wall, max_rss_kb } = JSON.parse(run.stdout) as { out: Json; wall: number; max_rss_kb: number };
    assert.ok(out, "the tool answered valid JSON");
    assert.equal(out.status, "partial");
    // Full coverage within the grace: the whole call, including making the flat directory's dentries visible to the
    // kernel cache, finishes well inside max_seconds (1s) plus the stop's grace (GRACE_SECONDS, 5s) plus slack.
    assert.ok(wall < 20, `wall clock was ${wall}s`);
    assert.ok(out.coverage.directories_not_entered >= 1 || out.coverage.entries_not_started >= 1, JSON.stringify(out.coverage));
    // RSS stays far below the ~208 MB a whole sorted(scandir()) of 600,000 entries held (the historical finding this fixes).
    assert.ok(max_rss_kb < 120_000, `max RSS was ${max_rss_kb} KB`);
  });
});

// --- ENC-09: limit has a ceiling -----------------------------------------------------------------------------------

test("limit is refused past its ceiling, in both manifests", async () => {
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "work", "ev"), { recursive: true });
    await writeFile(join(cwd, "work", "ev", "a.txt"), "nothing here\n");
    await writeFile(join(cwd, "work", "ev", "z.7z"), Buffer.from("7z\xbc\xaf\x27\x1c" + "\0".repeat(26), "binary"));
    const cases: Array<[string, { path: string; limit: number }]> = [
      [SCAN, { path: "work/ev", limit: 10 ** 9 }], [SCAN, { path: "work/ev", limit: 1000 }],
      [PROBE, { path: "work/ev/z.7z", limit: 10 ** 9 }],
    ];
    for (const [script, args] of cases) {
      const out = await tool(script, cwd, args, {});
      if (args.limit > 1000) {
        assert.notEqual(out.code, 0, out.stdout);
        const e = JSON.parse(out.stdout) as Json;
        assert.match(e.error, /limit must be an integer from 1 to 1000/);
      } else {
        body(out); // 1000 itself is accepted
      }
    }
  });
});

// --- ENC-10: a 7z listing ends when 7z itself ends, not when a child it forked lets go of the pipe ----------------

const FORKING_7Z = [
  "#!/bin/sh",
  'case "$1" in',
  '  --version) echo "7-Zip stub"; exit 0 ;;',
  "esac",
  "cat <<'EOF'",
  "",
  "7-Zip stub",
  "",
  "Scanning the drive for archives:",
  "1 file, 100 bytes",
  "",
  "Listing archive: fake.7z",
  "",
  "--",
  "Path = fake.7z",
  "Type = 7z",
  "Physical Size = 100",
  "",
  "----------",
  "Path = member1.txt",
  "Size = 10",
  "Packed Size = 10",
  "Modified = 2020-01-01 00:00:00",
  "Attributes = A",
  "CRC = 00000000",
  "Encrypted = -",
  "Method = Copy",
  "EOF",
  // Fork a detached grandchild that inherits the stdout pipe and holds it open long after this script exits.
  '(sleep 20 &) ',
  'sh -c \'sleep 20 & echo $! > "$GRANDCHILD_PID_FILE"\'',
  "exit 0",
].join("\n");

test("archive_probe's 7z listing ends when 7z itself ends, not when a forked grandchild lets go of the pipe; the grandchild is reaped", { timeout: 60_000 }, async () => {
  const { spawn } = await import("node:child_process");
  await withCwd(async (cwd, bin) => {
    const path = join(bin, "7z");
    await writeFile(path, FORKING_7Z, "utf8");
    await chmod(path, 0o755);
    // 100 bytes, matching the stub's claimed "Physical Size = 100": archive_probe checks the 7z-reported physical
    // size plus offset against the file's real size and rejects a mismatch as "not the whole 7z".
    await writeFile(join(cwd, "work", "fake.7z"), Buffer.from("7z\xbc\xaf\x27\x1c" + "\0".repeat(94), "binary"));
    const pidFile = join(cwd, "grandchild.pid");
    const env = { ...process.env, ...AGENT, GRANDCHILD_PID_FILE: pidFile, PATH: `${bin}:${process.env.PATH}` };
    // reap_orphans only acts when the tool leads its own process group (as the harness starts it): spawn it detached,
    // the way tests/pack-shared-process.test.ts's own harness check does, not through the plain tool() helper.
    const t0 = Date.now();
    const child = spawn("python3", [PROBE], { cwd, env, detached: true, stdio: ["pipe", "pipe", "pipe"] });
    const chunks: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => chunks.push(c));
    child.stdin.end(JSON.stringify({ path: "work/fake.7z", max_seconds: 30 }));
    const code = await new Promise<number | null>((resolve) => child.on("exit", (c) => resolve(c)));
    const wall = (Date.now() - t0) / 1000;
    assert.equal(code, 0);
    const a = JSON.parse(Buffer.concat(chunks).toString("utf8")) as Json;
    assert.equal(a.status, "complete");
    assert.equal(a.listing.status, "listed");
    assert.equal(a.listing.via, "7z");
    // The fix: the tool does not wait out max_seconds (30s) or the 7z-level SEVENZIP_TIMEOUT (60s) for the pipe to
    // reach EOF on its own; it ends within roughly PIPE_GRACE of 7z's own exit.
    assert.ok(wall < 15, `wall clock was ${wall}s: the read waited for the grandchild's pipe instead of 7z's own end`);
    const pid = Number((await readFile(pidFile, "utf8")).trim());
    await new Promise((r) => setTimeout(r, 500));
    let alive = true;
    try {
      process.kill(pid, 0);
    } catch {
      alive = false;
    }
    assert.equal(alive, false, "the grandchild that held the pipe was reaped with the tool, not left running");
  });
});
