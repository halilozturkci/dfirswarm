/**
 * network-forensics, second round: a file that becomes a pipe is never waited on, a second stop signal during the stop answer starts no second
 * document, and a stop answer prints no token-shaped log name and only a bounded list of names.
 *
 *  - open_regular: every read of a path the caller or the engine supplied opens it without blocking and takes the type from the descriptor.
 *  - second_in_answer (tests/network-signal-inject.py): SIGTERM, SIGINT and SIGHUP in every pair, for the six tools and the recipe.
 *  - zeek_run: a stop while the engine's logs are on disk names no token-shaped log; a log set aside by name is fast.
 *  - suricata_run: the stop answer lists at most 200 files.
 * Every process a case starts is killed by the case if it outlives its limit; none is left behind.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdir, readFile, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { BEACON, EXTRACT, LOGS, RECIPE, SUMMARY, SURICATA, ZEEK, body, drop, frameTcp4, pcapClassic, put, startDetached, stub, tool, TCP, withCwd } from "./pack-network-harness.ts";
import { createRng, planted } from "./pack-network-canaries.ts";
import { ROOT } from "./tool-library-harness.ts";

const INJECT = join(ROOT, "tests", "network-signal-inject.py");
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Answer = Record<string, any>;

function documents(text: string): Answer[] {
  const found: Answer[] = [];
  let depth = 0, from = -1, inString = false, escaped = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inString) { if (escaped) escaped = false; else if (c === "\\") escaped = true; else if (c === '"') inString = false; continue; }
    if (c === '"') inString = true;
    else if (c === "{") { if (depth++ === 0) from = i; }
    else if (c === "}" && --depth === 0) found.push(JSON.parse(text.slice(from, i + 1)));
  }
  assert.equal(depth, 0, `the output ends inside a document: ${text.slice(-200)}`);
  return found;
}

/** The tool through the injector, killed by the case when it has not ended within `ms` (a hang is a failure, never a leftover). */
async function injected(script: string, point: string, cwd: string, args: unknown, env: Record<string, string>, ms = 20_000): Promise<{ hung: boolean; stdout: string; code: number | null }> {
  const run = startDetached(INJECT, cwd, args, { ...env, INJECT_TOOL: script, INJECT_POINT: point });
  let timer: NodeJS.Timeout | undefined;
  const watchdog = new Promise<"hung">((resolve) => { timer = setTimeout(() => resolve("hung"), ms); });
  try {
    const ended = await Promise.race([run.closed, watchdog]);
    return { hung: ended === "hung", stdout: run.stdout(), code: ended === "hung" ? null : ended };
  } finally {
    clearTimeout(timer);
    try { run.killGroup(); } catch { /* already gone */ }
  }
}

const mkfifo = (path: string): void => { assert.equal(spawnSync("mkfifo", [path]).status, 0); };

// --- open_regular ----------------------------------------------------------------------------------------------

const SCRIPTS: Array<[string, string]> = [
  ["pcap_summary", SUMMARY], ["network_log_summary", LOGS], ["pcap_extract", EXTRACT], ["suricata_run", SURICATA], ["zeek_run", ZEEK], ["network-capture recipe", RECIPE],
];

test("open_regular: a pipe is refused at once whatever the tool, a symbolic link is followed for a caller's path and refused for an engine's, a regular file reads", { timeout: 120_000 }, async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "plain", "hello");
    await symlink(join(cwd, "plain"), join(cwd, "link"));
    mkfifo(join(cwd, "pipe"));
    const code = `import errno, importlib.util, sys
spec = importlib.util.spec_from_file_location("t", sys.argv[1]); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
out = []
for name, follow in (("plain", True), ("plain", False), ("link", True), ("link", False), ("pipe", True), ("pipe", False)):
    try:
        with m.open_regular(sys.argv[2] + "/" + name, follow) as fh:
            out.append("%s:%s read %s" % (name, follow, fh.read(10).decode()))
    except OSError as exc:
        out.append("%s:%s %s" % (name, follow, errno.errorcode.get(exc.errno)))
print("|".join(out))
`;
    for (const [name, script] of SCRIPTS) {
      const run = spawnSync("python3", ["-c", code, script, cwd], { encoding: "utf8", timeout: 15_000 });
      assert.equal(run.error, undefined, `${name}: open_regular waited on a pipe`);
      assert.equal(run.stdout.trim(), "plain:True read hello|plain:False read hello|link:True read hello|link:False ELOOP|pipe:True EINVAL|pipe:False EINVAL", `${name}: ${run.stderr}`);
    }
    // the digest of an exported object that became a pipe
    const digest = spawnSync("python3", ["-c", `import importlib.util, sys
spec = importlib.util.spec_from_file_location("t", sys.argv[1]); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
try:
    m.file_digest(sys.argv[2])
    print("read")
except OSError as exc:
    print("refused", exc.errno)
`, EXTRACT, join(cwd, "pipe")], { encoding: "utf8", timeout: 15_000 });
    assert.equal(digest.error, undefined, "file_digest waited on a pipe");
    assert.equal(digest.stdout.trim(), "refused 22");
  });
});

test("a path that is a pipe when the tool opens it (isfile said yes a moment before) is a JSON refusal, not a hang: pcap_summary and network_log_summary", { timeout: 120_000 }, async () => {
  await withCwd(async (cwd) => {
    mkfifo(join(cwd, "pipe"));
    for (const [name, script, args] of [["pcap_summary", SUMMARY, { path: "pipe" }], ["network_log_summary", LOGS, { path: "pipe", out_dir: "work/s1/o" }]] as const) {
      const run = await injected(script, "isfile_true", cwd, args, { AGENT_ID: "s1", INJECT_ISFILE_SUFFIX: "pipe" });
      assert.equal(run.hung, false, `${name} waited for a writer of the pipe`);
      assert.equal(run.code, 1, run.stdout);
      const docs = documents(run.stdout);
      assert.equal(docs.length, 1);
      assert.equal(docs[0].status, "failed", name);
      assert.match(docs[0].error, /regular file|could not be opened/, name);
    }
  });
});

test("links to a regular file and to a pipe, one after the other, never hang pcap_summary", { timeout: 180_000 }, async () => {
  await withCwd(async (cwd) => {
    const real = await drop(cwd, "real.pcap", pcapClassic([{ sec: 1_771_070_000, frame: frameTcp4({ src: "10.0.0.1", dst: "10.0.0.2", sport: 1, dport: 2, flags: TCP.SYN }) }]));
    mkfifo(join(cwd, "pipe"));
    let hung = 0;
    for (let i = 0; i < 24; i++) {
      await symlink(i % 2 ? join(cwd, "pipe") : join(cwd, real), join(cwd, `p${i}`));
      const run = startDetached(SUMMARY, cwd, { path: `p${i}` });
      let timer: NodeJS.Timeout | undefined;
      const ended = await Promise.race([run.closed.then(() => "ended"), new Promise<string>((r) => { timer = setTimeout(() => r("hung"), 8000); })]);
      clearTimeout(timer);
      try { run.killGroup(); } catch { /* already gone */ }
      if (ended === "hung") hung += 1;
    }
    assert.equal(hung, 0, "a run waited for a writer of the pipe");
  });
});

// --- a second signal during the answer ------------------------------------------------------------------------------

const PAIRS: Array<[string, string]> = [];
for (const first of ["SIGTERM", "SIGINT", "SIGHUP"]) for (const second of ["SIGTERM", "SIGINT", "SIGHUP"]) PAIRS.push([first, second]);
const NUMBER: Record<string, number> = { SIGHUP: 1, SIGINT: 2, SIGTERM: 15 };

for (const [name, script] of [["zeek_run", ZEEK], ["suricata_run", SURICATA], ["pcap_extract", EXTRACT], ["network_log_summary", LOGS], ["pcap_summary", SUMMARY], ["beacon_score", BEACON], ["network-capture recipe", RECIPE]] as const) {
  test(`${name}: a second signal while the answer to the first is written starts no second document (all nine pairs)`, { timeout: 180_000 }, async () => {
    await withCwd(async (cwd) => {
      for (const [first, second] of PAIRS) {
        const run = await injected(script, "second_in_answer", cwd, {}, { AGENT_ID: "s1", INJECT_SIGNAL: first, INJECT_SECOND: second });
        assert.equal(run.hung, false, `${first} then ${second}`);
        const docs = documents(run.stdout);
        assert.equal(docs.length, 1, `${first} then ${second}: ${docs.length} documents: ${run.stdout.slice(0, 300)}`);
        assert.equal(run.code, 128 + NUMBER[first], `${first} then ${second}: exit status`);
        assert.equal(docs[0].interrupted_by_signal, NUMBER[first], `${first} then ${second}`);
      }
    });
  });
}

// --- zeek_run ------------------------------------------------------------------------------------------------------

const ZEEK_STUB = `#!/bin/sh
for a in "$@"; do
  case "$a" in
    --version) printf 'zeek version 8.0.10-stand-in\\n'; exit 0;;
  esac
done
[ -d "$STUB_DIR/logs" ] && cp -R "$STUB_DIR/logs/." .
[ -f "$STUB_DIR/fifo" ] && mkfifo evil.log
[ -f "$STUB_DIR/sleep" ] && { echo started > "$STUB_DIR/started"; sleep 120 & wait; }
exit 0
`;

const TSV = (path: string): string => ["#separator \\x09", "#set_separator\t,", "#empty_field\t(empty)", "#unset_field\t-", `#path\t${path}`, "#fields\tts\tx", "#types\ttime\tcount", "1700000000.0\t1", "#close\t2023-11-14-22-14-00"].join("\n") + "\n";

async function zeekStage(cwd: string, bin: string, names: string[], o: { sleep?: boolean; fifo?: boolean } = {}): Promise<Record<string, string>> {
  const dir = join(cwd, "stub");
  await mkdir(join(dir, "logs"), { recursive: true });
  await stub(bin, "zeek", ZEEK_STUB);
  for (const n of names) await writeFile(join(dir, "logs", `${n}.log`), TSV("x"));
  if (o.sleep) await writeFile(join(dir, "sleep"), "1");
  if (o.fifo) await writeFile(join(dir, "fifo"), "1");
  await put(cwd, "work/c.pcap", "not read by the stand-in");
  return { STUB_DIR: dir };
}

const hex = (rng: () => number, n: number): string => Array.from({ length: n }, () => "0123456789abcdef"[Math.floor(rng() * 16)]).join("");
const b64 = (rng: () => number, n: number): string => Array.from({ length: n }, () => "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"[Math.floor(rng() * 64)]).join("");

test("a stop while the engine's logs are on disk names no token-shaped log: six shapes, each word withheld, the list bounded", { timeout: 120_000 }, async () => {
  await withCwd(async (cwd, bin) => {
    const rng = createRng(Number(randomBytes(4).readUInt32LE(0)));
    const stems = [hex(rng, 40), hex(rng, 32), b64(rng, 43), planted(rng, "akia"), planted(rng, "ghp"), planted(rng, "jwt").replaceAll(".", "_"), "conn"];
    // the shapes the shared block withholds are the ones a normal run sets aside under a withheld name
    const normal = await zeekStage(cwd, bin, stems);
    const done = body(await tool(ZEEK, cwd, { path: "work/c.pcap", out_dir: "work/n" }, normal, bin));
    const secret = stems.filter((s) => !done.logs_written.includes(s));
    assert.ok(secret.length >= 3, `the block withholds ${secret.length} of the six shapes`);
    const slept = await zeekStage(cwd, bin, stems, { sleep: true });
    const run = startDetached(ZEEK, cwd, { path: "work/c.pcap", out_dir: "work/s" }, slept, bin);
    try {
      for (let i = 0; i < 100 && !(await readFile(join(cwd, "stub", "started"), "utf8").catch(() => "")); i++) await new Promise((r) => setTimeout(r, 100));
      run.signal("SIGTERM");
      assert.equal(await run.closed, 143);
    } finally {
      try { run.killGroup(); } catch { /* gone */ }
    }
    const text = run.stdout();
    for (const s of secret) assert.ok(!text.includes(s), "a token-shaped log name is printed by the stop answer");
    const docs = documents(text);
    assert.equal(docs.length, 1);
    assert.ok(docs[0].logs_written_so_far.includes("withheld"), JSON.stringify(docs[0].logs_written_so_far));
    assert.ok(docs[0].logs_written_so_far.includes("conn"));
    assert.equal(docs[0].logs_written_so_far_total, stems.length);
  });
});

test("a log the engine made a pipe is not waited on: the run ends, the log is a problem and nothing hangs", { timeout: 120_000 }, async () => {
  await withCwd(async (cwd, bin) => {
    const env = await zeekStage(cwd, bin, ["conn"], { fifo: true });
    const run = startDetached(ZEEK, cwd, { path: "work/c.pcap", out_dir: "work/f" }, env, bin);
    let timer: NodeJS.Timeout | undefined;
    const ended = await Promise.race([run.closed.then(() => "ended"), new Promise<string>((r) => { timer = setTimeout(() => r("hung"), 40_000); })]);
    clearTimeout(timer);
    try { run.killGroup(); } catch { /* gone */ }
    assert.equal(ended, "ended", "zeek_run waited for a writer of evil.log");
    const out = documents(run.stdout())[0];
    assert.ok(out.problems.some((p: Answer) => p.log === "evil"), JSON.stringify(out.problems));
    assert.equal(out.logs.conn.records.length, 1);
  });
});

test("two thousand logs with token-shaped names are set aside in seconds, every one under its own withheld name, with an index of two thousand lines", { timeout: 180_000 }, async () => {
  await withCwd(async (cwd, bin) => {
    const rng = createRng(Number(randomBytes(4).readUInt32LE(0)));
    const stems = Array.from({ length: 2000 }, () => planted(rng, "ghp"));
    const env = await zeekStage(cwd, bin, stems);
    const began = Date.now();
    const out = body(await tool(ZEEK, cwd, { path: "work/c.pcap", out_dir: "work/m", limit: 1 }, env, bin));
    const ms = Date.now() - began;
    assert.equal(out.log_names_withheld, 2000);
    assert.equal((await readFile(join(cwd, out.log_names_file), "utf8")).trimEnd().split("\n").length, 2000);
    assert.ok(ms < 60_000, `${ms} ms`);
  });
});

// --- suricata_run ------------------------------------------------------------------------------------------------------

const SURICATA_STUB = `#!/bin/sh
mode=run; logdir=""
while [ $# -gt 0 ]; do
  case "$1" in
    --build-info) printf 'This is Suricata version 7.0.0-stand-in RELEASE\\n'; exit 0;;
    -T) mode=test;;
    -l) logdir="$2"; shift;;
  esac
  shift
done
[ "$mode" = test ] && exit 0
[ -f "$STUB_DIR/many" ] && { i=0; while [ $i -lt 500 ]; do : > "$logdir/f$i.txt"; i=$((i+1)); done; }
[ -f "$STUB_DIR/fifo" ] && mkfifo "$logdir/eve.json"
[ -f "$STUB_DIR/sleep" ] && { echo started > "$STUB_DIR/started"; sleep 120 & wait; }
exit 0
`;

async function suricataStage(cwd: string, bin: string, flags: string[]): Promise<Record<string, string>> {
  const dir = join(cwd, "stub");
  await mkdir(dir, { recursive: true });
  await stub(bin, "suricata", SURICATA_STUB);
  for (const f of flags) await writeFile(join(dir, f), "1");
  await put(cwd, "work/c.pcap", "not read by the stand-in");
  await put(cwd, "work/case.rules", 'alert tcp any any -> any any (msg:"one"; sid:1000001; rev:1;)\n');
  return { STUB_DIR: dir };
}

test("the stop answer of suricata_run lists at most 200 files and says how many there are", { timeout: 120_000 }, async () => {
  await withCwd(async (cwd, bin) => {
    const env = await suricataStage(cwd, bin, ["many", "sleep"]);
    const run = startDetached(SURICATA, cwd, { path: "work/c.pcap", rules: "work/case.rules", out_dir: "work/s" }, env, bin);
    try {
      for (let i = 0; i < 100 && !(await readFile(join(cwd, "stub", "started"), "utf8").catch(() => "")); i++) await new Promise((r) => setTimeout(r, 100));
      run.signal("SIGTERM");
      assert.equal(await run.closed, 143);
    } finally {
      try { run.killGroup(); } catch { /* gone */ }
    }
    const docs = documents(run.stdout());
    assert.equal(docs.length, 1);
    assert.ok(docs[0].files_on_disk.length <= 200, `${docs[0].files_on_disk.length} names`);
    assert.ok(docs[0].files_on_disk_total >= 500);
    assert.match(docs[0].files_on_disk_note, /first 200 names/);
  });
});

test("an eve.json that is a pipe by the time it is opened is a JSON refusal, not a wait for a writer", { timeout: 120_000 }, async () => {
  await withCwd(async (cwd, bin) => {
    const env = await suricataStage(cwd, bin, ["fifo"]);
    const run = await injected(SURICATA, "isfile_true", cwd, { path: "work/c.pcap", rules: "work/case.rules", out_dir: "work/e" }, { ...env, AGENT_ID: "s1", PATH: `${bin}:${process.env.PATH}`, INJECT_ISFILE_SUFFIX: "eve.json" }, 40_000);
    assert.equal(run.hung, false, "suricata_run waited for a writer of eve.json");
    assert.equal(run.code, 1, run.stdout);
    assert.match(documents(run.stdout)[0].error, /eve\.json is not a regular file/);
  });
});


// --- network_log_summary: the values file ------------------------------------------------------------------------------

test("a stop just after the values file is made leaves no values file: it is registered with the stop signals held", { timeout: 60_000 }, async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/l.log", '10.0.0.1 - - [10/Oct/2026:13:55:36 +0000] "GET /a HTTP/1.1" 200 5 "-" "ua"\n');
    await mkdir(join(cwd, "out"), { recursive: true });
    const env = { AGENT_ID: "s1", JOB_ID: "j000001", OUT: join(cwd, "out"), SECRET_OUTPUT: "1" };
    const run = await injected(LOGS, "after_values_open", cwd, { path: "inputs/l.log", out_dir: "out/o", write_values: true }, env);
    assert.equal(run.hung, false);
    assert.equal(run.code, 143, run.stdout);
    assert.equal(documents(run.stdout).length, 1);
    assert.equal(spawnSync("test", ["-e", join(cwd, "out", "network-log-values.jsonl")]).status, 1, "an empty values file is left behind");
  });
});
