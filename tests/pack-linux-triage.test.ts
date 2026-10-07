/**
 * The Linux pack: linux_triage and the linux-target recipe, against a target-query stand-in that answers per
 * function as the test configures it.
 * Every fixture is built by the test from the format's own layout, never from a tool's output.
 */
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { chmod, mkdir, readFile, realpath, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { test } from "node:test";
import { AGENT, IS_ROOT, RECIPE, TRIAGE, asJob, body, exists, lines, refused, tool, withCwd } from "./linux-pack-harness.ts";
import type { Json } from "./linux-pack-harness.ts";

async function targetQueryStub(bin: string): Promise<void> {
  const path = join(bin, "target-query");
  await writeFile(
    path,
    `#!/usr/bin/env python3
import json, os, sys, time
conf = json.load(open(os.environ["STUB_CONF"]))
args = sys.argv[1:]
funcs = args[args.index("-f") + 1].split(",")
open(os.environ["STUB_LOG"], "a").write(json.dumps(args) + "\\n")
code = 0
for fn in funcs:
    b = conf.get(fn, {})
    time.sleep(b.get("sleep", 0))
    if b.get("stderr"):
        sys.stderr.write(b["stderr"] + "\\n")
    for i in range(b.get("records", 1)):
        print(json.dumps({"fn": fn, "i": i}) if "-j" in args else "value-%s-%d" % (fn, i))
    if b.get("junk"):
        print(b["junk"])
    code = code or b.get("exit", 0)
sys.exit(code)
`,
  );
  await chmod(path, 0o755);
}

async function triageFixture(cwd: string, bin: string, conf: Record<string, unknown>): Promise<Record<string, string>> {
  await targetQueryStub(bin);
  await writeFile(join(cwd, "inputs", "server.E01"), "image bytes\n");
  await writeFile(join(cwd, "stub-conf.json"), JSON.stringify(conf));
  return { STUB_CONF: join(cwd, "stub-conf.json"), STUB_LOG: join(cwd, "stub-log.txt") };
}

const ALL_FUNCTIONS = [
  "os", "hostname", "version", "ips", "users", "wtmp", "btmp", "lastlog", "authlog", "bashhistory", "cronjobs", "services",
  "dpkg.status", "packagemanager.logs", "ssh.authorized_keys", "ssh.known_hosts", "ssh.public_keys", "journal", "syslog", "webserver.logs", "container.logs",
];

test("linux_triage tells a function the target does not support from a clean run, though the process exits 0", async () => {
  await withCwd(async (cwd, bin) => {
    const env = await triageFixture(cwd, bin, { "webserver.logs": { records: 0, stderr: "WARNING | webserver.logs: plugin not available for this target" }, lastlog: { records: 0 } });
    const out = body(await tool(TRIAGE, cwd, { source: "inputs/server.E01", out_dir: "work/triage", groups: ["web", "sessions", "users"] }, env, bin));
    assert.equal(out.execution_complete, true, "every process exited 0");
    const group = (name: string): Json => out.groups.find((g: Json) => g.group === name);
    assert.equal(group("web").status, "unsupported");
    assert.equal(group("web").functions[0].status, "unsupported");
    assert.equal(group("users").status, "produced_records");
    assert.equal(group("users").functions[0].status, "parsed");
    const sessions = Object.fromEntries(group("sessions").functions.map((f: Json) => [f.name, f.status]));
    assert.deepEqual(sessions, { wtmp: "parsed", btmp: "parsed", lastlog: "empty" });
    assert.equal(out.coverage.unsupported, 1);
    assert.equal(out.coverage.parsed, 3);
    assert.equal(out.coverage.empty, 1);
    assert.equal("complete" in out, false, "no field calls the run complete on the strength of exit codes");
    assert.match(out.coverage.note, /not established|does not establish/);
    // The answer names the exact functions each family selects.
    assert.deepEqual(group("sessions").functions.map((f: Json) => f.name), ["wtmp", "btmp", "lastlog"]);
    assert.match(group("sessions").covers, /classic/i);
  });
});

test("linux_triage reads an empty `groups` as a mistake, a repeated one as a mistake, and no `groups` as every family", async () => {
  await withCwd(async (cwd, bin) => {
    const env = await triageFixture(cwd, bin, {});
    assert.match(refused(await tool(TRIAGE, cwd, { source: "inputs/server.E01", out_dir: "work/t1", groups: [] }, env, bin)).error, /empty|omit/);
    assert.match(refused(await tool(TRIAGE, cwd, { source: "inputs/server.E01", out_dir: "work/t2", groups: ["users", "users"] }, env, bin)).error, /more than once|duplicate/i);
    assert.match(refused(await tool(TRIAGE, cwd, { source: "inputs/server.E01", out_dir: "work/t3", groups: ["nope"] }, env, bin)).error, /known/);
    assert.equal(await exists(env.STUB_LOG), false, "nothing ran for a refused request");
    const all = body(await tool(TRIAGE, cwd, { source: "inputs/server.E01", out_dir: "work/t4" }, env, bin));
    assert.equal(all.groups.length, 11);
    const called = (await readFile(env.STUB_LOG, "utf8")).trim().split("\n").map((l) => (JSON.parse(l) as string[])[(JSON.parse(l) as string[]).indexOf("-f") + 1]).sort();
    assert.deepEqual(called, [...ALL_FUNCTIONS].sort(), "each function once");
  });
});

test("linux_triage starts a function only if the time left covers its own timeout, and names the ones it did not start as not attempted, not failed", async () => {
  await withCwd(async (cwd, bin) => {
    // 7 s in all, 3 s for a function: users takes 2 s (5 s left), bashhistory is started and cut off at its own 3 s (2 s left),
    // and the 2 s left do not cover the 3 s a function may take, so webserver.logs is not started.
    const env = await triageFixture(cwd, bin, { users: { sleep: 2 }, bashhistory: { sleep: 30 } });
    const started = Date.now();
    const out = body(await tool(TRIAGE, cwd, { source: "inputs/server.E01", out_dir: "work/triage", groups: ["users", "history", "web"], timeout_seconds: 3, total_timeout_seconds: 7 }, env, bin));
    assert.ok(Date.now() - started < 20_000, "the deadline held");
    const fn = (name: string): Json => out.groups.flatMap((g: Json) => g.functions).find((f: Json) => f.name === name);
    assert.equal(fn("users").status, "parsed");
    assert.equal(fn("bashhistory").status, "failed");
    assert.equal(fn("bashhistory").timed_out, true);
    assert.equal(fn("bashhistory").deadline, "function", "a function is never cut by the total deadline: it is not started when that would be");
    assert.equal(fn("webserver.logs").status, "not_attempted");
    assert.match(fn("webserver.logs").reason, /less than this function's own timeout/);
    assert.equal(out.execution_complete, false);
    assert.equal(out.coverage.not_attempted, 1);
    assert.equal(out.coverage.failed, 1);
    assert.equal(out.status, "partial");
    assert.match(out.status_basis, /1 failed, 1 not_attempted/);
    assert.equal((await readFile(env.STUB_LOG, "utf8")).includes("webserver.logs"), false, "it was never started");
    const summary = JSON.parse(await readFile(join(cwd, "work", "triage", "summary.json"), "utf8"));
    assert.equal(summary.state, "finished");
    assert.equal(summary.coverage.not_attempted, 1);
    assert.equal(summary.status, "partial");
  });
});

test("linux_triage leaves a durable summary after each function, so a run killed in the middle still says what it had done", async () => {
  await withCwd(async (cwd, bin) => {
    const env = await triageFixture(cwd, bin, { users: { sleep: 0 }, bashhistory: { sleep: 8 } });
    const child = spawn("python3", [TRIAGE], { cwd, env: { ...process.env, ...env, ...AGENT, PATH: `${bin}:${process.env.PATH ?? ""}` }, detached: true, stdio: ["pipe", "pipe", "pipe"] });
    child.stdin.end(JSON.stringify({ source: "inputs/server.E01", out_dir: "work/triage", groups: ["users", "history"] }));
    const summaryPath = join(cwd, "work", "triage", "summary.json");
    let summary: Json = null;
    for (let i = 0; i < 100 && !summary; i++) {
      await new Promise((r) => setTimeout(r, 100));
      summary = await readFile(summaryPath, "utf8").then((t) => JSON.parse(t), () => null);
      if (summary && !summary.groups?.some((g: Json) => g.functions.some((f: Json) => f.name === "users" && f.status === "parsed"))) summary = null;
    }
    process.kill(-(child.pid as number), "SIGKILL");
    assert.ok(summary, "a summary with the first function done exists while the second runs");
    assert.equal(summary.state, "running");
    const history = summary.groups.find((g: Json) => g.group === "history");
    assert.ok(history, "the family being run is in it, as running");
    assert.equal(history.functions[0].status, "running");
  });
});

test("linux_triage counts the lines of a result that are no JSON, and hashes what it wrote", async () => {
  await withCwd(async (cwd, bin) => {
    const env = await triageFixture(cwd, bin, { users: { records: 3, junk: "{not json" } });
    const out = body(await tool(TRIAGE, cwd, { source: "inputs/server.E01", out_dir: "work/triage", groups: ["users"] }, env, bin));
    const [fn] = out.groups[0].functions;
    assert.equal(fn.records, 3);
    assert.equal(fn.invalid_lines, 1);
    assert.equal(fn.status, "unknown", "a result with a line that is no JSON is not called parsed");
    const text = await readFile(join(cwd, out.groups[0].file), "utf8");
    assert.equal(out.groups[0].sha256, createHash("sha256").update(text).digest("hex"));
  });
});

function recipe(cwd: string, bin: string, env: Record<string, string>, ...args: string[]): ReturnType<typeof spawnSync> {
  return spawnSync("python3", [RECIPE, ...args], { cwd, env: { ...process.env, ...env, PATH: `${bin}:${process.env.PATH ?? ""}` }, encoding: "utf8" });
}

test("the linux-target recipe says it could not tell, with exit 2, where it did not read the OS, and not Linux where it read another", async () => {
  await withCwd(async (cwd, bin) => {
    await writeFile(join(cwd, "inputs", "x.E01"), "bytes");
    await writeFile(join(cwd, "target.json"), JSON.stringify({ paths: [join(cwd, "inputs", "x.E01")], name: "x" }));
    const stub = (script: string): Promise<void> => writeFile(join(bin, "target-query"), `#!/usr/bin/env python3\n${script}\n`).then(() => chmod(join(bin, "target-query"), 0o755));
    const answer = (r: ReturnType<typeof spawnSync>): Json => JSON.parse(String(r.stdout).trim().split("\n").pop() ?? "{}");
    await stub('print("linux")');
    let r = recipe(cwd, bin, {}, "detect", "--target", join(cwd, "target.json"));
    assert.equal(r.status, 0);
    assert.equal(answer(r).applies, true);
    await stub('print("windows")');
    r = recipe(cwd, bin, {}, "detect", "--target", join(cwd, "target.json"));
    assert.equal(r.status, 1, "a typed answer naming another system is a no");
    assert.equal(answer(r).applies, false);
    // A name this recipe does not know is not a no: it could be a Linux the reader did not call by that name.
    for (const text of ["android-linux-ish-nonsense", "unix", "debian", "a linux box", "Ubuntu 22.04 linux"]) {
      await stub(`print(${JSON.stringify(text)})`);
      r = recipe(cwd, bin, {}, "detect", "--target", join(cwd, "target.json"));
      assert.equal(r.status, 2, text);
      assert.equal(answer(r).applies, "unknown", text);
      assert.equal(answer(r).status, "failed", text);
    }
    // The name is read as a value, not as a word among others: a hostname called linux is not the OS.
    await stub(`import json\nprint(json.dumps({"os": "windows", "hostname": "linux"}))`);
    r = recipe(cwd, bin, {}, "detect", "--target", join(cwd, "target.json"));
    assert.equal(r.status, 1);
    assert.equal(answer(r).applies, false);
    await stub(`import json\nprint(json.dumps({"os": "Linux"}))`);
    r = recipe(cwd, bin, {}, "detect", "--target", join(cwd, "target.json"));
    assert.equal(r.status, 0);
    assert.equal(answer(r).status, "complete");
    assert.match(answer(r).why, /unverified/);
    await stub(`import json\nprint(json.dumps({"hostname": "linux"}))`);
    assert.equal(recipe(cwd, bin, {}, "detect", "--target", join(cwd, "target.json")).status, 2, "no os field names no OS");
    await stub('print("freebsd")');
    assert.equal(recipe(cwd, bin, {}, "detect", "--target", join(cwd, "target.json")).status, 1);
    await stub("");
    r = recipe(cwd, bin, {}, "detect", "--target", join(cwd, "target.json"));
    assert.equal(r.status, 2, "an empty answer identifies nothing");
    assert.equal(answer(r).applies, "unknown");
    await stub('import sys\nsys.stderr.write("Failed to open target\\n")\nsys.exit(1)');
    r = recipe(cwd, bin, {}, "detect", "--target", join(cwd, "target.json"));
    assert.equal(r.status, 2);
    assert.equal(answer(r).applies, "unknown");
    assert.match(answer(r).why, /Failed to open target/);
    await stub("import time\ntime.sleep(30)");
    r = recipe(cwd, bin, { LINUX_TARGET_DETECT_SECONDS: "1" }, "detect", "--target", join(cwd, "target.json"));
    assert.equal(r.status, 2, "a detection that timed out has not closed the route");
    assert.equal(answer(r).applies, "unknown");
    assert.match(answer(r).why, /did not identify the OS/);
    // No reader at all: the route is not closed either.
    r = spawnSync("python3", [RECIPE, "detect", "--target", join(cwd, "target.json")], { cwd, env: { ...process.env, PATH: "/usr/bin:/bin" }, encoding: "utf8" });
    if (!(await exists("/usr/bin/target-query")) && !(await exists("/bin/target-query"))) {
      assert.equal(r.status, 2);
      assert.match(answer(r).why, /is not in this image/);
    }
  });
});

test("the linux-target recipe's coverage follows what each function produced, not the exit codes, and survives an early end", async () => {
  await withCwd(async (cwd, bin) => {
    const env = await triageFixture(cwd, bin, { ...Object.fromEntries(ALL_FUNCTIONS.map((f) => [f, { records: 2 }])), "webserver.logs": { records: 0, stderr: "WARNING | webserver.logs: plugin not available" } });
    await writeFile(join(cwd, "target.json"), JSON.stringify({ paths: [join(cwd, "inputs", "server.E01")], name: "server" }));
    const r = recipe(cwd, bin, env, "run", "--target", join(cwd, "target.json"), "--out", join(cwd, "recipe-out"));
    assert.equal(r.status, 0, String(r.stderr));
    const coverage = JSON.parse(await readFile(join(cwd, "recipe-out", "coverage.json"), "utf8"));
    assert.equal(coverage.status, "partial", "a function the target does not support makes the catalogue partial though every process exited 0");
    assert.equal(coverage.functions.unsupported, 1);
    assert.ok(coverage.errors.some((e: string) => /webserver\.logs/.test(e)));
    assert.match(coverage.covered, /selected/);
    // Every function produced: complete over the selected functions, and says only that.
    await writeFile(join(cwd, "stub-conf.json"), JSON.stringify(Object.fromEntries(ALL_FUNCTIONS.map((f) => [f, { records: 1 }]))));
    const ok = recipe(cwd, bin, env, "run", "--target", join(cwd, "target.json"), "--out", join(cwd, "recipe-out2"));
    assert.equal(ok.status, 0);
    const done = JSON.parse(await readFile(join(cwd, "recipe-out2", "coverage.json"), "utf8"));
    assert.equal(done.status, "complete");
    assert.match(done.not_covered, /deleted/);
  });
});

test("the linux-target recipe leaves a receipt before the wrapper starts and rewrites it from the wrapper's summary when it is terminated", async () => {
  await withCwd(async (cwd, bin) => {
    const env = await triageFixture(cwd, bin, { os: { records: 1 }, hostname: { sleep: 8 } });
    await writeFile(join(cwd, "target.json"), JSON.stringify({ paths: [join(cwd, "inputs", "server.E01")], name: "server" }));
    const child = spawn("python3", [RECIPE, "run", "--target", join(cwd, "target.json"), "--out", join(cwd, "recipe-out")], {
      cwd, env: { ...process.env, ...env, PATH: `${bin}:${process.env.PATH ?? ""}` }, detached: true, stdio: ["ignore", "pipe", "pipe"],
    });
    const exited = new Promise<number | null>((resolve) => child.on("close", (code) => resolve(code)));
    const summary = join(cwd, "recipe-out", "artefacts", "summary.json");
    let seen = false;
    for (let i = 0; i < 100 && !seen; i++) {
      await new Promise((r) => setTimeout(r, 100));
      const s = await readFile(summary, "utf8").then((t) => JSON.parse(t), () => null);
      seen = Boolean(s?.groups?.some((g: Json) => g.functions.some((f: Json) => f.name === "os" && f.status === "parsed")));
    }
    assert.ok(seen, "the wrapper's summary shows the first function done while the second runs");
    const before = JSON.parse(await readFile(join(cwd, "recipe-out", "coverage.json"), "utf8"));
    assert.equal(before.status, "partial", "a receipt exists, saying nothing is established, before the wrapper has ended");
    assert.match(before.status_basis, /had not finished/);
    process.kill(-(child.pid as number), "SIGTERM");
    await exited;
    const after = JSON.parse(await readFile(join(cwd, "recipe-out", "coverage.json"), "utf8"));
    assert.equal(after.status, "partial");
    assert.ok(after.functions.parsed >= 1);
    assert.ok(after.errors.some((e: string) => /hostname/.test(e)), JSON.stringify(after.errors));
    assert.match(after.receipt_written, /terminated/);
  });
});

test("linux_triage ends a function's unterminated last line so the next function's record is not glued to it, and says so", async () => {
  await withCwd(async (cwd, bin) => {
    const env = await triageFixture(cwd, bin, { journal: { records: 1, junk: "", exit: 1 }, syslog: { records: 2 } });
    // The stand-in prints `{"j":2` with no newline for the journal function, then fails.
    await writeFile(join(bin, "target-query"), `#!/usr/bin/env python3
import json, os, sys
args = sys.argv[1:]
fn = args[args.index("-f") + 1]
if fn == "journal":
    sys.stdout.write('{"j":1}\\n{"j":2'); sys.stdout.flush(); sys.exit(1)
print(json.dumps({"fn": fn}))
`);
    await chmod(join(bin, "target-query"), 0o755);
    const out = body(await tool(TRIAGE, cwd, { source: "inputs/server.E01", out_dir: "work/triage", groups: ["logs"] }, env, bin));
    const [journal, syslog] = out.groups[0].functions;
    assert.equal(journal.last_line_unterminated, true);
    assert.equal(journal.status, "failed");
    assert.equal(syslog.status, "parsed");
    const textOut = await readFile(join(cwd, out.groups[0].file), "utf8");
    assert.deepEqual(textOut.split("\n").filter(Boolean).map((l) => { try { JSON.parse(l); return "ok"; } catch { return "bad"; } }), ["ok", "bad", "ok"]);
    assert.equal(journal.bytes, Buffer.byteLength('{"j":1}\n{"j":2'), "its byte count is its own, not the repair");
  });
});

test("linux_triage reads a stderr by lines: an unrelated 'unsupported' is not this function's, and a traceback beside records is unknown", async () => {
  await withCwd(async (cwd, bin) => {
    const env = await triageFixture(cwd, bin, {
      users: { records: 0, stderr: "WARNING: unsupported filesystem btrfs on partition 3, skipped" },
      "webserver.logs": { records: 2, stderr: "Traceback (most recent call last):\n  File x\nValueError" },
      bashhistory: { records: 0, stderr: `${"noise ".repeat(100_000)}\nWARNING | bashhistory: plugin not available for this target` },
    });
    const out = body(await tool(TRIAGE, cwd, { source: "inputs/server.E01", out_dir: "work/triage", groups: ["users", "web", "history"] }, env, bin));
    const st = (name: string): Json => out.groups.flatMap((g: Json) => g.functions).find((f: Json) => f.name === name);
    assert.equal(st("users").status, "unknown");
    assert.equal(st("users").stderr_says_unavailable_without_naming_this_function, true);
    assert.equal(st("webserver.logs").status, "unknown");
    assert.equal(st("webserver.logs").stderr_has_a_traceback, true);
    assert.equal(st("bashhistory").status, "unsupported", "a long stderr is read through to the line that names the function");
  });
});

test("linux_triage and the recipe end what dissect.target they started when they are told to stop", async () => {
  await withCwd(async (cwd, bin) => {
    const env = await triageFixture(cwd, bin, {});
    await writeFile(join(bin, "target-query"), `#!/usr/bin/env python3
import os, time
open(os.environ["STUB_PID"], "w").write(str(os.getpid()))
time.sleep(60)
`);
    await chmod(join(bin, "target-query"), 0o755);
    const pidFile = join(cwd, "stub.pid");
    const child = spawn("python3", [TRIAGE], { cwd, env: { ...process.env, ...env, ...AGENT, STUB_PID: pidFile, PATH: `${bin}:${process.env.PATH ?? ""}` }, stdio: ["pipe", "pipe", "pipe"] });
    child.stdin.end(JSON.stringify({ source: "inputs/server.E01", out_dir: "work/triage", groups: ["users"] }));
    const exited = new Promise<number | null>((resolve) => child.on("close", (code) => resolve(code)));
    let pid = 0;
    for (let i = 0; i < 100 && !pid; i++) {
      await new Promise((r) => setTimeout(r, 100));
      pid = Number(await readFile(pidFile, "utf8").catch(() => "0"));
    }
    assert.ok(pid > 0, "dissect.target's stand-in is running");
    child.kill("SIGTERM");
    assert.equal(await exited, 143);
    await new Promise((r) => setTimeout(r, 300));
    assert.throws(() => process.kill(pid, 0), "the function it was running did not outlive it");
    const summary = JSON.parse(await readFile(join(cwd, "work", "triage", "summary.json"), "utf8"));
    assert.equal(summary.state, "terminated");
    assert.equal(summary.groups[0].functions[0].status, "failed");
  });
});

test("the linux-target recipe says could-not-tell for a target or an answer it cannot read, and ignores an earlier run's summary", async () => {
  await withCwd(async (cwd, bin) => {
    const env = await triageFixture(cwd, bin, Object.fromEntries(ALL_FUNCTIONS.map((f) => [f, { records: 1 }])));
    await writeFile(join(cwd, "target.json"), JSON.stringify({ paths: [join(cwd, "inputs", "server.E01")], name: "server" }));
    const answer = (r: ReturnType<typeof spawnSync>): Json => JSON.parse(String(r.stdout).trim().split("\n").pop() ?? "{}");
    for (const target of ['{"paths":{"0":"x"}}', "[]", "null"]) assert.equal(recipe(cwd, bin, {}, "detect", "--target", target).status, 2);
    // A reader that prints bytes that are not text, and one that cannot be started.
    await writeFile(join(bin, "target-query"), "#!/usr/bin/env python3\nimport sys\nsys.stdout.buffer.write(b'\\xff\\xfe\\x00')\n");
    await chmod(join(bin, "target-query"), 0o755);
    let r = recipe(cwd, bin, {}, "detect", "--target", join(cwd, "target.json"));
    assert.equal(r.status, 2);
    assert.equal(answer(r).applies, "unknown");
    await writeFile(join(bin, "target-query"), "#!/nonexistent/interpreter\n");
    r = recipe(cwd, bin, {}, "detect", "--target", join(cwd, "target.json"));
    assert.equal(r.status, 2);
    assert.equal(answer(r).applies, "unknown");
    // A second run into the same --out: the wrapper refuses, and the receipt does not borrow the first run's summary.
    await targetQueryStub(bin);
    const out = join(cwd, "recipe-out");
    assert.equal(recipe(cwd, bin, env, "run", "--target", join(cwd, "target.json"), "--out", out).status, 0);
    const again = recipe(cwd, bin, env, "run", "--target", join(cwd, "target.json"), "--out", out);
    assert.notEqual(again.status, 0);
    const coverage = JSON.parse(await readFile(join(out, "coverage.json"), "utf8"));
    assert.equal(coverage.status, "failed", "no summary of this run exists");
    assert.match(coverage.status_basis, /no summary of this run/);
    assert.ok(coverage.errors.some((e: string) => /linux_triage exited/.test(e)));
  });
});

test("linux_triage finds a function's name in a line as a word, not inside another word or another function's name", async () => {
  await withCwd(async (cwd, bin) => {
    const say = (what: string): { records: number; stderr: string } => ({ records: 0, stderr: `WARNING | ${what}: plugin not available for this target` });
    const env = await triageFixture(cwd, bin, {
      os: say("hostos"),                       // `os` inside another word
      ips: say("ships"),                       // `ips` inside another word
      hostname: say("os.hostname"),            // another function's name, with `os` before the dot
      version: say("version"),                 // the name itself, as a word
      "dpkg.status": say("dpkg.status"),       // the whole dotted name
      "ssh.known_hosts": say("known_hosts"),   // the last part of a dotted name alone is not the function
    });
    const out = body(await tool(TRIAGE, cwd, { source: "inputs/server.E01", out_dir: "work/triage", groups: ["identity", "packages", "ssh"] }, env, bin));
    const st = (name: string): Json => out.groups.flatMap((g: Json) => g.functions).find((f: Json) => f.name === name);
    assert.equal(st("os").status, "unknown");
    assert.equal(st("ips").status, "unknown");
    assert.equal(st("hostname").status, "unknown");
    assert.equal(st("version").status, "unsupported");
    assert.equal(st("dpkg.status").status, "unsupported");
    assert.equal(st("ssh.known_hosts").status, "unknown");
  });
});

test("linux_triage answers in JSON where it cannot make its directory, and in a job writes only under the job's output", async () => {
  await withCwd(async (cwd, bin) => {
    const env = await triageFixture(cwd, bin, {});
    if (!IS_ROOT) {
      await mkdir(join(cwd, "ro"), { recursive: true });
      await chmod(join(cwd, "ro"), 0o555);
      const run = await tool(TRIAGE, cwd, { source: "inputs/server.E01", out_dir: "ro/triage", groups: ["users"] }, env, bin);
      assert.doesNotMatch(run.stderr, /Traceback/);
      assert.match(refused(run).error, /could not be created/);
      await chmod(join(cwd, "ro"), 0o755);
    }
    // In a job only $OUT is writable: a directory elsewhere is refused before anything runs, and the example's place is accepted.
    const elsewhere = refused(await asJob(TRIAGE, cwd, { source: "inputs/server.E01", out_dir: "work/linux-triage", groups: ["users"] }, bin, env));
    assert.match(elsewhere.error, /work\/<your agent id>/);
    assert.equal(await exists(join(cwd, "work", "linux-triage")), false);
    assert.equal(await exists(env.STUB_LOG), false, "nothing ran");
    const ok = body(await asJob(TRIAGE, cwd, { source: "inputs/server.E01", out_dir: "out/linux-triage", groups: ["users"] }, bin, env));
    assert.equal(ok.status, "complete");
    assert.equal(await exists(join(cwd, "out", "linux-triage", "summary.json")), true);
  });
});

test("linux_triage and the recipe give every answer a status and say on what it rests", async () => {
  await withCwd(async (cwd, bin) => {
    const env = await triageFixture(cwd, bin, { users: { exit: 1 }, bashhistory: { exit: 1 }, "webserver.logs": { exit: 1 } });
    const failed = body(await tool(TRIAGE, cwd, { source: "inputs/server.E01", out_dir: "work/f", groups: ["users", "history", "web"] }, env, bin));
    assert.equal(failed.status, "failed");
    assert.match(failed.status_basis, /no selected function ran to an exit/);
    await writeFile(join(cwd, "stub-conf.json"), JSON.stringify({}));
    const whole = body(await tool(TRIAGE, cwd, { source: "inputs/server.E01", out_dir: "work/c", groups: ["users"] }, env, bin));
    assert.equal(whole.status, "complete");
    assert.match(whole.status_basis, /not coverage of the host/);
    assert.equal(refused(await tool(TRIAGE, cwd, { source: "inputs/none.E01", out_dir: "work/e" }, env, bin)).status, "failed");
    // The recipe's receipt and its answer carry the same pair.
    await writeFile(join(cwd, "stub-conf.json"), JSON.stringify({ users: { exit: 1 }, bashhistory: { exit: 1 }, "webserver.logs": { exit: 1 }, ...Object.fromEntries(ALL_FUNCTIONS.map((f) => [f, { exit: 1 }])) }));
    await writeFile(join(cwd, "target.json"), JSON.stringify({ paths: [join(cwd, "inputs", "server.E01")], name: "server" }));
    const r = recipe(cwd, bin, env, "run", "--target", join(cwd, "target.json"), "--out", join(cwd, "recipe-out"));
    const coverage = JSON.parse(await readFile(join(cwd, "recipe-out", "coverage.json"), "utf8"));
    assert.equal(coverage.status, "failed");
    assert.match(coverage.status_basis, /no selected function ran/);
    assert.equal(JSON.parse(String(r.stdout).trim()).status_basis, coverage.status_basis);
  });
});

test("the linux-target recipe makes what it makes under its own output directory, whatever directory it was started in", async () => {
  await withCwd(async (cwd, bin) => {
    const env = await triageFixture(cwd, bin, Object.fromEntries(ALL_FUNCTIONS.map((f) => [f, { records: 1 }])));
    // The census starts a recipe in the host's working directory, which is not the output directory's parent.
    const elsewhere = join(cwd, "elsewhere");
    await mkdir(elsewhere, { recursive: true });
    await writeFile(join(cwd, "target.json"), JSON.stringify({ paths: [join(cwd, "inputs", "server.E01")], name: "server" }));
    const out = join(cwd, "deep", "census", "linux");
    const r = spawnSync("python3", [RECIPE, "run", "--target", join(cwd, "target.json"), "--out", out], { cwd: elsewhere, env: { ...process.env, ...env, PATH: `${bin}:${process.env.PATH ?? ""}` }, encoding: "utf8" });
    assert.equal(r.status, 0, String(r.stdout) + String(r.stderr));
    assert.equal(JSON.parse(String(r.stdout).trim()).status, "complete");
    assert.equal(await exists(join(out, "artefacts", "summary.json")), true);
    assert.equal(await exists(join(elsewhere, "artefacts")), false, "nothing was made in the directory it started in");
    // A relative image path is read relative to where the recipe was started, and the wrapper gets it whole.
    await writeFile(join(elsewhere, "image.E01"), "bytes");
    await writeFile(join(cwd, "target2.json"), JSON.stringify({ paths: ["image.E01"], name: "rel" }));
    const rel = spawnSync("python3", [RECIPE, "run", "--target", join(cwd, "target2.json"), "--out", join(cwd, "out2")], { cwd: elsewhere, env: { ...process.env, ...env, PATH: `${bin}:${process.env.PATH ?? ""}` }, encoding: "utf8" });
    assert.equal(rel.status, 0, String(rel.stdout) + String(rel.stderr));
    const log = (await readFile(env.STUB_LOG, "utf8")).trim().split("\n").map((l) => JSON.parse(l) as string[]);
    const absolute = join(await realpath(elsewhere), "image.E01");
    assert.ok(log.some((a) => a[a.length - 1] === absolute), "the wrapper was given the image by its absolute path");
    // An output directory that cannot be made is an answer, not a traceback.
    if (!IS_ROOT) {
      await mkdir(join(cwd, "ro"), { recursive: true });
      await chmod(join(cwd, "ro"), 0o555);
      const bad = spawnSync("python3", [RECIPE, "run", "--target", join(cwd, "target.json"), "--out", join(cwd, "ro", "x")], { cwd, env: { ...process.env, ...env, PATH: `${bin}:${process.env.PATH ?? ""}` }, encoding: "utf8" });
      assert.doesNotMatch(String(bad.stderr), /Traceback/);
      assert.equal(bad.status, 2);
      assert.equal(JSON.parse(String(bad.stdout).trim()).status, "failed");
      await chmod(join(cwd, "ro"), 0o755);
    }
  });
});
