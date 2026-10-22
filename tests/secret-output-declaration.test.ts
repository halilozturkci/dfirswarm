/**
 * A tool manifest may declare that its jobs are secret output
 * (`"secret_output": "required"`, or `{"when_args": [...]}` for a tool whose
 * secret mode depends on an argument), and the job service then treats the
 * job as run with `secret_output` whether or not the agent said so: the
 * outputs are sealed sensitive, a reader is derived, a redacted package
 * withholds them. A secret job's process also gets SECRET_OUTPUT=1, so a tool
 * can refuse a values mode in a job that is not. The harness knows no tool and
 * no format: it reads one declaration and one argument's presence.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import * as P from "../extensions/protocol.ts";
import { argIsSet, declaredSecretOutput, ownSensitivity, parseSecretDeclaration, sensitiveEntries } from "../scripts/output-hygiene.ts";
import { storePaths } from "../scripts/evidence-store.ts";
import { describe, JobService, jobView } from "../scripts/job-service.ts";
import { redactPackage } from "../scripts/package-tools.ts";
import { localWorker } from "./job-service-worker.ts";
import type { WorkerSpec } from "../scripts/vm.ts";

const ROOT = join(import.meta.dirname, "..");
const BASE = join(ROOT, "packs", "computer-forensics-base");
const ENCRYPTED = join(ROOT, "packs", "encrypted-containers");
const RANSOMWARE = join(ROOT, "packs", "ransomware-response");
/** A value a job writes and the run treats as secret: a placeholder, never a real credential. */
const VALUE = "TOKEN-sample-7f3a91";

const dirs: string[] = [];
after(async () => {
  for (const d of dirs) {
    spawnSync("chmod", ["-R", "u+w", d]);
    await rm(d, { recursive: true, force: true });
  }
});

/** A tool that reports the SECRET_OUTPUT it was given and writes VALUE only when asked to. */
const PROBE = [
  "import json, os, sys",
  "a = json.load(sys.stdin)",
  "out = os.environ['OUT']",
  "open(os.path.join(out, 'env.txt'), 'w').write(os.environ.get('SECRET_OUTPUT', 'unset'))",
  `if a.get('write_values'): open(os.path.join(out, 'values.txt'), 'w').write('${VALUE}')`,
  "print(json.dumps({'ok': True}))",
  "",
].join("\n");

async function addTool(S: string, name: string, extra: Record<string, unknown>, params: Record<string, unknown> = { write_values: { type: "boolean" }, note: { type: "string" } }, body = PROBE) {
  await mkdir(join(S, "tools", name), { recursive: true });
  await writeFile(join(S, "tools", name, "run.py"), body);
  const sha256 = createHash("sha256").update(body).digest("hex");
  await writeFile(join(S, "tools", name, "manifest.json"), JSON.stringify({ name, description: "A probe.", params, runtime: "python3", entry: "run.py", timeout_seconds: 60, by: "t", at: "t", version: 1, sha256, ...extra }));
}

async function make(packDirs: string[] = [BASE]) {
  const base = await mkdtemp(join(tmpdir(), "secdecl-"));
  dirs.push(base);
  const S = join(base, "run");
  await P.initSandbox(S, { swarmId: "sdecl", agentIds: ["a1", "a2"] });
  for (const d of ["inputs", "tools", "catalog", "work/a1"]) await mkdir(join(S, d), { recursive: true });
  await writeFile(join(S, "inputs.json"), JSON.stringify({ files: [] }));
  const workers: WorkerSpec[] = [];
  const svc = new JobService({
    sandbox: S, run: "sdecl", image: "img:test", workers: 2, workerCpus: 1, workerMemoryMib: 512, allowHosts: [], openNet: false,
    packDirs, forging: true, minFreeMb: 1,
    runWorker: localWorker(workers), destroyWorker: async () => ({ ok: true }), notify: async () => undefined, identity: async (a) => ({ name: a }),
  });
  await svc.start();
  return { S, base, svc, workers };
}

async function until(svc: JobService, id: string) {
  for (let i = 0; i < 1200; i += 1) {
    const j = svc.jobs.get(id);
    if (j && ["committed", "failed", "cancelled"].includes(j.state)) return j;
    await new Promise((r) => setTimeout(r, 50));
  }
  throw new Error(`${id} did not finish`);
}

async function submitted(svc: JobService, who: string, spec: Record<string, unknown>) {
  const r = await svc.submit(who, { kind: "tool", timeout_seconds: 60, network: "off", inputs: [], ...spec } as never);
  assert.ok(r.ok, !r.ok ? r.reason : "");
  return until(svc, r.job.id);
}

const refused = async (svc: JobService, spec: Record<string, unknown>) => {
  const r = await svc.submit("a1", { kind: "tool", timeout_seconds: 60, network: "off", inputs: [], ...spec } as never);
  assert.equal(r.ok, false, "refused");
  return r.ok ? "" : r.reason;
};

async function committedLine(S: string, job: string): Promise<Record<string, unknown> & { sensitive?: Record<string, unknown> }> {
  for (let i = 0; i < 200; i++) {
    const journal = await readFile(storePaths(S).journal, "utf8").catch(() => "");
    const line = journal.split("\n").filter(Boolean).map((l) => JSON.parse(l)).find((l) => l.type === "job_committed" && l.job === job);
    if (line) return line;
    await new Promise((r) => setTimeout(r, 10));
  }
  throw new Error(`no job_committed line for ${job}`);
}

const outFile = (S: string, job: string, name: string) => readFile(join(storePaths(S).jobs, job, "out", name), "utf8");

test("a tool whose manifest says required is run as secret output without the agent's flag: sealed sensitive, derived on read, withheld from a package", async () => {
  const { S, svc, base } = await make();
  await addTool(S, "key_dump", { secret_output: "required" });
  const job = await submitted(svc, "a1", { tool: "key_dump", args: { write_values: true } });
  assert.equal(job.status, "ok");
  assert.equal(job.spec.secret_output, true, "the spec records what the job was run as");
  assert.equal(job.sensitive?.why, "secret_output");
  assert.equal((await committedLine(S, job.id)).sensitive?.why, "secret_output", "on the journal, as the agent's flag would put it");
  assert.equal(JSON.parse(await readFile(join(storePaths(S).jobs, job.id, "job.json"), "utf8")).sensitive.why, "secret_output");
  assert.match(describe(job), /Its outputs are sensitive \(it ran with secret_output, which the tool's manifest declares\)/);
  assert.equal(await outFile(S, job.id, "env.txt"), "1", "SECRET_OUTPUT reached the tool's process");

  // The agent saying false does not turn it off.
  const denied = await submitted(svc, "a1", { tool: "key_dump", args: {}, secret_output: false });
  assert.equal(denied.sensitive?.why, "secret_output");

  // A job that reads it is derived, as for the agent's own flag.
  const reader = await submitted(svc, "a2", { kind: "command", command: `wc -c < store/jobs/${job.id}/out/values.txt > "$OUT/n.txt"`, inputs: [`job:${job.id}/values.txt`] });
  assert.deepEqual([reader.sensitive?.why, reader.sensitive?.from], ["derived", [job.id]]);

  // An entry citing it is recorded sensitive.
  const rec = await P.recordEntry({ sandboxRoot: S, agentId: "a1" }, { kind: "finding", basis: "observed", confidence: "medium", indicates: "What the observation shows, and the step to it.", confidence_why: "Read directly from the object it cites.", value: "The tool wrote a value", source: "the job's output", evidence: "the job", refs: [`job:${job.id}/values.txt`] });
  assert.ok(rec.ok, (rec as { reason?: string }).reason);
  assert.equal((rec as { entry: P.LedgerEntry }).entry.sensitive, true);
  assert.equal((await sensitiveEntries(S, [(rec as { entry: P.LedgerEntry }).entry as never])).size, 1);

  // A redacted package withholds the file whole.
  await svc.stop("test over");
  const pkg = join(base, "pkg");
  await mkdir(join(pkg, "store", "jobs", job.id, "out"), { recursive: true });
  for (const f of ["job.json", "manifest.json", "stdout.log"]) await writeFile(join(pkg, "store", "jobs", job.id, f), await readFile(join(storePaths(S).jobs, job.id, f)));
  await writeFile(join(pkg, "store", "jobs", job.id, "out", "values.txt"), VALUE);
  await redactPackage(S, pkg, { leaks: "list" });
  assert.doesNotMatch(await readFile(join(pkg, "store", "jobs", job.id, "out", "values.txt"), "utf8"), new RegExp(VALUE), "the value is not in the redacted package");
});

test("a declaration with when_args applies only when one of the named arguments is set", async () => {
  const { S, svc, workers } = await make();
  await addTool(S, "maybe_dump", { secret_output: { when_args: ["write_values"] } });
  const plain = await submitted(svc, "a1", { tool: "maybe_dump", args: {} });
  assert.equal(plain.sensitive, undefined, "no value mode, no secret output");
  assert.equal(plain.spec.secret_output, undefined);
  assert.equal(await outFile(S, plain.id, "env.txt"), "unset", "a job that is not secret is not told it is");
  const off = await submitted(svc, "a1", { tool: "maybe_dump", args: { write_values: false, note: "" } });
  assert.equal(off.sensitive, undefined, "false and an empty string are not set");
  const on = await submitted(svc, "a1", { tool: "maybe_dump", args: { write_values: true } });
  assert.equal(on.sensitive?.why, "secret_output");
  assert.equal(on.spec.secret_output, true);
  assert.equal(await outFile(S, on.id, "env.txt"), "1");
  assert.equal(await outFile(S, on.id, "values.txt"), VALUE);
  // A string argument counts when it is not empty.
  await addTool(S, "text_dump", { secret_output: { when_args: ["deep"] } }, { deep: { type: "boolean", default: false }, note: { type: "string" } });
  assert.equal((await submitted(svc, "a1", { tool: "text_dump", args: { deep: true } })).sensitive?.why, "secret_output");
  assert.equal((await submitted(svc, "a1", { tool: "text_dump", args: { note: "x" } })).sensitive, undefined, "a parameter the declaration does not name decides nothing");
  assert.equal((await submitted(svc, "a1", { tool: "text_dump", args: {} })).sensitive, undefined);
  // The worker's own record carries the variable only for the secret jobs.
  const envOf = (id: string) => workers.find((w) => w.job === id)?.env;
  assert.equal(envOf(on.id)?.SECRET_OUTPUT, "1");
  assert.equal(envOf(plain.id)?.SECRET_OUTPUT, undefined);
  await svc.stop("test over");
});

test("a tool with no declaration is as before: the agent's flag decides, and the process is told only when the job is secret", async () => {
  const { S, svc } = await make();
  await addTool(S, "undeclared", {});
  const quiet = await submitted(svc, "a1", { tool: "undeclared", args: { write_values: true } });
  assert.equal(quiet.sensitive, undefined, "the harness does not guess from an argument's name");
  assert.equal(await outFile(S, quiet.id, "env.txt"), "unset");
  const flagged = await submitted(svc, "a1", { tool: "undeclared", args: { write_values: true }, secret_output: true });
  assert.equal(flagged.sensitive?.why, "secret_output");
  assert.equal(await outFile(S, flagged.id, "env.txt"), "1");
  assert.match(describe(flagged), /\(it ran with secret_output\)/, "the agent's flag is not described as the manifest's");
  // A command: the variable follows the flag too.
  const cmd = await submitted(svc, "a1", { kind: "command", command: `printf '%s' "\${SECRET_OUTPUT-unset}" > "$OUT/e.txt"` });
  assert.equal(await outFile(S, cmd.id, "e.txt"), "unset");
  const cmdSecret = await submitted(svc, "a1", { kind: "command", command: `printf '%s' "\${SECRET_OUTPUT-unset}" > "$OUT/e.txt"`, secret_output: true });
  assert.equal(await outFile(S, cmdSecret.id, "e.txt"), "1");
  // A variable the worker's image happens to carry does not reach a job that is not secret.
  const inherited = await (async () => {
    process.env.SECRET_OUTPUT = "1";
    try {
      return await submitted(svc, "a1", { kind: "command", command: `printf '%s' "\${SECRET_OUTPUT-unset}" > "$OUT/e.txt"` });
    } finally {
      delete process.env.SECRET_OUTPUT;
    }
  })();
  assert.equal(await outFile(S, inherited.id, "e.txt"), "unset");
  await svc.stop("test over");
});

test("a declaration that is not understood refuses the job, naming the manifest and the rule; none is guessed", async () => {
  const { S, svc } = await make();
  const bad: Array<[string, unknown, RegExp]> = [
    ["b_true", true, /"required"/],
    ["b_word", "sometimes", /"required"/],
    ["b_empty", {}, /when_args/],
    ["b_list", { when_args: [] }, /when_args/],
    ["b_name", { when_args: ["nope"] }, /nope.*not a parameter/],
    ["b_type", { when_args: [1] }, /when_args/],
    ["b_extra", { when_args: ["write_values"], also: 1 }, /when_args/],
    ["b_dup", { when_args: ["write_values", "write_values"] }, /twice/],
    ["b_array", ["write_values"], /"required"/],
    ["b_null", null, /"required"/],
    ["b_string_param", { when_args: ["note"] }, /note.*not declared type "boolean"/],
    ["b_untyped_param", { when_args: ["bare"] }, /bare.*not declared type "boolean"/],
    ["b_default_on", { when_args: ["on_by_default"] }, /on_by_default.*default other than false/],
  ];
  for (const [name, decl] of bad) {
    await addTool(S, name, { secret_output: decl }, { write_values: { type: "boolean" }, note: { type: "string" }, bare: {}, on_by_default: { type: "boolean", default: true } });
    const reason = await refused(svc, { tool: name, args: {} });
    assert.match(reason, /secret_output/, name);
    assert.match(reason, new RegExp(`tool ${name}`), name);
    assert.match(reason, bad.find((b) => b[0] === name)![2], name);
  }
  assert.equal([...svc.jobs.values()].length, 0, "nothing was accepted");
  await svc.stop("test over");
});

test("the base pack's sqlite_query is secret output when it writes values, with no flag from the agent, and a command running it by hand is refused", async () => {
  const { S, svc } = await make();
  await mkdir(join(S, "tools"), { recursive: true });
  spawnSync("cp", ["-R", join(BASE, "tools", "sqlite_query"), join(S, "tools", "sqlite_query")]);
  const db = join(S, "work", "a1", "logins.db");
  const made = spawnSync("python3", ["-c", `import sqlite3,sys\nc=sqlite3.connect(sys.argv[1])\nc.execute("create table logins(origin text, secret text)")\nc.execute("insert into logins values('site', '${VALUE}')")\nc.commit()`, db]);
  assert.equal(made.status, 0, String(made.stderr));
  const rel = "work/a1/logins.db";

  const values = await submitted(svc, "a1", { tool: "sqlite_query", args: { db_path: rel, table: "logins", write_values: true }, inputs: undefined });
  assert.equal(values.status, "ok", String(await readFile(join(storePaths(S).jobs, values.id, "stdout.log"), "utf8")));
  assert.equal(values.sensitive?.why, "secret_output");
  assert.match(await outFile(S, values.id, "sqlite-query-values.jsonl"), new RegExp(VALUE));
  assert.doesNotMatch(await readFile(join(storePaths(S).jobs, values.id, "stdout.log"), "utf8"), new RegExp(VALUE), "the answer carries no value");

  const read = await submitted(svc, "a1", { tool: "sqlite_query", args: { db_path: rel, sql: "select origin from logins" }, inputs: undefined });
  assert.equal(read.status, "ok");
  assert.equal(read.sensitive, undefined, "an ordinary query is an ordinary job");

  // Run by hand in a command job without the flag: no variable, so the tool refuses, as JSON, and writes nothing.
  const args = JSON.stringify({ db_path: rel, table: "logins", write_values: true });
  const hand = await submitted(svc, "a1", { kind: "command", command: `printf '%s' '${args}' | python3 tools/sqlite_query/run.py > "$OUT/answer.json"; true`, inputs: undefined });
  const answer = JSON.parse(await outFile(S, hand.id, "answer.json"));
  assert.equal(answer.ok, false);
  assert.equal(answer.write_values, "refused");
  assert.equal(answer.written, false);
  assert.match(answer.error, /secret_output/);
  assert.equal(existsSync(join(storePaths(S).jobs, hand.id, "out", "sqlite-query-values.jsonl")), false, "nothing was written");
  assert.equal(hand.sensitive, undefined);
  await svc.stop("test over");
});

test("recovery_key_scan declares the same, and writes no value in a job that is not secret", async () => {
  const { S, svc } = await make([ENCRYPTED]);
  spawnSync("cp", ["-R", join(ENCRYPTED, "tools", "recovery_key_scan"), join(S, "tools", "recovery_key_scan")]);
  const manifest = JSON.parse(await readFile(join(S, "tools", "recovery_key_scan", "manifest.json"), "utf8"));
  assert.deepEqual(manifest.secret_output, { when_args: ["write_values"] });
  const keyfile = join(S, "work", "a1", "notes.txt");
  const KEY = "123456-234567-345678-456789-567891-678912-789123-891234";
  await writeFile(keyfile, `recovery key ${KEY}\n`);
  const asked = await submitted(svc, "a1", { tool: "recovery_key_scan", args: { path: "work/a1/notes.txt", write_values: true }, inputs: undefined });
  assert.equal(asked.sensitive?.why, "secret_output", await readFile(join(storePaths(S).jobs, asked.id, "stderr.log"), "utf8"));
  assert.match(await outFile(S, asked.id, "recovery-passwords.jsonl"), new RegExp(KEY));
  const listed = await submitted(svc, "a1", { tool: "recovery_key_scan", args: { path: "work/a1/notes.txt" }, inputs: undefined });
  assert.equal(listed.sensitive, undefined);
  const args = JSON.stringify({ path: "work/a1/notes.txt", write_values: true });
  const hand = await submitted(svc, "a1", { kind: "command", command: `printf '%s' '${args}' | python3 tools/recovery_key_scan/run.py > "$OUT/answer.json"; true`, inputs: undefined });
  const answer = JSON.parse(await outFile(S, hand.id, "answer.json"));
  assert.deepEqual([answer.write_values, answer.written], ["refused", false]);
  assert.match(answer.error, /not run as secret output/);
  assert.equal(existsSync(join(storePaths(S).jobs, hand.id, "out", "recovery-passwords.jsonl")), false);
  await svc.stop("test over");
});

test("ransom_note_scan declares the same, and writes no value in a job that is not secret", async () => {
  const { S, svc } = await make([RANSOMWARE]);
  spawnSync("cp", ["-R", join(RANSOMWARE, "tools", "ransom_note_scan"), join(S, "tools", "ransom_note_scan")]);
  const manifest = JSON.parse(await readFile(join(S, "tools", "ransom_note_scan", "manifest.json"), "utf8"));
  assert.deepEqual(manifest.secret_output, { when_args: ["write_values"] });
  const ID = "Zq9" + "Km4".repeat(3) + "Pw";
  await mkdir(join(S, "work", "a1", "ev"), { recursive: true });
  await writeFile(join(S, "work", "a1", "ev", "README.txt"), `Your files are encrypted. Decrypt them and pay in bitcoin to restore your files.\nyour personal id: ${ID}\n`);
  const asked = await submitted(svc, "a1", { tool: "ransom_note_scan", args: { root: "work/a1/ev", write_values: true }, inputs: undefined });
  assert.equal(asked.sensitive?.why, "secret_output", await readFile(join(storePaths(S).jobs, asked.id, "stderr.log"), "utf8"));
  assert.match(await outFile(S, asked.id, "ransom-note-values.jsonl"), new RegExp(ID));
  const listed = await submitted(svc, "a1", { tool: "ransom_note_scan", args: { root: "work/a1/ev" }, inputs: undefined });
  assert.equal(listed.sensitive, undefined);
  const args = JSON.stringify({ root: "work/a1/ev", write_values: true });
  const hand = await submitted(svc, "a1", { kind: "command", command: `printf '%s' '${args}' | python3 tools/ransom_note_scan/run.py > "$OUT/answer.json"; true`, inputs: undefined });
  const answer = JSON.parse(await outFile(S, hand.id, "answer.json"));
  assert.deepEqual([answer.write_values, answer.written], ["refused", false]);
  assert.match(answer.error, /not run as secret output/);
  assert.equal(existsSync(join(storePaths(S).jobs, hand.id, "out", "ransom-note-values.jsonl")), false);
  await svc.stop("test over");
});

test("an argument is set unless it is absent, null or false: the reading fails closed", () => {
  for (const v of [true, 1, -2, 0.5, "x", " ", [0], [""], { a: 1 }]) assert.equal(argIsSet(v), true, JSON.stringify(v));
  for (const v of [undefined, null, false]) assert.equal(argIsSet(v), false, String(v));
  const params = { write_values: { type: "boolean" }, text: { type: "boolean", default: false } };
  const parsed = parseSecretDeclaration({ when_args: ["write_values", "text"] }, params, true);
  assert.ok(parsed.ok);
  const declaration = parsed.ok ? parsed.declaration : null;
  assert.equal(declaredSecretOutput(declaration, {}), false);
  assert.equal(declaredSecretOutput(declaration, { text: true }), true);
  assert.equal(declaredSecretOutput(declaration, { write_values: false, text: null }), false);
  assert.equal(declaredSecretOutput(null, { write_values: true }), false, "no declaration, no effect");
  assert.deepEqual(parseSecretDeclaration(undefined, params, false), { ok: true, declaration: null });
  assert.equal(parseSecretDeclaration(undefined, params, true).ok, false, "a key that is present and undefined (not JSON) is not understood");
  assert.equal(parseSecretDeclaration({ when_args: ["__proto__"] }, params, true).ok, false, "a name is a parameter the tool has, not one every object has");
  assert.equal(parseSecretDeclaration({ when_args: ["toString"] }, params, true).ok, false);
  assert.equal(ownSensitivity({ secret_output: true, secret_output_by: "tool_manifest" })?.declared, "tool_manifest");
  assert.equal(ownSensitivity({ secret_output: true })?.declared, undefined);
  assert.equal(ownSensitivity({ secret_output_by: "tool_manifest" }), null, "the flag decides, not the note about where it came from");
});

// --- review fixes ---------------------------------------------------------------------------------------------------

test("what counts as set fails closed: 0, an empty string, [] and {} are set, and a declaration over a parameter that is not a plain boolean is refused", async () => {
  for (const v of [0, "", [], {}, Number.NaN, "false", "0"]) assert.equal(argIsSet(v), true, JSON.stringify(v));
  for (const v of [undefined, null, false]) assert.equal(argIsSet(v), false, String(v));
  const prototypeKey = parseSecretDeclaration({ when_args: ["toString"] }, {}, true);
  assert.equal(prototypeKey.ok, false);
  // integer / string / untyped / default-on parameters cannot be named: a falsy-but-meaningful value would have been read as "not set"
  for (const params of [{ level: { type: "integer" } }, { tag: { type: "string" } }, { opt: {} }, { opt: { type: "boolean", default: true } }, { opt: { type: "boolean", default: "yes" } }, { opt: 7 }, { opt: null }]) {
    const name = Object.keys(params)[0];
    assert.equal(parseSecretDeclaration({ when_args: [name] }, params, true).ok, false, JSON.stringify(params));
  }
  assert.equal(parseSecretDeclaration({ when_args: ["opt"] }, { opt: { type: "boolean", default: false } }, true).ok, true, "an off default is fine");
  assert.equal(parseSecretDeclaration({ when_args: ["opt"] }, { opt: { type: "boolean" } }, true).ok, true);
  assert.equal(parseSecretDeclaration({ when_args: ["opt"] }, { opt: { type: "boolean", default: null } }, true).ok, true, "a null default is no default");
  // a default is allowed only when absent, null or false, whatever the language reads as falsy: [] and {} are truthy in JavaScript and falsy in Python, and scripts/pack.sh applies this same rule (tests/pack-tools.test.sh)
  for (const d of [[], {}, 0, "", 0.0, "false", "0", true, 1, [0], { a: 1 }, Number.NaN]) {
    const r = parseSecretDeclaration({ when_args: ["opt"] }, { opt: { type: "boolean", default: d } }, true);
    assert.equal(r.ok, false, `default ${JSON.stringify(d)}`);
    assert.match(r.ok ? "" : r.reason, /opt has a default other than false/, `default ${JSON.stringify(d)}`);
  }
  // the same through the job service: the integer tool of the reviewer's probe is refused, not run unsealed
  const { S, svc } = await make();
  await addTool(S, "int_dump", { secret_output: { when_args: ["level"] } }, { level: { type: "integer" } });
  const reason = await refused(svc, { tool: "int_dump", args: { level: 0 } });
  assert.match(reason, /level.*not declared type "boolean"/);
  await svc.stop("test over");
});

test("a params that is not a plain object is refused by the runtime reading as the seal lint refuses it (an array's length is not a parameter)", async () => {
  for (const params of [["length"], ["0"], "length", null, undefined, 5]) {
    for (const name of ["length", "0"]) assert.equal(parseSecretDeclaration({ when_args: [name] }, params as never, true).ok, false, JSON.stringify(params));
  }
  const { S, svc } = await make();
  await addTool(S, "arr_params", { secret_output: { when_args: ["length"] } }, [{ type: "boolean" }] as never);
  const reason = await refused(svc, { tool: "arr_params", args: {} });
  assert.match(reason, /secret_output/);
  await svc.stop("test over");
});

test("a declaration reaches only tool jobs: a forged tool that declares the recipe protocol and a secret_output is refused as a recipe, a pack recipe.json that carries the key is not run", async () => {
  const pack = await mkdtemp(join(tmpdir(), "secdecl-pack-"));
  dirs.push(pack);
  await writeFile(join(pack, "pack.json"), JSON.stringify({ id: "decl-pack", name: "decl-pack", version: "1.0.0" }));
  const body = "import sys\nprint('ok')\n";
  for (const [name, extra] of [["plain", {}], ["declares", { secret_output: "required" }]] as const) {
    await mkdir(join(pack, "recipes", name), { recursive: true });
    await writeFile(join(pack, "recipes", name, "run.py"), body);
    await writeFile(join(pack, "recipes", name, "recipe.json"), JSON.stringify({ id: name, version: "1.0.0", description: "d", runtime: "python3", entry: "run.py", sha256: createHash("sha256").update(body).digest("hex"), auto: ["kickoff"], limits: { seconds: 60 }, outputs: ["x"], covers: ["x"], ...extra }));
  }
  const { S, svc } = await make([BASE, pack]);
  const plain = await svc.recipe("decl-pack/plain");
  assert.ok(plain && !plain.refused, "a recipe without the key is as before");
  const declared = await svc.recipe("decl-pack/declares");
  assert.match(declared?.refused ?? "", /secret_output.*tool jobs only/);
  assert.deepEqual(declared?.auto, [], "never triggered");
  assert.ok(!(await svc.allRecipes("request")).some((r) => r.id === "decl-pack/declares"), "a detect pass does not ask it");
  assert.ok((await svc.allRecipes("request")).some((r) => r.id === "decl-pack/plain"));

  const target = join(S, "inputs", "f.bin");
  await writeFile(target, "x");
  const asRecipe = async (recipe: string) => svc.submit("a1", { kind: "recipe", recipe, target: { paths: [target], name: "f.bin" }, inputs: ["all"], timeout_seconds: 60, network: "off" } as never);
  const r1 = await asRecipe("decl-pack/declares");
  assert.equal(r1.ok, false);
  assert.match(r1.ok ? "" : r1.reason, /secret_output.*tool jobs only/);

  // A forged tool that declares the recipe protocol and the key.
  const rbody = "import sys,os\nopen(os.path.join(sys.argv[sys.argv.index('--out')+1],'v.txt'),'w').write('VAL')\n";
  await addTool(S, "rec_tool", { secret_output: "required", recipe: true }, {}, rbody);
  const r2 = await asRecipe("tool:rec_tool");
  assert.equal(r2.ok, false, "refused, not run unsealed");
  assert.match(r2.ok ? "" : r2.reason, /secret_output.*tool jobs only/);
  assert.equal(svc.jobs.size, 0, "nothing was accepted");
  // The same tool without the key is still a recipe.
  await addTool(S, "rec_plain", { recipe: true }, {}, rbody);
  const r3 = await asRecipe("tool:rec_plain");
  assert.ok(r3.ok, r3.ok ? "" : r3.reason);
  await svc.stop("test over");
});

test("a job accepted without the declaration is not run once the manifest declares it: the run script re-checks", async () => {
  const { S, svc } = await make();
  await addTool(S, "late", {}, { write_values: { type: "boolean" } });
  const job = await submitted(svc, "a1", { tool: "late", args: { write_values: true } });
  assert.equal(job.sensitive, undefined);
  const man = JSON.parse(await readFile(join(S, "tools", "late", "manifest.json"), "utf8"));
  await writeFile(join(S, "tools", "late", "manifest.json"), JSON.stringify({ ...man, secret_output: { when_args: ["write_values"] } }));
  await assert.rejects(svc.workerSpecFor(job, join(S, "..", "rerun-late")), /manifest declares this job secret output/);
  await svc.stop("test over");
});

test("an argument named like an inherited property is not a parameter", async () => {
  const { S, svc } = await make();
  await addTool(S, "plain_args", {});
  for (const key of ["constructor", "toString", "__proto__", "hasOwnProperty"]) {
    const reason = await refused(svc, { tool: "plain_args", args: JSON.parse(`{"${key}": true}`) });
    assert.match(reason, new RegExp(`takes no ${key}`), key);
  }
  await svc.stop("test over");
});

test("the answer to the agent names where the declaration came from with the spec's enum", async () => {
  const { S, svc } = await make();
  await addTool(S, "req", { secret_output: "required" });
  const job = await submitted(svc, "a1", { tool: "req", args: {} });
  const view = await jobView(S, job);
  assert.equal(view.secret_output, true);
  assert.equal(view.secret_output_by, "tool_manifest");
  assert.equal((view as Record<string, unknown>).secret_output_declared_by, undefined);
  assert.equal(job.spec.secret_output_by, "tool_manifest");
  assert.equal(job.sensitive?.declared, "tool_manifest");
  const flagged = await submitted(svc, "a1", { kind: "command", command: "true", secret_output: true });
  assert.equal((await jobView(S, flagged)).secret_output_by, undefined, "the agent's own flag is not the manifest's");
  await svc.stop("test over");
});

test("a recipe accepted without the key is not run once its manifest carries one: the run script re-checks the recipe branch too", async () => {
  const { S, svc } = await make();
  const target = join(S, "inputs", "f.bin");
  await writeFile(target, "x");
  const rbody = "import sys,os\nopen(os.path.join(sys.argv[sys.argv.index('--out')+1],'v.txt'),'w').write('VAL')\n";
  await addTool(S, "rec_late", { recipe: true }, {}, rbody);
  const r = await svc.submit("a1", { kind: "recipe", recipe: "tool:rec_late", target: { paths: [target], name: "f.bin" }, inputs: ["all"], timeout_seconds: 60, network: "off" } as never);
  assert.ok(r.ok, r.ok ? "" : r.reason);
  const job = await until(svc, r.job.id);
  const man = JSON.parse(await readFile(join(S, "tools", "rec_late", "manifest.json"), "utf8"));
  await writeFile(join(S, "tools", "rec_late", "manifest.json"), JSON.stringify({ ...man, secret_output: "required" }));
  await assert.rejects(svc.workerSpecFor(job, join(S, "..", "rerun-rec-late")), /secret_output.*tool jobs only/);
  await svc.stop("test over");
});

test("a manifest whose params has an entry that is not an object is refused, not a TypeError out of submit", async () => {
  const { S, svc } = await make();
  for (const [name, bad] of [["p_null", null], ["p_number", 5], ["p_string", "x"], ["p_list", ["type"]], ["p_true", true]] as const) {
    await addTool(S, name, {}, { fine: { type: "boolean" }, broken: bad });
    const reason = await refused(svc, { tool: name, args: {} });
    assert.match(reason, new RegExp(`tool ${name}: .*parameter broken is not an object`), name);
    // the same with the argument given, and with a declaration naming the good parameter
    const withArg = await refused(svc, { tool: name, args: { fine: true, broken: 1 } });
    assert.match(withArg, /parameter broken is not an object/, name);
  }
  assert.equal(svc.jobs.size, 0, "nothing was accepted");
  await svc.stop("test over");
});

test("make_tool never rewrites a tool that came from a pack or carries a declaration, even when the manifest names the forger as its author", async () => {
  const { S, svc } = await make();
  const forge = (agent: string, name: string) => P.forgeTool({ sandboxRoot: S, agentId: agent } as never, { name, description: "Replaces a tool.", runtime: "python3", script: "print(1)\n", params: {} });
  // a pack's tool, written by an id equal to the forger's
  await addTool(S, "pack_tool", { pack: "computer-forensics-base", by: "a1" });
  const before = await readFile(join(S, "tools", "pack_tool", "manifest.json"), "utf8");
  const r1 = await forge("a1", "pack_tool");
  assert.equal(r1.ok, false);
  assert.match(r1.ok ? "" : r1.reason, /packs or library/);
  assert.equal(await readFile(join(S, "tools", "pack_tool", "manifest.json"), "utf8"), before, "the manifest is as it was");
  assert.equal(await readFile(join(S, "tools", "pack_tool", "run.py"), "utf8"), PROBE, "so is the script");
  // a seeded tool with a declaration but no pack field
  await addTool(S, "decl_tool", { secret_output: "required", by: "a1" });
  const r2 = await forge("a1", "decl_tool");
  assert.equal(r2.ok, false);
  assert.equal(JSON.parse(await readFile(join(S, "tools", "decl_tool", "manifest.json"), "utf8")).secret_output, "required");
  // an agent's own tool is still its to update
  const own = await forge("a1", "own_tool");
  assert.ok(own.ok);
  const again = await forge("a1", "own_tool");
  assert.ok(again.ok);
  await svc.stop("test over");
});
