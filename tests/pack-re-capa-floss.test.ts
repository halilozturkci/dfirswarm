/**
 * The capa-floss recipe, against STAND-INS. capa and FLOSS are not installed in this checkout's test environment, and
 * these tests do not pretend otherwise: each "engine" below is a shell script that prints a small JSON object of the shape the
 * recipe reads (a `rules` mapping for capa; any object for FLOSS) or fails in one specific way. They say nothing about what the
 * real programs print, and no case here claims they do. What the cases hold is the recipe's own contract:
 *   - an engine that is not installed, exits non-zero, is stopped at its time limit, or prints something that is not JSON is
 *     a named status of that engine and the recipe is partial or failed, never complete;
 *   - the recipe's status comes from exit codes and the shape of the output, not from a non-empty file;
 *   - no string and no matched feature is copied into coverage.json, index.tsv or matches.tsv;
 *   - every program runs in the recipe's own process group, and a group kill or a signal ends it with what it started;
 *   - a result an earlier run left in the directory is kept and named, never replaced.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFile, readdir, rm } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { RE, childrenOf, gone, pidFile, put, startDetached, stub, withCwd } from "./pack-re-harness.ts";
import type { Json } from "./pack-re-harness.ts";
import { buildPe } from "./pack-re-harness.ts";
import { canaries, needles } from "./pack-re-canary-shapes.ts";

const RECIPE_DIR = join(RE, "recipes", "capa-floss");
const CAPA_FLOSS = join(RECIPE_DIR, "run.py");
const PYTHON = spawnSync("python3", ["-c", "import sys; print(sys.executable)"], { encoding: "utf8" }).stdout.trim();
const PLANTED = "PLANTED-STRING-never-in-an-index";

const CAPA_JSON = JSON.stringify({
  meta: { version: "stand-in", analysis: { format: "pe" } },
  rules: {
    "create mutex": { meta: { namespace: "host-interaction/mutex", attack: [{ id: "T1000", technique: "x" }] }, matches: [[4096, { feature: PLANTED }], [4200, {}]] },
    "other thing": { meta: { namespace: "data-manipulation/x" }, matches: { "8192": {} } },
  },
});
const FLOSS_JSON = JSON.stringify({ analysis: { enable_static_strings: true }, strings: { static_strings: [PLANTED, "second"], stack_strings: [], decoded_strings: [PLANTED] } });

async function engines(bin: string, o: { capa?: string | null; floss?: string | null } = {}): Promise<void> {
  const body = (json: string): string => `if [ "$1" = "--version" ]; then echo "stand-in 0.0 (not the real program)"; exit 0; fi\ncat <<'JSON'\n${json}\nJSON\n`;
  if (o.capa !== null) await stub(bin, "capa", o.capa ?? body(CAPA_JSON));
  if (o.floss !== null) await stub(bin, "floss", o.floss ?? body(FLOSS_JSON));
}

function recipe(cwd: string, bin: string | null, args: string[], sample = "inputs/s.exe", extraEnv: Record<string, string> = {}): { status: number | null; stdout: string; stderr: string } {
  const PATH = bin ? `${bin}:/usr/bin:/bin` : "/usr/bin:/bin";
  const r = spawnSync(PYTHON, [CAPA_FLOSS, ...args.map((a) => (a === "TARGET" ? JSON.stringify({ paths: [sample] }) : a))], { cwd, encoding: "utf8", env: { ...process.env, PATH, ...extraEnv } });
  return { status: r.status, stdout: r.stdout, stderr: r.stderr };
}

async function sample(cwd: string): Promise<void> {
  await put(cwd, "inputs/s.exe", buildPe({}).file);
}

const coverage = async (out: string): Promise<Json> => JSON.parse(await readFile(join(out, "coverage.json"), "utf8"));

test("detect: a PE and an ELF are offered; Mach-O, a Java class, a coincident MZ and a short ELF are not", async () => {
  await withCwd(async (cwd) => {
    const cases: Array<[string, Buffer, boolean]> = [
      ["pe.exe", buildPe({}).file, true],
      ["elf", Buffer.concat([Buffer.from("7f454c46020101", "hex"), Buffer.alloc(100)]), true],
      ["macho", Buffer.concat([Buffer.from("cffaedfe", "hex"), Buffer.alloc(100)]), false],
      ["java.class", Buffer.concat([Buffer.from("cafebabe00000034", "hex"), Buffer.alloc(100)]), false],
      ["mz.bin", Buffer.concat([Buffer.from("MZ"), Buffer.alloc(200)]), false],
      ["short.elf", Buffer.from("7f454c46020101", "hex"), false],
    ];
    for (const [name, data, applies] of cases) {
      await put(cwd, `inputs/${name}`, data);
      const r = recipe(cwd, null, ["detect", "--target", "TARGET"], `inputs/${name}`);
      assert.equal(JSON.parse(r.stdout).applies, applies, name);
      assert.equal(r.status, applies ? 0 : 1, name);
    }
  });
});

test("both engines ran and exited 0: complete, with each engine's argv, version output, exit code and size, and matches.tsv from the rules mapping", async () => {
  await withCwd(async (cwd, bin) => {
    await engines(bin);
    await sample(cwd);
    const out = join(cwd, "catalog");
    const r = recipe(cwd, bin, ["run", "--target", "TARGET", "--out", out]);
    assert.equal(r.status, 0, r.stderr + r.stdout);
    const c = await coverage(out);
    assert.equal(c.status, "complete", JSON.stringify(c));
    assert.equal(c.format, "PE");
    assert.deepEqual(c.engines.capa.argv, ["capa", "-j", "<sample>"]);
    assert.equal(c.engines.capa.version_command.first_line, "stand-in 0.0 (not the real program)");
    assert.equal(c.engines.capa.exit_code, 0);
    assert.equal(c.engines.capa.rules_matched, 2);
    assert.equal(c.engines.capa.reported_version, "stand-in");
    assert.deepEqual(c.engines.floss.string_kinds, { static_strings: 2, stack_strings: 0, decoded_strings: 1 });
    assert.deepEqual(c.errors, []);
    const matches = (await readFile(join(out, "matches.tsv"), "utf8")).trim().split("\n");
    assert.deepEqual(matches, ["rule\tnamespace\tattack_ids\tmatches", "create mutex\thost-interaction/mutex\tT1000\t2", "other thing\tdata-manipulation/x\t\t1"]);
    // The whole output of each engine is a file exactly as the program wrote it; the indexes and the receipt copy no string.
    assert.ok((await readFile(join(out, "capa.json"), "utf8")).includes(PLANTED));
    assert.ok((await readFile(join(out, "floss.json"), "utf8")).includes(PLANTED));
    for (const f of ["coverage.json", "index.tsv", "matches.tsv"]) assert.ok(!(await readFile(join(out, f), "utf8")).includes(PLANTED), `${f} copies a string`);
    assert.deepEqual(c.sensitive_outputs, ["capa.json", "floss.json"]);
    const index = await readFile(join(out, "index.tsv"), "utf8");
    assert.match(index, /^capa\.json\tcapa output, whole, exactly as the program wrote it \(status complete\)$/m);
    assert.deepEqual(JSON.parse(r.stdout), { ok: true, status: "complete", format: "PE", coverage: "coverage.json", index: "index.tsv" });
  });
});

test("an engine that is not installed is 'unavailable', not skipped: the recipe is partial with the other engine, failed with neither", async () => {
  await withCwd(async (cwd, bin) => {
    await sample(cwd);
    await engines(bin, { capa: null });
    const out = join(cwd, "catalog");
    const r = recipe(cwd, bin, ["run", "--target", "TARGET", "--out", out]);
    assert.equal(r.status, 0, r.stderr + r.stdout);
    const c = await coverage(out);
    assert.equal(c.status, "partial");
    assert.equal(c.engines.capa.status, "unavailable");
    assert.equal(c.engines.capa.installed, false);
    assert.match(c.errors.join(" "), /capa unavailable: capa is not on PATH/);
    assert.equal(c.engines.floss.status, "complete");
    // Neither installed.
    const empty = join(cwd, "bin2");
    await put(cwd, "bin2/.keep", "");
    const out2 = join(cwd, "catalog2");
    const r2 = recipe(cwd, empty, ["run", "--target", "TARGET", "--out", out2]);
    assert.equal(r2.status, 2);
    const c2 = await coverage(out2);
    assert.equal(c2.status, "failed");
    assert.deepEqual([c2.engines.capa.status, c2.engines.floss.status], ["unavailable", "unavailable"]);
  });
});

test("an engine that exits non-zero, prints something that is not JSON, or prints JSON the recipe does not read, is judged by that, and its output is kept whole", async () => {
  await withCwd(async (cwd, bin) => {
    await sample(cwd);
    const out = join(cwd, "c1");
    // capa fails with stderr; floss prints text.
    await engines(bin, { capa: 'if [ "$1" = "--version" ]; then echo v; exit 0; fi\necho "usage: capa [options]" >&2\necho \'{"rules": {}}\'\nexit 2', floss: 'if [ "$1" = "--version" ]; then echo v; exit 0; fi\necho "not json at all"' });
    const r = recipe(cwd, bin, ["run", "--target", "TARGET", "--out", out]);
    assert.equal(r.status, 2, "no engine gave a usable result");
    const c = await coverage(out);
    assert.equal(c.status, "failed");
    assert.equal(c.engines.capa.status, "failed");
    assert.match(c.engines.capa.reason, /exited with status 2; its stderr is kept/, "exit status wins over a JSON body");
    assert.match(c.engines.floss.reason, /exited 0 and its output is not a readable JSON object: not JSON/);
    assert.equal(await readFile(join(out, "capa.stderr"), "utf8"), "usage: capa [options]\n");
    assert.equal(await readFile(join(out, "floss.json"), "utf8"), "not json at all\n");
    assert.equal((await readdir(out)).includes("matches.tsv"), false, "no matches table from a failed engine");
    // capa prints JSON with no rules mapping: partial, kept, and the keys it did print are named.
    const out2 = join(cwd, "c2");
    await engines(bin, { capa: 'if [ "$1" = "--version" ]; then echo v; exit 0; fi\necho \'{"meta": {}, "signatures": []}\'' });
    recipe(cwd, bin, ["run", "--target", "TARGET", "--out", out2]);
    const c2 = await coverage(out2);
    assert.equal(c2.engines.capa.status, "partial");
    assert.deepEqual(c2.engines.capa.keys, ["meta", "signatures"]);
    assert.equal(c2.status, "partial");
    assert.ok(c2.warnings.some((w: string) => /capa partial: capa's JSON has no `rules` mapping/.test(w)));
  });
});

test("a zero exit code with an empty output is a failure, not a clean file", async () => {
  await withCwd(async (cwd, bin) => {
    await sample(cwd);
    await engines(bin, { capa: 'if [ "$1" = "--version" ]; then echo v; exit 0; fi\nexit 0', floss: 'if [ "$1" = "--version" ]; then echo v; exit 0; fi\nexit 0' });
    const out = join(cwd, "catalog");
    recipe(cwd, bin, ["run", "--target", "TARGET", "--out", out]);
    const c = await coverage(out);
    assert.equal(c.status, "failed");
    assert.match(c.engines.capa.reason, /output is not a readable JSON object/);
  });
});

test("an engine stopped at its time limit is a failure of that engine, named, and the program and what it started are gone", async () => {
  await withCwd(async (cwd, bin) => {
    await sample(cwd);
    await put(cwd, "pids/.keep", "");
    await engines(bin, { capa: `if [ "$1" = "--version" ]; then echo v; exit 0; fi\necho $$ > "$PIDS/capa.pid"\nsleep 60 &\necho $! > "$PIDS/child.pid"\nwait`, floss: null });
    const out = join(cwd, "catalog");
    const r = recipe(cwd, bin, ["run", "--target", "TARGET", "--out", out, "--seconds", "3"], "inputs/s.exe", { PIDS: join(cwd, "pids") });
    assert.equal(r.status, 2);
    const c = await coverage(out);
    assert.equal(c.engines.capa.status, "failed");
    assert.equal(c.engines.capa.timed_out, true);
    assert.match(c.engines.capa.reason, /was stopped at its time limit/);
    assert.ok(c.limits_hit.some((l: string) => /capa was stopped at its time limit/.test(l)));
    for (const f of ["capa.pid", "child.pid"]) assert.equal(await gone(await pidFile(join(cwd, "pids", f))), true, `${f} outlived the deadline`);
  });
});

test("the harness kills the recipe's process group: the engine and what it started end with it; SIGTERM ends them and leaves a receipt that says the recipe was stopped", async () => {
  await withCwd(async (cwd, bin) => {
    await sample(cwd);
    await put(cwd, "pids/.keep", "");
    await engines(bin, { capa: `if [ "$1" = "--version" ]; then echo v; exit 0; fi\necho $$ > "$PIDS/capa.pid"\nsleep 60 &\necho $! > "$PIDS/child.pid"\nwait`, floss: null });
    const out = join(cwd, "catalog");
    const argv = ["run", "--target", JSON.stringify({ paths: [join(cwd, "inputs/s.exe")] }), "--out", out];
    const run = startDetached(CAPA_FLOSS, cwd, {}, { PIDS: join(cwd, "pids") }, bin, argv);
    const capa = await pidFile(join(cwd, "pids", "capa.pid"));
    const child = await pidFile(join(cwd, "pids", "child.pid"));
    assert.ok(childrenOf(run.pid).includes(capa), "the engine is a child of the recipe, in its group");
    run.killGroup();
    await run.closed;
    assert.equal(await gone(capa), true, "the engine survived the group kill");
    assert.equal(await gone(child), true, "what the engine started survived");
    assert.notEqual((await coverage(out)).status, "complete", "a receipt from the first moment says the recipe did not finish");
    // SIGTERM
    const out2 = join(cwd, "catalog2");
    // the first run's pid file goes first: read again at once, it named the engine of the first run, and the signal could reach the
    // second recipe before it had started its engine (or its handlers)
    await rm(join(cwd, "pids", "capa.pid"), { force: true });
    const run2 = startDetached(CAPA_FLOSS, cwd, {}, { PIDS: join(cwd, "pids") }, bin, ["run", "--target", JSON.stringify({ paths: [join(cwd, "inputs/s.exe")] }), "--out", out2]);
    const capa2 = await pidFile(join(cwd, "pids", "capa.pid"));
    await new Promise((r) => setTimeout(r, 300));
    run2.signal("SIGTERM");
    const code = await run2.closed;
    assert.ok(code !== 0 && code !== null);
    assert.equal(await gone(capa2), true);
    const c = await coverage(out2);
    assert.ok(c.errors.some((e: string) => /stopped by signal 15/.test(e)), JSON.stringify(c.errors));
  });
});

test("a result an earlier run left in the directory is kept and named, and the new one is written under new names: its receipt too (lesson 5)", async () => {
  await withCwd(async (cwd, bin) => {
    await engines(bin);
    await sample(cwd);
    const out = join(cwd, "catalog");
    recipe(cwd, bin, ["run", "--target", "TARGET", "--out", out]);
    const first = await readFile(join(out, "capa.json"), "utf8");
    const receipt = await readFile(join(out, "coverage.json"), "utf8");
    const index = await readFile(join(out, "index.tsv"), "utf8");
    const again = recipe(cwd, bin, ["run", "--target", "TARGET", "--out", out]);
    assert.equal(await readFile(join(out, "capa.json"), "utf8"), first, "the earlier file is untouched");
    assert.equal(await readFile(join(out, "coverage.json"), "utf8"), receipt, "the earlier receipt is untouched");
    assert.equal(await readFile(join(out, "index.tsv"), "utf8"), index, "the earlier index is untouched");
    const files = await readdir(out);
    assert.ok(files.includes("capa-2.json") && files.includes("floss-2.json") && files.includes("matches-2.tsv") && files.includes("coverage-2.json") && files.includes("index-2.tsv"), files.join(","));
    assert.deepEqual({ coverage: JSON.parse(again.stdout).coverage, index: JSON.parse(again.stdout).index }, { coverage: "coverage-2.json", index: "index-2.tsv" });
    const c = JSON.parse(await readFile(join(out, "coverage-2.json"), "utf8"));
    assert.equal(c.engines.capa.file, "capa-2.json");
    const index2 = await readFile(join(out, "index-2.tsv"), "utf8");
    for (const name of ["capa.json", "coverage.json", "index.tsv"]) assert.match(index2, new RegExp(`^${name.replace(".", "\\.")}\tleft by an earlier run in this directory; kept, and not part of this result$`, "m"));
  });
});

test("an engine on PATH that cannot be executed (ENOEXEC) is a named failure of that engine, and the receipt is final, never 'started and has not finished'", async () => {
  await withCwd(async (cwd, bin) => {
    await sample(cwd);
    await engines(bin);
    // Not a program: no #! line and no executable format, so execve answers ENOEXEC.
    await put(cwd, "bin/capa", Buffer.from([0x00, 0x01, 0x02, 0x03, 0x7f, 0x45, 0x00]), 0o755);
    const out = join(cwd, "catalog");
    const r = recipe(cwd, bin, ["run", "--target", "TARGET", "--out", out]);
    assert.doesNotMatch(r.stderr, /Traceback/);
    assert.equal(r.status, 0, "floss gave a usable result: partial");
    const c = await coverage(out);
    assert.equal(c.status, "partial");
    assert.equal(c.engines.capa.status, "failed");
    assert.match(c.engines.capa.reason, /capa could not be started: (OSError|PermissionError).*(Exec format error|ENOEXEC|Permission denied)/);
    assert.equal(c.engines.floss.status, "complete");
    assert.ok(!c.errors.some((e: string) => /has not finished/.test(e)), JSON.stringify(c.errors));
  });
});

test("floss JSON with no strings mapping of the kinds the recipe reads is partial, not complete; the rule set and floss's analysis flags are recorded", async () => {
  await withCwd(async (cwd, bin) => {
    await sample(cwd);
    const capa = JSON.stringify({ meta: { version: "stand-in", analysis: { rules: ["/opt/capa-rules"] } }, rules: {} });
    const say = (json: string): string => `if [ "$1" = "--version" ]; then echo v; exit 0; fi\ncat <<'JSON'\n${json}\nJSON\n`;
    await engines(bin, { capa: say(capa), floss: say('{"error": "x"}') });
    const out = join(cwd, "catalog");
    recipe(cwd, bin, ["run", "--target", "TARGET", "--out", out]);
    const c = await coverage(out);
    assert.equal(c.engines.floss.status, "partial");
    assert.match(c.engines.floss.reason, /no `strings` mapping/);
    assert.equal(c.status, "partial");
    assert.deepEqual(c.engines.capa.rule_sets, ["/opt/capa-rules"]);
    const out2 = join(cwd, "catalog2");
    await engines(bin, { floss: say(JSON.stringify({ analysis: { enable_static_strings: true, enable_stack_strings: false }, strings: { other: [] } })) });
    recipe(cwd, bin, ["run", "--target", "TARGET", "--out", out2]);
    const c2 = await coverage(out2);
    assert.equal(c2.engines.floss.status, "partial");
    assert.match(c2.engines.floss.reason, /holds none of the string kinds this recipe reads/);
    assert.deepEqual(c2.engines.floss.analysis_enabled, { enable_stack_strings: false, enable_static_strings: true });
  });
});

test("a target that is not a PE or an ELF is 'unsupported' with a receipt, and no engine is run", async () => {
  await withCwd(async (cwd, bin) => {
    await engines(bin);
    await put(cwd, "inputs/x.bin", Buffer.alloc(200, 7));
    const out = join(cwd, "catalog");
    const r = recipe(cwd, bin, ["run", "--target", "TARGET", "--out", out], "inputs/x.bin");
    assert.equal(r.status, 2);
    const c = await coverage(out);
    assert.equal(c.status, "unsupported");
    assert.deepEqual((await readdir(out)).sort(), ["coverage.json"]);
    // bad arguments are JSON, not a trace
    for (const args of [[], ["run"], ["run", "--target", "{}"], ["run", "--target", "TARGET", "--out", out, "--seconds", "0"], ["nonsense"]]) {
      const bad = recipe(cwd, bin, args);
      assert.doesNotMatch(bad.stderr, /Traceback/);
      assert.equal(JSON.parse(bad.stdout).ok, false);
    }
  });
});

test("a path with a token-shaped component is withheld in the receipt", async () => {
  await withCwd(async (cwd, bin) => {
    await engines(bin);
    const dir = "Zk9mQ2xW7vB3nL8pR4tY6wD1sFgHjK";
    await put(cwd, `inputs/${dir}/s.exe`, buildPe({}).file);
    const out = join(cwd, "catalog");
    recipe(cwd, bin, ["run", "--target", "TARGET", "--out", out], `inputs/${dir}/s.exe`);
    const text = await readFile(join(out, "coverage.json"), "utf8");
    assert.ok(!text.includes(dir));
    assert.match(JSON.parse(text).target, /^inputs\/<token-shaped text withheld 30 characters>\/s\.exe$/);
  });
});

test("a first run's index.tsv names its own receipt as this run's, and lists nothing as left by an earlier run; a second run's lists the first run's files", async () => {
  await withCwd(async (cwd, bin) => {
    await engines(bin);
    await sample(cwd);
    const out = join(cwd, "catalog");
    recipe(cwd, bin, ["run", "--target", "TARGET", "--out", out]);
    const index = await readFile(join(out, "index.tsv"), "utf8");
    assert.doesNotMatch(index, /left by an earlier run/, index);
    assert.match(index, /^coverage\.json\tthis run's receipt/m);
    assert.match(index, /^index\.tsv\tthis run's index/m);
    recipe(cwd, bin, ["run", "--target", "TARGET", "--out", out]);
    const index2 = await readFile(join(out, "index-2.tsv"), "utf8");
    assert.match(index2, /^coverage-2\.json\tthis run's receipt/m);
    assert.doesNotMatch(index2, /^(coverage-2\.json|index-2\.tsv)\tleft by an earlier run/m);
    assert.match(index2, /^coverage\.json\tleft by an earlier run/m);
  });
});

test("an engine's text is withheld whole and then cut: a token across the cut leaves no head of it; the keys an engine's JSON names are withheld", async () => {
  await withCwd(async (cwd, bin) => {
    await sample(cwd);
    const token = "ghp_Ab3dEf5hIj7lMn9pQr1tUv3xYz5bCd7fGh9j";
    const line = "v ".repeat(96) + token;            // the 200-character cut falls inside the token
    const capa = JSON.stringify({ meta: { version: "w ".repeat(26) + token, [token]: 1, analysis: { rules: ["/r"] } }, rules: {}, [token + "x"]: 2 });
    const floss = JSON.stringify({ analysis: { ["enable_" + token]: true }, strings: { static_strings: [], [token]: [] }, [token]: 1 });
    const say = (json: string): string => `if [ "$1" = "--version" ]; then echo '${line}'; exit 0; fi\ncat <<'JSON'\n${json}\nJSON\n`;
    await engines(bin, { capa: say(capa), floss: say(floss) });
    const out = join(cwd, "catalog");
    recipe(cwd, bin, ["run", "--target", "TARGET", "--out", out]);
    for (const name of ["coverage.json", "index.tsv"]) {
      const text = await readFile(join(out, name), "utf8");
      for (let i = 0; i + 9 <= token.length; i++) assert.ok(!text.includes(token.slice(i, i + 9)), `${name}: '${token.slice(i, i + 9)}'`);
    }
    const c = await coverage(out);
    assert.match(c.engines.capa.version_command.first_line, /^(v )+<tok/);
    assert.ok(Object.keys(c.engines.floss.analysis_enabled).every((k) => /withheld/.test(k)));
  });
});

test("every shape the one way out withholds, in capa's rule set paths, rule names and namespaces and in a path of the target: none reaches the receipt, the index or matches.tsv", async () => {
  await withCwd(async (cwd, bin) => {
    await sample(cwd);
    const all = canaries(200, 9).map(([, c]) => c);
    const capa = JSON.stringify({
      meta: { version: "stand-in", analysis: { rules: all.map((c) => `/opt/rules/${c.plant}`) } },
      rules: Object.fromEntries(all.map((c, i) => [`rule ${i} ${c.plant}`, { meta: { namespace: `ns/${c.plant}`, attack: [{ id: c.plant }] }, matches: [[4096, {}]] }])),
    });
    const say = (json: string): string => `if [ "$1" = "--version" ]; then echo v; exit 0; fi\ncat <<'JSON'\n${json}\nJSON\n`;
    await engines(bin, { capa: say(capa) });
    const out = join(cwd, "catalog");
    recipe(cwd, bin, ["run", "--target", "TARGET", "--out", out]);
    const c = await coverage(out);
    assert.equal(c.withheld_by_final_check, undefined, "the sanitiser withheld every shape: the backstop caught nothing");
    assert.equal(c.engines.capa.rule_sets.length, all.length);
    for (const name of ["coverage.json", "index.tsv", "matches.tsv"]) {
      const text = await readFile(join(out, name));
      for (const cn of all) for (const n of needles(cn)) assert.ok(!text.includes(n.bytes), `${name}: ${n.label}`);
    }
  });
});

test("floss with a string kind whose analysis its own flags say was off (a .NET-style run) is partial: an empty list of a kind that was not run is not 'none found'", async () => {
  await withCwd(async (cwd, bin) => {
    await sample(cwd);
    const floss = JSON.stringify({ analysis: { enable_static_strings: true, enable_stack_strings: false, enable_tight_strings: false, enable_decoded_strings: false },
      strings: { static_strings: ["a"], stack_strings: [], tight_strings: [], decoded_strings: [] } });
    const say = (json: string): string => `if [ "$1" = "--version" ]; then echo v; exit 0; fi\ncat <<'JSON'\n${json}\nJSON\n`;
    await engines(bin, { floss: say(floss) });
    const out = join(cwd, "catalog");
    recipe(cwd, bin, ["run", "--target", "TARGET", "--out", out]);
    const c = await coverage(out);
    assert.equal(c.engines.floss.status, "partial", JSON.stringify(c.engines.floss));
    assert.deepEqual(c.engines.floss.kinds_not_run, ["stack_strings", "tight_strings", "decoded_strings"]);
    assert.match(c.engines.floss.reason, /were not run .*the kinds that ran: static_strings/);
    assert.equal(c.status, "partial");
    // every kind enabled: complete, as before
    const out2 = join(cwd, "catalog2");
    await engines(bin, { floss: say(JSON.stringify({ analysis: { enable_static_strings: true, enable_stack_strings: true, enable_tight_strings: true, enable_decoded_strings: true }, strings: { static_strings: [], stack_strings: [], tight_strings: [], decoded_strings: [] } })) });
    recipe(cwd, bin, ["run", "--target", "TARGET", "--out", out2]);
    assert.equal((await coverage(out2)).engines.floss.status, "complete");
  });
});

// --- the fourth review ------------------------------------------------------------------------------------------------------------

test("the backstop's count is of this receipt's fields: with the sanitiser of engine text taken out, two planted version lines are two, not one per rewrite of the receipt", async () => {
  await withCwd(async (cwd, bin) => {
    const t1 = "ghp_" + "Ab3dEf5hIj7lMn9pQr1tUv3xYz5bCd7fGh9j", t2 = "ghp_" + "Zz9yXw8vUt7sRq6pOn5mLk4jIh3gFe2dCb1a";
    const ver = (tok: string, json: string): string => `if [ "$1" = "--version" ]; then echo "${tok}"; exit 0; fi\ncat <<'JSON'\n${json}\nJSON\n`;
    await engines(bin, { capa: ver(t1, CAPA_JSON), floss: ver(t2, FLOSS_JSON) });
    await sample(cwd);
    const out = join(cwd, "catalog");
    const code = ["import importlib.util, sys", "spec = importlib.util.spec_from_file_location('r', sys.argv[1])", "m = importlib.util.module_from_spec(spec)",
      "spec.loader.exec_module(m)", "m.shown_text = lambda text, keep: m.cell(text)[:keep]", "sys.exit(m.main(['run.py'] + sys.argv[2:]))"].join("\n");
    const r = spawnSync(PYTHON, ["-c", code, CAPA_FLOSS, "run", "--target", JSON.stringify({ paths: ["inputs/s.exe"] }), "--out", out], { cwd, encoding: "utf8", env: { ...process.env, PATH: `${bin}:/usr/bin:/bin` } });
    assert.doesNotMatch(r.stderr, /Traceback/, r.stderr);
    const raw = await readFile(join(out, "coverage.json"), "utf8");
    const c = JSON.parse(raw) as Json;
    assert.equal((raw.match(/<withheld by the final check: /g) ?? []).length, 2, raw);
    assert.equal(c.withheld_by_final_check, 2);
    assert.equal(c.status, "partial");
    for (const tok of [t1, t2]) assert.ok(!raw.includes(tok.slice(4, 13)), "a token reached the receipt");
  });
});

test("an --out that cannot be written is a JSON failure, not a traceback", async () => {
  await withCwd(async (cwd, bin) => {
    await engines(bin);
    await sample(cwd);
    await put(cwd, "ro/.keep", "");
    const { chmod } = await import("node:fs/promises");
    await chmod(join(cwd, "ro"), 0o500);
    try {
      const r = recipe(cwd, bin, ["run", "--target", "TARGET", "--out", join(cwd, "ro", "catalog")]);
      if (process.getuid?.() === 0) return; // root writes anywhere: nothing to test
      assert.doesNotMatch(r.stderr, /Traceback/, r.stderr);
      const o = JSON.parse(r.stdout) as Json;
      assert.equal(o.ok, false);
      assert.match(o.error, /the output directory cannot be written/);
    } finally {
      await chmod(join(cwd, "ro"), 0o700);
    }
  });
});

test("an engine's JSON larger than the recipe reads (32 MiB: parsed JSON takes up to about twenty-five times its size) is kept whole and the engine is partial, not read", async () => {
  await withCwd(async (cwd, bin) => {
    const big = `if [ "$1" = "--version" ]; then echo "stand-in"; exit 0; fi\n${PYTHON} -c "import sys; sys.stdout.write('{\\"rules\\": {}, \\"pad\\": \\"' + 'a' * (33 << 20) + '\\"}')"\n`;
    await engines(bin, { capa: big });
    await sample(cwd);
    const out = join(cwd, "catalog");
    const r = recipe(cwd, bin, ["run", "--target", "TARGET", "--out", out]);
    assert.doesNotMatch(r.stderr, /Traceback/, r.stderr);
    const c = await coverage(out);
    assert.equal(c.engines.capa.status, "partial", JSON.stringify(c.engines.capa));
    assert.match(c.engines.capa.reason, /larger than 33554432 bytes: kept whole, not read here/);
    assert.ok(c.engines.capa.bytes > 33 << 20);
  });
});
