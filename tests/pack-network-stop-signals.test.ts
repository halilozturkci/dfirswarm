/**
 * network-forensics: a stop signal gives one JSON answer and leaves no hidden file, wherever it lands.
 *
 *  (a) A stop that arrives while a script is still importing (before main() installs its handlers) ends it with ONE document and exit
 *      128 + the signal, for the six tools and the recipe. A second signal that arrives during that answer starts no second one.
 *  (b) pcap_summary's and beacon_score's paging objects register their hidden `.<name>-*` file as it is made: a SIGTERM right after it is
 *      made, one just before it is moved onto its name, and a write that fails with EFBIG (a file size limit, SIGXFSZ ignored) leave no
 *      hidden file under tool-output.
 *  (c) network_log_summary installs its stop handler before it reads its arguments or opens its outputs.
 *
 * tests/network-signal-inject.py sends the signal at the point itself; a timer finds these windows only by luck. Every case here fails on
 * the scripts as they were before this change. The residual (the interpreter's own start) is measured, not tested: see the README.
 */
import assert from "node:assert/strict";
import { basename, join } from "node:path";
import { test } from "node:test";
import { BEACON, EXTRACT, LOGS, RECIPE, SUMMARY, SURICATA, ZEEK, drop, filesUnder, frameTcp4, pcapClassic, put, tool, TCP, withCwd } from "./pack-network-harness.ts";
import { ROOT, runPy } from "./tool-library-harness.ts";

const INJECT = join(ROOT, "tests", "network-signal-inject.py");
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Answer = Record<string, any>;

/** The JSON documents in a text: top-level objects, found by their braces (a string's braces do not count). */
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

async function inject(script: string, point: string, cwd: string, args: unknown, env: Record<string, string> = {}) {
  return runPy(INJECT, cwd, args, undefined, { AGENT_ID: "s1", ...env, INJECT_TOOL: script, INJECT_POINT: point });
}

async function hidden(cwd: string): Promise<string[]> {
  return (await filesUnder(join(cwd, "work"))).filter((f) => basename(f).startsWith("."));
}

const SCRIPTS: Array<[string, string]> = [
  ["zeek_run", ZEEK], ["suricata_run", SURICATA], ["pcap_extract", EXTRACT], ["network_log_summary", LOGS],
  ["pcap_summary", SUMMARY], ["beacon_score", BEACON], ["network-capture recipe", RECIPE],
];

for (const [name, script] of SCRIPTS) {
  test(`(a) ${name}: a stop during the imports gives one JSON answer and exit 143`, { timeout: 60_000 }, async () => {
    await withCwd(async (cwd) => {
      const run = await inject(script, "during_imports", cwd, {});
      assert.doesNotMatch(run.stderr, /Traceback|KeyboardInterrupt/, run.stderr);
      assert.equal(run.code, 143, `exit status (stdout: ${run.stdout.slice(0, 200)})`);
      const docs = documents(run.stdout);
      assert.equal(docs.length, 1, `${docs.length} documents`);
      assert.equal(docs[0].status, "partial");
      assert.equal(docs[0].ok, false);
      assert.equal(docs[0].interrupted_by_signal, 15);
      assert.match(docs[0].status_basis, /stopped by signal 15 before any work: nothing was read, started or written/);
    });
  });

  test(`(a) ${name}: a second signal during that answer starts no second one`, { timeout: 60_000 }, async () => {
    await withCwd(async (cwd) => {
      const run = await inject(script, "second_signal", cwd, {});
      assert.doesNotMatch(run.stderr, /Traceback|KeyboardInterrupt/, run.stderr);
      assert.equal(run.code, 143, "the first signal's exit status");
      assert.equal(documents(run.stdout).length, 1);
    });
  });
}

test("(a) a stop with SIGINT or SIGHUP during the imports is answered the same way, with its own exit status", { timeout: 60_000 }, async () => {
  await withCwd(async (cwd) => {
    for (const [signal, status, number] of [["SIGINT", 130, 2], ["SIGHUP", 129, 1]] as const) {
      const run = await inject(BEACON, "during_imports", cwd, {}, { INJECT_SIGNAL: signal });
      assert.doesNotMatch(run.stderr, /Traceback|KeyboardInterrupt/, run.stderr);
      assert.equal(run.code, status, signal);
      const docs = documents(run.stdout);
      assert.equal(docs.length, 1);
      assert.equal(docs[0].interrupted_by_signal, number);
    }
  });
});

/** A classic pcap of `n` packets from `n` distinct sources: top_talkers has `n` rows, so a page of 1 spills into a file. */
function manyTalkers(n: number): Buffer {
  return pcapClassic(Array.from({ length: n }, (_, i) => ({
    sec: 1_771_070_000 + i,
    frame: frameTcp4({ src: `10.1.${i >> 8}.${i & 255}`, dst: "192.0.2.9", sport: 40000 + (i % 1000), dport: 443, flags: TCP.ACK }),
  })));
}

const PAGING: Array<[string, string, (cwd: string) => Promise<unknown>]> = [
  ["pcap_summary", SUMMARY, async (cwd) => ({ path: await drop(cwd, "cap.pcap", manyTalkers(300)), top: 1 })],
  ["beacon_score", BEACON, async () => ({ timestamps: Array.from({ length: 300 }, (_, i) => 1_771_070_000 + i * 10), limit: 1 })],
];

for (const [name, script, args] of PAGING) {
  for (const point of ["after_tmp_open", "before_replace"]) {
    test(`(b) ${name}: SIGTERM at ${point} leaves one answer and no hidden file`, { timeout: 60_000 }, async () => {
      await withCwd(async (cwd) => {
        const run = await inject(script, point, cwd, await args(cwd));
        assert.doesNotMatch(run.stderr, /Traceback/, run.stderr);
        assert.equal(run.code, 143, `exit status (stdout: ${run.stdout.slice(0, 200)})`);
        const docs = documents(run.stdout);
        assert.equal(docs.length, 1);
        assert.equal(docs[0].status, "partial");
        assert.deepEqual(await hidden(cwd), [], "a hidden temporary file is left under tool-output");
      });
    });
  }

  test(`(b) ${name}: a write that fails with EFBIG (file size limit, SIGXFSZ ignored) leaves a JSON refusal and no hidden file`, { timeout: 60_000 }, async () => {
    await withCwd(async (cwd) => {
      const run = await inject(script, "fsize", cwd, await args(cwd), { INJECT_FSIZE: "4096" });
      assert.doesNotMatch(run.stderr, /Traceback/, run.stderr);
      const docs = documents(run.stdout);
      assert.equal(docs.length, 1, run.stdout.slice(0, 300));
      assert.equal(docs[0].status, "failed", JSON.stringify(docs[0]).slice(0, 300));
      assert.match(docs[0].error, /could not be written/);
      assert.deepEqual(await hidden(cwd), [], "a hidden temporary file is left under tool-output");
    });
  });
}

test("(c) network_log_summary: a stop while the arguments are read, or after the output directory was made, is answered, with the stage", { timeout: 60_000 }, async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "access.log", '203.0.113.9 - - [10/Feb/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 12 "-" "curl/8"\n');
    const args = { path: "access.log", out_dir: "work/s1/out" };
    for (const [point, stage] of [["during_args", "checking its arguments"], ["after_makedirs", "opening its outputs"]]) {
      const run = await inject(LOGS, point, cwd, args);
      assert.doesNotMatch(run.stderr, /Traceback/, run.stderr);
      assert.equal(run.code, 143, `${point}: exit status (stdout: ${run.stdout.slice(0, 200)})`);
      const docs = documents(run.stdout);
      assert.equal(docs.length, 1, point);
      assert.equal(docs[0].status, "partial", point);
      assert.equal(docs[0].stage, stage, point);
      assert.equal(docs[0].interrupted_by_signal, 15);
    }
  });
});

test("the injector runs a tool to its end when no signal lands: the stop cases above are not passing on a tool that never ran", { timeout: 60_000 }, async () => {
  await withCwd(async (cwd) => {
    const run = await tool(BEACON, cwd, { timestamps: Array.from({ length: 300 }, (_, i) => 1_771_070_000 + i * 10), limit: 1 });
    assert.equal(run.code, 0, run.stderr);
    const out = JSON.parse(run.stdout);
    assert.equal(out.status, "complete");
    const kept = await filesUnder(join(cwd, "work"));
    assert.ok(kept.some((f) => /beacon_intervals-[0-9a-f]+\.jsonl$/.test(f) && !basename(f).startsWith(".")), kept.join(","));
    assert.deepEqual(await hidden(cwd), []);
  });
});
