/**
 * prefetch_mam and mam_scan against the tool contract (docs/packs.md, section 8), with the helpers of tests/windows-tool-contract.ts. What only these
 * two can show is the decoder: it is pure Python (LZXPRESS-Huffman, about two seconds a megabyte), a MAM stream may declare 64 MiB, and the tool's
 * own clock has to stop it inside a match, with a partial answer that says how much was inflated and no field read from a short inflate.
 *
 * The inflate cases run against the suite's stand-in for dissect.util (tests/windows-stub-dissect.ts, held to the real library by
 * tests/pack-windows-forensics-prefetch.test.ts) always, and against dissect.util where it is installed. Streams are written by the suite's own
 * encoder from the format (MS-XCA), never by a tool.
 *
 * Red check: WINDOWS_PACK_TOOLS=<a copy of the tools before the fixes> node --experimental-strip-types --test tests/pack-windows-forensics-prefetch-contract.test.ts
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { withCwd } from "./tool-library-harness.ts";
import { DISSECT, WIN, stubModule } from "./windows-pack-harness.ts";
import { DISSECT_STAND_IN } from "./windows-stub-dissect.ts";
import { mam, mamOf, sample, xpressHuffman } from "./windows-prefetch-fixtures.ts";
import {
  STOP_STATUS, SIGNAL_NUMBER, assertJsonAnswer, assertStopped, fuzzTool, manifestOf, outputDirs, rerunSmaller, runTool, startTool, stopAt, typeConfused, withDeadline,
  type StopRun, type StopSignal,
} from "./windows-tool-contract.ts";

const SIGNALS: StopSignal[] = ["SIGTERM", "SIGINT", "SIGHUP"];
type Answer = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any
type Decoder = { name: string; skip: string | false; env: (cwd: string) => Promise<Record<string, string>> };
const DECODERS: Decoder[] = [
  { name: "stand-in decoder", skip: false, env: (cwd) => stubModule(cwd, DISSECT_STAND_IN) },
  { name: "dissect.util", skip: DISSECT, env: async () => ({}) },
];
const MIB = 1024 * 1024;

function each(title: string, fn: (decoder: Decoder) => Promise<void>): void {
  for (const d of DECODERS) test(`${title} [${d.name}]`, { skip: d.skip }, () => fn(d));
}

const put = (cwd: string, rel: string, bytes: Buffer): string => {
  mkdirSync(join(cwd, rel, ".."), { recursive: true });
  writeFileSync(join(cwd, rel), bytes);
  return rel;
};

/** A MAM stream that declares `megabytes` MiB and holds that much in matches of 17 bytes (a literal first, then matches of offset 1): the inflate of it is long. */
function bigStream(megabytes: number): Buffer {
  const total = megabytes * MIB;
  const ops: Array<number | { match: number }> = [0x41];
  let size = 1;
  while (size + 17 <= total) {
    ops.push({ match: 17 });
    size += 17;
  }
  while (size < total) {
    ops.push(0x42);
    size += 1;
  }
  return mam(total, xpressHuffman(ops));
}

// --- the clock inside the inflate ---------------------------------------------------------------------------------------------------------

each("prefetch_mam: a MAM stream that declares 64 MiB, with a deadline of zero, answers partial and names what was inflated", async (d) => {
  await withCwd(async (cwd) => {
    const env = await d.env(cwd);
    const path = put(cwd, "work/big.pf", bigStream(64));
    const started = Date.now();
    const answer = assertJsonAnswer(await runTool(withDeadline("prefetch_mam", 0), cwd, { path }, env), "prefetch_mam") as Answer;
    assert.ok(Date.now() - started < 15_000, `${Date.now() - started} ms`);
    assert.equal(answer.status, "partial");
    assert.match(String(answer.status_basis), /clock/);
    assert.match(String(answer.status_basis), /of the declared 67108864 bytes/);
    assert.equal(answer.stopped_by_time_limit, true);
    assert.ok(Number.isInteger(answer.bytes_inflated) && answer.bytes_inflated < 64 * MIB);
    assert.equal(answer.exe_name, undefined, "no field is read from a short inflate");
  });
});

each("prefetch_mam: a clock of two seconds stops a 64 MiB inflate inside the clock, not after it", async (d) => {
  await withCwd(async (cwd) => {
    const env = await d.env(cwd);
    const path = put(cwd, "work/big.pf", bigStream(64));
    const started = Date.now();
    const answer = assertJsonAnswer(await runTool(withDeadline("prefetch_mam", 2), cwd, { path }, env), "2 s") as Answer;
    const took = Date.now() - started;
    assert.equal(answer.status, "partial");
    assert.ok(took < 20_000, `${took} ms for a clock of 2 s`);
    console.log(`prefetch_mam [${d.name}] 64 MiB stream, clock 2 s: partial after ${took} ms, ${answer.bytes_inflated} bytes inflated`);
  });
});

each("mam_scan: a candidate that declares 64 MiB, with a deadline of zero, answers partial and counts it as neither parsed nor failed", async (d) => {
  await withCwd(async (cwd) => {
    const env = await d.env(cwd);
    const path = put(cwd, "work/dump.bin", Buffer.concat([Buffer.alloc(4096, 0x20), bigStream(64), Buffer.alloc(4096, 0x20)]));
    const answer = assertJsonAnswer(await runTool(withDeadline("mam_scan", 0), cwd, { path, max_uncomp: 64 * MIB }, env), "mam_scan") as Answer;
    assert.equal(answer.status, "partial");
    assert.match(String(answer.status_basis), /clock/);
    assert.equal(answer.stopped_by_time_limit, true);
    assert.equal(answer.parsed, 0);
    assert.equal(answer.failed, 0);
  });
});

each("mam_scan: a clock of three seconds stops the inflate of a 64 MiB candidate inside the clock", async (d) => {
  await withCwd(async (cwd) => {
    const env = await d.env(cwd);
    const path = put(cwd, "work/dump.bin", bigStream(64));
    const started = Date.now();
    const answer = assertJsonAnswer(await runTool(withDeadline("mam_scan", 3), cwd, { path, max_uncomp: 64 * MIB }, env), "3 s") as Answer;
    assert.equal(answer.status, "partial");
    assert.ok(Date.now() - started < 20_000, `${Date.now() - started} ms for a clock of 3 s`);
    assert.match(String(answer.status_basis), /inflated/);
  });
});

each("a stream that inflates short is never complete: prefetch_mam fails, mam_scan counts it failed and says partial", async (d) => {
  await withCwd(async (cwd) => {
    const env = await d.env(cwd);
    const plain = sample(30);
    const short = mam(plain.length + 500, xpressHuffman([...plain]));
    const one = await runTool("prefetch_mam", cwd, { path: put(cwd, "work/short.pf", short) }, env);
    assert.notEqual(one.code, 0);
    assert.equal(assertJsonAnswer(one, "short").status, "failed");
    const two = assertJsonAnswer(await runTool("mam_scan", cwd, { path: put(cwd, "work/dump.bin", Buffer.concat([Buffer.alloc(64, 0x20), short])) }, env), "short scan") as Answer;
    assert.equal(two.status, "partial");
    assert.equal(two.failed, 1);
    const ok = assertJsonAnswer(await runTool("prefetch_mam", cwd, { path: put(cwd, "work/good.pf", mamOf(plain)) }, env), "good") as Answer;
    assert.equal(ok.status, "complete");
    assert.match(String(ok.status_basis), /declared size/);
  });
});

// --- stop signals ---------------------------------------------------------------------------------------------------------------------------

each("prefetch_mam and mam_scan: SIGTERM, SIGINT and SIGHUP during a 64 MiB inflate end each with one JSON document, exit 128 plus the signal and no hidden file", async (d) => {
  await withCwd(async (cwd) => {
    const env = await d.env(cwd);
    put(cwd, "work/big.pf", bigStream(64));
    for (const [tool, args] of [["prefetch_mam", { path: "work/big.pf" }], ["mam_scan", { path: "work/big.pf", max_uncomp: 64 * MIB }]] as Array<[string, Record<string, unknown>]>) {
      for (const signal of SIGNALS) {
        const run = startTool(tool, cwd, args, env);
        await new Promise((r) => setTimeout(r, 1500)); // the decoder has been running for a second or more
        assert.equal(run.child.exitCode, null, `${tool} ended before it could be signalled`);
        run.child.kill(signal);
        const exit = await run.closed;
        const stopped: StopRun = { ...exit, stdout: run.stdout(), stderr: run.stderr(), moment: "temp", sent: signal, cwd, dirs: outputDirs(cwd, env), children: [] };
        const got = assertStopped(stopped, signal);
        assert.equal(got.answered, true, `${tool} ${signal}`);
        assert.equal(exit.code, 128 + SIGNAL_NUMBER[signal]);
      }
    }
  });
});

each("prefetch_mam and mam_scan: SIGTERM, SIGINT and SIGHUP after the handlers are installed and before main gives one JSON document", async (d) => {
  await withCwd(async (cwd) => {
    const env = await d.env(cwd);
    for (const tool of ["prefetch_mam", "mam_scan"]) {
      for (const signal of SIGNALS) assertStopped(await stopAt(tool, undefined, env, "early", signal, { cwd }), signal);
    }
  });
});

test("mam_scan: a signal while the page of hits is a temporary file leaves no hidden file, and a signal while the answer is written does not cut it", async () => {
  await withCwd(async (cwd) => {
    const candidates = Buffer.alloc(300_000 * 16);
    for (let i = 0; i < 300_000; i++) {
      candidates.write("MAM\x04", i * 16, "latin1");
      candidates.writeUInt32LE(2048, i * 16 + 4);
    }
    const path = put(cwd, "work/many.bin", candidates);
    for (const signal of SIGNALS) {
      const run = await stopAt("mam_scan", { path, parse: false, max_hits: 1 }, {}, "temp", signal, { cwd });
      assert.equal(assertStopped(run, signal).answered, true);
    }
    const printed = await stopAt("mam_scan", { path, parse: false, max_hits: 10000 }, {}, "print", "SIGTERM", { cwd });
    assert.equal(assertStopped(printed, "SIGTERM").answered, false);
    assert.ok(printed.stdout.length > 100_000);
  });
});

test("mam_scan: a rerun with a smaller result keeps the first file and names the second under -2", async () => {
  await withCwd(async (cwd) => {
    const make = (n: number): string => put(cwd, "work/many.bin", Buffer.concat(Array.from({ length: n }, () => Buffer.concat([Buffer.from("MAM\x04", "latin1"), Buffer.from([0, 8, 0, 0]), Buffer.alloc(8)]))));
    const args = { path: make(60), parse: false, max_hits: 1 };
    const out = await rerunSmaller("mam_scan", args, args, {}, { cwd, between: () => void make(8) });
    assert.ok(out.added.length >= 1);
  });
});

// --- arguments -----------------------------------------------------------------------------------------------------------------------------------

for (const tool of ["prefetch_mam", "mam_scan"] as const) {
  test(`${tool}: arguments of the wrong type (250 sets, and a top-level []) are all answered in JSON, and a missing path is a failure with a non-zero exit`, async () => {
    await withCwd(async (cwd) => {
      const base = { path: put(cwd, "work/x.pf", mamOf(sample(30))) };
      const seed = 2029;
      const statuses = await fuzzTool(tool, typeConfused(manifestOf(tool), 250, seed, base), seed, { cwd });
      assert.ok((statuses.failed ?? 0) > 0, JSON.stringify(statuses));
      for (const args of [{}, { path: "work/not-there.pf" }, { path: 5 }]) {
        const run = await runTool(tool, cwd, args);
        assert.notEqual(run.code, 0, JSON.stringify(args));
        assert.equal(assertJsonAnswer(run, JSON.stringify(args)).status, "failed");
      }
    });
  });
}

test("mam_scan: name_filter: 5 and the other numbers and flags of the wrong type are refused as JSON", async () => {
  await withCwd(async (cwd) => {
    const path = put(cwd, "work/dump.bin", Buffer.alloc(64, 0x20));
    for (const bad of [{ name_filter: 5 }, { parse: "yes" }, { max_uncomp: 2 ** 62 }, { max_hits: 0 }, { max_hits: 100000 }, { chunk: 10 }, { start: -1 }, { min_uncomp: 1.5 }]) {
      const run = await runTool("mam_scan", cwd, { path, ...bad });
      assert.notEqual(run.code, 0, JSON.stringify(bad));
      assert.equal(assertJsonAnswer(run, JSON.stringify(bad)).status, "failed");
    }
  });
});

// --- the shared text ------------------------------------------------------------------------------------------------------------------------------

test("the MAM code both tools share is one text, the STOP block is regkv's in both, and only mam_scan pages", () => {
  const sha = (s: string): string => createHash("sha256").update(s).digest("hex");
  const mamText = (name: string): string => {
    const text = readFileSync(join(WIN, name, "run.py"), "utf8");
    const from = text.indexOf("# ---- Shared by prefetch_mam and mam_scan");
    assert.ok(from >= 0, name);
    return text.slice(from, text.indexOf("def utf16_text(", from));
  };
  assert.equal(sha(mamText("prefetch_mam")), sha(mamText("mam_scan")));
  assert.match(mamText("prefetch_mam"), /class DecoderOutOfTime/);
  const block = (text: string, name: string): string => {
    const begin = `# BEGIN SHARED ${name}`;
    const end = `# END SHARED ${name}`;
    assert.ok(text.includes(begin), `no ${begin}`);
    return text.slice(text.indexOf(begin), text.indexOf(end) + end.length);
  };
  const reg = readFileSync(join(WIN, "regkv", "run.py"), "utf8");
  const scan = readFileSync(join(WIN, "mam_scan", "run.py"), "utf8");
  const pf = readFileSync(join(WIN, "prefetch_mam", "run.py"), "utf8");
  for (const name of ["PLACE", "PAGE", "STOP"]) assert.equal(sha(block(scan, name)), sha(block(reg, name)), `mam_scan ${name}`);
  assert.equal(sha(block(pf, "STOP")), sha(block(reg, "STOP")));
  assert.doesNotMatch(pf, /# BEGIN SHARED (PLACE|PAGE)/, "prefetch_mam keeps no result file");
  assert.doesNotMatch(scan + pf, /\bLosslessPage\(/);
  assert.match(pf, /^DEADLINE_SECONDS = \d+ /m);
  assert.match(scan, /^DEADLINE_SECONDS = \d+ /m);
  assert.equal(STOP_STATUS, "failed");
  assert.deepEqual(readdirSync(WIN).filter((n) => n === "mam_scan" || n === "prefetch_mam").sort(), ["mam_scan", "prefetch_mam"]);
});
