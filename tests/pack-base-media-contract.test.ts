/**
 * computer-forensics-base: qr_read, glyph_strip, cache_body and frame_survey under the tool contract every pack tool is held to.
 *
 *   - Hostile parameters, driven from the manifests as tests/tool-contract-hostile.test.ts drives the older base tools: for every
 *     parameter a list, an object, a number, a float, true, null, the empty string, a NUL, a lone surrogate, 300 characters, a huge and a
 *     negative integer, a list nested forty deep, a dot-dot path and an absolute path, each in an otherwise sensible call; and arguments
 *     that are no object at all. Every answer is ONE JSON object with `status` and `status_basis`, no traceback, in time.
 *   - A stop signal (SIGTERM, SIGINT, SIGHUP) in the middle of the work ends each tool with one JSON document, status failed and
 *     interrupted, exit 128 + the signal; a file it had begun is removed, and a program it was running is ended with it.
 *   - The tool's own clock, below the manifest's timeout, ends a long search as an answer that says where it stopped.
 *   - Writes go under $OUT and never through a link: an output directory that is a link is refused with nothing written, and a link
 *     that already has the call's own name is stepped past, never entered.
 *   - Called the way a job calls a tool: the working directory is the run's root, every path relative, with spaces.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { chmod, mkdir, readFile, readdir, rm, symlink, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { gzipSync } from "node:zlib";
import { join } from "node:path";
import { test } from "node:test";
import { PYTHON3 } from "./host-gates.ts";
import { call, CFB, filesBelow, greyPng, tool, withRun, type Doc, type Ran } from "./pack-base-media-fixture.ts";

const TOOLS = ["qr_read", "glyph_strip", "cache_body", "frame_survey"] as const;
const NO_PROGRAMS = "/usr/bin:/bin";      // a PATH that holds a shell and no decoder or OCR engine
const nest = (n: number): unknown => (n === 0 ? [] : [nest(n - 1)]);
const HOSTILE: Array<[string, unknown]> = [
  ["a list", [1]], ["an object", { a: 1 }], ["a number", 5], ["a float", 1.5], ["true", true], ["null", null], ["the empty string", ""],
  ["a NUL", "a\u0000b"], ["a lone surrogate", "x\udcffy"], ["300 characters", "n".repeat(300)], ["a huge integer", 10 ** 30], ["a negative integer", -1],
  ["a nested list", nest(40)], ["a list of strings", ["a", "b"]], ["a dot-dot path", "../../x"], ["an absolute path", "/proc/self/mem"],
];

/** A picture of noise: no symbol, and a long search for one. */
const noise = (side: number): Buffer => {
  const bytes = randomBytes(side * side);
  return greyPng(Array.from({ length: side }, (_, y) => Array.from(bytes.subarray(y * side, (y + 1) * side))));
};
/** A line of five bars: a crop glyph_strip cuts into five glyphs. */
const bars = (): Buffer => greyPng(Array.from({ length: 30 }, (_, y) => Array.from({ length: 80 }, (_, x) => (y > 5 && y < 25 && x > 8 && x < 72 && Math.floor((x - 8) / 6) % 2 === 0 ? 10 : 245))));
/** A simple-cache entry whose body is `stored`, written from the format's layout (tests/pack-base-cache-body.test.ts builds the full set). */
function entry(stored: Buffer, coding: string): Buffer {
  const key = Buffer.from("1/0/https://example.test/x");
  const head = Buffer.from(`HTTP/1.1 200 OK\0Content-Encoding: ${coding}\0\0`, "latin1");
  const record = (magic: bigint, a: number, b: number, c: number): Buffer => {
    const r = Buffer.alloc(24);
    r.writeBigUInt64LE(magic, 0);
    r.writeUInt32LE(a, 8);
    r.writeUInt32LE(b, 12);
    r.writeUInt32LE(c, 16);
    return r;
  };
  return Buffer.concat([record(0xfcfb6d1ba7725c30n, 5, key.length, 0), key, stored, record(0xf4fa6f45970d41d8n, 0, 0, 0), head, record(0xf4fa6f45970d41d8n, 0, 0, head.length)]);
}

async function fixtures(run: string): Promise<Record<(typeof TOOLS)[number], Doc>> {
  const dir = "inputs/case files";
  await writeFile(join(run, dir, "bars.png"), bars());
  await writeFile(join(run, dir, "abcdef0123456789_0"), entry(gzipSync(Buffer.from("a small body")), "gzip"));
  await writeFile(join(run, dir, "clip.mp4"), "no decoder reads this");
  return {
    qr_read: { image: `${dir}/bars.png` },
    glyph_strip: { image: `${dir}/bars.png`, reading: "lI1O0" },
    cache_body: { path: `${dir}/abcdef0123456789_0` },
    frame_survey: { video: `${dir}/clip.mp4` },
  };
}

function crash(r: Ran): string | null {
  if (r.killed) return "no answer in time";
  if (/Traceback/.test(r.stderr)) return `a traceback: ${r.stderr.trim().split("\n").pop()?.slice(0, 160)}`;
  if (!r.stdout.trim()) return "no JSON on stdout";
  if ("not_json" in r.doc || Array.isArray(r.doc)) return `stdout is not one JSON object: ${r.stdout.slice(0, 120)}`;
  if (typeof r.doc.status !== "string" || typeof r.doc.status_basis !== "string") return "the answer has no status and status_basis";
  if (!["complete", "partial", "failed"].includes(r.doc.status)) return `status is ${r.doc.status}`;
  if (r.stdout.trim().split("\n").filter((l) => l.startsWith("{") && l.length < 3).length > 1) return "more than one document";
  return null;
}

for (const name of TOOLS) {
  test(`${name}: a hostile value for each parameter, and arguments that are no object, are answered with one JSON document`, async () => {
    await withRun(async (run, out) => {
      const base = (await fixtures(run))[name];
      const manifest = JSON.parse(await readFile(join(CFB, "tools", name, "manifest.json"), "utf8")) as { params: Record<string, unknown> };
      const cases: Array<[string, unknown]> = [];
      for (const param of Object.keys(manifest.params)) for (const [label, value] of HOSTILE) cases.push([`${param} = ${label}`, { ...base, [param]: value }]);
      for (const raw of ["", "not json", "[]", "null", "7", '"text"', "[".repeat(100000), '{"image": ', JSON.stringify({ ...base, unknown_parameter: 1, another: [1, 2] })]) cases.push([`arguments ${raw.slice(0, 20)}`, raw]);
      assert.ok(cases.length > 100);
      const problems: string[] = [];
      for (let i = 0; i < cases.length; i += 8) {
        await Promise.all(cases.slice(i, i + 8).map(async ([label, args]) => {
          const r = await call(name, run, args, { out, path: NO_PROGRAMS, limitMs: 30_000 });
          const why = crash(r);
          if (why) problems.push(`${label}: ${why}`);
          else if (r.doc.status === "failed" && r.code === 0) problems.push(`${label}: a failed answer with exit 0`);
          else if (r.doc.status !== "failed" && r.code !== 0) problems.push(`${label}: status ${r.doc.status} with exit ${r.code}`);
        }));
      }
      assert.deepEqual(problems, []);
      // A parameter the tool does not know is named in the answer, and the call still runs.
      const unknown = await call(name, run, { ...base, unknown_parameter: 1 }, { out, path: NO_PROGRAMS });
      assert.deepEqual(unknown.doc.unrecognised_parameters, ["unknown_parameter"]);
    });
  });
}

/** One call that is stopped by a signal once `ready` says the work is under way: the whole run, with how it ended. */
function stopped(name: string, run: string, out: string, args: unknown, signal: NodeJS.Signals, ready: () => boolean, path?: string): Promise<Ran & { signalled: boolean }> {
  return new Promise((resolve) => {
    const child = spawn(PYTHON3, [tool(name)], { cwd: run, env: { ...process.env, AGENT_ID: "s1", JOB_ID: "j000001", OUT: out, ...(path ? { PATH: path } : {}) } });
    const so: Buffer[] = [];
    const se: Buffer[] = [];
    let signalled = false;
    const started = Date.now();
    const poll = setInterval(() => {
      if (!signalled && (ready() || Date.now() - started > 20_000)) {
        signalled = true;
        child.kill(signal);
      }
    }, 5);
    const guard = setTimeout(() => child.kill("SIGKILL"), 40_000);
    child.stdout.on("data", (c: Buffer) => so.push(c));
    child.stderr.on("data", (c: Buffer) => se.push(c));
    child.on("close", (code) => {
      clearInterval(poll);
      clearTimeout(guard);
      const stdout = Buffer.concat(so).toString("utf8");
      let doc: Doc = {};
      try {
        doc = JSON.parse(stdout) as Doc;
      } catch {
        doc = { not_json: stdout.slice(0, 300) };
      }
      resolve({ code, stdout, stderr: Buffer.concat(se).toString("utf8"), doc, ms: Date.now() - started, killed: false, signalled });
    });
    child.stdin.on("error", () => undefined);
    child.stdin.end(JSON.stringify(args));
  });
}

const SIGNALS: Array<[NodeJS.Signals, number]> = [["SIGTERM", 15], ["SIGINT", 2], ["SIGHUP", 1]];
const alive = (pid: number): boolean => {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
};
const settle = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

function assertStopped(r: Ran & { signalled: boolean }, number: number, what: string): void {
  assert.ok(r.signalled, `${what}: the signal was sent`);
  assert.equal(r.code, 128 + number, `${what}: ${r.stdout.slice(0, 300)} ${r.stderr.slice(0, 300)}`);
  assert.ok(!("not_json" in r.doc), `${what}: one JSON document: ${r.stdout.slice(0, 300)}`);
  assert.equal(r.doc.status, "failed", what);
  assert.ok(r.doc.interrupted, what);
  assert.doesNotMatch(r.stderr, /Traceback/, what);
}

test("a stop signal in the middle of a search, a body, an OCR run and a decode is answered once, and what was begun is removed", async () => {
  await withRun(async (run, out) => {
    const dir = "inputs/case files";
    await writeFile(join(run, dir, "noise.png"), noise(1400));
    await writeFile(join(run, dir, "bars.png"), bars());
    // A body of 1 GiB of zeros (1 MiB stored): long enough to be stopped while its file is being written.
    await writeFile(join(run, dir, "1111111111111111_0"), entry(gzipSync(Buffer.alloc(1 << 30), { level: 1 }), "gzip"));
    await writeFile(join(run, dir, "clip.mp4"), "the stand-in reads no byte of it");
    // Stand-ins that say they have started (a pid file) and then run for a minute.
    const bin = join(run, "work", "bin");
    await mkdir(bin, { recursive: true });
    await writeFile(join(bin, "tesseract"), `#!/bin/sh\nif [ "$1" = "--version" ]; then echo "tesseract standin"; exit 0; fi\necho $$ > "${bin}/ocr.pid"\nexec sleep 60\n`);
    await writeFile(join(bin, "ffprobe"), `#!/bin/sh\necho '{"streams": [{"codec_name": "standin", "width": 320, "height": 180, "avg_frame_rate": "25/1"}], "format": {"format_name": "standin"}}'\n`);
    await writeFile(join(bin, "ffmpeg"), `#!/bin/sh\necho $$ > "${bin}/decoder.pid"\nhead -c 43200 /dev/zero\nexec sleep 60\n`);
    for (const name of ["tesseract", "ffprobe", "ffmpeg"]) await chmod(join(bin, name), 0o755);
    const path = `${bin}:${NO_PROGRAMS}`;
    for (const [signal, number] of SIGNALS) {
      for (const d of await readdir(out)) await rm(join(out, d), { recursive: true, force: true });
      for (const f of ["ocr.pid", "decoder.pid"]) await rm(join(bin, f), { force: true });

      const startedAt = Date.now();
      const qr = await stopped("qr_read", run, out, { image: `${dir}/noise.png` }, signal, () => Date.now() - startedAt > 900);
      assertStopped(qr, number, `qr_read ${signal}`);

      const body = await stopped("cache_body", run, out, { path: `${dir}/1111111111111111_0`, max_bytes: 2 ** 31 }, signal, () => filesBelow(out).some((f) => /cache_body\/body\./.test(f)));
      assertStopped(body, number, `cache_body ${signal}`);
      assert.deepEqual(filesBelow(out).filter((f) => /body\./.test(f)), [], `cache_body ${signal}: the body that was being written is removed`);

      const ocr = await stopped("glyph_strip", run, out, { image: `${dir}/bars.png` }, signal, () => existsSync(join(bin, "ocr.pid")), path);
      assertStopped(ocr, number, `glyph_strip ${signal}`);
      const ocrPid = Number((await readFile(join(bin, "ocr.pid"), "utf8")).trim());

      const decode = await stopped("frame_survey", run, out, { video: `${dir}/clip.mp4` }, signal, () => existsSync(join(bin, "decoder.pid")), path);
      assertStopped(decode, number, `frame_survey ${signal}`);
      const decoderPid = Number((await readFile(join(bin, "decoder.pid"), "utf8")).trim());
      assert.deepEqual(filesBelow(out).filter((f) => f.includes(".decoder.log")), [], `frame_survey ${signal}: the decoder's log is removed`);
      await settle(200);
      assert.equal(alive(ocrPid), false, `glyph_strip ${signal}: the OCR program was ended with the tool`);
      assert.equal(alive(decoderPid), false, `frame_survey ${signal}: the decoder was ended with the tool`);
    }
  });
});

test("the tool's own clock ends a long search as an answer that names where it stopped, well inside the manifest's timeout", async () => {
  await withRun(async (run, out) => {
    const dir = "inputs/case files";
    await writeFile(join(run, dir, "noise.png"), noise(2000));
    await writeFile(join(run, dir, "bars.png"), bars());
    const r = await call("qr_read", run, { images: [`${dir}/noise.png`, `${dir}/bars.png`], max_seconds: 5 }, { out, limitMs: 40_000 });
    assert.equal(r.killed, false);
    assert.ok(r.ms < 15_000, `answered in ${r.ms} ms on a 5 second clock`);
    assert.equal(r.doc.rows[0].result, "not finished");
    assert.equal(r.doc.counts.not_finished, 2, "the picture it stopped in and the one it never reached");
    assert.match(JSON.stringify(r.doc.partial_reasons), /the clock ran out while picture 1 of 2 was being read/);
    assert.notEqual(r.doc.status, "complete");
    assert.equal(r.doc.complete, false);
    for (const name of TOOLS) {
      const manifest = JSON.parse(await readFile(join(CFB, "tools", name, "manifest.json"), "utf8")) as Doc;
      const source = await readFile(tool(name), "utf8");
      const most = Number(/DEFAULT_SECONDS, MAX_SECONDS = \d+, (\d+)/.exec(source)![1]);
      assert.ok(most < manifest.timeout_seconds, `${name}: its own clock (${most} s at most) is below the manifest's ${manifest.timeout_seconds} s`);
      assert.equal(manifest.version, Number(/TOOL = \{"name": "[a-z_]+", "version": (\d+)\}/.exec(source)![1]), `${name}: one version in the script and the manifest`);
    }
  });
});

test("writes go under $OUT and never through a link; outside a job they go under work/<agent>/tool-output, and the answer says so", async () => {
  await withRun(async (run, out) => {
    const args = await fixtures(run);
    const elsewhere = join(run, "elsewhere");
    await mkdir(elsewhere);
    // $OUT is itself a link: refused, nothing written where it points.
    const linked = join(run, "store", "jobs", "linked-out");
    await symlink(elsewhere, linked);
    for (const name of ["qr_read", "glyph_strip", "cache_body"] as const) {
      const r = await call(name, run, args[name], { out: linked, path: NO_PROGRAMS });
      assert.equal(r.code, 1, `${name}: ${r.stdout}`);
      assert.match(r.doc.error, /the output directory cannot be made or is reached through a link .*nothing was written/, name);
    }
    assert.deepEqual(await readdir(elsewhere), [], "nothing was written through the link");
    // A link that already has the call's own name under $OUT is stepped past: the call takes the next name.
    await symlink(elsewhere, join(out, "cache_body"));
    await symlink(elsewhere, join(out, "glyph_strip"));
    const body = await call("cache_body", run, args.cache_body, { out });
    assert.equal(body.doc.output_directory, "store/jobs/j000001/out/cache_body-2");
    const strip = await call("glyph_strip", run, args.glyph_strip, { out, path: NO_PROGRAMS });
    assert.equal(strip.doc.output_directory, "store/jobs/j000001/out/glyph_strip-2");
    assert.deepEqual(await readdir(elsewhere), []);
    // Outside a job: under work/<agent>/tool-output, with the note that it is not sealed; and a `work` that is a link is refused.
    const shell = await call("cache_body", run, args.cache_body, {});
    assert.equal(shell.doc.output_directory, "work/s1/tool-output/cache_body");
    assert.match(shell.doc.note, /written where you called it, not sealed: run it as a job \(job_run tool=cache_body\)/);
    assert.equal((await readFile(join(run, "work/s1/tool-output/cache_body/body.txt"), "utf8")), "a small body");
    await rm(join(run, "work"), { recursive: true });
    await symlink(elsewhere, join(run, "work"));
    const through = await call("cache_body", run, args.cache_body, {});
    assert.equal(through.code, 1);
    assert.match(through.doc.error, /reached through a link/);
    assert.deepEqual(await readdir(elsewhere), []);
  });
});
