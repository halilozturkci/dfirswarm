/**
 * lnk_parse and jumplist against the tool contract (docs/packs.md, section 8), with the helpers of tests/windows-tool-contract.ts: a stop signal at
 * four moments gives one JSON document and no hidden file, a zero deadline gives a partial answer that names the clock, a rerun with a smaller result
 * never replaces the larger file, and an argument of the wrong type gets JSON. Also what only these tools can show:
 *
 *  - lnk_parse counts every ExtraData block, shows 50, keeps the whole list in a file, and reads 8 MB of 8-byte blocks in bounded memory;
 *  - lnk_parse shows a switch only from a closed set of names: generated canaries glued to a switch (-p<c>, /p<c>, --password=<c>, -p<c> x) are never printed;
 *  - jumplist bounds its inline rows once (not per file), writes link files 0600 and only as secret output, and writes a long name that is not UTF-8;
 *  - lnk_jumplist keeps its own stop handlers when it loads the two siblings that now carry the STOP block.
 *
 * Fixtures follow MS-SHLLINK (the 76-byte header, string data, ExtraData blocks, a terminal block of zeros), never a tool's output.
 *
 * Red check: WINDOWS_PACK_TOOLS=<a copy of the tools before the fixes> node --experimental-strip-types --test tests/pack-windows-forensics-links-contract.test.ts
 */
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { withCwd } from "./tool-library-harness.ts";
import { WIN } from "./windows-pack-harness.ts";
import {
  assertJsonAnswer, assertStopped, fuzzTool, manifestOf, rerunSmaller, runTool, standIn, stopAt, typeConfused, withDeadline, type Moment, type StopSignal,
} from "./windows-tool-contract.ts";

const SIGNALS: StopSignal[] = ["SIGTERM", "SIGINT", "SIGHUP"];
const TIME = 133_500_000_000_000_001n;
type Answer = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any
const secretJob = { SECRET_OUTPUT: "1", JOB_ID: "j000001" };

// --- fixtures (MS-SHLLINK) --------------------------------------------------------------------------------------------------------------

const LINK_CLSID = Buffer.from("0114020000000000c000000000000046", "hex");

/** A shell link: the header, the arguments as UTF-16 string data when given, the extra blocks, and the terminal block. */
function lnk(o: { args?: string; extras?: Buffer[]; terminal?: boolean } = {}): Buffer {
  const header = Buffer.alloc(0x4c);
  header.writeUInt32LE(0x4c, 0);
  header.set(LINK_CLSID, 4);
  header.writeUInt32LE((o.args !== undefined ? 0x20 : 0) | 0x80, 0x14);
  header.writeUInt32LE(0x20, 0x18);
  for (let i = 0; i < 3; i++) header.writeBigUInt64LE(TIME, 0x1c + i * 8);
  header.writeUInt32LE(1234, 0x34);
  header.writeUInt32LE(1, 0x3c);
  const parts: Buffer[] = [header];
  if (o.args !== undefined) {
    const count = Buffer.alloc(2);
    count.writeUInt16LE(o.args.length);
    parts.push(count, Buffer.from(o.args, "utf16le"));
  }
  parts.push(...(o.extras ?? []));
  if (o.terminal !== false) parts.push(Buffer.alloc(4));
  return Buffer.concat(parts);
}

/** An ExtraData block of `size` bytes with a signature the reader does not know. */
function unknownBlock(size: number, sig = 0xa0000fff): Buffer {
  const b = Buffer.alloc(size);
  b.writeUInt32LE(size, 0);
  b.writeUInt32LE(sig, 4);
  return b;
}

function trackerBlock(machine: string): Buffer {
  const b = Buffer.alloc(0x60);
  b.writeUInt32LE(0x60, 0);
  b.writeUInt32LE(0xa0000003, 4);
  b.writeUInt32LE(0x58, 8);
  b.write(machine, 16, "latin1");
  b.set(randomBytes(64), 32);
  return b;
}

function put(cwd: string, rel: string, bytes: Buffer): string {
  mkdirSync(join(cwd, rel, ".."), { recursive: true });
  writeFileSync(join(cwd, rel), bytes);
  return rel;
}

/** A customDestinations-ms: link structures one after another (carved by their header). */
function customDest(count: number, tag = "x"): Buffer {
  return Buffer.concat(Array.from({ length: count }, (_, i) => lnk({ args: `${tag}-${i}` })));
}

const FEW = (cwd: string): Record<string, unknown> => ({ path: put(cwd, "work/a.lnk", lnk({ args: "-noprofile" })) });

// --- lnk_parse: the contract ------------------------------------------------------------------------------------------------------------

test("lnk_parse and jumplist: a deadline of zero ends in a partial answer that names the clock", async () => {
  await withCwd(async (cwd) => {
    const one = assertJsonAnswer(await runTool(withDeadline("lnk_parse", 0), cwd, FEW(cwd)), "lnk_parse");
    assert.equal(one.status, "partial");
    assert.match(String(one.status_basis), /clock/);
    assert.equal(one.stopped_by_time_limit, true);
    const jl = assertJsonAnswer(await runTool(withDeadline("jumplist", 0), cwd, { path: put(cwd, "work/jl/x.customDestinations-ms", customDest(5)) }), "jumplist");
    assert.equal(jl.status, "partial");
    assert.match(String(jl.status_basis), /clock/);
    assert.equal(jl.stopped_by_time_limit, true);
  });
});

/** The slow inputs: lnk_parse over a structure of 1.2 million 8-byte ExtraData blocks (seconds of work), jumplist over 60,000 carved links written to files. */
function slowInput(tool: "lnk_parse" | "jumplist", cwd: string): { args: Record<string, unknown>; env: Record<string, string> } {
  if (tool === "lnk_parse") {
    const blocks = Buffer.alloc(8 * 1_200_000);
    for (let i = 0; i < 1_200_000; i++) {
      blocks.writeUInt32LE(8, i * 8);
      blocks.writeUInt32LE(0xa0000fff, i * 8 + 4);
    }
    return { args: { path: put(cwd, "work/slow.lnk", lnk({ extras: [blocks] })), size: 16_000_000 }, env: {} };
  }
  return { args: { path: put(cwd, "work/jl/slow.customDestinations-ms", customDest(60_000)), out_dir: "work/s1/links", write_links: true, limit: 1 }, env: secretJob };
}

for (const tool of ["lnk_parse", "jumplist"] as const) {
  for (const signal of SIGNALS) {
    for (const moment of ["early", "temp"] as Moment[]) {
      test(`${tool}: ${signal} at ${moment} gives one JSON document, exit 128 plus the signal and no hidden file`, async () => {
        await withCwd(async (cwd) => {
          const input = slowInput(tool, cwd);
          const run = await stopAt(tool, input.args, input.env, moment, signal, { cwd });
          assert.equal(assertStopped(run, signal).answered, true);
        });
      });
    }
  }

  test(`${tool}: a signal while the answer is being written does not cut it`, async () => {
    await withCwd(async (cwd) => {
      const args: Record<string, unknown> = tool === "lnk_parse"
        ? { path: put(cwd, "work/many.bin", customDest(4000)), scan: true, size: 8_000_000, max: 4000, limit: 1 }
        : { path: put(cwd, "work/jl/many.customDestinations-ms", customDest(4000)), limit: 4000 };
      const run = await stopAt(tool, args, {}, "print", "SIGTERM", { cwd });
      const got = assertStopped(run, "SIGTERM");
      assert.equal(got.answered, false, "the answer was written whole, then the tool ended by itself");
      assert.ok(run.stdout.length > 100_000, `${run.stdout.length} bytes`);
    });
  });
}

test("lnk_parse: a rerun with a smaller result keeps the first file and names the second under -2", async () => {
  await withCwd(async (cwd) => {
    const args = { path: put(cwd, "work/many.bin", customDest(60)), scan: true, size: 1_000_000, max: 1, limit: 1 };
    const out = await rerunSmaller("lnk_parse", args, args, {}, { cwd, between: () => void put(cwd, "work/many.bin", customDest(8)) });
    assert.ok(out.added.length >= 1);
  });
});

test("jumplist: a rerun with a smaller result keeps the first file and names the second under -2", async () => {
  await withCwd(async (cwd) => {
    const args = { path: put(cwd, "work/jl/many.customDestinations-ms", customDest(60)), limit: 1 };
    const out = await rerunSmaller("jumplist", args, args, {}, { cwd, between: () => void put(cwd, "work/jl/many.customDestinations-ms", customDest(8)) });
    assert.ok(out.added.length >= 1);
  });
});

for (const tool of ["lnk_parse", "jumplist"] as const) {
  test(`${tool}: arguments of the wrong type (250 sets, and a top-level []) are all answered in JSON`, async () => {
    await withCwd(async (cwd) => {
      const base = tool === "lnk_parse" ? FEW(cwd) : { path: put(cwd, "work/jl/x.customDestinations-ms", customDest(3)) };
      const seed = 2027;
      const statuses = await fuzzTool(tool, typeConfused(manifestOf(tool), 250, seed, base), seed, { cwd });
      assert.ok((statuses.failed ?? 0) > 0, JSON.stringify(statuses));
    });
  });
}

// --- WIN-07: ExtraData blocks ------------------------------------------------------------------------------------------------------------

function runLimited(script: string, cwd: string, args: unknown, megabytes: number): { code: number | null; stdout: string; stderr: string; ms: number } {
  const started = Date.now();
  const ran = spawnSync("bash", ["-c", 'ulimit -v "$1"; exec python3 "$2"', "limited", String(megabytes * 1024), script], {
    cwd, input: JSON.stringify(args), encoding: "utf8", timeout: 60_000, maxBuffer: 1 << 28, env: { ...process.env, AGENT_ID: "s1" },
  });
  return { code: ran.status, stdout: ran.stdout, stderr: ran.stderr, ms: Date.now() - started };
}

test("lnk_parse: 8 MB of 8-byte ExtraData blocks are counted, 50 are shown, all are in a file, within the clock and 400 MB of address space", async () => {
  await withCwd(async (cwd) => {
    const count = 1_000_000;
    const blocks = Buffer.alloc(8 * count);
    for (let i = 0; i < count; i++) {
      blocks.writeUInt32LE(8, i * 8);
      blocks.writeUInt32LE(0xa0000fff, i * 8 + 4);
    }
    const path = put(cwd, "work/blocks.lnk", lnk({ args: "-noprofile", extras: [blocks] }));
    const ran = runLimited(join(WIN, "lnk_parse", "run.py"), cwd, { path, size: 9_000_000 }, 400);
    const answer = assertJsonAnswer(ran, "8 MB of blocks") as Answer;
    assert.ok(ran.ms < 30_000, `${ran.ms} ms`);
    assert.equal(answer.extra.length, 50);
    if (answer.status === "complete") {
      assert.equal(answer.extra_count, count);
      assert.equal(answer.extra_not_shown, count - 50);
      const rows = readFileSync(join(cwd, answer.all_extra_blocks), "utf8").trim().split("\n");
      assert.equal(rows.length, count, "every block is a row of the file");
      assert.equal(JSON.parse(rows[count - 1]).block, count - 1);
    } else {
      assert.equal(answer.status, "partial");
      assert.match(String(answer.status_basis), /clock/);
      assert.ok(answer.extra_count > 50 && answer.all_extra_blocks, "what was read is in the file");
    }
  });
});

test("lnk_parse: every tracker block is kept apart from the inline page of ExtraData blocks", async () => {
  await withCwd(async (cwd) => {
    const extras = [...Array.from({ length: 60 }, () => unknownBlock(16)), trackerBlock("LAPTOP-7")];
    const answer = assertJsonAnswer(await runTool("lnk_parse", cwd, { path: put(cwd, "work/t.lnk", lnk({ extras })) }), "tracker") as Answer;
    assert.equal(answer.extra.length, 50);
    assert.equal(answer.extra_count, 61);
    assert.equal(answer.tracker_count, 1);
    assert.equal(answer.tracker[0].machine, "LAPTOP-7");
    assert.equal(answer.tracker[0].block, 60);
    assert.ok(answer.all_extra_blocks, "the sixty-one blocks are in a file");
    assert.equal(readFileSync(join(cwd, answer.all_extra_blocks), "utf8").trim().split("\n").length, 61);
  });
});

// --- WIN-10: a switch only from a closed set --------------------------------------------------------------------------------------------

function canary(): string {
  return "k" + randomBytes(9).toString("hex");
}

test("lnk_parse and lnk_jumplist never print a canary glued to a switch (-p<c>, /p<c>, --password=<c>, -p<c> x), and show a known switch", async () => {
  await withCwd(async (cwd) => {
    let printed = 0;
    let runs = 0;
    for (const shape of [(c: string) => `-p${c}`, (c: string) => `/p${c}`, (c: string) => `--password=${c}`, (c: string) => `-p${c} x`]) {
      for (let i = 0; i < 12; i++) {
        const c = canary();
        const path = put(cwd, `work/c${runs}.lnk`, lnk({ args: shape(c) }));
        for (const tool of ["lnk_parse", "lnk_jumplist"]) {
          const run = await runTool(tool, cwd, { path });
          runs += 1;
          if (run.stdout.includes(c) || run.stderr.includes(c)) printed += 1;
          const answer = JSON.parse(run.stdout) as Answer;
          const strings = tool === "lnk_parse" ? answer : (answer.rows?.find((r: Answer) => r.row === "link") ?? {}).strings ?? {};
          assert.equal(strings.arguments_first_token ?? null, null, `${tool}: ${shape("<c>")}`);
          assert.equal(strings.arguments_first_token_withheld, true, `${tool}: ${shape("<c>")}`);
        }
      }
    }
    assert.equal(printed, 0, `${printed} of ${runs} canaries printed`);
    const known = assertJsonAnswer(await runTool("lnk_parse", cwd, { path: put(cwd, "work/k.lnk", lnk({ args: "-NoProfile -File x.ps1" })) }), "known") as Answer;
    assert.equal(known.arguments_first_token, "-NoProfile");
  });
});

// --- lnk_parse: write_strings is secret output -------------------------------------------------------------------------------------------

test("lnk_parse: write_strings is declared secret output and refused as JSON, before anything is created, outside such a job", async () => {
  await withCwd(async (cwd) => {
    const manifest = JSON.parse(readFileSync(join(WIN, "lnk_parse", "manifest.json"), "utf8")) as Answer;
    assert.deepEqual(manifest.secret_output, { when_args: ["write_strings"] });
    const out = join(cwd, "out");
    mkdirSync(out);
    const refused = await runTool("lnk_parse", cwd, { ...FEW(cwd), write_strings: true }, { JOB_ID: "j1", OUT: out, SECRET_OUTPUT: "0" });
    assert.notEqual(refused.code, 0);
    assert.equal(assertJsonAnswer(refused, "write_strings").status, "failed");
    assert.deepEqual(readdirSync(out), [], "nothing was created");
    const ok = assertJsonAnswer(await runTool("lnk_parse", cwd, { ...FEW(cwd), write_strings: true }, { JOB_ID: "j1", OUT: out, SECRET_OUTPUT: "1" }), "secret") as Answer;
    assert.equal(ok.status, "complete");
  });
});

// --- jumplist ---------------------------------------------------------------------------------------------------------------------------

test("jumplist: the inline rows are bounded once for the whole answer, not once per file", async () => {
  await withCwd(async (cwd) => {
    for (const name of ["a", "b", "c", "d"]) put(cwd, `work/jl/${name}.customDestinations-ms`, customDest(40, name));
    const limit = 10;
    const answer = assertJsonAnswer(await runTool("jumplist", cwd, { path: "work/jl", limit }), "bound") as Answer;
    assert.equal(answer.file_count, 4);
    const inline = answer.files.reduce((n: number, f: Answer) => n + f.links.length, 0);
    assert.ok(inline <= limit + answer.file_count, `${inline} link rows shown inline with limit ${limit} over 4 files`);
    assert.ok(answer.files.every((f: Answer) => f.link_count === 40), "every link is counted");
  });
});

test("jumplist: link files are mode 0600 and written only as secret output with write_links; out_dir alone is refused", async () => {
  await withCwd(async (cwd) => {
    put(cwd, "work/jl/x.customDestinations-ms", customDest(3));
    const manifest = JSON.parse(readFileSync(join(WIN, "jumplist", "manifest.json"), "utf8")) as Answer;
    assert.deepEqual(manifest.secret_output, { when_args: ["write_links"] });
    assert.equal(manifest.params.write_links.type, "boolean");
    const alone = await runTool("jumplist", cwd, { path: "work/jl", out_dir: "work/s1/links" }, secretJob);
    assert.notEqual(alone.code, 0);
    assert.equal(assertJsonAnswer(alone, "out_dir alone").status, "failed");
    const outside = await runTool("jumplist", cwd, { path: "work/jl", out_dir: "work/s1/links", write_links: true }, { SECRET_OUTPUT: "0" });
    assert.notEqual(outside.code, 0);
    assert.equal(assertJsonAnswer(outside, "no secret job").status, "failed");
    assert.throws(() => readdirSync(join(cwd, "work", "s1", "links")), "nothing was created");
    const ok = assertJsonAnswer(await runTool("jumplist", cwd, { path: "work/jl", out_dir: "work/s1/links", write_links: true }, secretJob), "write_links") as Answer;
    assert.equal(ok.status, "complete");
    const files = readdirSync(join(cwd, "work", "s1", "links"));
    assert.equal(files.length, 3);
    for (const f of files) assert.equal(statSync(join(cwd, "work", "s1", "links", f)).mode & 0o777, 0o600, f);
  });
});

test("jumplist: a long file name that is not UTF-8 is written under a shortened name, not a crash (Linux; skipped where the file system rewrites names)", async (t) => {
  await withCwd(async (cwd) => {
    const dir = join(cwd, "work", "jl");
    mkdirSync(dir, { recursive: true });
    const name = Buffer.concat([Buffer.from("a".repeat(215)), Buffer.from([0xff, 0xfe]), Buffer.from(".customDestinations-ms")]);
    try {
      writeFileSync(Buffer.concat([Buffer.from(dir + "/"), name]), customDest(2));
    } catch {
      t.skip("this file system does not keep names that are not UTF-8");
      return;
    }
    const answer = assertJsonAnswer(await runTool("jumplist", cwd, { path: "work/jl", out_dir: "work/s1/links", write_links: true }, secretJob), "raw name") as Answer;
    assert.notEqual(answer.status, "failed", JSON.stringify(answer).slice(0, 400));
    assert.equal(answer.files_failed, 0);
    assert.equal(readdirSync(join(cwd, "work", "s1", "links")).length, 2);
  });
});

// --- lnk_jumplist keeps its own handlers ------------------------------------------------------------------------------------------------

test("lnk_jumplist: a signal while a stand-in lnkinfo runs, after both siblings are loaded, ends lnkinfo, removes .xcheck files and answers with its own document", async () => {
  for (const signal of SIGNALS) {
    await withCwd(async (cwd, bin) => {
      put(cwd, "work/jl/x.customDestinations-ms", customDest(3));
      const pidFile = join(cwd, "lnkinfo.pid");
      await standIn(bin, "lnkinfo", pidFile);
      const env = { PATH: `${bin}:${process.env.PATH ?? ""}` };
      const run = await stopAt("lnk_jumplist", { path: "work/jl", limit: 5 }, env, "child", signal, { cwd, pidFile });
      const got = assertStopped(run, signal);
      assert.equal(got.answered, true);
      assert.match(String(got.answer.status_basis), /temporary files were removed/, "this tool's own last word, not a sibling's");
      assert.deepEqual(readdirSync(join(cwd, "work", "s1")).filter((n) => n.startsWith(".xcheck")), []);
    });
  }
});

test("the stop test above catches the defect: with the old load_sibling the siblings' handlers replace lnk_jumplist's", async () => {
  await withCwd(async (cwd, bin) => {
    const tools = mkdtempSync(join(tmpdir(), "oldload-"));
    try {
      for (const t of ["lnk_jumplist", "lnk_parse", "jumplist"]) cpSync(join(WIN, t), join(tools, t), { recursive: true });
      const file = join(tools, "lnk_jumplist", "run.py");
      const text = readFileSync(file, "utf8");
      const start = text.indexOf("    stop_signals = (signal.SIGTERM");
      const end = text.indexOf("    return module", start);
      if (start < 0) return; // the tools before the fix have no hold to remove
      writeFileSync(file, text.slice(0, start) + "    spec.loader.exec_module(module)\n" + text.slice(end));
      put(cwd, "work/jl/x.customDestinations-ms", customDest(3));
      const pidFile = join(cwd, "lnkinfo.pid");
      await standIn(bin, "lnkinfo", pidFile);
      const run = await stopAt(file, { path: "work/jl", limit: 5 }, { PATH: `${bin}:${process.env.PATH ?? ""}` }, "child", "SIGTERM", { cwd, pidFile });
      assert.throws(() => {
        const got = assertStopped(run, "SIGTERM");
        assert.match(String(got.answer.status_basis), /temporary files were removed/);
        assert.deepEqual(readdirSync(join(cwd, "work", "s1")).filter((n) => n.startsWith(".xcheck")), []);
      }, "the old loading leaves a child alive, a temporary file or the sibling's document");
    } finally {
      rmSync(tools, { recursive: true, force: true });
    }
  });
});

// --- the shared blocks ----------------------------------------------------------------------------------------------------------------------

test("lnk_parse and jumplist carry the PLACE, PAGE and STOP blocks of regkv, and lnk_jumplist its PLACE and PAGE, byte for byte", () => {
  const block = (text: string, name: string): string => {
    const begin = `# BEGIN SHARED ${name}`;
    const end = `# END SHARED ${name}`;
    assert.ok(text.includes(begin), `no ${begin}`);
    return text.slice(text.indexOf(begin), text.indexOf(end) + end.length);
  };
  const digest = (s: string): string => createHash("sha256").update(s).digest("hex");
  const reg = readFileSync(join(WIN, "regkv", "run.py"), "utf8");
  for (const [tool, names] of [["lnk_parse", ["PLACE", "PAGE", "STOP"]], ["jumplist", ["PLACE", "PAGE", "STOP"]], ["lnk_jumplist", ["PLACE", "PAGE"]]] as Array<[string, string[]]>) {
    const text = readFileSync(join(WIN, tool, "run.py"), "utf8");
    for (const name of names) assert.equal(digest(block(text, name)), digest(block(reg, name)), `${tool} ${name}`);
    if (tool !== "lnk_jumplist") assert.match(text, /^DEADLINE_SECONDS = \d+ /m, tool);
  }
});
