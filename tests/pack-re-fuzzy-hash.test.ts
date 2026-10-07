/**
 * fuzzy_hash against stand-ins for ssdeep and tlsh that print what the programs' documentation says they print:
 * `ssdeep -b FILE` a header line (`ssdeep,1.1--blocksize:hash:hash,filename`) and then `blocksize:hash:hash,"name"`;
 * `tlsh -f FILE` a digest (an optional `T1` version prefix and hexadecimal digits), a tab and the file name, or `TNULL`
 * when the file is too short or too uniform; `tlsh -c FILE1 -f FILE2` the distance, a tab and the name. A stand-in
 * proves nothing about a real ssdeep or tlsh version, and the tool says nothing about one as fact: it records what
 * the installed program reports.
 *
 * What these cases hold: a digest is accepted only when it has the digest's own shape (any other text is a
 * diagnostic, not a digest); a hung engine is stopped at its time limit and the failure is structured, per engine;
 * the engine's whole output is kept in a log file and not held in memory; a comparison that cannot be made names the
 * input that prevented it.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { readFile, symlink } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { FUZZY, asJob, body, put, refused, stub, tool, withCwd } from "./pack-re-harness.ts";
import type { Json } from "./pack-re-harness.ts";

const TLSH_DIGEST = "T1" + "A1B2C3D4E5".repeat(7); // T1 and 70 hexadecimal digits
const SSDEEP_DIGEST = "96:aBcDeF0123456789+/aBcDeF0123456789+/:XyZ0123456789+/";

async function engines(bin: string, opts: { tlsh?: string; ssdeep?: string } = {}): Promise<void> {
  await stub(
    bin,
    "ssdeep",
    opts.ssdeep ??
      `if [ "$1" = "-V" ]; then echo "2.14.1"; exit 0; fi
echo 'ssdeep,1.1--blocksize:hash:hash,filename'
echo '${SSDEEP_DIGEST},"sample.bin"'`,
  );
  await stub(
    bin,
    "tlsh",
    opts.tlsh ??
      `if [ "$1" = "-version" ]; then echo "tlsh 4.12.0"; exit 0; fi
if [ "$1" = "-c" ]; then printf '57\\t%s\\n' "$4"; exit 0; fi
printf '${TLSH_DIGEST}\\t%s\\n' "$2"`,
  );
}

function sha256(buf: Buffer): string {
  return createHash("sha256").update(buf).digest("hex");
}

test("valid digests are accepted, SHA-256 is computed from the bytes, and each engine's argv and version are recorded", async () => {
  await withCwd(async (cwd, bin) => {
    await engines(bin);
    const data = Buffer.from("some bytes ".repeat(500));
    await put(cwd, "work/sample.bin", data);
    const out = body(await tool(FUZZY, cwd, { path: "work/sample.bin" }, {}, bin));
    const f = out.files[0];
    assert.equal(f.sha256, sha256(data));
    assert.equal(f.bytes, data.length);
    assert.equal(f.ssdeep, SSDEEP_DIGEST);
    assert.equal(f.tlsh, TLSH_DIGEST);
    assert.equal(f.ssdeep_status, "ok");
    assert.equal(f.tlsh_status, "ok");
    assert.equal(out.status, "complete", JSON.stringify(out.problems));
    assert.deepEqual(out.engines.ssdeep.argv_per_file, ["ssdeep", "-b", "--", "<file>"]);
    assert.deepEqual(out.engines.tlsh.argv_per_file, ["tlsh", "-f", "<file>"]);
    assert.equal(out.engines.ssdeep.version_command_output, "2.14.1");
    assert.equal(out.engines.tlsh.version_command_output, "tlsh 4.12.0");
    assert.match(out.note, /identity|similarity/);
  });
});

test("text that is not a digest is a diagnostic: no digest, a status that says so, and the partial answer", async () => {
  await withCwd(async (cwd, bin) => {
    await engines(bin, { tlsh: `if [ "$1" = "-version" ]; then exit 1; fi
echo "error: foo"` });
    await put(cwd, "work/sample.bin", "x".repeat(2000));
    const out = body(await tool(FUZZY, cwd, { path: "work/sample.bin" }, {}, bin));
    const f = out.files[0];
    assert.equal(f.tlsh, null);
    assert.equal(f.tlsh_status, "unrecognised_output");
    assert.match(f.tlsh_unavailable, /error: foo/);
    assert.equal(f.ssdeep, SSDEEP_DIGEST, "the other engine's result stands");
    assert.equal(out.status, "partial");
  });
});

test("a digest with the wrong shape is refused whatever else it looks like", async () => {
  await withCwd(async (cwd, bin) => {
    await engines(bin, {
      tlsh: `printf 'T1ZZZZ\\t%s\\n' "$2"`,
      ssdeep: `echo 'ssdeep,1.1--blocksize:hash:hash,filename'
echo 'not-a-digest,"x"'`,
    });
    await put(cwd, "work/sample.bin", "x".repeat(2000));
    const f = body(await tool(FUZZY, cwd, { path: "work/sample.bin" }, {}, bin)).files[0];
    assert.equal(f.tlsh, null);
    assert.equal(f.ssdeep, null);
    assert.equal(f.tlsh_status, "unrecognised_output");
    assert.equal(f.ssdeep_status, "unrecognised_output");
  });
});

test("TNULL is the engine saying the file is too short or too uniform, and that is not a failure", async () => {
  await withCwd(async (cwd, bin) => {
    await engines(bin, { tlsh: `printf 'TNULL\\t%s\\n' "$2"` });
    await put(cwd, "work/tiny.bin", "abc");
    const out = body(await tool(FUZZY, cwd, { path: "work/tiny.bin" }, {}, bin));
    assert.equal(out.files[0].tlsh, null);
    assert.equal(out.files[0].tlsh_status, "insufficient_input");
    assert.match(out.files[0].tlsh_unavailable, /short|uniform|diversity/i);
    assert.equal(out.status, "complete");
  });
});

test("an engine that runs past its time limit is stopped, and the failure is the engine's, in the answer", async () => {
  await withCwd(async (cwd, bin) => {
    await engines(bin, { tlsh: `if [ "$1" = "-version" ]; then echo "tlsh 4.12.0"; exit 0; fi
sleep 8
printf '${TLSH_DIGEST}\\t%s\\n' "$2"` });
    await put(cwd, "work/sample.bin", "x".repeat(2000));
    const started = Date.now();
    const out = body(await tool(FUZZY, cwd, { path: "work/sample.bin", engine_timeout_seconds: 1 }, {}, bin));
    assert.ok(Date.now() - started < 6000, "the tool waited for the engine instead of stopping it");
    assert.equal(out.files[0].tlsh, null);
    assert.equal(out.files[0].tlsh_status, "timeout");
    assert.match(out.files[0].tlsh_unavailable, /1 second|time limit|timeout/i);
    assert.equal(out.files[0].ssdeep, SSDEEP_DIGEST);
    assert.equal(out.status, "partial");
  });
});

test("an engine that fails says why from its own stderr, and exits nonzero as a structured failure", async () => {
  await withCwd(async (cwd, bin) => {
    await engines(bin, { ssdeep: `if [ "$1" = "-V" ]; then echo 2.14.1; exit 0; fi
echo "ssdeep: cannot open file" >&2
exit 3` });
    await put(cwd, "work/sample.bin", "x".repeat(2000));
    const out = body(await tool(FUZZY, cwd, { path: "work/sample.bin" }, {}, bin));
    assert.equal(out.files[0].ssdeep, null);
    assert.equal(out.files[0].ssdeep_status, "failed");
    assert.match(out.files[0].ssdeep_unavailable, /cannot open file/);
    assert.equal(out.files[0].tlsh, TLSH_DIGEST);
  });
});

test("an engine's whole output is a log file, and the answer does not hold it", async () => {
  await withCwd(async (cwd, bin) => {
    await engines(bin, {
      tlsh: `if [ "$1" = "-version" ]; then echo "tlsh 4.12.0"; exit 0; fi
head -c 3000000 /dev/zero | tr '\\0' 'x' >&2
printf '${TLSH_DIGEST}\\t%s\\n' "$2"`,
    });
    await put(cwd, "work/sample.bin", "x".repeat(2000));
    const out = body(await tool(FUZZY, cwd, { path: "work/sample.bin" }, {}, bin));
    assert.ok(out.logs.stderr);
    const log = await readFile(join(cwd, "work", "s1", "tool-output", out.logs.stderr));
    assert.ok(log.length >= 3_000_000, "the whole of the engine's stderr is kept");
    assert.ok(JSON.stringify(out).length < 20_000, "and none of it is in the answer");
    assert.equal(out.files[0].tlsh, TLSH_DIGEST);
  });
});

test("in a job the logs go under $OUT and a second run does not replace them", async () => {
  await withCwd(async (cwd, bin) => {
    await engines(bin);
    await put(cwd, "work/sample.bin", "x".repeat(2000));
    const a = body(await asJob(FUZZY, cwd, { path: "work/sample.bin" }, bin));
    const b = body(await asJob(FUZZY, cwd, { path: "work/sample.bin" }, bin));
    assert.notEqual(a.logs.stdout, b.logs.stdout);
    for (const name of [a.logs.stdout, b.logs.stdout, a.logs.stderr]) assert.ok((await readFile(join(cwd, "out", "tool-output", name))).length >= 0);
  });
});

test("a comparison says the distance, and when it cannot be made it names the input that prevented it", async () => {
  await withCwd(async (cwd, bin) => {
    await engines(bin, {
      tlsh: `if [ "$1" = "-version" ]; then echo "tlsh 4.12.0"; exit 0; fi
if [ "$1" = "-c" ]; then printf '57\\t%s\\n' "$4"; exit 0; fi
case "$2" in *tiny*) printf 'TNULL\\t%s\\n' "$2";; *) printf '${TLSH_DIGEST}\\t%s\\n' "$2";; esac`,
    });
    await put(cwd, "work/a.bin", "a".repeat(3000));
    await put(cwd, "work/b.bin", "b".repeat(3000));
    await put(cwd, "work/tiny.bin", "t");
    const ok = body(await tool(FUZZY, cwd, { path: "work/a.bin", compare_to: "work/b.bin" }, {}, bin));
    assert.equal(ok.comparison.tlsh_distance, 57);
    assert.equal(ok.comparison.same_sha256, false);
    const second = body(await tool(FUZZY, cwd, { path: "work/a.bin", compare_to: "work/tiny.bin" }, {}, bin));
    assert.equal(second.comparison.tlsh_distance, null);
    assert.equal(second.comparison.unavailable.input, "compare_to");
    assert.match(second.comparison.unavailable.reason, /short|uniform|diversity/i);
    const first = body(await tool(FUZZY, cwd, { path: "work/tiny.bin", compare_to: "work/b.bin" }, {}, bin));
    assert.equal(first.comparison.unavailable.input, "path");
    const both = body(await tool(FUZZY, cwd, { path: "work/tiny.bin", compare_to: "work/tiny.bin" }, {}, bin));
    assert.equal(both.comparison.unavailable.input, "both");
    assert.equal(both.comparison.same_sha256, true);
  });
});

test("a comparison line that is not a distance is not read as one", async () => {
  await withCwd(async (cwd, bin) => {
    await engines(bin, { tlsh: `if [ "$1" = "-version" ]; then exit 1; fi
if [ "$1" = "-c" ]; then echo "usage: tlsh -f file"; exit 0; fi
printf '${TLSH_DIGEST}\\t%s\\n' "$2"` });
    await put(cwd, "work/a.bin", "a".repeat(3000));
    await put(cwd, "work/b.bin", "b".repeat(3000));
    const out = body(await tool(FUZZY, cwd, { path: "work/a.bin", compare_to: "work/b.bin" }, {}, bin));
    assert.equal(out.comparison.tlsh_distance, null);
    assert.match(out.comparison.unavailable.reason, /unrecognised/i);
    assert.equal(out.status, "partial");
  });
});

test("a program that is not installed is the same failure as before, in words the harness reads as a missing program", async () => {
  await withCwd(async (cwd, bin) => {
    // A PATH holding python3 and nothing else: no ssdeep, no tlsh.
    const python = spawnSync("sh", ["-c", "command -v python3"], { encoding: "utf8" }).stdout.trim();
    await symlink(python, join(bin, "python3"));
    await put(cwd, "work/sample.bin", "x".repeat(2000));
    const out = refused(await tool(FUZZY, cwd, { path: "work/sample.bin" }, { PATH: bin }));
    assert.match(out.error, /ssdeep is not installed|tlsh is not installed/);
  });
});

test("arguments are typed", async () => {
  await withCwd(async (cwd, bin) => {
    await engines(bin);
    await put(cwd, "work/sample.bin", "x".repeat(2000));
    for (const args of [{ engine_timeout_seconds: 0 }, { engine_timeout_seconds: 601 }, { engine_timeout_seconds: "5" }, { compare_to: 5 }]) {
      const out: Json = refused(await tool(FUZZY, cwd, { path: "work/sample.bin", ...args }, {}, bin));
      assert.ok(out.error, JSON.stringify(args));
    }
    assert.match(refused(await tool(FUZZY, cwd, { path: "work/none.bin" }, {}, bin)).error, /no such file/);
  });
});
