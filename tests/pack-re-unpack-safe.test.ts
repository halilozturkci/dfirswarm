/**
 * unpack_safe against a stand-in for upx that prints what UPX's documentation says it prints (`upx --version`; `upx -t -- FILE` exits 0
 * for a UPX file and prints `NotPackedException` for another; `upx -l -- FILE` lists `unpacked <- packed`; `upx -d -o OUT -- FILE` writes
 * OUT), driven by markers in the sample. A stand-in proves nothing about a real UPX version: one case at the end builds a sample with
 * the real program and is skipped, naming it, where upx is not installed.
 *
 * What these cases hold: the derivative is a new file under the tool-output directory, never the original, with no execute bit and its own
 * SHA-256; nothing is replaced on a rerun; a file UPX does not accept is `unsupported` or `failed` with no derivative; the output budget is
 * checked against the listing and against the growing file; a time limit and a stop signal end UPX and what it started; no sample text is
 * printed; a pipe, a link and hostile parameters are refused as JSON.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdir, readFile, stat, symlink } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { TOOLS, asJob, body, exists, filesUnder, gone, pidFile, put, refused, startDetached, stub, tool, withCwd } from "./pack-re-harness.ts";
import type { Json } from "./pack-re-harness.ts";
import { NO_ADOPTION, NO_SETSID } from "./host-gates.ts";

const UNPACK = join(TOOLS, "unpack_safe", "run.py");
const sha = (b: Buffer | string): string => createHash("sha256").update(b).digest("hex");

async function fakeUpx(bin: string): Promise<void> {
  await stub(bin, "upx", `case "$1" in
--version) echo "upx 5.2.1"; echo "UPX stand-in"; exit 0;;
-t) f="$3"
  if grep -q SLOWT "$f"; then sleep 60; fi
  if grep -q CORRUPT "$f"; then echo "upx: $f: CantUnpackException: file is possibly modified/hacked/protected; take care!" >&2; exit 1; fi
  if grep -q UPXOK "$f"; then echo "[OK] $f"; exit 0; fi
  echo "upx: $f: NotPackedException: not packed by UPX" >&2; exit 1;;
-l) f="$3"
  if grep -q SLOWL "$f"; then sleep 60; fi
  if grep -q NOLIST "$f"; then echo "     File size  Ratio  Format  Name"; exit 0; fi
  n=$(sed -n 's/.*expand=\\([0-9]*\\).*/\\1/p' "$f" | head -1)
  printf '   %s <-   %s   40.00%%   linux/amd64   x\\n' "$n" 100; exit 0;;
-d) out="$3"; f="$5"
  if grep -q HANG "$f"; then echo $$ > "$PIDS/upx.pid"; sleep 60; exit 0; fi
  if grep -q GROW "$f"; then yes AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA > "$out" & echo $! > "$PIDS/yes.pid"; wait; exit 0; fi
  if grep -q FAILD "$f"; then echo "upx: $f: CompressedDataException" >&2; exit 1; fi
  if grep -q EMPTYOUT "$f"; then : > "$out"; exit 0; fi
  if grep -q EXTRA "$f"; then echo junk > "$(dirname "$out")/junk"; fi
  n=$(sed -n 's/.*expand=\\([0-9]*\\).*/\\1/p' "$f" | head -1)
  head -c "$n" /dev/zero | tr '\\0' 'A' > "$out"; chmod 755 "$out"
  if grep -q FORKNOW "$f"; then ( while :; do printf 'B'; sleep 0.05; done >> "$out" ) & echo $! > "$PIDS/kid.pid"; fi
  if grep -q FORKLATE "$f"; then sleep 0.6; ( while :; do printf 'B'; sleep 0.05; done >> "$out" ) & echo $! > "$PIDS/kid.pid"; fi
  if grep -q FORKDOUBLE "$f"; then ( ( while :; do printf 'B'; sleep 0.05; done >> "$out" ) & echo $! > "$PIDS/kid.pid" ) & sleep 0.3; fi
  if grep -q HARDLINK "$f"; then ln "$out" "$(dirname "$out")/hl"; ( exec >&- 2>&-; sleep 1; printf x >> "$out" ) & fi
  if grep -q NEVEREXIT "$f"; then sleep 120 & echo $! > "$PIDS/kid.pid"; fi
  if grep -q SETSIDKID "$f"; then setsid sh -c 'echo $$ > "$PIDS/kid.pid"; while :; do printf B; sleep 0.05; done >> "$1"' sh "$out" </dev/null & sleep 0.5; fi
  exit 0;;
esac
exit 2`);
}

const packed = (extra = ""): string => `UPXOK expand=3000 ${extra}`;

test("a UPX file is unpacked into a new file under the tool-output directory: its own SHA-256, no execute bit, the original untouched, the version recorded", { skip: NO_ADOPTION }, async () => {
  await withCwd(async (cwd, bin) => {
    await fakeUpx(bin);
    const data = packed();
    await put(cwd, "work/sample.exe", data);
    const out = body(await tool(UNPACK, cwd, { path: "work/sample.exe" }, {}, bin));
    assert.equal(out.status, "complete", JSON.stringify(out));
    assert.equal(out.original.sha256, sha(data));
    assert.equal(out.derivative.bytes, 3000);
    assert.equal(out.derivative.sha256, sha("A".repeat(3000)));
    assert.equal(out.derivative.mode, "0600");
    const where = out.derivative.path as string;
    assert.match(where, /sample\.exe\.unpacked$/);
    const st = await stat(join(cwd, where));
    assert.equal(st.mode & 0o777, 0o600, "UPX's own mode (755 in the stand-in) is not kept");
    assert.equal(sha(await readFile(join(cwd, where))), out.derivative.sha256);
    assert.equal(await readFile(join(cwd, "work/sample.exe"), "utf8"), data);
    assert.equal(out.upx.version_command_output, "upx 5.2.1");
    assert.deepEqual(out.steps.map((s: Json) => s.label), ["upx --version", "upx -t", "upx -l", "upx -d"]);
    assert.ok(out.log);
    assert.equal((await filesUnder(join(cwd, "work/s1/tool-output"))).filter((f) => f.startsWith("stage-")).length, 0, "the stage directory is gone");
  });
});

test("a rerun makes a new file and replaces nothing", async () => {
  await withCwd(async (cwd, bin) => {
    await fakeUpx(bin);
    await put(cwd, "work/sample.exe", packed());
    const first = body(await tool(UNPACK, cwd, { path: "work/sample.exe" }, {}, bin));
    const second = body(await tool(UNPACK, cwd, { path: "work/sample.exe" }, {}, bin));
    assert.notEqual(first.derivative.path, second.derivative.path);
    assert.ok(await exists(join(cwd, first.derivative.path)));
    assert.ok(await exists(join(cwd, second.derivative.path)));
  });
});

test("in a job the derivative and the log are under $OUT", { skip: NO_ADOPTION }, async () => {
  await withCwd(async (cwd, bin) => {
    await fakeUpx(bin);
    await put(cwd, "work/sample.exe", packed());
    const out = body(await asJob(UNPACK, cwd, { path: "work/sample.exe" }, bin));
    assert.equal(out.status, "complete");
    assert.ok((out.derivative.path as string).startsWith(join(cwd, "out")), out.derivative.path);
  });
});

test("a file UPX does not recognise is unsupported with no derivative; another packer's marker is named as a hint", async () => {
  await withCwd(async (cwd, bin) => {
    await fakeUpx(bin);
    await put(cwd, "work/plain.exe", "MZ plain program");
    const a = refused(await tool(UNPACK, cwd, { path: "work/plain.exe" }, {}, bin));
    assert.equal(a.status, "unsupported");
    assert.equal(a.derivative, null);
    assert.equal(a.other_packer_hint, undefined);
    await put(cwd, "work/vmp.exe", "MZ .vmp0 section");
    const b = refused(await tool(UNPACK, cwd, { path: "work/vmp.exe" }, {}, bin));
    assert.equal(b.status, "unsupported");
    assert.equal(b.other_packer_hint, "VMProtect");
    assert.match(b.status_basis, /hint, not a finding/);
    assert.deepEqual((await filesUnder(join(cwd, "work/s1/tool-output"))).filter((f) => f.includes("unpacked")), []);
  });
});

test("a damaged UPX file, a failing unpack and an empty output are failed, and leave no derivative", async () => {
  await withCwd(async (cwd, bin) => {
    await fakeUpx(bin);
    for (const [name, text] of [["bad.exe", "UPXOK CORRUPT expand=10"], ["fail.exe", "UPXOK FAILD expand=10"], ["empty.exe", "UPXOK EMPTYOUT expand=10"]] as const) {
      await put(cwd, `work/${name}`, text);
      const a = refused(await tool(UNPACK, cwd, { path: `work/${name}` }, {}, bin));
      assert.equal(a.status, "failed", name);
      assert.equal(a.derivative, null, name);
    }
    const left = await filesUnder(join(cwd, "work/s1/tool-output"));
    assert.deepEqual(left.filter((f) => f.includes("unpacked") || f.startsWith("stage-")), []);
  });
});

test("the budget is checked against the listing before anything is written, and against the file while UPX writes it", async () => {
  await withCwd(async (cwd, bin) => {
    await fakeUpx(bin);
    await put(cwd, "work/bomb.exe", "UPXOK expand=999999999999");
    const listed = body(await tool(UNPACK, cwd, { path: "work/bomb.exe", max_output_bytes: 1048576 }, {}, bin));
    assert.equal(listed.status, "partial");
    assert.deepEqual(listed.limits_hit, ["max_output_bytes"]);
    assert.equal(listed.derivative, null);
    assert.ok(!listed.steps.some((s: Json) => s.label === "upx -d"), "upx -d was not started");
    await put(cwd, "work/grow.exe", "UPXOK NOLIST GROW");
    await mkdir(join(cwd, "pids"), { recursive: true });
    const t0 = Date.now();
    const grown = body(await tool(UNPACK, cwd, { path: "work/grow.exe", max_output_bytes: 1048576 }, { PIDS: join(cwd, "pids") }, bin));
    assert.equal(grown.status, "partial");
    assert.deepEqual(grown.limits_hit, ["max_output_bytes"]);
    assert.equal(grown.derivative, null);
    assert.ok(grown.steps.at(-1).stopped_by_watch);
    assert.ok(Date.now() - t0 < 60_000);
    const left = await filesUnder(join(cwd, "work/s1/tool-output"));
    assert.deepEqual(left.filter((f) => f.includes("unpacked") || f.startsWith("stage-")), [], "the half-written file was removed");
    assert.ok(await gone(await pidFile(join(cwd, "pids", "yes.pid")), 10_000), "the writer UPX started is gone");
  });
});

test("the call's time limit ends upx and what it started; the answer is partial and the half-written file is gone", async () => {
  await withCwd(async (cwd, bin) => {
    await fakeUpx(bin);
    await mkdir(join(cwd, "pids"), { recursive: true });
    await put(cwd, "work/hang.exe", "UPXOK HANG expand=10");
    const out = body(await tool(UNPACK, cwd, { path: "work/hang.exe", max_seconds: 5 }, { PIDS: join(cwd, "pids") }, bin));
    assert.equal(out.status, "partial");
    assert.deepEqual(out.limits_hit, ["time"]);
    assert.ok(await gone(await pidFile(join(cwd, "pids", "upx.pid")), 10_000));
  });
});

test("SIGTERM ends upx and answers with one document: failed, interrupted, exit 143", async () => {
  await withCwd(async (cwd, bin) => {
    await fakeUpx(bin);
    await mkdir(join(cwd, "pids"), { recursive: true });
    await put(cwd, "work/hang.exe", "UPXOK HANG expand=10");
    const run = startDetached(UNPACK, cwd, { path: "work/hang.exe" }, { PIDS: join(cwd, "pids") }, bin);
    try {
      const pid = await pidFile(join(cwd, "pids", "upx.pid"));
      run.signal("SIGTERM");
      run.signal("SIGTERM");
      assert.equal(await run.closed, 143);
      const word = JSON.parse(run.stdout()) as Json;
      assert.equal(word.status, "failed");
      assert.equal(word.interrupted, true);
      assert.equal(word.stopped_by_signal, 15);
      assert.ok(await gone(pid, 10_000));
      assert.deepEqual((await filesUnder(join(cwd, "work/s1/tool-output"))).filter((f) => f.startsWith("stage-")), []);
    } finally {
      try { run.signal("SIGKILL"); } catch { /* gone */ }
    }
  });
});

test("no text of the sample is printed: a canary in the packed file and in the unpacked output never reaches the answer", async () => {
  await withCwd(async (cwd, bin) => {
    await fakeUpx(bin);
    const canary = "AKIAIOSFODNN7EXAMPLE";
    await put(cwd, "work/c.exe", packed(canary));
    const answer = await tool(UNPACK, cwd, { path: "work/c.exe" }, {}, bin);
    assert.doesNotMatch(answer.stdout + answer.stderr, new RegExp(canary));
  });
});

test("a link, a pipe, a directory and a missing file are refused as JSON, and a pipe does not hang the tool", async () => {
  await withCwd(async (cwd, bin) => {
    await fakeUpx(bin);
    await put(cwd, "work/real.exe", packed());
    await symlink(join(cwd, "work/real.exe"), join(cwd, "work/link.exe"));
    assert.match(refused(await tool(UNPACK, cwd, { path: "work/link.exe" }, {}, bin)).error, /symbolic link/);
    spawnSync("mkfifo", [join(cwd, "work/pipe.exe")]);
    const t0 = Date.now();
    assert.match(refused(await tool(UNPACK, cwd, { path: "work/pipe.exe" }, {}, bin)).error, /named pipe/);
    assert.ok(Date.now() - t0 < 20_000);
    await mkdir(join(cwd, "work/d"), { recursive: true });
    assert.match(refused(await tool(UNPACK, cwd, { path: "work/d" }, {}, bin)).error, /directory/);
    assert.match(refused(await tool(UNPACK, cwd, { path: "work/none.exe" }, {}, bin)).error, /no such file/);
  });
});

test("hostile parameters are refused as JSON, never a traceback", async () => {
  await withCwd(async (cwd, bin) => {
    await fakeUpx(bin);
    const cases: unknown[] = [null, [], "x", { path: 1 }, { path: "" }, { path: "a\u0000b" }, { path: "work/x", max_output_bytes: 10 ** 30 }, { path: "work/x", max_output_bytes: true },
      { path: "work/x", max_seconds: 0 }, { path: "work/x", extra: 1 }, { path: "work/x", max_seconds: 1.5 }];
    for (const c of cases) refused(await tool(UNPACK, cwd, c, {}, bin));
    let nest: unknown = [];
    for (let i = 0; i < 4000; i++) nest = [nest];
    const deep = await tool(UNPACK, cwd, nest, {}, bin);
    assert.doesNotMatch(deep.stderr, /Traceback/);
    assert.notEqual(deep.code, 0);
    assert.doesNotThrow(() => JSON.parse(deep.stdout));
    const lone = await tool(UNPACK, cwd, { path: "\ud800" }, {}, bin);
    assert.doesNotMatch(lone.stderr, /Traceback/);
    assert.doesNotThrow(() => JSON.parse(lone.stdout));
  });
});

test("without upx the tool says so, as JSON", { skip: spawnSync("sh", ["-c", "command -v upx"]).status === 0 ? "upx is installed on this machine" : false }, async () => {
  await withCwd(async (cwd, bin) => {
    await put(cwd, "work/x.exe", packed());
    const out = refused(await tool(UNPACK, cwd, { path: "work/x.exe" }, {}, bin));
    assert.match(out.error, /upx is not installed/);
  });
});

const realUpx = spawnSync("sh", ["-c", "command -v upx"], { encoding: "utf8" }).status === 0;
test("with the real upx: an ELF built here is packed, unpacked, and the derivative is byte-identical to the original", { skip: realUpx ? false : "upx is not installed on this machine" }, async (t) => {
  await withCwd(async (cwd) => {
    const cc = spawnSync("sh", ["-c", "command -v cc"], { encoding: "utf8" });
    if (cc.status !== 0) return t.skip("no C compiler to build a sample with");
    await put(cwd, "work/hello.c", '#include <stdio.h>\nint main(void){puts("hello, hello, hello, hello");return 0;}\n');
    assert.equal(spawnSync("cc", ["-O0", "-o", join(cwd, "work/hello"), join(cwd, "work/hello.c")]).status, 0);
    const original = await readFile(join(cwd, "work/hello"));
    assert.equal(spawnSync("upx", ["-q", "-o", join(cwd, "work/hello.packed"), join(cwd, "work/hello")]).status, 0);
    t.diagnostic(spawnSync("upx", ["--version"], { encoding: "utf8" }).stdout.split("\n")[0] ?? "");
    const out = body(await tool(UNPACK, cwd, { path: "work/hello.packed" }));
    assert.equal(out.status, "complete", JSON.stringify(out));
    assert.equal(sha(await readFile(join(cwd, out.derivative.path))), sha(original));
  });
});

test("a call that spends max_seconds in upx -l or upx -t is partial with limits_hit time, and a step that never ran is not reported as failed", async () => {
  await withCwd(async (cwd, bin) => {
    await fakeUpx(bin);
    await put(cwd, "work/slowl.exe", "UPXOK SLOWL expand=10");
    const l = body(await tool(UNPACK, cwd, { path: "work/slowl.exe", max_seconds: 5 }, {}, bin));
    assert.equal(l.status, "partial", JSON.stringify(l));
    assert.deepEqual(l.limits_hit, ["time"]);
    assert.equal(l.derivative, null);
    assert.equal(l.steps.find((x: Json) => x.label === "upx -l").status, "timed_out");
    assert.ok(!l.steps.some((x: Json) => x.label === "upx -d"), "upx -d never ran and is not listed as a failed step");
    assert.match(l.status_basis, /upx -d was not attempted/);
    await put(cwd, "work/slowt.exe", "UPXOK SLOWT expand=10");
    const t = body(await tool(UNPACK, cwd, { path: "work/slowt.exe", max_seconds: 5 }, {}, bin));
    assert.equal(t.status, "partial", JSON.stringify(t));
    assert.deepEqual(t.limits_hit, ["time"]);
    assert.equal(t.steps.find((x: Json) => x.label === "upx -t").status, "timed_out");
    assert.doesNotMatch(t.status_basis, /failed/);
  });
});

test("a stage directory with extra files from upx is removed, and the log is mode 0600", { skip: NO_ADOPTION }, async () => {
  await withCwd(async (cwd, bin) => {
    await fakeUpx(bin);
    await put(cwd, "work/extra.exe", "UPXOK EXTRA expand=100");
    const out = body(await tool(UNPACK, cwd, { path: "work/extra.exe" }, {}, bin));
    assert.equal(out.status, "complete");
    const left = await filesUnder(join(cwd, "work/s1/tool-output"));
    assert.deepEqual(left.filter((f) => f.startsWith("stage-")), [], left.join());
    assert.equal((await stat(join(cwd, "work/s1/tool-output", out.log))).mode & 0o777, 0o600);
  });
});

/** A upx stand-in that forks a child which keeps appending to the derivative. The child's pid is recorded (PIDS) and killed at the end. */
for (const marker of ["FORKNOW", "FORKLATE", "FORKDOUBLE", "NEVEREXIT"]) {
  test(`a child upx abandons (${marker}) is ended before the derivative is hashed: partial, and no derivative that later differs from the answer`, { skip: NO_ADOPTION }, async () => {
    await withCwd(async (cwd, bin) => {
      await fakeUpx(bin);
      await put(cwd, "work/f.exe", packed(marker));
      const pids = join(cwd, "pids");
      await mkdir(pids, { recursive: true });
      let kid = 0;
      try {
        const out = body(await tool(UNPACK, cwd, { path: "work/f.exe" }, { PIDS: pids }, bin));
        kid = await pidFile(join(pids, "kid.pid"), 3_000).catch(() => 0);
        assert.ok(kid, "the child recorded its pid");
        assert.equal(out.status, "partial", JSON.stringify(out).slice(0, 400));
        assert.match(out.status_basis, /left \d+ process/);
        assert.equal(out.derivative, null);
        assert.ok(await gone(kid, 3_000), "the child is ended");
        assert.equal((await filesUnder(join(cwd, "work/s1/tool-output"))).filter((f) => f.endsWith(".unpacked") || f.startsWith("stage-")).length, 0);
      } finally {
        if (kid) { try { process.kill(kid, "SIGKILL"); } catch { /* gone */ } }
      }
    });
  });
}

test("a hard link to the derivative (a by-name writer with no descriptor open) makes the answer partial and no derivative is claimed", async () => {
  await withCwd(async (cwd, bin) => {
    await fakeUpx(bin);
    await put(cwd, "work/h.exe", packed("HARDLINK"));
    const out = body(await tool(UNPACK, cwd, { path: "work/h.exe" }, { PIDS: join(cwd, "pids") }, bin));
    assert.equal(out.status, "partial", JSON.stringify(out).slice(0, 400));
    assert.match(out.status_basis, /2 names/);
    assert.deepEqual(out.limits_hit, ["process_left_running"]);
    assert.equal(out.derivative, null);
    assert.equal((await filesUnder(join(cwd, "work/s1/tool-output"))).filter((f) => f.endsWith(".unpacked") || f.startsWith("stage-")).length, 0);
    await new Promise((r) => setTimeout(r, 1_200));
  });
});

test("a child upx puts in a session of its own (setsid) cannot be ended: partial, says so, and no derivative is claimed", { skip: NO_SETSID }, async () => {
  await withCwd(async (cwd, bin) => {
    await fakeUpx(bin);
    await put(cwd, "work/s.exe", packed("SETSIDKID"));
    const pids = join(cwd, "pids");
    await mkdir(pids, { recursive: true });
    let kid = 0;
    try {
      const out = body(await tool(UNPACK, cwd, { path: "work/s.exe" }, { PIDS: pids }, bin));
      kid = await pidFile(join(pids, "kid.pid"), 3_000).catch(() => 0);
      assert.ok(kid, "the child recorded its pid");
      assert.equal(out.status, "partial", JSON.stringify(out).slice(0, 400));
      assert.match(out.status_basis, /session of its own/);
      assert.equal(out.derivative, null);
      assert.equal((await filesUnder(join(cwd, "work/s1/tool-output"))).filter((f) => f.endsWith(".unpacked") || f.startsWith("stage-")).length, 0);
    } finally {
      if (kid) { try { process.kill(kid, "SIGKILL"); } catch { /* gone */ } }
    }
  });
});
