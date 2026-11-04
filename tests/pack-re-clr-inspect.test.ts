/**
 * clr_inspect (reverse-engineering): a .NET assembly's CLR header and metadata root read as structure, and a labelled reconstruction written by
 * `ilspycmd` in a job run as secret output.
 *
 * No .NET runtime exists on the machine these cases were written on, so `ilspycmd` was never run for real here. Every case that starts the
 * program uses a stand-in written in this file; a stand-in proves how the tool treats a program's exit status, output, time and signals, and
 * nothing about ilspycmd. The last case runs the real program on a real assembly and is skipped, naming what is missing, unless both are given
 * (`ilspycmd` on PATH and DFIRSWARM_CLR_SAMPLE naming an assembly).
 *
 * The assemblies are built from the specification (ECMA-335 II.24 and the PE/COFF specification) by tests/pack-re-doc-fixtures.ts.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, readdir, readFile, stat, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { parseSecretDeclaration } from "../scripts/output-hygiene.ts";
import { buildPeDirs } from "./pack-re-doc-fixtures.ts";
import { TOOLS, buildElf, buildPe, gone, pidFile, put, startDetached, stub, tool, withCwd } from "./pack-re-harness.ts";
import type { Json } from "./pack-re-harness.ts";

const CLR = join(TOOLS, "clr_inspect", "run.py");
const CANARY = "AKIAIOSFODNN7EXAMPLE";
const BODY = "namespace Demo { public class Program { static string Literal = \"reconstruction-body-marker-7731\"; } }";
const sha = (b: Buffer | string): string => createHash("sha256").update(b).digest("hex");

/** An assembly from the specification, with a scenario marker after the file's last byte for the stand-in (the tool never reads it). */
function asm(scenario = "ok", clr: Record<string, unknown> = {}): Buffer {
  return Buffer.concat([buildPeDirs({ clr }).file, Buffer.from(`\nSCENARIO:${scenario} \n`)]);
}

/** The stand-in `ilspycmd`: --version prints two lines; `--disable-updatecheck FILE` does what the file's SCENARIO marker says. */
async function fakeProgram(cwd: string, bin: string): Promise<void> {
  await mkdir(join(cwd, "pids"), { recursive: true });
  await writeFile(join(cwd, "body.cs"), BODY + "\n");
  await stub(bin, "ilspycmd", `case "$1" in
--version) printf 'ilspycmd: 11.2.0.10050\\nICSharpCode.Decompiler: 11.2.0.10050\\n'; exit 0;;
esac
[ "$1" = "--disable-updatecheck" ] || { echo "no update check option" >&2; exit 9; }
name=$(grep -a -o 'SCENARIO:[a-z_]*' "$2" | head -1 | cut -d: -f2)
case "$name" in
  ok) cat "${cwd}/body.cs"; exit 0;;
  partial_exit) cat "${cwd}/body.cs"; echo "error: could not decompile method X" >&2; exit 1;;
  empty) exit 0;;
  fail_empty) echo "bad assembly" >&2; exit 1;;
  hang) echo $$ > "${cwd}/pids/prog.pid"; cat "${cwd}/body.cs"; sleep 120; exit 0;;
  flood) echo $$ > "${cwd}/pids/prog.pid"; yes 'public class Generated {}'; exit 0;;
  errflood) echo $$ > "${cwd}/pids/prog.pid"; yes 'error: noisy' >&2; exit 0;;
  mutate) printf x >> "$2"; cat "${cwd}/body.cs"; exit 0;;
  env) env; exit 0;;
  child) (sleep 120 & echo $! > "${cwd}/pids/child.pid"; wait) ; exit 0;;
  daemon) sleep 120 & echo $! > "${cwd}/pids/child.pid"; sleep 1; cat "${cwd}/body.cs"; exit 0;;
  fork_now) ( while :; do printf '// late line\n'; sleep 0.05; done ) & echo $! > "${cwd}/pids/child.pid"; cat "${cwd}/body.cs"; exit 0;;
  fork_late) sleep 0.6; ( while :; do printf '// late line\n'; sleep 0.05; done ) & echo $! > "${cwd}/pids/child.pid"; cat "${cwd}/body.cs"; exit 0;;
  fork_double) ( ( while :; do printf '// late line\n'; sleep 0.05; done ) & echo $! > "${cwd}/pids/child.pid" ) & cat "${cwd}/body.cs"; sleep 0.3; exit 0;;
  setsid_child) setsid sh -c 'echo $$ > "${cwd}/pids/child.pid"; while :; do printf "// late line\n"; sleep 0.05; done' </dev/null & cat "${cwd}/body.cs"; sleep 0.5; exit 0;;
  never_exit) sleep 120 & echo $! > "${cwd}/pids/child.pid"; cat "${cwd}/body.cs"; exit 0;;
esac
exit 3`);
}

async function job(cwd: string, bin: string | undefined, args: Record<string, unknown>, o: { secret?: boolean; env?: Record<string, string> } = {}) {
  await mkdir(join(cwd, "out"), { recursive: true });
  return tool(CLR, cwd, args, { JOB_ID: "j000001", OUT: join(cwd, "out"), ...(o.secret === false ? {} : { SECRET_OUTPUT: "1" }), ...(o.env ?? {}) }, bin);
}

const parse = (out: { stdout: string; stderr: string }): Json => {
  assert.doesNotMatch(out.stderr, /Traceback/);
  return JSON.parse(out.stdout);
};

async function outputs(cwd: string): Promise<string[]> {
  return readdir(join(cwd, "out", "tool-output")).catch(() => [] as string[]);
}

test("the manifest declares secret_output for decompile in a form the harness accepts, says SENSITIVE, and names ilspycmd", async () => {
  const m = JSON.parse(await readFile(join(TOOLS, "clr_inspect", "manifest.json"), "utf8")) as { secret_output: unknown; params: Record<string, { type: string }>; description: string; requires: string[]; timeout_seconds: number };
  assert.deepEqual(m.secret_output, { when_args: ["decompile"] });
  assert.equal(parseSecretDeclaration(m.secret_output, m.params, true).ok, true);
  assert.equal(m.params.decompile!.type, "boolean");
  assert.match(m.description, /SENSITIVE/);
  assert.deepEqual(m.requires, ["ilspycmd"]);
  assert.match(m.description, /never run for real here/i, "the manifest says the program was not run for real");
  assert.ok(m.timeout_seconds >= 150);
});

test("metadata only: the CLR header, the metadata root and the declared row counts are read without any program", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "work/a.dll", asm("ok", { flags: 0x9, entryToken: 0x06000001 }));
    const out = await tool(CLR, cwd, { path: "work/a.dll" }, {}, undefined);
    const a = parse(out);
    assert.equal(out.code, 0, out.stdout);
    assert.equal(a.status, "complete", JSON.stringify(a));
    assert.equal(a.mode, "metadata only");
    assert.equal(a.reconstruction, null);
    assert.equal(a.clr.header.runtime_version, "2.5");
    assert.deepEqual(a.clr.header.flag_names, ["ILONLY", "STRONGNAMESIGNED"]);
    assert.deepEqual(a.clr.header.entry_point, { kind: "token", token: "0x06000001", table: "MethodDef", row: 1 });
    assert.equal(a.clr.metadata.version_string, "v4.0.30319");
    assert.equal(a.clr.metadata.stream_count, 5);
    assert.deepEqual(a.clr.metadata.streams.map((s: Json) => s.name), ["#~", "#Strings", "#US", "#GUID", "#Blob"]);
    assert.equal(a.clr.metadata.table_stream, "#~");
    assert.equal(a.clr.metadata.declared_row_counts.TypeDef, 0);
    assert.equal(a.file.sha256, sha(await readFile(join(cwd, "work/a.dll"))));
    assert.match(a.note, /never printed inline|never printed/);
  });
});

test("metadata only needs no secret job and creates nothing", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "work/a.dll", asm());
    const a = parse(await job(cwd, undefined, { path: "work/a.dll" }, { secret: false }));
    assert.equal(a.status, "complete");
    assert.deepEqual(await readdir(join(cwd, "out")), []);
  });
});

test("a file that is not a managed assembly is unsupported, never complete: no MZ, no CLR header, an ELF", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "work/text.bin", "just text, long enough to be read as nothing in particular, not a PE file at all..........................");
    await put(cwd, "work/native.exe", buildPe({}).file);
    await put(cwd, "work/elf.bin", buildElf({ type: 2, machine: 62, bits: 64 } as never));
    for (const f of ["text.bin", "native.exe", "elf.bin"]) {
      const out = await tool(CLR, cwd, { path: `work/${f}` });
      const a = parse(out);
      assert.equal(out.code, 1, f);
      assert.equal(a.status, "unsupported", `${f}: ${out.stdout.slice(0, 300)}`);
      assert.ok(a.status_basis.length > 10);
    }
  });
});

test("a damaged CLR header or metadata root is partial with the problem named, not complete", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "work/nometa.dll", asm("ok", { noMetadata: true }));
    await put(cwd, "work/badsig.dll", asm("ok", { badSignature: true }));
    for (const f of ["nometa.dll", "badsig.dll"]) {
      const out = await tool(CLR, cwd, { path: `work/${f}` });
      const a = parse(out);
      assert.equal(a.status, "partial", `${f}: ${out.stdout.slice(0, 300)}`);
      assert.equal(out.code, 0);
      assert.ok(a.problems.length >= 1, f);
      assert.equal(a.clr.metadata.readable, false);
    }
  });
});

test("a stream that runs past the metadata is a problem and makes the answer partial", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "work/s.dll", asm("ok", { streams: [{ name: "#~", size: 0x100 }, { name: "#Strings", size: 0x7fffffff }] }));
    const a = parse(await tool(CLR, cwd, { path: "work/s.dll" }));
    assert.equal(a.status, "partial");
    assert.match(a.problems.join("\n"), /runs past the end of the metadata/);
  });
});

test("strings out of the file are withheld by shape: a key-shaped version string and stream name never reach the answer", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "work/c.dll", asm("ok", { version: `v4.0 ${CANARY}`, streams: [{ name: "#~", size: 0x100 }, { name: CANARY.slice(0, 16), size: 4 }] }));
    const out = await tool(CLR, cwd, { path: "work/c.dll" });
    assert.ok(!out.stdout.includes(CANARY), "the whole key is not printed");
    assert.ok(!out.stdout.includes(CANARY.slice(0, 16)), "the stream name is not printed");
  });
});

for (const [label, secret] of [["outside a job", undefined], ["in a job not run as secret output", false]] as const) {
  test(`decompile is refused as JSON, before anything is read or created, ${label}`, async () => {
    await withCwd(async (cwd, bin) => {
      await fakeProgram(cwd, bin);
      await put(cwd, "work/a.dll", asm());
      await mkdir(join(cwd, "out"), { recursive: true });
      const out = secret === undefined ? await tool(CLR, cwd, { path: "work/a.dll", decompile: true }, {}, bin)
        : await tool(CLR, cwd, { path: "work/a.dll", decompile: true }, { JOB_ID: "j000001", OUT: join(cwd, "out") }, bin);
      const a = parse(out);
      assert.equal(out.code, 1);
      assert.equal(a.status, "failed");
      assert.match(a.error, /decompile is refused outside a job run as secret output/);
      assert.deepEqual(await readdir(join(cwd, "out")), [], "nothing created in $OUT");
    });
  });
}

test("decompile in a secret job: the reconstruction is a labelled file under $OUT, mode 0600, never inline; the answer names its size, lines and sha256", async () => {
  await withCwd(async (cwd, bin) => {
    await fakeProgram(cwd, bin);
    await put(cwd, "work/a.dll", asm("ok"));
    const out = await job(cwd, bin, { path: "work/a.dll", decompile: true });
    const a = parse(out);
    assert.equal(out.code, 0, out.stdout);
    assert.equal(a.status, "complete", JSON.stringify(a));
    assert.equal(a.mode, "metadata and reconstruction");
    assert.ok(!out.stdout.includes("reconstruction-body-marker-7731"), "the decompiled text is never printed");
    assert.equal(a.decompiler.version_output, "ilspycmd: 11.2.0.10050");
    assert.deepEqual(a.decompiler.argv.slice(1, 2), ["--disable-updatecheck"], "the update check is always disabled");
    assert.equal(a.decompiler.exit_code, 0);
    const file = a.reconstruction.reconstruction_file as string;
    assert.equal(file, join(cwd, "out", "tool-output", "clr-inspect.reconstruction.cs"));
    const text = await readFile(file, "utf8");
    assert.match(text, /^\/\/ RECONSTRUCTION: C# text written by a decompiler/);
    assert.match(text, /not the author's source/);
    assert.ok(text.includes(`sha256 ${a.file.sha256}`), "the header names the assembly");
    assert.ok(text.endsWith(BODY + "\n"), "the program's output follows the header unchanged");
    assert.equal(a.reconstruction.bytes, Buffer.byteLength(text));
    assert.equal(a.reconstruction.sha256, sha(text));
    assert.equal(a.reconstruction.lines, text.split("\n").length - 1);
    assert.equal(a.reconstruction.inline, false);
    assert.equal(((await stat(file)).mode & 0o777).toString(8), "600");
    assert.deepEqual((await outputs(cwd)).sort(), ["clr-inspect.log", "clr-inspect.reconstruction.cs"], "no stage directory is left");
    assert.equal(a.log.bytes, 0);
  });
});

test("a second call in the same $OUT never replaces the first call's files", async () => {
  await withCwd(async (cwd, bin) => {
    await fakeProgram(cwd, bin);
    await put(cwd, "work/a.dll", asm("ok"));
    const first = parse(await job(cwd, bin, { path: "work/a.dll", decompile: true }));
    const before = await readFile(first.reconstruction.reconstruction_file);
    const second = parse(await job(cwd, bin, { path: "work/a.dll", decompile: true }));
    assert.notEqual(second.reconstruction.reconstruction_file, first.reconstruction.reconstruction_file);
    assert.match(second.reconstruction.reconstruction_file, /clr-inspect\.reconstruction-2\.cs$/);
    assert.deepEqual(await readFile(first.reconstruction.reconstruction_file), before);
  });
});

test("the program gets a fixed environment: no caller variable, no proxy, an empty home under the call's own directory", async () => {
  await withCwd(async (cwd, bin) => {
    await fakeProgram(cwd, bin);
    await put(cwd, "work/a.dll", asm("env"));
    const out = await job(cwd, bin, { path: "work/a.dll", decompile: true }, { env: { EXTRA_SECRET: "hunter2-value", http_proxy: "http://proxy.invalid:3128", HTTPS_PROXY: "http://proxy.invalid:3128" } });
    const a = parse(out);
    const text = await readFile(a.reconstruction.reconstruction_file, "utf8");
    assert.doesNotMatch(text, /EXTRA_SECRET|hunter2|proxy/i);
    assert.match(text, /^DOTNET_CLI_TELEMETRY_OPTOUT=1$/m);
    assert.match(text, /^HOME=.*\/out\/tool-output\/stage-/m);
  });
});

test("a nonzero exit status with output is partial: the file is kept and the answer says it may be incomplete; with nothing written it is failed and nothing is kept", async () => {
  await withCwd(async (cwd, bin) => {
    await fakeProgram(cwd, bin);
    await put(cwd, "work/p.dll", asm("partial_exit"));
    await put(cwd, "work/e.dll", asm("empty"));
    await put(cwd, "work/f.dll", asm("fail_empty"));
    const p = parse(await job(cwd, bin, { path: "work/p.dll", decompile: true }));
    assert.equal(p.status, "partial");
    assert.deepEqual(p.limits_hit, ["program_exit_status"]);
    assert.ok(p.log.bytes > 0, "the error text is in the log, and is not printed");
    assert.ok(!JSON.stringify(p).includes("could not decompile method X"));
    assert.match(await readFile(p.log.log_file, "utf8"), /could not decompile method X/);
    for (const f of ["e.dll", "f.dll"]) {
      const out = await job(cwd, bin, { path: `work/${f}`, decompile: true });
      const a = parse(out);
      assert.equal(a.status, "failed", f);
      assert.equal(out.code, 1);
      assert.equal(a.reconstruction, null);
    }
    assert.deepEqual((await outputs(cwd)).sort(), ["clr-inspect.log", "clr-inspect.reconstruction.cs"], "only the partial call's two files remain, no stage directory");
  });
});

test("the time limit ends the program and what it started; the partial file is removed and the answer is partial", async () => {
  await withCwd(async (cwd, bin) => {
    await fakeProgram(cwd, bin);
    await put(cwd, "work/h.dll", asm("hang"));
    const t0 = Date.now();
    const out = await job(cwd, bin, { path: "work/h.dll", decompile: true, max_seconds: 5 });
    const a = parse(out);
    assert.equal(a.status, "partial", JSON.stringify(a));
    assert.deepEqual(a.limits_hit, ["time"]);
    assert.equal(a.reconstruction, null);
    assert.ok(Date.now() - t0 < 40_000, `took ${Date.now() - t0} ms`);
    assert.ok(await gone(await pidFile(join(cwd, "pids", "prog.pid")), 10_000));
    assert.deepEqual(await outputs(cwd), []);
  });
});

test("a program that writes without end is ended at the output budget; the partial file is removed and nothing is reported complete", async () => {
  await withCwd(async (cwd, bin) => {
    await fakeProgram(cwd, bin);
    await put(cwd, "work/f.dll", asm("flood"));
    const a = parse(await job(cwd, bin, { path: "work/f.dll", decompile: true, max_output_bytes: 1 << 20 }));
    assert.equal(a.status, "partial", JSON.stringify(a));
    assert.deepEqual(a.limits_hit, ["max_output_bytes"]);
    assert.equal(a.reconstruction, null);
    assert.ok(await gone(await pidFile(join(cwd, "pids", "prog.pid")), 10_000));
    assert.deepEqual(await outputs(cwd), []);
  });
});

test("a program that prints error text without end is ended at the error cap", async () => {
  await withCwd(async (cwd, bin) => {
    await fakeProgram(cwd, bin);
    await put(cwd, "work/e.dll", asm("errflood"));
    const a = parse(await job(cwd, bin, { path: "work/e.dll", decompile: true }));
    assert.equal(a.status, "partial", JSON.stringify(a));
    assert.deepEqual(a.limits_hit, ["program_error_text_bytes"]);
    assert.ok(await gone(await pidFile(join(cwd, "pids", "prog.pid")), 10_000));
    assert.deepEqual(await outputs(cwd), []);
  });
});

test("a file that changes while the program reads it is failed and the reconstruction is removed", async () => {
  await withCwd(async (cwd, bin) => {
    await fakeProgram(cwd, bin);
    await put(cwd, "work/m.dll", asm("mutate"));
    const a = parse(await job(cwd, bin, { path: "work/m.dll", decompile: true }));
    assert.equal(a.status, "failed");
    assert.match(a.status_basis, /changed/);
    assert.deepEqual(await outputs(cwd), []);
  });
});

test("a process the program leaves behind when it ends is ended with it before the file is read, and the answer is partial, not complete", async () => {
  await withCwd(async (cwd, bin) => {
    await fakeProgram(cwd, bin);
    await put(cwd, "work/d.dll", asm("daemon"));
    await mkdir(join(cwd, "out"), { recursive: true });
    const r = startDetached(CLR, cwd, { path: "work/d.dll", decompile: true }, { JOB_ID: "j000001", OUT: join(cwd, "out"), SECRET_OUTPUT: "1" }, bin);
    try {
      assert.equal(await r.closed, 0, r.stdout());
      const a = JSON.parse(r.stdout()) as Json;
      assert.equal(a.status, "partial", JSON.stringify(a).slice(0, 300));
      assert.match(a.status_basis, /left 1 process/);
      assert.ok(a.limits_hit.includes("process_left_behind"));
      assert.ok(await gone(await pidFile(join(cwd, "pids", "child.pid")), 3_000), "the daemon is ended by the tool, not by the end of the test");
    } finally {
      try { r.killGroup(); } catch { /* gone */ }
    }
  });
});

/** A decompiler stand-in that forks a child which keeps appending to the reconstruction. The child's pid is recorded and killed at the end. */
for (const scenario of ["fork_now", "fork_late", "fork_double", "never_exit"]) {
  test(`a child the decompiler abandons (${scenario}) is ended before the file is hashed: partial, and the file is the answer's bytes and hash one second later`, async () => {
    await withCwd(async (cwd, bin) => {
      await fakeProgram(cwd, bin);
      await put(cwd, "work/c.dll", asm(scenario));
      let child = 0;
      try {
        const a = parse(await job(cwd, bin, { path: "work/c.dll", decompile: true }));
        child = await pidFile(join(cwd, "pids", "child.pid"), 3_000).catch(() => 0);
        assert.ok(child, "the child recorded its pid");
        assert.notEqual(a.status, "complete", JSON.stringify(a).slice(0, 400));
        assert.equal(a.status, "partial");
        assert.match(a.status_basis, /left \d+ process/);
        assert.ok(await gone(child, 3_000), "the child is ended");
        if (a.reconstruction) {
          const path = join(cwd, "out", "tool-output", (await outputs(cwd)).find((n) => n.endsWith(".cs"))!);
          const first = await readFile(path);
          assert.equal(first.length, a.reconstruction.bytes);
          assert.equal(sha(first), a.reconstruction.sha256);
          await new Promise((r) => setTimeout(r, 1_000));
          const later = await readFile(path);
          assert.equal(later.length, first.length, "the file did not grow after the answer");
          assert.equal(sha(later), a.reconstruction.sha256);
        }
      } finally {
        if (child) { try { process.kill(child, "SIGKILL"); } catch { /* gone */ } }
      }
    });
  });
}

test("a child the decompiler puts in a session of its own (setsid) cannot be ended: the answer is partial, says so, and no file is claimed", async () => {
  await withCwd(async (cwd, bin) => {
    await fakeProgram(cwd, bin);
    await put(cwd, "work/s.dll", asm("setsid_child"));
    let child = 0;
    try {
      const a = parse(await job(cwd, bin, { path: "work/s.dll", decompile: true }));
      child = await pidFile(join(cwd, "pids", "child.pid"), 3_000).catch(() => 0);
      assert.ok(child, "the child recorded its pid");
      assert.equal(a.status, "partial", JSON.stringify(a).slice(0, 400));
      assert.match(a.status_basis, /session of its own cannot be ended/);
      assert.ok(a.limits_hit.includes("process_left_running"));
      assert.equal(a.reconstruction, null);
      assert.deepEqual(await outputs(cwd), [], "the growing file was removed");
    } finally {
      if (child) { try { process.kill(child, "SIGKILL"); } catch { /* gone */ } }
    }
    if (child) assert.ok(await gone(child, 3_000), "the test ended the child by its recorded pid");
  });
});

test("a clean run leaves the file unchanged one second after a complete answer", async () => {
  await withCwd(async (cwd, bin) => {
    await fakeProgram(cwd, bin);
    await put(cwd, "work/ok.dll", asm("ok"));
    const a = parse(await job(cwd, bin, { path: "work/ok.dll", decompile: true }));
    assert.equal(a.status, "complete", JSON.stringify(a).slice(0, 300));
    const path = join(cwd, "out", "tool-output", (await outputs(cwd)).find((n) => n.endsWith(".cs"))!);
    await new Promise((r) => setTimeout(r, 1_000));
    const later = await readFile(path);
    assert.equal(later.length, a.reconstruction.bytes);
    assert.equal(sha(later), a.reconstruction.sha256);
  });
});

test("SIGTERM ends the program and what it started, removes the partial files, and answers once: failed, interrupted, exit 143", async () => {
  await withCwd(async (cwd, bin) => {
    await fakeProgram(cwd, bin);
    await put(cwd, "work/h.dll", asm("child"));
    await mkdir(join(cwd, "out"), { recursive: true });
    const r = startDetached(CLR, cwd, { path: "work/h.dll", decompile: true }, { JOB_ID: "j000001", OUT: join(cwd, "out"), SECRET_OUTPUT: "1" }, bin);
    try {
      const child = await pidFile(join(cwd, "pids", "child.pid"));
      r.signal("SIGTERM");
      r.signal("SIGTERM");
      assert.equal(await r.closed, 143);
      const word = JSON.parse(r.stdout()) as Json;
      assert.equal(word.status, "failed");
      assert.equal(word.interrupted, true);
      assert.equal(word.stopped_by_signal, 15);
      assert.ok(await gone(child, 10_000), "what the program started is ended");
      assert.deepEqual(await outputs(cwd), [], "the stage directory and its files are removed");
    } finally {
      try { r.signal("SIGKILL"); } catch { /* gone */ }
    }
  });
});

test("without ilspycmd the tool says so as JSON for decompile, and metadata mode is unaffected; a program that cannot answer --version is failed", async () => {
  const have = spawnSync("sh", ["-c", "command -v ilspycmd"]).status === 0;
  await withCwd(async (cwd, bin) => {
    await put(cwd, "work/a.dll", asm());
    if (!have) {
      const out = await job(cwd, bin, { path: "work/a.dll", decompile: true });
      const a = parse(out);
      assert.equal(a.status, "failed");
      assert.match(a.error, /ilspycmd is not installed/);
      assert.equal(out.code, 1);
    }
    await stub(bin, "ilspycmd", "echo broken >&2; exit 4");
    const b = parse(await job(cwd, bin, { path: "work/a.dll", decompile: true }));
    assert.equal(b.status, "failed");
    assert.match(b.status_basis, /--version/);
    assert.deepEqual(await outputs(cwd), []);
    const c = parse(await job(cwd, bin, { path: "work/a.dll" }));
    assert.equal(c.status, "complete");
  });
});

test("a program found only through a relative PATH entry is not run: the evidence's working directory is not searched", async () => {
  await withCwd(async (cwd, bin) => {
    await put(cwd, "work/a.dll", asm());
    const evil = "#!/bin/sh\necho started > ran.txt\necho v\n";
    await put(cwd, "ilspycmd", evil, 0o755);
    await put(cwd, "bin/ilspycmd", evil, 0o755);
    await mkdir(join(cwd, "out"), { recursive: true });
    const out = await tool(CLR, cwd, { path: "work/a.dll", decompile: true }, { JOB_ID: "j000001", OUT: join(cwd, "out"), SECRET_OUTPUT: "1", PATH: `.:bin::${process.env.PATH ?? ""}` });
    const a = parse(out);
    assert.equal(a.status, "failed");
    assert.match(a.error, /ilspycmd is not installed/);
    assert.equal(await readFile(join(cwd, "ran.txt")).then(() => true, () => false), false, "nothing under the working directory was started");
  });
});

test("a tool-output directory that is a link is refused and nothing is written through it", async () => {
  await withCwd(async (cwd, bin) => {
    await fakeProgram(cwd, bin);
    await put(cwd, "work/a.dll", asm());
    await mkdir(join(cwd, "out"), { recursive: true });
    await mkdir(join(cwd, "elsewhere"), { recursive: true });
    await symlink(join(cwd, "elsewhere"), join(cwd, "out", "tool-output"));
    const a = parse(await job(cwd, bin, { path: "work/a.dll", decompile: true }));
    assert.equal(a.status, "failed");
    assert.match(a.status_basis, /symbolic link/);
    assert.deepEqual(await readdir(join(cwd, "elsewhere")), []);
  });
});

test("a link, a directory and a missing file are refused as JSON; hostile parameters are refused, never a traceback", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "work/a.dll", asm());
    await symlink(join(cwd, "work/a.dll"), join(cwd, "work/link.dll"));
    await mkdir(join(cwd, "work/dir"), { recursive: true });
    for (const path of ["work/link.dll", "work/dir", "work/none.dll"]) {
      const out = await tool(CLR, cwd, { path });
      assert.equal(parse(out).status, "failed", path);
      assert.equal(out.code, 1);
    }
    for (const args of [{}, { path: 5 }, { path: "work/a.dll", decompile: "yes" }, { path: "work/a.dll", max_seconds: 1 }, { path: "work/a.dll", max_output_bytes: 5 },
      { path: "work/a.dll", extra: 1 }, { path: "a\0b" }, [], null]) {
      const out = await tool(CLR, cwd, args);
      assert.equal(parse(out).status, "failed", JSON.stringify(args));
      assert.equal(out.code, 1);
    }
  });
});

test("four calls at once, each running the program, all finish well inside the manifest's limit", async () => {
  await withCwd(async (cwd, bin) => {
    await fakeProgram(cwd, bin);
    for (let i = 0; i < 4; i++) await put(cwd, `work/a${i}.dll`, asm("ok"));
    const t0 = Date.now();
    const outs = await Promise.all([0, 1, 2, 3].map((i) => job(cwd, bin, { path: `work/a${i}.dll`, decompile: true })));
    for (const o of outs) assert.equal(parse(o).status, "complete");
    assert.ok(Date.now() - t0 < 60_000);
    assert.equal((await outputs(cwd)).length, 8, "four reconstructions and four logs, none replaced");
  });
});

const REAL = process.env.DFIRSWARM_CLR_SAMPLE;
const realSkip = spawnSync("sh", ["-c", "command -v ilspycmd"]).status !== 0 ? "ilspycmd is not installed on this machine" : !REAL ? "DFIRSWARM_CLR_SAMPLE does not name an assembly" : false;
test("with the real ilspycmd and a real assembly: a reconstruction is written whole and labelled", { skip: realSkip }, async (t) => {
  await withCwd(async (cwd, bin) => {
    await put(cwd, "work/real.dll", await readFile(REAL!));
    const a = parse(await job(cwd, bin, { path: "work/real.dll", decompile: true }));
    t.diagnostic(`ilspycmd: ${a.decompiler.version_output}`);
    assert.ok(["complete", "partial"].includes(a.status), JSON.stringify(a).slice(0, 400));
    assert.match(await readFile(a.reconstruction.reconstruction_file, "utf8"), /^\/\/ RECONSTRUCTION/);
  });
});
