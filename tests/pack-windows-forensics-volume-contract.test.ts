/**
 * extract_stream and vss_stores against the tool contract (docs/packs.md, section 8), with the helpers of tests/windows-tool-contract.ts. The two run
 * programs (icat, vshadowinfo), which are stand-ins here that follow the programs' documented command lines: icat writes the stream to standard output,
 * vshadowinfo prints a report. What is held:
 *
 *  - one clock covers each tool's whole run: a digest of a huge sparse output that the clock cuts gives `not_hashed` and `partial`, and the output is
 *    still named; vshadowinfo's reading is inside the clock;
 *  - a stop signal at four moments (the module has loaded; a program is running; the answer is being written) gives one JSON document, exit 128 plus
 *    the signal, no stand-in left alive; the last word is set before any file is made;
 *  - the output, the .partial and the standard error files are mode 0600; vss_stores' files too;
 *  - arguments of the wrong type, a top-level array included, are refused as JSON.
 *
 * Red check: WINDOWS_PACK_TOOLS=<a copy of the tools before the fixes> node --experimental-strip-types --test tests/pack-windows-forensics-volume-contract.test.ts
 */
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { withCwd } from "./tool-library-harness.ts";
import { WIN, stub } from "./windows-pack-harness.ts";
import {
  assertJsonAnswer, assertStopped, fuzzTool, manifestOf, runTool, standIn, stopAt, typeConfused, withDeadline, type Moment, type StopSignal,
} from "./windows-tool-contract.ts";

const SIGNALS: StopSignal[] = ["SIGTERM", "SIGINT", "SIGHUP"];
type Answer = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

const modeOf = (path: string): number => statSync(path).mode & 0o777;

/** icat: a file of `gigabytes` GB made sparse on standard output (an ftruncate, so nothing is written), after `delay` seconds. */
const sparseIcat = (gigabytes: number, delay = 0): string => `sleep ${delay}\npython3 -c "import os; os.ftruncate(1, ${gigabytes} << 30)"`;

function setup(cwd: string): Record<string, string> {
  mkdirSync(join(cwd, "bin"), { recursive: true });
  writeFileSync(join(cwd, "work", "disk.raw"), Buffer.alloc(4096));
  return { PATH: `${join(cwd, "bin")}:${process.env.PATH ?? ""}` };
}

const REPORT = (shown: number): string => {
  const lines = ["vshadowinfo 20240504", "", "Volume Shadow Snapshot information:", `\tNumber of stores:\t${shown}`];
  for (let i = 1; i <= shown; i++) lines.push("", `Store: ${i}`, `\tIdentifier\t\t: 0b3cd1ec-aaaa-bbbb-cccc-${String(i).padStart(12, "0")}`, `\tCreation time\t\t: Oct 14, 2023 16:14:30.000000000 UTC`, `\tVolume size\t\t: 53 GiB (57982058496 bytes)`);
  return lines.join("\n");
};

async function vshadow(cwd: string, shown: number): Promise<void> {
  writeFileSync(join(cwd, "report.txt"), REPORT(shown));
  await stub(join(cwd, "bin"), "vshadowinfo", `cat '${join(cwd, "report.txt")}'`);
}

const EXTRACT = (cwd: string, name = "x.bin"): Record<string, unknown> => ({ image: "work/disk.raw", inode: "168-128-4", output: `work/s1/${name}` });

// --- one clock -----------------------------------------------------------------------------------------------------------------------

test("extract_stream: a digest the clock cuts gives not_hashed and partial, and the 30 GB sparse output is still named (a deadline of zero)", async () => {
  await withCwd(async (cwd) => {
    const env = setup(cwd);
    await stub(join(cwd, "bin"), "icat", sparseIcat(30));
    const answer = assertJsonAnswer(await runTool(withDeadline("extract_stream", 0), cwd, EXTRACT(cwd), env), "extract_stream") as Answer;
    assert.equal(answer.status, "partial");
    assert.equal(answer.not_hashed, true);
    assert.equal(answer.sha256, null);
    assert.equal(answer.size, 30 * 2 ** 30);
    assert.equal(answer.output, "work/s1/x.bin");
    assert.match(String(answer.status_basis), /clock/);
    assert.equal(statSync(join(cwd, "work", "s1", "x.bin")).size, 30 * 2 ** 30, "the output is there, whole");
  });
});

test("extract_stream: a small output is digested whole and complete, with a status_basis", async () => {
  await withCwd(async (cwd) => {
    const env = setup(cwd);
    await stub(join(cwd, "bin"), "icat", "printf 'hello'");
    const answer = assertJsonAnswer(await runTool("extract_stream", cwd, EXTRACT(cwd), env), "small") as Answer;
    assert.equal(answer.status, "complete");
    assert.equal(answer.sha256, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
  });
});

test("vss_stores: a deadline of zero stops the reading of vshadowinfo's output: partial, with the clock named", async () => {
  await withCwd(async (cwd) => {
    const env = setup(cwd);
    await vshadow(cwd, 5);
    const answer = assertJsonAnswer(await runTool(withDeadline("vss_stores", 0), cwd, { image: "work/disk.raw" }, env), "vss_stores") as Answer;
    assert.equal(answer.status, "partial");
    assert.match(String(answer.status_basis), /clock/);
    assert.equal(answer.stopped_by_time_limit, true);
  });
});

/** The module run as far as its handlers are installed (the PROCESS carriers have no STOP block), the signal sent from there. */
async function earlyProcess(tool: string, signal: StopSignal) {
  const text = readFileSync(join(WIN, tool, "run.py"), "utf8");
  const marker = "\ninstall_signal_handlers()\n";
  const at = text.indexOf(marker);
  assert.ok(at > 0 && text.indexOf(marker, at + 1) < 0, tool + " installs its handlers once, at module level");
  const dir = mkdtempSync(join(tmpdir(), "early-process-"));
  try {
    const script = join(dir, "prefix.py");
    writeFileSync(script, text.slice(0, at + marker.length) + "\nimport os as _os, signal as _signal, time as _time\n_os.kill(_os.getpid(), _signal." + signal + ")\n_time.sleep(30)\nprint('survived')\n");
    const done = await runTool(script, dir, undefined, {}, "");
    return { ...done, moment: "early" as Moment, sent: signal, cwd: dir, dirs: [] as string[], children: [] as number[] };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

// --- stops -----------------------------------------------------------------------------------------------------------------------------

for (const tool of ["extract_stream", "vss_stores"] as const) {
  for (const signal of SIGNALS) {
    test(`${tool}: ${signal} at early gives one JSON document and exit 128 plus the signal`, async () => {
      await withCwd(async (cwd) => {
        const got = assertStopped(await earlyProcess(tool, signal), signal);
        assert.equal(got.answered, true);
      });
    });

    test(`${tool}: ${signal} while the stand-in program runs ends it, leaves none alive and gives one JSON document`, async () => {
      await withCwd(async (cwd) => {
        const env = setup(cwd);
        const pidFile = join(cwd, "child.pid");
        await standIn(join(cwd, "bin"), tool === "extract_stream" ? "icat" : "vshadowinfo", pidFile);
        const args = tool === "extract_stream" ? EXTRACT(cwd) : { image: "work/disk.raw" };
        const run = await stopAt(tool, args, env, "child" as Moment, signal, { cwd, pidFile });
        const got = assertStopped(run, signal);
        assert.equal(got.answered, true);
        assert.match(String(got.answer.status_basis), /signal/);
        if (tool === "extract_stream") assert.ok(got.answer.partial_file, "what icat wrote is kept as the .partial file");
      });
    });
  }

  test(`${tool}: a signal while the answer is being written does not cut it`, async () => {
    await withCwd(async (cwd) => {
      const env = setup(cwd);
      let args: Record<string, unknown>;
      if (tool === "extract_stream") {
        // icat's first five standard-error lines are in the answer: five lines of 150 KB make it larger than the pipe
        await stub(join(cwd, "bin"), "icat", `for i in 1 2 3 4 5; do head -c 150000 /dev/zero | tr '\\0' x >&2; echo >&2; done\nprintf 'z'`);
        args = EXTRACT(cwd);
      } else {
        await vshadow(cwd, 3000);
        args = { image: "work/disk.raw" };
      }
      const run = await stopAt(tool, args, env, "print", "SIGTERM", { cwd });
      const got = assertStopped(run, "SIGTERM");
      assert.equal(got.answered, false, "the answer was written whole, then the tool ended by itself");
      assert.ok(run.stdout.length > 100_000, `${run.stdout.length} bytes`);
    });
  });
}

// --- files and arguments -------------------------------------------------------------------------------------------------------------------

test("extract_stream: the output, its standard error file and a .partial are mode 0600", async () => {
  await withCwd(async (cwd) => {
    const env = setup(cwd);
    await stub(join(cwd, "bin"), "icat", "printf 'abc'; echo 'a warning' >&2");
    const ok = assertJsonAnswer(await runTool("extract_stream", cwd, EXTRACT(cwd, "ok.bin"), env), "ok") as Answer;
    assert.equal(modeOf(join(cwd, "work/s1/ok.bin")), 0o600);
    assert.equal(modeOf(join(cwd, ok.stderr_file)), 0o600);
    await stub(join(cwd, "bin"), "icat", "printf 'abc'; echo 'broken' >&2; exit 3");
    const bad = await runTool("extract_stream", cwd, EXTRACT(cwd, "bad.bin"), env);
    const failed = assertJsonAnswer(bad, "failed") as Answer;
    assert.equal(failed.status, "failed");
    assert.equal(modeOf(join(cwd, failed.partial_file)), 0o600);
    assert.equal(modeOf(join(cwd, failed.stderr_file)), 0o600);
  });
});

test("vss_stores: its stdout and stderr files are mode 0600, and a rerun takes the next free name", async () => {
  await withCwd(async (cwd) => {
    const env = setup(cwd);
    await vshadow(cwd, 2);
    const one = assertJsonAnswer(await runTool("vss_stores", cwd, { image: "work/disk.raw" }, env), "one") as Answer;
    const two = assertJsonAnswer(await runTool("vss_stores", cwd, { image: "work/disk.raw" }, env), "two") as Answer;
    assert.equal(one.status, "complete");
    assert.notEqual(one.stdout_file, two.stdout_file);
    for (const f of [one.stdout_file, one.stderr_file, two.stdout_file, two.stderr_file]) assert.equal(modeOf(join(cwd, f)), 0o600, f);
    assert.deepEqual(readdirSync(join(cwd, "work", "s1", "tool-output")).filter((n) => n.startsWith(".")), []);
  });
});

test("vss_stores: a top-level [] and other non-objects are refused as JSON", async () => {
  await withCwd(async (cwd) => {
    const env = setup(cwd);
    for (const bad of [[], 5, "x", null]) {
      const run = await runTool("vss_stores", cwd, bad, env);
      assert.notEqual(run.code, 0);
      assert.equal(assertJsonAnswer(run, JSON.stringify(bad)).status, "failed");
    }
  });
});

for (const tool of ["extract_stream", "vss_stores"] as const) {
  test(`${tool}: arguments of the wrong type (250 sets) are all answered in JSON`, async () => {
    await withCwd(async (cwd) => {
      const env = setup(cwd);
      await vshadow(cwd, 2);
      await stub(join(cwd, "bin"), "icat", "printf 'abc'");
      const base = tool === "extract_stream" ? { image: "work/disk.raw", inode: "168", output: "work/s1/fuzz.bin" } : { image: "work/disk.raw" };
      const seed = 2029;
      const statuses = await fuzzTool(tool, typeConfused(manifestOf(tool), 250, seed, base), seed, { cwd, env });
      assert.ok((statuses.failed ?? 0) > 0, JSON.stringify(statuses));
    });
  });
}

test("extract_stream and vss_stores keep the windows PROCESS block (no STOP block) and a whole-run deadline below the manifest's 300 s", () => {
  for (const tool of ["extract_stream", "vss_stores"]) {
    const text = readFileSync(join(WIN, tool, "run.py"), "utf8");
    assert.ok(text.includes("# BEGIN SHARED PROCESS"), tool);
    assert.ok(!text.includes("# BEGIN SHARED STOP"), tool);
    const m = /^DEADLINE_SECONDS = (\d+) /m.exec(text);
    assert.ok(m && Number(m[1]) < 300, `${tool}: ${m?.[0]}`);
    assert.match(text, /^install_signal_handlers\(\)$/m, `${tool} installs its handlers at module level`);
  }
});
