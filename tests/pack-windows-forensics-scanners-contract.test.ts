/**
 * yara_scan and sigma_hunt against the tool contract (docs/packs.md, section 8), with the helpers of tests/windows-tool-contract.ts and stand-in engines
 * (a yara that prints what yara 4 prints for `-s -L`, a Hayabusa and a Zircolite that write what their documentation says):
 *
 *  - one clock over every phase of each tool, whatever the phase (the probes, the walk, yara, the digest; the engine, the parse, the sort);
 *  - a stop signal at three moments (early, child, print) gives one document, ends the stand-in and leaves no hidden file;
 *  - a rerun whose result is smaller never replaces the first file;
 *  - yara's console output is never a rule name; a path outside the target is not a rule line;
 *  - sigma_hunt survives a lone surrogate, fields of the wrong type and an empty directory, and says partial for the last;
 *  - both values modes are declared, and refused before anything is created outside a secret-output job.
 *
 * These tools carry the PROCESS block, which defines its own signal handler, so the STOP block is not added; "early" is the moment the module has run as far
 * as the installation of the handlers after it.
 *
 * Red check: WINDOWS_PACK_TOOLS=<a copy of the tools before the fixes> node --experimental-strip-types --test tests/pack-windows-forensics-scanners-contract.test.ts
 */
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { withCwd } from "./tool-library-harness.ts";
import { WIN, stub } from "./windows-pack-harness.ts";
import { NO_ADOPTION } from "./host-gates.ts";
import {
  assertJsonAnswer, assertStopped, fuzzTool, manifestOf, rerunSmaller, runTool, stopAt, typeConfused, withDeadline, scriptOf, type StopRun, type StopSignal,
} from "./windows-tool-contract.ts";

const SIGNALS: StopSignal[] = ["SIGTERM", "SIGINT", "SIGHUP"];
type Answer = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any
const path = (bin: string): Record<string, string> => ({ PATH: `${bin}:${process.env.PATH ?? ""}` });

// --- stand-ins ---------------------------------------------------------------------------------------------------------------------------

const YARA_PROBES = `case "$1" in
  --version) echo 4.5.8; exit 0;;
  --help) printf '%s\\n' '  -s,  --print-strings   print matching strings' '  -L,  --print-string-length   print length of matched strings' '  -q,  --disable-console-logs   disable printing console log messages' '  -N,  --no-follow-symlinks   do not follow symlinks'; exit 0;;
esac
for last; do :; done
`;

/** A yara that prints `rules` matches, each with one string line. */
const yaraPrinting = (rules: number, extra = ""): string => `${YARA_PROBES}${extra}
i=0
while [ $i -lt ${rules} ]; do echo "rule_$i $last/a.txt"; echo '0x0:5:$a: hello'; i=$((i+1)); done
`;

const yaraHanging = (pidFile: string): string => `${YARA_PROBES}echo $$ > '${pidFile}'\nexec sleep 120\n`;

const hayabusaWriting = (lines: string[], tail = ""): string => `case "$1" in --version|-V) echo "hayabusa 2.0"; exit 0;; esac
out=""
while [ $# -gt 0 ]; do case "$1" in -o) out="$2"; shift;; esac; shift; done
cat > "$out" <<'JSONL'
${lines.join("\n")}
JSONL
${tail}
`;

const hb = (title: string, level: string, id: number, details: unknown = { Cmd: "x" }): string =>
  JSON.stringify({ RuleTitle: title, Level: level, Timestamp: "2026-09-01T10:00:00Z", EventID: 4688, Channel: "Security", Computer: "WS01", RecordID: id, Details: details });

const hayabusaHanging = (pidFile: string): string => `case "$1" in --version|-V) echo "hayabusa 2.0"; exit 0;; esac\necho $$ > '${pidFile}'\nexec sleep 120\n`;

function evtxDir(cwd: string): string {
  mkdirSync(join(cwd, "work", "logs"), { recursive: true });
  writeFileSync(join(cwd, "work", "logs", "Security.evtx"), "ElfFile\0");
  return "work/logs";
}

function yaraInputs(cwd: string): { rules: string; target: string } {
  mkdirSync(join(cwd, "work", "t"), { recursive: true });
  writeFileSync(join(cwd, "work", "rules.yar"), "rule x { condition: true }\n");
  writeFileSync(join(cwd, "work", "t", "a.txt"), "hello\n");
  return { rules: "work/rules.yar", target: "work/t" };
}

const hunt = (cwd: string, extra: Record<string, unknown> = {}): Record<string, unknown> => ({ path: evtxDir(cwd), out_dir: "work/s1/hunt", ...extra });
const jobEnv = { SECRET_OUTPUT: "1" };

// --- the clock ----------------------------------------------------------------------------------------------------------------------------

test("yara_scan: a deadline of zero leaves yara no time and ends in a partial answer that names the clock", async () => {
  await withCwd(async (cwd, bin) => {
    await stub(bin, "yara", yaraPrinting(3));
    const answer = assertJsonAnswer(await runTool(withDeadline("yara_scan", 0), cwd, yaraInputs(cwd), path(bin)), "yara_scan") as Answer;
    assert.equal(answer.status, "partial");
    assert.match(String(answer.status_basis), /clock/);
    assert.equal(answer.complete, false);
  });
});

test("sigma_hunt: a deadline too short for the engine is a JSON failure that names the clock; one that cuts the engine is partial", async () => {
  await withCwd(async (cwd, bin) => {
    await stub(bin, "hayabusa", hayabusaWriting([hb("Rule A", "high", 1)], "sleep 120"));
    const none = await runTool(withDeadline("sigma_hunt", 0), cwd, hunt(cwd), path(bin), undefined);
    assert.notEqual(none.code, 0);
    const failed = assertJsonAnswer(none, "deadline 0") as Answer;
    assert.equal(failed.status, "failed");
    assert.match(String(failed.error), /clock/);
    // 135 s of clock less 120 s kept for what follows leaves the engine 15 s: it wrote its result and then hung, so the run is stopped there and partial
    const started = Date.now();
    const cut = assertJsonAnswer(await runTool(withDeadline("sigma_hunt", 135), cwd, hunt(cwd, { out_dir: "work/s1/hunt2" }), path(bin)), "135") as Answer;
    assert.ok(Date.now() - started < 60_000, `${Date.now() - started} ms`);
    assert.equal(cut.status, "partial");
    assert.match(String(cut.status_basis), /time limit/);
    assert.equal(cut.detection_count, 1);
  });
});

// --- stops --------------------------------------------------------------------------------------------------------------------------------

/** The moment the module has run as far as the installation of its handlers: the source up to there, then the signal. */
async function stopEarly(tool: string, signal: StopSignal): Promise<StopRun> {
  const text = readFileSync(scriptOf(tool), "utf8");
  const marker = 'STATE["last_word"] = last_word\ninstall_signal_handlers()\n';
  const end = text.indexOf(marker);
  assert.ok(end > 0, `${tool}: the handlers are installed at module level`);
  const dir = mkdtempSync(join(tmpdir(), "stop-early-"));
  try {
    const script = join(dir, "prefix.py");
    writeFileSync(script, `${text.slice(0, end + marker.length)}\nimport os as _os, signal as _signal, time as _time\n_os.kill(_os.getpid(), _signal.${signal})\n_time.sleep(30)\nprint("survived")\n`);
    const done = await runTool(script, dir, undefined, {}, "");
    return { ...done, moment: "early", sent: signal, cwd: dir, dirs: [], children: [] };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

for (const tool of ["yara_scan", "sigma_hunt"]) {
  for (const signal of SIGNALS) {
    test(`${tool}: ${signal} at early gives one JSON document and exit 128 plus the signal`, async () => {
      assert.equal(assertStopped(await stopEarly(tool, signal), signal).answered, true);
    });

    test(`${tool}: ${signal} while the engine runs ends it, removes the temporary files and gives one document`, async () => {
      await withCwd(async (cwd, bin) => {
        const pidFile = join(cwd, "engine.pid");
        let args: Record<string, unknown>;
        if (tool === "yara_scan") {
          await stub(bin, "yara", yaraHanging(pidFile));
          args = yaraInputs(cwd);
        } else {
          await stub(bin, "hayabusa", hayabusaHanging(pidFile));
          args = hunt(cwd);
        }
        const run = await stopAt(tool, args, path(bin), "child", signal, { cwd, pidFile });
        const got = assertStopped(run, signal);
        assert.equal(got.answered, true);
        assert.match(String(got.answer.status_basis), /temporary files|ended/);
      });
    });
  }

  test(`${tool}: a signal while the answer is being written does not cut it`, async () => {
    await withCwd(async (cwd, bin) => {
      let args: Record<string, unknown>;
      if (tool === "yara_scan") {
        await stub(bin, "yara", yaraPrinting(5000));
        args = { ...yaraInputs(cwd), limit: 10000 };
      } else {
        await stub(bin, "hayabusa", hayabusaWriting(Array.from({ length: 3000 }, (_, i) => hb(`Rule ${i % 50}`, "high", i))));
        args = hunt(cwd, { limit: 3000 });
      }
      const run = await stopAt(tool, args, path(bin), "print", "SIGTERM", { cwd });
      const got = assertStopped(run, "SIGTERM");
      assert.equal(got.answered, false, "the answer was written whole, then the tool ended by itself");
      assert.ok(run.stdout.length > 100_000, `${run.stdout.length} bytes`);
    });
  });
}

// --- reruns -------------------------------------------------------------------------------------------------------------------------------

test("yara_scan: a rerun with a shorter result (timeout_seconds 1) keeps the first file and names the second under -2", async () => {
  await withCwd(async (cwd, bin) => {
    await stub(bin, "yara", yaraPrinting(500));
    const first = { ...yaraInputs(cwd), limit: 5 };
    const out = await rerunSmaller("yara_scan", first, { ...first, timeout_seconds: 1 }, path(bin), {
      cwd,
      between: () => void stub(bin, "yara", yaraPrinting(50)),
    });
    assert.ok(out.added.length >= 1);
  });
});

// --- WIN-11: console output and paths ------------------------------------------------------------------------------------------------------

test("yara_scan: a rule's console line and a line for a path outside the target are counted and never shown; -q is passed where yara has it", async () => {
  await withCwd(async (cwd, bin) => {
    const planted = "KEY-" + randomBytes(6).toString("hex");
    await stub(bin, "yara", `${YARA_PROBES}
echo "$planted console message $planted"
echo "note_from_rule $planted"
echo "pw_rule /somewhere/else/b.txt"
echo "real_rule $last/a.txt"
echo '0x0:5:$a: hello'
`.replace("$planted", planted).replaceAll("$planted", planted));
    const run = await runTool("yara_scan", cwd, yaraInputs(cwd), path(bin));
    const answer = assertJsonAnswer(run, "console") as Answer;
    assert.deepEqual(answer.matches.map((m: Answer) => m.rule), ["real_rule"]);
    assert.equal(answer.ignored_lines, 3);
    assert.equal(run.stdout.includes(planted), false, "a console line is shown");
    assert.ok(answer.yara_argv.includes("-q"));
  });
});

// --- sigma_hunt: the engine's result ------------------------------------------------------------------------------------------------------------

test("sigma_hunt: a lone surrogate, fields of the wrong type and an empty directory are answered, counted and partial where they must be", { skip: NO_ADOPTION }, async () => {
  await withCwd(async (cwd, bin) => {
    await stub(bin, "hayabusa", hayabusaWriting([hb("Rule \\ud800 X", "high", 1, { Cmd: "a\\udfffb" }), hb("Rule B", "high", 2)]));
    const ok = assertJsonAnswer(await runTool("sigma_hunt", cwd, hunt(cwd), path(bin)), "surrogate") as Answer;
    assert.equal(ok.status, "complete", JSON.stringify(ok).slice(0, 400));
    assert.equal(ok.detection_count, 2);
    // a rule title that is a list, a matches value that is a string, a match that is not an object
    await stub(bin, "zircolite", `out=""
while [ $# -gt 0 ]; do case "$1" in --outfile) out="$2"; shift;; esac; shift; done
cat > "$out" <<'JSON'
[{"title": ["a", "list"], "rule_level": "high", "matches": [{"EventID": 1}]},
 {"title": "String matches", "rule_level": "high", "matches": "oops"},
 {"title": "Mixed", "rule_level": "high", "matches": [5, {"EventID": 4688, "Channel": "Security"}]},
 {"title": {"obj": 1}, "rule_level": "high", "matches": []}]
JSON
`);
    const mixed = assertJsonAnswer(await runTool("sigma_hunt", cwd, hunt(cwd, { out_dir: "work/s1/hunt-z", engine: "zircolite" }), path(bin)), "wrong shapes") as Answer;
    assert.equal(mixed.detection_count, 1);
    assert.equal(mixed.malformed_lines, 4);
    assert.equal(mixed.status, "partial");
    // a directory with no .evtx file
    mkdirSync(join(cwd, "work", "empty"), { recursive: true });
    const empty = assertJsonAnswer(await runTool("sigma_hunt", cwd, { path: "work/empty", out_dir: "work/s1/hunt-e", engine: "hayabusa" }, path(bin)), "empty") as Answer;
    assert.equal(empty.status, "partial");
    assert.match(String(empty.status_basis), /no \.evtx file/);
  });
});

test("sigma_hunt: rules_that_fired is bounded by limit, and the whole list is in a file", async () => {
  await withCwd(async (cwd, bin) => {
    await stub(bin, "hayabusa", hayabusaWriting(Array.from({ length: 300 }, (_, i) => hb(`Rule ${i}`, "high", i))));
    const answer = assertJsonAnswer(await runTool("sigma_hunt", cwd, hunt(cwd, { limit: 10 }), path(bin)), "fired") as Answer;
    assert.equal(answer.rules_that_fired.length, 10);
    assert.equal(answer.rules_fired, 300);
    assert.equal(answer.rules_fired_file.rows, 300);
  });
});

// --- arguments ----------------------------------------------------------------------------------------------------------------------------------

test("yara_scan and sigma_hunt: arguments of the wrong type (250 sets each, a top-level [] included) are all answered in JSON", async () => {
  await withCwd(async (cwd, bin) => {
    await stub(bin, "yara", yaraPrinting(2));
    await stub(bin, "hayabusa", hayabusaWriting([hb("Rule A", "high", 1)]));
    for (const [tool, base] of [["yara_scan", yaraInputs(cwd)], ["sigma_hunt", hunt(cwd)]] as Array<[string, Record<string, unknown>]>) {
      const seed = 2029;
      const statuses = await fuzzTool(tool, typeConfused(manifestOf(tool), 250, seed, base), seed, { cwd, env: path(bin) });
      assert.ok((statuses.failed ?? 0) > 0, JSON.stringify(statuses));
    }
  });
});

// --- secret output --------------------------------------------------------------------------------------------------------------------------------

test("yara_scan declares write_matches and sigma_hunt declares required; both refuse as JSON before anything is created outside a secret-output job", { skip: NO_ADOPTION }, async () => {
  await withCwd(async (cwd, bin) => {
    const yara = JSON.parse(readFileSync(join(WIN, "yara_scan", "manifest.json"), "utf8")) as Answer;
    assert.deepEqual(yara.secret_output, { when_args: ["write_matches"] });
    assert.equal(yara.params.write_matches.type, "boolean");
    const sigma = JSON.parse(readFileSync(join(WIN, "sigma_hunt", "manifest.json"), "utf8")) as Answer;
    assert.equal(sigma.secret_output, "required");
    await stub(bin, "yara", yaraPrinting(2));
    await stub(bin, "hayabusa", hayabusaWriting([hb("Rule A", "high", 1)]));
    const out = join(cwd, "out");
    mkdirSync(out);
    const job = { JOB_ID: "j1", OUT: out, SECRET_OUTPUT: "0", ...path(bin) };
    const refused = await runTool("yara_scan", cwd, { ...yaraInputs(cwd), write_matches: true }, job);
    assert.notEqual(refused.code, 0);
    assert.equal(assertJsonAnswer(refused, "write_matches").status, "failed");
    const refusedHunt = await runTool("sigma_hunt", cwd, { path: evtxDir(cwd), out_dir: join(out, "hunt") }, job);
    assert.notEqual(refusedHunt.code, 0);
    assert.equal(assertJsonAnswer(refusedHunt, "job without secret output").status, "failed");
    assert.deepEqual(readdirSync(out), [], "nothing was created");
    const ok = assertJsonAnswer(await runTool("sigma_hunt", cwd, { path: evtxDir(cwd), out_dir: join(out, "hunt") }, { ...job, ...jobEnv }), "secret job") as Answer;
    assert.equal(ok.status, "complete");
  });
});

// --- the shared blocks ---------------------------------------------------------------------------------------------------------------------------

test("yara_scan carries the PLACE and PAGE blocks of regkv byte for byte, and both tools their PROCESS block and no STOP block", () => {
  const block = (text: string, name: string): string => {
    const begin = `# BEGIN SHARED ${name}`;
    const end = `# END SHARED ${name}`;
    assert.ok(text.includes(begin), `no ${begin}`);
    return text.slice(text.indexOf(begin), text.indexOf(end) + end.length);
  };
  const sha = (s: string): string => createHash("sha256").update(s).digest("hex");
  const reg = readFileSync(join(WIN, "regkv", "run.py"), "utf8");
  const yara = readFileSync(join(WIN, "yara_scan", "run.py"), "utf8");
  for (const name of ["PLACE", "PAGE"]) assert.equal(sha(block(yara, name)), sha(block(reg, name)), name);
  const sigma = readFileSync(join(WIN, "sigma_hunt", "run.py"), "utf8");
  assert.equal(sha(block(yara, "PROCESS")), sha(block(sigma, "PROCESS")));
  for (const text of [yara, sigma]) {
    assert.doesNotMatch(text, /# BEGIN SHARED STOP/);
    assert.match(text, /^DEADLINE_SECONDS = \d+ /m);
    assert.doesNotMatch(text, /\bLosslessPage\(/);
  }
});
