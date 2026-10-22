/**
 * The windows-artefacts recipe: it reads the Windows artefacts of an extracted collection family by family with the tools of the pack,
 * and says, for each family, whether it was parsed, partial, empty, unsupported, failed or not attempted.
 *
 * What the cases hold:
 *   - detect classifies by name and first bytes (a decoy named like a hive is not one; a pipe is never read; a link is not followed),
 *     says `could not tell` (exit 2) for a walk that ran out of time or a path that is not there, and never `does not apply` for them;
 *   - run writes the receipt before the first tool and after every family, the whole answer of every call is in results.jsonl,
 *     a family with no input is not_attempted with the reason, and the status of the run follows the families (not the host);
 *   - a hive whose logs were replayed is read by the other hive tools from the recovered copy, and the row says so;
 *   - a tool that fails, refuses or runs past its time is a named status of its family and the run is partial, never complete;
 *   - the recipe never asks a tool to write a withheld value;
 *   - dissect.target's functions are run only for a target of one directory and only when target-query is installed, each as its own
 *     call with its whole stdout and stderr kept, and a function the installed version lacks is `unsupported`;
 *   - every program stays in the recipe's group: SIGTERM ends the running tool, writes the receipt as partial and exits 143.
 * The tools of the pack are the real ones; where a case needs a tool to fail or hang, a copy of the pack's tools and recipe is made in
 * a temporary directory and that one tool is replaced there.
 */
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { cp, mkdir, mkdtemp, readFile, readdir, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { withCwd } from "./tool-library-harness.ts";
import { REGIPY, WIN, py, stub } from "./windows-pack-harness.ts";
import { hive } from "./windows-hive.ts";
import { BASE_BLOCK, FILETIME_A, cfb, destList, differingPages, hvleLog, lnk, pathWithOnlyPython, withSequences } from "./windows-t1-fixtures.ts";

type Answer = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

const RECIPE_DIR = join(WIN, "..", "recipes", "windows-artefacts");
const RECIPE = join(RECIPE_DIR, "run.py");
const RECORDS = !REGIPY;

const LINK = lnk({ local: { path: "C:\\case\\report.txt", serial: 0x1a2b3c4d, label: "SYSTEM" }, name: "Report" });
const JUMP = cfb([{ name: "1", data: LINK }, { name: "DestList", data: destList(4, [{ number: 1, host: "WKS", filetime: FILETIME_A, pin: -1, path: "C:\\case\\report.txt" }]) }]);
const gen = (n: number): Buffer => hive({ name: "ROOT", children: [{ name: "Software", children: [{ name: "Run", values: [{ name: "App", type: "sz", value: `C:\\gen${n}.exe` }] }] }] }, { primarySeq: 10, secondarySeq: 10 });
const G = [gen(0), gen(1)];
const BINS = G[0].length - BASE_BLOCK;
const LOG = hvleLog(G[1], [{ sequence: 10, hiveBinsDataSize: BINS, pages: differingPages(G[0], G[1]) }], { primary: 10 });

/** A collection: a dirty NTUSER.DAT with its logs, a clean SYSTEM hive, a link, a jump list, and files that are none of these. */
async function collection(root: string): Promise<void> {
  const user = join(root, "C", "Users", "x");
  await mkdir(user, { recursive: true });
  await writeFile(join(user, "NTUSER.DAT"), withSequences(G[0], 11, 10));
  await writeFile(join(user, "NTUSER.DAT.LOG1"), LOG);
  await mkdir(join(root, "C", "Windows", "System32", "config"), { recursive: true });
  await writeFile(join(root, "C", "Windows", "System32", "config", "SYSTEM"), G[0]);
  await mkdir(join(user, "AppData", "Recent"), { recursive: true });
  await writeFile(join(user, "AppData", "Recent", "report.lnk"), LINK);
  await writeFile(join(user, "AppData", "Recent", "1b4dd67f29cb1962.automaticDestinations-ms"), JUMP);
  await writeFile(join(root, "C", "notes.txt"), "not an artefact");
  await writeFile(join(user, "SAM"), "a file named like a hive that is not one");
}

type Run = { code: number | null; stdout: string; stderr: string };
function recipe(cwd: string, args: string[], env: Record<string, string> = {}, entry: string = RECIPE): Run {
  const r = spawnSync("python3", [entry, ...args], { cwd, encoding: "utf8", env: { ...process.env, AGENT_ID: "s1", ...env } });
  return { code: r.status, stdout: r.stdout, stderr: r.stderr };
}
const target = (...paths: string[]): string => JSON.stringify({ paths });
const coverage = async (out: string): Promise<Answer> => JSON.parse(await readFile(join(out, "coverage.json"), "utf8")) as Answer;
const results = async (out: string, family: string): Promise<Answer[]> => (await readFile(join(out, family, "results.jsonl"), "utf8")).trim().split("\n").map((l) => JSON.parse(l) as Answer);

// ---- detect -----------------------------------------------------------------------------------------------------------------

test("detect: a collection applies (exit 0) with the families it holds; a decoy named like a hive, a text file and an empty directory do not", async () => {
  await withCwd(async (cwd) => {
    await collection(join(cwd, "c1"));
    const yes = recipe(cwd, ["detect", "--target", target("c1")]);
    assert.equal(yes.code, 0, yes.stderr);
    const said = JSON.parse(yes.stdout) as Answer;
    assert.equal(said.applies, true);
    assert.match(said.why, /registry-hives/);
    assert.match(said.why, /shortcuts-jumplists/);
    assert.equal(said.status, "complete");
    // Only the decoy and a text file: nothing to read.
    await mkdir(join(cwd, "c2"));
    await writeFile(join(cwd, "c2", "SAM"), "not a hive");
    await writeFile(join(cwd, "c2", "x.evtx"), "not an event log");
    await writeFile(join(cwd, "c2", "x.pf"), "not prefetch");
    const no = recipe(cwd, ["detect", "--target", target("c2")]);
    assert.equal(no.code, 1);
    assert.equal((JSON.parse(no.stdout) as Answer).applies, false);
    await mkdir(join(cwd, "c3"));
    assert.equal(recipe(cwd, ["detect", "--target", target("c3")]).code, 1);
    // A file, named one by one.
    assert.equal(recipe(cwd, ["detect", "--target", target("c1/C/Users/x/NTUSER.DAT")]).code, 0);
    assert.equal(recipe(cwd, ["detect", "--target", target("c2/SAM")]).code, 1);
  });
});

test("detect: a path that is not there, a target that is not JSON, and a walk that ran out of time are `could not tell` (exit 2), never `does not apply`", async () => {
  await withCwd(async (cwd) => {
    const missing = recipe(cwd, ["detect", "--target", target("none")]);
    assert.equal(missing.code, 2);
    assert.equal((JSON.parse(missing.stdout) as Answer).applies, "unknown");
    assert.equal(recipe(cwd, ["detect", "--target", "{not json"]).code, 2);
    assert.equal(recipe(cwd, ["detect", "--target", JSON.stringify({ paths: [] })]).code, 2);
    assert.equal(recipe(cwd, ["detect"]).code, 2);
    // A walk that is cut short and found nothing: in-process, with the walk's clock already past.
    await mkdir(join(cwd, "some"));
    const out = py(
      `
import contextlib, importlib.util, io, json, sys
spec = importlib.util.spec_from_file_location("wa", sys.argv[1]); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
m.walk = lambda paths, deadline: ([], True, 12)
buf = io.StringIO()
code = None
with contextlib.redirect_stdout(buf):
    try:
        m.detect([sys.argv[2]])
    except SystemExit as e:
        code = e.code
print(json.dumps({"code": code, "said": json.loads(buf.getvalue())}))
`,
      RECIPE,
      join(cwd, "some"),
    );
    const cut = JSON.parse(out) as Answer;
    assert.equal(cut.code, 2);
    assert.equal(cut.said.applies, "unknown");
    assert.match(cut.said.status_basis, /time or entry limit/);
    // And one that was cut short but found something says what it found, and that others may exist.
    const some = py(
      `
import contextlib, importlib.util, io, json, sys
spec = importlib.util.spec_from_file_location("wa", sys.argv[1]); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
m.walk = lambda paths, deadline: ([("event-logs", "/x/a.evtx")], True, 12)
buf = io.StringIO()
code = None
with contextlib.redirect_stdout(buf):
    try:
        m.detect([sys.argv[2]])
    except SystemExit as e:
        code = e.code
print(json.dumps({"code": code, "said": json.loads(buf.getvalue())}))
`,
      RECIPE,
      join(cwd, "some"),
    );
    const found = JSON.parse(some) as Answer;
    assert.equal(found.code, 0);
    assert.equal(found.said.status, "partial");
    assert.match(found.said.status_basis, /others may exist/);
  });
});

test("detect: a pipe is never read, a link is not followed, and the bytes of a file whose name is none of the names are not read", async () => {
  await withCwd(async (cwd) => {
    const root = join(cwd, "c");
    await mkdir(join(root, "sub"), { recursive: true });
    if (spawnSync("mkfifo", [join(root, "NTUSER.DAT")]).status === 0) {
      // Named like a hive and a pipe with no writer: reading it would block.
      const began = Date.now();
      const r = recipe(cwd, ["detect", "--target", target("c")]);
      assert.equal(r.code, 1);
      assert.ok(Date.now() - began < 20_000, "did not block on the pipe");
    }
    await writeFile(join(cwd, "real.dat"), G[0]);
    await symlink("../real.dat", join(root, "sub", "NTUSER.DAT"));
    await symlink("..", join(root, "sub", "up"));
    assert.equal(recipe(cwd, ["detect", "--target", target("c")]).code, 1, "a link to a hive is not a hive of the collection");
  });
});

test("detect and run stop at a walk's time or entry limit and say so", async () => {
  await withCwd(async (cwd) => {
    const out = py(
      `
import importlib.util, json, os, sys, time
spec = importlib.util.spec_from_file_location("wa", sys.argv[1]); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
os.makedirs(sys.argv[2] + "/d1/d2"); open(sys.argv[2] + "/d1/d2/x.txt", "w").write("x")
found, cut, seen = m.walk([sys.argv[2] + "/d1"], time.monotonic() - 1)
print(json.dumps({"found": found, "cut": cut}))
`,
      RECIPE,
      cwd,
    );
    const said = JSON.parse(out) as Answer;
    assert.equal(said.cut, true);
    assert.deepEqual(said.found, []);
  });
});

// ---- run --------------------------------------------------------------------------------------------------------------------

test("run: every family gets a status with its reason, the whole answer of every call is kept, and a dirty hive's logs are replayed and named", async () => {
  await withCwd(async (cwd) => {
    await collection(join(cwd, "c"));
    const out = join(cwd, "out");
    const r = recipe(cwd, ["run", "--target", target("c"), "--out", out]);
    assert.equal(r.code, 0, r.stderr + r.stdout);
    assert.doesNotMatch(r.stderr, /Traceback/);
    const cov = await coverage(out);
    assert.equal(cov.recipe, "windows-artefacts");
    assert.equal(cov.receipt_written, "after the last family");
    // The family list: every family of the recipe is in the receipt, with a status from the closed set.
    const states = ["parsed", "partial", "empty", "unsupported", "failed", "not_attempted"];
    for (const [name, fam] of Object.entries(cov.families) as Array<[string, Answer]>) {
      assert.ok(states.includes(fam.status), `${name}: ${fam.status}`);
      assert.ok(typeof fam.reason === "string" && fam.reason.length > 0, `${name} has its reason`);
    }
    for (const none of ["amcache", "prefetch", "event-logs", "recycle-bin", "mft", "usn-journal", "esedb", "browser-history"]) {
      assert.equal(cov.families[none].status, "not_attempted", none);
      assert.match(cov.families[none].reason, /no file of this family/);
    }
    assert.equal(cov.families["registry-hives"].inputs, 2, "NTUSER.DAT and SYSTEM; SAM (a decoy) and the .LOG1 are not hives");
    assert.equal(cov.families["shortcuts-jumplists"].inputs, 2);
    assert.equal(cov.families["shortcuts-jumplists"].status, "parsed");
    assert.equal(cov.families.plaso.status, "not_attempted");
    assert.match(cov.not_covered, /Plaso/);
    assert.match(cov.status_basis, /not coverage of the host|families/);
    // The links and the jump list are read with lnk_jumplist, once for the directory, and its answer is whole in results.jsonl.
    const links = await results(out, "shortcuts-jumplists");
    assert.equal(links.length, 1);
    assert.equal(links[0].tool, "lnk_jumplist");
    assert.equal(links[0].answer.counts.links, 2);
    assert.equal(links[0].state, "parsed");
    // The hive with its logs: registry_recover is given the logs it found beside it, and replays them.
    const hives = await results(out, "registry-hives");
    const dirty = hives.find((h) => String(h.input).endsWith("NTUSER.DAT"))!;
    assert.equal(dirty.tool, "registry_recover");
    assert.ok(String(dirty.arguments.log1).endsWith("NTUSER.DAT.LOG1"), "the log beside the hive is named in the call");
    assert.equal(dirty.arguments.log2, undefined);
    if (RECORDS) {
      assert.equal(dirty.answer.replayed, true);
      assert.equal(dirty.state, "parsed");
      assert.equal(cov.families["registry-hives"].status, "parsed");
    }
    // The index names the receipt and every results file.
    const index = await readFile(join(out, "index.tsv"), "utf8");
    assert.match(index, /^coverage\.json\t/m);
    assert.match(index, /^registry-hives\/results\.jsonl\t/m);
    assert.match(index, /^shortcuts-jumplists\/results\.jsonl\t/m);
    // The recipe never asked a tool to write a withheld value.
    for (const family of ["registry-hives", "shortcuts-jumplists", "shellbags"]) {
      for (const row of await results(out, family).catch(() => [])) assert.doesNotMatch(JSON.stringify(row.arguments ?? {}), /write_values|write_strings|write_url_secrets/);
    }
  });
});

test("run: the other hive tools read the recovered copy of a hive whose logs were replayed, and the row says so", { skip: REGIPY }, async () => {
  await withCwd(async (cwd) => {
    await collection(join(cwd, "c"));
    const out = join(cwd, "out");
    assert.equal(recipe(cwd, ["run", "--target", target("c"), "--out", out]).code, 0);
    const [row] = await results(out, "shellbags");
    assert.ok(row, "shellbags was called for the NTUSER.DAT");
    assert.match(row.note, /read from the recovered copy of .*NTUSER\.DAT made by registry_recover/);
    assert.match(row.arguments.hive, /registry_recover-[0-9a-f]+\/recovered\.hive$/);
    // The clean SYSTEM hive is not a shellbags or amcache input.
    assert.equal((await results(out, "shellbags")).length, 1);
  });
});

test("run: a target that holds nothing the recipe reads is a failed run, and a missing path is refused; the receipt is written before the first tool", async () => {
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "empty"));
    const out = join(cwd, "out");
    const r = recipe(cwd, ["run", "--target", target("empty"), "--out", out]);
    assert.equal(r.code, 2);
    const cov = await coverage(out);
    assert.equal(cov.status, "failed");
    assert.match(cov.status_basis, /no artefact of a family/);
    const missing = recipe(cwd, ["run", "--target", target("none"), "--out", join(cwd, "out2")]);
    assert.equal(missing.code, 2);
    assert.match((JSON.parse(missing.stdout) as Answer).error, /does not exist/);
    assert.equal(recipe(cwd, ["run", "--target", target("empty")]).code, 2);
    assert.equal(recipe(cwd, ["nonsense", "--target", target("empty")]).code, 2);
    assert.equal(recipe(cwd, ["run", "--target", target("empty"), "--out", join(cwd, "o3"), "--bogus"]).code, 2);
  });
});

// ---- a tool that fails, refuses or hangs ------------------------------------------------------------------------------------

/** A copy of the pack's tools and the recipe, so that one tool can be replaced by a stand-in without touching the pack. */
async function withPackCopy(fn: (root: string, entry: string) => Promise<void>): Promise<void> {
  const root = await mkdtemp(join(tmpdir(), "wa-pack-"));
  try {
    await cp(join(WIN, ".."), join(root, "windows-forensics"), { recursive: true, filter: (p) => !p.includes("__pycache__") && !p.includes("/skills") && !p.includes("/goals") });
    await fn(join(root, "windows-forensics"), join(root, "windows-forensics", "recipes", "windows-artefacts", "run.py"));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}
async function replace(root: string, tool: string, script: string, timeout?: number): Promise<void> {
  await writeFile(join(root, "tools", tool, "run.py"), script);
  if (timeout !== undefined) {
    const path = join(root, "tools", tool, "manifest.json");
    const m = JSON.parse(await readFile(path, "utf8")) as Answer;
    m.timeout_seconds = timeout;
    await writeFile(path, JSON.stringify(m));
  }
}

test("run: a tool that crashes is `failed`, one that refuses the input as not its kind is `unsupported`, one that answers partial is `partial`, one that finds nothing is `empty` — and the run is partial, never complete", async () => {
  await withCwd(async (cwd) => {
    await withPackCopy(async (pack, entry) => {
      const root = join(cwd, "c");
      await mkdir(join(root, "a"), { recursive: true });
      await mkdir(join(root, "b"), { recursive: true });
      await mkdir(join(root, "c"), { recursive: true });
      await mkdir(join(root, "d"), { recursive: true });
      const evtx = Buffer.concat([Buffer.from("ElfFile\0"), Buffer.alloc(100)]);
      await writeFile(join(root, "a", "Security.evtx"), evtx);
      await writeFile(join(root, "b", "System.evtx"), evtx);
      await writeFile(join(root, "c", "Application.evtx"), evtx);
      const pf = Buffer.concat([Buffer.alloc(4), Buffer.from("SCCA"), Buffer.alloc(100)]);
      await writeFile(join(root, "d", "A.EXE-12345678.pf"), pf);
      // evtx_query: crash for one file, refuse another, partial for the third.
      await replace(pack, "evtx_query", `import json, sys
a = json.load(sys.stdin)
p = a["path"]
if "Security" in p:
    sys.stderr.write("Traceback (most recent call last):\\nboom\\n"); sys.exit(1)
if "System" in p:
    print(json.dumps({"error": "this is not an event log file: the signature is wrong"})); sys.exit(1)
print(json.dumps({"status": "partial", "event_count": 3}))
`);
      await replace(pack, "prefetch_mam", `import json, sys
json.load(sys.stdin)
print(json.dumps({"status": "complete", "entry_count": 0}))
`);
      const out = join(cwd, "out");
      const r = recipe(cwd, ["run", "--target", target("c"), "--out", out], {}, entry);
      assert.equal(r.code, 0, r.stderr);
      const cov = await coverage(out);
      const rows = await results(out, "event-logs");
      const byState = Object.fromEntries(rows.map((row) => [String(row.input).split("/").pop(), row.state]));
      assert.deepEqual(byState, { "Application.evtx": "partial", "Security.evtx": "failed", "System.evtx": "unsupported" });
      assert.equal(cov.families["event-logs"].status, "partial");
      assert.deepEqual(cov.families["event-logs"].counts, { parsed: 0, partial: 1, empty: 0, unsupported: 1, failed: 1, not_attempted: 0 });
      assert.equal(cov.families.prefetch.status, "empty");
      assert.equal(cov.status, "partial");
      assert.match(cov.status_basis, /event-logs \(partial\)/);
      assert.equal(rows.find((row) => row.state === "failed")!.exit_code, 1);
      assert.match(rows.find((row) => row.state === "failed")!.stderr_tail, /boom/);
    });
  });
});

test("run: a tool that runs past its time is killed, its family is `failed`, and the limit is named", async () => {
  await withCwd(async (cwd) => {
    await withPackCopy(async (pack, entry) => {
      const root = join(cwd, "c");
      await mkdir(root, { recursive: true });
      await writeFile(join(root, "Security.evtx"), Buffer.concat([Buffer.from("ElfFile\0"), Buffer.alloc(100)]));
      // The call is given the tool's manifest time plus 15 seconds; the stand-in sleeps for a minute and a half.
      const pidFile = join(cwd, "tool.pid");
      await replace(pack, "evtx_query", `import json, os, sys, time
json.load(sys.stdin)
open(${JSON.stringify(pidFile)}, "w").write(str(os.getpid()))
time.sleep(90)
`, 0);
      const out = join(cwd, "out");
      const r = recipe(cwd, ["run", "--target", target("c"), "--out", out], {}, entry);
      assert.equal(r.code, 0, r.stderr);
      // Not a wall clock (a loaded machine is slow): the tool was started, and is gone when the recipe has returned.
      const pid = Number(await readFile(pidFile, "utf8"));
      assert.throws(() => process.kill(pid, 0), "the tool was killed at the call's limit");
      const cov = await coverage(out);
      const [row] = await results(out, "event-logs");
      assert.equal(row.state, "failed");
      assert.equal(row.timed_out, true);
      assert.equal(cov.families["event-logs"].status, "failed");
      assert.match(cov.limits_hit.join("\n"), /Security\.evtx was killed at \d+ seconds/);
      assert.equal(cov.status, "partial");
    });
  });
});

test("run: SIGTERM ends the running tool and what it started, writes the receipt as partial, and exits 143", async () => {
  await withCwd(async (cwd) => {
    await withPackCopy(async (pack, entry) => {
      const root = join(cwd, "c");
      await mkdir(root, { recursive: true });
      await writeFile(join(root, "Security.evtx"), Buffer.concat([Buffer.from("ElfFile\0"), Buffer.alloc(100)]));
      const pidFile = join(cwd, "tool.pid");
      await replace(pack, "evtx_query", `import json, os, sys, time
json.load(sys.stdin)
open(${JSON.stringify(pidFile)}, "w").write(str(os.getpid()))
time.sleep(300)
`);
      const out = join(cwd, "out");
      const child = spawn("python3", [entry, "run", "--target", target("c"), "--out", out], { cwd, env: { ...process.env, AGENT_ID: "s1" }, stdio: ["ignore", "pipe", "pipe"] });
      let pid = 0;
      for (let i = 0; i < 100 && !pid; i++) {
        await new Promise((r) => setTimeout(r, 100));
        pid = Number(await readFile(pidFile, "utf8").catch(() => "")) || 0;
      }
      assert.ok(pid, "the tool started");
      child.kill("SIGTERM");
      const code = await new Promise<number | null>((resolve) => child.on("close", (c) => resolve(c)));
      assert.equal(code, 143);
      await new Promise((r) => setTimeout(r, 300));
      assert.throws(() => process.kill(pid, 0), "the tool is gone");
      const cov = await coverage(out);
      assert.equal(cov.status, "partial");
      assert.match(cov.status_basis, /terminated by signal 15/);
      assert.equal(cov.receipt_written, "after this process was terminated");
    });
  });
});

test("run: when the recipe's own time is used, the calls not yet started are not_attempted, named, and the run is partial", async () => {
  await withCwd(async (cwd) => {
    await collection(join(cwd, "c"));
    const out = join(cwd, "out");
    py(
      `
import importlib.util, json, sys, time
spec = importlib.util.spec_from_file_location("wa", sys.argv[1]); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
m.RUN_SECONDS = -1
walk = m.walk
m.walk = lambda paths, deadline: walk(paths, time.monotonic() + 1000)   # the walk is not what is cut: the time is gone when the calls come
try:
    m.main_run([sys.argv[2]], sys.argv[2], __import__("pathlib").Path(sys.argv[3]))
except SystemExit:
    pass
`,
      RECIPE,
      join(cwd, "c"),
      out,
    );
    const cov = await coverage(out);
    assert.equal(cov.status, "partial");
    assert.ok(cov.limits_hit.length >= 1);
    assert.match(cov.limits_hit.join("\n"), /the recipe's own time/);
    for (const row of await results(out, "registry-hives")) assert.equal(row.state, "not_attempted");
    assert.equal(cov.families["registry-hives"].status, "not_attempted");
  });
});

// ---- dissect.target ---------------------------------------------------------------------------------------------------------

test("dissect.target: not installed, or a target that is not one directory, is not_attempted with the reason; installed, each function is its own call with its whole output kept", async () => {
  await withCwd(async (cwd, bin) => {
    await collection(join(cwd, "c"));
    // Not installed (PATH holds python3 and the recipe's own needs, nothing else).
    const onlyPython = await pathWithOnlyPython(cwd);
    const absent = join(cwd, "out-absent");
    assert.equal(recipe(cwd, ["run", "--target", target("c"), "--out", absent], { PATH: onlyPython }).code, 0);
    const none = (await coverage(absent)).families["dissect-target"];
    assert.equal(none.status, "not_attempted");
    assert.match(none.reason, /not installed/);
    assert.equal(none.inputs, 0);
    // Installed: bam produces records, srum is a function this version lacks, tasks prints nothing, userassist fails otherwise, the rest exit 0 with output.
    await stub(
      bin,
      "target-query",
      `case "$1" in
  --help) echo "usage: target-query [-f FUNCTIONS] [--json] target"; echo "  --json  output records as JSON"; exit 0;;
  --version) echo "target-query 3.20 (stand-in)"; exit 0;;
esac
fn="$2"
case "$fn" in
  bam) echo '{"a":1}'; echo '{"a":2}'; echo "warning text" >&2; exit 0;;
  srum) echo "error: unknown plugin: srum" >&2; exit 2;;
  tasks) exit 0;;
  userassist) echo "something broke" >&2; exit 1;;
  *) echo '{"x":1}'; exit 0;;
esac`,
    );
    const out = join(cwd, "out");
    const r = recipe(cwd, ["run", "--target", target("c"), "--out", out], { PATH: `${bin}:${process.env.PATH}` });
    assert.equal(r.code, 0, r.stderr);
    const cov = await coverage(out);
    const dissect = cov.families["dissect-target"];
    assert.equal(dissect.inputs, 1);
    assert.equal(dissect.calls, 7);
    assert.equal(dissect.records_format, "one JSON object per line");
    assert.match(dissect.version_output, /stand-in/);
    assert.equal(dissect.status, "partial");
    assert.deepEqual(dissect.counts, { parsed: 4, partial: 0, empty: 1, unsupported: 1, failed: 1, not_attempted: 0 });
    const rows = await results(out, "dissect-target");
    const byFn = Object.fromEntries(rows.map((row) => [row.function, row]));
    assert.equal(byFn.bam.state, "parsed");
    assert.equal(byFn.bam.records, 2);
    assert.equal(await readFile(join(out, "dissect-target", "bam.out"), "utf8"), '{"a":1}\n{"a":2}\n', "the whole stdout is kept");
    assert.equal(await readFile(join(out, "dissect-target", "bam.stderr"), "utf8"), "warning text\n", "and the whole stderr");
    assert.equal(byFn.srum.state, "unsupported");
    assert.equal(byFn.tasks.state, "empty");
    assert.equal(byFn.userassist.state, "failed");
    assert.deepEqual(byFn.bam.argv.slice(-2), ["--json", "<target>"], "the target path is not in the argv shown");
    assert.equal(cov.status, "partial", "a function that failed makes the run partial");
    // Two paths: dissect.target opens one target.
    await mkdir(join(cwd, "c2"));
    await writeFile(join(cwd, "c2", "SYSTEM"), G[0]);
    const two = join(cwd, "out-two");
    assert.equal(recipe(cwd, ["run", "--target", target("c", "c2"), "--out", two], { PATH: `${bin}:${process.env.PATH}` }).code, 0);
    assert.match((await coverage(two)).families["dissect-target"].reason, /not exactly one directory/);
  });
});

test("the files of the recipe: recipe.json names its entry and the outputs it writes, and the sealed digest is the entry's", async () => {
  const manifest = JSON.parse(await readFile(join(RECIPE_DIR, "recipe.json"), "utf8")) as Answer;
  assert.equal(manifest.id, "windows-artefacts");
  assert.equal(manifest.purpose, "broad_extraction");
  assert.deepEqual(manifest.auto, []);
  assert.ok(manifest.exclusions.length >= 4);
  assert.ok((await readdir(RECIPE_DIR)).includes("run.py"));
  for (const family of ["registry-hives", "shortcuts-jumplists", "dissect-target"]) assert.ok(manifest.outputs.some((o: string) => o.startsWith(family)), family);
  // Every family the recipe writes a directory for is listed in the outputs.
  const text = await readFile(RECIPE, "utf8");
  const families = [...text.matchAll(/^FAMILIES = \[(.*)\]$/gm)][0][1].match(/"([a-z-]+)"/g)!.map((x) => x.replace(/"/g, ""));
  for (const family of families) assert.ok(manifest.outputs.includes(`${family}/results.jsonl`), `${family}/results.jsonl is declared`);
});
