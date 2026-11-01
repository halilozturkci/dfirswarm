/**
 * triage-collection, a fix round on the independent verification of the first five fixes:
 *   - the recipe never opens a path it was given or finds without checking it is a regular file, so a FIFO as the target ends in JSON and does not hang;
 *   - every loop that runs after the walk (the search for collectors' records, for delivered files no record names, for the files a question
 *     matches) asks the clock and the memory bound, stops, and makes the answer partial;
 *   - the runs of collection_manifest_parse are a table (a page inline, the whole in a file), not a list that grows with the delivery;
 *   - a zip named like a document is a document only when it starts like one;
 *   - a row of the verification table that is not a row (a list for a status, a lone surrogate) is not used, and is counted;
 *   - the memory message does not say "0 MB" for a tiny bound.
 */
import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, readFile, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { runPySnippet } from "./tool-library-harness.ts";
import { KAPE_COPY_HEADER, TOOLS, TRIAGE, asJob, body, kapeCopyRow, put, withCwd } from "./pack-triage-harness.ts";
import type { Json } from "./pack-triage-harness.ts";

const RECIPE = join(TRIAGE, "recipes", "collection-intake", "run.py");
const sha1 = (data: string) => createHash("sha1").update(data).digest("hex").toUpperCase();

/** Run a program, killed after `ms`: {code, stdout, killed}. A hang is a `killed: true`. */
function run(cmd: string, args: string[], cwd: string, ms: number, input?: string, env: Record<string, string> = {}): Promise<{ code: number | null; stdout: string; stderr: string; killed: boolean }> {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, { cwd, env: { ...process.env, AGENT_ID: "s1", ...env } });
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    let killed = false;
    const timer = setTimeout(() => { killed = true; child.kill("SIGKILL"); }, ms);
    child.stdout.on("data", (c: Buffer) => out.push(c));
    child.stderr.on("data", (c: Buffer) => err.push(c));
    child.on("error", reject);
    child.on("close", (code) => { clearTimeout(timer); resolve({ code, stdout: Buffer.concat(out).toString("utf8"), stderr: Buffer.concat(err).toString("utf8"), killed }); });
    child.stdin.on("error", () => undefined);
    child.stdin.end(input ?? "");
  });
}
const target = (p: string) => JSON.stringify({ paths: [p] });

const COPY = (() => {
  const row = kapeCopyRow("C:\\notes.txt", "D:\\o\\C\\notes.txt", 5).replace("da39a3ee5e6b4b0d3255bfef95601890afd80709", sha1("hello"));
  return `${KAPE_COPY_HEADER}\n${row}\n`;
})();

test("a FIFO as the target of the recipe ends in JSON, in time, for detect and for run; a link to a file is refused, not followed", async () => {
  await withCwd(async (cwd) => {
    const fifo = join(cwd, "f");
    execFileSync("mkfifo", [fifo]);
    const detect = await run("python3", [RECIPE, "detect", "--target", target(fifo)], cwd, 20000);
    assert.equal(detect.killed, false, "detect hangs on a FIFO");
    assert.equal(detect.code, 2);
    const answer = JSON.parse(detect.stdout);
    assert.equal(answer.applies, "unknown");
    assert.match(answer.why, /not a regular file/);
    const result = await run("python3", [RECIPE, "run", "--target", target(fifo), "--out", "out"], cwd, 20000);
    assert.equal(result.killed, false, "run hangs on a FIFO");
    assert.notEqual(result.code, 0);
    const failed = JSON.parse(result.stdout);
    assert.equal(failed.status, "failed");
    assert.match(failed.error, /not a regular file/);
    // a link (to a regular zip, and to the FIFO) is not followed
    await runPySnippet("import zipfile,sys\nzipfile.ZipFile(sys.argv[1],'w').writestr('a.txt','x')", [join(cwd, "real.zip")], null);
    await symlink(join(cwd, "real.zip"), join(cwd, "link.zip"));
    await symlink(fifo, join(cwd, "linkf"));
    for (const name of ["link.zip", "linkf"]) {
      const r = await run("python3", [RECIPE, "detect", "--target", target(join(cwd, name))], cwd, 20000);
      assert.equal(r.killed, false, name);
      assert.equal(JSON.parse(r.stdout).applies, "unknown", name);
    }
  });
});

test("a FIFO inside a tar is listed as a special file and skipped, and the run ends", async () => {
  await withCwd(async (cwd) => {
    const made = await runPySnippet(`
import io, sys, tarfile
with tarfile.open(sys.argv[1], "w", format=tarfile.USTAR_FORMAT) as tf:
    rows = sys.argv[2].encode()
    for name, data in (("2026_run_CopyLog.csv", rows), ("C/notes.txt", b"hello")):
        info = tarfile.TarInfo(name); info.size = len(data); tf.addfile(info, io.BytesIO(data))
    info = tarfile.TarInfo("C/pipe"); info.type = tarfile.FIFOTYPE; tf.addfile(info)
`, [join(cwd, "p.tar"), COPY], null);
    assert.equal(made.code, 0, made.stderr);
    const r = await run("python3", [RECIPE, "run", "--target", target(join(cwd, "p.tar")), "--out", "out"], cwd, 30000);
    assert.equal(r.killed, false);
    assert.equal(JSON.parse(r.stdout).ok, true, r.stdout);
    const inventory = await readFile(join(cwd, "out", "inventory.tsv"), "utf8");
    assert.match(inventory, /C\/pipe\t.*a link or a special file: recorded, not followed/);
  });
});

// the tool's source run with the clock expired as soon as the walk is over: the loops after the walk must end at once
const EXPIRED = `
import sys, time
path, after = sys.argv[1], sys.argv[2]
g = {"__name__": "under_test", "__file__": path}
exec(compile(open(path).read(), path, "exec"), g)
real = g[after]
def wrapped(*a, **k):
    result = real(*a, **k)
    g["DEADLINE"][0] = time.monotonic() - 1
    return result
g[after] = wrapped
g["main"]()
`;

async function expired(cwd: string, tool: string, args: Json, after: "walk_census" | "discover"): Promise<Json> {
  const r = await run("python3", ["-c", EXPIRED, join(TOOLS, tool, "run.py"), after], cwd, 120000, JSON.stringify(args));
  assert.equal(r.killed, false);
  assert.doesNotMatch(r.stderr, /Traceback/, r.stderr);
  return JSON.parse(r.stdout);
}

test("the loops after the walk stop at the clock: verify, coverage and parse end partial and name the loop", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "ev/2026_run_CopyLog.csv", COPY);
    await put(cwd, "ev/C/notes.txt", "hello");
    await mkdir(join(cwd, "ev", "C", "many"), { recursive: true });
    for (let i = 0; i < 600; i++) await put(cwd, `ev/C/many/f${i}.txt`, "x");
    const verify = await expired(cwd, "collection_manifest_verify", { root: "ev" }, "discover");
    assert.equal(verify.status, "partial");
    assert.match(String(verify.census.stopped?.reason), /time limit ended the search for delivered files no record names/);
    assert.ok(verify.by_status.unexpected < 600, `${verify.by_status.unexpected} unexpected rows were written after the clock ran out`);
    assert.equal(verify.census.complete, false);
    const cov = await expired(cwd, "collection_coverage", { root: "ev", questions: [{ id: "q", delivered_paths: ["C/many/*"] }] }, "discover");
    assert.equal(cov.status, "partial");
    assert.match(String(cov.census.stopped?.reason), /time limit ended/);
    assert.ok(cov.questions[0].delivered_files < 600, `${cov.questions[0].delivered_files} files matched after the clock ran out`);
    const parse = await expired(cwd, "collection_manifest_parse", { root: "ev" }, "walk_census");
    assert.equal(parse.status, "partial");
    assert.match(String(parse.census.stopped?.reason), /time limit ended the search for the collectors' records/);
  });
});

test("the runs of collection_manifest_parse are a table: a page inline, the whole in a file", async () => {
  await withCwd(async (cwd) => {
    const meta = JSON.stringify({ Scheme: "PGP" });
    for (let i = 0; i < 450; i++) {
      await put(cwd, `ev/d${i}/metadata.json`, meta);
      await put(cwd, `ev/d${i}/data.zip`, "PK");
    }
    const out = body(await asJob("" + join(TOOLS, "collection_manifest_parse", "run.py"), cwd, { root: "ev", limit: 50 }));
    assert.equal(out.runs.length, 50, "the page is the limit");
    assert.equal(out.tables.runs.matched, 450, "and the whole is counted");
    assert.equal(out.tables.runs.truncated, true);
    assert.ok(out.tables.runs.all_results, "and named");
    assert.ok(out.failures_recorded.count === null);
  });
});

test("a zip named like a document is a document only when it starts like one", async () => {
  await withCwd(async (cwd) => {
    const MAKE = `
import sys, zipfile
out, first = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(out, "w") as z:
    z.writestr(first, "x")
    z.writestr("second", "y")
`;
    const row = COPY;
    for (const [name, first, isDocument] of [["good.docx", "[Content_Types].xml", true], ["odf.odt", "mimetype", true], ["jar.jar", "META-INF/MANIFEST.MF", true], ["fake.docx", "2026_other_CopyLog.csv", false], ["fake.jar", "records/uac.log", false]] as Array<[string, string, boolean]>) {
      const inner = join(cwd, `in-${name}`);
      assert.equal((await runPySnippet(MAKE, [inner, first], null)).code, 0);
      const bytes = await readFile(inner);
      const made = await runPySnippet(`
import sys, zipfile
with zipfile.ZipFile(sys.argv[1], "w") as z:
    z.writestr("2026_run_CopyLog.csv", sys.argv[2]); z.writestr("C/notes.txt", "hello"); z.writestr("Users/" + sys.argv[3], open(sys.argv[4], "rb").read())
`, [join(cwd, `${name}.zip`), row, name, inner], null);
      assert.equal(made.code, 0, made.stderr);
      void bytes;
      const r = await run("python3", [RECIPE, "run", "--target", target(join(cwd, `${name}.zip`)), "--out", `out-${name}`], cwd, 60000);
      const cov = JSON.parse(await readFile(join(cwd, `out-${name}`, "coverage.json"), "utf8"));
      assert.equal(r.code, 0);
      assert.equal(cov.status, isDocument ? "complete" : "partial", `${name}: ${cov.status_basis}`);
      assert.equal(cov.nested_archives_zip_documents_and_packages_total, isDocument ? 1 : 0, name);
    }
  });
});

test("a row of the verification table with a list for a status, or a lone surrogate in its path, is not used and is counted; the answer is not failed", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "ev/2026_run_CopyLog.csv", COPY);
    await put(cwd, "ev/C/notes.txt", "hello");
    const rows = [
      '{"delivered":"C/notes.txt","status":"matched"}',
      '{"delivered":"a","status":["matched"]}',
      '{"delivered":"b","status":{"x":1}}',
      '{"delivered":"\\ud800x","status":"matched"}',
      '{"delivered":["a"],"status":"matched"}',
    ];
    await writeFile(join(cwd, "checks.jsonl"), rows.join("\n") + "\n");
    const r = await run("python3", [join(TOOLS, "collection_coverage", "run.py")], cwd, 60000, JSON.stringify({ root: "ev", questions: [{ id: "q", delivered_paths: ["C/*"] }], verification: "checks.jsonl" }));
    assert.equal(r.code, 0, r.stdout + r.stderr);
    const out = JSON.parse(r.stdout);
    assert.notEqual(out.status, "failed");
    assert.equal(out.verification.rows_read, 5);
    assert.equal(out.verification.rows_not_used, 3, JSON.stringify(out.verification));
    assert.equal(out.questions[0].integrity.matched, 1);
  });
});

test("the memory message does not say 0 MB for a tiny bound", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "ev/2026_run_CopyLog.csv", COPY);
    await put(cwd, "ev/C/notes.txt", "hello");
    for (let i = 0; i < 1500; i++) await put(cwd, `ev/C/m${i}.txt`, "x");
    const out = body(await asJob(join(TOOLS, "collection_manifest_parse", "run.py"), cwd, { root: "ev" }, { COLLECTION_MEMORY_BYTES: "1000" }));
    assert.match(String(out.census.stopped?.reason), /memory bound \(\d+ MB held of the 1000 bytes this process may hold\)/);
    const kb = body(await asJob(join(TOOLS, "collection_manifest_parse", "run.py"), cwd, { root: "ev" }, { COLLECTION_MEMORY_BYTES: "5000" }));
    assert.match(String(kb.census.stopped?.reason), /of the 4 KB this process may hold/);
  });
});
