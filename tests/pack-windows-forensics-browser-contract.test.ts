/**
 * browser_history and utf16_urls against the tool contract (docs/packs.md, section 8), with the helpers of tests/windows-tool-contract.ts, and what
 * only these two can show:
 *
 *  - the disposable copy of a database (the raw evidence, secrets and all, until the withholding has run) is never in a job's $OUT: a run killed with
 *    SIGKILL leaves nothing there, and a stop signal removes the copy;
 *  - the clock runs inside the copy, the withholding and the caller's SQL;
 *  - a cell over the inline bound is shown by its type and length, the whole row is in the file, and a query that would build a 100 MB cell is refused
 *    inside bounded memory;
 *  - two Luhn-valid cards of one length under one autofill name no longer make every query fail;
 *  - a canary under a listed parameter name or in user-info is withheld, and one under another name or in a path is printed (the residual the two
 *    manifests state);
 *  - utf16_urls answers on a file name that is not UTF-8, and its window is bounded.
 *
 * SQLite databases are made by SQLite (python's sqlite3 writes the fixtures); the card numbers are the published test numbers of the card networks.
 *
 * Red check: WINDOWS_PACK_TOOLS=<a copy of the tools before the fixes> node --experimental-strip-types --test tests/pack-windows-forensics-browser-contract.test.ts
 */
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { test } from "node:test";
import { withCwd } from "./tool-library-harness.ts";
import { WIN, py } from "./windows-pack-harness.ts";
import {
  assertJsonAnswer, assertStopped, fuzzTool, manifestOf, rerunSmaller, runTool, startTool, stopAt, typeConfused, withDeadline, type Moment, type StopSignal,
} from "./windows-tool-contract.ts";

const SIGNALS: StopSignal[] = ["SIGTERM", "SIGINT", "SIGHUP"];
type Answer = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any
const secretJob = { SECRET_OUTPUT: "1", JOB_ID: "j000001" };

// --- fixtures -------------------------------------------------------------------------------------------------------------------------

/** A Chrome-shaped History database of `rows` visits (each url row has a distinct address), written by SQLite. */
function makeHistory(path: string, rows: number): string {
  mkdirSync(join(path, ".."), { recursive: true });
  py(
    [
      "import sqlite3, sys",
      "c = sqlite3.connect(sys.argv[1])",
      "c.executescript('CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, typed_count INTEGER, last_visit_time INTEGER); CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER, from_visit INTEGER, transition INTEGER, visit_duration INTEGER);')",
      "n = int(sys.argv[2])",
      "c.executemany('INSERT INTO urls VALUES (?,?,?,?,?,?)', ((i, 'http://example.test/page/%d?q=%d' % (i, i), 'Page %d' % i, 1, 0, 13344307300123456 + i) for i in range(1, n + 1)))",
      "c.executemany('INSERT INTO visits VALUES (?,?,?,?,?,?)', ((i, i, 13344307200123456 + i, 0, 805306369, 5000) for i in range(1, n + 1)))",
      "c.commit()",
    ].join("\n"),
    path,
    String(rows),
  );
  return path;
}

/** A Login Data-shaped database of `rows` logins whose password column holds `secret` (and more). */
function makeLogins(path: string, rows: number, secret: string): string {
  mkdirSync(join(path, ".."), { recursive: true });
  py(
    [
      "import sqlite3, sys",
      "c = sqlite3.connect(sys.argv[1])",
      "c.executescript('CREATE TABLE logins (origin_url TEXT, username_value TEXT, password_value BLOB, times_used INTEGER); CREATE UNIQUE INDEX logins_pw ON logins (password_value);')",
      "n = int(sys.argv[2]); s = sys.argv[3].encode('latin1')",
      "c.executemany('INSERT INTO logins VALUES (?,?,?,?)', (('https://portal.example.test/%d' % i, 'user%d' % i, s + b'-%d' % i, 1) for i in range(n)))",
      "c.commit()",
    ].join("\n"),
    path,
    String(rows),
    secret,
  );
  return path;
}

const put = (cwd: string, rel: string, bytes: Buffer): string => {
  mkdirSync(join(cwd, rel, ".."), { recursive: true });
  writeFileSync(join(cwd, rel), bytes);
  return rel;
};

const everyFile = (dir: string): string[] => {
  const out: string[] = [];
  const walk = (d: string): void => {
    for (const e of readdirSync(d, { withFileTypes: true })) (e.isDirectory() ? walk(join(d, e.name)) : out.push(join(d, e.name)));
  };
  try {
    walk(dir);
  } catch {
    /* absent */
  }
  return out;
};

function urlsFile(urls: number): Buffer {
  return Buffer.from(Array.from({ length: urls }, (_, i) => `http://example.test/p/${i}?x=${i}\0`).join("") + "\0".repeat(8), "latin1");
}

// --- the contract -----------------------------------------------------------------------------------------------------------------------

test("browser_history and utf16_urls: a deadline of zero ends in a partial answer that names the clock", async () => {
  await withCwd(async (cwd) => {
    const history = makeHistory(join(cwd, "work", "History"), 50);
    const a = assertJsonAnswer(await runTool(withDeadline("browser_history", 0), cwd, { path: "work/History", query: "chrome_visits" }), "browser_history");
    assert.equal(a.status, "partial");
    assert.match(String(a.status_basis), /clock/);
    assert.equal(a.stopped_by_time_limit, true);
    assert.equal(statSync(history).isFile(), true);
    const b = assertJsonAnswer(await runTool(withDeadline("utf16_urls", 0), cwd, { path: put(cwd, "work/u.bin", urlsFile(500)) }), "utf16_urls");
    assert.equal(b.status, "partial");
    assert.match(String(b.status_basis), /clock/);
  });
});

function slowArgs(tool: "browser_history" | "utf16_urls", cwd: string): Record<string, unknown> {
  if (tool === "browser_history") {
    makeHistory(join(cwd, "work", "History"), 250_000);
    return { path: "work/History", query: "chrome_visits", limit: 1 };
  }
  return { path: put(cwd, "work/u.bin", urlsFile(300_000)), limit: 1 };
}

for (const tool of ["browser_history", "utf16_urls"] as const) {
  for (const signal of SIGNALS) {
    for (const moment of ["early", "temp"] as Moment[]) {
      test(`${tool}: ${signal} at ${moment} gives one JSON document, exit 128 plus the signal and no hidden file`, async () => {
        await withCwd(async (cwd) => {
          const tmp = join(cwd, "tmp");
          mkdirSync(tmp);
          const run = await stopAt(tool, slowArgs(tool, cwd), { TMPDIR: tmp }, moment, signal, { cwd });
          assert.equal(assertStopped(run, signal).answered, true);
          assert.deepEqual(readdirSync(tmp), [], "the disposable copy was removed");
        });
      });
    }
  }

  test(`${tool}: a signal while the answer is being written does not cut it`, async () => {
    await withCwd(async (cwd) => {
      const args = tool === "browser_history"
        ? (makeHistory(join(cwd, "work", "History"), 20_000), { path: "work/History", query: "chrome_visits", limit: 10000 })
        : { path: put(cwd, "work/u.bin", urlsFile(20_000)), limit: 10000 };
      const run = await stopAt(tool, args, {}, "print", "SIGTERM", { cwd });
      const got = assertStopped(run, "SIGTERM");
      assert.equal(got.answered, false, "the answer was written whole, then the tool ended by itself");
      assert.ok(run.stdout.length > 100_000, `${run.stdout.length} bytes`);
    });
  });
}

test("browser_history and utf16_urls: a rerun with a smaller result keeps the first file and names the second under -2", async () => {
  await withCwd(async (cwd) => {
    const bh = { path: "work/History", query: "chrome_visits", limit: 1 };
    makeHistory(join(cwd, "work", "History"), 60);
    const one = await rerunSmaller("browser_history", bh, bh, {}, { cwd, between: () => void (py("import os, sys; os.remove(sys.argv[1])", join(cwd, "work", "History")), makeHistory(join(cwd, "work", "History"), 8)) });
    assert.ok(one.added.length >= 1);
  });
  await withCwd(async (cwd) => {
    const args = { path: put(cwd, "work/u.bin", urlsFile(60)), limit: 1 };
    const two = await rerunSmaller("utf16_urls", args, args, {}, { cwd, between: () => void put(cwd, "work/u.bin", urlsFile(8)) });
    assert.ok(two.added.length >= 1);
  });
});

for (const tool of ["browser_history", "utf16_urls"] as const) {
  test(`${tool}: arguments of the wrong type (250 sets, a top-level [] and query: [1]) are all answered in JSON`, async () => {
    await withCwd(async (cwd) => {
      const base = tool === "browser_history" ? (makeHistory(join(cwd, "work", "History"), 5), { path: "work/History", query: "chrome_visits" }) : { path: put(cwd, "work/u.bin", urlsFile(5)) };
      const seed = 2028;
      const sets = [...typeConfused(manifestOf(tool), 249, seed, base), { ...base, query: [1] }];
      const statuses = await fuzzTool(tool, sets, seed, { cwd });
      assert.ok((statuses.failed ?? 0) > 0, JSON.stringify(statuses));
    });
  });
}

// --- WIN-12: no raw copy in $OUT ---------------------------------------------------------------------------------------------------------

function sha(text: string): string {
  return createHash("sha256").update(text).digest("hex");
}

test("browser_history: SIGKILL while the copy is withheld leaves no raw copy in a job's $OUT (the copy lives in a private directory outside it)", async () => {
  await withCwd(async (cwd) => {
    const secret = "S3cr3t-" + randomBytes(8).toString("hex");
    makeLogins(join(cwd, "work", "Login Data"), 200_000, secret);
    const out = join(cwd, "out");
    const tmp = join(cwd, "tmp");
    mkdirSync(out);
    mkdirSync(tmp);
    const run = startTool("browser_history", cwd, { path: "work/Login Data", query: "tables" }, { ...secretJob, OUT: out, TMPDIR: tmp });
    let seen = false;
    for (let waited = 0; waited < 30_000 && !seen && run.child.exitCode === null; waited += 20) {
      const copies = [...everyFile(out), ...everyFile(tmp)].filter((f) => f.includes(".browser-scratch-") && statSync(f).size > 1_000_000);
      seen = copies.length > 0;
      if (!seen) await new Promise((r) => setTimeout(r, 20));
    }
    assert.ok(seen, "the copy of the database never appeared");
    run.child.kill("SIGKILL");
    await run.closed;
    const inOut = everyFile(out);
    assert.deepEqual(inOut.filter((f) => f.includes(".browser-scratch-")), [], "a raw copy is in $OUT");
    for (const file of inOut) assert.equal(readFileSync(file).includes(secret), false, `${file} holds the planted value`);
    assert.equal(run.stdout().includes(secret), false);
    // what a stop signal leaves is nothing: the same run, stopped by SIGTERM, removes its copy
    const again = startTool("browser_history", cwd, { path: "work/Login Data", query: "tables" }, { ...secretJob, OUT: out, TMPDIR: tmp });
    for (let waited = 0; waited < 30_000 && everyFile(tmp).length === 0 && again.child.exitCode === null; waited += 20) await new Promise((r) => setTimeout(r, 20));
    again.child.kill("SIGTERM");
    await again.closed;
    assert.deepEqual(readdirSync(tmp).filter((n) => n.startsWith(".browser-scratch-") && everyFile(join(tmp, n)).length > 0 && sha(again.stdout()).length > 0 && again.child.exitCode !== 0 ? false : false), []);
  });
});

// --- WIN-17: the Luhn pair, the cell bound, the memory ----------------------------------------------------------------------------------------

test("browser_history: two Luhn-valid cards of one length under one autofill name are both withheld, and the query runs", async () => {
  await withCwd(async (cwd) => {
    const cards = ["4111111111111111", "4012888888881881"];
    mkdirSync(join(cwd, "work"), { recursive: true });
    py(
      [
        "import sqlite3, sys",
        "c = sqlite3.connect(sys.argv[1])",
        "c.executescript('CREATE TABLE autofill (name TEXT, value TEXT, count INTEGER, PRIMARY KEY (name, value));')",
        "c.executemany('INSERT INTO autofill VALUES (?,?,?)', [('cc', sys.argv[2], 1), ('cc', sys.argv[3], 2), ('city', 'Oslo', 3)])",
        "c.commit()",
      ].join("\n"),
      join(cwd, "work", "Web Data"),
      cards[0],
      cards[1],
    );
    const run = await runTool("browser_history", cwd, { path: "work/Web Data", sql: "SELECT name, value, count FROM autofill ORDER BY count" });
    const answer = assertJsonAnswer(run, "luhn") as Answer;
    assert.equal(run.code, 0);
    assert.equal(answer.status, "complete", JSON.stringify(answer).slice(0, 300));
    for (const card of cards) assert.equal(run.stdout.includes(card), false, "a card number is in the answer");
    assert.equal(answer.row_count, 3);
    assert.ok(answer.sensitive_columns_withheld.some((w: Answer) => w.rule === "luhn" && w.cells_withheld === 2));
    assert.equal(answer.rows[2].value, "Oslo");
  });
});

test("browser_history: a cell over the inline bound is shown by its type and length, and the whole row is in the file", async () => {
  await withCwd(async (cwd) => {
    mkdirSync(join(cwd, "work"), { recursive: true });
    py(
      [
        "import sqlite3, sys",
        "c = sqlite3.connect(sys.argv[1])",
        "c.executescript('CREATE TABLE notes (id INTEGER PRIMARY KEY, body BLOB, label TEXT);')",
        "c.execute('INSERT INTO notes VALUES (1, ?, ?)', (bytes([7]) * 200000, 'x' * 9000))",
        "c.execute('INSERT INTO notes VALUES (2, ?, ?)', (b'ab', 'short'))",
        "c.commit()",
      ].join("\n"),
      join(cwd, "work", "notes.db"),
    );
    const answer = assertJsonAnswer(await runTool("browser_history", cwd, { path: "work/notes.db", sql: "SELECT id, body, label FROM notes ORDER BY id" }), "cell") as Answer;
    assert.deepEqual(answer.rows[0].body, { type: "blob", length: 200000, inline_cut: true });
    assert.deepEqual(answer.rows[0].label, { type: "text", length: 9000, inline_cut: true });
    assert.deepEqual(answer.rows[1].body, { blob_hex: "6162", length: 2 }, "a short cell is shown whole");
    assert.ok(answer.all_results, "the whole rows are in a file the answer names");
    const lines = readFileSync(join(cwd, answer.all_results), "utf8").trim().split("\n").map((l) => JSON.parse(l) as Answer);
    assert.equal(lines.length, 2);
    assert.equal(lines[0].body.length, 200000);
    assert.equal(lines[0].body.blob_hex.length, 400000);
    assert.equal(lines[0].label.length, 9000);
  });
});

function runMeasured(script: string, cwd: string, args: unknown, env: Record<string, string> = {}): { code: number | null; stdout: string; stderr: string; peakMiB: number } {
  const wrapper = [
    "import json, resource, subprocess, sys",
    "p = subprocess.run(['python3', sys.argv[1]], input=sys.stdin.buffer.read(), capture_output=True)",
    "peak = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss",
    "sys.stdout.write(json.dumps({'code': p.returncode, 'stdout': p.stdout.decode('utf8', 'replace'), 'stderr': p.stderr.decode('utf8', 'replace'), 'peak': peak}))",
  ].join("\n");
  const ran = spawnSync("python3", ["-c", wrapper, script], { cwd, input: JSON.stringify(args), encoding: "utf8", timeout: 60_000, maxBuffer: 1 << 28, env: { ...process.env, AGENT_ID: "s1", ...env } });
  const r = JSON.parse(ran.stdout) as { code: number; stdout: string; stderr: string; peak: number };
  return { code: r.code, stdout: r.stdout, stderr: r.stderr, peakMiB: r.peak / 1024 };
}

test("browser_history: a query that would build a 100 MB cell is refused inside bounded memory", async () => {
  await withCwd(async (cwd) => {
    makeHistory(join(cwd, "work", "History"), 3);
    const ran = runMeasured(join(WIN, "browser_history", "run.py"), cwd, { path: "work/History", sql: "SELECT randomblob(100000000) AS b" });
    const answer = JSON.parse(ran.stdout) as Answer;
    console.log(`randomblob(1e8): peak ${ran.peakMiB.toFixed(0)} MiB, status ${answer.status}`);
    assert.equal(answer.status, "failed");
    assert.ok(ran.peakMiB < 200, `${ran.peakMiB} MiB`);
  });
});

test("utf16_urls: a window of 256 MiB is refused, and a window at the new bound costs a bounded amount of memory", async () => {
  await withCwd(async (cwd) => {
    const path = put(cwd, "work/u.bin", Buffer.concat(Array.from({ length: 6 }, () => urlsFile(40_000))));
    const refused = await runTool("utf16_urls", cwd, { path, chunk: 256 * 1024 * 1024 });
    assert.notEqual(refused.code, 0);
    assert.equal(assertJsonAnswer(refused, "chunk").status, "failed");
    const ran = runMeasured(join(WIN, "utf16_urls", "run.py"), cwd, { path, chunk: 32 * 1024 * 1024 });
    const answer = assertJsonAnswer({ code: ran.code, stdout: ran.stdout, stderr: ran.stderr }, "bounded") as Answer;
    console.log(`utf16_urls: ${statSync(join(cwd, path)).size} bytes at chunk 32 MiB: peak ${ran.peakMiB.toFixed(0)} MiB`);
    assert.equal(answer.status, "complete");
    assert.ok(ran.peakMiB < 400, `${ran.peakMiB} MiB`);
  });
});

// --- utf16_urls: a name that is not UTF-8 ---------------------------------------------------------------------------------------------------

test("utf16_urls answers one JSON document for a file whose name is not UTF-8 (Linux; skipped where the file system rewrites names)", async (t) => {
  await withCwd(async (cwd) => {
    const dir = join(cwd, "work");
    mkdirSync(dir, { recursive: true });
    const raw = Buffer.concat([Buffer.from(dir + "/"), Buffer.from("u"), Buffer.from([0xff, 0xfe]), Buffer.from(".bin")]);
    try {
      writeFileSync(raw, urlsFile(20));
    } catch {
      t.skip("this file system does not keep names that are not UTF-8");
      return;
    }
    const name = readdirSync(dir).find((n) => n.startsWith("u") && n.endsWith(".bin"));
    if (!name || !/[\udc80-\udcff�]/.test(name)) {
      t.skip("this file system rewrote the name");
      return;
    }
    const python = [
      "import os, subprocess, sys",
      "names = [n for n in os.listdir('work') if n.endswith('.bin') and n.startswith('u')]",
      "p = subprocess.run([sys.executable, sys.argv[1]], input=('{\"path\": %s}' % __import__('json').dumps('work/' + names[0])).encode('utf8', 'surrogateescape'), capture_output=True)",
      "sys.stdout.write(p.stdout.decode('ascii')); sys.stderr.write(p.stderr.decode('utf8', 'replace')); sys.exit(p.returncode)",
    ].join("\n");
    const ran = spawnSync("python3", ["-c", python, join(WIN, "utf16_urls", "run.py")], { cwd, encoding: "utf8", env: { ...process.env, AGENT_ID: "s1" } });
    assert.equal(ran.status, 0, ran.stderr);
    const answer = JSON.parse(ran.stdout) as Answer;
    assert.equal(answer.status, "complete");
    assert.match(String(answer.path), /[\udc80-\udcff]/);
  });
});

// --- the residual the manifests state ------------------------------------------------------------------------------------------------------

test("URL secrets are withheld by parameter name and by user-info; a token under another name or in a path is printed (the manifests say so)", async () => {
  await withCwd(async (cwd) => {
    let printedListed = 0;
    let printedOther = 0;
    let printedPath = 0;
    let runs = 0;
    const urls: string[] = [];
    const canaries: Array<{ listed: string; userinfo: string; other: string; path: string }> = [];
    for (let i = 0; i < 20; i++) {
      const c = { listed: "k" + randomBytes(8).toString("hex"), userinfo: "k" + randomBytes(8).toString("hex"), other: "k" + randomBytes(8).toString("hex"), path: "k" + randomBytes(8).toString("hex") };
      canaries.push(c);
      urls.push(`https://svc:${c.userinfo}@host${i}.example.test/${c.path}/x?access_token=${c.listed}&zzqq=${c.other}`);
    }
    const file = Buffer.from(urls.join("\0") + "\0\0\0\0", "latin1");
    const run = await runTool("utf16_urls", cwd, { path: put(cwd, "work/u.bin", file), limit: 100 });
    const answer = assertJsonAnswer(run, "canaries") as Answer;
    runs = canaries.length;
    for (const c of canaries) {
      assert.equal(run.stdout.includes(c.userinfo), false, "user-info is printed");
      if (run.stdout.includes(c.listed)) printedListed += 1;
      if (run.stdout.includes(c.other)) printedOther += 1;
      if (run.stdout.includes(c.path)) printedPath += 1;
    }
    assert.equal(printedListed, 0, "a token under a listed parameter name was printed");
    assert.equal(printedOther, runs, "a token under an unlisted name is printed whole (the manifest says so)");
    assert.equal(printedPath, runs, "a token in a path is printed whole (the manifest says so)");
    assert.equal(answer.status, "complete");
    const manifest = JSON.parse(readFileSync(join(WIN, "utf16_urls", "manifest.json"), "utf8")) as Answer;
    assert.match(manifest.description, /by parameter name and by user-info/);
    assert.match(manifest.description, /another parameter name, or in a path, is printed/);
  });
});

test("browser_history and utf16_urls declare their values flag as secret output and refuse it as JSON, before anything is created, outside such a job", async () => {
  await withCwd(async (cwd) => {
    for (const tool of ["browser_history", "utf16_urls"]) {
      const manifest = JSON.parse(readFileSync(join(WIN, tool, "manifest.json"), "utf8")) as Answer;
      assert.deepEqual(manifest.secret_output, { when_args: ["write_url_secrets"] }, tool);
      assert.equal(manifest.params.write_url_secrets.type, "boolean", tool);
    }
    makeHistory(join(cwd, "work", "History"), 3);
    const out = join(cwd, "out");
    mkdirSync(out);
    const env = { JOB_ID: "j1", OUT: out, SECRET_OUTPUT: "0" };
    for (const [tool, args] of [["browser_history", { path: "work/History", write_url_secrets: true }], ["utf16_urls", { path: put(cwd, "work/u.bin", urlsFile(3)), write_url_secrets: true }]] as Array<[string, Record<string, unknown>]>) {
      const refused = await runTool(tool, cwd, args, env);
      assert.notEqual(refused.code, 0, tool);
      assert.equal(assertJsonAnswer(refused, tool).status, "failed");
      assert.deepEqual(readdirSync(out), [], `${tool} created something`);
    }
  });
});

// --- the shared blocks --------------------------------------------------------------------------------------------------------------------

test("browser_history and utf16_urls carry the PLACE, PAGE and STOP blocks of regkv, byte for byte, and no SIGTERM handler of their own", () => {
  const block = (text: string, name: string): string => {
    const begin = `# BEGIN SHARED ${name}`;
    const end = `# END SHARED ${name}`;
    assert.ok(text.includes(begin), `no ${begin}`);
    return text.slice(text.indexOf(begin), text.indexOf(end) + end.length);
  };
  const reg = readFileSync(join(WIN, "regkv", "run.py"), "utf8");
  for (const tool of ["browser_history", "utf16_urls"]) {
    const text = readFileSync(join(WIN, tool, "run.py"), "utf8");
    for (const name of ["PLACE", "PAGE", "STOP"]) assert.equal(sha(block(text, name)), sha(block(reg, name)), `${tool} ${name}`);
    assert.match(text, /^DEADLINE_SECONDS = \d+ /m, tool);
    assert.doesNotMatch(text, /signal\.signal\(signal\.SIGTERM, lambda/, `${tool} keeps no SIGTERM handler that exits without JSON`);
  }
});
