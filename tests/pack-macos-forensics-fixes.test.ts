/**
 * The smaller fixes of the review of the macos-forensics tools, each asserted on a case that failed before: an error row that quoted the file's
 * text, the key-name lexicon, a database whose schema is not UTF-8, the memory a TEXT cell costs, a journal that is not one, the mode of an out_file,
 * the status every answer carries, a reader that exits 0 and complains.
 */
import assert from "node:assert/strict";
import { mkdir, readFile, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { runPySnippet, withCwd } from "./tool-library-harness.ts";
import { CREATED, FS, KC, PLIST, body, fsDir, fsPage, fsRecord, gz, kcDb, logarchive, measured, ok, reachable, secretJob, tool, ul, ulStandin } from "./macos-pack-harness.ts";
import type { Json } from "./macos-pack-harness.ts";
import { prng } from "./windows-canary.ts";

const ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const rs = (r: () => number, n: number): string => Array.from({ length: n }, () => ALNUM[Math.floor(r() * ALNUM.length)]).join("");

const XML = (inner: string): string => `<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict>${inner}</dict></plist>`;

// ---- plist_read ---------------------------------------------------------------------------------------------------------------------------------

test("plist_read does not quote a malformed value in the failed row's error: 100 of 100 canaries per kind were printed before", async () => {
  // plistlib quotes the text that failed (`invalid literal for int() with base 10: 'x'`), and a value under a key named for a secret came out in `error`.
  const r = prng(71);
  await withCwd(async (cwd) => {
    const kinds: Array<[string, (c: string) => string]> = [
      ["integer", (c) => `<key>password</key><integer>${c}</integer>`],
      ["real", (c) => `<key>password</key><real>${c}</real>`],
      ["key without a value", (c) => `<key>a</key><string>x</string><key>${c}</key>`],
    ];
    for (const [kind, make] of kinds) {
      let printed = 0;
      for (let i = 0; i < 100; i++) {
        const canary = "Tk" + rs(r, 14);
        await writeFile(join(cwd, "work", "bad.plist"), XML(make(canary)));
        const run = await tool(PLIST, cwd, { path: "work/bad.plist" });
        assert.equal(run.code, 1);
        const answer = body(run);
        assert.equal(answer.files[0].status, "failed", kind);
        if ((run.stdout + run.stderr).includes(canary)) printed++;
        for (const text of await reachable(cwd, (f) => f.endsWith("bad.plist"))) assert.ok(!text.includes(canary), kind);
      }
      assert.equal(printed, 0, `${kind}: printed in ${printed} of 100`);
    }
    // The class and, for an XML syntax error, the fixed text of the reader and the place are kept.
    await writeFile(join(cwd, "work", "broken.plist"), "<plist><dict><key>a</key></plist>");
    const broken = body(await tool(PLIST, cwd, { path: "work/broken.plist" }));
    assert.match(broken.files[0].error, /^ExpatError: mismatched tag at line 1, column \d+$/);
    // In a job the harness runs as secret output, the whole message is in the values file, with the finding id the row carries.
    await writeFile(join(cwd, "work", "bad.plist"), XML("<key>password</key><integer>Tk1234567890abcd</integer>"));
    const job = await secretJob(PLIST, cwd, { path: "work/bad.plist", write_values: true });
    const row = body(job).files[0];
    assert.match(row.finding_id, /^F\d{6}$/);
    const values = (await readFile(join(cwd, "out", "plist-values.jsonl"), "utf8")).trimEnd().split("\n").map((l) => JSON.parse(l) as Json);
    assert.equal(values.length, 1);
    assert.equal(values[0].finding_id, row.finding_id);
    assert.match(values[0].value, /Tk1234567890abcd/);
    assert.equal(values[0].kind, "error");
    assert.ok(!job.stdout.includes("Tk1234567890abcd"));
  });
});

test("plist_read withholds the key names the review found printed: pre-shared keys, KDC and access keys, cookies, passcodes, hints; and not a name that only contains otp", async () => {
  await withCwd(async (cwd) => {
    const secretNames = ["PreSharedKey", "dsAttrTypeStandard:KDCAuthKey", "com.apple.PlatformSSO.AccessKey", "assertionCookie", "journalCookie_3", "ShowPasscode", "PasswordHint", "UserHint", "hint_text", "BearerToken", "WiFiPSK", "otp", "OTP_seed", "shared-otp"];
    const plainNames = ["Footprint", "Photo", "Shot", "Hinterland", "Autorun", "Stopover", "KeyboardType", "Name"];
    const entries = [...secretNames, ...plainNames].map((n) => `<key>${n}</key><string>VALUE-of-${n.replace(/[^A-Za-z]/g, "")}</string>`).join("");
    await writeFile(join(cwd, "work", "names.plist"), XML(entries));
    const run = await tool(PLIST, cwd, { path: "work/names.plist" });
    const value = body(run).files[0].value as Json;
    for (const n of secretNames) {
      assert.ok(value[n]._withheld, `${n} is withheld`);
      assert.ok(!run.stdout.includes("VALUE-of-" + n.replace(/[^A-Za-z]/g, "")), `${n}: its value is not printed`);
    }
    for (const n of plainNames) assert.equal(value[n], "VALUE-of-" + n, `${n} is printed`);
  });
});

test("plist_read, fsevents_parse and knowledgec_query create an out_file that only their user can read (0600), as the paging file is", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "p.plist"), XML("<key>a</key><string>b</string>"));
    const dir = await fsDir(cwd, "ev", { "0000000000000001": gz(fsPage("2SLD", [fsRecord("a/b", 1n, CREATED, 1n)])) });
    const db = await kcDb(cwd, "k.db", 3);
    for (const [script, args, file] of [[PLIST, { path: "work/p.plist" }, "po.jsonl"], [FS, { path: dir }, "fo.jsonl"], [KC, { db }, "ko.jsonl"]] as const) {
      ok(await tool(script, cwd, { ...args, out_file: `work/${file}` }));
      assert.equal((await stat(join(cwd, "work", file))).mode & 0o777, 0o600, file);
    }
  });
});

test("plist_read clamps max_seconds below the manifest's timeout and says so", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "p.plist"), XML("<key>a</key><string>b</string>"));
    const answer = ok(await tool(PLIST, cwd, { path: "work/p.plist", max_seconds: 100000 }));
    assert.equal(answer.limits.max_seconds, 100);
    assert.equal(answer.limits.max_seconds_requested, 100000);
  });
});

// ---- knowledgec_query ----------------------------------------------------------------------------------------------------------------------------

test("knowledgec_query answers with JSON, not a traceback, for a database whose schema holds text that is not UTF-8", async () => {
  // SQLite's own error message names the object, and Python cannot decode it: UnicodeDecodeError out of the first statement.
  await withCwd(async (cwd) => {
    const db = await kcDb(cwd, "k.db", 20);
    const file = join(cwd, "work", "k.db");
    const bytes = await readFile(file);
    const at = bytes.indexOf("ZSOURCEZSOURCE");
    assert.ok(at > 0);
    bytes[at + 1] = 0xa2;
    await writeFile(file, bytes);
    const run = await tool(KC, cwd, { db });
    assert.equal(run.code, 1);
    assert.doesNotMatch(run.stderr, /Traceback/);
    const answer = JSON.parse(run.stdout) as Json;
    assert.equal(answer.status, "failed");
    assert.match(answer.error, /not a usable SQLite database/);
    assert.equal(answer.reason, "UnicodeDecodeError");
    assert.equal(typeof answer.status_basis, "string");
  });
});

test("knowledgec_query reads a 300 MB TEXT cell as its head and its length, in a few tens of megabytes", async () => {
  // substr() makes SQLite load the whole cell: 324 MB of memory for one 300 MB value. A TEXT cell is read through a blob handle now.
  await withCwd(async (cwd) => {
    const file = join(cwd, "work", "big.db");
    const built = await runPySnippet(`
import sqlite3, sys
c = sqlite3.connect(sys.argv[1])
c.execute("CREATE TABLE ZOBJECT (Z_PK INTEGER PRIMARY KEY, ZSTREAMNAME VARCHAR, ZVALUESTRING VARCHAR, ZSTARTDATE TIMESTAMP)")
c.execute("INSERT INTO ZOBJECT VALUES (1, '/s', 'short', 700)")
c.execute("INSERT INTO ZOBJECT VALUES (2, '/s', ?, 701)", ("t" * (300 << 20),))
c.commit()
`, [file], null);
    assert.equal(built.code, 0, built.stderr);
    const run = await measured(KC, cwd, { db: "work/big.db" });
    assert.equal(run.code, 0, run.stderr);
    assert.ok(run.mb < 120, `peak memory ${run.mb.toFixed(0)} MB for a 300 MB TEXT value`);
    const answer = JSON.parse(run.stdout) as Json;
    const text = answer.entries[1].value_string;
    assert.equal(text._text_bytes, 300 << 20);
    assert.equal(text._text_head.length, 4096);
    assert.equal(answer.values.truncated, 1);
    assert.equal(answer.entries[0].value_string, "short");
  });
});

test("knowledgec_query does not call a journal that is not one a rollback: a garbage -journal beside the database changes nothing and is said so", async () => {
  await withCwd(async (cwd) => {
    const db = await kcDb(cwd, "k.db", 10);
    await writeFile(join(cwd, "work", "k.db-journal"), Buffer.from(Array.from({ length: 3000 }, (_, i) => (i * 131 + 7) % 256)));
    const answer = ok(await tool(KC, cwd, { db }));
    const journal = answer.source_used.journal;
    assert.equal(journal.rollback_applied, false, "the database is byte for byte what was acquired");
    assert.equal(journal.database_sha256_as_acquired, journal.database_sha256_after_open);
    assert.ok(answer.problems.some((p: string) => /not a valid hot journal|not a hot journal/.test(p)), JSON.stringify(answer.problems));
    assert.ok(!answer.problems.some((p: string) => /rolled back the uncommitted/.test(p)));
  });
});

// ---- unified_log -----------------------------------------------------------------------------------------------------------------------------------

test("unified_log warns when the reader exits 0 and writes to its error stream", async () => {
  await withCwd(async (cwd) => {
    const bin = await ulStandin(cwd, `
with open(out, "w") as f:
    f.write(json.dumps({"timestamp": "2026-02-14T09:30:00.000000+0000", "eventMessage": "m", "process": "sudo", "subsystem": "s"}) + "\\n")
sys.stderr.write("warning: skipped a chunk\\n")
`);
    const answer = ok(await ul(cwd, bin, { path: await logarchive(cwd), out_dir: "work/u" }));
    assert.equal(answer.exit_code, 0);
    assert.ok(answer.stderr_bytes > 0);
    assert.ok(answer.warnings.some((w: string) => /error stream/.test(w)), JSON.stringify(answer.warnings));
  });
});

// ---- the status every answer carries -----------------------------------------------------------------------------------------------------------

test("every answer of the four tools carries status in complete, partial or failed and a status_basis sentence, whatever happened", async () => {
  await withCwd(async (cwd) => {
    const seen: Array<[string, Json]> = [];
    const note = (name: string, run: { stdout: string; stderr: string }): void => {
      assert.doesNotMatch(run.stderr, /Traceback/, name);
      seen.push([name, JSON.parse(run.stdout) as Json]);
    };
    // plist_read: a file, a bad file, an empty directory, no such path, a bad argument
    await writeFile(join(cwd, "work", "good.plist"), XML("<key>a</key><string>b</string>"));
    await writeFile(join(cwd, "work", "bad.plist"), "not a plist");
    await mkdir(join(cwd, "work", "empty"), { recursive: true });
    note("plist good", await tool(PLIST, cwd, { path: "work/good.plist" }));
    note("plist bad", await tool(PLIST, cwd, { path: "work/bad.plist" }));
    note("plist empty directory", await tool(PLIST, cwd, { path: "work/empty" }));
    note("plist missing", await tool(PLIST, cwd, { path: "work/missing.plist" }));
    note("plist bad argument", await tool(PLIST, cwd, { path: "work/good.plist", limit: 0 }));
    // fsevents_parse: complete, unsupported, empty file, a file that is not one, no records
    const good = await fsDir(cwd, "fs-good", { "0000000000000001": gz(fsPage("2SLD", [fsRecord("a/b", 1n, CREATED, 1n)])) });
    const three = await fsDir(cwd, "fs-3", { "0000000000000001": gz(fsPage("3SLD", [fsRecord("a/b", 1n, CREATED, 1n)])) });
    const junk = await fsDir(cwd, "fs-junk", { "0000000000000001": Buffer.from("this is not an fsevents file") });
    const none = await fsDir(cwd, "fs-none", {});
    note("fsevents good", await tool(FS, cwd, { path: good }));
    note("fsevents unsupported", await tool(FS, cwd, { path: three }));
    note("fsevents junk", await tool(FS, cwd, { path: junk }));
    note("fsevents no files", await tool(FS, cwd, { path: none }));
    note("fsevents missing", await tool(FS, cwd, { path: "work/none-at-all" }));
    // knowledgec_query: complete, not a database, no ZOBJECT
    const db = await kcDb(cwd, "k.db", 5);
    await writeFile(join(cwd, "work", "notdb.db"), "plain text, not SQLite");
    note("knowledgec good", await tool(KC, cwd, { db }));
    note("knowledgec not a database", await tool(KC, cwd, { db: "work/notdb.db" }));
    note("knowledgec missing", await tool(KC, cwd, { db: "work/none.db" }));
    // unified_log: complete, empty output, reader failure, no output file
    for (const [name, script] of [["complete", `open(out, "w").write(json.dumps({"timestamp": "2026-02-14T09:30:00.000000+0000", "eventMessage": "m"}) + "\\n")`], ["empty", `open(out, "w").write("")`], ["fails", `sys.exit(3)`], ["no file", `sys.exit(0)`]] as const) {
      const bin = await ulStandin(cwd, script);
      note(`unified_log ${name}`, await ul(cwd, bin, { path: await logarchive(cwd, `${name.replace(" ", "-")}.logarchive`), out_dir: `work/u-${name.replace(" ", "-")}` }));
    }
    for (const [name, answer] of seen) {
      assert.ok(["complete", "partial", "failed"].includes(answer.status), `${name}: status ${answer.status}`);
      assert.equal(typeof answer.status_basis, "string", name);
      assert.ok(answer.status_basis.length > 10, name);
    }
    const byName = Object.fromEntries(seen);
    assert.equal(byName["plist good"].status, "complete");
    assert.equal(byName["plist bad"].status, "failed");
    assert.equal(byName["fsevents good"].status, "complete");
    assert.equal(byName["fsevents unsupported"].status, "failed");
    assert.equal(byName["knowledgec good"].status, "complete");
    assert.equal(byName["unified_log complete"].status, "complete");
    assert.equal(byName["unified_log empty"].status, "partial");
    assert.equal(byName["unified_log fails"].status, "failed");
    assert.equal(byName["unified_log no file"].status, "failed");
    // the basis says what the status rests on, in words of this run
    assert.match(byName["plist good"].status_basis, /1 matched file/);
    assert.match(byName["fsevents unsupported"].status_basis, /no file could be read/);
  });
});
