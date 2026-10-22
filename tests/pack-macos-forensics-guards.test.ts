/**
 * The corrections to fsevents_parse, knowledgec_query, unified_log and plist_read that were found missing, each tested on the tools
 * as a job runs them and each failing on the tools before them:
 *
 *  - a filter and an order must never look at the raw bytes of a name that the answer withholds (the `stream` pattern, the lists of streams, tables, files,
 *    keys and conflicts);
 *  - a token cut by NULs or invisible characters must not be printed whole as hexadecimal (a BLOB's head, a UUID, the raw bytes of a path);
 *  - `max_seconds` is the clock of the tool, read at every row and every record, not every few hundred;
 *  - a FileVault recovery key is withheld; the claims of the manifests are the measured ones;
 *  - `contains` refuses repeats nested to a product that is exponential;
 *  - a resume from a stopped read goes on at the next row, also when thousands of rows share one start; a signal that lands while the answer is sealed
 *    is named in it; the private copy of a database is created 0600, a dead run's copy is removed, the copy has the clock too; the reader's helpers end
 *    with the reader.
 *
 * Canaries are built from pieces and never printed whole in a failure message.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { runPySnippet, withCwd } from "./tool-library-harness.ts";
import { CREATED, FS, KC, MAC, PLIST, UL, body, fsDir, fsPage, fsRecord, gz, kcDb, ok, runAndSignal, tool, ul, ulStandin, logarchive } from "./macos-pack-harness.ts";
import type { Json } from "./macos-pack-harness.ts";
import { prng } from "./windows-canary.ts";

const ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const rnd = (r: () => number, n: number, alpha = ALNUM): string => Array.from({ length: n }, () => alpha[Math.floor(r() * alpha.length)]).join("");
const cut = (text: string, sep: string, every: number): string => (text.match(new RegExp(`.{1,${every}}`, "gs")) ?? []).join(sep);
const hexOf = (text: string): string => Buffer.from(text, "utf8").toString("hex");
const marked = (v: unknown): boolean => typeof v === "string" && v.startsWith("<withheld");

// three tokens that sort before, between and after the visible names of a list: the place of the placeholder must be the same for all of them
const tokens = (): string[] => {
  const r = prng(7);
  return [["AK", "IA"].join("") + rnd(r, 16, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"), ["gh", "p_"].join("") + rnd(r, 36), ["xo", "xb-"].join("") + rnd(r, 24)];
};

const VISIBLE = ["0", "5", "A", "F", "K", "P", "U", "a", "f", "k", "p", "u", "z"];
// names of record files that stay distinct on a file system that ignores case (and that sort before, between and after the three tokens)
const FILES = ["0", "3", "6", "9", "b", "e", "h", "k", "n", "q", "t", "w", "z"];

// ---- the guard block is a copy ----------------------------------------------------------------------------------------------------------------

test("the three tools that print evidence carry the same guard block, byte for byte, next to the boundary block", async () => {
  const blocks: string[] = [];
  for (const t of ["fsevents_parse", "knowledgec_query", "unified_log"]) {
    const text = await readFile(join(MAC, t, "run.py"), "utf8");
    const start = text.indexOf("# BEGIN SHARED GUARD");
    const stop = text.indexOf("# END SHARED GUARD");
    assert.ok(start > text.indexOf("# END SHARED BOUNDARY") && stop > start, t);
    blocks.push(text.slice(start, stop));
  }
  assert.ok(blocks[0].length > 3000);
  assert.equal(blocks[1], blocks[0]);
  assert.equal(blocks[2], blocks[0]);
});

// ---- P1-A: no filter and no order over the raw text of a name the answer withholds --------------------------------------------------------------

async function streamDb(cwd: string, name: string, token: string): Promise<string> {
  const names = [...VISIBLE, token];
  const over: Record<string, Record<string, unknown>> = {};
  names.forEach((n, i) => (over[String(i + 1)] = { ZSTREAMNAME: n }));
  return kcDb(cwd, name, names.length, 0, over);
}

test("knowledgec_query: the stream pattern is matched against the name as printed, so a prefix of a withheld name answers nothing", async () => {
  await withCwd(async (cwd) => {
    const [aws] = tokens();
    const a = await streamDb(cwd, "a.db", aws);
    const b = await streamDb(cwd, "b.db", aws.split("").reverse().join("")); // the same length and shape, other characters
    const patterns = [aws.slice(0, 4) + "%", aws.slice(0, 5) + "%", aws.slice(0, 5) + "Q%", aws.slice(0, 8) + "%", "%" + aws.slice(-6), "AKIA_%", "no-such-stream", "%withheld%", "/app/%", "0", "A"];
    for (const pattern of patterns) {
      const first = ok(await tool(KC, cwd, { db: a, stream: pattern }));
      const second = ok(await tool(KC, cwd, { db: b, stream: pattern }));
      assert.equal(first.entry_count, second.entry_count, `entry_count for ${pattern.length}-character pattern`);
      assert.equal(first.stream_blind_rows, second.stream_blind_rows);
      assert.equal(first.status, second.status);
      assert.ok(!first.stream_blind_rows || first.status === "partial", "rows a pattern may have matched in what is withheld make the answer partial");
    }
    // a pattern that does not match any printed name selects nothing, and says that the withheld one may be what it meant
    const none = ok(await tool(KC, cwd, { db: a, stream: aws.slice(0, 5) + "%" }));
    assert.equal(none.entry_count, 0);
    assert.equal(none.stream_blind_rows, 1);
    assert.equal(none.status, "partial");
    assert.ok((none.problems as string[]).some((p) => /stream_blind_rows/.test(p)), JSON.stringify(none.problems));
    // the visible names and the placeholder itself are matched as they are printed
    assert.equal(ok(await tool(KC, cwd, { db: a, stream: "/app/%" })).entry_count, 0, "no visible name starts with /app/ here");
    assert.equal(ok(await tool(KC, cwd, { db: a, stream: "0" })).entry_count, 1);
    assert.equal(ok(await tool(KC, cwd, { db: a, stream: "<withheld%" })).entry_count, 1, "the placeholder is what is printed, and it matches");
    const everything = ok(await tool(KC, cwd, { db: a, stream: "%" }));
    assert.equal(everything.entry_count, VISIBLE.length + 1);
    assert.equal(everything.stream_blind_rows, 0);
  });
});

test("knowledgec_query: the list of streams is in the order of the text printed, whatever the bytes of a withheld name", async () => {
  await withCwd(async (cwd) => {
    const positions: number[] = [];
    let n = 0;
    for (const token of tokens()) {
      const db = await streamDb(cwd, `s${n++}.db`, token);
      const answer = ok(await tool(KC, cwd, { db }));
      const list = (answer.streams as Json[]).map((s) => String(s.stream));
      assert.equal(list.length, VISIBLE.length + 1);
      assert.ok(!JSON.stringify(answer).includes(token), "the token is not printed");
      positions.push(list.findIndex((s) => s.startsWith("<withheld")));
    }
    assert.ok(positions[0] >= 0);
    assert.deepEqual(new Set(positions).size, 1, `the placeholder stands at ${positions.join(", ")} for tokens that sort first, in the middle and last`);
  });
});

test("knowledgec_query: streams of one count that are all withheld come in an order that changes from run to run", async () => {
  await withCwd(async (cwd) => {
    const r = prng(11);
    const hidden = Array.from({ length: 8 }, (_, i) => ["gh", "p_"].join("") + rnd(r, 35) + "ABCDEFGH"[i]);
    const over: Record<string, Record<string, unknown>> = {};
    hidden.forEach((n, i) => (over[String(i + 1)] = { ZSTREAMNAME: n }));
    const db = await kcDb(cwd, "h.db", hidden.length, 0, over);
    const orders = new Set<string>();
    for (let run = 0; run < 6; run++) {
      const answer = ok(await tool(KC, cwd, { db }));
      // which stored stream stands where is visible by the count if the counts differ; here the 8 streams are alike, so the order is told by the first start
      orders.add((answer.streams as Json[]).map((s) => String(s.first_start_raw)).join(","));
    }
    assert.ok(orders.size > 1, "the order of 8 equal placeholders was the same in 6 runs");
  });
});

const TABLES_DB = `
import sqlite3, sys, json
con = sqlite3.connect(sys.argv[1])
for name in json.load(sys.stdin):
    con.execute('CREATE TABLE "%s" (a INTEGER)' % name.replace('"', '""'))
con.commit()
`;

test("knowledgec_query: the tables of a database that is not knowledgeC are listed in the order printed, not by the bytes of a withheld name", async () => {
  await withCwd(async (cwd) => {
    const positions: number[] = [];
    let n = 0;
    for (const token of tokens()) {
      const path = join(cwd, "work", `t${n++}.db`);
      const built = await runPySnippet(TABLES_DB, [path], ["ZA", "ZM", "ZZ", token]);
      assert.equal(built.code, 0, built.stderr);
      const answer = body(await tool(KC, cwd, { db: `work/t${n - 1}.db` }));
      assert.equal(answer.status, "failed");
      const tables = (answer.tables as string[]).map(String);
      assert.equal(tables.length, 4);
      positions.push(tables.findIndex((s) => s.includes("withheld")));
    }
    assert.ok(positions[0] >= 0);
    assert.equal(new Set(positions).size, 1, `the placeholder stands at ${positions.join(", ")}`);
  });
});

test("fsevents_parse: the record files are listed and read in the order of the names printed, whatever the bytes of a withheld file name", async () => {
  await withCwd(async (cwd) => {
    const positions: number[] = [];
    let n = 0;
    for (const token of tokens()) {
      const files: Record<string, Buffer> = {};
      FILES.forEach((name, i) => (files[name] = gz(fsPage("2SLD", [fsRecord(`tmp/${name}`, BigInt(i + 1), CREATED, BigInt(i + 1))]))));
      files[token] = gz(fsPage("2SLD", [fsRecord("tmp/hidden", 99n, CREATED, 99n)]));
      const dir = await fsDir(cwd, `d${n++}`, files);
      const answer = ok(await tool(FS, cwd, { path: dir }));
      const list = (answer.per_file as Json[]).map((f) => String(f.file));
      assert.equal(list.length, FILES.length + 1);
      assert.ok(!JSON.stringify(answer).includes(token));
      positions.push(list.findIndex((f) => f.includes("withheld")));
    }
    assert.ok(positions[0] >= 0);
    assert.equal(new Set(positions).size, 1, `the placeholder stands at ${positions.join(", ")}`);
  });
});

test("unified_log: the keys of a record without an entry's fields and the members in both trees are listed in the order printed", async () => {
  await withCwd(async (cwd) => {
    const keyPositions: number[] = [];
    const conflictPositions: number[] = [];
    let n = 0;
    for (const token of tokens()) {
      const keys = Object.fromEntries([["a", 1], ["m", 2], ["z", 3], [token, 4]]);
      const bin = await ulStandin(cwd, `open(out, "w").write(json.dumps(${JSON.stringify(keys)}) + "\\n")`);
      const answer = ok(await ul(cwd, bin, { path: await logarchive(cwd, `k${n}.logarchive`), out_dir: `work/k${n}` }));
      const first = answer.decoded_coverage.first_records_without_entry_fields[0].keys as string[];
      assert.equal(first.length, 4);
      keyPositions.push(first.findIndex((k) => k.includes("withheld")));
      // members in both trees with different bytes: refused, and the first of them are named
      const root = join(cwd, "work", `v${n}`);
      for (const tree of ["diagnostics", "uuidtext"]) await mkdir(join(root, tree, "0A"), { recursive: true });
      for (const name of ["a", "m", "z", token]) {
        await writeFile(join(root, "diagnostics", "0A", name), "one");
        await writeFile(join(root, "uuidtext", "0A", name), "two");
      }
      const refused = body(await ul(cwd, bin, { path: `work/v${n}`, out_dir: `work/c${n}` }));
      assert.match(refused.error, /both diagnostics and uuidtext/);
      const conflicts = (refused.conflicts as string[]).map(String);
      assert.equal(conflicts.length, 4);
      conflictPositions.push(conflicts.findIndex((c) => c.includes("withheld")));
      n++;
    }
    assert.ok(keyPositions[0] >= 0 && conflictPositions[0] >= 0);
    assert.equal(new Set(keyPositions).size, 1, `keys: ${keyPositions.join(", ")}`);
    assert.equal(new Set(conflictPositions).size, 1, `conflicts: ${conflictPositions.join(", ")}`);
  });
});

test("plist_read has neither class: it prints key names and file names whole, withholds by the key's name, and selects by the key the caller names", async () => {
  await withCwd(async (cwd) => {
    const text = '<?xml version="1.0"?><plist version="1.0"><dict><key>Password</key><string>hunter2</string><key>b</key><string>x</string></dict></plist>';
    await writeFile(join(cwd, "work", "p.plist"), text);
    const answer = ok(await tool(PLIST, cwd, { path: "work/p.plist" }));
    assert.ok(!JSON.stringify(answer).includes("hunter2"));
    const byKey = ok(await tool(PLIST, cwd, { path: "work/p.plist", key: "Password" }));
    assert.ok(!JSON.stringify(byKey).includes("hunter2"), "selecting a secret-named key returns its locator, not the value");
    const miss = body(await tool(PLIST, cwd, { path: "work/p.plist", key: "Nope" }));
    assert.equal(miss.files[0].status, "failed", "a key that is not there is a plain miss for that file");
  });
});

// ---- P1-B: a token cut by NULs or invisible characters is not printed whole as hexadecimal --------------------------------------------------

function splitCanaries(): Array<{ label: string; bytes: Buffer }> {
  const out: Array<{ label: string; bytes: Buffer }> = [];
  const r = prng(31);
  const shapes: Array<[string, () => string]> = [
    ["ghp", () => ["gh", "p_"].join("") + rnd(r, 36)],
    ["akia", () => ["AK", "IA"].join("") + rnd(r, 16, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")],
    ["base62", () => rnd(r, 40)],
  ];
  for (const [name, make] of shapes) {
    for (const [sepName, sep] of [["nul", "\u0000"], ["zw", "​"]] as const) {
      for (const every of [6, 12, 15]) {
        for (let k = 0; k < 4; k++) out.push({ label: `${name} ${sepName} every ${every}`, bytes: Buffer.from(cut(make(), sep, every), "utf8") });
      }
    }
  }
  // the same tokens, UTF-16 with a NUL between the characters, and with a zero-width space every 6
  for (const [name, make] of shapes) {
    out.push({ label: `${name} utf-16le`, bytes: Buffer.from(cut(make(), "​", 6), "utf16le") });
    out.push({ label: `${name} utf-16be`, bytes: Buffer.from(cut(make(), "​", 6), "utf16le").swap16() });
  }
  return out;
}

test("knowledgec_query: a token cut by NULs or zero-width characters is not printed whole in the hexadecimal of a BLOB's head, a long BLOB's head or a UUID", async () => {
  const canaries = splitCanaries();
  await withCwd(async (cwd) => {
    const over: Record<string, Record<string, unknown>> = {};
    canaries.forEach((c, i) => {
      over[String(i + 1)] = {
        ZX0: { hex: c.bytes.toString("hex") }, // a BLOB of at most 4,096 bytes: shown whole as hex
        ZX1: { hex: Buffer.concat([c.bytes, Buffer.alloc(5000, 0x41)]).toString("hex") }, // longer than the cap: its head
        ZUUID: { hex: c.bytes.toString("hex") },
      };
    });
    const db = await kcDb(cwd, "split.db", canaries.length, ["ZX0", "ZX1"], over);
    const run = await tool(KC, cwd, { db, limit: 1000, max_inline_bytes: 20_000_000 });
    const answer = ok(run);
    assert.equal(answer.entries.length, canaries.length);
    const leaks: Record<string, number> = {};
    answer.entries.forEach((entry: Json, i: number) => {
      const c = canaries[i];
      for (const [slot, value] of [["blob head", entry.zobject_other?.ZX0?._hex], ["long blob head", entry.zobject_other?.ZX1?._hex], ["uuid", entry.uuid]]) {
        if (!marked(value)) leaks[`${slot}: ${c.label}`] = (leaks[`${slot}: ${c.label}`] ?? 0) + 1;
      }
    });
    assert.deepEqual(leaks, {}, "printed hexadecimal of a token that was cut");
    assert.ok(answer.boundary.strings_withheld >= canaries.length * 3);
  });
});

test("knowledgec_query: random binary data in a BLOB is not taken for a token (the guard withholds it in about 1 case in 200 or fewer)", async () => {
  await withCwd(async (cwd) => {
    const r = prng(5);
    const over: Record<string, Record<string, unknown>> = {};
    const n = 300;
    for (let i = 1; i <= n; i++) over[String(i)] = { ZX0: { hex: Buffer.from(Array.from({ length: 256 }, () => Math.floor(r() * 256))).toString("hex") } };
    const db = await kcDb(cwd, "rand.db", n, ["ZX0"], over);
    const answer = ok(await tool(KC, cwd, { db, limit: 1000, max_inline_bytes: 20_000_000 }));
    const withheld = answer.entries.filter((e: Json) => marked(e.zobject_other?.ZX0?._hex)).length;
    assert.ok(withheld <= 6, `${withheld} of ${n} random blobs withheld`);
  });
});

test("fsevents_parse: a path with an invalid UTF-8 byte and a token cut by zero-width characters does not print the token whole in path_raw_hex", async () => {
  const canaries = splitCanaries().filter((c) => c.label.includes(" zw "));          // (a NUL ends a path in this format: it cannot be inside one)
  await withCwd(async (cwd) => {
    const records = canaries.map((c, i) => fsRecord(Buffer.concat([Buffer.from("Users/alice/"), Buffer.from([0xff]), c.bytes]), BigInt(i + 1), CREATED, BigInt(i + 1)));
    const dir = await fsDir(cwd, "ev", { "0000000000000001": gz(fsPage("2SLD", records)) });
    const answer = ok(await tool(FS, cwd, { path: dir, limit: 1000, max_inline_bytes: 20_000_000 }));
    assert.equal(answer.records.length, canaries.length);
    const leaks = answer.records.filter((rec: Json) => rec.path_invalid_utf8 && !marked(rec.path_raw_hex)).length;
    assert.equal(leaks, 0, "records whose path_raw_hex was printed");
  });
});

// ---- the clock is read at every row and every record --------------------------------------------------------------------------------------------

const HEAVY_DB = `
import random, sqlite3, sys
path, rows, cols, length = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
rng = random.Random(3)
names = ["ZX%d" % i for i in range(cols)]
con = sqlite3.connect(path)
con.execute("CREATE TABLE ZOBJECT (Z_PK INTEGER PRIMARY KEY, ZSTREAMNAME VARCHAR, ZVALUESTRING VARCHAR, ZSTARTDATE TIMESTAMP%s)" % "".join(", %s TEXT" % n for n in names))
alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
for i in range(1, rows + 1):
    con.execute("INSERT INTO ZOBJECT VALUES (%s)" % ",".join("?" * (4 + cols)), [i, "/app/inFocus", "v", 700000000.0 + i] + ["".join(rng.choices(alpha, k=length)) for _ in names])
con.commit()
`;

test("knowledgec_query reads the clock at every row: rows of long strings do not run it past max_seconds by 256 rows' time", async () => {
  await withCwd(async (cwd) => {
    const rows = 100;
    const built = await runPySnippet(HEAVY_DB, [join(cwd, "work", "heavy.db"), String(rows), "30", "4000"], {});
    assert.equal(built.code, 0, built.stderr);
    const started = Date.now();
    const answer = ok(await tool(KC, cwd, { db: "work/heavy.db", max_seconds: 1.5, out_file: "work/o.jsonl" }));
    const wall = (Date.now() - started) / 1000;
    assert.equal(answer.status, "partial");
    assert.ok(answer.entry_count >= 1 && answer.entry_count < rows, `${answer.entry_count} rows read`);
    assert.ok(answer.limits.seconds_used <= 1.5 + 4, `seconds_used ${answer.limits.seconds_used} for max_seconds 1.5`);
    assert.ok(wall < 40, `wall ${wall} s`);
    assert.ok(answer.resume.after_z_pk >= 1);
  });
});

test("fsevents_parse reads the clock at every record: 250 KB paths do not run it past max_seconds by 512 records' time", async () => {
  await withCwd(async (cwd) => {
    const r = prng(9);
    const records = Array.from({ length: 24 }, (_, i) => fsRecord("tmp/" + rnd(r, 250_000), BigInt(i + 1), CREATED, BigInt(i + 1)));
    const dir = await fsDir(cwd, "ev", { "0000000000000001": gz(fsPage("2SLD", records)) });
    const answer = ok(await tool(FS, cwd, { path: dir, max_seconds: 1, out_file: "work/o.jsonl" }));
    assert.equal(answer.status, "partial");
    assert.ok(answer.coverage.records.decoded < 24, `${answer.coverage.records.decoded} records read`);
    assert.ok(answer.limits.seconds_used <= 1 + 4, `seconds_used ${answer.limits.seconds_used} for max_seconds 1`);
  });
});

// ---- P2-2: a predicate that names the text of a message ---------------------------------------------------------------------------------------

test("unified_log with Apple's log: a predicate on message text is warned about, and refused in a job run as secret output", { skip: process.platform !== "darwin" }, async () => {
  await withCwd(async (cwd) => {
    const bin = join(cwd, "ulbin");
    await mkdir(bin, { recursive: true });
    const { symlink, chmod } = await import("node:fs/promises");
    const python = spawnSync("python3", ["-c", "import sys; print(sys.executable)"], { encoding: "utf8" }).stdout.trim();
    await symlink(python, join(bin, "python3")).catch(() => undefined);
    await writeFile(join(bin, "log"), `#!${python}\nimport json, sys\nif "--version" in sys.argv: print("log"); sys.exit(0)\nprint(json.dumps({"timestamp": "2026-02-14 09:30:00.000000+0000", "eventMessage": "m", "processImagePath": "/usr/bin/sudo", "subsystem": "s"}))\n`);
    await chmod(join(bin, "log"), 0o755);
    const path = await logarchive(cwd);
    const onProcess = ok(await ul(cwd, bin, { path, out_dir: "work/p1", predicate: 'process == "sudo"' }));
    assert.ok(onProcess.warnings.some((w: string) => /predicate was evaluated/.test(w)), JSON.stringify(onProcess.warnings));
    const onText = ok(await ul(cwd, bin, { path, out_dir: "work/p2", predicate: 'eventMessage CONTAINS "password"' }));
    assert.ok(onText.warnings.some((w: string) => /count of matches/.test(w)));
    await mkdir(join(cwd, "out"), { recursive: true });
    const refused = await ul(cwd, bin, { path, out_dir: "out/p3", predicate: 'eventMessage CONTAINS "password"' }, {}, true);
    assert.equal(refused.code, 1);
    const answer = body(refused);
    assert.equal(answer.status, "failed");
    assert.equal(answer.predicate_names_message_text, true);
    const accepted = await ul(cwd, bin, { path, out_dir: "out/p4", predicate: 'process == "sudo" AND messageType == "Error"' }, {}, true);
    assert.equal(body(accepted).status, "complete", accepted.stdout);
  });
});

// ---- P2-3: a FileVault recovery key is withheld --------------------------------------------------------------------------------------------

const vault = (r: () => number): string => Array.from({ length: 6 }, () => rnd(r, 4, "ABCDEFGHJKLMNPQRSTUVWXYZ23456789")).join("-");

test("a FileVault recovery key is withheld in a value, a stream, a BLOB's head, a path and a log message, and an ordinary dashed string is not", async () => {
  await withCwd(async (cwd) => {
    const r = prng(77);
    const n = 40;
    const keys = Array.from({ length: n }, () => vault(r));
    const over: Record<string, Record<string, unknown>> = {};
    keys.forEach((k, i) => (over[String(i + 1)] = { ZVALUESTRING: `recovery key ${k} saved`, ZSTREAMNAME: k, ZX0: { hex: Buffer.from(k).toString("hex") } }));
    const db = await kcDb(cwd, "v.db", n, ["ZX0"], over);
    const run = await tool(KC, cwd, { db, limit: 1000, max_inline_bytes: 20_000_000 });
    const printed = run.stdout;
    assert.equal(keys.filter((k) => printed.includes(k) || printed.includes(Buffer.from(k).toString("hex"))).length, 0, "keys printed by knowledgec_query");
    const records = keys.map((k, i) => fsRecord(`Users/alice/${k}/notes.txt`, BigInt(i + 1), CREATED, BigInt(i + 1)));
    const dir = await fsDir(cwd, "ev", { "0000000000000001": gz(fsPage("2SLD", records)) });
    const fs = (await tool(FS, cwd, { path: dir, limit: 1000, max_inline_bytes: 20_000_000 })).stdout;
    assert.equal(keys.filter((k) => fs.includes(k)).length, 0, "keys printed by fsevents_parse");
    const lines = keys.map((k) => JSON.stringify({ timestamp: "2026-02-14T09:30:00.000000+0000", eventMessage: `backup key ${k}`, process: `/usr/bin/${k}`, subsystem: "s" })).join("\n") + "\n";
    const bin = await ulStandin(cwd, `open(out, "w").write(${JSON.stringify(lines)})`);
    const log = (await ul(cwd, bin, { path: await logarchive(cwd), out_dir: "work/u", limit: 1000 })).stdout;
    assert.equal(keys.filter((k) => log.includes(k)).length, 0, "keys printed by unified_log");
    // a dashed string that is not a key is left as it is
    const plain = ok(await tool(KC, cwd, { db: await kcDb(cwd, "p.db", 1, 0, { "1": { ZVALUESTRING: "2026-02-14-ABCD-build-notes", ZSTREAMNAME: "/app/inFocus" } }) }));
    assert.equal(plain.entries[0].value_string, "2026-02-14-ABCD-build-notes");
  });
});

// ---- P2-4: contains ----------------------------------------------------------------------------------------------------------------------------

test("fsevents_parse refuses repeats nested to an exponential product at once, and still runs the ordinary ones", async () => {
  await withCwd(async (cwd) => {
    const dir = await fsDir(cwd, "ev", { "0000000000000001": gz(fsPage("2SLD", [fsRecord("tmp/" + "a".repeat(40) + "b", 1n, CREATED, 1n), fsRecord("net/10.0.0.1/ab:cd:ef:01:23:45", 2n, CREATED, 2n), fsRecord("tmp/" + "a".repeat(16) + "b", 3n, CREATED, 3n)])) });
    for (const pattern of ["((((((a?){8}){8}){8}){8}){8}){8}b", "((a?){8}){8}b", "(((a{2,8}){2,8}){2,8}){2,8}b"]) {
      const started = Date.now();
      const run = await tool(FS, cwd, { path: dir, contains: pattern });
      assert.ok(Date.now() - started < 5000, pattern);
      assert.equal(run.code, 1, pattern);
      assert.match(body(run).error, /contains is not run: it has repeats inside repeats whose counts multiply/, pattern);
    }
    for (const [pattern, count] of [["(\\d{1,3}\\.){3}\\d{1,3}", 1], ["(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", 1], ["((a{4}){4})b", 1], ["Users/[^/]+/", 0]] as const) {
      const answer = ok(await tool(FS, cwd, { path: dir, contains: pattern }));
      assert.equal(answer.record_count, count, pattern);
    }
  });
});

// ---- P3: resume, signals during the seal, the private copy, the reader's helpers --------------------------------------------------------------

test("knowledgec_query resumes at the next row: 40 rows with one start are read once each, 1 row per run, and the older resume_since is still named", async () => {
  await withCwd(async (cwd) => {
    const rows = 40;
    const over: Record<string, Record<string, unknown>> = {};
    for (let i = 1; i <= rows; i++) over[String(i)] = { ZSTARTDATE: 700000000.5 };
    const tied = await kcDb(cwd, "tied.db", rows, 0, over);
    const distinct = await kcDb(cwd, "distinct.db", rows);
    for (const db of [tied, distinct]) {
      const seen: number[] = [];
      let args: Json = { db, max_seconds: 0.001 };
      for (let run = 0; run < rows + 5; run++) {
        const answer = ok(await tool(KC, cwd, args));
        for (const entry of answer.entries as Json[]) seen.push(entry.z_pk);
        if (!answer.resume) break;
        assert.equal(answer.resume.rows_read, answer.entry_count);
        assert.ok(answer.resume.resume_since, "the older way is still given");
        assert.match(answer.resume.to_go_on, /after_start_raw and after_z_pk/);
        args = { db, max_seconds: 0.001, after_start_raw: answer.resume.after_start_raw, after_z_pk: answer.resume.after_z_pk };
      }
      assert.equal(seen.length, rows, `${db}: ${seen.length} rows read in all`);
      assert.deepEqual([...seen].sort((a, b) => a - b), Array.from({ length: rows }, (_, i) => i + 1), "every row once");
    }
    // a start that is NULL sorts first: the keyset goes through the NULLs and on
    const nulls: Record<string, Record<string, unknown>> = {};
    for (let i = 1; i <= 6; i++) nulls[String(i)] = { ZSTARTDATE: null };
    const withNulls = await kcDb(cwd, "nulls.db", 12, 0, nulls);
    const seen: number[] = [];
    let args: Json = { db: withNulls, max_seconds: 0.001 };
    for (let run = 0; run < 20; run++) {
      const answer = ok(await tool(KC, cwd, args));
      for (const entry of answer.entries as Json[]) seen.push(entry.z_pk);
      if (!answer.resume) break;
      args = { db: withNulls, max_seconds: 0.001, after_start_raw: answer.resume.after_start_raw, after_z_pk: answer.resume.after_z_pk };
    }
    assert.deepEqual([...seen].sort((a, b) => a - b), Array.from({ length: 12 }, (_, i) => i + 1));
    const bad = body(await tool(KC, cwd, { db: tied, after_z_pk: "x" }));
    assert.equal(bad.status, "failed");
  });
});

const LOAD = `
import importlib.util, sys
spec = importlib.util.spec_from_file_location("tool", sys.argv[1])
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
`;

test("the answer names a stop signal that arrived while it was being sealed, and exits for it", async () => {
  const snippet = LOAD + `
import os, signal
m.install_stop_handlers()
signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM})
os.kill(os.getpid(), signal.SIGTERM)                  # it arrives while signals are held: pending
got = m.emit_answer({"status": "complete", "status_basis": "every row was read", "n": 1}, None, indent=2)
sys.stderr.write("RETURNED=%r\\n" % got)
`;
  for (const t of ["fsevents_parse", "knowledgec_query", "unified_log"]) {
    const run = await runPySnippet(snippet, [join(MAC, t, "run.py")], {});
    assert.equal(run.code, 0, run.stderr);
    const answer = JSON.parse(run.stdout) as Json;
    assert.equal(answer.status, "partial", t);
    assert.equal(answer.interrupted, "SIGTERM", t);
    assert.match(answer.status_basis, /SIGTERM arrived while the answer was being sealed/, t);
    assert.match(run.stderr, /RETURNED=<Signals.SIGTERM: 15>/, t);
  }
  const quiet = await runPySnippet(LOAD + `got = m.emit_answer({"status": "complete", "status_basis": "x"}, None)\nsys.stderr.write("RETURNED=%r\\n" % got)`, [join(MAC, "knowledgec_query", "run.py")], {});
  assert.equal((JSON.parse(quiet.stdout) as Json).status, "complete");
  assert.match(quiet.stderr, /RETURNED=None/);
});

test("knowledgec_query's private copy is created 0600, and a copy a killed run left is removed by the next run; a live run's is not", async () => {
  const snippet = LOAD + `
import os, stat, subprocess, tempfile
root = tempfile.mkdtemp(prefix="kc-stage-")
src = os.path.join(root, "src.bin")
open(src, "wb").write(b"x" * 3000000)
digest = m.sha256_copy(src, os.path.join(root, "copy.bin"))
print("mode", oct(stat.S_IMODE(os.stat(os.path.join(root, "copy.bin")).st_mode)))
dead = subprocess.Popen([sys.executable, "-c", "pass"]); dead.wait()
parent = os.path.join(root, "stage")
os.mkdir(parent)
names = {"dead": "knowledgec-%d-abcd1234" % dead.pid, "live": "knowledgec-%d-abcd1234" % os.getpid(), "other": "keep-%d-abcd1234" % dead.pid}
for n in names.values():
    os.mkdir(os.path.join(parent, n)); open(os.path.join(parent, n, "k.db"), "w").write("x")
os.symlink(root, os.path.join(parent, "knowledgec-%d-link" % dead.pid))
m.remove_dead_stages(parent)
print("left", sorted(os.listdir(parent)))
try:
    m.sha256_copy(src, os.path.join(root, "late.bin"), deadline=0.0)
except m.StageTimeUp:
    print("time up")
`;
  const run = await runPySnippet(snippet, [join(MAC, "knowledgec_query", "run.py")], {});
  assert.equal(run.code, 0, run.stderr);
  assert.match(run.stdout, /mode 0o600/);
  const left = /left (\[.*\])/.exec(run.stdout)?.[1] ?? "";
  assert.match(left, /knowledgec-\d+-abcd1234/);
  assert.equal((left.match(/abcd1234/g) ?? []).length, 2, `the dead run's copy is gone, the live run's and the other name stay: ${left}`);
  assert.match(left, /-link/, "a link is not followed or removed");
  assert.match(run.stdout, /time up/);
});

test("knowledgec_query stops copying a database that has used max_seconds, answers partial with nothing read, and removes what it copied", async () => {
  await withCwd(async (cwd) => {
    const db = await kcDb(cwd, "wal.db", 30, 0, {}, "wal");
    const answer = ok(await tool(KC, cwd, { db, max_seconds: 0.000001 }));
    assert.equal(answer.status, "partial");
    assert.equal(answer.entry_count, 0);
    assert.equal(answer.source_used.staged, false, "the copy was not finished");
    assert.match(answer.resume.to_go_on, /copied|larger max_seconds/);
    const left = spawnSync("find", [join(cwd, "work")], { encoding: "utf8" }).stdout;
    assert.doesNotMatch(left, /knowledgec-\d+-/, "no private copy is left");
  });
});

test("unified_log ends what the reader started, not only the reader: its helper is gone after a time-out and after a signal", async () => {
  await withCwd(async (cwd) => {
    const marker = (name: string): string => join(cwd, name);
    const reader = (pidFile: string): string => `
import subprocess
helper = subprocess.Popen(["/bin/sleep", "300"])
open(${JSON.stringify(pidFile)}, "w").write(str(helper.pid))
open(out, "w").write("")
time.sleep(120)
`;
    const alive = (pid: number): boolean => {
      try {
        process.kill(pid, 0);
        return true;
      } catch {
        return false;
      }
    };
    const gone = async (pid: number): Promise<boolean> => {
      for (let i = 0; i < 60 && alive(pid); i++) await new Promise((r) => setTimeout(r, 50));
      const dead = !alive(pid);
      if (!dead) process.kill(pid, "SIGKILL"); // (by the pid the stand-in recorded: the test's own decoy)
      return dead;
    };
    const timedOut = marker("helper1.pid");
    const bin1 = await ulStandin(cwd, reader(timedOut));
    const answer = body(await ul(cwd, bin1, { path: await logarchive(cwd), out_dir: "work/r1", timeout_seconds: 2 }));
    assert.equal(answer.timed_out, true);
    assert.equal(await gone(Number(await readFile(timedOut, "utf8"))), true, "the helper outlived the time-out");

    const signalled = marker("helper2.pid");
    await mkdir(join(cwd, "bin2"), { recursive: true });
    const bin2 = await ulStandin(cwd, reader(signalled));
    const run = await runAndSignal(UL, cwd, { path: await logarchive(cwd, "y.logarchive"), out_dir: "work/r2" }, "SIGTERM", async () => (await readFile(signalled, "utf8")).length > 0, {}, bin2);
    assert.equal(run.signalled, true);
    assert.equal(JSON.parse(run.stdout).interrupted, "SIGTERM");
    assert.equal(await gone(Number(await readFile(signalled, "utf8"))), true, "the helper outlived the signal");
  });
});

test("the manifests state what was measured: the clock, the signal during the seal, the private copy, the predicate, the FileVault key and the unclaimed shapes", async () => {
  const manifests: Record<string, string> = {};
  for (const t of ["fsevents_parse", "knowledgec_query", "unified_log", "plist_read"]) manifests[t] = JSON.parse(await readFile(join(MAC, t, "manifest.json"), "utf8")).description;
  for (const t of ["fsevents_parse", "knowledgec_query", "unified_log"]) {
    assert.match(manifests[t], /FileVault/, t);
    assert.doesNotMatch(manifests[t], /in 11 of 1,000|Of the 21 shapes the boundary claims, 20/, t);
    assert.match(manifests[t], /BitLocker recovery key/, t);
    assert.match(manifests[t], /Wi-Fi/, t);
  }
  assert.match(manifests.knowledgec_query, /after_z_pk/);
  assert.match(manifests.knowledgec_query, /every row/);
  assert.match(manifests.fsevents_parse, /every record/);
  assert.match(manifests.unified_log, /predicate/);
  assert.match(manifests.unified_log, /SIGKILL/);
  const params = JSON.parse(await readFile(join(MAC, "knowledgec_query", "manifest.json"), "utf8")).params;
  assert.equal(params.after_z_pk.type, "integer");
  assert.equal(params.after_start_raw.type, "number");
});
