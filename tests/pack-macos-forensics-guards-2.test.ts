/**
 * Second set of corrections to fsevents_parse, knowledgec_query and unified_log, each tested on the tools as a job runs them and each failing on the
 * tools before them:
 *
 *  - a token cut by a control character, a private-use or an unassigned code point is not printed whole as hexadecimal (the boundary's text layer reads
 *    through these, so the hex guard must too), and the cost on random and real binary data stays small;
 *  - the stream inventory, the table list and the directory listing are bounded and under the clock: a file with a hundred thousand stream names is a
 *    pass and a list of 2,000, not an answer that runs past the manifest's time;
 *  - a FileVault recovery key is withheld wherever it stands, also next to other letters or digits;
 *  - a stop signal that lands while the answer is written is found afterwards (exit code and stderr);
 *  - after_z_pk without after_start_raw and values SQLite cannot hold are refused with the reason; `stream` writes nothing to stderr;
 *  - a dead run's private copy is told from a live run's by a lock, not by a process number.
 *
 * Canaries are built from pieces and never printed whole in a failure message.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { runPySnippet, withCwd } from "./tool-library-harness.ts";
import { CREATED, FS, KC, MAC, body, fsDir, fsPage, fsRecord, gz, kcDb, measured, ok, tool } from "./macos-pack-harness.ts";
import type { Json } from "./macos-pack-harness.ts";
import { prng } from "./windows-canary.ts";

const ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const rnd = (r: () => number, n: number, alpha = ALNUM): string => Array.from({ length: n }, () => alpha[Math.floor(r() * alpha.length)]).join("");
const cut = (text: string, sep: string, every: number): string => (text.match(new RegExp(`.{1,${every}}`, "gs")) ?? []).join(sep);
const marked = (v: unknown): boolean => typeof v === "string" && v.startsWith("<withheld");
const TOOLS3 = ["fsevents_parse", "knowledgec_query", "unified_log"] as const;

const LOAD = `
import importlib.util, sys
spec = importlib.util.spec_from_file_location("tool", sys.argv[1])
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
`;

/** A Python snippet run in `cwd` with the given environment (runPySnippet has neither). */
function snippet(code: string, args: string[], stdin: unknown, cwd: string, env: Record<string, string> = {}): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn("python3", ["-c", code, ...args], { cwd, env: { ...process.env, AGENT_ID: "s1", ...env } });
    const so: Buffer[] = [];
    const se: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => so.push(c));
    child.stderr.on("data", (c: Buffer) => se.push(c));
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stdout: Buffer.concat(so).toString("utf8"), stderr: Buffer.concat(se).toString("utf8") }));
    child.stdin.end(JSON.stringify(stdin));
  });
}

/** The tool with the arguments as the JSON text the caller sends (a number JavaScript cannot hold goes through as it is). */
function toolRaw(script: string, cwd: string, text: string): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn("python3", [script], { cwd, env: { ...process.env, AGENT_ID: "s1" } });
    const so: Buffer[] = [];
    const se: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => so.push(c));
    child.stderr.on("data", (c: Buffer) => se.push(c));
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stdout: Buffer.concat(so).toString("utf8"), stderr: Buffer.concat(se).toString("utf8") }));
    child.stdin.end(text);
  });
}

/** The tool's main() with module constants replaced first (a small cap in place of the real one), the arguments on stdin. */
const WITH_CONSTANTS = LOAD + `
import json
for k, v in json.loads(sys.argv[2]).items():
    setattr(m, k, v)
m.install_stop_handlers()
m.main()
`;

// ---- P1-1: control characters, private-use and unassigned code points cut a token the same way NULs do ---------------------------------------------

const SEPARATORS: Array<[string, string]> = [
  ["SOH", "\u0001"],
  ["DEL", "\u007f"],
  ["ESC", "\u001b"],
  ["NEL", "\u0085"],
  ["private-use", ""],
  ["unassigned", "͸"],
  ["dotless i", "ı"],
];

function controlCanaries(): Array<{ label: string; bytes: Buffer }> {
  const r = prng(41);
  const shapes: Array<[string, () => string]> = [
    ["ghp", () => ["gh", "p_"].join("") + rnd(r, 36)],
    ["akia", () => ["AK", "IA"].join("") + rnd(r, 16, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")],
    ["xoxb", () => ["xo", "xb-"].join("") + rnd(r, 24)],
    ["base62", () => rnd(r, 40)],
  ];
  const out: Array<{ label: string; bytes: Buffer }> = [];
  for (const [name, make] of shapes) {
    for (const [sepName, sep] of SEPARATORS) {
      for (const every of [4, 6, 12, 15]) {
        // (a piece of 15 or fewer characters: the cuts the block's own hex reading does not see through; at 12 and 15 a 40-character token holds only two or three separators)
        for (let k = 0; k < 2; k++) out.push({ label: `${name} ${sepName} every ${every}`, bytes: Buffer.from(cut(make(), sep, every), "utf8") });
      }
    }
  }
  return out;
}

test("knowledgec_query: a token cut by a control character, a private-use or an unassigned code point is not printed whole in a BLOB's head or a UUID", async () => {
  const canaries = controlCanaries();
  await withCwd(async (cwd) => {
    const over: Record<string, Record<string, unknown>> = {};
    canaries.forEach((c, i) => {
      over[String(i + 1)] = {
        ZX0: { hex: c.bytes.toString("hex") },
        ZX1: { hex: Buffer.concat([c.bytes, Buffer.alloc(5000, 0x41)]).toString("hex") }, // longer than the cap: its head
        ZUUID: { hex: c.bytes.toString("hex") },
      };
    });
    const db = await kcDb(cwd, "ctl.db", canaries.length, ["ZX0", "ZX1"], over);
    const answer = ok(await tool(KC, cwd, { db, limit: 1000, max_inline_bytes: 40_000_000 }));
    assert.equal(answer.entries.length, canaries.length);
    const leaks: Record<string, number> = {};
    answer.entries.forEach((entry: Json, i: number) => {
      for (const [slot, value] of [["blob head", entry.zobject_other?.ZX0?._hex], ["long blob head", entry.zobject_other?.ZX1?._hex], ["uuid", entry.uuid]]) {
        if (!marked(value)) leaks[`${slot}: ${canaries[i].label}`] = (leaks[`${slot}: ${canaries[i].label}`] ?? 0) + 1;
      }
    });
    assert.deepEqual(leaks, {}, "printed hexadecimal of a token that was cut");
  });
});

test("fsevents_parse: a path with an invalid UTF-8 byte and a token cut by a control character does not print the token whole in path_raw_hex, nor in raw_hex of fseventsd-uuid", async () => {
  const canaries = controlCanaries();
  await withCwd(async (cwd) => {
    const records = canaries.map((c, i) => fsRecord(Buffer.concat([Buffer.from("Users/alice/"), Buffer.from([0xff]), c.bytes]), BigInt(i + 1), CREATED, BigInt(i + 1)));
    const dir = await fsDir(cwd, "ev", { "0000000000000001": gz(fsPage("2SLD", records)), "fseventsd-uuid": canaries[0].bytes });
    const answer = ok(await tool(FS, cwd, { path: dir, limit: 1000, max_inline_bytes: 40_000_000 }));
    assert.equal(answer.records.length, canaries.length);
    const leaks = answer.records.filter((rec: Json) => rec.path_invalid_utf8 && !marked(rec.path_raw_hex)).length;
    assert.equal(leaks, 0, "records whose path_raw_hex was printed");
    assert.ok(marked(answer.log_identity.raw_hex), "raw_hex of fseventsd-uuid was printed");
  });
});

test("the hex guard reads a control character out one at a time, and the budget, the controls and the false withholds are as measured", async () => {
  const code = LOAD + `
import os, random
r = random.Random(5)
def withheld(raw):
    h = raw.hex()
    return m.sealed_text(m.guard_hex(h, "_hex"), "hex", "_hex") != h
token = "gh" + "p_" + "".join(r.choice("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") for _ in range(36))
def cut(sep, n):
    return sep.join(token[i:i + n] for i in range(0, len(token), n))
# a separator that occurs once, twice, or in every piece
for sep in ("\\x01", "\\x7f", "\\x1b", "\\u0085", "\\ue000", "\\u0378", "\\u0130"):
    for n in (2, 6, 12, 15, 20):
        print("cut", repr(sep), n, withheld(cut(sep, n).encode()))
# UTF-16 and UTF-32 and Latin-1 forms of the same cut token
for codec in ("utf-16-le", "utf-16-be"):
    print("codec", codec, withheld(cut("\\x01", 6).encode(codec)), withheld(("\\ufeff" + cut("\\x01", 6)).encode(codec)))
print("codec latin-1", withheld(b"\\x07\\x08" + cut("\\x01", 6).encode() + b"\\x03\\x04"))
# the costs: random bytes and text with line ends are not taken for a token
rand4k = sum(withheld(bytes(r.getrandbits(8) for _ in range(4096))) for _ in range(100))
rand256 = sum(withheld(bytes(r.getrandbits(8) for _ in range(256))) for _ in range(100))
print("random4k", rand4k, "random256", rand256)
print("lines", withheld(b"first line of a note\\nsecond line of a note\\nthird line of a note\\n"))
# a field too long and too full of control characters to read is withheld whole; a long one with none is read as before
print("long-random", withheld(bytes(r.getrandbits(8) for _ in range(100000))))
print("long-plain", withheld(b"the quick brown fox jumps over the lazy dog\\n" * 2300))
`;
  for (const t of TOOLS3) {
    const run = await runPySnippet(code, [join(MAC, t, "run.py")], {});
    assert.equal(run.code, 0, run.stderr);
    const lines = run.stdout.trim().split("\n");
    for (const line of lines.filter((l) => l.startsWith("cut ") || l.startsWith("codec"))) assert.ok(!line.includes("False"), `${t}: a cut token was printed: ${line}`);
    const num = (name: string): number => Number(new RegExp(`${name} (\\d+)`).exec(run.stdout)?.[1]);
    assert.ok(num("random4k") <= 5, `${t}: ${num("random4k")} of 100 random 4 KB blobs withheld`);
    assert.ok(num("random256") <= 2, `${t}: ${num("random256")} of 100 random 256-byte blobs withheld`);
    assert.match(run.stdout, /long-random True/, t);
    assert.match(run.stdout, /long-plain False/, t);
  }
});

// ---- P1-2: the inventory, the table list and the directory listing are bounded and under the clock ----------------------------------------------------

const MANY_STREAMS = `
import random, sqlite3, sys
con = sqlite3.connect(sys.argv[1])
con.execute("CREATE TABLE ZOBJECT (Z_PK INTEGER PRIMARY KEY, ZSTREAMNAME VARCHAR, ZVALUESTRING VARCHAR, ZSTARTDATE TIMESTAMP)")
n = int(sys.argv[2])
r = random.Random(3)
con.executemany("INSERT INTO ZOBJECT VALUES (?, ?, ?, ?)", ((i, "/com.apple.%012x/%d" % (r.getrandbits(48), i), "v", 700000000.0 + i) for i in range(1, n + 1)))
# five streams with many rows each: the ones that the list must keep
for k in range(5):
    con.executemany("INSERT INTO ZOBJECT VALUES (?, ?, ?, ?)", ((n + 1 + k * 20 + j, "/keep/%d" % k, "v", 700000000.0) for j in range(20)))
con.commit()
`;

test("knowledgec_query lists at most 2,000 streams (the ones with the most entries), counts the rest, and ends inside its time on a file of 300,000 stream names", async () => {
  await withCwd(async (cwd) => {
    const path = join(cwd, "work", "many.db");
    const built = await runPySnippet(MANY_STREAMS, [path, "300000"], {});
    assert.equal(built.code, 0, built.stderr);
    const run = await measured(KC, cwd, { db: "work/many.db", max_seconds: 3, limit: 5 });
    assert.equal(run.code, 0, run.stderr);
    const answer = JSON.parse(run.stdout) as Json;
    assert.equal(answer.status, "partial");
    assert.equal(answer.streams_total, 2000, "the list holds 2,000 streams");
    assert.equal(answer.streams_in_file, 300005);
    assert.equal(answer.streams_not_listed, 300005 - 2000);
    assert.ok((answer.problems as string[]).some((p) => /streams_not_listed/.test(p)), JSON.stringify(answer.problems));
    const listed = (answer.streams as Json[]).map((s) => String(s.stream));
    for (let k = 0; k < 5; k++) assert.ok(listed.includes(`/keep/${k}`), `the stream with 20 entries is in the first 200 of the list: /keep/${k}`);
    // (the old head took 15 to 20 CPU seconds here: it judged and sealed every one of the 300,000 names outside every clock)
    assert.ok(run.cpu < 12, `cpu ${run.cpu} s`);
    assert.ok(run.mb < 400, `${run.mb} MB`);
  });
});

test("knowledgec_query with a stream filter on a file of many stream names keeps the same bound, and the filter still sees every name", async () => {
  await withCwd(async (cwd) => {
    const built = await runPySnippet(MANY_STREAMS, [join(cwd, "work", "many.db"), "3000"], {});
    assert.equal(built.code, 0, built.stderr);
    const answer = ok(await tool(KC, cwd, { db: "work/many.db", stream: "/keep/%", limit: 1000 }));
    assert.equal(answer.entry_count, 100, "the five streams of 20 rows");
    assert.equal(answer.streams_total, 2000);
    assert.equal(answer.streams_in_file, 3005);
    assert.equal(answer.streams_not_listed, 1005);
  });
});

test("knowledgec_query lists at most 1,000 tables, always the three it reads, and counts the rest", async () => {
  await withCwd(async (cwd) => {
    const db = await kcDb(cwd, "tables.db", 5);
    const extra = await runPySnippet(`
import sqlite3, sys
con = sqlite3.connect(sys.argv[1])
for i in range(1200):
    con.execute('CREATE TABLE "t%04d" (a INTEGER)' % i)
con.commit()
`, [join(cwd, db)], {});
    assert.equal(extra.code, 0, extra.stderr);
    const answer = ok(await tool(KC, cwd, { db }));
    const tables = answer.schema.tables as string[];
    assert.equal(tables.length, 1000);
    assert.equal(answer.schema.tables_not_listed, 1203 - 1000);
    for (const own of ["ZOBJECT", "ZSTRUCTUREDMETADATA", "ZSOURCE"]) assert.ok(tables.includes(own), own);
    assert.equal(answer.entry_count, 5);
  });
});

test("print_order_until gives print_order's order when it is not stopped, and every item exactly once when the clock has passed", async () => {
  const code = LOAD + `
import time
items = ["b", "a", "c", "ghp_" + "x" * 36, "AKIA" + "Q" * 16] + ["n%03d" % i for i in range(40)]
whole_order, whole = m.print_order_until(items, "path")
print("same", whole_order == m.print_order(items, "path") or sorted(whole_order) == sorted(m.print_order(items, "path")), whole)
stopped, whole2 = m.print_order_until(items, "path", until=time.monotonic() - 1)
print("stopped", whole2, sorted(stopped) == sorted(items), len(stopped) == len(items))
# the withheld names keep one place whatever their bytes (a random order among themselves)
a, _ = m.print_order_until(["a", "b", "ghp_" + "A" * 36, "z"], "path")
b, _ = m.print_order_until(["a", "b", "ghp_" + "z" * 36, "z"], "path")
print("place", [i for i, x in enumerate(a) if x.startswith("ghp_")] == [i for i, x in enumerate(b) if x.startswith("ghp_")])
`;
  for (const t of TOOLS3) {
    const run = await runPySnippet(code, [join(MAC, t, "run.py")], {});
    assert.equal(run.code, 0, run.stderr);
    assert.match(run.stdout, /same True True/, t);
    assert.match(run.stdout, /stopped False True True/, t);
    assert.match(run.stdout, /place True/, t);
  }
});

test("fsevents_parse reads the directory listing under the clock, and names at most 2,000 unread files one by one", async () => {
  await withCwd(async (cwd) => {
    const files: Record<string, Buffer> = {};
    const record = fsRecord("Users/alice/a.txt", 1n, CREATED, 1n);
    for (let i = 0; i < 12; i++) files[`00000000000000${(i + 16).toString(16)}`] = gz(fsPage("2SLD", [record]));
    const dir = await fsDir(cwd, "many", files);
    // the clock has passed before the listing: it says so and does not go on
    const none = body(await tool(FS, cwd, { path: dir, max_seconds: 0.000001 }));
    assert.equal(none.status, "failed");
    assert.match(none.error, /while the directory was being listed/);
    assert.equal(none.names_not_examined, 12);
    // a stop in the middle: the cap on the named files (patched small), the rest counted
    const code = LOAD + `
import io, json
m.NOT_ATTEMPTED_LISTED = 3
real = m.scan_file
calls = [0]
def scan_file(scan, *rest):
    calls[0] += 1
    if calls[0] > 2:
        raise m.TimeUp()
    return real(scan, *rest)
m.scan_file = scan_file
sys.stdin = io.StringIO(json.dumps({"path": sys.argv[2]}))
m.install_stop_handlers()
m.main()
`;
    const run = await snippet(code, [FS, dir], {}, cwd);
    const answer = body({ code: run.code, stdout: run.stdout, stderr: run.stderr });
    assert.equal(answer.files, 12);
    assert.equal(answer.files_by_state.not_attempted, 9);
    assert.equal(answer.files_not_listed, 6, "9 files not attempted, 3 named");
    assert.equal((answer.per_file as Json[]).filter((f) => f.state === "not_attempted").length, 3);
    assert.equal(answer.status, "partial");
    assert.ok((answer.status_basis as string).includes("files_not_listed"));
  });
});

test("unified_log orders the key names of a record under the clock", async () => {
  const code = LOAD + `
import time
keys = ["k%d" % i for i in range(3000)]
t0 = time.monotonic()
out, whole = m.print_order_until(keys, "name", until=time.monotonic() + 30)
print("whole", whole, len(out))
`;
  const run = await runPySnippet(code, [join(MAC, "unified_log", "run.py")], {});
  assert.equal(run.code, 0, run.stderr);
  assert.match(run.stdout, /whole True 3000/);
  const src = await readFile(join(MAC, "unified_log", "run.py"), "utf8");
  assert.doesNotMatch(src, /print_order\(list\(row\)/, "the keys of a record are ordered by print_order_until");
});

// ---- P2-1: a FileVault recovery key is withheld wherever it stands -------------------------------------------------------------------------------------

const vault = (r: () => number): string => Array.from({ length: 6 }, () => rnd(r, 4, "ABCDEFGHJKLMNPQRSTUVWXYZ23456789")).join("-");

test("a FileVault recovery key next to other letters or digits is withheld in a BLOB's head, a value, a table name, a stream and a file name", async () => {
  await withCwd(async (cwd) => {
    const r = prng(91);
    const keys = Array.from({ length: 24 }, () => vault(r));
    const over: Record<string, Record<string, unknown>> = {};
    keys.forEach((k, i) => {
      const glued = [`${k}xyz`, `abc${k}`, `abc${k}xyz`, `${k}\u0000more bytes after the key`][i % 4];
      over[String(i + 1)] = {
        ZX0: { hex: Buffer.concat([Buffer.from(glued), Buffer.alloc(i % 2 ? 5000 : 0, 0x41)]).toString("hex") },
        ZVALUESTRING: `note ${glued} end`,
        ZSTREAMNAME: `/app/${glued}`,
      };
    });
    const db = await kcDb(cwd, "v2.db", keys.length, ["ZX0"], over);
    const run = await tool(KC, cwd, { db, limit: 1000, max_inline_bytes: 20_000_000 });
    const printed = run.stdout;
    assert.equal(keys.filter((k) => printed.includes(k) || printed.includes(Buffer.from(k).toString("hex"))).length, 0, "keys printed by knowledgec_query");
    const tables = await runPySnippet(`
import sqlite3, sys, json
con = sqlite3.connect(sys.argv[1])
for name in json.load(sys.stdin):
    con.execute('CREATE TABLE "%s" (a INTEGER)' % name)
con.commit()
`, [join(cwd, db)], keys.map((k) => `t${k}z`));
    assert.equal(tables.code, 0, tables.stderr);
    const listed = (await tool(KC, cwd, { db })).stdout;
    assert.equal(keys.filter((k) => listed.includes(k)).length, 0, "keys printed as table names");
    const records = keys.map((k, i) => fsRecord(`Users/alice/${[`${k}x.txt`, `x${k}`, k][i % 3]}`, BigInt(i + 1), CREATED, BigInt(i + 1)));
    const dir = await fsDir(cwd, "ev", { "0000000000000001": gz(fsPage("2SLD", records)) });
    const fs = (await tool(FS, cwd, { path: dir, limit: 1000, max_inline_bytes: 20_000_000 })).stdout;
    assert.equal(keys.filter((k) => fs.includes(k)).length, 0, "keys printed by fsevents_parse, file names included");
  });
});

// ---- P2-2: a stop signal during the print ----------------------------------------------------------------------------------------------------------

test("a stop signal that arrives while the answer is being written is found afterwards: the exit code is the signal's and stderr says the answer is whole", async () => {
  const code = LOAD + `
import builtins, os, signal
m.install_stop_handlers()
m.hold_signals()                                     # (as the tool does once the work is done)
real_print = builtins.print
def print_then_signal(*a, **k):
    real_print(*a, **k)
    os.kill(os.getpid(), signal.SIGTERM)             # lands after the text is out, before emit_answer returns
m.print = print_then_signal
got = m.emit_answer({"status": "complete", "status_basis": "every row was read", "n": 1}, None)
real_print("RETURNED=%r" % got, file=sys.stderr)
`;
  for (const t of TOOLS3) {
    const run = await runPySnippet(code, [join(MAC, t, "run.py")], {});
    assert.equal(run.code, 0, run.stderr);
    assert.equal((JSON.parse(run.stdout) as Json).status, "complete", `${t}: the text that was out cannot change`);
    assert.match(run.stderr, /RETURNED=<Signals.SIGTERM: 15>/, t);
    assert.match(run.stderr, /SIGTERM arrived while the answer was being written/, t);
  }
});

// ---- P3 ---------------------------------------------------------------------------------------------------------------------------------------------

test("knowledgec_query: after_z_pk without after_start_raw and numbers SQLite cannot hold are refused with the reason", async () => {
  await withCwd(async (cwd) => {
    const db = await kcDb(cwd, "k.db", 5);
    const alone = body(await tool(KC, cwd, { db, after_z_pk: 2 }));
    assert.equal(alone.status, "failed");
    assert.match(alone.error, /after_z_pk is given without after_start_raw/);
    const hugeStart = body(await toolRaw(KC, cwd, `{"db": ${JSON.stringify(db)}, "after_z_pk": 2, "after_start_raw": 1${"0".repeat(400)}}`));
    assert.equal(hugeStart.status, "failed");
    assert.match(hugeStart.error, /after_start_raw must be a number SQLite can hold/);
    const hugeKey = body(await toolRaw(KC, cwd, `{"db": ${JSON.stringify(db)}, "after_z_pk": 1${"0".repeat(30)}, "after_start_raw": 700000010}`));
    assert.equal(hugeKey.status, "failed");
    assert.match(hugeKey.error, /after_z_pk must be an integer SQLite can hold/);
    const fine = ok(await tool(KC, cwd, { db, after_z_pk: 2, after_start_raw: 700000010 }));
    assert.equal(fine.entry_count, 3, "rows 3, 4 and 5 follow row 2");
    const nothing = ok(await tool(KC, cwd, { db, after_z_pk: 2, after_start_raw: null }));
    assert.equal(nothing.entry_count, 5, "a null start comes first: every row with a start follows it");
  });
});

test("knowledgec_query with a stream pattern writes nothing to stderr, with warnings turned into errors", async () => {
  await withCwd(async (cwd) => {
    const db = await kcDb(cwd, "w.db", 10);
    const run = await tool(KC, cwd, { db, stream: "/app/%" }, { PYTHONWARNINGS: "error" });
    assert.equal(run.code, 0, run.stderr);
    assert.equal(run.stderr, "");
    assert.ok(JSON.parse(run.stdout).entry_count >= 1);
  });
});

test("knowledgec_query tells a dead run's private copy from a live run's by a lock: a live process number does not save a dead run's, a dead one does not lose a live run's", async () => {
  const code = LOAD + `
import os, subprocess, tempfile, time
root = tempfile.mkdtemp(prefix="kc-lock-")
parent = os.path.join(root, "stage")
os.mkdir(parent)
# 1. named for a LIVE process (this one: a reused number), lock file free and old: the run that made it is gone
reused = os.path.join(parent, "knowledgec-%d-reused01" % os.getpid())
os.mkdir(reused)
lock = os.path.join(reused, ".lock")
open(lock, "w").write("")
os.utime(lock, (time.time() - 60, time.time() - 60))
# 2. named for a DEAD number, its lock held by a process of another namespace (here: a child that holds it): live
dead = subprocess.Popen([sys.executable, "-c", "pass"]); dead.wait()
held = os.path.join(parent, "knowledgec-%d-held0001" % dead.pid)
os.mkdir(held)
holder = subprocess.Popen([sys.executable, "-c", "import fcntl, os, sys, time; fd = os.open(sys.argv[1], os.O_WRONLY | os.O_CREAT); fcntl.flock(fd, fcntl.LOCK_EX); print('locked', flush=True); time.sleep(30)", os.path.join(held, ".lock")], stdout=subprocess.PIPE)
holder.stdout.readline()
# 3. an older directory with no lock file: the process number decides (dead: removed; ours: kept)
nolock_dead = os.path.join(parent, "knowledgec-%d-nolock01" % dead.pid)
os.mkdir(nolock_dead)
nolock_live = os.path.join(parent, "knowledgec-%d-nolock02" % os.getpid())
os.mkdir(nolock_live)
m.remove_dead_stages(parent)
holder.kill(); holder.wait()
print("left", sorted(os.listdir(parent)))
# 4. the lock a run takes is released when it ends
stage = os.path.join(root, "own")
os.mkdir(stage)
child = subprocess.Popen([sys.executable, "-c", "import importlib.util, sys, time; s = importlib.util.spec_from_file_location('t', sys.argv[1]); t = importlib.util.module_from_spec(s); s.loader.exec_module(t); fd = t.lock_stage(sys.argv[2]); print('ok' if fd is not None else 'none', flush=True); time.sleep(30)", sys.argv[1], stage], stdout=subprocess.PIPE)
print("child", child.stdout.readline().decode().strip())
class E:  # a directory entry as os.scandir gives it
    def __init__(self, p): self.path, self.name = p, os.path.basename(p)
os.utime(os.path.join(stage, ".lock"), (time.time() - 60, time.time() - 60))
print("live while held", m.stage_is_live(E(stage)))
child.kill(); child.wait()
print("live after death", m.stage_is_live(E(stage)))
`;
  const run = await runPySnippet(code, [join(MAC, "knowledgec_query", "run.py")], {});
  assert.equal(run.code, 0, run.stderr);
  const left = /left (\[.*\])/.exec(run.stdout)?.[1] ?? "";
  assert.ok(!left.includes("reused01"), `a lock that is free removes the copy of a run that is gone, whatever process has its number now: ${left}`);
  assert.ok(left.includes("held0001"), `a lock that is held keeps the copy, whatever the number says: ${left}`);
  assert.ok(!left.includes("nolock01") && left.includes("nolock02"), left);
  assert.match(run.stdout, /child ok/);
  assert.match(run.stdout, /live while held True/);
  assert.match(run.stdout, /live after death False/);
});

test("the three tools carry the same guard block, still, and the boundary block was not touched", async () => {
  const blocks: string[] = [];
  for (const t of TOOLS3) {
    const text = await readFile(join(MAC, t, "run.py"), "utf8");
    blocks.push(text.slice(text.indexOf("# BEGIN SHARED GUARD"), text.indexOf("# END SHARED GUARD")));
  }
  assert.ok(blocks[0].includes("print_order_until") && blocks[0].includes("_VIEW_WORK") && blocks[0].includes("Co") && blocks[0].includes("pending_stop_signal"));
  assert.equal(blocks[1], blocks[0]);
  assert.equal(blocks[2], blocks[0]);
});

test("the manifests and the changelog say what the checks read and what they do not", async () => {
  const text = async (t: string): Promise<string> => (JSON.parse(await readFile(join(MAC, t, "manifest.json"), "utf8")) as { description: string }).description;
  for (const t of TOOLS3) {
    const d = await text(t);
    assert.match(d, /stderr says that the answer on stdout is whole/, t);
    assert.match(d, /next to other letters or digits/, t);
    assert.match(d, /same id is the same alias/, t);
  }
  for (const t of ["fsevents_parse", "knowledgec_query"]) {
    const d = await text(t);
    assert.match(d, /control character/, t);
    assert.match(d, /private-use/, t);
    assert.match(d, /two or more different control characters/, t);
    assert.match(d, /spaced hexadecimal, as percent escapes/, t);
  }
  const kc = await text("knowledgec_query");
  assert.match(kc, /streams_not_listed/);
  assert.match(kc, /tables_not_listed/);
  assert.match(kc, /key inside a column name is not covered/);
  const fsm = await text("fsevents_parse");
  assert.match(fsm, /files_not_listed/);
  assert.match(fsm, /names_not_examined/);
  const log = await readFile(join(MAC, "..", "..", "..", "changelog.d", "claude-pack-macos-forensics-p1-fixes.md"), "utf8");
  for (const word of ["control character", "streams_not_listed", "tables_not_listed", "files_not_listed", "look-around", "lock file", "same id is the same alias", "two or more different control characters"]) {
    assert.ok(log.includes(word), `the changelog says: ${word}`);
  }
});
