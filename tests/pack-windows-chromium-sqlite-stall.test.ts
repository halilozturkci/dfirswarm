/**
 * chromium_logins against a Login Data whose b-trees are damaged so that SQLite walks them without end: the clock and a stop must still reach it.
 *
 * A b-tree whose interior pages all point at the same child (a DAG, not a tree) makes a walk visit the one leaf hundreds of billions of times. The
 * fixtures are built here from the file format (an interior table page is type 0x05, its cells a 4-byte child page and a row-id varint, its right
 * pointer at byte 8 of the page header), never from the tool's own reading. Two shapes:
 *
 * - the logins table's b-tree: a `SELECT count(*)` was one step of SQLite (OP_Count) that walked it in C, with no progress callback and no
 *   Python signal handler able to run, so the tool ran past the manifest's timeout and a SIGTERM got no answer. The rows are now counted as they
 *   are read, and a row id that is not above the one before ends the read (a page reached twice gives its rows again).
 * - sqlite_master's b-tree: the schema load walks it, so the first statement the tool prepares does not return. A copy of the tool with its
 *   progress handler taken out shows that the watchdog thread alone ends it, at the clock and at a stop signal.
 */
import assert from "node:assert/strict";
import { createCipheriv, randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { withCwd } from "./tool-library-harness.ts";
import { py } from "./windows-pack-harness.ts";
import { assertJsonAnswer, runTool, startTool, withDeadline } from "./windows-tool-contract.ts";

type Answer = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any
const TOOL = "chromium_logins";
const PROGRESS_LINE = "conn.set_progress_handler(lambda: 1 if out_of_time() else 0, 2000)";

function v10(key: Buffer, clear: string): Buffer {
  const nonce = randomBytes(12);
  const c = createCipheriv("aes-256-gcm", key, nonce);
  const body = Buffer.concat([c.update(Buffer.from(clear, "utf8")), c.final()]);
  return Buffer.concat([Buffer.from("v10", "latin1"), nonce, body, c.getAuthTag()]);
}

/**
 * A Login Data with one login, then rewritten so that the b-tree of `which` ("logins" or "sqlite_master") is a chain of `depth` interior pages
 * whose every cell points at the next one, the last at a leaf that holds the original rows.
 */
function dagLoginData(path: string, which: "logins" | "sqlite_master", value: Buffer, depth = 4): void {
  py(
    [
      "import os, sqlite3, struct, sys",
      "path, which, value, depth = sys.argv[1], sys.argv[2], bytes.fromhex(sys.argv[3]), int(sys.argv[4])",
      "os.path.exists(path) and os.remove(path)",
      "c = sqlite3.connect(path); c.execute('PRAGMA page_size=4096'); c.execute('PRAGMA journal_mode=DELETE')",
      "c.execute('CREATE TABLE logins (origin_url VARCHAR NOT NULL, action_url VARCHAR, username_value VARCHAR, password_value BLOB, signon_realm VARCHAR, date_created INTEGER)')",
      "c.execute('INSERT INTO logins VALUES (?,?,?,?,?,?)', ('https://x.example/', '', 'u', value, 'https://x.example/', 13300000000000000))",
      "c.commit()",
      "root = 1 if which == 'sqlite_master' else c.execute(\"SELECT rootpage FROM sqlite_master WHERE name = 'logins'\").fetchone()[0]",
      "c.close()",
      "PS = 4096",
      "data = bytearray(open(path, 'rb').read())",
      "n = len(data) // PS",
      "base = 100 if root == 1 else 0                                  # page 1 holds the 100-byte file header before its b-tree header",
      "old = bytes(data[(root - 1) * PS: root * PS])",
      "assert old[base] == 0x0D, 'the root is a table leaf'",
      "leaf = bytearray(PS)",
      "cells = struct.unpack_from('>H', old, base + 3)[0]",
      "start = struct.unpack_from('>H', old, base + 5)[0]",
      "leaf[start:] = old[start:]                                      # the cell content keeps its offsets",
      "leaf[0:8] = old[base:base + 8]",
      "leaf[8:8 + 2 * cells] = old[base + 8:base + 8 + 2 * cells]",
      "chain = [root] + [n + i for i in range(1, depth)]",
      "leaf_page = n + depth",
      "data += bytes(PS * depth)",
      "for i, page_no in enumerate(chain):",
      "    child = chain[i + 1] if i + 1 < len(chain) else leaf_page",
      "    b = 100 if page_no == 1 else 0",
      "    page = bytearray(PS)",
      "    if page_no == 1: page[:100] = data[:100]",
      "    fan = (PS - b - 12) // 7",
      "    content = PS",
      "    for k in range(fan):",
      "        cell = struct.pack('>I', child) + bytes([1 + k % 100])",
      "        content -= len(cell)",
      "        page[content:content + len(cell)] = cell",
      "        struct.pack_into('>H', page, b + 12 + 2 * k, content)",
      "    page[b] = 0x05",
      "    struct.pack_into('>HHHB', page, b + 1, 0, fan, content, 0)",
      "    struct.pack_into('>I', page, b + 8, child)",
      "    data[(page_no - 1) * PS: page_no * PS] = page",
      "data[(leaf_page - 1) * PS: leaf_page * PS] = leaf",
      "struct.pack_into('>I', data, 28, leaf_page)                    # the database's size in pages",
      "struct.pack_into('>I', data, 92, struct.unpack_from('>I', data, 24)[0])   # version-valid-for = change counter, so the size is believed",
      "open(path, 'wb').write(data)",
    ].join("\n"),
    path,
    which,
    value.toString("hex"),
    String(depth),
  );
}

let jobs = 0;
function secretJob(cwd: string): Record<string, string> {
  const id = `j${String(++jobs).padStart(6, "0")}`;
  const out = join(cwd, "store", "jobs", id, "out");
  mkdirSync(out, { recursive: true });
  return { JOB_ID: id, OUT: out, SECRET_OUTPUT: "1" };
}

/** A copy of the tool with its deadline set and, with `noProgress`, its progress handler taken out: only the watchdog can end a stalled step. */
function copyOfTool(seconds: number, noProgress: boolean): string {
  const copy = withDeadline(TOOL, seconds);
  if (noProgress) {
    const text = readFileSync(copy, "utf8");
    assert.equal(text.split(PROGRESS_LINE).length, 2, "the progress handler is installed in one place");
    writeFileSync(copy, text.replace(PROGRESS_LINE, "pass"));
  }
  return copy;
}

function fixture(cwd: string, which: "logins" | "sqlite_master"): { args: Record<string, string>; key: Buffer } {
  const key = randomBytes(32);
  mkdirSync(join(cwd, "work", which), { recursive: true });
  writeFileSync(join(cwd, "work", which, "key"), key);
  dagLoginData(join(cwd, "work", which, "Login Data"), which, v10(key, "a-password-in-the-damaged-file"));
  return { args: { login_data: `work/${which}/Login Data`, key_file: `work/${which}/key` }, key };
}

test("a logins b-tree whose pages are reached many times is read once: the read stops at the first row id that is not above the one before, partial, within seconds", async () => {
  await withCwd(async (cwd) => {
    const { args } = fixture(cwd, "logins");
    const env = secretJob(cwd);
    const began = Date.now();
    const run = await runTool(TOOL, cwd, args, env);
    const seconds = (Date.now() - began) / 1000;
    const out = assertJsonAnswer(run, "the DAG Login Data") as Answer;
    assert.ok(seconds < 30, `answered in ${seconds} s, inside the manifest's 60 s and well before the tool's own 45 s clock`);
    assert.equal(out.status, "partial", out.status_basis);
    assert.equal(out.parser, "chromium_logins/5");
    assert.match(out.status_basis, /the logins table gave a row id that is not above the one before it, after row 1: .* the read stopped there, with no row given twice/);
    assert.deepEqual([out.rows_read, out.rows_in_table, out.every_row_read, out.decrypted], [1, null, false, 1]);
    const values = readFileSync(join(env.OUT, "chromium_logins-values.jsonl"), "utf8").split("\n").filter(Boolean);
    assert.equal(values.length, 1, "the one login, written once");
  });
});

test("an sqlite_master b-tree whose schema load does not end: the clock ends it and says it was the clock, with the progress handler and without it", async () => {
  await withCwd(async (cwd) => {
    const { args } = fixture(cwd, "sqlite_master");
    for (const noProgress of [false, true]) {
      const began = Date.now();
      const run = await runTool(copyOfTool(3, noProgress), cwd, args, secretJob(cwd));
      const seconds = (Date.now() - began) / 1000;
      const out = assertJsonAnswer(run, `the DAG schema, progress handler ${noProgress ? "out" : "in"}`) as Answer;
      assert.ok(seconds < 15, `answered ${seconds} s after the start with a 3 s clock (progress handler ${noProgress ? "out" : "in"})`);
      assert.equal(out.status, "failed", out.status_basis);
      assert.match(out.error, /^the schema could not be read: the tool's own clock \(3 s\) ran out while SQLite read it, and no row was read/);
      assert.deepEqual([out.rows_read, out.every_row_read], [0, false]);
    }
  });
});

test("a SIGTERM while SQLite is in the endless schema load is answered at once with one JSON document, by the watchdog when no progress callback runs", async () => {
  await withCwd(async (cwd) => {
    const { args } = fixture(cwd, "sqlite_master");
    for (const noProgress of [false, true]) {
      const env = secretJob(cwd);
      const run = startTool(copyOfTool(45, noProgress), cwd, args, env);
      // The values file is made just before the database is opened: from a moment after it, the tool is inside the schema load, which the
      // 45 s clock would end only long after the signal.
      const values = join(env.OUT, "chromium_logins-values.jsonl");
      const waitUntil = Date.now() + 20_000;
      while (!existsSync(values) && Date.now() < waitUntil && run.child.exitCode === null) await new Promise((r) => setTimeout(r, 50));
      assert.ok(existsSync(values), "the tool reached the database");
      await new Promise((r) => setTimeout(r, 1500));
      assert.equal(run.child.exitCode, null, "the tool is still in the schema load");
      const sent = Date.now();
      run.child.kill("SIGTERM");
      const exit = await run.closed;
      const seconds = (Date.now() - sent) / 1000;
      assert.ok(seconds < 5, `answered ${seconds} s after the signal (progress handler ${noProgress ? "out" : "in"})`);
      assert.equal(exit.signal, null, "ended by its own handler, not by the signal");
      assert.equal(exit.code, 128 + 15);
      assert.doesNotMatch(run.stderr(), /Traceback/);
      const out = JSON.parse(run.stdout()) as Answer;
      assert.deepEqual([out.status, out.interrupted, out.signal, out.stopped], ["failed", true, 15, "while the logins were read"]);
    }
  });
});
