/**
 * browser_history, utf16_urls and esedb_query: what they hand back, and what they must not.
 *
 * Fixtures come from the formats and the programs' documented behaviour, never from a tool's own output: SQLite databases are
 * made by SQLite (python's sqlite3 is the fixture writer, and SQLite's own wal_checkpoint is the oracle for what a log holds),
 * a WAL is cut and corrupted by its documented layout (https://www.sqlite.org/fileformat2.html), UTF-16LE text is Buffer's own
 * encoding, and esedbexport is a stand-in that writes the files libesedb's utility writes. Every secret test plants the value in
 * the encodings a tool could print it in and asserts it is in neither the answer nor any file the tool wrote.
 */
import assert from "node:assert/strict";
import { chmod, mkdir, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { withCwd } from "./tool-library-harness.ts";
import { WIN, body, everyFileUnder, exists, failed, py, stub, tool, type Run } from "./windows-pack-harness.ts";
import { readFileSync } from "node:fs";

const root = process.getuid ? process.getuid() === 0 : false;

type Answer = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

const JOB = (cwd: string, n = 1): Record<string, string> => ({ JOB_ID: `j00000${n}`, OUT: join(cwd, "out") });

async function inJob(cwd: string): Promise<Record<string, string>> {
  await mkdir(join(cwd, "out"), { recursive: true });
  return JOB(cwd);
}

/** Every encoding a tool could print `secret` in. */
function encodings(secret: string): string[] {
  const raw = Buffer.from(secret, "latin1");
  return [secret, raw.toString("hex"), raw.toString("base64"), Buffer.from(secret, "utf16le").toString("hex"), secret.slice(0, Math.max(6, secret.length >> 1)), encodeURIComponent(secret)];
}

async function assertAbsent(run: Run, cwd: string, secrets: string[], allowed: (file: string) => boolean = () => false): Promise<void> {
  const answer = (run.stdout + run.stderr).toLowerCase();
  for (const secret of secrets.flatMap(encodings)) assert.equal(answer.includes(secret.toLowerCase()), false, `the answer holds ${secret}`);
  for (const file of await everyFileUnder(cwd)) {
    if (allowed(file) || file.startsWith(join(cwd, "bin") + "/")) continue; // the stand-in program holds its own fixture
    const text = (await readFile(file)).toString("latin1").toLowerCase();
    const textUtf16 = (await readFile(file)).toString("utf16le").toLowerCase();
    for (const secret of secrets.flatMap(encodings)) {
      assert.equal(text.includes(secret.toLowerCase()) || textUtf16.includes(secret.toLowerCase()), false, `${file} holds ${secret}`);
    }
  }
}

const mode = async (path: string): Promise<number> => (await stat(path)).mode & 0o777;

// --- browser_history ------------------------------------------------------------

const HISTORY_PY = [
  "import sqlite3, sys",
  "c = sqlite3.connect(sys.argv[1])",
  "c.executescript('''",
  "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, typed_count INTEGER, last_visit_time INTEGER);",
  "CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER, from_visit INTEGER, transition INTEGER, visit_duration INTEGER);",
  "INSERT INTO urls VALUES (1, 'http://example.test/a', 'A', 2, 1, 13344307300123456);",
  "INSERT INTO visits VALUES (1, 1, 13344307200123456, 0, 805306369, 5000000);",
  "''')",
  "c.commit()",
].join("\n");

const PASSWORD = "Summer2024!hunter2";

const LOGIN_PY = [
  "import sqlite3, sys",
  "c = sqlite3.connect(sys.argv[1])",
  "c.executescript('''",
  "CREATE TABLE logins (origin_url TEXT, username_value TEXT, password_value BLOB, times_used INTEGER, password_type INTEGER);",
  "CREATE TABLE cookies (host_key TEXT, name TEXT, value TEXT, encrypted_value BLOB);",
  "''')",
  "c.execute('INSERT INTO logins VALUES (?,?,?,?,?)', ('https://portal.example.test/', 'alice', sys.argv[2].encode('latin1'), 4, 1))",
  "c.execute('INSERT INTO cookies VALUES (?,?,?,?)', ('.example.test', 'sid', 'COOKIEVALUE-planted-9f8e7d', b'v10-planted-cipher'))",
  "c.commit()",
].join("\n");

test("browser_history reads evidence that is read-only (0444), with its log, and leaves it as it was", async () => {
  // shutil.copy2 copied the mode bits, so the retention UPDATE and the WAL checkpoint failed on the copy with 'attempt to write a
  // readonly database', and the answer called a good database 'not a SQLite database'.
  await withCwd(async (cwd) => {
    py(HISTORY_PY, join(cwd, "work", "History"));
    await chmod(join(cwd, "work", "History"), 0o444);
    const before = await readFile(join(cwd, "work", "History"));
    const visits = body<Answer>(await tool("browser_history", cwd, { path: "work/History", query: "chrome_visits" }));
    assert.equal(visits.row_count, 1);
    assert.deepEqual(await readFile(join(cwd, "work", "History")), before);
    assert.equal(await mode(join(cwd, "work", "History")), 0o444, "the evidence's mode is not touched");

    py(LOGIN_PY, join(cwd, "work", "Login Data"), PASSWORD);
    await chmod(join(cwd, "work", "Login Data"), 0o444);
    const run = await tool("browser_history", cwd, { path: "work/Login Data", sql: "SELECT * FROM logins" });
    const logins = body<Answer>(run);
    assert.equal(logins.rows[0].password_value, `[withheld: ${PASSWORD.length} bytes]`);
    await assertAbsent(run, join(cwd, "work"), [PASSWORD], (f) => f.endsWith("Login Data"));
  });
});

const WAL_PY = (extra = "") => [
  "import os, sqlite3, sys",
  "c = sqlite3.connect(sys.argv[1])",
  extra,
  "c.execute('PRAGMA journal_mode=WAL')",
  "c.execute('PRAGMA wal_autocheckpoint=0')",
  "c.execute('CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INT, typed_count INT, last_visit_time INT)')",
  "c.execute(\"INSERT INTO urls VALUES (1, 'http://example.test/a', 'A', 1, 0, 13350000000000000)\")",
  "c.commit()",
  "c.execute(\"INSERT INTO urls VALUES (2, 'http://203.0.113.24/upload.aspx', 'shell', 9, 1, 13350000060000000)\")",
  "c.commit()",
  "os._exit(0)",
].join("\n");

test("browser_history replays the log of read-only evidence too", async () => {
  await withCwd(async (cwd) => {
    py(WAL_PY(), join(cwd, "work", "History"));
    await chmod(join(cwd, "work", "History"), 0o444);
    await chmod(join(cwd, "work", "History-wal"), 0o444);
    const out = body<Answer>(await tool("browser_history", cwd, { path: "work/History", query: "chrome_url_summary" }));
    assert.ok(out.wal_frames_replayed >= 2);
    assert.deepEqual(out.rows.map((r: Answer) => r.id), [2, 1]);
  });
});

test("browser_history drops every trigger of its copy before it withholds, so a trigger cannot copy a credential to a table nothing withholds", async () => {
  // `AFTER UPDATE OF password_value ... INSERT INTO stash VALUES (old.password_value)` ran when the cell was replaced, and
  // `SELECT hex(...) FROM stash` brought the password back.
  await withCwd(async (cwd) => {
    py([
      "import sqlite3, sys",
      "c = sqlite3.connect(sys.argv[1])",
      "c.executescript('''",
      "CREATE TABLE logins (origin_url TEXT, username_value TEXT, password_value BLOB);",
      "CREATE TABLE stash (taken BLOB);",
      "CREATE TRIGGER keep AFTER UPDATE OF password_value ON logins BEGIN INSERT INTO stash VALUES (old.password_value); END;",
      "''')",
      "c.execute('INSERT INTO logins VALUES (?,?,?)', ('https://portal.example.test/', 'alice', sys.argv[2].encode('latin1')))",
      "c.commit()",
    ].join("\n"), join(cwd, "work", "Login Data"), PASSWORD);
    const run = await tool("browser_history", cwd, { path: "work/Login Data", sql: "SELECT hex(taken) AS h, taken FROM stash; SELECT name FROM sqlite_master WHERE type = 'trigger'" });
    const out = body<Answer>(run);
    assert.deepEqual(out.triggers_dropped, ["keep"]);
    assert.equal(out.results[0].row_count, 0, "nothing was stashed");
    assert.equal(out.results[1].row_count, 0, "the trigger is gone from the copy");
    await assertAbsent(run, join(cwd, "work"), [PASSWORD], (f) => f.endsWith("Login Data"));
  });
});

test("browser_history withholds a card number in autofill, a number or real in a credential column, and the text of a table named for cards", async () => {
  // Web Data's autofill.value is not a credential column by name, and a numeric cell in a credential column was passed.
  await withCwd(async (cwd) => {
    py([
      "import sqlite3, sys",
      "c = sqlite3.connect(sys.argv[1])",
      "c.executescript('''",
      "CREATE TABLE autofill (name TEXT, value TEXT, value_lower TEXT, date_created INTEGER, count INTEGER);",
      "CREATE TABLE credit_cards (guid TEXT, name_on_card TEXT, expiration_month INTEGER, nickname TEXT, use_count INTEGER);",
      "CREATE TABLE cookies (host_key TEXT, name TEXT, value, encrypted_value BLOB);",
      "CREATE TABLE logins (origin_url TEXT, username_value TEXT, password_value, password_type INTEGER, cvv INTEGER);",
      "''')",
      "c.execute(\"INSERT INTO autofill VALUES ('cc-number', '4111 1111 1111 1111', '4111 1111 1111 1111', 1, 1)\")",
      "c.execute(\"INSERT INTO autofill VALUES ('order-ref', '1234567890123456', '1234567890123456', 2, 1)\")",
      "c.execute(\"INSERT INTO autofill VALUES ('email', 'alice@example.test', 'alice@example.test', 3, 1)\")",
      "c.execute(\"INSERT INTO credit_cards VALUES ('g1', 'ALICE EXAMPLE', 12, 'my visa', 3)\")",
      "c.execute(\"INSERT INTO cookies VALUES ('.example.test', 'n', 424242424242, NULL)\")",
      "c.execute(\"INSERT INTO logins VALUES ('https://x.test/', 'alice', 987654321.5, 2, 737)\")",
      "c.commit()",
    ].join("\n"), join(cwd, "work", "Web Data"));
    const run = await tool("browser_history", cwd, {
      path: "work/Web Data",
      sql: "SELECT * FROM autofill ORDER BY date_created; SELECT * FROM credit_cards; SELECT * FROM cookies; SELECT * FROM logins",
    });
    const out = body<Answer>(run);
    const [autofill, cards, cookies, logins] = out.results.map((r: Answer) => r.rows as Answer[]);
    assert.equal(autofill[0].value, "[withheld: 19 characters]", "a card number that passes the Luhn check");
    assert.equal(autofill[0].value_lower, "[withheld: 19 characters]");
    assert.equal(autofill[1].value, "1234567890123456", "sixteen digits that fail the Luhn check are an order number");
    assert.equal(autofill[2].value, "alice@example.test");
    assert.equal(cards[0].name_on_card, "[withheld: 13 characters]");
    assert.equal(cards[0].nickname, "[withheld: 7 characters]");
    assert.equal(cards[0].expiration_month, 12, "what describes the row stays");
    assert.equal(cards[0].use_count, 3);
    assert.equal(cookies[0].value, "[withheld: 12 characters]", "an INTEGER in cookies.value is withheld too");
    assert.equal(logins[0].password_value, "[withheld: 11 characters]", "a REAL in password_value is withheld too");
    assert.equal(logins[0].password_type, 2, "a number that describes the credential is kept");
    assert.equal(logins[0].cvv, "[withheld: 3 characters]");
    const rules = new Set((out.sensitive_columns_withheld as Answer[]).map((w) => `${w.table}.${w.column}:${w.rule}`));
    for (const wanted of ["autofill.value:luhn", "credit_cards.name_on_card:name", "credit_cards.nickname:table", "cookies.value:named", "logins.cvv:name"]) assert.ok(rules.has(wanted), wanted);
    await assertAbsent(run, join(cwd, "work"), ["4111 1111 1111 1111", "4111111111111111", "424242424242", "987654321.5"], (f) => f.endsWith("Web Data"));
  });
});

test("browser_history withholds the secrets of a URL in every cell, and writes them whole only on request, in a job, to a 0600 file", async () => {
  // A token in a query string, a fragment or user-info is a credential, and a URL column is returned as it is stored.
  await withCwd(async (cwd) => {
    const TOKEN = "tk-9f8e7d6c5b4a-planted";
    const USERPW = "Pa55w0rd!planted";
    const FRAGMENT = "frag-planted-3c2b1a";
    py([
      "import sqlite3, sys",
      "c = sqlite3.connect(sys.argv[1])",
      "c.execute('CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER)')",
      "c.execute('INSERT INTO urls VALUES (1, ?, ?, 1)', ('https://api.example.test/cb?access_token=%s&q=cats&page=2' % sys.argv[2], 'ok'))",
      "c.execute('INSERT INTO urls VALUES (2, ?, ?, 1)', ('ftp://admin:%s@files.example.test/pub/' % sys.argv[3], 'ok'))",
      "c.execute('INSERT INTO urls VALUES (3, ?, ?, 1)', ('https://app.example.test/#id_token=%s&state=1' % sys.argv[4], 'ok'))",
      "c.commit()",
    ].join("\n"), join(cwd, "work", "History"), TOKEN, USERPW, FRAGMENT);
    const run = await tool("browser_history", cwd, { path: "work/History", sql: "SELECT id, url FROM urls ORDER BY id" });
    const out = body<Answer>(run);
    assert.equal(out.rows[0].url, `https://api.example.test/cb?access_token=[withheld: ${TOKEN.length} characters]&q=cats&page=2`, "what is not a secret stays");
    assert.equal(out.rows[1].url, `ftp://admin:[withheld: ${USERPW.length} characters]@files.example.test/pub/`, "the user name stays");
    assert.equal(out.rows[2].url, `https://app.example.test/#id_token=[withheld: ${FRAGMENT.length} characters]&state=1`);
    assert.equal(out.url_secrets_withheld.count, 3);
    assert.deepEqual(out.url_secrets_withheld.by_kind, { query_parameter: 1, userinfo_password: 1, fragment_parameter: 1 });
    assert.deepEqual(out.url_secrets_withheld.locators.map((l: Answer) => [l.kind, l.row, l.column, l.length]), [
      ["query_parameter", 1, "url", TOKEN.length], ["userinfo_password", 2, "url", USERPW.length], ["fragment_parameter", 3, "url", FRAGMENT.length],
    ]);
    assert.equal(out.secret_values.requested, false);
    await assertAbsent(run, join(cwd, "work"), [TOKEN, USERPW, FRAGMENT], (f) => f.endsWith("History"));

    // Outside a job the request is refused, and nothing is written.
    const refused = failed(await tool("browser_history", cwd, { path: "work/History", query: "chrome_url_summary", write_url_secrets: true }));
    assert.match(refused.error, /refused outside a job/);

    // In a job the whole text goes to a file of mode 0600 under $OUT, and the answer still holds no secret.
    const env = await inJob(cwd);
    const jobRun = await tool("browser_history", cwd, { path: "work/History", sql: "SELECT id, url FROM urls ORDER BY id", write_url_secrets: true }, env);
    const job = body<Answer>(jobRun);
    assert.equal(job.secret_values.written, 3);
    assert.equal(job.secret_values.contains_secret_values, true);
    const file = join(cwd, "out", "browser_history-url-secrets.jsonl");
    assert.equal(await mode(file), 0o600);
    const rows = (await readFile(file, "utf8")).trim().split("\n").map((l) => JSON.parse(l) as Answer);
    assert.deepEqual(rows.map((r) => r.value), [TOKEN, USERPW, FRAGMENT]);
    assert.equal(rows[0].url.includes(TOKEN), true, "the whole text is in the file");
    await assertAbsent(jobRun, join(cwd, "out"), [TOKEN, USERPW, FRAGMENT], (f) => f === file);
    // A second run in the same job does not replace it.
    const again = failed(await tool("browser_history", cwd, { path: "work/History", query: "chrome_url_summary", write_url_secrets: true }, env));
    assert.match(again.error, /already exists/);
    assert.deepEqual((await readFile(file, "utf8")).trim().split("\n").length, 3);
    // The disposable copy, which held the originals, is gone from $OUT.
    assert.deepEqual((await readdir(join(cwd, "out"))).filter((n) => n.startsWith(".browser-scratch")), []);
  });
});

test("browser_history says whether a file has the SQLite header and how large it is, and never echoes its first bytes", async () => {
  // first_bytes_hex returned 16 bytes of the file: `password=Summer2` came back as hex.
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "History"), Buffer.from("password=Summer2024!".padEnd(4096, " ")));
    const run = await tool("browser_history", cwd, { path: "work/History", query: "tables" });
    const err = failed(run);
    assert.equal(err.sqlite_header, false);
    assert.equal(err.size, 4096);
    assert.equal(run.stdout.includes(Buffer.from("password=Summer2").toString("hex")), false);
    assert.equal(err.first_bytes_hex, undefined);
  });
});

test("browser_history fails as JSON, with the reason, when the evidence or the place for its copy cannot be used", async (t) => {
  if (root) return t.skip("root reads and writes what mode bits forbid");
  await withCwd(async (cwd) => {
    py(HISTORY_PY, join(cwd, "work", "History"));
    await chmod(join(cwd, "work", "History"), 0o000);
    try {
      const unreadable = failed(await tool("browser_history", cwd, { path: "work/History", query: "tables" }));
      assert.match(unreadable.error, /could not be copied/);
      assert.match(String(unreadable.reason), /Permission denied/);
    } finally {
      await chmod(join(cwd, "work", "History"), 0o644);
    }
    await mkdir(join(cwd, "work", "s1"), { recursive: true });
    await chmod(join(cwd, "work", "s1"), 0o555);
    try {
      const nowhere = failed(await tool("browser_history", cwd, { path: "work/History", query: "tables" }));
      assert.match(nowhere.error, /scratch directory/);
    } finally {
      await chmod(join(cwd, "work", "s1"), 0o755);
    }
    // A sidecar that cannot be read stops the run before anything is read.
    await writeFile(join(cwd, "work", "History-journal"), Buffer.alloc(64));
    await chmod(join(cwd, "work", "History-journal"), 0o000);
    try {
      const sidecar = failed(await tool("browser_history", cwd, { path: "work/History", query: "tables" }));
      assert.match(sidecar.error, /sidecar could not be read/);
    } finally {
      await chmod(join(cwd, "work", "History-journal"), 0o644);
    }
  });
});

/** Another database's log beside this one: same page size, written by a database of another encoding or another schema history. */
async function foreignWal(cwd: string, mine: string, theirs: string): Promise<void> {
  await mkdir(join(cwd, "other"), { recursive: true });
  py(theirs, join(cwd, "other", "History"));
  py(mine, join(cwd, "work", "History"));
  await writeFile(join(cwd, "work", "History-wal"), await readFile(join(cwd, "other", "History-wal")));
}

const OWN_PY = (extra: string, more = "") => [
  "import sqlite3, sys",
  "c = sqlite3.connect(sys.argv[1])",
  extra,
  "c.execute('CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INT, typed_count INT, last_visit_time INT)')",
  "c.execute(\"INSERT INTO urls VALUES (1, 'http://mine.test/', 'mine', 1, 0, 13350000000000000)\")",
  more,
  "c.commit()",
].join("\n");

test("browser_history does not apply a log that contradicts its database: another encoding, or an older schema", async () => {
  // A WAL names no database. A log written by another database with the same page size was copied beside this one, applied by
  // SQLite, and its rows returned as this database's history; the docstring said such a log 'yields no frames'.
  await withCwd(async (cwd) => {
    await foreignWal(cwd, OWN_PY("c.execute(\"PRAGMA encoding='UTF-16le'\")"), WAL_PY());
    const run = await tool("browser_history", cwd, { path: "work/History", query: "chrome_url_summary" });
    const out = body<Answer>(run);
    assert.ok(out.wal_refused, JSON.stringify(out.wal_inspection));
    assert.match(out.wal_refused.contradictions[0], /text encoding .* is 1 and the database's is 2/);
    assert.deepEqual(out.sidecars_copied, []);
    assert.equal(out.wal_frames_replayed, 0);
    assert.deepEqual(out.rows.map((r: Answer) => r.url), ["http://mine.test/"], "the database is read as it was acquired");
    assert.doesNotMatch(out.wal_note, /belongs to another database/, "the claim that a foreign log yields no frames is gone");
    assert.equal(out.wal_inspection.header_valid, true);
    assert.equal(out.wal_inspection.checks.page_size.agree, true);
  });
  await withCwd(async (cwd) => {
    // Same encoding, but this database has had three schema changes and the log's last page 1 records one: it only grows.
    await foreignWal(cwd, OWN_PY("", "c.execute('CREATE TABLE a (x)')\nc.execute('CREATE TABLE b (x)')"), WAL_PY());
    const out = body<Answer>(await tool("browser_history", cwd, { path: "work/History", query: "chrome_url_summary" }));
    assert.match(out.wal_refused.contradictions[0], /schema cookie 1, older than the database's 3/);
    assert.deepEqual(out.rows.map((r: Answer) => r.url), ["http://mine.test/"]);
  });
  await withCwd(async (cwd) => {
    // Nothing contradicts: the log is applied, and the answer says that lineage could not be established.
    await foreignWal(cwd, OWN_PY(""), WAL_PY());
    const out = body<Answer>(await tool("browser_history", cwd, { path: "work/History", query: "chrome_url_summary" }));
    assert.equal(out.wal_refused, null);
    assert.match(out.wal_not_established, /cannot be told from this one/);
    assert.deepEqual(out.sidecars_copied, ["History-wal"]);
  });
});

test("browser_history reads the log's own header and frames: its counts agree with SQLite's, and a corrupted frame ends the valid prefix", async () => {
  await withCwd(async (cwd) => {
    py(WAL_PY(), join(cwd, "work", "History"));
    const wal = await readFile(join(cwd, "work", "History-wal"));
    const good = body<Answer>(await tool("browser_history", cwd, { path: "work/History", query: "chrome_url_summary" }));
    const log = good.wal_inspection;
    assert.equal(log.header_valid, true);
    assert.equal(log.header_checksum_ok, true);
    assert.equal(log.format_version, 3007000);
    assert.equal(log.page_size, 4096);
    assert.equal(log.frames_in_file, (wal.length - 32) / (24 + 4096));
    assert.equal(log.frames_valid, log.frames_in_file);
    assert.equal(log.frames_committed, good.wal_checkpoint.log_frames, "the committed prefix is what SQLite counts");
    assert.equal(log.stopped_because, "end of file");

    // Flip a byte in the page data of frame 3: its cumulative checksum fails and the prefix ends before it.
    const hurt = Buffer.from(wal);
    hurt[32 + 2 * (24 + 4096) + 24 + 10] ^= 0xff;
    await writeFile(join(cwd, "work", "History-wal"), hurt);
    const out = body<Answer>(await tool("browser_history", cwd, { path: "work/History", query: "tables" }));
    assert.equal(out.wal_inspection.frames_valid, 2);
    assert.match(out.wal_inspection.stopped_because, /frame 3 fails the cumulative checksum/);
    assert.equal(out.wal_inspection.frames_committed, out.wal_checkpoint.log_frames, "SQLite stops at the same frame");
    // A log whose salts are not the header's: the frames are from another log.
    const salted = Buffer.from(wal);
    salted.writeUInt32BE(0xdeadbeef, 32 + 2 * (24 + 4096) + 8);
    await writeFile(join(cwd, "work", "History-wal"), salted);
    const other = body<Answer>(await tool("browser_history", cwd, { path: "work/History", query: "tables" }));
    assert.match(other.wal_inspection.stopped_because, /frame 3 carries salts that are not the WAL header's/);
  });
});

test("browser_history copies the log but never the wal-index, and refuses a rollback journal of another page size", async () => {
  await withCwd(async (cwd) => {
    py(WAL_PY(), join(cwd, "work", "History"));
    await writeFile(join(cwd, "work", "History-shm"), Buffer.alloc(32768, 0x41));
    const out = body<Answer>(await tool("browser_history", cwd, { path: "work/History", query: "chrome_url_summary" }));
    assert.deepEqual(out.sidecars_copied, ["History-wal"]);
    assert.match(out.sidecars_not_copied[0].why, /wal-index is a derived index/);
    assert.deepEqual(out.rows.map((r: Answer) => r.id), [2, 1], "the log is applied without the index");
  });
  await withCwd(async (cwd) => {
    py(HISTORY_PY, join(cwd, "work", "History"));
    // A rollback journal header: the 8-byte magic, records, nonce, initial size, sector size, page size (here 512, not the database's 4096).
    const header = Buffer.alloc(512);
    Buffer.from("d9d505f920a163d7", "hex").copy(header, 0);
    header.writeUInt32BE(1, 8);
    header.writeUInt32BE(512, 20);
    header.writeUInt32BE(512, 24);
    await writeFile(join(cwd, "work", "History-journal"), header);
    const out = body<Answer>(await tool("browser_history", cwd, { path: "work/History", query: "chrome_url_summary" }));
    assert.match(out.journal_refused.contradictions[0], /journal's page size is 512 and the database's is 4096/);
    assert.deepEqual(out.sidecars_copied, []);
    assert.equal(out.row_count, 1);
  });
});

// --- utf16_urls -----------------------------------------------------------------

const wide = (text: string): Buffer => Buffer.from(text, "utf16le");

test("utf16_urls keeps a UTF-16LE URL whole past a non-ASCII character, and does not read 8-bit text beside it as one", async () => {
  // A character outside printable ASCII ended the run: `https://örnek.test/yol` came back as `https://`.
  await withCwd(async (cwd) => {
    const file = Buffer.concat([
      Buffer.alloc(40, 0xff),
      wide("https://örnek.test/yol/çay?q=ñandú&sayfa=2"),
      Buffer.from([0, 0]),
      Buffer.alloc(20, 0xff),
      wide("Visited: ivan@http://пример.test/путь/a"),
      Buffer.from([0, 0]),
      Buffer.alloc(20, 0xff),
      wide("http://192.168.4.7/admin"),
      Buffer.from("http://other.test/page-one"),
    ]);
    await writeFile(join(cwd, "work", "mem.raw"), file);
    const out = body<Answer>(await tool("utf16_urls", cwd, { path: "work/mem.raw" }));
    const wideOnes = (out.candidates as Answer[]).filter((c) => c.encoding === "utf16le").map((c) => c.text);
    assert.deepEqual(wideOnes, [
      "https://örnek.test/yol/çay?q=ñandú&sayfa=2",
      "Visited: ivan@http://пример.test/путь/a",
      "http://192.168.4.7/admin",
    ]);
    assert.deepEqual((out.candidates as Answer[]).filter((c) => c.encoding === "ascii").map((c) => c.text), ["http://other.test/page-one"]);
  });
});

test("utf16_urls decides each run on its own anchor: a long run without one is not emitted because an earlier run had one", async () => {
  // anchor_ok was set by the first anchored run and never reset, so the continuation pieces of a later run that holds no anchor
  // were returned as candidates.
  await withCwd(async (cwd) => {
    const chunk = 131072;
    const unanchored = wide("x".repeat(100_000));
    const file = Buffer.concat([wide("http://first.test/anchored/run"), Buffer.from([0, 0]), Buffer.alloc(1000, 0xff), unanchored, Buffer.from([0, 0]), Buffer.alloc(chunk, 0xff)]);
    await writeFile(join(cwd, "work", "mem.raw"), file);
    const out = body<Answer>(await tool("utf16_urls", cwd, { path: "work/mem.raw", chunk }));
    assert.deepEqual((out.candidates as Answer[]).map((c) => c.text), ["http://first.test/anchored/run"]);
    assert.equal(out.pieces, 0);
  });
});

test("utf16_urls fails as JSON when the file cannot be read", async (t) => {
  if (root) return t.skip("root reads what mode bits forbid");
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "mem.raw"), Buffer.from("http://example.test/page"));
    await chmod(join(cwd, "work", "mem.raw"), 0o000);
    try {
      const err = failed(await tool("utf16_urls", cwd, { path: "work/mem.raw" }));
      assert.match(err.error, /could not be read/);
      assert.match(String(err.reason), /Permission denied/);
      assert.equal(err.status, "failed");
    } finally {
      await chmod(join(cwd, "work", "mem.raw"), 0o644);
    }
  });
});

test("utf16_urls withholds the secrets of a URL in its candidates and groups, cannot be asked about them through contains, and writes them only on request, in a job", async () => {
  await withCwd(async (cwd) => {
    const TOKEN = "tk-1a2b3c4d5e6f-planted";
    const USERPW = "Pa55w0rd!planted";
    const ascii = `https://api.example.test/cb?access_token=${TOKEN}&page=1`;
    const utf16 = `https://admin:${USERPW}@files.example.test/pub/`;
    const file = Buffer.concat([Buffer.alloc(30, 0xff), Buffer.from(ascii), Buffer.alloc(30, 0xff), wide(utf16), Buffer.from([0, 0]), Buffer.alloc(30, 0xff), Buffer.from(ascii)]);
    await writeFile(join(cwd, "work", "mem.raw"), file);
    const run = await tool("utf16_urls", cwd, { path: "work/mem.raw", limit: 1 });
    const out = body<Answer>(run);
    assert.equal(out.candidates[0].text, `https://api.example.test/cb?access_token=[withheld: ${TOKEN.length} characters]&page=1`);
    assert.equal(out.url_secrets_withheld.count, 3);
    assert.deepEqual(out.url_secrets_withheld.locators_page.matched, 3);
    assert.equal(out.groups.length, 1, "the page is one group long; the rest are in the file");
    await assertAbsent(run, join(cwd, "work"), [TOKEN, USERPW], (f) => f.endsWith("mem.raw"));
    // `contains` is matched against the text as returned: a guess at a withheld value finds nothing.
    const guess = body<Answer>(await tool("utf16_urls", cwd, { path: "work/mem.raw", contains: TOKEN }));
    assert.equal(guess.candidate_count, 0);
    assert.equal(guess.url_secrets_withheld.count, 0, "a candidate that is filtered out is not a finding");
    const refused = failed(await tool("utf16_urls", cwd, { path: "work/mem.raw", write_url_secrets: true }));
    assert.match(refused.error, /refused outside a job/);
    const env = await inJob(cwd);
    const jobRun = await tool("utf16_urls", cwd, { path: "work/mem.raw", write_url_secrets: true }, env);
    const job = body<Answer>(jobRun);
    assert.equal(job.secret_values.written, 3);
    const file2 = join(cwd, "out", "utf16_urls-url-secrets.jsonl");
    assert.equal(await mode(file2), 0o600);
    const rows = (await readFile(file2, "utf8")).trim().split("\n").map((l) => JSON.parse(l) as Answer);
    assert.deepEqual(rows.map((r) => [r.value, r.encoding]), [[TOKEN, "ascii"], [TOKEN, "ascii"], [USERPW, "utf16le"]]);
    await assertAbsent(jobRun, join(cwd, "out"), [TOKEN, USERPW], (f) => f === file2);
  });
});

// --- esedb_query ----------------------------------------------------------------

/** esedbexport as libesedb's utility behaves: `esedbexport -t <root> <db>` writes <root>.export/<table>.<index>, tab separated, and `-V` prints a version. */
const ESEDBEXPORT = (script: string): string => `
if [ "$1" = "-V" ]; then echo "esedbexport 20231020"; exit 0; fi
root="$2"
echo run >> "$COUNT_FILE"
mkdir -p "$root.export"
${script}
`;

const NTDS_HASH = "8846f7eaee8fb117ad06bdd830b7586c";
const NTDS_HISTORY = "e19ccf75ee54e06b06a5907af13cef42";
const SUPPLEMENTAL = "0200000e5e7d3c2b1a";
const KEYLIST = "6bd1aa00c3d9e7f8a1b2c3d4";

test("esedb_query withholds the cells of a credential column and of the datatable attributes of a directory database, and the export is private", async () => {
  // NTDS.dit is an ESE database: its datatable attributes for password hashes, their history, supplemental credentials and the
  // password encryption keys came back as stored, under a manifest that spoke of URLs only. The export directory held every table
  // whole with the exporter's own modes.
  await withCwd(async (cwd, bin) => {
    const table = `DNT_col\\tATTm3\\tATTk589914\\tATTk589879\\tATTk589918\\tATTk589984\\tATTk590689\\tATTk589949\\tPasswordHint\\n1\\talice\\t${NTDS_HASH}\\t${NTDS_HASH}\\t${NTDS_HISTORY}\\t${NTDS_HISTORY}\\t${KEYLIST}\\t${SUPPLEMENTAL}\\tmy dog\\n2\\tbob\\t\\t\\t\\t\\t\\t\\t\\n`;
    await stub(bin, "esedbexport", ESEDBEXPORT(`printf '${table}' > "$root.export/datatable.3"\nchmod 644 "$root.export/datatable.3"\nchmod 755 "$root.export"`));
    await writeFile(join(cwd, "work", "ntds.dit"), "ESE stand-in");
    const env = { COUNT_FILE: join(cwd, "count") };
    const run = await tool("esedb_query", cwd, { path: "work/ntds.dit", table: "datatable" }, env, bin);
    const out = body<Answer>(run);
    assert.equal(out.rows[0].ATTm3, "alice", "what is not a credential is returned");
    assert.equal(out.rows[0].ATTk589914, `[withheld: ${NTDS_HASH.length} characters]`);
    assert.equal(out.rows[0].PasswordHint, "[withheld: 6 characters]", "a column whose name says password");
    assert.equal(out.rows[1].ATTk589914, "", "an empty cell holds nothing to withhold");
    const withheld = Object.fromEntries((out.columns_withheld as Answer[]).map((c) => [c.column, c]));
    assert.deepEqual(Object.keys(withheld).sort(), ["ATTk589879", "ATTk589914", "ATTk589918", "ATTk589949", "ATTk589984", "ATTk590689", "PasswordHint"]);
    assert.equal(withheld.ATTk589914.rule, "directory_credential_attribute");
    assert.equal(withheld.ATTk589914.cells_withheld, 1);
    assert.equal(withheld.ATTk589914.total_length, NTDS_HASH.length);
    assert.equal(withheld.PasswordHint.rule, "name");
    assert.match(out.export_dir_sensitive, /mode 0700/);
    // Nothing the tool wrote outside the export holds a value; the export holds them whole, and is private.
    const exportDir = join(cwd, out.export_dir);
    await assertAbsent(run, cwd, [NTDS_HASH, NTDS_HISTORY, SUPPLEMENTAL, KEYLIST, "my dog"], (f) => f.startsWith(exportDir) || f.endsWith("ntds.dit"));
    assert.equal(await mode(exportDir), 0o700);
    assert.equal(await mode(join(cwd, out.export_dir, "..")), 0o700);
    for (const f of await everyFileUnder(join(cwd, out.export_dir, ".."))) assert.equal(await mode(f), 0o600, f);
    const listing = body<Answer>(await tool("esedb_query", cwd, { path: "work/ntds.dit" }, env, bin));
    assert.equal(listing.export_reused, true, "a private export is still reused");
  });
});

test("esedb_query reuses an export only when its manifest is this version's and its files are the files it lists", async () => {
  // Any manifest with exporter_exit_status 0 was trusted: a truncated table, a missing file or a manifest of another version still
  // answered export_reused: true.
  async function first(cwd: string, bin: string): Promise<{ env: Record<string, string>; dir: string; manifest: string }> {
    await stub(bin, "esedbexport", ESEDBEXPORT(`printf 'Id\\tName\\n1\\ta\\n' > "$root.export/T.0"\nprintf 'Id\\tName\\n2\\tb\\n' > "$root.export/U.1"`));
    await writeFile(join(cwd, "work", "SRUDB.dat"), "ESE stand-in");
    const env = { COUNT_FILE: join(cwd, "count") };
    const one = body<Answer>(await tool("esedb_query", cwd, { path: "work/SRUDB.dat" }, env, bin));
    assert.equal(one.export_reused, false);
    const dir = join(cwd, "work", "s1", "esedb-export", (one.db_sha256 as string).slice(0, 16));
    return { env, dir, manifest: join(dir, "export-manifest.json") };
  }
  const exportedAgain = async (cwd: string, bin: string, env: Record<string, string>): Promise<boolean> =>
    !body<Answer>(await tool("esedb_query", cwd, { path: "work/SRUDB.dat" }, env, bin)).export_reused;

  await withCwd(async (cwd, bin) => {
    const { env } = await first(cwd, bin);
    assert.equal(await exportedAgain(cwd, bin, env), false, "an intact export is reused");
  });
  await withCwd(async (cwd, bin) => {
    const { env, dir } = await first(cwd, bin);
    await writeFile(join(dir, "db.export", "T.0"), "Id\tName\n"); // truncated
    assert.equal(await exportedAgain(cwd, bin, env), true, "a table file that is not the size it was recorded at");
    assert.equal(await readFile(join(dir, "db.export", "T.0"), "utf8"), "Id\tName\n1\ta\n", "the export was made again");
  });
  await withCwd(async (cwd, bin) => {
    const { env, dir } = await first(cwd, bin);
    await rm(join(dir, "db.export", "U.1"));
    assert.equal(await exportedAgain(cwd, bin, env), true, "a listed table file that is missing");
  });
  await withCwd(async (cwd, bin) => {
    const { env, dir } = await first(cwd, bin);
    await writeFile(join(dir, "db.export", "Extra.9"), "Id\n7\n");
    assert.equal(await exportedAgain(cwd, bin, env), true, "a file the manifest does not list");
  });
  await withCwd(async (cwd, bin) => {
    const { env, manifest } = await first(cwd, bin);
    const record = JSON.parse(await readFile(manifest, "utf8")) as Answer;
    record.parser = "esedb_query/4";
    await writeFile(manifest, JSON.stringify(record));
    assert.equal(await exportedAgain(cwd, bin, env), true, "a manifest written by another version of the tool");
  });
  await withCwd(async (cwd, bin) => {
    const { env, manifest } = await first(cwd, bin);
    await writeFile(manifest, "{ not json");
    assert.equal(await exportedAgain(cwd, bin, env), true, "an unreadable manifest");
  });
});

test("esedb_query withholds the secrets of a URL in a cell, and writes them only on request, in a job", async () => {
  await withCwd(async (cwd, bin) => {
    const TOKEN = "tk-7e6d5c4b3a29-planted";
    const USERPW = "Pa55w0rd!planted";
    const cells = [`Visited: alice@https://app.example.test/cb?access_token=${TOKEN}&x=1`, `ftp://admin:${USERPW}@files.example.test/`, "https://plain.example.test/page"];
    const lines = cells.map((u, i) => `${i + 1}\\t${u.replace(/%/g, "%%")}`).join("\\n");
    await stub(bin, "esedbexport", ESEDBEXPORT(`printf 'EntryId\\tUrl\\n${lines}\\n' > "$root.export/Container_1.4"`));
    await writeFile(join(cwd, "work", "WebCacheV01.dat"), "ESE stand-in");
    const env = { COUNT_FILE: join(cwd, "count") };
    const run = await tool("esedb_query", cwd, { path: "work/WebCacheV01.dat", table: "Container_1" }, env, bin);
    const out = body<Answer>(run);
    assert.equal(out.rows[0].Url, `Visited: alice@https://app.example.test/cb?access_token=[withheld: ${TOKEN.length} characters]&x=1`);
    assert.equal(out.rows[1].Url, `ftp://admin:[withheld: ${USERPW.length} characters]@files.example.test/`);
    assert.equal(out.rows[2].Url, "https://plain.example.test/page");
    assert.equal(out.url_secrets_withheld.count, 2);
    assert.deepEqual(out.url_secrets_withheld.locators.map((l: Answer) => [l.table, l.row, l.column]), [["Container_1", 1, "Url"], ["Container_1", 2, "Url"]]);
    await assertAbsent(run, cwd, [TOKEN, USERPW], (f) => f.includes("esedb-export") || f.endsWith("WebCacheV01.dat"));
    const refused = failed(await tool("esedb_query", cwd, { path: "work/WebCacheV01.dat", table: "Container_1", write_url_secrets: true }, env, bin));
    assert.match(refused.error, /refused outside a job/);
    const jobEnv = { ...env, ...(await inJob(cwd)) };
    const jobRun = await tool("esedb_query", cwd, { path: "work/WebCacheV01.dat", table: "Container_1", write_url_secrets: true }, jobEnv, bin);
    const job = body<Answer>(jobRun);
    assert.equal(job.secret_values.written, 2);
    const file = join(cwd, "out", "esedb_query-url-secrets.jsonl");
    assert.equal(await mode(file), 0o600);
    assert.deepEqual((await readFile(file, "utf8")).trim().split("\n").map((l) => (JSON.parse(l) as Answer).value), [TOKEN, USERPW]);
    await assertAbsent(jobRun, join(cwd, "out"), [TOKEN, USERPW], (f) => f === file || f.includes("esedb-export"));
  });
});

test("esedb_query fails as JSON when its export directory cannot be made, or the database cannot be read", async (t) => {
  if (root) return t.skip("root writes what mode bits forbid");
  await withCwd(async (cwd, bin) => {
    await stub(bin, "esedbexport", ESEDBEXPORT(`printf 'Id\\n1\\n' > "$root.export/T.0"`));
    await writeFile(join(cwd, "work", "SRUDB.dat"), "ESE stand-in");
    const env = { COUNT_FILE: join(cwd, "count") };
    await mkdir(join(cwd, "work", "s1"), { recursive: true });
    await chmod(join(cwd, "work", "s1"), 0o555);
    try {
      const err = failed(await tool("esedb_query", cwd, { path: "work/SRUDB.dat" }, env, bin));
      assert.match(err.error, /export could not be made/);
      assert.equal(err.status, "failed");
      assert.match(String(err.reason), /Permission denied|Read-only/);
    } finally {
      await chmod(join(cwd, "work", "s1"), 0o755);
    }
    await chmod(join(cwd, "work", "SRUDB.dat"), 0o000);
    try {
      const unreadable = failed(await tool("esedb_query", cwd, { path: "work/SRUDB.dat" }, env, bin));
      assert.match(unreadable.error, /could not be read/);
    } finally {
      await chmod(join(cwd, "work", "SRUDB.dat"), 0o644);
    }
  });
});

// --- the URL block ---------------------------------------------------------------

test("browser_history, utf16_urls and esedb_query carry one URL-secrets design, held identical", async () => {
  // The tools are standalone, so the design is a copy; this holds the three copies identical.
  const begin = "# ---- URL secrets: one design in browser_history, utf16_urls and esedb_query";
  const end = "# ---- end of URL secrets";
  const blocks = ["browser_history", "utf16_urls", "esedb_query"].map((name) => {
    const text = readFileSync(join(WIN, name, "run.py"), "utf8");
    return text.slice(text.indexOf(begin), text.indexOf(end) + end.length);
  });
  assert.ok(blocks[0].length > 3000, "the block was found");
  assert.ok(blocks[0] === blocks[1] && blocks[1] === blocks[2], "the URL-secrets block differs between the three tools");
  assert.equal(await exists(join(WIN, "browser_history", "run.py")), true);
});
