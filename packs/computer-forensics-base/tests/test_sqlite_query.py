"""sqlite_query: the WAL is said, not silently dropped; reading is all a statement may do; the answer is bounded and typed.

Databases are made with Python's sqlite3 module (the engine itself, not the tool's
output), the WAL's expected frame count is worked out from the file's size and the
documented frame layout, and the BLOB's digest from hashlib.
"""
import base64
import collections
import hashlib
import json
import os
import sqlite3
import stat
import subprocess
import sys
import unittest

from support import Case, run_tool, tool_path


class SqliteQuery(Case):
    def db(self, name="a.db", script="create table a(x); insert into a values(1),(2),(3);"):
        path = self.path(name)
        conn = sqlite3.connect(path)
        conn.executescript(script)
        conn.commit()
        conn.close()
        return path

    def query(self, db, sql, **kw):
        return run_tool("sqlite_query", dict({"db_path": db, "sql": sql}, **kw), self.dir)

    def test_rows_in_the_wal_are_flagged_as_not_applied(self):
        path = self.path("w.db")
        writer = sqlite3.connect(path)
        writer.execute("pragma journal_mode=wal")
        writer.execute("pragma wal_autocheckpoint=0")
        writer.execute("create table a(x)")
        writer.execute("insert into a values(1)")
        writer.commit()
        writer.execute("pragma wal_checkpoint(truncate)")      # row 1 is now in the main file
        writer.execute("insert into a values(2)")               # row 2 is committed, in the WAL only
        writer.commit()
        try:
            wal = path + "-wal"
            self.assertTrue(os.path.getsize(wal) > 32)
            page = sqlite3.connect(path).execute("pragma page_size").fetchone()[0]
            expected_frames = (os.path.getsize(wal) - 32) // (24 + page)      # the documented WAL layout
            r = self.query(path, "select x from a order by x")
        finally:
            writer.close()
        self.assertEqual(r.code, 0, r.stdout)
        self.assertEqual([row["values"][0] for row in r.json["rows"]], [1])        # the WAL's row is not in the result ...
        wal_entry = [s for s in r.json["sidecars"] if s["name"].endswith("-wal")][0]
        self.assertTrue(wal_entry["present"])
        self.assertEqual(wal_entry["frames_valid"], expected_frames)               # ... and the tool says there are frames
        self.assertGreater(wal_entry["frames_committed"], 0)
        self.assertIn("WAL NOT APPLIED", r.json["snapshot_status"])

    def test_a_database_with_no_sidecar_says_so(self):
        r = self.query(self.db(), "select count(*) from a")
        self.assertIn("no WAL frames", r.json["snapshot_status"])

    def test_nothing_that_writes_runs(self):
        db = self.db()
        before = self.read(db, "rb")
        other = self.path("other.db")
        for sql in ("delete from a", "insert into a values(9)", "update a set x=0", "drop table a", "create table b(y)",
                    "attach database '%s' as o" % other, "pragma journal_mode=delete", "pragma user_version=5",
                    "vacuum", "vacuum into '%s'" % other, "select load_extension('nothing')",
                    "with c as (select 1) delete from a", "select 1; delete from a"):
            r = self.query(db, sql)
            self.assertEqual(r.code, 1, sql)
            self.assertIs(r.json["ok"], False, sql)
            self.assertIn("refused", r.json["error"], sql)
        self.assertEqual(self.read(db, "rb"), before)
        self.assertFalse(os.path.exists(other))
        # readonly=false is refused outright, not honoured.
        r = self.query(db, "select 1", readonly=False)
        self.assertEqual(r.code, 1)
        self.assertIn("never opens a database for writing", r.json["error"])
        # What only reports is allowed.
        self.assertEqual(self.query(db, "pragma table_info(a)").json["rows"][0]["values"][1], "x")
        self.assertEqual(self.query(db, "pragma user_version").code, 0)
        self.assertEqual(self.query(db, "with c(n) as (select 1 union all select n+1 from c where n<3) select n from c").json["row_count"], 3)

    def test_a_large_result_has_a_bounded_inline_page_and_a_complete_file(self):
        db = self.db("big.db", "create table t(n integer, s text); " +
                     "with c(n) as (select 1 union all select n+1 from c where n<20000) insert into t select n, 'row ' || n from c;")
        r = self.query(db, "select n, s from t order by n")
        self.assertEqual(r.json["row_count"], 20000)
        self.assertEqual(r.json["returned"], 100)
        self.assertTrue(r.json["truncated"])
        lines = self.read(r.json["rows_file"]).splitlines()
        self.assertEqual(json.loads(lines[0])["columns"], ["n", "s"])
        self.assertEqual(len(lines), 20001)
        self.assertEqual(json.loads(lines[-1]), {"n": 20000, "values": [20000, "row 20000"]})
        # The inline page also stops at a byte ceiling, whatever limit says.
        wide = self.db("wide.db", "create table t(s text); with c(n) as (select 1 union all select n+1 from c where n<400) insert into t select hex(zeroblob(2000)) from c;")
        r = self.query(wide, "select s from t", limit=400)
        self.assertLess(r.json["returned"], 400)
        self.assertEqual(r.json["row_count"], 400)
        self.assertEqual(len(self.read(r.json["rows_file"]).splitlines()), 401)
        self.assertLess(len(r.stdout), 200 * 1024)

    def test_cells_are_typed(self):
        db = self.db("c.db", "create table t(a, b, c, d); insert into t values(NULL, 1.5, 'x', x'0001ff');")
        row = self.query(db, "select a, b, c, d from t").json["rows"][0]["values"]
        blob = b"\x00\x01\xff"
        self.assertEqual(row, [None, 1.5, "x", {"blob_b64": base64.b64encode(blob).decode(), "length": 3, "sha256": hashlib.sha256(blob).hexdigest()}])

    def test_a_long_blob_is_whole_in_the_file_and_headed_inline(self):
        blob = bytes(range(256)) * 8
        db = self.path("b.db")
        conn = sqlite3.connect(db)
        conn.execute("create table t(d)")
        for _ in range(3):
            conn.execute("insert into t values(?)", (blob,))
        conn.commit()
        conn.close()
        r = self.query(db, "select d from t", limit=1)
        inline = r.json["rows"][0]["values"][0]
        self.assertEqual(inline["length"], 2048)
        self.assertEqual(inline["sha256"], hashlib.sha256(blob).hexdigest())
        self.assertIn("blob_b64_head", inline)
        line = json.loads(self.read(r.json["rows_file"]).splitlines()[1])
        self.assertEqual(base64.b64decode(line["values"][0]["blob_b64"]), blob)

    def test_several_statements_run_one_by_one(self):
        r = self.query(self.db(), "select count(*) from a; select 'a;b';")
        self.assertEqual([x["rows"][0]["values"][0] for x in r.json["results"]], [3, "a;b"])

    def test_high_entropy_is_not_called_encryption(self):
        junk = self.write("events.db", os.urandom(8192))
        r = self.query(junk, "select 1")
        self.assertEqual(r.code, 1)
        self.assertGreater(r.json["first_page_entropy_bits_per_byte"], 7.5)
        reading = r.json["reading"]
        self.assertIn("not identified", reading)
        self.assertIn("one explanation", reading)
        self.assertNotIn("an encrypted database (SQLCipher or an app's own); no query runs without its key", reading)

    def test_a_query_stopped_by_its_time_budget_says_so_and_keeps_what_it_had(self):
        db = self.db()
        r = self.query(db, "with recursive c(n) as (select 1 union all select n+1 from c) select count(*) from c", max_seconds=1)
        self.assertEqual(r.code, 1)
        self.assertIs(r.json["ok"], False)
        self.assertIs(r.json["timed_out"], True)
        self.assertIs(r.json["complete"], False)
        # Rows that were being returned when the clock ran out are kept, in a file that is whole, and named.
        r = self.query(db, "with recursive c(n) as (select 1 union all select n+1 from c) select n from c", max_seconds=1, limit=5)
        self.assertIs(r.json["timed_out"], True)
        kept = r.json["rows_read_before_the_stop"]
        self.assertGreater(kept["row_count"], 5)
        lines = self.read(kept["rows_file"]).splitlines()
        self.assertEqual(len(lines), kept["row_count"] + 1)
        self.assertEqual(json.loads(lines[-1]), {"n": kept["row_count"], "values": [kept["row_count"]]})
        self.assertEqual([x["values"][0] for x in kept["rows"]], [1, 2, 3, 4, 5])
        self.assertFalse([n for n in os.listdir(os.path.dirname(self.path(kept["rows_file"]))) if n.startswith(".sqlite_query-")], "no half-written file is left")

    def test_the_last_statement_needs_no_semicolon_and_is_never_dropped(self):
        db = self.db()
        r = self.query(db, "select count(*) from a -- how many")
        self.assertEqual((r.code, r.json["rows"][0]["values"][0]), (0, 3))
        r = self.query(db, "select 1; select 2 /* the end */")
        self.assertEqual([x["rows"][0]["values"][0] for x in r.json["results"]], [1, 2])
        r = self.query(db, "select 1; select 'never closed")
        self.assertEqual(r.code, 1)
        self.assertIs(r.json["ok"], False)
        self.assertIn("error", r.json)
        self.assertEqual([x["rows"][0]["values"][0] for x in r.json["completed_statements"]], [1])

    def test_values_that_are_not_what_they_say_are_refused_not_tracebacks(self):
        db = self.db()
        for bad in ({"sql": "select 1\u0000"}, {"sql": "select '\ud800'"}, {"csv": "false"}, {"csv": 1}, {"readonly": "no"}, {"readonly": 0}):
            args = dict({"db_path": db, "sql": "select 1"}, **bad)
            r = run_tool("sqlite_query", args, self.dir)
            self.assertEqual(r.code, 1, bad)
            self.assertNotIn("Traceback", r.stderr, bad)
            self.assertIs(r.json["ok"], False, bad)
        self.assertEqual(self.query(db, "select 1", readonly=True, csv=False).code, 0)
        r = self.query(db, "select 1 " + " " * (64 * 1024))
        self.assertEqual(r.code, 1)
        self.assertIn("longer than 65536 bytes", r.json["error"])

    def test_a_result_of_large_blobs_is_read_a_row_at_a_time(self):
        db = self.path("big.db")
        conn = sqlite3.connect(db)
        conn.execute("create table t(d)")
        for _ in range(12):
            conn.execute("insert into t values(zeroblob(?))", (8 * 1024 * 1024,))
        conn.commit()
        conn.close()
        wrapper = ("import json, resource, subprocess, sys\n"
                   "p = subprocess.run([sys.executable, sys.argv[1]], input=sys.argv[2], capture_output=True, text=True)\n"
                   "print(json.dumps({'out': p.stdout, 'peak': resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss}))\n")
        env = {k: v for k, v in os.environ.items() if k not in ("JOB_ID", "OUT", "AGENT_ID", "SECRET_OUTPUT")}
        proc = subprocess.run([sys.executable, "-c", wrapper, tool_path("sqlite_query"), json.dumps({"db_path": db, "sql": "select d from t", "limit": 12})],
                              capture_output=True, text=True, cwd=self.dir, env=env)
        got = json.loads(proc.stdout)
        result = json.loads(got["out"])
        self.assertEqual((result["ok"], result["row_count"]), (True, 12))
        lines = self.read(result["rows_file"]).splitlines()
        self.assertEqual(len(lines), 13)
        first = json.loads(lines[1])["values"][0]
        self.assertEqual((first["length"], first["sha256"]), (8 * 1024 * 1024, hashlib.sha256(bytes(8 * 1024 * 1024)).hexdigest()))
        peak = got["peak"] * (1 if sys.platform == "darwin" else 1024)
        self.assertLess(peak, 140 * 1024 * 1024, "the peak was %d bytes for 96 MiB of blobs" % peak)

    def test_a_journal_that_is_not_hot_is_not_called_one_and_a_link_finds_its_targets_sidecars(self):
        db = self.db()
        self.write("a.db-journal", b"\0" * 512)
        r = self.query(db, "select 1")
        journal = [s for s in r.json["sidecars"] if s["name"].endswith("-journal")][0]
        self.assertIn("not a hot journal", journal["state"])
        self.assertNotIn("not been rolled back", r.json["snapshot_status"])
        self.assertNotIn("interrupted write", r.json["snapshot_status"])
        self.write("a.db-journal", bytes([0xd9, 0xd5, 0x05, 0xf9, 0x20, 0xa1, 0x63, 0xd7]) + b"\0" * 504)
        r = self.query(db, "select 1")
        self.assertIn("interrupted write", r.json["snapshot_status"])
        # A link to the database: the files beside the file it points at are the ones SQLite looks for.
        os.symlink(db, self.path("link.db"))
        r = self.query(self.path("link.db"), "select 1")
        self.assertTrue([s for s in r.json["sidecars"] if s["name"] == "a.db-journal"][0]["present"])

    def test_a_rows_file_is_never_replaced_by_a_later_answer_to_the_same_query(self):
        db = self.db()
        sql = "with recursive c(n) as (select 1 union all select n+1 from c where n<1000000) select n from c"
        first = self.query(db, sql, limit=5)
        self.assertEqual(first.json["row_count"], 1000000)
        whole = self.path(first.json["rows_file"])
        size = os.path.getsize(whole)
        # The same query with a clock of one second is cut short: a different answer under the same name.
        cut = self.query(db, sql, limit=5, max_seconds=1)
        kept = cut.json["rows_read_before_the_stop"]
        self.assertLess(kept["row_count"], 1000000)
        self.assertTrue(kept["rows_file"].endswith("-0.2.jsonl"), kept["rows_file"])
        self.assertEqual(os.path.getsize(whole), size, "the complete answer was replaced by the partial one")
        self.assertEqual((first.json["earlier_answers"], kept["earlier_answers"]), (0, 1))
        self.assertEqual(len(self.read(whole).splitlines()), 1000001)
        self.assertEqual(len(self.read(self.path(kept["rows_file"])).splitlines()), kept["row_count"] + 1)
        # The same complete answer again is the file that is there, not a copy of it.
        again = self.query(db, sql, limit=5)
        self.assertEqual(again.json["rows_file"], first.json["rows_file"])

    def test_a_value_past_the_limit_is_refused_by_name_and_one_below_it_is_streamed(self):
        db = self.path("big.db")
        conn = sqlite3.connect(db)
        conn.execute("create table t(d)")
        conn.execute("insert into t values(zeroblob(?))", (50 * 1024 * 1024,))
        conn.execute("insert into t values(zeroblob(?))", (66 * 1024 * 1024,))
        conn.commit()
        conn.close()
        wrapper = ("import json, resource, subprocess, sys\n"
                   "p = subprocess.run([sys.executable, sys.argv[1]], input=sys.argv[2], capture_output=True, text=True)\n"
                   "print(json.dumps({'out': p.stdout, 'peak': resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss}))\n")
        env = {k: v for k, v in os.environ.items() if k not in ("JOB_ID", "OUT", "AGENT_ID", "SECRET_OUTPUT")}

        def go(sql):
            proc = subprocess.run([sys.executable, "-c", wrapper, tool_path("sqlite_query"), json.dumps({"db_path": db, "sql": sql})], capture_output=True, text=True, cwd=self.dir, env=env)
            got = json.loads(proc.stdout)
            return json.loads(got["out"]), got["peak"] * (1 if sys.platform == "darwin" else 1024)

        ok, peak = go("select d from t where rowid = 1")
        self.assertEqual(ok["row_count"], 1)
        line = json.loads(self.read(ok["rows_file"]).splitlines()[1])["values"][0]
        self.assertEqual((line["length"], line["sha256"]), (50 * 1024 * 1024, hashlib.sha256(bytes(50 * 1024 * 1024)).hexdigest()))
        self.assertEqual(len(base64.b64decode(line["blob_b64"])), 50 * 1024 * 1024)
        self.assertLess(peak, 240 * 1024 * 1024, "peak %d bytes for one 50 MiB value (the earlier code needed 350 MB)" % peak)
        refused, peak = go("select d from t where rowid = 2")
        self.assertIs(refused["ok"], False)
        self.assertEqual(refused["reason"], "value_too_long")
        self.assertIn("substr()", refused["error"])
        self.assertLess(peak, 120 * 1024 * 1024, "peak %d bytes for a refused 66 MiB value" % peak)
        huge, peak = go("select zeroblob(999999999)")
        self.assertEqual(huge["reason"], "value_too_long")
        self.assertLess(peak, 120 * 1024 * 1024)


TEXT_CANARY = "canary-text-3f9a1c77d2e4"
BLOB_CANARY = b"canary-blob-b81e5d02a6c9"


class SqliteQueryValues(Case):
    """write_values: the values of one table go to a sealed file and nowhere else. Databases are made with the sqlite3 module;
    the canaries are strings the tests plant, so a value that reaches the answer or any other file is found by a plain search."""

    def secret_db(self, name="inputs/logins.db", rows=3):
        path = self.path(name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        conn = sqlite3.connect(path)
        # An ordinary rowid table: no column is its rowid (an INTEGER PRIMARY KEY would be; that table has tests of its own).
        conn.execute("create table logins(origin text, secret blob, note text)")
        conn.execute("insert into logins(origin, secret, note) values('site-one', ?, ?)", (BLOB_CANARY, TEXT_CANARY))
        for n in range(rows - 1):
            conn.execute("insert into logins(origin, secret, note) values(?, NULL, ?)", ("site-%d" % (n + 2), "plain %d" % n))
        conn.commit()
        conn.close()
        return path

    def job(self, name="job-out", job_id="j000031"):
        out = self.path(name)
        os.makedirs(out, exist_ok=True)
        return out, {"JOB_ID": job_id, "OUT": out, "SECRET_OUTPUT": "1"}

    def export(self, db, env=None, **kw):
        return run_tool("sqlite_query", dict({"db_path": db, "table": "logins", "write_values": True}, **kw), self.dir, env=env)

    def values_lines(self, out):
        """The values file's cell lines and its end line (None when it has none)."""
        lines = [json.loads(l) for l in self.read(os.path.join(out, "sqlite-query-values.jsonl")).splitlines()]
        end = lines[-1] if lines and lines[-1].get("end") is True else None
        return (lines[:-1] if end else lines), end

    def files_outside(self, *skip):
        """Every file under the scratch directory except the evidence and the skipped ones."""
        found = []
        for base, _dirs, files in os.walk(self.dir):
            for f in files:
                full = os.path.join(base, f)
                if full not in skip and not full.startswith(self.path("inputs") + os.sep):
                    found.append(full)
        return found

    def test_the_values_are_refused_outside_a_job_and_nothing_is_written(self):
        db = self.secret_db()
        r = self.export(db)
        self.assertEqual(r.code, 1)
        self.assertEqual(r.stderr, "", "a refusal is a JSON answer, not a traceback")
        self.assertIn("refused outside a job", r.json["error"])
        self.assertEqual(r.json["write_values"], "refused")
        self.assertNotIn(TEXT_CANARY, r.stdout)
        self.assertEqual(self.files_outside(), [])

    def test_the_values_are_refused_in_a_job_the_harness_did_not_run_as_secret_output_and_nothing_is_written(self):
        db = self.secret_db()
        out, env = self.job()
        for value in (None, "", "0", "yes", "true"):
            env = dict(env)
            env.pop("SECRET_OUTPUT", None)
            if value is not None:
                env["SECRET_OUTPUT"] = value
            r = self.export(db, env)
            self.assertEqual(r.code, 1, value)
            self.assertEqual(r.stderr, "", "a refusal is a JSON answer, not a traceback")
            self.assertIs(r.json["ok"], False)
            self.assertEqual((r.json["write_values"], r.json["written"]), ("refused", False))
            self.assertIn("not run as secret output", r.json["error"])
            self.assertNotIn(TEXT_CANARY, r.stdout)
            self.assertEqual(os.listdir(out), [], "nothing was created under OUT")
            self.assertEqual(self.files_outside(), [])
        # The same job with the variable the harness sets for a secret job: the export runs.
        env = dict(env, SECRET_OUTPUT="1")
        self.assertEqual(self.export(db, env).code, 0)
        # An ordinary query needs none of it.
        env.pop("SECRET_OUTPUT")
        self.assertEqual(run_tool("sqlite_query", {"db_path": db, "sql": "select origin from logins"}, self.dir, env=env).code, 0)

    def test_a_value_is_in_the_sealed_file_only_not_in_the_answer_nor_in_any_other_file(self):
        db = self.secret_db()
        out, env = self.job()
        r = self.export(db, env, limit=2)
        self.assertEqual(r.code, 0, r.stdout + r.stderr)
        self.assertIs(r.json["ok"], True)
        # Not in stdout (the whole answer, its text form included), in neither encoding.
        b64 = base64.b64encode(BLOB_CANARY).decode()
        for needle in (TEXT_CANARY, BLOB_CANARY.decode(), b64, hashlib.sha256(BLOB_CANARY).hexdigest(), hashlib.sha256(TEXT_CANARY.encode()).hexdigest()):
            self.assertNotIn(needle, r.stdout)
            self.assertNotIn(needle, r.stderr)
        # The locators are there: table, rowid, column, type, length, and the counts.
        self.assertEqual((r.json["table"], r.json["locator"], r.json["row_count"]), ("logins", "rowid", 3))
        first = r.json["rows"][0]
        self.assertEqual((first["n"], first["rowid"]), (1, 1))
        cols = [c["name"] for c in r.json["columns"]]
        self.assertEqual(cols, ["origin", "secret", "note"])
        self.assertEqual(first["cells"][cols.index("secret")], "blob:%d" % len(BLOB_CANARY))
        self.assertEqual(first["cells"][cols.index("note")], "text:%d" % len(TEXT_CANARY))
        self.assertEqual(r.json["cells_null"], 2)
        self.assertEqual(r.json["secret_values"]["written"], r.json["cells_with_a_value"])
        # The values file is the one place: mode 0600, named, with both canaries, one line per cell that is not NULL.
        values_path = os.path.join(out, "sqlite-query-values.jsonl")
        self.assertEqual(r.json["secret_values"]["values_file"], "store/jobs/j000031/out/sqlite-query-values.jsonl")
        self.assertEqual(stat.S_IMODE(os.stat(values_path).st_mode), 0o600)
        lines, end = self.values_lines(out)
        self.assertEqual(len(lines), 3 + 2 + 2)
        self.assertEqual(end, {"end": True, "complete": True, "rows_read": 3, "cells_written": 7, "cells_with_a_value": 7,
                               "cells_not_exported": {}, "stopped": None, "error_class": None, "sqlite_message": None})
        by = {(l["rowid"], l["column"]): l for l in lines}
        self.assertEqual(by[(1, "note")]["value"], TEXT_CANARY)
        self.assertEqual(base64.b64decode(by[(1, "secret")]["value"]["blob_b64"]), BLOB_CANARY)
        self.assertEqual((by[(1, "secret")]["table"], by[(1, "secret")]["n"], by[(1, "secret")]["length"]), ("logins", 1, len(BLOB_CANARY)))
        self.assertNotIn("sha256", self.read(values_path), "no digest of a value, not even in the sealed file")
        self.assertNotIn((2, "secret"), by)
        # No other file holds a value: the locators file (3 rows, limit 2) is made, and has none.
        self.assertTrue(r.json["truncated"])
        locators = os.path.join(out, "tool-output", os.path.basename(r.json["locators_file"]))
        extra = self.files_outside(values_path)
        self.assertEqual(extra, [locators], "the locators file is the only other file")
        for f in extra:
            data = self.read(f, "rb")
            for needle in (TEXT_CANARY.encode(), BLOB_CANARY, b64.encode()):
                self.assertNotIn(needle, data, f)
        located = [json.loads(l) for l in self.read(locators).splitlines()]
        self.assertEqual([x["rowid"] for x in located[1:]], [1, 2, 3])
        self.assertEqual(len(located[1]["cells"]), 3)

    def test_a_second_run_in_the_same_jobs_output_is_refused_as_json_and_keeps_the_first_file(self):
        db = self.secret_db()
        out, env = self.job(job_id="j000032")
        self.assertEqual(self.export(db, env).code, 0)
        values_path = os.path.join(out, "sqlite-query-values.jsonl")
        before = self.read(values_path)
        again = self.export(db, env)
        self.assertEqual(again.code, 1)
        self.assertEqual(again.stderr, "", "a refusal is a JSON answer, not a traceback")
        self.assertIn("values file already exists", again.json["error"])
        self.assertEqual(again.json["write_values"], "refused")
        self.assertEqual(self.read(values_path), before, "the first run's file is as it was")
        self.assertEqual([n for n in os.listdir(os.path.join(out, "tool-output")) if n.startswith(".")] if os.path.isdir(os.path.join(out, "tool-output")) else [], [], "no half-written file is left")

    def test_a_link_at_the_values_file_is_refused_by_name_and_not_followed(self):
        db = self.secret_db()
        out, env = self.job(job_id="j000033")
        victim = self.write("victim.txt", "keep me")
        os.symlink(victim, os.path.join(out, "sqlite-query-values.jsonl"))
        r = self.export(db, env)
        self.assertEqual(r.code, 1)
        self.assertIn("values file already exists", r.json["error"])
        self.assertEqual(self.read(victim), "keep me")

    def test_there_is_no_sql_in_the_mode_so_no_filter_confirms_a_guess(self):
        db = self.secret_db()
        out, env = self.job(job_id="j000034")
        # The oracle would be: select rowid from logins where note like 'canary-text-3f%' -> a row means the guess is right.
        r = run_tool("sqlite_query", {"db_path": db, "write_values": True, "table": "logins",
                                      "sql": "select rowid from logins where note like 'canary-text-3f%'"}, self.dir, env=env)
        self.assertEqual(r.code, 1)
        self.assertEqual(r.json["write_values"], "refused")
        self.assertIn("not sql", r.json["error"])
        self.assertFalse(os.path.exists(os.path.join(out, "sqlite-query-values.jsonl")), "refused before anything was created")
        # The parameters of the mode do not leak into an ordinary query either.
        plain = run_tool("sqlite_query", {"db_path": db, "sql": "select 1", "table": "logins"}, self.dir)
        self.assertEqual(plain.code, 1)
        self.assertTrue(plain.json["error"].startswith("table belongs to write_values"), plain.json["error"])
        both = run_tool("sqlite_query", {"db_path": db, "sql": "select 1", "table": "logins", "rowid_from": 1}, self.dir)
        self.assertTrue(both.json["error"].startswith("table, rowid_from belong to write_values"), both.json["error"])
        # A rowid range selects by position, and the counts are the same whatever the values are.
        ranged = self.export(db, env, rowid_from=2, rowid_to=3)
        self.assertEqual(ranged.code, 0, ranged.stdout)
        self.assertEqual([x["rowid"] for x in ranged.json["rows"]], [2, 3])
        self.assertEqual(ranged.json["row_count"], 2)
        self.assertNotIn(TEXT_CANARY, ranged.stdout)

    def test_columns_choose_what_is_written_and_a_wrong_name_or_a_view_is_refused(self):
        db = self.secret_db()
        out, env = self.job(job_id="j000035")
        r = self.export(db, env, columns=["note"])
        self.assertEqual(r.code, 0, r.stdout)
        self.assertEqual([c["name"] for c in r.json["columns"]], ["note"])
        lines, _end = self.values_lines(out)
        self.assertEqual({l["column"] for l in lines}, {"note"})
        for kw, word in (({"columns": ["nope"]}, "no column"), ({"columns": []}, "columns is a list"), ({"table": "nope"}, "no table")):
            out2, env2 = self.job(name="o-%d" % len(word), job_id="j000036")
            bad = self.export(db, env2, **kw)
            self.assertEqual(bad.code, 1, kw)
            self.assertIn(word, bad.json["error"], kw)
            self.assertIsNone(bad.json and bad.json.get("secret_values"))
            self.assertFalse(os.path.exists(os.path.join(out2, "sqlite-query-values.jsonl")), "a refused name leaves no values file")
        conn = sqlite3.connect(db)
        conn.execute("create view v as select * from logins")
        conn.commit()
        conn.close()
        out3, env3 = self.job(name="o-view", job_id="j000037")
        view = self.export(db, env3, table="v")
        self.assertEqual(view.code, 1)
        self.assertIn("no table", view.json["error"])

    def test_a_table_without_rowid_is_located_by_position_and_a_rowid_range_is_refused(self):
        path = self.path("inputs/w.db")
        os.makedirs(os.path.dirname(path))
        conn = sqlite3.connect(path)
        conn.execute("create table kv(k text primary key, v text) without rowid")
        conn.executemany("insert into kv values(?, ?)", [("a", TEXT_CANARY), ("b", "plain")])
        conn.commit()
        conn.close()
        out, env = self.job(job_id="j000038")
        r = run_tool("sqlite_query", {"db_path": path, "table": "kv", "write_values": True, "columns": ["v"]}, self.dir, env=env)
        self.assertEqual(r.code, 0, r.stdout)
        self.assertEqual(r.json["table_kind"], "without_rowid")
        self.assertEqual(r.json["locator"], "n")
        self.assertIn("primary key", r.json["locator_note"])
        self.assertEqual([(x["n"], x["rowid"]) for x in r.json["rows"]], [(1, None), (2, None)])
        self.assertNotIn(TEXT_CANARY, r.stdout)
        out2, env2 = self.job(name="o2", job_id="j000039")
        ranged = run_tool("sqlite_query", {"db_path": path, "table": "kv", "write_values": True, "rowid_from": 1}, self.dir, env=env2)
        self.assertEqual(ranged.code, 1)
        self.assertIn("WITHOUT ROWID", ranged.json["error"])

    def test_a_name_shaped_like_a_token_is_not_printed_and_text_that_is_not_utf8_is_kept_in_the_file_only(self):
        token = "Zq8Xv3Lm9Rt2Hw5Bn7Cd4Fg6Js1Kp0"
        path = self.path("inputs/%s.db" % token)
        os.makedirs(os.path.dirname(path))
        conn = sqlite3.connect(path)
        conn.text_factory = bytes
        conn.execute('create table "%s"(v)' % token)
        conn.execute('insert into "%s" values(CAST(? AS TEXT))' % token, (b"\xff\xfe" + TEXT_CANARY.encode(),))
        conn.commit()
        conn.close()
        out, env = self.job(job_id="j000040")
        r = run_tool("sqlite_query", {"db_path": path, "table": token, "write_values": True}, self.dir, env=env)
        self.assertEqual(r.code, 0, r.stdout + r.stderr)
        self.assertNotIn(token, r.stdout, "a file or table name shaped like a token is withheld on every channel")
        self.assertIn("withheld", r.stdout)
        self.assertNotIn(TEXT_CANARY, r.stdout)
        line = self.values_lines(out)[0][0]
        self.assertEqual(line["table"], token, "the sealed file keeps the real name")
        self.assertEqual(base64.b64decode(line["value"]["bytes_b64"]), b"\xff\xfe" + TEXT_CANARY.encode())
        self.assertEqual(r.json["rows"][0]["cells"], ["text_not_utf8:%d" % (2 + len(TEXT_CANARY))])
        # An error that quotes the name withholds it too.
        out2, env2 = self.job(name="o2", job_id="j000041")
        bad = run_tool("sqlite_query", {"db_path": path, "table": token + "x", "write_values": True}, self.dir, env=env2)
        self.assertEqual(bad.code, 1)
        self.assertNotIn(token, bad.stdout)

    def test_a_large_blob_is_written_in_slices_and_whole_and_the_ordinary_mode_is_as_it_was(self):
        path = self.path("inputs/big.db")
        os.makedirs(os.path.dirname(path))
        blob = os.urandom(2 * 1024 * 1024 + 17)
        conn = sqlite3.connect(path)
        conn.execute("create table t(d blob)")
        conn.execute("insert into t values(?)", (blob,))
        conn.commit()
        conn.close()
        out, env = self.job(job_id="j000042")
        r = run_tool("sqlite_query", {"db_path": path, "table": "t", "write_values": True}, self.dir, env=env)
        self.assertEqual(r.code, 0, r.stdout[:300])
        line = self.values_lines(out)[0][0]
        self.assertEqual(base64.b64decode(line["value"]["blob_b64"]), blob)
        self.assertEqual(line["length"], len(blob))
        self.assertNotIn(base64.b64encode(blob[:60]).decode(), r.stdout)
        # Outside write_values the tool returns what it always did: the value is in the answer.
        plain = run_tool("sqlite_query", {"db_path": self.secret_db(), "sql": "select note, secret from logins limit 1"}, self.dir)
        self.assertEqual(plain.code, 0, plain.stdout)
        self.assertIn(TEXT_CANARY, plain.stdout)
        self.assertEqual(plain.json["rows"][0]["values"][1]["sha256"], hashlib.sha256(BLOB_CANARY).hexdigest())
        # Inside a job the ordinary mode is unchanged too: no values file is made.
        out2, env2 = self.job(name="o3", job_id="j000043")
        injob = run_tool("sqlite_query", {"db_path": self.secret_db("inputs/b.db"), "sql": "select note from logins limit 1"}, self.dir, env=env2)
        self.assertEqual(injob.code, 0, injob.stdout)
        self.assertFalse(os.path.exists(os.path.join(out2, "sqlite-query-values.jsonl")))



PINS = (482915, 771203)


class SqliteQueryValuesReview(Case):
    """The review of #144: each test fails on the tool as it was at ea88a910 (PACK_DIR pointed at a copy of it)."""

    def job(self, name, job_id):
        out = self.path(name)
        os.makedirs(out, exist_ok=True)
        return out, {"JOB_ID": job_id, "OUT": out, "SECRET_OUTPUT": "1"}

    def export(self, db, table, env, **kw):
        return run_tool("sqlite_query", dict({"db_path": db, "table": table, "write_values": True}, **kw), self.dir, env=env)

    def make(self, name, statements, rows=()):
        path = self.path("inputs", name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        conn = sqlite3.connect(path)
        for st in statements:
            conn.execute(st)
        for st, params in rows:
            conn.execute(st, params)
        conn.commit()
        conn.close()
        return path

    def seen_by_the_agent(self, r, out):
        """stdout, stderr, and every file under the job's output except the values file, as bytes."""
        blobs = [r.stdout.encode(), r.stderr.encode()]
        for base, _dirs, files in os.walk(out):
            for f in files:
                blobs.append(f.encode())
                if f != "sqlite-query-values.jsonl":
                    blobs.append(self.read(os.path.join(base, f), "rb"))
        return b"\n".join(blobs)

    def values_lines(self, out):
        lines = [json.loads(l) for l in self.read(os.path.join(out, "sqlite-query-values.jsonl")).splitlines()]
        end = lines[-1] if lines and lines[-1].get("end") is True else None
        return (lines[:-1] if end else lines), end

    def test_an_integer_primary_key_is_the_rowid_so_the_rowid_is_never_printed_nor_ranged_over(self):
        # SQLite makes a table's one primary key column the rowid when its declared type is exactly INTEGER (any case, in the
        # column or the table constraint). Its value is then the rowid: printing the rowid prints the value, and a rowid range
        # is a filter over it (row_count 1 or 0 around a guess recovers it by bisection).
        db = self.make("pins.db", [
            "create table pins(pin INTEGER PRIMARY KEY, card TEXT)",
            "create table pins2(pin integer, card TEXT, primary key(pin))",
            "create table pins3(pin INT PRIMARY KEY, card TEXT)",       # INT is not INTEGER: no alias, the rowid is its own
        ], [("insert into %s values(?, ?)" % t, (p, "card-%d" % i)) for t in ("pins", "pins2", "pins3") for i, p in enumerate(PINS)])
        for k, table in enumerate(("pins", "pins2")):
            out, env = self.job("o-%s" % table, "j00010%d" % k)
            r = self.export(db, table, env, limit=1)
            self.assertEqual(r.code, 0, r.stdout + r.stderr)
            seen = self.seen_by_the_agent(r, out)
            for pin in PINS:
                self.assertNotIn(str(pin).encode(), seen, "%s: the rowid is the pin, and it is printed nowhere" % table)
            self.assertEqual((r.json["table_kind"], r.json["locator"]), ("alias", "n"))
            self.assertEqual([(x["n"], x["rowid"]) for x in r.json["rows"]], [(1, None)])
            located = [json.loads(l) for l in self.read(os.path.join(out, "tool-output", os.path.basename(r.json["locators_file"]))).splitlines()]
            self.assertEqual([(x["n"], x["rowid"]) for x in located[1:]], [(1, None), (2, None)])
            lines, end = self.values_lines(out)
            self.assertEqual(sorted(l["value"] for l in lines if l["column"] == "pin"), list(PINS), "the sealed file has the values")
            self.assertTrue(end["complete"])
            # A rowid range would select by the pin: refused by name, before any file is made.
            out2, env2 = self.job("r-%s" % table, "j00011%d" % k)
            for bounds in ({"rowid_from": 600000}, {"rowid_to": 771203}, {"rowid_from": 1, "rowid_to": 10 ** 9}):
                ranged = self.export(db, table, env2, **bounds)
                self.assertEqual(ranged.code, 1, ranged.stdout)
                self.assertEqual(ranged.json["reason"], "rowid_is_a_value")
                self.assertNotIn("row_count", ranged.json)
                self.assertEqual(os.listdir(out2), [])
        # INT PRIMARY KEY is an ordinary rowid table: its rowid (1, 2) is printed, its pin is not.
        out, env = self.job("o-pins3", "j000120")
        r = self.export(db, "pins3", env)
        self.assertEqual(r.code, 0, r.stdout)
        self.assertEqual(r.json["table_kind"], "rowid")
        self.assertEqual([x["rowid"] for x in r.json["rows"]], [1, 2])
        for pin in PINS:
            self.assertNotIn(str(pin).encode(), self.seen_by_the_agent(r, out))

    def test_rows_are_read_from_the_table_never_through_an_index_whose_order_is_the_values(self):
        # A covering index on the secret column would hand the rows over in the order of the secret values.
        db = self.make("kv.db", ["create table kv(k text primary key, v text) without rowid", "create index iv on kv(v)",
                                 "create table c(s text)", "create index ic on c(s)"],
                       [("insert into kv values(?, ?)", kv) for kv in (("a", "zz-secret"), ("b", "aa-secret"), ("c", "mm-secret"))]
                       + [("insert into c values(?)", (v,)) for v in ("zz-secret", "aa-secret", "mm-secret")])
        for table, job in (("kv", "j000130"), ("c", "j000131")):
            out, env = self.job("o-" + table, job)
            r = self.export(db, table, env, columns=["v" if table == "kv" else "s"])
            self.assertEqual(r.code, 0, r.stdout)
            lines, _end = self.values_lines(out)
            self.assertEqual([(l["n"], l["value"]) for l in lines], [(1, "zz-secret"), (2, "aa-secret"), (3, "mm-secret")],
                             "%s: n follows the table's own order (primary key, rowid), not the order of the values" % table)
        self.assertIn("ranks", self.export(db, "kv", self.job("o-kv2", "j000132")[1]).json["locator_note"], "the skill and the answer say n ranks the key")

    def run_limited(self, args, env, fsize):
        """The tool with RLIMIT_FSIZE set: a write past `fsize` bytes fails with EFBIG (Python ignores SIGXFSZ), as on a full disk."""
        import resource
        e = dict(os.environ)
        for k in ("JOB_ID", "OUT", "AGENT_ID", "SECRET_OUTPUT"):
            e.pop(k, None)
        e.update(env)
        proc = subprocess.run([sys.executable, tool_path("sqlite_query")], input=json.dumps(args), capture_output=True, text=True,
                              cwd=self.dir, env=e, timeout=120, preexec_fn=lambda: resource.setrlimit(resource.RLIMIT_FSIZE, (fsize, fsize)))
        return proc

    def test_a_write_that_fails_ends_the_export_as_json_and_says_what_the_kept_file_holds(self):
        db = self.make("many.db", ["create table cookies(host, value)"],
                       [("insert into cookies values(?, ?)", ("h%d" % i, "cookie-value-%06d" % i)) for i in range(400)])
        out, env = self.job("o", "j000140")
        proc = self.run_limited({"db_path": db, "table": "cookies", "write_values": True}, env, 4096)
        self.assertNotIn("Traceback", proc.stderr)
        self.assertEqual(proc.stderr, "")
        self.assertEqual(proc.returncode, 1, proc.stdout[-500:])
        j = json.loads(proc.stdout)
        self.assertIs(j["complete"], False)
        self.assertIs(j["ok"], False, "an export that stopped before its end is not ok")
        self.assertEqual(j["reason"], "values_file_error")
        self.assertIn("EFBIG", j["values_file_error"])
        self.assertIn("no end line", j["values_file_error"])
        self.assertIn("partial", j["values_file_state"])
        path = os.path.join(out, "sqlite-query-values.jsonl")
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        data = self.read(path, "rb")
        whole = data.count(b"\n")
        self.assertGreater(whole, 0)
        self.assertEqual(j["secret_values"]["written"], whole, "the count said is the whole lines that reached the file")
        self.assertIs(j["secret_values"]["end_line_written"], False)
        self.assertNotIn(b'"end": true', data)
        self.assertNotIn("cookie-value-", proc.stdout)
        leftovers = [n for _b, _d, fs in os.walk(out) for n in fs if n.startswith(".sqlite_query-")]
        self.assertEqual(leftovers, [], "no temporary locators file is left")

    def test_sqlites_message_is_never_printed_since_a_generated_column_quotes_the_value_in_it(self):
        # json_extract('{}', secret) fails with the secret in its message: "JSON path error near '<secret>'" (SQLite 3.4x) or
        # "bad JSON path: '<secret>'" (3.50). Whatever the wording, the value stays in the values file.
        secret = "lemon river otter maple 0417"  # not shaped like a token, so the shared scrub would not hide it
        db = self.make("gen.db", ["create table h(secret text)"], [("insert into h values(?)", (secret,)), ("insert into h values(?)", ("plain",))])
        conn = sqlite3.connect(db)
        conn.execute("ALTER TABLE h ADD COLUMN j TEXT GENERATED ALWAYS AS (json_extract('{}', secret)) VIRTUAL")
        conn.commit()
        conn.close()
        out, env = self.job("o", "j000150")
        r = self.export(db, "h", env)
        self.assertEqual(r.stderr, "")
        self.assertNotIn(secret.encode(), self.seen_by_the_agent(r, out))
        self.assertEqual(r.code, 0, r.stdout)
        self.assertEqual([x["cells"] for x in r.json["rows"]], [["text:%d" % len(secret), "unreadable"], ["text:5", "unreadable"]])
        self.assertEqual(r.json["cells_not_exported"]["cells"], {"unreadable": 2})
        self.assertNotIn("error", r.json["cells_not_exported"]["first"][0], "the class can depend on the message: values file only")
        self.assertIs(r.json["complete"], False)
        lines, end = self.values_lines(out)
        by = {(l["n"], l["column"]): l for l in lines}
        self.assertEqual(by[(1, "secret")]["value"], secret)
        self.assertIn(secret, by[(1, "j")]["sqlite_message"], "the message is kept in the sealed file")
        self.assertRegex(by[(1, "j")]["error_class"], r"^OperationalError")
        self.assertEqual(by[(1, "j")]["not_exported"], "unreadable")
        self.assertIs(end["complete"], False)
        # A table none of whose cells can be computed stops the export: the message is still not printed.
        out2, env2 = self.job("o2", "j000151")
        only = self.export(db, "h", env2, columns=["j"])
        self.assertEqual(only.code, 1, only.stdout)
        self.assertEqual(only.json["reason"], "row_unreadable")
        self.assertNotIn(secret.encode(), self.seen_by_the_agent(only, out2))
        self.assertIn(secret, self.values_lines(out2)[1]["sqlite_message"])

    def test_a_wrong_name_or_a_file_that_is_not_sqlite_leaves_nothing_and_the_same_job_can_ask_again(self):
        db = self.make("t.db", ["create table logins(v text)"], [("insert into logins values(?)", ("x",))])
        out, env = self.job("o", "j000160")
        typo = self.export(db, "login", env)
        self.assertEqual(typo.code, 1)
        self.assertIn("no table", typo.json["error"])
        self.assertEqual(os.listdir(out), [], "a wrong table name leaves no values file")
        not_db = self.write("inputs/blob.bin", b"\x8a\x13\xfe\x01SECRETHEAD" + bytes(range(256)) * 8)
        nd = self.export(not_db, "logins", env)
        self.assertEqual(nd.code, 1)
        self.assertIn("not a SQLite file", nd.json["error"])
        self.assertNotIn("header_hex", nd.json, "the first bytes of a file the caller marked secret are not printed")
        self.assertNotIn(b"\x8a\x13\xfe\x01".hex(), nd.stdout)
        self.assertEqual(os.listdir(out), [])
        again = self.export(db, "logins", env)
        self.assertEqual(again.code, 0, again.stdout)
        self.assertEqual(again.json["secret_values"]["written"], 1)

    def test_a_value_over_the_length_limit_is_recorded_and_the_rest_of_the_table_is_exported(self):
        if not hasattr(sqlite3.connect(":memory:"), "setlimit"):
            self.skipTest("Python before 3.11 has no setlimit: the tool does not enforce the length limit")
        limit = 64 * 1024 * 1024
        db = self.make("big.db", ["create table b(k, v)"], [("insert into b values(?, zeroblob(?))", (1, limit + 1)),
                                                             ("insert into b values(?, ?)", (2, b"short-blob-value")),
                                                             ("insert into b values(?, zeroblob(?))", (3, limit + 5))])
        out, env = self.job("o", "j000170")
        r = self.export(db, "b", env)
        self.assertEqual(r.code, 0, r.stdout[:500])
        self.assertEqual(r.json["row_count"], 3, "the export goes on past the large value")
        self.assertEqual([x["cells"] for x in r.json["rows"]],
                         [["integer:1", "too_large:blob:%d" % (limit + 1)], ["integer:1", "blob:16"], ["integer:1", "too_large:blob:%d" % (limit + 5)]])
        self.assertEqual(r.json["cells_not_exported"]["cells"], {"value_too_large": 2})
        self.assertEqual([(x["n"], x["rowid"], x["column"]) for x in r.json["cells_not_exported"]["first"]], [(1, 1, "v"), (3, 3, "v")])
        self.assertNotIn("in pieces", r.stdout, "no advice to read a secret into the context a piece at a time")
        lines, end = self.values_lines(out)
        by = {(l["n"], l["column"]): l for l in lines}
        self.assertEqual(by[(1, "v")]["not_exported"], "value_too_large")
        self.assertNotIn("value", by[(1, "v")])
        self.assertEqual(base64.b64decode(by[(2, "v")]["value"]["blob_b64"]), b"short-blob-value")
        self.assertEqual(by[(3, "k")]["value"], 3)
        self.assertIs(end["complete"], False)

    def test_the_locators_file_has_every_row_whether_or_not_the_page_is_truncated_and_it_is_bounded(self):
        db = self.make("t.db", ["create table t(v text)"], [("insert into t values(?)", ("value-%d" % i,)) for i in range(50)])
        out, env = self.job("o", "j000180")
        r = self.export(db, "t", env)
        self.assertEqual(r.code, 0, r.stdout)
        self.assertIs(r.json["truncated"], False)
        located = self.read(os.path.join(out, "tool-output", os.path.basename(r.json["locators_file"]))).splitlines()
        self.assertEqual(len(located), 1 + 50)
        # The file's byte cap, made small: the file stops at a row and says so; the values file still has every cell.
        out2, env2 = self.job("o2", "j000181")
        snippet = ("import importlib.util, sys; spec = importlib.util.spec_from_file_location('sq', sys.argv[1]); "
                   "m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); m.LOCATORS_BYTES = 400; m.main()")
        e = dict(os.environ, **env2)
        proc = subprocess.run([sys.executable, "-c", snippet, tool_path("sqlite_query")], cwd=self.dir, env=e, capture_output=True, text=True,
                              input=json.dumps({"db_path": db, "table": "t", "write_values": True}), timeout=120)
        j = json.loads(proc.stdout)
        self.assertEqual(j["locators_file_cap_bytes"], 400)
        stopped = j["locators_file_stopped_at_row"]
        self.assertGreater(stopped, 1)
        located = self.read(os.path.join(out2, "tool-output", os.path.basename(j["locators_file"])), "rb")
        self.assertLessEqual(len(located), 400)
        self.assertIs(j["complete"], False)
        self.assertEqual(len(self.values_lines(out2)[0]), 50)

    def test_a_column_name_echoed_in_an_error_is_withheld_when_shaped_like_a_token(self):
        db = self.make("t.db", ["create table t(v text)"], [("insert into t values(?)", ("x",))])
        token = "Zq8Xv3Lm9Rt2Hw5Bn7Cd4Fg6Js1Kp0"
        out, env = self.job("o", "j000190")
        r = self.export(db, "t", env, columns=[token])
        self.assertEqual(r.code, 1)
        self.assertIn("no column", r.json["error"])
        self.assertNotIn(token, r.stdout)

    def test_a_virtual_table_is_located_by_position_or_said_unsupported_by_name(self):
        conn = sqlite3.connect(":memory:")
        try:
            conn.execute("create virtual table x using fts5(b)")
        except sqlite3.Error:
            self.skipTest("this SQLite has no fts5")
        db = self.make("fts.db", ["create virtual table msgs using fts5(body)"],
                       [("insert into msgs(rowid, body) values(?, ?)", (PINS[0], "canary-fts-body-51c2"))])
        out, env = self.job("o", "j000200")
        r = self.export(db, "msgs", env, rowid_from=1)
        self.assertEqual(r.code, 1)
        self.assertIn(r.json["reason"], ("virtual_table", "virtual_table_unsupported"))
        r = self.export(db, "msgs", env)
        seen = self.seen_by_the_agent(r, out)
        self.assertNotIn(b"canary-fts-body", seen)
        self.assertNotIn(str(PINS[0]).encode(), seen, "a virtual table's rowid (an application's id here) is not printed")
        if r.code == 0:
            self.assertEqual(r.json["table_kind"], "virtual")
            self.assertEqual([x["rowid"] for x in r.json["rows"]], [None])
        else:
            # Some SQLite builds cannot start the module under the read-only authorizer (fts5 on Debian's 3.40): a named state.
            self.assertEqual(r.json["reason"], "virtual_table_unsupported", r.stdout)
            self.assertEqual(r.stderr, "")


def load_tool():
    """run.py as a module, for the parts of it a test reads directly (the statement it runs, how it reads an error)."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("sqlite_query_tool", tool_path("sqlite_query"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def in_process(snippet_body, args, env, cwd):
    """The tool run as a module with `snippet_body` applied first (m is the module), the way the harness runs it otherwise."""
    snippet = ("import importlib.util, sys, os, errno; spec = importlib.util.spec_from_file_location('sq', sys.argv[1]); "
               "m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)\n" + snippet_body + "\nm.main()")
    e = dict(os.environ)
    for k in ("JOB_ID", "OUT", "AGENT_ID", "SECRET_OUTPUT"):
        e.pop(k, None)
    e.update(env)
    return subprocess.run([sys.executable, "-c", snippet, tool_path("sqlite_query")], cwd=cwd, env=e, capture_output=True, text=True,
                          input=json.dumps(args), timeout=120)


# Values whose orders all differ: by pin, by card (binary and without regard to case), by note, and as inserted.
MATRIX_ROWS = [(771203, "card-B", "n-q"), (482915, "card-a", "n-z"), (905517, "CARD-c", "n-a"), (613377, "card-D", "n-m")]
# table name -> (CREATE, expected table_kind, expected n_ranks)
MATRIX_TABLES = {
    "rowid": ("create table t(pin INTEGER, card TEXT, note TEXT)", "rowid", []),
    "alias": ("create table t(pin INTEGER PRIMARY KEY, card TEXT, note TEXT)", "alias", ["pin"]),
    "alias_tcons": ("create table t(pin integer, card TEXT, note TEXT, primary key(pin))", "alias", ["pin"]),
    "alias_strict": ("create table t(pin INTEGER PRIMARY KEY, card TEXT, note TEXT) strict", "alias", ["pin"]),
    "ipk_desc": ("create table t(pin INTEGER PRIMARY KEY DESC, card TEXT, note TEXT)", "rowid", []),
    "int_pk": ("create table t(pin INT PRIMARY KEY, card TEXT, note TEXT)", "rowid", []),
    "wr_text": ("create table t(pin INTEGER, card TEXT PRIMARY KEY, note TEXT) without rowid", "without_rowid", ["card"]),
    "wr_int": ("create table t(pin INTEGER PRIMARY KEY, card TEXT, note TEXT) without rowid", "without_rowid", ["pin"]),
    "wr_desc": ("create table t(pin INTEGER, card TEXT, note TEXT, primary key(card desc)) without rowid", "without_rowid", ["card"]),
    "wr_nocase": ("create table t(pin INTEGER, card TEXT COLLATE NOCASE PRIMARY KEY, note TEXT) without rowid", "without_rowid", ["card"]),
    "wr_composite": ("create table t(pin INTEGER, card TEXT, note TEXT, primary key(note, pin)) without rowid", "without_rowid", ["note", "pin"]),
    "wr_strict": ("create table t(pin INTEGER, card TEXT PRIMARY KEY, note TEXT) strict, without rowid", "without_rowid", ["card"]),
    "wr_shadowed": ("create table t(rowid TEXT, oid TEXT, _rowid_ TEXT, pin INTEGER, card TEXT PRIMARY KEY, note TEXT) without rowid",
                    "without_rowid", ["card"]),
    "shadowed": ("create table t(rowid TEXT, oid TEXT, _rowid_ TEXT, pin INTEGER, card TEXT, note TEXT)", "shadowed", []),
    "shadowed_alias": ("create table t(rowid INTEGER PRIMARY KEY, oid TEXT, _rowid_ TEXT, pin INTEGER, card TEXT, note TEXT)", "shadowed", ["rowid"]),
}
MATRIX_INDEXES = {
    "none": [],
    "pin": ["create index ixp on t(pin)"],
    "card_pin": ["create index ixc on t(card, pin)"],
    "pin_card": ["create index ixpc on t(pin, card)"],
    "card_desc": ["create index ixd on t(card desc, pin)"],
    "note_unique": ["create unique index ixn on t(note)"],
    "expression": ["create index ixe on t(length(card), pin)"],
    "partial": ["create index ixw on t(pin) where pin > 0"],
}


class SqliteQueryValuesDelta(Case):
    """The delta review of #144 (findings A, B, C and the P3s): each test fails on the tool as it was at 5acefe58 (PACK_DIR pointed
    at a copy of it). Truth comes from SQLite itself: a table scanned before any index exists, rowid = key, exception codes."""

    def job(self, name, job_id):
        out = self.path(name)
        os.makedirs(out, exist_ok=True)
        return out, {"JOB_ID": job_id, "OUT": out, "SECRET_OUTPUT": "1"}

    def export(self, db, table, env, **kw):
        return run_tool("sqlite_query", dict({"db_path": db, "table": table, "write_values": True}, **kw), self.dir, env=env)

    def make(self, name, statements, rows=()):
        path = self.path("inputs", name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if os.path.exists(path):
            os.unlink(path)
        conn = sqlite3.connect(path)
        for st in statements:
            conn.execute(st)
        for st, params in rows:
            conn.execute(st, params)
        conn.commit()
        conn.close()
        return path

    def values_lines(self, out):
        lines = [json.loads(l) for l in self.read(os.path.join(out, "sqlite-query-values.jsonl")).splitlines()]
        end = lines[-1] if lines and lines[-1].get("end") is True else None
        return (lines[:-1] if end else lines), end

    def locator_rows(self, out, answer):
        return [json.loads(l) for l in self.read(os.path.join(out, "tool-output", os.path.basename(answer["locators_file"]))).splitlines()[1:]]

    def with_generated(self, db, expr, name="h"):
        conn = sqlite3.connect(db)
        conn.execute("ALTER TABLE t ADD COLUMN %s TEXT GENERATED ALWAYS AS (%s) VIRTUAL" % (name, expr))
        conn.commit()
        conn.close()
        return db

    # --- A: the order of the rows, and the cells of one row --------------------------------------------------------------

    def test_a_without_rowid_table_is_ordered_by_its_key_whatever_its_columns_are_named(self):
        # Columns named rowid, oid and _rowid_ made the old tool call a WITHOUT ROWID table `shadowed` and read it with no ORDER BY:
        # SQLite then reads it through the covering index on pin, and n ranked the secret pins.
        db = self.make("wrs.db", ["create table t(rowid TEXT, oid TEXT, _rowid_ TEXT, pin INTEGER, card TEXT PRIMARY KEY) WITHOUT ROWID",
                                  "create index ixp on t(pin)"],
                       [("insert into t values(?, ?, ?, ?, ?)", ("r%d" % i, "o%d" % i, "u%d" % i, pin, card))
                        for i, (pin, card, _note) in enumerate(MATRIX_ROWS)])
        out, env = self.job("o", "j000300")
        r = self.export(db, "t", env, columns=["pin"])
        self.assertEqual(r.code, 0, r.stdout)
        self.assertEqual((r.json["table_kind"], r.json["n_ranks"]), ("without_rowid", ["card"]))
        lines, _end = self.values_lines(out)
        by_card = [pin for pin, _card, _n in sorted(MATRIX_ROWS, key=lambda x: x[1])]   # binary order of the key
        self.assertEqual([l["value"] for l in lines], by_card, "the rows come in primary-key order, never the index's (the pins')")
        self.assertNotEqual(by_card, sorted(by_card))

    def test_the_cells_of_a_row_read_in_parts_are_always_one_rows(self):
        # The old tool read a failing row a column at a time, each query free to take its own covering index: one exported row
        # held cells of three rows, and k2's values were never exported.
        db = self.make("stitch.db", ["create table t(rowid TEXT, oid TEXT, _rowid_ TEXT, k TEXT PRIMARY KEY, a TEXT, b TEXT, s TEXT) WITHOUT ROWID",
                                     "create index ia on t(a)", "create index ib on t(b)"],
                       [("insert into t values('r', 'o', 'u', ?, ?, ?, ?)", row) for row in
                        (("k1", "a-zulu", "b-mike", '{"x": 1}'), ("k2", "a-alfa", "b-zulu", "not json"), ("k3", "a-mike", "b-alfa", '{"x": 3}'))])
        self.with_generated(db, "json_extract(s, '$.x')", "g")
        out, env = self.job("o", "j000301")
        r = self.export(db, "t", env, columns=["k", "a", "b", "g"])
        self.assertEqual(r.code, 0, r.stdout)
        lines, _end = self.values_lines(out)
        rows = {}
        for l in lines:
            rows.setdefault(l["n"], {})[l["column"]] = l.get("value", l.get("not_exported"))
        self.assertEqual(rows, {1: {"k": "k1", "a": "a-zulu", "b": "b-mike", "g": "1"},
                                2: {"k": "k2", "a": "a-alfa", "b": "b-zulu", "g": "unreadable"},
                                3: {"k": "k3", "a": "a-mike", "b": "b-alfa", "g": "3"}})

    def test_rows_come_in_the_tables_own_order_for_every_kind_and_index_set(self):
        m = load_tool()
        k = 0
        for tname, (ddl, kind, ranks) in MATRIX_TABLES.items():
            for iname, indexes in MATRIX_INDEXES.items():
                k += 1
                label = "%s / %s" % (tname, iname)
                path = self.path("m", "%s-%s.db" % (tname, iname))
                os.makedirs(os.path.dirname(path), exist_ok=True)
                conn = sqlite3.connect(path)
                conn.execute(ddl)
                names = [r[1] for r in conn.execute("pragma table_info(t)")]
                for i in (2, 0, 3, 1):
                    pin, card, note = MATRIX_ROWS[i]
                    v = {"rowid": pin if tname == "shadowed_alias" else "r%d" % i, "oid": "o%d" % i, "_rowid_": "u%d" % i,
                         "pin": pin, "card": card, "note": note}
                    conn.execute("insert into t(%s) values(%s)" % (", ".join('"%s"' % n for n in names), ", ".join("?" * len(names))),
                                 [v[n] for n in names])
                conn.commit()
                # Truth from SQLite: a rowid table's order is its rowids'; a table with no index of its own (WITHOUT ROWID, a
                # shadowed one) scanned before any index is made is its own order; an alias is rowid = key in every row.
                if kind in ("rowid", "alias"):
                    truth = [r[0] for r in conn.execute("select pin from t order by rowid")]
                else:
                    self.assertEqual([r[3] for r in conn.execute("explain query plan select pin from t")], ["SCAN t"], label)
                    truth = [r[0] for r in conn.execute("select pin from t")]
                if kind in ("rowid", "alias"):
                    is_alias = conn.execute("select count(*) = sum(rowid = pin) from t").fetchone()[0] == 1
                    self.assertEqual(kind == "alias", is_alias, label)
                for st in indexes:
                    conn.execute(st)
                conn.commit()
                conn.close()
                # The statement the tool runs: no sort, and an index only where its leading keys are the primary key's.
                ro = sqlite3.connect("file:%s?mode=ro" % path, uri=True)
                ro.set_authorizer(m.authorizer)
                table, cols, got_kind, order = m.table_layout(ro, "t", None)
                self.assertEqual((got_kind, order["ranks"]), (kind, ranks), label)
                for what in ('"pin"', ", ".join(m.q_ident(c) for c, _t in cols)):
                    stmt, params = m.export_statement(table, got_kind, order, what)
                    plan = " / ".join(str(r[3]) for r in ro.execute("EXPLAIN QUERY PLAN " + stmt, params))
                    self.assertNotIn("TEMP B-TREE", plan, "%s: %s" % (label, stmt))
                    used = [w.split()[-1] for w in plan.split(" / ") if "INDEX" in w]
                    if kind != "without_rowid":
                        self.assertEqual(used, [], "%s: NOT INDEXED reads the table itself: %s" % (label, plan))
                    for ix in used:
                        # An index of a WITHOUT ROWID table carries the key's columns after its own (key 0): the whole sequence orders it.
                        keys = [(x[2], str(x[4]).lower(), x[3]) for x in ro.execute("pragma index_xinfo(%s)" % m.q_ident(ix)) if x[2] is not None]
                        pk = [(x[2], str(x[4]).lower(), x[3]) for il in ro.execute("pragma index_list(t)") if il[3] == "pk"
                              for x in ro.execute("pragma index_xinfo(%s)" % m.q_ident(il[1])) if x[5]]
                        lead = keys[:len(pk)]
                        same = [(n, c) for n, c, _d in lead] == [(n, c) for n, c, _d in pk]
                        dirs = {d == pd for (_n, _c, d), (_pn, _pc, pd) in zip(lead, pk)}
                        self.assertTrue(same and len(dirs) == 1, "%s: index %s is not in the key's order: %s" % (label, ix, plan))
                ro.close()
                out, env = self.job("mo-%d" % k, "j%06d" % (400000 + k))
                r = self.export(path, "t", env, columns=["pin"])
                self.assertEqual(r.code, 0, "%s: %s" % (label, r.stdout[-400:]))
                self.assertEqual((r.json["table_kind"], r.json["n_ranks"]), (kind, ranks), label)
                lines, _end = self.values_lines(out)
                self.assertEqual([l["value"] for l in lines], truth, "%s: n follows the table's own order" % label)
                if kind == "rowid":
                    self.assertEqual(r.json["locator"], "rowid", label)
                else:
                    self.assertEqual([x["rowid"] for x in r.json["rows"]], [None] * 4, "%s: no rowid printed" % label)
                    for pin, _c, _n in MATRIX_ROWS:
                        self.assertNotIn(str(pin), r.stdout, label)

    def test_without_rowid_is_read_from_sqlite_or_from_the_statements_own_words(self):
        m = load_tool()
        for sql, want in (("CREATE TABLE t(a TEXT PRIMARY KEY, b) WITHOUT ROWID", True),
                          ("CREATE TABLE t(a TEXT PRIMARY KEY, b) STRICT, without\n  rowid", True),
                          ("CREATE TABLE t(a TEXT PRIMARY KEY, b DEFAULT 'x) WITHOUT ROWID')", False),
                          ('CREATE TABLE "without rowid)"(a TEXT PRIMARY KEY, b)', False),
                          ("CREATE TABLE t(a TEXT PRIMARY KEY, b /* ) WITHOUT ROWID */)", False),
                          ("CREATE TABLE t(a TEXT PRIMARY KEY, b) -- WITHOUT ROWID", False),
                          ("CREATE TABLE t(a TEXT PRIMARY KEY, [b) without rowid])", False)):
            self.assertEqual(m.declared_without_rowid(sql), want, sql)

        class NoTableList:
            def __init__(self, conn):
                self.conn = conn

            def execute(self, q, *a):
                if q.startswith("PRAGMA table_list"):
                    raise sqlite3.OperationalError("no such pragma")
                return self.conn.execute(q, *a)
        conn = sqlite3.connect(":memory:")
        conn.execute("create table w(rowid TEXT, oid TEXT, _rowid_ TEXT, k TEXT PRIMARY KEY) without rowid")
        conn.execute("create table r(rowid TEXT, oid TEXT, _rowid_ TEXT, k TEXT PRIMARY KEY)")
        sql = dict(conn.execute("select name, sql from sqlite_master where type = 'table'"))
        for wrap in (lambda c: c, NoTableList):
            self.assertIs(m.is_without_rowid(wrap(conn), "w", sql["w"]), True)
            self.assertIs(m.is_without_rowid(wrap(conn), "r", sql["r"]), False)
        conn.close()

    # --- B: a message that is not UTF-8 ------------------------------------------------------------------------------------

    def test_a_message_quoting_bytes_that_are_not_utf8_is_an_unreadable_cell_like_any_other(self):
        # Python cannot decode sqlite's message when it quotes such bytes and raises UnicodeDecodeError: the old tool stopped the
        # export there (row_count 1, exit 1), so where it stopped told which row held such bytes.
        answers = {}
        for label, second in (("plain", b"plain-two"), ("not_utf8", b"plain\xfftwo")):
            self.assertEqual(len(second), 9)
            db = self.make("%s.db" % label, ["create table t(s blob)"],
                           [("insert into t values(?)", (v,)) for v in (b"plain-one", second, b"plain-three")])
            self.with_generated(db, "json_extract('{}', s)")
            out, env = self.job("o-" + label, "j000310")
            r = self.export(db, "t", env)
            self.assertEqual(r.stderr, "")
            answers[label] = (r, out)
        plain, odd = answers["plain"][0], answers["not_utf8"][0]
        self.assertEqual((odd.code, odd.json["row_count"]), (plain.code, plain.json["row_count"]))
        self.assertEqual((odd.code, odd.json["row_count"]), (0, 3))
        for key in ("ok", "complete", "rows", "columns", "cells_not_exported", "cells_with_a_value", "secret_values", "stdout", "n_ranks"):
            self.assertEqual(odd.json.get(key), plain.json.get(key), key)
        lines, _end = self.values_lines(answers["not_utf8"][1])
        second = [l for l in lines if l["n"] == 2 and l["column"] == "h"][0]
        self.assertEqual(second["not_exported"], "unreadable")
        self.assertIn("UnicodeDecodeError", second["error_class"])
        self.assertIn("plain\\xfftwo", second["sqlite_message"], "the message is kept, its bytes escaped, in the values file only")

    # --- C: decisions on the code, never on the message -------------------------------------------------------------------

    def test_a_value_quoted_in_a_message_decides_nothing(self):
        # json_extract('{}', s) quotes s: the old tool read "interrupted", "not authorized" and "too big" in the message and
        # stopped the export as a time-out, as a refusal, or called the cell too large.
        for k, second in enumerate(("it was interrupted", "not authorized here", "authorization denied", "far too big a word",
                                    "string or blob too big")):
            db = self.make("c%d.db" % k, ["create table t(s text)"],
                           [("insert into t values(?)", (v,)) for v in ("plain value one", second, "plain value three")])
            self.with_generated(db, "json_extract('{}', s)")
            out, env = self.job("o%d" % k, "j00032%d" % k)
            r = self.export(db, "t", env)
            self.assertEqual(r.code, 0, "%r: %s" % (second, r.stdout[-300:]))
            self.assertEqual(r.json["row_count"], 3, second)
            self.assertNotIn("timed_out", r.json, second)
            self.assertEqual([x["cells"][1] for x in r.json["rows"]], ["unreadable"] * 3, second)
            self.assertEqual(r.json["cells_not_exported"]["cells"], {"unreadable": 3}, second)

    def test_the_code_decides_and_without_one_only_a_whole_fixed_message_does(self):
        m = load_tool()
        conn = sqlite3.connect(":memory:")
        self.addCleanup(conn.close)
        conn.execute("create table t(s text)")
        conn.execute("insert into t values('x')")
        conn.set_progress_handler(lambda: 1, 1)
        try:
            conn.execute("select count(*) from t, t as u").fetchall()
            self.fail("not interrupted")
        except sqlite3.Error as exc:
            if getattr(exc, "sqlite_errorcode", None) is not None:
                self.assertEqual(m.sqlite_code(exc), m.SQLITE_INTERRUPT)
            self.assertTrue(m.stops_the_export(exc))
        conn.set_progress_handler(None, 1)
        # A Python that gives no code (before 3.11): the exceptions below carry none, as such a Python's would.
        for text, code in (("interrupted", 9), ("string or blob too big", 18), ("not authorized", 23), ("authorization denied", 23),
                           ("bad JSON path: 'interrupted'", None), ("JSON path error near 'not authorized'", None),
                           ("malformed JSON", None), ("it was interrupted", None), ("interrupted 'x'", 9)):
            exc = sqlite3.OperationalError(text)
            self.assertIsNone(getattr(exc, "sqlite_errorcode", None))
            self.assertEqual(m.sqlite_code(exc), code, text)
            self.assertEqual(m.stops_the_export(exc), code in (9, 23), text)
            self.assertEqual(m.too_big(exc), code == 18, text)
        bad = UnicodeDecodeError("utf-8", b"bad JSON path: 'interrupted\xff'", 27, 28, "invalid start byte")
        self.assertIsNone(m.sqlite_code(bad))
        self.assertFalse(m.stops_the_export(bad))
        self.assertIn("interrupted\\xff", m.sqlite_text(bad))
        # A real code beats the text: an error whose message quotes "interrupted" is SQLITE_ERROR.
        conn.execute("ALTER TABLE t ADD COLUMN h TEXT GENERATED ALWAYS AS (json_extract('{}', s)) VIRTUAL")
        try:
            conn.execute("select h from t").fetchall()
        except sqlite3.Error as exc:
            self.assertFalse(m.stops_the_export(exc))
            self.assertFalse(m.too_big(exc))

    # --- P3: counts after a failure, the cell counts, the parts limit, what is left --------------------------------------

    def test_after_a_failed_write_every_count_is_what_the_file_holds(self):
        import resource
        db = self.make("many.db", ["create table t(s text, n integer)"],
                       [("insert into t values(?, ?)", ("value-%05d" % i if i % 3 else "not json %05d" % i, i)) for i in range(600)])
        self.with_generated(db, "json_extract(s, '$.a')", "g")
        out, env = self.job("o", "j000330")
        e = dict(os.environ)
        for key in ("JOB_ID", "OUT", "AGENT_ID", "SECRET_OUTPUT"):
            e.pop(key, None)
        e.update(env)
        proc = subprocess.run([sys.executable, tool_path("sqlite_query")], input=json.dumps({"db_path": db, "table": "t", "write_values": True}),
                              capture_output=True, text=True, cwd=self.dir, env=e, timeout=120,
                              preexec_fn=lambda: resource.setrlimit(resource.RLIMIT_FSIZE, (20000, 20000)))
        self.assertEqual(proc.stderr, "")
        j = json.loads(proc.stdout)
        self.assertEqual((proc.returncode, j["ok"], j["reason"], j["complete"]), (1, False, "values_file_error", False))
        data = self.read(os.path.join(out, "sqlite-query-values.jsonl"), "rb")
        whole = [json.loads(l) for l in data.split(b"\n")[:-1]]
        valued = sum(1 for l in whole if "value" in l)
        missing = collections.Counter(l["not_exported"] for l in whole if "not_exported" in l)
        holds = j["values_file_holds"]
        self.assertEqual((holds["cell_lines"], holds["values"], holds["not_exported"]), (len(whole), valued, dict(missing)))
        self.assertEqual(holds["last_row_with_a_whole_line"], whole[-1]["n"])
        self.assertEqual(holds["part_of_a_line_after"], not data.endswith(b"\n"))
        self.assertIs(holds["end_line"], False)
        self.assertEqual((j["cells_with_a_value"], j["secret_values"]["written"], j["secret_values"]["values"],
                          j["secret_values"]["not_exported"]), (valued, len(whole), valued, sum(missing.values())))
        self.assertTrue(j["values_file_state"].startswith("partial: "))
        self.assertIn("no end line", j["values_file_error"])
        self.assertIn("%d whole cell line(s)" % len(whole), j["values_file_state"])
        # row_count N: rows 1..N are in the locators file, and the stop is at N+1.
        located = self.locator_rows(out, j)
        self.assertEqual([x["n"] for x in located], list(range(1, j["row_count"] + 1)))
        self.assertEqual(j["rows_read_before_the_stop"], j["row_count"])

    def test_a_values_file_that_reads_whole_after_a_failed_sync_is_said_whole(self):
        db = self.make("t.db", ["create table t(v text)"], [("insert into t values(?)", ("value-%d" % i,)) for i in range(5)])
        out, env = self.job("o", "j000331")
        body = ("real = os.fsync\ncalls = []\n"
                "def fsync(fd):\n    calls.append(fd)\n    if len(calls) == 1:\n        raise OSError(errno.EIO, 'Input/output error')\n    return real(fd)\n"
                "m.os.fsync = fsync")
        proc = in_process(body, {"db_path": db, "table": "t", "write_values": True}, env, self.dir)
        j = json.loads(proc.stdout)
        self.assertEqual((proc.returncode, j["ok"], j["reason"]), (1, False, "values_file_error"))
        self.assertIn("EIO", j["values_file_error"])
        self.assertTrue(j["values_file_state"].startswith("whole: "), j["values_file_state"])
        self.assertNotIn("no end line", j["values_file_state"] + j["values_file_error"])
        self.assertIs(j["values_file_holds"]["end_line"], True)
        self.assertIs(j["secret_values"]["end_line_written"], True)
        lines, end = self.values_lines(out)
        self.assertEqual((len(lines), end["rows_read"]), (5, 5))

    def test_cells_with_a_value_count_only_cells_that_hold_one(self):
        db = self.make("gen.db", ["create table t(s text)"], [("insert into t values(?)", (v,)) for v in ("plain one", None, "plain three")])
        self.with_generated(db, "json_extract(s, '$.a')", "j")
        out, env = self.job("o", "j000332")
        r = self.export(db, "t", env)
        self.assertEqual(r.code, 0, r.stdout)
        # Row 2: s is NULL and j is NULL (json_extract of NULL); rows 1 and 3: s has a value, j cannot be computed.
        self.assertEqual([x["cells"] for x in r.json["rows"]], [["text:9", "unreadable"], ["null", "null"], ["text:11", "unreadable"]])
        self.assertEqual(r.json["cells_with_a_value"], 2)
        sv = r.json["secret_values"]
        self.assertEqual((sv["written"], sv["values"], sv["not_exported"], sv["contains_secret_values"]), (4, 2, 2, True))
        _lines, end = self.values_lines(out)
        self.assertEqual((end["cells_written"], end["cells_with_a_value"], end["cells_not_exported"]), (4, 2, {"unreadable": 2}))
        # Only cells that could not be computed: no value in the file, but sqlite's messages are, so it is secret all the same.
        out2, env2 = self.job("o2", "j000333")
        only = self.export(db, "t", env2, columns=["j", "s"], limit=1)
        self.assertEqual(only.json["cells_with_a_value"], 2)
        db2 = self.make("gen2.db", ["create table t(s text, k integer)"], [("insert into t values(?, ?)", ("plain", 1))])
        self.with_generated(db2, "json_extract(s, '$.a')", "j")
        out3, env3 = self.job("o3", "j000334")
        just = self.export(db2, "t", env3, columns=["j", "k"])
        self.assertEqual(just.code, 0, just.stdout)
        out4, env4 = self.job("o4", "j000335")
        db3 = self.make("gen3.db", ["create table t(s text)"], [("insert into t values(?)", ("plain",))])
        self.with_generated(db3, "json_extract(s, '$.a')", "j")
        conn = sqlite3.connect(db3)
        conn.execute("alter table t add column z text")
        conn.commit()
        conn.close()
        nothing = self.export(db3, "t", env4, columns=["j", "z"])
        self.assertEqual(nothing.code, 0, nothing.stdout)
        sv = nothing.json["secret_values"]
        self.assertEqual((nothing.json["cells_with_a_value"], sv["values"], sv["not_exported"], sv["contains_secret_values"]), (0, 0, 1, True))

    def test_a_row_is_charged_once_against_the_parts_limit(self):
        # Python's cursor steps to the next row before it hands over the current one, so a failing row made the old tool read
        # the row before it in parts too: the limit was spent twice per failing row.
        db = self.make("alt.db", ["create table t(s text)"], [("insert into t values(?)", ('{"a": %d}' % i if i % 2 == 0 else "plain %d" % i,)) for i in range(1200)])
        self.with_generated(db, "json_extract(s, '$.a')", "g")
        out, env = self.job("o", "j000336")
        r = self.export(db, "t", env)
        self.assertEqual(r.code, 0, r.stdout[-400:])
        self.assertEqual(r.json["row_count"], 1200)
        self.assertEqual(r.json["cells_not_exported"]["cells"], {"unreadable": 600})
        # With the limit made 5: five failing rows are read in parts, the sixth stops the export, and the sentence is true.
        out2, env2 = self.job("o2", "j000337")
        proc = in_process("m.PARTS_MAX = 5", {"db_path": db, "table": "t", "write_values": True}, env2, self.dir)
        j = json.loads(proc.stdout)
        self.assertEqual(j["reason"], "too_many_rows_read_in_parts")
        self.assertEqual(j["cells_not_exported"]["cells"], {"unreadable": 5})
        self.assertEqual(j["row_count"], 11, "rows 1..11 hold five failing rows (2, 4, ..., 10); row 12 is the sixth")
        self.assertIn("5 rows had a cell", j["error"])

    def test_a_temporary_locators_file_that_cannot_be_removed_is_said(self):
        db = self.make("t.db", ["create table t(v text)"], [("insert into t values(?)", ("value-%d" % i,)) for i in range(3)])
        out, env = self.job("o", "j000338")
        body = ("real = os.unlink\n"
                "def unlink(p, *a, **k):\n    if os.path.basename(str(p)).startswith('.sqlite_query-'):\n        raise OSError(errno.EPERM, 'Operation not permitted')\n"
                "    return real(p, *a, **k)\n"
                "m.os.unlink = unlink\nm.Path.unlink = lambda self, *a, **k: unlink(str(self))")
        proc = in_process(body, {"db_path": db, "table": "t", "write_values": True}, env, self.dir)
        j = json.loads(proc.stdout)
        left = [n for n in os.listdir(os.path.join(out, "tool-output")) if n.startswith(".sqlite_query-")]
        self.assertEqual(len(left), 1)
        self.assertIn(left[0], j.get("locators_file_left", ""), "what remains is named")
        self.assertNotIn("none is left", j.get("locators_file_error", ""))
        self.assertEqual(len(self.locator_rows(out, j)), 3, "the locators file itself is published")


class SqliteQueryValuesFinal(Case):
    """The final delta review of #144: each test fails on the pack as it was at 7afea4cb (PACK_DIR pointed at a copy of it). Truth
    comes from SQLite itself (its query plans, a collation the test registers when it writes the table) and from JSON's own rules
    for how long an escape can be."""

    job, export, make = SqliteQueryValuesDelta.job, SqliteQueryValuesDelta.export, SqliteQueryValuesDelta.make
    values_lines, with_generated = SqliteQueryValuesDelta.values_lines, SqliteQueryValuesDelta.with_generated

    # --- P2: the skill's fallback query outside a job --------------------------------------------------------------------

    def test_the_skills_fallback_query_reads_the_table_not_an_index_on_the_secret_column(self):
        skill = self.read(os.path.join(os.path.dirname(tool_path("sqlite_query")), "..", "..", "skills", "data", "sqlite-secrets.md"))
        fallback = next(p for p in skill.split("\n\n") if p.startswith("**Fallback"))
        self.assertIn("(`rowid`, `length(col)`, `typeof(col)`) `FROM t NOT INDEXED ORDER BY rowid`", fallback)
        self.assertIn("WITHOUT ROWID", fallback)
        self.assertIn("INTEGER PRIMARY KEY", fallback)
        # rowid order is not the values' order, and an index on the secret column covers the locator query.
        db = self.make("cookies.db", ["create table cookies(host text, value text)", "create index ix_value on cookies(value)"],
                       [("insert into cookies values(?, ?)", ("h%d" % i, v)) for i, v in enumerate(["zz-secret-1", "aa-secret-2", "mm-secret-3", "bb-secret-4"])])
        conn = sqlite3.connect(db)
        plain = "SELECT rowid, length(value), typeof(value) FROM cookies"
        self.assertIn("COVERING INDEX", " ".join(r[3] for r in conn.execute("EXPLAIN QUERY PLAN " + plain)))
        self.assertEqual([r[0] for r in conn.execute(plain)], [2, 4, 3, 1], "without the clause the rowids come ranked by the values")
        skills = plain + " NOT INDEXED ORDER BY rowid"
        plan = " ".join(r[3] for r in conn.execute("EXPLAIN QUERY PLAN " + skills))
        self.assertNotIn("INDEX", plan)
        self.assertNotIn("TEMP B-TREE", plan)
        conn.close()
        r = run_tool("sqlite_query", {"db_path": db, "sql": skills}, self.dir)
        self.assertEqual(r.code, 0, r.stdout)
        self.assertEqual([row["values"][0] for row in r.json["rows"]], [1, 2, 3, 4])
        # WITHOUT ROWID: ordered by its primary key, never by the index on the secret column.
        wr = self.make("wr.db", ["create table t(k text primary key, value text) without rowid", "create index ixv on t(value)"],
                       [("insert into t values(?, ?)", ("k%d" % i, v)) for i, v in enumerate(["zz", "aa", "mm"])])
        conn = sqlite3.connect(wr)
        plan = " ".join(r[3] for r in conn.execute("EXPLAIN QUERY PLAN SELECT length(value), typeof(value) FROM t NOT INDEXED ORDER BY k"))
        self.assertNotIn("ixv", plan)
        self.assertNotIn("TEMP B-TREE", plan)
        conn.close()

    # --- P3-1: where the values file stops does not depend on how a value escapes ----------------------------------------

    def test_where_the_values_file_stops_depends_on_no_values_content(self):
        answers = {}
        cap = 30000
        for label, first in (("ascii", "a" * 1000), ("control", "\x01" * 1000), ("quote", '"' * 1000), ("two_byte", "é" * 500),
                             ("astral", "\U0001F600" * 250)):
            db = self.make("cap-%s.db" % label, ["create table t(s text)"],
                           [("insert into t values(?)", (first,))] + [("insert into t values(?)", ("b" * 1000,))] * 39)
            # The same path for every database, as the twins of the review: the answer names it.
            same = self.path("inputs", "ev.db")
            if os.path.exists(same):
                os.unlink(same)
            os.link(db, same)
            out, env = self.job("o-" + label, "j000400")
            proc = in_process("m.FILE_BYTES = %d\nm.LOCATORS_BYTES = 10 ** 9" % cap, {"db_path": same, "table": "t", "write_values": True}, env, self.dir)
            j = json.loads(proc.stdout)
            self.assertLessEqual(os.path.getsize(os.path.join(out, "sqlite-query-values.jsonl")), cap)
            for k in ("database_sha256", "locators_file", "earlier_answers"):
                j.pop(k, None)
            answers[label] = j
        first = answers["ascii"]
        self.assertTrue(first.get("values_file_stopped_at_row"), first)
        for label, j in answers.items():
            self.assertEqual({k: j.get(k) for k in ("values_file_stopped_at_row", "cells_with_a_value", "resume", "row_count")},
                             {k: first.get(k) for k in ("values_file_stopped_at_row", "cells_with_a_value", "resume", "row_count")}, label)
            self.assertEqual(j, first, "the whole answer is the same: %s" % label)

    def test_a_cells_reserve_is_never_less_than_its_line_and_follows_only_its_type_and_length(self):
        import random
        m = load_tool()
        rnd = random.Random(144)
        pools = ["a", "\x00", "\x01", "\x1f", '"', "\\", "/", "é", " ", "￿", "\U0001F600", " ", "z"]

        def line(finding, locator, v):
            if isinstance(v, m.NotExported):
                extra = {"error_class": v.error, "sqlite_message": v.message} if v.error else {}
                return len(json.dumps({"finding_id": finding, **locator, "not_exported": v.why, **extra}) + "\n")
            if isinstance(v, bytes):
                return len(json.dumps({"finding_id": finding, **locator, "value": {"blob_b64": base64.b64encode(v).decode("ascii")}}) + "\n")
            return len(json.dumps({"finding_id": finding, **locator, "value": m.value_json(v)}) + "\n")

        for i in range(3000):
            pick = rnd.randrange(7)
            if pick == 0:
                v = "".join(rnd.choice(pools) for _ in range(rnd.randrange(60)))
            elif pick == 1:
                v = bytes(rnd.randrange(256) for _ in range(rnd.randrange(60)))
            elif pick == 2:
                raw = bytes(rnd.randrange(256) for _ in range(1 + rnd.randrange(60))) + b"\xff"
                v = m.text_factory(raw)
            elif pick == 3:
                v = rnd.choice([0, -1, 2 ** 63 - 1, -2 ** 63, rnd.randrange(-10 ** 12, 10 ** 12)])
            elif pick == 4:
                v = rnd.choice([0.1, -1e300, 1e-310, float("nan"), float("inf"), float("-inf"), rnd.random()])
            elif pick == 5:
                v = m.NotExported("unreadable", "unreadable", None, rnd.choice(["OperationalError SQLITE_ERROR", "UnicodeDecodeError (sqlite's message is not UTF-8)"]),
                                  "".join(rnd.choice(pools) for _ in range(rnd.randrange(80))))
            else:
                v = m.NotExported("value_too_large", rnd.choice(["text", "blob"]), rnd.choice([None, 70000000]))
            kind, length = m.value_kind(v)
            locator = {"table": rnd.choice(["t", "ta\"ble", "ét\x01"]), "rowid": rnd.choice([None, 7, -2 ** 63]), "n": 1 + i,
                       "column": rnd.choice(["c", "c\nol"]), "type": kind, "length": length}
            finding = "V%07d" % (1 + i)
            self.assertGreaterEqual(m.line_reserve(finding, locator, v), line(finding, locator, v), repr(v))
        # Same type and length, different content: the same reserve.
        loc = {"table": "t", "rowid": None, "n": 1, "column": "c", "type": "text", "length": 6}
        self.assertEqual(len({m.line_reserve("V0000001", loc, s) for s in ("aaaaaa", "\x01" * 6, '"' * 6, "é" * 3, "\U0001F600" + "ab")}), 1)
        loc = dict(loc, type="text_not_utf8", length=4)
        self.assertEqual(m.line_reserve("V0000001", loc, m.text_factory(b"\xff\xfe\xfd\xfc")),
                         m.line_reserve("V0000001", loc, m.text_factory(b"ab\xffc")))

    # --- P3-2: a WITHOUT ROWID key under an application's collation --------------------------------------------------------

    def collated(self, name, ddl, keys):
        path = self.path("inputs", name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        conn = sqlite3.connect(path)
        for coll in ("LOCALIZED", "UNICODE"):
            conn.create_collation(coll, lambda a, b: (a < b) - (a > b))      # reverse: the stored order is no byte order
        for st in ddl:
            conn.execute(st)
        for k in keys:
            conn.execute("insert into t(k, v, s) values(?, ?, ?)", k)
        conn.commit()
        conn.close()
        return path

    def test_a_key_under_an_applications_collation_is_read_in_its_stored_order(self):
        keys = [("apple", "v-apple", '{"a": 1}'), ("zebra", "v-zebra", "not json"), ("kiwi", "v-kiwi", '{"a": 3}'), ("mango", "v-mango", '{"a": 4}')]
        db = self.collated("loc.db", ["create table t(k text collate LOCALIZED primary key, v text, s text) without rowid", "create index iv on t(v)"], keys)
        out, env = self.job("o", "j000410")
        r = self.export(db, "t", env, columns=["k", "v"])
        self.assertEqual(r.code, 0, r.stdout)
        self.assertEqual((r.json["table_kind"], r.json["n_ranks"], r.json["row_count"]), ("without_rowid", ["k"], 4))
        self.assertEqual(r.json["collations_stood_in"]["names"], ["LOCALIZED"])
        lines, end = self.values_lines(out)
        self.assertTrue(end["complete"], end)
        self.assertEqual([l["value"] for l in lines if l["column"] == "k"], ["zebra", "mango", "kiwi", "apple"], "the application's order, as stored")
        # SQLite walks the table: no sort, no index, whatever the stand-in compares.
        m = load_tool()
        conn = sqlite3.connect("file:%s?mode=ro&immutable=1" % db, uri=True)
        self.assertEqual(m.stand_in_collations(conn, "t"), ["LOCALIZED"])
        info = list(conn.execute("PRAGMA table_xinfo(t)"))
        stmt, _p = m.export_statement("t", "without_rowid", {"order_by": m.primary_key_order(conn, "t", info)[1]}, '"k"')
        plan = " ".join(str(x[3]) for x in conn.execute("EXPLAIN QUERY PLAN " + stmt))
        self.assertNotIn("TEMP B-TREE", plan)
        self.assertNotIn("iv", plan)
        conn.close()
        # A composite key, the second part under another application collation and descending.
        db2 = self.collated("uni.db", ["create table t(k text, v text collate UNICODE, s text, primary key(k, v desc)) without rowid"],
                            [("a", "v1", "x"), ("a", "v3", "x"), ("b", "v2", "x")])
        out2, env2 = self.job("o2", "j000411")
        r2 = self.export(db2, "t", env2, columns=["k", "v"])
        self.assertEqual(r2.code, 0, r2.stdout)
        self.assertEqual(r2.json["collations_stood_in"]["names"], ["UNICODE"])
        lines2, _end = self.values_lines(out2)
        self.assertEqual([(l["n"], l["value"]) for l in lines2 if l["column"] == "v"], [(1, "v1"), (2, "v3"), (3, "v2")])

    def test_a_collation_missing_outside_the_key_is_named_as_the_schemas_doing(self):
        db = self.collated("gen.db", ["create table t(k text primary key, v text, s text) without rowid"], [("a", "v1", "x"), ("b", "v2", "y")])
        self.with_generated(db, "s < 'm' COLLATE LOCALIZED", "g")
        out, env = self.job("o", "j000412")
        r = self.export(db, "t", env, columns=["g"])
        self.assertEqual(r.code, 1, r.stdout)
        self.assertEqual(r.json["reason"], "missing_collation")
        self.assertIn("names a collation this SQLite does not have", r.json["error"])
        self.assertNotIn("can depend on a value", r.json["error"])
        _lines, end = self.values_lines(out)
        self.assertIn("LOCALIZED", end["sqlite_message"])
        m = load_tool()
        self.assertTrue(m.missing_collation(sqlite3.OperationalError("no such collation sequence: LOCALIZED")), "Python before 3.11: the fixed words")
        self.assertFalse(m.missing_collation(sqlite3.OperationalError("bad JSON path: 'no such collation sequence: x'")))

    # --- P3-3: a virtual table is what SQLite says, whatever its statement's text ----------------------------------------

    def test_a_virtual_table_with_a_comment_in_its_statement_is_still_virtual(self):
        for module in ("fts5", "fts4"):
            path = self.path("inputs", "vt-%s.db" % module)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            conn = sqlite3.connect(path)
            conn.execute("create virtual table v using %s(body)" % module)
            for docid, body in ((482915, "secret one"), (613377, "secret two"), (771203, "secret three")):
                conn.execute("insert into v(rowid, body) values (?, ?)", (docid, body))
            conn.commit()
            conn.execute("pragma writable_schema = 1")
            sql = conn.execute("select sql from sqlite_master where name = 'v'").fetchone()[0]
            conn.execute("update sqlite_master set sql = ? where name = 'v'", (sql.replace("CREATE VIRTUAL TABLE", "CREATE /* x */ VIRTUAL TABLE", 1),))
            conn.commit()
            conn.close()
            out, env = self.job("o-" + module, "j00042%d" % len(module))
            r = self.export(path, "v", env)
            self.assertEqual(r.stderr, "")
            if r.code == 0:
                self.assertEqual((r.json["table_kind"], r.json["locator"]), ("virtual", "n"), module)
            else:
                self.assertEqual(r.json["reason"], "virtual_table_unsupported", r.stdout)
            for docid in ("482915", "613377", "771203"):
                self.assertNotIn(docid, r.stdout, "a docid the application set is never printed (%s)" % module)
            out2, env2 = self.job("o2-" + module, "j00043%d" % len(module))
            ranged = self.export(path, "v", env2, rowid_from=600000)
            self.assertEqual(ranged.code, 1, ranged.stdout)
            self.assertIn(ranged.json["reason"], ("virtual_table", "virtual_table_unsupported"))
            self.assertNotIn("613377", ranged.stdout)
        # Where PRAGMA table_list is missing (SQLite before 3.37): the statement with its comments blanked, or no b-tree.
        m = load_tool()

        class NoTableList:
            def execute(self, *_a):
                raise sqlite3.OperationalError("unknown pragma")

        self.assertTrue(m.is_virtual(NoTableList(), "v", "CREATE /* x */ VIRTUAL TABLE v USING fts5(body)", 9))
        self.assertTrue(m.is_virtual(NoTableList(), "v", "CREATE TABLE v(body)", 0))
        self.assertFalse(m.is_virtual(NoTableList(), "v", "CREATE TABLE v(body DEFAULT 'CREATE VIRTUAL TABLE')", 2))

    # --- P3-4: OUT that is not a directory is said as such ---------------------------------------------------------------

    def test_an_out_that_is_not_a_directory_is_said_as_such(self):
        db = self.make("t.db", ["create table t(v text)"], [("insert into t values('value-1')", ())])
        nowhere = self.path("nowhere")
        dangling = self.path("out-dangling")
        os.symlink(nowhere, dangling)
        r = self.export(db, "t", {"JOB_ID": "j000440", "OUT": dangling, "SECRET_OUTPUT": "1"})
        self.assertEqual((r.code, r.stderr), (1, ""))
        self.assertIn("OUT is a link to nothing", r.json["error"])
        self.assertNotIn("already exists", r.json["error"])
        self.assertFalse(os.path.lexists(nowhere))
        plain = self.path("out-file")
        with open(plain, "w") as fh:
            fh.write("x")
        r = self.export(db, "t", {"JOB_ID": "j000441", "OUT": plain, "SECRET_OUTPUT": "1"})
        self.assertEqual((r.code, r.stderr), (1, ""))
        self.assertIn("OUT is not a directory", r.json["error"])
        self.assertNotIn("already exists", r.json["error"])
        self.assertEqual(self.read(plain), "x")


class SqliteQueryStatus(Case):
    """Every answer carries `status` (complete, partial or failed) and a one-sentence `status_basis`, with `ok` and `complete`
    kept for the readers that use them (docs/packs.md, "The tool contract")."""

    def db(self, rows=5):
        path = self.path("s.db")
        conn = sqlite3.connect(path)
        conn.execute("create table t(x)")
        conn.executemany("insert into t values(?)", [(i,) for i in range(rows)])
        conn.commit()
        conn.close()
        return path

    def pair(self, r, status):
        self.assertIsNotNone(r.json, r.stdout + r.stderr)
        self.assertEqual(r.json.get("status"), status, r.json)
        basis = r.json.get("status_basis")
        self.assertTrue(isinstance(basis, str) and len(basis) > 20 and basis.count(".") <= 1, basis)

    def test_a_clean_run_is_complete(self):
        r = run_tool("sqlite_query", {"db_path": self.db(), "sql": "select x from t"}, self.dir)
        self.pair(r, "complete")
        self.assertEqual((r.json["ok"], r.json["complete"]), (True, True))

    def test_a_row_budget_page_is_complete_when_the_file_holds_the_whole(self):
        r = run_tool("sqlite_query", {"db_path": self.db(50), "sql": "select x from t", "limit": 1}, self.dir)
        self.pair(r, "complete")
        self.assertTrue(r.json["truncated"])
        self.assertIn("rows_file", r.json)
        self.assertIn("rows_file", r.json["status_basis"])

    def test_a_page_whose_file_stopped_at_its_cap_is_partial_and_not_complete(self):
        out = in_process("m.FILE_BYTES = 300", {"db_path": self.db(2000), "sql": "select x from t", "limit": 1}, {}, self.dir)
        j = json.loads(out.stdout)
        self.assertTrue(j["truncated"] and j.get("rows_file_stopped_at_row"), j)
        self.assertEqual((j["status"], j["complete"], j["ok"]), ("partial", False, True), j)
        self.assertIn("rows_file", j["status_basis"])

    def test_a_clock_stop_is_partial(self):
        sql = "with recursive c(x) as (select 1 union all select x+1 from c) select count(*) from c"
        r = run_tool("sqlite_query", {"db_path": self.db(), "sql": sql, "max_seconds": 1}, self.dir, timeout=60)
        self.pair(r, "partial")
        self.assertEqual((r.json["ok"], r.json["complete"], r.json.get("timed_out")), (False, False, True))

    def test_a_refused_statement_and_malformed_sql_are_failed(self):
        db = self.db()
        for sql in ("delete from t", "select from from", "select load_extension('x')", "pragma user_version=3"):
            r = run_tool("sqlite_query", {"db_path": db, "sql": sql}, self.dir)
            self.pair(r, "failed")
            self.assertIs(r.json["ok"], False, sql)

    def test_every_refusal_of_main_is_failed_with_the_pair(self):
        db = self.db()
        for args in ({}, {"db_path": db}, {"db_path": self.path("nope.db"), "sql": "select 1"}, {"db_path": db, "sql": "select 1", "limit": 0},
                     {"db_path": db, "sql": "select 1", "max_seconds": "x"}, {"db_path": db, "sql": "select 1", "csv": "no"},
                     {"db_path": db, "sql": "select 1", "readonly": False}, {"db_path": db, "sql": "select 1", "apply_wal": True},
                     {"db_path": db, "sql": "x\0y"}, {"db_path": self.dir, "sql": "select 1"}, {"db_path": db, "sql": " "}):
            r = run_tool("sqlite_query", args, self.dir)
            self.pair(r, "failed")
            self.assertEqual(r.code, 1, args)
        self.write("empty.db", b"")
        self.pair(run_tool("sqlite_query", {"db_path": self.path("empty.db"), "sql": "select 1"}, self.dir), "failed")
        self.write("text.db", b"not sqlite at all, just text" * 40)
        self.pair(run_tool("sqlite_query", {"db_path": self.path("text.db"), "sql": "select 1"}, self.dir), "failed")
        self.pair(run_tool("sqlite_query", None, self.dir, raw_input="{not json"), "failed")
        self.pair(run_tool("sqlite_query", None, self.dir, raw_input="[1]"), "failed")
        self.pair(run_tool("sqlite_query", None, self.dir, raw_input="[" * 100000), "failed")

    def values_job(self, rows=3, **env_extra):
        path = self.path("inputs/v.db")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        conn = sqlite3.connect(path)
        conn.execute("create table t(a text, b text)")
        conn.executemany("insert into t values(?, ?)", [("a%d" % i, "b%d" % i) for i in range(rows)])
        conn.commit()
        conn.close()
        out = self.path("job-out")
        os.makedirs(out, exist_ok=True)
        return path, out, dict({"JOB_ID": "j000900", "OUT": out, "SECRET_OUTPUT": "1"}, **env_extra)

    def test_a_values_file_job_is_complete_and_a_refused_one_failed(self):
        db, out, env = self.values_job()
        r = run_tool("sqlite_query", {"db_path": db, "table": "t", "write_values": True}, self.dir, env=env)
        self.pair(r, "complete")
        self.assertEqual((r.json["ok"], r.json["complete"], r.json["mode"]), (True, True, "values_to_file"))
        outside = run_tool("sqlite_query", {"db_path": db, "table": "t", "write_values": True}, self.dir)
        self.pair(outside, "failed")
        self.assertEqual(outside.json["write_values"], "refused")
        absent = run_tool("sqlite_query", {"db_path": db, "table": "nothing_here", "write_values": True}, self.dir, env=dict(env, JOB_ID="j000901"))
        self.pair(absent, "failed")

    def test_a_values_file_that_stopped_at_its_cap_is_partial(self):
        db, out, env = self.values_job(rows=60)
        proc = in_process("m.FILE_BYTES = 1500\nm.LOCATORS_BYTES = 10 ** 9", {"db_path": db, "table": "t", "write_values": True}, env, self.dir)
        j = json.loads(proc.stdout)
        self.assertTrue(j.get("values_file_stopped_at_row"), j)
        self.assertEqual((j["status"], j["complete"]), ("partial", False), j)
        self.assertIn("values_file_stopped_at_row", j["status_basis"])
        self.assertNotIn("a1", j["status_basis"])

    def test_an_unexpected_error_is_a_failed_answer_with_the_pair_not_a_traceback(self):
        db = self.db()
        # The tool runs as __main__ with its statement splitter replaced by one that raises, the way an unforeseen error would.
        child = subprocess.run([sys.executable, "-c",
                                "import importlib.util, sys\n"
                                "spec = importlib.util.spec_from_file_location('__main__', sys.argv[1])\n"
                                "m = importlib.util.module_from_spec(spec)\n"
                                "src = open(sys.argv[1]).read().replace('def statements(', 'def statements_unused(', 1) + '\\ndef statements(*a, **k):\\n    raise KeyError(\"secret-looking-text\")\\n'\n"
                                "sys.argv = [sys.argv[1]]\n"
                                "exec(compile(src, sys.argv[0], 'exec'), {'__name__': '__main__', '__file__': sys.argv[0]})\n",
                                tool_path("sqlite_query")], input=json.dumps({"db_path": db, "sql": "select 1"}), capture_output=True, text=True,
                               cwd=self.dir, timeout=60)
        self.assertNotIn("Traceback", child.stderr)
        j = json.loads(child.stdout)
        self.assertEqual((j["status"], j["ok"]), ("failed", False), j)
        self.assertNotIn("secret-looking-text", child.stdout)
        self.assertEqual(child.returncode, 1)


if __name__ == "__main__":
    unittest.main()
