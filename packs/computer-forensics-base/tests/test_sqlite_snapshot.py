"""sqlite_snapshot: the set is copied whole and hashed, the WAL is read against the format and applied only in a copy.

The databases and their write-ahead logs are made by Python's sqlite3 module, the engine itself: a writer is kept open (so the last
connection's close does not checkpoint and delete the WAL) while the files are copied, as an acquisition of a live database would
copy them. What a frame count must be is worked out here from the documented WAL layout (a 32-byte header, then 24-byte frame
headers and page images; a frame is a commit when its database-size field is not zero), never from the tool's own output. A
big-endian WAL is written by hand from the format's checksum rule, and SQLite itself is the judge of it.
"""
import hashlib
import io
import json
import os
import shutil
import signal
import sqlite3
import struct
import subprocess
import sys
import time
import unittest

from support import Case, run_tool, tool_path


def sha(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def wal_layout(path):
    """(page size, [(page number, commit size)] of every whole frame): the WAL file read by its documented layout."""
    with open(path, "rb") as fh:
        data = fh.read()
    page = struct.unpack(">I", data[8:12])[0]
    frames = []
    stride = 24 + page
    for at in range(32, len(data) - stride + 1, stride):
        pgno, commit = struct.unpack(">II", data[at:at + 8])
        frames.append((pgno, commit))
    return page, frames


def checksum(data, big, s0=0, s1=0):
    fmt = (">" if big else "<") + "%dI" % (len(data) // 4)
    words = struct.unpack(fmt, data)
    for i in range(0, len(words), 2):
        s0 = (s0 + words[i] + s1) & 0xFFFFFFFF
        s1 = (s1 + words[i + 1] + s0) & 0xFFFFFFFF
    return s0, s1


class Snapshot(Case):
    def live_set(self, name, build, copy_as=None):
        """Run `build(conn)` on a WAL-mode database whose connection stays open, copy db, -wal and -shm to inputs/<copy_as>, close, and
        return the copy's path. `build` receives the connection with autocheckpoint off."""
        src = self.path("live", name)
        os.makedirs(os.path.dirname(src), exist_ok=True)
        conn = sqlite3.connect(src, isolation_level=None)
        conn.execute("pragma journal_mode=wal")
        conn.execute("pragma wal_autocheckpoint=0")
        build(conn)
        dst = self.path("inputs", copy_as or name)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        for suffix in ("", "-wal", "-shm"):
            if os.path.exists(src + suffix):
                shutil.copy(src + suffix, dst + suffix)
        conn.close()
        return dst

    def snap(self, db, out="work/snap", **kw):
        return run_tool("sqlite_snapshot", dict({"db_path": db, "out_dir": out}, **kw), self.dir)

    def rows(self, db, sql="select x from a order by x"):
        conn = sqlite3.connect("file:%s?mode=ro&immutable=1" % db, uri=True)
        try:
            return [r[0] for r in conn.execute(sql)]
        finally:
            conn.close()

    @staticmethod
    def three_commits(conn):
        conn.execute("create table a(x)")
        conn.execute("insert into a values(1)")
        conn.execute("pragma wal_checkpoint(truncate)")               # row 1 is in the main file
        conn.execute("insert into a values(2)")                        # rows 2 and 3 are committed, in the WAL only
        conn.execute("insert into a values(3)")

    # ---- a good set ----

    def test_the_wal_is_applied_in_a_copy_and_the_originals_are_the_bytes_that_were_there(self):
        db = self.live_set("a.db", self.three_commits)
        before = {s: sha(db + s) for s in ("", "-wal", "-shm")}
        listing = sorted(os.listdir(self.path("inputs")))
        page, frames = wal_layout(db + "-wal")
        r = self.snap(db)
        self.assertEqual(r.code, 0, r.stdout + r.stderr)
        j = r.json
        self.assertEqual(j["status"], "complete", j)
        for s in ("", "-wal", "-shm"):
            self.assertEqual(sha(db + s), before[s], "the evidence was changed")
            self.assertEqual(sha(self.path("work/snap/original/database.sqlite" + s)), before[s], "the copy is not the bytes that were there")
        self.assertEqual(sorted(os.listdir(self.path("inputs"))), listing, "something was written beside the evidence")
        files = {f["name"]: f for f in j["files"]}
        self.assertEqual(files["database.sqlite-wal"]["sha256"], before["-wal"])
        self.assertIs(files["database.sqlite"]["changed_during_copy"], False)
        # the frames, from the documented layout
        commits = [i for i, (_p, c) in enumerate(frames, 1) if c]
        self.assertEqual(j["wal"]["frames_in_file"], len(frames))
        self.assertEqual(j["wal"]["frames_valid"], len(frames))
        self.assertEqual(j["wal"]["frames_committed"], commits[-1])
        self.assertIs(j["wal"]["checksums_verified"], True)
        self.assertEqual(j["wal"]["page_size"], page)
        self.assertEqual(j["wal"]["checksum_byte_order"], "little-endian" if sys.byteorder == "little" else "big-endian")
        # the state: the main file has row 1 only; the applied copy has all three
        self.assertEqual(self.rows(db), [1])
        self.assertEqual(self.rows(self.path("work/snap/original/database.sqlite")), [1])
        self.assertEqual(j["database"], "applied/database.sqlite")
        self.assertEqual(self.rows(self.path("work/snap", j["database"])), [1, 2, 3])
        self.assertIs(j["applied"]["applied"], True)
        self.assertIs(j["applied"]["counts_agree"], True)
        self.assertEqual(j["applied"]["frames_in_wal_by_sqlite"], commits[-1])
        self.assertGreaterEqual(j["applied"]["pages_of_the_main_file_changed_by_the_wal"], 1)
        self.assertEqual(j["applied"]["files_left_in_applied"], [])
        self.assertEqual(sorted(os.listdir(self.path("work/snap/applied"))), ["database.sqlite"])
        self.assertEqual(j["database_sha256"], sha(self.path("work/snap/applied/database.sqlite")))
        self.assertIs(j["wal_applied"], True)

    def test_the_snapshot_is_private_and_writes_a_receipt(self):
        db = self.live_set("a.db", self.three_commits)
        self.snap(db)
        for rel in ("work/snap", "work/snap/original", "work/snap/applied"):
            self.assertEqual(os.stat(self.path(rel)).st_mode & 0o777, 0o700, rel)
        for rel in ("snapshot.json", "original/database.sqlite", "original/database.sqlite-wal", "applied/database.sqlite"):
            self.assertEqual(os.stat(self.path("work/snap", rel)).st_mode & 0o777, 0o600, rel)
        receipt = json.loads(self.read("work/snap/snapshot.json"))
        self.assertEqual(receipt["status"], "complete")
        self.assertEqual(receipt["tool"]["name"], "sqlite_snapshot")

    def test_a_set_with_no_wal_is_a_copy_and_says_there_was_nothing_to_apply(self):
        path = self.path("inputs/plain.db")
        os.makedirs(os.path.dirname(path))
        conn = sqlite3.connect(path)
        conn.executescript("create table a(x); insert into a values(7);")
        conn.commit()
        conn.close()
        r = self.snap(path)
        self.assertEqual(r.code, 0, r.stdout)
        self.assertEqual(r.json["status"], "complete")
        self.assertIsNone(r.json["wal"])
        self.assertIs(r.json["applied"]["applied"], False)
        self.assertIn("no -wal", r.json["applied"]["why"])
        self.assertEqual(r.json["database"], "original/database.sqlite")
        self.assertIs(r.json["wal_applied"], False)
        self.assertEqual(self.rows(self.path("work/snap", r.json["database"])), [7])
        self.assertFalse(os.path.exists(self.path("work/snap/applied")))

    def test_apply_wal_false_copies_and_reads_and_applies_nothing(self):
        db = self.live_set("a.db", self.three_commits)
        r = self.snap(db, apply_wal=False)
        self.assertEqual(r.code, 0)
        self.assertIs(r.json["wal_applied"], False)
        self.assertEqual(r.json["database"], "original/database.sqlite")
        self.assertGreater(r.json["wal"]["frames_committed"], 0)
        self.assertFalse(os.path.exists(self.path("work/snap/applied")))

    # ---- a WAL the format does not call whole ----

    @staticmethod
    def each_row_a_commit(conn):
        conn.execute("create table a(x, pad)")
        conn.execute("pragma wal_checkpoint(truncate)")
        for i in (1, 2, 3):
            conn.execute("insert into a values(?, ?)", (i, "p" * 3000))             # one commit each, three pages' worth in all

    def test_a_damaged_frame_ends_the_valid_chain_and_sqlite_agrees_with_the_count(self):
        db = self.live_set("a.db", self.each_row_a_commit)
        page, frames = wal_layout(db + "-wal")
        self.assertGreaterEqual(len(frames), 3)
        stride = 24 + page
        raw = bytearray(self.read(db + "-wal", "rb"))
        # damage the page image of the third frame: its checksum no longer matches
        raw[32 + 2 * stride + 24 + 100] ^= 0xFF
        self.write("inputs/a.db-wal", bytes(raw))
        r = self.snap(db)
        self.assertEqual(r.code, 0, r.stdout)
        j = r.json
        self.assertEqual(j["wal"]["frames_in_file"], len(frames))
        self.assertEqual(j["wal"]["frames_valid"], 2)
        self.assertEqual(j["wal"]["first_invalid_frame"]["frame"], 3)
        self.assertIn("checksum mismatch", j["wal"]["first_invalid_frame"]["reason"])
        self.assertEqual(j["status"], "partial")
        self.assertTrue(any("frame 3" in p for p in j["problems"]), j["problems"])
        committed = max([i for i, (_p, c) in enumerate(frames[:2], 1) if c] or [0])
        self.assertEqual(j["wal"]["frames_committed"], committed)
        if committed:
            self.assertIs(j["applied"]["counts_agree"], True, "SQLite and the tool must read the same valid prefix")
            self.assertEqual(j["applied"]["frames_in_wal_by_sqlite"], committed)

    def test_a_wal_that_ends_inside_a_frame_is_said(self):
        db = self.live_set("a.db", self.each_row_a_commit)
        page, frames = wal_layout(db + "-wal")
        raw = self.read(db + "-wal", "rb")
        self.write("inputs/a.db-wal", raw[:len(raw) - 1000])
        r = self.snap(db)
        self.assertEqual(r.code, 0, r.stdout)
        wal = r.json["wal"]
        self.assertEqual(wal["frames_in_file"], len(frames) - 1)
        self.assertEqual(wal["trailing_partial_frame_bytes"], page + 24 - 1000)
        self.assertIn("ends inside", wal["first_invalid_frame"]["reason"])
        self.assertEqual(r.json["status"], "partial")

    def test_a_wal_header_that_fails_its_own_checksum_is_ignored_as_sqlite_ignores_it(self):
        db = self.live_set("a.db", self.three_commits)
        raw = bytearray(self.read(db + "-wal", "rb"))
        raw[16] ^= 0x01                         # salt-1: inside the 24 bytes the header checksum covers
        self.write("inputs/a.db-wal", bytes(raw))
        r = self.snap(db)
        self.assertEqual(r.code, 0, r.stdout)
        self.assertIs(r.json["wal"]["valid_header"], False)
        self.assertIn("checksum", r.json["wal"]["state"])
        self.assertIs(r.json["applied"]["applied"], False)
        self.assertEqual(r.json["database"], "original/database.sqlite")
        self.assertEqual(r.json["status"], "partial")
        self.assertEqual(self.rows(self.path("work/snap", r.json["database"])), [1])

    def test_frames_of_an_earlier_generation_after_a_restart_are_noted_not_applied(self):
        def build(conn):
            conn.execute("create table a(x, pad)")
            for i in range(1, 7):
                conn.execute("insert into a values(?, ?)", (i, "q" * 3000))
            conn.execute("pragma wal_checkpoint(restart)")                  # the next writer starts the WAL over, on top of the old frames
            conn.execute("insert into a values(100, 'new generation')")
        db = self.live_set("a.db", build)
        page, frames = wal_layout(db + "-wal")
        r = self.snap(db)
        self.assertEqual(r.code, 0, r.stdout)
        wal = r.json["wal"]
        self.assertGreater(wal["frames_in_file"], wal["frames_valid"], "the old generation's frames should still be in the file")
        self.assertIn("salt mismatch", wal["first_invalid_frame"]["reason"])
        self.assertEqual(r.json["status"], "complete", "a leftover of an earlier generation is normal, not a defect")
        self.assertTrue(any("earlier generation" in n for n in r.json["notes"]))
        self.assertIs(r.json["applied"]["counts_agree"], True)
        self.assertEqual(self.rows(self.path("work/snap", r.json["database"]), "select x from a where x = 100"), [100])

    def test_valid_frames_after_the_last_commit_are_reported_and_never_applied(self):
        def build(conn):
            conn.execute("create table a(x, pad)")
            conn.execute("insert into a values(1, 'committed')")
            conn.execute("pragma wal_checkpoint(truncate)")
            conn.execute("pragma cache_size=2")                             # a small cache forces an open transaction's pages into the WAL
            conn.execute("begin")
            for i in range(200):
                conn.execute("insert into a values(?, ?)", (1000 + i, "u" * 2000))
        db = self.live_set("a.db", build)
        page, frames = wal_layout(db + "-wal")
        trailing = len(frames) - max([i for i, (_p, c) in enumerate(frames, 1) if c] or [0])
        self.assertGreater(trailing, 0, "the fixture should have uncommitted frames in the WAL")
        r = self.snap(db)
        self.assertEqual(r.code, 0, r.stdout)
        self.assertEqual(r.json["wal"]["frames_uncommitted_valid"], trailing)
        self.assertTrue(any("not committed" in n for n in r.json["notes"]))
        rows = self.rows(self.path("work/snap", r.json["database"]), "select count(*) from a where x >= 1000")
        self.assertEqual(rows, [0], "an uncommitted transaction's rows are not applied")

    def test_a_big_endian_wal_is_read_in_its_byte_order_and_agrees_with_sqlite(self):
        db = self.live_set("a.db", self.three_commits)
        raw = self.read(db + "-wal", "rb")
        page, frames = wal_layout(db + "-wal")
        stride = 24 + page
        # rewrite the same frames with the big-endian magic (0x377f0683) and big-endian checksums, from the format's rule
        salt1, salt2 = raw[16:20], raw[20:24]
        head = struct.pack(">IIIII", 0x377F0683, 3007000, page, struct.unpack(">I", raw[12:16])[0], 0)[:16] + salt1 + salt2
        c0, c1 = checksum(head, True)
        out = bytearray(head + struct.pack(">II", c0, c1))
        for i in range(len(frames)):
            frame = raw[32 + i * stride:32 + (i + 1) * stride]
            fh = frame[:8] + salt1 + salt2
            c0, c1 = checksum(fh[:8], True, c0, c1)
            c0, c1 = checksum(frame[24:], True, c0, c1)
            out += fh + struct.pack(">II", c0, c1) + frame[24:]
        self.write("inputs/a.db-wal", bytes(out))
        # SQLite is the judge: opened as it is, a big-endian WAL gives the same rows
        shutil.copy(db, self.path("judge.db"))
        shutil.copy(db + "-wal", self.path("judge.db-wal"))
        judge = sqlite3.connect(self.path("judge.db"))
        expected = [r[0] for r in judge.execute("select x from a order by x")]
        judge.close()
        self.assertEqual(expected, [1, 2, 3])
        r = self.snap(db)
        self.assertEqual(r.code, 0, r.stdout)
        self.assertEqual(r.json["wal"]["checksum_byte_order"], "big-endian")
        self.assertEqual(r.json["wal"]["frames_valid"], len(frames))
        self.assertIs(r.json["applied"]["counts_agree"], True)
        self.assertEqual(self.rows(self.path("work/snap", r.json["database"])), expected)

    def test_a_commit_that_claims_a_database_of_billions_of_pages_is_not_applied(self):
        db = self.live_set("a.db", self.three_commits)
        raw = bytearray(self.read(db + "-wal", "rb"))
        page, frames = wal_layout(db + "-wal")
        stride = 24 + page
        big = sys.byteorder == "big"
        # the last commit frame says the database has 0x7ffffff0 pages; every frame's checksum is written again, from the format's rule,
        # so that the frame is valid and only the claim is hostile
        last = max(i for i, (_p, c) in enumerate(frames) if c)
        raw[32 + last * stride + 4:32 + last * stride + 8] = struct.pack(">I", 0x7FFFFFF0)
        s0, s1 = checksum(bytes(raw[:24]), big)
        for i in range(len(frames)):
            at = 32 + i * stride
            s0, s1 = checksum(bytes(raw[at:at + 8]), big, s0, s1)
            s0, s1 = checksum(bytes(raw[at + 24:at + stride]), big, s0, s1)
            raw[at + 16:at + 24] = struct.pack(">II", s0, s1)
        self.write("inputs/a.db-wal", bytes(raw))
        r = self.snap(db, max_bytes=50 * 1024 * 1024)
        self.assertEqual(r.code, 0, r.stdout)
        self.assertEqual(r.json["wal"]["frames_valid"], len(frames))
        self.assertEqual(r.json["wal"]["database_pages_after_last_commit"], 0x7FFFFFF0)
        self.assertIs(r.json["applied"]["applied"], False)
        self.assertTrue(any("more than max_bytes" in p for p in r.json["problems"]), r.json["problems"])
        self.assertEqual(r.json["status"], "partial")
        self.assertFalse(os.path.exists(self.path("work/snap/applied")))

    def test_a_hot_rollback_journal_is_copied_reported_and_not_rolled_back(self):
        path = self.path("inputs/j.db")
        os.makedirs(os.path.dirname(path))
        conn = sqlite3.connect(path)
        conn.executescript("create table a(x); insert into a values(1);")
        conn.commit()
        conn.close()
        # a rollback journal's header, as the file format defines it: the 8-byte magic, then the page count, nonce, size and sector fields
        self.write("inputs/j.db-journal", bytes([0xD9, 0xD5, 0x05, 0xF9, 0x20, 0xA1, 0x63, 0xD7]) + struct.pack(">IIIII", 0xFFFFFFFF, 1234, 1, 512, 4096) + b"\0" * 480)
        r = self.snap(path)
        self.assertEqual(r.code, 0, r.stdout)
        self.assertEqual(sha(self.path("work/snap/original/database.sqlite-journal")), sha(path + "-journal"))
        self.assertIn("header present", r.json["rollback_journal"]["state"])
        self.assertIs(r.json["rollback_journal"]["applied"], False)
        self.assertEqual(r.json["status"], "partial")
        self.assertEqual(sha(self.path("work/snap/original/database.sqlite")), sha(path), "the journal must not have been rolled back into the copy")

    def test_a_zeroed_journal_is_not_a_hot_one(self):
        path = self.path("inputs/j.db")
        os.makedirs(os.path.dirname(path))
        conn = sqlite3.connect(path)
        conn.executescript("create table a(x); insert into a values(1);")
        conn.commit()
        conn.close()
        self.write("inputs/j.db-journal", b"\0" * 512)
        r = self.snap(path)
        self.assertIn("not a hot journal", r.json["rollback_journal"]["state"])
        self.assertEqual(r.json["status"], "complete")

    # ---- what the tool refuses, and how ----

    def test_a_file_that_is_not_sqlite_is_refused_with_its_first_bytes_and_makes_no_directory(self):
        self.write("inputs/x.db", b'{"this": "is json"}' * 40)
        r = self.snap(self.path("inputs/x.db"))
        self.assertEqual(r.code, 1)
        self.assertIn("not a SQLite file", r.json["error"])
        self.assertIn("another format", r.json["reading"])
        self.assertFalse(os.path.exists(self.path("work/snap")))
        self.write("inputs/e.db", os.urandom(8192))
        r = self.snap(self.path("inputs/e.db"))
        self.assertEqual(r.code, 1)
        self.assertIn("not identified", r.json["reading"])
        self.write("inputs/z.db", b"")
        self.assertEqual(self.snap(self.path("inputs/z.db")).code, 1)
        self.assertEqual(self.snap(self.path("inputs/missing.db")).code, 1)

    def test_an_out_dir_that_exists_is_refused_and_a_set_over_the_budget_is_refused_before_a_byte_is_copied(self):
        db = self.live_set("a.db", self.three_commits)
        os.makedirs(self.path("work/snap"))
        r = self.snap(db)
        self.assertEqual(r.code, 1)
        self.assertIn("already exists", r.json["error"])
        r = self.snap(db, out="work/other", max_bytes=5000)
        self.assertEqual(r.code, 1)
        self.assertIn("max_bytes", r.json["error"])
        self.assertFalse(os.path.exists(self.path("work/other")))

    def test_in_a_job_the_default_is_under_out_a_second_run_is_new_and_outside_is_refused(self):
        db = self.live_set("a.db", self.three_commits)
        out = self.path("store/jobs/j1/out")
        os.makedirs(out)
        env = {"JOB_ID": "j1", "OUT": out}
        one = run_tool("sqlite_snapshot", {"db_path": db}, self.dir, env=env)
        two = run_tool("sqlite_snapshot", {"db_path": db}, self.dir, env=env)
        self.assertEqual((one.code, two.code), (0, 0), one.stdout + two.stdout)
        self.assertNotEqual(one.json["snapshot_dir"], two.json["snapshot_dir"])
        for r in (one, two):
            self.assertTrue(os.path.realpath(self.path(r.json["snapshot_dir"])).startswith(os.path.realpath(out)))
        bad = run_tool("sqlite_snapshot", {"db_path": db, "out_dir": "work/elsewhere"}, self.dir, env=env)
        self.assertEqual(bad.code, 1)
        self.assertIn("$OUT", bad.json["error"])
        self.assertFalse(os.path.exists(self.path("work")))
        again = run_tool("sqlite_snapshot", {"db_path": db}, self.dir)
        self.assertEqual(again.code, 0, again.stdout)
        self.assertTrue(again.json["snapshot_dir"].startswith("work/"), again.json["snapshot_dir"])

    def test_bad_arguments_and_a_token_shaped_path_are_json_answers_that_do_not_echo_the_token(self):
        db = self.live_set("a.db", self.three_commits)
        for args in ({}, {"db_path": ""}, {"db_path": 4}, {"db_path": db, "max_bytes": 0}, {"db_path": db, "apply_wal": "yes"}, {"db_path": db, "bogus": 1},
                     {"db_path": "bad\udcff.db"}):
            r = run_tool("sqlite_snapshot", args, self.dir)
            self.assertEqual(r.code, 1, args)
            self.assertNotIn("Traceback", r.stderr)
            self.assertIsNotNone(r.json, args)
        token = "ghp_" + "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5"
        r = run_tool("sqlite_snapshot", {"db_path": "inputs/" + token + ".db"}, self.dir)
        self.assertEqual(r.code, 1)
        self.assertNotIn(token, r.stdout + r.stderr)
        r = run_tool("sqlite_snapshot", None, self.dir, raw_input="nope")
        self.assertEqual(r.code, 1)

    def test_a_link_is_followed_to_its_real_files_for_the_sidecars(self):
        db = self.live_set("a.db", self.three_commits)
        os.symlink(os.path.basename(db), self.path("inputs/link.db"))
        r = self.snap(self.path("inputs/link.db"))
        self.assertEqual(r.code, 0, r.stdout)
        self.assertIn("database.sqlite-wal", {f["name"] for f in r.json["files"]})
        self.assertIsNotNone(r.json["source"]["real_path"])
        self.assertEqual(self.rows(self.path("work/snap", r.json["database"])), [1, 2, 3])

    def test_a_file_that_changes_while_it_is_copied_is_said(self):
        import contextlib
        import importlib.util
        db = self.live_set("a.db", self.three_commits)
        spec = importlib.util.spec_from_file_location("ss", tool_path("sqlite_snapshot"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        real_copy = mod.copy_hashing

        def copy_then_grow(src, dst, deadline, left):
            out = real_copy(src, dst, deadline, left)
            if src.endswith("-wal"):
                with open(src, "ab") as fh:
                    fh.write(b"\0" * 64)               # the live database wrote more after the copy had read it
            return out
        mod.copy_hashing = copy_then_grow
        old = [signal.getsignal(s) for s in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)]
        sys.stdin = io.StringIO(json.dumps({"db_path": db, "out_dir": "work/snap"}))
        out = io.StringIO()
        cwd = os.getcwd()
        os.chdir(self.dir)
        try:
            with contextlib.redirect_stdout(out):
                try:
                    mod.main()
                except SystemExit as exc:
                    code = exc.code
        finally:
            os.chdir(cwd)
            sys.stdin = sys.__stdin__
            for s, h in zip((signal.SIGTERM, signal.SIGINT, signal.SIGHUP), old):
                signal.signal(s, h)
        got = json.loads(out.getvalue())
        self.assertEqual(code, 0)
        wal = [f for f in got["files"] if f["name"].endswith("-wal")][0]
        self.assertIs(wal["changed_during_copy"], True)
        self.assertEqual(got["status"], "partial")
        self.assertTrue(any("changed while it was copied" in p for p in got["problems"]))

    def test_a_sigterm_during_the_copy_leaves_an_interrupted_receipt(self):
        path = self.path("inputs/big.db")
        os.makedirs(os.path.dirname(path))
        head = bytearray(100)
        head[:16] = b"SQLite format 3\x00"
        head[16:18] = struct.pack(">H", 4096)
        head[18] = head[19] = 1
        head[21:24] = bytes([64, 32, 32])
        with open(path, "wb") as fh:
            fh.write(bytes(head))
            fh.truncate(768 * 1024 * 1024)
        proc = subprocess.Popen([sys.executable, tool_path("sqlite_snapshot")], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=self.dir,
                                env={k: v for k, v in os.environ.items() if k not in ("JOB_ID", "OUT")})
        proc.stdin.write(json.dumps({"db_path": path, "out_dir": "work/snap"}).encode())
        proc.stdin.close()
        partial = self.path("work/snap/original/database.sqlite.partial")
        for _ in range(4000):
            if os.path.exists(partial) and os.path.getsize(partial) > 0:
                break
            if proc.poll() is not None:
                break
            time.sleep(0.002)
        if proc.poll() is not None:
            proc.stdout.close()
            proc.stderr.close()
            self.skipTest("the copy finished before the signal could be sent")
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=30)
        proc.stdout.close()
        proc.stderr.close()
        self.assertEqual(proc.returncode, 143)
        receipt = json.loads(self.read("work/snap/snapshot.json"))
        self.assertEqual(receipt["status"], "interrupted")

    def test_no_program_is_started_and_nothing_in_a_session_of_its_own(self):
        text = self.read(tool_path("sqlite_snapshot"))
        code = "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))
        for word in ("subprocess", "start_new_session", "setsid", "os.system", "Popen"):
            self.assertNotIn(word, code)

    def test_a_wal_that_is_a_link_is_listed_and_not_followed_as_the_entry_says(self):
        db = self.live_set("a.db", self.three_commits)
        real_wal = self.path("elsewhere-wal")
        shutil.move(db + "-wal", real_wal)
        os.symlink(real_wal, db + "-wal")
        r = self.snap(db)
        files = {f["name"]: f for f in r.json["files"]}
        self.assertIs(files["database.sqlite-wal"]["copied"], False)
        self.assertIn("a link or a directory", files["database.sqlite-wal"]["error"])
        self.assertTrue([p for p in r.json["problems"] if "not a regular file" in p], r.json["problems"])
        self.assertNotEqual(r.json["status"], "complete")
        self.assertFalse(os.path.exists(self.path("work/snap/original/database.sqlite-wal")), "what the link points at was not copied")


class SqliteQueryOnASnapshot(Case):
    """sqlite_query takes a snapshot's directory or its database, says which state the rows are, and checks the file against the receipt."""

    def make(self):
        src = self.path("live/a.db")
        os.makedirs(os.path.dirname(src))
        conn = sqlite3.connect(src, isolation_level=None)
        conn.execute("pragma journal_mode=wal")
        conn.execute("pragma wal_autocheckpoint=0")
        conn.execute("create table a(x)")
        conn.execute("insert into a values(1)")
        conn.execute("pragma wal_checkpoint(truncate)")
        conn.execute("insert into a values(2)")
        os.makedirs(self.path("inputs"))
        for suffix in ("", "-wal", "-shm"):
            shutil.copy(src + suffix, self.path("inputs/a.db" + suffix))
        conn.close()
        r = run_tool("sqlite_snapshot", {"db_path": self.path("inputs/a.db"), "out_dir": "work/snap"}, self.dir)
        self.assertEqual(r.code, 0, r.stdout)
        return r.json

    def query(self, db, sql="select x from a order by x", **kw):
        return run_tool("sqlite_query", dict({"db_path": db, "sql": sql}, **kw), self.dir)

    def test_the_snapshot_directory_is_queried_at_the_applied_state_and_says_so(self):
        self.make()
        r = self.query("work/snap")
        self.assertEqual(r.code, 0, r.stdout)
        self.assertEqual([row["values"][0] for row in r.json["rows"]], [1, 2])
        self.assertIn("SNAPSHOT", r.json["snapshot_status"])
        self.assertIn("WAL applied", r.json["snapshot_status"])
        self.assertNotIn("WAL NOT APPLIED", r.json["snapshot_status"])
        self.assertIs(r.json["snapshot"]["wal_applied"], True)
        self.assertIs(r.json["snapshot"]["file_matches_recorded_sha256"], True)
        self.assertEqual(r.json["snapshot"]["queried"], "applied/database.sqlite")
        self.assertEqual(r.json["database_opened"], "work/snap/applied/database.sqlite")
        self.assertEqual(r.json["db_path"], "work/snap")

    def test_the_database_inside_the_snapshot_is_the_same_answer_and_the_original_copy_says_its_wal_is_not_applied(self):
        self.make()
        applied = self.query("work/snap/applied/database.sqlite")
        self.assertEqual([row["values"][0] for row in applied.json["rows"]], [1, 2])
        original = self.query("work/snap/original/database.sqlite")
        self.assertEqual([row["values"][0] for row in original.json["rows"]], [1])
        self.assertIn("WAL NOT APPLIED", original.json["snapshot_status"])
        self.assertIn("applied/database.sqlite", original.json["snapshot_status"])
        self.assertIn("sqlite_snapshot", original.json["snapshot_status"])

    def test_a_file_changed_after_the_snapshot_is_said_not_trusted(self):
        self.make()
        conn = sqlite3.connect(self.path("work/snap/applied/database.sqlite"))
        conn.execute("insert into a values(99)")
        conn.commit()
        conn.close()
        r = self.query("work/snap")
        self.assertEqual(r.code, 0, r.stdout)
        self.assertIs(r.json["snapshot"]["file_matches_recorded_sha256"], False)
        self.assertIn("NOT THE ONE THE SNAPSHOT RECORDED", r.json["snapshot_status"])

    def test_a_directory_that_is_not_a_snapshot_is_still_not_a_file(self):
        os.makedirs(self.path("work/dir"))
        self.write("work/dir/snapshot.json", json.dumps({"tool": {"name": "something_else"}}))
        r = self.query("work/dir")
        self.assertEqual(r.code, 1)
        self.assertIn("not a regular file", r.json["error"])

    def test_apply_wal_is_an_error_that_names_the_tool_that_does_it(self):
        path = self.path("a.db")
        conn = sqlite3.connect(path)
        conn.executescript("create table a(x); insert into a values(1);")
        conn.commit()
        conn.close()
        r = self.query(path, apply_wal=True)
        self.assertEqual(r.code, 1)
        self.assertIn("sqlite_snapshot", r.json["error"])

    def test_the_plain_wal_message_names_the_tool_that_applies_it(self):
        src = self.path("w.db")
        w = sqlite3.connect(src)
        w.execute("pragma journal_mode=wal")
        w.execute("pragma wal_autocheckpoint=0")
        w.execute("create table a(x)")
        w.execute("insert into a values(1)")
        w.commit()
        try:
            r = self.query(src)
        finally:
            w.close()
        self.assertIn("WAL NOT APPLIED", r.json["snapshot_status"])
        self.assertIn("sqlite_snapshot", r.json["snapshot_status"])


if __name__ == "__main__":
    unittest.main()
