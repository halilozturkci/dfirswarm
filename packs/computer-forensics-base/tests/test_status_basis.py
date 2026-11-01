"""Every answer of a tool carries `status` and `status_basis` (docs/packs.md, "The tool contract"): what the status rests on, in one sentence."""
import json
import os
import unittest

from support import Case, run_tool

WORDS = {"complete", "partial", "failed"}


class StatusBasis(Case):
    def check(self, name, args, **kw):
        r = run_tool(name, args, self.dir, **kw)
        self.assertIsNotNone(r.json, "%s: %s %s" % (name, r.stdout[:200], r.stderr[-200:]))
        self.assertIn(r.json.get("status"), WORDS, name)
        self.assertTrue(isinstance(r.json.get("status_basis"), str) and len(r.json["status_basis"]) > 20, "%s has no status_basis" % name)
        return r

    def test_the_scanners_and_the_single_shot_tools_say_what_their_status_rests_on(self):
        blob = self.write("work/blob.bin", b"\0" * 64 + b"needle" + b"\0" * 64 + b"PK\x03\x04" + b"\0" * 64)
        self.assertEqual(self.check("ioc_scan", {"path": blob, "needles": "needle"}).json["status"], "complete")
        self.assertEqual(self.check("chunk_needles", {"path": blob, "needles": "needle"}).json["status"], "complete")
        self.assertEqual(self.check("sig_carve", {"path": blob}).json["status"], "complete")
        self.assertEqual(self.check("file_type", {"path": blob}).json["status"], "complete")
        self.assertEqual(self.check("timestamp_decode", {"value": "1700000000"}).json["status"], "complete")
        self.write("inputs.json", json.dumps({"files": []}))
        self.assertEqual(self.check("check_inputs", {}).json["status"], "complete")
        self.write("catalog/Disk.E01/p2048/filelist.txt", "r/r 5-128-1:\tUsers/a/file.log\n")
        self.write("catalog/Disk.E01/partitions.txt", "002:  000:000   0000002048   ...   NTFS\n")
        self.assertEqual(self.check("catalog_search", {"pattern": "file"}).json["status"], "complete")
        db = self.path("s.db")
        import sqlite3
        conn = sqlite3.connect(db)
        conn.execute("create table t(x)")
        conn.commit()
        conn.close()
        self.assertEqual(self.check("sqlite_query", {"db_path": db, "sql": "select * from t"}).json["status"], "complete")

    def test_the_two_query_tools_say_failed_on_nothing_and_on_a_missing_path(self):
        for name, args in (("catalog_search", {}), ("catalog_search", {"pattern": "x", "catalog": "nowhere"}),
                           ("sqlite_query", {}), ("sqlite_query", {"db_path": "missing.db", "sql": "select 1"})):
            r = self.check(name, args)
            self.assertEqual((r.json["status"], r.json["ok"]), ("failed", False), (name, args))

    def test_every_refusal_of_twelve_tools_is_one_json_answer_with_the_status_pair_and_exit_1(self):
        # given nothing, a missing path, and a wrong type: JSON on stdout, status failed, a sentence for the basis, exit 1, no traceback
        missing = {
            "ad1_extract": "image", "archive_extract": "path", "chunk_needles": "path", "feature_scan": "path", "file_type": "path",
            "icat_extract": "image", "image_layout": "image", "ioc_scan": "path", "sig_carve": "path", "sqlite_snapshot": "db_path",
            "timeline_super": "out_dir", "timestamp_decode": "value",
        }
        for name, param in missing.items():
            cases = [("{}", {}), ("a missing path", {param: "work/does-not-exist"}), ("a wrong type", {param: 5})]
            if name == "icat_extract":
                cases[1] = ("a missing path", {param: "work/does-not-exist.dd", "inode": 5, "output": "work/out.bin"})
            if name == "timestamp_decode":
                cases[1] = ("a value that is no number", {param: "not a number"})
                cases[2] = ("a wrong type", {param: {"x": 1}})
            for label, args in cases:
                r = run_tool(name, args, self.dir)
                where = "%s given %s: exit %s, stdout %r, stderr %r" % (name, label, r.code, r.stdout[:120], r.stderr[-160:])
                self.assertIsNotNone(r.json, where)
                self.assertEqual(r.code, 1, where)
                self.assertEqual(r.json.get("status"), "failed", where)
                basis = r.json.get("status_basis")
                self.assertTrue(isinstance(basis, str) and len(basis) > 20 and "\n" not in basis, where)
                self.assertNotIn("Traceback", r.stderr, where)

    def test_a_name_that_is_not_utf8_is_a_name_not_a_crash(self):
        name = os.fsdecode(b"name-\xff.bin")
        open(os.path.join(self.dir, name), "wb").write(b"x")
        r = run_tool("image_layout", {"image": name}, self.dir)
        self.assertIsNotNone(r.json, "stdout %r, stderr %r" % (r.stdout[:120], r.stderr[-200:]))
        self.assertNotIn("Traceback", r.stderr)
        self.assertIn(r.json.get("status"), WORDS)

    def test_a_refusal_says_failed_and_why(self):
        r = run_tool("file_carver", {"path": self.write("work/x.bin", b"\0" * 64), "offset": 0, "sig_type": "PNG"}, self.dir)
        self.assertEqual((r.json["status"], r.json["ok"]), ("failed", False))
        self.assertIn("error", r.json["status_basis"])


if __name__ == "__main__":
    unittest.main()
