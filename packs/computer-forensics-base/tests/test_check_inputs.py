"""check_inputs: a manifest is checked whole, a size-only check is not a pass, and a long hash leaves receipts.

The manifest entries follow the shape the harness writes (path, bytes, sha256, link, special,
path_b64); digests are worked out with hashlib here.
"""
import base64
import hashlib
import json
import os
import unittest

from support import Case, run_tool


def sha(data):
    return hashlib.sha256(data).hexdigest()


class CheckInputs(Case):
    def manifest(self, files, **extra):
        self.write("inputs.json", json.dumps(dict({"files": files}, **extra)))

    def check(self, **kw):
        return run_tool("check_inputs", kw, self.dir)

    def test_a_clean_set_passes_and_every_file_has_a_receipt(self):
        a, b = b"alpha", b"beta bytes"
        self.write("inputs/a.bin", a)
        self.write("inputs/sub/b.bin", b)
        self.manifest([{"path": "inputs/a.bin", "bytes": 5, "sha256": sha(a)}, {"path": "inputs/sub/b.bin", "bytes": 10, "sha256": sha(b)}])
        r = self.check()
        self.assertEqual((r.code, r.json["status"], r.json["checked"], r.json["bytes_hashed"]), (0, "OK", 2, 15))
        rows = [json.loads(x) for x in self.read(r.json["receipts_file"]).splitlines()]
        self.assertEqual([(x["path"], x["result"]) for x in rows], [("inputs/a.bin", "ok"), ("inputs/sub/b.bin", "ok")])
        self.assertEqual(rows[0]["sha256"], sha(a))
        for key in ("modified", "missing", "added"):
            self.assertEqual(r.json[key], [])

    def test_a_missing_digest_is_a_failure_not_a_size_check(self):
        self.write("inputs/a.bin", b"alpha")
        self.manifest([{"path": "inputs/a.bin", "bytes": 5}])
        r = self.check()
        self.assertEqual((r.code, r.json["ok"]), (1, False))
        self.assertEqual(r.json["digest_missing"], ["inputs/a.bin"])
        self.assertIn("size matches", json.loads(self.read(r.json["receipts_file"]).splitlines()[0])["result"])

    def test_a_duplicate_path_and_malformed_entries_are_reported_not_skipped(self):
        self.write("inputs/a.bin", b"alpha")
        good = {"path": "inputs/a.bin", "bytes": 5, "sha256": sha(b"alpha")}
        self.manifest([good, dict(good), "not an object", {"bytes": 5}, {"path": "inputs/x", "bytes": 5, "sha256": "short"},
                       {"path": "inputs/y", "sha256": sha(b"")}, {"path": "inputs/l", "link": "target", "sha256": "x"}, {"path": "inputs/s", "special": "nonsense"}])
        r = self.check()
        self.assertEqual(r.code, 1)
        self.assertEqual(r.json["duplicates"], ["inputs/a.bin"])
        whys = {m.get("path") or m["index"]: m["why"] for m in r.json["malformed"]}
        self.assertIn("not an object", whys[2])
        self.assertIn("no readable path", whys[3])
        self.assertIn("64 hexadecimal", whys["inputs/x"])
        self.assertIn("no valid size", whys["inputs/y"])
        self.assertIn("special is not one of", whys["inputs/s"])
        self.assertNotIn("inputs/l", whys)                    # a link with a target is fine

    def test_a_file_that_cannot_be_opened_is_reported_and_the_rest_are_still_checked(self):
        if os.geteuid() == 0:
            self.skipTest("root reads every file")
        self.write("inputs/a.bin", b"alpha")
        locked = self.write("inputs/locked.bin", b"zzz")
        self.manifest([{"path": "inputs/locked.bin", "bytes": 3, "sha256": sha(b"zzz")}, {"path": "inputs/a.bin", "bytes": 5, "sha256": sha(b"alpha")}])
        os.chmod(locked, 0)
        try:
            r = self.check()
        finally:
            os.chmod(locked, 0o644)
        self.assertEqual(r.code, 1)
        self.assertEqual([u["path"] for u in r.json["unreadable"]], ["inputs/locked.bin"])
        results = {json.loads(x)["path"]: json.loads(x)["result"] for x in self.read(r.json["receipts_file"]).splitlines()}
        self.assertEqual(results["inputs/a.bin"], "ok")

    def test_a_hash_that_outruns_its_budget_leaves_a_receipt_and_is_not_a_pass(self):
        small = b"alpha"
        self.write("inputs/a.bin", small)
        big = self.path("inputs/big.bin")
        with open(big, "wb") as fh:
            fh.truncate(6 * 1024 ** 3)                      # sparse: reading it takes long, storing it takes nothing
        self.manifest([{"path": "inputs/a.bin", "bytes": 5, "sha256": sha(small)}, {"path": "inputs/big.bin", "bytes": 6 * 1024 ** 3, "sha256": sha(b"x")}])
        r = self.check(max_seconds=1)
        self.assertEqual((r.code, r.json["status"]), (1, "FAIL"))
        self.assertEqual(r.json["not_checked"], ["inputs/big.bin"])
        rows = {json.loads(x)["path"]: json.loads(x)["result"] for x in self.read(r.json["receipts_file"]).splitlines()}
        self.assertEqual(rows["inputs/a.bin"], "ok")
        self.assertIn("time budget", rows["inputs/big.bin"])

    def test_a_name_that_is_not_utf8_is_found_by_its_bytes(self):
        raw = b"inputs/caf\xe9.txt"
        os.makedirs(self.path("inputs"), exist_ok=True)
        try:
            with open(os.path.join(self.dir.encode(), raw), "wb") as fh:
                fh.write(b"latin1 name")
        except OSError:
            self.skipTest("this file system will not hold a name that is not UTF-8")
        self.manifest([{"path": raw.decode("utf-8", "replace"), "path_b64": base64.b64encode(raw).decode(), "bytes": 11, "sha256": sha(b"latin1 name")}])
        r = self.check()
        self.assertEqual((r.code, r.json["missing"], r.json["added"]), (0, [], []))

    def test_links_and_special_files_are_checked_as_what_they_are(self):
        os.makedirs(self.path("inputs"))
        os.symlink("target", self.path("inputs/l"))
        os.mkfifo(self.path("inputs/p"))
        self.manifest([{"path": "inputs/l", "link": "target", "bytes": 0, "sha256": "x"}, {"path": "inputs/p", "special": "fifo", "bytes": 0, "sha256": "y"}])
        self.assertEqual(self.check().code, 0)
        os.unlink(self.path("inputs/l"))
        os.symlink("elsewhere", self.path("inputs/l"))
        os.unlink(self.path("inputs/p"))
        self.write("inputs/p", b"now a file")
        r = self.check()
        self.assertEqual(sorted(r.json["modified"]), ["inputs/l", "inputs/p"])

    def test_an_added_file_and_a_changed_file_fail(self):
        self.write("inputs/a.bin", b"alpha")
        self.manifest([{"path": "inputs/a.bin", "bytes": 5, "sha256": sha(b"alpha")}])
        self.write("inputs/new.bin", b"planted")
        self.write("inputs/a.bin", b"ALPHA")
        r = self.check()
        self.assertEqual((r.json["added"], r.json["modified"]), (["inputs/new.bin"], ["inputs/a.bin"]))

    def test_no_manifest_is_a_failure(self):
        r = self.check()
        self.assertEqual((r.code, r.json["error"]), (1, "inputs.json not found"))

    def test_a_name_that_is_not_utf8_does_not_stop_the_receipts_and_is_reported(self):
        raw = b"inputs/caf\xe9.txt"
        self.manifest([{"path": raw.decode("utf-8", "replace"), "path_b64": base64.b64encode(raw).decode(), "bytes": 11, "sha256": sha(b"x")}])
        r = self.check()
        self.assertEqual(r.code, 1)
        self.assertEqual(len(r.json["missing"]), 1)
        rows = [json.loads(x) for x in self.read(r.json["receipts_file"]).splitlines()]
        self.assertEqual([x["result"] for x in rows], ["missing"])

    def test_two_checks_in_one_directory_keep_two_receipt_files(self):
        self.write("inputs/a.bin", b"alpha")
        self.manifest([{"path": "inputs/a.bin", "bytes": 5, "sha256": sha(b"alpha")}])
        first = self.check().json["receipts_file"]
        second = self.check().json["receipts_file"]
        self.assertNotEqual(first, second)
        self.assertEqual(len(self.read(first).splitlines()), 1)
        self.assertEqual(len(self.read(second).splitlines()), 1)

    def test_a_directory_that_cannot_be_listed_is_unreadable_and_not_a_pass(self):
        if os.geteuid() == 0:
            self.skipTest("root lists every directory")
        self.write("inputs/a.bin", b"alpha")
        locked = self.path("inputs/locked")
        os.makedirs(locked)
        self.manifest([{"path": "inputs/a.bin", "bytes": 5, "sha256": sha(b"alpha")}])
        os.chmod(locked, 0)
        try:
            r = self.check()
        finally:
            os.chmod(locked, 0o755)
        self.assertEqual((r.code, r.json["ok"]), (1, False))
        self.assertEqual([u["path"] for u in r.json["unreadable"]], ["inputs/locked"])

    def test_a_budget_beyond_the_tools_own_time_limit_is_refused(self):
        self.manifest([])
        r = self.check(max_seconds=7200)
        self.assertEqual(r.code, 1)
        self.assertIn("from 1 to 1700", r.json["error"])

    def test_an_entry_that_points_outside_inputs_is_malformed_and_is_never_hashed(self):
        self.write("inputs/a.bin", b"alpha")
        self.write("outside.txt", b"not evidence")
        good = {"path": "inputs/a.bin", "bytes": 5, "sha256": sha(b"alpha")}
        self.manifest([good, {"path": "inputs/../outside.txt", "bytes": 12, "sha256": sha(b"not evidence")},
                       {"path": self.path("outside.txt"), "bytes": 12, "sha256": sha(b"not evidence")},
                       {"path": "../outside.txt", "bytes": 12, "sha256": sha(b"not evidence")},
                       {"path": "inputs", "bytes": 0, "sha256": sha(b"")},
                       {"path": "inputs//./a.bin", "bytes": 5, "sha256": sha(b"alpha")}])
        r = self.check()
        self.assertEqual(r.code, 1)
        whys = {m["path"]: m["why"] for m in r.json["malformed"]}
        for bad in ("inputs/../outside.txt", self.path("outside.txt"), "../outside.txt", "inputs"):
            self.assertIn("outside inputs/", whys[bad], bad)
        self.assertEqual(r.json["duplicates"], ["inputs/a.bin"], "inputs//./a.bin is inputs/a.bin")
        rows = [json.loads(x)["path"] for x in self.read(r.json["receipts_file"]).splitlines()]
        self.assertEqual(rows, ["inputs/a.bin"], "nothing outside inputs/ was opened")


if __name__ == "__main__":
    unittest.main()
