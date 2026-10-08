"""file_type: what was looked at, what was not, and what a header can and cannot say.

Signatures are from the formats' own definitions: Java's class file magic and
version fields, Mach-O's fat header (a count of architectures), the Windows
prefetch header (a version, then SCCA at offset 4).
"""
import json
import os
import struct
import unittest

from support import Case, run_tool


class FileType(Case):
    def look(self, path="d", **kw):
        return run_tool("file_type", dict({"path": path}, **kw), self.dir)

    def test_the_examined_count_is_what_was_opened_and_every_result_is_kept(self):
        for i in range(50):
            self.write("d/f%02d.txt" % i, "text %d\n" % i)
        r = self.look(limit=10)
        self.assertEqual(r.code, 0, r.stdout)
        self.assertEqual((r.json["examined"], r.json["file_count"], r.json["discovered"]), (50, 10, 50))
        self.assertTrue(r.json["truncated"])
        rows = self.read(r.json["all_results"]).splitlines()
        self.assertEqual(len(rows), 50)
        self.assertTrue(all("sha256" in json.loads(x) for x in rows))

    def test_a_java_class_is_not_a_macho_binary_and_a_fat_header_is(self):
        self.write("d/Main.class", b"\xca\xfe\xba\xbe" + struct.pack(">HH", 0, 52) + b"\0" * 32)
        self.write("d/universal", b"\xca\xfe\xba\xbe" + struct.pack(">I", 2) + b"\0" * 32)
        types = {os.path.basename(f["file"]): f for f in self.look().json["files"]}
        self.assertEqual(types["Main.class"]["type"], "Java class file")
        self.assertTrue(types["Main.class"]["extension_matches"])
        self.assertEqual(types["universal"]["type"], "Mach-O universal binary")

    def test_prefetch_is_recognised_where_its_signature_is(self):
        # An uncompressed prefetch file: a format version (0x17 for Windows 7) and then SCCA at offset 4.
        self.write("d/CMD.EXE-0A1B2C3D.pf", struct.pack("<I", 0x17) + b"SCCA" + b"\0" * 64)
        self.write("d/compressed.pf", b"MAM\x04" + b"\0" * 64)
        types = {os.path.basename(f["file"]): f["type"] for f in self.look().json["files"]}
        self.assertEqual(types["CMD.EXE-0A1B2C3D.pf"], "prefetch record")
        self.assertEqual(types["compressed.pf"], "compressed prefetch record")

    def test_an_unknown_type_does_not_match_its_extension(self):
        # Zeros, not random bytes: libmagic names a random block something about one time in twenty, and `file -b` says
        # "data" (its word for no type) for zeros every time.
        self.write("d/random.bin", b"\0" * 512)
        f = self.look().json["files"][0]
        self.assertIsNone(f["extension_matches"])
        self.assertEqual(f["type"], "unrecognised")

    @unittest.skipIf(os.geteuid() == 0, "root reads every file")
    def test_an_unreadable_file_is_reported_whatever_mismatch_only_says(self):
        self.write("d/ok.txt", "x")
        bad = self.write("d/secret.dat", "x")
        os.chmod(bad, 0)
        try:
            r = self.look(mismatch_only=True)
        finally:
            os.chmod(bad, 0o644)
        self.assertEqual(r.json["error_count"], 1)
        self.assertEqual(r.json["errors"][0]["file"], "d/secret.dat")
        self.assertFalse(r.json["complete"])
        self.assertEqual(r.json["files"], [])

    def test_links_and_pipes_are_named_and_never_opened_or_followed(self):
        os.makedirs(self.path("outside"))
        self.write("outside/secret.txt", "do not read")
        self.write("d/real.txt", "x")
        os.symlink(self.path("outside"), self.path("d/dirlink"))
        os.symlink(self.path("outside/secret.txt"), self.path("d/filelink.txt"))
        os.mkfifo(self.path("d/pipe"))
        r = self.look()                          # opening the pipe would block until the run timed out
        self.assertEqual(r.code, 0, r.stdout)
        names = {os.path.basename(f["file"]): f for f in r.json["files"]}
        self.assertEqual(names["filelink.txt"]["kind"], "symbolic link")
        self.assertEqual(names["dirlink"]["kind"], "symbolic link")
        self.assertEqual(names["pipe"]["kind"], "not a regular file")
        self.assertNotIn("sha256", names["filelink.txt"])
        self.assertNotIn("secret.txt", [os.path.basename(f["file"]) for f in r.json["files"]])
        self.assertEqual((r.json["links_listed"], r.json["not_regular_listed"], r.json["examined"]), (2, 1, 1))

    def test_directories_are_walked_in_sorted_order(self):
        for p in ("d/b/y.txt", "d/a/x.txt", "d/top.txt", "d/a/w.txt"):
            self.write(p, "x")
        order = [f["file"] for f in self.look().json["files"]]
        self.assertEqual(order, ["d/top.txt", "d/a/w.txt", "d/a/x.txt", "d/b/y.txt"])

    def test_a_mismatch_is_found_by_direction(self):
        self.write("d/photo.jpg", b"PK\x03\x04" + b"\0" * 32)
        self.write("d/fine.docx", b"PK\x03\x04" + b"\0" * 32)
        r = self.look(mismatch_only=True)
        self.assertEqual([os.path.basename(f["file"]) for f in r.json["files"]], ["photo.jpg"])
        self.assertEqual(r.json["extension_mismatches"], 1)
        self.assertEqual(r.json["examined"], 2)
        self.assertIn("all_results", r.json)                     # what the filter hid is kept

    @unittest.skipIf(os.geteuid() == 0, "root lists every directory")
    def test_a_directory_that_cannot_be_listed_is_an_error_not_a_clean_walk(self):
        self.write("d/ok.txt", "x")
        locked = self.path("d/locked")
        os.makedirs(locked)
        os.chmod(locked, 0)
        try:
            r = self.look()
        finally:
            os.chmod(locked, 0o755)
        self.assertIs(r.json["complete"], False)
        self.assertEqual([(os.path.basename(e["file"]), "could not be listed" in e["error"]) for e in r.json["errors"]], [("locked", True)])
        self.assertEqual(r.json["error_count"], 1)

    def test_errors_past_the_shown_ones_are_in_a_kept_file_that_the_note_names(self):
        if os.geteuid() == 0:
            self.skipTest("root reads every file")
        for i in range(60):
            path = self.write("d/f%02d.dat" % i, "x")
            os.chmod(path, 0)
        try:
            r = self.look()
        finally:
            for i in range(60):
                os.chmod(self.path("d/f%02d.dat" % i), 0o644)
        self.assertEqual((r.json["error_count"], len(r.json["errors"])), (60, 50))
        self.assertIn("all_results", r.json["errors_note"])
        self.assertEqual(len(self.read(r.json["all_results"]).splitlines()), 60)

    def test_a_name_that_is_not_utf8_does_not_end_the_walk(self):
        os.makedirs(self.path("d"), exist_ok=True)
        try:
            with open(os.path.join(self.dir.encode(), b"d", b"caf\xe9.txt"), "wb") as fh:
                fh.write(b"latin1 name")
        except OSError:
            self.skipTest("this file system will not hold a name that is not UTF-8")
        self.write("d/ok.txt", "x")
        r = self.look(limit=1)
        self.assertEqual(r.code, 0, r.stdout + r.stderr)
        self.assertEqual(len(self.read(r.json["all_results"]).splitlines()), 2)

    def test_text_in_a_script_or_data_extension_is_no_mismatch_and_text_named_like_a_binary_is(self):
        for name in ("a.ps1", "b.vbs", "c.js", "d.reg", "e.tsv", "f.bat", "g"):
            self.write("d/" + name, "echo hello\n")
        self.write("d/h.exe", "echo hello\n")
        by = {os.path.basename(f["file"]): f for f in self.look().json["files"]}
        self.assertEqual({n: by[n]["extension_matches"] for n in by}, {"a.ps1": True, "b.vbs": True, "c.js": True, "d.reg": True, "e.tsv": True, "f.bat": True, "g": True, "h.exe": False})

    def test_ewf_files_are_named_whole_ex01_included_and_every_segment_matches_its_name(self):
        e01 = b"EVF\x09\x0d\x0a\xff\x00" + b"\0" * 64
        ex01 = b"EVF2\x0d\x0a\x81\x00" + b"\0" * 64
        for name, data in (("a.E01", e01), ("a.E02", e01), ("a.EAA", e01), ("b.Ex01", ex01), ("b.Ex02", ex01), ("c.L01", b"LVF\x09\x0d\x0a\xff\x00" + b"\0" * 64), ("d.jpg", e01)):
            self.write("d/" + name, data)
        by = {os.path.basename(f["file"]): f for f in self.look().json["files"]}
        for name in ("a.E01", "a.E02", "a.EAA", "b.Ex01", "b.Ex02", "c.L01"):
            self.assertIs(by[name]["extension_matches"], True, name)
        self.assertIn("EWF2", by["b.Ex01"]["type"])
        self.assertIs(by["d.jpg"]["extension_matches"], False)

    def test_a_hash_that_outruns_the_budget_says_how_far_it_got(self):
        import importlib.util, time
        from support import tool_path
        spec = importlib.util.spec_from_file_location("ft", tool_path("file_type"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        path = self.write("big.bin", b"\0" * (8 * 1024 * 1024))
        entry = mod.look(path, time.monotonic() - 1)
        self.assertIsNone(entry["sha256"])
        self.assertIn("no digest for this file", entry["hashing"])
        self.assertEqual(mod.look(path, time.monotonic() + 60)["sha256"], __import__("hashlib").sha256(b"\0" * (8 * 1024 * 1024)).hexdigest())

    def test_a_limit_beyond_its_bound_is_refused(self):
        self.write("d/a.txt", "x")
        for bad in (0, -1, 5001):
            self.assertEqual(self.look(limit=bad).code, 1, bad)

    def test_a_name_with_a_lone_surrogate_is_written_to_the_results_file_not_lost(self):
        import importlib.util
        from support import tool_path
        spec = importlib.util.spec_from_file_location("ft2", tool_path("file_type"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        here = os.getcwd()
        os.chdir(self.dir)
        try:
            results = mod.Results(["surrogate"])
            results.add({"file": "d/caf\udce9.txt", "type": "text"})
            shown = results.finish(keep=True)
        finally:
            os.chdir(here)
        self.assertEqual(json.loads(self.read(shown).splitlines()[0])["file"], "d/caf\udce9.txt")

    def test_a_results_file_is_never_replaced_by_a_later_walk_of_the_same_directory(self):
        for i in range(8):
            self.write("d/f%d.txt" % i, "text %d\n" % i)
        one = self.look(limit=2).json
        first = one["all_results"]
        self.assertEqual(one["earlier_answers"], 0)
        kept = self.read(first)
        self.assertEqual(self.look(limit=2).json["all_results"], first, "the same answer again is the file that is there")
        self.write("d/f3.txt", "other bytes\n")                      # the same walk, a different answer
        two = self.look(limit=2).json
        second = two["all_results"]
        self.assertEqual(two["earlier_answers"], 1)
        self.assertNotEqual(first, second)
        self.assertTrue(second.endswith(".2.jsonl"), second)
        self.assertEqual(self.read(first), kept)

    def test_a_path_that_is_a_link_to_a_directory_is_followed_once_and_a_walk_of_only_links_is_not_complete(self):
        self.write("real/a.txt", "alpha\n")
        self.write("real/sub/b.bin", b"\0" * 64)
        os.symlink(self.path("real"), self.path("held"))              # how a set held in place sits under inputs/
        r = self.look(path="held")
        self.assertEqual(r.code, 0, r.stdout)
        self.assertEqual((r.json["examined"], sorted(os.path.basename(f["file"]) for f in r.json["files"])), (2, ["a.txt", "b.bin"]))
        self.assertTrue(all(f["file"].startswith("held/") for f in r.json["files"]), "entries are named under the path the caller gave")
        self.assertEqual(r.json["path_is_a_link"]["link"], "held")
        self.assertIs(r.json["complete"], True)
        # Links inside are listed and never followed, and a directory of nothing but links did not examine anything.
        os.makedirs(self.path("only"))
        os.symlink(self.path("real/a.txt"), self.path("only/l1"))
        os.symlink(self.path("real"), self.path("only/l2"))
        r = self.look(path="only")
        self.assertIs(r.json["complete"], False)
        self.assertEqual((r.json["examined"], r.json["links_listed"]), (0, 2))
        self.assertIn("nothing was opened", " ".join(r.json["why_not_complete"]))
        os.symlink(self.path("nowhere"), self.path("dangling"))
        self.assertEqual(self.look(path="dangling").code, 1)

    def test_what_the_time_budget_left_unlooked_at_is_named_and_kept(self):
        import importlib.util
        import io
        import contextlib
        import types
        from support import tool_path
        for i in range(60):
            self.write("d/f%02d.txt" % i, "x\n")
        spec = importlib.util.spec_from_file_location("ft3", tool_path("file_type"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        calls = [0]

        def fake():
            calls[0] += 1
            return 0 if calls[0] <= 21 else 10 ** 6          # one call sets the deadline, two go to each file: the budget runs out after ten
        mod.time = types.SimpleNamespace(monotonic=fake)
        import sys
        sys.stdin = io.StringIO(json.dumps({"path": "d", "limit": 5}))
        out = io.StringIO()
        here = os.getcwd()
        os.chdir(self.dir)
        try:
            with contextlib.redirect_stdout(out):
                mod.main()
        finally:
            os.chdir(here)
            sys.stdin = sys.__stdin__
        got = json.loads(out.getvalue())
        self.assertEqual((got["examined"], got["not_attempted"]), (10, 50))
        self.assertIs(got["complete"], False)
        self.assertEqual(len(got["not_attempted_files"]), 50)
        self.assertTrue(all(n.startswith("d/f") for n in got["not_attempted_files"]))
        rows = [json.loads(x) for x in self.read(got["all_results"]).splitlines()]
        self.assertEqual(len(rows), 60)
        self.assertEqual(len([r for r in rows if "not_attempted" in r]), 50)

    def test_the_first_bytes_are_returned_only_when_asked_for(self):
        self.write("d/key.bin", bytes(range(32)))
        self.assertNotIn("head_hex", self.look().json["files"][0])
        self.assertEqual(self.look(head_hex=True).json["files"][0]["head_hex"], bytes(range(16)).hex())
        self.assertEqual(self.look(head_hex="yes").code, 1)

    def test_an_lx01_logical_evidence_file_is_named_and_matches_its_extension(self):
        self.write("d/a.Lx01", b"LVF2\x0d\x0a\x81\x00" + b"\0" * 64)
        self.write("d/a.L01", b"LVF\x09\x0d\x0a\xff\x00" + b"\0" * 64)
        by = {os.path.basename(f["file"]): f for f in self.look().json["files"]}
        self.assertIn("Lx01", by["a.Lx01"]["type"])
        self.assertIs(by["a.Lx01"]["extension_matches"], True)
        self.assertIs(by["a.L01"]["extension_matches"], True)


if __name__ == "__main__":
    unittest.main()
