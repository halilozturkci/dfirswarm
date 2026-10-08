"""catalog_search: where overflow goes in a job, which generation a path is, and what a corrupt revision says.

The catalogue is laid out as the harness lays it out (catalog/gen/gNNNN, catalog/revisions/<n>/
{MANIFEST.json,index.json}, catalog/<slug>/p<sector>/filelist.txt); the overflow is made by 3,000 matching rows.
"""
import json
import os
import stat
import unittest

from support import Case, run_tool


def answer(r):
    """What the tool said, from stdout, or from stderr where it exits with its error as the message."""
    return json.loads(r.stdout.strip() or r.stderr.strip())


class CatalogSearch(Case):
    def catalogue(self, rows=3000):
        self.write("catalog/Disk.E01/p2048/filelist.txt", "".join("r/r %d-128-1:\tUsers/a/file%04d.log\n" % (i, i) for i in range(rows)))
        self.write("catalog/Disk.E01/partitions.txt", "002:  000:000   0000002048   ...   NTFS\n")

    def revision(self, n, generations, index_text=None):
        self.write("catalog/revisions/%d/MANIFEST.json" % n, "{}")
        self.write("catalog/revisions/%d/index.json" % n, index_text if index_text is not None else json.dumps({"generations": generations}))

    def gen(self, gid, rows="r/r 1:\tx\n"):
        self.write("catalog/gen/%s/p2048/filelist.txt" % gid, rows)

    def test_overflow_in_a_job_goes_to_out_and_is_named_as_the_store_holds_it(self):
        self.catalogue()
        out = self.path("job-out")
        os.makedirs(out)
        os.chmod(self.dir, stat.S_IRUSR | stat.S_IXUSR)        # the run directory is read-only in a worker, work/ with it
        try:
            r = run_tool("catalog_search", {"pattern": "file", "limit": 100}, self.dir, env={"JOB_ID": "j000042", "OUT": out, "AGENT_ID": "s1"})
        finally:
            os.chmod(self.dir, stat.S_IRWXU)
        self.assertEqual(r.code, 0, r.stdout + r.stderr)
        self.assertEqual((r.json["matched"], r.json["returned"]), (3000, 100))
        shown = r.json["all_matches"]
        self.assertTrue(shown.startswith("store/jobs/j000042/out/catalog-search/"), shown)
        kept = os.path.join(out, shown[len("store/jobs/j000042/out/"):])
        self.assertEqual(len(self.read(kept).splitlines()), 3000)
        self.assertNotIn("all_matches_error", r.json)
        self.assertFalse(os.path.exists(self.path("work")))

    def test_the_old_place_is_kept_when_it_is_not_a_job(self):
        self.catalogue(300)
        r = run_tool("catalog_search", {"pattern": "file", "limit": 10}, self.dir, env={"AGENT_ID": "sab1"})
        self.assertRegex(r.json["all_matches"], r"^work/sab1/catalog-search/filelist-[0-9a-f]{16}\.txt$")

    def test_a_generation_not_in_the_revision_is_refused_by_any_spelling(self):
        self.catalogue(3)
        self.gen("g0001")
        self.gen("g0002")
        self.revision(1, [{"id": "g0001", "recipe": "r", "status": "complete"}])
        os.symlink(self.path("catalog/gen/g0002"), self.path("catalog/alias"))
        for spelling in ("catalog/gen/g0002", self.path("catalog/gen/g0002"), "./catalog/gen/g0002", "catalog/gen/../gen/g0002", "alias", "catalog/alias"):
            r = run_tool("catalog_search", {"pattern": "x", "catalog": spelling}, self.dir)
            self.assertEqual(r.code, 1, spelling)
            self.assertIn("g0002 is not in catalogue revision 1", answer(r)["error"], spelling)
        ok = run_tool("catalog_search", {"pattern": "x", "catalog": self.path("catalog/gen/g0001")}, self.dir)
        self.assertEqual(ok.code, 0, ok.stdout)
        self.assertEqual(ok.json["matched"], 1)

    def test_a_corrupt_revision_index_is_an_error_not_zero_generations(self):
        self.revision(2, None, index_text="{this is not json")
        r = run_tool("catalog_search", {"pattern": ".", "which": "generations"}, self.dir)
        self.assertEqual(r.code, 1)
        self.assertEqual(answer(r)["error"], "revision_unavailable")
        self.assertEqual(answer(r)["revision"], 2)
        # An index of the wrong shape is no better.
        self.revision(3, None, index_text=json.dumps({"generations": "none"}))
        r = run_tool("catalog_search", {"pattern": ".", "which": "generations", "revision": 3}, self.dir)
        self.assertEqual(answer(r)["error"], "revision_unavailable")
        # A search that does not need the index still runs, and says the index was unreadable.
        self.catalogue(3)
        r = run_tool("catalog_search", {"pattern": "file0001", "revision": 3}, self.dir)
        self.assertEqual(r.code, 0)

    def test_an_invalid_exclude_and_an_oversized_pattern_are_answers(self):
        self.catalogue(3)
        r = run_tool("catalog_search", {"pattern": "file", "exclude": "(unclosed"}, self.dir)
        self.assertEqual(r.code, 1)
        self.assertIn("exclude is not a regular expression", r.json["error"])
        self.assertNotIn("Traceback", r.stderr)
        r = run_tool("catalog_search", {"pattern": "a" * 5000}, self.dir)
        self.assertEqual(r.code, 1)
        self.assertIn("at most 4096", r.json["error"])

    def test_a_pattern_that_backtracks_badly_is_interrupted_and_says_so(self):
        self.write("catalog/Disk.E01/p2048/filelist.txt", "x" * 40 + "!\n")
        self.write("catalog/Disk.E01/partitions.txt", "p\n")
        r = run_tool("catalog_search", {"pattern": "(x+x+)+y", "ignore_case": False, "max_seconds": 1}, self.dir, timeout=60)
        self.assertEqual(r.code, 0, r.stdout + r.stderr)
        self.assertIs(r.json["complete"], False)
        self.assertIn("budget", r.json["interrupted"])
        self.assertIn("lower bound", r.json["interrupted"])

    def test_a_line_that_is_not_a_row_is_counted_not_silently_searched(self):
        self.write("catalog/Disk.E01/p2048/filelist.txt", "r/r 1:\tneedle.txt\n" + "n" * (2 * 1024 * 1024) + "\nr/r 2:\tneedle2.txt\n")
        self.write("catalog/Disk.E01/partitions.txt", "p\n")
        r = run_tool("catalog_search", {"pattern": "needle"}, self.dir)
        self.assertEqual(r.json["matched"], 2)
        self.assertEqual(r.json["lines_not_searched"], 1)
        self.assertIs(r.json["complete"], False)

    def test_a_generation_id_with_an_unreadable_index_is_that_error_not_no_catalogue(self):
        self.gen("g0001")
        self.revision(1, None, index_text="{this is not json")
        r = run_tool("catalog_search", {"pattern": "x", "catalog": "g0001"}, self.dir)
        self.assertEqual(r.code, 1)
        self.assertEqual(answer(r)["error"], "revision_unavailable")

    def test_a_listed_generation_whose_directory_is_gone_is_an_answer_not_a_traceback(self):
        self.revision(1, [{"id": "g0007", "recipe": "r", "status": "complete"}])
        r = run_tool("catalog_search", {"pattern": "x", "catalog": "g0007"}, self.dir)
        self.assertEqual(r.code, 1)
        self.assertNotIn("Traceback", r.stderr)
        self.assertIn("g0007 is listed by revision 1 but its directory", answer(r)["error"])

    def test_a_generations_search_is_under_the_budget_too(self):
        self.revision(1, [{"id": "g0001", "recipe": "r", "status": "complete", "target": {"name": "x" * 40 + "!"}}])
        r = run_tool("catalog_search", {"pattern": "(x+x+)+y", "which": "generations", "ignore_case": False, "max_seconds": 1}, self.dir, timeout=60)
        self.assertEqual(r.code, 0, r.stdout + r.stderr)
        self.assertNotIn("Traceback", r.stderr)
        self.assertIs(r.json["complete"], False)
        self.assertIn("lower bound", r.json["interrupted"])

    def test_a_row_ending_in_crlf_matches_its_own_end_and_is_returned_without_it(self):
        self.write("catalog/Disk.E01/p2048/filelist.txt", b"r/r 1:\tUsers/a/one.log\r\nr/r 2:\tUsers/a/two.txt\r\n")
        self.write("catalog/Disk.E01/partitions.txt", "p\n")
        r = run_tool("catalog_search", {"pattern": "log$"}, self.dir)
        self.assertEqual((r.json["matched"], r.json["hits"][0]["line"]), (1, "r/r 1:\tUsers/a/one.log"))

    def test_a_limit_outside_its_bounds_is_refused_and_an_agent_id_cannot_leave_work(self):
        self.catalogue(3000)
        for limit in (0, -1, 1001):
            r = run_tool("catalog_search", {"pattern": "file", "limit": limit}, self.dir)
            self.assertEqual(r.code, 1, limit)
            self.assertIn("from 1 to 1000", r.json["error"])
        r = run_tool("catalog_search", {"pattern": "file", "limit": 5}, self.dir, env={"AGENT_ID": "../../escape"})
        self.assertEqual(r.code, 0, r.stdout + r.stderr)
        self.assertTrue(os.path.realpath(self.path(r.json["all_matches"])).startswith(os.path.realpath(self.path("work")) + os.sep))
        self.assertFalse(os.path.exists(os.path.join(os.path.dirname(self.dir), "escape")))

    def test_a_matches_file_is_never_replaced_by_a_later_answer_to_the_same_search(self):
        self.catalogue(300)
        one = run_tool("catalog_search", {"pattern": "file", "limit": 5}, self.dir).json
        first = one["all_matches"]
        self.assertEqual(one["earlier_answers"], 0)
        kept = self.read(first)
        self.assertEqual(run_tool("catalog_search", {"pattern": "file", "limit": 5, "offset": 5}, self.dir).json["all_matches"], first,
                         "a page of the same search is the file that is there")
        self.write("catalog/Disk.E01/p2048/filelist.txt", "".join("r/r %d-128-1:\tUsers/b/file%04d.log\n" % (i, i) for i in range(300)))   # the same search, a different answer
        two = run_tool("catalog_search", {"pattern": "file", "limit": 5}, self.dir).json
        second = two["all_matches"]
        self.assertEqual(two["earlier_answers"], 1)
        self.assertNotEqual(first, second)
        self.assertTrue(second.endswith(".2.txt"), second)
        self.assertEqual(self.read(first), kept)

    def test_catalog_must_name_a_directory_under_catalog_not_any_directory(self):
        self.catalogue(3)
        self.write("outside/p2048/filelist.txt", "r/r 1:\tsecret/place.txt\n")
        self.write("outside/partitions.txt", "p\n")
        os.symlink(self.path("outside"), self.path("catalog/hop"))
        for spelling in (self.path("outside"), "../outside", "catalog/../outside", "hop", "catalog/hop"):
            r = run_tool("catalog_search", {"pattern": "secret", "catalog": spelling}, self.dir)
            self.assertEqual(r.code, 1, spelling)
            self.assertIn("no catalogue", answer(r)["error"], spelling)
        ok = run_tool("catalog_search", {"pattern": "file0001", "catalog": "Disk.E01"}, self.dir)
        self.assertEqual((ok.code, ok.json["matched"]), (0, 1))


if __name__ == "__main__":
    unittest.main()
