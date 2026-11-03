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


    def test_arguments_that_are_not_a_json_object_are_an_answer_and_not_a_traceback(self):
        for raw in ("not json", "[]", "7", ""):
            r = run_tool("catalog_search", None, self.dir, raw_input=raw)
            self.assertEqual(r.code, 1, raw)
            self.assertEqual(r.stderr, "", raw)
            self.assertIs(r.json["ok"], False, raw)


class CatalogSearchStatus(Case):
    """Every answer of catalog_search carries `status` (complete, partial or failed) and a one-sentence `status_basis`; `complete`
    and `ok` keep their meaning."""

    def catalogue(self, rows=10, text=None):
        self.write("catalog/Disk.E01/p2048/filelist.txt", text if text is not None else "".join("r/r %d-128-1:\tUsers/a/file%04d.log\n" % (i, i) for i in range(rows)))
        self.write("catalog/Disk.E01/partitions.txt", "002:  000:000   0000002048   ...   NTFS\n")

    def pair(self, r, status):
        j = answer(r)
        self.assertEqual(j.get("status"), status, j)
        basis = j.get("status_basis")
        self.assertTrue(isinstance(basis, str) and len(basis) > 20, j)
        return j

    def test_a_clean_run_is_complete(self):
        self.catalogue()
        r = run_tool("catalog_search", {"pattern": "file000[1-3]"}, self.dir)
        j = self.pair(r, "complete")
        self.assertEqual((r.code, j["matched"], j["complete"]), (0, 3, True))

    def test_a_paged_run_is_complete_and_names_the_file_with_every_match(self):
        self.catalogue(300)
        j = self.pair(run_tool("catalog_search", {"pattern": "file", "limit": 5}, self.dir, env={"AGENT_ID": "s1"}), "complete")
        self.assertIn("all_matches", j)
        self.assertIn("all_matches", j["status_basis"])

    def test_every_refusal_is_failed_with_the_pair(self):
        self.catalogue()
        for args in ({"pattern": "x", "which": "nonsense"}, {"pattern": "("}, {"pattern": "x", "exclude": "("}, {"pattern": "x", "limit": 0},
                     {"pattern": "x", "limit": "many"}, {"pattern": "x", "offset": -1}, {"pattern": "x", "max_seconds": 999},
                     {"pattern": 5}, {"pattern": "x" * 5000}, {"pattern": "x", "catalog": "Nope.E01"}, {"pattern": "x", "partition": "p9"},
                     {"pattern": "x", "revision": "abc"}, {"pattern": "x", "revision": 7}, {"pattern": "x", "which": ["filelist"]},
                     {"pattern": "x", "catalog": {"a": 1}}, {"pattern": "x", "limit": 1e999}, {"pattern": "x", "which": "timeline"}):
            r = run_tool("catalog_search", args, self.dir)
            self.assertEqual(r.code, 1, args)
            self.pair(r, "failed")
            self.assertNotIn("Traceback", r.stderr, args)
        for raw in ("not json", "[]", "", "[" * 100000):
            r = run_tool("catalog_search", None, self.dir, raw_input=raw)
            self.pair(r, "failed")
            self.assertNotIn("Traceback", r.stderr, raw)

    def test_no_catalogue_at_all_is_failed_with_the_pair(self):
        r = run_tool("catalog_search", {}, self.dir)
        j = self.pair(r, "failed")
        self.assertIs(j["ok"], False)
        self.write("catalog/revisions/1/MANIFEST.json", "{}")
        self.write("catalog/revisions/1/index.json", "not json")
        self.pair(run_tool("catalog_search", {"pattern": "x", "which": "generations"}, self.dir), "failed")
        self.pair(run_tool("catalog_search", {"pattern": "x", "catalog": "g0001"}, self.dir), "failed")

    def test_a_refusal_lists_at_most_200_names_and_counts_them(self):
        for i in range(250):
            self.write("catalog/cat%03d/partitions.txt" % i, "p\n")
        j = self.pair(run_tool("catalog_search", {"pattern": "x"}, self.dir), "failed")
        self.assertEqual((len(j["candidates"]), j["candidates_total"]), (200, 250))

    def test_a_clock_stop_is_partial_and_not_complete(self):
        self.catalogue(text=("a" * 40 + "\n") * 3)
        r = run_tool("catalog_search", {"pattern": "(a*)*b", "max_seconds": 1}, self.dir, timeout=60)
        j = self.pair(r, "partial")
        self.assertEqual((r.code, j["complete"]), (0, False))
        self.assertIn("interrupted", j)

    def test_a_clock_stop_over_the_generations_is_partial(self):
        self.write("catalog/revisions/1/MANIFEST.json", "{}")
        self.write("catalog/revisions/1/index.json", json.dumps({"generations": [{"id": "g0001", "recipe": "a" * 40, "status": "complete"}]}))
        j = self.pair(run_tool("catalog_search", {"pattern": "(a*)*b", "which": "generations", "max_seconds": 1}, self.dir, timeout=60), "partial")
        self.assertFalse(j["complete"])
        self.assertIn("interrupted", j)

    def test_the_generations_listing_is_complete(self):
        self.write("catalog/revisions/1/MANIFEST.json", "{}")
        self.write("catalog/revisions/1/index.json", json.dumps({"generations": [{"id": "g0001", "recipe": "r", "status": "complete"}]}))
        j = self.pair(run_tool("catalog_search", {"pattern": "r", "which": "generations"}, self.dir), "complete")
        self.assertEqual(j["matched"], 1)

    def test_lines_too_long_to_search_make_it_partial(self):
        self.catalogue(text="short file line\n" + "x" * ((1 << 20) + 10) + "\nanother file line\n")
        j = self.pair(run_tool("catalog_search", {"pattern": "file"}, self.dir), "partial")
        self.assertEqual((j["lines_not_searched"], j["complete"], j["matched"]), (1, False, 2))

    def test_a_match_file_that_could_not_be_written_is_partial(self):
        self.catalogue(300)
        self.write("work", b"a file where the work directory should be")
        j = self.pair(run_tool("catalog_search", {"pattern": "file", "limit": 5}, self.dir, env={"AGENT_ID": "s1"}), "partial")
        self.assertIn("all_matches_error", j)
        self.assertEqual((j["matched"], j["returned"]), (300, 5))
        self.assertIn("all_matches_error", j["status_basis"])

    def test_a_budget_that_runs_out_before_the_search_began_is_partial_json(self):
        import subprocess
        import sys
        from support import tool_path
        with open(tool_path("catalog_search"), encoding="utf-8") as fh:
            src = fh.read()
        patched = src.replace('revision = _revision(args.get("revision"))', "raise _Budget()", 1)
        self.assertNotEqual(src, patched)
        self.catalogue()
        # The tool with one line replaced, run like the harness runs a tool.
        path = self.path("patched_run.py")
        self.write("patched_run.py", patched)
        p = subprocess.run([sys.executable, path], input=json.dumps({"pattern": "x"}), capture_output=True, text=True, cwd=self.dir, timeout=60)
        self.assertNotIn("Traceback", p.stderr)
        j = json.loads(p.stdout)
        self.assertEqual((p.returncode, j["status"], j["ok"]), (1, "partial", False), j)
        self.assertGreater(len(j["status_basis"]), 20)

    def test_the_probe_of_a_missing_path_in_an_empty_directory(self):
        for args in ({}, {"pattern": "x", "catalog": "missing/path"}):
            self.pair(run_tool("catalog_search", args, self.dir), "failed")


if __name__ == "__main__":
    unittest.main()
