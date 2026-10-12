"""ioc_scan: locators by default, values only in a job's sealed file, and counts that do not depend on the read size.

Expected counts and offsets are worked out here with the standard library's re.finditer
(lookahead, so overlapping occurrences count), a method that shares nothing with the
tool's own search.
"""
import json
import os
import re
import stat
import unittest

from support import Case, run_tool

SECRET = b"hunter2-correct-horse"


class IocScan(Case):
    def scan(self, data, needles, env=None, **kw):
        src = self.write("blob.bin", data)
        return run_tool("ioc_scan", dict({"path": src, "needles": needles}, **kw), self.dir, env=env)

    def expect(self, data, needle):
        return [m.start() for m in re.finditer(b"(?=%s)" % re.escape(needle), data)]

    def test_context_is_not_returned_and_every_occurrence_is_kept(self):
        data = b"\0" * 20 + (b"A" * 16 + b"password=" + SECRET + b"Z" * 20) * 3
        r = self.scan(data, "password=", context=8)
        self.assertEqual(r.code, 0, r.stdout)
        for text in (SECRET, b"hunter2"):
            self.assertNotIn(text, r.stdout.encode(), "context bytes came back inline")
        self.assertNotIn("snippet", r.stdout)
        # The same context three times: the inline view lists it once, the whole result has all three offsets.
        self.assertEqual(len(r.json["hits"]), 1)
        self.assertEqual(r.json["repeats_hidden_inline"], 2)
        rows = [json.loads(x) for x in self.read(r.json["all_results"]).splitlines()]
        self.assertEqual([x["offset"] for x in rows], self.expect(data, b"password="))
        self.assertTrue(all(set(x) == {"finding_id", "offset", "needle", "enc", "context_length"} for x in rows))
        self.assertEqual(r.json["counts"], {"password=": 3})

    def test_a_needle_longer_than_a_read_is_found_whatever_the_read_size(self):
        needle = b"0123456789abcdefghijklmnopqrstuvwxyzABCD"            # 40 bytes
        data = b"-" * 37 + needle + b"-" * 50 + needle + b"-" * 3
        for chunk in (16, 17, 31, 40, 64, 1000, 8 * 1024 * 1024):
            r = self.scan(data, needle.decode(), chunk=chunk, unique_only=False)
            self.assertEqual([h["offset"] for h in r.json["hits"]], self.expect(data, needle), chunk)

    def test_counts_do_not_depend_on_the_read_size_and_overlaps_count(self):
        data = (b"aaaaa" + b"\0" * 9 + b"aaa") * 10 + b"\0" * 3
        want = len(self.expect(data, b"aaa"))
        self.assertGreater(want, 40)                     # runs of 'a' meet at the units' joins, and overlapping matches count
        for chunk in (16, 23, 100, 4096):
            r = self.scan(data, "aaa", chunk=chunk, unique_only=False)
            self.assertEqual(r.json["counts"], {"aaa": want}, chunk)
            self.assertEqual([h["offset"] for h in r.json["hits"]], self.expect(data, b"aaa"), chunk)

    def test_utf16_matches_and_their_context_length_are_counted_in_bytes(self):
        needle = "abc"
        wide = needle.encode("utf-16le")
        data = b"\0" * 5 + wide + b"x" * 50
        r = self.scan(data, needle, context=10, unique_only=False)
        utf16 = [h for h in r.json["hits"] if h["enc"] == "utf16"]
        self.assertEqual([h["offset"] for h in utf16], [5])
        self.assertEqual(utf16[0]["context_length"], 5 + len(wide) + 10)       # what precedes it (5 bytes, under 16), the match, 10 after
        # The context after a match is whole even when a read ends inside it.
        small = self.scan(data, needle, context=10, unique_only=False, chunk=16)
        self.assertEqual([h["context_length"] for h in small.json["hits"] if h["enc"] == "utf16"], [5 + len(wide) + 10])

    def test_values_are_refused_outside_a_job_and_written_privately_inside_one(self):
        data = b"\0" * 30 + b"password=" + SECRET + b"\0" * 30
        r = self.scan(data, "password=", write_values=True)
        self.assertEqual(r.code, 1)
        self.assertIn("refused outside a job", r.json["error"])
        self.assertEqual([n for n in os.listdir(self.dir) if n != "blob.bin"], [])
        out = self.path("job-out")
        os.makedirs(out)
        r = self.scan(data, "password=", write_values=True, env={"JOB_ID": "j000007", "OUT": out})
        self.assertEqual(r.code, 0, r.stdout)
        self.assertNotIn(SECRET.decode(), r.stdout)
        sv = r.json["secret_values"]
        self.assertTrue(sv["contains_secret_values"])
        self.assertEqual(sv["values_file"], "store/jobs/j000007/out/ioc-scan-values.jsonl")
        values_path = os.path.join(out, "ioc-scan-values.jsonl")
        self.assertEqual(stat.S_IMODE(os.stat(values_path).st_mode), 0o600)
        row = json.loads(self.read(values_path).splitlines()[0])
        self.assertEqual((row["offset"], row["finding_id"], row["file"]), (30, "F000001", self.path("blob.bin")))
        self.assertIn(SECRET.decode(), row["value"])
        # A second run in the same job's output does not overwrite the first's file.
        again = self.scan(data, "password=", write_values=True, env={"JOB_ID": "j000007", "OUT": out})
        self.assertEqual(again.code, 1)
        self.assertEqual(again.stderr, "", "a refusal is a JSON answer, not a traceback")
        self.assertIn("values file already exists", again.json["error"])
        self.assertEqual(again.json["write_values"], "refused")
        self.assertIn(SECRET.decode(), json.loads(self.read(values_path).splitlines()[0])["value"], "the first run's file is as it was")
        tool_output = os.path.join(out, "tool-output")
        self.assertEqual([n for n in (os.listdir(tool_output) if os.path.isdir(tool_output) else []) if n.startswith(".")], [], "no half-written file is left")

    def test_the_range_is_what_was_read_and_bad_numbers_are_refused(self):
        data = b"x" * 100 + b"needle" + b"y" * 100
        r = self.scan(data, "needle", start=50, length=10_000)
        self.assertEqual((r.json["scanned_start"], r.json["scanned_end"], r.json["bytes_scanned"]), (50, len(data), len(data) - 50))
        self.assertTrue(r.json["complete"])
        short = self.scan(data, "needle", start=0, length=103)
        self.assertEqual((short.json["bytes_scanned"], short.json["counts"]), (103, {}))
        for bad in ({"chunk": 0}, {"chunk": 4}, {"context": 10 ** 9}, {"max_hits": 0}, {"start": -1}, {"start": 10 ** 6}, {"length": -5}):
            self.assertEqual(self.scan(data, "needle", **bad).code, 1, bad)

    def test_a_needle_that_is_not_text_and_a_directory_are_answers(self):
        self.write("blob.bin", b"x")
        self.assertEqual(run_tool("ioc_scan", {"path": self.dir, "needles": "x"}, self.dir).code, 1)
        self.assertEqual(run_tool("ioc_scan", {"path": self.path("none"), "needles": "x"}, self.dir).json["error"], "no such file")

    def test_ids_order_and_the_inline_page_do_not_depend_on_the_chunk_and_a_needle_given_twice_is_one(self):
        data = b"x" * 10 + b"AAA" + b"-" * 40 + b"BBB" + b"-" * 40 + b"AAA" + b"-" * 40 + b"BBB"
        pages = {}
        for chunk in (16, 33, 1000, 1 << 20):
            r = self.scan(data, "AAA|BBB|AAA", chunk=chunk, context=0, max_hits=3, unique_only=False)
            pages[chunk] = [(h["finding_id"], h["offset"], h["needle"]) for h in r.json["hits"]]
            self.assertEqual(r.json["counts"], {"AAA": 2, "BBB": 2}, chunk)
            self.assertEqual(r.json["matched"], 4, chunk)
        self.assertEqual(len({str(v) for v in pages.values()}), 1, pages)
        self.assertEqual(pages[16], [("F000001", 10, "AAA"), ("F000002", 53, "BBB"), ("F000003", 96, "AAA")])

    def test_a_link_at_the_values_file_is_refused_by_name_and_an_empty_file_is_reported_with_nothing_written(self):
        out = self.path("job-out")
        os.makedirs(out)
        victim = self.write("victim.txt", "keep me")
        os.symlink(victim, os.path.join(out, "ioc-scan-values.jsonl"))
        env = {"JOB_ID": "j000008", "OUT": out}
        r = self.scan(b"\0" * 20 + b"password=" + SECRET, "password=", write_values=True, env=env)
        self.assertEqual(r.code, 1)
        self.assertIn("values file already exists", r.json["error"])
        self.assertEqual(self.read(victim), "keep me")
        os.unlink(os.path.join(out, "ioc-scan-values.jsonl"))
        r = self.scan(b"\0" * 64, "password=", write_values=True, env=env)
        self.assertEqual(r.code, 0, r.stdout)
        self.assertEqual((r.json["secret_values"]["written"], r.json["secret_values"]["values_file"], r.json["secret_values"]["contains_secret_values"]),
                         (0, "store/jobs/j000008/out/ioc-scan-values.jsonl", False))
        path = os.path.join(out, "ioc-scan-values.jsonl")
        self.assertEqual((os.path.getsize(path), stat.S_IMODE(os.stat(path).st_mode)), (0, 0o600))

    def test_a_results_file_is_never_replaced_by_a_later_scan_of_the_same_question(self):
        # Same question, same size, other bytes: the key (file, needles, range, size) is the same and the answer is not.
        data = b"\0" * 10 + b"needle" * 40
        other = b"needle" * 40 + b"\0" * 10
        one = self.scan(data, "needle", max_hits=2, unique_only=False).json
        first = one["all_results"]
        self.assertEqual(one["earlier_answers"], 0)
        kept = self.read(first)
        again = self.scan(data, "needle", max_hits=2, unique_only=False).json
        self.assertEqual((again["all_results"], again["earlier_answers"]), (first, 0), "the same answer again is the file that is there")
        two = self.scan(other, "needle", max_hits=2, unique_only=False).json
        second = two["all_results"]
        self.assertEqual(two["earlier_answers"], 1, "the agent sees the files of this question grow")
        self.assertNotEqual(first, second)
        self.assertTrue(second.endswith(".2.jsonl"), second)
        self.assertEqual(self.read(first), kept, "the first answer was replaced")
        self.assertNotEqual(self.read(second), kept)

    def test_the_needles_that_ran_are_named_and_an_empty_list_is_not_the_default_set(self):
        data = b"\0" * 10 + b"password=" + SECRET
        r = self.scan(data, "password=|token=")
        self.assertEqual((r.json["needles_that_ran"], r.json["needles_source"]), (["password=", "token="], "given"))
        absent = run_tool("ioc_scan", {"path": self.write("blob.bin", data)}, self.dir)
        self.assertEqual(absent.code, 0, absent.stdout)
        self.assertIn("password", absent.json["needles_that_ran"])
        self.assertIn("default set", absent.json["needles_source"])
        for empty in ("", [], "|"):
            r = self.scan(data, empty)
            self.assertEqual(r.code, 1, empty)
            self.assertIn("needles is empty", r.json["error"])


if __name__ == "__main__":
    unittest.main()
