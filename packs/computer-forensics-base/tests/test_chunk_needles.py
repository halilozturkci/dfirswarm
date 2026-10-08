"""chunk_needles: bounded parameters, a source that names its image and volume, locators instead of context, counts that do not depend on the chunk.

icat is a stand-in that records its arguments and writes a stream; expected offsets
come from re.finditer with a lookahead (overlapping occurrences count).
"""
import json
import os
import re
import stat
import unittest

from support import Case, run_tool, stand_in

SECRET = b"s3cr3t-token-value"


class ChunkNeedles(Case):
    def icat(self, stream):
        d = self.path("bin")
        os.makedirs(d, exist_ok=True)
        self.write("stream.bin", stream)
        self.argv_file = self.path("icat-args.txt")
        stand_in(d, "icat", 'printf "%%s\\n" "$@" > "%s"\ncat "%s"\n' % (self.argv_file, self.path("stream.bin")))
        return d

    def expect(self, data, needle):
        return [m.start() for m in re.finditer(b"(?=%s)" % re.escape(needle), data)]

    def inode_run(self, stream, needles, **kw):
        bin_dir = self.icat(stream)
        self.write("inputs/disk.E01", b"x")
        args = {"needles": needles, "inode": kw.pop("inode", 12), "image": "inputs/disk.E01", "offset": 2048}
        args.update(kw)
        return run_tool("chunk_needles", args, self.dir, [bin_dir], env=kw.pop("env", None))

    def file_run(self, data, needles, env=None, **kw):
        self.write("work/blob.bin", data)
        return run_tool("chunk_needles", dict({"needles": needles, "path": "work/blob.bin"}, **kw), self.dir, env=env)

    def test_the_source_names_the_image_the_volume_and_the_inode(self):
        r = self.inode_run(b"..needle..", "needle", inode="168-128-4", sector_size=4096)
        self.assertEqual(r.code, 0, r.stdout)
        src = r.json["source"]
        self.assertEqual((src["kind"], src["image"], src["volume_offset_sectors"], src["inode"], src["sector_size"]),
                         ("icat", "inputs/disk.E01", 2048, "168-128-4", 4096))
        self.assertEqual(self.read(self.argv_file).split(), ["-b", "4096", "-o", "2048", "inputs/disk.E01", "168-128-4"])
        self.assertEqual(r.json["hits"]["needle"]["ascii"], 1)

    def test_without_a_sector_size_icat_gets_no_b(self):
        self.inode_run(b"needle", "needle")
        self.assertEqual(self.read(self.argv_file).split(), ["-o", "2048", "inputs/disk.E01", "12"])

    def test_an_inode_that_is_not_an_address_never_reaches_icat(self):
        for bad in ("12; rm", "-5", "1-2-3-4", "abc", True, -1, 1.5):
            r = self.inode_run(b"x", "x", inode=bad)
            self.assertEqual(r.code, 1, bad)

    def test_bounds_are_enforced_and_zero_is_zero(self):
        for bad in ({"context": 10 ** 9}, {"context": -1}, {"chunk": 0}, {"chunk": 8}, {"chunk": 10 ** 12}, {"max_hits": 0}, {"max_hits": 10 ** 9}):
            self.assertEqual(self.file_run(b"abc needle abc", "needle", **bad).code, 1, bad)
        self.assertEqual(self.file_run(b"abc", "x" * 5000).code, 1)
        self.assertEqual(self.file_run(b"abc", "|".join("n%d" % i for i in range(1001))).code, 1)
        r = self.file_run(b"abc needle abc", "needle", context=0)
        self.assertEqual(r.json["hits"]["needle"]["locations"][0]["context_length"], len("needle"))     # a given 0 is 0, not the default 60

    def test_context_is_not_returned_and_values_go_to_a_sealed_file(self):
        data = b"\0" * 40 + b"token=" + SECRET + b"\0" * 40
        r = self.file_run(data, "token=")
        self.assertNotIn(SECRET.decode(), r.stdout)
        self.assertEqual(set(r.json["hits"]["token="]["locations"][0]), {"finding_id", "off", "enc", "context_length"})
        self.assertEqual(r.json["secret_values"]["contains_secret_values"], False)
        refused = self.file_run(data, "token=", write_values=True)
        self.assertEqual(refused.code, 1)
        self.assertIn("refused outside a job", refused.json["error"])
        out = self.path("job-out")
        os.makedirs(out)
        ok = self.file_run(data, "token=", write_values=True, env={"JOB_ID": "j000011", "OUT": out})
        self.assertEqual(ok.code, 0, ok.stdout)
        self.assertNotIn(SECRET.decode(), ok.stdout)
        path = os.path.join(out, "chunk-needles-values.jsonl")
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        self.assertIn(SECRET.decode(), json.loads(self.read(path).splitlines()[0])["value"])
        self.assertEqual(ok.json["secret_values"]["values_file"], "store/jobs/j000011/out/chunk-needles-values.jsonl")

    def test_a_long_needle_is_found_with_a_small_chunk_and_counts_do_not_depend_on_it(self):
        needle = b"0123456789abcdefghijklmnopqrstuvwxyzABCD"
        data = b"-" * 37 + needle + b"-" * 50 + needle + b"aaaaa" + b"-" * 3
        for chunk in (16, 17, 31, 40, 64, 1000, 8 * 1024 * 1024):
            r = self.file_run(data, needle.decode(), chunk=chunk, max_hits=100)
            self.assertEqual([x["off"] for x in r.json["hits"][needle.decode()]["locations"]], self.expect(data, needle), chunk)
        overlapping = b"aaaaa" + b"\0" * 9 + b"aaa"
        for chunk in (16, 23, 4096):
            r = self.file_run(overlapping * 5, "aaa", chunk=chunk, max_hits=1000)
            self.assertEqual(r.json["hits"]["aaa"]["ascii"], len(self.expect(overlapping * 5, b"aaa")), chunk)

    def test_the_context_after_a_match_is_whole_when_a_read_ends_inside_it(self):
        data = b"-" * 100 + b"needle" + b"+" * 100
        whole = self.file_run(data, "needle", context=30).json["hits"]["needle"]["locations"][0]["context_length"]
        for chunk in (16, 50, 101, 4096):
            got = self.file_run(data, "needle", context=30, chunk=chunk).json["hits"]["needle"]["locations"][0]["context_length"]
            self.assertEqual(got, whole, chunk)
        self.assertEqual(whole, 30 + len("needle") + 30)

    def test_a_link_back_up_the_tree_does_not_loop_the_image_search(self):
        bin_dir = self.icat(b"needle")
        self.write("inputs/set/disk.E01", b"x")
        os.symlink(self.path("inputs"), self.path("inputs/set/loop"))
        self.write("catalog/set_disk.E01/partitions.txt", "002:  000:000   0000002048   ...   NTFS\n")
        os.makedirs(self.path("catalog/set_disk.E01/p2048"))
        r = run_tool("chunk_needles", {"needles": "needle", "inode": 12}, self.dir, [bin_dir], timeout=30)
        self.assertEqual(r.code, 0, r.stdout + r.stderr)
        self.assertEqual(r.json["source"]["image"], "inputs/set/disk.E01")

    def test_ids_order_and_the_inline_page_do_not_depend_on_the_chunk_and_a_needle_given_twice_is_one(self):
        data = b"x" * 10 + "ab".encode("utf-16le") + b"-" * 40 + b"ab" + b"-" * 20
        pages = {}
        for chunk in (16, 33, 1000, 1 << 20):
            r = self.file_run(data, "ab|ab", chunk=chunk, context=0, max_hits=3)
            pages[chunk] = [(x["finding_id"], x["off"], x["enc"]) for x in r.json["hits"]["ab"]["locations"]]
            self.assertEqual((r.json["hits"]["ab"]["ascii"], r.json["hits"]["ab"]["utf16le"]), (1, 1), chunk)
        self.assertEqual(len({str(v) for v in pages.values()}), 1, pages)
        self.assertEqual(pages[16], [("F000001", 10, "utf16le"), ("F000002", 54, "ascii")])

    def test_a_leading_zero_is_the_same_address_and_icat_must_exist(self):
        bin_dir = self.icat(b"needle")
        r = self.inode_run(b"needle", "needle", inode="084284-128-4")
        self.assertEqual(self.read(self.argv_file).split()[-1], "84284-128-4")
        self.write("inputs/disk.E01", b"x")
        empty = self.path("empty")
        os.makedirs(empty)
        r = run_tool("chunk_needles", {"needles": "n", "inode": 5, "image": "inputs/disk.E01"}, self.dir, only_path=empty)
        self.assertEqual(r.code, 1)
        self.assertIn("icat is not on PATH", r.json["error"])

    def test_a_second_values_run_in_one_job_is_a_json_refusal_and_a_link_at_the_name_is_refused(self):
        data = b"\0" * 40 + b"token=" + SECRET + b"\0" * 40
        out = self.path("job-out")
        os.makedirs(out)
        env = {"JOB_ID": "j000012", "OUT": out}
        first = self.file_run(data, "token=", write_values=True, env=env)
        self.assertEqual(first.code, 0, first.stdout)
        again = self.file_run(data, "token=", write_values=True, env=env)
        self.assertEqual(again.code, 1)
        self.assertEqual(again.stderr, "")
        self.assertIn("values file already exists", again.json["error"])
        self.assertIn(SECRET.decode(), json.loads(self.read(os.path.join(out, "chunk-needles-values.jsonl")).splitlines()[0])["value"])
        os.unlink(os.path.join(out, "chunk-needles-values.jsonl"))
        victim = self.write("victim.txt", "keep me")
        os.symlink(victim, os.path.join(out, "chunk-needles-values.jsonl"))
        r = self.file_run(data, "token=", write_values=True, env=env)
        self.assertEqual((r.code, self.read(victim)), (1, "keep me"))
        os.unlink(os.path.join(out, "chunk-needles-values.jsonl"))
        r = self.file_run(b"\0" * 64, "token=", write_values=True, env=env)
        self.assertEqual((r.code, r.json["secret_values"]["written"], r.json["secret_values"]["values_file"]), (0, 0, "store/jobs/j000012/out/chunk-needles-values.jsonl"))
        self.assertEqual(os.path.getsize(os.path.join(out, "chunk-needles-values.jsonl")), 0)

    def test_a_results_file_is_never_replaced_by_a_later_scan_of_the_same_question(self):
        data = b"\0" * 10 + b"needle" * 40
        other = b"needle" * 40 + b"\0" * 10
        one = self.file_run(data, "needle", max_hits=2).json["hits"]["needle"]
        first = one["all_results"]
        self.assertEqual(one["earlier_answers"], 0)
        kept = self.read(first)
        self.assertEqual(self.file_run(data, "needle", max_hits=2).json["hits"]["needle"]["all_results"], first)
        two = self.file_run(other, "needle", max_hits=2).json["hits"]["needle"]
        second = two["all_results"]
        self.assertEqual(two["earlier_answers"], 1)
        self.assertNotEqual(first, second)
        self.assertTrue(second.endswith(".2.jsonl"), second)
        self.assertEqual(self.read(first), kept)
        self.assertNotEqual(self.read(second), kept)

    def test_image_discovery_does_not_walk_a_link_out_of_inputs_unless_the_manifest_names_it_as_a_set(self):
        bin_dir = self.icat(b"..needle..")
        self.write("outside/disk.bin", b"x")
        self.write("catalog/ext_disk.bin/partitions.txt", "p\n")
        os.makedirs(self.path("inputs"), exist_ok=True)
        os.symlink(self.path("outside"), self.path("inputs/ext"))
        r = run_tool("chunk_needles", {"needles": "needle", "inode": 12}, self.dir, [bin_dir])
        self.assertEqual(r.code, 1)
        self.assertIn("no disk image under inputs/", r.stdout + r.stderr)
        # A set held in place is a link directly under inputs/ and the manifest names it: that one is walked.
        self.write("inputs.json", json.dumps({"files": [], "sets": [{"name": "ext"}]}))
        r = run_tool("chunk_needles", {"needles": "needle", "inode": 12}, self.dir, [bin_dir])
        self.assertEqual(r.code, 0, r.stdout + r.stderr)
        self.assertEqual(r.json["source"]["image"], "inputs/ext/disk.bin")
        # A link inside the set is still a name, not a place.
        self.write("outside/deeper_target/more.bin", b"y")
        self.write("catalog/ext_hop_more.bin/partitions.txt", "p\n")
        os.symlink(self.path("outside/deeper_target"), self.path("outside/hop"))
        r = run_tool("chunk_needles", {"needles": "needle", "inode": 12}, self.dir, [bin_dir])
        self.assertEqual(r.code, 0, r.stdout + r.stderr)
        self.assertEqual(r.json["source"]["image"], "inputs/ext/disk.bin")


if __name__ == "__main__":
    unittest.main()
