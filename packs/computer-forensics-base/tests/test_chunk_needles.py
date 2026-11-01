"""chunk_needles: bounded parameters, a source that names its image and volume, locators instead of context, counts that do not depend on the chunk.

icat is a stand-in that records its arguments and writes a stream; expected offsets
come from re.finditer with a lookahead (overlapping occurrences count).
"""
import json
import os
import re
import stat
import unittest

from support import Case, manifest, run_tool, stand_in

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
        ok = self.file_run(data, "token=", write_values=True, env={"JOB_ID": "j000011", "OUT": out, "SECRET_OUTPUT": "1"})
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
        self.assertEqual(pages[16], [("F10-1", 10, "utf16le"), ("F54-0", 54, "ascii")])

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
        env = {"JOB_ID": "j000012", "OUT": out, "SECRET_OUTPUT": "1"}
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

    def test_an_image_that_cannot_be_chosen_is_a_json_answer_on_stdout_not_a_message_on_stderr(self):
        r = run_tool("chunk_needles", {"needles": "needle", "inode": 12}, self.dir)
        self.assertEqual(r.code, 1)
        self.assertIsNotNone(r.json, "stdout: %r stderr: %r" % (r.stdout, r.stderr))
        self.assertIn("no disk image", r.json["error"])
        self.write("inputs/a.dd", b"x")
        self.write("inputs/b.dd", b"y")
        r = run_tool("chunk_needles", {"needles": "needle", "inode": 12}, self.dir)
        self.assertEqual(r.code, 1)
        self.assertIn("several images", r.json["error"])
        self.assertEqual(sorted(r.json["candidates"]), ["inputs/a.dd", "inputs/b.dd"])


    def job_env(self, secret=True, **extra):
        out = self.path("job-out")
        os.makedirs(out, exist_ok=True)
        env = {"JOB_ID": "j000021", "OUT": out}
        if secret:
            env["SECRET_OUTPUT"] = "1"
        env.update(extra)
        return env, out

    def test_a_scan_that_uses_its_clock_answers_for_what_it_decided_and_says_how_to_go_on(self):
        needles = "|".join("zz%04dzz" % i for i in range(1000))
        planted = b"zz0007zz"
        data = bytearray(12 * 1024 * 1024)
        for k in range(12):
            data[k * 1024 * 1024 + 12345:k * 1024 * 1024 + 12345 + len(planted)] = planted
        data = bytes(data)
        expect = self.expect(data, planted)
        r = self.file_run(data, needles, max_seconds=1, max_hits=1000)
        self.assertEqual(r.code, 0, r.stdout[:300])
        j = r.json
        self.assertIs(j["complete"], False)
        self.assertEqual(j["status"], "partial")
        self.assertIn("1-second time budget", j["stopped"])
        self.assertIn("ioc_scan path=work/blob.bin start=%d" % j["next_start"], j["stopped"])
        got = [x["off"] for x in j["hits"]["zz0007zz"]["locations"]]
        self.assertTrue(got and all(o < j["next_start"] for o in got))
        self.assertEqual(got, [o for o in expect if o < j["next_start"]], "every occurrence that starts before next_start, none missing")
        whole = self.file_run(data, "zz0007zz", max_hits=1000)
        self.assertIs(whole.json["complete"], True)
        self.assertEqual(whole.json["status"], "complete")
        self.assertEqual([x["off"] for x in whole.json["hits"]["zz0007zz"]["locations"]], expect)

    def test_dense_matches_times_many_needles_end_at_the_clock_and_not_after_a_whole_feed(self):
        # 30 needles over 256 KiB of A: 7.8 million matches in the first feed alone; the clock was looked at only after the feed.
        import time
        t = time.monotonic()
        r = self.file_run(b"A" * (4 * 1024 * 1024), "|".join("A" * k for k in range(1, 31)), max_seconds=1, max_hits=5)
        wall = time.monotonic() - t
        self.assertEqual(r.code, 0, r.stdout[:300] + r.stderr[-300:])
        self.assertLess(wall, 6, "the call ended near its clock (1 second), after %.1f s" % wall)
        self.assertIs(r.json["complete"], False)
        self.assertEqual(r.json["status"], "partial")
        self.assertGreater(r.json["next_start"], 0)

    def test_a_finding_id_names_the_occurrence_so_a_scan_that_goes_on_never_reuses_one(self):
        data = b"-" * 10 + b"AAA" + b"-" * 40 + b"BBB" + b"-" * 20
        hits = self.file_run(data, "AAA|BBB", max_hits=10).json["hits"]
        rows = [x for n in hits for x in hits[n]["locations"]]
        self.assertEqual(sorted(x["off"] for x in rows), [10, 53])
        for x in rows:
            self.assertTrue(x["finding_id"].startswith("F%d-" % x["off"]), x)
        again = self.file_run(data, "BBB|AAA", max_hits=10).json["hits"]
        self.assertEqual({x["off"]: x["finding_id"] for n in again for x in again[n]["locations"]}.keys(), {10, 53})

    def test_an_inode_stream_that_uses_its_clock_stops_icat_and_is_not_reported_as_an_icat_failure(self):
        d = self.path("bin")
        os.makedirs(d)
        # an icat that never ends: it writes blocks until it is killed
        stand_in(d, "icat", "exec yes aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n")
        self.write("inputs/disk.E01", b"x")
        r = run_tool("chunk_needles", {"needles": "needle", "inode": 12, "image": "inputs/disk.E01", "offset": 0, "max_seconds": 1}, self.dir, [d], timeout=60)
        self.assertEqual(r.code, 0, r.stdout[:300] + r.stderr[-300:])
        self.assertEqual(r.json["status"], "partial")
        self.assertIn("extract the inode (icat_extract)", r.json["stopped"])
        self.assertGreater(r.json["next_start"], 0)

    def test_values_are_refused_in_a_job_that_was_not_run_as_secret_output(self):
        env, out = self.job_env(secret=False)
        r = self.file_run(b"x" * 20 + b"token=abc" + b"y" * 20, "token=", write_values=True, env=env)
        self.assertEqual(r.code, 1)
        self.assertIn("not run as secret output", r.json["error"])
        self.assertEqual(os.listdir(out), [])

    def test_the_manifest_makes_a_job_that_sets_write_values_secret_output(self):
        self.assertEqual(manifest("chunk_needles")["secret_output"], {"when_args": ["write_values"]})
        self.assertEqual(manifest("chunk_needles")["params"]["write_values"]["type"], "boolean")

    def test_the_values_file_stops_at_its_cap_and_says_where_while_the_locators_go_on(self):
        data = b"".join(b"..%03d token=%s .." % (i, SECRET) for i in range(200))
        env, out = self.job_env(CHUNK_NEEDLES_VALUES_BYTES="3000")
        r = self.file_run(data, "token=", write_values=True, env=env, max_hits=500)
        self.assertEqual(r.code, 0, r.stdout[:300])
        sv = r.json["secret_values"]
        path = os.path.join(out, "chunk-needles-values.jsonl")
        self.assertLessEqual(os.path.getsize(path), 3000)
        self.assertIs(sv["complete"], False)
        rows = self.read(path).splitlines()
        self.assertEqual(len(rows), sv["written"])
        self.assertEqual(sv["stopped_at_offset"], self.expect(data, b"token=")[len(rows)])
        self.assertEqual(r.json["status"], "partial")
        self.assertIs(r.json["complete"], False, "complete is false beside status partial, whichever file stopped")
        self.assertEqual(len(r.json["hits"]["token="]["locations"]), 200, "the locators have every occurrence")

    def test_the_locators_file_has_a_byte_cap_and_names_where_it_stopped_while_the_counts_go_on(self):
        data = b"".join(b"..%03d token=%s .." % (i, SECRET) for i in range(200))
        env, out = self.job_env(CHUNK_NEEDLES_LOCATORS_BYTES="3000")
        r = self.file_run(data, "token=", env=env, max_hits=1)
        self.assertEqual(r.code, 0, r.stdout[:300])
        h = r.json["hits"]["token="]
        path = os.path.join(out, "tool-output", os.path.basename(h["all_results"]))
        self.assertLessEqual(os.path.getsize(path), 3000)
        rows = [json.loads(x) for x in self.read(path).splitlines()]
        expect = self.expect(data, b"token=")
        self.assertEqual([x["off"] for x in rows], expect[:len(rows)], "the file is a prefix, every row whole")
        self.assertIs(h["all_results_complete"], False)
        self.assertEqual(h["all_results_stopped_at_offset"], expect[len(rows)])
        self.assertEqual(h["all_results_cap_bytes"], 3000)
        self.assertEqual(h["ascii"], 200, "the count is of the whole stream")

    def test_a_file_name_that_is_not_utf8_does_not_stop_the_values_writer(self):
        bad = os.path.join(self.dir, "bad\udcffname.bin")
        try:
            with open(bad, "wb") as fh:
                fh.write(b"\0" * 10 + b"token=abc" + b"\0" * 10)
        except OSError:
            self.skipTest("this file system does not hold a name that is not UTF-8")
        env, out = self.job_env()
        r = run_tool("chunk_needles", {"path": bad, "needles": "token=", "write_values": True}, self.dir, env=env)
        self.assertEqual(r.code, 0, r.stdout + r.stderr)
        row = json.loads(self.read(os.path.join(out, "chunk-needles-values.jsonl")).splitlines()[0])
        self.assertEqual(row["source"], bad)


class ChunkNeedlesLocators(Case):
    """Every needle's locators past its page go to one file whose rows name their needle; a list that cannot be written whole makes the
    answer partial; the locator directory is made by an own-directory walk that refuses a link anywhere on the way."""

    def run_limited(self, args, nofile=None, env=None, timeout=120):
        """The tool as a child with at most `nofile` open files (Linux), and its answer."""
        import resource
        import subprocess
        import sys
        from support import tool_path
        e = dict(os.environ)
        for k in ("JOB_ID", "OUT", "AGENT_ID", "SECRET_OUTPUT"):
            e.pop(k, None)
        e.update(env or {})

        def limit():
            if nofile:
                resource.setrlimit(resource.RLIMIT_NOFILE, (nofile, nofile))
        proc = subprocess.run([sys.executable, tool_path("chunk_needles")], input=json.dumps(args), capture_output=True, text=True, cwd=self.dir,
                              env=e, timeout=timeout, preexec_fn=limit)
        return proc, json.loads(proc.stdout)

    def test_a_thousand_needles_past_their_page_under_a_low_open_file_limit_lose_no_list(self):
        if not hasattr(os, "fork"):
            self.skipTest("an open-file limit is a Linux and macOS thing")
        needles = ["n%04d" % i for i in range(1000)]
        data = b"".join((b"." + n.encode()) * 3 for n in needles)
        self.write("work/blob.bin", data)
        proc, j = self.run_limited({"needles": needles, "path": "work/blob.bin", "max_hits": 1}, nofile=256)
        self.assertEqual(proc.returncode, 0, proc.stdout[:300] + proc.stderr[-300:])
        self.assertEqual((j["status"], j["complete"]), ("complete", True), j["status_basis"])
        files = {h["all_results"] for h in j["hits"].values()}
        self.assertEqual(len(files), 1, "one locator file for every needle")
        self.assertFalse(any("all_results_error" in h for h in j["hits"].values()))
        rows = [json.loads(x) for x in self.read(files.pop()).splitlines()]
        per = {}
        for x in rows:
            per.setdefault(x["needle_index"], []).append(x["off"])
        self.assertEqual(sorted(per), list(range(1000)))
        for i, n in enumerate(needles):
            self.assertEqual(sorted(per[i]), [m.start() for m in __import__("re").finditer(n.encode(), data)], n)
            self.assertEqual(j["hits"][n]["needle_index"], i)
            self.assertEqual(j["hits"][n]["all_results_rows"], 3)
        self.assertTrue(all(x["needle"] == needles[x["needle_index"]] for x in rows), "each row names its needle")

    def test_a_write_that_fails_makes_the_answer_partial_and_names_the_needles(self):
        import subprocess
        import sys
        from support import tool_path
        data = b"".join(b".needle-a.needle-b" for _ in range(40))
        self.write("work/blob.bin", data)
        prelude = ("import os, errno\n_fdopen = os.fdopen\n"
                   "class Full:\n"
                   "    def __init__(self, f): self.f, self.n = f, 0\n"
                   "    def write(self, s):\n"
                   "        self.n += len(s)\n"
                   "        if self.n > 300: raise OSError(errno.ENOSPC, 'No space left on device')\n"
                   "        return self.f.write(s)\n"
                   "    def __getattr__(self, k): return getattr(self.f, k)\n"
                   "os.fdopen = lambda fd, *a, **k: Full(_fdopen(fd, *a, **k))\n"
                   "import sys\nsrc = open(sys.argv[1], encoding='utf-8').read()\nexec(compile(src, sys.argv[1], 'exec'), {'__name__': '__main__'})\n")
        e = dict(os.environ)
        for k in ("JOB_ID", "OUT", "AGENT_ID", "SECRET_OUTPUT"):
            e.pop(k, None)
        proc = subprocess.run([sys.executable, "-c", prelude, tool_path("chunk_needles")], input=json.dumps({"needles": "needle-a|needle-b", "path": "work/blob.bin", "max_hits": 2}),
                              capture_output=True, text=True, cwd=self.dir, env=e, timeout=60)
        self.assertEqual(proc.returncode, 0, proc.stdout[:300] + proc.stderr[-300:])
        j = json.loads(proc.stdout)
        self.assertEqual((j["status"], j["complete"]), ("partial", False))
        for n in ("needle-a", "needle-b"):
            self.assertIn("a write failed", j["hits"][n]["all_results_error"])
            self.assertEqual(j["hits"][n]["ascii"], 40)
            self.assertNotIn("all_results", j["hits"][n])
        self.assertIn("needle_index 0, 1", j["status_basis"])
        self.assertIn("max_hits", j["status_basis"])
        left = [n for _d, _s, names in os.walk(self.path("work")) for n in names if n.endswith(".jsonl") or n.startswith(".chunk_needles")]
        self.assertEqual(left, [], "no half file is kept")

    def test_a_locator_file_that_cannot_be_created_is_partial(self):
        # work/<agent>/tool-output is a file, so the directory cannot be made
        self.write("work/s1/tool-output", b"in the way")
        self.write("inputs/blob.bin", b".needle" * 5)
        proc, j = self.run_limited({"needles": "needle", "path": "inputs/blob.bin", "max_hits": 1}, env={"AGENT_ID": "s1"})
        self.assertEqual((j["status"], j["complete"]), ("partial", False))
        self.assertIn("all_results_error", j["hits"]["needle"])

    def test_a_link_on_the_way_to_the_locator_directory_is_refused_and_nothing_is_written_through_it(self):
        self.write("inputs/blob.bin", b".needle" * 5)
        for where in ("work", "work/s1", "work/s1/tool-output"):
            target = self.path("elsewhere-%s" % where.replace("/", "-"))
            os.makedirs(target)
            if where == "work/s1/tool-output":
                os.makedirs(self.path("work/s1"), exist_ok=True)
            elif where == "work/s1":
                os.makedirs(self.path("work"), exist_ok=True)
            os.symlink(target, self.path(where))
            proc, j = self.run_limited({"needles": "needle", "path": "inputs/blob.bin", "max_hits": 1}, env={"AGENT_ID": "s1"})
            self.assertEqual(os.listdir(target), [], where)
            self.assertIn("symbolic link", j["hits"]["needle"]["all_results_error"], where)
            self.assertEqual(j["status"], "partial", where)
            os.unlink(self.path(where))
        # in a job: $OUT/tool-output is the link
        out = self.path("job-out")
        os.makedirs(out)
        target = self.path("elsewhere-job")
        os.makedirs(target)
        os.symlink(target, os.path.join(out, "tool-output"))
        proc, j = self.run_limited({"needles": "needle", "path": "inputs/blob.bin", "max_hits": 1}, env={"JOB_ID": "j000050", "OUT": out})
        self.assertEqual(os.listdir(target), [])
        self.assertIn("symbolic link", j["hits"]["needle"]["all_results_error"])

    def test_the_search_for_the_image_keeps_at_most_200_names_and_is_on_a_clock(self):
        import subprocess
        import sys
        from support import tool_path
        for i in range(201):
            self.write("inputs/set/d%03d/image%03d.bin" % (i % 7, i), b"x")
            self.write("catalog/set_d%03d_image%03d.bin/partitions.txt" % (i % 7, i), "p\n")
        r = run_tool("chunk_needles", {"needles": "x", "inode": 5}, self.dir)
        self.assertEqual((r.code, r.json["status"]), (1, "failed"))
        self.assertIn("more than 200 images", r.json["error"])
        self.assertLess(len(r.stdout), 2000)
        # a tree the search cannot finish inside its clock (a stand-in scandir that takes half a second a directory, a one-second clock)
        with open(tool_path("chunk_needles"), encoding="utf-8") as fh:
            src = fh.read().replace("RESOLVE_SECONDS = 60 ", "RESOLVE_SECONDS = 1 ", 1)
        self.assertIn("RESOLVE_SECONDS = 1 ", src)
        self.write("patched_run.py", src)
        prelude = ("import os, sys, time\n_scandir = os.scandir\n"
                   "def slow(*a, **k):\n    time.sleep(0.4)\n    return _scandir(*a, **k)\n"
                   "os.scandir = slow\n"
                   "exec(compile(open(sys.argv[1], encoding='utf-8').read(), sys.argv[1], 'exec'), {'__name__': '__main__'})\n")
        for n in range(201):          # fewer than 200 catalogued images, so only the clock can stop it
            if n >= 150:
                os.unlink(self.path("catalog/set_d%03d_image%03d.bin/partitions.txt" % (n % 7, n)))
        env = dict(os.environ)
        for k in ("JOB_ID", "OUT", "AGENT_ID", "SECRET_OUTPUT"):
            env.pop(k, None)
        proc = subprocess.run([sys.executable, "-c", prelude, self.path("patched_run.py")], input=json.dumps({"needles": "x", "inode": 5}),
                              capture_output=True, text=True, cwd=self.dir, env=env, timeout=60)
        j = json.loads(proc.stdout)
        self.assertEqual((proc.returncode, j["status"]), (1, "failed"))
        self.assertIn("used its 1 seconds", j["error"])

    def test_hostile_arguments_and_refusals_are_json_with_the_pair(self):
        self.write("work/blob.bin", b"abc needle abc")
        for raw in ("[" * 100000, "not json", "[]"):
            r = run_tool("chunk_needles", None, self.dir, raw_input=raw)
            self.assertEqual((r.code, r.json["status"]), (1, "failed"), raw[:20])
            self.assertNotIn("Traceback", r.stderr)
        for args in ({"needles": "x", "path": 5}, {"needles": "x", "path": ["a"]}, {"needles": "x", "path": "nope"}, {"needles": "x"},
                     {"needles": "x", "path": "work/blob.bin", "max_hits": 0}, {"needles": ["a", 1], "path": "work/blob.bin"}):
            r = run_tool("chunk_needles", args, self.dir)
            self.assertEqual((r.code, r.json["status"]), (1, "failed"), args)
            self.assertTrue(len(r.json["status_basis"]) > 20)
            self.assertNotIn("Traceback", r.stderr)

    def test_a_link_at_the_values_directory_is_refused_by_name(self):
        real = self.path("real-out")
        os.makedirs(real)
        link = self.path("out-link")
        os.symlink(real, link)
        self.write("inputs/blob.bin", b"x" * 10 + b"token=abc" + b"y" * 10)
        proc, j = self.run_limited({"needles": "token=", "path": "inputs/blob.bin", "write_values": True}, env={"JOB_ID": "j000051", "OUT": link, "SECRET_OUTPUT": "1"})
        self.assertEqual(proc.returncode, 1)
        self.assertIn("symbolic link", j["error"])
        self.assertEqual(os.listdir(real), [])


if __name__ == "__main__":
    unittest.main()
