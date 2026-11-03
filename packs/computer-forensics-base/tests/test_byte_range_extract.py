"""byte_range_extract: the bytes asked for, whole or said to be short, with a digest of each and nothing else about them.

The sources are built here; a range across the boundary of a split set goes through a descriptor layer_describe wrote (stand-in programs where the
Sleuth Kit is not needed). Every row says what was asked for and what was read.
"""
import hashlib
import json
import os
import resource
import signal
import subprocess
import sys
import time
import unittest

from support import Case, have, run_tool, stand_in, tool_path

DATA = bytes((i * 7 + i // 251) % 256 for i in range(5000))


def sha(data):
    return hashlib.sha256(data).hexdigest()


class ByteRangeExtract(Case):
    def source(self, data=DATA, name="evidence/disk.dd"):
        return self.write(name, data)

    def run_it(self, args, **kwargs):
        args = dict(args)
        args.setdefault("out_dir", self.path("out", "ranges"))
        return run_tool("byte_range_extract", args, self.dir, **kwargs)

    def got(self, a, n, suffix=".bin"):
        return self.read(os.path.join(a["out_dir"], "range-%06d%s" % (n + 1, suffix)), "rb")

    # ---- the ranges
    def test_ranges_are_written_whole_with_a_digest_each_and_one_for_the_concatenation(self):
        path = self.source()
        res = self.run_it({"source": path, "ranges": [{"offset": 0, "length": 300}, {"offset": 1000, "length": 200}]})
        self.assertEqual(res.code, 0, res.stderr)
        a = res.json
        self.assertEqual((a["status"], a["complete"], a["ranges_whole"], a["actual_bytes"], a["requested_bytes"]), ("complete", True, 2, 500, 500), a["status_basis"])
        self.assertEqual(self.got(a, 0), DATA[0:300])
        self.assertEqual(self.got(a, 1), DATA[1000:1200])
        self.assertEqual([r["sha256"] for r in a["ranges"]], [sha(DATA[0:300]), sha(DATA[1000:1200])])
        self.assertEqual(a["sha256_of_the_ranges_in_order"], sha(DATA[0:300] + DATA[1000:1200]))
        self.assertEqual(a["ranges_in_file"], 2)
        self.assertEqual(len(self.read(os.path.join(a["out_dir"], "ranges.jsonl")).splitlines()), 2)
        self.assertEqual(oct(os.stat(os.path.join(a["out_dir"], "range-000001.bin")).st_mode & 0o777), "0o600")
        self.assertEqual(oct(os.stat(a["out_dir"]).st_mode & 0o777), "0o700")
        self.assertNotIn(DATA[0:16].hex(), res.stdout)

    def test_the_answer_never_carries_a_byte_of_a_range(self):
        marker = b"PASSWORD=hunter2hunter2hunter2"
        path = self.source(b"\0" * 100 + marker + b"\0" * 400)
        res = self.run_it({"source": path, "ranges": [{"offset": 100, "length": len(marker)}]})
        self.assertNotIn("hunter2", res.stdout)
        self.assertNotIn("hunter2", res.stderr)
        self.assertNotIn(marker.hex(), res.stdout)
        self.assertIn("hunter2", self.read(os.path.join(res.json["out_dir"], "range-000001.bin")))

    def test_a_range_past_the_end_is_short_and_stays_partial(self):
        path = self.source()
        a = self.run_it({"source": path, "ranges": [{"offset": 4900, "length": 300}]}).json
        self.assertEqual((a["status"], a["complete"]), ("partial", False))
        row = a["ranges"][0]
        self.assertEqual((row["requested"], row["actual"], row["status"]), (300, 100, "short"))
        self.assertEqual(row["file"], "range-000001.bin.partial")
        self.assertEqual(self.got(a, 0, ".bin.partial"), DATA[4900:])
        self.assertFalse(os.path.exists(os.path.join(a["out_dir"], "range-000001.bin")))
        self.assertIsNone(a["sha256_of_the_ranges_in_order"])

    def test_an_offset_beyond_the_end_gives_nothing_and_says_so(self):
        a = self.run_it({"source": self.source(), "ranges": [{"offset": 9000, "length": 10}]}).json
        self.assertEqual((a["status"], a["ranges"][0]["actual"], a["ranges"][0]["status"]), ("partial", 0, "short"))
        self.assertNotEqual(a["status"], "complete")

    def test_a_zero_length_range_is_an_empty_whole_file(self):
        a = self.run_it({"source": self.source(), "ranges": [{"offset": 10, "length": 0}, {"offset": 20, "length": 0}]}).json
        self.assertEqual((a["status"], a["ranges_whole"]), ("complete", 2), a["status_basis"])
        self.assertEqual(self.got(a, 0), b"")
        self.assertIsNone(a["ranges"][0]["sha256"])

    def test_a_digest_of_fewer_than_128_bytes_is_not_written(self):
        a = self.run_it({"source": self.source(), "ranges": [{"offset": 0, "length": 127}, {"offset": 0, "length": 128}]}).json
        self.assertIsNone(a["ranges"][0]["sha256"])
        self.assertIn("reversed", a["ranges"][0]["digest_not_written"])
        self.assertEqual(a["ranges"][1]["sha256"], sha(DATA[:128]))

    def test_overlapping_ranges_are_each_copied_and_flagged(self):
        a = self.run_it({"source": self.source(), "ranges": [{"offset": 0, "length": 500}, {"offset": 400, "length": 500}, {"offset": 2000, "length": 200}]}).json
        self.assertEqual(a["status"], "complete", a["status_basis"])
        self.assertEqual([r["overlaps_an_earlier_range"] for r in a["ranges"]], [False, True, False])
        self.assertEqual(self.got(a, 1), DATA[400:900])

    def test_a_sparse_source_reads_as_zeros_where_it_has_holes(self):
        path = self.path("evidence", "sparse.dd")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.truncate(1 << 20)
            fh.seek(1 << 19)
            fh.write(b"tail-bytes")
        a = self.run_it({"source": path, "ranges": [{"offset": 1000, "length": 200}, {"offset": 1 << 19, "length": 10}]}).json
        self.assertEqual(a["status"], "complete", a["status_basis"])
        self.assertEqual(self.got(a, 0), b"\0" * 200)
        self.assertEqual(self.got(a, 1), b"tail-bytes")

    def test_a_budget_cuts_the_range_it_reaches_and_names_where_to_go_on(self):
        a = self.run_it({"source": self.source(), "ranges": [{"offset": 0, "length": 300}, {"offset": 300, "length": 300}, {"offset": 600, "length": 300}], "max_total_bytes": 450}).json
        self.assertEqual((a["status"], a["stopped_by"], a["next_range"]), ("partial", "max_total_bytes", 1))
        self.assertEqual([r["status"] for r in a["ranges"]], ["whole", "cut", "not_run"])
        self.assertEqual((a["ranges"][1]["actual"], a["actual_bytes"]), (150, 450))
        self.assertEqual(self.got(a, 1, ".bin.partial"), DATA[300:450])

    def test_a_taken_output_name_gets_a_new_one_and_nothing_is_replaced(self):
        out = self.path("out", "taken")
        os.makedirs(out)
        self.write("out/taken/range-000001.bin", b"earlier")
        self.write("out/taken/range-000001.bin.partial", b"earlier partial")
        self.write("out/taken/ranges.jsonl", b"earlier rows")
        self.write("out/taken/receipt.json", b"earlier receipt")
        path = self.source()
        one = self.run_it({"source": path, "ranges": [{"offset": 0, "length": 200}], "out_dir": out})
        self.assertEqual(one.code, 0, one.stderr)
        a = one.json
        self.assertEqual((a["status"], a["ranges"][0]["file"], a["ranges_file"], a["receipt"]), ("complete", "range-000001.2.bin", "ranges.2.jsonl", "receipt.2.json"))
        self.assertEqual(self.read("out/taken/range-000001.bin"), "earlier")
        self.assertEqual(self.read("out/taken/range-000001.bin.partial"), "earlier partial")
        self.assertEqual(self.read("out/taken/ranges.jsonl"), "earlier rows")
        self.assertEqual(self.read("out/taken/receipt.json"), "earlier receipt")
        self.assertEqual(self.read("out/taken/range-000001.2.bin", "rb"), DATA[:200])
        # and a second run in the same directory neither crashes nor writes over the first
        two = self.run_it({"source": path, "ranges": [{"offset": 0, "length": 200}], "out_dir": out}).json
        self.assertEqual((two["status"], two["ranges"][0]["file"], two["ranges_file"]), ("complete", "range-000001.3.bin", "ranges.3.jsonl"))
        self.assertEqual(self.read("out/taken/range-000001.2.bin", "rb"), DATA[:200])

    def test_the_default_out_dir_is_new_each_time(self):
        path = self.source()
        one = run_tool("byte_range_extract", {"source": path, "ranges": [{"offset": 0, "length": 200}]}, self.dir).json
        two = run_tool("byte_range_extract", {"source": path, "ranges": [{"offset": 0, "length": 200}]}, self.dir).json
        self.assertNotEqual(one["out_dir"], two["out_dir"])

    # ---- a split set through its descriptor
    def test_a_range_across_the_boundary_of_two_segments_of_a_descriptor(self):
        parts = [self.write("evidence/d.00%d" % (n + 1), DATA[n * 2000:(n + 1) * 2000 if n < 2 else 5000]) for n in range(3)]
        d = self.path("bin")
        os.makedirs(d, exist_ok=True)
        for name in ("mmls", "fsstat", "img_stat"):
            stand_in(d, name, "exit 1\n")
        desc = run_tool("layer_describe", {"sources": parts, "out_dir": self.path("out", "layers")}, self.dir, path_dirs=[d]).json
        self.assertIsNotNone(desc["descriptor"], desc)
        descriptor = os.path.join(self.path("out", "layers"), desc["descriptor"]["file"])
        a = self.run_it({"descriptor": descriptor, "ranges": [{"offset": 1900, "length": 300}, {"offset": 3900, "length": 1100}]}).json
        self.assertEqual(a["status"], "complete", a["status_basis"])
        self.assertEqual(self.got(a, 0), DATA[1900:2200])
        self.assertEqual(self.got(a, 1), DATA[3900:5000])
        self.assertEqual((a["source"]["kind"], a["source"]["bytes"], a["source"]["descriptor"]["sources"]), ("split_raw", 5000, 3))
        # the end of the media is the end of the last segment
        b = self.run_it({"descriptor": descriptor, "ranges": [{"offset": 4900, "length": 300}], "out_dir": self.path("out", "b")}).json
        self.assertEqual((b["status"], b["ranges"][0]["actual"]), ("partial", 100))
        # a forged descriptor, and an E01-layer descriptor, are refused
        with open(descriptor, "r+b") as fh:
            fh.seek(30)
            byte = fh.read(1)
            fh.seek(30)
            fh.write(bytes([byte[0] ^ 1]))
        c = self.run_it({"descriptor": descriptor, "ranges": [{"offset": 0, "length": 1}], "out_dir": self.path("out", "c")})
        self.assertEqual(c.code, 1)
        self.assertIn("do not hash to the name", c.json["status_basis"])

    # ---- hostile sources and arguments
    def test_a_symlink_a_fifo_a_directory_and_a_device_are_refused_without_waiting(self):
        good = self.source()
        link, fifo, directory = (self.path("evidence", n) for n in ("link.dd", "fifo.dd", "dir.dd"))
        os.symlink(good, link)
        os.mkfifo(fifo)
        os.mkdir(directory)
        for bad in (link, fifo, directory, "/dev/null", self.path("evidence", "gone.dd")):
            started = time.monotonic()
            res = self.run_it({"source": bad, "ranges": [{"offset": 0, "length": 10}], "out_dir": self.path("out", os.path.basename(bad))})
            self.assertLess(time.monotonic() - started, 15, bad)
            self.assertEqual((res.code, res.json["status"]), (1, "failed"), bad)

    def test_a_source_swapped_for_a_fifo_after_the_check_does_not_hang(self):
        path = self.source()
        os.unlink(path)
        os.mkfifo(path)
        started = time.monotonic()
        res = self.run_it({"source": path, "ranges": [{"offset": 0, "length": 10}]})
        self.assertLess(time.monotonic() - started, 15)
        self.assertEqual(res.code, 1)

    def test_the_arguments_are_checked(self):
        path = self.source()
        good = [{"offset": 0, "length": 10}]
        for args in ({}, {"source": path}, {"source": path, "ranges": []}, {"source": path, "ranges": [{"offset": -1, "length": 1}]}, {"source": path, "ranges": [{"offset": 0}]},
                     {"source": path, "ranges": [{"offset": 0, "length": 1, "x": 1}]}, {"source": path, "ranges": [{"offset": True, "length": 1}]}, {"source": path, "ranges": [{"offset": "0", "length": 1}]},
                     {"source": path, "ranges": good, "descriptor": path}, {"source": path, "ranges": good, "max_seconds": 0}, {"source": path, "ranges": good, "other": 1},
                     {"source": path, "ranges": good, "verify_sources": True}, {"source": path, "ranges": [{"offset": 0, "length": 1 << 41}]}):
            res = run_tool("byte_range_extract", args, self.dir)
            self.assertEqual((res.code, res.json["status"]), (1, "failed"), args)

    def test_a_name_shaped_like_a_token_is_not_printed(self):
        token = "AKIAIOSFODNN7EXAMPLEzzqq0987654321"
        path = self.source(name="evidence/%s.dd" % token)
        res = self.run_it({"source": path, "ranges": [{"offset": 0, "length": 200}]})
        self.assertNotIn(token, res.stdout)
        self.assertEqual(res.json["status"], "complete")
        self.assertNotIn(token, self.read(os.path.join(res.json["out_dir"], "receipt.json")))

    # ---- stops and writes
    def test_a_stop_signal_mid_copy_leaves_a_named_partial_and_one_partial_document(self):
        big = self.sparse(4 << 30)
        env = dict(os.environ)
        for k in ("JOB_ID", "OUT", "AGENT_ID", "SECRET_OUTPUT"):
            env.pop(k, None)
        for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            out = self.path("out", "stop%d" % signum)
            spec = self.write("spec%d.json" % signum, json.dumps({"source": big, "ranges": [{"offset": 0, "length": 4 << 30}], "out_dir": out}))
            stdin = open(spec, "rb")
            self.addCleanup(stdin.close)
            proc = subprocess.Popen([sys.executable, tool_path("byte_range_extract")], stdin=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=self.dir, env=env, start_new_session=True)
            try:
                deadline = time.monotonic() + 20
                partial = os.path.join(out, "range-000001.bin.partial")
                while time.monotonic() < deadline and not (os.path.exists(partial) and os.path.getsize(partial) > 0):
                    time.sleep(0.01)
                os.kill(proc.pid, signum)
                stdout, _ = proc.communicate(timeout=30)
            finally:
                if proc.poll() is None:
                    os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait()
            self.assertEqual(proc.returncode, 128 + signum)
            doc = json.loads(stdout)
            self.assertEqual((doc["status"], doc["interrupted"], doc["signal"], doc["current_range_file"]), ("partial", True, signum, "range-000001.bin.partial"))
            self.assertTrue(0 < os.path.getsize(os.path.join(out, "range-000001.bin.partial")) < (4 << 30))
            self.assertFalse(os.path.exists(os.path.join(out, "range-000001.bin")))
            self.assertEqual([n for n in os.listdir(out) if n.startswith(".") or ".tmp." in n], [])

    # ---- a copy that is held still while the world changes under it (SIGSTOP at the first bytes; nothing else in the tool is touched)
    def sparse(self, size, name="evidence/sparse.dd"):
        path = self.path(name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.truncate(size)
        return path

    def held_run(self, spec, out, between):
        """Start the tool, stop it when range 1 has its first bytes, call `between()`, let it go on, and return (code, document)."""
        env = dict(os.environ)
        for k in ("JOB_ID", "OUT", "AGENT_ID", "SECRET_OUTPUT"):
            env.pop(k, None)
        spec_path = self.write("spec-held.json", json.dumps(spec))
        stdin = open(spec_path, "rb")
        self.addCleanup(stdin.close)
        proc = subprocess.Popen([sys.executable, tool_path("byte_range_extract")], stdin=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=self.dir, env=env, start_new_session=True)
        try:
            partial = os.path.join(out, "range-000001.bin.partial")
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline and not (os.path.exists(partial) and os.path.getsize(partial) > 0):
                time.sleep(0.002)
            os.kill(proc.pid, signal.SIGSTOP)
            self.assertLess(os.path.getsize(partial), 1 << 30, "the copy was over before it could be held")
            between()
            os.kill(proc.pid, signal.SIGCONT)
            stdout, _ = proc.communicate(timeout=120)
        finally:
            if proc.poll() is None:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait()
        return proc.returncode, json.loads(stdout)

    def test_a_source_that_changes_while_it_is_copied_makes_the_run_failed(self):
        big = self.sparse(2 << 30)
        out = self.path("out", "changed")
        code, doc = self.held_run({"source": big, "ranges": [{"offset": 0, "length": 1 << 30}], "out_dir": out}, out, lambda: open(big, "ab").close() or os.truncate(big, (2 << 30) + 1))
        self.assertEqual((code, doc["status"]), (0, "failed"), doc)
        self.assertIn("changed", doc["status_basis"])
        self.assertFalse(doc.get("complete"))

    def test_a_final_name_taken_after_it_was_chosen_is_not_replaced(self):
        big = self.sparse(2 << 30)
        out = self.path("out", "taken")
        final = os.path.join(out, "range-000001.bin")

        def take():
            with open(final, "wb") as fh:
                fh.write(b"someone else's file")
        code, doc = self.held_run({"source": big, "ranges": [{"offset": 0, "length": 1 << 30}], "out_dir": out}, out, take)
        self.assertEqual(self.read(final, "rb"), b"someone else's file")
        self.assertNotEqual(doc["status"], "complete", doc)
        row = doc["ranges"][0]
        self.assertEqual(row["status"], "whole_but_not_renamed")
        self.assertEqual(row["file"], "range-000001.bin.partial")
        self.assertEqual(os.path.getsize(os.path.join(out, row["file"])), 1 << 30)

    def test_a_file_size_limit_never_gives_a_wrong_complete_and_the_counts_are_what_the_files_hold(self):
        path = self.source(os.urandom(6000))
        out = self.path("out", "limited")
        env = dict(os.environ)
        for k in ("JOB_ID", "OUT", "AGENT_ID", "SECRET_OUTPUT"):
            env.pop(k, None)
        proc = subprocess.run([sys.executable, tool_path("byte_range_extract")],
                              input=json.dumps({"source": path, "ranges": [{"offset": 0, "length": 3000}, {"offset": 0, "length": 3000}, {"offset": 0, "length": 3000}], "out_dir": out}).encode(),
                              capture_output=True, cwd=self.dir, env=env, timeout=60, preexec_fn=lambda: resource.setrlimit(resource.RLIMIT_FSIZE, (2500, 2500)))
        a = json.loads(proc.stdout)
        self.assertNotEqual(a["status"], "complete", a["status_basis"])
        self.assertFalse(a["complete"])
        listing = open(os.path.join(out, "ranges.jsonl"), "rb").read().count(b"\n") if os.path.exists(os.path.join(out, "ranges.jsonl")) else 0
        self.assertEqual(a["ranges_in_file"], listing)
        for r in a["ranges"]:
            if r["status"] == "whole":
                self.assertEqual(os.path.getsize(os.path.join(out, r["file"])), r["requested"])
        self.assertEqual([n for n in os.listdir(out) if n.startswith(".")], [])


if __name__ == "__main__":
    unittest.main()
