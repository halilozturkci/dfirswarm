"""sig_carve: every header found once, at its true offset, whatever the read block.

The headers are those the formats define (the PNG signature, the Windows event
log's "ElfFile", the SQLite header string); each test places one at, and either
side of, a read-block boundary and asks for it in files read with different block
sizes, so a header cut by a boundary, or counted twice for it, shows as a wrong count.
"""
import json
import os
import sys
import unittest

from support import Case, run_tool

PNG = b"\x89PNG\r\n\x1a\n"
EVTX = b"ElfFile\x00"
SQLITE = b"SQLite format 3\x00"


class SigCarve(Case):
    def scan(self, data, window, sig="all", **kw):
        src = self.write("dump.bin", data)
        return run_tool("sig_carve", dict({"path": src, "sig": sig, "window_bytes": window}, **kw), self.dir)

    def test_a_header_at_and_around_a_block_boundary_is_found_once_at_its_offset(self):
        for window in (64, 100, 4096):
            for sig_name, header in (("PNG", PNG), ("EVTX", EVTX), ("SQLite", SQLITE)):
                for delta in range(-len(header) - 1, 3):
                    at = window + delta
                    data = b"\x00" * at + header + b"\x00" * (3 * window)
                    r = self.scan(data, window, sig_name)
                    hits = r.json["signatures"][sig_name]
                    self.assertEqual((hits["count"], [h["offset"] for h in hits["hits"]]), (1, [at]), (window, sig_name, at))

    def test_a_seam_between_two_reads_makes_no_hit_the_file_does_not_hold(self):
        # "MAM" is M A M. Where one read ends and the next begins, the bytes "AM" at the next
        # read's first two offsets are not a MAM: the byte before them is not an M. A scanner that
        # glued a copy of the carried bytes onto the next read would see M (the carry), A, M and
        # report a MAM one byte before the seam. The default window is the real one (the old tool's
        # was 64 MiB, this one's 8 MiB), so both seams get the same two bytes.
        path = self.path("seam.bin")
        with open(path, "wb") as fh:
            fh.truncate(64 * 1024 * 1024 + 4096)
            for seam in (8 * 1024 * 1024, 64 * 1024 * 1024):
                fh.seek(seam)
                fh.write(b"AM")
        r = run_tool("sig_carve", {"path": path, "sig": "MAM"}, self.dir)
        self.assertEqual(r.code, 0, r.stdout)
        found = r.json.get("signatures", r.json)["MAM"]          # the old tool answered with the signatures at the top
        self.assertEqual(found["count"], 0, found["hits"])

    def test_every_signature_is_looked_for_in_one_pass(self):
        data = PNG + b"\x00" * 200 + EVTX + b"\x00" * 200 + SQLITE + b"\x00" * 200
        r = self.scan(data, 64)
        self.assertEqual(r.json["scanned"]["passes"], 1)
        self.assertEqual(r.json["scanned"], dict(r.json["scanned"], start=0, end=len(data), bytes=len(data), complete=True))
        self.assertEqual({k: v["count"] for k, v in r.json["signatures"].items() if v["count"]}, {"PNG": 1, "EVTX": 1, "SQLite": 1})
        self.assertEqual(r.json["source"]["bytes"], len(data))

    def test_overlapping_occurrences_of_one_header_are_each_a_hit(self):
        r = self.scan(b"\x00" * 10 + b"MZMZ" + b"\x00" * 10, 16, "MZ")
        self.assertEqual([h["offset"] for h in r.json["signatures"]["MZ"]["hits"]], [10, 12])

    def test_an_unknown_signature_is_an_error_not_an_empty_result(self):
        r = self.scan(b"\x00" * 64, 64, "NoSuchSig")
        self.assertEqual(r.code, 1)
        self.assertIn("no such signature", r.json["error"])
        self.assertIn("PNG", r.json["signatures"])

    def test_bounds_are_validated(self):
        for bad in ({"context": 10 ** 9}, {"context": -1}, {"max_hits": 0}, {"window_bytes": 1}):
            self.assertEqual(self.scan(b"\x00" * 64, 64, "PNG", **bad).code, 1 if "window_bytes" not in bad else 1, bad)

    def test_the_scca_hit_names_where_the_file_starts(self):
        r = self.scan(b"\x00" * 20 + b"\x17\x00\x00\x00SCCA" + b"\x00" * 40, 64, "SCCA")
        hit = r.json["signatures"]["SCCA"]["hits"][0]
        self.assertEqual((hit["offset"], hit["candidate_start"]), (24, 20))

    def test_more_hits_than_the_page_are_all_in_a_file(self):
        data = b"".join(b"\x00" * 30 + PNG for _ in range(40))
        r = self.scan(data, 64, "PNG", max_hits=5)
        png = r.json["signatures"]["PNG"]
        self.assertEqual((png["count"], png["returned"], png["truncated"]), (40, 5, True))
        rows = self.read(png["all_results"]).splitlines()
        self.assertEqual(len(rows), 40)

    def test_a_signature_name_that_is_not_a_string_is_an_answer_not_a_traceback(self):
        for bad in (["PNG"], {"a": 1}, 7):
            r = self.scan(b"\x00" * 64, 64, bad)
            self.assertEqual(r.code, 1, bad)
            self.assertNotIn("Traceback", r.stderr)
            self.assertIn("signature name", r.json["error"])

    def test_a_whole_result_file_that_cannot_be_written_is_said_and_the_count_stays_whole(self):
        if os.geteuid() == 0:
            self.skipTest("root writes everywhere")
        data = b"".join(b"\x00" * 30 + PNG for _ in range(40))
        src = self.write("inputs/blob.bin", data)
        os.makedirs(self.path("work"))
        os.chmod(self.path("work"), 0o555)                    # work/ cannot be made into: the tool-output directory cannot be created
        try:
            r = run_tool("sig_carve", {"path": src, "sig": "PNG", "max_hits": 5}, self.dir)
        finally:
            os.chmod(self.path("work"), 0o755)
        self.assertEqual(r.code, 0, r.stdout + r.stderr)
        self.assertNotIn("Traceback", r.stderr)
        png = r.json["signatures"]["PNG"]
        self.assertEqual((png["count"], png["returned"], png["truncated"]), (40, 5, True))
        self.assertNotIn("all_results", png)
        self.assertIn("could not be written", png["all_results_error"])

    def test_a_header_across_the_64_mib_seam_is_one_hit_at_its_own_offset(self):
        # The old default window was 64 MiB: a MAM whose M ends one window and whose AM begins the next, and one that begins the next, are
        # each counted once, at the offset the bytes are at.
        mib64 = 64 * 1024 * 1024
        path = self.path("seam2.bin")
        with open(path, "wb") as fh:
            fh.truncate(mib64 + 4096)
            fh.seek(mib64 - 1)
            fh.write(b"MAM")                 # straddles: M | AM
            fh.seek(mib64 + 100)
            fh.write(b"MAM")                 # wholly in the second window
            fh.seek(mib64 - 3)               # "MAM" at mib64-3 would overlap the straddler; it is not written
        r = run_tool("sig_carve", {"path": path, "sig": "MAM", "window_bytes": mib64}, self.dir)
        mam = r.json["signatures"]["MAM"]
        self.assertEqual((mam["count"], [h["offset"] for h in mam["hits"]]), (2, [mib64 - 1, mib64 + 100]))

    def test_a_scan_stopped_at_its_budget_is_continued_with_start_without_a_lost_seam_or_a_repeated_hit(self):
        import importlib.util
        import io
        import contextlib
        import signal
        import types
        from support import tool_path
        data = bytearray(b"\0" * 400)
        for at in (10, 60, 125, 140, 190, 255, 300):           # 60 and 125 straddle the 64-byte seams (125 the one the first scan stops at)
            data[at:at + len(PNG)] = PNG
        src = self.write("dump.bin", bytes(data))

        def scan(**kw):
            spec = importlib.util.spec_from_file_location("sc", tool_path("sig_carve"))
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            ticks = kw.pop("stop_after", None)
            if ticks is not None:
                calls = [0]

                def fake():
                    calls[0] += 1
                    return 0 if calls[0] <= ticks else 10 ** 6
                mod.time = types.SimpleNamespace(monotonic=fake)
            sys.stdin = io.StringIO(json.dumps(dict({"path": src, "sig": "PNG", "window_bytes": 64, "context": 0}, **kw)))
            out = io.StringIO()
            old_handlers = [signal.getsignal(s) for s in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT)]
            try:
                with contextlib.redirect_stdout(out):
                    try:
                        mod.main()
                    except SystemExit as exc:
                        code = exc.code
            finally:
                for s, h in zip((signal.SIGTERM, signal.SIGHUP, signal.SIGINT), old_handlers):
                    signal.signal(s, h)
                sys.stdin = sys.__stdin__
            return code, json.loads(out.getvalue())

        code, whole = scan()
        self.assertEqual(code, 0)
        want = [h["offset"] for h in whole["signatures"]["PNG"]["hits"]]
        self.assertEqual(want, [10, 60, 125, 140, 190, 255, 300])
        code, first = scan(stop_after=3)                      # the clock runs out after the second window: 128 bytes
        self.assertEqual(code, 0, "a stop at the budget is a valid answer for what it covered, not a failed run")
        self.assertIs(first["scanned"]["complete"], False)
        self.assertEqual(first["scanned"]["end"], 128)
        self.assertIn("start=128", first["scanned"]["stopped"])
        code, rest = scan(start=128)
        self.assertEqual(code, 0)
        self.assertEqual((rest["scanned"]["start"], rest["scanned"]["end"]), (128, 400))
        got = [h["offset"] for h in first["signatures"]["PNG"]["hits"]] + [h["offset"] for h in rest["signatures"]["PNG"]["hits"]]
        self.assertEqual(got, want)

    def test_a_results_file_is_never_replaced_by_a_later_scan_of_the_same_question(self):
        data = b"".join(b"\0" * 30 + PNG for _ in range(20))
        other = b"".join(PNG + b"\0" * 30 for _ in range(20))            # the same size, the headers elsewhere
        one = self.scan(data, 64, "PNG", max_hits=2).json["signatures"]["PNG"]
        first = one["all_results"]
        self.assertEqual(one["earlier_answers"], 0)
        kept = self.read(first)
        self.assertEqual(self.scan(data, 64, "PNG", max_hits=2).json["signatures"]["PNG"]["all_results"], first)
        two = self.scan(other, 64, "PNG", max_hits=2).json["signatures"]["PNG"]
        second = two["all_results"]
        self.assertEqual(two["earlier_answers"], 1)
        self.assertNotEqual(first, second)
        self.assertTrue(second.endswith(".2.jsonl"), second)
        self.assertEqual(self.read(first), kept)
        self.assertNotEqual(self.read(second), kept)

    def test_a_sigterm_removes_the_half_written_results_file(self):
        import signal
        import subprocess
        import sys
        import time
        from support import tool_path
        data = b"".join(b"\0" * 30 + PNG for _ in range(50)) + b"\0" * (6 * 1024 * 1024)
        src = self.write("dump.bin", data)
        proc = subprocess.Popen([sys.executable, tool_path("sig_carve")], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=self.dir,
                                env={k: v for k, v in os.environ.items() if k not in ("JOB_ID", "OUT")})
        proc.stdin.write(json.dumps({"path": src, "sig": "PNG", "max_hits": 1, "window_bytes": 16}).encode())
        proc.stdin.close()
        folder = self.path("work/tool/tool-output")
        for _ in range(100):
            if os.path.isdir(folder) and [n for n in os.listdir(folder) if n.startswith(".")]:
                break
            time.sleep(0.05)
        else:
            proc.kill()
            self.fail("the scan never opened its results file")
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=20)
        proc.stdout.close()
        proc.stderr.close()
        self.assertEqual(proc.returncode, 143)
        self.assertEqual(os.listdir(folder), [], "a half-written results file was left behind")


def load_tool():
    """run.py as a module (its main() runs only when it is the program), for the pager it carries."""
    import importlib.util
    from support import tool_path
    spec = importlib.util.spec_from_file_location("sig_carve_tool", tool_path("sig_carve"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SigCarvePager(Case):
    """The pager is the tool library's second LosslessPage generation, byte for byte."""

    def in_dir(self, fn):
        before = os.getcwd()
        os.chdir(self.dir)
        try:
            return fn()
        finally:
            os.chdir(before)

    def test_a_row_that_holds_a_name_that_is_not_utf8_pages_to_a_readable_file(self):
        mod = load_tool()
        env = {k: os.environ.pop(k, None) for k in ("JOB_ID", "OUT")}
        try:
            def run():
                for pager_class in (mod.LosslessPage, mod.SafePage):
                    page = pager_class("sig_carve-surrogate-%s" % pager_class.__name__, ["k"], 2)
                    rows = [{"offset": i, "name": "caf\udcff-%d" % i} for i in range(5)]
                    for row in rows:
                        page.add(row)
                    info = page.finish()
                    self.assertEqual((info["matched"], info["returned"], info["truncated"]), (5, 2, True))
                    lines = self.read(info["all_results"]).splitlines()
                    self.assertEqual(len(lines), 5, pager_class.__name__)
                    self.assertEqual([json.loads(x)["name"] for x in lines], [r["name"] for r in rows], "the lone surrogate is an escape, lost nowhere")
            self.in_dir(run)
        finally:
            for k, v in env.items():
                if v is not None:
                    os.environ[k] = v

    def test_the_library_pager_says_as_json_when_the_whole_result_cannot_be_written_and_exits_1(self):
        import subprocess
        import sys
        from support import tool_path
        if os.geteuid() == 0:
            self.skipTest("root writes everywhere")
        os.makedirs(self.path("work"))
        os.chmod(self.path("work"), 0o555)
        code = ("import importlib.util, sys\n"
                "spec = importlib.util.spec_from_file_location('m', %r)\nm = importlib.util.module_from_spec(spec)\nspec.loader.exec_module(m)\n"
                "p = m.LosslessPage('sig_carve-ro', ['k'], 1)\nfor i in range(4): p.add({'offset': i})\np.finish()\n" % tool_path("sig_carve"))
        env = {k: v for k, v in os.environ.items() if k not in ("JOB_ID", "OUT")}
        try:
            proc = subprocess.run([sys.executable, "-c", code], cwd=self.dir, env=env, capture_output=True, text=True, timeout=60)
        finally:
            os.chmod(self.path("work"), 0o755)
        self.assertEqual(proc.returncode, 1)
        self.assertNotIn("Traceback", proc.stderr)
        said = json.loads(proc.stdout)
        self.assertEqual(said["status"], "failed")
        self.assertIn("cannot be written", said["error"])

    def test_the_pager_is_the_library_s_second_generation_byte_for_byte(self):
        from support import PACK_DIR, tool_path
        library = os.path.join(PACK_DIR, "..", "..", "tool-library", "regkv", "run.py")
        if not os.path.isfile(library):
            self.skipTest("this copy of the pack has no tool library beside it")

        def pager(path):
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
            a = text.index("class LosslessPage")
            return text[a:text.index("return result", text.index("def finish", a))]
        self.assertEqual(pager(tool_path("sig_carve")), pager(library))
        self.assertIn("_cannot_write", pager(tool_path("sig_carve")))


if __name__ == "__main__":
    unittest.main()
