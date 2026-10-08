"""timeline_super: a failed stage is not a clean run, export does not collect again, and a bad line is not an event.

log2timeline and psort are stand-ins that record how they were called and write
the files the real ones write (a storage file; psort's JSON Lines, one event per
line, with the datetime in microseconds as Plaso's json_line writer has it).
"""
import importlib.util
import json
import os
import signal
import subprocess
import sys
import time
import unittest

from support import PACK_DIR, Case, run_tool, stand_in, tool_path

GOOD = [{"datetime": "2023-11-14T22:13:20.000000+00:00", "parser": "filestat", "data_type": "fs:stat", "message": "m1", "timestamp_desc": "Modification Time"},
        {"timestamp": 1700000100000000, "parser": "winreg", "data_type": "windows:registry:key_value", "message": "m2"}]


class TimelineSuper(Case):
    def plaso(self, collect_exit=0, export_exit=0, lines=None, collect_writes=True, export_writes=True):
        d = self.path("bin")
        os.makedirs(d, exist_ok=True)
        self.calls = self.path("calls.log")
        body = lines if lines is not None else [json.dumps(r) for r in GOOD]
        data = self.write("canned.jsonl", "\n".join(body) + "\n")
        l2t = ('echo "log2timeline $*" >> "%s"\n'
               'case "$1" in --version) echo "plaso - log2timeline version 20990101"; exit 0;; esac\n'
               'while [ $# -gt 0 ]; do case "$1" in --storage_file) %s; shift;; --logfile) echo log > "$2"; shift;; esac; shift; done\n'
               'exit %d\n') % (self.calls, 'echo storage > "$2"' if collect_writes else ':', collect_exit)
        ps = ('echo "psort $*" >> "%s"\n'
              'case "$1" in --version) echo "plaso - psort version 20990101"; exit 0;; esac\n'
              'while [ $# -gt 0 ]; do case "$1" in -w) %s; shift;; --logfile) echo log > "$2"; shift;; esac; shift; done\n'
              'exit %d\n') % (self.calls, 'cp "%s" "$2"' % data if export_writes else ':', export_exit)
        stand_in(d, "log2timeline.py", l2t)
        stand_in(d, "psort.py", ps)
        return d

    def calls_made(self):
        return self.read(self.calls).splitlines() if os.path.exists(self.calls) else []

    def go(self, bin_dir, **args):
        args.setdefault("out_dir", "work/tl")
        args.setdefault("source", self.write("inputs/disk.dd", b"\0" * 64))
        return run_tool("timeline_super", args, self.dir, [bin_dir])

    def test_a_clean_run_is_complete_and_names_both_exits_and_versions(self):
        r = self.go(self.plaso())
        self.assertEqual(r.code, 0, r.stdout)
        j = r.json
        self.assertEqual((j["status"], j["collect_exit"], j["export_exit"], j["events"], j["invalid_lines"]), ("complete", 0, 0, 2, 0))
        self.assertEqual(j["versions"]["log2timeline"], "plaso - log2timeline version 20990101")
        self.assertEqual(j["versions"]["psort"], "plaso - psort version 20990101")
        self.assertEqual(j["first_event"], "2023-11-14T22:13:20.000000+00:00")
        self.assertEqual(j["last_event"], "2023-11-14T22:15:00Z")
        self.assertIn("pinfo", j["coverage_note"])

    def test_log2timeline_failing_after_it_wrote_a_storage_file_is_partial_not_normal(self):
        r = self.go(self.plaso(collect_exit=1))
        self.assertEqual(r.code, 1)
        self.assertEqual(r.json["status"], "partial")
        self.assertEqual(r.json["collect_exit"], 1)
        self.assertEqual(r.json["export_exit"], 0)
        self.assertTrue(any("log2timeline exited 1" in p for p in r.json["problems"]), r.json["problems"])
        self.assertEqual(r.json["events"], 2)       # what psort made of the partial storage is still returned

    def test_psort_failing_after_it_wrote_output_is_partial_too(self):
        r = self.go(self.plaso(export_exit=3))
        self.assertEqual((r.code, r.json["status"], r.json["export_exit"]), (1, "partial", 3))

    def test_nothing_written_is_failed_with_an_error(self):
        r = self.go(self.plaso(collect_exit=1, collect_writes=False))
        self.assertEqual((r.code, r.json["status"]), (1, "failed"))
        self.assertIn("error", r.json)
        self.assertEqual([c for c in self.calls_made() if c.startswith("psort") and "--version" not in c], [])

    def test_export_mode_runs_psort_alone_over_an_existing_storage_file(self):
        bin_dir = self.plaso()
        store = self.write("work/old/timeline.plaso", b"storage")
        r = run_tool("timeline_super", {"mode": "export", "storage_file": store, "out_dir": "work/narrow",
                                        "psort_filter": "date > '2026-02-01'"}, self.dir, [bin_dir])
        self.assertEqual(r.code, 0, r.stdout)
        self.assertEqual(r.json["status"], "complete")
        self.assertIsNone(r.json["collect_exit"])
        self.assertEqual([c for c in self.calls_made() if c.startswith("log2timeline")], [])
        export = [c for c in self.calls_made() if c.startswith("psort") and "--version" not in c]
        self.assertEqual(len(export), 1)
        self.assertIn("--filter date > '2026-02-01'", export[0])
        self.assertTrue(export[0].endswith(store))
        self.assertNotIn("log2timeline", r.json["versions"])

    def test_export_mode_needs_a_storage_file_that_exists(self):
        bin_dir = self.plaso()
        for args in ({"mode": "export", "out_dir": "work/x"}, {"mode": "export", "out_dir": "work/x", "storage_file": self.path("nope.plaso")}):
            self.assertEqual(run_tool("timeline_super", args, self.dir, [bin_dir]).code, 1)

    def test_malformed_lines_are_not_events(self):
        lines = [json.dumps(GOOD[0]), "this is not json", json.dumps(GOOD[1]), '{"truncated": ']
        r = self.go(self.plaso(lines=lines))
        self.assertEqual((r.json["events"], r.json["invalid_lines"], r.json["status"]), (2, 2, "partial"))
        listing = self.read(r.json["invalid_lines_file"]).splitlines()
        self.assertEqual(len(listing), 3)             # a header and the two lines
        self.assertTrue(listing[1].startswith("2\t"))
        self.assertTrue(listing[2].startswith("4\t"))
        self.assertTrue(r.json["invalid_lines_listing_complete"])

    def test_an_existing_output_directory_is_refused_unless_resume(self):
        bin_dir = self.plaso()
        self.write("work/tl/timeline.jsonl", b'{"datetime": "1999-01-01T00:00:00Z"}\n')
        old = time.time() - 86400
        os.utime(self.path("work/tl/timeline.jsonl"), (old, old))
        r = self.go(bin_dir)
        self.assertEqual(r.code, 1)
        self.assertIn("already holds files", r.json["error"])
        self.assertEqual(self.calls_made(), [])
        # With resume the stale file is not this run's: a psort that writes nothing leaves the run failed.
        failing = self.plaso(export_writes=False)
        r = self.go(failing, resume=True)
        self.assertEqual(r.json["status"], "failed")
        self.assertEqual(r.json["preexisting"], ["timeline.jsonl"])

    def test_a_link_where_the_tool_writes_is_refused(self):
        bin_dir = self.plaso()
        os.makedirs(self.path("work/tl"))
        target = self.write("elsewhere.txt", b"x")
        os.symlink(target, self.path("work/tl/timeline.jsonl"))
        r = self.go(bin_dir, resume=True)
        self.assertEqual(r.code, 1)
        self.assertIn("link", r.json["error"])
        self.assertEqual(self.read(target), "x")

    def test_a_long_message_is_previewed_with_its_length(self):
        big = dict(GOOD[0], message="x" * 5000)
        r = self.go(self.plaso(lines=[json.dumps(big)]))
        row = r.json["sample"][0]
        self.assertEqual(len(row["message"]), 2000)
        self.assertEqual(row["message_length"], 5000)

    def test_one_deadline_covers_every_stage(self):
        spec = importlib.util.spec_from_file_location("ts", tool_path("timeline_super"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        os.makedirs(self.path("o"))
        started = time.monotonic()
        stage = mod.Stage("sleeper", ["sleep", "30"], self.path("o")).run(time.monotonic() + 0.5)
        self.assertTrue(stage.timed_out)
        self.assertLess(time.monotonic() - started, 10)
        spent = mod.Stage("late", ["sleep", "30"], self.path("o")).run(time.monotonic() - 1)
        self.assertTrue(spent.timed_out and spent.exit is None)

    def test_a_link_at_any_output_name_is_refused(self):
        for name in ("psort.stdout", "log2timeline.stderr", "timeline.invalid_lines.txt", "timeline.plaso", "psort.log.gz"):
            self.write("elsewhere.txt", b"x")
            os.makedirs(self.path("work/tl"), exist_ok=True)
            link = self.path("work/tl/" + name)
            if os.path.lexists(link):
                os.unlink(link)
            os.symlink(self.path("elsewhere.txt"), link)
            r = self.go(self.plaso(), resume=True)
            self.assertEqual(r.code, 1, name)
            self.assertIn("link", r.json["error"], name)
            self.assertEqual(self.read(self.path("elsewhere.txt")), "x", name)
            os.unlink(link)

    def test_logs_and_captured_output_of_an_earlier_run_are_not_this_runs(self):
        bin_dir = self.plaso()
        for name in ("log2timeline.log.gz", "log2timeline.stdout", "log2timeline.stderr"):
            self.write("work/tl/" + name, b"from last week")
            old = time.time() - 7 * 86400
            os.utime(self.path("work/tl/" + name), (old, old))
        storage = self.write("old.plaso", b"storage")
        r = self.go(bin_dir, resume=True, mode="export", storage_file=storage)
        self.assertEqual(r.json["status"], "complete", r.stdout)
        self.assertEqual([os.path.basename(x) for x in r.json["logs"]], ["psort.log.gz"])
        self.assertEqual(sorted(os.path.basename(x) for x in r.json["captured_output"]), ["psort.stderr", "psort.stdout"])
        self.assertIn("log2timeline.log.gz", r.json["preexisting"])

    def test_first_and_last_event_are_the_earliest_and_the_latest_whatever_the_file_order(self):
        rows = [{"datetime": "2024-05-05T00:00:00.000000+00:00", "parser": "a", "message": "late"},
                {"timestamp": 1500000000000000, "parser": "b", "message": "early"},
                {"datetime": "2023-01-01T00:00:00+00:00", "parser": "c", "message": "middle"},
                {"parser": "d", "message": "no time at all"}]
        r = self.go(self.plaso(lines=[json.dumps(x) for x in rows]))
        self.assertEqual((r.json["first_event"], r.json["last_event"]), ("2017-07-14T02:40:00Z", "2024-05-05T00:00:00.000000+00:00"))
        self.assertEqual((r.json["events"], r.json["events_without_a_time"]), (4, 1))

    def test_a_line_that_is_not_utf8_is_invalid_not_quietly_repaired(self):
        good = json.dumps(GOOD[0]).encode()
        bad = b'{"datetime": "2023-11-14T22:13:20+00:00", "message": "caf\xe9"}'
        data = self.write("canned2.jsonl", good + b"\n" + bad + b"\n")
        bin_dir = self.plaso()
        stand_in(bin_dir, "psort.py", 'case "$1" in --version) echo v; exit 0;; esac\nwhile [ $# -gt 0 ]; do case "$1" in -w) cp "%s" "$2"; shift;; --logfile) echo log > "$2"; shift;; esac; shift; done\n' % data)
        r = self.go(bin_dir)
        self.assertEqual((r.json["events"], r.json["invalid_lines"], r.json["status"]), (1, 1, "partial"))
        self.assertIn("utf-8", self.read(r.json["invalid_lines_file"]).lower())

    def test_values_that_would_be_options_or_are_not_strings_are_refused_and_bounds_hold(self):
        bin_dir = self.plaso()
        for key, bad in (("parsers", ["winreg"]), ("parsers", "a\0b"), ("parsers", "-x"), ("psort_filter", "-w"), ("timezone", "Europe/Istanbul; rm"), ("timezone", 7),
                         ("timeout_seconds", 3301), ("sample", 1001), ("sample", -1), ("mode", ["full"])):
            r = self.go(bin_dir, **{key: bad})
            self.assertEqual(r.code, 1, (key, bad))
            self.assertNotIn("Traceback", r.stderr)
            self.assertIn("error", r.json)
        self.assertEqual(self.calls_made(), [])

    def test_the_harness_ends_a_tool_by_killing_its_process_group_and_that_ends_the_engine_and_what_it_started(self):
        # The harness starts a tool in a process group of its own (node's `detached: true`, a setsid) and ends it on its deadline or an abort
        # with process.kill(-pid, SIGKILL). A program the tool put in a session of its own is not in that group and goes on writing; one in
        # the tool's group dies with it. SIGTERM, SIGINT and SIGHUP end the programs too and leave a last word.
        for how in ("group", "SIGTERM", "SIGINT", "SIGHUP"):
            work = self.path("run-" + how)
            os.makedirs(work)
            bin_dir = os.path.join(work, "bin")
            os.makedirs(bin_dir)
            engine_pid, child_pid = os.path.join(work, "engine.pid"), os.path.join(work, "child.pid")
            stand_in(bin_dir, "log2timeline.py", 'case "$1" in --version) echo v; exit 0;; esac\necho $$ > "%s"\nsleep 300 &\necho $! > "%s"\nwait\n' % (engine_pid, child_pid))
            stand_in(bin_dir, "psort.py", 'case "$1" in --version) echo v; exit 0;; esac\nexit 0\n')
            src = self.write("inputs/disk.dd", b"\0" * 64)
            env = dict(os.environ, PATH=bin_dir + os.pathsep + os.environ["PATH"])
            for k in ("JOB_ID", "OUT"):
                env.pop(k, None)
            proc = subprocess.Popen([sys.executable, tool_path("timeline_super")], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    cwd=work, env=env, start_new_session=True)
            proc.stdin.write(json.dumps({"out_dir": "work/tl", "source": src}).encode())
            proc.stdin.close()
            engine = child = 0
            try:
                for _ in range(200):
                    if os.path.exists(child_pid) and self.read(child_pid).strip():
                        break
                    time.sleep(0.05)
                engine, child = int(self.read(engine_pid).strip()), int(self.read(child_pid).strip())
                if how == "group":
                    os.killpg(proc.pid, signal.SIGKILL)
                else:
                    proc.send_signal(getattr(signal, how))
                out = proc.stdout.read()
                proc.wait(timeout=30)
                for pid, what in ((engine, "the engine"), (child, "what the engine started")):
                    for _ in range(100):
                        try:
                            os.kill(pid, 0)
                        except ProcessLookupError:
                            break
                        time.sleep(0.05)
                    else:
                        self.fail("%s: %s survived" % (how, what))
                if how != "group":
                    word = json.loads(out.decode().strip().splitlines()[-1])
                    self.assertEqual((word["stopped_by_signal"], word["status"]), (how, "failed"))
                    self.assertIn("log2timeline and psort were ended with it", word["error"])
                    self.assertEqual(proc.returncode, 128 + getattr(signal, how))
            finally:
                for pid in (engine, child):
                    if pid:
                        try:
                            os.kill(pid, signal.SIGKILL)
                        except OSError:
                            pass
                if proc.poll() is None:
                    proc.kill()
                    proc.wait()
                proc.stdout.close()
                proc.stderr.close()

    def test_no_tool_or_recipe_of_the_pack_starts_a_program_outside_its_own_process_group(self):
        import re
        import glob
        bad = re.compile(r"start_new_session|setsid|preexec_fn=os\.setsid|process_group")
        files = glob.glob(os.path.join(PACK_DIR, "tools", "*", "run.py")) + glob.glob(os.path.join(PACK_DIR, "recipes", "*", "run.*"))
        self.assertGreaterEqual(len(files), 17)
        for path in files:
            text = re.sub(r"(?m)^\s*#.*$", "", self.read(path))
            self.assertIsNone(bad.search(text), "%s starts a program outside the tool's process group" % path)

    def test_in_a_job_out_dir_is_bounded_by_out_and_defaults_to_it(self):
        bin_dir = self.plaso()
        out = self.path("job-out")
        os.makedirs(out)
        env = {"JOB_ID": "j000013", "OUT": out}
        src = self.write("inputs/disk.dd", b"\0" * 64)
        r = run_tool("timeline_super", {"source": src, "out_dir": "work/timeline"}, self.dir, [bin_dir], env=env)
        self.assertEqual(r.code, 1, r.stdout)
        self.assertIn("under $OUT", r.json["error"])
        self.assertFalse(os.path.exists(self.path("work")))
        r = run_tool("timeline_super", {"source": src}, self.dir, [bin_dir], env=env)
        self.assertEqual((r.code, r.json["status"]), (0, "complete"), r.stdout)
        self.assertEqual(r.json["out_dir"], os.path.join(os.path.realpath(out), "timeline"))
        self.assertTrue(os.path.isfile(os.path.join(out, "timeline", "timeline.jsonl")))

    def test_a_directory_that_cannot_be_written_is_an_answer_not_a_traceback(self):
        if os.geteuid() == 0:
            self.skipTest("root writes everywhere")
        bin_dir = self.plaso()
        locked = self.path("work/ro")
        os.makedirs(self.path("work/ro/exists"))
        os.chmod(self.path("work/ro/exists"), 0o555)               # exists, empty, cannot be written
        os.chmod(locked, 0o555)                                     # cannot be made into
        try:
            r = self.go(bin_dir, out_dir="work/ro/tl")                 # cannot be made
            self.assertEqual(r.code, 1)
            self.assertNotIn("Traceback", r.stderr)
            self.assertIn("cannot be made", r.json["error"])
            r = self.go(bin_dir, out_dir="work/ro/exists")
            self.assertEqual(r.code, 1)
            self.assertNotIn("Traceback", r.stderr)
            self.assertIn("cannot be written", r.json["error"])
        finally:
            os.chmod(locked, 0o755)
            os.chmod(self.path("work/ro/exists"), 0o755)

    def test_resume_never_overwrites_what_an_earlier_run_left(self):
        bin_dir = self.plaso()
        kept = {"log2timeline.stdout": b"first run, collect words", "psort.stdout": b"first run, export words", "timeline.jsonl": b'{"datetime": "1999-01-01T00:00:00Z"}\n',
                "timeline.invalid_lines.txt": b"first run's list", "timeline.plaso": b"first storage", "psort.log.gz": b"first log"}
        for name, data in kept.items():
            self.write("work/tl/" + name, data)
            old = time.time() - 86400
            os.utime(self.path("work/tl/" + name), (old, old))
        r = self.go(bin_dir, resume=True, lines=None)
        for name, data in kept.items():
            self.assertEqual(self.read(self.path("work/tl/" + name), "rb"), data, name + " was overwritten")
        self.assertEqual(r.json["status"], "complete", r.stdout)
        self.assertTrue(r.json["output"].endswith("timeline.2.jsonl"))
        self.assertTrue(r.json["storage_file"].endswith("timeline.2.plaso"))
        self.assertEqual(self.read(r.json["output"]).count("\n"), 2)

    def test_the_answer_says_the_timeline_and_its_sample_are_evidence_text(self):
        r = self.go(self.plaso())
        self.assertIs(r.json["contains_evidence_text"], True)
        self.assertIn("secret_output", r.json["sensitive_output_note"])
        none = self.go(self.plaso(), out_dir="work/tl2", sample=0)
        self.assertEqual(none.json["sample"], [])


if __name__ == "__main__":
    unittest.main()
