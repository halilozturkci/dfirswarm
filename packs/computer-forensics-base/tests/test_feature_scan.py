"""feature_scan: no value inline, a histogram is not a feature file, a failed run is not a clean one.

bulk_extractor is a stand-in that writes what the real one writes: tab-separated
feature files (offset, feature, context), a histogram file whose lines are "n=<count>",
report.xml and, for the net scanner, packets.pcap.
"""
import importlib.util
import json
import os
import stat
import tracemalloc
import unittest

from support import Case, run_tool, stand_in, tool_path

SECRET_ADDRESS = "alice.hidden@example.test"
CARD = "4111111111111111"


def stub_body(exit_code=0, extra=""):
    return ('while [ $# -gt 0 ]; do case "$1" in -o) OUTDIR="$2"; shift;; esac; shift; done\n'
            'mkdir -p "$OUTDIR"\n'
            'printf "# BANNER\\n1024\\t%(a)s\\tctx %(a)s\\n2048\\t%(a)s\\tctx\\n4096\\tbob@example.test\\tctx\\n" > "$OUTDIR/email.txt"\n'
            'printf "n=2\\t%(a)s\\nn=1\\tbob@example.test\\n" > "$OUTDIR/email_histogram.txt"\n'
            'printf "8192\\t%(c)s\\tctx\\n" > "$OUTDIR/ccn.txt"\n'
            'printf "<report/>" > "$OUTDIR/report.xml"\n'
            'printf "pcapbytes" > "$OUTDIR/packets.pcap"\n'
            'printf "ALERT possible recovery key %(c)s\\n" > "$OUTDIR/alerts.txt"\n'
            'echo scanning\n'
            + extra +
            'exit %(code)d\n') % {"a": SECRET_ADDRESS, "c": CARD, "code": exit_code}


class FeatureScan(Case):
    def scan(self, body=None, env=None, **kw):
        bin_dir = self.path("bin")
        os.makedirs(bin_dir, exist_ok=True)
        stand_in(bin_dir, "bulk_extractor", body or stub_body())
        src = self.write("inputs/blob.raw", b"\0" * 64)
        args = {"path": src, "out_dir": "work/features"}
        args.update(kw)
        return run_tool("feature_scan", args, self.dir, [bin_dir], env=env)

    def test_no_value_comes_back_and_the_shape_does(self):
        r = self.scan()
        self.assertEqual(r.code, 0, r.stdout)
        for secret in (SECRET_ADDRESS, CARD, "bob@example.test"):
            self.assertNotIn(secret, r.stdout, "a feature value came back inline")
        by = {f["feature"]: f for f in r.json["features"]}
        self.assertEqual((by["email"]["lines"], by["email"]["distinct"], by["email"]["first_offset"]), (3, 2, "1024"))
        self.assertEqual(by["ccn"]["lines"], 1)
        self.assertEqual(r.json["secret_values"]["contains_secret_values"], False)
        self.assertIs(r.json["values_inline"], False)

    def test_a_histogram_file_is_not_summarised_as_features(self):
        r = self.scan()
        self.assertNotIn("email_histogram", [f["feature"] for f in r.json["features"]])
        self.assertEqual([(h["file"].split("/")[-1], h["lines"]) for h in r.json["histograms"]], [("email_histogram.txt", 2)])
        kinds = {os.path.basename(f["file"]): f["kind"] for f in r.json["files"]}
        self.assertEqual((kinds["email.txt"], kinds["email_histogram.txt"], kinds["report.xml"], kinds["packets.pcap"]), ("features", "histogram", "run report", "pcap"))

    def test_the_whole_output_inventory_names_a_pcap(self):
        names = [os.path.basename(f["file"]) for f in self.scan().json["files"]]
        self.assertIn("packets.pcap", names)

    def test_a_nonzero_exit_is_partial_or_failed_with_its_words_kept(self):
        r = self.scan(stub_body(exit_code=2, extra='echo "scanner crashed" >&2\n'))
        self.assertEqual(r.code, 1)
        self.assertEqual((r.json["status"], r.json["exit_code"]), ("partial", 2))
        self.assertIn("exited 2", r.json["problem"])
        self.assertIn("scanner crashed", self.read(r.json["stderr_file"]))
        self.assertIn("scanning", self.read(r.json["stdout_file"]))
        # Nothing written at all is failed, and says why.
        r = self.scan('echo boom >&2\nexit 3\n', out_dir="work/features-none")
        self.assertEqual(r.code, 1)
        self.assertIn("wrote no output directory", r.json["error"])
        self.assertEqual(r.json["exit_code"], 3)

    def test_values_are_refused_outside_a_job_and_sealed_inside_one(self):
        r = self.scan(write_values=True)
        self.assertEqual(r.code, 1)
        self.assertIn("refused outside a job", r.json["error"])
        self.assertFalse(os.path.exists(self.path("work/features")))
        out = self.path("job-out")
        os.makedirs(out)
        r = self.scan(write_values=True, top=1, env={"JOB_ID": "j000009", "OUT": out}, out_dir=self.path("job-out/features"))
        self.assertEqual(r.code, 0, r.stdout)
        self.assertNotIn(SECRET_ADDRESS, r.stdout)
        self.assertEqual(r.json["secret_values"]["values_file"], "store/jobs/j000009/out/feature-scan-values.jsonl")
        path = os.path.join(out, "feature-scan-values.jsonl")
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        rows = [json.loads(x) for x in self.read(path).splitlines()]
        email = [x for x in rows if x["feature_file"].endswith("email.txt")][0]
        self.assertEqual((email["value"], email["count"]), (SECRET_ADDRESS, 2))

    def test_distinct_values_are_counted_within_a_bound(self):
        spec = importlib.util.spec_from_file_location("fs", tool_path("feature_scan"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        path = self.path("many.txt")
        with open(path, "w") as fh:
            for i in range(60000):
                fh.write("%d\tvalue-%d\tctx\n" % (i, i))
        tracemalloc.start()
        stats, counts = mod.summarise(path, cap=1000)
        peak = tracemalloc.get_traced_memory()[1]
        tracemalloc.stop()
        self.assertEqual((stats["lines"], stats["distinct"], stats["distinct_capped"], stats["occurrences_not_tallied"]), (60000, 1000, True, 59000))
        self.assertLess(peak, 5 * 1024 * 1024)

    def test_scanner_names_are_checked_before_they_reach_the_command_line(self):
        for bad in (["--help"], ["email;rm"], [3]):
            self.assertEqual(self.scan(only=bad).code, 1, bad)

    def test_a_run_that_wrote_nothing_but_its_own_words_is_failed_not_partial(self):
        r = self.scan('while [ $# -gt 0 ]; do case "$1" in -o) mkdir -p "$2";; esac; shift; done\necho "cannot read the image" >&2\nexit 4\n')
        self.assertEqual(r.code, 1)
        self.assertEqual((r.json["status"], r.json["exit_code"], r.json["files_written_by_bulk_extractor"]), ("failed", 4, 0))
        self.assertIn("cannot read the image", self.read(r.json["stderr_file"]))

    def test_an_out_dir_that_is_a_file_or_cannot_be_made_is_an_answer_not_a_traceback(self):
        self.write("work/afile", b"x")
        r = self.scan(out_dir="work/afile")
        self.assertEqual(r.code, 1)
        self.assertIn("exists and is not a directory", r.json["error"])
        self.assertNotIn("Traceback", r.stderr)
        if os.geteuid() != 0:
            locked = self.path("work/locked")
            os.makedirs(locked)
            os.chmod(locked, 0o555)
            try:
                r = self.scan(out_dir="work/locked/features")
            finally:
                os.chmod(locked, 0o755)
            self.assertEqual(r.code, 1)
            self.assertIn("cannot be written", r.json["error"])
            self.assertNotIn("Traceback", r.stderr)

    def test_in_a_job_out_dir_must_be_under_out(self):
        out = self.path("job-out")
        os.makedirs(out)
        r = self.scan(env={"JOB_ID": "j000010", "OUT": out}, out_dir="work/features")
        self.assertEqual(r.code, 1)
        self.assertIn("under $OUT", r.json["error"])
        self.assertFalse(os.path.exists(self.path("work/features")))
        r = self.scan(env={"JOB_ID": "j000010", "OUT": out}, out_dir=out)
        self.assertEqual(r.code, 1)
        self.assertIn("under $OUT", r.json["error"])

    def test_a_time_budget_outside_its_bounds_is_refused(self):
        for bad in (5, 1001, True, "900"):
            r = self.scan(timeout_seconds=bad)
            self.assertEqual(r.code, 1, bad)
            self.assertIn("from 10 to 1000", r.json["error"])

    def test_what_bulk_extractor_wrote_is_private_and_the_answer_says_it_holds_values(self):
        r = self.scan()
        self.assertEqual(r.code, 0, r.stdout)
        out_dir = self.path("work/features")
        self.assertEqual(stat.S_IMODE(os.stat(out_dir).st_mode), 0o700)
        modes = {n: stat.S_IMODE(os.stat(os.path.join(out_dir, n)).st_mode) for n in os.listdir(out_dir)}
        self.assertEqual(set(modes.values()), {0o600}, modes)
        self.assertIs(r.json["out_dir_contains_secret_values"], True)
        self.assertEqual(r.json["kinds_holding_values"], ["alerts", "features", "histogram", "pcap"])
        self.assertIn("alerts", r.json["out_dir_note"])
        self.assertIs(r.json["secret_values"]["contains_secret_values"], False, "that field is about the values file only")

    def test_a_second_values_run_in_one_job_is_a_json_refusal_and_an_empty_values_file_says_written_zero(self):
        out = self.path("job-out")
        os.makedirs(out)
        env = {"JOB_ID": "j000014", "OUT": out}
        first = self.scan(write_values=True, env=env, out_dir=self.path("job-out/f1"))
        self.assertEqual(first.code, 0, first.stdout)
        again = self.scan(write_values=True, env=env, out_dir=self.path("job-out/f2"))
        self.assertEqual((again.code, again.stderr), (1, ""))
        self.assertIn("values file already exists", again.json["error"])
        os.unlink(os.path.join(out, "feature-scan-values.jsonl"))
        victim = self.write("victim.txt", "keep me")
        os.symlink(victim, os.path.join(out, "feature-scan-values.jsonl"))
        r = self.scan(write_values=True, env=env, out_dir=self.path("job-out/f3"))
        self.assertEqual((r.code, self.read(victim)), (1, "keep me"))
        os.unlink(os.path.join(out, "feature-scan-values.jsonl"))
        nothing = self.scan('while [ $# -gt 0 ]; do case "$1" in -o) mkdir -p "$2";; esac; shift; done\nprintf "<report/>" > "$2/report.xml" 2>/dev/null; exit 0\n',
                            write_values=True, env=env, out_dir=self.path("job-out/f4"))
        self.assertEqual(nothing.json["secret_values"]["written"], 0)
        self.assertEqual(nothing.json["secret_values"]["values_file"], "store/jobs/j000014/out/feature-scan-values.jsonl")
        path = os.path.join(out, "feature-scan-values.jsonl")
        self.assertEqual((os.path.getsize(path), stat.S_IMODE(os.stat(path).st_mode)), (0, 0o600))


if __name__ == "__main__":
    unittest.main()
