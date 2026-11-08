"""memory-windows: a stop signal ends the step running, by its pid, and the recipe answers once.

The recipe runs as the harness runs it (`run.sh run --target T --out DIR`); `vol` is a stand-in that records its pid and becomes a sleep,
so the step to end is known and its survival can be looked at.
"""
import json
import os
import signal
import subprocess
import time
import unittest

from support import Case, recipe_path, stand_in


class MemoryWindowsStop(Case):
    def stubs(self, blocks):
        """A `vol` that answers windows.info at once and blocks in the plugin named `blocks` ("info" blocks in windows.info)."""
        d = self.path("bin")
        os.makedirs(d, exist_ok=True)
        pidfile = self.path("step.pid")
        block = '    echo $$ > "%s"\n    exec sleep 60\n' % pidfile
        info = block if blocks == "info" else "    echo 'NTBuildLab 19041.vb_release'\n"
        body = ('for last; do :; done\n'
                'case "$last" in\n'
                '  windows.info)\n' + info + '    ;;\n'
                '  windows.%s)\n' % ("psscan" if blocks == "psscan" else "none") + block + '    ;;\n'
                '  *) echo ok ;;\nesac\n')
        stand_in(d, "vol", body)
        self.write("mem.raw", b"\0" * 4096)
        return d, pidfile

    def start(self, bin_dir, args, out=None):
        e = dict(os.environ, PATH=bin_dir + os.pathsep + os.environ["PATH"])
        target = json.dumps({"paths": [self.path("mem.raw")], "name": "mem.raw"})
        argv = ["bash", recipe_path("memory-windows", "run.sh"), args, "--target", target] + (["--out", out] if out else [])
        return subprocess.Popen(argv, cwd=self.dir, env=e, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def wait_for(self, path, secs=15):
        end = time.monotonic() + secs
        while time.monotonic() < end:
            if os.path.exists(path):
                with open(path) as fh:
                    text = fh.read().strip()
                if text:
                    return int(text)
            time.sleep(0.05)
        self.fail("%s never appeared" % path)

    def gone(self, pid):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        try:
            with open("/proc/%d/status" % pid) as fh:
                return "Z" in fh.read().split("State:")[1].split("\n")[0]
        except (OSError, IndexError):
            return False

    def test_each_stop_signal_ends_the_step_running_and_answers_once_with_exit_128_plus_the_signal(self):
        for blocks in ("info", "psscan"):
            for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
                bin_dir, pidfile = self.stubs(blocks)
                out = self.path("out-%s-%d" % (blocks, sig))
                proc = self.start(bin_dir, "run", out)
                pid = self.wait_for(pidfile)
                proc.send_signal(sig)
                try:
                    stdout, stderr = proc.communicate(timeout=30)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.communicate()
                    self.fail("%s during %s: the recipe did not stop" % (sig.name, blocks))
                self.assertEqual(proc.returncode, 128 + sig, (blocks, sig.name, stdout, stderr))
                said = json.loads(stdout)                     # one document
                self.assertEqual((said["interrupted"], said["signal"], said["status"]), (True, sig.name, "partial"))
                cov = json.loads(self.read(out + "/coverage.json"))
                self.assertEqual((cov["status"], cov["interrupted"], cov["signal"]), ("partial", True, sig.name))
                self.assertTrue(any("stopped by " + sig.name in e for e in cov["errors"]), cov["errors"])
                if blocks == "psscan":
                    self.assertTrue(any(s["step"] == "pslist.txt" and s["exit"] == 0 for s in cov["steps"]), "the steps that finished are kept: %s" % cov["steps"])
                self.assertTrue(self.gone(pid), "the step (pid %d) was left running" % pid)
                os.unlink(pidfile)

    def test_a_second_signal_while_the_first_is_answered_changes_nothing(self):
        bin_dir, pidfile = self.stubs("info")
        proc = self.start(bin_dir, "run", self.path("out"))
        self.wait_for(pidfile)
        proc.send_signal(signal.SIGTERM)
        proc.send_signal(signal.SIGHUP)
        stdout, _ = proc.communicate(timeout=30)
        self.assertEqual(len(stdout.strip().splitlines()), 1, stdout)
        json.loads(stdout)

    def test_a_signal_during_detect_is_one_document_too(self):
        bin_dir, pidfile = self.stubs("info")
        proc = self.start(bin_dir, "detect")
        pid = self.wait_for(pidfile)
        proc.send_signal(signal.SIGTERM)
        stdout, _ = proc.communicate(timeout=30)
        said = json.loads(stdout)
        self.assertEqual((proc.returncode, said["applies"], said["interrupted"]), (143, False, True))
        self.assertTrue(self.gone(pid))

    def test_a_run_nobody_stops_is_as_before(self):
        bin_dir, _ = self.stubs("none")
        proc = self.start(bin_dir, "run", self.path("out"))
        stdout, stderr = proc.communicate(timeout=60)
        self.assertEqual(proc.returncode, 0, stdout + stderr)
        cov = json.loads(self.read("out/coverage.json"))
        self.assertEqual((cov["status"], len(cov["steps"])), ("complete", 12))   # (a shell recipe: it carries no process block, so a clean run is complete on every host)
        self.assertNotIn("interrupted", cov)


if __name__ == "__main__":
    unittest.main()
