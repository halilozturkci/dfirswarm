"""disk-timeline: the lines of Plaso's logs are scanned for errors up to 32 MiB, and what lies past that is said, per log, in the coverage.

log2timeline, psort and pinfo are stand-ins that write what the real ones write (a storage file, a CSV with a header and a row, a log);
the image is a file whose first sector is an NTFS boot sector's name field, which is all the recipe's detect reads.
"""
import json
import os
import subprocess
import sys
import unittest

from support import CLEAN, Case, recipe_path, stand_in

SCAN = 32 * 1024 * 1024


class DiskTimeline(Case):
    def stubs(self, log_bytes):
        d = self.path("bin")
        os.makedirs(d, exist_ok=True)
        stand_in(d, "log2timeline", 'while [ $# -gt 0 ]; do case "$1" in --storage-file) echo storage > "$2"; shift;; --logfile) LOG="$2"; shift;; esac; shift; done\n'
                 'head -c %d /dev/zero | tr "\\000" "a" > "$LOG"\nexit 0\n' % log_bytes)
        stand_in(d, "psort", 'while [ $# -gt 0 ]; do case "$1" in -w) printf "datetime,message\\n2023-11-14,one event\\n" > "$2"; shift;; --logfile) echo log > "$2"; shift;; esac; shift; done\nexit 0\n')
        stand_in(d, "pinfo", "echo 'storage file: ok'\n")
        head = bytearray(4096)
        head[3:11] = b"NTFS    "
        image = self.write("inputs/disk.raw", bytes(head))
        return d, image

    def run_recipe(self, bin_dir, image, out):
        env = dict(os.environ, PATH=bin_dir + os.pathsep + os.environ["PATH"])
        target = json.dumps({"paths": [image], "name": "disk.raw"})
        return subprocess.run([sys.executable, recipe_path("disk-timeline", "run.py"), "run", "--target", target, "--out", out],
                              cwd=self.dir, env=env, capture_output=True, text=True, timeout=120)

    def test_a_log_past_32_mib_is_named_with_the_bytes_not_read_and_the_run_is_partial(self):
        bin_dir, image = self.stubs(SCAN + 8 * 1024 * 1024)
        proc = self.run_recipe(bin_dir, image, self.path("out"))
        cov = json.loads(self.read("out/coverage.json"))
        self.assertEqual(cov["status"], "partial", proc.stdout + proc.stderr)
        self.assertEqual(cov["plaso_signals_not_read"], [{"file": "log2timeline.log.gz", "bytes_not_read": 8 * 1024 * 1024}])
        self.assertTrue(any("log2timeline.log.gz: only its first %d bytes were read" % SCAN in e and "8388608 bytes were not read" in e for e in cov["errors"]), cov["errors"])

    def test_a_log_within_32_mib_is_read_whole_and_the_run_stays_complete(self):
        bin_dir, image = self.stubs(SCAN)
        self.run_recipe(bin_dir, image, self.path("out"))
        cov = json.loads(self.read("out/coverage.json"))
        self.assertEqual(cov["status"], CLEAN, cov["errors"])
        self.assertNotIn("plaso_signals_not_read", cov)


if __name__ == "__main__":
    unittest.main()
