"""archive-members: what a hostile archive cannot make the listing do.

The recipe is run as the harness runs it (`run.py run --target T --out DIR`). A tar whose GNU long-name header declares a gigabyte is a
sparse file here, so the declared size is real to tarfile and costs the test no disk. The ZIP with a NUL inside a member name is written
by the standard library and then has one byte of a stored name changed, in both its local and its central header, as an archiver that
stored the name would have.
"""
import json
import os
import resource
import signal
import stat
import struct
import subprocess
import sys
import time
import unittest
import zipfile

from support import Case, recipe_path, stand_in


def tar_header(name, size, typeflag):
    block = bytearray(512)
    block[0:len(name)] = name
    block[100:108] = b"0000644\0"
    block[108:116] = b"0000000\0"
    block[116:124] = b"0000000\0"
    block[124:136] = (b"%011o\0" % size)
    block[136:148] = b"00000000000\0"
    block[148:156] = b" " * 8
    block[156:157] = typeflag
    block[257:265] = b"ustar  \0"
    block[148:156] = b"%06o\0 " % sum(block)
    return bytes(block)


class ArchiveMembers(Case):
    def run_recipe(self, archive, out="out", env=None, timeout=120, popen=False):
        e = dict(os.environ)
        e.update(env or {})
        argv = [sys.executable, recipe_path("archive-members", "run.py"), "run", "--target", json.dumps({"paths": [archive], "name": archive}), "--out", self.path(out)]
        if popen:
            return subprocess.Popen(argv, cwd=self.dir, env=e, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return subprocess.run(argv, cwd=self.dir, env=e, capture_output=True, text=True, timeout=timeout)

    def coverage(self, out="out"):
        return json.loads(self.read(self.path(out + "/coverage.json")))

    def members(self, out="out"):
        rows = [line.split("\t") for line in self.read(self.path(out + "/members.tsv")).splitlines()]
        return [dict(zip(rows[0], r)) for r in rows[1:]]

    def test_a_gigabyte_long_name_header_is_refused_by_its_declared_size_and_costs_no_gigabyte(self):
        path = self.path("huge.tar")
        with open(path, "wb") as fh:
            fh.write(tar_header(b"././@LongLink", 1 << 30, b"L"))
            fh.truncate(512 + (1 << 30) + 1024)
        wrapper = ("import resource, subprocess, sys, json\n"
                   "p = subprocess.run(sys.argv[1:], capture_output=True, text=True)\n"
                   "print(json.dumps({'peak': resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss, 'out': p.stdout}))\n")
        argv = [sys.executable, "-c", wrapper, sys.executable, recipe_path("archive-members", "run.py")]
        detect = subprocess.run(argv + ["detect", "--target", json.dumps({"paths": [path]})], capture_output=True, text=True, cwd=self.dir)
        got = json.loads(detect.stdout)
        self.assertIs(json.loads(got["out"])["applies"], True, got["out"])
        self.assertIn("declares 1073741824 bytes", json.loads(got["out"])["why"])
        peak = got["peak"] * (1 if sys.platform == "darwin" else 1024)
        self.assertLess(peak, 150 * 1024 * 1024, "detect peaked at %d bytes for a header that declares a gigabyte" % peak)
        run = subprocess.run(argv + ["run", "--target", json.dumps({"paths": [path]}), "--out", self.path("out")], capture_output=True, text=True, cwd=self.dir)
        got = json.loads(run.stdout)
        peak = got["peak"] * (1 if sys.platform == "darwin" else 1024)
        self.assertLess(peak, 150 * 1024 * 1024, "the listing peaked at %d bytes" % peak)
        cov = self.coverage()
        self.assertTrue([e for e in cov["errors"] if "declares 1073741824 bytes" in e and "not read" in e], cov)
        self.assertNotEqual(cov["status"], "complete")

    def test_a_pax_header_of_the_same_size_is_refused_the_same_way(self):
        path = self.path("pax.tar")
        with open(path, "wb") as fh:
            fh.write(tar_header(b"pax", 1 << 30, b"x"))
            fh.truncate(512 + (1 << 30) + 1024)
        self.run_recipe(path)
        self.assertTrue([e for e in self.coverage()["errors"] if "pax header" in e and "not read" in e])

    def test_coverage_is_written_before_the_first_member_and_a_stalled_7z_is_stopped_at_the_deadline(self):
        d = self.path("bin")
        os.makedirs(d)
        stand_in(d, "7z", 'printf "Path = a.txt\\nSize = 1\\n\\n"\nexec sleep 60\n')
        archive = self.write("a.7z", b"7z\xbc\xaf\x27\x1c" + b"\0" * 64)
        env = {"PATH": d + os.pathsep + os.environ["PATH"], "RECIPE_SECONDS": "3"}
        began = time.monotonic()
        proc = self.run_recipe(archive, env=env, popen=True)
        for _ in range(100):                                   # the first coverage is there while 7z is still running
            if os.path.exists(self.path("out/coverage.json")):
                break
            time.sleep(0.05)
        first = self.coverage()
        self.assertEqual(first["status"], "partial")
        self.assertIn("started", first["why"])
        out, err = proc.communicate(timeout=60)
        self.assertLess(time.monotonic() - began, 30, "the stalled 7z was waited on")
        cov = self.coverage()
        self.assertTrue([x for x in cov["limits_hit"] if x.startswith("seconds")], cov)
        self.assertEqual([m["path"] for m in self.members()], ["a.txt"], "what 7z listed before it stalled is kept")

    def test_a_name_with_a_nul_is_judged_whole_and_shown_whole(self):
        path = self.path("nul.zip")
        with zipfile.ZipFile(path, "w", zipfile.ZIP_STORED) as z:
            z.writestr("safe.txt/../../evil.exe", b"x")
            z.writestr("plain/ok.txt", b"y")
        data = bytearray(self.read(path, "rb"))
        name = b"safe.txt/../../evil.exe"
        at, count = 0, 0
        while True:
            at = data.find(name, at)
            if at < 0:
                break
            data[at + 8] = 0                                    # "safe.txt" NUL "../../evil.exe": in the local and the central header
            at += len(name)
            count += 1
        self.assertEqual(count, 2)
        self.write("nul.zip", bytes(data))
        self.run_recipe(path)
        rows = {m["n"]: m for m in self.members()}
        self.assertEqual(rows["0"]["path"], "safe.txt\\x00../../evil.exe", "the name is shown whole, not cut at the NUL")
        self.assertEqual(rows["0"]["flags"].split(","), ["nul-in-name", "escapes-root"])
        self.assertEqual(rows["1"]["flags"], "")

    def test_a_7z_member_that_climbs_is_flagged_like_a_tar_and_a_zip_member(self):
        d = self.path("bin")
        os.makedirs(d)
        stand_in(d, "7z", 'printf "Path = ../up/x.txt\\nSize = 1\\n\\nPath = C:\\\\win\\\\x.txt\\nSize = 1\\n\\nPath = ok/y.txt\\nSize = 1\\n\\n"\n')
        archive = self.write("a.7z", b"7z\xbc\xaf\x27\x1c" + b"\0" * 64)
        self.run_recipe(archive, env={"PATH": d + os.pathsep + os.environ["PATH"]})
        self.assertEqual([m["flags"] for m in self.members()], ["escapes-root", "escapes-root", ""])


if __name__ == "__main__":
    unittest.main()
