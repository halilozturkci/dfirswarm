"""icat_extract: streamed with bounded memory, a sector size that reaches icat, exact attribute attribution, and a partial that is not a file.

icat is a stand-in that records its arguments and writes a stream: from a file, or
generated (dd from /dev/zero) when the stream is too big to keep.
"""
import hashlib
import json
import os
import subprocess
import sys
import unittest

from support import Case, run_tool, stand_in, tool_path

MIB = 1024 * 1024


class IcatExtract(Case):
    def icat(self, body):
        d = self.path("bin")
        os.makedirs(d, exist_ok=True)
        self.argv_file = self.path("icat-args.txt")
        stand_in(d, "icat", 'printf "%%s\\n" "$@" > "%s"\n%s' % (self.argv_file, body))
        self.write("inputs/disk.E01", b"x")
        return d

    def extract(self, bin_dir, **kw):
        args = {"inode": "168-128-4", "output": "work/out.bin", "image": "inputs/disk.E01", "offset": 2048}
        args.update(kw)
        return run_tool("icat_extract", args, self.dir, [bin_dir])

    def test_the_sector_size_is_passed_to_icat_as_b_and_not_otherwise(self):
        bin_dir = self.icat('printf data\n')
        r = self.extract(bin_dir, sector_size=4096)
        self.assertEqual(r.code, 0, r.stdout)
        self.assertEqual(self.read(self.argv_file).split(), ["-b", "4096", "-o", "2048", "inputs/disk.E01", "168-128-4"])
        self.assertEqual((r.json["sector_size"], r.json["inode"], r.json["status"], r.json["icat_exit"]), (4096, "168-128-4", "complete", 0))
        self.extract(bin_dir, output="work/two.bin")
        self.assertEqual(self.read(self.argv_file).split(), ["-o", "2048", "inputs/disk.E01", "168-128-4"])
        for bad in (1000, 0, 100, True):
            self.assertEqual(self.extract(bin_dir, output="work/b%s.bin" % bad, sector_size=bad).code, 1, bad)

    def test_a_large_extract_is_streamed_and_hashed_without_holding_it(self):
        total = 256
        bin_dir = self.icat('dd if=/dev/zero bs=1048576 count=%d 2>/dev/null\n' % total)
        # The tool and its icat run under a wrapper that reports the peak memory of its own children, so what
        # earlier tests ran in this process cannot count towards it (ru_maxrss is bytes on macOS, kilobytes on Linux).
        wrapper = ("import json, os, resource, subprocess, sys\n"
                   "p = subprocess.run([sys.executable, sys.argv[1]], input=sys.argv[2], capture_output=True, text=True)\n"
                   "print(json.dumps({'out': p.stdout, 'code': p.returncode, 'peak': resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss}))\n")
        args = json.dumps({"inode": "168-128-4", "output": "work/out.bin", "image": "inputs/disk.E01", "offset": 2048})
        env = dict(os.environ, PATH=bin_dir + os.pathsep + os.environ["PATH"])
        for k in ("JOB_ID", "OUT", "AGENT_ID"):
            env.pop(k, None)
        proc = subprocess.run([sys.executable, "-c", wrapper, tool_path("icat_extract"), args], capture_output=True, text=True, cwd=self.dir, env=env)
        got = json.loads(proc.stdout)
        result = json.loads(got["out"])
        self.assertEqual(got["code"], 0, got["out"])
        h = hashlib.sha256()
        zero = bytes(MIB)
        for _ in range(total):
            h.update(zero)
        self.assertEqual((result["size"], result["sha256"]), (total * MIB, h.hexdigest()))
        self.assertEqual(os.path.getsize(self.path("work/out.bin")), total * MIB)
        peak = got["peak"] * (1 if sys.platform == "darwin" else 1024)
        self.assertLess(peak, 120 * MIB, "the tool's and icat's peak was %d bytes for a %d MiB stream" % (peak, total))

    def test_the_output_budget_keeps_a_partial_and_says_so(self):
        bin_dir = self.icat('dd if=/dev/zero bs=1048576 count=64 2>/dev/null\n')
        r = self.extract(bin_dir, max_bytes=10 * MIB)
        self.assertEqual(r.code, 1)
        self.assertEqual((r.json["status"], r.json["size"], r.json["path"]), ("partial", 10 * MIB, "work/out.bin.partial"))
        self.assertIn("budget", r.json["problem"])
        self.assertFalse(os.path.exists(self.path("work/out.bin")), "no truncated file keeps its own name")
        self.assertEqual(os.path.getsize(self.path("work/out.bin.partial")), 10 * MIB)

    def test_an_icat_that_fails_part_way_is_partial_and_one_that_wrote_nothing_is_an_error(self):
        bin_dir = self.icat('printf half\necho "Error reading block" >&2\nexit 1\n')
        r = self.extract(bin_dir)
        self.assertEqual((r.code, r.json["status"], r.json["size"], r.json["icat_exit"]), (1, "partial", 4, 1))
        self.assertIn("Error reading block", r.json["stderr_head"])
        self.assertFalse(os.path.exists(self.path("work/out.bin")))
        self.assertEqual(self.read("work/out.bin.partial"), "half")
        bin_dir = self.icat('echo "Cannot determine file system type" >&2\nexit 1\n')
        r = self.extract(bin_dir, output="work/none.bin")
        self.assertEqual(r.code, 1)
        self.assertIn("Cannot determine file system type", r.json["error"])
        self.assertFalse(os.path.exists(self.path("work/none.bin.partial")))

    def test_an_existing_output_is_never_replaced(self):
        bin_dir = self.icat('printf new\n')
        keep = self.write("work/out.bin", b"earlier extract")
        r = self.extract(bin_dir)
        self.assertEqual(r.code, 1)
        self.assertIn("never replaces", r.json["error"])
        self.assertEqual(self.read(keep, "rb"), b"earlier extract")
        os.symlink(self.path("elsewhere"), self.path("work/link.bin"))
        self.assertEqual(self.extract(bin_dir, output="work/link.bin").code, 1)
        self.assertFalse(os.path.exists(self.path("elsewhere")))

    def test_the_address_asked_for_selects_the_stream_named_in_the_catalogue(self):
        bin_dir = self.icat('printf data\n')
        self.write("catalog/disk.E01/partitions.txt", "002:  000:000   0000002048   ...   NTFS\n")
        self.write("catalog/disk.E01/p2048/filelist.txt",
                   "r/r 168-128-1:\tUsers/a/doc.txt\n"
                   "r/r 168-128-4:\tUsers/a/doc.txt:hidden\n"
                   "r/r 1680-128-1:\tUsers/other.txt\n")
        r = self.extract(bin_dir, inode="168-128-4")
        self.assertEqual(r.json["catalog_path"], "Users/a/doc.txt:hidden")
        self.assertEqual([e["address"] for e in r.json["catalog_paths"]], ["168-128-4"])
        r = self.extract(bin_dir, inode="168", output="work/b.bin")
        self.assertEqual(sorted(e["address"] for e in r.json["catalog_paths"]), ["168-128-1", "168-128-4"])

    def test_an_inode_that_is_not_an_address_never_reaches_icat(self):
        bin_dir = self.icat('printf data\n')
        for bad in ("12; rm -rf x", "-5", "1-2-3-4", "abc", True, -1, 2.5):
            self.assertEqual(self.extract(bin_dir, inode=bad, output="work/%s.bin" % abs(hash(str(bad)))).code, 1, bad)
        self.assertFalse(os.path.exists(self.argv_file))

    def test_a_leading_zero_is_the_same_address_and_the_arguments_must_be_json(self):
        bin_dir = self.icat('printf data\n')
        self.assertEqual(self.extract(bin_dir, inode="084284").code, 0)
        self.assertEqual(self.read(self.argv_file).split()[-1], "84284")
        self.assertEqual(self.extract(bin_dir, inode="084284-128-004", output="work/two.bin").code, 0)
        self.assertEqual(self.read(self.argv_file).split()[-1], "84284-128-4")
        r = run_tool("icat_extract", None, self.dir, [bin_dir], raw_input="{not json")
        self.assertEqual(r.code, 1)
        self.assertNotIn("Traceback", r.stderr)
        self.assertIn("not valid JSON", r.json["error"])

    def test_an_icat_that_stalls_is_stopped_at_the_time_budget_and_its_bytes_are_kept(self):
        bin_dir = self.icat('printf data\nexec sleep 60\n')
        r = run_tool("icat_extract", {"inode": "168-128-4", "output": "work/out.bin", "image": "inputs/disk.E01", "offset": 2048, "max_seconds": 1}, self.dir, [bin_dir], timeout=30)
        self.assertEqual(r.code, 1, r.stdout + r.stderr)
        self.assertEqual((r.json["status"], r.json["size"]), ("partial", 4))
        self.assertIn("time budget", r.json["problem"])
        self.assertEqual(self.read(self.path("work/out.bin.partial")), "data")
        self.assertFalse(os.path.exists(self.path("work/out.bin")))

    def test_a_file_that_appears_at_the_name_while_icat_runs_is_not_replaced(self):
        bin_dir = self.icat('mkdir -p work\necho planted > work/out.bin\nprintf data\n')
        r = self.extract(bin_dir)
        self.assertEqual(r.code, 1, r.stdout)
        self.assertEqual(self.read(self.path("work/out.bin")), "planted\n")
        self.assertIn("appeared while icat was running", r.json["problem"])
        self.assertEqual(self.read(self.path("work/out.bin.partial")), "data")
        self.assertIn("whole stream was written", r.json["note"])
        self.assertEqual((r.json["size"], r.json["path"]), (4, "work/out.bin.partial"))

    def test_icats_stderr_goes_to_a_file_of_its_own_and_never_over_another(self):
        bin_dir = self.icat('echo "icat complains" >&2\nprintf data\n')
        victim = self.write("victim.txt", "keep me")
        os.makedirs(self.path("work"), exist_ok=True)
        os.symlink(victim, self.path("work/out.bin.icat.stderr"))
        r = self.extract(bin_dir)
        self.assertEqual(r.code, 0, r.stdout)
        self.assertEqual(self.read(victim), "keep me")
        self.assertIn("icat complains", self.read(self.path(r.json["stderr_file"])))

    def test_a_time_budget_beyond_the_tools_own_limit_is_refused(self):
        bin_dir = self.icat('printf data\n')
        r = self.extract(bin_dir, max_seconds=1701)
        self.assertEqual(r.code, 1)
        self.assertIn("from 1 to 1700", r.json["error"])

    def test_in_a_job_an_output_outside_out_is_refused_and_one_under_it_is_written(self):
        bin_dir = self.icat('printf data\n')
        out = self.path("job-out")
        os.makedirs(out)
        env = {"JOB_ID": "j000011", "OUT": out}
        r = run_tool("icat_extract", {"inode": "168-128-4", "output": "work/out.bin", "image": "inputs/disk.E01", "offset": 2048}, self.dir, [bin_dir], env=env)
        self.assertEqual(r.code, 1, r.stdout)
        self.assertIn("under $OUT", r.json["error"])
        self.assertIn("{OUT}", r.json["hint"])
        self.assertFalse(os.path.exists(self.path("work")))
        r = run_tool("icat_extract", {"inode": "168-128-4", "output": os.path.join(out, "x.bin"), "image": "inputs/disk.E01", "offset": 2048}, self.dir, [bin_dir], env=env)
        self.assertEqual((r.code, r.json["status"]), (0, "complete"))
        self.assertEqual(self.read(os.path.join(out, "x.bin")), "data")


if __name__ == "__main__":
    unittest.main()
