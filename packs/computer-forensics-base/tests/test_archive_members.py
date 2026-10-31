"""archive-members: what a hostile archive cannot make the listing do.

The recipe is run as the harness runs it (`run.py run --target T --out DIR`). A tar whose GNU long-name header declares a gigabyte is a
sparse file here, so the declared size is real to tarfile and costs the test no disk. The ZIP with a NUL inside a member name is written
by the standard library and then has one byte of a stored name changed, in both its local and its central header, as an archiver that
stored the name would have.
"""
import bz2
import gzip
import io
import json
import lzma
import os
import shutil
import resource
import signal
import stat
import struct
import subprocess
import sys
import tarfile
import time
import unittest
import zipfile
import zlib

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


    def zip_bytes(self, name="a.txt", data=b"hello"):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr(name, data)
        return buf.getvalue()

    def test_a_tar_whose_last_member_is_a_zip_is_listed_as_the_tar_and_says_it_also_ends_in_a_zip_record(self):
        path = self.path("t.tar")
        inner = self.zip_bytes()
        with tarfile.open(path, "w") as tf:
            for name, data in (("first.txt", b"x" * 10), ("inner.zip", inner)):
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
        proc = self.run_recipe(path)
        self.assertEqual(json.loads(proc.stdout), {"ok": True, "status": "complete", "format": "tar", "members": 2})
        self.assertEqual([m["path"] for m in self.members()], ["first.txt", "inner.zip"], "the tar's own members, not the zip inside the last one")
        cov = self.coverage()
        self.assertEqual(cov["format"], "tar")
        self.assertTrue([n for n in cov["notes"] if "also ends in a zip end-of-central-directory record" in n], cov)

    def test_a_target_that_is_not_json_or_not_an_object_is_an_answer_not_a_traceback(self):
        for target in ("{not json", "[]", "3", '{"paths": 4}'):
            proc = subprocess.run([sys.executable, recipe_path("archive-members", "run.py"), "run", "--target", target, "--out", self.path("out")],
                                  cwd=self.dir, capture_output=True, text=True, timeout=60)
            self.assertNotIn("Traceback", proc.stderr, target)
            self.assertEqual(proc.returncode, 2, target)
            self.assertIs(json.loads(proc.stdout)["ok"], False, target)

    def test_a_7z_is_listed_by_7zz_when_there_is_no_7z(self):
        d = self.path("bin")
        os.makedirs(d)
        stand_in(d, "7zz", 'printf "Path = a.txt\\nSize = 1\\n\\n"\n')
        archive = self.write("a.7z", b"7z\xbc\xaf\x27\x1c" + b"\0" * 64)
        proc = self.run_recipe(archive, env={"PATH": d})
        self.assertEqual(json.loads(proc.stdout)["status"], "complete", proc.stdout + proc.stderr)
        self.assertEqual([m["path"] for m in self.members()], ["a.txt"])
        empty = self.path("none")
        os.makedirs(empty)
        proc = self.run_recipe(archive, out="out2", env={"PATH": empty})
        self.assertEqual(json.loads(proc.stdout)["status"], "unsupported")
        self.assertIn("7zz", "\n".join(self.coverage("out2")["errors"]), "the answer names every program it looked for")

    def test_a_tar_whose_first_member_is_named_like_a_zip_signature_and_ends_in_a_zip_is_listed_as_the_zip_and_says_it_is_also_a_tar(self):
        path = self.path("poly.tar")
        inner = self.zip_bytes()
        with tarfile.open(path, "w", format=tarfile.USTAR_FORMAT) as tf:
            for name, data in (("PK\x03\x04first", b"x" * 10), ("inner.zip", inner)):
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
        proc = self.run_recipe(path)
        self.assertEqual(json.loads(proc.stdout)["format"], "zip", proc.stdout + proc.stderr)
        cov = self.coverage()
        self.assertTrue([n for n in cov.get("notes", []) if "also reads there" in n and "also a tar" in n], cov)
        plain = self.path("plain.zip")
        with zipfile.ZipFile(plain, "w") as z:
            z.writestr("a.txt", "a")
        self.run_recipe(plain, out="out3")
        self.assertNotIn("notes", self.coverage("out3"), "a zip that is only a zip says nothing of a tar")

    def test_bytes_that_end_in_a_zip_record_that_does_not_agree_with_the_file_are_not_a_zip(self):
        for tail in (b"PK\x05\x06" + b"\0" * 18, b"PK\x05\x06" + b"\x01\0\x01\0" + b"\x2e\0\0\0" + b"\x10\0\0\0" + b"\0\0"):
            path = self.write("junk.bin", os.urandom(1000) + tail)
            proc = self.run_recipe(path)
            self.assertEqual(proc.returncode, 2)
            got = json.loads(proc.stdout)
            self.assertEqual((got["ok"], got["status"]), (False, "unsupported"), "the answer says so on stdout, not only in coverage.json")
            self.assertEqual(self.coverage()["status"], "unsupported")
            self.assertFalse(os.path.exists(self.path("out/members.tsv")))
            shutil.rmtree(self.path("out"))

    def test_a_zip_with_a_prefix_is_still_a_zip_and_so_is_one_with_trailing_junk(self):
        zb = self.zip_bytes("p.txt")
        for name, data in (("sfx.zip", b"MZ" + b"\0" * 100 + zb), ("trail.zip", zb + b"J" * 100)):
            path = self.write(name, data)
            proc = self.run_recipe(path)
            self.assertEqual(json.loads(proc.stdout)["format"], "zip", name)
            self.assertEqual([m["path"] for m in self.members()], ["p.txt"], name)
            shutil.rmtree(self.path("out"))


COMPRESSORS = {"gzip": lambda b: gzip.compress(b, mtime=0), "bzip2": bz2.compress, "xz": lzma.compress}


def small_tar(*names):
    """A plain tar of the given member names, ended as tarfile ends one: two zero blocks and zero padding to a 10240-byte record."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name in names:
            data = (name.encode() + b"\n") * 20
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


class CompressedTarTail(Case):
    """A compressed tar is complete only when its whole stream has been read: after the end blocks, a further tar in the same stream, a
    further compressed stream, bytes after the last stream, a trailer that does not match and a stream that does not end all make the
    answer partial with the offset named, as the same bytes uncompressed do. Fixtures are built from the formats with tarfile, gzip,
    bz2, lzma and zlib, never from the recipe's own output."""

    run_recipe = ArchiveMembers.run_recipe
    coverage = ArchiveMembers.coverage
    members = ArchiveMembers.members

    def listed(self, name, data, env=None):
        path = self.write(name, data)
        proc = self.run_recipe(path, env=env)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        return json.loads(proc.stdout), self.coverage(), [m["path"] for m in self.members()]

    def assert_partial(self, name, data, needle, members=("a.txt",), env=None):
        got, cov, paths = self.listed(name, data, env=env)
        self.assertEqual(got["status"], "partial", (name, cov))
        self.assertEqual(cov["status"], "partial", (name, cov))
        self.assertEqual(paths, list(members), name)
        text = " ".join(cov["errors"] + cov["limits_hit"])
        self.assertIn(needle, text, (name, cov))
        shutil.rmtree(self.path("out"))
        return cov

    def test_a_sound_compressed_tar_stays_complete_also_padded_to_a_record_and_followed_by_zeros(self):
        for kind, compress in COMPRESSORS.items():
            tar = small_tar("a.txt", "b.txt")
            for label, payload in (("plain", tar), ("zero tail", tar + b"\0" * 3_000_000), ("padded stream", tar + b"\0" * 10240)):
                got, cov, paths = self.listed("sound-%s-%s.tar" % (kind, label.replace(" ", "")), compress(payload))
                self.assertEqual(got["status"], "complete", (kind, label, cov))
                self.assertEqual(paths, ["a.txt", "b.txt"], (kind, label))
                self.assertEqual((cov["errors"], cov["limits_hit"]), ([], []), (kind, label))
                shutil.rmtree(self.path("out"))

    def test_two_tars_in_one_compressed_stream_are_partial_with_the_offset_of_the_second(self):
        first, second = small_tar("a.txt"), small_tar("b.txt")
        for kind, compress in COMPRESSORS.items():
            cov = self.assert_partial("cat-%s.tar" % kind, compress(first + second), "starts at decompressed offset %d" % len(first))
            self.assertIn("compressed stream 1", " ".join(cov["errors"]), kind)

    def test_a_second_compressed_stream_holding_a_tar_is_partial(self):
        first, second = small_tar("a.txt"), small_tar("b.txt")
        for kind, compress in COMPRESSORS.items():
            cov = self.assert_partial("multi-%s.tar" % kind, compress(first) + compress(second), "starts at decompressed offset %d" % len(first))
            self.assertIn("compressed stream 2", " ".join(cov["errors"]), kind)

    def test_a_second_compressed_stream_of_zeros_only_is_still_complete(self):
        tar = small_tar("a.txt")
        for kind, compress in COMPRESSORS.items():
            got, cov, paths = self.listed("zeros-%s.tar" % kind, compress(tar) + compress(b"\0" * 20480))
            self.assertEqual((got["status"], paths), ("complete", ["a.txt"]), (kind, cov))
            shutil.rmtree(self.path("out"))

    def test_bytes_after_the_last_stream_are_partial_unless_they_are_zeros(self):
        tar = small_tar("a.txt")
        for kind, compress in COMPRESSORS.items():
            self.assert_partial("tail-%s.tar" % kind, compress(tar) + b"garbage that is no stream", "after the last compressed stream")
            got, cov, paths = self.listed("pad-%s.tar" % kind, compress(tar) + b"\0" * 512)
            self.assertEqual(got["status"], "complete", (kind, cov))
            shutil.rmtree(self.path("out"))

    def test_a_gzip_trailer_that_does_not_match_is_partial_for_the_crc_and_for_the_length(self):
        tar = small_tar("a.txt")
        sound = gzip.compress(tar, mtime=0)
        for label, index, needle in (("crc", -8, "incorrect data check"), ("isize", -4, "incorrect length check")):
            bad = bytearray(sound)
            bad[index] ^= 0xFF
            self.assert_partial("bad-%s.tar.gz" % label, bytes(bad), needle)

    def test_a_stream_that_does_not_end_is_partial(self):
        tar = small_tar("a.txt")
        for kind, cut in (("gzip", 8), ("bzip2", 10), ("xz", 12)):
            whole = COMPRESSORS[kind](tar)
            self.assert_partial("cut-%s.tar" % kind, whole[:-cut], "does not end cleanly")

    def test_a_large_junk_rest_after_the_end_blocks_is_found_however_far_it_is(self):
        tar = small_tar("a.txt")
        for kind, compress in COMPRESSORS.items():
            payload = tar + b"\0" * (4 << 20) + b"J" * 4096
            self.assert_partial("far-%s.tar" % kind, compress(payload), "starts at decompressed offset %d" % (len(tar) + (4 << 20)))

    def test_a_rest_longer_than_the_clock_allows_is_partial_and_says_it_was_not_read_to_its_end(self):
        tar = small_tar("a.txt")
        path = self.path("long.tar.gz")
        comp = zlib.compressobj(1, zlib.DEFLATED, 31)
        with open(path, "wb") as fh:
            fh.write(comp.compress(tar))
            zeros = b"\0" * (1 << 20)
            for _ in range(3 * 1024):                         # 3 GiB of zeros after the end blocks, a few MiB compressed
                fh.write(comp.compress(zeros))
            fh.write(comp.flush())
        began = time.monotonic()
        proc = self.run_recipe(path, env={"RECIPE_SECONDS": "1"})
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertLess(time.monotonic() - began, 60, "the clock bounds the rest-read")
        cov = self.coverage()
        self.assertEqual(cov["status"], "partial", cov)
        self.assertTrue([x for x in cov["limits_hit"] if "was not read to its end" in x], cov)
        self.assertEqual([m["path"] for m in self.members()], ["a.txt"])


if __name__ == "__main__":
    unittest.main()
