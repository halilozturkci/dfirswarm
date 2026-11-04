"""archive_extract reads a RAR (versions 4 and 5) through 7zz, with a row for every member, and says what it could not read.

Two kinds of test, and the difference matters:

  * Real-reader tests read one real RAR 5 archive from the rarfile project's test files (tests/fixtures/rar/rar5-subdirs.rar, see
    SOURCE.txt there) with the real 7zz. They skip, and say so, where no 7zz is on PATH. The archive stores its files without
    compression (method m0), so they show listing, the split of the reader's output into members, the CRC check and the
    answers to a cut archive; they do not show that the reader decodes a compressed RAR. No real RAR 4 archive, no real
    compressed or solid RAR and no real multi-volume set is among the fixtures.
  * Stand-in tests put a small /bin/sh script named 7zz in front of PATH. It prints a listing in the shape 7-Zip's `l -slt -ba`
    prints (copied from the real reader's output for the fixture) and bytes that are made up here. They test what this tool does
    with what a reader says (an exit status, a flag in the listing, a stream too long), never what a real reader says about a
    real RAR, and they are named so.

The expected bytes of the real archive are the bytes stored in it (visible in the archive's own bytes, stored), their CRC-32
are the values in the archive's headers, hashed here, never read back from the tool's output.
"""
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import time
import unittest
import zlib

from support import Case, run_tool, stand_in, tool_path

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURE = os.path.join(HERE, "fixtures", "rar", "rar5-subdirs.rar")
FIXTURE_SHA256 = "4449d0e82e09f52af23a11cd84904625de8b15beafcf73e5c30dc3296beae0b2"
SEVEN_ZZ = shutil.which("7zz")

# name -> (content, CRC-32 from the archive's header)
MEMBERS = {
    "sub/dir2/file2.txt": (b"file2\n", 0xC904A4C7),
    "sub/with space/long fn.txt": (b"long fn\n", 0x71B7247D),
    "sub/üȵĩöḋè/file.txt": (b"file\n", 0x2FEC89C1),
    "sub/dir1/file1.txt": (b"file1\n", 0xE229F704),
}
DIRS = {"sub/dir2", "sub/with space", "sub/empty", "sub/üȵĩöḋè", "sub/dir1", "sub"}

LISTING_FILE = (
    "Path = %(name)s\nFolder = -\nSize = %(size)d\nPacked Size = %(size)d\nModified = 2020-07-20 21:01:44.319218821\nCreated = \nAccessed = \n"
    "Attributes =  -rw-r--r--\nAlternate Stream = %(ads)s\nEncrypted = %(enc)s\nSolid = -\nSplit Before = %(before)s\nSplit After = %(after)s\n"
    "CRC = %(crc)s\nHost OS = Unix\nMethod = v6:m0:128K\nCharacteristics = CRC Time:uMn\nSymbolic Link = %(sym)s\nHard Link = \nCopy Link = \n"
    "Volume Index = \nChecksum = \nNT Security = \n\n")


def record(name, size, crc="", enc="-", ads="-", before="-", after="-", sym=""):
    return LISTING_FILE % {"name": name, "size": size, "crc": crc, "enc": enc, "ads": ads, "before": before, "after": after, "sym": sym}


def dir_record(name):
    return ("Path = %s\nFolder = +\nSize = 0\nPacked Size = 0\nModified = 2020-07-20 21:01:44.335219144\nAttributes = D drwxr-xr-x\n"
            "Encrypted = -\nCRC = 00000000\nMethod = v6:m0\n\n" % name)


def sha(data):
    return hashlib.sha256(data).hexdigest()


class RarBase(Case):
    def extract(self, archive, out=None, path_dirs=(), **kw):
        args = dict({"path": archive}, **kw)
        if out:
            args["out_dir"] = out
        return run_tool("archive_extract", args, self.dir, path_dirs=list(path_dirs))

    def rows(self, out):
        with open(os.path.join(self.dir, out, "members.jsonl"), encoding="utf-8") as fh:
            return [json.loads(line) for line in fh]

    def copy_fixture(self, name="inputs/a.rar", size=None):
        with open(FIXTURE, "rb") as fh:
            data = fh.read()
        self.assertEqual(sha(data), FIXTURE_SHA256, "the fixture is not the file whose source is recorded in SOURCE.txt")
        return self.write(name, data if size is None else data[:size])

    def stand_in_reader(self, listing, extract, name="7zz"):
        """A 7zz that prints `listing` (a shell snippet) for `l` and runs `extract` for `x`; it records its arguments in args.log."""
        bindir = self.path("bin")
        os.makedirs(bindir, exist_ok=True)
        log = self.path("args.log")
        stand_in(bindir, name, (
            'echo "$@" >> %s\n'
            'case "$1" in\n'
            '  l) %s;;\n'
            '  x) %s;;\n'
            '  *) echo "7-Zip (z) stand-in";;\n'
            'esac\n') % (log, listing, extract))
        return bindir


@unittest.skipUnless(SEVEN_ZZ, "no 7zz on PATH: the real-reader tests need 7-Zip's own build (the base image holds one)")
class RealReader(RarBase):
    """The real 7zz on the real RAR 5 archive."""

    def test_a_rar5_comes_out_with_every_member_and_its_checks(self):
        self.copy_fixture()
        r = self.extract("inputs/a.rar", "work/out")
        self.assertEqual(r.code, 0, r.stdout + r.stderr)
        self.assertEqual(r.json["status"], "complete", r.json.get("status_basis"))
        self.assertEqual(r.json["archive"]["format"], "rar")
        self.assertEqual(os.path.basename(r.json["archive"]["program"]["path"]), "7zz")
        self.assertIn("7-Zip", r.json["archive"]["program"]["banner"])
        self.assertEqual(r.json["counts"], {"directory": len(DIRS), "extracted": len(MEMBERS)})
        self.assertIsNone(r.json["stopped_by"])
        rows = self.rows("work/out")
        self.assertEqual(len(rows), len(MEMBERS) + len(DIRS))
        self.assertEqual(sorted(row["n"] for row in rows), list(range(len(rows))), "one row per member, numbered from 0, in the reader's order")
        seen = {}
        for row in rows:
            name = row["name"]
            if row["type"] == "dir":
                self.assertEqual(row["status"], "directory")
                seen[name] = None
                continue
            content, crc = MEMBERS[name]
            seen[name] = row
            self.assertEqual((row["status"], row["type"]), ("extracted", "file"), row)
            self.assertEqual((row["size_declared"], row["size_written"]), (len(content), len(content)))
            self.assertIs(row["crc_verified"], True)
            self.assertEqual(zlib.crc32(content), crc, "the expected bytes are the ones whose CRC the archive's header holds")
            with open(os.path.join(self.dir, "work/out", row["path"]), "rb") as fh:
                self.assertEqual(fh.read(), content)
            # a member shorter than 128 bytes has no digest or CRC written: the row says so, and the file is checked here
            self.assertIsNone(row["sha256"])
            self.assertTrue(row["digest_withheld"])
            self.assertEqual(row["locator"].split("=")[0], "rar:index")
        self.assertEqual(set(seen), set(MEMBERS) | DIRS)

    def test_the_members_are_named_to_the_reader_in_a_list_file_with_wildcards_off(self):
        self.copy_fixture()
        r = self.extract("inputs/a.rar", "work/out")
        self.assertEqual(r.json["status"], "complete")
        sel = self.read("work/out/" + r.json["selection_file"], "rb")
        self.assertEqual(sorted(sel.decode("utf-8").splitlines()), sorted(MEMBERS))

    def test_a_cut_copy_is_never_complete_and_names_what_the_reader_said(self):
        size = os.path.getsize(FIXTURE)
        cuts = list(range(8, size, 11)) + [size - 1, size - 2, 80]
        for cut in cuts:
            with self.subTest(cut=cut):
                self.copy_fixture("inputs/cut%d.rar" % cut, cut)
                r = self.extract("inputs/cut%d.rar" % cut, "work/out%d" % cut)
                self.assertIsNotNone(r.json, "no JSON for a cut at %d: %r" % (cut, r.stderr[-200:]))
                self.assertIn(r.json["status"], ("partial", "failed"))
                self.assertNotEqual(r.json["status"], "complete")
                if r.json["status"] == "partial":
                    self.assertTrue(r.json["stopped_by"] or r.json["counts"].get("partial"), r.json["counts"])
                    self.assertIn(r.json["listing_exit"], (1, 2))

    def test_a_cut_inside_a_member_leaves_it_partial_with_the_bytes_it_got(self):
        self.copy_fixture("inputs/cut.rar", 80)
        r = self.extract("inputs/cut.rar", "work/out")
        self.assertEqual(r.code, 0, r.stdout)
        self.assertEqual(r.json["status"], "partial")
        row = self.rows("work/out")[0]
        self.assertEqual((row["status"], row["size_declared"], row["size_written"]), ("partial", 6, 3))
        self.assertIn("read_failed", row["reason"])
        self.assertTrue(row["path"].endswith(".partial"))
        self.assertEqual(r.json["next_index"], 1)
        self.assertEqual(r.json["stopped_by"], "reader_listing_exit")
        self.assertIn("Unexpected end of archive", r.json["stop"])
        self.assertEqual(self.read(os.path.join(self.dir, "work/out", row["path"]), "rb"), b"fil")

    def test_a_rar_signature_with_nothing_behind_it_is_failed_not_complete(self):
        self.write("inputs/j4.rar", b"Rar!\x1a\x07\x00" + b"\x00" * 100)
        self.write("inputs/j5.rar", b"Rar!\x1a\x07\x01\x00" + b"\x00" * 100)
        for name in ("j4", "j5"):
            r = self.extract("inputs/%s.rar" % name, "work/%s" % name)
            self.assertEqual(r.code, 1, r.stdout)
            self.assertEqual(r.json["status"], "failed")
            self.assertIn("listed no member of this RAR", r.json["error"])

    def test_from_index_goes_on_in_the_same_directory(self):
        self.copy_fixture()
        first = self.extract("inputs/a.rar", "work/out", max_members=2)
        self.assertEqual(first.json["status"], "partial")
        self.assertEqual(first.json["stopped_by"], "max_members")
        self.assertEqual(first.json["next_index"], 2)
        again = run_tool("archive_extract", {"path": "inputs/a.rar", "out_dir": "work/out", "resume": True, "from_index": 2}, self.dir)
        self.assertEqual(again.json["status"], "complete", again.stdout)
        self.assertEqual([x["status"] for x in self.rows("work/out")], ["extracted", "extracted"], "the first run's two files are in the first manifest")
        self.assertEqual(again.json["counts"], {"directory": len(DIRS), "extracted": 2})


class Detection(RarBase):
    def test_a_rar_signature_that_is_neither_version_is_refused_by_name(self):
        self.write("inputs/r.rar", b"Rar!\x1a\x07\x02" + b"\x00" * 100)
        r = self.extract("inputs/r.rar", "work/out2")
        self.assertEqual(r.code, 1)
        self.assertEqual(r.json["format"], "unsupported:rar")
        self.assertFalse(os.path.exists(self.path("work/out2")), "a refused archive makes no directory")

    def test_a_rar_without_a_reader_is_failed_and_names_the_program(self):
        self.copy_fixture()
        r = run_tool("archive_extract", {"path": "inputs/a.rar", "out_dir": "work/out"}, self.dir, only_path="")
        self.assertEqual(r.code, 1, r.stdout)
        self.assertEqual(r.json["status"], "failed")
        self.assertIn("7zz", r.json["error"])
        self.assertEqual(r.json["program"], "7zz")
        self.assertNotIn("members", r.json)
        self.assertEqual(os.listdir(self.path("work/out/extracted")), [], "nothing was extracted")

    def test_a_version_4_signature_is_routed_to_the_reader_too(self):
        self.write("inputs/v4.rar", b"Rar!\x1a\x07\x00" + b"\x00" * 100)
        bindir = self.stand_in_reader("exit 2", "exit 2")
        r = self.extract("inputs/v4.rar", "work/out", path_dirs=[bindir])
        self.assertEqual(r.json["archive"]["format"], "rar")
        self.assertIn("version 4", r.json["archive"]["detected_by"])
        self.assertEqual(r.json["status"], "failed")

    def test_without_7zz_another_7z_is_used_and_the_answer_says_it_was_not_checked_for_the_codec(self):
        self.write("inputs/v5.rar", b"Rar!\x1a\x07\x01\x00" + b"\x00" * 100)
        bindir = self.stand_in_reader(
            "printf '%s' '" + record("a.txt", 5, "3610A686") + "'", "printf hello", name="7z")
        r = run_tool("archive_extract", {"path": "inputs/v5.rar", "out_dir": "work/out"}, self.dir, only_path=bindir)
        self.assertEqual(r.json["status"], "complete", r.stdout)
        self.assertIn("RAR codec", r.json["archive"]["program"]["note"])
        self.assertEqual(os.path.basename(r.json["archive"]["program"]["path"]), "7z")

    def test_7zz_is_preferred_over_a_7z_found_first_on_PATH(self):
        self.write("inputs/v5.rar", b"Rar!\x1a\x07\x01\x00" + b"\x00" * 100)
        first = self.path("first")
        os.makedirs(first)
        stand_in(first, "7z", 'exit 2')
        second = self.stand_in_reader("printf '%s' '" + record("a.txt", 5, "3610A686") + "'", "printf hello")
        r = self.extract("inputs/v5.rar", "work/out", path_dirs=[first, second])
        self.assertEqual(r.json["status"], "complete", r.stdout)
        self.assertEqual(os.path.basename(r.json["archive"]["program"]["path"]), "7zz")


class StandInReader(RarBase):
    """What the tool does with what a reader says. The reader is a script here: nothing below is a claim about the real 7zz."""

    V5 = b"Rar!\x1a\x07\x01\x00" + b"\x00" * 64

    def run_with(self, listing_text, extract_cmd, listing_cmd_extra="", **kw):
        self.write("inputs/s.rar", self.V5)
        bindir = self.stand_in_reader("printf '%%s' '%s'%s" % (listing_text, listing_cmd_extra), extract_cmd)
        return self.extract("inputs/s.rar", "work/out", path_dirs=[bindir], **kw)

    def test_the_stand_in_listing_and_bytes_give_complete_and_the_reader_was_given_no_password(self):
        r = self.run_with(record("a.txt", 5, "3610A686"), "printf hello")
        self.assertEqual(r.json["status"], "complete", r.stdout)
        args = self.read("args.log")
        self.assertIn("x -so -y -bd -spd -scsUTF-8", args)
        self.assertFalse([t for t in args.split() if t.startswith("-p")], "no password switch is ever given")

    def test_a_reader_that_exits_non_zero_after_giving_every_byte_is_partial_even_without_a_crc(self):
        r = self.run_with(record("a.txt", 5, ""), 'printf hello; echo "Data error in a.txt" >&2; exit 2')
        self.assertEqual(r.code, 0, r.stdout)
        self.assertEqual(r.json["status"], "partial")
        self.assertEqual(r.json["stopped_by"], "reader_extract_exit")
        self.assertEqual(r.json["extract_exit"], 2)
        self.assertIn("Data error", r.json["stop"])
        self.assertIsNone(self.rows("work/out")[0]["crc_verified"], "no CRC was listed, so none was claimed verified")

    def test_a_listing_that_does_not_finish_makes_the_answer_partial_naming_the_volume_the_reader_names(self):
        r = self.run_with(record("a.txt", 5, "3610A686", after="+"), "printf hello",
                          listing_cmd_extra="; echo 'ERROR: Missing volume : s.part2.rar' >&2; exit 2")
        self.assertEqual(r.json["status"], "partial", r.stdout)
        self.assertEqual(r.json["stopped_by"], "reader_listing_exit")
        self.assertIn("Missing volume : s.part2.rar", r.json["stop"])
        self.assertIn("continues-in-next-volume", self.rows("work/out")[0]["flags"])

    def test_an_encrypted_member_is_counted_and_never_asked_for(self):
        r = self.run_with(record("a.txt", 5, "3610A686") + record("secret.txt", 9, "00000000", enc="+"), "printf hello")
        self.assertEqual(r.json["status"], "partial")
        self.assertEqual(r.json["counts"], {"encrypted": 1, "extracted": 1})
        self.assertEqual(self.read("work/out/" + r.json["selection_file"]).splitlines(), ["a.txt"])

    def test_a_link_an_alternate_stream_and_a_copy_record_are_not_asked_for_and_not_called_extracted(self):
        listing = (record("a.txt", 5, "3610A686") + record("ln", 0, sym="a.txt") + record("a.txt:stream", 3, "00000000", ads="+")
                   + "Path = c\nFolder = -\nSize = 5\nEncrypted = -\nCRC = 3610A686\nCopy Link = a.txt\n\n")
        r = self.run_with(listing, "printf hello")
        rows = self.rows("work/out")
        self.assertEqual([x["status"] for x in rows], ["extracted", "not_created", "unsupported", "unsupported"])
        self.assertEqual(rows[1]["link_target"], "a.txt")
        self.assertEqual(r.json["status"], "partial")
        self.assertEqual(self.read("work/out/" + r.json["selection_file"]).splitlines(), ["a.txt"])

    def test_nothing_to_extract_starts_no_extraction(self):
        r = self.run_with(dir_record("d") + dir_record("d/e"), "touch %s; exit 9" % self.path("x-was-run"))
        self.assertEqual(r.json["status"], "complete", r.stdout)
        self.assertFalse(os.path.exists(self.path("x-was-run")), "a list file with no name would not mean nothing: no extraction was started")
        self.assertIn("not started", r.json["extract_exit"])

    def test_output_longer_than_the_listing_is_partial(self):
        r = self.run_with(record("a.txt", 5, "3610A686"), "printf hello-and-more")
        self.assertEqual(r.json["status"], "partial", r.stdout)
        self.assertTrue(r.json["stream_longer_than_listing"])
        self.assertEqual(r.json["stopped_by"], "archive_unreadable")

    def test_output_shorter_than_the_listing_is_partial_and_the_row_says_how_short(self):
        r = self.run_with(record("a.txt", 5, "3610A686"), "printf hel")
        self.assertEqual(r.json["status"], "partial", r.stdout)
        row = self.rows("work/out")[0]
        self.assertEqual((row["status"], row["size_written"]), ("partial", 3))

    def test_wrong_bytes_of_the_right_size_are_a_crc_mismatch(self):
        r = self.run_with(record("a.txt", 5, "3610A686"), "printf HELLO")
        self.assertEqual(r.json["status"], "partial", r.stdout)
        self.assertIn("crc_mismatch", self.rows("work/out")[0]["reason"])

    def test_a_name_that_would_be_a_wildcard_or_a_path_outside_comes_out_under_a_harmless_name(self):
        r = self.run_with(record("../../x*?[a].txt", 5, "3610A686"), "printf hello")
        self.assertEqual(r.json["status"], "complete", r.stdout)
        row = self.rows("work/out")[0]
        self.assertTrue(row["path"].startswith("extracted/"), row["path"])
        self.assertNotIn("..", row["path"].split("/"))
        self.assertTrue(os.path.isfile(self.path("work/out", row["path"])))
        self.assertFalse(os.path.exists(self.path("x*?[a].txt")))
        self.assertFalse(os.path.exists(self.path("work", "x*?[a].txt")))

    def test_a_name_with_edge_whitespace_is_not_passed_to_the_reader_and_is_unsupported(self):
        r = self.run_with(record(" a.txt", 5, "3610A686"), "printf hello")
        self.assertEqual(self.rows("work/out")[0]["status"], "unsupported")
        self.assertEqual(r.json["status"], "partial")

    def test_a_sigterm_kills_the_reader_and_leaves_one_partial_document(self):
        pidfile = self.path("pids")
        self.write("inputs/slow.rar", self.V5)
        bindir = self.stand_in_reader("printf '%%s' '%s'" % record("slow.bin", 100000, "00000000"),
                                      'echo $$ > %s; printf "some bytes"; sleep 300' % pidfile)
        env = dict(os.environ, PATH=bindir + os.pathsep + os.environ["PATH"])
        env.pop("JOB_ID", None)
        env.pop("OUT", None)
        proc = subprocess.Popen([sys.executable, tool_path("archive_extract")], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                cwd=self.dir, env=env)
        proc.stdin.write(json.dumps({"path": "inputs/slow.rar", "out_dir": "work/out"}).encode())
        proc.stdin.close()
        for _ in range(200):
            if os.path.exists(pidfile) and self.read(pidfile).strip():
                break
            time.sleep(0.05)
        else:
            proc.kill()
            self.fail("the stand-in reader never started")
        pid = int(self.read(pidfile).split()[0])
        proc.send_signal(signal.SIGTERM)
        said = proc.stdout.read()
        proc.wait(timeout=20)
        proc.stdout.close()
        proc.stderr.close()
        self.assertEqual(proc.returncode, 143)
        word = json.loads(said)
        self.assertEqual((word["status"], word["interrupted"], word["signal"]), ("partial", True, int(signal.SIGTERM)))
        time.sleep(0.5)
        try:
            os.kill(pid, 0)
            alive = True
        except OSError:
            alive = False
        self.assertFalse(alive, "the reader was left running")

    def test_the_deadline_ends_a_reader_that_never_finishes(self):
        pidfile = self.path("pids")
        self.write("inputs/slow.rar", self.V5)
        bindir = self.stand_in_reader("printf '%%s' '%s'" % record("slow.bin", 100000, "00000000"),
                                      'echo $$ > %s; sleep 300 & echo $! >> %s; printf "some bytes"; sleep 300' % (pidfile, pidfile))
        start = time.monotonic()
        r = run_tool("archive_extract", {"path": "inputs/slow.rar", "out_dir": "work/out", "max_seconds": 2}, self.dir, path_dirs=[bindir], timeout=60)
        self.assertLess(time.monotonic() - start, 30)
        self.assertEqual(r.code, 0, r.stdout + r.stderr)
        self.assertEqual((r.json["status"], r.json["stopped_by"]), ("partial", "max_seconds"))
        time.sleep(0.5)
        for pid in [int(x) for x in self.read("pids").split()]:
            try:
                os.kill(pid, 0)
                self.fail("pid %d was left running" % pid)
            except OSError:
                pass


class ImageReadiness(unittest.TestCase):
    def test_the_fixture_embedded_in_the_image_script_is_the_fixture(self):
        script = os.path.join(HERE, "..", "..", "..", "tests", "image-programs.sh")
        if not os.path.isfile(script):
            self.skipTest("the repository's tests/image-programs.sh is not beside this pack")
        import base64
        with open(script, encoding="utf-8") as fh:
            text = fh.read()
        mark = "<<'B64'\n"
        start = text.index(mark) + len(mark)
        embedded = base64.b64decode(text[start:text.index("\nB64\n", start)])
        with open(FIXTURE, "rb") as fh:
            self.assertEqual(embedded, fh.read())
        self.assertIn(FIXTURE_SHA256, text)
        self.assertEqual(sha(embedded), FIXTURE_SHA256)


if __name__ == "__main__":
    unittest.main()
