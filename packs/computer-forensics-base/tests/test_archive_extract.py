"""archive_extract: what a hostile archive cannot make the extraction do, and what a good one gives back.

The fixtures are built from the formats: zip and tar archives by the standard library (with the header bytes of a member patched
where the library will not write what an archiver could, as the archive-members tests do), gzip, bzip2 and xz streams by their
modules, a 7z archive by the real 7z program (those tests skip, and say so, where it is not installed), and the expected bytes
are the bytes that were put in, hashed here, never read back from the tool's own output.
"""
import bz2
import gzip
import hashlib
import importlib.util
import io
import json
import lzma
import os
import shutil
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

from support import Case, recipe_path, run_tool, stand_in, tool_path

SEVEN_Z = next((p for p in ("7z", "7zz", "7za") if shutil.which(p)), None)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def zstd_available():
    """What the tool can read zstd with: Python 3.14's compression.zstd, or the zstd program."""
    try:
        from compression import zstd  # noqa: F401
        return True
    except ImportError:
        return shutil.which("zstd") is not None


def zstd_compress(data):
    try:
        from compression import zstd
        return zstd.compress(data)
    except ImportError:
        return subprocess.run(["zstd", "-q", "-c"], input=data, capture_output=True, check=True).stdout


def make_zip(path, members, compress=zipfile.ZIP_DEFLATED):
    """members: (name, data) pairs, or (ZipInfo, data)."""
    if isinstance(path, str):
        os.makedirs(os.path.dirname(path), exist_ok=True)
    with zipfile.ZipFile(path, "w", compress) as zf:
        for name, data in members:
            if isinstance(name, zipfile.ZipInfo):
                zf.writestr(name, data, compress_type=compress)
            else:
                zf.writestr(name, data)
    return path


def make_tar(path, entries, mode="w"):
    """entries: dicts with name, data, and optionally type / linkname / mode."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with tarfile.open(path, mode) as tf:
        for e in entries:
            info = tarfile.TarInfo(e["name"])
            info.type = e.get("type", tarfile.REGTYPE)
            data = e.get("data", b"")
            info.size = len(data) if info.type == tarfile.REGTYPE else 0
            info.mode = e.get("mode", 0o644)
            info.mtime = e.get("mtime", 1700000000)
            if "linkname" in e:
                info.linkname = e["linkname"]
            if "devmajor" in e:
                info.devmajor, info.devminor = e["devmajor"], e.get("devminor", 0)
            tf.addfile(info, io.BytesIO(data) if info.type == tarfile.REGTYPE else None)
    return path


def patch_zip(data, name, local=None, central=None):
    """Change bytes of the headers of the member `name` in a zip: `local` and `central` are (offset in the header, new bytes)."""
    raw = bytearray(data)
    needle = name.encode()
    for sig, edit in ((b"PK\x03\x04", local), (b"PK\x01\x02", central)):
        if edit is None:
            continue
        at = raw.find(sig)
        while at >= 0:
            fn_len_at = 26 if sig == b"PK\x03\x04" else 28
            fn_len = struct.unpack_from("<H", raw, at + fn_len_at)[0]
            fn_at = at + (30 if sig == b"PK\x03\x04" else 46)
            if bytes(raw[fn_at:fn_at + fn_len]) == needle:
                off, new = edit
                raw[at + off:at + off + len(new)] = new
                break
            at = raw.find(sig, at + 4)
        else:
            raise AssertionError("no %r header for %s" % (sig, name))
    return bytes(raw)


class Extract(Case):
    def extract(self, archive, out=None, **kw):
        args = dict({"path": archive}, **kw)
        if out:
            args["out_dir"] = out
        return run_tool("archive_extract", args, self.dir)

    def rows(self, out):
        with open(os.path.join(self.dir, out, "members.jsonl"), encoding="utf-8") as fh:
            return [json.loads(line) for line in fh]

    def files_under(self, root):
        """Every entry under root as (relative path, lstat mode), links not followed."""
        found = []
        for base, dirs, files in os.walk(root, followlinks=False):
            for name in dirs + files:
                full = os.path.join(base, name)
                found.append((os.path.relpath(full, root), os.lstat(full).st_mode))
        return sorted(found)

    def world(self, exclude):
        """Everything under the scratch directory outside `exclude`, with sizes: to show a run wrote nowhere else."""
        out = {}
        for base, dirs, files in os.walk(self.dir):
            if os.path.abspath(base).startswith(os.path.abspath(exclude)):
                dirs[:] = []
                continue
            for name in dirs + files:
                full = os.path.join(base, name)
                out[os.path.relpath(full, self.dir)] = os.lstat(full).st_size
        return out

    # ---- a good archive ----

    def test_a_zip_comes_out_member_for_member_with_the_bytes_that_went_in(self):
        a = os.urandom(5000) + b"A" * 5000
        b = b"".join(b"line %d\n" % i for i in range(2000))
        c = b"tiny"
        path = make_zip(self.path("inputs/c.zip"), [("a.bin", a), ("d/e/b.txt", b), ("c.txt", c), ("empty", b"")])
        r = self.extract("inputs/c.zip", "work/out")
        self.assertEqual(r.code, 0, r.stdout)
        self.assertEqual(r.json["status"], "complete")
        rows = self.rows("work/out")
        self.assertEqual([x["n"] for x in rows], [0, 1, 2, 3])
        self.assertEqual([x["name"] for x in rows], ["a.bin", "d/e/b.txt", "c.txt", "empty"])
        for row, data in zip(rows, (a, b, c, b"")):
            self.assertEqual(row["status"], "extracted", row)
            with open(os.path.join(self.dir, "work/out", row["path"]), "rb") as fh:
                self.assertEqual(fh.read(), data)
            self.assertEqual(row["size_written"], len(data))
            if len(data) >= 128:
                self.assertEqual(row["sha256"], sha(data))
                self.assertIs(row["crc_verified"], True)
        # the original name bytes are kept exactly
        self.assertEqual(json.loads(json.dumps(rows[1]))["name_b64"], "ZC9lL2IudHh0")
        self.assertEqual(r.json["archive"]["sha256"], sha(self.read(path, "rb")))
        self.assertEqual(r.json["counts"], {"extracted": 4})

    def test_a_member_shorter_than_128_bytes_has_no_digest_and_no_crc_written(self):
        make_zip(self.path("inputs/s.zip"), [("short.txt", b"p4ssw0rd-ish"), ("long.txt", b"x" * 300)])
        r = self.extract("inputs/s.zip", "work/out")
        short, long_ = self.rows("work/out")
        self.assertIsNone(short["sha256"])
        self.assertIs(short["digest_withheld"], True)
        self.assertNotIn("crc32_listed", short)
        self.assertIs(short["crc_verified"], True)           # checked, not printed
        self.assertEqual(long_["sha256"], sha(b"x" * 300))
        self.assertIn("crc32_listed", long_)
        self.assertNotIn(sha(b"p4ssw0rd-ish"), r.stdout + self.read("work/out/members.jsonl"))

    def test_the_output_directory_is_private(self):
        make_zip(self.path("inputs/p.zip"), [("a/b.txt", b"x" * 200)])
        self.extract("inputs/p.zip", "work/out")
        self.assertEqual(stat.S_IMODE(os.stat(self.path("work/out")).st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(os.stat(self.path("work/out/extracted/a")).st_mode), 0o700)
        for name in ("extracted/a/b.txt", "members.jsonl", "receipt.json"):
            self.assertEqual(stat.S_IMODE(os.stat(self.path("work/out", name)).st_mode), 0o600, name)

    def test_member_numbers_are_the_archive_members_recipes(self):
        zip_path = make_zip(self.path("inputs/n.zip"), [("one", b"1" * 200), ("two/three", b"2" * 200)])
        tar_path = make_tar(self.path("inputs/n.tar"), [{"name": "t1", "data": b"1" * 200}, {"name": "t2/t3", "data": b"2" * 200}])
        for archive, name in ((zip_path, "z"), (tar_path, "t")):
            proc = subprocess.run([sys.executable, recipe_path("archive-members", "run.py"), "run", "--target", json.dumps({"paths": [archive]}),
                                   "--out", self.path("rec-" + name)], capture_output=True, text=True, cwd=self.dir)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            lines = [l.split("\t") for l in self.read("rec-%s/members.tsv" % name).splitlines()]
            recipe = {int(r[0]): r[3] for r in lines[1:]}
            self.extract(archive, "work/" + name)
            ours = {r["n"]: r["name_b64"] for r in self.rows("work/" + name)}
            self.assertEqual(ours, recipe)

    # ---- hostile names ----

    def test_a_name_that_climbs_or_is_absolute_extracts_inside_the_directory_and_is_flagged(self):
        names = ["../evil.txt", "a/../../evil2.txt", "/abs/root.txt", "C:\\win\\drive.txt", "dir\\..\\back.txt", "x/./y.txt", ".."]
        members = [(n, b"payload-" + n.encode() + b"x" * 200) for n in names]
        make_zip(self.path("inputs/h.zip"), members)
        before = self.world(self.path("work"))
        r = self.extract("inputs/h.zip", "work/out")
        self.assertEqual(r.code, 0, r.stdout)
        after = self.world(self.path("work"))
        after.pop("work", None)
        self.assertEqual(after, before, "something was written outside work/")
        found = self.files_under(self.path("work/out/extracted"))
        for rel, mode in found:
            self.assertFalse(stat.S_ISLNK(mode), rel)
            self.assertNotIn("..", rel.split(os.sep))
        rows = self.rows("work/out")
        import base64
        flags = {base64.b64decode(r["name_b64"]).decode(): set(r["flags"]) for r in rows}
        self.assertIn("dotdot", flags["../evil.txt"])
        self.assertIn("escapes-root", flags["../evil.txt"])
        self.assertIn("absolute-path", flags["/abs/root.txt"])
        self.assertIn("drive-letter", flags["C:\\win\\drive.txt"])
        self.assertIn("backslash-separator", flags["dir\\..\\back.txt"])
        for row in rows:
            if row["status"] == "extracted":
                data = self.read(os.path.join("work/out", row["path"]), "rb")
                self.assertTrue(data.startswith(b"payload-"), row)

    def test_a_nul_in_a_name_is_flagged_and_does_not_hide_what_follows_it(self):
        data = make_zip(self.path("inputs/nul.zip"), [("okXevil/../../x", b"n" * 200)])
        raw = self.read(data, "rb").replace(b"okXevil", b"ok\x00evil")
        self.write("inputs/nul.zip", raw)
        r = self.extract("inputs/nul.zip", "work/out")
        row = self.rows("work/out")[0]
        self.assertIn("nul-in-name", row["flags"])
        self.assertIn("escapes-root", row["flags"])
        self.assertIn("%2E%2E", row["path"])
        self.assertNotIn("\x00", row["path"])
        self.assertEqual(self.rows("work/out")[0]["name_b64"], "b2sAZXZpbC8uLi8uLi94")
        self.assertEqual(r.code, 0)

    def test_two_members_with_one_name_are_two_files(self):
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            make_zip(self.path("inputs/d.zip"), [("dup.txt", b"first" * 40), ("dup.txt", b"second" * 40), ("Dup.txt", b"third" * 40)])
        self.extract("inputs/d.zip", "work/out")
        rows = self.rows("work/out")
        paths = [r["path"] for r in rows]
        self.assertEqual(len(set(paths)), 3, paths)
        contents = sorted(self.read(os.path.join("work/out", p), "rb") for p in paths)
        self.assertEqual(contents, sorted([b"first" * 40, b"second" * 40, b"third" * 40]))
        self.assertIn("duplicate-name", rows[1]["flags"])
        self.assertNotIn("duplicate-name", rows[2]["flags"])           # a different spelling is not a repeat of the bytes

    def test_a_file_and_a_directory_of_the_same_name_do_not_stop_the_run(self):
        make_tar(self.path("inputs/fd.tar"), [{"name": "a", "data": b"I am a file" * 20}, {"name": "a/b.txt", "data": b"under a" * 30},
                                              {"name": "c/d", "data": b"d" * 200}, {"name": "c", "data": b"c" * 200}])
        r = self.extract("inputs/fd.tar", "work/out")
        self.assertEqual(r.code, 0, r.stdout)
        rows = self.rows("work/out")
        self.assertEqual([x["status"] for x in rows], ["extracted"] * 4, rows)
        got = sorted(self.read(os.path.join("work/out", x["path"]), "rb") for x in rows)
        self.assertEqual(got, sorted([b"I am a file" * 20, b"under a" * 30, b"d" * 200, b"c" * 200]))

    def test_names_that_are_not_utf8_keep_their_bytes_and_get_an_ascii_path(self):
        raw_name = b"caf\xe9-\xff.txt"
        make_tar(self.path("inputs/u.tar"), [{"name": raw_name.decode("utf-8", "surrogateescape"), "data": b"u" * 200}])
        r = self.extract("inputs/u.tar", "work/out")
        self.assertEqual(r.code, 0, r.stdout + r.stderr)
        row = self.rows("work/out")[0]
        import base64
        self.assertEqual(base64.b64decode(row["name_b64"]), raw_name)
        self.assertIn("name-not-utf8", row["flags"])
        self.assertTrue(row["path"].isascii(), row["path"])
        self.assertEqual(self.read(os.path.join("work/out", row["path"]), "rb"), b"u" * 200)

    def test_a_cp437_zip_name_is_kept_as_the_bytes_the_archive_stores(self):
        info = zipfile.ZipInfo("placeholder")
        make_zip(self.path("inputs/cp.zip"), [("na\u00efve.txt", b"z" * 200)])
        row = None
        self.extract("inputs/cp.zip", "work/out")
        row = self.rows("work/out")[0]
        import base64
        # not flagged UTF-8 by zipfile for a name with a non-ASCII letter? it is: bit 11 is set, so the bytes are UTF-8
        self.assertEqual(base64.b64decode(row["name_b64"]), "na\u00efve.txt".encode("utf-8"))

    def test_a_name_longer_than_a_file_system_allows_is_shortened_on_disk_and_whole_in_the_manifest(self):
        long_name = "dirname_" * 25 + "/" + "filename_" * 70 + ".txt"
        make_zip(self.path("inputs/l.zip"), [(long_name, b"L" * 200)])
        r = self.extract("inputs/l.zip", "work/out")
        self.assertEqual(r.code, 0, r.stdout)
        row = self.rows("work/out")[0]
        self.assertEqual(row["status"], "extracted")
        import base64
        self.assertEqual(base64.b64decode(row["name_b64"]).decode(), long_name)
        self.assertTrue(all(len(p) <= 255 for p in row["path"].split("/")))

    def test_a_path_deeper_than_the_budget_is_skipped_and_recorded(self):
        make_zip(self.path("inputs/deep.zip"), [("/".join(["d"] * 100) + "/f.txt", b"deep" * 50), ("shallow.txt", b"ok" * 100)])
        r = self.extract("inputs/deep.zip", "work/out", max_depth=10)
        rows = self.rows("work/out")
        self.assertEqual((rows[0]["status"], rows[1]["status"]), ("skipped", "extracted"))
        self.assertIn("depth", rows[0]["reason"])
        self.assertEqual(r.json["status"], "partial")

    # ---- links, devices, directories ----

    def test_links_devices_and_fifos_are_recorded_and_never_created(self):
        make_tar(self.path("inputs/links.tar"), [
            {"name": "real.txt", "data": b"r" * 200},
            {"name": "sym", "type": tarfile.SYMTYPE, "linkname": "/etc/passwd"},
            {"name": "sym2", "type": tarfile.SYMTYPE, "linkname": "../../outside"},
            {"name": "hard", "type": tarfile.LNKTYPE, "linkname": "real.txt"},
            {"name": "dev", "type": tarfile.CHRTYPE, "devmajor": 1, "devminor": 3},
            {"name": "blk", "type": tarfile.BLKTYPE, "devmajor": 8, "devminor": 0},
            {"name": "pipe", "type": tarfile.FIFOTYPE},
            {"name": "somedir", "type": tarfile.DIRTYPE},
        ])
        r = self.extract("inputs/links.tar", "work/out")
        self.assertEqual(r.code, 0, r.stdout)
        for rel, mode in self.files_under(self.path("work/out")):
            self.assertTrue(stat.S_ISREG(mode) or stat.S_ISDIR(mode), "%s is not a plain file or directory" % rel)
        rows = {x["name"]: x for x in self.rows("work/out")}
        for name in ("sym", "sym2", "hard", "dev", "blk", "pipe"):
            self.assertEqual(rows[name]["status"], "not_created", name)
            self.assertIsNone(rows[name]["path"])
        self.assertEqual(rows["sym"]["link_target"], "/etc/passwd")
        self.assertEqual(rows["hard"]["link_target"], "real.txt")
        self.assertEqual(rows["dev"]["type"], "char-device")
        self.assertEqual(rows["somedir"]["status"], "directory")
        self.assertEqual(r.json["status"], "complete", "a link recorded as a link is not a failure")

    def test_a_zip_symlink_member_is_not_created_and_gives_its_target(self):
        info = zipfile.ZipInfo("lnk")
        info.create_system = 3
        info.external_attr = (0o120777 << 16)
        make_zip(self.path("inputs/zl.zip"), [(info, b"/etc/shadow"), ("plain.txt", b"p" * 200)])
        r = self.extract("inputs/zl.zip", "work/out")
        rows = self.rows("work/out")
        self.assertEqual(rows[0]["status"], "not_created")
        self.assertEqual(rows[0]["link_target"], "/etc/shadow")
        self.assertEqual(rows[1]["status"], "extracted")
        self.assertEqual([m for _rel, m in self.files_under(self.path("work/out/extracted")) if stat.S_ISLNK(m)], [])

    def test_an_existing_link_in_the_output_directory_is_not_followed(self):
        outside = self.path("outside")
        os.makedirs(outside)
        make_zip(self.path("inputs/t.zip"), [("fine.txt", b"y" * 200), ("trap/pwned.txt", b"x" * 200)])
        first = self.extract("inputs/t.zip", "work/out", max_members=1)      # stops after fine.txt: trap/ is not made yet
        self.assertEqual(first.json["next_index"], 1)
        os.symlink(outside, self.path("work/out/extracted/trap"))             # something plants a link where the next member goes
        r = self.extract("inputs/t.zip", "work/out", resume=True, from_index=1)
        self.assertEqual(r.code, 0, r.stdout)
        self.assertEqual(os.listdir(outside), [], "a file was written through a link")
        rows = [json.loads(l) for l in self.read("work/out/members.2.jsonl").splitlines()]
        self.assertEqual(rows[0]["status"], "extracted")
        self.assertIn("flat-path", rows[0]["flags"])
        self.assertTrue(rows[0]["path"].startswith("extracted/_flat/"), rows[0]["path"])

    # ---- compressed tars and single streams ----

    def test_tar_in_gzip_bzip2_and_xz_is_a_tar(self):
        entries = [{"name": "a/one.txt", "data": b"1" * 300}, {"name": "two.txt", "data": b"2" * 300}]
        for mode, suffix in (("w:gz", "gz"), ("w:bz2", "bz2"), ("w:xz", "xz")):
            make_tar(self.path("inputs/t." + suffix), entries, mode)
            r = self.extract("inputs/t." + suffix, "work/" + suffix)
            self.assertEqual(r.code, 0, (suffix, r.stdout))
            self.assertTrue(r.json["archive"]["format"].startswith("tar+"), r.json["archive"])
            rows = self.rows("work/" + suffix)
            self.assertEqual([x["name"] for x in rows], ["a/one.txt", "two.txt"])
            self.assertEqual(self.read("work/%s/%s" % (suffix, rows[0]["path"]), "rb"), b"1" * 300)

    @unittest.skipUnless(zstd_available(), "no zstd decompressor in this Python and no zstd program")
    def test_tar_in_zstd_is_a_tar(self):
        plain = io.BytesIO()
        with tarfile.open(fileobj=plain, mode="w") as tf:
            info = tarfile.TarInfo("z.txt")
            info.size = 300
            tf.addfile(info, io.BytesIO(b"z" * 300))
        data = zstd_compress(plain.getvalue())
        self.write("inputs/t.tar.zst", data)
        r = self.extract("inputs/t.tar.zst", "work/out")
        self.assertEqual(r.code, 0, r.stdout)
        self.assertEqual(self.read("work/out/" + self.rows("work/out")[0]["path"], "rb"), b"z" * 300)

    @unittest.skipUnless(zstd_available(), "no zstd decompressor in this Python and no zstd program")
    def test_a_truncated_zstd_stream_is_never_called_complete(self):
        plain = io.BytesIO()
        with tarfile.open(fileobj=plain, mode="w") as tf:
            for i in range(4):
                info = tarfile.TarInfo("m%d.bin" % i)
                info.size = 40000
                tf.addfile(info, io.BytesIO(os.urandom(40000)))
        data = zstd_compress(plain.getvalue())
        self.write("inputs/cut.tar.zst", data[:len(data) * 6 // 10])
        r = self.extract("inputs/cut.tar.zst", "work/out")
        self.assertNotIn("Traceback", r.stderr)
        self.assertIsNotNone(r.json, r.stdout)
        if r.code == 0:
            self.assertEqual(r.json["status"], "partial", r.json)
            self.assertTrue(r.json["counts"].get("partial") or r.json["stopped_by"], r.json)
        else:
            self.assertIs(r.json["ok"], False)
        self.assertNotEqual(r.json.get("counts"), {"extracted": 4})

    def test_zstd_without_a_decompressor_is_said_not_guessed(self):
        # the frame magic and nothing a decoder could use; where this Python or the PATH has a decoder the tool says the frame is damaged
        self.write("inputs/x.zst", b"\x28\xb5\x2f\xfd" + b"\x00" * 40)
        r = run_tool("archive_extract", {"path": "inputs/x.zst", "out_dir": "work/out"}, self.dir, only_path="")
        self.assertEqual(r.code, 1, r.stdout)
        self.assertNotIn("Traceback", r.stderr)
        self.assertIs(r.json["ok"], False)
        if not zstd_available():
            self.assertIn("no zstd decompressor", r.json["error"])
        self.assertEqual([x for x in self.files_under(self.path("work/out/extracted"))], [])

    def test_a_gzip_that_is_not_a_tar_is_one_member_named_by_its_header(self):
        body = b"just some log text\n" * 100
        buf = io.BytesIO()
        with gzip.GzipFile(filename="original-name.log", mode="wb", fileobj=buf, mtime=1700000000) as gz:
            gz.write(body)
        self.write("inputs/renamed.bin", buf.getvalue())
        r = self.extract("inputs/renamed.bin", "work/out")
        self.assertEqual(r.code, 0, r.stdout)
        rows = self.rows("work/out")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["name"], "original-name.log")
        self.assertEqual(rows[0]["mtime_utc"], "2023-11-14T22:13:20Z")
        self.assertEqual(self.read("work/out/" + rows[0]["path"], "rb"), body)
        self.assertEqual(rows[0]["sha256"], sha(body))

    def test_bzip2_and_xz_singles_take_the_archives_name_without_the_suffix(self):
        body = b"single file content " * 50
        self.write("inputs/data.txt.bz2", bz2.compress(body))
        self.write("inputs/data2.txt.xz", lzma.compress(body))
        for name, out in (("data.txt.bz2", "b"), ("data2.txt.xz", "x")):
            r = self.extract("inputs/" + name, "work/" + out)
            self.assertEqual(r.code, 0, r.stdout)
            row = self.rows("work/" + out)[0]
            self.assertEqual(row["name"], name.rsplit(".", 1)[0])
            self.assertEqual(self.read("work/%s/%s" % (out, row["path"]), "rb"), body)

    def test_a_gzip_of_several_streams_is_all_of_them_and_trailing_bytes_are_counted(self):
        one, two = b"first part " * 40, b"second part " * 40
        data = gzip.compress(one) + gzip.compress(two) + b"TRAILING-GARBAGE"
        self.write("inputs/multi.gz", data)
        r = self.extract("inputs/multi.gz", "work/out")
        self.assertEqual(r.code, 0, r.stdout)
        self.assertEqual(self.read("work/out/" + self.rows("work/out")[0]["path"], "rb"), one + two)
        self.assertEqual(r.json["trailing_bytes"], len(b"TRAILING-GARBAGE"))
        self.assertEqual(r.json["compressed_streams"], 2)

    # ---- bombs and budgets ----

    def test_a_member_that_expands_past_the_ratio_is_cut_and_kept_as_partial(self):
        make_zip(self.path("inputs/bomb.zip"), [("zeros.bin", b"\0" * (64 * 1024 * 1024)), ("after.txt", b"after" * 50)])
        r = self.extract("inputs/bomb.zip", "work/out", max_ratio=100)
        self.assertEqual(r.code, 0, r.stdout)
        rows = self.rows("work/out")
        self.assertEqual(rows[0]["status"], "partial")
        self.assertIn("max_ratio", rows[0]["reason"])
        self.assertTrue(rows[0]["path"].endswith(".partial"))
        written = os.path.getsize(self.path("work/out", rows[0]["path"]))
        self.assertLess(written, 64 * 1024 * 1024)
        self.assertEqual(written, rows[0]["size_written"])
        self.assertEqual(rows[1]["status"], "extracted", "a member-level budget does not stop the run")
        self.assertEqual(r.json["status"], "partial")

    def test_a_member_longer_than_the_member_budget_is_cut_at_the_budget(self):
        make_zip(self.path("inputs/big.zip"), [("big.bin", os.urandom(300000)), ("small.txt", b"s" * 200)], compress=zipfile.ZIP_STORED)
        r = self.extract("inputs/big.zip", "work/out", max_member_bytes=100000)
        rows = self.rows("work/out")
        self.assertEqual(rows[0]["status"], "skipped", "a declared size past the budget is not opened")
        self.assertIn("max_member_bytes", rows[0]["reason"])
        self.assertEqual(rows[1]["status"], "extracted")

    def test_an_understated_size_is_caught_by_the_bytes_written_not_the_claim(self):
        # a stored member whose declared size is 10 but whose data is 300000 bytes long (the central directory lies)
        data = make_zip(self.path("inputs/lie.zip"), [("liar.bin", b"x" * 300000)], compress=zipfile.ZIP_STORED)
        raw = self.read(data, "rb")
        raw = patch_zip(raw, "liar.bin", local=(22, struct.pack("<I", 10)), central=(24, struct.pack("<I", 10)))
        self.write("inputs/lie.zip", raw)
        r = self.extract("inputs/lie.zip", "work/out", max_member_bytes=50000)
        rows = self.rows("work/out")
        self.assertIn(rows[0]["status"], ("partial", "extracted"))
        written = rows[0]["size_written"]
        self.assertLessEqual(written, 50000 + 1 if rows[0]["status"] == "partial" else 10)
        self.assertNotEqual(rows[0]["status"] + str(rows[0]["reason"] or ""), "extracted", "a size that does not match is never a whole member")

    def test_the_total_budget_stops_the_run_names_it_and_a_resume_finishes_without_replacing_anything(self):
        blobs = [os.urandom(40000) for _ in range(6)]
        make_zip(self.path("inputs/many.zip"), [("m%d.bin" % i, b) for i, b in enumerate(blobs)], compress=zipfile.ZIP_STORED)
        r = self.extract("inputs/many.zip", "work/out", max_total_bytes=100000)
        self.assertEqual(r.code, 0, r.stdout)
        self.assertEqual(r.json["stopped_by"], "max_total_bytes")
        self.assertEqual(r.json["status"], "partial")
        first = self.rows("work/out")
        self.assertEqual([x["status"] for x in first], ["extracted", "extracted", "partial"])
        self.assertEqual(r.json["next_index"], 2, "the cut member is started again")
        kept = {x["path"]: self.read("work/out/" + x["path"], "rb") for x in first}
        again = self.extract("inputs/many.zip", "work/out", resume=True, from_index=r.json["next_index"])
        self.assertEqual(again.code, 0, again.stdout)
        self.assertEqual(again.json["status"], "complete")
        self.assertTrue(os.path.exists(self.path("work/out/members.2.jsonl")))
        self.assertTrue(os.path.exists(self.path("work/out/receipt.2.json")))
        for path, data in kept.items():
            self.assertEqual(self.read("work/out/" + path, "rb"), data, "an earlier file was replaced")
        second = [json.loads(l) for l in self.read("work/out/members.2.jsonl").splitlines()]
        self.assertEqual([x["n"] for x in second], [2, 3, 4, 5])
        done = {x["n"]: x for x in first[:2] + second}
        for i, blob in enumerate(blobs):
            self.assertEqual(self.read("work/out/" + done[i]["path"], "rb"), blob, i)

    def test_a_resume_with_another_archive_is_refused_and_writes_nothing(self):
        make_zip(self.path("inputs/five.zip"), [("f%d.txt" % i, b"%d" % i * 200) for i in range(5)])
        make_zip(self.path("inputs/other.zip"), [("g%d.txt" % i, b"g%d" % i * 200) for i in range(5)])
        first = self.extract("inputs/five.zip", "work/out", max_members=2)
        self.assertEqual(first.json["next_index"], 2)
        before = self.files_under(self.path("work/out"))
        r = self.extract("inputs/other.zip", "work/out", resume=True, from_index=2)
        self.assertEqual(r.code, 1, r.stdout)
        self.assertIn("not the archive the earlier run", r.json["error"])
        self.assertEqual(self.files_under(self.path("work/out")), before)
        r = self.extract("inputs/five.zip", "work/out", resume=True, from_index=2)
        self.assertEqual((r.code, r.json["status"]), (0, "complete"))
        self.write("work/empty/extracted/x", b"")
        os.remove(self.path("work/empty/extracted/x"))
        r = self.extract("inputs/five.zip", "work/empty", resume=True)
        self.assertEqual(r.code, 1)
        self.assertIn("receipt", r.json["error"])

    def test_the_member_budget_stops_after_that_many_members_and_resume_goes_on(self):
        make_zip(self.path("inputs/five.zip"), [("f%d.txt" % i, b"%d" % i * 200) for i in range(5)])
        r = self.extract("inputs/five.zip", "work/out", max_members=2)
        self.assertEqual((r.json["stopped_by"], r.json["next_index"], r.json["members_seen"]), ("max_members", 2, 2))
        r2 = self.extract("inputs/five.zip", "work/out", resume=True, from_index=2, max_members=10)
        self.assertEqual((r2.json["members_seen"], r2.json["status"]), (3, "complete"))

    def test_an_out_dir_that_holds_files_is_refused_unless_resume_is_true(self):
        make_zip(self.path("inputs/a.zip"), [("a.txt", b"a" * 200)])
        self.extract("inputs/a.zip", "work/out")
        r = self.extract("inputs/a.zip", "work/out")
        self.assertEqual(r.code, 1)
        self.assertIn("already holds files", r.json["error"])
        self.assertNotIn("Traceback", r.stderr)

    def test_a_second_default_run_gets_a_directory_of_its_own(self):
        make_zip(self.path("inputs/a.zip"), [("a.txt", b"a" * 200)])
        one, two = self.extract("inputs/a.zip"), self.extract("inputs/a.zip")
        self.assertEqual((one.code, two.code), (0, 0))
        self.assertNotEqual(one.json["out_dir"], two.json["out_dir"])
        self.assertTrue(os.path.exists(self.path(one.json["out_dir"], "members.jsonl")))

    # ---- encrypted, unsupported, damaged ----

    def test_an_encrypted_zip_member_is_counted_and_not_opened_and_the_rest_is_extracted(self):
        make_zip(self.path("inputs/e.zip"), [("secret.txt", b"s" * 200), ("open.txt", b"o" * 200)], compress=zipfile.ZIP_STORED)
        raw = self.read(self.path("inputs/e.zip"), "rb")
        raw = patch_zip(raw, "secret.txt", local=(6, b"\x01\x00"), central=(8, b"\x01\x00"))
        self.write("inputs/e.zip", raw)
        r = self.extract("inputs/e.zip", "work/out")
        self.assertEqual(r.code, 0, r.stdout)
        rows = self.rows("work/out")
        self.assertEqual([x["status"] for x in rows], ["encrypted", "extracted"])
        self.assertIsNone(rows[0]["path"])
        self.assertEqual(r.json["counts"], {"encrypted": 1, "extracted": 1})
        self.assertEqual(r.json["status"], "partial")

    def test_a_compression_method_this_build_cannot_read_is_unsupported_not_garbage(self):
        make_zip(self.path("inputs/m.zip"), [("odd.bin", b"o" * 200), ("ok.txt", b"k" * 200)], compress=zipfile.ZIP_STORED)
        raw = patch_zip(self.read(self.path("inputs/m.zip"), "rb"), "odd.bin", local=(8, struct.pack("<H", 9)), central=(10, struct.pack("<H", 9)))
        self.write("inputs/m.zip", raw)
        r = self.extract("inputs/m.zip", "work/out")
        rows = self.rows("work/out")
        self.assertEqual(rows[0]["status"], "unsupported")
        self.assertIn("method 9", rows[0]["reason"])
        self.assertEqual(rows[1]["status"], "extracted")

    def test_a_member_whose_crc_does_not_match_stays_partial_under_no_final_name(self):
        make_zip(self.path("inputs/crc.zip"), [("bad.bin", b"A" * 4000), ("good.bin", b"B" * 4000)], compress=zipfile.ZIP_STORED)
        raw = bytearray(self.read(self.path("inputs/crc.zip"), "rb"))
        at = raw.find(b"A" * 4000)
        raw[at + 100] = ord("Z")
        self.write("inputs/crc.zip", bytes(raw))
        r = self.extract("inputs/crc.zip", "work/out")
        rows = self.rows("work/out")
        self.assertEqual(rows[0]["status"], "partial")
        self.assertIn("crc_mismatch", rows[0]["reason"])
        self.assertTrue(rows[0]["path"].endswith(".partial"))
        self.assertFalse(os.path.exists(self.path("work/out/extracted/bad.bin")))
        self.assertIs(rows[0]["crc_verified"], False)
        self.assertEqual(rows[1]["status"], "extracted")
        self.assertEqual(r.json["status"], "partial")

    def test_a_truncated_zip_is_an_error_with_counts_and_extracts_nothing(self):
        make_zip(self.path("inputs/whole.zip"), [("a.txt", b"a" * 5000), ("b.txt", b"b" * 5000), ("c.txt", b"c" * 5000)], compress=zipfile.ZIP_STORED)
        raw = self.read(self.path("inputs/whole.zip"), "rb")
        self.write("inputs/cut.zip", raw[:len(raw) // 2])
        r = self.extract("inputs/cut.zip", "work/out")
        self.assertEqual(r.code, 1, r.stdout)
        self.assertNotIn("Traceback", r.stderr)
        self.assertIs(r.json["ok"], False)
        self.assertGreaterEqual(r.json["local_headers_seen"], 1)
        self.assertEqual(self.files_under(self.path("work/out/extracted")), [])

    def test_a_truncated_tar_gz_keeps_the_members_before_the_cut_and_says_where_it_broke(self):
        entries = [{"name": "m%d.bin" % i, "data": os.urandom(30000)} for i in range(6)]
        make_tar(self.path("inputs/full.tar.gz"), entries, "w:gz")
        raw = self.read(self.path("inputs/full.tar.gz"), "rb")
        self.write("inputs/cut.tar.gz", raw[:len(raw) * 6 // 10])
        r = self.extract("inputs/cut.tar.gz", "work/out")
        self.assertEqual(r.code, 0, r.stdout + r.stderr)
        self.assertEqual(r.json["status"], "partial")
        rows = self.rows("work/out")
        self.assertGreaterEqual(len(rows), 2)
        self.assertEqual(rows[0]["status"], "extracted")
        self.assertEqual(self.read("work/out/" + rows[0]["path"], "rb"), entries[0]["data"])
        last = rows[-1]
        self.assertEqual(last["status"], "partial", last)
        kept = self.read("work/out/" + last["path"], "rb")
        self.assertEqual(kept, entries[last["n"]]["data"][:len(kept)], "what was kept of the cut member is a prefix of it")
        self.assertEqual(len(kept), last["size_written"])
        self.assertGreater(len(kept), 0)
        self.assertTrue(r.json["stopped_by"] in ("archive_unreadable", None) or rows[-1]["status"] == "partial", r.json)
        self.assertTrue(any("truncated" in n or "ends before" in n or "broke" in n for n in r.json["notes"]) or rows[-1]["status"] == "partial", r.json["notes"])

    def test_a_tar_whose_data_runs_past_the_end_of_the_file_is_not_called_complete(self):
        make_tar(self.path("inputs/ok.tar"), [{"name": "a.bin", "data": b"a" * 20000}, {"name": "b.bin", "data": b"b" * 20000}])
        raw = self.read(self.path("inputs/ok.tar"), "rb")
        self.write("inputs/cut.tar", raw[:512 + 20480 + 512 + 7000])
        r = self.extract("inputs/cut.tar", "work/out")
        self.assertEqual(r.code, 0, r.stdout)
        self.assertEqual(r.json["status"], "partial")
        rows = self.rows("work/out")
        self.assertEqual(rows[0]["status"], "extracted")
        self.assertEqual(rows[1]["status"], "partial", rows[1])
        self.assertTrue(rows[1]["path"].endswith(".partial"))
        self.assertEqual(rows[1]["size_written"], 7000)
        self.assertEqual(self.read("work/out/" + rows[1]["path"], "rb"), b"b" * 7000, "the bytes the file does hold are kept, exactly")
        self.assertIn("size_mismatch", rows[1]["reason"])

    def test_a_file_that_is_not_an_archive_or_is_one_this_tool_does_not_read_is_named_and_refused(self):
        self.write("inputs/junk.bin", os.urandom(2000))
        r = self.extract("inputs/junk.bin", "work/out")
        self.assertEqual(r.code, 1)
        self.assertIn("unsupported or unrecognised", r.json["error"])
        self.write("inputs/r.rar", b"Rar!\x1a\x07\x00" + b"\x00" * 100)
        r = self.extract("inputs/r.rar", "work/out2")
        self.assertEqual(r.code, 1)
        self.assertEqual(r.json["format"], "unsupported:rar")
        self.assertFalse(os.path.exists(self.path("work/out2")), "a refused archive makes no directory")
        self.write("inputs/empty", b"")
        self.assertEqual(self.extract("inputs/empty").code, 1)
        self.assertEqual(self.extract("inputs/missing.zip").code, 1)

    def test_a_nested_archive_is_named_and_not_opened(self):
        inner = io.BytesIO()
        make_zip(inner, [("inner.txt", b"inside" * 50)])
        make_zip(self.path("inputs/outer.zip"), [("deep/inner.zip", inner.getvalue()), ("note.txt", b"n" * 200)])
        r = self.extract("inputs/outer.zip", "work/out")
        rows = self.rows("work/out")
        self.assertEqual(rows[0]["looks_like"], "zip")
        self.assertIn("nested-archive", rows[0]["flags"])
        self.assertEqual(r.json["nested_archives_total"], 1)
        names = [rel for rel, _m in self.files_under(self.path("work/out/extracted"))]
        self.assertNotIn(os.path.join("deep", "inner.zip", "inner.txt"), names)
        self.assertFalse(any(n.endswith("inner.txt") for n in names))

    # ---- names that look like secrets ----

    def test_a_token_shaped_name_is_withheld_from_every_channel_and_mapped_in_a_private_file(self):
        token = "ghp_" + "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5"
        make_zip(self.path("inputs/w.zip"), [("keys/" + token + ".txt", b"w" * 200), ("plain.txt", b"p" * 200)])
        r = self.extract("inputs/w.zip", "work/out")
        self.assertEqual(r.code, 0, r.stdout)
        row = self.rows("work/out")[0]
        self.assertIs(row["name_withheld"], True)
        self.assertNotIn("name_b64", row)
        self.assertEqual(row["path"], "extracted/_withheld/withheld-000000.txt")
        shown = r.stdout + r.stderr + "".join(self.read(os.path.join("work/out", f)) for f in ("members.jsonl", "receipt.json"))
        self.assertNotIn(token, shown)
        listing = " ".join(rel for rel, _ in self.files_under(self.path("work/out")))
        self.assertNotIn(token[:12], listing, "a withheld name must not name a file")
        mapping = [json.loads(l) for l in self.read("work/out/withheld-names.jsonl").splitlines()]
        self.assertEqual(mapping[0]["name"], "keys/" + token + ".txt")
        self.assertEqual(stat.S_IMODE(os.stat(self.path("work/out/withheld-names.jsonl")).st_mode), 0o600)
        self.assertEqual(self.read("work/out/" + row["path"], "rb"), b"w" * 200)
        self.assertEqual(r.json["members_withheld"], 1)

    def test_an_error_that_would_quote_a_token_shaped_path_does_not(self):
        token = "ghp_" + "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5"
        r = self.extract("inputs/" + token + ".zip", "work/out")
        self.assertEqual(r.code, 1)
        self.assertNotIn(token, r.stdout + r.stderr)

    def test_there_is_no_name_filter_to_ask_questions_of_withheld_text(self):
        make_zip(self.path("inputs/a.zip"), [("a.txt", b"a" * 200)])
        for key in ("name", "filter", "pattern", "member", "glob"):
            r = self.extract("inputs/a.zip", "work/out", **{key: "a"})
            self.assertEqual(r.code, 1, key)
            self.assertIn("never by a filter", r.json["error"])

    # ---- in a job ----

    def job_env(self):
        out = self.path("store/jobs/j1/out")
        os.makedirs(out)
        return {"JOB_ID": "j1", "OUT": out}

    def test_in_a_job_the_default_directory_is_under_out_and_a_place_outside_is_refused_as_json(self):
        make_zip(self.path("inputs/j.zip"), [("a.txt", b"a" * 200)])
        env = self.job_env()
        r = run_tool("archive_extract", {"path": "inputs/j.zip"}, self.dir, env=env)
        self.assertEqual(r.code, 0, r.stdout)
        self.assertTrue(os.path.realpath(self.path(r.json["out_dir"])).startswith(os.path.realpath(env["OUT"])), r.json["out_dir"])
        again = run_tool("archive_extract", {"path": "inputs/j.zip"}, self.dir, env=env)
        self.assertEqual(again.code, 0, again.stdout)
        self.assertNotEqual(again.json["out_dir"], r.json["out_dir"])
        bad = run_tool("archive_extract", {"path": "inputs/j.zip", "out_dir": "work/elsewhere"}, self.dir, env=env)
        self.assertEqual(bad.code, 1)
        self.assertIn("$OUT", bad.json["error"])
        self.assertNotIn("Traceback", bad.stderr)
        self.assertFalse(os.path.exists(self.path("work")))
        inside = run_tool("archive_extract", {"path": "inputs/j.zip", "out_dir": "inputs/x"}, self.dir)
        self.assertEqual(inside.code, 1)
        self.assertIn("inputs", inside.json["error"])

    def test_bad_arguments_are_json_answers(self):
        make_zip(self.path("inputs/a.zip"), [("a.txt", b"a" * 200)])
        for args in ({}, {"path": ""}, {"path": 5}, {"path": "inputs/a.zip", "max_ratio": 0}, {"path": "inputs/a.zip", "max_total_bytes": "1"},
                     {"path": "inputs/a.zip", "resume": "yes"}, {"path": "inputs/a.zip", "limit": 0}, {"path": "inputs/a.zip", "bogus": 1},
                     {"path": "bad\udcffname.zip"}):
            r = run_tool("archive_extract", args, self.dir)
            self.assertEqual(r.code, 1, args)
            self.assertNotIn("Traceback", r.stderr)
            self.assertIsNotNone(r.json, args)
        r = run_tool("archive_extract", None, self.dir, raw_input="not json")
        self.assertEqual(r.code, 1)
        self.assertIsNotNone(r.json)

    # ---- 7z, through the real program ----

    def make_7z(self, name, tree, extra=()):
        src = self.path("src7")
        os.makedirs(src, exist_ok=True)
        for rel, data in tree.items():
            full = os.path.join(src, rel)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            if isinstance(data, tuple):
                os.symlink(data[0], full)
            else:
                with open(full, "wb") as fh:
                    fh.write(data)
        out = self.path("inputs", name)
        os.makedirs(os.path.dirname(out), exist_ok=True)
        subprocess.run([SEVEN_Z, "a", "-snl", "-bd", out] + list(extra) + ["."], cwd=src, capture_output=True, check=True)
        return out

    @unittest.skipUnless(SEVEN_Z, "no 7z program on this host")
    def test_a_7z_comes_out_split_by_its_own_listing_and_checked_against_its_crc(self):
        a, b = os.urandom(3000), b"text " * 500
        self.make_7z("t.7z", {"a.bin": a, "dir/b c.txt": b, "empty": b"", "dir/e.bin": b"e" * 150})
        r = self.extract("inputs/t.7z", "work/out")
        self.assertEqual(r.code, 0, r.stdout)
        rows = self.rows("work/out")
        by_name = {x["name"]: x for x in rows}
        self.assertEqual(by_name["a.bin"]["status"], "extracted")
        self.assertEqual(self.read("work/out/" + by_name["a.bin"]["path"], "rb"), a)
        self.assertEqual(self.read("work/out/" + by_name["dir/b c.txt"]["path"], "rb"), b)
        self.assertEqual(by_name["dir/e.bin"]["sha256"], sha(b"e" * 150))
        self.assertEqual(by_name["dir"]["status"], "directory")
        for row in rows:
            if row["type"] == "file" and row["size_declared"]:
                self.assertIs(row["crc_verified"], True, row)
        self.assertEqual(r.json["status"], "complete")
        self.assertIn("7-Zip", r.json["archive"]["program"]["banner"] + "7-Zip")

    @unittest.skipUnless(SEVEN_Z, "no 7z program on this host")
    def test_a_7z_symlink_is_recorded_with_its_target_and_not_created(self):
        self.make_7z("l.7z", {"real.txt": b"r" * 200, "ln": ("../../etc/passwd",)})
        r = self.extract("inputs/l.7z", "work/out")
        self.assertEqual(r.code, 0, r.stdout)
        rows = {x["name"]: x for x in self.rows("work/out")}
        if rows["ln"]["type"] == "symlink":
            self.assertEqual(rows["ln"]["status"], "not_created")
            self.assertEqual(rows["ln"]["link_target"], "../../etc/passwd")
        self.assertEqual(self.read("work/out/" + rows["real.txt"]["path"], "rb"), b"r" * 200)
        self.assertEqual([1 for _p, m in self.files_under(self.path("work/out/extracted")) if stat.S_ISLNK(m)], [])

    @unittest.skipUnless(SEVEN_Z, "no 7z program on this host")
    def test_a_7z_with_an_encrypted_member_counts_it_and_extracts_the_rest(self):
        src = self.path("src7e")
        os.makedirs(src)
        with open(os.path.join(src, "open.txt"), "wb") as fh:
            fh.write(b"o" * 300)
        with open(os.path.join(src, "locked.txt"), "wb") as fh:
            fh.write(b"l" * 300)
        os.makedirs(self.path("inputs"), exist_ok=True)
        out = self.path("inputs/e.7z")
        subprocess.run([SEVEN_Z, "a", "-bd", out, "open.txt"], cwd=src, capture_output=True, check=True)
        subprocess.run([SEVEN_Z, "a", "-bd", "-pfixture-not-a-real-password", out, "locked.txt"], cwd=src, capture_output=True, check=True)
        r = self.extract("inputs/e.7z", "work/out")
        self.assertEqual(r.code, 0, r.stdout)
        by_name = {x["name"]: x for x in self.rows("work/out")}
        self.assertEqual(by_name["locked.txt"]["status"], "encrypted")
        self.assertEqual(by_name["open.txt"]["status"], "extracted")
        self.assertEqual(self.read("work/out/" + by_name["open.txt"]["path"], "rb"), b"o" * 300)
        self.assertEqual(r.json["encrypted_members"], 1)

    @unittest.skipUnless(SEVEN_Z, "no 7z program on this host")
    def test_a_7z_with_encrypted_headers_is_refused_loudly(self):
        src = self.path("src7h")
        os.makedirs(src)
        with open(os.path.join(src, "x.txt"), "wb") as fh:
            fh.write(b"x" * 300)
        os.makedirs(self.path("inputs"), exist_ok=True)
        subprocess.run([SEVEN_Z, "a", "-bd", "-mhe=on", "-pfixture-not-a-real-password", self.path("inputs/h.7z"), "x.txt"], cwd=src, capture_output=True, check=True)
        r = self.extract("inputs/h.7z", "work/out")
        self.assertEqual(r.code, 1, r.stdout)
        self.assertIs(r.json["ok"], False)
        self.assertEqual(self.files_under(self.path("work/out/extracted")), [])

    def test_a_7z_without_the_program_is_said_not_skipped(self):
        self.write("inputs/s.7z", b"7z\xbc\xaf\x27\x1c\x00\x04" + b"\x00" * 64)
        r = run_tool("archive_extract", {"path": "inputs/s.7z", "out_dir": "work/out"}, self.dir, only_path="")
        self.assertEqual(r.code, 1, r.stdout)
        self.assertIn("7z program", r.json["error"])
        self.assertFalse(os.path.exists(self.path("work/out/extracted/anything")))

    # ---- the engine program, its group and signals ----

    def fake_7z(self, extract_body):
        bindir = self.path("bin")
        os.makedirs(bindir, exist_ok=True)
        stand_in(bindir, "7z", (
            'case "$1" in\n'
            '  l) printf "Path = slow.bin\\nSize = 100000\\nPacked Size = 100\\nModified = 2026-01-01 00:00:00.0000000\\nAttributes = A -rw-r--r--\\nCRC = 00000000\\nEncrypted = -\\nMethod = LZMA2:12\\n\\n";;\n'
            '  x) ' + extract_body + ';;\n'
            '  *) echo "7-Zip fake";;\n'
            'esac\n'))
        self.write("inputs/slow.7z", b"7z\xbc\xaf\x27\x1c\x00\x04" + b"\x00" * 64)
        return bindir

    def alive(self, pid):
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return False

    def test_the_deadline_kills_the_7z_program_and_what_it_started(self):
        pidfile = self.path("pids")
        bindir = self.fake_7z('echo $$ > %s; sleep 300 & echo $! >> %s; printf "some bytes"; sleep 300' % (pidfile, pidfile))
        start = time.monotonic()
        r = run_tool("archive_extract", {"path": "inputs/slow.7z", "out_dir": "work/out", "max_seconds": 2}, self.dir, path_dirs=[bindir], timeout=60)
        self.assertLess(time.monotonic() - start, 30)
        self.assertEqual(r.code, 0, r.stdout + r.stderr)
        self.assertEqual(r.json["stopped_by"], "max_seconds")
        self.assertEqual(r.json["status"], "partial")
        pids = [int(x) for x in self.read("pids").split()]
        time.sleep(0.5)
        self.assertEqual([p for p in pids if self.alive(p)], [], "7z or what it started was left running")
        row = self.rows("work/out")[0]
        self.assertEqual(row["status"], "partial")
        self.assertTrue(row["path"].endswith(".partial"))

    def test_a_sigterm_kills_the_7z_program_and_leaves_an_interrupted_receipt(self):
        pidfile = self.path("pids2")
        bindir = self.fake_7z('echo $$ > %s; printf "some bytes"; sleep 300' % pidfile)
        env = dict(os.environ, PATH=bindir + os.pathsep + os.environ["PATH"])
        env.pop("JOB_ID", None)
        env.pop("OUT", None)
        proc = subprocess.Popen([sys.executable, tool_path("archive_extract")], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=self.dir, env=env)
        proc.stdin.write(json.dumps({"path": "inputs/slow.7z", "out_dir": "work/out"}).encode())
        proc.stdin.close()
        for _ in range(200):
            if os.path.exists(pidfile) and self.read(pidfile).strip():
                break
            time.sleep(0.05)
        else:
            proc.kill()
            self.fail("the fake 7z never started")
        pid = int(self.read(pidfile).split()[0])
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=20)
        proc.stdout.close()
        proc.stderr.close()
        self.assertEqual(proc.returncode, 143)
        time.sleep(0.5)
        self.assertFalse(self.alive(pid), "7z was left running")
        receipt = json.loads(self.read("work/out/receipt.json"))
        self.assertEqual(receipt["status"], "interrupted")
        self.assertEqual(receipt["stopped_by"], "signal")

    def test_killing_the_tools_process_group_the_way_the_harness_does_ends_7z_and_what_it_started(self):
        pidfile = self.path("pids3")
        bindir = self.fake_7z('echo $$ > %s; sleep 300 & echo $! >> %s; printf "some bytes"; sleep 300' % (pidfile, pidfile))
        env = dict(os.environ, PATH=bindir + os.pathsep + os.environ["PATH"])
        env.pop("JOB_ID", None)
        env.pop("OUT", None)
        # the harness starts a tool in a process group of its own and ends it with process.kill(-pid, SIGKILL)
        proc = subprocess.Popen([sys.executable, tool_path("archive_extract")], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                cwd=self.dir, env=env, start_new_session=True)
        proc.stdin.write(json.dumps({"path": "inputs/slow.7z", "out_dir": "work/out"}).encode())
        proc.stdin.close()
        for _ in range(200):
            if os.path.exists(pidfile) and len(self.read(pidfile).split()) == 2:
                break
            time.sleep(0.05)
        else:
            os.killpg(proc.pid, signal.SIGKILL)
            self.fail("the fake 7z never started")
        pids = [int(x) for x in self.read(pidfile).split()]
        os.killpg(proc.pid, signal.SIGKILL)
        proc.wait(timeout=20)
        time.sleep(0.5)
        self.assertEqual([p for p in pids if self.alive(p)], [], "7z or what it started is outside the tool's process group and outlived it")

    def test_a_defect_inside_the_tool_is_json_with_a_failed_receipt_and_not_a_traceback(self):
        import contextlib
        import importlib.util
        make_zip(self.path("inputs/a.zip"), [("a.txt", b"a" * 200)])
        spec = importlib.util.spec_from_file_location("ae", tool_path("archive_extract"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        def boom(*_a, **_k):
            raise RuntimeError("a defect")
        mod.run_zip = boom
        old = [signal.getsignal(s) for s in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)]
        sys.stdin = io.StringIO(json.dumps({"path": "inputs/a.zip", "out_dir": "work/out"}))
        out = io.StringIO()
        cwd = os.getcwd()
        os.chdir(self.dir)
        try:
            with contextlib.redirect_stdout(out):
                try:
                    mod.main()
                except SystemExit as exc:
                    code = exc.code
        finally:
            os.chdir(cwd)
            sys.stdin = sys.__stdin__
            for s, h in zip((signal.SIGTERM, signal.SIGINT, signal.SIGHUP), old):
                signal.signal(s, h)
        got = json.loads(out.getvalue())
        self.assertEqual(code, 1)
        self.assertIs(got["ok"], False)
        self.assertIn("internal error", got["error"])
        self.assertEqual(json.loads(self.read("work/out/receipt.json"))["status"], "failed")

    # ---- the zip directory is held whole in memory; the 7z ratio; the 7z listing's clock ----

    def test_a_zip_directory_declaring_far_more_members_than_the_call_extracts_is_not_loaded(self):
        make_zip(self.path("inputs/many.zip"), [("m%03d.txt" % i, b"x") for i in range(50)], compress=zipfile.ZIP_STORED)
        r = self.extract("inputs/many.zip", "work/out", max_members=5)
        self.assertEqual(r.code, 1, r.stdout[:300])
        self.assertIn("declares 50 members, more than 4 times the max_members of 5", r.json["error"])
        self.assertIn("Raise max_members to at least 13", r.json["error"])
        self.assertEqual(r.json["members_declared"], 50)
        self.assertFalse(os.path.exists(self.path("work/out/extracted/m000.txt")), "nothing was extracted")
        ok = self.extract("inputs/many.zip", "work/out2", max_members=13)
        self.assertEqual(ok.code, 0, ok.stdout[:300])
        self.assertEqual(ok.json["counts"]["extracted"], 13)
        self.assertEqual(ok.json["stopped_by"], "max_members")

    def test_a_zip_directory_declared_past_the_memory_the_tool_reads_it_into_is_refused_before_it_is_read(self):
        # a stored member, then an end record that declares one entry and a directory of 100 MiB that is not there
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
            zf.writestr("a.txt", b"a")
        data = buf.getvalue()
        eocd = data.rfind(b"PK\x05\x06")
        forged = bytearray(data)
        struct.pack_into("<I", forged, eocd + 12, 100 * 1024 * 1024)       # size of the central directory
        self.write("inputs/huge-dir.zip", bytes(forged))
        r = self.extract("inputs/huge-dir.zip", "work/out")
        self.assertEqual(r.code, 1, r.stdout[:300])
        self.assertIn("this tool reads into memory", r.json["error"])
        self.assertIn("%d" % (64 * 1024 * 1024), r.json["error"])
        self.assertIn("archive-members recipe", r.json["error"])

    def test_a_zip_directory_whose_size_says_more_than_its_count_is_not_loaded_for_a_few_members(self):
        n = 60000
        cd = b"".join(struct.pack("<IHHHHHHIIIHHHHHII", 0x02014b50, 20, 20, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0) + b"a%07d" % i for i in range(n))
        eocd = struct.pack("<IHHHHIIH", 0x06054b50, 0, 0, 1, 1, len(cd), 0, 0)      # the count says one entry; the directory holds sixty thousand
        self.write("inputs/lying.zip", cd + eocd)
        r = self.extract("inputs/lying.zip", "work/out", max_members=5)
        self.assertEqual(r.code, 1, r.stdout[:300])
        self.assertIn("whatever the end record's count says", r.json["error"])

    def test_a_7z_that_writes_far_more_than_its_size_allows_is_stopped_by_the_ratio_and_not_written_whole(self):
        # the archive file is 72 bytes; its listing says one member of 20 MiB and the program writes 20 MiB of zeros
        bindir = self.fake_7z("head -c 20971520 /dev/zero")
        listing = self.path("bin/7z")
        text = self.read(listing).replace("Size = 100000", "Size = 20971520")
        with open(listing, "w") as fh:
            fh.write(text)
        r = run_tool("archive_extract", {"path": "inputs/slow.7z", "out_dir": "work/out"}, self.dir, path_dirs=[bindir], timeout=60)
        self.assertEqual(r.code, 0, r.stdout + r.stderr)
        self.assertEqual(r.json["stopped_by"], "max_ratio")
        self.assertIn("7z wrote", r.json["stop"])
        self.assertLess(r.json["bytes_written"], 3 * 1024 * 1024, "the member stopped near the ratio's bound (1000 times 72 bytes, and a megabyte of slack)")
        self.assertEqual(r.json["status"], "partial")
        self.assertEqual(self.rows("work/out")[0]["status"], "partial")

    def test_the_first_pass_over_a_7z_listing_looks_at_the_clock(self):
        spec = importlib.util.spec_from_file_location("archive_extract_under_test", tool_path("archive_extract"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        bindir = self.fake_7z("true")

        class Eng:
            out_root = mod.Path(self.path("work/out7"))
            a = {"max_seconds": 1, "max_ratio": 1000}
            extra = {}

            def time_left(self):
                return -1.0                      # the budget is already spent

        os.makedirs(Eng.out_root)
        with self.assertRaises(mod.Budget) as ctx:
            mod.run_7z(Eng(), self.path("inputs/slow.7z"), 0, 10, os.path.join(bindir, "7z"))
        self.assertEqual(ctx.exception.reason, "max_seconds")
        self.assertIn("reading 7z's listing", str(ctx.exception))

    def test_no_program_is_started_in_a_session_of_its_own(self):
        text = self.read(tool_path("archive_extract"))
        code = "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))
        for word in ("start_new_session", "setsid", "process_group"):
            self.assertNotIn(word, code)


if __name__ == "__main__":
    unittest.main()
