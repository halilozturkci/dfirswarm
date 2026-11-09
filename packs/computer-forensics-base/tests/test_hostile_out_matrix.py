"""A hostile output directory, with the external program present.

The earlier hostile-path tests ran without Plaso, bulk_extractor, icat, Volatility or the Sleuth Kit, so every tool stopped at "program not found"
and the code that runs after the program (rename the files in, list the directory, count what was written) was never reached. Here a stand-in
for each program is on PATH, so the whole run happens, and the output location is made hostile in ten ways: a name of 255 and of 300 characters,
a directory under a parent that cannot be searched (mode 0), an existing directory that cannot be written (mode 555), a file where a directory
should be, a symlink to nowhere, a parent that is a symlink to nowhere, a read-only file system (tmpfs mounted ro inside `unshare -rm`), and a
path whose parents do not exist. At every one: one JSON document on stdout, no traceback, no death by signal, nothing hidden or `.tmp` left
anywhere under the working directory, and an answer that does not say `complete` where the location cannot be written.

The programs are stand-ins; the real Plaso, bulk_extractor, icat, Volatility and Sleuth Kit were never run by this test.
Run as nobody (setpriv) when the test is root, so that the permission variants bind; those variants are skipped without setpriv.
"""
import json
import os
import shutil
import stat
import subprocess
import sys
import unittest
import zipfile

import test_enospc_sweep as tes
import test_write_sweep as tws
from support import recipe_path, stand_in, tool_path

# name -> (setup(W), dir-style out, file-style out, must_fail, needs_mount)
VARIANTS = {}


def variant(name, dir_out, file_out, must_fail=True, setup=None, mount=False):
    VARIANTS[name] = (setup, dir_out, file_out, must_fail, mount)


def _mode0(w):
    os.makedirs(os.path.join(w, "locked"))
    os.chmod(os.path.join(w, "locked"), 0)


def _ro555(w):
    os.makedirs(os.path.join(w, "ro"))
    os.chmod(os.path.join(w, "ro"), 0o555)


def _file(w):
    with open(os.path.join(w, "afile"), "w") as fh:
        fh.write("x")


def _dangling(w):
    os.symlink("/nonexistent/x", os.path.join(w, "dang"))


def _dlink(w):
    os.symlink("/nonexistent", os.path.join(w, "dlink"))


def _rofs(w):
    os.makedirs(os.path.join(w, "rofs"))


variant("long255", "w/" + "a" * 255, "w/" + "a" * 255, must_fail=False)
variant("long300", "w/" + "a" * 300, "w/" + "a" * 300)
variant("mode0-parent", "locked/o", "locked/o.bin", setup=_mode0)
variant("ro555", "ro", "ro/o.bin", setup=_ro555)
variant("file-for-dir", "afile", "afile/o.bin", setup=_file)
variant("dangling-link", "dang", "dang", setup=_dangling)
variant("dangling-parent", "dlink/o", "dlink/o.bin", setup=_dlink)
variant("rofs", "rofs", "rofs/o.bin", setup=_rofs, mount=True)
variant("rofs-sub", "rofs/o", "rofs/o.bin", setup=_rofs, mount=True)
variant("parents-missing", "nope/deeper/o", "nope/deeper/o.bin", must_fail=False)


def files_in(root):
    seen = set()
    for base, dirs, names in os.walk(root, onerror=lambda e: None):
        for n in dirs + names:
            seen.add(os.path.relpath(os.path.join(base, n), root))
    return seen


def make_tree_removable(root):
    for base, dirs, names in os.walk(root):
        for n in dirs:
            try:
                os.chmod(os.path.join(base, n), 0o755)
            except OSError:
                pass
    try:
        os.chmod(root, 0o755)
    except OSError:
        pass


class HostileOut(tws.Scenarios):
    # ---- scenarios: (W, out, style) -> (argv, stdin, bin_dir or None); style "dir" or "file"
    def sc_timeline_super(self, w, out):
        b = os.path.join(w, "bin")
        os.makedirs(b)
        data = os.path.join(w, "canned.jsonl")
        with open(data, "w") as fh:
            fh.write(json.dumps({"datetime": "2023-11-14T22:13:20.000000+00:00", "parser": "filestat", "data_type": "fs:stat", "message": "m1"}) + "\n")
        stand_in(b, "log2timeline.py", 'case "$1" in --version) echo "plaso - log2timeline version 1"; exit 0;; esac\n'
                 'while [ $# -gt 0 ]; do case "$1" in --storage_file) echo storage > "$2"; shift;; --logfile) echo log > "$2"; shift;; esac; shift; done\nexit 0\n')
        stand_in(b, "psort.py", 'case "$1" in --version) echo "plaso - psort version 1"; exit 0;; esac\n'
                 'while [ $# -gt 0 ]; do case "$1" in -w) cp "%s" "$2"; shift;; --logfile) echo log > "$2"; shift;; esac; shift; done\nexit 0\n' % data)
        os.makedirs(os.path.join(w, "inputs"))
        with open(os.path.join(w, "inputs", "disk.dd"), "wb") as fh:
            fh.write(b"\0" * 64)
        return [sys.executable, tool_path("timeline_super")], json.dumps({"source": "inputs/disk.dd", "out_dir": out}), b

    def sc_feature_scan(self, w, out):
        b = os.path.join(w, "bin")
        os.makedirs(b)
        stand_in(b, "bulk_extractor",
                 'while [ $# -gt 0 ]; do case "$1" in -o) OUTDIR="$2"; shift;; esac; shift; done\n'
                 'mkdir -p "$OUTDIR" || exit 1\n'
                 'printf "1024\\tbob@example.test\\tctx\\n" > "$OUTDIR/email.txt"\necho scanning\nexit 0\n')
        os.makedirs(os.path.join(w, "inputs"))
        with open(os.path.join(w, "inputs", "blob.raw"), "wb") as fh:
            fh.write(b"\0" * 64)
        return [sys.executable, tool_path("feature_scan")], json.dumps({"path": "inputs/blob.raw", "out_dir": out}), b

    def sc_icat_extract(self, w, out):
        b = os.path.join(w, "bin")
        os.makedirs(b)
        stand_in(b, "icat", "printf data\n")
        os.makedirs(os.path.join(w, "inputs"))
        with open(os.path.join(w, "inputs", "disk.E01"), "wb") as fh:
            fh.write(b"x")
        return [sys.executable, tool_path("icat_extract")], json.dumps({"inode": "168-128-4", "output": out, "image": "inputs/disk.E01", "offset": 2048}), b

    def sc_archive_extract(self, w, out):
        os.makedirs(os.path.join(w, "inputs"))
        with zipfile.ZipFile(os.path.join(w, "inputs", "a.zip"), "w") as zf:
            for i in range(5):
                zf.writestr("m%d.txt" % i, b"member %d" % i)
        return [sys.executable, tool_path("archive_extract")], json.dumps({"path": "inputs/a.zip", "out_dir": out}), None

    def sc_file_carver(self, w, out):
        os.makedirs(os.path.join(w, "inputs"))
        with zipfile.ZipFile(os.path.join(w, "inputs", "z.zip"), "w") as zf:
            zf.writestr("big.bin", os.urandom(3000))
        return [sys.executable, tool_path("file_carver")], json.dumps({"path": "inputs/z.zip", "offset": 0, "sig_type": "ZIP", "output": out}), None

    def sc_sqlite_snapshot(self, w, out):
        import sqlite3
        os.makedirs(os.path.join(w, "inputs"))
        c = sqlite3.connect(os.path.join(w, "inputs", "s.db"))
        c.execute("create table t(x)")
        c.executemany("insert into t values (?)", [("row %d" % i,) for i in range(50)])
        c.commit()
        c.close()
        return [sys.executable, tool_path("sqlite_snapshot")], json.dumps({"db_path": "inputs/s.db", "out_dir": out}), None

    def recipe(self, name, entry, w, out, target, b=None):
        return ["bash" if entry.endswith(".sh") else sys.executable, recipe_path(name, entry), "run", "--target", json.dumps(target), "--out", out], None, b

    def sc_recipe_disk_volumes(self, w, out):
        b = self.stand_ins(w)
        img = os.path.join(w, "disk.img")
        with open(img, "wb") as fh:
            fh.write(b"\0" * 65536)
        return self.recipe("disk-volumes", "run.sh", w, out, {"paths": [img], "name": "disk.img"}, b)

    def sc_recipe_memory_windows(self, w, out):
        b = self.stand_ins(w)
        img = os.path.join(w, "mem.raw")
        with open(img, "wb") as fh:
            fh.write(b"\0" * 65536)
        return self.recipe("memory-windows", "run.sh", w, out, {"paths": [img], "name": "mem.raw"}, b)

    def sc_recipe_disk_timeline(self, w, out):
        b = os.path.join(w, "bin")
        os.makedirs(b)
        stand_in(b, "log2timeline", 'while [ $# -gt 0 ]; do case "$1" in --storage-file) echo storage > "$2"; shift;; --logfile) LOG="$2"; shift;; esac; shift; done\n'
                 'echo log > "$LOG"\nexit 0\n')
        stand_in(b, "psort", 'while [ $# -gt 0 ]; do case "$1" in -w) printf "datetime,message\\n2023-11-14,one event\\n" > "$2"; shift;; --logfile) echo log > "$2"; shift;; esac; shift; done\nexit 0\n')
        stand_in(b, "pinfo", "echo 'storage file: ok'\n")
        head = bytearray(4096)
        head[3:11] = b"NTFS    "
        img = os.path.join(w, "disk.raw")
        with open(img, "wb") as fh:
            fh.write(bytes(head))
        return self.recipe("disk-timeline", "run.py", w, out, {"paths": [img], "name": "disk.raw"}, b)

    def sc_recipe_archive_members(self, w, out):
        z = os.path.join(w, "many.zip")
        with zipfile.ZipFile(z, "w") as zf:
            for i in range(20):
                zf.writestr("member-%04d.txt" % i, b"x")
        return self.recipe("archive-members", "run.py", w, out, {"paths": [z], "name": "many.zip"})

    # ---- the matrix
    def matrix(self, name, style):
        nobody = os.geteuid() == 0
        if nobody and not shutil.which("setpriv"):
            self.skipTest("root, and no setpriv to run as another user")
        bad = []
        for vname, (setup, dir_out, file_out, must_fail, mount) in VARIANTS.items():
            if mount and not tes.MOUNT_OK:
                continue
            w = self.path("w-%s-%s" % (name, vname))
            os.makedirs(w)
            os.chmod(w, 0o777 if nobody else 0o755)
            out = dir_out if style == "dir" else file_out
            argv, stdin, extra = getattr(self, "sc_" + name)(w, out)
            if setup:
                setup(w)
            before = files_in(w)
            self.addCleanup(make_tree_removable, w)
            env = dict(os.environ)
            for k in ("JOB_ID", "OUT", "AGENT_ID", "SECRET_OUTPUT"):
                env.pop(k, None)
            if extra:
                env["PATH"] = extra + os.pathsep + env["PATH"]
            cmd = list(argv)
            if mount:
                cmd = ["unshare", "-rm", "bash", "-c", 'mount -t tmpfs -o ro tmpfs "$1/rofs" && shift && exec "$@"', "x", w] + cmd
            elif nobody:
                cmd = ["setpriv", "--reuid=65534", "--regid=65534", "--clear-groups"] + cmd
            try:
                p = subprocess.run(cmd, input=stdin, capture_output=True, text=True, cwd=w, env=env, timeout=90)
            except subprocess.TimeoutExpired:
                bad.append("%s: timed out" % vname)
                continue
            why = None
            doc = None
            try:
                doc = json.loads(p.stdout)
            except ValueError:
                try:
                    doc = json.loads(p.stdout.strip().splitlines()[-1])
                except (ValueError, IndexError):
                    doc = None
            if doc is None:
                why = "no JSON on stdout (exit %s) %r %r" % (p.returncode, p.stdout[:80], p.stderr[-200:].replace("\n", " "))
            elif p.returncode < 0:
                why = "killed by signal %d" % -p.returncode
            elif "Traceback" in p.stderr:
                why = "traceback: %r" % p.stderr[-200:].replace("\n", " ")
            if why is None:
                left = sorted(r for r in files_in(w) - before
                              if os.path.basename(r).startswith(".") or r.endswith((".tmp", ".partial")))
                if left:
                    why = "left behind: %s" % left[:3]
            if why is None and must_fail and isinstance(doc, dict) and (doc.get("status") == "complete"):
                why = "says complete although the location cannot be written"
            if why is not None:
                bad.append("%s: %s" % (vname, why))
        self.assertEqual(bad, [], "%s (%s-style out):\n%s" % (name, style, "\n".join(bad)))


def _add(name, style):
    def test(self):
        self.matrix(name, style)
    test.__name__ = "test_%s" % name
    setattr(HostileOut, test.__name__, test)


for _n, _s in (("timeline_super", "dir"), ("feature_scan", "dir"), ("icat_extract", "file"), ("archive_extract", "dir"), ("file_carver", "file"),
               ("sqlite_snapshot", "dir"), ("recipe_disk_volumes", "dir"), ("recipe_memory_windows", "dir"), ("recipe_disk_timeline", "dir"),
               ("recipe_archive_members", "dir")):
    _add(_n, _s)


if __name__ == "__main__":
    unittest.main()
