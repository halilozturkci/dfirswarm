"""Every path parameter of every tool and recipe, given every hostile path, is answered as JSON: no traceback, no hang, no empty stdout.

The matrix: a 300-character name (alone, as a directory, and in the middle of a path), a symlink loop, a NUL, a lone surrogate, a file where a
directory is expected, a directory where a file is expected, a directory that cannot be listed, a FIFO. It is run for each parameter that names a
place: path, image, db_path, source, out_dir, output.
"""
import json
import os
import sqlite3
import subprocess
import sys
import zipfile

from support import Case, recipe_path, run_tool, tool_path

LONG = "a" * 300


def values(case):
    os.makedirs(case.path("work"), exist_ok=True)
    os.symlink("loop", case.path("work", "loop"))
    os.makedirs(case.path("work", "adir"), exist_ok=True)
    case.write("work/afile", b"x")
    os.makedirs(case.path("work", "locked"), exist_ok=True)
    os.chmod(case.path("work", "locked"), 0)
    os.mkfifo(case.path("work", "fifo"))
    return {
        "long name": "work/" + LONG,
        "long directory": "work/" + LONG + "/x",
        "long in the middle": "work/adir/" + LONG + "/y/z",
        "symlink loop": "work/loop",
        "symlink loop below": "work/loop/x",
        "NUL": "work/a\0b",
        "lone surrogate": "work/\udcff",
        "file as directory": "work/afile/x",
        "directory as file": "work/adir",
        "unlistable directory": "work/locked/x",
        "fifo": "work/fifo",
    }


class HostilePaths(Case):
    def tearDown(self):
        try:
            os.chmod(self.path("work", "locked"), 0o700)
        except OSError:
            pass

    def setUp(self):
        super().setUp()
        self.good = self.write("work/ok.bin", b"\0" * 4096)
        zpath = self.path("work", "ok.zip")
        with zipfile.ZipFile(zpath, "w") as zf:
            zf.writestr("m.txt", b"member")
        sq = self.path("work", "ok.db")
        c = sqlite3.connect(sq)
        c.execute("create table t(x)")
        c.commit()
        c.close()
        self.cases = {
            "archive_extract": [("path", {"out_dir": "work/o"}, "work/ok.zip"), ("out_dir", {"path": "work/ok.zip"}, None)],
            "catalog_search": [("catalog", {"pattern": "x"}, None)],
            "chunk_needles": [("path", {"needles": "x"}, None), ("image", {"needles": "x", "inode": 5}, None)],
            "feature_scan": [("path", {"out_dir": "work/f"}, None), ("out_dir", {"path": "work/ok.bin"}, None)],
            "file_carver": [("path", {"offset": 0, "sig_type": "ZIP", "output": "work/c.bin"}, None),
                            ("output", {"path": "work/ok.zip", "offset": 0, "sig_type": "ZIP"}, None)],
            "file_type": [("path", {}, None)],
            "icat_extract": [("image", {"inode": "5", "output": "work/i.bin"}, None), ("output", {"image": "work/ok.bin", "inode": "5"}, None)],
            "image_layout": [("image", {}, None)],
            "ioc_scan": [("path", {"needles": "x"}, None)],
            "sig_carve": [("path", {}, None)],
            "sqlite_query": [("db_path", {"sql": "select 1"}, None)],
            "sqlite_snapshot": [("db_path", {"out_dir": "work/s"}, None), ("out_dir", {"db_path": "work/ok.db"}, None)],
            "timeline_super": [("source", {"out_dir": "work/t"}, None), ("out_dir", {"source": "work/ok.bin"}, None)],
            "ad1_extract": [("image", {"out_dir": "work/a"}, None), ("out_dir", {"image": "work/ok.bin"}, None)],
        }

    def test_every_path_parameter_of_every_tool_with_every_hostile_path(self):
        hostile = values(self)
        bad = []
        for tool, params in self.cases.items():
            for param, rest, fixed in params:
                for label, value in hostile.items():
                    args = dict(rest)
                    args[param] = value
                    try:
                        raw = json.dumps(args)
                    except UnicodeEncodeError:
                        continue
                    r = run_tool(tool, None, self.dir, raw_input=raw, timeout=40)
                    ok = r.json is not None and "Traceback" not in r.stderr[-600:] and r.code != 124
                    # a hostile path is a refusal that says so, not an "internal error" the tool did not foresee
                    if ok and "internal error" in str((r.json or {}).get("error", "")):
                        ok = False
                    if not ok:
                        bad.append("%s %s=%s: exit %s stdout %r stderr %r" % (tool, param, label, r.code, r.stdout[:80], r.stderr[-120:].replace("\n", " ")))
        self.assertEqual(bad, [], "\n" + "\n".join(bad))

    def run_recipe(self, name, entry, argv):
        cmd = ([sys.executable] if entry.endswith(".py") else ["bash"]) + [recipe_path(name, entry)] + argv
        e = dict(os.environ)
        for k in ("JOB_ID", "OUT", "AGENT_ID", "SECRET_OUTPUT"):
            e.pop(k, None)
        try:
            return subprocess.run(cmd, capture_output=True, text=True, cwd=self.dir, env=e, timeout=40)
        except subprocess.TimeoutExpired:
            return subprocess.CompletedProcess(cmd, 124, "", "timed out")

    def test_every_recipe_with_a_hostile_target_path_and_out(self):
        hostile = values(self)
        recipes = [("ad1-items", "run.py"), ("archive-members", "run.py"), ("disk-timeline", "run.py"), ("disk-volumes", "run.sh"), ("memory-windows", "run.sh")]
        wrong_types = [{"paths": [5]}, {"paths": "x"}, {"paths": [["a"]]}, {"paths": [10 ** 400]}, {"paths": []}, [], 5, "x", {"paths": ["a\u0000b"]}]
        bad = []

        def check(label, p):
            try:
                doc = json.loads(p.stdout.strip().splitlines()[-1])
            except (ValueError, IndexError):
                doc = None
            if doc is None or "Traceback" in p.stderr[-600:] or p.returncode == 124:
                bad.append("%s: exit %s stdout %r stderr %r" % (label, p.returncode, p.stdout[:80], p.stderr[-120:].replace("\n", " ")))

        for name, entry in recipes:
            for label, value in hostile.items():
                try:
                    target = json.dumps({"paths": [value], "name": "x"})
                except UnicodeEncodeError:
                    continue
                check("%s detect target %s" % (name, label), self.run_recipe(name, entry, ["detect", "--target", target]))
                check("%s run target %s" % (name, label), self.run_recipe(name, entry, ["run", "--target", target, "--out", self.path("o-" + name)]))
                good = json.dumps({"paths": ["work/ok.zip"], "name": "x"})
                if "\0" in value:
                    continue                            # a NUL cannot be on a command line
                check("%s run out %s" % (name, label), self.run_recipe(name, entry, ["run", "--target", good, "--out", value]))
                check("%s detect probe-out %s" % (name, label), self.run_recipe(name, entry, ["detect", "--target", good, "--probe-out", value]))
            for w in wrong_types:
                check("%s detect %r" % (name, w), self.run_recipe(name, entry, ["detect", "--target", json.dumps(w)]))
                check("%s run %r" % (name, w), self.run_recipe(name, entry, ["run", "--target", json.dumps(w), "--out", self.path("o2-" + name)]))
            check("%s detect lone surrogate (JSON escape)" % name, self.run_recipe(name, entry, ["detect", "--target", '{"paths":["\\ud800"]}']))
        self.assertEqual(bad, [], "\n" + "\n".join(bad))


if __name__ == "__main__":
    import unittest
    unittest.main()
