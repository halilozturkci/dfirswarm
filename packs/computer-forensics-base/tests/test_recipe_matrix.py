"""The five recipes, `detect` and `run`, under three classes of hostile input: a target of an odd type, a target file with odd content, and a
write that the file system refuses (an output directory that cannot be written, as a user who is not the owner; a file-size limit).

Every answer is JSON on stdout with no traceback and no hang. As root a 555 directory is still writable, so the tests run the recipe as
nobody (setpriv) when they are root, and skip that part when there is no setpriv.
"""
import json
import os
import resource
import shutil
import subprocess
import sys
import zipfile

from support import Case, recipe_path

RECIPES = [("ad1-items", "run.py"), ("archive-members", "run.py"), ("disk-timeline", "run.py"), ("disk-volumes", "run.sh"), ("memory-windows", "run.sh")]
ODD_TARGETS = ['{"paths":{"a":1}}', '{"paths":5}', '{"paths":true}', '{"paths":null}', '{"paths":[null]}', '{"paths":[{}]}', '{"paths":[5,"x"]}',
               '{"paths":[1e999]}', '{"paths":["x"],"name":5}', '{"paths":[["x"]]}', "[]", '"x"', "5", "null", "true", "{}"]


def limited():
    resource.setrlimit(resource.RLIMIT_FSIZE, (150, 150))


class RecipeMatrix(Case):
    def command(self, name, entry, argv, as_nobody=False):
        cmd = ([sys.executable] if entry.endswith(".py") else ["bash"]) + [recipe_path(name, entry)] + argv
        if as_nobody:
            cmd = ["setpriv", "--reuid=65534", "--regid=65534", "--clear-groups"] + cmd
        return cmd

    def go(self, label, name, entry, argv, bad, as_nobody=False, preexec=None):
        e = dict(os.environ)
        for k in ("JOB_ID", "OUT", "AGENT_ID", "SECRET_OUTPUT"):
            e.pop(k, None)
        try:
            p = subprocess.run(self.command(name, entry, argv, as_nobody), capture_output=True, text=True, cwd=self.dir, env=e, timeout=40, preexec_fn=preexec)
        except subprocess.TimeoutExpired:
            bad.append("%s %s: timed out" % (name, label))
            return
        try:
            json.loads(p.stdout.strip().splitlines()[-1])
        except (ValueError, IndexError):
            bad.append("%s %s: exit %s stdout %r stderr %r" % (name, label, p.returncode, p.stdout[:80], p.stderr[-140:].replace("\n", " ")))
            return
        if "Traceback" in p.stderr:
            bad.append("%s %s: traceback on stderr %r" % (name, label, p.stderr[-900:].replace("\n", " ")))

    def test_a_target_of_an_odd_type_or_with_odd_content_is_a_refusal_for_detect_and_run(self):
        bad = []
        self.write("t/nonutf8", b"\xff\xfe")
        self.write("t/nul", b'{"paths":["a\x00b"]}')
        self.write("t/huge", b" " * (3 << 20) + b"{}")
        self.write("t/empty", b"")
        self.write("t/binary", bytes(range(256)) * 40)
        os.makedirs(self.path("t", "adir"))
        os.mkfifo(self.path("t", "fifo"))
        files = ["t/nonutf8", "t/nul", "t/huge", "t/empty", "t/binary", "t/adir", "t/fifo"]
        for name, entry in RECIPES:
            for target in ODD_TARGETS + files:
                self.go("detect %r" % target, name, entry, ["detect", "--target", target], bad)
                self.go("run %r" % target, name, entry, ["run", "--target", target, "--out", self.path("o-" + name)], bad)
        self.assertEqual(bad, [], "\n" + "\n".join(bad))

    def zip_target(self):
        z = self.path("work", "many.zip")
        os.makedirs(os.path.dirname(z), exist_ok=True)
        with zipfile.ZipFile(z, "w") as zf:
            for i in range(200):
                zf.writestr("member-%04d.txt" % i, b"x")
        return json.dumps({"paths": [z], "name": "many.zip"})

    def test_an_output_directory_that_cannot_be_written_is_a_refusal(self):
        nobody = os.geteuid() == 0
        if nobody and not shutil.which("setpriv"):
            self.skipTest("root, and no setpriv to run the recipe as another user")
        os.chmod(self.dir, 0o755)
        target = self.zip_target()
        for part in ("work", "work/many.zip"):
            os.chmod(self.path(part), 0o755 if part == "work" else 0o644)
        os.makedirs(self.path("ro"))
        os.chmod(self.path("ro"), 0o555)
        os.makedirs(self.path("ro2", "inner"), exist_ok=True)
        os.chmod(self.path("ro2"), 0o555)
        bad = []
        try:
            for name, entry in RECIPES:
                for out in (self.path("ro"), self.path("ro2", "inner", "deeper"), "/", "/proc/x"):
                    self.go("run --out %s" % out, name, entry, ["run", "--target", target, "--out", out], bad, as_nobody=nobody)
        finally:
            os.chmod(self.path("ro"), 0o755)
            os.chmod(self.path("ro2"), 0o755)
        self.assertEqual(bad, [], "\n" + "\n".join(bad))

    def test_every_write_under_a_file_size_limit_is_a_refusal_or_a_partial_never_a_traceback(self):
        bad = []
        target = self.zip_target()
        for name, entry in RECIPES:
            self.go("run under ulimit -f", name, entry, ["run", "--target", target, "--out", self.path("lim-" + name)], bad, preexec=limited)
        self.assertEqual(bad, [], "\n" + "\n".join(bad))


if __name__ == "__main__":
    import unittest
    unittest.main()
