"""The perl wrapper every step of disk-volumes and memory-windows runs under: its clock, its process group, its checked writer, its word.

- A program that leaves a descendant running (`sleep 90 &`) does not hold the step: when the program has exited the wrapper takes what is
  readable and ends the step, and the descendant, which is part of the step, is ended with it.
- A program that ignores SIGTERM and SIGALRM is ended by SIGKILL of the step's group two seconds after its deadline.
- A write the disk or a size limit refuses is said by the wrapper in a file of its own, not by an exit code a program can also give: the answer is
  partial or failed and names the cause, never a statement about the image (not `unsupported`, not `applies: false`); a program that itself exits
  74 is an ordinary failed step.
- Without perl the recipe says so, and says nothing about the image.
"""
import json
import os
import resource
import shutil
import subprocess
import sys
import time

from support import Case, recipe_path, stand_in

MMLS = """GUID Partition Table (EFI)
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Safety Table
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  000       0000002048   0000002559   0000000512   data
"""
PAD = "x" * 1500


class StepWrapper(Case):
    def bins(self, fls_body, mmls=True, fsstat_pad=False):
        b = self.path("bin")
        os.makedirs(b, exist_ok=True)
        if mmls:
            stand_in(b, "mmls", "cat <<'EOF'\n%sEOF\n" % MMLS)
        else:
            stand_in(b, "mmls", "echo 'Cannot determine partition type' >&2\nexit 1\n")
        # padded first, so that the line that names the file system is past the first 700 bytes, which a size limit of 700 refuses
        stand_in(b, "fsstat", ('echo "%s"\n' % PAD if fsstat_pad else "") + "echo 'File System Type: Ext4'\necho 'Block Size: 4096'\n")
        stand_in(b, "fls", fls_body)
        stand_in(b, "mactime", "echo '2020-01-01T00:00:00Z,1,m...,r/rrwxrwxrwx,0,0,1,/x'\n")
        img = self.path("disk.img")
        with open(img, "wb") as fh:
            fh.write(b"\0" * 65536)
        return b, img

    def go(self, recipe, cmd, b, img, out=None, env=None, limit=None, timeout=90, path=None):
        run = recipe_path(recipe, "run.sh")
        target = json.dumps({"paths": [img], "name": "disk.img"})
        argv = [shutil.which("bash"), run, cmd, "--target", target] + (["--out", out] if out else [])
        e = dict(os.environ)
        for k in ("JOB_ID", "OUT", "AGENT_ID", "SECRET_OUTPUT"):
            e.pop(k, None)
        e["PATH"] = path if path is not None else b + os.pathsep + e["PATH"]
        e.update(env or {})

        def limiter():
            if limit:
                resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))
        began = time.monotonic()
        p = subprocess.run(argv, capture_output=True, text=True, cwd=self.dir, env=e, timeout=timeout, preexec_fn=limiter)
        return p, time.monotonic() - began

    def gone(self, pidfile):
        pid = int(open(pidfile).read().split()[0])
        for _ in range(30):
            try:
                os.kill(pid, 0)
            except OSError:
                return True
            time.sleep(0.2)
        try:
            os.kill(pid, 9)
        except OSError:
            pass
        return False

    # ---- the clock and the group
    def test_a_descendant_holding_the_output_does_not_outlive_the_recipe_clock(self):
        pidfile = self.path("sleeper.pid")
        b, img = self.bins('sleep 90 &\necho $! > "%s"\necho "r/r 1-128-1:\tx"\nexit 0\n' % pidfile)
        for recipe in ("disk-volumes",):
            p, took = self.go(recipe, "run", b, img, out=self.path("out-" + recipe), env={"RECIPE_SECONDS": "6"})
            self.assertLess(took, 25, "%s: the recipe was held %.1f s by a background descendant of a step: %s" % (recipe, took, p.stdout + p.stderr))
            json.loads(p.stdout.strip().splitlines()[-1])
            self.assertTrue(self.gone(pidfile), "the descendant of the step is still running")

    def test_a_step_that_ignores_sigterm_and_sigalrm_is_killed_at_its_deadline(self):
        pidfile = self.path("stubborn.pid")
        b, img = self.bins('echo $$ > "%s"\nexec perl -e \'$SIG{TERM}="IGNORE"; $SIG{ALRM}="IGNORE"; $SIG{HUP}="IGNORE"; sleep 120\'\n' % pidfile)
        p, took = self.go("disk-volumes", "run", b, img, out=self.path("out"), env={"RECIPE_SECONDS": "8", "RECIPE_STEP_SECONDS": "2"})
        self.assertLess(took, 40, "the recipe ran %.1f s over a step that ignores SIGTERM and SIGALRM: %s" % (took, p.stdout + p.stderr))
        json.loads(p.stdout.strip().splitlines()[-1])
        self.assertTrue(self.gone(pidfile), "the stubborn step is still running")

    # ---- a refused write is not a fact about the image
    def test_a_refused_write_in_detection_is_not_a_statement_about_the_image(self):
        b, img = self.bins('echo "r/r 1-128-1:\tx"\n', mmls=False, fsstat_pad=True)
        p, _ = self.go("disk-volumes", "detect", b, img, limit=700)
        doc = json.loads(p.stdout.strip().splitlines()[-1])
        self.assertEqual(doc.get("applies"), "unknown", p.stdout + p.stderr)
        self.assertIn("refused", doc["why"])

    def test_a_refused_write_in_a_run_is_partial_and_names_the_cause_not_unsupported(self):
        b, img = self.bins('echo "r/r 1-128-1:\tx"\n', mmls=False, fsstat_pad=True)
        out = self.path("out")
        p, _ = self.go("disk-volumes", "run", b, img, out=out, limit=700)
        doc = json.loads(p.stdout.strip().splitlines()[-1])
        self.assertNotEqual(doc.get("status"), "unsupported", p.stdout + p.stderr)
        self.assertIn(doc.get("status"), ("partial", "failed"), p.stdout + p.stderr)
        if os.path.exists(os.path.join(out, "coverage.json")):
            cov = json.load(open(os.path.join(out, "coverage.json")))
            self.assertNotEqual(cov.get("status"), "unsupported")
            self.assertNotEqual(cov.get("status"), "complete")

    def test_memory_windows_detect_under_a_refused_write_cannot_tell(self):
        b = self.path("bin")
        os.makedirs(b)
        stand_in(b, "vol", 'echo "NTBuildLab 19041.1"\necho "%s"\n' % PAD)
        stand_in(b, "file", 'echo "data"\n')
        img = self.path("mem.raw")
        with open(img, "wb") as fh:
            fh.write(b"\0" * 65536)
        p, _ = self.go("memory-windows", "detect", b, img, limit=700)
        doc = json.loads(p.stdout.strip().splitlines()[-1])
        self.assertNotEqual(doc.get("applies"), False, p.stdout + p.stderr)

    def test_a_program_that_exits_74_itself_is_not_reported_as_a_refused_write(self):
        b, img = self.bins('echo "r/r 1-128-1:\tx"\nexit 74\n')
        out = self.path("out")
        p, _ = self.go("disk-volumes", "run", b, img, out=out)
        doc = json.loads(p.stdout.strip().splitlines()[-1])
        cov = json.load(open(os.path.join(out, "coverage.json")))
        said = json.dumps(cov["errors"])
        self.assertNotIn("refused a write", said, said)
        self.assertIn("exit 74", said)
        self.assertIn(doc["status"], ("partial", "failed"))

    # ---- no perl
    def test_without_perl_the_recipe_says_so_and_says_nothing_about_the_image(self):
        b, img = self.bins('echo "r/r 1-128-1:\tx"\n')
        bare = self.path("bare")
        os.makedirs(bare)
        for name in ("python3", "sed", "grep", "head", "tr", "mktemp", "rm", "mkdir", "find", "sort", "wc", "cat", "dirname", "basename", "readlink",
                     "ls", "date", "sleep", "kill", "env", "expr", "file", "uniq", "cut", "awk", "tee", "mv", "cp", "true", "false", "chmod", "stat"):
            src = shutil.which(name)
            if src:
                os.symlink(src, os.path.join(bare, name))
        path = b + os.pathsep + bare
        for cmd, out in (("detect", None), ("run", self.path("out"))):
            p, _ = self.go("disk-volumes", cmd, b, img, out=out, path=path)
            doc = json.loads(p.stdout.strip().splitlines()[-1])
            self.assertEqual(p.returncode, 2, p.stdout + p.stderr)
            self.assertIn("perl", json.dumps(doc))
            self.assertNotEqual(doc.get("applies"), False)
            self.assertNotEqual(doc.get("status"), "unsupported")


if __name__ == "__main__":
    import unittest
    unittest.main()
