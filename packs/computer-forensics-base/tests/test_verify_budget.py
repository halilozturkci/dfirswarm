"""verify_sources is charged to the tool's own clock: a verify that outlasts the budget ends the run before the manifest's timeout, with JSON.

The source is a sparse file of 64 GiB (nothing on disk): reading and hashing it takes far longer than the budgets below, so a tool that
gives the verify a clock of its own (120 seconds) instead of the time it has left answers late, or not at all within the test's limit.
"""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
import unittest

from support import Case, have, run_tool, tool_path

NEEDED = ("mke2fs", "sfdisk", "mmls", "fsstat", "icat", "fls", "img_stat")
BIG = 64 << 30


@unittest.skipUnless(all(have(p) for p in NEEDED), "the Sleuth Kit, sfdisk and mke2fs are needed")
class VerifyBudget(Case):
    def setUp(self):
        super().setUp()
        src = self.path("src")
        os.makedirs(src)
        with open(os.path.join(src, "hello.txt"), "wb") as fh:
            fh.write(b"alpha\n")
        self.raw = self.path("evidence", "disk.raw")
        os.makedirs(self.path("evidence"))
        with open(self.raw, "wb") as fh:
            fh.truncate(16 << 20)
        subprocess.run(["sfdisk", self.raw], input=b"start=2048, size=24576, type=83\n", check=True, capture_output=True)
        subprocess.run(["mke2fs", "-q", "-t", "ext4", "-E", "offset=%d" % (2048 * 512), "-d", src, self.raw, "12M"], check=True, capture_output=True)
        listing = subprocess.run(["fls", "-o", "2048", self.raw], capture_output=True, text=True, check=True).stdout
        self.inode = [ln.split(":")[0].split()[-1] for ln in listing.splitlines() if ln.endswith("hello.txt")][0]
        made = run_tool("layer_describe", {"sources": [self.raw], "out_dir": self.path("out", "layers")}, self.dir).json
        self.assertEqual(made["status"], "complete", made.get("status_basis"))
        with open(os.path.join(self.path("out", "layers"), made["descriptor"]["file"]), "rb") as fh:
            doc = json.loads(fh.read())
        self.big = self.path("evidence", "big.raw")
        with open(self.big, "wb") as fh:
            fh.truncate(BIG)
        doc["sources"][0].update(path=self.big, bytes=BIG, sha256="0" * 64)
        body = (json.dumps(doc, sort_keys=True, ensure_ascii=True, separators=(",", ":")) + "\n").encode()
        self.descriptor = self.path("out", "forged", "layer-%s.json" % hashlib.sha256(body).hexdigest())
        os.makedirs(os.path.dirname(self.descriptor))
        with open(self.descriptor, "wb") as fh:
            fh.write(body)

    def check(self, res, started, limit):
        took = time.monotonic() - started
        self.assertLess(took, limit, "the answer came after %.1f seconds" % took)
        self.assertIsNotNone(res.json, (res.code, res.stdout[:200], res.stderr[:200]))
        self.assertEqual((res.code, res.json["status"]), (1, "failed"), res.json)
        self.assertIn("time budget", res.json["status_basis"])

    def test_chunk_needles_ends_the_verify_inside_max_seconds(self):
        started = time.monotonic()
        res = run_tool("chunk_needles", {"descriptor": self.descriptor, "verify_sources": True, "inode": self.inode, "needles": ["abc"], "offset": 2048, "max_seconds": 1}, self.dir, timeout=60)
        self.check(res, started, 8)

    def test_icat_extract_ends_the_verify_inside_max_seconds(self):
        started = time.monotonic()
        res = run_tool("icat_extract", {"descriptor": self.descriptor, "verify_sources": True, "inode": self.inode, "output": "work/out/never.bin", "max_seconds": 1}, self.dir, timeout=60)
        self.check(res, started, 8)
        self.assertFalse(os.path.exists(self.path("work", "out", "never.bin")))

    def test_image_layout_counts_the_verify_in_its_total_budget(self):
        # The total budget (270 seconds) is a constant: a copy of the tool with a budget of 2 seconds shows that the verify is inside it.
        copy = self.path("tool-copy", "run.py")
        os.makedirs(os.path.dirname(copy))
        with open(tool_path("image_layout"), encoding="utf-8") as fh:
            text = fh.read()
        self.assertEqual(text.count("TOTAL_BUDGET = 270 "), 1)
        with open(copy, "w", encoding="utf-8") as fh:
            fh.write(text.replace("TOTAL_BUDGET = 270 ", "TOTAL_BUDGET = 2 "))
        started = time.monotonic()
        proc = subprocess.run([sys.executable, copy], input=json.dumps({"descriptor": self.descriptor, "verify_sources": True}), capture_output=True, text=True, cwd=self.dir, timeout=60)
        took = time.monotonic() - started
        self.assertLess(took, 8, "the answer came after %.1f seconds" % took)
        doc = json.loads(proc.stdout)
        self.assertEqual((proc.returncode, doc["status"]), (1, "failed"), doc)
        self.assertIn("time budget", doc["status_basis"])

    def test_the_recipe_gives_the_verify_what_its_own_clock_has_left(self):
        with open(os.path.join(os.path.dirname(tool_path("image_layout")), "..", "..", "recipes", "disk-volumes", "run.sh"), encoding="utf-8") as fh:
            text = fh.read()
        self.assertIn("min(DESCRIPTOR_VERIFY_SECONDS,", text)
        self.assertIn("DEADLINE - SECONDS", text)


if __name__ == "__main__":
    unittest.main()
