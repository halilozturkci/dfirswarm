"""A FIFO put in the place of a file after the tool checked it is refused, not waited on.

The tools check `os.path.isfile` and open the path a moment later; between the two a caller can swap in a FIFO that never gives a byte. The
check is made to say "file" for the FIFO here (the swap, made deterministic), and the tool must still answer in seconds.
"""
import json
import os
import subprocess
import sys
import time

from support import Case, tool_path

PRELUDE = """
import os, runpy, sys
_isfile = os.path.isfile
os.path.isfile = lambda p, _f=_isfile: True if str(p).endswith("swapped.bin") else _f(p)
sys.argv = [sys.argv[1]]
runpy.run_path(sys.argv[0], run_name="__main__")
"""


class FifoSwap(Case):
    def drive(self, tool, args):
        os.mkfifo(self.path("swapped.bin"))
        started = time.monotonic()
        try:
            p = subprocess.run([sys.executable, "-c", PRELUDE, tool_path(tool)], input=json.dumps(args), capture_output=True, text=True,
                               cwd=self.dir, timeout=25)
        except subprocess.TimeoutExpired:
            self.fail("%s waited on a FIFO that was put in the place of its file" % tool)
        self.assertLess(time.monotonic() - started, 20, tool)
        self.assertNotIn("Traceback", p.stderr[-400:], (tool, p.stderr[-400:]))
        try:
            doc = json.loads(p.stdout)
        except ValueError:
            self.fail("%s printed no JSON: %r %r" % (tool, p.stdout[:200], p.stderr[-200:]))
        self.assertIn(doc.get("status"), ("failed", "partial"), (tool, doc))
        return doc

    def test_sig_carve(self):
        self.drive("sig_carve", {"path": "swapped.bin"})

    def test_chunk_needles(self):
        self.drive("chunk_needles", {"path": "swapped.bin", "needles": "x"})

    def test_sqlite_snapshot(self):
        self.drive("sqlite_snapshot", {"db_path": "swapped.bin", "out_dir": "work/snap"})

    def test_file_carver(self):
        self.drive("file_carver", {"path": "swapped.bin", "offset": 0, "sig_type": "ZIP", "output": "work/z.bin"})

    def test_image_layout(self):
        self.drive("image_layout", {"image": "swapped.bin"})


if __name__ == "__main__":
    import unittest
    unittest.main()
