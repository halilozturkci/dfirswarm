"""An answer is written by one protected printer, and a reader that stalls cannot make a tool unkillable.

The printer holds the stop signals while it writes (a signal must not cut the document). So that a reader that stops taking the answer (a full
pipe) does not make the tool immune to SIGTERM, the held write is bounded: when a stop signal is waiting after TOOL_HELD_WRITE_SECONDS the tool
says so on stderr and ends with 128 plus the signal. The tests give the tool a pipe of 4096 bytes that nobody reads.
"""
import ast
import fcntl
import json
import os
import signal
import sqlite3
import subprocess
import sys
import time
import zipfile

from support import PACK_DIR, Case, tool_path

F_SETPIPE_SZ = 1031
PRINTER_OWNERS = {"print_answer", "_guarded_write", "_unstick"}
# last words and the hooks that end the process by themselves: written with the stop signals already ignored, and followed by _exit
LAST_WORDS = {"_stopped", "last_word", "_early_last_word", "interrupted_answer", "_unexpected", "unexpected", "_cannot_write", "_on_signal", "_unexpected_recipe", "_unexpected_tool"}


class StalledReader(Case):
    def scenarios(self):
        """tool -> args producing an answer far larger than 4096 bytes."""
        blob = self.write("work/blob.bin", b"needle PK\x03\x04 MZ\x90\x00 %PDF-1.4 \n" * 3000)
        names = "|".join("keyword%03d" % i for i in range(150))
        many = self.write("work/many.bin", ("\n".join("keyword%03d" % i for i in range(150))).encode())
        for i in range(600):
            self.write("work/tree/f%03d.bin" % i, b"MZ\x90\x00" + bytes([i % 256]) * 20)
        self.write("catalog/Disk.E01/p2048/filelist.txt", "".join("r/r %d-128-1:\tUsers/a/file%04d.log\n" % (i, i) for i in range(3000)))
        self.write("catalog/Disk.E01/partitions.txt", "002:  000:000   0000002048   ...   NTFS\n")
        files = []
        for i in range(300):
            self.write("inputs/f%03d.bin" % i, b"x" * 10)
            files.append({"path": "inputs/f%03d.bin" % i, "bytes": 10, "sha256": "0" * 64})
        self.write("inputs.json", json.dumps({"files": files}))
        db = self.path("work", "s.db")
        c = sqlite3.connect(db)
        c.execute("create table t(x)")
        c.executemany("insert into t values (?)", [("row %d" % i * 3,) for i in range(1500)])
        c.commit()
        c.close()
        z = self.path("work", "a.zip")
        with zipfile.ZipFile(z, "w") as zf:
            for i in range(300):
                zf.writestr("m%04d.txt" % i, b"x")
        return {
            "sig_carve": {"path": blob, "sig": "all", "max_hits": 400},
            "ioc_scan": {"path": many, "needles": names, "max_hits": 300},
            "chunk_needles": {"path": blob, "needles": "needle|MZ"},
            "file_type": {"path": "work/tree", "limit": 500},
            "check_inputs": {},
            "catalog_search": {"pattern": "file", "limit": 400},
            "sqlite_query": {"db_path": db, "sql": "select * from t", "max_rows": 1000},
            "archive_extract": {"path": z, "out_dir": "work/ex", "limit": 300},
        }

    def start(self, tool, args, seconds):
        r, w = os.pipe()
        fcntl.fcntl(w, F_SETPIPE_SZ, 4096)
        e = dict(os.environ, TOOL_HELD_WRITE_SECONDS=str(seconds))
        for k in ("JOB_ID", "OUT", "AGENT_ID", "SECRET_OUTPUT"):
            e.pop(k, None)
        p = subprocess.Popen([sys.executable, tool_path(tool)], stdin=subprocess.PIPE, stdout=w, stderr=subprocess.PIPE, cwd=self.dir, env=e)
        os.close(w)
        p.stdin.write(json.dumps(args).encode())
        p.stdin.close()
        return p, r

    def test_a_stalled_reader_is_a_wait_not_a_cut_and_a_signal_ends_the_tool_after_the_bound(self):
        started = 0
        for tool, args in self.scenarios().items():
            for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
                if os.path.exists(self.path("work", "ex")):
                    import shutil
                    shutil.rmtree(self.path("work", "ex"))
                with self.subTest(tool=tool, signal=sig.name):
                    p, r = self.start(tool, args, 3)
                    try:
                        time.sleep(2.0)
                        if p.poll() is not None:
                            self.skipTest("%s answered in less than the pipe holds (exit %s)" % (tool, p.returncode))
                        started += 1
                        p.send_signal(sig)
                        try:
                            p.wait(timeout=20)
                        except subprocess.TimeoutExpired:
                            self.fail("%s: a stalled reader made the tool immune to %s" % (tool, sig.name))
                        said = p.stderr.read()
                        self.assertEqual(p.returncode, 128 + int(sig), (tool, sig.name, said[-300:]))
                        self.assertIn(b"could not be written", said)
                    finally:
                        if p.poll() is None:
                            p.kill()
                            p.wait()
                        p.stderr.close()
                        os.close(r)
        self.assertGreaterEqual(started, 24, "the scenarios did not block the printer")

    def test_a_reader_that_starts_again_gets_the_whole_document(self):
        for tool, args in self.scenarios().items():
            with self.subTest(tool=tool):
                p, r = self.start(tool, args, 30)
                time.sleep(1.0)
                chunks = []
                with os.fdopen(r, "rb") as fh:
                    chunks.append(fh.read())
                p.wait(timeout=30)
                p.stderr.close()
                doc = json.loads(b"".join(chunks))
                self.assertIn(doc.get("status"), ("complete", "partial", "failed"))


class OnePrinter(Case):
    def test_no_answer_is_printed_outside_the_printer_or_a_last_word(self):
        """Every print(json.dumps(...)) and sys.stdout.write(json.dumps(...)) of a tool or a recipe is inside the protected printer or a last word."""
        bad = []
        for kind in ("tools", "recipes"):
            for name in sorted(os.listdir(os.path.join(PACK_DIR, kind))):
                f = os.path.join(PACK_DIR, kind, name, "run.py")
                if not os.path.exists(f):
                    continue
                with open(f, encoding="utf-8") as src:
                    tree = ast.parse(src.read())
                parents = {}
                for node in ast.walk(tree):
                    for child in ast.iter_child_nodes(node):
                        parents[child] = node
                for node in ast.walk(tree):
                    if not (isinstance(node, ast.Call) and node.args):
                        continue
                    fn = node.func
                    is_print = isinstance(fn, ast.Name) and fn.id == "print"
                    is_write = isinstance(fn, ast.Attribute) and fn.attr == "write" and isinstance(fn.value, ast.Attribute) and fn.value.attr == "stdout"
                    if not (is_print or is_write):
                        continue
                    arg = node.args[0]
                    if not (isinstance(arg, ast.Call) and isinstance(arg.func, ast.Attribute) and arg.func.attr == "dumps"
                            or isinstance(arg, ast.BinOp) and isinstance(arg.left, ast.Call) and isinstance(arg.left.func, ast.Attribute) and arg.left.func.attr == "dumps"):
                        continue
                    up, owner = node, None
                    while up in parents:
                        up = parents[up]
                        if isinstance(up, ast.FunctionDef):
                            owner = up.name
                            if owner in PRINTER_OWNERS | LAST_WORDS:
                                break
                    if owner is None or owner not in PRINTER_OWNERS | LAST_WORDS:
                        bad.append("%s/%s line %d (in %s)" % (kind, name, node.lineno, owner))
        self.assertEqual(bad, [], "an answer is printed without the protected printer:\n" + "\n".join(bad))


if __name__ == "__main__":
    import unittest
    unittest.main()
