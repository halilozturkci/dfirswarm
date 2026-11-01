"""SIGTERM, SIGINT and SIGHUP give one JSON answer, exit 128 + the signal and leave no hidden temporary file, in the base tools that carry the
windows-lineage STOP block: right after the block (the module has run as far as it and no further) and in the middle of real work.

The mid-work cases run each tool on a workload that lasts (a sparse file read for seconds, a stand-in `icat` that never ends, a pattern that backtracks) and
send the signal once the tool has made the hidden file it is writing; the stand-in programs record their pids so that their survival can be looked at.
"""
import json
import os
import signal
import subprocess
import sys
import time
import unittest

from support import Case, stand_in, tool_path

SIGNALS = (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)
TOOLS = ("catalog_search", "check_inputs", "chunk_needles", "file_carver", "icat_extract", "ioc_scan", "sig_carve", "sqlite_query")


def hidden_files(root):
    found = []
    for base, _dirs, files in os.walk(root):
        found += [os.path.join(base, n) for n in files if n.startswith(".")]
    return found


def alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    try:
        with open("/proc/%d/status" % pid) as fh:
            return "Z" not in fh.read().split("State:")[1].split("\n")[0]
    except (OSError, IndexError):
        return True


class StopSignals(Case):
    def env(self, bin_dir=None, **more):
        e = dict(os.environ)
        for k in ("JOB_ID", "OUT", "AGENT_ID", "SECRET_OUTPUT"):
            e.pop(k, None)
        if bin_dir:
            e["PATH"] = bin_dir + os.pathsep + e["PATH"]
        e.update(more)
        return e

    def test_a_stop_right_after_the_block_is_one_json_document_in_every_tool(self):
        for tool in TOOLS:
            with open(tool_path(tool), encoding="utf-8") as fh:
                text = fh.read()
            end = text.index("# END SHARED STOP")
            cut = text.index("\n", end) + 1
            for sig in SIGNALS:
                script = self.write("prefix.py", text[:cut] + "\nimport os as _os, signal as _s, time as _t\n_os.kill(_os.getpid(), _s.%s)\n_t.sleep(30)\nprint('survived')\n" % sig.name)
                proc = subprocess.run([sys.executable, script], cwd=self.dir, capture_output=True, text=True, timeout=60, env=self.env())
                self.assertEqual(proc.returncode, 128 + sig, (tool, sig.name, proc.stdout, proc.stderr))
                said = json.loads(proc.stdout)
                self.assertEqual((said["status"], said["interrupted"], said["signal"]), ("failed", True, int(sig)), tool)
                self.assertNotIn("Traceback", proc.stderr, tool)

    def midway(self, tool, args, ready, bin_dir=None, children=(), expect=None, after=None, timeout=60):
        """Run `tool` with `args`; once ready() is true send each signal in turn (a fresh run each) and check the one answer."""
        for sig in SIGNALS:
            for p in children:
                if os.path.exists(p):
                    os.unlink(p)
            args_file = self.path("args-%s-%d.json" % (tool, sig))
            with open(args_file, "w") as fh:
                json.dump(args, fh)
            with open(args_file) as stdin:
                proc = subprocess.Popen([sys.executable, tool_path(tool)], stdin=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                        cwd=self.dir, env=self.env(bin_dir, AGENT_ID="s%d" % sig))
            end = time.monotonic() + 30
            while time.monotonic() < end and proc.poll() is None and not ready(sig):
                time.sleep(0.02)
            if proc.poll() is not None:
                self.fail("%s ended before it could be signalled (%s): %s" % (tool, sig.name, proc.communicate()))
            self.assertTrue(ready(sig), "%s: never reached the point to signal (%s; hidden: %r)" % (tool, sig.name, hidden_files(self.dir)))
            pids = []
            for p in children:
                waited = time.monotonic() + 10
                while time.monotonic() < waited and not (os.path.exists(p) and os.path.getsize(p) > 0):
                    time.sleep(0.02)
                with open(p) as fh:
                    pids.append(int(fh.read().split()[0]))
            proc.send_signal(sig)
            try:
                stdout, stderr = proc.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.communicate()
                self.fail("%s did not stop on %s" % (tool, sig.name))
            self.assertEqual(proc.returncode, 128 + sig, (tool, sig.name, stdout[:300], stderr[-300:]))
            lines = [l for l in stdout.splitlines() if l.strip()]
            said = json.loads(stdout)
            self.assertEqual(len(lines), 1, "%s: one document: %r" % (tool, stdout[:300]))
            self.assertEqual((said["status"], said["interrupted"], said["signal"]), ("partial", True, int(sig)), (tool, stdout[:300]))
            self.assertNotIn("Traceback", stderr, tool)
            time.sleep(0.2)
            for pid in pids:
                self.assertFalse(alive(pid), "%s: pid %d survived %s" % (tool, pid, sig.name))
            self.assertEqual(hidden_files(os.path.join(self.dir, "work")), [], "%s left a hidden temporary file" % tool)
            if after:
                after(said, sig)

    def hidden_exists(self, sig=None):
        return bool(hidden_files(os.path.join(self.dir, "work")))

    def test_catalog_search_mid_search(self):
        self.write("catalog/Disk.E01/p2048/filelist.txt", ("a" * 40 + "\n") * 5)
        self.write("catalog/Disk.E01/partitions.txt", "002:  000:000   0000002048   ...   NTFS\n")
        self.midway("catalog_search", {"pattern": "(a*)*b"}, self.hidden_exists, after=lambda said, sig: self.assertIn("matched_so_far", said))

    def test_check_inputs_mid_hash(self):
        os.makedirs(self.path("inputs"))
        with open(self.path("inputs/big.bin"), "wb") as fh:
            fh.truncate(8 * 1024 ** 3)
        self.write("inputs.json", json.dumps({"files": [{"path": "inputs/big.bin", "bytes": 8 * 1024 ** 3, "sha256": "0" * 64}]}))

        def ready(sig):
            return any(n.startswith("check_inputs-receipts") for _b, _d, fs in os.walk(self.path("work/s%d" % sig)) for n in fs)
        self.midway("check_inputs", {"max_seconds": 100}, ready, after=lambda said, sig: self.assertIs(said["ok"], False))

    def test_ioc_scan_mid_scan(self):
        with open(self.path("big.bin"), "wb") as fh:
            fh.truncate(8 * 1024 ** 3)
        self.midway("ioc_scan", {"path": self.path("big.bin"), "needles": "zzzzzzzz"}, self.hidden_exists)

    def test_sig_carve_mid_scan(self):
        self.write("dump.bin", b"".join(b"\0" * 30 + b"\x89PNG\r\n\x1a\n" for _ in range(50)) + b"\0" * (24 * 1024 * 1024))
        self.midway("sig_carve", {"path": self.path("dump.bin"), "sig": "PNG", "max_hits": 1, "window_bytes": 16}, self.hidden_exists)

    def test_sqlite_query_mid_query(self):
        import sqlite3
        db = self.path("s.db")
        conn = sqlite3.connect(db)
        conn.execute("create table t(x)")
        conn.commit()
        conn.close()
        self.midway("sqlite_query", {"db_path": db, "sql": "with recursive c(x) as (select 1 union all select x+1 from c) select x from c", "limit": 1},
                    self.hidden_exists)

    def endless_icat(self, name):
        d = self.path("bin")
        os.makedirs(d, exist_ok=True)
        pids = self.path(name)
        stand_in(d, "icat", 'echo $$ > "%s"\nexec yes aaaaaaaaaa\n' % pids)
        self.write("inputs/disk.E01", b"x")
        return d, pids

    def test_chunk_needles_mid_stream_ends_icat(self):
        bin_dir, pids = self.endless_icat("icat.pid")
        self.midway("chunk_needles", {"needles": "aaaaaaaaaa", "inode": 12, "image": "inputs/disk.E01", "offset": 0, "max_hits": 1, "max_seconds": 100},
                    self.hidden_exists, bin_dir=bin_dir, children=[pids])

    def test_icat_extract_mid_stream_ends_icat_and_keeps_the_partial(self):
        bin_dir, pids = self.endless_icat("icat2.pid")

        def ready(sig):
            return any(n.startswith("out%d.bin.partial" % sig) and os.path.getsize(os.path.join(b, n)) > 0 for b, _d, fs in os.walk(self.path("work")) for n in fs)

        for sig in SIGNALS:
            out = "work/out%d.bin" % sig
            self.midway_one("icat_extract", {"inode": 12, "output": out, "image": "inputs/disk.E01", "offset": 0}, sig, lambda s=sig: ready(s), bin_dir, pids)

    def midway_one(self, tool, args, sig, ready, bin_dir, pids):
        args_file = self.path("args-%s-%d.json" % (tool, sig))
        with open(args_file, "w") as fh:
            json.dump(args, fh)
        with open(args_file) as stdin:
            proc = subprocess.Popen([sys.executable, tool_path(tool)], stdin=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=self.dir, env=self.env(bin_dir))
        end = time.monotonic() + 30
        while time.monotonic() < end and proc.poll() is None and not ready():
            time.sleep(0.02)
        self.assertTrue(ready(), "never reached the point to signal")
        with open(pids) as fh:
            pid = int(fh.read().split()[0])
        proc.send_signal(sig)
        stdout, stderr = proc.communicate(timeout=60)
        self.assertEqual(proc.returncode, 128 + sig, (stdout[:300], stderr[-300:]))
        said = json.loads(stdout)
        self.assertEqual((said["status"], said["interrupted"], said["signal"]), ("partial", True, int(sig)))
        self.assertIn(".partial", said["path"])
        self.assertTrue(os.path.exists(self.path(said["path"])), "what was written is kept under its partial name")
        time.sleep(0.2)
        self.assertFalse(alive(pid), "icat survived")
        self.assertEqual(hidden_files(os.path.join(self.dir, "work")), [])
        os.unlink(pids)


if __name__ == "__main__":
    unittest.main()
