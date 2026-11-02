"""A write that can fail is checked, and the answer claims no more than was written.

Each scenario is run once without a limit, to learn how big its largest output is, and then at fifteen file-size limits (RLIMIT_FSIZE) from a
few bytes to one byte more than that largest output. At every size: one JSON document on stdout, no traceback, no death by SIGXFSZ, every
JSON status file that exists parses (it is whole or absent), and an answer that says `complete` has no new file that reached the limit.
"""
import json
import os
import resource
import shutil
import sqlite3
import subprocess
import sys
import zipfile

from support import Case, recipe_path, stand_in, tool_path

MMLS = """GUID Partition Table (EFI)
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Safety Table
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  000       0000002048   0000002559   0000000512   data
"""


def sizes_for(largest):
    low = 40
    out = {int(low + (largest + 1 - low) * k / 14) for k in range(15)}
    out.add(largest + 1)
    return sorted(s for s in out if s > 0)


def files_under(root):
    found = {}
    for base, _dirs, names in os.walk(root):
        for n in names:
            p = os.path.join(base, n)
            try:
                found[p] = os.path.getsize(p)
            except OSError:
                pass
    return found


class WriteSweep(Case):
    # ---- the scenarios: each builds its fixtures under `d` and returns (argv, stdin, env_extra)
    def stand_ins(self, d):
        b = os.path.join(d, "bin")
        os.makedirs(b, exist_ok=True)
        stand_in(b, "mmls", "cat <<'EOF'\n%sEOF\n" % MMLS)
        stand_in(b, "fsstat", "echo 'File System Type: Ext4'\necho 'Block Size: 4096'\n")
        stand_in(b, "fls", 'i=0\nwhile [ $i -lt 700 ]; do echo "r/r $i-128-1:\tdir/file$i.txt"; i=$((i+1)); done\n')
        stand_in(b, "mactime", 'i=0\nwhile [ $i -lt 700 ]; do echo "2020-01-01T00:00:00Z,$i,m...,r/rrwxrwxrwx,0,0,$i,/dir/file$i.txt"; i=$((i+1)); done\n')
        stand_in(b, "vol", 'case "$*" in *windows.info*) echo "NTBuildLab 19041.1"; echo "Kernel Base 0x0"; echo "SystemTime 2020-01-01";; *) i=0; while [ $i -lt 700 ]; do echo "row $i of a plugin table"; i=$((i+1)); done;; esac\n')
        return b

    def scenario_disk_volumes(self, d):
        b = self.stand_ins(d)
        img = os.path.join(d, "disk.img")
        with open(img, "wb") as fh:
            fh.write(b"\0" * 65536)
        target = json.dumps({"paths": [img], "name": "disk.img"})
        return ["bash", recipe_path("disk-volumes", "run.sh"), "run", "--target", target, "--out", os.path.join(d, "out")], None, b

    def scenario_memory_windows(self, d):
        b = self.stand_ins(d)
        img = os.path.join(d, "mem.raw")
        with open(img, "wb") as fh:
            fh.write(b"\0" * 65536)
        target = json.dumps({"paths": [img], "name": "mem.raw"})
        return ["bash", recipe_path("memory-windows", "run.sh"), "run", "--target", target, "--out", os.path.join(d, "out")], None, b

    def scenario_archive_members(self, d):
        z = os.path.join(d, "many.zip")
        with zipfile.ZipFile(z, "w") as zf:
            for i in range(300):
                zf.writestr("member-%04d.txt" % i, b"x")
        target = json.dumps({"paths": [z], "name": "many.zip"})
        return [sys.executable, recipe_path("archive-members", "run.py"), "run", "--target", target, "--out", os.path.join(d, "out")], None, None

    def tool(self, name, args):
        return [sys.executable, tool_path(name)], json.dumps(args), None

    def scenario_tool_catalog_search(self, d):
        os.makedirs(os.path.join(d, "catalog", "Disk.E01", "p2048"))
        with open(os.path.join(d, "catalog", "Disk.E01", "p2048", "filelist.txt"), "w") as fh:
            fh.write("".join("r/r %d-128-1:\tUsers/a/file%04d.log\n" % (i, i) for i in range(1500)))
        with open(os.path.join(d, "catalog", "Disk.E01", "partitions.txt"), "w") as fh:
            fh.write("002:  000:000   0000002048   ...   NTFS\n")
        return self.tool("catalog_search", {"pattern": "file", "limit": 5})

    def scenario_tool_ioc_scan(self, d):
        os.makedirs(os.path.join(d, "work"))
        with open(os.path.join(d, "work", "blob.bin"), "wb") as fh:
            fh.write(b"needle PK MZ\n" * 2000)
        return self.tool("ioc_scan", {"path": "work/blob.bin", "needles": "needle|MZ"})

    def scenario_tool_chunk_needles(self, d):
        os.makedirs(os.path.join(d, "work"))
        with open(os.path.join(d, "work", "blob.bin"), "wb") as fh:
            fh.write(b"needle PK MZ\n" * 2000)
        return self.tool("chunk_needles", {"path": "work/blob.bin", "needles": "needle|MZ", "max_hits": 3})

    def scenario_tool_sig_carve(self, d):
        os.makedirs(os.path.join(d, "work"))
        with open(os.path.join(d, "work", "blob.bin"), "wb") as fh:
            fh.write(b"PK\x03\x04 MZ\x90\x00 %PDF-1.4 \n" * 2000)
        return self.tool("sig_carve", {"path": "work/blob.bin", "sig": "all", "max_hits": 4})

    def scenario_tool_file_type(self, d):
        for i in range(300):
            p = os.path.join(d, "work", "tree", "f%03d.bin" % i)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "wb") as fh:
                fh.write(b"MZ\x90\x00" + bytes([i % 256]) * 20)
        return self.tool("file_type", {"path": "work/tree", "limit": 5})

    def scenario_tool_check_inputs(self, d):
        files = []
        for i in range(260):
            os.makedirs(os.path.join(d, "inputs"), exist_ok=True)
            with open(os.path.join(d, "inputs", "f%03d.bin" % i), "wb") as fh:
                fh.write(b"x" * 10)
            files.append({"path": "inputs/f%03d.bin" % i, "bytes": 10, "sha256": "0" * 64})
        with open(os.path.join(d, "inputs.json"), "w") as fh:
            json.dump({"files": files}, fh)
        return self.tool("check_inputs", {})

    def scenario_tool_sqlite_query(self, d):
        os.makedirs(os.path.join(d, "work"))
        c = sqlite3.connect(os.path.join(d, "work", "s.db"))
        c.execute("create table t(x)")
        c.executemany("insert into t values (?)", [("row %d" % i * 3,) for i in range(1200)])
        c.commit()
        c.close()
        return self.tool("sqlite_query", {"db_path": "work/s.db", "sql": "select * from t", "max_rows": 10})

    def scenario_tool_sqlite_snapshot(self, d):
        os.makedirs(os.path.join(d, "work"))
        c = sqlite3.connect(os.path.join(d, "work", "s.db"))
        c.execute("create table t(x)")
        c.executemany("insert into t values (?)", [("row %d" % i,) for i in range(300)])
        c.commit()
        c.close()
        return self.tool("sqlite_snapshot", {"db_path": "work/s.db", "out_dir": "work/snap"})

    def scenario_tool_archive_extract(self, d):
        os.makedirs(os.path.join(d, "work"))
        with zipfile.ZipFile(os.path.join(d, "work", "a.zip"), "w") as zf:
            for i in range(120):
                zf.writestr("m%03d.txt" % i, b"member %d" % i * 3)
        return self.tool("archive_extract", {"path": "work/a.zip", "out_dir": "work/ex", "limit": 5})

    def scenario_tool_file_carver(self, d):
        os.makedirs(os.path.join(d, "work"))
        with zipfile.ZipFile(os.path.join(d, "work", "z.zip"), "w") as zf:
            zf.writestr("big.bin", os.urandom(3000))
        return self.tool("file_carver", {"path": "work/z.zip", "offset": 0, "sig_type": "ZIP", "output": "work/carved.zip"})

    # ---- the sweep
    def execute(self, name, limit):
        d = self.path("run-%s-%s" % (name, limit if limit else "free"))
        os.makedirs(d)
        argv, stdin, extra = getattr(self, "scenario_" + name)(d)
        extra_path = extra if isinstance(extra, str) else None
        before = files_under(d)
        env = dict(os.environ)
        for k in ("JOB_ID", "OUT", "AGENT_ID", "SECRET_OUTPUT"):
            env.pop(k, None)
        if extra_path:
            env["PATH"] = extra_path + os.pathsep + env["PATH"]

        def limiter():
            if limit:
                resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))

        try:
            p = subprocess.run(argv, input=stdin, capture_output=True, text=True, cwd=d, env=env, timeout=120, preexec_fn=limiter)
        except subprocess.TimeoutExpired:
            self.fail("%s at %s: timed out" % (name, limit))
        after = files_under(d)
        new = {k: v for k, v in after.items() if k not in before or before[k] != v}
        return p, new, d

    def sweep(self, name):
        p, new, d = self.execute(name, 0)
        self.assertTrue(new, "%s wrote nothing without a limit: %r %r" % (name, p.stdout[:200], p.stderr[-200:]))
        largest = max(new.values())
        bad = []
        for limit in sizes_for(largest):
            p, new, d = self.execute(name, limit)
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
                why = "no JSON on stdout (exit %s) %r %r" % (p.returncode, p.stdout[:80], p.stderr[-160:].replace("\n", " "))
            if why is None and p.returncode < 0:
                why = "killed by signal %d" % -p.returncode
            if why is None and "Traceback" in p.stderr:
                why = "traceback on stderr: %r" % p.stderr[-200:].replace("\n", " ")
            if why is None:
                for path in new:
                    if path.endswith((".json",)) and os.path.exists(path):
                        try:
                            with open(path, encoding="utf-8") as fh:
                                json.load(fh)
                        except ValueError:
                            why = "%s is cut JSON" % os.path.relpath(path, d)
                            break
            if why is None and isinstance(doc, dict) and doc.get("status") == "complete":
                cut = sorted(os.path.relpath(k, d) for k, v in new.items() if v >= limit and not k.endswith(".json"))
                if cut:
                    why = "says complete but %s reached the limit" % cut[:3]
                elif doc.get("complete") is False:
                    why = "complete status with complete/ok false"
            if why is not None:
                bad.append("limit %d: %s" % (limit, why))
        self.assertEqual(bad, [], "%s:\n%s" % (name, "\n".join(bad)))

    def test_disk_volumes(self):
        self.sweep("disk_volumes")

    def test_memory_windows(self):
        self.sweep("memory_windows")

    def test_archive_members(self):
        self.sweep("archive_members")

    def test_tools(self):
        failed = []
        for n in ("catalog_search", "ioc_scan", "chunk_needles", "sig_carve", "file_type", "check_inputs", "sqlite_query", "sqlite_snapshot",
                  "archive_extract", "file_carver"):
            try:
                self.sweep("tool_" + n)
            except AssertionError as exc:
                failed.append(str(exc)[:900])
        self.assertEqual(failed, [], "\n".join(failed))


if __name__ == "__main__":
    import unittest
    unittest.main()
