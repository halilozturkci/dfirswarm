"""A write the file system refuses ends a tool with its JSON, and leaves no hidden temporary file behind.

The tools are run with a file-size limit (RLIMIT_FSIZE, so a write past it fails with EFBIG exactly as a full disk fails with ENOSPC; Python
ignores SIGXFSZ). Whatever a tool tried to write -- its all-matches file, a page of rows, a receipt, a carved file -- the answer is one JSON on
stdout, no traceback, and no `.name` temporary file in the run directory afterwards.
"""
import json
import os
import resource
import sqlite3
import subprocess
import sys
import zipfile

from support import Case, stand_in, tool_path

LIMIT = 300


def limited():
    resource.setrlimit(resource.RLIMIT_FSIZE, (LIMIT, LIMIT))


def hidden_files(root):
    found = []
    for base, dirs, files in os.walk(root):
        found += [os.path.join(base, n) for n in files + dirs if n.startswith(".") or ".tmp." in n or n.endswith(".tmp")]
    return found


class WriteFailures(Case):
    def run_limited(self, name, args, path_dirs=()):
        env = dict(os.environ)
        env["PATH"] = os.pathsep.join(list(path_dirs) + [env.get("PATH", "")])
        for k in ("JOB_ID", "OUT", "AGENT_ID", "SECRET_OUTPUT"):
            env.pop(k, None)
        p = subprocess.run([sys.executable, tool_path(name)], input=json.dumps(args), capture_output=True, text=True, cwd=self.dir, env=env,
                           timeout=120, preexec_fn=limited)
        self.assertNotIn("Traceback", p.stderr[-600:], name)
        try:
            doc = json.loads(p.stdout)
        except ValueError:
            self.fail("%s printed no JSON: %r %r" % (name, p.stdout[:200], p.stderr[-200:]))
        self.assertEqual(hidden_files(self.dir), [], "%s left a hidden temporary file" % name)
        self.assertIn(doc.get("status"), ("complete", "partial", "failed"), name)
        if os.environ.get("WF_VERBOSE"):
            sys.stderr.write("%s: %s %s\n" % (name, doc.get("status"), (doc.get("error") or doc.get("status_basis") or "")[:150]))
        # status, complete and ok are one fact: a partial or failed answer is never `complete: true`, a failed one is never `ok: true`
        if doc["status"] in ("partial", "failed"):
            self.assertIsNot(doc.get("complete"), True, "%s says complete with status %s: %r" % (name, doc["status"], doc))
        if doc["status"] == "failed":
            self.assertIsNot(doc.get("ok"), True, name)
        return doc

    def test_catalog_search_whose_all_matches_file_cannot_be_written(self):
        self.write("catalog/Disk.E01/p2048/filelist.txt", "".join("r/r %d-128-1:\tUsers/a/file%04d.log\n" % (i, i) for i in range(5000)))
        self.write("catalog/Disk.E01/partitions.txt", "002:  000:000   0000002048   ...   NTFS\n")
        doc = self.run_limited("catalog_search", {"pattern": "file", "limit": 5})
        self.assertEqual((doc["matched"], doc["returned"], doc["status"]), (5000, 5, "partial"), doc)
        self.assertIn("all_matches_error", doc)
        self.assertNotIn("all_matches", doc)

    def zip_bytes(self):
        import io
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("big.bin", os.urandom(6000))
        return buf.getvalue()

    def tree(self):
        for i in range(400):
            self.write("work/tree/f%03d.bin" % i, b"MZ\x90\x00" + bytes([i % 256]) * 40)
        return "work/tree"

    def test_the_scanners_and_pagers(self):
        blob = self.write("work/blob.bin", (b"needle PK\x03\x04 MZ\x90\x00 %PDF-1.4 \x89PNG\r\n\x1a\n\n") * 4000)
        for name, args in (("ioc_scan", {"path": blob, "needles": "needle"}), ("chunk_needles", {"path": blob, "needles": "needle"}),
                           ("sig_carve", {"path": blob, "sig": "all", "max_hits": 5}), ("file_type", {"path": self.tree(), "limit": 5}),
                           ("file_carver", {"path": self.write("work/z.bin", self.zip_bytes()), "offset": 0, "sig_type": "ZIP", "output": "work/carved/z.bin"}),
                           ("image_layout", {"image": blob})):
            with self.subTest(tool=name):
                self.run_limited(name, args)

    def test_check_inputs_and_the_sqlite_tools(self):
        files = []
        for i in range(300):
            self.write("inputs/f%03d.bin" % i, b"x" * 10)
            files.append({"path": "inputs/f%03d.bin" % i, "bytes": 10, "sha256": "0" * 64})
        self.write("inputs.json", json.dumps({"files": files}))
        self.run_limited("check_inputs", {})
        db = self.path("work", "s.db")
        os.makedirs(os.path.dirname(db), exist_ok=True)
        conn = sqlite3.connect(db)
        conn.execute("create table t(x)")
        conn.executemany("insert into t values (?)", [("row %d" % i * 4,) for i in range(2000)])
        conn.commit()
        conn.close()
        self.run_limited("sqlite_query", {"db_path": db, "sql": "select * from t", "max_rows": 10})
        self.run_limited("sqlite_snapshot", {"db_path": db, "out_dir": "work/snap"})

    def test_archive_extract_whose_member_cannot_be_written(self):
        z = self.path("work", "a.zip")
        os.makedirs(os.path.dirname(z))
        with zipfile.ZipFile(z, "w") as zf:
            zf.writestr("big.bin", os.urandom(5000))
        self.run_limited("archive_extract", {"path": z, "out_dir": "work/ex"})

    def test_icat_extract_whose_output_cannot_be_written(self):
        d = self.path("bin")
        os.makedirs(d)
        stand_in(d, "icat", "head -c 5000 /dev/zero\n")
        img = self.write("work/img.dd", b"\0" * 1024)
        self.run_limited("icat_extract", {"image": img, "inode": "5", "output": "work/o.bin"}, [d])
