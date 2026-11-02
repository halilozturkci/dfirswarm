"""An error nobody foresaw ends in one JSON document and leaves no hidden temporary file.

A sitecustomize.py on PYTHONPATH makes the Nth call of time.monotonic, os.fstat, os.stat or os.lstat raise RuntimeError, counted from the moment
the tool has installed its last-resort hook. Each tool is run once clean to learn how many such calls it makes, and then with the fault at a spread
of values of N (the first eight and four more up to the last). At every one: the whole of stdout is one JSON document, the process was not killed
by a signal, and no dot-file is left anywhere under the working directory that was not there before.

Covered: archive_extract, feature_scan, file_carver, file_type, image_layout, ioc_scan, sig_carve, sqlite_query, sqlite_snapshot, timeline_super,
timestamp_decode (ad1_extract is held to the same in tests/ad1-pack.test.ts, which has the AD1 image builder).
"""
import json
import os
import subprocess
import sys
import unittest

import test_hostile_out_matrix as hom
import test_write_sweep as tws
from support import stand_in, tool_path

SITECUSTOMIZE = r'''
import atexit, json, os, sys, time
_spec = os.environ.get("FAULT", "")
_label, _, _n = _spec.partition(":")
_target = int(_n) if _n else None
counts = {}
def _wrap(mod, name, label):
    real = getattr(mod, name)
    def f(*a, **k):
        if sys.excepthook is not sys.__excepthook__:         # counted from the moment the tool has installed its hook
            counts[label] = counts.get(label, 0) + 1
            if label == _label and counts[label] == _target:
                raise RuntimeError("injected fault")
        return real(*a, **k)
    setattr(mod, name, f)
_wrap(time, "monotonic", "monotonic")
_wrap(os, "fstat", "fstat")
_wrap(os, "stat", "stat")
_wrap(os, "lstat", "lstat")
if os.environ.get("FAULT_COUNTS"):
    def _save():
        with open(os.environ["FAULT_COUNTS"], "w") as fh:
            json.dump(counts, fh)
    atexit.register(_save)
'''

LABELS = ("monotonic", "fstat", "stat", "lstat")


def dotfiles(root):
    found = set()
    for base, dirs, names in os.walk(root, onerror=lambda e: None):
        for n in dirs + names:
            if n.startswith("."):
                found.add(os.path.relpath(os.path.join(base, n), root))
    return found


def spread(k):
    """The first eight values of N, and four more spread up to the last call."""
    if k <= 0:
        return []
    chosen = set(range(1, min(k, 8) + 1))
    if k > 8:
        for i in range(1, 5):
            chosen.add(8 + (k - 8) * i // 4)
    return sorted(chosen)


class FaultInjection(tws.Scenarios):
    sc_timeline_super = hom.HostileOut.sc_timeline_super
    sc_feature_scan = hom.HostileOut.sc_feature_scan

    def sc_image_layout(self, w, out):
        b = os.path.join(w, "bin")
        os.makedirs(b)
        stand_in(b, "mmls", "cat <<'EOF'\n%sEOF\n" % tws.MMLS)
        stand_in(b, "fsstat", "echo 'File System Type: Ext4'\necho 'Block Size: 4096'\n")
        os.makedirs(os.path.join(w, "inputs"))
        with open(os.path.join(w, "inputs", "d.img"), "wb") as fh:
            fh.write(b"\0" * 65536)
        return [sys.executable, tool_path("image_layout")], json.dumps({"image": "inputs/d.img"}), b

    def sc_timestamp_decode(self, w, out):
        return [sys.executable, tool_path("timestamp_decode")], json.dumps({"value": "1700000000"}), None

    def sc_tool(self, name, w, out):
        # the fixtures of the write sweep, built under w
        argv, stdin, extra = getattr(self, "scenario_tool_" + name)(w)
        return argv, stdin, extra

    def run_once(self, name, fault, w, counts_file=None):
        os.makedirs(w)
        if name in ("timeline_super", "feature_scan", "image_layout", "timestamp_decode"):
            argv, stdin, extra = getattr(self, "sc_" + name)(w, "work/out")
        else:
            argv, stdin, extra = self.sc_tool(name, w, "work/out")
        env = dict(os.environ)
        for k in ("JOB_ID", "OUT", "AGENT_ID", "SECRET_OUTPUT"):
            env.pop(k, None)
        site = os.path.join(self.path("site"))
        os.makedirs(site, exist_ok=True)
        with open(os.path.join(site, "sitecustomize.py"), "w") as fh:
            fh.write(SITECUSTOMIZE)
        env["PYTHONPATH"] = site
        env["FAULT"] = fault
        if counts_file:
            env["FAULT_COUNTS"] = counts_file
        if isinstance(extra, str):
            env["PATH"] = extra + os.pathsep + env["PATH"]
        before = dotfiles(w)
        p = subprocess.run(argv, input=stdin, capture_output=True, text=True, cwd=w, env=env, timeout=90)
        return p, dotfiles(w) - before

    def inject(self, name):
        counts_file = self.path("counts-%s.json" % name)
        p, _left = self.run_once(name, "", self.path("clean-%s" % name), counts_file)
        self.assertTrue(p.stdout.strip(), "%s: a clean run said nothing: %r" % (name, p.stderr[-200:]))
        with open(counts_file) as fh:
            counts = json.load(fh)
        bad = []
        run_no = 0
        for label in LABELS:
            for n in spread(counts.get(label, 0)):
                run_no += 1
                p, left = self.run_once(name, "%s:%d" % (label, n), self.path("inj-%s-%03d" % (name, run_no)))
                why = None
                try:
                    json.loads(p.stdout)
                except ValueError:
                    why = "stdout is not one JSON document (exit %s) %r %r" % (p.returncode, p.stdout[:80], p.stderr[-160:].replace("\n", " "))
                if why is None and p.returncode < 0:
                    why = "killed by signal %d" % -p.returncode
                if why is None and left:
                    why = "left behind %s" % sorted(left)[:3]
                if why:
                    bad.append("%s@%d: %s" % (label, n, why))
        self.assertEqual(bad, [], "%s:\n%s" % (name, "\n".join(bad)))


def _add(name):
    def test(self):
        self.inject(name)
    test.__name__ = "test_" + name
    setattr(FaultInjection, test.__name__, test)


for _n in ("archive_extract", "feature_scan", "file_carver", "file_type", "image_layout", "ioc_scan", "sig_carve", "sqlite_query",
           "sqlite_snapshot", "timeline_super", "timestamp_decode"):
    _add(_n)


if __name__ == "__main__":
    unittest.main()
