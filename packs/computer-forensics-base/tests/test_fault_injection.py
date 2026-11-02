"""An error nobody foresaw, or a full disk, or an interrupt, ends in one JSON document (or a normal stop) and leaves no temporary file behind.

A sitecustomize.py on PYTHONPATH makes the Nth call of one of these raise: os.write, os.close, os.replace, os.rename, os.fsync, os.open, os.unlink,
os.fdopen, os.link, os.stat, os.fstat, os.lstat, builtins.open and time.monotonic. The fault is a RuntimeError, an OSError(ENOSPC) or a
KeyboardInterrupt. Calls are counted from the moment the tool has installed its last-resort hook. Each tool is run once clean to learn how many
calls of each kind it makes, and then with the fault at a sample of N (1, 2, 3, 5, 8, 13, 21 and the last call); with FAULT_FULL=1 at every N from 1
to 40 and a spread up to the last call (slow: run it before closing a pack).

At every run: the whole of stdout is one JSON document, or the process ended with a stop's exit code (128 or more); it was not killed by a signal
it did not handle; and no dot-file and no file with ".tmp" in its name is left under the working directory that was not there before. A fault in
os.unlink is the cleanup failing itself: it must still answer in JSON, and is not held to the leftover rule.

Covered: archive_extract, feature_scan, file_carver, file_type, image_layout, ioc_scan, sig_carve, sqlite_query, sqlite_snapshot, timeline_super,
timestamp_decode, chunk_needles, catalog_search and the recipes archive-members and disk-timeline (ad1_extract is held to the same in tests/ad1-pack.test.ts, which has the AD1 image builder).
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
import atexit, builtins, errno, json, os, sys, time
_spec = os.environ.get("FAULT", "")
_label, _, rest = _spec.partition(":")
_n, _, _kind = rest.partition(":")
_target = int(_n) if _n else None
counts = {}
def _fault():
    if _kind == "enospc":
        return OSError(errno.ENOSPC, "No space left on device")
    if _kind == "kbint":
        return KeyboardInterrupt()
    return RuntimeError("injected fault")
def _wrap(mod, name, label):
    real = getattr(mod, name)
    def f(*a, **k):
        if sys.excepthook is not sys.__excepthook__:         # counted from the moment the tool has installed its hook
            counts[label] = counts.get(label, 0) + 1
            if label == _label and counts[label] == _target:
                raise _fault()
        return real(*a, **k)
    setattr(mod, name, f)
_wrap(time, "monotonic", "time.monotonic")
for _name in ("write", "close", "replace", "rename", "fsync", "open", "unlink", "fdopen", "link", "stat", "fstat", "lstat"):
    _wrap(os, _name, "os." + _name)
_wrap(builtins, "open", "builtins.open")
if os.environ.get("FAULT_COUNTS"):
    def _save():
        with open(os.environ["FAULT_COUNTS"], "w") as fh:
            json.dump(counts, fh)
    atexit.register(_save)
'''

LABELS = ("time.monotonic", "os.write", "os.close", "os.replace", "os.rename", "os.fsync", "os.open", "os.unlink", "os.fdopen", "os.link",
          "os.stat", "os.fstat", "os.lstat", "builtins.open")
KINDS = ("runtime", "enospc", "kbint")
FULL = bool(os.environ.get("FAULT_FULL"))


def leftovers(root):
    found = set()
    for base, dirs, names in os.walk(root, onerror=lambda e: None):
        for n in dirs + names:
            if n.startswith(".") or ".tmp" in n:
                found.add(os.path.relpath(os.path.join(base, n), root))
    return found


def spread(k):
    """The values of N to try: a sample, or with FAULT_FULL every N up to 40 and a spread up to the last call."""
    if k <= 0:
        return []
    if FULL:
        chosen = set(range(1, min(k, 40) + 1))
        if k > 40:
            for i in range(1, 9):
                chosen.add(40 + (k - 40) * i // 8)
        return sorted(chosen)
    chosen = {n for n in (1, 2, 3, 5, 8, 13, 21) if n <= k}
    chosen.add(k)
    return sorted(chosen)


class FaultInjection(tws.Scenarios):
    sc_timeline_super = hom.HostileOut.sc_timeline_super
    sc_feature_scan = hom.HostileOut.sc_feature_scan
    sc_recipe_archive_members = hom.HostileOut.sc_recipe_archive_members
    sc_recipe_disk_timeline = hom.HostileOut.sc_recipe_disk_timeline
    recipe = hom.HostileOut.recipe

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
        return getattr(self, "scenario_tool_" + name)(w)

    def run_once(self, name, fault, w, counts_file=None):
        os.makedirs(w)
        if name in ("timeline_super", "feature_scan", "image_layout", "timestamp_decode", "recipe_archive_members", "recipe_disk_timeline"):
            argv, stdin, extra = getattr(self, "sc_" + name)(w, "work/out")
        else:
            argv, stdin, extra = self.sc_tool(name, w, "work/out")
        env = dict(os.environ)
        for k in ("JOB_ID", "OUT", "AGENT_ID", "SECRET_OUTPUT"):
            env.pop(k, None)
        site = self.path("site")
        os.makedirs(site, exist_ok=True)
        with open(os.path.join(site, "sitecustomize.py"), "w") as fh:
            fh.write(SITECUSTOMIZE)
        env["PYTHONPATH"] = site
        env["FAULT"] = fault
        if counts_file:
            env["FAULT_COUNTS"] = counts_file
        if isinstance(extra, str):
            env["PATH"] = extra + os.pathsep + env["PATH"]
        before = leftovers(w)
        p = subprocess.run(argv, input=stdin, capture_output=True, text=True, cwd=w, env=env, timeout=90)
        return p, leftovers(w) - before

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
                for kind in KINDS:
                    run_no += 1
                    p, left = self.run_once(name, "%s:%d:%s" % (label, n, kind), self.path("inj-%s-%04d" % (name, run_no)))
                    why = None
                    try:
                        json.loads(p.stdout)
                    except ValueError:
                        if not (p.returncode >= 128 and not p.stdout.strip()):
                            why = "stdout is not one JSON document (exit %s) %r %r" % (p.returncode, p.stdout[:80], p.stderr[-160:].replace("\n", " "))
                    if why is None and p.returncode < 0:
                        why = "killed by signal %d" % -p.returncode
                    if why is None and left and label != "os.unlink":
                        why = "left behind %s" % sorted(left)[:3]
                    if why:
                        bad.append("%s@%d %s: %s" % (label, n, kind, why))
        self.assertEqual(bad, [], "%s:\n%s" % (name, "\n".join(bad[:60])))


def _add(name):
    def test(self):
        self.inject(name)
    test.__name__ = "test_" + name
    setattr(FaultInjection, test.__name__, test)


for _n in ("archive_extract", "feature_scan", "file_carver", "file_type", "image_layout", "ioc_scan", "sig_carve", "sqlite_query",
           "sqlite_snapshot", "timeline_super", "timestamp_decode", "chunk_needles", "catalog_search", "recipe_archive_members", "recipe_disk_timeline"):
    _add(_n)


if __name__ == "__main__":
    unittest.main()
