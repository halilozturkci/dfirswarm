"""A full disk: a write that fails midway is reported, nothing is left behind, and a `complete` answer means every file was written whole.

`ulimit -f` (test_write_sweep.py) refuses a write past a size; a full file system lets the first bytes in and fails the rest, and fails a
close() that flushes. Each scenario of test_write_sweep.py runs inside `unshare -rm` on a tmpfs mounted over its working directory, sized from
the room its inputs take plus a few KiB up to 1.6 times what the run writes, with page-boundary sizes around that. At every size: one JSON
document on stdout, no traceback, no death by signal, every new *.json parses, no hidden or .tmp file is left that a complete run does not
leave, and an answer that says `complete` has every file a complete run has, at the size a complete run makes it.

Skipped, with the reason, where `unshare -rm` and a tmpfs mount are not allowed. Run here: they are.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

import test_write_sweep as tws
from support import stand_in

WRAP = r'''set -u
SRC=$1; SIZE=$2; REPORT=$3; COPY=$4; shift 4
STASH=$(mktemp -d /tmp/enospc-stash.XXXXXX) || exit 96
cp -a "$SRC"/. "$STASH"/ || exit 96
mount -t tmpfs -o size="$SIZE" tmpfs "$SRC" || exit 97
cp -a "$STASH"/. "$SRC"/ || exit 98
rm -rf "$STASH"
U0=$(df --output=used -B1 "$SRC" | tail -1 | tr -d ' ')
cd "$SRC"
"$@"
rc=$?
U1=$(df --output=used -B1 "$SRC" | tail -1 | tr -d ' ')
echo "$U0 $U1 $rc" > "$REPORT"
cp -a "$SRC"/. "$COPY"/
exit $rc
'''

PAGE = 4096


def can_mount():
    d = tempfile.mkdtemp(prefix="enospc-probe-")
    try:
        r = subprocess.run(["unshare", "-rm", "bash", "-c", 'mount -t tmpfs -o size=64k tmpfs "$1" && echo ok', "x", d],
                           capture_output=True, text=True, timeout=30)
        return r.stdout.strip() == "ok", (r.stderr.strip() or "no output")
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)
    finally:
        shutil.rmtree(d, ignore_errors=True)


MOUNT_OK, MOUNT_WHY = can_mount()


def room_sizes(used, written):
    """tmpfs sizes: what the inputs take, plus from 8 KiB to 1.6 times the output, and the page boundaries around the output."""
    top = int(written * 1.6) + PAGE
    extra = {PAGE * 2}
    for k in range(1, 15):
        extra.add(int(top * k / 14) // PAGE * PAGE)
    for delta in (-PAGE, 0, PAGE):
        extra.add((written + delta) // PAGE * PAGE)
    extra = sorted(e for e in extra if 0 < e <= top)
    return [used + e for e in extra]


BALLAST = 8 * 16384          # what the "freed" scenarios give back, one 16 KiB file after each step


class EnospcSweep(tws.Scenarios):
    FREED = {"disk_volumes_freed": BALLAST, "memory_windows_freed": BALLAST}

    def with_ballast(self, d, argv, stdin, b, programs):
        """Another job on a shared disk frees space just after a step ends: each stand-in program removes one ballast file when it finishes, so a
        look at the disk at the end of the run finds room that was not there while the output was written."""
        for i in range(8):
            with open(os.path.join(d, "ballast-%d.bin" % i), "wb") as fh:
                fh.write(b"\0" * 16384)
        free = 'rm -f "$(ls %s/ballast-*.bin 2>/dev/null | head -1)"\n' % d
        for name in programs:
            path = os.path.join(b, name)
            body = open(path).read()
            with open(path, "w") as fh:
                fh.write(body + free)
        return argv, stdin, b

    def scenario_disk_volumes_freed(self, d):
        argv, stdin, b = self.scenario_disk_volumes(d)
        return self.with_ballast(d, argv, stdin, b, ("fls", "mactime", "fsstat"))

    def scenario_memory_windows_freed(self, d):
        argv, stdin, b = self.scenario_memory_windows(d)
        return self.with_ballast(d, argv, stdin, b, ("vol", "fsstat"))

    def scenario_tool_feature_scan(self, d):
        b = os.path.join(d, "bin")
        os.makedirs(b)
        stand_in(b, "bulk_extractor",
                 'while [ $# -gt 0 ]; do case "$1" in -o) OUTDIR="$2"; shift;; esac; shift; done\n'
                 'mkdir -p "$OUTDIR"\n'
                 'i=0; while [ $i -lt 1500 ]; do echo "$((i*16))\tperson$i@example.test\tcontext of the hit number $i"; i=$((i+1)); done > "$OUTDIR/email.txt"\n'
                 'i=0; while [ $i -lt 400 ]; do echo "n=$i\tperson$i@example.test"; i=$((i+1)); done > "$OUTDIR/email_histogram.txt"\n'
                 'echo scanning\nexit 0\n')
        os.makedirs(os.path.join(d, "inputs"))
        with open(os.path.join(d, "inputs", "blob.raw"), "wb") as fh:
            fh.write(b"\0" * 64)
        argv, stdin, _ = self.tool("feature_scan", {"path": "inputs/blob.raw", "out_dir": "work/features"})
        return argv, stdin, b

    def run_in_full_disk(self, name, size):
        # The run directory's name has the same length at every size, so a file that holds its own path is the same size in every run.
        self.runs = getattr(self, "runs", 0) + 1
        tag = "%s-%04d" % (name, self.runs)
        d = self.path("run-" + tag)
        os.makedirs(d)
        argv, stdin, extra = getattr(self, "scenario_" + name)(d)
        before = tws.files_under(d)
        report, copy = self.path("report-" + tag), self.path("copy-" + tag)
        os.makedirs(copy)
        env = dict(os.environ)
        for k in ("JOB_ID", "OUT", "AGENT_ID", "SECRET_OUTPUT"):
            env.pop(k, None)
        if isinstance(extra, str):
            env["PATH"] = extra + os.pathsep + env["PATH"]
        wrapper = self.path("wrap.sh")
        with open(wrapper, "w") as fh:
            fh.write(WRAP)
        try:
            p = subprocess.run(["unshare", "-rm", "bash", wrapper, d, str(size), report, copy] + argv, input=stdin, capture_output=True, text=True,
                               cwd="/", env=env, timeout=180)
        except subprocess.TimeoutExpired:
            self.fail("%s at %d bytes: timed out" % (name, size))
        used = written = None
        if os.path.exists(report):
            u0, u1, _rc = open(report).read().split()
            used, written = int(u0), int(u1) - int(u0)
        after = {os.path.relpath(k, copy): v for k, v in tws.files_under(copy).items()}
        was = {os.path.relpath(k, d): v for k, v in before.items()}
        new = {k: v for k, v in after.items() if k not in was or was[k] != v}
        return p, new, copy, used, written

    def sweep_full_disk(self, name):
        p, new1, copy1, used, written = self.run_in_full_disk(name, 64 * 1024 * 1024)
        written += self.FREED.get(name, 0)
        self.assertTrue(written > 0, "%s wrote nothing on a roomy disk: %r %r" % (name, p.stdout[:200], p.stderr[-300:]))
        p2, new2, _c, _u, _w = self.run_in_full_disk(name, 64 * 1024 * 1024 + PAGE)
        stable = {k: v for k, v in new1.items() if new2.get(k) == v}
        known = set(new1) | set(new2)
        bad = []
        for size in room_sizes(used, written):
            p, new, copy, _u, _w = self.run_in_full_disk(name, size)
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
                for rel in new:
                    if rel.endswith(".json"):
                        try:
                            with open(os.path.join(copy, rel), encoding="utf-8") as fh:
                                json.load(fh)
                        except ValueError:
                            why = "%s is cut JSON" % rel
                            break
            if why is None:
                left = sorted(rel for rel in new if rel not in known and (os.path.basename(rel).startswith(".") or rel.endswith(".tmp")))
                if left:
                    why = "left behind: %s" % left[:3]
            if why is None and isinstance(doc, dict) and doc.get("status") == "complete":
                missing = sorted(k for k in stable if not k.endswith(".json") and new.get(k) != stable[k])
                if missing:
                    why = "says complete but %s is missing or not whole" % missing[:3]
                elif doc.get("complete") is False:
                    why = "complete status with complete false"
            if why is not None:
                bad.append("tmpfs %d (inputs %d + %d): %s" % (size, used, size - used, why))
        self.assertEqual(bad, [], "%s:\n%s" % (name, "\n".join(bad)))


def _add(name):
    def test(self):
        if not MOUNT_OK:
            self.skipTest("unshare -rm with a tmpfs mount is not allowed here: %s" % MOUNT_WHY)
        self.sweep_full_disk(name)
    test.__name__ = "test_" + name
    setattr(EnospcSweep, test.__name__, test)


for _n in ("disk_volumes", "memory_windows", "disk_volumes_freed", "memory_windows_freed", "archive_members", "tool_catalog_search", "tool_ioc_scan", "tool_chunk_needles", "tool_sig_carve",
           "tool_file_type", "tool_check_inputs", "tool_sqlite_query", "tool_sqlite_snapshot", "tool_archive_extract", "tool_file_carver",
           "tool_feature_scan"):
    _add(_n)


if __name__ == "__main__":
    unittest.main()
