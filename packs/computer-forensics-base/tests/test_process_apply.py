"""PKG-P4: the base pack's carriers answer for what a program leaves behind.

The shared PROCESS block ends what a program leaves behind (settle()) before the file it wrote is read; these carriers now call process_apply, or
put the verdict into their own status, so that a program that exits 0 and leaves a writer behind never answers `complete` over a file the program
wrote (archive_extract, browser_storage with write_values, feature_scan, image_verify, layer_describe, timeline_super), and the disk-timeline recipe,
which carries no shared block, does the same with a small mechanism of its own. Stand-ins only, with real abandoned children:

  held        a child that holds the file's descriptor (a redirect) and writes after the program exited 0
  setsid      the same in a session of its own
  double      the same, forked twice (its parent ends at once)
  byname      a child with no descriptor of the tool's or the program's, in the tool's group, that opens the file by name later
  periodic    a child in a session of its own that appends every 0.2 seconds, for ever
  rewrite     a child in a session of its own that truncates the file and writes it again

For each carrier and each variant the answer is `partial`, says what was ended (program_group.left_behind), the file is what the program wrote (the
child never wrote, and is not alive) and has not changed two seconds later. A clean run is still `complete`. Where the absence of a leftover cannot be
proven (the host is not Linux, or the kernel refuses PR_SET_CHILD_SUBREAPER: the tool is run with sys.platform patched, or with a libc whose prctl
fails) a run that wrote a file is at most `partial` and says why; a run that only printed on a pipe is not held to it.
The cases that fail on the batch head (before these carriers called process_apply) are all of these: the answer was `complete`.
"""
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import time
import unittest
from concurrent.futures import ThreadPoolExecutor

import browser_storage_fixtures as BF
import test_feature_scan as tfs
import test_image_verify as tiv
import test_layer_describe as tld
from support import Case, PACK_DIR, recipe_path, stand_in, tool_path

LINUX = unittest.skipUnless(sys.platform.startswith("linux"), "needs /proc and PR_SET_CHILD_SUBREAPER")
DELAY = 1.5                       # seconds before a leftover writes; the tool ends it long before
AFTER = DELAY + 1.0               # how long the files are watched after the tool has answered
VARIANTS = ("held", "setsid", "double", "byname", "periodic", "rewrite")
SEVEN_Z = next((p for p in ("7z", "7zz", "7za") if shutil.which(p)), None)

DARWIN = """
import sys, runpy
script = sys.argv[1]
sys.argv = sys.argv[1:]
sys.platform = "darwin"
runpy.run_path(script, run_name="__main__")
"""
REFUSED = """
import sys, runpy, ctypes
script = sys.argv[1]
sys.argv = sys.argv[1:]
class Refusing(object):
    def prctl(self, *a):
        return -1
ctypes.CDLL = lambda *a, **k: Refusing()
runpy.run_path(script, run_name="__main__")
"""
WRAPPERS = {"linux": None, "darwin": DARWIN, "refused": REFUSED}


def sha(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def leave(variant, pids, delay=DELAY):
    """sh that starts a leftover and goes on: it writes to "$F" (a variable the stand-in sets) `delay` seconds later, and writes its pid to `pids`."""
    d = "%s" % delay
    body = 'echo $$ >> "$1"; sleep %s; echo LEFTOVER-WROTE' % d
    by_name = 'echo $$ >> "$1"; sleep %s; echo LEFTOVER-WROTE >> "$2"' % d
    if variant == "held":
        return 'sh -c \'%s\' sh "%s" >> "$F" 2>/dev/null &\n' % (body, pids)
    if variant == "setsid":
        return 'setsid sh -c \'%s\' sh "%s" >> "$F" </dev/null 2>/dev/null &\n' % (body, pids)
    if variant == "double":
        return '( setsid sh -c \'%s\' sh "%s" >> "$F" </dev/null 2>/dev/null & )\n' % (body, pids)
    if variant == "byname":
        return 'sh -c \'%s\' sh "%s" "$F" </dev/null >/dev/null 2>&1 &\n' % (by_name, pids)
    if variant == "periodic":
        return 'setsid sh -c \'echo $$ >> "$1"; while :; do sleep 0.2; echo LEFTOVER-WROTE >> "$2"; done\' sh "%s" "$F" </dev/null >/dev/null 2>&1 &\n' % pids
    if variant == "rewrite":
        return 'setsid sh -c \'echo $$ >> "$1"; sleep %s; : > "$2"; echo LEFTOVER-REWROTE >> "$2"\' sh "%s" "$F" </dev/null >/dev/null 2>&1 &\n' % (d, pids)
    if variant is None:
        return ""
    raise AssertionError(variant)


def alive(pid):
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    try:
        with open("/proc/%d/stat" % pid) as fh:
            return fh.read().rsplit(")", 1)[1].split()[0] != "Z"
    except OSError:
        return False


def invoke(script, stdin_text, cwd, env, args=(), host="linux", timeout=120):
    """Run a script the way the harness does (its own process group's leader), with sys.platform or the libc patched for the hosts that are not Linux."""
    wrapper = WRAPPERS[host]
    argv = [sys.executable] + (["-c", wrapper] if wrapper else []) + [script] + list(args)
    e = dict(os.environ)
    for k in ("JOB_ID", "OUT", "AGENT_ID", "SECRET_OUTPUT"):
        e.pop(k, None)
    e.update(env)
    proc = subprocess.run(argv, input=stdin_text, capture_output=True, text=True, cwd=cwd, env=e, timeout=timeout, start_new_session=True)
    try:
        doc = json.loads(proc.stdout) if proc.stdout.strip() else None
    except ValueError:
        doc = None
    return proc, doc


def path_env(*dirs):
    return {"PATH": os.pathsep.join(list(dirs) + [os.environ.get("PATH", "")])}


class Scenario(object):
    """What one run left to look at: the answer (and the process), the files that must not change, the pids of the leftovers."""

    def __init__(self, proc, answer, watched, pids):
        self.proc, self.answer, self.watched, self.pids = proc, answer, watched, pids


class Process(Case):
    # ---- the checks, shared
    def run_variants(self, make, variants=VARIANTS):
        """Run `make(root, variant)` for every variant (three at a time), wait for the leftovers' time to pass, and check each."""
        def one(variant):
            return variant, make(os.path.join(self.dir, "v-" + variant), variant)
        with ThreadPoolExecutor(3) as pool:
            ran = list(pool.map(one, variants))
        before = {v: [(p, sha(p) if os.path.exists(p) else None) for p in s.watched] for v, s in ran}
        time.sleep(AFTER)
        for variant, s in ran:
            with self.subTest(variant=variant):
                self.assertNotIn("Traceback", s.proc.stderr)
                a = s.answer
                self.assertIsNotNone(a, s.proc.stdout[:400] + s.proc.stderr[-400:])
                self.assertEqual(a["status"], "partial", (a.get("status_basis"), a.get("program_group")))
                for flag in ("ok", "complete"):
                    if flag in a and a["status"] == "partial" and flag == "complete":
                        self.assertIs(a[flag], False)
                group = a.get("program_group") or {}
                self.assertGreaterEqual(group.get("left_behind", 0), 1, a)
                self.assertIs(group.get("subreaper"), True, group)
                self.assertIn("left", json.dumps(a.get("status_basis")), a.get("status_basis"))
                for path, digest in before[variant]:
                    self.assertTrue(os.path.exists(path), path)
                    self.assertEqual(sha(path), digest, "%s changed after the tool had answered" % path)
                    with open(path, "rb") as fh:
                        content = fh.read()
                    self.assertNotIn(b"LEFTOVER-", content)
                    self.assertGreater(len(content), 0, "%s was truncated" % path)
                for pid in s.pids():
                    self.assertFalse(alive(pid), "the leftover %d is still running" % pid)

    def check_clean(self, s):
        a = s.answer
        self.assertIsNotNone(a, s.proc.stdout[:400] + s.proc.stderr[-400:])
        self.assertEqual(a["status"], "complete", (a.get("status_basis"), a.get("program_group")))
        group = a["program_group"]
        self.assertEqual((group["left_behind"], group["unproven"], group["subreaper"]), (0, [], True))

    def check_unproven(self, s, held=True):
        a = s.answer
        self.assertIsNotNone(a, s.proc.stdout[:400] + s.proc.stderr[-400:])
        group = a["program_group"]
        self.assertEqual(group["left_behind"], 0)
        self.assertTrue(group["unproven"], group)
        if held:
            self.assertEqual(a["status"], "partial", a.get("status_basis"))
            basis = json.dumps(a["status_basis"])
            self.assertTrue("final" in basis or "cannot prove" in basis, basis)
            for flag in ("ok", "complete"):
                if flag == "complete" and flag in a:
                    self.assertIs(a[flag], False)
        else:
            self.assertEqual(a["status"], "complete", a.get("status_basis"))

    def pidfile_reader(self, path):
        def pids():
            try:
                with open(path) as fh:
                    return [int(x) for x in fh.read().split()]
            except OSError:
                return []
        return pids

    def hosts(self, make):
        for host in ("darwin", "refused"):
            with self.subTest(host=host):
                yield host, make(os.path.join(self.dir, "h-" + host), host)


# ---- image_verify ----------------------------------------------------------------------------------------------------------------------------

def image_verify_run(root, variant, host="linux"):
    os.makedirs(root)
    pids = os.path.join(root, "pids")
    d = os.path.join(root, "bin")
    os.makedirs(d)
    segments = []
    for n in (1, 2, 3):
        path = os.path.join(root, "evidence", "disk.E%02d" % n)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(tiv.segment(n, n == 3, payload=bytes([n]) * 40))
        segments.append(path)
    stand_in(d, "ewfinfo", tiv.program(tiv.info_text()))
    stand_in(d, "ewfverify", 'if [ "$1" = "-V" ]; then echo "ewfverify 20140814"; exit 0; fi\n'
             + tiv.program(tiv.verify_text(), 0, extra='F=$(readlink /proc/$$/fd/1)\n' + leave(variant, pids)))
    out = os.path.join(root, "out")
    proc, doc = invoke(tool_path("image_verify"), json.dumps({"path": segments[0], "out_dir": out}), root, path_env(d), host=host)
    return proc, doc, os.path.join(out, "ewfverify.stdout.txt"), pids


class ImageVerifyProcess(Process):
    @LINUX
    def test_a_leftover_of_ewfverify_makes_the_receipt_partial_and_the_output_file_is_final(self):
        def make(root, variant):
            proc, doc, watched, pids = image_verify_run(root, variant)
            return Scenario(proc, doc, [watched], self.pidfile_reader(pids))
        self.run_variants(make)

    @LINUX
    def test_a_clean_run_is_still_complete_with_an_empty_program_group(self):
        proc, doc, _w, _p = image_verify_run(self.path("clean"), None)
        self.check_clean(Scenario(proc, doc, [], None))

    @LINUX
    def test_where_absence_cannot_be_proven_a_run_that_wrote_files_is_at_most_partial(self):
        for host, (proc, doc, _w, _p) in self.hosts(lambda root, host: image_verify_run(root, None, host)):
            self.check_unproven(Scenario(proc, doc, [], None))


# ---- layer_describe --------------------------------------------------------------------------------------------------------------------------

def layer_describe_run(root, variant, host="linux"):
    os.makedirs(root)
    pids = os.path.join(root, "pids")
    d = os.path.join(root, "bin")
    os.makedirs(d)
    parts = []
    for n in (1, 2):
        path = os.path.join(root, "evidence", "d.00%d" % n)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(((tld.mbr(2048, 24576) if n == 1 else b"") + b"\0" * (1 << 20))[:1 << 20])
        parts.append(path)
    stand_in(d, "mmls", 'F=$(readlink /proc/$$/fd/1)\n' + leave(variant, pids) + "cat <<'EOF'\n%sEOF\n" % tld.MMLS_512)
    stand_in(d, "fsstat", "cat <<'EOF'\n%sEOF\n" % tld.FSSTAT)
    stand_in(d, "img_stat", 'total=0; for a; do if [ -f "$a" ]; then total=$((total + $(wc -c < "$a"))); fi; done\n'
             'printf "IMAGE FILE INFORMATION\\n-----\\nImage Type:\\traw\\n\\nSize in bytes: %s\\n" "$total"\n')
    stand_in(d, "ewfinfo", "echo 'ewfinfo stand-in'; exit 1\n")
    stand_in(d, "qemu-img", "exit 1\n")
    out = os.path.join(root, "out")
    proc, doc = invoke(tool_path("layer_describe"), json.dumps({"sources": parts, "out_dir": out}), root, path_env(d), host=host)
    watched = []
    if doc:
        for p in doc.get("programs", []):
            if p["name"] == "mmls" and p.get("stdout_file"):
                watched.append(os.path.join(out, p["stdout_file"]))
    return proc, doc, watched, pids, out


class LayerDescribeProcess(Process):
    @LINUX
    def test_a_leftover_of_mmls_makes_the_descriptor_partial_and_the_hashed_output_is_final(self):
        def make(root, variant):
            proc, doc, watched, pids, out = layer_describe_run(root, variant)
            return Scenario(proc, doc, watched, self.pidfile_reader(pids))
        self.run_variants(make)

    @LINUX
    def test_the_descriptor_itself_says_partial(self):
        proc, doc, _w, _p, out = layer_describe_run(self.path("d"), "setsid")
        self.assertEqual(doc["status"], "partial", doc.get("status_basis"))
        with open(os.path.join(out, doc["descriptor"]["file"]), encoding="utf-8") as fh:
            self.assertEqual(json.load(fh)["status"], "partial")

    @LINUX
    def test_a_clean_run_is_still_complete(self):
        proc, doc, _w, _p, _o = layer_describe_run(self.path("clean"), None)
        self.check_clean(Scenario(proc, doc, [], None))

    @LINUX
    def test_where_absence_cannot_be_proven_a_run_that_wrote_files_is_at_most_partial(self):
        for host, (proc, doc, _w, _p, _o) in self.hosts(lambda root, host: layer_describe_run(root, None, host)):
            self.check_unproven(Scenario(proc, doc, [], None))


# ---- feature_scan ----------------------------------------------------------------------------------------------------------------------------

def feature_scan_run(root, variant, host="linux"):
    os.makedirs(root)
    pids = os.path.join(root, "pids")
    d = os.path.join(root, "bin")
    os.makedirs(d)
    stand_in(d, "bulk_extractor", tfs.stub_body(extra='F="$OUTDIR/email.txt"\n' + leave(variant, pids)))
    src = os.path.join(root, "inputs", "blob.raw")
    os.makedirs(os.path.dirname(src))
    with open(src, "wb") as fh:
        fh.write(b"\0" * 64)
    out = os.path.join(root, "work", "features")
    proc, doc = invoke(tool_path("feature_scan"), json.dumps({"path": src, "out_dir": "work/features"}), root, path_env(d), host=host)
    return proc, doc, os.path.join(out, "email.txt"), pids


class FeatureScanProcess(Process):
    @LINUX
    def test_a_leftover_of_bulk_extractor_makes_the_answer_partial_and_the_feature_file_is_final(self):
        def make(root, variant):
            proc, doc, watched, pids = feature_scan_run(root, variant)
            return Scenario(proc, doc, [watched], self.pidfile_reader(pids))
        self.run_variants(make)
        # the exit code follows the status
        proc, _doc, _w, _p = feature_scan_run(self.path("exit"), "setsid")
        self.assertEqual(proc.returncode, 1)

    @LINUX
    def test_a_clean_run_is_still_complete(self):
        proc, doc, _w, _p = feature_scan_run(self.path("clean"), None)
        self.assertEqual(proc.returncode, 0)
        self.check_clean(Scenario(proc, doc, [], None))

    @LINUX
    def test_where_absence_cannot_be_proven_a_run_that_wrote_files_is_at_most_partial(self):
        for host, (proc, doc, _w, _p) in self.hosts(lambda root, host: feature_scan_run(root, None, host)):
            self.check_unproven(Scenario(proc, doc, [], None))
            self.assertEqual(proc.returncode, 1)


# ---- timeline_super --------------------------------------------------------------------------------------------------------------------------

CANNED = "\n".join(json.dumps(r) for r in [
    {"datetime": "2023-11-14T22:13:20.000000+00:00", "parser": "filestat", "data_type": "fs:stat", "message": "m1", "timestamp_desc": "Modification Time"},
    {"timestamp": 1700000100000000, "parser": "winreg", "data_type": "windows:registry:key_value", "message": "m2"}]) + "\n"


def timeline_super_run(root, variant, host="linux", stage="psort"):
    os.makedirs(root)
    pids = os.path.join(root, "pids")
    d = os.path.join(root, "bin")
    os.makedirs(d)
    canned = os.path.join(root, "canned.jsonl")
    with open(canned, "w", encoding="utf-8") as fh:
        fh.write(CANNED)
    mine = leave(variant, pids)
    l2t = ('case "$1" in --version) echo "plaso - log2timeline version 20990101"; exit 0;; esac\n'
           'while [ $# -gt 0 ]; do case "$1" in --storage_file) echo storage > "$2"; F="$2"; shift;; --logfile) echo log > "$2"; shift;; esac; shift; done\n'
           + (mine if stage == "log2timeline" else "") + "exit 0\n")
    ps = ('case "$1" in --version) echo "plaso - psort version 20990101"; exit 0;; esac\n'
          'while [ $# -gt 0 ]; do case "$1" in -w) cp "%s" "$2"; F="$2"; shift;; --logfile) echo log > "$2"; shift;; esac; shift; done\n' % canned
          + (mine if stage == "psort" else "") + "exit 0\n")
    stand_in(d, "log2timeline.py", l2t)
    stand_in(d, "psort.py", ps)
    src = os.path.join(root, "inputs", "disk.dd")
    os.makedirs(os.path.dirname(src))
    with open(src, "wb") as fh:
        fh.write(b"\0" * 64)
    proc, doc = invoke(tool_path("timeline_super"), json.dumps({"source": src, "out_dir": "work/tl"}), root, path_env(d), host=host)
    out = os.path.join(root, "work", "tl")
    return proc, doc, os.path.join(out, "timeline.jsonl") if stage == "psort" else os.path.join(out, "timeline.plaso"), pids


class TimelineSuperProcess(Process):
    @LINUX
    def test_a_leftover_of_psort_makes_the_answer_partial_and_the_timeline_is_final(self):
        def make(root, variant):
            proc, doc, watched, pids = timeline_super_run(root, variant)
            return Scenario(proc, doc, [watched], self.pidfile_reader(pids))
        self.run_variants(make)

    @LINUX
    def test_a_leftover_of_log2timeline_makes_the_answer_partial_before_psort_reads_the_storage_file(self):
        def make(root, variant):
            proc, doc, watched, pids = timeline_super_run(root, variant, stage="log2timeline")
            return Scenario(proc, doc, [watched], self.pidfile_reader(pids))
        self.run_variants(make, variants=("setsid", "byname"))

    @LINUX
    def test_a_clean_run_is_still_complete(self):
        proc, doc, _w, _p = timeline_super_run(self.path("clean"), None)
        self.assertEqual(proc.returncode, 0)
        self.check_clean(Scenario(proc, doc, [], None))

    @LINUX
    def test_where_absence_cannot_be_proven_a_run_that_wrote_files_is_at_most_partial(self):
        for host, (proc, doc, _w, _p) in self.hosts(lambda root, host: timeline_super_run(root, None, host)):
            self.check_unproven(Scenario(proc, doc, [], None))
            self.assertEqual(proc.returncode, 1)

    @LINUX
    def test_the_version_probe_is_ended_with_what_it_started_at_its_clock(self):
        """subprocess.run(timeout=) ended only the probe itself; the probe is a program of the shared block now."""
        root = self.path("probe")
        os.makedirs(os.path.join(root, "bin"))
        pids = os.path.join(root, "pids")
        stand_in(os.path.join(root, "bin"), "psort.py", 'case "$1" in --version) setsid sh -c \'echo $$ >> "$1"; sleep 300\' sh "%s" </dev/null >/dev/null 2>&1 & sleep 300;; esac\nexit 0\n' % pids)
        # version_of runs in a subprocess of its own (spawn() makes its process a subreaper)
        code = ("import sys, runpy\nns = runpy.run_path(sys.argv[1], run_name='probe')\n"
                "ns['version_of'].__globals__['VERSION_TIMEOUT'] = 2\nprint(repr(ns['version_of'](sys.argv[2], sys.argv[3])))\n")
        start = time.monotonic()
        res = subprocess.run([sys.executable, "-c", code, tool_path("timeline_super"), os.path.join(root, "bin", "psort.py"), root], capture_output=True, text=True, timeout=60,
                             env=dict(os.environ, **path_env(os.path.join(root, "bin"))))
        self.assertLess(time.monotonic() - start, 20)
        self.assertEqual(res.stdout.strip(), "None", res.stderr[-400:])
        time.sleep(0.3)
        with open(pids) as fh:
            for pid in [int(x) for x in fh.read().split()]:
                self.assertFalse(alive(pid), "the process the version probe started is still running")


# ---- archive_extract -------------------------------------------------------------------------------------------------------------------------

def archive_extract_run(root, variant, host="linux"):
    os.makedirs(root)
    pids = os.path.join(root, "pids")
    d = os.path.join(root, "bin")
    os.makedirs(d)
    src = os.path.join(root, "src7")
    os.makedirs(src)
    with open(os.path.join(src, "a.bin"), "wb") as fh:
        fh.write(os.urandom(3000))
    with open(os.path.join(src, "b.txt"), "wb") as fh:
        fh.write(b"text " * 500)
    archive = os.path.join(root, "inputs", "t.7z")
    os.makedirs(os.path.dirname(archive))
    subprocess.run([SEVEN_Z, "a", "-bd", archive, "."], cwd=src, capture_output=True, check=True)
    real = shutil.which(SEVEN_Z)
    # the real 7-Zip, then a leftover: into its stdout file after the listing, into its stderr file after the extraction (its stdout is a pipe there)
    stand_in(d, "7z", '"%s" "$@"\nrc=$?\nargs="$*"\ncase "$1" in\n l) F=$(readlink /proc/$$/fd/1); echo "note" >&2\n%s;;\n x) F=$(readlink /proc/$$/fd/2); echo "note" >&2\n%s;;\nesac\nexit $rc\n'
             % (real, leave(variant, pids + ".l") or ":", leave(variant, pids) or ":"))
    out = os.path.join(root, "work", "out")
    proc, doc = invoke(tool_path("archive_extract"), json.dumps({"path": archive, "out_dir": out}), root, path_env(d), host=host)
    watched = []
    if doc:
        for key in ("listing_file", "extract_stderr_file", "listing_stderr_file"):
            if doc.get(key):
                watched.append(os.path.join(out, doc[key]))
    return proc, doc, watched, pids, out


@unittest.skipUnless(SEVEN_Z, "no 7z program on this host")
class ArchiveExtractProcess(Process):
    @LINUX
    def test_a_leftover_of_7z_makes_the_answer_partial_and_the_files_it_wrote_are_final(self):
        def make(root, variant):
            proc, doc, watched, pids, out = archive_extract_run(root, variant)
            return Scenario(proc, doc, watched, lambda: self.pidfile_reader(pids)() + self.pidfile_reader(pids + ".l")())
        self.run_variants(make, variants=("held", "setsid", "double", "byname", "rewrite"))

    @LINUX
    def test_the_receipt_on_disk_says_the_same_as_the_answer(self):
        proc, doc, _w, _p, out = archive_extract_run(self.path("receipt"), "setsid")
        with open(os.path.join(out, "receipt.json"), encoding="utf-8") as fh:
            receipt = json.load(fh)
        self.assertEqual((doc["status"], receipt["status"]), ("partial", "partial"))
        self.assertGreaterEqual(receipt["program_group"]["left_behind"], 1)

    @LINUX
    def test_a_clean_run_is_still_complete(self):
        proc, doc, _w, _p, _o = archive_extract_run(self.path("clean"), None)
        self.check_clean(Scenario(proc, doc, [], None))

    @LINUX
    def test_where_absence_cannot_be_proven_a_run_that_wrote_files_is_at_most_partial(self):
        for host, (proc, doc, _w, _p, _o) in self.hosts(lambda root, host: archive_extract_run(root, None, host)):
            self.check_unproven(Scenario(proc, doc, [], None))

    @LINUX
    def test_a_format_read_in_python_runs_no_program_and_is_not_held_to_it(self):
        import zipfile
        root = self.path("zip")
        os.makedirs(os.path.join(root, "inputs"))
        archive = os.path.join(root, "inputs", "t.zip")
        with zipfile.ZipFile(archive, "w") as z:
            z.writestr("a.txt", "hello" * 50)
        for host in ("darwin", "refused"):
            proc, doc = invoke(tool_path("archive_extract"), json.dumps({"path": archive, "out_dir": os.path.join(root, "out-" + host)}), root, {}, host=host)
            self.assertEqual(doc["status"], "complete", doc.get("status_basis"))
            self.assertEqual(doc["program_group"]["unproven"], [])


# ---- browser_storage -------------------------------------------------------------------------------------------------------------------------

ORIGIN = "https://app.example.test"
READER_DOC = ('{"ok":true,"versions":{},"files":[{"name":"000003.log","kind":"log","status":"read"}],"format":"leveldb","records_total":0,"counts":{},'
              '"previews":[],"decode_errors":{},"write":{"requested":true,"records":1}}')


def browser_storage_run(root, variant, host="linux", write_values=True):
    os.makedirs(root)
    pids = os.path.join(root, "pids")
    store = os.path.join(root, "idb")
    os.makedirs(store)
    meta = BF.global_metadata([(1, ORIGIN, "appdb", 1, {1: "messages"})])
    with open(os.path.join(store, "000003.log"), "wb") as fh:
        fh.write(BF.log_file([BF.write_batch(1, meta)]))
    venv = os.path.join(root, "src", "ccl_indexeddb_dump", ".venv", "bin")
    os.makedirs(venv)
    script = ('spec=$(cat)\nfd=$(printf \'%s\' "$spec" | sed -n \'s/.*"write_fd": *\\([0-9]*\\).*/\\1/p\')\n'
              + ('F=$(readlink /proc/$$/fd/$fd)\neval "printf \'{\\"header\\": true}\\n{\\"n\\": 1}\\n{\\"end\\": true, \\"records\\": 1, \\"stopped\\": null, \\"oversized\\": 0}\\n\' >&$fd"\n'
                 if write_values else 'F="%s"\n' % os.path.join(root, "unrelated.txt"))
              + leave(variant, pids)
              + "echo '%s'\n" % (READER_DOC if write_values else READER_DOC.replace(',"write":{"requested":true,"records":1}', "")))
    stand_in(venv, "python", script)
    out = os.path.join(root, "out")
    os.makedirs(out)
    env = {"DFIRSWARM_SRC_DIR": os.path.join(root, "src")}
    if write_values:
        env.update({"JOB_ID": "j1", "OUT": out, "SECRET_OUTPUT": "1"})
    args = {"path": store, "write_values": True} if write_values else {"path": store}
    proc, doc = invoke(tool_path("browser_storage"), json.dumps(args), root, env, host=host)
    return proc, doc, os.path.join(out, "browser-storage-records.jsonl"), pids


class BrowserStorageProcess(Process):
    @LINUX
    def test_a_leftover_of_the_reader_makes_a_values_file_answer_partial_and_the_file_is_final(self):
        def make(root, variant):
            proc, doc, watched, pids = browser_storage_run(root, variant)
            return Scenario(proc, doc, [watched], self.pidfile_reader(pids))
        self.run_variants(make)

    @LINUX
    def test_a_clean_values_file_run_is_still_complete(self):
        proc, doc, _w, _p = browser_storage_run(self.path("clean"), None)
        self.check_clean(Scenario(proc, doc, [], None))

    @LINUX
    def test_where_absence_cannot_be_proven_a_values_file_answer_is_at_most_partial_and_a_pipe_answer_is_not_held_to_it(self):
        for host, (proc, doc, _w, _p) in self.hosts(lambda root, host: browser_storage_run(root, None, host)):
            self.check_unproven(Scenario(proc, doc, [], None))
        for host in ("darwin", "refused"):
            with self.subTest(pipe_only=host):
                proc, doc, _w, _p = browser_storage_run(self.path("pipe-" + host), None, host, write_values=False)
                self.check_unproven(Scenario(proc, doc, [], None), held=False)

    @LINUX
    def test_a_pipe_only_reader_that_left_a_process_is_still_partial(self):
        proc, doc, _w, pids = browser_storage_run(self.path("pipe"), "setsid", write_values=False)
        self.assertEqual(doc["status"], "partial", doc.get("status_basis"))
        self.assertGreaterEqual(doc["program_group"]["left_behind"], 1)


# ---- the disk-timeline recipe (no shared block: a mechanism of its own) -------------------------------------------------------------------------

def disk_timeline_run(root, variant, host="linux", stage="psort"):
    os.makedirs(root)
    pids = os.path.join(root, "pids")
    d = os.path.join(root, "bin")
    os.makedirs(d)
    mine = leave(variant, pids)
    l2t = ('while [ $# -gt 0 ]; do case "$1" in --storage-file) echo storage > "$2"; F="$2"; shift;; --logfile) echo log > "$2"; shift;; esac; shift; done\n'
           + (mine if stage == "log2timeline" else "") + "exit 0\n")
    ps = ('while [ $# -gt 0 ]; do case "$1" in -w) printf "datetime,message\\n2023-11-14,one event\\n" > "$2"; F="$2"; shift;; --logfile) echo log > "$2"; shift;; esac; shift; done\n'
          + (mine if stage == "psort" else "") + "exit 0\n")
    stand_in(d, "log2timeline", l2t)
    stand_in(d, "psort", ps)
    stand_in(d, "pinfo", "echo 'storage file: ok'\n")
    head = bytearray(4096)
    head[3:11] = b"NTFS    "
    image = os.path.join(root, "inputs", "disk.raw")
    os.makedirs(os.path.dirname(image))
    with open(image, "wb") as fh:
        fh.write(bytes(head))
    out = os.path.join(root, "out")
    target = json.dumps({"paths": [image], "name": "disk.raw"})
    proc, _doc = invoke(recipe_path("disk-timeline", "run.py"), "", root, path_env(d), args=["run", "--target", target, "--out", out], host=host)
    with open(os.path.join(out, "coverage.json"), encoding="utf-8") as fh:
        cov = json.load(fh)
    return proc, cov, os.path.join(out, "timeline.csv") if stage == "psort" else os.path.join(out, "timeline.plaso"), pids


class DiskTimelineProcess(Process):
    @LINUX
    def test_a_leftover_of_psort_makes_the_run_partial_and_the_timeline_is_final(self):
        def make(root, variant):
            proc, cov, watched, pids = disk_timeline_run(root, variant)
            cov.setdefault("status_basis", "")
            cov["status_basis"] = json.dumps([cov["status_basis"], cov["errors"]])
            return Scenario(proc, cov, [watched], self.pidfile_reader(pids))
        self.run_variants(make)

    @LINUX
    def test_a_leftover_of_log2timeline_is_ended_before_psort_reads_the_storage_file(self):
        def make(root, variant):
            proc, cov, watched, pids = disk_timeline_run(root, variant, stage="log2timeline")
            cov["status_basis"] = json.dumps([cov["status_basis"], cov["errors"]])
            return Scenario(proc, cov, [watched], self.pidfile_reader(pids))
        self.run_variants(make, variants=("setsid", "byname", "rewrite"))

    @LINUX
    def test_a_clean_run_is_still_complete(self):
        proc, cov, _w, _p = disk_timeline_run(self.path("clean"), None)
        self.assertEqual((cov["status"], cov["errors"]), ("complete", []))
        self.assertEqual(cov["program_group"], {"subreaper": True, "left_behind": 0, "unproven": []})

    @LINUX
    def test_where_absence_cannot_be_proven_a_run_that_wrote_files_is_at_most_partial(self):
        for host, (proc, cov, _w, _p) in self.hosts(lambda root, host: disk_timeline_run(root, None, host)):
            self.assertEqual(cov["status"], "partial", cov["errors"])
            self.assertEqual(cov["program_group"]["left_behind"], 0)
            self.assertTrue(cov["program_group"]["unproven"])
            self.assertTrue(any("cannot be shown to be final" in e for e in cov["errors"]), cov["errors"])

    @LINUX
    def test_a_stop_signal_ends_what_the_step_started_and_lost_not_only_the_step(self):
        root = self.path("stop")
        os.makedirs(os.path.join(root, "bin"))
        pids = os.path.join(root, "pids")
        ready = os.path.join(root, "ready")
        stand_in(os.path.join(root, "bin"), "log2timeline", 'setsid sh -c \'echo $$ >> "$1"; sleep 300\' sh "%s" </dev/null >/dev/null 2>&1 &\nsleep 0.3\necho $$ > "%s"\nexec sleep 300\n' % (pids, ready))
        stand_in(os.path.join(root, "bin"), "psort", "exit 0\n")
        head = bytearray(4096)
        head[3:11] = b"NTFS    "
        image = os.path.join(root, "inputs", "disk.raw")
        os.makedirs(os.path.dirname(image))
        with open(image, "wb") as fh:
            fh.write(bytes(head))
        out = os.path.join(root, "out")
        proc = subprocess.Popen([sys.executable, recipe_path("disk-timeline", "run.py"), "run", "--target", json.dumps({"paths": [image]}), "--out", out],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=root, env=dict(os.environ, **path_env(os.path.join(root, "bin"))))
        end = time.monotonic() + 30
        while time.monotonic() < end and not (os.path.exists(ready) and os.path.getsize(ready) > 0):
            time.sleep(0.02)
        time.sleep(0.2)
        proc.send_signal(signal.SIGTERM)
        so, se = proc.communicate(timeout=30)
        self.assertEqual(proc.returncode, 128 + int(signal.SIGTERM), (so, se[-300:]))
        with open(pids) as fh:
            lost = [int(x) for x in fh.read().split()]
        self.assertTrue(lost)
        time.sleep(0.3)
        for pid in lost:
            self.assertFalse(alive(pid), "the process the step started in a session of its own survived the stop")


if __name__ == "__main__":
    unittest.main()
