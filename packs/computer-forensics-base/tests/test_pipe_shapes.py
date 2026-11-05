"""The pipe readers of the pack, held to one matrix of shapes of a program that ends (or does not) while something it started holds its pipe.

Every tool that reads a program's pipe without the shared block's communicate_bounded (image_layout, file_type, chunk_needles, icat_extract, the
archive-members recipe, archive_extract's zstd read) answers on its own clock, and a program that has ended is not waited on for longer than one
second whatever the leftover does with the pipe: nothing (silent), a write every 10 ms, a write every 0.7 s, or a flood (`yes`). The shapes:

  silent        a child that holds stdout and stderr and writes nothing
  stderr_only   a child that holds stderr only
  stdin_only    a child that holds none of the pipes (only the tool's stdin)
  w10ms         a child that writes to stdout every 10 ms, for ever
  w700ms        a child that writes to stdout every 0.7 s, for ever
  flood         a child that writes to stdout as fast as it can (`yes`)
  never_exits   the program itself does not end (the tool's clock ends it)

For each reader and shape: the answer comes within the time the reader's sentence in its manifest gives (one second after the program ended, or its
clock), says that the end of the stream was not seen (and not that a time budget was used) when the pipe was let go, and the leftover is dead
afterwards. image_layout's and file_type's run_child is also called directly, with a flood, to show the buffer is bounded.
"""
import json
import os
import shutil
import subprocess
import sys
import time
import unittest
from concurrent.futures import ThreadPoolExecutor

from support import Case, manifest, recipe_path, stand_in, tool_path

LINUX = unittest.skipUnless(sys.platform.startswith("linux"), "needs /proc and PR_SET_CHILD_SUBREAPER")
SHAPES = {
    "silent": 'sleep 600 &\necho $! >> "@PIDS@"\n',
    "stderr_only": 'sleep 600 >/dev/null &\necho $! >> "@PIDS@"\n',
    "stdin_only": 'sleep 600 >/dev/null 2>&1 &\necho $! >> "@PIDS@"\n',
    "w10ms": '( while :; do printf x; sleep 0.01; done ) &\necho $! >> "@PIDS@"\n',
    "w700ms": '( while :; do printf x; sleep 0.7; done ) &\necho $! >> "@PIDS@"\n',
    "flood": 'yes aaaaaaaaaaaaaaaa &\necho $! >> "@PIDS@"\n',
}
NEVER = 'echo $$ >> "@PIDS@"\nexec sleep 600\n'
PIPE_SHAPES = ("silent", "w10ms", "w700ms", "flood")          # hold stdout (and stderr) of the program
ANSWER_BOUND = 12                                             # seconds from the start of the tool: startup, the program, one second of grace, the answer


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


class Reader(object):
    """One pipe reader: how to run it with a stand-in whose body ends in `tail`, and how to read its answer."""
    name = ""
    stderr_is_pipe = False
    clock = 10                 # seconds the tool's clock is made when the program does not end

    def make(self, root, tail):
        raise NotImplementedError

    def held(self, doc):
        """The problems with an answer that was given when the pipe was let go ('' when it is right)."""
        raise NotImplementedError

    def never(self, doc):
        return ""


class ImageLayout(Reader):
    name = "image_layout"
    stderr_is_pipe = True
    clock = None

    def make(self, root, tail):
        mbr = bytearray(512)
        mbr[510:512] = b"\x55\xaa"
        return (tool_path("image_layout"), json.dumps({"image": "@ROOT@/disk.dd"}), [], {"disk.dd": bytes(mbr) + b"\0" * 4096},
                {"mmls": "echo 'DOS Partition Table'\n" + tail, "fsstat": "exit 1\n", "img_stat": "exit 1\n"}, {})

    def held(self, doc):
        return "" if doc.get("status") != "complete" else "image_layout answered complete over output whose end was not seen"


class FileType(Reader):
    name = "file_type"
    stderr_is_pipe = True
    clock = 10

    def make(self, root, tail):
        return (tool_path("file_type"), json.dumps({"path": "@ROOT@/d"}), [], {"d/a.bin": bytes(range(1, 200))}, {"file": "echo data\n" + tail}, {})

    def held(self, doc):
        return "" if doc.get("status") == "partial" and "file command" in json.dumps(doc.get("status_basis")) else "file_type did not say that the file command did not finish: %s" % doc.get("status_basis")

    def never(self, doc):
        return self.held(doc)


class ChunkNeedles(Reader):
    name = "chunk_needles"

    def make(self, root, tail):
        return (tool_path("chunk_needles"), json.dumps({"image": "@ROOT@/img.dd", "inode": 5, "offset": 2048, "needles": "needle", "max_seconds": 8}), [],
                {"img.dd": b"\0" * 1024}, {"icat": "printf 'aaneedle'\n" + tail}, {})

    def held(self, doc):
        stopped = doc.get("stopped") or ""
        if doc.get("status") == "partial" and "kept its output pipe open" in stopped and "time budget" not in stopped and "kept its output pipe open" in doc.get("status_basis", ""):
            return ""
        return "chunk_needles: %s / %s" % (doc.get("status"), stopped)

    def never(self, doc):
        return "" if doc.get("status") == "partial" and "time budget" in (doc.get("stopped") or "") else "chunk_needles never-exiting icat: %s" % doc.get("stopped")


class IcatExtract(Reader):
    name = "icat_extract"

    def make(self, root, tail):
        return (tool_path("icat_extract"), json.dumps({"image": "@ROOT@/img.dd", "inode": 5, "output": "@ROOT@/out/f.bin", "max_seconds": 8}), [],
                {"img.dd": b"\0" * 1024}, {"icat": "printf 'abc'\n" + tail, "fls": "exit 1\n"}, {})

    def held(self, doc):
        return "" if doc.get("status") == "partial" and "kept its output pipe open" in doc.get("problem", "") else "icat_extract: %s / %s" % (doc.get("status"), doc.get("problem"))

    def never(self, doc):
        return "" if doc.get("status") == "partial" and "time budget" in doc.get("problem", "") else "icat_extract never-exiting icat: %s" % doc.get("problem")


class ArchiveMembers(Reader):
    name = "archive-members"

    def make(self, root, tail):
        target = json.dumps({"paths": ["@ROOT@/a.7z"]})
        return (recipe_path("archive-members", "run.py"), "", ["run", "--target", target, "--out", "@ROOT@/out"], {"a.7z": b"7z\xbc\xaf\x27\x1c" + b"\0" * 64},
                {"7z": "printf 'Path = a.txt\\nSize = 1\\n\\n'\n" + tail}, {"RECIPE_SECONDS": "8"})

    def read(self, root, doc):
        with open(os.path.join(root, "out", "coverage.json"), encoding="utf-8") as fh:
            return json.load(fh)

    def held(self, doc):
        return "" if doc.get("status") == "partial" and any("kept its output pipe open" in x for x in doc.get("limits_hit", [])) else "archive-members: %s / %s" % (doc.get("status"), doc.get("limits_hit"))

    def never(self, doc):
        return "" if doc.get("status") == "partial" and any(x.startswith("seconds") for x in doc.get("limits_hit", [])) else "archive-members never-exiting 7z: %s" % doc.get("limits_hit")


class Zstd(Reader):
    name = "archive_extract (zstd)"

    def make(self, root, tail):
        return (tool_path("archive_extract"), json.dumps({"path": "@ROOT@/a.zst", "out_dir": "@ROOT@/out", "max_seconds": 8}), [],
                {"a.zst": b"\x28\xb5\x2f\xfd" + b"\0" * 64}, {"zstd": "printf 'hello'\n" + tail}, {})

    def held(self, doc):
        return "" if doc.get("status") != "complete" else "archive_extract answered complete over a zstd stream whose end was not seen"

    def never(self, doc):
        return self.held(doc)


READERS = [ImageLayout(), FileType(), ChunkNeedles(), IcatExtract(), ArchiveMembers(), Zstd()]


def run_case(root, reader, shape):
    """Run `reader` with a stand-in that ends in `shape` (a key of SHAPES, or 'never_exits'): (answer, seconds, pids)."""
    os.makedirs(root)
    pids = os.path.join(root, "pids")
    tail = (NEVER if shape == "never_exits" else SHAPES[shape]).replace("@PIDS@", pids)
    script, stdin_text, args, files, bins, env = reader.make(root, tail)
    d = os.path.join(root, "bin")
    os.makedirs(d)
    for n, body in bins.items():
        stand_in(d, n, body)
    for rel, data in files.items():
        p = os.path.join(root, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as fh:
            fh.write(data)
    e = dict(os.environ, PATH=d + os.pathsep + os.environ["PATH"], **env)
    for k in ("JOB_ID", "OUT", "AGENT_ID", "SECRET_OUTPUT"):
        e.pop(k, None)
    began = time.monotonic()
    try:
        proc = subprocess.run([sys.executable, script] + [a.replace("@ROOT@", root) for a in args], input=stdin_text.replace("@ROOT@", root), capture_output=True, text=True,
                              cwd=root, env=e, timeout=60, start_new_session=True)
        took = time.monotonic() - began
        try:
            doc = json.loads(proc.stdout) if proc.stdout.strip() else None
        except ValueError:
            doc = None
        if hasattr(reader, "read") and os.path.exists(os.path.join(root, "out", "coverage.json")):
            doc = reader.read(root, doc)
        err = proc.stderr[-300:]
    except subprocess.TimeoutExpired:
        took, doc, err = 60.0, None, "no answer in 60 s"
    left = []
    if os.path.exists(pids):
        with open(pids) as fh:
            left = [int(x) for x in fh.read().split()]
    return doc, took, left, err


class PipeShapes(Case):
    def test_every_pipe_reader_answers_on_its_clock_and_says_what_it_did_not_see(self):
        cases = [(r, s) for r in READERS for s in list(SHAPES) + ["never_exits"] if not (s == "never_exits" and r.clock is None)]

        def one(item):
            r, s = item
            return item, run_case(os.path.join(self.dir, "%s-%s" % (r.name.split()[0], s)), r, s)
        with ThreadPoolExecutor(3) as pool:
            ran = list(pool.map(one, cases))
        time.sleep(0.5)
        for (reader, shape), (doc, took, left, err) in ran:
            with self.subTest(reader=reader.name, shape=shape):
                self.assertIsNotNone(doc, err)
                if shape == "never_exits":
                    self.assertLess(took, reader.clock + ANSWER_BOUND, "the tool's clock did not end the program")
                    self.assertEqual(reader.never(doc), "")
                else:
                    self.assertLess(took, ANSWER_BOUND, "waited on a program that had ended")
                    if shape in PIPE_SHAPES or (shape == "stderr_only" and reader.stderr_is_pipe):
                        self.assertEqual(reader.held(doc), "")
                    else:
                        self.assertNotIn("kept its output pipe open", json.dumps(doc), "a pipe that nothing held was said to be held")
                for pid in left:
                    self.assertFalse(alive(pid), "the process %s left is still running" % shape)

    def test_the_manifest_sentences_about_pipes_are_what_the_matrix_measures(self):
        """The sentences say one second after the program ended, whatever the leftover writes, and the matrix above answers inside ANSWER_BOUND for each."""
        for tool in ("image_layout", "file_type", "icat_extract", "chunk_needles", "archive_extract"):
            text = manifest(tool)["description"]
            self.assertIn("one second", text, tool)
            if tool != "archive_extract":
                self.assertIn("PIPES:", text, tool)
        with open(os.path.join(os.path.dirname(recipe_path("archive-members", "run.py")), "recipe.json"), encoding="utf-8") as fh:
            self.assertIn("one second", json.load(fh)["description"])

    def run_child(self, tool, shape_body, timeout):
        """image_layout's / file_type's run_child, called in a process of its own: (outcome, seconds, peak RSS in MiB, bytes taken)."""
        code = ("import sys, time, resource, subprocess, runpy\n"
                "ns = runpy.run_path(sys.argv[1], run_name='probe')\n"
                "began = time.monotonic()\n"
                "try:\n"
                "    p = ns['run_child'](['sh', '-c', sys.argv[2]], float(sys.argv[3]))\n"
                "    out = 'finished %d %d' % (p.returncode, len(p.stdout))\n"
                "except subprocess.TimeoutExpired:\n"
                "    out = 'not taken'\n"
                "print(out, round(time.monotonic() - began, 2), resource.getrusage(resource.RUSAGE_SELF).ru_maxrss // 1024)\n")
        r = subprocess.run([sys.executable, "-c", code, tool_path(tool), shape_body, str(timeout)], capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr[-300:])
        parts = r.stdout.split()
        return " ".join(parts[:-2]), float(parts[-2]), int(parts[-1])

    @LINUX
    def test_run_child_of_image_layout_and_file_type_bounds_time_and_memory_in_every_shape(self):
        for tool in ("image_layout", "file_type"):
            for shape, body in (("silent", "echo ok; sleep 600 &"), ("w10ms", "echo ok; ( while :; do printf x; sleep 0.01; done ) &"),
                                ("w700ms", "echo ok; ( while :; do printf x; sleep 0.7; done ) &"), ("flood", "echo ok; yes aaaaaaaaaaaaaaaa &"),
                                ("stderr_only", "echo ok; sleep 600 >/dev/null &"), ("never_exits", "echo ok; exec sleep 600")):
                with self.subTest(tool=tool, shape=shape):
                    outcome, took, rss = self.run_child(tool, body, 3)
                    self.assertEqual(outcome, "not taken")
                    self.assertLess(took, 5.0 if shape == "never_exits" else 3.0)
                    self.assertLess(rss, 200, "the buffered output was not bounded")
            with self.subTest(tool=tool, shape="stdin_only"):
                outcome, took, rss = self.run_child(tool, "echo ok; sleep 600 >/dev/null 2>&1 &", 3)
                self.assertEqual(outcome, "finished 0 3")
                self.assertLess(took, 3.0)


class SevenZip(Reader):
    """archive_extract over the real 7-Zip, whose extraction stdout is a pipe read as the members' bytes; the stand-in wraps the real program and leaves the shape after `x`."""
    name = "archive_extract (7z)"
    clock = 10
    real = None

    def make(self, root, tail):
        src = os.path.join(root, "src7")
        os.makedirs(src)
        with open(os.path.join(src, "a.bin"), "wb") as fh:
            fh.write(os.urandom(3000))
        archive = os.path.join(root, "inputs", "t.7z")
        os.makedirs(os.path.dirname(archive))
        subprocess.run([self.real, "a", "-bd", archive, "."], cwd=src, capture_output=True, check=True)
        wrapper = '"%s" "$@"\nrc=$?\ncase "$1" in\n x)\n%s;;\nesac\nexit $rc\n' % (self.real, tail)
        return (tool_path("archive_extract"), json.dumps({"path": archive, "out_dir": "@ROOT@/out", "max_seconds": 8}), [], {}, {"7z": wrapper}, {})

    def held(self, doc):
        return "" if doc.get("status") != "complete" else "archive_extract answered complete although 7z's stream was held open after the program ended: %s" % doc.get("status_basis")


SEVEN_Z = next((p for p in ("7z", "7zz", "7za") if shutil.which(p)), None)


@unittest.skipUnless(SEVEN_Z, "no 7z program on this host")
class SevenZipShapes(Case):
    @LINUX
    def test_the_extraction_pipe_of_7z_in_every_shape(self):
        reader = SevenZip()
        reader.real = shutil.which(SEVEN_Z)

        def one(shape):
            return shape, run_case(os.path.join(self.dir, "7z-" + shape), reader, shape)
        with ThreadPoolExecutor(3) as pool:
            ran = list(pool.map(one, list(SHAPES)))
        time.sleep(0.5)
        for shape, (doc, took, left, err) in ran:
            with self.subTest(shape=shape):
                self.assertIsNotNone(doc, err)
                self.assertLess(took, ANSWER_BOUND, "waited on a program that had ended")
                # the members are checked against their CRC: a stream with bytes past the listing's is flagged, and a leftover that was ended makes the answer partial
                self.assertTrue(doc["status"] != "complete" or doc.get("stream_longer_than_listing") is True, (doc["status"], doc.get("status_basis")))
                if shape in ("stderr_only", "stdin_only", "silent"):
                    self.assertEqual(doc["status"], "partial")
                    self.assertGreaterEqual(doc["program_group"]["left_behind"], 1)
                for pid in left:
                    self.assertFalse(alive(pid), "the process %s left is still running" % shape)


class BrowserStorage(Reader):
    """The shared block's reader (communicate_bounded): the reader prints its document on a pipe and leaves the shape."""
    name = "browser_storage"
    clock = None

    def make(self, root, tail):
        import browser_storage_fixtures as BF
        meta = BF.global_metadata([(1, "https://app.example.test", "appdb", 1, {1: "messages"})])
        venv = os.path.join(root, "src", "ccl_indexeddb_dump", ".venv", "bin")
        os.makedirs(venv)
        doc = ('{"ok":true,"versions":{},"files":[{"name":"000003.log","kind":"log","status":"read"}],"format":"leveldb","records_total":0,"counts":{},'
               '"previews":[],"decode_errors":{}}')
        stand_in(venv, "python", "cat > /dev/null\necho '%s'\n%s" % (doc, tail))
        return (tool_path("browser_storage"), json.dumps({"path": "@ROOT@/idb"}), [], {"idb/000003.log": BF.log_file([BF.write_batch(1, meta)])}, {},
                {"DFIRSWARM_SRC_DIR": os.path.join(root, "src")})

    def held(self, doc):
        return "" if doc.get("status") == "partial" and doc.get("program_group", {}).get("left_behind", 0) >= 1 else "browser_storage: %s %s" % (doc.get("status"), doc.get("program_group"))


class BlockReaders(Case):
    @LINUX
    def test_the_shared_blocks_reader_in_every_shape(self):
        reader = BrowserStorage()

        def one(shape):
            return shape, run_case(os.path.join(self.dir, "bs-" + shape), reader, shape)
        with ThreadPoolExecutor(3) as pool:
            ran = list(pool.map(one, [s for s in SHAPES]))
        time.sleep(0.5)
        for shape, (doc, took, left, err) in ran:
            with self.subTest(shape=shape):
                self.assertIsNotNone(doc, err)
                self.assertLess(took, ANSWER_BOUND, "waited on a program that had ended")
                if shape in ("silent", "stderr_only", "stdin_only"):
                    self.assertEqual(reader.held(doc), "")
                elif shape in ("w10ms", "w700ms"):
                    self.assertNotEqual(doc["status"], "complete", "a leftover wrote into the document's pipe and the answer is complete")   # failed: the document is not JSON any more
                for pid in left:
                    self.assertFalse(alive(pid), "the process %s left is still running" % shape)


STOP_TAIL = ("setsid sh -c 'echo $$ >> \"@PIDS@\"; sleep 600' </dev/null >/dev/null 2>&1 &\n"
             "echo $$ >> \"@PIDS@\"\nexec sleep 600\n")


class StopPath(Case):
    """A stop signal ends what the program started and lost (a process of a session of its own), not only the program."""

    @LINUX
    def test_sigterm_ends_the_program_and_what_it_left_for_every_pipe_reader(self):
        import signal
        for reader in (ImageLayout(), FileType(), ChunkNeedles(), IcatExtract(), ArchiveMembers()):
            with self.subTest(reader=reader.name):
                root = os.path.join(self.dir, "stop-" + reader.name.split()[0])
                os.makedirs(root)
                pids = os.path.join(root, "pids")
                script, stdin_text, args, files, bins, env = reader.make(root, STOP_TAIL.replace("@PIDS@", pids))
                d = os.path.join(root, "bin")
                os.makedirs(d)
                for n, body in bins.items():
                    stand_in(d, n, body)
                for rel, data in files.items():
                    p = os.path.join(root, rel)
                    os.makedirs(os.path.dirname(p), exist_ok=True)
                    with open(p, "wb") as fh:
                        fh.write(data)
                e = dict(os.environ, PATH=d + os.pathsep + os.environ["PATH"], **env)
                for k in ("JOB_ID", "OUT", "AGENT_ID", "SECRET_OUTPUT"):
                    e.pop(k, None)
                with open(os.path.join(root, "stdin.json"), "w", encoding="utf-8") as fh:
                    fh.write(stdin_text.replace("@ROOT@", root))
                proc = subprocess.Popen([sys.executable, script] + [a.replace("@ROOT@", root) for a in args], stdin=open(os.path.join(root, "stdin.json"), encoding="utf-8"),
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=root, env=e, start_new_session=True)
                end = time.monotonic() + 30
                while time.monotonic() < end and not (os.path.exists(pids) and len(open(pids).read().split()) >= 2):
                    time.sleep(0.05)
                started = open(pids).read().split() if os.path.exists(pids) else []
                self.assertGreaterEqual(len(started), 2, "the stand-in did not start")
                proc.send_signal(signal.SIGTERM)
                proc.communicate(timeout=30)
                time.sleep(0.3)
                for pid in started:
                    self.assertFalse(alive(int(pid)), "%s: pid %s survived SIGTERM" % (reader.name, pid))


if __name__ == "__main__":
    unittest.main()
