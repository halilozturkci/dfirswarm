#!/usr/bin/env python3
"""Read an image's layout once, so a swarm does not read it seven times.

Every extract, every listing and every hive in a case is addressed by a volume
offset, and in the measured runs the commonest wasted minutes were spent
rediscovering it or passing it in the wrong unit. mmls prints sectors, the
Sleuth Kit's -o takes sectors, and an agent that multiplies by 512 once gets
nothing back and concludes the image is damaged.

So: run mmls, run fsstat per slot, read the E01's own acquisition record when
there is one, and hand back both the sector offset and the byte offset with the
unit named on each.

What this is: a probe, run through the Sleuth Kit as installed. What it is not:
a proof that there is no partition table, no volume or no encryption. A tool
that could not run, timed out or was refused is `unknown` or `not attempted`,
never "no partition table". A `sector_size` given by the caller is passed to
mmls and fsstat as -b, so the offsets the Sleuth Kit parsed with and the byte
offsets returned here use one unit; it is not arithmetic done afterwards. One
path is read: a split raw set is not assembled, and the note says so when it
sees a first segment. The programs' own output is kept whole in files.
"""
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path


# BEGIN SHARED STOP
# The same text is in every tool that carries this block (tests/pack-shared-stop.test.ts holds the copies equal). SIGTERM, SIGINT and SIGHUP end the tool with JSON
# (status failed with interrupted true: a stop is not a status, the statuses are complete, partial and failed; exit 128 + the signal) and remove the temporary file a page was writing; the tool's own clock (set_deadline) is below the manifest's.
# The handlers are in as soon as the module has run as far as this block, with a minimal last word until main() installs the tool's own (only
# the start of the interpreter and the compiling of the file come before it). The first signal counts: a second one does nothing while the
# first is answered. print_answer holds the stop signals back while the answer is printed, so exactly one complete document is written
# (the ransomware tools print through it; the windows tools hold the signals in the emit of their boundary block, and carry this text unused).
import signal
import time

STOP = {"last_word": None, "deadline": None}


def set_deadline(seconds):
    STOP["deadline"] = time.monotonic() + seconds


def out_of_time():
    return STOP["deadline"] is not None and time.monotonic() > STOP["deadline"]


def _on_signal(signum, _frame):
    for other in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(other, signal.SIG_IGN)
    for page in list(globals().get("PAGES", ())):
        tmp = getattr(page, "_tmp", None)
        if tmp is not None:
            try:
                os.unlink(tmp)
            except OSError:
                pass
    last_word = STOP["last_word"]
    if last_word:
        try:
            last_word(signum)
        except Exception:  # noqa: BLE001 - a last word is best effort
            pass
    os._exit(128 + signum)


def install_signal_handlers(last_word=None):
    STOP["last_word"] = last_word
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, _on_signal)


def interrupted_answer(signum, **extra):
    print(json.dumps({"error": "stopped by signal %d before the answer was complete" % signum, "status": "failed", "interrupted": True,
                      "status_basis": "the tool was stopped by signal %d; nothing it had read is an answer" % signum,
                      "signal": signum, **extra}), flush=True)


def print_answer(answer, **dumps_kwargs):
    """Print the answer with the stop signals held back: a signal that came in the middle of the write would end the process there, with the
    answer cut. The tool ends by itself right after, so a signal that is held is not lost for good."""
    try:
        signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT, signal.SIGHUP})
    except (AttributeError, ValueError, OSError):
        pass
    STOP["last_word"] = None
    print(json.dumps(answer, **dumps_kwargs))


install_signal_handlers(lambda signum: interrupted_answer(signum))
# END SHARED STOP

import os as _os
import sys as _sys
import threading as _threading

# ---- the one protected printer of an answer (outside the shared block) ------------------------------------------------------------
# The stop signals are held while the answer is written, so that a signal cannot cut the document. A reader that stops taking it (a full
# pipe) would make that tool unkillable by SIGTERM: the held write is therefore bounded. If a stop signal is waiting when
# HELD_WRITE_SECONDS have passed, the tool says so on stderr and ends with 128 plus that signal; nothing is claimed about the answer.
HELD_WRITE_SECONDS = int(_os.environ.get("TOOL_HELD_WRITE_SECONDS") or 30)       # the environment variable is for the tests
_STOPS = (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)


def _unstick():
    try:
        waiting = signal.sigpending()
    except (AttributeError, OSError):
        waiting = set()
    held = [s for s in _STOPS if s in waiting]
    if held:
        try:
            _os.write(2, ("the answer could not be written in %d seconds (the reader is not taking it); ended by the stop signal that was held\n" % HELD_WRITE_SECONDS).encode())
        except OSError:
            pass
        _os._exit(128 + int(held[0]))
    again = _threading.Timer(1.0, _unstick)
    again.daemon = True
    again.start()


ERROR_FLAGS = ("all_results_error", "all_matches_error", "receipt_error", "receipts_error", "rows_file_error", "rows_error", "invalid_lines_file_error",
               "write_error", "values_error")


def _flagged(node, depth=0):
    """The first error flag found in an answer (top level, and two levels of dicts below it), or None."""
    if not isinstance(node, dict) or depth > 2:
        return None
    for key in ERROR_FLAGS:
        if node.get(key):
            return key
    for value in node.values():
        found = _flagged(value, depth + 1)
        if found:
            return found
    return None


def _reconcile(answer):
    """status, complete and ok are one fact: an error flag in the answer (a file that should hold the rest could not be written) is not a
    complete answer, and a complete or ok that survives a partial or failed status is a wrong claim. Said once, here, for every answer."""
    if not isinstance(answer, dict):
        return
    flag = _flagged(answer)
    if flag and answer.get("status") == "complete":
        answer["status"] = "partial"
        basis = answer.get("status_basis")
        answer["status_basis"] = ("%s; but %s says part of what was asked for could not be kept" % (basis, flag)) if basis else "%s says part of what was asked for could not be kept" % flag
    if answer.get("status") in ("partial", "failed") or flag:
        if answer.get("complete") is True:
            answer["complete"] = False
    if answer.get("status") == "failed" and answer.get("ok") is True:
        answer["ok"] = False


# BEGIN SHARED TEMPS
# One lifecycle for the hidden temporary files of a run. A file is made by temp_create (or its name is registered with temp_hold before it is
# made), it is registered before anything else is done with it, and it stays registered until temp_done says it was renamed into place. What is
# still registered when the run ends is removed: by atexit on a normal end or any exception, by drop_temporaries in the last-resort handler, and
# by the stop signal's own cleanup, which removes the _tmp of every object in PAGES (a registered name is one such object).
import atexit
import tempfile

if "PAGES" not in globals():
    PAGES = []                 # objects with a hidden temporary file (_tmp) that a stop removes


class _HeldTemp:
    def __init__(self, name):
        self._tmp = name


def temp_hold(name):
    """Register a temporary file that is about to be made (or has been): it is removed on every way out unless temp_done is called."""
    held = _HeldTemp(os.fspath(name))
    PAGES.append(held)
    return held._tmp


def temp_create(directory, prefix, suffix=""):
    """tempfile.mkstemp with the new name registered at once: (fd, name)."""
    fd, name = tempfile.mkstemp(dir=os.fspath(directory), prefix=prefix, suffix=suffix)
    temp_hold(name)
    return fd, name


def temp_done(name):
    """The file was renamed into place (or is kept on purpose): it is no longer a temporary."""
    name = os.fspath(name)
    PAGES[:] = [p for p in PAGES if not (isinstance(p, _HeldTemp) and p._tmp == name)]


def temp_drop(name):
    """Remove one temporary now; False when it could not be removed (it stays registered, and the end of the run tries again)."""
    try:
        os.unlink(name)
    except FileNotFoundError:
        pass
    except OSError:
        return False
    temp_done(name)
    return True


def temp_replace(tmp, dest):
    os.replace(tmp, dest)
    temp_done(tmp)


def drop_temporaries():
    """Remove every temporary still registered (the pages being written and the held names); the names that could not be removed come back."""
    left = []
    for page in list(PAGES):
        tmp = None
        try:
            tmp = getattr(page, "_tmp", None)
            if tmp is not None:
                os.unlink(tmp)
        except FileNotFoundError:
            pass
        except Exception:   # noqa: BLE001 - every one is tried
            left.append(str(tmp))
    return left


atexit.register(drop_temporaries)
# END SHARED TEMPS


def _guarded_write(write):
    try:
        before = signal.pthread_sigmask(signal.SIG_BLOCK, set(_STOPS))      # before the timer thread exists, so that the thread holds them too
    except (AttributeError, ValueError, OSError):
        before = None
    watch = _threading.Timer(HELD_WRITE_SECONDS, _unstick)
    watch.daemon = True
    watch.start()
    try:
        write()
        _sys.stdout.flush()
    except BrokenPipeError:                       # the reader is gone: there is nobody to tell
        _os._exit(1)
    watch.cancel()
    if before is not None:
        # The document is whole. A stop that came while it was written is delivered now; the last word was cleared, so it ends the tool
        # (128 plus the signal) with nothing more on stdout. The mask is also what an in-process caller (a test) had before.
        signal.pthread_sigmask(signal.SIG_SETMASK, before)


_shared_print_answer = print_answer


def print_answer(answer, **dumps_kwargs):
    _reconcile(answer)
    _guarded_write(lambda: _shared_print_answer(answer, **dumps_kwargs))


def _unexpected_tool(kind, value, _tb):
    """Last resort: an error nobody foresaw is an answer too. The hidden temporaries are removed first (a name that cannot be removed is said in the
    answer), then one JSON document with the class and, for a file-system error, its reason (a message can quote a name from the evidence), and
    exit 1; what was written before it is not claimed. A stop signal that arrives while this runs is held with the answer's write and is answered by
    this document and exit 1, not by 128 + the signal."""
    try:
        left = drop_temporaries()
        reason = getattr(value, "strerror", None) if issubclass(kind, OSError) else None
        said = ("a path or file could not be used: %s" % (reason or kind.__name__)) if issubclass(kind, (OSError, ValueError)) else "internal error: %s" % kind.__name__
        answer = {"tool": globals().get("TOOL"), "status": "failed", "error": said,
                  "status_basis": "the tool stopped on an error it did not foresee (%s); what it had written before is not claimed" % kind.__name__}
        if left:
            answer["temporaries_left"] = left[:10]
            answer["status_basis"] += "; hidden temporary files that could not be removed are listed in temporaries_left"
        print_answer(answer)
    except BaseException:       # noqa: BLE001 - nothing may stop the exit
        pass
    os._exit(1)


sys.excepthook = _unexpected_tool

PAGES = []                 # objects with a hidden temporary file (_tmp) that a stop removes


CHILD = {"proc": None}     # the program being run, ended by its pid on a stop
IMAGES = []                # the image paths as the programs are given them (one, or the sources of a descriptor)


def run_child(argv, timeout, **kwargs):
    """subprocess.run with its output captured, with the child recorded so that a stop can end it by its pid."""
    for each in argv[1:]:
        if isinstance(each, str) and each in IMAGES and os.path.lexists(each):
            open_regular(each).close()         # the image was checked a moment ago: a FIFO or device put in its place is refused, not handed to mmls or fsstat
    proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)
    CHILD["proc"] = proc
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        raise
    finally:
        CHILD["proc"] = None
    return subprocess.CompletedProcess(argv, proc.returncode, out, err)


def end_child():
    proc = CHILD["proc"]
    if proc is not None:
        try:
            proc.kill()
            proc.wait(timeout=5)
        except Exception:  # noqa: BLE001 - best effort
            pass


class _Held:
    _tmp = None


HELD = _Held()             # the hidden file of the program output being kept
PAGES.append(HELD)

TOOL = {"name": "image_layout", "version": 13}
CHILD_TIMEOUT = 120
TOTAL_BUDGET = 270          # seconds, under the manifest's 300
SECTOR_MAX = 65536
VIRTUAL_DISKS = ("vhd", "vhdx", "vmdk", "qcow", "aff")
# The image type img_stat prints for what the Sleuth Kit has a reader for; a container with none is read as "raw" if at all.
TSK_IMAGE_TYPES = {"ewf": "ewf", "vmdk": "vmdk", "vhd": "vhd", "aff": "aff"}


def fail(message, **extra):
    print_answer({"error": message, "status": "failed", "status_basis": "the tool stopped with an error: %s" % message, "tool": TOOL, **extra})
    raise SystemExit(1)


class Deadline:
    def __init__(self, seconds):
        self.end = time.monotonic() + seconds

    def left(self):
        return self.end - time.monotonic()


def run(argv, deadline):
    """A program's outcome: kind is ok, missing, timeout, refused (it ran and
    exited non-zero), skipped (the time budget was gone) or error. Locale is C
    so the messages parsed below are the ones the Sleuth Kit prints."""
    if not shutil.which(argv[0]):
        return {"kind": "missing", "stdout": "", "stderr": "%s is not on PATH" % argv[0], "code": None}
    budget = min(CHILD_TIMEOUT, deadline.left())
    if budget <= 1:
        return {"kind": "skipped", "stdout": "", "stderr": "not run: the tool's time budget (%ds) was used" % TOTAL_BUDGET, "code": None}
    env = dict(os.environ, LC_ALL="C", LANG="C")
    try:
        p = run_child(argv, budget, env=env)
    except subprocess.TimeoutExpired:
        return {"kind": "timeout", "stdout": "", "stderr": "%s timed out after %ds" % (argv[0], budget), "code": None}
    except OSError as exc:
        return {"kind": "error", "stdout": "", "stderr": str(exc), "code": None}
    return {"kind": "ok" if p.returncode == 0 else "refused", "code": p.returncode,
            "stdout": p.stdout.decode("utf-8", "replace"), "stderr": p.stderr.decode("utf-8", "replace").strip()}


def open_regular(path):
    """open(path, "rb") for a path that was just checked as a regular file: opened without waiting (O_NONBLOCK) and looked at with fstat on the
    descriptor, so a FIFO or a device put in its place after the check is refused and never waited on (a FIFO would hold the tool for ever)."""
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    try:
        if os.fstat(fd).st_mode & 0o170000 != 0o100000:
            raise OSError(22, "is not a regular file (it changed after it was checked)")
    except BaseException:
        os.close(fd)
        raise
    return open(fd, "rb")


# ---- the descriptor (layer_describe's file), read the same way in image_layout, icat_extract, chunk_needles and byte_range_extract -----
DESCRIPTOR_MAX = 16 * 1024 * 1024
DESCRIPTOR_VERIFY_SECONDS = 120          # the clock for verify_sources (a descriptor is checked before the program runs)
DESCRIPTOR_LAYERS = ("raw", "split_raw", "ewf", "vmdk", "vhd", "vhdx", "qcow", "aff")


class DescriptorError(Exception):
    """The descriptor cannot be used. The message never quotes a path or text from the descriptor."""


def load_descriptor(ref, pin=None, verify_sources=False, deadline=None):
    """Read a layer descriptor and check it before anything is run on what it names. A dict: file, sha256, sector_size, unit, layer, images
    (the paths a Sleuth Kit program is given, in order), sources, media_bytes, volumes (the allocated slots fsstat read: offset_sectors,
    offset_bytes, fs_type) and checked ("sizes" or "sha256"). It is refused when its bytes do not hash to the name it carries (layer-<sha256>.json),
    when it is not the shape layer_describe writes, when it lists a dependency that is not declared, when a source is no longer a regular file of
    the size it records, or when a volume's offset is not inside the media. A source swapped for another of the same size is NOT found unless
    verify_sources is true, which reads every source again and compares its sha256."""
    import hashlib as _hashlib
    import re as _re
    import stat as _stat
    if not isinstance(ref, str) or not ref or "\0" in ref:
        raise DescriptorError("descriptor is a path to a layer descriptor file")
    if pin is not None and (not isinstance(pin, str) or not _re.fullmatch(r"[0-9a-f]{64}", pin)):
        raise DescriptorError("descriptor_sha256 is 64 lower-case hexadecimal digits")
    try:
        fd = os.open(ref, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise DescriptorError("the descriptor cannot be opened: %s" % (exc.strerror or exc.__class__.__name__))
    try:
        st = os.fstat(fd)
        if not _stat.S_ISREG(st.st_mode):
            raise DescriptorError("the descriptor is not a regular file")
        if st.st_size > DESCRIPTOR_MAX:
            raise DescriptorError("the descriptor is larger than %d bytes" % DESCRIPTOR_MAX)
        data = b""
        while len(data) <= DESCRIPTOR_MAX:
            block = os.read(fd, 1 << 20)
            if not block:
                break
            data += block
    except OSError as exc:
        raise DescriptorError("the descriptor cannot be read: %s" % (exc.strerror or exc.__class__.__name__))
    finally:
        os.close(fd)
    if len(data) > DESCRIPTOR_MAX:
        raise DescriptorError("the descriptor is larger than %d bytes" % DESCRIPTOR_MAX)
    sha = _hashlib.sha256(data).hexdigest()
    name = os.path.basename(ref)
    if name != "layer-%s.json" % sha:
        raise DescriptorError("the descriptor's bytes do not hash to the name it carries (layer-<sha256>.json): it was changed, renamed, or is not a descriptor layer_describe wrote")
    if pin is not None and pin != sha:
        raise DescriptorError("the descriptor's sha256 is not the one descriptor_sha256 pins")
    try:
        doc = json.loads(data.decode("ascii"))
    except (ValueError, RecursionError):
        raise DescriptorError("the descriptor is not JSON")
    if not isinstance(doc, dict) or doc.get("kind") != "layer_descriptor" or doc.get("descriptor_version") != 1:
        raise DescriptorError("the descriptor is not a layer descriptor of version 1")
    if doc.get("status") not in ("complete", "partial"):
        raise DescriptorError("the descriptor's status is not complete or partial")
    size = doc.get("sector_size")
    if not isinstance(size, int) or isinstance(size, bool) or size < 512 or size > 65536 or size % 512:
        raise DescriptorError("the descriptor's sector_size is not a multiple of 512 from 512 to 65536")
    if doc.get("missing_dependencies"):
        raise DescriptorError("the descriptor lists a dependency that is not declared (missing_dependencies): the set is not whole")
    layer = (doc.get("container") or {}).get("layer") if isinstance(doc.get("container"), dict) else None
    if layer not in DESCRIPTOR_LAYERS:
        raise DescriptorError("the descriptor's container layer is not one this tool knows")
    sources = doc.get("sources")
    if not isinstance(sources, list) or not 1 <= len(sources) <= 10000:
        raise DescriptorError("the descriptor lists no sources, or too many")
    for i, s in enumerate(sources):
        if not isinstance(s, dict) or s.get("index") != i or not isinstance(s.get("path"), str) or not s["path"] or "\0" in s["path"]:
            raise DescriptorError("source %d of the descriptor is malformed" % i)
        if not isinstance(s.get("bytes"), int) or isinstance(s.get("bytes"), bool) or s["bytes"] < 0:
            raise DescriptorError("source %d of the descriptor has no size" % i)
        if s.get("sha256") is not None and not (isinstance(s["sha256"], str) and _re.fullmatch(r"[0-9a-f]{64}", s["sha256"])):
            raise DescriptorError("source %d of the descriptor has a malformed sha256" % i)
    used = sources if layer in ("raw", "split_raw", "ewf") else sources[:1]
    checked = "sizes"
    for s in used:
        try:
            fd = os.open(s["path"], os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0))
        except OSError as exc:
            raise DescriptorError("source %d can no longer be opened: %s" % (s["index"], exc.strerror or exc.__class__.__name__))
        try:
            st = os.fstat(fd)
            if not _stat.S_ISREG(st.st_mode):
                raise DescriptorError("source %d is no longer a regular file" % s["index"])
            if st.st_size != s["bytes"]:
                raise DescriptorError("source %d is %d bytes, the descriptor says %d: it changed after the descriptor was made" % (s["index"], st.st_size, s["bytes"]))
            if verify_sources:
                if s.get("sha256") is None:
                    raise DescriptorError("source %d has no sha256 in the descriptor, so verify_sources cannot check it" % s["index"])
                h = _hashlib.sha256()
                while True:
                    block = os.read(fd, 1 << 20)
                    if not block:
                        break
                    h.update(block)
                    if deadline is not None and time.monotonic() > deadline:
                        raise DescriptorError("the time budget ran out while source %d was being verified" % s["index"])
                if h.hexdigest() != s["sha256"]:
                    raise DescriptorError("source %d no longer hashes to the sha256 the descriptor records" % s["index"])
                checked = "sha256"
        except OSError as exc:
            raise DescriptorError("source %d cannot be read: %s" % (s["index"], exc.strerror or exc.__class__.__name__))
        finally:
            os.close(fd)
    media = doc.get("media") if isinstance(doc.get("media"), dict) else {}
    media_bytes = media.get("bytes") if isinstance(media.get("bytes"), int) and not isinstance(media.get("bytes"), bool) else None
    unit = doc.get("partition_unit") if isinstance(doc.get("partition_unit"), int) and not isinstance(doc.get("partition_unit"), bool) else size
    volumes = []
    for p in doc.get("partitions") if isinstance(doc.get("partitions"), list) else []:
        fs = p.get("filesystem") if isinstance(p, dict) else None
        if not isinstance(fs, dict) or fs.get("readable") is not True:
            continue
        sectors, byte_offset = p.get("offset_sectors"), p.get("offset_bytes")
        if not isinstance(sectors, int) or isinstance(sectors, bool) or sectors < 0 or not isinstance(byte_offset, int) or byte_offset != sectors * unit:
            raise DescriptorError("a volume of the descriptor has an offset that is not its sector offset times the sector size")
        if media_bytes is not None and byte_offset >= media_bytes:
            raise DescriptorError("a volume of the descriptor starts at byte %d, past the end of the %d-byte media" % (byte_offset, media_bytes))
        volumes.append({"offset_sectors": sectors, "offset_bytes": byte_offset, "fs_type": fs.get("fs_type") if isinstance(fs.get("fs_type"), str) else None})
    return {"file": name, "sha256": sha, "sector_size": size, "unit": unit, "layer": layer, "images": [s["path"] for s in used], "sources": sources,
            "media_bytes": media_bytes, "volumes": volumes, "checked": checked, "status": doc["status"]}


def descriptor_offset(desc, given):
    """The volume offset in sectors a tool uses with a descriptor: the one the caller names, which must be a volume of the descriptor; else the only volume."""
    starts = [v["offset_sectors"] for v in desc["volumes"]]
    if given is not None:
        if given not in starts:
            raise DescriptorError("offset %s is not a volume of the descriptor (its volumes start at sectors %s)" % (given, ", ".join(str(s) for s in starts) or "none"))
        return given
    if len(starts) == 1:
        return starts[0]
    raise DescriptorError(("the descriptor has no volume fsstat read" if not starts else "the descriptor has several volumes; pass offset= (a start sector)") +
                          ((": " + ", ".join(str(s) for s in starts)) if starts else ""))


def container_of(path):
    """Name the container from its first bytes (and, for a fixed VHD, its last
    512), not from its extension. (name, basis): the basis says how sure that is."""
    try:
        size = os.path.getsize(path)
        with open_regular(path) as fh:
            head = fh.read(512)
            tail = b""
            if size >= 512:
                fh.seek(size - 512)
                tail = fh.read(512)
    except OSError as exc:
        fail("cannot read the image", path=path, reason=str(exc))
    if head[:3] in (b"EVF", b"LVF"):
        return "ewf", "signature at offset 0"          # E01/Ex01/L01
    if head[:3] == b"AFF":
        return "aff", "signature at offset 0"          # AFF1; AFF4 is a zip container and is not named from its head
    if head[:4] == b"QFI\xfb":
        return "qcow", "signature at offset 0"
    if head[:8] == b"vhdxfile":
        return "vhdx", "signature at offset 0"
    if head[:4] == b"KDMV" or head.startswith(b"# Disk DescriptorFile"):
        return "vmdk", "signature at offset 0"
    if head[:8] == b"conectix":
        return "vhd", "footer copy at offset 0 (a dynamic or differencing disk)"
    if tail[:8] == b"conectix":
        return "vhd", "footer in the last 512 bytes (a fixed disk)"
    return "raw", "no container signature matched: the bytes of a disk or volume, or a format this tool does not know"


# The columns mmls writes are fixed width: its slot is %.3d and its start, end and length are %.10 (TSK's mmls.c), so a row has three
# runs of ten or more ASCII digits. A GPT name holds 36 UTF-16 units, a Mac partition name 32 bytes: a line made of a slot, a table column
# and three such runs does not fit in one, so a name holding a line break cannot forge a row. [0-9], never \d (Arabic-Indic digits are \d).
SLOT = re.compile(
    r"^(?P<slot>[0-9]{3,}):[ \t]+(?P<table>\S+)[ \t]+(?P<start>[0-9]{10,})[ \t]+(?P<end>[0-9]{10,})[ \t]+(?P<len>[0-9]{10,})[ \t]+(?P<desc>.*\S)[ \t]*$"
)


def parse_mmls(text):
    sector = 512
    m = re.search(r"Units are in (\d+)-byte sectors", text)
    if m:
        sector = int(m.group(1))
    slots, skipped = [], []
    expect, header = 0, False
    # Split on the line feed only: a name holding a carriage return or a vertical tab is still one line of the table.
    for raw in text.split("\n"):
        line = raw.rstrip("\r").strip()
        m = SLOT.match(line)
        if not header and not m:
            header = "Slot" in line and "Start" in line and "Description" in line
            continue
        if not line:
            continue
        # mmls prints a GPT partition name raw, so a name holding a line break can put a forged line in the table: a row is a line of the
        # shape mmls writes, the one the table is at (slots count 000, 001, ...) and one whose end and length agree with its start. Anything
        # else after the header is not a partition and is said.
        if not m:
            skipped.append("is not a row of the table: " + line[:120])
            continue
        start, end, length = int(m.group("start")), int(m.group("end")), int(m.group("len"))
        if int(m.group("slot")) != expect:
            skipped.append("is row %d where row %d was due: %s" % (int(m.group("slot")), expect, line[:120]))
            continue
        if end < start or length != end - start + 1:
            expect += 1
            skipped.append("has an end (%d) and a length (%d) that do not agree with its start (%d): %s" % (end, length, start, line[:120]))
            continue
        expect += 1
        desc = m.group("desc")
        slots.append({
            "slot": m.group("slot"),
            "start_sector": start,
            "length_sectors": length,
            "description": desc,
            # The table column says what a row is ("-------" a gap, "Meta" a table area, anything else an entry);
            # the description is a partition's own name in a GPT and says nothing of the sort.
            "allocated": m.group("table") != "-------" and m.group("table").lower() != "meta",
        })
    return sector, slots, skipped


# [ \t]* after the colon, never \s*: a field with no value must not take the next line for its value.
FSSTAT_FIELDS = (
    ("fs_type", re.compile(r"^File System Type:[ \t]*(\S.*?)[ \t]*$", re.M)),
    # NTFS and exFAT print a serial number, FAT a volume ID.
    ("volume_serial", re.compile(r"^Volume (?:Serial Number|ID):[ \t]*(\S.*?)[ \t]*$", re.M)),
    # FAT names the label's source in brackets (Boot Sector, Root Directory); ext and NTFS call it a name.
    ("volume_label", re.compile(r"^Volume (?:Label|Name)(?: \([^)\n]*\))?:[ \t]*(\S.*?)[ \t]*$", re.M)),
    ("cluster_size", re.compile(r"^Cluster Size:[ \t]*(\d+)", re.M)),
    ("sector_size", re.compile(r"^Sector Size:[ \t]*(\d+)", re.M)),
    ("total_range", re.compile(r"^Total (?:Cluster|Sector|Inode) Range:[ \t]*(\S.*?)[ \t]*$", re.M)),
    ("last_mounted", re.compile(r"^Last Mounted (?:at|on):[ \t]*(\S.*?)[ \t]*$", re.M)),
)


def sector_args(unit, forced):
    """-b for every Sleuth Kit call: the caller's sector size, or the unit mmls
    printed its offsets in when that is not the default, so one unit holds."""
    size = forced or (unit if unit and unit != 512 else None)
    return ["-b", str(size)] if size else []


class Keep:
    """The whole output of each program, in a file, named in the result."""

    def __init__(self, image):
        self.digest = hashlib.sha256(os.path.abspath(image).encode("utf-8", "surrogateescape")).hexdigest()[:12]
        job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
        if job and out:
            self.dir = Path(out) / "tool-output"
            self.shown = "store/jobs/%s/out/tool-output/" % re.sub(r"[^A-Za-z0-9_.-]", "_", job)
        else:
            agent = re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool")
            self.dir = Path("work") / agent / "tool-output"
            self.shown = str(self.dir) + "/"
        self.files, self.error = {}, None

    def save(self, label, text, argv=None):
        # Keyed by the command as well as the image: the same program run with another sector size is another file.
        key = hashlib.sha256(" ".join(argv or [label]).encode("utf-8", "replace")).hexdigest()[:8]
        name = "image_layout-%s-%s-%s.txt" % (self.digest, label, key)
        try:
            self.dir.mkdir(parents=True, exist_ok=True)
            fd, tmp = temp_create(self.dir, ".image_layout-")
            try:
                fh = os.fdopen(fd, "w", encoding="utf-8", errors="replace")
            except BaseException:
                os.close(fd)
                raise
            with fh:
                fh.write(text)
            temp_replace(tmp, self.dir / name)
            self.files[label] = self.shown + name
        except OSError as exc:
            self.error = "the programs' whole output could not be kept (%s: %s)" % (self.dir, exc.strerror or exc)


def describe_fs(image, offset, unit, forced, deadline, keep, label):
    argv = ["fsstat"] + sector_args(unit, forced) + (["-o", str(offset)] if offset is not None else []) + (image if isinstance(image, list) else [image])
    res = run(argv, deadline)
    if res["stdout"] or res["stderr"]:
        keep.save("fsstat-" + label, "$ %s\n%s%s" % (shlex.join(argv), res["stdout"], ("\n[stderr]\n" + res["stderr"]) if res["stderr"] else ""), argv)
    if res["kind"] != "ok":
        why = res["stderr"].splitlines()[-1] if res["stderr"] else "fsstat returned nothing"
        return {"readable": None if res["kind"] in ("missing", "timeout", "skipped", "error") else False,
                "outcome": res["kind"], "why": why, "command": shlex.join(argv)}
    found = {"readable": True, "outcome": "read", "command": shlex.join(argv)}
    for key, pattern in FSSTAT_FIELDS:
        m = pattern.search(res["stdout"])
        if m:
            found[key] = int(m.group(1)) if key in ("cluster_size", "sector_size") else m.group(1)
    return found


ACQUISITION = (
    ("acquired_by", re.compile(r"^[ \t]*Examiner name:[ \t]*(\S.*?)[ \t]*$", re.M)),
    ("case_number", re.compile(r"^[ \t]*Case number:[ \t]*(\S.*?)[ \t]*$", re.M)),
    ("description", re.compile(r"^[ \t]*Description:[ \t]*(\S.*?)[ \t]*$", re.M)),
    ("acquired_at", re.compile(r"^[ \t]*Acquisition date:[ \t]*(\S.*?)[ \t]*$", re.M)),
    ("system_date", re.compile(r"^[ \t]*System date:[ \t]*(\S.*?)[ \t]*$", re.M)),
    ("imager", re.compile(r"^[ \t]*Acquisition software:[ \t]*(\S.*?)[ \t]*$", re.M)),
    ("media_size", re.compile(r"^[ \t]*Media size:[ \t]*(\S.*?)[ \t]*$", re.M)),
    ("bytes_per_sector", re.compile(r"^[ \t]*Bytes per sector:[ \t]*(\d+)", re.M)),
    ("md5", re.compile(r"^[ \t]*MD5:[ \t]*([0-9a-fA-F]+)", re.M)),
    ("sha1", re.compile(r"^[ \t]*SHA1:[ \t]*([0-9a-fA-F]+)", re.M)),
    ("sha256", re.compile(r"^[ \t]*SHA256:[ \t]*([0-9a-fA-F]+)", re.M)),
)


def acquisition_record(image, deadline, keep):
    res = run(["ewfinfo"] + (image if isinstance(image, list) else [image]), deadline)
    if res["stdout"] or res["stderr"]:
        keep.save("ewfinfo", "$ ewfinfo %s\n%s%s" % (shlex.join(image if isinstance(image, list) else [image]), res["stdout"], ("\n[stderr]\n" + res["stderr"]) if res["stderr"] else ""), ["ewfinfo"] + (image if isinstance(image, list) else [image]))
    if res["kind"] != "ok":
        return {"read": False, "outcome": res["kind"], "why": res["stderr"].splitlines()[-1] if res["stderr"] else "ewfinfo returned nothing"}
    rec = {"read": True}
    for key, pattern in ACQUISITION:
        m = pattern.search(res["stdout"])
        if m:
            rec[key] = m.group(1)
    return rec


def split_raw_note(image):
    """A first segment of a split raw set (x.001 with x.002 beside it)."""
    m = re.match(r"^(.*)\.(0*1)$", image) or re.match(r"^(.*)\.(0+)$", image)       # .001 first, or .000 (some imagers start there)
    if m:
        digits = m.group(2)
        nxt = m.group(1) + "." + (digits[:-1] + ("2" if digits.endswith("1") else "1"))
        if os.path.isfile(nxt):
            return ("%s has a second segment beside it (%s). This tool reads one path: the offsets and "
                    "volumes below cover that segment alone, not the whole image. Assemble the set in order "
                    "with a reader that supports it before relying on them." % (os.path.basename(image), os.path.basename(nxt)))
    return None


def main():
    try:
        args = json.load(sys.stdin)
    except (ValueError, RecursionError) as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    if not isinstance(args, dict):
        fail("arguments are a JSON object")

    descriptor = None
    if args.get("descriptor") is not None:
        for _key in ("image", "sector_size"):
            if args.get(_key) is not None:
                fail("a descriptor replaces image and sector_size: give %s or the descriptor, not both" % _key)
        if args.get("verify_sources") is not None and not isinstance(args.get("verify_sources"), bool):
            fail("verify_sources is true or false")
        try:
            descriptor = load_descriptor(args["descriptor"], args.get("descriptor_sha256"), args.get("verify_sources") is True, time.monotonic() + DESCRIPTOR_VERIFY_SECONDS)
        except DescriptorError as exc:
            fail(str(exc))
    elif args.get("verify_sources") is not None or args.get("descriptor_sha256") is not None:
        fail("verify_sources and descriptor_sha256 belong with descriptor")
    if descriptor is not None:
        images = descriptor["images"]
        image = images[0]
    else:
        image = args.get("image")
        if not isinstance(image, str) or not image:
            fail("image (or descriptor) is required: the path to a raw or E01 image")
        images = [image]
    if not os.path.isfile(image):
        fail("no such image", image=image)

    forced = args.get("sector_size")
    if forced is not None and (not isinstance(forced, int) or isinstance(forced, bool)
                               or forced < 512 or forced > SECTOR_MAX or forced % 512):
        fail("sector_size must be a multiple of 512 from 512 to %d (the Sleuth Kit's -b takes no other)" % SECTOR_MAX, sector_size=forced)

    if descriptor is not None and descriptor["sector_size"] != 512:
        forced = descriptor["sector_size"]         # as a caller's sector_size would be
    # A name that begins with "-" would be read by every Sleuth Kit program as an option: "./" makes it a path.
    arg = ["./" + p if p.startswith("-") else p for p in images]
    IMAGES[:] = arg
    deadline = Deadline(TOTAL_BUDGET)
    keep = Keep(image)
    container, basis = container_of(image)
    out = {
        "tool": TOOL,
        "image": image,
        "bytes": os.path.getsize(image),
        "container": container,
        "container_basis": basis,
        "notes": [],
    }

    def _stopped(signum):
        end_child()
        print(json.dumps({"tool": TOOL, "image": image, "status": "partial", "interrupted": True, "signal": signum, "container": container,
                          "status_basis": "the tool was stopped by signal %d: the program it was running was ended, and what it had found so far was not kept; run it again" % signum}), flush=True)
    install_signal_handlers(_stopped)
    split = split_raw_note(image)
    if split:
        out["notes"].append(split)
    if out["container"] == "ewf":
        out["acquisition"] = acquisition_record(arg, deadline, keep)
        if out["acquisition"].get("read"):
            out["notes"].append(
                "The digests under 'acquisition' are the imager's, over what it acquired (a disk, a volume or "
                "a set of files: the acquisition record says which). They are not the digest of this "
                "container, and not of the volume inside it."
            )

    probe = ["mmls"] + (["-b", str(forced)] if forced else []) + arg
    res = run(probe, deadline)
    keep.save("mmls", "$ %s\n%s%s" % (shlex.join(probe), res["stdout"], ("\n[stderr]\n" + res["stderr"]) if res["stderr"] else ""), probe)
    out["mmls_command"] = shlex.join(probe)
    opened_as = None
    if res["kind"] == "ok" and out["container"] != "raw":
        # mmls succeeding says the Sleuth Kit read bytes, not which reader it used: a VHD or a QCOW2 TSK cannot open is read as
        # a raw disk, and the offsets then belong to the container's bytes and mean nothing for the disk inside. img_stat names the
        # image type TSK opened it as.
        st_argv = ["img_stat"] + (["-b", str(forced)] if forced else []) + arg
        st = run(st_argv, deadline)
        if st["stdout"] or st["stderr"]:
            keep.save("img_stat", "$ %s\n%s%s" % (shlex.join(st_argv), st["stdout"], ("\n[stderr]\n" + st["stderr"]) if st["stderr"] else ""), st_argv)
        m = re.search(r"^Image Type:[ \t]*(\S+)", st["stdout"], re.M)
        opened_as = m.group(1).lower() if m else None
        out["image_type_opened_by_sleuth_kit"] = opened_as
        expected = TSK_IMAGE_TYPES.get(out["container"])
        if opened_as is not None and opened_as != expected:
            out["partition_table"] = "unknown"
            out["partition_table_basis"] = ("mmls printed a table, but img_stat says the Sleuth Kit opened this %s container as %s%s: its offsets belong to "
                                            "the container's bytes, not to the disk inside, and are not given here" % (out["container"], opened_as, " (it has no reader for %s)" % out["container"] if not expected else ""))
            out["sector_size"] = forced or 512
            out["sector_size_source"] = "given by the caller (-b)" if forced else "the default: the offsets were not used"
            out["partitions"] = []
            out["volumes_readable"] = out["volumes_refused"] = out["volumes_not_attempted"] = 0
            out["notes"].append(
                "The Sleuth Kit opened this %s container as %s, so no offset or file system is read from it: convert or attach it (qemu-img, a "
                "mount of the virtual disk) and run this tool on the result, or use a reader of the container." % (out["container"], opened_as))
            res = {"kind": "container-not-opened", "stdout": "", "stderr": "", "code": None}
    lines_not_read = 0
    if res["kind"] == "container-not-opened":
        pass
    elif res["kind"] == "ok":
        if out["container"] in VIRTUAL_DISKS:
            out["notes"].append(
                ("The Sleuth Kit opened this %s container as %s (img_stat). " % (out["container"], opened_as) if opened_as else
                 "img_stat did not say which image type the Sleuth Kit opened this %s container as, so that it read the container and not its raw bytes "
                 "is not confirmed. " % out["container"])
                + "The offsets below are sectors in the virtual disk, valid for Sleuth Kit commands against this container."
            )
        unit, slots, skipped = parse_mmls(res["stdout"])
        lines_not_read = len(skipped)
        for line in skipped:
            out["notes"].append("a line of mmls's table after its header %s (a partition name holding a line break would do this); it is not read as a partition" % line)
        if forced and unit != forced:
            out["notes"].append("sector_size %d was given, but mmls printed its offsets in %d-byte sectors: "
                                "the offsets below are in %d-byte sectors." % (forced, unit, unit))
        out["sector_size"] = unit
        out["sector_size_source"] = "given by the caller (-b)" if forced else "the units line of mmls"
        out["partition_table"] = True if slots else "unknown"
        if not slots:
            out["partition_table_basis"] = "mmls ran but printed no row this tool could read, so whether the image has a partition table, and where, is not established"
        parts = []
        for n, slot in enumerate(slots):
            entry = dict(slot)
            entry["offset_sectors"] = slot["start_sector"]
            entry["offset_bytes"] = slot["start_sector"] * unit
            entry["length_bytes"] = slot["length_sectors"] * unit
            if slot["allocated"]:
                entry["filesystem"] = describe_fs(arg, slot["start_sector"], unit, forced, deadline, keep, "p%d" % slot["start_sector"])
            parts.append(entry)
        out["partitions"] = parts
        fs = [p["filesystem"] for p in parts if "filesystem" in p]
        out["volumes_readable"] = sum(1 for f in fs if f["readable"] is True)
        out["volumes_refused"] = sum(1 for f in fs if f["readable"] is False)
        out["volumes_not_attempted"] = sum(1 for f in fs if f["readable"] is None)
        if out["volumes_refused"]:
            out["notes"].append(
                "%d allocated partition(s) have no file system fsstat read at their table offset. Not a "
                "diagnosis: the sector size, a mapping layer (LVM, RAID, Storage Spaces), a file system or "
                "feature this build does not read, damage and encryption each look like this. Test them "
                "in that order of cost: evidence/imaging, then filesystem/encrypted." % out["volumes_refused"]
            )
        if out["volumes_not_attempted"]:
            out["notes"].append(
                "%d allocated partition(s) were not examined (fsstat missing, timed out or the tool's time budget "
                "ran out): their state is unknown." % out["volumes_not_attempted"]
            )
        big_gaps = [p for p in parts if not p["allocated"] and p["length_bytes"] > 64 * 1024 * 1024]
        if big_gaps:
            out["notes"].append(
                "%d unallocated gap(s) larger than 64 MB. A gap can be unused space or the remains of a "
                "removed partition entry; its content is the evidence for either, not its size." % len(big_gaps)
            )
    else:
        if out["container"] in VIRTUAL_DISKS and res["kind"] == "refused":
            out["notes"].append(
                "The Sleuth Kit did not open this %s container. Inspect it with qemu-img; "
                "conversion to raw or attachment may be required before deriving offsets."
                % out["container"]
            )
        # mmls ran and found no table it recognises (exit 1, no complaint of its own):
        # that is a result about the bytes at that sector size. Anything else (a missing
        # program, a timeout, an error opening the image) says nothing about the image.
        # Only mmls saying so counts. An exit 1 with nothing said is not the same: the image may not have opened
        # at all, so img_stat is asked whether the Sleuth Kit opens it, and only then is silence taken for "no table".
        recognised_none = res["kind"] == "refused" and bool(
            re.search(r"cannot determine partition type|unknown partition", res["stderr"], re.I))
        silent_basis = None
        if res["kind"] == "refused" and not res["stderr"]:
            opened = run(["img_stat"] + (["-b", str(forced)] if forced else []) + arg, deadline)
            if opened["stdout"] or opened["stderr"]:
                keep.save("img_stat", "$ img_stat %s\n%s%s" % (shlex.join(arg), opened["stdout"], ("\n[stderr]\n" + opened["stderr"]) if opened["stderr"] else ""), ["img_stat"] + arg)
            if opened["kind"] == "ok":
                recognised_none = True
                silent_basis = "mmls exited %s with nothing to say, and img_stat opens the image" % res["code"]
            else:
                silent_basis = "mmls exited %s with nothing to say, and img_stat did not open the image (%s)" % (res["code"], opened["kind"])
        out["sector_size"] = forced or 512
        out["sector_size_source"] = "given by the caller (-b)" if forced else "the default: mmls printed no units"
        if recognised_none:
            out["partition_table"] = False
            out["partition_table_basis"] = ("mmls found no partition table it recognises%s. That does not show the image has none: "
                                            "a table type the Sleuth Kit does not read, a damaged one and a wrong sector size look the same."
                                            % (" at sector size %d" % forced if forced else ""))
            if silent_basis:
                out["partition_table_basis"] += " (%s)" % silent_basis
        else:
            out["partition_table"] = "unknown"
            out["partition_table_basis"] = "mmls could not tell (%s)" % (silent_basis or res["kind"])
            out["mmls_error"] = res["stderr"].splitlines()[-1] if res["stderr"] else "mmls returned nothing"
            out["notes"].append("mmls did not run to a result (%s: %s); nothing here shows whether the image has a "
                                "partition table." % (res["kind"], out["mmls_error"]))
        whole = describe_fs(arg, None, forced, forced, deadline, keep, "whole")
        out["partitions"] = [{
            "slot": "—",
            "description": "the whole image, probed with no partition table"
            if out["partition_table"] is False else "the whole image, probed because the partition table could not be read",
            "offset_sectors": 0,
            "offset_bytes": 0,
            "allocated": True,
            "filesystem": whole,
        }]
        out["volumes_readable"] = 1 if whole.get("readable") is True else 0
        out["volumes_refused"] = 1 if whole.get("readable") is False else 0
        out["volumes_not_attempted"] = 1 if whole.get("readable") is None else 0
        if whole.get("readable") is True and out["partition_table"] is False:
            out["notes"].append(
                "No partition table recognised, and a file system at offset 0: run the toolkit with no -o "
                "at all. mmls finding no table here is the expected answer, not a broken image."
            )
        elif whole.get("readable") is False:
            out["notes"].append(
                "Neither a partition table nor a file system at offset 0 was read. Check the container type "
                "above, the sector size and the image's size against the acquisition record first; "
                "filesystem/encrypted lists what else produces this, encryption among them."
            )

    ready = [p for p in out["partitions"] if p.get("filesystem", {}).get("readable") is True]
    b = sector_args(out["sector_size"], forced)
    flag = (" ".join(b) + " ") if b else ""
    out["use"] = [
        {
            "offset_sectors": p["offset_sectors"],
            "fs_type": p["filesystem"].get("fs_type"),
            "example": "fls -r %s-o %d %s" % (flag, p["offset_sectors"], shlex.join(arg))
            if out["partition_table"] is True else "fls -r %s%s" % (flag, shlex.join(arg)),
        }
        for p in ready
    ]
    if descriptor is not None:
        out["descriptor"] = {"file": descriptor["file"], "sha256": descriptor["sha256"], "layer": descriptor["layer"], "sources_checked": descriptor["checked"]}
        out["images"] = len(images)
    out["raw_outputs"] = keep.files
    if keep.error:
        out["raw_outputs_error"] = keep.error
    out["status"] = "partial" if (out.get("partition_table") == "unknown" or out.get("volumes_refused") or out.get("volumes_not_attempted") or lines_not_read) else "complete"
    out["status_basis"] = ("mmls and fsstat ran on every entry they were asked about and the layout is as they printed it" if out["status"] == "complete" else
                           "the partition table is not established, a line of it was not read as a row, or a file system fsstat was asked about was refused or not attempted (see notes and the partitions)")
    out["not_measured"] = ("Snapshots, backing files and the other segments of a split set are not read; "
                           "a file system fsstat reads here is not shown to be intact or complete, and an "
                           "encrypted volume looks like any other it cannot read.")
    print_answer(out, indent=2)


if __name__ == "__main__":
    main()
