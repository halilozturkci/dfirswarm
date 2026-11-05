#!/usr/bin/env python3
"""archive-members: the member list of a tar, zip or 7z archive, nothing extracted.

    run.py detect --target TARGET          exit 0 applies, 1 does not, 2 error
    run.py run --target TARGET --out DIR   members.tsv + coverage.json in DIR

TARGET is JSON (inline or a file path): {"paths": [...], "ref": ..., "name": ...};
the archive is paths[0]. Every member is one row of members.tsv:

    n  type  path  path_b64  size  packed  mtime  tz  mode  uid  gid  link  locator  flags

`path` and `link` are shown with control characters, tabs, newlines and
backslashes escaped; `path_b64` is the name's exact bytes. `n` counts from 0
in archive order, so two members with the same name are still two rows, and
is the number the archive_extract tool takes (its from_index) and gives back
in its own manifest: a member is extracted with that tool, never with the
archive's own program run on the whole archive. A tar's times are UTC; a zip's DOS times carry
no zone (`tz` is `unknown`) unless the member has an extended timestamp.
`flags` names what an examiner should know before extracting: escapes-root,
encrypted, ratio>1000, and name-not-utf8 (macOS refuses such a name, so an
extraction there must rename the member; its bytes are path_b64).

The format is read from the bytes in the order archive_extract reads them: a 7z or zip signature at offset 0, then a tar header that
reads at offset 0, and only then a zip with something in front of it, which needs an end-of-central-directory record that agrees with
the file (a directory of at least one entry that ends where the record starts and begins with a central-directory signature), not
four bytes that spell one somewhere near the end. A tar that holds a zip as a member is listed as the tar, and coverage.json notes the
zip record it also ends in.
"""
import base64
import bz2
import datetime
import json
import lzma
import os
import re
import select
import shutil
import struct
import subprocess
import sys
import tarfile
import time
import zipfile
import zlib


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


def _probe_out(directory):
    """The output directory is written to once, up front: a directory that cannot be written (not owned, mounted read-only, a full disk) is a refusal
    before anything is run, not a PermissionError in the middle of the coverage file."""
    probe = _os.path.join(directory, ".write-probe-%d" % _os.getpid())
    temp_hold(probe)                 # registered before it is made: whatever stops this, it is removed
    try:
        fd = _os.open(probe, _os.O_WRONLY | _os.O_CREAT | _os.O_EXCL, 0o600)
        _os.close(fd)
        if not temp_drop(probe):
            raise OSError(0, "the probe file could not be removed")
    except (OSError, ValueError) as exc:
        temp_drop(probe)
        print_answer({"ok": False, "status": "failed", "error": "--out cannot be written: %s" % (getattr(exc, "strerror", None) or exc.__class__.__name__),
                      "status_basis": "the output directory cannot be written, so nothing was run"})
        _sys.exit(2)


def _unexpected_recipe(kind, value, _tb):
    """What nobody foresaw (a file that cannot be written half way, a target of an odd type) is an answer too: its class only, exit 2."""
    try:
        drop_temporaries()
    except BaseException:   # noqa: BLE001
        pass
    why = "a path, a file or the target could not be used: %s" % kind.__name__
    if len(_sys.argv) > 1 and _sys.argv[1] == "detect":
        doc = {"applies": "unknown", "why": why, "ok": False, "error": why}
    else:
        doc = {"ok": False, "status": "failed", "error": why, "status_basis": "the recipe stopped on %s, so what it had written is not a complete result" % kind.__name__}
    try:
        _sys.stdout.write(json.dumps(doc) + "\n")
        _sys.stdout.flush()
    except (OSError, ValueError):
        pass
    _os._exit(2)


_sys.excepthook = _unexpected_recipe


def _write_json_whole(path, doc, **dumps_kwargs):
    """A JSON file whole or not at all: written beside, then renamed over the name. A write that fails (a full disk, a file-size limit) removes
    the part and raises, so the recipe answers (the excepthook) and the earlier file, if any, stands; a cut coverage.json is never left."""
    tmp = path + ".tmp"
    temp_hold(tmp)
    try:
        with open(tmp, "w") as fh:
            json.dump(doc, fh, **dumps_kwargs)
        temp_replace(tmp, path)
    except BaseException:
        temp_drop(tmp)
        raise


def open_regular(path):
    """open(path, "rb") for a caller's path that was checked as a regular file a moment ago: opened without waiting (O_NONBLOCK) and looked at with
    fstat on the descriptor, so a FIFO or a device put in its place is refused and never waited on (a FIFO would hold the tool for ever)."""
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    try:
        if os.fstat(fd).st_mode & 0o170000 != 0o100000:
            raise OSError(22, "is not a regular file (it changed after it was checked)")
    except BaseException:
        os.close(fd)
        raise
    return open(fd, "rb")

CHILD = {"proc": None}     # the 7z being read, ended by its pid on a stop

HERE = os.path.dirname(os.path.abspath(__file__))


def name_flags(raw):
    """What an examiner should know about a member's name before extracting it: it is not UTF-8 (APFS will not store it as it is),
    it holds a NUL (extractors differ on what follows one, so the whole name is judged, and a name that climbs after a NUL climbs),
    or it leaves the directory it is extracted into (an absolute path, a drive letter, or a ".." component, on either separator)."""
    flags = []
    try:
        raw.decode("utf-8")
    except UnicodeDecodeError:
        flags.append("name-not-utf8")
    if b"\x00" in raw:
        flags.append("nul-in-name")
    plain = raw.replace(b"\x00", b"/").replace(b"\\", b"/")
    if plain.startswith(b"/") or re.match(rb"^[A-Za-z]:", plain) or b"/../" in b"/" + plain + b"/":
        flags.append("escapes-root")
    return flags
SEVEN_Z_MAGIC = b"7z\xbc\xaf\x27\x1c"
SEVEN_Z_NAMES = ("7z", "7zz", "7za", "7zr")    # the programs archive_extract looks for, in the same order
COLUMNS = ["n", "type", "path", "path_b64", "size", "packed", "mtime", "tz", "mode", "uid", "gid", "link", "locator", "flags"]


def limits():
    try:
        spec = json.load(open(os.path.join(HERE, "recipe.json")))
        lim = spec.get("limits", {})
    except Exception:
        lim = {}
    seconds = int(os.environ.get("RECIPE_SECONDS") or lim.get("seconds") or 1800)
    members = int(os.environ.get("RECIPE_MEMBERS") or lim.get("members") or 2000000)
    return seconds, members


def refuse(message):
    """A target that cannot be read is an answer on stdout, as every other refusal here is, not a traceback."""
    print_answer({"ok": False, "error": message})
    sys.exit(2)


def target_of(arg):
    text = arg
    if os.path.isfile(arg):
        try:
            with open(arg, encoding="utf-8") as fh:
                text = fh.read(1 << 20)
        except (OSError, ValueError) as exc:               # ValueError: bytes that are not UTF-8
            refuse("the target file cannot be read as UTF-8 text: %s" % (getattr(exc, "strerror", None) or exc.__class__.__name__))
    try:
        t = json.loads(text)
    except (ValueError, RecursionError) as exc:
        refuse("the target is not valid JSON: %s" % exc)
    if not isinstance(t, dict):
        refuse("the target is a JSON object with a paths list")
    paths = t.get("paths") or []
    if not isinstance(paths, list):
        refuse("the target is a JSON object with a paths list")
    if not paths or not isinstance(paths[0], str):
        refuse("the target names no path")
    return t, paths[0]


def esc(raw):
    """A name for a reader: one line, one field, nothing hidden."""
    out = []
    for ch in raw.decode("utf-8", "surrogateescape"):
        o = ord(ch)
        if 0xDC80 <= o <= 0xDCFF:
            out.append("\\x%02x" % (o - 0xDC00))
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif o < 0x20 or o == 0x7F:
            out.append("\\x%02x" % o)
        else:
            out.append(ch)
    return "".join(out)


def b64(raw):
    return base64.b64encode(raw).decode("ascii")


def utc(ts):
    try:
        return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return ""


ZIP_TAIL = 65557 + 4096  # an end record's comment is at most 65535 bytes; room before it for a zip64 locator and record


def zip_end_agrees(path):
    """True when the end-of-central-directory record in the file's last 64 KiB agrees with the file: it counts at least one entry,
    its central directory ends where the record starts, begins with a central-directory signature, and does not start before the
    offset the record declares for it (the difference is a prefix: a self-extractor). zipfile.is_zipfile finds the four record
    bytes anywhere in that window and so says yes to a tar whose last member is a zip, and to any file that ends in 22 bytes
    that spell a record."""
    try:
        size = os.path.getsize(path)
        start = max(0, size - ZIP_TAIL)
        with open_regular(path) as fh:
            fh.seek(start)
            tail = fh.read()
            at = len(tail)
            while True:
                at = tail.rfind(b"PK\x05\x06", 0, at)
                if at < 0 or at + 22 > len(tail):
                    return False
                total, cd_bytes, cd_off = struct.unpack_from("<H", tail, at + 10)[0], struct.unpack_from("<I", tail, at + 12)[0], struct.unpack_from("<I", tail, at + 16)[0]
                end_of_dir = start + at
                if total == 0xFFFF or cd_bytes == 0xFFFFFFFF or cd_off == 0xFFFFFFFF:
                    loc = tail.rfind(b"PK\x06\x07", 0, at)
                    rec = tail.rfind(b"PK\x06\x06", 0, loc) if loc >= 0 else -1
                    if rec < 0 or rec + 56 > len(tail):
                        continue
                    total, cd_bytes, cd_off = struct.unpack_from("<Q", tail, rec + 32)[0], struct.unpack_from("<Q", tail, rec + 40)[0], struct.unpack_from("<Q", tail, rec + 48)[0]
                    end_of_dir = start + rec
                begins = end_of_dir - cd_bytes
                if total < 1 or cd_bytes < 46 or begins < 0 or begins < cd_off:
                    continue
                fh.seek(begins)
                if fh.read(4) == b"PK\x01\x02":
                    return True
    except (OSError, struct.error):
        return False


def reads_as_tar(path):
    """Whether a tar header with a valid checksum reads at offset 0 (a plain tar: the first member of one that is compressed is not asked)."""
    try:
        with open_regular(path) as fh:
            if fh.read(512)[257:262] != b"ustar":
                return False
        with tarfile.open(path, mode="r:", tarinfo=BoundedInfo) as tf:
            return tf.next() is not None
    except Exception:
        return False


def _open_regular(path):
    """The target opened for reading without waiting for it (an open of a FIFO named here would block until a writer came): the type is read from the
    descriptor, and anything but a regular file is refused as an OSError, which detect reads as "cannot tell"."""
    import errno
    import stat
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0))
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(errno.EINVAL, "not a regular file")
        os.set_blocking(fd, True)
        return os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise


def _is_regular(path):
    import stat
    try:
        return stat.S_ISREG(os.stat(path).st_mode)
    except (OSError, ValueError):
        return False


def detect(path):
    """(format, why) or (None, why). A tar header that reads at offset 0 decides before a zip end record found near the end does:
    the end record of a zip that is a member of a tar sits inside the tar. archive_extract orders the formats the same way."""
    try:
        with _open_regular(path) as fh:
            head = fh.read(512)
    except (OSError, ValueError) as e:        # ValueError: a NUL or a lone surrogate in the path
        return "unknown", "unreadable, so it cannot be told whether it is an archive: %s" % (getattr(e, "strerror", None) or e.__class__.__name__)
    if head.startswith(SEVEN_Z_MAGIC):
        return "7z", "7z signature"
    if head.startswith((b"PK\x03\x04", b"PK\x05\x06")):
        return "zip", "zip signature at offset 0"
    # tarfile.is_tarfile says yes to a file of zeros (an empty tar is two
    # zero blocks), and a memory or disk image can start with zeros: a tar
    # here is one whose first member header reads. Compressed by its magic,
    # as list_tar reads it: "r:*" tries every decompressor in turn, and the
    # LZMA one reads a run of zeros as a stream (64 MiB of them took it half
    # a minute), which the census pays for every input that starts so.
    compressed = head[:2] == b"\x1f\x8b" or head[:3] == b"BZh" or head[:6] == b"\xfd7zXZ\x00"
    try:
        with tarfile.open(path, mode="r|*" if compressed else "r:", tarinfo=BoundedInfo) as tf:
            first = tf.next()
        if first is not None:
            return "tar", "tar header"
        tar_why = "no tar member (zero blocks, or not a tar)"
    except HugeHeader as e:
        return "tar", "tar header (%s)" % e
    except Exception:
        tar_why = "no tar, zip or 7z structure"
    # No signature at offset 0: a zip with something in front of it (a self-extractor) is told by an end record that agrees
    # with the file, not by four bytes anywhere in its last 64 KiB.
    if zip_end_agrees(path):
        return "zip", "zip end-of-central-directory record that agrees with the file (a prefix before the first entry)"
    return None, tar_why


class Writer:
    def __init__(self, out_dir):
        self.fh = open(os.path.join(out_dir, "members.tsv"), "w", encoding="utf-8", newline="\n")
        self.fh.write("\t".join(COLUMNS) + "\n")
        self.rows = 0

    def row(self, **v):
        self.fh.write("\t".join(str(v.get(c, "")) for c in COLUMNS) + "\n")
        self.rows += 1

    def close(self):
        self.fh.close()


LINE_MAX = 16 * 1024 * 1024    # the longest line of 7z's listing read: a member name is a few hundred bytes
META_MAX = 1024 * 1024         # a GNU long-name or pax header that declares more than this is not read: tarfile reads it whole into memory


class BoundedInfo(tarfile.TarInfo):
    """tarfile reads a GNU long-name/long-link ('L', 'K') or pax ('x', 'g') header's data whole, however large the header says it is:
    one that declares a gigabyte takes a gigabyte of memory at detect and again at the listing. The size is checked first."""

    def _proc_gnulong(self, tf):
        if self.size > META_MAX:
            raise HugeHeader("a GNU long-name or long-link header at offset %d declares %d bytes (more than %d): it is not read" % (self.offset, self.size, META_MAX))
        return super()._proc_gnulong(tf)

    def _proc_pax(self, tf):
        if self.size > META_MAX:
            raise HugeHeader("a pax header at offset %d declares %d bytes (more than %d): it is not read" % (self.offset, self.size, META_MAX))
        return super()._proc_pax(tf)


class HugeHeader(tarfile.ReadError):
    pass


def tar_type(m):
    if m.isreg():
        return "file"
    if m.isdir():
        return "dir"
    if m.issym():
        return "symlink"
    if m.islnk():
        return "hardlink"
    if m.ischr():
        return "char"
    if m.isblk():
        return "block"
    if m.isfifo():
        return "fifo"
    return "other"


def gzip_header_length(data):
    """The length of the gzip member header at the start of `data` (RFC 1952: ten bytes, then the optional extra field, name, comment and
    header CRC the flags name), or None when `data` ends inside it. Raises ValueError when it is not a gzip member header."""
    if len(data) >= 3 and (data[:2] != b"\x1f\x8b" or data[2] != 8):
        raise ValueError("not a gzip member (bad magic or an unknown compression method)")
    if len(data) < 10:
        return None
    flags, at = data[3], 10
    if flags & 4:
        if len(data) < at + 2:
            return None
        at += 2 + int.from_bytes(data[at:at + 2], "little")
    for bit in (8, 16):
        if flags & bit:
            end = data.find(b"\0", at)
            if end < 0:
                return None
            at = end + 1
    if flags & 2:
        at += 2
    return at if len(data) >= at else None


class TarStream:
    """The decompressed bytes of a gzip, bzip2 or xz file, every stream of it in turn (read by tarfile in stream mode, and then by
    `read_rest`). tarfile stops at a tar's end blocks and reads nothing further, so a second archive in the same stream, a further
    compressed stream, bytes after the last stream and a trailer that does not match (the gzip CRC-32 and ISIZE) are never seen:
    the same bytes uncompressed are partial, and a compressed tar was listed complete. The text of this class is archive_extract's
    Decomp for the three kinds a tar comes in (a script does not import another): the decompressors are called with a maximum
    output of CHUNK, so a bomb costs one piece of memory, never more.

    read(n) returns at most n bytes and b"" only at the end of the last stream. `streams` counts the streams, `consumed` the compressed
    bytes read, `delivered` the decompressed bytes handed out, `trailing` the bytes after the last stream that are not another one
    (`trailing_nonzero` when any is not a zero, the padding some writers leave)."""

    CHUNK = 1 << 20
    MARKERS = {"gzip": b"\x1f\x8b", "bzip2": b"BZh", "xz": b"\xfd7zXZ\x00"}

    def __init__(self, path, kind):
        self.kind = kind
        self.fh = open_regular(path)
        self.consumed = 0
        self.delivered = 0
        self.buf = b""
        self.eof = False
        self.streams = 0
        self.trailing = 0
        self.trailing_nonzero = False
        self.pending = None        # an error from the decompressor, raised once the bytes before it have been read
        self.gen = self._pieces()

    def close(self):
        try:
            self.fh.close()
        except OSError:
            pass

    def _new(self):
        if self.kind == "gzip":
            return zlib.decompressobj(31)
        if self.kind == "bzip2":
            return bz2.BZ2Decompressor()
        return lzma.LZMADecompressor()

    def _step(self, dec, data):
        """(output, input left over, finished) after one call bounded to CHUNK bytes of output."""
        if self.kind == "gzip":
            out = dec.decompress(data, self.CHUNK)
            return out, (dec.unused_data if dec.eof else dec.unconsumed_tail), dec.eof
        out = dec.decompress(data, max_length=self.CHUNK)
        return out, (dec.unused_data if dec.eof else b""), dec.eof

    def _gzip_pieces(self):
        """gzip members back to back, framed here (header, raw deflate, CRC-32 and ISIZE trailer) rather than by zlib's gzip mode: zlib
        raises at the trailer and gives up the output of the call that reached it, so a member whose trailer does not match would
        have lost its last piece. Here every byte of a member is handed out first, and the trailer's mismatch is raised after them."""
        data = self.fh.read(self.CHUNK)
        self.consumed += len(data)
        if not data:
            raise EOFError("the gzip file is empty")
        while True:
            self.streams += 1
            while True:
                head = gzip_header_length(data)
                if head is not None:
                    break
                more = self.fh.read(self.CHUNK)
                self.consumed += len(more)
                if not more:
                    raise EOFError("the gzip stream ends inside its header (a truncated archive)")
                data += more
            data = data[head:]
            dec = zlib.decompressobj(-15)
            crc = size = 0
            while True:
                out = dec.decompress(data, self.CHUNK)
                data = dec.unused_data if dec.eof else dec.unconsumed_tail
                if out:
                    crc = zlib.crc32(out, crc)
                    size += len(out)
                    yield out
                if dec.eof:
                    break
                if not data and len(out) < self.CHUNK:
                    data = self.fh.read(self.CHUNK)
                    self.consumed += len(data)
                    if not data:
                        raise EOFError("the gzip stream ends before its end marker (a truncated archive)")
            while len(data) < 8:
                more = self.fh.read(self.CHUNK)
                self.consumed += len(more)
                if not more:
                    raise EOFError("the gzip stream ends inside its trailer (a truncated archive)")
                data += more
            want_crc, want_size = struct.unpack("<II", data[:8])
            data = data[8:]
            if want_crc != crc & 0xFFFFFFFF:
                raise zlib.error("Error -3 while decompressing data: incorrect data check")
            if want_size != size & 0xFFFFFFFF:
                raise zlib.error("Error -3 while decompressing data: incorrect length check")
            rest = data
            while not rest:
                rest = self.fh.read(self.CHUNK)
                self.consumed += len(rest)
                if not rest:
                    return
            if rest.startswith(b"\x1f\x8b"):
                data = rest
                continue
            # What follows the last stream is not another one: counted and said, not decompressed.
            self.trailing = len(rest)
            self.trailing_nonzero = bool(rest.strip(b"\0"))
            while True:
                more = self.fh.read(self.CHUNK)
                if not more:
                    return
                self.trailing += len(more)
                self.consumed += len(more)
                if more.strip(b"\0"):
                    self.trailing_nonzero = True

    def _pieces(self):
        if self.kind == "gzip":
            yield from self._gzip_pieces()
            return
        marker = self.MARKERS[self.kind]
        dec = self._new()
        self.streams = 1
        data = b""
        while True:
            if not data:
                data = self.fh.read(self.CHUNK)
                self.consumed += len(data)
                if not data:
                    if not getattr(dec, "eof", False):
                        raise EOFError("the %s stream ends before its end marker (a truncated archive)" % self.kind)
                    return
            while True:
                out, data, finished = self._step(dec, data)
                if out:
                    yield out
                if finished:
                    break
                if self.kind == "gzip":
                    if not data and len(out) < self.CHUNK:
                        break                      # all the input is used and nothing more is pending: more input is read above
                elif dec.needs_input:
                    break
                else:
                    data = b""                     # the decompressor holds output it has not given yet: ask again with no input
            if not finished:
                data = b""
                continue
            rest = data
            while not rest:
                rest = self.fh.read(self.CHUNK)
                self.consumed += len(rest)
                if not rest:
                    return
            if rest.startswith(marker):
                dec = self._new()
                self.streams += 1
                data = rest
                continue
            # What follows the last stream is not another one: counted and said, not decompressed.
            self.trailing = len(rest)
            self.trailing_nonzero = bool(rest.strip(b"\0"))
            while True:
                more = self.fh.read(self.CHUNK)
                if not more:
                    return
                self.trailing += len(more)
                self.consumed += len(more)
                if more.strip(b"\0"):
                    self.trailing_nonzero = True

    def read(self, n=-1):
        if n is None or n < 0:
            n = 1 << 62
        while len(self.buf) < n and not self.eof and self.pending is None:
            try:
                piece = next(self.gen)
            except StopIteration:
                self.eof = True
                break
            except (EOFError, OSError, zlib.error, lzma.LZMAError, ValueError) as exc:
                self.pending = exc               # the bytes decompressed before the break are read first, then this is raised
                break
            self.buf += piece
        if not self.buf and self.pending is not None:
            raise self.pending
        out, self.buf = self.buf[:n], self.buf[n:]
        self.delivered += len(out)
        return out


def read_rest(stream, leftover, deadline, n, cov):
    """A compressed tar is complete only when its whole stream has been read: everything after the tar's end blocks is read here, under
    the clock, and must be zeros (a tar ends in two zero blocks and zero padding to its record size). A byte that is not, a stream whose
    trailer does not match or that does not end, and bytes after the last stream that are not a stream go to cov["errors"] with their
    offset, as the plain tar's tail check puts its finding there (the listing is then partial); a rest the clock cut short says so in
    cov["limits_hit"]. `leftover` is what tarfile read from the stream beyond the end blocks and did not use."""
    pos = stream.delivered - len(leftover)        # the decompressed offset of the first byte tarfile did not use
    chunk = leftover
    while True:
        if chunk.strip(b"\0"):
            at = pos + len(chunk) - len(chunk.lstrip(b"\0"))
            cov["errors"].append("bytes after member %d are not zeros: a further tar header or other data starts at decompressed offset %d "
                                 "(compressed stream %d, %d compressed bytes read); the listing holds only the first archive of the stream"
                                 % (n - 1, at, stream.streams, stream.consumed))
            return
        pos += len(chunk)
        if time.monotonic() > deadline:
            cov["limits_hit"].append("seconds: the compressed stream was not read to its end (%d decompressed bytes read; the rest was not checked)" % pos)
            return
        try:
            chunk = stream.read(TarStream.CHUNK)
        except (EOFError, OSError, zlib.error, lzma.LZMAError, ValueError) as e:
            cov["errors"].append("the compressed stream does not end cleanly after the last member (decompressed offset %d): %s" % (pos, e))
            return
        if not chunk:
            break
    if stream.trailing_nonzero:
        cov["errors"].append("%d bytes after the last compressed stream are not another stream and not zero padding (compressed offset %d)"
                             % (stream.trailing, stream.consumed - stream.trailing))


def list_tar(path, w, deadline, max_members, cov):
    compressed = False
    kind = None
    with open_regular(path) as fh:
        magic = fh.read(6)
    if magic[:2] == b"\x1f\x8b":
        compressed, kind = True, "gzip"
    elif magic[:3] == b"BZh":
        compressed, kind = True, "bzip2"
    elif magic[:6] == b"\xfd7zXZ\x00":
        compressed, kind = True, "xz"
    cov["format"] = "tar" + (" (compressed)" if compressed else "")
    # A plain tar is walked header to header, seeking over the data; a compressed one is read once, front to back, in stream mode over
    # a reader that sees every compressed stream of the file (tarfile's own "r|*" reads no trailer and stops at the end blocks), and its
    # rest is read after the loop.
    stream = TarStream(path, kind) if compressed else None
    tf = tarfile.open(fileobj=stream, mode="r|", tarinfo=BoundedInfo) if compressed else tarfile.open(path, mode="r:", tarinfo=BoundedInfo)
    n = 0
    last = None
    leftover = b""
    clean = False
    try:
        for m in tf:
            raw = m.name.encode("utf-8", "surrogateescape")
            link = m.linkname.encode("utf-8", "surrogateescape") if m.linkname else b""
            loc = "tar:index=%d" % n if compressed else "tar:index=%d;header=%d;data=%d" % (n, m.offset, m.offset_data)
            flags = name_flags(raw)
            w.row(n=n, type=tar_type(m), path=esc(raw), path_b64=b64(raw), size=m.size, packed="",
                  mtime=utc(m.mtime), tz="utc", mode="%o" % m.mode, uid=m.uid, gid=m.gid,
                  link=esc(link), locator=loc, flags=",".join(flags))
            n += 1
            last = (m.offset_data, m.size if m.isreg() else 0)
            tf.members = []  # the listing is on disk; do not hold every header in memory
            if n >= max_members:
                cov["limits_hit"].append("members: stopped at %d" % max_members)
                break
            if time.monotonic() > deadline:
                cov["limits_hit"].append("seconds: stopped after %d members" % n)
                break
        else:
            clean = True       # the loop ended at the tar's end, not at a limit
            if compressed:
                # What tarfile read from the stream beyond the end blocks and did not use is part of the rest to be checked.
                leftover = bytes(getattr(getattr(tf, "fileobj", None), "buf", b"") or b"")
    except (tarfile.TarError, EOFError, OSError, zlib.error, lzma.LZMAError) as e:
        cov["errors"].append("the archive ended or broke after %d members: %s" % (n, e))
    finally:
        tf.close()
    if compressed:
        try:
            if clean and not cov["limits_hit"] and not cov["errors"]:
                read_rest(stream, leftover, deadline, n, cov)
        finally:
            stream.close()
    elif not cov["limits_hit"]:
        tar_tail(path, last, n, cov)
    return n


def tar_tail(path, last, n, cov):
    """tarfile takes a header it cannot read for the end of the archive and
    says nothing. A plain tar ends in zero blocks right after its last
    member's data: anything else after it is a part this listing never read."""
    size = os.path.getsize(path)
    end = 0 if last is None else last[0] + ((last[1] + 511) // 512) * 512
    if end > size:
        cov["errors"].append("member %d's data runs %d bytes past the end of the file: the archive is truncated" % (n - 1, end - size))
        return
    with open_regular(path) as fh:
        fh.seek(end)
        rest = fh.read(1 << 20)
    if rest.strip(b"\0"):
        cov["errors"].append("%d bytes after member %d are not a tar header this listing could read (truncated or damaged at offset %d)"
                             % (size - end, n - 1, end))


def zip_ext_time(extra):
    """The UTC mtime from an extended-timestamp field (0x5455), or None."""
    i = 0
    while i + 4 <= len(extra):
        hid, size = struct.unpack_from("<HH", extra, i)
        body = extra[i + 4:i + 4 + size]
        if hid == 0x5455 and len(body) >= 5 and body[0] & 1:
            return struct.unpack_from("<I", body, 1)[0]
        i += 4 + size
    return None


# zipfile reads the whole central directory into memory: past this many
# bytes of it, the archive is not listed, and says so (RECIPE_ZIP_DIRECTORY_BYTES).
ZIP_DIRECTORY_MAX = int(os.environ.get("RECIPE_ZIP_DIRECTORY_BYTES") or 64 * 1024 * 1024)


def zip_declared(path):
    """The member count and the central directory's size in bytes the
    end-of-central-directory record declares (zip64 too), read before
    zipfile loads the whole directory into memory."""
    size = os.path.getsize(path)
    with open_regular(path) as fh:
        fh.seek(max(0, size - 65557))
        tail = fh.read()
    at = tail.rfind(b"PK\x05\x06")
    if at < 0 or at + 22 > len(tail):
        return None, None
    total = struct.unpack_from("<H", tail, at + 10)[0]
    cd_bytes = struct.unpack_from("<I", tail, at + 12)[0]
    if total == 0xFFFF or cd_bytes == 0xFFFFFFFF:
        loc = tail.rfind(b"PK\x06\x07", 0, at)
        if loc >= 0:
            with open_regular(path) as fh:
                fh.seek(struct.unpack_from("<Q", tail, loc + 8)[0])
                rec = fh.read(56)
            if rec[:4] == b"PK\x06\x06":
                total = struct.unpack_from("<Q", rec, 32)[0]
                cd_bytes = struct.unpack_from("<Q", rec, 40)[0]
    return total, cd_bytes


def zip_declared_entries(path):
    return zip_declared(path)[0]


def list_zip(path, w, deadline, max_members, cov):
    cov["format"] = "zip"
    n = 0
    declared, cd_bytes = zip_declared(path)
    if declared is not None and declared > max_members:
        # zipfile reads every entry of the directory into memory before the
        # first one can be listed: past the limit nothing is listed, and says so.
        cov["limits_hit"].append("members: the central directory declares %d, more than the limit of %d; not listed (raise RECIPE_MEMBERS for this archive)" % (declared, max_members))
        return 0
    if cd_bytes is not None and cd_bytes > ZIP_DIRECTORY_MAX:
        cov["limits_hit"].append("members: the central directory is %d bytes, more than the limit of %d; not listed (raise RECIPE_ZIP_DIRECTORY_BYTES for this archive)" % (cd_bytes, ZIP_DIRECTORY_MAX))
        return 0
    with zipfile.ZipFile(path) as zf:
        for info in zf.infolist():
            utf8 = bool(info.flag_bits & 0x800)
            # orig_filename, not filename: zipfile cuts filename at the first NUL, and the name as stored is what an extractor may act on.
            raw = info.orig_filename.encode("utf-8" if utf8 else "cp437", "surrogateescape")
            ext = zip_ext_time(info.extra)
            if ext is not None:
                mtime, tz = utc(ext), "utc"
            else:
                try:
                    mtime = "%04d-%02d-%02dT%02d:%02d:%02d" % info.date_time
                except TypeError:
                    mtime = ""
                tz = "unknown"
            mode = (info.external_attr >> 16) & 0xFFFF
            kind = "dir" if info.is_dir() else ("symlink" if (mode & 0o170000) == 0o120000 else "file")
            flags = name_flags(raw)
            if info.flag_bits & 0x1:
                flags.append("encrypted")
            if info.compress_size and info.file_size / max(info.compress_size, 1) > 1000:
                flags.append("ratio>1000")
            w.row(n=n, type=kind, path=esc(raw), path_b64=b64(raw), size=info.file_size, packed=info.compress_size,
                  mtime=mtime, tz=tz, mode=("%o" % mode) if mode else "", uid="", gid="", link="",
                  locator="zip:index=%d;header=%d" % (n, info.header_offset), flags=",".join(flags))
            n += 1
            if n >= max_members:
                cov["limits_hit"].append("members: stopped at %d" % max_members)
                break
            if time.monotonic() > deadline:
                cov["limits_hit"].append("seconds: stopped after %d members" % n)
                break
    return n


PIPE_GRACE = 1.0           # seconds the pipes of a program that has ended are given to reach end of file
SUBREAPER = [False]


def become_subreaper():
    """On Linux ask the kernel to make this process the parent of every process a program leaves behind (PR_SET_CHILD_SUBREAPER = 36), so that
    end_leftovers() can find one that left the tool's group or session. Once. Nothing is adopted elsewhere, and a leftover is then not found."""
    if SUBREAPER[0] or not sys.platform.startswith("linux"):
        return
    SUBREAPER[0] = True
    try:
        import ctypes
        ctypes.CDLL(None).prctl(36, 1, 0, 0, 0)
    except Exception:  # noqa: BLE001 - no libc symbol, a sandbox: the leftover is not found
        pass


def end_leftovers():
    """Kill and reap what a program that has ended left behind: the children of this tool (it is a subreaper, and runs one program at a time, so
    every child it has is a leftover) and what they started. Linux only; the tool itself is not touched. Never raises."""
    if not sys.platform.startswith("linux"):
        return
    try:
        me = os.getpid()
        for _round in range(3):
            table = {}
            for name in os.listdir("/proc"):
                if name.isdigit():
                    try:
                        with open("/proc/%s/stat" % name, "rb") as fh:
                            fields = fh.read().decode("utf-8", "replace").rsplit(")", 1)[1].split()
                        table[int(name)] = (fields[0], int(fields[1]))
                    except (OSError, ValueError, IndexError):
                        continue
            kids = [pid for pid, (_state, parent) in table.items() if parent == me]
            if not kids:
                return
            group, grew = set(kids), True
            while grew:
                more = {pid for pid, (_state, parent) in table.items() if parent in group and pid not in group}
                grew = bool(more)
                group |= more
            for pid in group:
                if table[pid][0] not in ("Z", "X"):
                    try:
                        os.kill(pid, 9)
                    except OSError:
                        pass
            end = time.monotonic() + 1.0
            for pid in kids:
                while time.monotonic() < end:
                    try:
                        if os.waitpid(pid, os.WNOHANG)[0] != 0:
                            break
                    except ChildProcessError:
                        break
                    time.sleep(0.005)
    except Exception:  # noqa: BLE001 - a look for leftovers never stops the tool
        pass


def list_7z(path, w, deadline, max_members, cov, out_dir):
    """7z's own listing, read as it streams (a listing of millions of members
    is never held whole), its stderr kept whole beside the list."""
    cov["format"] = "7z"
    env = dict(os.environ, TZ="UTC", LANG="C.UTF-8", LC_ALL="C.UTF-8")
    err_path = os.path.join(out_dir, "7z.stderr")
    try:
        err = open(err_path, "wb")
        program = next((found for found in (shutil.which(n) for n in SEVEN_Z_NAMES) if found), None)
        if program is None:
            raise FileNotFoundError("7z")
        become_subreaper()
        proc = subprocess.Popen([program, "l", "-slt", "-ba", "--", path], stdout=subprocess.PIPE, stderr=err, env=env)
        CHILD["proc"] = proc
    except FileNotFoundError:
        cov["status_override"] = "unsupported"
        cov["errors"].append("no 7z program (7z, 7zz, 7za or 7zr) is in this image")
        return 0
    n = 0
    fields = {}
    stopped = None

    def emit():
        nonlocal n
        raw = fields[b"Path"]
        attrs = fields.get(b"Attributes", b"").decode("ascii", "replace")
        kind = "dir" if attrs.startswith("D") or fields.get(b"Folder") == b"+" else "file"
        mod = fields.get(b"Modified", b"").decode("ascii", "replace").strip()
        flags = name_flags(raw) + (["encrypted"] if fields.get(b"Encrypted") == b"+" else [])
        w.row(n=n, type=kind, path=esc(raw), path_b64=b64(raw), size=fields.get(b"Size", b"").decode(),
              packed=fields.get(b"Packed Size", b"").decode(), mtime=mod.replace(" ", "T") + ("Z" if mod else ""),
              tz="utc" if mod else "", mode="", uid="", gid="", link="", locator="7z:index=%d" % n, flags=",".join(flags))
        n += 1

    def lines():
        """7z's output a line at a time, waited for with the clock running: a 7z that stalls (a damaged archive, a stuck read) is stopped
        at the deadline and not waited on behind a read that returns nothing. A line past LINE_MAX is an error, not a name."""
        nonlocal stopped
        fd, pending, ended = proc.stdout.fileno(), b"", None
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                stopped = "seconds: stopped after %d members (7z was still running)" % n
                return
            if not select.select([fd], [], [], min(left, 0.2))[0]:
                if proc.poll() is not None:                 # 7z has ended and something it started holds its pipe: a moment's grace, then the listing is let go
                    ended = ended or time.monotonic()
                    if time.monotonic() - ended >= PIPE_GRACE:
                        stopped = "pipe: 7z ended, but something it started kept its output pipe open, so the end of the listing was not seen (after %d members)" % n
                        return
                continue
            block = os.read(fd, 65536)
            if not block:
                if pending:
                    yield pending
                return
            pending += block
            while b"\n" in pending:
                line, pending = pending.split(b"\n", 1)
                yield line
            if len(pending) > LINE_MAX:
                cov["errors"].append("7z printed a line of more than %d bytes (no newline): the listing was stopped there" % LINE_MAX)
                stopped = "line: 7z printed more than %d bytes with no newline, after %d members" % (LINE_MAX, n)
                return

    for line in lines():
        line = line.rstrip(b"\r\n")
        if not line:
            if b"Path" in fields:
                emit()
            fields = {}
            if n >= max_members:
                stopped = "members: stopped at %d" % max_members
                break
            if time.monotonic() > deadline:
                stopped = "seconds: stopped after %d members" % n
                break
            continue
        if b" = " in line:
            k, v = line.split(b" = ", 1)
            fields[k.strip()] = v
    if not stopped and b"Path" in fields and n < max_members:
        emit()
    if stopped:
        proc.kill()
        cov["limits_hit"].append(stopped)
    proc.stdout.close()
    rc = proc.wait()
    end_leftovers()
    err.close()
    size = os.path.getsize(err_path)
    text = open(err_path, "rb").read(65536).decode("utf-8", "replace").strip() if size else ""
    if size == 0:
        os.remove(err_path)
    if rc != 0 and not stopped:
        # Any nonzero exit is an error entry, whether or not 7z said anything on stderr.
        cov["errors"].append("7z exited %d%s%s" % (rc, ": " + text if text else " with nothing on stderr", " (the whole of it, %d bytes, is 7z.stderr)" % size if size > 65536 else ""))
    return n


def run(path, out_dir):
    seconds, max_members = limits()
    deadline = time.monotonic() + seconds * 0.9
    try:
        os.makedirs(out_dir, exist_ok=True)
    except (OSError, ValueError) as exc:        # a name too long, a loop, a file in the way, a directory that cannot be entered
        print_answer({"ok": False, "status": "failed", "error": "--out cannot be used: %s" % (getattr(exc, "strerror", None) or exc.__class__.__name__),
                      "status_basis": "the output directory could not be made, so nothing was run"})
        sys.exit(2)
    _probe_out(out_dir)
    fmt, why = detect(path)
    cov = {"recipe": "archive-members", "target": path, "format": fmt, "members": 0,
           "covered": "the archive's list of members", "not_covered": "member contents; archives inside the archive",
           "limits_hit": [], "errors": []}
    if fmt is None or fmt == "unknown":
        cov.update(status="unsupported", why=why, status_basis="no tar, zip or 7z structure was found in the file: " + why)
        _write_json_whole(os.path.join(out_dir, "coverage.json"), cov, indent=2)
        print_answer({"ok": False, "status": "unsupported", "why": why})
        return 2
    # Said before the first member is read, so a run cut short at any point leaves a coverage file that says it did not finish.
    _write_json_whole(os.path.join(out_dir, "coverage.json"), dict(cov, status="partial", status_basis="the run had started and had listed nothing yet", why="started; the member list was not finished (the run stopped before its end)"), indent=2)
    if fmt == "tar" and zip_end_agrees(path):
        note = ("read as a tar, because a tar header reads at offset 0; the file also ends in a zip end-of-central-directory record that "
                "agrees with it, so a zip inside a member (or a second reading of the whole file) is not listed")
        cov["notes"] = [note]
        cov["covered"] += " (" + note + ")"
    if fmt == "zip" and reads_as_tar(path):
        note = ("read as a zip, because a zip signature is at offset 0; a tar header with a valid checksum also reads there (a first member "
                "named like a zip signature), so the file is also a tar and its tar members are not listed")
        cov["notes"] = [note]
        cov["covered"] += " (" + note + ")"
    w = Writer(out_dir)

    def _stopped(signum):
        proc = CHILD["proc"]
        if proc is not None:
            try:
                proc.kill()
                proc.wait(timeout=5)
            except Exception:  # noqa: BLE001 - best effort
                pass
        try:
            w.close()
        except Exception:  # noqa: BLE001
            pass
        _write_json_whole(os.path.join(out_dir, "coverage.json"), dict(cov, status="partial", interrupted=True, signal=signum, members=w.rows,
                       status_basis="the recipe was stopped by signal %d: the members listed before the stop are in members.tsv, and nothing is claimed about the rest" % signum), indent=2)
        print(json.dumps({"ok": False, "status": "partial", "interrupted": True, "signal": signum, "format": fmt, "members": w.rows}), flush=True)
    install_signal_handlers(_stopped)
    try:
        if fmt == "7z":
            n = list_7z(path, w, deadline, max_members, cov, out_dir)
        else:
            n = {"tar": list_tar, "zip": list_zip}[fmt](path, w, deadline, max_members, cov)
    except Exception as e:
        n = w.rows
        cov["errors"].append("%s: %s" % (type(e).__name__, e))
    finally:
        w.close()
    cov["members"] = n
    status = cov.pop("status_override", None)
    if status is None:
        status = "complete" if not cov["limits_hit"] and not cov["errors"] else ("partial" if n else "failed")
    cov["status"] = status
    cov["status_basis"] = {"complete": "the whole member list was read and written, with no limit hit and no error",
                           "partial": "part of the member list was read: a limit was hit or the archive broke part way (see limits_hit and errors)",
                           "failed": "no member could be listed (see errors)",
                           "unsupported": "7z, which this format needs, is not in this image"}.get(status, status)
    _write_json_whole(os.path.join(out_dir, "coverage.json"), cov, indent=2)
    with open(os.path.join(out_dir, "index.tsv"), "w", encoding="utf-8") as fh:
        fh.write("members.tsv\t%s member list (%d): n, type, path, path_b64, size, packed, mtime, tz, mode, uid, gid, link, locator, flags; n is the member's number in archive order\n"
                 % (cov.get("format") or "archive", n))
    print_answer({"ok": status in ("complete", "partial"), "status": status, "format": cov["format"], "members": n})
    return 0 if status in ("complete", "partial") else 2


def main(argv):
    if len(argv) < 2 or argv[1] not in ("detect", "run"):
        print_answer({"ok": False, "error": "usage: run.py detect --target T | run --target T --out DIR"})
        return 2
    args = dict(zip(argv[2::2], argv[3::2]))
    if "--target" not in args:
        print_answer({"ok": False, "error": "--target is required"})
        return 2
    _t, path = target_of(args["--target"])
    if argv[1] == "detect":
        fmt, why = detect(path)
        if fmt == "unknown":
            print_answer({"applies": "unknown", "format": None, "why": why})
            return 2
        print_answer({"applies": fmt is not None, "format": fmt, "why": why})
        return 0 if fmt else 1
    if "--out" not in args:
        print_answer({"ok": False, "error": "run needs --out DIR"})
        return 2
    if not _is_regular(path):
        print_answer({"ok": False, "status": "failed", "status_basis": "the target is not a regular file, so nothing was run", "error": "not a regular file"})
        return 2
    return run(path, args["--out"])


if __name__ == "__main__":
    sys.exit(main(sys.argv))
