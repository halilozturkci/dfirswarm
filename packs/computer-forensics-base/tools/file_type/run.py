#!/usr/bin/env python3
"""Identify a file from its bytes, and say when the name disagrees.

A `.jpg` that is a ZIP, a `.txt` with a PE header, a `.pdf` that is an HTML page
with a script in it — these are not edge cases, they are how things are hidden,
and an examiner who trusts the extension walks past them. So this reads the
header and then compares the answer with what the name claimed.

The hash comes back with it, because the first thing a sample needs is an
identity the report can refer to for the rest of the case.

What it identifies with: a table of signatures that carry forensic weight
(executables, archives, registry hives, event logs, prefetch at offset 4 and
its compressed MAM form, shortcuts, AD1 and E01 containers, memory captures) and,
for a file the table does not know, the installed `file` (libmagic) when there
is one. An identification is a reading of the first bytes, not a validation; a
type no source knows is `unrecognised` and its extension is neither a match nor a
mismatch (`extension_matches` is null).

What it covers: a directory is walked in sorted order, a file at a time; every
regular file looked at is in the whole result, whatever `limit` or `mismatch_only`
show inline, and `examined` counts the files actually opened. Symbolic links and
files that are not regular (devices, pipes, sockets) are listed and never opened
or followed. A file that could not be read is an error entry, reported whatever
`mismatch_only` says.
"""
import hashlib
import json
import os
import re
import shutil
import stat
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


def _drop_temporaries():
    """The hidden temporaries go before the tool ends, as they do when a stop signal ends it: the pages being written (_tmp) and the TEMPS list."""
    for page in list(globals().get("PAGES", ())):
        try:
            tmp = getattr(page, "_tmp", None)
            if tmp is not None:
                os.unlink(tmp)
        except Exception:   # noqa: BLE001 - best effort, and every one is tried
            pass
    for name in list(globals().get("TEMPS", ())):
        try:
            os.unlink(name)
        except Exception:   # noqa: BLE001
            pass


def _unexpected_tool(kind, value, _tb):
    """Last resort: an error nobody foresaw is an answer too. The hidden temporaries are removed, then one JSON document with the class and, for a
    file-system error, its reason (a message can quote a name from the evidence), and exit 1; what was written before it is not claimed. A stop signal
    that arrives while this runs is held with the answer's write and is answered by this document and exit 1, not by 128 + the signal."""
    try:
        _drop_temporaries()
        reason = getattr(value, "strerror", None) if issubclass(kind, OSError) else None
        said = ("a path or file could not be used: %s" % (reason or kind.__name__)) if issubclass(kind, (OSError, ValueError)) else "internal error: %s" % kind.__name__
        print_answer({"tool": globals().get("TOOL"), "status": "failed", "error": said,
                      "status_basis": "the tool stopped on an error it did not foresee (%s); what it had written before is not claimed" % kind.__name__})
    except BaseException:       # noqa: BLE001 - nothing may stop the exit
        pass
    os._exit(1)


sys.excepthook = _unexpected_tool


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

PAGES = []                 # objects with a hidden temporary file (_tmp) that a stop removes


CHILD = {"proc": None}     # the program being run, ended by its pid on a stop


def run_child(argv, timeout, **kwargs):
    """subprocess.run with its output captured, with the child recorded so that a stop can end it by its pid."""
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

TOOL = {"name": "file_type", "version": 11}
BUDGET_SECONDS = 100          # under the manifest's 120
LIBMAGIC_TIMEOUT = 10
ERRORS_SHOWN = 50
LIMIT_MAX = 5000                # files shown inline; every file looked at is in the whole-result file

class _AdSegments:
    """.ad1, .ad2, ... .ad10 and on: FTK Imager numbers an AD1 image's segments without end."""

    def __contains__(self, ext):
        return len(ext) > 2 and ext[:2] == "ad" and ext[2:].isdigit()

    def __bool__(self):
        return True


AD_SEGMENTS = _AdSegments()


class _EwfSegments:
    """.E01 to .E99 and .EAA on (EnCase), .S01 (SMART) and .Ex01 on (EWF2): every segment opens with the file header."""

    def __init__(self, pattern):
        self.pattern = re.compile(pattern)

    def __contains__(self, ext):
        return bool(self.pattern.fullmatch(ext))

    def __bool__(self):
        return True


EWF1_SEGMENTS = _EwfSegments(r"[es]\d\d|e[a-z]{2}")
EWF2_SEGMENTS = _EwfSegments(r"ex\d\d|ex[a-z]{2}")
EWF_LOGICAL_SEGMENTS = _EwfSegments(r"l\d\d|l[a-z]{2}")
EWF2_LOGICAL_SEGMENTS = _EwfSegments(r"lx\d\d|lx[a-z]{2}")
# What a plain text file is not named: the extensions of formats that are not text. A text file given one of these
# is worth a sentence; a text file named .ps1, .vbs, .js, .reg or .conf is not, and an extension no table lists is no mismatch.
BINARY_EXTENSIONS = {
    "exe", "dll", "sys", "scr", "ocx", "cpl", "efi", "mui", "msi", "zip", "docx", "xlsx", "pptx", "docm", "xlsm", "pptm", "jar", "apk",
    "odt", "ods", "epub", "whl", "ipa", "aff4", "rar", "7z", "gz", "tgz", "bz2", "xz", "doc", "xls", "ppt", "msg", "pdf", "png", "jpg",
    "jpeg", "gif", "wav", "avi", "webp", "sqlite", "sqlite3", "evtx", "lnk", "pf", "ad1", "lime", "dmp", "tar", "hve", "hiv", "class",
    "dylib", "bundle", "so", "elf", "mp3", "mp4", "mov", "iso", "vhd", "vhdx", "vmdk", "qcow2",
}

MAGIC = [
    (0, b"MZ", "PE or DOS executable", {"exe", "dll", "sys", "scr", "ocx", "cpl", "efi", "mui", "msi"}),
    (0, b"\x7fELF", "ELF executable or object", {"so", "o", "elf", "bin", ""}),
    (0, b"\xcf\xfa\xed\xfe", "Mach-O 64-bit", {"dylib", "bundle", "o", ""}),
    (0, b"\xce\xfa\xed\xfe", "Mach-O 32-bit", {"dylib", "bundle", "o", ""}),
    (0, b"PK\x03\x04", "ZIP container", {"zip", "docx", "xlsx", "pptx", "docm", "xlsm", "pptm",
                                          "jar", "apk", "odt", "ods", "epub", "whl", "ipa", "aff4"}),
    (0, b"Rar!\x1a\x07", "RAR archive", {"rar"}),
    (0, b"7z\xbc\xaf\x27\x1c", "7-Zip archive", {"7z"}),
    (0, b"\x1f\x8b", "gzip", {"gz", "tgz", "svg", "log"}),
    (0, b"BZh", "bzip2", {"bz2"}),
    (0, b"\xfd7zXZ\x00", "xz", {"xz"}),
    (0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE compound file", {"doc", "xls", "ppt", "msg",
                                                                   "msi", "db", "ms", "automaticdestinations-ms"}),
    (0, b"%PDF-", "PDF", {"pdf"}),
    (0, b"{\\rtf", "RTF", {"rtf", "doc"}),
    (0, b"\x89PNG\r\n\x1a\n", "PNG", {"png"}),
    (0, b"\xff\xd8\xff", "JPEG", {"jpg", "jpeg"}),
    (0, b"GIF8", "GIF", {"gif"}),
    (0, b"RIFF", "RIFF container (wav, avi, webp)", {"wav", "avi", "webp"}),
    (0, b"SQLite format 3\x00", "SQLite database", {"db", "sqlite", "sqlite3", "history",
                                                    "cookies", "places", "dat", ""}),
    (0, b"regf", "Windows registry hive", {"dat", "hve", "hiv", ""}),
    (0, b"ElfFile\x00", "Windows event log", {"evtx"}),
    (0, b"bplist00", "binary property list", {"plist", "btm", "db", ""}),
    (0, b"<?xml", "XML", {"xml", "plist", "svg", "rels", "config"}),
    (0, b"#!", "script with a shebang", {"sh", "py", "pl", "rb", ""}),
    (0, b"\x4c\x00\x00\x00\x01\x14\x02\x00", "Windows shortcut", {"lnk"}),
    (0, b"MAM\x04", "compressed prefetch record", {"pf"}),
    (4, b"SCCA", "prefetch record", {"pf"}),
    (0, b"EVF\x09\x0d\x0a\xff\x00", "EnCase E01 image (EWF, a segment)", EWF1_SEGMENTS),
    (0, b"EVF2\x0d\x0a\x81\x00", "EnCase Ex01 image (EWF2, a segment)", EWF2_SEGMENTS),
    (0, b"LVF\x09\x0d\x0a\xff\x00", "EnCase L01 logical evidence file (EWF, a segment)", EWF_LOGICAL_SEGMENTS),
    (0, b"LVF2\x0d\x0a\x81\x00", "EnCase Lx01 logical evidence file (EWF2, a segment)", EWF2_LOGICAL_SEGMENTS),
    (0, b"EVF\x09", "an EWF header that is not a whole E01 file header", set()),
    (0, b"ADSEGMENTEDFILE\x00", "AccessData AD1 logical image (a segment)", AD_SEGMENTS),
    (0, b"ADCRYPT", "AccessData AD1 logical image, encrypted", {"ad1"}),
    (0, b"AVML", "AVML memory capture", {"lime", "raw", "mem"}),
    (0, b"EMiL", "LiME memory capture", {"lime", "raw", "mem"}),
    (0, b"PAGEDU", "Windows crash dump", {"dmp"}),
    (257, b"ustar", "tar archive", {"tar"}),
]
TEXTY = bytes(range(0x20, 0x7f)) + b"\r\n\t\f\b"


def fail(message, **extra):
    print_answer({"error": message, "status": "failed", "status_basis": "the tool stopped with an error: %s" % message, "tool": TOOL, **extra})
    raise SystemExit(1)


def class_or_fat(head):
    """0xCAFEBABE opens both a Mach-O universal binary (a big-endian count of architectures) and a
    Java class file (a minor and a major version). The count is small; Java's major starts at 45."""
    count = int.from_bytes(head[4:8], "big")
    major = int.from_bytes(head[6:8], "big")
    if 1 <= count < 45:
        return "Mach-O universal binary", {"dylib", "bundle", ""}
    if 45 <= major <= 90:
        return "Java class file", {"class"}
    return "0xCAFEBABE header (a Mach-O universal binary or a Java class file; neither layout fits)", set()


def identify(head):
    if head[:4] == b"\xca\xfe\xba\xbe" and len(head) >= 8:
        return class_or_fat(head)
    for offset, signature, name, extensions in MAGIC:
        if head[offset:offset + len(signature)] == signature:
            return name, extensions
    sample = head[:512]
    if sample and all(b in TEXTY for b in sample):
        lowered = sample.lstrip().lower()
        if lowered.startswith(b"<!doctype html") or lowered.startswith(b"<html"):
            return "HTML", {"html", "htm"}
        return "text", None                # any extension that is not a binary format's is consistent with text
    return "unrecognised", set()


_libmagic = {"state": None}


def libmagic(path):
    """The installed `file`'s description of a file, or None (and why, in _libmagic)."""
    if _libmagic["state"] is None:
        _libmagic["state"] = shutil.which("file") or False
    if not _libmagic["state"]:
        return None
    try:
        p = run_child([_libmagic["state"], "-b", "--", path], LIBMAGIC_TIMEOUT, env=dict(os.environ, LC_ALL="C"))
    except (subprocess.TimeoutExpired, OSError):
        return None
    text = p.stdout.decode("utf-8", "replace").strip()
    return text[:200] if p.returncode == 0 and text else None


def look(path, deadline=None, with_head=False):
    """One entry for one directory entry. Links and non-regular files are named and not opened.
    The hash is of the whole file unless the time budget runs out in it: the entry then says so, with how far it got."""
    try:
        st = os.lstat(path)
    except OSError as exc:
        return {"file": path, "error": exc.strerror or str(exc)}
    claimed = os.path.splitext(path)[1].lstrip(".").lower()
    if stat.S_ISLNK(st.st_mode):
        try:
            target = os.readlink(path)
        except OSError:
            target = None
        return {"file": path, "kind": "symbolic link", "link_target": target, "type": "not opened: a link is listed, never followed",
                "extension": claimed or None, "extension_matches": None}
    if not stat.S_ISREG(st.st_mode):
        return {"file": path, "kind": "not a regular file", "mode": stat.filemode(st.st_mode), "type": "not opened",
                "extension": claimed or None, "extension_matches": None}
    hashed_to = None
    try:
        with open_regular(path) as fh:
            head = fh.read(4096)
            digest = hashlib.sha256()
            digest.update(head)
            read = len(head)
            while True:
                if deadline is not None and time.monotonic() > deadline:
                    hashed_to = read
                    break
                block = fh.read(1 << 20)
                if not block:
                    break
                read += len(block)
                digest.update(block)
    except OSError as exc:
        return {"file": path, "error": exc.strerror or str(exc)}
    name, extensions = identify(head)
    source = "signature table" if name != "unrecognised" else None
    entry = {"file": path, "bytes": st.st_size, "type": name, "type_source": source}
    if name == "unrecognised":
        described = libmagic(path)
        if described and described != "data":
            entry["type"], entry["type_source"] = described, "libmagic (the installed file command)"
        elif described == "data":
            entry["type_source"] = "none: libmagic calls it data, which is its word for no type"
        else:
            entry["type_source"] = "none: neither the table nor libmagic names it" if _libmagic["state"] else "none: the table does not name it and `file` is not installed"
    # An extension can only be compared with a type whose extensions are known; an unknown type is neither a match nor a mismatch.
    entry["extension"] = claimed or None
    if extensions is None:                       # plain text
        entry["extension_matches"] = claimed not in BINARY_EXTENSIONS
    else:
        entry["extension_matches"] = (claimed in extensions) if extensions else None
    if hashed_to is None:
        entry["sha256"] = digest.hexdigest()
    else:
        entry["sha256"] = None
        entry["hashing"] = "stopped at the time budget after %d of %d bytes: no digest for this file" % (hashed_to, st.st_size)
    if with_head:
        entry["head_hex"] = head[:16].hex()           # opt-in: the first bytes of a key file or a credential store are the secret
    return entry


def walk(path):
    """Every entry under `path`, in sorted order, directories sorted too; a link to a directory is an entry, not a place to go.
    Yields (path, None), or (path, error text) for a directory that could not be listed: that is said, not skipped."""
    if not os.path.isdir(path) or os.path.islink(path):
        yield path, None
        return
    problems = []
    for dirpath, dirs, names in os.walk(path, followlinks=False, onerror=problems.append):
        dirs.sort()
        linked = [d for d in dirs if os.path.islink(os.path.join(dirpath, d))]
        for name in sorted(names + linked):
            yield os.path.join(dirpath, name), None
        dirs[:] = [d for d in dirs if d not in linked]
        while problems:
            exc = problems.pop(0)
            yield os.fsdecode(exc.filename or dirpath), "the directory could not be listed: %s" % (exc.strerror or exc)
    while problems:                          # the last directory walked may be the one that failed
        exc = problems.pop(0)
        yield os.fsdecode(exc.filename or path), "the directory could not be listed: %s" % (exc.strerror or exc)


def earlier_answers(path):
    """How many other files answer this same question in the folder (name.ext, name.2.ext, ...): one more for every different
    answer, and none is deleted, so the count is said."""
    stem, ext = os.path.splitext(os.path.basename(str(path)))
    base = re.sub(r"\.\d+$", "", stem)
    rx = re.compile(r"^%s(\.\d+)?%s$" % (re.escape(base), re.escape(ext)))
    try:
        return max(0, sum(1 for n in os.listdir(os.path.dirname(str(path)) or ".") if rx.match(n)) - 1)
    except OSError:
        return 0


def same_bytes(a, b, deadline=None):
    """Whether two files hold the same bytes (read in blocks, never whole). Each is opened without waiting and without following a link
    (O_NONBLOCK, O_NOFOLLOW) and looked at with fstat first: only two regular files of one size are read, so a FIFO, a device, a
    directory or a link at either name is never read (a FIFO would hold the tool for ever). Past `deadline` (a monotonic time) the
    answer is False."""
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
    fa = fb = None
    try:
        fa = os.fdopen(os.open(str(a), flags), "rb")
        fb = os.fdopen(os.open(str(b), flags), "rb")
        sa, sb = os.fstat(fa.fileno()), os.fstat(fb.fileno())
        if (sa.st_mode & 0o170000) != 0o100000 or (sb.st_mode & 0o170000) != 0o100000 or sa.st_size != sb.st_size:
            return False
        while True:
            if deadline is not None and time.monotonic() > deadline:
                return False
            x, y = fa.read(1 << 20), fb.read(1 << 20)
            if x != y:
                return False
            if not x:
                return True
    except OSError:
        return False
    finally:
        for fh in (fa, fb):
            if fh is not None:
                fh.close()


def publish(tmp, path, shown):
    """Move a finished file to `path` without replacing what is there: a file at the name is an earlier answer (a complete
    one, perhaps, where this run was cut short) and stays; this one is kept beside it as name.2.ext, unless it is the
    same bytes, when the file already there is it. Returns the path it has
    and the name to show for it."""
    stem, ext = os.path.splitext(str(path))
    shown_stem, _ = os.path.splitext(shown)
    k = 1
    while True:
        suffix = "" if k == 1 else ".%d" % k
        candidate = Path(stem + suffix + ext)
        try:
            os.link(tmp, candidate)
        except FileExistsError:
            if same_bytes(tmp, candidate):                # the same answer again (a page of the same search): the file is already there
                os.unlink(tmp)
                return candidate, shown_stem + suffix + ext
            k += 1
            continue
        except OSError:                                   # a file system with no hard links: a look, then a rename
            if os.path.lexists(candidate):
                if same_bytes(tmp, candidate):
                    os.unlink(tmp)
                    return candidate, shown_stem + suffix + ext
                k += 1
                continue
            os.rename(tmp, candidate)
            return candidate, shown_stem + suffix + ext
        os.unlink(tmp)
        return candidate, shown_stem + suffix + ext


class Results:
    """Every result goes to a file as it is made; the inline page is the filtered, limited view of them."""

    def __init__(self, key):
        digest = hashlib.sha256(json.dumps(key, sort_keys=True).encode()).hexdigest()[:16]
        name = "file_type-%s.jsonl" % digest
        job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
        if job and out:
            self.path = Path(out) / "tool-output" / name
            self.shown = "store/jobs/%s/out/tool-output/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", job), name)
        else:
            agent = re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool")
            self.path = Path("work") / agent / "tool-output" / name
            self.shown = str(self.path)
        self.tmp, self.fh, self.error = None, None, None
        PAGES.append(self)
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".file_type-")
            self.tmp, self.fh = Path(tmp), os.fdopen(fd, "w", encoding="utf-8")
        except OSError as exc:
            self.error = "the whole result could not be kept (%s: %s)" % (self.path.parent, exc.strerror or exc)

    @property
    def _tmp(self):
        return self.tmp

    def _give_up(self, exc):
        """The whole-result file cannot be written (a full disk, a file-size limit): it is closed and removed, the page and the counts stay
        whole, and the answer says so (all_results_error)."""
        self.error = "the whole result could not be kept (%s: %s)" % (self.path.parent, getattr(exc, "strerror", None) or exc.__class__.__name__)
        try:
            if self.fh:
                self.fh.close()
        except OSError:
            pass
        try:
            if self.tmp:
                os.unlink(self.tmp)
        except OSError:
            pass
        self.fh = self.tmp = None

    def add(self, entry):
        if self.fh:
            try:
                self.fh.write(json.dumps(entry) + "\n")          # ASCII escapes: a name that is not UTF-8 is written, never lost
            except OSError as exc:
                self._give_up(exc)

    def finish(self, keep):
        """Publish the file when the inline page is not the whole result; drop it when it is."""
        if not self.fh:
            return None
        try:
            self.fh.flush()
            os.fsync(self.fh.fileno())
            self.fh.close()
            if keep:
                self.path, self.shown = publish(self.tmp, self.path, self.shown)
                self.tmp = None
                return self.shown
            os.unlink(self.tmp)
        except OSError as exc:
            self._give_up(exc)
            return None
        return None


def main():
    try:
        args = json.load(sys.stdin)
    except (ValueError, RecursionError) as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    if not isinstance(args, dict):
        fail("arguments are a JSON object")
    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: a file or a directory to walk")
    if not os.path.lexists(path):
        fail("no such file or directory", path=path)
    limit = args.get("limit", 500)
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= LIMIT_MAX:
        fail("limit is a whole number from 1 to %d (every file looked at is kept in a file when the page is not all of them)" % LIMIT_MAX)
    mismatch_only = args.get("mismatch_only", False)
    if not isinstance(mismatch_only, bool):
        fail("mismatch_only is true or false")
    head_hex = args.get("head_hex", False)
    if not isinstance(head_hex, bool):
        fail("head_hex is true or false")

    # A path the caller named that is itself a link (a set held in place under inputs/ is one) is followed once: it is where they
    # asked to look. Links found inside it are listed, never followed.
    root, top = path, None
    if os.path.islink(path):
        real = os.path.realpath(path)
        if not os.path.exists(real):
            fail("the link at path points nowhere", path=path, target=os.readlink(path))
        root, top = real, {"path": path, "target": real}

    def shown(p):
        return path + p[len(root):] if top and (p == root or p.startswith(root.rstrip(os.sep) + os.sep)) else p

    deadline = time.monotonic() + BUDGET_SECONDS
    counts = {"discovered": 0, "examined": 0, "mismatches": 0, "unrecognised": 0, "links": 0, "not_regular": 0, "errors": 0, "not_attempted": 0, "not_hashed": 0}

    def _stopped(signum):
        end_child()
        print(json.dumps({"tool": TOOL, "path": path, "status": "partial", "interrupted": True, "signal": signum, "discovered": counts["discovered"], "examined": counts["examined"],
                          "status_basis": "the tool was stopped by signal %d: the files looked at so far were not kept (the half-written results file was removed); run it again" % signum}), flush=True)
    install_signal_handlers(_stopped)
    results = Results([path, mismatch_only, limit, head_hex])
    not_attempted = []
    page, errors = [], []
    inline_total = 0
    stopped = None
    for target, problem in walk(root):
        counts["discovered"] += 1
        if problem:
            entry = {"file": target, "error": problem}
        elif time.monotonic() > deadline:
            stopped = stopped or "the %d-second time budget was used" % BUDGET_SECONDS
            counts["not_attempted"] += 1
            # Named, not just counted: the entry is in the whole result, and the first ones are in the answer.
            results.add({"file": shown(target), "not_attempted": "the time budget was used before this was looked at"})
            if len(not_attempted) < ERRORS_SHOWN:
                not_attempted.append(shown(target))
            continue
        else:
            entry = look(target, deadline, head_hex)
            if entry.get("hashing"):
                stopped = stopped or "the %d-second time budget was used while hashing %s" % (BUDGET_SECONDS, shown(target))
                counts["not_hashed"] += 1
        entry["file"] = shown(entry["file"])
        results.add(entry)
        if "error" in entry:
            counts["errors"] += 1
            if len(errors) < ERRORS_SHOWN:
                errors.append({"file": entry["file"], "error": entry["error"]})
            continue
        counts["examined"] += entry.get("kind") is None
        counts["links"] += entry.get("kind") == "symbolic link"
        counts["not_regular"] += entry.get("kind") == "not a regular file"
        counts["unrecognised"] += entry.get("type") == "unrecognised" or str(entry.get("type_source", "")).startswith("none")
        mismatch = entry.get("extension_matches") is False
        counts["mismatches"] += mismatch
        if mismatch_only and not mismatch:
            continue
        inline_total += 1
        if len(page) < limit:
            page.append(entry)
    needed = (inline_total > len(page) or (mismatch_only and counts["discovered"] > inline_total) or counts["errors"] > ERRORS_SHOWN
              or counts["not_attempted"] > ERRORS_SHOWN)
    whole = results.finish(keep=needed)
    why_not_complete = []
    if stopped:
        why_not_complete.append(stopped)
    if counts["errors"]:
        why_not_complete.append("%d entries could not be read or listed (errors)" % counts["errors"])
    if counts["discovered"] and not counts["examined"]:
        why_not_complete.append("nothing was opened: every entry found was a link or not a regular file, and a link is listed, never followed")
    out = {
        "tool": TOOL,
        "path": path,
        "files": page,
        "file_count": len(page),
        "matching_the_filter": inline_total,
        "discovered": counts["discovered"],
        "examined": counts["examined"],
        "not_attempted": counts["not_attempted"],
        "not_attempted_files": not_attempted,
        "not_hashed": counts["not_hashed"],
        "extension_mismatches": counts["mismatches"],
        "unrecognised": counts["unrecognised"],
        "links_listed": counts["links"],
        "not_regular_listed": counts["not_regular"],
        "error_count": counts["errors"],
        "errors": errors,
        "truncated": inline_total > len(page),
        "complete": not why_not_complete,
        "status": "complete" if not why_not_complete else "partial",
        "status_basis": "every entry found was looked at" if not why_not_complete else "; ".join(why_not_complete),
        "note": "A mismatch is a lead, not a finding: plenty of legitimate files carry an "
                "unexpected extension, and a container type such as ZIP covers a dozen document "
                "formats. What matters is the direction — an executable named .txt is worth a "
                "sentence, a .docx that is a ZIP is simply what a .docx is. A type read from the first "
                "bytes is an identification, not a validation of the file.",
    }
    if whole:
        out["all_results"] = whole
        out["earlier_answers"] = earlier_answers(results.path)
        out["all_results_format"] = "JSON Lines, one complete entry per file looked at, whatever limit and mismatch_only show"
    if results.error:
        out["all_results_error"] = results.error
        if needed:                                   # the page is not the whole result and the file that holds the rest is missing
            out["complete"] = False
            out["status"] = "partial"
            out["status_basis"] = ("%s; %s" % (out["status_basis"], "the file that should hold every result could not be written (all_results_error)")
                                   if why_not_complete else "the page and the counts are right, but the file that should hold every result could not be written (all_results_error)")
    if stopped:
        out["stopped"] = stopped
    if why_not_complete:
        out["why_not_complete"] = why_not_complete
    if top:
        out["path_is_a_link"] = {"link": top["path"], "followed_to": top["target"], "note": "the path named is a link, followed once; links inside it are listed, never followed"}
    if counts["not_attempted"] > ERRORS_SHOWN:
        out["not_attempted_note"] = "%d entries were not looked at; the first %d are named, every one is in all_results" % (counts["not_attempted"], ERRORS_SHOWN)
    if counts["errors"] > ERRORS_SHOWN:
        out["errors_note"] = "%d errors; the first %d are listed, the rest are in all_results" % (counts["errors"], ERRORS_SHOWN)
    print_answer(out, indent=2)


if __name__ == "__main__":
    main()
