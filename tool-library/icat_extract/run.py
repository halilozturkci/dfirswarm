#!/usr/bin/env python3
"""Extract one Sleuth Kit address from a disk image to a new file, and say exactly what came out.

The extraction is streamed: icat's output goes through a block at a time into a file that is
created new (an existing file is never replaced) while it is hashed, so a pagefile or a virtual disk
of any size is never held in memory. An output budget (`max_bytes`) and a time budget (`max_seconds`)
bound it; a run that hits one, or whose icat fails part way, keeps what it wrote as `<output>.partial`
and says so (status partial): no truncated file keeps its own name. The result names the image, the
volume offset in sectors, the sector size passed to the Sleuth Kit (-b, only when given), the address
asked for, icat's exit code and where its stderr is kept. A 1 or 2 sector size is not guessed.
"""
import hashlib
import json
import os
import re
import select
import shutil
import subprocess
import sys
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
RUN = {"proc": None, "size": 0}      # the icat running and the bytes written, for a stop

TOOL = {"name": "icat_extract", "version": 17}
OFFSET_MAX = 1 << 40              # sectors: an explicit offset above this is not a volume offset (512 TiB at 512 bytes a sector)
BLOCK = 1 << 20
MAX_BYTES_DEFAULT = 32 * 1024 ** 3
MAX_BYTES_CEILING = 1024 ** 4
MAX_SECONDS_DEFAULT = 1500
MAX_SECONDS_CEILING = 1700        # inside the manifest's own 1800-second limit: a longer budget would be killed, not reported
SECTOR_MAX = 65536
INODE = re.compile(r"^\d+(-\d+(-\d+)?)?$")
RESOLVE_SECONDS = 60               # the search for the image under inputs/ (when image= is not given)
CANDIDATES_MAX = 200               # and the images it keeps before it asks the caller to say which

def _catalogue_slug(path):
    """The directory name the kickoff's catalogue gives an input: its path under
    inputs/ with every byte outside [A-Za-z0-9._-] made "_" (evidence-catalog.sh)."""
    import os, re
    rel = os.fsencode(os.path.relpath(path, "inputs"))
    return os.fsdecode(re.sub(rb"[^A-Za-z0-9._-]", b"_", rel))


def _inputs_roots():
    """inputs/, and each set held in place as a link directly under it (inputs.json names the sets): the only links followed.
    Any other link under inputs/ is a name and not a place to walk: following one could leave the evidence for the rest of the file system."""
    import json, os
    roots = ["inputs"]
    try:
        with open("inputs.json", encoding="utf-8") as fh:
            sets = json.load(fh).get("sets") or []
    except (OSError, ValueError, AttributeError):
        sets = []
    for entry in sets:
        name = entry.get("name") if isinstance(entry, dict) else None
        if isinstance(name, str) and name and "/" not in name and os.path.islink(os.path.join("inputs", name)):
            roots.append(os.path.join("inputs", name))
    return roots


def _resolve_image(explicit=None):
    """A pack tool belongs to no case: find the image under inputs/ instead of
    baking one in. One candidate is used; several mean the caller must say which.
    An image is known by its extension or, lacking one (a raw `dd` of a web
    server named after the host), by the catalogue: the kickoff writes
    catalog/<input>/partitions.txt for every input it read as a disk.
    The search is on a clock (RESOLVE_SECONDS, read for every entry) and keeps at most CANDIDATES_MAX names:
    a tree it cannot finish, or one with more images than that, is said, and the caller passes image=."""
    import glob, os, time
    if explicit:
        return explicit
    deadline = time.monotonic() + RESOLVE_SECONDS
    cands = []
    for ext in ("*.E01", "*.e01", "*.raw", "*.dd", "*.001", "*.img", "*.vhd", "*.vhdx"):
        cands += glob.glob(os.path.join("inputs", ext))
    for root_dir in _inputs_roots():
        stack = [root_dir]
        while stack:
            here = stack.pop()
            try:
                scan = os.scandir(here)
            except OSError:
                continue
            with scan:
                for entry in scan:
                    if time.monotonic() > deadline:
                        raise SystemExit(json.dumps({"ok": False, "error": "looking for the image under inputs/ used its %d seconds before it was done; pass image=" % RESOLVE_SECONDS}))
                    try:
                        is_dir = entry.is_dir()
                        if is_dir and entry.is_symlink():
                            continue                         # a directory link is a name and not a place to walk
                    except OSError:
                        continue
                    if is_dir:
                        stack.append(entry.path)
                    elif os.path.isfile(os.path.join("catalog", _catalogue_slug(entry.path), "partitions.txt")):
                        cands.append(entry.path)
                        if len(set(cands)) > CANDIDATES_MAX:
                            raise SystemExit(json.dumps({"ok": False, "error": "more than %d images under inputs/; pass image=" % CANDIDATES_MAX}))
    cands = sorted(set(cands))
    if len(cands) == 1:
        return cands[0]
    if not cands:
        raise SystemExit('{"ok": false, "error": "no disk image under inputs/; pass image="}')
    raise SystemExit('{"ok": false, "error": "several images under inputs/; pass image=", "candidates": %s}' % json.dumps(cands))


def _resolve_offset(image, explicit=None):
    """The volume's start sector for icat -o. Given, it is used as is; not
    given, the catalogue says: one filesystem catalogued (catalog/<input>/p<start>/)
    is that start, several mean the caller must say which, none is sector 0."""
    import os, re
    if explicit is not None:
        return explicit
    root = os.path.join("catalog", _catalogue_slug(image))
    starts = sorted(int(d[1:]) for d in (os.listdir(root) if os.path.isdir(root) else [])
                    if re.fullmatch(r"p\d+", d) and os.path.isdir(os.path.join(root, d)))
    if len(starts) == 1:
        return starts[0]
    if not starts:
        return 0
    raise SystemExit('{"ok": false, "error": "several filesystems in %s; pass offset= (a start sector, see %s/partitions.txt)", "candidates": %s}' % (image, root, json.dumps(starts)))


def _resolve_catalog(explicit=None):
    """The catalogue directory for the one image the kickoff catalogued, or
    the one named: by its name under catalog/, as the index lists it
    (catalog=Case4.E01 was a traceback), or by its path."""
    import os
    root = "catalog"
    subs = sorted(d for d in os.listdir(root) if os.path.isdir(os.path.join(root, d))) if os.path.isdir(root) else []
    if explicit:
        for cand in (explicit, os.path.join(root, explicit)):
            if os.path.isdir(cand):
                return cand
        raise SystemExit(json.dumps({"ok": False, "error": "no catalogue %s" % explicit, "candidates": subs}))
    if not os.path.isdir(root):
        raise SystemExit('{"ok": false, "error": "no catalog/ in this run; pass catalog="}')
    if len(subs) == 1:
        return os.path.join(root, subs[0])
    if not subs:
        raise SystemExit('{"ok": false, "error": "catalog/ is empty; pass catalog="}')
    # A disk and a memory image catalogue two directories, and only the
    # disk's has filesystems (partitions.txt): with one such, it is the one.
    disks = [d for d in subs if os.path.isfile(os.path.join(root, d, "partitions.txt"))]
    if len(disks) == 1:
        return os.path.join(root, disks[0])
    raise SystemExit('{"ok": false, "error": "several catalogues; pass catalog=", "candidates": %s}' % json.dumps(subs))

def _catalogued(image, offset, inode):
    """What the catalogue's path list says `inode` is on this filesystem:
    [{"type", "path", "deleted", "address"}], [] when there is no list or no line. An address
    with an attribute (168-128-4) matches only that attribute's lines; a bare record number
    matches every attribute of the record, each with its own address."""
    import os, re
    listing = os.path.join("catalog", _catalogue_slug(image), "p%s" % offset, "filelist.txt")
    if not os.path.isfile(listing):
        return []
    parts = str(inode).split("-")
    want_rec, want_attr = parts[0], (parts[1], parts[2]) if len(parts) == 3 else None
    marks = (" %s-" % want_rec, " %s:" % want_rec, " %s(" % want_rec)
    rx = re.compile(r"^\S/(\S) (\* )?(\d+)(?:-(\d+)-(\d+))?(?:\([^)]*\))?:\t(.*)$")
    out = []
    with open(listing, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if not any(m in line for m in marks):
                continue
            m = rx.match(line.rstrip("\n"))
            if not m or m.group(3) != want_rec:
                continue
            attr = (m.group(4), m.group(5)) if m.group(4) else None
            if want_attr and attr != want_attr:
                continue
            out.append({"type": m.group(1), "path": m.group(6), "deleted": bool(m.group(2)),
                        "address": m.group(3) + ("-%s-%s" % attr if attr else "")})
    return out


FAILED_BASIS = "the tool stopped with an error and extracted nothing (see error)"


def fail(msg, **extra):
    print_answer({"error": msg, "status": "failed", "status_basis": "the tool stopped with an error: %s" % msg, "tool": TOOL, **extra})
    sys.exit(1)


def unexpected(kind, value, _tb):
    """An error nobody expected is an answer too: its class only, since its message can quote a name from the evidence."""
    print(json.dumps({"error": ("a path or file could not be used: %s" if issubclass(kind, (OSError, ValueError)) else "internal error: %s") % kind.__name__, "tool": TOOL, "status": "failed", "status_basis": FAILED_BASIS}))
    sys.stdout.flush()
    os._exit(1)


sys.excepthook = unexpected


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


def on_stdout(resolve, *given):
    """The image and offset resolvers end with SystemExit(<JSON text>), which Python prints on stderr: the answer belongs on stdout, with the status pair."""
    try:
        return resolve(*given)
    except SystemExit as exc:
        if isinstance(exc.code, str):
            try:
                doc = json.loads(exc.code)
            except ValueError:
                doc = {"ok": False, "error": exc.code}
            if isinstance(doc, dict):
                doc = {"ok": False, "status": "failed", "status_basis": "the tool stopped with an error: %s" % doc.get("error"), "tool": TOOL, **doc}
            print_answer(doc)
            sys.exit(1)
        raise


def resolve_output(out):
    """Where `out` really lands, refusing anything outside the run directory.

    A string check is not enough: `work/../inputs/x` and an absolute path
    both name a file the tool must not write, and neither starts with
    "inputs/". Resolving first and comparing directories is what actually
    holds, and the read-only inputs are the one place extracted bytes must
    never appear -- a later integrity check would report the evidence as
    modified.
    """
    root = Path.cwd().resolve()
    try:
        dest = (root / out).resolve() if not Path(out).is_absolute() else Path(out).resolve()
    except (OSError, RuntimeError, ValueError) as exc:     # a symlink loop, a name too long, a lone surrogate
        fail("output cannot be resolved: %s" % (exc.__class__.__name__ if not getattr(exc, "strerror", None) else exc.strerror), output=str(out))
    if dest != root and root not in dest.parents:
        fail("output must stay inside the run directory", output=str(out))
    inputs = root / "inputs"
    if dest == inputs or inputs in dest.parents:
        fail("output cannot be under inputs/", output=str(out))
    job, bound = os.environ.get("JOB_ID"), os.environ.get("OUT")
    if job and bound:
        bound = Path(bound).resolve()
        if bound not in dest.parents:
            fail("in a job an output is a path under $OUT, the one place a job writes (the rest of the run is read-only there)",
                 output=str(out), out=str(bound), hint="give {OUT}/<name>, or work/extracted/<your id>/<name>, which the harness maps there")
    return dest


try:
    d = json.load(sys.stdin)
except (ValueError, RecursionError) as exc:
    fail("arguments are not valid JSON", reason=str(exc)[:200])
if not isinstance(d, dict):
    fail("arguments are a JSON object")
inode = d.get("inode")
output = d.get("output")
if inode is None or not isinstance(output, str) or not output:
    fail("need inode and output")
for _name, _value in (("output", output), ("image", d.get("image")), ("inode", inode)):
    if _name == "image" and _value is not None and not isinstance(_value, str):
        fail("image is a path")
    if isinstance(_value, str):
        if "\0" in _value:
            fail("%s holds a NUL character" % _name)
        try:
            _value.encode("utf-8")
        except UnicodeEncodeError:
            fail("%s is not text that can be written as UTF-8 (it holds a lone surrogate)" % _name)
# An explicit offset is a volume offset in sectors: a whole number, not a bool, not negative, and within what icat takes (OFFSET_MAX).
given_offset = d.get("offset")
if given_offset is not None and (isinstance(given_offset, bool) or not isinstance(given_offset, int) or not 0 <= given_offset <= OFFSET_MAX):
    fail("offset is a volume offset in sectors: a whole number from 0 to %d" % OFFSET_MAX, given=type(given_offset).__name__ + " " + str(given_offset)[:40])
descriptor = None
if d.get("descriptor") is not None:
    for _key in ("image", "sector_size"):
        if d.get(_key) is not None:
            fail("a descriptor replaces image and sector_size: give %s or the descriptor, not both" % _key)
    if d.get("verify_sources") is not None and not isinstance(d.get("verify_sources"), bool):
        fail("verify_sources is true or false")
    try:
        descriptor = load_descriptor(d["descriptor"], d.get("descriptor_sha256"), d.get("verify_sources") is True, time.monotonic() + DESCRIPTOR_VERIFY_SECONDS)
    except DescriptorError as exc:
        fail(str(exc))
elif d.get("verify_sources") is not None or d.get("descriptor_sha256") is not None:
    fail("verify_sources and descriptor_sha256 belong with descriptor")
if descriptor is not None:
    images = descriptor["images"]
    image = images[0]
else:
    image = on_stdout(_resolve_image, d.get("image"))
    images = [image]
if isinstance(inode, bool) or not (isinstance(inode, int) and inode >= 0 or isinstance(inode, str) and INODE.match(inode)):
    fail("inode is a Sleuth Kit address: a number, or number-type-id for an NTFS stream (168-128-4)", inode=inode)
# 084284 is address 84284: icat would read a leading zero as octal. The address is held as its numbers.
inode = "-".join(str(int(part)) for part in str(inode).split("-"))
sector_size = d.get("sector_size")
if sector_size is not None and (not isinstance(sector_size, int) or isinstance(sector_size, bool)
                                or sector_size < 512 or sector_size > SECTOR_MAX or sector_size % 512):
    fail("sector_size must be a multiple of 512 from 512 to %d (the Sleuth Kit's -b takes no other)" % SECTOR_MAX, sector_size=sector_size)
if descriptor is not None and descriptor["sector_size"] != 512:
    sector_size = descriptor["sector_size"]          # the descriptor's sector size goes to icat as -b, as a caller's sector_size would
max_bytes = d.get("max_bytes", MAX_BYTES_DEFAULT)
if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or not 1 <= max_bytes <= MAX_BYTES_CEILING:
    fail("max_bytes is a whole number from 1 to %d" % MAX_BYTES_CEILING, max_bytes=max_bytes)
max_seconds = d.get("max_seconds", MAX_SECONDS_DEFAULT)
if not isinstance(max_seconds, int) or isinstance(max_seconds, bool) or not 1 <= max_seconds <= MAX_SECONDS_CEILING:
    fail("max_seconds is a whole number from 1 to %d" % MAX_SECONDS_CEILING, max_seconds=max_seconds)
dest = resolve_output(output)
if not os.path.isfile(image):
    fail(f"image not found: {image}")
if descriptor is not None:
    try:
        offset = descriptor_offset(descriptor, given_offset)
    except DescriptorError as exc:
        fail(str(exc))
else:
    offset = on_stdout(_resolve_offset, image, given_offset)
# A directory's inode gives icat its index, not a file: an agent extracted
# Edge's History directory (d/d 84284) as "EdgeHistory.db", 272 bytes of
# $INDEX_ROOT, and read "file is not a database" from it. Said here when the
# catalogue lists the inode only as a directory and no attribute was named.
listed = _catalogued(image, offset, inode)
if listed and "-" not in str(inode) and all(e["type"] == "d" for e in listed):
    fail("inode %s is a directory, not a file: icat would give its index" % inode, path=listed[0]["path"],
         hint="take the file's own inode from the catalogue's filelist.txt, or name an attribute (inode-type-id)")

if os.path.lexists(output) or dest.exists() or dest.is_symlink():
    fail("output already exists; an extract never replaces a file: choose a new path", output=output)

cmd = ["icat"] + (["-b", str(sector_size)] if sector_size else []) + ["-o", str(offset)] + images + [str(inode)]
if not shutil.which("icat"):
    fail("icat is not on PATH", install="brew install sleuthkit, or apt-get install -y sleuthkit")
try:
    dest.parent.mkdir(parents=True, exist_ok=True)
except OSError as exc:
    fail("the output directory cannot be made: %s" % (exc.strerror or exc), output=output)
try:
    for _image in images:
        open_regular(_image).close()      # the image was checked a moment ago: a FIFO or device put in its place is refused, not handed to icat
except (OSError, ValueError) as exc:
    fail("the image is not a regular file that can be read: %s" % (getattr(exc, "strerror", None) or exc.__class__.__name__), image=image)
# The name it will have if it is whole; what is written goes to a name of its own until then.
part = dest.with_name(dest.name + ".partial")
n = 1
while part.exists() or part.is_symlink():
    n += 1
    part = dest.with_name("%s.partial.%d" % (dest.name, n))
# icat's stderr goes to a file made new, whatever else is there (O_EXCL: no other file is opened over or through).
err_path, err_fd, k = None, None, 0
while err_fd is None:
    k += 1
    err_path = dest.with_name(dest.name + ".icat.stderr" + ("" if k == 1 else ".%d" % k))
    try:
        err_fd = os.open(str(err_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    except FileExistsError:
        continue
    except OSError as exc:
        fail("icat's stderr file could not be created: %s" % (exc.strerror or exc), output=output)
digest = hashlib.sha256()
size = 0
status, why = "complete", None
started = time.monotonic()
try:
    out_fd = os.open(str(part), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
except OSError as exc:
    os.close(err_fd)
    os.unlink(err_path)
    fail("the output could not be created: %s" % (exc.strerror or exc), output=output)
def _stopped(signum):
    proc = RUN["proc"]
    if proc is not None:
        try:
            proc.kill()
            proc.wait(timeout=5)
        except Exception:  # noqa: BLE001 - best effort
            pass
    print(json.dumps({"tool": TOOL, "status": "partial", "interrupted": True, "signal": signum, "image": image, "inode": str(inode), "offset": offset,
                      "bytes_written": RUN["size"], "path": output + part.name[len(dest.name):], "stderr_file": output + err_path.name[len(dest.name):],
                      "status_basis": "the tool was stopped by signal %d: icat was ended, and what had been written is kept under its partial name (its size and sha256 are not claimed)" % signum}), flush=True)


install_signal_handlers(_stopped)
with os.fdopen(out_fd, "wb") as out, os.fdopen(err_fd, "wb") as errf:
    # A stop that arrives between the child's start and its being recorded would leave icat running: the stop signals are held back for
    # these two statements and delivered right after, when the handler can end the child by its pid. (A stop before this point finds no
    # child: it answers, and the empty .partial and .icat.stderr files that were made new are named in the answer.)
    _stops = {signal.SIGTERM, signal.SIGINT, signal.SIGHUP}
    signal.pthread_sigmask(signal.SIG_BLOCK, _stops)
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=errf)
        RUN["proc"] = proc
    finally:
        signal.pthread_sigmask(signal.SIG_UNBLOCK, _stops)
    pipe = proc.stdout.fileno()
    try:
        while True:
            # Waited for with the clock running: an icat that stalls (a damaged image, a stuck read) is stopped at the
            # budget, not waited on for ever behind a read that returns nothing.
            left = max_seconds - (time.monotonic() - started)
            if left <= 0 or not select.select([pipe], [], [], min(left, 5))[0]:
                if time.monotonic() - started > max_seconds:
                    status, why = "partial", "the time budget of %d seconds was reached; icat was stopped" % max_seconds
                    break
                continue
            block = os.read(pipe, BLOCK)
            if not block:
                break
            room = max_bytes - size
            if len(block) > room:
                block = block[:room]
                out.write(block)
                digest.update(block)
                size += len(block)
                RUN["size"] = size
                status, why = "partial", "the output budget of %d bytes was reached; icat was stopped, and the rest of the stream was not read" % max_bytes
                break
            out.write(block)
            digest.update(block)
            size += len(block)
            RUN["size"] = size
            if time.monotonic() - started > max_seconds:
                status, why = "partial", "the time budget of %d seconds was reached; icat was stopped" % max_seconds
                break
    except OSError as exc:
        status, why = "partial", "the write failed after %d bytes: %s" % (size, exc.strerror or exc)
    finally:
        if status != "complete":
            proc.kill()
        proc.stdout.close()
        rc = proc.wait()
if status == "complete" and rc != 0:
    status, why = "partial", "icat exited %d after %d bytes" % (rc, size)
if os.path.getsize(err_path) == 0:
    os.unlink(err_path)
    err_path = None
err = ""
if err_path:
    with open(err_path, "r", encoding="utf-8", errors="replace") as fh:
        err = fh.read(4000).strip()
stream_whole = status == "complete"
if status == "complete":
    # Whole: it takes its own name, and never over a file that appeared there while icat ran (a link fails where the name
    # is taken; a file system with no links gets a rename after a look).
    try:
        os.link(part, dest)
        os.unlink(part)
    except FileExistsError:
        status, why = "partial", "%s appeared while icat was running, and an extract never replaces a file; the whole stream is kept as %s" % (output, os.path.basename(part))
    except OSError:
        if os.path.lexists(dest):
            status, why = "partial", "%s appeared while icat was running, and an extract never replaces a file; the whole stream is kept as %s" % (output, os.path.basename(part))
        else:
            os.rename(part, dest)
    shown = output if status == "complete" else output + part.name[len(dest.name):]
else:
    if size == 0:
        os.unlink(part)
        fail(err or "icat exit %s" % rc, image=image, inode=inode, offset=offset, sector_size=sector_size, icat_exit=rc, command=" ".join(cmd))
    # The partial sits beside the name it would have had: said under the name the caller gave, with its suffix.
    shown = output + part.name[len(dest.name):]
files = [e for e in listed if e["type"] != "d"]
catalogued = (next((e for e in files if not e["deleted"]), None) or (files or [None])[0] or {}).get("path")
result = {"tool": TOOL, "path": shown, "size": size, "sha256": digest.hexdigest(), "image": image, "offset": offset,
          "sector_size": sector_size, "inode": str(inode), "status": status,
          "status_basis": ("icat exited 0 and the whole stream was written" if status == "complete" else
                           "icat did not exit 0 or the stream was not all written: what was written is kept under its partial name (see problem)"), "icat_exit": rc, "command": " ".join(cmd),
          "catalog_path": catalogued, "catalog_paths": [{"address": e["address"], "path": e["path"], "deleted": e["deleted"]} for e in files]}
if why and stream_whole:
    result["problem"] = why
    result["note"] = "the whole stream was written, and is kept as %s: size and sha256 are of it" % shown
elif why:
    result["problem"] = why
    result["note"] = "what was written is kept as %s and is not the whole stream: size and sha256 are of those bytes alone" % shown
if err_path:
    result["stderr_file"] = output + err_path.name[len(dest.name):]
    result["stderr_head"] = err[:400]
if descriptor is not None:
    result["descriptor"] = {"file": descriptor["file"], "sha256": descriptor["sha256"], "layer": descriptor["layer"], "sources_checked": descriptor["checked"]}
    result["images"] = len(images)
print_answer(result)
sys.exit(0 if status == "complete" else 1)
