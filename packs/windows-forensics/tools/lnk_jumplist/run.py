#!/usr/bin/env python3
"""Read shell links and jump lists as one set of rows: where each structure sits, what it decodes to, and whether it holds together.

An adapter, not a new decoder. A shell link is decoded by this pack's lnk_parse, the DestList stream of a jump list by this
pack's jumplist, and a link can be read again by liblnk's `lnkinfo` as an independent reader; what this tool adds is the part
those two do not do: it reads the OLE compound file a jump list is stored in (MS-CFB, with the standard library only, so olefile
is not needed) and says where every stream sits in the file, whether the container is consistent, which DestList entry names
which stream, and which entries have no stream and which streams no entry. The rows are JSON Lines, the whole of them kept in a
file the answer names.

Inputs: a shell link (.lnk), an automaticDestinations-ms (a compound file with a DestList stream and a link in each other
stream), a customDestinations-ms (no container: link structures one after another, carved by their 20-byte header, each marked
carved and the container not parsed), or a directory of them (walked, links not followed; a file of another kind is counted,
not read). A file is classified by its first bytes, not its name, when it is named as the path; in a directory by its name.

Rows (`row`): file, container, stream, destlist_entry, link. Every offset of a link's own record (a string's offset, a block's
place) is from the start of that link structure; `container` / `file_offset` and `extents` say where the structure sits in the file.
Each link row has `integrity`: structure_complete, lnk_parse's problems, and what `lnkinfo` says (time, size, volume, target and
label compared field by field, or why it was not run). status is complete only when no row is incomplete, no container problem is
named, no independent read disagrees, nothing was left unread, and the tool's own clock did not run out.

SENSITIVE OUTPUT. A link's arguments, its strings, and the text of a path-like field with the shape of a secret are handled as
lnk_parse handles them: not in the answer; `write_strings: true`, in a job run as secret output, writes them to a file with
mode 0600 under a finding id the rows cite. Refused anywhere else, before anything is made.
"""
import hashlib
import importlib.util
import json
import os
import re
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

PARSER = "lnk_jumplist/1"
LNK_MAGIC = bytes.fromhex("4c0000000114020000000000c000000000000046")
OLE_MAGIC = bytes.fromhex("d0cf11e0a1b11ae1")
MAX_LNK_BYTES = 64 << 20          # a link past this is not read whole: it is named and not parsed
MAX_STREAM_BYTES = 32 << 20       # the most of one container stream that is read (the same bound jumplist uses)
MAX_DESTLIST_BYTES = 64 << 20
MAX_DIR_ENTRIES = 100_000
MAX_EXTENTS_SHOWN = 32
DEFAULT_SECONDS = 100
MAX_SECONDS = 110
DEFAULT_FILES = 20_000
LNKINFO_MAX = 400                 # links read again by lnkinfo in one run
BLOCK = 1 << 20

# Lossless paging (the same in every library tool that pages): the page an
# agent reads stays small, and when there are more rows the whole result is
# written as JSON Lines under work/<agent>/tool-output and named.
import hashlib


class LosslessPage:
    def __init__(self, tool: str, key: object, limit: int):
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ValueError("limit must be a positive integer")
        self.tool = re.sub(r"[^A-Za-z0-9_.-]", "_", tool)
        self.limit = limit
        self.page: list[object] = []
        self.total = 0
        self._out = None
        self._tmp: Path | None = None
        digest = hashlib.sha256(
            json.dumps(key, sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()[:16]
        name = f"{self.tool}-{digest}.jsonl"
        job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
        if job and out:
            # In a job only $OUT is written, and it is sealed as the job's
            # output: the whole result is cited from there.
            self.path = Path(out) / "tool-output" / name
            self.shown = "store/jobs/%s/out/tool-output/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", job), name)
        else:
            agent = re.sub(
                r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool"
            )
            self.path = Path("work") / agent / "tool-output" / name
            self.shown = str(self.path)

    def _cannot_write(self, exc: BaseException) -> None:
        """The whole result cannot be kept: say so as JSON and stop, never a traceback."""
        import sys as _sys
        _sys.stdout.write(json.dumps({
            "error": "the whole result (%d rows so far) cannot be written to %s: %s. Outside a job the place is your own "
                     "work/<your id>/ directory; in a job it is $OUT." % (self.total, self.shown, exc),
            "status": "failed",
        }) + "\n")
        _sys.exit(1)

    def _write(self, row: object) -> None:
        assert self._out is not None
        text = json.dumps(row, ensure_ascii=False, default=str)
        try:
            text.encode("utf-8")
        except UnicodeEncodeError:
            # A lone surrogate (a file name that is not UTF-8): escape it, lose nothing.
            text = json.dumps(row, ensure_ascii=True, default=str)
        try:
            self._out.write(text)
            self._out.write("\n")
        except OSError as exc:
            self._cannot_write(exc)

    def add(self, row: object) -> None:
        self.total += 1
        if len(self.page) < self.limit:
            self.page.append(row)
            return
        if self._out is None:
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                fd, name = tempfile.mkstemp(
                    dir=self.path.parent, prefix=f".{self.path.name}-"
                )
                self._tmp = Path(name)
                self._out = os.fdopen(fd, "w", encoding="utf-8")
            except OSError as exc:
                self._cannot_write(exc)
            for kept in self.page:
                self._write(kept)
        self._write(row)

    def finish(self) -> dict:
        result = {
            "matched": self.total,
            "returned": len(self.page),
            "truncated": self.total > len(self.page),
        }
        if self._out is not None:
            try:
                self._out.flush()
                os.fsync(self._out.fileno())
                self._out.close()
                assert self._tmp is not None
                os.replace(self._tmp, self.path)
            except OSError as exc:
                self._cannot_write(exc)
            result["all_results"] = self.shown
            result["all_results_format"] = "JSON Lines, one complete result per line"
        return result

# BEGIN SHARED PLACE
# The same text is in every windows-forensics tool that keeps a result file (a windows-forensics test holds the copies equal).
# A result file that is there is never replaced by another result: a file of the same bytes is named again, any other result takes the next free
# <stem>-<n><suffix>. The name is taken first, with an exclusive create, so a result written at the same moment cannot be replaced either.
def same_bytes(a, b):
    """Whether two files hold the same bytes (read in blocks, never whole)."""
    try:
        if os.path.getsize(a) != os.path.getsize(b):
            return False
        with open(a, "rb") as fa, open(b, "rb") as fb:
            while True:
                x, y = fa.read(1 << 20), fb.read(1 << 20)
                if x != y:
                    return False
                if not x:
                    return True
    except OSError:
        return False


def place_without_replacing(tmp, path):
    """Move the finished `tmp` to `path` and never replace what is there. The name is taken first, with an exclusive create, so a
    result written at the same moment cannot be replaced either. Returns the path that holds it."""
    for n in range(1, 1000):
        candidate = path if n == 1 else path.with_name("%s-%d%s" % (path.stem, n, path.suffix))
        try:
            fd = os.open(str(candidate), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileExistsError:
            if not os.path.islink(candidate) and same_bytes(tmp, candidate):
                os.unlink(tmp)
                return candidate
            continue
        os.close(fd)
        os.replace(tmp, candidate)             # only replaces the empty file this call just made
        return candidate
    raise OSError("no free name beside %s" % path)
# END SHARED PLACE


# BEGIN SHARED PAGE
# The same text is in every windows-forensics tool that pages through LosslessPage (held equal by a windows-forensics test): LosslessPage replaces a file of the
# same name; this one places its finished file with place_without_replacing, and registers itself so that a stop can remove its temporary file.
PAGES = []


class NoReplacePage(LosslessPage):
    """LosslessPage whose finished file is placed without replacing an earlier file of the same name (a rerun with other limits, or one
    the time limit stopped, must not leave a smaller file where a larger one was)."""

    def __init__(self, tool, key, limit):
        super().__init__(tool, key, limit)
        PAGES.append(self)

    def finish(self) -> dict:
        result = {"matched": self.total, "returned": len(self.page), "truncated": self.total > len(self.page)}
        if self._out is not None:
            try:
                self._out.flush()
                os.fsync(self._out.fileno())
                self._out.close()
                assert self._tmp is not None
                placed = place_without_replacing(self._tmp, self.path)
            except OSError as exc:
                self._cannot_write(exc)
            self._tmp = None
            self.path = placed
            self.shown = self.shown[: len(self.shown) - len(Path(self.shown).name)] + placed.name
            result["all_results"] = self.shown
            result["all_results_format"] = "JSON Lines, one complete result per line"
        return result
# END SHARED PAGE


# BEGIN SHARED PROCESS
# The same text is in esedb_query, extract_stream, sigma_hunt, vss_stores and yara_scan; tests/pack-windows-forensics-process.test.ts
# holds the copies equal. A program a tool runs is started in THIS tool's process group, never in a session of its own: the
# harness ends a tool that runs too long, or is aborted, by killing the tool's group (process.kill(-pid, SIGKILL)), and a
# program in a group of its own goes on writing after the tool is gone. On Linux the kernel is also asked to kill it if the
# tool dies. The tool's own deadline kills the program and what it started by walking the process tree, and SIGTERM, SIGINT
# and SIGHUP do the same and then give the tool a last word. Only what is
# below a program this tool started and has not yet waited for is ever signalled: the walk starts at that program's pid
# and nowhere else, and a program that has been waited for (its pid may be another process's by now) is left alone. The
# walk has no bound but the number of processes. Two cases leave the tree running: a ps that needs more than PS_WAIT
# seconds, and a sandbox that denies both libproc and ps (macOS).
try:
    import ctypes
except ImportError:  # pragma: no cover
    ctypes = None

STATE = {"last_word": None}    # what to do, with the signal number, when the tool is stopped by a signal
ACTIVE = []                    # the programs running now


def _die_with_parent():  # runs in the child between fork and exec
    try:
        ctypes.CDLL(None).prctl(1, signal.SIGKILL)   # PR_SET_PDEATHSIG
    except Exception:  # noqa: BLE001
        pass


def spawn(argv, **kwargs):
    kwargs.setdefault("stdin", subprocess.DEVNULL)
    if sys.platform.startswith("linux") and ctypes is not None:
        kwargs["preexec_fn"] = _die_with_parent
    return subprocess.Popen(argv, **kwargs)


def _children_libproc(pid):
    """The direct children of `pid` on macOS, from libproc (macOS only: proc_listchildpids is not a symbol of the other
    BSDs; a library call, so no program is started and nothing can be slow); None when the library, the symbol or the
    call is not there."""
    try:
        import ctypes.util
        lib = ctypes.CDLL(ctypes.util.find_library("proc") or "/usr/lib/libproc.dylib", use_errno=True)
        lib.proc_listchildpids.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int]
        lib.proc_listchildpids.restype = ctypes.c_int
        size = 256
        while size <= 1 << 16:
            buf = (ctypes.c_int * size)()
            if lib.proc_listchildpids(pid, buf, ctypes.sizeof(buf)) < 0:
                return None
            found = []
            for value in buf:
                if value <= 0:
                    break
                found.append(int(value))
            if len(found) < size:
                return found
            size *= 4
        return found
    except Exception:  # noqa: BLE001 - no library, no symbol: the caller falls back
        return None


PS_WAIT = 10    # seconds the ps fallback is given: ps is slow on a heavily loaded host, and a tree that is not found is a program left running


def _below(kids, pid):
    found, seen, stack = [], {pid}, [pid]
    while stack:
        for child in kids.get(stack.pop(), []):
            if child not in seen:
                seen.add(child)
                found.append(child)
                stack.append(child)
    return found


def descendants(pid):
    """Every process below `pid` (never one beside it): from /proc where there is one, else from libproc, else from ps
    (given PS_WAIT seconds). libproc is believed when it lists a child; an empty answer is believed only when libproc has
    just listed this tool's own child `pid` (a library that answers nothing for a live child is not working, as in a
    sandbox that denies it), and otherwise ps is asked."""
    kids = {}
    try:
        if os.path.isdir("/proc/self"):
            for entry in os.listdir("/proc"):
                if entry.isdigit():
                    try:
                        with open("/proc/%s/stat" % entry, "rb") as fh:
                            fields = fh.read().rsplit(b")", 1)[1].split()
                        kids.setdefault(int(fields[1]), []).append(int(entry))
                    except (OSError, IndexError, ValueError):
                        continue
        else:
            first = _children_libproc(pid)
            if first:
                found, seen, stack = list(first), {pid, *first}, list(first)
                while stack:
                    for child in _children_libproc(stack.pop()) or []:
                        if child not in seen:
                            seen.add(child)
                            found.append(child)
                            stack.append(child)
                return found
            if first is not None and pid in (_children_libproc(os.getpid()) or []):
                return []
            out = subprocess.run(["ps", "-A", "-o", "pid=,ppid="], capture_output=True, text=True, timeout=PS_WAIT).stdout
            for line in out.splitlines():
                parts = line.split()
                if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
                    kids.setdefault(int(parts[1]), []).append(int(parts[0]))
    except (OSError, subprocess.SubprocessError):
        return []
    return _below(kids, pid)


def kill_tree(proc):
    """Kill the program and everything it started. The children are listed first: once the parent is gone they are
    adopted by init and can no longer be found below it. A program already waited for is not touched: its pid is free to
    be another process's, and the walk below it would be that process's children."""
    if proc.poll() is not None:
        return
    victims = descendants(proc.pid)
    try:
        proc.kill()
    except OSError:
        pass
    for pid in victims:
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass


def wait_for(proc, seconds):
    """(exit code, timed out): wait for the program for at most `seconds`; at the deadline it and what it started are killed."""
    ACTIVE.append(proc)
    try:
        try:
            return proc.wait(timeout=seconds), False
        except subprocess.TimeoutExpired:
            kill_tree(proc)
            return proc.wait(), True
    finally:
        if proc in ACTIVE:
            ACTIVE.remove(proc)


def _on_signal(signum, _frame):
    for proc in list(ACTIVE):
        kill_tree(proc)
    last_word = STATE.get("last_word")
    if last_word:
        try:
            last_word(signum)
        except Exception:  # noqa: BLE001 - a last word is best effort
            pass
    os._exit(128 + signum)


def install_signal_handlers():
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, _on_signal)
# END SHARED PROCESS


# ---- helpers ------------------------------------------------------------------------------------------------------------------------

def fail(message, **extra):
    print(json.dumps({"ok": False, "error": message, "status": "failed", "status_basis": "the tool stopped with an error (see error); nothing was read", **extra}))
    sys.exit(1)


def describe(exc):
    if isinstance(exc, OSError):
        return "%s: %s" % (type(exc).__name__, exc.strerror or exc)
    return "%s: %s" % (type(exc).__name__, exc)


CLOCK = {"deadline": None}
TEMPS = []


def out_of_time():
    return CLOCK["deadline"] is not None and time.monotonic() > CLOCK["deadline"]


def forget_temps():
    for page in list(PAGES):
        tmp = getattr(page, "_tmp", None)
        if tmp is not None:
            try:
                os.unlink(tmp)
            except OSError:
                pass
    for path in list(TEMPS):
        try:
            os.unlink(path)
        except OSError:
            pass
        TEMPS.remove(path)


def shown_path(path):
    job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
    path = Path(path)
    if job and out:
        try:
            return "store/jobs/%s/out/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", job), path.resolve().relative_to(Path(out).resolve()))
        except ValueError:
            return str(path)
    try:
        return str(path.resolve().relative_to(Path.cwd().resolve()))
    except ValueError:
        return str(path)


def output_directory(identity):
    job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
    name = "lnk_jumplist-" + identity
    if job and out:
        base = Path(out)
    else:
        agent = re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool")
        base = Path.cwd() / "work" / agent
    return base / name


class FilePage(NoReplacePage):
    """A paging file placed in the tool's own output directory under a fixed name, never replacing an earlier file."""

    def __init__(self, directory, name, key, limit):
        super().__init__("lnk_jumplist", key, limit)
        self.path = directory / name
        self.shown = shown_path(self.path)

    def finish(self):
        if self._out is None and self.total:
            # the whole result is always a file the answer names, even when it fits in the inline page
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                fd, name = tempfile.mkstemp(dir=self.path.parent, prefix=".%s-" % self.path.name)
                self._tmp = Path(name)
                self._out = os.fdopen(fd, "w", encoding="utf-8")
            except OSError as exc:
                self._cannot_write(exc)
            for kept in self.page:
                self._write(kept)
        result = super().finish()
        if result.get("all_results"):
            result["all_results"] = shown_path(self.path)
        return result


def load_sibling(name):
    """This pack's own tool, loaded as a module so that its decoder is used in this process: the pack is read-only code, installed beside this tool."""
    path = Path(__file__).resolve().parent.parent / name / "run.py"
    spec = importlib.util.spec_from_file_location("dfir_windows_" + name, str(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def ft_iso(value):
    if not value:
        return None
    try:
        import datetime
        whole, ticks = divmod(int(value), 10_000_000)
        return (datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(seconds=whole)).strftime("%Y-%m-%dT%H:%M:%S") + ".%07dZ" % ticks
    except (OverflowError, ValueError, TypeError):
        return None


# ---- the compound file (MS-CFB), with the standard library -------------------------------------------------------------------------

FREESECT, ENDOFCHAIN, FATSECT, DIFSECT = 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFD, 0xFFFFFFFC
NOSTREAM = 0xFFFFFFFF


class CfbError(Exception):
    pass


class Cfb:
    """The directory and sector chains of a compound file, read in sectors (never the file whole). `problems` collects what is inconsistent;
    a header that is not a compound file's raises CfbError."""

    def __init__(self, fh, size):
        self.fh, self.size, self.problems = fh, size, []
        head = self._read(0, 512)
        if len(head) < 512 or head[:8] != OLE_MAGIC:
            raise CfbError("not a compound file: the 8-byte signature is missing")
        major, = struct.unpack_from("<H", head, 0x1A)
        order, shift, mshift = struct.unpack_from("<HHH", head, 0x1C)
        if order != 0xFFFE:
            raise CfbError("the byte order mark is 0x%04x, not 0xFFFE" % order)
        if (major, shift) not in ((3, 9), (4, 12)) or mshift != 6:
            raise CfbError("major version %d with sector shift %d and mini sector shift %d is not a layout this reader knows (3/9/6 or 4/12/6)" % (major, shift, mshift))
        self.major, self.ss, self.mini_ss = major, 1 << shift, 64
        (self.n_fat, self.dir_start, _txn, self.cutoff, self.minifat_start, self.n_minifat, self.difat_start, self.n_difat) = struct.unpack_from("<IIIIIIII", head, 0x2C)
        self.sectors = max(-(-(size - self.ss) // self.ss), 0)       # the header takes the first sector-sized slot
        if size % self.ss:
            self.problems.append("the file is %d bytes, not a whole number of %d-byte sectors (the last sector is short)" % (size, self.ss))
        difat = list(struct.unpack_from("<109I", head, 0x4C))
        seen_difat, next_difat, left = set(), self.difat_start, self.n_difat
        while left > 0 and next_difat not in (ENDOFCHAIN, FREESECT):
            if next_difat in seen_difat or next_difat >= self.sectors:
                self.problems.append("the DIFAT chain %s (sector %d)" % ("loops" if next_difat in seen_difat else "leaves the file", next_difat))
                break
            seen_difat.add(next_difat)
            raw = self._sector(next_difat)
            per = self.ss // 4 - 1
            difat += list(struct.unpack_from("<%dI" % per, raw, 0))
            next_difat = struct.unpack_from("<I", raw, per * 4)[0]
            left -= 1
        fat_sectors = [s for s in difat if s != FREESECT][: self.n_fat]
        if len(fat_sectors) < self.n_fat:
            self.problems.append("the header declares %d FAT sectors and the DIFAT names %d" % (self.n_fat, len(fat_sectors)))
        self.fat = []
        for s in fat_sectors:
            if s >= self.sectors:
                self.problems.append("a FAT sector (%d) is outside the file" % s)
                continue
            self.fat += struct.unpack("<%dI" % (self.ss // 4), self._sector(s))
        self.owner = {}                                           # sector -> what holds it, to see two streams share one
        self.directory = self._directory()
        self.minifat = self._minifat()
        self.mini_container = None

    def _read(self, offset, length):
        self.fh.seek(offset)
        return self.fh.read(length)

    def _sector(self, n):
        return self._read(self.ss * (n + 1), self.ss).ljust(self.ss, b"\x00")

    def sector_offset(self, n):
        return self.ss * (n + 1)

    def chain(self, start, what, limit=None):
        """The sectors of a chain, and what is wrong with it: a loop, a sector outside the file or the FAT, an unallocated or FAT-marked link."""
        out, seen, n = [], set(), start
        cap = limit if limit is not None else len(self.fat) + 1
        while n not in (ENDOFCHAIN,) and len(out) <= cap:
            if n in (FREESECT, FATSECT, DIFSECT):
                self.problems.append("%s: its chain reaches a %s sector" % (what, {FREESECT: "free", FATSECT: "FAT", DIFSECT: "DIFAT"}[n]))
                break
            if n >= len(self.fat) or n >= self.sectors:
                self.problems.append("%s: its chain reaches sector %d, outside %s" % (what, n, "the FAT" if n >= len(self.fat) else "the file"))
                break
            if n in seen:
                self.problems.append("%s: its sector chain loops back to sector %d" % (what, n))
                break
            seen.add(n)
            out.append(n)
            n = self.fat[n]
        else:
            if n != ENDOFCHAIN:
                self.problems.append("%s: its sector chain is longer than the FAT" % what)
        return out

    def _directory(self):
        entries = []
        sectors = self.chain(self.dir_start, "the directory")
        for s in sectors:
            raw = self._sector(s)
            for i in range(self.ss // 128):
                if len(entries) >= MAX_DIR_ENTRIES:
                    self.problems.append("the directory holds more than %d entries; the rest are not read" % MAX_DIR_ENTRIES)
                    return entries
                rec = raw[i * 128:(i + 1) * 128]
                nlen = struct.unpack_from("<H", rec, 64)[0]
                kind = rec[66]
                name = rec[: max(min(nlen, 64) - 2, 0)].decode("utf-16-le", "replace") if kind else ""
                left, right, child = struct.unpack_from("<III", rec, 68)
                start = struct.unpack_from("<I", rec, 116)[0]
                size = struct.unpack_from("<Q", rec, 120)[0]
                if self.major == 3:
                    size &= 0xFFFFFFFF
                entries.append({"id": len(entries), "name": name, "type": kind, "left": left, "right": right, "child": child, "start": start, "size": size})
        return entries

    def _minifat(self):
        if self.minifat_start in (ENDOFCHAIN, FREESECT) or not self.n_minifat:
            return []
        out = []
        for s in self.chain(self.minifat_start, "the mini FAT"):
            out += struct.unpack("<%dI" % (self.ss // 4), self._sector(s))
        return out

    def streams(self):
        """Every stream entry reached from the root by the red-black tree, with its path; a loop in the tree is a problem."""
        if not self.directory or self.directory[0]["type"] != 5:
            self.problems.append("the first directory entry is not the root storage")
            return []
        found, seen, stack = [], set(), [(self.directory[0]["child"], "")]
        while stack:
            sid, prefix = stack.pop()
            if sid == NOSTREAM:
                continue
            if sid >= len(self.directory) or sid in seen:
                self.problems.append("the directory tree %s (entry %d)" % ("loops" if sid in seen else "names an entry outside the directory", sid))
                continue
            seen.add(sid)
            e = self.directory[sid]
            stack.append((e["left"], prefix))
            stack.append((e["right"], prefix))
            path = prefix + e["name"]
            if e["type"] == 2:
                found.append({**e, "path": path})
            elif e["type"] == 1:
                stack.append((e["child"], path + "/"))
        names = [s["path"].lower() for s in found]
        if len(set(names)) != len(names):
            self.problems.append("two streams have the same name")
        return sorted(found, key=lambda s: s["id"])

    def _container_chain(self):
        if self.mini_container is None:
            root = self.directory[0] if self.directory else None
            self.mini_container = self.chain(root["start"], "the mini stream") if root and root["start"] not in (ENDOFCHAIN, FREESECT) and root["size"] else []
        return self.mini_container

    def extents(self, entry):
        """[(stream offset, file offset, length)] of a stream, joined where the sectors are neighbours, and whether the chain is whole."""
        size = entry["size"]
        label = "stream %r" % entry["name"]
        pieces, whole = [], True
        if size == 0:
            return pieces, True
        if size < self.cutoff:
            container, mini = self._container_chain(), []
            n, seen = entry["start"], set()
            while n != ENDOFCHAIN and len(mini) <= len(self.minifat):
                if n >= len(self.minifat) or n in seen:
                    self.problems.append("%s: its mini sector chain %s" % (label, "loops" if n in seen else "leaves the mini FAT"))
                    break
                seen.add(n)
                mini.append(n)
                n = self.minifat[n]
            if len(mini) * self.mini_ss < size:
                self.problems.append("%s declares %d bytes and its mini chain holds %d" % (label, size, len(mini) * self.mini_ss))
                whole = False
            at = 0
            for m in mini:
                if at >= size:
                    break
                c, within = divmod(m * self.mini_ss, self.ss)
                if c >= len(container):
                    self.problems.append("%s: mini sector %d is past the end of the mini stream" % (label, m))
                    whole = False
                    break
                take = min(self.mini_ss, size - at)
                pieces.append((at, self.sector_offset(container[c]) + within, take))
                at += take
        else:
            sectors = self.chain(entry["start"], label, limit=(size + self.ss - 1) // self.ss + 1)
            for s in sectors:
                if self.owner.setdefault(s, label) != label:
                    self.problems.append("%s shares sector %d with %s" % (label, s, self.owner[s]))
            if len(sectors) * self.ss < size:
                self.problems.append("%s declares %d bytes and its chain holds %d" % (label, size, len(sectors) * self.ss))
                whole = False
            at = 0
            for s in sectors:
                if at >= size:
                    break
                take = min(self.ss, size - at)
                pieces.append((at, self.sector_offset(s), take))
                at += take
        joined = []
        for at, off, n in pieces:
            if joined and joined[-1][0] + joined[-1][2] == at and joined[-1][1] + joined[-1][2] == off:
                joined[-1] = (joined[-1][0], joined[-1][1], joined[-1][2] + n)
            else:
                joined.append((at, off, n))
        return joined, whole

    def read(self, extents, limit):
        data = bytearray()
        for _at, off, n in extents:
            if len(data) >= limit:
                break
            data += self._read(off, min(n, limit - len(data)))
        return bytes(data)


def map_range(extents, start, length):
    """Where [start, start + length) of a stream is in the file: [(file offset, bytes)], one piece when it is contiguous."""
    out, end = [], start + length
    for at, off, n in extents:
        lo, hi = max(at, start), min(at + n, end)
        if lo < hi:
            out.append((off + lo - at, hi - lo))
    return out


# ---- lnkinfo, the independent reader ---------------------------------------------------------------------------------------------------

MONTHS = {m: i + 1 for i, m in enumerate("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split())}
TIME_LINE = re.compile(r"^([A-Z][a-z]{2}) (\d{1,2}), (\d{4}) (\d\d):(\d\d):(\d\d)\.(\d{9}) UTC$")


def lnkinfo_fields(text):
    fields = {}
    for line in text.splitlines():
        m = re.match(r"^\t([A-Za-z][A-Za-z ]*?)\t+: (.*)$", line)
        if m and m.group(1) not in fields:
            fields[m.group(1)] = m.group(2).strip()
    return fields


def lnkinfo_time(value):
    m = TIME_LINE.match(value or "")
    if not m or m.group(1) not in MONTHS:
        return None
    return "%s-%02d-%02dT%s:%s:%s.%sZ" % (m.group(3), MONTHS[m.group(1)], int(m.group(2)), m.group(4), m.group(5), m.group(6), m.group(7)[:7])


def lnkinfo_run(path, seconds):
    import shutil
    program = shutil.which("lnkinfo")
    if not program:
        return None, "lnkinfo (liblnk-utils) is not in this image"
    try:
        proc = spawn([program, str(path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError as exc:
        return None, "lnkinfo could not be started: %s" % describe(exc)
    ACTIVE.append(proc)
    try:
        out, _err = proc.communicate(timeout=max(1.0, seconds))
    except subprocess.TimeoutExpired:
        kill_tree(proc)
        proc.communicate()
        return None, "lnkinfo did not answer in %d seconds" % max(1, int(seconds))
    finally:
        if proc in ACTIVE:
            ACTIVE.remove(proc)
    if proc.returncode != 0:
        return None, "lnkinfo exited %d (it could not read the structure)" % proc.returncode
    return lnkinfo_fields(out.decode("utf-8", "replace")), None


def compare_lnkinfo(decoded, info):
    """Field by field: what lnk_parse and lnkinfo both say, equal or not. A field one does not print is not compared."""
    checked, differ = [], []

    def same(name, mine, theirs):
        checked.append(name)
        if mine != theirs:
            differ.append({"field": name, "lnk_parse": mine, "lnkinfo": theirs})

    for field, label in (("created", "Creation time"), ("accessed", "Access time"), ("written", "Modification time")):
        theirs = info.get(label)
        if theirs is not None:
            same(field, decoded.get(field), lnkinfo_time(theirs) if not theirs.startswith("Not set") else None)
    if "File size" in info:
        m = re.match(r"(\d+) bytes", info["File size"])
        if m:
            same("file_length", decoded.get("file_length"), int(m.group(1)))
    volume = decoded.get("volume")
    if isinstance(volume, dict):
        if "Drive serial number" in info:
            same("volume.serial_number", str(volume.get("serial_number", "")).lower(), info["Drive serial number"].lower().replace("0x", ""))
        m = re.search(r"\((\d+)\)$", info.get("Drive type", ""))
        if m:
            same("volume.drive_type", volume.get("drive_type"), int(m.group(1)))
        if "Volume label" in info:
            same("volume.label", volume.get("label"), info["Volume label"])
    target = decoded.get("linkinfo_target")
    kind = decoded.get("linkinfo_target_kind")
    if target is not None and kind in ("local", "network"):
        theirs = info.get("Local path" if kind == "local" else "Network path")
        if theirs is not None:
            base = decoded.get("local_base_path") or ""
            suffix = decoded.get("common_path") or ""
            # liblnk puts a separator between the base path and the suffix where the link has none; the specification only joins them.
            ok = theirs == target or (kind == "local" and suffix and not base.endswith("\\") and theirs == base + "\\" + suffix)
            checked.append("target")
            if not ok:
                differ.append({"field": "target", "lnk_parse": target, "lnkinfo": theirs})
    return checked, differ


# ---- the rows ----------------------------------------------------------------------------------------------------------------------------

class Run:
    def __init__(self, directory, limit, write_strings, started):
        self.dir, self.limit, self.started = directory, limit, started
        self.rows = FilePage(directory, "rows.jsonl", [str(directory), "rows"], limit)
        self.strings = FilePage(directory, "strings.jsonl", [str(directory), "strings"], limit)
        self.counts = {"files": 0, "containers": 0, "streams": 0, "destlist_entries": 0, "links": 0}
        self.integrity = {"ok": 0, "incomplete": 0, "disagrees": 0, "unreadable": 0}
        self.container_problems = 0
        self.not_attempted = []
        self.lnkinfo = {"checked": 0, "agreed": 0, "disagreed": 0, "not_run": 0, "why_not_run": {}}
        self.unread = 0
        self.lnk = load_sibling("lnk_parse")
        self.jumplist = load_sibling("jumplist")
        values = None
        for n in range(1, 1000):
            name = "strings-values.jsonl" if n == 1 else "strings-values-%d.jsonl" % n
            try:
                values = self.lnk.SecretValues(write_strings, "lnk_jumplist", "write_strings", "lnk_jumplist-" + name)
                break
            except self.lnk.SecretValuesRefused as exc:
                if write_strings and "already exists" in str(exc):
                    continue
                raise ValueError(str(exc))
        self.values = values
        self.held = self.lnk.Held(values)
        self.string_sink = _StringSink(self.strings)
        self.stopped = False

    def add(self, row):
        self.rows.add(row)

    def finish(self):
        self.values.close()
        return self.rows.finish(), self.strings.finish()


class _StringSink:
    def __init__(self, page):
        self.page = page
        self.context = {}

    def add(self, row):
        self.page.add({**self.context, **row})


def link_row(run, data, base_off, where):
    """Decode one link structure with lnk_parse and put the result in a row; `where` holds the source, stream, container extents."""
    run.string_sink.context = {"source": where["source"], "stream": where.get("stream")}
    decoded = run.lnk.parse_lnk(data, base_off, run.held, run.string_sink)
    row = {"row": "link", **where, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    if not decoded.get("ok"):
        row["integrity"] = {"status": "unreadable", "problems": [decoded.get("error", "not a link structure")]}
        row["decoded"] = None
        return row, decoded
    row["header"] = {k: decoded.get(k) for k in ("flags_hex", "file_attr", "created", "created_filetime", "accessed", "accessed_filetime", "written", "written_filetime", "file_length", "show_cmd")}
    row["target"] = {"kind": decoded.get("linkinfo_target_kind"), "path": decoded.get("linkinfo_target"), "volume": decoded.get("volume"), "network": decoded.get("network")}
    row["strings"] = {k: decoded.get(k) for k in ("name", "relative_path", "working_dir", "icon_location", "arguments_present", "arguments_chars", "arguments_first_token") if k in decoded}
    row["tracker"] = [{"machine": b.get("machine"), "droid_hex": b.get("droid_hex"), "droid_birth_hex": b.get("droid_birth_hex")} for b in decoded.get("extra", []) if b.get("sig") == "0xa0000003"]
    integrity = {"structure_complete": decoded.get("structure_complete"), "problems": decoded.get("problems", [])}
    integrity["status"] = "ok" if decoded.get("structure_complete") and not decoded.get("problems") else "incomplete"
    row["integrity"] = integrity
    row["decoded"] = decoded
    return row, decoded


def cross_check(run, row, decoded, source_path, data):
    """Read the structure again with lnkinfo, within the run's budget, and compare."""
    info = row["integrity"]
    if run.lnkinfo["checked"] >= LNKINFO_MAX:
        run.lnkinfo["not_run"] += 1
        run.lnkinfo["why_not_run"]["budget"] = run.lnkinfo["why_not_run"].get("budget", 0) + 1
        info["lnkinfo"] = {"ran": False, "why": "more than %d links in this run: the independent read is made for the first %d" % (LNKINFO_MAX, LNKINFO_MAX)}
        return
    path, temp = source_path, None
    if path is None:
        fd, temp = tempfile.mkstemp(dir=run.dir, prefix=".xcheck-", suffix=".lnk")
        TEMPS.append(temp)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        path = temp
    try:
        fields, why = lnkinfo_run(path, min(20.0, max(2.0, CLOCK["deadline"] - time.monotonic() - 1)))
    finally:
        if temp:
            try:
                os.unlink(temp)
                TEMPS.remove(temp)
            except (OSError, ValueError):
                pass
    if fields is None:
        run.lnkinfo["not_run"] += 1
        key = why.split(" (")[0][:60]
        run.lnkinfo["why_not_run"][key] = run.lnkinfo["why_not_run"].get(key, 0) + 1
        info["lnkinfo"] = {"ran": False, "why": why}
        return
    checked, differ = compare_lnkinfo(decoded, fields)
    run.lnkinfo["checked"] += 1
    info["lnkinfo"] = {"ran": True, "compared": checked, "agrees": not differ, **({"differences": differ} if differ else {})}
    if differ:
        run.lnkinfo["disagreed"] += 1
        if info["status"] == "ok":
            info["status"] = "disagrees"
    else:
        run.lnkinfo["agreed"] += 1


def finish_link(run, row, decoded, source_path, data):
    if row["integrity"]["status"] != "unreadable":
        cross_check(run, row, decoded, source_path, data)
    run.integrity[row["integrity"]["status"]] += 1
    run.counts["links"] += 1
    run.add(row)


def read_lnk_file(run, path, size):
    if size > MAX_LNK_BYTES:
        run.unread += 1
        run.add({"row": "file", "path": path, "kind": "lnk", "bytes": size, "status": "failed", "problems": ["the file is %d bytes, over the %d this tool reads whole; it was not parsed" % (size, MAX_LNK_BYTES)]})
        return
    with open(path, "rb") as fh:
        data = fh.read(MAX_LNK_BYTES + 1)
    run.add({"row": "file", "path": path, "kind": "lnk", "bytes": size, "sha256": hashlib.sha256(data).hexdigest(), "status": "read"})
    row, decoded = link_row(run, data, 0, {"source": path, "container": "file", "stream": None, "file_offset": 0, "extents": [{"stream_offset": 0, "file_offset": 0, "bytes": len(data)}]})
    finish_link(run, row, decoded, path, data)


def read_custom(run, path, size):
    jl = run.jumplist
    run.add({"row": "file", "path": path, "kind": "customDestinations-ms", "bytes": size, "status": "read",
             "method": "carved: the file is split at every 20-byte link header; its own container structure is not parsed"})
    with open(path, "rb") as fh:
        starts = jl.lnk_starts(fh, size)
        if not starts:
            run.add({"row": "file", "path": path, "kind": "customDestinations-ms", "status": "partial", "problems": ["no link structure header was found in this file"]})
            run.container_problems += 1
            return
        for i, offset in enumerate(starts):
            if out_of_time():
                run.stopped = True
                return
            length = (starts[i + 1] if i + 1 < len(starts) else size) - offset
            fh.seek(offset)
            data = fh.read(min(length, MAX_LNK_BYTES))
            row, decoded = link_row(run, data, offset, {"source": path, "container": "customDestinations-ms", "stream": None, "carved": True, "index": i,
                                                          "file_offset": offset, "extents": [{"stream_offset": 0, "file_offset": offset, "bytes": length}]})
            if length > MAX_LNK_BYTES:
                row["integrity"].setdefault("problems", []).append("the carved span is %d bytes; the first %d were parsed" % (length, MAX_LNK_BYTES))
                row["integrity"]["status"] = "incomplete"
            finish_link(run, row, decoded, None, data)


def read_automatic(run, path, size):
    with open(path, "rb") as fh:
        try:
            cfb = Cfb(fh, size)
        except CfbError as exc:
            run.unread += 1
            run.add({"row": "file", "path": path, "kind": "compound file", "bytes": size, "status": "failed", "problems": [str(exc)]})
            return
        streams = cfb.streams()
        shown = []
        for s in streams:
            extents, whole = cfb.extents(s)
            shown.append((s, extents, whole))
        container_problems = list(cfb.problems)
        has_destlist = any(s["path"] == "DestList" for s in streams)
        run.add({"row": "file", "path": path, "kind": "automaticDestinations-ms" if has_destlist else "compound file without a DestList", "bytes": size, "status": "read",
                 "application_id": os.path.basename(path).split(".")[0] if re.fullmatch(r"[0-9a-fA-F]{16}", os.path.basename(path).split(".")[0]) else None})
        run.add({"row": "container", "source": path, "major_version": cfb.major, "sector_size": cfb.ss, "mini_sector_size": cfb.mini_ss, "mini_stream_cutoff": cfb.cutoff,
                 "sectors_in_file": cfb.sectors, "fat_sectors": cfb.n_fat, "directory_entries": len(cfb.directory), "streams": len(streams),
                 "problems": container_problems, "consistent": not container_problems})
        run.counts["containers"] += 1
        if container_problems:
            run.container_problems += 1
        destlist, by_stream = None, {}
        for s, extents, whole in shown:
            if s["path"] == "DestList":
                destlist = (s, extents)
        dest_entries = []
        if destlist is not None:
            s, extents = destlist
            if s["size"] > MAX_DESTLIST_BYTES:
                run.add({"row": "destlist", "source": path, "problems": ["the DestList stream is %d bytes, over the %d this tool reads; it was not parsed" % (s["size"], MAX_DESTLIST_BYTES)]})
                run.unread += 1
            else:
                parsed = run.jumplist.parse_destlist(cfb.read(extents, MAX_DESTLIST_BYTES))
                dest_entries = parsed.pop("entries")
                run.add({"row": "destlist", "source": path, "version": parsed.get("destlist_version"), "entries_claimed": parsed.get("entries_claimed"),
                         "entries_read": len(dest_entries), "pinned_claimed": parsed.get("pinned_claimed"), "problems": parsed.get("problems", []),
                         "not_decoded": parsed.get("not_decoded", [])})
                if parsed.get("problems"):
                    run.container_problems += 1
                for e in dest_entries:
                    pieces = map_range(extents, e["stream_offset"], 0x82 + 2 * e["path_chars"])
                    e_row = {"row": "destlist_entry", "source": path, **e, "container_offset": pieces[0][0] if pieces else None,
                             "container_contiguous": len(pieces) == 1, "stream_present": any(x["path"].lower() == e["stream"] for x in streams)}
                    by_stream[e["stream"]] = e_row
                    run.counts["destlist_entries"] += 1
                    run.add(e_row)
        for s, extents, whole in shown:
            if out_of_time():
                run.stopped = True
                return
            run.counts["streams"] += 1
            is_dest = s["path"] == "DestList"
            head = cfb.read(extents, 20)
            entry = by_stream.get(s["path"].lower())
            srow = {"row": "stream", "source": path, "name": s["path"], "bytes": s["size"], "storage": "mini stream" if s["size"] < cfb.cutoff else "sectors",
                    "start_sector": s["start"], "file_offset": extents[0][1] if extents else None, "contiguous": len(extents) <= 1,
                    "extent_count": len(extents), "extents": [{"stream_offset": a, "file_offset": o, "bytes": n} for a, o, n in extents[:MAX_EXTENTS_SHOWN]],
                    "chain_whole": whole, "is_link": head == LNK_MAGIC, "in_destlist": bool(entry) if not is_dest else None}
            if not is_dest and has_destlist and not entry:
                srow["orphan"] = "a stream the DestList has no entry for"
            run.add(srow)
            if is_dest or head != LNK_MAGIC:
                continue
            if s["size"] > MAX_STREAM_BYTES:
                run.unread += 1
                run.add({"row": "link", "source": path, "stream": s["path"], "integrity": {"status": "unreadable", "problems": ["the stream is %d bytes, over the %d this tool reads; it was not parsed" % (s["size"], MAX_STREAM_BYTES)]}})
                run.integrity["unreadable"] += 1
                continue
            data = cfb.read(extents, MAX_STREAM_BYTES)
            where = {"source": path, "container": "automaticDestinations-ms", "stream": s["path"], "file_offset": extents[0][1] if extents else None,
                     "contiguous": len(extents) <= 1, "extents": srow["extents"], "destlist_entry": entry["entry_number"] if entry else None}
            if entry:
                where["destlist_path"] = entry["path"]
                where["destlist_last_access"] = entry["last_access"]
            row, decoded = link_row(run, data, 0, where)
            if not whole:
                row["integrity"].setdefault("problems", []).append("the stream's sector chain is shorter than its size: only the sectors it has were read")
                if row["integrity"]["status"] == "ok":
                    row["integrity"]["status"] = "incomplete"
            finish_link(run, row, decoded, None, data)
        for number, e_row in by_stream.items():
            if not e_row["stream_present"]:
                run.add({"row": "destlist_entry_without_stream", "source": path, "entry_number": e_row["entry_number"], "stream": number, "path": e_row["path"],
                         "note": "the DestList names a stream that the container does not hold (deleted, or a damaged directory)"})
                run.container_problems += 1


def classify(path, name, size):
    with open(path, "rb") as fh:
        head = fh.read(20)
    if head[:20] == LNK_MAGIC:
        return "lnk"
    if head[:8] == OLE_MAGIC:
        return "cfb"
    lowered = name.lower()
    if lowered.endswith("customdestinations-ms"):
        return "custom"
    return None


def collect(path, max_files):
    targets, skipped, over = [], [], 0
    if os.path.isdir(path):
        for root, dirs, files in os.walk(path, followlinks=False):
            dirs.sort()
            for name in sorted(files):
                full = os.path.join(root, name)
                lowered = name.lower()
                if not (lowered.endswith(".lnk") or lowered.endswith("destinations-ms")):
                    skipped.append({"file": full, "reason": "not named like a link or a jump list: not read"})
                    continue
                try:
                    st = os.lstat(full)
                except OSError as exc:
                    skipped.append({"file": full, "reason": "could not be examined: " + describe(exc), "unopened": True})
                    continue
                if not stat.S_ISREG(st.st_mode):
                    skipped.append({"file": full, "reason": ("a symbolic link is not followed" if stat.S_ISLNK(st.st_mode) else "not a regular file") + ": it was not opened", "unopened": True})
                    continue
                if len(targets) >= max_files:
                    over += 1
                    continue
                targets.append((full, st.st_size))
    else:
        try:
            st = os.stat(path)
        except OSError as exc:
            fail("the path could not be examined", path=path, reason=describe(exc))
        if not stat.S_ISREG(st.st_mode):
            fail("the path is not a regular file or a directory (a pipe, a socket or a device is never opened)", path=path, not_attempted=1)
        targets.append((path, st.st_size))
    return targets, skipped, over


def last_word(signum):
    forget_temps()
    print(json.dumps({"error": "stopped by signal %d before the answer was complete" % signum, "status": "interrupted",
                      "status_basis": "the tool was stopped by signal %d; nothing it had made is a result (the temporary files were removed)" % signum, "signal": signum}), flush=True)


def check_args(args):
    if not isinstance(args, dict):
        fail("the arguments are one JSON object")
    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: a link, a jump list, or a directory of them")
    limit = args.get("limit", 100)
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        fail("limit must be a positive whole number", limit=limit)
    seconds = args.get("max_seconds", DEFAULT_SECONDS)
    if isinstance(seconds, bool) or not isinstance(seconds, (int, float)) or not 1 <= seconds <= MAX_SECONDS:
        fail("max_seconds must be a number from 1 to %d" % MAX_SECONDS, max_seconds=seconds)
    max_files = args.get("max_files", DEFAULT_FILES)
    if isinstance(max_files, bool) or not isinstance(max_files, int) or max_files < 1:
        fail("max_files must be a positive whole number", max_files=max_files)
    write_strings = args.get("write_strings", False)
    if not isinstance(write_strings, bool):
        fail("write_strings must be true or false")
    return path, limit, float(seconds), max_files, write_strings


def main():
    install_signal_handlers()
    STATE["last_word"] = last_word
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    path, limit, seconds, max_files, write_strings = check_args(args)
    if write_strings:
        job, out = os.environ.get("JOB_ID") or "", os.environ.get("OUT") or ""
        if not (job and out) or os.environ.get("SECRET_OUTPUT") != "1":
            fail("write_strings is refused: the text of a link's strings is written only in a job the harness runs as secret output (job_run with secret_output: true). Nothing was written.")
    CLOCK["deadline"] = time.monotonic() + seconds
    started = time.monotonic()
    targets, skipped, over = collect(path, max_files)
    identity = hashlib.sha256(json.dumps([path, [t for t in targets[:2000]], len(targets)]).encode("utf-8")).hexdigest()[:12]
    directory = output_directory(identity)
    try:
        directory.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        fail("the output directory could not be made", reason=describe(exc))
    try:
        run = Run(directory, limit, write_strings, started)
    except ValueError as exc:
        fail(str(exc))
    kinds = {}
    for full, size in targets:
        if out_of_time():
            run.stopped = True
            break
        try:
            kind = classify(full, os.path.basename(full), size)
            if kind is None:
                run.not_attempted.append({"file": full, "reason": "neither a link header, a compound file signature nor a customDestinations-ms name: not read"})
                continue
            run.counts["files"] += 1
            label = {"lnk": "shell link", "cfb": "compound file", "custom": "customDestinations-ms"}[kind]
            kinds[label] = kinds.get(label, 0) + 1
            if kind == "lnk":
                read_lnk_file(run, full, size)
            elif kind == "custom":
                read_custom(run, full, size)
            else:
                read_automatic(run, full, size)
        except OSError as exc:
            run.unread += 1
            run.add({"row": "file", "path": full, "status": "failed", "problems": ["could not be read: " + describe(exc)]})
    rows_result, strings_result = run.finish()
    unread_names = skipped + run.not_attempted
    reasons = []
    if run.stopped:
        reasons.append("the tool's own time limit (%d seconds) was reached: files after it were not read" % int(seconds))
    if over:
        reasons.append("%d file(s) past max_files (%d) were not read" % (over, max_files))
    unopened = sum(1 for item in skipped if item.get("unopened"))
    if unopened:
        reasons.append("%d file(s) named like a link or a jump list were not opened (a symbolic link is not followed; a pipe, a socket or a device is never opened): skipped_first and the receipt name them" % unopened)
    if run.not_attempted:
        reasons.append("%d file(s) were not read because their first bytes are neither a link, a compound file nor a customDestinations-ms name (skipped_first names them)" % len(run.not_attempted))
    if run.unread:
        reasons.append("%d file(s) or stream(s) could not be read whole" % run.unread)
    if run.container_problems:
        reasons.append("%d container problem(s) are named in the rows" % run.container_problems)
    if run.integrity["incomplete"] or run.integrity["unreadable"]:
        reasons.append("%d link(s) are incomplete and %d unreadable" % (run.integrity["incomplete"], run.integrity["unreadable"]))
    if run.integrity["disagrees"]:
        reasons.append("lnkinfo disagrees with lnk_parse on %d link(s)" % run.integrity["disagrees"])
    if not run.counts["files"] and not unread_names:
        status, basis = "failed", "no file was read"
    elif not run.counts["files"]:
        status, basis = "failed", "no link or jump list was found to read (%d file(s) skipped)" % len(unread_names)
    else:
        status = "partial" if reasons else "complete"
        basis = "; ".join(reasons) if reasons else "every file was read to its end, every container is consistent, and every link's structure is complete" + (
            " and agrees with lnkinfo where lnkinfo was run" if run.lnkinfo["checked"] else "")
        if not reasons and run.lnkinfo["not_run"]:
            basis += "; lnkinfo, the independent reader, was not run for %d link(s) (lnkinfo.why_not_run says why)" % run.lnkinfo["not_run"]
    receipt = {"parser": PARSER, "status": status, "status_basis": basis, "path": path, "counts": run.counts, "kinds": kinds, "integrity": run.integrity,
               "container_problems": run.container_problems, "lnkinfo": run.lnkinfo, "skipped": len(unread_names)}
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".receipt-")
    TEMPS.append(tmp)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump({**receipt, "skipped_files": unread_names[:5000]}, fh, indent=1)
        fh.write("\n")
    placed = place_without_replacing(Path(tmp), directory / "receipt.json")
    TEMPS[:] = [t for t in TEMPS if t != tmp]
    answer = {**receipt, "skipped_first": unread_names[:20], "rows": run.rows.page, "rows_total": rows_result["matched"], "rows_file": rows_result.get("all_results"),
              "strings_file": strings_result.get("all_results"), "string_locators": strings_result["matched"], "receipt": shown_path(placed),
              "secret_values": run.values.summary("JSON Lines, mode 0600: finding_id, link_offset, field, [offset, piece, continued_in_next,] value"),
              "elapsed_seconds": round(time.monotonic() - started, 2),
              "note": "Offsets inside a link's record are from the start of that link structure; file_offset and extents say where it sits in the file. lnk_parse decodes the link, "
                      "jumplist's layouts decode the DestList, lnkinfo is the independent read; nothing here executes or resolves a target."}
    print(json.dumps(answer, indent=1))
    if status == "failed":
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except ValueError as exc:
        fail(str(exc))
    except Exception as exc:                                  # whatever hostile input does, the answer is JSON
        forget_temps()
        print(json.dumps({"ok": False, "error": "the run failed", "status": "failed", "status_basis": "the tool stopped with an unexpected error", "reason": "%s: %s" % (type(exc).__name__, exc)}))
        sys.exit(1)
