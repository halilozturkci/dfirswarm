#!/usr/bin/env python3
"""Replay a registry hive's transaction logs on a copy, and read the recovered state.

A hive that was in use when it was copied can be dirty: its two sequence numbers differ and its newest
state is in the .LOG1 and .LOG2 files beside it, not in the hive. This tool applies the logs the caller
names (explicitly: nothing is looked for beside the hive) to a COPY of the hive under its own output
directory, writes a receipt of what was done and not done, and writes the key and value records of the
resulting state as JSON Lines. The hive and the logs are only opened for reading.

The replay follows the layout of the two log formats (Suhanov, "Windows registry file format
specification"; libyal's REGF notes):
  new format (HvLE entries, Windows 8.1 and later): an entry is applied only when its signature, the
  Marvin32 hash of its header (hash-2) and of its pages (hash-1) are right, and its sequence number is
  the next one the hive needs. A dirty hive needs the entry whose sequence number is its SECONDARY
  sequence number; after an entry of number n is applied the hive is at n + 1, and entries of the
  following numbers are applied in order, from one log or the other. An entry older than the hive's
  state is not applied (it would put an older page over a newer one), an entry that does not follow is
  not applied, and an entry whose hash is wrong ends the log there. Every entry not applied, and the
  hive ranges its pages would have written, are listed under `unrecovered`.
  old format (a DIRT vector and the dirty 512-byte sectors): applied as a whole when the log's own two
  sequence numbers agree and equal the hive's primary sequence number. It has no hash to check.
regipy's apply_transaction_logs is not used for the replay: it writes the pages of every entry whatever
its sequence number, so an entry older than the hive's state is written over newer data, and it takes
the first dirty sector of an old-format log to be at a fixed place.

The recovered copy differs from the original in the pages of the applied entries and in three fields of
its base block, which the receipt names: both sequence numbers (set to the number after the last applied
entry), the hive bins data size (from the last applied entry) and the base block checksum (recomputed).
A hive that is clean is not replayed (a clean hive's logs only hold entries it already contains; a log
entry newer than a clean hive is reported, not applied). The key and value records are read with
regipy: `keys.jsonl` is the state read (the recovered copy when something was applied, else the hive),
and when a replay applied something `changes.jsonl` lists the keys and values that differ from the
original.

SENSITIVE OUTPUT. A value that is registry material that can be a secret (the V and SupplementalCredentials
values of each SAM user, the values of the LSA secrets and cached-logon keys of a SECURITY hive, and a
value whose name says password, secret, token or credential, a DWORD or QWORD excepted) is written as a
record with its place, name, type and length, and not its bytes. `write_values: true` in a job run as
secret output writes those values to a file with mode 0600; it is refused anywhere else, before anything
is made. A secret inside a value that does not look like one (a command line with a password in it) is
not recognised and is written with the rest.
"""
import collections
import datetime
import json
import os
import re
import select
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

PARSER = "registry_recover/1"
BASE_BLOCK = 4096
LOG_HEADER = 512
MARVIN_SEED = 0x82EF4D887A4E55C5
FILETIME_EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
SENSITIVE_NAME = re.compile(r"passw(or)?d|pwd|secret|token|credential|api_?key|private_?key", re.I)
NUMBER_TYPES = ("REG_DWORD", "REG_DWORD_BIG_ENDIAN", "REG_QWORD")
MAX_HIVE_BYTES = 4 << 30
MAX_LOG_ENTRIES = 1_000_000
MAX_DEPTH = 512
DEFAULT_SECONDS = 90
MAX_SECONDS = 110
INLINE_PROBLEMS = 50
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


# BEGIN SHARED HIVE BOUNDS
# The same text is in regkv, shellbags and amcache_apps (a windows-forensics test holds the copies equal).
# A hive of N bytes holds at most N // 76 key cells (an nk cell is at least 76 bytes) and N // 20 value cells (a vk cell is at least 20), however
# many elements an index claims: regipy follows a subkey index (ri) element by element, so one list repeated by an index is read as many times as
# it is repeated (a 61 KB hive listed a million keys and took 1.2 GB). Every list of subkeys and values is read through these bounds, and what is
# past one is said, never followed.
import itertools
import logging
import warnings

KEY_CELL_BYTES = 76
VALUE_CELL_BYTES = 20


class LibraryLog(logging.Handler):
    """regipy reports what it cannot parse through the logging module, and its text carries bytes of the value or the name it failed on
    (for a text value that is neither UTF-16 nor UTF-8: the byte and its position). The text is not printed anywhere: it is counted."""
    messages = 0
    errors = 0

    def emit(self, record):
        LibraryLog.messages += 1
        if record.levelno >= logging.ERROR:
            LibraryLog.errors += 1


def withhold_library_output():
    logging.root.handlers[:] = [LibraryLog()]
    warnings.simplefilter("ignore")


class HiveBounds:
    def __init__(self, hive_path, size=None):
        size = os.path.getsize(hive_path) if size is None else size
        self.hive_bytes = size
        self.key_cells = max(size // KEY_CELL_BYTES, 1)
        self.value_cells = max(size // VALUE_CELL_BYTES, 1)
        self.keys_read = 0                      # subkey elements read over the whole walk
        self.data_read = 0                      # bytes of value data read over the whole walk
        self.repeats = 0                        # elements that named a key already named in the same list

    def subkeys(self, node, where, problems):
        """The distinct subkeys of `node`, at most the keys the hive can still hold; what is past that, or repeated, is a problem line."""
        room = max(self.key_cells - self.keys_read, 0)
        raw = list(itertools.islice(node.iter_subkeys() or [], room + 1))
        if len(raw) > room:
            raw = raw[:room]
            problems.append({"where": where, "what": "subkeys",
                             "error": "its subkey list yields more keys than a %d-byte hive can hold (%d keys at most, %d already read in this walk): "
                                      "an index that repeats a list; the elements past that are not read" % (self.hive_bytes, self.key_cells, self.keys_read)})
        self.keys_read += len(raw)
        seen, distinct, repeated = set(), [], 0
        for sub in raw:
            header = getattr(sub, "header", None)
            identity = (str(getattr(sub, "name", "")).lower(), getattr(header, "last_modified", None),
                        getattr(header, "subkeys_list_offset", None), getattr(header, "values_list_offset", None))
            if identity in seen:
                repeated += 1
                continue
            seen.add(identity)
            distinct.append(sub)
        if repeated:
            self.repeats += repeated
            problems.append({"where": where, "what": "subkeys",
                             "error": "its subkey list names %d key(s) more than once; each is listed once" % repeated})
        return distinct

    def values(self, node, where, problems, **kwargs):
        """At most the values the hive can hold, as a list, and at most the data it can hold over the whole walk (a value list that names one big
        record again and again reads that record every time); a key that lists more is a problem line."""
        raw = []
        for v in itertools.islice(node.iter_values(**kwargs), self.value_cells + 1):
            if len(raw) >= self.value_cells:
                problems.append({"where": where, "what": "values",
                                 "error": "its value list yields more values than a %d-byte hive can hold (%d at most): the elements past that are not read"
                                          % (self.hive_bytes, self.value_cells)})
                break
            data = getattr(v, "value", None)
            self.data_read += len(data) if isinstance(data, (bytes, bytearray, str)) else sum(len(x) for x in data if isinstance(x, (str, bytes))) if isinstance(data, list) else 0
            if self.data_read > 4 * self.hive_bytes:
                problems.append({"where": where, "what": "values",
                                 "error": "the values read in this walk hold more data than a %d-byte hive can: records that a value list names again and again; "
                                          "the values past that are not read" % self.hive_bytes})
                break
            raw.append(v)
        return raw
# END SHARED HIVE BOUNDS


# ---- small helpers ------------------------------------------------------------------------------------------------------------------

def fail(message, **extra):
    print(json.dumps({"ok": False, "error": message, "status": "failed", "status_basis": "the tool stopped with an error (see error); no hive was replayed", **extra}))
    sys.exit(1)


def describe(exc):
    if isinstance(exc, OSError):
        return "%s: %s" % (type(exc).__name__, exc.strerror or exc)
    return "%s: %s" % (type(exc).__name__, exc)


def ft_iso(value):
    """A FILETIME as ISO 8601 UTC with seven fractional digits, by integer arithmetic; None for 0 or a date past year 9999."""
    if not value:
        return None
    try:
        whole, ticks = divmod(int(value), 10_000_000)
        return (FILETIME_EPOCH + datetime.timedelta(seconds=whole)).strftime("%Y-%m-%dT%H:%M:%S") + ".%07dZ" % ticks
    except (OverflowError, ValueError, TypeError):
        return None


CLOCK = {"deadline": None}


def set_deadline(seconds):
    CLOCK["deadline"] = time.monotonic() + seconds


def out_of_time(share=1.0, started=None):
    if CLOCK["deadline"] is None:
        return False
    return time.monotonic() > CLOCK["deadline"]


TEMPS = []                       # temporary files made by this run, removed when it is stopped


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


def marvin32(chunks, seed=MARVIN_SEED):
    """The 64-bit Marvin32 hash the registry's transaction logs use (the .NET Marvin32 with the 64-bit seed 0x82EF4D887A4E55C5; the
    result is the high state word shifted up 32 beside the low one). `chunks` yields bytes; every piece but the last is a multiple of 4 long."""
    lo, hi = seed & 0xFFFFFFFF, seed >> 32
    pending = b""
    for chunk in chunks:
        data = pending + chunk if pending else chunk
        usable = len(data) - (len(data) % 4)
        pending = data[usable:]
        if not usable:
            continue
        view = memoryview(data)[:usable]
        words = view.cast("I") if sys.byteorder == "little" else (w for (w,) in struct.iter_unpack("<I", view))
        for w in words:
            lo = (lo + w) & 0xFFFFFFFF
            hi ^= lo
            lo = ((lo << 20) | (lo >> 12)) & 0xFFFFFFFF
            lo = (lo + hi) & 0xFFFFFFFF
            hi = ((hi << 9) | (hi >> 23)) & 0xFFFFFFFF
            hi ^= lo
            lo = ((lo << 27) | (lo >> 5)) & 0xFFFFFFFF
            lo = (lo + hi) & 0xFFFFFFFF
            hi = ((hi << 19) | (hi >> 13)) & 0xFFFFFFFF
    tail = 0
    for i, byte in enumerate(pending):
        tail |= byte << (8 * i)
    tail |= 0x80 << (8 * len(pending))
    lo = (lo + tail) & 0xFFFFFFFF
    for _ in range(2):
        hi ^= lo
        lo = ((lo << 20) | (lo >> 12)) & 0xFFFFFFFF
        lo = (lo + hi) & 0xFFFFFFFF
        hi = ((hi << 9) | (hi >> 23)) & 0xFFFFFFFF
        hi ^= lo
        lo = ((lo << 27) | (lo >> 5)) & 0xFFFFFFFF
        lo = (lo + hi) & 0xFFFFFFFF
        hi = ((hi << 19) | (hi >> 13)) & 0xFFFFFFFF
    return (hi << 32) | lo


class TimeLimit(Exception):
    """The tool's own time limit was reached while a long read was in progress."""


def file_chunks(fh, start, length, clock=False):
    fh.seek(start)
    left = length
    while left > 0:
        if clock and out_of_time():
            raise TimeLimit()
        piece = fh.read(min(BLOCK, left))
        if not piece:
            raise OSError("the file ended %d bytes before the range did" % left)
        left -= len(piece)
        yield piece


def base_checksum(block):
    """The base block checksum: the XOR of its first 127 little-endian dwords."""
    total = 0
    for (word,) in struct.iter_unpack("<I", block[:508]):
        total ^= word
    return total & 0xFFFFFFFF


def read_base(fh, size):
    """The fields of a base block (a hive's 4096 bytes, or a log's first 512), and what is wrong with it."""
    fh.seek(0)
    block = fh.read(BASE_BLOCK)
    info = {"bytes_read": len(block), "problems": []}
    if len(block) < LOG_HEADER:
        info["problems"].append("the file is %d bytes, shorter than a 512-byte base block" % size)
        info["signature_ok"] = False
        return info, block
    info["signature_ok"] = block[:4] == b"regf"
    if not info["signature_ok"]:
        info["problems"].append("the file does not start with the 'regf' signature")
        return info, block
    primary, secondary, written, major, minor, ftype, fmt, root, hbs = struct.unpack_from("<IIQIIIIII", block, 4)[0:9]
    info.update({"primary_sequence": primary, "secondary_sequence": secondary, "last_written_filetime": str(written), "last_written": ft_iso(written),
                 "version": "%d.%d" % (major, minor), "file_type": ftype, "format": fmt, "root_cell_offset": root, "hive_bins_data_size": hbs})
    stored = struct.unpack_from("<I", block, 508)[0]
    info["checksum_stored"] = stored
    info["checksum_ok"] = base_checksum(block) == stored
    if not info["checksum_ok"]:
        info["problems"].append("the base block checksum is wrong")
    if len(block) >= 0x94:
        info["flags"] = struct.unpack_from("<I", block, 0x90)[0]
    return info, block


# ---- the logs ---------------------------------------------------------------------------------------------------------------------------

def zero_tail(fh, start, size):
    fh.seek(start)
    left = size - start
    while left > 0:
        piece = fh.read(min(BLOCK, left))
        if not piece:
            break
        if piece.count(0) != len(piece):
            return False
        left -= len(piece)
    return True


def scan_hvle(fh, size, base_hbs):
    """The entries of a new-format log, in file order, each with what its header says; the scan stops at the first thing that is not a
    well-formed entry and says what the bytes from there on are."""
    entries, off, trailing = [], LOG_HEADER, None
    while off + 40 <= size and len(entries) < MAX_LOG_ENTRIES:
        fh.seek(off)
        head = fh.read(40)
        if head[:4] != b"HvLE":
            trailing = {"offset": off, "bytes": size - off, "reason": "no HvLE signature at this offset", "all_zero": zero_tail(fh, off, size)}
            break
        entry_size, flags, seq, hbs, count, hash1, hash2 = struct.unpack_from("<IIIIIQQ", head, 4)
        e = {"index": len(entries), "offset": off, "size": entry_size, "sequence": seq, "flags": flags, "hive_bins_data_size": hbs, "dirty_pages": count,
             "header_hash_ok": marvin32([head[:32]]) == hash2, "pages_hash_ok": None, "valid": False, "refs": []}
        entries.append(e)
        if not e["header_hash_ok"]:
            e["reason"] = "the header hash (hash-2) is wrong"
        elif entry_size % 512 or entry_size < 40 + 8 * count or off + entry_size > size:
            e["reason"] = "the entry size %d is not a multiple of 512 that holds its %d page references and fits in the file" % (entry_size, count)
        else:
            refs = fh.read(8 * count)
            total, bad = 0, None
            for i in range(count):
                ref_off, ref_size = struct.unpack_from("<II", refs, 8 * i)
                total += ref_size
                if ref_size == 0 or ref_off + ref_size > hbs:
                    bad = "page reference %d (offset %d, %d bytes) is outside the hive bins data size %d the entry declares" % (i, ref_off, ref_size, hbs)
                    break
                e["refs"].append((ref_off, ref_size))
            if bad is None and 40 + 8 * count + total > entry_size:
                bad = "its page references claim %d bytes of pages, more than the entry holds" % total
            if bad:
                e["reason"] = bad
                e["refs"] = []
            else:
                e["valid"] = True
                e["page_bytes"] = total
                e["pages_at"] = off + 40 + 8 * count
        if not e["valid"]:
            trailing = {"offset": off, "bytes": size - off, "reason": "the entry at this offset is not well formed (%s); nothing after it is read" % e["reason"], "all_zero": False}
            break
        off += entry_size
    else:
        if off + 40 <= size:
            trailing = {"offset": off, "bytes": size - off, "reason": "more than %d entries: the scan stopped" % MAX_LOG_ENTRIES, "all_zero": False}
    if trailing is None and off < size:
        trailing = {"offset": off, "bytes": size - off, "reason": "fewer than 40 bytes follow the last entry", "all_zero": zero_tail(fh, off, size)}
    return entries, trailing


def verify_pages(fh, e):
    """Hash-1 of an entry: the Marvin32 hash of everything after its 40-byte header up to its size."""
    if e["pages_hash_ok"] is None:
        stored = struct.unpack("<Q", read_at(fh, e["offset"] + 24, 8))[0]
        e["pages_hash_ok"] = marvin32(file_chunks(fh, e["offset"] + 40, e["size"] - 40, clock=True)) == stored
        if not e["pages_hash_ok"]:
            e["valid"] = False
            e["reason"] = "the pages hash (hash-1) is wrong"
    return e["pages_hash_ok"]


def read_at(fh, offset, length):
    fh.seek(offset)
    data = fh.read(length)
    if len(data) != length:
        raise OSError("short read at %d" % offset)
    return data


def old_format_layout(fh, size, hbs):
    """Where the dirty sectors of an old-format log start, and which sectors the DIRT vector says are dirty: the vector holds one bit for
    each 512-byte sector of the hive bins and is padded, with its 4-byte signature, to a whole sector."""
    vector_bytes = (hbs // 512 + 7) // 8
    data_start = LOG_HEADER + ((4 + vector_bytes + 511) // 512) * 512
    fh.seek(LOG_HEADER)
    raw = fh.read(4 + vector_bytes)
    if len(raw) < 4 + vector_bytes:
        return None
    sectors = [i for i in range(vector_bytes * 8) if raw[4 + i // 8] >> (i % 8) & 1]
    return {"vector_bytes": vector_bytes, "data_start": data_start, "sectors": sectors}


def examine_log(path, role, hive):
    """Everything the replay needs to know about one log, and its receipt entry."""
    log = {"role": role, "path": path, "problems": []}
    try:
        st = os.stat(path)
    except OSError as exc:
        log["problems"].append("could not be examined: %s" % describe(exc))
        log["usable"] = False
        return log, None
    if not stat.S_ISREG(st.st_mode):
        log["problems"].append("is not a regular file, so it was not opened")
        log["usable"] = False
        return log, None
    log["bytes"] = st.st_size
    if st.st_size > MAX_HIVE_BYTES:
        log["problems"].append("is larger than the %d bytes this tool reads" % MAX_HIVE_BYTES)
        log["usable"] = False
        return log, None
    fh = open(path, "rb")
    try:
        base, _block = read_base(fh, st.st_size)
        log["base_block"] = {k: v for k, v in base.items() if k != "problems"}
        log["problems"] += base["problems"]
        if not base["signature_ok"]:
            log["format"] = "not a log"
            log["usable"] = False
            fh.close()
            return log, None
        if base.get("file_type") == 0:
            log["problems"].append("its base block says it is a primary hive (file type 0), not a transaction log: it is not used")
            log["format"] = "not a log"
            log["usable"] = False
            fh.close()
            return log, None
        magic = read_at(fh, LOG_HEADER, 4) if st.st_size >= LOG_HEADER + 4 else b""
        if magic == b"HvLE":
            log["format"] = "new (HvLE entries)"
            entries, trailing = scan_hvle(fh, st.st_size, hive.get("hive_bins_data_size"))
            log["entry_count"] = len(entries)
            log["trailing"] = trailing
            log["usable"] = True
            return log, {"fh": fh, "kind": "hvle", "entries": entries, "base": base}
        if magic == b"DIRT":
            log["format"] = "old (DIRT vector)"
            hbs = hive.get("hive_bins_data_size") or 0
            layout = old_format_layout(fh, st.st_size, hbs)
            if layout is None:
                log["problems"].append("is shorter than the DIRT vector the hive's size needs")
                log["usable"] = False
                fh.close()
                return log, None
            log["usable"] = True
            log["dirty_sectors"] = len(layout["sectors"])
            return log, {"fh": fh, "kind": "dirt", "layout": layout, "base": base}
        log["format"] = "empty" if st.st_size <= LOG_HEADER or zero_tail(fh, LOG_HEADER, st.st_size) else "unknown"
        log["problems"].append("holds no HvLE entry and no DIRT vector after its base block (%s)" % ("only zeros follow it" if log["format"] == "empty" else "the bytes there are neither"))
        log["usable"] = False
        fh.close()
        return log, None
    except Exception:
        fh.close()
        raise


def entry_view(e):
    return {"index": e["index"], "offset": e["offset"], "size": e["size"], "sequence": e["sequence"], "dirty_pages": e["dirty_pages"],
            "hive_bins_data_size": e["hive_bins_data_size"], "header_hash_ok": e["header_hash_ok"], "pages_hash_ok": e["pages_hash_ok"],
            "state": e.get("state", "not examined"), **({"reason": e["reason"]} if e.get("reason") else {})}


# ---- the replay -------------------------------------------------------------------------------------------------------------------------

def plan_hvle(hive, parsed, receipt_logs):
    """Which entries to apply, in order. Returns (steps, expected_after, notes): steps are (log role, entry)."""
    start = hive["secondary_sequence"]
    expected = start
    steps, notes, timed_out = [], [], []
    by_seq = {}
    for role, p in parsed.items():
        if p["kind"] != "hvle":
            continue
        for e in p["entries"]:
            by_seq.setdefault(e["sequence"], []).append((role, e))
    current = None
    while True:
        choices = sorted(by_seq.get(expected, []), key=lambda c: (c[0] != current, c[0]))
        taken = None
        for role, e in choices:
            if not e["valid"]:
                continue
            try:
                good = verify_pages(parsed[role]["fh"], e)
            except TimeLimit:
                e["state"] = "not applied: the time limit was reached while its pages hash was being checked"
                timed_out.append(e["sequence"])
                return steps, start, expected, notes, timed_out
            if not good:
                e["state"] = "not applied: the pages hash is wrong"
                continue
            taken = (role, e)
            break
        if taken is None:
            for role, e in choices:
                if e["valid"] is False and e.get("state") is None:
                    e["state"] = "not applied: " + e.get("reason", "not valid")
            break
        role, e = taken
        e["state"] = "applied"
        steps.append((role, e))
        others = [c for c in choices if c[1] is not e and c[1]["valid"]]
        if others:
            notes.append("the other log holds an entry of sequence %d too; the one in the log the replay was already in (or the first named) was used" % expected)
        current = role
        expected += 1
    return steps, start, expected, notes, timed_out


def fresh_copy(src_path, dest, size):
    """A copy of the hive made in blocks (never read whole), opened for writing."""
    fd, name = tempfile.mkstemp(dir=dest.parent, prefix=".recovered-")
    TEMPS.append(name)
    with os.fdopen(fd, "wb") as out, open(src_path, "rb") as src:
        for piece in file_chunks(src, 0, size):
            out.write(piece)
    return Path(name)


def write_pages(out_fh, log_fh, e):
    """Copy an entry's pages to their places in the working copy, in blocks. Returns the hive ranges written."""
    written = []
    at = e["pages_at"]
    for ref_off, ref_size in e["refs"]:
        out_fh.seek(BASE_BLOCK + ref_off)
        for piece in file_chunks(log_fh, at, ref_size):
            out_fh.write(piece)
        written.append((ref_off, ref_size))
        at += ref_size
    return written


def merge_ranges(ranges):
    merged = []
    for start, length in sorted(ranges):
        if merged and start <= merged[-1][0] + merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], start + length - merged[-1][0])
        else:
            merged.append([start, length])
    return [{"hive_offset": s, "bytes": n} for s, n in merged]


def replay(hive_path, hive_size, hive, logs, out_dir):
    """The whole replay. Returns the receipt part, and the path of the working copy when something was applied."""
    receipt = {"performed": False, "reason": None, "order": [], "entries_applied": 0, "pages_applied": 0, "bytes_applied": 0}
    unrecovered, log_receipts, parsed = [], [], {}
    for role, path in logs:
        info, handle = examine_log(path, role, hive)
        log_receipts.append(info)
        if handle is not None:
            parsed[role] = handle
    dirty = hive.get("signature_ok") and hive["primary_sequence"] != hive["secondary_sequence"]
    receipt["dirty_before"] = bool(dirty)
    receipt["sequence_before"] = [hive.get("primary_sequence"), hive.get("secondary_sequence")]
    steps, working = [], None
    start = expected = None
    try:
        hvle_roles = [r for r, p in parsed.items() if p["kind"] == "hvle"]
        if not hive.get("signature_ok"):
            receipt["reason"] = "the hive has no 'regf' base block, so there is nothing to replay on"
        elif not dirty:
            receipt["reason"] = "the hive is clean (both sequence numbers are %d): nothing is replayed" % hive["primary_sequence"]
            for role in hvle_roles:
                for e in parsed[role]["entries"]:
                    if e["sequence"] >= hive["primary_sequence"]:
                        e["state"] = "not applied: newer than a clean hive (Windows does not replay a clean hive's logs)"
                        unrecovered.append({"log": role, "entry": e["index"], "sequence": e["sequence"], "why": e["state"][13:],
                                            "hive_ranges": merge_ranges(e["refs"]) if e["valid"] else [], "log_range": {"offset": e["offset"], "bytes": e["size"]}})
                    else:
                        e["state"] = "not needed: older than the clean hive's state"
        elif not parsed:
            receipt["reason"] = "the hive is dirty and no log that could be read was named: nothing is replayed"
        else:
            if hvle_roles:
                steps, start, expected, notes, timed_out = plan_hvle(hive, parsed, log_receipts)
                receipt["notes"] = notes
                if timed_out:
                    receipt["time_limit"] = "the time limit was reached while the pages hash of the entry of sequence %d was checked: nothing after it was examined" % timed_out[0]
            dirt_roles = [r for r, p in parsed.items() if p["kind"] == "dirt"]
            dirt_applied = None
            for role in dirt_roles:
                b = parsed[role]["base"]
                ok = b.get("checksum_ok") and b["primary_sequence"] == b["secondary_sequence"] == hive["primary_sequence"]
                parsed[role]["state"] = "applied" if ok and dirt_applied is None and not steps else None
                if not ok:
                    parsed[role]["why"] = ("its own sequence numbers (%s, %s) are not equal to each other and to the hive's primary sequence number (%s), or its base block checksum is wrong"
                                           % (b.get("primary_sequence"), b.get("secondary_sequence"), hive["primary_sequence"]))
                elif steps:
                    parsed[role]["why"] = "a new-format log was applied; an old-format log is not mixed with it"
                elif dirt_applied is not None:
                    parsed[role]["why"] = "another old-format log was applied"
                else:
                    dirt_applied = role
            if steps or dirt_applied:
                working = fresh_copy(hive_path, out_dir, hive_size)
                new_hbs = hive["hive_bins_data_size"]
                ranges_applied = []
                with open(working, "r+b") as out_fh:
                    if steps:
                        for role, e in steps:
                            ranges_applied += write_pages(out_fh, parsed[role]["fh"], e)
                            new_hbs = e["hive_bins_data_size"]
                            receipt["order"].append({"log": role, "entry": e["index"], "sequence": e["sequence"], "pages": e["dirty_pages"], "page_bytes": e["page_bytes"]})
                            receipt["entries_applied"] += 1
                            receipt["pages_applied"] += e["dirty_pages"]
                            receipt["bytes_applied"] += e["page_bytes"]
                        final = expected
                    else:
                        p = parsed[dirt_applied]
                        layout = p["layout"]
                        at = layout["data_start"]
                        for sector in layout["sectors"]:
                            out_fh.seek(BASE_BLOCK + sector * 512)
                            out_fh.write(read_at(p["fh"], at, 512))
                            ranges_applied.append((sector * 512, 512))
                            at += 512
                        new_hbs = p["base"].get("hive_bins_data_size", new_hbs)
                        final = hive["primary_sequence"]
                        receipt["order"].append({"log": dirt_applied, "dirty_sectors": len(layout["sectors"])})
                        receipt["entries_applied"] = 1
                        receipt["pages_applied"] = len(layout["sectors"])
                        receipt["bytes_applied"] = len(layout["sectors"]) * 512
                    wanted = BASE_BLOCK + new_hbs
                    current = out_fh.seek(0, 2)
                    if current < wanted:
                        out_fh.truncate(wanted)
                        covered = merge_ranges(ranges_applied)
                        gap_from = max(current - BASE_BLOCK, 0)
                        pos = gap_from
                        for r in covered:
                            if r["hive_offset"] + r["bytes"] <= gap_from:
                                continue
                            if r["hive_offset"] > pos:
                                unrecovered.append({"log": None, "why": "the working copy had %d bytes of hive bins and the log declares %d; no applied page writes this range, which is zeros" % (gap_from, new_hbs),
                                                    "hive_ranges": [{"hive_offset": pos, "bytes": r["hive_offset"] - pos}]})
                            pos = max(pos, r["hive_offset"] + r["bytes"])
                        if pos < new_hbs:
                            unrecovered.append({"log": None, "why": "the working copy had %d bytes of hive bins and the log declares %d; no applied page writes this range, which is zeros" % (gap_from, new_hbs),
                                                "hive_ranges": [{"hive_offset": pos, "bytes": new_hbs - pos}]})
                    out_fh.seek(0)
                    block = bytearray(out_fh.read(BASE_BLOCK))
                    struct.pack_into("<II", block, 4, final, final)
                    struct.pack_into("<I", block, 40, new_hbs)
                    struct.pack_into("<I", block, 508, base_checksum(bytes(block)))
                    out_fh.seek(0)
                    out_fh.write(block)
                    out_fh.flush()
                    os.fsync(out_fh.fileno())
                receipt["performed"] = True
                receipt["sequence_after"] = [final, final]
                receipt["dirty_after"] = False
                receipt["hive_bins_data_size"] = {"before": hive["hive_bins_data_size"], "after": new_hbs}
                receipt["base_block_fields_changed"] = ["primary_sequence", "secondary_sequence", "hive_bins_data_size", "checksum"]
            else:
                receipt["reason"] = "the hive is dirty (sequence %d / %d) and no named log holds an applicable entry" % (hive["primary_sequence"], hive["secondary_sequence"])
        # What was not applied, with the hive ranges its pages would have written.
        for role in hvle_roles:
            for e in parsed[role]["entries"]:
                if e.get("state") is None:
                    if e["valid"] is False:
                        e["state"] = "not applied: " + e.get("reason", "not valid")
                    elif dirty and start is not None and e["sequence"] < start:
                        e["state"] = "not needed: older than the state the hive was at (sequence %d)" % start
                    elif dirty and start is not None:
                        e["state"] = "not applied: its sequence number %d does not follow the last applied entry (the next needed is %d)" % (e["sequence"], expected)
                    else:
                        e["state"] = "not applied"
                if e["state"].startswith("not applied") and not (not dirty):
                    unrecovered.append({"log": role, "entry": e["index"], "sequence": e["sequence"], "why": e["state"][len("not applied: "):],
                                        "hive_ranges": merge_ranges(e["refs"]) if e["valid"] else [], "log_range": {"offset": e["offset"], "bytes": e["size"]}})
        for info in log_receipts:
            p = parsed.get(info["role"])
            if p is not None and p["kind"] == "hvle":
                info["entries"] = [entry_view(e) for e in p["entries"]]
                info["entries_applied"] = sum(1 for e in p["entries"] if e.get("state") == "applied")
                tr = info.get("trailing")
                if tr and not tr["all_zero"]:
                    unrecovered.append({"log": info["role"], "why": "bytes after the last well-formed entry are not an entry: %s" % tr["reason"], "hive_ranges": [],
                                        "log_range": {"offset": tr["offset"], "bytes": tr["bytes"]}})
            elif p is not None and p["kind"] == "dirt":
                info["state"] = p.get("state") or "not applied"
                if p.get("why"):
                    info["why_not_applied"] = p["why"]
                    if dirty:
                        unrecovered.append({"log": info["role"], "why": p["why"], "hive_ranges": [], "log_range": {"offset": 0, "bytes": info.get("bytes")}})
    finally:
        for p in parsed.values():
            p["fh"].close()
    return receipt, log_receipts, unrecovered, working


# ---- the typed key and value records ----------------------------------------------------------------------------------------------------

SAM_USER_KEY = re.compile(r"\\domains\\account\\users\\[0-9a-f]{8}\\$")
SAM_USER_SECRET_VALUES = ("v", "supplementalcredentials")
CACHED_LOGON = re.compile(r"^NL\$", re.I)
SECRET_PLACES = ("\\policy\\secrets\\", "\\policy\\poleklist\\", "\\policy\\polsecretencryptionkey\\")


def sensitive_value(names, name, vtype):
    """Whether this value is registry material that can be a secret: by its name and by the place the hive itself holds it in, never by its type
    (a DWORD or QWORD under a secret-sounding name is a number and is let through)."""
    name = name or ""
    if (SENSITIVE_NAME.search(name) or CACHED_LOGON.match(name)) and vtype not in NUMBER_TYPES:
        return "name"
    path = "\\" + "\\".join(names).lower() + "\\"
    if any(place in path for place in SECRET_PLACES):
        return "place"
    if SAM_USER_KEY.search(path) and name.lower() in SAM_USER_SECRET_VALUES:
        return "place"
    return None


class ValuesFile:
    def __init__(self, enabled, directory):
        self.enabled, self.fh, self.written, self.shown = enabled, None, 0, None
        if not enabled:
            return
        job, out = os.environ.get("JOB_ID") or "", os.environ.get("OUT") or ""
        if not (job and out) or os.environ.get("SECRET_OUTPUT") != "1":
            raise ValueError("write_values is refused: the values of what is withheld are written only in a job the harness runs as secret output "
                             "(job_run with secret_output: true), where the file is a sealed secret output. Nothing was written.")
        for n in range(1, 1000):
            name = "values.jsonl" if n == 1 else "values-%d.jsonl" % n
            path = directory / name
            try:
                fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
            except FileExistsError:
                continue
            except OSError as exc:
                raise ValueError("the values file could not be created: %s" % describe(exc))
            self.fh = os.fdopen(fd, "w", encoding="utf-8")
            self.shown = shown_path(path)
            return
        raise ValueError("no free name for the values file")

    def add(self, row):
        if self.fh is None:
            return
        text = json.dumps(row, ensure_ascii=False)
        try:
            text.encode("utf-8")
        except UnicodeEncodeError:
            text = json.dumps(row, ensure_ascii=True)
        self.fh.write(text + "\n")
        self.written += 1

    def close(self):
        if self.fh is not None:
            self.fh.flush()
            os.fsync(self.fh.fileno())
            self.fh.close()
            self.fh = None


def shown_path(path):
    """A file as the answer names it: in a job as the sealed place, else from the run directory."""
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


def value_record(v, names, shown_path_, withheld_kind, bounds):
    vtype = str(v.value_type)
    val = v.value
    rec = {"row": "value", "key": shown_path_, "name": v.name, "type": vtype}
    if isinstance(val, (bytes, bytearray)):
        rec["length"], rec["unit"] = len(val), "bytes"
        payload = {"data_hex": bytes(val).hex()}
    elif isinstance(val, str):
        rec["length"], rec["unit"] = len(val), "characters"
        payload = {"data": val}
    elif isinstance(val, list):
        rec["length"], rec["unit"] = len(val), "strings"
        payload = {"data": [x if isinstance(x, str) else str(x) for x in val]}
    elif isinstance(val, int) and not isinstance(val, bool):
        rec["length"], rec["unit"] = None, None
        payload = {"data": val}
    else:
        rec["length"], rec["unit"] = None, None
        payload = {"data": None}
    if getattr(v, "is_corrupted", False):
        rec["corrupted"] = True
    return rec, payload


def digest_of(*parts):
    import hashlib
    h = hashlib.blake2b(digest_size=16)
    for part in parts:
        h.update(repr(part).encode("utf-8", "surrogatepass"))
        h.update(b"\x00")
    return h.digest()


class Walk:
    """One depth-first read of a hive. `sink` receives (kind, path, name, ordinal, digest, record) for every key and value."""

    def __init__(self, path, deadline_at):
        from regipy.registry import RegistryHive
        self.hive = RegistryHive(path)
        self.bounds = HiveBounds(path)
        self.deadline_at = deadline_at
        self.keys = self.values = self.withheld = self.problems_count = 0
        self.stopped_by_time = False
        self.problems = []
        self.type_counts = collections.Counter()

    def release(self):
        """Let go of the library's copy of the hive (it holds the whole file in memory); the counts stay."""
        self.hive = None
        self.bounds = None
        import gc
        gc.collect()

    def problem(self, where, what, error):
        self.problems_count += 1
        if len(self.problems) < 5000:
            self.problems.append({"where": where, "what": what, "error": error})

    def run(self, on_key, on_value):
        root = self.hive.root
        stack = [(root, [], True)]
        visited = set()
        root_list = getattr(getattr(root, "header", None), "subkeys_list_offset", None)
        if root_list is not None:
            visited.add(root_list)
        while stack:
            if time.monotonic() > self.deadline_at:
                self.stopped_by_time = True
                self.problem("", "walk", "the time limit was reached after %d keys: %d branch(es) were not opened" % (self.keys, len(stack)))
                return
            node, names, descend = stack.pop()
            shown = "\\".join(names)
            self.keys += 1
            header = getattr(node, "header", None)
            lw = getattr(header, "last_modified", None)
            on_key({"row": "key", "path": shown, "name": node.name if names else "", "depth": len(names), "last_written": ft_iso(lw), "last_written_filetime": str(lw) if lw is not None else None,
                    "subkeys": getattr(node, "subkey_count", None), "values": getattr(node, "values_count", None)})
            seen_names = collections.Counter()
            try:
                for v in self.bounds.values(node, shown, _ProblemSink(self), trim_values=False):
                    self.values += 1
                    seen_names[v.name] += 1
                    kind = sensitive_value(names, v.name, str(v.value_type))
                    rec, payload = value_record(v, names, shown, kind, self.bounds)
                    rec["ordinal"] = seen_names[v.name]
                    self.type_counts[rec["type"]] += 1
                    on_value(rec, payload, kind)
            except Exception as exc:
                self.problem(shown, "values", "%s: %s" % (type(exc).__name__, exc))
            if not descend:
                continue
            if len(names) >= MAX_DEPTH:
                if getattr(node, "subkey_count", 0):
                    self.problem(shown, "subkeys", "deeper than %d levels: its subkeys are not read" % MAX_DEPTH)
                continue
            try:
                children = self.bounds.subkeys(node, shown, _ProblemSink(self))
            except Exception as exc:
                self.problem(shown, "subkeys", "%s: %s" % (type(exc).__name__, exc))
                continue
            for child in reversed(children):
                header = getattr(child, "header", None)
                lid = getattr(header, "subkeys_list_offset", None)
                enter = True
                if getattr(child, "subkey_count", 0) and lid is not None:
                    if lid in visited:
                        self.problem(shown + "\\" + child.name, "subkeys", "its subkey list (offset %s) was already reached: a cycle, or a list two keys share; it is not entered again" % lid)
                        enter = False
                    else:
                        visited.add(lid)
                stack.append((child, names + [child.name], enter))


class _ProblemSink:
    def __init__(self, walk):
        self.walk = walk

    def append(self, item):
        self.walk.problem(item.get("where", ""), item.get("what", ""), item.get("error", ""))


def read_state(hive_path, deadline_at, key_page, change_db, mode, values_file, changes_page, sensitive_log):
    """Walk a hive. mode 'index': fill the digest table only. mode 'export': write key and value rows to key_page and compare with the table."""
    walk = Walk(hive_path, deadline_at)
    seen_keys = set()

    def on_key(rec):
        if mode == "index":
            change_db.put("k", rec["path"], "", 1, digest_of(rec["last_written_filetime"], rec["subkeys"], rec["values"]))
            return
        key_page.add(rec)
        if change_db is not None:
            old = change_db.get("k", rec["path"], "", 1)
            if old is None:
                changes_page.add({"change": "key_added", "path": rec["path"], "last_written": rec["last_written"]})
            else:
                change_db.mark("k", rec["path"], "", 1)
                if old != digest_of(rec["last_written_filetime"], rec["subkeys"], rec["values"]):
                    changes_page.add({"change": "key_changed", "path": rec["path"], "last_written": rec["last_written"],
                                      "note": "its last-written time, subkey count or value count differs from the original's"})

    def on_value(rec, payload, kind):
        shown_digest = digest_of(rec["type"], sorted(payload.items(), key=lambda kv: kv[0]))
        if mode == "index":
            change_db.put("v", rec["key"], rec["name"], rec["ordinal"], shown_digest)
            return
        out = dict(rec)
        if kind:
            walk.withheld += 1
            out["withheld"] = kind
            out["withheld_why"] = "a value in a place or under a name that can hold a secret: its place, name, type and length are here, its bytes are not; write_values in a job run as secret output writes them"
            sensitive_log.append({"key": rec["key"], "name": rec["name"], "type": rec["type"], "length": rec["length"], "why": kind})
            values_file.add({**rec, **payload, "why": kind})
        else:
            out.update(payload)
        key_page.add(out)
        if change_db is not None:
            old = change_db.get("v", rec["key"], rec["name"], rec["ordinal"])
            if old is None:
                changes_page.add({"change": "value_added", "key": rec["key"], "name": rec["name"], "type": rec["type"], "length": rec["length"], **({} if kind else payload)})
            else:
                change_db.mark("v", rec["key"], rec["name"], rec["ordinal"])
                if old != shown_digest:
                    changes_page.add({"change": "value_changed", "key": rec["key"], "name": rec["name"], "type": rec["type"], "length": rec["length"], **({} if kind else payload)})

    walk.run(on_key, on_value)
    return walk


class ChangeDb:
    """The original's keys and values by digest, in a temporary SQLite file, so that a hive of millions of records is compared without being held."""

    def __init__(self, directory):
        import sqlite3
        fd, name = tempfile.mkstemp(dir=directory, prefix=".compare-", suffix=".sqlite")
        os.close(fd)
        TEMPS.append(name)
        self.name = name
        self.db = sqlite3.connect(name)
        self.db.execute("PRAGMA journal_mode=OFF")
        self.db.execute("PRAGMA synchronous=OFF")
        self.db.execute("CREATE TABLE t (kind TEXT, path TEXT, name TEXT, ord INTEGER, digest BLOB, seen INTEGER DEFAULT 0, PRIMARY KEY (kind, path, name, ord)) WITHOUT ROWID")
        self.count = 0

    def put(self, kind, path, name, ordinal, digest):
        self.db.execute("INSERT OR REPLACE INTO t (kind, path, name, ord, digest) VALUES (?,?,?,?,?)", (kind, path, name, ordinal, digest))
        self.count += 1
        if self.count % 50000 == 0:
            self.db.commit()

    def get(self, kind, path, name, ordinal):
        row = self.db.execute("SELECT digest FROM t WHERE kind=? AND path=? AND name=? AND ord=?", (kind, path, name, ordinal)).fetchone()
        return row[0] if row else None

    def mark(self, kind, path, name, ordinal):
        self.db.execute("UPDATE t SET seen=1 WHERE kind=? AND path=? AND name=? AND ord=?", (kind, path, name, ordinal))

    def removed(self):
        self.db.commit()
        return self.db.execute("SELECT kind, path, name, ord FROM t WHERE seen=0 ORDER BY kind, path, name, ord")

    def close(self):
        try:
            self.db.close()
        finally:
            try:
                os.unlink(self.name)
                TEMPS.remove(self.name)
            except (OSError, ValueError):
                pass


# ---- the run ---------------------------------------------------------------------------------------------------------------------------

def regfexport_counts(path, seconds):
    """An independent read of the hive: libregf's regfexport prints one 'Key path:' line per key and one 'Value:' line per value. The two counts, read
    from its output as it streams (nothing of the output is kept), and whether it finished."""
    import shutil
    program = shutil.which("regfexport")
    if not program:
        return {"ran": False, "why": "regfexport (libregf-utils) is not in this image"}
    try:
        proc = spawn([program, str(path)], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    except OSError as exc:
        return {"ran": False, "why": "regfexport could not be started: %s" % describe(exc)}
    ACTIVE.append(proc)
    keys = values = 0
    carry = b"\n"          # the first line of the output has a line break before it, as every other has
    end = time.monotonic() + max(seconds, 1.0)
    timed_out = False
    fd = proc.stdout.fileno()
    try:
        while True:
            left = end - time.monotonic()
            if left <= 0:
                kill_tree(proc)
                timed_out = True
                break
            # Wait for output for at most the time left: a program that prints nothing must not hold the tool past its clock.
            ready, _w, _x = select.select([fd], [], [], min(left, 1.0))
            if not ready:
                continue
            chunk = os.read(fd, 1 << 16)
            if not chunk:
                break
            data = carry + chunk
            keys += data.count(b"\nKey path: ")
            values += data.count(b"\nValue: ")
            carry = data[-12:]
        code = proc.wait()
    finally:
        if proc in ACTIVE:
            ACTIVE.remove(proc)
        try:
            proc.stdout.close()
        except OSError:
            pass
    return {"ran": True, "exit_code": code, "finished": not timed_out and code == 0, "keys": keys, "values": values,
            "counted_by": "the lines of its output that start 'Key path: ' and 'Value: ' (a value whose text holds such a line is counted too)"}


def output_directory(identity):
    job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
    name = "registry_recover-" + identity
    if job and out:
        base = Path(out)
    else:
        agent = re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool")
        base = Path.cwd() / "work" / agent
    return base / name


class FilePage(NoReplacePage):
    """A paging file placed in the tool's own output directory under a fixed name, never replacing an earlier file."""

    def __init__(self, directory, name, key, limit):
        super().__init__("registry_recover", key, limit)
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


def sha256_file(path):
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for piece in iter(lambda: fh.read(BLOCK), b""):
            h.update(piece)
    return h.hexdigest()


def place_json(directory, name, value):
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".receipt-")
    TEMPS.append(tmp)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(value, fh, indent=1)
        fh.write("\n")
    placed = place_without_replacing(Path(tmp), directory / name)
    if tmp in TEMPS:
        TEMPS.remove(tmp)
    return placed


def check_args(args):
    if not isinstance(args, dict):
        fail("the arguments are one JSON object")
    hive = args.get("hive")
    if not isinstance(hive, str) or not hive:
        fail("hive is required: the path of the registry hive file (a copy)")
    logs = []
    for role in ("log1", "log2"):
        value = args.get(role)
        if value is not None and (not isinstance(value, str) or not value):
            fail("%s must be the path of a transaction log file" % role)
        if value:
            logs.append((role, value))
    write_values = args.get("write_values", False)
    if not isinstance(write_values, bool):
        fail("write_values must be true or false")
    limit = args.get("limit", 200)
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        fail("limit must be a positive whole number", limit=limit)
    seconds = args.get("max_seconds", DEFAULT_SECONDS)
    if isinstance(seconds, bool) or not isinstance(seconds, (int, float)) or not 1 <= seconds <= MAX_SECONDS:
        fail("max_seconds must be a number from 1 to %d" % MAX_SECONDS, max_seconds=seconds)
    export = args.get("export", True)
    if not isinstance(export, bool):
        fail("export must be true or false")
    return hive, logs, write_values, limit, float(seconds), export


def refuse_special(path, what):
    try:
        mode = os.stat(path).st_mode
    except OSError as exc:
        fail("%s could not be examined" % what, path=path, reason=describe(exc))
    if not stat.S_ISREG(mode):
        fail("%s is not a regular file, so it was not opened (a pipe or a device is never opened)" % what, path=path, not_attempted=1)


def main():
    install_signal_handlers()
    STATE["last_word"] = last_word
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    hive_path, logs, write_values, limit, seconds, export = check_args(args)
    refuse_special(hive_path, "the hive")
    for role, path in logs:
        if not os.path.exists(path):
            fail("the %s named does not exist" % role, path=path)
    if write_values:
        job, out = os.environ.get("JOB_ID") or "", os.environ.get("OUT") or ""
        if not (job and out) or os.environ.get("SECRET_OUTPUT") != "1":
            fail("write_values is refused: the values of what is withheld are written only in a job the harness runs as secret output (job_run with secret_output: true). Nothing was written.")
    set_deadline(seconds)
    started = time.monotonic()
    hive_size = os.path.getsize(hive_path)
    if hive_size > MAX_HIVE_BYTES:
        fail("the hive is larger than the %d bytes this tool reads" % MAX_HIVE_BYTES, bytes=hive_size)
    with open(hive_path, "rb") as fh:
        hive, _block = read_base(fh, hive_size)
    identity_parts = [hive_path, sha256_file(hive_path)] + [sha256_file(p) if os.path.isfile(p) else p for _r, p in logs]
    import hashlib
    identity = hashlib.sha256(json.dumps(identity_parts).encode("utf-8")).hexdigest()[:12]
    directory = output_directory(identity)
    try:
        directory.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        fail("the output directory could not be made", reason=describe(exc))
    values_file = ValuesFile(write_values, directory)

    receipt = {"parser": PARSER, "hive_original": {"path": hive_path, "bytes": hive_size, **{k: v for k, v in hive.items() if k not in ("bytes_read", "problems")}, "problems": hive.get("problems", [])}}
    receipt["hive_original"]["sha256"] = identity_parts[1]
    replay_receipt, log_receipts, unrecovered, working = replay(hive_path, hive_size, hive, logs, directory)
    receipt["replay"] = replay_receipt
    receipt["logs"] = log_receipts
    recovered_path = None
    if working is not None:
        recovered_path = place_without_replacing(working, directory / "recovered.hive")
        TEMPS[:] = [t for t in TEMPS if t != str(working)]
        os.chmod(recovered_path, 0o644)
        receipt["recovered"] = {"path": shown_path(recovered_path), "bytes": os.path.getsize(recovered_path), "sha256": sha256_file(recovered_path)}
        with open(recovered_path, "rb") as fh:
            after, _b = read_base(fh, os.path.getsize(recovered_path))
        receipt["recovered"]["base_block"] = {k: v for k, v in after.items() if k not in ("bytes_read",)}
    # The records of the state read.
    export_receipt = {"requested": export, "source": None, "status": "not requested" if not export else "not started"}
    sensitive_log = []
    problems = []
    if export and hive.get("signature_ok"):
        read_from = recovered_path or Path(hive_path)
        export_receipt["source"] = "the recovered copy" if recovered_path else "the hive as it is (nothing was applied)"
        try:
            import regipy.registry  # noqa: F401
        except ImportError as exc:
            export_receipt.update(status="failed", why="regipy is not installed: python3 -m pip install regipy")
        else:
            withhold_library_output()
            key_page = FilePage(directory, "keys.jsonl", [identity, "keys"], limit)
            changes_page = FilePage(directory, "changes.jsonl", [identity, "changes"], limit)
            change_db = None
            try:
                comparing = recovered_path is not None
                original = None
                compare_failed = None
                if comparing:
                    change_db = ChangeDb(directory)
                    try:
                        original = read_state(hive_path, time.monotonic() + seconds * 0.4, None, change_db, "index", values_file, None, [])
                        export_receipt["original_walk"] = {"keys": original.keys, "values": original.values, "stopped_by_time_limit": original.stopped_by_time,
                                                           "problem_count": original.problems_count}
                        original.release()      # the library holds a hive in memory: the original's is let go before the recovered copy is read
                    except Exception as exc:
                        compare_failed = "the original hive could not be read by regipy (%s), so the recovered state is not compared with it" % type(exc).__name__
                        change_db.close()
                        change_db = None
                walk = read_state(str(read_from), CLOCK["deadline"], key_page, change_db, "export", values_file, changes_page, sensitive_log)
                walk.release()
                removed = 0
                if change_db is not None and not original.stopped_by_time and not walk.stopped_by_time:
                    for kind, path, name, ordinal in change_db.removed():
                        removed += 1
                        changes_page.add({"change": "key_removed" if kind == "k" else "value_removed", "path" if kind == "k" else "key": path, **({} if kind == "k" else {"name": name})})
                keys_result, changes_result = key_page.finish(), changes_page.finish()
                export_receipt.update({
                    "status": "complete" if not walk.stopped_by_time and not walk.problems_count else "partial",
                    "keys": walk.keys, "values": walk.values, "value_types": dict(sorted(walk.type_counts.items())),
                    "withheld_values": len(sensitive_log), "problem_count": walk.problems_count, "walk_stopped_by_time_limit": walk.stopped_by_time,
                    "keys_file": keys_result.get("all_results"), "keys_inline": key_page.page,
                    "library_messages_withheld": LibraryLog.messages,
                })
                if comparing and compare_failed:
                    export_receipt["changes"] = {"compared": False, "why": compare_failed}
                elif comparing:
                    both_whole = not original.stopped_by_time and not walk.stopped_by_time
                    export_receipt["changes"] = {"compared": both_whole, "count": changes_result["matched"], "removed": removed,
                                                 "file": changes_result.get("all_results"), "inline": changes_page.page,
                                                 "note": "keys and values of the recovered copy that are not in the original, are not in the recovered copy, or differ; a withheld value is compared by its bytes and shown by place only"}
                    if not both_whole:
                        export_receipt["status"] = "partial"
                        export_receipt["changes"]["note"] += "; a walk stopped at the time limit, so what is listed is not the whole difference"
                reader = regfexport_counts(read_from, max(5.0, CLOCK["deadline"] - time.monotonic() - 2)) if not walk.stopped_by_time else {"ran": False, "why": "the walk stopped at the time limit, so its counts are not whole"}
                if reader.get("ran") and reader.get("finished"):
                    reader["agrees"] = reader["keys"] == walk.keys and reader["values"] == walk.values
                    reader["regipy"] = {"keys": walk.keys, "values": walk.values}
                export_receipt["independent_reader"] = {"regfexport": reader}
                if reader.get("agrees") is False:
                    export_receipt["status"] = "partial"
                problems = walk.problems[:INLINE_PROBLEMS]
                export_receipt["problems"] = problems
                if walk.problems_count > INLINE_PROBLEMS:
                    export_receipt["problems_not_shown"] = walk.problems_count - INLINE_PROBLEMS
            except Exception as exc:
                export_receipt.update(status="failed", why="%s: %s" % (type(exc).__name__, exc))
            finally:
                if change_db is not None:
                    change_db.close()
    elif export:
        export_receipt.update(status="failed", why="the hive has no 'regf' base block: no record was read")
    receipt["records"] = export_receipt
    receipt["sensitive_values_withheld"] = sensitive_log[:INLINE_PROBLEMS]
    receipt["sensitive_values_withheld_count"] = len(sensitive_log)
    values_file.close()
    receipt["values_file"] = values_file.shown
    receipt["unrecovered"] = unrecovered[:INLINE_PROBLEMS]
    receipt["unrecovered_count"] = len(unrecovered)
    if len(unrecovered) > INLINE_PROBLEMS:
        receipt["unrecovered_not_shown"] = len(unrecovered) - INLINE_PROBLEMS
    reasons = []
    dirty_left = bool(hive.get("signature_ok")) and (receipt["replay"]["dirty_before"] and not receipt["replay"]["performed"])
    if not hive.get("signature_ok"):
        status, basis = "failed", "the hive has no 'regf' base block"
    else:
        if dirty_left:
            reasons.append("the hive is dirty and no replay was performed: %s" % receipt["replay"]["reason"])
        if unrecovered:
            reasons.append("%d log entr%s or range%s were not applied (unrecovered)" % (len(unrecovered), "y" if len(unrecovered) == 1 else "ies", "" if len(unrecovered) == 1 else "s"))
        if export and export_receipt.get("status") != "complete":
            reasons.append("the key and value records are %s" % export_receipt.get("status"))
        reader_said = (export_receipt.get("independent_reader") or {}).get("regfexport") or {}
        if reader_said.get("agrees") is False:
            reasons.append("regfexport counted %d keys and %d values where regipy counted %d and %d" % (
                reader_said["keys"], reader_said["values"], reader_said["regipy"]["keys"], reader_said["regipy"]["values"]))
        if hive.get("problems"):
            reasons.append("the hive's base block has a problem: " + "; ".join(hive["problems"]))
        if receipt["replay"].get("time_limit"):
            reasons.append(receipt["replay"]["time_limit"])
        status = "partial" if reasons else "complete"
        if reasons:
            basis = "; ".join(reasons)
        else:
            said = []
            if not receipt["replay"]["dirty_before"]:
                said.append("the hive is clean, so nothing was replayed")
            elif receipt["replay"]["performed"]:
                said.append("the replay applied %d entr%s up to sequence %d, and every named log entry that follows was applied or is older than the state the hive was at" % (
                    receipt["replay"]["entries_applied"], "y" if receipt["replay"]["entries_applied"] == 1 else "ies", receipt["replay"]["sequence_after"][0] - 1))
            if export:
                said.append("every key and value of the state read was written")
            basis = "; ".join(said)
    receipt["status"], receipt["status_basis"] = status, basis
    placed = place_json(directory, "receipt.json", receipt)
    answer = {"parser": PARSER, "status": status, "status_basis": basis, "hive": hive_path,
              "dirty_before": receipt["replay"]["dirty_before"], "replayed": receipt["replay"]["performed"],
              "sequence_before": receipt["replay"]["sequence_before"], "sequence_after": receipt["replay"].get("sequence_after"),
              "entries_applied": receipt["replay"]["entries_applied"], "unrecovered_count": len(unrecovered), "unrecovered": receipt["unrecovered"],
              "recovered_copy": receipt.get("recovered", {}).get("path"), "receipt": shown_path(placed),
              "records": {k: v for k, v in export_receipt.items() if k not in ("keys_inline",)},
              "keys_inline": export_receipt.get("keys_inline", []),
              "sensitive_values_withheld_count": len(sensitive_log), "values_file": values_file.shown,
              "contains_secret_values": values_file.written > 0,
              "elapsed_seconds": round(time.monotonic() - started, 2)}
    print(json.dumps(answer, indent=1))


def last_word(signum):
    forget_temps()
    print(json.dumps({"error": "stopped by signal %d before the answer was complete" % signum, "status": "interrupted",
                      "status_basis": "the tool was stopped by signal %d; nothing it had made is a result (the temporary files were removed)" % signum, "signal": signum}), flush=True)


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
