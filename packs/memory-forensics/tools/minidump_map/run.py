#!/usr/bin/env python3
"""Map a Windows process dump (a minidump, MDMP): its streams, its modules, its memory ranges, and what of each is in the file.

A minidump is one process, written by a debugger call (MiniDumpWriteDump: Task Manager, procdump, WerFault, a tool an intruder brought). It
is not a memory image: there is no kernel, no other process, no page tables, and a framework for full images (Volatility, MemProcFS) does
not read it. What it holds is a directory of streams; this tool reads them from the layouts the format's headers publish (minidumpapiset.h)
and answers one `view` a call:

    summary   the header, the dump's flags and what kind of dump it is, every stream of the directory, the system, the process (id, times,
              integrity), the exception, the writer's comment, the handle counts, the command line when the PEB can be reached, the totals
    modules   the loaded and unloaded modules: base, size, name, timestamp, checksum, version, the PDB record, and how much of each image
              is in the dump
    memory    the ranges of memory the dump holds (list: ranges), each with the protection, state and type the MemoryInfoList gives it, or
              the regions of the MemoryInfoList themselves (list: regions), in the dump or not
    threads   the threads: id, TEB, stack, the register values of an x86 or x64 context, start address, times and name
    va        one address or a list: the file offset of each, or that it is not in the dump
    read      the bytes of an address range, written to a file
    module    one module's image as it lay in memory, written to a file, with a coverage figure
    find      a text or hex needle in the memory the dump holds: the address and the file offset of every hit

THREE RULES THE ANSWERS HOLD TO.
1. An address that is not in the dump is not zero. The dump holds the ranges its writer chose; the rest of the address space is absent, and
   an answer says "not in the dump" for it. Nothing here invents a byte.
2. A module read from a dump can have gaps (pages that were never loaded, or that the writer left out). `module` and `read` give the count of
   bytes present and absent. With gaps they write nothing unless `allow_gaps` is true; then the absent bytes are zero in the file, every
   one of them is listed in the map file beside it (<name>.map.json), and the status is partial. A file without gaps says so.
3. `complete` means every byte and every record the view covers was read. A stream that runs past the end of the file, declares more
   entries than it holds, or is not laid out as the format says is named (the stream, the file offset) and the status is partial; the
   records before the fault are reported. A file that is not a minidump is refused.

WHAT IS PRINTED. Addresses are printed as hexadecimal strings and file offsets as integers. A string read from the dump (a module path, a
PDB path, a service pack string, a thread name, the command line) goes through the shared SHOWN rules: a part that looks like a secret is
replaced by a placeholder that says how long it was; withholding is by shape, so a plain password in a command line is printed. Memory
content itself is never printed: `find` gives positions, `read` and `module` write files. Those files are memory content (a credential can
be in any page), so writing needs `write_values: true`, a job, and a job run as secret output (SECRET_OUTPUT=1, which the manifest makes the
harness set): $OUT/minidump_map, directory 0700, files 0600, created exclusively and placed without replacing an earlier file; the
sha256 of each goes to manifest.jsonl beside them, with its size, and not into the answer (the size it gives is the length asked for). Without write_values, `read` and `module` still say what is present and what
is not, and write nothing.

BOUNDS. Lists are paged by `offset` and `limit`: every paged answer says total, returned and next_offset, and a page is cut at 256 KiB of
JSON as well. `find` reads the dump in 8 MiB pieces (the memory the tool uses does not grow with the dump), stops at `max_hits` or at
`max_seconds` with status partial and `resume_va`, the address to pass as `va_start` for the rest: every hit that starts below it is in
the answer and none that starts at or above it is, so the calls together give each hit once. The hits that start at one address (the
UTF-8 and UTF-16LE forms of a one-character needle) are never split by a stop: when they alone would pass max_hits at the head of an
answer, all of them are given and page.same_address_note says so. `read` writes at most 64 MiB and `module`
at most 512 MiB a call. At most 250,000 memory ranges, 250,000 regions, 16,384 modules, 65,536 threads and 250,000 handles are read; a
dump that declares more is partial and says so. Every handle's type name is read, and 512 distinct names are listed.

THE CLOCK. `max_seconds` is the clock of the whole call, counted from when the arguments are read, and every loop over something the dump
sizes looks at it. A loop that can say where it stopped does so (a page of a list, the search, the addresses of `va`, the type names of
the handles, the lines of a comment); any other (reading a table, comparing module names, counting coverage, writing a file) ends the
call with one failed answer that says what it was doing, and keeps nothing. What can run past it is one unit of work: one string put
through the display rules, one piece read, one write; and `find` may name the modules of the hits it has for 5 seconds more. The loops
that do not look at it are bounded by a constant and not by the dump: the retries of a read or a write that came back short (each makes
progress or ends), the 999 names tried for an output file, the registers and flags of a record.

STOPS. SIGTERM, SIGINT and SIGHUP end the call with one JSON document (status failed, interrupted true, exit 128 plus the signal); a file
that was being written is removed, and so is an image whose map was not yet placed beside it. A signal that arrives while the answer is written is held until it is out.
"""

# BEGIN SHARED ENDS
# The same text is in every pack tool and recipe and in their tool-library twins, before the file's own imports (tests/shared-blocks-census.test.ts
# holds the copies equal): the two ends of a call, where a stop signal (SIGTERM, SIGINT, SIGHUP) found no handler, or one that did harm.
# * The start. From here a stop is answered by ONE JSON document and exit 128 + the signal, until the tool installs its own handlers (which then
#   answer it), and for good for a signal the tool never takes. Only the start of the interpreter and the compiling of the file come before
#   it: a stop there ends the process with no answer, before anything was read. answer_a_stop() is that document: a handler whose own last word
#   wrote nothing on standard output calls it before it ends the process, so that a stop is never answered by silence.
# * The end. The interpreter's own teardown resets the handlers to their defaults before it frees what the call held, and a stop that landed
#   there killed a process that had printed its whole answer; a handler that raises, writes a last word or ends the process, run once the
#   answer was decided, wrote a second document, a traceback, or nothing at all. Python runs a handler on the main thread whichever thread the
#   signal reached, so a mask of the main thread alone holds nothing while another thread runs. hold_stop_signals() holds the stop signals for
#   good: blocked in this thread and given a handler that does nothing, which is the hold whatever thread the signal reaches; an error Python
#   can only report from then on (a file left open whose last write the file system refuses, closed when the frame that held it is freed) is
#   not printed (3.11 and 3.12 say nothing of it, 3.14 a traceback). A handler that was due runs on the way in: what it raises reaches the
#   writer that asked (the tool's own handling then answers the stop, before any byte of the answer), or, quietly, is dropped (the end of a
#   call, an error branch). Every writer of a final answer calls it before it commits to writing, every error branch at the end calls it
#   quietly, and, when the file runs as a program, standard output is wrapped so that its first write calls it too. _code(stop) is a
#   SystemExit's exit code (its text, if it has one, goes to standard error as the interpreter puts it), and _leave(code) ends the call: both
#   hold the signals first, quietly; _leave flushes
#   standard output (a write that fails there makes a 0 an exit 120, as the interpreter does) and standard error, runs the atexit hooks (a hook
#   that removes a temporary file), each step on its own and none able to raise, and ends the process with os._exit, never through the teardown.
# The modules are imported here, as the file is loaded, never inside the ending (an import there ran a due handler inside the import system).
import atexit
import json
import os
import signal
import sys

_ENDING = {"held": False, "program": __name__ == "__main__"}      # imported (a test that loads the file as a module), the block holds nothing
_ENDING_SIGNALS = (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)


def answer_a_stop(signum, when="before it had answered"):
    """The one document of a stop that ends the call before any answer was begun (nothing once one has): status failed, interrupted, and
    no claim about what was read or written. A handler whose own last word printed nothing calls it before it ends the process. It writes
    only when the file runs as a program: its wrapped standard output is what knows whether an answer was begun."""
    if _ENDING["held"] or not isinstance(sys.stdout, _AnswerStream):
        return
    _ENDING["held"] = True
    name = {signal.SIGTERM: "SIGTERM", signal.SIGINT: "SIGINT", signal.SIGHUP: "SIGHUP"}.get(signum, "signal %d" % signum)
    text = json.dumps({"error": "the tool was stopped by %s %s" % (name, when), "status": "failed", "interrupted": name,
                       "status_basis": "stopped by %s %s: no answer was made, and what it had read or written by then is not described" % (name, when)})
    try:
        os.write(1, (text + "\n").encode("ascii"))
    except OSError:
        pass


def _stopped_without_handler(signum, _frame):
    for other in _ENDING_SIGNALS:
        try:
            signal.signal(other, signal.SIG_IGN)
        except (ValueError, OSError):
            pass
    answer_a_stop(signum, "while it was being loaded, or at a point where it has no stop handling of its own")
    os._exit(128 + signum)


def _ending_nothing(*_ignored):
    """The stop signals' handler, and sys.unraisablehook, once the answer has begun: nothing."""


def hold_stop_signals(quietly=False):
    """Hold the stop signals for good. A handler that was due runs on the way in, before the hold and before any byte of the answer, and what
    it raises is raised here, so that the tool's own handling of a stop answers it; quietly (the end of a call, an error branch, where nothing
    may escape) it is dropped and the hold is made all the same. Called by a thread that is not the main one, it blocks the signals there and
    leaves the rest to the main thread's next call."""
    for _attempt in range(len(_ENDING_SIGNALS) + 2):
        if _ENDING["held"] or not _ENDING["program"]:
            return
        try:
            try:
                signal.pthread_sigmask(signal.SIG_BLOCK, _ENDING_SIGNALS)
            except (AttributeError, ValueError, OSError):
                pass                  # no pthread_sigmask here: the handler below is the hold
            main_thread = True
            for signum in _ENDING_SIGNALS:
                try:
                    signal.signal(signum, _ending_nothing)
                except (ValueError, OSError):
                    main_thread = False
            sys.unraisablehook = _ending_nothing
            _ENDING["held"] = main_thread
            return
        except BaseException:  # noqa: BLE001 - a handler that was due ran on the way in, and raised
            if not quietly:
                raise



class _AnswerStream:
    """Standard output of a call: the first write holds the stop signals (above); everything else is the stream's own."""

    def __init__(self, stream):
        self._stream = stream

    def write(self, text):
        if not _ENDING["held"]:
            hold_stop_signals()
        return self._stream.write(text)

    def writelines(self, lines):
        if not _ENDING["held"]:
            hold_stop_signals()
        return self._stream.writelines(lines)

    def __getattr__(self, name):
        if name == "_stream":
            raise AttributeError(name)
        return getattr(self._stream, name)


def _code(stop):
    hold_stop_signals(quietly=True)
    code = getattr(stop, "code", 1)
    if isinstance(code, int):
        return code
    if code is not None:
        try:
            sys.stderr.flush()
            os.write(2, ("%s\n" % (code,)).encode("utf-8", "backslashreplace"))
        except BaseException:  # noqa: BLE001
            pass
    return 0 if code is None else 1


def _leave(code):
    hold_stop_signals(quietly=True)
    code = code if isinstance(code, int) else 1
    try:
        sys.stdout.flush()
    except BaseException:  # noqa: BLE001 - a reader that is gone: the answer did not reach it
        code = code or 120
    try:
        sys.stderr.flush()
    except BaseException:  # noqa: BLE001
        pass
    try:
        atexit._run_exitfuncs()
    except BaseException:  # noqa: BLE001 - a hook that fails is not a failure of the answer
        pass
    os._exit(code)


if __name__ == "__main__":
    if sys.stdout is not None and not isinstance(sys.stdout, _AnswerStream):
        sys.stdout = _AnswerStream(sys.stdout)
    for _signum in _ENDING_SIGNALS:
        signal.signal(_signum, _stopped_without_handler)
# END SHARED ENDS


import json
import os
import signal
import sys

PARSER = "minidump_map/3"
TOOL = 7


def _before_start(signum, _frame):
    """A stop that arrives while the rest of the module is still loading: nothing was read or written yet, and the one answer says so."""
    sys.stdout.write(json.dumps({
        "error": "stopped by signal %d before the dump was read" % signum, "status": "failed", "interrupted": True,
        "status_basis": "the tool was stopped by signal %d before it read or wrote anything; nothing is a finding, and the call can be "
                        "repeated as it was" % signum,
        "signal": signum, "parser": PARSER}) + "\n")
    sys.stdout.flush()
    os._exit(128 + signum)


for _signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
    signal.signal(_signum, _before_start)   # replaced by run_guarded() once the module is loaded

import bisect  # noqa: E402  (after the early handler, so a stop during these imports is answered too)
import datetime  # noqa: E402
import errno  # noqa: E402
import hashlib  # noqa: E402
import re  # noqa: E402
import stat  # noqa: E402
import struct  # noqa: E402
import time  # noqa: E402
from pathlib import Path  # noqa: E402

MAX_STDIN = 1 << 20
MAX_TEXT = 4096
U64 = (1 << 64) - 1
CHUNK = 8 << 20                 # bytes of the dump held at once by find, read and module
INLINE_BYTES = 256 << 10        # JSON bytes of rows one page may hold
DEFAULT_LIMIT, MAX_LIMIT = 100, 1000
DEFAULT_SECONDS, MAX_SECONDS, MIN_SECONDS = 120, 240, 1      # inside the manifest's 300
DEFAULT_HITS, MAX_HITS = 200, 1000
MAX_NEEDLE = 1024               # bytes of one encoded needle
MAX_ADDRESSES = 256
READ_MAX = 64 << 20
MODULE_MAX = 512 << 20
MAX_STREAMS = 4096
HEADER_BYTES = 32                  # the MINIDUMP_HEADER: no location that points into it is read as a record or as memory
MAX_RANGES = 250_000
MAX_REGIONS = 250_000
MAX_MODULES = 16_384
MAX_THREADS = 65_536
MAX_HANDLES = 250_000
MAX_HANDLE_TYPES = 512          # distinct type names the handle count lists; handles of a further name are counted apart
PDB_PATH_BYTES = 520            # bytes of the path of a PDB record that are read
DESCRIBE_GRACE = 5              # seconds past max_seconds that find may spend on naming the modules of the hits it already has
TABLE_BYTES = 64 << 20          # bytes of one stream's table held at once, whatever entry size its header declares
MAX_ENTRY = 4096                # bytes of one table entry a header may declare
MAX_STRING_BYTES = 8192         # of one MINIDUMP_STRING (a path is at most 32,767 characters; more than this is cut and said)
MAX_PROBLEMS = 50
MAX_GAPS_INLINE = 50
VIEWS = ("summary", "modules", "memory", "threads", "va", "read", "module", "find")

STREAM_NAMES = {
    0: "Unused", 1: "Reserved0", 2: "Reserved1", 3: "ThreadList", 4: "ModuleList", 5: "MemoryList", 6: "Exception", 7: "SystemInfo",
    8: "ThreadExList", 9: "Memory64List", 10: "CommentA", 11: "CommentW", 12: "HandleData", 13: "FunctionTable", 14: "UnloadedModuleList",
    15: "MiscInfo", 16: "MemoryInfoList", 17: "ThreadInfoList", 18: "HandleOperationList", 19: "Token", 20: "JavaScriptData",
    21: "SystemMemoryInfo", 22: "ProcessVmCounters", 23: "IptTrace", 24: "ThreadNames",
}
FLAG_NAMES = [
    (0x1, "WithDataSegs"), (0x2, "WithFullMemory"), (0x4, "WithHandleData"), (0x8, "FilterMemory"), (0x10, "ScanMemory"),
    (0x20, "WithUnloadedModules"), (0x40, "WithIndirectlyReferencedMemory"), (0x80, "FilterModulePaths"), (0x100, "WithProcessThreadData"),
    (0x200, "WithPrivateReadWriteMemory"), (0x400, "WithoutOptionalData"), (0x800, "WithFullMemoryInfo"), (0x1000, "WithThreadInfo"),
    (0x2000, "WithCodeSegs"), (0x4000, "WithoutAuxiliaryState"), (0x8000, "WithFullAuxiliaryState"), (0x10000, "WithPrivateWriteCopyMemory"),
    (0x20000, "IgnoreInaccessibleMemory"), (0x40000, "WithTokenInformation"), (0x80000, "WithModuleHeaders"), (0x100000, "FilterTriage"),
    (0x200000, "WithAvxXStateContext"), (0x400000, "WithIptTrace"), (0x800000, "ScanInaccessiblePartialPages"),
]
ARCH = {0: "x86", 5: "ARM", 6: "IA64", 9: "x64", 12: "ARM64"}
PRODUCT = {1: "workstation", 2: "domain controller", 3: "server"}
PROTECT = {0x01: "NOACCESS", 0x02: "READONLY", 0x04: "READWRITE", 0x08: "WRITECOPY", 0x10: "EXECUTE", 0x20: "EXECUTE_READ",
           0x40: "EXECUTE_READWRITE", 0x80: "EXECUTE_WRITECOPY"}
PROTECT_MOD = [(0x100, "GUARD"), (0x200, "NOCACHE"), (0x400, "WRITECOMBINE")]
STATE = {0x1000: "COMMIT", 0x2000: "RESERVE", 0x10000: "FREE"}
MEMTYPE = {0x20000: "PRIVATE", 0x40000: "MAPPED", 0x1000000: "IMAGE"}
EXCEPTIONS = {0x80000003: "BREAKPOINT", 0x80000004: "SINGLE_STEP", 0xC0000005: "ACCESS_VIOLATION", 0xC000001D: "ILLEGAL_INSTRUCTION",
              0xC0000094: "INTEGER_DIVIDE_BY_ZERO", 0xC00000FD: "STACK_OVERFLOW", 0xC0000374: "HEAP_CORRUPTION",
              0xC0000409: "STACK_BUFFER_OVERRUN", 0xE06D7363: "C++ exception", 0xC0000420: "ASSERTION_FAILURE"}
INTEGRITY = {0x0000: "untrusted", 0x1000: "low", 0x2000: "medium", 0x2100: "medium plus", 0x3000: "high", 0x4000: "system",
             0x5000: "protected process"}
# Which streams a view's answer rests on: a fault in one of them makes that view partial (the header and the directory count for all).
VIEW_STREAMS = {
    "summary": None,            # every stream
    "modules": {"ModuleList", "UnloadedModuleList", "MemoryList", "Memory64List"},
    "memory": {"MemoryList", "Memory64List", "MemoryInfoList", "ModuleList"},     # a row names the module that holds its address
    "threads": {"ThreadList", "ThreadExList", "ThreadInfoList", "ThreadNames", "SystemInfo", "ModuleList", "MemoryList", "Memory64List"},
    "va": {"MemoryList", "Memory64List", "MemoryInfoList", "ModuleList"},
    "read": {"MemoryList", "Memory64List", "ModuleList"},
    "module": {"MemoryList", "Memory64List", "ModuleList"},
    "find": {"MemoryList", "Memory64List", "MemoryInfoList", "ModuleList"},
}

# BEGIN SHARED WITHHOLDING
# The same text is in every tool that withholds identifier-shaped strings and credentials (the network, base, encrypted-containers,
# memory, virtualization, ransomware and reverse-engineering packs, and the three tools of the cloud pack), so that they withhold the
# same strings; the tests that hold the copies equal are tests/shared-blocks-census.test.ts (how many carry it),
# tests/pack-re-delta10.test.ts (every copy equal, found by the marker), tests/pack-network-withholding.test.ts,
# tests/pack-base-shared.test.ts, tests/pack-virtualization-shared.test.ts, tests/pack-re-process.test.ts and
# tests/pack-cloud-shared.test.ts. An identifier-shaped string is withheld wherever the tool would print one: a name, a path
# component, a URL, a message that quotes either; and a credential (a value given to a password, a token, a cookie, a pair, a
# switch) by the name it is given under. A carrier may set two names above this block: WITHHOLD_LIMIT, the length past which a text is
# withheld whole (65536 when it sets none), and WITHHOLD_TICK, a hook that long scans call and that may raise to end them at the
# carrier's deadline (none when it sets none). Nothing else in the block is a carrier's to change.
COUNTS = {"names": 0, "urls": 0, "text": 0}
# A run of name characters long enough to be a token. `=` is only a padding at the end (so a key= prefix stays);
# `/` joins pieces of a base64 token and is handled apart, below.
_RUN = re.compile(r"[A-Za-z0-9_+%-]{20,}={0,2}|[A-Za-z0-9_+%-]{14,}={2}")
_SLASHED = re.compile(r"[A-Za-z0-9_+/%-]{30,}={0,2}")
_HEX = re.compile(r"[0-9a-fA-F]{32,}")
# The prefixed secrets that one expression finds. A JWT is not among them: `eyJ` + 8 name characters + `.` + 8 + `.` + the rest, tried at
# every `eyJ`, runs to the end of the run of name characters and fails again at each next `eyJ` of a text made of them, which costs the
# square of the length. `_prefixed_spans` reads a JWT in one pass instead, and puts it in order with these.
_PREFIX_RULES = re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}"
                           r"|xox[abeprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9_-]{20,}"
                           r"|(?i:basic|bearer)\s+[A-Za-z0-9+/=._~-]{8,}")
_JWT_RUN = re.compile(r"[A-Za-z0-9_-]+")
# User-info: after `//` (a URL, or a scheme-relative one), or bare as name:password@host. A mailto: address is not one.
_USERINFO = re.compile(r"(?<=//)[^/?#\s@]+(?=@)")
_BARE_USERINFO = re.compile(r"(?<![\w.%+:/-])(?!mailto:)[\w.%+-]{1,64}:[^\s/@:]{1,128}(?=@[\w\[])")


def _withheld(what, length, kind):
    COUNTS[kind] = COUNTS.get(kind, 0) + 1
    return ("<%s withheld %d characters>" % (what, length)) if what else ("<withheld %d characters>" % length)


def _token_run(run):
    """Is this run of name characters shaped like a token, and not like words, dates or versions?"""
    if _HEX.search(run):
        return True
    chunks = [(m.group()[0].isdigit(), m.start(), m.end()) for m in re.finditer(r"[A-Za-z]+|[0-9]+", run)]
    # digits packed between letters ("a9b2c7"), which words, dates and versions do not do
    packed = 0
    for i, (is_digit, start, end) in enumerate(chunks):
        if not is_digit or end - start > 3:
            continue
        before = i > 0 and not chunks[i - 1][0] and chunks[i - 1][2] == start
        after = i + 1 < len(chunks) and not chunks[i + 1][0] and chunks[i + 1][1] == end
        packed += 1 if before or after else 0
    if packed >= 3:
        return True
    letters = [c for c in run if c.isalpha()]
    case_flips = sum(1 for a, b in zip(letters, letters[1:]) if a.islower() != b.islower())
    if len(letters) >= 20 and case_flips >= max(8, 0.4 * len(letters)):
        return True
    if run.endswith("==") and len(run) >= 16:
        return True
    if run.endswith("=") and len(run) >= 24:
        return True
    return len(run) >= 40 and run.isalnum() and any(c.isdigit() for c in run) and any(c.isalpha() for c in run)


def _randomish(piece):
    """A piece of a path that is not a plain word: digits among letters, or capitals inside a word."""
    if len(piece) < 4 or "." in piece or re.fullmatch(r"[A-Z][a-z]+", piece):
        return False
    letters = [c for c in piece if c.isalpha()]
    mixed = any(c.islower() for c in letters) and any(c.isupper() for c in letters)
    return (any(c.isdigit() for c in piece) and bool(letters)) or mixed


_SPAN_PIECE = re.compile(r"[A-Za-z0-9_+%-]+")
# A text longer than this is withheld whole, by its length, and not examined: no name, path or URL is tens of thousands of characters
# long, and the answer says how long the text was. Every rule below reads a text of this length in well under a second whatever its
# characters are, so that no call of `scrub` or `token_spans` can run for long on a text a file chose; the limit is the backstop for
# a shape of text that no rule was tried on, and the rules themselves are linear.
TEXT_LIMIT = globals().get("WITHHOLD_LIMIT", 65536)


def _prefixed_spans(text, tail=None):
    """The spans of the prefixed secrets in the text (a vendor prefix, a JWT, `Basic`/`Bearer` and its value), left to right and apart,
    as one expression holding all of them would find them (the first match at each offset, the next search where the last ended), in
    time linear in the text. With `tail`, an expression matched where each span ends, the span takes what it matches.

    A JWT is read from the runs of name characters (`[A-Za-z0-9_-]+`), cut once: its head is the first `eyJ` of a run that is followed
    by 8 or more characters of that run, and it ends where the third part of the JWT does; every later `eyJ` of the run reads the same
    rest, so the first one is the one that matches and a run that does not hold a JWT is not read again for each `eyJ` in it."""
    from bisect import bisect_right
    size = len(text)
    starts, ends, rest = [], [], {}
    if "eyJ" in text:
        for m in _JWT_RUN.finditer(text):
            starts.append(m.start())
            ends.append(m.end())

    def jwt_end(r):      # where a JWT whose head is in run r ends, or -1: `.`, a run of 8 or more, `.`, then the rest of the next run
        if r not in rest:
            end, last = -1, ends[r] + 1
            if (last < size and text[last - 1] == "." and r + 1 < len(starts) and starts[r + 1] == last
                    and ends[r + 1] - last >= 8 and ends[r + 1] < size and text[ends[r + 1]] == "."):
                end = ends[r + 1] + 1
                if r + 2 < len(starts) and starts[r + 2] == end:
                    end = ends[r + 2]
            rest[r] = end
        return rest[r]

    def next_jwt(at):    # (start, end) of the first JWT that starts at or after `at`, or None
        while True:
            p = text.find("eyJ", at)
            if p < 0:
                return None
            r = bisect_right(starts, p) - 1
            if p + 11 <= ends[r] and jwt_end(r) >= 0:
                return p, jwt_end(r)
            at = ends[r]  # no `eyJ` further in this run can be a head either

    spans, at = [], 0
    other = _PREFIX_RULES.search(text)
    jwt = next_jwt(0) if starts else None
    while other is not None or jwt is not None:
        if other is not None and other.start() < at:      # it began inside the span just taken: look again from its end
            other = _PREFIX_RULES.search(text, at)
        elif jwt is not None and jwt[0] < at:
            jwt = next_jwt(at)
        else:
            start, end = other.span() if jwt is None or (other is not None and other.start() < jwt[0]) else jwt
            if tail is not None:
                end = tail.match(text, end).end()
            spans.append((start, end))
            at = end
    return spans


def _grow_spans(text, spans):
    """Each flagged span takes the random-looking pieces next to it across a `/`: the head of a token is not printed.

    One pass cuts the text into pieces (runs of name characters) and keeps where each starts and ends. A span then walks
    that array by index; a piece is judged once, and a walk that reaches a piece an earlier walk has settled stops there, so
    the work is linear in the text and no range is sliced or searched again. (Looking back with a search over everything
    before a piece costs the cube of the length for a name of many `/`-joined pieces.)"""
    from bisect import bisect_left
    starts, ends = [], []
    for m in _SPAN_PIECE.finditer(text):
        starts.append(m.start())
        ends.append(m.end())
    count, size = len(starts), len(text)
    judged_left, judged_right, settled_left, settled_right = {}, {}, {}, {}

    def padded(k):       # where piece k ends with the up to two `=` of padding after it
        e = ends[k]
        if e < size and text[e] == "=":
            e += 2 if e + 1 < size and text[e + 1] == "=" else 1
        return e

    def left_ok(j):
        if j not in judged_left:
            judged_left[j] = _randomish(text[starts[j]:ends[j]])
        return judged_left[j]

    def right_ok(k):
        if k not in judged_right:
            judged_right[k] = _randomish(text[starts[k]:padded(k)])
        return judged_right[k]

    def before(at):      # the piece that growing left from offset `at` takes, or -1. `$` also ends a match before a final line break.
        if at < 2 or text[at - 1] != "/":
            return -1
        for stop in ((at - 1, at - 2) if text[at - 2] == "\n" else (at - 1,)):
            j = bisect_left(ends, stop)
            if j < count and ends[j] == stop:
                return j if left_ok(j) else -1
        return -1

    def after(k):        # the piece that growing right from the end of piece k takes, or -1
        e = padded(k)
        if k + 1 >= count or e >= size - 1 or text[e] != "/" or starts[k + 1] != e + 1:
            return -1
        return k + 1 if right_ok(k + 1) else -1

    def settle(i, step, memo):
        trail = []
        while i not in memo:
            trail.append(i)
            j = step(i)
            if j < 0:
                memo[i] = i
                break
            i = j
        final = memo[i]
        for t in trail:
            memo[t] = final
        return final

    grown = []
    for start, end in spans:
        j = before(start)
        if j >= 0:
            start = starts[settle(j, lambda i: before(starts[i]), settled_left)]
        if end < size - 1 and text[end] == "/":
            k = bisect_left(starts, end + 1)
            if k < count and starts[k] == end + 1 and right_ok(k):
                end = padded(settle(k, after, settled_right))
        grown.append((start, end))
    return grown


def token_spans(text):
    if len(text) > TEXT_LIMIT:
        return [(0, len(text))]
    spans = _prefixed_spans(text)
    for m in _RUN.finditer(text):
        if _token_run(m.group()):
            spans.append(m.span())
    # A base64 token holds `/`: pieces too short to be one alone (an AWS-style secret has two) are caught as a whole.
    for m in _SLASHED.finditer(text):
        run = m.group()
        if "/" in run and sum(1 for p in run.split("/") if _randomish(p)) >= 3 and re.search(r"[0-9+]", run):
            spans.append(m.span())
    grown = _grow_spans(text, spans) if spans else []
    grown.sort()
    merged = []
    for start, end in grown:
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def token_shaped(text):
    return bool(token_spans(text))


# ---- credentials: a value is withheld by the name it is given under and by the text around it ----------------------------------
# The rules above find strings that are shaped like an identifier. These find a secret that has no shape, because of what it is
# assigned to (`password=`, a `Name`/`Value` pair, a `-Password` switch, `curl -u user:pass`, `mysql -pSECRET`), and the common
# token families, private key blocks and hashes of an account database. A name decides whether a value is a secret, a value
# decides nothing. Every rule runs in time linear in the text (a bounded stretch after each anchor, no nested repeat), and a
# carrier whose texts are long (a cloud log: a megabyte) sets WITHHOLD_TICK to a hook that ends the work at its deadline.
_CRED_CHECKSUM_NAME = re.compile(r"(?i)checksum|digest|sha[0-9]|md5|etag|crc[0-9]")
_CRED_REDACTED = re.compile(r"^\W*(?:hidden_due_to_security_reasons|redacted|masked|removed|\*+|x{3,}|\[\])\W*$", re.I)
_CRED_NOT_A_VALUE = frozenset(("true", "false", "null", "none", "nil", "undefined", "required", "optional", "enabled", "disabled"))
_CRED_EXACT = {
    "password", "newpassword", "oldpassword", "currentpassword", "passwd", "pwd", "passphrase", "passcode", "pin", "otp",
    "pass", "dbpass", "userpass", "adminpass", "rootpass", "plaintext",
    "secret", "clientsecret", "secretkey", "secretaccesskey", "awssecretaccesskey", "awssecretkey", "secretstring",
    "secretbinary", "secrettext", "secretvalue", "accesskeysecret",
    "sessiontoken", "securitytoken", "accesstoken", "refreshtoken", "idtoken", "bearertoken", "authtoken", "token",
    "tokencode", "mfacode", "verificationcode", "authorizationcode",
    "authorization", "proxyauthorization", "cookie", "setcookie", "apikey", "privatekey", "privatekeypem",
    "sharedaccesskey", "sharedaccesssignature", "accountkey", "primarykey", "secondarykey", "keyvalue", "masterkey",
    "storagekey", "subscriptionkey", "ocpapimsubscriptionkey",
    "connectionstring", "credential", "credentials", "assertion", "samlresponse", "mfasecret",
    "sastoken", "sassignature", "signature", "sig",
    "passwordhash", "nthash", "ntlmhash", "lmhash",
}
_CRED_SUFFIX = ("password", "passwd", "passphrase", "secret", "apikey", "privatekey", "sessiontoken", "securitytoken",
                "accesstoken", "refreshtoken", "clientsecret", "token", "secrettext", "secretkey", "secretaccesskey",
                "primarykey", "secondarykey", "accountkey", "sharedaccesskey", "subscriptionkey", "passwordhash",
                "ntlmhash", "nthash", "passcode", "signature", "cookie")
# a position or an idempotency key under a name that ends in `token`
_CRED_NOT_SECRET = ("nexttoken", "pagetoken", "continuationtoken", "paginationtoken", "nextpagetoken", "pagingtoken",
                    "startingtoken", "nextmarkertoken", "clienttoken", "clientrequesttoken", "idempotencytoken",
                    "nextforwardtoken", "nextbackwardtoken", "requesttoken")
_CRED_CONTAINERS = ("credential", "credentials")
_CRED_NAME_CACHE = {}
_CRED_NAME_KEYS = ("Name", "name", "Key", "key")
_CRED_VALUE_KEYS = ("Value", "NewValue", "OldValue", "value", "newValue", "oldValue")


def is_container_name(name):
    """`credentials` names a group of fields (an access key id, an expiry, a token): each is judged by its own name."""
    return re.sub(r"[^a-z0-9]", "", str(name).lower()) in _CRED_CONTAINERS


def name_is_sensitive(name):
    """Does a field or a parameter of this name hold a secret? (`Password`, `client_secret`, `x-api-key`; not `nextToken`.)"""
    hit = _CRED_NAME_CACHE.get(name)
    if hit is None:
        flat = re.sub(r"[^a-z0-9]", "", str(name).lower())
        hit = flat in _CRED_EXACT or (len(flat) > 6 and flat.endswith(_CRED_SUFFIX) and not flat.endswith(_CRED_NOT_SECRET))
        if len(_CRED_NAME_CACHE) < 20000:
            _CRED_NAME_CACHE[name] = hit
    return hit


_CRED_B64 = "A-Za-z0-9+/_-"
_CRED_B64_RUN = re.compile(r"(?<![%s])[%s]{128,}={0,2}(?![%s])" % (_CRED_B64, _CRED_B64, _CRED_B64))
_CRED_B64_EDGE = "(?<![A-Za-z0-9+/=_-])"
_CRED_B64_END = "(?![A-Za-z0-9+/=_-])"
# The names an assignment is recognised by. A long compound name may carry any prefix (dbPassword=, apiToken=, adminSecret:);
# a short one needs the edge of a word (sig= is not design=).
_CRED_STRONG = (r"password|passwd|passphrase|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token|session[_-]?token|"
                r"security[_-]?token|auth[_-]?token|bearer[_-]?token|account[_-]?key|shared[_-]?access[_-]?key|primary[_-]?key|"
                r"secondary[_-]?key|private[_-]?key|subscription[_-]?key|sas[_-]?token|password[_-]?hash|nt[_-]?hash|ntlm[_-]?hash|"
                r"lm[_-]?hash|client[_-]?secret|secret[_-]?access[_-]?key|secret[_-]?key|secret[_-]?text|secret[_-]?value|token|signature|plaintext")
_CRED_SHORT = r"(?<![A-Za-z0-9])(?:pwd|pass|sig|pin|otp|sas)"
_CRED_SEP = r"""(?:\\*["']|["'])?\s*(?:[:=]|%3[dD]|%3[aA])\s*"""
# a short name is a name only as `pwd=value` or `pass:value`: "pass: 3 attempts" is prose
_CRED_SEPS = r"""(?:\\*["']|["'])?(?:\s*(?:=|%3[dD])\s*|:(?=\S))"""
_CRED_NAME = r"(?:(?:%s)%s|%s%s)" % (_CRED_STRONG, _CRED_SEP, _CRED_SHORT, _CRED_SEPS)
_CRED_ARN_TAIL = re.compile(r"arn:[A-Za-z0-9-]+:[A-Za-z0-9-]+:[A-Za-z0-9-]*:[0-9]*:$")
_CRED_PAIR_WHY = "a value paired with a credential name"
_CRED_RULES = [
    # anchored at the start of a run and possessive, so that a megabyte of `eyJ` is read once, not once per `eyJ`
    ("a JSON Web Token", re.compile(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{6,}+\.[A-Za-z0-9_-]{2,}+(?:\.[A-Za-z0-9_-]*+)?"), 0),
    ("a JSON Web Encryption token", re.compile(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{6,}+(?:\.[A-Za-z0-9_-]*+){4}"), 0),
    ("a password in a URL", re.compile(r"(?i)(?<![A-Za-z0-9+.-])[a-z][a-z0-9+.-]{1,20}://[^\s:/@\"'<>\\]{0,256}:([^\s/\"'<>\\]{1,1024})@(?=[^\s/@\"'<>]{1,255})"), 1),
    ("an Azure Functions key", re.compile(r"""(?i)(?:x-functions-key["']?\s*[:=]\s*(?:\\*["'])?|[?&;]code=)([A-Za-z0-9_/+=-]{16,512})"""), 1),
    ("a private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----(?:[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----|[\s\S]*)"), 0),
    ("a base64 block of key lines", re.compile(r"(?:[A-Za-z0-9+/]{60,80}={0,2}\r?\n){2,}[A-Za-z0-9+/]{2,80}={0,2}"), 0),
    ("an authorization header value", re.compile(
        r"""(?i)authorization["']?\s*[:=]\s*(?:\\*["'])?(?:(?:bearer|basic|digest|negotiate|ntlm|token)\s+)?([^\s"'&,;\\]{1,4096})"""), 1),
    ("a cookie header value", re.compile(r"""(?i)cookie["']?\s*[:=]\s*(?:\\*["'])?([^\r\n"'\\]{1,4096})"""), 1),
    ("a scheme and its credential", re.compile(r"(?i)\b(?:bearer|basic)\s+([A-Za-z0-9._~+/=-]{3,4096})|\b(?:negotiate|ntlm|digest)\s+([A-Za-z0-9._~+/=-]{24,4096})"), -2),
    ("a value assigned to a credential name (quoted)", re.compile(
        r"""(?i)%s\\*(["'])(.{1,4096}?)(?=\\*\1)""" % _CRED_NAME), 2),
    ("a value assigned to a credential name", re.compile(
        r"""(?i)%s((?:(?!%%26)[^\s"'&<>\\]){1,4096})""" % _CRED_NAME), 1),
    ("a value given to a credential switch", re.compile(
        r"""(?i)(?<![A-Za-z0-9_])-(?:password|pass|pwd|passphrase|secret|clientsecret|apikey|accesstoken|token)\s+(?:\\*(["'])(.{1,4096}?)(?=\\*\1)|([^\s"'-][^\s"']{0,4095}))"""), -1),
    ("a secret given to ConvertTo-SecureString", re.compile(
        r"""(?i)ConvertTo-SecureString\s+(?:\\*(["'])(.{1,4096}?)(?=\\*\1)|([^\s"'-][^\s"']{0,4095}))"""), -1),
    # `mysql -u<user> -p<password>`: with `-p` glued to its value, and only as an option of a MySQL or MariaDB client (`ssh -p 22`,
    # `nc -p 80` and `mysql -p` alone, which asks for the password, name a port or nothing). The options are read up to the next
    # command of the kind, so that a text of many of them is read once, not once for each
    ("a password given to a MySQL client", re.compile(
        r"""(?i:(?<![\w.-])(?:mysql|mysqldump|mysqladmin|mysqlcheck|mysqlimport|mysqlshow|mariadb|mariadb-dump|mariadb-admin)(?:\.exe)?(?=\s))(?:(?!(?i:mysql|mariadb)\b)[^\n]){0,512}?(?<=\s)-p(?=[^\s`,;)])(?:"([^"\n]{1,256})"|'([^'\n]{1,256})'|([^\s"']{1,256}))"""), -3),
    # `curl -u user:password`: the part after the colon, and only when there is one (`curl -u user` asks for it)
    ("a password given to curl", re.compile(
        r"""(?i:(?<![\w.-])curl(?:\.exe)?(?=\s))(?:(?!(?i:curl)\b)[^\n]){0,512}?(?<=\s)(?:-u|-U|--user|--proxy-user)(?:\s+|=)(?:"[^":\n]*:([^"\n]{1,256})"|'[^':\n]*:([^'\n]{1,256})'|[^\s:"']*:([^\s"']{1,256}))"""), -3),
    ("a hash pair of an account database", re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{32}:([0-9a-fA-F]{32})(?![0-9a-fA-F])"), 1),
    ("a bcrypt hash", re.compile(r"(?<![A-Za-z0-9$])\$2[abxy]?\$[0-9]{2}\$[./A-Za-z0-9]{53}(?![./A-Za-z0-9])"), 0),
    ("a token of a known family", re.compile(
        r"(?:GOCSPX-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,}|xox[abprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])|"
        r"ya29\.[0-9A-Za-z_-]{20,}|1//0[0-9A-Za-z_-]{30,}|(?:IQoJb3JpZ2lu|FQoGZXIvYXdz|FwoGZXIvYXdz)[A-Za-z0-9+/=]{40,}|"
        r"[A-Za-z0-9_.~-]{3}[0-9]Q~[A-Za-z0-9_.~-]{30,}|[01]\.A[A-Za-z0-9_-]{50,}|[sr]k_(?:live|test)_[A-Za-z0-9]{16,})"), 0),
]
_CRED_GROUPS = {-1: (1, 2, 3), -2: (1, 2), -3: (1, 2, 3)}
# A random-looking run of an exact length that keys have: 32, 40 (an AWS secret access key), 43 + "=" and 86 + "==" (a base64 key).
_CRED_SHAPES = [
    ("a key-length base64 string", re.compile(_CRED_B64_EDGE + r"(?:[A-Za-z0-9+/]{32}|[A-Za-z0-9+/]{40}|[A-Za-z0-9+/]{43}=|[A-Za-z0-9+/]{86}==)" + _CRED_B64_END), True),
]
# A Name/Value pair written as JSON text inside a string (an AuditData in a column of another name, a parameter list in a cell): the
# structure rule (clean_value) cannot see it, so the text rule reads the head of the pair, and the name decides as it does there. The
# value is read by hand, not by an expression: a string up to its first quote (the backslashes before the quote are not part of it), a
# number, a flat array of up to 4,096 characters, or a literal; and the next value of the same pair (`OldValue`, then `NewValue`).
_CRED_PAIR_HEAD = re.compile(r"""(?i)\b(?:name|key)\\*"\s*:\s*\\*"([^"\\]{1,64})\\*"\s*,\s*\\*"(?:new|old)?value\\*"\s*:\s*""")
_CRED_NEXT_VALUE = re.compile(r"""(?i)\s*,\s*\\*"(?:new|old)?value\\*"\s*:\s*""")
_CRED_QUOTE = re.compile(r'\\*"')
# a format directive (`%s`, `%d`), a template field (`{0}`, `{name}`) or a `%VAR%` is where a value goes, not a value
_CRED_PLACEHOLDER = re.compile(r"%[-+ #0-9.]*[sdiuxXfeEgGcr](?![A-Za-z0-9])|\{\w*\}|%\w+%$|\.{2,}|\u2026")
_CRED_BARE = re.compile(r"-?[0-9][0-9.eE+-]{0,39}|\[[^\[\]]{0,4096}\]|(?:null|true|false)\b")
# What a text must hold for a rule to match it: a literal (lower case) of which one must be in the text, checked before the rule runs, so
# that a text with none of them (most names, addresses and ids) costs a few substring tests and no expression. An assignment rule also
# needs a separator in the text. Each is a necessary condition of its rule.
_CRED_ASSIGN = ("pass", "pwd", "secret", "key", "token", "signature", "plaintext", "sig", "pin", "otp", "sas", "hash")
_CRED_NEEDLES = {
    "a JSON Web Token": ("eyj",), "a JSON Web Encryption token": ("eyj",), "a password in a URL": ("://",),
    "an Azure Functions key": ("x-functions-key", "code="), "a private key block": ("-----begin",), "a base64 block of key lines": ("\n",),
    "an authorization header value": ("authorization",), "a cookie header value": ("cookie",),
    "a scheme and its credential": ("bearer", "basic", "negotiate", "ntlm", "digest"),
    "a value assigned to a credential name (quoted)": _CRED_ASSIGN, "a value assigned to a credential name": _CRED_ASSIGN,
    "a value given to a credential switch": ("password", "pass", "pwd", "secret", "apikey", "accesstoken", "token"),
    "a secret given to ConvertTo-SecureString": ("securestring",), "a password given to a MySQL client": ("mysql", "mariadb"),
    "a password given to curl": ("curl",), "a hash pair of an account database": (":",), "a bcrypt hash": ("$2",),
    "a token of a known family": ("gocspx-", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_", "xoxa-", "xoxb-", "xoxp-", "xoxr-", "xoxs-",
                                  "aiza", "ya29.", "1//0", "iqojb3", "fqogzx", "fwogzx", "q~", "0.a", "1.a", "sk_", "rk_"),
}
_CRED_CLEAN = set()               # short texts already judged to hold nothing (names, addresses and ids repeat)
_CRED_GATE = 4096                 # a text longer than this is scanned with the carrier's hook in view, rule by rule
# The carrier's hook for long scans: called with the work done so far (1 per stretch found, 4096 between rules over a long text); it may
# raise to end the scan at the carrier's deadline. Most carriers set none and the calls do nothing.
_tick = globals().get("WITHHOLD_TICK") or (lambda units=1: None)


def _cred_json_value(text, at):
    """(start, end, after) of the JSON value whose text starts at `at`: `end` is where what is withheld ends, `after` where the next
    token of the pair begins. None when no value starts there."""
    q = _CRED_QUOTE.match(text, at)
    if q:
        start = q.end()
        close = text.find('"', start)
        if close < 0:
            return start, len(text), len(text)      # a value that is cut off: the rest of the text is the value
        return start, start + len(text[start:close].rstrip("\\")), close + 1
    m = _CRED_BARE.match(text, at)
    if m is None:
        return None
    if m.group()[0] in "nft":
        return at, at, m.end()                     # null, true and false are not secrets
    return m.start(), m.end(), m.end()


def _cred_pair_spans(text, spans):
    for head in _CRED_PAIR_HEAD.finditer(text):
        if not name_is_sensitive(head.group(1)):
            continue
        at = head.end()
        for _ in range(3):
            got = _cred_json_value(text, at)
            if got is None:
                break
            start, end, after = got
            if end > start:
                value = text[start:end]
                if not (_CRED_REDACTED.match(value) or value.lower() in _CRED_NOT_A_VALUE or value.startswith(("${", "{{")) or _CRED_PLACEHOLDER.match(value)):
                    spans.append((start, end, _CRED_PAIR_WHY))
            more = _CRED_NEXT_VALUE.match(text, after)
            if more is None:
                break
            at = more.end()


def _cred_random_like(run):
    """A run that looks like random base64 and not like a path, a name or a hash: mixed case and digits in the proportions
    random text has (a long path is mostly lower case with few capitals; a hex digest has no case to mix)."""
    n = len(run)
    upper = sum(1 for ch in run if "A" <= ch <= "Z")
    lower = sum(1 for ch in run if "a" <= ch <= "z")
    digit = sum(1 for ch in run if "0" <= ch <= "9")
    return upper * 100 >= 15 * n and lower * 100 >= 15 * n and digit * 100 >= 5 * n


def _cred_name_before(text, at):
    """The letters and digits of the name an assigned value follows (`nextToken=` gives `nexttoken`)."""
    return re.sub(r"[^a-z0-9]", "", text[max(0, at - 64):at].lower())


def _cred_spans(text, shapes, skip=()):
    spans = []
    big = len(text) > _CRED_GATE
    low = text.lower()
    sep = "=" in text or ":" in text or "%3" in low
    if "value" in low:
        _cred_pair_spans(text, spans)
    for why, rx, group in _CRED_RULES:
        if why in skip:
            continue
        need = _CRED_NEEDLES[why]
        if need is _CRED_ASSIGN and not sep:
            continue
        for n in need:
            if n in low:
                break
        else:
            continue
        if big:
            _tick(4096)
        for m in rx.finditer(text):
            if big:
                _tick(1)
            if "assigned to a credential name" in why:
                if _CRED_ARN_TAIL.search(text[max(0, m.start() - 120):m.start()]):
                    continue                              # arn:aws:secretsmanager:...:secret:NAME is a name, not a value
                if _cred_name_before(text, m.start(m.lastindex or 0)).endswith(_CRED_NOT_SECRET):
                    continue                              # nextToken=, pageToken=, clientToken=: a position or an idempotency key
            for g in _CRED_GROUPS.get(group, (group,)):
                if g and m.group(g) is None:
                    continue
                start, end = m.span(g)
                value = text[start:end]
                if g and (_CRED_REDACTED.match(value) or value.lower() in _CRED_NOT_A_VALUE or value.startswith(("${", "{{")) or _CRED_PLACEHOLDER.match(value)):
                    continue
                if why == "a scheme and its credential" and g == 1 and not (re.search(r"[0-9+/=_.~-]", value) or len(value) >= 16):
                    continue                              # "basic authentication" is prose, "Basic dXNlcjpwYXNz" is not
                if g == 1 and group == -1 and len(m.groups()) >= 2 and m.group(1) in ("'", '"'):
                    continue                              # group 1 of the switch rules is the quote
                spans.append((start, end, why))
    if big:
        _tick(4096)
    for m in (_CRED_B64_RUN.finditer(text) if len(text) >= 128 and "a long unbroken base64-like run" not in skip else ()):
        if _cred_random_like(m.group(0)):
            spans.append((m.start(), m.end(), "a long unbroken base64-like run"))
    if shapes and len(text) >= 32 and "a key-length base64 string" not in skip:
        for why, rx, check in _CRED_SHAPES:
            for m in rx.finditer(text):
                if not check or _cred_random_like(m.group(0)):
                    spans.append((m.start(), m.end(), why))
    spans.sort()
    merged = []
    for s in spans:
        if merged and s[0] < merged[-1][1]:
            if s[1] > merged[-1][1]:
                merged[-1] = (merged[-1][0], s[1], merged[-1][2])
            continue
        merged.append(s)
    return merged


def credential_spans(text, shapes=True, skip=()):
    """(start, end, why) of each stretch of `text` that is a credential by the name it is given under or by its text, in order and
    not overlapping. `shapes` False leaves out the rules that recognise a key by its length alone (a value that is named a checksum or
    a digest is not scanned for them). This is not `token_spans`: an identifier (a GUID, a hex digest, an access key id, an ARN) is
    not a credential here, and a tool that prints identifiers on purpose asks only for these."""
    if len(text) > TEXT_LIMIT:
        return [(0, len(text), "text longer than %d characters" % TEXT_LIMIT)]
    if shapes and not skip and text in _CRED_CLEAN:
        return []
    spans = _cred_spans(text, shapes, skip)
    if shapes and not skip and not spans and len(text) <= 256 and len(_CRED_CLEAN) < 100000:
        _CRED_CLEAN.add(text)
    return spans


def clean_value(value, leaf, note, key=None, pointer="", depth=0, shapes=True, max_depth=200):
    """The structure rule: `value` (what a JSON document decoded to) with every credential in it replaced. A string goes to
    `leaf(text, pointer, shapes)`, which returns what is printed for it. A field whose name says it holds a secret (or a `Value` whose
    `Name` does), at any depth, is not read at all: `note(pointer, why, original)` returns what is printed for it (a number under such
    a name is withheld too: 0 and 1 are not nothing). A key goes through `key(text)` when one is given. A value nested deeper than
    `max_depth` is replaced the same way."""
    if isinstance(value, str):
        return leaf(value, pointer, shapes)
    _tick(1)
    if depth > max_depth and isinstance(value, (dict, list)):
        return note(pointer, "nested deeper than %d levels" % max_depth, value)
    if isinstance(value, dict):
        named = None
        for k in _CRED_NAME_KEYS:
            if isinstance(value.get(k), str):
                named = value[k]
                break
        pair_secret = named is not None and name_is_sensitive(named)
        out = {}
        for k, v in value.items():
            ks = str(k)
            point = "%s/%s" % (pointer, ks.replace("~", "~0").replace("/", "~1"))
            safe_key = key(ks) if key is not None else ks
            if safe_key in out:
                safe_key = "%s#%d" % (safe_key, len(out))
            sensitive = name_is_sensitive(ks) or (pair_secret and ks in _CRED_VALUE_KEYS)
            if sensitive and is_container_name(ks) and isinstance(v, (dict, list)):
                sensitive = False
            if sensitive and not (v is None or isinstance(v, bool) or v == "") and not (isinstance(v, str) and (_CRED_REDACTED.match(v) or v.lower() in _CRED_NOT_A_VALUE)):
                out[safe_key] = note(point, "credential-named field", v)
            else:
                out[safe_key] = clean_value(v, leaf, note, key, point, depth + 1, shapes and not _CRED_CHECKSUM_NAME.search(ks), max_depth)
        return out
    if isinstance(value, list):
        return [clean_value(v, leaf, note, key, "%s/%d" % (pointer, i), depth + 1, shapes, max_depth) for i, v in enumerate(value)]
    return value


# what the rules of the block above already withhold whole, with their own markers: the first pass leaves these to them
_CRED_OLD_COVERS = frozenset(("a JSON Web Token", "a password in a URL", "an authorization header value", "a scheme and its credential",
                              "a long unbroken base64-like run", "a key-length base64 string"))


def _credentials_withheld(text, kind, skip=()):
    """`text` with each credential in it withheld. It runs after the rules above, on text that may hold their markers: a stretch that
    begins at a marker is theirs already."""
    out, last = [], 0
    for start, end, why in credential_spans(text, True, skip):
        if text.startswith("<", start):
            continue
        out.append(text[last:start])
        out.append(_withheld(why, end - start, kind))
        last = end
    if not out:
        return text
    out.append(text[last:])
    return "".join(out)


def scrub(text, kind="text"):
    """The text with every token-shaped run, every user-info and every credential withheld."""
    if len(text) > TEXT_LIMIT:
        return _withheld("over-long text", len(text), kind)
    text = _credentials_withheld(text, kind, _CRED_OLD_COVERS)     # first: the rules above cut a secret into pieces that no rule for a whole one can match
    text = _USERINFO.sub(lambda m: _withheld("userinfo", len(m.group()), kind), text)
    text = _BARE_USERINFO.sub(lambda m: _withheld("userinfo", len(m.group()), kind), text)
    out, last = [], 0
    for start, end in token_spans(text):
        out.append(text[last:start])
        out.append(_withheld("token-shaped text", end - start, kind))
        last = end
    out.append(text[last:])
    return _credentials_withheld("".join(out), kind)


def redact_url(url):
    """A URL or request target without its user-info, its token-shaped path text, its query values or its fragment."""
    rest, fragment = (url.split("#", 1) + [None])[:2]
    rest, query = (rest.split("?", 1) + [None])[:2]
    scheme = authority = ""
    m = re.match(r"^((?:[A-Za-z][A-Za-z0-9+.-]*:)?//)([^/]*)(.*)$", rest, re.S)
    if m:
        scheme, authority, rest = m.group(1), m.group(2), m.group(3)
        if "@" in authority:
            userinfo, authority = authority.rsplit("@", 1)
            authority = _withheld("userinfo", len(userinfo), "urls") + "@" + authority
    out = scheme + authority + scrub(rest, "urls")
    if query is not None:
        pairs = []
        for pair in query.split("&"):
            name, eq, value = pair.partition("=")
            pairs.append(scrub(name, "urls") + (eq + _withheld("", len(value), "urls") if eq else ""))
        out += "?" + "&".join(pairs)
    if fragment is not None:
        out += "#" + _withheld("", len(fragment), "urls")
    return out


def cell(value):
    """Text for one tab-separated cell or one printed path: no tab or line break, and a byte that was not UTF-8
    (a lone surrogate) written as \\xNN, so that no writer raises on it."""
    text = value if isinstance(value, str) else str(value)
    out = []
    for ch in text:
        o = ord(ch)
        if ch == "\\":
            out.append("\\\\")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\n":
            out.append("\\n")
        elif 0xDC80 <= o <= 0xDCFF:
            out.append("\\x%02x" % (o - 0xDC00))
        elif 0xD800 <= o <= 0xDFFF:
            out.append("\\u%04x" % o)
        elif o < 0x20 or o == 0x7F:
            out.append("\\x%02x" % o)
        else:
            out.append(ch)
    return "".join(out)
# END SHARED WITHHOLDING
# BEGIN SHARED SHOWN
# MEMORY SHOWN v1: the same text is in mem_fs and mem_profile (tests/pack-memory-shared.test.ts holds the copies equal), and it
# reads the shared WITHHOLDING block above it. A string read from the capture (a name MemProcFS lists, a line the engine prints, a
# release string in a header) is not printed as it is: it goes through shown(text, kind), and the answer and the paged file go
# through sealed(), so that nothing reaches stdout or a file that is not sealed output without having been judged. Three layers,
# the hybrid design: an allow-list per kind, the shared deny-list, and an independent backstop with its own rules.
#
# LAYER 1, an allow-list per kind of field. "release" (a kernel release) and "build" (a Windows build string) are shown only when
# they fit the grammar of a version: digits, dots and the tags of a closed list (_RELEASE_WORD, _BUILD_WORD), at most 6 groups and 16
# digits after the version, nothing else, so a secret placed where a version should be, or glued to one, is not printed. "name" (a file, directory, process or key name; "path" is the same for a virtual path, judged as a whole and
# then component by component) is shown when it has no invisible character, no component over 128 characters, and no chain of 16
# or more letters and digits that looks random (it flips between letters and digits, or between capitals and lower case, as words
# do not). A GUID, a SID, a 16-digit hexadecimal address and 0x numbers are typed ids and are plain. "text" (one line of an
# engine's output) has no character grammar, only layers 2 and 3.
# LAYER 2, the deny-list of the shared block (token_spans: vendor prefixes, long token-like runs, user-info) plus the value after
# a secret's name (password=, token:, api key ...), read on the string with typed ids masked. A span is replaced; the rest stays.
# LAYER 3, the backstop, written apart from the two above and applied to what layers 1 and 2 would print: a PEM marker, a named
# secret, a vendor prefix in any case, user-info, 19 or more digits, 32 or more hexadecimal digits, a run of 20 or more characters
# that changes class (lower, upper, digit, other) as random text does; read on a copy with invisible characters taken out and NFKC
# applied, and on the original: 12 characters of anything it calls secret in the original that are still in the shown string mean
# a piece was left between two cuts. A string it finds suspect is replaced whole by <withheld N characters: why>, counted, and the
# answer says so.
# NOT RECOGNISED, by design: a plain password or passphrase, a pronounceable secret, anything under 16 characters in a name,
# a secret in an encoding this block does not read. Withholding is by shape. Measured on planted canaries (1,000 per cell; a name
# alone, then inside `proc_<k>.exe`, `<k>.dll` and `1234-<k>`), the share of keys printed whole: base64 and base62 keys 0 to 0.6 per
# cent alone and up to 3 per cent in a process-name context (24 base62 characters 2.9, 20 bytes of base64 1.2); in an engine line
# (kind text, used for the first lines of a failure, which has no allow-list) base64 keys of 16 to 32 bytes 0 to 18 per cent, base62
# keys of 20 to 32 characters 10 to 61, a 24-character base36 key 48 to 65, a base64 key holding `/` 37 to 40. The prefixes of the vendors in _PREFIX2 and _PREFIX_RULES are read at 0 in 3,400 plants per shape. Printed at
# 100 per cent, because they are made of pieces under 16 characters or of words: UUID-shaped and 16-digit hexadecimal secrets (typed
# ids are plain), tokens split by `.` or `:` into pieces under 16 characters, word passwords and passphrases, 14-character policy
# passwords. Printed at tens of per cent: base32 seeds (43 to 46), licence keys of 5 groups of 5 (18 to 20), a bcrypt hash's
# 12-character fragments (28 to 31), a vendor key whose prefix is in no list (`rk_live_` was 3 to 18 before it was added).
import collections
import unicodedata

LMIN = 16
MAX_ONE = 4096
MAX_COMPONENT = 128
BOUNDARY = {"shown": 0, "withheld_spans": 0, "withheld_whole": 0, "backstop_replaced": 0, "swept": 0}
BACKSTOP_WHY = collections.Counter()


class Shown(str):
    """A string read from the capture that has been judged: sealed() does not judge it again."""


_TYPED = re.compile(r"\{?[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}?"
                    r"|S-1-[0-9]{1,2}(?:-[0-9]{1,10}){1,15}"
                    r"|(?<![0-9A-Za-z])0x[0-9A-Fa-f]{1,16}(?![0-9A-Za-z])"
                    r"|(?<![0-9A-Za-z])[0-9A-Fa-f]{16}(?![0-9A-Za-z])"
                    r"|(?<=[A-Za-z0-9]_)[0-9a-z]{13}(?![0-9A-Za-z])")        # the publisher id at the end of an app package family name
_PREFIX2 = re.compile(r"(?i)glpat-[0-9a-z_-]{16,}|(?:sk|rk|pk)_(?:live|test)_[0-9a-z]{16,}|whsec_[0-9a-z_+/=-]{16,}|sg\.[0-9a-z_-]{16,}|aiza[0-9a-z_-]{30,}|npm_[0-9a-z]{30,}|dop_v1_[0-9a-f]{32,}|ya29\.[0-9a-z_-]{20,}")
_PIECE = re.compile(r"[A-Za-z0-9+_=-]{16,}")
_PLAIN_SHORT = re.compile(r"[A-Za-z0-9 ._()+-]{1,15}")
_NAMED = re.compile(r"(?i)(?:pass(?:word|wd|phrase)?|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential|auth)"
                    r"[A-Za-z0-9_]{0,12}[ \t]{0,3}[=:](?![=:/\\])[ \t]{0,3}['\"]?([^\s'\"<>&;,]{3,128})")
# the same rule for a string the tool wrote itself (documentation-like text such as "secret_output: true" must pass): the value is 6 or more characters with a digit or a symbol in it
_NAMED_TEXT = re.compile(r"(?i)(?:pass(?:word|wd|phrase)?|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential|auth)"
                         r"[A-Za-z0-9_]{0,12}[ \t]{0,3}[=:][ \t]{0,3}['\"]?(?=[^\s'\"<>&;,]{0,127}[0-9!#$%^*+@~])[^\s'\"<>&;,]{6,128}")
_USER_INFO = re.compile(r"[^\s/@:<>]{1,64}:[^\s/<>]{1,128}@[\w\[]")        # the backstop's own form: the password may hold an @
_UINFO_SPAN = re.compile(r"(?<![\w.%+-])[\w.%+-]{1,64}:[^\s/<>]{1,128}(?=@[\w\[])")   # layer 2's: up to the last @ before a host
_BS_PEM = re.compile(r"-----BEGIN")
_BS_PREFIX = re.compile(r"(?i)(?:akia|asia)[0-9a-z]{16}|gh[pousr]_[0-9a-z]{16}|github_pat_[0-9a-z_]{16}|xox[abeprs]-[0-9a-z-]{8}"
                        r"|glpat-[0-9a-z_-]{16}|(?:sk|rk|pk)_(?:live|test)_[0-9a-z]{16}|whsec_[0-9a-z_+/=-]{16}|sk-[0-9a-z_-]{16}|aiza[0-9a-z_-]{20}|npm_[0-9a-z]{20}"
                        r"|eyj[0-9a-z_-]{8,}\.[0-9a-z_-]{8,}\.|sg\.[0-9a-z_-]{16}|(?:basic|bearer)[ \t]{1,3}[0-9a-z+/=._~-]{16}")
_BS_DIGITS = re.compile(r"[0-9]{19,}")
_BS_HEX = re.compile(r"[0-9A-Fa-f]{32,}")
_BS_RUN = re.compile(r"[A-Za-z0-9+/=_-]{20,}")
# The version grammars are closed lists, not shapes: a release is the version, then at most six groups, each a number of up to five digits or one
# word of the list below (a distribution's or a kernel flavour's own tag, with up to three digits after it); a Windows build string is the build, the
# platform, and a branch made of at most four words of the list below and a date. A word that is not in the list, or a seventh group, or more than 16
# digits in all, is not a version, and the string is withheld whole (a release with an unusual tag is withheld too: the count is in boundary).
_RELEASE_WORD = (r"(?:generic|lowlatency|aws|azure|gcp|gke|oem|cloud|kvm|virtual|raspi|rpi|lts|zen|hardened|realtime|rt|rc|amd64|arm64|armhf|"
                 r"i[3-6]86|x86_64|aarch64|ppc64le|s390x|el|fc|ubuntu|debian|deb|bpo|pve|default|arch|mainline|android|linuxkit|coreos|edge|std|"
                 r"smp|preempt|uek|lp|oracle|ibm|nvidia|tegra|stable|gentoo|xanmod|liquorix|v7l?|v8|k3s|dirty)")
_RELEASE = re.compile(r"[0-9]{1,2}\.[0-9]{1,3}(?:\.[0-9]{1,3})?((?:[-+~._](?:[0-9]{1,5}|" + _RELEASE_WORD + r"[0-9]{0,3}(?:_[0-9]{1,3})?)){0,6})\+?")
_BUILD_WORD = (r"(?:win7sp1|win7|win8|winmain|winblue|vibranium|th[12]|rs|rs[0-9]{1,2}|[0-9]{2}h[12]|vb|ni|co|ge|fe|zn|mn|sv|lh|r[0-9]{1,2}|release|"
               r"prerelease|rtm|gdr|ldr|svc|sec|escrow|inmarket|flt|prod|dev|beta|lab|sp[0-9]|rc|oem|st|uup|rel|main|win|vista|server|ltsc)[0-9]{0,2}")
_BUILD = re.compile(r"[0-9]{3,6}\.[0-9]{1,5}\.(?:x86|amd64|arm64|armnt)(?:fre|chk)(?:\.(?:" + _BUILD_WORD + r"(?:_" + _BUILD_WORD + r"){0,3})?(?:\.[0-9]{0,6}(?:-[0-9]{0,4})?)?)?")


def _norm(text):
    """NFKC with the invisible characters (format, control, combining) taken out: what the rules read besides the string itself."""
    if text.isascii() and text.isprintable():
        return text
    folded = unicodedata.normalize("NFKC", text)
    return "".join(c for c in folded if unicodedata.category(c) not in ("Cf", "Cc", "Mn", "Me"))


def _hidden(text):
    """Whether the text holds an invisible or unassigned character (a byte that was not UTF-8, written as a lone surrogate escape, is not one)."""
    if text.isascii() and text.isprintable():
        return False
    for c in text:
        cat = unicodedata.category(c)
        if cat in ("Cf", "Cc", "Co", "Cn") or (cat == "Cs" and not 0xDC80 <= ord(c) <= 0xDCFF):
            return True
    return False


def _escaped(text):
    """A byte that was not UTF-8 (a lone surrogate escape) written as \\xNN, so that no writer raises on it."""
    if text.isascii():
        return text
    return "".join("\\x%02x" % (ord(c) - 0xDC00) if 0xDC80 <= ord(c) <= 0xDCFF else c for c in text)


def _mask(text):
    return _TYPED.sub(lambda m: "x" * len(m.group()), text)


_SEGMENT = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|[0-9]+")


def _random_piece(piece):
    """A run of 16 or more characters that is not shaped like words. Words, CamelCase names and dates break into segments (a word, a capital
    and its lower-case letters, a number) of 3 or more characters on average; random base62 and base64 break into segments of about 2. A
    base64 padding (== at the end, or a + inside a run of letters and digits) is not in a word either."""
    alnum = "".join(c for c in piece if c.isalnum())
    if len(alnum) < LMIN - 2 or alnum.isdigit():
        return False
    if piece.endswith("==") or (len(alnum) >= LMIN and "+" in piece.strip("+") and not piece.isalpha()):
        return True
    return len(alnum) >= LMIN and len(alnum) <= 3.0 * len(_SEGMENT.findall(alnum))


def _spans(text, kind):
    """The spans of a string that layers 1 and 2 withhold, as (start, end, what), merged."""
    masked = _mask(text)
    if kind == "text":
        found = [(s, e, "token-shaped text") for s, e in token_spans(masked)]
    else:
        # a name is judged by the allow-list below; of the shared deny-list only the vendor prefixes apply to it
        found = [(start, end, "token-shaped text") for start, end in _prefixed_spans(masked)]
    found += [(m.start(), m.end(), "token-shaped text") for m in _PREFIX2.finditer(masked)]
    if kind != "text":
        for m in _PIECE.finditer(masked):
            if _random_piece(m.group()):
                found.append((m.start(), m.end(), "random-looking text"))
    for rx in (_USERINFO, _BARE_USERINFO, _UINFO_SPAN):
        for m in rx.finditer(text):
            found.append((m.start(), m.end(), "userinfo"))
    for m in _NAMED.finditer(masked):
        found.append((m.start(1), m.end(1), "secret value"))
    found.sort()
    merged = []
    for start, end, what in found:
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end), merged[-1][2])
        else:
            merged.append((start, end, what))
    return merged


def _density(run):
    """For a run of 16 or more letters and digits (symbols left out): how often neighbours change class (lower, upper, digit), and whether it mixes classes
    as random text does. Words, paths and CamelCase names change class rarely; random base62 and base64 change in about 6 of 10 steps."""
    alnum = [0 if c.islower() else 1 if c.isupper() else 2 for c in run if c.isalnum()]
    if len(alnum) < LMIN:
        return False
    changes = sum(1 for a, b in zip(alnum, alnum[1:]) if a != b)
    return changes >= 0.45 * (len(alnum) - 1) and (2 in alnum or (0 in alnum and 1 in alnum))


def _backstop_reason(text):
    """Why a string is not printed, by rules that are not layer 2's; None when it may be."""
    plain = _norm(text)
    if _BS_PEM.search(plain):
        return "a PEM marker"
    if _NAMED.search(plain):
        return "a named secret"
    if _BS_PREFIX.search(plain):
        return "a token prefix"
    if _USER_INFO.search(plain):
        return "user-info"
    masked = _mask(plain)
    if _BS_DIGITS.search(masked):
        return "a long digit run"
    if _BS_HEX.search(masked):
        return "a long hexadecimal run"
    for m in _BS_RUN.finditer(masked):
        if _density(m.group()):
            return "a random-looking run"
    return None


def _backstop_pieces(original, printed):
    """Whether 12 characters of a secret-shaped part of the original are still in what would be printed (a piece left between two cuts)."""
    plain, out = _norm(original), _norm(printed)
    masked = _mask(plain)
    spans = [m.span() for m in _BS_RUN.finditer(masked) if _density(m.group())]
    spans += [m.span(1) for m in _NAMED.finditer(plain)]
    spans += [m.span() for m in _BS_PREFIX.finditer(plain)]
    for start, end in spans[:16]:
        piece = plain[start:end]
        if len(piece) >= 12 and any(piece[i:i + 12] in out for i in range(0, len(piece) - 11)):
            return True
    return False


def _whole(text, why, key):
    BOUNDARY["withheld_whole"] += 1
    COUNTS[key] = COUNTS.get(key, 0) + 1
    return Shown("<withheld %d characters: %s>" % (len(text), why))


def shown(text, kind="name"):
    """What may be printed of a string read from the capture. kind: name, path, text, release or build."""
    if not isinstance(text, str):
        text = str(text)
    if isinstance(text, Shown):
        return text
    BOUNDARY["shown"] += 1
    key = "text" if kind == "text" else "names"
    if kind in ("release", "build"):
        if len(text) > (48 if kind == "release" else 64):
            return _whole(text, "not a version", key)
        found = (_RELEASE if kind == "release" else _BUILD).fullmatch(text)
        if not found or (kind == "release" and sum(len(d) for d in re.findall(r"[0-9]+", found.group(1))) > 16):
            return _whole(text, "not a %s string" % kind, key)
        return Shown(text)
    if _PLAIN_SHORT.fullmatch(text):
        return Shown(text)
    if len(text) > MAX_ONE:
        return _whole(text, "longer than %d characters" % MAX_ONE, key)
    if _hidden(text):
        return _whole(text, "invisible or non-text characters", key)
    if kind in ("name", "path") and any(len(part) > MAX_COMPONENT for part in text.split("/")):
        return _whole(text, "a component over %d characters" % MAX_COMPONENT, key)
    spans = _spans(text, kind)
    pieces, last = [], 0
    for start, end, what in spans:
        pieces.append(text[last:start])
        pieces.append(_withheld(what, end - start, key))
        BOUNDARY["withheld_spans"] += 1
        last = end
    pieces.append(text[last:])
    printed = _escaped("".join(pieces))
    why = _backstop_reason(printed)
    if why is None and spans and _backstop_pieces(text, printed):
        why = "a part of a secret-shaped text"
    if why is not None:
        BOUNDARY["backstop_replaced"] += 1
        BACKSTOP_WHY[why] += 1
        return _whole(text, "backstop: " + why, key)
    return Shown(printed)


def _seal_text(s):
    """The strongest rules of the backstop on a string the tool did not mark as read from the capture."""
    if len(s) < 12:
        return s
    if len(s) > 4 * MAX_ONE:
        BOUNDARY["backstop_replaced"] += 1
        BACKSTOP_WHY["longer than the judged size"] += 1
        return Shown("<withheld %d characters: backstop: longer than the judged size>" % len(s))
    BOUNDARY["swept"] += 1
    plain = _norm(s)
    why = ("a PEM marker" if _BS_PEM.search(plain) else "a named secret" if _NAMED_TEXT.search(plain)
           else "a token prefix" if _BS_PREFIX.search(plain) else "user-info" if _USER_INFO.search(plain) else None)
    if why is None:
        return s
    BOUNDARY["backstop_replaced"] += 1
    BACKSTOP_WHY[why] += 1
    return Shown("<withheld %d characters: backstop: %s>" % (len(s), why))


def sealed(obj):
    """The serialisation boundary: the same structure with every string that is not already judged put through the strongest backstop rules."""
    if isinstance(obj, Shown):
        return obj
    if isinstance(obj, str):
        return _seal_text(obj)
    if isinstance(obj, dict):
        return {(sealed(k) if isinstance(k, str) else k): sealed(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [sealed(v) for v in obj]
    return obj


def boundary_summary():
    return {"strings_judged": BOUNDARY["shown"], "spans_withheld": BOUNDARY["withheld_spans"], "strings_withheld": BOUNDARY["withheld_whole"],
            "backstop_replaced": BOUNDARY["backstop_replaced"],
            "rule": "a string read from the capture is shown only when it fits the plain grammar of its kind and no deny-list or backstop rule "
                    "reads it as a secret; a placeholder says how many characters were withheld. Withholding is by shape: a plain password, "
                    "a pronounceable passphrase or anything under 16 characters in a name is printed. The originals of withheld names are "
                    "written only on write_values, in a job run as secret output."}
# END SHARED SHOWN


# --- stopping: a signal ends the tool with one JSON answer ------------------------------------------------------------------------------

class Terminated(BaseException):
    """Raised by the signal handler. A BaseException, so no `except Exception` swallows it and every `finally` runs."""

    def __init__(self, signum):
        super().__init__(signum)
        self.signum = signum


# GUARD["depth"] above zero holds a signal until the section is over (acted on at the next checkpoint()); GUARD["stopping"] says a stop is
# under way or the answer has left, so a later signal changes nothing.
GUARD = {"depth": 0, "pending": None, "stopping": False}
ANSWER = {"printed": False}
FILES = []                  # the output files of this call that are still under a hidden name


def _on_signal(signum, _frame):
    if GUARD["stopping"]:
        return
    if GUARD["depth"]:
        GUARD["pending"] = signum            # a file is being closed or the answer written: finished first, then the stop is raised
        return
    GUARD["stopping"] = True
    raise Terminated(signum)


def checkpoint():
    signum = GUARD["pending"]
    if signum is not None and not GUARD["depth"]:
        GUARD["pending"] = None
        GUARD["stopping"] = True
        raise Terminated(signum)


# The call's one clock: max_seconds, counted from the moment the arguments were read. Every loop over something the dump sizes looks at it,
# through tick() (which ends the call with a failed answer that says what it was doing: a loop that has no partial answer to give) or
# through late() (a loop that can stop and say where it stopped: a page, a search, a count).
CLOCK = {"deadline": None, "seconds": None}


class OutOfTime(Exception):
    """max_seconds was reached in a loop that has no partial answer to give; run_guarded() turns it into the one failed answer."""

    def __init__(self, doing):
        super().__init__(doing)
        self.doing = doing


def late():
    return CLOCK["deadline"] is not None and time.monotonic() > CLOCK["deadline"]


def tick(doing):
    checkpoint()
    if late():
        raise OutOfTime(doing)


def emit(answer):
    """The one way an answer leaves: whole, once, and not cut by a signal. A signal that arrives while it is written is held, and once it is
    out a later one changes nothing, so stdout never holds two documents."""
    hold_stop_signals()
    text = json.dumps(sealed(answer), indent=2)
    GUARD["depth"] += 1
    try:
        if ANSWER["printed"]:
            return
        ANSWER["printed"] = True
        print(text, flush=True)
    finally:
        GUARD["depth"] -= 1
        GUARD["stopping"] = True


def discard_files():
    GUARD["depth"] += 1
    try:
        for out in list(FILES):
            out.discard()
    finally:
        GUARD["depth"] -= 1


def fail(message, **extra):
    discard_files()             # a file that was being written is removed, whatever ended the call
    emit({"error": message, "status": "failed", "parser": PARSER,
          "status_basis": "the call was refused or ended before an answer; nothing in this document is a finding about the evidence", **extra})
    raise SystemExit(1)


# --- the arguments ----------------------------------------------------------------------------------------------------------------------

def read_args():
    try:
        raw = sys.stdin.read(MAX_STDIN + 1)
    except (OSError, ValueError) as exc:
        fail("the arguments could not be read", reason=type(exc).__name__)
    if len(raw) > MAX_STDIN:
        fail("the arguments are larger than %d bytes" % MAX_STDIN)
    try:
        args = json.loads(raw)
    except (ValueError, RecursionError):
        fail("arguments are not valid JSON (or are nested too deeply)")
    if not isinstance(args, dict):
        fail("arguments must be a JSON object")
    return args


def text_arg(args, key, limit=MAX_TEXT):
    value = args.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        fail("%s must be a non-empty string" % key)
    if len(value) > limit:
        fail("%s is longer than %d characters" % (key, limit))
    if "\x00" in value:
        fail("%s holds a NUL character" % key)
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        fail("%s is not text (it holds a lone surrogate)" % key)
    return value


def int_arg(args, key, default, low, high):
    value = args.get(key)
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        fail("%s must be an integer from %d to %d" % (key, low, high))
    return value


def bool_arg(args, key):
    value = args.get(key)
    if value is None:
        return False
    if not isinstance(value, bool):
        fail("%s must be true or false" % key)
    return value


def address(value, key):
    """An address given as an integer or as a hexadecimal string (0x optional), 0 to 2**64 - 1."""
    if isinstance(value, bool):
        fail("%s must be an address: an integer or a hexadecimal string such as \"0x7ff6a1b20000\"" % key)
    if isinstance(value, int):
        number = value
    elif isinstance(value, str) and re.fullmatch(r"(?:0[xX])?[0-9A-Fa-f`]{1,24}", value) and re.search(r"[0-9A-Fa-f]", value):
        number = int(value.replace("`", ""), 16)
    else:
        fail("%s must be an address: an integer or a hexadecimal string such as \"0x7ff6a1b20000\"" % key)
    if not 0 <= number <= U64:
        fail("%s must be an address from 0 to 2**64 - 1" % key)
    return number


def address_arg(args, key, default=None):
    if args.get(key) is None:
        return default
    return address(args[key], key)


def parse_args(args):
    allowed = {"path", "view", "offset", "limit", "list", "protect", "type", "addresses", "va", "length", "module", "base", "allow_gaps",
               "write_values", "needle", "needle_hex", "encodings", "ignore_case", "va_start", "va_end", "max_hits", "max_seconds"}
    unknown = sorted(k for k in args if k not in allowed)
    if unknown:
        fail("unknown parameter; the parameters are %s" % ", ".join(sorted(allowed)), count=len(unknown))
    p = {"path": text_arg(args, "path")}
    if not p["path"]:
        fail("path is required: a Windows process dump (a minidump, MDMP)")
    view = args.get("view", "summary")
    if view is None:
        view = "summary"
    if not isinstance(view, str) or view not in VIEWS:
        fail("view must be one of: %s" % ", ".join(VIEWS))
    p["view"] = view
    p["offset"] = int_arg(args, "offset", 0, 0, 1 << 40)
    p["limit"] = int_arg(args, "limit", DEFAULT_LIMIT, 1, MAX_LIMIT)
    p["seconds"] = int_arg(args, "max_seconds", DEFAULT_SECONDS, MIN_SECONDS, MAX_SECONDS)
    which = args.get("list")
    if which is None:
        which = "ranges"
    if which not in ("ranges", "regions"):
        fail("list must be \"ranges\" (the memory the dump holds) or \"regions\" (the MemoryInfoList, in the dump or not)")
    p["list"] = which
    for key, values in (("protect", ("any", "execute", "write", "execute_write")), ("type", ("any", "private", "mapped", "image"))):
        value = args.get(key)
        if value is None:
            value = "any"
        if not isinstance(value, str) or value not in values:
            fail("%s must be one of: %s" % (key, ", ".join(values)))
        p[key] = value
    p["allow_gaps"], p["write_values"], p["ignore_case"] = bool_arg(args, "allow_gaps"), bool_arg(args, "write_values"), bool_arg(args, "ignore_case")
    p["va"] = address_arg(args, "va")
    p["base"] = address_arg(args, "base")
    p["va_start"] = address_arg(args, "va_start", 0)
    p["va_end"] = address_arg(args, "va_end")
    p["length"] = int_arg(args, "length", None, 1, U64)
    p["max_hits"] = int_arg(args, "max_hits", DEFAULT_HITS, 1, MAX_HITS)
    p["module"] = text_arg(args, "module", 1024)
    addresses = args.get("addresses")
    if addresses is not None:
        if not isinstance(addresses, list) or not addresses or len(addresses) > MAX_ADDRESSES:
            fail("addresses must be a list of 1 to %d addresses (integers or hexadecimal strings)" % MAX_ADDRESSES)
        addresses = [address(a, "addresses") for a in addresses]
    p["addresses"] = addresses
    p["needle"] = text_arg(args, "needle", MAX_NEEDLE)
    hexed = text_arg(args, "needle_hex", 4 * MAX_NEEDLE)
    if hexed is not None:
        packed = re.sub(r"[\s:,-]|0[xX]", "", hexed)
        if not packed or len(packed) % 2 or not re.fullmatch(r"[0-9A-Fa-f]+", packed):
            fail("needle_hex must be an even number of hexadecimal digits (spaces, colons and 0x are ignored)")
        hexed = bytes.fromhex(packed)
        if len(hexed) > MAX_NEEDLE:
            fail("needle_hex is longer than %d bytes" % MAX_NEEDLE)
    p["needle_hex"] = hexed
    encodings = args.get("encodings")
    if encodings is None:
        encodings = ["utf-8", "utf-16le"]
    if (not isinstance(encodings, list) or not encodings or len(encodings) > 2 or not all(isinstance(e, str) for e in encodings)
            or any(e not in ("utf-8", "utf-16le") for e in encodings) or len(set(encodings)) != len(encodings)):
        fail("encodings must be a list of one or both of: utf-8, utf-16le")
    p["encodings"] = encodings

    # What each view needs, said before the dump is looked at.
    if view == "va":
        if p["addresses"] is None and p["va"] is None:
            fail("view va needs addresses (a list) or va (one address)")
        if p["addresses"] is None:
            p["addresses"] = [p["va"]]
    if view == "read":
        if p["va"] is None or p["length"] is None:
            fail("view read needs va (the first address) and length (how many bytes, at most %d)" % READ_MAX)
        if p["length"] > READ_MAX:
            fail("length is at most %d bytes a call; read a larger range in several calls" % READ_MAX)
        if p["va"] + p["length"] > U64 + 1:
            fail("va + length runs past the end of the address space")
    if view == "module" and (p["module"] is None) == (p["base"] is None):
        fail("view module needs exactly one of module (a name from view modules) or base (the module's base address)")
    if view == "find":
        if (p["needle"] is None) == (p["needle_hex"] is None):
            fail("view find needs exactly one of needle (text) or needle_hex (bytes as hexadecimal digits)")
        if p["needle_hex"] is not None and p["ignore_case"]:
            fail("ignore_case is for a text needle, not for needle_hex")
        if p["va_end"] is not None and p["va_end"] <= p["va_start"]:
            fail("va_end must be above va_start")
    if p["write_values"]:
        if view not in ("read", "module"):
            fail("write_values is for the views read and module, which write memory content to a file; view %s writes nothing" % view)
        if job_dir() is None:
            fail("write_values writes memory content to a file: it is refused outside a job, where the file would not be a sealed output. "
                 "Run this as a job with secret_output: true. Nothing was written and the dump was not read.", write_values="refused", written=False)
        if os.environ.get("SECRET_OUTPUT") != "1":
            fail("write_values is refused in a job that was not run as secret output: its file would be sealed as ordinary output. Run this "
                 "as a job with secret_output: true. Nothing was written and the dump was not read.", write_values="refused", written=False)
    return p


def job_dir():
    job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
    return (re.sub(r"[^A-Za-z0-9_.-]", "_", job), Path(out)) if job and out else None


# --- the output files -------------------------------------------------------------------------------------------------------------------

class OutFile:
    """A file under $OUT/minidump_map (a directory with mode 0700), mode 0600, created exclusively under a hidden name and given its name
    without replacing an earlier file (a name that is taken gives <stem>-2<suffix>, and so on). Nothing exists before the first write."""

    def __init__(self, name):
        job, out = job_dir()
        self.dir, self.name = out / "minidump_map", name
        self.shown_dir = "store/jobs/%s/out/minidump_map" % job
        self.tmp, self.fd, self.final, self.held = None, None, None, False
        self.digest, self.bytes = hashlib.sha256(), 0

    def _open(self):
        self.dir.mkdir(parents=True, exist_ok=True)
        if self.dir.is_symlink() or not self.dir.is_dir():
            raise OSError(errno.ENOTDIR, "the output directory is a link or not a directory")
        os.chmod(self.dir, 0o700)
        GUARD["depth"] += 1                 # the hidden file is known to the call before a stop can be acted on
        try:
            self.tmp = self.dir / (".%s-%s" % (self.name, os.urandom(6).hex()))
            self.fd = os.open(str(self.tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
            FILES.append(self)
        finally:
            GUARD["depth"] -= 1
        checkpoint()

    def write(self, block):
        if self.fd is None:
            self._open()
        view = memoryview(block)
        while len(view):
            view = view[os.write(self.fd, view):]
        self.digest.update(block)
        self.bytes += len(block)

    def finish(self, hold=False):
        """Close the file and give it its name; the name an answer may print. With hold, the placed file still belongs to the call (a stop
        or a failure removes it) until release(): an image is not left without the map that says where its gaps are."""
        if self.fd is None:
            self._open()
        GUARD["depth"] += 1                 # closing the file and giving it its name is finished before a stop is acted on
        try:
            os.fsync(self.fd)
            os.close(self.fd)
            self.fd = None
            for n in range(1, 1000):
                stem, dot, suffix = self.name.partition(".")
                candidate = self.dir / (self.name if n == 1 else "%s-%d%s%s" % (stem, n, dot, suffix))
                try:
                    os.link(self.tmp, candidate)
                except FileExistsError:
                    continue
                except OSError:
                    try:                    # no hard links here: an exclusive create takes the name, and the file is moved over it
                        os.close(os.open(str(candidate), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600))
                    except FileExistsError:
                        continue
                    os.replace(self.tmp, candidate)
                else:
                    os.unlink(self.tmp)
                self.final, self.tmp = candidate, None
                break
            else:
                raise OSError(errno.EEXIST, "no free name for %s" % self.name)
            self.held = hold
            if not hold and self in FILES:
                FILES.remove(self)
        finally:
            GUARD["depth"] -= 1
        checkpoint()
        return "%s/%s" % (self.shown_dir, self.final.name)

    def release(self):
        self.held = False
        if self in FILES:
            FILES.remove(self)

    def discard(self):
        try:
            if self.fd is not None:
                os.close(self.fd)
        except OSError:
            pass
        self.fd = None
        if self.tmp is not None:
            try:
                os.unlink(self.tmp)
            except OSError:
                pass
            self.tmp = None
        if self.held and self.final is not None:
            try:
                os.unlink(self.final)
            except OSError:
                pass
            self.held = False
        if self in FILES:
            FILES.remove(self)


def record_digests(rows):
    """The sha256 of what was written goes to manifest.jsonl beside the files, with its size, and never into the answer (which gives the
    size alone: the length of the range that was asked for). Returns the name to print."""
    job, out = job_dir()
    name = out / "minidump_map" / "manifest.jsonl"
    fd = os.open(str(name), os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.write(fd, "".join(json.dumps(row) + "\n" for row in rows).encode("ascii"))
        os.fsync(fd)
    finally:
        os.close(fd)
    return "store/jobs/%s/out/minidump_map/manifest.jsonl" % job


# --- reading the dump -------------------------------------------------------------------------------------------------------------------

def hx(value):
    return "0x%x" % value


def iso(seconds):
    """A time_t as ISO 8601 UTC, or None when it is zero or not a time this calendar holds."""
    if not seconds:
        return None
    try:
        return datetime.datetime.fromtimestamp(seconds, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return None


def filetime_iso(value):
    """A FILETIME (100 ns since 1601-01-01 UTC) as ISO 8601 UTC with its seven fraction digits, or None."""
    if not value:
        return None
    try:
        whole = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(seconds=value // 10_000_000)
    except OverflowError:
        return None
    return "%s.%07dZ" % (whole.strftime("%Y-%m-%dT%H:%M:%S"), value % 10_000_000)


def flags_of(value, table):
    return [name for bit, name in table if value & bit]


def protect_name(value):
    if value is None:
        return None
    base = PROTECT.get(value & 0xFF, "0x%x" % (value & 0xFF)) if value & 0xFF else "none"
    return "|".join([base] + flags_of(value, PROTECT_MOD))


def decode_utf16(raw):
    """UTF-16LE bytes as text, and how many units could not be decoded (a lone surrogate): each is U+FFFD in the text, and a caller
    that gets a count above 0 says so (a U+FFFD the bytes themselves hold is not counted)."""
    try:
        return raw.decode("utf-16-le"), 0
    except UnicodeDecodeError:
        text = raw.decode("utf-16-le", "replace")
        return text, max(1, text.count("�") - raw.decode("utf-16-le", "surrogatepass").count("�"))


def decode_utf8(raw):
    """UTF-8 bytes as text, and how many byte sequences could not be decoded (each is U+FFFD in the text)."""
    try:
        return raw.decode("utf-8"), 0
    except UnicodeDecodeError:
        text = raw.decode("utf-8", "replace")
        return text, max(1, text.count("�") - raw.decode("utf-8", "surrogateescape").count("�"))


EMPTY_TYPE_NAME = "<an empty type name>"       # the key of by_type that counts the handles whose type name string has 0 characters
# The size of the CONTEXT record of an architecture whose registers this tool decodes; a context declared smaller is not one.
CONTEXT_BYTES = {9: (1232, "an x64 CONTEXT"), 0: (716, "an x86 CONTEXT")}


class Dump:
    """The file, read with pread; the faults found in it (stream, file offset, what) are kept in `problems`."""

    def __init__(self, path):
        self.fd = None
        try:
            self.fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0))
            st = os.fstat(self.fd)
        except OSError as exc:
            if self.fd is not None:
                os.close(self.fd)
            fail("path cannot be opened (%s)" % errno.errorcode.get(exc.errno, "errno %s" % exc.errno))
        if not stat.S_ISREG(st.st_mode):
            os.close(self.fd)
            fail("path is not a regular file (a FIFO, a device or a directory is refused)")
        self.size = st.st_size
        self.problems, self.problem_count, self.faulty = [], 0, set()
        self.streams, self.directory = {}, []
        self.header = {}
        self.arch, self.pointer = None, 8
        self.system = self.misc = self.exception = self.handles = None
        self.modules, self.unloaded, self.threads = [], [], []
        self.thread_info, self.thread_names = {}, {}
        self.seg_va, self.seg_len, self.seg_have, self.seg_off, self.seg_src = [], [], [], [], []
        self.seg_sum = [0]
        self.declared_bytes = self.mapped_bytes = 0
        self.ranges_declared = 0
        self.ranges_empty = self.ranges_overlapping = self.ranges_cut = self.regions_overlapping = self.ranges_unreadable = 0
        self.reg_va, self.reg_len, self.reg_state, self.reg_protect, self.reg_type, self.reg_abase, self.reg_aprot = [], [], [], [], [], [], []
        self.absent = []            # the names of the streams the directory does not list, of those this tool reads
        self.mod_order, self.mod_bases = [], []
        self._shown_names = {}
        self._names = {}            # (stream, RVA) -> the string there: a name many modules point at is read once

    def problem(self, stream, offset, text):
        self.problem_count += 1
        self.faulty.add(stream)
        if len(self.problems) < MAX_PROBLEMS:
            self.problems.append({"stream": stream, "file_offset": offset, "problem": text})

    def read(self, offset, length):
        """At most `length` bytes at `offset` (fewer at the end of the file)."""
        if length <= 0 or offset < 0 or offset >= self.size:
            return b""
        parts, got = [], 0
        while got < length:
            piece = os.pread(self.fd, length - got, offset + got)
            if not piece:
                break
            parts.append(piece)
            got += len(piece)
        return parts[0] if len(parts) == 1 else b"".join(parts)

    def need(self, stream, offset, length, what):
        """Exactly `length` bytes at `offset`, or None with the fault recorded."""
        data = self.read(offset, length)
        if len(data) < length:
            self.problem(stream, offset, "%s: %d bytes are needed at file offset %d and the file (%d bytes) holds %d of them"
                         % (what, length, offset, self.size, len(data)))
            return None
        return data

    def locate(self, stream, size, rva, what, minimum, at=None, kind="its type"):
        """Where a location record (a byte count and an RVA) points, judged one way for every record this tool follows: a CodeView
        record, a thread's context and stack, the exception's context, a memory descriptor, a string. `size` None is a record whose
        length is in its own first bytes (a MINIDUMP_STRING), located by its first `minimum` bytes. Returns {state, in_file, why}:

          none                   no bytes are declared (size 0); nothing to read, and no fault
          read                   every declared byte is in the file
          cut_by_file            the record begins in the file and its declared end is past it; in_file bytes of it are there
          declared_not_readable  bytes are declared inside the header (RVA 0 to 31), at or past the end of the file, or fewer than
                                 `minimum`, the smallest record of its `kind`; nothing of it is read as that record

        cut_by_file and declared_not_readable are recorded in problems under `stream` (at the RVA, or at `at`, the place of the location
        itself, when the RVA is 0), so every view that rests on that stream is partial. `why` is a sentence for the answer; none of
        them says that a declared record is absent."""
        declared = "%d bytes" % size if size is not None else kind
        if size is not None and not size:
            why = ("none is declared (0 bytes at RVA 0)" if not rva else
                   "0 bytes are declared (at file offset %d), so there is no record to read" % rva)
            return {"state": "none", "in_file": 0, "why": why}
        need = size if size is not None else minimum
        if rva < HEADER_BYTES:
            self.problem(stream, at if at is not None and not rva else rva, "%s: %s declared at file offset %d, where the file's header is (its "
                         "first %d bytes); it was not read" % (what, declared, rva, HEADER_BYTES))
            return {"state": "declared_not_readable", "in_file": 0,
                    "why": "%s declared at file offset %d, where the file's header is: not read (problems). A record is declared, so this "
                           "is not an entry without one" % (declared, rva)}
        if rva >= self.size:
            self.problem(stream, rva, "%s: %s declared at file offset %d, at or past the end of the file (%d bytes); it was not read"
                         % (what, declared, rva, self.size))
            return {"state": "declared_not_readable", "in_file": 0,
                    "why": "%s declared at file offset %d, at or past the end of the file (%d bytes): not read (problems). A record is "
                           "declared, so this is not an entry without one" % (declared, rva, self.size)}
        if size is not None and size < minimum:
            self.problem(stream, rva, "%s: %d bytes are declared and %s needs at least %d; it was not read as one" % (what, size, kind, minimum))
            return {"state": "declared_not_readable", "in_file": 0,
                    "why": "%d bytes are declared at file offset %d and %s needs at least %d: not read as one (problems)" % (size, rva, kind, minimum)}
        if rva + need > self.size:
            held = self.size - rva
            self.problem(stream, rva, "%s: %s declared at file offset %d and the file (%d bytes) ends %d bytes into it" % (what, declared, rva, self.size, held))
            return {"state": "cut_by_file", "in_file": held,
                    "why": "%s declared at file offset %d and the file ends %d bytes into it (problems): what is said is from the bytes "
                           "the file holds" % (declared, rva, held)}
        return {"state": "read", "in_file": need, "why": None}

    def string(self, stream, rva, what, at=None):
        """A MINIDUMP_STRING (a u32 byte length, then UTF-16LE) at `rva`: the text, or None with the fault recorded. Located by
        `locate`, so an RVA of 0 (the header's place), one past the file and a string the file cuts are each a fault, never "no name";
        `at` is the place of the RVA itself. Text that is not valid UTF-16 is printed with U+FFFD and said in problems."""
        if self.locate(stream, None, rva, what, 4, at, "a MINIDUMP_STRING")["state"] != "read":
            return None
        length = struct.unpack("<I", self.read(rva, 4))[0]
        take = min(length, MAX_STRING_BYTES) & ~1
        if self.locate(stream, 4 + take, rva, what, 4, at, "a MINIDUMP_STRING")["state"] != "read":
            return None
        text, lossy = decode_utf16(self.read(rva + 4, take))
        if lossy:
            self.problem(stream, rva, "%s: the string is not valid UTF-16 (%d unit(s) could not be decoded, a lone surrogate among them); "
                         "U+FFFD stands for each in what is printed" % (what, lossy))
        if length > take:
            self.problem(stream, rva, "%s: the string declares %d bytes; the first %d were read" % (what, length, take))
        return text

    # ---- header and directory ----

    def parse(self):
        head = self.read(0, 32)
        if len(head) < 4 or head[:4] != b"MDMP":
            hint = ""
            if head[:4] == b"PAGE":
                hint = " It begins with PAGE: a Windows kernel crash dump, which mem_profile and Volatility read."
            elif head[:4] == b"\x7fELF":
                hint = " It begins with an ELF header: a core file or a hypervisor's memory dump, which mem_profile classifies."
            elif head[:2] == b"MZ":
                hint = " It begins with MZ: an executable, not a dump."
            fail("not a minidump: the file does not begin with the signature MDMP.%s" % hint, bytes=self.size)
        if len(head) < 32:
            fail("truncated minidump: the header is 32 bytes and the file holds %d" % len(head), bytes=self.size, stream="header", file_offset=0)
        _sig, version, count, directory, checksum, stamp, flags = struct.unpack("<4sIIIIIQ", head)
        if version & 0xFFFF != 0xA793:
            fail("the header's version word is 0x%04x, not 0xa793 (MINIDUMP_VERSION): a layout this tool does not read, and none is guessed"
                 % (version & 0xFFFF), stream="header", file_offset=4)
        self.header = {"signature": "MDMP", "version": hx(version & 0xFFFF), "implementation_version": version >> 16, "streams": count,
                       "directory_file_offset": directory, "checksum": checksum,
                       "time": {"raw": stamp, "utc": iso(stamp), "epoch": "seconds since 1970-01-01 UTC (the header's TimeDateStamp)"},
                       "flags": hx(flags), "flag_names": flags_of(flags, FLAG_NAMES)}
        self.flags = flags
        unknown = flags & ~sum(bit for bit, _n in FLAG_NAMES)
        if unknown:
            self.header["flags_not_named"] = hx(unknown)
        take = count
        if count > MAX_STREAMS:
            self.problem("directory", directory, "the header declares %d streams; the first %d directory entries are read" % (count, MAX_STREAMS))
            take = MAX_STREAMS
        if take and directory < HEADER_BYTES:
            # The directory is a location too: one inside the header would read the header's own fields as stream entries.
            self.problem("directory", directory, "the header puts the stream directory at file offset %d, inside the header (its first %d "
                         "bytes); no entry is read from it" % (directory, HEADER_BYTES))
            take = 0
        raw = self.read(directory, take * 12) if take else b""
        if len(raw) < take * 12:
            self.problem("directory", directory, "the directory of %d entries (12 bytes each) at file offset %d runs past the end of the file "
                         "(%d bytes): %d whole entries are in the file" % (take, directory, self.size, len(raw) // 12))
        for i in range(len(raw) // 12):
            if not i & 1023:
                tick("the directory was read")
            kind, size, rva = struct.unpack_from("<III", raw, i * 12)
            name = STREAM_NAMES.get(kind, "stream %d" % kind if kind <= 0xFFFF else "user stream 0x%x" % kind)
            row = {"index": i, "type": kind, "name": name, "bytes": size, "file_offset": rva}
            self.directory.append(row)
            if kind == 0:
                row["bytes_in_file"] = max(0, min(size, self.size - rva)) if rva else 0       # an unused entry: nothing is read
                continue
            # A stream is a location like the records inside it: one at RVA 0 (the header) or past the file holds no byte of it, and one
            # the file cuts holds what is before the end of the file; each is said once, here, and its parser reads only what is held.
            loc = self.locate(name, size, rva, "the %s stream (directory entry %d)" % (name, i), 1, directory + 12 * i + 4)
            in_file = row["bytes_in_file"] = loc["in_file"]
            if loc["state"] not in ("none", "read"):
                row["location"] = loc["state"]
            if name in self.streams:
                self.problem(name, rva, "a second %s stream (directory entry %d); the first is the one read" % (name, i))
                continue
            self.streams[name] = (rva, size, in_file)

    def stream(self, name):
        got = self.streams.get(name)
        if got is None:
            self.absent.append(name)
        return got

    def table(self, name, rva, size, in_file, header, count, entry, cap, what):
        """The bytes of a counted table: `count` entries of `entry` bytes after a header of `header` bytes. Returns (data, entries read)."""
        room = max(0, (min(size, in_file) - header) // entry) if entry else 0
        take = count
        if count > room:
            self.problem(name, rva, "%s: the stream declares %d entries of %d bytes and holds room for %d (stream of %d bytes, %d in the file)"
                         % (what, count, entry, room, size, in_file))
            take = room
        if entry > MAX_ENTRY:
            self.problem(name, rva, "%s: the header declares %d bytes an entry, above the %d this tool reads; the table is not read" % (what, entry, MAX_ENTRY))
            return b"", 0
        cap = min(cap, TABLE_BYTES // entry) if entry else 0
        if take > cap:
            self.problem(name, rva, "%s: %d entries, of which the first %d are read (the tool's bound)" % (what, take, cap))
            take = cap
        data = self.read(rva + header, take * entry)
        if len(data) < take * entry:
            self.problem(name, rva + header + len(data), "%s: the table ends at the end of the file" % what)
            take = len(data) // entry
        return data, take

    # ---- the streams ----

    def parse_system(self):
        got = self.stream("SystemInfo")
        if got is None:
            return
        rva, size, in_file = got
        if min(size, in_file) < 32:
            self.problem("SystemInfo", rva, "the stream holds %d bytes and MINIDUMP_SYSTEM_INFO needs 32 for its fixed fields" % min(size, in_file))
            return
        data = self.read(rva, 32)
        arch, level, revision, cpus, product, major, minor, build, platform, csd, suite, _r = struct.unpack("<HHHBBIIIIIHH", data)
        self.arch = arch
        self.pointer = 8 if arch in (6, 9, 12) else 4
        self.system = {"architecture": ARCH.get(arch, "unknown (%d)" % arch), "architecture_raw": arch, "pointer_bytes": self.pointer,
                       "processor_level": level, "processor_revision": hx(revision), "processors": cpus,
                       "product_type": PRODUCT.get(product, "unknown (%d)" % product),
                       "windows_version": "%d.%d.%d" % (major, minor, build), "platform_id": platform, "suite_mask": hx(suite)}
        text = self.string("SystemInfo", csd, "the service pack string (CSDVersionRva)", rva + 24)
        self.system["service_pack"] = shown(text, "text") if text else None

    def parse_misc(self):
        got = self.stream("MiscInfo")
        if got is None:
            return
        rva, size, in_file = got
        have = min(size, in_file)
        if have < 24:
            self.problem("MiscInfo", rva, "the stream holds %d bytes and MINIDUMP_MISC_INFO needs 24" % have)
            return
        data = self.read(rva, min(have, 1364))
        declared, flags1, pid, created, user, kernel = struct.unpack_from("<IIIIII", data)
        misc = {"size_of_info": declared, "flags1": hx(flags1)}
        if flags1 & 0x1:
            misc["process_id"] = pid
        if flags1 & 0x2:
            misc["process_create_time"] = {"raw": created, "utc": iso(created), "epoch": "seconds since 1970-01-01 UTC (ProcessCreateTime)"}
            misc["process_user_seconds"], misc["process_kernel_seconds"] = user, kernel
        for bit, needed, what in ((0x10, 48, "the integrity level"), (0x80, 56, "the protected-process field"), (0x100, 752, "the build string")):
            if flags1 & bit and len(data) < needed:
                self.problem("MiscInfo", rva, "Flags1 says the stream holds %s, which needs %d bytes, and it holds %d" % (what, needed, len(data)))
        if flags1 & 0x10 and len(data) >= 48:
            level = struct.unpack_from("<I", data, 44)[0]
            misc["integrity_level"] = {"raw": hx(level), "name": INTEGRITY.get(level & 0xF000 if level not in INTEGRITY else level)}
        if flags1 & 0x80 and len(data) >= 56:
            misc["protected_process"] = struct.unpack_from("<I", data, 52)[0]
        if flags1 & 0x100 and len(data) >= 232 + 520:
            text, lossy = decode_utf16(data[232:232 + 520])
            text = text.split("\x00", 1)[0]
            if lossy and "\ufffd" in text:
                self.problem("MiscInfo", rva + 232, "the build string is not valid UTF-16; U+FFFD stands for what could not be decoded")
            misc["build_string"] = shown(text, "build") if text else None
        self.misc = misc

    def parse_modules(self):
        got = self.stream("ModuleList")
        if got is not None:
            rva, size, in_file = got
            head = self.need("ModuleList", rva, 4, "the module count") if min(size, in_file) >= 4 else None
            if head is None and min(size, in_file) < 4:
                self.problem("ModuleList", rva, "the stream holds %d bytes and its count needs 4" % min(size, in_file))
            if head is not None:
                data, take = self.table("ModuleList", rva, size, in_file, 4, struct.unpack("<I", head)[0], 108, MAX_MODULES, "MINIDUMP_MODULE")
                for i in range(take):
                    if not i & 1023:
                        tick("the module list was read")
                    base, image, checksum, stamp, name_rva = struct.unpack_from("<QIIII", data, i * 108)
                    fixed = struct.unpack_from("<13I", data, i * 108 + 24)
                    cv_size, cv_rva = struct.unpack_from("<II", data, i * 108 + 76)
                    self.modules.append({"index": i, "base": base, "size": image, "checksum": checksum, "stamp": stamp, "name_rva": name_rva,
                                         "fixed": fixed, "cv": (cv_size, cv_rva), "entry_offset": rva + 4 + i * 108, "name": None, "named": False})
        got = self.stream("UnloadedModuleList")
        if got is not None:
            rva, size, in_file = got
            if min(size, in_file) < 12:
                self.problem("UnloadedModuleList", rva, "the stream holds %d bytes and its header needs 12" % min(size, in_file))
            else:
                header, entry, count = struct.unpack("<III", self.read(rva, 12))
                if header < 12 or entry < 24:
                    self.problem("UnloadedModuleList", rva, "the header says %d header bytes and %d bytes an entry; the format's are 12 and 24" % (header, entry))
                else:
                    data, take = self.table("UnloadedModuleList", rva, size, in_file, header, count, entry, MAX_MODULES, "MINIDUMP_UNLOADED_MODULE")
                    for i in range(take):
                        if not i & 1023:
                            tick("the unloaded module list was read")
                        base, image, checksum, stamp, name_rva = struct.unpack_from("<QIIII", data, i * entry)
                        self.unloaded.append({"index": i, "base": base, "size": image, "checksum": checksum, "stamp": stamp, "name_rva": name_rva,
                                              "entry_offset": rva + header + i * entry, "name": None, "named": False})
        self.mod_order = sorted(range(len(self.modules)), key=lambda i: self.modules[i]["base"])
        self.mod_bases = [self.modules[i]["base"] for i in self.mod_order]

    def module_name(self, module, stream="ModuleList"):
        if not module["named"]:
            key = (stream, module["name_rva"])
            if key not in self._names:      # read once: a fault in it is one problem, whatever the number of modules that name it
                self._names[key] = self.string(stream, module["name_rva"], "the name of module %d" % module["index"], module["entry_offset"] + 20)
            module["name"] = self._names[key]
            module["named"] = True
        return module["name"]

    def module_at(self, va):
        """The loaded module whose image holds `va` (the one with the highest base at or below it), or None."""
        at = bisect.bisect_right(self.mod_bases, va) - 1
        if at < 0:
            return None
        module = self.modules[self.mod_order[at]]
        return module if va < module["base"] + module["size"] else None

    def module_ref(self, va):
        module = self.module_at(va)
        if module is None:
            return None
        key = module["index"]
        if key not in self._shown_names:
            name = self.module_name(module)
            self._shown_names[key] = shown(re.split(r"[\\/]", name)[-1], "name") if name else None
        return {"name": self._shown_names[key], "base": hx(module["base"]), "rva": hx(va - module["base"])}

    def parse_threads(self):
        name, entry = ("ThreadList", 48) if "ThreadList" in self.streams else ("ThreadExList", 64)
        got = self.stream(name) if name in self.streams else None
        if got is None:
            self.absent.append("ThreadList")
        else:
            rva, size, in_file = got
            if min(size, in_file) < 4:
                self.problem(name, rva, "the stream holds %d bytes and its count needs 4" % min(size, in_file))
            else:
                data, take = self.table(name, rva, size, in_file, 4, struct.unpack("<I", self.read(rva, 4))[0], entry, MAX_THREADS, "MINIDUMP_THREAD")
                for i in range(take):
                    if not i & 1023:
                        tick("the thread list was read")
                    tid, suspend, pclass, priority, teb, stack_va, stack_size, stack_rva, ctx_size, ctx_rva = struct.unpack_from("<IIIIQQIIII", data, i * entry)
                    self.threads.append({"index": i, "id": tid, "suspend": suspend, "class": pclass, "priority": priority, "teb": teb,
                                         "stack": (stack_va, stack_size, stack_rva), "context": (ctx_size, ctx_rva), "entry_offset": rva + 4 + i * entry})
        got = self.stream("ThreadInfoList")
        if got is not None:
            rva, size, in_file = got
            if min(size, in_file) < 12:
                self.problem("ThreadInfoList", rva, "the stream holds %d bytes and its header needs 12" % min(size, in_file))
            else:
                header, entry, count = struct.unpack("<III", self.read(rva, 12))
                if header < 12 or entry < 64:
                    self.problem("ThreadInfoList", rva, "the header says %d header bytes and %d bytes an entry; the format's are 12 and 64" % (header, entry))
                else:
                    data, take = self.table("ThreadInfoList", rva, size, in_file, header, count, entry, MAX_THREADS, "MINIDUMP_THREAD_INFO")
                    for i in range(take):
                        if not i & 1023:
                            tick("the thread information list was read")
                        tid, dump_flags, dump_error, exit_status, created, exited, kernel, user, start, affinity = struct.unpack_from("<IIIIQQQQQQ", data, i * entry)
                        self.thread_info.setdefault(tid, {"dump_flags": hx(dump_flags), "dump_error": hx(dump_error), "exit_status": hx(exit_status),
                                                          "create_time": {"raw": created, "utc": filetime_iso(created), "epoch": "100 ns since 1601-01-01 UTC"},
                                                          "exit_time": {"raw": exited, "utc": filetime_iso(exited), "epoch": "100 ns since 1601-01-01 UTC"} if exited else None,
                                                          "kernel_time_100ns": kernel, "user_time_100ns": user, "start_address": start, "affinity": hx(affinity)})
        got = self.stream("ThreadNames")
        if got is not None:
            rva, size, in_file = got
            if min(size, in_file) < 4:
                self.problem("ThreadNames", rva, "the stream holds %d bytes and its count needs 4" % min(size, in_file))
            else:
                data, take = self.table("ThreadNames", rva, size, in_file, 4, struct.unpack("<I", self.read(rva, 4))[0], 12, MAX_THREADS, "MINIDUMP_THREAD_NAME")
                for i in range(take):
                    if not i & 1023:
                        tick("the thread names were read")
                    tid, name_rva = struct.unpack_from("<IQ", data, i * 12)
                    self.thread_names.setdefault(tid, (name_rva, rva + 4 + i * 12 + 4))

    def parse_memory(self):
        raw = []                    # (va, declared bytes, file offset, source)
        got = self.stream("Memory64List")
        if got is not None:
            rva, size, in_file = got
            if min(size, in_file) < 16:
                self.problem("Memory64List", rva, "the stream holds %d bytes and its header needs 16" % min(size, in_file))
            else:
                count, base_rva = struct.unpack("<QQ", self.read(rva, 16))
                self.ranges_declared += count
                data, take = self.table("Memory64List", rva, size, in_file, 16, count, 16, MAX_RANGES, "MINIDUMP_MEMORY_DESCRIPTOR64")
                listed = []
                for va, length in struct.iter_unpack("<QQ", data[:take * 16]):
                    if not len(listed) & 4095:
                        tick("the Memory64List was read")
                    listed.append((va, length))
                # The ranges' data lie one after another from BaseRva: a BaseRva of 0 (the header's place) with bytes declared is a
                # location that is not read, and none of those bytes is taken for the process's memory.
                total = sum(length for _va, length in listed)
                if base_rva >= HEADER_BYTES or not total:
                    at = base_rva
                    for va, length in listed:
                        if not len(raw) & 4095:
                            tick("the Memory64List was read")
                        raw.append((va, length, at, "Memory64List"))
                        at += length
                else:
                    self.locate("Memory64List", total, base_rva, "the memory of the Memory64List (%d ranges, from its BaseRva)" % len(listed), 1, rva + 8)
                    self.ranges_unreadable += sum(1 for _va, length in listed if length)
        got = self.stream("MemoryList")
        if got is not None:
            rva, size, in_file = got
            if min(size, in_file) < 4:
                self.problem("MemoryList", rva, "the stream holds %d bytes and its count needs 4" % min(size, in_file))
            else:
                count = struct.unpack("<I", self.read(rva, 4))[0]
                self.ranges_declared += count
                data, take = self.table("MemoryList", rva, size, in_file, 4, count, 16, max(0, MAX_RANGES - len(raw)), "MINIDUMP_MEMORY_DESCRIPTOR")
                for n, (va, length, at) in enumerate(struct.iter_unpack("<QII", data[:take * 16])):
                    if not len(raw) & 4095:
                        tick("the MemoryList was read")
                    if length and at < HEADER_BYTES:
                        # Bytes declared at RVA 0 are the file's header, not the process's memory: said, and the range is not mapped. A
                        # range past the file or cut by it is mapped for the bytes the file holds and said once, below, for all of them.
                        self.locate("MemoryList", length, at, "the memory range at %s" % hx(va), 1, rva + 4 + n * 16 + 12)
                        self.ranges_unreadable += 1
                        continue
                    raw.append((va, length, at, "MemoryList"))
        # One address, one place: the ranges in address order, an overlap given to the range that starts first, a range the file ends
        # inside counted for what the file holds of it.
        raw.sort(key=lambda r: (r[0], 0 if r[3] == "Memory64List" else 1))
        end = 0
        overlaps = cut = empty = 0
        first_overlap = first_cut = None
        tick("the memory ranges were put in address order")
        for n, (va, length, at, source) in enumerate(raw):
            if not n & 4095:
                tick("the memory ranges were put in address order")
            if length == 0:
                empty += 1
                continue
            if va + length > U64 + 1:
                self.problem(source, at, "the range at %s declares %d bytes, past the end of the address space; it is read up to the end" % (hx(va), length))
                length = U64 + 1 - va
            if va < end:
                overlaps += 1
                if first_overlap is None:
                    first_overlap = (source, at, va)
                skip = end - va
                if skip >= length:
                    continue
                va, length, at = va + skip, length - skip, at + skip
            have = max(0, min(length, self.size - at))
            if have < length:
                cut += 1
                if first_cut is None:
                    first_cut = (source, at, va, length, have)
            self.seg_va.append(va)
            self.seg_len.append(length)
            self.seg_have.append(have)
            self.seg_off.append(at)
            self.seg_src.append(source)
            self.declared_bytes += length
            self.mapped_bytes += have
            end = va + length
        self.seg_sum = [0]
        for n, have in enumerate(self.seg_have):
            if not n & 4095:
                tick("the memory ranges were totalled")
            self.seg_sum.append(self.seg_sum[-1] + have)
        self.ranges_empty = empty
        self.ranges_overlapping, self.ranges_cut = overlaps, cut
        if overlaps:
            source, at, va = first_overlap
            self.problem(source, at, "%d range(s) overlap a range that starts earlier (the first at %s): each address is read from the range "
                                     "that starts first, and the dump holds a second copy that is not read" % (overlaps, hx(va)))
        if cut:
            source, at, va, length, have = first_cut
            self.problem(source, at, "%d range(s) run past the end of the file (the first: %s, %d bytes declared at file offset %d, %d in the "
                                     "file of %d bytes): the dump is truncated, and those bytes are not in it" % (cut, hx(va), length, at, have, self.size))
        got = self.stream("MemoryInfoList")
        if got is not None:
            rva, size, in_file = got
            if min(size, in_file) < 16:
                self.problem("MemoryInfoList", rva, "the stream holds %d bytes and its header needs 16" % min(size, in_file))
            else:
                header, entry, count = struct.unpack("<IIQ", self.read(rva, 16))
                if header < 16 or entry < 48:
                    self.problem("MemoryInfoList", rva, "the header says %d header bytes and %d bytes an entry; the format's are 16 and 48" % (header, entry))
                else:
                    data, take = self.table("MemoryInfoList", rva, size, in_file, header, count, entry, MAX_REGIONS, "MINIDUMP_MEMORY_INFO")
                    rows = []
                    for i in range(take):
                        if not i & 4095:
                            tick("the MemoryInfoList was read")
                        rows.append(struct.unpack_from("<QQIIQIII", data, i * entry))
                    del data
                    # The lookups (which region holds an address) need the regions in address order and apart. VirtualQuery gives them so;
                    # a list that is not so is put in order, and both facts are said: an answer about a region then rests on a list
                    # that is not laid out as the format's writer lays it out.
                    disorder = None
                    for i in range(len(rows) - 1):
                        if not i & 4095:
                            tick("the MemoryInfoList was checked for order")
                        if rows[i][0] > rows[i + 1][0]:
                            disorder = i + 1
                            break
                    if disorder is not None:
                        self.problem("MemoryInfoList", rva + header + disorder * entry,
                                     "the regions are not in address order (entry %d, at %s, comes after one at %s): they were sorted by base "
                                     "address before any was looked up" % (disorder, hx(rows[disorder][0]), hx(rows[disorder - 1][0])))
                        rows.sort(key=lambda r: r[0])
                    lapped, first_lap = 0, None
                    for i in range(len(rows) - 1):
                        if not i & 4095:
                            tick("the MemoryInfoList was checked for overlaps")
                        if rows[i][0] + rows[i][4] > rows[i + 1][0]:
                            lapped += 1
                            if first_lap is None:
                                first_lap = rows[i][0]
                    self.regions_overlapping = lapped
                    if lapped:
                        self.problem("MemoryInfoList", rva, "%d region(s) run into the region after them in address order (the first at %s): an "
                                     "address that more than one region claims is answered by the region with the highest base at or below "
                                     "it, or by none where that one ends below the address" % (lapped, hx(first_lap)))
                    for n, (base, abase, aprot, _pad, length, state, protect, kind) in enumerate(rows):
                        if not n & 4095:
                            tick("the MemoryInfoList was read")
                        self.reg_va.append(base)
                        self.reg_len.append(length)
                        self.reg_state.append(state)
                        self.reg_protect.append(protect)
                        self.reg_type.append(kind)
                        self.reg_abase.append(abase)
                        self.reg_aprot.append(aprot)

    def parse_exception(self):
        got = self.stream("Exception")
        if got is None:
            return
        rva, size, in_file = got
        if min(size, in_file) < 168:
            self.problem("Exception", rva, "the stream holds %d bytes and MINIDUMP_EXCEPTION_STREAM needs 168" % min(size, in_file))
            return
        data = self.read(rva, 168)
        tid, _pad, code, flags, record, where, count, _pad2 = struct.unpack_from("<IIIIQQII", data)
        params = struct.unpack_from("<15Q", data, 40)
        ctx_size, ctx_rva = struct.unpack_from("<II", data, 160)
        if count > 15:
            self.problem("Exception", rva + 32, "NumberParameters is %d and EXCEPTION_RECORD holds at most 15 (EXCEPTION_MAXIMUM_PARAMETERS); "
                                                "the 15 the record holds are listed" % count)
        minimum, kind = CONTEXT_BYTES.get(self.arch, (1, "a context"))
        loc = self.locate("Exception", ctx_size, ctx_rva, "the context of the exception's thread", minimum, rva + 160, kind)
        context = {"bytes": ctx_size, "file_offset": ctx_rva, "location": loc["state"]}
        if loc["why"]:
            context["why"] = loc["why"]
        self.exception = {"thread_id": tid, "code": hx(code), "code_name": EXCEPTIONS.get(code), "flags": hx(flags), "nested_record": hx(record),
                          "address": hx(where), "address_in_module": self.module_ref(where),
                          "parameters": [hx(v) for v in params[:min(count, 15)]], "parameters_declared": count,
                          "context": context,
                          "note": "the exception the dump's writer recorded; a dump taken of a running process (Task Manager, procdump with no "
                                  "trigger) has no exception stream or a zero code, and neither says the process crashed"}

    def parse_handles(self):
        got = self.stream("HandleData")
        if got is None:
            return
        rva, size, in_file = got
        if min(size, in_file) < 16:
            self.problem("HandleData", rva, "the stream holds %d bytes and its header needs 16" % min(size, in_file))
            return
        header, entry, count, _r = struct.unpack("<IIII", self.read(rva, 16))
        if header < 16 or entry < 32:
            self.problem("HandleData", rva, "the header says %d header bytes and %d bytes a descriptor; the format's are 16 and 32 or 40" % (header, entry))
            return
        data, take = self.table("HandleData", rva, size, in_file, header, count, entry, MAX_HANDLES, "MINIDUMP_HANDLE_DESCRIPTOR")
        by_rva, named = {}, 0
        for i in range(take):
            if not i & 4095:
                tick("the handle descriptors were counted")
            _handle, type_rva, name_rva = struct.unpack_from("<QII", data, i * entry)
            by_rva[type_rva] = by_rva.get(type_rva, 0) + 1
            named += 1 if name_rva else 0
        del data
        # Every distinct TypeNameRva is read (a writer puts one string a handle, so there are as many as handles), the most frequent first.
        # What bounds it is said and counted apart, never as "no type name": the clock (type_name_not_read), the number of distinct
        # names the answer lists (type_name_not_listed) and a string the file does not hold (type_name_unreadable).
        without = by_rva.pop(0, 0)
        order = sorted(by_rva.items(), key=lambda kv: -kv[1])
        by_type, keys = {}, {}
        unreadable = not_listed = not_read = read = 0
        for done, (type_rva, n) in enumerate(order):
            checkpoint()
            if late():
                not_read = sum(m for _r2, m in order[done:])
                self.problem("HandleData", rva, "max_seconds was reached after the type names at %d of %d distinct TypeNameRva values were "
                             "read: %d handle(s) have a type name that was not read (type_name_not_read)" % (done, len(order), not_read))
                break
            text = self.string("HandleData", type_rva, "a handle's type name")
            read += 1
            if text is None:
                unreadable += n
                continue
            key = keys.get(text)
            if key is None:
                if len(keys) >= MAX_HANDLE_TYPES:
                    not_listed += n
                    continue
                key = str(shown(text, "name")) if text else EMPTY_TYPE_NAME
                if text and key == EMPTY_TYPE_NAME:
                    key += " (a type name of that text)"        # the bucket of empty names is never shared with a name the dump holds
                keys[text] = key
            by_type[key] = by_type.get(key, 0) + n
        if not_listed:
            self.problem("HandleData", rva, "the handles have more than %d distinct type names: %d handle(s) whose type name is a further one "
                         "are counted apart (type_name_not_listed), not by name" % (MAX_HANDLE_TYPES, not_listed))
        self.handles = {"handles": take, "handles_declared": count, "with_an_object_name": named, "by_type": by_type,
                        "without_a_type_name": without, "type_name_unreadable": unreadable, "type_name_not_listed": not_listed,
                        "type_name_not_read": not_read, "type_name_strings_read": read, "type_names_listed_at_most": MAX_HANDLE_TYPES,
                        "note": "a count by object type. without_a_type_name counts the handles whose TypeNameRva is 0 and no other; a type "
                                "name string of 0 characters is counted under the key %s; a type "
                                "name the file does not hold (type_name_unreadable, each in problems), one past the %d distinct names "
                                "listed (type_name_not_listed) and one the clock left unread (type_name_not_read) are counted apart, and "
                                "any of the three makes the status partial. Object names are not printed here (they are in the dump at "
                                "each descriptor's ObjectNameRva)" % (EMPTY_TYPE_NAME, MAX_HANDLE_TYPES)}

    def comments(self):
        """The comment streams (CommentA, CommentW): text the dump's writer put in, such as the command line of the dumping tool. Lines, judged."""
        out = []
        for name, encoding in (("CommentA", "latin-1"), ("CommentW", "utf-16-le")):
            got = self.streams.get(name)
            if got is None:
                continue
            rva, size, in_file = got
            take = min(size, in_file, MAX_STRING_BYTES) & (~1 if name == "CommentW" else ~0)
            raw = self.read(rva, take)
            text, lossy = decode_utf16(raw) if name == "CommentW" else (raw.decode(encoding), 0)
            text = text.replace("\x00", "")
            if lossy:
                self.problem(name, rva, "the comment is not valid UTF-16 (%d unit(s) could not be decoded); U+FFFD stands for each in what is printed" % lossy)
            lines = [line.strip() for line in re.split(r"[\r\n]+", text) if line.strip()]
            if min(size, in_file) > take or len(lines) > 32:
                self.problem(name, rva, "the comment is %d bytes in %d line(s); the first %d bytes and 32 lines are read" % (size, len(lines), take))
            judged = []
            for line in lines[:32]:
                checkpoint()
                if late():
                    self.problem(name, rva, "max_seconds was reached: %d of the comment's first %d line(s) are in this answer" % (len(judged), len(lines[:32])))
                    break
                judged.append(shown(line, "text"))
            out.append({"stream": name, "bytes": size, "file_offset": rva, "lines": judged})
        return out

    # ---- addresses ----

    def segment(self, va):
        """The index of the range that holds `va` (declared), or -1."""
        at = bisect.bisect_right(self.seg_va, va) - 1
        return at if at >= 0 and va < self.seg_va[at] + self.seg_len[at] else -1

    def pieces(self, va, length):
        """[va, va + length) as pieces in address order: (va, bytes, file offset or None, why absent or None)."""
        end = va + length
        at = max(0, bisect.bisect_right(self.seg_va, va) - 1)
        turns = 0
        while va < end:
            turns += 1
            if not turns & 1023:
                tick("the ranges of an address range were walked")
            while at < len(self.seg_va) and self.seg_va[at] + self.seg_len[at] <= va:      # at most one step: `at` starts at the range at or below va
                at += 1
            if at >= len(self.seg_va) or self.seg_va[at] >= end:
                yield va, end - va, None, "not in the dump"
                return
            start = self.seg_va[at]
            if start > va:
                yield va, start - va, None, "not in the dump"
                va = start
            inside = va - start
            have = max(0, min(self.seg_have[at] - inside, end - va))
            if have:
                yield va, have, self.seg_off[at] + inside, None
                va += have
            lost = min(start + self.seg_len[at], end) - va
            if lost > 0:
                yield va, lost, None, "listed by the dump, but the file ends before these bytes (a truncated dump)"
                va += lost
            at += 1

    def present(self, va, length):
        """How many bytes of [va, va + length) the file holds: from the running totals of the ranges, without walking them."""
        if length <= 0 or not self.seg_va:
            return 0
        end = va + length
        lo = max(0, bisect.bisect_right(self.seg_va, va) - 1)
        hi = bisect.bisect_left(self.seg_va, end)
        if hi <= lo:
            return 0
        total = self.seg_sum[hi] - self.seg_sum[lo]
        start, have = self.seg_va[lo], self.seg_have[lo]
        if start < va:
            total -= min(have, va - start)
        start, have = self.seg_va[hi - 1], self.seg_have[hi - 1]
        if start + have > end:
            total -= start + have - max(end, start)
        return max(0, total)

    def read_va(self, va, length):
        """`length` bytes at the address `va`, or None when any of them is not in the dump."""
        out = []
        for _va, n, at, _why in self.pieces(va, length):
            if at is None:
                return None
            data = self.read(at, n)
            if len(data) < n:
                return None
            out.append(data)
        return b"".join(out)

    def region(self, va):
        """The index of the MemoryInfoList region that holds `va`, or -1."""
        at = bisect.bisect_right(self.reg_va, va) - 1
        return at if at >= 0 and va < self.reg_va[at] + self.reg_len[at] else -1

    def region_facts(self, at):
        if at < 0:
            return None
        return {"base": hx(self.reg_va[at]), "bytes": self.reg_len[at], "state": STATE.get(self.reg_state[at], hx(self.reg_state[at])),
                "protect": protect_name(self.reg_protect[at]), "type": MEMTYPE.get(self.reg_type[at], hx(self.reg_type[at]) if self.reg_type[at] else None),
                "allocation_base": hx(self.reg_abase[at]), "allocation_protect": protect_name(self.reg_aprot[at])}


def shown_path(text):
    """A path read from the dump, judged as a path. The shared rule withholds a path whole when one of its components is over 128
    characters, and it cuts components at `/` only, so a Windows path of more than 128 characters (any module under WinSxS) was one
    component. Here such a path, when it has no `/` of its own and no component over 128 characters between its backslashes, is judged
    with its backslashes read as `/` and printed with them put back (a placeholder holds no `/`, so every `/` of the result is one of
    the path's separators). The backstop is asked about the path as it stands as well, because one of its rules reads across a backslash
    and not across a `/`; what it calls a secret stays withheld whole."""
    if len(text) <= MAX_COMPONENT or "\\" not in text or "/" in text or len(text) > MAX_ONE:
        return shown(text, "path")
    if any(len(part) > MAX_COMPONENT for part in text.split("\\")) or _hidden(text) or _backstop_reason(text) is not None:
        return shown(text, "path")
    judged = shown(text.replace("\\", "/"), "path")
    if str(judged).startswith("<withheld "):
        return judged
    return Shown(str(judged).replace("/", "\\"))


def load(path):
    dump = Dump(path)
    dump.parse()
    dump.parse_system()
    dump.parse_modules()
    dump.parse_memory()
    dump.parse_threads()
    return dump


def status_of(dump, view, complete_basis, extra_partial=()):
    """The status pair: partial when a stream this view rests on has a fault (or for the reasons the view gives), complete otherwise."""
    wanted = VIEW_STREAMS[view]
    faults = sorted(s for s in dump.faulty if wanted is None or s in wanted or s in ("header", "directory"))
    reasons = list(extra_partial)
    if faults:
        reasons.append("the dump is truncated or malformed in %s (problems names each fault and its file offset); what could be read is reported"
                       % ", ".join(faults))
    if reasons:
        return "partial", "; ".join(reasons)
    return "complete", complete_basis


def base_answer(dump, p):
    return {"parser": PARSER, "path": shown(p["path"], "path"), "file_bytes": dump.size, "view": p["view"]}


def finish(dump, out, status, basis):
    out["status"], out["status_basis"] = status, basis
    out["problems"] = dump.problems
    out["problem_count"] = dump.problem_count
    if dump.problem_count > len(dump.problems):
        out["problems_note"] = "problems lists the first %d of %d" % (len(dump.problems), dump.problem_count)
    out = sealed(out)
    out["boundary"] = boundary_summary()
    emit(out)


def paged(total, offset, limit, make, deadline=None):
    """Rows offset.. of `total`, at most `limit` of them, at most INLINE_BYTES of JSON, and (after the first row) none started past
    `deadline`. Returns (rows, the paging facts)."""
    rows, used, at, cut = [], 0, offset, None
    while at < total and len(rows) < limit:
        if rows and deadline is not None and time.monotonic() > deadline:
            cut = "max_seconds was reached"
            break
        row = make(at)
        size = len(json.dumps(sealed(row)))
        if rows and used + size > INLINE_BYTES:
            cut = "the page reached %d bytes of JSON" % INLINE_BYTES
            break
        rows.append(row)
        used += size
        at += 1
        if not at % 64:
            checkpoint()
    more = at < total
    facts = {"total": total, "offset": offset, "returned": len(rows), "next_offset": at if more else None, "truncated": more}
    if more:
        facts["truncated_by"] = cut or "limit (%d)" % limit
        facts["how_to_continue"] = "call again with offset %d; every row is reachable that way, and nothing is dropped" % at
    if offset > total:
        facts["note"] = "offset is past the end of the list (%d rows)" % total
    return rows, facts


def judge_before(offset, total, make, deadline, what):
    """A page that begins past row 0 answers for the whole list, so the rows before it are judged too: each is made and dropped, which
    locates its records and names and records their faults, so a fault on an earlier row makes this page partial as it does page 0.
    Returns a partial reason when the clock stopped the judging before the page's first row."""
    stop = min(offset, total)
    for i in range(stop):
        if deadline is not None and time.monotonic() > deadline:
            return ["the %s before offset %d were judged to row %d when max_seconds was reached: a fault in a record of rows %d to %d "
                    "would not be said here (call with a larger max_seconds, or from offset 0)" % (what, offset, i, i, stop - 1)]
        make(i)
        if not (i + 1) % 64:
            checkpoint()
    return []


def dump_kind(dump):
    full = bool(dump.flags & 0x2)
    has64, has32 = "Memory64List" in dump.streams, "MemoryList" in dump.streams
    if full and has64:
        return ("full-memory process dump", "the flags say WithFullMemory and a Memory64List is present: the writer asked for all accessible "
                "committed memory of the process. Pages it could not read, and memory freed before the dump, are still absent")
    if has64 or has32:
        return ("partial process dump", "no WithFullMemory flag: the dump holds the ranges its writer chose (thread stacks, and what the other "
                "flags added). Most of the process's memory, module code included, is usually not in it")
    return ("process dump without memory", "the directory lists no MemoryList and no Memory64List: no byte of the process's memory is in the file")


# --- the views --------------------------------------------------------------------------------------------------------------------------

def unicode_string(dump, va):
    """A UNICODE_STRING at `va` in the process: (length in bytes, buffer address, text or None, units that could not be decoded)."""
    head = dump.read_va(va, 16 if dump.pointer == 8 else 8)
    if head is None:
        return None
    if dump.pointer == 8:
        length, _maximum, _pad, buffer = struct.unpack("<HHIQ", head)
    else:
        length, _maximum, buffer = struct.unpack("<HHI", head)
    raw = dump.read_va(buffer, length & ~1) if buffer and length else None
    text, lossy = decode_utf16(raw) if raw is not None else (None, 0)
    return length, buffer, text, lossy


def process_parameters(dump):
    """The image path, the command line and the current directory, by the PEB: TEB -> PEB -> RTL_USER_PROCESS_PARAMETERS. Each step that
    is not in the dump is said; nothing is searched for or guessed."""
    out = {"reached": False}
    if dump.arch not in (0, 9, 12):
        out["why_not"] = "the walk is written for x86, x64 and ARM64 layouts, and the dump's architecture is %s" % (dump.system or {}).get("architecture", "not stated")
        return out
    wide = dump.pointer == 8
    fmt = "<Q" if wide else "<I"
    tebs = [t["teb"] for t in dump.threads if t["teb"]]
    if not tebs:
        out["why_not"] = "no thread with a TEB address is in the thread list"
        return out
    peb = None
    for teb in tebs[:16]:
        raw = dump.read_va(teb + (0x60 if wide else 0x30), dump.pointer)
        if raw is not None:
            peb = struct.unpack(fmt, raw)[0]
            out["teb"] = hx(teb)
            break
    if peb is None:
        out["why_not"] = "the TEB of the first %d thread(s) is not in the dump (the first at %s), so the PEB's address cannot be read" % (min(len(tebs), 16), hx(tebs[0]))
        return out
    out["peb"] = hx(peb)
    raw = dump.read_va(peb + (0x10 if wide else 0x08), dump.pointer)
    if raw is not None:
        image_base = struct.unpack(fmt, raw)[0]
        out["image_base"] = hx(image_base)
        out["image_base_module"] = dump.module_ref(image_base)
    raw = dump.read_va(peb + (0x20 if wide else 0x10), dump.pointer)
    if raw is None:
        out["why_not"] = "the PEB at %s is not in the dump" % hx(peb)
        return out
    params = struct.unpack(fmt, raw)[0]
    out["process_parameters"] = hx(params)
    out["reached"] = True
    for key, at in (("current_directory", 0x38 if wide else 0x24), ("image_path", 0x60 if wide else 0x38), ("command_line", 0x70 if wide else 0x40)):
        got = unicode_string(dump, params + at)
        if got is None:
            out[key] = {"in_dump": False, "why_not": "the UNICODE_STRING at %s is not in the dump" % hx(params + at)}
            continue
        length, buffer, text, lossy = got
        place = next(dump.pieces(buffer, 1)) if buffer else None
        row = {"in_dump": text is not None, "va": hx(buffer), "bytes": length, "characters": length // 2,
               "file_offset": place[2] if place else None}
        if lossy:
            row["lossy"] = True
            row["lossy_note"] = "the string is not valid UTF-16: U+FFFD stands for each of the %d unit(s) that could not be decoded" % lossy
            i = dump.segment(buffer)
            dump.problem(dump.seg_src[i] if i >= 0 else "memory", place[2] if place else None,
                         "the %s the PEB points at (%s) is not valid UTF-16 (%d unit(s) could not be decoded); U+FFFD stands for each in what "
                         "is printed" % (key.replace("_", " "), hx(buffer), lossy))
        if text is not None:
            row["shown"] = shown(text, "text") if key == "command_line" else shown_path(text)
        elif length:
            row["why_not"] = "the string's buffer at %s is not in the dump" % hx(buffer)
        out[key] = row
    out["note"] = ("read through the PEB as the process held it when it was dumped; a process can rewrite these strings, so they are what the "
                   "process said of itself. The command line is judged by the SHOWN rules (a part shaped like a secret is replaced; a plain "
                   "password is printed); its bytes are at va, for view read")
    return out


def view_summary(dump, p):
    dump.parse_misc()
    dump.parse_exception()
    dump.parse_handles()
    out = base_answer(dump, p)
    kind, why = dump_kind(dump)
    out["header"] = dump.header
    out["dump_kind"] = {"kind": kind, "basis": why}
    out["system"] = dump.system
    out["process"] = dump.misc
    out["process_parameters"] = process_parameters(dump)
    out["exception"] = dump.exception
    out["comments"] = dump.comments()
    out["counts"] = {"streams": len(dump.directory), "modules": len(dump.modules), "unloaded_modules": len(dump.unloaded), "threads": len(dump.threads),
                     "memory_ranges": len(dump.seg_va), "memory_ranges_declared": dump.ranges_declared, "memory_ranges_empty": dump.ranges_empty,
                     "memory_ranges_overlapping": dump.ranges_overlapping, "memory_ranges_cut_by_end_of_file": dump.ranges_cut,
                     "memory_ranges_not_readable": dump.ranges_unreadable,
                     "memory_info_regions": len(dump.reg_va), "memory_info_regions_overlapping": dump.regions_overlapping}
    out["memory"] = {"mapped_bytes": dump.mapped_bytes, "declared_bytes": dump.declared_bytes,
                     "lowest_address": hx(dump.seg_va[0]) if dump.seg_va else None,
                     "highest_address": hx(dump.seg_va[-1] + dump.seg_len[-1] - 1) if dump.seg_va else None,
                     "note": "mapped_bytes is the memory of the process that is in this file; declared_bytes is what the dump's memory lists "
                             "declare (larger only when the file is truncated). Every other address of the process is not in the dump, "
                             "which is not the same as zero"}
    out["handles"] = dump.handles
    streams, facts = paged(len(dump.directory), 0, MAX_LIMIT, lambda i: dump.directory[i], p["deadline"])
    out["streams"] = streams
    if facts["truncated"]:
        out["streams_page"] = facts
    read_here = {"SystemInfo", "MiscInfo", "ModuleList", "UnloadedModuleList", "ThreadList", "ThreadExList", "ThreadInfoList", "ThreadNames",
                 "MemoryList", "Memory64List", "MemoryInfoList", "Exception", "HandleData", "CommentA", "CommentW"}
    if "ThreadList" in dump.streams:
        read_here.discard("ThreadExList")       # the threads are read from the ThreadList; a ThreadExList beside it is not read
    out["streams_not_read"] = sorted({s["name"] for s in dump.directory if s["type"] and s["name"] not in read_here})
    if "ThreadList" in dump.streams and "ThreadExList" in dump.streams:
        out["streams_not_read_note"] = ("the dump has a ThreadList and a ThreadExList: the threads are read from the ThreadList, and the "
                                        "ThreadExList (the same threads, each with its backing store) is not read")
    out["streams_absent"] = sorted(set(dump.absent))
    out["not_read_in_this_view"] = ("the entries of the module and thread lists are counted here, not followed: a module's name and PDB record "
                                    "and a thread's context and name are read by the views modules and threads, and a fault in one of them "
                                    "is reported there, not here (the names this view prints, of the modules that hold the exception "
                                    "address and the image base, are read)")
    extra = []
    if facts["truncated"]:
        extra.append("the directory has %d entries and %d are listed" % (facts["total"], facts["returned"]))
    handles = dump.handles or {}
    if handles.get("type_name_not_read") or handles.get("type_name_not_listed") or handles.get("type_name_unreadable"):
        extra.append("the handle count by type is not whole: %d handle(s) have a type name that was not read, %d one past the names listed, "
                     "%d one the file does not hold" % (handles["type_name_not_read"], handles["type_name_not_listed"], handles["type_name_unreadable"]))
    status, basis = status_of(dump, "summary", "the header, the directory and the fixed part of every stream this tool reads were read whole, with "
                                               "every handle's type name; module names, PDB records and thread contexts are not read in this view "
                                               "(not_read_in_this_view); the streams the tool does not read are named in streams_not_read, and "
                                               "the ones the dump does not have in streams_absent", extra)
    finish(dump, out, status, basis)


def pdb_record(dump, module):
    """What a module's entry says of its CodeView record, in cases a reader can tell apart: None (the entry declares no record: 0 bytes),
    a record that was read (RSDS with its GUID, age and path, or one of another format), and a record that is declared and was not read
    (read false: at RVA 0, past the file, smaller than a signature, or with fewer bytes in the file than are read of it). Where the record
    points is judged by Dump.locate, which names every fault in problems, so the answer is partial; location says its state. A record
    whose first bytes are in the file and whose declared end is not is read and says cut_by_file. A path that the PDB_PATH_BYTES read of
    it do not end is said to be cut, and a path that is not UTF-8 is said to be lossy."""
    cv_size, cv_rva = module["cv"]
    what = "the CodeView (PDB) record of module %d" % module["index"]
    loc = dump.locate("ModuleList", cv_size, cv_rva, what, 4, module["entry_offset"] + 76, "a CodeView record (a 4-byte signature)")
    if loc["state"] == "none":
        return None
    out = {"read": False, "declared_bytes": cv_size, "file_offset": cv_rva, "format": None, "location": loc["state"]}
    if loc["state"] == "declared_not_readable":
        out["why_not"] = loc["why"]
        return out
    if loc["state"] == "cut_by_file":
        # The record's declared end is not in the file (said once, in problems, by locate); what the file holds of it is read.
        out["cut_by_file"] = True
        out["cut_note"] = loc["why"]
    take = min(cv_size, 24 + PDB_PATH_BYTES)
    raw = dump.read(cv_rva, take)
    if len(raw) < take:
        if raw[:4] == b"RSDS":
            out["format"] = "RSDS"
        out["why_not"] = ("the record declares %d bytes at file offset %d and the file holds %d of the %d bytes that are read of it "
                          "(problems): the record is declared and not readable, which is not a module without a record" % (cv_size, cv_rva, len(raw), take))
        return out
    out["read"] = True
    if raw[:4] != b"RSDS":
        out["format"] = "not RSDS"
        return out
    if len(raw) < 24:
        out["format"] = "RSDS"
        out["read"] = False
        out["why_not"] = "the record begins with RSDS and declares %d bytes; its GUID and age need 24" % cv_size
        dump.problem("ModuleList", cv_rva, "%s: it begins with RSDS and declares %d bytes, fewer than the 24 of its fixed part" % (what, cv_size))
        return out
    d1, d2, d3 = struct.unpack_from("<IHH", raw, 4)
    path, ended, _rest = raw[24:].partition(b"\x00")
    text, lossy = decode_utf8(path)
    out.update(format="RSDS", guid="%08X%04X%04X%s" % (d1, d2, d3, raw[12:20].hex().upper()), age=struct.unpack_from("<I", raw, 20)[0],
               path=shown_path(text) if text else None, path_bytes_read=len(path), path_cut=False)
    if lossy:
        out["path_lossy"] = True
        out["path_lossy_note"] = ("the path is not UTF-8: %d byte sequence(s) could not be decoded and U+FFFD stands for each in what is "
                                  "printed, so the printed path is not the path's bytes" % lossy)
        dump.problem("ModuleList", cv_rva + 24, "%s: the path is not UTF-8 (%d byte sequence(s) could not be decoded); U+FFFD stands for each "
                                                "in what is printed" % (what, lossy))
    if not ended and cv_size > take:
        out["path_cut"] = True
        out["path_note"] = ("the record declares %d bytes; the first %d bytes of its path were read and the path does not end in them, so "
                            "what is printed is the beginning of the path" % (cv_size, PDB_PATH_BYTES))
        dump.problem("ModuleList", cv_rva, "%s: %d bytes are declared and the path does not end in the first %d bytes of it, which are what "
                     "was read" % (what, cv_size, PDB_PATH_BYTES))
    elif not ended:
        out["path_note"] = "the path has no terminating NUL inside the record's %d bytes; it is printed as far as the record goes" % cv_size
    return out


def module_row(dump, module, state):
    name = dump.module_name(module, "ModuleList" if state == "loaded" else "UnloadedModuleList")
    row = {"state": state, "index": module["index"], "base": hx(module["base"]), "size": module["size"],
           "end": hx(module["base"] + module["size"]), "name": shown(re.split(r"[\\/]", name)[-1], "name") if name else None,
           "path": shown_path(name) if name else None,
           "timestamp": {"raw": module["stamp"], "utc": iso(module["stamp"]), "epoch": "seconds since 1970-01-01 UTC (the PE header's TimeDateStamp as the loader recorded it)"},
           "checksum": hx(module["checksum"]), "entry_file_offset": module["entry_offset"]}
    if not name:
        row["name_why_not"] = ("the entry's name RVA is %d, where the file's header is: the name was not read (problems), and this is not a "
                               "module without a name" % module["name_rva"] if module["name_rva"] < HEADER_BYTES else
                               "the name string at file offset %d is empty (0 characters)" % module["name_rva"] if name == "" else
                               "the name string at file offset %d could not be read (problems)" % module["name_rva"])
    if state == "loaded":
        fixed = module["fixed"]
        if fixed[0] == 0xFEEF04BD:
            row["file_version"] = "%d.%d.%d.%d" % (fixed[2] >> 16, fixed[2] & 0xFFFF, fixed[3] >> 16, fixed[3] & 0xFFFF)
            row["product_version"] = "%d.%d.%d.%d" % (fixed[4] >> 16, fixed[4] & 0xFFFF, fixed[5] >> 16, fixed[5] & 0xFFFF)
        else:
            row["file_version"] = row["product_version"] = None
        row["pdb"] = pdb_record(dump, module)
        row["pdb_record"] = ("none declared" if row["pdb"] is None else "declared, not readable" if not row["pdb"]["read"]
                             else "read" if row["pdb"]["format"] == "RSDS" else "read, not RSDS")
        have = dump.present(module["base"], module["size"]) if module["size"] else 0
        row["image_bytes_in_dump"] = have
        row["image_coverage_percent"] = round(100.0 * have / module["size"], 2) if module["size"] else None
    return row


def view_modules(dump, p):
    out = base_answer(dump, p)
    total = len(dump.modules) + len(dump.unloaded)

    def make(i):
        return module_row(dump, dump.modules[i], "loaded") if i < len(dump.modules) else module_row(dump, dump.unloaded[i - len(dump.modules)], "unloaded")
    before = judge_before(p["offset"], total, make, p["deadline"], "module rows")
    rows, facts = paged(total, p["offset"], p["limit"], make, p["deadline"])
    out["modules"] = rows
    out["page"] = facts
    out["counts"] = {"loaded": len(dump.modules), "unloaded": len(dump.unloaded)}
    out["streams_absent"] = sorted(s for s in set(dump.absent) if s in ("ModuleList", "UnloadedModuleList"))
    out["note"] = ("base and size are the image as the loader mapped it. image_bytes_in_dump is how much of that image's memory the dump holds: "
                   "a partial dump holds little or none of a module's code, and a module that is not wholly present has gaps (view module says "
                   "where). The timestamp and checksum are the loader's copy of the PE header's fields, which the file's author sets (a reproducible build, as "
                   "of Windows system files, puts a hash there, so a date far from the dump's is not a finding by itself). The loaded "
                   "rows come first, then the unloaded ones")
    extra = ["%d of %d rows are on this page (page.next_offset continues)" % (facts["returned"], total)] if facts["truncated"] else []
    extra += before
    status, basis = status_of(dump, "modules", "every entry of the module lists the dump has was read%s"
                              % ("" if not out["streams_absent"] else " (absent from this dump: %s)" % ", ".join(out["streams_absent"])), extra)
    finish(dump, out, status, basis)


def region_match(dump, at, p):
    if at < 0:
        return p["protect"] == "any" and p["type"] == "any"
    protect, kind = dump.reg_protect[at] & 0xFF, dump.reg_type[at]
    executable, writable = protect in (0x10, 0x20, 0x40, 0x80), protect in (0x04, 0x08, 0x40, 0x80)
    if p["protect"] == "execute" and not executable:
        return False
    if p["protect"] == "write" and not writable:
        return False
    if p["protect"] == "execute_write" and not (executable and writable):
        return False
    return p["type"] == "any" or kind == {"private": 0x20000, "mapped": 0x40000, "image": 0x1000000}[p["type"]]


def matching_part(dump, va, length, p, first_only=False):
    """What of the range [va, va + length) the protect and type filters are met by: (regions that match, bytes of the range in them, the
    first as (region index, from, to)). A range the dump holds can lie over several regions (a writer joins neighbours), so every region it
    overlaps is asked, not only the one at its first address: the region that holds `va`, then each that begins inside the range."""
    end = va + length
    at = dump.region(va)
    if at < 0:
        at = bisect.bisect_right(dump.reg_va, va)
    stop = bisect.bisect_left(dump.reg_va, end)
    count = total = 0
    first = None
    for turn, i in enumerate(range(at, stop)):
        if not turn & 1023:
            tick("the regions under a memory range were compared with the filter")
        start, finish = max(va, dump.reg_va[i]), min(end, dump.reg_va[i] + dump.reg_len[i])
        if finish <= start or not region_match(dump, i, p):
            continue
        count += 1
        total += finish - start
        if first is None:
            first = (i, start, finish)
            if first_only:
                break
    return count, min(total, length), first


def view_memory(dump, p):
    out = base_answer(dump, p)
    has_info = "MemoryInfoList" in dump.streams
    filtered = p["protect"] != "any" or p["type"] != "any"
    if filtered and not has_info:
        fail("protect and type filter by the MemoryInfoList, and this dump has none: the protection of its ranges is not recorded in it. "
             "Call again without them", memory_info_list="absent")
    out["list"] = p["list"]
    # The view names the module that holds an address, so it rests on every module's name, not only on those of this page's rows:
    # each is read here (once, cached), so a name fault makes every page of this view partial alike.
    names_cut = []
    for n, module in enumerate(dump.modules):
        if p["deadline"] is not None and time.monotonic() > p["deadline"]:
            names_cut = ["max_seconds was reached after %d of %d module names were read: a fault in the others would not be said here"
                         % (n, len(dump.modules))]
            break
        dump.module_name(module)
        if not (n + 1) % 64:
            checkpoint()
    if p["list"] == "ranges":
        if filtered:
            keep = []
            for i in range(len(dump.seg_va)):
                if not i & 1023:
                    tick("the memory ranges were compared with the filter")
                if matching_part(dump, dump.seg_va[i], dump.seg_len[i], p, first_only=True)[0]:
                    keep.append(i)
        else:
            keep = range(len(dump.seg_va))

        def make(n):
            i = keep[n]
            va, length, have = dump.seg_va[i], dump.seg_len[i], dump.seg_have[i]
            row = {"va": hx(va), "bytes": length, "end": hx(va + length), "file_offset": dump.seg_off[i], "bytes_in_file": have, "source": dump.seg_src[i]}
            if has_info:
                at = dump.region(va)
                row["region"] = dump.region_facts(at)
                last = dump.region(va + length - 1)
                if at >= 0 and last != at:
                    row["regions_spanned"] = (last - at + 1) if last >= 0 else None
                    row["region_note"] = ("the range spans more than one region; region is the one at its first address%s"
                                          % (", and matched says which part of the range the filter is met by" if filtered else ""))
                if filtered:
                    count, total, first = matching_part(dump, va, length, p)
                    row["matched"] = {"regions": count, "bytes": total, "whole_range": total >= length,
                                      "first": {"va": hx(first[1]), "end": hx(first[2]), "region": dump.region_facts(first[0])}}
            module = dump.module_ref(va)
            if module:
                row["module"] = module
            return row
        rows, facts = paged(len(keep), p["offset"], p["limit"], make, p["deadline"])
        out["ranges"] = rows
        out["totals"] = {"ranges": len(dump.seg_va), "ranges_matching": len(keep), "mapped_bytes": dump.mapped_bytes, "declared_bytes": dump.declared_bytes}
    else:
        if not has_info:
            fail("list regions reads the MemoryInfoList, and this dump has none. list ranges gives the memory the dump holds", memory_info_list="absent")
        if filtered:
            keep = []
            for i in range(len(dump.reg_va)):
                if not i & 4095:
                    tick("the regions were compared with the filter")
                if region_match(dump, i, p):
                    keep.append(i)
        else:
            keep = range(len(dump.reg_va))

        def make(n):
            i = keep[n]
            row = dump.region_facts(i)
            row["end"] = hx(dump.reg_va[i] + dump.reg_len[i])
            row["bytes_in_dump"] = dump.present(dump.reg_va[i], dump.reg_len[i]) if dump.reg_len[i] and dump.reg_va[i] + dump.reg_len[i] <= U64 + 1 else 0
            module = dump.module_ref(dump.reg_va[i])
            if module:
                row["module"] = module
            return row
        rows, facts = paged(len(keep), p["offset"], p["limit"], make, p["deadline"])
        out["regions"] = rows
        out["totals"] = {"regions": len(dump.reg_va), "regions_matching": len(keep)}
    out["page"] = facts
    out["filter"] = {"protect": p["protect"], "type": p["type"]}
    if filtered:
        out["filter"]["rule"] = ("a range is listed when any region it overlaps meets the filter (protect and type are both asked of the same "
                                 "region), not only the region at its first address; its row says in matched how many regions, how many "
                                 "bytes and where the first is" if p["list"] == "ranges" else "a region is listed when it meets the filter itself")
    out["memory_info_list"] = "present" if has_info else "absent: the dump does not record the protection, state or type of its ranges"
    out["note"] = ("a range is memory the dump holds, at file_offset; bytes_in_file is less than bytes only where the file is truncated. A region "
                   "is the process's own bookkeeping (VirtualQuery) at the moment of the dump: it can be reserved or free and hold no bytes, and "
                   "its protection is the page protection then, not what the pages were earlier. Addresses between ranges are not in the dump")
    extra = ["%d of %d rows are on this page (page.next_offset continues)" % (facts["returned"], facts["total"])] if facts["truncated"] else []
    extra += names_cut
    status, basis = status_of(dump, "memory", "every entry of the dump's memory lists%s was read" % (" and of its MemoryInfoList" if has_info else ""), extra)
    finish(dump, out, status, basis)


X64_REGS = (("rax", 0x78), ("rcx", 0x80), ("rdx", 0x88), ("rbx", 0x90), ("rsp", 0x98), ("rbp", 0xA0), ("rsi", 0xA8), ("rdi", 0xB0), ("r8", 0xB8),
            ("r9", 0xC0), ("r10", 0xC8), ("r11", 0xD0), ("r12", 0xD8), ("r13", 0xE0), ("r14", 0xE8), ("r15", 0xF0), ("rip", 0xF8))
X86_REGS = (("edi", 0x9C), ("esi", 0xA0), ("ebx", 0xA4), ("edx", 0xA8), ("ecx", 0xAC), ("eax", 0xB0), ("ebp", 0xB4), ("eip", 0xB8),
            ("eflags", 0xC0), ("esp", 0xC4))


def context(dump, size, rva, stream, what, at):
    """The register values of a thread context: x64 (CONTEXT of 1,232 bytes) and x86 (716 bytes); any other architecture's is located and
    not decoded. Where it points is judged by Dump.locate: a context declared at RVA 0, at or past the end of the file, or smaller than
    the architecture's CONTEXT is declared_not_readable (in problems, never decoded as a CONTEXT it is too short to be), one the file cuts
    is decoded from the bytes the file holds when they reach the registers, and both make the answer partial. `at` is the place of the
    location in the thread's entry."""
    minimum, kind = CONTEXT_BYTES.get(dump.arch, (1, "a context"))
    loc = dump.locate(stream, size, rva, what, minimum, at, kind)
    out = {"bytes": size, "file_offset": rva, "location": loc["state"], "decoded": False}
    if loc["state"] in ("none", "declared_not_readable"):
        out["why_not"] = loc["why"]
        return out
    if loc["state"] == "cut_by_file":
        out["cut_by_file"] = True
        out["cut_note"] = loc["why"]
    if dump.arch in (9, 0):
        need = 0x100 if dump.arch == 9 else 0xCC
        raw = dump.read(rva, need)
        if len(raw) < need:
            out["why_not"] = ("the file ends %d bytes into the record, before the end of the first %d bytes, where the registers are read; it "
                              "was not decoded (problems)" % (loc["in_file"], need))
            return out
    if dump.arch == 9:
        out.update(decoded=True, layout="x64 CONTEXT", context_flags=hx(struct.unpack_from("<I", raw, 0x30)[0]), eflags=hx(struct.unpack_from("<I", raw, 0x44)[0]),
                   registers={name: hx(struct.unpack_from("<Q", raw, at)[0]) for name, at in X64_REGS})
        segs = struct.unpack_from("<6H", raw, 0x38)
        out["segments"] = dict(zip(("cs", "ds", "es", "fs", "gs", "ss"), (hx(s) for s in segs)))
        out["ip"], out["sp"] = struct.unpack_from("<Q", raw, 0xF8)[0], struct.unpack_from("<Q", raw, 0x98)[0]
    elif dump.arch == 0:
        out.update(decoded=True, layout="x86 CONTEXT", context_flags=hx(struct.unpack_from("<I", raw, 0)[0]),
                   registers={name: hx(struct.unpack_from("<I", raw, at)[0]) for name, at in X86_REGS})
        gs, fs, es, ds = struct.unpack_from("<4I", raw, 0x8C)
        out["segments"] = {"cs": hx(struct.unpack_from("<I", raw, 0xBC)[0]), "ds": hx(ds), "es": hx(es), "fs": hx(fs), "gs": hx(gs), "ss": hx(struct.unpack_from("<I", raw, 0xC8)[0])}
        out["ip"], out["sp"] = struct.unpack_from("<I", raw, 0xB8)[0], struct.unpack_from("<I", raw, 0xC4)[0]
    else:
        out["why_not"] = ("register values are decoded for x86 and x64 contexts; this dump's architecture is %s and the record of %d bytes is "
                          "located, not decoded" % ((dump.system or {}).get("architecture", "not stated (no SystemInfo stream)"), size))
    return out


def view_threads(dump, p):
    out = base_answer(dump, p)
    stream = "ThreadList" if "ThreadList" in dump.streams else "ThreadExList"

    def make(i):
        t = dump.threads[i]
        stack_va, stack_size, stack_rva = t["stack"]
        ctx = context(dump, t["context"][0], t["context"][1], stream, "the context of thread %d (entry %d)" % (t["id"], i), t["entry_offset"] + 40)
        ip, sp = ctx.pop("ip", None), ctx.pop("sp", None)
        # The stack descriptor is a location like any other: bytes_in_file counts only what it points at in the file, never the header's
        # bytes for an RVA of 0; bytes_in_memory_lists says how much of the stack's address range the memory lists hold, found by address.
        # One case is not a fault: an RVA of 0 with the whole range in the memory lists, which is how a full-memory dump's writer lays
        # its stacks out (their bytes are in the Memory64List, which a 32-bit RVA cannot point into); location says in_memory_lists.
        held = dump.present(stack_va, stack_size) if stack_size and stack_va + stack_size <= U64 + 1 else 0
        if stack_size and not stack_rva and held == stack_size:
            loc = {"state": "in_memory_lists", "in_file": 0,
                   "why": "the descriptor gives RVA 0 and the memory lists hold the stack's whole address range (bytes_in_memory_lists), as a "
                          "full-memory dump's writer lays a stack out: its bytes are read by address, and none of the header's is taken for them"}
        else:
            loc = dump.locate(stream, stack_size, stack_rva, "the stack of thread %d (entry %d)" % (t["id"], i), 1, t["entry_offset"] + 24)
        stack = {"va": hx(stack_va), "bytes": stack_size, "end": hx(stack_va + stack_size), "file_offset": stack_rva, "location": loc["state"],
                 "bytes_in_file": loc["in_file"], "bytes_in_memory_lists": held}
        if loc["why"]:
            stack["why"] = loc["why"]
        row = {"index": i, "thread_id": t["id"], "suspend_count": t["suspend"], "priority_class": t["class"], "priority": t["priority"],
               "teb": hx(t["teb"]), "teb_in_dump": dump.segment(t["teb"]) >= 0, "stack": stack, "context": ctx, "entry_file_offset": t["entry_offset"]}
        if ip is not None:
            row["instruction_pointer_in_module"] = dump.module_ref(ip)
            row["stack_pointer_in_stack"] = stack_va <= sp < stack_va + stack_size
        info = dump.thread_info.get(t["id"])
        if info is not None:
            info = dict(info)
            start = info.pop("start_address")
            info["start_address"] = hx(start)
            info["start_address_in_module"] = dump.module_ref(start)
            row["info"] = info
        if t["id"] in dump.thread_names:
            name_rva, name_at = dump.thread_names[t["id"]]
            text = dump.string("ThreadNames", name_rva, "the name of thread %d" % t["id"], name_at)
            row["name"] = shown(text, "name") if text else None
            if text is None:
                row["name_why_not"] = "the ThreadNames entry gives a name at RVA %d and it could not be read (problems)" % name_rva
            elif not text:
                row["name_why_not"] = "the name string at file offset %d is empty (0 characters)" % name_rva
        return row
    before = judge_before(p["offset"], len(dump.threads), make, p["deadline"], "thread rows")
    rows, facts = paged(len(dump.threads), p["offset"], min(p["limit"], 500), make, p["deadline"])
    out["threads"] = rows
    out["page"] = facts
    out["architecture"] = (dump.system or {}).get("architecture")
    out["streams_absent"] = sorted(s for s in set(dump.absent) if s in ("ThreadList", "ThreadInfoList", "ThreadNames", "SystemInfo"))
    out["note"] = ("register values are the thread's saved context at the moment of the dump. instruction_pointer_in_module and "
                   "start_address_in_module are null when the address is in no loaded module of the module list: private or mapped memory, "
                   "which is a lead to look at (view va, then memory), not a finding that code was injected. Times and start addresses come "
                   "from the ThreadInfoList and are absent when the dump has none")
    extra = ["%d of %d threads are on this page (page.next_offset continues)" % (facts["returned"], facts["total"])] if facts["truncated"] else []
    extra += before
    status, basis = status_of(dump, "threads", "every thread of the dump's thread list was read, with the context and stack records it declares", extra)
    finish(dump, out, status, basis)


def nearest(dump, va):
    at = bisect.bisect_right(dump.seg_va, va) - 1
    below = {"va": hx(dump.seg_va[at]), "end": hx(dump.seg_va[at] + dump.seg_len[at])} if at >= 0 else None
    above = {"va": hx(dump.seg_va[at + 1]), "end": hx(dump.seg_va[at + 1] + dump.seg_len[at + 1])} if at + 1 < len(dump.seg_va) else None
    return below, above


def view_va(dump, p):
    out = base_answer(dump, p)
    rows, left = [], []
    for asked, va in enumerate(p["addresses"]):
        checkpoint()
        if rows and late():         # a module's name is judged for each address: past the clock the rest is said, not looked up
            left = p["addresses"][asked:]
            break
        va, n, at, why = next(dump.pieces(va, 1))
        row = {"va": hx(va), "in_dump": at is not None}
        if at is not None:
            i = dump.segment(va)
            row["file_offset"] = at
            row["range"] = {"va": hx(dump.seg_va[i]), "bytes": dump.seg_len[i], "file_offset": dump.seg_off[i], "source": dump.seg_src[i]}
            row["bytes_from_here_in_range"] = dump.seg_va[i] + dump.seg_have[i] - va
        else:
            row["why_not"] = why
            row["meaning"] = "the dump holds no byte for this address: its content is unknown, not zero"
            row["nearest_range_below"], row["nearest_range_above"] = nearest(dump, va)
        region = dump.region(va)
        if region >= 0:
            row["region"] = dump.region_facts(region)
        elif dump.reg_va:
            row["region"] = None
        module = dump.module_ref(va)
        if module:
            row["module"] = module
        rows.append(row)
    out["addresses"] = rows
    out["page"] = {"total": len(p["addresses"]), "returned": len(rows), "next_offset": None, "truncated": bool(left)}
    if left:
        out["not_answered"] = [hx(va) for va in left]
        out["page"]["how_to_continue"] = "call again with the addresses of not_answered; each address is answered by itself"
    out["counts"] = {"in_dump": sum(1 for r in rows if r["in_dump"]), "not_in_dump": sum(1 for r in rows if not r["in_dump"])}
    out["memory_info_list"] = "present" if "MemoryInfoList" in dump.streams else "absent"
    out["note"] = ("file_offset is where the byte at va is in the dump file. An address that is not in the dump has no file offset: the writer "
                   "did not put that memory in the file (or the file is truncated), which says nothing of what the process held there")
    status, basis = status_of(dump, "va", "each of the %d address(es) was looked up in every memory range the dump lists" % len(rows),
                              ["max_seconds (%d) was reached after %d of %d addresses; the others are in not_answered" % (p["seconds"], len(rows), len(p["addresses"]))] if left else [])
    finish(dump, out, status, basis)


def coverage_of(dump, va, length):
    """The pieces of [va, va + length) and the totals of what is present and what is not."""
    segments, present, absent, gaps = [], 0, 0, 0
    for turn, (at_va, n, at, why) in enumerate(dump.pieces(va, length)):
        if not turn & 1023:
            tick("the coverage of the range was counted")
        last = segments[-1] if segments else None
        if last is not None and at is None and last["state"] == "absent" and last["why"] == why:
            last["bytes"] += n
        elif last is not None and at is not None and last["state"] == "present" and last["file_offset"] + last["bytes"] == at:
            last["bytes"] += n
        else:
            row = {"offset": at_va - va, "va": hx(at_va), "bytes": n, "state": "present" if at is not None else "absent"}
            if at is not None:
                row["file_offset"] = at
            else:
                row["why"] = why
                gaps += 1
            segments.append(row)
        if at is not None:
            present += n
        else:
            absent += n
    return segments, {"bytes": length, "bytes_present": present, "bytes_absent": absent, "gaps": gaps,
                      "coverage_percent": round(100.0 * present / length, 4) if length else None}


def write_range(dump, p, va, length, name, what, deadline):
    """Write [va, va + length) to $OUT/minidump_map/<name> and its map beside it. Absent bytes are zero in the file and listed in the map."""
    body = OutFile(name)
    zeros = bytes(1 << 20)
    for at_va, n, at, _why in dump.pieces(va, length):
        done = 0
        while done < n:
            take = min(CHUNK if at is not None else len(zeros), n - done)
            if at is not None:
                block = dump.read(at + done, take)
                if len(block) < take:
                    fail("the dump could not be read at file offset %d (%d of %d bytes); nothing was kept" % (at + done, len(block), take), written=False)
            else:
                block = zeros[:take]
            body.write(block)
            done += take
            checkpoint()
            if time.monotonic() > deadline:
                fail("the file was not finished within max_seconds (%d): nothing was kept. Raise max_seconds or read a smaller range" % p["seconds"],
                     written=False, bytes_written_before_the_stop=body.bytes)
    placed = body.finish(hold=True)
    segments, totals = coverage_of(dump, va, length)
    map_file = OutFile(name + ".map.json")
    map_file.write(json.dumps({"parser": PARSER, "what": what, "file": placed.rsplit("/", 1)[-1], "va": hx(va), **totals,
                               "absent_bytes_are": "zero in the file; they were not in the dump, and their content is unknown",
                               "segments": segments}, indent=1).encode("ascii"))
    placed_map = map_file.finish(hold=True)
    GUARD["depth"] += 1                     # the digests are recorded and the two files become the call's result in one step a stop cannot split
    try:
        listed = record_digests([{"file": placed.rsplit("/", 1)[-1], "bytes": body.bytes, "sha256": body.digest.hexdigest(), "what": what, "va": hx(va),
                                  "bytes_present": totals["bytes_present"], "bytes_absent": totals["bytes_absent"]},
                                 {"file": placed_map.rsplit("/", 1)[-1], "bytes": map_file.bytes, "sha256": map_file.digest.hexdigest(), "what": "the map of " + what}])
        body.release()
        map_file.release()
    finally:
        GUARD["depth"] -= 1
    checkpoint()
    return {"written": True, "file": placed, "file_bytes": body.bytes, "map_file": placed_map, "digests_in": listed, "contains_secret_values": True,
            "note": "the file is memory content: cite it by job and path, never by content. file_bytes is the length of the range that was asked "
                    "for (absent bytes are zeros in the file); the file's sha256 is in digests_in, with its size, and not in this answer"}


def answer_range(dump, p, out, view, va, length, name, what, complete_basis, deadline):
    segments, totals = coverage_of(dump, va, length)
    out["coverage"] = totals
    gaps = [s for s in segments if s["state"] == "absent"]
    out["gaps"] = gaps[:MAX_GAPS_INLINE]
    if len(gaps) > MAX_GAPS_INLINE:
        out["gaps_note"] = "the first %d of %d gaps; the map file written with the image lists every one" % (MAX_GAPS_INLINE, len(gaps))
    extra = []
    if totals["bytes_absent"]:
        extra.append("%d of %d bytes (%.4f%%) are not in the dump: they are gaps, not zeros" % (totals["bytes_absent"], length, 100.0 * totals["bytes_absent"] / length))
    if not p["write_values"]:
        out["output"] = {"written": False, "why": "nothing is written without write_values: true (in a job run as secret output); this answer says what "
                                                  "of the range is in the dump"}
    elif totals["bytes_present"] == 0:
        out["output"] = {"written": False, "why": "no byte of the range is in the dump, so there is nothing to write"}
    elif totals["bytes_absent"] and not p["allow_gaps"]:
        out["output"] = {"written": False, "refused": True,
                         "why": "the range has gaps, and a file with gaps is written only with allow_gaps: true. It then holds zeros where the dump "
                                "holds nothing, every gap is listed in the map file beside it, and the status is partial"}
        extra.append("nothing was written: allow_gaps was not set")
    else:
        if totals["bytes_absent"]:
            stem, dot, suffix = name.rpartition(".")
            name = "%s.gaps%s%s" % (stem, dot, suffix)        # the name itself says the file has zero-filled gaps, with or without its map
        out["output"] = write_range(dump, p, va, length, name, what, deadline)
        if totals["bytes_absent"]:
            out["output"]["zero_filled_bytes"] = totals["bytes_absent"]
            out["output"]["zero_fill_note"] = ("%d bytes of the file are zeros that stand for memory the dump does not hold; the map file lists each "
                                               "gap. A tool reading the file must not take them for the process's bytes" % totals["bytes_absent"])
    status, basis = status_of(dump, view, complete_basis, extra)
    finish(dump, out, status, basis)


def view_read(dump, p):
    out = base_answer(dump, p)
    out["va"], out["bytes"] = hx(p["va"]), p["length"]
    module = dump.module_ref(p["va"])
    if module:
        out["module"] = module
    answer_range(dump, p, out, "read", p["va"], p["length"], "read-%x-%d.bin" % (p["va"], p["length"]), "memory at %s" % hx(p["va"]),
                 "every byte of the range is in the dump%s" % (" and was written" if p["write_values"] else ""), p["deadline"])


def pe_sections(dump, module):
    """The PE headers of the image as they lie in the dump, and how much of each section is present. Read from memory, never from a file."""
    base = module["base"]
    head = dump.read_va(base, 0x40)
    if head is None:
        return {"read": False, "why_not": "the first 64 bytes of the image are not in the dump"}
    if head[:2] != b"MZ":
        return {"read": False, "why_not": "the image does not begin with MZ in memory (headers erased or overwritten, or not an image)"}
    lfanew = struct.unpack_from("<I", head, 0x3C)[0]
    if lfanew > 0x10000 or lfanew + 24 > max(module["size"], 0x1000):
        return {"read": False, "why_not": "e_lfanew is %s, outside the image's headers" % hx(lfanew)}
    nt = dump.read_va(base + lfanew, 24)
    if nt is None or nt[:4] != b"PE\x00\x00":
        return {"read": False, "why_not": "no PE signature at e_lfanew (%s)%s" % (hx(lfanew), "" if nt is not None else ": that page is not in the dump")}
    machine, count, stamp, _sym, _nsym, opt_size, characteristics = struct.unpack_from("<HHIIIHH", nt, 4)
    out = {"read": True, "machine": hx(machine), "sections_declared": count, "characteristics": hx(characteristics),
           "timestamp": {"raw": stamp, "utc": iso(stamp), "epoch": "seconds since 1970-01-01 UTC (the in-memory PE header's TimeDateStamp)"},
           "timestamp_matches_module_list": stamp == module["stamp"]}
    opt = dump.read_va(base + lfanew + 24, min(opt_size, 96)) if opt_size >= 64 else None
    if opt is not None and len(opt) >= 64:
        magic = struct.unpack_from("<H", opt, 0)[0]
        out["optional_header_magic"] = hx(magic)
        out["entry_point_rva"] = hx(struct.unpack_from("<I", opt, 16)[0])
        out["size_of_image"] = struct.unpack_from("<I", opt, 56)[0]
        out["size_of_image_matches_module_list"] = out["size_of_image"] == module["size"]
    take = min(count, 96)
    table = dump.read_va(base + lfanew + 24 + opt_size, take * 40) if take else b""
    if table is None:
        out["sections"] = None
        out["sections_why_not"] = "the section table is not in the dump"
        return out
    sections = []
    for i in range(take):
        if not i & 15:
            tick("the section table of the image was read")
        raw_name, vsize, rva, raw_size, raw_at = struct.unpack_from("<8sIIII", table, i * 40)
        flags = struct.unpack_from("<I", table, i * 40 + 36)[0]
        span = vsize or raw_size
        inside = rva < module["size"] and span
        span = min(span, module["size"] - rva) if inside else 0
        have = dump.present(base + rva, span) if span else 0
        sections.append({"name": shown(raw_name.split(b"\x00", 1)[0].decode("latin-1"), "name"), "rva": hx(rva), "virtual_size": vsize,
                         "raw_size": raw_size, "raw_offset": raw_at, "characteristics": hx(flags),
                         "executable": bool(flags & 0x20000000), "writable": bool(flags & 0x80000000),
                         "bytes_in_dump": have, "coverage_percent": round(100.0 * have / span, 2) if span else None})
    out["sections"] = sections
    if count > take:
        out["sections_note"] = "the first %d of %d declared sections" % (take, count)
    return out


def printed_as(name, wanted):
    """Whether view modules prints this module's path or its file name as `wanted` (lower case), so that a withheld name answers no guess.
    What is printed of a string is the string itself or the string with parts replaced by <...> placeholders. So a name whose own text
    differs from `wanted` (when `wanted` has no `<`), or differs from it before its first `<` or after its last `>`, cannot be printed
    as it: that is compared first, and only a name that passes is put through the display rules, which cost far more than a comparison."""
    for text, path in ((name, True), (re.split(r"[\\/]", name)[-1], False)):
        if "Σ" not in text:            # str.lower() reads a capital sigma by what follows it; such a name skips the cheap test
            plain = _escaped(text).lower()
            if "<" not in wanted:
                if plain != wanted:
                    continue
            elif not (plain.startswith(wanted.partition("<")[0]) and plain.endswith(wanted.rpartition(">")[2])):
                continue
        if str(shown_path(text) if path else shown(text, "name")).lower() == wanted:
            return True
    return False


def view_module(dump, p):
    out = base_answer(dump, p)
    if not dump.modules:
        fail("the dump has no module list%s: there is no module to name. A range can still be read by address (view read)"
             % (" stream" if "ModuleList" not in dump.streams else " entries"))
    if p["base"] is not None:
        found = [m for m in dump.modules if m["base"] == p["base"]]
        if not found:
            inside = dump.module_at(p["base"])
            fail("no module of the module list has the base %s%s" % (hx(p["base"]), "" if inside is None else
                                                                   "; that address is inside the module at %s" % hx(inside["base"])))
    else:
        wanted = p["module"].lower()
        found, judged = [], {}
        guess = wanted.startswith("<")      # a placeholder names no module: what is withheld is named by base
        for compared, m in enumerate(dump.modules if not guess else ()):
            checkpoint()
            if late():
                fail("max_seconds (%d) was reached while the module names were compared with the one asked for (%d of %d compared): no module "
                     "was chosen and nothing was written. Name the module by base (view modules gives it), or raise max_seconds"
                     % (p["seconds"], compared, len(dump.modules)), modules=len(dump.modules), compared=compared, out_of_time=True)
            name = dump.module_name(m)
            if not name:
                continue
            hit = judged.get(name)          # a name is judged once, however many modules carry it
            if hit is None:
                hit = judged[name] = printed_as(name, wanted)
            if hit:
                found.append(m)
        if not found:
            fail("no module of the module list has that name (the file name or the whole path, in any case); view modules lists them, and "
                 "base names a module whose name is withheld", modules=len(dump.modules))
        if len(found) > 1:
            fail("%d modules have that name; name one by base" % len(found), bases=[hx(m["base"]) for m in found[:32]])
    module = found[0]
    if module["size"] == 0:
        fail("the module list gives this module a size of 0: there is no image to read", base=hx(module["base"]))
    if module["size"] > MODULE_MAX:
        fail("the module list gives this module %d bytes, above the %d a call materialises; read parts of it with view read" % (module["size"], MODULE_MAX),
             base=hx(module["base"]))
    out["module"] = module_row(dump, module, "loaded")
    out["pe"] = pe_sections(dump, module)
    out["layout"] = ("the file is the image as it lay in memory: offset N of the file is base + N, sections are at their virtual addresses and the "
                     "import table holds resolved addresses. It is not the file that was on disk and will not hash like it; load it as a mapped "
                     "(memory-layout) image")
    answer_range(dump, p, out, "module", module["base"], module["size"], "module-%x-%d.img" % (module["base"], module["size"]),
                 "the image of the module at %s" % hx(module["base"]),
                 "every byte of the module's image (%d bytes at %s) is in the dump%s" % (module["size"], hx(module["base"]), " and was written" if p["write_values"] else ""),
                 p["deadline"])


def needle_forms(p):
    """(label, bytes, compiled pattern or None) for each form of the needle. With ignore_case the bytes are the needle's with ASCII capitals
    lowered (what is looked for in a lowered copy of the memory) and the pattern says exactly which bytes may differ in case: it is only
    ever matched at one position a time, so no text makes it slow."""
    if p["needle_hex"] is not None:
        return [("hex", p["needle_hex"], None)]
    forms, seen = [], set()
    for encoding in p["encodings"]:
        raw = p["needle"].encode("utf-16-le" if encoding == "utf-16le" else "utf-8")
        if len(raw) > MAX_NEEDLE:
            fail("needle is longer than %d bytes as %s; shorten it%s" % (MAX_NEEDLE, encoding, ", or search it as UTF-8 only with encodings: [\"utf-8\"]"
                                                                           if encoding == "utf-16le" and len(p["needle"].encode("utf-8")) <= MAX_NEEDLE else ""))
        if raw in seen:
            continue
        seen.add(raw)
        pattern = None
        if p["ignore_case"]:
            parts = []
            for ch in p["needle"]:
                if ch.isascii() and ch.isalpha():
                    piece = b"[" + ch.lower().encode() + ch.upper().encode() + b"]"
                    parts.append(piece + (b"\\x00" if encoding == "utf-16le" else b""))
                else:
                    parts.append(re.escape(ch.encode("utf-16-le" if encoding == "utf-16le" else "utf-8")))
            pattern = re.compile(b"".join(parts), re.DOTALL)
            raw = raw.lower()
        forms.append((encoding, raw, pattern))
    return forms


def hits_in(buf, lowered, form, limit, room):
    """The first `room` positions below `limit` in `buf` of one form of the needle. A case-folding form is looked for in `lowered` (the
    same bytes with ASCII capitals lowered: a plain search, linear in the memory read) and each place found is then held to the form's
    exact rule on the bytes themselves, which a byte that is not a letter of the needle can fail (the high byte of a UTF-16 unit that
    happens to be a capital's code). Memory can be made of places that pass the plain search and fail the exact rule, millions a piece,
    so the clock is looked at every 16,384 places: returns (the positions, the offset below which every position was found), and that
    offset is `limit` unless the clock ended the look, in which case it is above 0."""
    _label, raw, pattern = form
    found, start, end, turns = [], 0, min(len(buf), limit + len(raw) - 1), 0
    while len(found) < room:
        at = (buf if pattern is None else lowered).find(raw, start, end)
        if at < 0:
            break
        if pattern is None or pattern.match(buf, at):
            found.append(at)
        start = at + 1
        turns += 1
        if not turns & 16383:
            checkpoint()
            if late():
                return found, min(start, limit)
    return found, limit


def view_find(dump, p):
    """The search. The memory is read in pieces of CHUNK bytes; of each piece, with the last bytes of the piece before it in front (the
    carried tail, one byte less than the longest form of the needle), only the hits that START below the frontier are taken: the frontier
    is the address where the next piece's buffer will begin, so a hit that starts at or above it is found by the next piece, whole, at
    the front of its buffer. Every hit is thus found once, in address order whatever the forms' lengths, and at any moment every hit that
    starts below the frontier is in the list and none that starts at or above it is. That is what a stop rests on: the search resumes
    at the frontier (the clock, a read that failed), or at the address of the first hits that were not taken (max_hits, the answer's
    size; the hits that start at one address are given together or not at all), and a call that starts there finds exactly the hits
    this one did not give. Where two ranges are not adjacent the tail is searched by itself and
    nothing is carried."""
    out = base_answer(dump, p)
    forms = needle_forms(p)
    longest = max(len(raw) for _l, raw, _p in forms)
    lo, hi = p["va_start"], p["va_end"] if p["va_end"] is not None else U64 + 1
    hits, read_bytes, stop, resume, over = [], 0, None, None, None
    tail, tail_va, previous_end = b"", None, None

    def take(buf, buf_va, limit):
        """The hits of `buf` that start below buf_va + limit, in address order, added to the list; False when max_hits ended the search.
        The hits that start at one address (the UTF-8 and UTF-16LE forms of a one-character needle, or of text that ends in NUL
        characters) are taken together or not at all, so that a stop never puts the resume address on a hit already given: max_hits
        stops before a group that would pass it, at the group's address, unless the list is still empty, and then the whole group is
        taken past max_hits (said in the answer) and the search stops at the next address that holds a hit."""
        nonlocal stop, resume, over
        # Each form gives at most `room` positions: enough for every hit this piece can add and the whole group after them (a group is
        # one hit of each form, at most two), so the merged list is exact as far as it is read.
        room = max(p["max_hits"] - len(hits), 0) + 3
        lowered = buf.lower() if p["ignore_case"] else None
        found, reached = [], limit
        for form in forms:              # a form the clock cut short lowers `reached`, and the forms after it look no further than that
            positions, reached = hits_in(buf, lowered, form, reached, room)
            found.extend((buf_va + i, form[0], len(form[1])) for i in positions)
        del lowered
        found.sort()
        i = 0
        while i < len(found) and found[i][0] < buf_va + reached:
            j = i + 1
            while j < len(found) and found[j][0] == found[i][0]:
                j += 1
            if len(hits) + (j - i) > p["max_hits"]:
                if hits:
                    stop, resume = "max_hits (%d) was reached" % p["max_hits"], found[i][0]
                    return False
                over = ("the first %d hits start at one address, %s (one per form of the needle): a stop never splits the hits at one "
                        "address, so all of them are in this answer, past max_hits (%d)" % (j - i, hx(found[i][0]), p["max_hits"]))
            hits.extend(found[i:j])
            i = j
        if reached < limit:             # the clock, inside a piece: every hit that starts below buf_va + reached is in the list
            stop, resume = "max_seconds (%d) was reached" % p["seconds"], buf_va + reached
            return False
        return True

    at = max(0, bisect.bisect_right(dump.seg_va, lo) - 1)
    while at < len(dump.seg_va) and stop is None:
        if not at & 1023:
            tick("the memory ranges were walked for the search")
        seg_va, have, seg_off = dump.seg_va[at], dump.seg_have[at], dump.seg_off[at]
        at += 1
        first, last = max(seg_va, lo), min(seg_va + have, hi)
        if first >= last:
            if seg_va >= hi:
                break
            continue
        if previous_end != first:   # not adjacent in the address space: what was carried is searched by itself, and nothing carries over
            if tail and not take(tail, tail_va, len(tail)):
                break
            tail = b""
        pos = first
        while pos < last:
            size = min(CHUNK, last - pos)
            data = dump.read(seg_off + (pos - seg_va), size)
            if len(data) < size:
                dump.problem(dump.seg_src[at - 1], seg_off + (pos - seg_va) + len(data), "a read of %d bytes returned %d: the file changed or cannot be read there" % (size, len(data)))
                stop, resume = "the dump could not be read at file offset %d" % (seg_off + (pos - seg_va) + len(data)), pos - len(tail)
                break
            buf = tail + data if tail else data
            buf_va = pos - len(tail)
            keep = min(longest - 1, len(buf))
            if not take(buf, buf_va, len(buf) - keep):
                break
            del data
            read_bytes += size
            pos += size
            tail, tail_va = (buf[len(buf) - keep:], pos - keep) if keep else (b"", pos)
            del buf
            checkpoint()
            # The clock stops the search only where it leaves a call from the resume address something to do and this call something done:
            # the frontier is above va_start, and memory lies beyond this piece.
            if late() and pos - len(tail) > lo and (pos < last or (at < len(dump.seg_va) and dump.seg_va[at] < hi)):
                stop, resume = "max_seconds (%d) was reached" % p["seconds"], pos - len(tail)
                break
        previous_end = last
    if stop is None and tail:
        take(tail, tail_va, len(tail))
    rows, names = [], {}
    for n, (hit_va, label, length) in enumerate(hits):
        if not n & 63:
            checkpoint()
        _va, _n, file_offset, _why = next(dump.pieces(hit_va, 1))
        row = {"va": hx(hit_va), "file_offset": file_offset, "form": label, "bytes": length}
        module = dump.module_at(hit_va)
        if module is not None:
            if module["index"] not in names:
                # A module's name is judged once, which costs. A search the clock ended still names the modules of the hits it has,
                # for DESCRIBE_GRACE seconds at most; the hits from there on are left to the next call.
                if rows and time.monotonic() > p["deadline"] + DESCRIBE_GRACE:
                    stop, resume = "max_seconds (%d) and %d more seconds for naming the hits' modules were reached" % (p["seconds"], DESCRIBE_GRACE), hit_va
                    break
                names[module["index"]] = dump.module_ref(hit_va)["name"]
            row["module"] = {"name": names[module["index"]], "base": hx(module["base"]), "rva": hx(hit_va - module["base"])}
        region = dump.region(hit_va)
        if region >= 0:
            row["protect"], row["type"] = protect_name(dump.reg_protect[region]), MEMTYPE.get(dump.reg_type[region])
        rows.append(row)
    shown_rows, facts = paged(len(rows), 0, len(rows) or 1, lambda i: rows[i])
    if facts["truncated"]:              # the page's byte ceiling: the rest is found again from the first hit that is not shown
        # The cut never falls inside the hits that start at one address: it moves back to the first of them, or, when that would leave
        # the answer empty, forward past the last of them.
        cut = facts["returned"]
        while cut > 0 and hits[cut - 1][0] == hits[cut][0]:
            cut -= 1
        if cut == 0:
            cut = facts["returned"]
            while cut < len(rows) and hits[cut][0] == hits[0][0]:
                cut += 1
            over = ("the first %d hits start at one address, %s (one per form of the needle): a stop never splits the hits at one "
                    "address, so all of them are in this answer, past the page's %d bytes of JSON" % (cut, hx(hits[0][0]), INLINE_BYTES))
            shown_rows = rows[:cut]
        else:
            shown_rows = shown_rows[:cut]
        if cut < len(rows):
            resume = hits[cut][0]
            stop = "the answer reached %d bytes of JSON" % INLINE_BYTES
    seconds = time.monotonic() - p["started"]
    # What was searched is the memory the dump holds below the address the search ended at: every hit that starts there is in the answer.
    reached = min(resume, hi) if resume is not None else hi
    searched = dump.present(lo, reached - lo) if reached > lo else 0
    out["hits"] = shown_rows
    out["page"] = {"total": len(shown_rows) if stop is None else None, "returned": len(shown_rows), "next_offset": None, "truncated": stop is not None,
                   "resume_va": hx(resume) if resume is not None else None}
    if over is not None:
        out["page"]["same_address_note"] = over
    if stop is not None:
        out["page"]["total_note"] = "the search stopped early, so the total is not known: at least %d" % len(shown_rows)
        out["page"]["how_to_continue"] = ("call again with va_start %s: every hit that starts below that address is in this answer and none that "
                                          "starts at or above it is, so the calls together give each hit once" % hx(resume))
        if stop.startswith("the dump could not be read"):
            out["page"]["how_to_continue"] += ("; while the file cannot be read there that call stops at the same place, and a va_start above "
                                               "the range that holds the unreadable bytes searches what lies beyond them")
    out["needle"] = {"forms": [{"form": label, "bytes": len(raw)} for label, raw, _p in forms], "ignore_case": p["ignore_case"],
                     "ignore_case_note": "ASCII letters only; any other character is matched exactly" if p["ignore_case"] else None}
    out["searched"] = {"va_start": hx(lo), "va_end": hx(hi) if hi <= U64 else None, "bytes": searched, "bytes_read": read_bytes,
                       "mapped_bytes_in_dump": dump.mapped_bytes,
                       "seconds": round(seconds, 3), "megabytes_per_second": round(read_bytes / 1048576 / seconds, 1) if seconds > 0.0005 else None,
                       "max_seconds": p["seconds"], "piece_bytes": CHUNK,
                       "note": "bytes is the memory the dump holds from va_start up to the address the search ended at (resume_va, or va_end): "
                               "every hit that starts in it is in this answer. bytes_read is what was read from the file, which is more when "
                               "the search stopped inside a piece; seconds is the whole call, the reading of the dump's tables included"}
    out["note"] = ("a hit is the needle's bytes at va in the process and at file_offset in the dump file; a needle that lies across two ranges "
                   "adjacent in the address space is found, and one that would lie across a gap is not. Only memory the dump holds was searched: "
                   "no hit is not absence from the process unless the dump is a full-memory one, and even then pages its writer could not read "
                   "are missing. A string in memory is an observation that the bytes were there, not that they were used. The bytes around a hit "
                   "are read with view read")
    extra = []
    if stop is not None:
        extra.append("the search stopped early: %s; memory from %s on was not searched (page.resume_va)" % (stop, hx(resume)))
    whole = lo == 0 and hi > U64
    status, basis = status_of(dump, "find", "every byte of memory the dump holds%s (%d bytes) was searched for the needle, and every hit is in the answer"
                              % ("" if whole else " between va_start and va_end", searched), extra)
    finish(dump, out, status, basis)


def main():
    args = read_args()
    started = time.monotonic()      # the clock starts when the arguments are in: waiting for them is not the tool's work
    p = parse_args(args)
    p["started"], p["deadline"] = started, started + p["seconds"]
    CLOCK["deadline"], CLOCK["seconds"] = p["deadline"], p["seconds"]
    dump = load(p["path"])
    {"summary": view_summary, "modules": view_modules, "memory": view_memory, "threads": view_threads, "va": view_va, "read": view_read,
     "module": view_module, "find": view_find}[p["view"]](dump, p)


def run_guarded():
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, _on_signal)
    try:
        try:
            main()
        except (SystemExit, Terminated):
            raise
        except OutOfTime as exc:
            fail("max_seconds (%d) was reached while %s: the call ended without an answer, nothing was kept and nothing in this document is "
                 "a finding. Raise max_seconds (at most %d), or ask for less in one call" % (CLOCK["seconds"], exc.doing, MAX_SECONDS),
                 max_seconds=CLOCK["seconds"], out_of_time=True)
        except MemoryError:
            fail("the tool ran out of memory; nothing in this document is a finding")
        except OSError as exc:      # the dump or an output file could not be read or written (a full disk, a file that went away)
            fail("a file could not be read or written (%s); nothing in this document is a finding, and a file that was being written was removed"
                 % errno.errorcode.get(exc.errno, "errno %s" % exc.errno))
        except Exception as exc:  # never an empty or clean answer for a failure (the message of the error can quote the dump, so only its kind and line are said)
            line, tb = None, exc.__traceback__
            while tb is not None:
                line, tb = tb.tb_lineno, tb.tb_next
            fail("unexpected failure: %s" % type(exc).__name__, line=line)
    except Terminated as stopped:   # a stop anywhere in the call, the handling of a failure included
        discard_files()
        emit({"error": "stopped by signal %d before the answer was made" % stopped.signum, "status": "failed", "interrupted": True,
              "status_basis": "the tool was stopped by signal %d; nothing it had read is an answer, and a file it was writing was removed "
                              "(the image and its map are kept only together, once both are whole)" % stopped.signum,
              "signal": stopped.signum, "parser": PARSER})
        raise SystemExit(128 + stopped.signum)


if __name__ == "__main__":
    exit_code = 0
    try:
        run_guarded()
    except SystemExit as stop:
        exit_code = _code(stop)
    _leave(exit_code)
