#!/usr/bin/env python3
"""Extract the members of a zip, tar (plain, gzip, bzip2, xz, zstd), 7z or single-file compressed archive into a new directory, bounded.

An archive is hostile input. This tool writes member CONTENT only: it never recreates a link, a device node, a FIFO or
a directory mode, never writes outside its output directory, never executes anything and never decompresses without a
bound. What it does, exactly:

  * Format is read from the bytes (zip, tar, gzip, bzip2, xz, zstd, 7z), never from the file name. A compressed stream
    is looked into: a tar inside it is a tar, anything else is ONE member (a gzip's own file name, else the archive's
    name without its suffix). RAR, CAB, ISO and the rest are named and refused (unsupported), never guessed. zstd is read
    through Python's compression.zstd (3.14) or the zstd program of the base image, in that order (the zstandard module is not used: its streaming reader
    ends a truncated frame without an error);
    if none is there a zstd archive is reported unsupported with that reason.
  * Every member is one row of members.jsonl, in archive order, numbered `n` from 0 (the same number the archive-members
    recipe gives it), with its original name kept exactly (`name_b64`, the bytes) beside a display form, its type, declared
    and written sizes, the times as the archive stores them with the zone said, the flags it earned, and a status:
    extracted, partial, directory, not_created (a link, device or FIFO: recorded, with its target, and never created),
    encrypted (counted, not extracted, not skipped silently), unsupported (a compression method this build cannot read),
    skipped (a budget rule for that member: depth, size, ratio). Two members with one name are two rows, two files.
  * Files are created exclusively (O_EXCL, O_NOFOLLOW, through directory descriptors, so no path component can be a link
    and nothing lands outside the output directory), mode 0600 in a 0700 directory, under an ASCII-safe rendering of the
    name (every byte outside A-Z a-z 0-9 . _ - + @ = , ( ) becomes %XX; `..` becomes %2E%2E; an absolute or drive-lettered
    name loses its root). The row's `path` is where the bytes are; `name_b64` is what the archive called them. A member
    whose name is shaped like a token (or carries user-info) is written under _withheld/withheld-NNNNNN<ext> and its name
    appears nowhere in the answer; the real name goes to withheld-names.jsonl (0600). There is no name filter: a filter
    over withheld text would be an oracle for it. Members are chosen by number (`from_index`).
  * What is written goes to <path>.partial and takes its real name only when the member is whole, its size is what the
    archive declared and its CRC (where the archive has one) matches. A member that stops, fails or mismatches stays as
    .partial and its row says why. A digest or CRC of a member shorter than 128 bytes is not written (a short value can
    be reversed from its digest); the row says so.
  * Budgets: max_total_bytes, max_member_bytes, max_members, max_ratio (expanded over packed: per member for a zip, whose directory
    gives each member's packed size; over the whole stream for a gzip, bzip2, xz or zstd file or tar, and for a 7z, whose output is
    held to max_ratio times the archive's size; a plain tar stores its members, so nothing in it expands), max_depth (path
    components) and max_seconds. A member-level budget
    skips or cuts that member and goes on; a global one stops the run, names it (`stopped_by`) and gives `next_index`:
    run again with from_index set to it and resume true to go on in the same out_dir (a second manifest, members.2.jsonl,
    is written beside the first; nothing is replaced).
  * A nested archive is NOT opened: the row says `looks_like` from the member's first bytes, and the caller extracts it in
    a call of its own (with its own budgets). One call extracts one level.
  * The 7z program (7z, 7zz or 7za) lists and extracts a 7z archive to a pipe; its bytes are split by the sizes in its own
    listing and checked against the listing's CRC, so the program never writes a file and path rules never depend on it.
    A listing's order is the stream's order; a CRC that does not match, or a stream that is longer or shorter than the
    listing, is said, member by member.

Exit code 0 means the engine ran and the answer is whole about what it did (a partial extraction is exit 0 with status
partial and the reasons); 1 is an archive that cannot be read at all, a refused argument or a place that cannot be
written. Extracted content is evidence content and can hold credentials: the output directory is private, the answer
says so, and the skill says to run the job with secret_output: true.
"""
import base64
import binascii
import bz2
import datetime
import errno
import hashlib
import json
import lzma
import os
import re
import select
import shutil
import signal
import stat
import struct
import subprocess
import sys
import tarfile
import time
import zipfile
import zlib
from pathlib import Path

TOOL = {"name": "archive_extract", "version": 2}
CHUNK = 1 << 20
SHORT_MEMBER = 128                       # a member shorter than this has no digest and no CRC written
MAX_TOTAL_DEFAULT = 8 * 1024 ** 3
MAX_MEMBER_DEFAULT = 4 * 1024 ** 3
BYTES_CEILING = 1024 ** 4
MAX_MEMBERS_DEFAULT = 200_000
MAX_MEMBERS_CEILING = 5_000_000
MAX_RATIO_DEFAULT = 1000
MAX_RATIO_CEILING = 1_000_000
RATIO_SLACK = 1 << 20                    # a member may expand this much past its ratio before the ratio counts (a tiny file)
MAX_DEPTH_DEFAULT = 64
MAX_DEPTH_CEILING = 1024
MAX_SECONDS_DEFAULT = 1500
MAX_SECONDS_CEILING = 1700               # inside the manifest's 1800: a longer budget would be killed, not reported
LIMIT_DEFAULT = 50
LIMIT_CEILING = 1000
LINK_TARGET_MAX = 4096
HASH_ARCHIVE_MAX = 4 * 1024 ** 3         # the archive's own sha256 is taken up to this size
META_MAX = 1024 * 1024                   # a tar long-name or pax header that declares more is not read (tarfile reads it whole)
ZIP_DIRECTORY_MAX = 64 * 1024 * 1024      # zipfile holds every entry of the directory in memory (about 500 bytes each): 64 MiB of it is some 1.4 million entries
ZIP_DIRECTORY_FACTOR = 4                  # and a directory declaring more than this many times max_members is not loaded to extract that few
SEVEN_Z_MAGIC = b"7z\xbc\xaf\x27\x1c"
SEVEN_Z_NAMES = ("7z", "7zz", "7za", "7zr")
LISTING_LINE_MAX = 16 * 1024 * 1024
TAIL_KEEP = 4 * 1024 * 1024               # decompressed bytes kept for salvaging a member cut short by a break
SEGMENT = 200                            # an on-disk name component longer than this is shortened and hashed; name_b64 keeps the whole
FIRST_FAILURES = 20

# BEGIN SHARED WITHHOLDING
# The same text is in every tool that withholds identifier-shaped strings (the network, base, virtualization and
# reverse-engineering packs), so that they withhold the same strings; the tests that hold the copies equal are
# tests/pack-network-withholding.test.ts, tests/pack-base-shared.test.ts, tests/pack-virtualization-shared.test.ts and
# tests/pack-re-process.test.ts. An identifier-shaped string is withheld wherever the tool would print one: a name, a
# path component, a URL, a message that quotes either.
COUNTS = {"names": 0, "urls": 0, "text": 0}
# A run of name characters long enough to be a token. `=` is only a padding at the end (so a key= prefix stays);
# `/` joins pieces of a base64 token and is handled apart, below.
_RUN = re.compile(r"[A-Za-z0-9_+%-]{20,}={0,2}|[A-Za-z0-9_+%-]{14,}={2}")
_SLASHED = re.compile(r"[A-Za-z0-9_+/%-]{30,}={0,2}")
_HEX = re.compile(r"[0-9a-fA-F]{32,}")
_PREFIXED = re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}"
                       r"|xox[abeprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9_-]{20,}"
                       r"|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*"
                       r"|(?i:basic|bearer)\s+[A-Za-z0-9+/=._~-]{8,}")
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
# A text longer than this is withheld whole, by its length, and not examined: the examination is linear, but a text of
# millions of characters is not one a name or a URL is, and the answer says how long it was.
TEXT_LIMIT = 2097152


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
    spans = [m.span() for m in _PREFIXED.finditer(text)]
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


def scrub(text, kind="text"):
    """The text with every token-shaped run and every user-info withheld."""
    if len(text) > TEXT_LIMIT:
        return _withheld("over-long text", len(text), kind)
    text = _USERINFO.sub(lambda m: _withheld("userinfo", len(m.group()), kind), text)
    text = _BARE_USERINFO.sub(lambda m: _withheld("userinfo", len(m.group()), kind), text)
    out, last = [], 0
    for start, end in token_spans(text):
        out.append(text[last:start])
        out.append(_withheld("token-shaped text", end - start, kind))
        last = end
    out.append(text[last:])
    return "".join(out)


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

# BEGIN SHARED PROCESS
# The same text is in pcap_extract, zeek_run, suricata_run, the network-capture recipe and computer-forensics-base's
# archive_extract; tests/pack-network-withholding.test.ts holds the four network copies equal and tests/pack-base-shared.test.ts
# holds archive_extract's to them. A program an engine tool runs is started in THIS tool's process group, never in a session of
# its own: the harness ends a tool that runs too long, or is aborted, by killing the tool's group (process.kill(-pid,
# SIGKILL)), and an engine in a group of its own goes on writing into the output directory after the tool is gone. On
# Linux the kernel is also asked to kill it if the tool dies. A deadline kills the program and what it started by
# walking the process tree, and SIGTERM, SIGINT and SIGHUP do the same and then give the tool a last word. Only what is
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


def preflight(argv, seconds):
    """Run a short program, bounded; (exit code or None, stdout bytes, stderr bytes, timed out)."""
    try:
        proc = spawn(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError as exc:
        return None, b"", describe(exc).encode("utf-8", "replace"), False
    ACTIVE.append(proc)
    try:
        out, err = proc.communicate(timeout=max(1.0, seconds))
        return proc.returncode, out, err, False
    except subprocess.TimeoutExpired:
        kill_tree(proc)
        out, err = proc.communicate()
        return None, out, err, True
    finally:
        ACTIVE.remove(proc)


def run_to_files(argv, stdout_path, stderr_path, seconds, cwd=None):
    """One program with its output in files, killed with what it started at `seconds`. (exit code, timed out)."""
    with open(stdout_path, "wb") as stdout, open(stderr_path, "wb") as stderr:
        proc = spawn(argv, stdout=stdout, stderr=stderr, cwd=cwd)
        ACTIVE.append(proc)
        try:
            return proc.wait(timeout=max(0.1, seconds)), False
        except subprocess.TimeoutExpired:
            kill_tree(proc)
            proc.wait()
            return None, True
        finally:
            ACTIVE.remove(proc)


def install_signal_handlers():
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, _on_signal)
# END SHARED PROCESS


def describe(exc):
    code = errno.errorcode.get(exc.errno, "") if getattr(exc, "errno", None) else ""
    return scrub("%s%s: %s" % (type(exc).__name__, " " + code if code else "", getattr(exc, "strerror", None) or str(exc)))


def in_job():
    return bool(os.environ.get("JOB_ID") and os.environ.get("OUT"))


def say(obj, code=0):
    print(json.dumps(obj, ensure_ascii=True))
    sys.stdout.flush()
    raise SystemExit(code)


def fail(message, **extra):
    say({"ok": False, "error": scrub(message), "tool": TOOL, **extra}, 1)


def whole(args, key, default, low, high):
    value = args.get(key)
    if value is None:
        return default
    if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
        fail("%s is a whole number from %d to %d" % (key, low, high), **{key: value})
    return value


def b64(raw):
    return base64.b64encode(raw).decode("ascii")


def iso_utc(epoch):
    """ISO-8601 UTC with the fraction kept, or None for a value no date can hold."""
    try:
        whole_s = int(epoch // 1)
        frac = epoch - whole_s
        stamp = datetime.datetime.fromtimestamp(whole_s, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    except (OverflowError, OSError, ValueError, TypeError):
        return None
    if frac:
        stamp += ("%.6f" % frac)[1:].rstrip("0")
    return stamp + "Z"


# ---- names ------------------------------------------------------------------------------------------------------------

SAFE_BYTES = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-+@=,()")


def name_analysis(raw, windows):
    """(components, flags) of a member name. A component is bytes; `.` and empty ones are dropped, `..` is kept (and flagged:
    it is never followed, only rendered). `windows` names where a backslash is a separator (zip and 7z come from
    archivers that write them); in a tar it is an ordinary byte."""
    flags = []
    try:
        raw.decode("utf-8")
    except UnicodeDecodeError:
        flags.append("name-not-utf8")
    if b"\x00" in raw:
        flags.append("nul-in-name")
    plain = raw.replace(b"\x00", b"/")
    if windows:
        if b"\\" in plain:
            flags.append("backslash-separator")
        plain = plain.replace(b"\\", b"/")
    elif b"\\" in plain:
        flags.append("backslash-in-name")
    if plain.startswith(b"/"):
        flags.append("absolute-path")
    if re.match(rb"^[A-Za-z]:", plain):
        flags.append("drive-letter")
    parts = plain.split(b"/")
    if b".." in parts:
        flags.append("dotdot")
    if "absolute-path" in flags or "drive-letter" in flags or "dotdot" in flags:
        flags.append("escapes-root")
    return [p for p in parts if p not in (b"", b".")], flags


def render_component(raw):
    out = "".join(chr(b) if b in SAFE_BYTES else "%%%02X" % b for b in raw)
    if raw in (b"..",):
        out = "%2E%2E"
    if len(out) > SEGMENT:
        out = out[:SEGMENT // 2] + "~" + hashlib.sha1(raw).hexdigest()[:12]
    return out


def extension_of(raw):
    m = re.search(rb"(\.[A-Za-z]{1,5})$", raw)
    return m.group(1).decode("ascii") if m else ""


def looks_like(head):
    """What the first bytes of a member say it may be: a candidate to extract in a call of its own, nothing more."""
    if head.startswith((b"PK\x03\x04", b"PK\x05\x06")):
        return "zip"
    if head.startswith(SEVEN_Z_MAGIC):
        return "7z"
    if head.startswith(b"\x1f\x8b\x08"):
        return "gzip"
    if head.startswith(b"BZh") and len(head) > 3 and head[3:4].isdigit():
        return "bzip2"
    if head.startswith(b"\xfd7zXZ\x00"):
        return "xz"
    if head.startswith(b"\x28\xb5\x2f\xfd"):
        return "zstd"
    if head[257:262] == b"ustar":
        return "tar"
    if head.startswith(b"Rar!\x1a\x07"):
        return "rar"
    if head.startswith(b"MSCF"):
        return "cab"
    return None


# ---- decompression --------------------------------------------------------------------------------------------------

class Budget(Exception):
    """A global budget ended the run; `reason` names it."""

    def __init__(self, reason, text=""):
        super().__init__(text or reason)
        self.reason = reason


class Ratio(Exception):
    pass


def zstd_module():
    """(kind, object) for the first zstd reader this Python has, else (None, why)."""
    try:
        from compression import zstd as zmod          # Python 3.14
        return "compression.zstd", zmod
    except ImportError:
        pass
    if shutil.which("zstd"):
        return "zstd program", None
    return None, "no zstd decompressor: this Python has no compression.zstd (3.14) and there is no zstd program on PATH"


class Decomp:
    """A decompressed byte stream over a compressed file: gzip, bzip2, xz or zstd, one or several streams back to back.

    read(n) returns at most n bytes and b"" only at the end of the last stream. The decompressors are called with a maximum
    output of CHUNK, so a bomb never costs more than one piece of memory, and the ratio of what came out to what went in is
    checked after every piece."""

    MARKERS = {"gzip": b"\x1f\x8b", "bzip2": b"BZh", "xz": b"\xfd7zXZ\x00"}

    def __init__(self, path, kind, max_ratio):
        self.kind, self.max_ratio = kind, max_ratio
        self.fh = open(path, "rb")
        self.consumed = 0          # compressed bytes read from the file
        self.produced = 0          # decompressed bytes handed out
        self.buf = b""
        self.eof = False
        self.streams = 0
        self.trailing = 0          # bytes after the last stream that are not another stream
        self.proc = None
        self.reader = None
        self.delivered = 0         # decompressed bytes handed to the reader so far
        self.tail = bytearray()    # the last TAIL_KEEP of them, so that a member cut short by a break can be given back what was decompressed
        self.pending = None        # an error from the decompressor, raised once the bytes before it have been read
        self.gen = self._zstd_pieces() if kind == "zstd" else self._pieces()

    def close(self):
        if self.reader is not None:
            try:
                self.reader.close()
            except Exception:   # noqa: BLE001
                pass
        try:
            self.fh.close()
        except OSError:
            pass
        if self.proc is not None:
            kill_tree(self.proc)
            if self.proc in ACTIVE:
                ACTIVE.remove(self.proc)

    def _check(self):
        if self.produced > self.max_ratio * max(self.consumed, 1) + RATIO_SLACK:
            raise Ratio("the stream expanded to %d bytes from %d compressed (more than %d times)" % (self.produced, self.consumed, self.max_ratio))

    def _new(self):
        if self.kind == "gzip":
            return zlib.decompressobj(31)
        if self.kind == "bzip2":
            return bz2.BZ2Decompressor()
        return lzma.LZMADecompressor()

    def _step(self, dec, data):
        """(output, input left over, finished) after one call bounded to CHUNK bytes of output."""
        if self.kind == "gzip":
            out = dec.decompress(data, CHUNK)
            return out, (dec.unused_data if dec.eof else dec.unconsumed_tail), dec.eof
        out = dec.decompress(data, max_length=CHUNK)
        return out, (dec.unused_data if dec.eof else b""), dec.eof

    def _pieces(self):
        marker = self.MARKERS[self.kind]
        dec = self._new()
        self.streams = 1
        data = b""
        while True:
            if not data:
                data = self.fh.read(CHUNK)
                self.consumed += len(data)
                if not data:
                    if not getattr(dec, "eof", False):
                        raise EOFError("the %s stream ends before its end marker (a truncated archive)" % self.kind)
                    return
            while True:
                out, data, finished = self._step(dec, data)
                if out:
                    self.produced += len(out)
                    self._check()
                    yield out
                if finished:
                    break
                if self.kind == "gzip":
                    if not data and len(out) < CHUNK:
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
                rest = self.fh.read(CHUNK)
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
            while True:
                more = self.fh.read(CHUNK)
                if not more:
                    return
                self.trailing += len(more)
                self.consumed += len(more)

    def _zstd_pieces(self):
        which, mod = zstd_module()
        self.streams = 1
        if which == "zstd program":
            self.proc = spawn(["zstd", "-dc", "-q"], stdin=self.fh, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            ACTIVE.append(self.proc)
            fd = self.proc.stdout.fileno()
            while True:
                piece = os.read(fd, CHUNK)
                if not piece:
                    break
                self.produced += len(piece)
                self.consumed = max(self.consumed, self.fh.tell())
                self._check()
                yield piece
            rc = self.proc.wait()
            if rc != 0:
                raise EOFError("the zstd program exited %d: the compressed stream is damaged or truncated" % rc)
            return
        if which == "compression.zstd":
            self.reader = mod.ZstdFile(self.fh)
        else:
            raise Unsupported(mod)
        while True:
            piece = self.reader.read(CHUNK)
            if not piece:
                return
            self.produced += len(piece)
            self.consumed = max(self.consumed, self.fh.tell())
            self._check()
            yield piece

    def read(self, n=-1):
        if n is None or n < 0:
            n = 1 << 62
        while len(self.buf) < n and not self.eof and self.pending is None:
            try:
                piece = next(self.gen)
            except StopIteration:
                self.eof = True
                break
            except (Ratio, Budget, EOFError, OSError, zlib.error, lzma.LZMAError, ValueError, Unsupported) as exc:
                self.pending = exc               # the bytes decompressed before the break are read first, then this is raised
                break
            self.buf += piece
        if not self.buf and self.pending is not None:
            raise self.pending
        out, self.buf = self.buf[:n], self.buf[n:]
        self.delivered += len(out)
        self.tail += out
        if len(self.tail) > TAIL_KEEP:
            del self.tail[:-TAIL_KEEP]
        return out

    def unread(self, data):
        """Give back bytes just read (the format sniff reads the first block and puts it back)."""
        self.buf = data + self.buf
        self.delivered -= len(data)
        del self.tail[len(self.tail) - len(data):]

    def slice(self, start, end):
        """The decompressed bytes at stream offsets [start, end) that are still in the tail."""
        base = self.delivered - len(self.tail)
        lo, hi = max(start, base), min(end, self.delivered)
        return bytes(self.tail[lo - base:hi - base]) if hi > lo else b""


class RawSlice:
    """`size` bytes of a file from `offset`: a plain tar member's data, read without tarfile, so that an archive which ends early gives what is there."""

    def __init__(self, path, offset, size):
        self.fh = open(path, "rb")
        self.fh.seek(offset)
        self.remaining = size

    def read(self, n=-1):
        if self.remaining <= 0:
            return b""
        data = self.fh.read(min(n if n and n > 0 else CHUNK, self.remaining))
        self.remaining -= len(data)
        return data

    def close(self):
        self.fh.close()


class TarMember:
    """A member of a tar read through a decompressor: tarfile's reader, plus the bytes the decompressor delivered when tarfile's read fails."""

    def __init__(self, tf, t, dec):
        self.f, self.t, self.dec = tf.extractfile(t), t, dec

    def read(self, n=-1):
        return self.f.read(n)

    def salvage(self, written):
        start = self.t.offset_data + written
        return self.dec.slice(start, self.t.offset_data + self.t.size)

    def close(self):
        self.f.close()


class Unsupported(Exception):
    pass


# ---- the output directory ---------------------------------------------------------------------------------------------

class Tree:
    """Files made under one directory through descriptors, so that no component can be a link and nothing lands outside.

    Directories are made 0700 and opened O_NOFOLLOW one component at a time; a file is created O_EXCL|O_NOFOLLOW as
    <name>.partial in its directory, and takes its name with link-then-unlink, which never replaces what is there."""

    def __init__(self, root):
        self.root = root
        self.root_fd = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))

    def close(self):
        try:
            os.close(self.root_fd)
        except OSError:
            pass

    def _dir(self, parts):
        fd = os.dup(self.root_fd)
        try:
            for part in parts:
                try:
                    os.mkdir(part, 0o700, dir_fd=fd)
                except FileExistsError:
                    pass
                nxt = os.open(part, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0), dir_fd=fd)
                os.close(fd)
                fd = nxt
            return fd
        except BaseException:
            os.close(fd)
            raise

    def create(self, parts, leaf):
        """(dir fd, partial name, file object) for a new <leaf>.partial in the directory `parts`."""
        dfd = self._dir(parts)
        k = 0
        while True:
            name = leaf + ".partial" + ("" if k == 0 else ".%d" % k)
            try:
                fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=dfd)
            except FileExistsError:
                k += 1
                continue
            except BaseException:
                os.close(dfd)
                raise
            return dfd, name, os.fdopen(fd, "wb")

    def publish(self, dfd, partial, leaf):
        """The final name of a finished member: `leaf`, or leaf~dup2, leaf~dup3 ... when that name is taken. Returns it."""
        k = 1
        while True:
            name = leaf if k == 1 else "%s~dup%d" % (leaf, k)
            try:
                os.link(partial, name, src_dir_fd=dfd, dst_dir_fd=dfd)
                os.unlink(partial, dir_fd=dfd)
                return name
            except FileExistsError:
                k += 1
            except OSError as exc:
                if exc.errno in (errno.EPERM, errno.ENOTSUP, errno.EOPNOTSUPP, errno.EXDEV, errno.EMLINK):   # no hard links: a look, then a rename
                    try:
                        os.stat(name, dir_fd=dfd, follow_symlinks=False)
                        k += 1
                        continue
                    except FileNotFoundError:
                        os.rename(partial, name, src_dir_fd=dfd, dst_dir_fd=dfd)
                        return name
                raise


def resolve_output(out):
    """Where `out` really lands, as a path under the run directory; a place outside it, the run directory itself or
    anything under inputs/ is refused, and in a job so is anything outside $OUT, the one place a job writes."""
    root = Path.cwd().resolve()
    dest = (root / out).resolve() if not Path(out).is_absolute() else Path(out).resolve()
    if dest == root or root not in dest.parents:
        fail("out_dir must stay inside the run directory", out_dir=str(out))
    inputs = root / "inputs"
    if dest == inputs or inputs in dest.parents:
        fail("out_dir cannot be under inputs/", out_dir=str(out))
    if in_job():
        job_out = Path(os.environ["OUT"]).resolve()
        if dest != job_out and job_out not in dest.parents:
            fail("in a job out_dir is a directory under $OUT, the one place a job writes", out_dir=str(out), out=str(job_out),
                 hint="give {OUT}/<name>, or work/extracted/<your id>/<name>, which the harness maps there")
    return dest


def first_free(directory, stem, ext):
    """stem+ext, or stem.2+ext, stem.3+ext ... : a name no earlier run of this out_dir has."""
    k = 1
    while True:
        name = "%s%s" % (stem, ext) if k == 1 else "%s.%d%s" % (stem, k, ext)
        if not os.path.lexists(os.path.join(directory, name)):
            return name
        k += 1


def private_file(path, mode="w"):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    return os.fdopen(fd, mode, **({"encoding": "utf-8"} if "b" not in mode else {}))


def write_json_atomic(path, obj):
    tmp = "%s.tmp.%d" % (path, os.getpid())
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2, ensure_ascii=True)
        fh.write("\n")
    os.replace(tmp, path)


# ---- the engine -------------------------------------------------------------------------------------------------------

class Engine:
    def __init__(self, args, out_root, run_no, archive_info):
        self.a = args
        self.out_root = out_root
        self.tree = Tree(str(out_root / "extracted"))
        suffix = "" if run_no == 1 else ".%d" % run_no
        self.members_path = out_root / ("members%s.jsonl" % suffix)
        self.receipt_path = out_root / ("receipt%s.json" % suffix)
        self.withheld_path = out_root / ("withheld-names%s.jsonl" % suffix)
        self.members_fh = private_file(str(self.members_path))
        self.withheld_fh = None
        self.archive = archive_info
        self.started = time.monotonic()
        self.deadline = self.started + args["max_seconds"]
        self.counts = {}
        self.types = {}
        self.flag_counts = {}
        self.total_written = 0
        self.rows = 0
        self.page = []
        self.failures = []
        self.nested = []
        self.name_seen = set()
        self.duplicate_names = 0
        self.members_withheld = 0
        self.stopped_by = None
        self.stop_text = None
        self.next_index = args["from_index"]
        self.current = None
        self.notes = []
        self.extra = {}
        self.status = "running"          # running | interrupted | failed while the run is not over; None once it is

    # -- bookkeeping --
    def count(self, status):
        self.counts[status] = self.counts.get(status, 0) + 1

    def write_receipt(self):
        write_json_atomic(str(self.receipt_path), self.receipt())

    def receipt(self):
        bad = {k: v for k, v in self.counts.items() if k not in ("extracted", "directory", "not_created")}
        status = self.status or ("partial" if bad or self.stopped_by else "complete")
        out = {
            "tool": TOOL,
            "status": status,
            "status_basis": {"complete": "every member the archive lists was read to its end and written, or is a directory",
                             "partial": "a member did not come out whole or a budget stopped the run (see counts, stopped_by and first_failures)",
                             "failed": "the archive could not be read",
                             "interrupted": "the run was ended by a signal before it finished", "running": "the run has not finished"}.get(status, status),
            "archive": self.archive,
            "out_dir": str(self.out_root.relative_to(Path.cwd().resolve())) if Path.cwd().resolve() in self.out_root.parents else str(self.out_root),
            "extracted_dir": "extracted",
            "members_file": self.members_path.name,
            "members_file_format": "JSON Lines, one object per member in archive order: n, type, name, name_b64, path, status, reason, sizes, sha256, times, flags",
            "withheld_names_file": self.withheld_path.name if self.withheld_fh is not None else None,
            "members_seen": self.rows,
            "counts": dict(sorted(self.counts.items())),
            "types": dict(sorted(self.types.items())),
            "flags": dict(sorted(self.flag_counts.items())),
            "bytes_written": self.total_written,
            "from_index": self.a["from_index"],
            "next_index": self.next_index,
            "stopped_by": self.stopped_by,
            "stop": self.stop_text,
            "duplicate_names": self.duplicate_names,
            "members_withheld": self.members_withheld,
            "nested_archives": self.nested[:100],
            "nested_archives_total": len(self.nested),
            "budgets": {k: self.a[k] for k in ("max_total_bytes", "max_member_bytes", "max_members", "max_ratio", "max_depth", "max_seconds")},
            "seconds": round(time.monotonic() - self.started, 2),
            "first_failures": self.failures,
            "notes": self.notes,
            "sensitive_output": {
                "extracted_content": True,
                "out_dir_mode": "0700, files 0600",
                "advice": "extracted members are evidence content and can hold credentials, keys and tokens: when the member list shows credential stores, keys, "
                          "tokens or browser profiles, run this as a job with secret_output: true, and record where a secret sits, its kind and length, never its value",
            },
            "not_measured": "the content of a member is not examined; a nested archive is named, not opened; a member's CRC or size agreeing with the "
                            "archive's record shows the bytes are what the archive held, not that the archive is authentic or complete",
        }
        out.update(self.extra)
        return out

    def record(self, row):
        self.rows += 1
        self.count(row["status"])
        self.types[row["type"]] = self.types.get(row["type"], 0) + 1
        for f in row.get("flags", []):
            self.flag_counts[f] = self.flag_counts.get(f, 0) + 1
        self.members_fh.write(json.dumps(row, ensure_ascii=True) + "\n")
        self.members_fh.flush()
        if len(self.page) < self.a["limit"]:
            self.page.append(row)
        if row["status"] not in ("extracted", "directory", "not_created") and len(self.failures) < FIRST_FAILURES:
            self.failures.append({k: row.get(k) for k in ("n", "name", "status", "reason")})

    def withhold(self, n, raw, ondisk):
        if self.withheld_fh is None:
            self.withheld_fh = private_file(str(self.withheld_path))
        self.withheld_fh.write(json.dumps({"n": n, "path": ondisk, "name": raw.decode("utf-8", "surrogateescape"), "name_b64": b64(raw)}, ensure_ascii=True) + "\n")
        self.withheld_fh.flush()
        self.members_withheld += 1

    def time_left(self):
        return self.deadline - time.monotonic()

    def finish_files(self):
        for fh in (self.members_fh, self.withheld_fh):
            if fh is not None:
                try:
                    fh.flush()
                    os.fsync(fh.fileno())
                    fh.close()
                except OSError:
                    pass
        self.tree.close()

    # -- one member --
    def handle(self, m, opener):
        """Record one member and, when it is a file this run may write, extract it. `opener()` gives a binary stream of its bytes."""
        n, raw = m["n"], m["raw"]
        self.next_index = n + 1
        self.current = n
        comps, flags = name_analysis(raw, m["windows"])
        key = hashlib.blake2b(raw, digest_size=8).digest()
        if key in self.name_seen:
            flags.append("duplicate-name")
            self.duplicate_names += 1
        else:
            self.name_seen.add(key)
        text = raw.decode("utf-8", "surrogateescape")
        shaped = token_shaped(text) or scrub(text) != text
        row = {"n": n, "type": m["kind"], "locator": m["locator"]}
        if shaped:
            row.update(name="<withheld %d characters>" % len(text), name_withheld=True, name_bytes=len(raw))
        else:
            row.update(name=cell(text), name_b64=b64(raw))
        row.update(path=None, size_declared=m.get("size"), packed=m.get("packed"), size_written=None, sha256=None, digest_withheld=False,
                   crc_verified=None, status=None, reason=None,
                   mtime_raw=m.get("mtime_raw"), mtime_utc=m.get("mtime_utc"), mtime_zone=m.get("mtime_zone"), mode=m.get("mode"),
                   uid=m.get("uid"), gid=m.get("gid"), method=m.get("method"))
        if m.get("link") is not None:
            row["link_target"] = scrub(cell(m["link"].decode("utf-8", "surrogateescape")))
        kind = m["kind"]

        def done(status, reason=None, **more):
            row["flags"] = flags
            row["status"], row["reason"] = status, reason
            row.update(more)
            self.record(row)
            self.current = None

        if kind == "dir":
            return done("directory")
        if kind != "file":
            return done("not_created", "a %s is recorded and never created" % kind)
        if m.get("encrypted"):
            return done("encrypted", "the member is encrypted: counted, not extracted (no password is used or guessed)")
        if m.get("unsupported"):
            return done("unsupported", m["unsupported"])
        if len(comps) > self.a["max_depth"]:
            return done("skipped", "depth: %d path components, more than max_depth %d" % (len(comps), self.a["max_depth"]))
        declared = m.get("size")
        if declared is not None and declared > self.a["max_member_bytes"]:
            # The declared size is a claim; the written size decides. A claim already past the budget is not worth opening.
            return done("skipped", "max_member_bytes: declares %d bytes, more than the budget of %d" % (declared, self.a["max_member_bytes"]))
        if self.total_written >= self.a["max_total_bytes"] and declared != 0:
            self.next_index = n
            raise Budget("max_total_bytes", "the total byte budget of %d is used" % self.a["max_total_bytes"])
        # Where it goes.
        if shaped:
            parts, leaf = ["_withheld"], "withheld-%06d%s" % (n, extension_of(raw))
            flags.append("name-withheld")
        elif comps:
            parts, leaf = [render_component(c) for c in comps[:-1]], render_component(comps[-1])
        else:
            parts, leaf = [], "unnamed-%06d" % n
        flat = False
        try:
            dfd, partial, fh = self.tree.create(parts, leaf)
        except OSError as exc:
            if exc.errno in (errno.EEXIST, errno.ENOTDIR, errno.EISDIR, errno.ELOOP, errno.ENAMETOOLONG, errno.EINVAL):
                parts, leaf, flat = ["_flat"], "%06d-%s" % (n, leaf[:100]), True
                try:
                    dfd, partial, fh = self.tree.create(parts, leaf)
                except OSError as exc2:
                    return done("failed", "the file could not be created: %s" % describe(exc2))
            else:
                return done("failed", "the file could not be created: %s" % describe(exc))
        if flat:
            flags.append("flat-path")
        if shaped:
            self.withhold(n, raw, "/".join(parts + [leaf]))
        packed = m.get("packed")
        crc_listed = m.get("crc")
        sha = hashlib.sha256()
        acc = {"crc": 0, "written": 0, "head": b""}
        status, reason, stop = "extracted", None, None
        stream = None
        cap = min(self.a["max_member_bytes"], self.a["max_total_bytes"] - self.total_written)

        def put(block):
            """Write a block that is within the cap; every byte written is counted, hashed and CRC'd."""
            fh.write(block)
            sha.update(block)
            acc["crc"] = zlib.crc32(block, acc["crc"])
            acc["written"] += len(block)
            self.total_written += len(block)
            if len(acc["head"]) < 512:
                acc["head"] += block[:512 - len(acc["head"])]

        try:
            stream = opener()
            while True:
                if self.time_left() <= 0:
                    status, reason, stop = "partial", "max_seconds: the time budget of %d seconds was reached" % self.a["max_seconds"], "max_seconds"
                    break
                block = stream.read(min(CHUNK, cap - acc["written"] + 1))
                if not block:
                    break
                if acc["written"] + len(block) > cap:
                    put(block[:max(0, cap - acc["written"])])
                    which = "max_member_bytes" if cap == self.a["max_member_bytes"] else "max_total_bytes"
                    status = "partial"
                    reason = ("%s: the member is longer than the budget of %d bytes; what was written is kept as .partial"
                              % (which, self.a["max_member_bytes"] if which == "max_member_bytes" else self.a["max_total_bytes"]))
                    if which == "max_total_bytes":
                        stop = which
                    break
                put(block)
                if packed and acc["written"] > self.a["max_ratio"] * max(packed, 1) + RATIO_SLACK:
                    status = "partial"
                    reason = ("max_ratio: %d bytes from %d packed (more than %d times); what was written is kept as .partial"
                              % (acc["written"], packed, self.a["max_ratio"]))
                    break
        except Budget as exc:
            status, reason, stop = "partial", "%s: %s" % (exc.reason, exc), exc.reason
        except Ratio as exc:
            status, reason, stop = "partial", "max_ratio: %s" % exc, "max_ratio"
        except (OSError, EOFError, zlib.error, lzma.LZMAError, tarfile.TarError, zipfile.BadZipFile, NotImplementedError, RuntimeError, ValueError,
                struct.error) as exc:
            msg = describe(exc)
            status = "partial"
            if isinstance(exc, OSError) and exc.errno in (errno.ENOSPC, errno.EDQUOT):
                reason = "write_failed: no space left to write (%s); %d bytes are kept as .partial" % (msg, acc["written"])
                stop = "disk_full"
            else:
                reason = "read_failed: %s" % msg
                # A reader that raises throws away the block it was reading. A stream that knows what it handed out can give back the
                # bytes of this member that were decompressed before the break: they are written too, and the row says how many.
                salvage = getattr(stream, "salvage", None)
                if salvage is not None:
                    try:
                        extra = salvage(acc["written"])[:max(0, cap - acc["written"])]
                        if extra:
                            put(extra)
                            reason += " (%d bytes decompressed before the break were recovered)" % len(extra)
                    except (OSError, ValueError):
                        pass
        finally:
            try:
                fh.flush()
                fh.close()
            except OSError:
                pass
            if stream is not None and hasattr(stream, "close"):
                try:
                    stream.close()
                except Exception:   # noqa: BLE001 - a close that fails changes nothing about the bytes written
                    pass
        written, crc, head = acc["written"], acc["crc"], acc["head"]
        verified = None
        if status == "extracted":
            if declared is not None and written != declared:
                status = "partial"
                reason = ("size_mismatch: the archive declares %d bytes and %d came out%s"
                          % (declared, written, " (the archive ends before the member's declared end)" if written < declared else ""))
            elif crc_listed is not None:
                verified = (crc & 0xFFFFFFFF) == crc_listed
                if not verified:
                    status, reason = "partial", "crc_mismatch: the CRC-32 of the bytes written does not match the archive's record"
        short = written < SHORT_MEMBER
        final = leaf
        if status == "extracted":
            try:
                final = self.tree.publish(dfd, partial, leaf)
            except OSError as exc:
                status, reason = "partial", "the finished file could not take its name: %s" % describe(exc)
        shown = partial if status != "extracted" else final
        if status != "extracted" and written == 0:
            try:
                os.unlink(partial, dir_fd=dfd)       # nothing was written: no empty .partial is left to look like a result
                shown = None
            except OSError:
                pass
        row["path"] = ("extracted/" + "/".join(parts + [shown])) if shown else None
        try:
            os.close(dfd)
        except OSError:
            pass
        if final != leaf and status == "extracted":
            flags.append("renamed-duplicate")
        row["size_written"] = written
        row["sha256"] = None if short else sha.hexdigest()
        row["digest_withheld"] = bool(short)
        if crc_listed is not None and not short:
            row["crc32_listed"] = "%08x" % crc_listed
            row["crc32_written"] = "%08x" % (crc & 0xFFFFFFFF)
        row["crc_verified"] = verified
        kind_of = looks_like(head)
        if kind_of:
            row["looks_like"] = kind_of
            if status == "extracted":
                self.nested.append({"n": n, "path": row["path"], "looks_like": kind_of})
                flags.append("nested-archive")
        done(status, reason)
        if stop:
            if status == "partial":
                self.next_index = n          # the member is not whole: a resume starts it again
            raise Budget(stop, reason or stop)


# ---- readers per format -------------------------------------------------------------------------------------------------

def tar_kind(t):
    if t.isreg():
        return "file"
    if t.isdir():
        return "dir"
    if t.issym():
        return "symlink"
    if t.islnk():
        return "hardlink"
    if t.ischr():
        return "char-device"
    if t.isblk():
        return "block-device"
    if t.isfifo():
        return "fifo"
    return "other"


class HugeHeader(tarfile.ReadError):
    pass


class BoundedInfo(tarfile.TarInfo):
    """tarfile reads a GNU long-name/long-link or pax header's data whole, however large the header says it is: the size is checked first."""

    def _proc_gnulong(self, tf):
        if self.size > META_MAX:
            raise HugeHeader("a GNU long-name or long-link header at offset %d declares %d bytes (more than %d): it is not read" % (self.offset, self.size, META_MAX))
        return super()._proc_gnulong(tf)

    def _proc_pax(self, tf):
        if self.size > META_MAX:
            raise HugeHeader("a pax header at offset %d declares %d bytes (more than %d): it is not read" % (self.offset, self.size, META_MAX))
        return super()._proc_pax(tf)


def tar_member(n, t, compressed):
    raw = t.name.encode("utf-8", "surrogateescape")
    link = t.linkname.encode("utf-8", "surrogateescape") if t.linkname else None
    mt = t.mtime
    return {"n": n, "raw": raw, "windows": False, "kind": tar_kind(t), "size": t.size if t.isreg() else None, "packed": None,
            "mtime_raw": repr(mt), "mtime_utc": iso_utc(mt), "mtime_zone": "utc (tar stores epoch seconds)", "mode": "%o" % t.mode,
            "uid": t.uid, "gid": t.gid, "link": link if tar_kind(t) in ("symlink", "hardlink") else None,
            "locator": "tar:index=%d" % n if compressed else "tar:index=%d;header=%d;data=%d" % (n, t.offset, t.offset_data)}


def run_tar(eng, stream, compressed, from_index, max_members):
    mode = "r|" if compressed else "r:"
    tf = tarfile.open(fileobj=stream, mode=mode, tarinfo=BoundedInfo, encoding="utf-8", errors="surrogateescape") if compressed else \
        tarfile.open(name=stream, mode=mode, tarinfo=BoundedInfo, encoding="utf-8", errors="surrogateescape")
    n = 0
    handled = 0
    last_end = 0
    try:
        for t in tf:
            if eng.time_left() <= 0:
                raise Budget("max_seconds", "the time budget of %d seconds was reached" % eng.a["max_seconds"])
            if n >= from_index:
                if handled >= max_members:
                    raise Budget("max_members", "the member budget of %d is used" % max_members)
                if eng.time_left() <= 0:
                    raise Budget("max_seconds", "the time budget of %d seconds was reached" % eng.a["max_seconds"])
                m = tar_member(n, t, compressed)
                if not t.isreg():
                    opener = lambda: None
                elif t.issparse():
                    opener = lambda t=t: tf.extractfile(t)
                elif compressed:
                    opener = lambda t=t: TarMember(tf, t, stream)
                else:
                    opener = lambda t=t: RawSlice(stream, t.offset_data, t.size)
                eng.handle(m, opener)
                handled += 1
            n += 1
            if not compressed:
                last_end = t.offset_data + ((t.size + 511) // 512) * 512 if t.isreg() else t.offset_data
            tf.members = []      # the manifest is on disk: do not hold every header in memory
        eng.extra["members_in_archive"] = n
    except HugeHeader as exc:
        eng.notes.append("the tar stopped being readable after %d members: %s" % (n, describe(exc)))
        eng.stopped_by, eng.stop_text = "archive_unreadable", describe(exc)
    except (tarfile.TarError, EOFError, zlib.error, lzma.LZMAError, OSError) as exc:
        eng.notes.append("the archive ended or broke after %d members: %s" % (n, describe(exc)))
        eng.stopped_by, eng.stop_text = "archive_unreadable", "the archive ended or broke after %d members: %s" % (n, describe(exc))
    finally:
        try:
            tf.close()
        except Exception:   # noqa: BLE001
            pass
    if not compressed and eng.stopped_by is None:
        size = os.path.getsize(stream)
        if last_end > size:
            eng.notes.append("member %d's data runs %d bytes past the end of the file: the archive is truncated" % (n - 1, last_end - size))
            eng.stopped_by, eng.stop_text = "archive_truncated", "the last member's data runs past the end of the file"
        else:
            with open(stream, "rb") as fh:
                fh.seek(last_end)
                rest = fh.read(1 << 20)
            if rest.strip(b"\0"):
                eng.notes.append("%d bytes after member %d are not a tar header this reader could read (damaged or not a tar at offset %d)" % (size - last_end, n - 1, last_end))
                eng.stopped_by, eng.stop_text = "archive_unreadable", "bytes after the last member are not a tar header"


def zip_declared(path):
    """The member count and the central directory's size the end-of-central-directory record declares (zip64 too), read before zipfile loads it."""
    size = os.path.getsize(path)
    with open(path, "rb") as fh:
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
            with open(path, "rb") as fh:
                fh.seek(struct.unpack_from("<Q", tail, loc + 8)[0])
                rec = fh.read(56)
            if rec[:4] == b"PK\x06\x06":
                total = struct.unpack_from("<Q", rec, 32)[0]
                cd_bytes = struct.unpack_from("<Q", rec, 40)[0]
    return total, cd_bytes


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


ZIP_METHODS = {0: "stored", 8: "deflate", 12: "bzip2", 14: "lzma"}


def run_zip(eng, path, from_index, max_members):
    declared, cd_bytes = zip_declared(path)
    if declared is not None:
        eng.extra["members_declared"] = declared
    if cd_bytes is not None and cd_bytes > ZIP_DIRECTORY_MAX:
        raise ArchiveError("the central directory is %d bytes, more than the %d this tool reads into memory (every entry is held, about 500 bytes each): "
                           "nothing was extracted; list it with the archive-members recipe, or split the archive" % (cd_bytes, ZIP_DIRECTORY_MAX), members_declared=declared)
    wanted = max(from_index + max_members, 1) * ZIP_DIRECTORY_FACTOR
    if cd_bytes is not None and cd_bytes > (1 << 20) and cd_bytes // 46 > wanted:
        # the count in the end record is the archive's claim and zipfile reads the directory by its size: an entry is at least 46 bytes
        raise ArchiveError("the central directory is %d bytes, room for more than %d entries (%d times the max_members of %d, and from_index %d), whatever the end record's count says: "
                           "the whole directory is loaded to extract any of it, so it is not loaded for that few; nothing was extracted. Raise max_members to at least %d"
                           % (cd_bytes, wanted, ZIP_DIRECTORY_FACTOR, max_members, from_index, -(-(cd_bytes // 46) // ZIP_DIRECTORY_FACTOR)), members_declared=declared)
    if declared is not None and declared > wanted:
        raise ArchiveError("the central directory declares %d members, more than %d times the max_members of %d (and from_index %d): the whole directory is loaded to extract any of it, "
                           "so it is not loaded for that few; nothing was extracted. Raise max_members to at least %d to extract from this archive"
                           % (declared, ZIP_DIRECTORY_FACTOR, max_members, from_index, -(-declared // ZIP_DIRECTORY_FACTOR)), members_declared=declared)
    try:
        zf = zipfile.ZipFile(path)
    except (zipfile.BadZipFile, OSError, NotImplementedError, ValueError, EOFError) as exc:
        raise ArchiveError("zip: the central directory cannot be read (%s)" % describe(exc), local_headers_seen=count_local_headers(path),
                           note="a damaged or truncated zip: its local headers are counted, not trusted; nothing was extracted")
    handled = 0
    with zf:
        infos = zf.infolist()
        eng.extra["members_in_archive"] = len(infos)
        for n, info in enumerate(infos):
            if n < from_index:
                continue
            if handled >= max_members:
                raise Budget("max_members", "the member budget of %d is used" % max_members)
            if eng.time_left() <= 0:
                raise Budget("max_seconds", "the time budget of %d seconds was reached" % eng.a["max_seconds"])
            utf8 = bool(info.flag_bits & 0x800)
            raw = info.orig_filename.encode("utf-8" if utf8 else "cp437", "surrogateescape")
            mode = (info.external_attr >> 16) & 0xFFFF
            unix = info.create_system == 3
            if info.is_dir():
                kind = "dir"
            elif unix and (mode & 0o170000) == 0o120000:
                kind = "symlink"
            elif unix and (mode & 0o170000) in (0o020000, 0o060000, 0o010000):
                kind = {0o020000: "char-device", 0o060000: "block-device", 0o010000: "fifo"}[mode & 0o170000]
            else:
                kind = "file"
            ext = zip_ext_time(info.extra)
            if ext is not None:
                mtime_raw, mtime_utc, zone = "extended timestamp %d" % ext, iso_utc(ext), "utc (extended timestamp 0x5455)"
            else:
                mtime_raw = "%04d-%02d-%02d %02d:%02d:%02d" % info.date_time
                mtime_utc, zone = None, "unknown (DOS local time, 2-second resolution; no zone is stored)"
            encrypted = bool(info.flag_bits & 0x1) or info.compress_type == 99
            unsupported = None
            if not encrypted and info.compress_type not in ZIP_METHODS and kind == "file":
                unsupported = "compression method %d is not one this build reads (stored, deflate, bzip2 and lzma are)" % info.compress_type
            link = None
            if kind == "symlink" and not encrypted and unsupported is None:
                try:
                    with zf.open(info) as lf:
                        link = lf.read(LINK_TARGET_MAX + 1)[:LINK_TARGET_MAX]
                except Exception as exc:   # noqa: BLE001 - a link target that cannot be read is said, not fatal
                    link = ("<unreadable: %s>" % describe(exc)).encode()
            m = {"n": n, "raw": raw, "windows": True, "kind": kind, "size": info.file_size, "packed": info.compress_size, "mtime_raw": mtime_raw,
                 "mtime_utc": mtime_utc, "mtime_zone": zone, "mode": ("%o" % mode) if mode else None, "uid": None, "gid": None, "link": link,
                 "encrypted": encrypted, "unsupported": unsupported, "crc": info.CRC, "method": ZIP_METHODS.get(info.compress_type, "method %d" % info.compress_type),
                 "locator": "zip:index=%d;header=%d" % (n, info.header_offset)}
            eng.handle(m, lambda info=info: zip_stream(zf, info))
            handled += 1


def zip_stream(zf, info):
    """The member's bytes. zipfile checks the CRC when the last byte is read and then raises instead of returning that byte; this
    tool checks the CRC itself (it keeps what was read, and says the CRC did not match), so the library's check is off."""
    stream = zf.open(info)
    if hasattr(stream, "_expected_crc"):
        stream._expected_crc = None
    return stream


def count_local_headers(path, cap=64 * 1024 * 1024):
    """How many local file headers (PK 03 04) the first `cap` bytes hold: a count for a zip whose directory is gone, not a listing."""
    count, tail = 0, b""
    try:
        with open(path, "rb") as fh:
            seen = 0
            while seen < cap:
                block = fh.read(CHUNK)
                if not block:
                    break
                seen += len(block)
                data = tail + block
                count += data.count(b"PK\x03\x04")
                tail = data[-3:]
    except OSError:
        return None
    return count


class ArchiveError(Exception):
    def __init__(self, message, **extra):
        super().__init__(message)
        self.extra = extra


def parse_gzip_header(head):
    """(name bytes or None, mtime int) from a gzip member header (RFC 1952), or (None, None) when it cannot be read from `head`."""
    if len(head) < 10 or head[:3] != b"\x1f\x8b\x08":
        return None, None
    flg, mtime = head[3], struct.unpack_from("<I", head, 4)[0]
    pos = 10
    if flg & 4:
        if len(head) < pos + 2:
            return None, mtime
        pos += 2 + struct.unpack_from("<H", head, pos)[0]
    name = None
    if flg & 8:
        end = head.find(b"\0", pos)
        if end < 0:
            return None, mtime
        name = head[pos:end]
    return name, mtime


def run_single(eng, path, kind, dec, from_index):
    """One compressed file that is not a tar: ONE member."""
    with open(path, "rb") as fh:
        head = fh.read(4096)
    name, mtime = parse_gzip_header(head) if kind == "gzip" else (None, None)
    base = os.path.basename(path)
    source = "the gzip header's file name" if name else "the archive's own name without its compression suffix"
    if not name:
        stem = re.sub(r"\.(gz|gzip|bz2|bzip2|xz|zst|zstd|z)$", "", base, flags=re.I)
        name = os.fsencode(stem or "data")
    m = {"n": 0, "raw": name, "windows": False, "kind": "file", "size": None, "packed": os.path.getsize(path), "mtime_raw": str(mtime) if mtime else None,
         "mtime_utc": iso_utc(mtime) if mtime else None, "mtime_zone": "utc (gzip stores epoch seconds; 0 means none)" if kind == "gzip" else None,
         "mode": None, "uid": None, "gid": None, "link": None, "locator": "%s:stream" % kind, "method": kind}
    eng.extra["single_file_name_from"] = source
    eng.extra["members_in_archive"] = 1
    if from_index > 0:
        return
    eng.handle(m, lambda: dec)


# ---- 7z ----------------------------------------------------------------------------------------------------------------

def find_7z():
    for name in SEVEN_Z_NAMES:
        found = shutil.which(name)
        if found:
            return found
    return None


def banner(program):
    try:
        proc = spawn([program], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=dict(os.environ, LC_ALL="C"))
        ACTIVE.append(proc)
        try:
            out, _ = proc.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            kill_tree(proc)
            out, _ = proc.communicate()
        finally:
            if proc in ACTIVE:
                ACTIVE.remove(proc)
        for line in out.decode("utf-8", "replace").splitlines():
            if line.strip():
                return line.strip()[:200]
    except OSError:
        pass
    return None


def listing_records(path):
    """The records of `7z l -slt -ba` as dicts of bytes, one per blank-line-separated block, read a line at a time."""
    fields = {}
    with open(path, "rb") as fh:
        for line in fh:
            if len(line) > LISTING_LINE_MAX:
                raise ArchiveError("7z printed a listing line of more than %d bytes" % LISTING_LINE_MAX)
            line = line.rstrip(b"\r\n")
            if not line:
                if b"Path" in fields:
                    yield fields
                fields = {}
                continue
            if b" = " in line:
                k, v = line.split(b" = ", 1)
                fields[k.strip()] = v
            elif line.endswith(b" =") and b" = " not in line:
                fields[line[:-2].strip()] = b""
    if b"Path" in fields:
        yield fields


def seven_member(n, f):
    attrs = f.get(b"Attributes", b"").decode("ascii", "replace")
    mode_text = attrs.split(" ", 1)[1] if " " in attrs else ""
    folder = f.get(b"Folder") == b"+" or attrs.startswith("D")
    if folder:
        kind = "dir"
    elif mode_text[:1] == "l":
        kind = "symlink"
    elif mode_text[:1] in ("c", "b", "p"):
        kind = {"c": "char-device", "b": "block-device", "p": "fifo"}[mode_text[:1]]
    else:
        kind = "file"
    mod = f.get(b"Modified", b"").decode("ascii", "replace").strip()
    size = f.get(b"Size", b"").strip()
    crc = f.get(b"CRC", b"").strip()
    return {"n": n, "raw": f[b"Path"], "windows": True, "kind": kind, "size": int(size) if size.isdigit() else None, "packed": None,
            "mtime_raw": mod or None, "mtime_utc": (mod.replace(" ", "T") + "Z") if mod else None,
            "mtime_zone": "utc (7z's listing was run with TZ=UTC; resolution 100 ns)" if mod else None,
            "mode": mode_text or attrs or None, "uid": None, "gid": None, "link": None, "encrypted": f.get(b"Encrypted") == b"+",
            "crc": int(crc, 16) if re.fullmatch(rb"[0-9A-Fa-f]{1,8}", crc) else None, "method": f.get(b"Method", b"").decode("ascii", "replace") or None,
            "locator": "7z:index=%d" % n}


class Pipe:
    """The bytes 7z writes to its stdout, read with the clock running; split into members by the sizes of its own listing."""

    def __init__(self, proc, deadline, max_ratio=None, packed=0):
        self.fd = proc.stdout.fileno()
        self.deadline = deadline
        self.eof = False
        self.total = 0
        self.max_ratio, self.packed = max_ratio, packed    # the whole output is held to max_ratio times the archive's size

    def read(self, n):
        if self.eof or n <= 0:
            return b""
        while True:
            left = self.deadline - time.monotonic()
            if left <= 0:
                raise Budget("max_seconds", "the time budget was reached while 7z was still writing")
            if select.select([self.fd], [], [], min(left, 5))[0]:
                break
        data = os.read(self.fd, min(n, CHUNK))
        if not data:
            self.eof = True
        self.total += len(data)
        if self.max_ratio and self.total > self.max_ratio * max(self.packed, 1) + RATIO_SLACK:
            raise Ratio("7z wrote %d bytes from an archive of %d (more than %d times)" % (self.total, self.packed, self.max_ratio))
        return data


class Piece:
    """`size` bytes of the pipe: one member's. A read past the member's end gives nothing; a pipe that ends first is said."""

    def __init__(self, pipe, size):
        self.pipe, self.remaining, self.short = pipe, size, False

    def read(self, n=-1):
        if self.remaining <= 0:
            return b""
        data = self.pipe.read(min(n if n and n > 0 else CHUNK, self.remaining))
        if not data:
            self.short = True
            raise EOFError("7z's output ended %d bytes before this member's declared size" % self.remaining)
        self.remaining -= len(data)
        return data

    def drain(self):
        while self.remaining > 0:
            self.read(CHUNK)


def run_7z(eng, path, from_index, max_members, sevenz):
    env = dict(os.environ, TZ="UTC", LANG="C.UTF-8", LC_ALL="C.UTF-8")
    listing = eng.out_root / first_free(str(eng.out_root), "7z-listing", ".txt")
    stderr_l = eng.out_root / first_free(str(eng.out_root), "7z-list.stderr", "")
    with private_file(str(listing), "wb") as out_fh, private_file(str(stderr_l), "wb") as err_fh:
        proc = spawn([sevenz, "l", "-slt", "-ba", "--", path], stdout=out_fh, stderr=err_fh, env=env)
        ACTIVE.append(proc)
        try:
            rc = proc.wait(timeout=max(1.0, eng.time_left()))
        except subprocess.TimeoutExpired:
            kill_tree(proc)
            proc.wait()
            raise Budget("max_seconds", "the time budget was used by 7z's listing")
        finally:
            if proc in ACTIVE:
                ACTIVE.remove(proc)
    err_text = ""
    try:
        with open(stderr_l, "rb") as fh:
            err_text = fh.read(2000).decode("utf-8", "replace").strip()
        if not err_text:
            os.unlink(stderr_l)
        else:
            eng.extra["listing_stderr_file"] = stderr_l.name
    except OSError:
        pass
    eng.extra["listing_file"] = listing.name
    eng.extra["listing_exit"] = rc
    # One pass over the listing to learn what the archive holds; the members are read again, a block at a time, below.
    n_all = encrypted_n = device_n = 0
    names_plain, names_all = {}, {}
    for n, f in enumerate(listing_records(str(listing))):
        if n % 1024 == 0 and eng.time_left() <= 0:
            raise Budget("max_seconds", "the time budget of %d seconds was used reading 7z's listing, after %d members" % (eng.a["max_seconds"], n))
        m = seven_member(n, f)
        n_all += 1
        encrypted_n += 1 if m["encrypted"] else 0
        device_n += 1 if m["kind"] in ("char-device", "block-device", "fifo") else 0
        names_all[f[b"Path"]] = names_all.get(f[b"Path"], 0) + 1
        if m["kind"] in ("file", "symlink") and not m["encrypted"] and m["size"] is not None:
            names_plain[f[b"Path"]] = names_plain.get(f[b"Path"], 0) + 1
    if n_all == 0:
        raise ArchiveError("7z listed no member (exit %s): %s" % (rc, scrub(err_text) or "nothing on stderr"), listing_exit=rc,
                           note="a 7z whose headers are encrypted cannot be listed without its password; none is used or guessed, so nothing was extracted")
    eng.extra["members_in_archive"] = n_all
    eng.extra["encrypted_members"] = encrypted_n
    # With an encrypted member or a device the stream is asked for by name: only the plain files that can be named are in it,
    # in listing order. Otherwise 7z is asked for everything and the stream holds every file, in listing order.
    select_mode = encrypted_n > 0 or device_n > 0
    argv = [sevenz, "x", "-so", "-y", "-bd"]
    unselectable = set()
    selection = None
    if select_mode:
        selection = eng.out_root / first_free(str(eng.out_root), "7z-selection", ".txt")
        refused = set()
        with private_file(str(selection), "wb") as sfh:
            for nm, k in sorted(names_plain.items()):
                # a spelling shared with a member that is not selected cannot be told apart from it in the stream; a line break,
                # an empty name or a leading dash cannot be passed in a list file
                if names_all[nm] != k or b"\n" in nm or b"\r" in nm or not nm or nm.startswith(b"-"):
                    refused.add(nm)
                    continue
                sfh.write(nm + b"\n")
        unselectable = refused
        eng.extra["selection_file"] = selection.name
        argv += ["-spd", "-scsUTF-8"]
    # No `--` here: 7z reads a list file named @file only before it, and a path that starts with a dash is given as ./path.
    argv.append(path if not path.startswith("-") else "./" + path)
    if selection is not None:
        argv.append("@" + str(selection))
    stderr_x = eng.out_root / first_free(str(eng.out_root), "7z-extract.stderr", "")
    err_fh = private_file(str(stderr_x), "wb")
    proc = spawn(argv, stdout=subprocess.PIPE, stderr=err_fh, env=env)
    ACTIVE.append(proc)
    pipe = Pipe(proc, eng.deadline, eng.a["max_ratio"], os.path.getsize(path))
    handled = 0
    desync = False
    try:
        for n, f in enumerate(listing_records(str(listing))):
            m = seven_member(n, f)
            name = f[b"Path"]
            in_stream = m["kind"] in ("file", "symlink") and not m["encrypted"] and m["size"] is not None and name not in unselectable
            piece = Piece(pipe, m["size"]) if in_stream else None
            if n < from_index:
                if piece is not None:
                    piece.drain()
                continue
            if handled >= max_members:
                raise Budget("max_members", "the member budget of %d is used" % max_members)
            if eng.time_left() <= 0:
                raise Budget("max_seconds", "the time budget of %d seconds was reached" % eng.a["max_seconds"])
            if m["kind"] == "symlink" and piece is not None:
                target = b""
                try:
                    while piece.remaining and len(target) <= LINK_TARGET_MAX:
                        target += piece.read(min(piece.remaining, LINK_TARGET_MAX + 1 - len(target)))
                except EOFError:
                    desync = True
                m["link"] = target[:LINK_TARGET_MAX]
            elif m["kind"] == "file" and piece is None and not m["encrypted"]:
                if m["size"] is None:
                    m["unsupported"] = "7z's listing gives no size for this member, so its bytes cannot be told apart in the stream"
                else:
                    m["unsupported"] = "the name cannot be passed to 7z in a list file (a line break, a leading dash, or a spelling shared with a member that is not a plain file)"
            eng.handle(m, (lambda piece=piece: piece) if (piece is not None and m["kind"] == "file") else (lambda: None))
            handled += 1
            if piece is not None:
                try:
                    piece.drain()
                except EOFError:
                    desync = True
        # Anything after the last declared byte is output the listing does not account for.
        if not desync and not pipe.eof:
            try:
                extra = pipe.read(1)
            except Budget:
                extra = b""
            if extra:
                eng.notes.append("7z wrote more bytes than its listing declares: the CRC of each member says which are whole")
                eng.extra["stream_longer_than_listing"] = True
    finally:
        try:
            proc.stdout.close()
        except OSError:
            pass
        kill_tree(proc)
        rc2 = proc.wait()
        if proc in ACTIVE:
            ACTIVE.remove(proc)
        err_fh.close()
    eng.extra["extract_exit"] = rc2 if rc2 >= 0 else "killed by signal %d" % -rc2
    try:
        if os.path.getsize(stderr_x) == 0:
            os.unlink(stderr_x)
        else:
            eng.extra["extract_stderr_file"] = stderr_x.name
    except OSError:
        pass
    if desync:
        eng.notes.append("7z's output ended before its listing did: the members after that point are not in the stream (see their statuses)")
        eng.stopped_by, eng.stop_text = eng.stopped_by or "archive_unreadable", "7z's output ended before its listing did"


# ---- detection ---------------------------------------------------------------------------------------------------------

def tar_header_ok(block):
    if len(block) < 512:
        return False
    try:
        tarfile.TarInfo.frombuf(block[:512], "utf-8", "surrogateescape")
        return True
    except Exception:   # noqa: BLE001 - any failure to read the block as a header means it is not one
        return False


def detect(path):
    """(format, detail). Format is zip, 7z, tar, gzip, bzip2, xz, zstd, or an unsupported name, from the bytes."""
    with open(path, "rb") as fh:
        head = fh.read(4096)
    if head.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        return "zip", "zip signature at offset 0"
    if head.startswith(SEVEN_Z_MAGIC):
        return "7z", "7z signature at offset 0"
    kind = looks_like(head)
    if kind in ("gzip", "bzip2", "xz", "zstd"):
        return kind, "%s signature at offset 0" % kind
    if head[257:262] == b"ustar" or tar_header_ok(head[:512]) and head[:512].strip(b"\0"):
        return "tar", "tar header at offset 0"
    if kind in ("rar", "cab"):
        return "unsupported:" + kind, "%s signature at offset 0" % kind
    if head[:4] == b"\xd0\xcf\x11\xe0":
        return "unsupported:ole", "OLE compound file signature"
    # A zip with something in front of it (a self-extractor): the end-of-central-directory record still says what it is.
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as fh:
            fh.seek(max(0, size - 65557))
            if b"PK\x05\x06" in fh.read():
                return "zip", "no signature at offset 0, but an end-of-central-directory record at the end (a zip with a prefix)"
    except OSError:
        pass
    return None, "not a zip, tar, gzip, bzip2, xz, zstd or 7z archive: its first bytes are %s" % head[:16].hex()


def sha256_of(path, limit):
    size = os.path.getsize(path)
    if size > limit:
        return None
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(CHUNK), b""):
            h.update(block)
    return h.hexdigest()


# ---- main --------------------------------------------------------------------------------------------------------------

def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    if not isinstance(args, dict):
        fail("arguments are a JSON object")
    path = args.get("path")
    if not isinstance(path, str) or not path or "\0" in path:
        fail("path is required: the archive to extract")
    try:
        path.encode("utf-8")
    except UnicodeEncodeError:
        fail("path holds a lone surrogate and cannot be written in an answer")
    a = {
        "from_index": whole(args, "from_index", 0, 0, 1 << 40),
        "max_total_bytes": whole(args, "max_total_bytes", MAX_TOTAL_DEFAULT, 1, BYTES_CEILING),
        "max_member_bytes": whole(args, "max_member_bytes", MAX_MEMBER_DEFAULT, 1, BYTES_CEILING),
        "max_members": whole(args, "max_members", MAX_MEMBERS_DEFAULT, 1, MAX_MEMBERS_CEILING),
        "max_ratio": whole(args, "max_ratio", MAX_RATIO_DEFAULT, 1, MAX_RATIO_CEILING),
        "max_depth": whole(args, "max_depth", MAX_DEPTH_DEFAULT, 1, MAX_DEPTH_CEILING),
        "max_seconds": whole(args, "max_seconds", MAX_SECONDS_DEFAULT, 1, MAX_SECONDS_CEILING),
        "limit": whole(args, "limit", LIMIT_DEFAULT, 1, LIMIT_CEILING),
    }
    resume = args.get("resume", False)
    if not isinstance(resume, bool):
        fail("resume is true or false")
    for key in ("name", "member", "members", "filter", "pattern", "glob"):
        if key in args:
            fail("%s is not a parameter: members are chosen by number (from_index), never by a filter over names, which would answer questions about withheld text" % key)
    unknown = sorted(set(args) - {"path", "out_dir", "resume", "from_index", "max_total_bytes", "max_member_bytes", "max_members", "max_ratio", "max_depth", "max_seconds", "limit"})
    if unknown:
        fail("unknown parameter: %s" % ", ".join(scrub(str(k)) for k in unknown))
    if not os.path.exists(path):
        fail("archive not found", path=scrub(path))
    if not os.path.isfile(path):
        fail("path is not a regular file", path=scrub(path))
    try:
        size = os.path.getsize(path)
    except OSError as exc:
        fail("the archive cannot be read: %s" % describe(exc), path=scrub(path))
    if size == 0:
        fail("the archive is empty (0 bytes)", path=scrub(path))

    try:
        fmt, why = detect(path)
    except OSError as exc:
        fail("the archive cannot be read: %s" % describe(exc), path=scrub(path))
    if fmt is None or fmt.startswith("unsupported:"):
        fail("unsupported or unrecognised archive: %s" % why, path=scrub(path), format=fmt, bytes=size,
             supported=["zip", "tar (plain, gzip, bzip2, xz, zstd)", "gzip, bzip2, xz, zstd (a single file)", "7z (with the 7z program)"])

    os.umask(0o077)
    install_signal_handlers()
    st = os.stat(path)
    digest = hashlib.sha256(("%s|%d|%d" % (os.path.abspath(path), size, st.st_mtime_ns)).encode("utf-8", "surrogateescape")).hexdigest()[:12]
    if args.get("out_dir"):
        if not isinstance(args["out_dir"], str) or "\0" in args["out_dir"]:
            fail("out_dir is a directory path")
        dest = resolve_output(args["out_dir"])
    elif in_job():
        dest = resolve_output(os.path.join(os.environ["OUT"], "archive_extract-" + digest))
    else:
        agent = re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool")
        dest = resolve_output(os.path.join("work", agent, "archive_extract-" + digest))
    if not args.get("out_dir") and dest.exists() and not resume:
        k = 2
        while Path("%s.%d" % (dest, k)).exists():
            k += 1
        dest = Path("%s.%d" % (dest, k))
    if dest.exists() and not dest.is_dir():
        fail("out_dir exists and is not a directory", out_dir=scrub(str(dest)))
    if dest.exists() and any(dest.iterdir()) and not resume:
        fail("out_dir already holds files: an extraction never writes over an earlier one. Pass a new out_dir, or resume: true (with from_index) "
             "to go on in this one; the new manifest is written beside the earlier one", out_dir=scrub(str(dest)))
    if resume and dest.exists() and not (dest / "extracted").is_dir():
        fail("resume: true needs an out_dir an earlier run made (it has no extracted/ directory)", out_dir=scrub(str(dest)))
    try:
        dest.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(dest, 0o700)
        (dest / "extracted").mkdir(mode=0o700, exist_ok=True)
        os.chmod(dest / "extracted", 0o700)
    except OSError as exc:
        fail("the output directory cannot be made: %s" % describe(exc), out_dir=scrub(str(dest)))
    run_no = 1
    while (dest / ("receipt.json" if run_no == 1 else "receipt.%d.json" % run_no)).exists():
        run_no += 1

    info = {"path": scrub(path), "bytes": size, "format": fmt, "detected_by": why, "sha256": None}
    sevenz = None
    if fmt == "7z":
        sevenz = find_7z()
        if sevenz is None:
            fail("a 7z archive needs the 7z program (7z, 7zz or 7za), which is not on PATH; nothing was extracted", path=scrub(path), format="7z",
                 install="apt-get install -y p7zip-full, or brew install sevenzip")
        info["program"] = {"path": sevenz, "banner": banner(sevenz)}
    try:
        info["sha256"] = sha256_of(path, HASH_ARCHIVE_MAX)
    except OSError as exc:
        fail("the archive cannot be read: %s" % describe(exc), path=scrub(path))
    if info["sha256"] is None:
        info["sha256_skipped"] = "the archive is larger than %d bytes; the run's own record of the input has its sha256" % HASH_ARCHIVE_MAX
    info["python"] = sys.version.split()[0]
    if resume:
        # A resume goes on in the directory of an earlier run of THIS archive: another archive's members would be mixed into it.
        try:
            with open(dest / "receipt.json", encoding="utf-8") as fh:
                earlier = json.load(fh)["archive"]
        except (OSError, ValueError, KeyError, TypeError):
            fail("resume: true needs the receipt of the earlier run (receipt.json) in out_dir, and it is not readable", out_dir=scrub(str(dest)))
        if earlier.get("bytes") != size or (earlier.get("sha256") and info["sha256"] and earlier["sha256"] != info["sha256"]):
            fail("this is not the archive the earlier run in out_dir extracted (its size or sha256 differs): a resume goes on with the same archive, "
                 "and an extraction of another archive takes a directory of its own", out_dir=scrub(str(dest)), earlier_bytes=earlier.get("bytes"),
                 earlier_sha256=earlier.get("sha256"), this_bytes=size, this_sha256=info["sha256"])

    try:
        eng = Engine(a, dest, run_no, info)
    except OSError as exc:
        fail("the output directory cannot be opened for writing: %s" % describe(exc), out_dir=scrub(str(dest)))
    eng.write_receipt()

    def last_word(signum):
        eng.stopped_by, eng.stop_text = "signal", "stopped by signal %d" % signum
        eng.next_index = eng.current if eng.current is not None else eng.next_index
        eng.extra["stopped_by_signal"] = signum
        eng.status = "interrupted"
        eng.write_receipt()
        eng.finish_files()
    STATE["last_word"] = last_word

    dec = None
    try:
        try:
            if fmt == "zip":
                run_zip(eng, path, a["from_index"], a["max_members"])
            elif fmt == "7z":
                run_7z(eng, path, a["from_index"], a["max_members"], sevenz)
            elif fmt == "tar":
                run_tar(eng, path, False, a["from_index"], a["max_members"])
            else:
                if fmt == "zstd":
                    which, mod = zstd_module()
                    if which is None:
                        raise ArchiveError("zstd: %s" % mod, format="zstd")
                    info["zstd_reader"] = which
                dec = Decomp(path, fmt, a["max_ratio"])
                peek = b""
                try:
                    peek = dec.read(512)
                except Ratio as exc:
                    raise ArchiveError("the compressed stream's first block already breaks the ratio budget: %s" % exc)
                except (EOFError, zlib.error, lzma.LZMAError, OSError, Unsupported) as exc:
                    raise ArchiveError("%s: the stream cannot be decompressed (%s)" % (fmt, describe(exc)))
                dec.unread(peek)
                if tar_header_ok(peek) and (peek[257:262] == b"ustar" or peek.strip(b"\0")):
                    info["format"] = "tar+" + fmt
                    run_tar(eng, dec, True, a["from_index"], a["max_members"])
                else:
                    info["format"] = fmt + " (a single file)"
                    run_single(eng, path, fmt, dec, a["from_index"])
                if dec.trailing:
                    eng.notes.append("%d bytes after the last %s stream are not another stream and were not decompressed" % (dec.trailing, fmt))
                    eng.extra["trailing_bytes"] = dec.trailing
                eng.extra["compressed_streams"] = dec.streams
        except Budget as exc:
            eng.stopped_by, eng.stop_text = exc.reason, scrub(str(exc))
        except Ratio as exc:
            eng.stopped_by, eng.stop_text = "max_ratio", scrub(str(exc))
        except Unsupported as exc:
            raise ArchiveError("zstd: %s" % exc, format="zstd")
        except (SystemExit, KeyboardInterrupt, ArchiveError):
            raise
        except Exception as exc:   # noqa: BLE001 - a defect in this tool or an input it did not foresee: said as JSON, with what was done kept
            eng.extra["rows_before_the_failure"] = eng.rows
            raise ArchiveError("internal error after %d member(s): %s: %s" % (eng.rows, type(exc).__name__, scrub(str(exc))), next_index=eng.next_index)
    except ArchiveError as exc:
        eng.finish_files()
        out = {"ok": False, "status": "failed", "error": scrub(str(exc)), "tool": TOOL, "archive": info, "out_dir": scrub(str(dest)), **exc.extra}
        eng.status = "failed"
        eng.stopped_by, eng.stop_text = "archive_unreadable", scrub(str(exc))
        eng.extra.update(exc.extra)
        eng.write_receipt()
        say(out, 1)
    finally:
        if dec is not None:
            dec.close()
    eng.finish_files()
    eng.status = None
    eng.write_receipt()
    receipt = eng.receipt()
    out = {"ok": True, **receipt, "members": eng.page,
           "members_returned": len(eng.page), "members_truncated": eng.rows > len(eng.page),
           "note": ("the inline members are a page; members_file has every member" if eng.rows > len(eng.page) else None)}
    if eng.stopped_by in ("archive_unreadable", "archive_truncated") and eng.rows == 0:
        out["ok"] = False
        say(out, 1)
    say(out, 0)


if __name__ == "__main__":
    main()
