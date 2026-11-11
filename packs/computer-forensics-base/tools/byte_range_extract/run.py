#!/usr/bin/env python3
"""Copy declared byte ranges of a file, or of a split raw image through its descriptor, to new files, bounded, with a digest of each.

Input is a regular file (`source`) or a layer descriptor (`descriptor`, from layer_describe; a range may then cross the boundary of two
segments of a raw split set) and a list of ranges, each an `offset` and a `length` in bytes. What it does, exactly:

  * Each source file is opened without waiting and without following a link and must be a regular file; a link, FIFO, directory or device
    is refused. Only a raw file or a raw split set is read: the decoded media of an E01, VMDK or QCOW is not these bytes, and a descriptor
    with such a layer is refused as unsupported. Its sources are looked at again at the end, and a source that changed makes the run a failure.
  * Every range is written to a file of its own in the output directory, created with O_EXCL and O_NOFOLLOW, mode 0600 in a 0700 directory, as
    range-NNNNNN.bin.partial and renamed to range-NNNNNN.bin only when it holds all the bytes asked for. A name that is taken gets a new
    one and the kept name is in the row; nothing is replaced. A range that ends past the end of the source, or starts beyond it, is short:
    it stays .partial, and the row says how many bytes were asked for (`requested`) and how many were read (`actual`). A sparse file
    reads as zeros where it has holes, as the file system gives them. Overlapping ranges are copied once each and flagged.
  * The sha256 of every range and of all the ranges together (in the order listed) is taken as the bytes are copied. The sha256 of fewer
    than 128 bytes is not written (a short value can be reversed from its digest), and the digest of the concatenation is written only when
    every range is whole. The answer carries locators, lengths and digests, never a byte of a range.
  * Budgets: `max_total_bytes` for everything written and `max_seconds` for the run, read between blocks. A range the byte budget cuts stays
    .partial; the ranges after it are `not_run`; the answer names the stop (`stopped_by`) and `next_range`, the one to go on from.
  * `complete` only when every range is whole, none was cut or left unrun, every row is in ranges.jsonl and the sources did not change. A
    short range, a budget stop or a failed write makes it `partial`; a refused source, a source that changed, or every range failed or left unrun, `failed`.
  * It says nothing about whether the bytes of a range form a file: a byte range is not a file. The bytes are evidence content and can hold
    credentials: run it as a job with secret_output true when a range may hold a credential store. The manifest does not force it, because a
    range of a whole case would make every output sensitive.

A SIGTERM, SIGINT or SIGHUP gives one JSON answer (partial, interrupted, with the range that was being copied) and exit 128 plus the signal;
the range being copied stays under its .partial name. Exit code 0 means the answer is whole about what was done; 1 is a refused argument or a
place that cannot be written.
"""
import errno
import hashlib
import json
import os
import re
import signal
import stat
import sys
import time
from bisect import bisect_right
from pathlib import Path

TOOL = {"name": "byte_range_extract", "version": 3}
STARTED = time.monotonic()
CHUNK = 1 << 20
RANGES_MAX = 10000
OFFSET_MAX = 1 << 62
BYTES_CEILING = 1 << 40
MAX_TOTAL_DEFAULT = 1 << 30
MAX_SECONDS_DEFAULT = 500
MAX_SECONDS_CEILING = 550               # inside the manifest's 600
SHORT_RANGE = 128                       # a range of fewer bytes has no digest written
LIMIT_DEFAULT = 200
LIMIT_CEILING = 5000


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


def describe(exc):
    code = errno.errorcode.get(exc.errno, "") if getattr(exc, "errno", None) else ""
    return scrub("%s%s: %s" % (type(exc).__name__, " " + code if code else "", getattr(exc, "strerror", None) or str(exc)))


def in_job():
    return bool(os.environ.get("JOB_ID") and os.environ.get("OUT"))


def say(obj, code=0):
    print_answer(obj, ensure_ascii=True)
    raise SystemExit(code)


def fail(message, **extra):
    say({"ok": False, "status": "failed", "status_basis": "the tool stopped with an error: %s" % scrub(message), "error": scrub(message), "tool": TOOL, **extra}, 1)


def whole(args, key, default, low, high):
    value = args.get(key)
    if value is None:
        return default
    if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
        fail("%s is a whole number from %d to %d" % (key, low, high), **{key: value})
    return value


def resolve_output(out):
    """Where `out` really lands, as a path under the run directory; a place outside it, the run directory itself or
    anything under inputs/ is refused, and in a job so is anything outside $OUT, the one place a job writes."""
    root = Path.cwd().resolve()
    try:
        dest = (root / out).resolve() if not Path(out).is_absolute() else Path(out).resolve()
    except (OSError, RuntimeError, ValueError) as exc:     # a symlink loop, a name too long, a lone surrogate
        fail("out_dir cannot be resolved: %s" % (exc.__class__.__name__ if not getattr(exc, "strerror", None) else exc.strerror), out_dir=scrub(str(out)))
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
    temp_hold(tmp)                   # registered before the file exists: whatever stops this, the half-written file is not left beside the receipt
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            fh = os.fdopen(fd, "w", encoding="utf-8")
        except BaseException:
            os.close(fd)
            raise
        with fh:
            json.dump(obj, fh, indent=2, ensure_ascii=True)
            fh.write("\n")
        temp_replace(tmp, path)
    except BaseException:
        temp_drop(tmp)
        raise


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


# ---- the media -------------------------------------------------------------------------------------------------------------------

PROGRESS = {"phase": "starting", "range": None, "partial": None, "done": 0, "bytes": 0, "dest": None}


class Media:
    """The bytes ranges are read from: one regular file, or the raw segments of a split set in order. One file is open at a time, opened without
    waiting and without following a link, and looked at on the descriptor."""

    def __init__(self, segments):
        self.segments = segments                      # [{"path", "start", "size"}]
        self.starts = [s["start"] for s in segments]
        self.size = sum(s["size"] for s in segments)
        self.fd = None
        self.index = None
        self.identity = {}

    def _open(self, index):
        if self.index == index:
            return
        self.close()
        seg = self.segments[index]
        fd = os.open(seg["path"], os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0))
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise OSError(errno.EINVAL, "is not a regular file (it changed after it was checked)")
            if st.st_size != seg["size"]:
                raise OSError(errno.EINVAL, "is not the size it had when it was checked")
            self.identity.setdefault(index, (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns))
        except BaseException:
            os.close(fd)
            raise
        self.fd, self.index = fd, index

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
        self.fd, self.index = None, None

    def read(self, position, count):
        """Up to `count` bytes at media position `position`, from the one segment that holds it (fewer at a segment's end; b'' at the end of the media)."""
        if position >= self.size or count <= 0:
            return b""
        index = bisect_right(self.starts, position) - 1
        seg = self.segments[index]
        self._open(index)
        within = position - seg["start"]
        return os.pread(self.fd, min(count, seg["size"] - within), within)

    def changed(self):
        """Indexes of the segments read whose file is no longer the one that was read."""
        bad = []
        for index, identity in self.identity.items():
            try:
                st = os.lstat(self.segments[index]["path"])
            except OSError:
                bad.append(index)
                continue
            if not stat.S_ISREG(st.st_mode) or (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns) != identity:
                bad.append(index)
        return bad


def refusal_of(path):
    try:
        st = os.lstat(path)
    except OSError as exc:
        return "cannot be examined: %s" % describe(exc)
    if stat.S_ISREG(st.st_mode):
        return None
    for test, what in ((stat.S_ISLNK, "a symbolic link"), (stat.S_ISDIR, "a directory"), (stat.S_ISFIFO, "a FIFO"), (stat.S_ISBLK, "a block device"),
                       (stat.S_ISCHR, "a character device"), (stat.S_ISSOCK, "a socket")):
        if test(st.st_mode):
            return "is %s, not a regular file: refused" % what
    return "is not a regular file: refused"


def whole_ranges(spec):
    """The ranges argument, checked: a list of {offset, length} (whole numbers, nothing else in them)."""
    if not isinstance(spec, list) or not 1 <= len(spec) <= RANGES_MAX:
        fail("ranges is a list of 1 to %d ranges, each {\"offset\": n, \"length\": n}" % RANGES_MAX)
    out = []
    for i, item in enumerate(spec):
        if not isinstance(item, dict) or set(item) != {"offset", "length"}:
            fail("range %d is {\"offset\": n, \"length\": n} and nothing else" % i)
        for key, high in (("offset", OFFSET_MAX), ("length", BYTES_CEILING)):
            v = item[key]
            if not isinstance(v, int) or isinstance(v, bool) or not 0 <= v <= high:
                fail("range %d: %s is a whole number from 0 to %d" % (i, key, high))
        out.append((item["offset"], item["length"]))
    return out


def overlaps(ranges):
    """The indexes of the ranges that overlap an earlier one in offset order: one pass over the ranges sorted by offset."""
    flagged, reach = set(), -1
    for index, (offset, length) in sorted(enumerate(ranges), key=lambda p: (p[1][0], p[0])):
        if length == 0:
            continue
        if offset < reach:
            flagged.add(index)
        reach = max(reach, offset + length)
    return flagged


def free_name(directory, stem, suffix):
    """stem+suffix, or stem.2+suffix ... : a name nothing in the directory has (checked with lstat; the file is then made with O_EXCL)."""
    k = 1
    while True:
        name = "%s%s" % (stem, suffix) if k == 1 else "%s.%d%s" % (stem, k, suffix)
        if not os.path.lexists(os.path.join(directory, name)):
            return name
        k += 1


# ---- main ---------------------------------------------------------------------------------------------------------------

def main():
    try:
        args = json.load(sys.stdin)
    except (ValueError, RecursionError) as exc:
        fail("arguments are not valid JSON", reason=str(exc)[:200])
    if not isinstance(args, dict):
        fail("arguments are a JSON object")
    unknown = sorted(set(args) - {"source", "descriptor", "descriptor_sha256", "verify_sources", "ranges", "out_dir", "max_total_bytes", "max_seconds", "limit"})
    if unknown:
        fail("unknown parameter: %s" % ", ".join(scrub(str(k)) for k in unknown))
    if (args.get("source") is None) == (args.get("descriptor") is None):
        fail("give source (a file) or descriptor (a layer descriptor), one of the two")
    ranges = whole_ranges(args.get("ranges"))
    max_total = whole(args, "max_total_bytes", MAX_TOTAL_DEFAULT, 0, BYTES_CEILING)
    max_seconds = whole(args, "max_seconds", MAX_SECONDS_DEFAULT, 1, MAX_SECONDS_CEILING)
    limit = whole(args, "limit", LIMIT_DEFAULT, 1, LIMIT_CEILING)
    verify = args.get("verify_sources")
    if verify is not None and not isinstance(verify, bool):
        fail("verify_sources is true or false")
    if args.get("source") is not None and (args.get("descriptor_sha256") is not None or verify is not None):
        fail("verify_sources and descriptor_sha256 belong with descriptor")
    deadline = STARTED + max_seconds

    description = None
    if args.get("source") is not None:
        source = args["source"]
        if not isinstance(source, str) or not source or "\0" in source:
            fail("source is a path (a non-empty string without a NUL)")
        try:
            source.encode("utf-8", "surrogateescape")
        except UnicodeEncodeError:
            fail("source holds a character that cannot be a byte of a file name")
        refusal = refusal_of(source)
        if refusal:
            fail("the source " + refusal, source=scrub(source))
        try:
            size = os.stat(source).st_size
        except OSError as exc:
            fail("the source cannot be read: %s" % describe(exc), source=scrub(source))
        media = Media([{"path": os.path.abspath(source), "start": 0, "size": size}])
        layer = "file"
    else:
        try:
            description = load_descriptor(args["descriptor"], args.get("descriptor_sha256"), verify is True, min(deadline, time.monotonic() + DESCRIPTOR_VERIFY_SECONDS))
        except DescriptorError as exc:
            fail(str(exc))
        layer = description["layer"]
        if layer not in ("raw", "split_raw"):
            fail("the descriptor's layer is %s: its bytes are not the media's, and a byte range of the decoded media needs a reader (img_cat) this tool does not use" % layer,
                 unsupported="descriptor layer " + layer)
        segments, start = [], 0
        for s in description["sources"]:
            segments.append({"path": s["path"], "start": start, "size": s["bytes"]})
            start += s["bytes"]
        media = Media(segments)

    os.umask(0o077)
    if args.get("out_dir"):
        if not isinstance(args["out_dir"], str) or "\0" in args["out_dir"]:
            fail("out_dir is a directory path")
        dest = resolve_output(args["out_dir"])
    elif in_job():
        dest = resolve_output(os.path.join(os.environ["OUT"], "byte_range_extract"))
    else:
        agent = re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool")
        dest = resolve_output(os.path.join("work", agent, "byte_range_extract"))
    try:
        if not args.get("out_dir") and dest.exists():
            k = 2
            while Path("%s.%d" % (dest, k)).exists():
                k += 1
            dest = Path("%s.%d" % (dest, k))
        if dest.exists() and not dest.is_dir():
            fail("out_dir exists and is not a directory", out_dir=scrub(str(dest)))
        made = not dest.exists()
        dest.mkdir(parents=True, exist_ok=True, mode=0o700)
        if made:
            os.chmod(dest, 0o700)
    except (OSError, ValueError, RuntimeError) as exc:
        fail("out_dir cannot be used: %s" % describe(exc), out_dir=scrub(str(args.get("out_dir") or dest)))
    PROGRESS["dest"] = scrub(str(dest))
    # An out_dir an earlier run used is not written over: this run's ranges.jsonl and receipt.json take the next free number (ranges.2.jsonl, receipt.2.json),
    # and a range file whose name is taken takes a new one (range-000001.2.bin); the name kept is in the row.
    run_no = 1
    while any(os.path.lexists(str(dest / name)) for name in (("ranges.jsonl", "receipt.json") if run_no == 1 else ("ranges.%d.jsonl" % run_no, "receipt.%d.json" % run_no))):
        run_no += 1
    rows_name = "ranges.jsonl" if run_no == 1 else "ranges.%d.jsonl" % run_no
    receipt_name = "receipt.json" if run_no == 1 else "receipt.%d.json" % run_no

    def last_word(signum):
        media.close()
        drop_temporaries()
        print(json.dumps({"ok": False, "tool": TOOL, "status": "partial", "interrupted": True, "signal": signum, "out_dir": PROGRESS["dest"],
                          "phase": PROGRESS["phase"], "ranges_done": PROGRESS["done"], "current_range": PROGRESS["range"], "current_range_file": PROGRESS["partial"],
                          "bytes_written": PROGRESS["bytes"],
                          "status_basis": "the tool was stopped by signal %d: the ranges before the current one are whole files, the current one stays under its .partial name "
                                          "(its size and sha256 are not claimed), and the ranges after it were not run" % signum}), flush=True)
    STOP["last_word"] = last_word

    # ---- the ranges
    overlapping = overlaps(ranges)
    rows, concat = [], hashlib.sha256()
    written_total, stopped_by, next_range, problems = 0, None, None, []
    rows_written, rows_error = 0, None
    rows_fh = None
    try:
        rows_fh = private_file(str(dest / rows_name))
    except OSError as exc:
        rows_error = "%s could not be made (%s)" % (rows_name, describe(exc))
    PROGRESS["phase"] = "copying the ranges"

    def row_out(row):
        nonlocal rows_written, rows_error, rows_fh
        rows.append(row)
        if rows_fh is not None:
            try:
                rows_fh.write(json.dumps(row, ensure_ascii=True) + "\n")
                rows_fh.flush()
                rows_written += 1
            except OSError as exc:
                rows_error = "%s could not be written whole (%s); %d of %d rows are in it" % (rows_name, describe(exc), rows_written, len(ranges))
                try:
                    rows_fh.close()
                except OSError:
                    pass
                rows_fh = None

    all_whole = True
    for n, (offset, length) in enumerate(ranges):
        row = {"n": n, "offset": offset, "requested": length, "actual": 0, "status": None, "file": None, "sha256": None, "overlaps_an_earlier_range": n in overlapping}
        PROGRESS["range"] = n
        if stopped_by:
            row["status"], row["why"] = "not_run", "an earlier stop: %s" % stopped_by
            all_whole = False
            row_out(row)
            continue
        if time.monotonic() > deadline:
            stopped_by, next_range = "max_seconds", n
            row["status"], row["why"] = "not_run", "the time budget (%d seconds) was used" % max_seconds
            all_whole = False
            row_out(row)
            continue
        if length > 0 and written_total >= max_total:
            stopped_by, next_range = "max_total_bytes", n
            row["status"], row["why"] = "not_run", "the byte budget (%d) was used" % max_total
            all_whole = False
            row_out(row)
            continue
        stem = "range-%06d" % (n + 1)
        final = free_name(str(dest), stem, ".bin")
        partial = final + ".partial"
        k = 1
        while os.path.lexists(os.path.join(str(dest), partial)):
            k += 1
            partial = "%s.partial.%d" % (final, k)
        PROGRESS["partial"] = partial
        try:
            out_fd = os.open(os.path.join(str(dest), partial), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except OSError as exc:
            row["status"], row["why"] = "failed", "its file could not be made: %s" % describe(exc)
            problems.append("range %d: %s" % (n, row["why"]))
            all_whole = False
            row_out(row)
            continue
        h = hashlib.sha256()
        position, remaining, actual, why = offset, length, 0, None
        try:
            with os.fdopen(out_fd, "wb") as out:
                while remaining > 0:
                    if time.monotonic() > deadline:
                        stopped_by, next_range, why = "max_seconds", n, "the time budget (%d seconds) ran out" % max_seconds
                        break
                    allowed = min(remaining, CHUNK, max_total - written_total)
                    if allowed <= 0:
                        stopped_by, next_range, why = "max_total_bytes", n, "the byte budget (%d) was reached" % max_total
                        break
                    data = media.read(position, allowed)
                    if not data:
                        why = "the source ends at byte %d" % media.size
                        break
                    out.write(data)
                    h.update(data)
                    concat.update(data)
                    position += len(data)
                    remaining -= len(data)
                    actual += len(data)
                    written_total += len(data)
                    PROGRESS["bytes"] = written_total
                out.flush()
        except OSError as exc:
            why = "a read or a write failed: %s" % describe(exc)
            problems.append("range %d: %s" % (n, why))
            row["status"] = "failed"
        row["actual"] = actual
        row["sha256"] = h.hexdigest() if actual >= SHORT_RANGE else None
        if actual < SHORT_RANGE:
            row["digest_not_written"] = "fewer than %d bytes: a short value can be reversed from its digest" % SHORT_RANGE
        if row["status"] is None:
            if actual == length and why is None:
                try:
                    os.link(os.path.join(str(dest), partial), os.path.join(str(dest), final))
                    os.unlink(os.path.join(str(dest), partial))
                    row["file"], row["status"] = final, "whole"
                except FileExistsError:
                    row["file"], row["status"], row["why"] = partial, "whole_but_not_renamed", "its final name was taken after it was chosen; the bytes are in the .partial file"
                    all_whole = False
                except OSError:
                    if not os.path.lexists(os.path.join(str(dest), final)):
                        os.rename(os.path.join(str(dest), partial), os.path.join(str(dest), final))
                        row["file"], row["status"] = final, "whole"
                    else:
                        row["file"], row["status"] = partial, "whole_but_not_renamed"
                        all_whole = False
            else:
                row["file"] = partial
                row["status"] = "cut" if stopped_by == "max_total_bytes" and next_range == n or stopped_by == "max_seconds" and next_range == n else "short"
                row["why"] = why or "the source ended before the range did"
                all_whole = False
        else:
            row["file"] = partial
            all_whole = False
        PROGRESS["done"] = n + 1
        PROGRESS["partial"] = None
        row_out(row)
    media.close()
    if rows_fh is not None:
        try:
            rows_fh.close()
        except OSError as exc:
            rows_error = rows_error or "%s could not be closed whole (%s)" % (rows_name, describe(exc))

    # ---- the sources are looked at again
    changed = media.changed()
    for index in changed:
        problems.append("source %d changed (size, modification time or file) while the ranges were copied" % index)
    whole_count = sum(1 for r in rows if r["status"] == "whole")
    if changed or (whole_count == 0 and not any(r["actual"] for r in rows) and ranges and all(r["status"] in ("failed", "not_run") for r in rows)):
        status = "failed"
    elif all_whole and not rows_error and not problems and rows_written == len(ranges):
        status = "complete"
    else:
        status = "partial"
    requested_total = sum(length for _o, length in ranges)
    if status == "complete":
        basis = "every range was copied whole (requested equals actual), none was cut or left unrun, every row is in the ranges file and the sources did not change"
    else:
        parts = []
        if stopped_by:
            parts.append("stopped by %s at range %s" % (stopped_by, next_range))
        shorts = [r["n"] for r in rows if r["status"] == "short"]
        if shorts:
            parts.append("%d range(s) are short (the source ended first): %s" % (len(shorts), ", ".join(str(i) for i in shorts[:10])))
        cut = [r["n"] for r in rows if r["status"] == "cut"]
        if cut:
            parts.append("range %s was cut and stays .partial" % ", ".join(str(i) for i in cut[:10]))
        parts += problems[:5]
        if rows_error:
            parts.append(rows_error)
        basis = "; ".join(parts) or "not every range was copied whole"
    concat_note = None
    if all_whole and status == "complete" and sum(r["actual"] for r in rows) >= SHORT_RANGE:
        concat_digest = concat.hexdigest()
    else:
        concat_digest = None
        concat_note = ("not written: it covers every range, in order, and is written only when every range is whole and they hold at least %d bytes" % SHORT_RANGE)
    answer = {
        "ok": status == "complete", "tool": TOOL, "status": status, "status_basis": scrub(basis), "complete": status == "complete",
        "source": {"kind": layer, "path": scrub(args["source"]) if args.get("source") is not None else None, "bytes": media.size,
                   "descriptor": ({"file": description["file"], "sha256": description["sha256"], "sources": len(description["sources"]), "sources_checked": description["checked"]}
                                  if description else None)},
        "ranges_total": len(ranges), "ranges_whole": whole_count, "requested_bytes": requested_total, "actual_bytes": sum(r["actual"] for r in rows),
        "stopped_by": stopped_by, "next_range": next_range,
        "ranges": rows[:limit], "ranges_shown": min(limit, len(rows)),
        "ranges_file": rows_name if rows_fh is not None or rows_written else None, "ranges_in_file": rows_written,
        "sha256_of_the_ranges_in_order": concat_digest, "sha256_of_the_ranges_note": concat_note,
        "out_dir": scrub(str(dest)),
        "note": "the bytes are evidence content and can hold credentials: run as a job with secret_output true when a range may; a byte range is not a file, and this answer says nothing about whether the bytes of a range are one",
        "python": sys.version.split()[0],
    }
    if rows_error:
        answer["rows_file_error"] = rows_error
    try:
        write_json_atomic(str(dest / receipt_name), answer)
        answer["receipt"] = receipt_name
    except OSError as exc:
        answer["receipt"] = None
        answer["receipt_error"] = "%s could not be written (%s)" % (receipt_name, describe(exc))
    say(answer, 0)


# BEGIN SHARED LEAVE
# The same text is in every pack tool and recipe and in their tool-library twins (tests/shared-blocks-census.test.ts holds the copies equal):
# how a call ends once its answer has begun. The interpreter's own teardown resets the signal handlers to their defaults before it frees what
# the call held, and a stop signal that landed there killed a process that had printed its whole answer; a handler that raises or writes a
# last word, run after the answer was out, wrote a second document or a traceback after a whole one. So, when the file runs as a program:
# * Standard output is wrapped, and its first write is the first byte of the answer: from there the stop signals are held for good (blocked
#   in this thread, and given a handler that does nothing for any other), so no handler runs into the answer or after it, and an error Python
#   can only report (a file the call left open whose last write the file system refuses, closed when the frame that held it is freed) is
#   not printed (Python 3.11 and 3.12 say nothing of it; 3.14 prints a traceback). A handler that was already due runs on the way in, before
#   any byte is written, and its own answer is then the one.
# * _code(stop) is a SystemExit's exit code, and _leave(code) ends the call: both hold the signals first; _leave then flushes standard output
#   and standard error, runs the atexit hooks (a hook that removes a temporary file), each step on its own and none able to raise, and ends
#   the process with os._exit, never through the teardown. A stop signal after the hold is not answered: the exit code is the call's own.
# The modules are imported here, as the file is loaded, never inside the ending (an import there ran a due handler inside the import system).
import atexit
import os
import signal
import sys

_ENDING = {"held": False}
_ENDING_SIGNALS = (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)


def _ending_nothing(*_ignored):
    """The stop signals' handler, and sys.unraisablehook, once the answer has begun: nothing."""


def hold_stop_signals():
    """Hold the stop signals for good. A handler that was due runs first, in the first call that can run it, and may raise: that is before
    any byte of the answer is written. Called by a thread that is not the main one, it blocks the signals there and leaves the rest to the
    main thread's next write."""
    if _ENDING["held"]:
        return
    try:
        signal.pthread_sigmask(signal.SIG_BLOCK, _ENDING_SIGNALS)
    except (AttributeError, ValueError, OSError):
        pass                          # no pthread_sigmask here: the handler below holds them
    main_thread = True
    for signum in _ENDING_SIGNALS:
        try:
            signal.signal(signum, _ending_nothing)
        except (ValueError, OSError):
            main_thread = False
    sys.unraisablehook = _ending_nothing
    _ENDING["held"] = main_thread


def _hold_at_the_end():
    for _attempt in range(len(_ENDING_SIGNALS) + 2):
        try:
            hold_stop_signals()
            return
        except BaseException:  # noqa: BLE001 - a handler that was due ran on the way in; the hold is made again
            continue


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
    _hold_at_the_end()
    code = getattr(stop, "code", 1)
    return code if isinstance(code, int) else (0 if code is None else 1)


def _leave(code):
    _hold_at_the_end()
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.flush()
        except BaseException:  # noqa: BLE001 - a reader that is gone, a stream that is closed: the exit code is the call's own
            pass
    try:
        atexit._run_exitfuncs()
    except BaseException:  # noqa: BLE001 - a hook that fails is not a failure of the answer
        pass
    code = code if isinstance(code, int) else 1
    os._exit(code)


if __name__ == "__main__" and sys.stdout is not None and not isinstance(sys.stdout, _AnswerStream):
    sys.stdout = _AnswerStream(sys.stdout)
# END SHARED LEAVE


if __name__ == "__main__":
    exit_code = 0
    try:
        main()
    except SystemExit as stop:
        exit_code = _code(stop)
    _leave(exit_code)
