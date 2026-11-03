#!/usr/bin/env python3
"""Copy declared byte ranges of a file, or of a split raw image through its descriptor, to new files, bounded, with a digest of each.

Input is a regular file (`source`) or a layer descriptor (`descriptor`, from layer_describe; a range may then cross the boundary of two
segments of a raw split set) and a list of ranges, each an `offset` and a `length` in bytes. What it does, exactly:

  * Each source file is opened without waiting and without following a link and must be a regular file; a link, FIFO, directory or device
    is refused. Only a raw file or a raw split set is read: the decoded media of an E01, VMDK or QCOW is not these bytes, and a descriptor
    with such a layer is refused as unsupported. Its sources are looked at again at the end, and a source that changed makes the run a failure.
  * Every range is written to a file of its own in a new directory, created with O_EXCL and O_NOFOLLOW, mode 0600 in a 0700 directory, as
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

TOOL = {"name": "byte_range_extract", "version": 1}
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
try:                                    # seconds to wait after each block: a hook for the tests, which need a copy that lasts long enough to be stopped
    PACE = min(max(float(os.environ.get("TOOL_TEST_BLOCK_SLEEP") or 0), 0.0), 1.0)
except ValueError:
    PACE = 0.0


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
TEXT_LIMIT = 65536


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
                    if PACE:
                        time.sleep(PACE)
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


if __name__ == "__main__":
    main()
