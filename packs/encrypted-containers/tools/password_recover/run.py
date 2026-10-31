#!/usr/bin/env python3
"""Recover a password this pack has already located a lead for, with john, inside a sealed job only.

This tool is the pack's one route from "a protected file, or a hash someone already pulled from one" to
"the attempt is made and the result is counted": it runs the matching *2john helper (zip2john, 7z2john,
rar2john, pdf2john, office2john, bitlocker2john, luks2john) on a file the case contract has authorised
examining, or takes an existing hash file from another sealed job by reference, then runs john against it
with a candidate list the case supplies (a file path on disk, never a value on the command line or in the
answer), an optional rule set from a closed list, and a time budget.

Every file that could carry the password or the hash (the extracted hash, john's pot, session and log, and
john's own run output) is written only under $OUT, 0600, created before anything is read. The answer carries
the format, the helper and john's own versions, how many hash lines were extracted, how many candidate lines
were offered, how many were recovered, and the status: it carries no value, no hash, no salt and no length of
either. A recovered password lives only in john's pot file under $OUT; this tool reads that file itself, once,
to COUNT what john recovered (`john --show`, its own output redirected to a sealed file and never echoed), and
never reproduces a line of it.

This tool runs only inside a job the harness ran as secret output (SECRET_OUTPUT=1 in its process; the
manifest's secret_output: "required" makes every job of this tool one): outside that, it refuses before
reading anything else, including its own stdin.

    format        one of a closed list (see FORMATS below); inferred from source's extension when not given,
                  else required
    source        the protected file (evidence); skipped when hash_file is given
    hash_file     an existing hash file (another sealed job's output), used instead of running a helper
    candidates    a file of candidate passwords, one per line; never read by this tool for its content, only
                  counted and handed to john as --wordlist
    rules         one of a closed list (see RULES below), default "none" (no mangling)
    max_seconds   the tool's own time limit (below the manifest's timeout_seconds)

status: "complete" when john ran the whole candidate list (or stopped early because every hash was cracked);
"partial" when the time budget or an external stop cut it short; "failed" when the helper ran but wrote no
hash; "unsupported" when the format's helper is not on this host. Every answer carries status and status_basis.
"""
import errno
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path


# BEGIN SHARED STOP
# The same text is in recovery_key_scan, archive_probe and crypto_id (a pack test holds the copies equal). SIGTERM, SIGINT and SIGHUP end the
# tool with ONE JSON answer and the exit status 128 + the signal, with no traceback and no temporary file left. A tool that scans
# (cooperative) only notes the signal: the scan reads stop_wanted() between windows and files, finishes its pages and prints a partial
# answer. If it is not finished GRACE_SECONDS later (a read that never returns), or a second signal comes, the stop is hard: the cleanup
# steps run (a program the tool started is killed, a values file is closed), the temporary files of the pages are removed, the last word
# is printed and the process ends. The tool's own clock (set_deadline) is below the manifest's timeout and is backed by the same hard stop:
# GRACE_SECONDS after the deadline a read that has not returned (a file on a volume that is not there, a pipe nobody writes) no longer holds
# the tool. SIGALRM ends it when the read can be interrupted, and a watchdog thread, which needs neither a signal nor the read to return,
# ends it when not; either prints ONE JSON answer, status partial, and exits 0. A page fault in a mapped file can be ended by neither (it
# holds the interpreter): a tool that maps a file reads the part it maps through a descriptor first, where the thread can run.
import signal
import threading
import time

GRACE_SECONDS = 5
STOP = {"signal": None, "deadline": None, "limit": None, "last_word": None, "cooperative": False, "cleanup": [], "answered": False,
        "owner": None, "hard_due": None}
_STOP_LOCK = threading.RLock()
_STOP_DONE = threading.Event()


def set_deadline(seconds):
    STOP["limit"] = seconds
    STOP["deadline"] = time.monotonic() + seconds
    arm_hard_stop(seconds + GRACE_SECONDS)
    threading.Thread(target=_watchdog, name="hard-stop", daemon=True).start()


def arm_hard_stop(seconds):
    """The hard stop is due in `seconds` at the latest (an earlier one stays): as SIGALRM, and as the time the watchdog waits for."""
    due = time.perf_counter() + seconds
    if STOP["hard_due"] is None or due < STOP["hard_due"]:
        STOP["hard_due"] = due
    left = signal.getitimer(signal.ITIMER_REAL)[0]
    signal.setitimer(signal.ITIMER_REAL, seconds if left <= 0 else min(seconds, left))


def disarm_stop():
    """No hard stop is wanted any more (the answer is going out, or the tool ends with an error): the timer and the watchdog stand down."""
    STOP["hard_due"] = None
    _STOP_DONE.set()
    signal.setitimer(signal.ITIMER_REAL, 0)


def _watchdog():
    while not _STOP_DONE.wait(0.2):
        due = STOP["hard_due"]
        if due is not None and time.perf_counter() >= due:
            hard_stop(STOP["signal"])


def stand_by():
    """When another thread is ending the tool, wait for it to do so: nothing else may print."""
    if STOP["owner"] not in (None, threading.get_ident()):
        while True:
            time.sleep(3600)


def out_of_time():
    return STOP["deadline"] is not None and time.monotonic() > STOP["deadline"]


def stop_wanted():
    return STOP["signal"] is not None or out_of_time()


def stop_cause():
    if STOP["signal"] is not None:
        return "stopped by signal %d" % STOP["signal"]
    return "the time limit (max_seconds %s) was reached" % STOP["limit"]


def remove_pending_pages():
    """Remove the temporary file of every page that is still being written."""
    for page in list(globals().get("PAGES", [])):
        tmp = getattr(page, "_tmp", None)
        if tmp is not None:
            try:
                os.unlink(tmp)
            except OSError:
                pass


def hard_stop(signum):
    """End the tool now. `signum` is the signal that asked for it; None when the clock did: the answer is then partial and the exit status 0."""
    with _STOP_LOCK:
        if signum is None and STOP["answered"]:     # the answer is being written: let it be written
            STOP["hard_due"] = None
            return
        if STOP["owner"] in (None, threading.get_ident()):
            STOP["owner"] = threading.get_ident()
            mine = True
        else:
            mine = False
    if not mine:
        stand_by()
    for step in list(STOP["cleanup"]):
        try:
            step()
        except Exception:  # noqa: BLE001 - a cleanup step is best effort
            pass
    remove_pending_pages()
    if STOP["last_word"] and not STOP["answered"]:
        try:
            STOP["last_word"](signum)
        except Exception:  # noqa: BLE001
            pass
    os._exit(128 + signum if signum else 0)


def _on_stop_signal(signum, _frame):
    if STOP["cooperative"] and STOP["signal"] is None:
        STOP["signal"] = signum
        arm_hard_stop(GRACE_SECONDS)
        return
    hard_stop(STOP["signal"] or signum)


def _on_stop_alarm(_signum, _frame):
    hard_stop(STOP["signal"])


def install_stop(last_word=None, cooperative=False):
    STOP["last_word"], STOP["cooperative"] = last_word, cooperative
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, _on_stop_signal)
    signal.signal(signal.SIGALRM, _on_stop_alarm)


def interrupted_answer(signum, **extra):
    if signum is None:       # the clock ran out, and then GRACE_SECONDS more, with a read that had not returned
        print(json.dumps({"status": "partial", "partial": True, "interrupted": True, "hard_stopped": True,
                          "stopped_by": "the tool's time limit (%s seconds) was reached" % STOP["limit"],
                          "status_basis": "the tool's time limit (%s seconds) and %d seconds more passed while a read had not returned (a file on a "
                                          "volume or share that is not available, or a pipe); the tool was ended there, and nothing it had read is "
                                          "an answer" % (STOP["limit"], GRACE_SECONDS), **extra}), flush=True)
        return
    print(json.dumps({"error": "stopped by signal %d before the answer was complete" % signum, "status": "interrupted",
                      "status_basis": "the tool was stopped by signal %d; nothing it had read is an answer" % signum,
                      "signal": signum, **extra}), flush=True)


def claim_answer():
    """Take the one answer (an answer or an error): the stop is disarmed, the stop signals are held back, and `answered` is set under the
    lock, so that a watchdog that has read its due time but not yet taken the lock finds the answer claimed and prints nothing. When the
    stop was claimed first, wait for the thread that has it to end the tool."""
    disarm_stop()
    held = {signal.SIGTERM, signal.SIGINT, signal.SIGHUP, signal.SIGALRM}
    signal.pthread_sigmask(signal.SIG_BLOCK, held)
    with _STOP_LOCK:
        mine = STOP["owner"] in (None, threading.get_ident())
        if mine:
            STOP["answered"] = True
    if not mine:
        stand_by()


def emit(answer):
    """Print the answer once, with the stop signals held back until it is out, and leave with 128 + the signal if one was noted."""
    claim_answer()
    text = json.dumps(seal(answer), indent=2, ensure_ascii=True)
    sys.stdout.write(text + "\n")
    sys.stdout.flush()
    if STOP["signal"] is not None:
        os._exit(128 + STOP["signal"])


# The handlers are in as soon as the module has run as far as this block (a hard stop with the generic last word, until main() installs the
# tool's own): only the start of the interpreter and the compiling of the file come before it.
install_stop(lambda signum: interrupted_answer(signum))
# END SHARED STOP


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


# BEGIN SHARED NAMES
# The same text is in recovery_key_scan, archive_probe and crypto_id (a pack test holds the copies equal). It decides what a name,
# a path, a header string or a diagnostic from evidence may show. Layer 1 (shown, withhold) cuts out of a string the spans that are
# shaped like an identifier or a secret and puts a fixed placeholder where each was (no length, no fragment); layer 2 (seal) reads
# every string of what is about to be printed or paged once more, by rules of its own, and replaces a string the first layer let
# through that still looks like a secret.
#
# WITHHELD, by shape: a recovery password (eight groups of six digits, joined by none to three characters that are not letters or digits)
# in a path component, whole component, and across the components of a path (the separators of a path join its groups); a run of 10 or
# more digits; a run of 8 or more letters and digits that has a digit in it (System32 and a few such names of Windows are let through); a
# letters-only run of 8 or more that is not one word, a camel-case word or all capitals; groups of 4 to 6 characters joined by one `-`, `_`
# or `.` (3 or more digit-only groups, or 4 or more groups that each hold a digit or are all capitals), and four or more groups of exactly
# six digits joined by spaces; the value after password, secret, token, api key, credential, auth (`password=...`); user-info; and the
# token shapes of the shared WITHHOLDING block above (vendor prefixes, JWT, long hex, long mixed runs, base64 with `/`). A string is also
# judged after NFKC, with invisible characters taken out and with the Cyrillic and Greek letters that look like Latin ones read as Latin,
# and a hit there that the string as written does not show withholds the whole string.
# NOT WITHHELD, by design: an identifier of 7 characters or fewer, a lowercase-only random run (it reads as a word), a secret that does
# not look like one, an all-capital letters-only run of any length, groups of other sizes (three groups of 4 to 6 letters and digits are
# printed), a recovery password cut into pieces by anything else than the separators above, and anything in the data a tool reads rather
# than prints.
# BOUNDED: the token rule of the WITHHOLDING block re-reads the text in front of a `/` once for each flagged piece after it, so its time
# grows with the square of a long run of name characters. What that block is given is therefore bounded first (_unjudgeable): a string of
# more than MAX_JUDGED characters, as written or after NFKC, or one that holds a `/` and a run of name characters of more than MAX_RUN, is
# withheld whole and not judged. The block itself is repaired at its source in a change of its own, for every pack that copies it.
# Measured on random draws and on real directory trees: tests/pack-encrypted-containers-names.test.ts and the manifests give the rates.
import unicodedata

NAMES = {"strings": 0, "replaced": 0}      # printed strings in which something was withheld; strings the output check replaced
RECOVERY_NAME = "<recovery-password-shaped name withheld>"
ID_TEXT = "<identifier-shaped text withheld>"
SECRET_TEXT = "<secret-shaped text withheld>"
LONG_TEXT = "<text too long to judge withheld>"
CHECKED = "<withheld by the output check>"
MAX_JUDGED = 4096        # characters judged in one string (a name, a component, a header string); longer is withheld whole
MAX_RUN = 256            # the longest run of name characters judged in a string that holds a `/`
_NAME_RUN = re.compile(r"[A-Za-z0-9_+%-]+")
_RECOVERY_SHAPE = re.compile(r"[0-9]{6}(?:[^0-9A-Za-z]{0,3}[0-9]{6}){7}")      # no look-arounds: a digit glued to the first or last group hides nothing
_SIX_SPACED = re.compile(r"(?<![0-9])(?:[0-9]{6} ){3,}[0-9]{6}(?![0-9])")
_GROUP = re.compile(r"(?<![A-Za-z0-9])[A-Za-z0-9]{4,6}(?![A-Za-z0-9])")
_ALNUM_RUN = re.compile(r"[A-Za-z0-9]{8,}")
_KNOWN_RUNS = frozenset(("System32", "SysWOW64", "Wow6432Node", "Windows10", "Windows11", "Windows7", "Windows8", "Windows2000", "Windows2003"))
_WORD_TOKEN = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+")
_NAMED = re.compile(r"(?i)(?<![A-Za-z0-9])(?:pass(?:word|wd|phrase)?|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential|auth)"
                    r"[A-Za-z0-9_-]{0,16}[ \t]*[=:][ \t]*([^\s\"'&;,/\\<][^\s\"'&;,/\\]*)")
_CACHE = {}
_CACHE_BYTES = [0]


def _chains(text):
    """Spans of groups of 4 to 6 characters joined by one `-`, `_` or `.`: 3 or more digit-only groups, or 4 or more that each hold a digit or are all capitals."""
    chain = []
    for m in _GROUP.finditer(text):
        g = m.group()
        joins = any(c.isdigit() for c in g) or g.isupper()
        if chain and joins and m.start() == chain[-1][1] + 1 and text[chain[-1][1]] in "-_.":
            chain.append((m.start(), m.end(), g.isdigit()))
            continue
        yield from _close(chain)
        chain = [(m.start(), m.end(), g.isdigit())] if joins else []
    yield from _close(chain)


def _close(chain):
    if len(chain) >= 4 or (len(chain) >= 3 and all(c[2] for c in chain)):
        yield chain[0][0], chain[-1][1]


def _wordy(run, caps=1 << 30):
    """A letters-only run that reads as words: one lowercase word (22 letters at most), one all-capital run, or camel case: capitalised
    words and capital runs (acronyms), of which at most a quarter are shorter than 3 letters (one short part is let through in a two-part name whose second part has 5 letters or more: MyDocument)."""
    if run.islower():
        return len(run) <= 22
    if run.isupper():
        return len(run) <= caps
    tokens = _WORD_TOKEN.findall(run)
    return "".join(tokens) == run and all(len(t) <= 22 for t in tokens) and sum(1 for t in tokens if len(t) < 3) <= max(len(tokens) // 4, 1 if len(tokens) == 2 and len(tokens[1]) >= 5 else 0)


def _runs(text):
    for m in _ALNUM_RUN.finditer(text):
        t = m.group()
        if t in _KNOWN_RUNS:
            continue
        if t.isdigit():
            if len(t) >= 10:
                yield m.span()
        elif any(c.isdigit() for c in t) or not _wordy(t):
            yield m.span()


def _spans(text):
    """(start, end, secret) of what a string shows that is shaped like an identifier (secret False) or like a secret (True), merged."""
    found = []
    for m in _NAMED.finditer(text):
        found.append((m.start(1), m.end(1), True))
    for rx in (_USERINFO, _BARE_USERINFO):
        for m in rx.finditer(text):
            found.append((m.start(), m.end(), True))
    for m in _SIX_SPACED.finditer(text):
        found.append((m.start(), m.end(), False))
    for a, b in list(token_spans(text)) + list(_chains(text)) + list(_runs(text)):
        found.append((a, b, False))
    found.sort()
    merged = []
    for a, b, secret in found:
        if merged and a <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], b), merged[-1][2] or secret)
        else:
            merged.append((a, b, secret))
    return merged


# Cyrillic and Greek letters that are written like Latin ones: a pair is (the letter, the Latin letter it is read as).
_LOOKALIKE_PAIRS = ("\u0430a\u0441c\u0435e\u043eo\u0440p\u0445x\u0443y\u0456i\u0458j\u0455s\u0501d\u04bbh\u0410A\u0412B\u0415E\u041aK\u041cM\u041dH"
                    "\u041eO\u0420P\u0421C\u0422T\u0425X\u0406I\u0408J\u0405S\u0423Y\u0391A\u0392B\u0395E\u0396Z\u0397H\u0399I\u039aK\u039cM"
                    "\u039dN\u039fO\u03a1P\u03a4T\u03a5Y\u03a7X\u03bfo\u03bdv\u03b9i\u03c1p")
_LOOKALIKES = {ord(_LOOKALIKE_PAIRS[i]): _LOOKALIKE_PAIRS[i + 1] for i in range(0, len(_LOOKALIKE_PAIRS), 2)}


def _fold(text):
    if text.isascii():
        return text
    return unicodedata.normalize("NFKC", "".join(c for c in text if unicodedata.category(c) != "Cf")).translate(_LOOKALIKES)


def _unjudgeable(text):
    """A string the token rule of the WITHHOLDING block must not be given: too long, or a long run of name characters beside a `/`."""
    return len(text) > MAX_JUDGED or ("/" in text and any(len(run) > MAX_RUN for run in _NAME_RUN.findall(text)))


def _judge(text, whole):
    """(the text as it may be shown, whether anything was withheld). `whole`: a recovery-password shape withholds the whole string."""
    if len(text) < 6:
        return text, False
    if _unjudgeable(text):
        return LONG_TEXT, True
    key = (text, whole)
    if key in _CACHE:
        return _CACHE[key]
    folded = _fold(text)
    if folded is not text and _unjudgeable(folded):
        return _remember(key, (LONG_TEXT, True))
    hit = False
    if _RECOVERY_SHAPE.search(text) or _RECOVERY_SHAPE.search(folded):
        if whole:
            return _remember(key, (RECOVERY_NAME, True))
        text, hit = _RECOVERY_SHAPE.sub(RECOVERY_NAME, folded), True
        folded = text
    spans = _spans(text)
    if folded != text and sum(b - a for a, b, _s in _spans(folded)) > sum(b - a for a, b, _s in spans):
        return _remember(key, (ID_TEXT, True))
    if spans:
        parts, last = [], 0
        for a, b, secret in spans:
            parts.append(text[last:a])
            parts.append(SECRET_TEXT if secret else ID_TEXT)
            last = b
        parts.append(text[last:])
        text, hit = "".join(parts), True
    return _remember(key, (text, hit))


def _remember(key, out):
    # bounded by the number of strings and by their size: 100,000 strings of a few kilobytes each are not a cache
    if len(_CACHE) < 100000 and _CACHE_BYTES[0] < (16 << 20):
        _CACHE[key] = out
        _CACHE_BYTES[0] += len(key[0]) + len(out[0])
    return out


def withhold(text):
    """A string of evidence text (a header field, a diagnostic, a string from a header) as it may be printed."""
    if not isinstance(text, str):
        return text
    out, hit = _judge(text, False)
    if hit:
        NAMES["strings"] += 1
    return out


def shown(path, count=True):
    """A path or a member name as it may be printed: every component judged by itself, a separator kept."""
    if not isinstance(path, str):
        return path
    if len(path) > 2 * MAX_JUDGED:      # a path is judged piece by piece: a name of a few such pieces is not a name
        NAMES["strings"] += 1 if count else 0
        return LONG_TEXT
    hit = False
    # A recovery password cut at the separators of the path ("123456-123456/123456-..."): the separators of a path join its groups.
    for candidate in ((path,) if path.isascii() else (path, _fold(path))):
        cut = _RECOVERY_SHAPE.sub(lambda m: RECOVERY_NAME if ("/" in m.group() or "\\" in m.group()) else m.group(), candidate)
        if cut != candidate:
            path, hit = cut, True
            break
    pieces = re.split(r"([/\\])", path)
    for i in range(0, len(pieces), 2):
        pieces[i], one = _judge(pieces[i], True)
        hit = hit or one
    if hit and count:
        NAMES["strings"] += 1
    return "".join(pieces)


# Layer 2: written apart from the rules above, over everything that is written. A string it finds suspect is replaced whole.
_CHECK_QUICK = re.compile(r"(?i)[0-9]{6}|PRIVATE KEY|[A-Za-z0-9+_=-]{24}|[0-9a-f]{16}|//[^/?#\s@]+@|pass|pwd|secret|token|api[_-]?key|AKIA|ASIA|gh.?_|github_pat|xox|eyJ|sk-|AIza|glpat|npm_")
_CHECK_PREFIX = re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{12}|gh[pousr]_[A-Za-z0-9]{16}|github_pat_[A-Za-z0-9_]{16}|xox[abeprs]-[A-Za-z0-9]{8}|eyJ[A-Za-z0-9_-]{8}"
                           r"|sk-[A-Za-z0-9_-]{16}|AIza[0-9A-Za-z_-]{16}|glpat-[A-Za-z0-9_-]{12}|npm_[A-Za-z0-9]{16}")
_CHECK_DIGITS = re.compile(r"(?<![0-9])(?:[0-9]{6}[-_. ]?){8}(?![0-9])|[0-9]{6}(?:[-_. ][0-9]{6}){7}")
_CHECK_PEM = re.compile(r"-----BEGIN [A-Z ]{0,40}PRIVATE KEY|PRIVATE KEY-----")
_CHECK_RUN = re.compile(r"[A-Za-z0-9+_=-]{24,}")
_CHECK_HEX = re.compile(r"(?<![0-9A-Za-z])(?=[0-9]*[a-fA-F])(?=[a-fA-F]*[0-9])[0-9a-fA-F]{16,}(?![0-9A-Za-z])")     # 16 or more hex digits, letters and digits both
_CHECK_USERINFO = re.compile(r"(?<=//)[^/?#\s@]{1,128}@")
_CHECK_VALUE = re.compile(r"(?i)(?:pass(?:word|wd|phrase)?|pwd|secret|token|api[_-]?key)[A-Za-z0-9_-]{0,16}[ \t]*[=:][ \t]*[^\s\"'<>]{6,}")
OWN_KEYS = {"all_results", "values_file", "paths_note"}      # strings the tool made itself


_UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")


def _suspect(text):
    if not text.isascii():      # full-width and invisible forms are read as the text they imitate
        text = unicodedata.normalize("NFKC", "".join(c for c in text if unicodedata.category(c) != "Cf"))
    if not _CHECK_QUICK.search(text) or _UUID.fullmatch(text):
        return False
    if _CHECK_DIGITS.search(text) or _CHECK_PEM.search(text) or _CHECK_VALUE.search(text) or _CHECK_PREFIX.search(text) \
            or _CHECK_HEX.search(text) or _CHECK_USERINFO.search(text):
        return True
    for m in _CHECK_RUN.finditer(text):
        run = m.group()
        if re.fullmatch(r"[0-9a-fA-F]{32,}", run):
            return True
        flips = sum(1 for a, b in zip(run, run[1:]) if a.isdigit() != b.isdigit() and a.isalnum() and b.isalnum())
        if flips >= 6:
            return True
    return False


def seal(value, key=None):
    """The value with every string the check finds suspect replaced (a dict's keys too). Counted in NAMES['replaced']."""
    if isinstance(value, str):
        if key in OWN_KEYS or len(value) < 8 or not _suspect(value):
            return value
        NAMES["replaced"] += 1
        return CHECKED
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if isinstance(k, str) and len(k) >= 8 and _suspect(k):
                NAMES["replaced"] += 1
                k = CHECKED + "#%d" % NAMES["replaced"]
            out[k] = seal(v, k)
        return out
    if isinstance(value, (list, tuple)):
        return [seal(v, key) for v in value]
    return value
# END SHARED NAMES

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
# seconds, and a sandbox that denies both libproc and ps (macOS). A stop signal is the one case that reaches further: it also
# ends everything below the tool itself (a program that was forked a moment before it was entered in ACTIVE is among it) and what
# the tool started and lost (reap_orphans): a process that was seen below the tool, in the tool's own group, and whose parent has since
# ended. Nothing else is ever ended: a process the tool never saw in its tree (the next stage of a pipeline the tool heads, a process a
# launcher put in the group) is left alone, whoever leads the group. A program that has ended while something it started still
# holds its pipes does not hold the tool: communicate_bounded gives the pipes PIPE_GRACE seconds and goes on without them.
import time

try:
    import ctypes
except ImportError:  # pragma: no cover
    ctypes = None

STATE = {"last_word": None}    # what to do, with the signal number, when the tool is stopped by a signal
ACTIVE = []                    # the programs running now
SEEN = set()                   # the pids seen below a program this tool started: the only ones reap_orphans may end once their parent is gone

def _die_with_parent():  # runs in the child between fork and exec
    try:
        ctypes.CDLL(None).prctl(1, signal.SIGKILL)   # PR_SET_PDEATHSIG
    except Exception:  # noqa: BLE001
        pass


def spawn(argv, **kwargs):
    kwargs.setdefault("stdin", subprocess.DEVNULL)
    if sys.platform.startswith("linux") and ctypes is not None:
        kwargs["preexec_fn"] = _die_with_parent
    proc = subprocess.Popen(argv, **kwargs)
    SEEN.add(proc.pid)
    return proc


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


def _libproc_works(pid):
    """Whether an empty libproc answer for `pid` can be believed: libproc has just listed `pid` as this tool's own child, or, when `pid`
    is the tool itself, has just listed the tool as its parent's child. A library that lists nothing for a live process is not working
    (as in a sandbox that denies it)."""
    if pid in (_children_libproc(os.getpid()) or []):
        return True
    return pid == os.getpid() and os.getpid() in (_children_libproc(os.getppid()) or [])


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
            if first is not None and _libproc_works(pid):
                return []
            out = subprocess.run(["ps", "-A", "-o", "pid=,ppid="], capture_output=True, text=True, timeout=PS_WAIT).stdout
            for line in out.splitlines():
                parts = line.split()
                if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
                    kids.setdefault(int(parts[1]), []).append(int(parts[0]))
    except (OSError, subprocess.SubprocessError):
        return []
    return _below(kids, pid)


def _process_table():
    """{pid: (parent pid, process group)} for every process, from /proc where there is one, else from ps (given PS_WAIT seconds);
    None when neither answers."""
    table = {}
    try:
        if os.path.isdir("/proc/self"):
            for entry in os.listdir("/proc"):
                if entry.isdigit():
                    try:
                        with open("/proc/%s/stat" % entry, "rb") as fh:
                            fields = fh.read().rsplit(b")", 1)[1].split()
                        table[int(entry)] = (int(fields[1]), int(fields[2]))
                    except (OSError, IndexError, ValueError):
                        continue
        else:
            out = subprocess.run(["ps", "-A", "-o", "pid=,ppid=,pgid="], capture_output=True, text=True, timeout=PS_WAIT).stdout
            for line in out.splitlines():
                parts = line.split()
                if len(parts) == 3 and all(part.isdigit() for part in parts):
                    table[int(parts[0])] = (int(parts[1]), int(parts[2]))
    except (OSError, subprocess.SubprocessError):
        return None
    return table


def _sample(pid):
    """Remember what is below `pid` now, by the cheap routes only (/proc, or libproc on macOS; never a program): a process that is seen
    here and later loses its parent is the tool's to end, and one that was never seen is not."""
    try:
        if os.path.isdir("/proc/self"):
            kids = {}
            for child, (parent, _group) in (_process_table() or {}).items():
                kids.setdefault(parent, []).append(child)
            SEEN.update(_below(kids, pid))
        else:
            seen, stack = {pid}, [pid]
            while stack:
                for child in _children_libproc(stack.pop()) or []:
                    if child not in seen:
                        seen.add(child)
                        stack.append(child)
            SEEN.update(seen - {pid})
    except Exception:  # noqa: BLE001 - a sample is best effort
        pass


def _pipe_inodes(proc):
    """The inodes of the pipes the tool holds with `proc` (Linux: /proc names a pipe by it; elsewhere the answer is not used)."""
    found = set()
    for handle in (proc.stdin, proc.stdout, proc.stderr):
        try:
            if handle is not None:
                found.add(os.fstat(handle.fileno()).st_ino)
        except (OSError, ValueError):
            pass
    return found


def _holds_pipe(pid, inodes):
    """Whether `pid` holds one of the pipes (Linux only, from /proc/<pid>/fd): the pipes are private to the tool and what it started."""
    try:
        for name in os.listdir("/proc/%d/fd" % pid):
            try:
                link = os.readlink("/proc/%d/fd/%s" % (pid, name))
            except OSError:
                continue
            if link.startswith("pipe:[") and link.endswith("]") and int(link[6:-1]) in inodes:
                return True
    except (OSError, ValueError):
        pass
    return False


def reap_orphans(inodes=None):
    """Kill what this tool started and lost: a process of the tool's own group that is no longer below the tool (its parent ended and
    init adopted it, so the walk from a program's pid cannot find it) and that the tool knows to be its own: it was seen below the tool
    (SEEN: the programs it started, the trees it listed, the samples taken while it waited), or, on Linux, it holds one of `inodes`,
    the pipes the tool made. A process the tool never saw in its tree is not touched, whoever leads the group: the next stage of a
    pipeline the tool heads, or a process a launcher put in the group, is not the tool's. A process outside the group is never looked
    at, and a pid is checked against the group again at the moment it is signalled. Returns the pids signalled."""
    me = os.getpid()
    try:
        if os.getpgrp() != me:
            return []
    except OSError:
        return []
    table = _process_table()
    if not table:
        return []
    kids = {}
    for pid, (parent, _group) in table.items():
        kids.setdefault(parent, []).append(pid)
    below = set(_below(kids, me))
    on_linux = os.path.isdir("/proc/self")
    killed = []
    for pid, (_parent, group) in table.items():
        if group != me or pid == me or pid in below:
            continue
        if pid not in SEEN and not (inodes and on_linux and _holds_pipe(pid, inodes)):
            continue
        try:
            if os.getpgid(pid) != me:
                continue
            os.kill(pid, signal.SIGKILL)
            killed.append(pid)
        except OSError:
            pass
    return killed


def kill_tree(proc):
    """Kill the program and everything it started. The children are listed first: once the parent is gone they are
    adopted by init and can no longer be found below it. A program already waited for is not touched: its pid is free to
    be another process's, and the walk below it would be that process's children."""
    if proc.poll() is not None:
        return
    try:
        proc.send_signal(signal.SIGSTOP)    # a program that is stopped forks nothing more while its tree is listed
    except OSError:
        pass
    try:
        victims = descendants(proc.pid)
        SEEN.update(victims)
    finally:
        try:
            proc.kill()
        except OSError:
            pass
    for pid in victims:
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass


PIPE_GRACE = 1.0    # seconds the pipes of a program that has ended are given to reach end of file


def communicate_bounded(proc, seconds, input=None):
    """(stdout bytes, stderr bytes, timed out) for a program started with pipes, in bytes. At `seconds` the program and what it started
    are killed (timed out). A program that has ended while something it started still holds its pipes (a daemon, a helper that
    inherited them) does not hold the tool: the pipes are given PIPE_GRACE seconds, what the program wrote is kept, what the tool
    lost is killed (reap_orphans), and the pipes are let go. The pipes are read here and by nothing else, so letting them go is safe."""
    deadline = time.monotonic() + max(0.1, seconds)
    out = err = b""
    started, timed_out = False, False
    while proc.poll() is None:
        now = time.monotonic()
        if now >= deadline:
            timed_out = True
            kill_tree(proc)
            break
        _sample(proc.pid)
        try:
            out, err = proc.communicate(None if started else input, timeout=max(0.01, min(0.2, deadline - now)))
            return out or b"", err or b"", False
        except subprocess.TimeoutExpired as exc:
            started = True
            out, err = exc.stdout or b"", exc.stderr or b""
    try:
        out, err = proc.communicate(None if started else input, timeout=PIPE_GRACE)
    except subprocess.TimeoutExpired as exc:
        out, err = exc.stdout or b"", exc.stderr or b""
        reap_orphans(_pipe_inodes(proc))
        for pipe in (proc.stdin, proc.stdout, proc.stderr):
            try:
                if pipe is not None:
                    pipe.close()
            except (OSError, ValueError):
                pass
    try:
        proc.wait(timeout=PIPE_GRACE)
    except subprocess.TimeoutExpired:
        pass
    return out or b"", err or b"", timed_out


def kill_all():
    """End every program the tool has running, with what each started. Then everything below the tool itself, which is the tool's own: a
    program forked a moment before it was entered in ACTIVE is among it. Then what an earlier program started and lost (reap_orphans)."""
    for proc in list(ACTIVE):
        kill_tree(proc)
    below = descendants(os.getpid())
    SEEN.update(below)
    for pid in below:
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass
    reap_orphans()


def _on_signal(signum, _frame):
    for other in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(other, signal.SIG_IGN)     # the first signal counts: a second one starts no second answer
    kill_all()
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
        out, err, timed_out = communicate_bounded(proc, max(1.0, seconds))
        return (None if timed_out else proc.returncode), out, err, timed_out
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
PARSER = "password_recover/1"
DEFAULT_SECONDS = 420          # the manifest allows 600; the tool stops at this and still answers
MAX_SECONDS = 540
PREFLIGHT_SECONDS = 10         # a --version probe is bounded short of the whole budget

# A format john can be given a hash for, and the *2john helper that makes one. Closed: a format not
# here is "unsupported", named as such in the answer, never guessed from a byte sniff this tool has
# not actually read.
HELPERS = {
    "zip": "zip2john",
    "7z": "7z2john",
    "rar": "rar2john",
    "pdf": "pdf2john",
    "office": "office2john",
    "bitlocker": "bitlocker2john",
    "luks": "luks2john",
}
FORMATS = tuple(sorted(HELPERS))
EXTENSION_FORMAT = {
    ".zip": "zip", ".7z": "7z", ".rar": "rar", ".pdf": "pdf",
    ".doc": "office", ".docx": "office", ".dot": "office", ".dotx": "office",
    ".xls": "office", ".xlsx": "office", ".xlsm": "office",
    ".ppt": "office", ".pptx": "office",
    ".bek": "bitlocker",
}
# A rule set john is given by name, never a mask, a mode or an inline mangling rule of this tool's own
# devising: "none" omits --rules (the candidate list is tried as written, once each).
RULES = ("none", "wordlist", "best64", "single")
RULE_NAMES = {"wordlist": "Wordlist", "best64": "best64", "single": "Single"}

REFUSED_NOT_SECRET = (
    "password_recover is refused outside a job run as secret output: the hash, the candidate list and "
    "whatever john recovers must be sealed, never ordinary output. Run this as job_run(tool: "
    "\"password_recover\", args: {...}); the manifest's secret_output: \"required\" makes every job of "
    "this tool one, and the harness then sets SECRET_OUTPUT=1 for the job's process, which this process "
    "does not have. Nothing was read."
)

STATE = {"job_out": None}


def refuse_unless_secret_job():
    """The one check this tool makes before reading anything else, stdin included: refused as JSON when the
    call is not a job (JOB_ID/OUT unset) or the job was not run as secret output (SECRET_OUTPUT=1)."""
    job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
    if not (job and out) or os.environ.get("SECRET_OUTPUT") != "1":
        claim_answer()
        print(json.dumps({"error": REFUSED_NOT_SECRET, "status": "failed",
                          "status_basis": "the call was refused before anything was read: not a secret_output job"}))
        raise SystemExit(1)
    STATE["job_out"] = out


def last_word(signum):
    interrupted_answer(signum)


def kill_active():
    kill_all()


def fail(message, **extra):
    claim_answer()
    print(json.dumps(seal({"error": message, "status": "failed",
                           "status_basis": "the tool stopped with an error (see error); nothing was recovered or the attempt was abandoned",
                           **extra})))
    raise SystemExit(1)


def describe(exc):
    code = errno.errorcode.get(exc.errno, "") if getattr(exc, "errno", None) else ""
    return withhold("%s%s: %s" % (type(exc).__name__, " " + code if code else "", getattr(exc, "strerror", None) or str(exc)))


def sealed_path(out_dir, name):
    """Create `name` under $OUT, 0600, refusing a file or link already there by name (O_EXCL, no symlink
    followed): the same create-before-read discipline every secret-output file in this pack uses."""
    path = Path(out_dir) / name
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    os.close(fd)
    return path


def count_lines(path, cap=10_000_000):
    """How many non-blank lines a file holds, read in chunks and never held whole or echoed; a count is not a
    value. Stops counting past `cap` lines (a candidate list or a hash file is not read for mischief)."""
    n = 0
    with open(path, "rb") as fh:
        for line in fh:
            if line.strip():
                n += 1
                if n >= cap:
                    break
    return n


def program_version(path, seconds):
    """The first line of `path --version`, bounded and never fed stdin a real argument that could be mistaken
    for a file; "" when the program does not answer that way (most *2john helpers do not)."""
    code, out, _err, timed_out = preflight([path, "--version"], seconds)
    if timed_out or code not in (0, None):
        return ""
    text = out.decode("utf-8", "replace").strip().splitlines()
    return text[0].strip() if text else ""


def run_recover(john, helper, helper_name, fmt, source, hash_file, candidates, rule_name, deadline, out_dir):
    """The one attempt: a helper (unless `hash_file` was given) then john, each bounded by what is left of
    `deadline`. Returns the answer's variable fields; raises nothing a caller must catch, only sets them."""
    # Nothing a helper or john writes without being told where (a default ~/.john/, a helper's own scratch file) may
    # land in the real HOME: this process's own HOME is moved under $OUT first, and every program spawned below
    # inherits it, since none of them is given its own environment.
    home = Path(out_dir) / "password_recover-home"
    home.mkdir(parents=True, exist_ok=True)
    os.environ["HOME"] = str(home)
    versions = {"john": program_version(john, PREFLIGHT_SECONDS) or "not reported by this build",
                "helper": (program_version(helper, PREFLIGHT_SECONDS) or "bundled with the pinned john build") if helper else None}

    if hash_file is not None:
        hash_path, hash_shown = hash_file, shown(hash_file)
    else:
        hash_path = sealed_path(out_dir, "password_recover-hash.txt")
        hash_shown = "store/jobs/%s/out/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ["JOB_ID"]), hash_path.name)
        helper_err = sealed_path(out_dir, "password_recover-helper-stderr.txt")
        code, timed_out = run_to_files([helper, source], str(hash_path), str(helper_err),
                                       max(1.0, deadline - time.monotonic()))
        if timed_out:
            return {"status": "partial", "status_basis": "the time budget was spent running %s; no hash was extracted yet" % helper_name,
                    "versions": versions, "hash_file": hash_shown, "hash_count": 0, "candidate_count": None, "recovered": 0}
        if code != 0 or hash_path.stat().st_size == 0:
            return {"status": "failed", "status_basis": "%s exited %s and wrote no hash to %s" % (helper_name, code, hash_shown),
                    "versions": versions, "hash_file": hash_shown, "hash_count": 0, "candidate_count": None, "recovered": 0}

    hash_count = count_lines(hash_path)
    candidate_count = count_lines(candidates)

    pot_path = sealed_path(out_dir, "password_recover-john.pot")
    john_log = sealed_path(out_dir, "password_recover-john-stdout.txt")
    john_err = sealed_path(out_dir, "password_recover-john-stderr.txt")
    session_path = Path(out_dir) / "password_recover-john-session"
    argv = [john, "--wordlist=%s" % candidates, "--pot=%s" % pot_path, "--session=%s" % session_path]
    if rule_name != "none":
        argv.append("--rules=%s" % RULE_NAMES[rule_name])
    argv.append(str(hash_path))
    code, timed_out = run_to_files(argv, str(john_log), str(john_err), max(1.0, deadline - time.monotonic()),
                                   cwd=None)
    show_log = sealed_path(out_dir, "password_recover-john-show.txt")
    show_err = sealed_path(out_dir, "password_recover-john-show-err.txt")
    run_to_files([john, "--show", "--pot=%s" % pot_path, str(hash_path)], str(show_log), str(show_err),
                 max(1.0, PREFLIGHT_SECONDS))
    recovered = 0
    try:
        text = show_log.read_text("utf-8", "replace")
    except OSError:
        text = ""
    m = re.search(r"(\d+)\s+password hash(?:es)? cracked", text)
    if m:
        recovered = int(m.group(1))

    if timed_out:
        status, basis = "partial", "the time budget (%s) was reached before every candidate was tried" % DEFAULT_SECONDS
    elif code not in (0, None):
        status, basis = "partial", "john exited %s before finishing; what it tried is in the sealed pot file" % code
    else:
        status, basis = "complete", "john tried every candidate line (or stopped once every hash was recovered)"
    return {"status": status, "status_basis": basis, "versions": versions, "hash_file": hash_shown,
            "hash_count": hash_count, "candidate_count": candidate_count, "recovered": recovered,
            "pot_file": "store/jobs/%s/out/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ["JOB_ID"]), pot_path.name)}


def main():
    install_stop(last_word, cooperative=False)
    STOP["cleanup"].append(kill_active)
    refuse_unless_secret_job()
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=withhold(str(exc)))
    if not isinstance(args, dict):
        fail("arguments must be a JSON object")

    out_dir = os.environ["OUT"]
    os.umask(0o077)

    source, hash_file = args.get("source"), args.get("hash_file")
    if bool(source) == bool(hash_file):
        fail("give exactly one of source (a protected file) or hash_file (an existing hash from another sealed job)")
    fmt = args.get("format")
    if fmt is not None and fmt not in FORMATS:
        fail("format must be one of %s" % ", ".join(FORMATS), format=fmt)
    if source is not None:
        if not isinstance(source, str) or not os.path.isfile(source):
            fail("source must name a file", source=shown(source) if isinstance(source, str) else None)
        if os.path.islink(source):
            fail("source is a symbolic link: name the file it resolves to", source=shown(source))
        if fmt is None:
            fmt = EXTENSION_FORMAT.get(os.path.splitext(source)[1].lower())
            if fmt is None:
                fail("format is required: source's extension does not name one of %s" % ", ".join(FORMATS), source=shown(source))
    else:
        if not isinstance(hash_file, str) or not os.path.isfile(hash_file):
            fail("hash_file must name a file", hash_file=shown(hash_file) if isinstance(hash_file, str) else None)
        if os.path.islink(hash_file):
            fail("hash_file is a symbolic link: name the file it resolves to", hash_file=shown(hash_file))

    candidates = args.get("candidates")
    if not isinstance(candidates, str) or not candidates:
        fail("candidates is required: a file of one candidate per line (a path, never values inline)")
    if not os.path.isfile(candidates):
        fail("candidates must name a file", candidates=shown(candidates))

    rule_name = args.get("rules", "none")
    if rule_name not in RULES:
        fail("rules must be one of %s" % ", ".join(RULES), rules=rule_name)

    seconds = args.get("max_seconds", DEFAULT_SECONDS)
    if not isinstance(seconds, int) or isinstance(seconds, bool) or not 1 <= seconds <= MAX_SECONDS:
        fail("max_seconds must be an integer from 1 to %d (the tool's own time limit; the manifest allows 600)" % MAX_SECONDS)
    set_deadline(seconds)
    deadline = time.monotonic() + seconds

    john = shutil.which("john")
    if not john:
        fail("john is not on PATH")

    helper_name = HELPERS.get(fmt) if hash_file is None else None
    helper = shutil.which(helper_name) if helper_name else None
    if hash_file is None and helper is None:
        emit(seal({"status": "unsupported", "status_basis": "%s is not on PATH: %s is declared but this host's build does not carry it" % (helper_name, fmt),
                  "format": fmt, "parser": PARSER}))
        return

    result = run_recover(john, helper, helper_name, fmt, source, hash_file, candidates, rule_name, deadline, out_dir)
    answer = {"parser": PARSER, "format": fmt, **result,
              "note": "A recovered password lives only in the sealed pot file named above (store/jobs/<job>/out/...), mode 0600. "
                      "This answer carries no value, no hash, no salt and no length of either. Report in the ledger WHERE the "
                      "candidate list and the authority to try it came from, and hand any recovered value to the operator "
                      "through the channel the case contract names."}
    emit(seal(answer))


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:  # never an empty or clean answer for a failure
        fail("unexpected failure: " + describe(exc) if isinstance(exc, OSError) else "unexpected failure: %s: %s" % (type(exc).__name__, withhold(str(exc))))
