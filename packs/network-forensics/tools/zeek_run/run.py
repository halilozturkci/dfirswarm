#!/usr/bin/env python3
"""Run Zeek over a capture and read its logs back as records, saying what each log holds and what it does not.

What is written, and what is recorded about it:

  * The Zeek version (`zeek --version`, as printed), the command, whether checksums were validated, and the policy
    script. By default the tool writes network-forensics.local.zeek into out_dir, loading
    policy/frameworks/files/hash-all-files, and records its path and SHA-256 (`policies` changes the list; an empty
    list loads nothing). Whether Zeek would hash files without that script is not assumed, and whether the named
    policy exists in the installed build is not either: a build that lacks it fails, and the failure is reported.
    A policy is a name Zeek resolves from its own script path: a path, a name that climbs out of it, or anything
    under inputs/ is refused, because a script from the evidence would be code the evidence supplied.
  * `-C` (ignore checksums) is Zeek's setting for captures taken on an offloading interface, where valid packets
    show bad checksums. checksum_validation: false (the default) passes -C and says so; true leaves checksums on.
  * Every log Zeek wrote stays whole in out_dir, private (mode 0700, files 0600), and is named. Inline records are
    bounded by `limit`; the count of what was not returned is given with the file that holds all of it.
  * The log reader follows the log's own header: #separator, #set_separator, #empty_field, #unset_field, #fields and
    #types, \\xNN escapes, set and vector values as lists, count/int/port as integers, double/interval as numbers,
    bool as T or F, and every `time` field with its raw text kept and a decoded `<name>_utc` beside it. JSON logs
    are read too. A record that does not fit its header (a wrong column count, a value that is not its declared
    type, a line that is not a JSON object, a log with no header) is counted with its line number and byte offset,
    its raw line is kept in malformed-<log>.jsonl, and ok is false: it is never dropped.
  * A log's name is the engine's, not the capture's: it comes from Zeek's scripts and from the policies this tool loads. A name shaped like a token or
    carrying user-info (only a hostile policy makes one) is shown as withheld-NNNNNN everywhere the answer names a log (the keys of `logs`, `file`,
    malformed-<log>.jsonl, the lists of logs), the log is renamed to that on disk, and the real name is kept in zeek-log-names.jsonl in out_dir (mode 0600,
    named in the answer as log_names_file), written at the moment of the rename. Every other name is printed as Zeek wrote it.
  * Requested logs Zeek did not write (logs_requested_not_written) are kept apart from logs it wrote with no
    records (logs_empty). reporter.log, weird.log and capture_loss.log are summarised every time, whatever `logs`
    asks for: they are where an engine says it did not understand the input or lost packets.
  * files.log: hashes_produced says whether any record has a value in a hash column. hash_fields names the hash
    columns the log has, which on a real install can exist whether or not an analyzer filled them, so it is not
    the signal; which hash functions a policy computes is a property of the build. An object shorter than 128 bytes
    has its hash left out of the inline records.
  * Zeek runs in this tool's own process group, not a session of its own: the harness ends a tool by killing its
    group, and an engine outside it would go on writing into the output directory. SIGTERM, SIGINT and SIGHUP kill
    Zeek and what it started. timeout_seconds is held under the manifest's 1200 seconds (at most 1100) for the
    same reason.

SENSITIVE OUTPUT. Zeek logs can carry credentials, cookies, community strings and request URIs (http, ftp, smtp,
ntlm, snmp, rdp and others, depending on the scripts loaded). The directory is private and the answer says to run
the tool as a job with secret_output: true. In the INLINE records a field named like a secret (password, cookie,
community, token ...) is withheld and so is the argument of an FTP PASS; a URL field loses its user-info,
token-shaped path text and query values; and every other string, in any field and in any list, is scrubbed (a
token-shaped run, a key, a JWT, user-info, a Basic or Bearer credential is withheld) except the fields that are
identifiers, hashes, fingerprints, addresses or times. That is by shape: a short secret in free text is not
recognised. Zeek's own log files are kept whole: they are the evidence, and they are in the sealed directory.
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

TOOL = {"name": "zeek_run", "version": 20}
PARSER = "zeek_run/5"


def _before_start(signum, _frame):
    """A stop that arrives while the rest of this file is still loading (the other imports, the compile of what follows): the first signal
    counts, nothing was read, started or written, and the one answer says so. main() installs the tool's own handlers and replaces this one.
    What no script can answer is a stop that arrives before the interpreter has run these first lines (its own start-up)."""
    for other in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(other, signal.SIG_IGN)
    try:
        sys.stdout.write(json.dumps({"tool": TOOL, "parser": PARSER, "status": "partial", "ok": False, "stage": "starting",
                                     "status_basis": "stopped by signal %d before any work: nothing was read, started or written" % signum,
                                     "interrupted_by_signal": signum}) + "\n")
        sys.stdout.flush()
    except (OSError, ValueError):
        pass
    os._exit(128 + signum)


for _signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
    signal.signal(_signum, _before_start)   # replaced by main() once the module is loaded


import stat
import datetime
import contextlib
import errno
import hashlib
import ipaddress
import re
import shutil
import subprocess
import time
from pathlib import Path

DEFAULT_TIMEOUT = 900
MAX_TIMEOUT = 1100            # the manifest's outer limit is 1200
MANIFEST_SECONDS = 1200       # the manifest's limit: the tool's own clock for reading the logs ends READ_MARGIN seconds before it
READ_MARGIN = 30              # kept for building and printing the answer after the last log was read
CLOCK_BYTES = 1 << 20         # the reading clock is also looked at after this many bytes of log
DEFAULT_POLICIES = ["policy/frameworks/files/hash-all-files"]
SCRIPT_NAME = "network-forensics.local.zeek"
MAX_LINE = 16 << 20            # a log line longer than this is located, not read
SHORT_OBJECT = 128
DIAGNOSTIC_LOGS = ("reporter", "weird", "capture_loss")
HASH_FIELDS = ("md5", "sha1", "sha256")
SECRET_FIELD = re.compile(r"(?i)(^|[._])(pass(word|wd)?|pwd|secret|token|cookie|community|credentials?|authorization|api_?key|session_?id)($|[._])")
URL_FIELD = re.compile(r"(?i)^(uri|url|full_url|referr?er|origin|post_uri)$")
MAX_NAMES = 10_000
MAX_SEPARATOR = 8              # a separator, an empty-field or an unset-field marker longer than this is a header problem
MAX_JSON_DEPTH = 64            # a JSON log record nested deeper than this is located and kept raw, not parsed (and never a recursion error)

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


def holds_files(directory):
    """Whether `directory` holds anything: one entry is looked at, never the whole listing (a caller's directory can hold millions of names)."""
    with os.scandir(directory) as entries:
        return next(entries, None) is not None


def open_regular(path, follow=True):
    """A file opened for reading that is never waited on: the open does not block (a name that became a pipe since it was checked would otherwise wait
    for a writer), the type is read from the descriptor, and anything but a regular file is refused. follow=False also refuses a symbolic link (for a
    name the capture or the engine produced). The file object it returns reads in the ordinary, blocking way."""
    flags = os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0) | (0 if follow else getattr(os, "O_NOFOLLOW", 0))
    fd = os.open(path, flags)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(errno.EINVAL, "not a regular file")
        os.set_blocking(fd, True)
        return os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise


def in_job():
    return bool(os.environ.get("JOB_ID") and os.environ.get("OUT"))


class LogNames:
    """The names the engine gave its logs, as the answer shows them: a stem shaped like a token (or carrying user-info) is shown as withheld-NNNNNN, the log is
    renamed to it on disk (it stays whole in out_dir under that name), and the real stem is written to zeek-log-names.jsonl in out_dir, mode 0600,
    flushed at the moment of the rename. Names that are not withheld are printed as they are."""

    NAME = "zeek-log-names.jsonl"

    def __init__(self, out_dir):
        self.out_dir, self.path, self.fh, self.count = out_dir, None, None, 0

    def shown(self, files, deadline=None):
        """(the .log file names in `files` as the answer shows them, sorted; the number of withheld names left unrenamed when `deadline` ran out).
        The index lines of every withheld name are written and fsynced once, then the logs are renamed; the clock is looked at for every entry. A
        name left unrenamed is not returned (it is not read or printed), and the caller says so."""
        out, plan = [], []
        left = 0
        for name in sorted(files):
            stem = name[:-4]
            if not (token_shaped(stem) or scrub(stem) != stem):
                out.append(name)
                continue
            if deadline is not None and time.monotonic() > deadline:
                left += 1
                continue
            while True:
                self.count += 1
                kept = "withheld-%06d.log" % self.count
                if not os.path.lexists(os.path.join(self.out_dir, kept)):
                    break
            plan.append((name, stem, kept))
        if plan:
            if self.fh is None:
                self.path = os.path.join(self.out_dir, self.NAME)
                fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
                self.fh = os.fdopen(fd, "w", encoding="utf-8")
            for position, (name, stem, kept) in enumerate(plan):
                self.fh.write(json.dumps({"finding_id": "G%06d" % (self.count - len(plan) + position + 1), "log": kept[:-4], "real_log": stem}) + "\n")
            self.fh.flush()
            os.fsync(self.fh.fileno())              # the real names are on disk before the first of them is renamed
            for name, stem, kept in plan:
                if deadline is not None and time.monotonic() > deadline:
                    left += 1
                    continue
                os.rename(os.path.join(self.out_dir, name), os.path.join(self.out_dir, kept))
                out.append(kept)
        return sorted(out), left

    def close(self):
        if self.fh is not None:
            self.fh.close()
            self.fh = None


def fail(message, **extra):
    if hasattr(signal, "pthread_sigmask"):
        signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT, signal.SIGHUP})     # one document: a stop that arrives while this is written waits, and the tool leaves with it
    hold_stop_signals()
    STATE["last_word"] = None
    print(json.dumps({"error": scrub(message), "tool": TOOL, "status": "failed", "status_basis": "the tool stopped with an error (see error)", **extra}))
    raise SystemExit(1)


def resolve_output(out, what="output"):
    """Where `out` really lands, as a path under the run directory; a place outside it, the run directory itself,
    or anything under inputs/ is refused, and in a job so is anything outside $OUT, the one place a job writes.

    A string check is not enough: `work/../inputs/x`, an absolute path and a symlink that points out all name a
    place the tool must not write. Resolving first and comparing directories is what holds, and the read-only
    inputs are the one place Zeek's logs must never appear: a later integrity check would report the evidence as
    modified.
    """
    root = Path.cwd().resolve()
    dest = (root / out).resolve() if not Path(out).is_absolute() else Path(out).resolve()
    if dest == root or root not in dest.parents:
        fail("%s must stay inside the run directory" % what, **{what: str(out)})
    inputs = root / "inputs"
    if dest == inputs or inputs in dest.parents:
        fail("%s cannot be under inputs/" % what, **{what: str(out)})
    if in_job():
        job_out = Path(os.environ["OUT"]).resolve()
        if dest != job_out and job_out not in dest.parents:
            fail("in a job %s is a directory under $OUT, the one place a job writes" % what, **{what: str(out), "out": str(job_out)})
    return str(dest.relative_to(root))


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
# walk is bounded (MAX_ROUNDS and WALK_SECONDS, below). A stop signal is the one case that reaches further: it also
# ends everything below the tool itself (a program that was forked a moment before it was entered in ACTIVE is among it) and what
# the tool started and lost (reap_orphans): a process that was seen below the tool, in the tool's own group, and whose parent has since
# ended. Nothing else is ever ended: a process the tool never saw in its tree (the next stage of a pipeline the tool heads, a process a
# launcher put in the group) is left alone, whoever leads the group. A program that has ended while something it started still
# holds its pipes does not hold the tool: communicate_bounded gives the pipes PIPE_GRACE seconds (and POST_EXIT_BYTES bytes) and goes on without them.
# The walk below a program is bounded: MAX_ROUNDS rounds and WALK_SECONDS seconds. Each process is stopped (SIGSTOP) as the walk finds it,
# so one that forks fast cannot outrun the walk; the walk is repeated for what the stopped ones had already forked, and the stopped set is
# then killed. A tree that is still growing at the bound is left, and process_notes() says so.
# Before a pid other than the program itself is signalled, its identity is read again (same_process(pid, ident)): the start time, from
# /proc/<pid>/stat (field 22, counted after the last ")") on Linux, from libproc's PROC_PIDTBSDINFO (pbi_start_tvsec, pbi_start_tvusec;
# written from <sys/proc_info.h>, not run on macOS in this repository's tests) on macOS, and from `ps -o lstart=` (to the second: coarse)
# where neither answers. The parent is no part of it: a child is re-parented when its parent ends, and is still the process that was
# listed. A pid that is gone, or whose start time is not the listed one, is left alone; a pid whose start time could not be read when it
# was listed is signalled only if it can be read now and is in the tool's own group; a ps listing that gave no start time (a minimal ps) is
# checked only for the pid still being there.
# A tree that cannot be listed (ps fails, lists nothing or needs more than PS_WAIT seconds, /proc cannot be read or takes more than
# TABLE_SECONDS) is never taken as an empty one: list_descendants raises TreeNotListed, the program itself is still ended, and a sentence
# in process_notes() says that the tree could not be listed (communicate_bounded also appends it to the stderr bytes it returns when it
# ended the program at its deadline). descendants() is list_descendants for a caller that cannot take an exception (a signal handler): its
# list is empty and has not_listed = True when the tree could not be listed.
# Open: a pid that ends and is reused between the identity check and the signal (two calls) is signalled; the Linux rule that a member of
# the tool's own group that holds the tool's pipe is ended; on macOS a daemon that holds the pipes of a finished program is not found (no
# /proc/<pid>/fd); a tool SIGKILLed between the stop and the kill leaves the program and the stopped set stopped (the harness ends the
# tool's group, and with it the stopped ones that are in it); a carrier's answer carries program_group (process_verdict, process_notes)
# only where that carrier's own code calls process_apply (without the call a program's leftovers are ended but not reported); the start of the interpreter, before any handler is in, is a window a signal can land in.
# What a program leaves behind (settle). A program can exit by itself and leave a process that goes on writing a file the answer then reports:
# one in a session of its own, or one that holds none of the tool's descriptors, which neither the walk nor the pipes reach. On Linux spawn()
# makes the tool a subreaper (become_subreaper, PR_SET_CHILD_SUBREAPER): such a process is adopted by the tool, so it is a direct child of the
# tool, and settle() ends it: when a program leaves ACTIVE after it has ended or been killed (ACTIVE is a list whose remove() does it), and at
# the end of communicate_bounded and inside kill_all. It ends only a child of the tool that is no program's own: not a program spawn() started
# (SPAWNED: Popen reaps those, their returncode is never taken), not one kept (KEEP, process_keep(pid), spawn(argv, leaves=True) for a
# program that leaves a process on purpose) and not a child the tool already had (PRE_KIDS). It stops each one, what it started with it (the
# walk above), kills and reaps them, for at most LEFTOVER_SECONDS, reading the clock for every process. While another program is running in
# ACTIVE nothing is ended and the answer says it is unproven. process_verdict() says what was found; process_apply(answer) puts it into an
# answer as program_group and turns a complete answer partial when a program left something or that could not be ruled out: a carrier
# calls it once where it prints its answer. Where nothing is adopted (not Linux, or the kernel refuses) settle() ends only what the tool saw
# below a program whose parent is gone, and the answer is unproven (NONLINUX_UNPROVEN_DOWNGRADE below is the one line that decides whether
# that alone makes a complete answer partial on a host that is not Linux). Not reached by any of this: a process that is not a descendant of
# a program (started through a service manager, a socket, another PID namespace), and the tool itself being killed (the harness ends its group).
# What a program's pipes deliver after it ended (the byte cap). communicate_bounded reads the pipes itself (a selector, not
# Popen.communicate) and looks at the program after every read. From the moment the program has ended, or been killed at its deadline, it
# takes at most POST_EXIT_BYTES (1 MiB) more bytes from its two pipes together and at most PIPE_GRACE seconds, whichever comes first; a
# program's own last words are in the pipe already (a pipe holds far less than the cap), so only what a process that went on holding the
# pipe wrote can be cut. At the cap the tool stops reading, ends the holder (reap_orphans, settle) and lets the pipes go: PIPE_CUT["cut"]
# counts the calls cut that way, process_notes() says so, and process_apply turns a complete answer partial. The bytes kept are the ones
# read, not a whole stream: a caller that parses the output sees the program's output and at most 1 MiB of what a leftover wrote. While the
# program runs each stream has a running cap too (STDOUT_CAP 64 MiB, STDERR_CAP 8 MiB with its head and last STDERR_TAIL 1 MiB kept, or the
# caller's `caps`): past it the program is ended on the deadline's own path (kill_tree, its tree only), the stream comes back cut
# (Output.cut, output_cut()), OUTPUT_CUT counts the call and process_apply turns a complete answer partial; a caller that parses a cut
# output says so and never takes it for a whole one.
import select as _select
import selectors as _selectors
import time

try:
    import ctypes
except ImportError:  # pragma: no cover
    ctypes = None

STATE = {"last_word": None}    # what to do, with the signal number, when the tool is stopped by a signal
class _Active(list):
    """The programs running now. A program that leaves the list after it has ended or been killed (a carrier removes it when it has waited
    for it) is followed by settle(): what it left behind is ended before the carrier reads what the program wrote. One that is still
    running when it is removed is not looked at."""

    def remove(self, proc):
        list.remove(self, proc)
        if proc.poll() is not None:
            settle()


ACTIVE = _Active()             # the programs running now
SPAWNED = {}                   # the programs spawn() started: pid -> identity (Popen reaps them, settle() never does)
KEEP = {}                      # the processes left on purpose: pid -> identity (settle() leaves them)
PRE_KIDS = {}                  # the children the tool already had when the first program was spawned: pid -> identity
LEAVES = {}                    # the programs started with leaves=True that have not ended yet: pid -> Popen
LEFT = {"left_behind": 0, "unproven": []}   # how many live processes settle() ended, and why nothing-left-behind cannot be proven
SUB = {"tried": False, "on": False, "note": None}        # whether the subreaper was asked for, and is on
SETTLING = [False]             # settle() is running (the stop signal's own call goes through)
LEFTOVER_SECONDS = 3              # the most one settle() works, in seconds; the clock is read for every process it ends, not once per pass
SETTLE_LOOK = 0.05             # the pause before the look that follows an ending: a fork that was under way when the first process died
# The one line the owner decides: on a host that cannot adopt orphaned processes (not Linux) a program may have left a process nobody can find.
# True: that alone is `unproven`, and process_apply turns a complete answer partial. False: the answer only carries a note.
NONLINUX_UNPROVEN_DOWNGRADE = True
SEEN = set()                   # the pids seen below a program this tool started: the only ones reap_orphans may end once their parent is gone
SEEN_IDENT = {}                # what each pid in SEEN was (its start time) when it was seen below the tool: a pid that ended and was reused does not match
NOTES = []                     # what this block could not do, as sentences for an answer (process_notes())
MAX_ROUNDS, WALK_SECONDS = 8, 15   # the bound of the walk below a program: rounds, and seconds
TABLE_SECONDS = 10             # the longest reading of /proc (or of a process table) is given
SEEN_MAX = 1 << 16             # the most pids SEEN holds

def _die_with_parent():  # runs in the child between fork and exec
    try:
        ctypes.CDLL(None).prctl(1, signal.SIGKILL)   # PR_SET_PDEATHSIG
    except Exception:  # noqa: BLE001
        pass


def spawn(argv, leaves=False, **kwargs):
    kwargs.setdefault("stdin", subprocess.DEVNULL)
    become_subreaper()
    if sys.platform.startswith("linux") and ctypes is not None:
        kwargs["preexec_fn"] = _die_with_parent
    proc = subprocess.Popen(argv, **kwargs)
    SEEN.add(proc.pid)
    started = _read_ident(proc.pid, "proc" if os.path.isdir("/proc/self") else "libproc")
    if started is not None:
        SEEN_IDENT[proc.pid] = started
    SPAWNED[proc.pid] = started
    if leaves:
        LEAVES[proc.pid] = proc     # what this program leaves behind stays (settle() keeps it)
    return proc


class TreeNotListed(Exception):
    """The processes could not be listed: ps failed, listed nothing or needed more than PS_WAIT seconds, /proc could not be read, or reading
    it took more than TABLE_SECONDS. It is never to be read as a tree with nothing below it."""


class _Listing(list):
    """The pids below a process, as a list; .ident holds each pid's identity from the same reading, .not_listed says the tree could not be listed."""
    ident = None
    not_listed = False


class _Table(dict):
    """{pid: (parent pid, process group)}; .ident holds each pid's identity from the same reading."""
    ident = None


def _note(text):
    """Record a sentence about what this block could not do (once, at most 20) and return it."""
    if text not in NOTES and len(NOTES) < 20:
        NOTES.append(text)
    return text


def process_notes():
    """What this block could not do so far, as sentences (a tree that could not be listed, a walk that was cut), for an answer."""
    return list(NOTES)


def _libproc_start(pid):
    """(seconds, microseconds) of the start of `pid` from libproc's PROC_PIDTBSDINFO (macOS), or None. Written from <sys/proc_info.h>
    (struct proc_bsdinfo, 136 bytes, flavor 3); not run on macOS in this repository's tests."""
    try:
        import ctypes.util

        class BsdInfo(ctypes.Structure):
            _fields_ = [("pbi_flags", ctypes.c_uint32), ("pbi_status", ctypes.c_uint32), ("pbi_xstatus", ctypes.c_uint32),
                        ("pbi_pid", ctypes.c_uint32), ("pbi_ppid", ctypes.c_uint32), ("pbi_uid", ctypes.c_uint32),
                        ("pbi_gid", ctypes.c_uint32), ("pbi_ruid", ctypes.c_uint32), ("pbi_rgid", ctypes.c_uint32),
                        ("pbi_svuid", ctypes.c_uint32), ("pbi_svgid", ctypes.c_uint32), ("rfu_1", ctypes.c_uint32),
                        ("pbi_comm", ctypes.c_char * 16), ("pbi_name", ctypes.c_char * 32), ("pbi_nfiles", ctypes.c_uint32),
                        ("pbi_pgid", ctypes.c_uint32), ("pbi_pjobc", ctypes.c_uint32), ("e_tdev", ctypes.c_uint32),
                        ("e_tpgid", ctypes.c_uint32), ("pbi_nice", ctypes.c_int32), ("pbi_start_tvsec", ctypes.c_uint64),
                        ("pbi_start_tvusec", ctypes.c_uint64)]

        lib = ctypes.CDLL(ctypes.util.find_library("proc") or "/usr/lib/libproc.dylib", use_errno=True)
        lib.proc_pidinfo.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int]
        lib.proc_pidinfo.restype = ctypes.c_int
        info = BsdInfo()
        if lib.proc_pidinfo(pid, 3, 0, ctypes.byref(info), ctypes.sizeof(info)) != ctypes.sizeof(info):
            return None
        return (int(info.pbi_start_tvsec), int(info.pbi_start_tvusec))
    except Exception:  # noqa: BLE001 - no library, no symbol, a sandbox: the caller falls back
        return None


def _ps_start(pid):
    """The start time `ps -o lstart= -p <pid>` prints, to the second (coarse), or None when ps fails, takes more than PS_WAIT seconds or prints none."""
    try:
        done = subprocess.run(["ps", "-o", "lstart=", "-p", str(pid)], capture_output=True, text=True, timeout=PS_WAIT)
    except (OSError, subprocess.SubprocessError):
        return None
    text = " ".join(done.stdout.split())
    return text if done.returncode == 0 and text else None


def _read_ident(pid, kind):
    """The identity of `pid` read the way `kind` ("proc", "libproc" or "ps") says, or None when the process is gone or the way fails."""
    if kind == "proc":
        try:
            with open("/proc/%d/stat" % pid, "rb") as fh:
                data = fh.read()
            return ("proc", int(data[data.rindex(b")") + 2:].split()[19]))   # field 22, counted after the last ")": the name may hold one
        except (OSError, ValueError, IndexError):
            return None
    if kind == "libproc":
        started = _libproc_start(pid)
        return None if started is None else ("libproc", started)
    started = _ps_start(pid)
    return None if started is None else ("ps", started)


def process_ident(pid):
    """What tells the process that has `pid` now from a later one that gets the same pid: its start time. Linux: field 22 of /proc/<pid>/stat;
    macOS: libproc's pbi_start_tvsec and pbi_start_tvusec; where neither answers, the start time ps prints (to the second). The parent is no
    part of it: a child is re-parented when its parent ends, and is still the process that was listed. None where the process is gone or
    cannot be read."""
    if os.path.isdir("/proc/self"):
        return _read_ident(pid, "proc")
    return _read_ident(pid, "libproc") or _read_ident(pid, "ps")


def same_process(pid, ident):
    """Whether `pid` is still the process `ident` was read from (process_ident, or the listing a walk made): a pid that is gone, or that
    another process has taken since (another start time), is not. An `ident` of None (it could not be read when the process was listed) is
    not vouched for either: the pid is signalled only if it can be read now and is in this process's own group. A listing by plain ps that
    gave no start time ("listed") can only be checked for the pid still being there."""
    if ident is None:
        try:
            return process_ident(pid) is not None and os.getpgid(pid) == os.getpgrp()
        except OSError:
            return False
    if ident[0] == "listed":
        try:
            os.kill(pid, 0)
        except PermissionError:
            return True
        except OSError:
            return False
        return True
    return _read_ident(pid, ident[0]) == ident


def _seen_below(pids, ident):
    """Enter pids seen below the tool in SEEN, with the identity the listing that showed them gave."""
    for pid in pids:
        if pid in SEEN or len(SEEN) < SEEN_MAX:
            SEEN.add(pid)
            if ident.get(pid) is not None:
                SEEN_IDENT[pid] = ident[pid]


def _ps_rows(columns):
    """The rows of `ps -A -o <columns>` as lists of fields. Raises TreeNotListed when ps cannot be run, fails, takes more than PS_WAIT seconds
    or lists nothing."""
    try:
        done = subprocess.run(["ps", "-A", "-o", columns], capture_output=True, text=True, timeout=PS_WAIT)
    except subprocess.TimeoutExpired as exc:
        raise TreeNotListed("ps took more than %d seconds" % PS_WAIT) from exc
    except (OSError, subprocess.SubprocessError) as exc:
        raise TreeNotListed("ps could not be run: %s" % type(exc).__name__) from exc
    rows = [line.split() for line in done.stdout.splitlines() if line.split()]
    if done.returncode != 0 or not rows:
        raise TreeNotListed("ps %s" % ("exited %d" % done.returncode if done.returncode != 0 else "listed nothing"))
    return rows


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
    """Every process below `pid` in `kids` ({parent: [children]}), a parent before its children."""
    found, seen, queue = [], {pid}, [pid]
    for parent in queue:
        for child in kids.get(parent, []):
            if child not in seen:
                seen.add(child)
                found.append(child)
                queue.append(child)
    return found


def _libproc_works(pid):
    """Whether an empty libproc answer for `pid` can be believed: libproc has just listed `pid` as this tool's own child, or, when `pid`
    is the tool itself, has just listed the tool as its parent's child. A library that lists nothing for a live process is not working
    (as in a sandbox that denies it)."""
    if pid in (_children_libproc(os.getpid()) or []):
        return True
    return pid == os.getpid() and os.getpid() in (_children_libproc(os.getppid()) or [])


def list_descendants(pid):
    """Every process below `pid` (never one beside it): from /proc where there is one, else from libproc, else from ps (given PS_WAIT
    seconds). libproc is believed when it lists a child; an empty answer is believed only when libproc has just listed this tool's own child
    `pid` (a library that answers nothing for a live child is not working, as in a sandbox that denies it), and otherwise ps is asked. The
    list carries .ident, the identity of each pid from the same reading. Raises TreeNotListed when the processes cannot be listed: that is
    never an empty list."""
    kids, ident = {}, {}
    try:
        if os.path.isdir("/proc/self"):
            started = time.monotonic()
            for entry in os.listdir("/proc"):
                if time.monotonic() - started > TABLE_SECONDS:
                    raise TreeNotListed("reading /proc took more than %d seconds" % TABLE_SECONDS)
                if entry.isdigit():
                    try:
                        with open("/proc/%s/stat" % entry, "rb") as fh:
                            fields = fh.read().rsplit(b")", 1)[1].split()
                        kids.setdefault(int(fields[1]), []).append(int(entry))
                        ident[int(entry)] = ("proc", int(fields[19]))
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
                listing = _Listing(found)
                listing.ident = {}
                for child in found:
                    started = _libproc_start(child)
                    if started is not None:
                        listing.ident[child] = ("libproc", started)
                return listing
            if first is not None and _libproc_works(pid):
                listing = _Listing()
                listing.ident = {}
                return listing
            for row in _ps_rows("pid=,ppid=,lstart="):
                if len(row) >= 2 and row[0].isdigit() and row[1].isdigit():
                    kids.setdefault(int(row[1]), []).append(int(row[0]))
                    ident[int(row[0])] = ("ps", " ".join(row[2:])) if len(row) >= 6 else ("listed", None)
    except OSError as exc:
        raise TreeNotListed("the processes could not be read: %s" % type(exc).__name__) from exc
    listing = _Listing(_below(kids, pid))
    listing.ident = {child: ident[child] for child in listing if child in ident}
    return listing


def descendants(pid):
    """list_descendants for a caller that cannot take an exception (a signal handler): the same list, but when the tree cannot be listed the
    list is empty, has not_listed = True, and process_notes() says so."""
    try:
        return list_descendants(pid)
    except TreeNotListed as exc:
        _note("the processes below pid %d could not be listed (%s)" % (pid, exc))
        listing = _Listing()
        listing.ident = {}
        listing.not_listed = True
        return listing


def _process_table():
    """{pid: (parent pid, process group)} for every process, from /proc where there is one, else from ps (given PS_WAIT seconds); .ident holds
    each pid's identity from the same reading. Raises TreeNotListed when neither answers."""
    table, ident = _Table(), {}
    try:
        if os.path.isdir("/proc/self"):
            started = time.monotonic()
            for entry in os.listdir("/proc"):
                if time.monotonic() - started > TABLE_SECONDS:
                    raise TreeNotListed("reading /proc took more than %d seconds" % TABLE_SECONDS)
                if entry.isdigit():
                    try:
                        with open("/proc/%s/stat" % entry, "rb") as fh:
                            fields = fh.read().rsplit(b")", 1)[1].split()
                        table[int(entry)] = (int(fields[1]), int(fields[2]))
                        ident[int(entry)] = ("proc", int(fields[19]))
                    except (OSError, IndexError, ValueError):
                        continue
        else:
            for row in _ps_rows("pid=,ppid=,pgid=,lstart="):
                if len(row) >= 3 and all(part.isdigit() for part in row[:3]):
                    table[int(row[0])] = (int(row[1]), int(row[2]))
                    ident[int(row[0])] = ("ps", " ".join(row[3:])) if len(row) >= 8 else ("listed", None)
    except OSError as exc:
        raise TreeNotListed("the processes could not be read: %s" % type(exc).__name__) from exc
    table.ident = ident
    return table


def _sample(pid):
    """Remember what is below `pid` now, by the cheap routes only (/proc, or libproc on macOS; never a program): a process that is seen
    here and later loses its parent is the tool's to end, and one that was never seen is not."""
    try:
        if os.path.isdir("/proc/self"):
            table = _process_table()
            kids = {}
            for child, (parent, _group) in table.items():
                kids.setdefault(parent, []).append(child)
            _seen_below(_below(kids, pid), table.ident)
        else:
            seen, stack = {pid}, [pid]
            while stack:
                for child in _children_libproc(stack.pop()) or []:
                    if child not in seen:
                        seen.add(child)
                        stack.append(child)
            idents = {child: ("libproc", started) for child in seen - {pid} for started in [_libproc_start(child)] if started is not None}
            _seen_below(seen - {pid}, idents)
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


def _same_ident(pid, before, listed):
    """Whether `pid` is still the process `before` was read from. `listed` is the identity the table just read gave it: when it is the same
    kind of identity (a start time from /proc, from libproc or from ps) the two are compared; when it is not (macOS: a process is seen
    through libproc and listed through ps, and the two give different texts for one start time) the pid is read again the way `before` was."""
    if listed is not None and listed[0] == before[0]:
        return listed == before
    return same_process(pid, before)


def reap_orphans(inodes=None):
    """Kill what this tool started and lost: a process of the tool's own group that is no longer below the tool (its parent ended and
    init adopted it, so the walk from a program's pid cannot find it) and that the tool knows to be its own: it was seen below the tool
    (SEEN: the programs it started, the trees it listed, the samples taken while it waited), or, on Linux, it holds one of `inodes`,
    the pipes the tool made. A process the tool never saw in its tree is not touched, whoever leads the group: the next stage of a
    pipeline the tool heads, or a process a launcher put in the group, is not the tool's. A process outside the group is never looked
    at, and a pid is checked against the group, and against the identity it had when it was seen (same_process), at the moment it is
    signalled. Returns the pids signalled; when the processes cannot be listed it signals none and process_notes() says so."""
    me = os.getpid()
    try:
        if os.getpgrp() != me:
            return []
    except OSError:
        return []
    try:
        table = _process_table()
    except TreeNotListed as exc:
        _note("what the tool started and lost could not be looked for: the processes could not be listed (%s)" % exc)
        return []
    kids = {}
    for pid, (parent, _group) in table.items():
        kids.setdefault(parent, []).append(pid)
    below = set(_below(kids, me))
    on_linux = os.path.isdir("/proc/self")
    killed = []
    started = time.monotonic()
    for pid, (_parent, group) in table.items():
        if time.monotonic() - started > TABLE_SECONDS:
            _note("the look for what the tool started and lost was cut after %d seconds" % TABLE_SECONDS)
            break
        if group != me or pid == me or pid in below:
            continue
        listed = table.ident.get(pid)
        holder = False
        if pid in SEEN:
            before = SEEN_IDENT.get(pid)
            if before is not None and not _same_ident(pid, before, listed):
                continue                           # the pid is another process's now: one the tool never saw
        elif inodes and on_linux and _holds_pipe(pid, inodes):
            holder = True
        else:
            continue
        try:
            if os.getpgid(pid) != me:
                continue
            if not same_process(pid, listed) or (holder and not _holds_pipe(pid, inodes)):
                continue
            os.kill(pid, signal.SIGKILL)
            killed.append(pid)
        except OSError:
            pass
    return killed


def _stop_below(root, stopped):
    """Stop (SIGSTOP) every process below `root` as the walk finds it, so one that forks fast cannot outrun the walk, and repeat the walk
    for what the stopped ones had already forked, for at most MAX_ROUNDS rounds and WALK_SECONDS seconds. `stopped` gets {pid: identity}.
    Returns None, or the sentence that says the tree could not be listed or that the walk was cut."""
    began = time.monotonic()
    for _round in range(MAX_ROUNDS):
        try:
            found = list_descendants(root)
        except TreeNotListed as exc:
            return _note("the processes below pid %d could not be listed (%s): the program itself was ended, nothing below it" % (root, exc))
        listed = getattr(found, "ident", None) or {}
        _seen_below(found, listed)
        fresh = [pid for pid in found if pid not in stopped]
        if not fresh:
            return None
        for pid in fresh:
            if not same_process(pid, listed.get(pid)):
                continue
            try:
                os.kill(pid, signal.SIGSTOP)
                stopped[pid] = listed.get(pid)
            except OSError:
                pass
        if time.monotonic() - began > WALK_SECONDS:
            break
    return _note("the walk below pid %d was cut at %d rounds or %d seconds: a process started after it may be running" % (root, MAX_ROUNDS, WALK_SECONDS))


def _end(stopped):
    """Kill the stopped set, each pid only if it is still the process that was stopped."""
    for pid, ident in list(stopped.items()):
        if same_process(pid, ident):
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass


def kill_tree(proc):
    """Kill the program and everything it started. The program is stopped first and then each process below it as the walk finds it
    (_stop_below), so the tree does not grow while it is listed; the stopped set is killed after the program. A pid is killed only if it
    is still the process that was listed (same_process). A program already waited for is not touched: its pid is free to be another
    process's, and the walk below it would be that process's children. Returns None, or a sentence when the tree could not be listed or
    the walk was cut."""
    if proc.poll() is not None:
        return None
    try:
        proc.send_signal(signal.SIGSTOP)    # a program that is stopped forks nothing more while its tree is listed
    except OSError:
        pass
    stopped, note = {}, None
    try:
        note = _stop_below(proc.pid, stopped)
    finally:
        try:
            proc.kill()
        except OSError:
            pass
        _end(stopped)
    return note


def _stat_row(pid):
    """(state letter, parent pid, identity) of `pid` from /proc/<pid>/stat, or None when it is gone or cannot be read. The identity is the one
    process_ident gives (field 22, counted after the last ")")."""
    try:
        with open("/proc/%d/stat" % pid, "rb") as fh:
            data = fh.read()
        rest = data[data.rindex(b")") + 2:].split()
        return rest[0].decode("ascii", "replace"), int(rest[1]), ("proc", int(rest[19]))
    except (OSError, ValueError, IndexError):
        return None


def _children_of_me():
    """{pid: (state, identity)} of the direct children of this process (Linux). The kernel's own list of each thread's children is read where
    there is one (no scan of every process), and every pid it names is checked against /proc/<pid>/stat; where there is none, /proc is
    scanned. Raises TreeNotListed when /proc cannot be read or takes more than TABLE_SECONDS."""
    me = os.getpid()
    pids = None
    try:
        named = set()
        for tid in os.listdir("/proc/%d/task" % me):
            with open("/proc/%d/task/%s/children" % (me, tid)) as fh:
                named.update(int(part) for part in fh.read().split())
        pids = sorted(named)
    except (OSError, ValueError):
        pids = None
    if pids is None:
        try:
            pids = [int(entry) for entry in os.listdir("/proc") if entry.isdigit()]
        except OSError as exc:
            raise TreeNotListed("the processes could not be read: %s" % type(exc).__name__) from exc
    found, started = {}, time.monotonic()
    for pid in pids:
        if time.monotonic() - started > TABLE_SECONDS:
            raise TreeNotListed("reading /proc took more than %d seconds" % TABLE_SECONDS)
        row = _stat_row(pid)
        if row is not None and row[1] == me:
            found[pid] = (row[0], row[2])
    return found


def _unproven(text):
    """Record why this block cannot say that no program left a process behind (once, at most 20) and return it."""
    if text not in LEFT["unproven"] and len(LEFT["unproven"]) < 20:
        LEFT["unproven"].append(text)
    return text


def become_subreaper():
    """On Linux ask the kernel to make this process the parent of every process a program leaves behind (PR_SET_CHILD_SUBREAPER = 36), so that
    one that left the tool's group or session, or holds none of its descriptors, is a child of the tool and settle() can find it. Called by
    spawn() before the first program; once. PRE_KIDS records the children the tool already had (pid and start time): they are not a program's
    and settle() leaves them. Where the kernel refuses, or the host is not Linux, nothing is adopted: settle() falls back to what the tool
    saw below a program (SEEN), and the answer cannot prove that nothing was left (process_verdict()['unproven']). Returns whether it is on."""
    if SUB["tried"]:
        return SUB["on"]
    SUB["tried"] = True
    if sys.platform.startswith("linux") and ctypes is not None:
        try:
            SUB["on"] = ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) == 0
        except Exception:  # noqa: BLE001 - no libc symbol, a sandbox: the caller falls back
            SUB["on"] = False
        if SUB["on"]:
            try:
                PRE_KIDS.update({pid: ident for pid, (_state, ident) in _children_of_me().items()})
            except TreeNotListed as exc:
                _unproven(_note("the children the tool already had could not be listed (%s): one of them may be taken for a program's" % exc))
        else:
            _unproven("this host refused PR_SET_CHILD_SUBREAPER: a process a program left behind outside the walk is not adopted and may not be found")
    else:
        reason = "this host cannot adopt orphaned processes (no PR_SET_CHILD_SUBREAPER): a process a program left behind may not be found"
        SUB["note"] = reason              # in process_verdict()["notes"], never in process_notes(): a tool that reads only what a program printed is not made partial by it
        if NONLINUX_UNPROVEN_DOWNGRADE:
            _unproven(reason)
    return SUB["on"]


def process_keep(pid):
    """Let `pid` stay: settle() does not end it. For a process a program leaves on purpose (a daemon the tool stops itself); spawn(argv,
    leaves=True) does it for what that program leaves. A kept process is still ended by a stop signal (kill_all)."""
    ident = process_ident(pid)
    if ident is not None:
        KEEP[pid] = ident


def _exempt(pid, ident, active):
    """Whether the process `pid` (identity `ident`) is the tool's own and not a program's leftover: a program spawn() started (Popen owns it
    and reaps it), one in ACTIVE (`active`, their pids), one kept (KEEP) or one the tool already had (PRE_KIDS). A pid whose identity differs is
    another process that has the number now."""
    if pid in active:
        return True
    for table in (SPAWNED, KEEP, PRE_KIDS):
        if pid in table and (table[pid] is None or (table[pid] == ident if ident is None or table[pid][0] == ident[0] else same_process(pid, table[pid]))):
            return True
    return False


def _victims_children(active):
    """[(pid, state, identity)]: the children of this tool that are no program's own (Linux, with the subreaper on)."""
    return [(pid, state, ident) for pid, (state, ident) in sorted(_children_of_me().items()) if not _exempt(pid, ident, active)]


def _victims_seen(active):
    """[(pid, state, identity)]: where nothing is adopted, the processes that were seen below a program, are still the ones that were seen, and
    have lost their parent (the parent is not the tool and is not a live process the tool saw). Raises TreeNotListed."""
    me = os.getpid()
    candidates = [pid for pid in list(SEEN) if pid != me and SEEN_IDENT.get(pid) is not None and not _exempt(pid, SEEN_IDENT[pid], active)]
    if not candidates:
        return []
    table = _process_table()
    found = []
    for pid in candidates:
        row, listed = table.get(pid), table.ident.get(pid)
        if row is None or not _same_ident(pid, SEEN_IDENT[pid], listed) or row[0] == me:
            continue
        parent = row[0]
        if parent in table and SEEN_IDENT.get(parent) is not None and _same_ident(parent, SEEN_IDENT[parent], table.ident.get(parent)):
            continue                               # its parent is a live process of a program's tree: the program has not ended
        found.append((pid, "S", listed))
    return found


def _stop_under(roots, stopped, deadline):
    """_stop_below for several roots at once with one reading of the processes per round (a program may leave thousands): stop (SIGSTOP)
    every process below any of `roots` as the walk finds it, for at most MAX_ROUNDS rounds, WALK_SECONDS seconds and until `deadline`.
    `stopped` gets {pid: identity}. Returns None, or the sentence that says the tree could not be listed or that the walk was cut."""
    began = time.monotonic()
    for _round in range(MAX_ROUNDS):
        try:
            table = _process_table()
        except TreeNotListed as exc:
            return _unproven(_note("the processes below what a program left behind could not be listed (%s): the leftovers were ended, nothing below them" % exc))
        kids = {}
        for child, (parent, _group) in table.items():
            kids.setdefault(parent, []).append(child)
        fresh = []
        for root in roots:
            fresh.extend(pid for pid in _below(kids, root) if pid not in stopped)
        if not fresh:
            return None
        for pid in fresh:
            ident = table.ident.get(pid)
            if pid not in stopped and same_process(pid, ident):
                try:
                    os.kill(pid, signal.SIGSTOP)
                    stopped[pid] = ident
                except OSError:
                    pass
        if time.monotonic() > min(deadline, began + WALK_SECONDS):
            break
    return _unproven(_note("the walk below what a program left behind was cut at %d rounds or %d seconds: a process started after it may be running" % (MAX_ROUNDS, WALK_SECONDS)))


def _end_counting(stopped):
    """Kill the stopped set, each pid only if it is still the process that was stopped. How many were alive (a zombie was not left running)."""
    alive = 0
    for pid, ident in list(stopped.items()):
        row = _stat_row(pid)
        if not same_process(pid, ident):
            continue
        try:
            os.kill(pid, signal.SIGKILL)
            if row is None or row[0] not in ("Z", "X"):
                alive += 1
        except OSError:
            pass
    return alive


def _end_children(victims, deadline):
    """End the leftovers that are this tool's children: each is stopped (its identity and parent read again first), what it started is stopped
    with it (_stop_under), the set is killed, and the children are reaped (waitpid WNOHANG: the tool is their parent). The clock is read for
    every one, so a program that left thousands is cut at `deadline`, not after a pass. Returns how many live processes were killed."""
    me = os.getpid()
    stopped, reap, cut = {}, [], False
    try:
        for pid, _state, ident in victims:
            if time.monotonic() >= deadline:
                cut = True
                break
            row = _stat_row(pid)
            if row is None or row[1] != me or row[2] != ident:
                continue                           # gone, or not this tool's child any more
            if row[0] in ("Z", "X"):
                reap.append(pid)
                continue
            try:
                os.kill(pid, signal.SIGSTOP)
            except OSError:
                continue
            stopped[pid] = ident
            reap.append(pid)
        _stop_under(list(stopped), stopped, deadline)
    finally:
        alive = _end_counting(stopped)
    pending = set(reap)
    while pending:
        for pid in list(pending):
            try:
                done, _status = os.waitpid(pid, os.WNOHANG)
            except OSError:
                pending.discard(pid)               # not this tool's child (any more): nothing to reap
                continue
            if done:
                pending.discard(pid)
        if not pending:
            break
        if time.monotonic() >= deadline:
            _unproven(_note("%d processes a program left behind did not end within %d seconds" % (len(pending), LEFTOVER_SECONDS)))
            break
        time.sleep(0.005)
    if cut:
        _unproven(_note("a program left more processes than could be ended within %d seconds: some are still running" % LEFTOVER_SECONDS))
    return alive


def _end_seen(victims, deadline):
    """End the leftovers where nothing is adopted: stopped, what they started stopped with them, then killed (each only if it is still the
    process that was seen). Returns how many live processes were killed."""
    stopped = {}
    try:
        for pid, _state, ident in victims:
            if time.monotonic() >= deadline:
                _unproven(_note("a program left more processes than could be ended within %d seconds: some are still running" % LEFTOVER_SECONDS))
                break
            if same_process(pid, ident):
                try:
                    os.kill(pid, signal.SIGSTOP)
                    stopped[pid] = ident
                except OSError:
                    pass
        _stop_under(list(stopped), stopped, deadline)
    finally:
        alive = _end_counting(stopped)
    return alive


def _settle(final):
    active = {proc.pid for proc in list(ACTIVE)}
    if not final and any(proc.poll() is None for proc in list(ACTIVE)):
        _unproven(_note("a program was still running when another one ended: what is left behind cannot be told from what that program started, so nothing was ended"))
        return 0
    deadline = time.monotonic() + LEFTOVER_SECONDS
    victims = _victims_children if SUB["on"] else _victims_seen
    ended, looked = 0, False
    ready = [proc for proc in list(LEAVES.values()) if proc.poll() is not None]
    if ready:
        for proc in ready:                         # a program that leaves a process on purpose: what it left stays
            LEAVES.pop(proc.pid, None)
        for pid, state, ident in victims(active):
            if state not in ("Z", "X"):
                KEEP[pid] = ident
    while True:
        found = victims(active)
        if not found:
            if ended and not looked:
                looked = True                      # one more look after a short pause: a fork that was under way when the first one died
                time.sleep(SETTLE_LOOK)
                continue
            return ended
        if time.monotonic() >= deadline:
            _unproven(_note("%d processes a program left behind were still there after %d seconds: they were not all ended" % (len(found), LEFTOVER_SECONDS)))
            return ended
        ended += (_end_children if SUB["on"] else _end_seen)(found, deadline)
        if not SUB["on"]:
            return ended                           # nothing is adopted: one pass, the processes are not this tool's to reap


def settle(final=False):
    """Look for what the programs this tool ran have left behind, and end it: the processes that are the tool's children and no program's own
    (the subreaper adopted them) are stopped, what they started with them, killed and reaped, for at most LEFTOVER_SECONDS (the clock is read for
    every process, and one more look follows an ending). Never a process of another program: while another program is running in ACTIVE nothing
    is ended and process_verdict() says it is unproven. Never a program spawn() started (Popen owns its exit status: its returncode is never
    taken), nor KEEP, PRE_KIDS or a process outside the tool's own children. final=True is the stop signal's own call (kill_all). Runs on the
    caller's thread, joins none and never raises. Returns how many live processes it ended; process_verdict() holds the totals."""
    if SETTLING[0] and not final:
        return 0
    SETTLING[0] = True
    try:
        ended = _settle(final)
        LEFT["left_behind"] += ended
        return ended
    except Exception as exc:  # noqa: BLE001 - never into the finally of a carrier: say it could not be proven
        _unproven(_note("the look for what a program left behind failed (%s)" % type(exc).__name__))
        return 0
    finally:
        SETTLING[0] = False


def process_verdict():
    """What an answer says about the programs the tool ran: {"subreaper": whether orphans were adopted, "left_behind": how many live processes
    settle() ended, "unproven": why 'nothing was left behind' cannot be claimed (empty when it can), "notes": process_notes()}."""
    return {"subreaper": SUB["on"], "left_behind": LEFT["left_behind"], "unproven": list(LEFT["unproven"]), "notes": process_notes() + ([SUB["note"]] if SUB["note"] else [])}


def process_apply(answer):
    """Put process_verdict() into `answer` as answer["program_group"] and, when a program left a process behind or that cannot be ruled out,
    turn a complete answer into a partial one (status "partial", the ok and complete flags that are there false, a sentence in status_basis;
    a call of communicate_bounded that was cut at POST_EXIT_BYTES counts, PIPE_CUT, and so does one that ended a program whose output passed
    its running cap, OUTPUT_CUT): what a program wrote while the tool read it, or what it printed past a cap, is not a complete result. A
    carrier calls it once where it prints its answer. Returns `answer`."""
    verdict = process_verdict()
    answer["program_group"] = verdict
    if (verdict["left_behind"] > 0 or verdict["unproven"] or PIPE_CUT["cut"] or OUTPUT_CUT["cut"]) and answer.get("status") == "complete":
        answer["status"] = "partial"
        for flag in ("ok", "complete"):
            if flag in answer:
                answer[flag] = False
        if verdict["left_behind"] > 0:
            sentence = "a program left %d process%s running after it ended; the tool ended them, and what they wrote before that is in the files named here" % (
                verdict["left_behind"], "" if verdict["left_behind"] == 1 else "es")
        elif OUTPUT_CUT["cut"]:
            sentence = "a program's output was not read whole: %s" % OUTPUT_CUT["last"]
        elif PIPE_CUT["cut"]:
            sentence = "a process that held a program's pipe after it ended went on writing; the tool read no more than %d bytes of it and let the pipe go" % POST_EXIT_BYTES
        else:
            sentence = "the tool cannot prove that no program left a process behind (see program_group.unproven)"
        basis = answer.get("status_basis")
        answer["status_basis"] = "%s; %s" % (basis, sentence) if isinstance(basis, str) and basis else sentence
    return answer

PIPE_GRACE = 1.0    # seconds the pipes of a program that has ended are given to reach end of file
POST_EXIT_BYTES = 1 << 20    # the most bytes (both pipes together) read from the pipes of a program that has ended
PIPE_CUT = {"cut": 0}        # how many calls stopped reading at POST_EXIT_BYTES because a process still held the pipes and went on writing
STDOUT_CAP = 64 << 20        # the most bytes of standard output one call of communicate_bounded keeps; past it the program is ended and the output is cut
STDERR_CAP = 8 << 20         # the most bytes of standard error one call reads before it ends the program; it keeps the head and the last STDERR_TAIL bytes
STDERR_TAIL = 1 << 20        # the tail of standard error kept once it passes STDERR_CAP (a program's last words are at its end)
OUTPUT_CUT = {"cut": 0, "last": None}    # how many calls cut a stream at its running cap, and the sentence of the last one


class Output(bytes):
    """What communicate_bounded kept of one stream: the bytes, and `cut`, None when the stream was read whole, or a sentence saying it was
    not (the program printed past the stream's cap and was ended there). A caller that parses the output reads `cut` first: a cut output
    is never a whole one."""
    cut = None


def output_cut(*outputs):
    """The sentence of the first of `outputs` (values communicate_bounded or preflight returned) that was cut at its cap; None when each was
    read whole."""
    for out in outputs:
        text = getattr(out, "cut", None)
        if text:
            return text
    return None


def _output(data, cut):
    out = Output(data)
    out.cut = cut
    return out


def communicate_bounded(proc, seconds, input=None, caps=None):
    """(stdout bytes, stderr bytes, timed out) for a program started with pipes, in bytes (Output: bytes with a `cut` sentence or None). At
    `seconds` the program and what it started are killed (timed out). What the tool holds is capped while the program runs: `caps` is
    (stdout cap, stderr cap), STDOUT_CAP and STDERR_CAP when it is None. Standard output is kept to its cap; standard error keeps its head and
    its last STDERR_TAIL bytes (at most half its cap). When either stream passes its cap the program and what it started are ended (kill_tree,
    the deadline's own path: its tree, nothing else), what was kept is returned with `cut` set on that stream, the call is counted in
    OUTPUT_CUT and said in process_notes(), and process_apply turns a complete answer partial. A program that has ended while something it
    started still holds its pipes (a daemon, a helper that inherited them) does not hold the tool: from the moment the program has ended (or
    was killed) the pipes are given PIPE_GRACE seconds and POST_EXIT_BYTES bytes, whichever is used up first; what the program wrote is kept,
    what the tool lost is killed (reap_orphans, settle), and the pipes are let go. A cut at the byte cap is counted in PIPE_CUT and noted
    (process_notes()); the return shape is the same. The pipes are read here and by nothing else (not by Popen.communicate), so letting them
    go is safe. `input` is written while the program runs and is dropped once it has ended."""
    deadline = time.monotonic() + max(0.1, seconds)
    out_cap, err_cap = (STDOUT_CAP, STDERR_CAP) if caps is None else (max(0, int(caps[0])), max(0, int(caps[1])))
    tail_keep = min(STDERR_TAIL, err_cap // 2)
    bufs = (bytearray(), bytearray())       # standard output; the head of standard error
    tail = bytearray()                      # the last tail_keep bytes of standard error read past its head
    seen, over = [0, 0], [False, False]     # bytes read from each stream; the stream passed its cap while the program ran
    late = [False, False]                   # the stream passed its cap after the program had ended (by itself, or at the deadline)
    sel = _selectors.DefaultSelector()
    pending = memoryview(input) if input and proc.stdin is not None else None
    for index, stream in enumerate((proc.stdout, proc.stderr)):
        if stream is not None:
            sel.register(stream, _selectors.EVENT_READ, index)
    if proc.stdin is not None:
        if pending:
            sel.register(proc.stdin, _selectors.EVENT_WRITE, 2)
        else:
            _close_pipe(proc.stdin)
    timed_out, note, ended, extra, cut, sampled, ended_at_cap = False, None, None, 0, False, 0.0, False
    try:
        while True:
            now = time.monotonic()
            if ended is None:
                if proc.poll() is not None:
                    ended = now
                elif over[0] or over[1]:
                    ended_at_cap = True
                    note = kill_tree(proc)
                    ended = time.monotonic()
                elif now >= deadline:
                    timed_out = True
                    note = kill_tree(proc)
                    ended = time.monotonic()
                elif now - sampled >= 0.2:
                    sampled = now
                    _sample(proc.pid)
            if ended is not None:
                if pending is not None:
                    sel.unregister(proc.stdin)
                    _close_pipe(proc.stdin)
                    pending = None
                if not any(key.data != 2 for key in sel.get_map().values()) or extra >= POST_EXIT_BYTES or now - ended >= PIPE_GRACE:
                    cut = extra >= POST_EXIT_BYTES and any(key.data != 2 for key in sel.get_map().values())
                    break
            wait = max(0.01, min(0.2, (deadline if ended is None else ended + PIPE_GRACE) - now))
            if not sel.get_map():
                try:
                    proc.wait(timeout=wait)
                except subprocess.TimeoutExpired:
                    pass
                continue
            for key, _mask in sel.select(wait):
                if key.data == 2:
                    try:
                        pending = pending[os.write(key.fd, pending[:_select.PIPE_BUF]):]
                    except OSError:
                        pending = None
                    if not pending:
                        sel.unregister(proc.stdin)
                        _close_pipe(proc.stdin)
                        pending = None
                    continue
                if ended is not None and extra >= POST_EXIT_BYTES:
                    break
                try:
                    data = os.read(key.fd, 65536 if ended is None else min(65536, POST_EXIT_BYTES - extra))
                except OSError:
                    data = b""
                if not data:
                    sel.unregister(key.fileobj)
                    continue
                index = key.data
                seen[index] += len(data)
                if ended is not None:
                    extra += len(data)
                if index == 0:
                    room = out_cap - len(bufs[0])
                    if room > 0:
                        bufs[0].extend(data[:room])
                    if seen[0] > out_cap:
                        over[0], late[0] = (over[0], True) if ended is not None else (True, late[0])
                else:
                    room = err_cap - tail_keep - len(bufs[1])
                    if room > 0:
                        bufs[1].extend(data[:room])
                        data = data[room:]
                    if data:
                        tail.extend(data)
                        if len(tail) > tail_keep:
                            del tail[:len(tail) - tail_keep]
                    if seen[1] > err_cap:
                        over[1], late[1] = (over[1], True) if ended is not None else (True, late[1])
                if (over[0] or over[1]) and ended is None:
                    break           # the loop's head ends the program at once
        if any(key.data != 2 for key in sel.get_map().values()):
            reap_orphans(_pipe_inodes(proc))
            settle()
    finally:
        sel.close()
        for pipe in (proc.stdin, proc.stdout, proc.stderr):
            _close_pipe(pipe)
    if cut:
        PIPE_CUT["cut"] += 1
        _note("a process that held a program's pipe after the program ended went on writing: the tool read %d bytes more and let the pipe go" % POST_EXIT_BYTES)
    try:
        proc.wait(timeout=PIPE_GRACE)
    except subprocess.TimeoutExpired:
        pass
    settle()
    # A stream that passed its cap only after the program had ended is cut too, unless the pipes were cut at POST_EXIT_BYTES: then what passed
    # it is a process that held the pipe and went on writing, PIPE_CUT says so, and the program's own output was read whole.
    for index in (0, 1):
        over[index] = over[index] or (late[index] and not cut)
    ending = "; the tool ended the program there" if ended_at_cap else ""
    out_cut = ("the program printed more than %d bytes on its standard output; the tool kept the first %d and did not read the rest%s" % (
        out_cap, len(bufs[0]), ending)) if over[0] else None
    err_cut = ("the program printed more than %d bytes on its standard error; the tool kept the first %d and the last %d%s" % (
        err_cap, len(bufs[1]), len(tail), ending)) if over[1] else None
    for sentence in (out_cut, err_cut):
        if sentence:
            OUTPUT_CUT["cut"] += 1
            OUTPUT_CUT["last"] = sentence
            _note(sentence)
    err = bytes(bufs[1])
    if over[1]:
        err += b"\n[... %d bytes of standard error not kept ...]\n" % (seen[1] - len(bufs[1]) - len(tail))
    err += bytes(tail)
    if note:
        err = err + (b"\n" if err else b"") + note.encode("utf-8", "replace")
    return _output(bufs[0], out_cut), _output(err, err_cut), timed_out     # (one copy of standard output, not two)


def _close_pipe(pipe):
    try:
        if pipe is not None:
            pipe.close()
    except (OSError, ValueError):
        pass


def kill_all():
    """End every program the tool has running, with what each started. Then everything below the tool itself, which is the tool's own: a
    program forked a moment before it was entered in ACTIVE is among it. Then what an earlier program started and lost (reap_orphans).
    Returns the sentences for what could not be done (also in process_notes())."""
    notes = []
    for proc in list(ACTIVE):
        note = kill_tree(proc)
        if note:
            notes.append(note)
    stopped = {}
    try:
        note = _stop_below(os.getpid(), stopped)
        if note:
            notes.append(note)
    finally:
        _end(stopped)
    reap_orphans()
    settle(True)     # what the stop ended below the tool is reaped (bounded; settle never raises)
    return notes


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
    if "answer_a_stop" in globals():     # (a block run on its own, by a test, has no ENDS block)
        answer_a_stop(signum)
    os._exit(128 + signum)


def preflight(argv, seconds, caps=None):
    """Run a short program, bounded; (exit code or None, stdout bytes, stderr bytes, timed out). The outputs are communicate_bounded's (Output,
    held to `caps`): a program ended because a stream passed its cap has that stream's `cut` set (output_cut()) and its own exit code."""
    try:
        proc = spawn(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError as exc:
        return None, _output(b"", None), _output(describe(exc).encode("utf-8", "replace"), None), False
    ACTIVE.append(proc)
    try:
        out, err, timed_out = communicate_bounded(proc, max(1.0, seconds), caps=caps)
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


def epoch_to_iso(text):
    """A Zeek time (seconds since the epoch, with a fraction of up to nine digits) as ISO 8601 UTC, the digits kept.
    Done on integer nanoseconds, so a time before 1970 with a fraction is the instant it names."""
    m = re.fullmatch(r"(-?)(\d{1,12})(?:\.(\d{1,9}))?", text.strip())
    if not m:
        return ""
    sign, whole, frac = m.group(1), int(m.group(2)), m.group(3) or ""
    total = whole * 1_000_000_000 + int((frac + "000000000")[:9])
    if sign:
        total = -total
    seconds, rest = divmod(total, 1_000_000_000)
    try:
        stamp = datetime.datetime.fromtimestamp(seconds, tz=datetime.timezone.utc)
    except (OverflowError, OSError, ValueError):
        return ""
    digits = ("%09d" % rest)[:len(frac)] if frac else ""
    return stamp.strftime("%Y-%m-%dT%H:%M:%S") + ("." + digits if digits else "") + "Z"


def unescape(text):
    """Zeek writes a byte it cannot print, and the separator, as \\xNN; decode those, leave every other backslash alone."""
    if "\\x" not in text:
        return text
    raw = text.encode("utf-8", "surrogateescape")
    raw = re.sub(rb"\\x([0-9a-fA-F]{2})", lambda m: bytes([int(m.group(1), 16)]), raw)
    return raw.decode("utf-8", "surrogateescape")


def valid_separator(text):
    return 1 <= len(text) <= MAX_SEPARATOR


def json_depth(line):
    """The deepest nesting of brackets in a JSON text, counted without recursion and without parsing."""
    depth = deepest = 0
    in_string = escaped = False
    for ch in line:
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
        elif ch == '"':
            in_string = True
        elif ch in "[{":
            depth += 1
            deepest = max(deepest, depth)
        elif ch in "]}":
            depth -= 1
    return deepest


class BadValue(Exception):
    pass


class ReadTimeLimit(Exception):
    """The tool's own clock for reading the logs ran out."""


INTEGER = re.compile(r"-?[0-9]+")
COUNT = re.compile(r"[0-9]+")
DECIMAL = re.compile(r"-?[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?|-?inf|nan")
TIME = re.compile(r"-?[0-9]+(?:\.[0-9]{1,9})?")


def convert(value, typ, set_separator, empty, unset):
    if value == unset:
        return None
    if typ.startswith(("set[", "vector[")):
        inner = typ[typ.index("[") + 1:-1]
        if value == empty:
            return []
        return [convert(v, inner, set_separator, empty, unset) for v in value.split(set_separator)]
    if value == empty and typ == "string":
        return ""
    text = unescape(value)
    if typ in ("count", "port"):
        if not COUNT.fullmatch(text):
            raise BadValue("the value is not a %s" % typ)
        return int(text)
    if typ == "int":
        if not INTEGER.fullmatch(text):
            raise BadValue("the value is not an int")
        return int(text)
    if typ in ("double", "interval"):
        if not DECIMAL.fullmatch(text):
            raise BadValue("the value is not %s %s" % ("an" if typ == "interval" else "a", typ))
        number = float(text)
        # NaN and infinity are not JSON numbers: they stay the text Zeek wrote
        return number if number == number and number not in (float("inf"), float("-inf")) else text
    if typ == "time":
        if not TIME.fullmatch(text):
            raise BadValue("the value is not a time")
        return text
    if typ == "bool":
        if text not in ("T", "F"):
            raise BadValue("the value is not T or F")
        return text == "T"
    return text


class LogReader:
    """One Zeek log, read as a stream: records that fit the header, and a locator for those that do not."""

    def __init__(self, path, stem, limit, malformed_path, hook, deadline=None):
        self.path, self.stem, self.limit, self.malformed_path, self.hook = path, stem, limit, malformed_path, hook
        self.deadline = deadline
        self.cut = None                     # where the tool's own clock stopped the read: {"lines_read", "stopped_at_byte"}
        self.format = None
        self.fields = None
        self.types = None
        self.records = []
        self.parsed = 0
        self.malformed = []
        self.malformed_total = 0
        self.header_problem = None
        self.sep_bad = {}                   # directive -> why, for an empty or over-long separator directive; cleared by a good one
        self.lines = 0
        self.hash_keys = set()
        self.times_not_decoded = 0
        self._bad = None

    def _flag(self, line_no, offset, why, raw=None):
        self.malformed_total += 1
        if len(self.malformed) < 10:
            self.malformed.append({"log": self.stem, "line": line_no, "byte_offset": offset, "why": scrub(why)})
        if self._bad is None:
            fd = os.open(self.malformed_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
            self._bad = os.fdopen(fd, "w", encoding="utf-8")
        row = {"line": line_no, "byte_offset": offset, "why": why}
        if raw is None:
            row["raw"] = None
            row["raw_kept_in"] = "the log file itself, at this offset (the line is over %d bytes)" % MAX_LINE
        else:
            row["raw"] = raw
        self._bad.write(json.dumps(row) + "\n")

    def _clock(self, offset, mid_line=False):
        """Raises when the tool's own clock for reading the logs has run out; the line being read is not counted."""
        if self.deadline is not None and time.monotonic() > self.deadline:
            self.cut = {"lines_read": self.lines - (1 if mid_line else 0), "stopped_at_byte": offset}
            raise ReadTimeLimit()

    def read(self):
        try:
            self._read()
        finally:
            if self._bad is not None:
                self._bad.flush()
                os.fsync(self._bad.fileno())
                self._bad.close()
                self._bad = None

    def _read(self):
        separator, set_separator, empty, unset = "\t", ",", "(empty)", "-"
        offset = 0
        since = 0
        with open_regular(self.path, follow=False) as fh:
            while True:
                raw = fh.readline(MAX_LINE + 1)
                if not raw:
                    break
                since += len(raw)
                if since >= CLOCK_BYTES or self.lines & 1023 == 0:
                    since = 0
                    self._clock(offset)
                start = offset
                offset += len(raw)
                self.lines += 1
                if len(raw) > MAX_LINE and not raw.endswith(b"\n"):
                    while True:
                        more = fh.readline(MAX_LINE)
                        offset += len(more)
                        if not more or more.endswith(b"\n"):
                            break
                        self._clock(offset, True)
                    self._flag(self.lines, start, "a line longer than %d bytes was not read" % MAX_LINE)
                    continue
                line = raw.rstrip(b"\n").decode("utf-8", "surrogateescape")
                if line.startswith("#"):
                    if line.startswith("#separator"):
                        wanted = unescape(line.split(" ", 1)[1]) if " " in line else "\t"
                        if valid_separator(wanted):
                            separator = wanted
                            self.sep_bad.pop("#separator", None)
                        else:
                            self.sep_bad["#separator"] = "the #separator is empty or longer than %d characters: the columns cannot be told apart" % MAX_SEPARATOR
                    else:
                        parts = line.split(separator)
                        key, rest = parts[0], parts[1:]
                        if key in ("#set_separator", "#empty_field", "#unset_field") and rest:
                            value = unescape(rest[0])
                            if not valid_separator(value):
                                self.sep_bad[key] = "the %s is empty or longer than %d characters" % (key, MAX_SEPARATOR)
                                continue
                            self.sep_bad.pop(key, None)
                            if key == "#set_separator":
                                set_separator = value
                            elif key == "#empty_field":
                                empty = value
                            else:
                                unset = value
                        elif key == "#fields":
                            self.fields, self.types, self.header_problem = rest, None, None
                            self.format = self.format or "tsv"
                            self.hash_keys.update(h for h in HASH_FIELDS if h in rest)
                        elif key == "#types":
                            self.types = rest
                            self.header_problem = None
                            if self.fields is not None and len(rest) != len(self.fields):
                                self.header_problem = "the header has %d fields and %d types" % (len(self.fields), len(rest))
                    continue
                if not line.strip():
                    continue
                if self.fields is None:
                    if self.format in (None, "json") and line.lstrip().startswith("{"):
                        self.format = "json"
                    else:
                        self.format = self.format or "tsv"
                        self._flag(self.lines, start, "a record before any #fields header: the columns are unknown", raw=line)
                        continue
                if self.format == "json":
                    if line.count("[") + line.count("{") > MAX_JSON_DEPTH and json_depth(line) > MAX_JSON_DEPTH:
                        self._flag(self.lines, start, "a JSON line nested deeper than %d levels was not parsed" % MAX_JSON_DEPTH, raw=line)
                        continue
                    try:
                        record = json.loads(line)
                    except (ValueError, RecursionError) as exc:
                        self._flag(self.lines, start, "not valid JSON (%s)" % str(exc)[:80], raw=line)
                        continue
                    if not isinstance(record, dict):
                        self._flag(self.lines, start, "a JSON value that is not an object", raw=line)
                        continue
                    self.hash_keys.update(h for h in HASH_FIELDS if h in record)
                    if isinstance(record.get("ts"), (int, float)) and not isinstance(record.get("ts"), bool) and "e" not in repr(record["ts"]):
                        record["ts_utc"] = epoch_to_iso(repr(record["ts"]))
                        if not record["ts_utc"]:
                            self.times_not_decoded += 1
                else:
                    if self.sep_bad:
                        self._flag(self.lines, start, "; ".join(self.sep_bad.values()), raw=line)
                        continue
                    cols = line.split(separator)
                    if self.header_problem:
                        self._flag(self.lines, start, self.header_problem, raw=line)
                        continue
                    if len(cols) != len(self.fields):
                        self._flag(self.lines, start, "%d columns, and the header names %d fields" % (len(cols), len(self.fields)), raw=line)
                        continue
                    types = self.types or ["string"] * len(self.fields)
                    record = {}
                    try:
                        for name, typ, value in zip(self.fields, types, cols):
                            record[name] = convert(value, typ, set_separator, empty, unset)
                            if typ == "time" and value != unset:
                                record[name + "_utc"] = epoch_to_iso(value)
                                if not record[name + "_utc"]:
                                    self.times_not_decoded += 1
                    except BadValue as exc:
                        self._flag(self.lines, start, "field %s: %s" % (name, exc), raw=line)
                        continue
                self.parsed += 1
                self.hook(self.stem, record, self)
                if len(self.records) < self.limit:
                    self.records.append(record)


def withheld_text(length):
    return "<withheld %d characters>" % length


# A string that is an identifier, a hash, a fingerprint, an address or a time stays as written; every other string is
# scrubbed, since a record's free text (a notice's msg, a weird's addl, a file name, a header) can quote anything. What
# counts as one of those is decided per log and per kind of value, not by a bare field name: `service` is a list of
# analyzer names in conn.log and a service principal name from the wire in kerberos.log.
KEEP_FIELD = re.compile(r"(?i)^(ts|uid|fuid|uids|fuids|conn_uids|md5|sha1|sha256|ja3s?|ja4[a-z0-9_]*|hassh[a-z0-9_]*|community_id|proto)$")
KEEP_BY_LOG = {"conn": frozenset(("service", "conn_state", "history"))}
ADDRESS_FIELD = re.compile(r"(?i)^(id\.(orig|resp)_h|[a-z_]*_h)$")
DERIVED_TIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$")
TS_TEXT = re.compile(r"^-?[0-9]+(?:\.[0-9]{1,9})?$")


def is_address(text):
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def kept_as_written(stem, key, value):
    """Is this value one of the typed kinds that is printed as written: a number or a bool (never text), an identifier or
    hash Zeek made, a time, an IP address in an address field."""
    if isinstance(value, list):
        return all(kept_as_written(stem, key, v) for v in value)
    if isinstance(value, dict):
        return False
    if not isinstance(value, str):
        return True
    if key == "ts":
        return bool(TS_TEXT.match(value)) or bool(DERIVED_TIME.match(value))
    if key.endswith("_utc"):
        return bool(DERIVED_TIME.match(value))
    if KEEP_FIELD.match(key) or key in KEEP_BY_LOG.get(stem, ()):
        return True
    return bool(ADDRESS_FIELD.match(key)) and is_address(value)


def shown_url(url):
    """A URL as printed: the block's own rule for user-info, token-shaped path text, query values and fragment, and the
    authority through the same host rule as every other string (a token in a sub-domain is withheld)."""
    # Over TEXT_LIMIT the query and fragment are withheld whole, by their length (the block's own rule for a text over the limit): the block
    # splits a query pair by pair, so a megabyte of `&` there costs seconds a URL. What is kept is the scheme, host and path part.
    cut = min((i for i in (url.find("?"), url.find("#")) if i >= 0), default=len(url)) if len(url) > TEXT_LIMIT else len(url)
    if cut < len(url):
        return shown_url(url[:cut]) + url[cut] + _withheld("over-long query or fragment", len(url) - cut - 1, "urls")
    out = redact_url(url)
    m = re.match(r"^((?:[A-Za-z][A-Za-z0-9+.-]*:)?//)([^/?#]*)(.*)$", out, re.S)
    if not m:
        return out
    prefix, _, host = m.group(2).rpartition("@")
    return m.group(1) + (prefix + "@" if prefix else "") + (scrub(host) if host and not is_address(host.strip("[]")) else host) + m.group(3)


def _scrub_value(value, withheld):
    if isinstance(value, str):
        if re.search(r"://|^//", value) or (value.startswith("/") and "?" in value):
            shown = shown_url(value)
            withheld["urls"] += 1 if shown != value else 0
        else:
            shown = scrub(value)
            withheld["text"] += 1 if shown != value else 0
        return shown
    if isinstance(value, list):
        return [_scrub_value(v, withheld) for v in value]
    if isinstance(value, dict):
        return {scrub(str(k)): _scrub_value(v, withheld) for k, v in value.items()}
    return value


def inline_copy(stem, record, withheld):
    """The record as it may be returned inline: secret-named fields withheld, every other string scrubbed, URLs redacted."""
    out = {}
    pass_command = isinstance(record.get("command"), str) and record["command"].upper() == "PASS"
    short = None
    if stem == "files":
        sizes = [v for v in (record.get("total_bytes"), record.get("seen_bytes")) if isinstance(v, int)]
        short = bool(sizes) and min(sizes) < SHORT_OBJECT
    for key, value in record.items():
        if value is None or value == [] or value == "":
            out[key] = value
        elif SECRET_FIELD.search(key) or (pass_command and key == "arg"):
            out[key] = withheld_text(len(str(value)))
            withheld["fields"] += 1
        elif short and key in HASH_FIELDS:
            out[key] = "<withheld: the object is shorter than %d bytes>" % SHORT_OBJECT
            withheld["short_hashes"] += 1
        elif URL_FIELD.match(key) and isinstance(value, str):
            out[key] = shown_url(value)
            withheld["urls"] += 1
        elif kept_as_written(stem, key, value):
            out[key] = value
        else:
            out[key] = _scrub_value(value, withheld)
    return out


PROGRESS = {"stage": "arguments", "out_dir": None}
STOP_LISTED = 200       # logs the answer to a stop names
STOP_COUNTED = 100_000  # logs it counts before it says "more than"


def last_word(signum):
    """What a stopped run says on stdout: partial, which stage it was in, and which logs were on disk."""
    out_dir = PROGRESS.get("out_dir")
    logs, total = [], 0
    try:
        with os.scandir(out_dir) if out_dir else contextlib.nullcontext([]) as entries:
            for entry in entries:
                if not entry.name.endswith(".log"):
                    continue
                total += 1
                if len(logs) < STOP_LISTED:
                    logs.append(entry.name[:-4])
                elif total > STOP_COUNTED:
                    break
    except OSError:
        pass
    # the names are the engine's: one shaped like a token (a log not yet set aside by name, or one that was) is the word withheld, never the name
    logs = sorted(("withheld" if (token_shaped(n) or scrub(n) != n) else n) for n in logs)
    print(json.dumps({"tool": TOOL, "parser": PARSER, "status": "partial", "ok": False,
                      "status_basis": "the tool was stopped by signal %d while it was %s; Zeek, if it was running, was killed with what it had started, and the logs it had written are whole files only up to the point it was stopped" % (signum, PROGRESS["stage"]),
                      "interrupted_by_signal": signum, "stage": PROGRESS["stage"], "out_dir": out_dir, "logs_written_so_far": logs,
                      "logs_written_so_far_total": total if total <= STOP_COUNTED else None}), flush=True)


def answer_out(text):
    """Print the final answer as one unit a stop signal cannot cut or follow: signals are held while it is written and there is no last
    word to add to it, so a signal that arrives during or after it is not answered (the shared ENDS block): the call ends with this one
    document and its own exit code."""
    held = (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)
    signal.pthread_sigmask(signal.SIG_BLOCK, held)
    try:
        hold_stop_signals()
        STATE["last_word"] = None
        print(text, flush=True)
    finally:
        signal.pthread_sigmask(signal.SIG_UNBLOCK, held)


def program_group_problems(what):
    """Sentences for `problems` from the shared process block's verdict, for an answer that reports `what` (files a program wrote). A process settle() ended means
    those files hold what it had written when it was ended; where the absence of one cannot be proven (not Linux, PR_SET_CHILD_SUBREAPER refused) they cannot be shown
    to be final. process_apply() then keeps the answer from `complete`, and a line under `problems` says why."""
    verdict = process_verdict()
    found = []
    if verdict["left_behind"]:
        found.append("a program left %d process(es) running after it ended (in the tool's process group, in a session of its own, or after a double fork); the shared process block "
                     "stopped, killed and reaped them before %s were read, so what they would still have written is missing from %s" % (verdict["left_behind"], what, what))
    for why in verdict["unproven"]:
        found.append("%s: %s cannot be shown to be final" % (why, what))
    return found


DRY_LIST_NAME = "network-forensics.dry-run.zeek"
DRY_MARK = "network-forensics-dry-run"
DRY_LIST_SCRIPT = ("# Written by zeek_run (network-forensics pack) for dry_run: it prints each script Zeek loads, once, and reads no capture.\n"
                   "event zeek_script_loaded(path: string, level: count)\n"
                   "    {\n"
                   "    print fmt(\"" + DRY_MARK + "\\t%d\\t%s\", level, path);\n"
                   "    }\n")
DRY_LISTED = re.compile(re.escape(DRY_MARK) + r"\t(\d{1,6})\t(.*)")
DRY_LINE_READ = 1 << 12     # the part of one line of Zeek's output that is read: a script path is shorter
DRY_KEPT = 200_000          # listed scripts kept for the policy check; every one is in zeek-dry-run.stdout
DRY_SHOWN = 200             # listed scripts answered inline
DRY_FAILURES = 10
DRY_FAILURE_CHARS = 300
DRY_FAILURE_READ = 1 << 16
DRY_TAIL_SEGMENTS = 12
DRY_FAILURE = re.compile(r"(?i)\b(error|fatal|can't find|cannot|failed)\b")


def read_listing(path, deadline):
    """(listed script paths, how many lines were listed, lines cut to DRY_LINE_READ, the clock cut). Each line is read in pieces: one hostile line is never held whole."""
    kept, total, cut_lines, clock_cut = [], 0, 0, False
    with open_regular(path, follow=False) as fh:
        n = 0
        while True:
            raw = fh.readline(DRY_LINE_READ)
            if not raw:
                break
            n += 1
            if n & 1023 == 0 and time.monotonic() > deadline:
                clock_cut = True
                break
            if not raw.endswith(b"\n"):
                more = fh.readline(DRY_LINE_READ)
                if more:
                    cut_lines += 1
                    while not more.endswith(b"\n"):      # the rest of a long line is passed over, in pieces
                        more = fh.readline(DRY_LINE_READ)
                        if not more:
                            break
                        if time.monotonic() > deadline:
                            clock_cut = True
                            break
                    if clock_cut:
                        break
            m = DRY_LISTED.fullmatch(raw.decode("utf-8", "replace").rstrip("\r\n"))
            if m:
                total += 1
                if len(kept) < DRY_KEPT:
                    kept.append(m.group(2))
    return kept, total, cut_lines, clock_cut


def withheld_cut(text, name):
    """A line of the engine's output as the answer shows it: the whole line goes through the block first, and only then is it cut, so that a cut never
    leaves a piece of a secret too short for the block to recognise."""
    shown = scrub(text)
    return shown[:DRY_FAILURE_CHARS] + (" ...(%d more characters in %s)" % (len(shown) - DRY_FAILURE_CHARS, name) if len(shown) > DRY_FAILURE_CHARS else "")


def first_failures(paths, deadline):
    """(the first DRY_FAILURES lines of Zeek's own output that name an error or a failure, how many there were, whether the clock cut the reading)."""
    shown, total, cut = [], 0, False
    for path in paths:
        try:
            with open_regular(path, follow=False) as fh:
                n = 0
                while True:
                    raw = fh.readline(DRY_FAILURE_READ)
                    if not raw:
                        break
                    n += 1
                    if n & 1023 == 0 and time.monotonic() > deadline:
                        cut = True
                        break
                    text = raw.decode("utf-8", "replace").strip()
                    if DRY_FAILURE.search(text):
                        total += 1
                        if len(shown) < DRY_FAILURES:
                            shown.append({"from": os.path.basename(path), "line": n,
                                          "text": withheld_cut(text, os.path.basename(path))})
        except OSError:
            continue
        if cut:
            break
    return shown, total, cut


def write_new(path, data):
    """A file of this run's own, new, private and whole; the problem as a sentence (None when written) when the write is refused."""
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        return None
    except OSError as exc:
        try:
            os.unlink(path)
        except OSError:
            pass
        return describe(exc)


def dry_run_receipt(c):
    """dry_run: the engine receipt without a capture. Zeek is started once, with the policy script and a small script of this tool's that prints each script
    Zeek loads, and with no capture and no interface: nothing is read, nothing listens, and everything is written under out_dir. complete says that
    the version was read, the help was kept, Zeek exited 0 and listed the scripts it loaded, and every requested policy is among them."""
    started, out_dir, binary = c["started"], c["out_dir"], c["binary"]
    deadline = min(started + c["timeout"], started + MANIFEST_SECONDS - READ_MARGIN)
    try:     # ZEEK_RUN_DRY_SECONDS (seconds from here) exists for the tests, as ZEEK_RUN_READ_SECONDS does for the reading of the logs
        deadline = time.monotonic() + float(os.environ["ZEEK_RUN_DRY_SECONDS"])
    except (KeyError, ValueError):
        pass
    problems = []

    def remaining():
        return deadline - time.monotonic()

    if c["zeek_version"] is None:
        problems.append("`zeek --version` %s, so the version of the engine is not recorded" % ("did not finish" if c["version_timed_out"] else "exited %s" % c["version_code"]))
    PROGRESS["stage"] = "reading the engine's help"
    help_code, help_out, help_err, help_timed = preflight([binary, "--help"], max(1.0, min(30, remaining())), caps=(1 << 20, 1 << 20))
    help_path = os.path.join(out_dir, "zeek-help.txt")
    help_problem = write_new(help_path, help_out + (b"\n--- stderr ---\n" + help_err if help_err else b""))
    if help_problem:
        problems.append("the engine's help could not be kept in a file (%s)" % help_problem)
    if help_timed or help_code is None:
        problems.append("`zeek --help` %s" % ("did not finish" if help_timed else "did not run"))
    elif output_cut(help_out, help_err):
        problems.append("`zeek --help` printed past its cap and was ended (%s): zeek-help.txt holds what was kept" % output_cut(help_out, help_err))

    list_path = os.path.join(out_dir, DRY_LIST_NAME)
    list_problem = write_new(list_path, DRY_LIST_SCRIPT.encode("utf-8"))
    if list_problem:
        problems.append("the script that lists the loaded scripts could not be written (%s)" % list_problem)
    stdout_path, stderr_path = os.path.join(out_dir, "zeek-dry-run.stdout"), os.path.join(out_dir, "zeek-dry-run.stderr")
    argv = [binary] + ([os.path.abspath(c["script_path"])] if c["script_path"] else []) + [os.path.abspath(list_path)]     # the program runs in out_dir: absolute names
    code, timed_out = None, False
    listed, listed_total, listed_cut_lines, listing_cut = [], 0, 0, False
    if not list_problem:
        if remaining() < 1:
            problems.append("the tool's own clock ran out before Zeek was started")
        else:
            PROGRESS["stage"] = "loading the policy"
            try:
                code, timed_out = run_to_files(argv, stdout_path, stderr_path, max(1.0, min(120, remaining())), cwd=out_dir)
            except OSError as exc:
                problems.append("zeek could not be run (%s)" % describe(exc))
            else:
                if timed_out:
                    problems.append("zeek did not finish in time and was killed with everything it had started")
                elif code != 0:
                    problems.append("zeek exited %s while loading the policy (first_failures)" % code)
                try:
                    listed, listed_total, listed_cut_lines, listing_cut = read_listing(stdout_path, deadline)
                except OSError as exc:
                    problems.append("the listing of the loaded scripts could not be read (%s)" % describe(exc))
                if listing_cut:
                    problems.append("the tool's own clock ran out while the listing was read: the scripts counted are those of the lines read")
                if code == 0 and not timed_out and listed_total == 0:
                    problems.append("Zeek exited 0 but listed no script: this build did not raise zeek_script_loaded, so which scripts the policy loads is not shown")
    failures, failure_total, failures_cut = first_failures([stderr_path, stdout_path], deadline) if code is not None or timed_out else ([], 0, False)
    if failures_cut:
        problems.append("the tool's own clock ran out while Zeek's output was searched for failures: the list and its count are those of the lines read")

    tails = set()
    for entry in listed:
        segments = entry.split("/")
        for k in range(1, min(len(segments), DRY_TAIL_SEGMENTS) + 1):
            tails.add("/".join(segments[-k:]))
    requested = []
    for name in c["policies"]:
        if not listed_total:
            requested.append({"policy": name, "loaded": None})
            continue
        found = any(("%s%s" % (name, tail)) in tails for tail in (".zeek", ".bro", "/__load__.zeek", "/__load__.bro")) if len(name.split("/")) + 1 <= DRY_TAIL_SEGMENTS else False
        requested.append({"policy": name, "loaded": found})
        if not found:
            problems.append("the policy %s is not among the scripts Zeek listed" % scrub(name))

    log_files, names_left = [], 0
    try:
        written, names_left = c["log_names"].shown([n for n in os.listdir(out_dir) if n.endswith(".log")], deadline)
        log_files = [n[:-4] for n in written]
    except OSError as exc:
        problems.append("the names of the logs the dry run wrote could not be set aside (%s)" % describe(exc))
    if names_left:
        problems.append("%d log(s) with a token-shaped name were not set aside under a withheld name before the tool's own clock ran out: they are whole in out_dir" % names_left)
    c["log_names"].close()
    for name in os.listdir(out_dir):
        full = os.path.join(out_dir, name)
        try:
            if not os.path.islink(full):
                os.chmod(full, 0o700 if os.path.isdir(full) else 0o600)
        except OSError:
            pass
    problems.extend(program_group_problems("the listing and the logs"))
    ok = not problems
    basis = ("Zeek exited 0, listed the scripts it loaded, and every requested policy is among them; no capture was read" if ok else
             "; ".join(problems[:6]) + (" (and %d more, all in problems)" % (len(problems) - 6) if len(problems) > 6 else "") + ": no capture was read")
    answer = {
        "tool": TOOL, "parser": PARSER, "dry_run": True,
        "status": "complete" if ok else "partial", "status_basis": basis,
        "out_dir": out_dir,
        "identities": {
            "policy_script": {"path": c["script_path"], "sha256": c["script_sha"], "bytes": c["script_bytes"], "policies": len(c["policies"]),
                              "note": ("no policy script was written: Zeek runs with its base scripts only" if not c["policies"] else
                                       "the script this tool writes for a run; the same bytes as a run writes for these policies")},
            "listing_script": {"path": list_path if not list_problem else None, "note": "this tool's own script that prints each script Zeek loads; a run does not load it"},
            "engine": {"zeek_version": c["zeek_version"], "help": help_path if not help_problem else None},
            "rule_count": None,
            "rule_count_note": "not applicable: this tool loads Zeek scripts, not signature rules (no sid, rev or action exists to count)",
        },
        "effective_configuration": {
            "command": argv, "exit_code": code, "timed_out": timed_out, "stdout": stdout_path if code is not None or timed_out else None,
            "stderr": stderr_path if code is not None or timed_out else None,
            "checksum_validation": c["checksum_validation"],
            "checksum_note": "no capture is read, so checksums are not looked at; the setting is recorded as a run would use it (-C unless checksum_validation is true)",
            "loaded_scripts": {"total": listed_total, "shown": min(len(listed), DRY_SHOWN), "scripts": [scrub(p) for p in listed[:DRY_SHOWN]],
                               "file": stdout_path if listed_total else None, "lines_cut": listed_cut_lines,
                               "note": "as Zeek printed them from its zeek_script_loaded event, in the order given; the inline list is the first %d and the file holds every line" % DRY_SHOWN},
        },
        "script_load_status": {"requested": requested, "first_failures": failures, "failure_lines_total": failure_total,
                               "failures_note": "lines of Zeek's own output that name an error or a failure, the first %d, each cut to %d characters and passed through the block; every line is "
                                                "in the files named under effective_configuration%s" % (DRY_FAILURES, DRY_FAILURE_CHARS,
                                                    "; Zeek exited 0, so these are its messages and not a failed load" if code == 0 and failure_total else ""),
                               "note": "a policy is loaded when Zeek listed a script of that name (the .zeek file or its __load__.zeek); null means Zeek listed nothing, so nothing is shown either way"},
        "log_outputs": {"directory": out_dir, "logs_written_by_the_dry_run": log_files,
                        "format": "Zeek's own default writer (tab-separated ASCII) unless a loaded script changes it; this mode does not read it from the scripts",
                        "streams_listed": False,
                        "note": "which logs a run writes depends on the scripts loaded and on the traffic, and a dry run has no traffic: it does not list them. "
                                "logs_written_by_the_dry_run are the .log files Zeek left in out_dir without one, and a run names what it wrote."},
        "arguments_not_used": c["unused"],
        "not_covered": [
            "No ruleset or signature file ships with the pack and none is fetched; this tool loads Zeek scripts by name from Zeek's own path.",
            "There is no automatic download and no package or script update; this mode downloads nothing.",
            "No capture was read: nothing here says what the scripts would log, or that any log would have a record.",
            "The scripts are those Zeek printed; whether they behave as their names suggest is a property of the build.",
            "The log streams a run would write are not listed (see log_outputs).",
        ],
        "problems": problems,
        "ok": ok,
        "withheld": dict(COUNTS),
        "log_names_withheld": c["log_names"].count,
        "log_names_file": c["log_names"].path,
        "out_dir_contains_secret_values": True,
        "out_dir_note": ("The directory holds Zeek's help, its output while it loaded the policy and the scripts this tool wrote. It is private (mode 0700, files 0600). "
                         "Run this tool as a job with secret_output: true so the job output is sealed."),
    }
    process_apply(answer)
    answer_out(json.dumps(answer, indent=2))
    return 0


def main():
    started = time.monotonic()
    STATE["last_word"] = last_word
    install_signal_handlers()
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    if not isinstance(args, dict):
        fail("arguments must be a JSON object")
    dry_run = args.get("dry_run", False)
    if not isinstance(dry_run, bool):
        fail("dry_run must be true or false")
    path = args.get("path")
    if dry_run:
        if path is not None:
            fail("path is not taken with dry_run: a dry run reads no capture (it gives the engine receipt of the version and the policy); leave path out, or leave dry_run out to run a capture")
    elif not isinstance(path, str) or not path:
        fail("path is required: a capture file")
    elif not os.path.isfile(path):
        fail("no such file", path=path)
    out_dir = args.get("out_dir")
    if not isinstance(out_dir, str) or not out_dir:
        fail("out_dir is required: a directory under work/ (in a job, under $OUT) for Zeek's logs")
    out_dir = resolve_output(out_dir, "out_dir")
    PROGRESS["out_dir"] = out_dir
    try:
        if os.path.exists(out_dir) and holds_files(out_dir):
            fail("out_dir already holds files; stale Zeek logs would contaminate the result", out_dir=out_dir)
    except OSError as exc:
        fail("out_dir cannot be listed (%s)" % describe(exc), out_dir=out_dir)
    log_names = LogNames(out_dir)
    limit = args.get("limit", 200)
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        fail("limit must be a positive integer")
    timeout = args.get("timeout_seconds", DEFAULT_TIMEOUT)
    if not isinstance(timeout, int) or isinstance(timeout, bool) or not 10 <= timeout <= MAX_TIMEOUT:
        fail("timeout_seconds must be an integer from 10 to %d: kept under the 1200-second limit so that this tool stops Zeek itself and the "
             "limit never has to" % MAX_TIMEOUT)
    wanted_arg = args.get("logs")
    if wanted_arg is not None and (not isinstance(wanted_arg, list) or any(not isinstance(n, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", n) for n in wanted_arg)):
        fail("logs must be a list of log names such as [\"conn\", \"dns\"]")
    wanted = set(wanted_arg or [])
    policies = args.get("policies", DEFAULT_POLICIES)
    if not isinstance(policies, list) or any(not isinstance(p, str) for p in policies):
        fail("policies must be a list of Zeek policy names, such as policy/frameworks/files/hash-all-files")
    for name in policies:
        segments = name.split("/")
        if (not re.fullmatch(r"[A-Za-z0-9_./-]{1,200}", name) or name.startswith("/") or ".." in segments or "." in segments or "" in segments
                or segments[0] in ("inputs", "work", "store")):
            fail("a policy is a name Zeek resolves from its own script path, not a path or anything from the evidence: refused", policy=name)
    checksum_validation = args.get("checksum_validation", False)
    if not isinstance(checksum_validation, bool):
        fail("checksum_validation must be true or false")

    binary = shutil.which("zeek") or shutil.which("bro")
    if not binary:
        fail("zeek is not on PATH",
             install="brew install zeek, or the Zeek project's own packages "
                     "(https://software.opensuse.org/download.html?project=security%3Azeek&package=zeek): "
                     "zeek is in neither Debian's nor Ubuntu's archive",
             note="Without it, pcap_summary still answers the first questions about a "
                  "capture. Say in the report which route was taken.")
    os.umask(0o077)
    version_code, version_out, version_err, version_timed_out = preflight([binary, "--version"], min(30, timeout), caps=(1 << 16, 1 << 16))
    version_text = (version_out + version_err).decode("utf-8", "replace").strip().splitlines()
    zeek_version = version_text[0].strip() if version_code == 0 and version_text and not output_cut(version_out, version_err) else None

    try:
        os.makedirs(out_dir, mode=0o700, exist_ok=True)
        os.chmod(out_dir, 0o700)
    except OSError as exc:
        fail("the output directory could not be created (%s)" % describe(exc), out_dir=out_dir)
    script_path = script_sha = None
    argv = [binary]
    if not checksum_validation:
        argv.append("-C")
    if not dry_run:
        argv += ["-r", os.path.abspath(path)]
    if policies:
        script_path = os.path.join(out_dir, SCRIPT_NAME)
        text = ("# Written by zeek_run (network-forensics pack): the policies the caller asked for, loaded explicitly.\n"
                + "".join("@load %s\n" % p for p in policies))
        try:
            fd = os.open(script_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(text)
        except OSError as exc:
            fail("the policy script could not be written (%s)" % describe(exc), out_dir=out_dir)
        script_sha = hashlib.sha256(text.encode("utf-8")).hexdigest()
        argv.append(os.path.abspath(script_path))
    if dry_run:
        return dry_run_receipt(dict(
            started=started, timeout=timeout, binary=binary, out_dir=out_dir, zeek_version=zeek_version, version_code=version_code, version_timed_out=version_timed_out,
            policies=policies, script_path=script_path, script_sha=script_sha, script_bytes=len(text.encode("utf-8")) if policies else None,
            checksum_validation=checksum_validation, log_names=log_names, unused=sorted(k for k in ("logs", "limit") if k in args)))
    stdout_path = os.path.join(out_dir, "zeek.stdout")
    stderr_path = os.path.join(out_dir, "zeek.stderr")
    PROGRESS["stage"] = "running Zeek"
    try:
        code, timed_out = run_to_files(argv, stdout_path, stderr_path, timeout - (time.monotonic() - started), cwd=out_dir)
    except OSError as exc:
        fail("zeek could not be run (%s)" % describe(exc), command=argv)
    if timed_out:
        try:
            partial = [n[:-4] for n in log_names.shown([n for n in os.listdir(out_dir) if n.endswith(".log")], started + MANIFEST_SECONDS - READ_MARGIN)[0]]
        except OSError:
            partial = []
        partial_total, partial = len(partial), partial[:STOP_LISTED]
        fail("zeek did not finish in time and was killed with everything it had started", after_seconds=timeout, command=argv,
             partial_output=out_dir, logs_written_so_far=partial, logs_written_so_far_total=partial_total, stdout=stdout_path, stderr=stderr_path)

    try:
        written, names_left = log_names.shown([n for n in os.listdir(out_dir) if n.endswith(".log")], started + MANIFEST_SECONDS - READ_MARGIN)
    except OSError as exc:
        fail("the names of the logs could not be set aside (%s)" % describe(exc), out_dir=out_dir)
    if not written:
        fail("zeek wrote no logs", exit_code=code, command=argv, stdout=stdout_path, stderr=stderr_path)
    chmod_cut = False
    for name in os.listdir(out_dir):
        if time.monotonic() > started + MANIFEST_SECONDS - READ_MARGIN:
            chmod_cut = True
            break          # the tool's own clock: the files left keep the modes the engine gave them, and the answer says so
        try:
            os.chmod(os.path.join(out_dir, name), 0o700 if os.path.isdir(os.path.join(out_dir, name)) else 0o600)
        except OSError:
            pass

    PROGRESS["stage"] = "reading the logs"
    # Reading the logs has its own end, the same for every log: the manifest's limit less READ_MARGIN, counted from the start of the tool, so
    # what the preflight and the engine used is already out of it. ZEEK_RUN_READ_SECONDS (seconds from here) exists for the tests.
    try:
        read_seconds = float(os.environ.get("ZEEK_RUN_READ_SECONDS", ""))
    except ValueError:
        read_seconds = None
    read_deadline = (time.monotonic() + read_seconds) if read_seconds is not None else started + MANIFEST_SECONDS - READ_MARGIN
    logs_not_read, logs_cut = [], {}
    withheld = {"fields": 0, "urls": 0, "text": 0, "short_hashes": 0}
    diagnostics = {"reporter": {"records": 0, "levels": {}, "first_messages": []},
                   "weird": {"records": 0, "by_name": {}, "names_over_cap": 0},
                   "capture_loss": {"records": 0, "gaps": 0, "acks": 0, "max_percent_lost": None}}
    files = {"records": 0, "records_with_a_hash": 0}

    def hook(stem, record, _reader):
        if stem == "reporter":
            d = diagnostics["reporter"]
            d["records"] += 1
            level = str(record.get("level"))
            d["levels"][level] = d["levels"].get(level, 0) + 1
            if len(d["first_messages"]) < 5:
                message = scrub(str(record.get("message", "")))
                d["first_messages"].append(message if len(message) <= 500 else
                                           message[:500] + " ...(%d characters not shown; the whole message is in reporter.log)" % (len(message) - 500))
        elif stem == "weird":
            d = diagnostics["weird"]
            d["records"] += 1
            name = scrub(str(record.get("name")))      # the names of weird events are Zeek's, but a few carry wire text
            if name in d["by_name"] or len(d["by_name"]) < MAX_NAMES:
                d["by_name"][name] = d["by_name"].get(name, 0) + 1
            else:
                d["names_over_cap"] += 1
        elif stem == "capture_loss":
            d = diagnostics["capture_loss"]
            d["records"] += 1
            for k in ("gaps", "acks"):
                if isinstance(record.get(k), int):
                    d[k] += record[k]
            pct = record.get("percent_lost")
            if isinstance(pct, (int, float)) and (d["max_percent_lost"] is None or pct > d["max_percent_lost"]):
                d["max_percent_lost"] = pct
        elif stem == "files":
            files["records"] += 1
            if any(record.get(h) not in (None, "", []) for h in HASH_FIELDS):
                files["records_with_a_hash"] += 1

    logs, problems, malformed, malformed_files, empty = {}, [], [], {}, []
    if names_left:
        problems.append({"why": "%d log(s) with a token-shaped name were not set aside under a withheld name before the tool's own clock ran out: they are whole in out_dir under the "
                                "engine's names, not read, and not named here" % names_left})
    if chmod_cut:
        problems.append({"why": "the tool's own clock ran out while the modes of the files in out_dir were set: those not reached keep the modes the engine gave them"})
    hash_fields = []
    total_malformed = 0
    times_not_decoded = 0
    for name in written:
        stem = name[:-4]
        log_path = os.path.join(out_dir, name)
        inline = (not wanted) or stem in wanted
        if time.monotonic() > read_deadline:
            logs_not_read.append(stem)
            problems.append({"log": stem, "why": "not read: the tool's own clock for reading the logs ran out before it; the file is whole in out_dir"})
            continue
        reader = LogReader(log_path, stem, limit if inline else 0, os.path.join(out_dir, "malformed-%s.jsonl" % re.sub(r"[^A-Za-z0-9_.-]", "_", stem)), hook,
                           read_deadline)
        try:
            reader.read()
        except ReadTimeLimit:
            logs_cut[stem] = reader.cut
            problems.append({"log": stem, "why": "read only to line %d (stopped at byte %d): the tool's own clock for reading the logs ran out; the file is whole in out_dir, "
                                                 "and the records, counts and diagnostics here are those of the lines read" % (reader.cut["lines_read"], reader.cut["stopped_at_byte"])})
        except OSError as exc:
            problems.append({"log": stem, "why": describe(exc)})
            continue
        if stem == "files":
            hash_fields = [h for h in HASH_FIELDS if h in reader.hash_keys]
        times_not_decoded += reader.times_not_decoded
        total_malformed += reader.malformed_total
        if reader.malformed_total:
            malformed.extend(reader.malformed)
            malformed_files[stem] = "malformed-%s.jsonl" % re.sub(r"[^A-Za-z0-9_.-]", "_", stem)
        if reader.parsed == 0 and not reader.malformed_total and reader.cut is None:
            empty.append(stem)
        if inline:
            logs[stem] = {"file": log_path, "format": reader.format, "fields": reader.fields, "types": reader.types,
                          "records": [inline_copy(stem, r, withheld) for r in reader.records],
                          "returned": len(reader.records), "total": reader.parsed, "omitted": reader.parsed - len(reader.records),
                          "malformed": reader.malformed_total, "lines": reader.lines,
                          "read_to_the_end": reader.cut is None,
                          **({"header_problem": reader.header_problem} if reader.header_problem else {})}
    not_written = sorted(n for n in wanted if n + ".log" not in written)
    hashes_produced = files["records_with_a_hash"] > 0
    if zeek_version is None:
        problems.append({"why": "`zeek --version` %s, so the version of the engine that wrote these logs is not recorded" %
                         ("did not finish" if version_timed_out else "printed past its cap and was ended" if output_cut(version_out, version_err) else "exited %s" % version_code)})
    group_problems = program_group_problems("the logs")      # a process Zeek left behind (ended before the logs were read), or a host that cannot show there was none
    problems.extend({"why": line} for line in group_problems)
    ok = code == 0 and not problems and not total_malformed
    if ok:
        basis = "Zeek exited 0, every log it wrote was read through, and every line fit its header"
    else:
        reasons = []
        if code != 0:
            reasons.append("Zeek exited %s" % code)
        if problems:
            reasons.append("%d problem(s) (problems names each)" % len(problems))
        if logs_cut or logs_not_read:
            reasons.append("the tool's own clock for reading the logs ran out (%d log(s) read in part, %d not read)" % (len(logs_cut), len(logs_not_read)))
        if total_malformed:
            reasons.append("%d record(s) did not fit their header (each is kept raw in a malformed-<log>.jsonl file)" % total_malformed)
        basis = "; ".join(reasons) + (": the logs are in out_dir, but a process Zeek left behind was ended, or none can be ruled out, so they are not shown to be final (problems), and the records that were read are in the answer"
                                      if group_problems else
                                      ": the logs are whole in out_dir and the records that were read are in the answer")
    answer = {
        "tool": TOOL, "parser": PARSER,
        "status": "complete" if ok else "partial", "status_basis": basis,
        "path": path, "out_dir": out_dir,
        "zeek_version": zeek_version,
        "command": argv,
        "checksum_validation": checksum_validation,
        "checksum_note": ("checksums were validated" if checksum_validation else
                          "checksums were NOT validated (-C): a packet with a bad checksum, such as one captured on an offloading interface, "
                          "was processed like any other"),
        "policy": {"requested": policies, "script": script_path, "script_sha256": script_sha,
                   "note": ("no policy script was loaded: Zeek ran with its base scripts only" if not policies else
                            "the script loads the named policies explicitly; that it ran, and that the installed build has them, is shown by the logs "
                            "and by exit_code, not assumed")},
        "exit_code": code,
        "logs_written": [n[:-4] for n in written],
        "log_names_withheld": log_names.count,
        "log_names_file": log_names.path,
        "logs_requested_not_written": not_written,
        "logs_empty": empty,
        "reading_cut_by_its_clock": bool(logs_cut or logs_not_read),
        "logs_read_in_part": logs_cut or None,
        "logs_not_read": logs_not_read or None,
        "logs": logs,
        "problems": problems,
        "malformed_records": total_malformed,
        "malformed": malformed,
        "malformed_files": malformed_files,
        "hashes_produced": hashes_produced,
        "hash_fields": hash_fields,
        "hash_note": ("hash_fields are the hash columns files.log has or its JSON records use; on a real install the columns can exist whether or not "
                      "any analyzer filled them, so only hashes_produced (a record with a value) says a hash exists, and which hash functions the "
                      "loaded policy computes is a property of the build"),
        "times_not_decoded": times_not_decoded,
        "files_log": {"written": "files.log" in written, "records": files["records"], "records_with_a_hash": files["records_with_a_hash"]},
        "engine_diagnostics": {**diagnostics,
                               "capture_loss_note": None if "capture_loss.log" in written else
                               "capture_loss.log was not written: Zeek writes it only when its capture-loss policy is loaded, so its absence says nothing about loss"},
        "withheld": {"inline_records": withheld, "shared_block": dict(COUNTS)},
        "stdout": stdout_path,
        "stderr": stderr_path,
        "ok": ok,
        "out_dir_contains_secret_values": True,
        "out_dir_note": ("Zeek's logs can carry credentials, cookies, community strings and request URIs, depending on the scripts loaded. The "
                         "directory is private (mode 0700, files 0600). Run this tool as a job with secret_output: true so the job output is "
                         "sealed. Inline records withhold secret-named fields and the hash of an object under 128 bytes, redact URLs, and scrub "
                         "every other string except identifiers, hashes, fingerprints, addresses and times (by shape: a short secret in free "
                         "text is not recognised); the log files themselves are whole."),
        "note": ("Each complete log is kept and named in its entry; inline records are bounded by limit, and omitted says how many were not returned. "
                 "conn.log's orig_bytes and resp_bytes count what Zeek saw each way for a connection as Zeek defines it (a connection with no "
                 "handshake, a UDP flow and a resumed one are all conn.log rows), not application data delivered. A hash in files.log exists only "
                 "if hash_fields names it and a record has a value: check hashes_produced, and where Zeek could not reassemble an object there is "
                 "none. Zeek's own stdout and stderr are kept beside the logs; reporter, weird and capture_loss are summarised under "
                 "engine_diagnostics."),
    }
    log_names.close()
    process_apply(answer)             # program_group: what settle() ended and why the absence of a leftover is unproven; a complete answer becomes partial
    answer_out(json.dumps(answer, indent=2))
    return 0


if __name__ == "__main__":
    exit_code = 0
    try:
        raise SystemExit(main())
    except SystemExit as stop:
        exit_code = _code(stop)
    except BaseException as exc:  # noqa: BLE001 - never a traceback, never a clean answer for a failure
        hold_stop_signals(quietly=True)
        try:
            fail("unexpected failure: %s" % describe(exc))
        except SystemExit as stop:
            exit_code = _code(stop)
    _leave(exit_code)
