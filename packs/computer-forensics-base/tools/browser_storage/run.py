#!/usr/bin/env python3
"""An inventory of a Chromium or Electron LevelDB directory (an IndexedDB, or any other LevelDB of a profile), read with ccl_chromium_reader.

The input is one directory (`path`): the `*.indexeddb.leveldb` directory of an origin, or a Local Storage / Session Storage
LevelDB. The reader is the pinned ccl_chromium_reader 0.3.18 in the venv of `ccl_indexeddb_dump` (/opt/dfir/src/ccl_indexeddb_dump/.venv);
this tool starts that venv's python as a program, with the reader's code run in a process of its own, and a venv that is missing, is
not the pinned reader or cannot be imported is `failed` with `unavailable: true`, never an empty inventory. What it does, exactly:

  * The directory is listed (a symbolic link, FIFO, device or directory under the name of a data file is refused and named, never
    followed), the LevelDB data files (NNNNNN.log, .ldb, .sst) are read one at a time by the reader's own LogFile and LdbFile classes,
    each opened without following a link and checked by identity before and after the reader opens it, and the highest-numbered
    MANIFEST is read. A file the reader cannot read to its end is named (its class of error, never the message, which can quote
    evidence) with the records it gave before it stopped; the others are still read. The reader does not verify the CRC32C of a log
    record or a table block, and neither does this tool: a record changed in place is read as it now is.
  * A directory whose records carry the IndexedDB global-metadata keys is read as an IndexedDB: databases (id, name, origin),
    object stores (id, name) and, per store, the data records by state (put, delete), the distinct keys, the keys whose newest
    record is a put, the keys whose newest record is a delete, the key types, and the index, exists and blob entries. Any other
    directory is a plain LevelDB: counts only, and Local Storage and Session Storage records are NOT interpreted.
  * `preview_records` (default 3) records of each store (the first current records, in file order) are shown: the locator
    (file, offset, sequence number, state), the key and the value after the shared withholding, bounded in depth, in the
    number of entries and in `preview_chars`. A preview is a lead, not the record.
  * `write_values: true`, in a job run as secret output, writes every data record of the selected stores (`db_id`, `store_id`) to a
    mode 0600 JSON Lines file under $OUT, whole: the locator, the key, the value decoded and the record's raw bytes in base64.
    The answer then carries counts and no value, no preview.
  * A value stored outside the LevelDB (a blob file) is not read: no blob directory is offered, and such a record is counted as
    not decoded. The reader holds every record of the directory in memory: the tool refuses more than 256 MiB of data files and
    stops at 2,000,000 records, and says which.

`complete` only when every data file was read to its end, the directory holds nothing refused, no limit or clock stopped the
reading, the IndexedDB metadata (when present) was read, and a values file (when asked for) is whole with its end line. Exit code 0
is `complete`; 1 is anything else, with the reason in `status_basis`.
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


import base64
import errno
import hashlib
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path

TOOL = {"name": "browser_storage", "version": 8}
PARSER = "browser_storage/1"
READER = "0.3.18"                        # the one ccl_chromium_reader this tool is written against; any other is refused
STARTED = time.monotonic()               # the run's clock starts with the tool
MAX_SECONDS_DEFAULT = 90
MAX_SECONDS_CEILING = 100                # the child's clock; the manifest's 120 holds this, the kill grace and the answer
CHILD_GRACE = 6                          # seconds past the child's own clock before the tool ends it
INPUT_MAX = 256 * 1024 * 1024            # bytes of data files the reader is given: it holds every record in memory
MAX_FILES = 5000
MAX_ENTRIES = 100000                     # directory entries looked at
MEMORY_BYTES = 3 * 1024 ** 3             # the child's address-space limit (Linux enforces it)
MAX_RECORDS = 2_000_000
MAX_STORE_IDS = 1000
MAX_LISTED = 50                          # stores previewed
FILE_QUOTA = 1024 ** 3                   # the values file stops here
if (os.environ.get("BROWSER_STORAGE_FILE_QUOTA") or "").isdigit():
    FILE_QUOTA = min(FILE_QUOTA, int(os.environ["BROWSER_STORAGE_FILE_QUOTA"]))      # lower only; for the tests
LINE_CAP = 48 * 1024 * 1024              # a record value over this is named, not written
READBACK_UNTIL = 108                     # seconds from the start: the values file is counted no later, 12 below the manifest's 120
STDOUT_MAX = 32 * 1024 * 1024            # the child's one document
LIST_DATABASES = 200
LIST_STORES = 200                        # per database
PREVIEW_CHARS_DEFAULT = 64
VALUES_NAME = "browser-storage-records.jsonl"
DATA_FILE = re.compile(r"^[0-9]{6}\.(ldb|log|sst)$")
MANIFEST_FILE = re.compile(r"^MANIFEST-([0-9A-F]{6})$")

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
        # The document is whole. A stop that came while it was written is let go now: run as a program, the shared ENDS block has given it a
        # handler that does nothing (the answer stands, and the call ends with its own code); loaded as a module, the tool's own handler ends it
        # (128 plus the signal; the last word was cleared) with nothing more on stdout. The mask is also what an in-process caller (a test) had before.
        signal.pthread_sigmask(signal.SIG_SETMASK, before)


def print_answer(answer, **dumps_kwargs):
    """Print the answer with the stop signals held back and the last word cleared (a signal in the middle of the write would cut the
    document, and the last word would add a second one), on the bounded write above."""
    hold_stop_signals()
    STATE["last_word"] = None
    _reconcile(answer)
    _guarded_write(lambda: print(json.dumps(answer, **dumps_kwargs)))


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


def _early_last_word(signum):
    """Until main() has its own: a stop before the arguments are read gives one document, `failed` and `interrupted`, and depends on nothing
    defined later."""
    sys.stdout.write(json.dumps({"ok": False, "tool": TOOL, "status": "failed", "interrupted": True, "signal": signum,
                                 "status_basis": "the tool was stopped by signal %d before it had read its arguments, so it did nothing" % signum}) + "\n")
    sys.stdout.flush()


STATE["last_word"] = _early_last_word
install_signal_handlers()


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


# The reader's side: this text is run by the venv's python (python -I -c), with the spec on stdin. It is the only code that touches the reader.
CHILD = r'''import base64, collections, datetime, io, json, os, pathlib, signal, stat, struct, sys

# What this program does: read the LevelDB files of one directory with ccl_chromium_reader (the venv it runs in), and write ONE JSON
# document on the real stdout. Its arguments are one JSON object on stdin. Anything the reader prints goes to /dev/null.
RESULT = os.fdopen(os.dup(1), "w", encoding="utf-8")
_null = os.open(os.devnull, os.O_WRONLY)
os.dup2(_null, 1)
os.close(_null)


class Deadline(BaseException):
    pass


class Cap(Exception):
    pass


def _alarm(_signum, _frame):
    raise Deadline()


STOP = {"why": None}
DOC = {"ok": False}


def emit(code=0):
    signal.setitimer(signal.ITIMER_REAL, 0)
    RESULT.write(json.dumps(DOC, ensure_ascii=True) + "\n")
    RESULT.flush()
    os._exit(code)


def iso(dt):
    return dt.isoformat(timespec="milliseconds") + "Z"


def varint(buf, at=0):
    """(value, bytes used) of a little-endian base-128 varint in buf at `at`, or None when it does not end."""
    value = shift = used = 0
    while at + used < len(buf) and used < 10:
        b = buf[at + used]
        value |= (b & 0x7F) << shift
        used += 1
        if not b & 0x80:
            return value, used
        shift += 7
    return None


def main():
    spec = json.loads(sys.stdin.buffer.read(1 << 20))
    limits = spec["limits"]
    signal.signal(signal.SIGALRM, _alarm)
    signal.setitimer(signal.ITIMER_REAL, float(spec["seconds"]))
    try:
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_AS)
        want = int(limits["memory_bytes"])
        if hard != resource.RLIM_INFINITY:
            want = min(want, hard)
        resource.setrlimit(resource.RLIMIT_AS, (want, hard))
        DOC["memory_limit_bytes"] = want
    except Exception:  # noqa: BLE001 - the platform has no RLIMIT_AS, or refuses it
        DOC["memory_limit_bytes"] = None

    import importlib.metadata as md

    def dist(name):
        try:
            return md.version(name)
        except Exception:  # noqa: BLE001
            return None
    DOC["versions"] = {"python": "%d.%d.%d" % sys.version_info[:3], "ccl_chromium_reader": dist("ccl_chromium_reader"),
                       "ccl_simplesnappy": dist("ccl_simplesnappy"), "brotli": dist("Brotli"), "zstd": dist("zstd")}
    if DOC["versions"]["ccl_chromium_reader"] != spec["expected_reader"]:
        DOC["fatal"] = "reader_version"
        emit()
    try:
        from ccl_chromium_reader import ccl_chromium_indexeddb as idb
        from ccl_chromium_reader.storage_formats import ccl_leveldb as ldb
        from ccl_chromium_reader.serialization_formats import ccl_blink_value_deserializer as blink
        from ccl_chromium_reader.serialization_formats import ccl_v8_value_deserializer as v8
    except Exception as exc:  # noqa: BLE001
        DOC["fatal"] = "reader_not_importable"
        DOC["error_class"] = type(exc).__name__
        emit()


    # ---- the reader reads past damage: it gives a log record cut inside its data, drops a spanning record that never ends, and reads a lying length as a
    # shorter value, with no error. The iteration below is the reader's own (same Record, same offsets) tightened by the format's rules (leveldb/doc/log_format.md,
    # table_format.md): the first inconsistency raises Damaged, and a batch is yielded whole or not at all. Everything else of the reader is used as it is. ----
    class Damaged(ValueError):
        def __init__(self, problem, offset):
            ValueError.__init__(self, problem)
            self.problem, self.offset = problem, offset

    def v32(buf, p, base):
        value = shift = 0
        for _n in range(5):
            if p >= len(buf):
                raise Damaged("varint_past_the_end", base + p)
            b = buf[p]
            p += 1
            value |= (b & 0x7F) << shift
            if not b & 0x80:
                return value, p
            shift += 7
        raise Damaged("varint_too_long", base + p)

    def strict_batches(self):
        size = ldb.LogFile.LOG_BLOCK_SIZE
        f = self._f
        f.seek(0)
        base, pending, start = 0, None, 0
        while True:
            block = f.read(size)
            if not block:
                break
            i = 0
            while i < len(block):
                if len(block) - i < 7:
                    if any(block[i:]):
                        raise Damaged("cut_header_or_trailer_not_zero", base + i)
                    break
                crc, length, kind = struct.unpack_from("<IHB", block, i)
                if kind not in (1, 2, 3, 4):
                    raise Damaged("zero_fill" if not (crc or length or kind) else "invalid_record_type", base + i)
                if i + 7 + length > len(block):
                    raise Damaged("cut_inside_record", base + i)
                data = block[i + 7:i + 7 + length]
                if kind == 1:
                    if pending is not None:
                        raise Damaged("full_record_inside_a_spanning_one", base + i)
                    yield base + i + 7, bytes(data)
                elif kind == 2:
                    if pending is not None:
                        raise Damaged("first_fragment_inside_a_spanning_record", base + i)
                    pending, start = bytearray(data), base + i + 7
                elif kind == 3:
                    if pending is None:
                        raise Damaged("middle_fragment_without_a_first", base + i)
                    pending += data
                else:
                    if pending is None:
                        raise Damaged("last_fragment_without_a_first", base + i)
                    pending += data
                    out, pending = bytes(pending), None
                    yield start, out
                i += 7 + length
            base += len(block)
        if pending is not None:
            raise Damaged("spanning_record_never_ends", start)

    def strict_log_iter(self):
        for at, batch in strict_batches(self):
            if len(batch) < 12:
                raise Damaged("batch_shorter_than_its_header", at)
            seq, count = struct.unpack_from("<QI", batch, 0)
            p, got = 12, []
            for n in range(count):
                entry = p
                if p >= len(batch):
                    raise Damaged("batch_ends_before_its_count", at + entry)
                kind = batch[p]
                p += 1
                if kind > 1:
                    raise Damaged("batch_entry_type", at + entry)
                klen, p = v32(batch, p, at)
                if p + klen > len(batch):
                    raise Damaged("key_past_the_batch", at + entry)
                key, p = bytes(batch[p:p + klen]), p + klen
                value = b""
                if kind == 1:
                    vlen, p = v32(batch, p, at)
                    if p + vlen > len(batch):
                        raise Damaged("value_past_the_batch", at + entry)
                    value, p = bytes(batch[p:p + vlen]), p + vlen
                got.append((entry, kind, key, value, seq + n))
            if p != len(batch):
                raise Damaged("batch_longer_than_its_entries", at + p)
            for entry, kind, key, value, number in got:
                yield ldb.Record.log_record(key, value, number, ldb.KeyState.Live if kind == 1 else ldb.KeyState.Deleted, self.path, at + entry)

    def strict_read_block(self, handle):
        self._f.seek(handle.offset)
        raw_block = self._f.read(handle.length)
        trailer = self._f.read(ldb.LdbFile.BLOCK_TRAILER_SIZE)
        if len(raw_block) != handle.length or len(trailer) != ldb.LdbFile.BLOCK_TRAILER_SIZE:
            raise Damaged("block_cut", handle.offset)
        if trailer[0] not in (0, 1):
            raise Damaged("block_compression_type_%d_not_read" % trailer[0], handle.offset)
        if trailer[0] == 1:
            raw_block = ldb.ccl_simplesnappy.decompress(io.BytesIO(raw_block))
        return ldb.Block(raw_block, trailer[0] == 1, self, handle.offset)

    def strict_block_iter(self):
        raw, end = self._raw, self._restart_array_offset
        if end < 4 or end > len(raw):
            raise Damaged("restart_array_outside_the_block", self.offset)
        p, key = self.get_first_entry_offset(), b""
        if p < 0 or p > end:
            raise Damaged("first_restart_outside_the_block", self.offset)
        while p < end:
            at = p
            shared, p = v32(raw, p, self.offset)
            non_shared, p = v32(raw, p, self.offset)
            value_length, p = v32(raw, p, self.offset)
            if shared > len(key):
                raise Damaged("shared_key_longer_than_the_previous_key", self.offset + at)
            if p + non_shared + value_length > end:
                raise Damaged("entry_past_the_restart_array", self.offset + at)
            key = key[:shared] + raw[p:p + non_shared]
            p += non_shared
            value = raw[p:p + value_length]
            p += value_length
            yield ldb.RawBlockEntry(key, value, at)

    ldb.LogFile.__iter__ = strict_log_iter
    ldb.ManifestFile._get_batches = strict_batches
    ldb.LdbFile._read_block = strict_read_block
    ldb.Block.__iter__ = strict_block_iter

    base = spec["path"]
    files = []
    records = []
    DOC["files"] = files
    # ---- the files, one at a time: a file that cannot be read is named and the others are still read ----
    for name, kind in spec["files"]:
        entry = {"name": name, "kind": kind, "size": None, "records": 0, "put": 0, "delete": 0, "unknown": 0, "records_in_compressed_blocks": 0,
                 "status": "read"}
        files.append(entry)
        if STOP["why"]:
            entry["status"] = "not_read"
            entry["reason"] = STOP["why"]
            continue
        path = os.path.join(base, name)
        stage = "open"
        held = None
        try:
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
            held = fd
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                entry["status"] = "failed"
                entry["stage"] = stage
                entry["reason"] = "not_a_regular_file"
                continue
            entry["size"] = st.st_size
            obj = (ldb.LogFile if kind == "log" else ldb.LdbFile)(pathlib.Path(path))
            again = os.stat(path, follow_symlinks=False)
            if (again.st_dev, again.st_ino) != (st.st_dev, st.st_ino):
                entry["status"] = "failed"
                entry["stage"] = stage
                entry["reason"] = "replaced_while_opening"
                obj.close()
                continue
            stage = "records"
            try:
                for rec in obj:
                    if len(records) >= limits["max_records"]:
                        raise Cap()
                    records.append(rec)
                    entry["records"] += 1
                    entry["put" if rec.state == ldb.KeyState.Live else "delete" if rec.state == ldb.KeyState.Deleted else "unknown"] += 1
                    if rec.was_compressed:
                        entry["records_in_compressed_blocks"] += 1
            finally:
                obj.close()
        except Deadline:
            STOP["why"] = "deadline"
            entry["status"] = "partial" if entry["records"] else "failed"
            entry["stage"] = stage
            entry["reason"] = "deadline"
        except Damaged as exc:
            entry["status"] = "partial" if entry["records"] else "failed"
            entry["stage"] = stage
            entry["error_class"] = "Damaged"
            entry["problem"] = exc.problem
            entry["problem_offset"] = exc.offset
        except Cap:
            STOP["why"] = "record_cap"
            entry["status"] = "partial"
            entry["stage"] = stage
            entry["reason"] = "record_cap"
        except Exception as exc:  # noqa: BLE001 - the class is the whole report: a message can quote the evidence
            entry["status"] = "partial" if entry["records"] else "failed"
            entry["stage"] = stage
            entry["error_class"] = type(exc).__name__
            if isinstance(exc, OSError) and exc.errno:
                entry["errno"] = exc.errno
        finally:
            if held is not None:
                os.close(held)
    # ---- the MANIFEST: the highest-numbered one, as the reader chooses ----
    manifest = None
    if spec.get("manifest") and not STOP["why"]:
        manifest = {"name": spec["manifest"], "status": "read"}
        try:
            fd = os.open(os.path.join(base, spec["manifest"]), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
            regular = stat.S_ISREG(os.fstat(fd).st_mode)
            os.close(fd)
            if not regular:
                manifest["status"] = "failed"
                manifest["reason"] = "not_a_regular_file"
            else:
                mf = ldb.ManifestFile(pathlib.Path(base, spec["manifest"]))
                manifest["table_files_added"] = len(mf.file_to_level)
                mf.close()
        except Deadline:
            STOP["why"] = "deadline"
            manifest["status"] = "failed"
            manifest["reason"] = "deadline"
        except Damaged as exc:
            manifest["status"] = "failed"
            manifest["error_class"] = "Damaged"
            manifest["problem"] = exc.problem
            manifest["problem_offset"] = exc.offset
        except Exception as exc:  # noqa: BLE001
            manifest["status"] = "failed"
            manifest["error_class"] = type(exc).__name__
    DOC["manifest"] = manifest
    records.sort(key=lambda r: (int(pathlib.Path(r.origin_file).stem, 16), r.offset))
    DOC["records_total"] = len(records)
    DOC["stopped"] = STOP["why"]

    def state_name(rec):
        return "put" if rec.state == ldb.KeyState.Live else "delete" if rec.state == ldb.KeyState.Deleted else "unknown"

    def split_prefix(uk):
        """(db id, store id, index id, prefix length) of an IndexedDB user key, or None."""
        if not uk:
            return None
        b0 = uk[0]
        d, s, i = ((b0 >> 5) & 7) + 1, ((b0 >> 2) & 7) + 1, (b0 & 3) + 1
        if 1 + d + s + i > len(uk):
            return None
        db = int.from_bytes(uk[1:1 + d], "little")
        store = int.from_bytes(uk[1 + d:1 + d + s], "little")
        index = int.from_bytes(uk[1 + d + s:1 + d + s + i], "little")
        return db, store, index, 1 + d + s + i

    is_idb = any(r.state == ldb.KeyState.Live and (r.user_key[:5] == b"\x00\x00\x00\x00\x00" or r.user_key[:5] == b"\x00\x00\x00\x00\xc9")
                 for r in records)
    DOC["format"] = "indexeddb" if is_idb else "leveldb"
    raw = None
    if is_idb:
        class Preloaded:
            """Stands in for the reader's RawLevelDb: the records read above, file by file, are the ones IndexedDb is given."""

            def __init__(self, _directory):
                pass

            def iterate_records_raw(self, *, reverse=False):
                return iter(records)

            def close(self):
                pass
        ldb.RawLevelDb = Preloaded
        try:
            raw = idb.IndexedDb(pathlib.Path(base))
        except Deadline:
            STOP["why"] = "deadline"
            DOC["stopped"] = "deadline"
        except Exception as exc:  # noqa: BLE001
            DOC["indexeddb_error_class"] = type(exc).__name__
            DOC["format"] = "leveldb"

    if raw is not None:
        newest = None
        for rec in records:
            if rec.state == ldb.KeyState.Live and rec.user_key == b"\x00\x00\x00\x00\x00" and (newest is None or newest.seq <= rec.seq):
                newest = rec
        got = varint(newest.value) if newest is not None else None
        DOC["schema_version"] = got[0] if got else None

    only_db, only_store = spec.get("db_id"), spec.get("store_id")
    want = int(spec.get("preview_records") or 0)
    write_fd = spec.get("write_fd")
    # ---- one pass over the records: per store counts, the newest record of each key ----
    stores = collections.OrderedDict()
    latest = {}
    other = collections.Counter()
    plain_latest = {}
    if not STOP["why"]:
        try:
            for idx, rec in enumerate(records):
                uk = rec.user_key
                if raw is None:
                    if rec.state != ldb.KeyState.Unknown:
                        prev = plain_latest.get(uk)
                        if prev is None or records[prev].seq <= rec.seq:
                            plain_latest[uk] = idx
                    continue
                sp = split_prefix(uk)
                if sp is None:
                    other["unparsed_key"] += 1
                    continue
                db, store, index, plen = sp
                if index == 0:
                    other["metadata"] += 1
                    continue
                st = stores.get((db, store))
                if st is None:
                    st = stores[(db, store)] = {"data_records": 0, "put": 0, "delete": 0, "unknown": 0, "exists_entries": 0, "index_entries": 0,
                                                "blob_entries": 0, "other_entries": 0, "key_types": collections.Counter()}
                if index == 1:
                    st["data_records"] += 1
                    st[state_name(rec)] += 1
                    kt = uk[plen] if len(uk) > plen else None
                    try:
                        st["key_types"][idb.IdbKeyType(kt).name] += 1
                    except Exception:  # noqa: BLE001
                        st["key_types"]["invalid"] += 1
                    if rec.state != ldb.KeyState.Unknown:
                        k = (db, store, uk[plen:])
                        prev = latest.get(k)
                        if prev is None or records[prev].seq <= rec.seq:
                            latest[k] = idx
                elif index == 2:
                    st["exists_entries"] += 1
                elif index == 3:
                    st["blob_entries"] += 1
                elif index >= 30:
                    st["index_entries"] += 1
                else:
                    st["other_entries"] += 1
        except Deadline:
            STOP["why"] = "deadline"
            DOC["stopped"] = "deadline"
    DOC["counts"] = {"puts": sum(1 for r in records if r.state == ldb.KeyState.Live), "deletes": sum(1 for r in records if r.state == ldb.KeyState.Deleted),
                     "unknown": sum(1 for r in records if r.state == ldb.KeyState.Unknown)}

    for k, idx in latest.items():
        st = stores[(k[0], k[1])]
        st["distinct_keys"] = st.get("distinct_keys", 0) + 1
        if records[idx].state == ldb.KeyState.Live:
            st["current_keys"] = st.get("current_keys", 0) + 1
        else:
            st["deleted_keys"] = st.get("deleted_keys", 0) + 1

    # ---- the databases and stores the reader's metadata names ----
    names = {}
    db_list = []
    if raw is not None:
        seen = set()
        try:
            for d in raw.global_metadata.db_ids:
                triple = (d.dbid_no, d.origin, d.name)
                if triple in seen:
                    DOC["duplicate_database_entries"] = DOC.get("duplicate_database_entries", 0) + 1
                    continue
                seen.add(triple)
                try:
                    top = raw.get_database_metadata(d.dbid_no, idb.DatabaseMetadataType.MaximumObjectStoreId)
                except Exception:  # noqa: BLE001
                    top = None
                entry = {"id": d.dbid_no, "name": d.name, "origin": d.origin, "max_store_id": top, "stores": []}
                db_list.append(entry)
                ids = set(range(1, min(top or 0, limits["max_store_ids"]) + 1)) | {s for (db, s) in stores if db == d.dbid_no}
                for sid in sorted(ids):
                    try:
                        sname = raw.get_object_store_metadata(d.dbid_no, sid, idb.ObjectStoreMetadataType.StoreName)
                    except Exception:  # noqa: BLE001
                        sname = None
                    names[(d.dbid_no, sid)] = (d.name, d.origin, sname)
                    st = stores.get((d.dbid_no, sid))
                    if sname is None and not st:
                        continue                # an id in the range that has neither a name nor a record: a store that was deleted, or never made
                    row = {"id": sid, "name": sname, "has_metadata": sname is not None}
                    if st:
                        row.update({k: (dict(v) if isinstance(v, collections.Counter) else v) for k, v in st.items()})
                        row.setdefault("distinct_keys", 0)
                        row.setdefault("current_keys", 0)
                        row.setdefault("deleted_keys", 0)
                    entry["stores"].append(row)
        except Deadline:
            STOP["why"] = "deadline"
            DOC["stopped"] = "deadline"
        except Exception as exc:  # noqa: BLE001
            DOC["indexeddb_error_class"] = type(exc).__name__
        known_dbs = {e["id"] for e in db_list}
        orphan = [{"database": db, "store": s, **{k: (dict(v) if isinstance(v, collections.Counter) else v) for k, v in st.items()}}
                  for (db, s), st in stores.items() if db not in known_dbs]
        DOC["indexeddb"] = {"databases": db_list, "records_outside_data": dict(other), "stores_of_unlisted_databases": orphan[:limits["max_listed"]]}
    else:
        current = sum(1 for i in plain_latest.values() if records[i].state == ldb.KeyState.Live)
        DOC["leveldb"] = {"distinct_keys": len(plain_latest), "current_keys": current, "deleted_keys": len(plain_latest) - current}

    # ---- decoding one value ----
    class Deserializer(v8.Deserializer):
        def _read_zigzag(self):
            # V8's ReadZigZag is (u >> 1) ^ -(u & 1); the reader returns -(u >> 1) for an odd u, which is one too high for every negative integer.
            u = self._read_le_varint()[0]
            return (u >> 1) ^ -(u & 1)

    blink_reader = blink.BlinkV8Deserializer() if raw is not None else None
    errors = collections.Counter()
    PREVIEW = {"depth": 4, "items": 12, "nodes": 120, "text": 4096}

    def preview_of(value, depth, budget):
        budget[0] -= 1
        if value is None or isinstance(value, bool) or isinstance(value, int):
            return value
        if isinstance(value, float):
            return value if value == value and value not in (float("inf"), float("-inf")) else {"$float": repr(value)}
        if isinstance(value, str):
            return value if len(value) <= PREVIEW["text"] else {"$long_text": True}
        if isinstance(value, datetime.datetime):
            try:
                return {"$date": iso(value)}
            except Exception:  # noqa: BLE001
                return {"$date": "unrepresentable"}
        if isinstance(value, (bytes, bytearray)):
            return {"$bytes": True}
        if value is v8.Deserializer.Undefined:
            return {"$undefined": True}
        if depth >= PREVIEW["depth"] or budget[0] <= 0:
            return {"$deeper": True}
        if isinstance(value, dict):
            out = {}
            for n, (k, v) in enumerate(value.items()):
                if n >= PREVIEW["items"]:
                    out["$more"] = len(value) - n
                    break
                out[str(k) if isinstance(k, str) else repr(k)[:60]] = preview_of(v, depth + 1, budget)
            return out
        if isinstance(value, (list, tuple, set, frozenset)):
            items = list(value) if not isinstance(value, (set, frozenset)) else list(value)
            out = [preview_of(v, depth + 1, budget) for v in items[:PREVIEW["items"]]]
            if len(items) > PREVIEW["items"]:
                out.append({"$more": len(items) - PREVIEW["items"]})
            return {"$set": out} if isinstance(value, (set, frozenset)) else out
        return {"$type": type(value).__name__}

    def full_of(value, depth=0):
        if value is None or isinstance(value, (bool, int, str)):
            return value
        if isinstance(value, float):
            return value if value == value and value not in (float("inf"), float("-inf")) else {"$float": repr(value)}
        if isinstance(value, datetime.datetime):
            try:
                return {"$date": iso(value)}
            except Exception:  # noqa: BLE001
                return {"$date": None}
        if isinstance(value, (bytes, bytearray)):
            return {"$bytes_b64": base64.b64encode(bytes(value)).decode("ascii")}
        if value is v8.Deserializer.Undefined:
            return {"$undefined": True}
        if depth > 200:
            return {"$too_deep": True}
        if isinstance(value, dict):
            if all(isinstance(k, str) for k in value):
                return {k: full_of(v, depth + 1) for k, v in value.items()}
            return {"$pairs": [[full_of(k, depth + 1), full_of(v, depth + 1)] for k, v in value.items()]}
        if isinstance(value, (list, tuple)):
            return [full_of(v, depth + 1) for v in value]
        if isinstance(value, (set, frozenset)):
            return {"$set": [full_of(v, depth + 1) for v in value]}
        if hasattr(value, "pattern"):
            return {"$regexp": str(value.pattern)}
        if type(value).__name__ == "BlobIndex":
            return {"$blob_index": getattr(value, "index_id", None)}
        return {"$type": type(value).__name__}

    def key_of(uk, plen):
        """(IdbKey or None, its JSON form, its type name) for the key part of an IndexedDB user key."""
        try:
            key = idb.IdbKey(uk[plen:])
        except Exception as exc:  # noqa: BLE001
            return None, None, "undecoded:" + type(exc).__name__

        def one(k):
            t = k.key_type
            if t == idb.IdbKeyType.Null:
                return None
            if t == idb.IdbKeyType.String:
                return k.value
            if t == idb.IdbKeyType.Number:
                return k.value if k.value == k.value and abs(k.value) != float("inf") else {"$float": repr(k.value)}
            if t == idb.IdbKeyType.Date:
                return {"$date": iso(k.value)}
            if t == idb.IdbKeyType.Array:
                return {"$array": [one(x) for x in k.value]}
            if t == idb.IdbKeyType.Binary:
                return {"$bytes_b64": base64.b64encode(k.value).decode("ascii")}
            return {"$type": t.name}
        try:
            return key, one(key), key.key_type.name
        except Exception as exc:  # noqa: BLE001
            return key, None, "undecoded:" + type(exc).__name__

    def decode(rec, db, sid, key):
        """(python value, error class) of a record's value. Never raises but Deadline."""
        raw_value = rec.value
        if not raw_value:
            return None, "empty_value"
        try:
            got = varint(raw_value)
            if got is None:
                return None, "no_version_varint"
            pre = raw.read_record_precursor(key, db, sid, raw_value[got[1]:], None)
            if pre is None:
                return None, "value_outside_the_database"
            _blink_version, body, _trailer, _external = pre
            return Deserializer(body, host_object_delegate=blink_reader.read).read(), None
        except Deadline:
            raise
        except Exception as exc:  # noqa: BLE001
            return None, type(exc).__name__

    def locator(rec):
        return {"file": pathlib.Path(rec.origin_file).name, "offset": rec.offset, "offset_is": "block_start" if rec.was_compressed else "record",
                "seq": rec.seq, "state": state_name(rec)}

    selected = lambda db, sid: (only_db is None or only_db == db) and (only_store is None or only_store == sid)

    # ---- previews: the first `want` current records of each store ----
    previews = []
    if want and not write_fd and not STOP["why"]:
        try:
            if raw is not None:
                picks = collections.OrderedDict()
                for k, idx in latest.items():
                    if records[idx].state == ldb.KeyState.Live and selected(k[0], k[1]):
                        picks.setdefault((k[0], k[1]), []).append(idx)
                for (db, sid), idxs in picks.items():
                    idxs.sort()
                    items = []
                    for idx in idxs[:want]:
                        rec = records[idx]
                        sp = split_prefix(rec.user_key)
                        key, keyjson, ktype = key_of(rec.user_key, sp[3])
                        value, err = decode(rec, db, sid, key)
                        if err:
                            errors[err] += 1
                        items.append({"locator": locator(rec), "key_type": ktype, "key": preview_of(keyjson, 2, [20]) if keyjson is not None else None,
                                      "value": preview_of(value, 0, [PREVIEW["nodes"]]) if not err else None, "value_error": err,
                                      "value_type": None if err else ("object" if isinstance(value, dict) else "array" if isinstance(value, list) else
                                                                      "string" if isinstance(value, str) else "boolean" if isinstance(value, bool) else
                                                                      "number" if isinstance(value, (int, float)) else "null" if value is None else
                                                                      "date" if isinstance(value, datetime.datetime) else "bytes" if isinstance(value, (bytes, bytearray)) else
                                                                      "undefined" if value is v8.Deserializer.Undefined else "other")})
                    nm = names.get((db, sid), (None, None, None))
                    previews.append({"database": db, "store": sid, "database_name": nm[0], "store_name": nm[2], "records": items,
                                     "current_keys_in_store": len(idxs)})
                    if len(previews) >= limits["max_listed"]:
                        break
            else:
                shown = 0
                for uk, idx in sorted(plain_latest.items(), key=lambda kv: kv[1]):
                    rec = records[idx]
                    if rec.state != ldb.KeyState.Live:
                        continue
                    previews.append({"locator": locator(rec), "key": uk[:200].decode("latin-1"), "value": rec.value[:PREVIEW["text"]].decode("latin-1"),
                                     "value_truncated_at": PREVIEW["text"] if len(rec.value) > PREVIEW["text"] else None})
                    shown += 1
                    if shown >= want:
                        break
        except Deadline:
            STOP["why"] = "deadline"
            DOC["stopped"] = "deadline"
    DOC["previews"] = previews
    DOC["decode_errors"] = dict(errors)

    # ---- the complete records, to the file the parent opened ----
    write = {"requested": bool(write_fd), "records": 0, "bytes": 0, "stopped": None, "write_error": None, "oversized": 0, "undecoded": 0}
    DOC["write"] = write
    if write_fd:
        sink = os.fdopen(write_fd, "wb", buffering=1 << 20, closefd=False)
        quota, line_cap, reserve = limits["file_quota"], limits["line_cap"], 4096

        def put(obj):
            data = (json.dumps(obj, ensure_ascii=True) + "\n").encode("ascii")
            if write["bytes"] + len(data) + reserve > quota:
                write["stopped"] = "file_quota"
                return False
            try:
                sink.write(data)
            except OSError as exc:
                write["write_error"] = os.strerror(exc.errno) if exc.errno else type(exc).__name__
                write["stopped"] = "write_error"
                return False
            write["bytes"] += len(data)
            return True
        try:
            put({"header": True, "parser": spec["parser"], "reader": spec["expected_reader"], "format": DOC["format"]})
            for idx, rec in enumerate(records):
                if write["stopped"] or STOP["why"]:
                    break
                uk = rec.user_key
                line = {"n": write["records"] + 1, "locator": locator(rec), "parser": spec["parser"]}
                if raw is not None:
                    sp = split_prefix(uk)
                    if sp is None or sp[2] != 1 or not selected(sp[0], sp[1]):
                        continue
                    db, sid, _i, plen = sp
                    nm = names.get((db, sid), (None, None, None))
                    key, keyjson, ktype = key_of(uk, plen)
                    line.update({"database": db, "store": sid, "database_name": nm[0], "origin": nm[1], "store_name": nm[2], "key_type": ktype,
                                 "key": keyjson, "key_raw_b64": base64.b64encode(uk[plen:]).decode("ascii")})
                    if rec.state == ldb.KeyState.Live:
                        value, err = decode(rec, db, sid, key)
                        line["value"] = full_of(value) if not err else None
                        line["value_error"] = err
                        if err:
                            write["undecoded"] += 1
                    else:
                        line["value"] = None
                        line["value_error"] = None
                else:
                    if only_db is not None or only_store is not None:
                        continue
                    line.update({"key_b64": base64.b64encode(uk).decode("ascii")})
                if len(rec.value) > line_cap:
                    line["raw_b64"] = None
                    line["value"] = None
                    line["not_written"] = "over_the_line_limit"
                    write["oversized"] += 1
                else:
                    line["raw_b64"] = base64.b64encode(rec.value).decode("ascii")
                if not put(line):
                    break
                write["records"] += 1
            if not write["stopped"] and STOP["why"]:
                write["stopped"] = STOP["why"]
            end = {"end": True, "records": write["records"], "stopped": write["stopped"], "oversized": write["oversized"]}
            if write["write_error"] is None:
                data = (json.dumps(end) + "\n").encode("ascii")
                try:
                    sink.write(data)
                    write["bytes"] += len(data)
                except OSError as exc:
                    write["write_error"] = os.strerror(exc.errno) if exc.errno else type(exc).__name__
            try:
                sink.flush()
            except OSError as exc:
                write["write_error"] = write["write_error"] or (os.strerror(exc.errno) if exc.errno else type(exc).__name__)
        except Deadline:
            STOP["why"] = "deadline"
            DOC["stopped"] = "deadline"
            write["stopped"] = "deadline"
        finally:
            try:
                sink.flush()
            except (OSError, Deadline):
                pass
    DOC["ok"] = True
    emit()


try:
    main()
except Deadline:
    DOC["stopped"] = "deadline"
    DOC["fatal"] = DOC.get("fatal") or "deadline"
    emit()
except MemoryError:
    DOC["fatal"] = "memory_limit"
    emit()
except BaseException as exc:  # noqa: BLE001
    DOC["fatal"] = "child_error"
    DOC["error_class"] = type(exc).__name__
    emit()
'''


_INVISIBLE = re.compile("[\x00\u200b-\u200d\u2060\ufeff]")


def visible(text):
    """The text without NUL and zero-width characters, which split a secret into pieces no shape rule can see; a preview shows it without them."""
    return _INVISIBLE.sub("", text)


def shown(text, limit=200):
    """A name or a text from the evidence as it may be printed: invisible characters removed, control characters escaped, then the shared withholding, then cut."""
    out = scrub(cell(visible(text)))
    return out if len(out) <= limit else out[:limit] + "..."


OWN_PATH_CHARS = 4096


def own_path(text):
    """The caller's own path argument as the answer repeats it: invisible characters removed and control characters escaped, and NOT
    run through the withholding. It is the caller's text, not the evidence's (the job's record holds it as given), and a long path of
    a run (store/jobs/<id>/out/.../User Data/...) is token-shaped to the shape rules, which hid the one clue to a wrong path."""
    out = cell(visible(text))
    return out if len(out) <= OWN_PATH_CHARS else out[:OWN_PATH_CHARS] + "..."


def optional_id(args, key):
    value = args.get(key)
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool) or value < 0 or value > 2 ** 62:
        fail("%s is a whole number, 0 or more" % key, **{key: shown(str(value), 40)})
    return value


def venv_python():
    """The python of the ccl_indexeddb_dump venv, or None when there is none to run."""
    src = os.environ.get("DFIRSWARM_SRC_DIR") or "/opt/dfir/src"
    py = os.path.join(src, "ccl_indexeddb_dump", ".venv", "bin", "python")
    return py if os.path.isfile(py) and os.access(py, os.X_OK) else None


def kind_of(mode):
    return ("a symbolic link" if stat.S_ISLNK(mode) else "a directory" if stat.S_ISDIR(mode) else "a FIFO" if stat.S_ISFIFO(mode) else
            "a device" if stat.S_ISBLK(mode) or stat.S_ISCHR(mode) else "a socket" if stat.S_ISSOCK(mode) else "not a regular file")


def list_directory(path, given):
    """What the directory holds that the reader reads, and what it refuses: the data files (regular only), the highest MANIFEST.
    `path` is the directory as it is opened (absolute), `given` the caller's argument, which is what an answer repeats."""
    try:
        st = os.lstat(path)
    except OSError as exc:
        fail("path cannot be looked at: %s" % describe(exc), path=own_path(given))
    if stat.S_ISLNK(st.st_mode):
        fail("path is a symbolic link: give the directory itself, since this tool follows no link", path=own_path(given))
    if not stat.S_ISDIR(st.st_mode):
        fail("path is not a directory: give the LevelDB directory (the one that holds the NNNNNN.log and NNNNNN.ldb files)", path=own_path(given))
    found = {"files": [], "manifest": None, "refused": [], "other_entries": 0, "bytes": 0, "entries": 0, "entries_cut": False}
    best = -1
    try:
        scan = os.scandir(path)
    except OSError as exc:
        fail("path cannot be listed: %s" % describe(exc), path=own_path(given))
    with scan:
        for entry in scan:
            found["entries"] += 1
            if found["entries"] > MAX_ENTRIES:
                found["entries_cut"] = True
                break
            name = entry.name
            is_data, is_manifest = bool(DATA_FILE.match(name)), bool(MANIFEST_FILE.match(name))
            if not (is_data or is_manifest):
                found["other_entries"] += 1
                continue
            try:
                info = entry.stat(follow_symlinks=False)
            except OSError as exc:
                found["refused"].append({"name": name, "why": "could not be looked at: %s" % (exc.strerror or exc.__class__.__name__)})
                continue
            if not stat.S_ISREG(info.st_mode):
                found["refused"].append({"name": name, "why": "is %s; this tool reads regular files only" % kind_of(info.st_mode)})
                continue
            if is_manifest:
                number = int(MANIFEST_FILE.match(name).group(1), 16)
                if number > best:
                    best, found["manifest"] = number, name
                continue
            found["files"].append((name, info.st_size))
            found["bytes"] += info.st_size
    found["files"].sort(key=lambda f: (int(f[0][:6], 16), f[0]))
    return found


class ValuesFile:
    """The file complete records go to, made before the reader is started and held open by this process while the reader writes to it."""

    def __init__(self):
        self.path = Path(os.environ["OUT"]) / VALUES_NAME
        self.shown = "store/jobs/%s/out/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("JOB_ID", "")), VALUES_NAME)
        self.fd = None
        self.ident = None

    def create(self):
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.fd = os.open(str(self.path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
            info = os.fstat(self.fd)
            self.ident = (info.st_dev, info.st_ino)
        except FileExistsError:
            fail("the values file already exists in this job's output: a second export in one job is refused, and nothing was written", write_values="refused")
        except OSError as exc:
            fail("the values file could not be created: %s" % describe(exc), write_values="refused")

    def close(self):
        if self.fd is not None:
            try:
                os.fsync(self.fd)
            except OSError:
                pass
            try:
                os.close(self.fd)
            except OSError:
                pass
            self.fd = None

    def drop(self):
        """The file was made for a run that wrote nothing: remove exactly it (by name, when it is still the file that was made)."""
        try:
            info = os.lstat(self.path)
            if (info.st_dev, info.st_ino) == self.ident and info.st_size == 0:
                os.unlink(self.path)
                return True
        except OSError:
            pass
        return False

    def read_back(self, until):
        """(bytes, lines or None, end line or None, problem): the kept file read again, so that the answer counts what is there and not what the reader said.
        The end of the file is read first; the lines are counted until the clock `until` and the count is None when it was not reached."""
        try:
            fd = os.open(str(self.path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        except OSError as exc:
            return None, None, None, "the values file could not be read back: %s" % describe(exc)
        try:
            info = os.fstat(fd)
            if (info.st_dev, info.st_ino) != self.ident:
                return None, None, None, "the values file is no longer the file that was made"
            size = info.st_size
            tail = b""
            if size:
                os.lseek(fd, max(0, size - (1 << 16)), os.SEEK_SET)
                tail = os.read(fd, 1 << 16)
            end = None
            body = tail[:-1] if tail.endswith(b"\n") else tail
            try:
                doc = json.loads(body.rsplit(b"\n", 1)[-1].decode("utf-8"))
                end = doc if isinstance(doc, dict) and doc.get("end") is True and tail.endswith(b"\n") else None
            except ValueError:
                end = None
            lines = 0
            os.lseek(fd, 0, os.SEEK_SET)
            while True:
                if time.monotonic() > until:
                    return size, None, end, None
                chunk = os.read(fd, 1 << 20)
                if not chunk:
                    return size, lines, end, None
                lines += chunk.count(b"\n")
        finally:
            os.close(fd)


def run_reader(py, spec, seconds, pass_fd):
    """Run the reader's child in the venv's python: (exit code, stdout bytes, timed out). The spec goes on stdin, never on the command line."""
    kwargs = {"stdin": subprocess.PIPE, "stdout": subprocess.PIPE, "stderr": subprocess.DEVNULL, "cwd": "/",
              "env": {"PATH": os.environ.get("PATH") or "/usr/local/bin:/usr/bin:/bin"}}
    if pass_fd is not None:
        kwargs["pass_fds"] = (pass_fd,)
    proc = spawn([py, "-I", "-c", CHILD], **kwargs)
    ACTIVE.append(proc)
    try:
        out, _err, timed_out = communicate_bounded(proc, seconds, input=json.dumps(spec).encode("utf-8"), caps=(STDOUT_MAX, 1 << 16))
    finally:
        ACTIVE.remove(proc)
    return proc.returncode, out, timed_out


def apply_program_verdict(answer, files_written):
    """program_group in the answer, from the shared block. The reader's child writes the values file (a descriptor it is handed, write_values) and prints its
    document on a pipe. When it wrote the values file, the whole rule holds: a process settle() ended after the child had ended, or a host where none can be ruled
    out (not Linux, PR_SET_CHILD_SUBREAPER refused), makes a complete answer partial (process_apply). When it only printed on the pipe, a process settle() ended
    still makes the answer partial, and a host that cannot rule one out is said in program_group.unproven and does not change the status."""
    if files_written or process_verdict()["left_behind"]:
        process_apply(answer)
    else:
        answer["program_group"] = process_verdict()


def cut_text(text, limit):
    return text if len(text) <= limit else text[:limit] + "..."


def shape_preview(node, limit):
    """A decoded value as it may be printed: every string withheld by shape and bounded, a credential-named field not read at all."""
    def leaf(text, _pointer, shapes):
        return cut_text(scrub(cell(visible(text))) if shapes else cell(visible(text)), limit)

    def note(_pointer, why, _original):
        COUNTS["text"] += 1
        return "<withheld: %s>" % why

    return clean_value(node, leaf, note, lambda text: cut_text(scrub(cell(visible(text))), 80))


def plain_text(raw):
    """A plain LevelDB value as text: Local Storage's one-byte prefix says latin-1 (1) or UTF-16 little-endian (0); anything else is latin-1."""
    if raw[:1] == b"\x00":
        try:
            return raw[1:].decode("utf-16-le")
        except UnicodeDecodeError:
            pass
    return (raw[1:] if raw[:1] == b"\x01" else raw).decode("latin-1")


def shape_plain_preview(item, limit):
    key = item["key"]
    name = re.split(r"[\x00\x01]", key)[-1]
    out = {"locator": item["locator"], "key": cut_text(scrub(cell(visible(key))), 120)}
    if name_is_sensitive(name):
        COUNTS["text"] += 1
        out["value"] = "<withheld: credential-named key>"
    else:
        out["value"] = cut_text(scrub(cell(visible(plain_text(item["value"].encode("latin-1"))))), limit)
    if item.get("value_truncated_at"):
        out["value_read_to"] = item["value_truncated_at"]
    return out


def shape_store(row):
    keep = ("id", "has_metadata", "data_records", "put", "delete", "unknown", "distinct_keys", "current_keys", "deleted_keys", "key_types", "exists_entries",
            "index_entries", "blob_entries", "other_entries")
    out = {k: row[k] for k in keep if k in row}
    out["name"] = shown(row["name"]) if row.get("name") is not None else None
    return out


def main():
    try:
        args = json.load(sys.stdin)
    except (ValueError, RecursionError):
        fail("arguments are not valid JSON")
    if not isinstance(args, dict):
        fail("arguments are a JSON object")
    unknown = sorted(set(args) - {"path", "preview_records", "preview_chars", "db_id", "store_id", "write_values", "max_seconds"})
    if unknown:
        fail("unknown parameter: %s" % ", ".join(shown(str(k), 40) for k in unknown[:5]))
    path = args.get("path")
    if not isinstance(path, str) or not path or "\0" in path:
        fail("path is required: the LevelDB directory (a text without a NUL byte)")
    try:
        path.encode("utf-8")
    except UnicodeEncodeError:
        fail("path is text that can be written as UTF-8 (a lone surrogate cannot)")
    preview_records = whole(args, "preview_records", 3, 0, 25)
    preview_chars = whole(args, "preview_chars", PREVIEW_CHARS_DEFAULT, 8, 200)
    seconds = whole(args, "max_seconds", MAX_SECONDS_DEFAULT, 5, MAX_SECONDS_CEILING)
    db_id, store_id = optional_id(args, "db_id"), optional_id(args, "store_id")
    write_values = args.get("write_values", False)
    if write_values is None:
        write_values = False
    if not isinstance(write_values, bool):
        fail("write_values is true or false")
    if write_values:
        # Refused before anything is opened or made: a values file outside a sealed job output would be an ordinary file.
        if not in_job():
            fail("write_values is refused outside a job: a value written here would be an ordinary file, not a sealed secret output. Run this as job_run "
                 "tool=browser_storage, whose manifest makes every job that sets write_values a secret_output job. Nothing was written.", write_values="refused")
        if os.environ.get("SECRET_OUTPUT") != "1":
            fail("write_values is refused in a job that was not run as secret output (SECRET_OUTPUT=1 is not set): its files would be sealed as ordinary "
                 "output. Run it as job_run(tool: \"browser_storage\", args: {...}), whose manifest makes the job secret output. Nothing was written.",
                 write_values="refused")

    py = venv_python()
    if py is None:
        fail("the ccl_indexeddb_dump venv is not installed in this image, so ccl_chromium_reader cannot be run: no inventory was made, and this is not an empty store",
             unavailable=True, status_detail="unavailable", needs="/opt/dfir/src/ccl_indexeddb_dump/.venv/bin/python (the base pack's ccl_indexeddb_dump)")
    # The reader's process runs with / as its working directory, so the directory is named to it (and listed here) by an absolute
    # path: a path relative to the caller's working directory, which is what a job gives, is joined to that directory first. The
    # join is textual (no "..", no link is resolved), so the directory opened is the one the caller's path names from where it stands.
    try:
        opened = path if os.path.isabs(path) else os.path.join(os.getcwd(), path)
    except OSError as exc:
        fail("the working directory cannot be named (%s), so a relative path cannot be made absolute for the reader: give an absolute path" % describe(exc),
             path=own_path(path))
    listing = list_directory(opened, path)
    if not listing["files"]:
        fail("the directory holds no LevelDB data file (NNNNNN.log, NNNNNN.ldb or NNNNNN.sst): there is nothing to inventory, and a LevelDB that holds no record "
             "cannot be told here from a directory that is not one", unsupported="no LevelDB data files", path=own_path(path),
             refused=[{"name": r["name"], "why": r["why"]} for r in listing["refused"][:20]] or None)
    if listing["bytes"] > INPUT_MAX:
        fail("the data files are %d bytes, over the %d bytes this tool reads (the reader holds every record in memory): nothing was read" % (listing["bytes"], INPUT_MAX),
             input_bytes=listing["bytes"], input_limit=INPUT_MAX, path=own_path(path))
    if len(listing["files"]) > MAX_FILES:
        fail("the directory holds %d data files, over the %d this tool reads: nothing was read" % (len(listing["files"]), MAX_FILES), path=own_path(path))

    values = None
    if write_values:
        values = ValuesFile()
        values.create()

    def last_word(signum):
        if values is not None:
            values.close()
        print(json.dumps({"tool": TOOL, "status": "partial", "interrupted": True, "signal": signum,
                          "status_basis": "the tool was stopped by signal %d: the reader's process and what it started were ended%s" % (
                              signum, "; the values file, if it was made, holds whole lines up to where the reader stopped and has no end line" if values else ""),
                          "values_file": values.shown if values else None, "process_notes": process_notes() or None}), flush=True)
    STATE["last_word"] = last_word

    spec = {"path": opened, "files": [[name, name.rsplit(".", 1)[1]] for name, _size in listing["files"]], "manifest": listing["manifest"],
            "preview_records": preview_records, "db_id": db_id, "store_id": store_id, "write_fd": values.fd if values else None,
            "seconds": seconds, "expected_reader": READER, "parser": PARSER,
            "limits": {"memory_bytes": MEMORY_BYTES, "max_records": MAX_RECORDS, "max_store_ids": MAX_STORE_IDS, "max_listed": MAX_LISTED,
                       "file_quota": FILE_QUOTA, "line_cap": LINE_CAP}}
    try:
        code, out, timed_out = run_reader(py, spec, seconds + CHILD_GRACE, values.fd if values else None)
    except OSError as exc:
        if values is not None:
            values.close()
            values.drop()
        fail("the reader's python could not be started: %s" % describe(exc), unavailable=True, status_detail="unavailable")
    doc = None
    if len(out) <= STDOUT_MAX and not output_cut(out):     # a document cut at its cap is never parsed: it is not a whole one
        try:
            doc = json.loads(out.decode("utf-8")) if out.strip() else None
        except (ValueError, UnicodeDecodeError, RecursionError):
            doc = None
    if values is not None:
        values.close()
    if not isinstance(doc, dict) or doc.get("fatal") or not doc.get("ok"):
        fatal = doc.get("fatal") if isinstance(doc, dict) else None
        dropped = values.drop() if values is not None else False
        said = {"reader_version": "the venv's ccl_chromium_reader is not %s, the version this tool is written against" % READER,
                "reader_not_importable": "ccl_chromium_reader could not be imported in the venv",
                "memory_limit": "the reader needed more memory than the %d bytes it is given" % ((doc.get("memory_limit_bytes") if isinstance(doc, dict) else None) or MEMORY_BYTES),
                "deadline": "the reader's clock of %d seconds ran out before it had made a document" % seconds}.get(fatal)
        basis = said or ("the reader's document was not read whole (%s)" % output_cut(out) if output_cut(out) else
                         "the reader's process was killed at its clock (%d seconds) and made no document" % (seconds + CHILD_GRACE) if timed_out else
                         "the reader's process ended with a signal (%d) and made no document" % -code if isinstance(code, int) and code < 0 else
                         "the reader's process did not make a document that could be read (exit code %s)" % code)
        extra = {}
        if isinstance(doc, dict):
            extra["reader"] = doc.get("versions")
            if doc.get("error_class"):
                extra["error_class"] = shown(doc["error_class"], 60)
        say({"ok": False, "tool": TOOL, "parser": PARSER, "status": "failed", "complete": False, "path": own_path(path),
             "status_basis": "no inventory was made: %s" % basis, "failure": fatal or "no_document",
             "unavailable": True if fatal in ("reader_version", "reader_not_importable") else None,
             "values_file": None if dropped or values is None else values.shown, "process_notes": process_notes() or None, **extra}, 1)

    reasons = []
    files = doc["files"]
    bad = [f for f in files if f["status"] != "read"]
    if bad:
        reasons.append("%d of %d data files could not be read to their end (named in files: their status, the stage and the class of the error)" % (len(bad), len(files)))
    if listing["refused"]:
        reasons.append("%d entries under a data file's name were refused (symbolic link or not a regular file) and not read" % len(listing["refused"]))
    if listing["entries_cut"]:
        reasons.append("the directory has more than %d entries; the listing stopped there" % MAX_ENTRIES)
    manifest = doc.get("manifest")
    if manifest and manifest.get("status") != "read":
        reasons.append("the MANIFEST could not be read")
    if doc.get("stopped"):
        reasons.append({"deadline": "the %d-second clock stopped the reading" % seconds, "record_cap": "the %d-record cap stopped the reading" % MAX_RECORDS}.get(doc["stopped"], "the reading was stopped"))
    if doc.get("indexeddb_error_class"):
        reasons.append("the IndexedDB metadata could not be read (%s): the directory is reported as a plain LevelDB or without some databases" % shown(doc["indexeddb_error_class"], 60))
    all_failed = bool(files) and all(f["status"] == "failed" for f in files)

    answer = {"ok": True, "tool": TOOL, "parser": PARSER, "path": own_path(path), "reader": doc.get("versions"), "format": doc.get("format"),
              "memory_limit_bytes": doc.get("memory_limit_bytes"),
              "files": [{k: f[k] for k in ("name", "kind", "size", "records", "put", "delete", "unknown", "records_in_compressed_blocks", "status", "stage", "reason",
                                           "error_class", "errno", "problem", "problem_offset") if k in f and f[k] is not None} for f in files],
              "manifest": {k: manifest[k] for k in ("name", "status", "table_files_added", "error_class", "problem", "problem_offset", "reason") if k in manifest} if manifest else None,
              "refused_entries": [{"name": shown(r["name"], 40), "why": r["why"]} for r in listing["refused"][:50]] or None,
              "other_entries": listing["other_entries"], "records": {"total": doc.get("records_total"), **(doc.get("counts") or {})},
              "provenance": "each record is located by its file, its offset (the start of its record in a log file or an uncompressed table block, the start of its "
                            "block in a compressed one: offset_is says which), its sequence number and its state (put, delete); the parser is %s on ccl_chromium_reader %s" % (PARSER, READER)}
    if doc.get("format") == "indexeddb":
        idb_doc = doc["indexeddb"]
        dbs = []
        cut = False
        for d in idb_doc["databases"][:LIST_DATABASES]:
            stores = d["stores"]
            if len(stores) > LIST_STORES:
                cut = True
            dbs.append({"id": d["id"], "name": shown(d["name"]), "origin": redact_url(cell(d["origin"]))[:200], "max_store_id": d["max_store_id"],
                        "stores_total": len(stores), "stores": [shape_store(s) for s in stores[:LIST_STORES]]})
        if len(idb_doc["databases"]) > LIST_DATABASES:
            cut = True
        if cut:
            reasons.append("the listing is bounded at %d databases and %d stores each; select with db_id and store_id to see the rest" % (LIST_DATABASES, LIST_STORES))
        answer["indexeddb"] = {"databases": dbs, "databases_total": len(idb_doc["databases"]), "schema_version": doc.get("schema_version"),
                               "records_outside_data": idb_doc.get("records_outside_data"),
                               "stores_of_unlisted_databases": len(idb_doc.get("stores_of_unlisted_databases") or []),
                               "duplicate_database_entries": doc.get("duplicate_database_entries", 0)}
        if idb_doc.get("stores_of_unlisted_databases"):
            reasons.append("%d stores belong to a database id that the metadata does not list" % len(idb_doc["stores_of_unlisted_databases"]))
    else:
        answer["leveldb"] = doc.get("leveldb")
    if write_values:
        answer["values_inline"] = False
        size, lines, end, problem = values.read_back(STARTED + READBACK_UNTIL) if values else (None, None, None, None)
        wr = doc.get("write") or {}
        agrees = lines is None or (end is not None and end.get("records") == lines - 2)
        whole_file = end is not None and problem is None and agrees and wr.get("write_error") is None
        written = (end or {}).get("records", 0) if end is not None and agrees else (max(0, lines - 1) if lines else 0)
        if lines is None and problem is None:
            reasons.append("the values file was too large to count in the time left: its end line is read, its lines are not counted")
        elif not whole_file:
            reasons.append("the values file has no end line or does not agree with it (%s): it is a prefix of whole lines" % (problem or wr.get("write_error") or "cut short"))
        if wr.get("stopped") and wr.get("stopped") != doc.get("stopped"):
            reasons.append("the values file stopped at %s" % shown(str(wr["stopped"]), 40))
        if wr.get("oversized"):
            reasons.append("%d records over %d bytes were named in the values file without their bytes" % (wr["oversized"], LINE_CAP))
        answer["secret_values"] = {"requested": True, "records_written": written, "values_file": values.shown, "contains_secret_values": written > 0,
                                   "file_bytes_read_back": size, "lines_counted": lines, "end_line": bool(end), "stopped": wr.get("stopped"), "write_error": wr.get("write_error"),
                                   "records_not_decoded": wr.get("undecoded"), "records_over_the_line_limit": wr.get("oversized"),
                                   "format": "JSON Lines, mode 0600: a header line, one line per record (n, locator{file, offset, offset_is, seq, state}, database, store, "
                                             "names, key, key_type, key_raw_b64, value, value_error, raw_b64 = the record's value bytes whole) and an end line"}
        if written == 0 and answer["format"] == "leveldb" and (db_id is not None or store_id is not None):
            answer["secret_values"]["note"] = "db_id and store_id select IndexedDB stores; this directory was read as a plain LevelDB, so nothing was selected"
        elif written == 0 and (db_id is not None or store_id is not None) and not doc.get("stopped"):
            answer["secret_values"]["note"] = "db_id and store_id matched no data record, so the file holds a header and an end line and no record; status complete says the files were read, not that anything was selected"
    else:
        answer["values_inline"] = preview_records > 0
        answer["preview_chars"] = preview_chars
        if doc.get("format") == "indexeddb":
            answer["previews"] = [{"database": p["database"], "store": p["store"], "database_name": shown(p["database_name"]) if p.get("database_name") is not None else None,
                                   "store_name": shown(p["store_name"]) if p.get("store_name") is not None else None, "current_keys_in_store": p["current_keys_in_store"],
                                   "records": [{"locator": r["locator"], "key_type": r["key_type"], "key": shape_preview(r["key"], preview_chars), "value_type": r["value_type"],
                                                "value": shape_preview(r["value"], preview_chars), "value_error": r["value_error"]} for r in p["records"]]}
                                  for p in doc.get("previews", [])]
        else:
            answer["previews"] = [shape_plain_preview(p, preview_chars) for p in doc.get("previews", [])]
        answer["records_not_decoded"] = doc.get("decode_errors") or None
    verdict = process_verdict()
    if verdict["left_behind"]:
        reasons.append("the reader's process left %d process(es) running after it ended (in the tool's process group or, in a session of its own, outside it); settle() killed and reaped "
                       "them before the document was read%s" % (verdict["left_behind"], ", so the values file is what they held at that moment and what the leftover would still have "
                                                                "written is missing" if write_values else ""))
    if write_values:
        reasons.extend(why + ": the values file cannot be shown to be final" for why in verdict["unproven"])
    answer["status"] = "failed" if all_failed else ("complete" if not reasons else "partial")
    answer["complete"] = answer["status"] == "complete"
    answer["status_basis"] = (
        ("every data file was read to its end by ccl_chromium_reader %s, nothing under a data file's name was refused, and the counts are those of the records it gave" % READER)
        if answer["status"] == "complete" else
        ("no data file could be read" if all_failed else "; ".join(reasons)))
    answer["not_checked"] = ["the CRC32C of log records and table blocks (neither the reader nor this tool verifies it)",
                             "values stored outside the LevelDB (blob files): no blob directory is read",
                             "that a record is the newest the browser wrote: the counts follow the sequence numbers the files hold",
                             "Local Storage and Session Storage records are not interpreted",
                             "that the MANIFEST agrees with the directory: it is read, and a table it names that is not there, a table that is there and it does not name, an empty MANIFEST or "
                             "a missing one does not change the status",
                             "that a database or object store listed is current: the reader takes the names from the newest metadata record that is a put, so a name whose newest record is a "
                             "delete is still listed, with has_metadata true"]
    answer["limits"] = {"input_bytes": listing["bytes"], "input_limit": INPUT_MAX, "record_limit": MAX_RECORDS, "clock_seconds": seconds,
                        "previews_are_bounded": "depth 4, 12 entries a level, preview_chars characters a text; the whole record is in the values file of a secret_output job"}
    answer["withholding"] = {"counts": dict(COUNTS), "rule": "by shape: a token-shaped run, user-info, a credential-named field or text pair is not printed; a secret of another shape is printed"}
    answer["notes"] = [
        "A preview is a lead, not a record. A secret of a shape the withholding does not know is printed in a preview: read the store in a secret_output job (write_values) when its secrets matter.",
        "put and delete are the states the files record for a key at a sequence number; a store's current_keys are the keys whose newest record is a put.",
    ]
    notes = process_notes()
    if notes:
        answer["process_notes"] = notes
    apply_program_verdict(answer, write_values)    # program_group: what settle() ended and why absence is unproven (a complete answer is already partial above)
    say(answer, 0 if answer["status"] == "complete" else 1)


if __name__ == "__main__":
    exit_code = 0
    try:
        main()
    except SystemExit as stop:
        exit_code = _code(stop)
    _leave(exit_code)
