#!/usr/bin/env python3
"""One immutable descriptor for declared image sources: what they are, in what order, what media they make, and where its volumes start.

Input is an ordered list of DECLARED sources (an E01 set's segments, the segments of a split raw image, or a virtual disk and the
files it depends on) and a sector size. Nothing outside that list is looked for, listed or opened by this tool, and nothing is
mounted. What it does, exactly:

  * Each source is opened without waiting and without following a link and must be a regular file (a link, FIFO, directory or
    device is refused). Its size is taken, and its sha256 unless hash_sources is false or the share of the time budget given to
    hashing ran out (it is then `not_hashed`, with the reason). The container is named from the bytes, not the name: EWF1 or
    EWF2 (E01, S01, Ex01), AFF, QCOW, VHDX, VMDK (a sparse extent or a text descriptor), VHD (a footer at the start or the end), else raw.
  * An EWF set must be declared whole and in order: the naming run (.E01 to .E99, .EAA on) is checked, a segment that is not
    declared is a missing dependency, and for an E01 or S01 segment the chain of section descriptors is read here (the checksum of
    each, `next` or `done` at the end), so a last declared segment that does not end the set is a missing dependency too. A split
    raw set is the declared files in the declared order; their sizes add up to the media. A QCOW2 header's backing file, a VMDK
    descriptor's parent and extents, and a VHD differencing disk's parent name are read from the headers and must be among the declared
    sources (matched by name); one that is not is listed in `missing_dependencies` and the programs are NOT run on that disk (they
    would look for it by name, outside what was declared). A VHDX parent locator is not read, and AFF is not examined: both are said.
  * With the sources whole, ewfinfo (EWF), `qemu-img info --output=json` (a virtual disk; never --backing-chain, which can open
    files outside the evidence), img_stat, mmls and fsstat are run through the shared process block, each bounded, each with its
    output kept whole in a content-addressed file. The sector size is passed to every program as -b. The partition table is
    `true` (mmls read one), `false` (mmls ran and recognised none, which does not show there is none) or `unknown`. Each allocated
    slot, or the whole media when there is no table, is read with fsstat at its offset in sectors.
  * The descriptor is canonical JSON with no clock in it, written under the out directory as layer-<sha256 of its bytes>.json,
    mode 0600, with O_EXCL and a link into place. The same inputs give the same bytes and the same name: a second call finds the
    file, compares its bytes and says it was already there; nothing is replaced. The tool returns the sha256, and a consumer
    refuses a descriptor whose bytes do not hash to the name it carries. The descriptor holds the declared paths exactly as given
    (a consumer opens them): it is a private file, and every path the answer prints goes through the shared withholding.
  * `complete` only when every source was read (and hashed unless that was declined), nothing declared is missing, the media size
    is known and agrees across what reports it, mmls ran to a table answer and every allocated slot was read by fsstat. A
    dependency that is not declared, a program that is missing, timed out or refused, and a time budget that ran out make it `partial`
    and say which. A refused or unreadable source, a set out of order or damaged, and a mixed set are `failed`.

Dissect's target-query is not used: no volume view of a target is part of this descriptor. Exit code 0 means a descriptor was written
and the answer is whole about what was done; 1 is a refused argument or a place that cannot be written.
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
#   not printed (3.11 and 3.12 say nothing of it, 3.14 a traceback). A handler that was due runs on the way in, and never raises out of it.
#   Every writer of a final answer calls it before it commits to writing, every error branch at the end calls it, and, when the file runs as
#   a program, standard output is wrapped so that its first write calls it too. _code(stop) is a SystemExit's exit code (its text, if it has
#   one, goes to standard error as the interpreter puts it), and _leave(code) ends the call: both hold the signals first; _leave flushes
#   standard output (a write that fails there makes a 0 an exit 120, as the interpreter does) and standard error, runs the atexit hooks (a hook
#   that removes a temporary file), each step on its own and none able to raise, and ends the process with os._exit, never through the teardown.
# The modules are imported here, as the file is loaded, never inside the ending (an import there ran a due handler inside the import system).
import atexit
import json
import os
import signal
import sys

_ENDING = {"held": False}
_ENDING_SIGNALS = (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)


def answer_a_stop(signum, when="before it had answered"):
    """The one document of a stop that ends the call before any answer was begun (nothing once one has): status failed, interrupted, and
    no claim about what was read or written. A handler whose own last word printed nothing calls it before it ends the process."""
    if _ENDING["held"]:
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


def hold_stop_signals():
    """Hold the stop signals for good. Never raises. Called by a thread that is not the main one, it blocks them there and leaves the rest to
    the main thread's next call."""
    for _attempt in range(len(_ENDING_SIGNALS) + 2):
        if _ENDING["held"]:
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
        except BaseException:  # noqa: BLE001 - a handler that was due ran on the way in (and raised): the hold is made again
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
    hold_stop_signals()
    code = getattr(stop, "code", 1)
    if isinstance(code, int):
        return code
    if code is not None:
        try:
            sys.stderr.write("%s\n" % (code,))
        except BaseException:  # noqa: BLE001
            pass
    return 0 if code is None else 1


def _leave(code):
    hold_stop_signals()
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
    for _signum in _ENDING_SIGNALS:
        signal.signal(_signum, _stopped_without_handler)
    if sys.stdout is not None and not isinstance(sys.stdout, _AnswerStream):
        sys.stdout = _AnswerStream(sys.stdout)
# END SHARED ENDS


import errno
import hashlib
import json
import os
import re
import shutil
import signal
import stat
import struct
import subprocess
import sys
import time
import zlib
from pathlib import Path

TOOL = {"name": "layer_describe", "version": 7}
STARTED = time.monotonic()
CHUNK = 1 << 20
MAX_SECONDS_DEFAULT = 1500
MAX_SECONDS_CEILING = 1700               # inside the manifest's 1800
RESERVE_SECONDS = 45
HASH_SHARE = 0.4
CHILD_SECONDS = 120
VERSION_SECONDS = 20
GAP_PROBE = 16
MAX_SOURCES = 10000
SECTION_MAX = 4_000_000
OUTPUT_READ_MAX = 4 * 1024 * 1024
HEADER_TEXT_MAX = 1024 * 1024            # a VMDK descriptor or a QCOW2 backing name is read up to this
SLOTS_MAX = 128                          # allocated slots read with fsstat in one call
LIMIT_DEFAULT = 200
LIMIT_CEILING = 5000
SECTOR_MAX = 65536
DESCRIPTOR_VERSION = 1

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
# program is still alive nothing is capped here (a program's own output is its caller's to bound); the timing is unchanged.
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
    a call of communicate_bounded that was cut at POST_EXIT_BYTES counts, PIPE_CUT):
    what a program wrote while the tool read it is not a complete result. A carrier calls it once where it prints its answer. Returns `answer`."""
    verdict = process_verdict()
    answer["program_group"] = verdict
    if (verdict["left_behind"] > 0 or verdict["unproven"] or PIPE_CUT["cut"]) and answer.get("status") == "complete":
        answer["status"] = "partial"
        for flag in ("ok", "complete"):
            if flag in answer:
                answer[flag] = False
        if verdict["left_behind"] > 0:
            sentence = "a program left %d process%s running after it ended; the tool ended them, and what they wrote before that is in the files named here" % (
                verdict["left_behind"], "" if verdict["left_behind"] == 1 else "es")
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


def communicate_bounded(proc, seconds, input=None):
    """(stdout bytes, stderr bytes, timed out) for a program started with pipes, in bytes. At `seconds` the program and what it started
    are killed (timed out). A program that has ended while something it started still holds its pipes (a daemon, a helper that
    inherited them) does not hold the tool: from the moment the program has ended (or was killed) the pipes are given PIPE_GRACE seconds
    and POST_EXIT_BYTES bytes, whichever is used up first; what the program wrote is kept, what the tool lost is killed (reap_orphans,
    settle), and the pipes are let go. A cut at the byte cap is counted in PIPE_CUT and noted (process_notes()); the return shape is the
    same. The pipes are read here and by nothing else (not by Popen.communicate), so letting them go is safe. `input` is written while
    the program runs and is dropped once it has ended."""
    deadline = time.monotonic() + max(0.1, seconds)
    bufs = (bytearray(), bytearray())
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
    timed_out, note, ended, extra, cut, sampled = False, None, None, 0, False, 0.0
    try:
        while True:
            now = time.monotonic()
            if ended is None:
                if proc.poll() is not None:
                    ended = now
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
                bufs[key.data].extend(data)
                if ended is not None:
                    extra += len(data)
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
    err = bytes(bufs[1])
    if note:
        err = err + (b"\n" if err else b"") + note.encode("utf-8", "replace")
    return bytes(bufs[0]), err, timed_out


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
    answer_a_stop(signum)
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


# ---- segment names --------------------------------------------------------------------------------------------------------

def ext_of(path):
    base = os.path.basename(path)
    stem, dot, ext = base.rpartition(".")
    return (stem, ext) if dot and stem else (None, None)


FIRST_EXT = re.compile(r"^([EeSsLl])([Xx]?)(01)$")


def expected_ext(first_ext, n):
    """The extension of segment n in the run the first segment's extension starts: E01 ... E99, EAA ... EZZ, FAA ... ZZZ; the same with a
    fixed x after the first letter for EWF2 (Ex01). The case of the first letter is kept. None when the run does not reach n."""
    lead = first_ext[:len(first_ext) - 2]
    if n < 1:
        return None
    if n <= 99:
        return "%s%02d" % (lead, n)
    m = n - 100
    hi, rem = divmod(m, 676)
    letter = ord(lead[0].upper()) + hi
    if letter > ord("Z"):
        return None
    first = chr(letter)
    tail = chr(65 + rem // 26) + chr(65 + rem % 26)
    if lead[0].islower():
        first, tail = first.lower(), tail.lower()
    return first + lead[1:] + tail


def number_of(first_ext, ext):
    """The place a segment's extension has in the run, or None when it is not an extension of that run (a mixed case is not one)."""
    lead_len = len(first_ext) - 2
    if len(ext) != len(first_ext):
        return None
    tail = ext[lead_len:]
    if tail.isascii() and tail.isdigit():
        n = int(tail)
    elif tail.isascii() and tail.isalpha():
        hi = ord(ext[0].upper()) - ord(first_ext[0].upper())
        if hi < 0:
            return None
        n = 100 + hi * 676 + (ord(tail[0].upper()) - 65) * 26 + (ord(tail[1].upper()) - 65)
    else:
        return None
    return n if n >= 1 and expected_ext(first_ext, n) == ext else None


EWF1_SIGNATURE = b"EVF\x09\x0d\x0a\xff\x00"
EWF2_SIGNATURE = b"EVF2\x0d\x0a\x81\x00"
LOGICAL_SIGNATURES = (b"LVF\x09\x0d\x0a\xff\x00", b"LVF2\x0d\x0a\x81\x00")


def refusal_of(path):
    """Why a segment may not be read, from lstat: a link, a directory, a FIFO, a device. None when it is a regular file."""
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


def sections_of(fd, size):
    """Walk the chain of section descriptors of an EWF1 segment from offset 13. (count, ended_with, problem): ended_with is the type of the
    section the chain stops at ("next" or "done"), None when it does not get there. A descriptor is 76 bytes: a 16-byte type, the offset of
    the next section and the section's size (8 bytes each), 40 bytes of padding and the Adler-32 of the first 72 bytes."""
    offset, count = 13, 0
    while True:
        if offset + 76 > size:
            return count, None, "the chain of sections runs past the end of the file (offset %d, %d bytes in the file)" % (offset, size)
        raw = os.pread(fd, 76, offset)
        if len(raw) < 76:
            return count, None, "the file ends inside a section descriptor at offset %d" % offset
        if zlib.adler32(raw[:72]) & 0xFFFFFFFF != struct.unpack("<I", raw[72:76])[0]:
            return count, None, "the checksum of the section descriptor at offset %d does not match" % offset
        count += 1
        kind = raw[:16].split(b"\0", 1)[0]
        following = struct.unpack("<Q", raw[16:24])[0]
        if kind in (b"done", b"next"):
            return count, kind.decode("ascii"), None
        if following <= offset or following > size:
            return count, None, "the section at offset %d points to %d, which is not further on in the file" % (offset, following)
        offset = following
        if count >= SECTION_MAX:
            return count, None, "more than %d sections: the chain is not walked further" % SECTION_MAX
        if count % 256 == 0 and time.monotonic() > STARTED + PROGRESS["budget"] - PROGRESS["reserve"]:
            return count, None, "the time budget ran out inside the chain of sections"


def hash_fd(fd, deadline):
    """(sha256, None) or (None, why not): read from the start with the clock read for every block."""
    h = hashlib.sha256()
    os.lseek(fd, 0, os.SEEK_SET)
    done = 0
    while True:
        block = os.read(fd, CHUNK)
        if not block:
            return h.hexdigest(), None
        h.update(block)
        done += len(block)
        if time.monotonic() > deadline:
            return None, "the time given to the sha256 of the segments ran out after %d bytes of this one" % done


INFO_FIELDS = (
    ("file_format", re.compile(r"^[ \t]*File format:[ \t]*(\S.*?)[ \t]*$", re.M), str),
    ("bytes_per_sector", re.compile(r"^[ \t]*Bytes per sector:[ \t]*([0-9]+)[ \t]*$", re.M), int),
    ("number_of_sectors", re.compile(r"^[ \t]*Number of sectors:[ \t]*([0-9]+)[ \t]*$", re.M), int),
    ("sectors_per_chunk", re.compile(r"^[ \t]*Sectors per chunk:[ \t]*([0-9]+)[ \t]*$", re.M), int),
    ("media_size_bytes", re.compile(r"^[ \t]*Media size:.*\(([0-9]+) bytes\)[ \t]*$", re.M), int),
    ("stored_md5", re.compile(r"^[ \t]*MD5:[ \t]*([0-9a-fA-F]{32})[ \t]*$", re.M), str),
    ("stored_sha1", re.compile(r"^[ \t]*SHA1:[ \t]*([0-9a-fA-F]{40})[ \t]*$", re.M), str),
    ("acquisition_date", re.compile(r"^[ \t]*Acquisition date:[ \t]*(\S.*?)[ \t]*$", re.M), str),
    ("software_version", re.compile(r"^[ \t]*Software version used:[ \t]*(\S.*?)[ \t]*$", re.M), str),
)


def parse_info(text):
    found = {}
    for key, pattern, kind in INFO_FIELDS:
        m = pattern.search(text)
        if m:
            value = kind(m.group(1))
            found[key] = value.lower() if key.startswith("stored_") else (scrub(value[:200]) if kind is str else value)
    return found


def same_identity(path, identity):
    try:
        st = os.lstat(path)
    except OSError:
        return False
    return stat.S_ISREG(st.st_mode) and (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns) == identity


# ---- the sources ---------------------------------------------------------------------------------------------------------

PROGRESS = {"phase": "starting", "budget": MAX_SECONDS_DEFAULT, "reserve": RESERVE_SECONDS, "sources": 0, "hashed": 0, "dest": None}
DEST = {"path": None}
VERSIONS = {}


def time_left():
    return STARTED + PROGRESS["budget"] - time.monotonic()


def program_path(argument):
    """A path as the programs are given it: never one that begins with a dash, which they would read as an option."""
    return "./" + argument if argument.startswith("-") else argument


def be(data, offset, size):
    return int.from_bytes(data[offset:offset + size], "big") if len(data) >= offset + size else None


def le(data, offset, size):
    return int.from_bytes(data[offset:offset + size], "little") if len(data) >= offset + size else None


def vmdk_text_names(text):
    """(parent file name or None, extent file names) from the text of a VMDK descriptor."""
    parent = re.search(r'^parentFileNameHint[ \t]*=[ \t]*"([^"\n]*)"', text, re.M)
    extents = re.findall(r'^(?:RW|RDONLY|NOACCESS)[ \t]+[0-9]+[ \t]+[A-Z]+[ \t]+"([^"\n]*)"', text, re.M)
    return (parent.group(1) if parent else None), extents


def name_key(name):
    """The last component of a name a header stores, whichever separator it was written with, lower-cased for the comparison."""
    return name.replace("\\", "/").rsplit("/", 1)[-1].casefold()


def inspect_source(path, index, do_hash, hash_deadline):
    """One declared source: (entry, identity). The entry never raises: what could not be read is in `problems`."""
    entry = {"index": index, "path": path, "bytes": None, "sha256": None, "not_hashed": None, "signature": None, "basis": None, "role": None,
             "problems": [], "references": []}
    refusal = refusal_of(path)
    if refusal:
        entry["problems"].append("the source " + refusal)
        entry["not_hashed"] = "the source was refused"
        return entry, None
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        entry["problems"].append("the source cannot be opened: %s" % describe(exc))
        entry["not_hashed"] = "the source could not be opened"
        return entry, None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            entry["problems"].append("the source is not a regular file (it changed after it was checked): refused")
            entry["not_hashed"] = "the source was refused"
            return entry, None
        size = st.st_size
        entry["bytes"] = size
        identity = (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns)
        try:
            head = os.pread(fd, 4096, 0)
            tail = os.pread(fd, 512, size - 512) if size >= 512 else b""
            sig, basis = "raw", "no container signature matched: the bytes of a disk or volume, or a format this tool does not know"
            if head[:8] == EWF1_SIGNATURE:
                sig, basis = "ewf1", "signature at offset 0"
            elif head[:8] == EWF2_SIGNATURE:
                sig, basis = "ewf2", "signature at offset 0"
            elif head[:8] in LOGICAL_SIGNATURES:
                sig, basis = "ewf-logical", "signature at offset 0"
            elif head[:3] == b"AFF":
                sig, basis = "aff", "signature at offset 0"
            elif head[:4] == b"QFI\xfb":
                sig, basis = "qcow", "signature at offset 0"
            elif head[:8] == b"vhdxfile":
                sig, basis = "vhdx", "signature at offset 0"
            elif head[:4] == b"KDMV":
                sig, basis = "vmdk", "sparse extent signature at offset 0"
            elif head.startswith(b"# Disk DescriptorFile"):
                sig, basis = "vmdk", "text descriptor at offset 0"
            elif head[:8] == b"conectix":
                sig, basis = "vhd", "footer copy at offset 0 (a dynamic or differencing disk)"
            elif tail[:8] == b"conectix":
                sig, basis = "vhd", "footer in the last 512 bytes (a fixed disk)"
            entry["signature"], entry["basis"] = sig, basis
            if sig == "ewf1":
                entry["segment_number_in_header"] = le(head, 9, 2)
                count, ended, problem = sections_of(fd, size)
                entry["sections"], entry["ends_with"] = count, ended
                if problem:
                    entry["problems"].append(problem)
            elif sig == "ewf2":
                entry["segment_number_in_header"] = le(head, 12, 4)
            elif sig == "qcow":
                off, length, virtual = be(head, 8, 8), be(head, 16, 4), be(head, 24, 8)
                entry["virtual_bytes"] = virtual
                entry["qcow_version"] = be(head, 4, 4)
                if off and length and length <= 4096 and off + length <= size:
                    name = os.pread(fd, length, off).decode("utf-8", "replace")
                    entry["references"].append({"kind": "backing file", "name": name})
                elif off or length:
                    entry["problems"].append("the QCOW header names a backing file that cannot be read (offset %s, length %s)" % (off, length))
            elif sig == "vmdk":
                text = ""
                if head[:4] == b"KDMV":
                    entry["virtual_bytes"] = (le(head, 12, 8) or 0) * 512 or None
                    doff, dlen = le(head, 28, 8), le(head, 36, 8)
                    if doff and dlen and doff * 512 < size:
                        text = os.pread(fd, min(dlen * 512, HEADER_TEXT_MAX, size - doff * 512), doff * 512).decode("utf-8", "replace")
                elif size <= HEADER_TEXT_MAX:
                    text = os.pread(fd, size, 0).decode("utf-8", "replace")
                else:
                    entry["problems"].append("the VMDK text descriptor is larger than %d bytes and is not read" % HEADER_TEXT_MAX)
                parent, extents = vmdk_text_names(text)
                if parent and parent != "":
                    entry["references"].append({"kind": "parent", "name": parent})
                for extent in extents:
                    if name_key(extent) != os.path.basename(path).casefold():
                        entry["references"].append({"kind": "extent", "name": extent})
            elif sig == "vhd":
                footer = head[:512] if head[:8] == b"conectix" else tail
                entry["virtual_bytes"] = be(footer, 48, 8)
                disk_type = be(footer, 60, 4)
                entry["vhd_type"] = {2: "fixed", 3: "dynamic", 4: "differencing"}.get(disk_type, disk_type)
                if disk_type == 4:
                    data_offset = be(footer, 16, 8)
                    block = os.pread(fd, 1024, data_offset) if data_offset is not None and data_offset + 1024 <= size else b""
                    if block[:8] == b"cxsparse":
                        raw = block[64:64 + 512]
                        name = raw.decode("utf-16-be", "replace").split("\0", 1)[0]
                        entry["references"].append({"kind": "parent", "name": name})
                    else:
                        entry["problems"].append("the VHD differencing header cannot be read, so its parent is not known")
            if do_hash:
                if time.monotonic() > hash_deadline:
                    entry["not_hashed"] = "the time given to the sha256 of the sources was used before this one"
                else:
                    entry["sha256"], entry["not_hashed"] = hash_fd(fd, hash_deadline)
            else:
                entry["not_hashed"] = "hashing was not asked for (hash_sources is false)"
        except OSError as exc:
            entry["problems"].append("the source cannot be read: %s" % describe(exc))
            if entry["sha256"] is None and entry["not_hashed"] is None:
                entry["not_hashed"] = "the source could not be read"
        return entry, identity
    finally:
        os.close(fd)


# ---- the programs ---------------------------------------------------------------------------------------------------------

def finish_file(temp, directory, label, sha, size):
    """Give a staged output file its content-addressed name (raw-<label>-<sha256 start>.txt) or drop it when that file is already there."""
    if size == 0:
        temp_drop(temp)
        return None
    name = "raw-%s-%s.txt" % (label, sha[:24])
    final = os.path.join(directory, name)
    try:
        os.link(temp, final)
    except FileExistsError:
        pass
    except OSError:
        # a file system without hard links: the staged file is renamed into place unless the name is taken
        if os.path.lexists(final):
            pass
        else:
            temp_replace(temp, final)
            return name
    temp_drop(temp)
    return name


def sha_and_text(path):
    h = hashlib.sha256()
    first = b""
    total = 0
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        while True:
            block = os.read(fd, CHUNK)
            if not block:
                break
            h.update(block)
            total += len(block)
            if len(first) < OUTPUT_READ_MAX:
                first += block[:OUTPUT_READ_MAX - len(first)]
    finally:
        os.close(fd)
    return h.hexdigest(), total, first.decode("utf-8", "replace"), total > OUTPUT_READ_MAX


LOGGED = [False]    # a program whose output went to files (mmls, fsstat, ewfinfo, qemu-img) was started: the files the descriptor hashes and names are written by a program


def program_reasons():
    """Why the files a program wrote cannot be taken as final, from the shared block's verdict (partial_reasons, so the descriptor says it too): settle() ended a
    process that a program left behind (it may have written to the output file whose sha256 and size the descriptor holds, and what it would still have written is
    missing), or nothing can show that none was left (a host that is not Linux, a kernel that refuses PR_SET_CHILD_SUBREAPER). Only when a program wrote a file:
    a version probe prints on a pipe, and a pipe is not held to the second."""
    verdict = process_verdict()
    reasons = []
    if verdict["left_behind"]:
        reasons.append("a program left %d process(es) running after it ended (a child that held its output file, in the tool's process group or, in a session of its own, outside it); "
                       "settle() killed and reaped them before the output was hashed and kept, so the sha256 and size of its stdout and stderr are those of what the file held "
                       "at that moment and what the leftover would still have written is missing" % verdict["left_behind"])
    if LOGGED[0]:
        reasons.extend(why + ": the output files of the programs (and their sha256) cannot be shown to be final" for why in verdict["unproven"])
    return reasons


def run_program(label, argv, shown_argv, seconds):
    """One program in this tool's process group, its output staged in two private files and kept whole under content-addressed names.
    A dict: exit_code, timed_out, error, the output's sha256 and size and file name, and the start of stdout as `text`."""
    result = {"name": argv[0], "label": label, "argv": shown_argv, "exit_code": None, "timed_out": False, "error": None, "text": "", "truncated": False}
    if shutil.which(argv[0]) is None:
        result["error"] = "%s is not on PATH" % argv[0]
        return result
    if seconds < 1:
        result["error"] = "the time budget was used before %s could be run" % argv[0]
        return result
    env = dict(os.environ, LC_ALL="C", LANG="C")
    directory = str(DEST["path"])
    out_fd = err_fd = None
    try:
        out_fd, out_name = temp_create(directory, ".ld-out-")
        err_fd, err_name = temp_create(directory, ".ld-err-")
    except OSError as exc:
        for fd in (out_fd, err_fd):
            if fd is not None:
                os.close(fd)
        result["error"] = "the program's output files could not be made: %s" % describe(exc)
        return result
    try:
        try:
            proc = spawn(argv, stdout=out_fd, stderr=err_fd, env=env)
        except OSError as exc:
            result["error"] = "the program could not be started: %s" % describe(exc)
            proc = None
        if proc is not None:
            LOGGED[0] = True
            ACTIVE.append(proc)
            try:
                result["exit_code"] = proc.wait(timeout=max(0.1, seconds))
            except subprocess.TimeoutExpired:
                kill_tree(proc)
                proc.wait()
                result["timed_out"] = True
            finally:
                ACTIVE.remove(proc)
    finally:
        os.close(out_fd)
        os.close(err_fd)
    for stream, name in (("stdout", out_name), ("stderr", err_name)):
        try:
            sha, total, text, cut = sha_and_text(name)
            result[stream + "_sha256"], result[stream + "_bytes"] = sha, total
            if stream == "stdout":
                result["text"], result["truncated"] = text, cut
            result[stream + "_file"] = finish_file(name, directory, "%s-%s" % (label, stream), sha, total)
        except OSError as exc:
            result[stream + "_error"] = "its output could not be kept: %s" % describe(exc)
            temp_drop(name)
    return result


def program_version(program):
    if program in VERSIONS:
        return VERSIONS[program]
    VERSIONS[program] = None
    if shutil.which(program):
        flag = "--version" if program == "qemu-img" else "-V"
        code, out, err, timed = preflight([program, flag], VERSION_SECONDS)
        line = next((ln.strip() for ln in (out + err).decode("utf-8", "replace").splitlines() if ln.strip()), "")
        VERSIONS[program] = scrub(line[:120]) if line and not timed else None
    return VERSIONS[program]


SLOT = re.compile(
    r"^(?P<slot>[0-9]{3,}):[ \t]+(?P<table>\S+)[ \t]+(?P<start>[0-9]{10,})[ \t]+(?P<end>[0-9]{10,})[ \t]+(?P<len>[0-9]{10,})[ \t]+(?P<desc>.*\S)[ \t]*$"
)


def parse_mmls(text):
    """(unit, slots, skipped): a row is a line of the shape mmls writes, the one the table is at, whose end and length agree with its start."""
    sector = 512
    m = re.search(r"Units are in (\d+)-byte sectors", text)
    if m:
        sector = int(m.group(1))
    slots, skipped = [], []
    expect, header = 0, False
    for raw in text.split("\n"):
        line = raw.rstrip("\r").strip()
        m = SLOT.match(line)
        if not header and not m:
            header = "Slot" in line and "Start" in line and "Description" in line
            continue
        if not line:
            continue
        if not m:
            skipped.append("is not a row of the table")
            continue
        start, end, length = int(m.group("start")), int(m.group("end")), int(m.group("len"))
        if int(m.group("slot")) != expect:
            skipped.append("is row %d where row %d was due" % (int(m.group("slot")), expect))
            continue
        expect += 1
        if end < start or length != end - start + 1:
            skipped.append("has an end and a length that do not agree with its start")
            continue
        slots.append({"slot": m.group("slot"), "start_sector": start, "length_sectors": length, "description": scrub(m.group("desc")[:200]),
                      "allocated": m.group("table") != "-------" and m.group("table").lower() != "meta"})
    return sector, slots, skipped


FSSTAT_FIELDS = (
    ("fs_type", re.compile(r"^File System Type:[ \t]*(\S.*?)[ \t]*$", re.M)),
    ("cluster_size", re.compile(r"^Cluster Size:[ \t]*(\d+)", re.M)),
    ("sector_size", re.compile(r"^Sector Size:[ \t]*(\d+)", re.M)),
)


def parse_qemu(text):
    try:
        doc = json.loads(text)
    except (ValueError, RecursionError):
        return None
    if not isinstance(doc, dict):
        return None
    out = {}
    if isinstance(doc.get("format"), str):
        out["format"] = scrub(doc["format"][:40])
    if isinstance(doc.get("virtual-size"), int) and not isinstance(doc["virtual-size"], bool):
        out["virtual_size"] = doc["virtual-size"]
    if isinstance(doc.get("backing-filename"), str):
        out["backing_filename"] = doc["backing-filename"]
    return out


# ---- main ---------------------------------------------------------------------------------------------------------------

def canonical(doc):
    return (json.dumps(doc, sort_keys=True, ensure_ascii=True, separators=(",", ":")) + "\n").encode("ascii")


def main():
    try:
        args = json.load(sys.stdin)
    except (ValueError, RecursionError) as exc:
        fail("arguments are not valid JSON", reason=str(exc)[:200])
    if not isinstance(args, dict):
        fail("arguments are a JSON object")
    unknown = sorted(set(args) - {"sources", "sector_size", "hash_sources", "out_dir", "max_seconds", "limit"})
    if unknown:
        fail("unknown parameter: %s" % ", ".join(scrub(str(k)) for k in unknown))
    sources = args.get("sources")
    if not isinstance(sources, list) or not sources or len(sources) > MAX_SOURCES:
        fail("sources is a list of 1 to %d declared paths, in order" % MAX_SOURCES)
    for item in sources:
        if not isinstance(item, str) or not item or "\0" in item:
            fail("a source is a path (a non-empty string without a NUL)")
        try:
            item.encode("utf-8", "surrogateescape")
        except UnicodeEncodeError:
            fail("a source path holds a character that cannot be a byte of a file name")
    sector_size = args.get("sector_size", 512)
    if not isinstance(sector_size, int) or isinstance(sector_size, bool) or sector_size < 512 or sector_size > SECTOR_MAX or sector_size % 512:
        fail("sector_size must be a multiple of 512 from 512 to %d (the Sleuth Kit's -b takes no other)" % SECTOR_MAX, sector_size=scrub(str(sector_size)))
    do_hash = args.get("hash_sources", True)
    if not isinstance(do_hash, bool):
        fail("hash_sources is true or false")
    max_seconds = whole(args, "max_seconds", MAX_SECONDS_DEFAULT, 5, MAX_SECONDS_CEILING)
    limit = whole(args, "limit", LIMIT_DEFAULT, 1, LIMIT_CEILING)
    PROGRESS["budget"] = max_seconds
    PROGRESS["reserve"] = min(RESERVE_SECONDS, max_seconds / 4.0)
    absolute = [os.path.abspath(p) for p in sources]
    if len(set(absolute)) != len(absolute):
        fail("the same source is declared twice")

    os.umask(0o077)
    if args.get("out_dir"):
        if not isinstance(args["out_dir"], str) or "\0" in args["out_dir"]:
            fail("out_dir is a directory path")
        dest = resolve_output(args["out_dir"])
    elif in_job():
        dest = resolve_output(os.path.join(os.environ["OUT"], "layer_describe"))
    else:
        agent = re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool")
        dest = resolve_output(os.path.join("work", agent, "layer_describe"))
    try:
        if dest.exists() and not dest.is_dir():
            fail("out_dir exists and is not a directory", out_dir=scrub(str(dest)))
        made = not dest.exists()
        dest.mkdir(parents=True, exist_ok=True, mode=0o700)
        if made:
            os.chmod(dest, 0o700)
    except (OSError, ValueError, RuntimeError) as exc:
        fail("out_dir cannot be used: %s" % describe(exc), out_dir=scrub(str(args.get("out_dir") or dest)))
    DEST["path"] = dest
    PROGRESS["dest"] = scrub(str(dest))

    def last_word(signum):
        drop_temporaries()                    # the staged output of the program that was running, and a descriptor being written
        print(json.dumps({"ok": False, "tool": TOOL, "status": "partial", "interrupted": True, "signal": signum, "out_dir": PROGRESS["dest"],
                          "phase": PROGRESS["phase"], "sources_read": PROGRESS["sources"], "descriptor": None,
                          "status_basis": "the tool was stopped by signal %d during %s: the program it was running was ended and no descriptor was written; "
                                          "run it again" % (signum, PROGRESS["phase"])}), flush=True)
    STATE["last_word"] = last_word

    fail_reasons, partial_reasons, notes = [], [], []
    missing_deps = []

    # ---- each declared source
    PROGRESS["phase"] = "reading the sources"
    hash_deadline = STARTED + max_seconds * HASH_SHARE
    entries, identities = [], {}
    for index, path in enumerate(absolute):
        entry, identity = inspect_source(path, index, do_hash, hash_deadline)
        entries.append(entry)
        identities[index] = identity
        PROGRESS["sources"] = len(entries)
        if entry["sha256"]:
            PROGRESS["hashed"] += 1
    for entry in entries:
        for problem in entry["problems"]:
            fail_reasons.append("source %d: %s" % (entry["index"], problem))
        if do_hash and entry["sha256"] is None and not entry["problems"]:
            partial_reasons.append("source %d was not hashed (%s)" % (entry["index"], entry["not_hashed"]))

    first = entries[0]
    layer = first["signature"] or "unknown"
    layer_name = "unknown"
    image_paths = []                       # what the programs are given
    expected_tsk = None
    media = {"bytes": None, "basis": None}
    if any(e["bytes"] is None for e in entries):
        notes.append("a source could not be read: no layer is described")
    elif "ewf-logical" in [e["signature"] for e in entries]:
        fail_reasons.append("a logical evidence file (.L01, .Lx01) holds files, not a media image: unsupported")
    elif layer in ("ewf1", "ewf2"):
        layer_name = "ewf"
        stem, first_ext = ext_of(absolute[0])
        if first_ext is None or not FIRST_EXT.match(first_ext):
            fail_reasons.append("the first EWF segment is named .E01, .S01 or .Ex01 (the first of a naming run); this one is not, so the run cannot be checked")
        else:
            numbers = []
            for entry in entries:
                if entry["signature"] != layer:
                    fail_reasons.append("source %d is not an %s segment (a set is one container)" % (entry["index"], layer.upper()))
                    numbers.append(None)
                    continue
                s, e = ext_of(entry["path"])
                n = number_of(first_ext, e) if e is not None else None
                if n is None or s != stem:
                    fail_reasons.append("source %d is not in the naming run of the first segment" % entry["index"])
                numbers.append(n)
                if entry.get("segment_number_in_header") not in (None, n) and n is not None:
                    fail_reasons.append("source %d: the header says this is segment %s, and its place in the run is %d" % (entry["index"], entry.get("segment_number_in_header"), n))
                entry["role"] = "segment %s" % n if n else "segment"
            real = [n for n in numbers if n is not None]
            if len(set(real)) != len(real):
                fail_reasons.append("an EWF segment is declared twice")
            elif real != sorted(real):
                fail_reasons.append("the segments are declared out of order")
            if real and real[0] != 1:
                fail_reasons.append("the declared list does not start with the first segment")
            have = set(real)
            for n in range(1, (max(real) if real else 0) + 1):
                if n not in have:
                    missing_deps.append({"kind": "segment", "name": "%s.%s" % (stem, expected_ext(first_ext, n)), "needed_by": None})
            if layer == "ewf1" and entries and not any(e["problems"] for e in entries[-1:]):
                last = max(zip([n or 0 for n in numbers], entries), key=lambda pair: pair[0])[1]
                if last["ends_with"] != "done" and not missing_deps:
                    nxt = expected_ext(first_ext, max(real) + 1) if real else None
                    missing_deps.append({"kind": "segment", "name": ("%s.%s" % (stem, nxt)) if nxt else "a segment after the last declared one", "needed_by": last["index"]})
                    notes.append("the last declared segment does not end the set (its sections end with %s): a later segment is not declared" % (last["ends_with"] or "nothing"))
            if layer == "ewf2":
                partial_reasons.append("the end of an EWF2 set is not established by this tool (its section chain is not read)")
        image_paths = absolute
        expected_tsk = ("ewf",)
        media["basis"] = "ewfinfo"
    elif layer in ("vmdk", "vhd", "vhdx", "qcow", "aff"):
        layer_name = layer
        entries[0]["role"] = "top"
        declared = {}
        for entry in entries[1:]:
            declared.setdefault(name_key(entry["path"]), []).append(entry)
        used = set()
        for entry in entries:
            for ref in entry["references"]:
                hits = declared.get(name_key(ref["name"]), [])
                hits = [h for h in hits if h["index"] != entry["index"]]
                if hits:
                    hits[0]["role"] = ref["kind"]
                    used.add(hits[0]["index"])
                else:
                    missing_deps.append({"kind": ref["kind"], "name": ref["name"], "needed_by": entry["index"]})
        for entry in entries[1:]:
            if entry["index"] not in used and entry["role"] is None:
                entry["role"] = "declared, not named by any header read"
                notes.append("source %d is declared but no header read here names it" % entry["index"])
        if layer == "vhdx":
            notes.append("a VHDX parent locator is not read by this tool: if this disk is a differencing disk, its parent is not listed as a dependency")
        if layer == "aff":
            notes.append("an AFF image is not examined by this tool beyond its signature; the Sleuth Kit is asked whether it opens it")
        image_paths = absolute[:1]
        expected_tsk = {"vmdk": ("vmdk",), "vhd": ("vhd",), "aff": ("aff",)}.get(layer)
        media["bytes"] = first.get("virtual_bytes")
        media["basis"] = "the %s header" % layer if media["bytes"] is not None else None
    else:
        layer_name = "raw" if len(entries) == 1 else "split_raw"
        for entry in entries:
            if entry["signature"] != "raw":
                fail_reasons.append("source %d is a %s container, not a raw segment: a split set is raw files only" % (entry["index"], entry["signature"]))
            entry["role"] = "raw segment" if len(entries) > 1 else "raw image"
        if len(entries) > 1:
            exts = [ext_of(e["path"]) for e in entries]
            nums = [x[1] for x in exts]
            if all(x[0] is not None and x[0] == exts[0][0] for x in exts) and all(n and n.isdigit() and len(n) == len(nums[0]) for n in nums):
                values = [int(n) for n in nums]
                if values != sorted(values):
                    fail_reasons.append("the numbered segments are declared out of order")
                else:
                    for v in range(values[0], values[-1] + 1):
                        if v not in set(values):
                            missing_deps.append({"kind": "segment", "name": "%s.%0*d" % (exts[0][0], len(nums[0]), v), "needed_by": None})
            else:
                notes.append("the segment names do not form a numbered run (.001, .002 ...): the order is the order declared, and a missing segment cannot be seen")
        image_paths = absolute
        expected_tsk = ("raw", "split")
        total = sum(e["bytes"] or 0 for e in entries)
        if all(e["bytes"] is not None for e in entries):
            media["bytes"], media["basis"] = total, "the sum of the declared segments' sizes" if len(entries) > 1 else "the size of the file"
    # the entries' roles: one place
    for entry in entries:
        if entry["role"] is None:
            entry["role"] = "top" if entry["index"] == 0 else "declared"
    for dep in missing_deps:
        partial_reasons.append("a dependency is not declared: %s%s" % (dep["kind"], "" if not dep["name"] else " " + scrub(dep["name"][:120])))

    # ---- the programs, only on sources that are whole
    programs, table = [], {"partition_table": "unknown", "basis": "the programs were not run", "unit": None, "partitions": []}
    readable_volumes = refused_volumes = unattempted_volumes = 0
    qemu_info, ewf_info = None, {}
    runnable = not fail_reasons and not missing_deps
    images = [program_path(p) for p in image_paths]
    shown = ["<%d source path%s, in order>" % (len(images), "" if len(images) == 1 else "s")]
    if not runnable:
        notes.append("mmls, fsstat and the other programs were not run: %s" % ("a source is refused or damaged, or the set is not in order" if fail_reasons else "a dependency is not declared, and a program would look for it by name outside what was declared"))
    else:
        for program in ("mmls", "fsstat", "img_stat"):
            if shutil.which(program) is None:
                partial_reasons.append("%s is not on PATH" % program)
        PROGRESS["phase"] = "reading the container"

        def step(label, argv, shown_argv):
            res = run_program(label, argv, shown_argv, min(CHILD_SECONDS, time_left() - PROGRESS["reserve"]))
            res["version"] = program_version(argv[0])
            programs.append(res)
            return res

        if layer_name == "ewf":
            res = step("ewfinfo", ["ewfinfo"] + images, ["ewfinfo"] + shown)
            if res["error"] or res["timed_out"] or res["exit_code"] != 0:
                partial_reasons.append("ewfinfo did not give a record (%s)" % scrub(res["error"] or ("timed out" if res["timed_out"] else "exit code %s" % res["exit_code"])))
            else:
                ewf_info = parse_info(res["text"])
                if ewf_info.get("media_size_bytes") is not None:
                    media["bytes"] = ewf_info["media_size_bytes"]
                else:
                    partial_reasons.append("ewfinfo printed no media size this tool can read")
        if layer_name in ("vmdk", "vhd", "vhdx", "qcow"):
            res = step("qemu-img", ["qemu-img", "info", "--output=json", images[0]], ["qemu-img", "info", "--output=json"] + shown)
            if res["error"] or res["timed_out"] or res["exit_code"] != 0:
                notes.append("qemu-img info did not answer (%s); the media size is the container header's where it has one" % scrub(res["error"] or ("timed out" if res["timed_out"] else "exit code %s" % res["exit_code"])))
            else:
                qemu_info = parse_qemu(res["text"])
                if qemu_info is None:
                    partial_reasons.append("qemu-img info printed no JSON this tool can read")
                else:
                    if qemu_info.get("virtual_size") is not None:
                        if media["bytes"] is not None and media["bytes"] != qemu_info["virtual_size"]:
                            partial_reasons.append("qemu-img says the virtual size is %d bytes and the header %d" % (qemu_info["virtual_size"], media["bytes"]))
                        media["bytes"], media["basis"] = qemu_info["virtual_size"], "qemu-img info"
                    back = qemu_info.get("backing_filename")
                    if back and not any(name_key(back) == name_key(e["path"]) for e in entries[1:]):
                        missing_deps.append({"kind": "backing file", "name": back, "needed_by": 0})
                        partial_reasons.append("qemu-img names a backing file that is not declared: %s" % scrub(back[:120]))
        PROGRESS["phase"] = "reading the media"
        sector_args = ["-b", str(sector_size)]
        st = step("img_stat", ["img_stat"] + sector_args + images, ["img_stat"] + sector_args + shown)
        opened_as, tsk_size = None, None
        if not (st["error"] or st["timed_out"]):
            m = re.search(r"^Image Type:[ \t]*(\S+)", st["text"], re.M)
            opened_as = m.group(1).lower() if m else None
            m = re.search(r"^Size in bytes:[ \t]*([0-9]+)", st["text"], re.M)
            tsk_size = int(m.group(1)) if m else None
        elif st["error"] and "PATH" not in st["error"]:
            notes.append("img_stat did not run (%s)" % scrub(st["error"]))
        opened_ok = True
        if opened_as is not None:
            if expected_tsk is None:               # QCOW and VHDX: the Sleuth Kit has no reader, so a raw reading is the container's bytes
                opened_ok = opened_as not in ("raw", "split")
            else:
                opened_ok = opened_as in expected_tsk
        if tsk_size is not None and opened_ok:
            if media["bytes"] is None:
                media["bytes"], media["basis"] = tsk_size, "img_stat"
            elif media["bytes"] != tsk_size:
                partial_reasons.append("img_stat says the media is %d bytes and %s says %d" % (tsk_size, media["basis"], media["bytes"]))
        mm = step("mmls", ["mmls"] + sector_args + images, ["mmls"] + sector_args + shown)
        found_slots = []
        if not opened_ok:
            table.update(partition_table="unknown", basis="mmls printed a table, but img_stat says the Sleuth Kit opened this %s container as %s: its offsets belong to the container's bytes, not to the disk inside, and are not given" % (layer_name, opened_as))
            partial_reasons.append("the Sleuth Kit opened the %s container as %s, so no partition or volume offset is read from it" % (layer_name, opened_as))
        elif mm["error"] or mm["timed_out"]:
            table.update(basis="mmls did not run to a result (%s)" % scrub(mm["error"] or "timed out"))
            partial_reasons.append("mmls did not run to a result (%s)" % scrub(mm["error"] or "timed out"))
        elif mm["exit_code"] == 0:
            unit, found_slots, skipped = parse_mmls(mm["text"])
            for line in skipped[:5]:
                notes.append("a line of mmls's table after its header %s; it is not read as a partition" % line)
            if skipped:
                partial_reasons.append("%d line(s) of mmls's table were not read as rows" % len(skipped))
            if unit != sector_size:
                partial_reasons.append("mmls printed its offsets in %d-byte sectors although -b %d was given" % (unit, sector_size))
            table.update(unit=unit)
            if found_slots:
                table.update(partition_table=True, basis="mmls printed %d row(s)" % len(found_slots))
            else:
                table.update(partition_table="unknown", basis="mmls ran but printed no row this tool can read")
                partial_reasons.append("mmls printed no row this tool can read: whether the image has a partition table is not established")
        else:
            silent = not mm.get("stdout_bytes") and not mm.get("stderr_bytes")
            says_none = False
            if mm.get("stderr_file"):
                try:
                    with open(os.path.join(str(dest), mm["stderr_file"]), "rb") as fh:
                        says_none = bool(re.search(r"cannot determine partition type|unknown partition", fh.read(65536).decode("utf-8", "replace"), re.I))
                except (OSError, TypeError):
                    pass
            if says_none or (silent and opened_as is not None):
                table.update(partition_table=False, unit=sector_size,
                             basis="mmls found no partition table it recognises at sector size %d. That does not show the image has none: a table type the Sleuth Kit does not read, a damaged one and a wrong sector size look the same" % sector_size)
            else:
                table.update(basis="mmls could not tell (exit code %s)" % mm["exit_code"])
                partial_reasons.append("mmls exited with code %s and said nothing this tool reads as 'no table'" % mm["exit_code"])
        # the volumes
        unit = table.get("unit") or sector_size
        targets = []
        if table["partition_table"] is True:
            for slot in found_slots:
                entry = dict(slot)
                entry["offset_sectors"] = slot["start_sector"]
                entry["offset_bytes"] = slot["start_sector"] * unit
                entry["length_bytes"] = slot["length_sectors"] * unit
                table["partitions"].append(entry)
                if slot["allocated"]:
                    targets.append(entry)
        elif opened_ok and (table["partition_table"] is False or table["partition_table"] == "unknown") and not (mm["error"] or mm["timed_out"]):
            whole_entry = {"slot": None, "description": "the whole media, probed with no partition table", "start_sector": 0, "offset_sectors": 0, "offset_bytes": 0, "allocated": True}
            table["partitions"].append(whole_entry)
            targets.append(whole_entry)
        if len(targets) > SLOTS_MAX:
            partial_reasons.append("%d allocated slots: the first %d were read with fsstat, the others are listed and not read" % (len(targets), SLOTS_MAX))
        for entry in targets[:SLOTS_MAX]:
            argv = ["fsstat", "-b", str(unit), "-o", str(entry["offset_sectors"])] + images
            fs = step("fsstat", argv, ["fsstat", "-b", str(unit), "-o", str(entry["offset_sectors"])] + shown)
            if fs["error"] or fs["timed_out"]:
                entry["filesystem"] = {"readable": None, "outcome": "not attempted" if fs["error"] else "timed out"}
                unattempted_volumes += 1
            elif fs["exit_code"] != 0:
                entry["filesystem"] = {"readable": False, "outcome": "refused"}
                refused_volumes += 1
            else:
                found = {"readable": True, "outcome": "read"}
                for key, pattern in FSSTAT_FIELDS:
                    m = pattern.search(fs["text"])
                    if m:
                        found[key] = int(m.group(1)) if key in ("cluster_size", "sector_size") else scrub(m.group(1)[:80])
                entry["filesystem"] = found
                readable_volumes += 1
        for entry in targets[SLOTS_MAX:]:
            entry["filesystem"] = {"readable": None, "outcome": "not attempted"}
            unattempted_volumes += 1
        if refused_volumes:
            partial_reasons.append("%d allocated slot(s) have no file system fsstat read at their offset (a sector size, a mapping layer, an unsupported or damaged file system or encryption each look like this)" % refused_volumes)
        if unattempted_volumes:
            partial_reasons.append("%d allocated slot(s) were not examined (fsstat missing, timed out or not reached)" % unattempted_volumes)
        for res in programs:
            if res.get("truncated"):
                partial_reasons.append("%s printed more than %d bytes: its fields are read from the start, the whole is in its file" % (res["name"], OUTPUT_READ_MAX))
        if media["bytes"] is None:
            partial_reasons.append("the media size is not known")

    # ---- the sources are read again: one that changed while the programs ran is not what was described
    for index, identity in identities.items():
        if identity is not None and not same_identity(entries[index]["path"], identity):
            fail_reasons.append("source %d changed (size, modification time or file) while the descriptor was made" % index)

    # ---- what the programs left behind, before the descriptor says its status
    if not fail_reasons:
        partial_reasons.extend(program_reasons())

    # ---- the descriptor
    for dep in missing_deps:
        dep.setdefault("declared", False)
    d_sources = []
    offset = 0
    for entry in entries:
        row = {"index": entry["index"], "path": entry["path"], "bytes": entry["bytes"], "sha256": entry["sha256"], "not_hashed": entry["not_hashed"],
               "signature": entry["signature"], "signature_basis": entry["basis"], "role": entry["role"]}
        if layer_name in ("split_raw", "raw") and entry["bytes"] is not None:
            row["offset_in_media"] = offset
            offset += entry["bytes"]
        if entry.get("sections") is not None:
            row["sections"], row["ends_with"] = entry["sections"], entry["ends_with"]
        if entry.get("segment_number_in_header") is not None:
            row["segment_number_in_header"] = entry["segment_number_in_header"]
        if entry["references"]:
            row["references"] = entry["references"]
        d_sources.append(row)
    d_programs = [{k: v for k, v in res.items() if k not in ("text", "truncated", "label")} for res in programs]
    status = "failed" if fail_reasons else ("partial" if partial_reasons or missing_deps else "complete")
    descriptor = {
        "descriptor_version": DESCRIPTOR_VERSION, "kind": "layer_descriptor", "tool": TOOL, "status": status,
        "sector_size": sector_size,
        "sources": d_sources,
        "container": {"layer": layer_name, "format": layer, "basis": first["basis"]},
        "media": media,
        "partition_table": table["partition_table"], "partition_table_basis": table["basis"], "partition_unit": table.get("unit"),
        "partitions": table["partitions"],
        "missing_dependencies": missing_deps,
        "programs": d_programs,
        "notes": notes,
        "not_examined": ["snapshots and the files a header names that were not declared", "that a file system fsstat reads is intact, complete or unencrypted",
                         "that a source is the evidence it is said to be: the sha256 of a source is a custody fact about the file"],
    }
    if ewf_info:
        descriptor["acquisition_record"] = {k: v for k, v in ewf_info.items() if k in ("file_format", "bytes_per_sector", "number_of_sectors", "media_size_bytes", "stored_md5", "stored_sha1")}
    if qemu_info:
        descriptor["qemu_img"] = qemu_info
    descriptor_info = None
    PROGRESS["phase"] = "writing the descriptor"
    write_error = None
    refused_sources = any(e["bytes"] is None for e in entries)
    if not refused_sources:
        body = canonical(descriptor)
        sha = hashlib.sha256(body).hexdigest()
        name = "layer-%s.json" % sha
        final = os.path.join(str(dest), name)
        created = False
        try:
            if os.path.lexists(final):
                fd = os.open(final, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
                try:
                    if not stat.S_ISREG(os.fstat(fd).st_mode):
                        raise OSError(errno.EEXIST, "the descriptor's name is taken by something that is not a regular file")
                    held = b""
                    while True:
                        block = os.read(fd, CHUNK)
                        if not block:
                            break
                        held += block
                        if len(held) > len(body):
                            break
                finally:
                    os.close(fd)
                if held != body:
                    raise OSError(errno.EEXIST, "a file of the descriptor's name holds other bytes; it is not replaced")
            else:
                fd, tmp = temp_create(str(dest), ".ld-desc-")
                try:
                    with os.fdopen(fd, "wb") as fh:
                        fh.write(body)
                        fh.flush()
                        os.fsync(fh.fileno())
                except BaseException:
                    temp_drop(tmp)
                    raise
                try:
                    os.link(tmp, final)
                    created = True
                    temp_drop(tmp)
                except FileExistsError:
                    temp_drop(tmp)
                except OSError:
                    temp_hold(final)
                    try:
                        fd = os.open(final, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
                        with os.fdopen(fd, "wb") as fh:
                            fh.write(body)
                            fh.flush()
                        created = True
                        temp_done(final)
                    except FileExistsError:
                        temp_done(final)
                    except BaseException:
                        temp_drop(final)
                        raise
                    temp_drop(tmp)
            descriptor_info = {"file": name, "path": scrub(str(dest)) + "/" + name, "sha256": sha, "bytes": len(body), "created": created, "already_present": not created}
        except OSError as exc:
            write_error = "the descriptor could not be written: %s" % describe(exc)
    if write_error:
        fail_reasons.append(write_error)

    if fail_reasons:
        status = "failed"
        basis = "; ".join(fail_reasons[:5]) + (" (and %d more)" % (len(fail_reasons) - 5) if len(fail_reasons) > 5 else "")
    elif partial_reasons or missing_deps:
        status = "partial"
        reasons = partial_reasons or ["a dependency is not declared"]
        basis = "; ".join(reasons[:5]) + (" (and %d more)" % (len(reasons) - 5) if len(reasons) > 5 else "")
    else:
        status = "complete"
        basis = ("every declared source was read%s, nothing it names is missing, the media size is known, and mmls and fsstat ran to an answer for every allocated slot"
                 % (" and hashed" if do_hash else ""))
    rows = []
    for entry, d in zip(entries, d_sources):
        rows.append({"index": entry["index"], "path": scrub(entry["path"]), "bytes": entry["bytes"], "sha256": entry["sha256"], "not_hashed": entry["not_hashed"],
                     "signature": entry["signature"], "role": entry["role"], "problems": [scrub(p) for p in entry["problems"]]})
    answer = {
        "ok": status == "complete", "tool": TOOL, "status": status, "status_basis": scrub(basis), "complete": status == "complete",
        "descriptor": descriptor_info,
        "container": descriptor["container"], "sector_size": sector_size, "media": media,
        "partition_table": table["partition_table"], "partition_table_basis": table["basis"],
        "partitions": table["partitions"][:limit], "partitions_total": len(table["partitions"]),
        "volumes_readable": readable_volumes, "volumes_refused": refused_volumes, "volumes_not_attempted": unattempted_volumes,
        "missing_dependencies": [{"kind": d["kind"], "name": scrub(d["name"][:200]), "needed_by": d["needed_by"]} for d in missing_deps[:100]],
        "missing_dependencies_count": len(missing_deps),
        "sources": rows[:limit], "sources_shown": min(limit, len(rows)), "sources_total": len(rows),
        "programs": [{"name": p["name"], "version": p.get("version"), "argv": p["argv"], "exit_code": p["exit_code"], "timed_out": p["timed_out"], "error": scrub(p["error"]) if p["error"] else None,
                      "stdout_file": p.get("stdout_file"), "stderr_file": p.get("stderr_file")} for p in programs[:limit]],
        "programs_total": len(programs),
        "notes": [scrub(n) for n in notes[:50]],
        "not_examined": descriptor["not_examined"],
        "out_dir": scrub(str(dest)),
        "python": sys.version.split()[0],
    }
    if write_error:
        answer["write_error"] = scrub(write_error)
    process_apply(answer)            # program_group: what settle() ended and why absence is unproven (a complete answer is already partial above)
    say(answer, 0)


if __name__ == "__main__":
    exit_code = 0
    try:
        main()
    except SystemExit as stop:
        exit_code = _code(stop)
    _leave(exit_code)
