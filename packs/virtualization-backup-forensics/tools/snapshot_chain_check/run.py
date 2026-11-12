#!/usr/bin/env python3
"""Read the descriptors of a set of virtual-disk files and say how they chain: which file names which as its parent,
whether the parent is there, whether the identity the child recorded is the identity the parent carries, which extents
a descriptor needs and which are missing, and which markers a consolidation or an unclean close may leave behind.

The formats read, from their public descriptions, and no others (a file of any other kind is counted and named, never
guessed at):

    VMware VMDK   a text descriptor (# Disk DescriptorFile: CID, parentCID, parentFileNameHint, createType, extent lines)
                  or the descriptor embedded in a sparse extent (KDMV header, version 1 to 3). A COWD extent is
                  recognised and not read.
    VMware        .vmx (the disk files the configuration names) and .vmsd (the snapshot database), read for the names
                  they hold, to hold the descriptors against.
    VHD           the footer (conectix), the dynamic-disk header (cxsparse) of a dynamic or differencing disk, the
                  parent's unique id, name and locators
    VHDX          the file identifier, the two headers (CRC-32C, sequence number, GUIDs, log GUID), the region table, the
                  metadata table, the file parameters, the virtual disk id and the parent locator. A child's parent_linkage
                  is held against the parent's DataWriteGuid (of its current header), which is what MS-VHDX says it
                  records; the VirtualDiskId is shown as information
    QCOW2         versions 2 and 3: the header, the backing file name, the header extensions, the feature bits, and the
                  internal snapshot table

What it is and is not. It is a reading of headers and descriptors, not of disk content: no sector of a disk is
interpreted, no extent is opened but to measure it, and nothing is mounted, converted, repaired or merged. A chain it
calls complete is a chain whose named parents are present in the set and read, whose recorded identities agree, and
whose extents and data files are in the set; any other chain says which of those failed first. It is not a
disk that boots, and it says nothing about what the parent held when the child was made (QCOW2 records no identity of its
backing file at all). A marker is a candidate with the observation beside it; it is not a verdict. The layouts are
implemented from the format descriptions; they have not been checked against files made by every product or version, and
a version this tool does not know is reported and not read.

qemu-img is run only when asked (qemu_img: auto or require), once per image of the set with the format fixed and never
with --backing-chain, and its answer is kept beside the native reading and never replaces it; a run that fails or times
out makes the answer partial. A VMDK text descriptor and a QCOW2 image with an external data file are not given to it,
because qemu-img opens the files those name, nor is an extent another descriptor names. Nothing in the set is executed, and a name inside a file is looked up among
the files given, never opened by this tool: a parent named outside the set is reported as missing.

SENSITIVE OUTPUT. Names, hints, snapshot names and descriptions are shown after the shape check of the shared block:
a token-shaped run or user-info is withheld, a long text is shown cut with its whole length, and the original goes to
one private file only when write_text is asked for, in a job. Every key and value of the answer and of its paging files
passes the one way out (SHARED BOUNDARY), which withholds by shape again and checks what it wrote. A VM configuration can hold a password or a token under a
key this tool does not read: only the names of the disk files and the snapshot database's names are taken from it.
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


import collections
import datetime
import errno
import itertools
import json
import math
import os
import posixpath
import re
import secrets
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import time
import unicodedata
import uuid
from pathlib import Path

TOOL = "snapshot_chain_check"
PARSER = "snapshot_chain_check/2"
DEFAULT_LIMIT = 200
DEFAULT_SECONDS = 50.0          # the manifest allows 60
MAX_SECONDS = 50.0
MAX_DESCRIPTOR = 1 << 20        # a descriptor, embedded or alone, is read to this many bytes
MAX_DESC_LINES = 20000
MAX_EXTENTS = 10000             # extent lines kept per descriptor; the rest are counted
MAX_CONFIG_BYTES = 16 << 20     # a .vmx or .vmsd over this is named and not read
MAX_CONFIG_LINE = 1 << 16
MAX_CONFIG_LINES = 500000
MAX_SNAPSHOT_ENTRIES = 20000    # distinct snapshotN indexes kept from one .vmsd; the rest are counted
DEFAULT_MAX_SNAPSHOTS = 100000  # internal QCOW2 snapshots read from one image
MAX_CHAIN_SHOWN = 50
MAX_CONFIG_ENTRIES_TOTAL = 100000  # snapshot entries (and disk entries) kept across every .vmsd (and .vmx) of one run
CREATE_TYPES = {"monolithicSparse", "monolithicFlat", "twoGbMaxExtentSparse", "twoGbMaxExtentFlat", "fullDevice", "partitionedDevice", "vmfs", "vmfsSparse",
                "vmfsEagerZeroedThick", "vmfsThin", "vmfsRaw", "vmfsRawDeviceMap", "vmfsPassthroughRawDeviceMap", "streamOptimized", "seSparse", "custom"}
KNOWN_DDB = ("ddb.adapterType", "ddb.virtualHWVersion", "ddb.toolsVersion", "ddb.thinProvisioned", "ddb.longContentID", "ddb.uuid")
VOCABULARY = CREATE_TYPES   # words the way out shows as they are (see SHARED BOUNDARY)
WITHHELD_CONFIG_NOTE = "other keys of a .vmx are not read: they can hold a password or a token"

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
# BEGIN SHARED COMMON
# The same text is in virtualization_inventory, snapshot_chain_check and backup_audit_normalise (a tool is standalone, none
# imports another); tests/pack-virtualization-shared.test.ts holds the copies equal. Arguments, the status every answer
# carries, lossless paging, and the one place a withheld text is kept when, and only when, it was asked for.


def in_job():
    return bool(os.environ.get("JOB_ID") and os.environ.get("OUT"))


def describe(exc):
    """An exception as text for an answer: its type and errno name, and its message withheld by shape (the way out's whole
    rules, so that nothing they would take is split first), never cut."""
    code = errno.errorcode.get(exc.errno, "") if getattr(exc, "errno", None) else ""
    return seal_head("%s%s: %s" % (type(exc).__name__, " " + code if code else "", getattr(exc, "strerror", None) or str(exc)), "text")


PAGING_OPEN = []        # the paging files being written (LosslessPage objects with a temporary file open)


def paging_left():
    """Close the paging files a stop leaves open and keep what they hold under a name that says so (`<name>.partial`): their
    rows were sealed as they were written. The names, as the answer shows them."""
    left = []
    for page in list(PAGING_OPEN):
        try:
            shown = page.abandon()
        except Exception:  # noqa: BLE001 - one file that cannot be closed must not hide the others
            shown = None
        if shown:
            left.append(shown)
    return left


def fail(message, **extra):
    """An error answer: JSON, exit 1, the same `status` every answer of this pack carries, through the one way out."""
    hold_stop_signals()
    if hasattr(signal, "pthread_sigmask"):
        signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT, signal.SIGHUP})     # one document: the stop handlers may not be in yet (a refusal can come before main() installs them), and one that is in would write a second, false, document after this one; a stop that arrives while this is written waits, and the tool leaves with it
    left = paging_left()
    if left:
        extra["paging_files_left"] = left
        extra["paging_files_note"] = "the rows written before the stop, sealed as they were written, kept under the name that says so"
    print(answer_text({"error": message, "tool": TOOL, "status": "failed", "status_basis": "the tool stopped with an error (see error)", **extra}))
    raise SystemExit(1)


def stop_word(signum):
    """The tool's last word when SIGTERM, SIGINT or SIGHUP ends it: one JSON answer through the one way out, naming the signal
    and any paging file it leaves. If the answer cannot be made (the signal came in the middle of the way out itself), a short
    one that says so."""
    name = {signal.SIGTERM: "SIGTERM", signal.SIGINT: "SIGINT", signal.SIGHUP: "SIGHUP"}.get(signum, "signal %d" % signum)
    left = []
    try:
        left = paging_left()
        print(answer_text({"tool": TOOL, "parser": PARSER, "status": "partial",
                           "status_basis": "the tool was stopped by %s before it finished: nothing after the stop was read or written" % name,
                           "stopped_by_signal": name, "paging_files_left": left,
                           "paging_files_note": "the rows written before the stop, sealed as they were written, kept under the name that says so" if left else "no paging file was open"}))
    except BaseException as exc:  # noqa: BLE001 - the last word is best effort, and never silent
        print(json.dumps({"tool": TOOL, "parser": PARSER, "status": "partial", "stopped_by_signal": name, "paging_files_left": left,
                          "status_basis": "the tool was stopped by %s; the full last word could not be made (%s)" % (name, type(exc).__name__)}))
    sys.stdout.flush()                      # the caller leaves with os._exit, which flushes nothing


def install_stop_handlers():
    """SIGTERM, SIGINT and SIGHUP: the last word, then exit 128 plus the signal number (snapshot_chain_check, which runs a program,
    gives its last word to the process block's handler instead)."""
    def on_signal(signum, _frame):
        try:
            stop_word(signum)
        except BaseException:  # noqa: BLE001 - a last word is best effort
            pass
        if "answer_a_stop" in globals():     # (a block run on its own, by a test, has no ENDS block)
            answer_a_stop(signum)
        os._exit(128 + signum)
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, on_signal)


def read_args():
    try:
        raw = sys.stdin.buffer.read(8 << 20 | 1)
        if len(raw) > 8 << 20:
            fail("arguments are larger than 8 MiB: pass a list of files, not their contents")
        args = json.loads(raw.decode("utf-8") or "{}")
    except (ValueError, UnicodeDecodeError) as exc:
        fail("arguments are not valid JSON", reason=describe(exc))
    if not isinstance(args, dict):
        fail("arguments must be a JSON object")
    return args


MAX_ARG_STRING = 8192


def want_str(args, key, required=None, maximum=MAX_ARG_STRING):
    value = args.get(key)
    if value is None:
        if required:
            fail(required)
        return None
    if not isinstance(value, str):
        fail("%s must be a string" % key)
    if required and not value:
        fail(required)
    if len(value) > maximum:
        fail("%s is longer than %d characters" % (key, maximum))
    return value


def want_str_list(args, key, maximum=100000):
    value = args.get(key)
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(x, str) and x and len(x) <= MAX_ARG_STRING for x in value):
        fail("%s must be a list of non-empty strings of at most %d characters" % (key, MAX_ARG_STRING))
    if len(value) > maximum:
        fail("%s holds more than %d entries: pass a directory as root instead" % (key, maximum))
    return value


def want_flag(args, key):
    value = args.get(key, False)
    if not isinstance(value, bool):
        fail("%s must be true or false" % key)
    return value


def want_int(args, key, default, minimum, maximum):
    value = args.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum or value > maximum:
        fail("%s must be an integer from %d to %d" % (key, minimum, maximum))
    return value


def want_seconds(args, key, default, maximum):
    """A time budget: a finite number above zero and no more than `maximum` (NaN and Infinity are not budgets)."""
    value = args.get(key, default)
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0 or value > maximum:
        fail("%s must be a number of seconds above 0 and at most %d" % (key, maximum))
    return float(value)


def status_of(complete, failed, basis_complete, basis_partial, basis_failed):
    """The `status` every answer of this pack carries, with the reason for it: complete (everything the request asked
    for was read and nothing was left out), partial (some of it was, and the answer names what was not) or failed."""
    if failed:
        return {"status": "failed", "status_basis": basis_failed}
    if complete:
        return {"status": "complete", "status_basis": basis_complete}
    return {"status": "partial", "status_basis": basis_partial}


class Overtime(Exception):
    pass


class Clock:
    def __init__(self, seconds):
        self.deadline = time.monotonic() + seconds
        self.count = 0

    def check(self, every=1):
        self.count += 1
        if self.count % every == 0 and time.monotonic() > self.deadline:
            raise Overtime()

    def left(self):
        return max(0.0, self.deadline - time.monotonic())


def blen(text):
    return len(text.encode("utf-8", "surrogatepass"))


def decode(data):
    """Bytes as text with no byte lost: an undecodable byte is a lone surrogate, which a JSON escape writes and which
    encodes back to the byte."""
    return data.decode("utf-8", "surrogateescape")


# Lossless paging: the page an agent reads stays small, and when there are more rows the whole result is written as JSON
# Lines under work/<agent>/tool-output (in a job, $OUT/tool-output) and named. The file name is random: it is never a
# digest of anything asked for (sixteen decimal digits), and the way out shows this exact name, registered here, as it is. Every row is sealed
# (the one way out, below) as it is written. A write that fails is an error answer naming the file, never a loss that
# goes unsaid.
# The rows an answer shows inline are cut by size as well as by count: the answer is judged, serialised and read back within
# the run's clock, and a `limit` of 100000 over rows of a few hundred bytes would make that take longer than max_seconds
# (and leave the answer without its keys). The cut is lossless: every row is in the paging file, named by all_results.
INLINE_BYTES = 1 << 19


class LosslessPage:
    def __init__(self, tool, key, limit):
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ValueError("limit must be a positive integer")
        self.tool = re.sub(r"[^A-Za-z0-9_.-]", "_", tool)
        self.key = re.sub(r"[^A-Za-z0-9_.-]", "_", key)
        self.limit = limit
        self.page = []
        self.page_bytes = 0
        self.total = 0
        self._out = None
        self._tmp = None
        name = "%s-%s-%016d.jsonl" % (self.tool, self.key, secrets.randbelow(10 ** 16))
        job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
        if job and out:
            self.path = Path(out) / "tool-output" / name
            self.shown = "store/jobs/%s/out/tool-output/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", job), name)
        else:
            agent = re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool")
            self.path = Path("work") / agent / "tool-output" / name
            self.shown = str(self.path)
        OWN_NAMES.update((self.shown, str(self.path)))     # this exact name, and no other of its shape, is shown as it is

    def _write(self, row):
        line = row_text(row, "pages/%s/all_results" % self.key)
        try:
            self._out.write(line)
            self._out.write("\n")
        except OSError as exc:
            fail("the whole result could not be written: %s" % describe(exc), paging_file=str(self.path))

    def add(self, row):
        self.total += 1
        if len(self.page) < self.limit and self.page_bytes < INLINE_BYTES:
            self.page.append(row)
            self.page_bytes += len(repr(row))
            return
        if self._out is None:
            stops = {signal.SIGTERM, signal.SIGINT, signal.SIGHUP}
            was = signal.pthread_sigmask(signal.SIG_BLOCK, stops)       # a stop must not come between the file and its registration
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                fd, name = tempfile.mkstemp(dir=self.path.parent, prefix=".%s-" % self.path.name)
                self._tmp = Path(name)
                self._out = os.fdopen(fd, "w", encoding="ascii", errors="backslashreplace")
                PAGING_OPEN.append(self)
            except OSError as exc:
                signal.pthread_sigmask(signal.SIG_SETMASK, was)
                fail("the whole result could not be written: the paging file cannot be created (%s)" % describe(exc), paging_file=str(self.path))
            signal.pthread_sigmask(signal.SIG_SETMASK, was)
            for kept in self.page:
                self._write(kept)
        self._write(row)

    def abandon(self):
        """A stop with the file open: the rows written so far are kept as `<name>.partial`; the name as the answer shows it."""
        if self._out is None or self._tmp is None:
            return None
        keep = self.path.with_name(self.path.name + ".partial")
        try:
            os.replace(self._tmp, keep)         # the name first: it is atomic and touches no file object
        except OSError:
            return None
        try:
            self._out.flush()
            self._out.close()
        except (OSError, RuntimeError, ValueError):
            pass                                # a write was in progress when the signal came in: what the system already holds is kept
        self._out = None
        if self in PAGING_OPEN:
            PAGING_OPEN.remove(self)
        OWN_NAMES.update((self.shown + ".partial", str(keep)))
        return self.shown + ".partial"

    def finish(self):
        result = {"matched": self.total, "returned": len(self.page), "truncated": self.total > len(self.page)}
        if self.total > len(self.page) and len(self.page) < self.limit:
            result["inline_cut_by_size"] = "the rows shown inline stop at about %d bytes whatever limit says; the whole list is in all_results" % INLINE_BYTES
        if self._out is not None:
            try:
                self._out.flush()
                os.fsync(self._out.fileno())
                self._out.close()
                os.replace(self._tmp, self.path)
                if self in PAGING_OPEN:
                    PAGING_OPEN.remove(self)
            except OSError as exc:
                fail("the whole result could not be written: %s" % describe(exc), paging_file=str(self.path))
            result["all_results"] = self.shown
            result["all_results_format"] = "JSON Lines, one complete row per line"
        return result


class TextRefused(Exception):
    pass


class TextFile:
    """Where the original of a withheld or shortened text goes when, and only when, the caller asked for it.

    The secret-safe output pattern of recovery_key_scan's SecretValues, for rows. With `enabled` false it writes
    nothing and `summary()` says so. Enabled, it is refused outside a job; inside one the file is created before
    anything is read (mode 0600, exclusively: a file or a link already at that name is refused by name) under $OUT, and
    the answer names it and says it may hold secrets. A job that was not run as secret output (the harness gives its process
    SECRET_OUTPUT=1 when it was) is refused too: the file would be sealed as an ordinary output. With nothing to keep it stays an empty file and says written: 0.
    """

    def __init__(self, name, enabled, what, flag="write_text"):
        self.enabled = enabled
        self.written = 0
        self.what = what
        self.flag = flag
        self._fh = None
        self.path = None
        self.shown = None
        if not enabled:
            return
        job, out = os.environ.get("JOB_ID") or "", os.environ.get("OUT") or ""
        if not (job and out):
            raise TextRefused("%s is refused outside a job: the originals written here would be an ordinary file, not a "
                              "sealed output. Run this as job_run tool=%s with secret_output: true, and ask again there. "
                              "Nothing was written." % (flag, TOOL))
        if os.environ.get("SECRET_OUTPUT") != "1":
            raise TextRefused("%s is refused in a job that was not run as secret output: the originals would be sealed as ordinary "
                              "output. The harness sets SECRET_OUTPUT=1 for a secret job's process and it is not set here. Run this as "
                              "job_run tool=%s with secret_output: true, and ask again there. Nothing was written." % (flag, TOOL))
        self.path = Path(out) / name
        self.shown = "store/jobs/%s/out/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", job), name)
        OWN_NAMES.update((self.shown, str(self.path)))
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(str(self.path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileExistsError:
            raise TextRefused("the values file already exists: %s" % name)
        except OSError as exc:
            raise TextRefused("the values file could not be created (%s)" % describe(exc))
        self._fh = os.fdopen(fd, "wb")

    def add(self, row):
        if self._fh is None:
            return
        try:
            self._fh.write(json.dumps(row, default=str).encode("ascii") + b"\n")
        except OSError as exc:
            fail("the values file could not be written (%s)" % describe(exc))
        self.written += 1

    def close(self):
        if self._fh is not None:
            try:
                self._fh.flush()
                os.fsync(self._fh.fileno())
                self._fh.close()
            except OSError as exc:
                fail("the values file could not be closed (%s)" % describe(exc))
            self._fh = None

    def summary(self):
        if not self.enabled:
            return {"requested": False, "written": 0, "file": None, "contains_text_that_may_hold_secrets": False,
                    "hint": "Nothing withheld or shortened is kept. %s: true, in a job run with secret_output: true, keeps the "
                            "original of each in a private file under $OUT." % self.flag}
        return {"requested": True, "written": self.written, "file": self.shown,
                "contains_text_that_may_hold_secrets": self.written > 0, "format": self.what}


class Shown(str):
    """A string that has been through the shape check: it is not checked again."""
    judged = True


# An open-ended authority or name:secret run at the point where a long text was cut might have its user-info separator beyond
# the cut, and a run of name characters the cut ends might be the head of a token: each is withheld whole.
_OPEN_AUTHORITY = re.compile(r"(?<=//)[^/?#\s]*$")
_OPEN_BARE = re.compile(r"[^\s/@:<>]{1,64}:[^\s/@<>]*$")
_RUN_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_+%/=.:@-")


def cut_safely(text, limit):
    """`text` cut to at most `limit` characters (plus a marker), never leaving the head of a run the cut split: a text
    is withheld by shape BEFORE it is cut, and what the cut leaves open is withheld whole, not shown in part."""
    if len(text) <= limit:
        return text
    head = text[:limit]
    if limit > 0 and text[limit] in _RUN_CHARS and head[-1] in _RUN_CHARS:      # the cut fell inside a run: the run's head is withheld whole
        start = limit
        while start > 0 and head[start - 1] in _RUN_CHARS:
            start -= 1
        head = head[:start] + _withheld("open run at a cut", limit - start, "cut")
    head = _OPEN_AUTHORITY.sub(lambda m: _withheld("userinfo", len(m.group()), "text"), head)
    return _OPEN_BARE.sub(lambda m: _withheld("userinfo", len(m.group()), "text"), head)


def brief(text, limit=300):
    """A message from a library or a program, withheld by shape whole and then cut safely: never cut first."""
    return cut_safely(seal_head(text if isinstance(text, str) else str(text), "text"), limit)


class Shower:
    """Every string the answer shows a name, a path or a value of passes through here: token-shaped runs and user-info are
    withheld, a text over `limit` characters is shown cut with its whole length, and the original of what was changed goes
    to the values file when one was asked for (never anywhere else). Only the first EXAMINED characters of a long text are
    checked (the check is not linear in the length of an adversary's text): a run of name characters, an authority or a
    name:secret run that the EXAMINED cut leaves open is withheld whole before the shape check, so that no fragment of a
    token the cut split can be shown; the check runs on the whole examined text, and the shorter cut to `limit` comes
    after it and leaves no run open either."""

    EXAMINED = 4096

    def __init__(self, values, limit=512):
        self.values = values
        self.limit = limit
        self.changed = 0
        self.cut = 0

    def __call__(self, text, where=None, field=None):
        if text is None:
            return None
        if not isinstance(text, str):
            text = str(text)
        total = len(text)
        head = text
        if total > self.EXAMINED:
            head = cut_safely(text, self.EXAMINED)
        RUN["record"] = False                      # this call records the original itself
        try:
            shown = seal_text(head, "text", field, where)
        finally:
            RUN["record"] = True
        was_cut = total > self.EXAMINED
        if len(shown) > self.limit:
            shown = cut_safely(shown, self.limit)
            was_cut = True
        if was_cut:
            shown += "...(whole text: %d characters)" % total
            self.cut += 1
        if shown != text:
            self.changed += 1
            if self.values.enabled:
                self.values.add({"record_type": "original", "where": where, "field": field, "value": text})
        return Shown(shown)


def withheld_summary(shower):
    return {"strings_withheld_by_shape": dict(COUNTS), "strings_changed": shower.changed, "strings_shortened": shower.cut,
            "note": ("Names, paths and values the answer shows are checked by shape: a token-shaped run, user-info in a URL and a key "
                     "are withheld, and a string over %d characters is shown cut with its whole length. A secret that does not look "
                     "like a token (a short password in a name) is not recognised, so run the tool as a job with secret_output: true.") % shower.limit}
# END SHARED COMMON
# BEGIN SHARED BOUNDARY
# BOUNDARY v2, the one text: the same text is in every tool that prints names, paths, event data, registry data, identifiers or table
# cells from evidence (tests/pack-boundary-shared.test.ts finds every copy under packs/ and tool-library/ and holds them equal: one variant, 16 carriers).
# It is the owner-approved HYBRID design: an allow-list for
# identifier-shaped fields, a deny-list for free text, and an independent backstop on the way out.
#
# Names defined here start with _b_ or _B_ where another shared block of a tool could define the same name (the WITHHOLDING block has _withheld and _USERINFO).
# THE CALLS A TOOL MAKES, and what the virtualization block called each (the three virtualization tools moved onto this text; the table is what they map to):
#   FIELDS, KEY_KINDS, bind_fields(table, key_kinds)           the table of field kinds, which the CALLER passes in (this text holds no tool's table);
#                                                              it was _FIELDS, _INHERIT and field_kind(); a digit run in a field name stands for any number
#                                                              (`ethernet#.address`), and a field the table does not list has the kind of the field above it
#   T(kind, text), show(s, kind, field)                        one string judged by its kind                         (the Shower, boundary_text, seal_text, seal_head)
#   sealed_text(text, kind, field), print_order(items, ...)    what an answer prints for a string; nothing counted    (seal_text without the count)
#   bind_values(enabled, tool), close_values(), values_summary()  the values file of a secret_output job            (bind_run(values, seconds))
#   seal_stop_after(seconds)                                   the clock: nothing is judged after it                  (bind_run's seconds, RUN["deadline"])
#   row_object(row)                                            one row of a paging file                               (row_text(row, where))
#   answer_object(doc), emit(doc)                              an answer, sealed and read back                        (answer_text(doc), backstop(value, where))
#   boundary_summary()                                         the "boundary" object; stopped_by is in it when judging stopped
#   OWN_NAMES                                                  the exact strings the run made and shows as they are   (OWN_NAMES)
# The kinds of a field: text (the default), name, path, key, url, host, hex, id (one of several forms of identifier: a GUID, a VMFS volume id, a device id, a VMware uuid, a MAC, a content id of 32 hexadecimal digits or a number; else a name), and the typed ones guid, digest, sid, mac, ip, time, number, version
# and, for virtualized storage and machines, vmfs (a VMFS volume id), device (naa., eui., wwn-0x, vml. and t10. ids), iqn, vmuuid (the VMware
# uuid of a machine), cid (a disk's content id), winhost (the name Windows gives a machine nobody named).
#
# LAYER 1, an allow-list per field type. A string the evidence supplied is shown as it is only when it fits the plain grammar of the
# type of the field it fills: a name (registry key and value names, event field names, provider and channel names, table and column
# names), a path (file names and paths, a registry path, a URL path), a key, a URL, or a typed id (GUID, SID, MAC, IP address, digest,
# time, number, version). The grammar is: letters of any script, digits, space and `_ - . $ @ ? : ~ + , # ( ) [ ] { } ' < > *`, at
# most 128 characters a component, no user-info shape (a `:` before an `@`), and no chain of 16 or more characters made of
# random-looking pieces (pieces that break into one- and two-character parts, flip between letters and digits, or are letters with
# no pronounceable word in them; a 16-hex id, a GUID or a number up to 18 digits is plain). Below 16 characters a chain is shown
# whatever it looks like: a short random password in a name is not recognised. A path is judged component by component and only the
# offending span is replaced; a string with a format, control or combining character is withheld whole.
#
# LAYER 2, for every kind, and it reads the string FIRST, as the evidence wrote it (the deny-list and the grammar cut spans out of a string
# and take with them the context these rules need: the user of `user:password@host`, the characters glued before `glpat-`): user-info up
# to the last `@` before the host (the password may hold a `/`, not a port); the value after a secret's name (password, secret, token,
# api/access/account/private key, credential, auth) found anywhere, up to a space or quote, and past a `& ; ,` that no `name=` follows;
# a PEM private key; a vendor token with its own prefix (AKIA, gh?_, github_pat_, xox?-, glpat-, sk_live_, SG., AIza, npm_, dop_v1_,
# ya29., sk-, JWT) in any case; a base64 key with its padding; and the same rules on a copy with invisible characters taken out and NFKC
# applied (a hit withholds the whole string). FREE TEXT (event data, messages, command lines, registry data strings, table cells) is on
# the deny-list: the same chain test applied to the text with its typed ids (GUID, SID, IP address, time, labelled digest, number) left
# alone, plus layer 2, and no character grammar.
#
# LAYER 3, the backstop, written apart from the layers above: every key and value of what is about to be written is read once more
# by its own normaliser and patterns (a PEM marker, a named secret, a run of 19 or more digits, a token prefix in any case, user-info, a
# run of 40 or more hex digits outside a typed field, a base64 run, a run that changes class as random text does; a typed field must hold
# the characters of its type; data written as hexadecimal is decoded and its printable text is read as text). It reads the shown string
# AND the original: a window of 12 characters of anything it calls secret in the original that is still in the shown string means the
# layers above left a piece of a secret between two cuts. A string it finds suspect is replaced by <withheld N bytes: backstop: why>,
# counted, its place named in boundary.replaced_at (built from the keys on the way as they are SHOWN, or their positions), and the
# answer is partial. A placeholder is only a placeholder when its reason is one of the fixed list. The names of the components of the Windows
# component store (WinSxS: lower case, a public key token, a language or `none`, a hash) are not judged by the backstop in a name or key slot:
# a real SOFTWARE hive lists them by the thousand and their hash looked random to it; layer 1 judges them as it does every name.
#
# ONE WAY OUT: emit() writes an answer, row_object() makes a row of a paging file, and both seal every key and value first (a value that is not
# a string, a number or a container is sealed as the text str() makes of it). Binary data written as hex (a REG_BINARY value, an ESE
# binary column) is decoded and its printable views (Latin-1, UTF-16LE and UTF-16BE, and runs holding full-width characters read as UTF-8 and UTF-16LE with
# the width folded) are judged by the free-text rules, by both layers and the
# backstop; hex that holds a secret-shaped text is withheld, and any other hex is shown (random bytes with no text in them are printed).
# What is withheld is a placeholder with its length and the reason; its original goes to the values file only when write_values was
# asked for in a job run as secret output. A list of names is printed in the order of the text shown for each, the placeholders of
# withheld names in a random order that is new every run (print_order); a `contains` filter is applied to the text the answer PRINTS (the
# string after the layers and the backstop, sealed_text), never to what is withheld or replaced, and contains_check says when the needle
# could have been in what is hidden. Every string is judged in linear time (a string is read to 256 KiB, the pieces the backstop compares
# are at most 64, a PEM body at most 20,000 characters), and an answer or a row that takes longer than SEAL_BUDGET seconds to seal, or that is
# still being sealed at the seal stop of the tool (seal_stop_after: a point in time after which nothing is judged, not a stop of the tool's own
# work, which has its own clock), has the rest of its strings replaced whole (<withheld N bytes: backstop: the judging time ran out>) and is
# partial; what stays readable past that point is the names the tool made itself (OWN_NAMES) and strings of 15 characters or fewer of letters,
# digits, `_` and `.` that do not start like a vendor token (and, in a field of a typed kind, fit the grammar of its type). The seal stop is 3.5 seconds before the
# tool's time limit: the string in progress finishes after it, and one string of 256 KiB takes up to 2.3 seconds to judge on a loaded machine (the worst measured).
# A run has a second bound: past MAX_JUDGED_CHARS characters judged (the final answer is always judged), a string not judged before is withheld by its size in the
# same way. boundary.stopped_by says which bound stopped the judging and boundary.strings_withheld_by_the_stop how many strings it withheld; the answer is partial.
# NOT RECOGNISED, by design: a secret that does not look like one (a plain password, a pronounceable passphrase, a UUID-shaped key,
# anything under 16 characters in a name, a secret hidden in words or in an encoding this block does not read).
import collections
import hashlib
import signal
import time
import unicodedata

LMIN = 16
MAX_ONE_STRING = 1 << 18
MAX_HEX_JUDGED = 1 << 20
MAX_PIECES = 64                 # the pieces of a string the backstop compares with what was shown (it stops collecting at this many)
MAX_PEM_BODY = 20000            # a PEM body is read to this many characters (a 16,384-bit RSA key is about 13,000)
SEAL_BUDGET = 10.0              # seconds one answer, or one row of a paging file, may take to be sealed; a tool may set another
_CLOCK = {"deadline": None, "stop": None}
_BIGRAMS_TEXT = "aaabacadaeafagahaiajakalamanaoapaqarasatauavawaxayazbabbbcbdbebfbhbibjblbmbnbobpbrbsbtbubvbycacbcccdcecfchcickclcncocqcrcsctcucydadbdcdddedfdgdhdidjdldmdndodpdrdsdtdudvdwdyeaebecedeeefegeheiejekelemeneoepeqereseteuevewexeyezfafbfcfdfefffiflfofrftfufygagbgdgegfggghgiglgmgngogrgsgtgugwgyhahbhchdhehfhhhihlhmhnhohphrhshthuhwhyiaibicidieifigihiiijikiliminioipiqirisitiuiviwixizjajejijojukakbkekfkhkikkklkmknkokpkrksktkukwkylalblcldlelflglhlilklllmlnlolplrlsltlulvlwlymambmemfmimlmmmnmompmrmsmumwmynanbncndnenfngnhninjnknlnmnnnonpnqnrnsntnunvnwnxnynzoaobocodoeofogohoiojokolomonooopoqorosotouovowoxoyozpapbpcpepfphpiplpmpnpoppprpsptpupwpyqurarbrcrdrerfrgrhrirjrkrlrmrnrorprqrrrsrtrurvrwryrzsasbscsdsesfsgshsiskslsmsnsospsqsrssstsusvswsytatbtctdtetftgthtitltmtntotptrtstttutvtwtytzuaubucudueufuguhuiukulumunuoupurusutuvuxuyuzvavevivovuvywawbwdwewfwhwiwkwlwmwnwowrwswtwuwyxaxcxexhxixoxpxtxuxxxyyaybycydyeyfygyhyiylymynyoypyrysytyuywyxyyyzzazezizlzozuzyzz"           # the 474 letter pairs that words and identifiers use (the system word list and Python identifiers)
_BIGRAMS = frozenset(_BIGRAMS_TEXT[i:i + 2] for i in range(0, len(_BIGRAMS_TEXT), 2))
BOUNDARY = {"withheld": 0, "by": collections.Counter(), "replaced": 0, "replaced_by": collections.Counter(), "where": [], "not_listed": 0}
OWN_NAMES = set()               # exact strings this run made and shows as they are (file names of its own results)
FIELDS = {}                     # a JSON key -> the kind of what it holds (a tool fills this in, or passes it to bind_fields); a key it does not list has the kind of the key above it (text at the top)
KEY_KINDS = {}                  # a JSON key holding a dict -> the kind of that dict's own keys (registry value names are paths); default: name
MAX_WHERE = 200
MAX_JUDGED_CHARS = 400000000    # characters one run may have judged (every string of its answers and paging files); past it a string not judged before is withheld by its size
FINAL_GRACE_CHARS = 4000000     # the final answer may always be judged: the cap is raised by this much, and is not spent again by the strings already withheld
_STOP = {"cap": MAX_JUDGED_CHARS, "chars": 0, "by": None, "strings": 0}   # why judging stopped (None: it did not), and how many strings it withheld by their size


class T(str):
    """A string with its field type, made by the tool where it knows the type (a registry type, an event field, a column)."""
    kind = "text"

    def __new__(cls, kind, text):
        self = super().__new__(cls, text)
        self.kind = kind
        return self


def _mark(n, label, unit="characters"):
    return "<withheld %d %s: %s>" % (n, unit, label)


# the reasons a placeholder can give: a fixed list, so that text which only looks like a placeholder is not taken for one (and not skipped by the rules)
_CHECKS = ("a PEM marker", "a named secret", "a token prefix", "user-info", "not the typed grammar", "a long digit run", "a long hexadecimal run",
           "a base64 run with / and +", "a padded base64 run", "a random-looking run", "a part of a secret-shaped text", "the judging time ran out")
_LABELS = ("not a plain name", "token-shaped text", "user-info", "secret value", "private key", "long number", "rest of a long string",
           "binary data over the judged size", "binary data holding a secret-shaped text", "invisible characters in a name", "not a port", "query value", "fragment",
           "not a guid", "not a digest", "not a sid", "not a mac", "not a ip", "not a time", "not a number", "not a version",
           "not a vmfs", "not a device", "not a iqn", "not a vmuuid", "not a cid", "not a winhost") + \
          tuple("backstop: " + c for c in _CHECKS) + tuple("backstop: in binary data: " + c for c in _CHECKS)
_MARK = re.compile(r"<withheld [0-9]{1,10} (?:characters|bytes)(?:: (?:%s))?>|\[withheld: [0-9]{1,10} (?:characters|bytes)\]"
                   % "|".join(re.escape(x) for x in sorted(_LABELS, key=len, reverse=True)))
_VALUES = {"fh": None, "shown": None, "written": 0, "seen": set(), "count": 0}   # "seen": 16-byte digests of the originals written (at most 200,000)


class ValuesRefused(Exception):
    pass


def bind_values(enabled, tool):
    """The values file: the originals of what the boundary withheld, in a job run as secret output and only when asked for. Decided before
    anything is opened or created (the harness sets SECRET_OUTPUT=1 for a secret job's process)."""
    if not enabled:
        return None
    job, out = os.environ.get("JOB_ID") or "", os.environ.get("OUT") or ""
    if not (job and out) or os.environ.get("SECRET_OUTPUT") != "1":
        raise ValuesRefused("write_values is refused: the originals of what was withheld are written only in a job the harness runs as secret output "
                            "(job_run with secret_output: true), where the file is a sealed secret output. Nothing was written.")
    name = "%s-values.jsonl" % re.sub(r"[^A-Za-z0-9_.-]", "_", tool)
    path = Path(out) / name
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    except FileExistsError:
        raise ValuesRefused("the values file already exists: %s" % path)
    except OSError as exc:
        raise ValuesRefused("the values file could not be created: %s: %s" % (path, exc.strerror or exc))
    _VALUES["fh"] = os.fdopen(fd, "w", encoding="utf-8")
    _VALUES["shown"] = "store/jobs/%s/out/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", job), name)
    return _VALUES["shown"]


def close_values():
    fh = _VALUES["fh"]
    if fh is not None:
        fh.flush()
        os.fsync(fh.fileno())
        fh.close()
        _VALUES["fh"] = None


def values_summary():
    return {"requested": _VALUES["shown"] is not None, "values_file": _VALUES["shown"], "written": _VALUES["written"], "contains_secret_values": _VALUES["written"] > 0,
            "format": "JSON Lines, mode 0600: id, field, label, length, value (the original text that was withheld)" if _VALUES["shown"] else None}


_EVENTS = [None]               # while a string is judged only to see what the answer would print (sealed_text): its withholdings, counted when the answer prints it
_QUIET = [False]


def _b_withheld(original, label, field=""):
    n = len(original)
    if _EVENTS[0] is not None:
        _EVENTS[0].append((original, label, field))
        return _mark(n, label)
    BOUNDARY["withheld"] += 1
    BOUNDARY["by"][label] += 1
    fh = _VALUES["fh"]
    digest = hashlib.blake2b(original.encode("utf-8", "surrogatepass"), digest_size=16).digest() if fh is not None else None
    if fh is not None and digest not in _VALUES["seen"]:
        if len(_VALUES["seen"]) < 200000:
            _VALUES["seen"].add(digest)
        _VALUES["count"] += 1
        text = json.dumps({"id": _VALUES["count"], "field": field, "label": label, "length": n, "value": original}, ensure_ascii=False)
        try:
            text.encode("utf-8")
        except UnicodeEncodeError:
            text = json.dumps({"id": _VALUES["count"], "field": field, "label": label, "length": n, "value": original}, ensure_ascii=True)
        fh.write(text + "\n")
        _VALUES["written"] += 1
    return _mark(n, label)


# ---- normalisation ----------------------------------------------------------------------------------------------------------------
_STRIP_CATS = frozenset(("Cf", "Cc", "Mn", "Me", "Cs", "Co", "Cn", "Zl", "Zp"))
_FILLERS = frozenset((0x115F, 0x1160, 0x3164, 0xFFA0, 0x2800))


class _Strip(dict):
    def __missing__(self, o):
        if len(self) > 20000:
            self.clear()
        keep = unicodedata.category(chr(o)) not in _STRIP_CATS and o not in _FILLERS
        self[o] = o if keep else None
        return self[o]


_STRIP = _Strip()
_ESCAPED = re.compile(r"(?<!\\)\\+(?:u([0-9A-Fa-f]{4})|U([0-9A-Fa-f]{8})|x([0-9A-Fa-f]{2})|u\{([0-9A-Fa-f]{1,6})\})")


def _unescape_invisible(m):
    try:
        c = chr(int(m.group(1) or m.group(2) or m.group(3) or m.group(4), 16))
    except (ValueError, OverflowError):
        return m.group(0)
    return "" if (unicodedata.category(c) in _STRIP_CATS or ord(c) in _FILLERS) else m.group(0)


def _flat(text):
    """The text with invisible characters (and the escapes of such characters) taken out, and past ASCII in NFKC form."""
    if "\\u" in text or "\\U" in text or "\\x" in text:          # (the escape pattern needs a backslash and one of these)
        text = _ESCAPED.sub(_unescape_invisible, text)
    if text.isascii():
        return text if text.isprintable() else text.translate(_STRIP)
    out = text.translate(_STRIP)
    return unicodedata.normalize("NFKC", out) if not out.isascii() else out


# ---- layer 1: the allow-list ------------------------------------------------------------------------------------------------------
_PIECE = re.compile(r"[A-Z]{2,}s(?![a-z])|[A-Z]+(?![a-z])|[A-Z]?[a-z]+|[0-9]+")        # (GPOs, an acronym in the plural, is one piece)
_GUID = re.compile(r"\{?[0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}\}?|[0-9a-f]{8}-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{12}")
_SID = re.compile(r"S-1-[0-9]{1,2}(?:-[0-9]{1,10}){1,15}")
_IPV4 = re.compile(r"(?<![0-9A-Za-z.])[0-9]{1,3}(?:\.[0-9]{1,3}){3}(?![0-9A-Za-z])")
_HEX_NUMBER = re.compile(r"(?<![0-9A-Za-z])0[xX][0-9A-Fa-f]{1,16}(?![0-9A-Za-z])")
# the publisher ids that follow the name of an AppX package family (the hash of the publisher's name), and the assembly public key tokens of Microsoft
_KNOWN_ID_WORDS = ("0x", "8wekyb", "cw5n1h", "kzf8qx", "31bf38", "b77a5c", "b03f5f")
_KNOWN_ID = re.compile(r"(?<![0-9A-Za-z])(?:8wekyb3d8bbwe|cw5n1h2txyewy|kzf8qxf38zg5c|31bf3856ad364e35|b77a5c561934e089|b03f5f7f11d50a3a|0x[0-9A-Fa-f]{1,16})(?![0-9A-Za-z])")
_NAME_SEPS = " _-.$@?:~+,#()[]{}'`<>*"
_PATH_EXTRA = "&!';=^%\""
_PCT = re.compile(r"%[0-9A-Fa-f]{2}")
_PCT_UNRESERVED = re.compile(r"%((?:4[1-9A-Fa-f]|5[0-9Aa]|6[1-9A-Fa-f]|7[0-9Aa]|3[0-9]|2[DdEe]|5[Ff]|7[Ee]))")
_JOIN_NAME, _JOIN_PATH = "-_+", "-_+/\\"
_CTRL = "\x01\x02\x03\x04\x05\x06\x07\x08\x09"


def _has(words, text):
    """Whether one of `words` is in `text` (a loop: a generator inside any() costs twice as much for the thousands of strings of a hive)."""
    for w in words:
        if w in text:
            return True
    return False


def _pronounceable(piece):
    p = piece.lower()
    bad = sum(1 for a, b in zip(p, p[1:]) if (a + b) not in _BIGRAMS)
    return bad <= 1 + len(p) // 10


_HEX_LOW_OR_UP = re.compile(r"[0-9a-f]+|[0-9A-F]+")
_HEX_ANY = re.compile(r"[0-9A-Fa-f]+")
_SEGMENT_MEMO = {}


def _structure_ok(seg):
    if seg.isdigit() and seg.isascii():
        return len(seg) <= 18
    if len(seg) <= 24 and _HEX_LOW_OR_UP.fullmatch(seg):
        return True                       # a hexadecimal id up to 24 digits (a USB serial, a 16-digit object id, a hash of a few bytes) is plain
    if len(seg) >= 20 and _HEX_ANY.fullmatch(seg):
        return False
    pieces = _PIECE.findall(seg)
    short = sum(1 for p in pieces if len(p) <= 2)
    if short > max(2, 0.4 * len(pieces)):
        return False
    flips = sum(1 for a, b in zip(seg, seg[1:]) if a.isdigit() != b.isdigit())
    if flips > 3 + len(seg) // 16:
        return False
    alpha = [p for p in pieces if p.isalpha()]
    if sum(len(p) for p in alpha) >= 12 and sum(len(p) for p in alpha) < 3.4 * len(alpha):
        return False
    return True


def _plain_segment(seg, lmin=None):
    lmin = LMIN if lmin is None else lmin
    if len(seg) < lmin:
        return True
    memo = (seg, lmin) if len(seg) <= 64 else None          # the same words come again and again in the records of one log
    if memo is not None:
        hit = _SEGMENT_MEMO.get(memo)
        if hit is not None:
            return hit
    if not _structure_ok(seg):
        ok = False
    else:
        ok = all(not (p.isalpha() and len(p) >= 6) or _pronounceable(p) for p in _PIECE.findall(seg))
    if memo is not None:
        if len(_SEGMENT_MEMO) >= 100000:
            _SEGMENT_MEMO.clear()
        _SEGMENT_MEMO[memo] = ok
    return ok


_EMBEDDED_ID = re.compile(r"(?<![A-Za-z0-9])(?:naa\.(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{16})|eui\.[0-9a-fA-F]{16}|wwn-0x[0-9a-fA-F]{16}|vml\.[0-9a-fA-F]{20,40}|vsan:[0-9a-f]{16}-[0-9a-f]{16})(?![A-Za-z0-9])")
_EMBEDDED_T10 = re.compile(r"(?<![A-Za-z0-9])t10\.[A-Za-z0-9_.+-]{8,120}")
_EMBEDDED_WORDS = ("naa.", "eui.", "wwn-0x", "vml.", "vsan:", "t10.")


def _t10_plain(text):
    """Whether a t10. id reads as the id of a drive: every piece between underscores is 19 characters or fewer, and the serial (the last) is not a run of 17 or more hexadecimal digits."""
    pieces = text.split("_")
    return all(len(piece) <= 19 for piece in pieces) and not (len(pieces[-1]) >= 17 and _HEX_ANY.fullmatch(pieces[-1]) is not None)


_ONE_CASE_TAIL = re.compile(r"[A-Za-z]{20,64}")


def _letter_serial_spans(t):
    """The t10. and iqn. ids in `t` whose serial (the last piece of a t10. id) or target (after the last colon of an iqn. name) is 20 or more letters of one case that do not read as a word."""
    if "t10." not in t and "iqn." not in t:
        return []
    spans = []
    for m in _EMBEDDED_T10.finditer(t):
        last = m.group().split("_")[-1]
        if _ONE_CASE_TAIL.fullmatch(last) and (last.islower() or last.isupper()) and not _word_letters(last):
            spans.append((m.start(), m.end()))
    for m in _IQN_NAME.finditer(t):
        last = m.group().rsplit(":", 1)[-1]
        if _ONE_CASE_TAIL.fullmatch(last) and (last.islower() or last.isupper()) and not _word_letters(last):
            spans.append((m.start(), m.end()))
    return spans


_IQN_NAME = re.compile(r"(?<![A-Za-z0-9])iqn[.][0-9]{4}-[0-9]{2}[.][a-z0-9.-]{1,60}(?::[A-Za-z0-9._-]{1,64})?")


def _t10_hex_spans(t):
    """The t10. ids in `t` whose serial is a run of 17 or more hexadecimal digits: a drive's serial is not one (a random one is), and a run of hexadecimal digits is otherwise plain."""
    if "t10." not in t and "iqn." not in t:
        return []
    spans = []
    for m in _EMBEDDED_T10.finditer(t):
        last = m.group().split("_")[-1]
        if len(last) >= 17 and _HEX_ANY.fullmatch(last) is not None:
            spans.append((m.start(), m.end()))
    return spans + _letter_serial_spans(t)


def _mask_embedded(t):
    """`t` with the well-formed ids of devices in it (naa., eui., wwn-0x, vml., vsan: and a t10. id of a drive) replaced by `~`, so that the judging of a name or a path does not take their digits for a random run."""
    if not _has(_EMBEDDED_WORDS, t):
        return t
    t = _EMBEDDED_ID.sub(lambda m: "~" * len(m.group()), t)
    return _EMBEDDED_T10.sub(lambda m: "~" * len(m.group()) if _t10_plain(m.group()) else m.group(), t)


def _prepare(s, typed=True):
    """A same-length copy of `s` in which a GUID, a SID, an IPv4 address and a %XX escape are replaced by `~` and a non-ASCII letter by `e`;
    None when `s` holds a format, control or combining character, a non-NFKC character or a stray space character."""
    if not s.isascii():
        for ch in s:
            cat = unicodedata.category(ch)
            if cat[0] in "CM" or (cat[0] == "Z" and ch != " "):
                return None
        if unicodedata.normalize("NFKC", s) != s:
            return None
        s = "".join(ch if ch.isascii() else "e" for ch in s)
    t = _GUID.sub(lambda m: "~" * len(m.group()), s) if s.count("-") >= 3 else s    # (each pattern is tried only when the text holds what it cannot match without: a GUID has three hyphens or more)
    if typed:
        if "S-1-" in t:
            t = _SID.sub(lambda m: "~" * len(m.group()), t)
        if "." in t:
            t = _IPV4.sub(lambda m: "~" * len(m.group()), t)
        if _has(_KNOWN_ID_WORDS, t):
            t = _KNOWN_ID.sub(lambda m: "~" * len(m.group()), t)
        t = _mask_embedded(t)
    return _PCT.sub("   ", t) if "%" in t else t


def _unpercent(s):
    if "%" not in s:
        return None
    out = _PCT_UNRESERVED.sub(lambda m: chr(int(m.group(1), 16)), s)
    return out if out != s else None


_CHAINS = {}
_SEGMENT = re.compile(r"[A-Za-z0-9]+")


_SEGMENT_PLAIN = {}


def _is_plain_segment(seg):
    """_plain_segment(seg, 0), remembered for the plain ones only (a dict that is asked a hundred thousand times for the same words)."""
    if not _plain_segment(seg, 0):
        return False
    if len(seg) <= 64:
        if len(_SEGMENT_PLAIN) >= 100000:
            _SEGMENT_PLAIN.clear()
        _SEGMENT_PLAIN[seg] = True
    return True


def _bad_runs(t, join):
    """Intervals of `t` that are not plain, judged on CHAINS: maximal sequences of alphanumeric segments joined only by `join` characters. A
    chain is bad when (A) its random-looking segments, adjacent ones taken together, add up to LMIN characters or more, or (B) it is LMIN
    characters or longer, holds 8 or more characters of letter-and-digit-mixed segments, and holds no word of five or more letters."""
    pattern = _CHAINS.get(join)
    if pattern is None:
        pattern = _CHAINS[join] = re.compile(r"[A-Za-z0-9]+(?:[%s]+[A-Za-z0-9]+)*" % "".join(re.escape(c) for c in join))
    plain = _SEGMENT_PLAIN
    if all(plain.get(seg) or _is_plain_segment(seg) for seg in _SEGMENT.findall(t)):
        return []                                       # no chain holds a random-looking segment, so none is bad (the same answer as the loop below, without building the chains)
    bad = []
    for found in pattern.finditer(t):
        if found.end() - found.start() < LMIN:
            continue                                    # a chain shorter than LMIN is neither a run of LMIN random characters nor a long mixed chain
        chain = [(m.start(), m.end()) for m in _SEGMENT.finditer(t, found.start(), found.end())]
        total = sum(b - a for a, b in chain)
        if total < LMIN:
            continue
        rnd = [not _plain_segment(t[a:b], 0) for a, b in chain]
        if not any(rnd):
            continue
        run = None
        for (a, b), r in zip(chain, rnd):
            if r:
                run = [a, b, b - a] if run is None else [run[0], b, run[2] + (b - a)]
            else:
                if run is not None and run[2] >= LMIN:
                    bad.append((run[0], run[1]))
                run = None
        if run is not None and run[2] >= LMIN:
            bad.append((run[0], run[1]))
        mixed = sum(b - a for a, b in chain if not _structure_ok(t[a:b]))
        if total >= LMIN and mixed >= 8 and not any(len(p) >= 5 and p.isalpha() and _pronounceable(p) for a, b in chain for p in _PIECE.findall(t[a:b])):
            bad.append((chain[0][0], chain[-1][1]))
    return bad


_CHARS = {}


def _chars_ok(comp, extra_ok):
    if comp.isascii():
        pattern = _CHARS.get(extra_ok)
        if pattern is None:
            pattern = _CHARS[extra_ok] = re.compile("[A-Za-z0-9%s]*" % re.escape(_NAME_SEPS + extra_ok))
        return pattern.fullmatch(comp) is not None
    return all(ch.isalnum() or ch in _NAME_SEPS or ch in extra_ok for ch in comp)


def _userinfo_shape(t):
    return ":" in t and "@" in t and t.index(":") < t.rindex("@")


def _plain_name(s, extra_ok=""):
    if not s or len(s) > 128:
        return False
    t = _prepare(s)
    if t is None or not _chars_ok(t, extra_ok) or _userinfo_shape(t) or _secret_in_ident(t) or _t10_hex_spans(t):
        return False
    u = _unpercent(s)
    if u is not None:
        pu = _prepare(u)
        if pu is None or _bad_runs(pu, _JOIN_NAME):
            return False
    return not _bad_runs(t, _JOIN_NAME)


def _merge(spans):
    merged = []
    for a, b in sorted(spans):
        if merged and a <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], b))
        else:
            merged.append((a, b))
    return merged


_SPLIT = re.compile(r"([\\/])")
_DRIVE = re.compile(r"[A-Za-z]:|\?|\.")


def _path_spans(s, extra_ok=_PATH_EXTRA):
    t = _prepare(s)
    if t is None:
        return [(0, len(s))]
    bad, pos = [], 0
    if len(t) <= 255 and "@" not in t and t.isascii() and _chars_ok(t, extra_ok + "\\/") and not _secret_in_ident(t):
        parts = ()                       # (every character is allowed, no part is long and none can hold a user-info shape: no part is bad)
    else:
        parts = _SPLIT.split(t)
    for part in parts:
        a, b = pos, pos + len(part)
        pos = b
        judged = part.lstrip(_CTRL)
        if part in ("\\", "/") or part == "" or _DRIVE.fullmatch(part):
            continue
        if len(part) - len(judged) > 1 or len(part) > 255 or not _chars_ok(judged, extra_ok) or _userinfo_shape(judged) or _secret_in_ident(judged):
            bad.append((a, b))
    bad += _bad_runs(t, _JOIN_PATH) + _t10_hex_spans(t)
    u = _unpercent(s)
    if u is not None:
        pu = _prepare(u)
        if pu is None or _bad_runs(pu, _JOIN_PATH):
            bad.append((0, len(s)))
    return _merge(bad)


def _replace_spans(s, spans, label, field):
    out, last = [], 0
    for a, b in spans:
        out.append(s[last:a])
        out.append(_b_withheld(s[a:b], label, field))
        last = b
    out.append(s[last:])
    return "".join(out)


def _show_name(s, field):
    return s if _plain_name(s) else _b_withheld(s, "not a plain name", field)


def _show_path(s, field, extra_ok=_PATH_EXTRA):
    return _replace_spans(s, _path_spans(s, extra_ok), "not a plain name", field)


def _show_key(s, field):
    return _show_path(s, field, _PATH_EXTRA + "*^<>")


_URL = re.compile(r"^((?:[A-Za-z][A-Za-z0-9+.-]*:)?//)(?:([^/?#]*)@)?([^/?#]*)([^?#]*)(?:\?([^#]*))?(?:#(.*))?$", re.S)


def _show_host(s, field):
    """A host name is on the deny-list: a random-looking label of a host is evidence (a C2 name), not a secret. Layer 2 reads it first: the deny-list
    would replace a random user of `user:password@host` and leave the context layer 2 needs."""
    return _deny_text(_layer2(s, field), field)


def _show_value(v):
    return v if re.fullmatch(r"[0-9]{1,12}|true|false|null|yes|no", v) or (v.isalpha() and len(v) <= 24 and _plain_name(v)) else None


def _show_url(s, field):
    m = _URL.match(s)
    if not m:
        return _show_path(s, field)
    scheme, userinfo, host, path, query, frag = m.groups()
    out = scheme
    if userinfo is not None:
        out += (userinfo if _MARK.fullmatch(userinfo) else _b_withheld(userinfo, "user-info", field)) + "@"
    hostname, colon, port = host.partition(":") if not host.startswith("[") else (host, "", "")
    out += _show_host(hostname, field) + (colon + (port if port.isdigit() else _b_withheld(port, "not a port", field)) if colon else "")
    out += _show_path(path, field)
    if query is not None:
        pairs = []
        for pair in query.split("&"):
            k, eq, v = pair.partition("=")
            kk = _show_name(k, field) if k else k
            if eq:
                sv = _show_value(v)
                pairs.append(kk + "=" + (sv if sv is not None else _b_withheld(v, "query value", field)))
            else:
                pairs.append(kk)
        out += "?" + "&".join(pairs)
    if frag is not None:
        sv = _show_value(frag)
        out += "#" + (sv if sv is not None else _b_withheld(frag, "fragment", field))
    return out


_TYPED = {
    "guid": re.compile(_GUID.pattern),
    "digest": re.compile(r"(?:sha256:|sha1:|md5:)?[0-9A-Fa-f]{32,128}|T1[0-9A-Fa-f]{60,72}|[0-9]{1,6}:[A-Za-z0-9+/]{3,}:[A-Za-z0-9+/]{3,}"),
    "sid": re.compile(_SID.pattern),
    "mac": re.compile(r"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}"),
    "ip": re.compile(r"[0-9]{1,3}(?:\.[0-9]{1,3}){3}|[0-9A-Fa-f:.]{2,45}(?:%[0-9A-Za-z_.-]{1,16})?"),
    "time": re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}(?:[T ][0-9:.]+(?:Z|[+-][0-9:]+)?)?|D:[0-9]{8,14}(?:[Zz+-][0-9']*)?|[0-9]{1,18}"),
    "number": re.compile(r"-?[0-9]{1,18}(?:\.[0-9]{1,18})?|0x[0-9A-Fa-f]{1,16}|(?:true|false|null)"),
    "version": re.compile(r"v?[0-9]+(?:\.[0-9A-Za-z]+){1,4}(?:[-+][0-9A-Za-z.]+)?"),
    # the identifiers of virtualized storage and machines: a VMFS volume id (8-8-4-12 hexadecimal digits), a SCSI device id (naa. with 16 or 32 digits, eui. and
    # wwn-0x with 16, vml. with 20 to 40, t10. with a vendor, a model and a serial), an iSCSI name, the VMware uuid of a machine (16 bytes, a `-` after the
    # eighth), the content id of a disk (8 digits) and the name Windows gives a machine nobody named (WIN- and 11 capitals and digits)
    "vmfs": re.compile(r"[0-9a-f]{8}-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{12}"),
    "device": re.compile(r"naa\.(?:[0-9a-fA-F]{16}|[0-9a-fA-F]{32})|eui\.[0-9a-fA-F]{16}|wwn-0x[0-9a-fA-F]{16}|vml\.[0-9a-fA-F]{20,40}|t10\.[A-Za-z0-9_.+-]{8,120}"),
    "iqn": re.compile(r"iqn\.[0-9]{4}-[0-9]{2}\.[a-z0-9][a-z0-9.-]{0,60}(?::[A-Za-z0-9._-]{1,40})?"),
    "vmuuid": re.compile(r"[0-9a-f]{2}(?: [0-9a-f]{2}){7}-[0-9a-f]{2}(?: [0-9a-f]{2}){7}"),
    "cid": re.compile(r"[0-9a-f]{8}"),
    "winhost": re.compile(r"WIN-[A-Z0-9]{11}"),
}
_ID_FORMS = ("guid", "vmfs", "vmuuid", "device", "mac", "cid", "number")      # the forms a field of kind `id` may hold (the kind of a field that holds one of several forms of identifier), else it is judged as a name
_CONTENT_ID = re.compile(r"[0-9A-Fa-f]{32}")
_NAMING_IDS = frozenset(("device", "iqn"))          # the ids that hold a name a person chose (a t10. vendor, model and serial; an iSCSI name): what they hold must read as a name, not as random text
_KNOWN_KINDS = frozenset(("text", "name", "path", "key", "url", "host", "hex", "label", "id")) | frozenset(_TYPED)
_NUMBER_RUN = re.compile(r"[0-9]+")


def bind_fields(table, key_kinds=None):
    """The field kinds of a tool, passed in by the tool (this text holds none): `table` maps a JSON key to the kind of what it holds, or to a function of
    the key of one item for a dict whose items have kinds of their own; `key_kinds` maps a key holding a dict to the kind of that dict's own keys. A kind
    this text does not know is refused (a misspelt kind would judge the field as free text without a word)."""
    for name, kind in list(table.items()) + list((key_kinds or {}).items()):
        if not isinstance(name, str) or not (callable(kind) or kind in _KNOWN_KINDS):
            raise ValueError("a field kind this text does not know: %r" % (name,))
    FIELDS.update(table)
    KEY_KINDS.update(key_kinds or {})


def _field_entry(name):
    """What FIELDS says of the field `name`; a digit run in a name stands for any number (`ethernet0.address` is `ethernet#.address`)."""
    entry = FIELDS.get(name)
    if entry is None and name and any(c.isdigit() for c in name):
        entry = FIELDS.get(_NUMBER_RUN.sub("#", name))
    return entry


# ---- layer 2: position and prefix rules -------------------------------------------------------------------------------------------
# user-info whose password holds a `/` (RFC 3986 says to encode it; people do not): after `//`, a user, a `:`, then everything up to the last `@` that is
# followed by a host; not `host:8080/...@...` (a port), whose first word after the colon is a number
_URL_USERINFO_SLASH = re.compile(r"(?<=//)(?![^\s/@:<>\"'`]*:[0-9]{1,5}(?:[/?#@]|$))[^\s/@:<>\"'`]{1,64}:[^\s<>\"'`]{1,128}(?=@[^\s/@<>\"'`]*(?:[\s/<>\"'`?#]|$))")
# a user the deny-list already replaced: `<withheld ...>:password@host`
_MARK_USERINFO = re.compile(r"(?P<mark><withheld \d+ (?:characters|bytes)[^<>]{0,70}>|\[withheld: \d+ characters\]):(?P<pw>[^\s/<>\"'`]{1,128})(?=@[^\s/@<>\"'`]*(?:[\s/<>\"'`?#]|$))")
_B_USERINFO = re.compile(r"(?<![A-Za-z0-9._%+-])(?!mailto:)[^\s/@:<>\"'`]{1,64}:[^\s/<>\"'`]{1,128}(?=@[^\s/@<>\"'`]*(?:[\s/<>\"'`?#]|$))")
_URL_USERINFO = re.compile(r"(?<=//)[^/?#\s@]+(?=@)")
_NAMED_HEAD = r"(?i:(?<![Bb]y)(?<![Cc]om)(?<![Oo]ver)(?<![Uu]nder)(?<![Tt]res)(?<![Ee]ncom)(?<![Ss]ur)(?<![Ii]m)pass(?:word|wd|phrase)?|pwd|secret|token|api[_-]?key|access[_-]?key|account[_-]?key|private[_-]?key|client[_-]?secret|credential|auth(?:orization)?|(?<![A-Za-z])(?:pw|sig|sas|otp|psk))" r"s?[0-9]{0,2}[\"']?[ \t]{0,3}[=:][ \t]{0,3}[\"']?"
_NAMED = re.compile(_NAMED_HEAD + r"(?!line[ \t]+[0-9])" + r"(?P<value>(?:(?i:token|bearer|basic|negotiate)[ \t]+(?=[A-Za-z0-9+/._~=-]{8}))?(?:[^\s\"'<>;,&]|[;,&](?![A-Za-z0-9_. -]{1,40}=)){1,512})")
# a placeholder (<redacted>, <password>, <***>) is not a value, but what is glued behind it is
_PLACEHOLDER = r"<(?i:redacted|hidden|masked|removed|omitted|secret|password|passwd|passphrase|pwd|pass|token|key|value|placeholder|empty|none|null|unset|your[ _-]?(?:password|secret|token|key)|\*{1,16})?>"
_PH_END = r"(?=[\s\"';,&\\<>)\]}]|\.(?:\s|$)|$)"
# a value in angle brackets after a secret's name (password=<hJaXeuQz>): withheld unless it reads as a placeholder word
_ANGLE_SPLIT = re.compile(r"[-_.+/=~]")
_NAMED_ANGLE = re.compile(_NAMED_HEAD + r"(?!" + _PLACEHOLDER + r")(?P<value><(?P<inner>[A-Za-z0-9+/_.~=-]{6,128})>)")
_NAMED_PH = re.compile(_NAMED_HEAD + _PLACEHOLDER + r"(?P<value>[^\s\"'<>;,&\\]{1,512})")
# the name of a flag that takes a secret (`-password x`, `--token x`, `--api-key x`, `-auth x`): the words below, any word with `secret` in it or ending in `token`, `key` or
# (after a letter or a digit) Key, Token, Password, Pwd, Pass, Secret, also after up to four words joined by `-` or `_`; `--key-file x` and `--keyboard x` are not (the name ends where the value begins)
_FLAG_NAME = (r"(?:[A-Za-z0-9]{1,20}[-_]){0,4}(?:(?i:passw(?:or)?d|passwd|pass(?:[-_]?phrase)?|pwd|pw|otp|[A-Za-z0-9]{0,20}secret[A-Za-z0-9]{0,20}|[A-Za-z0-9]{0,20}token|api[-_]?key|access[-_]?key|key|keypass|storepass|userpass|auth|authorization|bearer|psk|credentials?|community)"
              r"|[A-Za-z0-9]{1,20}(?-i:Key|Token|Password|Passwd|Pwd|Pass|Passphrase|Secret))")
# a placeholder, a space and a value built like a secret: the placeholder is not the value, the word after it is
_PH_SPACE = re.compile(r"(?:" + _NAMED_HEAD + r"|(?<![\w-])--?" + _FLAG_NAME + r"[ \t]+|(?<![\w-])(?i:set|enable)[ \t]+(?i:passw(?:or)?d|secret|passphrase|token)[ \t]+)"
                       + _PLACEHOLDER + r"[ \t]+(?P<value>[A-Za-z0-9]{8,40})(?![A-Za-z0-9])")
_NAMED_FLAG = re.compile(r"(?<![\w-])--?" + _FLAG_NAME + r"(?:=|[ \t]+)(?!-)(?!" + _PLACEHOLDER + _PH_END + r")(?![\x5ca-zA-Z0-9_./~:-]{1,120}[.](?i:key|pem|pub|crt|p12|pfx|jks)(?![A-Za-z0-9]))(?!(?:~|[.]{1,2})/[A-Za-z0-9_./-]{1,120}|/[A-Za-z0-9_.-]{1,40}(?:/[A-Za-z0-9_.-]{1,40})+)(?P<value>[^\s\"']+)")
_NAMED_SET = re.compile(r"(?<![\w-])(?i:set|enable)[ \t]+(?i:passw(?:or)?d|secret|passphrase|token)[ \t]+(?:[0-9][ \t]+)?(?!" + _PLACEHOLDER + _PH_END + r")(?P<value>[^\s\"']+)")
# in a name or a path component: a secret's name and, glued or after a separator or a space, something that is not a word (password-Zq7kP2mR, Token Zq7kP2mR, pwdZq7kP2mR), or a flag with its value
# (-password x, d--pwd x): a name that holds one is a command line, not a name
_IDENT_FLAG = re.compile(r"(?<![A-Za-z0-9])--?" + _FLAG_NAME + r"[ \t]+(?!-)\S")
_SECRET_THEN = re.compile(r"(?:(?i:passw(?:or)?d|passphrase|pwd|secret|token|credential|api[_-]?key|private[_-]?key|access[_-]?key|account[_-]?key)|(?<=-)(?i:pass|auth|bearer|psk))"
                          r"(?=s?[ \t_.-]*['\"(\[]?([A-Za-z0-9]{1,40}))")
_SECRET_THEN_TEXT = re.compile(r"(?<![A-Za-z0-9])(?i:passw(?:or)?d|passphrase|pwd|secret|token|credential|api[_-]?key|private[_-]?key|access[_-]?key|account[_-]?key)s?[ \t_.-]{1,3}['\"(\[]?(?P<value>[A-Za-z0-9]{7,40})(?![A-Za-z0-9])")
_GLUED_FLAG = re.compile(r"(?<![A-Za-z0-9])--?(?:[A-Za-z0-9]{1,20}[-_]){0,4}(?i:key|token|pass|password|pwd|secret)(?P<value>[A-Za-z0-9]{8,40})(?![A-Za-z0-9])")
_FLAG_THEN = re.compile(r"(?<![A-Za-z0-9])--?" + _FLAG_NAME + r"(?=[ \t_.-]*['\"(\[]?([A-Za-z0-9]{1,40}))")
_ID_SECRET_WORDS = ("pass", "pwd", "secret", "token", "key", "cred", "auth", "bearer", "psk", "otp", "pw", "community")
_WORD_PARTS = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|[0-9]+")


_FIVE_CONSONANTS = re.compile(r"[^aeiouy]{5}")
_VEEAM_GLUE = re.compile(r"D(?:19|20)[0-9]{2}$")
_DATE8 = re.compile(r"(?:19|20)[0-9]{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12][0-9]|3[01])(?:[0-2][0-9][0-5][0-9][0-5][0-9])?")


def _value_like(tok):
    """Whether a run of letters and digits after a secret's name is built like a secret and not like words: 7 or more characters with a digit among them (not the one to four
    digits of a counter at the end), or only digits, or a run of capitals of other than two or three, or a word of lower case letters that is not pronounceable."""
    if len(tok) < 7:
        return False
    tok = _VEEAM_GLUE.sub("", tok)                       # (the D2024 that Veeam glues to a job name before its time stamp)
    if len(tok) < 7:
        return False
    if tok.isdigit():
        return _DATE8.fullmatch(tok) is None             # (a date, 20240312, with or without a time of day, is not a value)
    parts = _WORD_PARTS.findall(tok)
    if parts and parts[-1].isdigit():
        if len(parts[-1]) > 4:
            return True
        parts.pop()
    for n, part in enumerate(parts):
        if part.isdigit():
            return True
        if part.isupper():
            if not 2 <= len(part) <= 3:
                return True
        elif len(part) < 3 or (n > 0 and not part[0].isupper()) or not _word_letters(part):
            return True
    return False


_TECH_WORDS = re.compile("vmware|vcenter|vsphere|vsan|proxmox|nextcloud|splunk|openvpn|pfsense|opnsense|switch|postgres(?:ql)?|pgsql|mysql|mssql|sqlserver|rabbitmq|kafka|"
                         "upgrad(?:e|ed|es|ing)|updat(?:e|ed|es|ing)|workstation|helpdesk|cloudhsm|hyperv|xenserver|netapp|nutanix|veeam|commvault|cohesity|wsus|sccm|pgbouncer|mongodb|redis|"
                         "kubernetes|openshift|jumpbox|gitlab|github|jfrog|zabbix|ldaps?|radius|kerberos|tacacs|cifs|ntnx|qemu|esxi|smtp|sftp|dhcp|https?|iscsi|ntfs|sshd|nightly|monthly|fortnightly|midnight|lightweight|scratch|snmp|crowdstrike|etcd|vmfs|btrfs|openbsd")
_NAME_TOKEN = re.compile(r"[A-Za-z0-9]+")
_TAG = re.compile(r"(?:[a-z]{3,5}|[A-Z]{3,5}|[A-Z][a-z]{2,4})[0-9]{1,4}|[A-Z][0-9][A-Z][0-9]")
_DATE_STAMP = re.compile(r"D?(?:19|20)[0-9]{2}[-_.]?(?:0[1-9]|1[0-2])[-_.]?(?:0[1-9]|[12][0-9]|3[01])(?:[-_.T ]?[0-2][0-9][0-5][0-9][0-5][0-9])?(?:_[0-9A-Fa-f]{4}(?![0-9A-Za-z]))?")


def _word_letters(word):
    """Whether a run of letters reads as a word: every pair of letters is one that words hold (the names of products and services are taken out first), and there are no five consonants in a row."""
    low = _TECH_WORDS.sub("", word.lower())
    for k in range(len(low) - 1):
        if low[k:k + 2] not in _BIGRAMS:
            return False
    return _FIVE_CONSONANTS.search(low) is None


_FILE_EXTS = frozenset(("vmdk", "vmx", "vmsd", "vmsn", "vmem", "vmss", "nvram", "log", "qcow2", "qcow", "vhdx", "avhdx", "vhd", "vdi", "ovf", "ova", "json", "jsonl", "yaml", "conf", "cfg", "flat", "delta", "sesparse", "iso", "img", "raw", "bak", "tmp"))


def _groupish(tok):
    """A run of 4 or more letters and digits that is not a tag (srv01, db02 are tags): the part of a value written in groups (ab12-cd34-ef56)."""
    if len(tok) < 4 or _TAG.fullmatch(tok) is not None:
        return False
    if tok.isalpha() and tok.isupper():
        return _TECH_WORDS.fullmatch(tok.lower()) is None            # (capitals of 4 or more letters are not a word: KHIL, not ESXI)
    if tok.isalpha() and not tok[1:].islower():
        return True                                                  # (a word is not written with a capital in the middle: paUn)
    base = tok.rstrip("0123456789")
    return not (base.isalpha() and len(base) >= 4 and len(tok) - len(base) <= 4 and _word_letters(base))


def _words_value(text, start):
    """Whether any word after a secret's name, from `start` on, is a value: built like a secret by itself, or one of two or more groups in a row (ab12-cd34), which are one value written in parts."""
    tokens = _NAME_TOKEN.findall(_DATE_STAMP.sub(" ", text[start:start + 400]))
    group, run, seen = [], [], False
    for tok in tokens[:40]:
        if _value_like(tok):
            return True
        if tok.lower() in _FILE_EXTS:
            run, seen = [], False                                    # (the end of a file name is not a part of a value)
        elif 4 <= len(tok) <= 6:                                     # (a short word between two groups, or next to one, is part of the value: yIgK-paUn)
            run.append(tok)
            seen = seen or (_groupish(tok) and not tok.isdigit())
            if seen and len(run) >= 2 and _value_like("".join(run)):
                return True
        else:
            run, seen = [], False
        if len(tok) == 5 or len(tok) == 6:
            if tok.isdigit() and tok[0] != "0":
                return True              # 5 or 6 digits that do not start like a counter (000001)
        if _groupish(tok):
            group.append(tok)
            if len(group) >= 2 and _value_like("".join(group)):
                return True
        else:
            group = []
    return False


def _secret_in_ident(text):
    """Whether a name or a path component holds a secret's name with a value after it (see above). Linear: each pattern is anchored on a name and reads at most 400 characters after it."""
    if not _has(_ID_SECRET_WORDS, text.lower()):
        return False
    if _IDENT_FLAG.search(text) is not None or _NAMED_SET.search(text) is not None:
        return True
    for pattern in (_SECRET_THEN, _FLAG_THEN):
        m = pattern.search(text)
        if m is not None and _words_value(text, m.start(1)):
            return True
    return False
_PEM = re.compile(r"-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]{0,40}PRIVATE KEY-----|$)", re.S)
_PREFIX = re.compile(r"(?i:(?:AKIA|ASIA)[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[abeprs]-[A-Za-z0-9-]{10,}|glpat-[A-Za-z0-9_-]{20,}"
                     r"|(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}|SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}|AIza[0-9A-Za-z_-]{30,}|npm_[A-Za-z0-9]{30,}"
                     r"|dop_v1_[0-9a-f]{40,}|ya29\.[0-9A-Za-z_-]{30,})|sk-(?=[A-Za-z0-9_-]{0,39}[0-9])[A-Za-z0-9_-]{20,}|eyJ[A-Za-z0-9_-]{8,300}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]*)?")
_BASE64_PADDED = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{16,}={1,2}(?![A-Za-z0-9+=])")
_LONG_DIGITS = re.compile(r"(?<![0-9])[0-9]{19,}(?![0-9])")


_BASE64_PADDED_PATH = re.compile(r"[A-Za-z0-9+/]{22,90}={1,2}(?![A-Za-z0-9+=])")           # (bounded: a long run of these characters costs a step for each of the 90 before a start, not the rest of the run)


def _padded_in_path(field):
    """A padded base64 key that stands behind a `/` (a path ends in the key, or the key's own `/` cut it): the last 22 characters before two pads, 27 before one, are withheld."""
    def sub(m):
        body = m.group().rstrip("=")
        pad = len(m.group()) - len(body)
        keep = len(body) - (22 if pad == 2 else 27)
        if keep < 0:
            return m.group()
        tail = body[keep:]
        if "/" not in tail or len({"d" if c.isdigit() else "u" if c.isupper() else "l" for c in tail if c.isalnum()}) < 2 or not _b64_shape(tail + "=" * pad):
            return m.group()
        return body[:keep] + _b_withheld(tail + "=" * pad, "token-shaped text", field)
    return sub


def _b64_shape(run):
    """Whether a padded run can be base64 of random bytes: its length with the padding is a multiple of 4, and it holds a digit, `+` or `/` (a long
    identifier before an `=` in a line of text, RelatedActivityID=, is not one)."""
    return len(run) % 4 == 0 and re.search(r"[0-9+/]", run) is not None


_NAMED_WORDS = ("pass", "pwd", "secret", "token", "key", "credential", "auth")
_PREFIX_HINTS = ("akia", "asia", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_", "xox", "glpat-", "_live_", "_test_", "sg.", "aiza", "npm_", "dop_v1_",
                 "ya29.", "sk-", "eyj")


def _layer2_once(s, field):
    # each rule is tried only when the text holds what it needs (a character or a word it cannot match without): the same result, a lot less reading
    if "withheld" in s:
        s = _MARK_USERINFO.sub(lambda m: m.group("mark") + ":" + _b_withheld(m.group("pw"), "user-info", field), s)
    if "-----" in s:
        s = _outside(s, _MARK, lambda p: _PEM.sub(lambda m: _b_withheld(m.group(), "private key", field), p))
    if "@" in s:
        s = _outside(s, _MARK, lambda p: _URL_USERINFO_SLASH.sub(lambda m: _b_withheld(m.group(), "user-info", field), p))
        s = _outside(s, _MARK, lambda p: _URL_USERINFO.sub(lambda m: _b_withheld(m.group(), "user-info", field), p))
        s = _outside(s, _MARK, lambda p: _B_USERINFO.sub(lambda m: _b_withheld(m.group(), "user-info", field), p))
    low = s.lower()
    if _has(_NAMED_WORDS, low):
        s = _outside(s, _MARK, lambda p: _NAMED.sub(lambda m: m.group()[:m.start("value") - m.start()] + _b_withheld(m.group("value"), "secret value", field), p))
        if "<" in s:
            s = _outside(s, _MARK, lambda p: _PH_SPACE.sub(lambda m: m.group()[:m.start("value") - m.start()] + (_b_withheld(m.group("value"), "secret value", field) if _value_like(m.group("value")) else m.group("value")), p))
            s = _outside(s, _MARK, lambda p: _NAMED_ANGLE.sub(lambda m: m.group()[:m.start("value") - m.start()] + (_b_withheld(m.group("value"), "secret value", field) if any(_value_like(x) for x in _ANGLE_SPLIT.split(m.group("inner"))) else m.group("value")), p))
            s = _outside(s, _MARK, lambda p: _NAMED_PH.sub(lambda m: m.group()[:m.start("value") - m.start()] + _b_withheld(m.group("value"), "secret value", field), p))
    if _has(("pass", "pwd", "secret", "token", "credential", "key"), low):
        s = _outside(s, _MARK, lambda p: _SECRET_THEN_TEXT.sub(lambda m: m.group()[:m.start("value") - m.start()] + (_b_withheld(m.group("value"), "secret value", field) if _value_like(m.group("value")) else m.group("value")), p))
        if "-" in s:
            s = _outside(s, _MARK, lambda p: _GLUED_FLAG.sub(lambda m: m.group()[:m.start("value") - m.start()] + (_b_withheld(m.group("value"), "secret value", field) if _value_like(m.group("value")) else m.group("value")), p))
    if "-" in s or "set" in low or "enable" in low:
        s = _outside(s, _MARK, lambda p: _NAMED_FLAG.sub(lambda m: m.group()[:m.start("value") - m.start()] + _b_withheld(m.group("value"), "secret value", field), p))
        s = _outside(s, _MARK, lambda p: _NAMED_SET.sub(lambda m: m.group()[:m.start("value") - m.start()] + _b_withheld(m.group("value"), "secret value", field), p))
    if "=" in s:
        s = _outside(s, _MARK, lambda p: _BASE64_PADDED.sub(lambda m: _b_withheld(m.group(), "token-shaped text", field) if _b64_shape(m.group()) else m.group(), p))
        if "/" in s:
            s = _outside(s, _MARK, lambda p: _BASE64_PADDED_PATH.sub(_padded_in_path(field), p))
    s = _outside(s, _MARK, lambda p: _LONG_DIGITS.sub(lambda m: _b_withheld(m.group(), "long number", field), p))
    low = s.lower()
    if _has(_PREFIX_HINTS, low):
        s = _outside(s, _MARK, lambda p: _PREFIX.sub(lambda m: _b_withheld(m.group(), "token-shaped text", field), p))
    if "t10." in s or "iqn." in s:
        spans = _t10_hex_spans(s)
        if spans:
            s = _replace_spans(s, _merge(spans), "token-shaped text", field)
    return s


def _outside(text, pattern, fn):
    """`fn` applied to the parts of `text` that `pattern` does not match; the matches are kept as they are."""
    if "withheld" not in text:
        return fn(text)
    out, last = [], 0
    for m in pattern.finditer(text):
        out.append(fn(text[last:m.start()]) if m.start() > last else "")
        out.append(m.group())
        last = m.end()
    out.append(fn(text[last:]) if last < len(text) else "")
    return "".join(out)


def _layer2(s, field):
    out = s
    for _ in range(3):
        nxt = _layer2_once(out, field)
        if nxt == out:
            break
        out = nxt
    return out


# ---- free text: the deny-list ------------------------------------------------------------------------------------------------------
_LABELLED_DIGEST = re.compile(r"(?i)(?:md5|sha-?1|sha-?256|sha-?384|sha-?512|imphash|hashes?|filehash|ssdeep|tlsh)[\"'=:> \t]{1,6}(?:(?:md5|sha-?1|sha-?256|imphash)=)?([0-9a-f]{32,128})")
_TIME = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}:[0-9]{2}(?:[.,][0-9]{1,9})?(?:Z|[+-][0-9]{2}:?[0-9]{2})?")
_HEX_RUN = re.compile(r"(?<![0-9A-Za-z])[0-9A-Fa-f]{32,}(?![0-9A-Za-z])")


def _mask_typed(s):
    """A same-length copy of free text in which what is a typed id (GUID, SID, IPv4, time, labelled digest) is `~`."""
    t = s
    if "-" in s:
        t = _GUID.sub(lambda m: "~" * len(m.group()), t)
        if "S-1-" in s:
            t = _SID.sub(lambda m: "~" * len(m.group()), t)
        if ":" in s:
            t = _TIME.sub(lambda m: "~" * len(m.group()), t)
    if "." in s:
        t = _IPV4.sub(lambda m: "~" * len(m.group()), t)
    low = s.lower()
    if _has(_KNOWN_ID_WORDS, low):
        t = _KNOWN_ID.sub(lambda m: "~" * len(m.group()), t)
    if "ash" in low or "md5" in low or "sha" in low:
        t = _LABELLED_DIGEST.sub(lambda m: m.group().replace(m.group(1), "~" * len(m.group(1))), t)
    return t


def _deny_text(s, field):
    t = _mask_typed(s)
    t = t.replace("\x00", " ")
    spans = _bad_runs(t, _JOIN_PATH)
    spans += [m.span() for m in _HEX_RUN.finditer(t)]
    return _replace_spans(s, _merge(spans), "token-shaped text", field) if spans else s


# ---- the entry point for one string ---------------------------------------------------------------------------------------------------
_MEMO = {}


_WIDE_RUN = re.compile(r"[\x20-\x7e\uff01-\uff5e]{4,}")


def _wide_views(raw):
    """Runs of ASCII and full-width ASCII in `raw` read as UTF-8 and as UTF-16LE (at both byte offsets), when it holds a full-width character at
    all: width is folded afterwards (NFKC), so a full-width token written as hexadecimal is read like a plain one."""
    views = []
    if b"\xef\xbc" in raw or b"\xef\xbd" in raw:
        views += _WIDE_RUN.findall(raw.decode("utf-8", "replace"))
    if b"\xff" in raw:
        for offset in (0, 1):
            views += _WIDE_RUN.findall(raw[offset:len(raw) - (len(raw) - offset) % 2].decode("utf-16-le", "replace"))
    return [unicodedata.normalize("NFKC", v) for v in views]


def _hex_views(s):
    """The printable views of binary data written as hex: Latin-1 runs of 6 or more, UTF-16LE and UTF-16BE runs of 4 or more, and the runs that hold
    full-width characters (UTF-8 and UTF-16LE), width folded."""
    try:
        raw = bytes.fromhex(s[: MAX_HEX_JUDGED])
    except ValueError:
        return None
    views = [m.group().decode("latin-1") for m in re.finditer(rb"[\x20-\x7e]{6,}", raw)]
    views += [m.group().decode("utf-16-le", "replace") for m in re.finditer(rb"(?:[\x20-\x7e]\x00){4,}", raw)]
    views += [m.group().decode("utf-16-be", "replace") for m in re.finditer(rb"(?:\x00[\x20-\x7e]){4,}", raw)]
    return views + _wide_views(raw)


def _show_hex(s, field):
    if not s or not re.fullmatch(r"(?:[0-9A-Fa-f]{2})+", s):
        return s if re.fullmatch(r"[0-9A-Fa-f]*", s) else _show_text(s, field)
    if len(s) > MAX_HEX_JUDGED:
        return _b_withheld(s, "binary data over the judged size", field)
    for v in _hex_views(s) or ():
        if _layer2(v, "") != v or _deny_text(v, "") != v or _suspect(v):
            return _b_withheld(s, "binary data holding a secret-shaped text", field)
    return s


def _show_text(s, field):
    # layer 2 reads the string as the evidence wrote it: the deny-list replaces a span and takes with it the context (`user:` of `user:pw@host`, the
    # characters glued before `glpat-`) the position and prefix rules need; what it leaves is read once more
    out = _layer2(s, field)
    denied = _deny_text(out, field)
    return _layer2(denied, field) if denied != out else out


def _show(s, kind, field):
    if s in OWN_NAMES or _MARK.fullmatch(s):
        return s
    if len(s) > MAX_ONE_STRING:
        return _show(s[:MAX_ONE_STRING], kind, field) + _b_withheld(s[MAX_ONE_STRING:], "rest of a long string", field)
    if kind == "id":
        if len(s) <= 3 or _CONTENT_ID.fullmatch(s):
            return s
        for form in _ID_FORMS:
            if _TYPED[form].fullmatch(s) and not (form in _NAMING_IDS and s[:4] in ("t10.", "iqn.") and _bad_runs(s, _JOIN_NAME)):
                return s
        kind = "name"
    if kind in _TYPED:
        if len(s) <= 3 or (_TYPED[kind].fullmatch(s) and not (kind in _NAMING_IDS and s[:4] in ("t10.", "iqn.") and _bad_runs(s, _JOIN_NAME))):
            return s
        return _b_withheld(s, "not a %s" % kind, field)
    if kind == "hex":
        return _show_hex(s, field)
    flat = _flat(s)
    if flat != s:
        # an invisible character, or the escape of one: identifiers fail closed; free text is judged without it
        if kind in ("name", "path", "key", "url"):
            return _b_withheld(s, "invisible characters in a name", field)
        sealed = _show_text(flat, field)
        return sealed if sealed != flat else s
    if kind not in ("name", "path", "key", "url", "host"):
        return _show_text(s, field)
    pre = _layer2(s, field)
    if kind == "name":
        base = _show_name(pre, field)
    elif kind == "path":
        base = _show_path(pre, field)
    elif kind == "key":
        base = _show_key(pre, field)
    elif kind == "url":
        base = _show_url(pre, field)
    else:
        base = _show_host(pre, field)
    return _layer2(base, field) if base != pre else base


def show(s, kind="text", field=""):
    """The text the answer may show for the string `s` of a field of type `kind` (a T carries its own)."""
    if not isinstance(s, str) or not s:
        return s
    kind = getattr(s, "kind", kind)
    memo = (kind, field, s) if len(s) <= 512 and kind not in _TYPED else None            # (a typed id is judged by one match: it is not worth a place in the memo)
    quiet = _QUIET[0]
    if memo is not None:
        hit = _MEMO.get(memo)
        if hit is not None:
            out, pending = hit
            if pending and not quiet:
                # judged earlier only to see what would be printed: it is withheld, counted and written to the values file now that it is printed (once)
                for original, label, where in pending:
                    _b_withheld(original, label, where)
                _MEMO[memo] = (out, None)
            return out
    events = _EVENTS[0] = [] if quiet and memo is not None else None
    try:
        out = _show(str(s), kind, field)
    finally:
        _EVENTS[0] = None
    if memo is not None:
        if len(_MEMO) > 40000:
            _MEMO.clear()
        _MEMO[memo] = (out, events or None)
    return out


_ORDER_SALT = os.urandom(16)


def _quietly(fn):
    """`fn()` with nothing counted, listed or written: judging a string to see what an answer would show of it is not withholding it."""
    saved = (BOUNDARY["withheld"], BOUNDARY["by"].copy(), BOUNDARY["replaced"], BOUNDARY["replaced_by"].copy(), BOUNDARY["where"][:], BOUNDARY["not_listed"], _VALUES["fh"])
    _VALUES["fh"] = None
    was, _QUIET[0] = _QUIET[0], True
    try:
        return fn()
    finally:
        _QUIET[0] = was
        (BOUNDARY["withheld"], BOUNDARY["by"], BOUNDARY["replaced"], BOUNDARY["replaced_by"], BOUNDARY["where"], BOUNDARY["not_listed"], _VALUES["fh"]) = saved


def sealed_text(text, kind="text", field=""):
    """The exact text an answer prints for the string `text` of a field of type `kind`: the layers, then the backstop (a string it replaces comes
    out as its placeholder). Nothing is counted, listed or written to the values file: this is for what must see what the answer shows (a
    `contains` filter, the order of a list)."""
    if not isinstance(text, str) or not text:
        return text
    return _quietly(lambda: _seal(text, kind, field, (), True))


def print_order(items, kind="name", text=str):
    """`items` in the order an answer prints them: by the text the answer PRINTS for each (the layers and the backstop, sealed_text), and the items
    whose text is the same placeholder in a random order that is new for every run. The rank of the withheld texts themselves (the order `sorted`
    would give, the order a directory or a hive lists them in) must never show in what an answer lists. `kind` is the kind of the field the items
    are printed in; `text` gives the string of an item."""
    def judge():
        out = []
        for n, i in enumerate(items):
            raw = text(i)
            shown = _seal(raw, kind, "", (), True) if isinstance(raw, str) and raw else raw
            out.append((shown, hashlib.blake2b(_ORDER_SALT + raw.encode("utf-8", "surrogatepass"), digest_size=8).digest(), n, i))
        return out
    items = list(items)
    keyed = _quietly(judge)
    keyed.sort(key=lambda k: (k[0], k[1], k[2]))
    return [k[3] for k in keyed]


def contains_check(needle_lower, text, kind="text", field=""):
    """(matched, blind) for a `contains` filter: the needle is looked for in the text the answer will PRINT for `text` (sealed_text: after the layers
    AND the backstop), never in what either of them withheld or replaced, so that a count of matches cannot tell a true guess of a hidden piece from
    a wrong one. `blind` is true when it was not found and that text holds a placeholder: the needle may be in what is hidden. It is the same
    whatever the needle, so counting it opens no way to test a guess."""
    sealed = sealed_text(text, kind, field)
    if needle_lower in sealed.lower():
        return True, False
    return False, _MARK.search(sealed) is not None


# ---- layer 3: the backstop, written apart from the layers above ------------------------------------------------------------------------
_S_ESC = re.compile(r"(?<!\\)\\+(?:u([0-9a-fA-F]{4})|U([0-9a-fA-F]{8})|[uU]\{([0-9a-fA-F]{1,8})\}|x([0-9a-fA-F]{2}))")
_S_FILL = "\u115f\u1160\u3164\uffa0\u2800"


def _s_gone(c):
    cat = unicodedata.category(c)
    return cat[0] == "C" or cat in ("Mn", "Me", "Zl", "Zp") or c in _S_FILL


def _s_unesc(m):
    try:
        c = chr(int(m.group(1) or m.group(2) or m.group(3) or m.group(4), 16))
    except (ValueError, OverflowError):
        return m.group(0)
    return "" if _s_gone(c) else m.group(0)


def _s_normal(text):
    if "\\u" in text or "\\U" in text or "\\x" in text:
        text = _S_ESC.sub(_s_unesc, text)
    if text.isascii() and text.isprintable():
        return text
    kept = [c for c in text if not _s_gone(c)]
    return unicodedata.normalize("NFKC", "".join(kept))


_S_PEM = re.compile(r"-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY|PRIVATE KEY-----")
_S_DELIM = re.compile(r"[=:]")
_S_NAME_WORDS = ("pass", "pw", "auth", "sig", "sas", "secret", "token", "credential", "key", "psk", "otp", "bearer", "community", "dsn", "pin", "connection_string", "webhook_url")        # a name that ends in a word of _S_STRONG or _S_WEAK holds one of these
_S_FLAGWORD = (r"(?:[a-z0-9]{1,20}[-_]){0,4}(?:passw(?:or)?d|passwd|pass(?:[-_]?phrase)?|pwd|pw|otp|[a-z0-9]{0,20}secret[a-z0-9]{0,20}|[a-z0-9]{0,20}token|api[-_]?key|access[-_]?key|key|keypass|storepass|userpass|auth|authorization|bearer|psk|credentials?|community)")
_S_FLAGCAMEL = r"[A-Za-z0-9]{1,20}(?-i:Key|Token|Password|Passwd|Pwd|Pass|Passphrase|Secret)"
_S_NOVALUE = r"(?!<[^<>\s]{0,40}>(?:[\s;,]|$))(?![A-Za-z0-9_./~:-]{1,120}[.](?i:key|pem|pub|crt|p12|pfx|jks)(?![A-Za-z0-9]))(?!(?:~|[.]{1,2})/[A-Za-z0-9_./-]{1,120}|/[A-Za-z0-9_.-]{1,40}(?:/[A-Za-z0-9_.-]{1,40})+)"
_S_ARGNAME = re.compile(r"(?<![A-Za-z0-9])--?(?i:" + _S_FLAGWORD + r")[= ]" + _S_NOVALUE + r"\S|(?<![A-Za-z0-9])--?" + _S_FLAGCAMEL + r"[= ]" + _S_NOVALUE + r"\S")
_S_PREFIX_WORDS = ("akia", "asia", "agpa", "aida", "aroa", "anpa", "anva", "aipa", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_", "glpat-", "xox", "xapp-",
                   "sk_live_", "rk_live_", "pk_live_", "sk_test_", "npm_", "pypi-", "shpat_", "dop_v1_", "aiza", "ya29.", "sg.", "sk-", "eyj")
_S_LINE = re.compile(r"[ \t]*line[ \t]+[0-9]")
_S_NAME_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-")
_S_STRONG = ("password", "passwd", "passphrase", "passw", "pwd", "secret", "token", "credential", "apikey", "api_key", "api-key", "accesskey", "access_key", "access-key",
             "accountkey", "account_key", "account-key", "privatekey", "private_key", "private-key", "masterkey", "master_key", "sharedkey", "shared_key", "signingkey", "encryptionkey",
             "secretkey", "secret_key", "secret-key")
_S_WEAK = ("pass", "pw", "auth", "sig", "sas")
_S_NOT_PASS = ("bypass", "compass", "overpass", "underpass", "trespass", "encompass", "surpass", "impass")
_S_STRONG_ENDS = tuple(w + p for w in _S_STRONG for p in ("", "s"))       # a name that ends in one of these, or in one of them plural
_S_WEAK_ENDS = tuple(w + p for w in _S_WEAK for p in ("", "s"))
_S_NOT_PASS_ENDS = tuple(w + p for w in _S_NOT_PASS for p in ("", "s"))
_S_VALUEY_ENDS = ("psk", "otp", "bearer", "authorization", "sshkey", "ssh_key", "ssh-key", "snmp_community", "pass_word", "pass-word", "connection_string", "webhook_url", "dsn", "pin")        # names after which only a value built like a secret counts (a log line says `authorization: failed`)
_S_DIGITS = re.compile(r"[0-9]{19}")
_S_HEXRUN = re.compile(r"(?<![0-9A-Za-z])[0-9A-Fa-f]{40,}(?![0-9A-Za-z])")
_S_B64NOPAD = re.compile(r"[A-Za-z0-9+/]{20,}")
_S_B64PADPATH = re.compile(r"[A-Za-z0-9+/]{22,90}={1,2}(?![A-Za-z0-9+=])")
_S_B64PAD = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{15,}={1,2}(?![A-Za-z0-9+=])")
# in any case where an upper-case spelling of a lower-case prefix is a likely leak (the vendors' prefixes with a body of 12 or more characters)
_S_PREFIX = re.compile(r"(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[A-Z0-9]{12}|(?i:(?<![A-Za-z0-9])(?:akia|asia)[a-z0-9]{12}|(?:gh[pousr]_|github_pat_|glpat-|xox[a-z]-|xapp-|sk_live_|rk_live_|pk_live_|sk_test_)[A-Za-z0-9_-]{12})"
                       r"|(?:npm_|pypi-|shpat_|dop_v1_|AIza|ya29\.|SG\.)[A-Za-z0-9_-]{12}|sk-(?=[A-Za-z0-9_-]{0,39}[0-9])[A-Za-z0-9_-]{12}|eyJ[A-Za-z0-9_-]{12}")
_S_TOKEN_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-")
_S_PWHOST = re.compile(r"(?<![A-Za-z0-9._%+-])([A-Za-z0-9]{12,64})@[^\s/@<>\"']")
_S_USERINFO = re.compile(r"[^\s/@:<>\"']{1,64}:(?P<pw>[^\s/<>\"']{1,128})@[^\s/@<>\"']")
_S_USERINFO_MARK = re.compile(r"<>:(?P<pw>[^\s/<>\"']{1,128})@[^\s/@<>\"']")
_S_USERINFO_URL = re.compile(r"(?<=//)(?![^\s/@:<>\"']*:[0-9]{1,5}(?:[/?#@]|$))[^\s/@:<>\"']{1,64}:(?P<pw>[^\s<>\"']{1,128})@[^\s/@<>\"']")
_S_VALUE = re.compile(r"(?:[^\s\"'<>;,&]|[;,&](?![A-Za-z0-9_. -]{1,40}=)){1,512}")
_S_ARGVAL = re.compile(r"(?<![A-Za-z0-9])--?(?:(?i:" + _S_FLAGWORD + r")|" + _S_FLAGCAMEL + r")[= ]" + _S_NOVALUE + r"(\S{1,512})")
# `set password x` and `enable secret x`, and a value glued behind a placeholder (password=<redacted>x, --password <redacted>x, token: <secret>x)
_S_PH_SPACE = re.compile(r"(?:pass|pwd|secret|token|credential|key|auth|psk|otp|pw|sig|sas)[a-z]{0,10}[0-9]{0,2}[\"']?[ \t]{0,2}(?:[=:]|[ \t])[ \t]{0,2}<[^<>\s]{0,40}>[ \t]+([A-Za-z0-9]{8,40})(?![A-Za-z0-9])", re.I)
_S_GLUED = re.compile(r"(?<![A-Za-z0-9])--?(?:[A-Za-z0-9]{1,20}[-_]){0,4}(?:(?i:key|token|pass|password|pwd|secret)|[A-Za-z]{1,20}(?:Key|Token|Pass|Password|Pwd|Secret))([A-Za-z0-9]{8,40})(?![A-Za-z0-9])")
_S_AUTHZ = re.compile(r"(?i:authorization)[\"']?[ \t]{0,2}[=:][ \t]{0,2}[\"']?(?i:token|bearer|basic|negotiate)[ \t]+[A-Za-z0-9+/._~=-]{8,}")
_S_T10TAIL = re.compile(r"t10[.][A-Za-z0-9_.+-]{0,100}?_([A-Za-z]{20,64})(?![A-Za-z0-9])|iqn[.][0-9]{4}-[0-9]{2}[.][a-z0-9.-]{1,60}:([A-Za-z]{20,64})(?![A-Za-z0-9])|iqn[.][0-9]{4}-[0-9]{2}[.]([A-Za-z]{20,64})(?![A-Za-z0-9])")
_S_SET = re.compile(r"(?<![\w-])(?:set|enable)[ \t]+(?:passw(?:or)?d|secret|passphrase|token)[ \t]+(?:[0-9][ \t]+)?[^\s<]", re.I)
_S_ANGLE = re.compile(r"(?:pass|pwd|secret|token|credential|key|auth|psk|otp|pw|sig|sas)[a-z]{0,10}[0-9]{0,2}[\"']?[ \t]{0,2}(?:[=:]|[ \t])[ \t]{0,2}<([A-Za-z0-9+/_.~=-]{6,128})>", re.I)
_S_PH_GLUED = re.compile(r"(?:pass|pwd|secret|token|credential|key|auth|psk|otp|pw|sig|sas)[a-z]{0,10}[0-9]{0,2}[\"']?[ \t]{0,2}(?:[=:]|[ \t])[ \t]{0,2}<[^<>\s]{0,40}>[^\s<>;,&\"']", re.I)
_S_PEMLINE = re.compile(r"[A-Za-z0-9+/=]{12,}")
_S_SHORTRUN = re.compile(r"[A-Za-z0-9]{16,19}")
_S_RUN = re.compile(r"[A-Za-z0-9+/_-]{20,}")
_S_HEX = re.compile(r"[0-9A-Fa-f-]+")
_S_IDS = re.compile(r"\{?[0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}\}?|[0-9A-Fa-f]{8}-[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}|S-1-[0-9]{1,2}(?:-[0-9]{1,10}){1,15}|[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9:.]+Z?")
_S_MARK = re.compile(r"<withheld [0-9]{1,10} (?:characters|bytes)(?:: [a-z][a-z ,/+-]{0,60}(?:: [a-z][a-z ,/+-]{0,60})?)?>|\[withheld: [0-9]{1,10} (?:characters|bytes)\]")
_S_DIGEST_LABEL = re.compile(r"(?i)(?:md5|sha-?1|sha-?256|sha-?384|sha-?512|imphash|hashes?|filehash|ssdeep|tlsh)[\"'=:> \t]{1,6}(?:(?:md5|sha-?1|sha-?256|imphash)=)?[0-9a-f]{32,128}")
_TYPED_KINDS = frozenset(("guid", "digest", "sid", "mac", "ip", "time", "number", "version", "hex", "label", "vmfs", "device", "iqn", "vmuuid", "cid", "winhost"))
# what a typed field may hold, by the characters of its type (apart from the grammar the first layer checks, and wider than it)
_S_TYPED = {
    "guid": re.compile(r"[0-9A-Fa-f{}-]{1,64}"), "sid": re.compile(r"[Ss0-9-]{1,400}"), "mac": re.compile(r"[0-9A-Fa-f:-]{1,64}"),
    "ip": re.compile(r"[0-9A-Fa-f:.]{1,64}(?:%[0-9A-Za-z_.-]{1,16})?"), "time": re.compile(r"[0-9TtZzDd:.,+' -]{1,64}"),
    "number": re.compile(r"-?[0-9.]{1,64}|0[xX][0-9A-Fa-f]{1,16}|true|false|null"), "version": re.compile(r"(?=.{1,64}\Z)[vV]?[0-9]+(?:\.[0-9A-Za-z]{1,16}){0,6}(?:[-+][0-9A-Za-z.]{1,32}){0,3}"),
    "digest": re.compile(r"(?:sha256:|sha1:|md5:)?[0-9A-Fa-f]{16,128}|T1[0-9A-Fa-f]{16,80}|[0-9]{1,6}:[A-Za-z0-9+/]+:[A-Za-z0-9+/]+"),
    "vmfs": re.compile(r"[0-9A-Fa-f-]{1,40}"), "cid": re.compile(r"[0-9A-Fa-f]{1,16}"), "vmuuid": re.compile(r"[0-9A-Fa-f -]{1,64}"),
    "winhost": re.compile(r"[Ww][Ii][Nn]-[A-Za-z0-9]{1,16}"), "iqn": re.compile(r"iqn\.[0-9A-Za-z.:_-]{1,120}"),
    "device": re.compile(r"(?:naa|eui|vml|t10)\.[A-Za-z0-9_.+-]{1,130}|wwn-0x[0-9A-Fa-f]{1,32}"),
}
_S_LONG = re.compile(r"[A-Za-z0-9+/_-]{19}")           # the shortest run any check below needs (19 digits); the hexadecimal run needs 40, the others 20
_S_PLAIN_NUM = re.compile(r"[0-9TZ:.+ -]+")
_S_HEXONLY = re.compile(r"(?:[0-9A-Fa-f]{2})+")
_S_PRINT_L1 = re.compile(rb"[\x20-\x7e]{6,}")
_S_PRINT_U16 = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")
_S_PRINT_U16BE = re.compile(rb"(?:\x00[\x20-\x7e]){4,}")


def _class(c):
    return 0 if c.isdigit() else 1 if c.isupper() else 2


def _random_run(run, shortest=20):
    if _S_HEX.fullmatch(run):
        return False
    pieces = [p for p in re.split(r"[/_+-]", run) if p]
    alnum = "".join(pieces)
    if len(alnum) < shortest or max(len(p) for p in pieces) < 12:
        return False
    kinds = {_class(c) for c in alnum}
    if len(kinds) < 2:
        return False
    lower = [len(r) for r in re.findall(r"[a-z]+", alnum)]
    if lower and sum(lower) >= 3 * len(lower) and not re.search(r"[A-Z]{2}", alnum):
        return False
    changes = sum(1 for a, b in zip(alnum, alnum[1:]) if _class(a) != _class(b)) / (len(alnum) - 1)
    digit_runs = len(re.findall(r"[0-9]+", alnum))
    if kinds == {0, 1, 2}:
        return changes >= 0.42 or (changes >= 0.3 and digit_runs >= 4 and len(set(alnum)) >= 0.6 * len(alnum))
    if kinds == {1, 2}:
        return changes >= 0.5 and len(alnum) >= 24
    return changes >= 0.4 and digit_runs >= 5 and len(set(alnum)) >= 0.5 * len(alnum)


def _s_letters_random(word):
    """Letters of one case that no word is made of: some pair of them is one that words do not hold (the second check's own test of the serial of a t10. id and the target of an iqn. name)."""
    if not (word.islower() or word.isupper()):
        return False
    low = word.lower()
    return any(low[k:k + 2] not in _BIGRAMS for k in range(len(low) - 1))


def _s_valuey(tok):
    """Whether a run after a placeholder is built like a secret (the second check's own test): a digit among letters that is not a counter at the end, 8 or more digits, or letters with a pair no word holds."""
    body = tok.rstrip("0123456789")
    if not body:
        return len(tok) >= 8
    if len(tok) - len(body) > 4 or any(c.isdigit() for c in body):
        return True
    low = body.lower()
    return any(low[k:k + 2] not in _BIGRAMS for k in range(len(low) - 1)) or re.search("[^aeiouy]{4}", low) is not None


def _s_named(flat, values=None):
    """Whether `flat` holds a value after a secret's name; with a list, the values themselves are added to it (until it holds MAX_PIECES)."""
    pos, found = 0, False
    while True:
        m = _S_DELIM.search(flat, pos)
        if not m or (values is not None and len(values) >= MAX_PIECES):
            return found
        i = m.start()
        pos = m.end()
        after = flat[i + 1:i + 6].lstrip(" \t\"'\\")
        if not after or after[0] in "<>" or _S_LINE.match(flat, i + 1):
            continue
        j = i
        while j > 0 and flat[j - 1] in " \t\"'\\" and i - j < 5:
            j -= 1
        k = j
        while k > 0 and j - k < 64 and flat[k - 1] in _S_NAME_CHARS:
            k -= 1
        low = flat[k:j].lower()
        if low.endswith(_S_STRONG_ENDS) or (low.endswith(_S_WEAK_ENDS) and not low.endswith(_S_NOT_PASS_ENDS)):
            if values is None:
                return True
            found = True
            v = i + 1
            while v < len(flat) and flat[v] in " \t\"'\\" and v - i <= 6:
                v += 1
            vm = _S_VALUE.match(flat, v)
            if vm:
                values.append(vm.group())
        elif low.rstrip("0123456789").endswith(_S_VALUEY_ENDS) or low.rstrip("0123456789").endswith(_S_STRONG_ENDS):
            v = i + 1
            while v < len(flat) and flat[v] in " \t\"'\\" and v - i <= 6:
                v += 1
            vm = _S_VALUE.match(flat, v)
            if vm and _s_valuey(vm.group()):
                if values is None:
                    return True
                found = True
                values.append(vm.group())


def _s_hex_views(text):
    """The printable text inside data written as hexadecimal (Latin-1 runs of 6 or more, UTF-16LE and UTF-16BE runs of 4 or more), or None when `text` is not such data."""
    if len(text) < 2 or not _S_HEXONLY.fullmatch(text[:MAX_HEX_JUDGED]):
        return None
    try:
        raw = bytes.fromhex(text[:MAX_HEX_JUDGED])
    except ValueError:
        return None
    return ([m.group().decode("latin-1") for m in _S_PRINT_L1.finditer(raw)] + [m.group().decode("utf-16-le", "replace") for m in _S_PRINT_U16.finditer(raw)]
            + [m.group().decode("utf-16-be", "replace") for m in _S_PRINT_U16BE.finditer(raw)] + _wide_views(raw))


def _suspect(text, kind="text"):
    """The name of the check a string fails, or None. A string of a typed kind is not tested for runs of hexadecimal digits or random-looking runs, but
    for the characters of its type; data written as hexadecimal is decoded and its printable text is tested as text."""
    if not text or text in OWN_NAMES:
        return None
    if len(text) > MAX_ONE_STRING:
        text = text[:MAX_ONE_STRING]
    if kind == "hex":
        views = _s_hex_views(text)
        if views is not None:
            for view in views:
                hit = _suspect(view, "text")
                if hit:
                    return "in binary data: " + hit
            return None
        kind = "text"
    if kind in _S_TYPED and len(text) <= 64 and _S_PLAIN_NUM.fullmatch(text):
        # digits, `. : + -`, a space, T and Z: no rule above the typed grammar can fire on these (no name, no prefix, no `@`), so the grammar alone decides
        return None if len(text) <= 3 or _S_TYPED[kind].fullmatch(text) else "not the typed grammar"
    flat = _s_normal(text)
    if "withheld" in flat:
        flat = _S_MARK.sub("<>", flat)
    low = flat.lower()
    if "private key" in low and _S_PEM.search(flat):
        return "a PEM marker"
    bare = _S_IDS.sub(" ", flat) if "-" in flat else flat            # (all three kinds of id hold a `-`)
    bare = _mask_embedded(bare)
    named_words = _has(_S_NAME_WORDS, low)
    if named_words and _S_AUTHZ.search(flat):
        return "a named secret"
    if (named_words and ("=" in bare or ":" in bare) and _s_named(bare)) or ("-" in flat and named_words and _S_ARGNAME.search(flat))             or (named_words and "-" in flat and any(_s_valuey(m.group(1)) for m in _S_GLUED.finditer(flat)))             or (named_words and ("<" in flat and (_S_PH_GLUED.search(flat) or any(_s_valuey(x) for m in _S_ANGLE.finditer(flat) for x in _ANGLE_SPLIT.split(m.group(1))) or any(_s_valuey(m.group(1)) for m in _S_PH_SPACE.finditer(flat))) or ("set" in low or "enable" in low) and _S_SET.search(flat))):
        return "a named secret"
    if _has(_S_PREFIX_WORDS, low) and _S_PREFIX.search(flat):
        return "a token prefix"
    if ("t10." in flat or "iqn." in flat) and any(_s_letters_random(m.group(1) or m.group(2) or m.group(3)) for m in _S_T10TAIL.finditer(flat)):
        return "a random-looking run"
    if "@" in flat:
        flat_user = re.sub("(?i)mailto:", "mailto ", flat)
        if _S_USERINFO.search(flat_user) or _S_USERINFO_URL.search(flat_user) or _S_USERINFO_MARK.search(flat_user):       # (the last: a user that was replaced is still a user)
            return "user-info"
        for m in _S_PWHOST.finditer(flat_user):
            word = m.group(1)
            if len({_class(c) for c in word}) == 3 and sum(1 for a, b2 in zip(word, word[1:]) if _class(a) != _class(b2)) >= 0.3 * len(word):
                return "user-info"            # (the password of a user-info whose user was cut off at a colon: a long run of capitals, small letters and digits before the host)
    if kind in _TYPED_KINDS:
        grammar = _S_TYPED.get(kind)
        return "not the typed grammar" if grammar is not None and len(text) > 3 and not grammar.fullmatch(text) else None
    if 16 <= len(bare) <= 19 and _S_SHORTRUN.fullmatch(bare) and _random_run(bare, 16):
        return "a random-looking run"          # (a whole value of 16 to 19 characters: the length of a generated password, as the first layer takes it too)
    if "=" not in bare and not _S_LONG.search(bare):
        return None                       # no run of 19 characters of these, and no `=` for a padded run: none of the checks below can find anything
    if _S_DIGITS.search(bare):
        return "a long digit run"
    labelled = _S_DIGEST_LABEL.sub(" ", bare) if "ash" in low or "sha" in low or "md5" in low else bare
    if _S_HEXRUN.search(labelled):
        return "a long hexadecimal run"
    for m in _S_B64NOPAD.finditer(labelled):
        if "/" in m.group() and "+" in m.group() and len({_class(c) for c in m.group() if c.isalnum()}) == 3:
            return "a base64 run with / and +"
    for m in _S_B64PAD.finditer(labelled):
        body = m.group().rstrip("=")
        if len(m.group()) % 4 == 0 and re.search(r"[0-9+/]", body) and len({_class(c) for c in body}) >= 2 and (("/" in body or "+" in body) or len(body) >= 20):
            return "a padded base64 run"
    if "=" in labelled:
        for m in _S_B64PADPATH.finditer(labelled):
            # a padded key behind the `/` of a path (inputs/Zk0khEa1Ge/Do3O4Hd43iH==): the key is the last 22 (two pads) or 27 (one pad) characters before the padding
            pad = len(m.group()) - len(m.group().rstrip("="))
            tail = m.group().rstrip("=")[-(22 if pad == 2 else 27):]
            if len(tail) >= 22 and "/" in tail and len({_class(c) for c in tail if c.isalnum()}) >= 2:
                return "a padded base64 run"
    for m in _S_RUN.finditer(labelled):
        if _random_run(m.group()):
            return "a random-looking run"
    return None


def _where_text(where, names=True):
    return "/" + "/".join((w[0][:60] if names else str(w[1])) for w in where)


def _replace(value, where, check, positions=False):
    BOUNDARY["replaced"] += 1
    BOUNDARY["replaced_by"][check] += 1
    if len(BOUNDARY["where"]) < MAX_WHERE:
        # the place is the keys on the way, each of them already sealed; their joining is read once more, and when it is not clean the place is the
        # positions (a key that was replaced or withheld must never come back whole through the report of where something was replaced)
        at = _where_text(where, False) if positions else _where_text(where)
        if not positions and _suspect(at, "label"):
            at = _where_text(where, False)
        BOUNDARY["where"].append({"at": at, "check": check})
    else:
        BOUNDARY["not_listed"] += 1
    return _mark(len(value.encode("utf-8", "replace")), "backstop: %s" % check, "bytes")


_CHECKED = {}
_SHORT_PLAIN = re.compile(r"[A-Za-z0-9_.]{0,15}")      # what the late path may print unjudged: 15 characters or fewer of letters, digits, `_` and `.` (no space, no `-`, so no
                                                          # argument after a flag and no `xox?-` token), and not starting like a vendor token (_unjudged)


def _unjudged(text, kind=None):
    """Whether a string may be printed past the judging time: a name this run made itself (OWN_NAMES: its schema keys, its file names), or a short plain
    string that does not start like one of the vendor tokens the block knows (a prefix and 12 characters are 15) and, in a field of a typed kind (a SID, a
    GUID, a digest ...), fits the grammar of that type as the backstop checks it."""
    if text in OWN_NAMES:
        return True
    if _SHORT_PLAIN.fullmatch(text) is None or text.lower().startswith(_S_PREFIX_WORDS):
        return False
    grammar = _S_TYPED.get(kind)
    return grammar is None or len(text) <= 3 or grammar.fullmatch(text) is not None


def _late(n=0):
    """Whether judging must stop for the string about to be judged, which has `n` characters (counted against the cap of the run, unless the string is
    only being judged to see what an answer would print). It says why, once, in _STOP["by"]: the cap of characters, or the clock of the seal."""
    if n and not _QUIET[0]:
        _STOP["chars"] += n
        if _STOP["chars"] > _STOP["cap"]:
            if _STOP["by"] is None:
                _STOP["by"] = "the cap of %d characters judged in one run" % MAX_JUDGED_CHARS
            return True
    deadline = _CLOCK["deadline"]
    if deadline is not None and time.monotonic() > deadline:
        if _STOP["by"] is None:
            _STOP["by"] = "the judging time (the budget of one answer or row, or the seal stop of the tool)"
        return True
    return False


def _stopped(value, where):
    """A string not judged because judging stopped: withheld whole, by its size, counted (what is let through is only _unjudged)."""
    if not _QUIET[0]:
        _STOP["strings"] += 1
    return _replace(value, where, "the judging time ran out", True)


def seal_stop_after(seconds):
    """The seal stop of a tool: no seal runs on past `seconds` from now (its manifest's time limit less 3.5 seconds); what is left is withheld whole,
    except what _unjudged lets through. It stops the judging only, not the tool's own work: that has its own clock, which must run out first."""
    _CLOCK["stop"] = time.monotonic() + seconds


def _timed(fn):
    """`fn()` with the clock of the seal running: SEAL_BUDGET seconds from the outermost call, and never past the seal stop of the tool."""
    first = _CLOCK["deadline"] is None
    if first:
        _CLOCK["deadline"] = time.monotonic() + SEAL_BUDGET
        if _CLOCK["stop"] is not None:
            _CLOCK["deadline"] = min(_CLOCK["deadline"], _CLOCK["stop"])
    try:
        return fn()
    finally:
        if first:
            _CLOCK["deadline"] = None


# the name of a component of the Windows component store (WinSxS), as a whole name or as a component of a key or a path: architecture, words (lower case, letters up
# to 40 or letters and digits up to 16, with `.`, `-` or `_` between them, never a hexadecimal hash), the 16-digit public key token, a four-part version (not always
# there), a language or `none`, and a hash of 8 to 16 hexadecimal digits; a placeholder that layer 1 put in the place of a word, or of the architecture and a word (a
# 32-digit hash), stands for it. A real SOFTWARE hive lists them by the thousand and the backstop took their hash for a random run, so it judges the text with such a
# component taken out; layer 1 judges them as it does every name. Names, keys and paths only, lower case only; every alternative starts with a different character,
# so that a failing match is not retried in a second way.
_WORD = r"(?:[a-z]{1,40}|(?=[a-z0-9]*[0-9])[a-z0-9]{1,16}|<withheld [0-9]{1,10} (?:characters|bytes): not a plain name>)"
_WINSXS = re.compile(r"(?<![^\\/])(?:(?:amd64|x86|wow64|msil|arm64|arm|ia64)_(?![0-9a-f]+_)%s(?:[._-]{1,3}%s){0,12}|<withheld [0-9]{1,10} (?:characters|bytes): not a plain name>)"
                     r"_[0-9a-f]{16}(?:_[0-9]{1,5}(?:\.[0-9]{1,5}){3})?_[a-z0-9-]{2,12}_[0-9a-f]{8,16}(?![^\\/])" % (_WORD, _WORD))


def _without_components(text, kind):
    """`text` as the backstop judges a name, key or path: a component of the component store is one plain word."""
    return _WINSXS.sub("w", text) if kind in ("name", "key", "path") and text.count("_") >= 3 else text


def _verdict(text, kind):
    memo = (kind, text) if len(text) <= 512 and kind not in _S_TYPED else None
    hit = _CHECKED.get(memo, False) if memo else False
    if hit is False:
        hit = None if _MARK.fullmatch(text) else _suspect(_without_components(text, kind), kind)
        if memo:
            if len(_CHECKED) >= 30000:
                _CHECKED.clear()
            _CHECKED[memo] = hit
    return hit


# ---- the backstop reads the original too: what of a secret-shaped text is still in what was shown
def _pem_pieces(flat, found):
    """The base64 lines of the bodies of PEM keys: after each `PRIVATE KEY-----` (found with str.find, at most MAX_PIECES of them) up to the next
    `-----END` or MAX_PEM_BODY characters."""
    pos, bodies = 0, 0
    while bodies < MAX_PIECES and len(found) < MAX_PIECES:
        i = flat.find("PRIVATE KEY-----", pos)
        if i < 0:
            return
        start = i + 16
        end = flat.find("-----END", start, start + MAX_PEM_BODY)
        stop = start + MAX_PEM_BODY if end < 0 else end
        bodies += 1
        for m in _S_PEMLINE.finditer(flat, start, stop):
            found.append(m.group())
            if len(found) >= MAX_PIECES:
                return
        pos = max(stop, start)


def _s_pieces(flat, kind):
    """The parts of `flat` (the original text, normalised) the backstop's own rules call secret: a value after a secret's name, the password of
    user-info, a vendor token, a key's base64, and (outside typed fields) the long random-looking runs. At most MAX_PIECES of them, in this
    order; every walk over the text stops when the list is full."""
    found = []
    bare = _S_IDS.sub(" ", flat)
    _s_named(bare, found)
    for pattern, group in ((_S_ARGVAL, 1), (_S_USERINFO, "pw"), (_S_USERINFO_URL, "pw")):
        for m in pattern.finditer(flat):
            if len(found) >= MAX_PIECES:
                return found
            found.append(m.group(group))
    for m in _S_PREFIX.finditer(flat):
        if len(found) >= MAX_PIECES:
            return found
        end = m.end()
        stop = min(len(flat), end + 512)
        while end < stop and flat[end] in _S_TOKEN_CHARS:
            end += 1
        found.append(flat[m.start():end])
    _pem_pieces(flat, found)
    if kind not in _TYPED_KINDS:
        labelled = _S_DIGEST_LABEL.sub(" ", bare) if "ash" in bare or "sha" in bare.lower() or "md5" in bare.lower() or "ASH" in bare else bare
        for m in _S_B64PAD.finditer(labelled):
            if len(found) >= MAX_PIECES:
                return found
            if _b64_shape(m.group()):
                found.append(m.group())
        for m in _S_HEXRUN.finditer(labelled):
            if len(found) >= MAX_PIECES:
                return found
            found.append(m.group())
        for m in _S_B64NOPAD.finditer(labelled):
            if len(found) >= MAX_PIECES:
                return found
            if "/" in m.group() and "+" in m.group():
                found.append(m.group())
        for m in _S_RUN.finditer(labelled):
            if len(found) >= MAX_PIECES:
                return found
            if _random_run(m.group()):
                found.append(m.group())
    return found


_RESIDUE = {}


def _residue_worthy(win):
    """Whether a window of a piece is a secret's and not the words of a path the piece ran into (a run of base64 characters takes in `/vmfs/volumes/ds1/` before a key): a window with a `/` needs 3 capitals, digits or `+`."""
    return "/" not in win or sum(1 for c in win if c.isupper() or c.isdigit() or c == "+") >= 3


def _residue(original, shown, kind):
    """A window of 12 characters (the whole piece when it is shorter, from 8) of something the backstop calls secret in the ORIGINAL that is still
    in what was shown: the layers above cut spans out of a string and can leave a piece of a secret between two cuts."""
    memo = (kind, original) if len(original) <= 512 else None
    if memo is not None and memo in _RESIDUE:
        return _RESIDUE[memo]
    verdict = None
    flat = _s_normal(original[:MAX_ONE_STRING])
    pieces = _s_pieces(flat, kind)[:MAX_PIECES]
    if pieces:
        kept = _S_MARK.sub("\x00", _s_normal(shown[:MAX_ONE_STRING]))
        rest = flat                                    # the original without those parts: a window that is also here is the text's own words, not the secret
        for piece in sorted(set(pieces), key=len, reverse=True):
            rest = rest.replace(piece, "\x00")
        for piece in pieces:
            n = len(piece)
            if n < 8:
                continue
            w = min(12, n)
            step = 1 if n * len(kept) <= 4000000 else max(1, (n - w + 1) // 64)       # a long piece in a long string: 64 windows, spread over it
            if any(piece[i:i + w] in kept and piece[i:i + w] not in rest and _residue_worthy(piece[i:i + w]) for i in range(0, n - w + 1, step)):
                verdict = "a part of a secret-shaped text"
                break
    if memo is not None:
        if len(_RESIDUE) >= 30000:
            _RESIDUE.clear()
        _RESIDUE[memo] = verdict
    return verdict


# ---- the walker ----------------------------------------------------------------------------------------------------------------------------
_SCALARS = (bool, int, float)
_SCALAR_TYPES = frozenset(_SCALARS)


_KEYS = {}


def _seal(value, kind, field, where, guard, fname=""):
    """`value` with every string sealed by the type of its field, and (guard) read back by the backstop. Keys are names. FIELDS maps a JSON key to the
    kind of what it holds, or to a function of the key of one item for a dict whose items have kinds of their own (event data, registry values).
    `where` is the tuple of (sealed key or position, position) on the way down."""
    if isinstance(value, str):
        k = getattr(value, "kind", kind)
        if _late(len(value)):
            # past the budget the rest is withheld whole, fail closed; what is let through is only a name of this run's own and a short plain string (_unjudged)
            return value if _unjudged(value, k) else _stopped(value, where)
        out = show(value, k, field)
        if guard:
            check = _verdict(out, k)
            if not check and out != value:
                check = _residue(str(value), out, k)
            if check:
                return _replace(out, where, check)
        return out
    if value is None or isinstance(value, _SCALARS):
        return value
    if isinstance(value, dict):
        hook = _field_entry(fname)
        hook = hook if callable(hook) else None
        kk = KEY_KINDS.get(fname, "name")
        out, dupes = {}, {}
        for idx, (key, v) in enumerate(value.items()):
            if isinstance(key, str):
                if _late(len(key)):
                    sk = key if _unjudged(key) else _stopped(key, where + (("(key)", idx),))
                else:
                    sk = _KEYS.get((kk, field, key, guard))
                    if sk is None:
                        sk = show(key, kk, field)
                        if guard:
                            check = _verdict(sk, kk)
                            if check:
                                sk = _replace(sk, where + (("(key)", idx),), check)
                        if sk == key and len(key) <= 128:
                            # a key that comes out as it went in changed nothing (no count, no list): its judging is not repeated for the next row
                            if len(_KEYS) >= 20000:
                                _KEYS.clear()
                            _KEYS[(kk, field, key, guard)] = sk
            elif key is None or isinstance(key, _SCALARS):
                sk = key
            else:
                key = str(key)
                sk = show(key, "name", field)
            if sk in out:
                # many names become one placeholder: the next free " #n" of that placeholder, counted (a probe from the first would be quadratic)
                n = dupes.get(sk, 1)
                while True:
                    n += 1
                    renamed = "%s #%d" % (sk, n)
                    if renamed not in out:
                        break
                dupes[sk] = n
                sk = renamed
            if v is None or type(v) in _SCALAR_TYPES:
                out[sk] = v                               # (a number, a truth value or nothing: there is no string to seal)
                continue
            fk = key if isinstance(key, str) else ""
            sub_kind = (hook(key) if hook else None) or _kind_of(fk, kind)
            label = sk if isinstance(sk, str) else str(sk)
            out[sk] = _seal(v, sub_kind, (field + "." + fk) if field and fk else (fk or field), where + ((label, idx),), guard, fk)
        return out
    if isinstance(value, (list, tuple)):
        return [_seal(v, kind, field, where + ((str(i), i),), guard, fname) for i, v in enumerate(value)]
    return _seal(str(value), "text", field, where, guard, fname)       # anything else the serialiser would have printed with str()


def _kind_of(field, inherited):
    k = _field_entry(field)
    return k if isinstance(k, str) else inherited


def seal(value, kind="text", field=""):
    return _timed(lambda: _seal(value, kind, field, (), True))


_ROW_TYPES = frozenset((str, int, float, bool))
_ROW = [None, None]             # the last row of plain scalars that was sealed without anything being replaced, and what it came out as


def row_object(row):
    """A row of a paging file, sealed and read back: what the file may hold. A tool that writes the same row to two files (every key listed, and
    the nodes of a walk) has it judged once: the second is the first's result, the same judging with nothing to count or list."""
    key = None
    if isinstance(row, dict):
        for k, v in row.items():
            if type(k) is not str or (v is not None and type(v) not in _ROW_TYPES):
                break
        else:
            # (the type is part of the key: 1, True and 1.0 are equal and print differently; a float by its repr, as -0.0 equals 0.0)
            key = tuple((k, type(v), repr(v) if type(v) is float else v) for k, v in row.items())
    if key is not None and _ROW[0] == key:
        return dict(_ROW[1])
    replaced = BOUNDARY["replaced"]
    out = _timed(lambda: _seal(row, "text", "", (), True))
    if key is not None and BOUNDARY["replaced"] == replaced:
        _ROW[0], _ROW[1] = key, dict(out)
    return out


def boundary_summary():
    stopped = {"stopped_by": _STOP["by"], "strings_withheld_by_the_stop": _STOP["strings"]} if _STOP["by"] is not None else {}
    return {"strings_withheld": BOUNDARY["withheld"], "withheld_by_reason": dict(BOUNDARY["by"]),
            "strings_replaced_by_the_backstop": BOUNDARY["replaced"], "replaced_by_check": dict(BOUNDARY["replaced_by"]),
            "replaced_at": list(BOUNDARY["where"]), "replaced_not_listed": BOUNDARY["not_listed"], "values": values_summary(), **stopped,
            "note": "every key and value of this answer and of its paging files was judged by the type of its field: a name, path, key or URL is shown only when it "
                    "fits a plain grammar (a path component by component), free text has token-shaped runs, user-info and the value after a secret's name withheld, "
                    "and a second check written apart from both read it back. A withheld text is <withheld N characters: reason>. Not recognised: a secret that does "
                    "not look like one (a plain password or passphrase, a UUID-shaped key, anything under 16 characters in a name)."}


def _last_look(obj):
    """What this block adds to an answer after the walker (the report of what it did) is read once more by the backstop, keys and values."""
    if isinstance(obj, str):
        return _mark(len(obj), "backstop: a part of a secret-shaped text") if _suspect(obj, "label") else obj
    if isinstance(obj, dict):
        return {_last_look(k): _last_look(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_last_look(v) for v in obj]
    return obj


def answer_object(doc):
    """The answer (or an error answer), sealed and read back. A string the backstop had to replace makes a complete answer partial."""
    _STOP["cap"] = max(_STOP["cap"], _STOP["chars"]) + FINAL_GRACE_CHARS            # (the final answer is always judged: the cap of the run does not take it)
    out = _timed(lambda: _seal(doc, "text", "", (), True))
    if isinstance(out, dict):
        out["boundary"] = _last_look(boundary_summary())
        if (BOUNDARY["replaced"] > 0 or _STOP["by"] is not None) and out.get("status") == "complete":
            out["status"] = "partial"
            basis = out.get("status_basis")
            why = []
            # a string withheld unjudged because judging stopped held nothing that was seen: the stop says it, not this count
            shaped = BOUNDARY["replaced"] - BOUNDARY["replaced_by"].get("the judging time ran out", 0)
            if shaped > 0:
                why.append("%d string(s) still held a secret-shaped text when the answer was checked on its way out and were replaced" % shaped)
            if _STOP["by"] is not None:
                why.append("judging the strings stopped at %s: %d string(s) after it were withheld by their size" % (_STOP["by"], _STOP["strings"]))
            out["status_basis"] = "%s%s (see boundary)" % (basis + "; " if isinstance(basis, str) and basis else "", "; ".join(why))
    return out


def emit(doc, **dumps_kwargs):
    """Print an answer through the boundary (the only way an answer leaves a tool that carries this block)."""
    hold_stop_signals()
    obj = answer_object(doc)
    try:
        text = json.dumps(obj, ensure_ascii=False, default=str, **dumps_kwargs)
        text.encode("utf-8")
    except UnicodeEncodeError:
        text = json.dumps(obj, ensure_ascii=True, default=str, **dumps_kwargs)
    try:
        # a signal that arrives while the answer is being written must not start a second one: signals are held from here (the answer is whole)
        signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT, signal.SIGHUP})
    except (AttributeError, ValueError, OSError):
        pass
    print(text, flush=True)
# END SHARED BOUNDARY
# ---- this tool's side of the one way out ------------------------------------------------------------------------------------------------
# The table of field kinds is this tool's, not the block's: a JSON key or the label a call site gives the Shower -> the kind of what it holds
# (a digit run in a name stands for any number: ethernet0.address is ethernet#.address). A field not listed has the kind of the key above it (text at the
# top: a description, an annotation, an audit action or actor, a message, a tool's own words are judged as free text).
_FIELD_KINDS = (
    # a name a person chose (a machine, a snapshot, a datastore): may hold a `/` (a date in a snapshot name), so it is judged as a path, component by component
    ("path", "name|display_name|displayName|snapshot name|parent snapshot name|current_parent_snapshot|snapshot_sections|snapshot|version"
             "|file|leaf_file|rel|root|links|special|unreadable|too_deep|lock directory|parent_hint|parentFileNameHint|parent name|parent_name|backing_file|backing_filename"
             "|external_data_file|parent_absolute_win32_path|parent_relative_path|parent_volume_path|disk_files|snapshot disk file|state_file|snapshot state file"
             "|extent file name|configuration_path|vmxCfgPath|datastore_hint|datastore path|nvram|disk file|volume|vm_state_volume|vmstate|path|named|export|special_sections|section|disk source|source_name|object"),
    ("name", "domain_name|job|storage|storage name|networkName|ethernet#.networkName|disk key|domain name|datastore|pool|vgname|thinpool|key"
             "|create_type|createType|encoding|backing_format|backing format|native_snapshot|isNativeSnapshot|hardware_version|config_version|arch|bios|firmware|machine"
             "|os_type|virt_type|guest_os|guestOS|cores|vcpus|memory_mb|memory|device|device_type|deviceType|disk_format|mode|present|snapshot_mode|bus|backup|size|state|type"
             "|source_protocol|ddb.adapterType|ddb.virtualHWVersion|ddb.toolsVersion|ddb.thinProvisioned|time_raw|createTimeHigh|createTimeLow|create_time_high_raw"
             "|create_time_low_raw|extent type|type_raw|content|shared|disable|maxfiles|mkdir|is_mountpoint|nodes|ethernet#.virtualDev|ethernet#.present|ethernet#.addressType"),
    # an identifier: one of several forms (a GUID, a VMFS volume id, a device id, a VMware uuid, a MAC, a content id, a number), else a name
    ("id", "uid|snapshot uid|snapshot parent|snapshot id|parent_uid|uuid|bios_uuid|location_uuid|vcenter_instance_uuid|cid_raw|parent_cid_raw|CID|parentCID|entry_id|object_id|vmid"
           "|ddb.uuid|ddb.longContentID|current|lastuid|lastUID|numsnapshots|numSnapshots|source_id|own_id|leaf|base|child|ethernet#.address|ethernet#.generatedAddress|address"
           "|virtual_disk_id|unique_id|parent_unique_id|data_write_guid|file_write_guid|log_guid|parent_identity|parent_identity_2|recorded_by_child|carried_by_parent|descriptor_id"),
)
_FIELD_TABLE = {}
for _kind, _names in _FIELD_KINDS:
    for _n in _names.split("|"):
        _FIELD_TABLE[_n] = _kind
bind_fields(_FIELD_TABLE, {})
OWN_NAMES.update(VOCABULARY)        # a word of the tool's own closed vocabulary is shown as it is
RUN = {"record": True}              # the Shower of the COMMON block sets this; the originals of what the boundary withheld are written by the block itself (bind_values)
_DIGIT_RUN = re.compile(r"[0-9]+")


def field_kind(field):
    """The kind of the field a call site names (the label the Shower is given): the table above, `text` for a field it does not list."""
    if not isinstance(field, str) or not field:
        return "text"
    kind = _FIELD_TABLE.get(field)
    if kind is None and any(c.isdigit() for c in field):
        kind = _FIELD_TABLE.get(_DIGIT_RUN.sub("#", field))
    return kind or "text"


# The calls the COMMON block makes (it stays as it is in the three tools): each is the one text's call under the name COMMON uses.
def seal_text(text, kind="text", field=None, where=""):
    """One string judged by the kind of its field, the layers and the backstop (counted; the original goes to the values file when one was asked for)."""
    return seal(text if isinstance(text, str) else str(text), field_kind(field), field or "")


def seal_head(text, kind="text", field=None, where=""):
    """seal_text for a text a call site reads a piece of: at most the first Shower.EXAMINED characters are judged and a longer text is shown with its whole length."""
    if not isinstance(text, str):
        text = str(text)
    if len(text) <= Shower.EXAMINED:
        return seal_text(text, kind, field, where)
    return seal_text(cut_safely(text, Shower.EXAMINED), kind, field, where) + "...(whole text: %d characters)" % len(text)


def big_ints(value, depth=0):
    """`value` with every integer of more than 18 digits turned into text (the one text then withholds it as a long number): no format this pack reads carries one,
    and its digits can be a secret's. A structure deeper than 64 levels is written as text."""
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value) if abs(value) >= 10 ** 18 else value
    if depth > 64 and isinstance(value, (dict, list, tuple)):
        return json.dumps(value, default=str)
    if isinstance(value, dict):
        return {k: big_ints(v, depth + 1) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [big_ints(v, depth + 1) for v in value]
    return value


def row_text(row, where=""):
    """One row of a paging file: sealed, read back by the backstop, serialised."""
    return json.dumps(row_object(big_ints(row)))


def answer_text(doc):
    """An answer that COMMON prints itself (an error answer, the last word of a signal): sealed and read back, with the values file closed."""
    text = json.dumps(answer_object(big_ints(doc)), indent=2)
    close_values()
    return text
# BEGIN SHARED FILES
# The same text is in virtualization_inventory and snapshot_chain_check; tests/pack-virtualization-shared.test.ts holds the
# copies equal. The evidence is a set of files: a directory walked without following a link, and/or files named one by one.
# Nothing outside that set is ever opened, whatever a file inside it names.


def open_regular(path):
    """Open a regular file for reading without following a final link and without blocking on a pipe; None and the
    reason when it is not one."""
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0))
    except OSError as exc:
        return None, describe(exc)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            os.close(fd)
            return None, "not a regular file"
    except OSError as exc:
        os.close(fd)
        return None, describe(exc)
    return os.fdopen(fd, "rb"), None


class FileSet:
    """The files an examination covers, in a fixed order (names sorted), each with an id that is a sequence number and
    derived from nothing. What was not reached is counted and named: a link, a special file, a directory too deep, a
    listing that was cut at a cap."""

    def __init__(self, shower):
        self.files = []
        self.by_rel = {}
        self.shower = shower
        self.skipped = {"links": [], "special": [], "unreadable": [], "too_deep": []}
        self.skipped_counts = {"links": 0, "special": 0, "unreadable": 0, "too_deep": 0}
        self.lock_dirs = []
        self.lock_dirs_total = 0
        self.entries_seen = 0
        self.truncated = None
        self.root_shown = None

    def note(self, which, rel):
        self.skipped_counts[which] += 1
        if len(self.skipped[which]) < 200:
            self.skipped[which].append(self.shower(rel, "walk", which))

    def add_file(self, rel, path, size):
        if len(self.files) >= self.max_files:
            self.truncated = self.truncated or "max_files (%d) was reached: the files after the last one listed were not examined" % self.max_files
            return False
        fid = "S%06d" % (len(self.files) + 1)
        rec = {"id": fid, "rel": rel, "path": path, "size": size}
        self.files.append(rec)
        self.by_rel[rel] = rec
        return True

    def walk(self, root, paths, max_files, max_entries, max_depth, clock):
        self.max_files = max_files
        if root is not None:
            if os.path.islink(root):
                fail("refusing a symlink root: pass the evidence directory itself", root=root)
            if not os.path.isdir(root):
                fail("root is not a directory", root=root)
            self.root_shown = self.shower(root, "root", "root")
            stack = [("", 0)]
            while stack:
                rel_dir, depth = stack.pop()
                clock.check()
                here = os.path.join(root, rel_dir) if rel_dir else root
                try:
                    with os.scandir(here) as it:
                        entries = list(itertools.islice(it, max_entries - self.entries_seen + 1))
                except OSError as exc:
                    self.note("unreadable", (rel_dir or ".") + ": " + describe(exc))
                    continue
                if self.entries_seen + len(entries) > max_entries:
                    entries = entries[:max(0, max_entries - self.entries_seen)]
                    self.truncated = self.truncated or "max_entries (%d) was reached: the directories after the last one listed were not read" % max_entries
                    stack = []
                self.entries_seen += len(entries)
                entries.sort(key=lambda e: e.name)
                subdirs = []
                for e in entries:
                    clock.check(256)
                    rel = (rel_dir + "/" + e.name) if rel_dir else e.name
                    try:
                        if e.is_symlink():
                            self.note("links", rel)
                        elif e.is_dir(follow_symlinks=False):
                            if e.name.lower().endswith(".lck") or e.name.lower().startswith(".lck-"):
                                self.lock_dirs_total += 1
                                if len(self.lock_dirs) < 1000:
                                    self.lock_dirs.append(rel)
                            if depth + 1 > max_depth:
                                self.note("too_deep", rel)
                            else:
                                subdirs.append((rel, depth + 1))
                        elif e.is_file(follow_symlinks=False):
                            self.add_file(rel, os.path.join(root, rel), e.stat(follow_symlinks=False).st_size)
                        else:
                            self.note("special", rel)
                    except OSError as exc:
                        self.note("unreadable", rel + ": " + describe(exc))
                for item in reversed(subdirs):
                    stack.append(item)
                if self.truncated and "max_entries" in self.truncated:
                    break
        for p in paths:
            clock.check()
            try:
                st = os.lstat(p)
            except OSError as exc:
                self.note("unreadable", p + ": " + describe(exc))
                continue
            if stat.S_ISLNK(st.st_mode):
                self.note("links", p)
            elif not stat.S_ISREG(st.st_mode):
                self.note("special", p)
            else:
                rel = p
                if rel not in self.by_rel:
                    self.add_file(rel, p, st.st_size)

    def skipped_summary(self):
        return {"counts": dict(self.skipped_counts), "named": self.skipped,
                "note": "A link is listed and never followed; a special file is never opened; at most 200 of each are named, all are counted."}
class Index:
    def __init__(self, files):
        self.exact = {f["rel"]: f for f in files}
        self.fold = collections.defaultdict(list)
        self.base = collections.defaultdict(list)
        for f in files:
            self.fold[f["rel"].casefold()].append(f)
            self.base[posixpath.basename(f["rel"]).casefold()].append(f)

    def resolve(self, from_rel, hint):
        """(file or None, how). The hint is a string some file wrote; it is looked up among the files given and never opened."""
        if not hint or "\x00" in hint:
            return None, "no_name"
        h = hint.replace("\\", "/") if ("\\" in hint and "/" not in hint) else hint
        drive = bool(re.match(r"^[A-Za-z]:", h)) or h.startswith("/") or h.startswith("//") or h.startswith("vmfs/") or h.startswith("[")
        joined = None
        if not drive:
            joined = posixpath.normpath(posixpath.join(posixpath.dirname(from_rel), h))
            if joined.startswith("../") or joined == "..":
                joined = None
        if joined is not None:
            f = self.exact.get(joined)
            if f:
                return f, "relative_exact"
            hits = self.fold.get(joined.casefold(), [])
            if len(hits) == 1:
                return hits[0], "relative_case_insensitive"
        hits = self.base.get(posixpath.basename(h.rstrip("/")).casefold(), [])
        if len(hits) == 1:
            return hits[0], "basename_only"
        if len(hits) > 1:
            return None, "ambiguous_basename"
        return None, "not_in_set"


EXTENSION = re.compile(r"\.[A-Za-z0-9]{1,10}")


def ext_of(rel):
    """The extension a file is counted under: a short one of letters and digits as it is (lower case), none as (none),
    and any other under one bucket that shows nothing of it (a file name can carry a token after its last dot)."""
    ext = posixpath.splitext(posixpath.basename(rel))[1]
    if not ext:
        return "(none)"
    return ext.lower() if EXTENSION.fullmatch(ext) else "(other extensions)"
# END SHARED FILES
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
    if "answer_a_stop" in globals():     # (a block run on its own, by a test, has no ENDS block)
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
# The process block's handlers (they end the programs the tool runs, then give the last word) are in as soon as the module has
# run this far, not when main() starts: a signal from here on gives one answer and exit 128 plus the signal number. What stays
# open is the start of the interpreter and the compiling of this file.
STATE["last_word"] = stop_word
install_signal_handlers()


# A value that is a number, a UUID or a run of hex bytes is shown as it is.
SAFE_VALUE = re.compile(r"[0-9]{1,12}|[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}|(?:[0-9A-Fa-f]{2}[ -]){3,31}[0-9A-Fa-f]{2}")


def make_net(shown, fid):
    """The net under every record: a string from the evidence that no call site has checked is checked here."""
    def net(value, depth=0, key="value"):
        if isinstance(value, str):
            if isinstance(value, Shown) or value in CREATE_TYPES or SAFE_VALUE.fullmatch(value):
                return value
            return shown(value, fid, key)
        if depth > 5:
            return value
        if isinstance(value, dict):
            return {k: net(v, depth + 1, k) for k, v in value.items()}
        if isinstance(value, list):
            return [net(v, depth + 1, key) for v in value]
        return value
    return net


# ---- small readers -----------------------------------------------------------------------------------------------

def read_at(fh, offset, length):
    if offset < 0 or length < 0:
        return b""
    fh.seek(offset)
    return fh.read(length)


def iso_utc(epoch, base=0):
    try:
        stamp = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(seconds=epoch + base)
        return stamp.strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, ValueError):
        return None


def guid_text(raw):
    return str(uuid.UUID(bytes_le=raw)).upper()


_CRC = []
for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = (_c >> 1) ^ 0x82F63B78 if _c & 1 else _c >> 1
    _CRC.append(_c)


def crc32c(data):
    crc = 0xFFFFFFFF
    for b in data:
        crc = _CRC[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFF


# ---- VMDK ------------------------------------------------------------------------------------------------------------

EXTENT = re.compile(r'^(RW|RDONLY|NOACCESS)\s+(\d+)\s+([A-Za-z0-9_]+)(?:\s+"((?:[^"\\]|\\.)*)")?(?:\s+(\d+))?\s*(?:#.*)?$')
EXTENT_LIKE = re.compile(r"^(?:RW|RDONLY|NOACCESS)(?:\s|$)", re.I)      # a line that says it is an extent and that EXTENT did not match
DESC_KV = re.compile(r'^([A-Za-z][A-Za-z0-9_.]*)\s*=\s*(.*)$')
CID_HEX = re.compile(r"^[0-9a-fA-F]{1,8}$")      # a 32-bit value in hexadecimal; qemu-img writes it without leading zeros
KNOWN_EXTENT_TYPES = {"FLAT", "SPARSE", "ZERO", "VMFS", "VMFSSPARSE", "VMFSRDM", "VMFSRAW", "VMFSPASSTHRU", "SESPARSE"}
NOT_A_FILE_EXTENT = ("ZERO", "VMFSRDM", "VMFSRAW", "VMFSPASSTHRU")


def cid_value(text):
    """A CID as eight lowercase hexadecimal digits, compared as the number it is; None when it is not one."""
    return "%08x" % int(text, 16) if text and CID_HEX.match(text) else None


def unquote(value):
    value = value.strip()
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        value = value[1:-1]
    return value


def parse_descriptor(text):
    """The fields of a VMDK descriptor, its extents (up to MAX_EXTENTS) and the counts of what was not kept."""
    d = {"fields": {}, "extents": [], "extents_total": 0, "ddb": {}, "ddb_other": 0, "lines_over_cap": False, "other_lines": 0,
         "extent_like_unread": 0, "extent_like_first": None, "over_read_cap": False, "blank": not text.strip()}
    for number, raw in enumerate(text.split("\n"), 1):
        if number > MAX_DESC_LINES:
            d["lines_over_cap"] = True
            break
        line = raw.strip().rstrip("\r")
        if not line or line.startswith("#"):
            continue
        m = EXTENT.match(line)
        if m:
            d["extents_total"] += 1
            if len(d["extents"]) < MAX_EXTENTS:
                # the type is compared in upper case and shown as written: folding it first would hide a token's shape
                d["extents"].append({"access": m.group(1), "sectors": int(m.group(2)), "type": m.group(3).upper(), "type_raw": m.group(3),
                                     "name": m.group(4), "offset": int(m.group(5)) if m.group(5) else None, "line": number})
            continue
        m = DESC_KV.match(line)
        if not m:
            d["other_lines"] += 1
            if EXTENT_LIKE.match(line):                    # an extent the tool could not read is an extent the chain does not know
                d["extent_like_unread"] += 1
                if d["extent_like_first"] is None:
                    d["extent_like_first"] = number
            continue
        key, value = m.group(1), unquote(m.group(2))
        if key.lower().startswith("ddb."):
            if key in KNOWN_DDB:
                d["ddb"][key] = value
            else:
                d["ddb_other"] += 1
        elif key.lower() in ("version", "encoding", "cid", "parentcid", "createtype", "parentfilenamehint", "isnativesnapshot"):
            d["fields"].setdefault(key.lower(), value)
        else:
            d["other_lines"] += 1
    return d


def descriptor_problems(d):
    """What the descriptor says that cannot be followed: the texts are this tool's own, never the evidence's."""
    f = d["fields"]
    cid, pcid, hint = f.get("cid"), f.get("parentcid"), f.get("parentfilenamehint")
    out = []
    if cid and not CID_HEX.match(cid):
        out.append("CID is not 1 to 8 hexadecimal digits")
    if pcid and not CID_HEX.match(pcid):
        out.append("parentCID is not 1 to 8 hexadecimal digits")
    if cid_value(pcid) not in (None, "ffffffff") and not hint:
        out.append("a parentCID is recorded and no parentFileNameHint names the parent")
    return out


def descriptor_gaps(d):
    """Why a descriptor does not tell the whole story of its disk: a cap that cut it, an extent line it could not read, no extent line
    at all, or a record that cannot be followed. Each is a gap in the chain, never a quiet `complete`."""
    gaps = []
    if d["lines_over_cap"]:
        gaps.append("the descriptor has more than %d lines: the lines after them (a parent, an extent) were not read" % MAX_DESC_LINES)
    if d["over_read_cap"]:
        gaps.append("the descriptor is longer than %d bytes: what lies after them (a parent, an extent) was not read" % MAX_DESCRIPTOR)
    if d["extent_like_unread"]:
        gaps.append("%d line(s) begin like an extent line (RW, RDONLY or NOACCESS; the first is line %d) and are not in the shape this tool reads: those extents were not checked" % (
            d["extent_like_unread"], d["extent_like_first"]))
    if d["extents_total"] == 0 and not d["blank"]:        # no text at all is no descriptor (the zero-filled area of a split sparse extent), not one without extents
        gaps.append("the descriptor lists no extent line: what the disk is made of is not known")
    return gaps + descriptor_problems(d)


def descriptor_node(d, source, shown, fid):
    f = d["fields"]
    cid, pcid = f.get("cid"), f.get("parentcid")
    node = {"format": "vmdk", "version": shown(f.get("version"), fid, "version"), "create_type": f.get("createtype") if f.get("createtype") in CREATE_TYPES else shown(f.get("createtype"), fid, "createType"), "encoding": shown(f.get("encoding"), fid, "encoding"),
            "cid": cid_value(cid), "cid_raw": shown(cid, fid, "CID"),
            "parent_cid": cid_value(pcid), "parent_cid_raw": shown(pcid, fid, "parentCID"),
            "cid_note": "a CID is a 32-bit number written in hexadecimal (qemu-img writes it without leading zeros); it is shown as eight digits and compared as a number",
            "has_parent": cid_value(pcid) not in (None, "ffffffff"),
            "parent_hint": shown(f.get("parentfilenamehint"), fid, "parentFileNameHint"), "native_snapshot": shown(f.get("isnativesnapshot"), fid, "isNativeSnapshot"),
            "other_lines": d["other_lines"], "extents_total": d["extents_total"], "capacity_sectors_by_extents": sum(e["sectors"] for e in d["extents"]) if d["extents_total"] == len(d["extents"]) else None, "ddb": {k: shown(v, fid, k) for k, v in d["ddb"].items()}, "ddb_other_keys": d["ddb_other"], "descriptor_source": source}
    problems = descriptor_problems(d)
    if problems:
        node["problem"] = problems[-1]
    if not node["has_parent"] and f.get("parentfilenamehint"):
        node["parent_hint_not_followed"] = "a parentFileNameHint is written and parentCID records no parent (ffffffff or none): the hint is not followed and no parent is looked for"
    return node


def capacity_is_zero(res):
    """True for a sparse extent whose header says capacity 0: qemu-img then reads the embedded descriptor as a descriptor file."""
    return (res.get("row") or {}).get("info", {}).get("capacity_sectors") == 0 or (res.get("info") or {}).get("capacity_sectors") == 0


def parse_vmdk_text(fh, size, head):
    raw = head if size <= len(head) else head + read_at(fh, len(head), min(size, MAX_DESCRIPTOR) - len(head))
    over = size > MAX_DESCRIPTOR
    text = raw[:MAX_DESCRIPTOR].replace(b"\x00", b"\n").decode("utf-8", "replace")
    d = parse_descriptor(text)
    d["over_read_cap"] = over
    return d, over


def parse_vmdk_sparse(fh, size, head):
    if len(head) < 512:
        return {"state": "failed", "reason": "a sparse extent header is 512 bytes and the file is shorter"}
    (magic, version, flags, capacity, grain, doff, dsize, gtes, rgd, gd, overhead, unclean, c1, c2, c3, c4, comp) = struct.unpack("<4sIIQQQQIQQQBccccH", head[:79])
    info = {"format": "vmdk_sparse_extent", "sparse_version": version, "flags": "0x%08x" % flags, "capacity_sectors": capacity,
            "grain_size_sectors": grain, "descriptor_offset_sectors": doff, "descriptor_sectors": dsize, "overhead_sectors": overhead,
            "unclean_shutdown_flag": bool(unclean), "compress_algorithm": comp}
    markers = []
    if unclean:
        markers.append({"kind": "unclean_shutdown_flag", "observation": "the sparse extent header's uncleanShutdown byte is %d" % unclean,
                        "reading": "the extent was open for writing when the file was last written; a candidate for an interrupted write, a snapshot "
                                   "taken while running or a copy of a live file, not a verdict"})
    if flags & 1 and (c1, c2, c3, c4) != (b"\n", b" ", b"\r", b"\n"):
        markers.append({"kind": "newline_detection_mismatch", "observation": "the header's newline-detection bytes differ from the values the format fixes",
                        "reading": "the file may have been transferred in a mode that rewrites line ends; a candidate for an altered copy"})
    if version not in (1, 2, 3):
        return {"state": "unsupported", "reason": "sparse extent version %d is not one this tool reads" % version, "info": info, "markers": markers}
    desc = None
    if doff and dsize:
        want = min(dsize * 512, MAX_DESCRIPTOR)
        start = doff * 512
        if start >= size:
            return {"state": "failed", "reason": "the descriptor offset (%d sectors) is past the end of the file" % doff, "info": info, "markers": markers}
        data = read_at(fh, start, min(want, size - start))
        text = data.split(b"\x00", 1)[0].decode("utf-8", "replace")
        desc = parse_descriptor(text)
        desc["over_read_cap"] = dsize * 512 > MAX_DESCRIPTOR
        info["descriptor_over_read_cap"] = desc["over_read_cap"]
    return {"state": "parsed", "info": info, "descriptor": desc, "markers": markers}


# ---- VHD -------------------------------------------------------------------------------------------------------------

VHD_FOOTER = struct.Struct(">8sIIQI4sI4sQQ4sII16sB")
VHD_TYPES = {2: "fixed", 3: "dynamic", 4: "differencing"}
VHD_EPOCH = 946684800  # 2000-01-01T00:00:00Z


def vhd_checksum_ok(raw, offset):
    zeroed = raw[:offset] + b"\x00\x00\x00\x00" + raw[offset + 4:]
    return (~sum(zeroed)) & 0xFFFFFFFF == struct.unpack(">I", raw[offset:offset + 4])[0]


def parse_vhd(fh, size, head):
    first = head[:512] if head[:8] == b"conectix" else None
    last = read_at(fh, size - 512, 512) if size >= 512 else b""
    footer = last if last[:8] == b"conectix" else first
    if footer is None or len(footer) < 512:
        return {"state": "failed", "reason": "no VHD footer (conectix) at the start or in the last 512 bytes"}
    (cookie, features, version, data_off, stamp, creator, creator_ver, host_os, original, current, geom, dtype, checksum, uid, saved) = VHD_FOOTER.unpack(footer[:85])
    info = {"format": "vhd", "disk_type": VHD_TYPES.get(dtype, "type %d (not read)" % dtype), "file_format_version": "0x%08x" % version,
            "footer_checksum_ok": vhd_checksum_ok(footer, 64), "unique_id": str(uuid.UUID(bytes=uid)).upper(),
            "created_utc": iso_utc(stamp, VHD_EPOCH), "created_raw": stamp, "created_epoch": "seconds since 2000-01-01T00:00:00Z",
            "original_size": original, "current_size": current, "saved_state": bool(saved),
            "creator_application": creator.decode("ascii", "replace"), "creator_version": "0x%08x" % creator_ver,
            "creator_host_os": host_os.decode("ascii", "replace"), "footer_location": "start" if footer is first and footer is not last else "end"}
    markers, damaged = [], []
    if not info["footer_checksum_ok"]:
        damaged.append("the VHD footer's checksum")
        markers.append({"kind": "vhd_footer_checksum_fail", "observation": "the footer's checksum does not match its bytes",
                        "reading": "the footer is damaged or was edited after it was written; its fields are shown as written and may be wrong"})
    if footer is first and last[:8] != b"conectix":
        damaged.append("the VHD footer at the end of the file is missing")
        markers.append({"kind": "vhd_footer_copy_missing", "observation": "the footer at the end of the file is missing (the last 512 bytes do not start with the cookie conectix); the copy at the start was read",
                        "reading": "the file was cut short, copied short, or its end footer was damaged; what the start copy records is shown as written, and the dynamic header and the parent names are read from the offsets it gives"})
    if saved:
        markers.append({"kind": "vhd_saved_state_flag", "observation": "the footer's Saved State byte is set",
                        "reading": "the disk was attached to a VM in a saved state when the footer was written; a candidate that the VM's saved state "
                                   "must be preserved with it"})
    if version >> 16 != 1:
        return {"state": "unsupported", "reason": "VHD file format version 0x%08x is not one this tool reads (major version 1 is)" % version, "info": info, "markers": markers}
    if dtype not in VHD_TYPES:
        return {"state": "unsupported", "reason": "disk type %d is not one this tool reads" % dtype, "info": info, "markers": markers}
    if dtype == 2:
        return {"state": "parsed", "info": info, "markers": markers, "damaged": damaged, "vhd": {"identity": info["unique_id"], "hints": [], "parent_identity": None}}
    if head[:8] == b"conectix" and last[:8] == b"conectix" and head[:512] != last[:512]:
        markers.append({"kind": "vhd_footer_copy_differs", "observation": "the footer copy at the start differs from the footer at the end",
                        "reading": "the two copies were not written together; a candidate for an interrupted write or an edit, not a verdict"})
    if data_off == 0xFFFFFFFFFFFFFFFF or data_off + 1024 > size:
        return {"state": "failed", "reason": "the footer's data offset does not point at a dynamic-disk header inside the file", "info": info, "markers": markers}
    hdr = read_at(fh, data_off, 1024)
    if len(hdr) < 1024 or hdr[:8] != b"cxsparse":
        return {"state": "failed", "reason": "no dynamic-disk header (cxsparse) at the footer's data offset", "info": info, "markers": markers}
    (_c, _d, table_off, hver, max_entries, block, hsum, pid, pstamp, _r, pname_raw) = struct.unpack(">8sQQIIII16sII512s", hdr[:576])
    pname = pname_raw.decode("utf-16-be", "replace").split("\x00", 1)[0]
    info.update({"dynamic_header_checksum_ok": vhd_checksum_ok(hdr, 36), "block_size": block, "max_table_entries": max_entries, "header_version": "0x%08x" % hver})
    if not info["dynamic_header_checksum_ok"]:
        damaged.append("the VHD dynamic-disk header's checksum")
        markers.append({"kind": "vhd_dynamic_header_checksum_fail", "observation": "the dynamic-disk header's checksum does not match its bytes",
                        "reading": "the header that holds the parent's id and name is damaged or was edited; the parent fields are shown as written and may be wrong"})
    if hver >> 16 != 1:
        return {"state": "unsupported", "reason": "VHD dynamic header version 0x%08x is not one this tool reads" % hver, "info": info, "markers": markers}
    hints, locators = [], []
    if dtype == 4:
        info["parent_unique_id"] = str(uuid.UUID(bytes=pid)).upper()
        info["parent_timestamp_utc"] = iso_utc(pstamp, VHD_EPOCH)
        info["parent_timestamp_raw"] = pstamp
        info["parent_name"] = pname
        if pname:
            hints.append(pname)
        for i in range(8):
            code, space, length, _res, loff = struct.unpack(">4sIIIQ", hdr[576 + 24 * i:576 + 24 * (i + 1)])
            if code == b"\x00\x00\x00\x00" or not length:
                continue
            entry = {"platform_code": code.decode("ascii", "replace"), "data_length": length, "data_offset": loff}
            if length <= 65536 and loff + length <= size:
                data = read_at(fh, loff, length)
                text = data.decode("utf-8" if code == b"MacX" else "utf-16-le", "replace").split("\x00", 1)[0]
                if text:
                    entry["path_present"] = True
                    hints.append(text)
            else:
                entry["problem"] = "the locator data is outside the file or over 64 KiB"
            locators.append(entry)
        info["parent_locators"] = len(locators)
    return {"state": "parsed", "info": info, "markers": markers, "damaged": damaged,
            "vhd": {"identity": info["unique_id"], "hints": hints, "parent_identity": info.get("parent_unique_id")}}


# ---- VHDX ------------------------------------------------------------------------------------------------------------

G_METADATA = "8B7CA206-4790-4B9A-B8FE-575F050F886E"
G_FILE_PARAMS = "CAA16737-FA36-4D43-B3B6-33F0AA44E76B"
G_DISK_ID = "BECA12AB-B2E6-4523-93EF-C309E000C746"
G_DISK_SIZE = "2FA54224-CD1B-4876-B211-5DBED83BF4B8"
G_PARENT_LOCATOR = "A8D35F2D-B30B-454D-ABF7-D3D84834AB0C"
G_LOCATOR_VHDX = "B04AEFB7-D19E-4A81-B789-25B8E9445913"
ZERO_GUID = "00000000-0000-0000-0000-000000000000"
GUID_TEXT = re.compile(r"[0-9A-F]{8}(?:-[0-9A-F]{4}){3}-[0-9A-F]{12}")


def vhdx_header(fh, offset, size):
    raw = read_at(fh, offset, 4096)
    if len(raw) < 4096 or raw[:4] != b"head":
        return None
    checksum = struct.unpack("<I", raw[4:8])[0]
    ok = crc32c(raw[:4] + b"\x00\x00\x00\x00" + raw[8:]) == checksum
    seq = struct.unpack("<Q", raw[8:16])[0]
    return {"offset": offset, "checksum_ok": ok, "sequence": seq, "file_write_guid": guid_text(raw[16:32]), "data_write_guid": guid_text(raw[32:48]),
            "log_guid": guid_text(raw[48:64]), "log_version": struct.unpack("<H", raw[64:66])[0], "version": struct.unpack("<H", raw[66:68])[0],
            "log_length": struct.unpack("<I", raw[68:72])[0], "log_offset": struct.unpack("<Q", raw[72:80])[0]}


def parse_vhdx(fh, size, head):
    markers = []
    headers = [h for h in (vhdx_header(fh, 65536, size), vhdx_header(fh, 131072, size)) if h]
    if not headers:
        return {"state": "failed", "reason": "no header with the head signature at 64 KiB or 128 KiB"}
    valid = [h for h in headers if h["checksum_ok"]]
    current = max(valid or headers, key=lambda h: h["sequence"])
    info = {"format": "vhdx", "headers_found": len(headers), "headers_checksum_ok": len(valid), "current_header_offset": current["offset"],
            "sequence_numbers": [h["sequence"] for h in headers], "file_write_guid": current["file_write_guid"], "data_write_guid": current["data_write_guid"],
            "log_guid": current["log_guid"], "log_length": current["log_length"], "version": current["version"]}
    damaged = []
    if not valid:
        damaged.append("both VHDX headers' CRC-32C")
        markers.append({"kind": "vhdx_headers_checksum_fail", "observation": "no header's CRC-32C matched",
                        "reading": "the headers are damaged or were edited; the current header was chosen by sequence number alone"})
    elif len(valid) < 2:
        damaged.append("one VHDX header's CRC-32C or signature")
        markers.append({"kind": "vhdx_header_copy_damaged", "observation": "%d of the two VHDX headers has a signature and a CRC-32C that hold; the header at %d KiB was taken as current" % (len(valid), current["offset"] // 1024),
                        "reading": "one copy is damaged, edited or missing; which header is current decides which DataWriteGuid a child's parent linkage is compared with, so the identity check below rests on the one copy that holds"})
    if current["version"] != 1:
        return {"state": "unsupported", "reason": "VHDX header version %d is not one this tool reads" % current["version"], "info": info, "markers": markers}
    if current["log_guid"] != ZERO_GUID:
        markers.append({"kind": "vhdx_log_guid_set", "observation": "the current header's LogGuid is not zero (log length %d)" % current["log_length"],
                        "reading": "a log is present; whether it holds entries that were not replayed is not read here, so this is a candidate for an "
                                   "interrupted write and also what a log in use looks like"})
    # MS-VHDX keeps two copies of the region table (192 KiB and 256 KiB): the first whose signature and CRC-32C hold is read
    copies = []
    for offset in (196608, 262144):
        raw = read_at(fh, offset, 65536)
        ok = len(raw) == 65536 and raw[:4] == b"regi" and crc32c(raw[:4] + b"\x00\x00\x00\x00" + raw[8:]) == struct.unpack("<I", raw[4:8])[0]
        copies.append((offset, raw, ok))
    good = [c for c in copies if c[2]]
    signed = [c for c in copies if len(c[1]) >= 16 and c[1][:4] == b"regi"]
    if not signed:
        return {"state": "failed", "reason": "no region table (regi) at 192 KiB or at 256 KiB", "info": info, "markers": markers}
    offset, region, _ok = (good or signed)[0]
    info["region_table_offset"] = offset
    info["region_table_checksum_ok"] = bool(good) and offset == good[0][0]
    info["region_table_copies_valid"] = len(good)
    if not good:
        damaged.append("both VHDX region tables' CRC-32C")
        markers.append({"kind": "vhdx_region_table_checksum_fail", "observation": "neither copy of the region table has a CRC-32C that matches",
                        "reading": "the region table (where the metadata is) is damaged or was edited; the metadata was read from the copy at %d KiB as written" % (offset // 1024)})
    elif len(good) < len(copies):
        markers.append({"kind": "vhdx_region_table_copy_damaged", "observation": "one copy of the region table does not hold (signature or CRC-32C); the copy at %d KiB does and was read" % (offset // 1024),
                        "reading": "a damaged or edited copy; the file can still be read from the other"})
    count = struct.unpack("<I", region[8:12])[0]
    meta_off = meta_len = None
    for i in range(min(count, 2047)):
        e = region[16 + 32 * i:48 + 32 * i]
        if len(e) < 32:
            break
        if guid_text(e[:16]) == G_METADATA:
            meta_off, meta_len = struct.unpack("<QI", e[16:28])
    if meta_off is None or meta_off + 65536 > size:
        return {"state": "failed", "reason": "the region table names no metadata region inside the file", "info": info, "markers": markers}
    table = read_at(fh, meta_off, 65536)
    if table[:8] != b"metadata":
        return {"state": "failed", "reason": "no metadata table at the region the region table names", "info": info, "markers": markers}
    items = {}
    for i in range(min(struct.unpack("<H", table[10:12])[0], 2047)):
        e = table[32 + 32 * i:64 + 32 * i]
        if len(e) < 32:
            break
        items[guid_text(e[:16])] = struct.unpack("<II", e[16:24])
    # MS-VHDX: a child's parent_linkage (and parent_linkage2) holds the DataWriteGuid of the parent's header, which the
    # parent changes the first time it is written after it was opened; the VirtualDiskId stays the same through every
    # write and is kept here as information only. So the identity a child is held against is the DataWriteGuid of the
    # parent's current header (the valid one with the higher sequence number).
    vx = {"identity": current["data_write_guid"], "identity_field": "DataWriteGuid of the current header", "hints": [], "parent_identity": None, "parent_identity_2": None}
    info["linkage_identity"] = current["data_write_guid"]
    info["linkage_identity_note"] = ("a child's parent_linkage is compared with this disk's DataWriteGuid (MS-VHDX); the VirtualDiskId is information "
                                     "and is not what a child records")
    if G_FILE_PARAMS in items:
        off, length = items[G_FILE_PARAMS]
        raw = read_at(fh, meta_off + off, 8) if length >= 8 else b""
        if len(raw) == 8:
            block, flags = struct.unpack("<II", raw)
            info["block_size"] = block
            info["has_parent"] = bool(flags & 2)
            info["leave_blocks_allocated"] = bool(flags & 1)
    if G_DISK_SIZE in items:
        off, length = items[G_DISK_SIZE]
        raw = read_at(fh, meta_off + off, 8) if length >= 8 else b""
        if len(raw) == 8:
            info["virtual_size"] = struct.unpack("<Q", raw)[0]
    if G_DISK_ID in items:
        off, length = items[G_DISK_ID]
        raw = read_at(fh, meta_off + off, 16) if length >= 16 else b""
        if len(raw) == 16:
            info["virtual_disk_id"] = guid_text(raw)
    if G_PARENT_LOCATOR in items:
        off, length = items[G_PARENT_LOCATOR]
        raw = read_at(fh, meta_off + off, min(length, 1 << 20))
        if len(raw) >= 20:
            ltype = guid_text(raw[:16])
            kv = struct.unpack("<H", raw[18:20])[0]
            info["parent_locator_type"] = ltype
            pairs = {}
            if ltype == G_LOCATOR_VHDX:
                for i in range(min(kv, 1024)):
                    e = raw[20 + 12 * i:32 + 12 * i]
                    if len(e) < 12:
                        break
                    ko, vo, kl, vl = struct.unpack("<IIHH", e)
                    if ko + kl <= len(raw) and vo + vl <= len(raw):
                        pairs[raw[ko:ko + kl].decode("utf-16-le", "replace")] = raw[vo:vo + vl].decode("utf-16-le", "replace")
                for key in ("relative_path", "absolute_win32_path", "volume_path"):
                    if pairs.get(key):
                        info["parent_" + key] = pairs[key]
                        if key != "volume_path":
                            vx["hints"].append(pairs[key])
                for key, slot in (("parent_linkage", "parent_identity"), ("parent_linkage2", "parent_identity_2")):
                    if pairs.get(key):
                        text = pairs[key].strip("{}").upper()
                        if GUID_TEXT.fullmatch(text):
                            vx[slot] = info[key] = text
                        else:
                            info[key + "_problem"] = "the value is not a GUID (%d characters): not compared" % len(pairs[key])
                info["parent_locator_keys"] = sorted(k for k in pairs if k in ("parent_linkage", "parent_linkage2", "relative_path", "volume_path", "absolute_win32_path"))
                info["parent_locator_other_keys"] = len(pairs) - len(info["parent_locator_keys"])
            else:
                info["parent_locator_note"] = "a locator of another type: not read"
    if info.get("has_parent") and not (vx["parent_identity"] or vx["hints"]):
        info["problem"] = "the file parameters say a parent exists and the parent locator names none"
    return {"state": "parsed", "info": info, "markers": markers, "damaged": damaged, "vhdx": vx}


# ---- QCOW2 -----------------------------------------------------------------------------------------------------------

QCOW_EXT_NAMES = {0xE2792ACA: "backing_file_format", 0x6803F857: "feature_name_table", 0x0537BE77: "full_disk_encryption_header",
                  0x23852875: "bitmaps", 0x44415441: "external_data_file_name"}
QCOW_INCOMPAT = ((0, "dirty"), (1, "corrupt"), (2, "external_data_file"), (3, "compression_type"), (4, "extended_l2_entries"))


def parse_qcow2(fh, size, head, snapshot_sink, max_snapshots, clock):
    if len(head) < 72:
        return {"state": "failed", "reason": "a QCOW2 header is at least 72 bytes and the file is shorter"}
    (magic, version, boff, bsize, cbits, vsize, crypt, l1size, l1off, rcoff, rcclusters, nsnap, soff) = struct.unpack(">4sIQIIQIIQQIIQ", head[:72])
    info = {"format": "qcow2", "version": version, "virtual_size": vsize, "cluster_bits": cbits, "encryption_method_field": crypt,
            "backing_file_offset": boff, "snapshots_declared": nsnap}
    markers = []
    if version not in (2, 3):
        return {"state": "unsupported", "reason": "QCOW version %d is not one this tool reads" % version, "info": info, "markers": markers}
    if not 9 <= cbits <= 21:
        return {"state": "failed", "reason": "cluster_bits %d is outside 9 to 21" % cbits, "info": info, "markers": markers}
    header_len = 72
    if version == 3:
        if len(head) < 104:
            return {"state": "failed", "reason": "a version 3 header is at least 104 bytes and the file is shorter", "info": info, "markers": markers}
        incompat, compat, autoclear, rorder, header_len = struct.unpack(">QQQII", head[72:104])
        info.update({"incompatible_features": "0x%x" % incompat, "compatible_features": "0x%x" % compat, "autoclear_features": "0x%x" % autoclear,
                     "refcount_order": rorder, "header_length": header_len})
        flags = [name for bit, name in QCOW_INCOMPAT if incompat & (1 << bit)]
        info["incompatible_feature_names"] = flags
        if incompat >> 5:
            info["incompatible_unknown_bits"] = "0x%x" % (incompat >> 5 << 5)
        if incompat & 1:
            markers.append({"kind": "qcow2_dirty_bit", "observation": "incompatible feature bit 0 (dirty) is set",
                            "reading": "the image's reference counts may be stale because it was not closed cleanly; a candidate for an interrupted "
                                       "write or a copy of a live image, not a verdict"})
        if incompat & 2:
            markers.append({"kind": "qcow2_corrupt_bit", "observation": "incompatible feature bit 1 (corrupt) is set",
                            "reading": "the image was marked corrupt by the program that last wrote it"})
    # header extensions
    exts, backing_format, ext_data = [], None, None
    ext_start = header_len if version == 3 else 72
    cluster = 1 << cbits
    window = read_at(fh, ext_start, min(max(0, cluster - ext_start), 1 << 20)) if ext_start < size else b""
    pos, n = 0, 0
    gaps = []                          # what the header says that this reading did not take in: each one keeps the chain from being called complete
    while pos + 8 <= len(window) and n < 64:
        etype, elen = struct.unpack(">II", window[pos:pos + 8])
        if etype == 0:
            break
        if pos + 8 + elen > len(window) and not any("runs past" in g for g in gaps):
            gaps.append("a header extension runs past the end of the header area read (the first cluster): its content, a backing format or an external data file name, is cut")
        data = window[pos + 8:pos + 8 + elen]
        name = QCOW_EXT_NAMES.get(etype, "0x%08x" % etype)
        exts.append(name)
        if etype == 0xE2792ACA:
            backing_format = data.decode("utf-8", "replace")
        elif etype == 0x44415441:
            ext_data = data.decode("utf-8", "surrogateescape")
        pos += 8 + ((elen + 7) & ~7)
        n += 1
    if n >= 64 and pos + 8 <= len(window) and struct.unpack(">I", window[pos:pos + 4])[0] != 0:
        gaps.append("the header lists more than 64 extensions: those after the 64th (an external data file name, a backing format) were not read")
    info["header_extensions"] = exts
    if backing_format is not None:
        info["backing_format"] = backing_format
    if ext_data is not None:
        info["external_data_file"] = ext_data
    hints = []
    if boff:
        if bsize > 1023:
            info["problem"] = "the backing file name is declared %d bytes; the format allows 1023" % bsize
            gaps.append(info["problem"])
        raw = read_at(fh, boff, min(bsize, 4096)) if boff < size else b""
        if len(raw) < min(bsize, 4096):
            info["problem"] = "the backing file name lies outside the file"
            gaps.append(info["problem"])
        else:
            name = decode(raw)
            info["backing_file"] = name
            hints.append(name)
    # internal snapshots, streamed
    snaps = {"declared": nsnap, "read": 0, "stopped": None}
    if nsnap:
        pos = soff
        if soff == 0 or soff >= size:
            snaps["stopped"] = "the snapshot table offset is %s" % ("0" if soff == 0 else "outside the file")
        else:
            for index in range(min(nsnap, max_snapshots)):
                clock.check(1024)
                raw = read_at(fh, pos, 40)
                if len(raw) < 40:
                    snaps["stopped"] = "the file ends inside entry %d" % index
                    break
                (l1o, l1s, idsz, namesz, dsec, dnsec, vmclock, vmstate, extra) = struct.unpack(">QIHHIIQII", raw)
                if idsz == 0:
                    snaps["stopped"] = "entry %d has an empty id string: the table ends or is damaged here" % index
                    break
                if extra > 65536 or pos + 40 + extra + idsz + namesz > size:
                    snaps["stopped"] = "entry %d declares sizes that run past the file or over 64 KiB of extra data" % index
                    break
                body = read_at(fh, pos + 40, extra + idsz + namesz)
                sid = decode(body[extra:extra + idsz])
                sname = decode(body[extra + idsz:extra + idsz + namesz])
                snapshot_sink({"index": index, "id": sid, "name": sname, "date_utc": iso_utc(dsec), "date_raw": dsec, "date_nsec": dnsec,
                               "vm_clock_ns": vmclock, "vm_state_size": vmstate, "l1_size": l1s, "l1_table_offset": l1o})
                snaps["read"] += 1
                pos += (40 + extra + idsz + namesz + 7) & ~7
            if snaps["read"] < nsnap and not snaps["stopped"]:
                snaps["stopped"] = "max_snapshots (%d) was reached" % max_snapshots
    info["internal_snapshots"] = snaps
    data_file = {"named": ext_data, "feature_bit": bool(version == 3 and "external_data_file" in info.get("incompatible_feature_names", []))}
    if data_file["feature_bit"] and not ext_data:
        gaps.append("the header sets the external data file bit and no external data file name was read: the guest data lives in a file this set does not name")
    if gaps:
        info["record_gaps"] = gaps
    out = {"state": "parsed", "info": info, "markers": markers, "gaps": gaps, "qcow2": {"hints": hints, "backing_format": backing_format, "data_file": data_file}}
    if snaps["read"] < nsnap:
        # the table declares more snapshots than were read: the image is not read whole, whatever stopped the read
        out["state"] = "partial"
        out["reason"] = "the header declares %d internal snapshot(s) and %d were read: %s" % (nsnap, snaps["read"], snaps["stopped"])
    return out


# ---- VMX and VMSD ----------------------------------------------------------------------------------------------------

CONFIG_KV = re.compile(r'^\s*([A-Za-z0-9_.:\-]+)\s*=\s*"(.*)"\s*$')
DISK_KEY = re.compile(r"^(scsi|ide|sata|nvme)\d+:\d+\.filename$", re.I)
SNAP_KEY = re.compile(r"^snapshot(\d+)\.(.+)$", re.I)


def read_config(fh, size):
    """Yield (line number, key, value) of the key = "value" lines of a .vmx or .vmsd, a line at a time."""
    n = 0
    while True:
        raw = fh.readline(MAX_CONFIG_LINE + 1)
        if not raw:
            return
        n += 1
        if n > MAX_CONFIG_LINES:
            yield n, None, "line cap"
            return
        if len(raw) > MAX_CONFIG_LINE:
            while raw and not raw.endswith(b"\n"):
                raw = fh.readline(MAX_CONFIG_LINE)
            yield n, None, "over-long line"
            continue
        m = CONFIG_KV.match(raw.decode("utf-8", "surrogateescape").rstrip("\r\n"))
        if m:
            yield n, m.group(1), m.group(2)


class ConfigGaps:
    """The lines of a .vmx or .vmsd that were not read: a line over MAX_CONFIG_LINE bytes, and everything after line MAX_CONFIG_LINES."""

    def __init__(self):
        self.long = 0
        self.first_long = None
        self.capped = False

    def note(self, n, why):
        if why == "line cap":
            self.capped = True
        else:
            self.long += 1
            if self.first_long is None:
                self.first_long = n

    def reasons(self):
        out = []
        if self.long:
            out.append("%d line(s) over %d bytes were not read (the first is line %d)" % (self.long, MAX_CONFIG_LINE, self.first_long))
        if self.capped:
            out.append("the file has more than %d lines: the lines after them were not read" % MAX_CONFIG_LINES)
        return out

    def settle(self, result):
        """The result of a parser, made partial with the reasons when any line was not read."""
        reasons = self.reasons()
        if reasons:
            result["state"] = "partial"
            result["reason"] = "; ".join(reasons)
        return result


def parse_vmx(fh, size):
    disks, problems, keys, gaps = [], [], 0, ConfigGaps()
    for n, key, value in read_config(fh, size):
        if key is None:
            gaps.note(n, value)
            continue
        keys += 1
        if DISK_KEY.match(key):
            disks.append({"key": key, "file": value, "line": n})
    return gaps.settle({"state": "parsed", "info": {"format": "vmx", "keys_read": keys, "disk_entries": len(disks), "note": WITHHELD_CONFIG_NOTE},
                        "vmx": {"disks": disks, "problems": gaps.reasons()}})


def parse_vmsd(fh, size):
    entries = collections.OrderedDict()
    top, over, gaps = {}, 0, ConfigGaps()
    for n, key, value in read_config(fh, size):
        if key is None:
            gaps.note(n, value)
            continue
        low = key.lower()
        if low in ("snapshot.numsnapshots", "snapshot.current", "snapshot.lastuid"):
            top[low.split(".", 1)[1]] = value
            continue
        m = SNAP_KEY.match(key)
        if not m:
            continue
        idx = int(m.group(1))
        if idx not in entries:
            if len(entries) >= MAX_SNAPSHOT_ENTRIES:
                over += 1
                continue
            entries[idx] = {"index": idx, "line": n, "disks": {}}
        sub, e = m.group(2), entries[idx]
        sl = sub.lower()
        dm = re.match(r"^disk(\d+)\.(.+)$", sl)
        if dm:
            if dm.group(2) == "filename":
                e["disks"][int(dm.group(1))] = value
        elif sl in ("uid", "filename", "displayname", "parent", "numdisks", "createtimehigh", "createtimelow", "type", "description", "id"):
            e[sl] = value
    return gaps.settle({"state": "parsed", "info": {"format": "vmsd", "snapshots_listed": len(entries), "snapshot_entries_over_cap": over,
                                                    "numsnapshots": top.get("numsnapshots"), "current": top.get("current"), "lastuid": top.get("lastuid")},
                        "vmsd": {"entries": list(entries.values()), "over": over, "top": top, "problems": gaps.reasons()}})


# ---- classification --------------------------------------------------------------------------------------------------

def classify(rec, fh, size):
    head = fh.read(min(size, 65536))
    name = rec["rel"].lower()
    if head[:4] == b"KDMV":
        return "vmdk_sparse", head
    if head[:4] == b"COWD":
        return "vmdk_cowd", head
    if head[:4] == b"QFI\xfb":
        return "qcow2", head
    if head[:8] == b"vhdxfile":
        return "vhdx", head
    if head[:8] == b"conectix":
        return "vhd", head
    if size >= 512:
        fh.seek(size - 512)
        if fh.read(8) == b"conectix":
            return "vhd", head
    text = head[3:] if head[:3] == b"\xef\xbb\xbf" else head
    if text.lstrip()[:24].startswith(b"# Disk DescriptorFile"):
        return "vmdk_descriptor", head
    if name.endswith(".vmsd"):
        return "vmsd", head
    if name.endswith(".vmx"):
        return "vmx", head
    if name.endswith(".lck") or posixpath.basename(name).startswith(".lck-"):
        return "lock_file", head
    return "other", head


# ---- the run ---------------------------------------------------------------------------------------------------------

def qemu_format(kind):
    return {"vmdk": "vmdk", "vhd": "vpc", "vhdx": "vhdx", "qcow2": "qcow2"}.get(kind)


# qemu's names for formats, as a QCOW2 backing-format extension writes them, against this tool's
QEMU_FORMAT_NAMES = {"vpc": "vhd", "vmdk": "vmdk", "vhdx": "vhdx", "qcow2": "qcow2", "raw": "raw", "file": "raw", "host_device": "raw"}


def run_qemu(path, kind, seconds):
    fmt = qemu_format(kind)
    if not path.startswith("/"):
        path = "./" + path                  # a relative name that begins with json:, nbd: or - must not be read as a protocol or an option
    argv = ["qemu-img", "info", "--output=json", "-f", fmt, path]
    code, out, err, timed_out = preflight(argv, seconds)
    result = {"command_format": fmt, "exit_code": code, "timed_out": timed_out}
    if code is None and not timed_out:
        result["available"] = False
        result["error"] = brief(err.decode("utf-8", "replace"), 300)
        return result
    result["available"] = True
    if timed_out or code != 0:
        result["error"] = brief(err.decode("utf-8", "replace"), 400) or ("timed out" if timed_out else "exit code %s, nothing on stderr" % code)
        return result
    try:
        data = json.loads(out[:1 << 20].decode("utf-8", "replace"))
        result.update({"format": data.get("format"), "virtual_size": data.get("virtual-size"), "actual_size": data.get("actual-size"),
                       "backing_filename": seal_head(str(data["backing-filename"]), "text") if data.get("backing-filename") else None,
                       "backing_filename_format": data.get("backing-filename-format"), "dirty_flag": data.get("dirty-flag")})
    except (ValueError, AttributeError):
        result["error"] = "qemu-img printed output that is not JSON"
    return result


CHAIN_ORDER = ("cycle", "too_deep", "broken", "record_incomplete", "parent_unreadable", "identity_not_compared", "identity_mismatch", "extent_missing", "data_file_missing")
CHAIN_DETAIL = {
    "broken": "the parent %s names is not in the set",
    "record_incomplete": "the descriptor or header of %s was not read whole or is inconsistent as written (see its markers): the parent and the extents it names are not all known",
    "parent_unreadable": "the parent of %s is in the set and could not be read as a disk (failed, unsupported, a bare extent or another kind of file): its identity was not compared",
    "identity_not_compared": "the identity of %s's parent could not be compared: one side records none, a value that is not one, or the parent is a disk of another format",
    "identity_mismatch": "the identity %s records for its parent is not the identity the parent file carries",
    "extent_missing": "an extent %s's descriptor needs is missing from the set or shorter than the descriptor says",
    "data_file_missing": "the external data file %s's header names is not in the set",
}


def main():
    args = read_args()
    root = want_str(args, "root")
    paths = want_str_list(args, "paths", 100000)
    if root is None and not paths:
        fail("name the evidence: root is a directory of descriptors and images, paths is a list of files")
    limit = want_int(args, "limit", DEFAULT_LIMIT, 1, 100000)
    max_files = want_int(args, "max_files", 20000, 1, 200000)
    max_entries = want_int(args, "max_entries", 200000, 1, 2000000)
    max_depth = want_int(args, "max_depth", 16, 1, 64)
    max_snapshots = want_int(args, "max_snapshots", DEFAULT_MAX_SNAPSHOTS, 1, 1000000)
    max_chain = want_int(args, "max_chain_depth", 10000, 1, 1000000)
    seconds = want_seconds(args, "max_seconds", DEFAULT_SECONDS, MAX_SECONDS)
    qemu_mode = args.get("qemu_img", "off")
    if qemu_mode not in ("off", "auto", "require"):
        fail("qemu_img must be off, auto or require")
    qemu_max = want_int(args, "qemu_img_max_images", 50, 1, 1000)
    write_text = want_flag(args, "write_text")
    try:
        values = TextFile("chain-values.jsonl", write_text, "JSON Lines, mode 0600: record_type original, where (a source id and the field), field, value (the "
                          "original text of a name, hint or snapshot name the answer shows withheld or shortened)")
    except TextRefused as exc:
        fail(str(exc))
    try:
        bind_values(write_text, TOOL)         # the originals of what the one way out withholds (the same job and secret-output rules as the text file: it was checked first)
    except ValuesRefused as exc:
        values.close()
        fail(str(exc))
    seal_stop_after(seconds + 6.5)            # no judging runs on past this (the manifest allows 60); the tool's own clock below runs out first
    shown = Shower(values)
    # The reading stops at four fifths of max_seconds; the rest is for writing the rows and the answer, which stop at
    # max_seconds itself, so that the call ends near the time asked for even when a stop leaves many rows to write.
    clock = Clock(seconds * 0.8)
    out_clock = Clock(seconds * 0.9)     # the rows and the answer end a tenth of the time before max_seconds: writing them took up to 12 s on a loaded host
    at_limit = "max_seconds (%s; the reading stops at four fifths of it)" % seconds
    files = FileSet(shown)
    partial = []
    try:
        files.walk(root, paths, max_files, max_entries, max_depth, clock)
    except Overtime:
        partial.append("the walk stopped at %s: the files after the last one listed were not reached" % at_limit)
    if files.truncated:
        partial.append(files.truncated)
    index = Index(files.files)

    pages = {k: LosslessPage(TOOL, k, limit) for k in ("sources", "disks", "edges", "chains", "extents", "snapshot_database", "internal_snapshots", "markers")}
    nodes, vmx_list, vmsd_list = {}, [], []
    kinds = collections.Counter()
    kind_of = {}
    other_ext = collections.Counter()
    state_counts = collections.Counter()
    problems = []                      # files recognised and not read
    damaged = []                       # files read whose header checksum does not hold: (id, what)
    config_total = {"disks": 0, "snapshots": 0, "dropped": 0}

    def marker(kind, ids, observation, reading, corroborate=None, **extra):
        """A marker row: every text in it is shown through the shape check, whatever was put into it."""
        row = {"kind": kind, "source_ids": ids, "observation": shown(observation, "marker", kind), "reading": shown(reading, "marker", kind),
               "corroborate": shown(corroborate or "the VM's own records of the operation (task or event log), the file times and a second copy", "marker", kind)}
        for key, value in extra.items():
            row[key] = shown(value, "marker", key) if isinstance(value, str) else value
        pages["markers"].add(row)

    def snapshot_sink_for(fid):
        def sink(row):
            row = dict(row)
            row["source_id"] = fid
            row["id"] = shown(row["id"], fid, "snapshot id")
            row["name"] = shown(row["name"], fid, "snapshot name")
            pages["internal_snapshots"].add(row)
        return sink

    disks, extent_targets, extents_over = {}, {}, []
    node_issue = collections.defaultdict(dict)     # disk id -> {issue kind: the disk it is about}

    def build_disk(fid, res):
        rec = res["rec"]
        kind = res["row"]["kind"]
        d = {"id": fid, "file": res["row"]["file"], "rel": rec["rel"], "state": res["state"], "has_identity": False, "own_id": None, "parent_id": None, "hints": []}
        if kind == "vmdk_cowd":
            d["role"] = "extent_only"
            disks[fid] = d
            return
        if kind in ("vmdk_descriptor", "vmdk_sparse"):
            desc = res.pop("descriptor", None)
            if kind == "vmdk_sparse" and desc is None:
                d["role"] = "extent_only"
                disks[fid] = d
                return
            if desc is None:
                disks[fid] = d
                return
            node = descriptor_node(desc, "embedded in a sparse extent" if kind == "vmdk_sparse" else "text descriptor", shown, fid)
            if kind == "vmdk_sparse":
                node["sparse_header"] = res["row"]["info"]
            d.update(format="vmdk", has_identity=node["cid"] is not None, own_id=node["cid"], parent_id=node["parent_cid"] if node["has_parent"] else None,
                     hints=[desc["fields"]["parentfilenamehint"]] if desc["fields"].get("parentfilenamehint") else [], has_parent=node["has_parent"], detail=node)
            gaps = res.get("gaps") or []
            if gaps:
                node["record_gaps"] = gaps
                node_issue[fid].setdefault("record_incomplete", fid)
                for gap in gaps:
                    marker("descriptor_problem", [fid], gap, "the descriptor was not read whole or is inconsistent as written; the chain through it is not read further than it says")
            # a sparse VMDK of capacity 0 is read by qemu-img through its embedded descriptor, which names its extents (any file): see names_other_files
            names_other = kind == "vmdk_sparse" and (capacity_is_zero(res) or bool(gaps) or desc["extents_total"] > len(desc["extents"]))
            for i, ext in enumerate(desc["extents"]):
                clock.check(256)
                target, how = (None, "no_name")
                if ext["name"] is not None and ext["type"] not in NOT_A_FILE_EXTENT:
                    target, how = index.resolve(rec["rel"], ext["name"].replace('\\"', '"'))
                erow = {"descriptor_id": fid, "index": i, "line": ext["line"], "access": ext["access"], "sectors": ext["sectors"],
                        "type": ext["type"] if ext["type"] in KNOWN_EXTENT_TYPES else shown(ext["type_raw"], fid, "extent type"),
                        "file": shown(ext["name"], fid, "extent file name") if ext["name"] is not None else None, "offset_sectors": ext["offset"],
                        "found": target["id"] if target else None, "resolution": how}
                if ext["name"] is not None and ext["type"] not in NOT_A_FILE_EXTENT and not (target is not None and target["id"] == fid and how == "relative_exact"):
                    names_other = True                      # an extent that is not, as written, this very file: qemu-img would open the name as it is
                if ext["name"] is None or ext["type"] in NOT_A_FILE_EXTENT:
                    erow["state"] = "not_a_file_extent"
                elif target is None:
                    erow["state"] = "missing"
                    node_issue[fid].setdefault("extent_missing", fid)
                    marker("extent_missing", [fid], "extent %d of the descriptor names a file that is not in the set (%s)" % (i, how),
                           "the disk cannot be read whole from this set; whether the file existed is not shown", line=ext["line"])
                else:
                    if target["id"] != fid:                # a monolithic sparse disk names its own file as its extent
                        extent_targets[target["id"]] = fid
                    if ext["type"] in ("FLAT", "VMFS"):
                        expected = (ext["sectors"] + (ext["offset"] or 0)) * 512
                        erow["expected_size_at_least"] = expected
                        erow["actual_size"] = target["size"]
                        erow["state"] = "short" if target["size"] < expected else "present"
                        if erow["state"] == "short":
                            node_issue[fid].setdefault("extent_missing", fid)
                            marker("extent_short", [fid, target["id"]], "extent %d is %d bytes and the descriptor needs at least %d" % (i, target["size"], expected),
                                   "the extent file is smaller than the descriptor says: truncated, partly copied or rewritten", line=ext["line"])
                    else:
                        erow["state"] = "present"
                        erow["size_check"] = "not made: a sparse extent has no size to compare"
                pages["extents"].add(erow)
            if desc["extents_total"] > len(desc["extents"]):
                node_issue[fid].setdefault("extent_missing", fid)
                extents_over.append(fid)
            d["names_other_files"] = names_other
        elif kind == "vhd":
            v = res.get("vhd")
            if v:
                d.update(format="vhd", has_identity=True, own_id=v["identity"], parent_id=v["parent_identity"], hints=v["hints"], has_parent=res["row"]["info"].get("disk_type") == "differencing", detail=res["row"]["info"])
        elif kind == "vhdx":
            v = res.get("vhdx")
            if v:
                d.update(format="vhdx", has_identity=bool(v["identity"]), own_id=v["identity"], parent_id=v["parent_identity"], parent_id_2=v.get("parent_identity_2"),
                         hints=v["hints"], has_parent=bool(res["row"]["info"].get("has_parent")), detail=res["row"]["info"])
        elif kind == "qcow2":
            v = res.get("qcow2")
            if v:
                d.update(format="qcow2", has_identity=False, hints=v["hints"], has_parent=bool(v["hints"]), detail=res["row"]["info"], backing_format=v.get("backing_format"))
                for gap in res.get("gaps") or []:
                    node_issue[fid].setdefault("record_incomplete", fid)
                    marker("descriptor_problem", [fid], gap, "the header was not read whole or is inconsistent as written; the backing file and the data file it names are not all known")
                data_file = v.get("data_file") or {}
                d["external_data_file"] = bool(data_file.get("named") or data_file.get("feature_bit"))
                if data_file.get("named"):
                    target, how = index.resolve(rec["rel"], data_file["named"])
                    d["detail"]["external_data_file_found"] = target["id"] if target else None
                    d["detail"]["external_data_file_resolution"] = how
                    if target is None:
                        node_issue[fid].setdefault("data_file_missing", fid)
                        marker("external_data_file_missing", [fid], "the header names an external data file that is not in the set (%s)" % how,
                               "the guest data of this image lives in that file; without it the image cannot be read whole from this set")
        disks[fid] = d

    examined = 0
    try:
        for rec in files.files:
            clock.check()
            fh, why = open_regular(rec["path"])
            if fh is None:
                files.note("unreadable", rec["rel"] + ": " + (why or ""))
                kind_of[rec["id"]] = "unreadable"
                continue
            with fh:
                kind, head = classify(rec, fh, rec["size"])
                kinds[kind] += 1
                kind_of[rec["id"]] = kind
                if kind == "other":
                    ext = ext_of(rec["rel"])
                    other_ext[ext if (ext in other_ext or len(other_ext) < 2000) else "(other extensions)"] += 1
                    continue
                examined += 1
                row = {"source_id": rec["id"], "file": shown(rec["rel"], rec["id"], "file"), "size": rec["size"], "kind": kind}
                try:
                    if kind == "vmdk_sparse":
                        res = parse_vmdk_sparse(fh, rec["size"], head)
                    elif kind == "vmdk_descriptor":
                        d, over = parse_vmdk_text(fh, rec["size"], head)
                        res = {"state": "parsed", "info": {"format": "vmdk"}, "descriptor": d}
                    elif kind == "vmdk_cowd":
                        res = {"state": "parsed", "info": {"format": "vmdk_cowd_extent", "header_read": False,
                                                          "note": "a COWD sparse extent (the delta of a VMFS sparse snapshot) is recognised by its first four bytes; its header is not read, because the chain is in the descriptor that names it"}}
                    elif kind == "vhd":
                        res = parse_vhd(fh, rec["size"], head)
                    elif kind == "vhdx":
                        res = parse_vhdx(fh, rec["size"], head)
                    elif kind == "qcow2":
                        res = parse_qcow2(fh, rec["size"], head, snapshot_sink_for(rec["id"]), max_snapshots, clock)
                    elif kind in ("vmx", "vmsd"):
                        if rec["size"] > MAX_CONFIG_BYTES:
                            res = {"state": "failed", "reason": "a configuration file over %d bytes is named and not read" % MAX_CONFIG_BYTES, "info": {"format": kind},
                                   "vmx": {"disks": [], "problems": []}, "vmsd": {"entries": [], "over": 0, "top": {}, "problems": []}}
                        else:
                            fh.seek(0)
                            res = parse_vmx(fh, rec["size"]) if kind == "vmx" else parse_vmsd(fh, rec["size"])
                    elif kind == "lock_file":
                        res = {"state": "parsed", "info": {"format": "lock_file"},
                               "markers": [{"kind": "lock_artefact", "observation": "a file named like a lock file is present",
                                            "reading": "a lock is made while a program holds the disk or the VM; it can be a copy of a live VM's directory or a left-over after a crash: a candidate"}]}
                    else:
                        res = {"state": "unsupported", "reason": "unknown kind"}
                except (struct.error, ValueError, OverflowError, MemoryError) as exc:
                    res = {"state": "failed", "reason": "the structure could not be read (%s)" % describe(exc)}
                except OSError as exc:
                    res = {"state": "failed", "reason": "a read failed (%s)" % describe(exc)}
            gaps = descriptor_gaps(res["descriptor"]) if res.get("descriptor") is not None else (res.get("gaps") or [])
            if gaps and res["state"] in ("parsed", "partial"):
                res["gaps"] = gaps
                if res["state"] == "parsed":
                    res["state"], res["reason"] = "partial", "; ".join(gaps)
                elif not res.get("reason"):
                    res["reason"] = "; ".join(gaps)
                else:
                    res["reason"] += "; " + "; ".join(gaps)
            state_counts[res["state"]] += 1
            row["state"] = res["state"]
            if res.get("reason"):
                row["reason"] = res["reason"]
            if res["state"] in ("failed", "unsupported", "partial"):
                problems.append(rec["id"])
            net = make_net(shown, rec["id"])
            row["info"] = net(res.get("info") or {})
            for m in res.get("markers") or []:
                marker(m["kind"], [rec["id"]], m["observation"], m["reading"])
            for what in res.get("damaged") or []:
                damaged.append((rec["id"], what))
            res["row"] = row
            res["rec"] = rec
            pages["sources"].add(row)
            if kind == "vmx":
                res.setdefault("vmx", {"disks": [], "problems": []})
                config_total["disks"] += len(res["vmx"]["disks"])
                if config_total["disks"] > MAX_CONFIG_ENTRIES_TOTAL:
                    res["vmx"]["disks"] = []
                    config_total["dropped"] += 1
                vmx_list.append(res)
            elif kind == "vmsd":
                res.setdefault("vmsd", {"entries": [], "over": 0, "top": {}, "problems": []})
                config_total["snapshots"] += len(res["vmsd"]["entries"])
                if config_total["snapshots"] > MAX_CONFIG_ENTRIES_TOTAL:
                    res["vmsd"]["entries"] = []
                    config_total["dropped"] += 1
                vmsd_list.append(res)
            elif kind in ("vmdk_descriptor", "vmdk_sparse", "vmdk_cowd", "vhd", "vhdx", "qcow2"):
                res["rec"], res["row"] = rec, row
                build_disk(rec["id"], res)
                nodes[rec["id"]] = {"rec": rec, "row": {"kind": kind}}
    except Overtime:
        partial.append("the examination stopped at %s: the files after the last one listed in sources were not read" % at_limit)

    parent_of, edge_of = {}, {}
    too_deep_leaves = []               # chain rows the max_chain_depth limit stopped
    depth, base, state_of, first_issue, cycle_of = {}, {}, {}, {}, {}
    chain_summary = collections.Counter()
    phase = "the parent edges"
    try:
        # ---- edges: one per disk that records a parent ----------------------------------------------------------------
        for fid, d in disks.items():
            clock.check(256)
            if d.get("role") == "extent_only" or not d.get("format") or not d.get("has_parent"):
                continue
            target, how, resolved = None, "no_name", []
            for h in d["hints"]:
                t, w = index.resolve(d["rel"], h)
                resolved.append((t, w))
                if target is None and t:
                    target, how = t, w
            if target is None and resolved:
                how = resolved[0][1]
            edge = {"child": fid, "parent_name": shown(d["hints"][0], fid, "parent name") if d["hints"] else None, "names_tried": len(d["hints"]),
                    "resolved_to": target["id"] if target else None, "resolution": how, "id_check": "not_available", "format": d["format"]}
            if d["format"] in ("vhd", "vhdx") and len(d["hints"]) > 1:
                found = sorted({t["id"] for t, _w in resolved if t})
                names = {posixpath.basename(h.replace("\\", "/")).casefold() for h in d["hints"]}
                if len(found) > 1 or len(names) > 1:
                    edge["parent_names_disagree"] = True
                    marker("parent_names_disagree", [fid] + found, "the %d parent names the child records (the header's name and its locators) do not name one file: %d different file name(s), %d file(s) of the set" % (len(d["hints"]), len(names), len(found)),
                           "the locators were written at different times or edited; which of them the hypervisor would follow is not decided here (the first name that resolves is used)")
            pkind = kind_of.get(target["id"]) if target else None
            pdisk = disks.get(target["id"]) if target else None
            if target is None:
                edge["parent_state"] = "not in the set"
                node_issue[fid].setdefault("broken", fid)
            elif pdisk is None or pdisk.get("role") == "extent_only" or not pdisk.get("format") or pdisk["state"] in ("failed", "unsupported"):
                bf = QEMU_FORMAT_NAMES.get((d.get("backing_format") or "").lower(), None) if d.get("backing_format") else None
                raw_base = d["format"] == "qcow2" and pkind == "other" and (d.get("backing_format") is None or bf == "raw")
                if raw_base:
                    edge["parent_state"] = "raw or unread"
                    edge["parent_note"] = "the backing file is in the set and is raw or of a kind this tool does not read: present, not examined (a raw base records no identity, and QCOW2 records none of its backing file)"
                else:
                    edge["parent_state"] = ("a sparse extent without a descriptor of its own" if pdisk is not None and pdisk.get("role") == "extent_only" else
                                            "the file is in the set and is not a disk this tool reads" if pdisk is None and pkind in ("other", "vmx", "vmsd", "lock_file") else
                                            "the file is in the set and could not be opened" if pdisk is None and pkind == "unreadable" else
                                            "the file is in the set and was not read (the examination stopped before it)" if pdisk is None else pdisk["state"])
                    if d.get("backing_format") and pkind == "other":
                        edge["format_note"] = "the child says the backing file is %s and the file found is not one this tool reads" % shown(d["backing_format"], fid, "backing format")
                    node_issue[fid].setdefault("parent_unreadable", fid)
            else:
                edge["parent_state"] = pdisk["state"]
                if d["format"] in ("vmdk", "vhd", "vhdx"):
                    want, have = d.get("parent_id"), pdisk.get("own_id")
                    if pdisk["format"] != d["format"]:
                        edge["id_check"] = "not_available"
                        edge["format_note"] = "the parent is a %s file and the child a %s file" % (pdisk["format"], d["format"])
                        node_issue[fid].setdefault("identity_not_compared", fid)
                    elif want and have:
                        if d["format"] == "vhdx":
                            edge["compared"] = "the child's parent_linkage with the parent's DataWriteGuid (MS-VHDX)"
                        if want.upper() == have.upper():
                            edge["id_check"] = "match"
                        elif d["format"] == "vhdx" and d.get("parent_id_2") and d["parent_id_2"].upper() == have.upper():
                            edge["id_check"] = "match_via_parent_linkage2"
                        else:
                            edge["id_check"] = "mismatch"
                            edge["recorded_by_child"] = want
                            edge["carried_by_parent"] = have
                            node_issue[fid].setdefault("identity_mismatch", fid)
                            marker({"vmdk": "parent_cid_mismatch", "vhd": "parent_unique_id_mismatch", "vhdx": "parent_linkage_mismatch"}[d["format"]], [fid, target["id"]],
                                   "the child records parent identity %s and the parent file carries %s" % (want, have),
                                   "the named parent is not the file the child was made against, or the parent was written after the child was made; the "
                                   "chain through this edge cannot be trusted as one history")
                    else:
                        edge["id_note"] = "an identity is missing on one side (the child's record or the parent's own): not compared"
                        node_issue[fid].setdefault("identity_not_compared", fid)
                elif d["format"] == "qcow2":
                    edge["id_check"] = "not_available"
                    edge["id_note"] = "QCOW2 records no identity of its backing file: the name is all the link there is"
                    bf = d.get("backing_format")
                    if bf:
                        theirs = QEMU_FORMAT_NAMES.get(bf.lower())
                        if theirs != pdisk["format"]:
                            edge["format_note"] = "the child says the backing file is %s and the file found is %s" % (shown(bf, fid, "backing format"), pdisk["format"])
            if target is not None:
                parent_of[fid] = target["id"]
            if not target and how == "ambiguous_basename":
                marker("parent_ambiguous", [fid], "the parent's name matches more than one file in the set by file name alone", "which file is the parent is not decided by the set")
            elif not target:
                marker("parent_missing", [fid], "the parent named by the child (%s) is not in the set" % how, "the chain is broken in this set: whether the parent existed, was deleted, "
                                                                                                        "or was not collected is not shown")
            edge_of[fid] = edge
            pages["edges"].add(edge)

        phase = "the extent and CID checks"
        for fid, d in disks.items():
            clock.check(256)
            if d.get("role") == "extent_only" and fid not in extent_targets:
                marker("extent_without_descriptor", [fid], "a sparse extent file is present and no descriptor in the set names it as an extent",
                       "its descriptor was not collected, was removed, or the extent belongs to a disk outside this set: a candidate; the descriptor, if found, holds the chain")
        by_cid = collections.defaultdict(list)
        for fid, d in disks.items():
            if d.get("format") == "vmdk" and d.get("own_id") and d["own_id"] != "ffffffff" and fid not in extent_targets:
                by_cid[d["own_id"]].append(fid)
        for cid, ids in by_cid.items():
            clock.check(256)
            if len(ids) > 1:
                marker("duplicate_cid", ids[:20], "%d descriptors carry the same CID %s" % (len(ids), cid),
                       "a copy of one descriptor, or a clone made without a new CID: a child's parentCID cannot tell these files apart, so an identity match "
                       "through any of them proves less", files_with_this_cid=len(ids))

        # ---- chains: each node's depth, base and first problem toward the base, found once (no recursion) -----------
        phase = "the chain walk"
        for start in disks:
            if start in depth:
                continue
            path_nodes, seen_here, cur = [], set(), start
            while True:
                clock.check(4096)
                if cur in depth:
                    outcome = ("known", cur)
                    break
                if cur in seen_here:
                    outcome = ("cycle", cur)
                    break
                if len(path_nodes) >= max_chain:
                    outcome = ("too_deep", cur)
                    break
                seen_here.add(cur)
                path_nodes.append(cur)
                nxt = parent_of.get(cur)
                if nxt is None:
                    outcome = ("end", cur)
                    break
                cur = nxt
            kind_, at = outcome
            if kind_ == "known":
                b, dp, st, fi, cy = base[at], depth[at], state_of[at], first_issue[at], cycle_of.get(at)
            elif kind_ == "end":
                b, dp, st, fi, cy = path_nodes[-1], 0, None, {}, None
            elif kind_ == "cycle":
                members = path_nodes[path_nodes.index(at):]
                cy = min(members)
                marker("chain_cycle", members[:20], "following parent names from %s returns to %s (%d file(s) on the cycle)" % (at, at, len(members)),
                       "the set contains files that name each other (or themselves) as parents; no history has a cycle, so at least one name or file is wrong",
                       files_on_cycle=len(members))
                for n in members:
                    depth[n], base[n], state_of[n], first_issue[n], cycle_of[n] = len(members), cy, "cycle", node_issue.get(n, {}), cy
                path_nodes = path_nodes[:path_nodes.index(at)]
                b, dp, st, fi = cy, len(members), "cycle", {}
            else:
                b, dp, st, fi, cy = at, 0, "too_deep", {}, None
            for n in reversed(path_nodes):
                dp += 1
                own = node_issue.get(n)
                fi = dict(fi, **own) if own else fi       # the issue nearest the leaf wins; a node with none shares its parent's
                depth[n], base[n], state_of[n], first_issue[n] = dp, b, st or ("too_deep" if dp > max_chain else None), fi
                if cy is not None:
                    cycle_of[n] = cy

        phase = "the chain rows"
        named_as_parent = set(parent_of.values())
        leaves = [f for f in disks if f not in named_as_parent and disks[f].get("role") != "extent_only" and disks[f].get("format") and f not in extent_targets]
        cycles_reached = set()

        def chain_row(leaf, status_override=None):
            ids, cur, seen = [], leaf, set()
            while cur and cur not in seen and len(ids) < MAX_CHAIN_SHOWN:
                ids.append(cur)
                seen.add(cur)
                cur = parent_of.get(cur)
            issues = first_issue.get(leaf, {})
            st = status_override or state_of.get(leaf)
            status, detail = "complete", None
            if st in ("cycle", "too_deep"):
                status = st
                detail = ("the chain from %s runs into a cycle" % leaf) if st == "cycle" else "the chain is deeper than max_chain_depth (%d)" % max_chain
            else:
                for k in CHAIN_ORDER[2:]:
                    if k in issues:
                        status, detail = k, CHAIN_DETAIL[k] % issues[k]
                        break
            row = {"leaf": leaf, "leaf_file": disks[leaf]["file"] if leaf in disks else None, "format": disks.get(leaf, {}).get("format"), "chain_length": depth.get(leaf, 1),
                   "base": base.get(leaf, leaf), "chain_shown": ids, "chain_shown_cut": depth.get(leaf, 1) > len(ids), "status": status, "detail": detail,
                   "issues": {k: issues[k] for k in CHAIN_ORDER if k in issues}}
            b = base.get(leaf, leaf)
            if b not in disks and st not in ("cycle", "too_deep"):
                row["base_note"] = "the base %s is in the set and is not a disk this tool reads (raw, another kind of file, or not opened): present, not examined" % b
            chain_summary[status] += 1
            if status == "too_deep":
                too_deep_leaves.append(leaf)
            pages["chains"].add(row)

        for leaf in leaves:
            clock.check(256)
            if cycle_of.get(leaf) is not None:
                cycles_reached.add(cycle_of[leaf])
            chain_row(leaf)
        for cy in sorted({c for c in cycle_of.values()} - cycles_reached):
            clock.check(256)
            chain_row(cy, "cycle")       # a cycle no leaf reaches (every file on it is named by another) has a row of its own

        # ---- the configuration files held against the descriptors -----------------------------------------------------
        phase = "the configuration files"
        snap_disk_names = {}
        for res in vmsd_list:
            rec = res["rec"]
            data = res["vmsd"]
            for e in data["entries"]:
                clock.check(256)
                names = [shown(n, rec["id"], "snapshot disk file") for n in e["disks"].values()]
                pages["snapshot_database"].add({"source_id": rec["id"], "index": e["index"], "line": e["line"], "uid": shown(e.get("uid"), rec["id"], "snapshot uid"), "parent": shown(e.get("parent"), rec["id"], "snapshot parent"),
                                                "display_name": shown(e.get("displayname"), rec["id"], "snapshot name") if e.get("displayname") is not None else None,
                                                "description_present": "description" in e, "state_file": shown(e.get("filename"), rec["id"], "snapshot state file") if e.get("filename") is not None else None,
                                                "disk_files": names, "create_time_high_raw": shown(e.get("createtimehigh"), rec["id"], "createTimeHigh"), "create_time_low_raw": shown(e.get("createtimelow"), rec["id"], "createTimeLow"),
                                                "create_time_note": "raw values as written; how the two fields encode a time is not decoded here"})
                for n in e["disks"].values():
                    target, how = index.resolve(rec["rel"], n)
                    snap_disk_names.setdefault(rec["id"], set()).add(target["id"] if target else None)
                    if target is None:
                        marker("snapshot_disk_missing", [rec["id"]], "snapshot %s of the database names a disk file that is not in the set (%s)" % (e["index"], how),
                               "the snapshot's disk is missing from this set: removed, never collected or renamed; the database entry alone does not say which", line=e["line"])
            if data["over"]:
                partial.append("a snapshot database lists more than %d snapshot indexes: the first %d are listed, %d more entries were counted and not listed" % (MAX_SNAPSHOT_ENTRIES, MAX_SNAPSHOT_ENTRIES, data["over"]))
        vmsd_by_dir = collections.defaultdict(list)
        for v in vmsd_list:
            if v["state"] == "parsed":               # a database that was not read says nothing about how many snapshots it lists
                vmsd_by_dir[posixpath.dirname(v["rec"]["rel"])].append(v)
        for res in vmx_list:
            rec = res["rec"]
            for dk in res["vmx"]["disks"]:
                clock.check(256)
                target, how = index.resolve(rec["rel"], dk["file"])
                d = disks.get(target["id"]) if target else None
                if d and d.get("has_parent"):
                    for v in vmsd_by_dir.get(posixpath.dirname(rec["rel"]), ()):
                        clock.check(256)
                        n = len(v["vmsd"]["entries"])
                        declared = v["vmsd"]["top"].get("numsnapshots")
                        if n == 0 or declared in ("0", 0):
                            marker("running_disk_is_a_delta_without_snapshots", [rec["id"], target["id"], v["rec"]["id"]],
                                   "the configuration's disk %s is a delta (it records a parent) and the snapshot database lists %s snapshot(s)" % (
                                       shown(dk["key"], rec["id"], "disk key"), shown(declared, v["rec"]["id"], "numSnapshots") if declared is not None else n),
                                   "a consolidation that did not finish, a snapshot removed without its delta merged, or a database that was not collected with the disk: a "
                                   "candidate; the VM's task log decides it", line=dk["line"])
        if vmsd_list:
            referenced = set()
            for ids in snap_disk_names.values():
                referenced.update(i for i in ids if i)
            for res in vmx_list:
                for dk in res["vmx"]["disks"]:
                    clock.check(256)
                    target, _how = index.resolve(res["rec"]["rel"], dk["file"])
                    if target:
                        referenced.add(target["id"])
            reachable, stack = set(), list(referenced)
            while stack:                          # the ancestors of every disk the configuration names are in use
                clock.check(4096)
                cur = stack.pop()
                if cur in reachable:
                    continue
                reachable.add(cur)
                if cur in parent_of:
                    stack.append(parent_of[cur])
            listing = [v["rec"]["id"] for v in vmsd_list][:20]
            for fid, d in disks.items():
                clock.check(256)
                if d.get("format") == "vmdk" and d.get("has_parent") and fid not in reachable and fid not in extent_targets:
                    marker("delta_not_in_snapshot_database", [fid] + listing,
                           "this descriptor records a parent, and it is neither named by the snapshot database or the configuration nor a parent of a disk they name",
                           "a delta left behind by a removed snapshot or a consolidation, or a file of another VM in the set: a candidate; the task log decides it")
        for rel in files.lock_dirs:
            marker("lock_artefact", [], "an entry named %s is present" % shown(rel, "walk", "lock directory"),
                   "a lock directory or file is made while a program holds the disk or the VM; it can be a copy of a live VM's directory or a left-over after a crash: a candidate")
    except Overtime:
        partial.append("%s was reached during %s: the rows after the last one listed were not made, and the chain rows, edges and markers "
                       "listed are the ones made before it" % (at_limit, phase))

    # ---- qemu-img, when asked ------------------------------------------------------------------------------------------
    qemu_report = {"mode": qemu_mode, "checked": 0, "available": None, "note": "qemu-img was not run (qemu_img: off); the reading above is the tool's own"}
    if qemu_mode != "off":
        qemu_report["note"] = ("qemu-img info was run once per image of the set with the format fixed and without --backing-chain; its answer sits beside the "
                               "native reading in `qemu_img` of the disk row and replaces nothing. A VMDK text descriptor, a sparse VMDK of capacity 0 or whose "
                               "embedded descriptor names a file other than itself, and a QCOW2 image with an external data file are not given to it (qemu-img "
                               "would open the files they name, which can lie outside the set), nor an extent another descriptor names (the disk is that "
                               "descriptor)")
        cross, failed_runs = [], []
        skipped = collections.Counter()
        skipped_first = {}
        count = 0
        for fid, d in disks.items():
            fmt_kind = {"vmdk": "vmdk", "vhd": "vhd", "vhdx": "vhdx", "qcow2": "qcow2"}.get(d.get("format"))
            if not fmt_kind or d.get("role") == "extent_only" or d["state"] != "parsed":
                continue
            why = None
            if d["format"] == "vmdk" and nodes[fid]["row"]["kind"] != "vmdk_sparse":
                why = "text_descriptor"           # qemu-img would open its extents by the names it holds
            elif d["format"] == "vmdk" and d.get("names_other_files"):
                why = "sparse_vmdk_names_other_files"  # capacity 0 (qemu-img reads the embedded descriptor as a descriptor file) or an embedded descriptor that names a file other than itself
            elif fid in extent_targets:
                why = "extent_of_another_descriptor"   # a split disk's extent: the disk is its descriptor, which qemu-img is not given
            elif d.get("external_data_file"):
                why = "external_data_file"        # qemu-img would open the data file by the name the header holds
            elif count >= qemu_max:
                why = "over_qemu_img_max_images"
            elif out_clock.left() < 2.5:
                why = "max_seconds"
            if why:
                skipped[why] += 1
                skipped_first.setdefault(why, fid)
                continue
            rec = nodes[fid]["rec"]
            result = run_qemu(rec["path"], fmt_kind, min(30.0, max(1.0, out_clock.left() - 1.5)))
            count += 1
            qemu_report["available"] = result.get("available")
            if result.get("available") is False:
                break
            d["qemu_img"] = result
            if result.get("timed_out") or result.get("exit_code") != 0 or result.get("error"):
                failed_runs.append(fid)
                continue
            native = d.get("detail") or {}
            if d["format"] == "vmdk":
                cap = (native.get("sparse_header") or {}).get("capacity_sectors")
                native_size = (cap if cap is not None else native.get("capacity_sectors_by_extents"))
                native_size = native_size * 512 if native_size is not None else None
            else:
                native_size = native.get("virtual_size") if d["format"] in ("qcow2", "vhdx") else native.get("current_size") if d["format"] == "vhd" else None
            if result.get("virtual_size") is not None and native_size is not None and result["virtual_size"] != native_size:
                marker("qemu_img_disagrees", [fid], "qemu-img reports virtual size %s and the header reads %s" % (result["virtual_size"], native_size),
                       "one of the two readings is wrong or the file is damaged; neither is preferred")
            cross.append(fid)
        qemu_report["checked"] = len(cross)
        qemu_report["failed"] = len(failed_runs)
        qemu_report["failed_first"] = failed_runs[:20]
        qemu_report["skipped"] = dict(skipped)
        qemu_report["skipped_first"] = skipped_first
        if qemu_mode == "require" and qemu_report["available"] is False:
            fail("qemu_img: require was asked for and qemu-img is not on PATH (the base pack lists it as optional: check the image the job runs in)")
        if qemu_report["available"] is False:
            qemu_report["note"] = "qemu-img is not on PATH here (the base pack lists it as optional): the native reading above is all there is"
        else:
            if failed_runs:
                partial.append("qemu-img failed, timed out or printed no JSON on %d image(s) (first %s): the second reading of those is missing" % (len(failed_runs), failed_runs[0]))
            for why in ("over_qemu_img_max_images", "max_seconds"):
                if skipped.get(why):
                    partial.append("qemu-img was not run on %d eligible image(s) (%s; first %s)" % (skipped[why], "qemu_img_max_images (%d) was reached" % qemu_max if why != "max_seconds" else "max_seconds was near", skipped_first[why]))
            if qemu_report["checked"] == 0 and not failed_runs:
                qemu_report["note"] += "; no parsed image was eligible"
        if SUB["tried"]:
            # qemu-img's second reading is what it printed on a pipe, so a host that cannot show that nothing was left does not make the answer partial (program_group says so);
            # a process settle() ended is a fact: the pipe was let go at the grace, and what the process would still have printed is not in the second reading.
            if PIPE_CUT["cut"] and not process_verdict()["left_behind"]:
                partial.append("a process that held qemu-img's pipe after it ended went on writing: the tool read %d bytes of it and let the pipe go, so the second reading is not trusted" % POST_EXIT_BYTES)
            if process_verdict()["left_behind"]:
                partial.append("qemu-img left %d process(es) running after it ended (in the tool's process group, in a session of its own, or after a double fork); the shared process block stopped, "
                               "killed and reaped them, so what they would still have printed is not in the second reading" % process_verdict()["left_behind"])

    # ---- disks page ------------------------------------------------------------------------------------------------
    listed = 0
    for fid, d in disks.items():
        try:
            out_clock.check(256)
        except Overtime:
            partial.append("max_seconds (%s) was reached while the disk rows were written: %d of %d are listed (the edges and chains name the rest by id)" % (seconds, listed, len(disks)))
            break
        listed += 1
        row = {"source_id": fid, "file": d["file"], "format": d.get("format"), "state": d["state"], "role": d.get("role", "disk"),
               "own_id": d.get("own_id"), "records_a_parent": bool(d.get("has_parent")), "is_extent_of": extent_targets.get(fid),
               "depth": depth.get(fid), "base": base.get(fid), "chain_state": state_of.get(fid), "detail": make_net(shown, fid)(d.get("detail"))}
        if d.get("format") == "vhdx":
            row["own_id_field"] = "DataWriteGuid of the current header (what a child's parent_linkage records)"
        if d.get("qemu_img"):
            row["qemu_img"] = d["qemu_img"]
        pages["disks"].add(row)

    if damaged:
        partial.append("%d header(s) failed their checksum (first %s: %s): read as written and named in markers; what they record may be wrong" % (len(damaged), damaged[0][0], damaged[0][1]))
    if too_deep_leaves:
        partial.append("max_chain_depth (%d) was reached on %d chain(s) (first leaf %s): those chains were not followed to their base" % (max_chain, len(too_deep_leaves), too_deep_leaves[0]))
    if extents_over:
        partial.append("%d descriptor(s) list more than %d extents (first %s): the first %d of each were checked and the rest are counted in extents_total" % (len(extents_over), MAX_EXTENTS, extents_over[0], MAX_EXTENTS))
    if config_total["dropped"]:
        partial.append("the .vmx and .vmsd files hold more than %d entries between them: %d file(s) were counted and their entries were not held against the descriptors" % (MAX_CONFIG_ENTRIES_TOTAL, config_total["dropped"]))
    values.close()
    result_pages = {k: v.finish() for k, v in pages.items()}
    all_parsed = not problems
    complete = all_parsed and not partial and not files.skipped_counts["unreadable"] and not files.skipped_counts["too_deep"]
    outcome = status_of(complete, bool(files.files) and examined == 0 and bool(problems),
                        "every recognised file in the set was read, none was left out, and every limit held",
                        "%d recognised file(s) were not read whole (failed, unsupported or partial), %d unreadable, %d directory(ies) too deep%s: the answer names them" % (
                            len(problems), files.skipped_counts["unreadable"], files.skipped_counts["too_deep"], ("; " + "; ".join(partial)) if partial else ""),
                        "no recognised file could be read")
    recognised = sum(c for k, c in kinds.items() if k != "other")
    if files.files and not recognised and outcome["status"] == "complete":
        outcome = {"status": "complete", "status_basis": "the set holds no file of a kind this tool reads (%d other file(s), counted by extension): zero disks is a statement about this tool's formats, not about the VM" % sum(other_ext.values())}
    if not files.files:
        skipped = sum(files.skipped_counts.values())
        outcome = ({"status": "partial", "status_basis": "the set holds no file that could be read; %d entr(ies) were skipped (links, special files, directories too deep, unreadable)%s: the answer names them" % (skipped, ("; " + "; ".join(partial)) if partial else "")}
                   if skipped or partial else {"status": "failed", "status_basis": "the set holds no file"})
    emit(big_ints({
        "parser": PARSER, **outcome,
        "root": files.root_shown, "files_in_set": len(files.files), "kinds": dict(kinds), "other_files_by_extension": dict(other_ext.most_common(20)),
        "other_files_note": "files of no kind this tool reads are counted by extension and not examined (an extension that is not 1 to 10 letters or digits is counted under (other extensions) and not shown); absence of a disk here is not absence of a disk",
        "states": dict(state_counts), "recognised_not_read_whole": problems[:200],
        "sources": pages["sources"].page, "disks": pages["disks"].page, "edges": pages["edges"].page, "chains": pages["chains"].page,
        "extents": pages["extents"].page, "snapshot_database": pages["snapshot_database"].page, "internal_snapshots": pages["internal_snapshots"].page,
        "markers": pages["markers"].page, "pages": result_pages,
        "chain_summary": dict(chain_summary),
        "chain_note": ("A chain is complete when every parent a disk names is in the set, can be read, and carries the identity the child recorded where the format "
                       "records one, every extent and data file its disks name is in the set, and every descriptor and header on it was read whole and says nothing "
                       "that cannot be followed. Otherwise its status names the first problem from the leaf "
                       "(cycle, too_deep, broken, record_incomplete, parent_unreadable, identity_not_compared, identity_mismatch, extent_missing, data_file_missing) and `issues` lists each kind found. "
                       "record_incomplete: a descriptor or header the tool did not read whole (a line, size or extension cap, an extent line it could not read, no extent line, "
                       "a backing file name or external data file name it could not take) or a record it cannot follow (a CID that is not a number, a parent CID with no parent file name): "
                       "what that file names as a parent or an extent is not all known, whatever the rest of the chain looks like. "
                       "It is not a disk that boots, and it says nothing about the parent's content when the child was made. A QCOW2 child that declares its backing "
                       "format as qcow2 over a file that is raw (or any file this tool does not read as a disk) is `parent_unreadable`: the file found is not the format the child "
                       "declares, and no identity of it is compared."),
        "walk": files.skipped_summary(), "walk_truncated": files.truncated, "partial_reasons": partial, "lock_directories_total": files.lock_dirs_total,
        "qemu_img": qemu_report, **({"program_group": process_verdict()} if SUB["tried"] else {}),
        "text": values.summary(), "withheld": withheld_summary(shown),
        "truncated": any(p["truncated"] for p in result_pages.values()),
        "limits": {"max_files": max_files, "max_entries": max_entries, "max_depth": max_depth, "max_snapshots": max_snapshots, "max_chain_depth": max_chain, "descriptor_read_cap": MAX_DESCRIPTOR},
        "note": "Markers are candidates with the observation beside them. A header or a descriptor says what its writer recorded; it does not say who or what wrote it, when, or why. "
                "Corroborate with the hypervisor's own task and event records before calling a snapshot deleted, a consolidation failed or a disk tampered with.",
    }), indent=2)
    close_values()
    return 0 if outcome["status"] != "failed" else 1


if __name__ == "__main__":
    exit_code = 0
    try:
        try:
            raise SystemExit(main())
        except SystemExit:
            raise
        except BaseException as exc:  # noqa: BLE001 - never a traceback, never a clean answer for a failure
            hold_stop_signals(quietly=True)
            fail("unexpected failure: %s" % describe(exc))
    except SystemExit as stop:
        exit_code = _code(stop)
    _leave(exit_code)
