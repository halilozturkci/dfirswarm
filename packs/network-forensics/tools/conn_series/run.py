#!/usr/bin/env python3
"""Connection observations and a timestamp series for beacon_score, from a Zeek conn.log or a capture.

Two sources, one model. A Zeek conn.log (TSV with #separator/#set_separator/#empty_field/#unset_field/#fields/#types, repeated after a rotation or a change of
header; or JSON lines) is read as a stream: one row of it is one connection record, and `ts` is the first packet of the connection, not one event per exchange.
A capture (pcap or pcapng) is listed by tshark (-T fields, never a conversation summary) and the connections are built here: TCP by a SYN that is not a
retransmission of the one before, UDP by the tuple plus an inactivity gap, IPv6 like IPv4. Every row of the answer is a unique connection observation with a
locator (the line of the log or the first frame of the capture), start, duration, bytes and packets (as the source counts them: Zeek's payload bytes, or the
frame lengths of a capture), state, service and the time semantics. The whole table is a JSON Lines file; the start times, sorted, are a second file with one
epoch per line that beacon_score accepts as `timestamps_file` (at most 3,000,000 events). The window (window_start, window_end) is given with explicit zones.
Sensor coverage is carried to beacon_score's arguments only as the caller states it; it is never assumed.
"""
import json
import os
import signal
import sys

TOOL = {"name": "conn_series", "version": 2}
PARSER = "conn_series/1"


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

import datetime
import errno
import hashlib
import ipaddress
import re
import select
import shutil
import stat
import subprocess
import tempfile
import time
from pathlib import Path

MANIFEST_SECONDS = 1200       # the manifest's limit; the tool's own clock (max_seconds) ends well before it
DEFAULT_SECONDS = 900
MAX_SECONDS = 1000
PREFLIGHT_SECONDS = 30
FIELDS_SECONDS = 120
DIAG_LINES = 20               # lines of a program's output answered inline; the whole is in a file
DIAG_CHARS = 300
DIAG_READ = 1 << 16
LISTING_LINE = 1 << 16
LISTING_BYTES = 2 << 30         # the most a listing pass is read; past it tshark is killed and the answer is partial
CLOCK_EVERY = 2000


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
    return "%s%s: %s" % (type(exc).__name__, " " + code if code else "", getattr(exc, "strerror", None) or str(exc))


def in_job():
    return bool(os.environ.get("JOB_ID") and os.environ.get("OUT"))


def open_regular(path, follow=True):
    """A file opened for reading that is never waited on: the open does not block (a name that became a pipe since it was checked would otherwise wait
    for a writer), the type is read from the descriptor, and anything but a regular file is refused."""
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


PROGRESS = {"stage": "arguments", "out_dir": None, "work": None, "placed": [], "keylog": None}
STOP_LISTED = 200


def shown(path):
    """A path as the answer prints it: no control character, and any identifier-shaped part withheld. The key log's own path may be secret-shaped."""
    return scrub(cell(str(path)))


def hide(text):
    """Text from a program or an error, for the answer: the key log's path is replaced, then the text is scrubbed."""
    text = str(text)
    for secret_path in (PROGRESS.get("keylog"),):
        if secret_path:
            text = text.replace(secret_path, "<key log file>")
            text = text.replace(os.path.basename(secret_path), "<key log file>") if len(os.path.basename(secret_path)) > 3 else text
    return scrub(cell(text))


def cleanup():
    """What this run left that is not a result: the temporary directory (tshark's output and every payload not yet placed) and the hidden file of a page."""
    for page in list(PAGES):
        tmp = getattr(page, "_tmp", None)
        if tmp is not None:
            try:
                os.unlink(tmp)
            except OSError:
                pass
    work, PROGRESS["work"] = PROGRESS.get("work"), None
    if work:
        shutil.rmtree(work, ignore_errors=True)


def fail(message, **extra):
    if hasattr(signal, "pthread_sigmask"):
        signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT, signal.SIGHUP})     # one document: a stop that arrives while this is written waits
    STATE["last_word"] = None
    STOP["last_word"] = None
    cleanup()
    basis = "the tool stopped with an error (see error); " + ("the payload files already placed are whole" if PROGRESS["placed"] else "no decrypted data was placed")
    print(json.dumps({"error": message, "tool": TOOL, "status": "failed", "status_basis": basis,
                      **({"payload_files_placed": PROGRESS["placed"][:STOP_LISTED]} if PROGRESS["placed"] else {}), **extra}))
    raise SystemExit(1)


def resolve_output(out, what="output"):
    """Where `out` really lands, as a path under the run directory; a place outside it, the run directory itself, or anything under inputs/ is refused, and in a
    job so is anything outside $OUT."""
    root = Path.cwd().resolve()
    dest = (root / out).resolve() if not Path(out).is_absolute() else Path(out).resolve()
    if dest == root or root not in dest.parents:
        fail("%s must stay inside the run directory" % what, **{what: shown(out)})
    inputs = root / "inputs"
    if dest == inputs or inputs in dest.parents:
        fail("%s cannot be under inputs/" % what, **{what: shown(out)})
    if in_job():
        job_out = Path(os.environ["OUT"]).resolve()
        if dest != job_out and job_out not in dest.parents:
            fail("in a job %s is a directory under $OUT, the one place a job writes" % what, **{what: shown(out), "out": shown(job_out)})
    return str(dest.relative_to(root))


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
# <stem>-<n><suffix>. A result written at the same moment cannot be replaced either: taking a name fails when it is there.
# Only regular files are ever compared: both names are opened with O_NONBLOCK and O_NOFOLLOW and looked at with fstat before a byte is
# read, so a FIFO, a device, a directory or a link at a name (the caller's own results_to, say) is another result's and cannot hold the
# tool. The comparing of one call has PLACE_COMPARE_SECONDS in all; past it an earlier result is taken as different and this one takes
# the next free name (nothing is replaced, but an identical rerun may then be named anew).
# The name is taken with a hard link of the finished file, so it never holds an empty file, whatever stops the tool and when (SIGKILL
# included). Where the file system refuses the link, the name is taken with an exclusive create and the file is moved over it: a stop
# that unwinds (an exception) takes the empty name back while it is still the empty file this call made; a stop that ends the process
# without unwinding (SIGKILL, the handlers of the STOP block) between the create and the move leaves the empty name, and the next run takes -2.
PLACE_COMPARE_SECONDS = 5   # all the comparing one call to place_without_replacing does; past it an earlier result is taken as different


def same_bytes(a, b, deadline=None):
    """Whether two files hold the same bytes (read in blocks, never whole). Each is opened without waiting and without following a link
    (O_NONBLOCK, O_NOFOLLOW) and looked at with fstat first: only two regular files of one size are read, so a FIFO, a device, a
    directory or a link at either name is never read (a FIFO would hold the tool for ever). Past `deadline` (a monotonic time) the
    answer is False."""
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
    fa = fb = None
    try:
        fa = os.fdopen(os.open(str(a), flags), "rb")
        fb = os.fdopen(os.open(str(b), flags), "rb")
        sa, sb = os.fstat(fa.fileno()), os.fstat(fb.fileno())
        if (sa.st_mode & 0o170000) != 0o100000 or (sb.st_mode & 0o170000) != 0o100000 or sa.st_size != sb.st_size:
            return False
        while True:
            if deadline is not None and time.monotonic() > deadline:
                return False
            x, y = fa.read(1 << 20), fb.read(1 << 20)
            if x != y:
                return False
            if not x:
                return True
    except OSError:
        return False
    finally:
        for fh in (fa, fb):
            if fh is not None:
                fh.close()


def _take_name(tmp, candidate):
    """Give the finished `tmp` the name `candidate` if it is free, and say whether it now has it (False: the name is taken, by a file, a
    link, a FIFO or a directory). The name is taken with a hard link, so it never holds an empty file; where the file system refuses the
    link it is taken with an exclusive create and the file is moved over it, and a stop that unwinds in between takes the empty name back."""
    try:
        os.link(tmp, candidate)
    except FileExistsError:
        return False
    except OSError:
        pass                                   # no hard links here: the older way, below
    else:
        try:
            os.unlink(tmp)
        except OSError:
            pass                               # the hidden name stays beside the placed file; the stop path of the page removes it
        return True
    fd = made = None
    try:
        fd = os.open(str(candidate), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        made = os.fstat(fd)
        closing, fd = fd, None
        os.close(closing)
        os.replace(tmp, candidate)             # only replaces the empty file this call just made
        return True
    except FileExistsError:
        return False
    except BaseException:
        try:
            if made is None and fd is not None:
                made = os.fstat(fd)
        except OSError:
            pass
        try:
            if fd is not None:
                os.close(fd)
        except OSError:
            pass
        try:
            now = os.lstat(candidate)
            if made is not None and (now.st_mode & 0o170000) == 0o100000 and now.st_size == 0 and (now.st_dev, now.st_ino) == (made.st_dev, made.st_ino):
                os.unlink(candidate)           # the empty name this call took is not left behind
        except OSError:
            pass
        raise


def place_without_replacing(tmp, path):
    """Move the finished `tmp` to `path` and never replace what is there. A name that is taken (by a file, a link, a FIFO or a directory) is
    left as it is: a regular file of the same bytes is named again, any other result takes the next free <stem>-<n><suffix>. Returns the
    path that holds it. The comparing with earlier results has PLACE_COMPARE_SECONDS in all: past it an earlier result is taken as
    different and this one takes the next free name."""
    deadline = time.monotonic() + PLACE_COMPARE_SECONDS
    for n in range(1, 1000):
        candidate = path if n == 1 else path.with_name("%s-%d%s" % (path.stem, n, path.suffix))
        if _take_name(tmp, candidate):
            return candidate
        if not os.path.islink(candidate) and same_bytes(tmp, candidate, deadline):
            os.unlink(tmp)
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
# holds its pipes does not hold the tool: communicate_bounded gives the pipes PIPE_GRACE seconds and goes on without them.
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
            if before is not None and listed is not None and before != listed:
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
        if pid in table and (table[pid] is None or table[pid] == ident):
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
        if row is None or listed != SEEN_IDENT[pid] or row[0] == me:
            continue
        parent = row[0]
        if parent in table and SEEN_IDENT.get(parent) is not None and table.ident.get(parent) == SEEN_IDENT[parent]:
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
    turn a complete answer into a partial one (status "partial", the ok and complete flags that are there false, a sentence in status_basis):
    what a program wrote while the tool read it is not a complete result. A carrier calls it once where it prints its answer. Returns `answer`."""
    verdict = process_verdict()
    answer["program_group"] = verdict
    if (verdict["left_behind"] > 0 or verdict["unproven"]) and answer.get("status") == "complete":
        answer["status"] = "partial"
        for flag in ("ok", "complete"):
            if flag in answer:
                answer[flag] = False
        if verdict["left_behind"] > 0:
            sentence = "a program left %d process%s running after it ended; the tool ended them, and what they wrote before that is in the files named here" % (
                verdict["left_behind"], "" if verdict["left_behind"] == 1 else "es")
        else:
            sentence = "the tool cannot prove that no program left a process behind (see program_group.unproven)"
        basis = answer.get("status_basis")
        answer["status_basis"] = "%s; %s" % (basis, sentence) if isinstance(basis, str) and basis else sentence
    return answer


PIPE_GRACE = 1.0    # seconds the pipes of a program that has ended are given to reach end of file


def communicate_bounded(proc, seconds, input=None):
    """(stdout bytes, stderr bytes, timed out) for a program started with pipes, in bytes. At `seconds` the program and what it started
    are killed (timed out). A program that has ended while something it started still holds its pipes (a daemon, a helper that
    inherited them) does not hold the tool: the pipes are given PIPE_GRACE seconds, what the program wrote is kept, what the tool
    lost is killed (reap_orphans), and the pipes are let go. The pipes are read here and by nothing else, so letting them go is safe."""
    deadline = time.monotonic() + max(0.1, seconds)
    out = err = b""
    started, timed_out, note = False, False, None
    while proc.poll() is None:
        now = time.monotonic()
        if now >= deadline:
            timed_out = True
            note = kill_tree(proc)
            break
        _sample(proc.pid)
        try:
            out, err = proc.communicate(None if started else input, timeout=max(0.01, min(0.2, deadline - now)))
            settle()
            return out or b"", err or b"", False
        except subprocess.TimeoutExpired as exc:
            started = True
            out, err = exc.stdout or b"", exc.stderr or b""
    try:
        out, err = proc.communicate(None if started else input, timeout=PIPE_GRACE)
    except subprocess.TimeoutExpired as exc:
        out, err = exc.stdout or b"", exc.stderr or b""
        reap_orphans(_pipe_inodes(proc))
        settle()
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
    settle()
    err = err or b""
    if note:
        err = err + (b"\n" if err else b"") + note.encode("utf-8", "replace")
    return out or b"", err, timed_out


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

def answer_out(text):
    """Print the final answer as one unit a stop signal cannot cut or follow: signals are held while it is written and there is no last
    word to add to it, so a signal that arrives during or after it ends the tool (exit 128 plus the signal) with this one document."""
    held = (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)
    signal.pthread_sigmask(signal.SIG_BLOCK, held)
    try:
        STATE["last_word"] = None
        STOP["last_word"] = None
        print(text, flush=True)
    finally:
        signal.pthread_sigmask(signal.SIG_UNBLOCK, held)


def int_in(args, key, default, low, high):
    value = args.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        fail("%s must be an integer from %d to %d" % (key, low, high))
    return value


def text_arg(args, key, longest=4096):
    value = args.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not value or "\0" in value or len(value) > longest:
        fail("%s must be a non-empty string of at most %d characters, without a NUL" % (key, longest))
    return value


def first_line(blob):
    for line in blob.decode("utf-8", "replace").splitlines():
        if line.strip():
            return line.strip()[:200]
    return None


def stream_program(argv, stderr_path, seconds, byte_cap, feed):
    """Run `argv` with its stdout on a pipe, read as it comes with select (no thread, so the deadline needs no second one). feed(piece, complete) gets each
    line (complete True) and, for a line longer than LISTING_LINE, its parts (complete False). The program is killed with what it started at `seconds` or past
    `byte_cap` bytes. A dict: code (None when killed), timed_out, capped, bytes, error."""
    res = {"code": None, "timed_out": False, "capped": False, "bytes": 0, "error": None}
    with open(stderr_path, "wb") as err:
        try:
            proc = spawn(argv, stdout=subprocess.PIPE, stderr=err)
        except OSError as exc:
            res["error"] = describe(exc)
            return res
        ACTIVE.append(proc)
        stop_at = time.monotonic() + max(1.0, seconds)
        buf = b""
        try:
            fd = proc.stdout.fileno()
            while True:
                left = stop_at - time.monotonic()
                if left <= 0:
                    res["timed_out"] = True
                    kill_tree(proc)
                    break
                ready, _, _ = select.select([fd], [], [], min(1.0, left))
                if not ready:
                    continue
                chunk = os.read(fd, 1 << 20)
                if not chunk:
                    break
                res["bytes"] += len(chunk)
                parts = (buf + chunk).split(b"\n")
                buf = parts.pop()
                for line in parts:
                    feed(line, True)
                if len(buf) > LISTING_LINE:
                    feed(buf, False)
                    buf = b""
                if res["bytes"] > byte_cap:
                    res["capped"] = True
                    kill_tree(proc)
                    break
            if buf and not res["timed_out"] and not res["capped"]:
                feed(buf, True)
        except OSError as exc:
            res["error"] = describe(exc)
            kill_tree(proc)
        finally:
            try:
                proc.stdout.close()
            except OSError:
                pass
            code = proc.wait()
            if ACTIVE and proc in ACTIVE:
                ACTIVE.remove(proc)
        res["code"] = None if (res["timed_out"] or res["capped"]) else code
    return res


def run_logged(argv, work, tag, seconds):
    """A short program with its output in two files in `work`; (exit code or None, timed out, stdout path, stderr path)."""
    so, se = os.path.join(work, tag + ".stdout"), os.path.join(work, tag + ".stderr")
    code, timed_out = run_to_files(argv, so, se, seconds, cwd=work)
    return code, timed_out, so, se


def diagnostics(*paths):
    """The first DIAG_LINES lines of a program's stderr files (each cut to DIAG_CHARS, scrubbed, the key log's path replaced) and the counts."""
    lines, total, size = [], 0, 0
    for path in paths:
        try:
            with open_regular(path, follow=False) as fh:
                while True:
                    raw = fh.readline(DIAG_READ)
                    if not raw:
                        break
                    total += 1
                    size += len(raw)
                    text = raw.decode("utf-8", "replace").strip()
                    if text and len(lines) < DIAG_LINES:
                        lines.append(hide(text[:DIAG_CHARS]) + (" ...(%d more characters)" % (len(text) - DIAG_CHARS) if len(text) > DIAG_CHARS else ""))
        except OSError:
            continue
    return {"lines": lines, "lines_total": total, "bytes": size}


def discover_fields(binary, wanted, seconds):
    """Which of `wanted` the installed tshark lists as fields (`tshark -G fields`); (the names found, why the list could not be read or None)."""
    found = set()

    def feed(line, complete):
        cells = line.decode("utf-8", "replace").split("\t")
        if complete and len(cells) > 2 and cells[0] == "F" and cells[2] in wanted:
            found.add(cells[2])

    res = stream_program([binary, "-G", "fields"], os.devnull, seconds, 1 << 30, feed)
    if res["error"]:
        return found, "tshark -G fields could not be run (%s)" % res["error"]
    if res["timed_out"]:
        return found, "tshark -G fields did not finish in time"
    if res["capped"]:
        return found, "tshark -G fields printed more than the tool reads"
    if res["code"] != 0:
        return found, "tshark -G fields exited %s" % res["code"]
    return found, None


def epoch_iso(text):
    try:
        seconds = float(text)
        return datetime.datetime.fromtimestamp(seconds, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
    except (ValueError, OverflowError, OSError):
        return None


import array
import heapq
import math
import resource

LINE_MAX = 1 << 20                 # a log line longer than this is counted and skipped, never held
MAX_CONNECTIONS = 3_000_000        # unique connections kept; the series file is at most this long (beacon_score's own cap)
MAX_OPEN = 1_000_000               # connections open at once in a capture; past it the oldest are closed early and the answer is partial
SWEEP_EVERY = 200_000              # packets between sweeps for idle connections
CHECK_EVERY = 4096
ALLOWED = ("conn_log", "capture", "host", "port", "proto", "service", "window_start", "window_end", "assume_utc", "sensor_coverage_confirmed", "udp_gap_seconds",
           "tcp_gap_seconds", "limit", "max_seconds")
TIME_SEMANTICS = {
    "conn_log": "ts is the first packet Zeek saw of the connection, not one event per exchange; a connection that Zeek logs again (a long connection) has the same uid and is one observation",
    "capture": "the time of the first packet of the connection in this capture; a connection already open when the capture began starts at its first packet seen (midstream), not at its SYN",
}
REQUIRED_ZEEK = ("ts", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto")


class SplitPage(NoReplacePage):
    """The inline rows (scrubbed) and the whole file (the values as they are) differ: add(shown, raw)."""

    def __init__(self, tool, key, limit):
        super().__init__(tool, key, limit)
        self._shown = []

    def add(self, shown_row, raw):
        if len(self._shown) < self.limit:
            self._shown.append(shown_row)
        super().add(raw)

    def finish(self):
        result = super().finish()
        self.page = self._shown
        result["returned"] = len(self._shown)
        return result

    def _cannot_write(self, exc):
        fail("the whole table (%d rows so far) cannot be written to %s (%s); nothing was placed" % (self.total, self.shown, describe(exc)))


def last_word(signum):
    cleanup()
    print(json.dumps({"tool": TOOL, "parser": PARSER, "status": "partial", "ok": False,
                      "status_basis": "the tool was stopped by signal %d while it was %s; the programs it had started were killed with what they started, the temporary directory "
                                      "and the result files being written were removed, and the connections read so far are not kept" % (signum, PROGRESS["stage"]),
                      "interrupted_by_signal": signum, "stage": PROGRESS["stage"]}), flush=True)


def parse_instant(value, assume_utc, counter):
    """An epoch (number) or an ISO 8601 string with a zone, as epoch seconds; (value, why not)."""
    if isinstance(value, bool):
        return None, "not a time"
    if isinstance(value, (int, float)):
        return (float(value), None) if math.isfinite(value) else (None, "not a finite number")
    if not isinstance(value, str) or not value.strip() or len(value) > 64:
        return None, "not a time"
    text = value.strip()
    try:
        return (float(text), None) if math.isfinite(float(text)) else (None, "not a finite number")
    except ValueError:
        pass
    iso = text[:-1] + "+00:00" if text.endswith(("Z", "z")) else text
    try:
        moment = datetime.datetime.fromisoformat(iso)
    except ValueError:
        return None, "not an epoch or an ISO 8601 time"
    if moment.tzinfo is None:
        if not assume_utc:
            return None, "has no zone (give a zone, or set assume_utc)"
        counter["naive_assumed_utc"] = counter.get("naive_assumed_utc", 0) + 1
        moment = moment.replace(tzinfo=datetime.timezone.utc)
    return moment.timestamp(), None


def read_arguments():
    try:
        args = json.load(sys.stdin)
    except ValueError:
        fail("arguments are not valid JSON")
    if not isinstance(args, dict):
        fail("arguments must be a JSON object")
    unknown = sorted(str(k) for k in args if k not in ALLOWED)
    if unknown:
        fail("unknown parameters: %s" % ", ".join(hide(k[:40]) for k in unknown[:10]), allowed=list(ALLOWED))
    log, capture = text_arg(args, "conn_log"), text_arg(args, "capture")
    if (log is None) == (capture is None):
        fail("give exactly one of conn_log (a Zeek conn.log) and capture (a pcap or pcapng)")
    host = text_arg(args, "host", 64)
    if host is not None:
        try:
            host = str(ipaddress.ip_address(host))
        except ValueError:
            fail("host must be an IP address")
    port = int_in(args, "port", None, 0, 65535) if "port" in args else None
    proto = text_arg(args, "proto", 8)
    if proto is not None and proto.lower() not in ("tcp", "udp", "icmp"):
        fail("proto must be tcp, udp or icmp")
    service = text_arg(args, "service", 128)
    for key in ("assume_utc", "sensor_coverage_confirmed"):
        if not isinstance(args.get(key, False), bool):
            fail("%s must be true or false" % key)
    max_seconds = args.get("max_seconds", DEFAULT_SECONDS)
    if isinstance(max_seconds, bool) or not isinstance(max_seconds, int) or not 10 <= max_seconds <= MAX_SECONDS:
        fail("max_seconds must be an integer from 10 to %d: kept under the manifest's %d seconds so that this tool stops its programs itself" % (MAX_SECONDS, MANIFEST_SECONDS))
    counter = {}
    window = {}
    for key, raw in (("window_start", args.get("window_start")), ("window_end", args.get("window_end"))):
        if raw is None:
            window[key] = None
            continue
        value, why = parse_instant(raw, args.get("assume_utc", False), counter)
        if why:
            fail("%s %s" % (key, why))
        window[key] = value
    if window["window_start"] is not None and window["window_end"] is not None and window["window_end"] <= window["window_start"]:
        fail("window_end must be after window_start")
    return dict(conn_log=log, capture=capture, host=host, port=port, proto=proto.lower() if proto else None, service=service, window=window, window_text={k: args.get(k) for k in ("window_start", "window_end")},
                assume_utc=bool(args.get("assume_utc", False)), coverage=bool(args.get("sensor_coverage_confirmed", False)), naive=counter,
                udp_gap=int_in(args, "udp_gap_seconds", 60, 1, 86400), tcp_gap=int_in(args, "tcp_gap_seconds", 3600, 1, 86400),
                limit=int_in(args, "limit", 200, 1, 1_000_000), max_seconds=max_seconds)


class Collector:
    """Receives each finished connection: filters, de-duplicates, pages and keeps the start for the series. Everything here is bounded."""

    def __init__(self, p, page, source_shown):
        self.p, self.page, self.source = p, page, source_shown
        self.starts = array.array("d")
        self.seen = set()
        self.counts = {"records": 0, "duplicates": 0, "outside_window": 0, "filtered_out": 0, "kept": 0, "over_cap": 0, "bad_time": 0, "bad_fields": 0, "service_withheld_not_matched": 0}
        self.service_filter = p["service"]

    def offer(self, c):
        """c: dict with ts, uid, oh, op, rh, rp, proto, service, duration, ob, rb, opk, rpk, state, locator, source_kind."""
        counts = self.counts
        counts["records"] += 1
        win = self.p["window"]
        ts = c["ts"]
        if (win["window_start"] is not None and ts < win["window_start"]) or (win["window_end"] is not None and ts >= win["window_end"]):
            counts["outside_window"] += 1
            return
        p = self.p
        if p["proto"] and c["proto"] != p["proto"]:
            counts["filtered_out"] += 1
            return
        if p["host"] and p["host"] not in (c["oh"], c["rh"]):
            counts["filtered_out"] += 1
            return
        if p["port"] is not None and p["port"] not in (c["op"], c["rp"]):
            counts["filtered_out"] += 1
            return
        shown_service = scrub(cell(c["service"])) if c["service"] else c["service"]
        if self.service_filter is not None:
            # The filter reads the text the answer prints, never the value behind a withheld one: a withheld value cannot be probed by guessing.
            names = [x.strip() for x in (shown_service or "").split(",")]
            if self.service_filter not in names:
                counts["filtered_out"] += 1
                if shown_service and shown_service != c["service"]:
                    counts["service_withheld_not_matched"] += 1
                return
        key = c["uid"]
        if key is not None and key in self.seen:
            counts["duplicates"] += 1
            return
        if counts["kept"] >= MAX_CONNECTIONS:
            counts["over_cap"] += 1
            return
        if key is not None:
            self.seen.add(key)
        counts["kept"] += 1
        self.starts.append(ts)
        raw = {"locator": c["locator"], "uid": c["uid"], "proto": c["proto"], "orig": {"ip": c["oh"], "port": c["op"]}, "resp": {"ip": c["rh"], "port": c["rp"]},
               "start": {"raw": c["ts_text"], "utc": epoch_iso(repr(ts)), "zone": "UTC (the epoch of the source)"}, "duration_seconds": c["duration"],
               "bytes": {"orig": c["ob"], "resp": c["rb"], "basis": c["bytes_basis"]}, "packets": {"orig": c["opk"], "resp": c["rpk"]}, "state": c["state"], "service": c["service"],
               "time_semantics": TIME_SEMANTICS[c["source_kind"]], "flags": c.get("flags", []),
               "provenance": {"source": self.source, "program": c["program"], "parser": PARSER}}
        shown_row = dict(raw)
        shown_row["uid"] = scrub(cell(c["uid"])) if c["uid"] else c["uid"]
        shown_row["service"] = shown_service
        self.page.add(shown_row, raw)


def unescape_separator(text):
    return re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), text)


def zeek_value(cell_text, kind, state):
    """A cell as Zeek writes it: the unset field is None, the empty field is empty, and a set[..]/vector[..] is a list split on the set separator."""
    if cell_text == state["unset"]:
        return None
    if cell_text == state["empty"]:
        return [] if kind.startswith(("set[", "vector[")) else ""
    if kind.startswith(("set[", "vector[")):
        return cell_text.split(state["set_sep"])
    return cell_text


def as_number(value):
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) else None


def as_count(value):
    number = as_number(value)
    return int(number) if number is not None and number >= 0 else None


def as_port(value):
    number = as_count(value)
    return number if number is not None and number <= 65535 else None


def as_ip(value):
    if not isinstance(value, str):
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def finish_record(fields, line_no, p, col, counts, state_source, ts_error_counter):
    """fields: name -> raw value (text or JSON value); a connection record or None (and the reason counted)."""
    ts_text = fields.get("ts")
    ts, why = parse_instant(ts_text, p["assume_utc"], p["naive"])
    if why:
        counts["bad_time"] += 1
        return None
    oh, rh = as_ip(fields.get("id.orig_h")), as_ip(fields.get("id.resp_h"))
    op, rp = as_port(fields.get("id.orig_p")), as_port(fields.get("id.resp_p"))
    proto = fields.get("proto")
    if oh is None or rh is None or op is None or rp is None or not isinstance(proto, str) or proto.lower() not in ("tcp", "udp", "icmp"):
        counts["bad_fields"] += 1
        return None
    service = fields.get("service")
    if isinstance(service, list):
        service = ",".join(str(x) for x in service) if service else None
    elif service in ("", None):
        service = None
    uid = fields.get("uid")
    return {"ts": ts, "ts_text": ts_text if isinstance(ts_text, (str, int, float)) else None, "uid": uid if isinstance(uid, str) and uid else None, "oh": oh, "op": op, "rh": rh, "rp": rp,
            "proto": proto.lower(), "service": service if isinstance(service, str) else None, "duration": as_number(fields.get("duration")),
            "ob": as_count(fields.get("orig_bytes")), "rb": as_count(fields.get("resp_bytes")), "opk": as_count(fields.get("orig_pkts")), "rpk": as_count(fields.get("resp_pkts")),
            "state": fields.get("conn_state") if isinstance(fields.get("conn_state"), str) else None, "locator": {"source": state_source, "line": line_no},
            "source_kind": "conn_log", "bytes_basis": "payload bytes (Zeek orig_bytes, resp_bytes)", "program": "zeek conn.log"}


def read_zeek(path, p, collector, deadline, counts, notes):
    """Stream a Zeek conn.log (TSV or JSON lines): bounded lines, headers re-read when they repeat."""
    state = {"sep": "\t", "set_sep": ",", "empty": "(empty)", "unset": "-", "fields": None, "types": None, "index": None}
    headers_seen = 0
    json_lines = 0
    tsv_rows = 0
    source = shown(path)
    ts_counter = {}
    with open_regular(path) as fh:
        first = fh.read(2)
        if first == b"\x1f\x8b":
            fail("conn_log is gzip-compressed (a rotated log): decompress it first; this tool does not expand an archive", conn_log=source)
        fh.seek(0)
        line_no = 0
        offset = 0
        while True:
            line_start = offset
            raw = fh.readline(LINE_MAX + 1)
            if not raw:
                break
            offset += len(raw)
            line_no += 1
            if len(raw) > LINE_MAX and not raw.endswith(b"\n"):
                counts["long_lines"] += 1
                while True:                       # the rest of the line is read and dropped, a block at a time
                    rest = fh.readline(1 << 16)
                    offset += len(rest)
                    if not rest or rest.endswith(b"\n"):
                        break
                continue
            if line_no % CHECK_EVERY == 0 and time.monotonic() > deadline:
                counts["timed_out"] = True
                return
            line = raw.rstrip(b"\r\n")
            if not line:
                continue
            if b"\0" in line:
                counts["nul_lines"] += 1
                continue
            try:
                text = line.decode("utf-8")
            except UnicodeDecodeError:
                counts["non_utf8_lines"] += 1
                continue
            if text[0] == "#":
                if text.startswith("#separator"):
                    value = text.split(" ", 1)[1] if " " in text else ""
                    state["sep"] = unescape_separator(value) or "\t"
                    headers_seen += 1
                elif text.startswith("#set_separator"):
                    state["set_sep"] = text.split(state["sep"], 1)[1] if state["sep"] in text else ","
                elif text.startswith("#empty_field"):
                    state["empty"] = text.split(state["sep"], 1)[1] if state["sep"] in text else "(empty)"
                elif text.startswith("#unset_field"):
                    state["unset"] = text.split(state["sep"], 1)[1] if state["sep"] in text else "-"
                elif text.startswith("#fields"):
                    state["fields"] = text.split(state["sep"])[1:]
                    state["index"] = {n: i for i, n in enumerate(state["fields"])}
                    state["types"] = None
                    state["missing"] = [n for n in REQUIRED_ZEEK if n not in state["index"]]
                elif text.startswith("#types"):
                    state["types"] = text.split(state["sep"])[1:]
                continue
            if text[0] == "{":
                json_lines += 1
                try:
                    obj = json.loads(text)
                except ValueError:
                    counts["bad_json_lines"] += 1
                    continue
                if not isinstance(obj, dict):
                    counts["bad_json_lines"] += 1
                    continue
                fields = dict(obj)
                nested = obj.get("id")
                if isinstance(nested, dict):
                    for k, v in nested.items():
                        fields["id." + k] = v
                missing = [n for n in REQUIRED_ZEEK if n not in fields]
                if missing:
                    counts["rows_without_required_fields"] += 1
                    continue
                rec = finish_record(fields, line_no, p, None, counts, source, ts_counter)
                if rec is not None:
                    rec["flags"] = []
                    rec["locator"]["byte_offset"] = line_start
                    collector.offer(rec)
                continue
            tsv_rows += 1
            if state["fields"] is None:
                counts["rows_before_fields"] += 1
                continue
            cells = text.split(state["sep"])
            if len(cells) != len(state["fields"]):
                counts["mismatched_columns"] += 1
                continue
            if state.get("missing"):
                counts["rows_without_required_fields"] += 1
                continue
            idx, types = state["index"], state["types"]
            fields = {}
            for name in ("ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service", "duration", "orig_bytes", "resp_bytes", "conn_state", "orig_pkts", "resp_pkts"):
                i = idx.get(name)
                if i is None:
                    continue
                kind = types[i] if types and i < len(types) else "string"
                fields[name] = zeek_value(cells[i], kind, state)
            if fields.get("ts") is None:
                counts["bad_time"] += 1
                continue
            rec = finish_record(fields, line_no, p, None, counts, source, ts_counter)
            if rec is not None:
                rec["locator"]["byte_offset"] = line_start
                collector.offer(rec)
    counts["header_blocks"] = headers_seen
    counts["tsv_rows"] = tsv_rows
    counts["json_rows"] = json_lines
    counts["lines"] = line_no
    if headers_seen > 1:
        notes.append("the log has %d header blocks (a rotation or a change of header): each block's #fields, #types and separators were used for its own rows" % headers_seen)


FLAG_FIN, FLAG_SYN, FLAG_RST, FLAG_ACK = 0x01, 0x02, 0x04, 0x10


class CaptureBuilder:
    """Builds connections from a packet listing. TCP: a SYN without ACK starts one unless it repeats the ISN of the open one (a retransmission). UDP and a TCP
    packet with no SYN seen (midstream): the tuple plus an inactivity gap."""

    def __init__(self, p, collector, source):
        self.p, self.out, self.source = p, collector, source
        self.open = {}
        self.packets = 0
        self.last_t = 0.0
        self.sweep_at = SWEEP_EVERY
        self.counts = {"packets": 0, "syn_retransmissions": 0, "port_reuse": 0, "midstream": 0, "open_cap_evictions": 0, "other_packets": 0, "bad_packets": 0, "syn_seq_unknown": 0}

    def close(self, key, reason=None):
        c = self.open.pop(key, None)
        if c is None:
            return
        c["flags"] = list(c["flags"])
        dur = c["last"] - c["ts"]
        c["duration"] = dur
        c["state"] = c["state_note"]
        self.out.offer(c)

    def packet(self, frame, t, src, dst, sport, dport, proto, flags, seq, length, t_text):
        counts = self.counts
        counts["packets"] += 1
        self.last_t = max(self.last_t, t)
        a, b = (src, sport), (dst, dport)
        key = (proto, a, b) if a <= b else (proto, b, a)
        c = self.open.get(key)
        gap = self.p["tcp_gap"] if proto == "tcp" else self.p["udp_gap"]
        if c is not None and t - c["last"] > gap:
            self.close(key)
            c = None
        syn_only = proto == "tcp" and flags is not None and flags & FLAG_SYN and not flags & FLAG_ACK
        if syn_only and c is not None:
            if seq is not None and c["syn_seq"] == seq:
                counts["syn_retransmissions"] += 1
                c["last"] = max(c["last"], t)
                c["syn_rexmit"] += 1
                c["opk"] += 1                       # the packet is the connection's own: counted as a packet, not as a connection
                c["ob"] += length or 0
                return
            counts["port_reuse"] += 1
            self.close(key)
            c = None
        if c is None:
            if len(self.open) >= MAX_OPEN:
                for victim in heapq.nsmallest(MAX_OPEN // 10, self.open, key=lambda k: self.open[k]["last"]):   # a tenth at a time: one scan per MAX_OPEN/10 new connections
                    counts["open_cap_evictions"] += 1
                    self.close(victim)
            midstream = proto == "tcp" and not syn_only
            if midstream:
                counts["midstream"] += 1
            c = {"ts": t, "ts_text": t_text, "last": t, "uid": None, "oh": src, "op": sport, "rh": dst, "rp": dport, "proto": proto, "service": None, "duration": 0.0, "ob": 0, "rb": 0,
                 "opk": 0, "rpk": 0, "state": None, "state_note": "midstream (no SYN seen)" if midstream else ("SYN seen" if syn_only else None), "locator": {"source": self.source, "frame": frame},
                 "source_kind": "capture", "bytes_basis": "frame length (headers included), not payload", "program": "tshark", "syn_seq": seq if syn_only else None, "syn_rexmit": 0,
                 "flags": ["midstream"] if midstream else []}
            self.open[key] = c
        c["last"] = max(c["last"], t)
        if (src, sport) == (c["oh"], c["op"]):
            c["opk"] += 1
            c["ob"] += length or 0
        else:
            c["rpk"] += 1
            c["rb"] += length or 0
        if proto == "tcp" and flags is not None:
            if flags & FLAG_RST:
                c["state_note"] = "reset"
            elif flags & FLAG_FIN and c["state_note"] not in ("reset",):
                c["state_note"] = "closing (FIN seen)"
            elif flags & FLAG_SYN and flags & FLAG_ACK and c["state_note"] in ("SYN seen", None):
                c["state_note"] = "established (SYN-ACK seen)"
        self.packets += 1
        if self.packets >= self.sweep_at:
            self.sweep_at = self.packets + SWEEP_EVERY
            for k in [k for k, v in self.open.items() if self.last_t - v["last"] > (self.p["tcp_gap"] if v["proto"] == "tcp" else self.p["udp_gap"])]:
                self.close(k)

    def finish(self):
        for k in list(self.open):
            self.close(k)


def time_left(deadline, floor=0.0):
    return deadline - time.monotonic() - floor


def main():
    started = time.monotonic()
    STATE["last_word"] = last_word
    STOP["last_word"] = last_word
    install_signal_handlers()
    p = read_arguments()
    deadline = started + p["max_seconds"]
    path = p["conn_log"] or p["capture"]
    PROGRESS["stage"] = "looking at the input"
    if not os.path.exists(path):
        fail("no such file", **{"conn_log" if p["conn_log"] else "capture": shown(path)})
    try:
        with open_regular(path):
            pass
    except OSError as exc:
        fail("the input is not a regular file that can be read (%s)" % hide(describe(exc)), input=shown(path))
    digest = hashlib.sha256(json.dumps([os.path.basename(path), p["host"], p["port"], p["proto"], p["service"], p["window_text"], p["assume_utc"], p["udp_gap"], p["tcp_gap"]]).encode()).hexdigest()[:16]
    rows_page = SplitPage(TOOL["name"], digest, p["limit"])
    place = rows_page.path.parent
    try:
        place.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        fail("the place for the result could not be made (%s)" % hide(describe(exc)), place=shown(place))
    held = {signal.SIGTERM, signal.SIGINT, signal.SIGHUP}
    was = signal.pthread_sigmask(signal.SIG_BLOCK, held)
    try:
        work = tempfile.mkdtemp(dir=str(place), prefix=".conn_series-")
        PROGRESS["work"] = work
    except OSError as exc:
        signal.pthread_sigmask(signal.SIG_SETMASK, was)
        fail("the temporary directory could not be created (%s)" % hide(describe(exc)), place=shown(place))
    signal.pthread_sigmask(signal.SIG_SETMASK, was)
    try:
        return examine(p, started, deadline, path, place, work, rows_page, digest)
    except SystemExit:
        raise
    except BaseException as exc:  # noqa: BLE001 - never a traceback, and the temporary directory never stays
        fail("unexpected failure: %s" % hide(describe(exc)) if isinstance(exc, Exception) else "interrupted: %s" % type(exc).__name__)


def examine(p, started, deadline, path, place, work, rows_page, digest):
    problems, notes = [], []
    collector = Collector(p, rows_page, shown(path))
    counts = {"long_lines": 0, "nul_lines": 0, "non_utf8_lines": 0, "bad_json_lines": 0, "rows_before_fields": 0, "mismatched_columns": 0, "rows_without_required_fields": 0,
              "bad_time": 0, "bad_fields": 0, "timed_out": False}
    version = None
    capture_counts = None
    if p["conn_log"]:
        PROGRESS["stage"] = "reading the Zeek conn.log"
        read_zeek(path, p, collector, deadline, counts, notes)
        mode = "zeek_conn_log"
        for k in ("bad_time", "bad_fields"):
            collector.counts[k] += counts[k]
    else:
        mode = "capture"
        binary = shutil.which("tshark")
        if not binary:
            fail("tshark is not on PATH", requires=["tshark"], note="a capture is listed by tshark; a Zeek conn.log needs no program. Nothing was read or written")
        PROGRESS["stage"] = "reading the version of tshark"
        code, out, err, timed_out = preflight([binary, "--version"], max(1.0, min(PREFLIGHT_SECONDS, time_left(deadline))))
        version = first_line(out) or first_line(err)
        if version is None:
            problems.append("`tshark --version` gave no version line, so the version of tshark is not recorded")
        PROGRESS["stage"] = "checking the fields of tshark"
        wanted = {"frame.number", "frame.time_epoch", "frame.len", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst", "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport", "tcp.flags", "tcp.seq_raw"}
        available, why = discover_fields(binary, wanted, max(1.0, min(FIELDS_SECONDS, time_left(deadline))))
        if why:
            fail("%s, so the fields this tool relies on cannot be checked against this build; nothing was read" % why, tshark=version)
        core = ["frame.number", "frame.time_epoch", "ip.src", "ip.dst", "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport", "tcp.flags"]
        lacking = [n for n in core if n not in available]
        if lacking:
            fail("this tshark build lacks the field(s) %s that a connection is built from; nothing was read" % ", ".join(lacking), tshark=version, fields_missing=lacking)
        optional_missing = [n for n in ("ipv6.src", "ipv6.dst", "frame.len", "tcp.seq_raw") if n not in available]
        if "tcp.seq_raw" in optional_missing:
            problems.append("this tshark build lacks tcp.seq_raw: a retransmitted SYN cannot be told from a new connection on the same ports, so it may be counted twice")
        if "ipv6.src" in optional_missing or "ipv6.dst" in optional_missing:
            problems.append("this tshark build lacks the IPv6 address fields: IPv6 packets are not listed")
        columns = [n for n in ["frame.number", "frame.time_epoch", "ip.src", "ipv6.src", "ip.dst", "ipv6.dst", "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport", "tcp.flags",
                               "tcp.seq_raw", "frame.len"] if n in available]
        index = {n: i for i, n in enumerate(columns)}
        builder = CaptureBuilder(p, collector, shown(path))
        counters = builder.counts

        def feed(line, complete):
            if not complete:
                counts["long_lines"] += 1
                return
            cells = line.decode("utf-8", "replace").split("\t")
            if len(cells) != len(columns):
                counters["bad_packets"] += 1
                return
            get = lambda n: cells[index[n]] if n in index else ""
            src, dst = get("ip.src") or get("ipv6.src"), get("ip.dst") or get("ipv6.dst")
            if get("tcp.srcport") != "":
                proto, sport, dport = "tcp", get("tcp.srcport"), get("tcp.dstport")
            elif get("udp.srcport") != "":
                proto, sport, dport = "udp", get("udp.srcport"), get("udp.dstport")
            else:
                counters["other_packets"] += 1
                return
            frame, t = get("frame.number"), as_number(get("frame.time_epoch"))
            sp, dp = as_port(sport), as_port(dport)
            if not frame.isdigit() or t is None or sp is None or dp is None or as_ip(src) is None or as_ip(dst) is None:
                counters["bad_packets"] += 1
                return
            flags = None
            if proto == "tcp":
                try:
                    flags = int(get("tcp.flags"), 16) if get("tcp.flags").lower().startswith("0x") else int(get("tcp.flags"))
                except ValueError:
                    counters["bad_packets"] += 1
                    return
            seq = as_count(get("tcp.seq_raw"))
            builder.packet(int(frame), t, as_ip(src), as_ip(dst), sp, dp, proto, flags, seq, as_count(get("frame.len")), get("frame.time_epoch")[:40])

        argv = [binary, "-r", path, "-n", "-2", "-Y", "tcp || udp", "-T", "fields", "-E", "separator=/t", "-E", "occurrence=f"]
        for name in columns:
            argv += ["-e", name]
        PROGRESS["stage"] = "listing the packets (tshark -T fields)"
        left = time_left(deadline)
        if left < 5:
            fail("the tool's own clock (max_seconds) ran out before the listing could start; nothing was read")
        stderr_path = os.path.join(work, "listing.stderr")
        run = stream_program(argv, stderr_path, left * 0.9, LISTING_BYTES, feed)
        if run["error"]:
            fail("tshark could not be run (%s)" % hide(run["error"]))
        diag = diagnostics(stderr_path)
        if run["timed_out"]:
            problems.append("the listing did not finish before the tool's own clock and was killed with everything it had started: the connections are those of the packets read so far")
            counts["timed_out"] = True
        elif run["capped"]:
            problems.append("the listing passed %d bytes and was stopped: the connections are those of the packets read so far" % LISTING_BYTES)
        elif run["code"] not in (0, None):
            problems.append("tshark exited %s in the listing pass" % run["code"])
        if counters["packets"] == 0 and (run["timed_out"] or run["capped"] or run["code"] not in (0, None)):
            fail("tshark's listing pass did not give a result (%s)" % ("timed out" if run["timed_out"] else ("stopped at the byte cap" if run["capped"] else "exit %s" % run["code"])), diagnostics=diag, tshark=version)
        builder.finish()
        capture_counts = dict(counters)
        capture_counts["diagnostics"] = diag
        if counters["syn_retransmissions"]:
            notes.append("%d retransmitted SYN packet(s) (same initial sequence number as the open connection) were not counted as connections" % counters["syn_retransmissions"])
        if counters["port_reuse"]:
            notes.append("%d new SYN(s) on a tuple still open were counted as new connections (port reuse)" % counters["port_reuse"])
        if counters["midstream"]:
            notes.append("%d connection(s) were already open when the capture began or had no SYN in it: their start is their first packet seen, not their SYN" % counters["midstream"])
        if counters["bad_packets"]:
            problems.append("%d listing line(s) did not have the fields asked for and are not in any connection" % counters["bad_packets"])
        if counters["open_cap_evictions"]:
            problems.append("%d connection(s) were closed early because more than %d were open at once: a connection may be split in two" % (counters["open_cap_evictions"], MAX_OPEN))
        if counts["long_lines"]:
            problems.append("%d listing line(s) were over %d bytes and are not in any connection" % (counts["long_lines"], LISTING_LINE))
    cc = collector.counts
    if p["conn_log"]:
        for key, text in (("long_lines", "line(s) over %d bytes" % LINE_MAX), ("nul_lines", "line(s) with a NUL byte"), ("non_utf8_lines", "line(s) that are not UTF-8"), ("bad_json_lines", "JSON line(s) that did not parse"),
                          ("rows_before_fields", "row(s) before any #fields line"), ("mismatched_columns", "row(s) whose column count differs from #fields"),
                          ("rows_without_required_fields", "row(s) without ts, id.orig_h, id.orig_p, id.resp_h, id.resp_p or proto")):
            if counts[key]:
                problems.append("%d %s were skipped: they are not in the table or the series" % (counts[key], text))
        if cc["bad_time"] or cc["bad_fields"]:
            problems.append("%d row(s) had a time that is not an epoch or an ISO time with a zone, and %d had an address, port or protocol that is not valid: skipped" % (cc["bad_time"], cc["bad_fields"]))
    elif cc["bad_time"] or cc["bad_fields"]:
        pass
    if counts["timed_out"] and p["conn_log"]:
        problems.append("the tool's own clock (max_seconds) ran out while reading the log: the connections are those of the lines read so far")
    if cc["over_cap"]:
        problems.append("%d connection(s) past the %d-connection cap were counted and not kept: the table and the series stop at the cap" % (cc["over_cap"], MAX_CONNECTIONS))
    if p["naive"].get("naive_assumed_utc"):
        notes.append("%d window time(s) with no zone were read as UTC because assume_utc is true" % p["naive"]["naive_assumed_utc"])
    if cc["service_withheld_not_matched"]:
        notes.append("the service filter reads the text this answer prints: %d connection(s) have a service value that is withheld here and did not match it" % cc["service_withheld_not_matched"])
    PROGRESS["stage"] = "writing the series"
    rows_shown = rows_page.finish()
    ordered = sorted(collector.starts)
    series_name = "conn_series-%s.series.txt" % digest
    series_tmp = os.path.join(work, "series.txt")
    with open(series_tmp, "w", encoding="ascii") as fh:
        for i, t in enumerate(ordered):
            fh.write(repr(t))
            fh.write("\n")
    os.chmod(series_tmp, 0o600)
    try:
        series_path = place_without_replacing(Path(series_tmp), place / series_name)
    except OSError as exc:
        fail("the series file cannot be written to %s (%s)" % (shown(place), hide(describe(exc))))
    series_shown = rows_page.shown.rsplit("/", 1)[0] + "/" + series_path.name
    logs = []
    if capture_counts is not None:
        try:
            if os.path.getsize(os.path.join(work, "listing.stderr")) > 0:
                logs.append(place_without_replacing(Path(os.path.join(work, "listing.stderr")), place / "tshark-conn-series-listing.stderr").name)
        except OSError as exc:
            problems.append("tshark's messages could not be kept (%s)" % hide(describe(exc)))
    cleanup()
    ok = not problems
    if cc["kept"] == 0:
        notes.append("no connection matched: this says nothing about connections the source did not record, or that the filters and the window excluded")
    coverage = {"sensor_coverage_confirmed": p["coverage"] if p["window"]["window_end"] is not None else None}
    bs_args = {"timestamps_file": series_shown}
    if p["window"]["window_end"] is not None:
        bs_args["window_end"] = p["window_text"]["window_end"]
        if p["coverage"]:
            bs_args["sensor_coverage_confirmed"] = True
    if p["coverage"] and p["window"]["window_end"] is None:
        notes.append("sensor_coverage_confirmed was given without window_end: it is not carried to beacon_score, which needs both to say anything about silence")
    usage = resource.getrusage(resource.RUSAGE_SELF)
    basis = ("%d unique connection(s) from %s; every row has its locator and the time semantics of its source" % (cc["kept"], "the Zeek conn.log" if p["conn_log"] else "the capture")
             if ok else "; ".join(problems[:4]) + (" (and %d more, all in problems)" % (len(problems) - 4) if len(problems) > 4 else ""))
    answer_out(json.dumps({
        "tool": TOOL, "parser": PARSER, "status": "complete" if ok else "partial", "status_basis": basis, "mode": mode, "source": shown(path), "tshark": version,
        "scope": {"host": p["host"], "port": p["port"], "proto": p["proto"], "service": p["service"] if p["service"] is None else scrub(cell(p["service"])),
                  "window": {"start": p["window_text"]["window_start"], "end": p["window_text"]["window_end"], "start_epoch": p["window"]["window_start"], "end_epoch": p["window"]["window_end"],
                             "rule": "start inclusive, end exclusive, on the connection's start time; a zone-less time is refused unless assume_utc"}},
        "observations": rows_page.page, "observations_total": rows_page.total, "observations_returned": len(rows_page.page),
        **{k: v for k, v in rows_shown.items() if k not in ("matched", "returned")},
        "series": {"file": series_shown, "events": len(ordered), "sorted": "ascending by start time", "one_epoch_per_line": True, "mode": "0600",
                   "first_utc": epoch_iso(repr(ordered[0])) if ordered else None, "last_utc": epoch_iso(repr(ordered[-1])) if ordered else None,
                   "note": "each event is the START of a connection, not an exchange; a log in order of connection END is re-sorted here"},
        "beacon_score_arguments": bs_args,
        "coverage": {**coverage, "note": "carried only as given: window_end and sensor_coverage_confirmed together; this tool never decides that the sensor kept recording"},
        "counts": {**{k: v for k, v in cc.items()}, **({"capture": capture_counts} if capture_counts else {}), **({"log": {k: v for k, v in counts.items() if k != "timed_out"}} if p["conn_log"] else {})},
        "time_semantics": TIME_SEMANTICS["conn_log" if p["conn_log"] else "capture"],
        "resources": {"seconds": round(time.monotonic() - started, 1), "max_rss_kb": usage.ru_maxrss, "connections_kept": cc["kept"], "cap": MAX_CONNECTIONS},
        "logs": logs, "problems": problems, "notes": notes, "ok": ok,
        "relies_on": "Zeek's documented conn.log fields (ts, uid, id.*, proto, service, duration, orig_bytes, resp_bytes, conn_state, orig_pkts, resp_pkts) or tshark's -T fields output; a log from a Zeek that writes other formats is read as far as its fields match",
    }, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except BaseException as exc:  # noqa: BLE001 - never a traceback, never a clean answer for a failure
        fail("unexpected failure: %s" % hide(describe(exc)))
