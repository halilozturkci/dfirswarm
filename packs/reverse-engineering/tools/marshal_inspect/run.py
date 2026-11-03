#!/usr/bin/env python3
"""marshal_inspect: read a Python marshal stream as data, and never run it.

A compiled module (a .pyc, a stream carved out of a packed executable or a
memory image) is a marshal stream: constants, names and code objects, whose
bytecode is data until something runs it. This parses the stream itself,
byte by byte, with its own reader. It never calls marshal.loads, never builds
a code object, never imports or runs what it reads, so a hostile stream costs
what any other file costs.

For every code object it says its name, qualified name, file name, first line,
argument counts, flags, the names it uses, its constants, and the size and
sha256 of its bytecode (and the bytecode itself, as hex, in the result file).
The whole tree of the stream goes to a file in out_dir; the answer carries the
counts, the code objects in a short form and where the rest is.

A constant can be a credential. Every string and byte string the answer or the
result file shows passes through the pack's shared withholding (by shape: a
secret of another shape is printed); a string longer than 4,096 characters is
given by its length; the whole text of each one withheld is written only with
write_values, in a job run as secret output, to a sealed file.

The code-object layout read here is CPython 3.11 to 3.13 (argcount,
posonlyargcount, kwonlyargcount, stacksize, flags, code, consts, names,
localsplusnames, localspluskinds, filename, name, qualname, firstlineno,
linetable, exceptiontable). A .pyc header names its interpreter by magic number:
3.10 or older, and 3.14 or newer, are `unsupported` with the version named. A
stream without a header that does not parse as this layout stops with the
position where it stopped rather than being guessed at.

Args, JSON on stdin:
  path          the file
  offset        where the stream starts (default: after a .pyc header when the
                file begins with one, else 0)
  out_dir       where the whole result goes (default work/<agent>/marshal_inspect,
                in a job $OUT/marshal_inspect)
  max_bytes     the largest stream read (default 64 MiB)
  preview       characters of a string or bytes of a byte string shown in the
                answer (default 160); the result file holds them as far as the
                withholding allows
  bytecode      put each code object's bytecode, as hex, in the result file
                (default true)
  limit         code objects shown in the answer (default 50, at most 5000)
  max_seconds   the tool's own time limit (default 45)
  write_values  write the whole text of what was withheld to a sealed file
"""
import errno
import hashlib
import json
import os
import re
import stat
import struct
import sys
import time
import unicodedata
from datetime import datetime, timezone
from pathlib import Path

TOOL = {"name": "marshal_inspect", "version": 5}
PARSER = "marshal_inspect/2"
SCHEMA_VERSION = 2
NOTE = ("A marshal stream is data until something runs it, and this tool runs none of it. A constant, a name or a file name is what the file says, "
        "not what the program does with it. Read `status`, `status_basis`, `problems` and `limits_hit` first. A string out of the file is withheld by its shape only: "
        "a secret of another shape is printed.")

MAX_DEPTH = 200
MAX_OBJECTS = 2_000_000
READ_CLOCK_BYTES = 1 << 16          # the reader reads the clock each time this many more bytes have been taken
VIEW_CLOCK_UNITS = 1 << 15          # the views read it each time this many characters (or 32 per node) have been shown
MAX_LONG_DIGITS = 1 << 20           # digits of one `long`; a longer one is refused with the bound named
OLDEST_MAGIC = 3450                 # 3.11's code objects begin here; 3.10 ended at 3439
SUPPORTED = ("3.11", "3.12", "3.13")
DEFAULT_SECONDS = 45                # the tool's own clock, below the manifest's 60 s
MAX_SECONDS = 50
DEFAULT_LIMIT = 50
MAX_LIMIT = 5000
MAX_PREVIEW = 4096
MAX_ANSWER_NODES = 500              # nodes of the stream's root shown in the answer; the whole is in the result file
MAX_ROW_NODES = 200                 # nodes of one field of a code object shown in the answer
MAX_PROBLEMS = 100
SHOWN_TARGET = 4096                 # characters of a string out of the file shown; a longer one is given by its length
BYTES_WINDOW = 4096
FLAGS = (
    (0x1, "OPTIMIZED"), (0x2, "NEWLOCALS"), (0x4, "VARARGS"), (0x8, "VARKEYWORDS"), (0x10, "NESTED"),
    (0x20, "GENERATOR"), (0x80, "COROUTINE"), (0x100, "ITERABLE_COROUTINE"), (0x200, "ASYNC_GENERATOR"),
)

PAGES = []                          # the stop block removes the temporary file (`_tmp`) of each entry: the result file is written under a temporary name

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
        r"""(?i:(?<![\w.-])(?:mysql|mysqldump|mysqladmin|mysqlcheck|mysqlimport|mysqlshow|mariadb|mariadb-dump|mariadb-admin)(?:\.exe)?(?=\s))(?:(?!(?i:mysql|mariadb)\b)[^\n]){0,512}?(?<=\s)-p(?=\S)(?:"([^"\n]{1,256})"|'([^'\n]{1,256})'|([^\s"']{1,256}))"""), -3),
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
_CRED_PLACEHOLDER = re.compile(r"%[-+ #0-9.]*[sdiuxXfeEgGcr](?![A-Za-z0-9])|\{\w*\}|%\w+%$")
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


def _cred_spans(text, shapes):
    spans = []
    big = len(text) > _CRED_GATE
    low = text.lower()
    sep = "=" in text or ":" in text or "%3" in low
    if "value" in low:
        _cred_pair_spans(text, spans)
    for why, rx, group in _CRED_RULES:
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
    for m in (_CRED_B64_RUN.finditer(text) if len(text) >= 128 else ()):
        if _cred_random_like(m.group(0)):
            spans.append((m.start(), m.end(), "a long unbroken base64-like run"))
    if shapes and len(text) >= 32:
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


def credential_spans(text, shapes=True):
    """(start, end, why) of each stretch of `text` that is a credential by the name it is given under or by its text, in order and
    not overlapping. `shapes` False leaves out the rules that recognise a key by its length alone (a value that is named a checksum or
    a digest is not scanned for them). This is not `token_spans`: an identifier (a GUID, a hex digest, an access key id, an ARN) is
    not a credential here, and a tool that prints identifiers on purpose asks only for these."""
    if len(text) > TEXT_LIMIT:
        return [(0, len(text), "text longer than %d characters" % TEXT_LIMIT)]
    if shapes and text in _CRED_CLEAN:
        return []
    spans = _cred_spans(text, shapes)
    if shapes and not spans and len(text) <= 256 and len(_CRED_CLEAN) < 100000:
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


def _credentials_withheld(text, kind):
    """`text` with each credential in it withheld. It runs after the rules above, on text that may hold their markers: a stretch that
    begins at a marker is theirs already."""
    out, last = [], 0
    for start, end, why in credential_spans(text):
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
    return shown_path("%s%s: %s" % (type(exc).__name__, " " + code if code else "", getattr(exc, "strerror", None) or type(exc).__name__))


def in_job():
    return bool(os.environ.get("JOB_ID") and os.environ.get("OUT"))


VALUES = [None]    # the values file of this call, once it exists: an answer that fails after it was created names it


# BEGIN SHARED ONE WAY OUT
# The same text is in doc_structure, pe_directories and the capa-floss recipe (tests/pack-re-process.test.ts holds the copies equal).
# Two steps stand between a string out of a file and any byte the tool writes. shown_path is the sanitiser: it withholds every shape
# below, by shape only: what is printed is what no rule here recognises, and a secret of another shape (a plain password, a token
# family the rules do not name, a token split across two fields) is printed. It reads the WHOLE text for what only the whole shows (a
# user-info whose `//` or host a split would remove, a `Basic`/`Bearer` credential, base64 joined by `/`), then each `/` component (a
# path is not one token), and a copy of the text without the characters that can split a token unseen (NUL, other control characters
# and their \xNN escapes, zero-width, soft hyphen, bidi and combining marks; NFKD folds full-width forms): a text whose copy holds a
# token is withheld whole. final_check is the backstop: every key and every value of what the tool is about to print or write is
# tested again with the same rules, and one that the sanitiser would still change (a string that did not pass through it, or a number
# long enough to be a key) is replaced by its length, counted, and the answer is partial. A field the backstop withholds is a fault of
# the tool, never of the file: the count says how many.
_CLEAN = set()                      # strings known to hold nothing to withhold: tested once (a table repeats its keys and kinds)
_CLEAN_CHARS = [0]                  # their total length, bounded
_CACHE_ALL = [False]                # True while a string is sanitised that the tool keeps for its answer: its settled result is remembered whatever its size
# A mailto: address has no user-info (RFC 6068: an address is local-part@domain), so the shared block keeps `mailto:name:secret@host`
# as an address; a ':' in the local part is a name:password pair placed there, and what follows the ':' (to the last `@` within
# MAILTO_SPAN characters, no `?`, space, `<` or `>` before it) is withheld here. It is found with one pass over the `mailto:name:`
# heads and a search for `@` inside a fixed window after each, so that a million `mailto:a:` cost a million small steps and not their
# square: a password of more than MAILTO_SPAN characters in a mailto: address is not withheld by this rule (the shared rules for a
# token-shaped run still read it).
MAILTO_HEAD = re.compile(r"mailto:[^:@?/\s]*:", re.I)
MAILTO_STOP = re.compile(r"[?\s<>]")
MAILTO_SPAN = 512


def mailto_userinfo(text):
    out, last = [], 0
    for m in MAILTO_HEAD.finditer(text):
        if m.start() < last:
            continue
        begin = m.end()
        window = min(len(text), begin + MAILTO_SPAN + 1)
        at = text.rfind("@", begin, window)
        if at >= 0:
            stop = MAILTO_STOP.search(text, begin, at)
            if stop:
                at = text.rfind("@", begin, stop.start())
        if at < 0:
            continue
        out.append(text[last:begin])
        out.append(_withheld("userinfo", at - begin, "urls"))
        last = at
    if not out:
        return text
    out.append(text[last:])
    return "".join(out)


# `name:secret@` wherever it stands, with or without a host after the `@` (a name cut at a declared length ends right there): the
# shared block's bare rule wants a host, and its URL rule wants the `//` a path split removes. A password may hold `@`: the user-info
# runs to the last `@` before the host, as a URL's does (RFC 3986 3.2.1). A format string (`user:%s@%s`) is kept.
CUT_USERINFO = re.compile(r"(?<![\w.%+-])(?!mailto:)[\w.%+-]{1,64}:[^\s/:<>]{1,128}(?=@)", re.I)
# A URL's user-info whose password holds `/`, `?` or `#` (files hold them raw, though RFC 3986 3.2.1 asks for percent-encoding): the
# first `@` of such a string follows a `/`, `?` or `#`, which no authority holds, so the password is read to the last `@` of the same
# whitespace-delimited token. A port (`host:8080/path@x`) is not one: only digits and then `/`, `?`, `#` or the end after the `:`. The
# `///` (a file URL: `file:///C:/Dir/icon@2x.png`) is not one. The bare form (`name:pass/word@host`, no `//`) is not read: a path with an `@` in it (`C:/Dir/icon@2x.png`) is not user-info.
SLASH_USERINFO = re.compile(r"(?:(?<=[^/]//)|(?<=^//))[\w.%+-]{1,64}:(?!\d{1,5}(?:[/?#]|$))(?=[^\s@/?#]{0,256}[/?#][^\s@]{0,256}@)(?:[^\s@]|@(?=[^\s@]*@)){1,512}(?=@)")


def slash_userinfo(text):
    """text with the user-info of a URL whose password holds `/`, `?` or `#` withheld (shown_path reads it too; a URL's query is split
    off before the sanitiser sees it, so this is also run first on a target)."""
    if "//" not in text or "@" not in text:
        return text
    return SLASH_USERINFO.sub(lambda m: _withheld("userinfo", len(m.group()), "urls"), text)


def plain_userinfo(text):
    """text with the user-info of a URL whose password holds `/`, `?` or `#` replaced by a plain name of the same length, which
    redact_url (it splits a URL at the first `?` and `#` and its authority at the first `/`) then withholds as user-info."""
    if "//" not in text or "@" not in text:
        return text
    return SLASH_USERINFO.sub(lambda m: "x" * len(m.group()), text)
# The value of a secret-named key (`Password=...;`, `password: ...`, `Pwd='...'`, `"AccountKey": "..."`, `"token": "..."`): after `=`, or
# after `:` for the password and key names (`token:`, `secret:` and `credentials:` are common in prose, so their `:` form counts only
# when the key itself is quoted, as in JSON), quoted (to its closing quote; an opening quote nothing closes is dropped and the rest is
# the value) or not (to `;`, a space or the end: a `,` `&` `<` `>` stays in the value, as a password may hold them). The short names
# (`pw`, `pass`, `auth`) only where no letter or digit precedes them, so that `bypass:` or `OAuth=` inside a word is not one. A value
# made only of `%` conversions is a format. A password that holds `;` or a space, or a quote of the other kind, is withheld up to it.
# The text can show a quote in three ways: as is, with up to four backslashes before it (JSON inside a JSON string, and the backslashes doubled again
# when the text is printed), and as an entity (`&quot;`, `&apos;`, `&#34;`, `&#39;`, `&#x22;`, `&#x27;`); a gap between a name and its `=` or `:`
# is a space, a tab, or a tab as it is written (`\t`, `\x09`). The same rule reads `<add key="Password" value="...">` (a name, its quote, then `value=`),
# and ELEMENT_SECRET reads `<Password>...</Password>` and its escaped form (`&lt;Password&gt;...&lt;/Password&gt;`).
_KV_ENTITY = r"&(?:quot|apos|#0{0,6}3[49]|#x2[27]);"
_KV_QUOTE = r"(?:\\{0,4}[\"']|" + _KV_ENTITY + r")"
_KV_GAP = r"(?:[ \t]|\\{1,2}(?:x09|t))*"
_KV_NAMES = (r"pass[_-]?word|pass[_-]?wd|pass[_-]?phrase|pwd|pswd|psw|secret[_-]?key|private[_-]?key|secret|client[_-]?secret|token|api[_-]?key"
             r"|access[_-]?key|account[_-]?key|shared[_-]?access[_-]?key|credentials?|(?<![A-Za-z0-9])(?:pw|pass|auth|sig)")
_KV_PASSWORD_NAMES = (r"pass[_-]?word|pass[_-]?wd|pass[_-]?phrase|pwd|pswd|psw|secret[_-]?key|private[_-]?key|client[_-]?secret|api[_-]?key|access[_-]?key|account[_-]?key"
                      r"|shared[_-]?access[_-]?key|(?<![A-Za-z0-9])(?:pw|pass)")
KEYVALUE_SECRET = re.compile(r"((?:(?:" + _KV_NAMES + r")" + _KV_QUOTE + r"?" + _KV_GAP + r"="
                             r"|(?:" + _KV_NAMES + r")" + _KV_QUOTE + r"[ \t]+value[ \t]*="
                             r"|(?:" + _KV_PASSWORD_NAMES + r")" + _KV_QUOTE + r"?" + _KV_GAP + r":"
                             r"|" + _KV_QUOTE + r"(?:token|secret|credentials?|auth|sig)" + _KV_QUOTE + _KV_GAP + r":)" + _KV_GAP + r")"
                             r"(?:(" + _KV_QUOTE + r")(?!<withheld )((?:(?!" + _KV_ENTITY + r")[^\"'\r\n]){1,512})(?=[\"']|" + _KV_ENTITY + r")"
                             r"|" + _KV_QUOTE + r"?(?!" + _KV_QUOTE + r"|\\{1,2}(?:x09|t))(?!<[a-z -]{0,40}withheld \d)([^;\s\"']{1,512}))", re.I)
# The letters any name of the rule above has in it. A text without them is not read by the rule, which would otherwise try every name at every
# position of it: the test is a few times cheaper than the rule on a text of any other kind.
KEYVALUE_HINT = re.compile(r"pw|pass|psw|secret|private|token|key|cred|auth|sig", re.I)
# The name of an element (or of a `name="..."` attribute) that holds a secret. Its text is withheld to the next `<` (or `&lt;`), the end of the
# line or the end of the text: nothing has to follow it, a `>` or `&gt;` inside the text does not end it and its length is not bounded, so that
# a value that is not closed, that holds `>` or that is longer than any window is withheld to its end and not printed whole. A text that begins
# with white space is read only when it is closed (`<token> x` in prose is no value; a padded `<Password> pw </Password>` is). The element
# may carry a namespace prefix (`<wsse:Password>`), and the setting forms are `<setting name="Password"><value>...`, and the element whose
# `name` or `key` attribute names the secret (`<property name="password">...`, `<entry key="password">...`).
_EL_NAMES = (r"pass[_-]?word|pass[_-]?wd|pass[_-]?phrase|pwd|pswd|secret[_-]?key|private[_-]?key|client[_-]?secret|api[_-]?key|access[_-]?key"
             r"|account[_-]?key|shared[_-]?access[_-]?key|token|secret")
# attributes of the open tag (`<Password Type="x">`, also with `&quot;`): `name=value` pairs, so that prose such as `<secret key>` is no element
_EL_ATTRS = (r"(?:[ \t]+[\w:.-]{1,64}[ \t]*=[ \t]*(?:\"[^\"<>\r\n]{0,128}\"|'[^'<>\r\n]{0,128}'|&quot;(?:(?!&quot;)[^<>\r\n]){0,128}&quot;"
             r"|[^\s\"'<>&]{1,128}))*")
# the text of an element: any character but `<` and a line break (`&lt;` ends it too); a value that begins with a `<` that is no tag (not a name and an
# end, a closing tag, a comment or an instruction) is a value that begins with one
_EL_REST = r"[^<&\r\n]*(?:&(?!lt;)[^<&\r\n]*)*"
_EL_TEXT = r"(?:[^<&\r\n]|&(?!lt;))" + _EL_REST
_EL_LEAD = r"(?:<|&lt;)(?!/?[A-Za-z][\w:.-]*(?:[ \t][^<>\r\n]{0,256})?/?(?:>|&gt;)|[!?/])"
# White space, `*`, `${NAME}`, `%NAME%` and `%s` in front of a value that begins with a `<` that is no tag are part of that value, not the text before it
# (`<Password>*****<8r$...` is a password after a mask, withheld whole). Each unit begins with a character of its own, so the run has one reading.
_EL_PREFIX = r"(?:[ \t*]|\$\{[A-Za-z_][A-Za-z0-9_]{0,31}\}|%(?:[A-Za-z_][A-Za-z0-9_]{0,31}%?|@))*"
ELEMENT_SECRET = re.compile(r"((?:(?:<|&lt;)(?:[A-Za-z_][\w.-]{0,31}:)?(?:" + _EL_NAMES + r")" + _EL_ATTRS + r"(?<!/)(?:>|&gt;)"
                            r"|<setting[ \t]+name[ \t]*=[ \t]*[\"'](?:" + _EL_NAMES + r")[\"']" + _EL_ATTRS + r"(?<!/)>(?:\s|\\[nrt]){0,256}<value>"
                            r"|<(?:property|entry)[ \t]+(?:name|key)[ \t]*=[ \t]*[\"'](?:" + _EL_NAMES + r")[\"']" + _EL_ATTRS + r"(?<!/)>))"
                            r"((?:" + _EL_PREFIX + _EL_LEAD + _EL_REST + r"|(?=\S)(?:" + _EL_LEAD + _EL_REST + r"|" + _EL_TEXT + r")|" + _EL_TEXT + r"(?=<|&lt;)))", re.I)
FORMAT_ONLY = re.compile(r"(?:%[-+ #0-9.*]*[A-Za-z@])+")
# What is no secret in a secret-named key's place: a format (above), a run of `*` (a mask), `${NAME}` and `%NAME%` (a variable a file names). Only
# those two rules use it; a user-info keeps FORMAT_ONLY. The other rules still read what is kept.
PLACEHOLDER_ONLY = re.compile(r"(?:%[-+ #0-9.*]*[A-Za-z@])+|\*+|\$\{[A-Za-z_][A-Za-z0-9_]{0,31}\}|%[A-Za-z_][A-Za-z0-9_]{0,31}%")


def _ends_element(m):
    """True when the part the rule read is all of the element's text: a closing tag, a line break or the end of the text follows it. A mask
    or a variable followed by more text (`*<8r<...`) is the head of a value and not the whole of one."""
    rest = m.string[m.end():m.end() + 5].lower()
    return rest == "" or rest[0] in "\r\n" or rest.startswith("</") or rest.startswith("&lt;/")


# The head of a token whose own prefix says what it is, too short for the shared block's patterns (a name cut by a declared length, a
# string read from the middle of a field): the prefix and four characters more are a piece of a token. An AWS key id's head, in capitals, is one
# wherever it stands (`XAKIA...` is a key id with a letter in front: its capitals and digits are no word). The GitHub, Slack and `sk-`
# prefixes are also the ends of words (`highs_lows`, `Risk-Assessment`, `Task-Scheduler`), so a short head of those counts only
# where no letter or digit precedes it, and twenty characters after the prefix count anywhere. `sk-` needs a capital or a digit in its
# first twelve characters, as a random key has, and twelve characters, or four where the string or a path component ends (a name cut
# by a declared length ends there). The GitHub and Slack prefixes are matched in any case: a resource compiler upper-cases a string
# resource name, and `XOXB-<digits>-...` keeps the digits. A JWT's head takes the `.`-joined segments after it (a JWT glued to another
# token loses its own head to that token's match, and its signature would be left).
TOKEN_HEAD = re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{4,}"
                        r"|(?<![A-Za-z0-9])(?i:gh[pousr]_)[A-Za-z0-9]{4,}|(?i:gh[pousr]_)[A-Za-z0-9]{20,}"
                        r"|(?i:github_pat_)[A-Za-z0-9_]{4,}|(?i:xox[abeprs]-)[A-Za-z0-9-]{4,}"
                        r"|(?<![A-Za-z0-9])sk-(?=[A-Za-z0-9_-]{0,11}[0-9A-Z])(?:[A-Za-z0-9_-]{12,}|[A-Za-z0-9_-]{4,11}(?=$|[/\\]))"
                        r"|sk-(?=[A-Za-z0-9_-]{0,11}[0-9A-Z])[A-Za-z0-9_-]{20,}|eyJ[A-Za-z0-9_-]{6,}(?:\.[A-Za-z0-9_-]+){0,2}")
# The body of a PEM block after its header (RFC 7468), up to the next '-' (its END line): withheld whole whatever its letters look like,
# as the dashes of a header glued to it join the two into one run that no shape rule of the shared block reads as a token.
PEM_BODY = re.compile(r"(-----BEGIN [^\r\n-]{1,64}-----)(?!<withheld)([^-]{8,})")
_GLUED_TAIL = re.compile(r"[A-Za-z0-9_+%-]*")


def _glued_spans(text):
    """The prefixed secrets of the shared block, each with the rest of the run of name characters it ends inside."""
    return _prefixed_spans(text, _GLUED_TAIL)


def _withhold_glued(text):
    out, last = [], 0
    for start, end in _glued_spans(text):
        out.append(text[last:start])
        out.append(_withheld("token-shaped text", end - start, "names"))
        last = end
    out.append(text[last:])
    return "".join(out)


JWT_TAIL = re.compile(r"(?<![A-Za-z0-9_+/-])eyJ[A-Za-z0-9_-]{6,}(?:\.[A-Za-z0-9_-]+){1,2}")
LONG_NUMBER = 10 ** 31              # a number of 32 digits or more is printed as its size: the same digits as a string are withheld (32 hex)
# Base64 joined by `/` (the AWS secret access key shape; a 16-, 20- or 32-byte value encoded): the pieces between two `/` are often too
# short to look like a token alone (the shared block's `/` rule wants three random-looking pieces), so whole pieces are read together.
# Random base64 changes character class (capital, small letter, digit) at about 0.64 of its characters; words, CamelCase names,
# versions and dated folders at 0.15 to 0.3. Every window of two or more whole pieces, 16 to 64 characters with its `/`, that holds a
# digit and no piece that is a plain word (`Outlook`, `Temp`, `FinalDraftV2`, `scan0042`: a random folder name next to a word is a
# cache directory, not a key), and that changes class at SLASH_DENSITY of its characters or more, is withheld; so is padded base64
# across `/` (below). A drive letter, a UNC host and a file name's extension are never in a window (a `.` or `:` ends the run). This
# is a shape rule with a measured residue, which the changelog states in numbers. The shared block's own `/` rule (three random-looking
# pieces) is kept, counting no plain word: the published example key, whose `EXAMPLEKEY` tail is not random, is caught by it.
SLASH_RUN = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
SLASH_DENSITY = 0.45
PLAIN_PIECE = re.compile(r"[A-Z]?[a-z]{3,}|(?=.{8})(?:[A-Z][a-z]{3,}){2,}(?:[A-Z]?[0-9]{1,4})?|(?=.{8})[A-Z]?[a-z]{3,}[0-9]{1,4}")


_CLASS_RUNS = re.compile(r"[A-Z]+|[a-z]+|[0-9]+")           # a piece's runs of one character class (`+` is not counted)


def _char_class(ch):
    return 0 if "A" <= ch <= "Z" else 1 if "a" <= ch <= "z" else 2 if "0" <= ch <= "9" else 3


def _slash_spans(text):
    spans = []
    # the shared block's `/` rule (three random-looking pieces, 30 characters, a digit), read as three such pieces in a row, none a plain word
    for m in _SLASHED.finditer(text):
        if "/" not in m.group():
            continue
        group, at = [], m.start()
        for piece in m.group().split("/") + [""]:
            if piece and _randomish(piece) and not PLAIN_PIECE.fullmatch(piece.rstrip("=")):
                group.append((at, at + len(piece)))
            else:
                if len(group) >= 3 and group[-1][1] - group[0][0] >= 30 and re.search(r"[0-9+]", text[group[0][0]:group[-1][1]]):
                    spans.append((group[0][0], group[-1][1]))
                group = []
            at += len(piece) + 1
    for m in SLASH_RUN.finditer(text):
        run = m.group()
        if "/" not in run.strip("/"):
            continue
        # each piece is read once: its start and end, whether it can be in a window (not a plain word; an empty piece, as `//` makes, and
        # `==` alone can be inside one, though no window begins or ends with either), the class of its first
        # and last counted character, its class changes, its counted characters and whether one is a digit (`+` and `=` not counted)
        pieces, at = [], m.start()
        for piece in run.split("/"):
            core = piece.rstrip("=")
            runs = _CLASS_RUNS.findall(core.replace("+", "")) if "+" in core else _CLASS_RUNS.findall(core)
            counted = sum(len(r) for r in runs)
            pieces.append((at, at + len(piece), bool(PLAIN_PIECE.fullmatch(core)), _char_class(runs[0][0]) if runs else None,
                           _char_class(runs[-1][0]) if runs else None, max(0, len(runs) - 1), counted, any(r[0].isdigit() for r in runs), len(core)))
            at += len(piece) + 1
        n = len(pieces)
        if run.endswith("="):
            # padded base64 (RFC 4648 section 4): the longest window of whole pieces that ends the run, holds a `/` and no plain word,
            # and is a multiple of four characters long, as an encoding with its padding is: the shared block's own `==` rule, across `/`
            clear = [False] * (n + 1)
            clear[n] = True
            for i in range(n - 1, -1, -1):
                clear[i] = clear[i + 1] and not pieces[i][2]
            for i in range(n - 1):
                length = m.end() - pieces[i][0]
                if clear[i] and pieces[i][8] and 16 <= length <= 64 and length % 4 == 0:
                    spans.append((pieces[i][0], m.end()))
                    break
        # prefix sums, so that a window costs a few additions: class changes inside pieces, at the `/` between two pieces (the last
        # counted character of the one before and the first of the next), counted characters, digits, and pieces a window cannot hold
        inner_sum, join_sum, char_sum, digit_sum, block_sum = [0], [0], [0], [0], [0]
        join, next_counted, last = [0] * n, [n] * (n + 1), None
        for k, (start, end, blocked, first, tail, inner, count, digit, core_len) in enumerate(pieces):
            join[k] = 1 if last is not None and first is not None and first != last else 0
            last = tail if tail is not None else last
            inner_sum.append(inner_sum[-1] + inner)
            join_sum.append(join_sum[-1] + join[k])
            char_sum.append(char_sum[-1] + count)
            digit_sum.append(digit_sum[-1] + (1 if digit else 0))
            block_sum.append(block_sum[-1] + (1 if blocked else 0))
        for k in range(n - 1, -1, -1):
            next_counted[k] = k if pieces[k][6] else next_counted[k + 1]
        far = 0
        for i in range(n):
            if pieces[i][2] or pieces[i][8] < 3:
                continue
            # the last piece a window from i can reach: within 64 characters and before a piece a window cannot hold
            far = max(far, i)
            while far + 1 < n and pieces[far + 1][1] - pieces[i][0] <= 64 and not pieces[far + 1][2]:
                far += 1
            while far > i and pieces[far][1] - pieces[i][0] > 64:
                far -= 1
            if far == i or digit_sum[far + 1] == digit_sum[i]:
                continue
            f = next_counted[i]
            # the longest window from i that is withheld: one span per start. A window neither begins nor ends with a piece of one or two
            # characters (a file name `s` after a withheld folder is not taken into it; such a piece of a key, left out, is two at most)
            for j in range(far, i, -1):
                end = pieces[j][1]
                if end - pieces[i][0] < 16:
                    break
                chars = char_sum[j + 1] - char_sum[i]
                if pieces[j][8] < 3 or chars < 14 or digit_sum[j + 1] == digit_sum[i]:
                    continue
                changes = inner_sum[j + 1] - inner_sum[i] + join_sum[j + 1] - join_sum[i + 1] - (join[f] if i < f <= j else 0)
                if changes >= SLASH_DENSITY * (chars - 1):
                    spans.append((pieces[i][0], end))
                    break
    spans.sort()
    merged = []
    for start, end in spans:
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


# What can split a token without being seen: control characters (NUL between the bytes of UTF-16 read as 8-bit text), their \xNN and
# \uNNNN escapes as cell() writes them, and the format and combining characters (zero-width, soft hyphen, bidi, variation selectors).
_HIDDEN_ESCAPE = re.compile(r"\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}")
_MAYBE_HIDDEN = re.compile(r"[^\x20-\x7e]|\\[xu][0-9a-fA-F]{2}")
# every space but U+0020 (no-break, en, ideographic and the like), which NFKD would make plain spaces that end a user-info; and the
# characters that print as nothing without being a format or combining mark: the line and paragraph separators, the braille blank, the
# Hangul fillers (U+115F, U+1160, U+3164, U+FFA0)
_NO_BREAK = {c: None for c in (0xA0, 0x1680, 0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008, 0x2009, 0x200A, 0x2028, 0x2029,
                               0x202F, 0x205F, 0x2800, 0x3000, 0x115F, 0x1160, 0x3164, 0xFFA0)}
_NON_ASCII_RUN = re.compile(r"[^\x00-\x7f]+")


def _redecoded(text, encoding):
    """text with each run of non-ASCII characters that is the UTF-8 of something, read by a tool as 8-bit text (Latin-1, CP437) and
    shown as the three or two characters it came to, put back to what the bytes mean (the three bytes of a zero-width space read as
    Latin-1 are three visible characters, and a token split by them is split unseen). None when no run is."""
    changed = [False]

    def back(m):
        try:
            fixed = m.group().encode(encoding).decode("utf-8")
        except UnicodeError:
            return m.group()
        changed[0] = True
        return fixed
    out = _NON_ASCII_RUN.sub(back, text)
    return out if changed[0] else None


def unhidden(text):
    """The text without what can split a token unseen (a copy that is tested, never printed)."""
    if not _MAYBE_HIDDEN.search(text):
        return text
    text = _HIDDEN_ESCAPE.sub("", text).translate(_NO_BREAK)
    # NFKD, so that a mark a composition would fold into its letter (L and U+0301 compose to U+0139) is a mark that is dropped
    text = unicodedata.normalize("NFKD", text)
    return "".join(ch for ch in text if not (unicodedata.category(ch) in ("Cc", "Cf", "Mn", "Me", "Cs")))


def hidden_copies(text):
    """The copies of the text a token may be split in unseen: without the hidden characters, and the same after the UTF-8 that was
    read as Latin-1 or CP437 is put back."""
    if not _MAYBE_HIDDEN.search(text):
        return ()
    copies = [unhidden(text)]
    for encoding in ("latin-1", "cp437"):
        back = _redecoded(text, encoding)
        if back is not None:
            copies.append(unhidden(back))
    return copies


def _whole_withheld(m, kind="names"):
    return _withheld("token-shaped text", len(m.group()), kind)


def _shown_pass(out):
    if "-----BEGIN " in out:
        out = PEM_BODY.sub(lambda m: m.group(1) + _withheld("", len(m.group(2)), "text"), out)
    if ":" in out:
        out = mailto_userinfo(out)
    if "@" in out:
        # first: a rule that withheld a piece of a password with a `:` in it would leave the marker, which breaks the token this one reads
        out = slash_userinfo(out)
    if ("=" in out or ":" in out) and KEYVALUE_HINT.search(out):
        # the value of a secret-named key before the bare user-info rule, for the same reason (the marker of that rule holds spaces)
        out = KEYVALUE_SECRET.sub(lambda m: m.group(0) if PLACEHOLDER_ONLY.fullmatch(m.group(3) or m.group(4)) else
                                  m.group(1) + (m.group(2) or "") + _withheld("", len(m.group(3) or m.group(4)), "text"), out)
    if ">" in out or "&gt;" in out:
        out = ELEMENT_SECRET.sub(lambda m: m.group() if PLACEHOLDER_ONLY.fullmatch(m.group(2).strip(" \t")) and _ends_element(m) else m.group(1) + _withheld("", len(m.group(2)), "text"), out)
    if "@" in out:
        out = CUT_USERINFO.sub(lambda m: m.group() if FORMAT_ONLY.fullmatch(m.group().partition(":")[2]) else _withheld("userinfo", len(m.group()), "urls"), out)
    # a prefixed token takes the rest of the run of name characters it ends inside (a token glued to it, whose own prefix it took), and
    # a JWT's payload and signature after a `.` are one token even when its head was glued to another and taken with it
    if "/" in out:
        # what only the whole text shows, found in the same text and withheld together (one rule's match never hides another's): base64
        # joined by `/`, a prefixed token (a JWT, `Basic`/`Bearer` holding `/`) with the run it ends inside, a user-info whose `//` or
        # host a split would remove; then each component alone
        found = [(s, e, "token-shaped text") for s, e in _slash_spans(out)]
        found += [(start, end, "token-shaped text") for start, end in _glued_spans(out)]
        found += [(m.start(), m.end(), "token-shaped text") for m in JWT_TAIL.finditer(out)]
        found += [(m.start(), m.end(), "userinfo") for rule in (_USERINFO, _BARE_USERINFO) for m in rule.finditer(out)]
        if found:
            found.sort()
            merged = []
            for s, e, what in found:
                if merged and s < merged[-1][1]:
                    ps, pe, pw = merged[-1]
                    merged[-1] = (ps, max(pe, e), "token-shaped text" if "token" in pw + what else pw)
                else:
                    merged.append((s, e, what))
            parts, last = [], 0
            for s, e, what in merged:
                parts.append(out[last:s])
                parts.append(_withheld(what, e - s, "urls" if what == "userinfo" else "names"))
                last = e
            parts.append(out[last:])
            out = "".join(parts)
        out = "/".join(scrub(part, "names") for part in out.split("/"))
    else:
        if "eyJ" in out:
            out = JWT_TAIL.sub(_whole_withheld, out)
        out = scrub(_withhold_glued(out), "names")
    return _grow(TOKEN_HEAD.sub(_whole_withheld, out))


_MARK_END = re.compile(r"<token-shaped text withheld (\d+) characters>$")
_MARK_START = re.compile(r"<token-shaped text withheld (\d+) characters>")
_PIECE = re.compile(r"[A-Za-z0-9_+%-]+={0,2}")
_PIECE_END = re.compile(r"[A-Za-z0-9_+%-]+={0,2}$")


def _grow(out):
    """A withheld token takes the random-looking pieces joined to it by `/` (the shared block's growth across `/`, which the component
    pass does not see): a piece of a key next to a piece withheld alone is not left printed."""
    if "/" not in out or "withheld" not in out:
        return out
    # the run of name characters a part begins or ends with is the piece taken, as the shared block's growth takes it (`\\srv\<piece>/`)
    res = []
    for part in out.split("/"):
        m = _MARK_END.search(res[-1]) if res else None
        piece = _PIECE.match(part) if m else None
        if piece and _randomish(piece.group()):
            res[-1] = res[-1][:m.start()] + _withheld("token-shaped text", int(m.group(1)) + 1 + piece.end(), "names") + part[piece.end():]
        else:
            res.append(part)
    out = []
    for part in reversed(res):
        m = _MARK_START.match(out[-1]) if out else None
        piece = _PIECE_END.search(part) if m else None
        if piece and _randomish(piece.group()):
            out[-1] = part[:piece.start()] + _withheld("token-shaped text", int(m.group(1)) + 1 + len(piece.group()), "names") + out[-1][m.end():]
        else:
            out.append(part)
    return "/".join(reversed(out))


_ONE_CLEAN = set()                  # pieces of text between escapes known to pass _shown_one unchanged


def _shown_one(text):
    if text in _ONE_CLEAN:
        return text, 1
    out = _shown_pass(text)
    passes = 1
    while out != text and passes < 4:
        text, out = out, _shown_pass(out)
        passes += 1
    if passes == 1 and len(out) <= 256 and len(_ONE_CLEAN) < 200000:
        _ONE_CLEAN.add(out)
    return out, passes


# The escapes cell() writes (\xNN and \uNNNN) end a piece of text: `\x06DataSpaces` is a control character and a word, and the `x06` of
# its escape is not a part of the word (whose digit would make it read as random). What an escape splits is tested joined by unhidden.
# A backslash of the file is written doubled and is a character of its piece, not an end of it (a password holding one is read whole);
# it is found as a pair only so that the `\x06` written for a file's own backslash and `x06` is not taken for an escape.
_ESCAPE = re.compile(r"\\\\|(\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4})")


def _shown(text):
    if "\\" not in text:
        return _shown_one(text)
    parts, passes, start = [], 1, 0
    for m in _ESCAPE.finditer(text):
        if m.group(1) is not None:
            parts.append(text[start:m.start()])
            parts.append(m.group(1))
            start = m.end()
    parts.append(text[start:])
    for k in range(0, len(parts), 2):
        parts[k], n = _shown_one(parts[k])
        passes = max(passes, n)
    return "".join(parts), passes


def shown_path(text):
    """A string as it may be printed: user-info, a secret-named value, a token-shaped run of the whole text and of each `/` component,
    every token head, withheld; and the whole text withheld when its copy without hidden characters (unhidden) holds any of these.
    A pass that withheld something is run again on its own result (a marker it wrote can leave a new edge in front of a user-info), up
    to four times, so that the result is a fixed point: shown_path of it is itself, which is what final_check tests."""
    if not isinstance(text, str):
        return text
    if text in _CLEAN:
        return text
    for bare in hidden_copies(text):
        if bare != text and _shown(bare)[0] != bare:
            return _withheld("token-shaped text", len(text), "names")
    out, passes = _shown(text)
    for bare in hidden_copies(out):
        if bare != out and _shown(bare)[0] != bare:
            return _withheld("token-shaped text", len(text), "names")
    # A result that settled (the last pass changed nothing, and the hidden-character copies above held nothing more) is known to be a
    # fixed point: the backstop and the next write of the same string do not read it again, so that a file of thousands of hostile names
    # costs the sanitiser one pass over each and not three. (Four passes may not have settled: that result is read again.)
    if passes < 4 and (_CACHE_ALL[0] or (len(out) <= 65536 and len(_CLEAN) < 200000 and _CLEAN_CHARS[0] + len(out) <= (1 << 25))):
        _CLEAN.add(out)
        _CLEAN_CHARS[0] += len(out)
    return out


def shown_number(value):
    if isinstance(value, int) and not isinstance(value, bool) and abs(value) >= LONG_NUMBER:
        return "<a number of %d bits, withheld>" % value.bit_length()
    return value


FINAL = {"fields": 0}


def _final_withheld(what):
    FINAL["fields"] += 1
    return "<withheld by the final check: %s>" % what


def final_check(value, safe=None, key=""):
    """The backstop. `value` is what is about to be written (after the sanitiser); `safe(key, text)` names the strings the tool made
    itself and registered (a file's path, a class id). Every other string, key or value, is withheld whole when shown_path would still
    change it; a number of 32 digits or more and any value of a type JSON does not carry are withheld too. Returns the value to write."""
    if isinstance(value, str):
        if (safe is not None and safe(key, value)) or shown_path(value) == value:
            return value
        return _final_withheld("%d characters" % len(value))
    if isinstance(value, bool) or value is None or isinstance(value, float):
        return value
    if isinstance(value, int):
        return value if abs(value) < LONG_NUMBER else _final_withheld("a number of %d bits" % value.bit_length())
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            name = k if isinstance(k, str) else str(k)
            if shown_path(name) != name:
                name = _final_withheld("a key of %d characters" % len(name))
            base, n = name, 1
            while name in out:
                n += 1
                name = "%s #%d" % (base, n)
            out[name] = final_check(v, safe, k if isinstance(k, str) else "")
        return out
    if isinstance(value, (list, tuple)):
        return [final_check(v, safe) for v in value]
    return _final_withheld("a value of type %s" % type(value).__name__)
# END SHARED ONE WAY OUT


class Rendered(str):
    """A string the tool made itself from bytes it has checked (a digest, the hex of a byte string whose text is clean): the backstop lets it through."""


def long_text(text, what="text"):
    return "<%s of %d characters: longer than the %d shown, so not shown>" % (what, len(text), SHOWN_TARGET)


def text_of(value):
    """A string out of a file as it may be printed: control characters escaped, then the sanitiser (shown_path) over the whole, and one
    longer than SHOWN_TARGET given by its length only."""
    text = value if isinstance(value, str) else str(value)
    if len(text) > SHOWN_TARGET:
        return long_text(text, "a string")
    return shown_path(cell(text))


def shown_name(text):
    return text_of(text)


# --- the one way out: every key and every value the tool prints or writes passes through shown_answer -------------------------------

SAFE_KEYS = {"result_file", "values_file"}
MADE = set()


def made(text):
    MADE.add(text)
    return text


def safe_made(key, text):
    return isinstance(text, Rendered) or (key in SAFE_KEYS and text in MADE)


def shown_key(key):
    key = key if isinstance(key, str) else str(key)
    if len(key) > SHOWN_TARGET:
        return long_text(key, "a key")
    return shown_path(key)


def shown_answer(value, key=""):
    """Every key and every value, at the boundary: a string is withheld component by component, a key the same way and given by its length
    past SHOWN_TARGET; two keys that are withheld to the same text are both kept (the second gets ' #2'); bytes are never printed."""
    if isinstance(value, str):
        if isinstance(value, Rendered) or (key in SAFE_KEYS and value in MADE):
            return value
        return shown_path(value)
    if isinstance(value, bool) or value is None or isinstance(value, float):
        return value
    if isinstance(value, int):
        return shown_number(value)
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            base, n = shown_key(k), 1
            name = base
            while name in out:
                n += 1
                name = "%s #%d" % (base, n)
            out[name] = shown_answer(v, k if isinstance(k, str) else "")
        return out
    if isinstance(value, (list, tuple)):
        return [shown_answer(v) for v in value]
    if isinstance(value, (bytes, bytearray, memoryview)):
        return "<%d bytes, not shown>" % len(value)
    return shown_path(str(value))


def build_answer(result):
    """The answer through the sanitiser (shown_answer), then through the backstop (final_check). A field the backstop withholds is counted in
    `withheld_by_final_check`, named in `problems`, and makes a complete answer partial: it is a fault of this tool, never of the file."""
    _CACHE_ALL[0] = True
    try:
        answer = final_check(shown_answer(result), safe_made)
    finally:
        _CACHE_ALL[0] = False
    if FINAL["fields"]:
        note = ("the final check withheld %d field(s) the sanitiser had let through: each is given by its length; a fault of this tool, "
                "not of the file" % FINAL["fields"])
        answer["withheld_by_final_check"] = FINAL["fields"]
        if isinstance(answer.get("problems"), list):
            answer["problems"].append(note)
        if answer.get("status") == "complete":
            answer["status"], answer["status_basis"] = "partial", note
    return answer



class Short(Exception):
    pass


class StreamError(Exception):
    pass


class Over(StreamError):
    """A budget or the clock was reached while the stream was shown; the message says which."""


# --- the call's plumbing ----------------------------------------------------------------------------------------------------

def emit(answer):
    print_answer(build_answer(answer), indent=None)


def fail(message, **extra):
    status = extra.pop("status", "failed")
    answer = {"ok": False, "error": message, "status": status, "status_basis": extra.pop("status_basis", message), "tool": TOOL, "problems": [], "limits_hit": [], **extra}
    if VALUES[0] is not None:
        VALUES[0].close()
        answer["secret_values"] = VALUES[0].summary()
    emit(answer)
    raise SystemExit(1)


def own_dir(path):
    """Create the directory and return None, or say why it is not used: a symbolic link anywhere on the way (the directory itself, or work/
    or the agent's directory under it) would send the result somewhere else, and O_NOFOLLOW guards only the last name of a file. In a job
    only the part under $OUT is checked ($OUT is the job service's)."""
    path = Path(path)
    out = os.environ.get("OUT")
    start = len(Path(out).parts) if out and path.parts[:len(Path(out).parts)] == Path(out).parts else 0
    for i in range(max(start, 1), len(path.parts) + 1):
        step = Path(*path.parts[:i])
        if os.path.islink(step):
            return "%s is a symbolic link: refused, nothing written through it" % shown_name(str(step))
    path.mkdir(parents=True, exist_ok=True)
    return None


VALUES = [None]


class ValuesRefused(Exception):
    pass


class Values:
    """The whole text of every string and byte string the answer and the result file withheld, in a job run as secret output and only when asked
    for (write_values). Decided before anything is read: the harness sets SECRET_OUTPUT=1 for a secret job's process. The file is created now,
    exclusively, mode 0600."""

    NAME = "marshal-inspect-values.jsonl"

    def __init__(self, enabled):
        self.enabled, self.written, self._fh, self.shown = enabled, 0, None, None
        if not enabled:
            return
        job, out = os.environ.get("JOB_ID") or "", os.environ.get("OUT") or ""
        if not (job and out) or os.environ.get("SECRET_OUTPUT") != "1":
            raise ValuesRefused("write_values is refused: the whole text of what was withheld is written only in a job the harness runs as secret "
                                "output (job_run with secret_output: true), where the file is a sealed secret output. Nothing was written.")
        path = Path(out) / self.NAME
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileExistsError:
            raise ValuesRefused("the values file already exists in $OUT: nothing was written")
        except OSError as exc:
            raise ValuesRefused("the values file could not be created: %s" % describe(exc))
        self._fh = os.fdopen(fd, "w", encoding="utf-8", buffering=1)
        self.shown = made("store/jobs/%s/out/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", job), self.NAME))

    def add(self, locator, value):
        if self._fh is None:
            return
        self.written += 1
        self._fh.write(json.dumps({"id": "V%06d" % self.written, **locator, "value": value}) + "\n")

    def close(self):
        if self._fh is not None:
            try:
                self._fh.flush()
                os.fsync(self._fh.fileno())
                self._fh.close()
            except OSError:
                pass
            self._fh = None

    def summary(self):
        return {"requested": self.enabled, "written": self.written, "values_file": self.shown, "contains_secret_values": self.written > 0,
                "format": "JSON Lines, mode 0600: id, code object, where in it, the whole string (or the hex of the whole byte string) that was withheld" if self.enabled else None}


def whole(args, name, default, low, high):
    v = args.get(name)
    if v is None:
        v = default
    if isinstance(v, bool) or not isinstance(v, int) or not low <= v <= high:
        fail("%s must be a whole number from %d to %d" % (name, low, high))
    return v


def open_regular(path):
    """The file as a descriptor, only if it is a regular file: opened without following a link and without blocking, then examined."""
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        fail("path is not a readable regular file: no such file", path=shown_name(path))
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            fail("path is a symbolic link: refused (this tool reads evidence files, not what a link points to)", path=shown_name(path))
        fail("path is not a readable regular file: %s" % describe(exc), path=shown_name(path))
    mode = os.fstat(fd).st_mode
    if not stat.S_ISREG(mode):
        os.close(fd)
        kinds = ((stat.S_ISDIR, "a directory"), (stat.S_ISFIFO, "a named pipe"), (stat.S_ISSOCK, "a socket"), (stat.S_ISBLK, "a block device"),
                 (stat.S_ISCHR, "a character device"))
        fail("path is not a readable regular file (%s)" % next((n for t, n in kinds if t(mode)), "a special file"), path=shown_name(path))
    return fd


def resolve_output(given):
    """Where `out_dir` lands: inside the run directory, not under inputs/, ledger/ or tools/ (the harness owns them), and in a job under $OUT, the
    one place a job writes. Returns the path relative to the run directory (or the absolute one under $OUT)."""
    root = Path.cwd().resolve()
    job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
    agent = re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool")
    want = given if given is not None else (os.path.join(out, TOOL["name"]) if job and out else os.path.join("work", agent, TOOL["name"]))
    if not isinstance(want, str) or not want or "\x00" in want:
        fail("out_dir must be a path")
    try:
        dest = Path(want).resolve() if Path(want).is_absolute() else (root / want).resolve()
    except (OSError, RuntimeError, ValueError):
        fail("out_dir could not be resolved")
    if dest == root or root not in dest.parents:
        fail("out_dir must be a directory inside the run directory")
    for owned in ("inputs", "ledger", "tools"):
        place = root / owned
        if dest == place or place in dest.parents:
            fail("out_dir cannot be under %s/" % owned)
    if job and out:
        base = Path(out).resolve()
        if dest != base and base not in dest.parents:
            fail("in a job out_dir is a directory under $OUT, the one place a job writes")
    if dest.exists() and not dest.is_dir():
        fail("out_dir is a file")
    # The path to create under is the one the caller gave, lexically (a symbolic link on the way is looked for in it, and `resolve` above would
    # have followed it): relative to the run directory, or absolute under $OUT in a job.
    lexical = Path(os.path.normpath(want if Path(want).is_absolute() else os.path.join(os.getcwd(), want)))
    try:
        return lexical.relative_to(os.getcwd())
    except ValueError:
        return lexical


def read_args():
    try:
        text = sys.stdin.read(1 << 20)
        args = json.loads(text)
    except (ValueError, RecursionError) as exc:
        fail("the arguments are not JSON", reason=type(exc).__name__)
    if not isinstance(args, dict):
        fail("the arguments must be a JSON object")
    known = ("path", "offset", "out_dir", "max_bytes", "preview", "bytecode", "limit", "max_seconds", "write_values")
    unknown = sorted(k for k in args if k not in known)
    if unknown:
        fail("argument(s) this tool does not have: %s" % ", ".join(shown_name(str(k)) for k in unknown[:10]))
    return args


# --- the objects ---------------------------------------------------------------------------------------------------------------

class Raw:
    """A byte string."""
    def __init__(self, data, offset):
        self.data, self.offset = data, offset


class Ref:
    """A reference to a container already read (or still being read): named, never followed, so a stream that refers to itself cannot make a
    loop, and one that refers to the same thing many times cannot make a result a million times its size."""
    def __init__(self, index):
        self.index = index


class Pending:
    """A container whose items are still being read."""


class Cont:
    """A tuple, list, set, frozenset or dict (items are (key, value) pairs), with its reference number when the stream marks it, and its weight:
    the objects in it."""
    def __init__(self, kind, items, ref):
        self.kind, self.items, self.ref = kind, items, ref
        self.weight = 1 + sum(weight(i) for pair in items for i in (pair if kind == "dict" else (pair,)))


def weight(x):
    return x.weight if isinstance(x, Cont) else 1


SMALL = 32   # a tuple this small that is referred to again is shown where it is referred to


class Special:
    """None, False, True, StopIteration, Ellipsis."""
    def __init__(self, name):
        self.name = name


class Code:
    def __init__(self, number, start):
        self.number, self.start = number, start


class Reader:
    def __init__(self, data, base, deadline):
        self.b, self.p, self.base, self.deadline = data, 0, base, deadline     # base: the stream's offset in the file
        self.refs, self.objects, self.depth_max, self.progress = [], 0, 0, 0
        self.codes = []
        self.cost, self.next_check = 0, READ_CLOCK_BYTES

    def clock(self, units):
        """The clock by what is processed, not by how many objects: one `long` of a million digits costs as much as thousands of small objects, so
        the clock is read each time READ_CLOCK_BYTES more bytes have been taken (before the work on them is done)."""
        self.cost += units
        if self.cost >= self.next_check:
            self.next_check = self.cost + READ_CLOCK_BYTES
            if time.monotonic() > self.deadline:
                raise Over("time: the read stopped at max_seconds after %d objects, at offset %d" % (self.objects, self.at()))

    def at(self):
        return self.base + self.p

    def take(self, n):
        if n < 0 or self.p + n > len(self.b):
            raise StreamError("the stream is cut short: %d more byte(s) wanted at offset %d, %d left" % (n, self.at(), len(self.b) - self.p))
        self.clock(n + 1)
        z = self.b[self.p:self.p + n]
        self.p += n
        return z

    def i32(self):
        return struct.unpack("<i", self.take(4))[0]

    def count(self, n, per=1):
        # A count that cannot fit in what is left is a damaged stream, and is refused before anything is allocated for it.
        if n < 0 or n * per > len(self.b) - self.p:
            raise StreamError("a count of %d at offset %d cannot fit in the %d byte(s) left" % (n, self.at(), len(self.b) - self.p))
        return n

    def reserve(self, flag, value=None):
        if flag:
            self.refs.append(value)
            return len(self.refs) - 1
        return None

    def obj(self, depth=0):
        if depth > MAX_DEPTH:
            raise StreamError("nesting deeper than %d at offset %d" % (MAX_DEPTH, self.at()))
        self.objects += 1
        if self.objects > MAX_OBJECTS:
            raise StreamError("more than %d objects" % MAX_OBJECTS)
        if not self.objects & 0xFFF and time.monotonic() > self.deadline:
            raise Over("time: the read stopped at max_seconds after %d objects, at offset %d" % (self.objects, self.at()))
        self.depth_max = max(self.depth_max, depth)
        start = self.at()
        raw = self.take(1)[0]
        flag, t = bool(raw & 0x80), chr(raw & 0x7F)
        if t == "0":
            return None
        if t == "r":
            n = self.i32()
            if not 0 <= n < len(self.refs):
                raise StreamError("a reference to object %d at offset %d, with %d read" % (n, start, len(self.refs)))
            target = self.refs[n]
            if isinstance(target, Pending) or (isinstance(target, Cont) and not (target.kind in ("tuple", "frozenset") and target.weight <= SMALL)):
                return Ref(n)
            return target
        if t in "NFTS.":
            v = Special({"N": "None", "F": "False", "T": "True", "S": "StopIteration", ".": "Ellipsis"}[t])
            self.reserve(flag, v)
            self.progress += 1
            return v
        if t == "i":
            v = self.i32()
        elif t == "I":
            v = struct.unpack("<q", self.take(8))[0]
        elif t == "l":
            n = self.i32()
            if time.monotonic() > self.deadline:
                raise Over("time: the read stopped at max_seconds after %d objects, at offset %d" % (self.objects, self.at()))
            if abs(n) > MAX_LONG_DIGITS:
                raise StreamError("a long of %d digits at offset %d is over the %d this reader builds" % (abs(n), start, MAX_LONG_DIGITS))
            digits = [struct.unpack("<H", self.take(2))[0] for _ in range(self.count(abs(n), 2))]
            if any(d >= 32768 for d in digits):
                raise StreamError("a digit of a long at offset %d is out of range" % start)
            # Built from its bits, so a long of a million digits costs a million steps, not their square.
            v = int("".join(format(d, "015b") for d in reversed(digits)) or "0", 2) * (-1 if n < 0 else 1)
        elif t == "g":
            v = struct.unpack("<d", self.take(8))[0]
        elif t == "y":
            v = ("complex", *struct.unpack("<dd", self.take(16)))
        elif t in "fx":
            parts = [self.take(self.take(1)[0]).decode("ascii", "replace") for _ in range(1 if t == "f" else 2)]
            v = parts[0] if t == "f" else ("complex-text", *parts)
        elif t == "s":
            n = self.count(self.i32())
            v = Raw(self.take(n), self.at() - n)
        elif t in "tuaA":
            n = self.count(self.i32())
            v = self.take(n).decode("utf-8", "surrogatepass")
        elif t in "zZ":
            v = self.take(self.take(1)[0]).decode("ascii", "replace")
        elif t in "()[<>":
            idx = self.reserve(flag, Pending())
            n = self.take(1)[0] if t == ")" else self.count(self.i32())
            items = [self.obj(depth + 1) for _ in range(n)]
            v = Cont({"(": "tuple", ")": "tuple", "[": "list", "<": "set", ">": "frozenset"}[t], items, idx)
            if idx is not None:
                self.refs[idx] = v
            self.progress += 1
            return v
        elif t == "{":
            idx = self.reserve(flag, Pending())
            pairs = []
            while True:
                k = self.obj(depth + 1)
                if k is None:
                    break
                pairs.append((k, self.obj(depth + 1)))
                if len(pairs) > MAX_OBJECTS:
                    raise StreamError("a dictionary of more than %d pairs" % MAX_OBJECTS)
            v = Cont("dict", pairs, idx)
            if idx is not None:
                self.refs[idx] = v
            self.progress += 1
            return v
        elif t == "c":
            return self.code(flag, start, depth)
        else:
            raise StreamError("marshal type %r (byte 0x%02x) at offset %d is not one this reader knows" % (t, raw, start))
        self.reserve(flag, v)
        self.progress += 1
        return v

    def code(self, flag, start, depth):
        idx = self.reserve(flag, Pending())
        c = Code(len(self.codes), start)
        self.codes.append(c)
        c.ref = idx
        c.argcount, c.posonlyargcount, c.kwonlyargcount, c.stacksize, c.flags = struct.unpack("<5i", self.take(20))
        for name in ("code", "consts", "names", "localsplusnames", "localspluskinds", "filename", "name", "qualname"):
            setattr(c, name, self.obj(depth + 1))
        c.firstlineno = self.i32()
        c.linetable = self.obj(depth + 1)
        c.exceptiontable = self.obj(depth + 1)
        c.end = self.at()
        if not isinstance(c.code, Raw) or not isinstance(c.name, str) or not isinstance(c.filename, str):
            raise StreamError("the code object at offset %d does not have the 3.11 to 3.13 layout this reader knows (its code is not bytes, or its name or file name is not text)" % start)
        if idx is not None:
            self.refs[idx] = c
        self.progress += 1
        return c


# --- views -----------------------------------------------------------------------------------------------------------------------

PRINTABLE_TRIGGER = re.compile(rb"[\x20-\x7e]{4}|(?:[\x20-\x7e]\x00){4}|(?:\x00[\x20-\x7e]){4}")
INT_BITS_NOTE = "an integer of 32 digits or more is given by its size (the sanitiser's rule); its whole is in the values file"


class View:
    """The objects of a stream as JSON-ready values, every string through the sanitiser and a second look (the backstop). `preview` shortens
    text and byte strings (None: as far as the sanitiser allows); `nodes` bounds how many nodes of a container are shown (None: all); `budget`
    bounds the characters shown, so that a text referred to many times cannot make a result a million times its size; `values`, when given,
    receives the whole of each string and byte string that was withheld."""

    def __init__(self, preview, nodes, budget, deadline, values=None):
        self.preview, self.nodes, self.budget, self.deadline, self.values = preview, nodes, budget, deadline, values
        self.spent = 0
        self.ticks = 0
        self.cost, self.next_check = 0, VIEW_CLOCK_UNITS
        self.code = None

    def clock(self, units):
        self.cost += units
        if self.cost >= self.next_check:
            self.next_check = self.cost + VIEW_CLOCK_UNITS
            if time.monotonic() > self.deadline:
                raise Over("time: showing the stream stopped at max_seconds")

    def spend(self, n):
        self.spent += n
        if self.spent > self.budget:
            raise Over("the stream shares text or numbers so that shown where they are used they come to more than %d characters" % self.budget)

    def tick(self):
        self.ticks += 1
        self.clock(32)

    def field(self, x, nodes=None):
        self.nodes = nodes
        return self.v(x, ())

    def withheld(self, path, value):
        if self.values is not None:
            self.values.add({"code": self.code, "where": list(path)[:64], "length": len(value)}, value)

    def sanitise(self, text):
        """The first stage: the string as it may be printed (the backstop below looks at what this returns)."""
        if len(text) > SHOWN_TARGET:
            return long_text(text, "a string")
        return shown_path(cell(text))

    def text(self, text, path):
        n = len(text)
        self.clock(min(n, SHOWN_TARGET) + 1)
        self.spend(n if self.preview is None else min(n, 2 * self.preview))
        shown = self.sanitise(text)
        changed = n > SHOWN_TARGET or shown != cell(text)
        if shown_path(shown) != shown:
            FINAL["fields"] += 1
            shown, changed = "<withheld by the final check: %d characters>" % len(shown), True
        if changed:
            self.withheld(path, text)
        if self.preview is not None and len(shown) > self.preview:
            return {"text": shown[:self.preview], "length": n, "shown": self.preview}
        return shown

    def bytes_clean(self, data):
        """Whether the text of these bytes (read as Latin-1, and the NUL-split forms that UTF-16 makes) holds nothing the sanitiser would withhold."""
        for at in range(0, len(data), BYTES_WINDOW):
            window = data[at:at + BYTES_WINDOW + 256]
            self.clock(len(window))
            if not PRINTABLE_TRIGGER.search(window):
                continue
            plain = cell(window.decode("latin-1"))
            if shown_path(plain) != plain:
                return False
        return True

    def raw(self, raw, path):
        data = raw.data
        shown = data if self.preview is None else data[:self.preview]
        self.clock(len(shown))
        self.spend(2 * len(shown))
        if self.bytes_clean(shown):
            out = {"bytes": len(data), "hex": Rendered(shown.hex())}
            if self.preview is not None and len(data) > self.preview:
                out["shown"] = self.preview
            return out
        self.withheld(path, data.hex())
        return {"bytes": len(data), "withheld": "the text of these bytes is shaped like a secret: not shown"}

    def hexed(self, data, path):
        """A byte string of the tool's own rendering (a code object's bytecode or tables) as hex, when its text is clean."""
        self.spend(2 * len(data))
        if self.bytes_clean(data):
            return Rendered(data.hex())
        self.withheld(path, data.hex())
        return "<withheld: the text of these bytes is shaped like a secret>"

    def v(self, x, path, depth=0):
        if depth > MAX_DEPTH + 4:
            return {"depth_limit": True}
        self.tick()
        if isinstance(x, Special):
            if x.name in ("None", "False", "True"):
                return {"None": None, "False": False, "True": True}[x.name]
            return {"const": x.name}
        if isinstance(x, Raw):
            return self.raw(x, path)
        if isinstance(x, str):
            return self.text(x, path)
        if isinstance(x, Ref):
            return {"ref": x.index}
        if isinstance(x, Code):
            return {"code": x.number}
        if isinstance(x, Cont):
            items = x.items
            body = []
            for i, item in enumerate(items):
                if self.nodes is not None:
                    if self.nodes <= 0:
                        body.append({"not_shown": len(items) - i})
                        break
                    self.nodes -= 1
                if x.kind == "dict":
                    body.append([self.v(item[0], path + (i, 0), depth + 1), self.v(item[1], path + (i, 1), depth + 1)])
                else:
                    body.append(self.v(item, path + (i,), depth + 1))
            if x.kind == "tuple" and (x.ref is None or x.weight <= SMALL):
                return body
            return {x.kind: body, **({"ref": x.ref} if x.ref is not None else {})}
        if isinstance(x, tuple) and x and x[0] in ("complex", "complex-text"):
            return {x[0]: [self.text(p, path) if isinstance(p, str) else p for p in x[1:]]}
        if isinstance(x, float):
            return {"float": repr(x)} if x != x or x in (float("inf"), float("-inf")) else x
        if isinstance(x, int) and not isinstance(x, bool):
            self.clock(x.bit_length() // 8 + 1)
            shown = shown_number(x)
            if shown is not x and shown != x:
                self.withheld(path, hex(x))
            return shown
        return x


def type_name(x):
    if isinstance(x, Cont):
        return x.kind
    if isinstance(x, Special):
        return x.name
    if isinstance(x, Raw):
        return "bytes"
    if isinstance(x, Code):
        return "code"
    if isinstance(x, Ref):
        return "ref"
    if isinstance(x, tuple):
        return x[0]
    return type(x).__name__ if x is not None else "none"


def code_row(c, view, bytecode, nodes):
    view.code = c.number
    names = [name for bit, name in FLAGS if c.flags & bit]
    base = ("code", c.number)
    row = {
        "code": c.number, "ref": c.ref, "stream_start": c.start, "stream_end": c.end,
        "name": view.field(c.name, nodes), "qualname": view.field(c.qualname, nodes), "filename": view.field(c.filename, nodes),
        "firstlineno": c.firstlineno, "argcount": c.argcount, "posonlyargcount": c.posonlyargcount, "kwonlyargcount": c.kwonlyargcount,
        "stacksize": c.stacksize, "flags": c.flags, "flag_names": names,
        "names": view.field(c.names, nodes), "localsplusnames": view.field(c.localsplusnames, nodes), "consts": view.field(c.consts, nodes),
        "bytecode_bytes": len(c.code.data), "bytecode_sha256": Rendered(hashlib.sha256(c.code.data).hexdigest()),
        "linetable_bytes": len(c.linetable.data) if isinstance(c.linetable, Raw) else None,
        "exceptiontable_bytes": len(c.exceptiontable.data) if isinstance(c.exceptiontable, Raw) else None,
    }
    if bytecode:
        row["bytecode_hex"] = view.hexed(c.code.data, base + ("bytecode",))
        row["linetable_hex"] = view.hexed(c.linetable.data, base + ("linetable",)) if isinstance(c.linetable, Raw) else None
        row["exceptiontable_hex"] = view.hexed(c.exceptiontable.data, base + ("exceptiontable",)) if isinstance(c.exceptiontable, Raw) else None
    return row


def python_of(magic):
    """The interpreter a .pyc magic number belongs to, by the bands CPython's importlib assigns (the final number of a release is the top of
    its band; development numbers sit below it)."""
    if magic < OLDEST_MAGIC:
        return "3.10 or older"
    for top, name in ((3499, "3.11"), (3549, "3.12"), (3599, "3.13"), (3649, "3.14")):
        if magic <= top:
            return name
    return "3.15 or newer"


def pyc_header(head):
    """The fields of a .pyc header (16 bytes, since Python 3.7), or None when it is not one."""
    if len(head) < 16 or head[2:4] != b"\r\n":
        return None
    magic = struct.unpack("<H", head[:2])[0]
    flags = struct.unpack("<I", head[4:8])[0]
    info = {"magic": magic, "python": python_of(magic), "flags": flags}
    if flags & 1:
        info["source_hash"] = head[8:16].hex()
        info["hash_checked"] = bool(flags & 2)
    else:
        mtime, size = struct.unpack("<II", head[8:16])
        try:
            info["source_mtime"] = datetime.fromtimestamp(mtime, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except (OverflowError, OSError, ValueError):
            info["source_mtime"] = None
        info["source_mtime_raw"] = mtime
        info["source_size"] = size
    return info


class ResultFile:
    """The whole result, written under a temporary name in its directory (exclusively, mode 0600) and given its final name only when it is
    complete, so that a stop signal or a failure never leaves a half-written file under the name the answer would have given: the stop block
    removes `_tmp`."""

    def __init__(self, directory, key):
        refused = own_dir(directory)
        if refused:
            raise OSError(errno.EPERM, refused)
        self.directory = Path(directory)
        self.stem = "%s-%s" % (TOOL["name"], hashlib.sha256(key.encode("utf-8", "surrogatepass")).hexdigest()[:12])
        self._tmp = None
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        for n in range(1, 100):
            name = ".%s.%d.%d.tmp" % (self.stem, os.getpid(), n)
            try:
                fd = os.open(str(self.directory / name), flags, 0o600)
            except FileExistsError:
                continue
            self._tmp = str(self.directory / name)
            self.fh = os.fdopen(fd, "w", encoding="ascii")
            PAGES.append(self)
            return
        raise OSError(errno.EEXIST, "ninety-nine temporary files of this name already exist")

    def publish(self):
        """Close the file and give it its final name, a name no earlier call used (a rerun never replaces a file). Returns the path."""
        self.fh.flush()
        os.fsync(self.fh.fileno())
        self.fh.close()
        try:
            for n in range(1, 100):
                name = "%s.json" % self.stem if n == 1 else "%s-%d.json" % (self.stem, n)
                final = self.directory / name
                try:
                    os.link(self._tmp, str(final))
                except FileExistsError:
                    continue
                except OSError:
                    if os.path.lexists(str(final)):
                        continue
                    os.rename(self._tmp, str(final))      # a file system without links: the name was free a moment ago
                    self._tmp = None
                    return final
                return final
            raise OSError(errno.EEXIST, "ninety-nine files of this name already exist")
        finally:
            self.discard()

    def discard(self):
        """Remove the temporary file (it no longer exists once it was renamed)."""
        tmp, self._tmp = self._tmp, None
        if self in PAGES:
            PAGES.remove(self)
        if tmp is not None:
            try:
                os.unlink(tmp)
            except OSError:
                pass


def main():
    install_signal_handlers(lambda signum: interrupted_answer(signum, tool=TOOL))
    args = read_args()
    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: the file holding the marshal stream")
    if "\x00" in path:
        fail("path is not a readable regular file: it holds a NUL")
    try:
        path.encode(sys.getfilesystemencoding(), sys.getfilesystemencodeerrors())
    except UnicodeError:
        fail("path cannot be encoded as a file name")
    max_bytes = whole(args, "max_bytes", 64 * 1024 * 1024, 16, 512 * 1024 * 1024)
    preview = whole(args, "preview", 160, 8, MAX_PREVIEW)
    limit = whole(args, "limit", DEFAULT_LIMIT, 1, MAX_LIMIT)
    seconds = whole(args, "max_seconds", DEFAULT_SECONDS, 1, MAX_SECONDS)
    bytecode = args.get("bytecode", True)
    if not isinstance(bytecode, bool):
        fail("bytecode is true or false")
    write_values = args.get("write_values", False)
    if not isinstance(write_values, bool):
        fail("write_values must be true or false")
    given_offset = args.get("offset")
    if given_offset is not None:
        given_offset = whole(args, "offset", 0, 0, 1 << 62)
    out_arg = args.get("out_dir")
    if out_arg is not None and (not isinstance(out_arg, str) or not out_arg):
        fail("out_dir must be a path")
    try:
        values = Values(write_values)
    except ValuesRefused as exc:
        fail(str(exc), write_values="refused", written=False)
    VALUES[0] = values
    deadline = time.monotonic() + seconds
    fd = open_regular(path)
    try:
        size = os.fstat(fd).st_size
        head = os.pread(fd, 16, 0)
        header, offset = None, given_offset
        if offset is None:
            header = pyc_header(head)
            offset = 16 if header else 0
        if offset > size:
            fail("offset is past the end of the file", offset=offset, size=size)
        if size - offset > max_bytes:
            fail("the stream is %d bytes, over max_bytes (%d); raise max_bytes or give an offset nearer its end" % (size - offset, max_bytes), size=size - offset)
        if header and python_of(header["magic"]) not in SUPPORTED:
            fail("the .pyc header names magic number %d, Python %s, whose code objects are %s from what this reads (3.11 to 3.13)" %
                 (header["magic"], header["python"], "laid out differently" if header["magic"] < OLDEST_MAGIC else "not read here"),
                 status="unsupported", pyc_header=header, python=header["python"])
        chunks, at = [], offset
        while at < size:
            if time.monotonic() > deadline:
                fail("time: reading the file stopped at max_seconds after %d of %d bytes" % (at - offset, size - offset), status="partial")
            block = os.pread(fd, min(8 << 20, size - at), at)
            if not block:
                break
            chunks.append(block)
            at += len(block)
        data = b"".join(chunks)
    finally:
        os.close(fd)
    rel_dir = resolve_output(out_arg)

    problems, limits = [], []
    reader = Reader(data, offset, deadline)
    error, root = None, None
    try:
        root = reader.obj()
    except Over as e:
        error = str(e)
        limits.append(error)
    except StreamError as e:
        error = str(e)
    except RecursionError:
        error = "the stream nests deeper than this reader can follow"
    _CACHE_ALL[0] = True
    try:
        file_view = View(None, None, 32 * 1024 * 1024, deadline, values if write_values else None)
        answer_view = View(preview, None, 8 * 1024 * 1024, deadline)
        try:
            done = [c for c in reader.codes if hasattr(c, "end")]
            rows = [code_row(c, file_view, bytecode, None) for c in done]
            file_view.code = None
            whole_root = file_view.field(root)
            shown = [code_row(c, answer_view, False, MAX_ROW_NODES) for c in done[:limit]]
            answer_root = answer_view.field(root, MAX_ANSWER_NODES)
        except Over as e:
            fail(str(e), status="partial", objects=reader.objects, references=len(reader.refs))
    finally:
        _CACHE_ALL[0] = False
    values.close()

    summary = {
        "tool": TOOL, "parser": PARSER, "schema_version": SCHEMA_VERSION,
        "source": {"path": shown_name(path), "bytes": size, "stream_offset": offset, **({"pyc_header": header} if header else {})},
        "mode": "data only: never marshal.loads, never a code object built, nothing imported or run",
        "layout": "CPython 3.11 to 3.13 code objects",
        "consumed_bytes": reader.p,
        "trailing_bytes": len(data) - reader.p,
        "objects": reader.objects,
        "references": len(reader.refs),
        "max_depth": reader.depth_max,
        "code_objects": len(rows),
        **({"error": error, "stopped_at": reader.at()} if error else {}),
    }
    document = dict(summary, root=whole_root, codes=rows)
    result_path = None
    key = json.dumps([shown_name(path), offset, bytecode], sort_keys=True)
    result = None
    try:
        result = ResultFile(rel_dir, key)
        json.dump(document, result.fh, indent=2, ensure_ascii=True)
        result_path = result.publish()
    except (OSError, ValueError) as exc:
        problems.append("the whole result could not be written to a file: %s" % describe(exc))
        result_path = None
        if result is not None:
            try:
                result.fh.close()
            except (OSError, ValueError):
                pass
            result.discard()
    if error:
        status = "partial" if reader.progress else "failed"
        basis = error
    elif limits or problems or FINAL["fields"]:
        status = "partial"
        basis = "%d problem(s), %d limit(s): see `problems` and `limits_hit`" % (len(problems), len(limits))
    else:
        status = "complete"
        basis = "the stream was read to the end of its root object, every object and every code object, and the whole result is in the file named in result_file"
    answer = dict(summary, ok=status == "complete", status=status, status_basis=basis, problems=problems, limits_hit=limits)
    answer["root_type"] = type_name(root)
    answer["root"] = answer_root
    answer["codes"] = shown
    if len(rows) > limit:
        answer["codes_shown"] = limit
    if result_path is not None:
        answer["result_file"] = made(os.path.relpath(result_path, Path.cwd()) if not result_path.is_absolute() else str(result_path))
        answer["result_file_holds"] = ("the whole tree, every code object and its bytecode as hex, with strings and byte strings withheld by shape" if bytecode else
                                       "the whole tree and every code object, with strings and byte strings withheld by shape")
    answer["withheld"] = COUNTS
    answer["secret_values"] = values.summary()
    answer["max_seconds"] = seconds
    answer["note"] = NOTE
    emit(answer)
    if error:
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:  # never a traceback and never a clean answer for a failure
        fail("unexpected failure: %s" % (describe(exc) if isinstance(exc, OSError) else type(exc).__name__))
