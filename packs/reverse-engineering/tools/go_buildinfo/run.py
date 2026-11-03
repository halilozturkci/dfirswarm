#!/usr/bin/env python3
"""Read the build information a Go binary carries, from its bytes, and never run it.

A binary built by the Go toolchain holds a header (the 14 bytes `\\xff Go buildinf:`, a pointer size, a flags byte) that names two
strings: the toolchain's version, and the module information the go command embedded (the main package and module, every
dependency with its version, its checksum and any replacement, and the build settings: `-compiler`, `-ldflags`, `CGO_ENABLED`,
`GOOS`, `GOARCH`, `vcs.revision`, ...). This tool finds that header in an ELF, PE or Mach-O file (a universal binary: in every
slice), reads the two strings, and reports them:

    where the header is   the section that holds it (`.go.buildinfo` in an ELF; `.data` in a PE; `__DATA,__go_buildinfo` in a
                          Mach-O), else a scan of the file for the magic at an offset that is a multiple of 16
    two formats           inline (Go 1.18 and later: two varint-prefixed strings follow the 32-byte header) and pointer (older:
                          two virtual addresses of Go string headers, turned into file offsets only through a section or
                          segment the container maps; a pointer outside them is a problem, never a guess)
    the module block      between its two 16-byte sentinels: `path`, `mod`, `dep` (and `=>` for a replacement) and `build` lines

Nothing is executed and nothing is resolved: a dependency is named by the version and checksum the binary records, not looked up. A
version, a path or a setting is a claim the go command wrote into the file; it shows what was built in, not what the code calls.
A binary built with `-ldflags -X` can carry a value there, so every string is withheld by its shape, and the whole of each string
the answer withheld is written to a sealed values file only with write_values, in a job.
"""
import errno
import hashlib
import json
import mmap
import os
import re
import stat
import struct
import sys
import time
import unicodedata
from pathlib import Path

TOOL = {"name": "go_buildinfo", "version": 4}
PARSER = "go_buildinfo/1"
SCHEMA_VERSION = 1
NOTE = ("A Go binary's build information is what the go command wrote into the file: the toolchain version, the module graph and the build settings. "
        "It shows what was built in, not what the code calls or whether a dependency is used, and a stripped or older binary may carry none: no header "
        "found is not 'not Go'. Read `status`, `status_basis`, `problems` and `limits_hit` first. A string out of the file is withheld by its shape only.")

MAGIC = b"\xff Go buildinf:"
HEADER_BYTES = 32
ALIGN = 16
INFO_START = bytes.fromhex("3077af0c9274080241e1c107e6d618e6")
INFO_END = bytes.fromhex("f932433186182072008242104116d8f2")
MAX_VERSION_BYTES = 4096                # the toolchain's version string: a longer one is not one
MAX_MODULE_BYTES = 64 << 20             # the module block read in one piece; a longer one is read to here and the rest is named
MAX_LINES = 2_000_000                   # lines of the module block read
MAX_LINE_BYTES = 1 << 20                # one line
DEFAULT_LIMIT = 500                     # rows of one table kept in the answer; the whole of a longer table is in a file
MAX_LIMIT = 5000
DEFAULT_SCAN = 512 << 20                # bytes the scan for the magic may cover in one call
MAX_SCAN = 4 << 30
SCAN_CHUNK = 16 << 20
DEFAULT_SECONDS = 80                    # the tool's own clock, below the manifest's 120 s: a slow file is a partial answer, not a kill
MAX_SECONDS = 100
MAX_SLICES = 16                         # slices of a universal binary read; the rest are named
MAX_SECTIONS = 65535
MAX_SEGMENTS = 65535
MAX_LOAD_COMMANDS = 65536
MAX_PROBLEMS = 100
MAX_UNALIGNED = 8                       # offsets of an unaligned magic that are listed
SHOWN_TARGET = 4096                     # characters of a string out of the file the answer shows; a longer one is given by its length
SECRET_NAME = re.compile(r"(?i)secret|passw|pwd|token|credential|api[_-]?key|private|auth|bearer|signing|cert|salt|seed")

PAGES = []                              # the pagers of this call (the stop block removes a temporary file of each; these write none)

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
# What a text must hold for any rule to match it: a literal one of them looks for, or a run long enough for a shape. A text with none of
# these is judged clean without running the rules (most names, addresses and ids).
_CRED_QUICK = re.compile(r"eyJ|-----BEGIN|\n|authorization|cookie|bearer|basic|digest|negotiate|ntlm|pass|pwd|secret|token|key|signature|sig|"
                         r"plaintext|hash|pin|otp|sas|securestring|gh[pousr]_|github_pat_|xox|AIza|ya29\.|1//0|IQoJb|FQoG|FwoG|Q~|[01]\.A|[sr]k_|"
                         r"://|gocspx|functions|code=|credential|assertion|mfacode|saml|mysql|mariadb|curl|\$2|"
                         r"[A-Za-z0-9+/]{32}|[A-Za-z0-9+/_-]{128}", re.I)
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
    if "value" in text.lower():
        _cred_pair_spans(text, spans)
    for why, rx, group in _CRED_RULES:
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
    for m in _CRED_B64_RUN.finditer(text):
        if _cred_random_like(m.group(0)):
            spans.append((m.start(), m.end(), "a long unbroken base64-like run"))
    if shapes:
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
    spans = _cred_spans(text, shapes) if _CRED_QUICK.search(text) else []
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
    if not _CRED_QUICK.search(text):
        return text
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


SUM_FORM = re.compile(r"h1:[A-Za-z0-9+/]{43}=\Z")                   # the checksum the go command writes: a hash of module files, no secret
REVISION_FORM = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")      # a version control revision (SHA-1 or SHA-256 of a commit)


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

# Strings the tool made itself and registered (a page file's path, a checksum or a revision in the exact form the go command writes): only
# these, and only under one of these keys, leave unchanged. Anything else, under any key, is withheld like any string out of the file.
SAFE_KEYS = {"all_results", "sum", "value", "vcs.revision"}
MADE = set()


def made(text):
    MADE.add(text)
    return text


def safe_made(key, text):
    return key in SAFE_KEYS and text in MADE


def shown_key(key):
    key = key if isinstance(key, str) else str(key)
    if len(key) > SHOWN_TARGET:
        return long_text(key, "a key")
    return shown_path(key)


def shown_answer(value, key=""):
    """Every key and every value, at the boundary: a string is withheld component by component, a key the same way and given by its length
    past SHOWN_TARGET; two keys that are withheld to the same text are both kept (the second gets ' #2'); bytes are never printed."""
    if isinstance(value, str):
        if key in SAFE_KEYS and value in MADE:
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


def ldflags_text(text):
    """A build setting's value with the value of every `-X symbol=value` whose symbol name is secret-named withheld whole (a name such as
    token, password or key says what the value is). By name only: the shape rules then read the rest, and a secret under another name is
    read by shape alone."""
    out, last = [], 0
    for m in re.finditer(r"""-X(?:=|\s+)(["']?)([^\s="']+)=""", text):
        if m.start() < last or not SECRET_NAME.search(m.group(2)):
            continue
        quote, begin = m.group(1), m.end()
        stop = text.find(quote, begin) if quote else -1
        if quote:
            end = stop if stop >= 0 else len(text)
        else:
            end = begin
            while end < len(text) and not text[end].isspace():
                end += 1
        out.append(text[last:begin])
        out.append(_withheld("secret-named value", end - begin, "text"))
        last = end
    out.append(text[last:])
    return "".join(out)

class Short(Exception):
    """A read that would run past the end of the file or of the structure that holds it."""


class Bad(Exception):
    """A field that cannot be what the format says it is."""


class Unmapped(Exception):
    """An address no section or segment of the container maps to file bytes."""


# --- the answer ---------------------------------------------------------------------------------------------------------------

def emit(answer):
    print_answer(build_answer(answer), indent=2)


def fail(message, **extra):
    status = extra.pop("status", "failed")
    answer = {"error": message, "status": status, "status_basis": message, "tool": TOOL, "problems": [], "limits_hit": [], **extra}
    if VALUES[0] is not None:
        answer["secret_values"] = VALUES[0].summary()
    emit(answer)
    raise SystemExit(1)


def own_dir(path):
    """Create the tool-output directory and return None, or say why it is not used: a symbolic link anywhere on the way (the directory itself,
    or work/ or the agent's directory under it) would send the tables somewhere else, and O_NOFOLLOW guards only the last name of a file.
    In a job only the part under $OUT is checked ($OUT is the job service's)."""
    path = Path(path)
    out = os.environ.get("OUT")
    start = len(Path(out).parts) if out and path.parts[:len(Path(out).parts)] == Path(out).parts else 0
    for i in range(max(start, 1), len(path.parts) + 1):
        step = Path(*path.parts[:i])
        if os.path.islink(step):
            return "%s is a symbolic link: refused, nothing written through it" % step
    path.mkdir(parents=True, exist_ok=True)
    return None


class Pager:
    """The first `limit` rows of a table in the answer; when there are more, the whole table as JSON Lines in a file that is created
    exclusively, mode 0600 (under a new name when the name is taken), and named in the answer. A row is added already withheld. A table
    that cannot be written whole says so, and the call goes partial."""

    def __init__(self, tool, key, limit):
        PAGES.append(self)
        self.tool = re.sub(r"[^A-Za-z0-9_.-]", "_", tool)
        self.limit = limit
        self.page = []
        self.total = 0
        self._out = None
        self.shown = None
        self.not_written = None
        digest = hashlib.sha256(json.dumps(key, sort_keys=True, default=str).encode("utf-8", "surrogatepass")).hexdigest()[:16]
        self.stem = "%s-%s" % (self.tool, digest)
        job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
        if out:
            self.dir = Path(out) / "tool-output"
            self.prefix = ("store/jobs/%s/out/tool-output/" % re.sub(r"[^A-Za-z0-9_.-]", "_", job)) if job else str(self.dir) + "/"
        else:
            agent = re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool")
            self.dir = Path("work") / agent / "tool-output"
            self.prefix = str(self.dir) + "/"

    def _open(self):
        try:
            refused = own_dir(self.dir)
            if refused:
                self.not_written = refused
                return
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            for n in range(1, 100):
                name = "%s.jsonl" % self.stem if n == 1 else "%s-%d.jsonl" % (self.stem, n)
                try:
                    fd = os.open(str(self.dir / name), flags, 0o600)
                except FileExistsError:
                    continue
                self.shown = made(self.prefix + name)
                self._out = os.fdopen(fd, "w", encoding="utf-8", buffering=1)
                for kept in self.page:
                    self._write(kept)
                return
            self.not_written = "ninety-nine files of this name already exist in the tool-output directory"
        except OSError as exc:
            self.not_written = "the file could not be created in the tool-output directory (%s)" % describe(exc)

    def _write(self, row):
        self._out.write(json.dumps(row) + "\n")

    @staticmethod
    def _clean(row):
        """The row as it will be written and shown (the sanitiser, then the backstop), kept in that form: the answer does not pay for it again."""
        _CACHE_ALL[0] = True
        try:
            return final_check(shown_answer(row), safe_made)
        finally:
            _CACHE_ALL[0] = False

    def add(self, row):
        self.total += 1
        row = self._clean(row)
        if len(self.page) < self.limit:
            self.page.append(row)
            return
        if self._out is None and self.not_written is None:
            self._open()
        if self._out is not None:
            try:
                self._write(row)
            except OSError as exc:
                self.not_written = "writing the file failed (%s)" % describe(exc)
                self._out = None

    def finish(self):
        result = {"matched": self.total, "returned": len(self.page), "truncated": self.total > len(self.page)}
        if self._out is not None:
            try:
                self._out.flush()
                os.fsync(self._out.fileno())
                self._out.close()
            except OSError as exc:
                self.not_written = "writing the file failed (%s)" % describe(exc)
            else:
                result["all_results"] = self.shown
                result["all_results_format"] = "JSON Lines, mode 0600, one complete row per line"
        if self.not_written:
            result["not_written"] = self.not_written
        return result


VALUES = [None]


class ValuesRefused(Exception):
    pass


class Values:
    """The whole text of every string the answer withheld, in a job run as secret output and only when asked for (write_values). Decided
    before anything is read: the harness sets SECRET_OUTPUT=1 for a secret job's process. The file is created now, exclusively, mode 0600."""

    NAME = "go-buildinfo-values.jsonl"

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
        self.shown = "store/jobs/%s/out/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", job), self.NAME)

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
                "format": "JSON Lines, mode 0600: id, slice, field, file offset, value (the whole string that the answer withheld)" if self.enabled else None}


# --- the call's bookkeeping ---------------------------------------------------------------------------------------------------

class Ctx:
    def __init__(self, seconds, limit, scan_budget, values, key):
        self.seconds, self.limit, self.values, self.key = seconds, limit, values, key
        self.deadline = time.monotonic() + seconds
        self.scan_left = scan_budget
        self.scan_budget = scan_budget
        self.slice = None

    def expired(self):
        return time.monotonic() > self.deadline


class Report:
    """What one slice (or the file) says about itself: problems, limits hit, and what was not read."""

    def __init__(self):
        self.problems, self.limits, self.dropped = [], [], 0
        self.timed_out = False
        self.incomplete = False        # something this read should have covered was not (a limit, the clock, a cut)

    def problem(self, text):
        if text in self.problems:
            return
        if len(self.problems) >= MAX_PROBLEMS:
            self.dropped += 1
            return
        self.problems.append(text)
        self.incomplete = True

    def limit_hit(self, text):
        if text not in self.limits:
            self.limits.append(text)
        self.incomplete = True

    def out_of_time(self, ctx, where):
        if not ctx.expired():
            return False
        if not self.timed_out:
            self.timed_out = True
            self.limit_hit("time: %s stopped at max_seconds (%d); what was read is reported, and the counts are lower bounds" % (where, ctx.seconds))
        return True


class Image:
    """One thin file, or one slice of a universal binary: offsets are relative to its start; `base` is where it starts in the file."""

    def __init__(self, mm, base, size):
        self.mm, self.base, self.size = mm, base, size

    def read(self, at, n):
        if at < 0 or n < 0 or at + n > self.size:
            raise Short("%d byte(s) at offset %d run past the end of the file (%d bytes)" % (n, at, self.size))
        return bytes(self.mm[self.base + at:self.base + at + n])

    def unpack(self, fmt, at):
        n = struct.calcsize(fmt)
        if at < 0 or at + n > self.size:
            raise Short("%d byte(s) at offset %d run past the end of the file (%d bytes)" % (n, at, self.size))
        return struct.unpack_from(fmt, self.mm, self.base + at)

    def find(self, needle, start, end):
        at = self.mm.find(needle, self.base + start, self.base + end)
        return at - self.base if at >= 0 else -1

    def cstr(self, at, cap=256):
        """The NUL-terminated name at `at` (read no further than `cap` bytes), as text; None when it is not terminated or not there."""
        if at < 0 or at >= self.size:
            return None
        stop = min(self.size, at + cap)
        nul = self.find(b"\x00", at, stop)
        if nul < 0:
            return None
        return self.read(at, nul - at).decode("utf-8", "replace")


class Container:
    """What a container tells about where to look and how to turn an address into a file offset."""

    def __init__(self, kind, bits, order):
        self.kind, self.bits, self.order = kind, bits, order
        self.maps = []        # (virtual address, bytes the file holds there, slice offset): the only way an address becomes an offset
        self.named = []       # (label, slice offset, size): where the header is expected
        self.data = []        # (label, slice offset, size): the data areas it can be in when no section names it
        self.notes = []       # facts for `container` in the answer


def translate(cont, address, length):
    """The slice offset of the `length` bytes at virtual address `address`, only through a mapping that holds them in the file."""
    if length < 0:
        raise Unmapped("a negative length")
    for virtual, held, offset in cont.maps:
        if virtual <= address < virtual + max(held, 1) and address + length <= virtual + held:
            return offset + (address - virtual)
    for virtual, held, offset in cont.maps:
        if virtual <= address < virtual + held:
            raise Unmapped("the %d bytes at address 0x%x run past the part of their section or segment that the file holds" % (length, address))
    raise Unmapped("address 0x%x is outside every section or segment the container maps" % address)


# --- containers -------------------------------------------------------------------------------------------------------------

ELF_PT_LOAD, ELF_PF_X, ELF_PF_W, ELF_SHT_NOBITS = 1, 1, 2, 8


def parse_elf(ctx, img, rep):
    ident = img.read(0, 16)
    cls, data = ident[4], ident[5]
    if cls not in (1, 2) or data not in (1, 2):
        raise Bad("the ELF identification names no known class or byte order (class %d, data %d)" % (cls, data))
    e = "<" if data == 1 else ">"
    cont = Container("elf", 64 if cls == 2 else 32, "little" if data == 1 else "big")
    if cls == 2:
        phoff, shoff = img.unpack(e + "QQ", 0x20)
        phentsize, phnum, shentsize, shnum, shstrndx = img.unpack(e + "HHHHH", 0x36)
        php, shp = "IIQQQQQQ", "IIQQQQIIQQ"
    else:
        phoff, shoff = img.unpack(e + "II", 0x1C)
        phentsize, phnum, shentsize, shnum, shstrndx = img.unpack(e + "HHHHH", 0x2A)
        php, shp = "IIIIIIII", "IIIIIIIIII"
    pn, sn = struct.calcsize(php), struct.calcsize(shp)
    if phnum and phentsize < pn:
        rep.problem("program headers: the entry size (%d) is smaller than a program header (%d): they are not read" % (phentsize, pn))
        phnum = 0
    if phnum > MAX_SEGMENTS:
        rep.limit_hit("program headers: %d are declared; the first %d are read" % (phnum, MAX_SEGMENTS))
        phnum = MAX_SEGMENTS
    try:
        for i in range(phnum):
            if i % 1024 == 0 and rep.out_of_time(ctx, "the program headers"):
                break
            row = img.unpack(e + php, phoff + i * phentsize)
            if cls == 2:
                p_type, p_flags, p_offset, p_vaddr, _pa, p_filesz, _ms, _al = row
            else:
                p_type, p_offset, p_vaddr, _pa, p_filesz, _ms, p_flags, _al = row
            if p_type != ELF_PT_LOAD:
                continue
            held = max(0, min(p_filesz, img.size - p_offset)) if p_offset < img.size else 0
            if held < p_filesz:
                rep.problem("program header %d declares %d file bytes at offset %d; the file holds %d of them" % (i, p_filesz, p_offset, held))
            cont.maps.append((p_vaddr, held, p_offset))
            if p_flags & ELF_PF_W and not p_flags & ELF_PF_X and held:
                cont.data.append(("a writable data segment (program header %d)" % i, p_offset, held))
    except Short as exc:
        rep.problem("program headers: %s" % exc)
    if shnum and shentsize < sn:
        rep.problem("section headers: the entry size (%d) is smaller than a section header (%d): they are not read" % (shentsize, sn))
        shnum = 0
    if shnum > MAX_SECTIONS:
        rep.limit_hit("section headers: %d are declared; the first %d are read" % (shnum, MAX_SECTIONS))
        shnum = MAX_SECTIONS
    if shnum and shoff:
        try:
            names_at = names_size = None
            if shstrndx < shnum:
                srow = img.unpack(e + shp, shoff + shstrndx * shentsize)
                names_at, names_size = (srow[4], srow[5]) if cls == 2 else (srow[4], srow[5])
            for i in range(shnum):
                if i % 1024 == 0 and rep.out_of_time(ctx, "the section headers"):
                    break
                sh_name, sh_type, _fl, _addr, sh_offset, sh_size = img.unpack(e + shp, shoff + i * shentsize)[:6]
                if names_at is None or sh_name >= (names_size or 0):
                    continue
                if img.cstr(names_at + sh_name, 32) == ".go.buildinfo":
                    if sh_type == ELF_SHT_NOBITS:
                        rep.problem("the .go.buildinfo section is NOBITS: the file holds no bytes for it")
                    else:
                        cont.named.append(("the .go.buildinfo section", sh_offset, sh_size))
        except Short as exc:
            rep.problem("section headers: %s" % exc)
    elif not shnum:
        cont.notes.append("no section headers: the header is looked for in the writable data segments and then in the whole file")
    return cont


def parse_pe(ctx, img, rep):
    lfanew = img.unpack("<I", 0x3C)[0]
    if img.read(lfanew, 4) != b"PE\x00\x00":
        raise Bad("the MZ header does not lead to a PE signature (e_lfanew 0x%x)" % lfanew)
    machine, nsec, _ts, _sym, _nsym, opt_size, _chars = img.unpack("<HHIIIHH", lfanew + 4)
    opt = lfanew + 24
    magic = img.unpack("<H", opt)[0]
    if magic == 0x10B:
        bits, image_base = 32, img.unpack("<I", opt + 28)[0]
    elif magic == 0x20B:
        bits, image_base = 64, img.unpack("<Q", opt + 24)[0]
    else:
        raise Bad("the optional header's magic is 0x%x, neither PE32 (0x10b) nor PE32+ (0x20b)" % magic)
    cont = Container("pe", bits, "little")
    if nsec > MAX_SECTIONS:
        rep.limit_hit("section table: %d sections are declared; the first %d are read" % (nsec, MAX_SECTIONS))
        nsec = MAX_SECTIONS
    table = opt + opt_size
    try:
        for i in range(nsec):
            if i % 1024 == 0 and rep.out_of_time(ctx, "the section table"):
                break
            name, vsize, rva, raw_size, raw_at, _r, _l, _nr, _nl, chars = img.unpack("<8sIIIIIIHHI", table + i * 40)
            held = raw_size if vsize == 0 else min(vsize, raw_size)
            if raw_at >= img.size:
                held = 0
            elif raw_at + held > img.size:
                rep.problem("section %d declares %d file bytes at offset %d; the file holds %d of them" % (i, held, raw_at, img.size - raw_at))
                held = img.size - raw_at
            cont.maps.append((image_base + rva, held, raw_at))
            label = name.rstrip(b"\x00").decode("latin-1")
            if label == ".data" and held:
                cont.named.append(("the .data section", raw_at, held))
            if chars & 0x80000000 and not chars & 0x20000000 and held:
                cont.data.append(("a writable section (%d)" % i, raw_at, held))
    except Short as exc:
        rep.problem("section table: %s" % exc)
    return cont


MACHO_THIN = {b"\xce\xfa\xed\xfe": (32, "<"), b"\xcf\xfa\xed\xfe": (64, "<"), b"\xfe\xed\xfa\xce": (32, ">"), b"\xfe\xed\xfa\xcf": (64, ">")}
FAT_MAGIC = {b"\xca\xfe\xba\xbe": (False, ">"), b"\xbe\xba\xfe\xca": (False, "<"), b"\xca\xfe\xba\xbf": (True, ">"), b"\xbf\xba\xfe\xca": (True, "<")}
LC_SEGMENT, LC_SEGMENT_64 = 0x1, 0x19


def parse_macho(ctx, img, rep):
    bits, e = MACHO_THIN[img.read(0, 4)]
    cont = Container("macho", bits, "little" if e == "<" else "big")
    _cpu, _sub, _type, ncmds, sizeofcmds, _flags = img.unpack(e + "iiIIII", 4)
    at = 28 if bits == 32 else 32
    end = min(img.size, at + sizeofcmds)
    if at + sizeofcmds > img.size:
        rep.problem("load commands: %d bytes are declared at offset %d; the file holds %d of them" % (sizeofcmds, at, max(0, img.size - at)))
    if ncmds > MAX_LOAD_COMMANDS:
        rep.limit_hit("load commands: %d are declared; the first %d are read" % (ncmds, MAX_LOAD_COMMANDS))
        ncmds = MAX_LOAD_COMMANDS
    try:
        for i in range(ncmds):
            if i % 1024 == 0 and rep.out_of_time(ctx, "the load commands"):
                break
            if at + 8 > end:
                rep.problem("load commands: %d are declared and the area holds %d" % (ncmds, i))
                break
            cmd, size = img.unpack(e + "II", at)
            if size < 8 or at + size > end:
                rep.problem("load command %d has the size %d, which does not fit the load command area: the rest are not read" % (i, size))
                break
            if cmd in (LC_SEGMENT, LC_SEGMENT_64):
                wide = cmd == LC_SEGMENT_64
                head = e + ("16sQQQQiiII" if wide else "16sIIIIiiII")
                seg_off = at + 8
                if size < 8 + struct.calcsize(head):
                    rep.problem("load command %d is a segment command shorter than its own fields" % i)
                else:
                    segname, vmaddr, _vmsize, fileoff, filesize, _mp, _ip, nsects, _fl = img.unpack(head, seg_off)
                    segname = segname.rstrip(b"\x00")
                    held = max(0, min(filesize, img.size - fileoff)) if fileoff < img.size else 0
                    if held < filesize:
                        rep.problem("segment %d declares %d file bytes at offset %d; the file holds %d of them" % (i, filesize, fileoff, held))
                    cont.maps.append((vmaddr, held, fileoff))
                    if segname in (b"__DATA", b"__DATA_CONST") and held:
                        cont.data.append(("the %s segment" % segname.decode("latin-1"), fileoff, held))
                    sect = e + ("16s16sQQIIIIIIII" if wide else "16s16sIIIIIIIII")
                    sect_size = struct.calcsize(sect)
                    first = seg_off + struct.calcsize(head)
                    for s in range(min(nsects, (size - 8 - struct.calcsize(head)) // sect_size)):
                        row = img.unpack(sect, first + s * sect_size)
                        sectname, sname = row[0].rstrip(b"\x00"), row[1].rstrip(b"\x00")
                        sec_size, sec_off = (row[3], row[4]) if wide else (row[3], row[4])
                        if sectname == b"__go_buildinfo" and sname.startswith(b"__DATA"):
                            cont.named.append(("the __DATA,__go_buildinfo section", sec_off, sec_size))
            at += size
    except Short as exc:
        rep.problem("load commands: %s" % exc)
    return cont


def sniff(img):
    head = img.read(0, min(4, img.size)) if img.size else b""
    if head == b"\x7fELF":
        return "elf"
    if head[:2] == b"MZ":
        return "pe"
    if head in MACHO_THIN:
        return "macho"
    return None


# --- the header ------------------------------------------------------------------------------------------------------------

def scan(ctx, img, rep, start, end, label, seen):
    """The slice offset of the first copy of the magic in [start, end) at a multiple of 16 from `start`, else None. (None, complete): whether
    every byte of the range was looked at. Copies at another alignment are not accepted; they are counted in `seen`."""
    pos = start
    while pos < end:
        if rep.out_of_time(ctx, "the scan for the header"):
            return None, False
        if ctx.scan_left <= 0:
            rep.limit_hit("scan: the budget of %d bytes was reached at offset %d of %s; the rest of it was not looked at" % (ctx.scan_budget, pos, label))
            return None, False
        stop = min(end, pos + min(SCAN_CHUNK, ctx.scan_left) + len(MAGIC) - 1)
        at = img.find(MAGIC, pos, stop)
        if at < 0:
            ctx.scan_left -= stop - pos - (len(MAGIC) - 1 if stop < end else 0)
            pos = stop - (len(MAGIC) - 1) if stop < end else stop
            continue
        if (at - start) % ALIGN == 0:
            if at + HEADER_BYTES <= img.size:
                return at, True
            rep.problem("the magic at offset %d is aligned, but the file ends before its 32-byte header does: not read" % (img.base + at))
            return None, False
        if at not in seen["offsets"]:
            seen["count"] += 1
            if len(seen["offsets"]) < MAX_UNALIGNED:
                seen["offsets"].append(at)
        ctx.scan_left -= at + 1 - pos
        pos = at + 1
    return None, True


def locate(ctx, img, cont, rep):
    """(slice offset of the header, where it was found, whether every place that could hold it was looked at, unaligned copies)."""
    seen = {"count": 0, "offsets": []}
    covered = True
    tried = []
    for places in (cont.named if cont else [], cont.data if cont else []):
        for label, off, size in places:
            end = min(img.size, off + size)
            if off < 0 or off >= end:
                continue
            tried.append((off, end))
            hit, ok = scan(ctx, img, rep, off, end, label, seen)
            if hit is not None:
                return hit, label, True, seen
            covered = covered and ok
        if not covered:
            break
    if covered and not any(off == 0 and end >= img.size for off, end in tried):
        hit, ok = scan(ctx, img, rep, 0, img.size, "the file", seen)
        if hit is not None:
            return hit, "a scan of the file for the magic", True, seen
        covered = covered and ok
    return None, None, covered, seen


def uvarint(data, at):
    """(value, bytes used) of the unsigned LEB128 number at `at`; a number of more than 64 bits is Bad."""
    value, shift = 0, 0
    for i in range(10):
        if at + i >= len(data):
            raise Short("a variable-length number runs past the end of the data")
        byte = data[at + i]
        if i == 9 and byte > 1:
            raise Bad("a variable-length number does not fit 64 bits (overflow)")
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            return value, i + 1
        shift += 7
    raise Bad("a variable-length number is longer than 10 bytes (overflow)")


def go_unquote(text):
    """(the string, the length used) of a Go double-quoted string at the start of `text`; Bad when it is not one."""
    if not text.startswith('"'):
        raise Bad("not a quoted string")
    out, i = [], 1
    simple = {"a": "\a", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t", "v": "\v", "\\": "\\", '"': '"'}
    while i < len(text):
        ch = text[i]
        if ch == '"':
            return "".join(out), i + 1
        if ch == "\n":
            raise Bad("a line break inside a quoted string")
        if ch != "\\":
            out.append(ch)
            i += 1
            continue
        i += 1
        if i >= len(text):
            break
        esc = text[i]
        if esc in simple:
            out.append(simple[esc])
            i += 1
        elif esc in "xuU":
            n = {"x": 2, "u": 4, "U": 8}[esc]
            digits = text[i + 1:i + 1 + n]
            if len(digits) != n or not all(c in "0123456789abcdefABCDEF" for c in digits):
                raise Bad("a bad \\%s escape" % esc)
            code = int(digits, 16)
            if esc == "x":
                out.append(chr(0xDC00 + code) if code >= 0x80 else chr(code))     # a raw byte: kept as the escape the printer writes
            else:
                if code > 0x10FFFF or 0xD800 <= code < 0xE000:
                    raise Bad("a code point out of range in an escape")
                out.append(chr(code))
            i += 1 + n
        elif esc in "01234567":
            digits = text[i:i + 3]
            if len(digits) != 3 or not all(c in "01234567" for c in digits) or int(digits, 8) > 255:
                raise Bad("a bad octal escape")
            code = int(digits, 8)
            out.append(chr(0xDC00 + code) if code >= 0x80 else chr(code))
            i += 3
        else:
            raise Bad("an unknown escape \\%s" % esc)
    raise Bad("a quoted string that is not closed")


def split_build(rest):
    """The key and the value of a `build` line: `key=value`, with either side quoted by Go when it holds a space, a quote or an unprintable."""
    if rest.startswith('"'):
        key, used = go_unquote(rest)
        if rest[used:used + 1] != "=":
            raise Bad("a quoted key that is not followed by =")
        value_text = rest[used + 1:]
    else:
        key, eq, value_text = rest.partition("=")
        if not eq:
            raise Bad("a build line with no =")
    if value_text.startswith('"'):
        value, used = go_unquote(value_text)
        if used != len(value_text):
            raise Bad("text after a quoted value")
        return key, value
    return key, value_text


# --- the strings the header names -----------------------------------------------------------------------------------------

def read_strings(ctx, img, rep, cont, at):
    """Read the two strings the header at slice offset `at` names. Returns (info, version bytes or None, module block or None), the block as
    (bytes, absolute offset, bytes declared, cut). Whatever cannot be read is a problem of `rep`, never a guess."""
    raw = img.read(at, HEADER_BYTES)
    ptr, flags = raw[14], raw[15]
    inline = bool(flags & 2)
    info = {"offset": img.base + at, "slice_offset": at, "pointer_size": ptr, "flags": flags, "format": "inline" if inline else "pointer"}
    if inline:
        info["flags_basis"] = "bit 1 set: the version and the module information follow the header as varint-prefixed strings"
    version = module = None
    if inline:
        pos = at + HEADER_BYTES
        try:
            head = img.read(pos, min(10, img.size - pos))
            n, used = uvarint(head, 0)
            start = pos + used
            if n > MAX_VERSION_BYTES:
                raise Bad("the version string is declared %d bytes, more than the %d a version can be" % (n, MAX_VERSION_BYTES))
            if n > img.size - start:
                raise Short("the version string is declared %d bytes and the file holds %d after it" % (n, img.size - start))
            version = img.read(start, n)
            pos = start + n
            head = img.read(pos, min(10, img.size - pos))
            n, used = uvarint(head, 0)
            start = pos + used
            avail = img.size - start
            take = min(n, avail, MAX_MODULE_BYTES)
            if n > MAX_MODULE_BYTES:
                rep.limit_hit("module block: %d bytes are declared; the first %d are read and the rest is not" % (n, MAX_MODULE_BYTES))
            module = (img.read(start, take), img.base + start, n, n > avail)
        except (Short, Bad) as exc:
            rep.problem("inline strings: %s" % exc)
        return info, version, module
    if ptr not in (4, 8):
        rep.problem("pointer format: the header's pointer size is %d, neither 4 nor 8" % ptr)
        return info, None, None
    order = ">" if flags != 0 else "<"
    info["byte_order"] = "big" if flags != 0 else "little"
    if flags not in (0, 1):
        rep.problem("pointer format: the flags byte is 0x%02x, not 0 or 1; read as big-endian, as the go command's own reader does" % flags)
    fmt = order + ("I" if ptr == 4 else "Q")

    def string_at(label, header_address, cap):
        if header_address == 0:
            raise Bad("the %s pointer is 0" % label)
        hdr = img.read(translate(cont, header_address, 2 * ptr), 2 * ptr)
        data_address, length = struct.unpack(order + ("II" if ptr == 4 else "QQ"), hdr)
        if length > cap:
            raise Bad("the %s string is declared %d bytes, more than the %d read" % (label, length, cap))
        where = translate(cont, data_address, length)
        return img.read(where, length), img.base + where, length

    try:
        version = string_at("version", struct.unpack_from(fmt, raw, 16)[0], MAX_VERSION_BYTES)[0]
    except (Short, Bad, Unmapped) as exc:
        rep.problem("pointer format: the version string: %s" % exc)
    try:
        data, where, length = string_at("module information", struct.unpack_from(fmt, raw, 16 + ptr)[0], MAX_MODULE_BYTES)
        module = (data, where, length, False)
    except (Short, Bad, Unmapped) as exc:
        rep.problem("pointer format: the module information: %s" % exc)
    return info, version, module


# --- the module block --------------------------------------------------------------------------------------------------------

SELECTED = ("-compiler", "-ldflags", "-buildmode", "CGO_ENABLED", "GOOS", "GOARCH", "vcs", "vcs.revision", "vcs.time", "vcs.modified")


def show(ctx, field, raw, offset, kind="names", exact=None, pre=None):
    """A string out of the file as it may be printed; what the answer withheld of it goes whole to the values file when that was asked for."""
    if exact is not None and exact.match(raw):
        return made(raw)
    text = pre(raw) if pre else raw
    shown = text_of(text)
    if ctx.values is not None and (text != raw or len(text) > SHOWN_TARGET or shown != cell(text)):
        ctx.values.add({"slice": ctx.slice, "field": field, "offset": offset}, raw)
    return shown


def parse_module(ctx, rep, block, deps, settings):
    """Read the module block into the pagers. Returns the facts about it; complete only when it ran from its start sentinel to its end sentinel
    at the declared length and every line was read."""
    data, abs_at, declared, cut = block
    facts = {"bytes_declared": declared, "bytes_read": len(data), "offset": abs_at, "start_sentinel": data.startswith(INFO_START),
             "end_sentinel": data.endswith(INFO_END), "lines": 0, "main_package": None, "main_module": None, "settings_selected": {}}
    framed = len(data) >= 33 and data[-17] == 10 and facts["start_sentinel"] and facts["end_sentinel"]
    ended = framed and not cut and len(data) == declared
    if declared == 0:
        facts["present"] = False
        return facts, True
    facts["present"] = True
    if cut:
        rep.problem("module block: %d bytes are declared and the file holds %d: the block is cut and has no end sentinel" % (declared, len(data)))
    elif len(data) < declared:
        rep.problem("module block: %d bytes are declared and %d were read" % (declared, len(data)))
    elif not ended:
        rep.problem("module block: %s" % ("it is shorter than its two sentinels" if len(data) < 33 else
                                          "the start or the end sentinel is not the one the go command writes, or no line break precedes the end sentinel"))
    begin = 16 if facts["start_sentinel"] else 0
    end = len(data) - 16 if facts["end_sentinel"] and len(data) >= 33 else len(data)
    pending = [None]            # the last dependency row, held until the line after it shows whether it has a replacement
    last = [None]               # the object a `=>` line belongs to
    counts = {"dep": 0, "setting": 0}
    unknown = {}
    pos, line_no = begin, 0
    stopped = False

    def triple(rest, field, offset):
        parts = rest.split("\t")
        if len(parts) > 3:
            rep.problem("module block line %d has %d tab-separated fields; the first three are read" % (line_no, len(parts)))
        parts = (parts + ["", "", ""])[:3]
        return {"path": show(ctx, field + ".path", parts[0], offset, "names"),
                "version": show(ctx, field + ".version", parts[1], offset, "names"),
                "sum": show(ctx, field + ".sum", parts[2], offset, "names", SUM_FORM)}

    def flush():
        if pending[0] is not None:
            deps.add(pending[0])
            pending[0] = None

    while pos < end:
        if line_no % 256 == 0 and rep.out_of_time(ctx, "the module block"):
            stopped = True
            break
        if line_no >= MAX_LINES:
            rep.limit_hit("module block: %d lines were read; the rest of the block was not" % MAX_LINES)
            stopped = True
            break
        nl = data.find(b"\n", pos, end)
        if nl < 0:
            rep.problem("module block: the last line (offset %d) has no line break (the block is cut there); it is not read" % (abs_at + pos))
            break
        line_no += 1
        if nl - pos > MAX_LINE_BYTES:
            rep.problem("module block line %d is %d bytes, more than the %d read; it is not read" % (line_no, nl - pos, MAX_LINE_BYTES))
            pos = nl + 1
            continue
        line_at = abs_at + pos
        line = data[pos:nl].decode("utf-8", "surrogateescape")
        pos = nl + 1
        kind, _tab, rest = line.partition("\t")
        if kind == "=>":
            flush_target = last[0]
            if flush_target is None:
                rep.problem("module block line %d is a replacement with no module before it" % line_no)
            else:
                flush_target["replacement"] = triple(rest, "replacement", line_at)
            continue
        flush()
        if kind == "path":
            facts["main_package"] = show(ctx, "main_package", rest, line_at, "names")
            last[0] = None
        elif kind == "mod":
            mod = triple(rest, "main_module", line_at)
            mod["replacement"] = None
            facts["main_module"] = mod
            last[0] = mod
        elif kind == "dep":
            row = triple(rest, "dependency[%d]" % (counts["dep"] + 1), line_at)
            counts["dep"] += 1
            row = {"n": counts["dep"], **row, "replacement": None, "offset": line_at, "line": line_no}
            pending[0] = row
            last[0] = row
        elif kind == "build":
            try:
                key, value = split_build(rest)
            except Bad as exc:
                rep.problem("module block line %d: a build setting that is not in the form the go command writes (%s): kept as text" % (line_no, exc))
                counts["setting"] += 1
                settings.add({"n": counts["setting"], "key": None, "value": None, "parsed": False,
                              "text": show(ctx, "build_setting[%d].text" % counts["setting"], rest, line_at, "text", None, ldflags_text),
                              "offset": line_at, "line": line_no})
                last[0] = None
                continue
            counts["setting"] += 1
            shown_key = show(ctx, "build_setting[%d].key" % counts["setting"], key, line_at, "names")
            # the value of a setting whose key says what it holds (a key named password, token, secret ...) is withheld whole, by the key's name
            secret_key = SECRET_NAME.search(key) is not None
            shown_value = show(ctx, "build_setting[%d].value" % counts["setting"], value, line_at, "text", REVISION_FORM if key == "vcs.revision" else None,
                               (lambda raw: _withheld("secret-named value", len(raw), "text")) if secret_key else ldflags_text)
            settings.add({"n": counts["setting"], "key": shown_key, "value": shown_value, "parsed": True, "offset": line_at, "line": line_no})
            if key in SELECTED and key not in facts["settings_selected"]:
                facts["settings_selected"][key] = shown_value
            last[0] = None
        else:
            if kind not in unknown and len(unknown) >= 8:
                unknown["(other kinds)"] = unknown.get("(other kinds)", 0) + 1
            else:
                unknown[kind] = unknown.get(kind, 0) + 1
    flush()
    facts["lines"] = line_no
    facts["dependencies_read"] = counts["dep"]
    facts["settings_read"] = counts["setting"]
    if unknown:
        total = sum(unknown.values())
        rep.problem("module block: %d line(s) have a kind the tool does not read (%s); they are counted, not interpreted" %
                    (total, ", ".join("%s x%d" % (text_of(k), n) for k, n in list(unknown.items())[:8])))
        facts["lines_not_understood"] = total
    return facts, ended and not stopped and not unknown


# --- one slice ---------------------------------------------------------------------------------------------------------------

def read_slice(ctx, mm, base, size, index, universal, slice_info):
    """One image (the file, or a slice of a universal binary) -> (a build, its report). The build always carries status and status_basis."""
    img = Image(mm, base, size)
    rep = Report()
    ctx.slice = index
    build = {"slice": slice_info, "container": None, "found": False}
    kind = sniff(img)
    if kind is None:
        build.update(status="unsupported", status_basis="the slice is not an ELF, PE or Mach-O image, the containers whose sections and segments this tool reads; nothing in it was looked at")
        return build, rep
    build["container"] = kind
    cont = None
    try:
        cont = {"elf": parse_elf, "pe": parse_pe, "macho": parse_macho}[kind](ctx, img, rep)
    except (Short, Bad) as exc:
        rep.problem("%s headers: %s: sections and segments are not used; the whole slice is scanned for the header" % (kind.upper(), exc))
    if cont is not None:
        build.update(bits=cont.bits, byte_order=cont.order)
        if cont.notes:
            build["container_notes"] = cont.notes
    at, where, covered, seen = locate(ctx, img, cont, rep)
    if seen["count"]:
        build["unaligned_copies"] = {"count": seen["count"], "first_offsets": [img.base + o for o in seen["offsets"]],
                                     "note": "the magic occurs at an offset that is not a multiple of 16 from the start of its area: not a header, not read"}
    deps = Pager("go_buildinfo-dependencies", [ctx.key, index, "dependencies"], ctx.limit)
    settings = Pager("go_buildinfo-settings", [ctx.key, index, "settings"], ctx.limit)
    if at is None:
        build["status"] = "complete" if covered and not rep.incomplete else "partial"
        build["status_basis"] = ("no Go build-information header was found in the places that can hold one (%s); a stripped or older binary may carry none, and absence is not 'not Go'" %
                                 ("every one was looked at" if covered else "not every one was looked at: see limits_hit"))
        return build, rep
    build["found"] = True
    info, version, module = read_strings(ctx, img, rep, cont, at)
    info["found_in"] = where
    build["header"] = info
    build["go_version"] = show(ctx, "go_version", version.decode("utf-8", "surrogateescape"), info["offset"], "names") if version is not None else None
    facts = {"present": None}
    block_ok = False
    if module is not None:
        facts, block_ok = parse_module(ctx, rep, module, deps, settings)
    elif version is not None or info["format"] == "inline":
        rep.problem("the module information could not be read")
    dep_done, set_done = deps.finish(), settings.finish()
    for label, done in (("dependencies", dep_done), ("build settings", set_done)):
        if done.get("not_written"):
            rep.problem("the whole %s table could not be written to a file: %s" % (label, done["not_written"]))
    build.update(main_package=facts.get("main_package"), main_module=facts.get("main_module"),
                 module_block={k: v for k, v in facts.items() if k in ("present", "offset", "bytes_declared", "bytes_read", "start_sentinel", "end_sentinel", "lines",
                                                                       "dependencies_read", "settings_read", "lines_not_understood")},
                 build_settings_selected=facts.get("settings_selected", {}),
                 dependencies={**dep_done, "rows": deps.page}, build_settings={**set_done, "rows": settings.page})
    whole = version is not None and module is not None and block_ok and not rep.incomplete and not dep_done.get("not_written") and not set_done.get("not_written")
    if whole and facts.get("present") is False:
        basis = ("the header was read and it declares no module information (a binary built outside module mode, or with it stripped): "
                 "the version was read and there is no module block to read")
    elif whole:
        basis = "the header, the version and the module block were read from the start sentinel to the end sentinel, every line"
    else:
        basis = "%d problem(s), %d limit(s): see `problems` and `limits_hit`" % (len(rep.problems), len(rep.limits)) if (rep.problems or rep.limits) else \
            "the module block was not read to its end sentinel"
    build["status"] = "complete" if whole else "partial"
    build["status_basis"] = basis
    return build, rep


# --- the call ----------------------------------------------------------------------------------------------------------------

def positive_int(args, key, default, maximum):
    value = args.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int) or value < 1 or value > maximum:
        fail("%s must be an integer from 1 to %d" % (key, maximum))
    return value


def open_regular(path):
    """The file as a descriptor, only if it is a regular file: opened without following a link and without blocking, then examined."""
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        fail("no such file", path=shown_name(path))
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            fail("the path is a symbolic link: refused (this tool reads evidence files, not what a link points to)", path=shown_name(path))
        fail("the file could not be opened: %s" % describe(exc), path=shown_name(path))
    mode = os.fstat(fd).st_mode
    if not stat.S_ISREG(mode):
        os.close(fd)
        kinds = ((stat.S_ISDIR, "a directory"), (stat.S_ISFIFO, "a named pipe"), (stat.S_ISSOCK, "a socket"), (stat.S_ISBLK, "a block device"),
                 (stat.S_ISCHR, "a character device"))
        fail("not a regular file (%s)" % next((n for t, n in kinds if t(mode)), "a special file"), path=shown_name(path))
    return fd


def read_args():
    try:
        text = sys.stdin.read(1 << 20)
        args = json.loads(text)
    except (ValueError, RecursionError) as exc:
        fail("arguments are not valid JSON", reason=type(exc).__name__)
    if not isinstance(args, dict):
        fail("arguments must be a JSON object")
    unknown = sorted(k for k in args if k not in ("path", "limit", "max_seconds", "max_scan_bytes", "write_values"))
    if unknown:
        fail("argument(s) this tool does not have: %s" % ", ".join(shown_name(str(k)) for k in unknown[:10]))
    return args


def main():
    install_signal_handlers(lambda signum: interrupted_answer(signum, tool=TOOL))
    args = read_args()
    path = args.get("path")
    if not isinstance(path, str) or not path or "\x00" in path:
        fail("path is required: a Go binary (ELF, PE or Mach-O)")
    try:
        path.encode(sys.getfilesystemencoding(), sys.getfilesystemencodeerrors())
    except UnicodeError:
        fail("path cannot be encoded as a file name")
    write_values = args.get("write_values", False)
    if not isinstance(write_values, bool):
        fail("write_values must be true or false")
    limit = positive_int(args, "limit", DEFAULT_LIMIT, MAX_LIMIT)
    seconds = positive_int(args, "max_seconds", DEFAULT_SECONDS, MAX_SECONDS)
    scan_budget = positive_int(args, "max_scan_bytes", DEFAULT_SCAN, MAX_SCAN)
    try:
        values = Values(write_values)
    except ValuesRefused as exc:
        fail(str(exc), write_values="refused", written=False)
    VALUES[0] = values
    fd = open_regular(path)
    try:
        size = os.fstat(fd).st_size
        shown_file = shown_name(path)
        if size == 0:
            values.close()
            fail("the file is empty", path=shown_file)
        try:
            mm = mmap.mmap(fd, 0, access=mmap.ACCESS_READ)
        except (OSError, ValueError) as exc:
            values.close()
            fail("the file could not be mapped for reading: %s" % describe(exc), path=shown_file)
    finally:
        os.close(fd)
    ctx = Ctx(seconds, limit, scan_budget, values if write_values else None, shown_file)
    file_rep = Report()
    builds, reports = [], []
    container = None
    try:
        head = bytes(mm[:4])
        if head in FAT_MAGIC:
            container = "universal"
            wide, e = FAT_MAGIC[head]
            count = struct.unpack_from(">I" if e == ">" else "<I", mm, 4)[0] if size >= 8 else 0
            entry = 32 if wide else 20
            if not 1 <= count <= 4096 or 8 + count * entry > size:
                fail("this is not a universal Mach-O file: the slice count %d does not fit the file" % count, status="unsupported", path=shown_file)
            if count > MAX_SLICES:
                file_rep.limit_hit("universal binary: %d slices are declared; the first %d are read and the rest are not" % (count, MAX_SLICES))
            for i in range(min(count, MAX_SLICES)):
                if file_rep.out_of_time(ctx, "the slice table"):
                    break
                if wide:
                    cpu, sub, off, length, _al, _res = struct.unpack_from(e + "iiQQII", mm, 8 + i * entry)
                else:
                    cpu, sub, off, length, _al = struct.unpack_from(e + "iiIII", mm, 8 + i * entry)
                info = {"index": i, "cputype": cpu, "offset": off, "size": length}
                if off >= size:
                    file_rep.problem("slice %d starts at offset %d, past the end of the file (%d bytes): not read" % (i, off, size))
                    builds.append(({"slice": info, "container": None, "found": False, "status": "failed", "status_basis": "the slice starts past the end of the file"}, Report()))
                    continue
                if off + length > size:
                    file_rep.problem("slice %d declares %d bytes at offset %d; the file holds %d of them" % (i, length, off, size - off))
                    length = size - off
                builds.append(read_slice(ctx, mm, off, length, i, True, info))
        else:
            builds.append(read_slice(ctx, mm, 0, size, 0, False, None))
            container = builds[0][0]["container"]
    finally:
        mm.close()
        values.close()
    problems, limits = list(file_rep.problems), list(file_rep.limits)
    dropped = file_rep.dropped
    statuses = []
    out_builds = []
    for build, rep in builds:
        statuses.append(build["status"])
        prefix = "slice %d: " % build["slice"]["index"] if build["slice"] else ""
        for p in rep.problems:
            if len(problems) < MAX_PROBLEMS:
                problems.append(prefix + p)
            else:
                dropped += 1
        dropped += rep.dropped
        limits.extend(prefix + t for t in rep.limits if prefix + t not in limits)
        out_builds.append(build)
    if all(s == "complete" for s in statuses) and not file_rep.incomplete:
        status = "complete"
    elif all(s == "unsupported" for s in statuses):
        status = "unsupported"
    elif all(s == "failed" for s in statuses):
        status = "failed"
    else:
        status = "partial"
    found = any(b["found"] for b in out_builds)
    if status == "complete":
        basis = ("a Go build-information header was found and read in full" if found and len(out_builds) == 1 else
                 "%d of %d slice(s) carry a header, each read in full; the others were searched in full and carry none" % (sum(1 for b in out_builds if b["found"]), len(out_builds)) if found else
                 "no header was found in any place that can hold one, and every such place was looked at: a stripped or older binary may carry none, and absence is not 'not Go'")
    elif status == "unsupported":
        basis = out_builds[0]["status_basis"]
    else:
        basis = "%d problem(s), %d limit(s) over %d slice(s): see `problems`, `limits_hit` and each build's status_basis" % (len(problems) + dropped, len(limits), len(out_builds))
    result = {"tool": TOOL, "parser": PARSER, "schema_version": SCHEMA_VERSION, "path": shown_file, "bytes": size, "container": container, "found": found,
              "builds": out_builds, "status": status, "status_basis": basis, "problems": problems, "limits_hit": limits, "withheld": COUNTS,
              "max_seconds": seconds, "secret_values": values.summary(), "note": NOTE}
    if dropped:
        result["problems_not_listed"] = dropped
    if COUNTS["names"] or COUNTS["urls"] or COUNTS["text"]:
        result["withheld_note"] = ("Text is withheld by its shape only: user-info, a secret-named -X value, and token-shaped text are withheld from this answer, "
                                   "each by its length. A secret of another shape (a plain password, a token family the rules do not name, a token split "
                                   "across two fields) is printed. The whole string is in the values file when write_values was asked for in a secret_output job.")
    emit(result)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:  # never a traceback and never a clean answer for a failure
        fail("unexpected failure: %s" % (describe(exc) if isinstance(exc, OSError) else type(exc).__name__))
