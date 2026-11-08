#!/usr/bin/env python3
"""Export protocol objects from a capture with tshark, index every one, and tie each to the frame it came from where the bytes allow.

What it does, and what it does not:

  * It asks the installed tshark which export object types it has (`--export-objects help`) and records the
    version. An explicitly requested type the build does not list is refused by name before anything is written;
    the default list is cut to the supported ones and the rest is named (protocols_skipped_unsupported). If the
    list cannot be read the passes still run, each failing loudly on its own, and the answer says
    exporters_discovered: false.
  * One deadline, counted from the start of the tool and covering the preflight and every pass (timeout_seconds,
    default 3000, at most 3300 so that this tool stops its passes before the manifest's 3600 seconds do), is kept. A
    pass that uses it up is killed with everything it started; the passes after it are not_attempted and are listed.
    tshark runs in the tool's own process group, not a session of its own: the harness ends a tool by killing its
    group, and an engine outside it would go on writing into the output directory (on Linux the kernel also kills it
    if the tool dies). SIGTERM, SIGINT and SIGHUP kill the pass, leave the receipt as "interrupted" and end the tool.
  * index.tsv and receipt.json exist from the first moment and are replaced (written under a temporary name and
    moved into place) after every pass, so an outer timeout leaves what was done. receipt.json says "running"
    until the last step; a receipt that still says running was cut off.
  * HTTP objects are tied to frames by CONTENT: a second tshark pass lists the HTTP responses with the hex of
    http.file_data (the fields it asks for are the ones `tshark -G fields` shows the installed build has; a field it
    lacks is named in association_pass.fields_missing, and the host of a response is taken from its request URI when
    http.host is empty), and an object whose SHA-256 equals exactly one listed body, and only one object has it, is
    matched_by_content (frame, stream, time, endpoints, host, request URI). A body that occurs in several frames,
    or an object that several bodies fit, is ambiguous and lists the frames (the whole list of a repeated body is
    in association-candidates.jsonl); an object that matches nothing, or whose protocol has no method here, is
    unmapped and says why. This is a statement about equal bytes, never about a session: whether the exported
    bytes and the field's bytes are the same after content decoding is a property of the tshark build, and an
    object that does not match is unmapped, not absent from the capture. If the listing pass fails, times out or
    holds a row that cannot be read, no association is claimed at all. The listing is read from a pipe as it
    comes and a body is hashed, never held, so no file with the bodies in it is ever written.
  * tshark is a single engine here: an index that agrees with the recipe's tshark listings is agreement of one
    program with itself, not an independent check.

SENSITIVE OUTPUT. Exported objects are evidence content and can hold credentials, cookies and tokens, and so
can their names and the request URIs. The tool follows the secret-safe output pattern (docs/packs.md,
"Secrets and sensitive output"; recovery_key_scan is the reference implementation):

  * The directory is private: mode 0700, every file 0600, including what tshark itself writes (the tool runs
    with umask 077 and sets the modes again after each pass). The answer says out_dir_contains_secret_values and
    names the advice: run the tool as a job with secret_output: true.
  * An object name shaped like a token, or carrying a query string (Wireshark names an HTTP object after the last
    part of its request target, so `login.php%3fuser=bob&pw=x` is a name), is moved to disk as withheld-NNNNNN<ext>
    (never onto a name that is there) and is never printed; the real name is written, at the moment of the rename,
    to withheld-names.jsonl in the output directory (0600) whether or not write_values was given, so that no name
    is lost. A request URI loses its user-info, its token-shaped path text and every query value. The digest of an
    object shorter than 128 bytes is not written (the digest of a short value can be reversed), though it is
    used in memory to match the object to its frame.
  * write_values: true (refused outside a job; created exclusively, mode 0600, before anything runs) writes the
    real names and URIs to $OUT/pcap-extract-values.jsonl and nowhere else. A second run in the same job is
    refused by name and leaves the first file as it was; with nothing withheld the file stays empty and the
    answer says written: 0. Nothing is ever written about a short object's digest, not even there.
  * Nothing is placed on a command line but the capture's path, the output place and the caller's own display
    filter.
"""
import json
import os
import signal
import sys

TOOL = {"name": "pcap_extract", "version": 14}
PARSER = "pcap_extract/5"


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


import array
import binascii
import datetime
import errno
import hashlib
import ipaddress
import re
import select
import shutil
import stat
import subprocess
import time
from pathlib import Path

try:
    import ctypes
except ImportError:  # pragma: no cover
    ctypes = None

DEFAULT_PROTOCOLS = ["http", "ftp-data", "smb", "smb2", "tftp", "imf"]
DEFAULT_DEADLINE = 3000
MAX_DEADLINE = 3300           # the manifest's outer limit is 3600: the tool stops its own passes first, so nothing is left running
PREFLIGHT_SECONDS = 30
SHORT_OBJECT = 128            # an object shorter than this has no digest written
MAX_OBJECTS = 200_000         # rows held for the index; files past it stay on disk, are counted, and the run is partial
MAX_FIELD = 4 << 20           # one non-body listing field longer than this makes its row unreadable
LISTED_FRAMES = 20            # frames named in one index cell; the whole list is in association-candidates.jsonl
CELL_LIMIT = 8192
# Export types that have a content-to-frame method here. Every other type is indexed and marked unmapped.
ASSOCIATED = ("http",)
# The listing asks the installed tshark which fields it has (`tshark -G fields`) and asks for those only: a field a build
# does not list makes the whole program refuse (`Some fields aren't valid`), so none is assumed. The body field and the
# frame number are the two the matching cannot do without; the rest are named as missing in the answer when they are.
ESSENTIAL_FIELDS = ["frame.number", "http.file_data"]
OPTIONAL_FIELDS = ["frame.time_epoch", "tcp.stream", "ip.src", "ipv6.src", "ip.dst", "ipv6.dst", "http.host"]
# The request URI of a response: tshark 4.6 generates http.request.full_uri on the response frame (and no longer lists
# http.response_for.uri); older builds list the other. The first one the build lists is used.
URI_FIELDS = ["http.request.full_uri", "http.response_for.uri"]
ALL_LISTING_CANDIDATES = ESSENTIAL_FIELDS + OPTIONAL_FIELDS + URI_FIELDS
COLUMNS = ["protocol", "name", "path", "bytes", "sha256", "sha256_withheld", "association", "association_reason",
           "frame", "frames", "stream", "time_epoch", "time_utc", "src", "dst", "host", "request_uri", "pass_status"]

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


def fail(message, **extra):
    if hasattr(signal, "pthread_sigmask"):
        signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT, signal.SIGHUP})     # one document: a stop that arrives while this is written waits, and the tool leaves with it
    STATE["last_word"] = None
    print(json.dumps({"error": scrub(message), "tool": TOOL, "status": "failed", "status_basis": "the tool stopped with an error (see error)", **extra}))
    raise SystemExit(1)


def resolve_output(out, what="output"):
    """Where `out` really lands, as a path under the run directory; a place outside it, the run directory itself,
    or anything under inputs/ is refused, and in a job so is anything outside $OUT, the one place a job writes.

    A string check is not enough: `work/../inputs/x`, an absolute path and a symlink that points out all name a
    place the tool must not write. Resolving first and comparing directories is what holds, and the read-only
    inputs are the one place extracted bytes must never appear: a later integrity check would report the
    evidence as modified.
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


REFUSED_NOT_SECRET = ("write_values is refused in a job that was not run as secret output: its files would be sealed as ordinary output. "
                      "The harness sets SECRET_OUTPUT=1 for a secret job's process and it is not set here. Run it as job_run(tool: \"pcap_extract\", args: {...}), "
                      "whose manifest makes every job of this tool secret output, or give a command job secret_output: true; if that is refused the "
                      "same way, this run's harness does not set the variable and the values mode is not available in it. Nothing was written.")


class SecretValuesRefused(Exception):
    def __init__(self, message, path=None):
        super().__init__(message)
        self.path = str(path) if path else None


class SecretValues:
    """Where a value goes when, and only when, the caller asked for it.

    The reference implementation of the secret-safe output pattern (recovery_key_scan), with one change: a row is
    written as JSON escapes, so that a name that is not UTF-8 cannot raise. Call `add` once per finding with its
    id, its locator and the value. With `enabled` false it writes nothing and `summary()` says so.
    """

    NAME = "pcap-extract-values.jsonl"

    def __init__(self, enabled):
        self.enabled = enabled
        self.written = 0
        self._fh = None
        self.job = os.environ.get("JOB_ID") or ""
        self.out = os.environ.get("OUT") or ""
        self.path = None
        self.shown = None
        if not enabled:
            return
        if not (self.job and self.out):
            raise SecretValuesRefused(
                "write_values is refused outside a job: a value written here would be an ordinary "
                "file, not a sealed secret output. Run this as job_run tool=pcap_extract with "
                "secret_output: true, and ask again there. Nothing was written."
            )
        if os.environ.get("SECRET_OUTPUT") != "1":
            raise SecretValuesRefused(REFUSED_NOT_SECRET)
        self.path = Path(self.out) / self.NAME
        self.shown = "store/jobs/%s/out/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", self.job), self.NAME)
        # Created now, before anything runs: a file or a link already at that name is refused by name at once
        # (O_EXCL does not follow a link, a dangling one included), instead of failing, or writing through it,
        # after the passes. With nothing withheld it stays an empty file, mode 0600, and the answer says written: 0.
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(str(self.path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileExistsError:
            raise SecretValuesRefused("the values file already exists", self.path)
        except OSError as exc:
            raise SecretValuesRefused("the values file could not be created (%s)" % describe(exc), self.path)
        self._fh = os.fdopen(fd, "w", encoding="utf-8")

    def add(self, finding_id, locator, value):
        if not self.enabled or self._fh is None:
            return
        self._fh.write(json.dumps({"finding_id": finding_id, **locator, "value": value}))
        self._fh.write("\n")
        self.written += 1

    def close(self):
        if self._fh is not None:
            self._fh.flush()
            os.fsync(self._fh.fileno())
            self._fh.close()
            self._fh = None

    def discard(self):
        """A run that stopped before it wrote a value gives the job its one values file back."""
        if self.enabled and self.written == 0 and self.path is not None:
            self.close()
            try:
                os.unlink(str(self.path))
            except OSError:
                pass

    def summary(self):
        return {
            "requested": self.enabled,
            "written": self.written,
            "values_file": self.shown if self.enabled else None,
            "contains_secret_values": self.written > 0,
            "format": ("JSON Lines, mode 0600: finding_id, protocol, path (as index.tsv names it), request_uri (the whole, "
                       "unredacted), value (the real object name)") if self.enabled else None,
        }


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


def parse_exporters(*texts):
    """The export object types a tshark build lists, in the order it lists them: the indented one-word lines of
    its `--export-objects help` text. Nothing parsed means the list was not read, which is not an empty list."""
    names = []
    for text in texts:
        for line in text.splitlines():
            m = re.fullmatch(r"\s+([A-Za-z0-9][A-Za-z0-9_.-]*)\s*", line)
            if m and m.group(1) not in names:
                names.append(m.group(1))
    return names


# --- the listing pass: HTTP responses and the hash of each body --------------------------------------------

class Listing:
    """Reads the tab-separated listing of HTTP responses from a pipe, one chunk at a time, and keeps for each body
    only what matching needs: the SHA-256 of the decoded hex of the last field, against the digests of the
    exported objects. A body is never held: a response of a gigabyte is hashed as it goes by."""

    def __init__(self, wanted, fields):
        self.wanted = wanted
        self.fields = list(fields)           # the columns asked for, the body field last
        self.lines = 0
        self.rows = 0
        self.bodies = 0
        self.unreadable = array.array("Q")   # line numbers of rows that could not be read (all of them: a file names them)
        self.header_ok = None
        self.found = {}                      # digest -> [count, first info, frame numbers]
        self._fields_needed = len(self.fields) - 1
        self._reset()

    def _reset(self):
        self._mode = "prefix"                # prefix: the fields before the body; body: the last field; skip: to the next line
        self._pre = b""
        self._fields = []
        self._parts = []                     # per body of this row: [hasher, length]
        self._carry = b""
        self._bad = False
        self._header = None

    def feed(self, chunk):
        self._feed(chunk)

    def finish(self):
        """The end of the listing: a last line with no line end is still a line."""
        if self._mode == "body":
            self._finish_line()
        elif self._mode == "prefix" and self._pre:
            self._short_line(self._pre)
            self._reset()

    @staticmethod
    def _nth_tab(buf, n):
        pos = -1
        for _ in range(n):
            pos = buf.find(b"\t", pos + 1)
            if pos < 0:
                return -1
        return pos

    def _feed(self, data):
        while data:
            if self._mode == "skip":
                nl = data.find(b"\n")
                if nl < 0:
                    return
                data = data[nl + 1:]
                self._reset()
            elif self._mode == "prefix":
                self._pre += data
                data = b""
                nl = self._pre.find(b"\n")
                tabs = self._nth_tab(self._pre, self._fields_needed)
                if nl >= 0 and (tabs < 0 or nl < tabs):
                    line, data = self._pre[:nl], self._pre[nl + 1:]
                    self._short_line(line)
                    self._reset()
                elif tabs < 0:
                    if len(self._pre) > MAX_FIELD:
                        self._bad_row()
                        self._reset()
                        self._mode = "skip"
                    return
                else:
                    head, data = self._pre[:tabs], self._pre[tabs + 1:]
                    self._fields = head.split(b"\t")
                    self._pre = b""
                    self._mode = "body"
                    self._parts = [[hashlib.sha256(), 0]]
                    self._header = b"" if self.header_ok is None else None
            else:
                nl = data.find(b"\n")
                seg, data = (data, b"") if nl < 0 else (data[:nl], data[nl + 1:])
                if self._header is not None:
                    self._header += seg
                else:
                    self._body(seg)
                if nl >= 0:
                    self._finish_line()

    def _short_line(self, line):
        """A line with fewer fields than were asked for: the header of another listing, a blank line, or a damaged row."""
        self.lines += 1
        if self.header_ok is None:
            self.header_ok = False
        elif line.strip():
            self.unreadable.append(self.lines)

    def _bad_row(self):
        self.lines += 1
        self.unreadable.append(self.lines)

    def _body(self, seg):
        pieces = seg.split(b",")
        for i, piece in enumerate(pieces):
            if i:
                if self._carry:
                    self._bad, self._carry = True, b""
                self._parts.append([hashlib.sha256(), 0])
            data = self._carry + piece.replace(b":", b"").replace(b"\r", b"")
            self._carry = data[-1:] if len(data) % 2 else b""
            data = data[:len(data) - len(data) % 2]
            if not data:
                continue
            try:
                raw = binascii.unhexlify(data)
            except (binascii.Error, ValueError):
                self._bad = True
                continue
            self._parts[-1][0].update(raw)
            self._parts[-1][1] += len(raw)

    def _finish_line(self):
        if self._header is not None:
            tail = self._header.decode("utf-8", "replace").rstrip("\r")
            self.lines += 1
            self.header_ok = [f.decode("utf-8", "replace") for f in self._fields] + [tail] == self.fields
            self._reset()
            return
        self.lines += 1
        if self._carry:
            self._bad = True
        if self._bad:
            self.unreadable.append(self.lines)
            self._reset()
            return
        self.rows += 1
        cells = dict(zip(self.fields, (f.decode("utf-8", "surrogateescape") for f in self._fields)))
        many = len(self._parts) > 1
        uri = "" if many else next((cells[f] for f in URI_FIELDS if cells.get(f)), "")
        host = "" if many else (cells.get("http.host") or host_of_uri(uri))
        info = {"frame": cells.get("frame.number", "").strip(), "time_epoch": cells.get("frame.time_epoch", ""),
                "stream": cells.get("tcp.stream", ""), "src": cells.get("ip.src") or cells.get("ipv6.src") or "",
                "dst": cells.get("ip.dst") or cells.get("ipv6.dst") or "", "host": host, "uri": uri,
                "several_responses_in_frame": many}
        for hasher, size in self._parts:
            if not size:
                continue
            self.bodies += 1
            digest = hasher.hexdigest()
            if digest not in self.wanted:
                continue
            entry = self.found.get(digest)
            if entry is None:
                entry = self.found[digest] = [0, info, array.array("Q")]
            entry[0] += 1
            if info["frame"].isdigit():
                entry[2].append(int(info["frame"]))
        self._reset()


def epoch_to_iso(text):
    """tshark's frame.time_epoch (seconds, a decimal fraction of up to nine digits) as ISO 8601 UTC, digits kept."""
    m = re.fullmatch(r"(-?\d{1,12})(?:\.(\d{1,9}))?", text.strip())
    if not m:
        return ""
    try:
        stamp = datetime.datetime.fromtimestamp(int(m.group(1)), tz=datetime.timezone.utc)
    except (OverflowError, OSError, ValueError):
        return ""
    return stamp.strftime("%Y-%m-%dT%H:%M:%S") + ("." + m.group(2) if m.group(2) else "") + "Z"


def host_of_uri(uri):
    """The authority of an absolute URI (`http://host:port/path`), without user-info; empty for anything else.
    tshark 4.6 leaves http.host empty on a response frame, and the request URI it generates there is absolute."""
    m = re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://([^/?#]*)", uri)
    return m.group(1).rsplit("@", 1)[-1] if m else ""


def shown_host(host):
    """A host or an address as printed: an IP address as it is, any other text through the block's own rule, so that a
    token in a sub-domain is withheld here as it is in every other tool of the pack."""
    if not host:
        return ""
    parts = host.split(",")
    for part in parts:
        try:
            ipaddress.ip_address(part.strip())
        except ValueError:
            return scrub(host)
    return host


def shown_number(text):
    """A number tshark printed (a frame, a stream, an epoch time) as it is; anything else through the block."""
    return text if re.fullmatch(r"-?\d{1,20}(?:\.\d{1,9})?", text.strip()) else scrub(text)


def shown_url(url):
    """A request URI as printed: user-info, token-shaped path text, query values and fragment withheld by the block, and
    the authority through the same host rule as the host column."""
    # Over TEXT_LIMIT the query and fragment are withheld whole, by their length (the block's own rule for a text over the limit): the block
    # splits a query pair by pair, so a megabyte of `&` there costs seconds a URL. What is kept is the scheme, host and path part.
    cut = min((i for i in (url.find("?"), url.find("#")) if i >= 0), default=len(url)) if len(url) > TEXT_LIMIT else len(url)
    if cut < len(url):
        return shown_url(url[:cut]) + url[cut] + _withheld("over-long query or fragment", len(url) - cut - 1, "urls")
    out = redact_url(url)
    m = re.match(r"^((?:[A-Za-z][A-Za-z0-9+.-]*:)?//)([^/?#]*)(.*)$", out, re.S)
    if not m:
        return out
    authority = m.group(2)
    prefix, _, host = authority.rpartition("@")
    return m.group(1) + (prefix + "@" if prefix else "") + shown_host(host) + m.group(3)


# --- the exported objects ---------------------------------------------------------------------------------------

def file_digest(path):
    h = hashlib.sha256()
    with open_regular(path, follow=False) as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def extension_of(name):
    ext = os.path.splitext(name)[1]
    return ext if re.fullmatch(r"\.[A-Za-z0-9]{1,8}", ext) else ""


def name_withheld(name):
    """A name to keep off the page: shaped like a token, or carrying a query string. Wireshark names an HTTP object
    after the last part of its request target and escapes only a few characters, so `login.php%3fuser=bob&pw=x` is a
    name that holds a query."""
    return token_shaped(name) or "=" in name or re.search(r"%3f", name, re.I) is not None


class Mapping:
    """withheld-names.jsonl: the real name behind every name moved aside, kept in the private output directory and
    written (and flushed) at the moment of the rename, so that nothing is lost whether or not write_values was given."""

    NAME = "withheld-names.jsonl"

    def __init__(self, out_dir):
        self.path = os.path.join(out_dir, self.NAME)
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        self.fh = os.fdopen(fd, "w", encoding="utf-8")
        self.count = 0

    def add(self, protocol, shown_path, real_path):
        self.count += 1
        self.fh.write(json.dumps({"finding_id": "N%06d" % self.count, "protocol": protocol, "path": shown_path, "real_path": real_path}) + "\n")
        self.fh.flush()
        os.fsync(self.fh.fileno())

    def close(self):
        if self.fh is not None:
            self.fh.close()
            self.fh = None


class LongCells:
    """A cell over CELL_LIMIT characters is cut in index.tsv and kept whole in index-long-cells.jsonl (named by id)."""

    NAME = "index-long-cells.jsonl"

    def __init__(self, out_dir):
        self.path = os.path.join(out_dir, self.NAME)
        self.ids = {}
        self.fh = None

    def cell(self, key, text):
        if len(text) <= CELL_LIMIT:
            return text
        ident = self.ids.get(key)
        if ident is None:
            if self.fh is None:
                fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
                self.fh = os.fdopen(fd, "w", encoding="utf-8")
            ident = self.ids[key] = "L%06d" % (len(self.ids) + 1)
            self.fh.write(json.dumps({"id": ident, "row": key[0], "column": key[1], "value": text}) + "\n")
            self.fh.flush()
        return text[:CELL_LIMIT] + " ...(%d characters not shown; the whole is %s in %s)" % (len(text) - CELL_LIMIT, ident, self.NAME)

    def close(self):
        if self.fh is not None:
            self.fh.close()
            self.fh = None


class Objects:
    """The rows of the index, and the work of keeping an exported tree private and free of names that are secrets."""

    def __init__(self, out_dir):
        self.out_dir = out_dir
        self.rows = []
        self.mapping = None
        self.long_cells = None
        self.seq = 0                  # withheld-NNNNNN names
        self.names_withheld = 0
        self.not_indexed = 0
        self.short_digests_withheld = 0
        self._blind = {}              # path of an entry with a withheld name -> (size, digest), read once for its sort key

    @staticmethod
    def private(top):
        for root, dirs, files in os.walk(top):
            for name in dirs + files:
                full = os.path.join(root, name)
                try:
                    if not os.path.islink(full):
                        os.chmod(full, 0o700 if os.path.isdir(full) else 0o600)
                except OSError:
                    pass

    def _blind_key(self, entry):
        """The sort key of an entry whose name is withheld: made of its content only (kind, size, SHA-256), never of its
        name. The order of the rows and the numbers in withheld-NNNNNN follow this key, so neither says where the real
        name falls among the visible ones (an order that followed the names would be a rank oracle on them)."""
        try:
            if entry.is_symlink():
                return (2, 0, "")
            if entry.is_dir(follow_symlinks=False):
                parts = []
                for root, _dirs, files in os.walk(entry.path):
                    for name in files:
                        full = os.path.join(root, name)
                        try:
                            if stat.S_ISREG(os.lstat(full).st_mode):
                                parts.append("%d:%s" % (os.path.getsize(full), file_digest(full)))
                            else:
                                parts.append("-")
                        except OSError:
                            parts.append("?")
                parts.sort()
                return (1, len(parts), hashlib.sha256("\n".join(parts).encode("ascii")).hexdigest())
            if not stat.S_ISREG(os.lstat(entry.path).st_mode):
                return (3, 0, "")
            size, digest = os.path.getsize(entry.path), file_digest(entry.path)
            self._blind[entry.path] = (size, digest)
            return (0, size, digest)
        except OSError:
            return (4, 0, "")

    def collect(self, protocol, status):
        """Index the files a pass left under <out_dir>/<protocol>: private modes first, names that are secrets
        moved aside, every file sized and hashed."""
        top = os.path.join(self.out_dir, protocol)
        self.private(top)
        stack = [(top, "", "")]        # directory on disk, its path as shown, its path as it really was
        while stack:
            directory, shown, real = stack.pop()
            try:
                with os.scandir(directory) as it:
                    entries = list(it)
            except OSError as exc:
                self.rows.append(self._row(protocol, "<directory not listed>", shown + "/", None, status, error=describe(exc)))
                continue
            # Names that are not withheld come first, by name; the others follow, by content (a tie is two entries whose
            # printed rows are identical, so which of them gets the lower number is told by the private names file only).
            plain = sorted((e for e in entries if not name_withheld(e.name)), key=lambda e: os.fsencode(e.name))
            secret = sorted((e for e in entries if name_withheld(e.name)), key=lambda e: (self._blind_key(e), os.fsencode(e.name)))
            subdirs = []
            for entry in plain + secret:
                name, kept = entry.name, entry.name
                is_dir = entry.is_dir(follow_symlinks=False)
                if name_withheld(name):
                    ext = "" if is_dir else extension_of(name)
                    while True:
                        # never onto a name that is there: a capture can name an object withheld-000001.bin on purpose
                        self.seq += 1
                        kept = "withheld-%06d%s" % (self.seq, ext)
                        if not os.path.lexists(os.path.join(directory, kept)):
                            break
                    self.names_withheld += 1
                    COUNTS["names"] += 1
                    os.rename(os.path.join(directory, name), os.path.join(directory, kept))
                    if entry.path in self._blind:
                        self._blind[os.path.join(directory, kept)] = self._blind.pop(entry.path)
                    label = "<name withheld: token-shaped or query-shaped, %d characters>" % len(name)
                    if self.mapping is not None:
                        self.mapping.add(protocol, "%s/%s" % (protocol, (shown + "/" if shown else "") + kept),
                                         "%s/%s" % (protocol, (real + "/" if real else "") + name))
                else:
                    label = name
                rel = (shown + "/" if shown else "") + kept
                real_rel = (real + "/" if real else "") + name
                full = os.path.join(directory, kept)
                if os.path.islink(full):
                    self.rows.append(self._row(protocol, label, rel, None, status, error="a symbolic link, not followed"))
                elif is_dir:
                    subdirs.append((full, rel, real_rel))
                elif len(self.rows) >= MAX_OBJECTS:
                    self.not_indexed += 1
                else:
                    self.rows.append(self._row(protocol, label, rel, full, status, real=real_rel, withheld=kept != name))
            stack.extend(reversed(subdirs))

    def _row(self, protocol, label, rel, full, status, error=None, real=None, withheld=False):
        row = {"protocol": protocol, "name": label, "path": "%s/%s" % (protocol, rel) if rel else protocol,
               "pass_status": status, "real_path": real, "name_withheld": withheld, "bytes": "", "sha": "",
               "sha256": "", "sha256_withheld": "", "request_uri": "", "request_uri_real": ""}
        if error:
            row["association_reason"] = error
        if full is None:
            return row
        try:
            if not stat.S_ISREG(os.lstat(full).st_mode):
                row["association_reason"] = "not a regular file (a named pipe, a device or a socket): not read"
                return row
            size, digest = self._blind.pop(full, None) or (os.path.getsize(full), file_digest(full))
        except OSError as exc:
            row["association_reason"] = "the object could not be read: " + describe(exc)
            return row
        row["bytes"] = size
        row["sha"] = digest
        if size < SHORT_OBJECT:
            self.short_digests_withheld += 1
            row["sha256_withheld"] = ("the object is shorter than %d bytes: the digest of a short value can be reversed, "
                                      "so none is written" % SHORT_OBJECT)
        else:
            row["sha256"] = digest
        return row


def frame_list(frames):
    shown = ",".join(str(f) for f in frames[:LISTED_FRAMES])
    return shown + (",+%d more" % (len(frames) - LISTED_FRAMES) if len(frames) > LISTED_FRAMES else "")


def write_index(path, rows, long_cells=None):
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\t".join(COLUMNS) + "\n")
        for number, row in enumerate(rows, 1):
            fh.write("\t".join(cell(long_cells.cell((number, c), str(row.get(c, ""))) if long_cells else str(row.get(c, ""))) for c in COLUMNS) + "\n")
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def write_json(path, data):
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(data, fh, indent=2)
        fh.write("\n")
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def associate(rows, listing, status, why, candidates_path, missing=()):
    """Set the association of every row. `listing` is None when the pass did not complete: then nothing is claimed.
    Returns the counts and whether the candidates file was written."""
    counts = {"matched_by_content": 0, "ambiguous": 0, "unmapped": 0, "not_attempted": 0, "failed": 0}
    by_digest = {}
    for row in rows:
        if row["protocol"] in ASSOCIATED and row.get("sha"):
            by_digest.setdefault(row["sha"], []).append(row)
    sets = {}
    for row in rows:
        if row["protocol"] not in ASSOCIATED:
            row["association"] = "unmapped"
            row["association_reason"] = "no content-to-frame association exists here for %s objects; no frame is claimed" % row["protocol"]
        elif not row.get("sha"):
            row["association"] = "unmapped"
            row["association_reason"] = row.get("association_reason") or "the object could not be read, so it was not compared with any response body"
        elif listing is None:
            row["association"] = status
            row["association_reason"] = why
        else:
            entry = listing.found.get(row["sha"])
            objects_with_it = len(by_digest.get(row["sha"], []))
            if entry is None:
                row["association"] = "unmapped"
                row["association_reason"] = "no listed HTTP response body has this object's SHA-256; that does not show the object was not in the capture"
            elif entry[0] == 1 and objects_with_it == 1:
                info = entry[1]
                row["association"] = "matched_by_content"
                row["association_reason"] = ("SHA-256 equal to exactly one listed response body, and to no other exported object"
                                             + ("; the frame holds several responses, so host and request URI are not given" if info["several_responses_in_frame"] else ""))
                if missing:
                    row["association_reason"] += "; this tshark build does not list: " + ", ".join(missing)
                row["frame"], row["stream"] = shown_number(info["frame"]), shown_number(info["stream"]) if info["stream"] else ""
                row["time_epoch"], row["time_utc"] = (shown_number(info["time_epoch"]) if info["time_epoch"] else ""), epoch_to_iso(info["time_epoch"])
                row["src"], row["dst"], row["host"] = shown_host(info["src"]), shown_host(info["dst"]), shown_host(info["host"])
                row["request_uri_real"] = info["uri"]
                row["request_uri"] = shown_url(info["uri"]) if info["uri"] else ""
            else:
                set_id = sets.get(row["sha"])
                if set_id is None:
                    set_id = sets[row["sha"]] = "S%06d" % (len(sets) + 1)
                row["association"] = "ambiguous"
                row["frames"] = frame_list(list(entry[2]))
                row["association_reason"] = ("%d listed responses carry this body and %d exported objects have it (candidate_set %s in "
                                             "association-candidates.jsonl); no single frame is claimed" % (entry[0], objects_with_it, set_id))
        counts[row["association"]] = counts.get(row["association"], 0) + 1
    if sets and listing is not None:
        fd = os.open(candidates_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            for digest, set_id in sets.items():
                fh.write(json.dumps({"candidate_set": set_id, "frames": list(listing.found[digest][2]),
                                     "objects": [r["path"] for r in by_digest[digest]]}) + "\n")
        return counts, True
    return counts, False


def discover_fields(binary, wanted, seconds):
    """Which of `wanted` the installed tshark lists as fields (`tshark -G fields`, read as a stream so that the deadline
    needs no second thread); (the names found, why the list could not be read or None)."""
    found, buffer, killed = set(), b"", False
    try:
        proc = spawn([binary, "-G", "fields"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    except OSError as exc:
        return found, "tshark -G fields could not be run (%s)" % describe(exc)
    ACTIVE.append(proc)
    stop_at = time.monotonic() + max(1.0, seconds)
    try:
        fd = proc.stdout.fileno()
        while True:
            left = stop_at - time.monotonic()
            if left <= 0:
                killed = True
                kill_tree(proc)
                break
            ready, _, _ = select.select([fd], [], [], min(1.0, left))
            if not ready:
                continue
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            buffer += chunk
            *lines, buffer = buffer.split(b"\n")
            for raw in lines:
                cells = raw.decode("utf-8", "replace").split("\t")
                if len(cells) > 2 and cells[0] == "F" and cells[2] in wanted:
                    found.add(cells[2])
    except OSError as exc:
        kill_tree(proc)
        return found, "tshark -G fields could not be read (%s)" % describe(exc)
    finally:
        try:
            proc.stdout.close()
        except OSError:
            pass
        code = proc.wait()
        ACTIVE.remove(proc)
    if killed:
        return found, "tshark -G fields did not finish in time"
    if code != 0:
        return found, "tshark -G fields exited %d" % code
    return found, None


def listing_fields(available, discovered):
    """The columns of the listing for this build: (fields in order, body field last; the fields left out, with the reason).
    With the list of fields unread nothing can be left out, and what the program does with an unknown one is told by its
    own exit code."""
    fields, missing = [], []
    for name in ["frame.number"] + OPTIONAL_FIELDS:
        if not discovered or name in available:
            fields.append(name)
        else:
            missing.append(name)
    uri = next((f for f in URI_FIELDS if f in available), URI_FIELDS[0] if not discovered else None)
    if uri:
        fields.append(uri)
    else:
        missing += URI_FIELDS
    fields.append("http.file_data")
    if discovered and "http.file_data" not in available:
        missing.append("http.file_data")
    if discovered and "frame.number" not in available:
        missing.append("frame.number")
    return fields, sorted(set(missing), key=missing.index)


def stream_listing(argv, stderr_path, seconds, listing):
    """Run the listing pass with its output on a pipe read as it comes; (exit code, killed at the deadline, read error).
    The pipe is read with select, so the deadline is kept without a second thread."""
    with open(stderr_path, "wb") as stderr:
        try:
            proc = spawn(argv, stdout=subprocess.PIPE, stderr=stderr)
        except OSError as exc:
            return None, False, describe(exc)
        ACTIVE.append(proc)
        stop_at = time.monotonic() + seconds
        killed, read_error = False, None
        try:
            fd = proc.stdout.fileno()
            while True:
                left = stop_at - time.monotonic()
                if left <= 0:
                    killed = True
                    kill_tree(proc)
                    break
                ready, _, _ = select.select([fd], [], [], min(1.0, left))
                if not ready:
                    continue
                chunk = os.read(fd, 1 << 20)
                if not chunk:
                    break
                listing.feed(chunk)
            if not killed:
                listing.finish()
        except OSError as exc:
            read_error = describe(exc)
            kill_tree(proc)
        finally:
            try:
                proc.stdout.close()
            except OSError:
                pass
            code = proc.wait()
            ACTIVE.remove(proc)
        return (None if killed else code), killed, read_error


def run_everything(binary, path, out_dir, protocols, display_filter, deadline, objects, runs, errors, state, index_path, receipt, log_dir):
    capture = os.path.abspath(path)
    exhausted = "the shared deadline was used up by an earlier pass"
    for protocol in protocols:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            runs.append({"protocol": protocol, "status": "not_attempted", "reason": exhausted})
            errors.append({"protocol": protocol, "error": "not_attempted", "reason": exhausted})
            receipt("running")
            continue
        destination = os.path.join(out_dir, protocol)
        os.makedirs(destination, mode=0o700, exist_ok=True)
        if os.path.dirname(os.path.realpath(destination)) != os.path.realpath(out_dir):
            runs.append({"protocol": protocol, "status": "failed", "reason": "the export directory is not directly under out_dir: refused"})
            errors.append({"protocol": protocol, "error": "the export directory is not directly under out_dir: refused"})
            receipt("running")
            continue
        argv = [binary, "-n", "-q", "-r", capture]
        if display_filter:
            argv += ["-Y", display_filter]
        argv += ["--export-objects", "%s,%s" % (protocol, destination)]
        stdout_path = os.path.join(log_dir, protocol + ".stdout")
        stderr_path = os.path.join(log_dir, protocol + ".stderr")
        began = time.monotonic()
        code, timed_out = run_to_files(argv, stdout_path, stderr_path, remaining)
        for p in (stdout_path, stderr_path):
            try:
                os.chmod(p, 0o600)
            except OSError:
                pass
        status = "timed_out" if timed_out else ("ok" if code == 0 else "failed")
        before = len(objects.rows)
        objects.collect(protocol, status)
        run = {"protocol": protocol, "status": status, "exit_code": code, "objects": len(objects.rows) - before,
               "seconds": round(time.monotonic() - began, 3), "stdout": stdout_path, "stderr": stderr_path}
        if timed_out:
            run["reason"] = ("the pass was still running when the shared deadline ended and was killed with everything it had started; "
                             "the objects it had written are partial")
            errors.append({"protocol": protocol, "error": "timeout", "after_seconds": state["deadline_seconds"],
                           "stdout": stdout_path, "stderr": stderr_path})
        elif code != 0:
            errors.append({"protocol": protocol, "exit_code": code, "stdout": stdout_path, "stderr": stderr_path})
        runs.append(run)
        for row in objects.rows:
            if "association" not in row:
                row["association"] = "not_attempted"
                row["association_reason"] = row.get("association_reason") or "the association pass has not run yet"
        write_index(index_path, objects.rows, objects.long_cells)
        receipt("running")

    candidates_path = os.path.join(out_dir, "association-candidates.jsonl")
    http_rows = [r for r in objects.rows if r["protocol"] in ASSOCIATED and r.get("sha")]
    listing, status, why = None, "not_attempted", "no HTTP objects were exported, so there was nothing to tie to a frame"
    pass_result = {"status": "not_needed", "reason": why}
    if http_rows:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            status, why = "not_attempted", "the association pass was not attempted: " + exhausted
            pass_result = {"status": "not_attempted", "reason": why}
            errors.append({"pass": "association", "error": "not_attempted", "reason": exhausted})
        else:
            available, field_problem = discover_fields(binary, set(ALL_LISTING_CANDIDATES), min(300.0, max(1.0, remaining)))
            discovered = field_problem is None
            fields, missing = listing_fields(available, discovered)
            pass_result = {"status": "ok", "fields_discovered": discovered, "fields_asked_for": fields, "fields_missing": missing}
            if field_problem:
                pass_result["fields_note"] = field_problem + ": the fields were asked for without being checked against the build"
            blocked = [f for f in ESSENTIAL_FIELDS if f in missing]
            if blocked:
                # A named reason, not a failed run: the objects stay indexed and none is tied to a frame.
                status = "not_attempted"
                why = ("this tshark build does not list the field%s %s, which the content matching cannot do without; no listing was made and no "
                       "frame is claimed for any object (the objects themselves are indexed)" % ("s" if len(blocked) > 1 else "", ", ".join(blocked)))
                pass_result.update(status="unavailable", reason=why)
                errors.append({"pass": "association", "error": "unavailable", "reason": why})
                listing = None
            else:
                listing = Listing({r["sha"] for r in http_rows}, fields)
                # The listing's own display filter is fixed. The caller's filter is applied to the export passes only: a
                # count of listed responses that followed it would tell the caller whether a filter over text this tool
                # withholds (a request URI) matched.
                argv = [binary, "-n", "-r", capture, "-Y", "http.response",
                        "-T", "fields", "-E", "header=y", "-E", "separator=/t", "-E", "occurrence=a", "-E", "aggregator=,"]
                for field in fields:
                    argv += ["-e", field]
                stderr_path = os.path.join(log_dir, "association.stderr")
                began = time.monotonic()
                code, timed_out, read_error = stream_listing(argv, stderr_path, remaining, listing)
                try:
                    os.chmod(stderr_path, 0o600)
                except OSError:
                    pass
                pass_result.update(exit_code=code, seconds=round(time.monotonic() - began, 3), stderr=stderr_path,
                                   response_rows=listing.rows, bodies_hashed=listing.bodies, rows_unreadable=len(listing.unreadable))
                if listing.unreadable:
                    unreadable_path = os.path.join(out_dir, "association-unreadable-lines.json")
                    write_json(unreadable_path, {"listing_lines": list(listing.unreadable)})
                    pass_result["unreadable_lines_file"] = os.path.basename(unreadable_path)
                problem = None
                if timed_out:
                    problem, pass_result["status"] = "the listing pass was killed at the shared deadline", "timed_out"
                elif read_error:
                    problem, pass_result["status"] = "the listing could not be read (%s)" % read_error, "failed"
                elif code != 0:
                    problem, pass_result["status"] = "the listing pass exited with code %s (its stderr is named)" % code, "failed"
                elif listing.header_ok is not True:
                    problem, pass_result["status"] = "the listing's header was not the fields asked for, so its columns cannot be trusted", "failed"
                elif listing.unreadable:
                    problem, pass_result["status"] = ("%d listing rows could not be read (a body that was not hex, or a row with missing fields)"
                                                      % len(listing.unreadable)), "incomplete"
                if problem:
                    listing, status = None, ("not_attempted" if pass_result["status"] == "timed_out" else "failed")
                    why = problem + ": no frame is claimed for any object, because a claim from a partial listing could be wrong"
                    pass_result["reason"] = why
                    errors.append({"pass": "association", "error": pass_result["status"], "reason": why, "stderr": stderr_path})
                elif missing:
                    pass_result["note"] = ("fields this build does not list were left out: %s; the columns they feed are empty (a response's host "
                                           "is taken from the request URI when http.host is empty)" % ", ".join(missing))
    counts, wrote = associate(objects.rows, listing, status, why, candidates_path, pass_result.get("fields_missing") or ())
    if objects.not_indexed:
        errors.append({"error": "object_cap", "reason": "%d more files are on disk under the protocol directories and are not in index.tsv: "
                                                        "the index holds at most %d objects" % (objects.not_indexed, MAX_OBJECTS)})
    state["association_pass"] = pass_result
    state["association"] = counts
    write_index(index_path, objects.rows, objects.long_cells)
    return wrote


def decryption_secrets(path, seconds=20.0):
    """How many Decryption Secrets Blocks (block type 0x0000000A) a pcapng file holds, from the block headers alone:
    (count or None when it could not be told, a sentence). tshark applies such a block to the packets it decrypts, so the
    objects it exports and the fields it lists can be decrypted content, not what was on the wire."""
    deadline = time.monotonic() + seconds
    count = blocks = 0
    try:
        with open_regular(path) as fh:
            head = fh.read(12)
            if len(head) < 12 or head[:4] != b"\x0a\x0d\x0d\x0a":
                return 0, "not a pcapng file: it holds no Decryption Secrets Block"
            order = "<" if head[8:12] == b"\x4d\x3c\x2b\x1a" else (">" if head[8:12] == b"\x1a\x2b\x3c\x4d" else None)
            if order is None:
                return None, "the pcapng byte-order mark was not read: Decryption Secrets Blocks were not counted"
            fh.seek(0)
            while True:
                header = fh.read(8)
                if len(header) < 8:
                    break
                kind = int.from_bytes(header[:4], "little" if order == "<" else "big")
                total = int.from_bytes(header[4:], "little" if order == "<" else "big")
                blocks += 1
                if kind == 0x0A:
                    count += 1
                if total < 12 or total % 4:
                    return count, "a block length was not valid after %d blocks: Decryption Secrets Blocks past that point were not counted" % blocks
                fh.seek(total - 8, 1)
                if blocks % 4096 == 0 and time.monotonic() > deadline:
                    return count, "the block scan stopped after %d blocks at its own time limit: later blocks were not counted" % blocks
    except OSError as exc:
        return None, "the capture's blocks could not be scanned (%s)" % describe(exc)
    if count:
        return count, ("the capture holds %d Decryption Secrets Block(s): tshark applies them, so exported objects and listed fields can be "
                       "decrypted content, not what was on the wire; the secrets themselves are never printed here" % count)
    return 0, "no Decryption Secrets Block was found in the pcapng blocks scanned"


def program_group_problems(what):
    """Sentences for `errors` from the shared process block's verdict, for an answer that reports `what` (files a program wrote). A process settle() ended means
    those files hold what it had written when it was ended; where the absence of one cannot be proven (not Linux, PR_SET_CHILD_SUBREAPER refused) they cannot be shown
    to be final. The answer is then partial, and a line under `errors` says why."""
    verdict = process_verdict()
    found = []
    if verdict["left_behind"]:
        found.append("a program left %d process(es) running after it ended (in the tool's process group, in a session of its own, or after a double fork); the shared process block "
                     "stopped, killed and reaped them before %s were indexed and hashed, so what they would still have written is missing from %s" % (verdict["left_behind"], what, what))
    for why in verdict["unproven"]:
        found.append("%s: %s cannot be shown to be final" % (why, what))
    return found


def basis_of(status, why=None):
    """The sentence `status` rests on. While a run is going the file says so; a finished run says what it found."""
    if status == "running":
        return "the receipt is written after every pass; a receipt that still says running was cut off"
    if status == "interrupted":
        return why or "the tool was stopped by a signal before it finished"
    if status == "failed":
        return why or "the tool stopped with an error (see why)"
    return why or ""


PROGRESS = {"stage": "reading the arguments", "out_dir": None}


def early_word(signum):
    """What a run stopped before its receipt exists says on stdout: partial, the stage it was in, and that no export pass had begun.
    The receipt (and the last word that writes it) takes over once the output directory is ready; until then the two tshark
    preflights and the checks run, and a signal in them must still end in the partial JSON the README promises."""
    print(json.dumps({"tool": TOOL, "parser": PARSER, "status": "partial", "ok": False, "receipt_status": None,
                      "status_basis": "the tool was stopped by signal %d while it was %s; no export pass had started, so no object was exported, and %s" %
                                      (signum, PROGRESS["stage"], "the output directory may hold the files the tool had begun to write there"
                                       if PROGRESS["stage"] == "preparing the output directory" else "the output directory was not written"),
                      "interrupted_by_signal": signum, "stage": PROGRESS["stage"], "out_dir": PROGRESS["out_dir"]}), flush=True)


def main():
    started = time.monotonic()
    STATE["last_word"] = early_word
    install_signal_handlers()
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    if not isinstance(args, dict):
        fail("arguments must be a JSON object")
    path, out_dir = args.get("path"), args.get("out_dir")
    if not isinstance(path, str) or not path or not os.path.isfile(path):
        fail("path must name a capture file", path=path if isinstance(path, str) else None)
    if not isinstance(out_dir, str) or not out_dir:
        fail("out_dir is required: an empty directory under work/ (in a job, under $OUT)")
    out_dir = resolve_output(out_dir, "out_dir")
    PROGRESS["out_dir"] = out_dir
    try:
        if os.path.exists(out_dir) and holds_files(out_dir):
            fail("out_dir already holds files", out_dir=out_dir)
    except OSError as exc:
        fail("out_dir cannot be listed (%s)" % describe(exc), out_dir=out_dir)
    explicit = args.get("protocols")
    if explicit is not None and (not isinstance(explicit, list) or not explicit or any(
            not isinstance(p, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,39}", p) for p in explicit)):
        fail("protocols must be a non-empty list of Wireshark export object type names (letters, digits, - and _; no dot or slash)")
    timeout = args.get("timeout_seconds", DEFAULT_DEADLINE)
    if not isinstance(timeout, int) or isinstance(timeout, bool) or not 1 <= timeout <= MAX_DEADLINE:
        fail("timeout_seconds must be an integer from 1 to %d: one deadline shared by every pass, kept under the 3600-second limit so "
             "that this tool stops its own passes and the limit never has to" % MAX_DEADLINE)
    display_filter = args.get("display_filter")
    if display_filter is not None and (not isinstance(display_filter, str) or not display_filter.strip()):
        fail("display_filter must be a non-empty string")
    write_values = args.get("write_values", False)
    if not isinstance(write_values, bool):
        fail("write_values must be true or false")
    if write_values:
        if not in_job():
            try:
                SecretValues(True)
            except SecretValuesRefused as exc:
                fail(str(exc), write_values="refused", written=False)
        elif os.environ.get("SECRET_OUTPUT") != "1":
            fail(REFUSED_NOT_SECRET, write_values="refused", written=False)
        elif os.path.lexists(os.path.join(os.environ["OUT"], SecretValues.NAME)):
            fail("the values file already exists", write_values="refused", written=False,
                 values_file=os.path.join(os.environ["OUT"], SecretValues.NAME))

    binary = shutil.which("tshark")
    if not binary:
        fail("tshark is not on PATH")
    os.umask(0o077)
    deadline = started + timeout
    PROGRESS["stage"] = "checking what tshark offers (--version, --export-objects help)"
    version_code, version_out, version_err, _ = preflight([binary, "--version"], min(PREFLIGHT_SECONDS, deadline - time.monotonic()))
    _, help_out, help_err, _ = preflight([binary, "--export-objects", "help"], min(PREFLIGHT_SECONDS, deadline - time.monotonic()))
    version_line = ""
    if version_code == 0:
        version_line = (version_out.decode("utf-8", "replace").splitlines() or [""])[0].strip()
    supported = parse_exporters(help_out.decode("utf-8", "replace"), help_err.decode("utf-8", "replace"))
    discovered = bool(supported)

    skipped = []
    if explicit is None:
        protocols = list(DEFAULT_PROTOCOLS)
        if discovered:
            skipped = [p for p in protocols if p not in supported]
            protocols = [p for p in protocols if p in supported]
            if not protocols:
                fail("this tshark build lists none of the default export object types; nothing was written", exporters_supported=supported)
    else:
        protocols = list(dict.fromkeys(explicit))
        if len({p.lower() for p in protocols}) != len(protocols):
            fail("protocols names one export object type twice (a case-insensitive file system would put both in one directory)")
        unknown = [p for p in protocols if discovered and p not in supported]
        if unknown:
            fail("%s %s of this tshark build; nothing was written" % (", ".join(unknown), "is not an export object type" if len(unknown) == 1 else "are not export object types"),
                 exporters_supported=supported, tshark_version=version_line or None)

    # Everything that can refuse has refused. From here on the tool writes, and the values file comes first.
    PROGRESS["stage"] = "preparing the output directory"
    try:
        values = SecretValues(write_values)
    except SecretValuesRefused as exc:
        fail(str(exc), write_values="refused", written=False, values_file=exc.path)
    objects = Objects(out_dir)
    index_path = os.path.join(out_dir, "index.tsv")
    receipt_path = os.path.join(out_dir, "receipt.json")
    log_dir = os.path.join(out_dir, "_logs")
    runs, errors = [], []
    state = {
        "tool": TOOL, "parser": PARSER, "status": "running",
        "path": path, "out_dir": out_dir, "index_tsv": index_path, "receipt": receipt_path,
        "tshark_version": version_line or None,
        "display_filter_given": display_filter is not None,
        "exporters_supported": supported, "exporters_discovered": discovered,
        "protocols_requested": protocols, "protocols_skipped_unsupported": skipped,
        "deadline_seconds": timeout, "runs": runs, "errors": errors,
        "withheld_names_file": Mapping.NAME,
    }

    def receipt(status, why=None, basis=None):
        state["status"] = status
        state["status_basis"] = basis or basis_of(status, why)
        state["elapsed_seconds"] = round(time.monotonic() - started, 3)
        state["objects"] = len(objects.rows)
        if why:
            state["why"] = scrub(why)
        write_json(receipt_path, state)

    def write_values_rows():
        """One row per object that has a name or a URI withheld, with the real ones. Written once, at the end, or
        by the last word if the run is stopped."""
        finding = 0
        for row in objects.rows:
            if row.get("name_withheld") or row.get("request_uri_real") != row.get("request_uri"):
                finding += 1
                values.add("O%06d" % finding, {"protocol": row["protocol"], "path": row["path"], "request_uri": row.get("request_uri_real", "")},
                           row.get("real_path") or "")

    def last_word(signum):
        write_values_rows()
        values.close()
        if objects.mapping is not None:
            objects.mapping.close()
        receipt("interrupted", "the tool was stopped by signal %d before it finished" % signum)
        # The same word on stdout, in the vocabulary of every answer: what is on disk is partial, and the receipt says so.
        print(json.dumps({**state, "status": "partial", "receipt_status": "interrupted", "ok": False, "interrupted_by_signal": signum}), flush=True)

    try:
        os.makedirs(log_dir, mode=0o700, exist_ok=True)
        os.chmod(out_dir, 0o700)
        os.chmod(log_dir, 0o700)
        for name, data in (("version.stdout", version_out), ("version.stderr", version_err),
                           ("export-help.stdout", help_out), ("export-help.stderr", help_err)):
            fd = os.open(os.path.join(log_dir, name), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
        objects.mapping = Mapping(out_dir)
        objects.long_cells = LongCells(out_dir)
        write_index(index_path, [])
        receipt("running")
    except OSError as exc:
        values.discard()
        fail("the output directory could not be created or written (%s)" % describe(exc), out_dir=out_dir)
    STATE["last_word"] = last_word

    try:
        wrote_candidates = run_everything(binary, path, out_dir, protocols, display_filter, deadline, objects, runs, errors,
                                          state, index_path, receipt, log_dir)
    except SystemExit:
        values.close()
        raise
    except BaseException as exc:  # noqa: BLE001 - leave a last word, then fail loudly
        try:
            write_values_rows()
            values.close()
            objects.mapping.close()
            receipt("failed", "unexpected failure: %s" % describe(exc))
        except Exception:  # noqa: BLE001
            pass
        fail("unexpected failure: %s" % describe(exc), out_dir=out_dir)
    try:
        write_values_rows()
    finally:
        values.close()
        objects.mapping.close()
        objects.long_cells.close()

    group_problems = program_group_problems("the exported objects, the index and the logs")     # a process tshark left behind (ended before the objects were indexed and hashed), or a host that cannot show there was none
    for line in group_problems:
        errors.append({"step": "programs", "error": "a process was left behind or its absence cannot be proven", "reason": line})
    ok = not errors
    secrets_blocks, secrets_note = decryption_secrets(path, max(1.0, min(20.0, deadline - time.monotonic())))
    state.update({
        "ok": ok,
        "program_group": process_verdict(),
        "decryption_secrets_blocks": secrets_blocks,
        "decryption_secrets_note": secrets_note,
        "bytes": sum(r["bytes"] for r in objects.rows if isinstance(r.get("bytes"), int)),
        "objects_not_indexed": objects.not_indexed,
        "association_candidates": "association-candidates.jsonl" if wrote_candidates else None,
        "names_withheld": objects.names_withheld,
        "short_digests_withheld": objects.short_digests_withheld,
        "withheld": dict(COUNTS),
        "secret_values": values.summary(),
        "out_dir_contains_secret_values": bool(objects.rows) or values.written > 0,
        "out_dir_note": ("The output directory holds exported protocol objects, which are evidence content and can carry credentials, "
                         "cookies and tokens, and tshark's own logs. It is private (mode 0700, files 0600). Run this tool as a job with "
                         "secret_output: true so the job output is sealed. A name shaped like a token or carrying a query string is withheld "
                         "as withheld-NNNNNN (the real name is in withheld-names.jsonl in this directory, mode 0600, always), a request URI "
                         "loses its user-info, token-shaped path text and query values, and the digest of an object under 128 bytes is not "
                         "written; write_values: true (jobs only) puts the real names and the whole URIs in one 0600 file under $OUT."),
        "note": ("No object content is returned here. index.tsv names every exported object with its size, SHA-256 (not for an object under "
                 "128 bytes) and, for HTTP objects whose bytes equal exactly one listed response body, its frame, stream, time and endpoints. "
                 "association says how far a frame is claimed: matched_by_content (equal bytes, one frame), ambiguous (the frames are "
                 "listed) or unmapped (and why: the exported bytes can differ from the field's bytes after content decoding, a partial body "
                 "or a response whose body tshark does not print as http.file_data). A frame is where tshark attributes the response, which for a reassembled "
                 "response is where reassembly completed, not necessarily the first packet. "
                 "Preserve the capture's hash and this receipt with any object used in a report. Whether -Y limits what tshark exports (it is applied to the export passes only, never to the listing, and is not echoed here), "
                 "whether http.file_data holds the same bytes as the exported object after content decoding, and whether a given exporter "
                 "writes every object are properties of the tshark build named here that this tool does not establish: check an object "
                 "you rely on against the capture. Complete stdout and stderr of every pass are in _logs/."),
    })
    done = "complete" if ok else "partial"
    receipt(done, basis=("every pass ran and exited 0, every exported file is indexed, and the association pass ran or was not needed" if ok else
                         "%d pass(es) or step(s) did not finish or did not succeed (errors names each); what was exported is indexed" % len(errors) +
                         ("; a process tshark left behind was ended, or none can be ruled out, so the exported files are not shown to be final" if group_problems else "")))
    process_apply(state)              # program_group (the same verdict the receipt holds); a complete answer cannot have got here with a leftover
    print(json.dumps(state, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except BaseException as exc:  # noqa: BLE001 - never a traceback, never a clean answer for a failure
        fail("unexpected failure: %s" % describe(exc))
