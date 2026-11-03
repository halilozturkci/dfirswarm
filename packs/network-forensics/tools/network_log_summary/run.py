#!/usr/bin/env python3
"""Normalise web, proxy and firewall logs into one table, and account for every line without printing a secret.

The grammars implemented, and no others:

    web       Apache or nginx access log, common or combined format ([day/Mon/year:time zone offset] ... "request")
    squid     Squid's native access.log (epoch seconds, elapsed, client, code/status, bytes, method, URL, user,
              hierarchy/peer, type)
    firewall  a line of upper-case KEY=VALUE pairs (SRC=, DST=, PROTO=, SPT=, DPT= ...), such as netfilter's log

A line that fits none of them is unparsed, and says so; a vendor format that is none of these is not parsed.

What the table holds. Every source line is in normalized.tsv or unparsed.tsv, and each row carries its physical line
number and the byte offset and length of the line in the stream that was read (the decompressed stream, for a gzip
file), so a row can be found in the evidence. The file is read as bytes: a line that is not valid UTF-8 is decoded
with substitution and counted (decoding_substituted), a CRLF is counted, a final line with no line end is said, and
a line longer than max_line_bytes is located and not read.

Time has three columns and no more meaning than each carries: timestamp_raw is the text as written (for a
firewall line, the whole prefix before the first KEY=VALUE, which holds the host and often the action as well);
timestamp_utc is filled only where the line itself gives enough to derive it (a web line has an offset, a Squid
line is epoch seconds, a firewall line may begin with an ISO 8601 time that has a zone) and is empty for a syslog
stamp, which has no year and no zone; timezone_source says which. Nothing is assumed to be UTC.

Nothing is cut and nothing is unbounded: gzip expansion is capped (max_expanded_bytes) and a cap that ends the read
is reported with the offset it ended at (complete: false, ok: false); a corrupt gzip stream is a structured error
that keeps the rows written before it and names the last good offset; aggregates hold at most max_distinct_values
distinct values per category, and the occurrences past that are counted (distinct_cap_reached).

SENSITIVE OUTPUT. A request target can carry credentials (user-info, tokens in the path or the query), and an
unparsed line can be anything. The target in the table is REDACTED: user-info, token-shaped path text and every
query value are withheld (the parameter names stay). The raw text of an unparsed line is not in unparsed.tsv, and no
raw line is in the answer. write_values: true (refused outside a job; created exclusively, mode 0600, before
anything is read) writes the unparsed lines' text and each redacted target's original to
$OUT/network-log-values.jsonl and nowhere else; a second run in the same job is refused by name. The directory is
private (mode 0700, files 0600): run the tool as a job with secret_output: true.
"""
import json
import os
import signal
import sys

TOOL = {"name": "network_log_summary", "version": 10}
PARSER = "network_log_summary/5"


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
import collections
import datetime
import errno
import gzip
import ipaddress
import re
import time
import zlib
from pathlib import Path

COLUMNS = ["line", "byte_offset", "byte_length", "format", "parse_status", "timestamp_raw", "timestamp_utc", "timezone_source",
           "src", "dst", "src_port", "dst_port", "protocol", "method", "target", "referer", "status", "bytes", "action", "user",
           "user_agent", "elapsed_ms", "hierarchy", "mime", "in_if", "out_if", "nat_src", "nat_dst", "tcp_flags", "unparsed_tail", "decoding"]
UNPARSED_COLUMNS = ["line", "byte_offset", "byte_length", "parse_status", "reason", "decoding"]
DEFAULT_MAX_LINE = 1 << 20
CLOCK_BYTES = 1 << 16  # the clock is also read after this many bytes of lines
DEFAULT_MAX_EXPANDED = 4 << 30
DEFAULT_MAX_DISTINCT = 200_000
DEFAULT_SECONDS = 540          # the tool's own clock; the manifest's limit is 600, so this tool stops and answers first
MAX_SECONDS = 570
MAX_KEY = 512                  # an aggregate key is cut here (counted); the table row has the whole value
# A quoted field: Apache writes a quote inside it as \" and a backslash as \\, so a quote is the end of the field only
# when no backslash escapes it. A pattern that stopped at the first quote cut the field there and dropped the rest.
QUOTED = r'(?:[^"\\]|\\.)*'
WEB = re.compile(
    r'^(?P<src>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<time>[^]]+)\]\s+'
    r'"(?P<request>' + QUOTED + r')"\s+(?P<status>\S+)\s+(?P<bytes>\S+)'
    r'(?:\s+"(?P<ref>' + QUOTED + r')"\s+"(?P<ua>' + QUOTED + r')")?(?P<tail>.*)$')
KV = re.compile(r'\b([A-Z][A-Z0-9_]*)=("(?:[^"\\]|\\.)*"|\S*)')
WEB_TIME = re.compile(r"^(\d{1,2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-])(\d{2})(\d{2})$")
ISO_PREFIX = re.compile(r"^\s*(?:<\d{1,3}>\d\s+)?(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:?\d{2})(?=\s|$)")
MONTHS = {m: i for i, m in enumerate(("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"), 1)}

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
    # `nc -p 80` and `mysql -p` alone, which asks for the password, name a port or nothing)
    ("a password given to a MySQL client", re.compile(
        r"""(?i:(?<![\w.-])(?:mysql|mysqldump|mysqladmin|mysqlcheck|mysqlimport|mysqlshow|mariadb|mariadb-dump|mariadb-admin)(?:\.exe)?(?=\s))[^\n]{0,512}?(?<=\s)-p(?=\S)(?:"([^"\n]{1,256})"|'([^'\n]{1,256})'|([^\s"']{1,256}))"""), -3),
    # `curl -u user:password`: the part after the colon, and only when there is one (`curl -u user` asks for it)
    ("a password given to curl", re.compile(
        r"""(?i:(?<![\w.-])curl(?:\.exe)?(?=\s))[^\n]{0,512}?(?<=\s)(?:-u|-U|--user|--proxy-user)(?:\s+|=)(?:"[^":\n]*:([^"\n]{1,256})"|'[^':\n]*:([^'\n]{1,256})'|[^\s:"']*:([^\s"']{1,256}))"""), -3),
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
                if not (_CRED_REDACTED.match(value) or value.lower() in _CRED_NOT_A_VALUE or value.startswith(("${", "{{"))):
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
                if g and (_CRED_REDACTED.match(value) or value.lower() in _CRED_NOT_A_VALUE or value.startswith(("${", "{{"))):
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
    print(json.dumps({"error": scrub(message), "tool": TOOL, "status": "failed", "status_basis": "the tool stopped with an error (see error)", **extra}))
    raise SystemExit(1)


def resolve_output(out, what="output"):
    """Where `out` really lands, as a path under the run directory; a place outside it, the run directory itself,
    or anything under inputs/ is refused, and in a job so is anything outside $OUT, the one place a job writes.

    A string check is not enough: `work/../inputs/x`, an absolute path and a symlink that points out all name a
    place the tool must not write. Resolving first and comparing directories is what holds, and the read-only
    inputs are the one place the tables must never appear: a later integrity check would report the evidence as
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


REFUSED_NOT_SECRET = ("write_values is refused in a job that was not run as secret output: its files would be sealed as ordinary output. "
                      "The harness sets SECRET_OUTPUT=1 for a secret job's process and it is not set here. Run it as job_run(tool: \"network_log_summary\", args: {...}), "
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

    NAME = "network-log-values.jsonl"

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
                "file, not a sealed secret output. Run this as job_run tool=network_log_summary with "
                "secret_output: true, and ask again there. Nothing was written."
            )
        if os.environ.get("SECRET_OUTPUT") != "1":
            raise SecretValuesRefused(REFUSED_NOT_SECRET)
        self.path = Path(self.out) / self.NAME
        self.shown = "store/jobs/%s/out/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", self.job), self.NAME)
        # Created now, before anything is read: a file or a link already at that name is refused by name at once
        # (O_EXCL does not follow a link, a dangling one included), instead of failing, or writing through it,
        # after the read. With nothing withheld it stays an empty file, mode 0600, and the answer says written: 0.
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            before = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT, signal.SIGHUP}) if hasattr(signal, "pthread_sigmask") else None
            try:
                # made and registered with the stop signals held: a stop between the two would leave an empty values file that nothing removes
                fd = os.open(str(self.path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
                self._fh = os.fdopen(fd, "w", encoding="utf-8")
                STAGE["values"] = self
            finally:
                if before is not None:
                    signal.pthread_sigmask(signal.SIG_SETMASK, before)
        except FileExistsError:
            raise SecretValuesRefused("the values file already exists", self.path)
        except OSError as exc:
            raise SecretValuesRefused("the values file could not be created (%s)" % describe(exc), self.path)

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
            "format": ("JSON Lines, mode 0600: finding_id, line, byte_offset, byte_length, status, target and referer (the originals, for a redacted "
                       "one), value (the whole source line, as JSON escapes)") if self.enabled else None,
        }


def epoch_to_iso(text):
    m = re.fullmatch(r"(\d{1,12})(?:\.(\d{1,9}))?", text.strip())
    if not m:
        return ""
    try:
        stamp = datetime.datetime.fromtimestamp(int(m.group(1)), tz=datetime.timezone.utc)
    except (OverflowError, OSError, ValueError):
        return ""
    return stamp.strftime("%Y-%m-%dT%H:%M:%S") + ("." + m.group(2) if m.group(2) else "") + "Z"


def web_time(text):
    """A common-log time such as 14/Nov/2023:22:13:20 +0000 as ISO 8601 UTC; empty when it does not parse."""
    m = WEB_TIME.match(text.strip())
    if not m or m.group(2).lower() not in MONTHS:
        return ""
    day, mon, year, hh, mm, ss, sign, oh, om = m.groups()
    try:
        offset = datetime.timedelta(hours=int(oh), minutes=int(om)) * (1 if sign == "+" else -1)
        local = datetime.datetime(int(year), MONTHS[mon.lower()], int(day), int(hh), int(mm), int(ss), tzinfo=datetime.timezone(offset))
        return local.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, OverflowError):
        return ""


def iso_to_utc(m):
    """An ISO 8601 time with a zone, matched by ISO_PREFIX, as UTC with its fraction digits kept; empty when it does not parse.
    Done by hand: the standard library's fromisoformat accepts different forms in different Python versions."""
    year, mon, day, hh, mm, ss, frac, zone = m.groups()
    try:
        sign = -1 if zone.startswith("-") else 1
        digits = zone.lstrip("Z+-").replace(":", "")
        offset = datetime.timedelta(hours=int(digits[:2] or 0), minutes=int(digits[2:] or 0)) * sign
        local = datetime.datetime(int(year), int(mon), int(day), int(hh), int(mm), int(ss), tzinfo=datetime.timezone(offset))
        return local.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S") + ("." + frac if frac else "") + "Z"
    except (ValueError, OverflowError):
        return ""


def unescape(text):
    """A quoted field as the writer meant it: \\" is a quote and \\\\ a backslash. Other backslash sequences (\\xNN, which
    nginx writes for a quote and Apache for a control byte) are left as written."""
    return re.sub(r'\\(["\\])', r"\1", text)


def web(line):
    m = WEB.match(line)
    if not m:
        return None
    request = unescape(m.group("request")).split()
    method = request[0] if request else ""
    target = request[1] if len(request) > 1 else ""
    derived = web_time(m.group("time"))
    if derived:
        source = "the offset written in the line"
    elif re.search(r" [+-]\d{4}$", m.group("time").strip()):
        source = "an offset is written but the date did not parse"
    else:
        source = "no zone offset is written in the line"
    ref = unescape(m.group("ref")) if m.group("ref") is not None else None
    return {"format": "web", "timestamp_raw": m.group("time"), "timestamp_utc": derived, "timezone_source": source,
            "src": m.group("src"), "method": method, "target": target, "referer": "" if ref in (None, "-") else ref, "status": m.group("status"),
            "bytes": "" if m.group("bytes") == "-" else m.group("bytes"),
            "user": "" if m.group("user") == "-" else m.group("user"),
            "user_agent": unescape(m.group("ua")) if m.group("ua") is not None else "",
            # Text after the last field the grammar names (a request time, a vhost, an upstream address ...): kept, not dropped.
            "unparsed_tail": m.group("tail").strip()}


def squid(line):
    parts = line.split()
    if len(parts) < 9 or not re.fullmatch(r"\d+(?:\.\d+)?", parts[0]):
        return None
    if "/" not in parts[3] or not re.fullmatch(r"\d+", parts[4]):
        return None
    derived = epoch_to_iso(parts[0])
    return {"format": "squid", "timestamp_raw": parts[0], "timestamp_utc": derived,
            "timezone_source": "epoch seconds, which are UTC by definition" if derived else "epoch seconds out of range",
            "src": parts[2], "method": parts[5], "target": parts[6], "status": parts[3].split("/", 1)[1], "bytes": parts[4],
            "action": parts[3].split("/", 1)[0], "elapsed_ms": parts[1],
            "user": "" if parts[7] == "-" else parts[7], "hierarchy": parts[8], "mime": parts[9] if len(parts) > 9 else "",
            "unparsed_tail": " ".join(parts[10:])}


def firewall(line):
    pairs = {k: (unescape(v[1:-1]) if len(v) >= 2 and v[0] == v[-1] == '"' else v) for k, v in KV.findall(line)}
    if not pairs or not ({"SRC", "DST", "PROTO"} & set(pairs)):
        return None
    action = pairs.get("ACTION", "")
    if not action:
        for candidate in ("DROP", "REJECT", "ACCEPT", "ALLOW", "DENY", "BLOCK"):
            if re.search(r"(?:^|\s)%s(?:\s|$)" % candidate, line, re.I):
                action = candidate.upper()
                break
    first_kv = min((m.start() for m in KV.finditer(line)), default=0)
    flags = [flag for flag in ("SYN", "ACK", "FIN", "RST", "PSH", "URG", "ECE", "CWR") if re.search(r"(?:^|\s)%s(?:\s|$)" % flag, line, re.I)]
    prefix = line[:first_kv].strip()
    derived, source = "", "none in the line: a syslog stamp has no year and no zone"
    if not prefix:
        source = "no timestamp in the line"
    m = ISO_PREFIX.match(prefix)
    if m:
        derived = iso_to_utc(m)
        source = "the zone written in the line" if derived else "a zone is written but the time did not parse"

    def first(*names):
        return next((pairs[name] for name in names if pairs.get(name)), "")
    return {"format": "firewall", "timestamp_raw": prefix, "timestamp_utc": derived, "timezone_source": source,
            "src": pairs.get("SRC", ""), "dst": pairs.get("DST", ""),
            "src_port": pairs.get("SPT", pairs.get("SRC_PORT", "")), "dst_port": pairs.get("DPT", pairs.get("DST_PORT", "")),
            "protocol": pairs.get("PROTO", ""), "bytes": pairs.get("LEN", ""),
            "action": action, "in_if": pairs.get("IN", ""), "out_if": pairs.get("OUT", ""),
            "nat_src": first("NATSRC", "NAT_SRC", "ORIGSRC", "ORIG_SRC", "TRANS_SRC"),
            "nat_dst": first("NATDST", "NAT_DST", "ORIGDST", "ORIG_DST", "TRANS_DST"), "tcp_flags": ",".join(flags)}


# One rule per column, and no column without one. Nothing a log line wrote is printed as it is unless its TYPE says it cannot
# hold a secret: an address (an IP address and nothing else), a number (digits), or text the tool derived itself. Every other
# string goes through the block of the pack, by column. A column the grammar fills with free text (a host name in the address
# column, a method that is not a method) is text.
ADDRESS = ("src", "dst", "nat_src", "nat_dst")
NUMBER = ("src_port", "dst_port", "elapsed_ms", "bytes", "status")
TEXT = ("timestamp_raw", "method", "protocol", "action", "user", "user_agent", "hierarchy", "mime", "in_if", "out_if", "unparsed_tail")
URL = ("target", "referer")
DERIVED = ("line", "byte_offset", "byte_length", "format", "parse_status", "timestamp_utc", "timezone_source", "tcp_flags", "decoding")


def shown(column, value):
    """The value of one column as it may be printed. The rule is the column's, not the line's."""
    if not value:
        return value
    if column in NUMBER:
        return value if re.fullmatch(r"-?\d{1,12}", value) else scrub(value)
    if column in ADDRESS:
        return value if all(shown_host(part.strip()) == part.strip() for part in value.split(",")) else scrub(value)
    if column in URL:
        return redact_target(value)
    if column in TEXT:
        return scrub(value)
    return value


def shown_host(host):
    """A host as printed: an IP address (with a port, or in brackets) as it is, any other name through the block."""
    bare = host
    if bare.startswith("["):
        bare = bare[1:].split("]")[0]
    elif bare.count(":") == 1:
        bare = bare.split(":")[0]
    try:
        ipaddress.ip_address(bare)
        return host
    except ValueError:
        return scrub(host)


def redact_target(url):
    """A request target or referer: the block's own URL rule, and the authority of an absolute one through the host rule.
    A target over TEXT_LIMIT keeps its scheme, host and path part as the rule has them and has its query and fragment
    withheld whole, by their length (the block's own rule for a text over the limit): the block splits a query pair by pair,
    so a megabyte of `&` there costs seconds a line. The line stays in the table with its offset and length."""
    cut = min((i for i in (url.find("?"), url.find("#")) if i >= 0), default=len(url)) if len(url) > TEXT_LIMIT else len(url)
    if cut < len(url):
        return redact_target(url[:cut]) + url[cut] + _withheld("over-long query or fragment", len(url) - cut - 1, "urls")
    out = redact_url(url)
    m = re.match(r"^((?:[A-Za-z][A-Za-z0-9+.-]*:)?//)([^/?#]*)(.*)$", out, re.S)
    if not m:
        return out
    prefix, _, host = m.group(2).rpartition("@")
    return m.group(1) + (prefix + "@" if prefix else "") + (shown_host(host) if host else host) + m.group(3)


def parse(line, wanted):
    parsers = {"web": web, "squid": squid, "firewall": firewall}
    if wanted != "auto":
        return parsers[wanted](line)
    for parser in (web, squid, firewall):
        found = parser(line)
        if found:
            return found
    return None


class ExpansionLimit(Exception):
    pass


class TimeLimit(Exception):
    pass


class Stopped(BaseException):
    """A stop signal (SIGTERM, SIGINT, SIGHUP), raised in the main thread by the handler. Raised, not handled in place: a
    handler that wrote to the tables could be running in the middle of a write to them."""

    def __init__(self, signum):
        super().__init__(signum)
        self.signum = signum


class Line:
    """One line's bookkeeping as a unit a stop signal cannot cut. While it is held, the handler only notes the signal; on
    leaving it the signal is raised, so the line is in a table and in the counts, or in neither. Without it a signal that
    arrived between "lines += 1" and the write left a line counted but in no table, and one that arrived between the write
    and "parsed += 1" left a row in the table that no count held. A plain flag, not a signal mask: the handler runs in the
    main thread between two bytecodes, so the flag is never half set, and no system call is paid per line."""

    def __init__(self):
        self.held = False
        self.pending = None

    def __enter__(self):
        self.held = True
        return self

    def __exit__(self, exc_type, _exc, _tb):
        self.held = False
        if exc_type is None and self.pending is not None:
            signum, self.pending = self.pending, None
            raise Stopped(signum)
        return False


LINE = Line()


def _stop(signum, _frame):
    if LINE.held:
        if LINE.pending is None:
            LINE.pending = signum
        return
    raise Stopped(signum)


STAGE = {"now": "checking its arguments", "values": None}   # what a stop that ends the run outside the read loop says it was doing


class ClockedFile:
    """The file under a gzip stream, read through the tool's clock. Python's gzip reader walks the members of a stream inside one
    read: a stream of a few hundred thousand empty members returns nothing for seconds, and the tool's line loop never gets
    to look at the clock. Each read of the file under it (8 KiB of the stream) looks at it instead."""

    def __init__(self, fh, deadline):
        self.fh, self.deadline = fh, deadline

    def read(self, size=-1):
        if time.monotonic() > self.deadline:
            raise TimeLimit()
        return self.fh.read(size)

    def __getattr__(self, name):
        return getattr(self.fh, name)


class Source:
    """The log as a stream of bytes: plain, or gzip with a cap on what it may expand to."""

    def __init__(self, path, cap, deadline):
        self.raw = open_regular(path)
        try:
            magic = self.raw.read(2)
            self.raw.seek(0)
        except BaseException:
            self.raw.close()
            raise
        self.gzip = magic == b"\x1f\x8b"
        self.cap = cap
        self.fh = gzip.GzipFile(fileobj=ClockedFile(self.raw, deadline), mode="rb") if self.gzip else self.raw
        self.read_total = 0

    def readline(self, limit):
        raw = self.fh.readline(limit)
        self.read_total += len(raw)
        if self.gzip and self.read_total > self.cap:
            raise ExpansionLimit()
        return raw

    def close(self):
        try:
            self.fh.close()
        finally:
            self.raw.close()


def optional_int(args, key, default, minimum):
    value = args.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        fail("%s must be an integer of at least %d" % (key, minimum))
    return value


def main():
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, _stop)     # first, before the arguments are read and before anything is opened; the read loop below answers a stop of its own
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    if not isinstance(args, dict):
        fail("arguments must be a JSON object")
    path, out_dir = args.get("path"), args.get("out_dir")
    if not isinstance(path, str) or not os.path.isfile(path):
        fail("path must name a readable log file", path=path if isinstance(path, str) else None)
    if not isinstance(out_dir, str) or not out_dir:
        fail("out_dir is required: an empty directory under work/ (in a job, under $OUT)")
    out_dir = resolve_output(out_dir, "out_dir")
    try:
        if os.path.exists(out_dir) and holds_files(out_dir):
            fail("out_dir already holds files", out_dir=out_dir)
    except OSError as exc:
        fail("out_dir cannot be listed (%s)" % describe(exc), out_dir=out_dir)
    wanted = str(args.get("format") or "auto").lower()
    if wanted not in ("auto", "web", "squid", "firewall"):
        fail("format must be auto, web, squid or firewall", format=wanted)
    top = optional_int(args, "top", 20, 1)
    max_line = optional_int(args, "max_line_bytes", DEFAULT_MAX_LINE, 4096)
    max_expanded = optional_int(args, "max_expanded_bytes", DEFAULT_MAX_EXPANDED, 1 << 20)
    max_distinct = optional_int(args, "max_distinct_values", DEFAULT_MAX_DISTINCT, 1)
    max_seconds = optional_int(args, "max_seconds", DEFAULT_SECONDS, 1)
    if max_seconds > MAX_SECONDS:
        fail("max_seconds is at most %d: the tool stops and answers before the manifest's 600-second limit" % MAX_SECONDS, max_seconds=max_seconds)
    deadline = time.monotonic() + max_seconds
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
            fail("the values file already exists", write_values="refused", written=False, values_file=os.path.join(os.environ["OUT"], SecretValues.NAME))

    STAGE["now"] = "opening its outputs"
    os.umask(0o077)
    try:
        values = SecretValues(write_values)
    except SecretValuesRefused as exc:
        fail(str(exc), write_values="refused", written=False, values_file=exc.path)
    STAGE["values"] = values
    try:
        os.makedirs(out_dir, mode=0o700, exist_ok=True)
        os.chmod(out_dir, 0o700)
        source = Source(path, max_expanded, deadline)
    except (OSError, EOFError, zlib.error) as exc:
        values.discard()
        fail("the log or the output directory could not be opened (%s)" % describe(exc), out_dir=out_dir)
    normal_path, bad_path = os.path.join(out_dir, "normalized.tsv"), os.path.join(out_dir, "unparsed.tsv")
    categories = ("format", "src", "dst", "method", "status", "action")
    counts = {name: collections.Counter() for name in categories}
    over_cap = {name: 0 for name in categories}
    stats = {"lines": 0, "parsed": 0, "blank": 0, "unparsed_nonblank": 0, "over_limit": 0, "decoding_substituted": 0, "crlf_lines": 0,
             "timestamps_derived": 0, "timestamps_not_derived": 0, "bom_stripped": 0, "keys_cut": 0, "partial": 0}
    zones = collections.Counter()
    unterminated = False
    read_error = None
    stopped = None
    in_long_line = False
    since_clock = 0
    offset = 0
    try:
        with open(normal_path, "x", encoding="utf-8", newline="\n") as normal, open(bad_path, "x", encoding="utf-8", newline="\n") as bad:
            normal.write("\t".join(COLUMNS) + "\n")
            bad.write("\t".join(UNPARSED_COLUMNS) + "\n")
            STAGE["now"] = "reading the log"
            try:
                while True:
                    raw = source.readline(max_line + 1)
                    if not raw:
                        break
                    # The clock is read every 256 lines and after every CLOCK_BYTES of lines, so a few long lines cannot outrun it.
                    since_clock += len(raw)
                    if since_clock >= CLOCK_BYTES or stats["lines"] % 256 == 0:
                        since_clock = 0
                        if time.monotonic() > deadline:
                            raise TimeLimit()
                    with LINE:
                        stats["lines"] += 1
                        number, start = stats["lines"], offset
                        if len(raw) > max_line and not raw.endswith(b"\n"):
                            length = len(raw)
                            in_long_line = True
                            LINE.held = False  # reading the rest of a long line can take long: a stop signal ends it at once
                            while True:
                                more = source.readline(max_line)
                                length += len(more)
                                if time.monotonic() > deadline:
                                    raise TimeLimit()
                                if not more or more.endswith(b"\n"):
                                    break
                            LINE.held = True
                            offset += length
                            in_long_line = False
                            stats["over_limit"] += 1
                            bad.write("\t".join(cell(v) for v in (number, start, length, "line_over_limit", "longer than max_line_bytes (%d): located, not read" % max_line, "not read")) + "\n")
                            continue
                        offset += len(raw)
                        terminated = raw.endswith(b"\n")
                        unterminated = not terminated
                        body = raw[:-1] if terminated else raw
                        if number == 1 and body.startswith(b"\xef\xbb\xbf"):
                            body = body[3:]
                            stats["bom_stripped"] += 1
                        if body.endswith(b"\r"):
                            body = body[:-1]
                            stats["crlf_lines"] += 1
                        try:
                            line = body.decode("utf-8")
                            decoding = "exact"
                        except UnicodeDecodeError:
                            line = body.decode("utf-8", "replace")
                            decoding = "substituted"
                            stats["decoding_substituted"] += 1
                        if not line.strip():
                            stats["blank"] += 1
                            bad.write("\t".join(cell(v) for v in (number, start, len(raw), "blank", "an empty line", decoding)) + "\n")
                            continue
                        row = parse(line, wanted)
                        if row is None:
                            stats["unparsed_nonblank"] += 1
                            bad.write("\t".join(cell(v) for v in (number, start, len(raw), "unparsed", "no grammar of the requested format matched", decoding)) + "\n")
                            values.add("L%06d" % number, {"line": number, "byte_offset": start, "byte_length": len(raw), "status": "unparsed"},
                                       body.decode("utf-8", "surrogateescape"))
                            continue
                        original, original_referer = row.get("target", ""), row.get("referer", "")
                        changed = False
                        for column in COLUMNS:
                            if row.get(column):
                                printed = shown(column, str(row[column]))
                                changed = changed or printed != row[column]
                                row[column] = printed
                        status_of_row = "partial" if row.get("unparsed_tail") else "parsed"
                        if changed:
                            values.add("L%06d" % number, {"line": number, "byte_offset": start, "byte_length": len(raw), "status": status_of_row,
                                                           "target": original, "referer": original_referer}, body.decode("utf-8", "surrogateescape"))
                        if row.get("timestamp_utc"):
                            stats["timestamps_derived"] += 1
                        else:
                            stats["timestamps_not_derived"] += 1
                        zones[row.get("timezone_source", "")] += 1
                        row.update(line=number, byte_offset=start, byte_length=len(raw), parse_status=status_of_row, decoding=decoding)
                        normal.write("\t".join(cell(row.get(column, "")) for column in COLUMNS) + "\n")
                        stats["parsed"] += 1
                        stats["partial"] += status_of_row == "partial"
                        for name in categories:
                            if row.get(name):
                                key = str(row[name])
                                if len(key) > MAX_KEY:
                                    key = key[:MAX_KEY] + "...(+%d characters)" % (len(key) - MAX_KEY)
                                    stats["keys_cut"] += 1
                                if key in counts[name] or len(counts[name]) < max_distinct:
                                    counts[name][key] += 1
                                else:
                                    over_cap[name] += 1
            except Stopped as stop:
                stopped = stop.signum
                read_error = {"error": "interrupted", "message": "the tool was stopped by signal %d: the tables hold the lines read before it" % stop.signum,
                              "last_complete_line": stats["lines"] - (1 if in_long_line else 0), "stream_offset": offset}
            except TimeLimit:
                read_error = {"error": "time_limit", "message": "max_seconds (%d) ran out: the tool stopped reading and answers with what it read" % max_seconds,
                              "last_complete_line": stats["lines"] - (1 if in_long_line else 0), "stream_offset": offset}
            except ExpansionLimit:
                read_error = {"error": "expansion_limit", "message": "the decompressed stream passed max_expanded_bytes (%d)" % max_expanded,
                              "last_complete_line": stats["lines"] - (1 if in_long_line else 0), "stream_offset": offset}
            except (OSError, EOFError, zlib.error) as exc:
                read_error = {"error": type(exc).__name__, "message": describe(exc),
                              "last_complete_line": stats["lines"] - (1 if in_long_line else 0), "stream_offset": offset}
            if in_long_line:
                stats["lines"] -= 1  # a long line cut by the stop is in no table, so it is not a line read
                in_long_line = False
            normal.flush()
            os.fsync(normal.fileno())
            bad.flush()
            os.fsync(bad.fileno())
    except OSError as exc:
        values.discard()
        fail("a table could not be written (%s)" % describe(exc), out_dir=out_dir)
    finally:
        for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            signal.signal(signum, signal.SIG_DFL)
        source.close()
        values.close()
    for name in os.listdir(out_dir):
        try:
            os.chmod(os.path.join(out_dir, name), 0o600)
        except OSError:
            pass

    def leading(counter):
        return [{"value": value, "count": count} for value, count in counter.most_common(top)]
    complete = read_error is None
    if not complete:
        values.discard()
    unparsed_count = stats["lines"] - stats["parsed"]
    all_read = complete and not unparsed_count - stats["blank"] and not stats["over_limit"] and not stats["partial"]
    if not complete and not stats["lines"]:
        basis = "the read stopped before the first line (read_error): the tables are empty"
    elif not complete:
        basis = "the read stopped early (read_error): the tables hold the lines read before it"
    elif all_read:
        basis = "every line was read and every non-blank line matched a grammar completely"
    else:
        basis = ("the whole log was read; %d line(s) matched no grammar, %d were over max_line_bytes, %d matched with text left over (unparsed_tail), "
                 "and each is in a table with its line number" % (stats["unparsed_nonblank"], stats["over_limit"], stats["partial"]))
    answer = {
        "tool": TOOL, "parser": PARSER,
        "status": "complete" if all_read else ("failed" if not complete and not stats["lines"] else "partial"), "status_basis": basis,
        "path": path, "format_requested": wanted, "compression": "gzip" if source.gzip else "none",
        "offsets_are_in": "the decompressed stream" if source.gzip else "the file",
        "lines": stats["lines"], "parsed": stats["parsed"], "parsed_with_text_left_over": stats["partial"], "unparsed": stats["lines"] - stats["parsed"], "blank": stats["blank"],
        "unparsed_not_blank": stats["unparsed_nonblank"], "lines_over_limit": stats["over_limit"], "max_line_bytes": max_line,
        "decoding_substituted": stats["decoding_substituted"], "crlf_lines": stats["crlf_lines"],
        "last_line_has_no_line_end": unterminated,
        "timestamps": {"derived": stats["timestamps_derived"], "not_derived": stats["timestamps_not_derived"], "timezone_sources": dict(zones)},
        "normalized_tsv": normal_path, "unparsed_tsv": bad_path,
        "aggregate": {name: leading(counter) for name, counter in counts.items()},
        "distinct_cap_reached": {name: n for name, n in over_cap.items() if n} or None,
        "aggregate_keys_cut": stats["keys_cut"], "bom_stripped": stats["bom_stripped"],
        "aggregate_note": "a ranking is exact only while distinct_cap_reached is null: once a category holds max_distinct_values values, a value first seen later is counted in distinct_cap_reached and never in the ranking",
        "max_distinct_values": max_distinct, "max_seconds": max_seconds,
        "complete": complete, "read_error": read_error,
        "ok": complete,
        "withheld": dict(COUNTS),
        "secret_values": values.summary(),
        "out_dir_contains_secret_values": True,
        "out_dir_note": ("The tables carry redacted targets and no raw line, and the directory is private (mode 0700, files 0600). Redaction is by shape: "
                         "user-info, token-shaped path text and every query value are withheld, and the text of an unparsed line is not in "
                         "unparsed.tsv; a secret that does not look like a token (a short password in a path segment, a user column) is not recognised, "
                         "so run the tool as a job with secret_output: true. write_values: true (jobs only) writes the originals to one 0600 file."),
        "note": ("Every source line is in normalized.tsv or unparsed.tsv with its line number, byte offset and byte length; the answer holds no raw line. "
                 "Aggregates are bounded by top. timestamp_utc is filled only where the line gives enough to derive it, and timezone_source says how; a "
                 "syslog stamp has no year and no zone and is never read as UTC. A forwarded-for header, a NAT address and an action label are what the "
                 "logging device wrote, not facts about the host that sent the traffic."),
    }
    if not complete:
        answer["note"] = "THE READ STOPPED EARLY (read_error): what is in the tables is what was read before it. " + answer["note"]
    if stopped:
        answer["interrupted_by_signal"] = stopped
    print(json.dumps(answer, indent=2))
    return 128 + stopped if stopped else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except Stopped as stop:
        # a stop outside the read loop (the arguments, the opening of the outputs): the loop answers its own, with the tables it wrote
        for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            signal.signal(signum, signal.SIG_IGN)
        if STAGE["values"] is not None:
            STAGE["values"].discard()
        print(json.dumps({"tool": TOOL, "parser": PARSER, "status": "partial", "ok": False,
                          "status_basis": "the tool was stopped by signal %d while it was %s; no line of the log had been normalised%s" %
                                          (stop.signum, STAGE["now"], ", and the output directory may hold the empty tables it had begun to write" if STAGE["values"] is not None else ""),
                          "interrupted_by_signal": stop.signum, "stage": STAGE["now"]}), flush=True)
        os._exit(128 + stop.signum)
    except BaseException as exc:  # noqa: BLE001 - never a traceback, never a clean answer for a failure
        fail("unexpected failure: %s" % describe(exc))
