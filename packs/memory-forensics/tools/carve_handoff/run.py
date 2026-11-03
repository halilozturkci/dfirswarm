#!/usr/bin/env python3
"""Make one hit of mem_carve ready for the parser that reads it: the structure's true start, what the header supports, whether its pages are adjacent, and a slice.

mem_carve surveys an image for the signatures of structures that other parsers read and says where each signature is. This tool takes ONE of
those hits (`path`, `kind`, `signature_offset`) and prepares it for a parser, without parsing the structure itself:

    object start     where the structure starts. For a plain Prefetch record that is four bytes before "SCCA", and only when those four
                     bytes are a version the format has (17, 23, 26, 30, 31); otherwise the start is not established and the cut is
                     taken from the signature with validation "unknown". For every other kind the structure starts at its signature.
                     A caller's `object_offset` is compared with that and the difference said, never taken.
    the cut          the same rule as mem_carve's: the kind's fixed size, or the length the header declares up to the kind's cap;
                     `declared_bytes`, `requested_bytes`, `available_bytes` (what the file holds) and `cut_complete`.
    structure checks `validation` (header plausible, header implausible, truncated, unknown) and its detail, from the fields the format
                     fixes; and, for three families, checks that a slice can fail: a registry hive's base-block checksum, its two sequence
                     numbers (a hive whose numbers differ was written to while it was copied and needs its transaction logs) and its chain
                     of bins; an event log file's chunks, each of which must start with ElfChnk; an event log chunk's header checksum. A break
                     in a chain is where the pages of the structure stop being adjacent in the image (`fragmentation`): the cut then runs into
                     unrelated bytes. Other families have no such check, and the answer says "not checkable", not "intact".
    the slice        sha256 of the cut for a family that cannot be a credential store. A registry hive, a SQLite database and a binary
                     property list can be one (SAM, SECURITY, a browser database, a keychain): their slice is never hashed, because the
                     digest of a secret is itself a secret-shaped output. Slice bytes are written only with `write_values` in a job run as
                     secret output (mode 0600, in a directory with mode 0700, under $OUT/carve_handoff, created exclusively and placed
                     without replacing an earlier file); the answer names the file and never prints content.
    the parser       the names of the windows-forensics tools that read the family (regkv, evtx_carve, mam_scan, prefetch_mam), as
                     names: whether that pack is loaded is not known here, and this tool calls none of them. When a result of one of them
                     is passed as `parser_result` (a file under the run directory, a declared job input) the answer references it by path
                     and size and says it was not read.

The tool opens the image without waiting and looks at it with fstat first (a FIFO, a device or a directory is refused), reads at the offsets
it needs and nothing else, and has its own clock: `max_seconds` (default 120, at most 270, inside the manifest's 300) is looked at before
every block of the chain walks, the hash and the copy; a walk or a hash that the clock or `examine_bytes` ends is said (status partial) and
gives no digest. Its list of anomalies is paged: 20 in the answer, the whole in a file the answer names.

STOPS. SIGTERM, SIGINT and SIGHUP end the tool with one JSON answer (status failed, interrupted true, exit 128 plus the signal); a slice
file that was being written is closed and named with a name ending in .partial, never left under a hidden one. A signal that arrives while a
file is placed or the answer written is held until that is done. The process leaves without the interpreter's shutdown. What no script can
answer is a stop that arrives before the interpreter has run this file's first lines: it ends the process with no answer, and nothing had
been read or written yet.
"""
import json
import os
import signal
import sys

PARSER = "carve_handoff/1"


def _before_start(signum, _frame):
    """A stop that arrives while the rest of the module is still loading: nothing was read or written yet, and the one answer says so."""
    sys.stdout.write(json.dumps({
        "error": "stopped by signal %d before the hit was read" % signum, "status": "failed", "interrupted": True,
        "status_basis": "the tool was stopped by signal %d before it read or wrote anything; nothing is a finding, and the call can be "
                        "repeated as it was" % signum,
        "signal": signum, "parser": PARSER}) + "\n")
    sys.stdout.flush()
    os._exit(128 + signum)


for _signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
    signal.signal(_signum, _before_start)   # replaced by run_guarded() once the module is loaded

import errno  # noqa: E402  (after the early handler, so a stop during these imports is answered too)
import hashlib  # noqa: E402
import re  # noqa: E402
import stat  # noqa: E402
import struct  # noqa: E402
import time  # noqa: E402
import zlib  # noqa: E402
from pathlib import Path  # noqa: E402

DEFAULT_SECONDS, MAX_SECONDS, MIN_SECONDS = 120.0, 270.0, 5.0
DEFAULT_EXAMINE, MAX_EXAMINE = 64 << 20, 1 << 30
BLOCK = 1 << 20            # bytes read between two looks at the clock
MAX_STDIN = 1 << 20
MAX_TEXT = 4096
MAX_OFFSET = 1 << 62
ANOMALIES_INLINE = 20
PARSERS = ("regkv", "evtx_carve", "mam_scan", "prefetch_mam")
# Families whose slice can be a credential store: never hashed, bytes only with write_values in a secret job.
CREDENTIAL_POSSIBLE = ("registry hive", "SQLite database", "binary property list")
SUGGESTED = {
    "registry hive": ["regkv"], "event log chunk": ["evtx_carve"], "event log file": ["evtx_carve"],
    "compressed prefetch record": ["mam_scan", "prefetch_mam"], "prefetch record": ["prefetch_mam"],
}
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
# BEGIN SHARED SHOWN
# MEMORY SHOWN v1: the same text is in mem_fs and mem_profile (tests/pack-memory-shared.test.ts holds the copies equal), and it
# reads the shared WITHHOLDING block above it. A string read from the capture (a name MemProcFS lists, a line the engine prints, a
# release string in a header) is not printed as it is: it goes through shown(text, kind), and the answer and the paged file go
# through sealed(), so that nothing reaches stdout or a file that is not sealed output without having been judged. Three layers,
# the hybrid design: an allow-list per kind, the shared deny-list, and an independent backstop with its own rules.
#
# LAYER 1, an allow-list per kind of field. "release" (a kernel release) and "build" (a Windows build string) are shown only when
# they fit the grammar of a version: digits, dots and the tags of a closed list (_RELEASE_WORD, _BUILD_WORD), at most 6 groups and 16
# digits after the version, nothing else, so a secret placed where a version should be, or glued to one, is not printed. "name" (a file, directory, process or key name; "path" is the same for a virtual path, judged as a whole and
# then component by component) is shown when it has no invisible character, no component over 128 characters, and no chain of 16
# or more letters and digits that looks random (it flips between letters and digits, or between capitals and lower case, as words
# do not). A GUID, a SID, a 16-digit hexadecimal address and 0x numbers are typed ids and are plain. "text" (one line of an
# engine's output) has no character grammar, only layers 2 and 3.
# LAYER 2, the deny-list of the shared block (token_spans: vendor prefixes, long token-like runs, user-info) plus the value after
# a secret's name (password=, token:, api key ...), read on the string with typed ids masked. A span is replaced; the rest stays.
# LAYER 3, the backstop, written apart from the two above and applied to what layers 1 and 2 would print: a PEM marker, a named
# secret, a vendor prefix in any case, user-info, 19 or more digits, 32 or more hexadecimal digits, a run of 20 or more characters
# that changes class (lower, upper, digit, other) as random text does; read on a copy with invisible characters taken out and NFKC
# applied, and on the original: 12 characters of anything it calls secret in the original that are still in the shown string mean
# a piece was left between two cuts. A string it finds suspect is replaced whole by <withheld N characters: why>, counted, and the
# answer says so.
# NOT RECOGNISED, by design: a plain password or passphrase, a pronounceable secret, anything under 16 characters in a name,
# a secret in an encoding this block does not read. Withholding is by shape. Measured on planted canaries (1,000 per cell; a name
# alone, then inside `proc_<k>.exe`, `<k>.dll` and `1234-<k>`), the share of keys printed whole: base64 and base62 keys 0 to 0.6 per
# cent alone and up to 3 per cent in a process-name context (24 base62 characters 2.9, 20 bytes of base64 1.2); in an engine line
# (kind text, used for the first lines of a failure, which has no allow-list) base64 keys of 16 to 32 bytes 0 to 18 per cent, base62
# keys of 20 to 32 characters 10 to 61, a 24-character base36 key 48 to 65, a base64 key holding `/` 37 to 40. The prefixes of the vendors in _PREFIX2 and _PREFIX_RULES are read at 0 in 3,400 plants per shape. Printed at
# 100 per cent, because they are made of pieces under 16 characters or of words: UUID-shaped and 16-digit hexadecimal secrets (typed
# ids are plain), tokens split by `.` or `:` into pieces under 16 characters, word passwords and passphrases, 14-character policy
# passwords. Printed at tens of per cent: base32 seeds (43 to 46), licence keys of 5 groups of 5 (18 to 20), a bcrypt hash's
# 12-character fragments (28 to 31), a vendor key whose prefix is in no list (`rk_live_` was 3 to 18 before it was added).
import collections
import unicodedata

LMIN = 16
MAX_ONE = 4096
MAX_COMPONENT = 128
BOUNDARY = {"shown": 0, "withheld_spans": 0, "withheld_whole": 0, "backstop_replaced": 0, "swept": 0}
BACKSTOP_WHY = collections.Counter()


class Shown(str):
    """A string read from the capture that has been judged: sealed() does not judge it again."""


_TYPED = re.compile(r"\{?[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}?"
                    r"|S-1-[0-9]{1,2}(?:-[0-9]{1,10}){1,15}"
                    r"|(?<![0-9A-Za-z])0x[0-9A-Fa-f]{1,16}(?![0-9A-Za-z])"
                    r"|(?<![0-9A-Za-z])[0-9A-Fa-f]{16}(?![0-9A-Za-z])"
                    r"|(?<=[A-Za-z0-9]_)[0-9a-z]{13}(?![0-9A-Za-z])")        # the publisher id at the end of an app package family name
_PREFIX2 = re.compile(r"(?i)glpat-[0-9a-z_-]{16,}|(?:sk|rk|pk)_(?:live|test)_[0-9a-z]{16,}|whsec_[0-9a-z_+/=-]{16,}|sg\.[0-9a-z_-]{16,}|aiza[0-9a-z_-]{30,}|npm_[0-9a-z]{30,}|dop_v1_[0-9a-f]{32,}|ya29\.[0-9a-z_-]{20,}")
_PIECE = re.compile(r"[A-Za-z0-9+_=-]{16,}")
_PLAIN_SHORT = re.compile(r"[A-Za-z0-9 ._()+-]{1,15}")
_NAMED = re.compile(r"(?i)(?:pass(?:word|wd|phrase)?|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential|auth)"
                    r"[A-Za-z0-9_]{0,12}[ \t]{0,3}[=:](?![=:/\\])[ \t]{0,3}['\"]?([^\s'\"<>&;,]{3,128})")
# the same rule for a string the tool wrote itself (documentation-like text such as "secret_output: true" must pass): the value is 6 or more characters with a digit or a symbol in it
_NAMED_TEXT = re.compile(r"(?i)(?:pass(?:word|wd|phrase)?|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential|auth)"
                         r"[A-Za-z0-9_]{0,12}[ \t]{0,3}[=:][ \t]{0,3}['\"]?(?=[^\s'\"<>&;,]{0,127}[0-9!#$%^*+@~])[^\s'\"<>&;,]{6,128}")
_USER_INFO = re.compile(r"[^\s/@:<>]{1,64}:[^\s/<>]{1,128}@[\w\[]")        # the backstop's own form: the password may hold an @
_UINFO_SPAN = re.compile(r"(?<![\w.%+-])[\w.%+-]{1,64}:[^\s/<>]{1,128}(?=@[\w\[])")   # layer 2's: up to the last @ before a host
_BS_PEM = re.compile(r"-----BEGIN")
_BS_PREFIX = re.compile(r"(?i)(?:akia|asia)[0-9a-z]{16}|gh[pousr]_[0-9a-z]{16}|github_pat_[0-9a-z_]{16}|xox[abeprs]-[0-9a-z-]{8}"
                        r"|glpat-[0-9a-z_-]{16}|(?:sk|rk|pk)_(?:live|test)_[0-9a-z]{16}|whsec_[0-9a-z_+/=-]{16}|sk-[0-9a-z_-]{16}|aiza[0-9a-z_-]{20}|npm_[0-9a-z]{20}"
                        r"|eyj[0-9a-z_-]{8,}\.[0-9a-z_-]{8,}\.|sg\.[0-9a-z_-]{16}|(?:basic|bearer)[ \t]{1,3}[0-9a-z+/=._~-]{16}")
_BS_DIGITS = re.compile(r"[0-9]{19,}")
_BS_HEX = re.compile(r"[0-9A-Fa-f]{32,}")
_BS_RUN = re.compile(r"[A-Za-z0-9+/=_-]{20,}")
# The version grammars are closed lists, not shapes: a release is the version, then at most six groups, each a number of up to five digits or one
# word of the list below (a distribution's or a kernel flavour's own tag, with up to three digits after it); a Windows build string is the build, the
# platform, and a branch made of at most four words of the list below and a date. A word that is not in the list, or a seventh group, or more than 16
# digits in all, is not a version, and the string is withheld whole (a release with an unusual tag is withheld too: the count is in boundary).
_RELEASE_WORD = (r"(?:generic|lowlatency|aws|azure|gcp|gke|oem|cloud|kvm|virtual|raspi|rpi|lts|zen|hardened|realtime|rt|rc|amd64|arm64|armhf|"
                 r"i[3-6]86|x86_64|aarch64|ppc64le|s390x|el|fc|ubuntu|debian|deb|bpo|pve|default|arch|mainline|android|linuxkit|coreos|edge|std|"
                 r"smp|preempt|uek|lp|oracle|ibm|nvidia|tegra|stable|gentoo|xanmod|liquorix|v7l?|v8|k3s|dirty)")
_RELEASE = re.compile(r"[0-9]{1,2}\.[0-9]{1,3}(?:\.[0-9]{1,3})?((?:[-+~._](?:[0-9]{1,5}|" + _RELEASE_WORD + r"[0-9]{0,3}(?:_[0-9]{1,3})?)){0,6})\+?")
_BUILD_WORD = (r"(?:win7sp1|win7|win8|winmain|winblue|vibranium|th[12]|rs|rs[0-9]{1,2}|[0-9]{2}h[12]|vb|ni|co|ge|fe|zn|mn|sv|lh|r[0-9]{1,2}|release|"
               r"prerelease|rtm|gdr|ldr|svc|sec|escrow|inmarket|flt|prod|dev|beta|lab|sp[0-9]|rc|oem|st|uup|rel|main|win|vista|server|ltsc)[0-9]{0,2}")
_BUILD = re.compile(r"[0-9]{3,6}\.[0-9]{1,5}\.(?:x86|amd64|arm64|armnt)(?:fre|chk)(?:\.(?:" + _BUILD_WORD + r"(?:_" + _BUILD_WORD + r"){0,3})?(?:\.[0-9]{0,6}(?:-[0-9]{0,4})?)?)?")


def _norm(text):
    """NFKC with the invisible characters (format, control, combining) taken out: what the rules read besides the string itself."""
    if text.isascii() and text.isprintable():
        return text
    folded = unicodedata.normalize("NFKC", text)
    return "".join(c for c in folded if unicodedata.category(c) not in ("Cf", "Cc", "Mn", "Me"))


def _hidden(text):
    """Whether the text holds an invisible or unassigned character (a byte that was not UTF-8, written as a lone surrogate escape, is not one)."""
    if text.isascii() and text.isprintable():
        return False
    for c in text:
        cat = unicodedata.category(c)
        if cat in ("Cf", "Cc", "Co", "Cn") or (cat == "Cs" and not 0xDC80 <= ord(c) <= 0xDCFF):
            return True
    return False


def _escaped(text):
    """A byte that was not UTF-8 (a lone surrogate escape) written as \\xNN, so that no writer raises on it."""
    if text.isascii():
        return text
    return "".join("\\x%02x" % (ord(c) - 0xDC00) if 0xDC80 <= ord(c) <= 0xDCFF else c for c in text)


def _mask(text):
    return _TYPED.sub(lambda m: "x" * len(m.group()), text)


_SEGMENT = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|[0-9]+")


def _random_piece(piece):
    """A run of 16 or more characters that is not shaped like words. Words, CamelCase names and dates break into segments (a word, a capital
    and its lower-case letters, a number) of 3 or more characters on average; random base62 and base64 break into segments of about 2. A
    base64 padding (== at the end, or a + inside a run of letters and digits) is not in a word either."""
    alnum = "".join(c for c in piece if c.isalnum())
    if len(alnum) < LMIN - 2 or alnum.isdigit():
        return False
    if piece.endswith("==") or (len(alnum) >= LMIN and "+" in piece.strip("+") and not piece.isalpha()):
        return True
    return len(alnum) >= LMIN and len(alnum) <= 3.0 * len(_SEGMENT.findall(alnum))


def _spans(text, kind):
    """The spans of a string that layers 1 and 2 withhold, as (start, end, what), merged."""
    masked = _mask(text)
    if kind == "text":
        found = [(s, e, "token-shaped text") for s, e in token_spans(masked)]
    else:
        # a name is judged by the allow-list below; of the shared deny-list only the vendor prefixes apply to it
        found = [(start, end, "token-shaped text") for start, end in _prefixed_spans(masked)]
    found += [(m.start(), m.end(), "token-shaped text") for m in _PREFIX2.finditer(masked)]
    if kind != "text":
        for m in _PIECE.finditer(masked):
            if _random_piece(m.group()):
                found.append((m.start(), m.end(), "random-looking text"))
    for rx in (_USERINFO, _BARE_USERINFO, _UINFO_SPAN):
        for m in rx.finditer(text):
            found.append((m.start(), m.end(), "userinfo"))
    for m in _NAMED.finditer(masked):
        found.append((m.start(1), m.end(1), "secret value"))
    found.sort()
    merged = []
    for start, end, what in found:
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end), merged[-1][2])
        else:
            merged.append((start, end, what))
    return merged


def _density(run):
    """For a run of 16 or more letters and digits (symbols left out): how often neighbours change class (lower, upper, digit), and whether it mixes classes
    as random text does. Words, paths and CamelCase names change class rarely; random base62 and base64 change in about 6 of 10 steps."""
    alnum = [0 if c.islower() else 1 if c.isupper() else 2 for c in run if c.isalnum()]
    if len(alnum) < LMIN:
        return False
    changes = sum(1 for a, b in zip(alnum, alnum[1:]) if a != b)
    return changes >= 0.45 * (len(alnum) - 1) and (2 in alnum or (0 in alnum and 1 in alnum))


def _backstop_reason(text):
    """Why a string is not printed, by rules that are not layer 2's; None when it may be."""
    plain = _norm(text)
    if _BS_PEM.search(plain):
        return "a PEM marker"
    if _NAMED.search(plain):
        return "a named secret"
    if _BS_PREFIX.search(plain):
        return "a token prefix"
    if _USER_INFO.search(plain):
        return "user-info"
    masked = _mask(plain)
    if _BS_DIGITS.search(masked):
        return "a long digit run"
    if _BS_HEX.search(masked):
        return "a long hexadecimal run"
    for m in _BS_RUN.finditer(masked):
        if _density(m.group()):
            return "a random-looking run"
    return None


def _backstop_pieces(original, printed):
    """Whether 12 characters of a secret-shaped part of the original are still in what would be printed (a piece left between two cuts)."""
    plain, out = _norm(original), _norm(printed)
    masked = _mask(plain)
    spans = [m.span() for m in _BS_RUN.finditer(masked) if _density(m.group())]
    spans += [m.span(1) for m in _NAMED.finditer(plain)]
    spans += [m.span() for m in _BS_PREFIX.finditer(plain)]
    for start, end in spans[:16]:
        piece = plain[start:end]
        if len(piece) >= 12 and any(piece[i:i + 12] in out for i in range(0, len(piece) - 11)):
            return True
    return False


def _whole(text, why, key):
    BOUNDARY["withheld_whole"] += 1
    COUNTS[key] = COUNTS.get(key, 0) + 1
    return Shown("<withheld %d characters: %s>" % (len(text), why))


def shown(text, kind="name"):
    """What may be printed of a string read from the capture. kind: name, path, text, release or build."""
    if not isinstance(text, str):
        text = str(text)
    if isinstance(text, Shown):
        return text
    BOUNDARY["shown"] += 1
    key = "text" if kind == "text" else "names"
    if kind in ("release", "build"):
        if len(text) > (48 if kind == "release" else 64):
            return _whole(text, "not a version", key)
        found = (_RELEASE if kind == "release" else _BUILD).fullmatch(text)
        if not found or (kind == "release" and sum(len(d) for d in re.findall(r"[0-9]+", found.group(1))) > 16):
            return _whole(text, "not a %s string" % kind, key)
        return Shown(text)
    if _PLAIN_SHORT.fullmatch(text):
        return Shown(text)
    if len(text) > MAX_ONE:
        return _whole(text, "longer than %d characters" % MAX_ONE, key)
    if _hidden(text):
        return _whole(text, "invisible or non-text characters", key)
    if kind in ("name", "path") and any(len(part) > MAX_COMPONENT for part in text.split("/")):
        return _whole(text, "a component over %d characters" % MAX_COMPONENT, key)
    spans = _spans(text, kind)
    pieces, last = [], 0
    for start, end, what in spans:
        pieces.append(text[last:start])
        pieces.append(_withheld(what, end - start, key))
        BOUNDARY["withheld_spans"] += 1
        last = end
    pieces.append(text[last:])
    printed = _escaped("".join(pieces))
    why = _backstop_reason(printed)
    if why is None and spans and _backstop_pieces(text, printed):
        why = "a part of a secret-shaped text"
    if why is not None:
        BOUNDARY["backstop_replaced"] += 1
        BACKSTOP_WHY[why] += 1
        return _whole(text, "backstop: " + why, key)
    return Shown(printed)


def _seal_text(s):
    """The strongest rules of the backstop on a string the tool did not mark as read from the capture."""
    if len(s) < 12:
        return s
    if len(s) > 4 * MAX_ONE:
        BOUNDARY["backstop_replaced"] += 1
        BACKSTOP_WHY["longer than the judged size"] += 1
        return Shown("<withheld %d characters: backstop: longer than the judged size>" % len(s))
    BOUNDARY["swept"] += 1
    plain = _norm(s)
    why = ("a PEM marker" if _BS_PEM.search(plain) else "a named secret" if _NAMED_TEXT.search(plain)
           else "a token prefix" if _BS_PREFIX.search(plain) else "user-info" if _USER_INFO.search(plain) else None)
    if why is None:
        return s
    BOUNDARY["backstop_replaced"] += 1
    BACKSTOP_WHY[why] += 1
    return Shown("<withheld %d characters: backstop: %s>" % (len(s), why))


def sealed(obj):
    """The serialisation boundary: the same structure with every string that is not already judged put through the strongest backstop rules."""
    if isinstance(obj, Shown):
        return obj
    if isinstance(obj, str):
        return _seal_text(obj)
    if isinstance(obj, dict):
        return {(sealed(k) if isinstance(k, str) else k): sealed(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [sealed(v) for v in obj]
    return obj


def boundary_summary():
    return {"strings_judged": BOUNDARY["shown"], "spans_withheld": BOUNDARY["withheld_spans"], "strings_withheld": BOUNDARY["withheld_whole"],
            "backstop_replaced": BOUNDARY["backstop_replaced"],
            "rule": "a string read from the capture is shown only when it fits the plain grammar of its kind and no deny-list or backstop rule "
                    "reads it as a secret; a placeholder says how many characters were withheld. Withholding is by shape: a plain password, "
                    "a pronounceable passphrase or anything under 16 characters in a name is printed. The originals of withheld names are "
                    "written only on write_values, in a job run as secret output."}
# END SHARED SHOWN
# BEGIN SHARED PAGE
# The same text is in mem_carve, mem_fs and mem_profile (tests/pack-memory-shared.test.ts holds the copies equal).
# LosslessPage keeps the page an agent reads small and, when there are more rows, writes the whole result as JSON Lines
# under work/<agent>/tool-output (in a job, $OUT/tool-output) and names it. A row is serialised with the default ASCII
# escapes, so a name that is not valid UTF-8 (a lone surrogate) is written as a \udcXX escape and cannot break the writer.
# The finished file is placed without replacing an earlier one (a rerun that stopped sooner never leaves a smaller file
# where a larger one was; the name actually used is the one in `shown`), and a stop removes or names the temporary file, under a name
# an answer may print (never the hidden one). Closing and placing the file is held against a stop, which is acted on right after.
# Only regular files are ever compared: both names are opened with O_NONBLOCK and O_NOFOLLOW and looked at with fstat before a byte is
# read, so a FIFO, a device, a directory or a link at a name (the caller's own results_to, say) is another result's and cannot hold the
# tool. The comparing of one call has PLACE_COMPARE_SECONDS in all; past it an earlier result is taken as different and this one takes
# the next free name (nothing is replaced, but an identical rerun may then be named anew).
# The name is taken with a hard link of the finished file, so it never holds an empty file, whatever stops the tool and when (SIGKILL
# included). Where the file system refuses the link, the name is taken with an exclusive create and the file is moved over it: a stop
# that unwinds (an exception) takes the empty name back while it is still the empty file this call made; a stop that ends the process
# without unwinding (SIGKILL, the handlers of the STOP block) between the create and the move leaves the empty name, and the next run takes -2.
# abort_pages() drops the temporary files of all the pages under that guard; the module's fail() calls it before it answers.
# The module that carries this block defines GUARD (a dict with "depth") and checkpoint().
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
    raise OSError(errno.EEXIST, "no free name beside %s" % path)


def place_visibly(tmp, wanted):
    """Give the kept `tmp` a name an answer may print: `wanted` (or the next free one), and when the directory refuses that, a plain
    rename to <wanted>.<pid>. Returns the path, or None when `tmp` is gone or could not be renamed. The hidden name of `tmp` is never
    what an answer prints: a caller that gets None says that nothing is named."""
    try:
        return place_without_replacing(tmp, wanted)
    except OSError:
        pass
    if not os.path.lexists(tmp):
        return None
    fallback = wanted.with_name("%s.%d" % (wanted.name, os.getpid()))
    try:
        os.rename(tmp, fallback)
    except OSError:
        return None
    return fallback


PAGES = []


def abort_pages():
    """Drop the hidden temporary file of every page that was being written, under the signal guard (GUARD["depth"], as emit holds it for an
    answer): a signal that lands in the loop is held until it is over, so that no page's file is left and the answer that follows is the one
    answer."""
    GUARD["depth"] += 1
    try:
        for page in list(PAGES):
            page.abort()
    finally:
        GUARD["depth"] -= 1


class LosslessPage:
    def __init__(self, tool: str, key: object, limit: int):
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ValueError("limit must be a positive integer")
        self.tool = re.sub(r"[^A-Za-z0-9_.-]", "_", tool)
        self.limit = limit
        self.page: list[object] = []
        self.total = 0
        self.bytes = 0                          # what the whole result takes as JSON Lines, kept in memory or not
        self._out = None
        self._tmp: Path | None = None
        self.placed = False                     # the finished file is under its final name (and, if a stop comes now, is kept and named)
        digest = hashlib.sha256(
            json.dumps(key, sort_keys=True, default=str).encode("utf-8", "surrogatepass")
        ).hexdigest()[:16]
        name = f"{self.tool}-{digest}.jsonl"
        job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
        if job and out:
            # In a job only $OUT is written, and it is sealed as the job's output: the whole result is cited from there.
            self.path = Path(out) / "tool-output" / name
            self.shown = "store/jobs/%s/out/tool-output/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", job), name)
        else:
            agent = re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool")
            self.path = Path("work") / agent / "tool-output" / name
            self.shown = str(self.path)
        PAGES.append(self)

    def _write(self, line: str) -> None:
        assert self._out is not None
        self._out.write(line)
        self._out.write("\n")

    def add(self, row: object, line: str | None = None) -> None:
        self.total += 1
        if line is None:
            line = json.dumps(row, default=str)
        self.bytes += len(line) + 1
        if len(self.page) < self.limit:
            self.page.append(row)
            return
        if self._out is None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            # The object knows the hidden name before the file exists, so a stop at any point leaves nothing that abort() or
            # keep_partial() cannot find.
            self._tmp = self.path.parent / (".%s-%s" % (self.path.name, os.urandom(6).hex()))
            fd = os.open(str(self._tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
            self._out = os.fdopen(fd, "w", encoding="ascii")
            for kept in self.page:
                self._write(json.dumps(kept, default=str))
        self._write(line)

    def finish(self) -> dict:
        result = {"matched": self.total, "returned": len(self.page), "truncated": self.total > len(self.page)}
        if self._out is not None:
            GUARD["depth"] += 1                 # closing the file and giving it its name is finished before a stop is acted on
            try:
                self._out.flush()
                os.fsync(self._out.fileno())
                self._out.close()
                self._out = None
                assert self._tmp is not None
                placed = place_without_replacing(self._tmp, self.path)
                self._tmp = None
                self.path = placed
                self.shown = self.shown[: len(self.shown) - len(self.shown.rsplit("/", 1)[-1])] + placed.name
                self.placed = True
            finally:
                GUARD["depth"] -= 1
            checkpoint()
            result["all_results"] = self.shown
            result["all_results_format"] = "JSON Lines, one complete result per line"
        return result

    def abort(self) -> None:
        """Drop the hidden temporary file of a run that failed part way. Closing the file flushes what is buffered, and on a full disk
        (or past a quota) that raises: the file is unlinked all the same, and the error is not the caller's to meet while it is
        already giving up the page."""
        out, tmp = self._out, self._tmp
        self._out = None
        try:
            if out is not None:
                out.close()
        except OSError:
            pass
        finally:
            if tmp is not None:
                try:
                    os.unlink(tmp)
                except FileNotFoundError:
                    pass
                except OSError:
                    pass
                self._tmp = None

    def keep_partial(self):
        """Close the temporary file and give it a visible name ending in .partial (never replacing a file); returns the
        path, or None when nothing was being written. Whole lines only are in it when the rows were added whole."""
        if self._tmp is None:
            return None
        if self._out is not None:
            try:
                self._out.flush()
                self._out.close()
            except OSError:
                pass
            self._out = None
        if not os.path.lexists(self._tmp):      # a stop between choosing the name and creating the file
            self._tmp = None
            return None
        placed = place_visibly(self._tmp, self.path.with_name(self.path.name + ".partial"))
        self._tmp = None
        return placed
# END SHARED PAGE


# --- copied from mem_carve (a tool is standalone; none imports another): its signatures, the caps of a declared length and the checks of each kind's first bytes. tests/pack-memory-carve-handoff.test.ts holds the two tools equal on the same image. ---
SIGNATURES = [
    (b"regf", "registry hive", 1 << 20),
    (b"ElfChnk\x00", "event log chunk", 65536),
    (b"ElfFile\x00", "event log file", 1 << 20),
    (b"MAM\x04", "compressed prefetch record", 1 << 17),
    (b"SCCA", "prefetch record", 1 << 17),
    (b"MZ\x90\x00\x03", "PE header", 1 << 20),
    (b"SQLite format 3\x00", "SQLite database", 1 << 21),
    (b"FILE0", "MFT record", 1024),
    (b"INDX(", "NTFS index block", 4096),
    (b"\x50\x4b\x03\x04", "zip or office document", 1 << 20),
    (b"%PDF-", "PDF", 1 << 20),
    (b"bplist00", "binary property list", 1 << 16),
]
# Where a header declares a length longer than the kind's fixed cut, the cut grows to the declared length up to this cap.
DECLARED_CAPS = {
    "prefetch record": 16 << 20,
    "event log file": 64 << 20,
    "SQLite database": 64 << 20,
    "NTFS index block": 65536,
    "event log chunk": 65536,
}
# How much of a structure's start a validator may look at.
HEAD = 4096
# The versions a plain Prefetch record carries in its first four bytes (libscca's
# format notes): 17 Windows XP and 2003, 23 Vista and 7, 26 8 and 8.1, 30 10, 31 11.
PREFETCH_VERSIONS = (17, 23, 26, 30, 31)


# --- what each kind's first bytes say ------------------------------------------
#
# A validator reads at most HEAD bytes from the structure's start and returns
# (state, declared_bytes, detail). It checks fields the format fixes and nothing
# more: "header plausible" is not "a whole, readable structure".

PLAUSIBLE, IMPLAUSIBLE, TRUNCATED, UNKNOWN = "header plausible", "header implausible", "truncated", "unknown"
PAGE_SIZES = {512 << n for n in range(8)}  # 512 to 65536, powers of two


def check_regf(head):
    # Base block: the major version at 0x14 is 1 and the minor at 0x18 is 3 to 6.
    if len(head) < 0x1C:
        return TRUNCATED, None, "the file ends inside the hive's base block"
    major, minor = struct.unpack_from("<II", head, 0x14)
    if major == 1 and 3 <= minor <= 6:
        return PLAUSIBLE, None, "format version 1.%d" % minor
    return IMPLAUSIBLE, None, "major %d, minor %d are not a registry hive version" % (major, minor)


def check_evtx_chunk(head):
    # Chunk header: its own size, at 0x28, is 128; a chunk is 64 KiB.
    if len(head) < 0x2C:
        return TRUNCATED, None, "the file ends inside the chunk header"
    size, = struct.unpack_from("<I", head, 0x28)
    if size == 128:
        return PLAUSIBLE, 65536, "a chunk is 65536 bytes"
    return IMPLAUSIBLE, None, "header size %d, not 128" % size


def check_evtx_file(head):
    # File header: its size, 128, at 0x20; major version 3 at 0x26; chunk count at 0x2A.
    if len(head) < 0x2C:
        return TRUNCATED, None, "the file ends inside the file header"
    size, = struct.unpack_from("<I", head, 0x20)
    major, = struct.unpack_from("<H", head, 0x26)
    chunks, = struct.unpack_from("<H", head, 0x2A)
    if size == 128 and major == 3:
        return PLAUSIBLE, 4096 + chunks * 65536, "%d chunks declared" % chunks
    return IMPLAUSIBLE, None, "header size %d, major version %d" % (size, major)


def check_mam(head):
    # "MAM" 0x04, then the uncompressed size (a Prefetch file is far below 16 MiB).
    if len(head) < 8:
        return TRUNCATED, None, "the file ends inside the 8-byte MAM header"
    size, = struct.unpack_from("<I", head, 4)
    if 0 < size <= 1 << 24:
        return PLAUSIBLE, None, "declared uncompressed size %d" % size
    return IMPLAUSIBLE, None, "declared uncompressed size %d" % size


def check_scca(head):
    # head starts at the version field: the version at 0, "SCCA" at 4, the file size at 0x0C.
    if len(head) < 0x10:
        return TRUNCATED, None, "the file ends inside the Prefetch header"
    version, = struct.unpack_from("<I", head, 0)
    size, = struct.unpack_from("<I", head, 0x0C)
    if version not in PREFETCH_VERSIONS:
        return IMPLAUSIBLE, None, "version %d is not one of %s" % (version, ", ".join(map(str, PREFETCH_VERSIONS)))
    if not 0x54 <= size <= 1 << 24:
        return IMPLAUSIBLE, None, "version %d, declared file size %d" % (version, size)
    return PLAUSIBLE, size, "version %d" % version


def check_pe(head):
    # DOS header: e_lfanew at 0x3C names the "PE\0\0" signature.
    if len(head) < 0x40:
        return TRUNCATED, None, "the file ends inside the DOS header"
    lfanew, = struct.unpack_from("<I", head, 0x3C)
    if lfanew < 0x40:
        return IMPLAUSIBLE, None, "e_lfanew is %d" % lfanew
    if lfanew + 4 > len(head):
        if len(head) < HEAD:
            return TRUNCATED, None, "e_lfanew is %d and the file ends before it" % lfanew
        return UNKNOWN, None, "e_lfanew is %d, beyond the %d bytes examined" % (lfanew, HEAD)
    if head[lfanew:lfanew + 4] == b"PE\x00\x00":
        return PLAUSIBLE, None, "PE signature at +0x%x" % lfanew
    return IMPLAUSIBLE, None, "no PE signature at e_lfanew (+0x%x)" % lfanew


def check_sqlite(head):
    # The 100-byte header: page size at 16 (2 bytes; 1 means 65536), write and read
    # format versions at 18 and 19, file change counter at 24, size in pages at 28,
    # version-valid-for number at 92 (the size in pages can be trusted only when it
    # equals the change counter).
    if len(head) < 100:
        return TRUNCATED, None, "the file ends inside the 100-byte header"
    page, = struct.unpack_from(">H", head, 16)
    page = 65536 if page == 1 else page
    write, read = head[18], head[19]
    if page not in PAGE_SIZES or write not in (1, 2) or read not in (1, 2):
        return IMPLAUSIBLE, None, "page size %d, format versions %d and %d" % (page, write, read)
    counter, pages = struct.unpack_from(">II", head, 24)
    valid_for, = struct.unpack_from(">I", head, 92)
    if pages and counter == valid_for:
        return PLAUSIBLE, pages * page, "%d pages of %d bytes" % (pages, page)
    return PLAUSIBLE, None, "page size %d; the size in pages is not valid for this change counter" % page


def check_mft(head):
    # FILE record: update sequence count at 6 (3 for a 1024-byte record), allocated size at 0x1C.
    if len(head) < 0x20:
        return TRUNCATED, None, "the file ends inside the record header"
    count, = struct.unpack_from("<H", head, 6)
    allocated, = struct.unpack_from("<I", head, 0x1C)
    if count == 3 and allocated == 1024:
        return PLAUSIBLE, 1024, "a 1024-byte record"
    return IMPLAUSIBLE, None, "update sequence count %d, allocated size %d: not the header of a 1024-byte record" % (count, allocated)


def check_indx(head):
    # INDX block: the update sequence count at 6 is 1 plus the block size over 512.
    if len(head) < 8:
        return TRUNCATED, None, "the file ends inside the block header"
    count, = struct.unpack_from("<H", head, 6)
    if count - 1 in (2, 8, 16):
        return PLAUSIBLE, (count - 1) * 512, "update sequence count %d" % count
    return IMPLAUSIBLE, None, "update sequence count %d" % count


def check_pdf(head):
    if len(head) < 8:
        return TRUNCATED, None, "the file ends inside the version marker"
    if re.match(rb"%PDF-\d\.\d", head[:8]):
        return PLAUSIBLE, None, "version marker %s" % head[5:8].decode("ascii")
    return IMPLAUSIBLE, None, "no version marker after %PDF-"


def no_check(_head):
    return UNKNOWN, None, "a signature only: no structural check exists for this kind"


VALIDATORS = {
    "registry hive": check_regf,
    "event log chunk": check_evtx_chunk,
    "event log file": check_evtx_file,
    "compressed prefetch record": check_mam,
    "prefetch record": check_scca,
    "PE header": check_pe,
    "SQLite database": check_sqlite,
    "MFT record": check_mft,
    "NTFS index block": check_indx,
    "PDF": check_pdf,
}


# --- stopping: a signal ends the tool with one JSON answer ------------------------------------------------------------------------------------

class Terminated(BaseException):
    def __init__(self, signum):
        super().__init__(signum)
        self.signum = signum


# GUARD["depth"] above zero holds a signal until the section is over (acted on at the next checkpoint()); GUARD["stopping"] says a stop is
# under way or the answer has left, so a later signal changes nothing.
GUARD = {"depth": 0, "pending": None, "stopping": False}
ANSWER = {"printed": False}
SLICE = {"file": None}     # the slice file while it is being written


def _on_signal(signum, _frame):
    if GUARD["stopping"]:
        return
    if GUARD["depth"]:
        GUARD["pending"] = signum            # a file is being closed or the answer written: finished first, then the stop is raised
        return
    GUARD["stopping"] = True
    raise Terminated(signum)


def checkpoint():
    signum = GUARD["pending"]
    if signum is not None and not GUARD["depth"]:
        GUARD["pending"] = None
        GUARD["stopping"] = True
        raise Terminated(signum)


def emit(answer):
    """The one way an answer leaves: whole, once, and not cut by a signal. A signal that arrives while it is written is held, and once it is
    out a later one changes nothing, so stdout never holds two documents."""
    text = json.dumps(sealed(answer), indent=2)
    GUARD["depth"] += 1
    try:
        if ANSWER["printed"]:
            return
        ANSWER["printed"] = True
        print(text, flush=True)
    finally:
        GUARD["depth"] -= 1
        GUARD["stopping"] = True


def fail(message, **extra):
    abort_pages()               # a page that was being written is dropped with its hidden temporary file, whatever ended the call
    if SLICE["file"] is not None:
        SLICE["file"].discard()
        SLICE["file"] = None
    emit({"error": message, "status": "failed", "parser": PARSER,
          "status_basis": "the call was refused or ended before an answer; nothing in this document is a finding about the evidence", **extra})
    raise SystemExit(1)


def describe(exc):
    return "%s: %s" % (type(exc).__name__, exc)


# --- the arguments ----------------------------------------------------------------------------------------------------------------------------

def read_args():
    try:
        raw = sys.stdin.read(MAX_STDIN + 1)
    except (OSError, ValueError) as exc:
        fail("the arguments could not be read", reason=type(exc).__name__)
    if len(raw) > MAX_STDIN:
        fail("the arguments are larger than %d bytes" % MAX_STDIN)
    try:
        args = json.loads(raw)
    except (ValueError, RecursionError):
        fail("arguments are not valid JSON (or are nested too deeply)")
    if not isinstance(args, dict):
        fail("arguments must be a JSON object")
    return args


def text_arg(args, key):
    value = args.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        fail("%s must be a non-empty string" % key)
    if len(value) > MAX_TEXT:
        fail("%s is longer than %d characters" % (key, MAX_TEXT))
    if "\x00" in value:
        fail("%s holds a NUL character" % key)
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        fail("%s holds a character that is not text (a lone surrogate)" % key)
    return value


def offset_arg(args, key, required):
    if key not in args or args[key] is None:
        if required:
            fail("%s is required: the offset of a hit, as mem_carve gives it" % key)
        return None
    value = args[key]
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < MAX_OFFSET:
        fail("%s must be an integer from 0 to %d" % (key, MAX_OFFSET - 1))
    return value


def parse_args(args):
    allowed = {"path", "kind", "signature_offset", "object_offset", "write_values", "parser", "parser_result", "max_seconds", "examine_bytes"}
    unknown = sorted(k for k in args if k not in allowed)
    if unknown:
        fail("unknown parameter; the parameters are %s" % ", ".join(sorted(allowed)), count=len(unknown))
    path = text_arg(args, "path")
    if not path:
        fail("path is required: the memory image the hit was found in")
    kind = args.get("kind")
    kinds = [name for _sig, name, _cut in SIGNATURES]
    if not isinstance(kind, str) or kind not in kinds:
        fail("kind must be one of mem_carve's kinds: %s" % ", ".join(kinds))
    write_values = args.get("write_values", False)
    if write_values is None:
        write_values = False
    if not isinstance(write_values, bool):
        fail("write_values must be true or false")
    parser, result = args.get("parser"), text_arg(args, "parser_result")
    if (parser is None) != (result is None):
        fail("parser and parser_result go together: the downstream tool and the file its result is in")
    if parser is not None and parser not in PARSERS:
        fail("parser must be one of: %s" % ", ".join(PARSERS))
    seconds = args.get("max_seconds", DEFAULT_SECONDS)
    if isinstance(seconds, bool) or not isinstance(seconds, (int, float)) or seconds != seconds or not MIN_SECONDS <= seconds <= MAX_SECONDS:
        fail("max_seconds must be a number from %d to %d" % (MIN_SECONDS, MAX_SECONDS))
    examine = args.get("examine_bytes", DEFAULT_EXAMINE)
    if isinstance(examine, bool) or not isinstance(examine, int) or not BLOCK <= examine <= MAX_EXAMINE:
        fail("examine_bytes must be an integer from %d to %d" % (BLOCK, MAX_EXAMINE))
    return {"path": path, "kind": kind, "signature_offset": offset_arg(args, "signature_offset", True),
            "object_offset": offset_arg(args, "object_offset", False), "write_values": write_values, "parser": parser, "parser_result": result,
            "seconds": float(seconds), "examine": examine}


def job_dir():
    job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
    return (re.sub(r"[^A-Za-z0-9_.-]", "_", job), Path(out)) if job and out else None


class SliceFile:
    """The slice, written to $OUT/carve_handoff (a directory with mode 0700) as a file with mode 0600, created exclusively under a hidden name
    and placed without replacing an earlier file. Opened by the first block; nothing exists before it."""
    def __init__(self, name):
        job, out = job_dir()
        self.dir, self.name = out / "carve_handoff", name
        self.shown_dir = "store/jobs/%s/out/carve_handoff" % job
        self.tmp, self.fh, self.final = None, None, None

    def write(self, block):
        if self.fh is None:
            self.dir.mkdir(parents=True, exist_ok=True)
            os.chmod(self.dir, 0o700)
            self.tmp = self.dir / (".%s-%s" % (self.name, os.urandom(6).hex()))
            fd = os.open(str(self.tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
            self.fh = os.fdopen(fd, "wb")
        self.fh.write(block)

    def finish(self):
        """Close and place the file; the name an answer may print. An empty slice is written as an empty file."""
        GUARD["depth"] += 1                 # closing the file and giving it its name is finished before a stop is acted on
        try:
            if self.fh is None:
                self.write(b"")
            self.fh.flush()
            os.fsync(self.fh.fileno())
            self.fh.close()
            self.fh = None
            self.final = place_without_replacing(self.tmp, self.dir / self.name)
            self.tmp = None
        finally:
            GUARD["depth"] -= 1
        checkpoint()
        return "%s/%s" % (self.shown_dir, self.final.name)

    def discard(self):
        try:
            if self.fh is not None:
                self.fh.close()
        except OSError:
            pass
        self.fh = None
        if self.tmp is not None:
            try:
                os.unlink(self.tmp)
            except OSError:
                pass
            self.tmp = None

    def stop(self):
        """After a stop: the hidden file, closed, gets a visible name ending in .partial; its name, or None."""
        if self.tmp is None:
            return "%s/%s" % (self.shown_dir, self.final.name) if self.final else None
        try:
            if self.fh is not None:
                self.fh.flush()
                self.fh.close()
                self.fh = None
        except OSError:
            pass
        placed = place_visibly(self.tmp, self.dir / (self.name + ".partial")) if os.path.lexists(self.tmp) else None
        self.tmp = None
        return "%s/%s" % (self.shown_dir, placed.name) if placed else None


# --- reading the image --------------------------------------------------------------------------------------------------------------------

class Image:
    def __init__(self, path):
        self.fd = None
        try:
            self.fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0))
            st = os.fstat(self.fd)
        except OSError as exc:
            if self.fd is not None:
                os.close(self.fd)
            fail("path cannot be opened (%s)" % errno.errorcode.get(exc.errno, "errno %s" % exc.errno))
        if not stat.S_ISREG(st.st_mode):
            os.close(self.fd)
            fail("path is not a regular file (a FIFO, a device or a directory is refused)")
        self.size = st.st_size

    def read(self, offset, length):
        """At most `length` bytes at `offset` (fewer at the end of the file)."""
        if length <= 0 or offset >= self.size:
            return b""
        out = b""
        while len(out) < length:
            piece = os.pread(self.fd, length - len(out), offset + len(out))
            if not piece:
                break
            out += piece
        return out


def deadline_passed(deadline):
    return time.monotonic() >= deadline


# --- the structure checks a slice can fail ---------------------------------------------------------------------------------------------------

def hive_checks(img, start, available, window, deadline):
    """A registry hive's base-block checksum, its two sequence numbers and its chain of bins. (checks, fragmentation, anomalies)."""
    checks, anomalies = [], []
    base = img.read(start, 4096)
    if len(base) < 4096:
        checks.append({"name": "base block", "result": "not checkable", "detail": "the file ends inside the 4096-byte base block"})
        return checks, {"state": "not checkable", "detail": "the base block is not whole"}, anomalies
    words = struct.unpack_from("<127I", base, 0)
    stored, = struct.unpack_from("<I", base, 0x1FC)
    computed = 0
    for w in words:
        computed ^= w
    computed = 0xFFFFFFFE if computed == 0xFFFFFFFF else 1 if computed == 0 else computed
    checks.append({"name": "base block checksum", "result": "pass" if computed == stored else "fail",
                   "detail": "the stored checksum %s the XOR of the first 127 dwords" % ("equals" if computed == stored else "differs from")})
    primary, secondary = struct.unpack_from("<II", base, 4)
    checks.append({"name": "sequence numbers", "result": "pass" if primary == secondary else "fail",
                   "detail": ("the two sequence numbers are equal (%d)" % primary) if primary == secondary else
                             "the sequence numbers differ (%d and %d): the hive was written to while it was copied, and its transaction logs hold the rest" % (primary, secondary)})
    bins_size, = struct.unpack_from("<I", base, 0x28)
    if bins_size == 0 or bins_size % 4096:
        checks.append({"name": "bins size", "result": "fail", "detail": "the hive bins data size is %d, not a positive multiple of 4096" % bins_size})
        return checks, {"state": "not checkable", "detail": "the base block declares no usable size"}, anomalies
    total = 4096 + bins_size
    limit = min(total, window)
    offset, bins, broke = 4096, 0, None
    while offset < limit:
        if bins % 256 == 0 and bins and deadline_passed(deadline):
            return checks, {"state": "not examined to the end", "examined_bytes": offset, "declared_bytes": total, "bins_contiguous": bins,
                            "detail": "the clock ended the chain walk"}, anomalies
        head = img.read(start + offset, 12)
        if len(head) < 12:
            broke = (offset, "the file ends before the bin header")
            break
        sig, rel, size = struct.unpack("<4sII", head)
        if sig != b"hbin" or rel != offset - 4096 or size == 0 or size % 4096 or offset + size > total:
            broke = (offset, "no bin header here: signature %s, offset field %d (expected %d), size field %d" % (sig.hex(), rel, offset - 4096, size))
            break
        offset += size
        bins += 1
    if broke:
        anomalies.append({"where": "bin chain", "offset_in_structure": broke[0], "detail": broke[1]})
        return checks, {"state": "break found", "examined_bytes": broke[0], "declared_bytes": total, "bins_contiguous": bins, "break_at": broke[0],
                        "detail": "the bins stop being adjacent at +%d: what follows in the image is not this hive's next bin" % broke[0]}, anomalies
    if offset < total:
        return checks, {"state": "not examined to the end", "examined_bytes": offset, "declared_bytes": total, "bins_contiguous": bins,
                        "detail": "examine_bytes (%d) ended the chain walk before the declared size" % window}, anomalies
    return checks, {"state": "none seen", "examined_bytes": offset, "declared_bytes": total, "bins_contiguous": bins,
                    "detail": "every bin header up to the declared size is where the chain puts it"}, anomalies


def evtx_file_checks(img, start, chunks, window, deadline):
    """An event log file's chunks, each of which starts with ElfChnk, at 4096 + n * 65536. (fragmentation, anomalies)."""
    anomalies, seen, offset = [], 0, 4096
    total = 4096 + chunks * 65536
    while seen < chunks and offset < window:
        if seen % 64 == 0 and seen and deadline_passed(deadline):
            return {"state": "not examined to the end", "examined_bytes": offset, "declared_bytes": total, "chunks_contiguous": seen,
                    "detail": "the clock ended the chunk walk"}, anomalies
        sig = img.read(start + offset, 8)
        if sig != b"ElfChnk\x00":
            what = "the file ends before the chunk" if len(sig) < 8 else "no ElfChnk signature (found %s)" % sig.hex()
            anomalies.append({"where": "chunk %d" % seen, "offset_in_structure": offset, "detail": what})
            return {"state": "break found", "examined_bytes": offset, "declared_bytes": total, "chunks_contiguous": seen, "break_at": offset,
                    "detail": "chunk %d is not where the header puts it: the chunks stop being adjacent in the image" % seen}, anomalies
        seen += 1
        offset += 65536
    if seen < chunks:
        return {"state": "not examined to the end", "examined_bytes": offset, "declared_bytes": total, "chunks_contiguous": seen,
                "detail": "examine_bytes (%d) ended the chunk walk before the declared chunk count" % window}, anomalies
    return {"state": "none seen", "examined_bytes": offset, "declared_bytes": total, "chunks_contiguous": seen,
            "detail": "every one of the %d declared chunks starts with ElfChnk where the header puts it" % chunks}, anomalies


def evtx_chunk_check(img, start):
    head = img.read(start, 0x200)
    if len(head) < 0x200:
        return {"name": "chunk header checksum", "result": "not examined", "detail": "the file ends inside the first 512 bytes of the chunk"}
    stored, = struct.unpack_from("<I", head, 0x7C)
    computed = zlib.crc32(head[0:0x78] + head[0x80:0x200]) & 0xFFFFFFFF
    return {"name": "chunk header checksum", "result": "pass" if computed == stored else "fail",
            "detail": "the stored CRC-32 %s that of bytes 0-0x77 and 0x80-0x1FF" % ("equals" if computed == stored else "differs from")}


# --- the call ---------------------------------------------------------------------------------------------------------------------------------

def main():
    started = time.monotonic()
    args = read_args()
    p = parse_args(args)
    deadline = started + p["seconds"]
    secret_ok = False
    if p["write_values"]:
        # Slice bytes are written only to a sealed secret output: decided before the image is opened or anything is created.
        if job_dir() is None:
            fail("write_values writes the slice, which is memory content, to a file: it is refused outside a job, where the file would be an "
                 "ordinary one. Run this as job_run tool=carve_handoff (its manifest makes the job secret output). Nothing was written and the "
                 "image was not read.", write_values="refused", written=False)
        if os.environ.get("SECRET_OUTPUT") != "1":
            fail("write_values is refused in a job that was not run as secret output: its file would be sealed as ordinary output. Run this as "
                 "job_run tool=carve_handoff (its manifest makes the job secret output). Nothing was written and the image was not read.",
                 write_values="refused", written=False)
        secret_ok = True
    img = Image(p["path"])
    if img.size == 0:
        fail("the file is empty: there is no hit in it")
    kind, sig_at = p["kind"], p["signature_offset"]
    signature, cut = next((s, c) for s, n, c in SIGNATURES if n == kind)
    if sig_at + len(signature) > img.size or img.read(sig_at, len(signature)) != signature:
        fail("the bytes at signature_offset are not the signature of that kind: the hit is not in this image at that offset, or is of another kind",
             signature_offset=sig_at, kind=kind)
    # Where the structure starts (the rule of mem_carve: the same text, copied).
    object_offset = sig_at
    if kind == "prefetch record":
        object_offset = None
        if sig_at >= 4:
            version, = struct.unpack("<I", img.read(sig_at - 4, 4))
            if version in PREFETCH_VERSIONS:
                object_offset = sig_at - 4
    cut_from = object_offset if object_offset is not None else sig_at
    if kind == "prefetch record" and object_offset is None:
        state, declared, detail = UNKNOWN, None, "the four bytes before SCCA are not a known Prefetch version, so where the structure starts is not established"
    else:
        state, declared, detail = VALIDATORS.get(kind, no_check)(img.read(cut_from, HEAD))
    file_left = max(0, img.size - cut_from)
    wants = cut
    if state == PLAUSIBLE and declared is not None and declared > cut and kind in DECLARED_CAPS:
        wants = min(declared, DECLARED_CAPS[kind])
    available = min(wants, file_left)
    cut_complete = None
    if state == PLAUSIBLE and declared is not None:
        if declared > file_left:
            state = TRUNCATED
            detail += "; the file ends %d bytes after the structure's start, before the %d bytes the header declares" % (file_left, declared)
            cut_complete = False
        elif declared > available:
            cut_complete = False
            detail += "; the header declares %d bytes and the cut keeps the first %d (the image holds the rest)" % (declared, available)
        else:
            cut_complete = True
    out = {"parser": PARSER, "path": shown(p["path"], "path"), "bytes": img.size, "kind": kind, "signature_offset": sig_at,
           "object_offset": object_offset, "cut_from": cut_from, "page_aligned": cut_from % 4096 == 0, "validation": state, "validation_detail": detail}
    if declared is not None:
        out["declared_bytes"] = declared
    out.update({"requested_bytes": wants, "available_bytes": available, "cut_complete": cut_complete})
    if p["object_offset"] is not None:
        out["object_offset_given"] = p["object_offset"]
        out["object_offset_agrees"] = p["object_offset"] == object_offset
    reasons = []

    # Structure checks that a slice can fail, and where the pages stop being adjacent.
    window = min(p["examine"], file_left)
    anomalies_list = []
    structure = {"checks": [], "fragmentation": {"state": "not checkable", "detail": "no check of the pages' adjacency exists for this family: the "
                                                 "validation above is the header only, and a slice can still run into unrelated bytes"}}
    if state in (PLAUSIBLE, TRUNCATED) or kind in ("registry hive", "event log file", "event log chunk"):
        if kind == "registry hive" and state != IMPLAUSIBLE:
            structure["checks"], structure["fragmentation"], anomalies_list = hive_checks(img, cut_from, available, window, deadline)
        elif kind == "event log file" and state == PLAUSIBLE and declared is not None:
            chunks = (declared - 4096) // 65536
            structure["fragmentation"], anomalies_list = evtx_file_checks(img, cut_from, chunks, window, deadline)
        elif kind == "event log chunk" and state != IMPLAUSIBLE:
            structure["checks"] = [evtx_chunk_check(img, cut_from)]
            structure["fragmentation"] = {"state": "not checkable", "detail": "a chunk is checked by its header checksum; its records' adjacency is not examined"}
    if structure["fragmentation"].get("state") == "not examined to the end":
        reasons.append("the chain walk did not reach the end of the structure (%s)" % structure["fragmentation"]["detail"])
    page = LosslessPage("carve_handoff_anomalies", {"path": p["path"], "kind": kind, "at": sig_at}, ANOMALIES_INLINE)
    for row in anomalies_list:
        page.add(sealed(row))
    structure["anomalies"] = page.finish()
    structure["anomalies"]["rows"] = page.page
    out["structure"] = structure

    # The slice: hashed only for a family that cannot be a credential store; bytes written only in a secret job.
    credential = kind in CREDENTIAL_POSSIBLE
    digest = hashlib.sha256() if not credential else None
    slice_info = {"credential_possible": credential, "bytes": available, "sha256": None, "written": False, "file": None}
    sfile = SliceFile("%012x-%s.bin" % (cut_from, kind.replace(" ", "_"))) if secret_ok else None
    SLICE["file"] = sfile
    done, ended = 0, None
    if digest is not None or sfile is not None:
        while done < available:
            if deadline_passed(deadline):
                ended = "the clock"
                break
            block = img.read(cut_from + done, min(BLOCK, available - done))
            if not block:
                break
            if digest is not None:
                digest.update(block)
            if sfile is not None:
                sfile.write(block)
            done += len(block)
    if ended or done < available and (digest is not None or sfile is not None):
        reasons.append("the slice was %s %d of %d bytes: %s" % ("read" if ended else "cut short at", done, available, ended or "the file gave fewer bytes than it had"))
        if sfile is not None:
            slice_info["file"] = sfile.stop()
            slice_info["written"] = False
            slice_info["bytes_written"] = done
        SLICE["file"] = None
    else:
        if digest is not None:
            slice_info["sha256"] = digest.hexdigest()
        if sfile is not None:
            slice_info["file"] = sfile.finish()
            slice_info["written"] = True
            slice_info["bytes_written"] = done
        SLICE["file"] = None
    if credential:
        slice_info["sha256_withheld"] = ("this family can be a credential store (a SAM, SYSTEM or SECURITY hive, a browser database, a keychain): its slice "
                                         "is not hashed, because the digest of a secret is itself a secret-shaped output")
    if not secret_ok:
        slice_info["note"] = "slice bytes are written only with write_values: true, in a job run as secret output"
    out["slice"] = slice_info
    out["secret_values"] = {"contains_secret_values": bool(slice_info["written"]), "note": "the slice is memory content; its file is the only place it is written"}
    out["suggested_parsers"] = {"names": SUGGESTED.get(kind, []),
                                "note": "windows-forensics tools that read this family, if that pack is loaded; this tool calls none of them and does not depend on it"}
    if p["parser"]:
        target = Path(p["parser_result"])
        problem = None
        try:
            fd = os.open(str(target), os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0))
            try:
                st = os.fstat(fd)
            finally:
                os.close(fd)
            if not stat.S_ISREG(st.st_mode):
                problem = "it is not a regular file"
            elif os.path.commonpath([os.path.realpath(target), os.path.realpath(".")]) != os.path.realpath("."):
                problem = "it is outside the run directory: only a declared job input is referenced"
            elif os.path.samefile(target, p["path"]):
                problem = "it is the image itself"
        except (OSError, ValueError) as exc:
            problem = "it cannot be opened (%s)" % (errno.errorcode.get(getattr(exc, "errno", None), type(exc).__name__))
        if problem:
            fail("parser_result cannot be referenced: " + problem)
        out["downstream"] = {"parser": p["parser"], "result": shown(p["parser_result"], "path"), "bytes": st.st_size, "read": False,
                             "note": "a reference to the result of a downstream parser, passed as a declared job input; this tool did not read it, hash it or check "
                                     "that it was made from this slice"}
    out["notes"] = ["A hit is a candidate. The validation is the header's own fields, not a parse; a slice can still run into unrelated bytes, and "
                    "fragmentation says only whether the families it can check stay adjacent in the bytes it examined.",
                    "The cut follows mem_carve's rule (the same constants and checks, copied); a test holds the two equal on the same image."]
    if reasons:
        out["status"] = "partial"
        out["status_basis"] = "; ".join(reasons)
    else:
        out["status"] = "complete"
        out["status_basis"] = ("the hit was checked and its slice %s: the validation and the structure checks are findings about the bytes, whatever they say" %
                               ("written" if slice_info["written"] else "hashed" if slice_info["sha256"] else "left unwritten and unhashed as asked"))
    out = sealed(out)
    out["boundary"] = boundary_summary()
    if BOUNDARY["backstop_replaced"]:
        out["status"] = "partial"
        out["status_basis"] += "; the backstop replaced %d string(s) it found secret-shaped (boundary)" % BOUNDARY["backstop_replaced"]
    emit(out)


def run_guarded():
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, _on_signal)
    try:
        main()
    except SystemExit:
        raise
    except Terminated as stopped:
        kept = [page.shown for page in PAGES if page.placed]
        for page in list(PAGES):
            if not page.placed:
                named = page.keep_partial()
                if named is not None:
                    kept.append(str(named))
        if SLICE["file"] is not None:
            named = SLICE["file"].stop()
            if named:
                kept.append(named)
        emit({"error": "stopped by signal %d before the hit was prepared" % stopped.signum, "status": "failed", "interrupted": True,
              "status_basis": "the tool was stopped by signal %d; nothing it had read is an answer%s" % (
                  stopped.signum, "; files that were being written are kept and named in kept_results (a name ending in .partial was cut by the stop)" if kept else ""),
              "signal": stopped.signum, "parser": PARSER, **({"kept_results": kept} if kept else {})})
        raise SystemExit(128 + stopped.signum)
    except Exception as exc:  # never an empty or clean answer for a failure
        fail("unexpected failure: %s: %s" % (type(exc).__name__, exc))


if __name__ == "__main__":
    code = 0
    try:
        run_guarded()
    except SystemExit as exit_:
        code = exit_.code if isinstance(exit_.code, int) else (0 if exit_.code is None else 1)
    # The answer is out and flushed. Leave here and not through the interpreter's own shutdown, which puts every signal's default action
    # back before it is over: a stop that arrived in that time ended the process by the signal although the one document had been written.
    try:
        sys.stdout.flush()
        sys.stderr.flush()
    except (OSError, ValueError):
        pass
    os._exit(code)
