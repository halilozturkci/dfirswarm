#!/usr/bin/env python3
"""Run capa and FLOSS over one PE or ELF file, if they are installed, and say exactly what each of them said.

Two programs, each started in this recipe's own process group with its output going straight to a file of the recipe's
directory: `capa -j` (capability rule matches) and `floss -j` (recovered strings). The programs are not shipped by the pack
(it declares them as optional), and this recipe does not assume either is present:

    complete      every engine ran, exited 0 and wrote JSON of the shape this recipe reads
    partial       at least one engine produced a usable result and something is missing: an engine that is not installed, that failed,
                  that was stopped at its time limit, or whose JSON had no rules mapping (coverage.json says which and why)
    unsupported   the file is not a PE or an ELF
    failed        no engine produced a usable result

The recipe judges an engine by its exit status and the shape of its output, never by the output file being non-empty. It records each
program's argv and what `--version` printed, copies no string and no matched feature into coverage.json, index.tsv or matches.tsv (the
whole output files hold them, and they can hold credentials), and does not know or claim which release has which capability: a
program that rejects an argument fails visibly, with its stderr kept. Nothing here executes the sample; capa and FLOSS analyse it, and
FLOSS emulates parts of its code inside its own process, which is the program's behaviour and not this recipe's.
"""
import errno
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
import unicodedata
from pathlib import Path

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
# tool's group, and with it the stopped ones that are in it); a carrier's answer says what process_notes() holds only where that carrier's
# own code reads it; the start of the interpreter, before any handler is in, is a window a signal can land in.
import time

try:
    import ctypes
except ImportError:  # pragma: no cover
    ctypes = None

STATE = {"last_word": None}    # what to do, with the signal number, when the tool is stopped by a signal
ACTIVE = []                    # the programs running now
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


def spawn(argv, **kwargs):
    kwargs.setdefault("stdin", subprocess.DEVNULL)
    if sys.platform.startswith("linux") and ctypes is not None:
        kwargs["preexec_fn"] = _die_with_parent
    proc = subprocess.Popen(argv, **kwargs)
    SEEN.add(proc.pid)
    started = _read_ident(proc.pid, "proc" if os.path.isdir("/proc/self") else "libproc")
    if started is not None:
        SEEN_IDENT[proc.pid] = started
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
            return out or b"", err or b"", False
        except subprocess.TimeoutExpired as exc:
            started = True
            out, err = exc.stdout or b"", exc.stderr or b""
    try:
        out, err = proc.communicate(None if started else input, timeout=PIPE_GRACE)
    except subprocess.TimeoutExpired as exc:
        out, err = exc.stdout or b"", exc.stderr or b""
        reap_orphans(_pipe_inodes(proc))
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

def _first_word(signum):
    """The last word of a stop signal that comes before main() has set the recipe's own: one answer that says it was stopped and had produced
    nothing yet. main() replaces it, and installs the handlers again."""
    print(json.dumps({"error": "stopped by signal %d before the recipe had begun its work" % signum, "status": "interrupted",
                      "status_basis": "the recipe was stopped by signal %d before it had begun its work: nothing it read is an answer" % signum,
                      "ok": False, "recipe": "capa-floss", "stopped_by_signal": signum}))
    sys.stdout.flush()


STATE["last_word"] = _first_word
install_signal_handlers()
# the stop handlers are installed here, at module level


# -- new code of the capa-floss recipe --

HERE = os.path.dirname(os.path.abspath(__file__))


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


BUDGET_SECONDS = 3500                     # recipe.json gives this recipe 3600
GRACE_SECONDS = 10                        # a program that outlives its own clock by this much is ended
VERSION_SECONDS = 20
MAX_JSON = 32 << 20                       # an engine's JSON read here: parsed JSON takes up to about twenty-five times its size, so a larger file is kept whole and not read
TSV_ROWS = 1_000_000
EARLIER = re.compile(r"^(capa|floss|coverage)(-\d+)?\.(json|stderr)$|^(matches|index)(-\d+)?\.tsv$")
FLOSS_KINDS = ("static_strings", "stack_strings", "tight_strings", "decoded_strings")
# The engines are programs the pack declares and does not ship; this recipe runs them if they are on PATH and says what they said.
ENGINES = [
    {"id": "capa", "program": "capa", "argv": ["-j"], "seconds": 1500,
     "what": "capability rule matches over features the program extracts from the file; each match is a hypothesis about what code could do"},
    {"id": "floss", "program": "floss", "argv": ["-j"], "seconds": 1900,
     "what": "strings recovered by analysis and emulation, in the program's own modes; recovered strings are derived, not literals at a file offset"},
]
NOT_COVERED = "execution of the sample, reachability or intent of any matched capability, strings or capabilities the engines do not recover, any engine that is not installed"


def describe(exc):
    return "%s: %s" % (type(exc).__name__, getattr(exc, "strerror", None) or str(exc))


def target_of(arg):
    text = open(arg, encoding="utf-8").read() if os.path.isfile(arg) else arg
    target = json.loads(text)
    if not isinstance(target, dict):
        raise ValueError("the target is not a JSON object")
    paths = target.get("paths")
    if not isinstance(paths, list) or not paths or not isinstance(paths[0], str):
        raise ValueError("the target names no path")
    return target, paths[0]


def detect(path):
    """(format or None, why): a PE with its signature where the DOS header points, or an ELF with a class, a byte order and a whole header."""
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as fh:
            head = fh.read(64)
            if head[:2] == b"MZ":
                if len(head) < 0x40:
                    return None, "MZ header is too short to name a PE signature"
                fh.seek(int.from_bytes(head[0x3C:0x40], "little"))
                if fh.read(4) == b"PE\x00\x00":
                    return "PE", "DOS header points to a PE signature"
                return None, "MZ header does not point to a PE signature"
            if head[:4] == b"\x7fELF":
                if len(head) < 6 or head[4] not in (1, 2) or head[5] not in (1, 2):
                    return None, "ELF signature with an unusable class or byte order"
                need = 64 if head[4] == 2 else 52
                if size < need:
                    return None, "ELF signature, and the file is shorter than its header (%d bytes)" % need
                return "ELF", "ELF signature and a whole ELF header"
    except OSError as exc:
        return "unknown", "unreadable, so it cannot be told what it is: %s" % (exc.strerror or exc)
    return None, "no PE or ELF signature (the engines are run on those; Mach-O and raw shellcode are not offered)"


def new_name(out_dir, stem, ext, mode=0o644):
    """A name in `out_dir` that nothing has: `stem.ext`, or `stem-2.ext`, ... The file is created at once, exclusively, so that a result an
    earlier run left in this directory is never opened for writing, let alone replaced."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    for n in range(1, 1000):
        name = "%s%s" % (stem if n == 1 else "%s-%d" % (stem, n), ext)
        try:
            os.close(os.open(os.path.join(out_dir, name), flags, mode))
        except FileExistsError:
            continue
        return name
    raise OSError(errno.EEXIST, "a thousand files of this name already exist in %s" % out_dir)


def version_of(exe, out_dir, seconds=VERSION_SECONDS):
    """(exit code, stdout head, stderr head, timed out) of `exe --version`: its output goes to two files of the recipe's directory and
    is read back 4 KiB at a time, so a program that never stops printing fills a file, not this process's memory."""
    import tempfile
    paths = []
    try:
        for kind in ("out", "err"):
            fd, name = tempfile.mkstemp(prefix=".version-", suffix="." + kind, dir=out_dir)
            os.close(fd)
            paths.append(name)
        rc, timed = run_to_files([exe, "--version"], paths[0], paths[1], seconds)
        heads = []
        for name in paths:
            with open(name, "rb") as fh:
                heads.append(fh.read(4096))
        return rc, heads[0], heads[1], timed
    except OSError as exc:
        return None, b"", describe(exc).encode("utf-8", "replace"), False
    finally:
        for name in paths:
            try:
                os.unlink(name)
            except OSError:
                pass


def shown_text(text, keep):
    """A string an engine printed, withheld whole and then cut to `keep` characters: a cut before the withholding could leave the head of
    a token too short to be recognised as one."""
    return shown_path(cell(text))[:keep]


def shown_key(key):
    return shown_path(cell(str(key)))


def shown_cell(value):
    """One cell of matches.tsv: through the sanitiser, then the backstop."""
    return final_check(shown_path(cell(str(value))))


def first_line(raw):
    for line in raw.decode("utf-8", "replace").splitlines():
        if line.strip():
            return shown_text(line.strip(), 200)
    return None


def read_json(path):
    try:
        if os.path.getsize(path) > MAX_JSON:
            return None, "the output is larger than %d bytes: kept whole, not read here" % MAX_JSON
        with open(path, encoding="utf-8") as fh:
            value = json.load(fh)
    except (OSError, ValueError, RecursionError) as exc:
        return None, "not JSON (%s)" % type(exc).__name__
    return (value, None) if isinstance(value, dict) else (None, "JSON, but not an object")


def judge(engine, rc, timed_out, doc, why):
    """(status, reason, details) from what the program said. Never from the output file being non-empty."""
    if timed_out:
        return "failed", "%s was stopped at its time limit; what it had written is kept" % engine["program"], {}
    if rc is None:
        return "failed", "%s could not be started" % engine["program"], {}
    if rc != 0:
        return "failed", "%s exited with status %d; its stderr is kept" % (engine["program"], rc), {}
    if doc is None and why and why.startswith("the output is larger"):
        return "partial", "%s exited 0; %s, so nothing of it is summarised here" % (engine["program"], why), {}
    if doc is None:
        return "failed", "%s exited 0 and its output is not a readable JSON object: %s" % (engine["program"], why), {}
    if engine["id"] == "capa":
        rules = doc.get("rules")
        if not isinstance(rules, dict):
            return "partial", "capa's JSON has no `rules` mapping, so no match was listed; the whole output is kept", {"keys": sorted(shown_key(k) for k in doc)[:20]}
        meta = doc.get("meta") if isinstance(doc.get("meta"), dict) else {}
        details = {"rules_matched": len(rules), "meta_keys": sorted(shown_key(k) for k in meta)[:20]}
        for key in ("version",):
            if isinstance(meta.get(key), str):
                details["reported_version"] = shown_text(meta[key], 60)
        # Which rule set matched is part of the result: capa names it (meta.analysis.rules, the rule paths it loaded).
        analysis = meta.get("analysis") if isinstance(meta.get("analysis"), dict) else {}
        rule_sets = analysis.get("rules")
        if isinstance(rule_sets, list):
            details["rule_sets"] = [shown_path(cell(str(r))) for r in rule_sets[:20]]
            if len(rule_sets) > 20:
                details["rule_sets_total"] = len(rule_sets)
        else:
            details["rule_sets"] = None
            details["rule_sets_note"] = "capa's JSON does not name the rule set it loaded (meta.analysis.rules)"
        return "complete", "capa exited 0 and wrote a JSON object with a rules mapping", details
    strings = doc.get("strings")
    details = {"keys": sorted(shown_key(k) for k in doc)[:20]}
    analysis = doc.get("analysis") if isinstance(doc.get("analysis"), dict) else {}
    flags = {shown_key(k): v for k, v in analysis.items() if str(k).startswith("enable_") and isinstance(v, bool)}
    if flags:
        details["analysis_enabled"] = dict(sorted(flags.items()))
    if not isinstance(strings, dict):
        return "partial", "floss's JSON has no `strings` mapping, so no string kind was counted; the whole output is kept", details
    details["string_kinds"] = {shown_key(k): (len(v) if isinstance(v, list) else None) for k, v in list(strings.items())[:20]}
    known = [k for k in FLOSS_KINDS if isinstance(strings.get(k), list)]
    if not known:
        return "partial", "floss's `strings` mapping holds none of the string kinds this recipe reads (%s) as a list; the whole output is kept" % ", ".join(FLOSS_KINDS), details
    # A kind whose analysis floss's own flags say was off (analysis.enable_<kind> false, as for a .NET file) was not run: its empty list
    # is not "none found", and only the kinds that ran are counted as read.
    off = [k for k in FLOSS_KINDS if analysis.get("enable_" + k) is False]
    ran = [k for k in known if k not in off]
    if off:
        details["kinds_not_run"] = off
        return "partial", ("floss exited 0 and its analysis flags say %s %s not run (analysis.enable_* false): an empty list of %s is not 'none found'; "
                           "the kinds that ran: %s" % (", ".join(off), "was" if len(off) == 1 else "were", "that kind" if len(off) == 1 else "those kinds",
                                                         ", ".join(ran) or "none")), details
    return "complete", "floss exited 0 and wrote a JSON object whose `strings` mapping holds %s" % ", ".join(known), details


def write_matches(doc, path):
    """matches.tsv from capa's `rules` mapping: rule name, namespace, ATT&CK ids, match count. No matched feature or string is copied."""
    rows = 0
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("rule\tnamespace\tattack_ids\tmatches\n")
        for name, rule in doc["rules"].items():
            if rows >= TSV_ROWS:
                return rows, True
            meta = rule.get("meta") if isinstance(rule, dict) and isinstance(rule.get("meta"), dict) else {}
            attack = meta.get("attack") if isinstance(meta.get("attack"), list) else []
            ids = [str(a.get("id")) for a in attack if isinstance(a, dict) and a.get("id")]
            matches = rule.get("matches") if isinstance(rule, dict) else None
            fh.write("%s\t%s\t%s\t%s\n" % (shown_cell(name), shown_cell(meta.get("namespace", "")), ",".join(shown_cell(i) for i in ids),
                                           len(matches) if isinstance(matches, (list, dict)) else ""))
            rows += 1
    return rows, False


def assemble(state):
    out_dir = state["out_dir"]
    engines = state["engines"]
    errors = list(state["errors"])
    notes, limits = [], []
    for e in engines.values():
        if e["status"] in ("failed", "unavailable"):
            errors.append("%s %s: %s" % (e["id"], e["status"], e["reason"]))
        elif e["status"] == "partial":
            notes.append("%s partial: %s" % (e["id"], e["reason"]))
        if e.get("timed_out"):
            limits.append("%s was stopped at its time limit (%d s)" % (e["id"], e["seconds"]))
    statuses = [e["status"] for e in engines.values()]
    usable = [s for s in statuses if s in ("complete", "partial")]
    if statuses and all(s == "complete" for s in statuses) and not state["errors"]:
        status = "complete"
    elif usable:
        status = "partial"
    else:
        status = "failed"
    # One sentence saying which engine, or which stop of the recipe, decided the status.
    if status == "complete":
        basis = "every engine ran, exited 0 and printed output of the shape the recipe reads (%s)" % ", ".join("%s %s" % (e["id"], e["status"]) for e in engines.values())
    else:
        why = list(state["errors"]) + ["%s %s: %s" % (e["id"], e["status"], e["reason"]) for e in engines.values() if e["status"] != "complete"]
        basis = "; ".join(why) if why else "an engine did not finish"
    coverage = {
        "recipe": "capa-floss",
        "target": state["shown"],
        "format": state["fmt"],
        "status": status,
        "status_basis": basis,
        "covered": "what each engine that is installed wrote about the file, as the engine said it (see engines); a match is a hypothesis, a recovered string is derived",
        "not_covered": NOT_COVERED,
        "engines": {k: {kk: vv for kk, vv in v.items() if kk not in ("seconds",)} for k, v in engines.items()},
        "limits_hit": limits,
        "warnings": notes,
        "errors": errors,
        "sensitive_outputs": [e["file"] for e in engines.values() if e.get("file")],
        "sensitive_note": "capa's explanations and floss's recovered strings can hold credentials: read them by rule, offset and length. coverage.json, index.tsv and matches.tsv copy no string and no matched feature",
    }
    lines = []
    for e in engines.values():
        for key, what in (("file", "%s output, whole, exactly as the program wrote it (status %s)" % (e["id"], e["status"])), ("stderr_file", "what %s said on stderr" % e["id"])):
            name = e.get(key)
            if name and os.path.isfile(os.path.join(out_dir, name)) and os.path.getsize(os.path.join(out_dir, name)):
                lines.append("%s\t%s" % (name, what))
    if state.get("matches") and os.path.isfile(os.path.join(out_dir, state["matches"])):
        lines.append("%s\tcapa rules that matched: name, namespace, ATT&CK ids, match count (no feature or string)" % state["matches"])
    # This run's own receipt is this run's: it is named as such and never as a file an earlier run left.
    lines.append("%s\tthis run's receipt: the status of each engine, what was and was not covered, and the files of this run" % state["coverage_name"])
    lines.append("%s\tthis run's index of its files (this file)" % state["index_name"])
    listed = {l.split("\t", 1)[0] for l in lines}
    try:
        present = sorted(os.listdir(out_dir))
    except OSError:
        present = []
    for name in present:
        if name in listed or not EARLIER.match(name) or not os.path.isfile(os.path.join(out_dir, name)) or os.path.getsize(os.path.join(out_dir, name)) == 0:
            continue
        lines.append("%s\tleft by an earlier run in this directory; kept, and not part of this result" % name)
    coverage["outputs"] = {k: v for k, v in {"matches": state.get("matches"), **{e["id"]: e.get("file") for e in engines.values()}}.items() if v}
    return status, coverage, lines


def receipt_names(out_dir):
    """coverage.json and index.tsv, or, when an earlier run left either in this directory, new names for this run's: the earlier run's
    receipt describes the files it wrote, which are still there, and is never replaced."""
    if not any(os.path.lexists(os.path.join(out_dir, n)) for n in ("coverage.json", "index.tsv")):
        return "coverage.json", "index.tsv"
    return new_name(out_dir, "coverage", ".json"), new_name(out_dir, "index", ".tsv")


def own_dir(path):
    """Create the tool-output directory and return None, or say why it is not used: a symbolic link anywhere on the way (the directory itself,
    or work/ or the agent's directory under it) would send the tables and the private names file somewhere else, and O_NOFOLLOW guards only
    the last name of a file. In a job only the part under $OUT is checked ($OUT is the job service's)."""
    path = Path(path)
    out = os.environ.get("OUT")
    start = len(Path(out).parts) if out and path.parts[:len(Path(out).parts)] == Path(out).parts else 0
    for i in range(max(start, 1), len(path.parts) + 1):
        step = Path(*path.parts[:i])
        if os.path.islink(step):
            return "%s is a symbolic link: refused, nothing written through it" % step
    path.mkdir(parents=True, exist_ok=True)
    return None


def make_out_dir(out_dir):
    """Create the recipe's output directory and return None, or say why it was not: a symbolic link anywhere on the way inside the run
    directory (own_dir) or as the directory itself when it is elsewhere. Nothing is written through a link."""
    absolute = os.path.abspath(out_dir)
    cwd = os.getcwd()
    if absolute == cwd or absolute.startswith(cwd + os.sep):
        return own_dir(Path(os.path.relpath(absolute, cwd)))
    if os.path.islink(absolute):
        return "%s is a symbolic link: refused, nothing written through it" % absolute
    os.makedirs(absolute, exist_ok=True)
    return None


RECEIPT_TMP = []                    # temporary files of a receipt being written: a stop signal removes them before it writes the last receipt


def write_receipt(out_dir, name, text):
    """`text` into this run's own receipt file, whole or not at all: a temporary file beside it, then a rename over it."""
    import tempfile
    fd, tmp = tempfile.mkstemp(prefix=".receipt-", suffix=".tmp", dir=out_dir)
    RECEIPT_TMP.append(tmp)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.chmod(tmp, 0o644)
        os.replace(tmp, os.path.join(out_dir, name))
        RECEIPT_TMP.remove(tmp)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        if tmp in RECEIPT_TMP:
            RECEIPT_TMP.remove(tmp)
        raise


def write_results(state):
    """The receipt and the index, each through the backstop (final_check) as the last step: a field it withholds here or in matches.tsv
    is counted in the receipt, named in its errors, and makes a complete result partial (a fault of this recipe, never of the file)."""
    status, coverage, lines = assemble(state)
    out_dir = state["out_dir"]
    # this pass's count, with what the backstop withheld in matches.tsv (written once): the receipt is rewritten after every engine
    FINAL["fields"] = state.get("matches_withheld", 0)
    lines = ["\t".join(final_check(part) for part in l.split("\t")) for l in lines]
    coverage = final_check(coverage)
    if FINAL["fields"]:
        coverage["withheld_by_final_check"] = FINAL["fields"]
        coverage["errors"].append("the final check withheld %d field(s) the sanitiser had let through: each is given by its length; a fault of this recipe, not of the file" % FINAL["fields"])
        if coverage["status"] == "complete":
            coverage["status"] = status = "partial"
            coverage["status_basis"] = "the final check withheld %d field(s) the sanitiser had let through: a fault of this recipe, never of the file" % FINAL["fields"]
    state["status_basis"] = coverage["status_basis"]
    write_receipt(out_dir, state["coverage_name"], json.dumps(coverage, indent=2) + "\n")
    write_receipt(out_dir, state["index_name"], "".join(l + "\n" for l in lines))
    return status


def run(path, out_dir, fmt, budget):
    existed = os.path.isdir(out_dir)
    refused = make_out_dir(out_dir)
    if refused:
        raise OSError(errno.EPERM, refused)
    if not existed:
        os.chmod(out_dir, 0o700)
    started = time.monotonic()
    sample = os.path.abspath(path)
    state = {"out_dir": out_dir, "fmt": fmt, "shown": shown_path(path), "errors": [], "engines": {}, "matches": None}
    state["coverage_name"], state["index_name"] = receipt_names(out_dir)

    def last_word(signum):
        state["errors"].append("the recipe was stopped by signal %d; the program that was running was ended" % signum)
        for tmp in list(RECEIPT_TMP):
            try:
                os.unlink(tmp)
            except OSError:
                pass
            RECEIPT_TMP.remove(tmp)
        try:
            write_results(state)
        except OSError:
            pass
        print(json.dumps({"ok": False, "status": "interrupted", "status_basis": state.get("status_basis") or "the recipe was stopped by signal %d" % signum,
                          "format": fmt, "coverage": state["coverage_name"], "index": state["index_name"]}))
        sys.stdout.flush()

    STATE["last_word"] = last_word
    install_signal_handlers()
    become_subreaper()
    for engine in ENGINES:
        state["engines"][engine["id"]] = {"id": engine["id"], "program": engine["program"], "status": "failed", "reason": "%s has not run" % engine["program"],
                                          "argv": [engine["program"]] + engine["argv"] + ["<sample>"], "seconds": engine["seconds"], "file": None, "stderr_file": None,
                                          "what": engine["what"]}

    def unfinished():
        state["errors"].append("the recipe was started and has not finished")
        write_results(state)
        state["errors"].pop()

    unfinished()
    try:
        run_engines(state, sample, budget, started, unfinished)
    except Exception as exc:  # noqa: BLE001 - the receipt says what stopped the recipe, never "started and has not finished"
        state["errors"].append("the recipe stopped on an unexpected error (%s): the engines' statuses are as far as it got" % scrub(describe(exc), "text"))
    sweep_orphans()
    final = write_results(state)
    print(json.dumps({"ok": final == "complete", "status": final, "status_basis": state["status_basis"], "format": fmt, "coverage": state["coverage_name"], "index": state["index_name"]}))
    return 0 if final in ("complete", "partial") else 2


def run_engines(state, sample, budget, started, unfinished):
    out_dir = state["out_dir"]
    for engine in ENGINES:
        e = state["engines"][engine["id"]]
        exe = shutil.which(engine["program"])
        if exe is None:
            e.update({"status": "unavailable", "reason": "%s is not on PATH in this image (the pack declares it as optional)" % engine["program"], "installed": False})
            unfinished()
            continue
        e["installed"] = True
        rc, out, err, timed = version_of(exe, out_dir, max(1, min(VERSION_SECONDS, int(budget - (time.monotonic() - started)))))
        sweep_orphans()
        e["version_command"] = {"argv": [engine["program"], "--version"], "exit_code": rc, "first_line": first_line(out) or first_line(err), "timed_out": timed,
                                "note": "what the program printed, not a statement of what this recipe knows about that release"}
        left = budget - (time.monotonic() - started)
        seconds = max(1, min(engine["seconds"], int(left)))
        if left < 1:
            e.update({"status": "failed", "reason": "the recipe's time budget was spent before %s could start" % engine["program"], "timed_out": True})
            unfinished()
            continue
        # what an engine wrote is raw (strings out of the sample, as FLOSS recovers them): mode 0600, as the tools' own raw files are
        e["file"] = new_name(out_dir, engine["id"], ".json", 0o600)
        e["stderr_file"] = new_name(out_dir, engine["id"], ".stderr", 0o600)
        e["seconds"] = seconds
        try:
            rc, timed_out = run_to_files([exe] + engine["argv"] + [sample], os.path.join(out_dir, e["file"]), os.path.join(out_dir, e["stderr_file"]), seconds)
        except OSError as exc:
            # A program on PATH that cannot be executed (not a program, a missing interpreter, no permission: ENOEXEC, ENOENT, EACCES)
            # is a named failure of that engine; the recipe goes on and its receipt says so.
            e.update({"status": "failed", "reason": "%s could not be started: %s" % (engine["program"], scrub(describe(exc), "text")), "exit_code": None, "timed_out": False,
                      "start_error": errno.errorcode.get(exc.errno, "") if exc.errno else type(exc).__name__})
            if drop_if_empty(os.path.join(out_dir, e["stderr_file"])):
                e["stderr_file"] = None
            if drop_if_empty(os.path.join(out_dir, e["file"])):
                e["file"] = None
            unfinished()
            continue
        e["exit_code"], e["timed_out"] = rc, timed_out
        orphans = sweep_orphans()
        doc, why = read_json(os.path.join(out_dir, e["file"]))
        status, reason, details = judge(engine, rc, timed_out, doc, why)
        if orphans:
            e["orphans_ended"] = orphans
            if status == "complete":
                status, reason = "partial", "%s exited 0 and left %d process(es) of its own running, which were ended: what they wrote after it exited is not in its output" % (engine["program"], orphans)
        e.update({"status": status, "reason": reason, "bytes": os.path.getsize(os.path.join(out_dir, e["file"])), **details})
        if engine["id"] == "capa" and status == "complete" and isinstance(doc.get("rules"), dict):
            state["matches"] = new_name(out_dir, "matches", ".tsv")
            before = FINAL["fields"]
            rows, capped = write_matches(doc, os.path.join(out_dir, state["matches"]))
            state["matches_withheld"] = state.get("matches_withheld", 0) + FINAL["fields"] - before
            e["matches_listed"] = rows
            if capped:
                e["status"], e["reason"] = "partial", "capa matched more than %d rules: matches.tsv lists the first %d; capa.json holds them all" % (TSV_ROWS, TSV_ROWS)
        if drop_if_empty(os.path.join(out_dir, e["stderr_file"])):
            e["stderr_file"] = None
        unfinished()


SUBREAPER = [False]


def become_subreaper():
    """On Linux, ask the kernel to make this process the parent of any process an engine leaves behind (PR_SET_CHILD_SUBREAPER = 36), so that
    one that called setsid or double-forked and outlived its parent can still be found and ended. macOS has no such call: there an orphan
    of an engine that exited by itself is not found (the tree is walked, and killed, only while its parent is alive)."""
    if sys.platform.startswith("linux") and ctypes is not None:
        try:
            SUBREAPER[0] = ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) == 0
        except Exception:  # noqa: BLE001
            SUBREAPER[0] = False


def sweep_orphans():
    """End every process still below this one (an engine has exited, so none should be) and reap what can be reaped; how many were ended."""
    if not SUBREAPER[0]:
        return 0
    ended = 0
    for _ in range(4):
        victims = descendants(os.getpid())
        if not victims:
            break
        for pid in victims:
            try:
                os.kill(pid, signal.SIGKILL)
                ended += 1
            except OSError:
                pass
        for pid in victims:
            try:
                os.waitpid(pid, 0)
            except OSError:
                pass
    return ended


def drop_if_empty(path):
    try:
        if os.path.isfile(path) and os.path.getsize(path) == 0:
            os.unlink(path)
            return True
    except OSError:
        pass
    return False


def refuse(message):
    """An answer for a call the recipe did not start: a status and the one sentence that says why."""
    # a detect that could not start answers the third state too (docs/packs.md, a recipe's detect step has three answers)
    print(json.dumps({"applies": "unknown", "why": message, "ok": False, "status": "failed", "status_basis": message, "error": message}))
    return 2


def main(argv):
    if len(argv) < 2 or argv[1] not in ("detect", "run"):
        return refuse("usage: run.py detect --target T | run --target T --out DIR [--seconds N]")
    args = dict(zip(argv[2::2], argv[3::2]))
    if "--target" not in args:
        return refuse("--target is required")
    try:
        _target, path = target_of(args["--target"])
    except (OSError, ValueError, RecursionError) as exc:
        return refuse(scrub(str(exc) if not isinstance(exc, RecursionError) else "the target is nested too deeply"))
    if not os.path.isfile(path):
        return refuse("the target is not a readable file")
    fmt, why = detect(path)
    if argv[1] == "detect":
        if fmt == "unknown":
            print(json.dumps({"applies": "unknown", "format": None, "why": why}))
            return 2
        print(json.dumps({"applies": fmt is not None, "format": fmt, "why": why}))
        return 0 if fmt else 1
    if "--out" not in args:
        return refuse("run needs --out DIR")
    if fmt is None or fmt == "unknown":
        existed = os.path.isdir(args["--out"])
        refused = make_out_dir(args["--out"])
        if refused:
            return refuse("the output directory cannot be written: %s" % scrub(refused, "text"))
        if not existed:
            os.chmod(args["--out"], 0o700)
        name, index = receipt_names(args["--out"])
        if index != "index.tsv":
            os.unlink(os.path.join(args["--out"], index))
        write_receipt(args["--out"], name, json.dumps({"recipe": "capa-floss", "status": "unsupported", "status_basis": why, "why": why, "limits_hit": [], "errors": []}, indent=2))
        print(json.dumps({"ok": False, "status": "unsupported", "status_basis": why, "why": why, "coverage": name}))
        return 2
    budget = BUDGET_SECONDS
    if "--seconds" in args:
        try:
            budget = int(args["--seconds"])
        except ValueError:
            budget = 0
        if not 1 <= budget <= BUDGET_SECONDS:
            return refuse("--seconds is a whole number from 1 to %d" % BUDGET_SECONDS)
    try:
        return run(path, args["--out"], fmt, budget)
    except OSError as exc:
        # an --out that cannot be made or written (a hand run; the harness gives a writable $OUT): said as JSON, never a traceback
        return refuse("the output directory cannot be written: %s" % scrub(describe(exc), "text"))


if __name__ == "__main__":
    sys.exit(main(sys.argv))
