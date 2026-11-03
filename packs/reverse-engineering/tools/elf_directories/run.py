#!/usr/bin/env python3
"""Read what pe_info does not say about an ELF file: its dynamic tags, its symbol tables, its notes and its program headers. Never run the file.

pe_info lists an ELF file's sections, imports (DT_NEEDED) and the dynamic array's library names. This tool reads, through checked ranges:

    program headers   every segment: type, flags, offset, addresses, sizes, alignment; the interpreter; whether the stack is executable
                      (PT_GNU_STACK) and whether RELRO is asked for; a segment that runs past the end of the file is a problem
    dynamic           every entry of the dynamic array, found through PT_DYNAMIC (so a file whose section headers are stripped or damaged
                      is read the same way): the tag, its value, and for NEEDED, SONAME, RPATH, RUNPATH, FILTER and AUXILIARY the string;
                      FLAGS, FLAGS_1, BIND_NOW, SYMBOLIC and TEXTREL are decoded. A file with no DT_NEEDED says zero, and a file with no
                      dynamic array says it has none
    symbols           .dynsym, found through DT_SYMTAB (its length from DT_HASH or DT_GNU_HASH, else from the section header), and
                      .symtab, which only a section header can locate: every row, with its name, value, size, type, binding,
                      visibility and section index
    notes             every note of the PT_NOTE segments (of the SHT_NOTE sections when there is no program header table), with the GNU build
                      ID and the ABI tag read, and the others given by owner, type and size

A table range that runs past the end of the file is a problem and the rows that are there are read; it is never an empty list. A string out
of the file (a library name, a runpath, a symbol name) is evidence the file supplies: it is withheld from the answer when it is shaped like a
token, and the whole is kept only when the caller asks for write_values in a job. Nothing is executed and nothing is verified, and nothing
is named a family, a compiler or a version beyond what the file's own numbers say.
"""
import bisect
import errno
import hashlib
import json
import mmap
import os
import re
import signal
import stat
import struct
import sys
import time
import unicodedata
from pathlib import Path

TOOL = {"name": "elf_directories", "version": 2}
PARSER = "elf_directories/1"
NOTE = ("Static structure only. A dynamic tag, a symbol or a note shows what the file declares to its loader and tools, not what the code does: a "
        "NEEDED entry, an RPATH or an undefined symbol is a declaration, and a build ID is a claim. Read `status`, `problems` and `coverage` first: "
        "they say what was read and what was not. A string out of the file is shown with each backslash written twice and each control character "
        "as \\xNN.")

MAX_LIMIT = 20000                  # the most rows of one table the answer may hold (a longer table is in its file; the rows are withheld as the reading adds them)
DEFAULT_LIMIT = 1000
DEFAULT_SECONDS = 70               # the reading clock; the answer is built after it (HARD_SECONDS below), inside the manifest's 120 s
MAX_SECONDS = 90
MAX_PROBLEMS = 100
NAME_CAP = 4096
MAX_PHDRS = 65536
MAX_SHDRS = 65536
MAX_DYNAMIC = 1 << 16              # entries of the dynamic array
MAX_SYMBOLS = 4_000_000            # rows of one symbol table
MAX_NOTES = 1 << 14
MAX_NOTE_BYTES = 1 << 24           # bytes of one note segment read
SPILL_FLOOR = 100                  # no list in the answer is longer than the larger of `limit` and this: a longer one is in a file, whole
NAME_SHOWN = 512                   # characters of a symbol or library name the answer shows; a longer one is given by its length


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


SHOWN_TARGET = 2048                 # characters of a string out of the file the answer shows; a longer one is given by its length


def describe(exc):
    code = errno.errorcode.get(exc.errno, "") if getattr(exc, "errno", None) else ""
    return shown_path("%s%s: %s" % (type(exc).__name__, " " + code if code else "", getattr(exc, "strerror", None) or str(exc)))


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


def long_text(text, what="text"):
    return "<%s of %d characters: longer than the %d shown, so not shown>" % (what, len(text), SHOWN_TARGET)


def shown_name(text):
    """A name or a path out of the file as it may be printed: one longer than SHOWN_TARGET by its length only (a cut could leave the head
    of a token too short to be recognised as one), any other through shown_path."""
    if not isinstance(text, str):
        return text
    if len(text) > SHOWN_TARGET:
        return long_text(text, "a name")
    return shown_path(text)


# --- the one way out: every key and every value the tool prints or writes passes through shown_answer ------------------------------

# Strings the tool made itself and registered (a page file's path, the names file's path, a CodeView GUID that is not text): only these, and
# only under one of these keys, leave unchanged. Anything else, under any key, is withheld like any string out of the file: a key here
# is never a way round the withholding for a string built from the file's bytes.
SAFE_KEYS = {"build_id", "gnu_build_id", "all_results", "withheld_names_file"}
MADE = set()


def made(text):
    MADE.add(text)
    return text


def safe_made(key, text):
    """What final_check lets through unchanged: a string the tool made and registered, under one of SAFE_KEYS."""
    return key in SAFE_KEYS and text in MADE


class Spill:
    """Where a list of the answer that is longer than `at` goes whole: a file of the paging directory, one row per item; the answer keeps
    the first `at` items and names the file beside the list (`<key>_not_shown`)."""

    def __init__(self, ctx, at):
        self.ctx, self.at, self.n = ctx, at, 0

    def write(self, key, items):
        self.n += 1
        page = LosslessPage("elf_directories-list", [self.ctx.key, "list", self.n], 0)
        for item in items:
            page.add(item if isinstance(item, dict) else {"item": item})
        done = page.finish()
        return {"items": len(items), "shown": self.at, "all_results": made(done["all_results"]) if done.get("all_results") else None,
                "not_written": done.get("not_written"), "note": "the whole list is in the file, one item per line"}


# The answer has a time of its own. Past ANSWER_DEADLINE a string that is not already known to be clean is given by its length (a
# marker no rule changes), which costs nothing and withholds more than the rule would: the answer is then partial and says so. The
# reading's rows are withheld when they are added (LosslessPage), under the reading's clock; this bound is for what is built after it.
START = time.monotonic()
ANSWER_BY = 90                      # seconds after the start of the call by which the answer's strings are withheld (HARD_SECONDS less 15)
ANSWER_MIN = 5                      # the least time the answer has after the reading, however late the reading ended
ANSWER_LATE_CHARS = 200             # only a string longer than this is given by its length when the time has run out: a short one costs next to nothing, and the keys and words of the answer's own frame stay
ANSWER_DEADLINE = [None]
ANSWER_CUT = [0]


def _answer_late(text):
    """True (and counted) when the answer's time has run out and `text` is a long string not known to be clean."""
    deadline = ANSWER_DEADLINE[0]
    if deadline is None or len(text) <= ANSWER_LATE_CHARS or time.monotonic() <= deadline or text in _CLEAN:
        return False
    ANSWER_CUT[0] += 1
    return True


def shown_key(key):
    key = key if isinstance(key, str) else str(key)
    if len(key) > SHOWN_TARGET:
        return long_text(key, "a key")
    if _answer_late(key):
        return "<a key of %d characters: not shown, the answer ran out of time>" % len(key)
    return shown_path(key)


def shown_answer(value, key="", spill=None):
    """Every key and every value, at the boundary: what any writer of this tool (the answer, a table file, a list file, a failure) puts
    out. A string is withheld component by component, a key the same way and given by its length past SHOWN_TARGET; two keys that are
    withheld to the same text are both kept (the second gets ' #2'); bytes are never printed; and in the answer (`spill` given) no list is
    longer than the larger of `limit` and 100 items: a longer one is written whole to a file named beside it."""
    if isinstance(value, str):
        if key in SAFE_KEYS and value in MADE:
            return value
        if _answer_late(value):
            return "<%d characters: not shown, the answer ran out of time>" % len(value)
        return shown_path(value)
    if isinstance(value, bool) or value is None or isinstance(value, float):
        return value
    if isinstance(value, int):
        return shown_number(value)
    if isinstance(value, dict):
        out = {}

        def free(base):
            name, n = base, 1
            while name in out:
                n += 1
                name = "%s #%d" % (base, n)
            return name
        for k, v in value.items():
            name = free(shown_key(k))
            if spill is not None and isinstance(v, (list, tuple)) and len(v) > spill.at:
                out[name] = [shown_answer(x, "", spill) for x in v[:spill.at]]
                # the file named beside the list takes a key no other key holds: a key of the file spelled `<key>_not_shown` is kept apart
                out[free(name + "_not_shown")] = spill.write(name, list(v))
            else:
                out[name] = shown_answer(v, k if isinstance(k, str) else "", spill)
        return out
    if isinstance(value, (list, tuple)):
        return [shown_answer(v, "", spill) for v in value]
    if isinstance(value, (bytes, bytearray, memoryview)):
        return "<%d bytes, not shown>" % len(value)
    return shown_path(str(value))


def build_answer(result, spill=None, seconds=None):
    """The answer through the sanitiser (shown_answer), then through the backstop (final_check). A field the backstop withholds, here
    or in a table or list file written before it, is counted in `withheld_by_final_check`, named in `problems`, and makes a complete
    answer partial: it is a fault of this tool, never of the file. The answer has until ANSWER_BY seconds after the start of the call
    (at least ANSWER_MIN after now, `seconds` after now when given); a string it has no time for is given by its length."""
    now = time.monotonic()
    ANSWER_DEADLINE[0] = now + seconds if seconds else min(max(START + ANSWER_BY, now + ANSWER_MIN), max(START + HARD_SECONDS - 6, now + 1))
    ANSWER_CUT[0] = 0
    _CACHE_ALL[0] = True
    try:
        answer = final_check(shown_answer(result, "", spill), safe_made)
    finally:
        _CACHE_ALL[0] = False
    if ANSWER_CUT[0]:
        note = ("time: the answer ran out of time (%d s after the call began): %d string(s) are given by their length only; the rows already "
                "withheld are all in it; read with a smaller limit or max_seconds, or the whole in a job with write_values" % (ANSWER_BY, ANSWER_CUT[0]))
        if isinstance(answer.get("limits_hit"), list):
            answer["limits_hit"].append(note)
        else:
            answer["limits_hit"] = [note]
        if answer.get("status") == "complete":
            answer["status"], answer["status_basis"] = "partial", note
    if FINAL["fields"]:
        note = ("the final check withheld %d field(s) the sanitiser had let through: each is given by its length; a fault of this tool, "
                "not of the file" % FINAL["fields"])
        answer["withheld_by_final_check"] = FINAL["fields"]
        if isinstance(answer.get("problems"), list):
            answer["problems"].append(note)
        if answer.get("status") == "complete":
            answer["status"], answer["status_basis"] = "partial", note
    return answer


def emit(result, spill=None, indent=2):
    """The last step of every call: the answer (build_answer), written."""
    answer = build_answer(result, spill)
    PRINTING[0] = True
    print(json.dumps(answer, indent=indent))


def fail(message, **extra):
    status = extra.pop("status", "failed")
    basis = extra.pop("status_basis", None)
    answer = {"error": message, "status": status, "status_basis": basis if isinstance(basis, str) and basis else message, "tool": TOOL, **extra}
    if VALUES[0] is not None:
        answer["secret_values"] = VALUES[0].summary()
    emit(answer, None, None)
    raise SystemExit(1)


def resolve_output(out, what="output"):
    """Where `out` really lands, as a path under the run directory; a place outside it, the run directory itself,
    or anything under inputs/ is refused, and in a job so is anything outside $OUT, the one place a job writes.

    A string check is not enough: `work/../inputs/x`, an absolute path and a symlink that points out all name a
    place the tool must not write, and none of them starts with "inputs/". Resolving first and comparing
    directories is what actually holds, and the read-only inputs are the one place extracted bytes must never
    appear -- a later integrity check would report the evidence as modified.
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


# --- lossless paging ------------------------------------------------------------------------------------------------

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


class LosslessPage:
    """The first `limit` rows of a table in the answer; when there are more, the whole table as JSON Lines in a
    file that is created exclusively (under a new name when the name is taken) and named in the answer. A table
    that cannot be written whole says so."""

    def __init__(self, tool, key, limit, tick=None):
        self.tick = tick
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
                self._path = str(self.dir / name)
                self._out = os.fdopen(fd, "w", encoding="utf-8", buffering=1)
                for kept in self.page:
                    self._write(kept)
                return
            self.not_written = "ninety-nine files of this name already exist in %s" % shown_path(str(self.dir))
        except OSError as exc:
            self.not_written = "the file could not be created in %s (%s)" % (shown_path(str(self.dir)), describe(exc))

    def _write(self, row):
        # A row in the file is withheld exactly as the same row is in the answer: the file is read by the same agent.
        # one write for the row and its line break, and the file is line-buffered: a call stopped by the hard limit leaves whole rows
        self._out.write(json.dumps(final_check(shown_answer(row), safe_made)) + "\n")

    @staticmethod
    def _clean(row):
        """The row as it will be written (the sanitiser, then the backstop), kept in the form in which the answer will carry it."""
        _CACHE_ALL[0] = True
        try:
            return final_check(shown_answer(row), safe_made)
        finally:
            _CACHE_ALL[0] = False

    def add(self, row):
        self.total += 1
        if len(self.page) < self.limit:
            # withheld now, while the reading's clock runs, and kept as it will be printed: the answer does not pay for it again
            self.page.append(self._clean(row))
            return
        if self._out is None and self.not_written is None:
            self._open()
        if self._out is not None:
            try:
                self._write(row)
            except OSError as exc:
                self.not_written = "writing the file failed (%s)" % describe(exc)
                self._drop()

    def _drop(self):
        """A file that could not be written whole is removed and not named: a partial table must not look like the whole one."""
        out, self._out = self._out, None
        self.shown = None
        try:
            if out is not None:
                out.close()
        except OSError:
            pass
        try:
            os.unlink(self._path)
        except (OSError, AttributeError):
            pass

    def finish(self):
        result = {"matched": self.total, "returned": len(self.page), "truncated": self.total > len(self.page)}
        if self._out is not None:
            try:
                self._out.flush()
                os.fsync(self._out.fileno())
                self._out.close()
            except OSError as exc:
                self.not_written = "writing the file failed (%s)" % describe(exc)
                self._drop()
            else:
                result["all_results"] = self.shown
                result["all_results_format"] = "JSON Lines, one complete row per line"
        if self.not_written:
            result["not_written"] = shown_path(cell(self.not_written))
        return result


# --- values the answer does not carry ----------------------------------------------------------------------------------

class SecretValuesRefused(Exception):
    pass


class SecretValues:
    """Where a value goes when, and only when, the caller asked for it.

    The secret-safe output pattern (recovery_key_scan is the reference implementation), with one change: a row is
    written as JSON escapes, so that a name that is not UTF-8 cannot raise. Call `add` once per finding with its id,
    its locator and the value. With `enabled` false it writes nothing and `summary()` says so.
    """

    NAME = "elf-directories-values.jsonl"

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
                "file, not a sealed secret output. Run this as job_run tool=elf_directories with "
                "secret_output: true, and ask again there. Nothing was written."
            )
        self.path = Path(self.out) / self.NAME
        self.shown = "store/jobs/%s/out/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", self.job), self.NAME)
        # Created now, before anything is read: a file or a link already at that name is refused by name at once
        # (O_EXCL does not follow a link, a dangling one included), instead of failing, or writing through it,
        # after the read. With nothing withheld it stays an empty file, mode 0600, and the answer says written: 0.
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(str(self.path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileExistsError:
            raise SecretValuesRefused("the values file already exists: %s" % shown_path(str(self.path)))
        except OSError as exc:
            raise SecretValuesRefused("the values file could not be created: %s (%s)" % (shown_path(str(self.path)), describe(exc)))
        self._fh = os.fdopen(fd, "w", encoding="utf-8", buffering=1)

    def add(self, finding_id, locator, value):
        if not self.enabled or self._fh is None:
            return
        self._fh.write(json.dumps({"finding_id": finding_id, **locator, "value": value}) + "\n")
        self.written += 1

    def close(self):
        if self._fh is not None:
            self._fh.flush()
            os.fsync(self._fh.fileno())
            self._fh.close()
            self._fh = None

    def summary(self):
        return {
            "requested": self.enabled,
            "written": self.written,
            "values_file": self.shown if self.enabled else None,
            "contains_secret_values": self.written > 0,
            "format": ("JSON Lines, mode 0600: finding_id, the field and its file offset, value (the whole, unredacted string, and the real name behind a withheld one)") if self.enabled else None,
        }


class Names:
    """The real name behind every name withheld from the answer: a private file (mode 0600, created exclusively, in the
    tool-output directory) written at the moment a name is withheld, whether or not write_values was given, so that no name
    is lost; with write_values the values file holds them as well. The answer names the file."""

    NAME = "elf-directories-withheld-names"

    def __init__(self, values):
        self.values = values
        self.count = 0
        self.written = 0
        self.capped = False
        self._fh = None
        self.shown = None
        self.error = None
        job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
        if out:
            self.dir = Path(out) / "tool-output"
            self.prefix = ("store/jobs/%s/out/tool-output/" % re.sub(r"[^A-Za-z0-9_.-]", "_", job)) if job else str(self.dir) + "/"
        else:
            agent = re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool")
            self.dir = Path("work") / agent / "tool-output"
            self.prefix = str(self.dir) + "/"

    MAX_BYTES = 64 << 20            # the file of withheld names stops growing here; the file read is the source of the rest

    def add(self, real, shown, kind="part_name"):
        self.count += 1
        finding_id = "N%06d" % self.count
        self.values.add(finding_id, {"kind": kind}, real)
        if self.written >= self.MAX_BYTES:
            self.capped = True
            return finding_id
        if self._fh is None and self.error is None:
            try:
                refused = own_dir(self.dir)
                if refused:
                    raise OSError(refused)
                for n in range(1, 100):
                    name = "%s.jsonl" % self.NAME if n == 1 else "%s-%d.jsonl" % (self.NAME, n)
                    try:
                        fd = os.open(str(self.dir / name), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
                    except FileExistsError:
                        continue
                    self._fh = os.fdopen(fd, "w", encoding="utf-8")
                    self.shown = made(self.prefix + name)
                    break
                else:
                    self.error = "ninety-nine files of this name already exist"
            except OSError as exc:
                self.error = "the file could not be created in %s (%s)" % (self.dir, describe(exc))
        if self._fh is not None:
            line = json.dumps({"finding_id": finding_id, "kind": kind, "name": real, "shown": shown}) + "\n"
            self.written += len(line)
            self._fh.write(line)
            self._fh.flush()
        return finding_id

    def close(self):
        if self._fh is not None:
            try:
                self._fh.flush()
                os.fsync(self._fh.fileno())
                self._fh.close()
            except OSError:
                pass
            self._fh = None




# --- the call's bookkeeping ----------------------------------------------------------------------------------------------

class Over(Exception):
    """A budget was reached. The message says which."""


class Unreadable(Exception):
    def __init__(self, kind, reason):
        Exception.__init__(self, reason)
        self.kind, self.reason = kind, reason


class Stop(Exception):
    def __init__(self, status, message, partial=None):
        Exception.__init__(self, message)
        self.status, self.message, self.partial = status, message, partial or {}


class Short(Exception):
    """A read that would run past the end of the file."""


def text_of(value, kind="text"):
    """A string out of a file, as it may be printed: control characters escaped, then the sanitiser (shown_path) over the whole, and one
    longer than SHOWN_TARGET given by its length only. (The shared block's scrub alone, first, would leave a marker where a user-info's
    user name was token-shaped, and no rule after it would read `<marker>:password@` as a user-info.)"""
    text = value if isinstance(value, str) else str(value)
    if len(text) > SHOWN_TARGET:
        return long_text(text, "a string")
    return shown_path(cell(text))


class Ctx:
    def __init__(self, key, cfg, values, seconds):
        self.key = key
        self.cfg = cfg
        self.limit = cfg["limit"]
        self.values = values
        self.deadline = time.monotonic() + seconds
        self.seconds = seconds
        self.problems = []
        self.problems_dropped = 0
        self.limits = []
        self.pages = {}
        self.names = Names(values)
        self.extracted = []
        self.counter = [0]
        self.finding = [0]
        self.used = 0
        self.timed_out = set()

    def expired(self, where):
        if time.monotonic() <= self.deadline:
            return False
        if where in self.timed_out:
            return True
        self.timed_out.add(where)
        self.limit_hit("time: %s stopped at max_seconds (%d); what was read is reported, and the counts are lower bounds" % (where, self.seconds))
        return True

    def problem(self, text):
        # the cap is tested before the text is withheld: a file that raises a problem a million times pays for a hundred
        if len(self.problems) >= MAX_PROBLEMS:
            self.problems_dropped += 1
            return
        text = shown_path(text)
        if text in self.problems:
            return
        self.problems.append(text)

    def limit_hit(self, text):
        text = shown_path(text)
        if text not in self.limits:
            self.limits.append(text)

    def page(self, name):
        if name not in self.pages:
            self.pages[name] = LosslessPage("elf_directories-" + name, [self.key, name], self.limit)
        return self.pages[name]

    def next_finding(self, letter):
        self.finding[0] += 1
        return "%s%06d" % (letter, self.finding[0])

    def spend(self, n, what):
        self.used += n
        if self.used > self.cfg["max_total_bytes"]:
            raise Over("%s: the structures read together passed max_total_bytes (%d); the rest of this call reads no more of them" % (what, self.cfg["max_total_bytes"]))


TOKEN_BYTES = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_+%-")
LEADING_RUN = re.compile(r"[A-Za-z0-9_+%-]+")


def run_before(img, at, utf16=False):
    """The token characters of the file just before offset `at` (UTF-16 code units when `utf16`), at most 256 of them."""
    out, p = [], at
    while len(out) < 256:
        if utf16:
            if p < 2 or img.mm[p - 1] != 0 or img.mm[p - 2] not in TOKEN_BYTES:
                break
            out.append(chr(img.mm[p - 2]))
            p -= 2
        else:
            if p < 1 or img.mm[p - 1] not in TOKEN_BYTES:
                break
            out.append(chr(img.mm[p - 1]))
            p -= 1
    return "".join(reversed(out))


def shown_at(ctx, text, at, utf16=False, kind="names"):
    """A string the file holds at offset `at`, as it may be printed. A string whose address points into the middle of a run of token
    characters (a name read a byte or a field late) is the tail of that run: the run is tested whole, and when the whole is shaped like a
    token the string's head (its leading run, with the random-looking pieces joined to it by `/`: the shared block's growth across `/`)
    is withheld. The string itself always goes through the sanitiser whole, head included (so that `<head>:password@host` is still a
    user-info and a JWT still a JWT); what of the head the sanitiser left as it is, is then withheld."""
    shown = text_of(text, kind)
    img = getattr(ctx, "img", None)
    lead = LEADING_RUN.match(text) if text else None
    if img is not None and lead and at is not None and 0 < at <= img.size and len(text) <= SHOWN_TARGET:
        before = run_before(img, at, utf16)
        if before and (token_shaped(before + lead.group()) or TOKEN_HEAD.search(before + lead.group())):
            end = lead.end()
            while end < len(text) - 1 and text[end] == "/":
                piece = re.match(r"[A-Za-z0-9_+%-]+={0,2}", text[end + 1:])
                if not piece or not _randomish(piece.group()):
                    break
                end += 1 + piece.end()
            k = 0
            while k < min(len(shown), end) and shown[k] == text[k]:
                k += 1
            if k:
                shown = _withheld("token-shaped text", k, kind) + shown[k:]
    return shown


NAME_KINDS = {"needed", "soname", "rpath", "runpath", "filter", "auxiliary", "interpreter", "symbol_name", "note_owner", "section_name"}


def show(ctx, what, text, at, finding=None, complete=True):
    """A string out of the file as it may be printed (shown_at); the whole goes to the values file when it was asked for. A name longer than
    NAME_SHOWN is given by its length only (no linker writes one that long, and a file that holds thousands of them must not cost the
    sanitiser a pass over each)."""
    limit = NAME_SHOWN if what in NAME_KINDS else SHOWN_TARGET
    if not complete and text:
        # the string was cut where it was read (no terminator within its table or NAME_CAP bytes): what was seen is a lower bound, and the answer is partial
        ctx.problem("a %s at file offset %s has no terminator within its table or %d bytes: it was cut there, and the length shown is a lower bound" % (what.replace("_", " "), at if at is not None else "unknown", NAME_CAP))
    if not complete and len(text) > limit:
        shown = "<a string of at least %d characters, cut where it was read: longer than the %d shown, so not shown>" % (len(text), limit)
    elif what in NAME_KINDS and len(text) > NAME_SHOWN:
        shown = "<a name of %d characters: longer than the %d shown, so not shown>" % (len(text), NAME_SHOWN)
    else:
        shown = shown_at(ctx, text, at)
    if shown != cell(text):
        ctx.names.add(text, shown, what)
    if finding is not None:
        ctx.values.add(finding, {"field": what, "file_offset": at}, text)
    return shown


class Image:
    def __init__(self, mm):
        self.mm = mm
        self.size = len(mm)

    def unpack(self, fmt, at):
        n = struct.calcsize(fmt)
        if at < 0 or at + n > self.size:
            raise Short("%d byte(s) at offset %d run past the end of the file (%d bytes)" % (n, at, self.size))
        return struct.unpack_from(fmt, self.mm, at)

    def cstr(self, at, end=None, cap=NAME_CAP):
        """(bytes, complete): the C string at `at`, read no further than `end` or `cap` bytes."""
        end = self.size if end is None else min(end, self.size)
        if at < 0 or at >= end:
            return None, False
        stop = min(end, at + cap)
        nul = self.mm.find(b"\x00", at, stop)
        if nul >= 0:
            return bytes(self.mm[at:nul]), True
        return bytes(self.mm[at:stop]), False


MACHINES = {2: "SPARC", 3: "i386", 4: "m68k", 8: "MIPS", 20: "PowerPC", 21: "PowerPC64", 22: "S390", 40: "ARM", 42: "SuperH", 43: "SPARC V9", 50: "IA-64",
            62: "x86-64", 183: "AArch64", 243: "RISC-V", 247: "BPF", 258: "LoongArch"}
TYPES = {0: "NONE", 1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}
OS_ABI = {0: "System V", 1: "HP-UX", 2: "NetBSD", 3: "GNU/Linux", 6: "Solaris", 9: "FreeBSD", 12: "OpenBSD", 97: "ARM EABI", 255: "standalone"}
PT = {0: "NULL", 1: "LOAD", 2: "DYNAMIC", 3: "INTERP", 4: "NOTE", 5: "SHLIB", 6: "PHDR", 7: "TLS", 0x6474e550: "GNU_EH_FRAME", 0x6474e551: "GNU_STACK",
      0x6474e552: "GNU_RELRO", 0x6474e553: "GNU_PROPERTY", 0x65041580: "PAX_FLAGS"}
DT = {0: "NULL", 1: "NEEDED", 2: "PLTRELSZ", 3: "PLTGOT", 4: "HASH", 5: "STRTAB", 6: "SYMTAB", 7: "RELA", 8: "RELASZ", 9: "RELAENT", 10: "STRSZ", 11: "SYMENT",
      12: "INIT", 13: "FINI", 14: "SONAME", 15: "RPATH", 16: "SYMBOLIC", 17: "REL", 18: "RELSZ", 19: "RELENT", 20: "PLTREL", 21: "DEBUG", 22: "TEXTREL",
      23: "JMPREL", 24: "BIND_NOW", 25: "INIT_ARRAY", 26: "FINI_ARRAY", 27: "INIT_ARRAYSZ", 28: "FINI_ARRAYSZ", 29: "RUNPATH", 30: "FLAGS",
      32: "PREINIT_ARRAY", 33: "PREINIT_ARRAYSZ", 0x6ffffef5: "GNU_HASH", 0x6ffffff0: "VERSYM", 0x6ffffff9: "RELACOUNT", 0x6ffffffa: "RELCOUNT",
      0x6ffffffb: "FLAGS_1", 0x6ffffffc: "VERDEF", 0x6ffffffd: "VERDEFNUM", 0x6ffffffe: "VERNEED", 0x6fffffff: "VERNEEDNUM",
      0x7ffffffd: "AUXILIARY", 0x7fffffff: "FILTER"}
STRING_TAGS = {1: "needed", 14: "soname", 15: "rpath", 29: "runpath", 0x7ffffffd: "auxiliary", 0x7fffffff: "filter"}
DT_FLAGS = [(0x1, "ORIGIN"), (0x2, "SYMBOLIC"), (0x4, "TEXTREL"), (0x8, "BIND_NOW"), (0x10, "STATIC_TLS")]
DT_FLAGS_1 = [(0x1, "NOW"), (0x2, "GLOBAL"), (0x4, "GROUP"), (0x8, "NODELETE"), (0x10, "LOADFLTR"), (0x20, "INITFIRST"), (0x40, "NOOPEN"), (0x80, "ORIGIN"),
              (0x100, "DIRECT"), (0x200, "TRANS"), (0x400, "INTERPOSE"), (0x800, "NODEFLIB"), (0x1000, "NODUMP"), (0x2000, "CONFALT"), (0x4000, "ENDFILTEE"),
              (0x8000, "DISPRELDNE"), (0x10000, "DISPRELPND"), (0x20000, "NODIRECT"), (0x40000, "IGNMULDEF"), (0x80000, "NOKSYMS"), (0x100000, "NOHDR"),
              (0x200000, "EDITED"), (0x400000, "NORELOC"), (0x800000, "SYMINTPOSE"), (0x1000000, "GLOBAUDIT"), (0x2000000, "SINGLETON"), (0x4000000, "STUB"),
              (0x8000000, "PIE")]
SYM_TYPES = {0: "NOTYPE", 1: "OBJECT", 2: "FUNC", 3: "SECTION", 4: "FILE", 5: "COMMON", 6: "TLS", 10: "GNU_IFUNC"}
SYM_BINDS = {0: "LOCAL", 1: "GLOBAL", 2: "WEAK", 10: "GNU_UNIQUE"}
SYM_VIS = {0: "DEFAULT", 1: "INTERNAL", 2: "HIDDEN", 3: "PROTECTED"}
SHT_SYMTAB, SHT_DYNAMIC, SHT_NOTE, SHT_DYNSYM, SHT_STRTAB = 2, 6, 7, 11, 3

READ = ["the ELF header (with the extended counts in section header 0 when the header says so) and the program header table",
        "the dynamic array through PT_DYNAMIC (through an SHT_DYNAMIC section when there is no program header table): every tag and its value, the strings of NEEDED, SONAME, RPATH, RUNPATH, FILTER and AUXILIARY, and FLAGS, FLAGS_1, BIND_NOW, SYMBOLIC and TEXTREL decoded",
        ".dynsym (through DT_SYMTAB and its length from DT_HASH or DT_GNU_HASH, else the section header) and .symtab (through its section header): every row",
        "the notes of the PT_NOTE segments (the SHT_NOTE sections when there is no program header table): owner, type, size; the GNU build ID and ABI tag by value"]
NOT_READ = ["sections, imports by name and versions (pe_info reads the sections and the NEEDED names)", "the contents of a note other than the GNU build ID and the ABI tag",
            "relocations, symbol versions, string and data tables other than the ones named above, and DWARF", "a signature or a hash of the file: nothing is verified",
            "anything about the code: what a symbol, an initialiser or an entry point does"]


def machine_name(value):
    return MACHINES.get(value, hex(value))


def decode_bits(value, table):
    return [name for bit, name in table if value & bit]


class Elf:
    """The header facts the readers need: the byte order, the widths, the segments and sections, and the file-offset mapping of an address."""

    def __init__(self, img):
        self.img = img
        self.wide = False
        self.end = "<"
        self.phdrs = []        # dicts
        self.shdrs = []        # dicts, or [] when absent or unreadable
        self.loads = []        # (vaddr, filesz, offset) of PT_LOAD with file bytes, sorted by vaddr

    def u(self, fmt, at):
        return self.img.unpack(self.end + fmt, at)

    def to_offset(self, addr):
        """The file offset an address maps to through a PT_LOAD that holds file bytes there, and the end of those bytes; or None."""
        starts = [l[0] for l in self.loads]
        i = bisect.bisect_right(starts, addr) - 1
        while i >= 0:
            vaddr, filesz, offset = self.loads[i]
            if vaddr <= addr < vaddr + filesz:
                at = offset + (addr - vaddr)
                return (at, min(offset + filesz, self.img.size)) if at < self.img.size else None
            if vaddr + filesz <= addr and i < len(self.loads) - 1 and self.loads[i + 1][0] > addr:
                break
            i -= 1
        return None


def parse_headers(img, ctx):
    """The ELF header, the program headers and the section headers (when they are readable). Raises Stop when the file is not usable."""
    out = {"format": "ELF"}
    if img.size < 16:
        raise Stop("failed", "shorter than an ELF identification (16 bytes): the file is %d bytes" % img.size, out)
    ident = bytes(img.mm[:16])
    cls, data, version = ident[4], ident[5], ident[6]
    if cls not in (1, 2):
        raise Stop("failed", "EI_CLASS is %d, neither ELFCLASS32 (1) nor ELFCLASS64 (2)" % cls, out)
    if data not in (1, 2):
        raise Stop("failed", "EI_DATA is %d, neither ELFDATA2LSB (1) nor ELFDATA2MSB (2)" % data, out)
    elf = Elf(img)
    elf.wide = cls == 2
    elf.end = "<" if data == 1 else ">"
    out["bits"] = 64 if elf.wide else 32
    out["byte_order"] = "little" if data == 1 else "big"
    out["os_abi"] = OS_ABI.get(ident[7], ident[7])
    if version != 1:
        ctx.problem("EI_VERSION is %d, not 1 (EV_CURRENT)" % version)
    need = 64 if elf.wide else 52
    if img.size < need:
        raise Stop("failed", "shorter than an ELF%d header (%d bytes): the file is %d bytes" % (out["bits"], need, img.size), out)
    fields = elf.u("HHIQQQIHHHHHH" if elf.wide else "HHIIIIIHHHHHH", 16)
    e_type, e_machine, _ver, entry, phoff, shoff, flags, ehsize, phentsize, phnum, shentsize, shnum, shstrndx = fields
    out.update({"type": TYPES.get(e_type, hex(e_type)), "machine": machine_name(e_machine), "entry": hex(entry), "flags": hex(flags)})
    want_ph, want_sh = (56, 64) if elf.wide else (32, 40)
    # Section header 0 carries the real counts when the header's fields hold the escape values (PN_XNUM, SHN_XINDEX).
    sh0 = None
    if shoff and (phnum == 0xFFFF or shnum == 0 or shstrndx == 0xFFFF) and shoff + want_sh <= img.size and shentsize == want_sh:
        sh0 = read_shdr(elf, shoff)
    if phnum == 0xFFFF:
        if sh0:
            phnum = sh0["info"]
        else:
            ctx.problem("e_phnum is 0xFFFF (the extended count) and section header 0 could not be read: the program header count is unknown")
            phnum = 0
    if shnum == 0 and shoff and sh0:
        shnum = sh0["size"]
    if shstrndx == 0xFFFF and sh0:
        shstrndx = sh0["link"]
    out["program_headers_declared"] = phnum
    out["section_headers_declared"] = shnum
    # --- program headers
    if phnum:
        if phentsize != want_ph:
            ctx.problem("e_phentsize is %d, not %d: the program headers are not read" % (phentsize, want_ph))
        elif phoff == 0 or phoff >= img.size:
            ctx.problem("the program header table (%d entries) is at offset %d, outside the file (%d bytes)" % (phnum, phoff, img.size))
        else:
            fit = (img.size - phoff) // phentsize
            if phnum > fit:
                ctx.problem("the program header table declares %d entries at offset %d; the file holds room for %d: the rest are not read" % (phnum, phoff, fit))
            if min(phnum, fit) > MAX_PHDRS:
                ctx.limit_hit("the program header table declares %d entries: the first %d are read" % (phnum, MAX_PHDRS))
            for i in range(min(phnum, fit, MAX_PHDRS)):
                if i % 1024 == 0 and ctx.expired("the program headers"):
                    break
                at = phoff + i * phentsize
                if elf.wide:
                    p_type, p_flags, off, vaddr, paddr, filesz, memsz, align = elf.u("IIQQQQQQ", at)
                else:
                    p_type, off, vaddr, paddr, filesz, memsz, p_flags, align = elf.u("IIIIIIII", at)
                elf.phdrs.append({"index": i, "type": p_type, "flags": p_flags, "offset": off, "vaddr": vaddr, "paddr": paddr, "filesz": filesz, "memsz": memsz, "align": align})
    # --- section headers
    out["section_headers"] = "absent" if not shoff or shnum == 0 else "declared"
    if shoff and shnum:
        if shentsize != want_sh:
            ctx.problem("e_shentsize is %d, not %d: the section headers are not read (what needs them, .symtab, is not read)" % (shentsize, want_sh))
            out["section_headers"] = "unreadable"
        elif shoff >= img.size or shoff + shentsize > img.size:
            ctx.problem("the section header table (%d entries) is at offset %d, outside the file (%d bytes): what needs it, .symtab, is not read" % (shnum, shoff, img.size))
            out["section_headers"] = "unreadable"
        else:
            fit = (img.size - shoff) // shentsize
            if shnum > fit:
                ctx.problem("the section header table declares %d entries at offset %d; the file holds room for %d" % (shnum, shoff, fit))
                out["section_headers"] = "truncated"
            if min(shnum, fit) > MAX_SHDRS:
                ctx.limit_hit("the section header table declares %d entries: the first %d are read" % (shnum, MAX_SHDRS))
            for i in range(min(shnum, fit, MAX_SHDRS)):
                if i % 1024 == 0 and ctx.expired("the section headers"):
                    break
                row = read_shdr(elf, shoff + i * shentsize)
                row["index"] = i
                elf.shdrs.append(row)
            if out["section_headers"] == "declared":
                out["section_headers"] = "readable"
    for p in elf.phdrs:
        if p["type"] == 1 and p["filesz"]:
            if p["offset"] >= img.size:
                continue
            elf.loads.append((p["vaddr"], p["filesz"], p["offset"]))
    elf.loads.sort()
    return out, elf


def read_shdr(elf, at):
    if elf.wide:
        name, typ, flags, addr, off, size, link, info, align, entsize = elf.u("IIQQQQIIQQ", at)
    else:
        name, typ, flags, addr, off, size, link, info, align, entsize = elf.u("IIIIIIIIII", at)
    return {"name": name, "type": typ, "flags": flags, "addr": addr, "offset": off, "size": size, "link": link, "info": info, "align": align, "entsize": entsize}


def flags_text(flags):
    return ("R" if flags & 4 else "-") + ("W" if flags & 2 else "-") + ("X" if flags & 1 else "-")


def read_program_headers(img, elf, ctx, out):
    table = ctx.page("program_headers")
    interp = None
    stack, relro = None, False
    for p in elf.phdrs:
        if ctx.expired("the program headers"):
            break
        row = {"index": p["index"], "type": PT.get(p["type"], hex(p["type"])), "flags": flags_text(p["flags"]), "offset": hex(p["offset"]), "vaddr": hex(p["vaddr"]),
               "paddr": hex(p["paddr"]), "filesz": p["filesz"], "memsz": p["memsz"], "align": p["align"]}
        if p["type"] not in (0, 6) and p["filesz"] and (p["offset"] > img.size or p["offset"] + p["filesz"] > img.size):
            ctx.problem("segment %d (%s) runs past the end of the file: offset %d + %d bytes, file %d bytes" % (p["index"], PT.get(p["type"], hex(p["type"])), p["offset"], p["filesz"], img.size))
            row["past_end_of_file"] = True
        if p["filesz"] > p["memsz"] and p["type"] == 1:
            ctx.problem("segment %d (LOAD) has p_filesz %d greater than p_memsz %d" % (p["index"], p["filesz"], p["memsz"]))
        if p["align"] and (p["align"] & (p["align"] - 1)):
            ctx.problem("segment %d has p_align %d, not a power of two" % (p["index"], p["align"]))
        if p["type"] == 3 and interp is None:
            raw, complete = img.cstr(p["offset"], min(img.size, p["offset"] + p["filesz"]) if p["filesz"] else None)
            if raw is not None:
                interp = show(ctx, "interpreter", raw.decode("utf-8", "replace"), p["offset"], complete=complete)
                if not complete:
                    ctx.problem("the interpreter path has no terminator within its segment")
        if p["type"] == 0x6474e551:
            stack = bool(p["flags"] & 1)
        if p["type"] == 0x6474e552:
            relro = True
        table.add(row)
    out["program_headers"] = {"table": "program_headers", "listed": len(elf.phdrs)}
    out["interpreter"] = interp
    out["stack_executable"] = stack
    out["gnu_relro"] = relro
    if stack is None and elf.phdrs:
        out["stack_executable_note"] = "no PT_GNU_STACK segment: the loader's default for the architecture applies, and this tool does not say what it is"


def find_dynamic(elf, ctx):
    """(file offset, byte length available, source) of the dynamic array, or None."""
    dyn = [p for p in elf.phdrs if p["type"] == 2]
    if dyn:
        p = dyn[0]
        if len(dyn) > 1:
            ctx.problem("%d PT_DYNAMIC segments: the first is read" % len(dyn))
        if p["offset"] >= elf.img.size:
            ctx.problem("PT_DYNAMIC points at offset %d, outside the file (%d bytes)" % (p["offset"], elf.img.size))
            return "unreadable"
        return p["offset"], min(p["filesz"] or elf.img.size, elf.img.size - p["offset"]), "PT_DYNAMIC"
    for s in elf.shdrs:
        if s["type"] == SHT_DYNAMIC and s["offset"] < elf.img.size:
            return s["offset"], min(s["size"], elf.img.size - s["offset"]), "SHT_DYNAMIC section"
    return None


def read_dynamic(img, elf, ctx, out):
    found = find_dynamic(elf, ctx)
    if found is None:
        out["dynamic"] = {"present": False, "note": "no PT_DYNAMIC segment and no SHT_DYNAMIC section: a static file, or a file with its dynamic array removed; this tool cannot tell which"}
        return None
    if found == "unreadable":
        out["dynamic"] = {"present": True, "status": "unreadable"}
        return None
    at, avail, source = found
    step = 16 if elf.wide else 8
    entries, terminated = [], False
    for i in range(MAX_DYNAMIC + 1):
        pos = at + i * step
        if (i + 1) * step > avail:
            break
        if i == MAX_DYNAMIC:
            ctx.limit_hit("the dynamic array holds more than %d entries: the first %d are read" % (MAX_DYNAMIC, MAX_DYNAMIC))
            break
        if ctx.expired("the dynamic array"):
            break
        tag, val = elf.u("qQ" if elf.wide else "iI", pos)
        entries.append((tag & 0xFFFFFFFFFFFFFFFF if tag < 0 else tag, val, pos))
        if tag == 0:
            terminated = True
            break
    if not terminated:
        ctx.problem("the dynamic array (%s, %d bytes at offset %d) has no DT_NULL terminator within %s: %d entries are read" % (
            source, avail, at, "the segment" if source == "PT_DYNAMIC" else "the section", len(entries)))
    tags = {}
    for tag, val, _pos in entries:
        tags.setdefault(tag, val)
    strtab_addr, strsz = tags.get(5), tags.get(10)
    str_base = str_end = None
    if strtab_addr is not None:
        mapped = elf.to_offset(strtab_addr)
        if mapped is None:
            for s in elf.shdrs:
                if s["type"] == SHT_STRTAB and s["addr"] == strtab_addr and s["offset"] < img.size:
                    mapped = (s["offset"], min(s["offset"] + s["size"], img.size))
                    break
        if mapped is None:
            ctx.problem("DT_STRTAB (address 0x%x) is not mapped by any PT_LOAD segment that holds file bytes: the strings of the dynamic array are not read" % strtab_addr)
        else:
            str_base = mapped[0]
            str_end = mapped[1] if strsz is None else min(mapped[1], mapped[0] + strsz)
    elif any(t in STRING_TAGS for t, _v, _p in entries):
        ctx.problem("the dynamic array names strings but has no DT_STRTAB: they are not read")
    table = ctx.page("dynamic")
    strings = {name: [] for name in STRING_TAGS.values()}
    for index, (tag, val, pos) in enumerate(entries):
        row = {"index": index, "tag": DT.get(tag, hex(tag)), "tag_value": hex(tag), "value": hex(val)}
        kind = STRING_TAGS.get(tag)
        if kind is not None and str_base is not None:
            if val >= (str_end - str_base):
                ctx.problem("dynamic entry %d (%s): the string offset %d is outside the string table (%d bytes)" % (index, DT.get(tag), val, str_end - str_base))
            else:
                raw, complete = img.cstr(str_base + val, str_end)
                if raw is not None:
                    if not complete:
                        ctx.problem("dynamic entry %d (%s): the string has no terminator within the string table or %d bytes" % (index, DT.get(tag), NAME_CAP))
                    finding = ctx.next_finding("D")
                    row["string"] = show(ctx, kind, raw.decode("utf-8", "replace"), str_base + val, finding, complete=complete)
                    row["finding_id"] = finding
                    strings[kind].append(row["string"])
        elif tag == 30:
            row["decoded"] = decode_bits(val, DT_FLAGS)
        elif tag == 0x6ffffffb:
            row["decoded"] = decode_bits(val, DT_FLAGS_1)
        table.add(row)
    flags, flags1 = tags.get(30, 0), tags.get(0x6ffffffb, 0)
    info = {"present": True, "source": source, "offset": at, "entries": len(entries), "terminated": terminated, "table": "dynamic",
            "needed": strings["needed"], "needed_count": len(strings["needed"]), "soname": strings["soname"][0] if strings["soname"] else None,
            "rpath": strings["rpath"], "runpath": strings["runpath"], "filter": strings["filter"], "auxiliary": strings["auxiliary"],
            "flags": decode_bits(flags, DT_FLAGS), "flags_1": decode_bits(flags1, DT_FLAGS_1),
            "bind_now": bool(24 in tags or flags & 8 or flags1 & 1), "symbolic": bool(16 in tags or flags & 2), "textrel": bool(22 in tags or flags & 4)}
    if str_base is None and strings["needed"] == [] and any(t == 1 for t, _v, _p in entries):
        info["needed_note"] = "the file has NEEDED entries; their names could not be read (see problems)"
    out["dynamic"] = info
    return {"tags": tags, "str_base": str_base, "str_end": str_end}


CHUNK_WORDS = 65536                # words of a hash table read between two looks at the clock


def gnu_hash_symbols(img, elf, ctx, start, avail):
    """(count, floor) for a DT_GNU_HASH table: the symbol count it implies (the highest chain index reached + 1) or None when it implies none,
    and the table's own lower bound (symoffset: the symbols before it are not hashed). A table in which no bucket holds a symbol implies no
    count: symoffset is only a lower bound there (every unhashed symbol, an import for one, is below it), so it is never returned as a count.
    The bucket scan and the chain walk look at the clock every CHUNK_WORDS words."""
    if avail < 16:
        return None, 0
    nbuckets, symoffset, bloom_size, _shift = elf.u("IIII", start)
    wordsize = 8 if elf.wide else 4
    buckets_at = start + 16 + bloom_size * wordsize
    chain_at = buckets_at + nbuckets * 4
    if buckets_at + nbuckets * 4 > start + avail or nbuckets > (1 << 24):
        return None, symoffset
    top = 0
    done = 0
    while done < nbuckets:
        if ctx.expired("the DT_GNU_HASH buckets"):
            return None, symoffset
        n = min(CHUNK_WORDS, nbuckets - done)
        raw = bytes(img.mm[buckets_at + done * 4:buckets_at + (done + n) * 4])
        if len(raw) < n * 4:
            return None, symoffset
        top = max(top, max(v for (v,) in struct.iter_unpack(elf.end + "I", raw)))
        done += n
    if top < symoffset:
        return None, symoffset
    i = top
    walked = 0
    while True:
        if walked % CHUNK_WORDS == 0 and ctx.expired("the DT_GNU_HASH chain"):
            return None, symoffset
        at = chain_at + (i - symoffset) * 4
        if at + 4 > start + avail or at + 4 > img.size:
            return None, symoffset
        (c,) = elf.u("I", at)
        if c & 1:
            return i + 1, symoffset
        i += 1
        walked += 1
        if i - symoffset > MAX_SYMBOLS:
            return None, symoffset


def read_symbols(img, elf, ctx, out, dyn):
    symsz = 24 if elf.wide else 16
    tables = []
    if dyn and 6 in dyn["tags"] and dyn["str_base"] is not None:
        addr = dyn["tags"][6]
        mapped = elf.to_offset(addr)
        if mapped is None:
            ctx.problem("DT_SYMTAB (address 0x%x) is not mapped by any PT_LOAD segment that holds file bytes: .dynsym is not read through the dynamic array" % addr)
        else:
            count, how, floor = None, None, 0
            ent = dyn["tags"].get(11)
            if ent is not None and ent != symsz:
                ctx.problem("DT_SYMENT is %d, not %d: .dynsym is not read" % (ent, symsz))
            else:
                if 4 in dyn["tags"]:
                    h = elf.to_offset(dyn["tags"][4])
                    if h is not None and h[0] + 8 <= img.size:
                        (count,) = elf.u("I", h[0] + 4)
                        how = "DT_HASH nchain"
                if count is None and 0x6ffffef5 in dyn["tags"]:
                    h = elf.to_offset(dyn["tags"][0x6ffffef5])
                    if h is not None:
                        try:
                            count, floor = gnu_hash_symbols(img, elf, ctx, h[0], h[1] - h[0])
                        except Short:
                            count = None
                        if count is not None:
                            how = "DT_GNU_HASH"
                sec = next((x for x in elf.shdrs if x["type"] == SHT_DYNSYM and (x["addr"] == addr or x["offset"] == mapped[0])), None)
                sec_count = sec["size"] // symsz if sec is not None else None
                if count is None and sec_count is not None:
                    count, how = sec_count, "the .dynsym section header"
                elif count is not None and sec_count is not None and sec_count != count:
                    ctx.problem(".dynsym: %s gives %d symbols and the section header gives %d: the loader's count (%d) is listed" % (how, count, sec_count, count))
                if count is None and floor and not ctx.expired("the symbol count"):
                    count, how = floor, "DT_GNU_HASH lower bound"
                    ctx.problem(".dynsym: DT_GNU_HASH has no symbol in any bucket and there is no section header or DT_HASH to count them: the table holds at least %d symbols "
                                "(the ones before symoffset are not hashed); only that many are listed" % floor)
                if count is None:
                    ctx.problem(".dynsym: the symbol count could not be found (no DT_HASH, no usable DT_GNU_HASH and no matching section header): it is not listed")
                else:
                    tables.append(("dynsym", mapped[0], count, dyn["str_base"], dyn["str_end"], how))
    for s in elf.shdrs:
        if s["type"] == SHT_SYMTAB:
            link = s["link"]
            if link < len(elf.shdrs) and elf.shdrs[link]["type"] == SHT_STRTAB:
                st = elf.shdrs[link]
                tables.append(("symtab", s["offset"], s["size"] // symsz, st["offset"], min(st["offset"] + st["size"], img.size), "the .symtab section header"))
            else:
                ctx.problem(".symtab: sh_link %d is not a string table section: it is not listed" % link)
            break
    result = {}
    if not tables:
        out["symbols"] = {"status": "none_found", "note": "no .dynsym through the dynamic array and no .symtab through a section header (a stripped file has no .symtab)"}
        return
    for name, start, count, sbase, send, how in tables:
        page = ctx.page(name)
        fit = max(0, (img.size - start) // symsz) if start < img.size else 0
        if count > fit:
            ctx.problem("%s: %d symbols declared (by %s) at offset %d; the file holds room for %d: the rest are not read" % (name, count, how, start, fit))
        n = min(count, fit)
        if n > MAX_SYMBOLS:
            ctx.limit_hit("%s: %d symbols: the first %d are listed" % (name, n, MAX_SYMBOLS))
            n = MAX_SYMBOLS
        listed = bad_name = 0
        by_bind = {}
        for i in range(n):
            if i % 16 == 0 and ctx.expired("the " + name + " table"):
                break
            at = start + i * symsz
            if elf.wide:
                st_name, info, other, shndx, value, size = elf.u("IBBHQQ", at)
            else:
                st_name, value, size, info, other, shndx = elf.u("IIIBBH", at)
            typ, bind = info & 0xF, info >> 4
            row = {"index": i, "value": hex(value), "size": size, "type": SYM_TYPES.get(typ, typ), "bind": SYM_BINDS.get(bind, bind),
                   "visibility": SYM_VIS.get(other & 3, other & 3),
                   "section_index": {0: "UND", 0xFFF1: "ABS", 0xFFF2: "COMMON"}.get(shndx, shndx)}
            if st_name:
                if st_name >= send - sbase:
                    bad_name += 1
                    row["name"] = None
                else:
                    raw, complete = img.cstr(sbase + st_name, send)
                    if raw is not None:
                        row["name"] = show(ctx, "symbol_name", raw.decode("utf-8", "replace"), sbase + st_name, complete=complete)
                        if not complete:
                            row["name_unterminated"] = True
                    else:
                        bad_name += 1
                        row["name"] = None
            else:
                row["name"] = ""
            by_bind[row["bind"]] = by_bind.get(row["bind"], 0) + 1
            page.add(row)
            listed += 1
        if bad_name:
            ctx.problem("%s: %d symbol name offset(s) are outside the string table" % (name, bad_name))
        result[name] = {"table": name, "declared": count, "found_by": how, "listed": listed, "by_binding": by_bind}
    out["symbols"] = result


def read_notes(img, elf, ctx, out):
    spans = [(p["offset"], min(p["filesz"], max(0, img.size - p["offset"])), p["align"], "PT_NOTE %d" % p["index"]) for p in elf.phdrs if p["type"] == 4 and p["offset"] < img.size]
    source = "PT_NOTE"
    if not elf.phdrs:
        spans = [(s["offset"], min(s["size"], max(0, img.size - s["offset"])), s["align"], "SHT_NOTE section %d" % s["index"]) for s in elf.shdrs if s["type"] == SHT_NOTE and s["offset"] < img.size]
        source = "SHT_NOTE"
    table = ctx.page("notes")
    found, build_id, abi = 0, None, None
    for start, length, align, label in spans:
        if length > MAX_NOTE_BYTES:
            ctx.limit_hit("%s is %d bytes: the first %d are read" % (label, length, MAX_NOTE_BYTES))
            length = MAX_NOTE_BYTES
        pad = 8 if align == 8 else 4
        pos, end = start, start + length
        while pos + 12 <= end:
            if found >= MAX_NOTES:
                ctx.limit_hit("more than %d notes: the first %d are listed" % (MAX_NOTES, MAX_NOTES))
                break
            if ctx.expired("the notes"):
                break
            namesz, descsz, typ = elf.u("III", pos)
            name_at = pos + 12
            desc_at = name_at + (namesz + 3) // 4 * 4        # the owner is padded to 4; the descriptor and the next note to the segment's alignment (8 for GNU property notes)
            nxt = desc_at + (descsz + pad - 1) // pad * pad
            row = {"source": label, "offset": pos, "type": typ, "owner_size": namesz, "desc_size": descsz}
            if name_at + namesz > end or desc_at + descsz > end:
                ctx.problem("%s: the note at offset %d (name %d bytes, descriptor %d bytes) runs past the end of its segment: it is not read further" % (label, pos, namesz, descsz))
                row["past_end_of_segment"] = True
                table.add(row)
                found += 1
                break
            raw = bytes(img.mm[name_at:name_at + namesz]).split(b"\0", 1)[0]
            owner = raw.decode("utf-8", "replace")
            row["owner"] = show(ctx, "note_owner", owner, name_at)
            if owner == "GNU" and typ == 3 and 0 < descsz <= 64:
                build_id = made(bytes(img.mm[desc_at:desc_at + descsz]).hex())
                row["build_id"] = build_id
            elif owner == "GNU" and typ == 1 and descsz >= 16:
                os_id, a, b, c = elf.u("IIII", desc_at)
                abi = {"os": {0: "Linux", 1: "GNU Hurd", 2: "Solaris", 3: "FreeBSD"}.get(os_id, os_id), "version": [a, b, c]}
                row["abi_tag"] = abi
            table.add(row)
            found += 1
            if nxt <= pos:
                break
            pos = nxt
    out["notes"] = {"source": source, "listed": found, "table": "notes", "gnu_build_id": build_id, "gnu_abi_tag": abi,
                    "note": "a build ID is the linker's claim about the file it wrote; it identifies a build, not the file's content, and nothing here checks it"}


# --- the call ---------------------------------------------------------------------------------------------------------------

def positive_int(args, key, default, maximum=None):
    value = args.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int) or value < 1 or (maximum is not None and value > maximum):
        fail("%s must be an integer from 1%s" % (key, " to %d" % maximum if maximum else ""))
    return value


def file_problem(path):
    """Why `path` is not a file this tool can read, in words that fit: a missing file, a directory, a device, a loop."""
    try:
        mode = os.stat(path).st_mode
    except FileNotFoundError:
        return "no such file"
    except OSError as exc:
        return "the file could not be examined: %s" % describe(exc)
    if stat.S_ISREG(mode):
        return None
    kinds = ((stat.S_ISDIR, "a directory"), (stat.S_ISFIFO, "a named pipe"), (stat.S_ISSOCK, "a socket"), (stat.S_ISBLK, "a block device"), (stat.S_ISCHR, "a character device"))
    return "not a regular file (%s)" % next((n for t, n in kinds if t(mode)), "a special file")


def guarded(ctx, label, fn, *args):
    """Run one reader. A read that runs off the file, a budget, or a structure that is not what it claims is a problem of that reader and
    never ends the call."""
    try:
        fn(*args)
    except Short as exc:
        ctx.problem("%s: %s" % (label, exc))
    except Over as exc:
        ctx.limit_hit("%s: %s" % (label, exc))
    except (struct.error, ValueError, IndexError, OverflowError) as exc:
        ctx.problem("%s: a field could not be read (%s: %s)" % (label, type(exc).__name__, exc))


HARD_SECONDS = 105                  # the manifest's 120 s less 15: the answer is built and printed after the reading clock, and past this the tool answers that it did not finish
PRINTING = [False]                  # the answer has begun to be written: a signal after that must not write a second one


PARTIAL_BUILDING = [False]          # the partial answer of the hard limit is being built
PARTIAL_WRITING = [False]           # and has begun to be written: no other document may follow it


def _stopped_by_signal(signum, frame):
    """SIGINT, SIGTERM and SIGHUP end the call with one JSON answer and the exit code 128 + the signal, not a traceback and not silence. A signal
    while the partial answer of the hard limit is being built (not yet being written) is answered by a minimal failed document; one while a
    document is being written leaves that document, which is cut (the reader of a half-written answer has to expect that)."""
    if not PRINTING[0] or (PARTIAL_BUILDING[0] and not PARTIAL_WRITING[0]):
        PRINTING[0] = True
        PARTIAL_BUILDING[0] = False
        sys.stdout.write(json.dumps({"tool": TOOL, "status": "failed", "error": "the tool was stopped by signal %d before it finished; a file it was writing can be incomplete" % signum}) + "\n")
        sys.stdout.flush()
    raise SystemExit(128 + signum)


# The stop signals are answered from here on: _stopped_by_signal needs only TOOL, json, sys and the flags above, all defined before this line. The
# SIGALRM hard limit is not armed here: only main() arms it, with its deadline.
def install_stop_handlers():
    for name in ("SIGINT", "SIGTERM", "SIGHUP"):
        if hasattr(signal, name):
            signal.signal(getattr(signal, name), _stopped_by_signal)


install_stop_handlers()
# the stop handlers are installed here, at module level


HARD_GRACE = 5                      # seconds the partial answer of the hard limit has, before the failed one


def _hard_limit_last(signum, frame):
    """The partial answer was not finished in HARD_GRACE seconds. One document only: when its writing had begun (a reader that does not read
    the pipe) nothing is appended to it, and the call ends with what the reader took; else the failed one is the document."""
    if not PARTIAL_WRITING[0]:
        sys.stdout.write(json.dumps({"tool": TOOL, "status": "failed", "error": "the answer was not finished within %d seconds (the manifest's limit is 120) and the partial answer of what "
                                     "had been read was not finished either; a file the call wrote can be incomplete; read with a smaller limit or max_seconds" % HARD_SECONDS}) + "\n")
        sys.stdout.flush()
    os._exit(1)


ASSEMBLED = {}                      # what the call holds for the answer, once the reading has begun: the head and the Ctx (set in main)


def _hard_limit(signum, frame):
    """The call has not answered within HARD_SECONDS: the answer is the one of what is already assembled (the problems and limits, and the
    first rows of each table, all of them withheld when they were added), before the harness's kill; nothing else of the structure is in
    it. A call that had read nothing yet answers that it failed."""
    if PRINTING[0]:
        return
    PRINTING[0] = True
    PARTIAL_BUILDING[0] = True
    # should the partial answer itself not be finished in HARD_GRACE seconds, the failed one ends the call
    signal.signal(signal.SIGALRM, _hard_limit_last)
    signal.setitimer(signal.ITIMER_REAL, HARD_GRACE)
    note = ("time: the call had not answered within %d seconds (the manifest's limit is 120): this answer holds what had been read and withheld by then "
            "(the problems, the limits and the first rows of each table); the rest of the structure is not in it, and a file the call wrote can be incomplete "
            "(a table file named in `all_results` holds the rows written so far, one complete row to a line, and its last line can be cut); "
            "read with a smaller limit or max_seconds" % HARD_SECONDS)
    try:
        ctx = ASSEMBLED.get("ctx")
        if ctx is None:
            raise LookupError("nothing was read")
        tables = {}
        for name, page in list(ctx.pages.items()):
            table = {"matched": page.total, "returned": len(page.page), "rows_shown": min(len(page.page), SPILL_FLOOR), "rows": page.page[:SPILL_FLOOR]}
            if page.shown and page._out is not None:
                table["all_results"] = page.shown
            tables[name] = table
        partial = {**ASSEMBLED["head"], "status": "partial", "status_basis": note, "problems": list(ctx.problems), "limits_hit": list(ctx.limits) + [note],
                   "tables": tables, "withheld": COUNTS, "note": NOTE}
        document = json.dumps(build_answer(partial, None, 4)) + "\n"
        PARTIAL_WRITING[0] = True
        sys.stdout.write(document)
        sys.stdout.flush()
        os._exit(0)
    except Exception:
        if PARTIAL_WRITING[0]:
            os._exit(1)
        PARTIAL_BUILDING[0] = False
        sys.stdout.write(json.dumps({"tool": TOOL, "status": "failed", "error": "the answer was not finished within %d seconds (the manifest's limit is 120) and nothing "
                                     "had been read yet; a file the call wrote can be incomplete; read with a smaller limit or max_seconds" % HARD_SECONDS}) + "\n")
        sys.stdout.flush()
        os._exit(1)


def install_signal_handlers():
    install_stop_handlers()
    if hasattr(signal, "setitimer") and hasattr(signal, "SIGALRM"):
        signal.signal(signal.SIGALRM, _hard_limit)
        signal.setitimer(signal.ITIMER_REAL, HARD_SECONDS)




def open_regular(path):
    """(fd, stat) of a regular file, opened without blocking and without following a link, or (None, why). The kind is read from the open
    descriptor, so a pipe swapped in after a look at the name is still not read."""
    flags = os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        return None, "no such file"
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            return None, "a symbolic link: refused, the file is not followed"
        return None, "the file could not be opened: %s" % describe(exc)
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode):
        os.close(fd)
        kinds = ((stat.S_ISDIR, "a directory"), (stat.S_ISFIFO, "a named pipe"), (stat.S_ISSOCK, "a socket"), (stat.S_ISBLK, "a block device"), (stat.S_ISCHR, "a character device"))
        return None, "not a regular file (%s)" % next((n for t, n in kinds if t(st.st_mode)), "a special file")
    return fd, st


def main():
    install_signal_handlers()
    try:
        args = json.load(sys.stdin)
    except (ValueError, RecursionError) as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    if not isinstance(args, dict):
        fail("arguments must be a JSON object")
    for key in args:
        if key not in ("path", "write_values", "limit", "max_seconds"):
            fail("unknown parameter: a name of %d characters" % len(str(key)))
    path = args.get("path")
    if not isinstance(path, str) or not path or "\0" in path:
        fail("path is required: an ELF file to read (a non-empty string without a NUL)")
    try:
        path.encode("utf-8")
    except UnicodeEncodeError:
        fail("path must be text that can be written as UTF-8 (it holds a lone surrogate)")
    write_values = args.get("write_values", False)
    if not isinstance(write_values, bool):
        fail("write_values must be true or false")
    cfg = {"limit": positive_int(args, "limit", DEFAULT_LIMIT, MAX_LIMIT)}
    seconds = positive_int(args, "max_seconds", DEFAULT_SECONDS, MAX_SECONDS)
    fd, st = open_regular(path)
    if fd is None:
        fail(st, path=path)
    try:
        values = SecretValues(write_values)
    except SecretValuesRefused as exc:
        os.close(fd)
        fail(str(exc), write_values="refused", written=False)
    VALUES[0] = values
    size = st.st_size
    # The key that names this call's paging files is the path as it may be printed: a digest of a path that holds a token would be a
    # digest of the token (docs/packs.md section 8).
    ctx = Ctx(shown_path(os.path.realpath(path)), cfg, values, seconds)
    shown = shown_name(path)
    if shown != path:
        ctx.names.add(path, shown, "input_path")
    ASSEMBLED.update(ctx=ctx, head={"tool": TOOL, "parser": PARSER, "path": shown, "bytes": size})
    if size == 0:
        values.close()
        os.close(fd)
        fail("the file is empty", path=path)
    body, stop = {}, None
    try:
        mm = mmap.mmap(fd, 0, access=mmap.ACCESS_READ)
        os.close(fd)
        try:
            img = Image(mm)
            ctx.img = img
            if img.mm[:4] != b"\x7fELF":
                values.close()
                fail("this is not an ELF file (no \\x7fELF magic)", status="unsupported", path=path, head_hex=bytes(img.mm[:4]).hex())
            elf = None
            try:
                body, elf = parse_headers(img, ctx)
            except Stop as exc:
                stop = exc
                body = exc.partial
            except Short as exc:
                stop = Stop("failed", "the headers run past the end of the file: %s" % exc)
            if stop is None:
                guarded(ctx, "program headers", read_program_headers, img, elf, ctx, body)
                dyn = [None]

                def read_dyn():
                    dyn[0] = read_dynamic(img, elf, ctx, body)
                guarded(ctx, "dynamic array", read_dyn)
                guarded(ctx, "symbols", read_symbols, img, elf, ctx, body, dyn[0])
                guarded(ctx, "notes", read_notes, img, elf, ctx, body)
                body["coverage"] = {"structures_read": READ, "structures_not_read": NOT_READ}
        finally:
            ctx.img = None
            mm.close()
    finally:
        values.close()
        ctx.names.close()

    tables = {}
    for name, page in ctx.pages.items():
        tables[name] = page.finish()
        tables[name]["rows"] = page.page
        if page.not_written:
            ctx.problem("the whole %s table could not be written to a file: %s" % (name, page.not_written))
    if ctx.names.capped:
        ctx.limit_hit("the file of withheld names reached %d MiB and stopped growing: %d names were withheld in all; the later ones are not kept there (the file that was read is the source)" % (Names.MAX_BYTES >> 20, ctx.names.count))
    if ctx.names.error:
        ctx.problem("the real names behind the withheld ones could not be kept: %s" % ctx.names.error)
    truncated = any(p["truncated"] for p in tables.values())
    head_out = {"tool": TOOL, "parser": PARSER, "path": shown, "bytes": size}
    spill = Spill(ctx, max(cfg["limit"], SPILL_FLOOR))
    if stop is not None:
        emit({**head_out, **body, "status": stop.status, "status_basis": stop.message, "error": stop.message, "problems": ctx.problems,
              "limits_hit": ctx.limits, "withheld": COUNTS, "secret_values": values.summary(), "note": NOTE}, spill)
        raise SystemExit(1)
    status = "partial" if (ctx.problems or ctx.limits) else "complete"
    basis = ("every structure this tool reads and the file declares was read in full" if status == "complete" else
             "%d problem(s), %d limit(s): see `problems`, `limits_hit` and `coverage`" % (len(ctx.problems), len(ctx.limits)))
    result = {**head_out, **body, "status": status, "status_basis": basis, "problems": ctx.problems, "limits_hit": ctx.limits, "tables": tables, "truncated": truncated,
              "withheld": COUNTS, "secret_values": values.summary(), "note": NOTE}
    if ctx.names.shown:
        result["withheld_names_file"] = ctx.names.shown
        result["withheld_names_note"] = ("The real name behind every name withheld here is in this file (mode 0600, always written when a name is withheld): "
                                         "run the job with secret_output: true.")
    if ctx.problems_dropped:
        result["problems_not_listed"] = ctx.problems_dropped
    if values.enabled or COUNTS["urls"] or COUNTS["names"] or COUNTS["text"]:
        result["withheld_note"] = ("Text is withheld by its shape only: user-info, the value of a secret-named key and token-shaped text are withheld "
                                   "from this answer, each by its length. A secret of another shape (a plain password, a token family the rules do "
                                   "not name, a token split across two fields) is printed. The whole string is in the values file when write_values "
                                   "was asked for in a secret_output job: read a file whose secrets matter in such a job.")
    emit(result, spill)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:  # never a traceback and never a clean answer for a failure
        fail("unexpected failure: %s" % (describe(exc) if isinstance(exc, OSError) else "%s: %s" % (type(exc).__name__, shown_path(str(exc)))))
