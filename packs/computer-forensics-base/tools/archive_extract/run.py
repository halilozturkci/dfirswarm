#!/usr/bin/env python3
"""Extract the members of a zip, tar (plain, gzip, bzip2, xz, zstd), 7z or single-file compressed archive into a new directory, bounded.

An archive is hostile input. This tool writes member CONTENT only: it never recreates a link, a device node, a FIFO or
a directory mode, never writes outside its output directory, never executes anything and never decompresses without a
bound. What it does, exactly:

  * Format is read from the bytes (zip, tar, gzip, bzip2, xz, zstd, 7z), never from the file name. A compressed stream
    is looked into: a tar inside it is a tar, anything else is ONE member (a gzip's own file name, else the archive's
    name without its suffix). RAR, CAB, ISO and the rest are named and refused (unsupported), never guessed. zstd is read
    through Python's compression.zstd (3.14) or the zstd program of the base image, in that order (the zstandard module is not used: its streaming reader
    ends a truncated frame without an error);
    if none is there a zstd archive is reported unsupported with that reason.
  * Every member is one row of members.jsonl, in archive order, numbered `n` from 0 (the same number the archive-members
    recipe gives it), with its original name kept exactly (`name_b64`, the bytes) beside a display form, its type, declared
    and written sizes, the times as the archive stores them with the zone said, the flags it earned, and a status:
    extracted, partial, directory, not_created (a link, device or FIFO: recorded, with its target, and never created),
    encrypted (counted, not extracted, not skipped silently), unsupported (a compression method this build cannot read),
    skipped (a budget rule for that member: depth, size, ratio). Two members with one name are two rows, two files.
  * Files are created exclusively (O_EXCL, O_NOFOLLOW, through directory descriptors, so no path component can be a link
    and nothing lands outside the output directory), mode 0600 in a 0700 directory, under an ASCII-safe rendering of the
    name (every byte outside A-Z a-z 0-9 . _ - + @ = , ( ) becomes %XX; `..` becomes %2E%2E; an absolute or drive-lettered
    name loses its root). The row's `path` is where the bytes are; `name_b64` is what the archive called them. A member
    whose name is shaped like a token (or carries user-info) is written under _withheld/withheld-NNNNNN<ext> and its name
    appears nowhere in the answer; the real name goes to withheld-names.jsonl (0600). There is no name filter: a filter
    over withheld text would be an oracle for it. Members are chosen by number (`from_index`).
  * What is written goes to <path>.partial and takes its real name only when the member is whole, its size is what the
    archive declared and its CRC (where the archive has one) matches. A member that stops, fails or mismatches stays as
    .partial and its row says why. A digest or CRC of a member shorter than 128 bytes is not written (a short value can
    be reversed from its digest); the row says so.
  * Budgets: max_total_bytes, max_member_bytes, max_members, max_ratio (expanded over packed: per member for a zip, whose directory
    gives each member's packed size; over the whole stream for a gzip, bzip2, xz or zstd file or tar, and for a 7z, whose output is
    held to max_ratio times the archive's size; a plain tar stores its members, so nothing in it expands), max_depth (path
    components) and max_seconds. A member-level budget
    skips or cuts that member and goes on; a global one stops the run, names it (`stopped_by`) and gives `next_index`:
    run again with from_index set to it and resume true to go on in the same out_dir (a second manifest, members.2.jsonl,
    is written beside the first; nothing is replaced).
  * A nested archive is NOT opened: the row says `looks_like` from the member's first bytes, and the caller extracts it in
    a call of its own (with its own budgets). One call extracts one level.
  * The 7z program (7z, 7zz or 7za) lists and extracts a 7z archive to a pipe; its bytes are split by the sizes in its own
    listing and checked against the listing's CRC, so the program never writes a file and path rules never depend on it.
    A listing's order is the stream's order; a CRC that does not match, or a stream that is longer or shorter than the
    listing, is said, member by member.

Exit code 0 means the engine ran and the answer is whole about what it did (a partial extraction is exit 0 with status
partial and the reasons); 1 is an archive that cannot be read at all, a refused argument or a place that cannot be
written. Extracted content is evidence content and can hold credentials: the output directory is private, the answer
says so, and the skill says to run the job with secret_output: true.
"""
import base64
import binascii
import bz2
import datetime
import errno
import hashlib
import json
import lzma
import os
import re
import select
import shutil
import signal
import stat
import struct
import subprocess
import sys
import tarfile
import time
import zipfile
import zlib
from pathlib import Path

TOOL = {"name": "archive_extract", "version": 15}
STARTED = time.monotonic()               # the run's clock starts with the tool: the archive hash and the 7z banner are on it too
CHUNK = 1 << 20
SHORT_MEMBER = 128                       # a member shorter than this has no digest and no CRC written
MAX_TOTAL_DEFAULT = 8 * 1024 ** 3
MAX_MEMBER_DEFAULT = 4 * 1024 ** 3
BYTES_CEILING = 1024 ** 4
MAX_MEMBERS_DEFAULT = 200_000
MAX_MEMBERS_CEILING = 5_000_000
MAX_RATIO_DEFAULT = 1000
MAX_RATIO_CEILING = 1_000_000
RATIO_SLACK = 1 << 20                    # a member may expand this much past its ratio before the ratio counts (a tiny file)
MAX_DEPTH_DEFAULT = 64
MAX_DEPTH_CEILING = 1024
MAX_SECONDS_DEFAULT = 1500
MAX_SECONDS_CEILING = 1700               # inside the manifest's 1800: a longer budget would be killed, not reported
LIMIT_DEFAULT = 50
LIMIT_CEILING = 1000
LINK_TARGET_MAX = 4096
HASH_ARCHIVE_MAX = 4 * 1024 ** 3         # the archive's own sha256 is taken up to this size
META_MAX = 1024 * 1024                   # a tar long-name or pax header that declares more is not read (tarfile reads it whole)
ZIP_DIRECTORY_MAX = 64 * 1024 * 1024      # zipfile holds every entry of the directory in memory (about 500 bytes each): 64 MiB of it is some 1.4 million entries
ZIP_DIRECTORY_FACTOR = 4                  # and a directory declaring more than this many times max_members is not loaded to extract that few
SEVEN_Z_MAGIC = b"7z\xbc\xaf\x27\x1c"
SEVEN_Z_NAMES = ("7z", "7zz", "7za", "7zr")
LISTING_LINE_MAX = 16 * 1024 * 1024
TAIL_KEEP = 4 * 1024 * 1024               # decompressed bytes kept for salvaging a member cut short by a break
SEGMENT = 200                            # an on-disk name component longer than this is shortened and hashed; name_b64 keeps the whole
FIRST_FAILURES = 20

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


def b64(raw):
    return base64.b64encode(raw).decode("ascii")


def iso_utc(epoch):
    """ISO-8601 UTC with the fraction kept, or None for a value no date can hold."""
    try:
        whole_s = int(epoch // 1)
        frac = epoch - whole_s
        stamp = datetime.datetime.fromtimestamp(whole_s, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    except (OverflowError, OSError, ValueError, TypeError):
        return None
    if frac:
        stamp += ("%.6f" % frac)[1:].rstrip("0")
    return stamp + "Z"


# ---- names ------------------------------------------------------------------------------------------------------------

SAFE_BYTES = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-+@=,()")


def name_analysis(raw, windows):
    """(components, flags) of a member name. A component is bytes; `.` and empty ones are dropped, `..` is kept (and flagged:
    it is never followed, only rendered). `windows` names where a backslash is a separator (zip and 7z come from
    archivers that write them); in a tar it is an ordinary byte."""
    flags = []
    try:
        raw.decode("utf-8")
    except UnicodeDecodeError:
        flags.append("name-not-utf8")
    if b"\x00" in raw:
        flags.append("nul-in-name")
    plain = raw.replace(b"\x00", b"/")
    if windows:
        if b"\\" in plain:
            flags.append("backslash-separator")
        plain = plain.replace(b"\\", b"/")
    elif b"\\" in plain:
        flags.append("backslash-in-name")
    if plain.startswith(b"/"):
        flags.append("absolute-path")
    if re.match(rb"^[A-Za-z]:", plain):
        flags.append("drive-letter")
    parts = plain.split(b"/")
    if b".." in parts:
        flags.append("dotdot")
    if "absolute-path" in flags or "drive-letter" in flags or "dotdot" in flags:
        flags.append("escapes-root")
    return [p for p in parts if p not in (b"", b".")], flags


def render_component(raw):
    out = "".join(chr(b) if b in SAFE_BYTES else "%%%02X" % b for b in raw)
    if raw in (b"..",):
        out = "%2E%2E"
    if len(out) > SEGMENT:
        out = out[:SEGMENT // 2] + "~" + hashlib.sha1(raw).hexdigest()[:12]
    return out


def extension_of(raw):
    m = re.search(rb"(\.[A-Za-z]{1,5})$", raw)
    return m.group(1).decode("ascii") if m else ""


def looks_like(head):
    """What the first bytes of a member say it may be: a candidate to extract in a call of its own, nothing more."""
    if head.startswith((b"PK\x03\x04", b"PK\x05\x06")):
        return "zip"
    if head.startswith(SEVEN_Z_MAGIC):
        return "7z"
    if head.startswith(b"\x1f\x8b\x08"):
        return "gzip"
    if head.startswith(b"BZh") and len(head) > 3 and head[3:4].isdigit():
        return "bzip2"
    if head.startswith(b"\xfd7zXZ\x00"):
        return "xz"
    if head.startswith(b"\x28\xb5\x2f\xfd"):
        return "zstd"
    if head[257:262] == b"ustar":
        return "tar"
    if head.startswith(b"Rar!\x1a\x07"):
        return "rar"
    if head.startswith(b"MSCF"):
        return "cab"
    return None


# ---- decompression --------------------------------------------------------------------------------------------------

class Budget(Exception):
    """A global budget ended the run; `reason` names it."""

    def __init__(self, reason, text=""):
        super().__init__(text or reason)
        self.reason = reason


class Ratio(Exception):
    pass


def zstd_module():
    """(kind, object) for the first zstd reader this Python has, else (None, why)."""
    try:
        from compression import zstd as zmod          # Python 3.14
        return "compression.zstd", zmod
    except ImportError:
        pass
    if shutil.which("zstd"):
        return "zstd program", None
    return None, "no zstd decompressor: this Python has no compression.zstd (3.14) and there is no zstd program on PATH"


def gzip_header_length(data):
    """The length of the gzip member header at the start of `data` (RFC 1952: ten bytes, then the optional extra field, name, comment and
    header CRC the flags name), or None when `data` ends inside it. Raises ValueError when it is not a gzip member header."""
    if len(data) >= 3 and (data[:2] != b"\x1f\x8b" or data[2] != 8):
        raise ValueError("not a gzip member (bad magic or an unknown compression method)")
    if len(data) < 10:
        return None
    flags, at = data[3], 10
    if flags & 4:
        if len(data) < at + 2:
            return None
        at += 2 + int.from_bytes(data[at:at + 2], "little")
    for bit in (8, 16):
        if flags & bit:
            end = data.find(b"\0", at)
            if end < 0:
                return None
            at = end + 1
    if flags & 2:
        at += 2
    return at if len(data) >= at else None


class Decomp:
    """A decompressed byte stream over a compressed file: gzip, bzip2, xz or zstd, one or several streams back to back.

    read(n) returns at most n bytes and b"" only at the end of the last stream. The decompressors are called with a maximum
    output of CHUNK, so a bomb never costs more than one piece of memory, and the ratio of what came out to what went in is
    checked after every piece."""

    MARKERS = {"gzip": b"\x1f\x8b", "bzip2": b"BZh", "xz": b"\xfd7zXZ\x00"}

    def __init__(self, path, kind, max_ratio):
        self.kind, self.max_ratio = kind, max_ratio
        self.fh = open_regular(path)
        self.consumed = 0          # compressed bytes read from the file
        self.produced = 0          # decompressed bytes handed out
        self.buf = b""
        self.eof = False
        self.streams = 0
        self.trailing = 0          # bytes after the last stream that are not another stream
        self.trailing_nonzero = False   # whether any of them is not a zero (zeros are the padding some writers leave)
        self.proc = None
        self.reader = None
        self.delivered = 0         # decompressed bytes handed to the reader so far
        self.tail = bytearray()    # the last TAIL_KEEP of them, so that a member cut short by a break can be given back what was decompressed
        self.pending = None        # an error from the decompressor, raised once the bytes before it have been read
        self.gen = self._zstd_pieces() if kind == "zstd" else self._pieces()

    def close(self):
        if self.reader is not None:
            try:
                self.reader.close()
            except Exception:   # noqa: BLE001
                pass
        try:
            self.fh.close()
        except OSError:
            pass
        if self.proc is not None:
            kill_tree(self.proc)
            if self.proc in ACTIVE:
                ACTIVE.remove(self.proc)

    def _check(self):
        if self.produced > self.max_ratio * max(self.consumed, 1) + RATIO_SLACK:
            raise Ratio("the stream expanded to %d bytes from %d compressed (more than %d times)" % (self.produced, self.consumed, self.max_ratio))

    def _new(self):
        if self.kind == "gzip":
            return zlib.decompressobj(31)
        if self.kind == "bzip2":
            return bz2.BZ2Decompressor()
        return lzma.LZMADecompressor()

    def _step(self, dec, data):
        """(output, input left over, finished) after one call bounded to CHUNK bytes of output."""
        if self.kind == "gzip":
            out = dec.decompress(data, CHUNK)
            return out, (dec.unused_data if dec.eof else dec.unconsumed_tail), dec.eof
        out = dec.decompress(data, max_length=CHUNK)
        return out, (dec.unused_data if dec.eof else b""), dec.eof

    def _gzip_pieces(self):
        """gzip members back to back, framed here (header, raw deflate, CRC-32 and ISIZE trailer) rather than by zlib's gzip mode: zlib
        raises at the trailer and gives up the output of the call that reached it, so a member whose trailer does not match would
        have lost its last piece. Here every byte of a member is handed out first, and the trailer's mismatch is raised after them."""
        data = self.fh.read(CHUNK)
        self.consumed += len(data)
        if not data:
            raise EOFError("the gzip file is empty")
        while True:
            self.streams += 1
            while True:
                head = gzip_header_length(data)
                if head is not None:
                    break
                more = self.fh.read(CHUNK)
                self.consumed += len(more)
                if not more:
                    raise EOFError("the gzip stream ends inside its header (a truncated archive)")
                data += more
            data = data[head:]
            dec = zlib.decompressobj(-15)
            crc = size = 0
            while True:
                out = dec.decompress(data, CHUNK)
                data = dec.unused_data if dec.eof else dec.unconsumed_tail
                if out:
                    crc = zlib.crc32(out, crc)
                    size += len(out)
                    self.produced += len(out)
                    self._check()
                    yield out
                if dec.eof:
                    break
                if not data and len(out) < CHUNK:
                    data = self.fh.read(CHUNK)
                    self.consumed += len(data)
                    if not data:
                        raise EOFError("the gzip stream ends before its end marker (a truncated archive)")
            while len(data) < 8:
                more = self.fh.read(CHUNK)
                self.consumed += len(more)
                if not more:
                    raise EOFError("the gzip stream ends inside its trailer (a truncated archive)")
                data += more
            want_crc, want_size = struct.unpack("<II", data[:8])
            data = data[8:]
            if want_crc != crc & 0xFFFFFFFF:
                raise zlib.error("Error -3 while decompressing data: incorrect data check")
            if want_size != size & 0xFFFFFFFF:
                raise zlib.error("Error -3 while decompressing data: incorrect length check")
            rest = data
            while not rest:
                rest = self.fh.read(CHUNK)
                self.consumed += len(rest)
                if not rest:
                    return
            if rest.startswith(b"\x1f\x8b"):
                data = rest
                continue
            # What follows the last stream is not another one: counted and said, not decompressed.
            self.trailing = len(rest)
            self.trailing_nonzero = bool(rest.strip(b"\0"))
            while True:
                more = self.fh.read(CHUNK)
                if not more:
                    return
                self.trailing += len(more)
                self.consumed += len(more)
                if more.strip(b"\0"):
                    self.trailing_nonzero = True

    def _pieces(self):
        if self.kind == "gzip":
            yield from self._gzip_pieces()
            return
        marker = self.MARKERS[self.kind]
        dec = self._new()
        self.streams = 1
        data = b""
        while True:
            if not data:
                data = self.fh.read(CHUNK)
                self.consumed += len(data)
                if not data:
                    if not getattr(dec, "eof", False):
                        raise EOFError("the %s stream ends before its end marker (a truncated archive)" % self.kind)
                    return
            while True:
                out, data, finished = self._step(dec, data)
                if out:
                    self.produced += len(out)
                    self._check()
                    yield out
                if finished:
                    break
                if self.kind == "gzip":
                    if not data and len(out) < CHUNK:
                        break                      # all the input is used and nothing more is pending: more input is read above
                elif dec.needs_input:
                    break
                else:
                    data = b""                     # the decompressor holds output it has not given yet: ask again with no input
            if not finished:
                data = b""
                continue
            rest = data
            while not rest:
                rest = self.fh.read(CHUNK)
                self.consumed += len(rest)
                if not rest:
                    return
            if rest.startswith(marker):
                dec = self._new()
                self.streams += 1
                data = rest
                continue
            # What follows the last stream is not another one: counted and said, not decompressed.
            self.trailing = len(rest)
            self.trailing_nonzero = bool(rest.strip(b"\0"))
            while True:
                more = self.fh.read(CHUNK)
                if not more:
                    return
                self.trailing += len(more)
                self.consumed += len(more)
                if more.strip(b"\0"):
                    self.trailing_nonzero = True

    def _zstd_pieces(self):
        which, mod = zstd_module()
        self.streams = 1
        if which == "zstd program":
            self.proc = spawn(["zstd", "-dc", "-q"], stdin=self.fh, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            ACTIVE.append(self.proc)
            fd = self.proc.stdout.fileno()
            while True:
                piece = os.read(fd, CHUNK)
                if not piece:
                    break
                self.produced += len(piece)
                self.consumed = max(self.consumed, self.fh.tell())
                self._check()
                yield piece
            rc = self.proc.wait()
            if rc != 0:
                raise EOFError("the zstd program exited %d: the compressed stream is damaged or truncated" % rc)
            return
        if which == "compression.zstd":
            self.reader = mod.ZstdFile(self.fh)
        else:
            raise Unsupported(mod)
        while True:
            piece = self.reader.read(CHUNK)
            if not piece:
                return
            self.produced += len(piece)
            self.consumed = max(self.consumed, self.fh.tell())
            self._check()
            yield piece

    def read(self, n=-1):
        if n is None or n < 0:
            n = 1 << 62
        while len(self.buf) < n and not self.eof and self.pending is None:
            try:
                piece = next(self.gen)
            except StopIteration:
                self.eof = True
                break
            except (Ratio, Budget, EOFError, OSError, zlib.error, lzma.LZMAError, ValueError, Unsupported) as exc:
                self.pending = exc               # the bytes decompressed before the break are read first, then this is raised
                break
            self.buf += piece
        if not self.buf and self.pending is not None:
            raise self.pending
        out, self.buf = self.buf[:n], self.buf[n:]
        self.delivered += len(out)
        self.tail += out
        if len(self.tail) > TAIL_KEEP:
            del self.tail[:-TAIL_KEEP]
        return out

    def unread(self, data):
        """Give back bytes just read (the format sniff reads the first block and puts it back)."""
        self.buf = data + self.buf
        self.delivered -= len(data)
        del self.tail[len(self.tail) - len(data):]

    def slice(self, start, end):
        """The decompressed bytes at stream offsets [start, end) that are still in the tail."""
        base = self.delivered - len(self.tail)
        lo, hi = max(start, base), min(end, self.delivered)
        return bytes(self.tail[lo - base:hi - base]) if hi > lo else b""


class RawSlice:
    """`size` bytes of a file from `offset`: a plain tar member's data, read without tarfile, so that an archive which ends early gives what is there."""

    def __init__(self, path, offset, size):
        self.fh = open_regular(path)
        self.fh.seek(offset)
        self.remaining = size

    def read(self, n=-1):
        if self.remaining <= 0:
            return b""
        data = self.fh.read(min(n if n and n > 0 else CHUNK, self.remaining))
        self.remaining -= len(data)
        return data

    def close(self):
        self.fh.close()


class TarMember:
    """A member of a tar read through a decompressor: tarfile's reader, plus the bytes the decompressor delivered when tarfile's read fails."""

    def __init__(self, tf, t, dec):
        self.f, self.t, self.dec = tf.extractfile(t), t, dec

    def read(self, n=-1):
        return self.f.read(n)

    def salvage(self, written):
        start = self.t.offset_data + written
        return self.dec.slice(start, self.t.offset_data + self.t.size)

    def close(self):
        self.f.close()


class Unsupported(Exception):
    pass


# ---- the output directory ---------------------------------------------------------------------------------------------

class Tree:
    """Files made under one directory through descriptors, so that no component can be a link and nothing lands outside.

    Directories are made 0700 and opened O_NOFOLLOW one component at a time; a file is created O_EXCL|O_NOFOLLOW as
    <name>.partial in its directory, and takes its name with link-then-unlink, which never replaces what is there."""

    def __init__(self, root):
        self.root = root
        self.root_fd = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))

    def close(self):
        try:
            os.close(self.root_fd)
        except OSError:
            pass

    def _dir(self, parts):
        fd = os.dup(self.root_fd)
        try:
            for part in parts:
                try:
                    os.mkdir(part, 0o700, dir_fd=fd)
                except FileExistsError:
                    pass
                nxt = os.open(part, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0), dir_fd=fd)
                os.close(fd)
                fd = nxt
            return fd
        except BaseException:
            os.close(fd)
            raise

    def create(self, parts, leaf):
        """(dir fd, partial name, file object) for a new <leaf>.partial in the directory `parts`."""
        dfd = self._dir(parts)
        k = 0
        while True:
            name = leaf + ".partial" + ("" if k == 0 else ".%d" % k)
            try:
                fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=dfd)
            except FileExistsError:
                k += 1
                continue
            except BaseException:
                os.close(dfd)
                raise
            return dfd, name, os.fdopen(fd, "wb")

    def publish(self, dfd, partial, leaf):
        """The final name of a finished member: `leaf`, or leaf~dup2, leaf~dup3 ... when that name is taken. Returns it."""
        k = 1
        while True:
            name = leaf if k == 1 else "%s~dup%d" % (leaf, k)
            try:
                os.link(partial, name, src_dir_fd=dfd, dst_dir_fd=dfd)
                os.unlink(partial, dir_fd=dfd)
                return name
            except FileExistsError:
                k += 1
            except OSError as exc:
                if exc.errno in (errno.EPERM, errno.ENOTSUP, errno.EOPNOTSUPP, errno.EXDEV, errno.EMLINK):   # no hard links: a look, then a rename
                    try:
                        os.stat(name, dir_fd=dfd, follow_symlinks=False)
                        k += 1
                        continue
                    except FileNotFoundError:
                        os.rename(partial, name, src_dir_fd=dfd, dst_dir_fd=dfd)
                        return name
                raise


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


# ---- the engine -------------------------------------------------------------------------------------------------------

class Engine:
    def __init__(self, args, out_root, run_no, archive_info):
        self.a = args
        self.out_root = out_root
        self.tree = Tree(str(out_root / "extracted"))
        suffix = "" if run_no == 1 else ".%d" % run_no
        self.members_path = out_root / ("members%s.jsonl" % suffix)
        self.receipt_path = out_root / ("receipt%s.json" % suffix)
        self.withheld_path = out_root / ("withheld-names%s.jsonl" % suffix)
        self.members_fh = private_file(str(self.members_path))
        self.withheld_fh = None
        self.archive = archive_info
        self.started = STARTED
        self.deadline = self.started + args["max_seconds"]
        self.counts = {}
        self.types = {}
        self.flag_counts = {}
        self.total_written = 0
        self.rows = 0
        self.page = []
        self.failures = []
        self.nested = []
        self.name_seen = set()
        self.duplicate_names = 0
        self.members_withheld = 0
        self.stopped_by = None
        self.stop_text = None
        self.next_index = args["from_index"]
        self.current = None
        self.notes = []
        self.extra = {}
        self.status = "running"          # running | interrupted | failed while the run is not over; None once it is
        self.receipt_error = None        # why receipt.json could not be written, when it could not

    # -- bookkeeping --
    def count(self, status):
        self.counts[status] = self.counts.get(status, 0) + 1

    def write_receipt(self):
        """Write receipt.json; a disk that refuses is said in the answer (receipt_error) and makes it partial, never a crash with no JSON."""
        try:
            write_json_atomic(str(self.receipt_path), self.receipt())
            return True
        except OSError as exc:
            self.receipt_error = describe(exc)
            return False

    def receipt(self):
        bad = {k: v for k, v in self.counts.items() if k not in ("extracted", "directory", "not_created")}
        status = self.status or ("partial" if bad or self.stopped_by else "complete")
        out = {
            "tool": TOOL,
            "status": status,
            "status_basis": {"complete": "every member the archive lists was read to its end and written, or is a directory",
                             "partial": "a member did not come out whole or a budget stopped the run (see counts, stopped_by and first_failures)",
                             "failed": "the archive could not be read",
                             "interrupted": "the run was ended by a signal before it finished", "running": "the run has not finished"}.get(status, status),
            "archive": self.archive,
            "out_dir": str(self.out_root.relative_to(Path.cwd().resolve())) if Path.cwd().resolve() in self.out_root.parents else str(self.out_root),
            "extracted_dir": "extracted",
            "members_file": self.members_path.name,
            "members_file_format": "JSON Lines, one object per member in archive order: n, type, name, name_b64, path, status, reason, sizes, sha256, times, flags",
            "withheld_names_file": self.withheld_path.name if self.withheld_fh is not None else None,
            "members_seen": self.rows,
            "counts": dict(sorted(self.counts.items())),
            "types": dict(sorted(self.types.items())),
            "flags": dict(sorted(self.flag_counts.items())),
            "bytes_written": self.total_written,
            "from_index": self.a["from_index"],
            "next_index": self.next_index,
            "stopped_by": self.stopped_by,
            "stop": self.stop_text,
            "duplicate_names": self.duplicate_names,
            "members_withheld": self.members_withheld,
            "nested_archives": self.nested[:100],
            "nested_archives_total": len(self.nested),
            "budgets": {k: self.a[k] for k in ("max_total_bytes", "max_member_bytes", "max_members", "max_ratio", "max_depth", "max_seconds")},
            "seconds": round(time.monotonic() - self.started, 2),
            "first_failures": self.failures,
            "notes": self.notes,
            "sensitive_output": {
                "extracted_content": True,
                "out_dir_mode": "0700, files 0600",
                "advice": "extracted members are evidence content and can hold credentials, keys and tokens: when the member list shows credential stores, keys, "
                          "tokens or browser profiles, run this as a job with secret_output: true, and record where a secret sits, its kind and length, never its value",
            },
            "not_measured": "the content of a member is not examined; a nested archive is named, not opened; a member's CRC or size agreeing with the "
                            "archive's record shows the bytes are what the archive held, not that the archive is authentic or complete",
        }
        out.update(self.extra)
        return out

    def record(self, row):
        self.rows += 1
        self.count(row["status"])
        self.types[row["type"]] = self.types.get(row["type"], 0) + 1
        for f in row.get("flags", []):
            self.flag_counts[f] = self.flag_counts.get(f, 0) + 1
        self.members_fh.write(json.dumps(row, ensure_ascii=True) + "\n")
        self.members_fh.flush()
        if len(self.page) < self.a["limit"]:
            self.page.append(row)
        if row["status"] not in ("extracted", "directory", "not_created") and len(self.failures) < FIRST_FAILURES:
            self.failures.append({k: row.get(k) for k in ("n", "name", "status", "reason")})

    def withhold(self, n, raw, ondisk):
        if self.withheld_fh is None:
            self.withheld_fh = private_file(str(self.withheld_path))
        self.withheld_fh.write(json.dumps({"n": n, "path": ondisk, "name": raw.decode("utf-8", "surrogateescape"), "name_b64": b64(raw)}, ensure_ascii=True) + "\n")
        self.withheld_fh.flush()
        self.members_withheld += 1

    def time_left(self):
        return self.deadline - time.monotonic()

    def finish_files(self):
        for fh in (self.members_fh, self.withheld_fh):
            if fh is not None:
                try:
                    fh.flush()
                    os.fsync(fh.fileno())
                    fh.close()
                except OSError:
                    pass
        self.tree.close()

    # -- one member --
    def handle(self, m, opener):
        """Record one member and, when it is a file this run may write, extract it. `opener()` gives a binary stream of its bytes."""
        n, raw = m["n"], m["raw"]
        self.next_index = n + 1
        self.current = n
        comps, flags = name_analysis(raw, m["windows"])
        key = hashlib.blake2b(raw, digest_size=8).digest()
        if key in self.name_seen:
            flags.append("duplicate-name")
            self.duplicate_names += 1
        else:
            self.name_seen.add(key)
        text = raw.decode("utf-8", "surrogateescape")
        shaped = token_shaped(text) or scrub(text) != text
        row = {"n": n, "type": m["kind"], "locator": m["locator"]}
        if shaped:
            row.update(name="<withheld %d characters>" % len(text), name_withheld=True, name_bytes=len(raw))
        else:
            row.update(name=cell(text), name_b64=b64(raw))
        row.update(path=None, size_declared=m.get("size"), packed=m.get("packed"), size_written=None, sha256=None, digest_withheld=False,
                   crc_verified=None, status=None, reason=None,
                   mtime_raw=m.get("mtime_raw"), mtime_utc=m.get("mtime_utc"), mtime_zone=m.get("mtime_zone"), mode=m.get("mode"),
                   uid=m.get("uid"), gid=m.get("gid"), method=m.get("method"))
        if m.get("link") is not None:
            row["link_target"] = scrub(cell(m["link"].decode("utf-8", "surrogateescape")))
        kind = m["kind"]

        def done(status, reason=None, **more):
            row["flags"] = flags
            row["status"], row["reason"] = status, reason
            row.update(more)
            self.record(row)
            self.current = None

        if kind == "dir":
            return done("directory")
        if kind != "file":
            return done("not_created", "a %s is recorded and never created" % kind)
        if m.get("encrypted"):
            return done("encrypted", "the member is encrypted: counted, not extracted (no password is used or guessed)")
        if m.get("unsupported"):
            return done("unsupported", m["unsupported"])
        if len(comps) > self.a["max_depth"]:
            return done("skipped", "depth: %d path components, more than max_depth %d" % (len(comps), self.a["max_depth"]))
        declared = m.get("size")
        if declared is not None and declared > self.a["max_member_bytes"]:
            # The declared size is a claim; the written size decides. A claim already past the budget is not worth opening.
            return done("skipped", "max_member_bytes: declares %d bytes, more than the budget of %d" % (declared, self.a["max_member_bytes"]))
        if self.total_written >= self.a["max_total_bytes"] and declared != 0:
            self.next_index = n
            raise Budget("max_total_bytes", "the total byte budget of %d is used" % self.a["max_total_bytes"])
        # Where it goes.
        if shaped:
            parts, leaf = ["_withheld"], "withheld-%06d%s" % (n, extension_of(raw))
            flags.append("name-withheld")
        elif comps:
            parts, leaf = [render_component(c) for c in comps[:-1]], render_component(comps[-1])
        else:
            parts, leaf = [], "unnamed-%06d" % n
        flat = False
        try:
            dfd, partial, fh = self.tree.create(parts, leaf)
        except OSError as exc:
            if exc.errno in (errno.EEXIST, errno.ENOTDIR, errno.EISDIR, errno.ELOOP, errno.ENAMETOOLONG, errno.EINVAL):
                parts, leaf, flat = ["_flat"], "%06d-%s" % (n, leaf[:100]), True
                try:
                    dfd, partial, fh = self.tree.create(parts, leaf)
                except OSError as exc2:
                    return done("failed", "the file could not be created: %s" % describe(exc2))
            else:
                return done("failed", "the file could not be created: %s" % describe(exc))
        if flat:
            flags.append("flat-path")
        if shaped:
            self.withhold(n, raw, "/".join(parts + [leaf]))
        packed = m.get("packed")
        crc_listed = m.get("crc")
        sha = hashlib.sha256()
        acc = {"crc": 0, "written": 0, "head": b""}
        status, reason, stop = "extracted", None, None
        stream = None
        cap = min(self.a["max_member_bytes"], self.a["max_total_bytes"] - self.total_written)

        def put(block):
            """Write a block that is within the cap; every byte written is counted, hashed and CRC'd."""
            fh.write(block)
            sha.update(block)
            acc["crc"] = zlib.crc32(block, acc["crc"])
            acc["written"] += len(block)
            self.total_written += len(block)
            if len(acc["head"]) < 512:
                acc["head"] += block[:512 - len(acc["head"])]

        try:
            stream = opener()
            while True:
                if self.time_left() <= 0:
                    status, reason, stop = "partial", "max_seconds: the time budget of %d seconds was reached" % self.a["max_seconds"], "max_seconds"
                    break
                block = stream.read(min(CHUNK, cap - acc["written"] + 1))
                if not block:
                    break
                if acc["written"] + len(block) > cap:
                    put(block[:max(0, cap - acc["written"])])
                    which = "max_member_bytes" if cap == self.a["max_member_bytes"] else "max_total_bytes"
                    status = "partial"
                    reason = ("%s: the member is longer than the budget of %d bytes; what was written is kept as .partial"
                              % (which, self.a["max_member_bytes"] if which == "max_member_bytes" else self.a["max_total_bytes"]))
                    if which == "max_total_bytes":
                        stop = which
                    break
                put(block)
                if packed and acc["written"] > self.a["max_ratio"] * max(packed, 1) + RATIO_SLACK:
                    status = "partial"
                    reason = ("max_ratio: %d bytes from %d packed (more than %d times); what was written is kept as .partial"
                              % (acc["written"], packed, self.a["max_ratio"]))
                    break
        except Budget as exc:
            status, reason, stop = "partial", "%s: %s" % (exc.reason, exc), exc.reason
        except Ratio as exc:
            status, reason, stop = "partial", "max_ratio: %s" % exc, "max_ratio"
        except (OSError, EOFError, zlib.error, lzma.LZMAError, tarfile.TarError, zipfile.BadZipFile, NotImplementedError, RuntimeError, ValueError,
                struct.error) as exc:
            msg = describe(exc)
            status = "partial"
            if isinstance(exc, OSError) and exc.errno in (errno.ENOSPC, errno.EDQUOT):
                reason = "write_failed: no space left to write (%s); %d bytes are kept as .partial" % (msg, acc["written"])
                stop = "disk_full"
            else:
                reason = "read_failed: %s" % msg
                # A reader that raises throws away the block it was reading. A stream that knows what it handed out can give back the
                # bytes of this member that were decompressed before the break: they are written too, and the row says how many.
                salvage = getattr(stream, "salvage", None)
                if salvage is not None:
                    try:
                        extra = salvage(acc["written"])[:max(0, cap - acc["written"])]
                        if extra:
                            put(extra)
                            reason += " (%d bytes decompressed before the break were recovered)" % len(extra)
                    except (OSError, ValueError):
                        pass
        finally:
            try:
                fh.flush()
                fh.close()
            except OSError:
                pass
            if stream is not None and hasattr(stream, "close"):
                try:
                    stream.close()
                except Exception:   # noqa: BLE001 - a close that fails changes nothing about the bytes written
                    pass
        written, crc, head = acc["written"], acc["crc"], acc["head"]
        verified = None
        if status == "extracted":
            if declared is not None and written != declared:
                status = "partial"
                reason = ("size_mismatch: the archive declares %d bytes and %d came out%s"
                          % (declared, written, " (the archive ends before the member's declared end)" if written < declared else ""))
            elif crc_listed is not None:
                verified = (crc & 0xFFFFFFFF) == crc_listed
                if not verified:
                    status, reason = "partial", "crc_mismatch: the CRC-32 of the bytes written does not match the archive's record"
        short = written < SHORT_MEMBER
        final = leaf
        if status == "extracted":
            try:
                final = self.tree.publish(dfd, partial, leaf)
            except OSError as exc:
                status, reason = "partial", "the finished file could not take its name: %s" % describe(exc)
        shown = partial if status != "extracted" else final
        if status != "extracted" and written == 0:
            try:
                os.unlink(partial, dir_fd=dfd)       # nothing was written: no empty .partial is left to look like a result
                shown = None
            except OSError:
                pass
        row["path"] = ("extracted/" + "/".join(parts + [shown])) if shown else None
        try:
            os.close(dfd)
        except OSError:
            pass
        if final != leaf and status == "extracted":
            flags.append("renamed-duplicate")
        row["size_written"] = written
        row["sha256"] = None if short else sha.hexdigest()
        row["digest_withheld"] = bool(short)
        if crc_listed is not None and not short:
            row["crc32_listed"] = "%08x" % crc_listed
            row["crc32_written"] = "%08x" % (crc & 0xFFFFFFFF)
        row["crc_verified"] = verified
        kind_of = looks_like(head)
        if kind_of:
            row["looks_like"] = kind_of
            if status == "extracted":
                self.nested.append({"n": n, "path": row["path"], "looks_like": kind_of})
                flags.append("nested-archive")
        done(status, reason)
        if stop:
            if status == "partial":
                self.next_index = n          # the member is not whole: a resume starts it again
            raise Budget(stop, reason or stop)


# ---- readers per format -------------------------------------------------------------------------------------------------

def tar_kind(t):
    if t.isreg():
        return "file"
    if t.isdir():
        return "dir"
    if t.issym():
        return "symlink"
    if t.islnk():
        return "hardlink"
    if t.ischr():
        return "char-device"
    if t.isblk():
        return "block-device"
    if t.isfifo():
        return "fifo"
    return "other"


class HugeHeader(tarfile.ReadError):
    pass


class BoundedInfo(tarfile.TarInfo):
    """tarfile reads a GNU long-name/long-link or pax header's data whole, however large the header says it is: the size is checked first."""

    def _proc_gnulong(self, tf):
        if self.size > META_MAX:
            raise HugeHeader("a GNU long-name or long-link header at offset %d declares %d bytes (more than %d): it is not read" % (self.offset, self.size, META_MAX))
        return super()._proc_gnulong(tf)

    def _proc_pax(self, tf):
        if self.size > META_MAX:
            raise HugeHeader("a pax header at offset %d declares %d bytes (more than %d): it is not read" % (self.offset, self.size, META_MAX))
        return super()._proc_pax(tf)


def tar_member(n, t, compressed):
    raw = t.name.encode("utf-8", "surrogateescape")
    link = t.linkname.encode("utf-8", "surrogateescape") if t.linkname else None
    mt = t.mtime
    return {"n": n, "raw": raw, "windows": False, "kind": tar_kind(t), "size": t.size if t.isreg() else None, "packed": None,
            "mtime_raw": repr(mt), "mtime_utc": iso_utc(mt), "mtime_zone": "utc (tar stores epoch seconds)", "mode": "%o" % t.mode,
            "uid": t.uid, "gid": t.gid, "link": link if tar_kind(t) in ("symlink", "hardlink") else None,
            "locator": "tar:index=%d" % n if compressed else "tar:index=%d;header=%d;data=%d" % (n, t.offset, t.offset_data)}


def run_tar(eng, stream, compressed, from_index, max_members):
    mode = "r|" if compressed else "r:"
    tf = tarfile.open(fileobj=stream, mode=mode, tarinfo=BoundedInfo, encoding="utf-8", errors="surrogateescape") if compressed else \
        tarfile.open(name=stream, mode=mode, tarinfo=BoundedInfo, encoding="utf-8", errors="surrogateescape")
    n = 0
    handled = 0
    last_end = 0
    leftover = b""
    try:
        for t in tf:
            if eng.time_left() <= 0:
                raise Budget("max_seconds", "the time budget of %d seconds was reached" % eng.a["max_seconds"])
            if n >= from_index:
                if handled >= max_members:
                    raise Budget("max_members", "the member budget of %d is used" % max_members)
                if eng.time_left() <= 0:
                    raise Budget("max_seconds", "the time budget of %d seconds was reached" % eng.a["max_seconds"])
                m = tar_member(n, t, compressed)
                if not t.isreg():
                    opener = lambda: None
                elif t.issparse():
                    opener = lambda t=t: tf.extractfile(t)
                elif compressed:
                    opener = lambda t=t: TarMember(tf, t, stream)
                else:
                    opener = lambda t=t: RawSlice(stream, t.offset_data, t.size)
                eng.handle(m, opener)
                handled += 1
            n += 1
            if not compressed:
                last_end = t.offset_data + ((t.size + 511) // 512) * 512 if t.isreg() else t.offset_data
            tf.members = []      # the manifest is on disk: do not hold every header in memory
        eng.extra["members_in_archive"] = n
        if compressed:
            # What tarfile read from the stream beyond the end blocks and did not use: it is part of the rest to be checked.
            leftover = bytes(getattr(getattr(tf, "fileobj", None), "buf", b"") or b"")
    except HugeHeader as exc:
        eng.notes.append("the tar stopped being readable after %d members: %s" % (n, describe(exc)))
        eng.stopped_by, eng.stop_text = "archive_unreadable", describe(exc)
    except (tarfile.TarError, EOFError, zlib.error, lzma.LZMAError, OSError) as exc:
        eng.notes.append("the archive ended or broke after %d members: %s" % (n, describe(exc)))
        eng.stopped_by, eng.stop_text = "archive_unreadable", "the archive ended or broke after %d members: %s" % (n, describe(exc))
    finally:
        try:
            tf.close()
        except Exception:   # noqa: BLE001
            pass
    if compressed and eng.stopped_by is None:
        read_rest(eng, stream, leftover, n)
    if not compressed and eng.stopped_by is None:
        size = os.path.getsize(stream)
        if last_end > size:
            eng.notes.append("member %d's data runs %d bytes past the end of the file: the archive is truncated" % (n - 1, last_end - size))
            eng.stopped_by, eng.stop_text = "archive_truncated", "the last member's data runs past the end of the file"
        else:
            with open(stream, "rb") as fh:
                fh.seek(last_end)
                rest = fh.read(1 << 20)
            if rest.strip(b"\0"):
                eng.notes.append("%d bytes after member %d are not a tar header this reader could read (damaged or not a tar at offset %d)" % (size - last_end, n - 1, last_end))
                eng.stopped_by, eng.stop_text = "archive_unreadable", "bytes after the last member are not a tar header"


def read_rest(eng, stream, leftover, n):
    """A compressed tar is complete only when its whole stream has been read. tarfile stops at the end blocks and reads no further: a
    second archive in the same stream, a further compressed stream, bytes after the last stream, a gzip CRC-32 or ISIZE that does not
    match and a bzip2 or xz stream that does not end would all go unseen. Everything after the end blocks is read here, under the clock
    and the ratio budget, and must be zeros (a tar ends in two zero blocks and zero padding to its record size); anything else stops
    the listing as partial with its offset named, and a rest that the clock or the budget cut short says it was not read to its end."""
    pos = stream.delivered - len(leftover)        # the decompressed offset of the first byte tarfile did not use
    chunk = leftover
    while True:
        if chunk.strip(b"\0"):
            at = pos + len(chunk) - len(chunk.lstrip(b"\0"))
            eng.notes.append("bytes after member %d are not zeros: a further tar header or other data starts at decompressed offset %d (compressed stream %d, %d compressed bytes read); "
                             "the listing holds only the first archive of the stream" % (n - 1, at, stream.streams, stream.consumed))
            eng.stopped_by, eng.stop_text = "archive_unreadable", "bytes after the tar's end blocks are not zeros: the stream holds more than the listed archive"
            return
        pos += len(chunk)
        if eng.time_left() <= 0:
            raise Budget("max_seconds", "the time budget of %d seconds was reached and the compressed stream was not read to its end (%d decompressed bytes read; the rest was not checked)" % (eng.a["max_seconds"], pos))
        try:
            chunk = stream.read(CHUNK)
        except Ratio as exc:
            raise Ratio("%s; the compressed stream was not read to its end after %d decompressed bytes" % (exc, pos))
        except (EOFError, zlib.error, lzma.LZMAError, OSError) as exc:
            eng.notes.append("the compressed stream does not end cleanly after the last member (decompressed offset %d): %s" % (pos, describe(exc)))
            eng.stopped_by, eng.stop_text = "archive_unreadable", "the compressed stream fails its integrity check or does not end: %s" % describe(exc)
            return
        if not chunk:
            return


def zip_declared(path):
    """The member count and the central directory's size the end-of-central-directory record declares (zip64 too), read before zipfile loads it."""
    size = os.path.getsize(path)
    with open_regular(path) as fh:
        fh.seek(max(0, size - 65557))
        tail = fh.read()
    at = tail.rfind(b"PK\x05\x06")
    if at < 0 or at + 22 > len(tail):
        return None, None
    total = struct.unpack_from("<H", tail, at + 10)[0]
    cd_bytes = struct.unpack_from("<I", tail, at + 12)[0]
    if total == 0xFFFF or cd_bytes == 0xFFFFFFFF:
        loc = tail.rfind(b"PK\x06\x07", 0, at)
        if loc >= 0:
            with open_regular(path) as fh:
                fh.seek(struct.unpack_from("<Q", tail, loc + 8)[0])
                rec = fh.read(56)
            if rec[:4] == b"PK\x06\x06":
                total = struct.unpack_from("<Q", rec, 32)[0]
                cd_bytes = struct.unpack_from("<Q", rec, 40)[0]
    return total, cd_bytes


def zip_ext_time(extra):
    """The UTC mtime from an extended-timestamp field (0x5455), or None."""
    i = 0
    while i + 4 <= len(extra):
        hid, size = struct.unpack_from("<HH", extra, i)
        body = extra[i + 4:i + 4 + size]
        if hid == 0x5455 and len(body) >= 5 and body[0] & 1:
            return struct.unpack_from("<I", body, 1)[0]
        i += 4 + size
    return None


ZIP_METHODS = {0: "stored", 8: "deflate", 12: "bzip2", 14: "lzma"}


def run_zip(eng, path, from_index, max_members):
    declared, cd_bytes = zip_declared(path)
    if declared is not None:
        eng.extra["members_declared"] = declared
    if cd_bytes is not None and cd_bytes > ZIP_DIRECTORY_MAX:
        raise ArchiveError("the central directory is %d bytes, more than the %d this tool reads into memory (every entry is held, about 500 bytes each): "
                           "nothing was extracted; list it with the archive-members recipe, or split the archive" % (cd_bytes, ZIP_DIRECTORY_MAX), members_declared=declared)
    wanted = max(from_index + max_members, 1) * ZIP_DIRECTORY_FACTOR
    if cd_bytes is not None and cd_bytes > (1 << 20) and cd_bytes // 46 > wanted:
        # the count in the end record is the archive's claim and zipfile reads the directory by its size: an entry is at least 46 bytes
        raise ArchiveError("the central directory is %d bytes, room for more than %d entries (%d times the max_members of %d, and from_index %d), whatever the end record's count says: "
                           "the whole directory is loaded to extract any of it, so it is not loaded for that few; nothing was extracted. Raise max_members to at least %d"
                           % (cd_bytes, wanted, ZIP_DIRECTORY_FACTOR, max_members, from_index, -(-(cd_bytes // 46) // ZIP_DIRECTORY_FACTOR)), members_declared=declared)
    if declared is not None and declared > wanted:
        raise ArchiveError("the central directory declares %d members, more than %d times the max_members of %d (and from_index %d): the whole directory is loaded to extract any of it, "
                           "so it is not loaded for that few; nothing was extracted. Raise max_members to at least %d to extract from this archive"
                           % (declared, ZIP_DIRECTORY_FACTOR, max_members, from_index, -(-declared // ZIP_DIRECTORY_FACTOR)), members_declared=declared)
    try:
        zf = zipfile.ZipFile(path)
    except (zipfile.BadZipFile, OSError, NotImplementedError, ValueError, EOFError) as exc:
        raise ArchiveError("zip: the central directory cannot be read (%s)" % describe(exc), local_headers_seen=count_local_headers(path),
                           note="a damaged or truncated zip: its local headers are counted, not trusted; nothing was extracted")
    handled = 0
    with zf:
        infos = zf.infolist()
        eng.extra["members_in_archive"] = len(infos)
        for n, info in enumerate(infos):
            if n < from_index:
                continue
            if handled >= max_members:
                raise Budget("max_members", "the member budget of %d is used" % max_members)
            if eng.time_left() <= 0:
                raise Budget("max_seconds", "the time budget of %d seconds was reached" % eng.a["max_seconds"])
            utf8 = bool(info.flag_bits & 0x800)
            raw = info.orig_filename.encode("utf-8" if utf8 else "cp437", "surrogateescape")
            mode = (info.external_attr >> 16) & 0xFFFF
            unix = info.create_system == 3
            if info.is_dir():
                kind = "dir"
            elif unix and (mode & 0o170000) == 0o120000:
                kind = "symlink"
            elif unix and (mode & 0o170000) in (0o020000, 0o060000, 0o010000):
                kind = {0o020000: "char-device", 0o060000: "block-device", 0o010000: "fifo"}[mode & 0o170000]
            else:
                kind = "file"
            ext = zip_ext_time(info.extra)
            if ext is not None:
                mtime_raw, mtime_utc, zone = "extended timestamp %d" % ext, iso_utc(ext), "utc (extended timestamp 0x5455)"
            else:
                mtime_raw = "%04d-%02d-%02d %02d:%02d:%02d" % info.date_time
                mtime_utc, zone = None, "unknown (DOS local time, 2-second resolution; no zone is stored)"
            encrypted = bool(info.flag_bits & 0x1) or info.compress_type == 99
            unsupported = None
            if not encrypted and info.compress_type not in ZIP_METHODS and kind == "file":
                unsupported = "compression method %d is not one this build reads (stored, deflate, bzip2 and lzma are)" % info.compress_type
            link = None
            if kind == "symlink" and not encrypted and unsupported is None:
                try:
                    with zf.open(info) as lf:
                        link = lf.read(LINK_TARGET_MAX + 1)[:LINK_TARGET_MAX]
                except Exception as exc:   # noqa: BLE001 - a link target that cannot be read is said, not fatal
                    link = ("<unreadable: %s>" % describe(exc)).encode()
            m = {"n": n, "raw": raw, "windows": True, "kind": kind, "size": info.file_size, "packed": info.compress_size, "mtime_raw": mtime_raw,
                 "mtime_utc": mtime_utc, "mtime_zone": zone, "mode": ("%o" % mode) if mode else None, "uid": None, "gid": None, "link": link,
                 "encrypted": encrypted, "unsupported": unsupported, "crc": info.CRC, "method": ZIP_METHODS.get(info.compress_type, "method %d" % info.compress_type),
                 "locator": "zip:index=%d;header=%d" % (n, info.header_offset)}
            eng.handle(m, lambda info=info: zip_stream(zf, info))
            handled += 1


def zip_stream(zf, info):
    """The member's bytes. zipfile checks the CRC when the last byte is read and then raises instead of returning that byte; this
    tool checks the CRC itself (it keeps what was read, and says the CRC did not match), so the library's check is off."""
    stream = zf.open(info)
    if hasattr(stream, "_expected_crc"):
        stream._expected_crc = None
    return stream


def count_local_headers(path, cap=64 * 1024 * 1024):
    """How many local file headers (PK 03 04) the first `cap` bytes hold: a count for a zip whose directory is gone, not a listing."""
    count, tail = 0, b""
    try:
        with open_regular(path) as fh:
            seen = 0
            while seen < cap:
                block = fh.read(CHUNK)
                if not block:
                    break
                seen += len(block)
                data = tail + block
                count += data.count(b"PK\x03\x04")
                tail = data[-3:]
    except OSError:
        return None
    return count


class ArchiveError(Exception):
    def __init__(self, message, **extra):
        super().__init__(message)
        self.extra = extra


def parse_gzip_header(head):
    """(name bytes or None, mtime int) from a gzip member header (RFC 1952), or (None, None) when it cannot be read from `head`."""
    if len(head) < 10 or head[:3] != b"\x1f\x8b\x08":
        return None, None
    flg, mtime = head[3], struct.unpack_from("<I", head, 4)[0]
    pos = 10
    if flg & 4:
        if len(head) < pos + 2:
            return None, mtime
        pos += 2 + struct.unpack_from("<H", head, pos)[0]
    name = None
    if flg & 8:
        end = head.find(b"\0", pos)
        if end < 0:
            return None, mtime
        name = head[pos:end]
    return name, mtime


def run_single(eng, path, kind, dec, from_index):
    """One compressed file that is not a tar: ONE member."""
    with open_regular(path) as fh:
        head = fh.read(4096)
    name, mtime = parse_gzip_header(head) if kind == "gzip" else (None, None)
    base = os.path.basename(path)
    source = "the gzip header's file name" if name else "the archive's own name without its compression suffix"
    if not name:
        stem = re.sub(r"\.(gz|gzip|bz2|bzip2|xz|zst|zstd|z)$", "", base, flags=re.I)
        name = os.fsencode(stem or "data")
    m = {"n": 0, "raw": name, "windows": False, "kind": "file", "size": None, "packed": os.path.getsize(path), "mtime_raw": str(mtime) if mtime else None,
         "mtime_utc": iso_utc(mtime) if mtime else None, "mtime_zone": "utc (gzip stores epoch seconds; 0 means none)" if kind == "gzip" else None,
         "mode": None, "uid": None, "gid": None, "link": None, "locator": "%s:stream" % kind, "method": kind}
    eng.extra["single_file_name_from"] = source
    eng.extra["members_in_archive"] = 1
    if from_index > 0:
        return
    eng.handle(m, lambda: dec)


# ---- 7z ----------------------------------------------------------------------------------------------------------------

def find_7z():
    for name in SEVEN_Z_NAMES:
        found = shutil.which(name)
        if found:
            return found
    return None


def banner(program, seconds=15):
    if seconds <= 0:
        return None
    try:
        proc = spawn([program], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=dict(os.environ, LC_ALL="C"))
        ACTIVE.append(proc)
        try:
            out, _, _ = communicate_bounded(proc, min(15, seconds))
        finally:
            if proc in ACTIVE:
                ACTIVE.remove(proc)
        for line in out.decode("utf-8", "replace").splitlines():
            if line.strip():
                return line.strip()[:200]
    except OSError:
        pass
    return None


def listing_records(path):
    """The records of `7z l -slt -ba` as dicts of bytes, one per blank-line-separated block, read a line at a time."""
    fields = {}
    with open_regular(path) as fh:
        for line in fh:
            if len(line) > LISTING_LINE_MAX:
                raise ArchiveError("7z printed a listing line of more than %d bytes" % LISTING_LINE_MAX)
            line = line.rstrip(b"\r\n")
            if not line:
                if b"Path" in fields:
                    yield fields
                fields = {}
                continue
            if b" = " in line:
                k, v = line.split(b" = ", 1)
                fields[k.strip()] = v
            elif line.endswith(b" =") and b" = " not in line:
                fields[line[:-2].strip()] = b""
    if b"Path" in fields:
        yield fields


def seven_member(n, f):
    attrs = f.get(b"Attributes", b"").decode("ascii", "replace")
    mode_text = attrs.split(" ", 1)[1] if " " in attrs else ""
    folder = f.get(b"Folder") == b"+" or attrs.startswith("D")
    if folder:
        kind = "dir"
    elif mode_text[:1] == "l":
        kind = "symlink"
    elif mode_text[:1] in ("c", "b", "p"):
        kind = {"c": "char-device", "b": "block-device", "p": "fifo"}[mode_text[:1]]
    else:
        kind = "file"
    mod = f.get(b"Modified", b"").decode("ascii", "replace").strip()
    size = f.get(b"Size", b"").strip()
    crc = f.get(b"CRC", b"").strip()
    return {"n": n, "raw": f[b"Path"], "windows": True, "kind": kind, "size": int(size) if size.isdigit() else None, "packed": None,
            "mtime_raw": mod or None, "mtime_utc": (mod.replace(" ", "T") + "Z") if mod else None,
            "mtime_zone": "utc (7z's listing was run with TZ=UTC; resolution 100 ns)" if mod else None,
            "mode": mode_text or attrs or None, "uid": None, "gid": None, "link": None, "encrypted": f.get(b"Encrypted") == b"+",
            "crc": int(crc, 16) if re.fullmatch(rb"[0-9A-Fa-f]{1,8}", crc) else None, "method": f.get(b"Method", b"").decode("ascii", "replace") or None,
            "locator": "7z:index=%d" % n}


class Pipe:
    """The bytes 7z writes to its stdout, read with the clock running; split into members by the sizes of its own listing."""

    def __init__(self, proc, deadline, max_ratio=None, packed=0):
        self.fd = proc.stdout.fileno()
        self.deadline = deadline
        self.eof = False
        self.total = 0
        self.max_ratio, self.packed = max_ratio, packed    # the whole output is held to max_ratio times the archive's size

    def read(self, n):
        if self.eof or n <= 0:
            return b""
        while True:
            left = self.deadline - time.monotonic()
            if left <= 0:
                raise Budget("max_seconds", "the time budget was reached while 7z was still writing")
            if select.select([self.fd], [], [], min(left, 5))[0]:
                break
        data = os.read(self.fd, min(n, CHUNK))
        if not data:
            self.eof = True
        self.total += len(data)
        if self.max_ratio and self.total > self.max_ratio * max(self.packed, 1) + RATIO_SLACK:
            raise Ratio("7z wrote %d bytes from an archive of %d (more than %d times)" % (self.total, self.packed, self.max_ratio))
        return data


class Piece:
    """`size` bytes of the pipe: one member's. A read past the member's end gives nothing; a pipe that ends first is said."""

    def __init__(self, pipe, size):
        self.pipe, self.remaining, self.short = pipe, size, False

    def read(self, n=-1):
        if self.remaining <= 0:
            return b""
        data = self.pipe.read(min(n if n and n > 0 else CHUNK, self.remaining))
        if not data:
            self.short = True
            raise EOFError("7z's output ended %d bytes before this member's declared size" % self.remaining)
        self.remaining -= len(data)
        return data

    def drain(self):
        while self.remaining > 0:
            self.read(CHUNK)


def run_7z(eng, path, from_index, max_members, sevenz):
    env = dict(os.environ, TZ="UTC", LANG="C.UTF-8", LC_ALL="C.UTF-8")
    listing = eng.out_root / first_free(str(eng.out_root), "7z-listing", ".txt")
    stderr_l = eng.out_root / first_free(str(eng.out_root), "7z-list.stderr", "")
    with private_file(str(listing), "wb") as out_fh, private_file(str(stderr_l), "wb") as err_fh:
        proc = spawn([sevenz, "l", "-slt", "-ba", "--", path], stdout=out_fh, stderr=err_fh, env=env)
        ACTIVE.append(proc)
        try:
            rc = proc.wait(timeout=max(1.0, eng.time_left()))
        except subprocess.TimeoutExpired:
            kill_tree(proc)
            proc.wait()
            raise Budget("max_seconds", "the time budget was used by 7z's listing")
        finally:
            if proc in ACTIVE:
                ACTIVE.remove(proc)
    err_text = ""
    try:
        with open(stderr_l, "rb") as fh:
            err_text = fh.read(2000).decode("utf-8", "replace").strip()
        if not err_text:
            os.unlink(stderr_l)
        else:
            eng.extra["listing_stderr_file"] = stderr_l.name
    except OSError:
        pass
    eng.extra["listing_file"] = listing.name
    eng.extra["listing_exit"] = rc
    # One pass over the listing to learn what the archive holds; the members are read again, a block at a time, below.
    n_all = encrypted_n = device_n = 0
    names_plain, names_all = {}, {}
    for n, f in enumerate(listing_records(str(listing))):
        if n % 1024 == 0 and eng.time_left() <= 0:
            raise Budget("max_seconds", "the time budget of %d seconds was used reading 7z's listing, after %d members" % (eng.a["max_seconds"], n))
        m = seven_member(n, f)
        n_all += 1
        encrypted_n += 1 if m["encrypted"] else 0
        device_n += 1 if m["kind"] in ("char-device", "block-device", "fifo") else 0
        names_all[f[b"Path"]] = names_all.get(f[b"Path"], 0) + 1
        if m["kind"] in ("file", "symlink") and not m["encrypted"] and m["size"] is not None:
            names_plain[f[b"Path"]] = names_plain.get(f[b"Path"], 0) + 1
    if n_all == 0:
        raise ArchiveError("7z listed no member (exit %s): %s" % (rc, scrub(err_text) or "nothing on stderr"), listing_exit=rc,
                           note="a 7z whose headers are encrypted cannot be listed without its password; none is used or guessed, so nothing was extracted")
    eng.extra["members_in_archive"] = n_all
    eng.extra["encrypted_members"] = encrypted_n
    # With an encrypted member or a device the stream is asked for by name: only the plain files that can be named are in it,
    # in listing order. Otherwise 7z is asked for everything and the stream holds every file, in listing order.
    select_mode = encrypted_n > 0 or device_n > 0
    argv = [sevenz, "x", "-so", "-y", "-bd"]
    unselectable = set()
    selection = None
    if select_mode:
        selection = eng.out_root / first_free(str(eng.out_root), "7z-selection", ".txt")
        refused = set()
        with private_file(str(selection), "wb") as sfh:
            for nm, k in sorted(names_plain.items()):
                # a spelling shared with a member that is not selected cannot be told apart from it in the stream; a line break,
                # an empty name or a leading dash cannot be passed in a list file
                if names_all[nm] != k or b"\n" in nm or b"\r" in nm or not nm or nm.startswith(b"-"):
                    refused.add(nm)
                    continue
                sfh.write(nm + b"\n")
        unselectable = refused
        eng.extra["selection_file"] = selection.name
        argv += ["-spd", "-scsUTF-8"]
    # No `--` here: 7z reads a list file named @file only before it, and a path that starts with a dash is given as ./path.
    argv.append(path if not path.startswith("-") else "./" + path)
    if selection is not None:
        argv.append("@" + str(selection))
    stderr_x = eng.out_root / first_free(str(eng.out_root), "7z-extract.stderr", "")
    err_fh = private_file(str(stderr_x), "wb")
    proc = spawn(argv, stdout=subprocess.PIPE, stderr=err_fh, env=env)
    ACTIVE.append(proc)
    pipe = Pipe(proc, eng.deadline, eng.a["max_ratio"], os.path.getsize(path))
    handled = 0
    desync = False
    try:
        for n, f in enumerate(listing_records(str(listing))):
            m = seven_member(n, f)
            name = f[b"Path"]
            in_stream = m["kind"] in ("file", "symlink") and not m["encrypted"] and m["size"] is not None and name not in unselectable
            piece = Piece(pipe, m["size"]) if in_stream else None
            if n < from_index:
                if piece is not None:
                    piece.drain()
                continue
            if handled >= max_members:
                raise Budget("max_members", "the member budget of %d is used" % max_members)
            if eng.time_left() <= 0:
                raise Budget("max_seconds", "the time budget of %d seconds was reached" % eng.a["max_seconds"])
            if m["kind"] == "symlink" and piece is not None:
                target = b""
                try:
                    while piece.remaining and len(target) <= LINK_TARGET_MAX:
                        target += piece.read(min(piece.remaining, LINK_TARGET_MAX + 1 - len(target)))
                except EOFError:
                    desync = True
                m["link"] = target[:LINK_TARGET_MAX]
            elif m["kind"] == "file" and piece is None and not m["encrypted"]:
                if m["size"] is None:
                    m["unsupported"] = "7z's listing gives no size for this member, so its bytes cannot be told apart in the stream"
                else:
                    m["unsupported"] = "the name cannot be passed to 7z in a list file (a line break, a leading dash, or a spelling shared with a member that is not a plain file)"
            eng.handle(m, (lambda piece=piece: piece) if (piece is not None and m["kind"] == "file") else (lambda: None))
            handled += 1
            if piece is not None:
                try:
                    piece.drain()
                except EOFError:
                    desync = True
        # Anything after the last declared byte is output the listing does not account for.
        if not desync and not pipe.eof:
            try:
                extra = pipe.read(1)
            except Budget:
                extra = b""
            if extra:
                eng.notes.append("7z wrote more bytes than its listing declares: the CRC of each member says which are whole")
                eng.extra["stream_longer_than_listing"] = True
    finally:
        try:
            proc.stdout.close()
        except OSError:
            pass
        kill_tree(proc)
        rc2 = proc.wait()
        if proc in ACTIVE:
            ACTIVE.remove(proc)
        err_fh.close()
    eng.extra["extract_exit"] = rc2 if rc2 >= 0 else "killed by signal %d" % -rc2
    try:
        if os.path.getsize(stderr_x) == 0:
            os.unlink(stderr_x)
        else:
            eng.extra["extract_stderr_file"] = stderr_x.name
    except OSError:
        pass
    if desync:
        eng.notes.append("7z's output ended before its listing did: the members after that point are not in the stream (see their statuses)")
        eng.stopped_by, eng.stop_text = eng.stopped_by or "archive_unreadable", "7z's output ended before its listing did"


# ---- detection ---------------------------------------------------------------------------------------------------------

def tar_header_ok(block):
    if len(block) < 512:
        return False
    try:
        tarfile.TarInfo.frombuf(block[:512], "utf-8", "surrogateescape")
        return True
    except Exception:   # noqa: BLE001 - any failure to read the block as a header means it is not one
        return False


def detect(path):
    """(format, detail). Format is zip, 7z, tar, gzip, bzip2, xz, zstd, or an unsupported name, from the bytes."""
    with open_regular(path) as fh:
        head = fh.read(4096)
    if head.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        return "zip", "zip signature at offset 0"
    if head.startswith(SEVEN_Z_MAGIC):
        return "7z", "7z signature at offset 0"
    kind = looks_like(head)
    if kind in ("gzip", "bzip2", "xz", "zstd"):
        return kind, "%s signature at offset 0" % kind
    if head[257:262] == b"ustar" or tar_header_ok(head[:512]) and head[:512].strip(b"\0"):
        return "tar", "tar header at offset 0"
    if kind in ("rar", "cab"):
        return "unsupported:" + kind, "%s signature at offset 0" % kind
    if head[:4] == b"\xd0\xcf\x11\xe0":
        return "unsupported:ole", "OLE compound file signature"
    # A zip with something in front of it (a self-extractor): the end-of-central-directory record still says what it is.
    try:
        size = os.path.getsize(path)
        with open_regular(path) as fh:
            fh.seek(max(0, size - 65557))
            if b"PK\x05\x06" in fh.read():
                return "zip", "no signature at offset 0, but an end-of-central-directory record at the end (a zip with a prefix)"
    except OSError:
        pass
    return None, "not a zip, tar, gzip, bzip2, xz, zstd or 7z archive: its first bytes are %s" % head[:16].hex()


def sha256_of(path, limit, deadline):
    """(sha256, None), or (None, why it was not taken): the archive is larger than `limit`, or the run's clock ran out after some bytes.
    Opened without blocking and checked to be a regular file on the descriptor; the clock is read for every block."""
    size = os.path.getsize(path)
    if size > limit:
        return None, "the archive is larger than %d bytes" % limit
    h = hashlib.sha256()
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(fd, "rb") as fh:
        if not stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
            raise OSError(0, "not a regular file any more")
        done = 0
        for block in iter(lambda: fh.read(CHUNK), b""):
            h.update(block)
            done += len(block)
            if time.monotonic() > deadline:
                return None, "the time budget ran out after %d bytes of the archive were hashed" % done
    return h.hexdigest(), None


# ---- main --------------------------------------------------------------------------------------------------------------

def main():
    try:
        args = json.load(sys.stdin)
    except (ValueError, RecursionError) as exc:
        fail("arguments are not valid JSON", reason=str(exc)[:200])
    if not isinstance(args, dict):
        fail("arguments are a JSON object")
    path = args.get("path")
    if not isinstance(path, str) or not path or "\0" in path:
        fail("path is required: the archive to extract")
    try:
        path.encode("utf-8")
    except UnicodeEncodeError:
        fail("path holds a lone surrogate and cannot be written in an answer")
    a = {
        "from_index": whole(args, "from_index", 0, 0, 1 << 40),
        "max_total_bytes": whole(args, "max_total_bytes", MAX_TOTAL_DEFAULT, 1, BYTES_CEILING),
        "max_member_bytes": whole(args, "max_member_bytes", MAX_MEMBER_DEFAULT, 1, BYTES_CEILING),
        "max_members": whole(args, "max_members", MAX_MEMBERS_DEFAULT, 1, MAX_MEMBERS_CEILING),
        "max_ratio": whole(args, "max_ratio", MAX_RATIO_DEFAULT, 1, MAX_RATIO_CEILING),
        "max_depth": whole(args, "max_depth", MAX_DEPTH_DEFAULT, 1, MAX_DEPTH_CEILING),
        "max_seconds": whole(args, "max_seconds", MAX_SECONDS_DEFAULT, 1, MAX_SECONDS_CEILING),
        "limit": whole(args, "limit", LIMIT_DEFAULT, 1, LIMIT_CEILING),
    }
    resume = args.get("resume", False)
    if not isinstance(resume, bool):
        fail("resume is true or false")
    for key in ("name", "member", "members", "filter", "pattern", "glob"):
        if key in args:
            fail("%s is not a parameter: members are chosen by number (from_index), never by a filter over names, which would answer questions about withheld text" % key)
    unknown = sorted(set(args) - {"path", "out_dir", "resume", "from_index", "max_total_bytes", "max_member_bytes", "max_members", "max_ratio", "max_depth", "max_seconds", "limit"})
    if unknown:
        fail("unknown parameter: %s" % ", ".join(scrub(str(k)) for k in unknown))
    if not os.path.exists(path):
        fail("archive not found", path=scrub(path))
    if not os.path.isfile(path):
        fail("path is not a regular file", path=scrub(path))
    try:
        size = os.path.getsize(path)
    except OSError as exc:
        fail("the archive cannot be read: %s" % describe(exc), path=scrub(path))
    if size == 0:
        fail("the archive is empty (0 bytes)", path=scrub(path))

    try:
        fmt, why = detect(path)
    except OSError as exc:
        fail("the archive cannot be read: %s" % describe(exc), path=scrub(path))
    if fmt is None or fmt.startswith("unsupported:"):
        fail("unsupported or unrecognised archive: %s" % why, path=scrub(path), format=fmt, bytes=size,
             supported=["zip", "tar (plain, gzip, bzip2, xz, zstd)", "gzip, bzip2, xz, zstd (a single file)", "7z (with the 7z program)"])

    os.umask(0o077)
    st = os.stat(path)
    digest = hashlib.sha256(("%s|%d|%d" % (os.path.abspath(path), size, st.st_mtime_ns)).encode("utf-8", "surrogateescape")).hexdigest()[:12]
    if args.get("out_dir"):
        if not isinstance(args["out_dir"], str) or "\0" in args["out_dir"]:
            fail("out_dir is a directory path")
        dest = resolve_output(args["out_dir"])
    elif in_job():
        dest = resolve_output(os.path.join(os.environ["OUT"], "archive_extract-" + digest))
    else:
        agent = re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool")
        dest = resolve_output(os.path.join("work", agent, "archive_extract-" + digest))
    try:                    # exists(), is_dir() and iterdir() raise for a name too long, a directory that cannot be searched, a loop: a refusal, never a traceback
        if not args.get("out_dir") and dest.exists() and not resume:
            k = 2
            while Path("%s.%d" % (dest, k)).exists():
                k += 1
            dest = Path("%s.%d" % (dest, k))
        if dest.exists() and not dest.is_dir():
            fail("out_dir exists and is not a directory", out_dir=scrub(str(dest)))
        if dest.exists() and any(dest.iterdir()) and not resume:
            fail("out_dir already holds files: an extraction never writes over an earlier one. Pass a new out_dir, or resume: true (with from_index) "
                 "to go on in this one; the new manifest is written beside the earlier one", out_dir=scrub(str(dest)))
        if resume and dest.exists() and not (dest / "extracted").is_dir():
            fail("resume: true needs an out_dir an earlier run made (it has no extracted/ directory)", out_dir=scrub(str(dest)))
    except (OSError, ValueError, RuntimeError) as exc:
        fail("out_dir cannot be used: %s" % describe(exc), out_dir=scrub(str(args.get("out_dir") or dest)))
    try:
        made_dest, made_extracted = not dest.exists(), not (dest / "extracted").exists()
        dest.mkdir(parents=True, exist_ok=True, mode=0o700)
        if made_dest:
            os.chmod(dest, 0o700)               # a directory the caller made keeps the caller's mode; one made here is private
        (dest / "extracted").mkdir(mode=0o700, exist_ok=True)
        if made_extracted:
            os.chmod(dest / "extracted", 0o700)
    except OSError as exc:
        fail("the output directory cannot be made: %s" % describe(exc), out_dir=scrub(str(dest)))
    run_no = 1
    while (dest / ("receipt.json" if run_no == 1 else "receipt.%d.json" % run_no)).exists():
        run_no += 1

    info = {"path": scrub(path), "bytes": size, "format": fmt, "detected_by": why, "sha256": None}
    sevenz = None
    if fmt == "7z":
        sevenz = find_7z()
        if sevenz is None:
            fail("a 7z archive needs the 7z program (7z, 7zz or 7za), which is not on PATH; nothing was extracted", path=scrub(path), format="7z",
                 install="apt-get install -y p7zip-full, or brew install sevenzip")
        info["program"] = {"path": sevenz, "banner": banner(sevenz, STARTED + a["max_seconds"] - time.monotonic())}
    try:
        info["sha256"], why_not = sha256_of(path, HASH_ARCHIVE_MAX, STARTED + a["max_seconds"])
    except OSError as exc:
        fail("the archive cannot be read: %s" % describe(exc), path=scrub(path))
    if info["sha256"] is None:
        info["sha256_skipped"] = "%s; the run's own record of the input has its sha256" % why_not
    info["python"] = sys.version.split()[0]
    if resume:
        # A resume goes on in the directory of an earlier run of THIS archive: another archive's members would be mixed into it.
        try:
            with open(dest / "receipt.json", encoding="utf-8") as fh:
                earlier = json.load(fh)["archive"]
        except (OSError, ValueError, KeyError, TypeError):
            fail("resume: true needs the receipt of the earlier run (receipt.json) in out_dir, and it is not readable", out_dir=scrub(str(dest)))
        if earlier.get("bytes") != size or (earlier.get("sha256") and info["sha256"] and earlier["sha256"] != info["sha256"]):
            fail("this is not the archive the earlier run in out_dir extracted (its size or sha256 differs): a resume goes on with the same archive, "
                 "and an extraction of another archive takes a directory of its own", out_dir=scrub(str(dest)), earlier_bytes=earlier.get("bytes"),
                 earlier_sha256=earlier.get("sha256"), this_bytes=size, this_sha256=info["sha256"])

    try:
        eng = Engine(a, dest, run_no, info)
    except OSError as exc:
        fail("the output directory cannot be opened for writing: %s" % describe(exc), out_dir=scrub(str(dest)))
    eng.write_receipt()

    def last_word(signum):
        eng.stopped_by, eng.stop_text = "signal", "stopped by signal %d" % signum
        eng.next_index = eng.current if eng.current is not None else eng.next_index
        eng.extra["stopped_by_signal"] = signum
        eng.status = "interrupted"
        eng.write_receipt()
        eng.finish_files()
        # one document on stdout: a stop is not a status (the statuses are complete, partial and failed), it is partial with interrupted true
        print(json.dumps({"ok": False, "tool": TOOL, "status": "partial", "interrupted": True, "signal": signum, "out_dir": scrub(str(dest)),
                          "members_seen": eng.rows, "next_index": eng.next_index, "receipt": eng.receipt_path.name if not eng.receipt_error else None,
                          "receipt_error": eng.receipt_error,
                          "status_basis": "the tool was stopped by signal %d: the members already written are on disk (an unfinished one is a .partial file), "
                                          "members_file lists them, and next_index is where a run with from_index and resume true goes on" % signum}), flush=True)
    STATE["last_word"] = last_word

    dec = None
    try:
        try:
            if fmt == "zip":
                run_zip(eng, path, a["from_index"], a["max_members"])
            elif fmt == "7z":
                run_7z(eng, path, a["from_index"], a["max_members"], sevenz)
            elif fmt == "tar":
                run_tar(eng, path, False, a["from_index"], a["max_members"])
            else:
                if fmt == "zstd":
                    which, mod = zstd_module()
                    if which is None:
                        raise ArchiveError("zstd: %s" % mod, format="zstd")
                    info["zstd_reader"] = which
                dec = Decomp(path, fmt, a["max_ratio"])
                peek = b""
                try:
                    peek = dec.read(512)
                except Ratio as exc:
                    raise ArchiveError("the compressed stream's first block already breaks the ratio budget: %s" % exc)
                except (EOFError, zlib.error, lzma.LZMAError, OSError, Unsupported) as exc:
                    raise ArchiveError("%s: the stream cannot be decompressed (%s)" % (fmt, describe(exc)))
                dec.unread(peek)
                if tar_header_ok(peek) and (peek[257:262] == b"ustar" or peek.strip(b"\0")):
                    info["format"] = "tar+" + fmt
                    run_tar(eng, dec, True, a["from_index"], a["max_members"])
                else:
                    info["format"] = fmt + " (a single file)"
                    run_single(eng, path, fmt, dec, a["from_index"])
                if dec.trailing:
                    eng.notes.append("%d bytes after the last %s stream are not another stream and were not decompressed" % (dec.trailing, fmt))
                    eng.extra["trailing_bytes"] = dec.trailing
                    if dec.trailing_nonzero and info["format"].startswith("tar+") and eng.stopped_by is None:
                        eng.stopped_by, eng.stop_text = "archive_unreadable", "bytes after the last compressed stream are not a stream (and not zero padding)"
                eng.extra["compressed_streams"] = dec.streams
        except Budget as exc:
            eng.stopped_by, eng.stop_text = exc.reason, scrub(str(exc))
        except Ratio as exc:
            eng.stopped_by, eng.stop_text = "max_ratio", scrub(str(exc))
        except Unsupported as exc:
            raise ArchiveError("zstd: %s" % exc, format="zstd")
        except (SystemExit, KeyboardInterrupt, ArchiveError):
            raise
        except Exception as exc:   # noqa: BLE001 - a defect in this tool or an input it did not foresee: said as JSON, with what was done kept
            eng.extra["rows_before_the_failure"] = eng.rows
            raise ArchiveError("internal error after %d member(s): %s: %s" % (eng.rows, type(exc).__name__, scrub(str(exc))), next_index=eng.next_index)
    except ArchiveError as exc:
        eng.finish_files()
        out = {"ok": False, "status": "failed", "error": scrub(str(exc)), "tool": TOOL, "archive": info, "out_dir": scrub(str(dest)), **exc.extra}
        eng.status = "failed"
        eng.stopped_by, eng.stop_text = "archive_unreadable", scrub(str(exc))
        eng.extra.update(exc.extra)
        eng.write_receipt()
        say(out, 1)
    finally:
        if dec is not None:
            dec.close()
    eng.finish_files()
    eng.status = None
    eng.write_receipt()
    receipt = eng.receipt()
    if eng.receipt_error:
        receipt["status"] = "failed" if receipt["status"] == "failed" else "partial"
        receipt["status_basis"] = ("the extraction ran, but %s could not be written (%s): the members already written are on disk, and the answer "
                                   "is the only record of the run" % (eng.receipt_path.name, eng.receipt_error))
        receipt["receipt_error"] = eng.receipt_error
    out = {"ok": True, **receipt, "members": eng.page,
           "members_returned": len(eng.page), "members_truncated": eng.rows > len(eng.page),
           "note": ("the inline members are a page; members_file has every member" if eng.rows > len(eng.page) else None)}
    if eng.stopped_by in ("archive_unreadable", "archive_truncated") and eng.rows == 0:
        out["ok"] = False
        say(out, 1)
    say(out, 0)


if __name__ == "__main__":
    main()
