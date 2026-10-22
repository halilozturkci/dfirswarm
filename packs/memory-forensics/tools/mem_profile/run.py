#!/usr/bin/env python3
"""Say what a memory file's header shows, before anything is run against it.

Memory arrives in half a dozen shapes and they are not interchangeable. A
framework handed the wrong one returns an error that reads exactly like a
corrupt image, and an hour goes into the wrong question.

This is a first pass at the file's header and a sample of its bytes. It names a
container only when the header says so; a file with no header this tool knows is
"unrecognised", which is what a flat capture (a raw image, a .vmem) looks like and
also what a file that is not memory looks like. It is not validation: confirm the
format, the architecture, the captured ranges and the completeness before framework
analysis.

The one that matters most: **a Windows crash dump is not contiguous physical
memory**. Its header carries a run list, pairs of (starting page, page count), and
the file holds the runs one after another, so a physical address is not a file
offset. The runs are printed with both, and checked against each other and against
the size of the file, so that mistake is visible rather than silent.

Headers recognised:

    "PAGEDUMP" / "PAGEDU64"   Windows crash dump, 32- and 64-bit
    "HIBR" / "WAKE" / zeroed  hibernation file: a saved state, not read here
    "EMiL"                    LiME: its ranges are walked, header by header
    "AVML"                    recognised by its first four bytes; its framing is not read
    \\x7fELF                   an ELF file; type 4 is a core dump (byte order from e_ident)

What the answer prints from the capture is header facts: numbers, the four-letter state of a hibernation file, and two strings that sit in
a capture as free text, a kernel release (kernel_build) and a Windows build string (version_user). Those two are shown only when they have
the grammar of a version, a closed list of tags (the SHOWN block): a secret placed where a version should be, or glued to one, is not printed, and the banner around a kernel
release is not printed at all (kernel_build_offset says where it is). The tool stops its sampling by itself after SCAN_SECONDS, and a signal
ends it with one JSON answer (status interrupted, exit 128 plus the signal). The walk of a LiME file's headers has its own clock
(LIME_WALK_SECONDS) and cap; when it stops before the end of the file (container.walk_complete false) the status is partial.
"""
import errno
import hashlib
import json
import os
import re
import signal
import struct
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

PARSER = "mem_profile/4"
HINTS = [
    (b"Windows", "Windows"), (b"Linux version ", "Linux"),
    (b"Darwin Kernel Version", "macOS or iOS"), (b"FreeBSD", "FreeBSD"),
]
STRUCTURES = [
    (b"regf", "registry hive"), (b"ElfChnk\x00", "event log chunk"),
    (b"MAM\x04", "compressed prefetch record"), (b"MZ\x90\x00", "PE header"),
    (b"SQLite format 3\x00", "SQLite database"), (b"INDX", "NTFS index block"),
    (b"FILE0", "MFT record"),
]
CHUNK = 1 << 22
MAX_SCAN_MB = 4096
FIRST_OFFSETS = 5
LIME_MAGIC = 0x4C694D45  # the bytes "EMiL"
LIME_HEADER = 32
LIME_WALK_CAP = 1_000_000
LIME_WALK_SECONDS = 60  # the walk of a LiME file's headers stops here (one read per range); the sampling that follows has its own SCAN_SECONDS
LIME_CHECK_EVERY = 1024  # ranges between two looks at the clock
RANGE_PAGE = 200
SCAN_SECONDS = 200      # the sampling stops here; the manifest's limit is 300


# BEGIN SHARED WITHHOLDING
# The same text is in every tool that withholds identifier-shaped strings (the network, base, virtualization and
# reverse-engineering packs), so that they withhold the same strings; the tests that hold the copies equal are
# tests/pack-network-withholding.test.ts, tests/pack-base-shared.test.ts, tests/pack-virtualization-shared.test.ts and
# tests/pack-re-process.test.ts. An identifier-shaped string is withheld wherever the tool would print one: a name, a
# path component, a URL, a message that quotes either.
COUNTS = {"names": 0, "urls": 0, "text": 0}
# A run of name characters long enough to be a token. `=` is only a padding at the end (so a key= prefix stays);
# `/` joins pieces of a base64 token and is handled apart, below.
_RUN = re.compile(r"[A-Za-z0-9_+%-]{20,}={0,2}|[A-Za-z0-9_+%-]{14,}={2}")
_SLASHED = re.compile(r"[A-Za-z0-9_+/%-]{30,}={0,2}")
_HEX = re.compile(r"[0-9a-fA-F]{32,}")
_PREFIXED = re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}"
                       r"|xox[abeprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9_-]{20,}"
                       r"|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*"
                       r"|(?i:basic|bearer)\s+[A-Za-z0-9+/=._~-]{8,}")
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
# A text longer than this is withheld whole, by its length, and not examined: the examination is linear, but a text of
# millions of characters is not one a name or a URL is, and the answer says how long it was.
TEXT_LIMIT = 2097152


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
    spans = [m.span() for m in _PREFIXED.finditer(text)]
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


def scrub(text, kind="text"):
    """The text with every token-shaped run and every user-info withheld."""
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
    return "".join(out)


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
# keys of 20 to 32 characters 10 to 61, a 24-character base36 key 48 to 65, a base64 key holding `/` 37 to 40. The prefixes of the vendors in _PREFIX2 and _PREFIXED are read at 0 in 3,400 plants per shape. Printed at
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
        found = [(m.start(), m.end(), "token-shaped text") for m in _PREFIXED.finditer(masked)]
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
# where a larger one was; the name actually used is the one in `shown`), and a stop removes or names the temporary file.
def same_bytes(a, b):
    """Whether two files hold the same bytes (read in blocks, never whole)."""
    try:
        if os.path.getsize(a) != os.path.getsize(b):
            return False
        with open(a, "rb") as fa, open(b, "rb") as fb:
            while True:
                x, y = fa.read(1 << 20), fb.read(1 << 20)
                if x != y:
                    return False
                if not x:
                    return True
    except OSError:
        return False


def place_without_replacing(tmp, path):
    """Move the finished `tmp` to `path` and never replace what is there, a file or a link: the name is taken first with an
    exclusive create that does not follow links; a file of the same bytes is named again, any other result takes the next free
    <stem>-<n><suffix>. Returns the path that holds it."""
    for n in range(1, 1000):
        candidate = path if n == 1 else path.with_name("%s-%d%s" % (path.stem, n, path.suffix))
        try:
            fd = os.open(str(candidate), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileExistsError:
            if not os.path.islink(candidate) and same_bytes(tmp, candidate):
                os.unlink(tmp)
                return candidate
            continue
        os.close(fd)
        os.replace(tmp, candidate)             # only replaces the empty file this call just made
        return candidate
    raise OSError(errno.EEXIST, "no free name beside %s" % path)


PAGES = []


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
            fd, name = tempfile.mkstemp(dir=self.path.parent, prefix=f".{self.path.name}-")
            self._tmp = Path(name)
            self._out = os.fdopen(fd, "w", encoding="ascii")
            for kept in self.page:
                self._write(json.dumps(kept, default=str))
        self._write(line)

    def finish(self) -> dict:
        result = {"matched": self.total, "returned": len(self.page), "truncated": self.total > len(self.page)}
        if self._out is not None:
            self._out.flush()
            os.fsync(self._out.fileno())
            self._out.close()
            self._out = None
            assert self._tmp is not None
            placed = place_without_replacing(self._tmp, self.path)
            self._tmp = None
            self.path = placed
            self.shown = self.shown[: len(self.shown) - len(self.shown.rsplit("/", 1)[-1])] + placed.name
            result["all_results"] = self.shown
            result["all_results_format"] = "JSON Lines, one complete result per line"
        return result

    def abort(self) -> None:
        """Drop the hidden temporary file of a run that failed part way."""
        if self._out is not None:
            self._out.close()
            self._out = None
        if self._tmp is not None:
            try:
                os.unlink(self._tmp)
            except FileNotFoundError:
                pass
            self._tmp = None

    def keep_partial(self):
        """Close the temporary file and give it a visible name ending in .partial (never replacing a file); returns the
        path, or None when nothing was being written. Whole lines only are in it when the rows were added whole."""
        if self._out is None or self._tmp is None:
            return None
        try:
            self._out.flush()
            self._out.close()
        except OSError:
            pass
        self._out = None
        placed = place_without_replacing(self._tmp, self.path.with_name(self.path.name + ".partial"))
        self._tmp = None
        return placed
# END SHARED PAGE


# --- stopping: a signal ends the tool with one JSON answer ------------------------------

class Terminated(BaseException):
    def __init__(self, signum):
        super().__init__(signum)
        self.signum = signum


def _on_signal(signum, _frame):
    raise Terminated(signum)


def emit(answer):
    print(json.dumps(sealed(answer), indent=2), flush=True)


def fail(message, **extra):
    emit({"error": message, "status": "failed",
          "status_basis": "the call was refused or ended before an answer; nothing in this document is a finding about the evidence", **extra})
    raise SystemExit(1)


def filetime(value):
    """A Windows FILETIME (100 ns ticks since 1601-01-01 UTC) as ISO 8601 with its seven fractional digits.

    Returns (text, None) or (None, why): a value that is not a time this tool can write is
    said with its raw value, never turned into a silent null.
    """
    try:
        seconds, ticks = divmod(value, 10_000_000)
        moment = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=seconds)
    except (OverflowError, ValueError):
        return None, "the FILETIME %d is out of range: it is past the year 9999, so it is not a time" % value
    return moment.strftime("%Y-%m-%dT%H:%M:%S") + ".%07dZ" % ticks, None


def crash_dump(fh, wide, size):
    """The run list is the whole reason to read this header."""
    out = {"format": "Windows crash dump", "bits": 64 if wide else 32}
    problems = []
    fh.seek(0)
    header_bytes = 0x2000 if wide else 0x1000
    head = fh.read(header_bytes)
    try:
        if wide:
            out["major_version"], out["minor_version"] = struct.unpack_from("<II", head, 0x08)
            out["directory_table_base"] = struct.unpack_from("<Q", head, 0x10)[0]
            out["machine_image_type"] = hex(struct.unpack_from("<I", head, 0x30)[0])
            out["processors"] = struct.unpack_from("<I", head, 0x34)[0]
            bugcheck = struct.unpack_from("<I", head, 0x38)[0]
            out["bugcheck_code"] = hex(bugcheck)
            marker = struct.pack("<I", bugcheck)
            if all(0x20 <= b < 0x7f for b in marker):
                out["bugcheck_code_note"] = (
                    "the field contains printable bytes %r and may be acquisition-tool filler, "
                    "not a Windows bugcheck" % marker.decode("ascii", "replace"))
            runs_at = 0x88
            runs_start = runs_at + 0x10  # descriptor padding + 64-bit NumberOfPages
            dump_type_at, system_time_at, uptime_at = 0xF98, 0xFA8, 0x1030
            version_at = 0x60
        else:
            out["major_version"], out["minor_version"] = struct.unpack_from("<II", head, 0x08)
            out["directory_table_base"] = struct.unpack_from("<I", head, 0x10)[0]
            out["machine_image_type"] = hex(struct.unpack_from("<I", head, 0x20)[0])
            out["processors"] = struct.unpack_from("<I", head, 0x24)[0]
            runs_at = 0x64
            runs_start = runs_at + 8
            dump_type_at, system_time_at, uptime_at = 0xF88, 0xFC0, 0xFB8
            version_at = 0x3C

        version_raw = head[version_at:version_at + 32].split(b"\0", 1)[0]
        # Some acquisition tools fill unused header fields with a repeated
        # four-byte marker (for example PAGE).  Do not present that as an OS
        # version string.
        chunks = [version_raw[i:i + 4] for i in range(0, len(version_raw), 4)]
        if version_raw and not (len(version_raw) % 4 == 0 and len(set(chunks)) == 1):
            # The field is 32 bytes of the capture: it is shown only when it has the grammar of a Windows build string.
            text = version_raw.decode("ascii", "replace")
            printed = shown(text, "build")
            if printed == text:
                out["version_user"] = printed
            else:
                out["version_user"] = None
                out["version_user_withheld"] = printed
        out["dump_type"] = struct.unpack_from("<I", head, dump_type_at)[0]
        system_time = struct.unpack_from("<Q", head, system_time_at)[0]
        # The raw FILETIME beside the decoded time (epoch 1601-01-01, UTC, 100 ns ticks).
        out["system_time_filetime"] = system_time
        out["system_time_utc"], why = filetime(system_time)
        if why:
            problems.append("SystemTime: " + why)
        elif system_time == 0:
            out["system_time_note"] = ("FILETIME 0 is 1601-01-01T00:00:00Z itself: the header may simply not have been "
                                       "filled in, so it records no time")
        out["system_uptime_100ns"] = struct.unpack_from("<Q", head, uptime_at)[0]

        # Only a complete dump (type 1) describes memory as a run array here.
        # Bitmap/active dumps use a summary bitmap after the header instead.
        if out["dump_type"] == 1:
            count = struct.unpack_from("<I", head, runs_at)[0]
            pages = struct.unpack_from("<Q" if wide else "<I", head, runs_at + (8 if wide else 4))[0]
            width = 8 if wide else 4
            available = max(0, (len(head) - runs_start) // (width * 2))
            if not 0 < count <= available:
                problems.append(
                    "the physical-memory run count is %d, but the header holds at most %d" %
                    (count, available))
            else:
                runs, cursor, file_offset = [], runs_start, header_bytes
                for _ in range(count):
                    if wide:
                        base, length = struct.unpack_from("<QQ", head, cursor)
                    else:
                        base, length = struct.unpack_from("<II", head, cursor)
                    cursor += width * 2
                    # physical_start is an address in the guest's physical memory; file_offset is
                    # where the run's first page is in this file: the runs are stored in order,
                    # one after another, after the header.
                    runs.append({"start_page": base, "pages": length,
                                 "physical_start": base * 4096, "bytes": length * 4096,
                                 "file_offset": file_offset})
                    file_offset += length * 4096
                out["memory_runs"] = runs
                out["run_count"] = count
                out["pages_total"] = pages
                out["runs_pages_total"] = sum(run["pages"] for run in runs)
                out["header_bytes"] = header_bytes
                if out["runs_pages_total"] != pages:
                    problems.append(
                        "the run lengths total %d pages, not the descriptor's %d" %
                        (out["runs_pages_total"], pages))
                for before, after in zip(runs, runs[1:]):
                    if after["start_page"] < before["start_page"]:
                        problems.append(
                            "the runs are not in ascending order: the run at page %d follows the run at page %d" %
                            (after["start_page"], before["start_page"]))
                    elif after["start_page"] < before["start_page"] + before["pages"]:
                        problems.append(
                            "runs overlap: the run at page %d starts inside the run at page %d (%d pages)" %
                            (after["start_page"], before["start_page"], before["pages"]))
                # Adjacent means each run starts at the page after the previous one ends.
                out["contiguous"] = all(
                    after["start_page"] == before["start_page"] + before["pages"]
                    for before, after in zip(runs, runs[1:]))
                payload = max(0, size - header_bytes)
                declared = out["runs_pages_total"] * 4096
                out["payload_bytes"] = payload
                out["runs_declare_bytes"] = declared
                if payload < declared:
                    problems.append(
                        "the file holds %d bytes after the header and the runs declare %d: the dump is shorter than its run list" %
                        (payload, declared))
                elif payload > declared:
                    out["trailing_bytes"] = payload - declared
        else:
            out["memory_layout"] = (
                "dump type %d uses a bitmap/summary layout; use a crash-dump-aware framework "
                "to map its physical pages" % out["dump_type"])
    except struct.error:
        problems.append("the header is shorter than the format requires")
    if problems:
        out["problems"] = problems
    return out


def elf_header(head):
    """e_ident gives the class (byte 4) and the byte order (byte 5) of every later field."""
    out = {"format": "ELF"}
    problems = []
    if len(head) < 20:
        problems.append("the ELF header is shorter than 20 bytes (%d): no type or machine to read" % len(head))
        out["problems"] = problems
        return out
    cls, data = head[4], head[5]
    if cls not in (1, 2):
        problems.append("EI_CLASS is %d, neither 1 (32-bit) nor 2 (64-bit)" % cls)
    else:
        out["bits"] = 32 if cls == 1 else 64
    if data not in (1, 2):
        problems.append("EI_DATA is %d, neither 1 (little-endian) nor 2 (big-endian): the type is not read" % data)
        out["problems"] = problems
        return out
    order = "<" if data == 1 else ">"
    out["endian"] = "little" if data == 1 else "big"
    elf_type, machine = struct.unpack_from(order + "HH", head, 16)
    out["elf_type"] = elf_type
    out["machine"] = machine
    out["format"] = "ELF core" if elf_type == 4 else "ELF (type %d)" % elf_type
    if elf_type == 4:
        out["segments"] = "not enumerated: a core's PT_LOAD segments map file bytes to addresses, and this tool does not read them"
    if problems:
        out["problems"] = problems
    return out


def lime_ranges(fh, size, deadline=None):
    """Walk a LiME file range by range: each is a 32-byte header and then the bytes it frames. `walk_complete` says whether the walk
    reached the end of the file; a walk that stopped (a header that is not LiME's, the cap, the clock, a range that runs past the file) did not."""
    page = LosslessPage("mem_profile", [os.path.realpath(fh.name), "lime ranges"], RANGE_PAGE)
    problems, position, total, version, previous_start, previous_end = [], 0, 0, None, None, None
    while position < size and page.total < LIME_WALK_CAP:
        if deadline is not None and page.total % LIME_CHECK_EVERY == 0 and time.monotonic() >= deadline:
            problems.append("the walk stopped at its time limit (%d s) after %d ranges, with %d bytes after offset %d not walked" %
                            (LIME_WALK_SECONDS, page.total, size - position, position))
            break
        fh.seek(position)
        head = fh.read(LIME_HEADER)
        if len(head) < LIME_HEADER:
            problems.append("the file ends inside a LiME header at offset %d (%d bytes of 32)" % (position, len(head)))
            break
        magic, found_version, start, end = struct.unpack_from("<IIQQ", head, 0)
        if magic != LIME_MAGIC:
            problems.append("no LiME magic at offset %d: the walk stopped there, with %d bytes after it not walked" % (position, size - position))
            break
        if version is None:
            version = found_version
        if found_version != 1:
            problems.append("the LiME header at offset %d has version %d; only version 1 is read, so the walk stopped there" % (position, found_version))
            break
        if end < start:
            problems.append("the LiME header at offset %d ends (0x%x) before it starts (0x%x)" % (position, end, start))
            break
        length = end - start + 1
        data_at = position + LIME_HEADER
        if previous_end is not None and start <= previous_end:
            problems.append("the range at offset %d starts at 0x%x, not after the end of the range before it (0x%x): the ranges are %s" %
                            (position, start, previous_end, "out of order" if start < previous_start else "overlapping"))
        previous_start, previous_end = start, end
        page.add({"physical_start": start, "physical_end": end, "bytes": length, "file_offset": data_at})
        total += length
        if data_at + length > size:
            problems.append(
                "the range at offset %d declares %d bytes and the file holds %d after its header: the file ends inside the range" %
                (position, length, size - data_at))
            break
        position = data_at + length
    else:
        if position < size:
            problems.append("the walk stopped at %d ranges (the cap), with %d bytes after offset %d not walked" % (page.total, size - position, position))
    paged = page.finish()
    out = {"format": "LiME", "version": version, "range_count": paged["matched"], "ranges": page.page,
           "walk_complete": position >= size,
           "physical_bytes_total": total,
           "ranges_note": "the ranges as the LiME headers frame them, in file order; the file is the ranges one after another, so a physical address is not a file offset"}
    if paged.get("all_results"):
        out["ranges_all"] = paged["all_results"]
        out["ranges_truncated"] = True
    if problems:
        out["problems"] = problems
    return out


def identify(path, deadline=None):
    size = os.path.getsize(path)
    with open(path, "rb") as fh:
        head = fh.read(64)
        if head[:8] == b"PAGEDUMP":
            return {**crash_dump(fh, False, size), "recognition_basis": "the first 8 bytes are PAGEDUMP"}, size
        if head[:8] == b"PAGEDU64":
            return {**crash_dump(fh, True, size), "recognition_basis": "the first 8 bytes are PAGEDU64"}, size
        if head[:4] in (b"HIBR", b"hibr", b"WAKE", b"wake"):
            return {"format": "hibernation file", "state": head[:4].decode("ascii", "replace"),
                    "compression": "not read: a hibernation file's pages are usually compressed, and this tool does not decode them",
                    "recognition_basis": "the first 4 bytes are %s" % head[:4].decode("ascii", "replace")}, size
        if head[:4] == b"EMiL":
            return {**lime_ranges(fh, size, deadline), "recognition_basis": "the first 4 bytes are the LiME magic"}, size
        if head[:4] == b"AVML":
            return {"format": "AVML", "recognition_basis": "the first 4 bytes are AVML",
                    "framing": "not read by this tool: its ranges and compression are not described here"}, size
        if head[:4] == b"\x7fELF":
            return {**elf_header(head), "recognition_basis": "the first 4 bytes are the ELF magic"}, size
        if not any(head[:16]) and path.lower().endswith("hiberfil.sys"):
            return {"format": "hibernation file, header cleared",
                    "recognition_basis": "the first 16 bytes are zero and the name is hiberfil.sys",
                    "note": "a resumed hibernation file has its header zeroed; the compressed "
                            "pages are usually still there"}, size
        container = {
            "format": "unrecognised",
            "recognition_basis": "no known container header in the first 64 bytes",
            "interpretation": "the file may be flat physical memory (a raw capture or a .vmem has no header), "
                              "a container this tool does not know, or not memory at all; nothing here shows which",
        }
        extension = os.path.splitext(path.lower())[1]
        if extension in (".vmem", ".raw", ".mem", ".lime", ".dmp", ".bin"):
            container["name_hint"] = "the extension %s is a hint only" % extension
        return container, size


def sample_ranges(size, megabytes):
    """The head, the middle and the tail, merged where they touch or overlap.

    Each range is scanned on its own, so a match is never joined across two
    windows that are not adjacent in the file, and a byte is never counted twice.
    """
    window = megabytes * 1024 * 1024 // 3 or 1
    spots = [0, max(0, size // 2 - window // 2), max(0, size - window)]
    raw = sorted((spot, min(size, spot + window)) for spot in spots)
    merged = []
    for lo, hi in raw:
        if merged and lo <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], hi))
        else:
            merged.append((lo, hi))
    return merged


def scan(path, ranges, needles, deadline):
    """Count each needle in each range separately, streaming; return the counts, the first offsets, and whether the clock ended it.

    A range is read in blocks, and a block is searched with the end of the one before it, so a
    needle across a block boundary is counted once. The count is made by the engine's own
    counter over the part of the buffer no earlier block owned, so a dense file costs a count
    and not a loop per match. One pass serves every needle, and the clock is looked at between blocks.
    """
    overlap = max(len(n) for n, _label in needles) - 1
    counts = {label: 0 for _n, label in needles}
    first = {label: [] for _n, label in needles}
    stopped = None
    with open(path, "rb") as fh:
        for lo, hi in ranges:
            position, tail, tail_at, accept_lo = lo, b"", lo, lo
            while position < hi:
                if time.monotonic() >= deadline:
                    stopped = position
                    return counts, first, stopped
                fh.seek(position)
                block = fh.read(min(CHUNK, hi - position))
                if not block:
                    break
                buf, base = tail + block, tail_at
                block_end = position + len(block)
                # A needle that starts before accept_hi lies wholly inside buf; one that starts
                # later is found in the next buffer, which begins at accept_hi.
                accept_hi = hi if block_end >= hi else max(accept_lo, block_end - overlap)
                for needle, label in needles:
                    own = buf[accept_lo - base:accept_hi - base + len(needle) - 1]
                    counts[label] += own.count(needle)
                    at = 0
                    while len(first[label]) < FIRST_OFFSETS:
                        found = own.find(needle, at)
                        if found < 0:
                            break
                        first[label].append(accept_lo + found)
                        at = found + 1
                accept_lo = accept_hi
                keep = accept_hi - base
                tail, tail_at = buf[keep:], base + keep
                position = block_end
    return counts, first, stopped


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    if not isinstance(args, dict):
        fail("arguments must be a JSON object")
    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: a memory image, dump or hibernation file")
    if not os.path.isfile(path):
        fail("no such file", path=path)
    megabytes = args.get("scan_mb", 64)
    if not isinstance(megabytes, int) or isinstance(megabytes, bool) or not 1 <= megabytes <= MAX_SCAN_MB:
        fail("scan_mb must be an integer from 1 to %d: it is a sample for hints, and the ranges actually read are in the answer" % MAX_SCAN_MB)
    size = os.path.getsize(path)
    if size == 0:
        fail("the file is empty: there is nothing to profile", path=path)

    started = time.monotonic()
    container, size = identify(path, started + LIME_WALK_SECONDS)
    ranges = sample_ranges(size, megabytes)
    counts, first, scan_stopped = scan(path, ranges, [(n, label) for n, label in HINTS] + [(n, label) for n, label in STRUCTURES],
                                       started + SCAN_SECONDS)
    os_counts = {label: counts[label] for _n, label in HINTS}
    os_first = {label: first[label] for _n, label in HINTS}
    struct_counts = {label: counts[label] for _n, label in STRUCTURES}
    struct_first = {label: first[label] for _n, label in STRUCTURES}
    systems = sorted(label for label, n in os_counts.items() if n)
    structures = {label: n for label, n in struct_counts.items() if n}
    build, build_at, build_withheld = None, None, None
    if os_first.get("Linux"):
        build_at = os_first["Linux"][0]
        with open(path, "rb") as fh:
            fh.seek(build_at)
            # The kernel release is the first word after "Linux version ": the banner around it (builder, compiler, date) is not printed.
            found = re.match(rb"Linux version ([^\x00\n ()]{1,80})", fh.read(120))
        if found:
            text = found.group(1).decode("ascii", "replace")
            printed = shown(text, "release")
            if printed == text:
                build = printed
            else:
                build_withheld = printed

    problems = list(container.get("problems", []))
    out = {
        "path": path,
        "parser": PARSER,
        "bytes": size,
        "file_pages_4k_estimate": size // 4096,
        "container": container,
        "operating_system_hints": systems,
        "operating_system_hint_offsets": {label: offsets for label, offsets in os_first.items() if offsets},
        "kernel_build": build,
        "kernel_build_offset": build_at,
        "kernel_build_note": ("the release only (the first word after 'Linux version '), and only when it has the grammar of a release; "
                              "the banner around it is not printed: read it at kernel_build_offset in a job run as secret output"),
        "structures_in_sample": structures,
        "structure_first_offsets": {label: offsets for label, offsets in struct_first.items() if offsets},
        "sampled_megabytes": megabytes,
        "sampled_ranges": [{"offset": lo, "bytes": hi - lo} for lo, hi in ranges],
        "bytes_sampled": sum(hi - lo for lo, hi in ranges),
        "problems": problems,
        "notes": [
            "file_pages_4k_estimate is the file's length divided by 4096. It is not a count of captured "
            "physical pages: a container's framing, its ranges and any gaps are not accounted for in it.",
            "Structure and operating-system counts are signature counts in the sampled ranges only "
            "(sampled_ranges), each range read on its own; they are hints, not counts for the file.",
        ],
    }
    if out["bytes_sampled"] < size:
        out["notes"].append(
            "Only %d of %d bytes were sampled (head, middle and tail). Raise scan_mb for more; a hint "
            "that is absent from the sample says nothing about the rest of the file." % (out["bytes_sampled"], size))
    if container.get("format", "").startswith("Windows crash dump") and container.get("contiguous") is False:
        out["notes"].append(
            "This dump is not contiguous: %d memory runs with gaps between them. A tool that "
            "treats the file as flat physical memory reads the wrong offset for everything after "
            "the first gap." % container.get("run_count", 0))
    if "hibernation" in container.get("format", ""):
        out["notes"].append(
            "A hibernation file is a saved state, not the state at acquisition. Say which moment you "
            "are quoting once its time has been established from the file and the acquisition record.")
    if not systems:
        out["notes"].append(
            "No operating-system string in the sample. That is normal for a small sample of a "
            "large image; raise scan_mb before concluding anything from it.")
    if build_withheld is not None:
        out["kernel_build_withheld"] = build_withheld
    if scan_stopped is not None:
        out["scan_stopped_at"] = scan_stopped
        out["notes"].append("The sampling ran out of time (SCAN_SECONDS %d) at offset %d: the counts cover what was read before that, and the "
                            "ranges after it were not read. Lower scan_mb or profile a copy on a faster disk." % (SCAN_SECONDS, scan_stopped))
        out["status"] = "partial"
        out["status_basis"] = "the sampling stopped at its time limit (offset %d), so the counts cover only part of the sampled ranges" % scan_stopped
    else:
        out["status"] = "complete"
        out["status_basis"] = ("the header was read and the sample ranges named in sampled_ranges were scanned in full; this is a first pass, "
                               "not a validation of the capture")
    if container.get("walk_complete") is False:
        walk = ("the walk of the LiME headers stopped before the end of the file (container.problems says where and why), so the range list "
                "is not the capture's whole framing")
        out["status_basis"] = walk if out["status"] == "complete" else out["status_basis"] + "; " + walk
        out["status"] = "partial"
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
        for page in list(PAGES):
            page.abort()
        emit({"error": "stopped by signal %d before the profile was complete" % stopped.signum, "status": "interrupted",
              "status_basis": "the tool was stopped by signal %d; nothing it had read is an answer, and no partial file was left" % stopped.signum,
              "signal": stopped.signum, "parser": PARSER})
        raise SystemExit(128 + stopped.signum)
    except Exception as exc:  # never an empty or clean answer for a failure
        fail("unexpected failure: %s: %s" % (type(exc).__name__, exc))


if __name__ == "__main__":
    run_guarded()
