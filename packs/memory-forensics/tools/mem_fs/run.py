#!/usr/bin/env python3
"""Drive MemProcFS, which turns a memory image into a file tree, for one call.

MemProcFS is AGPL-3.0, the same licence as this harness, and this pack drives it
as a separate executable. Volatility remains at its own executable boundary
under its Volatility Software License 1.0; the skills invoke `vol` directly.

What the mount gives: sys/proc for the process list, a directory per process
holding its modules, handles, memory map and the regions MemProcFS can read, and
the parsed artefacts it builds. All of it is files, for the length of the call.

This tool starts MemProcFS, does one thing with the tree and stops it, so nothing
is left holding the evidence open. The mount is gone when the call returns: what
survives is the files an export wrote. Three modes:

    list     names, kinds and sizes of a directory (or one file): metadata, no content
    text     one file that is UTF-8 text, written to a file under $OUT/mem_fs
    export   the named virtual files, copied byte for byte to $OUT/mem_fs, with their
             sizes and sha256 in a sealed manifest beside them

THE SECRET-SAFE OUTPUT PATTERN (docs/packs.md, "Secrets and sensitive output"),
copied from recovery_key_scan, the reference implementation, with one change: the
value here is a file. A memory file can hold anything the machine held (a command
line, an environment block, a key, a page of a process), so:

  1. The answer is a locator: virtual path, output file, size, status. It carries
     no content, no characters of it and no digest of it. A digest is in the
     manifest file only. A name the engine lists, and a line it prints, come from the
     capture too: they are judged before they are shown (the SHOWN block), and the
     originals of what was withheld go to a names file only on write_values.
  2. Content is written only when the caller asks (`write_values: true`), only when
     the tool runs as a job (JOB_ID and OUT are set) that the harness runs as secret
     output (SECRET_OUTPUT=1, which this tool's manifest makes it set), and only under
     $OUT/mem_fs, mode 0600, created exclusively. Anywhere else the request is refused
     as JSON before MemProcFS is started.
  3. A secret is never on a command line: this tool takes paths and flags only.

Mounting needs FUSE (a /dev/fuse the process can open, and fusermount3 or fusermount
to unmount), which a sandbox may not allow. When it fails the phase and the reason are
returned, with the engine's own output kept in files (mode 0600) and its first lines
shown after judging, because "no framework was available" is a legitimate line in a
report and "the memory was examined and nothing was found" is not. A log keeps the first LOG_CAP
bytes of its stream (a thread always reads the pipe, so a verbose engine neither stops on a full
pipe nor fills the disk); the answer counts what was read after that and discarded.

The tool stops by itself: timeout_seconds is at most 480, so the end of the call (the
engine's stop, its unmount, the last file) stays inside the manifest's 600. A signal
(SIGTERM, SIGINT, SIGHUP) ends it with one JSON answer (status interrupted, exit 128 plus
the signal), after the engine is stopped and the mount released.
"""
import codecs
import errno
import hashlib
import json
import os
import random
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

PARSER = "mem_fs/5"
CHUNK = 1 << 20
DEFAULT_TIMEOUT = 300
MIN_TIMEOUT = 2
MAX_TIMEOUT = 480          # 480 s + the engine's stop and unmount (at most 65 s) stays inside the manifest's 600
DEFAULT_MAX_BYTES = 4 << 30
MAX_PATHS = 1000
PAGE = 200
MAX_PAGE = 5000
CLEANUP_WAIT = 20
OUT_DIR = "mem_fs"
MANIFEST = "export-manifest.jsonl"
ENGINE_LINES = 20
LOG_CAP = 1 << 20          # bytes of each engine stream kept in its log file; the rest is counted and discarded
ENGINE_LINE_CHARS = 200
MAX_OUTPUT_COMPONENT = 200


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
    """Raised by the signal handler in the main thread. A BaseException, so no `except Exception` swallows it and every `finally` runs."""

    def __init__(self, signum):
        super().__init__(signum)
        self.signum = signum


GUARD = {"depth": 0, "pending": None, "stopping": False}
STATE = {"logs": None, "secret": None}


def _on_signal(signum, _frame):
    if GUARD["stopping"]:
        return
    if GUARD["depth"]:
        GUARD["pending"] = signum            # the engine is being stopped: that is finished first, then the stop is raised
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
    """The one way out: the answer is sealed (every string the tool did not judge goes through the backstop) and printed."""
    print(json.dumps(sealed(answer), indent=2), flush=True)


def fail(message, **extra):
    emit({"error": message, "status": "failed",
          "status_basis": "the call was refused or ended before an answer; nothing in this document is a finding about the evidence", **extra})
    raise SystemExit(1)


def interrupted_answer(signum, **extra):
    emit({"error": "stopped by signal %d before the call was complete" % signum, "status": "interrupted",
          "status_basis": "the tool was stopped by signal %d; the engine was stopped and the mount released, and what an export had written "
                          "before that is kept and named" % signum, "signal": signum, "parser": PARSER, **extra})


class SecretValuesRefused(Exception):
    pass


def make_private_dirs(path):
    """mkdir -p where every directory it creates has mode 0700 (Path.mkdir(parents=True, mode=...) gives the parents the default mode,
    so the names of what is below them would be listed by anyone)."""
    missing, here = [], Path(path)
    while not os.path.lexists(here):
        missing.append(here)
        if here.parent == here:
            break
        here = here.parent
    for directory in reversed(missing):
        try:
            os.mkdir(str(directory), 0o700)
        except FileExistsError:
            pass


class SecretValues:
    """Where content read from memory goes when, and only when, the caller asked for it.

    The secret-safe output pattern of recovery_key_scan, with a file for a value:
    `open_value` makes the output file, exclusively and private, under
    $OUT/mem_fs; `note` adds one row to the manifest beside them (append-only: a second
    call in the same job adds its rows, and never fails for the first one's file). With
    `enabled` false nothing is written and `summary()` says so.
    """

    def __init__(self, enabled: bool):
        self.enabled = enabled
        self.written = 0
        self._manifest = None
        self.job = os.environ.get("JOB_ID") or ""
        self.out = os.environ.get("OUT") or ""
        if enabled and not (self.job and self.out):
            raise SecretValuesRefused(
                "write_values is refused outside a job: a file written here would be an ordinary file, not a sealed "
                "secret output, and memory can hold anything the machine held. Run this as job_run tool=mem_fs "
                "(its manifest declares secret_output, so the job is sealed as secret output) and ask again there; mode list without write_values needs no job. "
                "Nothing was written and MemProcFS was not started.")
        if enabled and os.environ.get("SECRET_OUTPUT") != "1":
            raise SecretValuesRefused(
                "write_values is refused in a job that was not run as secret output: its files would be sealed as ordinary "
                "output. Run this as job_run tool=mem_fs (its manifest declares secret_output, which the harness enforces and signals with SECRET_OUTPUT=1). Nothing was written and "
                "MemProcFS was not started.")
        self.root = Path(self.out) / OUT_DIR if enabled else None
        job_name = re.sub(r"[^A-Za-z0-9_.-]", "_", self.job)
        # Whether or not THIS call writes values, an earlier call of the same job may have: the job's output is what is sealed, and the
        # answer must not say it holds no values because this call asked for none.
        self.values_root = Path(self.out) / OUT_DIR if (self.job and self.out) else None
        self.shown = ("store/jobs/%s/out/%s" % (job_name, OUT_DIR)) if self.values_root is not None else None
        self.earlier = self._holds()

    def shown_path(self, rel: str) -> str:
        return "%s/%s" % (self.shown, rel)

    def open_value(self, rel: str) -> int:
        """A file descriptor for $OUT/mem_fs/<rel>, created exclusively, never through a link, mode 0600. The file is counted the moment it exists."""
        assert self.root is not None
        target = self.root / rel
        make_private_dirs(target.parent)
        parent, root = target.parent.resolve(), self.root.resolve()
        if parent != root and root not in parent.parents:
            raise OSError(errno.EPERM, "the output directory is not inside $OUT/%s" % OUT_DIR)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(str(target), flags, 0o600)
        self.written += 1
        return fd

    def open_unique(self, rel: str):
        """Like open_value, for a file this tool names itself: the next free name when an earlier call took this one."""
        stem, dot, suffix = rel.rpartition(".")
        for n in range(1000):
            name = rel if n == 0 else "%s.%d.%s" % (stem, n, suffix)
            try:
                return name, self.open_value(name)
            except FileExistsError:
                continue
        raise OSError(errno.EEXIST, "no free name for %s" % rel)

    def note(self, row: dict) -> None:
        assert self.root is not None
        if self._manifest is None:
            make_private_dirs(self.root)
            fd = os.open(str(self.root / MANIFEST), os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0), 0o600)
            self._manifest = os.fdopen(fd, "a", encoding="ascii")
        self._manifest.write(json.dumps(row) + "\n")
        self._manifest.flush()

    def close(self) -> None:
        if self._manifest is not None:
            try:
                self._manifest.flush()
                os.fsync(self._manifest.fileno())
            finally:
                self._manifest.close()
                self._manifest = None

    def _holds(self) -> bool:
        """Whether $OUT/mem_fs holds anything, from this call or an earlier one in the same job (a call that asked for no values included)."""
        if self.values_root is None:
            return False
        try:
            return any(self.values_root.iterdir())
        except OSError:
            return False

    def holds_values(self) -> bool:
        return self._holds()

    def summary(self) -> dict:
        present = self.written > 0 or self.earlier or self._holds()
        earlier_only = present and self.written == 0 and self.earlier
        answer = {
            "requested": self.enabled,
            "written": self.written,
            "values_dir": self.shown if present else None,
            "manifest": ("%s/%s" % (self.shown, MANIFEST)) if present and self.values_root is not None and (self.values_root / MANIFEST).exists() else None,
            "contains_secret_values": present,
            "earlier_calls_in_this_job_wrote_values": self.earlier,
            "format": "files byte for byte, mode 0600; the manifest is JSON Lines, appended to by every call of the job: item_id, virtual_path, output, bytes, sha256, status" if present else None,
        }
        if present and not self.enabled:
            answer["note"] = ("this call asked for no values and wrote none, but the job's output holds values written by earlier calls of this job: "
                              "treat the whole output as secret; the manifest, appended to by every call, is the record of what is there")
        elif earlier_only:
            answer["note"] = "this call wrote no value; the values in the job's output were written by earlier calls (the manifest lists them all)"
        return answer


def writable_mount(path):
    """Resolve a mount below this agent's work/<id>/ directory, or, in a job,
    below its $OUT: the one place a worker may write. A pack tool the agent's
    VM cannot run is run again as a job with work/<id>/x given as $OUT/x, and
    a mount refused there was a rerun that could never mount anything. As in
    mem_carve, resolving first (symlinks included) is what holds a path to
    where it really lands."""
    root = Path.cwd().resolve()
    dest = (root / path).resolve() if not Path(path).is_absolute() else Path(path).resolve()
    job_out = Path(os.environ["OUT"]).resolve() if os.environ.get("JOB_ID") and os.environ.get("OUT") else None
    if job_out is not None and job_out in dest.parents:
        return dest
    if dest == root:
        fail("mount must be a child directory, not the run directory itself", mount=str(path))
    if root not in dest.parents:
        fail("mount must stay inside the run directory", mount=str(path))
    work = (root / "work").resolve()
    if dest == work or work not in dest.parents:
        fail("mount must be under your own work/<your id>/ directory", mount=str(path))
    relative = dest.relative_to(work)
    if len(relative.parts) < 2 or relative.parts[0] in ("", ".", ".."):
        fail("mount must name a directory inside work/<your id>/, not work/ itself",
             mount=str(path))
    return dest


class OutsideMount(Exception):
    """A virtual path that is not, or does not resolve to, a place inside the mount."""

    def __init__(self, label, virtual, reason):
        super().__init__("%s %s: %s" % (label, json.dumps(shown(virtual, "path") if isinstance(virtual, str) else virtual), reason))
        self.label, self.virtual, self.reason = label, virtual, reason


def inside_mount(mount, virtual, label):
    """A virtual path as a path in the mount, held inside it.

    Raises OutsideMount for an empty or absolute path, a `..`, and a link that resolves
    outside the mount; a link loop raises the OSError or RuntimeError of the resolution.
    It never ends the program: it is called from the worker thread, where an exit would
    stop that thread alone and leave the answer to be printed after an error document.
    """
    if not isinstance(virtual, str) or not virtual:
        raise OutsideMount(label, virtual, "must be a non-empty path inside the mount")
    if virtual.startswith("/") or any(part == ".." for part in virtual.split("/")):
        raise OutsideMount(label, virtual, "must stay inside the mount: a relative path with no ..")
    target = (mount / virtual).resolve()
    if target != mount and mount not in target.parents:
        raise OutsideMount(label, virtual, "resolves outside the mount (a link)")
    return target


def output_name(virtual):
    """A virtual path as the relative path its export is written under: each character outside a safe set is written as %XX of its bytes
    (a % itself too), so two different names never share one, and a name that is not valid UTF-8 keeps its bytes."""
    def part(p):
        raw = os.fsencode(p)
        return "".join(chr(b) if (chr(b).isascii() and re.fullmatch(r"[A-Za-z0-9._@+=,-]", chr(b))) else "%%%02X" % b for b in raw)
    parts = [part(p) for p in virtual.split("/") if p not in ("", ".")]
    return "/".join(parts) or "_"


def prerequisites():
    device = "/dev/fuse"
    return {
        "dev_fuse_present": os.path.exists(device),
        "dev_fuse_usable": os.access(device, os.R_OK | os.W_OK),
        "unmount_helper": shutil.which("fusermount3") or shutil.which("fusermount"),
    }


def blocked_by():
    """What the host lacks for a FUSE mount, as words, so a report can say 'no framework' without parsing text."""
    have = prerequisites()
    missing = []
    if not have["dev_fuse_present"]:
        missing.append("/dev/fuse is not present")
    elif not have["dev_fuse_usable"]:
        missing.append("/dev/fuse cannot be opened by this process")
    if not have["unmount_helper"]:
        missing.append("neither fusermount3 nor fusermount is installed")
    return missing


def engine_lines(path):
    """The first lines of an engine's log, each judged as free text, and how many there are: the whole log is the file."""
    try:
        with open(path, "rb") as fh:
            data = fh.read(64 * 1024)
            more = bool(fh.read(1))
    except OSError:
        return {"lines": [], "lines_in_first_64k": 0, "complete_in_file": str(path)}
    text = data.decode("utf-8", "replace").splitlines()
    return {"lines": [shown(line[:ENGINE_LINE_CHARS], "text") for line in text[:ENGINE_LINES] if line.strip()],
            "lines_in_first_64k": len(text), "more_than_64k": more,
            "note": "the first %d lines, each cut at %d characters and judged as text; the whole log is the file named in logs" % (ENGINE_LINES, ENGINE_LINE_CHARS)}


class LogDrain:
    """Copies one stream of the engine into its private log file, the first LOG_CAP bytes of it; the rest is read, counted and discarded.
    A pipe that is always read cannot fill and stop the engine, and the log of a verbose engine (raw text of the capture, 0600 but not
    judged) cannot grow without bound, which a file the engine writes itself would."""

    def __init__(self, stream, handle):
        self.stream, self.handle, self.kept, self.dropped = stream, handle, 0, 0
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        try:
            while True:
                data = self.stream.read1(65536)
                if not data:
                    break
                room = max(0, LOG_CAP - self.kept)
                if room:
                    try:
                        self.handle.write(data[:room])
                        self.kept += min(room, len(data))
                    except (OSError, ValueError):
                        room = 0
                self.dropped += len(data) - min(room, len(data))
        except (OSError, ValueError):
            pass

    def finish(self, wait):
        self.thread.join(wait)
        try:
            self.handle.flush()
        except (OSError, ValueError):
            pass


def _pdeathsig():
    """The engine ends with the tool (Linux): a tool that is killed leaves no engine and no FUSE mount holding the evidence."""
    try:
        import ctypes
        ctypes.CDLL(None).prctl(1, signal.SIGTERM)   # PR_SET_PDEATHSIG
    except Exception:  # noqa: BLE001 - best effort
        pass


def is_mounted(mount):
    """Whether the path is a mount point, a dead one included: os.path.ismount says no for a FUSE mount whose engine has died (ENOTCONN)."""
    try:
        if os.path.ismount(mount):
            return True
        os.lstat(mount)
        return False
    except OSError as exc:
        return exc.errno == errno.ENOTCONN


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    if not isinstance(args, dict):
        fail("arguments must be a JSON object")
    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: the memory image")
    if not os.path.isfile(path):
        fail("no such file", path=path)
    mount_arg = args.get("mount")
    if not isinstance(mount_arg, str) or not mount_arg:
        fail("mount is required: a directory under your own work/<your id>/ to mount the image at "
             "(the rest of work/ is read-only in a VM)")
    mount = writable_mount(mount_arg)
    timeout = args.get("timeout_seconds", DEFAULT_TIMEOUT)
    if not isinstance(timeout, int) or isinstance(timeout, bool) or not MIN_TIMEOUT <= timeout <= MAX_TIMEOUT:
        fail("timeout_seconds must be an integer from %d to %d: the engine's stop and unmount after it need up to 65 s, "
             "and the tool's own limit is 600" % (MIN_TIMEOUT, MAX_TIMEOUT))
    mode = args.get("mode", "list")
    if mode not in ("list", "text", "export"):
        fail("mode must be list, text or export", mode=mode if isinstance(mode, str) else None)
    write_values = args.get("write_values", False)
    if write_values is None:
        write_values = False
    if not isinstance(write_values, bool):
        fail("write_values must be true or false")
    limit = args.get("limit", PAGE)
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        fail("limit must be a positive integer")
    limit_requested = None
    if limit > MAX_PAGE:
        limit_requested, limit = limit, MAX_PAGE
    max_bytes = args.get("max_bytes_per_path", DEFAULT_MAX_BYTES)
    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes < 1:
        fail("max_bytes_per_path must be a positive integer")

    requested = args.get("list") or ("." if mode == "list" else None)
    if requested is not None and not isinstance(requested, str):
        fail("list must be a path inside the mount (a string)")
    paths = args.get("paths")
    if mode == "text":
        if not isinstance(requested, str) or not requested or requested == ".":
            fail("mode text names one file in list: a path inside the mount")
    if mode == "export":
        if not isinstance(paths, list) or not paths or not all(isinstance(p, str) and p for p in paths):
            fail("mode export needs paths: a non-empty list of virtual paths inside the mount")
        if len(paths) > MAX_PATHS:
            fail("at most %d paths in one call; export the rest in another" % MAX_PATHS, paths=len(paths))
    if mode in ("text", "export") and not write_values:
        fail("mode %s writes memory content to a file: ask for it with write_values: true, in a job run as "
             "secret output. Nothing was written and MemProcFS was not started." % mode)
    try:
        secret = SecretValues(write_values)
    except SecretValuesRefused as exc:
        fail(str(exc), write_values="refused", written=False)
    STATE["secret"] = secret

    binary = shutil.which("memprocfs")
    if not binary:
        fail("memprocfs is not on PATH",
             install="https://github.com/ufrisk/MemProcFS/releases",
             blocked_by=["memprocfs is not installed"],
             note="MemProcFS is AGPL-3.0, the same licence as this harness. Without it, "
                  "triage/no-framework says what a memory image still gives you, and the report "
                  "should say no framework was available rather than that nothing was found.")
    if mount.exists() and not mount.is_dir():
        fail("mount exists and is not a directory", mount=str(mount))
    # Every path is checked against the mount before MemProcFS is started.
    targets = []
    try:
        if mode == "export":
            for virtual in paths:
                inside_mount(mount, virtual, "paths")
                targets.append(virtual)
        elif requested:
            inside_mount(mount, requested, "list")
    except OutsideMount as exc:
        fail(str(exc), **{exc.label: shown(exc.virtual, "path") if isinstance(exc.virtual, str) else None})
    except (OSError, RuntimeError) as exc:
        fail("a path could not be resolved inside the mount: %s" % shown(describe_text(exc), "text"))
    mount.mkdir(parents=True, exist_ok=True)
    if any(mount.iterdir()):
        fail("mount directory must be empty; refusing stale files or an existing mount",
             mount=str(mount))

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    stdout_log = mount.parent / ("%s.memprocfs-%s-%d.stdout.log" % (mount.name, stamp, os.getpid()))
    stderr_log = mount.parent / ("%s.memprocfs-%s-%d.stderr.log" % (mount.name, stamp, os.getpid()))
    argv = [binary, "-device", path, "-mount", str(mount)]
    started = time.monotonic()
    deadline = started + timeout
    try:
        # The engine's output can hold what the capture held: the logs are private.
        stdout_file = os.fdopen(os.open(str(stdout_log), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600), "wb")
        stderr_file = os.fdopen(os.open(str(stderr_log), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600), "wb")
    except OSError as exc:
        fail("the engine's log files could not be created next to the mount", reason=shown(describe_text(exc), "text"), logs=str(stdout_log))
    STATE["logs"] = {"stdout": str(stdout_log), "stderr": str(stderr_log)}
    try:
        # Pipes that a thread per stream always reads into the log files (up to LOG_CAP each): MemProcFS can be verbose, and a full pipe
        # would otherwise deadlock before the mount becomes readable. The logs are kept.
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                preexec_fn=_pdeathsig if sys.platform.startswith("linux") else None)
    except OSError as exc:
        stdout_file.close()
        stderr_file.close()
        fail("memprocfs would not start", phase="startup", reason=shown(describe_text(exc), "text"), command=" ".join(argv),
             logs={"stdout": str(stdout_log), "stderr": str(stderr_log)})

    drains = [LogDrain(proc.stdout, stdout_file), LogDrain(proc.stderr, stderr_file)]
    state = {"phase": "startup", "abandon": False}
    problem = None  # (phase, message)
    result = {}
    timings = {}
    interrupted = None
    ready_marker = mount / "sys"
    page = LosslessPage("mem_fs", [str(mount), mode, requested, paths], limit)
    counts = {"requested": len(targets), "exported": 0, "failed": 0, "refused": 0, "not_exported": 0, "partial": 0,
              "not_attempted": 0}
    names_info = {"withheld": 0, "file": None}

    def describe(exc):
        code = errno.errorcode.get(exc.errno, "") if getattr(exc, "errno", None) else ""
        return "%s%s: %s" % (type(exc).__name__, " " + code if code else "", getattr(exc, "strerror", None) or str(exc))

    def judged(text):
        return shown(text, "text")

    # --- the work: runs in a thread, so one deadline holds over a read that blocks ---

    def copy_out(source, virtual, item):
        """Copy one virtual file to $OUT/mem_fs/<name>, whole; item['status'] says what happened, and the
        return value is the count it belongs to (exported, failed, refused, not_exported, partial)."""
        rel = output_name(virtual)
        label = shown(virtual, "path")
        if any(len(part) > MAX_OUTPUT_COMPONENT for part in rel.split("/")):
            item["status"] = "refused: the output name would have a component over %d characters; nothing was written" % MAX_OUTPUT_COMPONENT
            return "refused"
        try:
            st = os.lstat(source)
        except FileNotFoundError:
            item["status"] = "failed: not found in the mount"
            return "failed"
        except OSError as exc:
            item["status"] = judged("failed: %s" % describe(exc))
            return "failed"
        if stat.S_ISDIR(st.st_mode):
            item["status"] = "not exported: a directory (export names files; list shows what a directory holds)"
            return "not_exported"
        if not stat.S_ISREG(st.st_mode):
            item["status"] = "not exported: not a regular file"
            return "not_exported"
        if st.st_size > max_bytes:
            item["status"] = "not exported: %d bytes exceeds max_bytes_per_path (%d); raise it to export this file" % (st.st_size, max_bytes)
            item["bytes"] = st.st_size
            return "not_exported"
        try:
            # Never through a link: the path was resolved just now, and a link planted since
            # is refused by the open rather than followed.
            source_fd = os.open(str(source), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        except OSError as exc:
            item["status"] = judged("failed: %s could not be opened: %s" % (label, describe(exc)))
            return "failed"
        try:
            fd = secret.open_value(rel)
        except FileExistsError:
            os.close(source_fd)
            item["status"] = judged("refused: the output name %s already exists (another virtual path maps to it, or an earlier call wrote it); nothing was overwritten" % shown(rel, "path"))
            return "refused"
        except OSError as exc:
            os.close(source_fd)
            item["status"] = judged("failed: the output file could not be created: %s" % describe(exc))
            return "failed"
        # `size` and the digest count the bytes the operating system accepted (an unbuffered writer, short writes followed), so a disk that
        # fills leaves a count, a digest and a file that agree; what is on disk is read back at the end and said.
        digest, size, partial, error = hashlib.sha256(), 0, None, None
        try:
            with os.fdopen(fd, "wb", buffering=0) as out, os.fdopen(source_fd, "rb") as src:
                while True:
                    if state["abandon"]:
                        partial = "the call was stopped or its deadline was reached"
                        break
                    chunk = src.read(CHUNK)
                    if not chunk:
                        break
                    if size + len(chunk) > max_bytes:
                        partial = "max_bytes_per_path (%d) was reached while reading" % max_bytes
                        break
                    view = memoryview(chunk)
                    while len(view):
                        taken = out.write(view)
                        if not taken:
                            raise OSError(errno.EIO, "a write took no bytes")
                        digest.update(view[:taken])
                        size += taken
                        view = view[taken:]
                os.fsync(out.fileno())
        except OSError as exc:
            error = exc
        try:
            on_disk = os.lstat(secret.root / rel).st_size
        except OSError:
            on_disk = None
        item["bytes"] = size
        if on_disk is not None and on_disk != size:
            item["bytes_on_disk"] = on_disk
        item["output"] = shown(secret.shown_path(rel), "path")
        kept = "%d bytes are on disk and kept" % (on_disk if on_disk is not None else size)
        if error is not None:
            item["status"] = judged("failed: copying %s: %s; %s (the manifest row counts the %d bytes the system accepted and their digest)" % (label, describe(error), kept, size))
            category = "failed"
        elif partial:
            item["status"] = "partial: %s; %s" % (partial, kept)
            category = "partial"
        else:
            item["status"] = "exported"
            category = "exported"
        try:
            row = {"item_id": item["item_id"], "virtual_path": virtual, "output": rel, "bytes": size,
                   "sha256": digest.hexdigest(), "status": str(item["status"])}
            if on_disk is not None and on_disk != size:
                row["bytes_on_disk"] = on_disk
            secret.note(row)
        except OSError as exc:
            # The file is on disk and counted; a manifest row that could not be written is said, never hidden.
            item["status"] = Shown(str(item["status"]) + "; the manifest row was not written: " + describe(exc))
        return category

    def work_export():
        state["phase"] = "export"
        for number, virtual in enumerate(targets, 1):
            item = {"item_id": "X%06d" % number, "virtual_path": shown(virtual, "path")}
            if state["abandon"]:
                item["status"] = "not attempted: the call was stopped or its deadline was reached"
                category = "not_attempted"
            else:
                # One item's trouble is that item's status and count, and the next item goes on.
                try:
                    category = copy_out(inside_mount(mount, virtual, "paths"), virtual, item)
                except OutsideMount as exc:
                    item["status"] = "refused: %s" % exc.reason
                    category = "refused"
                except (RuntimeError, OSError) as exc:
                    item["status"] = judged("failed: %s" % describe_text(exc))
                    category = "failed"
            counts[category] += 1
            page.add(sealed(item))

    def work_text():
        state["phase"] = "read"
        virtual = requested
        source = inside_mount(mount, virtual, "list")
        if not source.is_file():
            raise FileNotFoundError("the named path is not a file in the mount")
        rel = output_name(virtual)
        fd = secret.open_value(rel)
        decoder = codecs.getincrementaldecoder("utf-8")("strict")
        digest, size, lines, reason = hashlib.sha256(), 0, 0, None
        try:
            with os.fdopen(fd, "wb") as out, open(source, "rb") as src:
                while True:
                    if state["abandon"]:
                        reason = "the call was stopped or its deadline was reached"
                        break
                    chunk = src.read(CHUNK)
                    if not chunk:
                        break
                    if size + len(chunk) > max_bytes:
                        reason = "larger than max_bytes_per_path (%d)" % max_bytes
                        break
                    if b"\x00" in chunk:
                        reason = "a NUL byte at offset %d" % (size + chunk.index(b"\x00"))
                        break
                    try:
                        decoder.decode(chunk)
                    except UnicodeDecodeError as exc:
                        reason = "bytes that are not UTF-8 at offset %d" % (size + exc.start)
                        break
                    out.write(chunk)
                    digest.update(chunk)
                    size += len(chunk)
                    lines += chunk.count(b"\n")
                if reason is None:
                    try:
                        decoder.decode(b"", final=True)
                    except UnicodeDecodeError:
                        reason = "the file ends inside a UTF-8 sequence"
        except BaseException:
            os.unlink(secret.root / rel)
            raise
        if reason:
            os.unlink(secret.root / rel)
            result["not_text"] = "%s is not text: %s. Nothing was written; use mode export for its bytes." % (shown(virtual, "path"), reason)
            return
        secret.note({"item_id": "X000001", "virtual_path": virtual, "output": rel, "bytes": size,
                     "sha256": digest.hexdigest(), "status": "exported"})
        counts["exported"] = 1
        result["text"] = {"virtual_path": shown(virtual, "path"), "output": shown(secret.shown_path(rel), "path"), "encoding": "utf-8",
                          "bytes": size, "lines": lines}

    def work_list():
        state["phase"] = "read"
        source = inside_mount(mount, requested, "list")
        if not source.exists():
            raise FileNotFoundError("the named path is not in the mount")
        names = sorted(os.listdir(source), key=os.fsencode) if source.is_dir() else [None]
        plain_rows, hidden_rows, originals = [], [], []
        for name in names:
            child = source if name is None else source / name
            label = name or source.name
            printed = shown(label, "name")
            row = {"name": printed}
            try:
                st = os.lstat(child)
            except OSError as exc:
                row["error"] = describe(exc)
            else:
                row["directory"] = stat.S_ISDIR(st.st_mode)
                if not row["directory"]:
                    row["size"] = st.st_size
            if str(printed) != _escaped(label):
                hidden_rows.append(row)
                originals.append(label)
            else:
                plain_rows.append(row)
        # The names that were changed are listed after the plain ones, in an order that is new every call: their position must not
        # tell where in the sorted listing the original sat.
        order = list(range(len(hidden_rows)))
        random.SystemRandom().shuffle(order)
        for index in order:
            hidden_rows[index]["name_withheld"] = True
        names_info["withheld"] = len(hidden_rows)
        if secret.enabled and originals:
            rel, vfd = secret.open_unique("names.jsonl")
            with os.fdopen(vfd, "w", encoding="ascii") as handle:
                for label in originals:
                    handle.write(json.dumps({"name": label, "listed": requested}) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            names_info["file"] = shown(secret.shown_path(rel), "path")
        for row in plain_rows:
            page.add(sealed(row))
        for index in order:
            page.add(sealed(hidden_rows[index]))

    def describe_for_result(exc):
        return exc if isinstance(exc, (FileNotFoundError, OutsideMount)) else describe_text(exc)

    def work():
        try:
            {"list": work_list, "text": work_text, "export": work_export}[mode]()
        except BaseException as exc:  # reported by phase, never swallowed
            result["error"] = exc

    worker = None
    try:
        # --- startup: until the mount appears ---
        while True:
            if is_mounted(mount) and ready_marker.is_dir():
                break
            if proc.poll() is not None:
                problem = ("startup", "memprocfs exited before the mount appeared (exit status %s)" % proc.returncode)
                break
            if time.monotonic() >= deadline:
                problem = ("startup", "the mount did not appear within %ds" % timeout)
                break
            time.sleep(0.2)
        timings["startup_seconds"] = round(time.monotonic() - started, 2)
        if not problem:
            work_started = time.monotonic()
            worker = threading.Thread(target=work, daemon=True)
            worker.start()
            worker.join(max(0.0, deadline - time.monotonic()))
            if worker.is_alive():
                state["abandon"] = True
                problem = (state["phase"], "the %s phase did not finish within the %ds deadline" % (state["phase"], timeout))
            timings["work_seconds"] = round(time.monotonic() - work_started, 2)
            if "error" in result and not problem:
                exc = result["error"]
                problem = (state["phase"], str(shown(str(describe_for_result(exc)), "text")))
    except Terminated as stopped:
        interrupted = stopped.signum
        state["abandon"] = True
    finally:
        GUARD["depth"] += 1            # stopping the engine and releasing the mount is finished before a stop is acted on
        try:
            cleanup_started = time.monotonic()
            # Stop the engine, then release a FUSE mount: a successful return must not leave
            # a mount holding evidence. A blocked read ends when the engine does.
            state["abandon"] = state["abandon"] or interrupted is not None
            proc.terminate()
            try:
                proc.wait(timeout=CLEANUP_WAIT)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=CLEANUP_WAIT)
            if is_mounted(mount):
                unmount = shutil.which("fusermount3") or shutil.which("fusermount")
                if unmount:
                    for flags in (["-u"], ["-u", "-z"]):
                        subprocess.run([unmount, *flags, str(mount)], stdout=subprocess.DEVNULL,
                                       stderr=subprocess.DEVNULL, timeout=CLEANUP_WAIT, check=False)
                        if not is_mounted(mount):
                            break
            if is_mounted(mount) and not problem:
                problem = ("cleanup", "memprocfs stopped but the FUSE mount remained")
            for drain in drains:
                drain.finish(5)
            for handle in (stdout_file, stderr_file, proc.stdout, proc.stderr):
                try:
                    handle.close()
                except (OSError, ValueError):
                    pass
            if state["abandon"] and worker is not None:
                worker.join(5)
            secret.close()
            timings["cleanup_seconds"] = round(time.monotonic() - cleanup_started, 2)
        finally:
            GUARD["depth"] -= 1
    try:
        checkpoint()
    except Terminated as stopped:
        interrupted = stopped.signum

    timings["deadline_seconds"] = timeout
    if mode == "export":
        # Whatever the worker did not reach (it ended early, or was abandoned) is counted, so the counts always add up to the requested.
        unreached = counts["requested"] - sum(counts[k] for k in ("exported", "failed", "refused", "not_exported", "partial", "not_attempted"))
        if unreached > 0:
            counts["not_attempted"] += unreached
    logs = {"stdout": str(stdout_log), "stderr": str(stderr_log),
            "stdout_bytes": stdout_log.stat().st_size, "stderr_bytes": stderr_log.stat().st_size, "mode": "0600",
            "stdout_dropped_bytes": drains[0].dropped, "stderr_dropped_bytes": drains[1].dropped,
            "cap_bytes": LOG_CAP,
            "cap_note": "each log keeps the first %d bytes of its stream; what the engine wrote after that was read and discarded (the dropped counts)" % LOG_CAP}
    paged = page.finish()
    items = {"items": page.page} if mode == "export" else {}

    if interrupted is not None:
        interrupted_answer(interrupted, mode=mode, mount=str(mount), logs=logs, phases=timings,
                           counts=counts if mode == "export" else None, secret_values=secret.summary(), **items)
        raise SystemExit(128 + interrupted)

    if problem:
        phase, message = problem
        blocked = blocked_by() if phase == "startup" else None
        fail(message, phase=phase, command=" ".join(argv), mount=str(mount), logs=logs,
             engine_stderr=engine_lines(stderr_log), engine_stdout=engine_lines(stdout_log),
             engine_exit_status=proc.returncode, blocked_by=blocked,
             prerequisites=prerequisites(), phases=timings,
             counts=counts if mode == "export" else None,
             secret_values=secret.summary(),
             note="Mounting needs FUSE, which a sandbox may refuse. That is a limit on the host, not a finding "
                  "about the evidence, and the report should say so. The engine's own output is in the log files named; "
                  "the lines shown here are judged as text.",
             **items)
    if "not_text" in result:
        fail(result["not_text"], phase="read", mount=str(mount), logs=logs, secret_values=secret.summary())

    answer = {
        "path": path,
        "parser": PARSER,
        "mode": mode,
        "mount": str(mount),
        "command": " ".join(argv),
        "prerequisites": prerequisites(),
        "phases": timings,
        "logs": logs,
        "secret_values": secret.summary(),
    }
    row_errors = 0
    if mode == "list":
        answer["listed"] = shown(requested, "path")
        answer["entries"] = page.page
        answer["entry_count"] = paged["matched"]
        row_errors = sum(1 for row in page.page if isinstance(row, dict) and "error" in row)
        answer["names"] = {"withheld_or_changed": names_info["withheld"], "originals_file": names_info["file"]}
        if names_info["withheld"] and not names_info["file"]:
            answer["names"]["originals"] = ("not written: ask with write_values: true in a job run as secret output to have the original names "
                                            "in a sealed file")
        complete = row_errors == 0
        basis = ("the directory was read once through the mounted tree: %d entries, %d of them with a name withheld or changed by the "
                 "boundary%s" % (paged["matched"], names_info["withheld"], "" if not row_errors else "; %d entries could not be read (their rows say why)" % row_errors))
    elif mode == "text":
        answer["text"] = result["text"]
        complete = True
        basis = "the one file named was written whole, as UTF-8 text with no NUL byte"
    else:
        answer["items"] = page.page
        answer["counts"] = counts
        complete = counts["exported"] == counts["requested"]
        basis = ("%d of %d requested files were exported whole%s" % (counts["exported"], counts["requested"], "" if complete else
                 "; the others are refused, failed, partial, not exported or not attempted (each item's status says which)"))
    if paged.get("all_results"):
        answer["complete_results"] = paged["all_results"]
        answer["complete_results_format"] = paged["all_results_format"]
    if limit_requested is not None:
        answer["limit_clamped_to"] = MAX_PAGE
        answer["limit_requested"] = limit_requested
    answer["truncated"] = paged["truncated"]
    answer["boundary"] = boundary_summary()
    answer["status"] = "complete" if complete else "partial"
    answer["status_basis"] = basis
    answer["complete"] = complete
    answer["note"] = ("The mount is gone now: this tool starts MemProcFS, does one thing with the tree and stops it, so "
                      "nothing is left holding the evidence open. What survives is what was written under "
                      "$OUT/mem_fs (a job's sealed output), and the engine's own output in the log files (mode 0600). "
                      "The answer carries no file content and no digest of one: the manifest named in "
                      "secret_values has each export's size and sha256. A file that was not exported, or only in part, "
                      "is named in items with its status: an export that is not complete says so in complete. "
                      "Names are shown by shape: see boundary.")
    answer = sealed(answer)
    answer["boundary"] = boundary_summary()
    if BOUNDARY["backstop_replaced"]:
        answer["status"] = "partial"
        answer["status_basis"] += "; the backstop replaced %d string(s) it found secret-shaped (boundary)" % BOUNDARY["backstop_replaced"]
    emit(answer)


def describe_text(exc):
    """An exception as words that name no path: the message of an OSError is its strerror (no file name); a RuntimeError from resolving a path
    quotes the path it was resolving, with the components of the mounted tree, so it is not quoted; any other message is judged as a path."""
    if isinstance(exc, OSError):
        code = errno.errorcode.get(exc.errno, "") if getattr(exc, "errno", None) else ""
        return "%s%s: %s" % (type(exc).__name__, " " + code if code else "", getattr(exc, "strerror", None) or type(exc).__name__)
    if isinstance(exc, RuntimeError):
        return "%s: a symbolic link loop, or a path too deep to resolve, in the mounted tree (the resolver's message quotes the path and is not shown)" % type(exc).__name__
    return "%s: %s" % (type(exc).__name__, shown(str(exc), "path"))


def run_guarded():
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, _on_signal)
    try:
        main()
    except SystemExit:
        raise
    except Terminated as stopped:   # a signal before the engine started, or while the answer was being made
        interrupted_answer(stopped.signum, logs=STATE["logs"])
        raise SystemExit(128 + stopped.signum)
    except Exception as exc:  # never an empty or clean answer for a failure
        fail("unexpected failure: %s: %s" % (type(exc).__name__, exc))


if __name__ == "__main__":
    run_guarded()
