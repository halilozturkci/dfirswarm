#!/usr/bin/env python3
"""Read the structure of a document from its bytes, and never as an application would open it.

doc_probe says what a byte search finds; this tool reads the container. Four containers, each read to the depth
its format lets a standard-library reader go, and for each structure the answer says whether it was read whole:

    OLE compound file   the header, the FAT and mini FAT, the directory (every entry, with the entries no storage
                        reaches), stream sizes and times; the VBA project (the `dir` stream is decompressed, each
                        module's stream and the size of its compressed source are listed; source is written out
                        only when asked for); the encryption structures that the Office formats record (the
                        EncryptionInfo stream, the Word FIB flags, the Excel FILEPASS record, the PowerPoint
                        header token); Excel sheet kinds from the BOUNDSHEET records
    OOXML / ZIP         the central directory, [Content_Types].xml, the document and workbook protection
                        elements, and the VBA project (by content type, relationship, name or compound file
                        signature) read as an OLE compound file
    PDF                 the cross-reference chain (tables and streams, hybrid files, every revision), the objects
                        with their stream filters, object streams, the trailer's encryption dictionary read, the
                        catalog's actions and the way they are triggered, embedded files, the page tree
    RTF                 group structure and nesting, control words, the object groups with their class names and
                        the signature their data begins with, fields and templates

Nothing here executes a document, a macro, a script or an embedded object, and nothing is fetched. A password
verifier, a salt, a hash or an encrypted value that a structure holds is reported as present and by length, never as
bytes. Streams are decoded only under budgets (a stream, all streams together, an expansion ratio, a depth, a
count of objects and a clock), and a budget that is reached is a limit in the answer, not a clean result.
"""
import array
import base64
import bisect
import errno
import hashlib
import io
import json
import mmap
import os
import posixpath
import re
import signal
import struct
import sys
import time
import unicodedata
import urllib.parse
import xml.parsers.expat
import zipfile
import zlib
from collections import OrderedDict
from datetime import datetime, timedelta, timezone
from pathlib import Path

TOOL = {"name": "doc_structure", "version": 1}
PARSER = "doc_structure/1"
NOTE = ("Static structure only. A structure shows what the file holds, not what an application would do with it: an action, a macro, "
        "a field or an external target does not show that anything ran or was fetched. Record what was read and what was not before "
        "drawing an absence conclusion. A string out of the file is shown with each backslash written twice and each control character as \\xNN.")

DEFAULT_STREAM = 16 << 20           # bytes one stream may be read or expand to
DEFAULT_TOTAL = 128 << 20           # bytes all streams may be read or expand to, together
DEFAULT_ENTRIES = 10000             # OLE directory entries and ZIP members read
DEFAULT_OBJECTS = 200000            # PDF objects indexed
DEFAULT_DEPTH = 256                 # nesting followed: RTF groups, PDF structures, OLE storages
DEFAULT_RATIO = 1000                # expanded bytes per compressed byte
MAX_LIMIT = 20000                  # the most rows of one table the answer may hold (a longer table is in its file; the rows are withheld as the reading adds them)
DEFAULT_LIMIT = 1000                # rows of one table in the answer; the whole of a longer one is in a file
MAX_ENTRIES = 100000
MAX_OBJECTS = 2000000
MAX_DEPTH = 10000
DEFAULT_SECONDS = 70                # the reading clock: the answer is built after it (HARD_SECONDS below), so a slow file is a partial answer inside the manifest's 120 s, not a kill
MAX_SECONDS = 90
RATIO_FLOOR = 1 << 20
MAX_DIRECTORY_ENTRIES = 100000
MAX_DIRECTORY_BYTES = 64 << 20
MIN_ENTRY = 46
METHODS_READ = (0, 8)
HEAD_BYTES = 1024
MAX_PROBLEMS = 100
PAGE = 1 << 16
MAX_EXTRACT = 64
NESTED_INLINE = 20                  # nested compound files whose VBA projects the answer repeats inline (all are rows of nested_vba_*)
SPILL_FLOOR = 100                   # no list in the answer is longer than the larger of `limit` and this: a longer one is in a file, whole

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


SHOWN_TARGET = 2048                 # characters of a target the answer shows; the whole is in the values file with write_values


def shown_target(text):
    """A target (a URL, a path) as the answer shows it. One longer than SHOWN_TARGET is not shown at all: a cut could leave the head of a
    token too short to be recognised as one (a mailto: address with a password in it is handled by shown_path)."""
    if len(text) > SHOWN_TARGET:
        return "<a target of %d characters: longer than the %d shown, so not shown; the whole is in the values file with write_values>" % (len(text), SHOWN_TARGET)
    if re.match(r"[A-Za-z][A-Za-z0-9+.-]*://", text):
        # the URL's own rules (user-info to the last `@`, query values, fragment, host), then the sanitiser over the whole, as for any
        # other string: a base64 key joined by `/` in the path is read across its pieces here too
        return shown_path(redact_target(plain_userinfo(text)))
    return cell(shown_path(text))


def redact_target(url):
    """redact_url, and the host too: the shared block keeps the authority as it is, and a host name can carry a token (a bucket
    or a tenant named after a key). Everything token-shaped in the host is withheld; a plain host name stays."""
    out = redact_url(url)
    m = re.match(r"^((?:[A-Za-z][A-Za-z0-9+.-]*:)?//)([^/?#]*)(.*)$", out, re.S)
    if not m:
        return out
    userinfo, at, host = m.group(2).rpartition("@")
    return m.group(1) + userinfo + at + scrub(host, "urls") + m.group(3)


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
GLUED = re.compile(r"(?:%s)[A-Za-z0-9_+%%-]*" % _PREFIXED.pattern)
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
        found += [(m.start(), m.end(), "token-shaped text") for rule in (GLUED, JWT_TAIL) for m in rule.finditer(out)]
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
        out = scrub(GLUED.sub(_whole_withheld, out), "names")
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

# Strings the tool made itself and registered (a page file's path, the names file's path, a class id that is not text): only these, and
# only under one of these keys, leave unchanged. Anything else, under any key, is withheld like any string out of the file: a key here
# is never a way round the withholding for a string built from the file's bytes.
SAFE_KEYS = {"clsid", "root_clsid", "all_results", "withheld_names_file"}
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
        page = LosslessPage("doc_structure-list", [self.ctx.key, "list", self.n], 0)
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
    answer = {"error": message, "status": status, "tool": TOOL, **extra}
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
        # The clock first: a row the clock stops is not counted, so that `matched` is the rows kept and written and never one more than the file.
        if self.tick is not None:
            self.tick()
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

    NAME = "doc-structure-values.jsonl"

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
                "file, not a sealed secret output. Run this as job_run tool=doc_structure with "
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
            "format": ("JSON Lines, mode 0600: finding_id, the locator of the finding, value (the whole, unredacted text: a target, an instruction, "
                       "the real name behind a withheld one)") if self.enabled else None,
        }


class Names:
    """The real name behind every name withheld from the answer: a private file (mode 0600, created exclusively, in the
    tool-output directory) written at the moment a name is withheld, whether or not write_values was given, so that no name
    is lost; with write_values the values file holds them as well. The answer names the file."""

    NAME = "doc-structure-withheld-names"

    def __init__(self, values):
        self.values = values
        self.count = 0
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

    def add(self, real, shown, kind="part_name"):
        self.count += 1
        finding_id = "N%06d" % self.count
        self.values.add(finding_id, {"kind": kind}, real)
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
            self._fh.write(json.dumps({"finding_id": finding_id, "kind": kind, "name": real, "shown": shown}) + "\n")
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


# --- ZIP reading: the end record, then members under budgets ----------------------------------------------------

class Budget:
    def __init__(self, member, total, ratio):
        self.member, self.total, self.ratio, self.used = member, total, ratio, 0


class Unreadable(Exception):
    def __init__(self, kind, reason):
        Exception.__init__(self, reason)
        self.kind, self.reason = kind, reason


# --- ZIP: the end record, then members under budgets ------------------------------------------------------------------------

class ZipProblem(Exception):
    pass


def zip_directory(fh, size):
    """The end record the tool chooses, and what it names: {total, cd_size, cd_off, eocd_at, others}. The choice is the last end
    record in the last 64 KiB whose comment fits the file; `others` lists every other signature there, because a reader that
    chooses differently lists another directory. The zip64 record is read when the end record holds its sentinels. Nothing here
    depends on the standard library's validators."""
    tail_len = min(size, 65557)
    fh.seek(size - tail_len)
    tail = fh.read(tail_len)
    found, pos = [], tail.find(b"PK\x05\x06")
    while pos >= 0:
        found.append(pos)
        pos = tail.find(b"PK\x05\x06", pos + 1)
    plausible = [p for p in found if p + 22 <= len(tail) and p + 22 + struct.unpack_from("<H", tail, p + 20)[0] <= len(tail)]
    if not plausible:
        raise ZipProblem("no end of central directory record in the last %d bytes of the file" % tail_len)
    pos = plausible[-1]
    _sig, _disk, _cd_disk, _n_disk, total, cd_size, cd_off, _clen = struct.unpack_from("<IHHHHIIH", tail, pos)
    eocd_at = size - tail_len + pos
    others = [size - tail_len + p for p in found if p != pos]
    if total == 0xFFFF or cd_size == 0xFFFFFFFF or cd_off == 0xFFFFFFFF:
        if eocd_at < 20:
            raise ZipProblem("the end record holds zip64 values and there is no room for the zip64 locator")
        fh.seek(eocd_at - 20)
        locator = fh.read(20)
        if locator[:4] != b"PK\x06\x07":
            raise ZipProblem("the end record holds zip64 values and no zip64 locator precedes it")
        _s, _d, record_at, _n = struct.unpack("<IIQI", locator)
        fh.seek(record_at)
        record = fh.read(56)
        if len(record) < 56 or record[:4] != b"PK\x06\x06":
            raise ZipProblem("the zip64 end of central directory record is not where its locator says")
        total, cd_size, cd_off = struct.unpack_from("<QQQ", record, 32)
    if cd_off + cd_size > size:
        raise ZipProblem("the central directory (offset %d, %d bytes) lies outside the %d-byte file" % (cd_off, cd_size, size))
    return {"total": total, "cd_size": cd_size, "cd_off": cd_off, "eocd_at": eocd_at, "others": others}


class Window(io.RawIOBase):
    """The first `limit` bytes of a file, with the end record's comment length read as 0: the ZIP reader sees the archive up to
    the end record the tool chose, so that it lists the directory the tool counted and not one hidden in a comment."""

    def __init__(self, fh, limit, zero_at, patches=None):
        self._fh, self._limit, self._zero_at, self._pos = fh, limit, zero_at, 0
        self._patches = patches or {}     # file offset -> the byte the reader sees there instead

    def readable(self):
        return True

    def seekable(self):
        return True

    def tell(self):
        return self._pos

    def seek(self, offset, whence=0):
        base = {0: 0, 1: self._pos, 2: self._limit}[whence]
        self._pos = max(0, base + offset)
        return self._pos

    def readinto(self, buffer):
        n = max(0, min(len(buffer), self._limit - self._pos))
        if not n:
            return 0
        self._fh.seek(self._pos)
        data = bytearray(self._fh.read(n))
        for at in (self._zero_at, self._zero_at + 1):
            if self._pos <= at < self._pos + len(data):
                data[at - self._pos] = 0
        for at, value in self._patches.items():
            if self._pos <= at < self._pos + len(data):
                data[at - self._pos] = value
        buffer[:len(data)] = data
        self._pos += len(data)
        return len(data)


def local_header_differs(fh, info, size):
    """The fields of a member's local header (PKWARE APPNOTE 4.3.7) that disagree with its central directory entry: the signature, the name,
    the method, the flags' encryption bit, and the CRC and sizes when the local header carries them (no data descriptor, flag bit 3, and
    no zip64 sentinel). An empty list when they agree."""
    at = info.header_offset
    if at < 0 or at + 30 > size:
        return ["the local header lies outside the file"]
    fh.seek(at)
    head = fh.read(30)
    sig, _ver, flags, method, _t, _d, crc, csize, usize, nlen, _xlen = struct.unpack("<IHHHHHIIIHH", head)
    if sig != 0x04034B50:
        return ["no local header signature at its offset"]
    raw = fh.read(nlen)
    # decoded as the central entry's name was (a UTF-8 flag on a name that is not UTF-8 is read as CP437 there), so that one spelling of
    # the bytes is one name
    name = raw.decode("utf-8", "surrogateescape") if info.flag_bits & 0x800 else raw.decode("cp437")
    out = []
    if name != info.filename and name.replace("\\", "/") != info.filename:
        out.append("name")
    if method != info.compress_type:
        out.append("method")
    if (flags ^ info.flag_bits) & 0x1:
        out.append("encryption flag")
    if not flags & 0x8 and 0xFFFFFFFF not in (csize, usize):
        if crc != info.CRC:
            out.append("crc")
        if csize != info.compress_size or usize != info.file_size:
            out.append("sizes")
    return out


def stream_member(archive, info, budget):
    """Yield the bytes of one member in chunks, under the budgets. Raises Unreadable (kind: encrypted, unsupported,
    failed, over_budget, not_attempted) and never returns a truncated member as a whole one."""
    if info.flag_bits & 0x1 or info.compress_type == 99:
        raise Unreadable("encrypted", "the member is marked encrypted (general purpose flag bit 0%s)" % (" or AES method 99" if info.compress_type == 99 else ""))
    if info.compress_type not in METHODS_READ:
        raise Unreadable("unsupported", ("compression method %d is not read: OOXML parts are stored (0) or deflated (8), and the standard library "
                                         "decompresses any other method whole, with no limit on its output, so it cannot be held to a budget") % info.compress_type)
    declared = info.file_size
    if declared > budget.member:
        raise Unreadable("over_budget", "the member declares %d bytes, over max_stream_bytes (%d)" % (declared, budget.member))
    if declared > RATIO_FLOOR and declared > budget.ratio * max(info.compress_size, 1):
        raise Unreadable("over_budget", "the member declares %d bytes from %d compressed: an expansion ratio over max_ratio (%d)"
                         % (declared, info.compress_size, budget.ratio))
    if budget.used + declared > budget.total:
        raise Unreadable("not_attempted", "the member declares %d bytes and %d of the total budget of %d are left"
                         % (declared, budget.total - budget.used, budget.total))
    try:
        fh = archive.open(info)
    except RuntimeError as exc:
        raise Unreadable("encrypted", "the member needs a password (%s)" % type(exc).__name__)
    except NotImplementedError:
        raise Unreadable("unsupported", "compression method %d is not read" % info.compress_type)
    except Exception as exc:
        raise Unreadable("failed", "the member could not be opened (%s)" % type(exc).__name__)
    read = 0
    with fh:
        while True:
            try:
                chunk = fh.read(PAGE)
            except Exception as exc:
                raise Unreadable("failed", "the member could not be read to its end (%s: %s)" % (type(exc).__name__, shown_path(str(exc))))
            if not chunk:
                return
            read += len(chunk)
            budget.used += len(chunk)
            if read > budget.member:
                raise Unreadable("over_budget", "the member expanded past max_stream_bytes (%d)" % budget.member)
            if read > RATIO_FLOOR and read > budget.ratio * max(info.compress_size, 1):
                raise Unreadable("over_budget", "the member expanded past max_ratio (%d) of its compressed size" % budget.ratio)
            if budget.used > budget.total:
                raise Unreadable("over_budget", "the members together expanded past max_total_bytes (%d)" % budget.total)
            yield chunk


# --- the call's bookkeeping ----------------------------------------------------------------------------------------------

class Over(Exception):
    """A budget was reached. The message says which, in words that go straight into `limits_hit`."""


class TimeUp(Over):
    """The clock ran out inside a structure that has no loop of its own to check it (a PDF object being parsed, a predictor)."""


class Stop(Exception):
    def __init__(self, message, partial=None):
        Exception.__init__(self, message)
        self.message, self.partial = message, partial or {}


def member_name(name, ctx, kind="part_name"):
    """A name as it may be printed: tested one component at a time, by its length only past SHOWN_TARGET. The real name behind a
    withheld one is kept."""
    shown = shown_name(name)
    if shown != name:
        ctx.names.add(name, shown, kind)
    return shown


def text_of(value, ctx=None, kind="text"):
    """A string out of a document, as it may be printed: control characters escaped, then the sanitiser (shown_path) over the whole, and
    one longer than SHOWN_TARGET given by its length only. (The shared block's scrub alone, first, would leave a marker where a
    user-info's user name was token-shaped, and no rule after it would read `<marker>:password@` as a user-info.)"""
    text = value if isinstance(value, str) else str(value)
    if len(text) > SHOWN_TARGET:
        return long_text(text, "a string")
    return shown_path(cell(text))


def key_of(value):
    """A string out of a document used as a key of the answer (a /Type, a filter chain, a crypt filter or an annotation subtype that
    is counted): as text_of, and a `<` written \\x3c, so that no text of the file reads as a marker the tool writes (a withheld
    string, or a key kept apart with ' #2')."""
    if isinstance(value, LongName):
        return str(value)
    text = value if isinstance(value, str) else str(value)
    if len(text) > SHOWN_TARGET:
        return long_text(text, "a key")
    return shown_path(cell(text).replace("<", "\\x3c"))


class KeyedCounts:
    """Counts keyed by a string out of the file as the answer shows it (key_of): two different strings that are withheld to one text are
    two keys, the second with ' #2', so that no count of one name is added to another's."""

    def __init__(self):
        self.keys, self.counts = {}, {}

    def key(self, raw):
        k = self.keys.get(raw)
        if k is None:
            base = k = key_of(raw)
            n = 1
            while k in self.counts:
                n += 1
                k = "%s #%d" % (base, n)
            self.keys[raw] = k
            self.counts[k] = 0
        return k

    def add(self, raw):
        self.counts[self.key(raw)] += 1

    def __contains__(self, raw):
        return raw in self.keys

    def __len__(self):
        return len(self.counts)


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
        self.budget = Budget(cfg["max_stream_bytes"], cfg["max_total_bytes"], cfg["max_ratio"])
        self.extracted = []
        self.counter = [0]
        self.finding = [0]
        self.nested = [0]               # nested compound files read (ZIP members, RTF objects): their sequence numbers

    def expired(self, where):
        if time.monotonic() <= self.deadline:
            return False
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

    def page(self, name, limit=None):
        if name not in self.pages:
            self.pages[name] = LosslessPage("doc_structure-" + name, [self.key, name], limit or self.limit, self.tick)
        return self.pages[name]

    def tick(self):
        """The clock, for a loop that has no place to stop of its own: past max_seconds it raises TimeUp, which the reader of the
        container turns into a limit, keeping what was read."""
        if time.monotonic() > self.deadline:
            raise TimeUp("time: max_seconds (%d) was reached; what was read is reported, and the counts are lower bounds" % self.seconds)

    def next_finding(self, letter):
        self.finding[0] += 1
        return "%s%06d" % (letter, self.finding[0])

    def spend(self, n, what):
        """Count `n` bytes read or expanded against the total budget."""
        self.budget.used += n
        if self.budget.used > self.budget.total:
            raise Over("%s: the streams read together passed max_total_bytes (%d); the rest of this call reads no more stream content" % (what, self.budget.total))


def iso_filetime(value):
    """A Windows FILETIME (100 ns ticks since 1601-01-01 UTC) as ISO 8601 UTC with its fraction, or None for zero and for a value
    outside the calendar."""
    if not value:
        return None
    try:
        moment = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=value // 10)
    except OverflowError:
        return None
    return "%s.%07dZ" % (moment.strftime("%Y-%m-%dT%H:%M:%S"), value % 10_000_000)


GUID_TEXT = re.compile(rb"[A-Za-z0-9_+/=-]{9,}")
GUID_CHARS = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_+/=-")


def guid_is_text(raw):
    """Sixteen bytes that hold a run of nine token characters, or ten such characters in all (text split by a NUL every few bytes, so that
    no run is nine long), are text placed where an identifier goes. Uniform random bytes reach ten about once in 420 ids (a class id
    of the Office formats, mostly zero bytes, never does): such an id is withheld, by its length."""
    return bool(GUID_TEXT.search(raw)) or sum(1 for b in raw if b in GUID_CHARS) >= 10


def guid(raw):
    """A class id as a GUID. Sixteen bytes that read as text (guid_is_text) are text placed where an identifier goes, not an identifier,
    and their hex would print the text: such a field is given as withheld, by its length."""
    if len(raw) != 16 or not any(raw):
        return None
    if guid_is_text(raw):
        return "<16 bytes that read as text, withheld>"
    d1, d2, d3 = struct.unpack_from("<IHH", raw)
    return made("%08X-%04X-%04X-%s-%s" % (d1, d2, d3, raw[8:10].hex().upper(), raw[10:16].hex().upper()))


# --- extraction: byte-exact, in a file, only what was asked for -----------------------------------------------------------

class Extractor:
    """Writes the objects the caller named (selectors) into `extract_to`: each file is created exclusively, mode 0600, under a name
    made of a counter and nothing from the document. A selector that matches nothing is a problem. Every object is written
    under the stream budget or not at all: a cut copy would pass for the object."""

    KINDS = ("vba", "javascript", "ole", "zip", "pdf", "pdf-raw", "rtf")

    def __init__(self, ctx, extract_to, selectors):
        self.ctx = ctx
        self.dir = extract_to
        self.selectors = []
        for text in selectors:
            kind, _sep, rest = text.partition(":")
            if kind not in self.KINDS or (kind in ("vba", "javascript")) == bool(rest) or (kind in ("pdf", "pdf-raw", "rtf") and not rest.isdigit()):
                fail("extract: a selector of %d characters is not a selector this tool reads (vba, javascript, ole:<stream path>, zip:<member name>, pdf:<object number>, pdf-raw:<object number>, rtf:<object number>)" % len(text))
            self.selectors.append({"kind": kind, "arg": rest, "matched": 0, "text": text})

    def wants(self, kind, arg=None):
        found = False
        for sel in self.selectors:
            if sel["kind"] == kind and (arg is None or sel["arg"] == str(arg) or (kind in ("ole", "zip") and sel["arg"].lower() == str(arg).lower())):
                found = True
        return found

    def wanted_args(self, kind):
        return [s["arg"] for s in self.selectors if s["kind"] == kind]

    def write(self, kind, arg, locator, chunks, source):
        """Write `chunks` (bytes or an iterable of bytes) for the selector (kind, arg); returns the row."""
        for sel in self.selectors:
            if sel["kind"] == kind and (not sel["arg"] or sel["arg"] == str(arg) or sel["arg"].lower() == str(arg).lower()):
                sel["matched"] += 1
        self.ctx.counter[0] += 1
        index = self.ctx.counter[0]
        shown = shown_path(locator)
        row = {"locator": shown, "source": source}
        if shown != locator:
            row["locator_withheld"] = True
            self.ctx.names.add(locator, shown, "extraction_locator")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        fd = target = None
        for n in range(1, 100):
            name = "extract-%04d.bin" % index if n == 1 else "extract-%04d-%d.bin" % (index, n)
            target = resolve_output(os.path.join(self.dir, name), "extract_to")
            try:
                fd = os.open(target, flags, 0o600)
                break
            except FileExistsError:
                continue
            except OSError as exc:
                self.ctx.problem("%s: the file could not be created in extract_to (%s)" % (shown, describe(exc)))
                row["status"] = "failed"
                self.ctx.extracted.append(row)
                return row
        if fd is None:
            self.ctx.problem("%s: ninety-nine files of this name already exist in extract_to" % shown)
            row["status"] = "failed"
            self.ctx.extracted.append(row)
            return row
        written, kept, digest = 0, False, hashlib.sha256()
        try:
            with os.fdopen(fd, "wb") as out_fh:
                fd = None
                if isinstance(chunks, (bytes, bytearray)):
                    chunks = [bytes(chunks)]
                for chunk in chunks:
                    out_fh.write(chunk)
                    digest.update(chunk)
                    written += len(chunk)
            kept = True
        except Over as exc:
            row["status"] = "over_budget"
            self.ctx.limit_hit("%s: %s" % (shown, exc))
        except Unreadable as exc:
            row["status"] = exc.kind
            (self.ctx.limit_hit if exc.kind in ("over_budget", "not_attempted") else self.ctx.problem)("%s: %s" % (shown, exc.reason))
        except OSError as exc:
            row["status"] = "failed"
            self.ctx.problem("%s: writing failed (%s)" % (shown, describe(exc)))
        finally:
            if fd is not None:
                os.close(fd)
            if not kept:
                try:
                    os.unlink(target)
                except OSError:
                    pass
        if kept:
            row["status"] = "written"
            row["file"] = shown_path(target)
            row["bytes"] = written
            # No digest of an extracted object is in the answer: the object can be a secret (a token planted as a script), and a hash
            # of a secret confirms it (docs/packs.md section 8). With write_values, in a job, the digest goes to the values file.
            if self.ctx.values.enabled:
                finding = self.ctx.next_finding("E")
                self.ctx.values.add(finding, {"kind": "extracted_object_sha256", "file": row["file"], "bytes": written}, digest.hexdigest())
                row["sha256_in_values_file"] = finding
        self.ctx.extracted.append(row)
        return row

    def tried(self, kind, arg=None):
        """A selector whose object was found and could not be written: the reason is a problem or a limit already, not "matched nothing"."""
        for sel in self.selectors:
            if sel["kind"] == kind and (arg is None or not sel["arg"] or sel["arg"] == str(arg)):
                sel["matched"] += 1

    def unmatched(self):
        return [s["text"] for s in self.selectors if not s["matched"]]


# --- XML: namespace-aware, no DOCTYPE, nothing expanded --------------------------------------------------------------------

class DoctypeRefused(Exception):
    pass


def xml_elements(chunks, on_element):
    """Hand every element to `on_element(local_name, namespace, attrs)` as it is read; attribute names are local names. A DOCTYPE is
    refused, so no entity is ever expanded. Raises DoctypeRefused or xml.parsers.expat.ExpatError."""
    parser = xml.parsers.expat.ParserCreate(namespace_separator=" ")
    parser.SetParamEntityParsing(xml.parsers.expat.XML_PARAM_ENTITY_PARSING_NEVER)

    def start(name, attrs):
        ns, _sp, local = name.rpartition(" ")
        on_element(local, ns, {k.rpartition(" ")[2]: v for k, v in attrs.items()})

    def doctype(*_args):
        raise DoctypeRefused()

    parser.StartElementHandler = start
    parser.StartDoctypeDeclHandler = doctype
    for chunk in chunks:
        parser.Parse(chunk, False)
    parser.Parse(b"", True)


# --- OLE compound file (MS-CFB) --------------------------------------------------------------------------------------------

FREESECT, ENDOFCHAIN, FATSECT, DIFSECT, MAXREGSECT = 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFD, 0xFFFFFFFC, 0xFFFFFFFA
NOSTREAM = 0xFFFFFFFF
CFB_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
ENTRY_TYPES = {0: "unallocated", 1: "storage", 2: "stream", 5: "root"}
# name (lower case) -> (kinds it applies to: 1 storage, 2 stream, what it is)
NOTABLE_STREAMS = {
    "\x01ole10native": ((2,), "OLE 1.0 native data: an embedded file, package or other object's bytes"),
    "\x01compobj": ((2,), "the compound object's class and format names"),
    "\x05summaryinformation": ((2,), "the summary property set (title, author, times)"),
    "\x05documentsummaryinformation": ((2,), "the document summary property set"),
    "encryptioninfo": ((2,), "the encryption descriptor of an OOXML package in an OLE wrapper"),
    "encryptedpackage": ((2,), "the encrypted OOXML package"),
    "worddocument": ((2,), "the Word binary document stream"),
    "workbook": ((2,), "the Excel workbook stream (BIFF8)"),
    "book": ((2,), "the Excel workbook stream (BIFF5 and earlier)"),
    "powerpoint document": ((2,), "the PowerPoint document stream"),
    "current user": ((2,), "the PowerPoint current-user stream"),
    "_vba_project_cur": ((1,), "an Excel VBA project storage"),
    "macros": ((1,), "the Word VBA storage"),
    "vba": ((1,), "a VBA storage"),
    "_vba_project": ((2,), "the VBA project header and performance cache"),
    "project": ((2,), "the VBA project properties stream (text)"),
    "projectwm": ((2,), "the VBA module-name map"),
    "dir": ((2,), "in a VBA storage: the compressed project information stream"),
    "objectpool": ((1,), "the storage of embedded objects"),
    "\x01ole": ((2,), "the OLE link or embedding stream"),
    "\x06dataspaces": ((1,), "how the package is transformed (encryption, rights management)"),
}


class CfbError(Exception):
    pass


class Entry:
    __slots__ = ("sid", "name", "kind", "left", "right", "child", "clsid", "start", "size", "created", "modified", "reachable", "parts", "name_bad", "parent", "duplicate")


def cfb_key(name):
    """A directory entry name as [MS-CFB] 2.6.4 compares names: each UTF-16 code unit upper-cased by its simple (one to one) mapping, so
    that `dir` and `DIR` are one name, and a character whose upper case is longer (as `ß`) is compared as it is."""
    out = []
    for c in name:
        u = c.upper()
        if len(u) != 1:
            # Python upper-cases by the full mapping; where that gives more than one character, the simple mapping is the title case
            # when that is one character (U+1FB3 to U+1FBC), and none otherwise (U+00DF stays itself)
            u = c.title()
        out.append(u if len(u) == 1 else c)
    return "".join(out)


class Cfb:
    """A compound file read from a bytes-like source (a memory map or bytes): header, FAT, mini FAT, directory. Sector chains are
    walked with cycle detection and a step budget, and every offset is checked against the source before it is read. Whatever is
    wrong is a problem on the context, with the label of this file ("" for the document itself, a path for a nested one)."""

    def __init__(self, src, ctx, label=""):
        self.src, self.ctx, self.label = src, ctx, label
        self.size = len(src)
        self.entries = []
        self.by_path = {}               # the path of names as [MS-CFB] compares them -> every reachable entry at that path
        self.kids = {}                  # the sid of a storage -> name as compared -> the entries of that name in it
        self.duplicates = 0             # names that a storage holds more than once
        self.orphans = 0
        head = src[:512]
        if len(head) < 512:
            raise CfbError("the file is shorter than the 512-byte compound file header")
        if head[:8] != CFB_MAGIC:
            raise CfbError("the compound file signature is not at offset 0")
        self.minor, self.major, order, shift, mini_shift = struct.unpack_from("<HHHHH", head, 24)
        if order != 0xFFFE:
            raise CfbError("the byte-order mark is 0x%04X, not 0xFFFE" % order)
        if (self.major, shift) not in ((3, 9), (4, 12)):
            raise CfbError("major version %d with sector shift %d is not a layout this tool reads (3 with 9, 4 with 12)" % (self.major, shift))
        if mini_shift != 6:
            raise CfbError("the mini sector shift is %d, not 6" % mini_shift)
        self.ss = 1 << shift
        (self.n_dir_sectors, self.n_fat, self.first_dir, _tx, self.cutoff, self.first_minifat, self.n_minifat,
         self.first_difat, self.n_difat) = struct.unpack_from("<IIIIIIIII", head, 40)
        self.nsect = max(0, (self.size - self.ss + self.ss - 1) // self.ss)
        self.steps = max(1_000_000, 20 * self.nsect)
        if self.cutoff != 4096:
            self.warn("the mini stream cutoff is %d, not 4096" % self.cutoff)
        self.fat = self._read_fat(head)
        self.minifat = self._read_minifat()
        self.mini_chain = None

    def warn(self, text):
        self.ctx.problem(("%s: " % self.label if self.label else "") + text)

    # sectors and chains ---------------------------------------------------------------------------------------------

    def sector(self, n):
        at = (n + 1) * self.ss
        if n >= self.nsect or at >= self.size:
            return None
        return self.src[at:at + self.ss]

    def _u32s(self, raw):
        a = array.array("I")
        a.frombytes(raw[:len(raw) // 4 * 4])
        if sys.byteorder == "big":
            a.byteswap()
        return a

    def _read_fat(self, head):
        difat = list(struct.unpack_from("<109I", head, 76))
        sectors, seen = [], set()
        for n in difat:
            if n == FREESECT:
                continue
            sectors.append(n)
        nxt, hops = self.first_difat, 0
        per = self.ss // 4 - 1
        while nxt not in (ENDOFCHAIN, FREESECT) and hops < min(self.n_difat, self.nsect + 1):
            if nxt in seen:
                self.warn("the DIFAT chain loops back to sector %d" % nxt)
                break
            seen.add(nxt)
            raw = self.sector(nxt)
            if raw is None or len(raw) < self.ss:
                self.warn("DIFAT sector %d lies outside the file" % nxt)
                break
            vals = struct.unpack("<%dI" % (self.ss // 4), raw)
            sectors += [v for v in vals[:per] if v != FREESECT]
            nxt = vals[per]
            hops += 1
        if len(sectors) != self.n_fat:
            self.warn("the header declares %d FAT sector(s) and the DIFAT lists %d" % (self.n_fat, len(sectors)))
        fat = array.array("I")
        for n in sectors:
            raw = self.sector(n)
            if raw is None:
                self.warn("FAT sector %d lies outside the file (the file may be truncated)" % n)
                continue
            if len(raw) < self.ss:
                self.warn("FAT sector %d is cut short by the end of the file" % n)
            fat.extend(self._u32s(raw))
        # [MS-CFB] 2.3: a sector that holds the FAT is marked FATSECT in the FAT, and a DIFAT sector DIFSECT. One that is not is also
        # free for a stream's chain to take, and two readers can disagree on what it holds.
        unmarked = sum(1 for n in sectors if n < len(fat) and fat[n] != FATSECT)
        if unmarked:
            self.warn("%d FAT sector(s) are not marked FATSECT in the FAT itself" % unmarked)
        unmarked = sum(1 for n in seen if n < len(fat) and fat[n] != DIFSECT)
        if unmarked:
            self.warn("%d DIFAT sector(s) are not marked DIFSECT in the FAT" % unmarked)
        return fat

    def chain(self, start, fat=None, label="chain"):
        """The sectors of a chain, and what ended it: 'end' (ENDOFCHAIN), 'loop', 'outside' (a sector number past the FAT or the
        file), 'free' (a free sector inside a chain), 'budget'."""
        fat = self.fat if fat is None else fat
        out, seen, n = array.array("I"), set(), start
        while True:
            if n == ENDOFCHAIN:
                return out, "end"
            if n >= len(fat) or n > MAXREGSECT:
                return out, ("free" if n == FREESECT else "outside")
            if n in seen:
                return out, "loop"
            self.steps -= 1
            if self.steps < 0:
                return out, "budget"
            seen.add(n)
            out.append(n)
            n = fat[n]

    def _read_minifat(self):
        if self.n_minifat == 0 or self.first_minifat == ENDOFCHAIN:
            return array.array("I")
        chain, why = self.chain(self.first_minifat)
        if why != "end":
            self.warn("the mini FAT chain ends with %s, not at an end-of-chain marker" % why)
        mf = array.array("I")
        for n in chain:
            raw = self.sector(n)
            if raw is None:
                self.warn("mini FAT sector %d lies outside the file" % n)
                continue
            mf.extend(self._u32s(raw))
        return mf

    # directory ------------------------------------------------------------------------------------------------------

    def read_directory(self, max_entries):
        chain, why = self.chain(self.first_dir)
        if why != "end":
            self.warn("the directory chain ends with %s, not at an end-of-chain marker" % why)
        per = self.ss // 128
        total = len(chain) * per
        if total > max_entries:
            self.ctx.limit_hit("%sthe directory holds %d entries: the first %d were read" % ("%s: " % self.label if self.label else "", total, max_entries))
        raws = []
        for n in chain:
            raw = self.sector(n)
            if raw is None:
                self.warn("directory sector %d lies outside the file" % n)
                break
            raws.append(raw)
            if len(raws) * per >= max_entries:
                break
        data = b"".join(raws)
        for i in range(min(len(data) // 128, max_entries)):
            row = data[i * 128:(i + 1) * 128]
            e = Entry()
            e.sid, e.reachable, e.parts, e.parent, e.duplicate = i, False, None, None, False
            namelen = struct.unpack_from("<H", row, 64)[0]
            # [MS-CFB] 2.6.1: the length counts the terminating NUL, which is there: a name without one is broken too
            e.name_bad = namelen > 64 or namelen % 2 == 1 or (namelen == 0 and row[66] != 0) or (2 <= namelen <= 64 and row[namelen - 2:namelen] != b"\0\0")
            # The length counts bytes of UTF-16 with its terminator; an odd one (or one past 64) is a broken entry, read as far
            # as whole code units go and said, never a decoding error that ends the call.
            take = (max(0, min(namelen, 64) - 2) if namelen >= 2 else 0) & ~1
            e.name = row[:take].decode("utf-16-le", "surrogatepass")
            e.kind = row[66]
            e.left, e.right, e.child = struct.unpack_from("<III", row, 68)
            e.clsid = guid(row[80:96])
            e.created, e.modified = struct.unpack_from("<QQ", row, 100)
            e.start = struct.unpack_from("<I", row, 116)[0]
            e.size = struct.unpack_from("<Q", row, 120)[0]
            if self.major == 3:
                e.size &= 0xFFFFFFFF
            self.entries.append(e)
        if not self.entries or self.entries[0].kind != 5:
            raise CfbError("the first directory entry is not the root storage")
        return len(self.entries)

    def walk(self, max_depth):
        """Mark the entries the red-black trees reach from the root; build each reachable entry's path. Cycles and shared entries are
        problems, and an allocated entry no tree reaches is an orphan."""
        root = self.entries[0]
        root.reachable, root.parts = True, ()
        stack = [(root.child, (), 1, 0)]
        n = len(self.entries)
        while stack:
            sid, parent, depth, holder = stack.pop()
            if sid == NOSTREAM:
                continue
            if sid >= n:
                self.warn("a directory link names entry %d and the directory has %d entries read" % (sid, n))
                continue
            e = self.entries[sid]
            if e.reachable:
                self.warn("directory entry %d is reached twice: the trees loop or share an entry" % sid)
                continue
            e.reachable = True
            e.parts = parent + (e.name,)
            e.parent = holder
            stack.append((e.left, parent, depth, holder))
            stack.append((e.right, parent, depth, holder))
            if e.kind in (1, 5):
                if depth >= max_depth:
                    self.ctx.limit_hit("%sstorages nest past max_depth (%d): the entries below %s are listed without a path" % ("%s: " % self.label if self.label else "", max_depth, shown_path("/".join(e.parts))))
                else:
                    stack.append((e.child, e.parts, depth + 1, e.sid))
        self.orphans = sum(1 for e in self.entries if e.kind != 0 and not e.reachable)
        for e in self.entries:
            if e.reachable and e.parts is not None and e.kind in (1, 2):
                self.by_path.setdefault(tuple(cfb_key(p) for p in e.parts), []).append(e)
                self.kids.setdefault(e.parent, {}).setdefault(cfb_key(e.name), []).append(e)
        # [MS-CFB] 2.6.4: the names of the entries of one storage are unique, compared in upper case. Two entries of one name are two
        # readings of the file (a reader takes the one its tree search meets first): each is listed and read, and the file is partial.
        for holder, names in self.kids.items():
            for same in names.values():
                if len(same) > 1:
                    self.duplicates += 1
                    for e in same:
                        e.duplicate = True
                    self.warn("directory entries %s share the name %s in one storage ([MS-CFB] 2.6.4: names in a storage are unique, compared in upper "
                              "case): readers differ on which one they take; each is listed, every copy of a VBA storage's dir and module streams is read, and so is every copy of a root WordDocument, "
                              "Workbook, Book, PowerPoint Document, Current User, EncryptionInfo or EncryptedPackage stream (the others under other_copies); of any "
                              "other stream the first is read"
                              % (", ".join(str(e.sid) for e in same), cell(shown_path("/".join(same[0].parts)))))

    def find(self, *parts):
        found = self.by_path.get(tuple(cfb_key(p) for p in parts))
        return found[0] if found else None

    def find_all(self, *parts):
        return list(self.by_path.get(tuple(cfb_key(p) for p in parts), ()))

    def in_storage(self, storage, name, kind=None):
        """The entries named `name` (as [MS-CFB] compares names) in one storage entry, every copy, of `kind` when given."""
        found = self.kids.get(storage.sid, {}).get(cfb_key(name), [])
        return [e for e in found if kind is None or e.kind == kind]

    def find_stream(self, *parts):
        """The stream at this path, or None: a storage of that name is not a stream and is never read as one."""
        e = self.find(*parts)
        return e if e is not None and e.kind == 2 else None

    def children(self, parts):
        low = tuple(cfb_key(p) for p in parts)
        return [e for e in self.entries if e.reachable and e.parts is not None and len(e.parts) == len(low) + 1 and tuple(cfb_key(p) for p in e.parts[:-1]) == low]

    # streams --------------------------------------------------------------------------------------------------------

    def mini_sectors(self):
        if self.mini_chain is None:
            root = self.entries[0]
            self.mini_chain, why = self.chain(root.start) if root.size else (array.array("I"), "end")
            if why != "end":
                self.warn("the mini stream's chain ends with %s" % why)
            # [MS-CFB] 2.6.3: the root entry's size is the mini stream's size; its chain holds that many bytes, rounded up to a sector
            need = (root.size + self.ss - 1) // self.ss
            if len(self.mini_chain) < need:
                self.warn("the root entry declares a mini stream of %d bytes and its chain holds %d sector(s)" % (root.size, len(self.mini_chain)))
            elif len(self.mini_chain) > need:
                self.warn("the mini stream's chain holds %d sectors and the root entry's size (%d bytes) needs %d" % (len(self.mini_chain), root.size, need))
        return self.mini_chain

    def chunks(self, e, limit=None, take=None):
        """The bytes of a stream, in pieces: all of it, or its first `take` bytes. A stream (or the part asked for) past `limit`
        (default the stream budget) raises Unreadable('over_budget'); a chain that ends early or leaves the file raises
        Unreadable('failed'). Nothing wrong is yielded."""
        limit = self.ctx.budget.member if limit is None else limit
        size = e.size
        want = size if take is None else min(size, take)
        if want > limit:
            raise Unreadable("over_budget", "the stream declares %d bytes, over max_stream_bytes (%d)" % (want, limit))
        if want > self.size:
            raise Unreadable("failed", "the stream declares %d bytes in a %d-byte file" % (want, self.size))
        self.ctx.spend(want, "a stream")
        if want <= 0:
            return
        if size < self.cutoff and e.kind == 2:
            yield from self._mini(e, want)
            return
        chain, why = self.chain(e.start)
        need = (want + self.ss - 1) // self.ss
        if len(chain) < need:
            raise Unreadable("failed", "the stream declares %d bytes (%d sectors) and its chain ends after %d sector(s) (%s)" % (want, need, len(chain), why))
        left = want
        for n in chain[:need]:
            raw = self.sector(n)
            if raw is None or (len(raw) < min(self.ss, left)):
                raise Unreadable("failed", "sector %d of the stream is cut off by the end of the file" % n)
            piece = raw[:min(self.ss, left)]
            left -= len(piece)
            yield bytes(piece)

    def _mini(self, e, want):
        need = (want + 63) // 64
        chain, why = self.chain(e.start, self.minifat)
        if len(chain) < need:
            raise Unreadable("failed", "the stream declares %d bytes (%d mini sectors) and its mini chain ends after %d (%s)" % (want, need, len(chain), why))
        base = self.mini_sectors()
        left = want
        for m in chain[:need]:
            off = m * 64
            holder = off // self.ss
            if holder >= len(base) or off + min(64, left) > self.entries[0].size:
                raise Unreadable("failed", "mini sector %d lies beyond the mini stream (the root entry declares %d bytes)" % (m, self.entries[0].size))
            raw = self.sector(base[holder])
            if raw is None:
                raise Unreadable("failed", "the sector holding mini sector %d lies outside the file" % m)
            piece = raw[off % self.ss:off % self.ss + min(64, left)]
            if len(piece) < min(64, left):
                raise Unreadable("failed", "mini sector %d is cut off by the end of the file" % m)
            left -= len(piece)
            yield bytes(piece)

    def verify_stream(self, e, owners=None):
        """(None when the stream's chain is whole and inside the file, else why not; notes on the rest of the chain). Walks the whole
        chain, past what the size needs, and reads no data. The notes: a chain that goes on past the sectors the size needs and does not
        end at an end-of-chain marker (a loop or a link out of the FAT), more sectors than the size needs, and a sector another
        stream's chain holds too (`owners`, sector -> entry, kept across the directory)."""
        size = e.size
        if size == 0:
            return None, []
        if size > self.size:
            return "it declares %d bytes in a %d-byte file" % (size, self.size), []
        if self.steps <= 0:
            return "not checked: the chain-walk budget of this file is spent", []
        mini = size < self.cutoff and e.kind == 2
        chain, why = self.chain(e.start, self.minifat if mini else None)
        need = (size + 63) // 64 if mini else (size + self.ss - 1) // self.ss
        unit = "mini sector" if mini else "sector"
        notes = []
        if len(chain) >= need:
            if why != "end":
                notes.append("its chain goes on past the %d %s(s) its size needs and ends with %s, not at an end-of-chain marker" % (need, unit, why))
            elif len(chain) > need:
                notes.append("its chain holds %d %ss and its size needs %d" % (len(chain), unit, need))
            if owners is not None:
                book = owners.setdefault(unit, {})
                shared = next(((n, book[n]) for n in chain if n in book and book[n] != e.sid), None)
                for n in chain:
                    book.setdefault(n, e.sid)
                if shared:
                    notes.append("%s %d of its chain is also in the chain of directory entry %d" % (unit, shared[0], shared[1]))
        if mini:
            if len(chain) < need:
                return "its mini chain ends after %d of %d mini sectors (%s)" % (len(chain), need, why), notes
            base = self.mini_sectors()
            # each mini sector the stream uses lies inside the mini stream's declared size: the last one to the stream's last byte
            ends = max([m * 64 + 64 for m in chain[:need - 1]] + [chain[need - 1] * 64 + size - (need - 1) * 64])
            if (max(chain[:need]) * 64 + 63) // self.ss >= len(base) or ends > self.entries[0].size:
                return "a mini sector lies beyond the mini stream (the root entry declares %d bytes)" % self.entries[0].size, notes
            return None, notes
        if len(chain) < need:
            return "its chain ends after %d of %d sectors (%s)" % (len(chain), need, why), notes
        rem = size - (need - 1) * self.ss
        if need > 1 and (max(chain[:need - 1]) + 2) * self.ss > self.size:
            return "a sector of the stream is cut off by the end of the file", notes
        if (chain[need - 1] + 1) * self.ss + rem > self.size:
            return "its last sector is cut off by the end of the file", notes
        return None, notes

    def head(self, e, n):
        return b"".join(self.chunks(e, take=n))

    def read(self, e, limit=None):
        return b"".join(self.chunks(e, limit))


def ole_entry_rows(cfb, ctx, page, extractor, extra=None):
    kinds = {"storage": 0, "stream": 0, "root": 0, "unallocated": 0, "other": 0}
    chains = {"checked": 0, "broken": 0, "not_checked": 0, "anomalies": 0}
    owners = {}
    for e in cfb.entries:
        name = ENTRY_TYPES.get(e.kind, "other")
        kinds[name] += 1
        if e.kind == 0 and not e.reachable:
            continue
        path = "/".join(e.parts) if e.parts is not None else e.name
        shown = shown_name(path)
        row = {"sid": e.sid, "path": cell(shown), "type": name, "size": e.size, "start_sector": e.start, "reachable": e.reachable}
        if extra:
            row.update(extra)
        if shown != path:
            row["name_withheld"] = True
            ctx.names.add(path, shown)
        if e.clsid:
            row["clsid"] = e.clsid
        if e.created:
            row["created"] = {"raw": e.created, "utc": iso_filetime(e.created)}
        if e.modified:
            row["modified"] = {"raw": e.modified, "utc": iso_filetime(e.modified)}
        known = NOTABLE_STREAMS.get(e.name.lower()) if e.parts is not None else None
        if known and e.kind in known[0]:
            row["note"] = known[1]
        if e.name_bad:
            row["name_length_inconsistent"] = True
        if e.duplicate:
            row["duplicate_name_in_storage"] = True
        if e.kind == 2:
            ctx.tick()
            why, notes = cfb.verify_stream(e, owners)
            for note in notes:
                chains["anomalies"] += 1
                row.setdefault("chain_notes", []).append(note)
                ctx.problem("%sstream %s: %s" % ("%s: " % cfb.label if cfb.label else "", cell(shown), note))
            if why is None:
                chains["checked"] += 1
            elif why.startswith("not checked"):
                chains["not_checked"] += 1
                row["chain"] = why
            else:
                chains["checked"] += 1
                chains["broken"] += 1
                row["chain"] = "broken: " + why
                ctx.problem("stream %s: %s" % (cell(shown), why))
        page.add(row)
    odd = sorted({e.kind for e in cfb.entries if e.kind not in ENTRY_TYPES})
    if odd:
        ctx.problem("%s%d directory entr%s of a type [MS-CFB] 2.6.1 does not define (%s): listed as other, not read" % (
            "%s: " % cfb.label if cfb.label else "", kinds["other"], "y is" if kinds["other"] == 1 else "ies are", ", ".join("0x%02X" % k for k in odd)))
    reached_free = sum(1 for e in cfb.entries if e.kind == 0 and e.reachable)
    if reached_free:
        ctx.problem("%s%d unallocated directory entr%s reached from a storage's tree: listed, and read as nothing" % (
            "%s: " % cfb.label if cfb.label else "", reached_free, "y is" if reached_free == 1 else "ies are"))
    bad_names = sum(1 for e in cfb.entries if e.kind != 0 and e.name_bad)
    if bad_names:
        ctx.problem("%s%d directory entr%s a name length that does not fit the name field (odd, over 64 bytes, or zero with a name): each name is read as far as whole UTF-16 code units go, and the row says name_length_inconsistent"
                    % ("%s: " % cfb.label if cfb.label else "", bad_names, "y has" if bad_names == 1 else "ies have"))
    if chains["not_checked"]:
        ctx.limit_hit("%sthe chain-walk budget of this file was spent: %d stream chain(s) were not checked" % ("%s: " % cfb.label if cfb.label else "", chains["not_checked"]))
    kinds["stream_chains"] = chains
    return kinds


# --- VBA project (MS-OVBA) -------------------------------------------------------------------------------------------------

def ovba_decompress(data, limit, ctx=None):
    """MS-OVBA 2.4.1 decompression of a compressed container. Returns (bytes, problem or None). Output past `limit` raises Over."""
    if not data:
        return b"", "the compressed container is empty"
    if data[0] != 1:
        return b"", "the compressed container does not begin with the signature byte 0x01"
    out, pos, n, chunks = bytearray(), 1, len(data), 0
    while pos < n:
        chunks += 1
        if ctx is not None and chunks % 64 == 0 and ctx.expired("a VBA decompression"):
            return bytes(out), "the clock ran out while decompressing"
        if pos + 2 > n:
            return bytes(out), "a chunk header is cut off"
        header = data[pos] | data[pos + 1] << 8
        size, sig, flag = (header & 0x0FFF) + 3, (header >> 12) & 7, header >> 15
        if sig != 3:
            return bytes(out), "a chunk header carries the signature bits %d, not 3" % sig
        end, start_out = pos + size, len(out)
        if end > n:
            return bytes(out), "a chunk of %d bytes is cut off after %d" % (size, n - pos)
        p = pos + 2
        if not flag:
            # An uncompressed chunk is its header and exactly 4096 bytes (MS-OVBA 2.4.1.1.8): the bytes are taken from the chunk
            # itself and never from past its end.
            if size != 4098:
                return bytes(out), "an uncompressed chunk declares %d bytes, not 4098 (a header and 4096 bytes)" % size
            out += data[p:end]
        else:
            while p < end:
                flags = data[p]
                p += 1
                for bit in range(8):
                    if p >= end:
                        break
                    if not (flags >> bit) & 1:
                        out.append(data[p])
                        p += 1
                    else:
                        if p + 2 > end:
                            return bytes(out), "a copy token is cut off by the end of its chunk"
                        token = data[p] | data[p + 1] << 8
                        p += 2
                        done = len(out) - start_out
                        if done < 1:
                            return bytes(out), "a copy token at the start of a chunk has nothing to copy"
                        bits = max((done - 1).bit_length(), 4)
                        length = (token & (0xFFFF >> bits)) + 3
                        offset = (token >> (16 - bits)) + 1
                        if offset > done:
                            return bytes(out), "a copy token reaches %d bytes back in a chunk that has %d" % (offset, done)
                        for _i in range(length):
                            out.append(out[-offset])
                if len(out) - start_out > 4096:
                    return bytes(out), "a chunk expands past 4096 bytes"
        pos = end
        if len(out) > limit:
            raise Over("a VBA module's source expands past max_stream_bytes (%d)" % limit)
    return bytes(out), None


DIR_NO_SIZE = {0x0009}


def parse_vba_dir(data, ctx, where):
    """Walk the decompressed `dir` stream's records (an id, a size, that many bytes; PROJECTVERSION is the one exception)."""
    info = {"modules": [], "references": 0, "codepage": None, "project_name": None, "module_count_declared": None, "cookie": None}
    pos, n, current = 0, len(data), None
    while pos + 6 <= n:
        rid, size = struct.unpack_from("<HI", data, pos)
        pos += 6
        if rid in DIR_NO_SIZE:
            body = data[pos:pos + 4]
            pos += 4 + 2
        else:
            if pos + size > n:
                ctx.problem("%s: a dir record (id 0x%04X) of %d bytes is cut off by the end of the stream" % (where, rid, size))
                break
            body = data[pos:pos + size]
            pos += size
        if rid == 0x0003 and len(body) == 2:
            info["codepage"] = struct.unpack("<H", body)[0]
        elif rid == 0x0004:
            info["project_name"] = body
        elif rid in (0x000D, 0x000E, 0x002F, 0x0033):
            info["references"] += 1
        elif rid == 0x000F and len(body) == 2:
            info["module_count_declared"] = struct.unpack("<H", body)[0]
        elif rid == 0x0019:
            current = {"name": body, "unicode_name": None, "stream_name": None, "text_offset": None, "type": None, "read_only": False, "private": False}
            info["modules"].append(current)
        elif current is not None:
            if rid == 0x0047:
                current["unicode_name"] = body
            elif rid == 0x001A:
                current["stream_name"] = body
            elif rid == 0x0032:
                current["unicode_stream_name"] = body
            elif rid == 0x0031 and len(body) == 4:
                current["text_offset"] = struct.unpack("<I", body)[0]
            elif rid == 0x0021:
                current["type"] = "procedural"
            elif rid == 0x0022:
                current["type"] = "document, class or designer"
            elif rid == 0x0025:
                current["read_only"] = True
            elif rid == 0x0028:
                current["private"] = True
            elif rid == 0x002B:
                current = None
    return info


def codec(info):
    page = info.get("codepage")
    return ("cp%d" % page) if isinstance(page, int) else "latin-1"


def decode_text(raw, encoding):
    try:
        return raw.decode(encoding, "replace")
    except LookupError:
        return raw.decode("latin-1", "replace")


def vba_projects(cfb, ctx, extractor, where):
    """Every storage named VBA that holds a `dir` stream, read as a VBA project: every copy of the dir stream a storage holds is a project
    of its own (two entries of one name are two readings, [MS-CFB] 2.6.4), and every copy of a module's stream is read."""
    found, projects = [], []
    for e in cfb.entries:
        if not (e.reachable and e.parts and cfb_key(e.parts[-1]) == "VBA"):
            continue
        label = shown_path("/".join(e.parts))
        # An entry named VBA that is not a storage, or a VBA storage whose dir is missing or is not a stream, is a VBA project
        # this tool cannot read: it is listed and said, never dropped (a flipped entry type would otherwise hide a project).
        if e.kind != 1:
            projects.append({"storage": cell(label), "modules": [], "status": "not_a_storage", "entry_type": ENTRY_TYPES.get(e.kind, "type %d" % e.kind)})
            ctx.problem("%s: an entry named VBA is of type %s, not a storage: no VBA project was read from it" % (label, ENTRY_TYPES.get(e.kind, "type %d" % e.kind)))
            continue
        dirs = cfb.in_storage(e, "dir")
        streams = [d for d in dirs if d.kind == 2]
        if not streams:
            why = "has no dir stream" if not dirs else "holds a dir entry of type %s, not a stream" % ENTRY_TYPES.get(dirs[0].kind, "type %d" % dirs[0].kind)
            projects.append({"storage": cell(label), "modules": [], "status": "dir_missing" if not dirs else "dir_not_a_stream"})
            ctx.problem("%s: a VBA storage that %s: its project was not read" % (label, why))
            continue
        for k, d in enumerate(streams):
            found.append((e, d, k, len(streams)))
    named = {}                          # VBA storage sid -> the stream names its dir streams give their modules (as compared)
    for store, dir_entry, copy, copies in found:
        base = store.parts
        label = shown_path("/".join(base))
        project = {"storage": cell(label), "modules": [], "status": "read"}
        if copies > 1:
            project["dir_copy"] = {"copy": copy + 1, "of": copies, "dir_entry": dir_entry.sid,
                                   "note": "the storage holds %d entries named dir: each is read as a project of its own" % copies}
        if label != "/".join(base):
            ctx.names.add("/".join(base), label)
        projects.append(project)
        mine = named.setdefault(store.sid, set())
        try:
            raw = cfb.read(dir_entry, ctx.budget.member)
        except (Unreadable, Over) as exc:
            project["status"] = "dir_unreadable"
            ctx.problem("%s: the dir stream could not be read: %s" % (label, getattr(exc, "reason", None) or exc))
            continue
        try:
            data, why = ovba_decompress(raw, ctx.budget.member, ctx)
        except Over as exc:
            project["status"] = "dir_over_budget"
            ctx.limit_hit("%s: %s" % (label, exc))
            continue
        if why:
            ctx.problem("%s: the dir stream does not decompress cleanly: %s" % (label, why))
            project["status"] = "dir_partial"
        info = parse_vba_dir(data, ctx, label)
        enc = codec(info)
        project["codepage"] = info["codepage"]
        if info["project_name"] is not None:
            project["project_name"] = text_of(decode_text(info["project_name"], enc), ctx, "names")
        project["references"] = info["references"]
        project["modules_declared"] = info["module_count_declared"]
        if info["module_count_declared"] is not None and info["module_count_declared"] != len(info["modules"]):
            ctx.problem("%s: the dir stream declares %d module(s) and lists %d" % (label, info["module_count_declared"], len(info["modules"])))
        vps = cfb.in_storage(store, "_VBA_PROJECT", 2)
        vp = vps[0] if vps else None
        if vp is not None:
            project["performance_cache_stream"] = {"bytes": vp.size, "note": "the _VBA_PROJECT stream: a header and the compiled (p-code) cache; this tool does not read it"}
            try:
                head = cfb.head(vp, 7)
            except (Unreadable, Over) as exc:
                head = b""
                ctx.problem("%s: the _VBA_PROJECT stream's header could not be read: %s" % (label, getattr(exc, "reason", None) or exc))
            if len(head) >= 4:
                project["performance_cache_stream"]["version_field"] = struct.unpack_from("<H", head, 2)[0]
        else:
            ctx.problem("%s: no _VBA_PROJECT stream beside the dir stream" % label)
        holder = cfb.entries[store.parent] if store.parent is not None and store.parent < len(cfb.entries) else None
        projs = cfb.in_storage(holder, "PROJECT", 2) if holder is not None else []
        proj_stream = projs[0] if projs else None
        if proj_stream is not None and proj_stream.size > 1 << 20:
            ctx.limit_hit("%s: the PROJECT stream is %d bytes, over the 1 MiB read limit: its keys were not read" % (label, proj_stream.size))
        if proj_stream is not None and proj_stream.size <= 1 << 20:
            try:
                text = cfb.read(proj_stream, 1 << 20)
            except (Unreadable, Over) as exc:
                text = b""
                ctx.problem("%s: the PROJECT stream could not be read: %s" % (label, getattr(exc, "reason", None) or exc))
            keys = []
            for line in text.split(b"\n"):
                key = line.split(b"=", 1)[0].strip().decode("latin-1", "replace")
                if re.fullmatch(r"[A-Za-z]{1,32}", key) and key not in keys:
                    keys.append(key)
            protected = [k for k in ("ID", "CMG", "DPB", "GC") if k in keys]
            if len(keys) > 50:
                ctx.limit_hit("%s: the PROJECT stream holds %d distinct keys: the first 50 are listed" % (label, len(keys)))
            project["project_properties"] = {"keys": keys[:50], "keys_total": len(keys), "protection_fields_present": [k for k in protected if k != "ID"],
                                             "note": "CMG, DPB and GC hold the project's protection data (a password verifier among it): their presence is reported, their values never are"}
        for mod in info["modules"]:
            if ctx.expired("the VBA modules"):
                break
            name_raw = mod["unicode_name"].decode("utf-16-le", "replace") if mod["unicode_name"] else decode_text(mod["name"], enc)
            stream_name = (mod["unicode_stream_name"].decode("utf-16-le", "replace") if mod.get("unicode_stream_name")
                           else decode_text(mod["stream_name"] or b"", enc))
            shown = shown_path(name_raw)
            if shown != name_raw:
                ctx.names.add(name_raw, shown, "vba_module_name")
            copies_of = cfb.in_storage(store, stream_name, 2) if stream_name else []
            if stream_name:
                mine.add(cfb_key(stream_name))
            for k, stream in enumerate(copies_of or [None]):
                row = {"name": cell(shown), "type": mod["type"], "read_only": mod["read_only"], "private": mod["private"], "text_offset": mod["text_offset"]}
                if len(copies_of) > 1:
                    row["stream_copy"] = {"copy": k + 1, "of": len(copies_of), "entry": stream.sid}
                if stream is None:
                    row["stream"] = "missing"
                    ctx.problem("%s: module %s names a stream that the directory does not hold" % (label, cell(shown)))
                    project["modules"].append(row)
                    continue
                row["stream_bytes"] = stream.size
                off = mod["text_offset"]
                if off is None or off > stream.size:
                    row["source"] = "text offset missing or past the stream"
                    ctx.problem("%s: module %s has a text offset (%s) outside its %d-byte stream" % (label, cell(shown), off, stream.size))
                else:
                    row["compressed_source_bytes"] = stream.size - off
                    row["compiled_cache_bytes_before_source"] = off
                    try:
                        blob = cfb.read(stream, ctx.budget.member)
                        source, why = ovba_decompress(blob[off:], ctx.budget.member, ctx)
                    except (Unreadable, Over) as exc:
                        row["source"] = "unreadable"
                        (ctx.limit_hit if isinstance(exc, Over) or getattr(exc, "kind", "") == "over_budget" else ctx.problem)(
                            "%s: module %s: %s" % (label, cell(shown), getattr(exc, "reason", None) or exc))
                    else:
                        row["source_bytes"] = len(source)
                        row["source"] = "decompressed" if not why else "decompressed in part (%s)" % why
                        if why:
                            ctx.problem("%s: module %s: the source does not decompress cleanly: %s" % (label, cell(shown), why))
                        if extractor is not None and extractor.wants("vba"):
                            r = extractor.write("vba", "", "%s%s/%s" % (where, "/".join(base), name_raw), source, "decompressed VBA module source")
                            row["extracted"] = r.get("file") or r.get("status")
                project["modules"].append(row)
    # A stream of a VBA storage that no dir stream read names as a module's (beside dir, _VBA_PROJECT and the __SRP_ caches) is code no
    # project lists: it is said, by name.
    for store, _d, copy, _n in found:
        if copy:
            continue
        mine = named.get(store.sid, set())
        for key, entries in cfb.kids.get(store.sid, {}).items():
            if key in mine or key in ("DIR", "_VBA_PROJECT") or re.fullmatch(r"__SRP_[0-9]+", key):
                continue
            for e in entries:
                if e.kind == 2:
                    ctx.problem("%s: the stream %s in the VBA storage is named by no module of the dir stream%s read" % (
                        shown_path("/".join(store.parts)), cell(shown_path(e.name)), "s" if sum(1 for f in found if f[0] is store) > 1 else ""))
    return projects


# --- encryption structures an Office file records -------------------------------------------------------------------------

STD_ALG = {0x6801: "RC4", 0x660E: "AES-128", 0x660F: "AES-192", 0x6610: "AES-256", 0x0000: "not set (the flags decide)"}
STD_HASH = {0x8004: "SHA-1", 0x0000: "not set (SHA-1)"}
AGILE_SAFE = ("saltSize", "blockSize", "keyBits", "hashSize", "cipherAlgorithm", "cipherChaining", "hashAlgorithm", "spinCount")
KEY_ENCRYPTOR_KINDS = {"http://schemas.microsoft.com/office/2006/keyEncryptor/password": "password",
                       "http://schemas.microsoft.com/office/2006/keyEncryptor/certificate": "certificate"}


def num(text):
    return int(text) if re.fullmatch(r"[0-9]{1,12}", text) else text_of(text, None, "names")


def encryption_info(cfb, ctx, entry):
    """MS-OFFCRYPTO EncryptionInfo. Algorithms, key sizes and counts are reported; salts, verifiers and encrypted keys are not."""
    out = {"stream_bytes": entry.size}
    try:
        data = cfb.read(entry, min(entry.size, 1 << 20))
    except (Unreadable, Over) as exc:
        ctx.problem("EncryptionInfo could not be read: %s" % (getattr(exc, "reason", None) or exc))
        out["scheme"] = "unreadable"
        return out
    if len(data) < 8:
        out["scheme"] = "too short to hold a version"
        ctx.problem("EncryptionInfo is %d bytes: shorter than its version and flags" % len(data))
        return out
    major, minor, flags = struct.unpack_from("<HHI", data, 0)
    out["version"] = "%d.%d" % (major, minor)
    if (major, minor) == (4, 4):
        out["scheme"] = "agile"
        summary = {"key_encryptors": []}

        def element(local, _ns, attrs):
            if local == "keyData":
                summary["data"] = {k: num(attrs[k]) for k in AGILE_SAFE if k in attrs}
            elif local == "keyEncryptor":
                kind = KEY_ENCRYPTOR_KINDS.get(attrs.get("uri", ""), "other")
                summary["key_encryptors"].append({"kind": kind})
                summary["current"] = summary["key_encryptors"][-1]
            elif local == "encryptedKey" and summary.get("current") is not None:
                summary["current"].update({k: num(attrs[k]) for k in AGILE_SAFE if k in attrs})
            elif local == "dataIntegrity":
                summary["data_integrity_present"] = True

        try:
            xml_elements([data[8:]], element)
        except DoctypeRefused:
            ctx.problem("EncryptionInfo: the XML descriptor contains a DOCTYPE, which is refused: it was not parsed")
            out["descriptor"] = "doctype_refused"
        except xml.parsers.expat.ExpatError as exc:
            ctx.problem("EncryptionInfo: the XML descriptor is not well-formed (%s)" % xml.parsers.expat.ErrorString(exc.code))
            out["descriptor"] = "not_well_formed"
        except (LookupError, ValueError) as exc:
            ctx.problem("EncryptionInfo: the XML descriptor declares an encoding the XML reader cannot decode (%s): it was not parsed" % type(exc).__name__)
            out["descriptor"] = "encoding_not_readable"
        summary.pop("current", None)
        out.update(summary)
        out["not_reported"] = "salts, encrypted verifier values and the encrypted key are present in the descriptor and are not reported"
    elif minor == 2 and major in (2, 3, 4):
        out["scheme"] = "standard"
        out["header_flags"] = flags
        if len(data) >= 12:
            hsize = struct.unpack_from("<I", data, 8)[0]
            if 32 <= hsize <= len(data) - 12:
                f, _extra, alg, hashalg, keysize, provider = struct.unpack_from("<IIIIII", data, 12)
                out["flags"] = {"crypto_api": bool(f & 0x04), "doc_props_not_encrypted": bool(f & 0x08), "external": bool(f & 0x10), "aes": bool(f & 0x20)}
                out["algorithm"] = STD_ALG.get(alg, "unrecognised (0x%04X)" % alg)
                out["hash"] = STD_HASH.get(hashalg, "unrecognised (0x%04X)" % hashalg)
                out["key_bits"] = keysize
                out["provider_type"] = provider
            else:
                ctx.problem("EncryptionInfo: the standard header declares %d bytes in a %d-byte stream" % (hsize, len(data)))
        out["not_reported"] = "the salt, the encrypted verifier and its hash are present in the stream and are not reported"
    elif minor == 3 and major in (3, 4):
        out["scheme"] = "extensible (a provider-defined descriptor; not read)"
    else:
        out["scheme"] = "version %d.%d is not one this tool reads" % (major, minor)
        ctx.problem("EncryptionInfo: version %d.%d is not one this tool reads" % (major, minor))
    return out


def biff_records(data, limit):
    """(type, body) for each BIFF record until the first EOF record (0x000A) after the first BOF, or the data ends."""
    pos, n, count = 0, len(data), 0
    seen_bof = False
    while pos + 4 <= n and count < limit:
        rtype, size = struct.unpack_from("<HH", data, pos)
        body = data[pos + 4:pos + 4 + size]
        pos += 4 + size
        count += 1
        yield rtype, body, pos > n
        if rtype == 0x0809:
            seen_bof = True
        elif rtype == 0x000A and seen_bof:
            return


def excel_findings(cfb, ctx, entry, out):
    try:
        data = cfb.read(entry, ctx.budget.member)
    except (Unreadable, Over) as exc:
        (ctx.limit_hit if isinstance(exc, Over) or getattr(exc, "kind", "") == "over_budget" else ctx.problem)("the Excel workbook stream was not read: %s" % (getattr(exc, "reason", None) or exc))
        out["status"] = "unreadable"
        return
    sheets, filepass, bof_version, ended = [], None, None, False
    for rtype, body, cut in biff_records(data, 2_000_000):
        if rtype == 0x0809 and len(body) >= 2 and bof_version is None:
            bof_version = struct.unpack_from("<H", body, 0)[0]
        elif rtype == 0x002F and len(body) >= 2:
            etype = struct.unpack_from("<H", body, 0)[0]
            if etype == 0:
                filepass = {"scheme": "XOR obfuscation", "note": "a weak obfuscation, not encryption; the key check value is not reported"}
            elif etype == 1 and len(body) >= 6:
                vmaj, vmin = struct.unpack_from("<HH", body, 2)
                filepass = {"scheme": "RC4 (Office 97-2003)" if (vmaj, vmin) == (1, 1) else ("RC4 CryptoAPI" if vmin == 2 and vmaj in (2, 3, 4) else "RC4 variant %d.%d" % (vmaj, vmin)),
                            "version": "%d.%d" % (vmaj, vmin)}
            else:
                filepass = {"scheme": "encryption type %d" % etype}
        elif rtype == 0x0085 and filepass is not None and len(body) >= 4:
            # After FILEPASS every record body is encrypted except BoundSheet8's lbPlyPos ([MS-XLS] 2.2.10): the sheet's state, type and
            # name are ciphertext, so only the count and the stream position are reported, and nothing is derived from the rest.
            if len(sheets) >= 1000:
                if len(sheets) == 1000:
                    ctx.limit_hit("the Excel globals substream lists more than 1000 sheets: the first 1000 are listed")
                    sheets.append(None)
                continue
            sheets.append({"lbPlyPos": struct.unpack_from("<I", body, 0)[0], "name": None, "state": None, "kind": None,
                           "encrypted": "not readable: the record follows FILEPASS, and its state, type and name are encrypted"})
        elif rtype == 0x0085 and len(body) >= 8:
            state, kind = body[4], body[5]
            if bof_version == 0x0500:
                cch, flag, at = body[6], 0, 7
            else:
                cch, flag, at = body[6], body[7], 8
            raw = body[at:at + (cch * 2 if flag & 1 else cch)]
            name = raw.decode("utf-16-le" if flag & 1 else "latin-1", "replace")
            if len(sheets) >= 1000:
                if len(sheets) == 1000:
                    ctx.limit_hit("the Excel globals substream lists more than 1000 sheets: the first 1000 are listed")
                    sheets.append(None)
                continue
            sheets.append({"name": text_of(name, ctx, "names"), "state": {0: "visible", 1: "hidden", 2: "very hidden"}.get(state & 3, "state %d" % state),
                           "kind": {0: "worksheet", 1: "Excel 4.0 macro sheet", 2: "chart", 6: "VBA module"}.get(kind, "type %d" % kind)})
        elif rtype == 0x000A:
            ended = True
    out["biff_version_field"] = bof_version
    out["sheets"] = [x for x in sheets if x is not None]
    if filepass is not None:
        out["sheets_encrypted"] = sum(1 for x in out["sheets"] if x.get("encrypted"))
        if out["sheets_encrypted"]:
            out["sheets_note"] = "the workbook is encrypted (FILEPASS): each sheet's name, visibility and type are ciphertext and not read; no key is tried"
    out["globals_substream_ended"] = ended
    if not ended:
        ctx.problem("the Excel globals substream did not end with an EOF record in the bytes read: the sheet list may be incomplete")
    if filepass is not None:
        out["filepass"] = filepass


def word_findings(cfb, ctx, entry, out):
    try:
        head = cfb.head(entry, 64)
    except (Unreadable, Over) as exc:
        ctx.problem("the WordDocument stream was not read: %s" % (getattr(exc, "reason", None) or exc))
        return
    if len(head) < 12:
        ctx.problem("the WordDocument stream is %d bytes: shorter than the FIB base" % len(head))
        return
    ident, nfib, _u, _lid, _pn, flags = struct.unpack_from("<HHHHHH", head, 0)
    out["fib"] = {"ident": "0x%04X" % ident, "nFib": nfib}
    if ident != 0xA5EC:
        ctx.problem("the WordDocument stream does not begin with the FIB identifier 0xA5EC")
        return
    out["fib"]["fEncrypted"] = bool(flags & 0x0100)
    out["fib"]["fObfuscated"] = bool(flags & 0x8000)
    out["fib"]["fWhichTblStm"] = bool(flags & 0x0200)
    if flags & 0x0100:
        table = cfb.find_stream("1Table" if flags & 0x0200 else "0Table")
        if table is None:
            ctx.problem("the FIB says the document is encrypted and the table stream it names is not in the directory")
        elif flags & 0x8000:
            out["scheme"] = "XOR obfuscation (fObfuscated)"
        else:
            try:
                t = cfb.head(table, 4)
            except (Unreadable, Over):
                t = b""
            if len(t) >= 4:
                vmaj, vmin = struct.unpack_from("<HH", t, 0)
                out["scheme"] = "RC4 (Office 97-2003)" if (vmaj, vmin) == (1, 1) else ("RC4 CryptoAPI" if vmin == 2 and vmaj in (2, 3, 4) else "encryption header version %d.%d" % (vmaj, vmin))
                out["version"] = "%d.%d" % (vmaj, vmin)


def powerpoint_findings(cfb, ctx, out, cu):
    if cu is None:
        return
    try:
        head = cfb.head(cu, 16)
    except (Unreadable, Over):
        return
    if len(head) >= 16:
        token = struct.unpack_from("<I", head, 12)[0]
        out["current_user_header_token"] = "0x%08X" % token
        if token == 0xF3D1C4DF:
            out["scheme"] = "encrypted (the Current User header token for an encrypted presentation)"
        elif token == 0xE391C05F:
            out["scheme"] = "not encrypted (the header token for an unencrypted presentation)"
        else:
            ctx.problem("the Current User header token 0x%08X is neither of the two defined values" % token)


def probe_ole_blob(src, ctx, extractor, label="", source=None):
    """Read a compound file and return the answer's body: directory, applications, VBA projects, encryption. Raises CfbError.

    `label` is how messages name a nested compound file (already shown: a ZIP member's name withheld where it is token-shaped, or
    "rtf-object-N"); `source` is the real name, used only for an extraction's locator. A nested file's directory rows go to the one
    table ole_nested_directories, each row carrying the container's sequence number: a table's name never holds a name out of
    the file, and a thousand nested files are one table, not a thousand."""
    cfb = Cfb(src, ctx, label)
    cfb.read_directory(ctx.cfg["max_entries"])
    cfb.walk(ctx.cfg["max_depth"])
    out = {"cfb": {"major_version": cfb.major, "minor_version": cfb.minor, "sector_bytes": cfb.ss, "mini_stream_cutoff": cfb.cutoff,
                   "fat_sectors": cfb.n_fat, "file_bytes": cfb.size, "entries_read": len(cfb.entries)}}
    root = cfb.entries[0]
    if root.clsid:
        out["root_clsid"] = root.clsid
    if root.modified:
        out["root_modified"] = {"raw": root.modified, "utc": iso_filetime(root.modified), "note": "a FILETIME in UTC; the root storage's time is a claim, not an editing history"}
    if label:
        ctx.nested[0] += 1
        out["directory"] = {"table": "ole_nested_directories", "container": ctx.nested[0]}
        page, extra = ctx.page("ole_nested_directories"), {"container": ctx.nested[0], "container_source": label}
    else:
        page, extra = ctx.page("ole_directory"), None
    try:
        _probe_ole_body(cfb, ctx, extractor, label, source, out, page, extra)
    except Over as exc:
        ctx.limit_hit("%s%s; the reading of this compound file stopped there" % ("%s: " % label if label else "", exc))
    for key, empty in (("orphan_entries", cfb.orphans), ("applications", []), ("encryption_items", []), ("protection_items", [])):
        out.setdefault(key, empty)
    if label and out.get("vba_projects"):
        # Every nested file's VBA projects and modules are rows of two tables (the whole of each is in a file past `limit` rows), and
        # the answer repeats them inline for the first NESTED_INLINE nested files only: two thousand copies of a vbaProject.bin are two
        # tables and a count, not two thousand project lists.
        n = ctx.nested[0]
        projects_page, modules_page = ctx.page("nested_vba_projects"), ctx.page("nested_vba_modules")
        for proj in out["vba_projects"]:
            projects_page.add({"container": n, **{k: v for k, v in proj.items() if k != "modules"}, "modules": len(proj["modules"])})
            for mod in proj["modules"]:
                modules_page.add({"container": n, "storage": proj["storage"], **mod})
        if n > NESTED_INLINE:
            projects = out.pop("vba_projects")
            out["vba_projects_summary"] = {"projects": len(projects), "modules": sum(len(p["modules"]) for p in projects), "tables": ["nested_vba_projects", "nested_vba_modules"],
                                           "note": "past the first %d nested compound files, a file's VBA projects and modules are rows of these tables (column container), not repeated here" % NESTED_INLINE}
    return out, cfb


def _probe_ole_body(cfb, ctx, extractor, label, source, out, page, extra):
    out["entry_counts"] = ole_entry_rows(cfb, ctx, page, extractor, extra)
    if cfb.orphans:
        ctx.problem("%s%d allocated directory entr%s no storage reaches: listed with reachable false" % ("%s: " % label if label else "", cfb.orphans, "y is one" if cfb.orphans == 1 else "ies are ones"))
    out["orphan_entries"] = cfb.orphans
    apps, enc, protection = [], {"items": []}, []
    prefix = "%s: " % label if label else ""
    # The root's entries by name (lower case). A name the Office formats give a stream is read only from a stream: an entry of that
    # name with another type is said, and not read (it is not what the format puts there).
    at_root = {}
    for e in cfb.entries:
        if e.reachable and e.parts is not None and len(e.parts) == 1:
            at_root.setdefault(cfb_key(e.name), []).append(e)

    def root_streams(low):
        found = at_root.get(cfb_key(low), [])
        for e in found:
            if e.kind != 2:
                ctx.problem("%sthe root entry %s is of type %s, not a stream: it is not read as one" % (prefix, cell(shown_path(e.name)), ENTRY_TYPES.get(e.kind, "type %d" % e.kind)))
        streams = [e for e in found if e.kind == 2]
        if len(streams) > 1:
            ctx.problem("%sthe root holds %d streams named %s (directory entries %s): every copy is read, the first under its own key and the others "
                        "under `other_copies`, each with its directory entry's sid, and `ole:` extracts every copy"
                        % (prefix, len(streams), cell(shown_path(streams[0].name)), ", ".join(str(e.sid) for e in streams)))
        return streams

    streams_at_root = {low: root_streams(low) for low in ("worddocument", "workbook", "book", "powerpoint document", "current user", "encryptioninfo", "encryptedpackage")}
    names = {low for low, e in streams_at_root.items() if e}

    def each_copy(streams, read):
        """read(stream) for every copy: the first's result, with the others' (each with its sid) under other_copies."""
        first = None
        for e in streams:
            got = read(e)
            got["sid"] = e.sid
            if first is None:
                first = got
            else:
                first.setdefault("other_copies", []).append(got)
        return first

    if "worddocument" in names:
        apps.append("Word binary document")

        def word(e):
            w = {"container": "Word"}
            word_findings(cfb, ctx, e, w)
            if w.get("scheme"):
                enc["items"].append({"where": "WordDocument FIB", "sid": e.sid, **{k: w[k] for k in ("scheme", "version", "fib") if k in w}})
            return w
        out["word"] = each_copy(streams_at_root["worddocument"], word)
    for key in ("workbook", "book"):
        if key in names:
            apps.append("Excel workbook (BIFF)")

            def excel(e, key=key):
                x = {"stream": cell(key), "container": "Excel"}
                excel_findings(cfb, ctx, e, x)
                if x.get("filepass"):
                    enc["items"].append({"where": "Excel FILEPASS record", "sid": e.sid, **x["filepass"]})
                macro = [s for s in x.get("sheets", []) if s["kind"] == "Excel 4.0 macro sheet"]
                if macro:
                    protection.append({"kind": "macro_sheets", "count": len(macro), "sid": e.sid,
                                       "note": "Excel 4.0 macro sheets are formula-language macros: not VBA, not read by a VBA reader"})
                return x
            out["excel"] = each_copy(streams_at_root[key], excel)
            break
    if "powerpoint document" in names:
        apps.append("PowerPoint binary presentation")

        def powerpoint(e):
            p = {"container": "PowerPoint"}
            powerpoint_findings(cfb, ctx, p, e)
            if "encrypted" in p.get("scheme", "") and not p["scheme"].startswith("not"):
                enc["items"].append({"where": "PowerPoint Current User stream", "sid": e.sid if e is not None else None, "scheme": p["scheme"],
                                     "header_token": p.get("current_user_header_token")})
            return p
        out["powerpoint"] = each_copy(streams_at_root["current user"], powerpoint) if streams_at_root["current user"] else powerpoint(None)
    if "encryptioninfo" in names and "encryptedpackage" in names:
        apps.append("encrypted OOXML package in an OLE wrapper")
        packages = []
        for pkg in streams_at_root["encryptedpackage"]:
            row = {"sid": pkg.sid, "stream_bytes": pkg.size}
            if pkg.size >= 8:
                try:
                    row["declared_size"] = struct.unpack("<Q", cfb.head(pkg, 8))[0]
                except (Unreadable, Over):
                    pass
            packages.append(row)
        for k, e in enumerate(streams_at_root["encryptioninfo"]):
            info = encryption_info(cfb, ctx, e)
            info["sid"] = e.sid
            if packages and "declared_size" in packages[0]:
                info["encrypted_package_declared_size"] = packages[0]["declared_size"]
                info["encrypted_package_stream_bytes"] = packages[0]["stream_bytes"]
            if len(packages) > 1 and k == 0:
                info["encrypted_package_copies"] = packages
            enc["items"].append({"where": "EncryptionInfo and EncryptedPackage streams", **info})
    elif "encryptedpackage" in names or "encryptioninfo" in names:
        ctx.problem("only one of EncryptionInfo and EncryptedPackage is in the root: an encrypted OOXML package needs both")
    ds = [e for e in cfb.entries if e.reachable and e.parts and e.parts[0] == "\x06DataSpaces" and len(e.parts) > 1]
    if ds:
        transforms = sorted({e.parts[-1] for e in ds if len(e.parts) >= 3 and e.parts[1].lower() == "transforminfo" and e.kind == 1})
        if len(transforms) > 20:
            ctx.limit_hit("%sthe \\x06DataSpaces storage names %d transforms: the first 20 are listed" % (prefix, len(transforms)))
        protection.append({"kind": "data_spaces", "entries": len(ds), "transforms": [text_of(t, ctx, "names") for t in transforms[:20]],
                           "note": "the \\x06DataSpaces storage records how the package is transformed (strong encryption, rights management); the names are directory entries, not a reading of the transform"})
    out["applications"] = apps
    out["encryption_items"] = enc["items"]
    out["protection_items"] = protection
    where = (source if source is not None else label) + "/" if (source or label) else ""
    vba = vba_projects(cfb, ctx, extractor, where)
    if vba:
        out["vba_projects"] = vba
        apps.append("VBA project")
    # Streams the caller named.
    if extractor is not None:
        for sel_path in extractor.wanted_args("ole"):
            parts = [p for p in sel_path.split("/") if p != ""]
            copies = [e for e in (cfb.find_all(*parts) if parts else []) if e.kind == 2]
            for entry in copies:
                # two entries of one path (MS-CFB 2.6.4 forbids it; a reader takes one) are each written, the locator naming the sid
                locator = where + "/".join(entry.parts) + (" (directory entry %d)" % entry.sid if len(copies) > 1 else "")
                extractor.write("ole", sel_path, locator, cfb.chunks(entry), "OLE stream, byte for byte")
    # Embedded OLE 1.0 / Package payloads are listed, not opened.


# --- OOXML / ZIP ----------------------------------------------------------------------------------------------------------

ZIP_READ = ["the ZIP central directory: member names, sizes, DOS times, flags",
            "[Content_Types].xml: the content types the package declares",
            "the document, workbook and presentation protection elements, by attribute name (a hash, salt or password attribute is reported by length only)",
            "the VBA project, read as an OLE compound file (see the VBA project and OLE entries): every member the content types or a vbaProject "
            "relationship declare as one, every member named vbaProject.bin, and every other member that begins with the compound file signature and holds a VBA storage",
            "the relationship parts (*.rels), for the relationships of type vbaProject only"]
ZIP_NOT_READ = ["the contents of any other part (document.xml, shared strings, sheets, embedded objects under embeddings/)",
                "relationship targets other than the VBA project's (doc_probe reads *.rels parts)", "compiled VBA (p-code), Excel 4.0 macro sheet formulas and ActiveX binaries",
                "digital-signature parts", "encryption of the whole package: an encrypted OOXML package is an OLE compound file, not a ZIP"]
OLE_READ = ["the compound file header, FAT, mini FAT and directory (every entry, reachable or not), stream sizes and times",
            "the VBA project: the dir stream, each module's stream and the size of its compressed source (source is written only with extract)",
            "the encryption structures: EncryptionInfo, the Word FIB flags and table-stream header, the Excel FILEPASS record, the PowerPoint Current User token",
            "Excel BOUNDSHEET records: sheet names, kinds and visibility"]
OLE_NOT_READ = ["stream contents other than those named above (document text, workbook cells, presentation slides, embedded objects)",
                "property sets (SummaryInformation, DocumentSummaryInformation)", "compiled VBA (p-code) in the _VBA_PROJECT stream and the module streams' cache",
                "OLE 1.0 and Package payloads in \\x01Ole10Native streams: listed, not opened", "whether any password, empty or otherwise, opens the file: no key is tried"]
PROTECTION_ELEMENTS = {"documentProtection", "writeProtection", "workbookProtection", "fileSharing", "modifyVerifier"}
SECRETISH = re.compile(r"hash|salt|password|digest|verifier", re.I)
VBA_CONTENT_TYPE = "application/vnd.ms-office.vbaproject"
VBA_RELS = re.compile(r"(?:^|/)_rels/[^/]*\.rels$", re.I)
LISTING_SHARE = 0.6                 # of max_seconds: the lists of a ZIP (names check, member rows, repeated names); the rest is for its content types, relationships and VBA project
CONTENT_TYPE_ROWS_SHARE = 0.75      # of max_seconds: the rows of [Content_Types].xml, which cost a sanitising of every name, stop here
CONTENT_TYPE_DECLARATIONS_SHARE = 0.85  # of max_seconds: what [Content_Types].xml declares (cheap to read) stops here; the last 15% is for the relationships and the VBA project
DUPLICATES_LISTED = 100             # repeated part names listed in the answer (all are counted)
DUPLICATES_NAMED = 10               # repeated part names named in the problems
SPELLINGS_LISTED = 20               # spellings of one repeated part name listed
NOTABLE_CONTENT_TYPES = ("vbaProject", "macroEnabled", "macrosheet", "activeX", "oleObject", "vbaProjectSignature", "vbaData")


class _Quiet:
    """The context, with a compound file's problems kept to itself: a member read only to see whether it holds a VBA storage."""

    def __init__(self, ctx):
        self._ctx = ctx

    def problem(self, text):
        pass

    def limit_hit(self, text):
        pass

    def __getattr__(self, name):
        return getattr(self._ctx, name)


def cfb_has_vba(blob, ctx):
    """Does this compound file hold a VBA storage (a stream `dir` beside a stream `_VBA_PROJECT`, [MS-OVBA] 2.2)?"""
    try:
        cfb = Cfb(blob, _Quiet(ctx))
        cfb.read_directory(ctx.cfg["max_entries"])
        cfb.walk(ctx.cfg["max_depth"])
    except (CfbError, Over, ValueError, IndexError, struct.error):
        return False
    streams = {(tuple(cfb_key(p) for p in e.parts[:-1]), cfb_key(e.parts[-1])) for e in cfb.entries if e.reachable and e.parts and e.kind == 2}
    return any(name == "DIR" and (parent, "_VBA_PROJECT") in streams for parent, name in streams)


def read_member(archive, info, ctx):
    return b"".join(stream_member(archive, info, ctx.budget))


def zip_unreadable(ctx, members, shown, exc):
    kind = exc.kind
    members[kind] = members.get(kind, 0) + 1
    (ctx.limit_hit if kind in ("over_budget", "not_attempted") else ctx.problem)("%s: %s" % (shown, exc.reason))


def protection_row(local, attrs):
    row = {"element": local, "attributes": {}, "secret_bearing_attributes": []}
    for key, value in attrs.items():
        if SECRETISH.search(key):
            row["secret_bearing_attributes"].append({"name": text_of(key, None, "names"), "length": len(value)})
        else:
            row["attributes"][text_of(key, None, "names")] = text_of(value, None, "names") if len(value) <= 64 else "<%d characters>" % len(value)
    return row


def probe_zip(path, size, ctx, extractor):
    """The ZIP answer. A budget or the clock reached anywhere in it is a limit, and the answer keeps what was read before it."""
    out = {"container": "OOXML or ZIP", "timestamps_note": "ZIP member times are DOS local times with no zone recorded and a resolution of two seconds: they are claims, not UTC."}
    try:
        _probe_zip(path, size, ctx, extractor, out)
    except Over as exc:
        ctx.limit_hit("%s; the reading of the package stopped there" % exc)
    out.setdefault("coverage", {"structures_read": ZIP_READ, "structures_not_read": ZIP_NOT_READ})
    return out


def _probe_zip(path, size, ctx, extractor, out):
    members = {"declared": 0, "listed": 0, "read": 0, "flagged_encrypted": 0, "encrypted": 0, "unsupported": 0, "failed": 0, "over_budget": 0, "not_attempted": 0}
    out["members"] = members
    parts = ctx.page("parts")
    cfg = ctx.cfg
    out["protection_items"] = []
    out["encryption_items"] = []
    with open(path, "rb") as fh:
        try:
            end = zip_directory(fh, size)
        except ZipProblem as exc:
            raise Stop("the archive's directory cannot be read: %s" % exc, out)
        total, cd_size = end["total"], end["cd_size"]
        members["declared"] = total
        if end["others"]:
            ctx.problem("the last 64 KiB of the file hold more than one end of central directory signature (at offsets %s besides the one chosen, at %d): "
                        "a reader that chooses another lists another directory. This tool lists the directory of the chosen one"
                        % (", ".join(str(o) for o in end["others"][:5]), end["eocd_at"]))
        if total > MAX_DIRECTORY_ENTRIES or cd_size > MAX_DIRECTORY_BYTES or cd_size // MIN_ENTRY > MAX_DIRECTORY_ENTRIES:
            ctx.limit_hit("the central directory declares %d members in %d bytes (it can hold up to %d): over the %d-member and %d-byte limits for opening it; "
                          "no member was listed or read" % (total, cd_size, cd_size // MIN_ENTRY, MAX_DIRECTORY_ENTRIES, MAX_DIRECTORY_BYTES))
            members["not_attempted"] = total
            out["coverage"] = {"structures_read": ["the end of central directory record"], "structures_not_read": ZIP_READ + ZIP_NOT_READ}
            return out
        # A name the directory marks UTF-8 (flag bit 11) that is not UTF-8 would stop the standard library's reader for the whole archive:
        # that member's flag is shown to the reader without the bit, so its name is read as CP437, every other member is listed, and it is said.
        # A Unicode Path extra field (0x7075, APPNOTE 4.6.9) names a member a second time: Python 3.12 and later take that name (and stop at
        # one that is not UTF-8, losing the whole archive), 3.11 ignores it. Its tag is hidden from the reader, so that every version lists
        # every member by its central directory name; this tool reads the field itself, shows the second name beside the first, and says so.
        patches, not_utf8, unicode_paths = {}, 0, {}
        fh.seek(end["cd_off"])
        cd = fh.read(min(end["cd_size"], MAX_DIRECTORY_BYTES))
        at = index = 0
        while at + 46 <= len(cd) and cd[at:at + 4] == b"PK\x01\x02":
            flags = struct.unpack_from("<H", cd, at + 8)[0]
            nlen, xlen, clen = struct.unpack_from("<HHH", cd, at + 28)
            raw_name = cd[at + 46:at + 46 + nlen]
            if flags & 0x800:
                try:
                    raw_name.decode("utf-8")
                except UnicodeDecodeError:
                    patches[end["cd_off"] + at + 9] = (flags & ~0x800) >> 8
                    not_utf8 += 1
            x = at + 46 + nlen
            x_end = min(x + xlen, len(cd))
            while x + 4 <= x_end:
                tag, ln = struct.unpack_from("<HH", cd, x)
                if x + 4 + ln > x_end:
                    break
                if tag == 0x7075:
                    data = cd[x + 4:x + 4 + ln]
                    patches[end["cd_off"] + x] = 0
                    patches[end["cd_off"] + x + 1] = 0
                    found = {"version": data[0] if data else None}
                    if len(data) >= 5:
                        found["names_this_name"] = struct.unpack_from("<I", data, 1)[0] == zlib.crc32(raw_name)
                        try:
                            found["name"] = data[5:].decode("utf-8")
                        except UnicodeDecodeError:
                            found["name"] = data[5:].decode("cp437")
                            found["not_utf8"] = True
                    found["central_as_utf8"] = raw_name.decode("utf-8", "replace")
                    unicode_paths.setdefault(index, found)
                x += 4 + ln
            at += 46 + nlen + xlen + clen
            index += 1
        if not_utf8:
            ctx.problem("%d member name%s marked UTF-8 (general purpose flag bit 11) %s not UTF-8: read as CP437, so the name shown is not the one a "
                        "UTF-8 reader shows" % (not_utf8, "" if not_utf8 == 1 else "s", "is" if not_utf8 == 1 else "are"))
        window = Window(fh, end["eocd_at"] + 22, end["eocd_at"] + 20, patches)
        try:
            archive = zipfile.ZipFile(io.BufferedReader(window))
        except Exception as exc:
            raise Stop("the archive will not open (%s: %s)" % (type(exc).__name__, shown_path(str(exc))), out)
        # Part names compare case-insensitively (ECMA-376-2 9.1.1.1.2): every member is kept under its lower-case name, so that two
        # spellings of one part are a duplicate, and every copy of a part this tool reads is read.
        by_name, by_lower, local_mismatch, aliases, renamed = {}, {}, [], {}, []
        with archive:
            infos = archive.infolist()
            # The package is indexed whole before anything is listed (no judge, no clock: a lower-case copy of each name), so that the content
            # types, the relationships and the VBA project are found whatever the listing below manages to list in its time.
            scan = infos[:cfg["max_entries"]]
            # Part names compare without case (ECMA-376-2 9.1.1.1.2): every spelling of a name is that name, so when one spelling is withheld
            # every spelling is (a case variant of a token shows its characters but its case).
            spelled = {}
            for info in scan:
                low = info.filename.lower()
                spelled.setdefault(low, set()).add(info.filename)
                by_name.setdefault(low, info)
                by_lower.setdefault(low, []).append(info)
            # The lists of a package (the check of its names, the member rows, the repeated names) are cosmetic beside what the package says about
            # itself: they have LISTING_SHARE of max_seconds, and the rest is kept for the content types, the relationships and the VBA project,
            # so that a package of thousands of long names cannot use the clock up before its macros are looked for.
            listing_deadline = ctx.deadline - (1 - LISTING_SHARE) * ctx.seconds

            def listing_over(where):
                if time.monotonic() <= listing_deadline:
                    return False
                ctx.limit_hit("time: %s stopped at max_seconds (%d) less the %g s kept for reading the content types, the relationships and the VBA project; "
                              "what was listed is reported, and the counts are lower bounds" % (where, ctx.seconds, (1 - LISTING_SHARE) * ctx.seconds))
                return True

            # Each distinct name goes through the sanitiser once: the check, the row and the list of repeated names all take it from here.
            shown_cache = {}

            def shown_of(name):
                shown = shown_cache.get(name)
                if shown is None:
                    shown = shown_cache[name] = shown_name(name)
                return shown
            # The check reads the clock: a package of thousands of names of 2,000 characters each takes a minute to check. With the clock out the
            # names not yet checked are all treated as withheld (given by their length): more is withheld, never less.
            withheld_names, all_withheld = set(), False
            for low, names in spelled.items():
                if listing_over("the check of the part names"):
                    all_withheld = True
                    break
                if any(shown_of(n) != n for n in names):
                    withheld_names.add(low)

            def zname(name, record=True):
                if all_withheld or (name.lower() in withheld_names and shown_of(name) == name):
                    shown = ("<withheld %d characters: the time for checking part names ran out>" if all_withheld else
                             "<withheld %d characters: a spelling of a part name that is withheld>") % len(name)
                    COUNTS["names"] += 1
                    if record:
                        ctx.names.add(name, shown, "part_name")
                    return shown
                shown = shown_of(name)
                if record and shown != name:
                    ctx.names.add(name, shown, "part_name")
                return shown
            if len(infos) != total:
                ctx.problem("the end record declares %d member%s and the central directory holds %d" % (total, "" if total == 1 else "s", len(infos)))
            for index, info in enumerate(infos):
                if index >= cfg["max_entries"]:
                    members["not_attempted"] = len(infos) - index
                    ctx.limit_hit("%d members are past max_entries (%d): not listed, not read" % (len(infos) - index, cfg["max_entries"]))
                    break
                if listing_over("the member loop"):
                    members["not_attempted"] = len(infos) - index
                    break
                name = info.filename
                shown = zname(name)
                row = {"name": shown, "bytes": info.file_size, "compressed": info.compress_size, "method": info.compress_type,
                       "modified": "%04d-%02d-%02dT%02d:%02d:%02d" % info.date_time}
                if shown != name:
                    row["name_withheld"] = True
                up = unicode_paths.get(index)
                if up is not None:
                    alias = up.get("name")
                    row["unicode_path_field"] = {"name": member_name(alias, ctx) if alias else None, "version": up["version"],
                                                 "crc_names_this_name": up.get("names_this_name"), "utf8": not up.get("not_utf8")}
                    if alias:
                        aliases[name] = alias
                    if up.get("not_utf8") or (up.get("names_this_name") and alias and alias not in (name, up["central_as_utf8"])):
                        renamed.append(shown)
                if info.flag_bits & 0x1:
                    row["encrypted"] = True
                    members["flagged_encrypted"] += 1
                differs = local_header_differs(fh, info, size)
                if differs:
                    row["local_header_differs"] = differs
                    local_mismatch.append((shown, differs))
                parts.add(row)
                members["listed"] += 1       # after the row: a row the clock stopped is not listed, and `matched` is never one more than the file
            if renamed:
                ctx.problem("%d member(s) carry a Unicode Path extra field (0x7075) that names them otherwise or is not UTF-8 (%s): a reader that honours "
                            "the field (Python 3.12 and later, Info-ZIP) lists the second name, or fails on one that is not UTF-8, and one that ignores it "
                            "(Python 3.11) lists the central directory's; this tool lists and reads each member by the central directory's name, shows "
                            "the second as unicode_path_field, and reads a member as the VBA project when either name says it is one"
                            % (len(renamed), "; ".join(renamed[:5]) + ("; and %d more" % (len(renamed) - 5) if len(renamed) > 5 else "")))
            if local_mismatch:
                out["local_headers_that_differ"] = len(local_mismatch)
                ctx.problem("%d member(s) have a local header that disagrees with the central directory (%s): a reader that walks the local headers (a "
                            "streaming reader) sees other names, methods or sizes; this tool lists and reads by the central directory, and each row says "
                            "local_header_differs" % (len(local_mismatch), "; ".join("%s: %s" % (n, ", ".join(d)) for n, d in local_mismatch[:5])
                                                      + ("; and %d more" % (len(local_mismatch) - 5) if len(local_mismatch) > 5 else "")))
            # The repeated names: counted whole (no judge), listed to DUPLICATES_LISTED and named in the problems to DUPLICATES_NAMED, each by the
            # name the listing already holds, under the listing's clock. The problems have room for a hundred: a package of a thousand repeated
            # names does not take it all from what is said after.
            repeated = [copies for copies in by_lower.values() if len(copies) > 1]
            duplicates = []
            for copies in repeated[:DUPLICATES_LISTED]:
                if listing_over("the list of repeated part names"):
                    break
                spellings = sorted({i.filename for i in copies})
                first = zname(copies[0].filename, False)
                duplicates.append({"name": first, "copies": len(copies), "spellings": [zname(x, False) for x in spellings[:SPELLINGS_LISTED]],
                                   **({"spellings_not_listed": len(spellings) - SPELLINGS_LISTED} if len(spellings) > SPELLINGS_LISTED else {})})
                if len(duplicates) <= DUPLICATES_NAMED:
                    ctx.problem("the part name %s appears %d times%s: part names compare case-insensitively (ECMA-376-2 9.1.1.1.2), so an OPC package has one "
                                "part of each name, and readers resolve a repeated one differently; every copy of a part this tool reads is read"
                                % (first, len(copies), " (spelled %d ways)" % len(spellings) if len(spellings) > 1 else ""))
            if duplicates:
                out["duplicate_part_names"] = duplicates
            if len(repeated) > DUPLICATES_NAMED:
                out["duplicate_part_names_total"] = len(repeated)
                ctx.problem("%d part names appear more than once in all: %d are named in the problems and %d are listed in `duplicate_part_names` (at most "
                            "%d are listed, and the list stops at the clock); the rest are counted, not listed (every copy of a part this tool reads is read)"
                            % (len(repeated), min(DUPLICATES_NAMED, len(duplicates)), len(duplicates), DUPLICATES_LISTED))
            if members["flagged_encrypted"]:
                ctx.problem("%d member%s marked encrypted in the directory: its content is not examined" % (members["flagged_encrypted"], "" if members["flagged_encrypted"] == 1 else "s"))
                out["encryption_items"].append({"where": "ZIP central directory", "scheme": "member-level ZIP encryption (general purpose flag bit 0 or AES method 99)", "members": members["flagged_encrypted"]})
            names = set(by_name)
            out["kind"] = ("Word" if "word/document.xml" in names else "Excel" if any(n.startswith("xl/") for n in names)
                           else "PowerPoint" if any(n.startswith("ppt/") for n in names) else "a ZIP with no word/, xl/ or ppt/ part names")
            out["opc_markers"] = {"[Content_Types].xml": "[content_types].xml" in names, "_rels/.rels": "_rels/.rels" in names}
            # [Content_Types].xml
            ct = by_name.get("[content_types].xml")
            vba_declared = {}                # lower-case part name -> how the package declares it its VBA project
            vba_extensions = set()
            overridden = set()               # every part an Override names: its own content type wins over the Default of its extension
            if ct is not None:
                overrides, defaults, notable = ctx.page("content_types"), 0, []
                # The rows of the table cost a sanitising of every name; what the table declares (the parts that have a content type of their
                # own, the VBA project) costs nothing. So the rows have until CONTENT_TYPE_ROWS_SHARE of max_seconds and the declarations until
                # CONTENT_TYPE_DECLARATIONS_SHARE, each stopped with a limit that says so, and the rest is kept for the relationships and the VBA
                # project whatever the table holds: a table of 60,000 long names cannot use the clock up before they are looked for.
                rows_deadline = ctx.deadline - (1 - CONTENT_TYPE_ROWS_SHARE) * ctx.seconds
                declarations_deadline = ctx.deadline - (1 - CONTENT_TYPE_DECLARATIONS_SHARE) * ctx.seconds
                seen, rows_stopped = 0, False

                def element(local, _ns, attrs):
                    nonlocal defaults, seen, rows_stopped
                    if local not in ("Default", "Override"):
                        return
                    seen += 1
                    kind = attrs.get("ContentType", "")
                    if local == "Default":
                        defaults += 1
                    else:
                        overridden.add(attrs.get("PartName", "").lstrip("/").lower())
                    if kind.strip().lower() == VBA_CONTENT_TYPE:
                        if local == "Default":
                            vba_extensions.add(attrs.get("Extension", "").lower())
                        else:
                            vba_declared.setdefault(attrs.get("PartName", "").lstrip("/").lower(), set()).add("content_type")
                    # the clock: every 16 elements for the rows (a row of a long name costs a millisecond), every 256 for the declarations
                    if not rows_stopped and not seen & 15 and time.monotonic() > rows_deadline:
                        rows_stopped = True
                        ctx.limit_hit("time: the rows of [Content_Types].xml stopped at max_seconds (%d) less the %g s kept for the relationships and the VBA project; "
                                      "the rows listed are the ones before that point, and what the table declares (a part's own content type, the VBA project) is "
                                      "still read" % (ctx.seconds, (1 - CONTENT_TYPE_ROWS_SHARE) * ctx.seconds))
                    if not seen & 255 and time.monotonic() > declarations_deadline:
                        raise Over("time: [Content_Types].xml stopped at max_seconds (%d) less the %g s kept for the relationships and the VBA project; what it "
                                   "declares after that point is not read (a VBA project named vbaProject.bin, one a relationship names and one that begins with the "
                                   "compound file signature are still looked for)" % (ctx.seconds, (1 - CONTENT_TYPE_DECLARATIONS_SHARE) * ctx.seconds))
                    if rows_stopped:
                        return
                    if local == "Default":
                        row = {"extension": text_of(attrs.get("Extension", ""), None, "names"), "content_type": text_of(kind, None, "names")}
                    else:
                        part = attrs.get("PartName", "")
                        row = {"part": zname(part[1:], False) if part.startswith("/") and part[1:].lower() in withheld_names else shown_name(part),
                               "content_type": text_of(kind, None, "names")}
                    overrides.add(row)
                    if any(k in kind for k in NOTABLE_CONTENT_TYPES) and len(notable) < 50 and row not in notable:
                        notable.append(row)

                try:
                    xml_elements(stream_member(archive, ct, ctx.budget), element)
                    members["read"] += 1
                    out["content_types"] = {"read": True, "notable": notable, "table": "content_types", **({"rows_complete": False} if rows_stopped else {})}
                except Over as exc:
                    # the clock ended the table: what was read stays, the table is not whole, and the relationships and the VBA project are still looked for
                    ctx.limit_hit(str(exc))
                    out["content_types"] = {"read": False, "notable": notable, "table": "content_types", "rows_complete": False}
                except Unreadable as exc:
                    zip_unreadable(ctx, members, "[Content_Types].xml", exc)
                except DoctypeRefused:
                    ctx.problem("[Content_Types].xml contains a DOCTYPE, which is refused: it was not parsed")
                except xml.parsers.expat.ExpatError as exc:
                    ctx.problem("[Content_Types].xml is not well-formed XML (%s): the entries before the error are listed" % xml.parsers.expat.ErrorString(exc.code))
                except (LookupError, ValueError) as exc:
                    ctx.problem("[Content_Types].xml declares an encoding the XML reader cannot decode (%s): it was not parsed" % type(exc).__name__)
            else:
                ctx.problem("no [Content_Types].xml member: an OPC package needs one")
            # protection elements
            for part, info in [(part, info) for part in ("word/settings.xml", "xl/workbook.xml", "ppt/presentation.xml") for info in by_lower.get(part, [])]:
                if ctx.expired("the protection elements"):
                    break
                found = []

                def element2(local, _ns, attrs, found=found):
                    if local in PROTECTION_ELEMENTS and len(found) < 20:
                        found.append(protection_row(local, attrs))

                try:
                    xml_elements(stream_member(archive, info, ctx.budget), element2)
                    members["read"] += 1
                except Unreadable as exc:
                    zip_unreadable(ctx, members, part, exc)
                except DoctypeRefused:
                    ctx.problem("%s contains a DOCTYPE, which is refused: it was not parsed" % part)
                except xml.parsers.expat.ExpatError as exc:
                    ctx.problem("%s is not well-formed XML (%s): the elements before the error are listed" % (part, xml.parsers.expat.ErrorString(exc.code)))
                except (LookupError, ValueError) as exc:
                    ctx.problem("%s declares an encoding the XML reader cannot decode (%s): it was not parsed" % (part, type(exc).__name__))
                for row in found:
                    out["protection_items"].append({"where": part, **row, "note": "an editing restriction, not encryption: the content is readable without a password"})
            # The VBA project: every member the package declares as one (an Override or Default content type, a vbaProject relationship
            # in any relationship part), every member named vbaProject.bin (by either name a Unicode Path field gives it), and every other
            # member that begins with the compound file signature and holds a VBA storage. A declared one that is absent or not read is
            # a problem: the answer is partial.
            listed = scan                    # every member the package index holds, listed or not: the listing's time does not decide what is looked for
            for rels in [info for info in listed if VBA_RELS.search(info.filename)]:
                if ctx.expired("the relationship parts"):
                    break
                base = rels.filename[:VBA_RELS.search(rels.filename).start()]

                def rel(local, _ns, attrs, base=base):
                    kind = attrs.get("Type", "")
                    if local == "Relationship" and kind.rstrip("/").rpartition("/")[2].lower() == "vbaproject" and attrs.get("TargetMode", "").lower() != "external":
                        target = urllib.parse.unquote(attrs.get("Target", ""))
                        target = target.lstrip("/") if target.startswith("/") else posixpath.normpath(posixpath.join(base, target))
                        vba_declared.setdefault(target.lower(), set()).add("relationship")
                try:
                    xml_elements(stream_member(archive, rels, ctx.budget), rel)
                    members["read"] += 1
                except Unreadable as exc:
                    zip_unreadable(ctx, members, zname(rels.filename, False), exc)
                except DoctypeRefused:
                    ctx.problem("%s contains a DOCTYPE, which is refused: it was not parsed" % zname(rels.filename, False))
                except xml.parsers.expat.ExpatError as exc:
                    ctx.problem("%s is not well-formed XML (%s): the relationships before the error are read" % (zname(rels.filename, False), xml.parsers.expat.ErrorString(exc.code)))
                except (LookupError, ValueError) as exc:
                    ctx.problem("%s declares an encoding the XML reader cannot decode (%s): it was not parsed" % (zname(rels.filename, False), type(exc).__name__))
            vba_parts, chosen = [], set()
            for info in listed:
                names = {info.filename.lower()} | ({aliases[info.filename].lower()} if info.filename in aliases else set())
                why = set()
                for n in names:
                    why |= vba_declared.get(n, set())
                    if n.endswith("vbaproject.bin"):
                        why.add("name")
                    if n.rpartition(".")[2] in vba_extensions and "." in n and n not in overridden:
                        why.add("content_type")
                if why:
                    vba_parts.append((info, sorted(why)))
                    chosen |= names
            missing = sorted(n for n in vba_declared if n not in chosen)
            for n in missing[:DUPLICATES_NAMED]:
                ctx.problem("the package declares %s its VBA project (%s), and no member of that name is listed: the project is not read"
                            % (shown_name(n), " and ".join(sorted(vba_declared[n]))))
            if len(missing) > DUPLICATES_NAMED:
                ctx.problem("the package declares %d more names as its VBA project and no member of those names is listed: those projects are not read"
                            % (len(missing) - DUPLICATES_NAMED))
            vba_ids = {id(i) for i, _ in vba_parts}
            for info in listed:
                if id(info) in vba_ids or info.flag_bits & 0x1 or info.compress_type not in METHODS_READ:
                    continue
                if ctx.expired("the compound file signature check"):
                    break
                try:
                    with archive.open(info) as fh_member:
                        head = fh_member.read(8)
                except Exception:
                    continue
                if head == CFB_MAGIC:
                    vba_parts.append((info, ["cfb_signature"]))
            projects = []
            for k, (info, why) in enumerate(vba_parts):
                if ctx.expired("the VBA project parts"):
                    members["not_attempted"] += len(vba_parts) - k
                    if any(w != "cfb_signature" for _, ws in vba_parts[k:] for w in ws):
                        ctx.problem("the clock ended before every member the package declares as its VBA project was read")
                    break
                shown = zname(info.filename)
                if why == ["cfb_signature"]:
                    try:
                        blob = read_member(archive, info, ctx)
                    except Unreadable as exc:
                        # a member nothing declares, with the compound file signature, that a bound keeps unread: said, and the answer partial
                        zip_unreadable(ctx, members, shown, exc)
                        ctx.problem("%s begins with the compound file signature and was not read, so whether it holds a VBA project is not known" % shown)
                        continue
                    if not cfb_has_vba(blob, ctx):
                        continue
                    members["read"] += 1
                else:
                    try:
                        blob = read_member(archive, info, ctx)
                    except Unreadable as exc:
                        zip_unreadable(ctx, members, shown, exc)
                        ctx.problem("%s is declared as the VBA project (%s) and was not read" % (shown, ", ".join(why)))
                        continue
                    members["read"] += 1
                try:
                    body, _cfb = probe_ole_blob(blob, ctx, extractor, label=shown, source=info.filename)
                except CfbError as exc:
                    ctx.problem("%s is not read as a compound file: %s" % (shown, exc))
                    continue
                part = {"part": shown, "selected_by": why, "vba_projects": body.get("vba_projects", []), "orphan_entries": body["orphan_entries"], "cfb": body["cfb"],
                        "directory": body.get("directory")}
                if why == ["cfb_signature"]:
                    part["note"] = "a compound file holding a VBA storage that no content type, relationship or vbaProject.bin name declares as the package's VBA project"
                if "vba_projects_summary" in body:
                    part["vba_projects_summary"] = body["vba_projects_summary"]
                projects.append(part)
            if projects:
                out["vbaproject_parts"] = projects
            if extractor is not None:
                for want in extractor.wanted_args("zip"):
                    for info in by_lower.get(want.lower(), []):
                        if ctx.expired("the extraction of the ZIP members"):
                            break
                        extractor.write("zip", want, info.filename, stream_member(archive, info, ctx.budget), "ZIP member, byte for byte")
    out["coverage"] = {"structures_read": ZIP_READ, "structures_not_read": ZIP_NOT_READ}


# --- PDF (ISO 32000) -------------------------------------------------------------------------------------------------------

PDF_READ = ["the header line, the cross-reference chain (tables, streams, hybrid files; every revision) and the trailers",
            "every indexed object's header and dictionary (not stream contents), and the objects held in object streams",
            "stream filters, named; stream lengths declared and measured",
            "the encryption dictionary named by the current trailer: handler, version, revision, crypt filters, permission bits",
            "actions (OpenAction, additional-actions, link and widget annotations, form fields, outlines, the JavaScript name tree) and the way each is reached",
            "embedded files named by file specifications, and the page tree's counts"]
PDF_NOT_READ = ["page content streams, fonts, images and metadata", "the content of JavaScript, embedded files and object streams unless extract asks for it",
                "the plaintext of an encrypted file: no key is tried (not even the empty password), so objects inside encrypted object streams are not parsed, and a string of a plain object (an action's target) is ciphertext, marked so and given by length",
                "filters other than FlateDecode, ASCIIHexDecode, ASCII85Decode and RunLengthDecode (LZW, JBIG2, JPX, DCT and CCITT streams are listed with their filter, not decoded)",
                "whether an action would run: that depends on the reader, its version and its settings"]
WS_BYTES = b"\x00\t\n\x0c\r "
REGULAR_END = re.compile(rb"[\x00\t\n\x0c\r ()<>\[\]{}/%]")
NUM_RE = re.compile(rb"[+-]?(?:[0-9]+\.?[0-9]*|\.[0-9]+)")
REF_RE = re.compile(rb"([0-9]{1,10})[\x00\t\n\x0c\r ]+([0-9]{1,5})[\x00\t\n\x0c\r ]+R(?![^\x00\t\n\x0c\r ()<>\[\]{}/%])")
OBJ_RE = re.compile(rb"[\x00\t\n\x0c\r ]*([0-9]{1,10})[\x00\t\n\x0c\r ]+([0-9]{1,5})[\x00\t\n\x0c\r ]+obj(?![A-Za-z0-9])")
SCAN_OBJ = re.compile(rb"(?<![0-9])([0-9]{1,10})[ \t\r\n\x00\x0c]+([0-9]{1,5})[ \t\r\n\x00\x0c]+obj(?![A-Za-z0-9])")
XREF_ENTRY = re.compile(rb"[\x00\t\n\x0c\r ]*([0-9]{1,10})[\x00\t\n\x0c\r ]+([0-9]{1,5})[\x00\t\n\x0c\r ]+([nf])")
STRING_SPECIAL = re.compile(rb"[()\\]")
HEX_NAME = re.compile(rb"#([0-9A-Fa-f]{2})")
ENDSTREAM_AFTER = re.compile(rb"[\x00\t\n\x0c\r ]*endstream")
DIRECT_LENGTH = re.compile(rb"/Length[\x00\t\n\x0c\r ]+([0-9]+)(?![0-9]|[\x00\t\n\x0c\r ]+[0-9]+[\x00\t\n\x0c\r ]+R)")
MAX_OBJECT_WINDOW = 32 << 20
MAX_ITEMS = 250_000                 # values one parse may read (a PDF object and all it holds): past it, a bound of the parser, named
# What the PDF reader keeps of what it parsed, by an estimate of the memory it takes: ITEM_BYTES for each value (a name, a number, an empty
# array costs 50 to 70 bytes of heap; the input costs 2 or 3), plus the bytes of every string and name as held (a name's characters at one,
# two or four bytes each, by its widest character, and a dictionary key twice). A parsed value costs 20 to 30
# times its input, so the scan budgets, which count input, do not bound it: these do, and none of them loses anything (an object that
# is not kept is read again when it is needed, under the same clock and budgets).
ITEM_BYTES = 80


def str_bytes(text):
    """The bytes a Python string's characters take: one, two or four each, by its widest character (PEP 393). A name of the file is held
    as a string, and one character past U+FFFF makes every character of it take four bytes."""
    if not text:
        return 0
    widest = max(text)
    return len(text) * (4 if widest > "\uffff" else 2 if widest > "\xff" else 1)
PARSE_BYTES = 64 << 20              # what one parse (an object and all it holds) may take in memory, estimated so: past it, a bound, named
CACHE_BYTES = 96 << 20              # the parsed objects the reader keeps for the next lookup, oldest out first
CACHE_OBJECT_BYTES = 8 << 20        # an object larger than this is not kept in that cache at all
CACHE_OBJECTS = 4000
KEEP_BYTES = 32 << 20               # the objects the census keeps for the structure trace (catalog, actions, object streams, file specs)
KEEP_OBJECT_BYTES = 1 << 20
OBJSTM_CACHE_BYTES = 48 << 20       # decoded object streams kept, with their header pairs
FAILED_AT_MAX = 100_000             # offsets remembered as unreadable (never parsed twice)
ACTION_SUBTYPES = {"JavaScript", "Launch", "URI", "SubmitForm", "GoToR", "GoToE", "ImportData", "Named", "Rendition", "Movie", "Sound", "GoTo", "Thread",
                   "ResetForm", "Hide", "SetOCGState", "Trans", "GoTo3DView", "RichMediaExecute", "SetState", "NoOp"}
SUPPORTED_FILTERS = {"FlateDecode": "FlateDecode", "Fl": "FlateDecode", "ASCIIHexDecode": "ASCIIHexDecode", "AHx": "ASCIIHexDecode",
                     "ASCII85Decode": "ASCII85Decode", "A85": "ASCII85Decode", "RunLengthDecode": "RunLengthDecode", "RL": "RunLengthDecode"}
PREDICTOR_MAX = 4 << 20
MAX_FILTERS = 8
MAX_REVISIONS = 1000
MAX_HEADER_PAIRS = 1_000_000
PDF_NESTING = 150                   # PDF objects are parsed recursively: nesting past this is an error whatever max_depth says
NON_HEX = bytes(sorted(set(range(256)) - set(b"0123456789abcdefABCDEF")))
A85_WS = b" \t\n\r\x0b\x00\x0c"
A85_ZRUN = re.compile(rb"(z+)")
A85_LEAD = re.compile(rb"[ \t\n\r\x0b\x00\x0c]*(?:<~)?")


class PdfError(Exception):
    pass


class NeedMore(PdfError):
    pass


class ParseBound(PdfError):
    """An object passes a bound of the parser (its values, its window, its nesting): a limit of this tool, not a fault of the file."""


class ObjStmUnreadable(PdfError):
    """An object that lives in an object stream that cannot be read: said once, for the stream, and counted (as not read at a limit
    when the stream was refused at a budget or a bound, else as unreadable)."""

    def __init__(self, message, at_limit=False):
        PdfError.__init__(self, message)
        self.at_limit = at_limit


class Name(str):
    __slots__ = ()


class LongName(Name):
    """A name longer than SHOWN_TARGET, which the lexer keeps as its length and offset: a marker the tool wrote, not text of the file."""
    __slots__ = ()


class PStr(bytes):
    __slots__ = ()


class Ref:
    __slots__ = ("num", "gen")

    def __init__(self, num, gen):
        self.num, self.gen = num, gen


class _Null:
    def __bool__(self):
        return False


NULL = _Null()


def unescape_name(raw):
    return HEX_NAME.sub(lambda m: bytes([int(m.group(1), 16)]), raw).decode("utf-8", "surrogateescape")


try:
    SKIP_RE = re.compile(rb"(?:[\x00\t\n\x0c\r ]+|%[^\r\n]*)*+")    # possessive (Python 3.11 and later): no backtracking record per repetition
except re.error:                    # an older Python has no possessive quantifier: main() refuses the call by name, before reading anything
    SKIP_RE = None
MIN_PYTHON = (3, 11)
OBJECT_SCAN = 64 << 20              # bytes one object may take to scan, over every window it is read in
SCAN_FACTOR = 8                     # bytes all PDF parses of one call may scan: this many times the file, plus SCAN_FLOOR
SCAN_FLOOR = 64 << 20


class ScanSpent(Over):
    """The bytes all parses of one call may scan are spent: a limit of the call, not of one object."""


class Meter:
    """The budget of one top-level parse, over every window it is tried in: the call's clock, the bytes this object may still scan,
    and the bytes every parse of the call may still scan together. The lexer charges each piece of input it walks over before it
    walks on, so no loop of the lexer (a string, a hex string, a name, a number, a comment, white space, an array, a dictionary)
    and no window it is retried in outlives max_seconds or the budgets: each ends as a named limit."""

    __slots__ = ("pdf", "left", "calls", "cap", "pool")

    def __init__(self, pdf, cap=OBJECT_SCAN, pool=None):
        self.pdf, self.left, self.calls, self.cap, self.pool = pdf, cap, 0, cap, pool

    def charge(self, n):
        self.left -= n
        pdf = self.pdf
        if self.pool is not None:
            self.pool.left -= n
            if self.left < 0:
                raise ParseBound("%s of more than %d bytes" % (self.pool.what, self.cap))
            if self.pool.left < 0:
                raise ScanSpent(self.pool.spent)
        else:
            pdf.scan_left -= n
            if self.left < 0:
                raise ParseBound("an object that takes more than %d bytes of scanning over all the windows it is read in" % OBJECT_SCAN)
            if pdf.scan_left < 0:
                raise ScanSpent("the PDF parser scanned %d bytes, its budget for one call (%d times the file's size plus %d): the objects not read after that "
                                "are counted in census.objects_not_read_at_a_limit" % (pdf.scan_total, SCAN_FACTOR, SCAN_FLOOR))
        self.calls += 1
        if (n >= 4096 or not self.calls & 63) and time.monotonic() > pdf.ctx.deadline:
            raise TimeUp("time: a PDF object was being parsed when max_seconds (%d) was reached; what was read is reported, and the counts are lower bounds" % pdf.ctx.seconds)


class ScanPool:
    """A share of scanning set apart from the call's budget for one search (the scan for trailers in a file whose cross-reference chain
    cannot be used): spending it ends that search, named, and leaves the call's budget to the census and the trace."""

    __slots__ = ("left", "what", "spent")

    def __init__(self, left, what, spent):
        self.left, self.what, self.spent = left, what, spent


class Lexer:
    """PDF syntax over buf[pos:end] (a memory map of the file or a decoded object stream, read in place: a window is a pair of offsets,
    never a copy). `final` says that `end` is the end of the data: running off it is then an error, and otherwise a request for a
    longer window (NeedMore).

    One parse (a top-level object and everything inside it) reads at most `max_items` values, and every piece of input it walks is
    charged to its meter (the clock and the scan budgets), in pieces of at most 1 MiB. A string or a hex string longer than
    max_stream_bytes, and a name longer than SHOWN_TARGET, are bounds of the parser, named; no message of the lexer quotes a byte of
    the input (a token is described by its length and its offset)."""

    def __init__(self, buf, pos, end, final, max_depth, meter, max_string, max_items=MAX_ITEMS):
        self.buf, self.pos, self.end, self.final, self.max_depth = buf, pos, end, final, max_depth
        self.meter, self.max_string, self.max_items, self.items, self.held = meter, max_string, max_items, 0, 0

    def cost(self):
        """What the values this parse read take in memory, estimated: ITEM_BYTES each, and the bytes of their strings and names."""
        return self.items * ITEM_BYTES + self.held

    def count(self):
        self.items += 1
        if self.items > self.max_items:
            raise ParseBound("an object of more than %d values in one parse" % self.max_items)
        if not self.items & 255:
            self.meter.charge(0)
            if self.cost() > PARSE_BYTES:
                raise ParseBound("an object whose parsed values take more than %d bytes of memory (estimated) in one parse" % PARSE_BYTES)

    def eof(self):
        if self.final:
            raise PdfError("unexpected end of the data")
        raise NeedMore()

    def skip(self):
        # White space and comments in one match, possessive: a group repeated over a run without it keeps a backtracking record for
        # every repetition (a megabyte of comments took gigabytes). One match walks at most the window (32 MiB, well under a second)
        # and is charged when it ends.
        m = SKIP_RE.match(self.buf, self.pos, self.end)
        if m.end() > self.pos:
            self.meter.charge(m.end() - self.pos)
            self.pos = m.end()

    def token_end(self, start):
        m = REGULAR_END.search(self.buf, start, self.end)
        end = m.start() if m else self.end
        self.meter.charge(end - start)
        if m:
            return end
        if not self.final:
            raise NeedMore()
        return end

    def parse(self, depth=0):
        if depth > self.max_depth:
            raise PdfError("objects nest deeper than max_depth (%d)" % self.max_depth)
        self.count()
        self.skip()
        buf = self.buf
        if self.pos >= self.end:
            self.eof()
        c = buf[self.pos]
        if c == 0x2F:
            end = self.token_end(self.pos + 1)
            length = end - self.pos - 1
            if length > SHOWN_TARGET:
                # A name that long is no name a reader defines (ISO 32000-1 Annex C gives 127 bytes as an implementation limit): it is
                # kept as its length and offset, so that no withholding or comparison ever walks it.
                name = LongName("<a name of %d bytes at offset %d>" % (length, self.pos))
            else:
                name = Name(unescape_name(buf[self.pos + 1:end]))
            self.held += str_bytes(name)
            self.pos = end
            return name
        if c == 0x3C:
            if self.end - self.pos < 2:
                self.eof()
            if buf[self.pos + 1] == 0x3C:
                return self.dictionary(depth)
            return self.hex_string()
        if c == 0x5B:
            return self.array(depth)
        if c == 0x28:
            return self.literal()
        if c in b"+-.0123456789":
            if not self.final and self.end - self.pos < 64:
                raise NeedMore()
            m = REF_RE.match(buf, self.pos, self.end)
            if m:
                self.pos = m.end()
                return Ref(int(m.group(1)), int(m.group(2)))
            m = NUM_RE.match(buf, self.pos, self.end)
            if not m:
                raise PdfError("a malformed number at offset %d" % self.pos)
            self.meter.charge(m.end() - m.start())
            if m.end() - m.start() > 64:
                raise PdfError("a number of %d characters at offset %d" % (m.end() - m.start(), m.start()))
            self.pos = m.end()
            text = m.group()
            if b"." in text:
                try:
                    return float(text)
                except ValueError:
                    raise PdfError("a malformed number at offset %d" % m.start())
            return int(text)
        start = self.pos
        end = self.token_end(start)
        if end - start in (4, 5):
            word = bytes(buf[start:end])
            if word in (b"true", b"false", b"null"):
                self.pos = end
                return {b"true": True, b"false": False, b"null": NULL}[word]
        raise PdfError("an unexpected token of %d bytes at offset %d" % (end - start, start))

    def dictionary(self, depth):
        self.pos += 2
        out = {}
        while True:
            self.skip()
            if self.pos + 1 >= self.end:
                self.eof()
            if self.buf[self.pos] == 0x3E and self.buf[self.pos + 1] == 0x3E:
                self.pos += 2
                return out
            at = self.pos
            key = self.parse(depth + 1)
            if not isinstance(key, Name):
                raise PdfError("a dictionary key that is not a name, at offset %d" % at)
            out[str(key)] = self.parse(depth + 1)
            self.held += str_bytes(key)      # the key is held a second time, as the plain string the dictionary is keyed by
            if len(out) > MAX_ITEMS:
                raise PdfError("a dictionary of more than %d entries" % MAX_ITEMS)

    def array(self, depth):
        self.pos += 1
        out = []
        while True:
            self.skip()
            if self.pos >= self.end:
                self.eof()
            if self.buf[self.pos] == 0x5D:
                self.pos += 1
                return out
            out.append(self.parse(depth + 1))
            if len(out) > MAX_ITEMS:
                raise PdfError("an array of more than %d items" % MAX_ITEMS)

    def hex_string(self):
        """<...>: the digits are taken a piece at a time (white space and any other byte dropped by translate, never a regular
        expression over the whole window), each piece charged; more than max_stream_bytes decoded is a bound, named."""
        start = self.pos + 1
        close = self.buf.find(b">", start, self.end)
        if close < 0:
            self.meter.charge(self.end - start)
            self.pos = self.end
            self.eof()
        digits = bytearray()
        for p in range(start, close, 1 << 20):
            piece = self.buf[p:min(close, p + (1 << 20))]
            self.meter.charge(len(piece))
            digits += piece.translate(None, NON_HEX)
            if len(digits) > 2 * self.max_string:
                raise ParseBound("a hex string that decodes to more than max_stream_bytes (%d), at offset %d" % (self.max_string, start - 1))
        if len(digits) % 2:
            digits.append(0x30)
        self.pos = close + 1
        self.held += len(digits) // 2
        return PStr(bytes.fromhex(digits.decode("ascii")))

    def literal(self):
        """(...): balanced parentheses and escapes (ISO 32000-1 7.3.4.2). The input is walked a special character at a time and charged
        every 1024 of them and every 1 MiB; more than max_stream_bytes of string is a bound, named."""
        buf, end, pos, depth, out = self.buf, self.end, self.pos + 1, 1, bytearray()
        mark, steps, opened = pos, 0, self.pos
        while True:
            steps += 1
            if not steps & 1023 or pos - mark >= 1 << 20:
                self.meter.charge(pos - mark)
                mark = pos
                if len(out) > self.max_string:
                    raise ParseBound("a string longer than max_stream_bytes (%d), at offset %d" % (self.max_string, opened))
            m = STRING_SPECIAL.search(buf, pos, end)
            if not m:
                self.meter.charge(end - mark)
                self.pos = end
                self.eof()
                raise PdfError("an unterminated string")
            s = m.start()
            if s - pos > 1 << 20:
                self.meter.charge(s - mark)
                mark = s
            out += buf[pos:s]
            c, pos = buf[s], s + 1
            if c == 0x28:
                depth += 1
                out.append(c)
            elif c == 0x29:
                depth -= 1
                if depth == 0:
                    self.meter.charge(pos - mark)
                    if len(out) > self.max_string:
                        raise ParseBound("a string longer than max_stream_bytes (%d), at offset %d" % (self.max_string, opened))
                    self.pos = pos
                    self.held += len(out)
                    return PStr(bytes(out))
                out.append(c)
            else:
                if pos >= end:
                    self.meter.charge(end - mark)
                    self.pos = end
                    self.eof()
                e = buf[pos]
                pos += 1
                if e in b"nrtbf":
                    out.append({0x6E: 10, 0x72: 13, 0x74: 9, 0x62: 8, 0x66: 12}[e])
                elif 0x30 <= e <= 0x37:
                    value, k = e - 0x30, 1
                    while k < 3 and pos < end and 0x30 <= buf[pos] <= 0x37:
                        value = value * 8 + buf[pos] - 0x30
                        pos += 1
                        k += 1
                    out.append(value & 0xFF)
                elif e == 0x0D:
                    if pos < end and buf[pos] == 0x0A:
                        pos += 1
                elif e == 0x0A:
                    pass
                else:
                    out.append(e)


def text_string(raw):
    """A PDF text string as text: UTF-16 with a byte-order mark, UTF-8 with a mark, or the single-byte PDFDocEncoding read as Latin-1."""
    if raw[:2] == b"\xfe\xff":
        return raw[2:].decode("utf-16-be", "replace")
    if raw[:2] == b"\xff\xfe":
        return raw[2:].decode("utf-16-le", "replace")
    if raw[:3] == b"\xef\xbb\xbf":
        return raw[3:].decode("utf-8", "replace")
    return raw.decode("latin-1")


def png_unpredict(data, columns, colors, bpc, ctx=None):
    rowlen = (columns * colors * bpc + 7) // 8
    bpp = max(1, (colors * bpc + 7) // 8)
    if rowlen < 1 or len(data) < rowlen + 1:
        return b""
    prev = bytearray(rowlen)
    out = bytearray()
    for n, start in enumerate(range(0, len(data) - rowlen, rowlen + 1)):
        if ctx is not None and not n & 1023 and time.monotonic() > ctx.deadline:
            raise TimeUp("time: a predictor was being undone when max_seconds (%d) was reached; what was read is reported, and the counts are lower bounds" % ctx.seconds)
        ft = data[start]
        row = bytearray(data[start + 1:start + 1 + rowlen])
        if ft == 1:
            for i in range(bpp, rowlen):
                row[i] = (row[i] + row[i - bpp]) & 0xFF
        elif ft == 2:
            for i in range(rowlen):
                row[i] = (row[i] + prev[i]) & 0xFF
        elif ft == 3:
            for i in range(rowlen):
                left = row[i - bpp] if i >= bpp else 0
                row[i] = (row[i] + ((left + prev[i]) >> 1)) & 0xFF
        elif ft == 4:
            for i in range(rowlen):
                a = row[i - bpp] if i >= bpp else 0
                b = prev[i]
                c = prev[i - bpp] if i >= bpp else 0
                p = a + b - c
                pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                pred = a if pa <= pb and pa <= pc else (b if pb <= pc else c)
                row[i] = (row[i] + pred) & 0xFF
        elif ft != 0:
            raise PdfError("a PNG predictor row of type %d" % ft)
        out += row
        prev = row
    return bytes(out)


class Obj:
    __slots__ = ("num", "gen", "value", "offset", "stream", "header_offset", "cost")


class Pdf:
    def __init__(self, blob, ctx):
        self.blob, self.size, self.ctx = blob, len(blob), ctx
        self.cfg = ctx.cfg
        self.entries = {}
        self.cache = OrderedDict()      # object number -> Obj or None, oldest first, held to CACHE_BYTES
        self.cache_bytes = 0
        self.kept_bytes = 0
        self.objstm_cache = OrderedDict()
        self.objstm_bytes = 0
        self.objstm_charged = set()     # object streams whose decoded size was counted against max_total_bytes: counted once
        self.trailers = []
        self.revisions = []
        self.base = 0
        self.resolving = False
        self.scan_budget = 4 * self.size + (64 << 20)
        self.unreadable_compressed = 0
        self.encrypted = False
        self.strings_encrypted = False
        self.streams_encrypted = False
        self.encrypt_object = None
        self.length_problems = 0
        self.nesting = min(self.cfg["max_depth"], PDF_NESTING)
        self.failed_at = {}             # file offset -> why an object could not be parsed there: read once, never again
        self.objstm_failed = {}         # object stream number -> why it cannot be read
        self.objstm_at_limit = set()    # the object streams of those that were refused at a budget or a bound of the parser
        self.not_read_at_limit = set()  # the objects counted in over_objects, each once
        self.free_by_revision = {}      # revision index -> the numbers its table lists as free (a hybrid's stream may define them)
        self.over_objects = 0           # objects not read because a budget or the clock was reached
        self.scan_total = SCAN_FACTOR * self.size + SCAN_FLOOR
        self.scan_left = self.scan_total  # bytes every parse of this call may still scan together (see Meter)

    def problem(self, text):
        self.ctx.problem(text)

    # parsing at an offset, with a window that grows ---------------------------------------------------------------------

    def lexer(self, off, end, final, meter):
        return Lexer(self.blob, off, end, final, self.nesting, meter, self.cfg["max_stream_bytes"])

    def parse_at(self, off, fn, kind="object", cap=OBJECT_SCAN, pool=None):
        """fn(lexer) over a window at `off` that grows (64 KiB, x4, up to 32 MiB) while the object runs past it. Every attempt is
        charged to one meter, so the windows of one object together scan at most OBJECT_SCAN bytes, and the clock is read before
        each attempt. A failure is remembered by (offset, kind) and never read again, and only a failure that a larger window cannot
        change is remembered: the lexer reads its bytes in order and only NeedMore depends on where the window ends, so an error it
        raises inside a window is the error of every larger window, and running off the window is remembered only at the largest
        window or at the end of the file. The clock and the call's scan budget (TimeUp, ScanSpent) are limits of the call and are
        not remembered for the object."""
        if (off, kind) in self.failed_at:
            cls, message = self.failed_at[(off, kind)]
            raise cls(message)
        if pool is not None and pool.left <= 0:
            raise ScanSpent(pool.spent)
        if pool is None and self.scan_left <= 0:
            raise ScanSpent("the PDF parser's scan budget for this call is spent: the objects not read after that are counted in census.objects_not_read_at_a_limit")
        meter = Meter(self, cap, pool)
        window = 1 << 16
        try:
            while True:
                if time.monotonic() > self.ctx.deadline:
                    raise TimeUp("time: a PDF object was being parsed when max_seconds (%d) was reached; what was read is reported, and the counts are lower bounds" % self.ctx.seconds)
                end = min(self.size, off + window)
                try:
                    return fn(self.lexer(off, end, end >= self.size, meter)), off
                except NeedMore:
                    if end >= self.size:
                        raise PdfError("the object is cut off by the end of the file")
                    if window >= MAX_OBJECT_WINDOW:
                        raise ParseBound("an object longer than the %d-byte window" % MAX_OBJECT_WINDOW)
                    window *= 4
        except PdfError as exc:
            # The class and the message only: the exception itself holds its traceback, and through it the data it was read from.
            if len(self.failed_at) < FAILED_AT_MAX:
                self.failed_at[(off, kind)] = (type(exc), str(exc))
            raise

    def read_indirect(self, off, expect=None):
        """The object whose 'N G obj' header is at `off` (relative to the file; the header's own offset shift is tried when it is not
        there). Parses the value; for a stream, locates the data and checks its length against the 'endstream' keyword."""
        last = None
        for shift in ((0, self.base) if self.base else (0,)):
            at = off + shift
            if at < 0 or at >= self.size:
                continue

            def fn(lx):
                m = OBJ_RE.match(lx.buf, lx.pos, lx.end)
                if not m:
                    raise PdfError("no 'N G obj' header at offset %d" % at)
                lx.pos = m.end()
                value = lx.parse()
                lx.skip()
                stream_at = None
                if isinstance(value, dict):
                    # The 'stream' keyword and its end of line may lie past this window (a dictionary padded to the window's edge): the
                    # window grows before the object is taken for a plain dictionary.
                    if not lx.final and lx.end - lx.pos < 16:
                        raise NeedMore()
                    if lx.buf[lx.pos:lx.pos + 6] == b"stream":
                        p = lx.pos + 6
                        if lx.buf[p:p + 2] == b"\r\n":
                            p += 2
                        elif lx.buf[p:p + 1] in (b"\n", b"\r"):
                            p += 1
                        stream_at = p
                return int(m.group(1)), int(m.group(2)), value, stream_at, lx.cost()

            try:
                (num, gen, value, stream_at, cost), _ = self.parse_at(at, fn)
            except PdfError as exc:
                last = last or exc
                continue
            if expect is not None and num != expect:
                self.problem("the cross-reference entry for object %d points at the header of object %d (offset %d)" % (expect, num, at))
            o = Obj()
            o.num, o.gen, o.value, o.offset, o.stream, o.header_offset, o.cost = num, gen, value, at, None, shift, cost
            if stream_at is not None:
                o.stream = self.locate_stream(value, stream_at)
            return o
        raise last or PdfError("no object header at offset %d" % off)

    def locate_stream(self, value, start):
        """Where a stream's bytes are: {start, declared, measured, length, consistent}; `start` is the file offset after 'stream'."""
        declared = value.get("Length")
        if isinstance(declared, Ref):
            declared = self.int_of(declared)
        if isinstance(declared, bool) or not isinstance(declared, int) or declared < 0:
            declared = None
        ok = False
        if declared is not None and start + declared <= self.size:
            ok = ENDSTREAM_AFTER.match(self.blob, start + declared, min(self.size, start + declared + 24)) is not None
        measured = None
        if not ok:
            if self.scan_budget > 0:
                idx = self.blob.find(b"endstream", start)
                self.scan_budget -= max(1, (idx if idx >= 0 else self.size) - start)
                if idx >= 0:
                    end = idx
                    if self.blob[end - 2:end] == b"\r\n":
                        end -= 2
                    elif self.blob[end - 1:end] in (b"\n", b"\r"):
                        end -= 1
                    measured = max(0, end - start)
            else:
                self.ctx.limit_hit("stream lengths: the search for 'endstream' used its budget; later streams with a wrong /Length are listed without a measured length")
        length = declared if ok else measured
        return {"start": start, "declared": declared, "measured": measured, "length": length, "consistent": ok}

    def int_of(self, ref):
        if self.resolving:
            return None
        self.resolving = True
        try:
            o = self.get(ref.num)
        finally:
            self.resolving = False
        return o.value if o is not None and isinstance(o.value, int) and not isinstance(o.value, bool) else None

    # objects ----------------------------------------------------------------------------------------------------------

    def get(self, num):
        if num in self.cache:
            return self.cache[num]
        entry = self.entries.get(num)
        o = None
        if entry is not None:
            try:
                if entry[0] == 1:
                    o = self.read_indirect(entry[1], num)
                elif entry[0] == 2:
                    o = self.from_objstm(entry[1], entry[2], num)
            except ObjStmUnreadable as exc:
                if exc.at_limit:        # said once, for the object stream; counted as not read at a limit, not as unreadable
                    self.over_objects += 1
                    self.not_read_at_limit.add(num)
            except ParseBound as exc:
                self.ctx.limit_hit("PDF objects that pass a bound of the parser are not read (%s); they are counted in census.objects_not_read_at_a_limit" % exc)
                self.over_objects += 1
                self.not_read_at_limit.add(num)
            except PdfError as exc:
                self.problem("object %d could not be read: %s" % (num, exc))
            except Over as exc:
                # A budget or the clock reached while reading one object is a limit of the call, and that object is unread: the
                # reader that asked for it goes on with what it has (an Over that ended the whole answer lost everything read).
                self.ctx.limit_hit(str(exc))
                self.over_objects += 1
                self.not_read_at_limit.add(num)
        cost = o.cost if o is not None else 0
        if cost <= CACHE_OBJECT_BYTES:
            # oldest out first, until this one fits: what the cache holds is bounded by its estimated size, not by a count alone
            while self.cache and (self.cache_bytes + cost > CACHE_BYTES or len(self.cache) >= CACHE_OBJECTS):
                _n, old = self.cache.popitem(last=False)
                self.cache_bytes -= old.cost if old is not None else 0
            self.cache[num] = o
            self.cache_bytes += cost
        return o

    def keep(self, o):
        """o, when what the census keeps for the trace stays under KEEP_BYTES; else None, and the trace reads the object again (again())."""
        if o is not None and o.cost <= KEEP_OBJECT_BYTES and self.kept_bytes + o.cost <= KEEP_BYTES:
            self.kept_bytes += o.cost
            return o
        return None

    def again(self, num, kept):
        return kept if kept is not None else self.get(num)

    def deref(self, x, hops=8):
        num, first = None, x
        while isinstance(x, Ref) and hops > 0:
            o = self.get(x.num)
            if o is None:
                return None, x.num
            num, x, hops = x.num, o.value, hops - 1
        if isinstance(x, Ref):
            # an object whose value is a reference to another, eight times in a row: what the last one names is not read, and said
            self.problem("object %d leads through more than 8 references in a row (an object whose value is a reference to another): what the last names was not read" % first.num)
        if isinstance(x, (Ref, _Null)):
            return None, num
        return x, num

    # stream decoding --------------------------------------------------------------------------------------------------

    def filters_of(self, value):
        raw, _ = self.deref(value.get("Filter"))
        parms, _ = self.deref(value.get("DecodeParms", value.get("DP")))
        names = [raw] if isinstance(raw, Name) else [self.deref(x)[0] for x in raw] if isinstance(raw, list) else []
        plist = [parms] if isinstance(parms, dict) else [self.deref(x)[0] for x in parms] if isinstance(parms, list) else []
        out = []
        for i, name in enumerate(names[:MAX_FILTERS + 1]):
            p = plist[i] if i < len(plist) and isinstance(plist[i], dict) else {}
            out.append((str(name) if isinstance(name, Name) else "?", p))
        return out

    def decode(self, o, cap=None, charge=True):
        """The decoded bytes of a stream object under the budgets. Raises PdfError (a filter this tool does not decode, a corrupt stream)
        or Over. A stream is never returned cut.

        Every filter decodes in pieces, and every step's output is held to one bound that is checked before the bytes are allocated:
        the stream budget, the expansion ratio against the stream's encoded length, and what is left of the total budget. A step
        that would pass it raises Over at once, so that a decoder never builds an output it is not allowed to keep. The first filter
        reads the encoded bytes where they are in the file, a piece at a time: an encoded stream is never copied whole, so its length
        alone is no reason to refuse it (white space in ASCIIHex or ASCII85 data takes room and decodes to nothing)."""
        info = o.stream
        if info is None or info["length"] is None:
            raise PdfError("the stream's length cannot be established")
        member = self.ctx.budget.member if cap is None else min(cap, self.ctx.budget.member)
        budget = self.ctx.budget
        encoded = max(info["length"], 1)
        bounds = [(member, "a stream expanded past max_stream_bytes (%d)" % member),
                  (max(RATIO_FLOOR, budget.ratio * encoded), "a stream expanded past max_ratio (%d) of its encoded size (%d bytes)" % (budget.ratio, encoded)),
                  (max(0, budget.total - budget.used), "a stream would pass max_total_bytes (%d): the streams read before it used %d; the rest of this call reads no more stream content"
                   % (budget.total, budget.used))]
        if not charge:
            bounds = bounds[:2]         # a stream counted once already is held to the stream and ratio bounds, not to the total again
        limit, why = min(bounds, key=lambda b: b[0])
        chain = self.filters_of(o.value)
        if len(chain) > MAX_FILTERS:
            raise PdfError("a chain of more than %d filters" % MAX_FILTERS)
        src, s, e = self.blob, info["start"], info["start"] + info["length"]
        data = None
        for name, parms in chain:
            canon = SUPPORTED_FILTERS.get(name)
            if name == "Crypt":
                if str(parms.get("Name", "Identity")) != "Identity":
                    raise PdfError("a Crypt filter that is not the identity")
                continue
            if canon is None:
                raise PdfError("the %s filter is not decoded by this tool" % text_of(name, None, "names"))
            if data is not None:
                src, s, e = data, 0, len(data)
            if canon == "FlateDecode":
                data = self._flate(src, s, e, limit, why)
            elif canon == "ASCIIHexDecode":
                data = self._ahx(src, s, e, limit, why)
            elif canon == "ASCII85Decode":
                data = self._a85(src, s, e, limit, why)
            elif canon == "RunLengthDecode":
                data = self._rl(src, s, e, limit, why)
            predictor = parms.get("Predictor", 1) if isinstance(parms, dict) else 1
            if canon == "FlateDecode" and isinstance(predictor, int) and predictor > 1:
                if predictor == 2:
                    raise PdfError("a TIFF predictor is not decoded by this tool")
                if len(data) > PREDICTOR_MAX:
                    raise Over("a predictor-coded stream of %d bytes is over the %d-byte limit for undoing a predictor" % (len(data), PREDICTOR_MAX))
                get = lambda k, d: parms.get(k) if isinstance(parms.get(k), int) and not isinstance(parms.get(k), bool) else d
                data = png_unpredict(data, get("Columns", 1), get("Colors", 1), get("BitsPerComponent", 8), self.ctx)
            if len(data) > limit:
                raise Over(why)
        if data is None:
            if e - s > limit:
                raise Over(why)
            data = bytes(src[s:e])
        if len(data) > limit:
            raise Over(why)
        if charge:
            self.ctx.spend(len(data), "a stream")
        return data

    def _clock(self):
        if time.monotonic() > self.ctx.deadline:
            raise TimeUp("time: a PDF stream was being decoded when max_seconds (%d) was reached; what was read is reported, and the counts are lower bounds" % self.ctx.seconds)

    def _flate(self, src, s, e, limit, why):
        d = zlib.decompressobj()
        out = bytearray()
        pos = s
        try:
            while pos < e and not d.eof:
                chunk = src[pos:min(e, pos + PAGE)]
                pos += len(chunk)
                out += d.decompress(chunk, limit + 1 - len(out))
                while d.unconsumed_tail and len(out) <= limit:
                    out += d.decompress(d.unconsumed_tail, limit + 1 - len(out))
                if len(out) > limit:
                    raise Over(why)
                if not (pos - s) & 0xFFFFF:
                    self._clock()
        except zlib.error as exc:
            raise PdfError("the Flate data is corrupt (%s)" % exc)
        if not d.eof:
            raise PdfError("the Flate data ends before its end marker")
        return bytes(out)

    def _ahx(self, src, s, e, limit, why):
        close = src.find(b">", s, e)
        if close >= 0:
            e = close
        out, carry = bytearray(), b""
        for pos in range(s, e, PAGE):
            piece = carry + src[pos:min(e, pos + PAGE)].translate(None, NON_HEX)
            usable = len(piece) // 2 * 2
            if len(out) + usable // 2 > limit:
                raise Over(why)
            out += bytes.fromhex(piece[:usable].decode("ascii"))
            carry = piece[usable:]
            if not (pos - s) & 0xFFFFF:
                self._clock()
        if carry:
            if len(out) + 1 > limit:
                raise Over(why)
            out += bytes.fromhex((carry + b"0").decode("ascii"))
        return bytes(out)

    def _a85(self, src, s, e, limit, why):
        """ASCII base-85 (ISO 32000-1 7.4.3) in pieces: groups of five characters give four bytes, a 'z' gives four zero bytes (and only
        between groups), a final group of two to four characters gives one byte fewer, white space is ignored, '~>' ends the data."""
        m = A85_LEAD.match(src, s, e)
        if m:
            s = m.end()
        close = src.find(b"~>", s, e)
        if close >= 0:
            e = close
        out, rem = bytearray(), b""
        try:
            for pos in range(s, e, PAGE):
                parts = A85_ZRUN.split(rem + src[pos:min(e, pos + PAGE)].translate(None, A85_WS))
                rem = parts.pop()
                for i, part in enumerate(parts):
                    if i % 2:
                        if len(out) + 4 * len(part) > limit:
                            raise Over(why)
                        out += bytes(4 * len(part))
                    elif part:
                        if len(part) % 5:
                            raise PdfError("the ASCII85 data is corrupt (a 'z' inside a group of five)")
                        if len(out) + len(part) // 5 * 4 > limit:
                            raise Over(why)
                        out += base64.a85decode(part, adobe=False)
                whole = len(rem) // 5 * 5
                if whole:
                    if len(out) + whole // 5 * 4 > limit:
                        raise Over(why)
                    out += base64.a85decode(rem[:whole], adobe=False)
                    rem = rem[whole:]
                if not (pos - s) & 0xFFFFF:
                    self._clock()
            if rem:
                if len(rem) == 1:
                    raise PdfError("the ASCII85 data is corrupt (a final group of one character)")
                if len(out) + len(rem) - 1 > limit:
                    raise Over(why)
                out += base64.a85decode(rem, adobe=False)
        except ValueError as exc:
            raise PdfError("the ASCII85 data is corrupt (%s)" % exc)
        return bytes(out)

    def _rl(self, src, s, e, limit, why):
        out, i, runs = bytearray(), s, 0
        while i < e:
            c = src[i]
            i += 1
            if c == 128:
                break
            if c < 128:
                piece = src[i:min(e, i + c + 1)]
                i += c + 1
            else:
                piece = src[i:min(e, i + 1)] * (257 - c)
                i += 1
            if len(out) + len(piece) > limit:
                raise Over(why)
            out += piece
            runs += 1
            if not runs & 0xFFFF:
                self._clock()
        return bytes(out)

    # object streams ---------------------------------------------------------------------------------------------------

    def objstm(self, num):
        if num in self.objstm_cache:
            self.objstm_cache.move_to_end(num)
            return self.objstm_cache[num]
        if num in self.objstm_failed:
            raise PdfError(self.objstm_failed[num])
        try:
            return self._objstm(num)
        except Over as exc:
            if isinstance(exc, TimeUp):
                raise
            self.ctx.limit_hit("object stream %d: %s; the objects it holds are counted in census.objects_not_read_at_a_limit" % (num, exc))
            self.objstm_failed[num] = "a budget was reached reading it (%s)" % exc
            self.objstm_at_limit.add(num)
            raise PdfError(self.objstm_failed[num])
        except PdfError as exc:
            self.objstm_failed[num] = str(exc)
            if not isinstance(exc, ParseBound):
                self.problem("object stream %d cannot be read: %s; the objects it holds are counted unreadable" % (num, exc))
            else:
                self.ctx.limit_hit("object stream %d passes a bound of the parser (%s); the objects it holds are counted in census.objects_not_read_at_a_limit" % (num, exc))
                self.objstm_at_limit.add(num)
            raise

    def _objstm(self, num):
        entry = self.entries.get(num)
        o = self.get(num) if entry is not None and entry[0] == 1 else None
        res = None
        if o is None or o.stream is None or not isinstance(o.value, dict) or o.value.get("Type") != "ObjStm":
            raise PdfError("object %d is not an object stream" % num)
        n, first = o.value.get("N"), o.value.get("First")
        if not (isinstance(n, int) and isinstance(first, int)) or n < 0 or first < 0 or n > MAX_HEADER_PAIRS:
            raise PdfError("object stream %d has no usable /N and /First" % num)
        # A stream read again after it left the cache is decoded again, and counted against max_total_bytes once: the budget is of
        # the content the call reads, and reading one stream twice is not reading more of the file.
        data = self.decode(o, charge=num not in self.objstm_charged)
        self.objstm_charged.add(num)
        found = re.findall(rb"[0-9]+", data[:first])[:2 * n]
        if any(len(x) > 20 for x in found):
            raise PdfError("object stream %d's header holds a number of more than 20 digits" % num)
        nums = [int(x) for x in found]
        if len(nums) < 2 * n:
            raise PdfError("object stream %d lists %d of the %d objects it declares" % (num, len(nums) // 2, n))
        res = (data, first, [(nums[2 * i], nums[2 * i + 1]) for i in range(n)])
        cost = len(data) + n * ITEM_BYTES
        if cost <= OBJSTM_CACHE_BYTES:
            while self.objstm_cache and self.objstm_bytes + cost > OBJSTM_CACHE_BYTES:
                _n, old = self.objstm_cache.popitem(last=False)
                self.objstm_bytes -= len(old[0]) + len(old[2]) * ITEM_BYTES
            self.objstm_cache[num] = res
            self.objstm_bytes += cost
        return res

    def from_objstm(self, stm, index, num):
        try:
            data, first, pairs = self.objstm(stm)
        except PdfError as exc:
            self.unreadable_compressed += 1
            raise ObjStmUnreadable("object %d lives in object stream %d, which cannot be read: %s" % (num, stm, exc), stm in self.objstm_at_limit)
        if not (0 <= index < len(pairs)) or pairs[index][0] != num:
            idx = next((i for i, p in enumerate(pairs) if p[0] == num), None)
            if idx is None:
                raise PdfError("object %d is not in object stream %d" % (num, stm))
            index = idx
        at = first + pairs[index][1]
        if at >= len(data):
            raise PdfError("object %d's offset is outside object stream %d" % (num, stm))
        lx = Lexer(data, at, len(data), True, self.nesting, Meter(self), self.cfg["max_stream_bytes"])
        value = lx.parse()
        o = Obj()
        o.num, o.gen, o.value, o.offset, o.stream, o.header_offset, o.cost = num, 0, value, None, None, 0, lx.cost()
        return o

    # cross-reference chain --------------------------------------------------------------------------------------------

    def find_startxref(self):
        tail = self.blob[max(0, self.size - 4096):]
        i = tail.rfind(b"startxref")
        if i < 0:
            return None
        m = re.match(rb"startxref[\x00\t\n\x0c\r ]+([0-9]{1,15})", tail[i:])
        return int(m.group(1)) if m else None

    def read_xref_chain(self, start):
        seen, off = set(), start
        pending = [("startxref", off, None)]
        while pending and len(self.revisions) < MAX_REVISIONS:
            how, off, owner = pending.pop(0)
            if off in seen:
                self.problem("the cross-reference chain returns to offset %d: a /Prev loop" % off)
                break
            seen.add(off)
            if self.ctx.expired("the cross-reference chain"):
                return False
            try:
                nxt = self.read_xref_section(off, how, owner)
            except PdfError as exc:
                self.problem("the cross-reference section at offset %d cannot be read: %s" % (off, exc))
                return False
            pending.extend(nxt)
        if pending:
            self.ctx.limit_hit("the cross-reference chain has more than %d sections: the rest were not followed" % MAX_REVISIONS)
        return True

    def read_xref_section(self, off, how, owner=None):
        for shift in ((0, self.base) if self.base else (0,)):
            at = off + shift
            if at < 0 or at >= self.size:
                continue
            head = self.blob[at:at + 64].lstrip(WS_BYTES)
            if head.startswith(b"xref"):
                return self.read_xref_table(at, off, how)
            if OBJ_RE.match(self.blob[at:at + 64]):
                return self.read_xref_stream(at, off, how, owner)
        raise PdfError("neither an 'xref' keyword nor an object header is there")

    def add_entry(self, num, kind, a, b, over_free=None):
        if num in self.entries:
            # A hybrid file lists, as free in its table, the objects its cross-reference stream defines: the stream's entry takes the free
            # one's place, but only for a number the table OF THE SAME REVISION made free. A number a newer revision freed (a deleted
            # object) stays free: an older revision's stream does not bring it back.
            if over_free is not None and num in over_free and self.entries[num][0] == 0 and kind != 0:
                self.entries[num] = (kind, a, b)
            return
        if len(self.entries) >= self.cfg["max_objects"]:
            if not self.ctx.cfg.get("_objects_capped"):
                self.ctx.cfg["_objects_capped"] = True
                self.ctx.limit_hit("the cross-reference sections list more than max_objects (%d) objects: the rest are not indexed" % self.cfg["max_objects"])
            return
        self.entries[num] = (kind, a, b)

    def read_xref_table(self, at, off, how):
        pos = at + (len(self.blob[at:at + 64]) - len(self.blob[at:at + 64].lstrip(WS_BYTES))) + 4
        count_entries = 0
        subsections = 0
        freed = set()
        while True:
            subsections += 1
            if not subsections & 4095 and self.ctx.expired("a cross-reference table"):
                raise PdfError("the clock ran out inside a cross-reference table, after %d subsections" % subsections)
            window = self.blob[pos:pos + 64]
            m = re.match(rb"[\x00\t\n\x0c\r ]*([0-9]{1,10})[\x00\t\n\x0c\r ]+([0-9]{1,10})", window)
            if not m:
                break
            first, count = int(m.group(1)), int(m.group(2))
            pos += m.end()
            if count > (self.size - pos) // 18 + 1:
                raise PdfError("a subsection declares %d entries and the file cannot hold them" % count)
            body = self.blob[pos:pos + count * 20 + 40]
            ent = XREF_ENTRY
            p = 0
            for i in range(count):
                em = ent.match(body, p)
                if not em:
                    raise PdfError("entry %d of a subsection that starts at object %d is malformed" % (i, first))
                p = em.end()
                if em.group(3) == b"n":
                    self.add_entry(first + i, 1, int(em.group(1)), int(em.group(2)))
                else:
                    if first + i not in self.entries:
                        freed.add(first + i)
                    self.add_entry(first + i, 0, 0, int(em.group(2)))
                count_entries += 1
                if i % 4096 == 0 and self.ctx.expired("a cross-reference table"):
                    raise PdfError("the clock ran out inside a cross-reference table")
            pos += p
        rest = self.blob[pos:pos + 16].lstrip(WS_BYTES)
        if not rest.startswith(b"trailer"):
            raise PdfError("no 'trailer' keyword after the table")
        tpos = pos + (len(self.blob[pos:pos + 16]) - len(rest)) + 7
        trailer, _ = self.parse_at(tpos, lambda lx: lx.parse(), "dictionary")
        if not isinstance(trailer, dict):
            raise PdfError("the trailer is not a dictionary")
        self.trailers.append(trailer_view(trailer))
        rev = {"index": len(self.revisions), "kind": "table", "startxref": off, "entries": count_entries, "size": trailer.get("Size") if isinstance(trailer.get("Size"), int) else None,
               "prev": trailer.get("Prev") if isinstance(trailer.get("Prev"), int) else None, "encrypt_in_trailer": "Encrypt" in trailer}
        self.revisions.append(rev)
        nxt = []
        xs = trailer.get("XRefStm")
        if isinstance(xs, int) and not isinstance(xs, bool):
            rev["hybrid_xrefstm"] = xs
            self.free_by_revision[rev["index"]] = freed
            nxt.append(("XRefStm", xs, rev["index"]))
        if isinstance(trailer.get("Prev"), int):
            nxt.append(("Prev", trailer["Prev"], None))
        return nxt

    def read_xref_stream(self, at, off, how, owner=None):
        o = self.read_indirect(off, None)
        v = o.value
        if not isinstance(v, dict) or v.get("Type") != "XRef" or o.stream is None:
            raise PdfError("the object at offset %d is not a cross-reference stream" % off)
        w = v.get("W")
        if not (isinstance(w, list) and len(w) == 3 and all(isinstance(x, int) and 0 <= x <= 8 for x in w)) or sum(w) == 0:
            raise PdfError("the cross-reference stream has no usable /W")
        size = v.get("Size")
        if not isinstance(size, int):
            raise PdfError("the cross-reference stream has no /Size")
        index = v.get("Index") if isinstance(v.get("Index"), list) else [0, size]
        if len(index) % 2 or not all(isinstance(x, int) and x >= 0 for x in index):
            raise PdfError("the cross-reference stream's /Index is not a list of pairs")
        data = self.decode(o)
        width = sum(w)
        total = len(data) // width
        entries, pos = 0, 0
        for k in range(0, len(index), 2):
            first, count = index[k], index[k + 1]
            if not k & 1023 and self.ctx.expired("a cross-reference stream's /Index"):
                raise PdfError("the clock ran out inside a cross-reference stream, at its /Index pair %d" % (k // 2))
            for i in range(count):
                if pos + width > len(data):
                    self.problem("the cross-reference stream holds %d entries and its /Index declares more" % (pos // width))
                    break
                f1 = int.from_bytes(data[pos:pos + w[0]], "big") if w[0] else 1
                f2 = int.from_bytes(data[pos + w[0]:pos + w[0] + w[1]], "big")
                f3 = int.from_bytes(data[pos + w[0] + w[1]:pos + width], "big") if w[2] else 0
                pos += width
                entries += 1
                hybrid = self.free_by_revision.get(owner) if how == "XRefStm" else None
                if f1 == 1:
                    self.add_entry(first + i, 1, f2, f3, hybrid)
                elif f1 == 2:
                    self.add_entry(first + i, 2, f2, f3, hybrid)
                elif f1 == 0:
                    self.add_entry(first + i, 0, 0, f3)
                if entries % 8192 == 0 and self.ctx.expired("a cross-reference stream"):
                    raise PdfError("the clock ran out inside a cross-reference stream")
        self.trailers.append(trailer_view(v))
        rev = {"index": len(self.revisions), "kind": "stream", "startxref": off, "entries": entries, "size": size,
               "prev": v.get("Prev") if isinstance(v.get("Prev"), int) else None, "encrypt_in_trailer": "Encrypt" in v}
        self.revisions.append(rev)
        return [("Prev", v["Prev"], None)] if isinstance(v.get("Prev"), int) else []


TRAILER_KEPT = ("Size", "Prev", "Root", "Encrypt", "XRefStm", "Type")


def trailer_view(d):
    """What the reader keeps of a trailer (or of a cross-reference stream's dictionary) for later: the entries it reads, and whether /Info
    and /ID are there. A trailer can hold anything else, up to MAX_ITEMS values, and a file can hold a thousand revisions of them."""
    view = {k: d[k] for k in TRAILER_KEPT if k in d}
    for k in ("Info", "ID"):
        if k in d:
            view[k] = True
    return view


def is_action(d):
    if not isinstance(d, dict):
        return False
    s = d.get("S")
    return (isinstance(s, Name) and str(s) in ACTION_SUBTYPES and d.get("Type") in (None, "Action")) or ("JS" in d and d.get("Type") in (None, "Action"))


def pdf_encryption(pdf, ctx):
    """The encryption dictionary the newest trailer names, read as structure: handler, version, revision, crypt filters, permission
    bits; the owner and user verifiers and their companions are reported by length and never as bytes."""
    if not pdf.trailers:
        return None
    holder = next((t for t in pdf.trailers if "Encrypt" in t), None)
    if holder is None:
        return {"present": False}
    current = pdf.trailers[0]
    entry = {"present": "Encrypt" in current, "in_current_trailer": "Encrypt" in current}
    if not entry["in_current_trailer"]:
        entry["in_an_earlier_revision_only"] = True
        entry["note"] = "an earlier revision's trailer names an encryption dictionary and the current one does not: the current trailer is what a reader follows, and the file's objects may still be encrypted"
        return entry
    d, num = pdf.deref(holder["Encrypt"])
    # Strings and streams of an encrypted file are ciphertext (ISO 32000-1 7.6.1), except where a crypt filter of the identity is
    # named (V 4 and 5: StrF and StmF, whose default is the identity) and in the encryption dictionary itself.
    pdf.strings_encrypted = pdf.streams_encrypted = True
    pdf.encrypt_object = num
    if not isinstance(d, dict):
        ctx.problem("the trailer's /Encrypt does not lead to a dictionary")
        entry["dictionary"] = "unreadable"
        return entry
    if isinstance(d.get("V"), int) and d.get("V") in (4, 5):
        pdf.strings_encrypted = str(d.get("StrF", "Identity")) != "Identity"
        pdf.streams_encrypted = str(d.get("StmF", "Identity")) != "Identity"
    out = {"object": num}
    for key, name in (("Filter", "filter"), ("SubFilter", "sub_filter"), ("StmF", "stm_f"), ("StrF", "str_f"), ("EFF", "eff")):
        if isinstance(d.get(key), Name):
            out[name] = text_of(str(d[key]), None, "names")
    for key, name in (("V", "v"), ("R", "r"), ("Length", "length_bits")):
        if isinstance(d.get(key), int) and not isinstance(d.get(key), bool):
            out[name] = d[key]
    p = d.get("P")
    if isinstance(p, int) and not isinstance(p, bool):
        u = p & 0xFFFFFFFF
        out["permissions"] = {"signed": u - (1 << 32) if u & 0x80000000 else u, "hex": "0x%08X" % u, "note": "permission flags: what a conforming reader is asked to allow, not a protection"}
    if isinstance(d.get("EncryptMetadata"), bool):
        out["encrypt_metadata"] = d["EncryptMetadata"]
    cf, _ = pdf.deref(d.get("CF"))
    if isinstance(cf, dict):
        filters, names = {}, KeyedCounts()
        if len(cf) > 20:
            ctx.limit_hit("the encryption dictionary's /CF names %d crypt filters: the first 20 are listed" % len(cf))
        for name, f in list(cf.items())[:20]:
            f, _n = pdf.deref(f)
            if isinstance(f, dict):
                filters[names.key(name)] = {"cfm": text_of(str(f.get("CFM")), None, "names") if isinstance(f.get("CFM"), Name) else None,
                                                         "length": f.get("Length") if isinstance(f.get("Length"), int) else None,
                                                         "auth_event": text_of(str(f.get("AuthEvent")), None, "names") if isinstance(f.get("AuthEvent"), Name) else None}
        out["crypt_filters"] = filters
    out["verifier_fields_present"] = [{"name": k, "length": len(d[k])} for k in ("O", "U", "OE", "UE", "Perms") if isinstance(d.get(k), PStr)]
    out["not_reported"] = "the owner and user password verifiers (/O, /U, /OE, /UE) and /Perms are in the dictionary and are reported by length only"
    out["not_determined"] = "whether an opening password is needed: no password, empty or otherwise, was tried"
    entry["dictionary"] = out
    return entry


def stream_spans(blob, ctx, budget):
    """(start, end) of the data of every 'stream' ... 'endstream' run in the file, in order, found by scanning: what a scan of the
    file for keywords must not take for structure (a trailer written inside a stream is data)."""
    spans, pos, n = [], 0, 0
    for m in re.finditer(rb">>[\x00\t\n\x0c\r ]*stream(?:\r\n|\n|\r)", blob):
        if m.start() < pos:
            continue
        n += 1
        if not n & 1023 and ctx.expired("the scan for stream data"):
            break
        # The data ends at its direct /Length when 'endstream' follows there (an 'endstream' written inside the data is data), else at the
        # first 'endstream'.
        end = -1
        length = DIRECT_LENGTH.findall(blob[max(0, m.start() - 512):m.start()])
        if length and len(length[-1]) <= 12:
            at = m.end() + int(length[-1])
            if at <= len(blob) and ENDSTREAM_AFTER.match(blob, at, min(len(blob), at + 24)):
                end = at
        if end < 0:
            end = blob.find(b"endstream", m.end())
        end = len(blob) if end < 0 else end
        spans.append((m.end(), end))
        pos = end
        if len(spans) >= budget:
            ctx.limit_hit("the scan for stream data stopped after %d streams: a trailer keyword after them is not checked against stream data" % budget)
            break
    return spans


def in_comment(blob, at):
    """Whether the keyword at `at` follows a '%' on its own line (a comment, ISO 32000-1 7.2.3). Strings are not followed: a '%' in a
    string on the same line makes this say comment, which keeps a keyword out rather than in. Only the 4096 bytes before the keyword
    are looked at: on a longer line a '%' further back is not seen (and the header's '%PDF' at offset 0 is never taken for the start
    of this line's comment)."""
    floor = max(0, at - 4096)
    line = max(blob.rfind(b"\n", floor, at), blob.rfind(b"\r", floor, at))
    return blob.find(b"%", max(line + 1, floor), at) >= 0


def probe_pdf(blob, ctx, extractor):
    """The PDF answer. A budget or the clock reached anywhere in it is a limit, and the answer keeps what was read before it."""
    out = {"container": "PDF"}
    try:
        _probe_pdf(blob, ctx, extractor, out)
    except Over as exc:
        ctx.limit_hit("%s; the PDF answer holds what was read before it%s" % (exc, "" if "census" in out else " (the census was not reached: the answer has none)"))
    out.setdefault("coverage", {"structures_read": PDF_READ, "structures_not_read": PDF_NOT_READ})
    return out


def _probe_pdf(blob, ctx, extractor, out):
    cfg = ctx.cfg
    size = len(blob)
    pdf = Pdf(blob, ctx)
    if cfg["max_depth"] > PDF_NESTING:
        out["object_nesting"] = {"followed": PDF_NESTING, "max_depth": cfg["max_depth"],
                                 "note": "PDF objects are parsed to a nesting of %d whatever max_depth says; an object nested deeper is an unreadable object, named in problems" % PDF_NESTING}
    head = blob[:HEAD_BYTES]
    m = re.search(rb"%PDF-(\d\.\d)", head)
    anomalies = []
    if m:
        out["pdf_header"] = {"version": m.group(1).decode("ascii"), "offset": m.start()}
        pdf.base = m.start()
        if m.start():
            anomalies.append("%d byte(s) before the %%PDF- header: offsets in the file are relative to the header in a strict reader and absolute in many others" % m.start())
    else:
        ctx.problem("no %%PDF- header line in the first %d bytes" % HEAD_BYTES)
    eofs = [x.start() for x in re.finditer(rb"%%EOF", blob[max(0, size - (4 << 20)):])]
    out["eof_markers"] = len(eofs) if size <= 4 << 20 else "%d in the last 4 MiB" % len(eofs)
    trail = blob[max(0, size - 4096):].rfind(b"%%EOF")
    if trail >= 0:
        after = blob[max(0, size - 4096) + trail + 5:]
        if after.strip(WS_BYTES):
            anomalies.append("%d non-whitespace byte(s) after the last %%%%EOF marker" % len(after.strip(WS_BYTES)))
    else:
        anomalies.append("no %%EOF marker in the last 4096 bytes")
    structure = "xref"
    start = pdf.find_startxref()
    if start is None:
        ctx.problem("no startxref in the last 4096 bytes: the cross-reference chain is rebuilt by scanning the file")
        structure = "scan"
    else:
        out["startxref"] = start
        try:
            ok = pdf.read_xref_chain(start)
        except Over as exc:
            ctx.limit_hit(str(exc))
            ok = False
        if not ok or not pdf.entries:
            structure = "scan"
    # A scan of the whole file for 'N G obj' headers: the objects a reader that ignores the table would find.
    # The scan goes a piece at a time, so that the clock is checked between pieces even when a piece holds no header at all (a regular
    # expression over the whole file is one call that cannot be stopped); a header that starts in a piece is read past its end.
    scanned, scan_total, dups, truncated_scan = {}, 0, {}, False   # number -> the offset of its last header; number -> headers past the first
    piece = 1 << 20
    for chunk_at in range(0, size, piece):
        if ctx.expired("the object scan"):
            truncated_scan = True
            break
        for hit in SCAN_OBJ.finditer(blob, chunk_at, min(size, chunk_at + piece + 64)):
            if hit.start() >= chunk_at + piece:
                break
            scan_total += 1
            n = int(hit.group(1))
            if n in scanned:
                dups[n] = dups.get(n, 0) + 1
            scanned[n] = hit.start()
            if scan_total >= cfg["max_objects"] * 4:
                break
        if scan_total >= cfg["max_objects"] * 4:
            ctx.limit_hit("the object scan stopped after %d headers (max_objects x 4)" % scan_total)
            truncated_scan = True
            break
    if structure == "scan":
        for n, at in scanned.items():
            pdf.add_entry(n, 1, at, 0)
        if not pdf.trailers:
            # Trailers by scan: every 'trailer' keyword with a dictionary, and cross-reference stream dictionaries found below. A keyword
            # inside a stream's data or in a comment is not a trailer: taking it for one would let a stream choose the "current" trailer.
            spans = stream_spans(blob, ctx, cfg["max_objects"] * 4)
            starts = [a for a, _b in spans]
            ignored = {"in_stream_data": 0, "in_a_comment": 0}
            # The search has a share of its own (a quarter of the call's scan budget, at most 64 MiB) and a trailer dictionary is read to
            # 1 MiB at most: a junk tail of 'trailer' keywords ends this search, named, and the census and the trace still run.
            pool = ScanPool(min(pdf.scan_total // 4, 64 << 20), "a trailer dictionary found by the scan",
                            "the scan for trailers spent its share of the parser's budget: the 'trailer' keywords after that were not read")
            for k, t in enumerate(re.finditer(rb"trailer[\x00\t\n\x0c\r ]*<<", blob)):
                if not (k + 1) & 255 and ctx.expired("the scan for trailers"):
                    break
                i = bisect.bisect_right(starts, t.start()) - 1
                if i >= 0 and spans[i][0] <= t.start() < spans[i][1]:
                    ignored["in_stream_data"] += 1
                    continue
                if in_comment(blob, t.start()):
                    ignored["in_a_comment"] += 1
                    continue
                try:
                    d, _ = pdf.parse_at(t.end() - 2, lambda lx: lx.parse(), "dictionary", 1 << 20, pool)
                except ParseBound:
                    ignored["over_1_mib"] = ignored.get("over_1_mib", 0) + 1
                    continue
                except PdfError:
                    continue
                except Over as exc:
                    ctx.limit_hit(str(exc))
                    break
                if isinstance(d, dict):
                    pdf.trailers.insert(0, trailer_view(d))
            if ignored.get("over_1_mib"):
                ctx.limit_hit("%d 'trailer' keyword(s) found by the scan begin a dictionary of more than 1 MiB: not read as trailers" % ignored["over_1_mib"])
            if ignored["in_stream_data"] or ignored["in_a_comment"] or ignored.get("over_1_mib"):
                out["trailer_keywords_ignored"] = ignored
                anomalies.append("%d 'trailer' keyword(s) inside stream data and %d in a comment were not taken for trailers" % (ignored["in_stream_data"], ignored["in_a_comment"]))
        anomalies.append("the cross-reference chain could not be used; the object index comes from scanning the file for object headers, and the newest definition of a number wins")
    out["structure_source"] = "cross-reference chain" if structure == "xref" else "scan of the file for object headers"
    revisions = pdf.revisions
    out["revisions"] = revisions
    out["objects_scan"] = {"object_headers_found": scan_total, "distinct_numbers": len(scanned), "complete": not truncated_scan,
                           "numbers_defined_more_than_once": len(dups)}
    outside = {}                    # object number -> (how the newest chain leaves it out, the offset of its header)
    if structure == "xref":
        # A header the newest chain does not use: no entry at all, or an entry that the newest section to name the number marks free (a
        # deleted object whose bytes are still in the file). A reader that follows the chain does not see either; one that rebuilds the
        # file by scanning does. Each is counted apart, and the action dictionaries among them are read and listed (trace_catalog).
        absent = [n for n in scanned if n not in pdf.entries]
        freed = [n for n in scanned if n in pdf.entries and pdf.entries[n][0] == 0]
        packed = [n for n in scanned if n in pdf.entries and pdf.entries[n][0] == 2]
        out["objects_scan"]["headers_not_in_the_cross_reference_chain"] = len(absent)
        out["objects_scan"]["headers_freed_in_newest_chain"] = len(freed)
        out["objects_scan"]["headers_the_chain_places_in_object_streams"] = len(packed)
        if absent:
            anomalies.append("%d object number(s) have an 'N G obj' header in the file and no entry in the cross-reference chain" % len(absent))
        if freed:
            anomalies.append("%d object number(s) have an 'N G obj' header in the file and an entry that the newest cross-reference section to name them marks free" % len(freed))
        if packed:
            anomalies.append("%d object number(s) have an 'N G obj' header in the file and an entry that places them in an object stream" % len(packed))
        outside = {n: ("absent", scanned[n]) for n in absent}
        outside.update({n: ("freed", scanned[n]) for n in freed})
    # The census: each indexed object's dictionary, never its stream.
    objects = ctx.page("objects")
    types, filters_seen, streams = KeyedCounts(), KeyedCounts(), {"count": 0, "declared_bytes": 0, "length_inconsistent": 0, "undecodable_filter": 0}
    interesting = {}
    embedded = []
    compressed_total = sum(1 for e in pdf.entries.values() if e[0] == 2)
    unreadable = 0
    census_done = 0
    stop_census = False
    def census(order):
        nonlocal census_done, stop_census, unreadable
        for num in order:
            if stop_census:
                break
            entry = pdf.entries[num]
            if entry[0] == 0:
                continue
            if ctx.expired("the object census"):
                stop_census = True
                break
            try:
                o = pdf.get(num)
            except Over as exc:
                ctx.limit_hit(str(exc))
                stop_census = True
                break
            census_done += 1
            if o is None:
                if num not in pdf.not_read_at_limit:
                    unreadable += 1
                continue
            v = o.value
            row = {"object": num, "generation": o.gen}
            if entry[0] == 1:
                row["offset"] = o.offset
            else:
                row["in_object_stream"] = entry[1]
                row["index_in_stream"] = entry[2]
            kind = "dictionary" if isinstance(v, dict) else "array" if isinstance(v, list) else type(v).__name__
            if o.stream is not None:
                kind = "stream"
            row["kind"] = kind
            if isinstance(v, dict):
                t = v.get("Type")
                if isinstance(t, Name):
                    row["type"] = text_of(str(t), None, "names")
                    types.add(t)
                st = v.get("Subtype")
                if isinstance(st, Name):
                    row["subtype"] = text_of(str(st), None, "names")
                if t in ("Catalog", "ObjStm", "XRef", "EmbeddedFile", "Filespec") or "JS" in v or is_action(v) or "EF" in v:
                    interesting[num] = pdf.keep(o)
            if o.stream is not None:
                info = o.stream
                streams["count"] += 1
                streams["declared_bytes"] += info["declared"] or 0
                chain = [n for n, _p in pdf.filters_of(v)]
                names = [text_of(n, None, "names") for n in chain]
                row["stream"] = {"declared_length": info["declared"], "measured_length": info["measured"], "length_consistent": info["consistent"], "filters": names}
                key = "+".join(chain) if chain else "none"
                if key in filters_seen or len(filters_seen) < 100:
                    filters_seen.add(key)
                else:
                    streams["in_chains_past_the_first_100"] = streams.get("in_chains_past_the_first_100", 0) + 1
                if not info["consistent"]:
                    streams["length_inconsistent"] += 1
                if any(SUPPORTED_FILTERS.get(n) is None and n != "Crypt" for n in chain):
                    streams["undecodable_filter"] += 1
                if len(chain) > 3:
                    row["note"] = "a chain of %d filters" % len(chain)
            objects.add(row)

    census(sorted(pdf.entries))
    if structure == "scan":
        # Objects inside object streams are not listed by any table here: read each object stream found and index what it holds.
        for onum, kept in list(interesting.items()):
            if stop_census:
                break
            oo = pdf.again(onum, kept)
            if oo is not None and isinstance(oo.value, dict) and oo.value.get("Type") == "ObjStm" and oo.stream is not None:
                try:
                    _data, _first, pairs = pdf.objstm(onum)
                except (PdfError, Over) as exc:
                    (ctx.limit_hit if isinstance(exc, Over) else ctx.problem)("object stream %d was not read: %s" % (onum, exc))
                    continue
                new = []
                for i, (n, _off) in enumerate(pairs):
                    if n not in pdf.entries:
                        pdf.add_entry(n, 2, onum, i)
                        if n in pdf.entries:        # not indexed when max_objects is reached: that is a limit, said by add_entry
                            new.append(n)
                census(new)
        if not pdf.trailers:
            for onum, kept in interesting.items():
                oo = pdf.again(onum, kept)
                if oo is not None and isinstance(oo.value, dict) and oo.value.get("Type") == "XRef":
                    pdf.trailers.append(trailer_view(oo.value))
    compressed_total = sum(1 for e in pdf.entries.values() if e[0] == 2)
    out["census"] = {"objects_listed": census_done, "objects_in_table_of_kind_free": sum(1 for e in pdf.entries.values() if e[0] == 0), "compressed_objects_indexed": compressed_total,
                     "objects_unreadable": unreadable, "objects_not_read_at_a_limit": len(pdf.not_read_at_limit), "complete": not stop_census and not pdf.not_read_at_limit}
    if stop_census:
        ctx.limit_hit("the object census stopped early: the counts and the actions found are lower bounds")
    out["streams"] = {**streams, "by_filter_chain": filters_seen.counts}
    if streams.get("in_chains_past_the_first_100"):
        ctx.limit_hit("the streams use more than 100 distinct filter chains: the first 100 are counted in streams.by_filter_chain, the %d streams of the "
                      "others in streams.in_chains_past_the_first_100; every stream's filters are in the objects table" % streams["in_chains_past_the_first_100"])
    out["object_types"] = dict(sorted(types.counts.items(), key=lambda kv: -kv[1])[:50])
    if len(types) > 50:
        out["object_types_total"] = len(types)
        ctx.limit_hit("the objects carry %d distinct /Type names: the 50 most frequent are counted in object_types; every object's type is in the objects table" % len(types))
    # Trailer and encryption
    trailer = pdf.trailers[0] if pdf.trailers else {}
    out["trailer"] = {"size": trailer.get("Size") if isinstance(trailer.get("Size"), int) else None, "root": isinstance(trailer.get("Root"), Ref),
                      "info": "Info" in trailer, "id": "ID" in trailer, "encrypt": "Encrypt" in trailer, "newest_of": len(pdf.trailers)}
    enc = pdf_encryption(pdf, ctx)
    out["encryption"] = enc
    pdf.encrypted = bool(enc and enc.get("in_current_trailer"))
    if pdf.encrypted and pdf.unreadable_compressed:
        ctx.problem("%d object(s) live in object streams that could not be read; in an encrypted file the streams are encrypted and no key is tried" % pdf.unreadable_compressed)
    # Catalog
    catalog, cnum = (pdf.deref(trailer.get("Root")) if trailer else (None, None))
    if not isinstance(catalog, dict):
        cat = next(((n, o) for n, o in ((n, pdf.again(n, kept)) for n, kept in interesting.items()) if o is not None and isinstance(o.value, dict) and o.value.get("Type") == "Catalog"), None)
        if cat:
            catalog, cnum = cat[1].value, cat[0]
            anomalies.append("the trailer's /Root does not lead to a catalog; the catalog found is object %d" % cnum)
    findings = trace_catalog(pdf, ctx, catalog, cnum, interesting, extractor, outside)
    out.update(findings)
    out["anomalies"] = anomalies
    if extractor is not None:
        for kind in ("pdf", "pdf-raw"):
            for arg in extractor.wanted_args(kind):
                try:
                    o = pdf.get(int(arg))
                except Over as exc:
                    ctx.limit_hit("extract %s:%s: %s" % (kind, arg, exc))
                    continue
                if o is None or o.stream is None:
                    ctx.problem("extract %s:%s: the object is not there or is not a stream" % (kind, arg))
                    continue
                # In an encrypted file a stream is ciphertext (ISO 32000-1 7.6.1) unless it is the cross-reference stream or its crypt filter
                # is the identity: no key is tried, so pdf-raw:<n> writes the encrypted bytes, marked so, and pdf:<n> is not decoded.
                ciphertext = pdf.streams_encrypted and not (isinstance(o.value, dict) and o.value.get("Type") == "XRef") and int(arg) != pdf.encrypt_object
                if kind == "pdf-raw":
                    info = o.stream
                    if info["length"] is None:
                        ctx.problem("extract pdf-raw:%s: the stream's length cannot be established" % arg)
                        continue
                    row = extractor.write(kind, arg, "object %s" % arg, pdf_slices(blob, info["start"], info["length"], ctx),
                                          "PDF stream bytes, still encoded" + (", and ciphertext: the file is encrypted and no key is tried" if ciphertext else ""))
                    if ciphertext:
                        row["ciphertext"] = True
                elif ciphertext:
                    ctx.problem("extract pdf:%s: the file is encrypted and no key is tried, so the stream is ciphertext and is not decoded; pdf-raw:%s writes its encrypted bytes" % (arg, arg))
                    extractor.tried(kind, arg)
                else:
                    try:
                        data = pdf.decode(o)
                    except (PdfError, Over) as exc:
                        (ctx.limit_hit if isinstance(exc, Over) else ctx.problem)("extract pdf:%s: %s" % (arg, exc))
                        extractor.tried(kind, arg)
                        continue
                    extractor.write(kind, arg, "object %s" % arg, data, "PDF stream, filters undone")
    out["coverage"] = {"structures_read": PDF_READ, "structures_not_read": PDF_NOT_READ}
    return out


def pdf_slices(blob, start, length, ctx):
    ctx.spend(length, "a stream")
    pos = start
    end = start + length
    while pos < end:
        yield bytes(blob[pos:min(end, pos + PAGE)])
        pos += PAGE


def filespec_info(pdf, ctx, spec):
    """Name and embedded stream of a file specification dictionary (or a bare file name string)."""
    d, _n = pdf.deref(spec)
    info = {}
    if isinstance(d, PStr):
        info["name"] = d
        return info
    if not isinstance(d, dict):
        return info
    for key in ("UF", "F", "DOS", "Mac", "Unix"):
        v, _ = pdf.deref(d.get(key))
        if isinstance(v, PStr):
            info["name"] = v
            break
    ef, _ = pdf.deref(d.get("EF"))
    if isinstance(ef, dict):
        for key in ("F", "UF"):
            if isinstance(ef.get(key), Ref):
                info["stream_object"] = ef[key].num
                break
    return info


def trace_catalog(pdf, ctx, catalog, cnum, interesting, extractor, outside=None):
    """Every action reached from the catalog, with the key that reaches it, and every action object nothing reaches. No walker cuts a
    list: each step is counted against max_objects and the clock (tick), and a depth or a budget reached is a limit, named."""
    out = {"catalog": None}
    actions, embedded, seen_actions, scripts = [], [], set(), []
    values = ctx.values
    page = ctx.page("pdf_actions")
    files = ctx.page("pdf_embedded_files")
    max_depth = pdf.cfg["max_depth"]
    traced = isinstance(catalog, dict)
    if not traced:
        # no catalog to trace from: every action object and embedded file read is still listed below, as reached from no catalog
        ctx.problem("no catalog could be found: actions, pages and embedded files were not traced from one; every action object read is listed, "
                    "with reached_from_catalog false")
        catalog = {}
    keys = sorted(text_of(k, None, "names") for k in catalog)
    if traced:
        out["catalog"] = {"object": cnum, "keys": keys[:40], "keys_total": len(keys)}
    if len(keys) > 40:
        ctx.limit_hit("the catalog holds %d keys: the first 40 (sorted) are listed by name; every key that reaches an action is traced" % len(keys))
    budget = [pdf.cfg["max_objects"]]
    ciphertext = pdf.strings_encrypted

    def tick():
        budget[0] -= 1
        if budget[0] < 0:
            raise Over("the traversal of the document's structures visited max_objects (%d) objects: the rest is not traced" % pdf.cfg["max_objects"])
        if ctx.expired("the structure trace"):
            raise TimeUp("the structure trace stopped at max_seconds")

    def too_deep(what):
        ctx.limit_hit("%s nests deeper than max_depth (%d): what lies below that depth was not traced" % (what, max_depth))

    def string_target(raw, row):
        """A target string: shown withheld where token-shaped; in an encrypted file it is ciphertext, so it is marked, given by length,
        and neither shown nor put in the values file."""
        if ciphertext:
            row["target"] = None
            row["target_length"] = len(raw)
            row["ciphertext"] = True
            return None
        return text_string(raw)

    def held_by(where):
        """A direct action's place as the answer gives it: the number of the object that holds it and the key path in that object."""
        path = []
        while isinstance(where, tuple):
            where, rest = where[0], where[1:]
            path[:0] = [("[%d]" % k) if isinstance(k, int) else "/" + str(k) for k in rest]
        return {"object": where if isinstance(where, int) else None, "path": "".join(path)}

    def describe_action(value, num, trigger, reached=True, extra=None):
        s = value.get("S")
        subtype = text_of(str(s), None, "names") if isinstance(s, Name) else None
        finding = ctx.next_finding("A")
        row = {"finding_id": finding, "object": num, "action": subtype, "trigger": trigger, "reached_from_catalog": reached}
        if extra:
            row.update(extra)
        if subtype == "JavaScript" or "JS" in value:
            js, jnum = pdf.deref(value.get("JS"))
            o = pdf.get(value["JS"].num) if isinstance(value.get("JS"), Ref) else None
            if o is not None and o.stream is not None:
                row["script"] = {"form": "stream", "object": value["JS"].num, "stream_bytes": o.stream["length"]}
                if pdf.streams_encrypted:
                    row["script"]["ciphertext"] = True
                scripts.append(("stream", o, value["JS"].num))
            elif isinstance(js, PStr):
                row["script"] = {"form": "string", "bytes": len(js)}
                if ciphertext:
                    row["script"]["ciphertext"] = True
                scripts.append(("string", js, num))
            else:
                row["script"] = {"form": "not found"}
        target_value = None
        if subtype == "URI":
            u, _ = pdf.deref(value.get("URI"))
            if isinstance(u, PStr):
                text = string_target(u, row)
                if text is not None:
                    row["target"] = shown_target(text)
                    row["target_length"] = len(text)
                    target_value = text
        elif subtype in ("Launch", "GoToR", "GoToE", "SubmitForm", "ImportData"):
            fs = filespec_info(pdf, ctx, value.get("F"))
            if "name" in fs:
                text = string_target(fs["name"], row)
                if text is not None:
                    row["target"] = shown_target(text)
                    row["target_length"] = len(text)
                    target_value = text
            win, _ = pdf.deref(value.get("Win"))
            if isinstance(win, dict):
                row["windows_launch"] = {k: (len(win[k]) if isinstance(win.get(k), PStr) else None) for k in ("F", "D", "O", "P") if k in win}
                row["windows_launch_note"] = "the lengths of the file, directory, operation and parameter strings of a Launch action's Win dictionary; their text is not reported"
        elif subtype == "Named":
            n = value.get("N")
            if isinstance(n, Name):
                row["name"] = text_of(str(n), None, "names")
        nxt, _ = pdf.deref(value.get("Next"))
        if nxt is not None:
            row["has_next"] = True
        if target_value is not None:
            values.add(finding, {"object": num, "trigger": trigger}, target_value)
        page.add(row)
        actions.append(row)
        return row

    def act(x, trigger, where):
        """x is an action dictionary, a reference to one, or a destination (an array / a name / a string); /Next actions follow,
        iteratively, to max_depth. `where` is the place x sits: the number of the object that holds it (or, for one inside direct
        structures, their path) and the key. An action object is known by its number and a direct action by that place, never by the
        identity of a Python object (the object cache is cleared and reused, and a freed dictionary's identity is given to the next).
        One chain visits each action once: an action a /Next link leads back to (one of the actions before it in the chain) is a
        cycle, one that two /Next links reach is reached twice; each is said once and followed once, so a self-loop is one row."""
        stack = [(x, 0, where, None)]
        chain_seen = set()
        while stack:
            x, depth, where, parent = stack.pop()
            # the key that reaches the chain, and how many /Next links in it this action is: a trigger is never a growing path
            trig = trigger if not depth else trigger + "/Next" if depth == 1 else "%s/Next[%d]" % (trigger, depth)
            if depth > max_depth:
                too_deep("an action's /Next chain")
                continue
            tick()
            num = x.num if isinstance(x, Ref) else None
            d, n2 = pdf.deref(x)
            if isinstance(d, dict) and (is_action(d) or "S" in d or "JS" in d):
                ident = num if num is not None else n2
                mark = ident if ident is not None else ("direct",) + where
                if mark in chain_seen:
                    up, back = parent, False
                    while up is not None and not back:
                        back, up = up[0] == mark, up[1]
                    what = "object %d" % ident if ident is not None else "a direct action"
                    ctx.problem(("the /Next chain reached from %s returns to %s: a cycle, followed once" if back else
                                 "the /Next chain reached from %s reaches %s by two /Next links: it is listed once") % (trigger, what))
                    continue
                chain_seen.add(mark)
                key = (mark, trig)
                if key in seen_actions:
                    continue
                seen_actions.add(key)
                describe_action(d, ident, trig, extra=None if ident is not None else {"held_by": held_by(where)})
                here = ident if ident is not None else where
                link = (mark, parent)
                nxt, _ = pdf.deref(d.get("Next")) if isinstance(d.get("Next"), Ref) else (d.get("Next"), None)
                if isinstance(nxt, list):
                    for i in range(len(nxt) - 1, -1, -1):
                        stack.append((nxt[i], depth + 1, (here, "Next", i), link))
                elif nxt is not None:
                    stack.append((d.get("Next"), depth + 1, (here, "Next"), link))
            elif isinstance(d, (list, Name, PStr)):
                out.setdefault("destinations_seen", 0)
                out["destinations_seen"] += 1

    def aa(x, trigger, where):
        d, n = pdf.deref(x)
        if isinstance(d, dict):
            here = n if n is not None else where
            for k, v in list(d.items()):
                act(v, "%s/AA/%s" % (trigger, text_of(k, None, "names")), (here, "AA", k))

    def walk_name_tree(root, label, visit_leaf, where):
        seen = set()
        stack = [(root, 0, where)]
        while stack:
            node, dp, where = stack.pop()
            tick()
            d, n = pdf.deref(node)
            here = n if n is not None else where
            if not isinstance(d, dict) or (n is not None and n in seen):
                continue
            if dp > max_depth:
                too_deep("the %s name tree" % label)
                continue
            if n is not None:
                seen.add(n)
            names, _ = pdf.deref(d.get("Names"))
            if isinstance(names, list):
                if len(names) % 2:
                    ctx.problem("a node of the %s name tree holds an odd number of entries (%d): the last has no value" % (label, len(names)))
                for i in range(0, len(names) - 1, 2):
                    tick()
                    key, _k = pdf.deref(names[i])
                    visit_leaf(key if isinstance(key, PStr) else None, names[i + 1], (here, "Names", i + 1))
            kids, _ = pdf.deref(d.get("Kids"))
            if isinstance(kids, list):
                for i in range(len(kids) - 1, -1, -1):
                    stack.append((kids[i], dp + 1, (here, "Kids", i)))

    def leaf_label(key):
        if key is None:
            return "?"
        if ciphertext:
            return "ciphertext, %d bytes" % len(key)
        return cell(shown_name(text_string(key)))

    def embedded_row(row):
        embedded.append(row)
        files.add(row)

    try:
        # Catalog level: OpenAction, AA, names, form.
        if "OpenAction" in catalog:
            act(catalog["OpenAction"], "Catalog/OpenAction", (cnum, "OpenAction"))
        if "AA" in catalog:
            aa(catalog["AA"], "Catalog", (cnum, "AA"))
        names, _ = pdf.deref(catalog.get("Names"))
        if isinstance(names, dict):
            if "JavaScript" in names:
                walk_name_tree(names["JavaScript"], "JavaScript", lambda key, val, where: act(val, "Catalog/Names/JavaScript[%s]" % leaf_label(key), where),
                               (cnum, "Names", "JavaScript"))
            if "EmbeddedFiles" in names:
                def leaf(key, val, _where):
                    fs = filespec_info(pdf, ctx, val)
                    row = {"source": "Catalog/Names/EmbeddedFiles"}
                    if "name" in fs:
                        if ciphertext:
                            row.update({"name": None, "name_length": len(fs["name"]), "ciphertext": True})
                        else:
                            row["name"] = cell(member_name(text_string(fs["name"]), ctx, "pdf_filespec_name"))
                    if "stream_object" in fs:
                        o = pdf.get(fs["stream_object"])
                        row["stream_object"] = fs["stream_object"]
                        if o is not None and o.stream is not None:
                            row["stream_bytes"] = o.stream["length"]
                            row["filters"] = [text_of(n, None, "names") for n, _p in pdf.filters_of(o.value)]
                    embedded_row(row)
                walk_name_tree(names["EmbeddedFiles"], "EmbeddedFiles", leaf, (cnum, "Names", "EmbeddedFiles"))
        form, _ = pdf.deref(catalog.get("AcroForm"))
        if isinstance(form, dict):
            out["acroform"] = {"fields_root": isinstance(form.get("Fields"), (Ref, list)), "xfa_present": "XFA" in form, "need_appearances": form.get("NeedAppearances") if isinstance(form.get("NeedAppearances"), bool) else None}
            fields, _ = pdf.deref(form.get("Fields"))
            fields = fields if isinstance(fields, list) else []
            stack = [(fields[i], 0, (cnum, "AcroForm", "Fields", i)) for i in range(len(fields) - 1, -1, -1)]
            fseen, nfields = set(), 0
            while stack:
                f, dp, where = stack.pop()
                tick()
                d, n = pdf.deref(f)
                here = n if n is not None else where
                if not isinstance(d, dict) or (n is not None and n in fseen):
                    continue
                if dp > max_depth:
                    too_deep("the form field tree")
                    continue
                if n is not None:
                    fseen.add(n)
                nfields += 1
                if "A" in d:
                    act(d["A"], "AcroForm/Field/A", (here, "A"))
                if "AA" in d:
                    aa(d["AA"], "AcroForm/Field", (here, "AA"))
                kids, _ = pdf.deref(d.get("Kids"))
                if isinstance(kids, list):
                    stack.extend((kids[i], dp + 1, (here, "Kids", i)) for i in range(len(kids) - 1, -1, -1))
            out["acroform"]["fields_traversed"] = nfields
        # Outlines
        outl, _ = pdf.deref(catalog.get("Outlines"))
        if isinstance(outl, dict):
            stack, oseen, n_items = [(outl.get("First"), ("outline", "First"))], set(), 0
            while stack:
                item, where = stack.pop()
                tick()
                d, n = pdf.deref(item)
                here = n if n is not None else where
                if isinstance(d, dict) and n is not None and n in oseen:
                    ctx.problem("the outline returns to object %d: a cycle, followed once" % n)
                    continue
                if not isinstance(d, dict):
                    continue
                if n is not None:
                    oseen.add(n)
                n_items += 1
                if "A" in d:
                    act(d["A"], "Outlines/Item/A", (here, "A"))
                stack.append((d.get("Next"), (here, "Next")))
                stack.append((d.get("First"), (here, "First")))
            out["outline_items"] = n_items
        # Pages
        pages, _ = pdf.deref(catalog.get("Pages"))
        leaves, declared, pseen = 0, None, set()
        annot_types = KeyedCounts()
        if isinstance(pages, dict):
            declared = pages.get("Count") if isinstance(pages.get("Count"), int) else None
            stack = [(catalog.get("Pages"), 0, (cnum, "Pages"))]
            while stack:
                node, dp, where = stack.pop()
                tick()
                d, n = pdf.deref(node)
                here = n if n is not None else where
                if not isinstance(d, dict) or (n is not None and n in pseen):
                    if isinstance(d, dict) and n in pseen:
                        ctx.problem("the page tree returns to object %d: a cycle" % n)
                    continue
                if dp > max_depth:
                    too_deep("the page tree")
                    continue
                if n is not None:
                    pseen.add(n)
                kids, _ = pdf.deref(d.get("Kids"))
                if isinstance(kids, list) and d.get("Type") != "Page":
                    stack.extend((kids[i], dp + 1, (here, "Kids", i)) for i in range(len(kids) - 1, -1, -1))
                    continue
                leaves += 1
                if "AA" in d:
                    aa(d["AA"], "Page", (here, "AA"))
                an, an_num = pdf.deref(d.get("Annots"))
                if isinstance(an, list):
                    for i, a in enumerate(an):
                        tick()
                        ad, anum = pdf.deref(a)
                        # a direct annotation's place is the array that holds it: an /Annots array two pages share is one place
                        ahere = anum if anum is not None else (an_num, i) if an_num is not None else (here, "Annots", i)
                        if not isinstance(ad, dict):
                            continue
                        st = ad.get("Subtype")
                        key = text_of(str(st), None, "names") if isinstance(st, Name) else "?"
                        annot_types.add(st if isinstance(st, Name) else LongName("?"))
                        if "A" in ad:
                            act(ad["A"], "Page/Annot[%s]/A" % key, (ahere, "A"))
                        if "AA" in ad:
                            aa(ad["AA"], "Page/Annot[%s]" % key, (ahere, "AA"))
        out["pages"] = {"declared_count_in_root_pages_node": declared, "leaf_nodes_traversed": leaves,
                        "note": "the declared count is what the root node says; the traversed count is the leaves reached from it. Neither is a verified page count"}
        out["annotation_subtypes"] = annot_types.counts
    except Over as exc:
        ctx.limit_hit(str(exc))
    # Objects that are actions or hold scripts and were not reached from the catalog.
    reached_nums = {a["object"] for a in actions}
    unreached = 0
    listed = {e.get("stream_object") for e in embedded}
    outside_counts = {"freed": 0, "absent": 0}
    try:
        # Objects whose header is in the file and that the newest cross-reference chain does not use: an action among them is listed,
        # with outside_chain saying which, and is a problem of the answer (a freed JavaScript action is not a clean result).
        for k, (num, (how, off)) in enumerate(sorted((outside or {}).items())):
            if ctx.expired("the objects outside the cross-reference chain"):
                break
            tick()
            try:
                o = pdf.read_indirect(off, None)
            except PdfError:
                continue
            if isinstance(o.value, dict) and is_action(o.value):
                outside_counts[how] += 1
                describe_action(o.value, num, None, reached=False, extra={"outside_chain": how})
    except Over as exc:
        ctx.limit_hit(str(exc))
    if outside_counts["freed"] or outside_counts["absent"]:
        ctx.problem("%d action dictionar%s in objects the newest cross-reference chain does not use (%d freed by the newest section that names them, %d with no entry): "
                    "a reader that follows the chain does not see them, one that rebuilds the file by scanning may; each is a row with outside_chain"
                    % (outside_counts["freed"] + outside_counts["absent"], "y is" if outside_counts["freed"] + outside_counts["absent"] == 1 else "ies are",
                       outside_counts["freed"], outside_counts["absent"]))
    try:
        for k, (num, kept) in enumerate(interesting.items()):
            if not (k + 1) & 1023 and ctx.expired("the objects no key reaches"):
                break
            o = pdf.again(num, kept)
            if o is None:
                continue
            if isinstance(o.value, dict) and is_action(o.value) and num not in reached_nums:
                unreached += 1
                describe_action(o.value, num, None, reached=False)
            elif isinstance(o.value, dict) and o.value.get("Type") == "EmbeddedFile":
                if num not in listed:
                    listed.add(num)
                    embedded_row({"source": "an EmbeddedFile stream no file specification reached", "stream_object": num, "stream_bytes": o.stream["length"] if o.stream else None,
                                  "filters": [text_of(n, None, "names") for n, _p in pdf.filters_of(o.value)]})
        # File specifications that name an embedded stream but sit outside the name tree.
        for k, (num, kept) in enumerate(interesting.items()):
            if not (k + 1) & 1023 and ctx.expired("the file specifications no key reaches"):
                break
            o = pdf.again(num, kept)
            if o is not None and isinstance(o.value, dict) and "EF" in o.value:
                fs = filespec_info(pdf, ctx, Ref(num, 0))
                if "stream_object" in fs and fs["stream_object"] not in listed:
                    emb = {"source": "a file specification (object %d)" % num, "stream_object": fs["stream_object"]}
                    if "name" in fs:
                        if ciphertext:
                            emb.update({"name": None, "name_length": len(fs["name"]), "ciphertext": True})
                        else:
                            emb["name"] = cell(shown_name(text_string(fs["name"])))
                    listed.add(fs["stream_object"])
                    embedded_row(emb)
    except Over as exc:
        ctx.limit_hit(str(exc))
    counts = {}
    for a in actions:
        counts[a["action"] or "?"] = counts.get(a["action"] or "?", 0) + 1
    out["actions"] = {"count": len(actions), "by_type": counts, "unreached_from_catalog": unreached, "outside_chain": outside_counts, "table": "pdf_actions", "traced": traced,
                      "note": "an action dictionary and the key that reaches it are different facts: a trigger is where the reader is asked to run it, and whether it runs depends on the reader"}
    if ciphertext:
        out["actions"]["ciphertext_note"] = ("the file is encrypted and no key is tried: the action dictionaries of objects outside object streams are read, and every target string "
                                             "they hold is ciphertext, marked ciphertext: true and given by length only")
    out["embedded_files"] = embedded[:200]
    out["embedded_files_table"] = "pdf_embedded_files"
    if len(embedded) > 200:
        ctx.limit_hit("%d embedded files were found: the first 200 are in the answer's embedded_files, and every one is in the pdf_embedded_files table" % len(embedded))
    if extractor is not None and extractor.wants("javascript"):
        for i, (form, src, ref) in enumerate(scripts, 1):
            if form == "string":
                extractor.write("javascript", "", "script %d (string, action object %s)" % (i, ref), bytes(src), "PDF JavaScript string" + (", ciphertext" if ciphertext else ""))
            elif pdf.streams_encrypted:
                ctx.problem("script %d (stream object %s) was not extracted: the file is encrypted and no key is tried, so the stream is ciphertext; pdf-raw:%s writes its encrypted bytes" % (i, ref, ref))
                extractor.tried("javascript")
            else:
                try:
                    data = pdf.decode(src)
                except PdfError as exc:
                    ctx.problem("script %d (stream object %s) was not extracted: %s" % (i, ref, exc))
                    extractor.tried("javascript")
                    continue
                except Over as exc:
                    ctx.limit_hit("script %d (stream object %s) was not extracted: %s" % (i, ref, exc))
                    extractor.tried("javascript")
                    continue
                extractor.write("javascript", "", "script %d (stream object %s)" % (i, ref), data, "PDF JavaScript stream, filters undone")
        if not scripts:
            for sel in extractor.selectors:
                if sel["kind"] == "javascript":
                    sel["matched"] += 1
    return out


# --- RTF -------------------------------------------------------------------------------------------------------------------

RTF_READ = ["group structure: nesting depth, brace balance, the bytes after the last group", "control words and destinations, counted",
            "object groups: the object kind, class name, the length of the hex-encoded data, the signature its decoded data begins with (named, never printed) and the OLE 1.0 object header",
            "fields (the field type the instruction begins with, when it is one of the ECMA-376 field types), templates and data stores, by length, each a row of a table; a nested compound file inside object data is read as one"]
RTF_NOT_READ = ["text, formatting, tables, styles and pictures", "the meaning of an embedded object: its payload is listed, not opened",
                "fields' instruction text and template paths, beyond the field type and the length (the whole is in the values file only when write_values is asked for in a secret_output job)",
                "the bytes of an object's data: the answer names the signature it begins with and prints none of it"]
RTF_TOKEN = re.compile(rb"\\([A-Za-z]{1,32})(-?[0-9]{1,10})? ?|\\'[0-9A-Fa-f]{2}|\\[^A-Za-z]|[{}]")
RTF_OBJECT_KINDS = ("objemb", "objlink", "objautlink", "objsub", "objpub", "objicemb", "objhtml", "objocx")
RTF_WATCH = ("objupdate", "objautlink", "objlink", "objemb", "objhtml", "objocx", "objsetsize", "datastore", "template", "fldinst", "field", "pict", "bin", "objdata", "objclass", "objname",
             "result", "listoverridetable", "mmath", "stylesheet", "fonttbl", "colortbl", "info", "rsidtbl", "falt", "upr", "ud", "ansicpg", "mac", "pc", "pca", "ansi")
MAX_WORDS = 5000
MAX_RTF_OBJECTS = 20000
MAX_FIELDS = 20000
MAX_TEMPLATES = 2000
HEXDIGITS = b"0123456789abcdefABCDEF"
CAPTURE_LIMIT = 4096                # bytes of a class or object name kept; a field instruction or a template is kept to max_stream_bytes
# The field types of ECMA-376 Part 1, 17.16.5, and the older ones Word still reads ([MS-DOC] 2.9.90): the first word of a field
# instruction is printed only when it is one of these, so that an instruction that begins with something else (a key, a path)
# never has a slice of it in the answer.
FIELD_WORDS = frozenset("""ADDIN ADDRESSBLOCK ADVANCE ASK AUTHOR AUTONUM AUTONUMLGL AUTONUMOUT AUTOTEXT AUTOTEXTLIST BARCODE BIBLIOGRAPHY BIDIOUTLINE
    CITATION COMMENTS COMPARE CONTROL CREATEDATE DATA DATABASE DATE DDE DDEAUTO DISPLAYBARCODE DOCPROPERTY DOCVARIABLE EDITTIME EMBED EQ FILENAME
    FILESIZE FILLIN FORMCHECKBOX FORMDROPDOWN FORMTEXT GLOSSARY GOTOBUTTON GREETINGLINE HTMLCONTROL HYPERLINK IF IMPORT INCLUDE INCLUDEPICTURE
    INCLUDETEXT INDEX INFO KEYWORDS LASTSAVEDBY LINK LISTNUM MACROBUTTON MERGEBARCODE MERGEFIELD MERGEREC MERGESEQ NEXT NEXTIF NOTEREF NUMCHARS
    NUMPAGES NUMWORDS PAGE PAGEREF PRINT PRINTDATE PRIVATE QUOTE RD REF REVNUM SAVEDATE SECTION SECTIONPAGES SEQ SET SHAPE SKIPIF STYLEREF SUBJECT
    SYMBOL TA TC TEMPLATE TIME TITLE TOA TOC USERADDRESS USERINITIALS USERNAME XE""".split())
# The signatures an object's decoded data may begin with, by name: the answer names one of these and prints no byte of the data.
DATA_SIGNATURES = ((b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE compound file"), (b"\x01\x05\x00\x00", "OLE 1.0 ObjectHeader (version 0x00000501)"),
                   (b"PK\x03\x04", "ZIP local file header"), (b"MZ", "MZ executable header"), (b"%PDF-", "PDF header"), (b"{\\rt", "RTF header"),
                   (b"\x89PNG", "PNG image"), (b"\xff\xd8\xff", "JPEG image"), (b"GIF8", "GIF image"), (b"\x7fELF", "ELF header"))


def field_word(clean):
    """The field type an instruction begins with, upper-cased, when it is one this tool names; '=' for a formula; None otherwise."""
    m = re.match(r"[\s{}]*([A-Za-z]{1,20})(?![A-Za-z])", clean)
    if m and m.group(1).upper() in FIELD_WORDS:
        return m.group(1).upper()
    if re.match(r"[\s{}]*=", clean):
        return "="
    return None


def data_signature(raw):
    return next((name for magic, name in DATA_SIGNATURES if raw.startswith(magic)), None)


def hex_decode_range(blob, start, end, limit, ctx=None):
    """The bytes encoded as hex digits in blob[start:end], white space ignored, read in pieces. Returns (bytes, non_hex_count, truncated):
    at most `limit` bytes are kept, and `truncated` says the range held more. The clock is read for every piece."""
    out, nonhex, pos, truncated, carry = bytearray(), 0, start, False, b""
    while pos < end:
        if ctx is not None:
            ctx.tick()
        piece = carry + blob[pos:min(end, pos + (1 << 20))].translate(None, b" \t\r\n")
        pos += 1 << 20
        bad = piece.translate(None, HEXDIGITS)
        if bad:
            nonhex += len(bad)
            piece = piece.translate(None, bytes(set(bad)))
        usable = len(piece) // 2 * 2
        out += bytes.fromhex(piece[:usable].decode("ascii"))
        carry = piece[usable:]
        if len(out) > limit:
            truncated = True
            del out[limit:]
            break
    return bytes(out), nonhex, truncated


def count_hex(blob, start, end, ctx=None):
    """(hex digits, other bytes) in blob[start:end], white space ignored, counted in pieces; the clock is read for every piece."""
    digits = other = pos = 0
    pos = start
    while pos < end:
        if ctx is not None:
            ctx.tick()
        piece = blob[pos:min(end, pos + (1 << 20))].translate(None, b" \t\r\n")
        pos += 1 << 20
        good = len(piece.translate(None, bytes(set(piece.translate(None, HEXDIGITS)))))
        digits += good
        other += len(piece) - good
    return digits, other


def ole1_header(raw):
    """MS-OLEDS 2.2.4 ObjectHeader: version, format, then three length-prefixed ANSI strings and the native data size."""
    if len(raw) < 12:
        return None
    version, fmt = struct.unpack_from("<II", raw, 0)
    if version != 0x00000501:
        return None
    pos, names, utf16 = 8, [], False
    for k in range(3):
        if pos + 4 > len(raw):
            return {"ole_version": "0x%08X" % version, "format_id": fmt, "header_truncated": True}
        n = struct.unpack_from("<I", raw, pos)[0]
        pos += 4
        if n > 4096 or pos + n > len(raw):
            return {"ole_version": "0x%08X" % version, "format_id": fmt, "header_truncated": True}
        field = raw[pos:pos + n].rstrip(b"\x00")
        # the strings are ANSI; one whose every other byte is NUL is UTF-16LE written there, read as such (as 8-bit text, its NULs
        # would sit between the characters of whatever it spells)
        if len(field) >= 3 and not any(field[1::2]) and all(field[0::2]):
            names.append((field + b"\x00").decode("utf-16-le"))
            utf16 = utf16 or k == 0
        else:
            names.append(field.decode("latin-1"))
        pos += n
    native = struct.unpack_from("<I", raw, pos)[0] if pos + 4 <= len(raw) else None
    out = {"ole_version": "0x%08X" % version, "format_id": fmt, "format": {1: "linked", 2: "embedded"}.get(fmt, "other"), "class_name": names[0],
           "native_data_bytes": native, "native_data_offset": pos + 4}
    if utf16:
        out["class_name_encoding"] = "UTF-16LE in a field MS-OLEDS 2.2.4 makes an ANSI string"
    return out


MAX_CAPTURES = 8                    # field instructions and templates open inside one another that are each kept as a row


def rtf_word(name):
    """A control word as the answer may name it. The RTF specification makes a control word of lowercase letters a to z: a word with a
    capital letter is not one a reader defines, and its letters are the file's text (the head of a key split by a digit, `\\AKIA...`),
    so it is counted and never printed. (`name` is letters only: the tokenizer reads [A-Za-z]{1,32}.)"""
    return name if name.islower() else None


def probe_rtf(blob, ctx, extractor):
    """The RTF answer. A budget or the clock reached anywhere in it is a limit, and the answer keeps what was read before it."""
    out = {"container": "RTF"}
    try:
        _probe_rtf(blob, ctx, extractor, out)
    except Over as exc:
        ctx.limit_hit("%s; the RTF answer holds what was read before it" % exc)
    out.setdefault("coverage", {"structures_read": RTF_READ, "structures_not_read": RTF_NOT_READ})
    return out


def _probe_rtf(blob, ctx, extractor, out):
    cfg = ctx.cfg
    max_depth = cfg["max_depth"]
    size = len(blob)
    head = blob[:HEAD_BYTES]
    start = head.find(b"{\\rt")
    out["rtf_header_offset"] = start
    m = re.match(rb"\{\\(rt[A-Za-z]*)(-?[0-9]{0,10})", head[start:])
    letters = m.group(1).decode("ascii") if m else "rt"
    word_ok = rtf_word(letters) is not None
    out["rtf_version_word"] = (letters + m.group(2).decode("ascii")) if m and word_ok else None
    if m and not word_ok:
        out["rtf_header_word"] = {"letters": len(letters), "note": "the word after {\\ holds a capital letter: it is not an RTF control word, and it is not printed"}
    if start > 0:
        ctx.problem("the {\\rtf header starts at offset %d, after %d byte(s) a reader may skip" % (start, start))
    if letters != "rtf":
        ctx.problem("the header is {\\%s, not {\\rtf: Word opens a file that begins with {\\rt as RTF, and a strict reader does not"
                    % (letters if word_ok else "rt and %d more letters" % (len(letters) - 2)))
    words, other_words, symbols, destinations = {}, 0, 0, {}
    odd_words = {"occurrences": 0, "distinct": set()}   # control words with a capital letter: counted, never printed
    stack = []                      # (destination name, ignorable, start offset) of each open group
    over = 0
    depth = max_depth_seen = groups = 0
    skip_until = 0
    unbalanced_close = 0
    objects, fields, templates, stores = [], [], [], 0
    fields_over = [0, 0]
    captures = []                   # the open captures, innermost last: [kind, buffer, group depth at start, owner, offset, bytes seen, cut, nested]
    captures_not_kept = [0]         # field instructions or templates opened inside MAX_CAPTURES others: counted, not kept
    kept = [0, 0]                   # bytes kept in captures, captures cut
    cur_obj_stack = []              # indexes into objects of the open \object groups
    uc, uc_skip = [1], [0]          # the \uc count in force, and the fallback characters after a \uN still to drop
    last_end = 0
    pos_after_last_close = None
    tokens = 0
    expired = False
    bin_blocks, bin_bytes = 0, 0

    def room(cap):
        bound = CAPTURE_LIMIT if cap[0] in ("objclass", "objname") else cfg["max_stream_bytes"]
        return max(0, min(bound - len(cap[1]) // 2, cfg["max_total_bytes"] - kept[0]))

    def keep(piece):
        """Add text between two tokens (or a decoded symbol) to every open text capture, each as far as its bound goes: what is past it is
        counted, and the capture is marked cut. A capture inside object data keeps nothing (the data is hex, not text). A capture holds
        characters (as UTF-16LE): a byte of the file is the character of that code (ISO 8859-1), a \\uN control word the character N, and
        the fallback characters after a \\uN (\\ucN of them, 1 by default) are dropped, as a reader of Unicode RTF drops them."""
        if isinstance(piece, (bytes, bytearray)):
            piece = piece.decode("latin-1")
        if uc_skip[0] and piece:
            drop = min(uc_skip[0], len(piece))
            uc_skip[0] -= drop
            piece = piece[drop:]
        if not captures or any(c[0] == "objdata" for c in captures):
            return
        for cap in captures:
            cap[5] += len(piece)
            r = room(cap)
            if len(piece) > r:
                cap[6] = True
            take = min(len(piece), r)
            if take:
                cap[1] += piece[:take].encode("utf-16-le", "surrogatepass")
                kept[0] += take

    def text_between(a, b):
        # RTF readers ignore a carriage return and a line feed in the text (they break lines of the file, not of the document): a class
        # name, a field type or a key split by a line break is read as one, before it is matched or withheld.
        return blob[a:b].translate(None, b"\r\n")

    def finish_capture():
        kind, buf, _d, owner, off, seen, cut, nested = captures.pop()
        text = bytes(buf).decode("utf-16-le", "surrogatepass")
        kept[1] += 1 if cut else 0
        if kind == "objclass" and owner is not None:
            objects[owner]["class_name_raw"] = text.strip()
            objects[owner]["class_name_cut"] = cut
        elif kind == "objname" and owner is not None:
            objects[owner]["name_raw"] = text.strip()
            objects[owner]["name_cut"] = cut
        elif kind == "fldinst":
            if len(fields) < MAX_FIELDS:
                fields.append((text, off, seen, cut, nested))
            else:
                fields_over[0] += 1
        elif kind == "template":
            if len(templates) < MAX_TEMPLATES:
                templates.append((text, off, seen, cut, nested))
            else:
                fields_over[1] += 1

    for tok in RTF_TOKEN.finditer(blob):
        tokens += 1
        if tokens % 8192 == 0 and ctx.expired("the RTF scan"):
            expired = True
            break
        s = tok.start()
        if s < skip_until:
            continue
        gap_start, last_end = last_end, tok.end()
        if captures and s > gap_start and captures[-1][0] != "objdata":
            keep(text_between(gap_start, s))
        lead = tok.group()[:1]
        if lead == b"{":
            groups += 1
            depth += 1
            uc_skip[0] = 0
            max_depth_seen = max(max_depth_seen, depth)
            if len(stack) < max_depth:
                stack.append([None, False, s, uc[0]])
            else:
                over += 1
            continue
        if lead == b"}":
            if depth == 0:
                unbalanced_close += 1
                continue
            depth -= 1
            uc_skip[0] = 0
            if over:
                over -= 1
            else:
                dest, _ign, gs, uc[0] = stack.pop()
                if captures and captures[-1][2] == len(stack) + 1:
                    if captures[-1][0] == "objdata":
                        objects[captures[-1][3]]["data_end"] = s
                    finish_capture()
                if dest == "object" and cur_obj_stack:
                    cur_obj_stack.pop()
            if depth == 0:
                pos_after_last_close = tok.end()
            continue
        word = tok.group(1)
        if word is None:
            symbols += 1
            if captures:
                sym = tok.group()
                if sym in (b"\\\\", b"\\{", b"\\}"):
                    keep(sym[1:2])
                elif sym[:2] == b"\\'":
                    keep(bytes.fromhex(sym[2:4].decode("ascii")))
            elif uc_skip[0] and tok.group()[:2] == b"\\'":
                uc_skip[0] -= 1
            if tok.group()[:2] == b"\\*" and stack:
                stack[-1][1] = True
            continue
        name = word.decode("ascii")
        param = int(tok.group(2)) if tok.group(2) else None
        if name == "uc" and param is not None:
            uc[0] = max(0, min(param, 16))
        elif name == "u" and param is not None:
            uc_skip[0] = 0
            keep(chr((param + 65536 if param < 0 else param) & 0xFFFF))
            uc_skip[0] = uc[0]
        else:
            uc_skip[0] = 0
        if rtf_word(name) is None:
            odd_words["occurrences"] += 1
            if len(odd_words["distinct"]) < MAX_WORDS:
                odd_words["distinct"].add(name)
        elif name in words or len(words) < MAX_WORDS:
            words[name] = words.get(name, 0) + 1
        else:
            other_words += 1
        if stack and stack[-1][0] is None and not over:
            stack[-1][0] = name
            if rtf_word(name) is not None and (name in destinations or len(destinations) < MAX_WORDS):
                destinations[name] = destinations.get(name, 0) + 1
            text_open = sum(1 for c in captures if c[0] in ("fldinst", "template"))
            if name == "object" and len(objects) < MAX_RTF_OBJECTS:
                objects.append({"index": len(objects) + 1, "offset": s, "depth": depth, "kind": None, "flags": []})
                cur_obj_stack.append(len(objects) - 1)
            elif name == "datastore":
                stores += 1
            elif name in ("objclass", "objname") and not captures:
                owner = cur_obj_stack[-1] if cur_obj_stack else None
                captures.append([name, bytearray(), len(stack), owner, s, 0, False, False])
            elif name in ("fldinst", "template") and not any(c[0] in ("objdata", "objclass", "objname") for c in captures):
                # A field inside a field's instruction (a DDEAUTO inside a QUOTE), or inside a template, is a row of its own: each open
                # instruction keeps the text of the groups inside it, so the outer one is read whole and the inner one by itself.
                if text_open >= MAX_CAPTURES:
                    captures_not_kept[0] += 1
                else:
                    captures.append([name, bytearray(), len(stack), None, s, 0, False, text_open > 0])
            elif name == "objdata" and cur_obj_stack and not captures:
                o = objects[cur_obj_stack[-1]]
                o["data_start"] = tok.end()
                captures.append(["objdata", bytearray(), len(stack), cur_obj_stack[-1], s, 0, False, False])
        if cur_obj_stack:
            o = objects[cur_obj_stack[-1]]
            if name in RTF_OBJECT_KINDS and o["kind"] is None:
                o["kind"] = name
            elif name in ("objupdate", "objlock", "objsetsize", "objscalex", "objscaley", "objw", "objh", "objcropt", "objcropb", "objcropl", "objcropr") and name not in o["flags"]:
                o["flags"].append(name)
        if name == "bin" and param is not None and param > 0:
            bin_blocks += 1
            bin_bytes += param
            skip_until = tok.end() + param
            if skip_until > size:
                ctx.problem("a \\bin%d control word at offset %d declares more bytes than the file holds" % (param, s))
    # Close any capture still open, and the bookkeeping at the end of the data.
    while captures:
        if captures[-1][0] == "objdata":
            objects[captures[-1][3]]["data_end"] = size
        finish_capture()
    out["structure"] = {"groups": groups, "max_depth_seen": max_depth_seen, "open_groups_at_end": depth, "close_without_open": unbalanced_close,
                        "depth_over_limit": over > 0 or max_depth_seen > max_depth, "binary_blocks": bin_blocks, "binary_bytes": bin_bytes}
    if depth:
        ctx.problem("the file ends with %d group(s) still open" % depth)
    if unbalanced_close:
        ctx.problem("%d closing brace(s) with no open group" % unbalanced_close)
    if max_depth_seen > max_depth:
        ctx.limit_hit("groups nest to %d, past max_depth (%d): destinations of the groups below that depth were not tracked" % (max_depth_seen, max_depth))
    if expired:
        ctx.limit_hit("the RTF scan stopped at max_seconds: the counts and objects found are lower bounds")
    if captures_not_kept[0]:
        ctx.limit_hit("%d field instruction(s) or template(s) open inside %d others were counted and not kept as rows" % (captures_not_kept[0], MAX_CAPTURES))
    if pos_after_last_close is not None and size - pos_after_last_close > 0:
        tail = blob[pos_after_last_close:]
        stripped = tail.strip(b" \t\r\n\x00")
        if stripped:
            ctx.problem("%d non-whitespace byte(s) follow the last group's closing brace" % len(stripped))
            out["bytes_after_last_group"] = len(stripped)
    top = sorted(words.items(), key=lambda kv: -kv[1])[:40]
    out["control_words"] = {"distinct": len(words), "not_counted_past_limit": other_words, "top": [{"word": w, "count": c} for w, c in top],
                            "watched": {w: words[w] for w in RTF_WATCH if w in words}, "control_symbols": symbols, "table": "rtf_control_words",
                            "with_capital_letters": {"occurrences": odd_words["occurrences"], "distinct": len(odd_words["distinct"]),
                                                     "note": "not RTF control words (the specification's are lowercase): counted, not printed"}}
    out["destinations"] = dict(sorted(destinations.items(), key=lambda kv: -kv[1])[:40])
    out["destinations_distinct"] = len(destinations)
    word_page = ctx.page("rtf_control_words")
    for w, c in sorted(words.items(), key=lambda kv: (-kv[1], kv[0])):
        word_page.add({"word": w, "count": c, "as_destination": destinations.get(w, 0)})
    if len(words) > 40 or len(destinations) > 40:
        out["control_words_note"] = "the 40 most frequent control words and destinations are in the answer; every one is a row of the rtf_control_words table"
    # Objects
    table = ctx.page("rtf_objects")
    rows = []
    out["objects"] = {"count": len(objects), "table": "rtf_objects", "capped": len(objects) >= MAX_RTF_OBJECTS, "first": rows}
    if len(objects) >= MAX_RTF_OBJECTS:
        ctx.limit_hit("the file holds at least %d object groups: the first %d are listed" % (MAX_RTF_OBJECTS, MAX_RTF_OBJECTS))
    for k, o in enumerate(objects):
        if ctx.expired("the RTF objects"):
            out["objects"]["not_examined_at_the_clock"] = len(objects) - k
            break
        row = {"index": o["index"], "offset": o["offset"], "kind": o["kind"], "flags": o["flags"]}
        if "class_name_raw" in o:
            row["class_name"] = text_of(o["class_name_raw"], None, "names")
            if o.get("class_name_cut"):
                row["class_name_cut_at_bytes"] = CAPTURE_LIMIT
        if "name_raw" in o:
            row["object_name"] = text_of(o["name_raw"], None, "names")
            if o.get("name_cut"):
                row["object_name_cut_at_bytes"] = CAPTURE_LIMIT
        if "data_start" in o and "data_end" in o:
            digits, other = count_hex(blob, o["data_start"], o["data_end"], ctx)
            row["data"] = {"offset": o["data_start"], "end_offset": o["data_end"], "hex_digits": digits, "non_hex_bytes": other}
            if other:
                ctx.problem("RTF object %d: %d byte(s) of its data are not hex digits or white space" % (o["index"], other))
            raw, nonhex, trunc = hex_decode_range(blob, o["data_start"], min(o["data_end"], o["data_start"] + 4096 * 4), 4096, ctx)
            # The start of the data is named by its signature, never printed: object data can be anything, a token included.
            row["data"]["decoded_start"] = {"bytes_read": len(raw), "signature": data_signature(raw)}
            hdr = ole1_header(raw)
            if hdr:
                row["ole1_header"] = {k2: (text_of(v, None, "names") if isinstance(v, str) and k2 == "class_name" else v) for k2, v in hdr.items()}
                if hdr.get("header_truncated"):
                    ctx.problem("RTF object %d: its OLE 1.0 ObjectHeader is cut short or declares a name longer than its data: the header is not read whole" % o["index"])
            if digits % 2:
                ctx.problem("RTF object %d: an odd number of hex digits in its data" % o["index"])
            need = digits // 2
            nested_kind = raw[:8] == CFB_MAGIC or bool(hdr and hdr.get("native_data_offset") is not None)
            if nested_kind and need > cfg["max_stream_bytes"]:
                row["nested_compound_file"] = {"status": "over_budget", "bytes": need}
                ctx.limit_hit("RTF object %d: its data is %d bytes, over max_stream_bytes (%d): the object it holds was not read" % (o["index"], need, cfg["max_stream_bytes"]))
            if need <= cfg["max_stream_bytes"] and nested_kind:
                try:
                    full, nonhex2, trunc2 = hex_decode_range(blob, o["data_start"], o["data_end"], cfg["max_stream_bytes"], ctx)
                    ctx.spend(len(full), "an RTF object")
                    payload = full
                    if hdr and hdr.get("native_data_offset") is not None:
                        base = hdr["native_data_offset"]
                        payload = full[base:base + (hdr["native_data_bytes"] or 0)]
                    if payload[:8] == CFB_MAGIC:
                        try:
                            inner, _cfb = probe_ole_blob(payload, ctx, extractor, label="rtf-object-%d" % o["index"])
                            row["nested_compound_file"] = {"bytes": len(payload), "cfb": inner["cfb"], "applications": inner["applications"], "orphan_entries": inner["orphan_entries"],
                                                           "vba_projects": inner.get("vba_projects", []), "encryption_items": inner["encryption_items"], "directory": inner.get("directory")}
                            if "vba_projects_summary" in inner:
                                row["nested_compound_file"]["vba_projects_summary"] = inner["vba_projects_summary"]
                        except CfbError as exc:
                            ctx.problem("RTF object %d: its payload begins like a compound file and is not read as one: %s" % (o["index"], exc))
                    if extractor is not None and extractor.wants("rtf", o["index"]):
                        extractor.write("rtf", o["index"], "rtf object %d" % o["index"], full, "RTF object data, hex decoded")
                except TimeUp:
                    raise
                except Over as exc:
                    ctx.limit_hit("RTF object %d: %s" % (o["index"], exc))
            elif extractor is not None and extractor.wants("rtf", o["index"]):
                try:
                    full, _n, trunc2 = hex_decode_range(blob, o["data_start"], o["data_end"], cfg["max_stream_bytes"], ctx)
                    if trunc2:
                        ctx.limit_hit("RTF object %d: the data is over max_stream_bytes (%d): not extracted" % (o["index"], cfg["max_stream_bytes"]))
                    else:
                        ctx.spend(len(full), "an RTF object")
                        extractor.write("rtf", o["index"], "rtf object %d" % o["index"], full, "RTF object data, hex decoded")
                except TimeUp:
                    raise
                except Over as exc:
                    ctx.limit_hit("RTF object %d: %s" % (o["index"], exc))
        elif o["kind"] or "data_start" in o:
            ctx.problem("RTF object %d: its data group has no end in the bytes read" % o["index"])
        if len(rows) < 20:
            rows.append(row)
        table.add(row)
    # Fields and templates: the field type an instruction begins with when it is one this tool names, the rest by length. Every one is a
    # row of a table (the whole table is in a file when it is longer than `limit`), and every one's whole text is in the values file
    # when write_values is asked for in a job; a text longer than its bound is counted whole and said.
    field_page, field_rows = ctx.page("rtf_fields"), []
    out["fields"] = {"count": len(fields) + fields_over[0], "table": "rtf_fields", "listed": field_rows,
                     "listed_note": "the first 200 fields; every field read is a row of the rtf_fields table, a field inside another's instruction included"}
    for text, off, seen, cut, nested in fields:
        clean = text.strip()
        finding = ctx.next_finding("F")
        row = {"finding_id": finding, "offset": off, "instruction_word": field_word(clean), "instruction_length": len(clean)}
        if nested:
            row["inside_another_instruction"] = True
        if row["instruction_word"] is None:
            row["instruction_word_note"] = "the instruction does not begin with a field type this tool names: its first word is not printed"
        if cut:
            row.update({"instruction_cut": True, "instruction_bytes_in_file": seen})
        field_page.add(row)
        if len(field_rows) < 200:
            field_rows.append(row)
        ctx.values.add(finding, {"kind": "field_instruction", "offset": off, "complete": not cut}, clean)
    if fields_over[0] or fields_over[1]:
        ctx.limit_hit("the file holds more than %d field instructions or %d templates: the rest are counted, not listed and not in the values file" % (MAX_FIELDS, MAX_TEMPLATES))
    tmpl_page, tmpl_rows = ctx.page("rtf_templates"), []
    out["templates"] = tmpl_rows
    out["templates_table"] = "rtf_templates"
    for text, off, seen, cut, nested in templates:
        if ctx.expired("the RTF templates"):
            break
        clean = text.strip()
        finding = ctx.next_finding("T")
        row = {"finding_id": finding, "offset": off, "target": shown_target(clean), "target_length": len(clean)}
        if nested:
            row["inside_another_instruction"] = True
        if cut:
            row.update({"target_cut": True, "target_bytes_in_file": seen})
        tmpl_page.add(row)
        if len(tmpl_rows) < 200:
            tmpl_rows.append(row)
        ctx.values.add(finding, {"kind": "template", "offset": off, "complete": not cut}, clean)
    if len(templates) > 200:
        out["templates_note"] = "the first 200 templates; every template read is a row of the rtf_templates table"
    if kept[1]:
        ctx.limit_hit("%d class name(s), object name(s), field instruction(s) or template(s) are longer than their bound (%d bytes for a name, max_stream_bytes for an "
                      "instruction or a template, max_total_bytes for all together): their length in the file is counted whole, and what is kept (and in the values file) is cut"
                      % (kept[1], CAPTURE_LIMIT))
    out["data_stores"] = stores
    out["coverage"] = {"structures_read": RTF_READ, "structures_not_read": RTF_NOT_READ}


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
    import stat as _stat
    if _stat.S_ISREG(mode):
        return None
    kinds = ((_stat.S_ISDIR, "a directory"), (_stat.S_ISFIFO, "a named pipe"), (_stat.S_ISSOCK, "a socket"), (_stat.S_ISBLK, "a block device"), (_stat.S_ISCHR, "a character device"))
    return "not a regular file (%s)" % next((n for t, n in kinds if t(mode)), "a special file")


HARD_SECONDS = 105                  # the manifest's 120 s less 15: the answer is built and printed after the reading clock, and past this the tool answers that it did not finish
PRINTING = [False]                  # the answer has begun to be written: a signal after that must not write a second one


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


HARD_GRACE = 5                      # seconds the partial answer of the hard limit has, before the failed one
PARTIAL_BUILDING = [False]          # the partial answer of the hard limit is being built
PARTIAL_WRITING = [False]           # and has begun to be written: no other document may follow it


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
    for name in ("SIGINT", "SIGTERM", "SIGHUP"):
        if hasattr(signal, name):
            signal.signal(getattr(signal, name), _stopped_by_signal)
    if hasattr(signal, "setitimer") and hasattr(signal, "SIGALRM"):
        signal.signal(signal.SIGALRM, _hard_limit)
        signal.setitimer(signal.ITIMER_REAL, HARD_SECONDS)


def main():
    install_signal_handlers()
    if sys.version_info[:2] < MIN_PYTHON:
        fail("doc_structure needs Python %d.%d or later (its PDF lexer uses possessive quantifiers, which Python has from 3.11): this is Python %d.%d; "
             "nothing was read" % (MIN_PYTHON + tuple(sys.version_info[:2])), python="%d.%d.%d" % tuple(sys.version_info[:3]))
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    if not isinstance(args, dict):
        fail("arguments must be a JSON object")
    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: a document to read the structure of")
    why_not = file_problem(path)
    if why_not:
        fail(why_not, path=path)
    extract_to = args.get("extract_to")
    if extract_to is not None and (not isinstance(extract_to, str) or not extract_to):
        fail("extract_to must be a non-empty path when supplied")
    selectors = args.get("extract", [])
    if not isinstance(selectors, list) or not all(isinstance(x, str) and x for x in selectors) or len(selectors) > MAX_EXTRACT:
        fail("extract must be a list of at most %d selectors (vba, javascript, ole:<stream path>, zip:<member name>, pdf:<object number>, pdf-raw:<object number>, rtf:<object number>)" % MAX_EXTRACT)
    if selectors and extract_to is None:
        fail("extract names objects to write and needs extract_to: a directory under work/<your agent id>/ (in a job, under $OUT)")
    if extract_to is not None:
        extract_to = resolve_output(extract_to, "extract_to")
        try:
            os.makedirs(extract_to, exist_ok=True)
        except OSError as exc:
            fail("extract_to could not be created: %s" % describe(exc))
    write_values = args.get("write_values", False)
    if not isinstance(write_values, bool):
        fail("write_values must be true or false")
    cfg = {
        "max_stream_bytes": positive_int(args, "max_stream_bytes", DEFAULT_STREAM),
        "max_total_bytes": positive_int(args, "max_total_bytes", DEFAULT_TOTAL),
        "max_entries": positive_int(args, "max_entries", DEFAULT_ENTRIES, MAX_ENTRIES),
        "max_objects": positive_int(args, "max_objects", DEFAULT_OBJECTS, MAX_OBJECTS),
        "max_depth": positive_int(args, "max_depth", DEFAULT_DEPTH, MAX_DEPTH),
        "max_ratio": positive_int(args, "max_ratio", DEFAULT_RATIO),
        "limit": positive_int(args, "limit", DEFAULT_LIMIT, MAX_LIMIT),
    }
    seconds = positive_int(args, "max_seconds", DEFAULT_SECONDS, MAX_SECONDS)
    try:
        values = SecretValues(write_values)
    except SecretValuesRefused as exc:
        fail(str(exc), write_values="refused", written=False)
    VALUES[0] = values

    size = os.path.getsize(path)
    # The key that names this call's paging files is the path as it may be printed: a digest of a path that holds a token would be a
    # digest of the token (docs/packs.md section 8).
    ctx = Ctx(shown_path(os.path.realpath(path)), cfg, values, seconds)
    shown = shown_name(path)
    if shown != path:
        ctx.names.add(path, shown, "input_path")
    ASSEMBLED.update(ctx=ctx, head={"tool": TOOL, "parser": PARSER, "path": shown, "bytes": size})
    try:
        with open(path, "rb") as fh:
            head = fh.read(HEAD_BYTES)
    except OSError as exc:
        values.close()
        fail("the file could not be opened: %s" % describe(exc), path=path)
    if not head:
        values.close()
        fail("the file is empty", path=path)
    extractor = Extractor(ctx, extract_to, selectors) if selectors else None
    body, stop = {}, None
    try:
        if head[:4] in (b"PK\x03\x04", b"PK\x05\x06"):
            try:
                body = probe_zip(path, size, ctx, extractor)
            except Stop as exc:
                stop = exc
                body = exc.partial
        else:
            with open(path, "rb") as fh:
                blob = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
                try:
                    if head[:8] == CFB_MAGIC:
                        try:
                            body, cfb = probe_ole_blob(blob, ctx, extractor)
                            body = {"container": "OLE compound file", **body}
                            body["coverage"] = {"structures_read": OLE_READ, "structures_not_read": OLE_NOT_READ}
                        except CfbError as exc:
                            stop = Stop("the compound file cannot be read: %s" % exc, {"container": "OLE compound file"})
                            body = stop.partial
                        except Over as exc:
                            ctx.limit_hit("%s; the reading of the compound file stopped there" % exc)
                            body = {"container": "OLE compound file", "coverage": {"structures_read": OLE_READ, "structures_not_read": OLE_NOT_READ}}
                    elif b"%PDF-" in head:
                        body = probe_pdf(blob, ctx, extractor)
                    elif b"{\\rt" in head:
                        body = probe_rtf(blob, ctx, extractor)
                    else:
                        values.close()
                        fail("this is not a container this tool reads", status="unsupported", path=path, head_hex=head[:4].hex(),
                             reads=["OLE compound file", "OOXML or ZIP", "PDF", "RTF"])
                finally:
                    blob.close()
    finally:
        values.close()
        ctx.names.close()

    if extractor is not None:
        for text in extractor.unmatched():
            ctx.problem("extract %s matched nothing in this document" % text_of(text, None, "names"))
    tables = {}
    for name, page in ctx.pages.items():
        tables[name] = page.finish()
        if page.not_written:
            ctx.problem("the whole %s table could not be written to a file: %s" % (name, page.not_written))
    if ctx.names.error:
        ctx.problem("the real names behind the withheld ones could not be kept: %s" % ctx.names.error)
    for name, table in tables.items():
        table["rows"] = ctx.pages[name].page
    extension = os.path.splitext(path)[1].lower().lstrip(".")
    truncated = any(p["truncated"] for p in tables.values())
    members = body.get("members")
    unread = bool(members and (members["encrypted"] or members["unsupported"] or members["failed"] or members["over_budget"] or members["not_attempted"]))
    head_out = {"tool": TOOL, "parser": PARSER, "path": shown, "bytes": size, "extension": scrub(extension, "names") or None}
    # One normalised block for what the structures say about encryption and protection.
    encryption_items = body.pop("encryption_items", None)
    protection_items = body.pop("protection_items", None)
    spill = Spill(ctx, max(cfg["limit"], SPILL_FLOOR))
    if stop is not None:
        emit({**head_out, **body, "status": "failed", "status_basis": stop.message, "error": stop.message,
              "problems": ctx.problems, "limits_hit": ctx.limits, "withheld": COUNTS, "secret_values": values.summary(), "note": NOTE}, spill)
        raise SystemExit(1)
    status = "partial" if (ctx.problems or ctx.limits or unread) else "complete"
    basis = ("every structure this tool reads was read in full" if status == "complete" else
             "%d problem(s), %d limit(s)%s: see `problems`, `limits_hit` and `coverage`" % (len(ctx.problems), len(ctx.limits), "; some members were not read" if unread else ""))
    container = body.get("container")
    if container == "PDF":
        enc = body.get("encryption") or {}
        if enc.get("in_current_trailer"):
            body["encryption_summary"] = {"found": True, "basis": "the newest trailer names an encryption dictionary, which was read", "items": [enc.get("dictionary")]}
        elif enc.get("in_an_earlier_revision_only"):
            body["encryption_summary"] = {"found": None, "basis": "not determined: the newest trailer names no encryption dictionary and an earlier revision's trailer does",
                                          "note": enc["note"]}
        elif enc.get("present") is False and body.get("structure_source") == "cross-reference chain":
            body["encryption_summary"] = {"found": False, "basis": "no trailer of the cross-reference chain names an encryption dictionary",
                                          "limit": "bounded to the cross-reference chain this tool read; not read: objects the chain does not list"}
        else:
            body["encryption_summary"] = {"found": None, "basis": "the cross-reference chain was not usable or the trailer's encryption entry could not be read: not determined"}
    elif encryption_items is not None:
        body["encryption_summary"] = {"found": bool(encryption_items), "items": encryption_items,
                                      "basis": ("structures named in the coverage list were read and one or more records encryption" if encryption_items else
                                                "none of the encryption structures this tool reads was found; encryption not recorded in those structures is not excluded"),
                                      "not_determined": "whether any password opens the file: no key is tried"}
    if protection_items:
        body["protection_items"] = protection_items
    if extractor is not None:
        body["extracted"] = ctx.extracted
        body["extraction_note"] = "Objects are written byte for byte, under budgets, mode 0600, and can contain secrets: run extraction in a job with secret_output: true. A file is the whole object or absent."
        body["extracted_parts_may_contain_secrets"] = True
    result = {**head_out, **body, "status": status, "status_basis": basis, "problems": ctx.problems, "limits_hit": ctx.limits, "tables": tables, "truncated": truncated,
              "budgets": {"max_stream_bytes": cfg["max_stream_bytes"], "max_total_bytes": cfg["max_total_bytes"], "max_entries": cfg["max_entries"], "max_objects": cfg["max_objects"],
                          "max_depth": cfg["max_depth"], "max_ratio": cfg["max_ratio"], "max_seconds": seconds, "stream_bytes_read": ctx.budget.used},
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
